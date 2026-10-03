package app.shizuku.smb.server

import java.io.IOException
import java.nio.ByteBuffer
import java.nio.channels.FileChannel
import java.nio.file.AccessDeniedException
import java.nio.file.DirectoryNotEmptyException
import java.nio.file.FileAlreadyExistsException
import java.nio.file.Files
import java.nio.file.NoSuchFileException
import java.nio.file.NotDirectoryException
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import java.nio.file.StandardOpenOption
import java.nio.file.attribute.BasicFileAttributeView
import java.nio.file.attribute.FileTime

/** CREATE, CLOSE, READ, WRITE, directory listing and file information requests. */
internal class FileOps(private val conn: Connection, private val config: SmbConfig) {

    private val ok4 = ByteWriter().u16(4).u16(0).toByteArray()

    // ---- CREATE ----

    fun create(req: Request, tree: Tree): Reply {
        val desired = req.i32(24)
        val disposition = req.i32(36)
        val options = req.i32(40)
        val name = String(req.buffer(req.u16(44), req.u16(46)), Charsets.UTF_16LE)
        val contexts = parseContexts(req, req.u32(48).toInt(), req.u32(52).toInt())

        val fs = tree.fs ?: return openPipe(tree, name)
        if (disposition !in Smb2.FILE_SUPERSEDE..Smb2.FILE_OVERWRITE_IF) throw SmbException(Status.INVALID_PARAMETER)
        val dirOnly = options and Smb2.FILE_DIRECTORY_FILE != 0
        val fileOnly = options and Smb2.FILE_NON_DIRECTORY_FILE != 0
        if (dirOnly && fileOnly) throw SmbException(Status.INVALID_PARAMETER)

        val path = fs.resolve(name)
        val exists = Files.exists(path)
        val isDir = exists && Files.isDirectory(path)
        val isRoot = path == fs.root

        // Work out the access to grant before touching the file system.
        val maxAllowed = desired and Smb2.MAXIMUM_ALLOWED != 0
        var access = mapGeneric(desired) and (Smb2.MAXIMUM_ALLOWED or Smb2.ACCESS_SYSTEM_SECURITY).inv()
        val writes = disposition != Smb2.FILE_OPEN && (disposition != Smb2.FILE_OPEN_IF || !exists)
        val deleteOnClose = options and Smb2.FILE_DELETE_ON_CLOSE != 0
        if (fs.readOnly) {
            if (access and Smb2.WRITE_ACCESS_MASK != 0 || writes || deleteOnClose) {
                throw SmbException(Status.ACCESS_DENIED)
            }
            if (maxAllowed) access = access or Smb2.READ_ONLY_ACCESS
        } else if (maxAllowed) {
            access = access or Smb2.FILE_ALL_ACCESS
        }
        if (deleteOnClose && access and Smb2.DELETE == 0) throw SmbException(Status.ACCESS_DENIED)
        if (isRoot && (deleteOnClose || writes && exists && disposition != Smb2.FILE_OPEN_IF)) {
            throw SmbException(Status.ACCESS_DENIED)
        }

        val action: Int
        when {
            !exists -> {
                if (disposition == Smb2.FILE_OPEN || disposition == Smb2.FILE_OVERWRITE) {
                    val parent = path.parent
                    throw SmbException(
                        if (parent != null && Files.isDirectory(parent)) Status.OBJECT_NAME_NOT_FOUND
                        else Status.OBJECT_PATH_NOT_FOUND,
                    )
                }
                val parent = path.parent
                if (parent == null || !Files.isDirectory(parent)) throw SmbException(Status.OBJECT_PATH_NOT_FOUND)
                io {
                    if (dirOnly) Files.createDirectory(path) else Files.createFile(path)
                }
                action = Smb2.FILE_CREATED
            }
            disposition == Smb2.FILE_CREATE -> throw SmbException(Status.OBJECT_NAME_COLLISION)
            isDir && fileOnly -> throw SmbException(Status.FILE_IS_A_DIRECTORY)
            !isDir && dirOnly -> throw SmbException(Status.NOT_A_DIRECTORY)
            disposition == Smb2.FILE_SUPERSEDE || disposition == Smb2.FILE_OVERWRITE ||
                disposition == Smb2.FILE_OVERWRITE_IF -> {
                if (isDir) throw SmbException(Status.INVALID_PARAMETER)
                io { FileChannel.open(path, StandardOpenOption.WRITE).use { it.truncate(0) } }
                action = if (disposition == Smb2.FILE_SUPERSEDE) Smb2.FILE_SUPERSEDED else Smb2.FILE_OVERWRITTEN
            }
            else -> action = Smb2.FILE_OPENED
        }

        val directory = Files.isDirectory(path)
        val open = Open(conn.server.newFileId(), tree, path, directory, access)
        if (!directory) openChannel(open, maxAllowed)
        open.deleteOnClose = deleteOnClose
        try {
            conn.addOpen(open)
        } catch (e: SmbException) {
            release(open)
            throw e
        }
        val info = fs.stat(path) ?: run {
            conn.closeOpen(open)
            throw SmbException(Status.OBJECT_NAME_NOT_FOUND)
        }
        val maximal = if (fs.readOnly) Smb2.READ_ONLY_ACCESS else Smb2.FILE_ALL_ACCESS
        val responseContexts = ArrayList<Pair<String, ByteArray>>()
        if ("MxAc" in contexts) {
            responseContexts += "MxAc" to ByteWriter().u32(0).u32(maximal).toByteArray()
        }
        if ("QFid" in contexts) {
            responseContexts += "QFid" to ByteWriter().u64(info.fileId).u64(Info.VOLUME_SERIAL).zeros(16).toByteArray()
        }
        return createReply(action, info, open.id, responseContexts)
    }

    private fun openPipe(tree: Tree, name: String): Reply {
        val pipeName = name.trimStart('\\').lowercase()
        if (pipeName != "srvsvc") throw SmbException(Status.OBJECT_NAME_NOT_FOUND)
        val open = Open(conn.server.newFileId(), tree, null, false, Smb2.FILE_ALL_ACCESS)
        open.pipe = SrvsvcPipe(conn.server.shareListings())
        conn.addOpen(open)
        val info = FileInfo(pipeName, false, 0, 0, 0, 0, 0, Smb2.ATTR_NORMAL, 0)
        return createReply(Smb2.FILE_OPENED, info, open.id, emptyList())
    }

    private fun createReply(action: Int, info: FileInfo, id: Long, contexts: List<Pair<String, ByteArray>>): Reply {
        val w = ByteWriter()
        w.u16(89).u8(0).u8(0).u32(action)
        w.u64(info.creationTime).u64(info.lastAccessTime).u64(info.lastWriteTime).u64(info.changeTime)
        w.u64(info.allocationSize).u64(info.size).u32(info.attributes).u32(0)
        w.u64(id).u64(id)
        val ctxAt = w.size
        w.u32(0).u32(0)
        if (contexts.isNotEmpty()) {
            val start = w.size
            contexts.forEachIndexed { i, (name, data) ->
                val entryStart = w.size
                w.u32(0).u16(16).u16(4).u16(0).u16(24).u32(data.size)
                w.bytes(name.toByteArray(Charsets.US_ASCII)).zeros(4).bytes(data)
                if (i != contexts.lastIndex) {
                    w.align(8)
                    w.putU32(entryStart, w.size - entryStart)
                }
            }
            w.putU32(ctxAt, Smb2.HEADER_SIZE + start)
            w.putU32(ctxAt + 4, w.size - start)
        }
        return Reply(Status.SUCCESS, w.toByteArray())
    }

    private fun parseContexts(req: Request, offset: Int, length: Int): Set<String> {
        if (offset == 0 || length == 0) return emptySet()
        val names = HashSet<String>()
        val r = req.r.slice(offset, length)
        var pos = 0
        while (true) {
            val next = r.u32(pos).toInt()
            val nameOffset = r.u16(pos + 4)
            val nameLength = r.u16(pos + 6)
            names += String(r.bytes(pos + nameOffset, nameLength), Charsets.US_ASCII)
            if (next == 0 || names.size > 32) break
            pos += next
        }
        return names
    }

    private fun mapGeneric(access: Int): Int {
        var a = access
        if (a and Smb2.GENERIC_READ != 0) a = a or Smb2.FILE_GENERIC_READ
        if (a and Smb2.GENERIC_WRITE != 0) a = a or Smb2.FILE_GENERIC_WRITE
        if (a and Smb2.GENERIC_EXECUTE != 0) a = a or Smb2.FILE_GENERIC_EXECUTE
        if (a and Smb2.GENERIC_ALL != 0) a = a or Smb2.FILE_ALL_ACCESS
        return a and (Smb2.GENERIC_READ or Smb2.GENERIC_WRITE or Smb2.GENERIC_EXECUTE or Smb2.GENERIC_ALL).inv()
    }

    /** Opens the data channel the handle's access needs; may downgrade a MAXIMUM_ALLOWED open. */
    private fun openChannel(open: Open, maxAllowed: Boolean) {
        val path = open.path ?: return
        val wantWrite = open.access and (Smb2.FILE_WRITE_DATA or Smb2.FILE_APPEND_DATA) != 0
        val wantRead = open.access and (Smb2.FILE_READ_DATA or Smb2.FILE_EXECUTE) != 0
        if (!wantRead && !wantWrite) return
        try {
            open.channel = if (wantWrite) {
                FileChannel.open(path, StandardOpenOption.READ, StandardOpenOption.WRITE)
            } else {
                FileChannel.open(path, StandardOpenOption.READ)
            }
        } catch (e: IOException) {
            if (!(wantWrite && maxAllowed)) throw SmbException(mapIoError(e))
            open.access = open.access and Smb2.WRITE_ACCESS_MASK.inv()
            open.channel = io { FileChannel.open(path, StandardOpenOption.READ) }
        }
    }

    // ---- CLOSE / FLUSH ----

    fun close(req: Request, open: Open): Reply {
        val postQuery = req.u16(2) and 0x0001 != 0
        val info = if (postQuery) open.path?.let { open.tree.fs?.stat(it) } else null
        conn.closeOpen(open)
        val w = ByteWriter().u16(60).u16(if (info != null) 1 else 0).u32(0)
        if (info != null) {
            w.u64(info.creationTime).u64(info.lastAccessTime).u64(info.lastWriteTime).u64(info.changeTime)
            w.u64(info.allocationSize).u64(info.size).u32(info.attributes)
        } else {
            w.zeros(52)
        }
        return Reply(Status.SUCCESS, w.toByteArray())
    }

    /** Releases the handle's resources and carries out a pending delete. */
    fun release(open: Open) {
        runCatching { open.channel?.close() }
        open.channel = null
        val path = open.path
        if (open.deleteOnClose && path != null) {
            runCatching { Files.deleteIfExists(path) }
        }
    }

    fun flush(open: Open): Reply {
        if (open.access and (Smb2.FILE_WRITE_DATA or Smb2.FILE_APPEND_DATA) == 0 && !open.isDirectory && open.pipe == null) {
            throw SmbException(Status.ACCESS_DENIED)
        }
        open.channel?.let { ch -> io { ch.force(true) } }
        return Reply(Status.SUCCESS, ok4)
    }

    // ---- READ / WRITE ----

    fun read(req: Request, open: Open): Reply {
        val length = req.u32(4)
        val offset = req.u64(8)
        val minimum = req.u32(32)
        if (length > conn.maxIo) throw SmbException(Status.INVALID_PARAMETER)
        val pipe = open.pipe
        if (pipe != null) {
            if (!pipe.hasOutput) throw SmbException(Status.PIPE_EMPTY)
            val (data, more) = pipe.read(length.toInt())
            return readReply(data, data.size, if (more) Status.BUFFER_OVERFLOW else Status.SUCCESS)
        }
        if (open.isDirectory) throw SmbException(Status.INVALID_DEVICE_REQUEST)
        if (open.access and (Smb2.FILE_READ_DATA or Smb2.FILE_EXECUTE) == 0) throw SmbException(Status.ACCESS_DENIED)
        if (offset < 0) throw SmbException(Status.INVALID_PARAMETER)
        val channel = open.channel ?: throw SmbException(Status.ACCESS_DENIED)
        val buf = ByteArray(length.toInt())
        var total = 0
        io {
            while (total < buf.size) {
                val n = channel.read(ByteBuffer.wrap(buf, total, buf.size - total), offset + total)
                if (n <= 0) break
                total += n
            }
        }
        if ((total == 0 && length > 0) || total < minimum) throw SmbException(Status.END_OF_FILE)
        return readReply(buf, total, Status.SUCCESS)
    }

    private fun readReply(data: ByteArray, length: Int, status: Int): Reply {
        val w = ByteWriter(16 + length)
        w.u16(17).u8(Smb2.HEADER_SIZE + 16).u8(0).u32(length).u32(0).u32(0)
        w.bytes(data, 0, length)
        return Reply(status, w.toByteArray())
    }

    fun write(req: Request, open: Open): Reply {
        val dataOffset = req.u16(2)
        val length = req.u32(4).toInt()
        var offset = req.u64(8)
        if (length < 0 || length > conn.maxIo) throw SmbException(Status.INVALID_PARAMETER)
        val data = req.r.slice(dataOffset, length) // bounds check
        val pipe = open.pipe
        if (pipe != null) {
            pipe.write(data.bytes(0, length))
            return writeReply(length)
        }
        if (open.isDirectory) throw SmbException(Status.INVALID_DEVICE_REQUEST)
        if (open.tree.fs?.readOnly != false) throw SmbException(Status.ACCESS_DENIED)
        if (open.access and (Smb2.FILE_WRITE_DATA or Smb2.FILE_APPEND_DATA) == 0) throw SmbException(Status.ACCESS_DENIED)
        val channel = open.channel ?: throw SmbException(Status.ACCESS_DENIED)
        io {
            if (offset == -1L || open.access and Smb2.FILE_WRITE_DATA == 0) offset = channel.size()
            if (offset < 0) throw SmbException(Status.INVALID_PARAMETER)
            val bb = ByteBuffer.wrap(data.data, data.start, length)
            var written = 0
            while (written < length) {
                written += channel.write(bb, offset + written)
            }
        }
        return writeReply(length)
    }

    private fun writeReply(count: Int): Reply =
        Reply(Status.SUCCESS, ByteWriter().u16(17).u16(0).u32(count).u32(0).u16(0).u16(0).toByteArray())

    // ---- QUERY_DIRECTORY ----

    fun queryDirectory(req: Request, open: Open): Reply {
        val infoClass = req.u8(2)
        val flags = req.u8(3)
        val pattern = String(req.buffer(req.u16(24), req.u16(26)), Charsets.UTF_16LE)
        val maxOut = req.u32(28).toInt()
        if (!open.isDirectory) throw SmbException(Status.INVALID_PARAMETER)
        if (open.access and Smb2.FILE_READ_DATA == 0) throw SmbException(Status.ACCESS_DENIED)
        Info.directoryEntryBaseSize(infoClass) // validates the class
        val fs = open.tree.fs ?: throw SmbException(Status.INVALID_PARAMETER)
        val dir = open.path ?: throw SmbException(Status.INVALID_PARAMETER)

        val restart = flags and (RESTART_SCANS or REOPEN) != 0
        val first = open.listing == null || restart
        if (first) {
            open.listing = list(fs, dir, pattern.ifEmpty { "*" })
            open.cursor = 0
        }
        val listing = open.listing!!
        if (open.cursor >= listing.size) {
            throw SmbException(if (first) Status.NO_SUCH_FILE else Status.NO_MORE_FILES)
        }

        val out = ByteWriter()
        var lastStart = -1
        while (open.cursor < listing.size) {
            val entry = ByteWriter()
            Info.directoryEntry(entry, infoClass, listing[open.cursor])
            val aligned = (out.size + 7) and 7.inv()
            if (aligned + entry.size > maxOut) break
            out.align(8)
            if (lastStart >= 0) out.putU32(lastStart, out.size - lastStart)
            lastStart = out.size
            out.bytes(entry.toByteArray())
            open.cursor++
            if (flags and RETURN_SINGLE_ENTRY != 0) break
        }
        if (lastStart < 0) throw SmbException(Status.INFO_LENGTH_MISMATCH)
        val body = ByteWriter().u16(9).u16(Smb2.HEADER_SIZE + 8).u32(out.size).bytes(out.toByteArray())
        return Reply(Status.SUCCESS, body.toByteArray())
    }

    private fun list(fs: ShareFs, dir: Path, pattern: String): List<FileInfo> {
        val result = ArrayList<FileInfo>()
        if (!Wildcard.isPattern(pattern)) {
            // An exact name: look up just that entry.
            val path = runCatching { fs.resolve(fs.smbName(dir) + "\\" + pattern) }.getOrNull()
            val info = path?.takeIf { it.parent == dir }?.let { fs.stat(it) }
            if (info != null) result += info
            return result
        }
        fs.stat(dir, ".")?.let { if (Wildcard.matches(pattern, ".")) result += it }
        val parent = if (dir == fs.root) dir else dir.parent
        fs.stat(parent, "..")?.let { if (Wildcard.matches(pattern, "..")) result += it }
        try {
            Files.newDirectoryStream(dir).use { stream ->
                for (child in stream) {
                    val name = child.fileName.toString()
                    if (!Wildcard.matches(pattern, name)) continue
                    // Don't reveal anything about where links out of the share point.
                    if (Files.isSymbolicLink(child) && runCatching { fs.checkInside(child) }.isFailure) continue
                    fs.stat(child, name)?.let(result::add)
                }
            }
        } catch (e: IOException) {
            throw SmbException(mapIoError(e))
        }
        return result
    }

    // ---- QUERY_INFO ----

    fun queryInfo(req: Request, open: Open): Reply {
        val infoType = req.u8(2)
        val infoClass = req.u8(3)
        val maxOut = req.u32(4).toInt()
        val additional = req.i32(16)
        val w = ByteWriter()
        var variable = false
        when (infoType) {
            Smb2.INFO_FILE -> variable = fileInfo(w, open, infoClass)
            Smb2.INFO_FILESYSTEM -> {
                val fs = open.tree.fs ?: throw SmbException(Status.NOT_SUPPORTED)
                fsInfo(w, fs, infoClass)
                variable = infoClass == Info.FS_VOLUME || infoClass == Info.FS_ATTRIBUTE
            }
            Smb2.INFO_SECURITY -> {
                val sd = Info.securityDescriptor(additional, if (open.tree.fs?.readOnly == false) Smb2.FILE_ALL_ACCESS else Smb2.READ_ONLY_ACCESS)
                if (sd.size > maxOut) {
                    throw SmbException(Status.BUFFER_TOO_SMALL, ByteWriter().u32(sd.size).toByteArray())
                }
                w.bytes(sd)
            }
            else -> throw SmbException(Status.NOT_SUPPORTED)
        }
        var data = w.toByteArray()
        var status = Status.SUCCESS
        if (data.size > maxOut) {
            if (!variable) throw SmbException(Status.INFO_LENGTH_MISMATCH)
            data = data.copyOf(maxOut)
            status = Status.BUFFER_OVERFLOW
        }
        val body = ByteWriter().u16(9).u16(Smb2.HEADER_SIZE + 8).u32(data.size).bytes(data)
        return Reply(status, body.toByteArray())
    }

    /** Writes a file information class; returns whether it has a variable-length part. */
    private fun fileInfo(w: ByteWriter, open: Open, infoClass: Int): Boolean {
        if (open.pipe != null) {
            if (infoClass != Info.FILE_STANDARD) throw SmbException(Status.NOT_SUPPORTED)
            w.u64(4096).u64(0).u32(1).u8(0).u8(0).u16(0)
            return false
        }
        val fs = open.tree.fs!!
        val path = open.path!!
        val info = fs.stat(path) ?: throw SmbException(Status.OBJECT_NAME_NOT_FOUND)
        when (infoClass) {
            Info.FILE_BASIC -> Info.basic(w, info)
            Info.FILE_STANDARD -> Info.standard(w, info, open.deleteOnClose)
            Info.FILE_INTERNAL -> w.u64(info.fileId)
            Info.FILE_EA -> w.u32(0)
            Info.FILE_ACCESS -> w.u32(open.access)
            Info.FILE_POSITION -> w.u64(0)
            Info.FILE_MODE -> w.u32(0)
            Info.FILE_ALIGNMENT -> w.u32(0)
            Info.FILE_NETWORK_OPEN -> Info.networkOpen(w, info)
            Info.FILE_ATTRIBUTE_TAG -> w.u32(info.attributes).u32(0)
            Info.FILE_COMPRESSION -> w.u64(info.size).u16(0).u8(0).u8(0).u8(0).zeros(3)
            Info.FILE_ID -> w.u64(Info.VOLUME_SERIAL).u64(info.fileId).u64(0)
            Info.FILE_ALL -> {
                Info.all(w, info, open.access, open.deleteOnClose, fs.smbName(path))
                return true
            }
            Info.FILE_NAME, Info.FILE_NORMALIZED_NAME -> {
                val name = utf16(fs.smbName(path))
                w.u32(name.size).bytes(name)
                return true
            }
            Info.FILE_STREAM -> {
                Info.stream(w, info)
                return true
            }
            Info.FILE_ALTERNATE_NAME -> throw SmbException(Status.OBJECT_NAME_NOT_FOUND)
            else -> throw SmbException(Status.INVALID_INFO_CLASS)
        }
        return false
    }

    private fun fsInfo(w: ByteWriter, fs: ShareFs, infoClass: Int) {
        when (infoClass) {
            Info.FS_VOLUME -> Info.fsVolume(w, config.shareName)
            Info.FS_SIZE -> Info.fsSize(w, fs.totalBytes(), fs.freeBytes())
            Info.FS_FULL_SIZE -> Info.fsFullSize(w, fs.totalBytes(), fs.freeBytes())
            Info.FS_DEVICE -> w.u32(0x07).u32(0) // FILE_DEVICE_DISK
            Info.FS_ATTRIBUTE -> Info.fsAttribute(w, fs.readOnly)
            Info.FS_OBJECT_ID -> w.zeros(64)
            Info.FS_SECTOR_SIZE -> Info.fsSectorSize(w)
            else -> throw SmbException(Status.INVALID_INFO_CLASS)
        }
    }

    // ---- SET_INFO ----

    fun setInfo(req: Request, open: Open): Reply {
        val infoType = req.u8(2)
        val infoClass = req.u8(3)
        val length = req.u32(4).toInt()
        val data = req.r.slice(req.u16(8), length)
        val fs = open.tree.fs ?: throw SmbException(Status.NOT_SUPPORTED)
        if (fs.readOnly) throw SmbException(Status.ACCESS_DENIED)
        val path = open.path!!
        when (infoType) {
            Smb2.INFO_FILE -> when (infoClass) {
                Info.FILE_BASIC -> setBasic(open, path, data)
                Info.FILE_RENAME -> rename(open, fs, path, data)
                Info.FILE_DISPOSITION -> setDisposition(open, path, data.u8(0) != 0)
                Info.FILE_DISPOSITION_EX -> setDisposition(open, path, data.i32(0) and 0x1 != 0)
                Info.FILE_END_OF_FILE -> setSize(open, data.u64(0), extend = true)
                Info.FILE_ALLOCATION -> setSize(open, data.u64(0), extend = false)
                Info.FILE_POSITION, Info.FILE_MODE, Info.FILE_VALID_DATA_LENGTH -> Unit
                Info.FILE_FULL_EA -> throw SmbException(Status.EAS_NOT_SUPPORTED)
                else -> throw SmbException(Status.INVALID_INFO_CLASS)
            }
            Smb2.INFO_SECURITY -> Unit // Permissions come from the Android file system; accept and ignore.
            else -> throw SmbException(Status.NOT_SUPPORTED)
        }
        return Reply(Status.SUCCESS, ByteWriter().u16(2).toByteArray())
    }

    private fun setBasic(open: Open, path: Path, data: ByteReader) {
        if (open.access and Smb2.FILE_WRITE_ATTRIBUTES == 0) throw SmbException(Status.ACCESS_DENIED)
        fun time(offset: Int): FileTime? {
            val v = data.u64(offset)
            return if (v == 0L || v == -1L || v == -2L) null else FileTime.fromMillis(FileTimes.toMillis(v))
        }
        val access = time(8)
        val write = time(16)
        if (access != null || write != null) {
            // Not every Android file system lets the shell set times; that shouldn't fail a copy.
            runCatching {
                Files.getFileAttributeView(path, BasicFileAttributeView::class.java).setTimes(write, access, null)
            }
        }
    }

    private fun setDisposition(open: Open, path: Path, delete: Boolean) {
        if (open.access and Smb2.DELETE == 0) throw SmbException(Status.ACCESS_DENIED)
        if (delete) {
            if (path == open.tree.fs?.root) throw SmbException(Status.ACCESS_DENIED)
            if (open.isDirectory) {
                val empty = io { Files.newDirectoryStream(path).use { !it.iterator().hasNext() } }
                if (!empty) throw SmbException(Status.DIRECTORY_NOT_EMPTY)
            }
        }
        open.deleteOnClose = delete
    }

    private fun setSize(open: Open, size: Long, extend: Boolean) {
        if (open.access and (Smb2.FILE_WRITE_DATA or Smb2.FILE_APPEND_DATA) == 0) throw SmbException(Status.ACCESS_DENIED)
        if (size < 0) throw SmbException(Status.INVALID_PARAMETER)
        val channel = open.channel ?: throw SmbException(Status.ACCESS_DENIED)
        io {
            val current = channel.size()
            if (size < current) {
                channel.truncate(size)
            } else if (extend && size > current) {
                channel.write(ByteBuffer.wrap(ByteArray(1)), size - 1)
            }
        }
    }

    private fun rename(open: Open, fs: ShareFs, source: Path, data: ByteReader) {
        if (open.access and Smb2.DELETE == 0) throw SmbException(Status.ACCESS_DENIED)
        if (source == fs.root) throw SmbException(Status.ACCESS_DENIED)
        val replace = data.u8(0) != 0
        val nameLength = data.u32(16).toInt()
        val name = data.utf16(20, nameLength)
        val target = fs.resolve(name)
        if (target == source) return
        if (target == fs.root || target.startsWith(source)) throw SmbException(Status.INVALID_PARAMETER)
        val parent = target.parent
        if (parent == null || !Files.isDirectory(parent)) throw SmbException(Status.OBJECT_PATH_NOT_FOUND)
        val sameFile = Files.exists(target) && runCatching { Files.isSameFile(source, target) }.getOrDefault(false)
        io {
            when {
                sameFile -> {
                    // A case-only rename on a case-insensitive file system: go through a temporary name.
                    val temp = source.resolveSibling(".smbrename-" + System.nanoTime())
                    Files.move(source, temp)
                    Files.move(temp, target)
                }
                Files.exists(target, java.nio.file.LinkOption.NOFOLLOW_LINKS) -> {
                    if (!replace) throw SmbException(Status.OBJECT_NAME_COLLISION)
                    if (Files.isDirectory(target)) throw SmbException(Status.ACCESS_DENIED)
                    Files.move(source, target, StandardCopyOption.REPLACE_EXISTING)
                }
                else -> Files.move(source, target)
            }
        }
        // Keep handles below a renamed folder pointing at the right place.
        for (other in conn.opens.values) {
            val p = other.path ?: continue
            if (p == source) other.path = target
            else if (p.startsWith(source)) other.path = target.resolve(source.relativize(p))
        }
    }

    private inline fun <T> io(block: () -> T): T = try {
        block()
    } catch (e: IOException) {
        throw SmbException(mapIoError(e))
    }

    private fun mapIoError(e: IOException): Int = when (e) {
        is NoSuchFileException -> Status.OBJECT_NAME_NOT_FOUND
        is FileAlreadyExistsException -> Status.OBJECT_NAME_COLLISION
        is AccessDeniedException -> Status.ACCESS_DENIED
        is DirectoryNotEmptyException -> Status.DIRECTORY_NOT_EMPTY
        is NotDirectoryException -> Status.NOT_A_DIRECTORY
        else -> if (e.message?.contains("No space", ignoreCase = true) == true) Status.DISK_FULL else Status.ACCESS_DENIED
    }

    private companion object {
        const val RESTART_SCANS = 0x01
        const val RETURN_SINGLE_ENTRY = 0x02
        const val REOPEN = 0x10
    }
}
