package app.shizuku.smb.server

import java.io.File
import java.io.IOException
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.Paths
import java.nio.file.attribute.BasicFileAttributes

/** Attributes of one file, already mapped to SMB conventions. */
internal class FileInfo(
    val name: String,
    val isDirectory: Boolean,
    val size: Long,
    val creationTime: Long,
    val lastAccessTime: Long,
    val lastWriteTime: Long,
    val changeTime: Long,
    val attributes: Int,
    val fileId: Long,
) {
    val allocationSize: Long get() = if (isDirectory) 0 else (size + 4095) / 4096 * 4096
}

/**
 * The shared folder. Every client path goes through [resolve], which keeps it inside [root]:
 * `..` is rejected and symlinks whose target lies outside the share are refused.
 */
internal class ShareFs(rootPath: String, val readOnly: Boolean) {
    val root: Path = Paths.get(rootPath).toRealPath()
    val rootFile: File = root.toFile()

    /**
     * Maps an SMB path (backslash separated, relative to the share) to a path under [root].
     * The target need not exist, but its parent must stay inside the share. Lookups are
     * case-insensitive when no exact match exists, as Windows clients expect.
     */
    fun resolve(smbPath: String): Path {
        var name = smbPath
        // A default data stream suffix names the file itself.
        if (name.endsWith("::\$DATA", ignoreCase = true)) name = name.dropLast(7)
        val parts = name.split('\\').filter { it.isNotEmpty() && it != "." }
        var current = root
        for ((index, part) in parts.withIndex()) {
            if (part == ".." || part.any { it == '/' || it < ' ' }) {
                throw SmbException(Status.OBJECT_NAME_INVALID)
            }
            // Named streams aren't supported; report them as missing so clients such as macOS
            // fall back to storing metadata in ._ files.
            if (':' in part) throw SmbException(Status.OBJECT_NAME_NOT_FOUND)
            val isLast = index == parts.lastIndex
            if (!isLast && !Files.isDirectory(current)) throw SmbException(Status.OBJECT_PATH_NOT_FOUND)
            current = child(current, part)
        }
        checkInside(current)
        return current
    }

    private fun child(dir: Path, name: String): Path {
        val exact = dir.resolve(name)
        if (Files.exists(exact, LinkOption.NOFOLLOW_LINKS)) return exact
        val match = runCatching {
            Files.newDirectoryStream(dir).use { stream ->
                stream.firstOrNull { it.fileName.toString().equals(name, ignoreCase = true) }
            }
        }.getOrNull()
        return match ?: exact
    }

    /** Throws ACCESS_DENIED if [path] (or, when it doesn't exist, its parent) escapes the share. */
    fun checkInside(path: Path) {
        val target = if (Files.exists(path)) path else path.parent ?: root
        val real = try {
            target.toRealPath()
        } catch (e: IOException) {
            // A dangling symlink or a missing parent; the operation will fail on its own.
            if (Files.isSymbolicLink(path)) throw SmbException(Status.ACCESS_DENIED)
            return
        }
        if (!real.startsWith(root)) throw SmbException(Status.ACCESS_DENIED)
    }

    /** The client-visible path of [path], e.g. `\Music\a.mp3`; the root is `\`. */
    fun smbName(path: Path): String = "\\" + root.relativize(path).toString().replace('/', '\\')

    fun stat(path: Path, name: String = path.fileName?.toString() ?: ""): FileInfo? {
        val attrs = try {
            Files.readAttributes(path, BasicFileAttributes::class.java)
        } catch (e: IOException) {
            return null
        }
        return info(name, attrs, path)
    }

    fun info(name: String, attrs: BasicFileAttributes, path: Path): FileInfo {
        val dir = attrs.isDirectory
        var attributes = if (dir) Smb2.ATTR_DIRECTORY else Smb2.ATTR_ARCHIVE
        if (name.startsWith('.') && name != "." && name != "..") attributes = attributes or Smb2.ATTR_HIDDEN
        val write = FileTimes.fromMillis(attrs.lastModifiedTime().toMillis())
        val creation = attrs.creationTime()?.toMillis()?.takeIf { it > 0 }?.let(FileTimes::fromMillis) ?: write
        val access = attrs.lastAccessTime()?.toMillis()?.takeIf { it > 0 }?.let(FileTimes::fromMillis) ?: write
        return FileInfo(
            name = name,
            isDirectory = dir,
            size = if (dir) 0 else attrs.size(),
            creationTime = minOf(creation, write),
            lastAccessTime = access,
            lastWriteTime = write,
            changeTime = write,
            attributes = attributes,
            fileId = fileId(attrs, path),
        )
    }

    private fun fileId(attrs: BasicFileAttributes, path: Path): Long {
        val key = attrs.fileKey()?.toString()
        if (key != null) {
            INODE_REGEX.find(key)?.groupValues?.get(1)?.toLongOrNull()?.let { return it }
        }
        return (key ?: path.toString()).hashCode().toLong() and 0xFFFFFFFFL
    }

    fun totalBytes(): Long = rootFile.totalSpace

    fun freeBytes(): Long = rootFile.usableSpace

    private companion object {
        val INODE_REGEX = Regex("ino=(\\d+)")
    }
}

/** Glob matching for directory searches: `*` and `?`, plus the DOS variants `<`, `>` and `"`. */
internal object Wildcard {
    fun isPattern(pattern: String): Boolean = pattern.any { it in "*?<>\"" }

    fun matches(pattern: String, name: String): Boolean {
        if (pattern == "*" || pattern == "*.*" || pattern.isEmpty()) return true
        val p = pattern.lowercase()
        val n = name.lowercase()
        // next[j]: does p[i+1..] match n[j..]; cur[j]: does p[i..] match n[j..].
        var next = BooleanArray(n.length + 1).also { it[n.length] = true }
        for (i in p.lastIndex downTo 0) {
            val cur = BooleanArray(n.length + 1)
            for (j in n.length downTo 0) {
                val more = j < n.length
                cur[j] = when (val c = p[i]) {
                    '*', '<' -> next[j] || (more && cur[j + 1])
                    '?' -> more && next[j + 1]
                    '>' -> (more && next[j + 1]) || next[j]
                    '"' -> (more && n[j] == '.' && next[j + 1]) || next[j]
                    else -> more && n[j] == c && next[j + 1]
                }
            }
            next = cur
        }
        return next[0]
    }
}
