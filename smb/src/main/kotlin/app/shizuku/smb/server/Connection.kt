package app.shizuku.smb.server

import java.io.BufferedInputStream
import java.io.BufferedOutputStream
import java.io.DataInputStream
import java.io.EOFException
import java.io.IOException
import java.net.Socket
import java.net.SocketTimeoutException

/** One SMB2 request inside a (possibly compound) frame. Offsets are relative to its header. */
internal class Request(val buf: ByteArray, val off: Int, val len: Int) {
    val r = ByteReader(buf, off, off + len)
    val creditCharge = r.u16(6)
    val command = r.u16(12)
    val creditRequest = r.u16(14)
    val flags = r.i32(16)
    val nextCommand = r.i32(20)
    val messageId = r.u64(24)
    val isAsync = flags and Smb2.FLAGS_ASYNC_COMMAND != 0
    val asyncId = if (isAsync) r.u64(32) else 0L
    val processId = r.i32(32)
    var treeId = if (isAsync) 0 else r.i32(36)
    var sessionId = r.u64(40)
    val isRelated = flags and Smb2.FLAGS_RELATED_OPERATIONS != 0
    val isSigned = flags and Smb2.FLAGS_SIGNED != 0

    // Body field readers; offsets are relative to the start of the body.
    fun u8(o: Int) = r.u8(Smb2.HEADER_SIZE + o)
    fun u16(o: Int) = r.u16(Smb2.HEADER_SIZE + o)
    fun i32(o: Int) = r.i32(Smb2.HEADER_SIZE + o)
    fun u32(o: Int) = r.u32(Smb2.HEADER_SIZE + o)
    fun u64(o: Int) = r.u64(Smb2.HEADER_SIZE + o)

    /** Reads a buffer described by an offset (from the header) and a length. */
    fun buffer(offset: Int, length: Int): ByteArray = if (length == 0) ByteArray(0) else r.bytes(offset, length)

    fun bytes(): ByteArray = buf.copyOfRange(off, off + len)
}

/** A handler's answer to one request. */
internal class Reply(
    val status: Int,
    val body: ByteArray,
    val asyncId: Long = 0,
    val sessionId: Long? = null,
    val treeId: Int? = null,
    /** Runs with the final response bytes (after compounding and signing). */
    val onSent: ((ByteArray) -> Unit)? = null,
    /** The session whose key signs this response, when different from the request's. */
    val signWith: Session? = null,
)

internal class Session(val id: Long, var ntlm: Ntlm?) {
    var valid = false
    var mechTypes: ByteArray? = null
    var ntlmPreferred = true
    var preauthHash: ByteArray? = null
    var signingKey: ByteArray? = null
    var user: String = ""
    val trees = HashMap<Int, Tree>()
}

internal class Tree(val id: Int, val session: Session, val fs: ShareFs?) {
    val isIpc: Boolean get() = fs == null
}

internal class PendingNotify(val messageId: Long, val asyncId: Long, val sessionId: Long, val creditCharge: Int)

internal class Open(val id: Long, val tree: Tree, var path: java.nio.file.Path?, val isDirectory: Boolean, var access: Int) {
    var channel: java.nio.channels.FileChannel? = null
    var deleteOnClose = false
    var pipe: SrvsvcPipe? = null
    var listing: List<FileInfo>? = null
    var cursor = 0
    var notify: PendingNotify? = null
}

/** Serves one TCP client. All requests from a client are handled on its thread, in order. */
internal class Connection(
    val server: SmbServer,
    private val socket: Socket,
) : Runnable {
    private val config = server.config
    private val input = DataInputStream(BufferedInputStream(socket.getInputStream(), 64 * 1024))
    private val output = BufferedOutputStream(socket.getOutputStream(), 64 * 1024)
    private val writeLock = Any()
    private val client = socket.remoteSocketAddress.toString()

    var dialect = 0
        private set
    private var negotiated = false
    private var clientSecurityMode = 0
    private var connectionPreauth: ByteArray? = null
    private var authFailures = 0

    val sessions = HashMap<Long, Session>()
    val opens = HashMap<Long, Open>()
    private val files = FileOps(this, config)

    private var nextAsyncId = 1L

    val maxIo: Int get() = if (dialect == Smb2.DIALECT_202) 65536 else MAX_IO

    override fun run() {
        try {
            socket.tcpNoDelay = true
            socket.soTimeout = PRE_AUTH_TIMEOUT_MS
            while (!socket.isClosed) {
                val frame = readFrame() ?: break
                if (!processFrame(frame)) break
                if (sessions.values.any { it.valid }) socket.soTimeout = IDLE_TIMEOUT_MS
            }
        } catch (e: SocketTimeoutException) {
            server.log("$client timed out")
        } catch (e: EOFException) {
            // Client disconnected.
        } catch (e: IOException) {
            if (!socket.isClosed) server.log("$client connection error: ${e.message}")
        } catch (e: MalformedMessageException) {
            server.log("$client sent a malformed message: ${e.message}")
        } catch (e: RuntimeException) {
            server.log("$client internal error: $e")
        } finally {
            close()
        }
    }

    fun close() {
        runCatching { socket.close() }
        synchronized(this) {
            opens.values.toList().forEach { runCatching { files.release(it) } }
            opens.clear()
            sessions.clear()
        }
        server.onConnectionClosed(this)
    }

    /** Reads one NetBIOS-framed message; returns null at end of stream. */
    private fun readFrame(): ByteArray? {
        while (true) {
            val type = input.read()
            if (type < 0) return null
            val length = (input.readUnsignedByte() shl 16) or (input.readUnsignedByte() shl 8) or input.readUnsignedByte()
            if (type == 0x85) continue // NetBIOS keep-alive
            if (type != 0 || length > MAX_FRAME || length < 4) throw MalformedMessageException("bad frame header")
            val frame = ByteArray(length)
            input.readFully(frame)
            return frame
        }
    }

    private fun send(frames: List<ByteArray>) {
        synchronized(writeLock) {
            for (frame in frames) {
                val n = frame.size
                output.write(byteArrayOf(0, (n ushr 16).toByte(), (n ushr 8).toByte(), n.toByte()))
                output.write(frame)
            }
            output.flush()
        }
    }

    /** Handles one frame; returns false if the connection must be dropped. */
    @Synchronized
    private fun processFrame(frame: ByteArray): Boolean {
        val r = ByteReader(frame)
        val magic = r.i32(0)
        if (magic == SMB1_MAGIC) return negotiateSmb1(frame)
        if (magic != SMB2_MAGIC) return false

        val outgoing = ArrayList<Pair<Request, Reply>>()
        var offset = 0
        var compoundFileId = -1L
        var createError = 0
        var lastSessionId = 0L
        var lastTreeId = 0
        while (true) {
            if (frame.size - offset < Smb2.HEADER_SIZE) return false
            val next = ByteReader(frame, offset).i32(20)
            val length = if (next == 0) frame.size - offset else next
            if (length < Smb2.HEADER_SIZE || offset + length > frame.size || (next != 0 && next % 8 != 0)) return false
            val req = Request(frame, offset, length)
            if (ByteReader(frame, offset).i32(0) != SMB2_MAGIC) return false
            if (req.isRelated) {
                req.sessionId = lastSessionId
                req.treeId = lastTreeId
            }
            if (!negotiated && req.command != Smb2.NEGOTIATE) return false

            val reply: Reply? = if (req.isRelated && createError != 0) {
                errorReply(createError)
            } else {
                dispatch(req, if (req.isRelated) compoundFileId else -1L)
            }
            if (reply == null && req.command == Smb2.NEGOTIATE) return false
            if (req.command == Smb2.CREATE && !req.isRelated) createError = 0
            if (reply != null) {
                if (req.command == Smb2.CREATE) {
                    if (isError(reply.status)) {
                        createError = reply.status
                    } else {
                        compoundFileId = ByteReader(reply.body).u64(72)
                    }
                }
                outgoing += req to reply
            }
            lastSessionId = req.sessionId
            lastTreeId = reply?.treeId ?: req.treeId
            if (next == 0) break
            offset += next
        }
        if (outgoing.isNotEmpty()) send(listOf(buildCompound(outgoing)))
        return !closing
    }

    @Volatile private var closing = false

    private fun isError(status: Int) = (status ushr 30) == 3

    private fun buildCompound(items: List<Pair<Request, Reply>>): ByteArray {
        val parts = items.mapIndexed { index, (req, reply) ->
            val last = index == items.lastIndex
            val w = ByteWriter(Smb2.HEADER_SIZE + reply.body.size + 8)
            writeHeader(w, req, reply)
            w.bytes(reply.body)
            if (!last) w.align(8)
            val msg = w.toByteArray()
            if (!last) putI32(msg, 20, msg.size)
            signIfNeeded(msg, req, reply)
            reply.onSent?.invoke(msg)
            msg
        }
        val out = ByteWriter(parts.sumOf { it.size })
        parts.forEach { out.bytes(it) }
        return out.toByteArray()
    }

    private fun writeHeader(w: ByteWriter, req: Request, reply: Reply) {
        var flags = Smb2.FLAGS_SERVER_TO_REDIR
        if (req.isRelated) flags = flags or Smb2.FLAGS_RELATED_OPERATIONS
        val async = reply.asyncId != 0L
        if (async) flags = flags or Smb2.FLAGS_ASYNC_COMMAND
        val credits = if (req.command == Smb2.CANCEL) 0 else grantCredits(req)
        w.u32(SMB2_MAGIC).u16(64).u16(req.creditCharge).u32(reply.status).u16(req.command)
        w.u16(credits).u32(flags).u32(0).u64(req.messageId)
        if (async) w.u64(reply.asyncId) else w.u32(req.processId).u32(reply.treeId ?: req.treeId)
        w.u64(reply.sessionId ?: req.sessionId).zeros(16)
    }

    private fun grantCredits(req: Request): Int =
        maxOf(minOf(req.creditRequest, MAX_CREDIT_GRANT), maxOf(req.creditCharge, 1))

    private fun signIfNeeded(msg: ByteArray, req: Request, reply: Reply) {
        val session = reply.signWith ?: sessions[reply.sessionId ?: req.sessionId] ?: return
        if (!session.valid || (reply.sessionId ?: req.sessionId) == 0L) return
        sign(msg, 0, msg.size, session)
    }

    private fun sign(msg: ByteArray, off: Int, len: Int, session: Session) {
        val key = session.signingKey ?: return
        putI32(msg, off + 16, ByteReader(msg, off).i32(16) or Smb2.FLAGS_SIGNED)
        java.util.Arrays.fill(msg, off + 48, off + 64, 0)
        val sig = signature(key, msg, off, len)
        System.arraycopy(sig, 0, msg, off + 48, 16)
    }

    private fun signature(key: ByteArray, msg: ByteArray, off: Int, len: Int): ByteArray =
        if (dialect >= Smb2.DIALECT_300) {
            Crypto.aesCmac(key, msg, off, len)
        } else {
            val mac = javax.crypto.Mac.getInstance("HmacSHA256")
            mac.init(javax.crypto.spec.SecretKeySpec(key, "HmacSHA256"))
            mac.update(msg, off, len)
            mac.doFinal().copyOf(16)
        }

    private fun verifySignature(req: Request, session: Session): Boolean {
        val key = session.signingKey ?: return false
        val copy = req.bytes()
        val received = copy.copyOfRange(48, 64)
        java.util.Arrays.fill(copy, 48, 64, 0)
        return Crypto.equal(received, signature(key, copy, 0, copy.size))
    }

    private fun errorReply(status: Int, data: ByteArray = ByteArray(0)): Reply {
        val w = ByteWriter().u16(9).u8(0).u8(0).u32(data.size)
        if (data.isEmpty()) w.u8(0) else w.bytes(data)
        return Reply(status, w.toByteArray())
    }

    private fun dispatch(req: Request, relatedFileId: Long): Reply? {
        try {
            when (req.command) {
                Smb2.NEGOTIATE -> return negotiate(req)
                Smb2.SESSION_SETUP -> return sessionSetup(req)
                Smb2.ECHO -> return Reply(Status.SUCCESS, ByteWriter().u16(4).u16(0).toByteArray())
                Smb2.CANCEL -> {
                    cancel(req)
                    return null
                }
            }
            val session = sessions[req.sessionId]?.takeIf { it.valid }
                ?: return errorReply(Status.USER_SESSION_DELETED)
            if (req.isSigned) {
                if (!verifySignature(req, session)) {
                    server.log("$client sent a request with a bad signature")
                    return errorReply(Status.ACCESS_DENIED)
                }
            } else {
                return errorReply(Status.ACCESS_DENIED)
            }
            if (req.command == Smb2.LOGOFF) return logoff(session)
            if (req.command == Smb2.TREE_CONNECT) return treeConnect(req, session)
            val tree = session.trees[req.treeId] ?: return errorReply(Status.NETWORK_NAME_DELETED)
            return when (req.command) {
                Smb2.TREE_DISCONNECT -> treeDisconnect(session, tree)
                Smb2.CREATE -> files.create(req, tree)
                Smb2.CLOSE -> files.close(req, findOpen(req, 8, relatedFileId, tree))
                Smb2.FLUSH -> files.flush(findOpen(req, 8, relatedFileId, tree))
                Smb2.READ -> files.read(req, findOpen(req, 16, relatedFileId, tree))
                Smb2.WRITE -> files.write(req, findOpen(req, 16, relatedFileId, tree))
                Smb2.LOCK -> {
                    findOpen(req, 8, relatedFileId, tree)
                    Reply(Status.SUCCESS, ByteWriter().u16(4).u16(0).toByteArray())
                }
                Smb2.IOCTL -> ioctl(req, tree, relatedFileId)
                Smb2.QUERY_DIRECTORY -> files.queryDirectory(req, findOpen(req, 8, relatedFileId, tree))
                Smb2.CHANGE_NOTIFY -> changeNotify(req, findOpen(req, 8, relatedFileId, tree))
                Smb2.QUERY_INFO -> files.queryInfo(req, findOpen(req, 24, relatedFileId, tree))
                Smb2.SET_INFO -> files.setInfo(req, findOpen(req, 16, relatedFileId, tree))
                else -> errorReply(Status.NOT_SUPPORTED)
            }
        } catch (e: SmbException) {
            return errorReply(e.status, e.errorData)
        } catch (e: MalformedMessageException) {
            return errorReply(Status.INVALID_PARAMETER)
        }
    }

    /** Looks up the open whose FileId is at body offset [at]. */
    private fun findOpen(req: Request, at: Int, relatedFileId: Long, tree: Tree): Open {
        val persistent = req.u64(at)
        var volatile = req.u64(at + 8)
        if (persistent == -1L && volatile == -1L && req.isRelated) volatile = relatedFileId
        val open = opens[volatile] ?: throw SmbException(Status.FILE_CLOSED)
        if (open.tree !== tree) throw SmbException(Status.FILE_CLOSED)
        return open
    }

    // ---- NEGOTIATE ----

    private fun negotiateSmb1(frame: ByteArray): Boolean {
        if (negotiated || frame.size < 35 || frame[4].toInt() != 0x72) return false
        val dialects = String(frame, 35, frame.size - 35, Charsets.US_ASCII).split('\u0000')
            .map { it.trimStart('\u0002') }
        val chosen = when {
            "SMB 2.???" in dialects -> Smb2.DIALECT_WILDCARD
            "SMB 2.002" in dialects -> Smb2.DIALECT_202
            else -> return false
        }
        if (chosen == Smb2.DIALECT_202) {
            dialect = chosen
            negotiated = true
        }
        val w = ByteWriter()
        w.u32(SMB2_MAGIC).u16(64).u16(0).u32(0).u16(Smb2.NEGOTIATE).u16(1)
        w.u32(Smb2.FLAGS_SERVER_TO_REDIR).u32(0).u64(0).u32(0).u32(0).u64(0).zeros(16)
        w.bytes(negotiateBody(chosen, emptyList()))
        send(listOf(w.toByteArray()))
        return true
    }

    private fun negotiate(req: Request): Reply? {
        if (negotiated) {
            closing = true
            return null
        }
        val count = req.u16(2)
        clientSecurityMode = req.u16(4)
        val offered = (0 until count).map { req.u16(36 + it * 2) }.toSet()
        val chosen = SUPPORTED_DIALECTS.firstOrNull { it in offered }
            ?: return errorReply(Status.NOT_SUPPORTED).also { closing = true }

        val contexts = ArrayList<Pair<Int, ByteArray>>()
        if (chosen == Smb2.DIALECT_311) {
            val ctxOffset = req.u32(28).toInt()
            val ctxCount = req.u16(32)
            var pos = ctxOffset
            var preauthOk = false
            repeat(ctxCount) {
                val type = req.r.u16(pos)
                val length = req.r.u16(pos + 2)
                if (type == CTX_PREAUTH_INTEGRITY) {
                    val algCount = req.r.u16(pos + 8)
                    preauthOk = (0 until algCount).any { req.r.u16(pos + 12 + it * 2) == HASH_SHA512 }
                }
                pos += (8 + length + 7) and 7.inv()
            }
            if (!preauthOk) return errorReply(Status.INVALID_PARAMETER).also { closing = true }
            val salt = ByteArray(32).also(server.random::nextBytes)
            contexts += CTX_PREAUTH_INTEGRITY to ByteWriter().u16(1).u16(salt.size).u16(HASH_SHA512).bytes(salt).toByteArray()
            connectionPreauth = Crypto.sha512(ByteArray(64), req.bytes())
        }
        dialect = chosen
        negotiated = true
        return Reply(Status.SUCCESS, negotiateBody(chosen, contexts), onSent = { sent ->
            connectionPreauth?.let { connectionPreauth = Crypto.sha512(it, sent) }
        })
    }

    private val securityMode = Smb2.NEGOTIATE_SIGNING_ENABLED or Smb2.NEGOTIATE_SIGNING_REQUIRED

    private fun capabilities(d: Int) = if (d >= Smb2.DIALECT_210 && d != Smb2.DIALECT_WILDCARD) Smb2.GLOBAL_CAP_LARGE_MTU else 0

    private fun negotiateBody(d: Int, contexts: List<Pair<Int, ByteArray>>): ByteArray {
        val blob = Spnego.negotiateHint()
        val io = if (d == Smb2.DIALECT_202 || d == Smb2.DIALECT_WILDCARD) 65536 else MAX_IO
        val w = ByteWriter()
        w.u16(65).u16(securityMode).u16(d).u16(contexts.size)
        w.bytes(server.serverGuid).u32(capabilities(d))
        w.u32(io).u32(io).u32(io)
        w.u64(FileTimes.now()).u64(0)
        w.u16(Smb2.HEADER_SIZE + 64).u16(blob.size)
        val ctxOffsetAt = w.size
        w.u32(0)
        w.bytes(blob)
        if (contexts.isNotEmpty()) {
            w.align(8)
            w.putU32(ctxOffsetAt, Smb2.HEADER_SIZE + w.size)
            contexts.forEachIndexed { i, (type, data) ->
                w.u16(type).u16(data.size).u32(0).bytes(data)
                if (i != contexts.lastIndex) w.align(8)
            }
        }
        return w.toByteArray()
    }

    // ---- SESSION_SETUP / LOGOFF ----

    private fun sessionSetup(req: Request): Reply {
        if (req.u8(2) and 0x01 != 0) return errorReply(Status.REQUEST_NOT_ACCEPTED) // binding
        val token = req.buffer(req.u16(12), req.u16(14))
        val session = if (req.sessionId == 0L) {
            if (sessions.size >= MAX_SESSIONS) return errorReply(Status.INSUFFICIENT_RESOURCES)
            Session(server.newSessionId(), Ntlm(config.username, config.password, config.serverName, server.random))
                .also {
                    sessions[it.id] = it
                    it.preauthHash = connectionPreauth
                }
        } else {
            sessions[req.sessionId] ?: return errorReply(Status.USER_SESSION_DELETED)
        }
        if (session.ntlm == null) {
            // Re-authentication of an established session.
            session.ntlm = Ntlm(config.username, config.password, config.serverName, server.random)
        }
        val ntlm = session.ntlm!!
        if (dialect == Smb2.DIALECT_311) {
            session.preauthHash = Crypto.sha512(session.preauthHash ?: ByteArray(64), req.bytes())
        }

        val parsed = try {
            Spnego.parse(token)
        } catch (e: MalformedMessageException) {
            return failLogon(session)
        }
        val message = parsed.mechToken
        if (parsed.mechTypes != null) {
            session.mechTypes = parsed.mechTypes
            session.ntlmPreferred = parsed.ntlmPreferred
        }
        val type = message?.let(Ntlm::messageType) ?: -1
        when {
            type == 1 -> {
                val challenge = ntlm.challenge(message!!)
                val out = if (parsed.raw) {
                    challenge
                } else {
                    Spnego.response(Spnego.ACCEPT_INCOMPLETE, true, challenge, null)
                }
                return moreProcessing(session, out)
            }
            type == -1 && !parsed.raw && parsed.mechTypes != null -> {
                // The client's optimistic token is for another mechanism; ask for NTLM.
                return moreProcessing(session, Spnego.response(Spnego.ACCEPT_INCOMPLETE, true, null, null))
            }
            type == 3 -> {
                val result = ntlm.authenticate(message!!) ?: return failLogon(session)
                session.ntlm = null
                session.user = result.user
                session.signingKey = when {
                    dialect == Smb2.DIALECT_311 ->
                        Crypto.smb3Kdf(result.sessionKey, "SMBSigningKey\u0000".toByteArray(), session.preauthHash!!)
                    dialect >= Smb2.DIALECT_300 ->
                        Crypto.smb3Kdf(result.sessionKey, "SMB2AESCMAC\u0000".toByteArray(), "SmbSign\u0000".toByteArray())
                    else -> result.sessionKey
                }
                session.valid = true
                authFailures = 0
                server.log("$client logged in as ${result.user}")
                val out = if (parsed.raw) {
                    ByteArray(0)
                } else {
                    val mechTypes = session.mechTypes
                    val needMic = mechTypes != null && (parsed.mechListMic != null || !session.ntlmPreferred)
                    Spnego.response(Spnego.ACCEPT_COMPLETED, false, null, if (needMic) ntlm.mic(result, mechTypes!!) else null)
                }
                return Reply(Status.SUCCESS, sessionSetupBody(out), sessionId = session.id, signWith = session)
            }
            else -> return failLogon(session)
        }
    }

    private fun moreProcessing(session: Session, token: ByteArray) = Reply(
        Status.MORE_PROCESSING_REQUIRED,
        sessionSetupBody(token),
        sessionId = session.id,
        onSent = { sent ->
            if (dialect == Smb2.DIALECT_311) session.preauthHash = Crypto.sha512(session.preauthHash!!, sent)
        },
    )

    private fun sessionSetupBody(token: ByteArray): ByteArray =
        ByteWriter().u16(9).u16(0).u16(Smb2.HEADER_SIZE + 8).u16(token.size).bytes(token).toByteArray()

    private fun failLogon(session: Session): Reply {
        if (!session.valid) sessions.remove(session.id)
        session.ntlm = null
        server.log("$client failed to log in")
        authFailures++
        // Slow down password guessing; repeated failures drop the connection.
        Thread.sleep(AUTH_FAILURE_DELAY_MS)
        if (authFailures >= MAX_AUTH_FAILURES) closing = true
        return errorReply(Status.LOGON_FAILURE)
    }

    private fun logoff(session: Session): Reply {
        session.trees.values.toList().forEach { treeDisconnect(session, it) }
        val reply = Reply(Status.SUCCESS, ByteWriter().u16(4).u16(0).toByteArray(), signWith = session)
        sessions.remove(session.id)
        return reply
    }

    // ---- TREE_CONNECT / TREE_DISCONNECT ----

    private fun treeConnect(req: Request, session: Session): Reply {
        val path = String(req.buffer(req.u16(4), req.u16(6)), Charsets.UTF_16LE)
        val name = path.substringAfterLast('\\')
        val fs = when {
            name.equals(config.shareName, ignoreCase = true) -> server.fs
            name.equals("IPC$", ignoreCase = true) -> null
            else -> return errorReply(Status.BAD_NETWORK_NAME)
        }
        if (session.trees.size >= MAX_TREES) return errorReply(Status.INSUFFICIENT_RESOURCES)
        val id = server.newTreeId()
        session.trees[id] = Tree(id, session, fs)
        val maximal = when {
            fs == null -> Smb2.FILE_ALL_ACCESS
            fs.readOnly -> Smb2.READ_ONLY_ACCESS
            else -> Smb2.FILE_ALL_ACCESS
        }
        val body = ByteWriter()
            .u16(16)
            .u8(if (fs == null) 0x02 else 0x01) // pipe or disk
            .u8(0)
            .u32(0x00000030) // SMB2_SHAREFLAG_NO_CACHING
            .u32(0)
            .u32(maximal)
            .toByteArray()
        return Reply(Status.SUCCESS, body, treeId = id)
    }

    private fun treeDisconnect(session: Session, tree: Tree): Reply {
        opens.values.filter { it.tree === tree }.forEach { closeOpen(it) }
        session.trees.remove(tree.id)
        return Reply(Status.SUCCESS, ByteWriter().u16(4).u16(0).toByteArray())
    }

    fun addOpen(open: Open) {
        if (opens.size >= MAX_OPENS) throw SmbException(Status.INSUFFICIENT_RESOURCES)
        opens[open.id] = open
    }

    fun closeOpen(open: Open) {
        opens.remove(open.id)
        open.notify?.let { completeNotify(it, Status.NOTIFY_CLEANUP) }
        open.notify = null
        files.release(open)
    }

    // ---- IOCTL ----

    private fun ioctl(req: Request, tree: Tree, relatedFileId: Long): Reply {
        val ctlCode = req.i32(4)
        val input = req.buffer(req.u32(24).toInt(), req.u32(28).toInt())
        val maxOut = req.u32(44).toInt()
        val output: ByteArray = when (ctlCode) {
            Smb2.FSCTL_VALIDATE_NEGOTIATE_INFO -> {
                ByteWriter().u32(capabilities(dialect)).bytes(server.serverGuid).u16(securityMode).u16(dialect)
                    .toByteArray()
            }
            Smb2.FSCTL_PIPE_TRANSCEIVE -> {
                val open = findOpen(req, 8, relatedFileId, tree)
                val pipe = open.pipe ?: throw SmbException(Status.INVALID_DEVICE_REQUEST)
                pipe.write(input)
                val (data, more) = pipe.read(maxOut)
                return ioctlReply(ctlCode, req, data, if (more) Status.BUFFER_OVERFLOW else Status.SUCCESS)
            }
            Smb2.FSCTL_DFS_GET_REFERRALS, Smb2.FSCTL_DFS_GET_REFERRALS_EX ->
                throw SmbException(Status.FS_DRIVER_REQUIRED)
            Smb2.FSCTL_SET_SPARSE -> {
                findOpen(req, 8, relatedFileId, tree)
                ByteArray(0)
            }
            else -> throw SmbException(Status.NOT_SUPPORTED)
        }
        if (output.size > maxOut) throw SmbException(Status.BUFFER_TOO_SMALL)
        return ioctlReply(ctlCode, req, output, Status.SUCCESS)
    }

    private fun ioctlReply(ctlCode: Int, req: Request, output: ByteArray, status: Int): Reply {
        val offset = Smb2.HEADER_SIZE + 48
        val body = ByteWriter()
            .u16(49).u16(0).u32(ctlCode)
            .u64(req.u64(8)).u64(req.u64(16))
            .u32(offset).u32(0)
            .u32(offset).u32(output.size)
            .u32(0).u32(0)
            .bytes(output)
            .toByteArray()
        return Reply(status, body)
    }

    // ---- CHANGE_NOTIFY / CANCEL ----

    private fun changeNotify(req: Request, open: Open): Reply {
        if (!open.isDirectory) throw SmbException(Status.INVALID_PARAMETER)
        // Change tracking isn't implemented: the request stays pending until it is cancelled
        // or the directory is closed, which is valid behaviour for a quiet directory.
        open.notify?.let { completeNotify(it, Status.CANCELLED) }
        val asyncId = nextAsyncId++
        open.notify = PendingNotify(req.messageId, asyncId, req.sessionId, req.creditCharge)
        val w = ByteWriter().u16(9).u8(0).u8(0).u32(0).u8(0)
        return Reply(Status.PENDING, w.toByteArray(), asyncId = asyncId)
    }

    private fun cancel(req: Request) {
        val open = opens.values.firstOrNull { o ->
            val n = o.notify ?: return@firstOrNull false
            if (req.isAsync) n.asyncId == req.asyncId else n.messageId == req.messageId && n.sessionId == req.sessionId
        } ?: return
        val n = open.notify ?: return
        open.notify = null
        completeNotify(n, Status.CANCELLED)
    }

    private fun completeNotify(n: PendingNotify, status: Int) {
        val body = if (status == Status.NOTIFY_CLEANUP) {
            ByteWriter().u16(9).u16(Smb2.HEADER_SIZE + 8).u32(0).u8(0).toByteArray()
        } else {
            ByteWriter().u16(9).u8(0).u8(0).u32(0).u8(0).toByteArray()
        }
        val w = ByteWriter()
        w.u32(SMB2_MAGIC).u16(64).u16(n.creditCharge).u32(status).u16(Smb2.CHANGE_NOTIFY).u16(0)
        w.u32(Smb2.FLAGS_SERVER_TO_REDIR or Smb2.FLAGS_ASYNC_COMMAND).u32(0).u64(n.messageId)
        w.u64(n.asyncId).u64(n.sessionId).zeros(16)
        w.bytes(body)
        val msg = w.toByteArray()
        sessions[n.sessionId]?.takeIf { it.valid }?.let { sign(msg, 0, msg.size, it) }
        runCatching { send(listOf(msg)) }
    }

    companion object {
        const val SMB2_MAGIC = 0x424D53FE
        const val SMB1_MAGIC = 0x424D53FF
        const val MAX_IO = 1024 * 1024
        const val MAX_FRAME = MAX_IO + 64 * 1024
        const val MAX_CREDIT_GRANT = 512
        const val MAX_SESSIONS = 16
        const val MAX_TREES = 64
        const val MAX_OPENS = 4096
        const val MAX_AUTH_FAILURES = 5
        const val AUTH_FAILURE_DELAY_MS = 1000L
        const val PRE_AUTH_TIMEOUT_MS = 30_000
        const val IDLE_TIMEOUT_MS = 15 * 60_000
        const val CTX_PREAUTH_INTEGRITY = 1
        const val HASH_SHA512 = 1

        val SUPPORTED_DIALECTS = listOf(
            Smb2.DIALECT_311, Smb2.DIALECT_302, Smb2.DIALECT_300, Smb2.DIALECT_210, Smb2.DIALECT_202,
        )

        fun putI32(b: ByteArray, at: Int, v: Int) {
            b[at] = v.toByte()
            b[at + 1] = (v ushr 8).toByte()
            b[at + 2] = (v ushr 16).toByte()
            b[at + 3] = (v ushr 24).toByte()
        }
    }
}
