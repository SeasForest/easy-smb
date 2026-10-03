package app.shizuku.smb.server

import java.io.File
import java.io.IOException
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.security.SecureRandom
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong

/** Settings for the single share the server exposes. */
data class SmbConfig(
    val rootPath: String,
    val shareName: String,
    val username: String,
    val password: String,
    val readOnly: Boolean,
    val port: Int,
    /** NetBIOS-style name the server reports during authentication. */
    val serverName: String = "EASYSMB",
) {
    override fun toString(): String =
        "SmbConfig(rootPath=$rootPath, shareName=$shareName, username=$username, readOnly=$readOnly, port=$port)"
}

/**
 * An SMB 2/3 file server for one folder (dialects 2.0.2 to 3.1.1, NTLMv2 authentication,
 * required message signing). Each client connection is served on its own thread.
 */
class SmbServer(
    val config: SmbConfig,
    private val logger: (String) -> Unit = {},
) {
    internal val random = SecureRandom()
    internal val serverGuid = ByteArray(16).also(random::nextBytes)
    internal lateinit var fs: ShareFs
        private set

    private var serverSocket: ServerSocket? = null
    private val connections = java.util.Collections.synchronizedSet(HashSet<Connection>())
    private val sessionIds = AtomicLong(random.nextInt(0x7FFF).toLong() shl 32)
    private val treeIds = AtomicInteger(1)
    private val fileIds = AtomicLong(1)

    @Volatile
    var isRunning = false
        private set

    /** The port actually bound; useful when [SmbConfig.port] is 0. */
    val localPort: Int get() = serverSocket?.localPort ?: -1

    val connectionCount: Int get() = connections.size

    /** Binds the port and starts accepting clients. Throws [IOException] if that fails. */
    @Synchronized
    fun start() {
        check(!isRunning) { "already running" }
        val root = File(config.rootPath)
        if (!root.isDirectory) throw IOException("Not a folder: ${config.rootPath}")
        fs = ShareFs(config.rootPath, config.readOnly)
        val socket = ServerSocket()
        try {
            socket.reuseAddress = true
            socket.bind(InetSocketAddress(config.port), 50)
        } catch (e: IOException) {
            socket.close()
            throw e
        }
        serverSocket = socket
        isRunning = true
        Thread({ acceptLoop(socket) }, "smb-accept").apply { isDaemon = true }.start()
        log("Listening on port ${socket.localPort}, sharing ${config.rootPath} as ${config.shareName}")
    }

    @Synchronized
    fun stop() {
        if (!isRunning) return
        isRunning = false
        runCatching { serverSocket?.close() }
        serverSocket = null
        synchronized(connections) { connections.toList() }.forEach { it.close() }
        log("Stopped")
    }

    private fun acceptLoop(socket: ServerSocket) {
        while (isRunning) {
            val client: Socket = try {
                socket.accept()
            } catch (e: IOException) {
                if (isRunning) log("Accept failed: ${e.message}")
                break
            }
            if (connections.size >= MAX_CONNECTIONS) {
                log("Too many connections; rejecting ${client.remoteSocketAddress}")
                runCatching { client.close() }
                continue
            }
            val connection = try {
                Connection(this, client)
            } catch (e: IOException) {
                runCatching { client.close() }
                continue
            }
            connections += connection
            log("Client connected: ${client.remoteSocketAddress}")
            Thread(connection, "smb-client").apply { isDaemon = true }.start()
        }
    }

    internal fun onConnectionClosed(connection: Connection) {
        if (connections.remove(connection)) log("Client disconnected")
    }

    internal fun log(message: String) = logger(message)

    internal fun newSessionId(): Long = sessionIds.incrementAndGet()

    internal fun newTreeId(): Int = treeIds.incrementAndGet()

    internal fun newFileId(): Long = fileIds.incrementAndGet()

    internal fun shareListings(): List<ShareListing> = listOf(
        ShareListing(config.shareName, SrvsvcPipe.STYPE_DISKTREE, if (config.readOnly) "Read-only" else ""),
        ShareListing("IPC$", SrvsvcPipe.STYPE_IPC_SPECIAL, "IPC Service"),
    )

    private companion object {
        const val MAX_CONNECTIONS = 32
    }
}
