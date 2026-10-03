package app.shizuku.smb.service

import android.os.Process
import app.shizuku.smb.IShareService
import app.shizuku.smb.data.ShareConfig
import java.io.File
import java.io.IOException
import java.net.InetSocketAddress
import java.net.ServerSocket
import kotlin.system.exitProcess

/**
 * Shizuku user service. Shizuku starts this class in its own process running as the shell
 * (or root) uid, which is what lets it read folders the app itself can't reach.
 *
 * The SMB protocol isn't implemented yet: [start] checks that the folder is accessible and the
 * port can be bound from this process, then reports that the server is ready to be wired up.
 */
class ShareService : IShareService.Stub() {

    @Volatile private var running = false
    @Volatile private var status = "Idle"
    private val myUid = Process.myUid()

    override fun destroy() {
        stop()
        exitProcess(0)
    }

    override fun getUid(): Int = myUid

    @Synchronized
    override fun start(
        sharePath: String,
        shareName: String,
        port: Int,
        username: String,
        password: String,
        readOnly: Boolean,
    ): String? {
        if (running) return "Server is already running"
        val config = ShareConfig(sharePath, shareName, port, username, password, readOnly)
        config.validate().firstOrNull()?.let { return fail(it) }

        val folder = File(sharePath)
        when {
            !folder.exists() -> return fail("Folder does not exist: $sharePath")
            !folder.isDirectory -> return fail("Not a folder: $sharePath")
            !folder.canRead() -> return fail("Folder is not readable as uid $myUid: $sharePath")
            !readOnly && !folder.canWrite() ->
                return fail("Folder is not writable as uid $myUid: $sharePath")
        }

        try {
            ServerSocket().use { it.bind(InetSocketAddress(port)) }
        } catch (e: IOException) {
            return fail("Cannot listen on port $port as uid $myUid: ${e.message}")
        }

        running = true
        status = "Checks passed for \\\\device\\$shareName on port $port " +
            "(uid $myUid). SMB protocol not implemented yet."
        return null
    }

    @Synchronized
    override fun stop() {
        running = false
        status = "Stopped"
    }

    override fun isRunning(): Boolean = running

    override fun getStatus(): String = status

    private fun fail(message: String): String {
        status = message
        return message
    }
}
