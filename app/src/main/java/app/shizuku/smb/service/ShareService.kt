package app.shizuku.smb.service

import android.os.Process
import android.util.Log
import app.shizuku.smb.IShareService
import app.shizuku.smb.data.ShareConfig
import app.shizuku.smb.server.SmbConfig
import app.shizuku.smb.server.SmbServer
import java.io.File
import java.io.IOException
import java.text.SimpleDateFormat
import java.util.ArrayDeque
import java.util.Date
import java.util.Locale
import kotlin.system.exitProcess

/**
 * Shizuku user service. Shizuku starts this class in its own process running as the shell
 * (or root) uid, which is what lets it read folders the app itself can't reach. It hosts the
 * SMB server.
 */
class ShareService : IShareService.Stub() {

    @Volatile private var server: SmbServer? = null
    @Volatile private var status = "Idle"
    private val myUid = Process.myUid()
    private val logLines = ArrayDeque<String>()
    private val timeFormat = SimpleDateFormat("HH:mm:ss", Locale.US)

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
        if (server?.isRunning == true) return "Server is already running"
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

        val smb = SmbServer(
            SmbConfig(
                rootPath = sharePath,
                shareName = shareName,
                username = username,
                password = password,
                readOnly = readOnly,
                port = port,
            ),
            logger = ::addLog,
        )
        try {
            smb.start()
        } catch (e: IOException) {
            return fail("Cannot listen on port $port as uid $myUid: ${e.message}")
        }
        server = smb
        status = "Sharing $sharePath" + if (readOnly) " (read-only)" else ""
        return null
    }

    @Synchronized
    override fun stop() {
        server?.stop()
        server = null
        status = "Stopped"
    }

    override fun isRunning(): Boolean = server?.isRunning == true

    override fun getStatus(): String = status

    override fun getClientCount(): Int = server?.connectionCount ?: 0

    override fun getLog(): String = synchronized(logLines) { logLines.joinToString("\n") }

    private fun addLog(message: String) {
        Log.i(TAG, message)
        synchronized(logLines) {
            // SimpleDateFormat isn't thread-safe; clients log from their own threads.
            logLines.addLast(timeFormat.format(Date()) + "  " + message)
            while (logLines.size > MAX_LOG_LINES) logLines.removeFirst()
        }
    }

    private fun fail(message: String): String {
        status = message
        addLog(message)
        return message
    }

    private companion object {
        const val TAG = "EasySmb"
        const val MAX_LOG_LINES = 300
    }
}
