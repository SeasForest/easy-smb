package app.shizuku.smb.server

/** Human-readable descriptions of requests and statuses for the activity log. */
internal object Diagnostics {
    private val COMMANDS = arrayOf(
        "NEGOTIATE", "SESSION_SETUP", "LOGOFF", "TREE_CONNECT", "TREE_DISCONNECT", "CREATE", "CLOSE",
        "FLUSH", "READ", "WRITE", "LOCK", "IOCTL", "CANCEL", "ECHO", "QUERY_DIRECTORY", "CHANGE_NOTIFY",
        "QUERY_INFO", "SET_INFO", "OPLOCK_BREAK",
    )

    private val STATUSES = mapOf(
        Status.SUCCESS to "SUCCESS",
        Status.BUFFER_OVERFLOW to "BUFFER_OVERFLOW",
        Status.NO_MORE_FILES to "NO_MORE_FILES",
        Status.INVALID_INFO_CLASS to "INVALID_INFO_CLASS",
        Status.INFO_LENGTH_MISMATCH to "INFO_LENGTH_MISMATCH",
        Status.INVALID_PARAMETER to "INVALID_PARAMETER",
        Status.NO_SUCH_FILE to "NO_SUCH_FILE",
        Status.INVALID_DEVICE_REQUEST to "INVALID_DEVICE_REQUEST",
        Status.END_OF_FILE to "END_OF_FILE",
        Status.ACCESS_DENIED to "ACCESS_DENIED",
        Status.BUFFER_TOO_SMALL to "BUFFER_TOO_SMALL",
        Status.OBJECT_NAME_INVALID to "OBJECT_NAME_INVALID",
        Status.OBJECT_NAME_NOT_FOUND to "OBJECT_NAME_NOT_FOUND",
        Status.OBJECT_NAME_COLLISION to "OBJECT_NAME_COLLISION",
        Status.OBJECT_PATH_NOT_FOUND to "OBJECT_PATH_NOT_FOUND",
        Status.EAS_NOT_SUPPORTED to "EAS_NOT_SUPPORTED",
        Status.LOGON_FAILURE to "LOGON_FAILURE",
        Status.DISK_FULL to "DISK_FULL",
        Status.INSUFFICIENT_RESOURCES to "INSUFFICIENT_RESOURCES",
        Status.FILE_IS_A_DIRECTORY to "FILE_IS_A_DIRECTORY",
        Status.NOT_SUPPORTED to "NOT_SUPPORTED",
        Status.NETWORK_NAME_DELETED to "NETWORK_NAME_DELETED",
        Status.BAD_NETWORK_NAME to "BAD_NETWORK_NAME",
        Status.REQUEST_NOT_ACCEPTED to "REQUEST_NOT_ACCEPTED",
        Status.INTERNAL_ERROR to "INTERNAL_ERROR",
        Status.DIRECTORY_NOT_EMPTY to "DIRECTORY_NOT_EMPTY",
        Status.NOT_A_DIRECTORY to "NOT_A_DIRECTORY",
        Status.CANCELLED to "CANCELLED",
        Status.FILE_CLOSED to "FILE_CLOSED",
        Status.FS_DRIVER_REQUIRED to "FS_DRIVER_REQUIRED",
        Status.USER_SESSION_DELETED to "USER_SESSION_DELETED",
        Status.PIPE_EMPTY to "PIPE_EMPTY",
    )

    fun statusName(status: Int): String = STATUSES[status] ?: "0x%08X".format(status)

    fun dialectName(d: Int): String = when (d) {
        Smb2.DIALECT_WILDCARD -> "2.???"
        else -> "%d.%d.%d".format(d shr 8, (d shr 4) and 0xF, d and 0xF)
    }

    /** Failures worth showing; routine outcomes such as the end of a listing are skipped. */
    fun worthLogging(status: Int): Boolean = (status ushr 30) == 3 &&
        status != Status.MORE_PROCESSING_REQUIRED && status != Status.LOGON_FAILURE

    fun describe(req: Request): String {
        val name = COMMANDS.getOrNull(req.command) ?: "COMMAND_0x%02X".format(req.command)
        val detail = runCatching {
            when (req.command) {
                Smb2.CREATE -> "'" + String(req.buffer(req.u16(44), req.u16(46)), Charsets.UTF_16LE) +
                    "' disposition=${req.i32(36)} options=0x%X access=0x%X".format(req.i32(40), req.i32(24))
                Smb2.TREE_CONNECT -> String(req.buffer(req.u16(4), req.u16(6)), Charsets.UTF_16LE)
                Smb2.QUERY_INFO -> "type=${req.u8(2)} class=${req.u8(3)} max=${req.u32(4)}"
                Smb2.SET_INFO -> "type=${req.u8(2)} class=${req.u8(3)}"
                Smb2.QUERY_DIRECTORY -> "class=${req.u8(2)} flags=0x%X '".format(req.u8(3)) +
                    String(req.buffer(req.u16(24), req.u16(26)), Charsets.UTF_16LE) + "'"
                Smb2.IOCTL -> "ctl=0x%08X".format(req.i32(4))
                Smb2.READ, Smb2.WRITE -> "length=${req.u32(4)} offset=${req.u64(8)}"
                else -> ""
            }
        }.getOrDefault("?")
        val related = if (req.isRelated) " (related)" else ""
        return "$name $detail$related".trimEnd()
    }
}
