package app.shizuku.smb.data

/** Everything needed to serve the single v1 share. */
data class ShareConfig(
    val sharePath: String = DEFAULT_PATH,
    val shareName: String = DEFAULT_SHARE_NAME,
    val port: Int = DEFAULT_PORT,
    val username: String = "",
    val password: String = "",
    val readOnly: Boolean = true,
) {
    /** Returns a list of problems; empty means the config can be used to start the server. */
    fun validate(): List<String> = buildList {
        if (!sharePath.startsWith("/")) add("Folder must be an absolute path")
        if (!SHARE_NAME_REGEX.matches(shareName)) {
            add("Share name must be 1-80 letters, digits, '-', '_' or '.'")
        }
        if (port !in MIN_PORT..MAX_PORT) add("Port must be between $MIN_PORT and $MAX_PORT")
        if (username.isBlank()) add("Username is required")
        if (username.any { it in INVALID_USER_CHARS }) add("Username contains invalid characters")
        if (password.length < MIN_PASSWORD_LENGTH) {
            add("Password must be at least $MIN_PASSWORD_LENGTH characters")
        }
    }

    companion object {
        const val DEFAULT_PATH = "/storage/emulated/0"
        const val DEFAULT_SHARE_NAME = "share"
        const val DEFAULT_PORT = 4445
        const val MIN_PORT = 1
        const val MAX_PORT = 65535
        const val MIN_PASSWORD_LENGTH = 8

        private val SHARE_NAME_REGEX = Regex("^[A-Za-z0-9._-]{1,80}$")
        private const val INVALID_USER_CHARS = "\"/\\[]:;|=,+*?<>@ "
    }
}
