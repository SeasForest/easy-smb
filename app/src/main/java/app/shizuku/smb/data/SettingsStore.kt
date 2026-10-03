package app.shizuku.smb.data

import android.content.Context

/** Persists the share configuration in app-private preferences. */
class SettingsStore(context: Context) {
    private val prefs = context.getSharedPreferences("settings", Context.MODE_PRIVATE)
    private val cipher = SecretCipher()

    /** Whether the user wants the server on; used to reattach or restart it on app launch. */
    var serverEnabled: Boolean
        get() = prefs.getBoolean(KEY_SERVER_ENABLED, false)
        set(value) = prefs.edit().putBoolean(KEY_SERVER_ENABLED, value).apply()

    fun load(): ShareConfig = ShareConfig(
        sharePath = prefs.getString(KEY_PATH, null) ?: ShareConfig.DEFAULT_PATH,
        shareName = prefs.getString(KEY_NAME, null) ?: ShareConfig.DEFAULT_SHARE_NAME,
        port = prefs.getInt(KEY_PORT, ShareConfig.DEFAULT_PORT),
        username = prefs.getString(KEY_USER, null) ?: "",
        password = loadPassword(),
        readOnly = prefs.getBoolean(KEY_READ_ONLY, true),
    )

    fun save(config: ShareConfig) {
        prefs.edit()
            .putString(KEY_PATH, config.sharePath)
            .putString(KEY_NAME, config.shareName)
            .putInt(KEY_PORT, config.port)
            .putString(KEY_USER, config.username)
            .putString(KEY_PASSWORD_ENCRYPTED, config.password.takeIf { it.isNotEmpty() }?.let(cipher::encrypt))
            .remove(KEY_LEGACY_PASSWORD)
            .putBoolean(KEY_READ_ONLY, config.readOnly)
            .apply()
    }

    private fun loadPassword(): String {
        prefs.getString(KEY_PASSWORD_ENCRYPTED, null)?.let { return cipher.decrypt(it).orEmpty() }
        // Migrate a password saved in plain text by an earlier build.
        val legacy = prefs.getString(KEY_LEGACY_PASSWORD, null) ?: return ""
        prefs.edit()
            .putString(KEY_PASSWORD_ENCRYPTED, cipher.encrypt(legacy))
            .remove(KEY_LEGACY_PASSWORD)
            .apply()
        return legacy
    }

    private companion object {
        const val KEY_PATH = "share_path"
        const val KEY_NAME = "share_name"
        const val KEY_PORT = "port"
        const val KEY_USER = "username"
        const val KEY_LEGACY_PASSWORD = "password"
        const val KEY_PASSWORD_ENCRYPTED = "password_encrypted"
        const val KEY_READ_ONLY = "read_only"
        const val KEY_SERVER_ENABLED = "server_enabled"
    }
}
