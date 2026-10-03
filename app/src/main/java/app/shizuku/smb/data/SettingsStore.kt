package app.shizuku.smb.data

import android.content.Context

/** Persists the share configuration in app-private preferences. */
class SettingsStore(context: Context) {
    private val prefs = context.getSharedPreferences("settings", Context.MODE_PRIVATE)

    fun load(): ShareConfig = ShareConfig(
        sharePath = prefs.getString(KEY_PATH, null) ?: ShareConfig.DEFAULT_PATH,
        shareName = prefs.getString(KEY_NAME, null) ?: ShareConfig.DEFAULT_SHARE_NAME,
        port = prefs.getInt(KEY_PORT, ShareConfig.DEFAULT_PORT),
        username = prefs.getString(KEY_USER, null) ?: "",
        password = prefs.getString(KEY_PASSWORD, null) ?: "",
        readOnly = prefs.getBoolean(KEY_READ_ONLY, true),
    )

    fun save(config: ShareConfig) {
        prefs.edit()
            .putString(KEY_PATH, config.sharePath)
            .putString(KEY_NAME, config.shareName)
            .putInt(KEY_PORT, config.port)
            .putString(KEY_USER, config.username)
            .putString(KEY_PASSWORD, config.password)
            .putBoolean(KEY_READ_ONLY, config.readOnly)
            .apply()
    }

    private companion object {
        const val KEY_PATH = "share_path"
        const val KEY_NAME = "share_name"
        const val KEY_PORT = "port"
        const val KEY_USER = "username"
        const val KEY_PASSWORD = "password"
        const val KEY_READ_ONLY = "read_only"
    }
}
