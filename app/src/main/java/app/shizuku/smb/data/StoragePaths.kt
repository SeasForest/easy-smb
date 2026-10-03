package app.shizuku.smb.data

import java.net.URLDecoder

object StoragePaths {
    private const val EXTERNAL_STORAGE_AUTHORITY = "com.android.externalstorage.documents"

    /**
     * Converts a document-tree URI from the system folder picker into a filesystem path that
     * the Shizuku service can open, e.g.
     * `content://com.android.externalstorage.documents/tree/primary%3ADownload` ->
     * `/storage/emulated/0/Download`. Returns null for providers we can't map.
     */
    fun treeUriToPath(uri: String): String? {
        val prefix = "content://$EXTERNAL_STORAGE_AUTHORITY/tree/"
        if (!uri.startsWith(prefix)) return null
        val docId = URLDecoder.decode(uri.removePrefix(prefix).substringBefore('/'), "UTF-8")
        val volume = docId.substringBefore(':')
        val relative = docId.substringAfter(':', "").trim('/')
        val root = when {
            volume.equals("primary", ignoreCase = true) -> "/storage/emulated/0"
            volume.isNotEmpty() && volume != "home" -> "/storage/$volume"
            else -> return null
        }
        return if (relative.isEmpty()) root else "$root/$relative"
    }
}
