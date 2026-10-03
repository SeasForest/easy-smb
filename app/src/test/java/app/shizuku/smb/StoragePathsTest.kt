package app.shizuku.smb

import app.shizuku.smb.data.StoragePaths
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class StoragePathsTest {
    private val base = "content://com.android.externalstorage.documents/tree/"

    @Test
    fun mapsPrimaryRoot() {
        assertEquals("/storage/emulated/0", StoragePaths.treeUriToPath("${base}primary%3A"))
    }

    @Test
    fun mapsPrimarySubfolder() {
        assertEquals(
            "/storage/emulated/0/Download/My Files",
            StoragePaths.treeUriToPath("${base}primary%3ADownload%2FMy%20Files"),
        )
    }

    @Test
    fun keepsLiteralPlusInFolderNames() {
        assertEquals("/storage/emulated/0/C++", StoragePaths.treeUriToPath("${base}primary%3AC++"))
    }

    @Test
    fun mapsRemovableVolume() {
        assertEquals("/storage/1234-ABCD/Music", StoragePaths.treeUriToPath("${base}1234-ABCD%3AMusic"))
    }

    @Test
    fun rejectsOtherProviders() {
        assertNull(StoragePaths.treeUriToPath("content://com.example.provider/tree/x"))
    }
}
