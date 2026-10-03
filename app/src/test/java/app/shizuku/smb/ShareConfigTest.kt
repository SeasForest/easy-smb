package app.shizuku.smb

import app.shizuku.smb.data.ShareConfig
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class ShareConfigTest {
    private val valid = ShareConfig(username = "alice", password = "correct-horse")

    @Test
    fun validConfigHasNoProblems() {
        assertEquals(emptyList<String>(), valid.validate())
    }

    @Test
    fun rejectsRelativePath() {
        assertTrue(valid.copy(sharePath = "Download").validate().isNotEmpty())
    }

    @Test
    fun rejectsBadShareName() {
        assertTrue(valid.copy(shareName = "").validate().isNotEmpty())
        assertTrue(valid.copy(shareName = "a/b").validate().isNotEmpty())
    }

    @Test
    fun rejectsOutOfRangePort() {
        assertTrue(valid.copy(port = 0).validate().isNotEmpty())
        assertTrue(valid.copy(port = 70000).validate().isNotEmpty())
    }

    @Test
    fun requiresCredentials() {
        assertTrue(valid.copy(username = "").validate().isNotEmpty())
        assertTrue(valid.copy(username = "a b").validate().isNotEmpty())
        assertTrue(valid.copy(password = "short").validate().isNotEmpty())
    }
}
