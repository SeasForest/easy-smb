package app.shizuku.smb.server

import com.hierynomus.msdtyp.AccessMask
import com.hierynomus.mserref.NtStatus
import com.hierynomus.msfscc.FileAttributes
import com.hierynomus.msfscc.fileinformation.FileStandardInformation
import com.hierynomus.mssmb2.SMB2CreateDisposition
import com.hierynomus.mssmb2.SMB2CreateOptions
import com.hierynomus.mssmb2.SMB2Dialect
import com.hierynomus.mssmb2.SMB2ShareAccess
import com.hierynomus.mssmb2.SMBApiException
import com.hierynomus.smbj.SMBClient
import com.hierynomus.smbj.auth.AuthenticationContext
import com.hierynomus.smbj.session.Session
import com.hierynomus.smbj.share.DiskShare
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File
import java.nio.file.Files
import java.util.EnumSet
import java.util.Random
import java.util.concurrent.TimeUnit
import com.hierynomus.smbj.SmbConfig as ClientConfig

/** Runs the server on a random port and drives it with smbj, an independent SMB client. */
class SmbServerTest {
    @get:Rule
    val tmp = TemporaryFolder()

    private lateinit var root: File
    private var server: SmbServer? = null
    private val clients = ArrayList<SMBClient>()

    @Before
    fun setUp() {
        root = tmp.newFolder("share")
        File(root, "hello.txt").writeText("hello world")
        File(root, "docs").mkdir()
        File(root, "docs/readme.md").writeText("# readme")
    }

    @After
    fun tearDown() {
        clients.forEach { it.close() }
        server?.stop()
    }

    private fun start(readOnly: Boolean = false): SmbServer {
        val s = SmbServer(SmbConfig(root.path, "share", USER, PASSWORD, readOnly, 0))
        s.start()
        server = s
        return s
    }

    private fun connect(
        dialect: SMB2Dialect = SMB2Dialect.SMB_3_1_1,
        user: String = USER,
        password: String = PASSWORD,
    ): Session {
        val config = ClientConfig.builder()
            .withDialects(dialect)
            .withSigningRequired(true)
            .withTimeout(10, TimeUnit.SECONDS)
            .build()
        val client = SMBClient(config).also(clients::add)
        val connection = client.connect("127.0.0.1", server!!.localPort)
        return connection.authenticate(AuthenticationContext(user, password.toCharArray(), "WORKGROUP"))
    }

    private fun share(session: Session) = session.connectShare("share") as DiskShare

    @Test
    fun everyDialectCanListAndRead() {
        start()
        for (dialect in listOf(SMB2Dialect.SMB_2_0_2, SMB2Dialect.SMB_2_1, SMB2Dialect.SMB_3_0, SMB2Dialect.SMB_3_0_2, SMB2Dialect.SMB_3_1_1)) {
            val share = share(connect(dialect))
            val names = share.list("").map { it.fileName }.toSet()
            assertTrue("$dialect: $names", names.containsAll(listOf("hello.txt", "docs")))
            assertEquals("hello world", readText(share, "hello.txt"))
        }
    }

    @Test
    fun wrongPasswordAndUnknownUserAreRejected() {
        start()
        for ((user, password) in listOf(USER to "wrong-password", "mallory" to PASSWORD)) {
            try {
                connect(user = user, password = password)
                fail("login as $user should fail")
            } catch (e: SMBApiException) {
                assertEquals(NtStatus.STATUS_LOGON_FAILURE, e.status)
            }
        }
    }

    @Test
    fun anonymousIsRejected() {
        start()
        val client = SMBClient().also(clients::add)
        try {
            client.connect("127.0.0.1", server!!.localPort).authenticate(AuthenticationContext.anonymous())
            fail("anonymous login should fail")
        } catch (e: SMBApiException) {
            assertEquals(NtStatus.STATUS_LOGON_FAILURE, e.status)
        }
    }

    @Test
    fun unknownShareIsRejected() {
        start()
        try {
            connect().connectShare("other")
            fail()
        } catch (e: SMBApiException) {
            assertEquals(NtStatus.STATUS_BAD_NETWORK_NAME, e.status)
        }
    }

    @Test
    fun writeRenameAndDelete() {
        start()
        val share = share(connect())
        val data = ByteArray(3 * 1024 * 1024 + 17).also { Random(1).nextBytes(it) }
        writeBytes(share, "big.bin", data)
        assertArrayEquals(data, File(root, "big.bin").readBytes())
        assertArrayEquals(data, readBytes(share, "big.bin"))

        share.mkdir("new folder")
        assertTrue(File(root, "new folder").isDirectory)
        rename(share, "big.bin", "new folder\\moved.bin")
        assertFalse(File(root, "big.bin").exists())
        assertTrue(File(root, "new folder/moved.bin").exists())

        share.rm("new folder\\moved.bin")
        share.rmdir("new folder", false)
        assertFalse(File(root, "new folder").exists())
    }

    @Test
    fun overwriteTruncates() {
        start()
        val share = share(connect())
        writeBytes(share, "hello.txt", "hi".toByteArray())
        assertEquals("hi", File(root, "hello.txt").readText())
    }

    @Test
    fun nonEmptyFolderCannotBeDeleted() {
        start()
        val share = share(connect())
        try {
            share.rmdir("docs", false)
            fail()
        } catch (e: SMBApiException) {
            assertEquals(NtStatus.STATUS_DIRECTORY_NOT_EMPTY, e.status)
        }
        assertTrue(File(root, "docs/readme.md").exists())
    }

    @Test
    fun fileInformation() {
        start()
        val share = share(connect())
        val info = share.getFileInformation("docs\\readme.md")
        assertEquals(8L, info.standardInformation.endOfFile)
        assertFalse(info.standardInformation.isDirectory)
        assertTrue(share.getFileInformation("docs").standardInformation.isDirectory)
        assertTrue(share.fileExists("HELLO.TXT")) // case-insensitive lookup
        assertFalse(share.fileExists("missing.txt"))
        assertTrue(share.folderExists("docs"))
        val space = share.shareInformation
        assertTrue(space.totalSpace > 0)
    }

    @Test
    fun readOnlyShareRejectsChanges() {
        start(readOnly = true)
        val share = share(connect())
        assertEquals("hello world", readText(share, "hello.txt"))
        expectDenied { writeBytes(share, "new.txt", "x".toByteArray()) }
        expectDenied { share.mkdir("dir") }
        expectDenied { share.rm("hello.txt") }
        expectDenied { rename(share, "hello.txt", "renamed.txt") }
        assertEquals("hello world", File(root, "hello.txt").readText())
        assertFalse(File(root, "new.txt").exists())
    }

    @Test
    fun pathsCannotEscapeTheShare() {
        val outside = tmp.newFolder("outside")
        File(outside, "secret.txt").writeText("secret")
        Files.createSymbolicLink(File(root, "link").toPath(), outside.toPath())
        start()
        val share = share(connect())
        for (path in listOf("..\\outside\\secret.txt", "docs\\..\\..\\outside\\secret.txt", "link\\secret.txt")) {
            try {
                readText(share, path)
                fail("$path should not be readable")
            } catch (e: SMBApiException) {
                assertTrue(
                    "$path: ${e.status}",
                    e.status == NtStatus.STATUS_ACCESS_DENIED || e.status == NtStatus.STATUS_OBJECT_NAME_INVALID,
                )
            }
        }
        assertFalse(share.list("").any { it.fileName == "link" })
    }

    @Test
    fun directoryListingPagesThroughLargeFolders() {
        val big = File(root, "many").apply { mkdir() }
        repeat(1500) { File(big, "file-with-a-reasonably-long-name-$it.txt").writeText("$it") }
        start()
        val names = share(connect()).list("many").map { it.fileName }.filter { it != "." && it != ".." }
        assertEquals(1500, names.size)
        assertEquals(1500, names.toSet().size)
    }

    @Test
    fun connectionCountTracksClients() {
        val s = start()
        val session = connect()
        assertEquals(1, s.connectionCount)
        session.connection.close()
        val deadline = System.currentTimeMillis() + 5000
        while (s.connectionCount != 0 && System.currentTimeMillis() < deadline) Thread.sleep(20)
        assertEquals(0, s.connectionCount)
    }

    private fun expectDenied(block: () -> Unit) {
        try {
            block()
            fail("expected ACCESS_DENIED")
        } catch (e: SMBApiException) {
            assertEquals(NtStatus.STATUS_ACCESS_DENIED, e.status)
        }
    }

    private fun rename(share: DiskShare, from: String, to: String) {
        share.open(
            from,
            EnumSet.of(AccessMask.DELETE, AccessMask.FILE_READ_ATTRIBUTES),
            null,
            SMB2ShareAccess.ALL,
            SMB2CreateDisposition.FILE_OPEN,
            null,
        ).use { it.rename(to) }
    }

    private fun readText(share: DiskShare, path: String) = String(readBytes(share, path))

    private fun readBytes(share: DiskShare, path: String): ByteArray =
        share.openFile(
            path,
            EnumSet.of(AccessMask.GENERIC_READ),
            EnumSet.of(FileAttributes.FILE_ATTRIBUTE_NORMAL),
            SMB2ShareAccess.ALL,
            SMB2CreateDisposition.FILE_OPEN,
            EnumSet.of(SMB2CreateOptions.FILE_NON_DIRECTORY_FILE),
        ).use { f ->
            val size = f.getFileInformation(FileStandardInformation::class.java).endOfFile.toInt()
            f.inputStream.use { it.readBytes() }.also { assertEquals(size, it.size) }
        }

    private fun writeBytes(share: DiskShare, path: String, data: ByteArray) {
        share.openFile(
            path,
            EnumSet.of(AccessMask.GENERIC_WRITE),
            EnumSet.of(FileAttributes.FILE_ATTRIBUTE_NORMAL),
            SMB2ShareAccess.ALL,
            SMB2CreateDisposition.FILE_OVERWRITE_IF,
            EnumSet.of(SMB2CreateOptions.FILE_NON_DIRECTORY_FILE),
        ).use { f -> f.outputStream.use { it.write(data) } }
    }

    private companion object {
        const val USER = "alice"
        const val PASSWORD = "correct-horse"
    }
}
