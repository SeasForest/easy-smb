package app.shizuku.smb.server

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class CryptoTest {
    private fun hex(b: ByteArray) = b.joinToString("") { "%02x".format(it) }
    private fun unhex(s: String) = ByteArray(s.length / 2) { s.substring(it * 2, it * 2 + 2).toInt(16).toByte() }

    @Test
    fun md4MatchesRfc1320() {
        assertEquals("31d6cfe0d16ae931b73c59d7e0c089c0", hex(Crypto.md4(ByteArray(0))))
        assertEquals("a448017aaf21d8525fc10ae87aa6729d", hex(Crypto.md4("abc".toByteArray())))
        assertEquals(
            "e33b4ddc9c38f2199c3e7b164fcc0536",
            hex(Crypto.md4("12345678901234567890123456789012345678901234567890123456789012345678901234567890".toByteArray())),
        )
    }

    @Test
    fun ntHashOfPassword() {
        // MS-NLMP 4.2.4.1.1: NTOWFv1("Password")
        assertEquals("a4f49c406510bdcab6824ee7c30fd852", hex(Crypto.md4(utf16("Password"))))
    }

    @Test
    fun aesCmacMatchesRfc4493() {
        val key = unhex("2b7e151628aed2a6abf7158809cf4f3c")
        val msg = unhex(
            "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710",
        )
        assertEquals("bb1d6929e95937287fa37d129b756746", hex(Crypto.aesCmac(key, ByteArray(0))))
        assertEquals("070a16b46b4d4144f79bdd9dd04a287c", hex(Crypto.aesCmac(key, msg, 0, 16)))
        assertEquals("dfa66747de9ae63030ca32611497c827", hex(Crypto.aesCmac(key, msg, 0, 40)))
        assertEquals("51f0bebf7e3b9d92fc49741779363cfe", hex(Crypto.aesCmac(key, msg)))
    }

    @Test
    fun rc4MatchesKnownVector() {
        assertEquals("bbf316e8d940af0ad3", hex(Rc4("Key".toByteArray()).apply("Plaintext".toByteArray())))
    }

    @Test
    fun ntlmv2RoundTrip() {
        val random = java.security.SecureRandom()
        val server = Ntlm("alice", "correct-horse", "TEST", random)
        val challenge = server.challenge(negotiateMessage())
        val auth = authenticateMessage(challenge, "Alice", "WORKGROUP", "correct-horse")
        val result = server.authenticate(auth)
        assertTrue(result != null)
        assertEquals("Alice", result!!.user)

        val server2 = Ntlm("alice", "correct-horse", "TEST", random)
        val challenge2 = server2.challenge(negotiateMessage())
        assertEquals(null, server2.authenticate(authenticateMessage(challenge2, "alice", "", "wrong")))
        val server3 = Ntlm("alice", "correct-horse", "TEST", random)
        val challenge3 = server3.challenge(negotiateMessage())
        assertEquals(null, server3.authenticate(authenticateMessage(challenge3, "bob", "", "correct-horse")))
    }

    @Test
    fun wildcards() {
        assertTrue(Wildcard.matches("*", "anything"))
        assertTrue(Wildcard.matches("*.TXT", "notes.txt"))
        assertTrue(Wildcard.matches("a?c", "abc"))
        assertFalse(Wildcard.matches("a?c", "abbc"))
        assertTrue(Wildcard.matches("<.jpg", "photo.jpg"))
        assertFalse(Wildcard.matches("*.jpg", "photo.png"))
        assertFalse(Wildcard.isPattern("plain.txt"))
    }

    private fun negotiateMessage(): ByteArray = ByteWriter()
        .bytes("NTLMSSP\u0000".toByteArray()).u32(1)
        .u32(Ntlm.NEGOTIATE_UNICODE or Ntlm.NEGOTIATE_NTLM or Ntlm.EXTENDED_SESSIONSECURITY or Ntlm.NEGOTIATE_128)
        .zeros(16)
        .toByteArray()

    /** Builds a client NTLMv2 AUTHENTICATE message the way MS-NLMP 3.3.2 describes. */
    private fun authenticateMessage(challenge: ByteArray, user: String, domain: String, password: String): ByteArray {
        val r = ByteReader(challenge)
        val serverChallenge = r.bytes(24, 8)
        val targetInfo = r.bytes(r.u32(44).toInt(), r.u16(40))
        val ntowf = Crypto.hmacMd5(Crypto.md4(utf16(password)), utf16(user.uppercase() + domain))
        val blob = ByteWriter().u8(1).u8(1).zeros(6).u64(FileTimes.now()).bytes(ByteArray(8) { 7 }).u32(0)
            .bytes(targetInfo).u32(0).toByteArray()
        val proof = Crypto.hmacMd5(ntowf, serverChallenge, blob)
        val nt = proof + blob
        val d = utf16(domain)
        val u = utf16(user)
        val base = 64
        return ByteWriter()
            .bytes("NTLMSSP\u0000".toByteArray()).u32(3)
            .u16(0).u16(0).u32(base) // LM
            .u16(nt.size).u16(nt.size).u32(base)
            .u16(d.size).u16(d.size).u32(base + nt.size)
            .u16(u.size).u16(u.size).u32(base + nt.size + d.size)
            .u16(0).u16(0).u32(base + nt.size + d.size + u.size) // workstation
            .u16(0).u16(0).u32(base + nt.size + d.size + u.size) // session key
            .u32(Ntlm.NEGOTIATE_UNICODE or Ntlm.NEGOTIATE_NTLM or Ntlm.EXTENDED_SESSIONSECURITY)
            .bytes(nt).bytes(d).bytes(u)
            .toByteArray()
    }
}
