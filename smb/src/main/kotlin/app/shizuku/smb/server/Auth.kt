package app.shizuku.smb.server

import java.io.ByteArrayOutputStream
import java.security.SecureRandom

/** Minimal DER support for the SPNEGO tokens that wrap NTLMSSP (RFC 4178). */
internal object Der {
    class Tlv(val tag: Int, val data: ByteArray, val start: Int, val contentStart: Int, val end: Int) {
        val content: ByteArray get() = data.copyOfRange(contentStart, end)
        val encoded: ByteArray get() = data.copyOfRange(start, end)

        fun children(): List<Tlv> {
            val out = ArrayList<Tlv>()
            var pos = contentStart
            while (pos < end) {
                val child = read(data, pos, end)
                out += child
                pos = child.end
            }
            return out
        }
    }

    fun read(data: ByteArray, offset: Int, limit: Int = data.size): Tlv {
        var pos = offset
        fun next(): Int {
            if (pos >= limit) throw MalformedMessageException("truncated DER")
            return data[pos++].toInt() and 0xFF
        }
        val tag = next()
        var length = next()
        if (length and 0x80 != 0) {
            val count = length and 0x7F
            if (count == 0 || count > 3) throw MalformedMessageException("bad DER length")
            length = 0
            repeat(count) { length = (length shl 8) or next() }
        }
        if (pos + length > limit) throw MalformedMessageException("DER value past end")
        return Tlv(tag, data, offset, pos, pos + length)
    }

    fun encode(tag: Int, vararg parts: ByteArray): ByteArray {
        val length = parts.sumOf { it.size }
        val out = ByteArrayOutputStream(length + 6)
        out.write(tag)
        when {
            length < 0x80 -> out.write(length)
            length < 0x100 -> { out.write(0x81); out.write(length) }
            length < 0x10000 -> { out.write(0x82); out.write(length ushr 8); out.write(length) }
            else -> { out.write(0x83); out.write(length ushr 16); out.write(length ushr 8); out.write(length) }
        }
        parts.forEach { out.write(it) }
        return out.toByteArray()
    }
}

internal object Spnego {
    private val SPNEGO_OID = byteArrayOf(0x2b, 0x06, 0x01, 0x05, 0x05, 0x02)
    val NTLMSSP_OID = byteArrayOf(0x2b, 0x06, 0x01, 0x04, 0x01, 0x82.toByte(), 0x37, 0x02, 0x02, 0x0a)

    const val ACCEPT_COMPLETED = 0
    const val ACCEPT_INCOMPLETE = 1
    const val REJECT = 2

    /** A client SPNEGO token, or a bare NTLMSSP message (then [raw] is true). */
    class ClientToken(
        val mechToken: ByteArray?,
        /** DER encoding of the MechTypeList, needed to compute mechListMIC. */
        val mechTypes: ByteArray?,
        val mechListMic: ByteArray?,
        val raw: Boolean,
        /** Whether the client listed NTLMSSP first, so its optimistic token is NTLM. */
        val ntlmPreferred: Boolean,
    )

    /** The token the server puts in the NEGOTIATE response, advertising NTLMSSP only. */
    fun negotiateHint(): ByteArray {
        val mechTypes = Der.encode(0x30, Der.encode(0x06, NTLMSSP_OID))
        val init = Der.encode(0x30, Der.encode(0xa0, mechTypes))
        return Der.encode(0x60, Der.encode(0x06, SPNEGO_OID), Der.encode(0xa0, init))
    }

    fun parse(token: ByteArray): ClientToken {
        if (Ntlm.isNtlm(token)) return ClientToken(token, null, null, raw = true, ntlmPreferred = true)
        val outer = Der.read(token, 0)
        return when (outer.tag) {
            0x60 -> {
                val children = outer.children()
                val init = children.firstOrNull { it.tag == 0xa0 }?.children()?.firstOrNull()
                    ?: throw MalformedMessageException("missing NegTokenInit")
                var mechToken: ByteArray? = null
                var mechTypes: ByteArray? = null
                var mic: ByteArray? = null
                var preferred = false
                for (field in init.children()) {
                    val value = field.children().firstOrNull() ?: continue
                    when (field.tag) {
                        0xa0 -> {
                            mechTypes = value.encoded
                            preferred = value.children().firstOrNull()?.content?.contentEquals(NTLMSSP_OID) == true
                        }
                        0xa2 -> mechToken = value.content
                        0xa3 -> mic = value.content
                    }
                }
                ClientToken(mechToken, mechTypes, mic, raw = false, ntlmPreferred = preferred)
            }
            0xa1 -> {
                val seq = outer.children().firstOrNull() ?: throw MalformedMessageException("empty NegTokenResp")
                var token2: ByteArray? = null
                var mic: ByteArray? = null
                for (field in seq.children()) {
                    val value = field.children().firstOrNull() ?: continue
                    when (field.tag) {
                        0xa2 -> token2 = value.content
                        0xa3 -> mic = value.content
                    }
                }
                ClientToken(token2, null, mic, raw = false, ntlmPreferred = true)
            }
            else -> throw MalformedMessageException("unknown security token")
        }
    }

    fun response(state: Int, includeMech: Boolean, token: ByteArray?, mic: ByteArray?): ByteArray {
        val fields = ArrayList<ByteArray>()
        fields += Der.encode(0xa0, Der.encode(0x0a, byteArrayOf(state.toByte())))
        if (includeMech) fields += Der.encode(0xa1, Der.encode(0x06, NTLMSSP_OID))
        if (token != null) fields += Der.encode(0xa2, Der.encode(0x04, token))
        if (mic != null) fields += Der.encode(0xa3, Der.encode(0x04, mic))
        return Der.encode(0xa1, Der.encode(0x30, *fields.toTypedArray()))
    }
}

/** Server side of NTLMv2 authentication (MS-NLMP), for a single configured account. */
internal class Ntlm(
    private val username: String,
    password: String,
    private val serverName: String,
    private val random: SecureRandom,
) {
    private val ntHash = Crypto.md4(utf16(password))
    private val serverChallenge = ByteArray(8).also(random::nextBytes)
    private var challengeFlags = 0

    class Result(val sessionKey: ByteArray, val user: String, val domain: String, val flags: Int)

    fun challenge(negotiate: ByteArray): ByteArray {
        val clientFlags = if (negotiate.size >= 16) ByteReader(negotiate).i32(12) else 0
        var flags = NEGOTIATE_UNICODE or REQUEST_TARGET or NEGOTIATE_NTLM or ALWAYS_SIGN or
            TARGET_TYPE_SERVER or EXTENDED_SESSIONSECURITY or TARGET_INFO or NEGOTIATE_VERSION
        flags = flags or (clientFlags and (NEGOTIATE_128 or NEGOTIATE_56 or KEY_EXCH or NEGOTIATE_SIGN or NEGOTIATE_SEAL))
        challengeFlags = flags

        val target = utf16(serverName)
        val info = ByteWriter()
        fun av(id: Int, value: ByteArray) {
            info.u16(id).u16(value.size).bytes(value)
        }
        av(AV_NB_DOMAIN, target)
        av(AV_NB_COMPUTER, target)
        av(AV_DNS_DOMAIN, utf16(serverName.lowercase()))
        av(AV_DNS_COMPUTER, utf16(serverName.lowercase()))
        av(AV_TIMESTAMP, ByteWriter().u64(FileTimes.now()).toByteArray())
        info.u16(AV_EOL).u16(0)
        val targetInfo = info.toByteArray()

        val headerSize = 56
        return ByteWriter()
            .bytes(SIGNATURE)
            .u32(2)
            .u16(target.size).u16(target.size).u32(headerSize)
            .u32(flags)
            .bytes(serverChallenge)
            .zeros(8)
            .u16(targetInfo.size).u16(targetInfo.size).u32(headerSize + target.size)
            .bytes(VERSION)
            .bytes(target)
            .bytes(targetInfo)
            .toByteArray()
    }

    /** Returns null if the credentials are wrong or the client used something other than NTLMv2. */
    fun authenticate(message: ByteArray): Result? {
        val r = ByteReader(message)
        if (!isNtlm(message) || r.i32(8) != 3) return null
        fun field(offset: Int): ByteArray {
            val length = r.u16(offset)
            val pos = r.u32(offset + 4).toInt()
            return if (length == 0) ByteArray(0) else r.bytes(pos, length)
        }
        val ntResponse = field(20)
        val domain = String(field(28), Charsets.UTF_16LE)
        val user = String(field(36), Charsets.UTF_16LE)
        val encryptedKey = field(52)
        val flags = r.i32(60)

        // Reject anonymous logons and NTLMv1 (24-byte responses).
        if (user.isEmpty() || ntResponse.size < 16 + 28) return null
        if (!user.equals(username, ignoreCase = true) &&
            !user.substringBefore('@').equals(username, ignoreCase = true)
        ) {
            return null
        }

        val proof = ntResponse.copyOf(16)
        val blob = ntResponse.copyOfRange(16, ntResponse.size)
        for (candidateDomain in linkedSetOf(domain, domain.uppercase(), "")) {
            val ntowf = Crypto.hmacMd5(ntHash, utf16(user.uppercase() + candidateDomain))
            val expected = Crypto.hmacMd5(ntowf, serverChallenge, blob)
            if (!Crypto.equal(expected, proof)) continue
            val baseKey = Crypto.hmacMd5(ntowf, proof)
            val negotiated = flags and challengeFlags
            val sessionKey = if (negotiated and KEY_EXCH != 0 && encryptedKey.size == 16) {
                Rc4(baseKey).apply(encryptedKey)
            } else {
                baseKey
            }
            return Result(sessionKey, user, domain, negotiated)
        }
        return null
    }

    /** GSS_GetMIC over [message] with the server-to-client keys, sequence number 0. */
    fun mic(result: Result, message: ByteArray): ByteArray {
        val signKey = Crypto.md5(result.sessionKey, SERVER_SIGN_MAGIC)
        val sealBase = when {
            result.flags and NEGOTIATE_128 != 0 -> result.sessionKey
            result.flags and NEGOTIATE_56 != 0 -> result.sessionKey.copyOf(7)
            else -> result.sessionKey.copyOf(5)
        }
        val sealKey = Crypto.md5(sealBase, SERVER_SEAL_MAGIC)
        val seq = byteArrayOf(0, 0, 0, 0)
        var checksum = Crypto.hmacMd5(signKey, seq, message).copyOf(8)
        if (result.flags and KEY_EXCH != 0) checksum = Rc4(sealKey).apply(checksum)
        return ByteWriter().u32(1).bytes(checksum).bytes(seq).toByteArray()
    }

    companion object {
        private val SIGNATURE = "NTLMSSP\u0000".toByteArray(Charsets.US_ASCII)
        // Windows 10 build 19041, NTLM revision 15.
        private val VERSION = byteArrayOf(10, 0, 0x61, 0x4a, 0, 0, 0, 15)
        private val SERVER_SIGN_MAGIC =
            "session key to server-to-client signing key magic constant\u0000".toByteArray(Charsets.US_ASCII)
        private val SERVER_SEAL_MAGIC =
            "session key to server-to-client sealing key magic constant\u0000".toByteArray(Charsets.US_ASCII)

        const val NEGOTIATE_UNICODE = 0x00000001
        const val REQUEST_TARGET = 0x00000004
        const val NEGOTIATE_SIGN = 0x00000010
        const val NEGOTIATE_SEAL = 0x00000020
        const val NEGOTIATE_NTLM = 0x00000200
        const val ALWAYS_SIGN = 0x00008000
        const val TARGET_TYPE_SERVER = 0x00020000
        const val EXTENDED_SESSIONSECURITY = 0x00080000
        const val TARGET_INFO = 0x00800000
        const val NEGOTIATE_VERSION = 0x02000000
        const val NEGOTIATE_128 = 0x20000000
        const val KEY_EXCH = 0x40000000
        const val NEGOTIATE_56 = 0x80000000.toInt()

        private const val AV_EOL = 0
        private const val AV_NB_COMPUTER = 1
        private const val AV_NB_DOMAIN = 2
        private const val AV_DNS_COMPUTER = 3
        private const val AV_DNS_DOMAIN = 4
        private const val AV_TIMESTAMP = 7

        fun isNtlm(token: ByteArray): Boolean =
            token.size >= 12 && token.copyOf(8).contentEquals(SIGNATURE)

        fun messageType(token: ByteArray): Int = if (isNtlm(token)) ByteReader(token).i32(8) else -1
    }
}

internal object FileTimes {
    private const val EPOCH_DIFF_100NS = 116444736000000000L

    fun fromMillis(millis: Long): Long = millis * 10_000 + EPOCH_DIFF_100NS

    fun toMillis(fileTime: Long): Long = (fileTime - EPOCH_DIFF_100NS) / 10_000

    fun now(): Long = fromMillis(System.currentTimeMillis())
}
