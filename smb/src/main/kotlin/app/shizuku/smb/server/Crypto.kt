package app.shizuku.smb.server

import java.security.MessageDigest
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * Cryptographic primitives SMB needs. MD4, RC4 and AES-CMAC are implemented here because
 * Android's providers don't offer them.
 */
internal object Crypto {

    fun hmacMd5(key: ByteArray, vararg parts: ByteArray): ByteArray = hmac("HmacMD5", key, parts)

    fun hmacSha256(key: ByteArray, vararg parts: ByteArray): ByteArray = hmac("HmacSHA256", key, parts)

    private fun hmac(algorithm: String, key: ByteArray, parts: Array<out ByteArray>): ByteArray {
        val mac = Mac.getInstance(algorithm)
        mac.init(SecretKeySpec(key, algorithm))
        parts.forEach(mac::update)
        return mac.doFinal()
    }

    fun md5(vararg parts: ByteArray): ByteArray {
        val digest = MessageDigest.getInstance("MD5")
        parts.forEach(digest::update)
        return digest.digest()
    }

    fun sha512(vararg parts: ByteArray): ByteArray {
        val digest = MessageDigest.getInstance("SHA-512")
        parts.forEach(digest::update)
        return digest.digest()
    }

    /** Constant-time comparison. */
    fun equal(a: ByteArray, b: ByteArray): Boolean = MessageDigest.isEqual(a, b)

    /** SP800-108 counter-mode KDF with HMAC-SHA256, producing a 128-bit key (MS-SMB2 3.1.4.2). */
    fun smb3Kdf(key: ByteArray, label: ByteArray, context: ByteArray): ByteArray {
        val out = hmacSha256(
            key,
            byteArrayOf(0, 0, 0, 1),
            label,
            byteArrayOf(0),
            context,
            byteArrayOf(0, 0, 0, 128.toByte()),
        )
        return out.copyOf(16)
    }

    /** AES-CMAC as defined in RFC 4493. */
    fun aesCmac(key: ByteArray, message: ByteArray, offset: Int = 0, length: Int = message.size): ByteArray {
        val aes = Cipher.getInstance("AES/ECB/NoPadding")
        aes.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"))
        val l = aes.doFinal(ByteArray(16))
        val k1 = shiftLeftXor(l)
        val k2 = shiftLeftXor(k1)

        val blocks = if (length == 0) 1 else (length + 15) / 16
        val lastComplete = length != 0 && length % 16 == 0
        var x = ByteArray(16)
        val y = ByteArray(16)
        for (i in 0 until blocks - 1) {
            for (j in 0 until 16) y[j] = (x[j].toInt() xor message[offset + i * 16 + j].toInt()).toByte()
            x = aes.doFinal(y)
        }
        val last = ByteArray(16)
        val lastStart = (blocks - 1) * 16
        if (lastComplete) {
            for (j in 0 until 16) last[j] = (message[offset + lastStart + j].toInt() xor k1[j].toInt()).toByte()
        } else {
            val remaining = length - lastStart
            for (j in 0 until 16) {
                val m = when {
                    j < remaining -> message[offset + lastStart + j].toInt()
                    j == remaining -> 0x80
                    else -> 0
                }
                last[j] = (m xor k2[j].toInt()).toByte()
            }
        }
        for (j in 0 until 16) y[j] = (x[j].toInt() xor last[j].toInt()).toByte()
        return aes.doFinal(y)
    }

    private fun shiftLeftXor(input: ByteArray): ByteArray {
        val out = ByteArray(16)
        var carry = 0
        for (i in 15 downTo 0) {
            val b = input[i].toInt() and 0xFF
            out[i] = ((b shl 1) or carry).toByte()
            carry = b ushr 7
        }
        if (input[0].toInt() and 0x80 != 0) out[15] = (out[15].toInt() xor 0x87).toByte()
        return out
    }

    /** MD4 (RFC 1320), used only to derive the NT hash of the share password. */
    fun md4(input: ByteArray): ByteArray {
        val bitLength = input.size.toLong() * 8
        val padLength = ((56 - (input.size + 1) % 64) + 64) % 64
        val msg = ByteArray(input.size + 1 + padLength + 8)
        System.arraycopy(input, 0, msg, 0, input.size)
        msg[input.size] = 0x80.toByte()
        for (i in 0 until 8) msg[msg.size - 8 + i] = (bitLength ushr (8 * i)).toByte()

        var a = 0x67452301
        var b = 0xefcdab89.toInt()
        var c = 0x98badcfe.toInt()
        var d = 0x10325476
        val x = IntArray(16)
        for (block in 0 until msg.size / 64) {
            for (i in 0 until 16) {
                val p = block * 64 + i * 4
                x[i] = (msg[p].toInt() and 0xFF) or ((msg[p + 1].toInt() and 0xFF) shl 8) or
                    ((msg[p + 2].toInt() and 0xFF) shl 16) or ((msg[p + 3].toInt() and 0xFF) shl 24)
            }
            val aa = a
            val bb = b
            val cc = c
            val dd = d
            fun f(x: Int, y: Int, z: Int) = (x and y) or (x.inv() and z)
            fun g(x: Int, y: Int, z: Int) = (x and y) or (x and z) or (y and z)
            fun h(x: Int, y: Int, z: Int) = x xor y xor z
            val r1 = intArrayOf(3, 7, 11, 19)
            for (i in 0 until 16) {
                val t = Integer.rotateLeft(a + f(b, c, d) + x[i], r1[i % 4])
                a = d; d = c; c = b; b = t
            }
            val r2 = intArrayOf(3, 5, 9, 13)
            for (i in 0 until 16) {
                val k = (i % 4) * 4 + i / 4
                val t = Integer.rotateLeft(a + g(b, c, d) + x[k] + 0x5A827999, r2[i % 4])
                a = d; d = c; c = b; b = t
            }
            val r3 = intArrayOf(3, 9, 11, 15)
            val order = intArrayOf(0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15)
            for (i in 0 until 16) {
                val t = Integer.rotateLeft(a + h(b, c, d) + x[order[i]] + 0x6ED9EBA1, r3[i % 4])
                a = d; d = c; c = b; b = t
            }
            a += aa; b += bb; c += cc; d += dd
        }
        val out = ByteArray(16)
        intArrayOf(a, b, c, d).forEachIndexed { i, v ->
            for (j in 0 until 4) out[i * 4 + j] = (v ushr (8 * j)).toByte()
        }
        return out
    }
}

/** RC4 stream cipher; NTLM uses it for key exchange and to seal message signatures. */
internal class Rc4(key: ByteArray) {
    private val s = IntArray(256) { it }
    private var i = 0
    private var j = 0

    init {
        var j = 0
        for (i in 0 until 256) {
            j = (j + s[i] + (key[i % key.size].toInt() and 0xFF)) and 0xFF
            val t = s[i]; s[i] = s[j]; s[j] = t
        }
    }

    fun apply(input: ByteArray): ByteArray {
        val out = ByteArray(input.size)
        for (k in input.indices) {
            i = (i + 1) and 0xFF
            j = (j + s[i]) and 0xFF
            val t = s[i]; s[i] = s[j]; s[j] = t
            out[k] = (input[k].toInt() xor s[(s[i] + s[j]) and 0xFF]).toByte()
        }
        return out
    }
}
