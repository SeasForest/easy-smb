package app.shizuku.smb.server

/** Thrown when a client message is too short or internally inconsistent. */
class MalformedMessageException(message: String) : Exception(message)

/** Little-endian reads from a byte array with bounds checks. */
class ByteReader(val data: ByteArray, val start: Int = 0, val end: Int = data.size) {

    fun u8(offset: Int): Int {
        check(offset, 1)
        return data[start + offset].toInt() and 0xFF
    }

    fun u16(offset: Int): Int = u8(offset) or (u8(offset + 1) shl 8)

    fun u32(offset: Int): Long = (u16(offset).toLong()) or (u16(offset + 2).toLong() shl 16)

    fun i32(offset: Int): Int = u32(offset).toInt()

    fun u64(offset: Int): Long = u32(offset) or (u32(offset + 4) shl 32)

    fun bytes(offset: Int, length: Int): ByteArray {
        check(offset, length)
        return data.copyOfRange(start + offset, start + offset + length)
    }

    fun utf16(offset: Int, length: Int): String =
        String(bytes(offset, length), Charsets.UTF_16LE)

    val size: Int get() = end - start

    fun slice(offset: Int, length: Int): ByteReader {
        check(offset, length)
        return ByteReader(data, start + offset, start + offset + length)
    }

    private fun check(offset: Int, length: Int) {
        if (offset < 0 || length < 0 || start + offset + length > end || start + offset + length < 0) {
            throw MalformedMessageException("read of $length at $offset past end ($size)")
        }
    }
}

/** Growable little-endian writer. */
class ByteWriter(initialCapacity: Int = 256) {
    private var buf = ByteArray(initialCapacity)
    var size: Int = 0
        private set

    private fun ensure(extra: Int) {
        if (size + extra > buf.size) {
            buf = buf.copyOf(maxOf(buf.size * 2, size + extra))
        }
    }

    fun u8(v: Int): ByteWriter {
        ensure(1)
        buf[size++] = v.toByte()
        return this
    }

    fun u16(v: Int): ByteWriter = u8(v).u8(v ushr 8)

    fun u32(v: Long): ByteWriter = u16(v.toInt()).u16((v ushr 16).toInt())

    fun u32(v: Int): ByteWriter = u32(v.toLong() and 0xFFFFFFFFL)

    fun u64(v: Long): ByteWriter = u32(v and 0xFFFFFFFFL).u32(v ushr 32)

    fun bytes(b: ByteArray, offset: Int = 0, length: Int = b.size - offset): ByteWriter {
        ensure(length)
        System.arraycopy(b, offset, buf, size, length)
        size += length
        return this
    }

    fun zeros(n: Int): ByteWriter {
        ensure(n)
        size += n // buffer is zero-filled on growth and never shrinks
        return this
    }

    fun utf16(s: String): ByteWriter = bytes(s.toByteArray(Charsets.UTF_16LE))

    /** Pads with zeros until [size] is a multiple of [alignment]. */
    fun align(alignment: Int): ByteWriter {
        val rem = size % alignment
        if (rem != 0) zeros(alignment - rem)
        return this
    }

    fun putU16(at: Int, v: Int) {
        buf[at] = v.toByte()
        buf[at + 1] = (v ushr 8).toByte()
    }

    fun putU32(at: Int, v: Int) {
        putU16(at, v)
        putU16(at + 2, v ushr 16)
    }

    fun toByteArray(): ByteArray = buf.copyOf(size)
}

internal fun utf16(s: String): ByteArray = s.toByteArray(Charsets.UTF_16LE)
