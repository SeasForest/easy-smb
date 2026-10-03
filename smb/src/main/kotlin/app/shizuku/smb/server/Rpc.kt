package app.shizuku.smb.server

/** A share as listed by the server service: name, STYPE_* type and comment. */
internal class ShareListing(val name: String, val type: Int, val remark: String)

/**
 * The `srvsvc` named pipe on IPC$: just enough DCE/RPC (MS-RPCE) and MS-SRVS for clients to
 * list shares (NetrShareEnum) and look one up (NetrShareGetInfo).
 */
internal class SrvsvcPipe(private val shares: List<ShareListing>) {
    private val output = java.io.ByteArrayOutputStream()
    private var fragments = java.io.ByteArrayOutputStream()
    private val pending = java.io.ByteArrayOutputStream()

    /** Feeds bytes the client wrote; complete PDUs are answered into the read buffer. */
    fun write(data: ByteArray) {
        pending.write(data)
        while (true) {
            val buf = pending.toByteArray()
            if (buf.size < 16) return
            val length = ByteReader(buf).u16(8)
            if (length < 16) throw SmbException(Status.INVALID_PARAMETER)
            if (buf.size < length) return
            pending.reset()
            pending.write(buf, length, buf.size - length)
            handlePdu(buf.copyOf(length))?.let(output::write)
        }
    }

    /** Returns up to [max] bytes of pending output, and whether more remain. */
    fun read(max: Int): Pair<ByteArray, Boolean> {
        val all = output.toByteArray()
        val n = minOf(max, all.size)
        output.reset()
        output.write(all, n, all.size - n)
        return all.copyOf(n) to (all.size > n)
    }

    val hasOutput: Boolean get() = output.size() > 0

    private fun handlePdu(pdu: ByteArray): ByteArray? {
        val r = ByteReader(pdu)
        if (r.u8(0) != 5) throw SmbException(Status.INVALID_PARAMETER)
        val type = r.u8(2)
        val flags = r.u8(3)
        val callId = r.i32(12)
        return when (type) {
            PTYPE_BIND, PTYPE_ALTER_CONTEXT -> bindAck(r, callId, if (type == PTYPE_BIND) PTYPE_BIND_ACK else PTYPE_ALTER_CONTEXT_RESP)
            PTYPE_REQUEST -> {
                val stubStart = if (flags and PFC_OBJECT_UUID != 0) 40 else 24
                val authLength = r.u16(10)
                val stubEnd = pdu.size - if (authLength > 0) authLength + 8 else 0
                fragments.write(pdu, stubStart, maxOf(0, stubEnd - stubStart))
                if (flags and PFC_LAST_FRAG == 0) return null
                val stub = fragments.toByteArray()
                fragments = java.io.ByteArrayOutputStream()
                val contextId = r.u16(20)
                val opnum = r.u16(22)
                val result = runCatching { call(opnum, ByteReader(stub)) }.getOrNull()
                if (result == null) fault(callId, contextId) else response(callId, contextId, result)
            }
            else -> null
        }
    }

    private fun header(type: Int, callId: Int) = ByteWriter()
        .u8(5).u8(0).u8(type).u8(PFC_FIRST_FRAG or PFC_LAST_FRAG)
        .u8(0x10).u8(0).u8(0).u8(0)
        .u16(0) // frag length, patched below
        .u16(0)
        .u32(callId)

    private fun finish(w: ByteWriter): ByteArray {
        w.putU16(8, w.size)
        return w.toByteArray()
    }

    private fun bindAck(r: ByteReader, callId: Int, type: Int): ByteArray {
        val maxXmit = r.u16(16)
        val maxRecv = r.u16(18)
        val count = r.u8(24)
        val w = header(type, callId)
            .u16(minOf(maxXmit, 4280)).u16(minOf(maxRecv, 4280))
            .u32(ASSOC_GROUP)
        if (type == PTYPE_BIND_ACK) {
            val address = "\\PIPE\\srvsvc\u0000".toByteArray(Charsets.US_ASCII)
            w.u16(address.size).bytes(address)
        } else {
            w.u16(0)
        }
        w.align(4)
        w.u8(count).u8(0).u16(0)
        var pos = 28
        var accepted = false
        repeat(count) {
            val transferCount = r.u8(pos + 2)
            var ndr = false
            for (t in 0 until transferCount) {
                if (r.bytes(pos + 24 + t * 20, 20).contentEquals(NDR_SYNTAX)) ndr = true
            }
            if (ndr && !accepted) {
                accepted = true
                w.u16(0).u16(0).bytes(NDR_SYNTAX)
            } else {
                // Provider rejection: proposed transfer syntaxes not supported.
                w.u16(2).u16(2).zeros(20)
            }
            pos += 24 + transferCount * 20
        }
        return finish(w)
    }

    private fun response(callId: Int, contextId: Int, stub: ByteArray): ByteArray = finish(
        header(PTYPE_RESPONSE, callId)
            .u32(stub.size).u16(contextId).u8(0).u8(0)
            .bytes(stub),
    )

    private fun fault(callId: Int, contextId: Int): ByteArray = finish(
        header(PTYPE_FAULT, callId)
            .u32(0).u16(contextId).u8(0).u8(0)
            .u32(NCA_OP_RNG_ERROR).u32(0),
    )

    private fun call(opnum: Int, r: ByteReader): ByteArray? = when (opnum) {
        OP_NETR_SHARE_ENUM -> shareEnum(r)
        OP_NETR_SHARE_GET_INFO -> shareGetInfo(r)
        else -> null
    }

    /** Skips a unique pointer to a conformant varying string; returns the position after it. */
    private fun skipUniqueString(r: ByteReader, pos: Int): Int {
        if (r.u32(pos) == 0L) return pos + 4
        return skipString(r, pos + 4)
    }

    private fun skipString(r: ByteReader, pos: Int): Int {
        val actual = r.u32(pos + 8).toInt()
        val end = pos + 12 + actual * 2
        return (end + 3) and 3.inv()
    }

    private fun readString(r: ByteReader, pos: Int): String {
        val actual = r.u32(pos + 8).toInt()
        return r.utf16(pos + 12, actual * 2).trimEnd('\u0000')
    }

    private fun shareEnum(r: ByteReader): ByteArray {
        val pos = skipUniqueString(r, 0)
        val level = r.i32(pos)
        val w = ByteWriter()
        if (level != 0 && level != 1 && level != 2) {
            return w.u32(level).u32(level).u32(0).u32(0).u32(0).u32(WERR_UNKNOWN_LEVEL).toByteArray()
        }
        var ref = 0x20000
        w.u32(level).u32(level).u32(ref++)
        w.u32(shares.size).u32(ref++)
        w.u32(shares.size)
        shares.forEach { writeInfoFixed(w, it, level) { ref++ } }
        shares.forEach { writeInfoDeferred(w, it, level) }
        w.u32(shares.size) // total entries
        w.u32(ref).u32(0) // resume handle
        w.u32(0) // WERR_OK
        return w.toByteArray()
    }

    private fun shareGetInfo(r: ByteReader): ByteArray {
        var pos = skipUniqueString(r, 0)
        val name = readString(r, pos)
        pos = skipString(r, pos)
        val level = r.i32(pos)
        val w = ByteWriter()
        val share = shares.firstOrNull { it.name.equals(name, ignoreCase = true) }
        if (share == null || (level != 0 && level != 1 && level != 2)) {
            val error = if (share == null) WERR_NET_NAME_NOT_FOUND else WERR_UNKNOWN_LEVEL
            return w.u32(level).u32(0).u32(error).toByteArray()
        }
        var ref = 0x20000
        w.u32(level).u32(ref++)
        writeInfoFixed(w, share, level) { ref++ }
        writeInfoDeferred(w, share, level)
        w.u32(0)
        return w.toByteArray()
    }

    private fun writeInfoFixed(w: ByteWriter, share: ShareListing, level: Int, nextRef: () -> Int) {
        w.u32(nextRef())
        if (level == 0) return
        w.u32(share.type).u32(nextRef())
        if (level == 2) {
            w.u32(0) // permissions
            w.u32(-1) // max uses
            w.u32(0) // current uses
            w.u32(nextRef()) // path
            w.u32(0) // password (null)
        }
    }

    private fun writeInfoDeferred(w: ByteWriter, share: ShareListing, level: Int) {
        writeString(w, share.name)
        if (level == 0) return
        writeString(w, share.remark)
        if (level == 2) writeString(w, if (share.type == STYPE_DISKTREE) "C:\\" else "")
    }

    private fun writeString(w: ByteWriter, s: String) {
        val chars = s.length + 1
        w.u32(chars).u32(0).u32(chars).utf16(s).u16(0).align(4)
    }

    companion object {
        const val STYPE_DISKTREE = 0
        const val STYPE_IPC_SPECIAL = 0x80000003.toInt()

        private const val PTYPE_REQUEST = 0
        private const val PTYPE_RESPONSE = 2
        private const val PTYPE_FAULT = 3
        private const val PTYPE_BIND = 11
        private const val PTYPE_BIND_ACK = 12
        private const val PTYPE_ALTER_CONTEXT = 14
        private const val PTYPE_ALTER_CONTEXT_RESP = 15
        private const val PFC_FIRST_FRAG = 0x01
        private const val PFC_LAST_FRAG = 0x02
        private const val PFC_OBJECT_UUID = 0x80
        private const val ASSOC_GROUP = 0x53f0
        private const val NCA_OP_RNG_ERROR = 0x1c010002
        private const val OP_NETR_SHARE_ENUM = 15
        private const val OP_NETR_SHARE_GET_INFO = 16
        private const val WERR_UNKNOWN_LEVEL = 0x7C
        private const val WERR_NET_NAME_NOT_FOUND = 0x906

        /** NDR 2.0 transfer syntax 8a885d04-1ceb-11c9-9fe8-08002b104860, version 2. */
        private val NDR_SYNTAX = byteArrayOf(
            0x04, 0x5d, 0x88.toByte(), 0x8a.toByte(), 0xeb.toByte(), 0x1c, 0xc9.toByte(), 0x11,
            0x9f.toByte(), 0xe8.toByte(), 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60,
            0x02, 0x00, 0x00, 0x00,
        )
    }
}
