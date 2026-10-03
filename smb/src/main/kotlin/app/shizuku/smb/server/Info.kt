package app.shizuku.smb.server

/** Encoders for MS-FSCC information classes. */
internal object Info {
    // File information classes
    const val FILE_DIRECTORY = 0x01
    const val FILE_FULL_DIRECTORY = 0x02
    const val FILE_BOTH_DIRECTORY = 0x03
    const val FILE_BASIC = 0x04
    const val FILE_STANDARD = 0x05
    const val FILE_INTERNAL = 0x06
    const val FILE_EA = 0x07
    const val FILE_ACCESS = 0x08
    const val FILE_NAME = 0x09
    const val FILE_RENAME = 0x0A
    const val FILE_NAMES = 0x0C
    const val FILE_DISPOSITION = 0x0D
    const val FILE_POSITION = 0x0E
    const val FILE_FULL_EA = 0x0F
    const val FILE_MODE = 0x10
    const val FILE_ALIGNMENT = 0x11
    const val FILE_ALL = 0x12
    const val FILE_ALLOCATION = 0x13
    const val FILE_END_OF_FILE = 0x14
    const val FILE_ALTERNATE_NAME = 0x15
    const val FILE_STREAM = 0x16
    const val FILE_COMPRESSION = 0x1C
    const val FILE_NETWORK_OPEN = 0x22
    const val FILE_ATTRIBUTE_TAG = 0x23
    const val FILE_ID_BOTH_DIRECTORY = 0x25
    const val FILE_ID_FULL_DIRECTORY = 0x26
    const val FILE_VALID_DATA_LENGTH = 0x27
    const val FILE_NORMALIZED_NAME = 0x30
    const val FILE_ID = 0x3B
    const val FILE_DISPOSITION_EX = 0x40

    // File system information classes
    const val FS_VOLUME = 0x01
    const val FS_SIZE = 0x03
    const val FS_DEVICE = 0x04
    const val FS_ATTRIBUTE = 0x05
    const val FS_FULL_SIZE = 0x07
    const val FS_OBJECT_ID = 0x08
    const val FS_SECTOR_SIZE = 0x0B

    const val VOLUME_SERIAL = 0x534D4231L // "SMB1"
    private const val BYTES_PER_SECTOR = 512
    private const val SECTORS_PER_UNIT = 8
    private const val UNIT = BYTES_PER_SECTOR * SECTORS_PER_UNIT

    /** Bytes per entry before the file name, per directory information class. */
    fun directoryEntryBaseSize(infoClass: Int): Int = when (infoClass) {
        FILE_DIRECTORY -> 64
        FILE_FULL_DIRECTORY -> 68
        FILE_ID_FULL_DIRECTORY -> 80
        FILE_BOTH_DIRECTORY -> 94
        FILE_ID_BOTH_DIRECTORY -> 104
        FILE_NAMES -> 12
        else -> throw SmbException(Status.INVALID_INFO_CLASS)
    }

    /** One directory entry with NextEntryOffset left as 0. */
    fun directoryEntry(w: ByteWriter, infoClass: Int, f: FileInfo) {
        val name = utf16(f.name)
        w.u32(0).u32(0) // NextEntryOffset, FileIndex
        if (infoClass == FILE_NAMES) {
            w.u32(name.size).bytes(name)
            return
        }
        w.u64(f.creationTime).u64(f.lastAccessTime).u64(f.lastWriteTime).u64(f.changeTime)
        w.u64(f.size).u64(f.allocationSize).u32(f.attributes).u32(name.size)
        when (infoClass) {
            FILE_FULL_DIRECTORY -> w.u32(0)
            FILE_ID_FULL_DIRECTORY -> w.u32(0).u32(0).u64(f.fileId)
            FILE_BOTH_DIRECTORY -> w.u32(0).u8(0).u8(0).zeros(24)
            FILE_ID_BOTH_DIRECTORY -> w.u32(0).u8(0).u8(0).zeros(24).u16(0).u64(f.fileId)
        }
        w.bytes(name)
    }

    fun basic(w: ByteWriter, f: FileInfo) {
        w.u64(f.creationTime).u64(f.lastAccessTime).u64(f.lastWriteTime).u64(f.changeTime)
        w.u32(f.attributes).u32(0)
    }

    fun standard(w: ByteWriter, f: FileInfo, deletePending: Boolean) {
        w.u64(f.allocationSize).u64(f.size).u32(1)
        w.u8(if (deletePending) 1 else 0).u8(if (f.isDirectory) 1 else 0).u16(0)
    }

    fun networkOpen(w: ByteWriter, f: FileInfo) {
        w.u64(f.creationTime).u64(f.lastAccessTime).u64(f.lastWriteTime).u64(f.changeTime)
        w.u64(f.allocationSize).u64(f.size).u32(f.attributes).u32(0)
    }

    fun all(w: ByteWriter, f: FileInfo, access: Int, deletePending: Boolean, name: String) {
        basic(w, f)
        standard(w, f, deletePending)
        w.u64(f.fileId) // internal
        w.u32(0) // EA size
        w.u32(access)
        w.u64(0) // position
        w.u32(0) // mode
        w.u32(0) // alignment
        val n = utf16(name)
        w.u32(n.size).bytes(n)
    }

    fun stream(w: ByteWriter, f: FileInfo) {
        if (f.isDirectory) return
        val name = utf16("::\$DATA")
        w.u32(0).u32(name.size).u64(f.size).u64(f.allocationSize).bytes(name)
    }

    fun fsVolume(w: ByteWriter, label: String) {
        val n = utf16(label)
        w.u64(0).u32(VOLUME_SERIAL).u32(n.size).u8(0).u8(0).bytes(n)
    }

    fun fsSize(w: ByteWriter, total: Long, free: Long) {
        w.u64(total / UNIT).u64(free / UNIT).u32(SECTORS_PER_UNIT).u32(BYTES_PER_SECTOR)
    }

    fun fsFullSize(w: ByteWriter, total: Long, free: Long) {
        w.u64(total / UNIT).u64(free / UNIT).u64(free / UNIT).u32(SECTORS_PER_UNIT).u32(BYTES_PER_SECTOR)
    }

    fun fsAttribute(w: ByteWriter, readOnly: Boolean) {
        // Case-preserving, Unicode names; no ACLs, streams or EAs.
        var attrs = 0x00000002 or 0x00000004
        if (readOnly) attrs = attrs or 0x00080000
        val name = utf16("NTFS")
        w.u32(attrs).u32(255).u32(name.size).bytes(name)
    }

    fun fsSectorSize(w: ByteWriter) {
        w.u32(BYTES_PER_SECTOR).u32(BYTES_PER_SECTOR).u32(BYTES_PER_SECTOR).u32(BYTES_PER_SECTOR)
        w.u32(0x3) // aligned device, partition aligned
        w.u32(0).u32(0)
    }

    /**
     * A self-relative security descriptor: owner and group Everyone, and a DACL granting
     * Everyone [access]. Only the parts selected by [additional] are included.
     */
    fun securityDescriptor(additional: Int, access: Int): ByteArray {
        val everyone = byteArrayOf(1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0)
        val owner = additional and 0x1 != 0
        val group = additional and 0x2 != 0
        val dacl = additional and 0x4 != 0
        var control = 0x8000 // self-relative
        if (dacl) control = control or 0x0004
        var offset = 20
        val ownerOffset = if (owner) offset.also { offset += everyone.size } else 0
        val groupOffset = if (group) offset.also { offset += everyone.size } else 0
        val daclOffset = if (dacl) offset else 0
        val w = ByteWriter()
        w.u8(1).u8(0).u16(control)
        w.u32(ownerOffset).u32(groupOffset).u32(0).u32(daclOffset)
        if (owner) w.bytes(everyone)
        if (group) w.bytes(everyone)
        if (dacl) {
            val aceSize = 8 + everyone.size
            w.u8(2).u8(0).u16(8 + aceSize).u16(1).u16(0) // ACL header, one ACE
            w.u8(0).u8(0x03).u16(aceSize).u32(access).bytes(everyone) // allowed, inherited by children
        }
        return w.toByteArray()
    }
}
