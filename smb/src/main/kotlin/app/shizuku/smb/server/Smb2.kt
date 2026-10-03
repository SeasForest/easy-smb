package app.shizuku.smb.server

/** Protocol constants from MS-SMB2 and MS-FSCC. */
internal object Smb2 {
    const val HEADER_SIZE = 64

    // Commands
    const val NEGOTIATE = 0x00
    const val SESSION_SETUP = 0x01
    const val LOGOFF = 0x02
    const val TREE_CONNECT = 0x03
    const val TREE_DISCONNECT = 0x04
    const val CREATE = 0x05
    const val CLOSE = 0x06
    const val FLUSH = 0x07
    const val READ = 0x08
    const val WRITE = 0x09
    const val LOCK = 0x0A
    const val IOCTL = 0x0B
    const val CANCEL = 0x0C
    const val ECHO = 0x0D
    const val QUERY_DIRECTORY = 0x0E
    const val CHANGE_NOTIFY = 0x0F
    const val QUERY_INFO = 0x10
    const val SET_INFO = 0x11
    const val OPLOCK_BREAK = 0x12

    // Header flags
    const val FLAGS_SERVER_TO_REDIR = 0x00000001
    const val FLAGS_ASYNC_COMMAND = 0x00000002
    const val FLAGS_RELATED_OPERATIONS = 0x00000004
    const val FLAGS_SIGNED = 0x00000008

    // Dialects
    const val DIALECT_202 = 0x0202
    const val DIALECT_210 = 0x0210
    const val DIALECT_300 = 0x0300
    const val DIALECT_302 = 0x0302
    const val DIALECT_311 = 0x0311
    const val DIALECT_WILDCARD = 0x02FF

    const val NEGOTIATE_SIGNING_ENABLED = 0x0001
    const val NEGOTIATE_SIGNING_REQUIRED = 0x0002
    const val GLOBAL_CAP_LARGE_MTU = 0x00000004

    // Create dispositions
    const val FILE_SUPERSEDE = 0
    const val FILE_OPEN = 1
    const val FILE_CREATE = 2
    const val FILE_OPEN_IF = 3
    const val FILE_OVERWRITE = 4
    const val FILE_OVERWRITE_IF = 5

    // Create options
    const val FILE_DIRECTORY_FILE = 0x00000001
    const val FILE_NON_DIRECTORY_FILE = 0x00000040
    const val FILE_DELETE_ON_CLOSE = 0x00001000

    // Create actions
    const val FILE_SUPERSEDED = 0
    const val FILE_OPENED = 1
    const val FILE_CREATED = 2
    const val FILE_OVERWRITTEN = 3

    // Access mask bits
    const val FILE_READ_DATA = 0x00000001
    const val FILE_WRITE_DATA = 0x00000002
    const val FILE_APPEND_DATA = 0x00000004
    const val FILE_READ_EA = 0x00000008
    const val FILE_WRITE_EA = 0x00000010
    const val FILE_EXECUTE = 0x00000020
    const val FILE_DELETE_CHILD = 0x00000040
    const val FILE_READ_ATTRIBUTES = 0x00000080
    const val FILE_WRITE_ATTRIBUTES = 0x00000100
    const val DELETE = 0x00010000
    const val READ_CONTROL = 0x00020000
    const val WRITE_DAC = 0x00040000
    const val WRITE_OWNER = 0x00080000
    const val SYNCHRONIZE = 0x00100000
    const val ACCESS_SYSTEM_SECURITY = 0x01000000
    const val MAXIMUM_ALLOWED = 0x02000000
    const val GENERIC_ALL = 0x10000000
    const val GENERIC_EXECUTE = 0x20000000
    const val GENERIC_WRITE = 0x40000000
    const val GENERIC_READ = 0x80000000.toInt()

    const val FILE_ALL_ACCESS = 0x001F01FF
    const val FILE_GENERIC_READ = 0x00120089
    const val FILE_GENERIC_WRITE = 0x00120116
    const val FILE_GENERIC_EXECUTE = 0x001200A0

    /** Every access right that can modify a file, its metadata or its security. */
    const val WRITE_ACCESS_MASK = FILE_WRITE_DATA or FILE_APPEND_DATA or FILE_WRITE_EA or
        FILE_DELETE_CHILD or FILE_WRITE_ATTRIBUTES or DELETE or WRITE_DAC or WRITE_OWNER

    /** What a read-only share grants: reading data, attributes, EAs and security. */
    const val READ_ONLY_ACCESS = FILE_GENERIC_READ or FILE_EXECUTE

    // File attributes
    const val ATTR_READONLY = 0x00000001
    const val ATTR_HIDDEN = 0x00000002
    const val ATTR_DIRECTORY = 0x00000010
    const val ATTR_ARCHIVE = 0x00000020
    const val ATTR_NORMAL = 0x00000080

    // Info types
    const val INFO_FILE = 0x01
    const val INFO_FILESYSTEM = 0x02
    const val INFO_SECURITY = 0x03
    const val INFO_QUOTA = 0x04

    // FSCTL codes
    const val FSCTL_DFS_GET_REFERRALS = 0x00060194
    const val FSCTL_DFS_GET_REFERRALS_EX = 0x000601B0
    const val FSCTL_PIPE_TRANSCEIVE = 0x0011C017
    const val FSCTL_VALIDATE_NEGOTIATE_INFO = 0x00140204
    const val FSCTL_QUERY_NETWORK_INTERFACE_INFO = 0x001401FC
    const val FSCTL_SET_SPARSE = 0x000900C4
    const val IOCTL_IS_FSCTL = 0x00000001

    /** Placeholder FileId meaning "the file opened earlier in this compound". */
    val RELATED_FILE_ID = -1L
}

/** NTSTATUS codes. */
internal object Status {
    const val SUCCESS = 0x00000000
    const val PENDING = 0x00000103
    const val NOTIFY_CLEANUP = 0x0000010B
    const val NO_MORE_FILES = 0x80000006.toInt()
    const val BUFFER_OVERFLOW = 0x80000005.toInt()
    const val INVALID_INFO_CLASS = 0xC0000003.toInt()
    const val INFO_LENGTH_MISMATCH = 0xC0000004.toInt()
    const val INVALID_HANDLE = 0xC0000008.toInt()
    const val INVALID_PARAMETER = 0xC000000D.toInt()
    const val NO_SUCH_FILE = 0xC000000F.toInt()
    const val INVALID_DEVICE_REQUEST = 0xC0000010.toInt()
    const val END_OF_FILE = 0xC0000011.toInt()
    const val MORE_PROCESSING_REQUIRED = 0xC0000016.toInt()
    const val ACCESS_DENIED = 0xC0000022.toInt()
    const val BUFFER_TOO_SMALL = 0xC0000023.toInt()
    const val OBJECT_NAME_INVALID = 0xC0000033.toInt()
    const val OBJECT_NAME_NOT_FOUND = 0xC0000034.toInt()
    const val OBJECT_NAME_COLLISION = 0xC0000035.toInt()
    const val OBJECT_PATH_NOT_FOUND = 0xC000003A.toInt()
    const val SHARING_VIOLATION = 0xC0000043.toInt()
    const val EAS_NOT_SUPPORTED = 0xC000004F.toInt()
    const val LOGON_FAILURE = 0xC000006D.toInt()
    const val DISK_FULL = 0xC000007F.toInt()
    const val INSUFFICIENT_RESOURCES = 0xC000009A.toInt()
    const val FILE_IS_A_DIRECTORY = 0xC00000BA.toInt()
    const val NOT_SUPPORTED = 0xC00000BB.toInt()
    const val NETWORK_NAME_DELETED = 0xC00000C9.toInt()
    const val BAD_NETWORK_NAME = 0xC00000CC.toInt()
    const val REQUEST_NOT_ACCEPTED = 0xC00000D0.toInt()
    const val INTERNAL_ERROR = 0xC00000E5.toInt()
    const val DIRECTORY_NOT_EMPTY = 0xC0000101.toInt()
    const val NOT_A_DIRECTORY = 0xC0000103.toInt()
    const val CANCELLED = 0xC0000120.toInt()
    const val FILE_CLOSED = 0xC0000128.toInt()
    const val FS_DRIVER_REQUIRED = 0xC000019C.toInt()
    const val USER_SESSION_DELETED = 0xC0000203.toInt()
    const val NOT_FOUND = 0xC0000225.toInt()
    const val PIPE_EMPTY = 0xC00000D9.toInt()
}

/** An operation failed with an NTSTATUS code to report to the client. */
internal class SmbException(val status: Int, val errorData: ByteArray = ByteArray(0)) :
    Exception("status 0x%08x".format(status))
