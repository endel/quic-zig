//! Windows API shim for libxev.
//!
//! Zig 0.16 moved networking and file I/O under `std.Io` and stripped most
//! of the raw Win32/Winsock function externs and several struct/error
//! declarations out of `std.os.windows`. libxev's IOCP backend drives
//! OVERLAPPED I/O directly through kernel32/ws2_32 instead of going through
//! `std.Io`, so this module re-declares the missing surface locally.

const std = @import("std");
const windows = std.os.windows;
const posix = std.posix;

// === Types still provided by std.os.windows ===
pub const BOOL = windows.BOOL;
pub const BYTE = windows.BYTE;
pub const DWORD = windows.DWORD;
pub const LARGE_INTEGER = windows.LARGE_INTEGER;
pub const HANDLE = windows.HANDLE;
pub const HMODULE = windows.HMODULE;
pub const LPCSTR = windows.LPCSTR;
pub const LPVOID = windows.LPVOID;
pub const PVOID = windows.PVOID;
pub const SECURITY_ATTRIBUTES = windows.SECURITY_ATTRIBUTES;
pub const SIZE_T = windows.SIZE_T;
pub const ULONG = windows.ULONG;
pub const ULONG_PTR = windows.ULONG_PTR;
pub const ULONGLONG = windows.ULONGLONG;
/// `std.os.windows.UnexpectedError` became private in 0.16. Source of truth
/// is `std.posix.UnexpectedError`.
pub const UnexpectedError = posix.UnexpectedError;
pub const Win32Error = windows.Win32Error;
pub const INVALID_HANDLE_VALUE = windows.INVALID_HANDLE_VALUE;
pub const DUPLICATE_SAME_ACCESS = windows.DUPLICATE_SAME_ACCESS;
pub const CloseHandle = windows.CloseHandle;
pub const unexpectedError = windows.unexpectedError;

// === Constants removed from std.os.windows in 0.16 ===
pub const INFINITE: DWORD = 0xFFFFFFFF;
pub const GENERIC_READ: DWORD = 0x80000000;
pub const GENERIC_WRITE: DWORD = 0x40000000;
pub const OPEN_ALWAYS: DWORD = 4;
pub const FILE_FLAG_OVERLAPPED: DWORD = 0x40000000;

// === OVERLAPPED structures (removed from std.os.windows in 0.16) ===
pub const OVERLAPPED = extern struct {
    Internal: ULONG_PTR,
    InternalHigh: ULONG_PTR,
    DUMMYUNIONNAME: extern union {
        DUMMYSTRUCTNAME: extern struct {
            Offset: DWORD,
            OffsetHigh: DWORD,
        },
        Pointer: ?PVOID,
    },
    hEvent: ?HANDLE,
};

pub const OVERLAPPED_ENTRY = extern struct {
    lpCompletionKey: ULONG_PTR,
    lpOverlapped: ?*OVERLAPPED,
    Internal: ULONG_PTR,
    dwNumberOfBytesTransferred: DWORD,
};

// === Local error sets (removed from std.os.windows in 0.16) ===
pub const ReadFileError = error{
    OperationAborted,
    BrokenPipe,
    HandleEof,
    NetNameDeleted,
    Unexpected,
};

pub const WriteFileError = error{
    OperationAborted,
    BrokenPipe,
    NotOpenForWriting,
    NetNameDeleted,
    Unexpected,
};

// === ntdll-backed helpers (QPC/QPF were removed from std.os.windows in 0.16) ===
pub fn QueryPerformanceCounter() u64 {
    var v: LARGE_INTEGER = undefined;
    _ = windows.ntdll.RtlQueryPerformanceCounter(&v);
    return @bitCast(v);
}

pub fn QueryPerformanceFrequency() u64 {
    var v: LARGE_INTEGER = undefined;
    _ = windows.ntdll.RtlQueryPerformanceFrequency(&v);
    return @bitCast(v);
}

// === Local kernel32 externs (most were removed from std.os.windows.kernel32) ===
pub const kernel32 = struct {
    pub const GetLastError = getLastError;
    fn getLastError() Win32Error {
        return windows.GetLastError();
    }

    pub extern "kernel32" fn CreateFileW(
        lpFileName: [*:0]const u16,
        dwDesiredAccess: DWORD,
        dwShareMode: DWORD,
        lpSecurityAttributes: ?*SECURITY_ATTRIBUTES,
        dwCreationDisposition: DWORD,
        dwFlagsAndAttributes: DWORD,
        hTemplateFile: ?HANDLE,
    ) callconv(.winapi) HANDLE;

    pub extern "kernel32" fn ReadFile(
        hFile: HANDLE,
        lpBuffer: [*]u8,
        nNumberOfBytesToRead: DWORD,
        lpNumberOfBytesRead: ?*DWORD,
        lpOverlapped: ?*OVERLAPPED,
    ) callconv(.winapi) BOOL;

    pub extern "kernel32" fn WriteFile(
        hFile: HANDLE,
        lpBuffer: [*]const u8,
        nNumberOfBytesToWrite: DWORD,
        lpNumberOfBytesWritten: ?*DWORD,
        lpOverlapped: ?*OVERLAPPED,
    ) callconv(.winapi) BOOL;

    pub extern "kernel32" fn CancelIoEx(
        hFile: HANDLE,
        lpOverlapped: ?*OVERLAPPED,
    ) callconv(.winapi) BOOL;

    pub extern "kernel32" fn CreateIoCompletionPort(
        FileHandle: HANDLE,
        ExistingCompletionPort: ?HANDLE,
        CompletionKey: ULONG_PTR,
        NumberOfConcurrentThreads: DWORD,
    ) callconv(.winapi) ?HANDLE;

    pub extern "kernel32" fn GetQueuedCompletionStatusEx(
        CompletionPort: HANDLE,
        lpCompletionPortEntries: [*]OVERLAPPED_ENTRY,
        ulCount: DWORD,
        ulNumEntriesRemoved: *DWORD,
        dwMilliseconds: DWORD,
        fAlertable: BOOL,
    ) callconv(.winapi) BOOL;

    pub extern "kernel32" fn PostQueuedCompletionStatus(
        CompletionPort: HANDLE,
        dwNumberOfBytesTransferred: DWORD,
        dwCompletionKey: ULONG_PTR,
        lpOverlapped: ?*OVERLAPPED,
    ) callconv(.winapi) BOOL;

    pub extern "kernel32" fn DeleteFileW(
        lpFileName: [*:0]const u16,
    ) callconv(.winapi) BOOL;

    pub extern "kernel32" fn GetOverlappedResult(
        hFile: HANDLE,
        lpOverlapped: *OVERLAPPED,
        lpNumberOfBytesTransferred: *DWORD,
        bWait: BOOL,
    ) callconv(.winapi) BOOL;
};

// Kept as a top-level name for legacy call sites.
pub const DeleteFileW = kernel32.DeleteFileW;

/// A stack-sized buffer for a WTF-16 path, mirroring the `span()` surface
/// libxev's call sites use on the pre-0.16 `PathSpace`.
pub const PathSpace = struct {
    /// `PATH_MAX_WIDE + 1` in legacy Windows; we size to
    /// `std.fs.max_path_bytes` which is large enough for any legit path.
    data: [std.fs.max_path_bytes]u16 = undefined,
    len: usize = 0,

    pub fn span(self: *const PathSpace) [:0]const u16 {
        // Safety: `sliceToPrefixedFileW` always writes a trailing 0 at `len`.
        return self.data[0..self.len :0];
    }
};

/// WTF-8 → WTF-16LE path conversion. Replaces the removed
/// `std.os.windows.sliceToPrefixedFileW`. The first parameter is retained
/// to match the legacy call-site shape (`null` = treat `path` as absolute);
/// libxev never passed a non-null directory handle.
pub fn sliceToPrefixedFileW(
    dir: ?HANDLE,
    path: []const u8,
) error{ BadPathName, NameTooLong, InvalidWtf8 }!PathSpace {
    _ = dir;
    var ps: PathSpace = .{};
    const len = std.unicode.wtf8ToWtf16Le(ps.data[0 .. ps.data.len - 1], path) catch
        return error.InvalidWtf8;
    if (len >= ps.data.len) return error.NameTooLong;
    ps.data[len] = 0;
    ps.len = len;
    return ps;
}

// === Local ws2_32 (Winsock) shim ===
//
// 0.16 trimmed ws2_32.zig down to type/constant definitions — every function
// extern we rely on is declared locally below. Types that still exist
// upstream are re-exported to keep call sites stable.
pub const ws2_32 = struct {
    pub const ADDRESS_FAMILY = windows.ws2_32.ADDRESS_FAMILY;
    pub const GROUP = windows.ws2_32.GROUP;
    pub const AF = windows.ws2_32.AF;
    pub const SOCK = windows.ws2_32.SOCK;
    pub const SOL = windows.ws2_32.SOL;
    pub const SO = windows.ws2_32.SO;
    pub const IPPROTO = windows.ws2_32.IPPROTO;
    pub const MSG = windows.ws2_32.MSG;
    pub const TCP = windows.ws2_32.TCP;
    pub const sockaddr = windows.ws2_32.sockaddr;
    pub const socklen_t = windows.ws2_32.socklen_t;
    pub const timeval = windows.ws2_32.timeval;

    pub const SOCKET = *anyopaque;
    pub const INVALID_SOCKET: SOCKET = @ptrFromInt(@as(usize, std.math.maxInt(usize)));
    pub const SOCKET_ERROR: c_int = -1;

    pub const WSA_FLAG_OVERLAPPED: DWORD = 0x01;

    pub const WSABUF = extern struct {
        len: ULONG,
        buf: [*]u8,
    };

    pub const WSAPROTOCOL_INFOW = extern struct {
        dwServiceFlags1: DWORD,
        dwServiceFlags2: DWORD,
        dwServiceFlags3: DWORD,
        dwServiceFlags4: DWORD,
        dwProviderFlags: DWORD,
        ProviderId: extern struct {
            Data1: ULONG,
            Data2: u16,
            Data3: u16,
            Data4: [8]u8,
        },
        dwCatalogEntryId: DWORD,
        ProtocolChain: extern struct {
            ChainLen: c_int,
            ChainEntries: [7]DWORD,
        },
        iVersion: c_int,
        iAddressFamily: c_int,
        iMaxSockAddr: c_int,
        iMinSockAddr: c_int,
        iSocketType: c_int,
        iProtocol: c_int,
        iProtocolMaxOffset: c_int,
        iNetworkByteOrder: c_int,
        iSecurityScheme: c_int,
        dwMessageSize: DWORD,
        dwProviderReserved: DWORD,
        szProtocol: [256]u16,
    };

    pub const WSAOVERLAPPED_COMPLETION_ROUTINE = ?*const fn (
        dwError: DWORD,
        cbTransferred: DWORD,
        lpOverlapped: *OVERLAPPED,
        dwFlags: DWORD,
    ) callconv(.winapi) void;

    /// Pared-down WinsockError — libxev only pattern-matches on a small set
    /// of values and falls through to `unexpectedWSAError` for everything
    /// else, so we don't need to exhaustively list every WSA code.
    pub const WinsockError = enum(u16) {
        WSA_IO_PENDING = 997,
        WSA_OPERATION_ABORTED = 995,
        WSAEINTR = 10004,
        WSAEBADF = 10009,
        WSAEACCES = 10013,
        WSAEINVAL = 10022,
        WSAEMFILE = 10024,
        WSAEWOULDBLOCK = 10035,
        WSAEINPROGRESS = 10036,
        WSAENOTSOCK = 10038,
        WSAEPROTONOSUPPORT = 10043,
        WSAEAFNOSUPPORT = 10047,
        WSAENETDOWN = 10050,
        WSAENETUNREACH = 10051,
        WSAENETRESET = 10052,
        WSAECONNABORTED = 10053,
        WSAECONNRESET = 10054,
        WSAENOBUFS = 10055,
        WSAEISCONN = 10056,
        WSAENOTCONN = 10057,
        WSAETIMEDOUT = 10060,
        _,
    };

    pub extern "ws2_32" fn WSAGetLastError() callconv(.winapi) WinsockError;

    pub extern "ws2_32" fn WSASocketW(
        af: c_int,
        @"type": c_int,
        protocol: c_int,
        lpProtocolInfo: ?*WSAPROTOCOL_INFOW,
        g: GROUP,
        dwFlags: DWORD,
    ) callconv(.winapi) SOCKET;

    pub extern "ws2_32" fn closesocket(s: SOCKET) callconv(.winapi) c_int;

    pub extern "ws2_32" fn connect(
        s: SOCKET,
        name: *const posix.sockaddr,
        namelen: c_int,
    ) callconv(.winapi) c_int;

    pub extern "ws2_32" fn getsockname(
        s: SOCKET,
        name: *posix.sockaddr,
        namelen: *c_int,
    ) callconv(.winapi) c_int;

    pub extern "ws2_32" fn getsockopt(
        s: SOCKET,
        level: c_int,
        optname: c_int,
        optval: [*]u8,
        optlen: *c_int,
    ) callconv(.winapi) c_int;

    pub extern "mswsock" fn AcceptEx(
        sListenSocket: SOCKET,
        sAcceptSocket: SOCKET,
        lpOutputBuffer: *anyopaque,
        dwReceiveDataLength: DWORD,
        dwLocalAddressLength: DWORD,
        dwRemoteAddressLength: DWORD,
        lpdwBytesReceived: *DWORD,
        lpOverlapped: *OVERLAPPED,
    ) callconv(.winapi) BOOL;

    pub extern "ws2_32" fn WSASend(
        s: SOCKET,
        lpBuffers: [*]WSABUF,
        dwBufferCount: DWORD,
        lpNumberOfBytesSent: ?*DWORD,
        dwFlags: DWORD,
        lpOverlapped: ?*OVERLAPPED,
        lpCompletionRoutine: WSAOVERLAPPED_COMPLETION_ROUTINE,
    ) callconv(.winapi) c_int;

    pub extern "ws2_32" fn WSARecv(
        s: SOCKET,
        lpBuffers: [*]WSABUF,
        dwBufferCount: DWORD,
        lpNumberOfBytesRecvd: ?*DWORD,
        lpFlags: *DWORD,
        lpOverlapped: ?*OVERLAPPED,
        lpCompletionRoutine: WSAOVERLAPPED_COMPLETION_ROUTINE,
    ) callconv(.winapi) c_int;

    pub extern "ws2_32" fn WSASendTo(
        s: SOCKET,
        lpBuffers: [*]WSABUF,
        dwBufferCount: DWORD,
        lpNumberOfBytesSent: ?*DWORD,
        dwFlags: DWORD,
        lpTo: *const posix.sockaddr,
        iTolen: c_int,
        lpOverlapped: ?*OVERLAPPED,
        lpCompletionRoutine: WSAOVERLAPPED_COMPLETION_ROUTINE,
    ) callconv(.winapi) c_int;

    pub extern "ws2_32" fn WSARecvFrom(
        s: SOCKET,
        lpBuffers: [*]WSABUF,
        dwBufferCount: DWORD,
        lpNumberOfBytesRecvd: ?*DWORD,
        lpFlags: *DWORD,
        lpFrom: ?*posix.sockaddr,
        lpFromlen: ?*c_int,
        lpOverlapped: ?*OVERLAPPED,
        lpCompletionRoutine: WSAOVERLAPPED_COMPLETION_ROUTINE,
    ) callconv(.winapi) c_int;

    pub extern "ws2_32" fn WSAGetOverlappedResult(
        s: SOCKET,
        lpOverlapped: *OVERLAPPED,
        lpcbTransfer: *DWORD,
        fWait: BOOL,
        lpdwFlags: *DWORD,
    ) callconv(.winapi) BOOL;

    pub extern "ws2_32" fn bind(
        s: SOCKET,
        name: *const posix.sockaddr,
        namelen: c_int,
    ) callconv(.winapi) c_int;

    pub extern "ws2_32" fn listen(
        s: SOCKET,
        backlog: c_int,
    ) callconv(.winapi) c_int;

    pub extern "ws2_32" fn setsockopt(
        s: SOCKET,
        level: c_int,
        optname: c_int,
        optval: [*]const u8,
        optlen: c_int,
    ) callconv(.winapi) c_int;
};

pub const WSASocketError = error{
    AddressFamilyNotSupported,
    ProcessFdQuotaExceeded,
    ProtocolNotSupported,
    SystemResources,
    Unexpected,
};

pub fn WSASocketW(
    af: i32,
    sock_type: i32,
    proto: i32,
    lpProtocolInfo: ?*ws2_32.WSAPROTOCOL_INFOW,
    g: ws2_32.GROUP,
    dwFlags: DWORD,
) WSASocketError!ws2_32.SOCKET {
    const s = ws2_32.WSASocketW(af, sock_type, proto, lpProtocolInfo, g, dwFlags);
    if (@intFromPtr(s) == @intFromPtr(ws2_32.INVALID_SOCKET)) {
        const err = ws2_32.WSAGetLastError();
        return switch (err) {
            .WSAEAFNOSUPPORT => error.AddressFamilyNotSupported,
            .WSAEMFILE => error.ProcessFdQuotaExceeded,
            .WSAEPROTONOSUPPORT => error.ProtocolNotSupported,
            .WSAENOBUFS => error.SystemResources,
            else => unexpectedWSAError(err),
        };
    }
    return s;
}

pub fn unexpectedWSAError(err: ws2_32.WinsockError) UnexpectedError {
    return unexpectedError(@enumFromInt(@intFromEnum(err)));
}

pub fn CreateIoCompletionPort(
    FileHandle: HANDLE,
    ExistingCompletionPort: ?HANDLE,
    CompletionKey: ULONG_PTR,
    NumberOfConcurrentThreads: DWORD,
) error{Unexpected}!HANDLE {
    const h = kernel32.CreateIoCompletionPort(
        FileHandle,
        ExistingCompletionPort,
        CompletionKey,
        NumberOfConcurrentThreads,
    );
    return h orelse return unexpectedError(windows.GetLastError());
}

pub fn GetQueuedCompletionStatusEx(
    CompletionPort: HANDLE,
    entries: []OVERLAPPED_ENTRY,
    dwMilliseconds: ?DWORD,
    fAlertable: bool,
) error{ Aborted, Cancelled, EOF, Timeout, Unexpected }!u32 {
    var removed: DWORD = 0;
    const ok = kernel32.GetQueuedCompletionStatusEx(
        CompletionPort,
        entries.ptr,
        @intCast(entries.len),
        &removed,
        dwMilliseconds orelse INFINITE,
        if (fAlertable) .TRUE else .FALSE,
    );
    if (ok == .FALSE) {
        return switch (windows.GetLastError()) {
            .ABANDONED_WAIT_0 => error.Aborted,
            .OPERATION_ABORTED => error.Cancelled,
            .HANDLE_EOF => error.EOF,
            .WAIT_TIMEOUT => error.Timeout,
            else => |err| unexpectedError(err),
        };
    }
    return removed;
}

pub fn PostQueuedCompletionStatus(
    CompletionPort: HANDLE,
    dwNumberOfBytesTransferred: DWORD,
    dwCompletionKey: ULONG_PTR,
    lpOverlapped: ?*OVERLAPPED,
) error{Unexpected}!void {
    const ok = kernel32.PostQueuedCompletionStatus(
        CompletionPort,
        dwNumberOfBytesTransferred,
        dwCompletionKey,
        lpOverlapped,
    );
    if (ok == .FALSE) return unexpectedError(windows.GetLastError());
}

pub const exp = struct {
    pub const STATUS_PENDING = 0x00000103;
    pub const STILL_ACTIVE = STATUS_PENDING;

    pub const JOBOBJECT_ASSOCIATE_COMPLETION_PORT = extern struct {
        CompletionKey: windows.ULONG_PTR,
        CompletionPort: windows.HANDLE,
    };

    pub const JOBOBJECT_BASIC_LIMIT_INFORMATION = extern struct {
        PerProcessUserTimeLimit: windows.LARGE_INTEGER,
        PerJobUserTimeLimit: windows.LARGE_INTEGER,
        LimitFlags: windows.DWORD,
        MinimumWorkingSetSize: windows.SIZE_T,
        MaximumWorkingSetSize: windows.SIZE_T,
        ActiveProcessLimit: windows.DWORD,
        Affinity: windows.ULONG_PTR,
        PriorityClass: windows.DWORD,
        SchedulingClass: windows.DWORD,
    };

    pub const IO_COUNTERS = extern struct {
        ReadOperationCount: windows.ULONGLONG,
        WriteOperationCount: windows.ULONGLONG,
        OtherOperationCount: windows.ULONGLONG,
        ReadTransferCount: windows.ULONGLONG,
        WriteTransferCount: windows.ULONGLONG,
        OtherTransferCount: windows.ULONGLONG,
    };

    pub const JOBOBJECT_EXTENDED_LIMIT_INFORMATION = extern struct {
        BasicLimitInformation: JOBOBJECT_BASIC_LIMIT_INFORMATION,
        IoInfo: IO_COUNTERS,
        ProcessMemoryLimit: windows.SIZE_T,
        JobMemoryLimit: windows.SIZE_T,
        PeakProcessMemoryUsed: windows.SIZE_T,
        PeakJobMemoryUsed: windows.SIZE_T,
    };

    pub const JOB_OBJECT_LIMIT_ACTIVE_PROCESS = 0x00000008;
    pub const JOB_OBJECT_LIMIT_AFFINITY = 0x00000010;
    pub const JOB_OBJECT_LIMIT_BREAKAWAY_OK = 0x00000800;
    pub const JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION = 0x00000400;
    pub const JOB_OBJECT_LIMIT_JOB_MEMORY = 0x00000200;
    pub const JOB_OBJECT_LIMIT_JOB_TIME = 0x00000004;
    pub const JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000;
    pub const JOB_OBJECT_LIMIT_PRESERVE_JOB_TIME = 0x00000004;
    pub const JOB_OBJECT_LIMIT_PRIORITY_CLASS = 0x00000020;
    pub const JOB_OBJECT_LIMIT_PROCESS_MEMORY = 0x00000100;
    pub const JOB_OBJECT_LIMIT_PROCESS_TIME = 0x00000002;
    pub const JOB_OBJECT_LIMIT_SCHEDULING_CLASS = 0x00000080;
    pub const JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK = 0x00001000;
    pub const JOB_OBJECT_LIMIT_SUBSET_AFFINITY = 0x00004000;
    pub const JOB_OBJECT_LIMIT_WORKINGSET = 0x00000001;

    pub const JOBOBJECT_INFORMATION_CLASS = enum(c_int) {
        JobObjectAssociateCompletionPortInformation = 7,
        JobObjectBasicLimitInformation = 2,
        JobObjectBasicUIRestrictions = 4,
        JobObjectCpuRateControlInformation = 15,
        JobObjectEndOfJobTimeInformation = 6,
        JobObjectExtendedLimitInformation = 9,
        JobObjectGroupInformation = 11,
        JobObjectGroupInformationEx = 14,
        JobObjectLimitViolationInformation2 = 34,
        JobObjectNetRateControlInformation = 32,
        JobObjectNotificationLimitInformation = 12,
        JobObjectNotificationLimitInformation2 = 33,
        JobObjectSecurityLimitInformation = 5,
    };

    pub const JOB_OBJECT_MSG_TYPE = enum(windows.DWORD) {
        JOB_OBJECT_MSG_END_OF_JOB_TIME = 1,
        JOB_OBJECT_MSG_END_OF_PROCESS_TIME = 2,
        JOB_OBJECT_MSG_ACTIVE_PROCESS_LIMIT = 3,
        JOB_OBJECT_MSG_ACTIVE_PROCESS_ZERO = 4,
        JOB_OBJECT_MSG_NEW_PROCESS = 6,
        JOB_OBJECT_MSG_EXIT_PROCESS = 7,
        JOB_OBJECT_MSG_ABNORMAL_EXIT_PROCESS = 8,
        JOB_OBJECT_MSG_PROCESS_MEMORY_LIMIT = 9,
        JOB_OBJECT_MSG_JOB_MEMORY_LIMIT = 10,
        JOB_OBJECT_MSG_NOTIFICATION_LIMIT = 11,
        JOB_OBJECT_MSG_JOB_CYCLE_TIME_LIMIT = 12,
        JOB_OBJECT_MSG_SILO_TERMINATED = 13,
        _,
    };

    /// Process/Job Object extern declarations. Named `job` (not `kernel32`)
    /// to avoid shadowing the top-level `kernel32` struct in this module.
    pub const job = struct {
        pub extern "kernel32" fn GetProcessId(Process: HANDLE) callconv(.winapi) DWORD;
        pub extern "kernel32" fn CreateJobObjectA(lpSecurityAttributes: ?*SECURITY_ATTRIBUTES, lpName: ?LPCSTR) callconv(.winapi) HANDLE;
        pub extern "kernel32" fn AssignProcessToJobObject(hJob: HANDLE, hProcess: HANDLE) callconv(.winapi) BOOL;
        pub extern "kernel32" fn SetInformationJobObject(
            hJob: HANDLE,
            JobObjectInformationClass: JOBOBJECT_INFORMATION_CLASS,
            lpJobObjectInformation: LPVOID,
            cbJobObjectInformationLength: DWORD,
        ) callconv(.winapi) BOOL;
    };

    pub const CreateFileError = error{} || UnexpectedError;

    pub fn CreateFile(
        lpFileName: [*:0]const u16,
        dwDesiredAccess: DWORD,
        dwShareMode: DWORD,
        lpSecurityAttributes: ?*SECURITY_ATTRIBUTES,
        dwCreationDisposition: DWORD,
        dwFlagsAndAttributes: DWORD,
        hTemplateFile: ?HANDLE,
    ) CreateFileError!HANDLE {
        const handle = kernel32.CreateFileW(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
        if (handle == INVALID_HANDLE_VALUE) {
            return unexpectedError(windows.GetLastError());
        }

        return handle;
    }

    pub fn ReadFile(
        handle: HANDLE,
        buffer: []u8,
        overlapped: ?*OVERLAPPED,
    ) ReadFileError!?usize {
        var read: DWORD = 0;
        const result: BOOL = kernel32.ReadFile(handle, buffer.ptr, @intCast(buffer.len), &read, overlapped);
        if (result == .FALSE) {
            const err = windows.GetLastError();
            return switch (err) {
                .IO_PENDING => null,
                else => unexpectedError(err),
            };
        }

        return @intCast(read);
    }

    pub fn WriteFile(
        handle: HANDLE,
        buffer: []const u8,
        overlapped: ?*OVERLAPPED,
    ) WriteFileError!?usize {
        var written: DWORD = 0;
        const result: BOOL = kernel32.WriteFile(handle, buffer.ptr, @intCast(buffer.len), &written, overlapped);
        if (result == .FALSE) {
            const err = windows.GetLastError();
            return switch (err) {
                .IO_PENDING => null,
                else => unexpectedError(err),
            };
        }

        return @intCast(written);
    }

    pub const DeleteFileError = error{} || UnexpectedError;

    pub fn DeleteFile(name: [*:0]const u16) DeleteFileError!void {
        const result: BOOL = kernel32.DeleteFileW(name);
        if (result == .FALSE) {
            return unexpectedError(windows.GetLastError());
        }
    }

    pub const CreateJobObjectError = error{AlreadyExists} || UnexpectedError;
    pub fn CreateJobObject(
        lpSecurityAttributes: ?*SECURITY_ATTRIBUTES,
        lpName: ?LPCSTR,
    ) !HANDLE {
        const handle = exp.job.CreateJobObjectA(lpSecurityAttributes, lpName);
        return switch (windows.GetLastError()) {
            .SUCCESS => handle,
            .ALREADY_EXISTS => CreateJobObjectError.AlreadyExists,
            else => |err| unexpectedError(err),
        };
    }

    pub fn AssignProcessToJobObject(hJob: HANDLE, hProcess: HANDLE) UnexpectedError!void {
        const result: BOOL = exp.job.AssignProcessToJobObject(hJob, hProcess);
        if (result == .FALSE) {
            return unexpectedError(windows.GetLastError());
        }
    }

    pub fn SetInformationJobObject(
        hJob: HANDLE,
        JobObjectInformationClass: JOBOBJECT_INFORMATION_CLASS,
        lpJobObjectInformation: LPVOID,
        cbJobObjectInformationLength: DWORD,
    ) UnexpectedError!void {
        const result: BOOL = exp.job.SetInformationJobObject(
            hJob,
            JobObjectInformationClass,
            lpJobObjectInformation,
            cbJobObjectInformationLength,
        );

        if (result == .FALSE) {
            return unexpectedError(windows.GetLastError());
        }
    }
};
