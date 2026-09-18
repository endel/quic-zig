//! Thin syscall wrappers for libxev. Replaces the pre-0.16 `std.posix`
//! wrapper surface that Zig removed; each function here is ~1-3 lines of
//! composition over `std.posix.system.*` and a shared `wrap` helper, so
//! callers still get `try posix.foo(args)` ergonomics without reinventing
//! errno handling per call site.

const std = @import("std");
const builtin = @import("builtin");
const posix_std = std.posix;

// ---- Re-exports so this module is a drop-in for `const posix = std.posix` ----
pub const system = posix_std.system;
pub const errno = posix_std.errno;
pub const unexpectedErrno = posix_std.unexpectedErrno;
pub const setsockopt = if (builtin.os.tag == .windows) setsockoptWin else posix_std.setsockopt;

fn setsockoptWin(
    sockfd: anytype,
    level: i32,
    optname: u32,
    opt: []const u8,
) error{
    PermissionDenied,
    FileDescriptorInvalid,
    FileDescriptorNotASocket,
    InvalidProtocolOption,
    SystemResources,
    TimeoutTooBig,
    AlreadyConnected,
    NetworkSubsystemFailed,
    Unexpected,
}!void {
    const w = @import("windows.zig");
    const s: w.ws2_32.SOCKET = @ptrCast(sockfd);
    const rc = w.ws2_32.setsockopt(s, @intCast(level), @intCast(optname), opt.ptr, @intCast(opt.len));
    if (rc != -1) return;
    return switch (w.ws2_32.WSAGetLastError()) {
        .WSAEACCES => error.PermissionDenied,
        .WSAEBADF => error.FileDescriptorInvalid,
        .WSAENOTSOCK => error.FileDescriptorNotASocket,
        .WSAEINVAL => error.InvalidProtocolOption,
        .WSAENOBUFS => error.SystemResources,
        .WSAENETDOWN => error.NetworkSubsystemFailed,
        else => error.Unexpected,
    };
}

pub const AF = posix_std.AF;
pub const CLOCK = posix_std.CLOCK;
pub const E = posix_std.E;
pub const IPPROTO = posix_std.IPPROTO;
pub const Kevent = posix_std.Kevent;
pub const MSG = posix_std.MSG;
pub const O = posix_std.O;
pub const POLL = posix_std.POLL;
pub const SHUT = posix_std.SHUT;
pub const SO = posix_std.SO;
pub const SOCK = posix_std.SOCK;
pub const SOL = posix_std.SOL;
pub const TCP = posix_std.TCP;
pub const W = posix_std.W;

pub const fd_t = posix_std.fd_t;
pub const socket_t = posix_std.socket_t;
pub const socklen_t = posix_std.socklen_t;
pub const pid_t = posix_std.pid_t;
pub const clockid_t = posix_std.clockid_t;
pub const timespec = posix_std.timespec;
pub const sockaddr = posix_std.sockaddr;
pub const msghdr = posix_std.msghdr;
pub const msghdr_const = posix_std.msghdr_const;
pub const iovec = posix_std.iovec;
pub const iovec_const = posix_std.iovec_const;

// ---- Error handling ----

/// Replacement for the removed `std.posix.ShutdownHow`.
pub const ShutdownHow = enum { recv, send, both };

/// Unified error set for every wrapper below — a conservative superset of
/// the pre-0.16 `posix.{Read,Write,Accept,Connect,Shutdown,...}Error`
/// composites. libxev's public error sets are unions over this.
pub const Error = error{
    AccessDenied,
    AddressFamilyNotSupported,
    AddressInUse,
    AddressNotAvailable,
    AlreadyConnected,
    BrokenPipe,
    Canceled,
    ConnectionAborted,
    ConnectionPending,
    ConnectionRefused,
    ConnectionResetByPeer,
    ConnectionTimedOut,
    DeviceBusy,
    DiskQuota,
    EOF,
    EventNotFound,
    FileDescriptorAlreadyPresentInSet,
    FileDescriptorInvalid,
    FileDescriptorNotASocket,
    FileDescriptorNotRegistered,
    FileTooBig,
    InputOutput,
    IsDir,
    MessageTooBig,
    NetworkSubsystemFailed,
    NetworkUnreachable,
    NoDevice,
    NoSpaceLeft,
    NotConnected,
    NotOpenForReading,
    NotOpenForWriting,
    OperationNotSupported,
    Overflow,
    PermissionDenied,
    ProcessFdQuotaExceeded,
    ProcessNotFound,
    ProtocolFailure,
    ProtocolNotSupported,
    SocketNotBound,
    SocketNotListening,
    SystemFdQuotaExceeded,
    SystemResources,
    TimerUnsupported,
    Unexpected,
    Unseekable,
    UserResourceLimitReached,
    WouldBlock,
    // Aliases accepted by legacy libxev call sites.
    SocketNotConnected,
    // setsockopt error variants (present in std.posix.setsockopt's error set).
    NetworkDown,
    OperationUnsupported,
    InvalidProtocolOption,
    TimeoutTooBig,
};

pub fn errnoToError(e: E) Error {
    return switch (e) {
        .SUCCESS => unreachable,
        .ACCES, .PERM => error.PermissionDenied,
        .ADDRINUSE => error.AddressInUse,
        .ADDRNOTAVAIL => error.AddressNotAvailable,
        .AFNOSUPPORT => error.AddressFamilyNotSupported,
        .AGAIN, .INPROGRESS => error.WouldBlock,
        .ALREADY => error.ConnectionPending,
        .BADF => error.FileDescriptorInvalid,
        .BUSY => error.DeviceBusy,
        .CONNABORTED => error.ConnectionAborted,
        .CONNREFUSED => error.ConnectionRefused,
        .CONNRESET => error.ConnectionResetByPeer,
        .DQUOT => error.DiskQuota,
        .EXIST => error.FileDescriptorAlreadyPresentInSet,
        .FBIG => error.FileTooBig,
        .HOSTUNREACH, .NETUNREACH => error.NetworkUnreachable,
        .IO => error.InputOutput,
        .ISCONN => error.AlreadyConnected,
        .ISDIR => error.IsDir,
        .MFILE => error.ProcessFdQuotaExceeded,
        .MSGSIZE => error.MessageTooBig,
        .NETDOWN => error.NetworkSubsystemFailed,
        .NFILE => error.SystemFdQuotaExceeded,
        .NOBUFS, .NOMEM => error.SystemResources,
        .NODEV, .NXIO => error.NoDevice,
        .NOENT => error.EventNotFound,
        .NOSPC => error.NoSpaceLeft,
        .NOTCONN => error.NotConnected,
        .NOTSOCK => error.FileDescriptorNotASocket,
        .OPNOTSUPP => error.OperationNotSupported,
        .OVERFLOW => error.Overflow,
        .PIPE => error.BrokenPipe,
        .PROTO => error.ProtocolFailure,
        .PROTONOSUPPORT, .PROTOTYPE => error.ProtocolNotSupported,
        .SPIPE => error.Unseekable,
        .SRCH => error.ProcessNotFound,
        .TIMEDOUT => error.ConnectionTimedOut,
        else => error.Unexpected,
    };
}

/// Map a raw syscall return to either its value or a libxev `Error`.
pub inline fn wrap(rc: anytype) Error!@TypeOf(rc) {
    return switch (errno(rc)) {
        .SUCCESS => rc,
        else => |e| errnoToError(e),
    };
}

/// Like `wrap`, but retries the call on EINTR. Pass the syscall as a fn
/// value + args tuple so the retry can re-issue it.
pub inline fn wrapRetry(comptime f: anytype, args: anytype) Error!@TypeOf(@call(.auto, f, args)) {
    while (true) {
        const rc = @call(.auto, f, args);
        switch (errno(rc)) {
            .SUCCESS => return rc,
            .INTR => continue,
            else => |e| return errnoToError(e),
        }
    }
}

// ---- File descriptors ----

pub inline fn close(fd: fd_t) void {
    if (builtin.os.tag == .windows) {
        // On Windows, `fd` is always a socket handle in libxev's call sites
        // (regular file handles are closed via `windows.CloseHandle`). The
        // POSIX `close(2)` wrapper in std.c requires libc on Windows and
        // isn't appropriate for sockets anyway, so route to `closesocket`
        // from our local ws2_32 shim.
        _ = @import("windows.zig").ws2_32.closesocket(@ptrCast(fd));
        return;
    }
    _ = system.close(fd);
}

pub inline fn dup(old_fd: fd_t) Error!fd_t {
    return @intCast(try wrap(system.dup(old_fd)));
}

pub inline fn read(fd: fd_t, buf: []u8) Error!usize {
    return @intCast(try wrapRetry(system.read, .{ fd, buf.ptr, buf.len }));
}

pub inline fn write(fd: fd_t, bytes: []const u8) Error!usize {
    return @intCast(try wrapRetry(system.write, .{ fd, bytes.ptr, bytes.len }));
}

pub inline fn pread(fd: fd_t, buf: []u8, offset: u64) Error!usize {
    return @intCast(try wrapRetry(system.pread, .{ fd, buf.ptr, buf.len, @as(i64, @bitCast(offset)) }));
}

pub inline fn pwrite(fd: fd_t, bytes: []const u8, offset: u64) Error!usize {
    return @intCast(try wrapRetry(system.pwrite, .{ fd, bytes.ptr, bytes.len, @as(i64, @bitCast(offset)) }));
}

// ---- Sockets ----

/// On Windows, socket syscalls live in ws2_32.dll, not libc. `std.posix`
/// still forwards to `std.c.<name>` which fails to link without `-lc`, so
/// we dispatch to our local ws2_32 shim for all Winsock calls.
const is_windows = builtin.os.tag == .windows;
const win = if (is_windows) struct {
    const w = @import("windows.zig");

    fn wrapWsa(rc: c_int) Error!c_int {
        if (rc != -1) return rc;
        const err = w.ws2_32.WSAGetLastError();
        return switch (err) {
            .WSA_IO_PENDING => error.WouldBlock,
            .WSAEWOULDBLOCK => error.WouldBlock,
            .WSAENETDOWN => error.NetworkSubsystemFailed,
            .WSAENETUNREACH => error.NetworkUnreachable,
            .WSAECONNABORTED => error.ConnectionAborted,
            .WSAECONNRESET => error.ConnectionResetByPeer,
            .WSAENOBUFS => error.SystemResources,
            .WSAEMFILE => error.ProcessFdQuotaExceeded,
            .WSAEAFNOSUPPORT => error.AddressFamilyNotSupported,
            .WSAEPROTONOSUPPORT => error.ProtocolNotSupported,
            else => error.Unexpected,
        };
    }

    fn asSocket(s: socket_t) w.ws2_32.SOCKET {
        return @ptrCast(s);
    }
} else struct {};

pub inline fn socket(domain: u32, socket_type: u32, protocol: u32) Error!socket_t {
    if (is_windows) {
        const s = win.w.ws2_32.WSASocketW(
            @intCast(domain),
            @intCast(socket_type),
            @intCast(protocol),
            null,
            0,
            win.w.ws2_32.WSA_FLAG_OVERLAPPED,
        );
        if (@intFromPtr(s) == @intFromPtr(win.w.ws2_32.INVALID_SOCKET)) {
            return switch (win.w.ws2_32.WSAGetLastError()) {
                .WSAEAFNOSUPPORT => error.AddressFamilyNotSupported,
                .WSAEMFILE => error.ProcessFdQuotaExceeded,
                .WSAEPROTONOSUPPORT => error.ProtocolNotSupported,
                .WSAENOBUFS => error.SystemResources,
                else => error.Unexpected,
            };
        }
        return @ptrCast(s);
    }
    // macOS lacks SOCK.CLOEXEC/SOCK.NONBLOCK as socket() flags; callers must
    // apply them via fcntl after creation if needed.
    var stype = socket_type;
    if (builtin.os.tag == .macos or builtin.os.tag == .ios or builtin.os.tag == .visionos) {
        stype &= ~@as(u32, SOCK.CLOEXEC | SOCK.NONBLOCK);
    }
    return @intCast(try wrap(system.socket(@intCast(domain), @intCast(stype), @intCast(protocol))));
}

pub inline fn bind(sock: socket_t, addr: *const sockaddr, len: socklen_t) Error!void {
    if (is_windows) {
        _ = try win.wrapWsa(win.w.ws2_32.bind(win.asSocket(sock), addr, @intCast(len)));
        return;
    }
    _ = try wrap(system.bind(sock, addr, len));
}

pub inline fn listen(sock: socket_t, backlog: u31) Error!void {
    if (is_windows) {
        _ = try win.wrapWsa(win.w.ws2_32.listen(win.asSocket(sock), backlog));
        return;
    }
    _ = try wrap(system.listen(sock, backlog));
}

pub inline fn accept(
    sock: socket_t,
    addr: ?*sockaddr,
    addr_size: ?*socklen_t,
    flags: u32,
) Error!socket_t {
    _ = flags;
    return @intCast(try wrapRetry(system.accept, .{ sock, addr, addr_size }));
}

pub inline fn connect(sock: socket_t, addr: *const sockaddr, len: socklen_t) Error!void {
    _ = try wrapRetry(system.connect, .{ sock, addr, len });
}

pub inline fn getsockname(sock: socket_t, addr: *sockaddr, addrlen: *socklen_t) Error!void {
    if (is_windows) {
        var wlen: c_int = @intCast(addrlen.*);
        _ = try win.wrapWsa(win.w.ws2_32.getsockname(win.asSocket(sock), addr, &wlen));
        addrlen.* = @intCast(wlen);
        return;
    }
    _ = try wrap(system.getsockname(sock, addr, addrlen));
}

pub inline fn getsockoptError(sockfd: fd_t) Error!void {
    var code: c_int = undefined;
    try setsockopt(sockfd, SOL.SOCKET, SO.ERROR, std.mem.asBytes(&code));
    return switch (@as(E, @enumFromInt(code))) {
        .SUCCESS => {},
        else => |e| errnoToError(e),
    };
}

pub inline fn shutdown(sock: socket_t, how: ShutdownHow) Error!void {
    if (is_windows) {
        // Winsock shutdown uses SD_RECEIVE=0, SD_SEND=1, SD_BOTH=2.
        const n: c_int = switch (how) {
            .recv => 0,
            .send => 1,
            .both => 2,
        };
        // Declared inline: std.os.windows.ws2_32 doesn't export `shutdown`.
        const shutdown_fn = struct {
            extern "ws2_32" fn shutdown(s: win.w.ws2_32.SOCKET, how_i: c_int) callconv(.winapi) c_int;
        }.shutdown;
        _ = try win.wrapWsa(shutdown_fn(win.asSocket(sock), n));
        return;
    }
    const n: i32 = switch (how) {
        .recv => SHUT.RD,
        .send => SHUT.WR,
        .both => SHUT.RDWR,
    };
    _ = try wrap(system.shutdown(sock, n));
}

pub inline fn send(sock: socket_t, buf: []const u8, flags: u32) Error!usize {
    return sendto(sock, buf, flags, null, 0);
}

pub inline fn sendto(
    sock: socket_t,
    buf: []const u8,
    flags: u32,
    dest_addr: ?*const sockaddr,
    addrlen: socklen_t,
) Error!usize {
    return @intCast(try wrapRetry(system.sendto, .{ sock, buf.ptr, buf.len, flags, dest_addr, addrlen }));
}

pub inline fn sendmsg(sock: socket_t, msg: *const msghdr_const, flags: u32) Error!usize {
    return @intCast(try wrapRetry(system.sendmsg, .{ sock, msg, flags }));
}

pub inline fn recv(sock: socket_t, buf: []u8, flags: u32) Error!usize {
    return recvfrom(sock, buf, flags, null, null);
}

pub inline fn recvfrom(
    sock: socket_t,
    buf: []u8,
    flags: u32,
    src_addr: ?*sockaddr,
    addrlen: ?*socklen_t,
) Error!usize {
    return @intCast(try wrapRetry(system.recvfrom, .{ sock, buf.ptr, buf.len, flags, src_addr, addrlen }));
}

// ---- Linux-specific event fds / epoll ----

pub inline fn eventfd(initval: u32, flags: u32) Error!i32 {
    return @intCast(try wrap(system.eventfd(initval, flags)));
}

pub inline fn epoll_create1(flags: u32) Error!i32 {
    return @intCast(try wrap(system.epoll_create1(flags)));
}

pub inline fn epoll_ctl(epfd: i32, op: u32, fd: i32, event: ?*system.epoll_event) Error!void {
    _ = try wrap(system.epoll_ctl(epfd, op, fd, event));
}

pub inline fn epoll_wait(epfd: i32, events: []system.epoll_event, timeout: i32) usize {
    while (true) {
        const rc = system.epoll_wait(epfd, events.ptr, @intCast(events.len), timeout);
        switch (errno(rc)) {
            .INTR => continue,
            else => return @intCast(rc),
        }
    }
}

pub inline fn pipe2(flags: O) Error![2]fd_t {
    if (builtin.os.tag != .linux) return error.OperationNotSupported;
    var fds: [2]i32 = undefined;
    _ = try wrap(std.os.linux.pipe2(&fds, flags));
    return .{ fds[0], fds[1] };
}

// ---- kqueue ----

pub inline fn kqueue() Error!i32 {
    return @intCast(try wrap(system.kqueue()));
}

pub inline fn kevent(
    kq: i32,
    changelist: []const Kevent,
    eventlist: []Kevent,
    timeout: ?*const timespec,
) Error!usize {
    while (true) {
        const rc = system.kevent(
            kq,
            changelist.ptr,
            std.math.cast(c_int, changelist.len) orelse return error.Overflow,
            eventlist.ptr,
            std.math.cast(c_int, eventlist.len) orelse return error.Overflow,
            timeout,
        );
        switch (errno(rc)) {
            .SUCCESS => return @intCast(rc),
            .INTR => continue,
            else => |e| return errnoToError(e),
        }
    }
}

// ---- Time / process ----

pub inline fn clock_gettime(clock_id: clockid_t) Error!timespec {
    var ts: timespec = undefined;
    _ = try wrap(system.clock_gettime(clock_id, &ts));
    return ts;
}

pub const WaitPidResult = struct { pid: pid_t, status: u32 };

pub fn waitpid(pid: pid_t, flags: u32) WaitPidResult {
    var status: if (builtin.link_libc) c_int else u32 = undefined;
    while (true) {
        const rc = system.waitpid(pid, &status, @intCast(flags));
        switch (errno(rc)) {
            .SUCCESS => return .{ .pid = @intCast(rc), .status = @bitCast(status) },
            .INTR => continue,
            else => unreachable,
        }
    }
}
