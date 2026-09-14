//! Thin syscall wrappers, kept as the library's single syscall seam: every
//! call into the OS goes through here, so a port is a matter of this file.
//! We only claim to work where we actually test. Currently: Linux, macOS,
//! FreeBSD and Windows.
//!
//! POSIX targets call `std.c` directly. Windows lives in `sys/windows.zig`:
//! Winsock for sockets, `std.Io` for files, clocks and randomness. Each
//! function here hands Windows off on its first line, so what follows is the
//! POSIX version.
//!
//! These helpers did not disappear in Zig 0.16, they moved onto the `Io`
//! interface: sockets to `std.Io.net`, files to `std.Io.Dir`, randomness to
//! `std.Io.random`, time to `std.Io.Clock`, sleep to `std.Io.sleep`. What
//! `std.posix` still exposes is `setsockopt`, `poll` and `read`.
//!
//! We keep this seam because `Io` is viral: adopting it means threading an
//! `io: Io` argument through ~170 call sites across the library, and `Io`
//! is new enough in 0.16 that its shape will still move. The seam lets the
//! internals here migrate to `std.Io.net` later — worth doing for
//! `Socket.sendMany` (`sendmmsg` on Linux) — without touching callers.
//!
//! Naming mirrors the pre-0.16 `std.posix.X`. Constants (`AF`, `SOCK`,
//! `SOL`, `SO`) still live on `std.posix`.

const std = @import("std");
const builtin = @import("builtin");
const posix = std.posix;
const c = std.c;
const windows = @import("sys/windows.zig");

const is_windows = builtin.os.tag == .windows;

comptime {
    switch (builtin.os.tag) {
        .linux, .macos, .ios, .watchos, .tvos, .visionos, .freebsd, .netbsd, .openbsd, .dragonfly, .windows => {},
        else => @compileError("sys: unsupported OS"),
    }
}

// BSD/Darwin-only. 0.16 std.c drops the declaration; declare locally.
extern "c" fn arc4random_buf(buf: [*]u8, nbytes: usize) void;
const c_arc4random_buf = arc4random_buf;

pub const socket_t = posix.socket_t;
pub const fd_t = posix.fd_t;
pub const sockaddr = posix.sockaddr;
pub const socklen_t = posix.socklen_t;
pub const timespec = posix.timespec;

// Not on every target's `std.posix` — Winsock's `IPPROTO` has no IPv6 entry.
const IPPROTO_IPV6: i32 = 41;
const IPV6_V6ONLY: u32 = if (builtin.os.tag == .linux) 26 else 27;

// --- errors ---

pub const SocketError = error{
    AddressFamilyNotSupported,
    ProtocolFamilyNotSupported,
    ProtocolNotSupported,
    SystemFdQuotaExceeded,
    ProcessFdQuotaExceeded,
    SystemResources,
    PermissionDenied,
    Unexpected,
};

pub const BindError = error{
    AccessDenied,
    AddressInUse,
    AddressNotAvailable,
    AddressFamilyNotSupported,
    SymLinkLoop,
    NameTooLong,
    FileNotFound,
    SystemResources,
    NotDir,
    ReadOnlyFileSystem,
    NetworkSubsystemFailed,
    FileDescriptorNotASocket,
    AlreadyBound,
    Unexpected,
};

pub const SendToError = error{
    WouldBlock,
    ConnectionResetByPeer,
    MessageTooBig,
    SystemResources,
    BrokenPipe,
    NetworkUnreachable,
    HostUnreachable,
    AccessDenied,
    NetworkSubsystemFailed,
    FileDescriptorNotASocket,
    AddressFamilyNotSupported,
    Unexpected,
};

pub const RecvFromError = error{
    WouldBlock,
    SystemResources,
    ConnectionRefused,
    ConnectionResetByPeer,
    NetworkSubsystemFailed,
    SocketNotConnected,
    Unexpected,
};

pub const GetSockNameError = error{
    SystemResources,
    NetworkSubsystemFailed,
    NotSocket,
    SocketNotBound,
    Unexpected,
};

pub const SetSockOptError = posix.SetSockOptError;

pub const ClockGetTimeError = error{
    UnsupportedClock,
    Unexpected,
};

pub const GetRandomError = error{
    Unexpected,
};

// --- functions ---

pub fn socket(domain: u32, sock_type: u32, protocol: u32) SocketError!socket_t {
    if (is_windows) return windows.socket(domain, sock_type, protocol);
    // On Darwin, SOCK.NONBLOCK / SOCK.CLOEXEC are not accepted by socket(2)
    // and must be applied via fcntl after creation.
    const darwin_family = switch (builtin.os.tag) {
        .macos, .ios, .watchos, .tvos, .visionos => true,
        else => false,
    };
    const filtered_type: u32 = if (darwin_family)
        sock_type & ~@as(u32, posix.SOCK.NONBLOCK | posix.SOCK.CLOEXEC)
    else
        sock_type;
    const rc = c.socket(@intCast(domain), @intCast(filtered_type), @intCast(protocol));
    switch (posix.errno(rc)) {
        .SUCCESS => {},
        .ACCES => return error.PermissionDenied,
        .AFNOSUPPORT => return error.AddressFamilyNotSupported,
        .INVAL => return error.ProtocolFamilyNotSupported,
        .MFILE => return error.ProcessFdQuotaExceeded,
        .NFILE => return error.SystemFdQuotaExceeded,
        .NOBUFS => return error.SystemResources,
        .NOMEM => return error.SystemResources,
        .PROTONOSUPPORT => return error.ProtocolNotSupported,
        else => |err| return unexpected(err),
    }
    const fd: socket_t = @intCast(rc);
    if (darwin_family and (sock_type & posix.SOCK.NONBLOCK) != 0) {
        const nonblock: c_int = @bitCast(posix.O{ .NONBLOCK = true });
        _ = c.fcntl(fd, posix.F.SETFL, nonblock);
    }
    if (darwin_family and (sock_type & posix.SOCK.CLOEXEC) != 0) {
        const cloexec: c_int = posix.FD_CLOEXEC;
        _ = c.fcntl(fd, posix.F.SETFD, cloexec);
    }
    return fd;
}

pub const UdpSocketOptions = struct {
    /// IPv6 sockets only: carry IPv4 too, as v4-mapped addresses.
    dual_stack: bool = true,
    /// See `setReuseAddr`.
    reuse_addr: bool = false,
};

/// A nonblocking UDP socket for `family`, ready to bind.
///
/// On Windows it also stops ICMP errors from failing the socket's next
/// receive. By default Winsock reports a port-unreachable as WSAECONNRESET,
/// so on a server socket one departed client would break the receive loop
/// for every other connection.
pub fn udpSocket(family: u32, options: UdpSocketOptions) SocketError!socket_t {
    const fd = if (is_windows)
        try windows.udpSocket(family)
    else
        try socket(family, posix.SOCK.DGRAM | posix.SOCK.NONBLOCK, 0);
    errdefer close(fd);
    if (family == posix.AF.INET6) {
        const v6only: c_int = @intFromBool(!options.dual_stack);
        setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, std.mem.asBytes(&v6only)) catch {};
    }
    if (options.reuse_addr) setReuseAddr(fd);
    return fd;
}

pub fn setsockopt(sock: socket_t, level: i32, optname: u32, opt: []const u8) SetSockOptError!void {
    if (is_windows) return windows.setsockopt(sock, level, optname, opt);
    return posix.setsockopt(sock, level, optname, opt);
}

/// Let a restarted server bind its port straight away. A no-op on Windows,
/// where SO_REUSEADDR means something else: it lets a second socket bind a
/// port that is still in use.
pub fn setReuseAddr(sock: socket_t) void {
    if (is_windows) return;
    setsockopt(sock, posix.SOL.SOCKET, posix.SO.REUSEADDR, &std.mem.toBytes(@as(c_int, 1))) catch {};
}

pub fn close(fd: fd_t) void {
    if (is_windows) return windows.close(fd);
    // close(2) failures are unrecoverable from userspace (EINTR/EIO on some systems),
    // and retrying EINTR close is itself an anti-pattern on Linux — follow libc practice.
    _ = c.close(fd);
}

pub fn bind(sock: socket_t, addr: *const sockaddr, len: socklen_t) BindError!void {
    if (is_windows) return windows.bind(sock, addr, len);
    const rc = c.bind(sock, addr, len);
    switch (posix.errno(rc)) {
        .SUCCESS => return,
        .ACCES, .PERM => return error.AccessDenied,
        .ADDRINUSE => return error.AddressInUse,
        .ADDRNOTAVAIL => return error.AddressNotAvailable,
        .AFNOSUPPORT => return error.AddressFamilyNotSupported,
        .BADF => unreachable, // always a race condition
        .INVAL => return error.AlreadyBound,
        .NOTSOCK => return error.FileDescriptorNotASocket,
        .FAULT => unreachable,
        .LOOP => return error.SymLinkLoop,
        .NAMETOOLONG => return error.NameTooLong,
        .NOENT => return error.FileNotFound,
        .NOMEM => return error.SystemResources,
        .NOTDIR => return error.NotDir,
        .ROFS => return error.ReadOnlyFileSystem,
        else => |err| return unexpected(err),
    }
}

pub fn sendto(
    sock: socket_t,
    buf: []const u8,
    flags: u32,
    dest_addr: ?*const sockaddr,
    addrlen: socklen_t,
) SendToError!usize {
    if (is_windows) return windows.sendto(sock, buf, flags, dest_addr, addrlen);
    const rc = c.sendto(sock, buf.ptr, buf.len, flags, dest_addr, addrlen);
    switch (posix.errno(rc)) {
        .SUCCESS => return @intCast(rc),
        .ACCES => return error.AccessDenied,
        .AGAIN => return error.WouldBlock,
        .ALREADY => return error.WouldBlock,
        .BADF => unreachable, // always a race condition
        .CONNRESET => return error.ConnectionResetByPeer,
        .DESTADDRREQ => unreachable, // non-null dest_addr required
        .FAULT => unreachable,
        .INTR => return error.Unexpected,
        .INVAL => unreachable,
        .ISCONN => unreachable,
        .MSGSIZE => return error.MessageTooBig,
        .NOBUFS => return error.SystemResources,
        .NOMEM => return error.SystemResources,
        .NOTSOCK => return error.FileDescriptorNotASocket,
        .OPNOTSUPP => unreachable,
        .PIPE => return error.BrokenPipe,
        .AFNOSUPPORT => return error.AddressFamilyNotSupported,
        .LOOP => return error.Unexpected,
        .NAMETOOLONG => return error.Unexpected,
        .NOENT => return error.Unexpected,
        .NOTDIR => return error.Unexpected,
        .HOSTUNREACH => return error.HostUnreachable,
        .NETUNREACH => return error.NetworkUnreachable,
        .NOTCONN => return error.Unexpected,
        .NETDOWN => return error.NetworkSubsystemFailed,
        else => |err| return unexpected(err),
    }
}

pub fn recvfrom(
    sock: socket_t,
    buf: []u8,
    flags: u32,
    src_addr: ?*sockaddr,
    addrlen: ?*socklen_t,
) RecvFromError!usize {
    if (is_windows) return windows.recvfrom(sock, buf, flags, src_addr, addrlen);
    const rc = c.recvfrom(sock, buf.ptr, buf.len, flags, src_addr, addrlen);
    switch (posix.errno(rc)) {
        .SUCCESS => return @intCast(rc),
        .AGAIN => return error.WouldBlock,
        .BADF => unreachable, // always a race condition
        .CONNREFUSED => return error.ConnectionRefused,
        .CONNRESET => return error.ConnectionResetByPeer,
        .FAULT => unreachable,
        .INTR => return error.Unexpected,
        .INVAL => unreachable,
        .NOMEM => return error.SystemResources,
        .NOTCONN => return error.SocketNotConnected,
        .NOTSOCK => unreachable,
        .NETDOWN => return error.NetworkSubsystemFailed,
        else => |err| return unexpected(err),
    }
}

/// Raw write(2) — replaces `posix.write` for TCP streams etc.
pub fn write(fd: fd_t, bytes: []const u8) WriteError!usize {
    if (is_windows) return windows.write(fd, bytes);
    while (true) {
        const rc = c.write(fd, bytes.ptr, bytes.len);
        if (rc < 0) switch (posix.errno(rc)) {
            .INTR => continue,
            .AGAIN => return 0,
            .DQUOT => return error.DiskQuota,
            .NOSPC => return error.NoSpaceLeft,
            .PIPE => return error.BrokenPipe,
            .IO => return error.InputOutput,
            .CONNRESET => return error.ConnectionResetByPeer,
            .ACCES, .PERM => return error.AccessDenied,
            else => |err| return unexpected(err),
        };
        return @intCast(rc);
    }
}

/// Raw read(2) — replaces `posix.read` for TCP streams etc.
pub fn read(fd: fd_t, dest: []u8) ReadError!usize {
    if (is_windows) return windows.read(fd, dest);
    while (true) {
        const rc = c.read(fd, dest.ptr, dest.len);
        if (rc < 0) switch (posix.errno(rc)) {
            .INTR => continue,
            .AGAIN => return 0,
            .IO => return error.InputOutput,
            .ISDIR => return error.IsDir,
            .ACCES, .PERM => return error.AccessDenied,
            else => |err| return unexpected(err),
        };
        return @intCast(rc);
    }
}

pub const ListenError = error{
    AddressInUse,
    FileDescriptorNotASocket,
    SystemResources,
    OperationNotSupported,
    Unexpected,
};

pub fn listen(sock: socket_t, backlog: u31) ListenError!void {
    if (is_windows) return windows.listen(sock, backlog);
    const rc = c.listen(sock, @intCast(backlog));
    switch (posix.errno(rc)) {
        .SUCCESS => return,
        .ADDRINUSE => return error.AddressInUse,
        .BADF => unreachable,
        .NOTSOCK => return error.FileDescriptorNotASocket,
        .OPNOTSUPP => return error.OperationNotSupported,
        else => |err| return unexpected(err),
    }
}

pub const ResolveError = error{
    UnknownHostName,
    PathTooLong,
    Unexpected,
};

/// getaddrinfo, however the target spells it.
const netdb = if (is_windows) windows else struct {
    const addrinfo = c.addrinfo;
    const freeaddrinfo = c.freeaddrinfo;
    fn getaddrinfo(node: ?[*:0]const u8, service: ?[*:0]const u8, hints: ?*const addrinfo, result: *?*addrinfo) i32 {
        return @intFromEnum(c.getaddrinfo(node, service, hints, result));
    }
};

/// Resolve `host` (numeric IP or hostname) to an IPv4/IPv6 sockaddr via
/// getaddrinfo. Replaces 0.15 `std.net.getAddressList` which is gone in
/// 0.16. The returned address carries `port` in network byte order ready
/// for `sys.bind`/`sys.sendto`.
pub fn resolveHost(host: []const u8, port: u16) ResolveError!posix.sockaddr.storage {
    // Null-terminate host on the stack.
    var host_buf: [256]u8 = undefined;
    if (host.len >= host_buf.len) return error.PathTooLong;
    @memcpy(host_buf[0..host.len], host);
    host_buf[host.len] = 0;
    const host_z: [*:0]const u8 = @ptrCast(&host_buf);

    var port_buf: [8]u8 = undefined;
    const port_str = std.fmt.bufPrint(&port_buf, "{d}", .{port}) catch return error.Unexpected;
    if (port_str.len >= port_buf.len) return error.Unexpected;
    port_buf[port_str.len] = 0;
    const service_z: [*:0]const u8 = @ptrCast(&port_buf);

    var hints: netdb.addrinfo = std.mem.zeroes(netdb.addrinfo);
    hints.family = posix.AF.UNSPEC;
    hints.socktype = posix.SOCK.DGRAM;

    var res: ?*netdb.addrinfo = null;
    if (netdb.getaddrinfo(host_z, service_z, &hints, &res) != 0) return error.UnknownHostName;
    defer if (res) |r| netdb.freeaddrinfo(r);

    const first = res orelse return error.UnknownHostName;
    const addr_ptr = first.addr orelse return error.UnknownHostName;

    var storage: posix.sockaddr.storage = std.mem.zeroes(posix.sockaddr.storage);
    const copy_len = @min(@as(usize, first.addrlen), @sizeOf(posix.sockaddr.storage));
    @memcpy(
        @as([*]u8, @ptrCast(&storage))[0..copy_len],
        @as([*]const u8, @ptrCast(addr_ptr))[0..copy_len],
    );
    return storage;
}

pub const AcceptError = error{
    WouldBlock,
    ConnectionAborted,
    ProcessFdQuotaExceeded,
    SystemFdQuotaExceeded,
    SystemResources,
    ProtocolFailure,
    Unexpected,
};

pub fn accept(sock: socket_t) AcceptError!socket_t {
    if (is_windows) return windows.accept(sock);
    const rc = c.accept(sock, null, null);
    switch (posix.errno(rc)) {
        .SUCCESS => return @intCast(rc),
        .AGAIN => return error.WouldBlock,
        .BADF => unreachable,
        .CONNABORTED => return error.ConnectionAborted,
        .FAULT => unreachable,
        .INTR => return error.WouldBlock,
        .INVAL => unreachable,
        .NOTSOCK => unreachable,
        .MFILE => return error.ProcessFdQuotaExceeded,
        .NFILE => return error.SystemFdQuotaExceeded,
        .NOBUFS, .NOMEM => return error.SystemResources,
        .OPNOTSUPP => unreachable,
        .PROTO => return error.ProtocolFailure,
        else => |err| return unexpected(err),
    }
}

pub fn getsockname(sock: socket_t, addr: *sockaddr, addrlen: *socklen_t) GetSockNameError!void {
    if (is_windows) return windows.getsockname(sock, addr, addrlen);
    const rc = c.getsockname(sock, addr, addrlen);
    switch (posix.errno(rc)) {
        .SUCCESS => return,
        .BADF => unreachable,
        .FAULT => unreachable,
        .INVAL => return error.SocketNotBound,
        .NOBUFS => return error.SystemResources,
        .NOTSOCK => return error.NotSocket,
        .NETDOWN => return error.NetworkSubsystemFailed,
        else => |err| return unexpected(err),
    }
}

/// Sleep for the given number of nanoseconds. Replaces `std.Thread.sleep`
/// which was removed in Zig 0.16.
pub fn sleepNs(ns: u64) void {
    if (is_windows) return windows.sleepNs(ns);
    var req: timespec = .{
        .sec = @intCast(ns / std.time.ns_per_s),
        .nsec = @intCast(ns % std.time.ns_per_s),
    };
    var rem: timespec = undefined;
    while (c.nanosleep(&req, &rem) == -1) {
        switch (posix.errno(@as(c_int, -1))) {
            .INTR => {
                req = rem;
                continue;
            },
            else => return,
        }
    }
}

/// Seconds since the Unix epoch, off the realtime clock (replaces
/// `std.time.timestamp`). Use this and not `nanoTimestamp` for anything an
/// absolute date is compared against — certificate validity, a timestamp
/// written into something another host will read back. `nanoTimestamp` is
/// monotonic, so its zero is the last boot.
pub fn realtimeSeconds() i64 {
    if (is_windows) return windows.realtimeSeconds();
    var ts: timespec = undefined;
    if (c.clock_gettime(posix.CLOCK.REALTIME, &ts) != 0) return 0;
    return @intCast(ts.sec);
}

/// Monotonic clock timestamp in nanoseconds (replaces `std.time.nanoTimestamp`).
pub fn nanoTimestamp() i64 {
    if (is_windows) return windows.nanoTimestamp();
    var ts: timespec = undefined;
    const rc = c.clock_gettime(posix.CLOCK.MONOTONIC, &ts);
    if (rc != 0) return 0; // monotonic clock should never fail; fall back to 0.
    return @as(i64, ts.sec) * std.time.ns_per_s + @as(i64, ts.nsec);
}

/// Return a single random integer of the given type (replaces
/// `std.crypto.random.int(T)` for small integer types).
pub fn randomInt(comptime T: type) T {
    var bytes: [@sizeOf(T)]u8 = undefined;
    randomBytes(&bytes);
    return std.mem.readInt(T, &bytes, .little);
}

/// Read cryptographic randomness into buf (replaces `std.crypto.random.bytes`).
/// Uses arc4random_buf on macOS/BSD, getrandom on Linux and the CNG device on
/// Windows.
pub fn randomBytes(buf: []u8) void {
    switch (builtin.os.tag) {
        .linux => {
            var off: usize = 0;
            while (off < buf.len) {
                const rc = std.os.linux.getrandom(buf[off..].ptr, buf.len - off, 0);
                switch (posix.errno(@as(isize, @bitCast(rc)))) {
                    .SUCCESS => off += rc,
                    .INTR => continue,
                    else => @panic("getrandom failed"),
                }
            }
        },
        .macos, .ios, .watchos, .tvos, .visionos, .freebsd, .openbsd => {
            // arc4random_buf is always available and never fails on BSD/Darwin.
            c_arc4random_buf(buf.ptr, buf.len);
        },
        .windows => windows.randomBytes(buf),
        else => @compileError("sys.randomBytes: unsupported OS"),
    }
}

/// getenv: look up an environment variable. Returns null if not set.
/// On POSIX this is a direct libc getenv() call; the returned slice
/// points into libc-managed static storage and must not be freed.
pub fn getenv(name: [*:0]const u8) ?[:0]const u8 {
    if (is_windows) return windows.getenv(name);
    const raw = c.getenv(name) orelse return null;
    return std.mem.span(raw);
}

/// The command line, one argument at a time. Windows has to decode it into an
/// allocation first; like the arguments themselves, that lives as long as the
/// process.
pub fn argsIterator(args: std.process.Args) std.process.Args.Iterator {
    if (is_windows) {
        return args.iterateAllocator(std.heap.page_allocator) catch @panic("sys.argsIterator: out of memory");
    }
    return args.iterate();
}

fn unexpected(err: posix.E) error{Unexpected} {
    if (builtin.mode == .Debug) {
        std.log.warn("sys: unexpected errno: {t}", .{err});
    }
    return error.Unexpected;
}

// --- file I/O ---

pub const OpenError = error{
    FileNotFound,
    AccessDenied,
    IsDir,
    NameTooLong,
    SystemResources,
    NoSpaceLeft,
    PathAlreadyExists,
    SystemFdQuotaExceeded,
    ProcessFdQuotaExceeded,
    PathTooLong,
    Unexpected,
};

pub const WriteError = error{
    DiskQuota,
    NoSpaceLeft,
    BrokenPipe,
    InputOutput,
    ConnectionResetByPeer,
    AccessDenied,
    Unexpected,
};

pub const ReadError = error{
    InputOutput,
    AccessDenied,
    IsDir,
    Unexpected,
};

/// A minimal file handle with close/writeAll/readAll, replacing the
/// 0.15 `std.fs.File` for the narrow ways we use it.
pub const File = struct {
    fd: fd_t,

    pub fn close(self: File) void {
        closeFd(self.fd);
    }

    pub fn writeAll(self: File, bytes: []const u8) WriteError!void {
        if (is_windows) return windows.writeAll(self.fd, bytes);
        var written: usize = 0;
        while (written < bytes.len) {
            const rc = c.write(self.fd, bytes[written..].ptr, bytes.len - written);
            if (rc < 0) {
                switch (posix.errno(rc)) {
                    .INTR => continue,
                    .AGAIN => continue,
                    .DQUOT => return error.DiskQuota,
                    .NOSPC => return error.NoSpaceLeft,
                    .PIPE => return error.BrokenPipe,
                    .IO => return error.InputOutput,
                    .CONNRESET => return error.ConnectionResetByPeer,
                    .ACCES, .PERM => return error.AccessDenied,
                    else => |err| return unexpected(err),
                }
            }
            written += @intCast(rc);
        }
    }

    pub fn read(self: File, dest: []u8) ReadError!usize {
        if (is_windows) return windows.readFile(self.fd, dest);
        while (true) {
            const rc = c.read(self.fd, dest.ptr, dest.len);
            if (rc < 0) {
                switch (posix.errno(rc)) {
                    .INTR => continue,
                    .AGAIN => return 0,
                    .IO => return error.InputOutput,
                    .ISDIR => return error.IsDir,
                    .ACCES, .PERM => return error.AccessDenied,
                    else => |err| return unexpected(err),
                }
            }
            return @intCast(rc);
        }
    }

    pub const Stat = struct { size: u64 };

    /// Returns file size via lseek (portable across Linux/Darwin/BSD without
    /// needing the platform-specific fstat struct layout). Preserves file
    /// position so sequential read()s still work.
    pub fn stat(self: File) !Stat {
        if (is_windows) return .{ .size = try windows.fileSize(self.fd) };
        const cur = c.lseek(self.fd, 0, std.c.SEEK.CUR);
        if (cur < 0) switch (posix.errno(cur)) {
            else => |err| return unexpected(err),
        };
        const end = c.lseek(self.fd, 0, std.c.SEEK.END);
        if (end < 0) switch (posix.errno(end)) {
            else => |err| return unexpected(err),
        };
        // Restore original position.
        _ = c.lseek(self.fd, cur, std.c.SEEK.SET);
        return .{ .size = @intCast(end) };
    }
};

/// The process's standard output.
pub fn stdout() File {
    return .{ .fd = if (is_windows) windows.stdout() else posix.STDOUT_FILENO };
}

fn closeFd(fd: fd_t) void {
    if (is_windows) return windows.closeFile(fd);
    _ = c.close(fd);
}

/// Null-terminate a path onto a stack buffer. Errors if the path would
/// overflow PATH_MAX.
fn pathZ(path: []const u8, buf: *[std.fs.max_path_bytes]u8) OpenError![:0]const u8 {
    if (path.len >= buf.len) return error.PathTooLong;
    @memcpy(buf[0..path.len], path);
    buf[path.len] = 0;
    return buf[0..path.len :0];
}

/// Open an existing file for reading. Replaces `std.fs.cwd().openFile`.
pub fn openFileRead(path: []const u8) OpenError!File {
    if (is_windows) return .{ .fd = try windows.openFileRead(path) };
    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const z = try pathZ(path, &path_buf);
    const flags: posix.O = .{ .ACCMODE = .RDONLY };
    const rc = c.open(z.ptr, flags, @as(posix.mode_t, 0));
    switch (posix.errno(rc)) {
        .SUCCESS => return .{ .fd = @intCast(rc) },
        .ACCES, .PERM => return error.AccessDenied,
        .NOENT => return error.FileNotFound,
        .ISDIR => return error.IsDir,
        .NAMETOOLONG => return error.NameTooLong,
        .NOMEM => return error.SystemResources,
        .MFILE => return error.ProcessFdQuotaExceeded,
        .NFILE => return error.SystemFdQuotaExceeded,
        else => |err| return unexpected(err),
    }
}

/// Create/truncate a file for writing (mode 0644 on POSIX). Replaces
/// the `std.fs.cwd().createFile(path, .{})` pattern.
pub fn createFile(path: []const u8) OpenError!File {
    if (is_windows) return .{ .fd = try windows.createFile(path) };
    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const z = try pathZ(path, &path_buf);
    const flags: posix.O = .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true };
    const rc = c.open(z.ptr, flags, @as(posix.mode_t, 0o644));
    switch (posix.errno(rc)) {
        .SUCCESS => return .{ .fd = @intCast(rc) },
        .ACCES, .PERM => return error.AccessDenied,
        .NOENT => return error.FileNotFound,
        .ISDIR => return error.IsDir,
        .NAMETOOLONG => return error.NameTooLong,
        .NOMEM => return error.SystemResources,
        .NOSPC => return error.NoSpaceLeft,
        .EXIST => return error.PathAlreadyExists,
        .MFILE => return error.ProcessFdQuotaExceeded,
        .NFILE => return error.SystemFdQuotaExceeded,
        else => |err| return unexpected(err),
    }
}

pub const MakeDirError = error{
    PathAlreadyExists,
    AccessDenied,
    FileNotFound,
    NoSpaceLeft,
    NotDir,
    PathTooLong,
    Unexpected,
};

/// Create a directory (mode 0755). Returns `PathAlreadyExists` if it
/// already exists — callers can catch that and treat as success.
pub fn makeDir(path: []const u8) MakeDirError!void {
    if (is_windows) return windows.makeDir(path);
    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const z = try pathZBad(path, &path_buf);
    const rc = c.mkdir(z.ptr, @as(posix.mode_t, 0o755));
    switch (posix.errno(rc)) {
        .SUCCESS => return,
        .EXIST => return error.PathAlreadyExists,
        .ACCES, .PERM => return error.AccessDenied,
        .NOENT => return error.FileNotFound,
        .NOSPC => return error.NoSpaceLeft,
        .NOTDIR => return error.NotDir,
        .NAMETOOLONG => return error.PathTooLong,
        else => |err| return unexpected(err),
    }
}

fn pathZBad(path: []const u8, buf: *[std.fs.max_path_bytes]u8) MakeDirError![:0]const u8 {
    if (path.len >= buf.len) return error.PathTooLong;
    @memcpy(buf[0..path.len], path);
    buf[path.len] = 0;
    return buf[0..path.len :0];
}

/// Read the entire contents of `path` into a newly-allocated buffer.
/// Replaces the `std.fs.cwd().readFileAlloc(gpa, path, max)` pattern.
pub fn readFileAlloc(
    gpa: std.mem.Allocator,
    path: []const u8,
    max_bytes: usize,
) ![]u8 {
    if (is_windows) return windows.readFileAlloc(gpa, path, max_bytes);
    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const z = try pathZ(path, &path_buf);
    const flags: posix.O = .{ .ACCMODE = .RDONLY };
    const fd_rc = c.open(z.ptr, flags, @as(posix.mode_t, 0));
    if (fd_rc < 0) switch (posix.errno(fd_rc)) {
        .ACCES, .PERM => return error.AccessDenied,
        .NOENT => return error.FileNotFound,
        .ISDIR => return error.IsDir,
        .NAMETOOLONG => return error.NameTooLong,
        .NOMEM => return error.SystemResources,
        .MFILE => return error.ProcessFdQuotaExceeded,
        .NFILE => return error.SystemFdQuotaExceeded,
        else => |err| return unexpected(err),
    };
    const fd: fd_t = @intCast(fd_rc);
    defer closeFd(fd);

    // Stat first so we can size the buffer exactly. Falls back to streaming
    // if stat fails (e.g. file is on a pipe/procfs and has no size).
    var initial_size: usize = 4096;
    {
        const cur = c.lseek(fd, 0, std.c.SEEK.CUR);
        const end = c.lseek(fd, 0, std.c.SEEK.END);
        if (cur >= 0 and end >= 0) {
            _ = c.lseek(fd, cur, std.c.SEEK.SET);
            const size: usize = @intCast(end);
            if (size > max_bytes) return error.StreamTooLong;
            if (size > 0) initial_size = size;
        }
    }

    var buf = try gpa.alloc(u8, initial_size);
    errdefer gpa.free(buf);
    var len: usize = 0;
    while (true) {
        // Grow if the buffer is full. Read one extra byte past `max_bytes`
        // on the final grow so we can distinguish "file is exactly
        // max_bytes" (OK — read returns 0 next) from "file is bigger
        // than max_bytes" (overflow — read returns > 0).
        if (len == buf.len) {
            if (buf.len > max_bytes) return error.StreamTooLong;
            const new_size = if (buf.len >= max_bytes) max_bytes + 1 else @min(buf.len * 2, max_bytes);
            buf = try gpa.realloc(buf, new_size);
        }
        const rc = c.read(fd, buf[len..].ptr, buf.len - len);
        if (rc < 0) switch (posix.errno(rc)) {
            .INTR => continue,
            .AGAIN => continue,
            .IO => return error.InputOutput,
            .ISDIR => return error.IsDir,
            .ACCES, .PERM => return error.AccessDenied,
            else => |err| return unexpected(err),
        };
        if (rc == 0) break; // EOF
        len += @intCast(rc);
        if (len > max_bytes) return error.StreamTooLong;
    }
    return gpa.realloc(buf, len);
}

test "realtimeSeconds is wall clock, not uptime" {
    // Certificate validity is compared against this. nanoTimestamp() is
    // monotonic — its zero is the last boot — and checking a notBefore
    // against that made every real certificate "not yet valid", which is why
    // nothing could verify a chain until this existed.
    const now = realtimeSeconds();
    try std.testing.expect(now > 1_767_225_600); // 2026-01-01
    try std.testing.expect(now < 4_102_444_800); // 2100-01-01
    try std.testing.expect(now > @divTrunc(nanoTimestamp(), std.time.ns_per_s));
}

test "udpSocket round-trips a datagram over loopback" {
    const net = @import("sockaddr.zig");
    const rx = try udpSocket(posix.AF.INET, .{});
    defer close(rx);
    const any = try net.Address.parseIp4("127.0.0.1", 0);
    try bind(rx, &any.any, any.getOsSockLen());

    var bound: posix.sockaddr.storage = undefined;
    var bound_len: socklen_t = @sizeOf(posix.sockaddr.storage);
    try getsockname(rx, @ptrCast(&bound), &bound_len);

    var buf: [16]u8 = undefined;
    try std.testing.expectError(error.WouldBlock, recvfrom(rx, &buf, 0, null, null));

    const tx = try udpSocket(posix.AF.INET, .{});
    defer close(tx);
    _ = try sendto(tx, "ping", 0, @ptrCast(&bound), bound_len);

    // Loopback delivery is not synchronous everywhere; give it a moment.
    var n: usize = 0;
    for (0..100) |_| {
        n = recvfrom(rx, &buf, 0, null, null) catch |err| switch (err) {
            error.WouldBlock => {
                sleepNs(std.time.ns_per_ms);
                continue;
            },
            else => return err,
        };
        break;
    }
    try std.testing.expectEqualStrings("ping", buf[0..n]);
}
