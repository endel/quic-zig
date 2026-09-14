//! Windows backend for `../sys.zig`.
//!
//! Sockets go through Winsock. Zig 0.16 dropped the ws2_32 function bindings
//! from std — its own `Io` talks to the AFD driver instead — so the few this
//! library calls are declared below. Files, clocks, sleep and randomness go
//! through `std.Io`'s global single-threaded instance, which is how std itself
//! implements them on Windows.

const std = @import("std");
const builtin = @import("builtin");
const posix = std.posix;
const Io = std.Io;
const sys = @import("../sys.zig");

const socket_t = posix.socket_t;
const fd_t = posix.fd_t;
const sockaddr = posix.sockaddr;
const socklen_t = posix.socklen_t;

const INVALID_SOCKET: socket_t = @ptrFromInt(~@as(usize, 0));
const SOCKET_ERROR: i32 = -1;

/// `_IOW('f', 126, u_long)`: set or clear nonblocking mode.
const FIONBIO: i32 = @bitCast(@as(u32, 0x8004667E));
/// Whether an ICMP port-unreachable resets a UDP socket.
const SIO_UDP_CONNRESET: u32 = 0x9800000C;
/// Whether an ICMP time-exceeded resets a UDP socket.
const SIO_UDP_NETRESET: u32 = 0x9800000F;

const WSADATA = extern struct {
    wVersion: u16,
    wHighVersion: u16,
    iMaxSockets: u16,
    iMaxUdpDg: u16,
    lpVendorInfo: ?[*]u8,
    szDescription: [257]u8,
    szSystemStatus: [129]u8,
};

/// `ADDRINFOA`. Field names match `std.c.addrinfo` so `sys.resolveHost` reads
/// either; the order does not, Windows puts `canonname` before `addr`.
pub const addrinfo = extern struct {
    flags: i32,
    family: i32,
    socktype: i32,
    protocol: i32,
    addrlen: usize,
    canonname: ?[*:0]u8,
    addr: ?*sockaddr,
    next: ?*addrinfo,
};

/// The Winsock errors this file tells apart. Anything else is `Unexpected`.
const WSAError = enum(i32) {
    WSAEINTR = 10004,
    WSAEACCES = 10013,
    WSAEINVAL = 10022,
    WSAEMFILE = 10024,
    WSAEWOULDBLOCK = 10035,
    WSAENOTSOCK = 10038,
    WSAEMSGSIZE = 10040,
    WSAENOPROTOOPT = 10042,
    WSAEPROTONOSUPPORT = 10043,
    WSAEOPNOTSUPP = 10045,
    WSAEAFNOSUPPORT = 10047,
    WSAEADDRINUSE = 10048,
    WSAEADDRNOTAVAIL = 10049,
    WSAENETDOWN = 10050,
    WSAENETUNREACH = 10051,
    WSAENETRESET = 10052,
    WSAECONNABORTED = 10053,
    WSAECONNRESET = 10054,
    WSAENOBUFS = 10055,
    WSAENOTCONN = 10057,
    WSAESHUTDOWN = 10058,
    WSAECONNREFUSED = 10061,
    WSAEHOSTUNREACH = 10065,
    _,
};

const ws2 = struct {
    extern "ws2_32" fn WSAStartup(version: u16, data: *WSADATA) callconv(.winapi) i32;
    extern "ws2_32" fn WSAGetLastError() callconv(.winapi) WSAError;
    extern "ws2_32" fn socket(af: i32, @"type": i32, protocol: i32) callconv(.winapi) socket_t;
    extern "ws2_32" fn closesocket(s: socket_t) callconv(.winapi) i32;
    extern "ws2_32" fn bind(s: socket_t, name: *const sockaddr, namelen: i32) callconv(.winapi) i32;
    extern "ws2_32" fn listen(s: socket_t, backlog: i32) callconv(.winapi) i32;
    extern "ws2_32" fn accept(s: socket_t, addr: ?*sockaddr, addrlen: ?*i32) callconv(.winapi) socket_t;
    extern "ws2_32" fn send(s: socket_t, buf: [*]const u8, len: i32, flags: i32) callconv(.winapi) i32;
    extern "ws2_32" fn recv(s: socket_t, buf: [*]u8, len: i32, flags: i32) callconv(.winapi) i32;
    extern "ws2_32" fn sendto(s: socket_t, buf: [*]const u8, len: i32, flags: i32, to: ?*const sockaddr, tolen: i32) callconv(.winapi) i32;
    extern "ws2_32" fn recvfrom(s: socket_t, buf: [*]u8, len: i32, flags: i32, from: ?*sockaddr, fromlen: ?*i32) callconv(.winapi) i32;
    extern "ws2_32" fn getsockname(s: socket_t, name: *sockaddr, namelen: *i32) callconv(.winapi) i32;
    extern "ws2_32" fn setsockopt(s: socket_t, level: i32, optname: i32, optval: [*]const u8, optlen: i32) callconv(.winapi) i32;
    extern "ws2_32" fn ioctlsocket(s: socket_t, cmd: i32, argp: *u32) callconv(.winapi) i32;
    extern "ws2_32" fn WSAIoctl(
        s: socket_t,
        code: u32,
        in_buf: ?*const anyopaque,
        in_len: u32,
        out_buf: ?*anyopaque,
        out_len: u32,
        bytes_returned: *u32,
        overlapped: ?*anyopaque,
        completion_routine: ?*anyopaque,
    ) callconv(.winapi) i32;
    extern "ws2_32" fn getaddrinfo(node: ?[*:0]const u8, service: ?[*:0]const u8, hints: ?*const addrinfo, result: *?*addrinfo) callconv(.winapi) i32;
    extern "ws2_32" fn freeaddrinfo(info: *addrinfo) callconv(.winapi) void;
};

var started: std.atomic.Value(bool) = .init(false);

/// Winsock has to be started before its first call. WSAStartup counts its
/// callers, so two threads racing here cost a count, not correctness.
fn startup() void {
    if (started.load(.acquire)) return;
    var data: WSADATA = undefined;
    if (ws2.WSAStartup(0x0202, &data) == 0) started.store(true, .release);
}

fn unexpected(err: WSAError) error{Unexpected} {
    if (builtin.mode == .Debug) {
        std.log.warn("sys: unexpected Winsock error: {d}", .{@intFromEnum(err)});
    }
    return error.Unexpected;
}

fn len32(n: usize) i32 {
    return @intCast(@min(n, std.math.maxInt(i32)));
}

// --- sockets ---

pub fn socket(domain: u32, sock_type: u32, protocol: u32) sys.SocketError!socket_t {
    startup();
    const s = ws2.socket(@intCast(domain), @intCast(sock_type), @intCast(protocol));
    if (s != INVALID_SOCKET) return s;
    return switch (ws2.WSAGetLastError()) {
        .WSAEACCES => error.PermissionDenied,
        .WSAEAFNOSUPPORT => error.AddressFamilyNotSupported,
        .WSAEPROTONOSUPPORT => error.ProtocolNotSupported,
        .WSAEMFILE => error.ProcessFdQuotaExceeded,
        .WSAENOBUFS => error.SystemResources,
        else => |err| unexpected(err),
    };
}

/// See `sys.udpSocket`.
pub fn udpSocket(family: u32) sys.SocketError!socket_t {
    const s = try socket(family, posix.SOCK.DGRAM, 0);
    errdefer close(s);
    var nonblocking: u32 = 1;
    if (ws2.ioctlsocket(s, FIONBIO, &nonblocking) != 0) return unexpected(ws2.WSAGetLastError());
    // Best effort: a socket that keeps the default still works, it just sees
    // the spurious resets.
    for ([_]u32{ SIO_UDP_CONNRESET, SIO_UDP_NETRESET }) |code| {
        var enabled: u32 = 0;
        var returned: u32 = 0;
        _ = ws2.WSAIoctl(s, code, &enabled, @sizeOf(u32), null, 0, &returned, null, null);
    }
    return s;
}

pub fn close(s: socket_t) void {
    _ = ws2.closesocket(s);
}

pub fn bind(s: socket_t, addr: *const sockaddr, len: socklen_t) sys.BindError!void {
    if (ws2.bind(s, addr, @intCast(len)) == 0) return;
    return switch (ws2.WSAGetLastError()) {
        .WSAEACCES => error.AccessDenied,
        .WSAEADDRINUSE => error.AddressInUse,
        .WSAEADDRNOTAVAIL => error.AddressNotAvailable,
        .WSAEAFNOSUPPORT => error.AddressFamilyNotSupported,
        .WSAEINVAL => error.AlreadyBound,
        .WSAENOTSOCK => error.FileDescriptorNotASocket,
        .WSAENOBUFS => error.SystemResources,
        .WSAENETDOWN => error.NetworkSubsystemFailed,
        else => |err| unexpected(err),
    };
}

pub fn listen(s: socket_t, backlog: u31) sys.ListenError!void {
    if (ws2.listen(s, backlog) == 0) return;
    return switch (ws2.WSAGetLastError()) {
        .WSAEADDRINUSE => error.AddressInUse,
        .WSAENOTSOCK => error.FileDescriptorNotASocket,
        .WSAEOPNOTSUPP => error.OperationNotSupported,
        .WSAENOBUFS => error.SystemResources,
        else => |err| unexpected(err),
    };
}

pub fn accept(s: socket_t) sys.AcceptError!socket_t {
    const conn = ws2.accept(s, null, null);
    if (conn != INVALID_SOCKET) return conn;
    return switch (ws2.WSAGetLastError()) {
        .WSAEWOULDBLOCK, .WSAEINTR => error.WouldBlock,
        // Also what closing the listener from another thread looks like,
        // which is how Http1Server stops its accept loop.
        .WSAECONNRESET, .WSAENOTSOCK, .WSAEINVAL => error.ConnectionAborted,
        .WSAEMFILE => error.ProcessFdQuotaExceeded,
        .WSAENOBUFS => error.SystemResources,
        else => |err| unexpected(err),
    };
}

pub fn sendto(
    s: socket_t,
    buf: []const u8,
    flags: u32,
    dest_addr: ?*const sockaddr,
    addrlen: socklen_t,
) sys.SendToError!usize {
    const rc = ws2.sendto(s, buf.ptr, len32(buf.len), @intCast(flags), dest_addr, @intCast(addrlen));
    if (rc != SOCKET_ERROR) return @intCast(rc);
    return switch (ws2.WSAGetLastError()) {
        .WSAEWOULDBLOCK => error.WouldBlock,
        .WSAEACCES => error.AccessDenied,
        .WSAECONNRESET, .WSAENETRESET => error.ConnectionResetByPeer,
        .WSAEMSGSIZE => error.MessageTooBig,
        .WSAENOBUFS => error.SystemResources,
        .WSAENETUNREACH => error.NetworkUnreachable,
        .WSAEHOSTUNREACH => error.HostUnreachable,
        .WSAENETDOWN => error.NetworkSubsystemFailed,
        .WSAENOTSOCK => error.FileDescriptorNotASocket,
        .WSAEAFNOSUPPORT => error.AddressFamilyNotSupported,
        else => |err| unexpected(err),
    };
}

pub fn recvfrom(
    s: socket_t,
    buf: []u8,
    flags: u32,
    src_addr: ?*sockaddr,
    addrlen: ?*socklen_t,
) sys.RecvFromError!usize {
    const rc = ws2.recvfrom(s, buf.ptr, len32(buf.len), @intCast(flags), src_addr, @ptrCast(addrlen));
    if (rc != SOCKET_ERROR) return @intCast(rc);
    return switch (ws2.WSAGetLastError()) {
        .WSAEWOULDBLOCK => error.WouldBlock,
        // The datagram was longer than `buf`. Winsock fills the buffer, drops
        // the rest and calls it a failure; POSIX returns the full buffer, so
        // this does too.
        .WSAEMSGSIZE => buf.len,
        .WSAECONNRESET, .WSAENETRESET => error.ConnectionResetByPeer,
        .WSAECONNREFUSED => error.ConnectionRefused,
        .WSAENOTCONN => error.SocketNotConnected,
        .WSAENETDOWN => error.NetworkSubsystemFailed,
        .WSAENOBUFS => error.SystemResources,
        else => |err| unexpected(err),
    };
}

/// A TCP read. Like the POSIX version, 0 means either EOF or would-block.
pub fn read(s: socket_t, dest: []u8) sys.ReadError!usize {
    const rc = ws2.recv(s, dest.ptr, len32(dest.len), 0);
    if (rc != SOCKET_ERROR) return @intCast(rc);
    return switch (ws2.WSAGetLastError()) {
        .WSAEWOULDBLOCK => 0,
        .WSAEACCES => error.AccessDenied,
        else => |err| unexpected(err),
    };
}

/// A TCP write. Like the POSIX version, 0 means would-block.
pub fn write(s: socket_t, bytes: []const u8) sys.WriteError!usize {
    const rc = ws2.send(s, bytes.ptr, len32(bytes.len), 0);
    if (rc != SOCKET_ERROR) return @intCast(rc);
    return switch (ws2.WSAGetLastError()) {
        .WSAEWOULDBLOCK => 0,
        .WSAECONNRESET, .WSAENETRESET => error.ConnectionResetByPeer,
        .WSAESHUTDOWN, .WSAECONNABORTED => error.BrokenPipe,
        .WSAEACCES => error.AccessDenied,
        else => |err| unexpected(err),
    };
}

pub fn getsockname(s: socket_t, addr: *sockaddr, addrlen: *socklen_t) sys.GetSockNameError!void {
    if (ws2.getsockname(s, addr, @ptrCast(addrlen)) == 0) return;
    return switch (ws2.WSAGetLastError()) {
        .WSAEINVAL => error.SocketNotBound,
        .WSAENOTSOCK => error.NotSocket,
        .WSAENOBUFS => error.SystemResources,
        .WSAENETDOWN => error.NetworkSubsystemFailed,
        else => |err| unexpected(err),
    };
}

pub fn setsockopt(s: socket_t, level: i32, optname: u32, opt: []const u8) posix.SetSockOptError!void {
    if (ws2.setsockopt(s, level, @intCast(optname), opt.ptr, len32(opt.len)) == 0) return;
    return switch (ws2.WSAGetLastError()) {
        .WSAENOPROTOOPT, .WSAEINVAL => error.InvalidProtocolOption,
        .WSAENOTSOCK => error.FileDescriptorNotASocket,
        .WSAENETDOWN => error.NetworkDown,
        .WSAENOBUFS => error.SystemResources,
        else => |err| unexpected(err),
    };
}

pub fn getaddrinfo(node: ?[*:0]const u8, service: ?[*:0]const u8, hints: ?*const addrinfo, result: *?*addrinfo) i32 {
    startup();
    return ws2.getaddrinfo(node, service, hints, result);
}

pub const freeaddrinfo = ws2.freeaddrinfo;

// --- everything else, through std.Io ---

fn io() Io {
    return Io.Threaded.global_single_threaded.io();
}

pub fn sleepNs(ns: u64) void {
    io().sleep(.fromNanoseconds(ns), .awake) catch {};
}

pub fn realtimeSeconds() i64 {
    return Io.Clock.real.now(io()).toSeconds();
}

pub fn nanoTimestamp() i64 {
    return @intCast(Io.Clock.awake.now(io()).toNanoseconds());
}

pub fn randomBytes(buf: []u8) void {
    io().randomSecure(buf) catch @panic("sys.randomBytes: no system randomness");
}

/// The environment is UTF-16 on Windows. The value is converted once and kept
/// for the life of the process, which suits the callers: apps reading their
/// configuration at startup.
pub fn getenv(name: [*:0]const u8) ?[:0]const u8 {
    const gpa = std.heap.page_allocator;
    const key = std.unicode.wtf8ToWtf16LeAllocZ(gpa, std.mem.span(name)) catch return null;
    defer gpa.free(key);
    const env: std.process.Environ = .{ .block = .global };
    const value = env.getWindows(key) orelse return null;
    return std.unicode.wtf16LeToWtf8AllocZ(gpa, value) catch null;
}

fn ioFile(handle: fd_t) Io.File {
    return .{ .handle = handle, .flags = .{ .nonblocking = false } };
}

pub fn stdout() fd_t {
    return Io.File.stdout().handle;
}

pub fn closeFile(handle: fd_t) void {
    ioFile(handle).close(io());
}

pub fn writeAll(handle: fd_t, bytes: []const u8) sys.WriteError!void {
    ioFile(handle).writeStreamingAll(io(), bytes) catch return error.InputOutput;
}

pub fn readFile(handle: fd_t, dest: []u8) sys.ReadError!usize {
    return ioFile(handle).readStreaming(io(), &.{dest}) catch |err| switch (err) {
        error.EndOfStream => 0,
        else => error.InputOutput,
    };
}

pub fn fileSize(handle: fd_t) !u64 {
    return ioFile(handle).length(io());
}

pub fn openFileRead(path: []const u8) sys.OpenError!fd_t {
    const file = Io.Dir.cwd().openFile(io(), path, .{}) catch |err| return openError(err);
    return file.handle;
}

pub fn createFile(path: []const u8) sys.OpenError!fd_t {
    const file = Io.Dir.cwd().createFile(io(), path, .{}) catch |err| return openError(err);
    return file.handle;
}

fn openError(err: Io.File.OpenError) sys.OpenError {
    return switch (err) {
        error.FileNotFound => error.FileNotFound,
        error.AccessDenied => error.AccessDenied,
        error.IsDir => error.IsDir,
        error.NameTooLong => error.NameTooLong,
        error.SystemResources => error.SystemResources,
        error.NoSpaceLeft => error.NoSpaceLeft,
        error.PathAlreadyExists => error.PathAlreadyExists,
        error.ProcessFdQuotaExceeded => error.ProcessFdQuotaExceeded,
        error.SystemFdQuotaExceeded => error.SystemFdQuotaExceeded,
        else => error.Unexpected,
    };
}

pub fn makeDir(path: []const u8) sys.MakeDirError!void {
    Io.Dir.cwd().createDir(io(), path, .default_dir) catch |err| return switch (err) {
        error.PathAlreadyExists => error.PathAlreadyExists,
        error.AccessDenied => error.AccessDenied,
        error.FileNotFound => error.FileNotFound,
        error.NoSpaceLeft => error.NoSpaceLeft,
        error.NotDir => error.NotDir,
        error.NameTooLong => error.PathTooLong,
        else => error.Unexpected,
    };
}

pub fn readFileAlloc(gpa: std.mem.Allocator, path: []const u8, max_bytes: usize) ![]u8 {
    return Io.Dir.cwd().readFileAlloc(io(), path, gpa, .limited(max_bytes));
}
