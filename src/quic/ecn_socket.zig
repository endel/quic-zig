const std = @import("std");
const posix = std.posix;
const builtin = @import("builtin");

const is_windows = builtin.os.tag == .windows;

// Platform-specific constants for ECN socket options (IPv4).
const IPPROTO_IP: u32 = 0;

const IP_TOS: u32 = switch (builtin.os.tag) {
    .macos => 3,
    .linux => 1,
    .windows => 3, // unused — ECN not supported on Windows
    else => @compileError("unsupported OS for ECN"),
};

const IP_RECVTOS: u32 = switch (builtin.os.tag) {
    .macos => 27,
    .linux => 13,
    .windows => 0, // unused — ECN not supported on Windows
    else => @compileError("unsupported OS for ECN"),
};

// IPv6 ECN constants
const IPV6_TCLASS: u32 = switch (builtin.os.tag) {
    .macos => 36,
    .linux => 67,
    .windows => 0,
    else => @compileError("unsupported OS for ECN"),
};

const IPV6_RECVTCLASS: u32 = switch (builtin.os.tag) {
    .macos => 35,
    .linux => 66,
    .windows => 0,
    else => @compileError("unsupported OS for ECN"),
};

// cmsg_type returned by recvmsg for TOS/ECN ancillary data.
// On macOS, the kernel returns IP_RECVTOS as the cmsg_type.
// On Linux, the kernel returns IP_TOS as the cmsg_type.
const CMSG_TYPE_TOS: u32 = switch (builtin.os.tag) {
    .macos => 27, // IP_RECVTOS
    .linux => 1, // IP_TOS
    .windows => 0,
    else => @compileError("unsupported OS for ECN"),
};

// cmsg header — Zig std doesn't expose this on macOS.
// Not used on Windows.
const CmsgHdr = extern struct {
    cmsg_len: switch (builtin.os.tag) {
        .macos => u32,
        .windows => u32,
        else => usize,
    },
    cmsg_level: i32,
    cmsg_type: i32,
};

const CMSG_HDR_SIZE = @sizeOf(CmsgHdr);

// Aligned cmsg buffer size (header + 4 bytes data, padded to alignment).
const CMSG_SPACE = (CMSG_HDR_SIZE + 4 + @alignOf(CmsgHdr) - 1) & ~@as(usize, @alignOf(CmsgHdr) - 1);
const CMSG_BUF_SIZE = CMSG_SPACE * 2; // room for at least 2 cmsgs

/// Raw setsockopt that doesn't panic on EINVAL (needed for trying IPv6 opts on IPv4 sockets).
fn rawSetsockopt(sockfd: posix.socket_t, level: i32, optname: u32, optval: []const u8) void {
    _ = std.c.setsockopt(sockfd, level, @intCast(optname), optval.ptr, @intCast(optval.len));
}

/// Enable receiving ECN/TOS info on incoming packets.
/// No-op on Windows (ECN ancillary data not supported).
pub fn enableEcnRecv(sockfd: posix.socket_t) !void {
    if (comptime is_windows) return;
    const val: u32 = 1;
    const val_bytes = std.mem.asBytes(&val);
    // Enable for IPv4 (may fail on IPv6-only sockets — that's OK)
    rawSetsockopt(sockfd, IPPROTO_IP, IP_RECVTOS, val_bytes);
    // Enable for IPv6 (may fail on IPv4-only sockets — that's OK)
    rawSetsockopt(sockfd, @intCast(posix.IPPROTO.IPV6), IPV6_RECVTCLASS, val_bytes);
}

/// Set the ECN codepoint for outgoing packets (low 2 bits of IP TOS).
/// No-op on Windows.
pub fn setEcnMark(sockfd: posix.socket_t, ecn_mark: u2) !void {
    if (comptime is_windows) return;
    const tos: u32 = @as(u32, ecn_mark);
    const tos_bytes = std.mem.asBytes(&tos);
    // Try both IPv4 and IPv6 — one will fail silently depending on socket family
    rawSetsockopt(sockfd, IPPROTO_IP, IP_TOS, tos_bytes);
    rawSetsockopt(sockfd, @intCast(posix.IPPROTO.IPV6), IPV6_TCLASS, tos_bytes);
}

pub const RecvResult = struct {
    bytes_read: usize,
    from_addr: posix.sockaddr.storage,
    addr_len: posix.socklen_t,
    ecn: u2,
};

/// Receive a UDP datagram and extract the ECN codepoint from ancillary data.
/// On Windows, falls back to recvfrom with ecn=0 (no ancillary data support).
pub fn recvmsgEcn(sockfd: posix.socket_t, buf: []u8) !RecvResult {
    if (comptime is_windows) {
        // Windows fallback: plain recvfrom, no ECN info.
        var from_addr: posix.sockaddr.storage = std.mem.zeroes(posix.sockaddr.storage);
        var addr_len: posix.socklen_t = @sizeOf(posix.sockaddr.storage);
        const bytes_read = try posix.recvfrom(sockfd, buf, 0, @ptrCast(&from_addr), &addr_len);
        return .{
            .bytes_read = bytes_read,
            .from_addr = from_addr,
            .addr_len = addr_len,
            .ecn = 0,
        };
    }

    var iov = [1]posix.iovec{
        .{
            .base = buf.ptr,
            .len = buf.len,
        },
    };

    var cmsg_buf: [CMSG_BUF_SIZE]u8 align(@alignOf(CmsgHdr)) = .{0} ** CMSG_BUF_SIZE;
    var from_addr: posix.sockaddr.storage = std.mem.zeroes(posix.sockaddr.storage);
    var addr_len: posix.socklen_t = @sizeOf(posix.sockaddr.storage);

    var msg = std.c.msghdr{
        .name = @ptrCast(&from_addr),
        .namelen = addr_len,
        .iov = &iov,
        .iovlen = 1,
        .control = &cmsg_buf,
        .controllen = CMSG_BUF_SIZE,
        .flags = 0,
    };

    const rc = std.c.recvmsg(sockfd, &msg, 0);
    if (rc < 0) {
        const err = std.posix.errno(rc);
        return switch (err) {
            .AGAIN => error.WouldBlock,
            .CONNREFUSED => error.ConnectionRefused,
            .NOTCONN => error.SocketNotConnected,
            else => posix.unexpectedErrno(err),
        };
    }

    const bytes_read: usize = @intCast(rc);
    addr_len = msg.namelen;

    // Parse cmsg for IP_TOS
    var ecn: u2 = 0;
    var offset: usize = 0;
    while (offset + CMSG_HDR_SIZE <= msg.controllen) {
        const hdr: *const CmsgHdr = @ptrCast(@alignCast(&cmsg_buf[offset]));
        const data_offset = offset + CMSG_HDR_SIZE;
        const data_len = @as(usize, hdr.cmsg_len) -| CMSG_HDR_SIZE;
        const is_ipv4_tos = hdr.cmsg_level == @as(i32, @intCast(IPPROTO_IP)) and
            hdr.cmsg_type == @as(i32, @intCast(CMSG_TYPE_TOS));
        const is_ipv6_tclass = hdr.cmsg_level == @as(i32, @intCast(posix.IPPROTO.IPV6)) and
            hdr.cmsg_type == @as(i32, @intCast(IPV6_TCLASS));
        if ((is_ipv4_tos or is_ipv6_tclass) and
            data_len >= 1 and data_offset < CMSG_BUF_SIZE)
        {
            ecn = @truncate(cmsg_buf[data_offset] & 0x03);
            break;
        }
        // Advance to next cmsg (aligned)
        const total = (CMSG_HDR_SIZE + data_len + @alignOf(CmsgHdr) - 1) & ~@as(usize, @alignOf(CmsgHdr) - 1);
        if (total == 0) break;
        offset += total;
    }

    return .{
        .bytes_read = bytes_read,
        .from_addr = from_addr,
        .addr_len = addr_len,
        .ecn = ecn,
    };
}

/// Convert an AF_INET sockaddr to IPv4-mapped AF_INET6 (::ffff:a.b.c.d) in-place.
/// No-op if already AF_INET6. Useful for dual-stack IPv6 sockets that need to sendto IPv4 addresses.
pub fn mapV4ToV6(storage: *posix.sockaddr.storage) void {
    if (storage.family != posix.AF.INET) return;
    const in_addr: *const posix.sockaddr.in = @ptrCast(@alignCast(storage));
    const v4_bytes: [4]u8 = @bitCast(in_addr.addr);
    const port = in_addr.port;
    var result: posix.sockaddr.storage = std.mem.zeroes(posix.sockaddr.storage);
    result.family = posix.AF.INET6;
    const in6: *posix.sockaddr.in6 = @ptrCast(@alignCast(&result));
    in6.addr[10] = 0xff;
    in6.addr[11] = 0xff;
    @memcpy(in6.addr[12..16], &v4_bytes);
    in6.port = port;
    storage.* = result;
}

/// Batch sender that collects outgoing packets and flushes them together.
/// Reduces syscall overhead by batching sendto calls and caching ECN marks.
pub const SendBatch = struct {
    const MAX_BATCH: usize = 64;

    sockfd: posix.socket_t,
    count: usize = 0,
    current_ecn: u2 = 0,

    // Per-packet data
    addrs: [MAX_BATCH]posix.sockaddr.storage = undefined,
    addr_lens: [MAX_BATCH]posix.socklen_t = undefined,
    offsets: [MAX_BATCH]u32 = undefined, // offset into data_buf
    lengths: [MAX_BATCH]u32 = undefined, // length of each packet
    ecn_marks: [MAX_BATCH]u2 = undefined,

    // Contiguous buffer holding all packet data
    data_buf: [MAX_BATCH * 1500]u8 = undefined,
    data_len: usize = 0,

    pub fn init(sockfd: posix.socket_t) SendBatch {
        return .{ .sockfd = sockfd };
    }

    /// Add a packet to the batch. Flushes automatically when full.
    pub fn add(self: *SendBatch, data: []const u8, addr: *const posix.sockaddr, addr_len: posix.socklen_t, ecn: u2) void {
        if (self.count >= MAX_BATCH or self.data_len + data.len > self.data_buf.len) {
            self.flush();
        }
        const idx = self.count;
        self.offsets[idx] = @intCast(self.data_len);
        self.lengths[idx] = @intCast(data.len);
        @memcpy(self.data_buf[self.data_len..][0..data.len], data);
        self.data_len += data.len;
        self.addrs[idx] = @as(*const posix.sockaddr.storage, @ptrCast(@alignCast(addr))).*;
        self.addr_lens[idx] = addr_len;
        self.ecn_marks[idx] = ecn;
        self.count += 1;
    }

    /// Send all queued packets. Caches ECN marks to avoid redundant setsockopt calls.
    pub fn flush(self: *SendBatch) void {
        if (self.count == 0) return;

        for (0..self.count) |i| {
            // Only call setsockopt when ECN mark changes (saves 2 syscalls per packet)
            if (self.ecn_marks[i] != self.current_ecn) {
                self.current_ecn = self.ecn_marks[i];
                setEcnMark(self.sockfd, self.current_ecn) catch {};
            }
            const data = self.data_buf[self.offsets[i]..][0..self.lengths[i]];
            _ = posix.sendto(
                self.sockfd,
                data,
                0,
                @ptrCast(&self.addrs[i]),
                self.addr_lens[i],
            ) catch {};
        }

        self.count = 0;
        self.data_len = 0;
    }
};

// Tests — ECN ancillary data tests only run on POSIX platforms.
test "enableEcnRecv on a real socket" {
    if (comptime is_windows) return error.SkipZigTest;
    const sockfd = try posix.socket(posix.AF.INET, posix.SOCK.DGRAM | posix.SOCK.NONBLOCK, 0);
    defer posix.close(sockfd);

    const addr = try std.net.Address.parseIp4("127.0.0.1", 0);
    try posix.bind(sockfd, &addr.any, addr.getOsSockLen());

    try enableEcnRecv(sockfd);
}

test "setEcnMark on a real socket" {
    if (comptime is_windows) return error.SkipZigTest;
    const sockfd = try posix.socket(posix.AF.INET, posix.SOCK.DGRAM | posix.SOCK.NONBLOCK, 0);
    defer posix.close(sockfd);

    const addr = try std.net.Address.parseIp4("127.0.0.1", 0);
    try posix.bind(sockfd, &addr.any, addr.getOsSockLen());

    // ECT(0) = 0b10 = 2
    try setEcnMark(sockfd, 0b10);
    // Not-ECT = 0b00 = 0
    try setEcnMark(sockfd, 0b00);
}

test "recvmsgEcn returns WouldBlock on empty socket" {
    if (comptime is_windows) return error.SkipZigTest;
    const sockfd = try posix.socket(posix.AF.INET, posix.SOCK.DGRAM | posix.SOCK.NONBLOCK, 0);
    defer posix.close(sockfd);

    const addr = try std.net.Address.parseIp4("127.0.0.1", 0);
    try posix.bind(sockfd, &addr.any, addr.getOsSockLen());
    try enableEcnRecv(sockfd);

    var buf: [1500]u8 = undefined;
    const result = recvmsgEcn(sockfd, &buf);
    try std.testing.expectError(error.WouldBlock, result);
}
