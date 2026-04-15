const std = @import("std");
const posix = std.posix;
const builtin = @import("builtin");

const is_windows = builtin.os.tag == .windows;

/// Linux sendmmsg batches multiple datagrams into one syscall.
/// Compile-time gate; on other platforms the portable sendmsg loop is used.
const use_sendmmsg = builtin.os.tag == .linux;
const linux = std.os.linux;

/// Runtime kill switch. Set QUIC_ZIG_NO_SENDMMSG=1 to force the sendmsg loop
/// on Linux (useful for bisecting regressions without rebuilding).
const sendmmsg_env_var = "QUIC_ZIG_NO_SENDMMSG";

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
/// On Linux, flush uses sendmmsg to send many packets per syscall
/// (grouped by ECN mark so the cached IP_TOS stays valid). On other platforms
/// it falls back to a per-packet sendmsg loop.
pub const SendBatch = struct {
    const MAX_BATCH: usize = 64;

    /// Warn every N dropped packets so a stuck send path is visible without
    /// flooding the log when ENOBUFS briefly spikes.
    const DROP_WARN_INTERVAL: u64 = 1024;

    sockfd: posix.socket_t,
    count: usize = 0,
    current_ecn: u2 = 0,

    /// Total packets the kernel refused to accept from this batcher.
    /// UDP is lossy and QUIC loss detection recovers; we just surface a metric.
    dropped_packets: u64 = 0,

    /// Runtime kill switch — resolved once at init, so flush() never touches env.
    use_mmsg: bool = false,

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
        return .{
            .sockfd = sockfd,
            .use_mmsg = use_sendmmsg and !envFlagSet(sendmmsg_env_var),
        };
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

    /// Send all queued packets. Dispatches to the fastest available path.
    pub fn flush(self: *SendBatch) void {
        if (self.count == 0) return;
        defer {
            self.count = 0;
            self.data_len = 0;
        }

        if (comptime use_sendmmsg) {
            if (self.use_mmsg) {
                self.flushLinux();
                return;
            }
        }
        self.flushPortable();
    }

    /// Per-packet sendmsg loop — used on macOS/Windows and as the kill-switch fallback.
    fn flushPortable(self: *SendBatch) void {
        for (0..self.count) |i| {
            self.applyEcn(self.ecn_marks[i]);
            const data = self.data_buf[self.offsets[i]..][0..self.lengths[i]];
            var iov = [1]posix.iovec_const{.{
                .base = data.ptr,
                .len = data.len,
            }};
            const msg = std.c.msghdr_const{
                .name = @ptrCast(&self.addrs[i]),
                .namelen = self.addr_lens[i],
                .iov = &iov,
                .iovlen = 1,
                .control = null,
                .controllen = 0,
                .flags = 0,
            };
            if (std.c.sendmsg(self.sockfd, &msg, 0) < 0) {
                self.recordDrop(1);
            }
        }
    }

    /// Linux sendmmsg path: walks runs of same ECN mark, issues one syscall per run.
    fn flushLinux(self: *SendBatch) void {
        if (comptime !use_sendmmsg) unreachable;

        // Scratch arrays live on the stack — sized for MAX_BATCH (~5 KB total).
        var iovs: [MAX_BATCH]posix.iovec_const = undefined;
        var msgvec: [MAX_BATCH]linux.mmsghdr_const = undefined;

        var start: usize = 0;
        while (start < self.count) {
            // Extend the run while the ECN mark matches the one at `start`.
            const run_ecn = self.ecn_marks[start];
            var end = start + 1;
            while (end < self.count and self.ecn_marks[end] == run_ecn) : (end += 1) {}

            self.applyEcn(run_ecn);

            // One mmsghdr per packet within the run.
            for (start..end) |i| {
                iovs[i] = .{
                    .base = self.data_buf[self.offsets[i]..].ptr,
                    .len = self.lengths[i],
                };
                msgvec[i] = .{
                    .hdr = .{
                        .name = @ptrCast(&self.addrs[i]),
                        .namelen = self.addr_lens[i],
                        .iov = @ptrCast(&iovs[i]),
                        .iovlen = 1,
                        .control = null,
                        .controllen = 0,
                        .flags = 0,
                    },
                    .len = 0,
                };
            }

            const run_len: u32 = @intCast(end - start);
            const sent = sendmmsgRun(self.sockfd, msgvec[start..end].ptr, run_len);
            if (sent < run_len) {
                self.recordDrop(run_len - sent);
            }
            start = end;
        }
    }

    /// Issue one sendmmsg syscall for `n` packets starting at `msgvec`.
    /// Retries once on EINTR when no packets have been sent yet.
    /// Returns the number of packets the kernel accepted.
    fn sendmmsgRun(sockfd: posix.socket_t, msgvec: [*]linux.mmsghdr_const, n: u32) u32 {
        var attempts: u2 = 0;
        while (true) : (attempts += 1) {
            const rc = linux.sendmmsg(sockfd, msgvec, n, 0);
            switch (linux.E.init(rc)) {
                .SUCCESS => return @intCast(rc),
                .INTR => if (attempts == 0) continue else return 0,
                else => return 0,
            }
        }
    }

    /// Update the socket ECN mark via setsockopt, skipping the syscall when
    /// the mark hasn't changed since the last send.
    fn applyEcn(self: *SendBatch, ecn: u2) void {
        if (ecn == self.current_ecn) return;
        self.current_ecn = ecn;
        setEcnMark(self.sockfd, ecn) catch {};
    }

    fn recordDrop(self: *SendBatch, n: u32) void {
        const before = self.dropped_packets;
        self.dropped_packets += n;
        // Log only when we cross a DROP_WARN_INTERVAL boundary.
        const crossed = (before / DROP_WARN_INTERVAL) != (self.dropped_packets / DROP_WARN_INTERVAL);
        if (crossed) {
            std.log.warn("ecn_socket: {d} outgoing UDP packets dropped so far", .{self.dropped_packets});
        }
    }
};

/// Treats an env var as a boolean flag: unset, empty, or "0" → false; anything else → true.
fn envFlagSet(name: [:0]const u8) bool {
    if (comptime is_windows) return false;
    const value = std.posix.getenv(name) orelse return false;
    return !(value.len == 0 or std.mem.eql(u8, value, "0"));
}

/// Send a single packet directly from the caller's buffer (zero-copy send path).
/// Avoids the batch memcpy overhead for single-packet sends — the common case
/// for latency-sensitive echo/datagram workloads.
pub fn sendDirect(sockfd: posix.socket_t, data: []const u8, addr: *const posix.sockaddr.storage, addr_len: posix.socklen_t, ecn: u2, current_ecn: *u2) void {
    if (ecn != current_ecn.*) {
        current_ecn.* = ecn;
        setEcnMark(sockfd, ecn) catch {};
    }
    var iov = [1]posix.iovec_const{.{
        .base = data.ptr,
        .len = data.len,
    }};
    const msg = std.c.msghdr_const{
        .name = @ptrCast(addr),
        .namelen = addr_len,
        .iov = &iov,
        .iovlen = 1,
        .control = null,
        .controllen = 0,
        .flags = 0,
    };
    _ = std.c.sendmsg(sockfd, &msg, 0);
}

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

test "SendBatch delivers mixed-ECN packets in order" {
    if (comptime is_windows) return error.SkipZigTest;

    const rx = try posix.socket(posix.AF.INET, posix.SOCK.DGRAM | posix.SOCK.NONBLOCK, 0);
    defer posix.close(rx);
    const tx = try posix.socket(posix.AF.INET, posix.SOCK.DGRAM, 0);
    defer posix.close(tx);

    const bind_addr = try std.net.Address.parseIp4("127.0.0.1", 0);
    try posix.bind(rx, &bind_addr.any, bind_addr.getOsSockLen());
    try enableEcnRecv(rx);

    var peer: posix.sockaddr.storage = std.mem.zeroes(posix.sockaddr.storage);
    var peer_len: posix.socklen_t = @sizeOf(posix.sockaddr.storage);
    try posix.getsockname(rx, @ptrCast(&peer), &peer_len);

    var batch = SendBatch.init(tx);
    // Alternate ECN marks to exercise the run-segmentation logic.
    const payloads = [_][]const u8{ "aa", "bb", "cc", "dd", "ee" };
    const marks = [_]u2{ 0, 0b10, 0b10, 0, 0b01 };
    for (payloads, marks) |p, m| {
        batch.add(p, @ptrCast(&peer), peer_len, m);
    }
    batch.flush();
    try std.testing.expectEqual(@as(u64, 0), batch.dropped_packets);

    // Drain the receiver — order should match the send order on loopback.
    var buf: [64]u8 = undefined;
    // Give the kernel a moment to queue everything (loopback is fast but not sync).
    var received: usize = 0;
    const deadline = std.time.milliTimestamp() + 200;
    while (received < payloads.len and std.time.milliTimestamp() < deadline) {
        const r = recvmsgEcn(rx, &buf) catch |err| switch (err) {
            error.WouldBlock => {
                std.Thread.sleep(1 * std.time.ns_per_ms);
                continue;
            },
            else => return err,
        };
        try std.testing.expectEqualSlices(u8, payloads[received], buf[0..r.bytes_read]);
        received += 1;
    }
    try std.testing.expectEqual(payloads.len, received);
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
