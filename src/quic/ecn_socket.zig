const std = @import("std");
const sys = @import("../sys.zig");
const net = @import("../sockaddr.zig");
const posix = std.posix;
const builtin = @import("builtin");

const is_windows = builtin.os.tag == .windows;
const is_linux = builtin.os.tag == .linux;
const linux = if (is_linux) std.os.linux else void;

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
// A receive timestamp is a timespec, wider than the 4-byte TOS cmsgs.
const CMSG_SPACE_TS = (CMSG_HDR_SIZE + 16 + @alignOf(CmsgHdr) - 1) & ~@as(usize, @alignOf(CmsgHdr) - 1);
const CMSG_BUF_SIZE = CMSG_SPACE * 2 + CMSG_SPACE_TS;

// SO_TIMESTAMPNS: the kernel stamps each datagram as it is queued, which is the
// only way to see how long one waited for the loop to come and read it.
const SO_TIMESTAMPNS: u32 = 35; // Linux
const SOL_SOCKET_LEVEL: i32 = 1; // Linux

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

/// Ask the kernel to stamp incoming datagrams with their arrival time, so a
/// receive queue can be told apart from a slow answer. Linux only, and only
/// worth turning on for a diagnostic run: it adds a cmsg to every recvmsg.
pub fn enableRxTimestamps(sockfd: posix.socket_t) void {
    if (comptime builtin.os.tag != .linux) return;
    const val: u32 = 1;
    const rc = std.c.setsockopt(sockfd, SOL_SOCKET_LEVEL, @intCast(SO_TIMESTAMPNS), std.mem.asBytes(&val).ptr, 4);
    if (rc != 0) std.debug.print("rx timestamps: setsockopt failed rc={d}\n", .{rc});
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
    /// The datagram was longer than `buf` and the tail is gone. Worth saying
    /// out loud: a truncated QUIC packet fails AEAD authentication, so it
    /// otherwise surfaces as a decryption failure rather than a short read.
    truncated: bool = false,
    /// When the kernel queued this datagram, 0 unless `enableRxTimestamps`
    /// was called on the socket. Diagnostic only.
    kernel_ns: i64 = 0,
};

/// Receive a UDP datagram and extract the ECN codepoint from ancillary data.
/// On Windows, falls back to recvfrom with ecn=0 (no ancillary data support).
pub fn recvmsgEcn(sockfd: posix.socket_t, buf: []u8) !RecvResult {
    if (comptime is_windows) {
        // Windows fallback: plain recvfrom, no ECN info.
        var from_addr: posix.sockaddr.storage = std.mem.zeroes(posix.sockaddr.storage);
        var addr_len: posix.socklen_t = @sizeOf(posix.sockaddr.storage);
        const bytes_read = try sys.recvfrom(sockfd, buf, 0, @ptrCast(&from_addr), &addr_len);
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

    // Parse cmsg for IP_TOS, and for the arrival stamp when it was asked for.
    var ecn: u2 = 0;
    var kernel_ns: i64 = 0;
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
        } else if (builtin.os.tag == .linux and
            hdr.cmsg_level == SOL_SOCKET_LEVEL and
            hdr.cmsg_type == @as(i32, @intCast(SO_TIMESTAMPNS)) and
            data_len >= 16 and data_offset + 16 <= CMSG_BUF_SIZE)
        {
            const ts: *align(1) const extern struct { sec: i64, nsec: i64 } =
                @ptrCast(&cmsg_buf[data_offset]);
            kernel_ns = ts.sec * std.time.ns_per_s + ts.nsec;
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
        .truncated = msg.flags & @as(i32, @intCast(posix.MSG.TRUNC)) != 0,
        .kernel_ns = kernel_ns,
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
///
/// On Linux a run of same-sized packets to one address leaves as a single
/// `sendmsg` carrying `UDP_SEGMENT`, so the kernel does the splitting: one
/// syscall and one skb for up to 64 datagrams, which is what nginx's `quic_gso`
/// buys. Where that is unavailable the run still goes out in one `sendmmsg`.
/// Other platforms send one `sendmsg` per packet.
pub const SendBatch = struct {
    const MAX_BATCH: usize = 64;
    /// GSO needs every segment but the last to be the same size, and the whole
    /// thing to fit one datagram's length field.
    const max_gso_bytes: usize = 65535;
    /// Room for one packet, and the size of a `reserve` slot.
    pub const max_packet: usize = 1500;

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
    data_buf: [MAX_BATCH * max_packet]u8 = undefined,
    data_len: usize = 0,
    /// Cleared for the socket's life once the kernel refuses a segmented send.
    gso: bool = is_linux,

    pub fn init(sockfd: posix.socket_t) SendBatch {
        return .{ .sockfd = sockfd };
    }

    /// Where the next packet should be written, so that packing it needs no
    /// copy: the batch sends from this buffer. Followed by `commit`.
    pub fn reserve(self: *SendBatch) *[max_packet]u8 {
        if (self.count >= MAX_BATCH or self.data_len + max_packet > self.data_buf.len) self.flush();
        return self.data_buf[self.data_len..][0..max_packet];
    }

    /// Record the packet just written into `reserve`'s slot.
    pub fn commit(self: *SendBatch, len: usize, addr: *const posix.sockaddr, addr_len: posix.socklen_t, ecn: u2) void {
        const idx = self.count;
        self.offsets[idx] = @intCast(self.data_len);
        self.lengths[idx] = @intCast(len);
        self.data_len += len;
        self.addrs[idx] = @as(*const posix.sockaddr.storage, @ptrCast(@alignCast(addr))).*;
        self.addr_lens[idx] = addr_len;
        self.ecn_marks[idx] = ecn;
        self.count += 1;
    }

    /// Add a packet the caller already holds elsewhere. Flushes when full.
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

    /// Send everything queued, in as few syscalls as the platform allows.
    pub fn flush(self: *SendBatch) void {
        defer {
            self.count = 0;
            self.data_len = 0;
        }
        // Packets that share a destination and an ECN mark go out together:
        // changing the mark is a setsockopt, and a segmented send carries one
        // address. A connection's burst is one run, which is the case that pays.
        var start: usize = 0;
        while (start < self.count) {
            var end = start + 1;
            while (end < self.count and
                self.ecn_marks[end] == self.ecn_marks[start] and
                self.sameAddr(start, end)) : (end += 1)
            {}
            if (self.ecn_marks[start] != self.current_ecn) {
                self.current_ecn = self.ecn_marks[start];
                setEcnMark(self.sockfd, self.current_ecn) catch {};
            }
            self.sendRun(start, end);
            start = end;
        }
    }

    fn sameAddr(self: *const SendBatch, a: usize, b: usize) bool {
        if (self.addr_lens[a] != self.addr_lens[b]) return false;
        const bytes_a = std.mem.asBytes(&self.addrs[a]);
        const bytes_b = std.mem.asBytes(&self.addrs[b]);
        return std.mem.eql(u8, bytes_a[0..self.addr_lens[a]], bytes_b[0..self.addr_lens[b]]);
    }

    /// One `sendmsg` per packet: correct everywhere, and the fallback for the
    /// paths below.
    fn sendEach(self: *SendBatch, from: usize, to: usize) void {
        for (from..to) |i| {
            const data = self.data_buf[self.offsets[i]..][0..self.lengths[i]];
            var iov = [1]posix.iovec_const{.{ .base = data.ptr, .len = data.len }};
            const msg = std.c.msghdr_const{
                .name = @ptrCast(&self.addrs[i]),
                .namelen = self.addr_lens[i],
                .iov = &iov,
                .iovlen = 1,
                .control = null,
                .controllen = 0,
                .flags = 0,
            };
            _ = std.c.sendmsg(self.sockfd, &msg, 0);
        }
    }

    fn sendRun(self: *SendBatch, from: usize, to: usize) void {
        if (!is_linux or to - from == 1) return self.sendEach(from, to);
        if (self.gso and self.sendSegmented(from, to)) return;
        self.sendMany(from, to);
    }

    /// The whole run as one datagram plus a segment size, where its shape allows
    /// it. False when it does not, or when the kernel turned it down.
    fn sendSegmented(self: *SendBatch, from: usize, to: usize) bool {
        const seg = self.lengths[from];
        var total: usize = 0;
        for (from..to) |i| {
            // Every segment but the last is exactly `seg`, and none exceeds it.
            if (self.lengths[i] != seg and i != to - 1) return false;
            if (self.lengths[i] > seg) return false;
            total += self.lengths[i];
        }
        if (total > max_gso_bytes) return false;

        var control: [cmsgSpace(@sizeOf(u16))]u8 align(@alignOf(linux.cmsghdr)) = undefined;
        const cmsg: *linux.cmsghdr = @ptrCast(&control);
        cmsg.* = .{
            .len = cmsgLen(@sizeOf(u16)),
            .level = linux.IPPROTO.UDP,
            .type = linux.UDP.SEGMENT,
        };
        const seg16: u16 = @intCast(seg);
        @memcpy(control[cmsgLen(0)..][0..@sizeOf(u16)], std.mem.asBytes(&seg16));

        var iov = [1]posix.iovec_const{.{
            .base = self.data_buf[self.offsets[from]..].ptr,
            .len = total,
        }};
        const msg = std.c.msghdr_const{
            .name = @ptrCast(&self.addrs[from]),
            .namelen = self.addr_lens[from],
            .iov = &iov,
            .iovlen = 1,
            .control = &control,
            .controllen = @intCast(control.len),
            .flags = 0,
        };
        const rc = std.c.sendmsg(self.sockfd, &msg, 0);
        if (rc >= 0) return true;
        // A kernel or socket without UDP_SEGMENT will keep saying so, so stop
        // asking. Any other failure is this send's problem, not the feature's.
        switch (posix.errno(rc)) {
            .INVAL, .NOPROTOOPT, .OPNOTSUPP => self.gso = false,
            else => {},
        }
        return false;
    }

    /// The run in one `sendmmsg`.
    fn sendMany(self: *SendBatch, from: usize, to: usize) void {
        var iovs: [MAX_BATCH]posix.iovec_const = undefined;
        var msgs: [MAX_BATCH]linux.mmsghdr = undefined;
        const n = to - from;
        for (0..n) |k| {
            const i = from + k;
            iovs[k] = .{ .base = self.data_buf[self.offsets[i]..].ptr, .len = self.lengths[i] };
            msgs[k] = .{
                .hdr = .{
                    .name = @ptrCast(&self.addrs[i]),
                    .namelen = self.addr_lens[i],
                    .iov = @ptrCast(&iovs[k]),
                    .iovlen = 1,
                    .control = null,
                    .controllen = 0,
                    .flags = 0,
                },
                .len = 0,
            };
        }
        // Partial sends are normal: keep going from where it stopped.
        var sent: usize = 0;
        while (sent < n) {
            const rc = std.c.sendmmsg(self.sockfd, msgs[sent..].ptr, @intCast(n - sent), 0);
            if (rc <= 0) return self.sendEach(from + sent, to);
            sent += @intCast(rc);
        }
    }
};

/// Bytes a control message of `len` payload occupies, header included.
fn cmsgLen(len: usize) usize {
    return std.mem.alignForward(usize, @sizeOf(linux.cmsghdr), @alignOf(usize)) + len;
}

fn cmsgSpace(len: usize) usize {
    return std.mem.alignForward(usize, cmsgLen(len), @alignOf(usize));
}

// Tests — ECN ancillary data tests only run on POSIX platforms.
test "enableEcnRecv on a real socket" {
    if (comptime is_windows) return error.SkipZigTest;
    const sockfd = try sys.socket(posix.AF.INET, posix.SOCK.DGRAM | posix.SOCK.NONBLOCK, 0);
    defer sys.close(sockfd);

    const addr = try net.Address.parseIp4("127.0.0.1", 0);
    try sys.bind(sockfd, &addr.any, addr.getOsSockLen());

    try enableEcnRecv(sockfd);
}

test "setEcnMark on a real socket" {
    if (comptime is_windows) return error.SkipZigTest;
    const sockfd = try sys.socket(posix.AF.INET, posix.SOCK.DGRAM | posix.SOCK.NONBLOCK, 0);
    defer sys.close(sockfd);

    const addr = try net.Address.parseIp4("127.0.0.1", 0);
    try sys.bind(sockfd, &addr.any, addr.getOsSockLen());

    // ECT(0) = 0b10 = 2
    try setEcnMark(sockfd, 0b10);
    // Not-ECT = 0b00 = 0
    try setEcnMark(sockfd, 0b00);
}

test "recvmsgEcn returns WouldBlock on empty socket" {
    if (comptime is_windows) return error.SkipZigTest;
    const sockfd = try sys.socket(posix.AF.INET, posix.SOCK.DGRAM | posix.SOCK.NONBLOCK, 0);
    defer sys.close(sockfd);

    const addr = try net.Address.parseIp4("127.0.0.1", 0);
    try sys.bind(sockfd, &addr.any, addr.getOsSockLen());
    try enableEcnRecv(sockfd);

    var buf: [1500]u8 = undefined;
    const result = recvmsgEcn(sockfd, &buf);
    try std.testing.expectError(error.WouldBlock, result);
}
