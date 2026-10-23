const std = @import("std");
const sys = @import("../sys.zig");
const net = @import("../sockaddr.zig");
const posix = std.posix;
const builtin = @import("builtin");

const is_windows = builtin.target.os.tag == .windows;
const is_linux = builtin.target.os.tag == .linux;
const linux = if (is_linux) std.os.linux else void;

// Platform-specific constants for ECN socket options (IPv4).
const IPPROTO_IP: u32 = 0;

const IP_TOS: u32 = switch (builtin.target.os.tag) {
    .macos => 3,
    .linux => 1,
    .windows => 3, // unused — ECN not supported on Windows
    else => @compileError("unsupported OS for ECN"),
};

const IP_RECVTOS: u32 = switch (builtin.target.os.tag) {
    .macos => 27,
    .linux => 13,
    .windows => 0, // unused — ECN not supported on Windows
    else => @compileError("unsupported OS for ECN"),
};

// IPv6 ECN constants
const IPV6_TCLASS: u32 = switch (builtin.target.os.tag) {
    .macos => 36,
    .linux => 67,
    .windows => 0,
    else => @compileError("unsupported OS for ECN"),
};

const IPV6_RECVTCLASS: u32 = switch (builtin.target.os.tag) {
    .macos => 35,
    .linux => 66,
    .windows => 0,
    else => @compileError("unsupported OS for ECN"),
};

// cmsg_type returned by recvmsg for TOS/ECN ancillary data.
// On macOS, the kernel returns IP_RECVTOS as the cmsg_type.
// On Linux, the kernel returns IP_TOS as the cmsg_type.
const CMSG_TYPE_TOS: u32 = switch (builtin.target.os.tag) {
    .macos => 27, // IP_RECVTOS
    .linux => 1, // IP_TOS
    .windows => 0,
    else => @compileError("unsupported OS for ECN"),
};

// cmsg header — Zig std doesn't expose this on macOS.
// Not used on Windows.
const CmsgHdr = extern struct {
    cmsg_len: switch (builtin.target.os.tag) {
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
    if (comptime builtin.target.os.tag != .linux) return;
    const val: u32 = 1;
    const rc = std.c.setsockopt(sockfd, SOL_SOCKET_LEVEL, @intCast(SO_TIMESTAMPNS), std.mem.asBytes(&val).ptr, 4);
    if (rc != 0) std.debug.print("rx timestamps: setsockopt failed rc={d}\n", .{rc});
}

/// Have what the socket sends go with the don't-fragment bit, for IPv4 and
/// IPv6 alike (RFC 9000 §14): a datagram too large for the path is then lost
/// rather than fragmented, which is what path MTU discovery has to see. One
/// larger than the interface's MTU fails to send, with EMSGSIZE.
///
/// Linux gets IP_PMTUDISC_PROBE: it ignores the path MTU the kernel learns
/// from ICMP, which is the connection's PMTUD to find, and spares the kernel
/// picking an IP ID for every packet. macOS refuses IP_DONTFRAG on a
/// dual-stack socket, so there IPv4 peers go without. Windows: no-op.
pub fn setDontFragment(sockfd: posix.socket_t) void {
    const opts: [2]struct { level: i32, name: u32, value: c_int } = switch (builtin.target.os.tag) {
        .linux => .{
            .{ .level = IPPROTO_IP, .name = linux.IP.MTU_DISCOVER, .value = linux.IP.PMTUDISC_PROBE },
            .{ .level = posix.IPPROTO.IPV6, .name = linux.IPV6.MTU_DISCOVER, .value = linux.IPV6.PMTUDISC_PROBE },
        },
        .macos => .{
            .{ .level = IPPROTO_IP, .name = posix.IP.DONTFRAG, .value = 1 },
            .{ .level = posix.IPPROTO.IPV6, .name = posix.IPV6.DONTFRAG, .value = 1 },
        },
        else => return,
    };
    // One the socket's family lacks fails, and may.
    for (opts) |o| rawSetsockopt(sockfd, o.level, o.name, std.mem.asBytes(&o.value));
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

    var cmsg_buf: [CMSG_BUF_SIZE]u8 align(@alignOf(CmsgHdr)) = @splat(0);
    var from_addr: posix.sockaddr.storage = std.mem.zeroes(posix.sockaddr.storage);
    const addr_len: posix.socklen_t = @sizeOf(posix.sockaddr.storage);

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

    const control = parseControl(cmsg_buf[0..msg.controllen]);
    return .{
        .bytes_read = @intCast(rc),
        .from_addr = from_addr,
        .addr_len = msg.namelen,
        .ecn = control.ecn,
        .truncated = msg.flags & @as(i32, @intCast(posix.MSG.TRUNC)) != 0,
        .kernel_ns = control.kernel_ns,
    };
}

const Control = struct { ecn: u2 = 0, kernel_ns: i64 = 0 };

/// A received datagram's ECN codepoint, and its arrival stamp when one was
/// asked for, from its control messages.
fn parseControl(control: []align(@alignOf(CmsgHdr)) const u8) Control {
    var out: Control = .{};
    var offset: usize = 0;
    while (offset + CMSG_HDR_SIZE <= control.len) {
        const hdr: *const CmsgHdr = @ptrCast(@alignCast(&control[offset]));
        const data_offset = offset + CMSG_HDR_SIZE;
        const data_len = @as(usize, hdr.cmsg_len) -| CMSG_HDR_SIZE;
        const is_ipv4_tos = hdr.cmsg_level == @as(i32, @intCast(IPPROTO_IP)) and
            hdr.cmsg_type == @as(i32, @intCast(CMSG_TYPE_TOS));
        const is_ipv6_tclass = hdr.cmsg_level == @as(i32, @intCast(posix.IPPROTO.IPV6)) and
            hdr.cmsg_type == @as(i32, @intCast(IPV6_TCLASS));
        if ((is_ipv4_tos or is_ipv6_tclass) and
            data_len >= 1 and data_offset < control.len)
        {
            out.ecn = @truncate(control[data_offset] & 0x03);
        } else if (builtin.target.os.tag == .linux and
            hdr.cmsg_level == SOL_SOCKET_LEVEL and
            hdr.cmsg_type == @as(i32, @intCast(SO_TIMESTAMPNS)) and
            data_len >= 16 and data_offset + 16 <= control.len)
        {
            const ts: *align(1) const extern struct { sec: i64, nsec: i64 } =
                @ptrCast(&control[data_offset]);
            out.kernel_ns = ts.sec * std.time.ns_per_s + ts.nsec;
        }
        // Advance to next cmsg (aligned)
        const total = (CMSG_HDR_SIZE + data_len + @alignOf(CmsgHdr) - 1) & ~@as(usize, @alignOf(CmsgHdr) - 1);
        if (total == 0) break;
        offset += total;
    }
    return out;
}

/// Datagrams taken off a socket together: up to `capacity` per `recvmmsg` on
/// Linux, one `recvmsg` elsewhere. A slot holds the largest datagram a peer
/// may send, so the slots are allocated.
pub const RecvBatch = struct {
    pub const capacity: usize = if (is_linux) 32 else 1;

    slots: []u8,
    slot_len: usize,
    /// What the last `recv` read, one per datagram.
    results: [capacity]RecvResult = undefined,
    addrs: [capacity]posix.sockaddr.storage = undefined,
    controls: [capacity][CMSG_BUF_SIZE]u8 align(@alignOf(CmsgHdr)) = undefined,

    pub fn init(gpa: std.mem.Allocator, slot_len: usize) !RecvBatch {
        return .{ .slots = try gpa.alloc(u8, capacity * slot_len), .slot_len = slot_len };
    }

    pub fn deinit(self: *RecvBatch, gpa: std.mem.Allocator) void {
        gpa.free(self.slots);
    }

    /// The `i`th datagram the last `recv` read, to be decrypted in place.
    pub fn datagram(self: *RecvBatch, i: usize) []u8 {
        return self.slots[i * self.slot_len ..][0..self.results[i].bytes_read];
    }

    /// Reads at least one datagram and at most `max`: error.WouldBlock when
    /// none is queued.
    pub fn recv(self: *RecvBatch, sockfd: posix.socket_t, max: usize) !usize {
        if (comptime !is_linux) {
            self.results[0] = try recvmsgEcn(sockfd, self.slots[0..self.slot_len]);
            return 1;
        }
        // Rebuilt each call: the batch may have moved since the last.
        const n = @min(max, capacity);
        var iovs: [capacity]posix.iovec = undefined;
        var msgs: [capacity]linux.mmsghdr = undefined;
        for (0..n) |i| {
            iovs[i] = .{ .base = self.slots[i * self.slot_len ..].ptr, .len = self.slot_len };
            msgs[i] = .{
                .hdr = .{
                    .name = @ptrCast(&self.addrs[i]),
                    .namelen = @sizeOf(posix.sockaddr.storage),
                    .iov = @ptrCast(&iovs[i]),
                    .iovlen = 1,
                    .control = &self.controls[i],
                    .controllen = CMSG_BUF_SIZE,
                    .flags = 0,
                },
                .len = 0,
            };
        }
        const rc = linux.recvmmsg(sockfd, &msgs, @intCast(n), 0, null);
        switch (linux.errno(rc)) {
            .SUCCESS => {},
            .AGAIN => return error.WouldBlock,
            .CONNREFUSED => return error.ConnectionRefused,
            else => |err| return posix.unexpectedErrno(err),
        }
        for (msgs[0..rc], 0..) |*m, i| {
            const control = parseControl(self.controls[i][0..m.hdr.controllen]);
            self.results[i] = .{
                .bytes_read = m.len,
                .from_addr = self.addrs[i],
                .addr_len = m.hdr.namelen,
                .ecn = control.ecn,
                .truncated = m.hdr.flags & linux.MSG.TRUNC != 0,
                .kernel_ns = control.kernel_ns,
            };
        }
        return rc;
    }
};

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
/// On Linux the batch leaves in one `sendmmsg` per ECN mark, each message to
/// its own address, and each stretch to one address that GSO can take
/// (same-sized packets, then at most one shorter) is a single message carrying
/// `UDP_SEGMENT`, so the kernel does the splitting: one skb for the stretch,
/// which is what nginx's `quic_gso` buys. Where UDP_SEGMENT is unavailable
/// every packet is its own message. Other platforms send one `sendmsg` per
/// packet.
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
        // Packets that share an ECN mark go out together: changing the mark is
        // a setsockopt. A server sends one packet to each of many peers a pass,
        // and those runs of one cost a syscall apiece when split by address.
        var start: usize = 0;
        while (start < self.count) {
            var end = start + 1;
            while (end < self.count and self.ecn_marks[end] == self.ecn_marks[start]) : (end += 1) {}
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
        if (!self.gso) return self.sendMany(from, to);
        // GSO takes equal-sized packets and one shorter last, so a whole run
        // qualified only when every packet in it did: one ACK or short packet
        // anywhere sent the lot one skb per datagram, 85% of sends on the 10 KB
        // HTTP/3 row. Each qualifying stretch is now one message carrying its
        // own UDP_SEGMENT, beside plain messages for the packets between them,
        // all in one sendmmsg: splitting into separate syscalls cost more than
        // it saved where the stretches are short.
        var iovs: [MAX_BATCH]posix.iovec_const = undefined;
        var msgs: [MAX_BATCH]linux.mmsghdr = undefined;
        var controls: [MAX_BATCH][cmsgSpace(@sizeOf(u16))]u8 align(@alignOf(linux.cmsghdr)) = undefined;
        var starts: [MAX_BATCH]usize = undefined; // first packet of each message
        var n: usize = 0;
        var i = from;
        while (i < to) : (n += 1) {
            var end = self.segmentEnd(i, to);
            if (end - i < 2) end = i + 1;
            const last = end - 1;
            const bytes = self.offsets[last] + self.lengths[last] - self.offsets[i];
            iovs[n] = .{ .base = self.data_buf[self.offsets[i]..].ptr, .len = bytes };
            msgs[n] = .{
                .hdr = .{
                    .name = @ptrCast(&self.addrs[i]),
                    .namelen = self.addr_lens[i],
                    .iov = @ptrCast(&iovs[n]),
                    .iovlen = 1,
                    .control = null,
                    .controllen = 0,
                    .flags = 0,
                },
                .len = 0,
            };
            if (end - i >= 2) {
                const control = &controls[n];
                const cmsg: *linux.cmsghdr = @ptrCast(control);
                cmsg.* = .{
                    .len = cmsgLen(@sizeOf(u16)),
                    .level = linux.IPPROTO.UDP,
                    .type = linux.UDP.SEGMENT,
                };
                const seg16: u16 = @intCast(self.lengths[i]);
                @memcpy(control[cmsgLen(0)..][0..@sizeOf(u16)], std.mem.asBytes(&seg16));
                msgs[n].hdr.control = control;
                msgs[n].hdr.controllen = @intCast(control.len);
            }
            starts[n] = i;
            i = end;
        }
        // Partial sends are normal: keep going from where it stopped.
        var sent: usize = 0;
        while (sent < n) {
            const rc = std.c.sendmmsg(self.sockfd, msgs[sent..].ptr, @intCast(n - sent), 0);
            if (rc > 0) {
                sent += @intCast(rc);
                continue;
            }
            // A kernel or socket without UDP_SEGMENT will keep saying so, so
            // stop asking. Either way, what is left goes out a packet at a time.
            switch (posix.errno(rc)) {
                .INVAL, .NOPROTOOPT, .OPNOTSUPP => self.gso = false,
                else => {},
            }
            return self.sendMany(starts[sent], to);
        }
    }

    /// Where a GSO send starting at `from` has to stop: packets to its address
    /// the size of the first, then at most one shorter, within the length
    /// limit.
    fn segmentEnd(self: *const SendBatch, from: usize, to: usize) usize {
        const seg = self.lengths[from];
        var total: usize = seg;
        var i = from + 1;
        while (i < to) : (i += 1) {
            const len = self.lengths[i];
            if (len > seg or total + len > max_gso_bytes or !self.sameAddr(from, i)) break;
            total += len;
            if (len < seg) return i + 1;
        }
        return i;
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

test "RecvBatch: datagrams from two senders arrive whole, in order, with their sources" {
    if (comptime is_windows) return error.SkipZigTest;
    const loopback = try net.Address.parseIp4("127.0.0.1", 0);
    const rx = try sys.socket(posix.AF.INET, posix.SOCK.DGRAM | posix.SOCK.NONBLOCK, 0);
    defer sys.close(rx);
    try sys.bind(rx, &loopback.any, loopback.getOsSockLen());
    try enableEcnRecv(rx);
    var to: net.Address = undefined;
    var to_len: posix.socklen_t = @sizeOf(net.Address);
    try sys.getsockname(rx, &to.any, &to_len);

    var senders: [2]posix.socket_t = undefined;
    var ports: [2]u16 = undefined;
    for (&senders, &ports, 0..) |*fd, *port, k| {
        fd.* = try sys.socket(posix.AF.INET, posix.SOCK.DGRAM, 0);
        try sys.bind(fd.*, &loopback.any, loopback.getOsSockLen());
        var a: net.Address = undefined;
        var len: posix.socklen_t = @sizeOf(net.Address);
        try sys.getsockname(fd.*, &a.any, &len);
        port.* = a.getPort();
        if (k == 1) try setEcnMark(fd.*, 0b10);
    }
    defer for (senders) |fd| sys.close(fd);

    // Past one batch, sizes up to a slot's, alternating senders.
    const total = 2 * RecvBatch.capacity + 5;
    var out: [3000]u8 = undefined;
    for (0..total) |i| {
        const len = 1 + i * 97 % out.len;
        @memset(out[0..len], @truncate(i));
        _ = std.c.sendto(senders[i % 2], &out, len, 0, &to.any, to.getOsSockLen());
    }

    var batch = try RecvBatch.init(std.testing.allocator, out.len);
    defer batch.deinit(std.testing.allocator);
    var seen: usize = 0;
    while (seen < total) {
        // macOS loopback delivers after sendto returns, not before.
        var pfd = [_]std.c.pollfd{.{ .fd = rx, .events = posix.POLL.IN, .revents = 0 }};
        try std.testing.expectEqual(@as(c_int, 1), std.c.poll(&pfd, 1, 5_000));
        const got = try batch.recv(rx, RecvBatch.capacity);
        for (batch.results[0..got], 0..) |r, k| {
            const i = seen + k;
            const d = batch.datagram(k);
            try std.testing.expectEqual(1 + i * 97 % out.len, d.len);
            for (d) |b| try std.testing.expectEqual(@as(u8, @truncate(i)), b);
            const from: *const posix.sockaddr.in = @ptrCast(@alignCast(&r.from_addr));
            try std.testing.expectEqual(ports[i % 2], std.mem.bigToNative(u16, from.port));
            if (is_linux) try std.testing.expectEqual(@as(u2, if (i % 2 == 1) 0b10 else 0), r.ecn);
        }
        seen += got;
    }
    try std.testing.expectError(error.WouldBlock, batch.recv(rx, RecvBatch.capacity));
}

test "SendBatch.segmentEnd: equal packets and one shorter last" {
    var b = SendBatch.init(0);
    @memset(&b.addr_lens, 0); // one address for all
    const cases = [_]struct { lens: []const u32, from: usize, want: usize }{
        // All the same size: the whole run.
        .{ .lens = &.{ 1436, 1436, 1436 }, .from = 0, .want = 3 },
        // A shorter one ends it, as the last segment.
        .{ .lens = &.{ 1436, 1436, 60, 1436 }, .from = 0, .want = 3 },
        // A larger one ends it before.
        .{ .lens = &.{ 60, 1436, 1436 }, .from = 0, .want = 1 },
        .{ .lens = &.{ 60, 1436, 1436 }, .from = 1, .want = 3 },
    };
    for (cases) |c| {
        for (c.lens, 0..) |l, i| b.lengths[i] = l;
        try std.testing.expectEqual(c.want, b.segmentEnd(c.from, c.lens.len));
    }
    // The datagram's 16-bit length caps it: 45 x 1436 fits, 46 does not.
    for (0..50) |i| b.lengths[i] = 1436;
    try std.testing.expectEqual(@as(usize, 45), b.segmentEnd(0, 50));
    // Another address ends it.
    b.addr_lens[3] = 16;
    try std.testing.expectEqual(@as(usize, 3), b.segmentEnd(0, 50));
}

test "SendBatch: a run with odd packets in it arrives whole and in order" {
    if (comptime !is_linux) return error.SkipZigTest;
    const rx = try sys.socket(posix.AF.INET, posix.SOCK.DGRAM | posix.SOCK.NONBLOCK, 0);
    defer sys.close(rx);
    const any = try net.Address.parseIp4("127.0.0.1", 0);
    try sys.bind(rx, &any.any, any.getOsSockLen());
    var to: posix.sockaddr.storage = undefined;
    var to_len: posix.socklen_t = @sizeOf(posix.sockaddr.storage);
    try std.testing.expectEqual(@as(c_int, 0), std.c.getsockname(rx, @ptrCast(&to), &to_len));

    const tx = try sys.socket(posix.AF.INET, posix.SOCK.DGRAM | posix.SOCK.NONBLOCK, 0);
    defer sys.close(tx);
    var batch = SendBatch.init(tx);

    // Two segmentable stretches around an ACK-sized packet, and a short tail.
    const sizes = [_]usize{ 1200, 1200, 1200, 60, 1200, 1200, 700, 1200 };
    for (sizes, 0..) |len, i| {
        const slot = batch.reserve();
        @memset(slot[0..len], @intCast(i));
        batch.commit(len, @ptrCast(&to), to_len, 0);
    }
    batch.flush();

    var buf: [1500]u8 = undefined;
    var got: usize = 0;
    var tries: usize = 0;
    while (got < sizes.len and tries < 1000) : (tries += 1) {
        const r = recvmsgEcn(rx, &buf) catch |err| switch (err) {
            error.WouldBlock => {
                sys.sleepNs(std.time.ns_per_ms);
                continue;
            },
            else => return err,
        };
        try std.testing.expectEqual(sizes[got], r.bytes_read);
        try std.testing.expectEqual(@as(u8, @intCast(got)), buf[0]);
        got += 1;
    }
    try std.testing.expectEqual(sizes.len, got);
}

test "SendBatch: packets for two peers, interleaved, each arrive whole and in order" {
    if (comptime !is_linux) return error.SkipZigTest;
    var rx: [2]posix.socket_t = undefined;
    var to: [2]posix.sockaddr.storage = undefined;
    var to_len: [2]posix.socklen_t = @splat(@sizeOf(posix.sockaddr.storage));
    for (&rx, &to, &to_len) |*fd, *addr, *len| {
        fd.* = try sys.socket(posix.AF.INET, posix.SOCK.DGRAM | posix.SOCK.NONBLOCK, 0);
        const any = try net.Address.parseIp4("127.0.0.1", 0);
        try sys.bind(fd.*, &any.any, any.getOsSockLen());
        try std.testing.expectEqual(@as(c_int, 0), std.c.getsockname(fd.*, @ptrCast(addr), len));
    }
    defer for (rx) |fd| sys.close(fd);

    const tx = try sys.socket(posix.AF.INET, posix.SOCK.DGRAM | posix.SOCK.NONBLOCK, 0);
    defer sys.close(tx);
    var batch = SendBatch.init(tx);
    // Peer 0 gets a segmentable pair; the rest alternate one packet each.
    const peers = [_]usize{ 0, 0, 1, 0, 1, 1, 0 };
    for (peers, 0..) |p, i| {
        const slot = batch.reserve();
        @memset(slot[0..300], @intCast(i));
        batch.commit(300, @ptrCast(&to[p]), to_len[p], 0);
    }
    batch.flush();

    var buf: [1500]u8 = undefined;
    for (rx, 0..) |fd, p| {
        var tries: usize = 0;
        for (peers, 0..) |want_peer, i| {
            if (want_peer != p) continue;
            const r = while (tries < 1000) : (tries += 1) {
                break recvmsgEcn(fd, &buf) catch |err| switch (err) {
                    error.WouldBlock => {
                        sys.sleepNs(std.time.ns_per_ms);
                        continue;
                    },
                    else => return err,
                };
            } else return error.Timeout;
            try std.testing.expectEqual(@as(usize, 300), r.bytes_read);
            try std.testing.expectEqual(@as(u8, @intCast(i)), buf[0]);
        }
    }
}
