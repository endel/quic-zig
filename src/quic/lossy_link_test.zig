//! A client and a server connection wired back to back through a simulated
//! link on a virtual clock, so loss recovery can be tested deterministically
//! and without real time passing.

const std = @import("std");
const posix = std.posix;
const testing = std.testing;
const sys = @import("../sys.zig");
const connection = @import("connection.zig");
const connection_manager = @import("connection_manager.zig");
const ack_handler = @import("ack_handler.zig");
const congestion = @import("congestion.zig");
const tls13 = @import("tls13.zig");
const mtu = @import("mtu.zig");

const EcdsaP256Sha256 = std.crypto.sign.ecdsa.EcdsaP256Sha256;

const MAX_DGRAM = 1500;

const Datagram = struct {
    arrive: i64,
    len: usize,
    bytes: [MAX_DGRAM]u8,
};

/// One direction of the link: fixed delay, and a drop decision per datagram.
const Link = struct {
    queue: std.ArrayList(Datagram) = .empty,
    delay_ns: i64,
    sent: u64 = 0,
    dropped: u64 = 0,
    loss: Loss,

    const Loss = union(enum) {
        none,
        /// Drop `burst` consecutive datagrams out of every `period`.
        periodic: struct { period: u64, burst: u64, phase: u64 = 0 },
        /// Gilbert-Elliott: enter a loss burst with `p_enter`, leave with
        /// `p_leave`; every datagram inside a burst is dropped.
        bursty: struct { prng: std.Random.DefaultPrng, p_enter: f64, p_leave: f64, in_burst: bool = false },
    };

    fn deinit(self: *Link) void {
        self.queue.deinit(testing.allocator);
    }

    fn drops(self: *Link) bool {
        const n = self.sent;
        self.sent += 1;
        return switch (self.loss) {
            .none => false,
            .periodic => |p| (n + p.phase) % p.period < p.burst,
            .bursty => |*b| blk: {
                const r = b.prng.random().float(f64);
                if (b.in_burst) {
                    if (r < b.p_leave) b.in_burst = false;
                } else if (r < b.p_enter) b.in_burst = true;
                break :blk b.in_burst;
            },
        };
    }

    fn push(self: *Link, now: i64, bytes: []const u8) !void {
        if (self.drops()) {
            self.dropped += 1;
            return;
        }
        var d: Datagram = .{ .arrive = now + self.delay_ns, .len = bytes.len, .bytes = undefined };
        @memcpy(d.bytes[0..bytes.len], bytes);
        try self.queue.append(testing.allocator, d);
    }

    fn nextArrival(self: *const Link) ?i64 {
        return if (self.queue.items.len > 0) self.queue.items[0].arrive else null;
    }
};

fn addr(port: u16) posix.sockaddr.storage {
    var st = std.mem.zeroes(posix.sockaddr.storage);
    const in: *posix.sockaddr.in = @ptrCast(@alignCast(&st));
    in.* = .{ .port = std.mem.nativeToBig(u16, port), .addr = std.mem.nativeToBig(u32, 0x7f000001) };
    return st;
}

fn serverTls() tls13.TlsConfig {
    const S = struct {
        var secret_key_bytes: [32]u8 = undefined;
        var pub_key_bytes: [65]u8 = undefined;
        var cert_chain: [1][]const u8 = undefined;
        var alpn: [1][]const u8 = .{"bulk"};
    };
    const kp = EcdsaP256Sha256.KeyPair.generate(testing.io);
    S.secret_key_bytes = kp.secret_key.toBytes();
    S.pub_key_bytes = kp.public_key.toUncompressedSec1();
    S.cert_chain = .{&S.pub_key_bytes};
    return .{ .cert_chain_der = &S.cert_chain, .private_key_bytes = &S.secret_key_bytes, .alpn = &S.alpn };
}

fn clientTls() tls13.TlsConfig {
    return .{
        .cert_chain_der = &.{},
        .private_key_bytes = &.{},
        .alpn = &client_alpn,
        .server_name = "localhost",
        .skip_cert_verify = true,
    };
}

/// Point at a directory to get qlog traces of both ends when debugging.
var qlog_dir: ?[]const u8 = null;
const client_alpn = [_][]const u8{"bulk"};

const Result = struct {
    delivered: u64,
    finished: bool,
    elapsed_ns: i64,
    c2s_dropped: u64,
    c2s_sent: u64,
    s2c_dropped: u64,
    s2c_sent: u64,
    closed: bool,
    /// Longest stretch of virtual time in which the server read nothing new.
    max_stall_ns: i64,
    /// Datagram size each side ended up using.
    client_mtu: u16,
    server_mtu: u16,
};

/// Client uploads `total` bytes on one bidi stream; the server reads as it
/// arrives. Stops when the server has read the FIN, a connection closes, or
/// `limit_ns` of virtual time has passed.
fn runBulk(total: usize, c2s_loss: Link.Loss, s2c_loss: Link.Loss, one_way_ns: i64, limit_ns: i64) !Result {
    return runBulkWith(.{}, total, c2s_loss, s2c_loss, one_way_ns, limit_ns);
}

/// `runBulk` with the server's connection config.
fn runBulkWith(server_config: connection.ConnectionConfig, total: usize, c2s_loss: Link.Loss, s2c_loss: Link.Loss, one_way_ns: i64, limit_ns: i64) !Result {
    const alloc = testing.allocator;
    const start: i64 = 1_000 * std.time.ns_per_s;
    sys.test_clock = start;
    defer sys.test_clock = null;
    var now = start;

    var config = server_config;
    config.qlog_dir = qlog_dir;
    var mgr = connection_manager.ConnectionManager.init(alloc, serverTls(), config, @splat(1), @splat(2));
    defer mgr.deinit();

    const client = try alloc.create(connection.Connection);
    defer alloc.destroy(client);
    try connection.connectInto(client, alloc, "localhost", .{ .qlog_dir = qlog_dir }, .{
        .cert_chain_der = &.{},
        .private_key_bytes = &.{},
        .alpn = &client_alpn,
        .server_name = "localhost",
        .skip_cert_verify = true,
    }, null);
    defer client.deinit();

    const c_addr = addr(40000);
    const s_addr = addr(4433);
    client.paths[0].peer_addr = s_addr;
    client.paths[0].local_addr = c_addr;

    var c2s: Link = .{ .delay_ns = one_way_ns, .loss = c2s_loss };
    defer c2s.deinit();
    var s2c: Link = .{ .delay_ns = one_way_ns, .loss = s2c_loss };
    defer s2c.deinit();

    const payload = try alloc.alloc(u8, total);
    defer alloc.free(payload);
    for (payload, 0..) |*b, k| b.* = @intCast(k % 251);

    var last_delivered: u64 = 0;
    var last_progress: i64 = start;
    var max_stall: i64 = 0;
    var stream_id: ?u64 = null;
    var delivered: u64 = 0;
    var finished = false;
    var buf: [MAX_DGRAM]u8 = undefined;
    var resp: [MAX_DGRAM]u8 = undefined;

    while (now - start < limit_ns and !finished) {
        // Timers due now.
        if (client.nextTimeoutNs()) |t| if (t <= now) client.onTimeout() catch {};
        for (mgr.entries.items) |e| if (e.conn.nextTimeoutNs()) |t| if (t <= now) e.conn.onTimeout() catch {};
        if (client.isClosed()) break;
        if (mgr.entries.items.len > 0 and mgr.entries.items[0].conn.isClosed()) break;

        // Application: open and fill the upload once connected.
        if (stream_id == null and client.isEstablished()) {
            const s = try client.openStream();
            try s.send.writeData(payload);
            s.send.close();
            stream_id = s.stream_id;
        }
        if (mgr.entries.items.len > 0) {
            const sconn = mgr.entries.items[0].conn;
            if (stream_id) |id| if (sconn.streams.getStream(id)) |s| {
                while (s.recv.read()) |d| {
                    for (d, delivered..) |v, k| try testing.expectEqual(@as(u8, @intCast(k % 251)), v);
                    delivered += d.len;
                    alloc.free(d);
                }
                if (s.recv.finished) finished = true;
            };
        }
        if (delivered != last_delivered) {
            max_stall = @max(max_stall, now - last_progress);
            last_delivered = delivered;
            last_progress = now;
        }

        // Send everything each side will send now.
        while (true) {
            const n = client.send(&buf) catch break;
            if (n == 0) break;
            try c2s.push(now, buf[0..n]);
        }
        for (mgr.entries.items) |e| while (true) {
            const n = e.conn.send(&buf) catch break;
            if (n == 0) break;
            try s2c.push(now, buf[0..n]);
        };

        // Deliver what has arrived.
        var delivered_any = false;
        while (c2s.queue.items.len > 0 and c2s.queue.items[0].arrive <= now) {
            var d = c2s.queue.orderedRemove(0);
            delivered_any = true;
            switch (mgr.recvDatagram(d.bytes[0..d.len], c_addr, s_addr, 0, &resp)) {
                .send_response => |r| try s2c.push(now, r),
                else => {},
            }
        }
        while (s2c.queue.items.len > 0 and s2c.queue.items[0].arrive <= now) {
            var d = s2c.queue.orderedRemove(0);
            client.handleDatagram(d.bytes[0..d.len], .{ .to = c_addr, .from = s_addr, .datagram_size = d.len });
            delivered_any = true;
        }
        if (delivered_any) continue;

        // Advance to the next event.
        var next: i64 = std.math.maxInt(i64);
        if (c2s.nextArrival()) |t| next = @min(next, t);
        if (s2c.nextArrival()) |t| next = @min(next, t);
        if (client.nextTimeoutNs()) |t| next = @min(next, t);
        for (mgr.entries.items) |e| if (e.conn.nextTimeoutNs()) |t| {
            next = @min(next, t);
        };
        // A timer already due that fired without effect must not spin.
        now = @max(now + std.time.ns_per_us, next);
        sys.test_clock = now;
    }

    const closed = client.isClosed() or (mgr.entries.items.len > 0 and mgr.entries.items[0].conn.isClosed());
    return .{
        .delivered = delivered,
        .finished = finished,
        .elapsed_ns = now - start,
        .c2s_dropped = c2s.dropped,
        .c2s_sent = c2s.sent,
        .s2c_dropped = s2c.dropped,
        .s2c_sent = s2c.sent,
        .closed = closed,
        .max_stall_ns = @max(max_stall, now - last_progress),
        .client_mtu = client.mtu_discoverer.current_mtu,
        .server_mtu = if (mgr.entries.items.len > 0) mgr.entries.items[0].conn.mtu_discoverer.current_mtu else 0,
    };
}

const ms = std.time.ns_per_ms;

test "lossy link: a clean 4 MiB upload finishes within a second" {
    const r = try runBulk(4 << 20, .none, .none, 10 * ms, 60 * std.time.ns_per_s);
    try testing.expect(r.finished);
    try testing.expect(r.elapsed_ns < std.time.ns_per_s);
}

test "lossy link: an upload past the stream window gets MAX_STREAM_DATA" {
    // 16 MiB against the 6 MiB initial stream window: without the server
    // re-granting credit as it reads, the upload stalls and never finishes.
    const r = try runBulk(16 << 20, .none, .none, 10 * ms, 60 * std.time.ns_per_s);
    try testing.expect(r.finished);
}

test "lossy link: an upload read as it comes goes through many stream and connection windows" {
    // Each read has to bring the next MAX_STREAM_DATA and MAX_DATA, or the
    // upload stalls at a window and never finishes.
    const r = try runBulkWith(.{
        .initial_max_data = 64 << 10,
        .initial_max_stream_data_bidi_remote = 16 << 10,
    }, 1 << 20, .none, .none, 10 * ms, 60 * std.time.ns_per_s);
    try testing.expect(r.finished);
}

test "lossy link: a busy connection still finds the path MTU" {
    // The probe used to sit below the pacer, where the only way to reach it was
    // a pass with nothing to send and no pacing due — which a connection
    // carrying data back to back never gets. Every datagram stayed at 1200.
    const r = try runBulk(4 << 20, .none, .none, 10 * ms, 60 * std.time.ns_per_s);
    try testing.expect(r.finished);
    try testing.expect(r.client_mtu > mtu.BASE_PLPMTU);
    try testing.expect(r.server_mtu > mtu.BASE_PLPMTU);
}

test "lossy link: an upload survives bursty loss on the data path" {
    // ~9.5% loss in bursts averaging 3.3 datagrams.
    const r = try runBulk(2 << 20, .{ .bursty = .{ .prng = .init(2), .p_enter = 0.03, .p_leave = 0.3 } }, .none, 10 * ms, 120 * std.time.ns_per_s);
    try testing.expect(r.finished);
    try testing.expect(r.c2s_dropped > r.c2s_sent / 20);
}

test "lossy link: an upload survives periodic loss bursts in both directions" {
    const burst: Link.Loss = .{ .periodic = .{ .period = 55, .burst = 5 } };
    const r = try runBulk(2 << 20, burst, burst, 10 * ms, 120 * std.time.ns_per_s);
    try testing.expect(r.finished);
}

test "lossy link: with a byte threshold, a full-size upload still draws an ACK every two packets" {
    // It takes 2 ms either way; waiting for the alarm instead, ~120 ms.
    const r = try runBulkWith(.{ .max_ack_delay = 60, .ack_bytes_threshold = 2000 }, 4 << 20, .none, .none, 100 * std.time.ns_per_us, 60 * std.time.ns_per_s);
    try testing.expect(r.finished);
    try testing.expect(r.elapsed_ns < 10 * ms);
}

const stateless_reset = @import("stateless_reset.zig");

/// A connected client and server, handshake done and CIDs exchanged.
const Pair = struct {
    mgr: connection_manager.ConnectionManager,
    client: *connection.Connection,
    c_addr: posix.sockaddr.storage = addr(40000),
    s_addr: posix.sockaddr.storage = addr(4433),

    fn init(self: *Pair) !void {
        return self.initWith(.{}, .{});
    }

    fn initWith(self: *Pair, server_config: connection.ConnectionConfig, client_config: connection.ConnectionConfig) !void {
        return self.initTls(serverTls(), server_config, client_config, clientTls());
    }

    fn initTls(self: *Pair, server_tls: tls13.TlsConfig, server_config: connection.ConnectionConfig, client_config: connection.ConnectionConfig, client_tls: tls13.TlsConfig) !void {
        const alloc = testing.allocator;
        self.* = .{
            .mgr = connection_manager.ConnectionManager.init(alloc, server_tls, server_config, @splat(1), @splat(2)),
            .client = try alloc.create(connection.Connection),
        };
        errdefer {
            alloc.destroy(self.client);
            self.mgr.deinit();
        }
        try connection.connectInto(self.client, alloc, "localhost", client_config, client_tls, null);
        self.client.paths[0].peer_addr = self.s_addr;
        self.client.paths[0].local_addr = self.c_addr;

        var i: usize = 0;
        while (i < 50 and self.exchange()) : (i += 1) {}
        try testing.expect(self.client.handshake_confirmed);
        try testing.expectEqual(@as(usize, 1), self.mgr.entries.items.len);
    }

    fn deinit(self: *Pair) void {
        self.client.deinit();
        testing.allocator.destroy(self.client);
        self.mgr.deinit();
    }

    /// One round of both sides sending what they have; false once quiet.
    fn exchange(self: *Pair) bool {
        var buf: [MAX_DGRAM]u8 = undefined;
        var resp: [MAX_DGRAM]u8 = undefined;
        var any = false;
        while (true) {
            const n = self.client.send(&buf) catch break;
            if (n == 0) break;
            any = true;
            _ = self.mgr.recvDatagram(buf[0..n], self.c_addr, self.s_addr, 0, &resp);
        }
        for (self.mgr.entries.items) |e| while (true) {
            const n = e.conn.send(&buf) catch break;
            if (n == 0) break;
            any = true;
            self.client.handleDatagram(buf[0..n], .{ .to = self.c_addr, .from = self.s_addr, .datagram_size = n });
        };
        return any;
    }

    /// The client sends one datagram and the server answers into the void,
    /// so the client acknowledges nothing it sent. The server's datagram
    /// count, or null if the client had nothing to send.
    fn sendUnheard(self: *Pair) !?usize {
        var buf: [MAX_DGRAM]u8 = undefined;
        var resp: [MAX_DGRAM]u8 = undefined;
        const n = try self.client.send(&buf);
        if (n == 0) return null;
        _ = self.mgr.recvDatagram(buf[0..n], self.c_addr, self.s_addr, 0, &resp);
        var replies: usize = 0;
        for (self.mgr.entries.items) |e| while (true) {
            const m = e.conn.send(&buf) catch break;
            if (m == 0) break;
            replies += 1;
        };
        return replies;
    }
};

test "ACK-only packets: a peer that never acknowledges them costs the server nothing" {
    // Every packet sent was recorded for loss detection, which only reaches
    // the largest packet acknowledged: a peer sending PINGs and never
    // acknowledging the ACKs they earned grew the server's records until it
    // ran out of memory.
    var p: Pair = undefined;
    try p.init();
    defer p.deinit();
    const sconn = p.mgr.entries.items[0].conn;
    const tracker = &sconn.pkt_handler.sent[@backingInt(ack_handler.EncLevel.application)];
    const held = tracker.sent_packets.count();

    var replies: usize = 0;
    for (0..1000) |_| {
        p.client.pending_frames.push(.ping);
        // Its own PINGs go unacknowledged too, so its window fills.
        replies += try p.sendUnheard() orelse break;
    }
    try testing.expect(replies >= 100);
    try testing.expectEqual(held, tracker.sent_packets.count());
}

test "ACK-only packets: a one-way flow of datagrams draws one per two packets" {
    // RFC 9000 13.2.2. The server is visited after every packet, as its
    // event loop does, and has nothing to send back.
    sys.test_clock = 1_000 * std.time.ns_per_s;
    defer sys.test_clock = null;
    const config: connection.ConnectionConfig = .{ .max_datagram_frame_size = 1200, .disable_pmtud = true };
    var p: Pair = undefined;
    try p.initWith(config, config);
    defer p.deinit();
    const sconn = p.mgr.entries.items[0].conn;
    const sent = sconn.total_packets_sent;

    var buf: [MAX_DGRAM]u8 = undefined;
    var resp: [MAX_DGRAM]u8 = undefined;
    const inputs = 20;
    for (0..inputs) |_| {
        sys.test_clock.? += std.time.ns_per_ms;
        try p.client.sendDatagram("input");
        const n = try p.client.send(&buf);
        try testing.expect(n > 0);
        _ = p.mgr.recvDatagram(buf[0..n], p.c_addr, p.s_addr, 0, &resp);
        while (true) {
            const m = try sconn.send(&buf);
            if (m == 0) break;
            p.client.handleDatagram(buf[0..m], .{ .to = p.c_addr, .from = p.s_addr, .datagram_size = m });
        }
    }
    // One more for the packet number the client skips (RFC 9000 21.4):
    // a gap is acknowledged at once.
    try testing.expect(sconn.total_packets_sent - sent <= inputs / 2 + 1);
    try testing.expectEqual(@as(u32, 0), p.client.pkt_handler.sent[2].ack_eliciting_in_flight);
}

test "ACK-only packets: with a byte threshold, small datagrams wait for the alarm" {
    // The server has nothing to send back, so the ACK goes alone, once.
    sys.test_clock = 1_000 * std.time.ns_per_s;
    defer sys.test_clock = null;
    const config: connection.ConnectionConfig = .{ .max_datagram_frame_size = 1200, .disable_pmtud = true };
    var server_config = config;
    server_config.max_ack_delay = 60;
    server_config.ack_bytes_threshold = 2000;
    var p: Pair = undefined;
    try p.initWith(server_config, config);
    defer p.deinit();
    const sconn = p.mgr.entries.items[0].conn;
    for (0..3) |_| {
        sys.test_clock.? += 70 * std.time.ns_per_ms;
        while (p.exchange()) {}
    }
    // A gap would be acknowledged at once.
    p.client.pkt_handler.skip_pn = std.math.maxInt(u64);
    const sent = sconn.total_packets_sent;

    var buf: [MAX_DGRAM]u8 = undefined;
    var resp: [MAX_DGRAM]u8 = undefined;
    const first = sys.test_clock.? + std.time.ns_per_ms;
    for (0..20) |_| {
        sys.test_clock.? += std.time.ns_per_ms;
        try p.client.sendDatagram("input");
        const n = try p.client.send(&buf);
        _ = p.mgr.recvDatagram(buf[0..n], p.c_addr, p.s_addr, 0, &resp);
        try testing.expectEqual(@as(usize, 0), try sconn.send(&buf));
    }
    try testing.expectEqual(sent, sconn.total_packets_sent);
    // Set by the first, 1 ms short of the 60 advertised.
    const alarm = sconn.pkt_handler.recv[2].ack_alarm.?;
    try testing.expectEqual(first + 59 * std.time.ns_per_ms, alarm);

    sys.test_clock = alarm;
    _ = try sconn.fireTimers();
    try testing.expect(try sconn.send(&buf) > 0);
    try testing.expectEqual(@as(u64, 0), sconn.pkt_handler.recv[2].ack_eliciting_bytes);
    try testing.expectEqual(sent + 1, sconn.total_packets_sent);
}

test "transport parameters: each end advertises its max_ack_delay, min_ack_delay never above it" {
    var p: Pair = undefined;
    try p.initWith(.{ .max_ack_delay = 60 }, .{ .max_ack_delay = 0 });
    defer p.deinit();
    const sconn = p.mgr.entries.items[0].conn;
    const ms_ns: i64 = std.time.ns_per_ms;

    try testing.expectEqual(@as(u64, 60), p.client.peer_params.?.max_ack_delay);
    try testing.expectEqual(60 * ms_ns, p.client.pkt_handler.rtt_stats.max_ack_delay);
    try testing.expectEqual(60 * ms_ns, sconn.pkt_handler.recv[2].max_ack_delay_ns);

    const from_client = sconn.peer_params.?;
    try testing.expectEqual(@as(u64, 0), from_client.max_ack_delay);
    try testing.expectEqual(@as(i64, 0), p.client.pkt_handler.recv[2].max_ack_delay_ns);
    // draft-ietf-quic-ack-frequency forbids a min_ack_delay over max_ack_delay.
    try testing.expect(from_client.min_ack_delay.? <= from_client.max_ack_delay * 1000);
}

test "PATH_CHALLENGE: a peer that never acknowledges the responses can't grow the server's records" {
    // PATH_RESPONSE goes out even when congestion-limited, so a peer
    // challenging in every packet and acknowledging nothing kept the server
    // sending, and recording, past its window. Within a large window, tiny
    // responses made a record of every few dozen bytes of it.
    for ([_]u64{ 0, 1000 }) |window_packets| {
        var p: Pair = undefined;
        try p.init();
        defer p.deinit();
        const sconn = p.mgr.entries.items[0].conn;
        const mds = sconn.cc.max_datagram_size;
        if (window_packets > 0) sconn.cc.congestion_window = window_packets * mds;
        const tracker = &sconn.pkt_handler.sent[@backingInt(ack_handler.EncLevel.application)];

        var replies: usize = 0;
        for (0..5000) |i| {
            var data: [8]u8 = undefined;
            std.mem.writeInt(u64, &data, i, .little);
            p.client.pending_frames.push(.{ .path_challenge = data });
            // It ignores its own window, as an attacker would.
            p.client.pkt_handler.bytes_in_flight = 0;
            replies += try p.sendUnheard() orelse continue;
        }
        const window = sconn.cc.sendWindow();
        try testing.expect(replies >= 100);
        // Two datagrams of slack, and the packet that crossed it.
        try testing.expect(sconn.pkt_handler.bytes_in_flight <= window + 3 * mds);
        try testing.expect(tracker.sent_packets.count() <= ack_handler.maxTrackedPackets(window, mds));
    }
}

test "PTO: probes a peer never acknowledges stop at the record limit" {
    // A peer that kept the connection alive and acknowledged nothing got up
    // to two more probes every PTO, and nothing ever released one.
    sys.test_clock = 1_000 * std.time.ns_per_s;
    defer sys.test_clock = null;
    // An idle timeout of days stands in for the peer's packets keeping the
    // connection open.
    var p: Pair = undefined;
    const days = 30 * std.time.ms_per_day;
    try p.initWith(.{ .max_idle_timeout = days }, .{ .max_idle_timeout = days });
    defer p.deinit();
    const sconn = p.mgr.entries.items[0].conn;
    var buf: [MAX_DGRAM]u8 = undefined;
    sconn.pending_frames.push(.ping);
    for (0..20_000) |_| {
        while (try sconn.send(&buf) > 0) {}
        // A timer already due that fired without effect must not spin.
        const now = sys.test_clock.?;
        sys.test_clock = @max(now + std.time.ns_per_us, sconn.nextTimeoutNs() orelse break);
        try sconn.onTimeout();
    }
    const held = sconn.pkt_handler.trackedPackets();
    try testing.expect(held > 100);
    try testing.expect(held <= ack_handler.maxTrackedPackets(sconn.cc.sendWindow(), sconn.cc.max_datagram_size));

    // A probe still goes out at the limit, or a peer whose packets were lost
    // would get nothing to answer; its ACK of that probe frees the rest.
    sys.test_clock = @max(sys.test_clock.? + std.time.ns_per_us, sconn.nextTimeoutNs().?);
    try sconn.onTimeout();
    const m = try sconn.send(&buf);
    try testing.expect(m > 0);
    p.client.handleDatagram(buf[0..m], .{ .to = p.c_addr, .from = p.s_addr, .datagram_size = m });
    sys.test_clock.? += 30 * std.time.ns_per_ms;
    try p.client.onTimeout();
    var resp: [MAX_DGRAM]u8 = undefined;
    while (true) {
        const n = try p.client.send(&buf);
        if (n == 0) break;
        _ = p.mgr.recvDatagram(buf[0..n], p.c_addr, p.s_addr, 0, &resp);
    }
    try testing.expect(sconn.pkt_handler.trackedPackets() < held);
}

/// A server connection opened by one client Initial, from a client never
/// heard from again.
const HalfOpen = struct {
    mgr: connection_manager.ConnectionManager,
    client: *connection.Connection,

    fn init(self: *HalfOpen, server_tls: tls13.TlsConfig) !void {
        const alloc = testing.allocator;
        self.* = .{
            .mgr = connection_manager.ConnectionManager.init(alloc, server_tls, .{}, @splat(1), @splat(2)),
            .client = try alloc.create(connection.Connection),
        };
        errdefer {
            alloc.destroy(self.client);
            self.mgr.deinit();
        }
        try connection.connectInto(self.client, alloc, "localhost", .{}, clientTls(), null);
        self.client.paths[0].peer_addr = addr(4433);
        self.client.paths[0].local_addr = addr(40000);
        var buf: [MAX_DGRAM]u8 = undefined;
        var resp: [MAX_DGRAM]u8 = undefined;
        const n = try self.client.send(&buf);
        _ = self.mgr.recvDatagram(buf[0..n], addr(40000), addr(4433), 0, &resp);
    }

    fn deinit(self: *HalfOpen) void {
        self.client.deinit();
        testing.allocator.destroy(self.client);
        self.mgr.deinit();
    }

    fn server(self: *HalfOpen) *connection.Connection {
        return self.mgr.entries.items[0].conn;
    }
};

test "timers: an ACK alarm due alone takes one onTimeout call" {
    // The alarm stays due until a send carries the ACK: firing timers until
    // no deadline at all has passed would run onTimeout 8 times for it.
    sys.test_clock = 1_000 * std.time.ns_per_s;
    defer sys.test_clock = null;
    const config: connection.ConnectionConfig = .{ .max_datagram_frame_size = 1200, .disable_pmtud = true };
    var p: Pair = undefined;
    try p.initWith(config, config);
    defer p.deinit();
    const sconn = p.mgr.entries.items[0].conn;
    // Everything from the handshake acknowledged, so no PTO is armed.
    for (0..3) |_| {
        sys.test_clock.? += 30 * std.time.ns_per_ms;
        while (p.exchange()) {}
    }
    // A gap would be acknowledged at once, with no alarm.
    p.client.pkt_handler.skip_pn = std.math.maxInt(u64);

    var buf: [MAX_DGRAM]u8 = undefined;
    var resp: [MAX_DGRAM]u8 = undefined;
    try p.client.sendDatagram("input");
    const n = try p.client.send(&buf);
    _ = p.mgr.recvDatagram(buf[0..n], p.c_addr, p.s_addr, 0, &resp);
    try testing.expectEqual(@as(usize, 0), try sconn.send(&buf));
    const alarm = sconn.pkt_handler.recv[2].ack_alarm.?;
    try testing.expectEqual(alarm, sconn.nextTimeoutNsAt(sys.test_clock.?).?);
    try testing.expect(sconn.nextOnTimeoutNs().? > alarm);

    sys.test_clock = alarm;
    try testing.expectEqual(@as(usize, 1), try sconn.fireTimers());
    try testing.expect(try sconn.send(&buf) > 0);
    try testing.expectEqual(@as(?i64, null), sconn.pkt_handler.recv[2].ack_alarm);
}

test "timers: a closing connection waits for its drain, not for an ACK it owes" {
    // Nothing sends that ACK while closing, so the alarm would stay due.
    sys.test_clock = 1_000 * std.time.ns_per_s;
    defer sys.test_clock = null;
    const config: connection.ConnectionConfig = .{ .max_datagram_frame_size = 1200, .disable_pmtud = true };
    var p: Pair = undefined;
    try p.initWith(config, config);
    defer p.deinit();
    const sconn = p.mgr.entries.items[0].conn;
    p.client.pkt_handler.skip_pn = std.math.maxInt(u64);

    var buf: [MAX_DGRAM]u8 = undefined;
    var resp: [MAX_DGRAM]u8 = undefined;
    try p.client.sendDatagram("input");
    const n = try p.client.send(&buf);
    _ = p.mgr.recvDatagram(buf[0..n], p.c_addr, p.s_addr, 0, &resp);
    const alarm = sconn.pkt_handler.recv[2].ack_alarm.?;
    sconn.close(0, "");
    const drained = sconn.closing_start_time + 3 * sconn.pkt_handler.rtt_stats.pto();
    try testing.expect(drained > alarm);
    try testing.expectEqual(drained, sconn.nextTimeoutNsAt(sys.test_clock.?).?);
}

test "PTO: an expiry at the backoff cap fires each handshake space once" {
    // At the cap a fire no longer moved its space's deadline, so one expiry
    // fired up to 8 times and pto_count ran ahead of the probes sent.
    const start: i64 = 1_000 * std.time.ns_per_s;
    sys.test_clock = start;
    defer sys.test_clock = null;
    var h: HalfOpen = undefined;
    try h.init(serverTls());
    defer h.deinit();
    const sconn = h.server();
    var buf: [MAX_DGRAM]u8 = undefined;
    // The server's replies are all lost; past 6 s its probes are at the cap.
    var fires: usize = 0;
    var most: usize = 0;
    while (sys.test_clock.? - start < 9 * std.time.ns_per_s) {
        while (try sconn.send(&buf) > 0) {}
        const now = sconn.nextTimeoutNs() orelse break;
        sys.test_clock = now;
        const before = sconn.pkt_handler.pto_count;
        _ = try sconn.fireTimers();
        try testing.expect(sconn.pkt_handler.pto_count - before <= 2);
        fires += sconn.pkt_handler.pto_count - before;
        most = @max(most, sconn.pkt_handler.pto_count - before);
    }
    try testing.expect(fires >= 10);
    // Both spaces expiring together fire in one pass.
    try testing.expectEqual(@as(usize, 2), most);
}

test "PTO: a server out of amplification budget waits instead of spinning" {
    // Its flight is over 3x the client's Initial, so probes can't go out, and
    // the deadline, counted from the last packet sent, stayed in the past once
    // backed off to the cap: every pass fired again, a busy loop until the
    // handshake timeout. One spoofed Initial was enough.
    const S = struct {
        var secret_key_bytes: [32]u8 = undefined;
        var pub_key_bytes: [65]u8 = undefined;
        var intermediate: [6000]u8 = @splat(0x30);
        var cert_chain: [2][]const u8 = undefined;
        var alpn: [1][]const u8 = .{"bulk"};
    };
    const kp = EcdsaP256Sha256.KeyPair.generate(testing.io);
    S.secret_key_bytes = kp.secret_key.toBytes();
    S.pub_key_bytes = kp.public_key.toUncompressedSec1();
    S.cert_chain = .{ &S.pub_key_bytes, &S.intermediate };

    const start: i64 = 1_000 * std.time.ns_per_s;
    sys.test_clock = start;
    defer sys.test_clock = null;
    var h: HalfOpen = undefined;
    try h.init(.{ .cert_chain_der = &S.cert_chain, .private_key_bytes = &S.secret_key_bytes, .alpn = &S.alpn });
    defer h.deinit();
    const sconn = h.server();
    const budget = 3 * sconn.paths[0].bytes_received;
    var buf: [MAX_DGRAM]u8 = undefined;
    var passes: usize = 0;
    while (!sconn.isClosed()) : (passes += 1) {
        try testing.expect(passes < 100);
        while (try sconn.send(&buf) > 0) {}
        const now = @max(sconn.nextTimeoutNs() orelse break, sys.test_clock.? + std.time.ns_per_us);
        sys.test_clock = now;
        _ = try sconn.fireTimers();
    }
    try testing.expect(sconn.paths[0].bytes_sent > budget - 100 and sconn.paths[0].bytes_sent <= budget);
    try testing.expect(sys.test_clock.? - start >= 10 * std.time.ns_per_s);
}

test "PTO: a client sends no Application Data probe before the handshake is confirmed" {
    // RFC 9002 6.2.1. Its 1-RTT data goes out with its Finished, and until
    // HANDSHAKE_DONE it is the Handshake PTO that probes, resending both.
    const alloc = testing.allocator;
    const start: i64 = 1_000 * std.time.ns_per_s;
    sys.test_clock = start;
    defer sys.test_clock = null;
    var mgr = connection_manager.ConnectionManager.init(alloc, serverTls(), .{}, @splat(1), @splat(2));
    defer mgr.deinit();
    const client = try alloc.create(connection.Connection);
    defer alloc.destroy(client);
    try connection.connectInto(client, alloc, "localhost", .{}, clientTls(), null);
    defer client.deinit();
    client.paths[0].peer_addr = addr(4433);
    client.paths[0].local_addr = addr(40000);

    var buf: [MAX_DGRAM]u8 = undefined;
    var resp: [MAX_DGRAM]u8 = undefined;
    const n = try client.send(&buf);
    _ = mgr.recvDatagram(buf[0..n], addr(40000), addr(4433), 0, &resp);
    while (true) {
        const m = try mgr.entries.items[0].conn.send(&buf);
        if (m == 0) break;
        client.handleDatagram(buf[0..m], .{ .to = addr(40000), .from = addr(4433), .datagram_size = m });
    }
    try testing.expect(client.isEstablished() and !client.handshake_confirmed);
    const s = try client.openStream();
    try s.send.writeData("sent with the Finished");

    // Everything the client sends from here on is lost.
    const app = @backingInt(ack_handler.EncLevel.application);
    while (sys.test_clock.? - start < 3 * std.time.ns_per_s) {
        while (try client.send(&buf) > 0) {}
        sys.test_clock = client.nextTimeoutNs() orelse break;
        try client.onTimeout();
    }
    try testing.expect(client.pkt_handler.sent[app].ack_eliciting_in_flight > 0);
    try testing.expectEqual(@as(u32, 0), client.pkt_handler.sent[app].pto_count);
    try testing.expect(client.pkt_handler.sent[@backingInt(ack_handler.EncLevel.handshake)].pto_count > 0);
}

test "idle timeout: a peer gone with a packet in flight is waited out, not spun on" {
    // While a packet is unacknowledged, onTimeout() stretches the idle timeout
    // to cover the probes' backoff. The deadline handed to the loop didn't, so
    // from the plain timeout on every pass was due and did nothing.
    sys.test_clock = 1_000 * std.time.ns_per_s;
    defer sys.test_clock = null;
    var p: Pair = undefined;
    try p.initWith(.{ .max_idle_timeout = 200 }, .{ .max_idle_timeout = 200 });
    defer p.deinit();
    const sconn = p.mgr.entries.items[0].conn;
    sconn.pending_frames.push(.ping);
    var buf: [MAX_DGRAM]u8 = undefined;
    var passes: usize = 0;
    while (!sconn.isClosed()) : (passes += 1) {
        try testing.expect(passes < 100);
        while (try sconn.send(&buf) > 0) {} // the peer is gone
        const now = @max(sconn.nextTimeoutNs() orelse break, sys.test_clock.? + std.time.ns_per_us);
        sys.test_clock = now;
        _ = try sconn.fireTimers();
    }
    try testing.expect(sconn.isClosed());
}

test "PTO: a server's probes carry its ServerHello" {
    // Both probes of a PTO resend the server's in-flight CRYPTO. The first
    // left the ServerHello out, as a client with Handshake keys may; a server
    // has them before its client has seen any. Losing the second then cost a
    // round trip. The client's own retransmissions are lost too, so only the
    // server's probes can help.
    const c2s: Link.Loss = .{ .periodic = .{ .period = 1 << 60, .burst = 3, .phase = (1 << 60) - 1 } };
    const r = try runBulk(1000, c2s, .{ .periodic = .{ .period = 2, .burst = 1 } }, 50 * ms, 10 * std.time.ns_per_s);
    try testing.expect(r.finished);
    try testing.expect(r.elapsed_ns <= 400 * ms);
}

test "migration: a new address gets its PATH_CHALLENGE with the old path's packets still held" {
    // An IP change resets the window, and the old path's packets still
    // filled it, and the record limit sized from it: the challenge waited,
    // and the server's first packet to the new address carried only an ACK.
    sys.test_clock = 1_000 * std.time.ns_per_s;
    defer sys.test_clock = null;
    var p: Pair = undefined;
    try p.init();
    defer p.deinit();
    const sconn = p.mgr.entries.items[0].conn;
    const mds = sconn.cc.max_datagram_size;
    sconn.cc.congestion_window = 2000 * mds;
    var buf: [MAX_DGRAM]u8 = undefined;
    for (0..1100) |_| {
        sconn.pending_frames.push(.ping);
        while (try sconn.send(&buf) > 0) {}
        sys.test_clock.? += std.time.ns_per_ms;
    }
    const fresh = congestion.Cubic.init().sendWindow();
    try testing.expect(sconn.pkt_handler.bytes_in_flight > fresh + 2 * mds);
    try testing.expect(sconn.pkt_handler.trackedPackets() > ack_handler.maxTrackedPackets(fresh, mds));

    var moved = addr(40000);
    const in: *posix.sockaddr.in = @ptrCast(@alignCast(&moved));
    in.addr = std.mem.nativeToBig(u32, 0x7f000002);
    p.client.pending_frames.push(.ping);
    const n = try p.client.send(&buf);
    var resp: [MAX_DGRAM]u8 = undefined;
    _ = p.mgr.recvDatagram(buf[0..n], moved, p.s_addr, 0, &resp);

    const m = try sconn.send(&buf);
    try testing.expect(m > 0);
    p.client.handleDatagram(buf[0..m], .{ .to = moved, .from = p.s_addr, .datagram_size = m });
    var answered = false;
    for (p.client.pending_frames.queued()) |f| answered = answered or f == .path_response;
    try testing.expect(answered);
}

test "qlog: every packet the server sends is traced once, as its own type" {
    // One event per datagram, numbered after the highest space with keys:
    // coalesced packets went untraced, a Handshake packet sent once 1-RTT
    // keys existed was logged as the last 1-RTT one, and a CONNECTION_CLOSE
    // never appeared.
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var dir_buf: [64]u8 = undefined;
    const dir = try std.fmt.bufPrint(&dir_buf, ".zig-cache/tmp/{s}", .{tmp.sub_path});
    var p: Pair = undefined;
    try p.initWith(.{ .qlog_dir = dir }, .{});
    defer p.deinit();
    for (0..10) |_| {
        p.client.pending_frames.push(.ping);
        _ = p.exchange();
    }
    const sconn = p.mgr.entries.items[0].conn;
    sconn.close(0, "");
    var buf: [MAX_DGRAM]u8 = undefined;
    _ = try sconn.send(&buf);

    // Written as it happens, so readable before the connection closes.
    var path_buf: [128]u8 = undefined;
    const path = try std.fmt.bufPrint(&path_buf, "{s}/{x}_server.sqlog", .{ dir, p.client.odcid_buf[0..p.client.odcid_len] });
    const trace = try sys.readFileAlloc(testing.allocator, path, 1 << 20);
    defer testing.allocator.free(trace);
    const sent = "\"transport:packet_sent\",\"data\":{\"header\":{\"packet_type\":";
    const handler = &sconn.pkt_handler;
    var skipped: u64 = 0;
    for (handler.skipped_pns) |pn| skipped += @intFromBool(pn != null);
    try testing.expectEqual(handler.next_pn[0], std.mem.count(u8, trace, sent ++ "\"initial\""));
    try testing.expectEqual(handler.next_pn[1], std.mem.count(u8, trace, sent ++ "\"handshake\""));
    try testing.expectEqual(handler.next_pn[2] - skipped, std.mem.count(u8, trace, sent ++ "\"1RTT\""));
}

test "stateless reset: a client whose server lost the connection drains" {
    sys.test_clock = 1_000 * std.time.ns_per_s;
    defer sys.test_clock = null;
    var p: Pair = undefined;
    try p.init();
    defer p.deinit();

    p.mgr.removeConnection(p.mgr.entries.items[0]);

    const s = try p.client.openStream();
    try s.send.writeData(&@as([64]u8, @splat('x')));
    var buf: [MAX_DGRAM]u8 = undefined;
    var resp: [MAX_DGRAM]u8 = undefined;
    const n = try p.client.send(&buf);
    const reset = switch (p.mgr.recvDatagram(buf[0..n], p.c_addr, p.s_addr, 0, &resp)) {
        .send_response => |r| r,
        else => return error.TestUnexpectedResult,
    };
    p.client.handleDatagram(@constCast(reset), .{ .to = p.c_addr, .from = p.s_addr, .datagram_size = reset.len });
    try testing.expect(p.client.isDraining());
    try testing.expect(p.client.received_stateless_reset);
    try testing.expectEqual(@as(usize, 0), try p.client.send(&buf));
}

test "stateless reset: the server drains a connection its client reset" {
    sys.test_clock = 1_000 * std.time.ns_per_s;
    defer sys.test_clock = null;
    var p: Pair = undefined;
    try p.init();
    defer p.deinit();

    // A token the client issued in NEW_CONNECTION_ID; the reset's DCID is random.
    const token = for (&p.client.local_cid_pool.entries) |*e| {
        if (e.occupied and e.seq_num > 0) break e.stateless_reset_token;
    } else return error.TestUnexpectedResult;
    var reset: [48]u8 = undefined;
    sys.randomBytes(&reset);
    reset[0] = 0x40 | (reset[0] & 0x3f);
    @memcpy(reset[reset.len - stateless_reset.TOKEN_LEN ..], &token);

    var resp: [MAX_DGRAM]u8 = undefined;
    const entry = p.mgr.entries.items[0];
    const sconn = entry.conn;
    // As a pass leaves it, with nothing to look at.
    entry.needs_visit = false;
    entry.needs_poll = false;
    p.mgr.settleVisits();
    try testing.expect(p.mgr.recvDatagram(&reset, p.c_addr, p.s_addr, 0, &resp) == .processed);
    try testing.expect(sconn.isDraining());
    try testing.expect(sconn.received_stateless_reset);
    // Draining ends on a deadline only a visit puts in the timers.
    try testing.expect(entry.queued and entry.needs_visit);
}

const packet = @import("packet.zig");
const io = @import("../io_compat.zig");

/// Where the first short-header packet of a datagram starts: its length if
/// it has none.
fn shortHeaderStart(bytes: []u8) !usize {
    var pos: usize = 0;
    while (pos < bytes.len and bytes[pos] & 0x80 != 0) {
        var r = io.fixedBufferStream(bytes[pos..]);
        const h = try packet.Header.parse(&r, 0);
        pos += r.seek + h.remainder_len;
    }
    return pos;
}

test "handshake: the server holds 1-RTT packets until the client's Finished" {
    // RFC 9001 5.7: before it, the client is not authenticated. Held, they
    // are stamped when they are read in the end, not when they arrived.
    sys.test_clock = 1_000 * std.time.ns_per_s;
    defer sys.test_clock = null;
    const alloc = testing.allocator;
    var mgr = connection_manager.ConnectionManager.init(alloc, serverTls(), .{}, @splat(1), @splat(2));
    defer mgr.deinit();
    const client = try alloc.create(connection.Connection);
    defer alloc.destroy(client);
    try connection.connectInto(client, alloc, "localhost", .{}, .{
        .cert_chain_der = &.{},
        .private_key_bytes = &.{},
        .alpn = &client_alpn,
        .server_name = "localhost",
        .skip_cert_verify = true,
    }, null);
    defer client.deinit();
    const c_addr = addr(40000);
    const s_addr = addr(4433);
    client.paths[0].peer_addr = s_addr;
    client.paths[0].local_addr = c_addr;

    var buf: [MAX_DGRAM]u8 = undefined;
    var resp: [MAX_DGRAM]u8 = undefined;
    var i: usize = 0;
    while (!client.isEstablished() and i < 20) : (i += 1) {
        while (true) {
            const n = client.send(&buf) catch break;
            if (n == 0) break;
            _ = mgr.recvDatagram(buf[0..n], c_addr, s_addr, 0, &resp);
        }
        for (mgr.entries.items) |e| while (true) {
            const n = e.conn.send(&buf) catch break;
            if (n == 0) break;
            client.handleDatagram(buf[0..n], .{ .to = c_addr, .from = s_addr, .datagram_size = n });
        };
    }
    const sconn = mgr.entries.items[0].conn;
    try testing.expect(client.isEstablished() and !sconn.isEstablished());

    const s = try client.openStream();
    try s.send.writeData("before Finished");
    var dgrams: [4][MAX_DGRAM]u8 = undefined;
    var lens: [4]usize = undefined;
    var count: usize = 0;
    while (count < dgrams.len) : (count += 1) {
        lens[count] = try client.send(&dgrams[count]);
        if (lens[count] == 0) break;
    }
    // 1-RTT parts first: the server must not act on them yet.
    mgr.recv_time = sys.test_clock.?;
    for (dgrams[0..count], lens[0..count]) |*d, n| {
        const at = try shortHeaderStart(d[0..n]);
        if (at < n) _ = mgr.recvDatagram(d[at..n], c_addr, s_addr, 0, &resp);
    }
    try testing.expect(sconn.streams.getStream(s.stream_id) == null);

    // The Finished completes the handshake, and what was held is read then.
    sys.test_clock.? += std.time.ns_per_s;
    mgr.recv_time = sys.test_clock.? - 2 * std.time.ns_per_ms;
    for (dgrams[0..count], lens[0..count]) |*d, n| {
        const at = try shortHeaderStart(d[0..n]);
        if (at > 0) _ = mgr.recvDatagram(d[0..at], c_addr, s_addr, 0, &resp);
    }
    try testing.expect(sconn.isEstablished());
    try testing.expect(sconn.streams.getStream(s.stream_id) != null);
    try testing.expectEqual(sys.test_clock.?, sconn.last_packet_received_time);

    // Read at a time its reader gives, a packet is stamped with that.
    try s.send.writeData("after");
    const n = try client.send(&buf);
    mgr.recv_time = sys.test_clock.? - std.time.ns_per_ms;
    _ = mgr.recvDatagram(buf[0..n], c_addr, s_addr, 0, &resp);
    try testing.expectEqual(mgr.recv_time.?, sconn.last_packet_received_time);
}

/// Sends `data` on a new stream from `sender`, runs the pair until quiet, and
/// says whether `receiver` read all of it.
fn sendAndRead(p: *Pair, sender: *connection.Connection, receiver: *connection.Connection, data: []const u8) !bool {
    const s = try sender.openStream();
    try s.send.writeData(data);
    s.send.close();
    var i: usize = 0;
    while (i < 50 and p.exchange()) : (i += 1) {}
    // A lone packet is acknowledged once max_ack_delay is up.
    sys.test_clock.? += 25 * std.time.ns_per_ms;
    while (i < 50 and p.exchange()) : (i += 1) {}
    const r = receiver.streams.getStream(s.stream_id) orelse return false;
    var got: usize = 0;
    while (r.recv.read()) |d| {
        got += d.len;
        testing.allocator.free(d);
    }
    return got == data.len and r.recv.finished;
}

test "key update: a peer's second update right after its first is still read" {
    // OpenSSL updates again as soon as its first update is acknowledged: the
    // flipped phase then comes from the next keys, not from stragglers on the
    // previous ones, and has to be read.
    sys.test_clock = 1_000 * std.time.ns_per_s;
    defer sys.test_clock = null;
    for ([_]bool{ true, false }) |client_initiates| {
        var p: Pair = undefined;
        try p.init();
        defer p.deinit();
        const sconn = p.mgr.entries.items[0].conn;
        const initiator = if (client_initiates) p.client else sconn;
        const responder = if (client_initiates) sconn else p.client;
        try testing.expect(initiator.initiateKeyUpdate());
        try testing.expect(try sendAndRead(&p, initiator, responder, "first"));
        try testing.expect(initiator.initiateKeyUpdate());
        try testing.expect(try sendAndRead(&p, initiator, responder, "second"));
    }
}

test "key update: a peer's next update after a quiet spell is still read" {
    // The previous keys are long expired, but nothing arrived to discard them.
    sys.test_clock = 1_000 * std.time.ns_per_s;
    defer sys.test_clock = null;
    for ([_]bool{ true, false }) |client_initiates| {
        var p: Pair = undefined;
        try p.init();
        defer p.deinit();
        const sconn = p.mgr.entries.items[0].conn;
        const initiator = if (client_initiates) p.client else sconn;
        const responder = if (client_initiates) sconn else p.client;
        try testing.expect(initiator.initiateKeyUpdate());
        try testing.expect(try sendAndRead(&p, initiator, responder, "first"));
        sys.test_clock.? += 10 * std.time.ns_per_s;
        try testing.expect(initiator.initiateKeyUpdate());
        try testing.expect(try sendAndRead(&p, initiator, responder, "second"));
    }
}

test "key update: a packet sent before an update and delivered after it still opens" {
    sys.test_clock = 1_000 * std.time.ns_per_s;
    defer sys.test_clock = null;
    var p: Pair = undefined;
    try p.init();
    defer p.deinit();
    const sconn = p.mgr.entries.items[0].conn;

    const early = try p.client.openStream();
    try early.send.writeData("early");
    early.send.close();
    var held: [MAX_DGRAM]u8 = undefined;
    const n = try p.client.send(&held);
    try testing.expect(n > 0);

    try testing.expect(p.client.initiateKeyUpdate());
    try testing.expect(try sendAndRead(&p, p.client, sconn, "late"));

    var resp: [MAX_DGRAM]u8 = undefined;
    _ = p.mgr.recvDatagram(held[0..n], p.c_addr, p.s_addr, 0, &resp);
    const r = sconn.streams.getStream(early.stream_id) orelse return error.TestUnexpectedResult;
    const d = r.recv.read() orelse return error.TestUnexpectedResult;
    defer testing.allocator.free(d);
    try testing.expectEqualStrings("early", d);
}

test "handshake: a client that sends no key share is asked for one, and connects" {
    // RFC 8446 4.1.4 over QUIC: the HelloRetryRequest and the second
    // ClientHello both travel in Initial packets.
    sys.test_clock = 1_000 * std.time.ns_per_s;
    defer sys.test_clock = null;
    var client_tls = clientTls();
    client_tls.key_share_groups = &.{};
    var p: Pair = undefined;
    try p.initTls(serverTls(), .{}, .{}, client_tls);
    defer p.deinit();
    const sconn = p.mgr.entries.items[0].conn;
    try testing.expect(p.client.tls13_hs.?.hrr_seen);
    try testing.expect(sconn.isEstablished()); // a server lets its handshake state go
    try testing.expect(try sendAndRead(&p, p.client, sconn, "after a retry"));
}

test "handshake: 0-RTT sent before a HelloRetryRequest still arrives, as 1-RTT" {
    // The retry rejects 0-RTT (RFC 8446 4.2.10), so the client stops sending
    // it and resends what it had sent once the handshake completes.
    sys.test_clock = 1_000 * std.time.ns_per_s;
    defer sys.test_clock = null;
    const alloc = testing.allocator;
    var server_tls = serverTls();
    server_tls.ticket_key = @splat(7);
    var client_tls = clientTls();

    const ticket = blk: {
        var first: Pair = undefined;
        try first.initTls(server_tls, .{}, .{}, client_tls);
        defer first.deinit();
        var i: usize = 0;
        while (i < 10 and first.exchange()) : (i += 1) {}
        break :blk first.client.session_ticket orelse return error.TestUnexpectedResult;
    };

    client_tls.session_ticket = &ticket;
    client_tls.key_share_groups = &.{};
    var p: Pair = .{
        .mgr = connection_manager.ConnectionManager.init(alloc, server_tls, .{}, @splat(1), @splat(2)),
        .client = try alloc.create(connection.Connection),
    };
    try connection.connectInto(p.client, alloc, "localhost", .{}, client_tls, null);
    defer p.deinit();
    p.client.paths[0].peer_addr = p.s_addr;
    p.client.paths[0].local_addr = p.c_addr;
    try testing.expect(p.client.early_data_seal != null);

    const s = try p.client.openStream();
    try s.send.writeData("sent as 0-RTT");
    s.send.close();
    // One round: the first ClientHello and the 0-RTT out, the retry back.
    try testing.expect(p.exchange());
    try testing.expect(p.client.tls13_hs.?.hrr_seen and !p.client.isEstablished());
    try testing.expect(p.client.early_data_seal == null);
    var i: usize = 0;
    while (i < 50 and p.exchange()) : (i += 1) {}
    try testing.expect(p.client.tls13_hs.?.using_psk);
    const r = p.mgr.entries.items[0].conn.streams.getStream(s.stream_id) orelse return error.TestUnexpectedResult;
    const d = r.recv.read() orelse return error.TestUnexpectedResult;
    defer alloc.free(d);
    try testing.expectEqualStrings("sent as 0-RTT", d);
    try testing.expect(r.recv.read() == null and r.recv.finished);
}

/// A client whose server never answers, driven like an application loop
/// that calls onTimeout() every `tick_ns` whether or not a timer is due.
/// Returns how many datagrams it sent in [from_ns, to_ns), and when it
/// closed (null if it never did before `to_ns`).
fn silentServer(config: connection.ConnectionConfig, tick_ns: i64, from_ns: i64, to_ns: i64) !struct { sent: usize, closed_at: ?i64 } {
    const alloc = testing.allocator;
    const start: i64 = 1_000 * std.time.ns_per_s;
    sys.test_clock = start;
    defer sys.test_clock = null;

    // The idle timer and the probes are under test, not a handshake deadline.
    var cfg = config;
    if (@hasField(connection.ConnectionConfig, "handshake_timeout")) cfg.handshake_timeout = 0;

    const client = try alloc.create(connection.Connection);
    defer alloc.destroy(client);
    try connection.connectInto(client, alloc, "localhost", cfg, .{
        .cert_chain_der = &.{},
        .private_key_bytes = &.{},
        .alpn = &client_alpn,
        .server_name = "localhost",
        .skip_cert_verify = true,
    }, null);
    defer client.deinit();
    client.paths[0].peer_addr = addr(4433);
    client.paths[0].local_addr = addr(40000);

    var buf: [MAX_DGRAM]u8 = undefined;
    var sent: usize = 0;
    var now = start;
    while (now - start < to_ns) {
        client.onTimeout() catch {};
        if (client.isClosed()) return .{ .sent = sent, .closed_at = now - start };
        while (true) {
            const n = client.send(&buf) catch break;
            if (n == 0) break;
            if (now - start >= from_ns) sent += 1;
        }
        now += if (tick_ns > 0) tick_ns else @max(std.time.ns_per_us, (client.nextTimeoutNs() orelse now) - now);
        sys.test_clock = now;
    }
    return .{ .sent = sent, .closed_at = null };
}

test "handshake: a client that hears nothing gives up at its idle timeout" {
    // RFC 9000 10.1: only the first ack-eliciting packet after one received
    // restarts the idle timer. Restarting it on every probe would keep a
    // client facing silence alive forever.
    const r = try silentServer(.{}, 0, 0, 120 * std.time.ns_per_s);
    try testing.expect(r.closed_at != null);
    try testing.expect(r.closed_at.? <= 31 * std.time.ns_per_s);
}

test "handshake: a client polled every millisecond through a stalled handshake does not flood" {
    // Probes back off however old the handshake is. A deadline counted from
    // the connection's creation, its backoff capped at 60 s, would probe on
    // every onTimeout() from then on: ~38,000 datagrams a second.
    const r = try silentServer(.{ .max_idle_timeout = 300_000 }, std.time.ns_per_ms, 60 * std.time.ns_per_s, 75 * std.time.ns_per_s);
    try testing.expect(r.closed_at == null);
    try testing.expect(r.sent <= 20);
}

test "idle timeout: a peer's value too large for nanoseconds is capped" {
    // With ours disabled (0) the peer's is used alone.
    sys.test_clock = 1_000 * std.time.ns_per_s;
    defer sys.test_clock = null;
    for ([_]u64{ std.math.maxInt(i64) / std.time.ns_per_ms, (1 << 62) - 1 }) |peer_ms| {
        var p: Pair = undefined;
        try p.initWith(.{ .max_idle_timeout = 0 }, .{ .max_idle_timeout = peer_ms });
        defer p.deinit();
        const sconn = p.mgr.entries.items[0].conn;
        try testing.expect(sconn.nextTimeoutNs() != null);
        try sconn.onTimeout();
        try testing.expect(!sconn.isClosed());
    }
}
