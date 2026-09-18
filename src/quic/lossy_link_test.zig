//! A client and a server connection wired back to back through a simulated
//! link on a virtual clock, so loss recovery can be tested deterministically
//! and without real time passing.

const std = @import("std");
const posix = std.posix;
const testing = std.testing;
const sys = @import("../sys.zig");
const connection = @import("connection.zig");
const connection_manager = @import("connection_manager.zig");
const tls13 = @import("tls13.zig");

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
};

/// Client uploads `total` bytes on one bidi stream; the server reads as it
/// arrives. Stops when the server has read the FIN, a connection closes, or
/// `limit_ns` of virtual time has passed.
fn runBulk(total: usize, c2s_loss: Link.Loss, s2c_loss: Link.Loss, one_way_ns: i64, limit_ns: i64) !Result {
    const alloc = testing.allocator;
    const start: i64 = 1_000 * std.time.ns_per_s;
    sys.test_clock = start;
    defer sys.test_clock = null;
    var now = start;

    var mgr = connection_manager.ConnectionManager.init(alloc, serverTls(), .{ .qlog_dir = qlog_dir }, .{1} ** 16, .{2} ** 16);
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
    };
}

const ms = std.time.ns_per_ms;

test "lossy link: a clean 4 MiB upload finishes within a second" {
    const r = try runBulk(4 << 20, .none, .none, 10 * ms, 60 * std.time.ns_per_s);
    try testing.expect(r.finished);
    try testing.expect(r.elapsed_ns < std.time.ns_per_s);
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
