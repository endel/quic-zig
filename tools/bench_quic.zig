//! In-process QUIC benchmark: a client `Connection` and a server
//! `ConnectionManager` wired back to back, no sockets, on the virtual clock
//! (`sys.test_clock`, which only test builds have, hence the test blocks).
//! It times the CPU a connection costs: packing, sealing and opening packets,
//! ACK and loss bookkeeping, timers, and the datagram queues or stream
//! buffers. Syscalls and the event loop are left out; measure those end to
//! end.
//!
//! Each round the server queues its traffic and the client its own, both
//! sides send everything they have (client first) and read what arrived, then
//! the clock advances 5 ms and due timers fire, as the event loop fires them.
//! Scenarios, `rounds` rounds each after an untimed handshake:
//!   datagrams  server 7 × 64 B datagrams, client 1 × 32 B: a relay's fan-out
//!              against one player's input.
//!   streams    the same sizes as writes on one bidi stream: reliable
//!              messages on a control stream.
//!
//! Time is the thread's CPU time over the rounds, so other load on the
//! machine skews it less than it would wall time. One line per scenario goes
//! to stdout, the test runner's own lines to stderr:
//!   scenario=datagrams ns_per_round=1070 rounds=400000 datagrams=3200000
//!   scenario=streams ns_per_round=1115 rounds=400000 bytes=192000000
//! A scenario fails if anything sent went undelivered, so two trees that pass
//! did the same work.
//!
//! Run: `zig build bench-quic`. Always ReleaseFast, whatever -Doptimize says;
//! `zig build test` doesn't run it.
//!
//! A/B two trees by alternating runs, so drift in the machine's state lands
//! on both. With the step in both trees (builds are cached after the first):
//!   for i in 1 2 3 4 5; do (cd a && zig build bench-quic); (cd b && zig build bench-quic); done 2>/dev/null
//! Or build a binary from each, copying this file into a tree that predates it:
//!   zig test -OReleaseFast -lc --test-no-exec -femit-bin=/tmp/bench-a \
//!     --dep quic -Mroot=tools/bench_quic.zig -OReleaseFast -Mquic=src/lib.zig
//!   for i in 1 2 3 4 5; do /tmp/bench-a; /tmp/bench-b; done 2>/dev/null
//!
//! Noise: on an M-series Mac, five runs land within ±1% of each other
//! (±2% with other work on the machine); end-to-end runs of a server under
//! load vary by ±10%. A gap past 3% between alternating runs is not noise.

const std = @import("std");
const posix = std.posix;
const testing = std.testing;
const quic = @import("quic");
const sys = quic.sys;
const connection = quic.connection;
const connection_manager = quic.connection_manager;
const tls13 = quic.tls13;

const EcdsaP256Sha256 = std.crypto.sign.ecdsa.EcdsaP256Sha256;

const rounds = 400_000;
const tick_ns = 5 * std.time.ns_per_ms;
const MAX_DGRAM = 1500;

/// A server's allocator, not the test runner's leak-checking one.
const alloc = std.heap.smp_allocator;

const config: connection.ConnectionConfig = .{ .max_datagram_frame_size = 1200, .max_idle_timeout = 1_000_000 };
const alpn = [_][]const u8{"bench"};

fn addr(port: u16) posix.sockaddr.storage {
    var st = std.mem.zeroes(posix.sockaddr.storage);
    const in: *posix.sockaddr.in = @ptrCast(@alignCast(&st));
    in.* = .{ .port = std.mem.nativeToBig(u16, port), .addr = std.mem.nativeToBig(u32, 0x7f000001) };
    return st;
}

const c_addr = addr(40000);
const s_addr = addr(4433);

fn serverTls() !tls13.TlsConfig {
    const S = struct {
        var secret_key_bytes: [32]u8 = undefined;
        var pub_key_bytes: [65]u8 = undefined;
        var cert_chain: [1][]const u8 = undefined;
    };
    const kp = try EcdsaP256Sha256.KeyPair.generateDeterministic(@splat(1));
    S.secret_key_bytes = kp.secret_key.toBytes();
    S.pub_key_bytes = kp.public_key.toUncompressedSec1();
    S.cert_chain = .{&S.pub_key_bytes};
    return .{ .cert_chain_der = &S.cert_chain, .private_key_bytes = &S.secret_key_bytes, .alpn = &alpn };
}

/// A client and the server connection it opened, handshake confirmed.
const Pair = struct {
    mgr: connection_manager.ConnectionManager,
    client: *connection.Connection,

    fn init(self: *Pair) !void {
        self.* = .{
            .mgr = connection_manager.ConnectionManager.init(alloc, try serverTls(), config, @splat(1), @splat(2)),
            .client = try alloc.create(connection.Connection),
        };
        try connection.connectInto(self.client, alloc, "localhost", config, .{
            .cert_chain_der = &.{},
            .private_key_bytes = &.{},
            .alpn = &alpn,
            .server_name = "localhost",
            .skip_cert_verify = true,
        }, null);
        self.client.paths[0].peer_addr = s_addr;
        self.client.paths[0].local_addr = c_addr;
        for (0..50) |_| self.round();
        try testing.expect(self.client.handshake_confirmed and self.client.datagrams_enabled);
    }

    fn deinit(self: *Pair) void {
        self.client.deinit();
        alloc.destroy(self.client);
        self.mgr.deinit();
    }

    fn server(self: *Pair) *connection.Connection {
        return self.mgr.entries.items[0].conn;
    }

    /// Both sides send all they have, then the clock moves on a tick.
    fn round(self: *Pair) void {
        var buf: [MAX_DGRAM]u8 = undefined;
        var resp: [MAX_DGRAM]u8 = undefined;
        while (true) {
            const n = self.client.send(&buf) catch break;
            if (n == 0) break;
            _ = self.mgr.recvDatagram(buf[0..n], c_addr, s_addr, 0, &resp);
        }
        const sconn = self.server();
        while (true) {
            const n = sconn.send(&buf) catch break;
            if (n == 0) break;
            self.client.handleDatagram(buf[0..n], .{ .to = c_addr, .from = s_addr, .datagram_size = n });
        }
        sys.test_clock.? += tick_ns;
        const now = sys.test_clock.?;
        for ([_]*connection.Connection{ self.client, sconn }) |conn| {
            if (conn.nextTimeoutNs()) |t| if (t <= now) conn.onTimeout() catch {};
        }
    }
};

fn threadCpuNs() i64 {
    var ts: std.c.timespec = undefined;
    _ = std.c.clock_gettime(std.c.CLOCK.THREAD_CPUTIME_ID, &ts);
    return @as(i64, ts.sec) * std.time.ns_per_s + ts.nsec;
}

fn report(scenario: []const u8, elapsed_ns: i64, unit: []const u8, delivered: u64) !void {
    var line: [160]u8 = undefined;
    const s = try std.fmt.bufPrint(&line, "scenario={s} ns_per_round={d} rounds={d} {s}={d}\n", .{
        scenario, @divTrunc(elapsed_ns, rounds), rounds, unit, delivered,
    });
    try std.Io.File.stdout().writeStreamingAll(testing.io, s);
}

test "datagrams" {
    sys.test_clock = 1_000 * std.time.ns_per_s;
    defer sys.test_clock = null;
    var p: Pair = undefined;
    try p.init();
    defer p.deinit();
    const sconn = p.server();

    var dgram: [64]u8 = @splat(7);
    var buf: [MAX_DGRAM]u8 = undefined;
    var delivered: u64 = 0;
    const start = threadCpuNs();
    for (0..rounds) |_| {
        for (0..7) |i| {
            dgram[0] = @intCast(i);
            try sconn.sendDatagram(&dgram);
        }
        try p.client.sendDatagram(dgram[0..32]);
        p.round();
        while (p.client.recvDatagram(&buf)) |_| delivered += 1;
        while (sconn.recvDatagram(&buf)) |_| delivered += 1;
    }
    const elapsed = threadCpuNs() - start;
    try testing.expectEqual(@as(u64, rounds * 8), delivered);
    try report("datagrams", elapsed, "datagrams", delivered);
}

test "streams" {
    sys.test_clock = 1_000 * std.time.ns_per_s;
    defer sys.test_clock = null;
    var p: Pair = undefined;
    try p.init();
    defer p.deinit();

    const msg: [64]u8 = @splat(7);
    const cs = try p.client.openStream();
    try cs.send.writeData(msg[0..32]);
    p.round();
    const ss = p.server().streams.getStream(cs.stream_id) orelse return error.StreamNotOpened;
    alloc.free(ss.recv.read() orelse return error.NothingRead);

    var delivered: u64 = 0;
    const start = threadCpuNs();
    for (0..rounds) |_| {
        for (0..7) |_| try ss.send.writeData(&msg);
        try cs.send.writeData(msg[0..32]);
        p.round();
        while (cs.recv.read()) |d| : (alloc.free(d)) delivered += d.len;
        while (ss.recv.read()) |d| : (alloc.free(d)) delivered += d.len;
    }
    const elapsed = threadCpuNs() - start;
    try testing.expectEqual(@as(u64, rounds * (7 * 64 + 32)), delivered);
    try report("streams", elapsed, "bytes", delivered);
}
