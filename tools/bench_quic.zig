//! In-process QUIC benchmark: a client `Connection` and a server
//! `ConnectionManager` wired back to back, no sockets, on the virtual clock
//! (`sys.test_clock`, which only test builds have, hence the test blocks).
//! It times the CPU a connection costs: packing, sealing and opening packets,
//! ACK and loss bookkeeping, timers, and the datagram queues or stream
//! buffers. Syscalls and the event loop are left out, but for `idle` below;
//! measure the rest end to end.
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
//!   idle       the event loop's cost of what is connected but quiet. A real
//!              `event_loop.Server` on a loopback socket, run on a thread of
//!              its own, holds `idle` connections that finished their
//!              handshakes and went silent, next to one active client. Each
//!              round the client sends 1 × 32 B datagram and waits for the
//!              server's 7 × 64 B answer, so every round is a wakeup and a
//!              pass. Timed is the server thread's CPU alone, syscalls
//!              included, over `loop_rounds` rounds; run at 0, 1024 and 4096
//!              idle connections, the difference is what a pass spends on
//!              connections with nothing to do.
//!
//! Time is the thread's CPU time over the rounds, so other load on the
//! machine skews it less than it would wall time. One line per scenario goes
//! to stdout, the test runner's own lines to stderr:
//!   scenario=datagrams ns_per_round=1070 rounds=400000 datagrams=3200000
//!   scenario=streams ns_per_round=1115 rounds=400000 bytes=192000000
//!   scenario=idle idle=4096 ns_per_round=9000 rounds=20000 datagrams=140000
//! A scenario fails if anything sent went undelivered, so two trees that pass
//! did the same work.
//!
//! Run: `zig build bench-quic`. Always ReleaseFast, whatever -Doptimize says;
//! `zig build test` doesn't run it.
//!
//! A/B two trees by alternating runs, so drift in the machine's state lands
//! on both. With the step in both trees (builds are cached after the first):
//!   for i in 1 2 3 4 5; do (cd a && zig build bench-quic); (cd b && zig build bench-quic); done 2>/dev/null
//! Or build a binary from each, copying this file into a tree that predates it
//! (`$XEV` is the pinned libxev under zig-pkg/):
//!   zig test -OReleaseFast -lc --test-no-exec -femit-bin=/tmp/bench-a \
//!     --dep quic -Mroot=tools/bench_quic.zig -OReleaseFast --dep xev \
//!     -Mquic=src/lib.zig -OReleaseFast -Mxev=$XEV/src/main.zig
//!   for i in 1 2 3 4 5; do /tmp/bench-a; /tmp/bench-b; done 2>/dev/null
//!
//! Noise: on an M-series Mac, five runs land within ±1% of each other
//! (±2% with other work on the machine); end-to-end runs of a server under
//! load vary by ±10%. A gap past 3% between alternating runs is not noise.
//! `idle` goes through the kernel twice a round, so it is noisier than the
//! others: compare its idle counts within a run, and runs by their medians.

const std = @import("std");
const posix = std.posix;
const testing = std.testing;
const quic = @import("quic");
const sys = quic.sys;
const connection = quic.connection;
const connection_manager = quic.connection_manager;
const event_loop = quic.event_loop;
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

// ─── idle: a pass's cost of what is connected but quiet ──────────────────

const loop_rounds = 20_000;
/// Clients connected per step of the setup, so their handshake flights fit
/// the client socket's buffer, which Linux holds to `net.core.rmem_max`.
const setup_batch = 64;
/// The round number that asks the server to stop.
const stop_round = std.math.maxInt(u64);

/// Answers each datagram with seven, as `datagrams` does, and reads its own
/// thread's CPU time at the first measured round and the last.
const Echo = struct {
    pub const protocol: event_loop.Protocol = .quic;
    /// The `IdleServer`, which can't be named in its own handler's fields.
    server: *anyopaque = undefined,
    cpu_first: i64 = 0,
    cpu_last: i64 = 0,
    stopping: bool = false,

    pub fn onDatagram(self: *Echo, s: *event_loop.Session, _: u64, data: []const u8) void {
        const r = std.mem.readInt(u64, data[0..8], .little);
        if (r == stop_round) {
            if (!self.stopping) @as(*IdleServer, @ptrCast(@alignCast(self.server))).stop();
            self.stopping = true;
            return;
        }
        if (r == 0) self.cpu_first = threadCpuNs();
        if (r == loop_rounds - 1) self.cpu_last = threadCpuNs();
        var reply: [64]u8 = @splat(7);
        for (0..7) |i| {
            reply[0] = @intCast(i);
            s.sendQuicDatagram(&reply) catch {};
        }
    }
};

const IdleServer = event_loop.Server(Echo);

/// 127.0.0.1 on a port of the kernel's choosing.
fn loopbackSocket() !struct { posix.socket_t, posix.sockaddr.storage } {
    const fd = try sys.socket(posix.AF.INET, posix.SOCK.DGRAM | posix.SOCK.NONBLOCK, 0);
    errdefer sys.close(fd);
    const any = addr(0);
    try sys.bind(fd, @ptrCast(&any), @sizeOf(posix.sockaddr.in));
    const rcvbuf: c_int = 4 << 20;
    sys.setsockopt(fd, posix.SOL.SOCKET, posix.SO.RCVBUF, std.mem.asBytes(&rcvbuf)) catch {};
    var bound: posix.sockaddr.storage = undefined;
    var len: posix.socklen_t = @sizeOf(posix.sockaddr.storage);
    try sys.getsockname(fd, @ptrCast(&bound), &len);
    return .{ fd, bound };
}

/// Clients sharing one socket; the server tells them apart by CID, and so
/// does `owner` on the way back.
const Clients = struct {
    fd: posix.socket_t,
    local: posix.sockaddr.storage,
    server: posix.sockaddr.storage,
    /// The ones being served. Datagrams for any other are dropped.
    live: std.ArrayList(*connection.Connection) = .empty,

    fn connect(self: *Clients) !*connection.Connection {
        const c = try alloc.create(connection.Connection);
        errdefer alloc.destroy(c);
        try connection.connectInto(c, alloc, "localhost", config, .{
            .cert_chain_der = &.{},
            .private_key_bytes = &.{},
            .alpn = &alpn,
            .server_name = "localhost",
            .skip_cert_verify = true,
        }, null);
        c.paths[0].peer_addr = self.server;
        c.paths[0].local_addr = self.local;
        try self.live.append(alloc, c);
        return c;
    }

    fn dropAll(self: *Clients) void {
        for (self.live.items) |c| {
            c.deinit();
            alloc.destroy(c);
        }
        self.live.clearRetainingCapacity();
    }

    fn owner(self: *Clients, bytes: []const u8) ?*connection.Connection {
        if (bytes.len < 9) return null;
        const dcid = if (bytes[0] & 0x80 != 0) blk: {
            if (bytes.len < 6 or bytes.len < 6 + @as(usize, bytes[5])) return null;
            break :blk bytes[6..][0..bytes[5]];
        } else bytes[1..9];
        for (self.live.items) |c| {
            if (std.mem.eql(u8, c.scid[0..c.scid_len], dcid)) return c;
        }
        return null;
    }

    /// Sends what the clients have, reads what has arrived, waiting up to
    /// `wait_ms` for the first, then fires due timers and sends again.
    fn pump(self: *Clients, wait_ms: c_int) !void {
        self.sendAll();
        var fds = [_]std.c.pollfd{.{ .fd = self.fd, .events = std.c.POLL.IN, .revents = 0 }};
        if (wait_ms > 0) _ = std.c.poll(&fds, 1, wait_ms);
        var buf: [MAX_DGRAM]u8 = undefined;
        while (true) {
            const n = sys.recvfrom(self.fd, &buf, 0, null, null) catch |err| switch (err) {
                error.WouldBlock => break,
                else => return err,
            };
            const c = self.owner(buf[0..n]) orelse continue;
            c.handleDatagram(buf[0..n], .{ .to = self.local, .from = self.server, .datagram_size = n });
        }
        const now = sys.nanoTimestamp();
        for (self.live.items) |c| {
            if (c.nextTimeoutNs()) |t| if (t <= now) c.onTimeout() catch {};
        }
        self.sendAll();
    }

    fn sendAll(self: *Clients) void {
        var buf: [MAX_DGRAM]u8 = undefined;
        for (self.live.items) |c| {
            while (true) {
                const n = c.send(&buf) catch break;
                if (n == 0) break;
                _ = sys.sendto(self.fd, buf[0..n], 0, @ptrCast(&self.server), @sizeOf(posix.sockaddr.in)) catch {};
            }
        }
    }

    /// Runs the server here, beside the clients, until each live one is
    /// connected and the server has nothing in flight to any of them and no
    /// ACK to send: the clients may go, and their connections stay quiet.
    fn handshake(self: *Clients, server: *IdleServer) !void {
        const give_up = sys.nanoTimestamp() + 10 * std.time.ns_per_s;
        var checked_at: i64 = 0;
        while (true) {
            try server.tick();
            try self.pump(0);
            const now = sys.nanoTimestamp();
            if (now > give_up) return error.HandshakesStalled;
            for (self.live.items) |c| {
                if (!c.handshake_confirmed) break;
            } else if (now - checked_at > 5 * std.time.ns_per_ms) {
                if (timersDue(server, 10 * std.time.ns_per_s) == 0) return;
                checked_at = now;
            }
        }
    }
};

/// Server connections with a timer due within `within_ns`: none, once
/// nothing is in flight and no ACK is owed.
fn timersDue(server: *IdleServer, within_ns: i64) usize {
    const horizon = sys.nanoTimestamp() + within_ns;
    var n: usize = 0;
    for (server.conn_mgr.entries.items) |e| {
        if (e.conn.nextTimeoutNs()) |t| if (t < horizon) {
            n += 1;
        };
    }
    return n;
}

fn serve(server: *IdleServer) void {
    server.eventLoop().run(.until_done) catch |err| std.debug.panic("server loop: {any}", .{err});
}

fn idleScenario(idle: usize) !void {
    sys.test_clock = null;
    const sfd, const s_bound = try loopbackSocket();
    var handler: Echo = .{};
    var server = IdleServer.init(alloc, &handler, .{
        .socket = sfd,
        .tls_config = try serverTls(),
        .conn_config = config,
        .max_connections = 2 * idle + 16,
    }) catch |err| {
        sys.close(sfd);
        return err;
    };
    defer server.deinit();
    handler.server = &server;

    const cfd, const c_bound = try loopbackSocket();
    defer sys.close(cfd);
    var clients: Clients = .{ .fd = cfd, .local = c_bound, .server = s_bound };
    defer {
        clients.dropAll();
        clients.live.deinit(alloc);
    }

    // Idle from here on: nothing in flight, nothing owed, the client gone.
    var made: usize = 0;
    while (made < idle) {
        const n = @min(setup_batch, idle - made);
        for (0..n) |_| _ = try clients.connect();
        try clients.handshake(&server);
        clients.dropAll();
        made += n;
    }
    try testing.expectEqual(idle, server.conn_mgr.connectionCount());

    const active = try clients.connect();
    try clients.handshake(&server);

    const thread = try std.Thread.spawn(.{}, serve, .{&server});
    var dgram: [32]u8 = @splat(7);
    var buf: [MAX_DGRAM]u8 = undefined;
    var delivered: u64 = 0;
    for (0..loop_rounds) |r| {
        std.mem.writeInt(u64, dgram[0..8], r, .little);
        try active.sendDatagram(&dgram);
        const want = delivered + 7;
        const give_up = sys.nanoTimestamp() + 2 * std.time.ns_per_s;
        while (delivered < want) {
            try clients.pump(1);
            while (active.recvDatagram(&buf)) |_| delivered += 1;
            if (sys.nanoTimestamp() > give_up) return error.RoundStalled;
        }
    }
    std.mem.writeInt(u64, dgram[0..8], stop_round, .little);
    try active.sendDatagram(&dgram);
    try clients.pump(0);
    thread.join();


    try testing.expectEqual(@as(u64, loop_rounds * 7), delivered);
    var line: [160]u8 = undefined;
    const s = try std.fmt.bufPrint(&line, "scenario=idle idle={d} ns_per_round={d} rounds={d} datagrams={d}\n", .{
        idle, @divTrunc(handler.cpu_last - handler.cpu_first, loop_rounds - 1), loop_rounds, delivered,
    });
    try std.Io.File.stdout().writeStreamingAll(testing.io, s);
}

test "idle" {
    for ([_]usize{ 0, 1024, 4096 }) |idle| try idleScenario(idle);
}
