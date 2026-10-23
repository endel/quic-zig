//! A live connection moving between two servers on two threads:
//! `Session.handOver`, `Server.adopt`, the CID rotation that follows and the
//! steering that carries its packets meanwhile. Each server listens on a
//! port of its own here, and a relay stands in for the kernel's choice of
//! socket, so a test decides which server a client's packets reach. By
//! default that is the server the connection began on, as with a 4-tuple
//! hash: after a handover every packet has to be forwarded.

const std = @import("std");
const posix = std.posix;
const testing = std.testing;
const sys = @import("sys.zig");
const net = @import("sockaddr.zig");
const event_loop = @import("event_loop.zig");
const quic_lb = @import("quic/quic_lb.zig");
const tls13 = @import("quic/tls13.zig");

const xev = event_loop.Xev;
const Server = event_loop.Server;
const Client = event_loop.Client;
const Session = event_loop.Session;
const ClientSession = event_loop.ClientSession;
const Handover = event_loop.Handover;
const ForeignDatagram = event_loop.ForeignDatagram;
const MovedCids = event_loop.MovedCids;

const gpa = testing.allocator;

fn lbConfig(id: u8) quic_lb.Config {
    var cfg: quic_lb.Config = .{ .config_id = 0, .server_id_len = 1, .nonce_len = 6 };
    cfg.server_id[0] = id;
    return cfg;
}

/// The QUIC-LB server id a CID carries.
fn serverIdOf(cid: []const u8) u8 {
    var id: [1]u8 = undefined;
    if (!quic_lb.extractServerId(&lbConfig(0), cid, &id)) return 0;
    return id[0];
}

fn testTlsConfig() tls13.TlsConfig {
    const S = struct {
        var secret_key_bytes: [32]u8 = undefined;
        var pub_key_bytes: [65]u8 = undefined;
        var cert_chain: [1][]const u8 = undefined;
        var alpn: [1][]const u8 = .{"h3"};
        var ticket_key: [16]u8 = @splat(7);
    };
    const kp = std.crypto.sign.ecdsa.EcdsaP256Sha256.KeyPair.generate(testing.io);
    S.secret_key_bytes = kp.secret_key.toBytes();
    S.pub_key_bytes = kp.public_key.toUncompressedSec1();
    S.cert_chain = .{&S.pub_key_bytes};
    return .{
        .cert_chain_der = &S.cert_chain,
        .private_key_bytes = &S.secret_key_bytes,
        .alpn = &S.alpn,
        .ticket_key = S.ticket_key,
    };
}

const SpinLock = struct {
    held: std.atomic.Value(bool) = .init(false),

    fn lock(self: *SpinLock) void {
        while (self.held.cmpxchgWeak(false, true, .acquire, .monotonic) != null) std.atomic.spinLoopHint();
    }

    fn unlock(self: *SpinLock) void {
        self.held.store(false, .release);
    }
};

/// Echoes stream data and datagrams. "move" on a stream hands the
/// connection to the other server; "move+close" hands it over and closes it
/// in the same breath.
const EchoServer = struct {
    pub const protocol: event_loop.Protocol = .webtransport;

    worker: *Worker = undefined,
    session: ?Session = null,
    handed: std.atomic.Value(u32) = .init(0),
    closed: std.atomic.Value(u32) = .init(0),
    /// The connection asked to move, and events delivered for it after.
    leaving: ?*event_loop.ConnEntry = null,
    late: std.atomic.Value(u32) = .init(0),

    pub fn onConnectRequest(self: *EchoServer, session: *Session, session_id: u64, _: []const u8) void {
        session.acceptSession(session_id) catch unreachable;
        self.session = session.*;
    }

    pub fn onStreamData(self: *EchoServer, session: *Session, stream_id: u64, data: []const u8, fin: bool) void {
        if (self.isLate(session)) return;
        if (std.mem.startsWith(u8, data, "move")) {
            session.handOver(&.{self.worker.other()}) catch unreachable;
            self.leaving = session.entry;
            self.session = null;
            if (std.mem.eql(u8, data, "move+close")) session.closeConnection();
            return;
        }
        if (data.len > 0) session.sendStreamData(stream_id, data) catch {};
        if (fin) session.closeStream(stream_id);
    }

    pub fn onDatagram(self: *EchoServer, session: *Session, session_id: u64, data: []const u8) void {
        if (self.isLate(session)) return;
        // Read as the packet is: whatever came with it is polled after.
        if (std.mem.eql(u8, data, "move")) {
            session.handOver(&.{self.worker.other()}) catch unreachable;
            self.leaving = session.entry;
            self.session = null;
            return;
        }
        session.sendDatagram(session_id, data) catch {};
    }

    pub fn onHandover(self: *EchoServer, h: Handover) void {
        self.leaving = null;
        _ = self.handed.fetchAdd(1, .monotonic);
        self.worker.group.workers[self.worker.other() - 1].push(.{ .handover = h });
    }

    /// Delivered here after the handover was asked for: lost to the new server.
    fn isLate(self: *EchoServer, session: *Session) bool {
        if (self.leaving != session.entry) return false;
        _ = self.late.fetchAdd(1, .monotonic);
        return true;
    }

    pub fn onConnectionClosed(self: *EchoServer, _: *Session) void {
        _ = self.closed.fetchAdd(1, .monotonic);
        self.session = null;
    }
};

/// Work for a worker's thread, in the order it was queued: a connection's
/// handover always comes before the datagrams forwarded to it after.
const Item = union(enum) {
    datagram: struct { bytes: []u8, peer: posix.sockaddr.storage, local: posix.sockaddr.storage, ecn: u2 },
    handover: Handover,
    call: *const fn (*Worker) void,
};

/// A server on its own thread and loop, and the queue its sibling and the
/// test hand it work through.
const Worker = struct {
    id: u8,
    group: *Group,
    handler: EchoServer = .{},
    server: Server(EchoServer) = undefined,
    wakeup: xev.Async = undefined,
    wakeup_c: xev.Completion = .{},
    thread: std.Thread = undefined,

    lock: SpinLock = .{},
    queue: std.ArrayList(Item) = .empty,
    /// Leave the queue be: a handover waits in it.
    held: std.atomic.Value(bool) = .init(false),
    quit: std.atomic.Value(bool) = .init(false),
    adopted: std.atomic.Value(u32) = .init(0),
    injected: std.atomic.Value(u32) = .init(0),
    /// Set by `call`s, read by the test.
    connections: std.atomic.Value(usize) = .init(0),
    peer_port: std.atomic.Value(u16) = .init(0),
    /// The connection's wakeups, header buffers and datagrams are this
    /// server's, not the one it came from.
    owns_hooks: std.atomic.Value(bool) = .init(false),

    fn other(self: *const Worker) u8 {
        return 3 - self.id;
    }

    /// Any thread.
    fn push(self: *Worker, item: Item) void {
        self.lock.lock();
        self.queue.append(gpa, item) catch unreachable;
        self.lock.unlock();
        self.wakeup.notify() catch {};
    }

    fn run(self: *Worker) void {
        self.server.start();
        self.wakeup.wait(self.server.eventLoop(), &self.wakeup_c, Worker, self, onWakeup);
        self.server.eventLoop().run(.until_done) catch {};
    }

    fn onWakeup(self_opt: ?*Worker, _: *xev.Loop, _: *xev.Completion, r: xev.Async.WaitError!void) xev.CallbackAction {
        const self = self_opt.?;
        _ = r catch return .rearm;
        if (self.quit.load(.acquire)) {
            self.server.stop();
            return .disarm;
        }
        if (self.held.load(.acquire)) return .rearm;
        var items: std.ArrayList(Item) = .empty;
        defer items.deinit(gpa);
        self.lock.lock();
        std.mem.swap(std.ArrayList(Item), &items, &self.queue);
        self.lock.unlock();
        for (items.items) |item| switch (item) {
            .datagram => |d| {
                self.server.injectDatagram(d.bytes, d.peer, d.local, d.ecn);
                gpa.free(d.bytes);
                _ = self.injected.fetchAdd(1, .monotonic);
            },
            .handover => |h| {
                self.handler.session = self.server.adopt(h) catch continue;
                _ = self.adopted.fetchAdd(1, .monotonic);
            },
            .call => |f| f(self),
        };
        return .rearm;
    }

    /// What the test reads off this worker, from its own thread.
    fn record(self: *Worker) void {
        self.connections.store(self.server.conn_mgr.connectionCount(), .release);
        const s = self.handler.session orelse return;
        self.peer_port.store(std.mem.bigToNative(u16, @as(*const posix.sockaddr.in, @ptrCast(s.entry.conn.peerAddress())).port), .release);
        const e = s.entry;
        self.owns_hooks.store(e.wake_ctx == @as(*anyopaque, @ptrCast(&self.server)) and
            e.datagram_handler_ctx == @as(*anyopaque, @ptrCast(&self.handler)) and
            e.h3_conn.?.qpack_scratch.ptr == &self.server.qpack_scratch, .release);
    }

    /// Drop the connection without a word, as a server that lost its state.
    fn forget(self: *Worker) void {
        const s = self.handler.session orelse return;
        self.server.conn_mgr.removeConnection(s.entry);
        self.handler.session = null;
    }
};

/// Two servers sharing QUIC-LB, reset key, TLS and the moved-CID map.
const Group = struct {
    moved: MovedCids,
    workers: [2]*Worker,
    forwarded: std.atomic.Value(usize) = .init(0),

    fn init(self: *Group, ports: [2]u16) !void {
        self.* = .{ .moved = .init(gpa), .workers = undefined };
        const tls = testTlsConfig();
        for (&self.workers, ports, 1..) |*slot, port, id| {
            const w = try gpa.create(Worker);
            w.* = .{ .id = @intCast(id), .group = self };
            w.handler.worker = w;
            w.server = try Server(EchoServer).init(gpa, &w.handler, .{
                .port = port,
                .tls_config = tls,
                .quic_lb = lbConfig(@intCast(id)),
                .foreign_datagram = .{ .ctx = self, .func = onForeign },
                .moved_cids = &self.moved,
                .static_reset_key = @splat(0x42),
                .retry_token_key = @splat(0x43),
                .id_base = @as(u64, id) << 48,
            });
            w.wakeup = try xev.Async.init();
            slot.* = w;
        }
        for (self.workers) |w| w.thread = try std.Thread.spawn(.{}, Worker.run, .{w});
    }

    fn deinit(self: *Group) void {
        for (self.workers) |w| {
            w.quit.store(true, .release);
            w.wakeup.notify() catch {};
        }
        for (self.workers) |w| w.thread.join();
        for (self.workers) |w| {
            for (w.queue.items) |item| switch (item) {
                .datagram => |d| gpa.free(d.bytes),
                .handover => |h| h.discard(),
                .call => {},
            };
            w.queue.deinit(gpa);
            w.wakeup.deinit();
            w.server.deinit();
            gpa.destroy(w);
        }
        self.moved.deinit();
    }

    fn onForeign(ctx: ?*anyopaque, dg: *const ForeignDatagram) void {
        const self: *Group = @ptrCast(@alignCast(ctx.?));
        const id = dg.server_id[0];
        if (id < 1 or id > self.workers.len) return;
        _ = self.forwarded.fetchAdd(1, .monotonic);
        const copy = gpa.dupe(u8, dg.bytes) catch return;
        self.workers[id - 1].push(.{ .datagram = .{ .bytes = copy, .peer = dg.peer, .local = dg.local, .ecn = dg.ecn } });
    }

    /// Run `f` on worker `id`'s thread and wait for it.
    fn call(self: *Group, id: u8, comptime f: fn (*Worker) void) void {
        const Done = struct {
            var flag: std.atomic.Value(bool) = .init(false);
            fn run(w: *Worker) void {
                f(w);
                flag.store(true, .release);
            }
        };
        Done.flag.store(false, .release);
        self.workers[id - 1].push(.{ .call = Done.run });
        while (!Done.flag.load(.acquire)) sys.sleepNs(100 * std.time.ns_per_us);
    }

    fn connections(self: *Group, id: u8) usize {
        self.call(id, Worker.record);
        return self.workers[id - 1].connections.load(.acquire);
    }
};

/// The network between the client and the servers: relays the client's
/// datagrams to `target`'s port through an upstream socket, and the
/// answers back. `rebind` moves to a fresh upstream socket, as a NAT that
/// picked a new port; `loss_per_mille` drops datagrams both ways.
const Relay = struct {
    front: posix.socket_t,
    up: [2]posix.socket_t,
    ports: [2]u16,
    target: std.atomic.Value(u8) = .init(0),
    upstream: std.atomic.Value(u8) = .init(0),
    loss_per_mille: u32 = 0,
    prng: std.Random.DefaultPrng = .init(0x5eed),
    quit: std.atomic.Value(bool) = .init(false),
    client: posix.sockaddr.storage = undefined,
    client_len: posix.socklen_t = 0,
    thread: std.Thread = undefined,

    fn udp(port: u16) !posix.socket_t {
        const fd = try sys.socket(posix.AF.INET, posix.SOCK.DGRAM | posix.SOCK.NONBLOCK, 0);
        errdefer sys.close(fd);
        const addr = try net.Address.parseIp4("127.0.0.1", port);
        try sys.bind(fd, &addr.any, addr.getOsSockLen());
        return fd;
    }

    fn init(self: *Relay, port: u16, ports: [2]u16, loss_per_mille: u32) !void {
        self.* = .{
            .front = try udp(port),
            .up = .{ try udp(0), try udp(0) },
            .ports = ports,
            .loss_per_mille = loss_per_mille,
        };
        self.thread = try std.Thread.spawn(.{}, run, .{self});
    }

    fn deinit(self: *Relay) void {
        self.quit.store(true, .release);
        self.thread.join();
        for ([_]posix.socket_t{ self.front, self.up[0], self.up[1] }) |fd| sys.close(fd);
    }

    fn lost(self: *Relay) bool {
        return self.loss_per_mille > 0 and self.prng.random().uintLessThan(u32, 1000) < self.loss_per_mille;
    }

    fn run(self: *Relay) void {
        var buf: [65536]u8 = undefined;
        while (!self.quit.load(.acquire)) {
            var idle = true;
            var from: posix.sockaddr.storage = undefined;
            var from_len: posix.socklen_t = @sizeOf(posix.sockaddr.storage);
            if (sys.recvfrom(self.front, &buf, 0, @ptrCast(&from), &from_len)) |n| {
                idle = false;
                self.client = from;
                self.client_len = from_len;
                const to = net.Address.parseIp4("127.0.0.1", self.ports[self.target.load(.acquire)]) catch unreachable;
                if (!self.lost()) _ = sys.sendto(self.up[self.upstream.load(.acquire)], buf[0..n], 0, &to.any, to.getOsSockLen()) catch {};
            } else |_| {}
            for (self.up) |fd| {
                if (sys.recvfrom(fd, &buf, 0, null, null)) |n| {
                    idle = false;
                    if (self.client_len != 0 and !self.lost()) {
                        _ = sys.sendto(self.front, buf[0..n], 0, @ptrCast(&self.client), self.client_len) catch {};
                    }
                } else |_| {}
            }
            if (idle) sys.sleepNs(20 * std.time.ns_per_us);
        }
    }

    fn upstreamPort(self: *Relay, i: usize) u16 {
        var addr: posix.sockaddr.storage = undefined;
        var len: posix.socklen_t = @sizeOf(posix.sockaddr.storage);
        sys.getsockname(self.up[i], @ptrCast(&addr), &len) catch return 0;
        return std.mem.bigToNative(u16, @as(*const posix.sockaddr.in, @ptrCast(&addr)).port);
    }
};

fn pattern(offset: usize) u8 {
    return @intCast('A' + offset % 26);
}

/// Streams a patterned body on one bidi stream and a datagram per step,
/// and checks what comes back.
const MoveClient = struct {
    pub const protocol: event_loop.Protocol = .webtransport;

    session_id: ?u64 = null,
    data_stream: ?u64 = null,
    echoed: usize = 0,
    corrupt: bool = false,
    fin: bool = false,
    datagrams: u32 = 0,

    pub fn onSessionReady(self: *MoveClient, session: *ClientSession, session_id: u64) void {
        self.session_id = session_id;
        self.data_stream = session.openBidiStream(session_id, null) catch null;
    }

    pub fn onStreamData(self: *MoveClient, _: *ClientSession, stream_id: u64, data: []const u8, fin: bool) void {
        if (stream_id != self.data_stream) return;
        for (data, self.echoed..) |b, i| {
            if (b != pattern(i)) self.corrupt = true;
        }
        self.echoed += data.len;
        if (fin) self.fin = true;
    }

    pub fn onDatagram(self: *MoveClient, _: *ClientSession, _: u64, _: []const u8) void {
        self.datagrams += 1;
    }

    fn ready(self: *MoveClient) bool {
        return self.data_stream != null;
    }
};

const Fixture = struct {
    group: Group,
    relay: Relay,
    loop: xev.Loop,
    handler: MoveClient = .{},
    client: Client(MoveClient),

    fn init(self: *Fixture, base_port: u16, loss_per_mille: u32) !void {
        const ports = [2]u16{ base_port + 1, base_port + 2 };
        try self.group.init(ports);
        errdefer self.group.deinit();
        try self.relay.init(base_port, ports, loss_per_mille);
        errdefer self.relay.deinit();
        self.loop = try xev.Loop.init(.{});
        self.handler = .{};
        self.client = try Client(MoveClient).init(gpa, &self.handler, .{
            .port = base_port,
            .skip_cert_verify = true,
            .loop = &self.loop,
        });
        self.client.start();
        try self.runUntil(MoveClient.ready, &self.handler, 10_000);
    }

    fn deinit(self: *Fixture) void {
        self.client.stop();
        const deadline = sys.nanoTimestamp() + 3 * std.time.ns_per_s;
        while (!self.client.isStopped() and sys.nanoTimestamp() < deadline) self.step();
        self.client.deinit();
        self.loop.deinit();
        self.group.deinit();
        self.relay.deinit();
    }

    fn step(self: *Fixture) void {
        self.loop.run(.no_wait) catch {};
        sys.sleepNs(50 * std.time.ns_per_us);
    }

    fn runUntil(self: *Fixture, comptime done: anytype, ctx: anytype, timeout_ms: i64) !void {
        const deadline = sys.nanoTimestamp() + timeout_ms * std.time.ns_per_ms;
        while (!done(ctx)) {
            if (sys.nanoTimestamp() > deadline) return error.Timeout;
            self.step();
        }
    }

    fn session(self: *Fixture) ClientSession {
        return self.client.clientSession();
    }

    /// Ask the server holding the connection to hand it to the other.
    fn move(self: *Fixture, how: []const u8) !void {
        var cs = self.session();
        const control = try cs.openBidiStream(self.handler.session_id.?, null);
        try cs.sendStreamData(control, how);
    }

    /// The server id the client's packets now carry.
    fn dcidServer(self: *Fixture) u8 {
        const conn = self.client.conn;
        return serverIdOf(conn.dcid[0..conn.dcid_len]);
    }

    /// Streams `total` bytes and a datagram per step, asking for the
    /// handover once `move_at` bytes are out; true once all came back.
    fn stream(self: *Fixture, total: usize, move_at: usize, timeout_ms: i64) !void {
        return self.streamMoving(total, move_at, .stream, timeout_ms);
    }

    fn streamMoving(self: *Fixture, total: usize, move_at: usize, how: enum { stream, datagram }, timeout_ms: i64) !void {
        var cs = self.session();
        const id = self.handler.data_stream.?;
        var sent: usize = 0;
        var moved = false;
        var chunk: [4096]u8 = undefined;
        var seq: u32 = 0;
        const deadline = sys.nanoTimestamp() + timeout_ms * std.time.ns_per_ms;
        while (!(self.handler.fin and self.handler.echoed == total)) {
            if (sys.nanoTimestamp() > deadline) return error.Timeout;
            // Keep a window in flight, as a game's traffic would be.
            while (sent < total and sent - self.handler.echoed < 64 * 1024) {
                const n = @min(chunk.len, total - sent);
                for (chunk[0..n], sent..) |*b, i| b.* = pattern(i);
                try cs.sendStreamData(id, chunk[0..n]);
                sent += n;
                if (sent == total) cs.closeStream(id);
            }
            if (!moved and sent >= move_at) {
                moved = switch (how) {
                    .stream => blk: {
                        try self.move("move");
                        break :blk true;
                    },
                    // Queued behind the per-step datagrams on a busy host: next step.
                    .datagram => if (cs.sendDatagram(self.handler.session_id.?, "move")) |_| true else |err| switch (err) {
                        error.DatagramQueueFull => false,
                        else => return err,
                    },
                };
            }
            var dg: [16]u8 = undefined;
            std.mem.writeInt(u32, dg[0..4], seq, .little);
            seq += 1;
            cs.sendDatagram(self.handler.session_id.?, &dg) catch {};
            self.step();
        }
    }
};

fn handedOnce(f: *Fixture) bool {
    return f.group.workers[1].adopted.load(.monotonic) == 1;
}

fn onServerTwo(f: *Fixture) bool {
    return f.dcidServer() == 2;
}

fn movedEmpty(f: *Fixture) bool {
    return f.group.moved.count() == 0;
}

test "handover: streams and datagrams carry on across it, and the client moves to the new server's CIDs" {
    var f: Fixture = undefined;
    try f.init(29600, 0);
    defer f.deinit();
    try testing.expectEqual(@as(u8, 1), f.dcidServer());

    try f.streamMoving(512 * 1024, 128 * 1024, .datagram, 20_000);
    try testing.expect(!f.handler.corrupt);
    try f.runUntil(handedOnce, &f, 5_000);
    try f.runUntil(onServerTwo, &f, 5_000);

    // Datagrams keep coming back from the new server.
    const before = f.handler.datagrams;
    var cs = f.session();
    for (0..20) |_| {
        cs.sendDatagram(f.handler.session_id.?, "ping") catch {};
        f.step();
    }
    const MoreDatagrams = struct {
        before: u32,
        h: *MoveClient,
        fn done(self: *const @This()) bool {
            return self.h.datagrams > self.before;
        }
    };
    try f.runUntil(MoreDatagrams.done, &MoreDatagrams{ .before = before, .h = &f.handler }, 5_000);

    // The client has retired the first server's CIDs, so nothing is left to steer by.
    try f.runUntil(movedEmpty, &f, 5_000);
    try testing.expectEqual(@as(usize, 0), f.group.connections(1));
    try testing.expectEqual(@as(usize, 1), f.group.connections(2));
    try testing.expectEqual(@as(u32, 1), f.group.workers[0].handler.handed.load(.monotonic));
    try testing.expect(f.group.workers[1].owns_hooks.load(.acquire));
    // Nothing the first server polled after the request went missing.
    try testing.expectEqual(@as(u32, 0), f.group.workers[0].handler.late.load(.monotonic));
    // Everything after the handover reached the first server's socket.
    try testing.expect(f.group.forwarded.load(.monotonic) > 0);
}

test "handover: under 5% loss both ways the stream still comes back whole" {
    var f: Fixture = undefined;
    try f.init(29610, 50);
    defer f.deinit();

    try f.stream(256 * 1024, 64 * 1024, 30_000);
    try testing.expect(!f.handler.corrupt);
    try f.runUntil(onServerTwo, &f, 10_000);
    try testing.expectEqual(@as(usize, 1), f.group.connections(2));
    try testing.expectEqual(@as(usize, 0), f.group.connections(1));
}

fn closedOnTwo(f: *Fixture) bool {
    return f.group.workers[1].handler.closed.load(.monotonic) == 1;
}

fn handedByOne(f: *Fixture) bool {
    return f.group.workers[0].handler.handed.load(.monotonic) == 1;
}

test "handover: a client that closes while its connection is between servers is closed on the new one" {
    var f: Fixture = undefined;
    try f.init(29620, 0);
    defer f.deinit();

    // The handover waits in the second server's queue while the client closes.
    f.group.workers[1].held.store(true, .release);
    try f.move("move");
    try f.runUntil(handedByOne, &f, 5_000);
    f.client.stop();
    const deadline = sys.nanoTimestamp() + 200 * std.time.ns_per_ms;
    while (sys.nanoTimestamp() < deadline) f.step();
    f.group.workers[1].held.store(false, .release);
    f.group.workers[1].wakeup.notify() catch {};

    try f.runUntil(closedOnTwo, &f, 5_000);
    try f.runUntil(movedEmpty, &f, 5_000);
    try testing.expectEqual(@as(u32, 1), f.group.workers[1].adopted.load(.monotonic));
    try testing.expectEqual(@as(usize, 0), f.group.connections(2));
}

fn closedOnOne(f: *Fixture) bool {
    return f.group.workers[0].handler.closed.load(.monotonic) == 1;
}

test "handover: a connection that starts closing before its pass ends stays and closes where it is" {
    var f: Fixture = undefined;
    try f.init(29630, 0);
    defer f.deinit();

    try f.move("move+close");
    try f.runUntil(closedOnOne, &f, 5_000);
    try testing.expectEqual(@as(u32, 0), f.group.workers[0].handler.handed.load(.monotonic));
    try testing.expectEqual(@as(u32, 0), f.group.workers[1].adopted.load(.monotonic));
    try testing.expectEqual(@as(usize, 0), f.group.moved.count());
}

test "handover: after a NAT rebinding onto the old server, the new one validates the path and carries on" {
    var f: Fixture = undefined;
    try f.init(29640, 0);
    defer f.deinit();

    try f.stream(64 * 1024, 16 * 1024, 20_000);
    try f.runUntil(onServerTwo, &f, 5_000);

    // A new source port, still landing on the first server.
    f.relay.upstream.store(1, .release);
    f.handler.echoed = 0;
    f.handler.fin = false;
    var cs = f.session();
    f.handler.data_stream = try cs.openBidiStream(f.handler.session_id.?, null);
    try f.stream(64 * 1024, std.math.maxInt(usize), 20_000);
    try testing.expect(!f.handler.corrupt);

    f.group.call(2, Worker.record);
    try testing.expectEqual(f.relay.upstreamPort(1), f.group.workers[1].peer_port.load(.acquire));
    try testing.expectEqual(@as(usize, 0), f.group.connections(1));
}

fn resetReceived(f: *Fixture) bool {
    return f.client.conn.received_stateless_reset;
}

test "handover: a connection the new server lost draws a stateless reset the client accepts" {
    var f: Fixture = undefined;
    try f.init(29650, 0);
    defer f.deinit();

    try f.stream(16 * 1024, 0, 20_000);
    try f.runUntil(onServerTwo, &f, 5_000);
    try f.runUntil(movedEmpty, &f, 5_000);
    f.group.call(2, Worker.forget);

    // Through the first server, which steers it by the CID to the second,
    // which answers with the token it issued for that CID.
    var cs = f.session();
    try cs.sendDatagram(f.handler.session_id.?, "anyone there? anyone there? anyone there? anyone there?");
    const t0 = sys.nanoTimestamp();
    try f.runUntil(resetReceived, &f, 5_000);
    try testing.expect(sys.nanoTimestamp() - t0 < 2 * std.time.ns_per_s);
}

test "handover: a packet the old server gets back while its connection is on the way is passed on" {
    var f: Fixture = undefined;
    try f.init(29660, 0);
    defer f.deinit();

    f.group.workers[1].held.store(true, .release);
    try f.move("move");
    try f.runUntil(handedByOne, &f, 5_000);
    // The client's packets, still on the first server's CIDs, now land on
    // the second, which steers them to the first by their id, which passes
    // them on to where the connection went.
    f.relay.target.store(1, .release);
    var cs = f.session();
    const deadline = sys.nanoTimestamp() + 200 * std.time.ns_per_ms;
    while (sys.nanoTimestamp() < deadline) {
        cs.sendDatagram(f.handler.session_id.?, "still there?") catch {};
        f.step();
    }
    try testing.expectEqual(@as(u32, 0), f.group.workers[1].injected.load(.monotonic));
    f.group.workers[1].held.store(false, .release);
    f.group.workers[1].wakeup.notify() catch {};

    try f.stream(16 * 1024, std.math.maxInt(usize), 10_000);
    try testing.expect(f.group.workers[1].injected.load(.monotonic) > 0);
    try testing.expectEqual(@as(usize, 1), f.group.connections(2));
}

test "handover: one discarded on the way takes its CIDs out of MovedCids, so the client is reset" {
    var f: Fixture = undefined;
    try f.init(29670, 0);
    defer f.deinit();

    f.group.workers[1].held.store(true, .release);
    try f.move("move");
    try f.runUntil(handedByOne, &f, 5_000);
    try testing.expect(f.group.moved.count() > 0);
    // As a server that stops with it still queued.
    const w = f.group.workers[1];
    w.lock.lock();
    var items = w.queue;
    w.queue = .empty;
    w.lock.unlock();
    defer items.deinit(gpa);
    for (items.items) |item| switch (item) {
        .datagram => |d| gpa.free(d.bytes),
        .handover => |h| h.discard(),
        .call => {},
    };
    try testing.expectEqual(@as(usize, 0), f.group.moved.count());
    w.held.store(false, .release);

    // Its CIDs name the first server, which no longer knows them.
    var cs = f.session();
    try cs.sendDatagram(f.handler.session_id.?, "anyone there? anyone there? anyone there? anyone there?");
    const t0 = sys.nanoTimestamp();
    try f.runUntil(resetReceived, &f, 5_000);
    try testing.expect(sys.nanoTimestamp() - t0 < 2 * std.time.ns_per_s);
}
