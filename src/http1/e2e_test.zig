//! End-to-end tests of the HTTP/1.1 listener inside `event_loop.Server`:
//! WebSockets and static files, plain and over TLS, next to WebTransport on
//! the same handler and loop. The client side is a plain socket driven from
//! the test, between non-blocking runs of the loop.

const std = @import("std");
const builtin = @import("builtin");
const posix = std.posix;
const testing = std.testing;
const sys = @import("../sys.zig");
const net = @import("../sockaddr.zig");
const event_loop = @import("../event_loop.zig");
const tls13 = @import("../quic/tls13.zig");
const tls_client = @import("../tls/client.zig");
const test_certs = @import("../tls/test_certs.zig");
const http1 = @import("server.zig");
const websocket = @import("websocket.zig");
const socket = @import("socket.zig");

const xev = event_loop.Xev;
const WsConn = event_loop.WsConn;
const WsRequest = event_loop.WsRequest;

const sample_key = "dGhlIHNhbXBsZSBub25jZQ==";
const sample_accept = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=";

// ─── Server side ─────────────────────────────────────────────────────

/// Echoes WebSocket messages and WebTransport streams, and records what
/// the WebSocket callbacks saw.
const EchoHandler = struct {
    pub const protocol: event_loop.Protocol = .webtransport;

    mode: enum { accept, reject_404, undecided } = .accept,
    upgrades: u32 = 0,
    path_buf: [64]u8 = undefined,
    path_len: usize = 0,
    ws: ?*WsConn = null,
    ws_id: u64 = 0,
    closes: u32 = 0,
    close_code: u16 = 0,
    close_reason_buf: [64]u8 = undefined,
    close_reason_len: usize = 0,
    send_after_close: ?event_loop.WsSendError = null,
    flood_result: ?event_loop.WsSendError = null,
    flood_sent: usize = 0,
    /// `bufferedAmount` while "corked" held three messages, and after.
    corked_buffered: usize = 0,
    uncorked_buffered: usize = 0,
    /// What "move" let go of, for the test to adopt or discard.
    handed: ?event_loop.WsHandover = null,
    /// A read or write of it was still in flight on this loop then.
    handed_busy: bool = false,
    wt_session_ids: [4]u64 = @splat(0),
    wt_sessions: usize = 0,

    pub fn onWsUpgrade(self: *EchoHandler, req: *WsRequest, path: []const u8) void {
        self.upgrades += 1;
        self.path_len = @min(path.len, self.path_buf.len);
        @memcpy(self.path_buf[0..self.path_len], path[0..self.path_len]);
        switch (self.mode) {
            .reject_404 => req.reject(404),
            .undecided => {},
            .accept => {
                const proto: ?[]const u8 = if (req.offersProtocol("echo")) "echo" else null;
                const ws = req.accept(.{ .protocol = proto, .headers = &.{.{ .name = "X-Test", .value = "1" }} }) catch return;
                self.ws = ws;
                self.ws_id = ws.id();
                ws.send("hello") catch unreachable;
            },
        }
    }

    pub fn onWsMessage(self: *EchoHandler, ws: *WsConn, data: []const u8, kind: event_loop.WsMessageKind) void {
        if (std.mem.eql(u8, data, "close-me")) {
            ws.close(4000, "done");
            ws.send("late") catch |err| {
                self.send_after_close = err;
            };
            return;
        }
        if (std.mem.startsWith(u8, data, "flood")) {
            var chunk: [16 * 1024]u8 = undefined;
            @memset(&chunk, 'f');
            for (0..4096) |_| {
                ws.send(&chunk) catch |err| {
                    self.flood_result = err;
                    break;
                };
                self.flood_sent += 1;
            }
            if (std.mem.endsWith(u8, data, "move")) ws.handOver() catch unreachable;
            return;
        }
        if (std.mem.eql(u8, data, "move")) return ws.handOver() catch unreachable;
        if (std.mem.eql(u8, data, "corked")) {
            ws.cork();
            for ([_][]const u8{ "a", "b", "c" }) |m| ws.send(m) catch unreachable;
            self.corked_buffered = ws.bufferedAmount();
            ws.uncork();
            self.uncorked_buffered = ws.bufferedAmount();
            return;
        }
        switch (kind) {
            .binary => ws.send(data) catch {},
            .text => ws.sendText(data) catch {},
        }
    }

    pub fn onWsClose(self: *EchoHandler, ws: *WsConn, code: u16, reason: []const u8) void {
        self.closes += 1;
        self.close_code = code;
        self.close_reason_len = @min(reason.len, self.close_reason_buf.len);
        @memcpy(self.close_reason_buf[0..self.close_reason_len], reason[0..self.close_reason_len]);
        if (self.ws == ws) self.ws = null;
    }

    pub fn onWsHandover(self: *EchoHandler, h: event_loop.WsHandover) void {
        self.handed = h;
        self.handed_busy = h.conn.sock.reading or h.conn.sock.writing;
    }

    pub fn onHttpRequest(_: *EchoHandler, req: *event_loop.HttpRequest, target: []const u8) void {
        if (std.mem.eql(u8, target, "/hello")) req.respond(200, "text/plain", "hi there");
        if (std.mem.eql(u8, target, "/cors")) req.respondWith(200, "application/json", "Access-Control-Allow-Origin: *\r\n", "[]");
    }

    pub fn onConnectRequest(self: *EchoHandler, session: *event_loop.Session, session_id: u64, _: []const u8) void {
        session.acceptSession(session_id) catch return;
        if (self.wt_sessions < self.wt_session_ids.len) {
            self.wt_session_ids[self.wt_sessions] = session.id();
            self.wt_sessions += 1;
        }
    }

    pub fn onStreamData(_: *EchoHandler, session: *event_loop.Session, stream_id: u64, data: []const u8, fin: bool) void {
        if (data.len > 0) session.sendStreamData(stream_id, data) catch {};
        if (fin) session.closeStream(stream_id);
    }

    fn closeReason(self: *const EchoHandler) []const u8 {
        return self.close_reason_buf[0..self.close_reason_len];
    }
};

const Harness = HarnessFor(EchoHandler);

/// A server on a loop the test owns, with real certificates so TLS over
/// TCP works as well as QUIC.
fn HarnessFor(comptime H: type) type {
    return struct {
        const Self = @This();

        loop: xev.Loop,
        certs: test_certs.TestCerts,
        handler: H,
        server: event_loop.Server(H),
        port: u16,

        /// In place: the server keeps pointers into `self` once started.
        fn init(self: *Self, port: u16, h1: event_loop.Http1Config) !void {
            self.port = port;
            self.handler = .{};
            try self.certs.load();
            self.loop = try xev.Loop.init(.{});
            errdefer self.loop.deinit();
            self.server = try event_loop.Server(H).init(testing.allocator, &self.handler, .{
                .port = port,
                .tls_config = .{
                    .cert_chain_der = &.{},
                    .private_key_bytes = &.{},
                    .certs = self.certs.entries[0..1],
                    .alpn = &.{"h3"},
                },
                .loop = &self.loop,
                .http1 = h1,
            });
            self.server.start();
        }

        fn deinit(self: *Self) void {
            self.server.stop();
            self.spinUntil(self, stopped) catch @panic("server did not stop");
            self.server.deinit();
            self.loop.deinit();
        }

        fn stopped(self: *Self) bool {
            return self.server.isStopped();
        }

        fn step(self: *Self) !void {
            try self.loop.run(.no_wait);
            sys.sleepNs(50 * std.time.ns_per_us);
        }

        fn spinUntil(self: *Self, ctx: anytype, comptime done: fn (@TypeOf(ctx)) bool) !void {
            const deadline = sys.nanoTimestamp() + 10 * std.time.ns_per_s;
            while (!done(ctx)) {
                if (sys.nanoTimestamp() > deadline) return error.Timeout;
                try self.step();
            }
        }

        /// The next response head from `c`.
        fn head(self: *Self, c: *TestClient) ![]const u8 {
            const deadline = sys.nanoTimestamp() + 10 * std.time.ns_per_s;
            while (true) {
                c.poll();
                if (c.takeHead()) |h| return h;
                if (c.eof) return error.EndOfStream;
                if (sys.nanoTimestamp() > deadline) return error.Timeout;
                try self.step();
            }
        }

        /// The next `n` bytes from `c`.
        fn bytes(self: *Self, c: *TestClient, n: usize) ![]const u8 {
            const deadline = sys.nanoTimestamp() + 10 * std.time.ns_per_s;
            while (true) {
                c.poll();
                if (c.in.items.len - c.pos >= n) {
                    defer c.pos += n;
                    return c.in.items[c.pos..][0..n];
                }
                if (c.eof) return error.EndOfStream;
                if (sys.nanoTimestamp() > deadline) return error.Timeout;
                try self.step();
            }
        }

        /// The next frame the server sent `c`.
        fn frame(self: *Self, c: *TestClient) !ServerFrame {
            const deadline = sys.nanoTimestamp() + 10 * std.time.ns_per_s;
            while (true) {
                c.poll();
                if (try c.takeFrame()) |f| return f;
                if (c.eof) return error.EndOfStream;
                if (sys.nanoTimestamp() > deadline) return error.Timeout;
                try self.step();
            }
        }

        /// Waits for the server to close `c`'s connection.
        fn eof(self: *Self, c: *TestClient) !void {
            const deadline = sys.nanoTimestamp() + 10 * std.time.ns_per_s;
            while (!c.eof) {
                c.poll();
                if (sys.nanoTimestamp() > deadline) return error.Timeout;
                try self.step();
            }
        }

        fn handlerCloses(self: *Self, n: u32) !void {
            const W = struct {
                h: *Self,
                n: u32,
                fn done(w: *const @This()) bool {
                    return w.h.handler.closes >= w.n;
                }
            };
            try self.spinUntil(&W{ .h = self, .n = n }, W.done);
        }

        /// Connects, upgrades, and checks the 101 and the greeting.
        fn upgrade(self: *Self, c: *TestClient, path: []const u8, use_tls: bool) !void {
            try c.connect(self.port, use_tls);
            if (use_tls) try self.handshake(c);
            try c.sendRequest(path, "13", "echo");
            const h = try self.head(c);
            try testing.expect(std.mem.startsWith(u8, h, "HTTP/1.1 101 Switching Protocols\r\n"));
            try testing.expect(std.mem.indexOf(u8, h, "Sec-WebSocket-Accept: " ++ sample_accept ++ "\r\n") != null);
            try testing.expect(std.mem.indexOf(u8, h, "Sec-WebSocket-Protocol: echo\r\n") != null);
            try testing.expect(std.mem.indexOf(u8, h, "X-Test: 1\r\n") != null);
            const hello = try self.frame(c);
            try testing.expectEqual(websocket.Opcode.binary, hello.opcode);
            try testing.expectEqualStrings("hello", hello.payload);
        }

        fn handshake(self: *Self, c: *TestClient) !void {
            const deadline = sys.nanoTimestamp() + 10 * std.time.ns_per_s;
            while (!c.tls.?.handshakeComplete()) {
                c.poll();
                if (c.eof) return error.EndOfStream;
                if (sys.nanoTimestamp() > deadline) return error.Timeout;
                try self.step();
            }
        }
    };
}

/// Two servers, each on a loop of its own as two workers' would be: a
/// WebSocket the first lets go of is adopted by the second at once.
const Pair = struct {
    a: Harness,
    b: Harness,
    adopted: u32,

    fn init(self: *Pair, port: u16, h1: event_loop.Http1Config) !void {
        self.adopted = 0;
        try self.a.init(port, h1);
        errdefer self.a.deinit();
        try self.b.init(port + 1, h1);
    }

    fn deinit(self: *Pair) void {
        self.b.deinit();
        self.a.deinit();
    }

    fn step(self: *Pair) !void {
        try self.a.loop.run(.no_wait);
        if (self.a.handler.handed) |h| {
            self.a.handler.handed = null;
            try testing.expect(!self.a.handler.handed_busy);
            self.b.handler.ws = try self.b.server.http1_server.?.adopt(h);
            self.adopted += 1;
        }
        try self.b.loop.run(.no_wait);
        sys.sleepNs(50 * std.time.ns_per_us);
    }

    fn frame(self: *Pair, c: *TestClient) !ServerFrame {
        const deadline = sys.nanoTimestamp() + 10 * std.time.ns_per_s;
        while (true) {
            c.poll();
            if (try c.takeFrame()) |f| return f;
            if (c.eof) return error.EndOfStream;
            if (sys.nanoTimestamp() > deadline) return error.Timeout;
            try self.step();
        }
    }

    fn closesOnB(self: *Pair, n: u32) !void {
        const deadline = sys.nanoTimestamp() + 10 * std.time.ns_per_s;
        while (self.b.handler.closes < n) {
            if (sys.nanoTimestamp() > deadline) return error.Timeout;
            try self.step();
        }
    }
};

// ─── Client side ─────────────────────────────────────────────────────

const ServerFrame = struct {
    fin: bool,
    opcode: websocket.Opcode,
    payload: []const u8,

    fn closeCode(self: ServerFrame) ?u16 {
        if (self.opcode != .close or self.payload.len < 2) return null;
        return std.mem.readInt(u16, self.payload[0..2], .big);
    }
};

const TestClient = struct {
    fd: posix.socket_t = -1,
    tls_config: tls_client.Config = .{},
    tls: ?tls_client.Conn = null,
    /// Plaintext from the server; `pos` bytes of it consumed.
    in: std.ArrayList(u8) = .empty,
    pos: usize = 0,
    eof: bool = false,

    /// In place: the TLS connection points at `tls_config`.
    fn connect(self: *TestClient, port: u16, use_tls: bool) !void {
        self.* = .{};
        const fd = try sys.socket(posix.AF.INET, posix.SOCK.STREAM, 0);
        errdefer sys.close(fd);
        const addr = try net.Address.parseIp4("127.0.0.1", port);
        if (std.c.connect(fd, &addr.any, addr.getOsSockLen()) != 0) return error.ConnectionRefused;
        socket.setNonBlocking(fd);
        self.fd = fd;
        if (use_tls) {
            self.tls_config = .{ .server_name = "localhost", .skip_cert_verify = true, .alpn = &.{"http/1.1"} };
            self.tls = try tls_client.Conn.init(testing.allocator, &self.tls_config);
            self.flushTls();
        }
    }

    fn connectUnix(self: *TestClient, path: []const u8) !void {
        self.* = .{};
        const fd = try sys.socket(posix.AF.UNIX, posix.SOCK.STREAM, 0);
        errdefer sys.close(fd);
        var addr: posix.sockaddr.un = .{ .path = @splat(0) };
        @memcpy(addr.path[0..path.len], path);
        if (std.c.connect(fd, @ptrCast(&addr), @sizeOf(posix.sockaddr.un)) != 0) return error.ConnectionRefused;
        socket.setNonBlocking(fd);
        self.fd = fd;
    }

    fn deinit(self: *TestClient) void {
        if (self.tls) |*t| t.deinit();
        self.in.deinit(testing.allocator);
        if (self.fd >= 0) sys.close(self.fd);
        self.fd = -1;
    }

    /// Sends nothing more, reading on: a FIN, or over TLS a close_notify.
    fn halfClose(self: *TestClient) void {
        if (self.tls) |*t| {
            t.close();
            return self.flushTls();
        }
        _ = std.c.shutdown(self.fd, posix.SHUT.WR);
    }

    /// Drops the connection with no Close frame.
    fn abort(self: *TestClient) void {
        sys.close(self.fd);
        self.fd = -1;
    }

    fn writeAll(self: *TestClient, bytes: []const u8) void {
        var rest = bytes;
        while (rest.len > 0) {
            const rc = std.c.send(self.fd, rest.ptr, rest.len, 0);
            if (rc < 0) {
                if (std.posix.errno(rc) == .AGAIN) {
                    sys.sleepNs(100 * std.time.ns_per_us);
                    continue;
                }
                return;
            }
            rest = rest[@intCast(rc)..];
        }
    }

    fn flushTls(self: *TestClient) void {
        const t = &(self.tls orelse return);
        const out = t.pendingOutput();
        self.writeAll(out);
        t.consumeOutput(out.len);
    }

    fn send(self: *TestClient, plaintext: []const u8) !void {
        if (self.tls) |*t| {
            try t.write(plaintext);
            self.flushTls();
        } else {
            self.writeAll(plaintext);
        }
    }

    fn sendRequest(self: *TestClient, path: []const u8, version: []const u8, protocol: ?[]const u8) !void {
        var buf: [512]u8 = undefined;
        var w: std.Io.Writer = .fixed(&buf);
        try w.print("GET {s} HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\nConnection: keep-alive, Upgrade\r\n" ++
            "Sec-WebSocket-Key: " ++ sample_key ++ "\r\nSec-WebSocket-Version: {s}\r\n", .{ path, version });
        if (protocol) |p| try w.print("Sec-WebSocket-Protocol: chat, {s}\r\n", .{p});
        try w.writeAll("\r\n");
        try self.send(w.buffered());
    }

    /// A masked client frame.
    fn sendFrame(self: *TestClient, opcode: websocket.Opcode, fin: bool, payload: []const u8) !void {
        var buf: [4096]u8 = undefined;
        var hdr: [10]u8 = undefined;
        const h = websocket.writeFrameHeader(&hdr, opcode, fin, payload.len);
        @memcpy(buf[0..h.len], h);
        buf[1] |= 0x80;
        const key = [4]u8{ 0xa1, 0x07, 0x5e, 0xc3 };
        @memcpy(buf[h.len..][0..4], &key);
        const body = buf[h.len + 4 ..][0..payload.len];
        @memcpy(body, payload);
        websocket.unmask(body, key);
        try self.send(buf[0 .. h.len + 4 + payload.len]);
    }

    fn poll(self: *TestClient) void {
        if (self.eof or self.fd < 0) return;
        var buf: [16 * 1024]u8 = undefined;
        while (true) {
            const rc = std.c.recv(self.fd, &buf, buf.len, 0);
            if (rc < 0) {
                if (std.posix.errno(rc) == .AGAIN) return;
                self.eof = true;
                return;
            }
            if (rc == 0) {
                self.eof = true;
                return;
            }
            const data = buf[0..@intCast(rc)];
            if (self.tls) |*t| {
                t.feed(data) catch {
                    self.eof = true;
                    return;
                };
                self.flushTls();
                while (true) {
                    self.in.ensureUnusedCapacity(testing.allocator, 16 * 1024) catch return;
                    const n = t.read(self.in.unusedCapacitySlice());
                    if (n == 0) break;
                    self.in.items.len += n;
                }
            } else {
                self.in.appendSlice(testing.allocator, data) catch return;
            }
        }
    }

    fn takeHead(self: *TestClient) ?[]const u8 {
        const rest = self.in.items[self.pos..];
        const end = std.mem.indexOf(u8, rest, "\r\n\r\n") orelse return null;
        self.pos += end + 4;
        return rest[0 .. end + 4];
    }

    fn takeFrame(self: *TestClient) !?ServerFrame {
        const b = self.in.items[self.pos..];
        if (b.len < 2) return null;
        if (b[1] & 0x80 != 0) return error.MaskedServerFrame;
        var pos: usize = 2;
        const len: usize = switch (b[1] & 0x7f) {
            126 => blk: {
                if (b.len < 4) return null;
                pos = 4;
                break :blk std.mem.readInt(u16, b[2..4], .big);
            },
            127 => blk: {
                if (b.len < 10) return null;
                pos = 10;
                break :blk @intCast(std.mem.readInt(u64, b[2..10], .big));
            },
            else => |n| n,
        };
        if (b.len < pos + len) return null;
        self.pos += pos + len;
        return .{
            .fin = b[0] & 0x80 != 0,
            .opcode = @fromBackingInt(@intCast(@as(u4, @truncate(b[0])))),
            .payload = b[pos..][0..len],
        };
    }
};

/// A masked client frame written into `buf`.
fn maskedFrame(buf: []u8, opcode: websocket.Opcode, payload: []const u8) []u8 {
    var hdr: [10]u8 = undefined;
    const h = websocket.writeFrameHeader(&hdr, opcode, true, payload.len);
    @memcpy(buf[0..h.len], h);
    buf[1] |= 0x80;
    const key = [4]u8{ 0x5c, 0x21, 0xe0, 0x17 };
    @memcpy(buf[h.len..][0..4], &key);
    const body = buf[h.len + 4 ..][0..payload.len];
    @memcpy(body, payload);
    websocket.unmask(body, key);
    return buf[0 .. h.len + 4 + payload.len];
}

// ─── Tests ───────────────────────────────────────────────────────────

test "ws: upgrade, echo, a fragmented message with a ping inside, and the client's close" {
    var h: Harness = undefined;
    try h.init(29440, .{ .tls = false });
    defer h.deinit();
    var c: TestClient = .{};
    defer c.deinit();
    try h.upgrade(&c, "/room?token=ab", false);
    try testing.expectEqualStrings("/room?token=ab", h.handler.path_buf[0..h.handler.path_len]);
    // Ids come from the QUIC connection counter, which starts at 1.
    try testing.expect(h.handler.ws_id >= 1);

    try c.sendFrame(.binary, true, &.{ 1, 2, 3 });
    const echo = try h.frame(&c);
    try testing.expectEqual(websocket.Opcode.binary, echo.opcode);
    try testing.expectEqualSlices(u8, &.{ 1, 2, 3 }, echo.payload);

    try c.sendFrame(.text, false, "Hel");
    try c.sendFrame(.ping, true, "p!");
    try c.sendFrame(.continuation, true, "lo");
    const pong = try h.frame(&c);
    try testing.expectEqual(websocket.Opcode.pong, pong.opcode);
    try testing.expectEqualStrings("p!", pong.payload);
    const text = try h.frame(&c);
    try testing.expectEqual(websocket.Opcode.text, text.opcode);
    try testing.expectEqualStrings("Hello", text.payload);

    var p: [125]u8 = undefined;
    try c.sendFrame(.close, true, websocket.closePayload(&p, 1000, "bye"));
    const close = try h.frame(&c);
    try testing.expectEqual(@as(?u16, 1000), close.closeCode());
    try h.eof(&c);
    try h.handlerCloses(1);
    try testing.expectEqual(@as(u16, 1000), h.handler.close_code);
    try testing.expectEqualStrings("bye", h.handler.closeReason());
    try testing.expectEqual(@as(u32, 1), h.handler.closes);
}

fn pathExists(path: [*:0]const u8) bool {
    return std.c.access(path, 0) == 0;
}

test "unix socket: a WebSocket and a request, and stop() removes the file" {
    const path = "/tmp/quic-zig-e2e-29620.sock";
    var h: Harness = undefined;
    try h.init(29620, .{ .tls = false, .unix_path = path });
    var stopped = false;
    defer if (!stopped) h.deinit();
    try testing.expectEqual(@as(u16, 0), h.server.http1_server.?.port());
    try testing.expect(pathExists(path));

    var ws: TestClient = undefined;
    try ws.connectUnix(path);
    defer ws.deinit();
    try ws.sendRequest("/chat", "13", null);
    try testing.expect(std.mem.startsWith(u8, try h.head(&ws), "HTTP/1.1 101"));
    try testing.expectEqualStrings("hello", (try h.frame(&ws)).payload);
    try ws.sendFrame(.text, true, "over a file");
    try testing.expectEqualStrings("over a file", (try h.frame(&ws)).payload);
    try testing.expectEqual(posix.AF.UNIX, h.handler.ws.?.peerAddress().family);
    try testing.expectEqual(@as(?u64, null), h.handler.ws.?.rtt());

    var http: TestClient = undefined;
    try http.connectUnix(path);
    defer http.deinit();
    try http.send("GET /hello HTTP/1.1\r\nHost: localhost\r\n\r\n");
    try testing.expect(std.mem.startsWith(u8, try h.head(&http), "HTTP/1.1 200"));

    h.deinit();
    stopped = true;
    try testing.expect(!pathExists(path));
}

test "unix socket: replaces a dead server's file, not a live server's or a regular file" {
    const path = "/tmp/quic-zig-e2e-29622.sock";
    const opts: http1.ListenOptions = .{ .quic_port = 0 };
    const config: http1.Config = .{ .tls = false, .unix_path = path };

    var addr: posix.sockaddr.un = .{ .path = @splat(0) };
    @memcpy(addr.path[0..path.len], path);
    _ = std.c.unlink(path);
    const dead = try sys.socket(posix.AF.UNIX, posix.SOCK.STREAM, 0);
    try sys.bind(dead, @ptrCast(&addr), @sizeOf(posix.sockaddr.un));
    sys.close(dead);
    try testing.expect(pathExists(path));

    var live = try http1.Server.init(testing.allocator, config, opts);
    try testing.expectError(error.AddressInUse, http1.Server.init(testing.allocator, config, opts));
    live.deinit();
    try testing.expect(!pathExists(path));

    const file = std.c.open(path, .{ .ACCMODE = .WRONLY, .CREAT = true }, @as(std.c.mode_t, 0o600));
    try testing.expect(file >= 0);
    sys.close(file);
    defer _ = std.c.unlink(path);
    try testing.expectError(error.AddressInUse, http1.Server.init(testing.allocator, config, opts));
    try testing.expect(pathExists(path));

    const long: [@sizeOf(posix.sockaddr.un)]u8 = @splat('x');
    try testing.expectError(error.NameTooLong, http1.Server.init(testing.allocator, .{ .tls = false, .unix_path = &long }, opts));
    try testing.expectError(error.FileNotFound, http1.Server.init(testing.allocator, .{ .tls = false, .unix_path = "" }, opts));
}

test "ws: rtt() reads the kernel's round trip for the TCP connection" {
    var h: Harness = undefined;
    try h.init(29454, .{ .tls = false });
    defer h.deinit();
    var c: TestClient = .{};
    defer c.deinit();
    try h.upgrade(&c, "/", false);
    try c.sendFrame(.binary, true, "x");
    _ = try h.frame(&c);

    const rtt = h.handler.ws.?.rtt();
    switch (builtin.target.os.tag) {
        // Loopback: a sample under a second, possibly 0 at macOS's ms resolution.
        .linux, .macos => try testing.expect(rtt.? < std.time.ns_per_s),
        else => try testing.expectEqual(@as(?u64, null), rtt),
    }
}

test "ws: a frame split across reads, then two frames in one read" {
    for ([_]bool{ false, true }) |use_tls| {
        var h: Harness = undefined;
        try h.init(if (use_tls) 29451 else 29450, .{ .tls = use_tls });
        defer h.deinit();
        var c: TestClient = .{};
        defer c.deinit();
        try h.upgrade(&c, "/", use_tls);

        // Two masked frames built back to back, then cut mid-way through the
        // first: its head arrives alone, its tail with the whole second one.
        var frames: [2400]u8 = undefined;
        const first: [1000]u8 = @splat(0x61);
        const second: [1200]u8 = @splat(0x62);
        var n: usize = 0;
        n += maskedFrame(frames[n..], .binary, &first).len;
        n += maskedFrame(frames[n..], .binary, &second).len;
        try c.send(frames[0..300]);
        for (0..20) |_| try h.step();
        try c.send(frames[300..n]);

        try testing.expectEqualSlices(u8, &first, (try h.frame(&c)).payload);
        try testing.expectEqualSlices(u8, &second, (try h.frame(&c)).payload);
    }
}

test "ws: rejected, undecided and wrong-version upgrades get HTTP errors" {
    var h: Harness = undefined;
    try h.init(29441, .{ .tls = false });
    defer h.deinit();

    h.handler.mode = .reject_404;
    var a: TestClient = .{};
    defer a.deinit();
    try a.connect(h.port, false);
    try a.sendRequest("/nope", "13", null);
    try testing.expect(std.mem.startsWith(u8, try h.head(&a), "HTTP/1.1 404 "));
    try h.eof(&a);

    h.handler.mode = .undecided;
    var b: TestClient = .{};
    defer b.deinit();
    try b.connect(h.port, false);
    try b.sendRequest("/", "13", null);
    try testing.expect(std.mem.startsWith(u8, try h.head(&b), "HTTP/1.1 403 "));

    var v: TestClient = .{};
    defer v.deinit();
    try v.connect(h.port, false);
    try v.sendRequest("/", "12", null);
    const head = try h.head(&v);
    try testing.expect(std.mem.startsWith(u8, head, "HTTP/1.1 426 "));
    try testing.expect(std.mem.indexOf(u8, head, "Sec-WebSocket-Version: 13\r\n") != null);

    // The handler only saw the two well-formed upgrades, and none opened.
    try testing.expectEqual(@as(u32, 2), h.handler.upgrades);
    try testing.expectEqual(@as(u32, 0), h.handler.closes);
}

test "ws: a dropped connection reports 1006; a server close waits for the peer's" {
    var h: Harness = undefined;
    try h.init(29442, .{ .tls = false });
    defer h.deinit();

    var a: TestClient = .{};
    defer a.deinit();
    try h.upgrade(&a, "/", false);
    a.abort();
    try h.handlerCloses(1);
    try testing.expectEqual(@as(u16, 1006), h.handler.close_code);

    var b: TestClient = .{};
    defer b.deinit();
    try h.upgrade(&b, "/", false);
    try b.sendFrame(.binary, true, "close-me");
    const close = try h.frame(&b);
    try testing.expectEqual(@as(?u16, 4000), close.closeCode());
    try testing.expectEqualStrings("done", close.payload[2..]);
    // Sending after close() fails, and onWsClose waits for the handshake.
    try testing.expectEqual(@as(?event_loop.WsSendError, error.Closed), h.handler.send_after_close);
    try testing.expectEqual(@as(u32, 1), h.handler.closes);
    var p: [125]u8 = undefined;
    try b.sendFrame(.close, true, websocket.closePayload(&p, 4000, ""));
    try h.eof(&b);
    try h.handlerCloses(2);
    try testing.expectEqual(@as(u16, 4000), h.handler.close_code);
}

test "ws: protocol violations close with 1002, 1007 and 1009" {
    var h: Harness = undefined;
    try h.init(29443, .{ .tls = false, .websocket = .{ .max_message_size = 1024 } });
    defer h.deinit();

    const Case = struct { code: u16, frame: []const u8 };
    // Built by hand: an unmasked frame, invalid UTF-8, and a header
    // announcing 2000 bytes.
    const cases = [_]Case{
        .{ .code = 1002, .frame = &.{ 0x82, 0x01, 'x' } },
        .{ .code = 1007, .frame = &.{ 0x81, 0x81, 0, 0, 0, 0, 0xff } },
        .{ .code = 1009, .frame = &.{ 0x82, 0xfe, 0x07, 0xd0, 0, 0, 0, 0 } },
    };
    for (cases, 1..) |case, i| {
        var c: TestClient = .{};
        defer c.deinit();
        try h.upgrade(&c, "/", false);
        try c.send(case.frame);
        const close = try h.frame(&c);
        try testing.expectEqual(@as(?u16, case.code), close.closeCode());
        try h.eof(&c);
        try h.handlerCloses(@intCast(i));
        try testing.expectEqual(case.code, h.handler.close_code);
    }
}

test "ws: stop() sends 1001 and reports it once" {
    var h: Harness = undefined;
    try h.init(29444, .{ .tls = false });
    defer h.deinit();
    var c: TestClient = .{};
    defer c.deinit();
    try h.upgrade(&c, "/", false);

    try testing.expect(!h.server.isStopping());
    h.server.stop();
    try testing.expect(h.server.isStopping());
    const close = try h.frame(&c);
    try testing.expectEqual(@as(?u16, 1001), close.closeCode());
    try h.eof(&c);
    try testing.expectEqual(@as(u32, 1), h.handler.closes);
    try testing.expectEqual(@as(u16, 1001), h.handler.close_code);
}

fn listenerClosed(h: *Harness) bool {
    return h.server.http1_server.?.port() == 0;
}

test "ws: drain() refuses new connections and leaves an open WebSocket working until stop()" {
    var h: Harness = undefined;
    try h.init(29483, .{ .tls = false });
    defer h.deinit();
    var c: TestClient = .{};
    defer c.deinit();
    try h.upgrade(&c, "/", false);

    h.server.drain(.{});
    try h.spinUntil(&h, listenerClosed);
    // Refused by the kernel, rather than accepted only to be closed.
    var late: TestClient = .{};
    defer late.deinit();
    try testing.expectError(error.ConnectionRefused, late.connect(h.port, false));
    try testing.expect(!h.server.isDrained()); // the WebSocket is open

    try c.sendFrame(.binary, true, "still here");
    const echo = try h.frame(&c);
    try testing.expectEqualStrings("still here", echo.payload);
    try testing.expectEqual(@as(u32, 0), h.handler.closes);

    h.server.stop();
    try testing.expectEqual(@as(?u16, 1001), (try h.frame(&c)).closeCode());
    try h.eof(&c);
    try testing.expectEqual(@as(u16, 1001), h.handler.close_code);
}

test "ws: an idle peer gets a ping, and is dropped when it stays silent" {
    var h: Harness = undefined;
    try h.init(29445, .{ .tls = false, .websocket = .{ .ping_interval_ms = 200 } });
    defer h.deinit();
    var c: TestClient = .{};
    defer c.deinit();
    try h.upgrade(&c, "/", false);

    const ping = try h.frame(&c);
    try testing.expectEqual(websocket.Opcode.ping, ping.opcode);
    try h.eof(&c);
    try h.handlerCloses(1);
    try testing.expectEqual(@as(u16, 1006), h.handler.close_code);
}

test "ws: a message that stops making progress is dropped, a slow one is not" {
    // Any byte counted as a sign of life, so a peer that trickled a byte per
    // interval held its unfinished message in memory for good.
    var h: Harness = undefined;
    try h.init(29460, .{ .tls = false, .websocket = .{ .ping_interval_ms = 200 } });
    defer h.deinit();
    var c: TestClient = .{};
    defer c.deinit();
    try h.upgrade(&c, "/", false);

    // 16 KiB over ~0.6 s, well above the floor, spanning several intervals.
    var msg: [16 * 1024]u8 = undefined;
    @memset(&msg, 'm');
    try c.send(&.{ 0x82, 0xfe, 0x40, 0x00, 0, 0, 0, 0 });
    var sent: usize = 0;
    while (sent < msg.len) : (sent += 256) {
        try c.send(msg[sent..][0..256]);
        const next = sys.nanoTimestamp() + 10 * std.time.ns_per_ms;
        while (sys.nanoTimestamp() < next) try h.step();
    }
    const echo = try h.frame(&c);
    try testing.expectEqual(websocket.Opcode.binary, echo.opcode);
    try testing.expectEqual(msg.len, echo.payload.len);

    // A 64 KiB frame fed a byte every 50 ms.
    try c.send(&.{ 0x82, 0xfe, 0xff, 0xff, 0, 0, 0, 0 });
    const deadline = sys.nanoTimestamp() + 3 * std.time.ns_per_s;
    while (!c.eof) {
        if (sys.nanoTimestamp() > deadline) return error.Timeout;
        try c.send("x");
        const next = sys.nanoTimestamp() + 50 * std.time.ns_per_ms;
        while (sys.nanoTimestamp() < next and !c.eof) {
            c.poll();
            try h.step();
        }
    }
    try h.handlerCloses(1);
    try testing.expectEqual(@as(u16, 1006), h.handler.close_code);
}

test "ws: send refuses to queue past max_send_buffer for a peer that isn't reading" {
    var h: Harness = undefined;
    try h.init(29446, .{ .tls = false, .websocket = .{ .max_send_buffer = 256 * 1024 } });
    defer h.deinit();
    var c: TestClient = .{};
    defer c.deinit();
    try h.upgrade(&c, "/", false);

    try c.sendFrame(.binary, true, "flood");
    const W = struct {
        fn done(hh: *Harness) bool {
            return hh.handler.flood_result != null;
        }
    };
    try h.spinUntil(&h, W.done);
    try testing.expectEqual(@as(?event_loop.WsSendError, error.SendBufferFull), h.handler.flood_result);
    try testing.expect(h.handler.ws.?.bufferedAmount() <= 256 * 1024);
}

test "http1: a client that sends but never reads cannot grow the send queue without end" {
    // Pipelined requests were all answered as they came, so a client that
    // never read queued responses until the server ran out of memory.
    var h: Harness = undefined;
    try h.init(29459, .{ .tls = false, .static_dir = "src/http1" });
    defer h.deinit();
    var c: TestClient = .{};
    defer c.deinit();
    try c.connect(h.port, false);

    const req = "GET /missing.txt HTTP/1.1\r\nHost: a\r\n\r\n";
    var reqs: [req.len * 512]u8 = undefined;
    for (0..512) |i| @memcpy(reqs[i * req.len ..][0..req.len], req);
    var off: usize = 0;
    for (0..3000) |_| {
        const rc = std.c.send(c.fd, reqs[off..].ptr, reqs.len - off, 0);
        if (rc > 0) off = (off + @as(usize, @intCast(rc))) % req.len;
        try h.step();
    }
    const conn = h.server.http1_server.?.conns.?;
    try testing.expect(conn.sock.buffered() <= socket.high_water + 16 * 1024);
}

fn corkedSendsLeaveTogether(port: u16, tls: bool) !void {
    var h: Harness = undefined;
    try h.init(port, if (tls) .{} else .{ .tls = false });
    defer h.deinit();
    var c: TestClient = .{};
    defer c.deinit();
    try h.upgrade(&c, "/", tls);
    try c.sendFrame(.text, true, "corked");
    for ([_][]const u8{ "a", "b", "c" }) |want| {
        const f = try h.frame(&c);
        try testing.expectEqualStrings(want, f.payload);
    }
    // Held while corked, then sent in one go: nothing was left queued.
    try testing.expect(h.handler.corked_buffered > 0);
    try testing.expectEqual(@as(usize, 0), h.handler.uncorked_buffered);
}

test "ws: corked sends wait for uncork, then leave in one send, plain and over TLS" {
    try corkedSendsLeaveTogether(29493, false);
    try corkedSendsLeaveTogether(29494, true);
}

test "ws: over TLS, with ALPN http/1.1" {
    var h: Harness = undefined;
    try h.init(29447, .{});
    defer h.deinit();
    var c: TestClient = .{};
    defer c.deinit();
    try h.upgrade(&c, "/tls", true);
    try testing.expectEqualStrings("http/1.1", c.tls.?.alpn().?);

    const big: [3000]u8 = @splat(0x5a);
    try c.sendFrame(.binary, true, &big);
    const echo = try h.frame(&c);
    try testing.expectEqualSlices(u8, &big, echo.payload);

    var p: [125]u8 = undefined;
    try c.sendFrame(.close, true, websocket.closePayload(&p, 1000, ""));
    try testing.expectEqual(@as(?u16, 1000), (try h.frame(&c)).closeCode());
    try h.handlerCloses(1);
}

test "http1: listeners given one ticket key seal tickets with it; others draw their own" {
    // Equal keys are what lets one resume another's session: see tls/server.zig.
    const key: [16]u8 = @splat(0x4b);
    var shared: Pair = undefined;
    try shared.init(29453, .{ .ticket_key = key });
    defer shared.deinit();
    try testing.expectEqual(key, shared.a.server.http1_server.?.tlsConfig().?.ticket_key.?);
    try testing.expectEqual(key, shared.b.server.http1_server.?.tlsConfig().?.ticket_key.?);

    var own: Pair = undefined;
    try own.init(29455, .{});
    defer own.deinit();
    const a = own.a.server.http1_server.?.tlsConfig().?.ticket_key.?;
    try testing.expect(!std.mem.eql(u8, &a, &own.b.server.http1_server.?.tlsConfig().?.ticket_key.?));
}

test "http1: static files with keep-alive, HEAD, 404 and 403 on the WebSocket listener" {
    var h: Harness = undefined;
    try h.init(29448, .{ .tls = false, .static_dir = "src/http1" });
    defer h.deinit();
    const expected = try sys.readFileAlloc(testing.allocator, "src/http1/parser.zig", 1 << 20);
    defer testing.allocator.free(expected);

    var c: TestClient = .{};
    defer c.deinit();
    try c.connect(h.port, false);
    // Two requests in one write: pipelined, answered in order.
    try c.send("GET /parser.zig HTTP/1.1\r\nHost: a\r\n\r\nHEAD /parser.zig HTTP/1.1\r\nHost: a\r\n\r\n");
    const get = try h.head(&c);
    try testing.expect(std.mem.startsWith(u8, get, "HTTP/1.1 200 OK\r\n"));
    try testing.expect(std.mem.indexOf(u8, get, "Alt-Svc: h3=\":29448\"") != null);
    try testing.expectEqualStrings(expected, try h.bytes(&c, expected.len));
    const head = try h.head(&c);
    try testing.expect(std.mem.startsWith(u8, head, "HTTP/1.1 200 OK\r\n"));

    // Same connection: errors keep it alive too.
    try c.send("GET /missing.txt HTTP/1.1\r\nHost: a\r\n\r\n");
    const missing = try h.head(&c);
    try testing.expect(std.mem.startsWith(u8, missing, "HTTP/1.1 404 "));
    _ = try h.bytes(&c, "Not found".len);
    try c.send("GET /../build.zig HTTP/1.1\r\nHost: a\r\n\r\n");
    try testing.expect(std.mem.startsWith(u8, try h.head(&c), "HTTP/1.1 403 "));
    _ = try h.bytes(&c, "Forbidden".len);

    try c.send("POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 0\r\n\r\n");
    try testing.expect(std.mem.startsWith(u8, try h.head(&c), "HTTP/1.1 405 "));
    try h.eof(&c);
}

/// Opens a WebTransport stream, sends "wt-ping", and keeps the echo.
const WtEchoClient = struct {
    pub const protocol: event_loop.Protocol = .webtransport;
    echo_buf: [32]u8 = undefined,
    echo_len: usize = 0,

    pub fn onSessionReady(_: *WtEchoClient, session: *event_loop.ClientSession, session_id: u64) void {
        const sid = session.openBidiStream(session_id, null) catch return;
        session.sendStreamData(sid, "wt-ping") catch return;
    }

    pub fn onStreamData(self: *WtEchoClient, _: *event_loop.ClientSession, _: u64, data: []const u8, _: bool) void {
        const n = @min(data.len, self.echo_buf.len - self.echo_len);
        @memcpy(self.echo_buf[self.echo_len..][0..n], data[0..n]);
        self.echo_len += n;
    }

    fn done(self: *WtEchoClient) bool {
        return self.echo_len >= "wt-ping".len;
    }
};

test "ws: a WebTransport client and a WebSocket client share one handler and loop" {
    var h: Harness = undefined;
    try h.init(29449, .{});
    defer h.deinit();

    var wh = WtEchoClient{};
    var wt_client = try event_loop.Client(WtEchoClient).init(testing.allocator, &wh, .{
        .port = h.port,
        .skip_cert_verify = true,
        .loop = &h.loop,
    });
    wt_client.start();
    defer {
        wt_client.stop();
        const S = struct {
            fn done(cl: *event_loop.Client(WtEchoClient)) bool {
                return cl.isStopped();
            }
        };
        h.spinUntil(&wt_client, S.done) catch {};
        wt_client.deinit();
    }

    var c: TestClient = .{};
    defer c.deinit();
    try h.upgrade(&c, "/mixed", true);
    try c.sendFrame(.binary, true, "ws-ping");
    try testing.expectEqualStrings("ws-ping", (try h.frame(&c)).payload);

    try h.spinUntil(&wh, WtEchoClient.done);
    try testing.expectEqualStrings("wt-ping", wh.echo_buf[0..wh.echo_len]);

    // One counter for both: the WebSocket's id is no session's.
    try testing.expectEqual(@as(usize, 1), h.handler.wt_sessions);
    try testing.expect(h.handler.ws_id != h.handler.wt_session_ids[0]);
    try testing.expect(h.server.passes > 0 and h.server.pass_ns > 0);
}

test "ws: handed over to a server on another loop, with the message behind the move" {
    for ([_]bool{ false, true }) |use_tls| {
        var p: Pair = undefined;
        try p.init(if (use_tls) 29472 else 29470, .{ .tls = use_tls });
        defer p.deinit();
        var c: TestClient = .{};
        defer c.deinit();
        try p.a.upgrade(&c, "/", use_tls);
        try c.sendFrame(.binary, true, "before");
        try testing.expectEqualStrings("before", (try p.frame(&c)).payload);

        // In one write, so the first server reads both and delivers one.
        var frames: [64]u8 = undefined;
        var n = maskedFrame(&frames, .binary, "move").len;
        n += maskedFrame(frames[n..], .binary, "behind").len;
        try c.send(frames[0..n]);
        try testing.expectEqualStrings("behind", (try p.frame(&c)).payload);
        try testing.expectEqual(@as(u32, 1), p.adopted);
        try testing.expectEqual(p.a.handler.ws_id, p.b.handler.ws.?.id());
        try c.sendFrame(.binary, true, "after");
        try testing.expectEqualStrings("after", (try p.frame(&c)).payload);
        try testing.expectEqual(@as(usize, 0), p.a.server.http1_server.?.conn_count);
        try testing.expectEqual(@as(usize, 1), p.b.server.http1_server.?.ws_count);
        // Its ping timer went with it.
        try testing.expect(p.a.server.http1_server.?.timers.head == null);
        try testing.expect(p.b.server.http1_server.?.timers.head != null);

        var cp: [125]u8 = undefined;
        try c.sendFrame(.close, true, websocket.closePayload(&cp, 1000, ""));
        try testing.expectEqual(@as(?u16, 1000), (try p.frame(&c)).closeCode());
        try p.closesOnB(1);
        try testing.expectEqual(@as(u32, 0), p.a.handler.closes);
    }
}

test "ws: a handover waits out a write in flight, and the new server sends the rest" {
    // Asked for with a write in flight, or once the flood drained enough for
    // the next message to be read. `Pair.step` checks nothing was in flight
    // when it moved.
    for ([_]bool{ true, false }) |at_once| {
        var p: Pair = undefined;
        try p.init(29474, .{ .tls = false });
        defer p.deinit();
        var c: TestClient = .{};
        defer c.deinit();
        try p.a.upgrade(&c, "/", false);
        if (at_once) {
            try c.sendFrame(.binary, true, "flood, move");
        } else {
            try c.sendFrame(.binary, true, "flood");
            try c.sendFrame(.binary, true, "move");
        }
        try c.sendFrame(.binary, true, "behind");
        try expectFloodThenBehind(&p, &c);
        try testing.expect(p.a.handler.flood_result != null);
    }
}

fn expectFloodThenBehind(p: *Pair, c: *TestClient) !void {
    var floods: usize = 0;
    while (true) {
        const f = try p.frame(c);
        if (f.payload.len != 16 * 1024) {
            try testing.expectEqualStrings("behind", f.payload);
            break;
        }
        floods += 1;
    }
    try testing.expectEqual(p.a.handler.flood_sent, floods);
    try testing.expectEqual(@as(u32, 1), p.adopted);
}

test "ws: a peer that drops while handed over is closed by the new server" {
    var p: Pair = undefined;
    try p.init(29480, .{ .tls = false });
    defer p.deinit();
    var c: TestClient = .{};
    defer c.deinit();
    try p.a.upgrade(&c, "/", false);
    try c.sendFrame(.binary, true, "move");
    c.abort();
    try p.closesOnB(1);
    try testing.expectEqual(@as(u16, 1006), p.b.handler.close_code);
    try testing.expectEqual(@as(u32, 1), p.adopted);
    try testing.expectEqual(@as(u32, 0), p.a.handler.closes);
}

test "ws: handOver only from onWsMessage; a discarded handover ends the connection" {
    var h: Harness = undefined;
    try h.init(29478, .{ .tls = false });
    defer h.deinit();
    var c: TestClient = .{};
    defer c.deinit();
    try h.upgrade(&c, "/", false);
    try testing.expectError(error.NotInMessage, h.handler.ws.?.handOver());

    try c.sendFrame(.binary, true, "move");
    const W = struct {
        fn done(hh: *Harness) bool {
            return hh.handler.handed != null;
        }
    };
    try h.spinUntil(&h, W.done);
    try testing.expectEqual(@as(usize, 0), h.server.http1_server.?.conn_count);
    h.handler.handed.?.discard();
    try h.eof(&c);
    try testing.expectEqual(@as(u32, 0), h.handler.closes);
}

test "ws: a server that stops while a WebSocket waits to move closes it there" {
    var h: Harness = undefined;
    try h.init(29479, .{ .tls = false });
    defer h.deinit();
    var c: TestClient = .{};
    defer c.deinit();
    try h.upgrade(&c, "/", false);
    try c.sendFrame(.binary, true, "move");
    // The loop iteration that reads the move lets go of it on a later one.
    const conn = h.server.http1_server.?.conns.?;
    const deadline = sys.nanoTimestamp() + 10 * std.time.ns_per_s;
    while (conn.phase != .moving) {
        if (sys.nanoTimestamp() > deadline) return error.Timeout;
        c.poll();
        try h.loop.run(.no_wait);
    }

    h.server.stop();
    try h.handlerCloses(1);
    try testing.expectEqual(@as(u16, 1001), h.handler.close_code);
    for (0..20) |_| try h.step();
    try testing.expect(h.handler.handed == null);
}

test "http1: onHttpRequest answers what it takes; the rest goes to the static files" {
    var h: Harness = undefined;
    try h.init(29482, .{ .tls = false, .static_dir = "src/http1" });
    defer h.deinit();
    var c: TestClient = .{};
    defer c.deinit();
    try c.connect(h.port, false);

    try c.send("GET /hello HTTP/1.1\r\nHost: a\r\n\r\n");
    const head = try h.head(&c);
    try testing.expect(std.mem.startsWith(u8, head, "HTTP/1.1 200 OK\r\n"));
    try testing.expect(std.mem.indexOf(u8, head, "Content-Type: text/plain\r\n") != null);
    try testing.expectEqualStrings("hi there", try h.bytes(&c, 8));

    // Same connection: HEAD has no body, and an unanswered path is a file.
    try c.send("HEAD /hello HTTP/1.1\r\nHost: a\r\n\r\n");
    try testing.expect(std.mem.indexOf(u8, try h.head(&c), "Content-Length: 8\r\n") != null);
    try c.send("GET /missing.txt HTTP/1.1\r\nHost: a\r\n\r\n");
    try testing.expect(std.mem.startsWith(u8, try h.head(&c), "HTTP/1.1 404 "));

    // respondWith adds its own header lines.
    try c.send("GET /cors HTTP/1.1\r\nHost: a\r\n\r\n");
    const cors = try h.head(&c);
    try testing.expect(std.mem.indexOf(u8, cors, "Content-Type: application/json\r\nContent-Length: 2\r\nAccess-Control-Allow-Origin: *\r\n") != null);
    try testing.expectEqualStrings("[]", try h.bytes(&c, 2));
}

// ─── Raw connections ─────────────────────────────────────────────────

/// Serves what the server doesn't answer itself: echoes it, and records
/// what it saw. "close" asks for a goodbye and a close; "big" for writes
/// until they queue past high water.
const RawHandler = struct {
    pub const protocol: event_loop.Protocol = .webtransport;

    raw: ?*event_loop.RawConn = null,
    opens: u32 = 0,
    closes: u32 = 0,
    drains: u32 = 0,
    ends: u32 = 0,
    /// Close on the peer's end, as Node's http.Server does by default; off,
    /// the connection stays open for a reply to a half-closed peer.
    close_on_end: bool = true,
    /// Bytes the "big" writes made, `bufferedAmount` after them, and at `onRawDrain`.
    big_written: usize = 0,
    queued_after_big: usize = 0,
    queued_at_drain: usize = 0,
    pause_on_open: bool = false,
    received: std.ArrayList(u8) = .empty,

    pub fn onWsUpgrade(_: *RawHandler, req: *WsRequest, _: []const u8) void {
        _ = req.accept(.{}) catch {};
    }

    pub fn onHttpRequest(_: *RawHandler, req: *event_loop.HttpRequest, target: []const u8) void {
        if (std.mem.eql(u8, target, "/hello")) req.respond(200, "text/plain", "hi");
    }

    pub fn onRawOpen(self: *RawHandler, raw: *event_loop.RawConn) void {
        self.opens += 1;
        self.raw = raw;
        if (self.pause_on_open) raw.pauseReading();
    }

    pub fn onRawData(self: *RawHandler, raw: *event_loop.RawConn, data: []const u8) void {
        self.received.appendSlice(testing.allocator, data) catch unreachable;
        if (std.mem.endsWith(u8, data, "close")) {
            raw.write("bye") catch unreachable;
            return raw.close();
        }
        if (std.mem.endsWith(u8, data, "corked")) {
            // Past low water while corked: a drain is owed, and the uncork
            // that sends it all must still pay it.
            const chunk: [16 * 1024]u8 = @splat('c');
            raw.cork();
            while (raw.bufferedAmount() < socket.low_water) {
                raw.write(&chunk) catch unreachable;
                self.big_written += chunk.len;
            }
            self.queued_after_big = raw.bufferedAmount();
            raw.uncork();
            return;
        }
        if (std.mem.endsWith(u8, data, "big")) {
            // Until something queues: the kernel's buffers take the first
            // megabytes on loopback, however many that is.
            const chunk: [64 * 1024]u8 = @splat('b');
            while (raw.bufferedAmount() <= socket.high_water and self.big_written < 64 << 20) {
                raw.write(&chunk) catch unreachable;
                self.big_written += chunk.len;
            }
            self.queued_after_big = raw.bufferedAmount();
            return;
        }
        raw.write(data) catch unreachable;
    }

    pub fn onRawClose(self: *RawHandler, raw: *event_loop.RawConn) void {
        self.closes += 1;
        if (self.raw == raw) self.raw = null;
    }

    pub fn onRawEnd(self: *RawHandler, raw: *event_loop.RawConn) void {
        self.ends += 1;
        if (self.close_on_end) raw.close();
    }

    pub fn onRawDrain(self: *RawHandler, raw: *event_loop.RawConn) void {
        self.drains += 1;
        self.queued_at_drain = raw.bufferedAmount();
    }
};

const RawHarness = HarnessFor(RawHandler);

fn rawOpened(h: *RawHarness) bool {
    return h.handler.opens > 0;
}

test "http1: what the handler doesn't answer reaches onRawOpen as bytes, request line first, with its connection" {
    var h: RawHarness = undefined;
    try h.init(29484, .{ .tls = false });
    defer h.deinit();
    defer h.handler.received.deinit(testing.allocator);
    var c: TestClient = .{};
    defer c.deinit();
    try c.connect(h.port, false);

    // onHttpRequest still answers first, and the connection stays the server's.
    try c.send("GET /hello HTTP/1.1\r\nHost: a\r\n\r\n");
    try testing.expect(std.mem.startsWith(u8, try h.head(&c), "HTTP/1.1 200 OK\r\n"));
    try testing.expectEqualStrings("hi", try h.bytes(&c, 2));
    try testing.expectEqual(@as(u32, 0), h.handler.opens);

    // A method and a body the server can't serve itself.
    const post = "POST /matchmake/joinOrCreate/room HTTP/1.1\r\nHost: a\r\nContent-Length: 7\r\n\r\n{\"a\":1}";
    try c.send(post);
    try testing.expectEqualStrings(post, try h.bytes(&c, post.len));
    try testing.expectEqual(@as(u32, 1), h.handler.opens);

    // From here on everything is the handler's, even what the server would answer.
    const get = "GET /hello HTTP/1.1\r\nHost: a\r\n\r\n";
    try c.send(get);
    try testing.expectEqualStrings(get, try h.bytes(&c, get.len));
    try testing.expectEqualStrings(post ++ get, h.handler.received.items);
    try testing.expectEqual(@as(u32, 1), h.handler.opens);

    // An upgrade on another connection is still a WebSocket.
    var ws: TestClient = .{};
    defer ws.deinit();
    try ws.connect(h.port, false);
    try ws.sendRequest("/", "13", null);
    try testing.expect(std.mem.startsWith(u8, try h.head(&ws), "HTTP/1.1 101 Switching Protocols\r\n"));
    try testing.expectEqual(@as(u32, 1), h.handler.opens);
}

test "http1: a raw connection's close sends what was queued first; a peer's end reports it too" {
    var h: RawHarness = undefined;
    try h.init(29485, .{ .tls = false });
    defer h.deinit();
    defer h.handler.received.deinit(testing.allocator);

    var c: TestClient = .{};
    defer c.deinit();
    try c.connect(h.port, false);
    try c.send("DELETE /x HTTP/1.1\r\nHost: a\r\nContent-Length: 5\r\n\r\nclose");
    try testing.expectEqualStrings("bye", try h.bytes(&c, 3));
    try h.eof(&c);
    try h.handlerCloses(1);

    var d: TestClient = .{};
    defer d.deinit();
    try d.connect(h.port, false);
    try d.send("PUT /y HTTP/1.1\r\nHost: a\r\nContent-Length: 2\r\n\r\nhi");
    try h.spinUntil(&h, rawOpened);
    d.abort();
    try h.handlerCloses(2);
    try testing.expect(h.handler.raw == null);
    try testing.expectEqual(@as(u32, 1), h.handler.ends);
}

test "http1: pauseReading holds input back until resumeReading" {
    var h: RawHarness = undefined;
    try h.init(29486, .{ .tls = false });
    defer h.deinit();
    defer h.handler.received.deinit(testing.allocator);
    h.handler.pause_on_open = true;

    var c: TestClient = .{};
    defer c.deinit();
    try c.connect(h.port, false);
    const req = "POST /up HTTP/1.1\r\nHost: a\r\nContent-Length: 4\r\n\r\nbody";
    try c.send(req);
    try h.spinUntil(&h, rawOpened);
    for (0..50) |_| try h.step();
    try testing.expectEqual(@as(usize, 0), h.handler.received.items.len);

    h.handler.raw.?.resumeReading();
    try testing.expectEqualStrings(req, try h.bytes(&c, req.len));
    try testing.expectEqualStrings(req, h.handler.received.items);
}

test "http1: a raw write that queues owes onRawDrain, paid once the peer reads it down" {
    var h: RawHarness = undefined;
    try h.init(29487, .{ .tls = false });
    defer h.deinit();
    defer h.handler.received.deinit(testing.allocator);

    var c: TestClient = .{};
    defer c.deinit();
    try c.connect(h.port, false);
    try c.send("POST /dl HTTP/1.1\r\nHost: a\r\nContent-Length: 3\r\n\r\nbig");
    try h.spinUntil(&h, rawOpened);
    try testing.expect(h.handler.queued_after_big > socket.high_water);
    try testing.expect(h.handler.raw.?.owesDrain());

    _ = try h.bytes(&c, h.handler.big_written);
    const W = struct {
        fn done(hh: *RawHarness) bool {
            return hh.handler.drains > 0;
        }
    };
    try h.spinUntil(&h, W.done);
    for (0..20) |_| try h.step();
    try testing.expectEqual(@as(u32, 1), h.handler.drains);
    try testing.expect(h.handler.queued_at_drain < socket.low_water);
    try testing.expect(!h.handler.raw.?.owesDrain());
}

test "http1: a corked raw write past low water still owes onRawDrain, paid after the uncork" {
    var h: RawHarness = undefined;
    try h.init(29495, .{ .tls = false });
    defer h.deinit();
    defer h.handler.received.deinit(testing.allocator);

    var c: TestClient = .{};
    defer c.deinit();
    try c.connect(h.port, false);
    try c.send("POST /c HTTP/1.1\r\nHost: a\r\nContent-Length: 6\r\n\r\ncorked");
    try h.spinUntil(&h, rawOpened);
    try testing.expect(h.handler.queued_after_big >= socket.low_water);

    _ = try h.bytes(&c, h.handler.big_written);
    const W = struct {
        fn done(hh: *RawHarness) bool {
            return hh.handler.drains > 0;
        }
    };
    try h.spinUntil(&h, W.done);
    try testing.expectEqual(@as(u32, 1), h.handler.drains);
    try testing.expect(!h.handler.raw.?.owesDrain());
}

test "http1: raw connections over TLS hold drain() open and end at stop()" {
    var h: RawHarness = undefined;
    try h.init(29488, .{});
    defer h.deinit();
    defer h.handler.received.deinit(testing.allocator);

    var c: TestClient = .{};
    defer c.deinit();
    try c.connect(h.port, true);
    try h.handshake(&c);
    const req = "PATCH /tls HTTP/1.1\r\nHost: a\r\nContent-Length: 3\r\n\r\nabc";
    try c.send(req);
    try testing.expectEqualStrings(req, try h.bytes(&c, req.len));

    h.server.drain(.{});
    for (0..20) |_| try h.step();
    try testing.expect(!h.server.isDrained());
    try testing.expectEqual(@as(u32, 0), h.handler.closes);

    h.server.stop();
    try h.eof(&c);
    try h.handlerCloses(1);
}

fn replyAfterHalfClose(port: u16, h1: event_loop.Http1Config, use_tls: bool) !void {
    var h: RawHarness = undefined;
    try h.init(port, h1);
    defer h.deinit();
    defer h.handler.received.deinit(testing.allocator);
    h.handler.close_on_end = false;
    var c: TestClient = .{};
    defer c.deinit();
    try c.connect(h.port, use_tls);
    if (use_tls) try h.handshake(&c);

    const req = "POST /half HTTP/1.1\r\nHost: a\r\nContent-Length: 2\r\n\r\nhi";
    try c.send(req);
    try testing.expectEqualStrings(req, try h.bytes(&c, req.len));
    c.halfClose();
    for (0..30) |_| try h.step();
    try testing.expectEqual(@as(u32, 0), h.handler.closes);
    try testing.expectEqual(@as(u32, 1), h.handler.ends);

    h.handler.raw.?.write("late reply") catch unreachable;
    h.handler.raw.?.close();
    try testing.expectEqualStrings("late reply", try h.bytes(&c, 10));
    try h.eof(&c);
    try h.handlerCloses(1);
}

test "http1: a raw connection's peer may half-close and still get the handler's reply" {
    try replyAfterHalfClose(29489, .{ .tls = false }, false);
    try replyAfterHalfClose(29490, .{}, true);
}

test "http1: a raw connection's abort drops what was queued, and onRawClose follows" {
    var h: RawHarness = undefined;
    try h.init(29492, .{ .tls = false });
    defer h.deinit();
    defer h.handler.received.deinit(testing.allocator);
    var c: TestClient = .{};
    defer c.deinit();
    try c.connect(h.port, false);

    try c.send("POST /dl HTTP/1.1\r\nHost: a\r\nContent-Length: 3\r\n\r\nbig");
    try h.spinUntil(&h, rawOpened);
    try testing.expect(h.handler.queued_after_big > socket.high_water);

    h.handler.raw.?.abort();
    try testing.expectEqual(@as(u32, 0), h.handler.closes); // never from inside the call
    try h.eof(&c);
    // What was queued never left; only what the kernel already had arrived.
    try testing.expect(c.in.items.len + h.handler.queued_after_big <= h.handler.big_written);
    try h.handlerCloses(1);
}

/// Takes every request as an exchange: answers "/now" inside the callback,
/// passes "/raw" there, and leaves the rest pending for the test.
const ExchangeHandler = struct {
    pub const protocol: event_loop.Protocol = .webtransport;

    offers: u32 = 0,
    gone: u32 = 0,
    pending: ?*event_loop.HttpExchange = null,
    target_buf: [64]u8 = undefined,
    target_len: usize = 0,
    body_buf: [64]u8 = undefined,
    body_len: usize = 0,
    method_buf: [8]u8 = undefined,
    method_len: usize = 0,
    raw_opens: u32 = 0,
    raw_received: std.ArrayList(u8) = .empty,

    pub fn onWsUpgrade(_: *ExchangeHandler, req: *WsRequest, _: []const u8) void {
        _ = req.accept(.{}) catch {};
    }

    pub fn onHttpExchange(self: *ExchangeHandler, ex: *event_loop.HttpExchange) void {
        self.offers += 1;
        self.target_len = @min(ex.target().len, self.target_buf.len);
        @memcpy(self.target_buf[0..self.target_len], ex.target()[0..self.target_len]);
        self.body_len = @min(ex.body().len, self.body_buf.len);
        @memcpy(self.body_buf[0..self.body_len], ex.body()[0..self.body_len]);
        self.method_len = @min(ex.method().len, self.method_buf.len);
        @memcpy(self.method_buf[0..self.method_len], ex.method()[0..self.method_len]);
        if (std.mem.eql(u8, ex.target(), "/now")) return ex.respond(200, "Content-Type: text/plain\r\n", "now");
        if (std.mem.eql(u8, ex.target(), "/raw")) return ex.pass();
        self.pending = ex;
    }

    pub fn onHttpExchangeGone(self: *ExchangeHandler, ex: *event_loop.HttpExchange) void {
        self.gone += 1;
        if (self.pending == ex) self.pending = null;
    }

    pub fn onRawOpen(self: *ExchangeHandler, _: *event_loop.RawConn) void {
        self.raw_opens += 1;
    }

    pub fn onRawData(self: *ExchangeHandler, _: *event_loop.RawConn, data: []const u8) void {
        self.raw_received.appendSlice(testing.allocator, data) catch unreachable;
    }

    pub fn onRawClose(_: *ExchangeHandler, _: *event_loop.RawConn) void {}

    fn target(self: *const ExchangeHandler) []const u8 {
        return self.target_buf[0..self.target_len];
    }
};

const ExchangeHarness = HarnessFor(ExchangeHandler);

fn offeredTwice(h: *ExchangeHarness) bool {
    return h.handler.offers >= 2;
}

fn exchangePending(h: *ExchangeHarness) bool {
    return h.handler.pending != null;
}

test "http1: an exchange is answered after its callback, then the request pipelined behind it is offered" {
    var h: ExchangeHarness = undefined;
    try h.init(29496, .{ .tls = false });
    defer h.deinit();
    var c: TestClient = .{};
    defer c.deinit();
    try c.connect(h.port, false);

    try c.send("POST /a HTTP/1.1\r\nHost: x\r\nContent-Length: 2\r\n\r\nhiGET /b HTTP/1.1\r\nHost: x\r\n\r\n");
    try h.spinUntil(&h, exchangePending);
    try testing.expectEqualStrings("POST", h.handler.method_buf[0..h.handler.method_len]);
    try testing.expectEqualStrings("/a", h.handler.target());
    try testing.expectEqualStrings("hi", h.handler.body_buf[0..h.handler.body_len]);
    // The second waits for the first's answer.
    for (0..20) |_| try h.step();
    try testing.expectEqual(@as(u32, 1), h.handler.offers);

    const first = h.handler.pending.?;
    h.handler.pending = null;
    first.respond(201, "Content-Type: text/plain\r\nX-Test: 1\r\n", "made");
    const head1 = try h.head(&c);
    try testing.expect(std.mem.startsWith(u8, head1, "HTTP/1.1 201 Created\r\n"));
    try testing.expect(std.mem.indexOf(u8, head1, "Content-Length: 4\r\n") != null);
    try testing.expect(std.mem.indexOf(u8, head1, "X-Test: 1\r\n") != null);
    try testing.expectEqualStrings("made", try h.bytes(&c, 4));

    try h.spinUntil(&h, exchangePending);
    try testing.expectEqualStrings("/b", h.handler.target());
    try testing.expectEqual(@as(usize, 0), h.handler.body_len);
    h.handler.pending.?.respond(200, "", "");
    const head2 = try h.head(&c);
    try testing.expect(std.mem.startsWith(u8, head2, "HTTP/1.1 200 OK\r\n"));
    try testing.expectEqual(@as(u32, 0), h.handler.gone);
}

test "http1: an exchange answered inside its callback, and passed ones reach the raw handler whole" {
    var h: ExchangeHarness = undefined;
    try h.init(29497, .{ .tls = false });
    defer h.deinit();
    defer h.handler.raw_received.deinit(testing.allocator);

    var a: TestClient = .{};
    defer a.deinit();
    try a.connect(h.port, false);
    try a.send("GET /now HTTP/1.1\r\nHost: x\r\n\r\n");
    try testing.expect(std.mem.startsWith(u8, try h.head(&a), "HTTP/1.1 200 OK\r\n"));
    try testing.expectEqualStrings("now", try h.bytes(&a, 3));

    // Passed inside the callback.
    const raw_req = "POST /raw HTTP/1.1\r\nHost: x\r\nContent-Length: 3\r\n\r\nabc";
    var b: TestClient = .{};
    defer b.deinit();
    try b.connect(h.port, false);
    try b.send(raw_req);
    const W = struct {
        fn got(hh: *ExchangeHarness, n: usize) bool {
            return hh.handler.raw_received.items.len >= n;
        }
        fn first(hh: *ExchangeHarness) bool {
            return got(hh, raw_req.len);
        }
        fn both(hh: *ExchangeHarness) bool {
            return got(hh, 2 * raw_req.len - "/raw".len + "/later".len);
        }
    };
    try h.spinUntil(&h, W.first);
    try testing.expectEqualStrings(raw_req, h.handler.raw_received.items);

    // Passed after it.
    var d: TestClient = .{};
    defer d.deinit();
    try d.connect(h.port, false);
    const later_req = "POST /later HTTP/1.1\r\nHost: x\r\nContent-Length: 3\r\n\r\nabc";
    try d.send(later_req);
    try h.spinUntil(&h, exchangePending);
    h.handler.pending.?.pass();
    h.handler.pending = null;
    try h.spinUntil(&h, W.both);
    try testing.expectEqualStrings(later_req, h.handler.raw_received.items[raw_req.len..]);
    try testing.expectEqual(@as(u32, 2), h.handler.raw_opens);
}

test "http1: a chunked request isn't offered; a half-closed peer still gets its answer; stop() ends a pending one" {
    var h: ExchangeHarness = undefined;
    try h.init(29498, .{ .tls = false });
    defer h.deinit();
    defer h.handler.raw_received.deinit(testing.allocator);

    var a: TestClient = .{};
    defer a.deinit();
    try a.connect(h.port, false);
    try a.send("POST /up HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n");
    const W = struct {
        fn rawOpened(hh: *ExchangeHarness) bool {
            return hh.handler.raw_opens > 0;
        }
        fn isGone(hh: *ExchangeHarness) bool {
            return hh.handler.gone > 0;
        }
    };
    try h.spinUntil(&h, W.rawOpened);
    try testing.expectEqual(@as(u32, 0), h.handler.offers);

    // TCP can't tell a half-close from a peer that left: it waits.
    var b: TestClient = .{};
    defer b.deinit();
    try b.connect(h.port, false);
    try b.send("GET /half HTTP/1.1\r\nHost: x\r\n\r\n");
    try h.spinUntil(&h, exchangePending);
    b.halfClose();
    for (0..20) |_| try h.step();
    try testing.expectEqual(@as(u32, 0), h.handler.gone);
    h.handler.pending.?.respond(200, "", "late");
    h.handler.pending = null;
    const head = try h.head(&b);
    try testing.expect(std.mem.indexOf(u8, head, "Connection: close\r\n") != null);
    try testing.expectEqualStrings("late", try h.bytes(&b, 4));
    try h.eof(&b);

    var c: TestClient = .{};
    defer c.deinit();
    try c.connect(h.port, false);
    try c.send("GET /wait HTTP/1.1\r\nHost: x\r\n\r\n");
    try h.spinUntil(&h, exchangePending);
    h.server.stop();
    try h.spinUntil(&h, W.isGone);
    try testing.expect(h.handler.pending == null);
}

test "http1: an exchange over TLS, answered after its callback" {
    var h: ExchangeHarness = undefined;
    try h.init(29499, .{});
    defer h.deinit();
    var c: TestClient = .{};
    defer c.deinit();
    try c.connect(h.port, true);
    try h.handshake(&c);
    try c.send("POST /tls HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\nhello");
    try h.spinUntil(&h, exchangePending);
    try testing.expectEqualStrings("hello", h.handler.body_buf[0..h.handler.body_len]);
    h.handler.pending.?.respond(200, "Content-Type: text/plain\r\n", "ok");
    h.handler.pending = null;
    try testing.expect(std.mem.startsWith(u8, try h.head(&c), "HTTP/1.1 200 OK\r\n"));
    try testing.expectEqualStrings("ok", try h.bytes(&c, 2));
}
