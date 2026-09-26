//! End-to-end tests of the HTTP/1.1 listener inside `event_loop.Server`:
//! WebSockets and static files, plain and over TLS, next to WebTransport on
//! the same handler and loop. The client side is a plain socket driven from
//! the test, between non-blocking runs of the loop.

const std = @import("std");
const posix = std.posix;
const testing = std.testing;
const sys = @import("../sys.zig");
const net = @import("../sockaddr.zig");
const event_loop = @import("../event_loop.zig");
const tls13 = @import("../quic/tls13.zig");
const tls_client = @import("../tls/client.zig");
const test_certs = @import("../tls/test_certs.zig");
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
        if (std.mem.eql(u8, data, "flood")) {
            var chunk: [16 * 1024]u8 = undefined;
            @memset(&chunk, 'f');
            for (0..4096) |_| {
                ws.send(&chunk) catch |err| {
                    self.flood_result = err;
                    return;
                };
            }
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

/// A server on a loop the test owns, with real certificates so TLS over
/// TCP works as well as QUIC.
const Harness = struct {
    loop: xev.Loop,
    certs: test_certs.TestCerts,
    handler: EchoHandler,
    server: event_loop.Server(EchoHandler),
    port: u16,

    /// In place: the server keeps pointers into `self` once started.
    fn init(self: *Harness, port: u16, h1: event_loop.Http1Config) !void {
        self.port = port;
        self.handler = .{};
        try self.certs.load();
        self.loop = try xev.Loop.init(.{});
        errdefer self.loop.deinit();
        self.server = try event_loop.Server(EchoHandler).init(testing.allocator, &self.handler, .{
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

    fn deinit(self: *Harness) void {
        self.server.stop();
        self.spinUntil(self, stopped) catch @panic("server did not stop");
        self.server.deinit();
        self.loop.deinit();
    }

    fn stopped(self: *Harness) bool {
        return self.server.isStopped();
    }

    fn step(self: *Harness) !void {
        try self.loop.run(.no_wait);
        sys.sleepNs(50 * std.time.ns_per_us);
    }

    fn spinUntil(self: *Harness, ctx: anytype, comptime done: fn (@TypeOf(ctx)) bool) !void {
        const deadline = sys.nanoTimestamp() + 10 * std.time.ns_per_s;
        while (!done(ctx)) {
            if (sys.nanoTimestamp() > deadline) return error.Timeout;
            try self.step();
        }
    }

    /// The next response head from `c`.
    fn head(self: *Harness, c: *TestClient) ![]const u8 {
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
    fn bytes(self: *Harness, c: *TestClient, n: usize) ![]const u8 {
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
    fn frame(self: *Harness, c: *TestClient) !ServerFrame {
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
    fn eof(self: *Harness, c: *TestClient) !void {
        const deadline = sys.nanoTimestamp() + 10 * std.time.ns_per_s;
        while (!c.eof) {
            c.poll();
            if (sys.nanoTimestamp() > deadline) return error.Timeout;
            try self.step();
        }
    }

    fn handlerCloses(self: *Harness, n: u32) !void {
        const W = struct {
            h: *Harness,
            n: u32,
            fn done(w: *const @This()) bool {
                return w.h.handler.closes >= w.n;
            }
        };
        try self.spinUntil(&W{ .h = self, .n = n }, W.done);
    }

    /// Connects, upgrades, and checks the 101 and the greeting.
    fn upgrade(self: *Harness, c: *TestClient, path: []const u8, use_tls: bool) !void {
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

    fn handshake(self: *Harness, c: *TestClient) !void {
        const deadline = sys.nanoTimestamp() + 10 * std.time.ns_per_s;
        while (!c.tls.?.handshakeComplete()) {
            c.poll();
            if (c.eof) return error.EndOfStream;
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
            self.tls_config = .{ .server_name = "localhost", .alpn = &.{"http/1.1"} };
            self.tls = try tls_client.Conn.init(testing.allocator, &self.tls_config);
            self.flushTls();
        }
    }

    fn deinit(self: *TestClient) void {
        if (self.tls) |*t| t.deinit();
        self.in.deinit(testing.allocator);
        if (self.fd >= 0) sys.close(self.fd);
        self.fd = -1;
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
            .opcode = @enumFromInt(@as(u4, @truncate(b[0]))),
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
        const first = [_]u8{0x61} ** 1000;
        const second = [_]u8{0x62} ** 1200;
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

test "ws: over TLS, with ALPN http/1.1" {
    var h: Harness = undefined;
    try h.init(29447, .{});
    defer h.deinit();
    var c: TestClient = .{};
    defer c.deinit();
    try h.upgrade(&c, "/tls", true);
    try testing.expectEqualStrings("http/1.1", c.tls.?.alpn().?);

    const big = [_]u8{0x5a} ** 3000;
    try c.sendFrame(.binary, true, &big);
    const echo = try h.frame(&c);
    try testing.expectEqualSlices(u8, &big, echo.payload);

    var p: [125]u8 = undefined;
    try c.sendFrame(.close, true, websocket.closePayload(&p, 1000, ""));
    try testing.expectEqual(@as(?u16, 1000), (try h.frame(&c)).closeCode());
    try h.handlerCloses(1);
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
}
