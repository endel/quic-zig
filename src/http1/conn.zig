//! One TCP connection on the HTTP/1.1 listener: TLS (or plain text),
//! request heads, static files, and the WebSocket it may upgrade to.
//!
//! Everything runs on the listener's loop thread. A connection is freed only
//! from its socket's deferred close, so a handler callback may do anything —
//! close the WebSocket, stop the server — and the code that called it can
//! still look at the connection afterwards.

const std = @import("std");
const posix = std.posix;
const sys = @import("../sys.zig");
const tls_server = @import("../tls/server.zig");
const parser = @import("parser.zig");
const websocket = @import("websocket.zig");
const socket = @import("socket.zig");
const timers = @import("timers.zig");
const Server = @import("server.zig").Server;

const log = std.log.scoped(.http1);

pub const Header = parser.Header;

/// Our Close sent, waiting for the peer's.
const close_timeout_ms = 5_000;
/// Waiting for the peer's FIN after ours.
const linger_ms = 5_000;
/// A static response the client stopped reading.
const io_timeout_ms = 30_000;
/// Stop reading pipelined requests past this much unread input.
const max_pipelined_input = 64 * 1024;
/// An emptied input buffer keeps up to this much capacity, so a stream of
/// large messages doesn't free and regrow it for each one. A quiet
/// connection gives it back at its next ping timer.
const keep_input_capacity = 256 * 1024;
const file_chunk = 16 * 1024;
/// Messages up to this size go out as one write (one TLS record).
const coalesce_limit = 16 * 1024;

const Phase = enum {
    /// Waiting for a request head (and, first, the TLS handshake).
    head,
    /// Sending a file.
    static_body,
    /// Upgraded.
    ws_open,
    /// Our Close is out; waiting for the peer's.
    ws_closing,
    /// Flushing, lingering or aborting; nothing more is read or written.
    closing,
};

pub const SendError = error{
    /// The WebSocket is closing or gone.
    Closed,
    /// More than `max_send_buffer` bytes would be waiting for the socket.
    /// Nothing was queued.
    SendBufferFull,
};

/// An open WebSocket. Valid from `WsRequest.accept` until `onWsClose`
/// returns; use it only on the loop's thread.
pub const WsConn = struct {
    ws_id: u64 = 0,
    decoder: websocket.Decoder = .init(0),
    /// The handler has heard `onWsClose`, or was never given this handle.
    notified: bool = true,
    close_sent: bool = false,
    /// Anything arrived since the last ping timer.
    rx_since_ping: bool = false,
    ping_outstanding: bool = false,

    fn conn(self: *WsConn) *Conn {
        return @alignCast(@fieldParentPtr("ws", self));
    }

    fn constConn(self: *const WsConn) *const Conn {
        return @alignCast(@fieldParentPtr("ws", self));
    }

    /// Unique within the server and never reused. Drawn from the same
    /// counter as `Session.id()` when the listener runs inside an
    /// `event_loop.Server`, so one map can key both.
    pub fn id(self: *const WsConn) u64 {
        return self.ws_id;
    }

    /// Sends one binary message. Safe from any callback on the loop,
    /// including ones for other connections; it goes to the socket at once.
    pub fn send(self: *WsConn, data: []const u8) SendError!void {
        return self.conn().sendMessage(.binary, data);
    }

    /// Sends one text message. `data` must be UTF-8; it isn't checked.
    pub fn sendText(self: *WsConn, data: []const u8) SendError!void {
        return self.conn().sendMessage(.text, data);
    }

    /// Starts the closing handshake. `onWsClose` follows once the peer
    /// answers, or with 1006 when it doesn't within 5 s; never from inside
    /// this call. A code a peer may not receive (1005, 1006, 1015, or
    /// outside the defined ranges) is sent as 1000. `reason` is cut to fit
    /// a control frame.
    pub fn close(self: *WsConn, code: u16, reason: []const u8) void {
        self.conn().closeWebSocket(code, reason);
    }

    /// Bytes queued for the socket and not yet taken by the kernel,
    /// counting TLS framing. What a producer compares against its own
    /// high-water mark before sending something it may drop.
    pub fn bufferedAmount(self: *const WsConn) usize {
        return self.constConn().sock.buffered();
    }

    pub fn peerAddress(self: *const WsConn) *const posix.sockaddr.storage {
        return &self.constConn().peer;
    }
};

pub const AcceptOptions = struct {
    /// Sec-WebSocket-Protocol to answer with. Must be one the client offered.
    protocol: ?[]const u8 = null,
    /// Extra response headers (Set-Cookie, say).
    headers: []const Header = &.{},
};

pub const AcceptError = error{
    /// `accept` or `reject` was already called.
    AlreadyDecided,
    /// The connection failed meanwhile.
    Closed,
    /// `AcceptOptions.protocol` isn't in the client's Sec-WebSocket-Protocol.
    ProtocolNotOffered,
    /// A header in `AcceptOptions.headers` isn't a valid field.
    InvalidHeader,
    OutOfMemory,
};

/// A WebSocket upgrade request, valid only during `onWsUpgrade`. The
/// handler calls `accept` or `reject`; a request left undecided is
/// rejected with 403.
pub const WsRequest = struct {
    conn: *Conn,
    head: *const parser.RequestHead,
    key: []const u8,
    decision: enum { pending, accepted, rejected } = .pending,

    /// A request header, matched case-insensitively.
    pub fn header(self: *const WsRequest, name: []const u8) ?[]const u8 {
        return self.head.get(name);
    }

    pub fn headers(self: *const WsRequest) []const Header {
        return self.head.headers;
    }

    /// Whether the client listed `protocol` in Sec-WebSocket-Protocol.
    pub fn offersProtocol(self: *const WsRequest, protocol: []const u8) bool {
        return websocket.protocolOffered(self.head, protocol);
    }

    pub fn peerAddress(self: *const WsRequest) *const posix.sockaddr.storage {
        return &self.conn.peer;
    }

    /// Answers 101 and returns the WebSocket, which can send right away.
    pub fn accept(self: *WsRequest, opts: AcceptOptions) AcceptError!*WsConn {
        if (self.decision != .pending) return error.AlreadyDecided;
        const c = self.conn;
        if (!c.sock.isOpen()) return error.Closed;
        if (opts.protocol) |p| {
            if (!websocket.protocolOffered(self.head, p)) return error.ProtocolNotOffered;
        }
        for (opts.headers) |h| {
            if (!parser.isToken(h.name) or !parser.isFieldValue(h.value)) return error.InvalidHeader;
        }

        const gpa = c.server.alloc;
        var out: std.ArrayList(u8) = .empty;
        defer out.deinit(gpa);
        const accept_key = websocket.acceptKey(self.key);
        try out.print(gpa, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" ++
            "Sec-WebSocket-Accept: {s}\r\n", .{&accept_key});
        if (opts.protocol) |p| try out.print(gpa, "Sec-WebSocket-Protocol: {s}\r\n", .{p});
        for (opts.headers) |h| try out.print(gpa, "{s}: {s}\r\n", .{ h.name, h.value });
        try out.appendSlice(gpa, "\r\n");

        self.decision = .accepted;
        c.output(out.items);
        c.startWebSocket();
        return &c.ws;
    }

    /// Answers with `status` and closes the connection; nothing is upgraded.
    pub fn reject(self: *WsRequest, status: u16) void {
        if (self.decision != .pending) return;
        self.decision = .rejected;
        self.conn.respond(status, parser.reason(status), .close, null);
    }
};

pub const Conn = struct {
    server: *Server,
    sock: socket.Socket(Conn),
    /// Its own allocation: a plain connection shouldn't carry TLS's state.
    tls: ?*tls_server.Conn,
    peer: posix.sockaddr.storage,

    /// Plaintext received and not yet consumed, from `in_pos` on. Only a
    /// plain connection's partial request or frame lands here: input is
    /// parsed where it arrives (the socket's read buffer, TLS's plaintext
    /// buffer), and only what is left over is copied.
    in: std.ArrayList(u8) = .empty,
    in_pos: usize = 0,
    phase: Phase = .head,
    deadline: timers.Deadline = .{ .callback = onDeadline },
    processing: bool = false,

    // The request being answered.
    keep_alive: bool = true,
    http10: bool = false,
    head_only: bool = false,
    file: ?sys.File = null,
    file_remaining: u64 = 0,

    ws: WsConn = .{},

    // The server's list.
    prev: ?*Conn = null,
    next: ?*Conn = null,

    pub fn create(server: *Server, fd: posix.socket_t) !*Conn {
        const gpa = server.alloc;
        const tls = if (server.tlsConfig()) |tc| blk: {
            const t = try gpa.create(tls_server.Conn);
            t.* = tls_server.Conn.init(gpa, tc);
            break :blk t;
        } else null;
        errdefer if (tls) |t| gpa.destroy(t);
        const self = try gpa.create(Conn);
        errdefer gpa.destroy(self);
        self.* = .{
            .server = server,
            .sock = undefined,
            .tls = tls,
            .peer = undefined,
        };
        var len: posix.socklen_t = @sizeOf(posix.sockaddr.storage);
        if (std.c.getpeername(fd, @ptrCast(&self.peer), &len) != 0) {
            self.peer = std.mem.zeroes(posix.sockaddr.storage);
        }
        try self.sock.init(self, server.loop, &server.timers, gpa, server.xevTcp(fd));
        server.timers.set(&self.deadline, server.config.handshake_timeout_ms);
        self.sock.startReading();
        return self;
    }

    fn destroy(self: *Conn) void {
        const gpa = self.server.alloc;
        self.server.timers.clear(&self.deadline);
        self.closeFile();
        self.ws.decoder.deinit(gpa);
        if (self.tls) |t| {
            t.deinit();
            gpa.destroy(t);
        }
        self.in.deinit(gpa);
        gpa.destroy(self);
    }

    /// Frees the connection without the loop: the server is being torn
    /// down and the loop will not run again.
    pub fn teardown(self: *Conn) void {
        self.notifyClose(websocket.CloseCode.going_away, "");
        self.sock.closeFd();
        self.sock.freeBuffers();
        self.destroy();
    }

    // ─── Socket events ───────────────────────────────────────────────

    pub fn onSocketData(self: *Conn, data: []u8) void {
        if (self.phase == .ws_open or self.phase == .ws_closing) self.ws.rx_since_ping = true;
        if (self.tls) |t| {
            t.feed(data) catch |err| {
                log.debug("tls: {s}", .{@errorName(err)});
                // The alert is queued; send it before closing.
                self.flushTls();
                return self.finish(websocket.CloseCode.abnormal, .graceful);
            };
            self.flushTls();
            self.process();
            if (t.peerClosed()) self.onSocketEof();
            return;
        }
        if (self.in.items.len > self.in_pos) {
            self.in.appendSlice(self.server.alloc, data) catch return self.finish(websocket.CloseCode.abnormal, .abort);
            return self.process();
        }
        // Nothing buffered: parse straight from the read buffer and keep
        // only what is left over, typically nothing.
        self.in.clearRetainingCapacity();
        self.in_pos = 0;
        const used = self.processBuf(data) orelse 0;
        if (used == data.len or !self.sock.isOpen()) return;
        self.in.appendSlice(self.server.alloc, data[used..]) catch return self.finish(websocket.CloseCode.abnormal, .abort);
        self.afterInput();
    }

    pub fn onSocketEof(self: *Conn) void {
        switch (self.phase) {
            // Let what is queued go out; the socket ends itself.
            .closing => {},
            // A client that half-closed after its request still gets the answer.
            .head => self.enterClosing(.graceful),
            // A WebSocket that ends without a Close frame is abnormal (1006).
            .static_body, .ws_open, .ws_closing => self.finish(websocket.CloseCode.abnormal, .abort),
        }
    }

    pub fn onSocketWritable(self: *Conn) void {
        if (self.phase == .static_body) self.pumpFile();
    }

    pub fn onSocketClosed(self: *Conn) void {
        // Backstop for failures found while writing: the handler hears of
        // them here, from a deferred callback, never inside `send`.
        self.notifyClose(websocket.CloseCode.abnormal, "");
        self.server.removeConn(self);
        self.destroy();
    }

    fn onDeadline(d: *timers.Deadline) void {
        const self: *Conn = @alignCast(@fieldParentPtr("deadline", d));
        switch (self.phase) {
            .ws_open => self.onPingTimer(),
            // No Close answered ours; the connection ends abnormally.
            .ws_closing => self.finish(websocket.CloseCode.abnormal, .abort),
            // Handshake, idle keep-alive, a stalled response, or linger.
            .head, .static_body, .closing => self.finish(websocket.CloseCode.abnormal, .abort),
        }
    }

    // ─── Output ──────────────────────────────────────────────────────

    /// Sends plaintext, through TLS when the listener has it.
    fn output(self: *Conn, bytes: []const u8) void {
        if (bytes.len == 0) return;
        if (self.tls) |t| {
            t.write(bytes) catch return self.sock.abort();
            self.flushTls();
        } else {
            self.sock.write(bytes);
        }
    }

    fn flushTls(self: *Conn) void {
        const t = self.tls orelse return;
        const pending = t.pendingOutput();
        if (pending.len == 0) return;
        self.sock.write(pending);
        t.consumeOutput(pending.len);
    }

    const How = enum { graceful, abort };

    /// Ends the connection: the handler hears `onWsClose(code)` first if a
    /// WebSocket is open, then the socket closes, flushing what is queued
    /// when `graceful`.
    fn finish(self: *Conn, code: u16, how: How) void {
        self.notifyClose(code, "");
        self.enterClosing(how);
    }

    fn enterClosing(self: *Conn, how: How) void {
        self.phase = .closing;
        self.closeFile();
        switch (how) {
            .graceful => {
                if (self.tls) |t| {
                    t.close();
                    self.flushTls();
                }
                self.sock.closeAfterFlush();
                self.server.timers.set(&self.deadline, linger_ms);
            },
            .abort => {
                self.server.timers.clear(&self.deadline);
                self.sock.abort();
            },
        }
    }

    fn notifyClose(self: *Conn, code: u16, reason: []const u8) void {
        if (self.ws.notified) return;
        self.ws.notified = true;
        self.server.ws_count -= 1;
        self.server.handlers.close(self.server.handlers.ctx, &self.ws, code, reason);
    }

    // ─── Input ───────────────────────────────────────────────────────

    /// Handles what is buffered: TLS's plaintext, or `in`.
    fn process(self: *Conn) void {
        if (self.tls) |t| {
            // Only `feed` moves TLS's plaintext, and nothing in here feeds.
            const used = self.processBuf(t.unread()) orelse return;
            t.consume(used);
        } else {
            const used = self.processBuf(self.in.items[self.in_pos..]) orelse return;
            self.in_pos += used;
            self.compactInput();
        }
        self.afterInput();
    }

    /// Runs requests and frames from `buf` until one is incomplete or the
    /// phase stops taking input; returns how much of `buf` it used, or null
    /// when re-entered: a response that finishes inside the loop leads back
    /// here, and the loop picks the new phase up itself.
    fn processBuf(self: *Conn, buf: []u8) ?usize {
        if (self.processing) return null;
        self.processing = true;
        defer self.processing = false;
        var pos: usize = 0;
        while (self.sock.isOpen()) {
            const used = switch (self.phase) {
                .head => self.processHead(buf[pos..]),
                .ws_open, .ws_closing => self.processFrame(buf[pos..]),
                .static_body, .closing => null,
            } orelse break;
            pos += used;
        }
        return pos;
    }

    fn unreadLen(self: *Conn) usize {
        if (self.tls) |t| return t.unread().len;
        return self.in.items.len - self.in_pos;
    }

    fn afterInput(self: *Conn) void {
        if (self.phase == .static_body and self.unreadLen() > max_pipelined_input) self.sock.pauseRead();
    }

    fn compactInput(self: *Conn) void {
        if (self.in_pos == 0) return;
        const rest = self.in.items.len - self.in_pos;
        std.mem.copyForwards(u8, self.in.items[0..rest], self.in.items[self.in_pos..]);
        self.in.items.len = rest;
        self.in_pos = 0;
        if (rest == 0 and self.in.capacity > keep_input_capacity) self.in.clearAndFree(self.server.alloc);
    }

    /// Handles the request head at the start of `buf`, if all of it has
    /// arrived; returns its length.
    fn processHead(self: *Conn, buf: []u8) ?usize {
        var hb: [100]Header = undefined;
        const parsed = parser.parseRequest(buf, &hb, .{}) catch |err| {
            const status: u16 = switch (err) {
                error.HeadTooLarge => 431,
                error.TooManyHeaders => 431,
                error.VersionNotSupported => 505,
                error.NotImplemented => 501,
                error.BadRequest => 400,
            };
            self.respond(status, parser.reason(status), .close, null);
            return null;
        } orelse return null;
        self.server.timers.clear(&self.deadline);
        const head = &parsed.head;
        self.keep_alive = head.keep_alive and !self.server.draining;
        self.http10 = head.version == .http10;
        self.head_only = std.mem.eql(u8, head.method, "HEAD");

        if (websocket.isUpgrade(head) and self.server.handlers.upgrade != null) {
            self.handleUpgrade(head);
        } else if (!std.mem.eql(u8, head.method, "GET") and !self.head_only) {
            self.respond(405, "Method not allowed", .close, "Allow: GET, HEAD\r\n");
        } else if (head.hasBody()) {
            self.respond(400, "Unexpected request body", .close, null);
        } else {
            self.serveStatic(head.target);
        }
        return parsed.len;
    }

    fn handleUpgrade(self: *Conn, head: *const parser.RequestHead) void {
        const key = websocket.checkUpgrade(head) catch |err| switch (err) {
            error.BadRequest => return self.respond(400, "Bad WebSocket upgrade", .close, null),
            error.UnsupportedVersion => return self.respond(426, "Upgrade required", .close, "Sec-WebSocket-Version: 13\r\n"),
        };
        var req: WsRequest = .{ .conn = self, .head = head, .key = key };
        const h = self.server.handlers;
        h.upgrade.?(h.ctx, &req, head.target);
        if (req.decision == .pending) req.reject(403);
    }

    fn startWebSocket(self: *Conn) void {
        const cfg = self.server.config.websocket;
        self.phase = .ws_open;
        self.ws = .{
            .ws_id = self.server.nextId(),
            .decoder = .init(cfg.max_message_size),
            .notified = false,
        };
        self.server.ws_count += 1;
        if (cfg.ping_interval_ms > 0) self.server.timers.set(&self.deadline, cfg.ping_interval_ms);
    }

    /// Handles the frame at the start of `buf`, if all of it has arrived;
    /// returns its length. Event slices point into `buf`, which stays put
    /// until the handler returns.
    fn processFrame(self: *Conn, buf: []u8) ?usize {
        const step = self.ws.decoder.decode(self.server.alloc, buf) catch |err| {
            self.failWebSocket(websocket.closeCodeFor(err));
            return null;
        };
        if (step.consumed == 0) return null;
        const ev = step.event orelse return step.consumed;
        switch (ev) {
            .message => |m| {
                // §5.5.1: after our Close, data frames are discarded.
                if (self.phase == .ws_open and !self.ws.notified) {
                    const h = self.server.handlers;
                    h.message(h.ctx, &self.ws, m.data, m.kind);
                }
            },
            .ping => |payload| {
                if (self.phase == .ws_open) self.sendFrame(.pong, payload);
            },
            .pong => self.ws.ping_outstanding = false,
            .close => |c| self.onPeerClose(c.code, c.reason),
        }
        return step.consumed;
    }

    fn onPeerClose(self: *Conn, code: ?u16, reason: []const u8) void {
        if (!self.ws.close_sent) {
            // Echo the code (§5.5.1), then close: the server closes TCP first.
            var p: [125]u8 = undefined;
            const payload: []const u8 = if (code) |c| websocket.closePayload(&p, c, "") else &.{};
            self.sendFrame(.close, payload);
            self.ws.close_sent = true;
        }
        self.notifyClose(code orelse websocket.CloseCode.no_status, reason);
        self.enterClosing(.graceful);
    }

    /// _Fail the WebSocket Connection_ (§7.1.7): a Close with the error's
    /// code, then the TCP connection closes.
    fn failWebSocket(self: *Conn, code: u16) void {
        if (!self.ws.close_sent) {
            var p: [125]u8 = undefined;
            self.sendFrame(.close, websocket.closePayload(&p, code, ""));
            self.ws.close_sent = true;
        }
        self.finish(code, .graceful);
    }

    fn onPingTimer(self: *Conn) void {
        const interval = self.server.config.websocket.ping_interval_ms;
        if (self.ws.rx_since_ping) {
            self.ws.rx_since_ping = false;
            self.ws.ping_outstanding = false;
        } else if (self.ws.ping_outstanding) {
            // Silent for two intervals, pong included.
            return self.finish(websocket.CloseCode.abnormal, .abort);
        } else {
            self.sendFrame(.ping, "");
            self.ws.ping_outstanding = true;
            // Quiet for an interval: give back what large messages grew.
            if (self.in.items.len == self.in_pos) self.in.clearAndFree(self.server.alloc);
        }
        self.server.timers.set(&self.deadline, interval);
    }

    // ─── WebSocket output ────────────────────────────────────────────

    fn sendFrame(self: *Conn, opcode: websocket.Opcode, payload: []const u8) void {
        var hdr_buf: [10]u8 = undefined;
        const hdr = websocket.writeFrameHeader(&hdr_buf, opcode, true, payload.len);
        if (self.tls == null and hdr.len + payload.len > coalesce_limit) {
            // One sendmsg for both, without copying the payload.
            return self.sock.writeVec(&.{ hdr, payload });
        }
        // Small frames, and the first TLS record of a large one: the header
        // travels with (the start of) the payload, not in a record of its own.
        var buf: [coalesce_limit]u8 = undefined;
        const head = @min(payload.len, buf.len - hdr.len);
        @memcpy(buf[0..hdr.len], hdr);
        @memcpy(buf[hdr.len..][0..head], payload[0..head]);
        self.output(buf[0 .. hdr.len + head]);
        self.output(payload[head..]);
    }

    fn sendMessage(self: *Conn, kind: websocket.MessageKind, data: []const u8) SendError!void {
        if (self.ws.notified or self.phase != .ws_open or !self.sock.isOpen()) return error.Closed;
        if (self.sock.buffered() + data.len > self.server.config.websocket.max_send_buffer) return error.SendBufferFull;
        self.sendFrame(if (kind == .text) .text else .binary, data);
        // A failed write aborts; `onWsClose` follows from the deferred close.
        if (!self.sock.isOpen()) return error.Closed;
    }

    fn closeWebSocket(self: *Conn, code: u16, reason: []const u8) void {
        if (self.ws.notified or self.phase != .ws_open) return;
        const send_code = if (websocket.isValidCloseCode(code)) code else websocket.CloseCode.normal;
        var p: [125]u8 = undefined;
        self.sendFrame(.close, websocket.closePayload(&p, send_code, reason));
        self.ws.close_sent = true;
        self.phase = .ws_closing;
        self.server.timers.set(&self.deadline, close_timeout_ms);
    }

    /// For `Server.stop`: a Close with 1001 on an open WebSocket, then the
    /// connection goes. The frame is written directly when the socket has
    /// room; nothing waits for it.
    pub fn shutdown(self: *Conn) void {
        if (self.phase == .ws_open and !self.ws.close_sent) {
            var p: [125]u8 = undefined;
            self.sendFrame(.close, websocket.closePayload(&p, websocket.CloseCode.going_away, ""));
            self.ws.close_sent = true;
        }
        self.finish(websocket.CloseCode.going_away, .abort);
    }

    /// For `Server.drain`: whether the connection holds no request in flight.
    pub fn isIdle(self: *Conn) bool {
        return switch (self.phase) {
            .head => self.unreadLen() == 0,
            .static_body => false,
            .ws_open, .ws_closing, .closing => true,
        };
    }

    // ─── HTTP responses ──────────────────────────────────────────────

    const After = enum { keep, close };

    /// A short text/plain response. `extra` is preformatted header lines.
    fn respond(self: *Conn, status: u16, body: []const u8, after: After, extra: ?[]const u8) void {
        var buf: [1024]u8 = undefined;
        var w: std.Io.Writer = .fixed(&buf);
        const close = after == .close or !self.keep_alive;
        w.print("HTTP/1.1 {d} {s}\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {d}\r\n", .{
            status, parser.reason(status), body.len,
        }) catch unreachable;
        self.writeCommonHeaders(&w, close) catch unreachable;
        if (extra) |e| w.writeAll(e) catch unreachable;
        w.writeAll("\r\n") catch unreachable;
        if (!self.head_only) w.writeAll(body) catch unreachable;
        self.output(w.buffered());
        if (close) self.keep_alive = false;
        self.responseDone();
    }

    fn writeCommonHeaders(self: *Conn, w: *std.Io.Writer, close: bool) std.Io.Writer.Error!void {
        if (close) {
            try w.writeAll("Connection: close\r\n");
        } else if (self.http10) {
            try w.writeAll("Connection: keep-alive\r\n");
        }
        if (self.server.altSvc()) |v| try w.print("Alt-Svc: {s}\r\n", .{v});
    }

    fn serveStatic(self: *Conn, target: []const u8) void {
        const root = self.server.config.static_dir orelse return self.respond(404, "Not found", .keep, null);
        const path = target[0 .. std.mem.indexOfScalar(u8, target, '?') orelse target.len];
        if (path.len == 0 or path[0] != '/') return self.respond(400, "Bad request", .close, null);
        if (std.mem.indexOf(u8, path, "..") != null) return self.respond(403, "Forbidden", .keep, null);
        const rel = path[1..];

        var buf: [std.fs.max_path_bytes]u8 = undefined;
        const file, const full = openStatic(&buf, root, rel) orelse return self.respond(404, "Not found", .keep, null);
        if ((file.kind() catch .other) != .file) {
            file.close();
            return self.respond(404, "Not found", .keep, null);
        }
        const size = (file.stat() catch {
            file.close();
            return self.respond(500, "Cannot stat file", .keep, null);
        }).size;

        var hdr: [1024]u8 = undefined;
        var w: std.Io.Writer = .fixed(&hdr);
        w.print("HTTP/1.1 200 OK\r\nContent-Type: {s}\r\nContent-Length: {d}\r\n" ++
            "Access-Control-Allow-Origin: *\r\n" ++
            // Cross-origin isolation: sub-millisecond performance.now() in
            // Chrome, which the WebTransport demos time with.
            "Cross-Origin-Opener-Policy: same-origin\r\nCross-Origin-Embedder-Policy: require-corp\r\n", .{
            mimeType(full), size,
        }) catch unreachable;
        self.writeCommonHeaders(&w, !self.keep_alive) catch unreachable;
        w.writeAll("\r\n") catch unreachable;
        self.output(w.buffered());

        if (self.head_only or size == 0) {
            file.close();
            return self.responseDone();
        }
        self.file = file;
        self.file_remaining = size;
        self.phase = .static_body;
        self.pumpFile();
    }

    /// `{root}/{rel}`, with `index.html` for a directory path.
    fn openStatic(buf: []u8, root: []const u8, rel: []const u8) ?struct { sys.File, []const u8 } {
        const dir_path = rel.len == 0 or rel[rel.len - 1] == '/';
        const full = if (dir_path)
            std.fmt.bufPrint(buf, "{s}/{s}index.html", .{ root, rel }) catch return null
        else
            std.fmt.bufPrint(buf, "{s}/{s}", .{ root, rel }) catch return null;
        const opened: ?sys.File = sys.openFileRead(full) catch null;
        if (opened) |f| {
            if (dir_path or (f.kind() catch .other) != .directory) return .{ f, full };
            f.close();
        }
        if (dir_path) return null;
        // A directory named without its trailing slash.
        const index = std.fmt.bufPrint(buf, "{s}/{s}/index.html", .{ root, rel }) catch return null;
        const f = sys.openFileRead(index) catch return null;
        return .{ f, index };
    }

    fn pumpFile(self: *Conn) void {
        const file = self.file orelse return;
        var buf: [file_chunk]u8 = undefined;
        while (self.file_remaining > 0 and self.sock.isOpen() and self.sock.buffered() < socket.high_water) {
            const want: usize = @intCast(@min(self.file_remaining, buf.len));
            const n = file.read(buf[0..want]) catch 0;
            // The file shrank or failed mid-response: the length is a lie now.
            if (n == 0) return self.finish(websocket.CloseCode.abnormal, .abort);
            self.output(buf[0..n]);
            self.file_remaining -= n;
        }
        if (!self.sock.isOpen()) return;
        if (self.file_remaining > 0) {
            self.server.timers.set(&self.deadline, io_timeout_ms);
            return;
        }
        self.closeFile();
        self.responseDone();
    }

    fn closeFile(self: *Conn) void {
        if (self.file) |f| f.close();
        self.file = null;
    }

    /// A response is fully queued: wait for the next request, or close.
    fn responseDone(self: *Conn) void {
        if (self.phase == .closing) return;
        if (!self.keep_alive or self.server.stopping) return self.enterClosing(.graceful);
        self.phase = .head;
        self.server.timers.set(&self.deadline, self.server.config.keepalive_timeout_ms);
        self.sock.resumeRead();
        // Pipelined requests already buffered.
        if (self.unreadLen() > 0) self.process();
    }
};

pub fn mimeType(path: []const u8) []const u8 {
    const ext = std.fs.path.extension(path);
    const table = [_]struct { []const u8, []const u8 }{
        .{ ".html", "text/html; charset=utf-8" },
        .{ ".htm", "text/html; charset=utf-8" },
        .{ ".css", "text/css; charset=utf-8" },
        .{ ".js", "application/javascript; charset=utf-8" },
        .{ ".mjs", "application/javascript; charset=utf-8" },
        .{ ".json", "application/json; charset=utf-8" },
        .{ ".png", "image/png" },
        .{ ".jpg", "image/jpeg" },
        .{ ".jpeg", "image/jpeg" },
        .{ ".gif", "image/gif" },
        .{ ".svg", "image/svg+xml" },
        .{ ".ico", "image/x-icon" },
        .{ ".woff2", "font/woff2" },
        .{ ".woff", "font/woff" },
        .{ ".wasm", "application/wasm" },
        .{ ".txt", "text/plain; charset=utf-8" },
        .{ ".xml", "application/xml" },
    };
    for (table) |e| {
        if (std.ascii.eqlIgnoreCase(ext, e[0])) return e[1];
    }
    return "application/octet-stream";
}

test "mime type lookup" {
    const expect = std.testing.expectEqualStrings;
    try expect("text/html; charset=utf-8", mimeType("index.html"));
    try expect("application/javascript; charset=utf-8", mimeType("app.js"));
    try expect("text/css; charset=utf-8", mimeType("style.css"));
    try expect("image/png", mimeType("logo.PNG"));
    try expect("application/octet-stream", mimeType("data.bin"));
}
