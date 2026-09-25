//! HTTP/1.1 over TCP, on the same libxev loop as the QUIC server: static
//! files and WebSockets (RFC 6455), with TLS 1.3 from `tls/server.zig` or
//! in plain text.
//!
//! `event_loop.Server` runs one of these when `Config.http1` is set, bound to
//! the QUIC port by default (TCP and UDP don't clash), sharing its
//! certificates and advertising HTTP/3 through Alt-Svc. The handler's
//! `onWsUpgrade` / `onWsMessage` / `onWsClose` run on the loop's thread, like
//! every WebTransport callback, so one handler can serve both transports
//! without locks.
//!
//! Requests: `Upgrade: websocket` goes to `onWsUpgrade` when the handler has
//! it; GET and HEAD are served from `static_dir` (404 without one); other
//! methods get 405. Request bodies are not supported.

const std = @import("std");
const posix = std.posix;
const builtin = @import("builtin");
const sys = @import("../sys.zig");
const net = @import("../sockaddr.zig");
const tls13 = @import("../quic/tls13.zig");
const tls_server = @import("../tls/server.zig");
const xev_backend = @import("../xev_backend.zig");
const xev = xev_backend.xev;
const conn_mod = @import("conn.zig");
const socket = @import("socket.zig");
const timers = @import("timers.zig");
pub const parser = @import("parser.zig");
pub const websocket = @import("websocket.zig");

const log = std.log.scoped(.http1);

pub const Conn = conn_mod.Conn;
pub const Header = parser.Header;
pub const WsConn = conn_mod.WsConn;
pub const WsRequest = conn_mod.WsRequest;
pub const WsAcceptOptions = conn_mod.AcceptOptions;
pub const WsSendError = conn_mod.SendError;
pub const WsMessageKind = websocket.MessageKind;
pub const WsCloseCode = websocket.CloseCode;
pub const mimeType = conn_mod.mimeType;

pub const Config = struct {
    /// Directory GET and HEAD are served from. Null serves none: requests
    /// that aren't a WebSocket upgrade get 404.
    static_dir: ?[]const u8 = null,
    /// TCP port. Null means the QUIC port.
    port: ?u16 = null,
    /// Send `Alt-Svc: h3=":<quic port>"` to advertise HTTP/3.
    alt_svc: bool = true,
    /// TLS 1.3 with the QUIC server's certificates. False serves plain
    /// http:// and ws://: for localhost development, where a browser can't
    /// be given a certificate hash the way WebTransport can, or behind a
    /// proxy that terminates TLS.
    tls: bool = true,
    /// Open TCP connections past which new ones are closed on accept.
    max_connections: u32 = 4096,
    /// Time for the TLS handshake and the first request head.
    handshake_timeout_ms: u32 = 10_000,
    /// How long an idle connection waits for its next request.
    keepalive_timeout_ms: u32 = 15_000,
    websocket: WebSocketConfig = .{},
};

pub const WebSocketConfig = struct {
    /// Largest message accepted, fragments included; a bigger one closes
    /// the connection with 1009.
    max_message_size: usize = 1 << 20,
    /// `WsConn.send` fails with `error.SendBufferFull` rather than queue past
    /// this many bytes for a peer that isn't reading.
    max_send_buffer: usize = 4 << 20,
    /// A connection quiet this long gets a ping; one quiet for two intervals
    /// is dropped (1006). Zero disables both.
    ping_interval_ms: u32 = 30_000,
};

/// Where a listener's socket goes and what it shares with the QUIC server.
pub const ListenOptions = struct {
    address: []const u8 = "127.0.0.1",
    /// Dual-stack `::` instead of `address`.
    ipv6: bool = false,
    /// The QUIC port: the TCP port when `Config.port` is null, and what
    /// Alt-Svc advertises.
    quic_port: u16,
    reuse_port: bool = false,
    /// Certificates for TLS; required unless `Config.tls` is false. The
    /// slices must outlive the listener.
    certs: ?Certs = null,
};

pub const Certs = struct {
    /// Chosen by SNI; see `tls_server.Config.certs`. Empty means `single`.
    entries: []const tls13.CertEntry = &.{},
    single: ?tls13.ServerCertificate = null,
    client_auth: ?*const tls13.ClientAuth = null,
};

/// The handler, type-erased: see `handlersFor`.
pub const Handlers = struct {
    ctx: *anyopaque,
    /// Null when the handler takes no WebSockets: upgrades are then served
    /// as ordinary requests.
    upgrade: ?*const fn (ctx: *anyopaque, req: *WsRequest, path: []const u8) void,
    message: *const fn (ctx: *anyopaque, ws: *WsConn, data: []const u8, kind: WsMessageKind) void,
    close: *const fn (ctx: *anyopaque, ws: *WsConn, code: u16, reason: []const u8) void,
};

/// Binds a handler's optional `onWsUpgrade(self, req, path)`,
/// `onWsMessage(self, ws, data[, kind])` and `onWsClose(self, ws, code,
/// reason)`.
pub fn handlersFor(comptime H: type, handler: *H) Handlers {
    const S = struct {
        fn upgrade(ctx: *anyopaque, req: *WsRequest, path: []const u8) void {
            H.onWsUpgrade(@ptrCast(@alignCast(ctx)), req, path);
        }
        fn message(ctx: *anyopaque, ws: *WsConn, data: []const u8, kind: WsMessageKind) void {
            if (comptime !@hasDecl(H, "onWsMessage")) return;
            const h: *H = @ptrCast(@alignCast(ctx));
            if (comptime @typeInfo(@TypeOf(H.onWsMessage)).@"fn".params.len == 4) {
                h.onWsMessage(ws, data, kind);
            } else {
                h.onWsMessage(ws, data);
            }
        }
        fn close(ctx: *anyopaque, ws: *WsConn, code: u16, reason: []const u8) void {
            if (comptime !@hasDecl(H, "onWsClose")) return;
            H.onWsClose(@ptrCast(@alignCast(ctx)), ws, code, reason);
        }
    };
    return .{
        .ctx = handler,
        .upgrade = if (@hasDecl(H, "onWsUpgrade")) S.upgrade else null,
        .message = S.message,
        .close = S.close,
    };
}

pub const Server = struct {
    alloc: std.mem.Allocator,
    config: Config,
    listen_fd: posix.socket_t,
    listen_file: xev.File,
    poll_c: xev.Completion = .{},
    poll_cancel_c: xev.Completion = .{},

    // Set by start(), once the server has its final address.
    loop: *xev.Loop = undefined,
    timers: timers.Timers = undefined,
    handlers: Handlers = undefined,
    next_id: *u64 = undefined,
    tls_conf: tls_server.Config = undefined,

    certs: ?Certs,
    single_entry: [1]tls13.CertEntry = undefined,
    ticket_key: [16]u8,
    own_next_id: u64 = 1,

    conns: ?*Conn = null,
    conn_count: usize = 0,
    ws_count: usize = 0,

    alt_svc_buf: [48]u8 = undefined,
    alt_svc_len: u8 = 0,
    started: bool = false,
    draining: bool = false,
    stopping: bool = false,

    /// Opens and binds the listening socket; nothing runs until `start`.
    pub fn init(alloc: std.mem.Allocator, config: Config, opts: ListenOptions) !Server {
        if (config.tls and opts.certs == null) return error.Http1TlsNeedsCertificate;
        const fd = try openListener(opts, config.port orelse opts.quic_port);
        errdefer sys.close(fd);

        var self: Server = .{
            .alloc = alloc,
            .config = config,
            .listen_fd = fd,
            .listen_file = xev.File.initFd(fd),
            .certs = if (config.tls) opts.certs else null,
            // Our own key: a QUIC ticket must not resume a TCP session.
            .ticket_key = undefined,
        };
        sys.randomBytes(&self.ticket_key);
        if (config.alt_svc) {
            const v = std.fmt.bufPrint(&self.alt_svc_buf, "h3=\":{d}\"; ma=86400", .{opts.quic_port}) catch "";
            self.alt_svc_len = @intCast(v.len);
        }
        return self;
    }

    /// Starts accepting on `loop`. `id_counter` is where WebSocket ids come
    /// from (the QUIC connection counter, under `event_loop.Server`); null
    /// uses our own.
    pub fn start(self: *Server, loop: *xev.Loop, handlers: Handlers, id_counter: ?*u64) !void {
        self.loop = loop;
        self.handlers = handlers;
        self.next_id = id_counter orelse &self.own_next_id;
        self.timers = try timers.Timers.init(loop);
        if (self.certs) |c| {
            const entries = if (c.entries.len > 0) c.entries else blk: {
                self.single_entry[0] = .{ .server_names = &.{}, .cert = c.single.?, .client_auth = c.client_auth };
                break :blk self.single_entry[0..];
            };
            self.tls_conf = .{ .certs = entries, .alpn = &.{"http/1.1"}, .ticket_key = self.ticket_key };
        }
        self.listen_file.poll(loop, &self.poll_c, .read, Server, self, onListenReadable);
        self.started = true;
    }

    /// Stop taking new work: requests in flight finish and their connections
    /// close, idle keep-alive connections close now, new connections are
    /// closed on accept. WebSockets stay open until the handler or the peer
    /// closes them, as WebTransport sessions do under drain.
    pub fn drain(self: *Server) void {
        if (self.draining or self.stopping) return;
        self.draining = true;
        var it = self.conns;
        while (it) |c| {
            it = c.next;
            if (c.isIdle() and c.phase == .head) c.shutdown();
        }
    }

    /// True once no HTTP request is in flight.
    pub fn isDrained(self: *const Server) bool {
        var it = self.conns;
        while (it) |c| : (it = c.next) {
            if (!c.isIdle()) return false;
        }
        return true;
    }

    /// Stop accepting and end every connection: each open WebSocket gets a
    /// Close with 1001 (sent if the socket takes it at once) and
    /// `onWsClose(1001)`. On a loop the caller keeps running, `isStopped`
    /// turns true once every socket is closed.
    pub fn stop(self: *Server) void {
        if (self.stopping) return;
        self.stopping = true;
        if (!self.started) return;
        xev_backend.cancelCompletion(self.loop, &self.poll_c, &self.poll_cancel_c);
        var it = self.conns;
        while (it) |c| {
            it = c.next;
            c.shutdown();
        }
        self.timers.stop();
    }

    pub fn isStopped(self: *const Server) bool {
        if (!self.started) return true;
        return self.stopping and self.conn_count == 0 and self.timers.isIdle() and
            self.poll_c.state() == .dead and self.poll_cancel_c.state() == .dead;
    }

    /// Frees everything. On a loop that will run again, `isStopped` must be
    /// true first; on one that won't, whatever is left is closed here, and
    /// each open WebSocket's handler hears `onWsClose(1001)`.
    pub fn deinit(self: *Server) void {
        if (self.started) {
            // Deferred closes that will not get another loop iteration.
            self.timers.runDeferred();
            while (self.conns) |c| {
                self.removeConn(c);
                c.teardown();
            }
            self.timers.deinit();
        }
        sys.close(self.listen_fd);
    }

    /// The TCP port the listener is bound to.
    pub fn port(self: *const Server) u16 {
        var addr: net.Address = undefined;
        var len: posix.socklen_t = @sizeOf(net.Address);
        if (std.c.getsockname(self.listen_fd, &addr.any, &len) != 0) return 0;
        return addr.getPort();
    }

    // ─── For connections ─────────────────────────────────────────────

    pub fn tlsConfig(self: *const Server) ?*const tls_server.Config {
        return if (self.certs != null) &self.tls_conf else null;
    }

    pub fn altSvc(self: *const Server) ?[]const u8 {
        return if (self.alt_svc_len > 0) self.alt_svc_buf[0..self.alt_svc_len] else null;
    }

    pub fn xevTcp(_: *const Server, fd: posix.socket_t) xev.TCP {
        return xev.TCP.initFd(fd);
    }

    pub fn nextId(self: *Server) u64 {
        const id = self.next_id.*;
        self.next_id.* += 1;
        return id;
    }

    pub fn removeConn(self: *Server, c: *Conn) void {
        if (c.prev) |p| p.next = c.next else self.conns = c.next;
        if (c.next) |n| n.prev = c.prev;
        c.prev = null;
        c.next = null;
        self.conn_count -= 1;
    }

    // ─── Accepting ───────────────────────────────────────────────────

    fn onListenReadable(ud: ?*Server, _: *xev.Loop, c: *xev.Completion, _: xev.File, r: xev.PollError!xev.PollEvent) xev.CallbackAction {
        xev_backend.forgetPollResult(c);
        _ = r catch return .rearm;
        const self = ud orelse return .disarm;
        if (self.stopping) return xev_backend.halted_poll_action;
        // Several per wakeup, capped so a storm can't starve the loop.
        var n: usize = 0;
        while (n < 64) : (n += 1) {
            const fd = socket.acceptNow(self.listen_fd) orelse break;
            self.serve(fd);
        }
        return .rearm;
    }

    fn serve(self: *Server, fd: posix.socket_t) void {
        if (self.draining or self.conn_count >= self.config.max_connections) {
            sys.close(fd);
            return;
        }
        const c = Conn.create(self, fd) catch {
            sys.close(fd);
            return;
        };
        c.next = self.conns;
        if (self.conns) |h| h.prev = c;
        self.conns = c;
        self.conn_count += 1;
    }
};

fn openListener(opts: ListenOptions, tcp_port: u16) !posix.socket_t {
    const addr = if (opts.ipv6)
        try net.Address.parseIp6("::", tcp_port)
    else
        try net.Address.parseIp4(opts.address, tcp_port);
    const family: u32 = if (opts.ipv6) posix.AF.INET6 else posix.AF.INET;
    const fd = try sys.socket(family, posix.SOCK.STREAM | posix.SOCK.NONBLOCK | posix.SOCK.CLOEXEC, 0);
    errdefer sys.close(fd);
    if (opts.ipv6) {
        // Dual-stack: also accept IPv4 peers.
        const IPV6_V6ONLY: u32 = if (builtin.os.tag == .linux) 26 else 27;
        posix.setsockopt(fd, posix.IPPROTO.IPV6, IPV6_V6ONLY, std.mem.asBytes(&@as(c_int, 0))) catch {};
    }
    posix.setsockopt(fd, posix.SOL.SOCKET, posix.SO.REUSEADDR, std.mem.asBytes(&@as(c_int, 1))) catch {};
    if (opts.reuse_port) {
        try posix.setsockopt(fd, posix.SOL.SOCKET, posix.SO.REUSEPORT, std.mem.asBytes(&@as(c_int, 1)));
    }
    try sys.bind(fd, &addr.any, addr.getOsSockLen());
    try sys.listen(fd, 1024);
    return fd;
}

test {
    _ = parser;
    _ = websocket;
    _ = conn_mod;
}
