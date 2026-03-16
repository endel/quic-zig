const std = @import("std");
const posix = std.posix;
const builtin = @import("builtin");
const xev_mod = @import("xev");

/// Global signal state for graceful shutdown.
var shutdown_requested: std.atomic.Value(bool) = std.atomic.Value(bool).init(false);
var shutdown_pipe_fd: std.atomic.Value(i32) = std.atomic.Value(i32).init(-1);

// Default backend: io_uring on Linux, kqueue on macOS.
// Callers can use ServerWithBackend(xev_mod.Epoll, H) for containers that block io_uring.
const xev = xev_mod;

const connection = @import("quic/connection.zig");
const connection_manager = @import("quic/connection_manager.zig");
const ConnEntry = connection_manager.ConnEntry;
const tls13 = @import("quic/tls13.zig");
const ecn_socket = @import("quic/ecn_socket.zig");
const h3 = @import("h3/connection.zig");
const h0 = @import("h0/connection.zig");
const qpack = @import("h3/qpack.zig");
const wt = @import("webtransport/session.zig");

pub const Protocol = enum { quic, h3, h0, webtransport };

pub const Config = struct {
    address: []const u8 = "127.0.0.1",
    port: u16 = 4433,
    cert_path: []const u8 = "interop/certs/server.crt",
    key_path: []const u8 = "interop/certs/server.key",
    max_datagram_frame_size: u64 = 65536,
    webtransport_max_sessions: u64 = 4,
    require_retry: bool = false,

    // Advanced: provide pre-built TLS and connection configs directly.
    // When tls_config is set, cert_path/key_path are ignored.
    tls_config: ?tls13.TlsConfig = null,
    conn_config: ?connection.ConnectionConfig = null,
    retry_token_key: ?[16]u8 = null,
    static_reset_key: ?[16]u8 = null,

    // Use IPv6 dual-stack socket (supports both IPv4 and IPv6)
    ipv6: bool = false,

    // Optional second port for preferred_address (connectionmigration).
    // When set, a second socket is created on this port so that clients
    // migrating to the server's preferred address can reach us.
    preferred_port: ?u16 = null,
};

/// Session wraps a ConnEntry and provides convenience methods for sending data.
pub const Session = struct {
    entry: *ConnEntry,

    // --- H3 methods ---

    pub fn sendResponse(self: *Session, stream_id: u64, headers: []const qpack.Header, body: []const u8) !void {
        var h3c = &self.entry.h3_conn.?;
        try h3c.sendResponse(stream_id, headers, body);
    }

    // --- WebTransport methods ---

    pub fn sendStreamData(self: *Session, stream_id: u64, data: []const u8) !void {
        if (self.entry.wt_conn) |*wtc| {
            try wtc.sendStreamData(stream_id, data);
        }
    }

    pub fn sendDatagram(self: *Session, session_id: u64, data: []const u8) !void {
        if (self.entry.wt_conn) |*wtc| {
            try wtc.sendDatagram(session_id, data);
        }
    }

    pub fn acceptSession(self: *Session, session_id: u64) !void {
        if (self.entry.wt_conn) |*wtc| {
            try wtc.acceptSession(session_id);
        }
    }

    pub fn closeStream(self: *Session, stream_id: u64) void {
        if (self.entry.wt_conn) |*wtc| {
            wtc.closeStream(stream_id);
        }
    }

    pub fn openBidiStream(self: *Session, session_id: u64) !u64 {
        if (self.entry.wt_conn) |*wtc| {
            return try wtc.openBidiStream(session_id);
        }
        return error.NoWtConnection;
    }

    pub fn openUniStream(self: *Session, session_id: u64) !u64 {
        if (self.entry.wt_conn) |*wtc| {
            return try wtc.openUniStream(session_id);
        }
        return error.NoWtConnection;
    }

    pub fn closeSession(self: *Session, session_id: u64) void {
        if (self.entry.wt_conn) |*wtc| {
            wtc.closeSession(session_id);
        }
    }

    pub fn closeSessionWithError(self: *Session, session_id: u64, error_code: u32, reason: []const u8) !void {
        if (self.entry.wt_conn) |*wtc| {
            try wtc.closeSessionWithError(session_id, error_code, reason);
        }
    }

    pub fn resetStream(self: *Session, stream_id: u64, error_code: u32) void {
        if (self.entry.wt_conn) |*wtc| {
            wtc.resetStream(stream_id, error_code);
        }
    }

    pub fn acceptSessionWithHeaders(self: *Session, session_id: u64, extra_headers: []const qpack.Header) !void {
        if (self.entry.wt_conn) |*wtc| {
            try wtc.acceptSessionWithHeaders(session_id, extra_headers);
        }
    }

    pub fn closeConnection(self: *Session) void {
        self.entry.conn.close(0, "");
    }

    pub fn isDatagramSendQueueFull(self: *const Session) bool {
        if (self.entry.wt_conn) |*wtc| {
            return wtc.isDatagramSendQueueFull();
        }
        return true;
    }

    pub fn maxDatagramPayloadSize(self: *const Session, session_id: u64) ?usize {
        if (self.entry.wt_conn) |*wtc| {
            return wtc.maxDatagramPayloadSize(session_id);
        }
        return null;
    }

    // --- H0 methods ---

    pub fn serveFile(self: *Session, stream_id: u64, root_dir: []const u8, path: []const u8) !void {
        if (self.entry.h0_conn) |h0c| {
            try h0c.serveFile(stream_id, root_dir, path);
        }
    }

    pub fn sendH0Response(self: *Session, stream_id: u64, data: []const u8) !void {
        if (self.entry.h0_conn) |h0c| {
            try h0c.sendResponse(stream_id, data);
        }
    }

    // --- Connection-level methods ---

    pub fn sendKeepAlive(self: *Session) void {
        self.entry.conn.sendKeepAlive();
    }
};

pub fn Server(comptime Handler: type) type {
    comptime {
        if (!@hasDecl(Handler, "protocol")) {
            @compileError("Handler must declare 'pub const protocol: event_loop.Protocol'");
        }

        const known = [_][]const u8{
            "onConnectRequest", "onSessionReady",  "onStreamData",
            "onDatagram",       "onSessionClosed",  "onSessionDraining",
            "onBidiStream",     "onUniStream",      "onPollComplete",
            "onRequest",        "onData",
            "onH0Request",      "onH0Data",         "onH0Finished",
        };

        for (@typeInfo(Handler).@"struct".decls) |decl| {
            if (decl.name.len >= 2 and decl.name[0] == 'o' and decl.name[1] == 'n') {
                var found = false;
                for (known) |k| {
                    if (std.mem.eql(u8, decl.name, k)) {
                        found = true;
                        break;
                    }
                }
                if (!found) {
                    @compileError("Handler has unrecognized callback '" ++ decl.name ++
                        "'. Known callbacks: onRequest, onData, onConnectRequest, " ++
                        "onSessionReady, onStreamData, onDatagram, onSessionClosed, " ++
                        "onSessionDraining, onBidiStream, onUniStream, onPollComplete, " ++
                        "onH0Request, onH0Data, onH0Finished");
                }
            }
        }

        if (@hasDecl(Handler, "onStreamData")) {
            const params = @typeInfo(@TypeOf(Handler.onStreamData)).@"fn".params;
            if (params.len != 4 and params.len != 5) {
                @compileError("onStreamData must have 4 params (self, session, stream_id, data) " ++
                    "or 5 params (self, session, stream_id, data, fin)");
            }
        }
    }

    return struct {
        const Self = @This();

        allocator: std.mem.Allocator,
        handler: *Handler,
        conn_mgr: connection_manager.ConnectionManager,

        // libxev
        loop: xev.Loop,
        file: xev.File,
        timer: xev.Timer,
        poll_completion: xev.Completion,
        timer_completion: xev.Completion,
        timer_cancel_completion: xev.Completion,
        signal_completion: xev.Completion,
        signal_file: ?xev.File,
        signal_pipe_fd: ?posix.socket_t,
        timer_armed: bool,
        started: bool,
        stopping: bool,

        // I/O (our own, for ECN support)
        sockfd: posix.socket_t,
        local_addr: posix.sockaddr.storage,
        batch: ecn_socket.SendBatch,
        recv_buf: [8192]u8,
        out_buf: [1500]u8,

        /// Optional second socket for preferred_address (connectionmigration).
        /// When the server advertises a preferred_address on a different port,
        /// clients migrate there. This socket receives and responds on that port.
        preferred: ?PreferredSocket,

        const PreferredSocket = struct {
            sockfd: posix.socket_t,
            local_addr: posix.sockaddr.storage,
            port: u16,
            file: xev.File,
            poll_completion: xev.Completion,
            batch: ecn_socket.SendBatch,
        };

        pub fn init(alloc: std.mem.Allocator, handler: *Handler, config: Config) !Self {
            // Determine TLS config: use advanced or build from cert/key paths
            const tls_config: tls13.TlsConfig = if (config.tls_config) |tc| tc else blk: {
                // Read cert files
                const server_cert_pem = try std.fs.cwd().readFileAlloc(alloc, config.cert_path, 8192);
                const server_key_pem = try std.fs.cwd().readFileAlloc(alloc, config.key_path, 8192);

                // Parse PEM -> DER (supports certificate chains, e.g. Let's Encrypt fullchain.pem)
                const cert_chain = try tls13.parsePemCertChain(alloc, server_cert_pem);

                var key_der_buf: [4096]u8 = undefined;
                const key_der = try tls13.parsePemPrivateKey(server_key_pem, &key_der_buf);
                const ec_private_key_tmp = tls13.extractEcPrivateKey(key_der) catch try tls13.extractPkcs8EcPrivateKey(key_der);
                const ec_private_key = try alloc.dupe(u8, ec_private_key_tmp);

                const alpn = try alloc.alloc([]const u8, 1);
                alpn[0] = "h3";

                var ticket_key: [16]u8 = undefined;
                std.crypto.random.bytes(&ticket_key);

                break :blk .{
                    .cert_chain_der = cert_chain,
                    .private_key_bytes = ec_private_key,
                    .alpn = alpn,
                    .ticket_key = ticket_key,
                };
            };

            var retry_token_key: [16]u8 = if (config.retry_token_key) |k| k else undefined;
            if (config.retry_token_key == null) std.crypto.random.bytes(&retry_token_key);

            var static_reset_key: [16]u8 = if (config.static_reset_key) |k| k else undefined;
            if (config.static_reset_key == null) std.crypto.random.bytes(&static_reset_key);

            // Connection config
            const conn_config: connection.ConnectionConfig = if (config.conn_config) |cc| cc else blk: {
                var cc: connection.ConnectionConfig = .{ .token_key = retry_token_key };
                if (Handler.protocol == .webtransport or Handler.protocol == .quic) {
                    cc.max_datagram_frame_size = config.max_datagram_frame_size;
                }
                break :blk cc;
            };

            // Create UDP socket
            const sockfd, const local_addr = if (config.ipv6) blk: {
                // IPv6 dual-stack socket (handles both IPv4 and IPv6)
                const addr6 = try std.net.Address.parseIp6("::", config.port);
                const fd6 = try posix.socket(posix.AF.INET6, posix.SOCK.DGRAM | posix.SOCK.NONBLOCK, 0);
                errdefer posix.close(fd6);
                // Allow dual-stack (disable IPV6_V6ONLY)
                const IPV6_V6ONLY: u32 = if (@import("builtin").os.tag == .linux) 26 else 27;
                const zero_val: c_int = 0;
                posix.setsockopt(fd6, posix.IPPROTO.IPV6, IPV6_V6ONLY, std.mem.asBytes(&zero_val)) catch {};
                posix.setsockopt(fd6, posix.SOL.SOCKET, posix.SO.REUSEADDR, &std.mem.toBytes(@as(c_int, 1))) catch {};
                try posix.bind(fd6, &addr6.any, addr6.getOsSockLen());
                break :blk .{ fd6, addr6 };
            } else blk: {
                // IPv4 socket
                const addr4 = try std.net.Address.parseIp4(config.address, config.port);
                const fd4 = try posix.socket(posix.AF.INET, posix.SOCK.DGRAM | posix.SOCK.NONBLOCK, 0);
                errdefer posix.close(fd4);
                posix.setsockopt(fd4, posix.SOL.SOCKET, posix.SO.REUSEADDR, &std.mem.toBytes(@as(c_int, 1))) catch {};
                try posix.bind(fd4, &addr4.any, addr4.getOsSockLen());
                break :blk .{ fd4, addr4 };
            };
            ecn_socket.enableEcnRecv(sockfd) catch {};

            // Optional second socket for preferred_address (connectionmigration)
            const preferred: ?PreferredSocket = if (config.preferred_port) |pp| blk: {
                const pfd, const paddr = if (config.ipv6) v6: {
                    const a6 = try std.net.Address.parseIp6("::", pp);
                    const fd = try posix.socket(posix.AF.INET6, posix.SOCK.DGRAM | posix.SOCK.NONBLOCK, 0);
                    errdefer posix.close(fd);
                    const IPV6_V6ONLY2: u32 = if (@import("builtin").os.tag == .linux) 26 else 27;
                    const zero2: c_int = 0;
                    posix.setsockopt(fd, posix.IPPROTO.IPV6, IPV6_V6ONLY2, std.mem.asBytes(&zero2)) catch {};
                    posix.setsockopt(fd, posix.SOL.SOCKET, posix.SO.REUSEADDR, &std.mem.toBytes(@as(c_int, 1))) catch {};
                    try posix.bind(fd, &a6.any, a6.getOsSockLen());
                    break :v6 .{ fd, a6 };
                } else v4: {
                    const a4 = try std.net.Address.parseIp4(config.address, pp);
                    const fd = try posix.socket(posix.AF.INET, posix.SOCK.DGRAM | posix.SOCK.NONBLOCK, 0);
                    errdefer posix.close(fd);
                    posix.setsockopt(fd, posix.SOL.SOCKET, posix.SO.REUSEADDR, &std.mem.toBytes(@as(c_int, 1))) catch {};
                    try posix.bind(fd, &a4.any, a4.getOsSockLen());
                    break :v4 .{ fd, a4 };
                };
                ecn_socket.enableEcnRecv(pfd) catch {};
                break :blk .{
                    .sockfd = pfd,
                    .local_addr = connection.sockaddrToStorage(&paddr.any),
                    .port = pp,
                    .file = xev.File.initFd(pfd),
                    .poll_completion = .{},
                    .batch = ecn_socket.SendBatch.init(pfd),
                };
            } else null;

            var conn_mgr = connection_manager.ConnectionManager.init(
                alloc,
                tls_config,
                conn_config,
                retry_token_key,
                static_reset_key,
            );
            conn_mgr.require_retry = config.require_retry;

            // Init libxev
            const loop = try xev.Loop.init(.{});
            const file_handle = xev.File.initFd(sockfd);
            const timer_handle = try xev.Timer.init();

            return .{
                .allocator = alloc,
                .handler = handler,
                .conn_mgr = conn_mgr,
                .loop = loop,
                .file = file_handle,
                .timer = timer_handle,
                .poll_completion = .{},
                .timer_completion = .{},
                .timer_cancel_completion = .{},
                .signal_completion = .{},
                .signal_file = null,
                .signal_pipe_fd = null,
                .timer_armed = false,
                .started = false,
                .stopping = false,
                .sockfd = sockfd,
                .local_addr = connection.sockaddrToStorage(&local_addr.any),
                .batch = ecn_socket.SendBatch.init(sockfd),
                .recv_buf = undefined,
                .out_buf = undefined,
                .preferred = preferred,
            };
        }

        pub fn deinit(self: *Self) void {
            // Clean up H0 connections (heap-allocated pointers)
            for (self.conn_mgr.entries.items) |entry| {
                if (entry.h0_conn) |h0c| {
                    h0c.deinit();
                    self.allocator.destroy(h0c);
                    entry.h0_conn = null;
                }
            }
            self.timer.deinit();
            self.loop.deinit();
            posix.close(self.sockfd);
            if (self.preferred) |p| posix.close(p.sockfd);
            if (self.signal_pipe_fd) |fd| posix.close(fd);
            const write_fd = shutdown_pipe_fd.swap(-1, .release);
            if (write_fd >= 0) posix.close(@intCast(write_fd));
            self.conn_mgr.deinit();
        }

        /// Register watchers and start the event loop. Call once before tick().
        pub fn start(self: *Self) void {
            // Register socket readability watch
            self.file.poll(&self.loop, &self.poll_completion, .read, Self, self, onReadable);
            // Register preferred socket if present
            if (self.preferred) |*p| {
                p.file.poll(&self.loop, &p.poll_completion, .read, Self, self, onReadable);
            }
            // Arm initial timer (1ms to kick things off)
            self.timer.run(&self.loop, &self.timer_completion, 1, Self, self, onTimer);
            self.timer_armed = true;
            self.started = true;
        }

        /// Blocking run: registers watchers and runs the event loop until done.
        /// Installs SIGTERM/SIGINT handlers for graceful shutdown.
        pub fn run(self: *Self) !void {
            self.installSignalHandlers();
            self.start();
            try self.loop.run(.until_done);
        }

        /// Non-blocking tick: process all pending events and return immediately.
        /// Call start() once before the first tick().
        pub fn tick(self: *Self) !void {
            if (!self.started) self.start();
            try self.loop.run(.no_wait);
        }

        /// Initiate graceful shutdown. All active connections receive
        /// CONNECTION_CLOSE, pending data is flushed, then the event loop exits.
        pub fn stop(self: *Self) void {
            if (self.stopping) return;
            self.stopping = true;
            std.log.info("graceful shutdown: closing {d} connection(s)", .{self.conn_mgr.entries.items.len});
            for (self.conn_mgr.entries.items) |entry| {
                const conn = entry.conn;
                if (!conn.isClosed() and conn.state != .closing and conn.state != .draining) {
                    conn.close(0, "server shutdown");
                }
            }
            // Flush pending close packets immediately
            self.tickAndSend();
        }

        fn installSignalHandlers(self: *Self) void {
            if (comptime builtin.os.tag == .windows) return;

            // Create a self-pipe so the signal handler can wake the event loop
            const pipe = posix.pipe() catch return;
            shutdown_pipe_fd.store(pipe[1], .release);

            // Watch the read end of the pipe for readability
            self.signal_pipe_fd = pipe[0];
            self.signal_file = xev.File.initFd(pipe[0]);
            self.signal_file.?.poll(&self.loop, &self.signal_completion, .read, Self, self, onSignalPipe);

            const handler = struct {
                fn handle(_: c_int) callconv(.c) void {
                    shutdown_requested.store(true, .release);
                    // Wake the event loop by writing to the pipe
                    const fd = shutdown_pipe_fd.load(.acquire);
                    if (fd >= 0) {
                        _ = posix.write(@intCast(fd), "x") catch {};
                    }
                }
            }.handle;

            const act = posix.Sigaction{
                .handler = .{ .handler = handler },
                .mask = std.mem.zeroes(posix.sigset_t),
                .flags = 0,
            };
            posix.sigaction(posix.SIG.TERM, &act, null);
            posix.sigaction(posix.SIG.INT, &act, null);
        }

        fn onSignalPipe(
            self_opt: ?*Self,
            _: *xev.Loop,
            _: *xev.Completion,
            _: xev.File,
            _: xev.PollError!xev.PollEvent,
        ) xev.CallbackAction {
            const self = self_opt orelse return .disarm;
            // Drain the pipe
            var buf: [16]u8 = undefined;
            _ = posix.read(self.signal_pipe_fd.?, &buf) catch {};

            if (!self.stopping) {
                self.stop();
            }
            if (self.allConnectionsClosed()) {
                self.loop.stop();
                return .disarm;
            }
            return .rearm;
        }

        // ---- Internal callbacks ----

        fn onReadable(
            self_opt: ?*Self,
            _: *xev.Loop,
            _: *xev.Completion,
            _: xev.File,
            r: xev.PollError!xev.PollEvent,
        ) xev.CallbackAction {
            _ = r catch return .rearm;
            const self = self_opt orelse return .disarm;

            // Check for signal-triggered shutdown
            if (shutdown_requested.load(.acquire) and !self.stopping) {
                self.stop();
            }

            // Drain all available packets
            self.recvAllPackets();

            // Process all connections (H3/WT/H0 init + event dispatch)
            self.processConnections();

            // Tick + burst send
            self.tickAndSend();

            if (self.stopping and self.allConnectionsClosed()) {
                self.loop.stop();
                return .disarm;
            }

            // Reschedule timer
            self.rescheduleTimer();

            return .rearm;
        }

        fn onTimer(
            self_opt: ?*Self,
            _: *xev.Loop,
            _: *xev.Completion,
            r: xev.Timer.RunError!void,
        ) xev.CallbackAction {
            _ = r catch return .disarm;
            const self = self_opt orelse return .disarm;
            self.timer_armed = false;

            // Check for signal-triggered shutdown
            if (shutdown_requested.load(.acquire) and !self.stopping) {
                self.stop();
            }

            // Process events generated by timeouts
            self.processConnections();

            // Tick + burst send (after processing, so generated data is included)
            self.tickAndSend();

            if (self.stopping and self.allConnectionsClosed()) {
                self.loop.stop();
                return .disarm;
            }

            // Reschedule timer
            self.rescheduleTimer();

            return .disarm; // one-shot; rescheduled via rescheduleTimer
        }

        fn recvAllPackets(self: *Self) void {
            self.drainSocket(self.sockfd, self.local_addr, &self.batch);
            if (self.preferred) |*p| {
                self.drainSocket(p.sockfd, p.local_addr, &p.batch);
            }
        }

        fn drainSocket(self: *Self, sockfd: posix.socket_t, local_addr: posix.sockaddr.storage, recv_batch: *ecn_socket.SendBatch) void {
            while (true) {
                const recv_result = ecn_socket.recvmsgEcn(sockfd, &self.recv_buf) catch |err| {
                    if (err == error.WouldBlock) break;
                    break;
                };

                switch (self.conn_mgr.recvDatagram(
                    self.recv_buf[0..recv_result.bytes_read],
                    recv_result.from_addr,
                    local_addr,
                    recv_result.ecn,
                    &self.out_buf,
                )) {
                    .processed => |entry| {
                        const conn = entry.conn;
                        const bytes_written = conn.send(&self.out_buf) catch continue;
                        if (bytes_written > 0) {
                            const send_addr = conn.peerAddress();
                            self.batchForConn(conn).add(
                                self.out_buf[0..bytes_written],
                                @ptrCast(send_addr),
                                connection.sockaddrLen(send_addr),
                                conn.getEcnMark(),
                            );
                        }
                    },
                    .send_response => |data| {
                        recv_batch.add(data, @ptrCast(&recv_result.from_addr), recv_result.addr_len, 0);
                    },
                    .dropped => {},
                }
            }

            self.batch.flush();
            if (self.preferred) |*p| p.batch.flush();
        }

        /// Pick the correct SendBatch for a connection based on its local port.
        /// After preferred_address migration, the connection's local_addr will
        /// have the preferred port, so we send from the preferred socket.
        fn batchForConn(self: *Self, conn: *connection.Connection) *ecn_socket.SendBatch {
            if (self.preferred) |*p| {
                const local = conn.localAddress();
                const port = connection.sockaddrPort(local);
                if (port == p.port) return &p.batch;
            }
            return &self.batch;
        }

        fn processConnections(self: *Self) void {
            for (self.conn_mgr.entries.items) |entry| {
                const conn = entry.conn;

                // Initialize protocol layer once handshake completes
                if (conn.isEstablished() and !entry.h3_initialized) {
                    self.initProtocol(entry);
                }

                // Poll events and dispatch to handler
                switch (Handler.protocol) {
                    .webtransport => self.pollWtEvents(entry),
                    .h3 => self.pollH3Events(entry),
                    .h0 => self.pollH0Events(entry),
                    .quic => {},
                }
            }
        }

        fn initProtocol(self: *Self, entry: *ConnEntry) void {
            switch (Handler.protocol) {
                .webtransport => {
                    entry.h3_conn = h3.H3Connection.init(self.allocator, entry.conn, true);
                    entry.h3_conn.?.local_settings = .{
                        .enable_connect_protocol = true,
                        .h3_datagram = true,
                        .enable_webtransport = true,
                        .webtransport_max_sessions = 4,
                    };
                    entry.h3_conn.?.initConnection() catch return;
                    entry.wt_conn = wt.WebTransportConnection.init(
                        self.allocator,
                        &entry.h3_conn.?,
                        entry.conn,
                        true,
                    );
                },
                .h3 => {
                    entry.h3_conn = h3.H3Connection.init(self.allocator, entry.conn, true);
                    entry.h3_conn.?.initConnection() catch return;
                },
                .h0 => {
                    const h0c = self.allocator.create(h0.H0Connection) catch return;
                    h0c.* = h0.H0Connection.init(self.allocator, entry.conn, true);
                    entry.h0_conn = h0c;
                },
                .quic => {},
            }

            entry.h3_initialized = true;
        }

        fn pollWtEvents(self: *Self, entry: *ConnEntry) void {
            if (entry.wt_conn == null) return;
            var wtc = &entry.wt_conn.?;
            var session = Session{ .entry = entry };

            // Allow handler to run deferred work each poll cycle
            if (@hasDecl(Handler, "onPollComplete")) {
                self.handler.onPollComplete(&session);
            }

            while (true) {
                const event = wtc.poll() catch break;
                if (event == null) break;

                switch (event.?) {
                    .connect_request => |req| {
                        if (@hasDecl(Handler, "onConnectRequest")) {
                            self.handler.onConnectRequest(&session, req.session_id, req.path);
                        }
                    },
                    .session_ready => |sr| {
                        if (@hasDecl(Handler, "onSessionReady")) {
                            self.handler.onSessionReady(&session, sr.session_id);
                        }
                    },
                    .stream_data => |sd| {
                        if (@hasDecl(Handler, "onStreamData")) {
                            // Support both 4-arg (with fin) and 3-arg (without fin) signatures
                            if (@typeInfo(@TypeOf(Handler.onStreamData)).@"fn".params.len == 5) {
                                self.handler.onStreamData(&session, sd.stream_id, sd.data, sd.fin);
                            } else {
                                self.handler.onStreamData(&session, sd.stream_id, sd.data);
                            }
                        }
                    },
                    .datagram => |dg| {
                        if (@hasDecl(Handler, "onDatagram")) {
                            self.handler.onDatagram(&session, dg.session_id, dg.data);
                        }
                        if (dg.data.len > 0) self.allocator.free(dg.data);
                    },
                    .session_closed => |cls| {
                        if (@hasDecl(Handler, "onSessionClosed")) {
                            self.handler.onSessionClosed(&session, cls.session_id, cls.error_code, cls.reason);
                        }
                    },
                    .session_draining => |drain| {
                        if (@hasDecl(Handler, "onSessionDraining")) {
                            self.handler.onSessionDraining(&session, drain.session_id);
                        }
                    },
                    .bidi_stream => |bs| {
                        if (@hasDecl(Handler, "onBidiStream")) {
                            self.handler.onBidiStream(&session, bs.session_id, bs.stream_id);
                        }
                    },
                    .uni_stream => |us| {
                        if (@hasDecl(Handler, "onUniStream")) {
                            self.handler.onUniStream(&session, us.session_id, us.stream_id);
                        }
                    },
                    .session_rejected => {},
                }
            }
        }

        fn pollH3Events(self: *Self, entry: *ConnEntry) void {
            if (entry.h3_conn == null) return;
            var h3c = &entry.h3_conn.?;
            var session = Session{ .entry = entry };

            while (true) {
                const event = h3c.poll() catch break;
                if (event == null) break;

                switch (event.?) {
                    .headers => |hdr| {
                        if (@hasDecl(Handler, "onRequest")) {
                            self.handler.onRequest(&session, hdr.stream_id, hdr.headers);
                        }
                    },
                    .data => |d| {
                        if (@hasDecl(Handler, "onData")) {
                            var body_buf: [8192]u8 = undefined;
                            while (true) {
                                const n = h3c.recvBody(&body_buf);
                                if (n == 0) break;
                                self.handler.onData(&session, d.stream_id, body_buf[0..n]);
                            }
                        } else {
                            // Drain body even if handler doesn't consume it
                            var sink: [4096]u8 = undefined;
                            while (h3c.recvBody(&sink) > 0) {}
                        }
                    },
                    .settings, .finished, .goaway, .connect_request, .shutdown_complete, .request_cancelled => {},
                }
            }
        }

        fn pollH0Events(self: *Self, entry: *ConnEntry) void {
            const h0c = entry.h0_conn orelse return;
            var session = Session{ .entry = entry };

            while (true) {
                const event = h0c.poll() catch break;
                if (event == null) break;

                switch (event.?) {
                    .request => |req| {
                        if (@hasDecl(Handler, "onH0Request")) {
                            self.handler.onH0Request(&session, req.stream_id, req.path);
                        }
                    },
                    .data => |d| {
                        if (@hasDecl(Handler, "onH0Data")) {
                            self.handler.onH0Data(&session, d.stream_id, d.data);
                        }
                    },
                    .finished => |stream_id| {
                        if (@hasDecl(Handler, "onH0Finished")) {
                            self.handler.onH0Finished(&session, stream_id);
                        }
                    },
                }
            }
        }

        fn tickAndSend(self: *Self) void {
            var i: usize = 0;
            while (i < self.conn_mgr.entries.items.len) {
                const entry = self.conn_mgr.entries.items[i];

                if (!self.conn_mgr.tickEntry(entry)) {
                    // Entry was removed — clean up H0 pointer if present
                    // (tickEntry already freed the entry, but we cleaned h0 before tick)
                    continue; // removed, don't increment
                }

                const conn = entry.conn;
                const batch = self.batchForConn(conn);
                const max_burst_packets = 1000;
                var send_count: usize = 0;
                while (send_count < max_burst_packets) : (send_count += 1) {
                    const bytes_written = conn.send(&self.out_buf) catch break;
                    if (bytes_written == 0) break;
                    const send_addr = conn.peerAddress();
                    batch.add(
                        self.out_buf[0..bytes_written],
                        @ptrCast(send_addr),
                        connection.sockaddrLen(send_addr),
                        conn.getEcnMark(),
                    );
                }

                i += 1;
            }

            self.batch.flush();
            if (self.preferred) |*p| p.batch.flush();
        }

        fn rescheduleTimer(self: *Self) void {
            const next_ms = self.computeNextTimeoutMs() orelse return;

            if (self.timer_armed) {
                self.timer.reset(
                    &self.loop,
                    &self.timer_completion,
                    &self.timer_cancel_completion,
                    next_ms,
                    Self,
                    self,
                    onTimer,
                );
            } else {
                self.timer.run(
                    &self.loop,
                    &self.timer_completion,
                    next_ms,
                    Self,
                    self,
                    onTimer,
                );
            }
            self.timer_armed = true;
        }

        fn allConnectionsClosed(self: *Self) bool {
            for (self.conn_mgr.entries.items) |entry| {
                if (!entry.conn.isClosed()) return false;
            }
            return true;
        }

        fn computeNextTimeoutMs(self: *Self) ?u64 {
            const now: i64 = @intCast(std.time.nanoTimestamp());
            var earliest: ?i64 = null;

            for (self.conn_mgr.entries.items) |entry| {
                if (entry.conn.nextTimeoutNs()) |deadline| {
                    if (earliest == null or deadline < earliest.?) {
                        earliest = deadline;
                    }
                }
            }

            const deadline = earliest orelse return null;
            const delta_ns = deadline - now;
            if (delta_ns <= 0) return 1; // fire immediately (overdue)
            // Convert ns to ms (truncate, don't add extra ms)
            const ms: u64 = @intCast(@divFloor(delta_ns, 1_000_000));
            return if (ms == 0) 1 else ms;
        }
    };
}
