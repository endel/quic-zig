const std = @import("std");
const posix = std.posix;
const builtin = @import("builtin");
const log = std.log.scoped(.event_loop);
const xev_mod = @import("xev");

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
const http1 = @import("http1/server.zig");
const qpack = @import("h3/qpack.zig");
const wt = @import("webtransport/session.zig");
const Certificate = std.crypto.Certificate;

pub const Protocol = enum { quic, h3, h0, webtransport };

pub const Http1Config = http1.Http1Config;

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

    /// Enable HTTP/1.1 static file server on TCP alongside QUIC on UDP.
    /// Uses the same port (TCP and UDP are separate namespaces) by default.
    /// Serves files from static_dir and advertises HTTP/3 via Alt-Svc header.
    http1: ?Http1Config = null,
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

    // --- Raw QUIC methods ---

    pub fn writeStream(self: *Session, stream_id: u64, data: []const u8) !void {
        const stream = self.entry.conn.streams.getStream(stream_id) orelse return error.StreamNotFound;
        try stream.send.writeData(data);
    }

    pub fn closeQuicStream(self: *Session, stream_id: u64) void {
        if (self.entry.conn.streams.getStream(stream_id)) |stream| {
            stream.send.close();
        }
    }

    pub fn readStream(self: *Session, stream_id: u64) ?[]const u8 {
        const stream = self.entry.conn.streams.getStream(stream_id) orelse return null;
        return stream.recv.read();
    }

    pub fn openStream(self: *Session) !u64 {
        const stream = try self.entry.conn.openStream();
        return stream.stream_id;
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
            "onStreamFinished", "onDatagram",       "onSessionClosed",
            "onSessionDraining","onBidiStream",     "onUniStream",
            "onPollComplete",   "onRequest",        "onData",
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
                        "onSessionReady, onStreamData, onStreamFinished, onDatagram, onSessionClosed, " ++
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

        /// Optional HTTP/1.1 static file server (runs on a separate thread).
        http1_server: ?http1.Http1Server,

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

            // Optional HTTP/1.1 static file server
            const http1_server: ?http1.Http1Server = if (config.http1) |h1cfg|
                try http1.Http1Server.init(config.address, h1cfg, config.port, .{
                    .cert_chain_der = tls_config.cert_chain_der,
                    .private_key_bytes = tls_config.private_key_bytes,
                })
            else
                null;

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
                .timer_armed = false,
                .started = false,
                .stopping = false,
                .sockfd = sockfd,
                .local_addr = connection.sockaddrToStorage(&local_addr.any),
                .batch = ecn_socket.SendBatch.init(sockfd),
                .recv_buf = undefined,
                .out_buf = undefined,
                .preferred = preferred,
                .http1_server = http1_server,
            };
        }

        pub fn deinit(self: *Self) void {
            // Stop HTTP/1.1 server
            if (self.http1_server) |*h1| h1.deinit();

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
            // Start HTTP/1.1 server thread if configured
            if (self.http1_server) |*h1| {
                h1.start() catch |err| {
                    log.err("Failed to start HTTP/1.1 server: {any}", .{err});
                };
            }
            // Arm initial timer (1ms to kick things off)
            self.timer.run(&self.loop, &self.timer_completion, 1, Self, self, onTimer);
            self.timer_armed = true;
            self.started = true;
        }

        /// Blocking run: registers watchers and runs the event loop until done.
        pub fn run(self: *Self) !void {
            self.start();
            try self.loop.run(.until_done);
        }

        /// Non-blocking tick: process all pending events and return immediately.
        /// Call start() once before the first tick().
        pub fn tick(self: *Self) !void {
            if (!self.started) self.start();
            try self.loop.run(.no_wait);
        }

        /// Flush any data queued by external callers (e.g. C API handlers that
        /// called sendStreamData / acceptSession / sendDatagram between ticks).
        /// This ensures outgoing QUIC packets are built and sent immediately
        /// rather than waiting for the next onReadable / onTimer callback.
        pub fn flush(self: *Self) void {
            for (self.conn_mgr.entries.items) |entry| {
                const conn = entry.conn;
                if (conn.isClosed()) continue;
                const batch = self.batchForConn(conn);
                var send_count: usize = 0;
                while (send_count < 1000) : (send_count += 1) {
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
            }
            self.batch.flush();
            if (self.preferred) |*p| p.batch.flush();
            self.rescheduleTimer();
        }

        /// Initiate graceful shutdown. All active connections receive
        /// CONNECTION_CLOSE, pending data is flushed, then the event loop exits.
        pub fn stop(self: *Self) void {
            self.stopping = true;
            for (self.conn_mgr.entries.items) |entry| {
                const conn = entry.conn;
                if (!conn.isClosed() and conn.state != .closing and conn.state != .draining) {
                    conn.close(0, "server shutdown");
                }
            }
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

            // Process loop: receive → dispatch events → send responses.
            // Loop to catch packets that arrive during processing (critical for
            // edge-triggered I/O where we'd otherwise miss them until the next
            // timer fires, causing ~30ms latency spikes).
            var iterations: usize = 0;
            while (iterations < 4) : (iterations += 1) {
                const received = self.recvAllPackets();
                self.processConnections();
                self.tickAndSend();

                // If no new packets arrived during this cycle, we're done.
                // On the first iteration we always process (triggered by poll event).
                if (iterations > 0 and !received) break;
            }

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

            // Also drain any packets that may have arrived (edge-triggered
            // poll may not re-fire if data arrived while we were processing).
            _ = self.recvAllPackets();

            // Process events generated by timeouts + received packets
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

        fn recvAllPackets(self: *Self) bool {
            var received = self.drainSocket(self.sockfd, self.local_addr, &self.batch);
            if (self.preferred) |*p| {
                if (self.drainSocket(p.sockfd, p.local_addr, &p.batch)) received = true;
            }
            return received;
        }

        fn drainSocket(self: *Self, sockfd: posix.socket_t, local_addr: posix.sockaddr.storage, recv_batch: *ecn_socket.SendBatch) bool {
            var received = false;
            while (true) {
                const recv_result = ecn_socket.recvmsgEcn(sockfd, &self.recv_buf) catch |err| {
                    if (err == error.WouldBlock) break;
                    break;
                };
                received = true;

                switch (self.conn_mgr.recvDatagram(
                    self.recv_buf[0..recv_result.bytes_read],
                    recv_result.from_addr,
                    local_addr,
                    recv_result.ecn,
                    &self.out_buf,
                )) {
                    .processed => {},
                    .send_response => |data| {
                        recv_batch.add(data, @ptrCast(&recv_result.from_addr), recv_result.addr_len, 0);
                    },
                    .dropped => {},
                }
            }

            // No flush here — tickAndSend handles flushing so that ACKs
            // from recv processing and stream data from event handlers are
            // coalesced into fewer packets (reducing round-trips).
            return received;
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
                    .quic => self.pollQuicEvents(entry),
                }

                // Remove streams that were queued for disposal during this cycle.
                // WT layer reads the queue first (to clean its own maps), then
                // QUIC layer drains it (actually removing stream objects).
                if (Handler.protocol == .webtransport) {
                    if (entry.wt_conn) |*wtc| wtc.drainDisposalQueue();
                }
                conn.streams.drainDisposalQueue();
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
                            self.handler.onStreamData(&session, sd.stream_id, sd.data);
                        }
                    },
                    .stream_finished => |sf| {
                        if (@hasDecl(Handler, "onStreamFinished")) {
                            self.handler.onStreamFinished(&session, sf.stream_id);
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

        fn pollQuicEvents(self: *Self, entry: *ConnEntry) void {
            const conn = entry.conn;
            var session = Session{ .entry = entry };

            if (@hasDecl(Handler, "onPollComplete")) {
                self.handler.onPollComplete(&session);
            }

            var stream_it = conn.streams.streams.iterator();
            while (stream_it.next()) |kv| {
                const stream_id = kv.key_ptr.*;
                const stream = kv.value_ptr.*;

                if (stream.recv.read()) |data| {
                    if (@hasDecl(Handler, "onStreamData")) {
                        self.handler.onStreamData(&session, stream_id, data);
                    }
                    self.allocator.free(data);
                }
                if (stream.recv.finished and !entry.finished_streams.contains(stream_id)) {
                    entry.finished_streams.put(self.allocator, stream_id, {}) catch {};
                    if (@hasDecl(Handler, "onStreamFinished")) {
                        self.handler.onStreamFinished(&session, stream_id);
                    }
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

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

pub const ClientConfig = struct {
    // Target server
    address: []const u8 = "127.0.0.1",
    port: u16 = 4433,
    server_name: []const u8 = "localhost",

    // WebTransport session path (auto-CONNECT on handshake complete)
    path: []const u8 = "/.well-known/webtransport",

    // TLS ALPN override (when null, derived from handler protocol: "h3" for h3/webtransport)
    alpn: ?[]const u8 = null,

    // TLS verification
    ca_cert_path: ?[]const u8 = null,
    skip_cert_verify: bool = false,

    // QUIC transport
    max_datagram_frame_size: u64 = 65536,

    // Advanced overrides
    tls_config: ?tls13.TlsConfig = null,
    conn_config: ?connection.ConnectionConfig = null,

    // IPv6
    ipv6: bool = false,
};

/// ClientSession wraps a single client-side connection and provides the same
/// convenience methods as the server-side Session.
pub const ClientSession = struct {
    conn: *connection.Connection,
    h3_conn: ?*h3.H3Connection = null,
    wt_conn: ?*wt.WebTransportConnection = null,

    // --- H3 methods ---

    pub fn sendRequest(self: *ClientSession, headers: []const qpack.Header, body: ?[]const u8) !u64 {
        if (self.h3_conn) |h3c| {
            return try h3c.sendRequest(headers, body);
        }
        return error.NoH3Connection;
    }

    pub fn sendResponse(self: *ClientSession, stream_id: u64, headers: []const qpack.Header, body: []const u8) !void {
        if (self.h3_conn) |h3c| {
            try h3c.sendResponse(stream_id, headers, body);
        } else return error.NoH3Connection;
    }

    pub fn recvBody(self: *ClientSession, buf: []u8) usize {
        if (self.h3_conn) |h3c| {
            return h3c.recvBody(buf);
        }
        return 0;
    }

    // --- Raw QUIC methods ---

    pub fn openStream(self: *ClientSession) !u64 {
        const stream = try self.conn.openStream();
        return stream.stream_id;
    }

    pub fn openQuicUniStream(self: *ClientSession) !u64 {
        const send_stream = try self.conn.openUniStream();
        return send_stream.stream_id;
    }

    pub fn writeStream(self: *ClientSession, stream_id: u64, data: []const u8) !void {
        const stream = self.conn.streams.getStream(stream_id) orelse return error.StreamNotFound;
        try stream.send.writeData(data);
    }

    pub fn closeQuicStream(self: *ClientSession, stream_id: u64) void {
        if (self.conn.streams.getStream(stream_id)) |stream| {
            stream.send.close();
        }
    }

    pub fn readStream(self: *ClientSession, stream_id: u64) ?[]const u8 {
        const stream = self.conn.streams.getStream(stream_id) orelse return null;
        return stream.recv.read();
    }

    // --- WebTransport methods ---

    pub fn sendStreamData(self: *ClientSession, stream_id: u64, data: []const u8) !void {
        if (self.wt_conn) |wtc| {
            try wtc.sendStreamData(stream_id, data);
        } else return error.NoWtConnection;
    }

    pub fn sendDatagram(self: *ClientSession, session_id: u64, data: []const u8) !void {
        if (self.wt_conn) |wtc| {
            try wtc.sendDatagram(session_id, data);
        } else return error.NoWtConnection;
    }

    pub fn closeStream(self: *ClientSession, stream_id: u64) void {
        if (self.wt_conn) |wtc| {
            wtc.closeStream(stream_id);
        }
    }

    pub fn openBidiStream(self: *ClientSession, session_id: u64) !u64 {
        if (self.wt_conn) |wtc| {
            return try wtc.openBidiStream(session_id);
        }
        return error.NoWtConnection;
    }

    pub fn openUniStream(self: *ClientSession, session_id: u64) !u64 {
        if (self.wt_conn) |wtc| {
            return try wtc.openUniStream(session_id);
        }
        return error.NoWtConnection;
    }

    pub fn closeSession(self: *ClientSession, session_id: u64) void {
        if (self.wt_conn) |wtc| {
            wtc.closeSession(session_id);
        }
    }

    pub fn closeSessionWithError(self: *ClientSession, session_id: u64, error_code: u32, reason: []const u8) !void {
        if (self.wt_conn) |wtc| {
            try wtc.closeSessionWithError(session_id, error_code, reason);
        }
    }

    pub fn resetStream(self: *ClientSession, stream_id: u64, error_code: u32) void {
        if (self.wt_conn) |wtc| {
            wtc.resetStream(stream_id, error_code);
        }
    }

    pub fn drainSession(self: *ClientSession, session_id: u64) !void {
        if (self.wt_conn) |wtc| {
            try wtc.drainSession(session_id);
        }
    }

    pub fn closeConnection(self: *ClientSession) void {
        self.conn.close(0, "");
    }

    pub fn isDatagramSendQueueFull(self: *const ClientSession) bool {
        if (self.wt_conn) |wtc| {
            return wtc.isDatagramSendQueueFull();
        }
        return true;
    }

    pub fn maxDatagramPayloadSize(self: *const ClientSession, session_id: u64) ?usize {
        if (self.wt_conn) |wtc| {
            return wtc.maxDatagramPayloadSize(session_id);
        }
        return null;
    }

    pub fn sendKeepAlive(self: *ClientSession) void {
        self.conn.sendKeepAlive();
    }
};

pub fn Client(comptime Handler: type) type {
    comptime {
        if (!@hasDecl(Handler, "protocol")) {
            @compileError("Handler must declare 'pub const protocol: event_loop.Protocol'");
        }

        const known = [_][]const u8{
            // Common
            "onConnected",        "onPollComplete",
            // H3
            "onHeaders",          "onData",            "onFinished",
            "onSettings",         "onGoaway",
            // Raw QUIC
            "onStreamData",       "onStreamFinished",
            // WebTransport
            "onSessionReady",     "onSessionRejected",
            "onDatagram",         "onSessionClosed",
            "onSessionDraining",  "onBidiStream",      "onUniStream",
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
                        "'. Known client callbacks: onConnected, onPollComplete, " ++
                        "onHeaders, onData, onFinished, onSettings, onGoaway, " ++
                        "onStreamData, onStreamFinished, " ++
                        "onSessionReady, onSessionRejected, onDatagram, onSessionClosed, " ++
                        "onSessionDraining, onBidiStream, onUniStream");
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

        // libxev
        loop: xev.Loop,
        file: xev.File,
        timer: xev.Timer,
        poll_completion: xev.Completion,
        timer_completion: xev.Completion,
        timer_cancel_completion: xev.Completion,
        timer_armed: bool,
        started: bool,
        stopping: bool,

        // I/O
        sockfd: posix.socket_t,
        local_addr: posix.sockaddr.storage,
        batch: ecn_socket.SendBatch,
        recv_buf: [8192]u8,
        out_buf: [1500]u8,

        // Single QUIC connection
        conn: *connection.Connection,
        remote_addr: posix.sockaddr.storage,

        // Protocol layers (initialized after handshake)
        h3_conn: ?h3.H3Connection,
        wt_conn: ?wt.WebTransportConnection,
        protocol_initialized: bool,
        session_id: ?u64,

        // For raw QUIC: track streams whose fin has been delivered
        finished_streams: std.AutoHashMap(u64, void),

        // Config retained for protocol init
        server_name: []const u8,
        path: []const u8,

        pub fn init(alloc: std.mem.Allocator, handler: *Handler, config: ClientConfig) !Self {
            // Build TLS config
            const tls_config: tls13.TlsConfig = if (config.tls_config) |tc| tc else blk: {
                const alpn = try alloc.alloc([]const u8, 1);
                alpn[0] = if (config.alpn) |a| a else switch (Handler.protocol) {
                    .h3, .webtransport => "h3",
                    .quic, .h0 => "h3", // default; override via config.alpn for custom protocols
                };

                var ca_bundle: ?*Certificate.Bundle = null;
                if (config.ca_cert_path) |ca_path| {
                    const bundle_ptr = try alloc.create(Certificate.Bundle);
                    bundle_ptr.* = .{};
                    try bundle_ptr.addCertsFromFilePath(alloc, std.fs.cwd(), ca_path);
                    ca_bundle = bundle_ptr;
                }

                break :blk .{
                    .cert_chain_der = &.{},
                    .private_key_bytes = &.{},
                    .alpn = alpn,
                    .server_name = config.server_name,
                    .skip_cert_verify = config.skip_cert_verify,
                    .ca_bundle = ca_bundle,
                };
            };

            // Connection config
            const conn_config: connection.ConnectionConfig = if (config.conn_config) |cc| cc else cc_blk: {
                var cc: connection.ConnectionConfig = .{};
                if (Handler.protocol == .webtransport or Handler.protocol == .quic) {
                    cc.max_datagram_frame_size = config.max_datagram_frame_size;
                }
                break :cc_blk cc;
            };

            // Create QUIC client connection
            const conn = try connection.connect(
                alloc,
                config.server_name,
                conn_config,
                tls_config,
                null,
            );
            // Heap-allocate so pointers remain stable
            const conn_ptr = try alloc.create(connection.Connection);
            errdefer {
                conn_ptr.deinit();
                alloc.destroy(conn_ptr);
            }
            conn_ptr.* = conn;

            // Resolve remote address
            const remote_addr = if (config.ipv6) blk: {
                const addr6 = try std.net.Address.parseIp6(config.address, config.port);
                break :blk connection.sockaddrToStorage(&addr6.any);
            } else blk: {
                const addr4 = try std.net.Address.parseIp4(config.address, config.port);
                break :blk connection.sockaddrToStorage(&addr4.any);
            };

            // Create non-blocking UDP socket, bind to ephemeral port
            const sockfd, const local_addr = if (config.ipv6) blk: {
                const addr6 = try std.net.Address.parseIp6("::", 0);
                const fd = try posix.socket(posix.AF.INET6, posix.SOCK.DGRAM | posix.SOCK.NONBLOCK, 0);
                errdefer posix.close(fd);
                const IPV6_V6ONLY: u32 = if (@import("builtin").os.tag == .linux) 26 else 27;
                const zero_val: c_int = 0;
                posix.setsockopt(fd, posix.IPPROTO.IPV6, IPV6_V6ONLY, std.mem.asBytes(&zero_val)) catch {};
                try posix.bind(fd, &addr6.any, addr6.getOsSockLen());
                break :blk .{ fd, addr6 };
            } else blk: {
                const addr4 = try std.net.Address.parseIp4("0.0.0.0", 0);
                const fd = try posix.socket(posix.AF.INET, posix.SOCK.DGRAM | posix.SOCK.NONBLOCK, 0);
                errdefer posix.close(fd);
                try posix.bind(fd, &addr4.any, addr4.getOsSockLen());
                break :blk .{ fd, addr4 };
            };
            errdefer posix.close(sockfd);
            ecn_socket.enableEcnRecv(sockfd) catch {};

            // Init libxev
            const loop = try xev.Loop.init(.{});
            const file_handle = xev.File.initFd(sockfd);
            const timer_handle = try xev.Timer.init();

            return .{
                .allocator = alloc,
                .handler = handler,
                .loop = loop,
                .file = file_handle,
                .timer = timer_handle,
                .poll_completion = .{},
                .timer_completion = .{},
                .timer_cancel_completion = .{},
                .timer_armed = false,
                .started = false,
                .stopping = false,
                .sockfd = sockfd,
                .local_addr = connection.sockaddrToStorage(&local_addr.any),
                .batch = ecn_socket.SendBatch.init(sockfd),
                .recv_buf = undefined,
                .out_buf = undefined,
                .conn = conn_ptr,
                .remote_addr = remote_addr,
                .h3_conn = null,
                .wt_conn = null,
                .protocol_initialized = false,
                .session_id = null,
                .finished_streams = std.AutoHashMap(u64, void).init(alloc),
                .server_name = config.server_name,
                .path = config.path,
            };
        }

        pub fn deinit(self: *Self) void {
            if (self.wt_conn) |*wtc| wtc.deinit();
            if (self.h3_conn) |*h3c| h3c.deinit();
            self.finished_streams.deinit();
            self.timer.deinit();
            self.loop.deinit();
            posix.close(self.sockfd);
            self.conn.deinit();
            self.allocator.destroy(self.conn);
        }

        pub fn start(self: *Self) void {
            self.file.poll(&self.loop, &self.poll_completion, .read, Self, self, onReadable);
            self.timer.run(&self.loop, &self.timer_completion, 1, Self, self, onTimer);
            self.timer_armed = true;
            self.started = true;
        }

        pub fn run(self: *Self) !void {
            self.start();
            try self.loop.run(.until_done);
        }

        pub fn tick(self: *Self) !void {
            if (!self.started) self.start();
            try self.loop.run(.no_wait);
        }

        pub fn flush(self: *Self) void {
            const conn = self.conn;
            if (conn.isClosed()) return;
            const send_addr: *const posix.sockaddr.storage = if (conn.isEstablished())
                conn.peerAddress()
            else
                &self.remote_addr;
            var send_count: usize = 0;
            while (send_count < 1000) : (send_count += 1) {
                const bytes_written = conn.send(&self.out_buf) catch break;
                if (bytes_written == 0) break;
                self.batch.add(
                    self.out_buf[0..bytes_written],
                    @ptrCast(send_addr),
                    connection.sockaddrLen(send_addr),
                    conn.getEcnMark(),
                );
            }
            self.batch.flush();
            self.rescheduleTimer();
        }

        pub fn stop(self: *Self) void {
            self.stopping = true;
            const conn = self.conn;
            if (!conn.isClosed() and conn.state != .closing and conn.state != .draining) {
                conn.close(0, "client shutdown");
            }
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

            // Process loop: catch packets arriving during processing
            var iterations: usize = 0;
            while (iterations < 4) : (iterations += 1) {
                const received = self.recvAllPackets();
                self.processConnection();
                self.tickAndSend();

                if (iterations > 0 and !received) break;
            }

            if (self.stopping and self.conn.isClosed()) {
                self.loop.stop();
                return .disarm;
            }

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

            _ = self.recvAllPackets();
            self.processConnection();
            self.tickAndSend();

            if (self.stopping and self.conn.isClosed()) {
                self.loop.stop();
                return .disarm;
            }

            self.rescheduleTimer();
            return .disarm;
        }

        fn recvAllPackets(self: *Self) bool {
            var received = false;
            while (true) {
                const recv_result = ecn_socket.recvmsgEcn(self.sockfd, &self.recv_buf) catch |err| {
                    if (err == error.WouldBlock) break;
                    break;
                };
                received = true;

                // Update remote addr (may change due to preferred address migration)
                self.remote_addr = recv_result.from_addr;

                self.conn.handleDatagram(self.recv_buf[0..recv_result.bytes_read], .{
                    .to = self.local_addr,
                    .from = recv_result.from_addr,
                    .ecn = recv_result.ecn,
                    .datagram_size = recv_result.bytes_read,
                });

                // Don't send here — tickAndSend will coalesce ACKs with
                // stream data into a single QUIC packet, reducing round-trips.
            }
            // No flush — tickAndSend handles it
            return received;
        }

        fn processConnection(self: *Self) void {
            const conn = self.conn;

            // Initialize protocol layer once handshake completes
            if (conn.isEstablished() and !self.protocol_initialized) {
                self.initProtocol();

                if (@hasDecl(Handler, "onConnected")) {
                    var session = self.makeSession();
                    self.handler.onConnected(&session);
                }
            }

            // Poll events and dispatch to handler
            switch (Handler.protocol) {
                .webtransport => self.pollWtEvents(),
                .h3 => self.pollH3Events(),
                .quic => self.pollQuicEvents(),
                .h0 => {},
            }

            // Drain disposal queues
            if (Handler.protocol == .webtransport) {
                if (self.wt_conn) |*wtc| wtc.drainDisposalQueue();
            }
            conn.streams.drainDisposalQueue();
        }

        fn initProtocol(self: *Self) void {
            switch (Handler.protocol) {
                .webtransport => {
                    self.h3_conn = h3.H3Connection.init(self.allocator, self.conn, false);
                    self.h3_conn.?.local_settings = .{
                        .enable_connect_protocol = true,
                        .h3_datagram = true,
                        .enable_webtransport = true,
                        .webtransport_max_sessions = 1,
                    };
                    self.h3_conn.?.initConnection() catch return;

                    self.wt_conn = wt.WebTransportConnection.init(
                        self.allocator,
                        &self.h3_conn.?,
                        self.conn,
                        false,
                    );

                    // Send Extended CONNECT to establish WebTransport session
                    const session_id = self.wt_conn.?.connect(
                        self.server_name,
                        self.path,
                    ) catch return;
                    self.session_id = session_id;
                },
                .h3 => {
                    self.h3_conn = h3.H3Connection.init(self.allocator, self.conn, false);
                    self.h3_conn.?.initConnection() catch return;
                },
                .quic, .h0 => {},
            }
            self.protocol_initialized = true;
        }

        fn pollWtEvents(self: *Self) void {
            if (self.wt_conn == null) return;
            var wtc = &self.wt_conn.?;
            var session = self.makeSession();

            if (@hasDecl(Handler, "onPollComplete")) {
                self.handler.onPollComplete(&session);
            }

            while (true) {
                const event = wtc.poll() catch break;
                if (event == null) break;

                switch (event.?) {
                    .session_ready => |sr| {
                        if (@hasDecl(Handler, "onSessionReady")) {
                            self.handler.onSessionReady(&session, sr.session_id);
                        }
                    },
                    .session_rejected => |rej| {
                        if (@hasDecl(Handler, "onSessionRejected")) {
                            self.handler.onSessionRejected(&session, rej.session_id, rej.status);
                        }
                    },
                    .stream_data => |sd| {
                        if (@hasDecl(Handler, "onStreamData")) {
                            self.handler.onStreamData(&session, sd.stream_id, sd.data);
                        }
                    },
                    .stream_finished => |sf| {
                        if (@hasDecl(Handler, "onStreamFinished")) {
                            self.handler.onStreamFinished(&session, sf.stream_id);
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
                    .connect_request => {},
                }
            }
        }

        fn pollH3Events(self: *Self) void {
            if (self.h3_conn == null) return;
            var h3c = &self.h3_conn.?;
            var session = self.makeSession();

            if (@hasDecl(Handler, "onPollComplete")) {
                self.handler.onPollComplete(&session);
            }

            while (true) {
                const event = h3c.poll() catch break;
                if (event == null) break;

                switch (event.?) {
                    .headers => |hdr| {
                        if (@hasDecl(Handler, "onHeaders")) {
                            self.handler.onHeaders(&session, hdr.stream_id, hdr.headers);
                        }
                    },
                    .data => |d| {
                        if (@hasDecl(Handler, "onData")) {
                            self.handler.onData(&session, d.stream_id, d.len);
                        } else {
                            // Drain body even if handler doesn't consume it
                            var sink: [4096]u8 = undefined;
                            while (h3c.recvBody(&sink) > 0) {}
                        }
                    },
                    .finished => |stream_id| {
                        if (@hasDecl(Handler, "onFinished")) {
                            self.handler.onFinished(&session, stream_id);
                        }
                    },
                    .settings => |settings| {
                        if (@hasDecl(Handler, "onSettings")) {
                            self.handler.onSettings(&session, settings);
                        }
                    },
                    .goaway => |id| {
                        if (@hasDecl(Handler, "onGoaway")) {
                            self.handler.onGoaway(&session, id);
                        }
                    },
                    .connect_request, .shutdown_complete, .request_cancelled => {},
                }
            }
        }

        fn pollQuicEvents(self: *Self) void {
            const conn = self.conn;
            var session = self.makeSession();

            if (@hasDecl(Handler, "onPollComplete")) {
                self.handler.onPollComplete(&session);
            }

            // Poll bidi streams for incoming data
            var stream_it = conn.streams.streams.iterator();
            while (stream_it.next()) |entry| {
                const stream_id = entry.key_ptr.*;
                const stream = entry.value_ptr.*;

                if (stream.recv.read()) |data| {
                    if (@hasDecl(Handler, "onStreamData")) {
                        self.handler.onStreamData(&session, stream_id, data);
                    }
                    self.allocator.free(data);
                }
                if (stream.recv.finished and !self.finished_streams.contains(stream_id)) {
                    self.finished_streams.put(stream_id, {}) catch {};
                    if (@hasDecl(Handler, "onStreamFinished")) {
                        self.handler.onStreamFinished(&session, stream_id);
                    }
                }
            }
        }

        fn tickAndSend(self: *Self) void {
            const conn = self.conn;
            conn.onTimeout() catch |err| {
                std.log.warn("client onTimeout error: {}", .{err});
            };

            if (conn.isClosed()) {
                if (self.stopping) self.loop.stop();
                return;
            }

            // Use remote_addr for pre-handshake, peer address after connection established
            const send_addr: *const posix.sockaddr.storage = if (conn.isEstablished())
                conn.peerAddress()
            else
                &self.remote_addr;

            const max_burst_packets = 1000;
            var send_count: usize = 0;
            while (send_count < max_burst_packets) : (send_count += 1) {
                const bytes_written = conn.send(&self.out_buf) catch break;
                if (bytes_written == 0) break;
                self.batch.add(
                    self.out_buf[0..bytes_written],
                    @ptrCast(send_addr),
                    connection.sockaddrLen(send_addr),
                    conn.getEcnMark(),
                );
            }
            self.batch.flush();
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

        fn computeNextTimeoutMs(self: *Self) ?u64 {
            const deadline = self.conn.nextTimeoutNs() orelse return null;
            const now: i64 = @intCast(std.time.nanoTimestamp());
            const delta_ns = deadline - now;
            if (delta_ns <= 0) return 1;
            const ms: u64 = @intCast(@divFloor(delta_ns, 1_000_000));
            return if (ms == 0) 1 else ms;
        }

        fn makeSession(self: *Self) ClientSession {
            return .{
                .conn = self.conn,
                .h3_conn = if (self.h3_conn != null) &self.h3_conn.? else null,
                .wt_conn = if (self.wt_conn != null) &self.wt_conn.? else null,
            };
        }
    };
}

// ─── Tests ───────────────────────────────────────────────────────────

const testing = std.testing;
const crypto = std.crypto;
const EcdsaP256Sha256 = crypto.sign.ecdsa.EcdsaP256Sha256;

fn makeTestTlsConfig() tls13.TlsConfig {
    const server_key_pair = EcdsaP256Sha256.KeyPair.generate();
    const S = struct {
        var secret_key_bytes: [32]u8 = undefined;
        var pub_key_bytes: [65]u8 = undefined;
        var cert_chain: [1][]const u8 = undefined;
        var alpn: [1][]const u8 = undefined;
        var ticket_key: [16]u8 = undefined;
    };
    S.secret_key_bytes = server_key_pair.secret_key.toBytes();
    S.pub_key_bytes = server_key_pair.public_key.toUncompressedSec1();
    S.cert_chain = .{&S.pub_key_bytes};
    S.alpn = .{"h3"};
    crypto.random.bytes(&S.ticket_key);
    return .{
        .cert_chain_der = &S.cert_chain,
        .private_key_bytes = &S.secret_key_bytes,
        .alpn = &S.alpn,
        .ticket_key = S.ticket_key,
    };
}

// Handler with compile-time validation
const TestWtHandler = struct {
    pub const protocol: Protocol = .webtransport;
    session_ready_count: u32 = 0,
    stream_data_count: u32 = 0,
    connect_request_count: u32 = 0,

    pub fn onConnectRequest(self: *TestWtHandler, session: *Session, session_id: u64, _: []const u8) void {
        self.connect_request_count += 1;
        session.acceptSession(session_id) catch {};
    }
    pub fn onSessionReady(self: *TestWtHandler, _: *Session, _: u64) void {
        self.session_ready_count += 1;
    }
    pub fn onStreamData(self: *TestWtHandler, session: *Session, stream_id: u64, data: []const u8) void {
        self.stream_data_count += 1;
        // Echo back
        session.sendStreamData(stream_id, data) catch {};
        session.closeStream(stream_id);
    }
    pub fn onDatagram(_: *TestWtHandler, _: *Session, _: u64, _: []const u8) void {}
    pub fn onSessionClosed(_: *TestWtHandler, _: *Session, _: u64, _: u32, _: []const u8) void {}
};

const TestH3Handler = struct {
    pub const protocol: Protocol = .h3;
    request_count: u32 = 0,

    pub fn onRequest(self: *TestH3Handler, session: *Session, stream_id: u64, _: []const qpack.Header) void {
        self.request_count += 1;
        const resp = [_]qpack.Header{.{ .name = ":status", .value = "200" }};
        session.sendResponse(stream_id, &resp, "OK") catch {};
    }
};

// Compile-time handler validation: unrecognized callback should fail
// (can't test compile errors in Zig tests, but we verify valid handlers compile)
test "Server: handler validation compiles for valid handlers" {
    // These should compile without error
    _ = Server(TestWtHandler);
    _ = Server(TestH3Handler);
}

test "Client: handler validation compiles for valid handlers" {
    // WebTransport client handler
    const TestWtClientHandler = struct {
        pub const protocol: Protocol = .webtransport;
        pub fn onSessionReady(_: *@This(), _: *ClientSession, _: u64) void {}
        pub fn onStreamData(_: *@This(), _: *ClientSession, _: u64, _: []const u8) void {}
        pub fn onDatagram(_: *@This(), _: *ClientSession, _: u64, _: []const u8) void {}
    };
    _ = Client(TestWtClientHandler);

    // H3 client handler
    const TestH3ClientHandler = struct {
        pub const protocol: Protocol = .h3;
        pub fn onConnected(_: *@This(), _: *ClientSession) void {}
        pub fn onHeaders(_: *@This(), _: *ClientSession, _: u64, _: []const qpack.Header) void {}
        pub fn onData(_: *@This(), _: *ClientSession, _: u64, _: usize) void {}
        pub fn onFinished(_: *@This(), _: *ClientSession, _: u64) void {}
        pub fn onSettings(_: *@This(), _: *ClientSession, _: h3.H3Connection.Settings) void {}
        pub fn onGoaway(_: *@This(), _: *ClientSession, _: u64) void {}
    };
    _ = Client(TestH3ClientHandler);

    // Raw QUIC client handler
    const TestQuicClientHandler = struct {
        pub const protocol: Protocol = .quic;
        pub fn onConnected(_: *@This(), _: *ClientSession) void {}
        pub fn onStreamData(_: *@This(), _: *ClientSession, _: u64, _: []const u8) void {}
        pub fn onStreamFinished(_: *@This(), _: *ClientSession, _: u64) void {}
    };
    _ = Client(TestQuicClientHandler);
}

test "Server: init and deinit with in-memory TLS config" {
    const tls_config = makeTestTlsConfig();
    var handler = TestH3Handler{};
    var server = try Server(TestH3Handler).init(testing.allocator, &handler, .{
        .port = 0, // ephemeral port
        .tls_config = tls_config,
    });
    defer server.deinit();

    // Server should be in initial state
    try testing.expect(!server.started);
    try testing.expect(!server.stopping);
}

test "Client: init and deinit with in-memory TLS config" {
    var handler = struct {
        pub const protocol: Protocol = .webtransport;
        pub fn onSessionReady(_: *@This(), _: *ClientSession, _: u64) void {}
    }{};

    var client = try Client(@TypeOf(handler)).init(testing.allocator, &handler, .{
        .port = 19876,
        .skip_cert_verify = true,
    });
    defer client.deinit();

    try testing.expect(!client.started);
    try testing.expect(!client.stopping);
    try testing.expect(!client.protocol_initialized);
    try testing.expect(client.session_id == null);
}

test "Server: start, tick, stop lifecycle" {
    const tls_config = makeTestTlsConfig();
    var handler = TestH3Handler{};
    var server = try Server(TestH3Handler).init(testing.allocator, &handler, .{
        .port = 0,
        .tls_config = tls_config,
    });
    defer server.deinit();

    // tick() should auto-start
    try server.tick();
    try testing.expect(server.started);

    // stop() should set stopping flag
    server.stop();
    try testing.expect(server.stopping);

    // tick after stop with no connections should be fine
    try server.tick();
}

test "Client H3: init and deinit" {
    var handler = struct {
        pub const protocol: Protocol = .h3;
        pub fn onHeaders(_: *@This(), _: *ClientSession, _: u64, _: []const qpack.Header) void {}
    }{};

    var client = try Client(@TypeOf(handler)).init(testing.allocator, &handler, .{
        .port = 19877,
        .skip_cert_verify = true,
    });
    defer client.deinit();

    try testing.expect(!client.started);
    try testing.expect(!client.protocol_initialized);
    try testing.expect(client.h3_conn == null);
}

test "Client QUIC: init and deinit" {
    var handler = struct {
        pub const protocol: Protocol = .quic;
        pub fn onStreamData(_: *@This(), _: *ClientSession, _: u64, _: []const u8) void {}
    }{};

    var client = try Client(@TypeOf(handler)).init(testing.allocator, &handler, .{
        .port = 19878,
        .skip_cert_verify = true,
    });
    defer client.deinit();

    try testing.expect(!client.started);
    try testing.expect(!client.protocol_initialized);
    try testing.expect(client.h3_conn == null);
}

test "Client H3: start, tick, stop lifecycle" {
    var handler = struct {
        pub const protocol: Protocol = .h3;
        pub fn onHeaders(_: *@This(), _: *ClientSession, _: u64, _: []const qpack.Header) void {}
    }{};

    var client = try Client(@TypeOf(handler)).init(testing.allocator, &handler, .{
        .port = 19879,
        .skip_cert_verify = true,
    });
    defer client.deinit();

    try client.tick();
    try testing.expect(client.started);

    client.stop();
    try testing.expect(client.stopping);
}

test "Client QUIC: start, tick, stop lifecycle" {
    var handler = struct {
        pub const protocol: Protocol = .quic;
        pub fn onStreamData(_: *@This(), _: *ClientSession, _: u64, _: []const u8) void {}
    }{};

    var client = try Client(@TypeOf(handler)).init(testing.allocator, &handler, .{
        .port = 19880,
        .skip_cert_verify = true,
    });
    defer client.deinit();

    try client.tick();
    try testing.expect(client.started);

    client.stop();
    try testing.expect(client.stopping);
}
