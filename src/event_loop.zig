const std = @import("std");
const posix = std.posix;
const xev = @import("xev");

const connection = @import("quic/connection.zig");
const connection_manager = @import("quic/connection_manager.zig");
const ConnEntry = connection_manager.ConnEntry;
const tls13 = @import("quic/tls13.zig");
const ecn_socket = @import("quic/ecn_socket.zig");
const h3 = @import("h3/connection.zig");
const qpack = @import("h3/qpack.zig");
const wt = @import("webtransport/session.zig");

pub const Protocol = enum { quic, h3, webtransport };

pub const Config = struct {
    address: []const u8 = "127.0.0.1",
    port: u16 = 4433,
    cert_path: []const u8 = "interop/certs/server.crt",
    key_path: []const u8 = "interop/certs/server.key",
    max_datagram_frame_size: u64 = 65536,
    webtransport_max_sessions: u64 = 4,
    require_retry: bool = false,
};

/// Session wraps a ConnEntry and provides convenience methods for sending data.
pub const Session = struct {
    entry: *ConnEntry,

    pub fn sendResponse(self: *Session, stream_id: u64, headers: []const qpack.Header, body: []const u8) !void {
        var h3c = &self.entry.h3_conn.?;
        try h3c.sendResponse(stream_id, headers, body);
    }

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
};

pub fn Server(comptime Handler: type) type {
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

        // I/O (our own, for ECN support)
        sockfd: posix.socket_t,
        local_addr: posix.sockaddr.storage,
        batch: ecn_socket.SendBatch,
        recv_buf: [8192]u8,
        out_buf: [1500]u8,

        pub fn init(alloc: std.mem.Allocator, handler: *Handler, config: Config) !Self {
            // Read cert files
            const server_cert_pem = try std.fs.cwd().readFileAlloc(alloc, config.cert_path, 8192);
            const server_key_pem = try std.fs.cwd().readFileAlloc(alloc, config.key_path, 8192);

            // Parse PEM -> DER
            var cert_der_buf: [4096]u8 = undefined;
            const cert_der = try tls13.parsePemCert(server_cert_pem, &cert_der_buf);

            var key_der_buf: [4096]u8 = undefined;
            const key_der = try tls13.parsePemPrivateKey(server_key_pem, &key_der_buf);
            const ec_private_key = try tls13.extractEcPrivateKey(key_der);

            // Build TLS config
            const cert_chain = try alloc.alloc([]const u8, 1);
            cert_chain[0] = cert_der;

            const alpn = try alloc.alloc([]const u8, 1);
            alpn[0] = "h3";

            var ticket_key: [16]u8 = undefined;
            std.crypto.random.bytes(&ticket_key);

            var retry_token_key: [16]u8 = undefined;
            std.crypto.random.bytes(&retry_token_key);

            var static_reset_key: [16]u8 = undefined;
            std.crypto.random.bytes(&static_reset_key);

            const tls_config: tls13.TlsConfig = .{
                .cert_chain_der = cert_chain,
                .private_key_bytes = ec_private_key,
                .alpn = alpn,
                .ticket_key = ticket_key,
            };

            // Connection config
            const conn_config: connection.ConnectionConfig = blk: {
                var cc: connection.ConnectionConfig = .{ .token_key = retry_token_key };
                if (Handler.protocol == .webtransport or Handler.protocol == .quic) {
                    cc.max_datagram_frame_size = config.max_datagram_frame_size;
                }
                break :blk cc;
            };

            // Create UDP socket
            const local_addr = try std.net.Address.parseIp4(config.address, config.port);
            const sockfd = try posix.socket(posix.AF.INET, posix.SOCK.DGRAM | posix.SOCK.NONBLOCK, 0);
            errdefer posix.close(sockfd);
            try posix.bind(sockfd, &local_addr.any, local_addr.getOsSockLen());
            ecn_socket.enableEcnRecv(sockfd) catch {};

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
                .timer_armed = false,
                .started = false,
                .sockfd = sockfd,
                .local_addr = connection.sockaddrToStorage(&local_addr.any),
                .batch = ecn_socket.SendBatch.init(sockfd),
                .recv_buf = undefined,
                .out_buf = undefined,
            };
        }

        pub fn deinit(self: *Self) void {
            self.timer.deinit();
            self.loop.deinit();
            posix.close(self.sockfd);
            self.conn_mgr.deinit();
        }

        /// Register watchers and start the event loop. Call once before tick().
        pub fn start(self: *Self) void {
            // Register socket readability watch
            self.file.poll(&self.loop, &self.poll_completion, .read, Self, self, onReadable);
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

            // Drain all available packets
            self.recvAllPackets();

            // Process all connections (H3/WT init + event dispatch)
            self.processConnections();

            // Tick + burst send
            self.tickAndSend();

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

            // Tick + burst send
            self.tickAndSend();

            // Process events generated by timeouts
            self.processConnections();

            // Reschedule timer
            self.rescheduleTimer();

            return .disarm; // one-shot; rescheduled via rescheduleTimer
        }

        fn recvAllPackets(self: *Self) void {
            while (true) {
                const recv_result = ecn_socket.recvmsgEcn(self.sockfd, &self.recv_buf) catch |err| {
                    if (err == error.WouldBlock) break;
                    break;
                };

                switch (self.conn_mgr.recvDatagram(
                    self.recv_buf[0..recv_result.bytes_read],
                    recv_result.from_addr,
                    self.local_addr,
                    recv_result.ecn,
                    &self.out_buf,
                )) {
                    .processed => |entry| {
                        const conn = entry.conn;
                        const bytes_written = conn.send(&self.out_buf) catch continue;
                        if (bytes_written > 0) {
                            const send_addr = conn.peerAddress();
                            self.batch.add(
                                self.out_buf[0..bytes_written],
                                @ptrCast(send_addr),
                                connection.sockaddrLen(send_addr),
                                conn.getEcnMark(),
                            );
                        }
                    },
                    .send_response => |data| {
                        self.batch.add(data, @ptrCast(&recv_result.from_addr), recv_result.addr_len, 0);
                    },
                    .dropped => {},
                }
            }

            self.batch.flush();
        }

        fn processConnections(self: *Self) void {
            for (self.conn_mgr.entries.items) |entry| {
                const conn = entry.conn;

                // Initialize H3 once handshake completes
                if (conn.isEstablished() and !entry.h3_initialized) {
                    self.initProtocol(entry);
                }

                // Poll events and dispatch to handler
                switch (Handler.protocol) {
                    .webtransport => self.pollWtEvents(entry),
                    .h3 => self.pollH3Events(entry),
                    .quic => {},
                }
            }
        }

        fn initProtocol(self: *Self, entry: *ConnEntry) void {
            entry.h3_conn = h3.H3Connection.init(self.allocator, entry.conn, true);

            switch (Handler.protocol) {
                .webtransport => {
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
                    entry.h3_conn.?.initConnection() catch return;
                },
                .quic => {},
            }

            entry.h3_initialized = true;
        }

        fn pollWtEvents(self: *Self, entry: *ConnEntry) void {
            if (entry.wt_conn == null) return;
            var wtc = &entry.wt_conn.?;
            var session = Session{ .entry = entry };

            while (true) {
                const event = wtc.poll() catch break;
                if (event == null) break;

                switch (event.?) {
                    .connect_request => |req| {
                        if (@hasDecl(Handler, "onConnectRequest")) {
                            self.handler.onConnectRequest(&session, req.session_id, req.path);
                        }
                    },
                    .session_ready => |sid| {
                        if (@hasDecl(Handler, "onSessionReady")) {
                            self.handler.onSessionReady(&session, sid);
                        }
                    },
                    .stream_data => |sd| {
                        if (@hasDecl(Handler, "onStreamData")) {
                            self.handler.onStreamData(&session, sd.stream_id, sd.data);
                        }
                    },
                    .datagram => |dg| {
                        if (@hasDecl(Handler, "onDatagram")) {
                            self.handler.onDatagram(&session, dg.session_id, dg.data);
                        }
                    },
                    .session_closed => |cls| {
                        if (@hasDecl(Handler, "onSessionClosed")) {
                            self.handler.onSessionClosed(&session, cls.session_id, cls.error_code, cls.reason);
                        }
                    },
                    .bidi_stream, .uni_stream, .session_rejected => {},
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
                            self.handler.onData(&session, d.stream_id, d.data);
                        }
                    },
                    .settings, .finished, .goaway, .connect_request, .shutdown_complete, .request_cancelled => {},
                }
            }
        }

        fn tickAndSend(self: *Self) void {
            var i: usize = 0;
            while (i < self.conn_mgr.entries.items.len) {
                const entry = self.conn_mgr.entries.items[i];

                if (!self.conn_mgr.tickEntry(entry)) continue; // removed, don't increment

                const conn = entry.conn;
                var send_count: usize = 0;
                while (send_count < 100) : (send_count += 1) {
                    const bytes_written = conn.send(&self.out_buf) catch break;
                    if (bytes_written == 0) break;
                    const send_addr = conn.peerAddress();
                    self.batch.add(
                        self.out_buf[0..bytes_written],
                        @ptrCast(send_addr),
                        connection.sockaddrLen(send_addr),
                        conn.getEcnMark(),
                    );
                }

                i += 1;
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
            if (delta_ns <= 0) return 1; // fire immediately
            // Convert ns to ms, round up
            return @intCast(@divFloor(delta_ns, 1_000_000) + 1);
        }
    };
}
