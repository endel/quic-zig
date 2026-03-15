const std = @import("std");
const quic = @import("quic");
const event_loop = quic.event_loop;
const tls13 = quic.tls13;
const wt_session = quic.webtransport;
const qpack = quic.qpack;

/// WPT-compatible WebTransport server.
/// Routes requests to handler behaviors based on the CONNECT path,
/// mimicking the Python handlers in web-platform-tests/wpt.
const WptHandler = struct {
    pub const protocol: event_loop.Protocol = .webtransport;

    // Fields
    allocator: std.mem.Allocator,
    session_state: std.AutoHashMap(u64, SessionInfo),
    stash: std.StringHashMap([]const u8),
    pending_actions: [MAX_PENDING]PendingAction = .{PendingAction{ .session_id = 0 }} ** MAX_PENDING,
    pending_count: u8 = 0,

    // Types
    const MAX_PENDING = 8;

    const PendingAction = struct {
        session_id: u64,
        handler: Handler = .unknown,
        code: u32 = 0,
        reason_buf: [256]u8 = undefined,
        reason_len: u8 = 0,
        ticks_remaining: u16 = 100, // ~20ms at 200µs poll interval

        fn getReason(self: *const PendingAction) []const u8 {
            return self.reason_buf[0..self.reason_len];
        }
    };

    const Handler = enum {
        echo,
        echo_raw, // echo without "Echo: " prefix
        server_close,
        client_close,
        query,
        echo_request_headers,
        custom_response,
        server_connection_close,
        server_read_then_close,
        abort_stream_from_server,
        unknown,
    };

    const SessionInfo = struct {
        handler: Handler = .unknown,
        session_id: u64 = 0,
        path: [512]u8 = undefined,
        path_len: u16 = 0,
        // For echo handler: track uni streams to echo on new uni stream
        // For client-close: accumulate events
        close_code: ?u32 = null,
        close_reason_buf: [256]u8 = undefined,
        close_reason_len: u16 = 0,
        token_buf: [128]u8 = undefined,
        token_len: u8 = 0,

        fn getPath(self: *const SessionInfo) []const u8 {
            return self.path[0..self.path_len];
        }

        fn getToken(self: *const SessionInfo) []const u8 {
            return self.token_buf[0..self.token_len];
        }
    };

    fn init(allocator: std.mem.Allocator) WptHandler {
        return .{
            .allocator = allocator,
            .session_state = std.AutoHashMap(u64, SessionInfo).init(allocator),
            .stash = std.StringHashMap([]const u8).init(allocator),
        };
    }

    fn deinit(self: *WptHandler) void {
        self.session_state.deinit();
        // Free stash values
        var it = self.stash.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.*);
        }
        self.stash.deinit();
    }

    /// Parse handler name from path like "/webtransport/handlers/echo.py"
    fn parseHandler(path: []const u8) Handler {
        // Strip query string
        const path_only = if (std.mem.indexOf(u8, path, "?")) |qi| path[0..qi] else path;

        if (std.mem.endsWith(u8, path_only, "/echo.py") or
            std.mem.endsWith(u8, path_only, "/echo"))
            return .echo;
        if (std.mem.endsWith(u8, path_only, "/echo-raw.py") or
            std.mem.endsWith(u8, path_only, "/echo-raw"))
            return .echo_raw;
        if (std.mem.endsWith(u8, path_only, "/server-close.py") or
            std.mem.endsWith(u8, path_only, "/server-close"))
            return .server_close;
        if (std.mem.endsWith(u8, path_only, "/client-close.py") or
            std.mem.endsWith(u8, path_only, "/client-close"))
            return .client_close;
        if (std.mem.endsWith(u8, path_only, "/query.py") or
            std.mem.endsWith(u8, path_only, "/query"))
            return .query;
        if (std.mem.endsWith(u8, path_only, "/echo-request-headers.py") or
            std.mem.endsWith(u8, path_only, "/echo-request-headers"))
            return .echo_request_headers;
        if (std.mem.endsWith(u8, path_only, "/custom-response.py") or
            std.mem.endsWith(u8, path_only, "/custom-response"))
            return .custom_response;
        if (std.mem.endsWith(u8, path_only, "/server-connection-close.py") or
            std.mem.endsWith(u8, path_only, "/server-connection-close"))
            return .server_connection_close;
        if (std.mem.endsWith(u8, path_only, "/server-read-then-close.py") or
            std.mem.endsWith(u8, path_only, "/server-read-then-close"))
            return .server_read_then_close;
        if (std.mem.endsWith(u8, path_only, "/abort-stream-from-server.py") or
            std.mem.endsWith(u8, path_only, "/abort-stream-from-server"))
            return .abort_stream_from_server;

        // Default to echo for unrecognized paths
        return .echo;
    }

    /// Extract a query parameter value from a URL path.
    fn getQueryParam(path: []const u8, key: []const u8) ?[]const u8 {
        const qi = std.mem.indexOf(u8, path, "?") orelse return null;
        var rest = path[qi + 1 ..];

        while (rest.len > 0) {
            // Find end of this param
            const amp = std.mem.indexOf(u8, rest, "&") orelse rest.len;
            const param = rest[0..amp];

            // Find = separator
            if (std.mem.indexOf(u8, param, "=")) |eq| {
                const k = param[0..eq];
                const v = param[eq + 1 ..];
                if (std.mem.eql(u8, k, key)) return v;
            } else {
                if (std.mem.eql(u8, param, key)) return "";
            }

            if (amp >= rest.len) break;
            rest = rest[amp + 1 ..];
        }
        return null;
    }

    fn queueAction(self: *WptHandler, action: PendingAction) void {
        if (self.pending_count < MAX_PENDING) {
            self.pending_actions[self.pending_count] = action;
            self.pending_count += 1;
        }
    }

    fn executePendingActions(self: *WptHandler, session: *event_loop.Session) void {
        const wtc = if (session.entry.wt_conn) |*w| w else return;

        var i: u8 = 0;
        while (i < self.pending_count) {
            var action = &self.pending_actions[i];

            // Only process actions belonging to THIS connection's sessions
            var has_session = false;
            for (&wtc.sessions) |*s| {
                if (s.occupied and s.session_id == action.session_id) {
                    has_session = true;
                    break;
                }
            }
            if (!has_session) {
                i += 1;
                continue; // Skip — this action belongs to a different connection
            }

            if (action.ticks_remaining > 0) {
                action.ticks_remaining -= 1;
                i += 1;
                continue;
            }

            const sid = action.session_id;
            std.log.info("[wpt] executing deferred {s}: session={d} code={d}", .{
                @tagName(action.handler), sid, action.code,
            });
            switch (action.handler) {
                .server_close => {
                    session.closeSessionWithError(sid, action.code, action.getReason()) catch {};
                },
                .server_connection_close => {
                    _ = session.openBidiStream(sid) catch {};
                    session.closeConnection();
                },
                .abort_stream_from_server => {
                    if (session.openUniStream(sid)) |stream_id| {
                        session.sendStreamData(stream_id, "a") catch {};
                        session.resetStream(stream_id, action.code);
                    } else |_| {}
                    if (session.openBidiStream(sid)) |stream_id| {
                        session.resetStream(stream_id, action.code);
                    } else |_| {}
                },
                else => {},
            }

            // Remove by swapping with last
            self.pending_actions[i] = self.pending_actions[self.pending_count - 1];
            self.pending_count -= 1;
        }
    }

    // -- Event loop handler callbacks --

    pub fn onConnectRequest(self: *WptHandler, session: *event_loop.Session, session_id: u64, path: []const u8) void {
        const handler = parseHandler(path);
        std.log.info("[wpt] CONNECT session={d} handler={s} path={s}", .{
            session_id, @tagName(handler), path,
        });

        // Store session state
        var info = SessionInfo{
            .handler = handler,
            .session_id = session_id,
        };
        const copy_len = @min(path.len, info.path.len);
        @memcpy(info.path[0..copy_len], path[0..copy_len]);
        info.path_len = @intCast(copy_len);

        // Extract token if present
        if (getQueryParam(path, "token")) |token| {
            const tlen = @min(token.len, info.token_buf.len);
            @memcpy(info.token_buf[0..tlen], token[0..tlen]);
            info.token_len = @intCast(tlen);
        }

        self.session_state.put(session_id, info) catch {};

        // Accept the session
        session.acceptSession(session_id) catch |err| {
            std.log.err("[wpt] accept error: {any}", .{err});
            return;
        };

        // Defer server-initiated actions so the 200 response is flushed first
        switch (handler) {
            .server_close => {
                const code_str = getQueryParam(path, "code") orelse "0";
                const code = std.fmt.parseInt(u32, code_str, 10) catch 0;
                const reason = getQueryParam(path, "reason") orelse "";
                var action = PendingAction{ .session_id = session_id, .handler = .server_close, .code = code };
                const rlen = @min(reason.len, action.reason_buf.len);
                @memcpy(action.reason_buf[0..rlen], reason[0..rlen]);
                action.reason_len = @intCast(rlen);
                self.queueAction(action);
            },
            .server_connection_close => {
                self.queueAction(.{ .session_id = session_id, .handler = .server_connection_close });
            },
            .abort_stream_from_server => {
                const code_str = getQueryParam(path, "code") orelse "0";
                const code = std.fmt.parseInt(u32, code_str, 10) catch 0;
                self.queueAction(.{ .session_id = session_id, .handler = .abort_stream_from_server, .code = code });
            },
            .query => {
                // Retrieve stashed data by token and send on a uni stream
                const token = getQueryParam(path, "token") orelse "";
                if (self.stash.get(token)) |data| {
                    if (session.openUniStream(session_id)) |stream_id| {
                        session.sendStreamData(stream_id, data) catch {};
                        session.closeStream(stream_id);
                    } else |_| {}
                } else {
                    if (session.openUniStream(session_id)) |stream_id| {
                        session.sendStreamData(stream_id, "{}") catch {};
                        session.closeStream(stream_id);
                    } else |_| {}
                }
            },
            else => {},
        }
    }

    pub fn onPollComplete(self: *WptHandler, session: *event_loop.Session) void {
        self.executePendingActions(session);
    }

    pub fn onSessionReady(_: *WptHandler, _: *event_loop.Session, sid: u64) void {
        std.log.info("[wpt] session {d} ready", .{sid});
    }

    pub fn onBidiStream(self: *WptHandler, _: *event_loop.Session, session_id: u64, stream_id: u64) void {
        const info = self.session_state.get(session_id) orelse return;
        std.log.info("[wpt] bidi stream: handler={s} session={d} stream={d}", .{
            @tagName(info.handler), session_id, stream_id,
        });
    }

    pub fn onUniStream(self: *WptHandler, _: *event_loop.Session, session_id: u64, stream_id: u64) void {
        const info = self.session_state.get(session_id) orelse return;
        std.log.info("[wpt] uni stream: handler={s} session={d} stream={d}", .{
            @tagName(info.handler), session_id, stream_id,
        });
    }

    pub fn onStreamData(self: *WptHandler, session: *event_loop.Session, stream_id: u64, data: []const u8) void {
        // Find which session this stream belongs to
        const session_id = self.findSessionForStream(session) orelse return;
        const info = self.session_state.get(session_id) orelse return;

        std.log.info("[wpt] stream data: handler={s} stream={d} len={d}", .{
            @tagName(info.handler), stream_id, data.len,
        });

        switch (info.handler) {
            .echo => {
                // Echo data back on the same stream (for bidi), or on new uni stream (for uni)
                if (isUniStream(stream_id)) {
                    // Unidirectional: echo on a NEW uni stream
                    if (session.openUniStream(session_id)) |new_stream_id| {
                        session.sendStreamData(new_stream_id, data) catch {};
                        session.closeStream(new_stream_id);
                    } else |_| {}
                } else {
                    // Bidirectional: echo back on same stream
                    session.sendStreamData(stream_id, data) catch {};
                    session.closeStream(stream_id);
                }
            },
            .echo_raw => {
                if (isUniStream(stream_id)) {
                    if (session.openUniStream(session_id)) |new_stream_id| {
                        session.sendStreamData(new_stream_id, data) catch {};
                        session.closeStream(new_stream_id);
                    } else |_| {}
                } else {
                    session.sendStreamData(stream_id, data) catch {};
                    session.closeStream(stream_id);
                }
            },
            .server_read_then_close => {
                // Close session on first data
                session.closeSession(session_id);
            },
            .client_close => {
                // Stash stream data for later query
            },
            else => {},
        }
    }

    pub fn onDatagram(self: *WptHandler, session: *event_loop.Session, session_id: u64, data: []const u8) void {
        const info = self.session_state.get(session_id) orelse return;

        std.log.info("[wpt] datagram: handler={s} session={d} len={d}", .{
            @tagName(info.handler), session_id, data.len,
        });

        switch (info.handler) {
            .echo, .echo_raw => {
                // Echo datagram back as-is
                session.sendDatagram(session_id, data) catch {};
            },
            else => {},
        }
    }

    pub fn onSessionClosed(self: *WptHandler, _: *event_loop.Session, session_id: u64, error_code: u32, reason: []const u8) void {
        const info = self.session_state.get(session_id) orelse return;
        std.log.info("[wpt] session {d} closed (handler={s}, code={d}, reason={s})", .{
            session_id, @tagName(info.handler), error_code, reason,
        });

        // For client-close handler: stash the close info
        if (info.handler == .client_close) {
            const token = info.getToken();
            if (token.len > 0) {
                var buf: [512]u8 = undefined;
                const json = std.fmt.bufPrint(&buf, "{{\"close_code\":{d},\"close_reason\":\"{s}\"}}", .{
                    error_code, reason,
                }) catch return;

                const key = self.allocator.dupe(u8, token) catch return;
                const val = self.allocator.dupe(u8, json) catch {
                    self.allocator.free(key);
                    return;
                };

                // Remove old entry if present
                if (self.stash.fetchRemove(key)) |old| {
                    self.allocator.free(old.key);
                    self.allocator.free(old.value);
                }
                self.stash.put(key, val) catch {
                    self.allocator.free(key);
                    self.allocator.free(val);
                };
            }
        }

        _ = self.session_state.remove(session_id);
    }

    pub fn onSessionDraining(self: *WptHandler, _: *event_loop.Session, session_id: u64) void {
        _ = self;
        std.log.info("[wpt] session {d} draining", .{session_id});
    }

    // -- Helpers --

    fn findSessionForStream(_: *WptHandler, session: *event_loop.Session) ?u64 {
        if (session.entry.wt_conn) |*wtc| {
            // Check bidi streams
            var bidi_it = wtc.wt_bidi_streams.iterator();
            while (bidi_it.next()) |entry| {
                return entry.value_ptr.*;
            }
            // Check uni streams
            var uni_it = wtc.wt_uni_streams.iterator();
            while (uni_it.next()) |entry| {
                return entry.value_ptr.*;
            }
            // Fallback: first active session
            for (&wtc.sessions) |*s| {
                if (s.occupied and s.state == .active) return s.session_id;
            }
        }
        return null;
    }

    /// Check if a stream ID is a unidirectional stream.
    fn isUniStream(stream_id: u64) bool {
        return (stream_id & 0x02) != 0;
    }
};

pub fn main() !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    // Parse args
    var port: u16 = 4433;
    var cert_path: []const u8 = "interop/browser/certs/server.crt";
    var key_path: []const u8 = "interop/browser/certs/server.key";

    var args = std.process.args();
    _ = args.next();
    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--port")) {
            if (args.next()) |v| port = std.fmt.parseInt(u16, v, 10) catch 4433;
        } else if (std.mem.eql(u8, arg, "--cert")) {
            if (args.next()) |v| cert_path = v;
        } else if (std.mem.eql(u8, arg, "--key")) {
            if (args.next()) |v| key_path = v;
        }
    }

    // Print certificate SHA-256 hash for browser pinning
    const server_cert_pem = try std.fs.cwd().readFileAlloc(alloc, cert_path, 8192);
    var cert_der_buf: [4096]u8 = undefined;
    const cert_der = try tls13.parsePemCert(server_cert_pem, &cert_der_buf);

    var cert_hash: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(cert_der, &cert_hash, .{});

    std.debug.print("\n=== WPT WebTransport Test Server ===\n", .{});
    std.debug.print("Port: {d}\n", .{port});
    std.debug.print("Cert: {s}\n", .{cert_path});
    std.debug.print("\nCertificate SHA-256: ", .{});
    for (cert_hash) |byte| {
        std.debug.print("{x:0>2}", .{byte});
    }
    std.debug.print("\n\n", .{});

    // Print hash as JS array for the test runner
    std.debug.print("JS hash: new Uint8Array([", .{});
    for (cert_hash, 0..) |byte, idx| {
        if (idx > 0) std.debug.print(", ", .{});
        std.debug.print("{d}", .{byte});
    }
    std.debug.print("])\n\n", .{});

    std.debug.print("Supported handlers:\n", .{});
    std.debug.print("  /webtransport/handlers/echo.py\n", .{});
    std.debug.print("  /webtransport/handlers/server-close.py?code=N&reason=R\n", .{});
    std.debug.print("  /webtransport/handlers/client-close.py?token=T\n", .{});
    std.debug.print("  /webtransport/handlers/query.py?token=T\n", .{});
    std.debug.print("  /webtransport/handlers/echo-request-headers.py\n", .{});
    std.debug.print("  /webtransport/handlers/abort-stream-from-server.py?code=N\n", .{});
    std.debug.print("  /webtransport/handlers/server-connection-close.py\n", .{});
    std.debug.print("  /webtransport/handlers/server-read-then-close.py\n", .{});
    std.debug.print("\n", .{});

    var handler = WptHandler.init(alloc);
    defer handler.deinit();

    var server = try event_loop.Server(WptHandler).init(alloc, &handler, .{
        .address = "0.0.0.0",
        .port = port,
        .cert_path = cert_path,
        .key_path = key_path,
    });
    defer server.deinit();

    std.debug.print("Listening on https://0.0.0.0:{d}\n\n", .{port});
    try server.run();
}
