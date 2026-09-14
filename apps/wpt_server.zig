const std = @import("std");
const quic = @import("quic");
const sys = quic.sys;
const event_loop = quic.event_loop;
const tls13 = quic.tls13;
const wt_session = quic.webtransport;
const wt_protocol = quic.webtransport_protocol;

// Server preference order; the first one the client also offered wins.
const SUPPORTED_PROTOCOLS = [_][]const u8{ "echo", "moqt-18" };
const qpack = quic.qpack;

/// An env var read as a flag: "1" or "0", anything else takes the default.
fn envFlag(name: [*:0]const u8, default: bool) bool {
    const raw = sys.getenv(name) orelse return default;
    if (std.mem.eql(u8, raw, "1")) return true;
    if (std.mem.eql(u8, raw, "0")) return false;
    return default;
}

/// WPT-compatible WebTransport server.
/// Routes requests to handler behaviors based on the CONNECT path,
/// mimicking the Python handlers in web-platform-tests/wpt.
const WptHandler = struct {
    pub const protocol: event_loop.Protocol = .webtransport;

    // Fields
    allocator: std.mem.Allocator,
    session_state: std.AutoHashMap(StateKey, SessionInfo),
    stash: std.StringHashMap([]const u8),
    uni_echo_streams: std.AutoHashMap(StateKey, u64),

    /// Session ids restart at 0 on every connection, so a session id alone is
    /// not a name. Connections linger after a client walks away — the browser
    /// runner and the Zig runner both leave the previous scenario's connection
    /// draining while the next one starts — and two of them sharing the key
    /// meant one connection's poll consumed the other's deferred action.
    const StateKey = struct { conn: usize, id: u64 };

    fn keyFor(session: *event_loop.Session, id: u64) StateKey {
        return .{ .conn = @intFromPtr(session.entry), .id = id };
    }
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
        server_drain,
        stop_sending,
        abort_echo,
        echo_datagram_length,
        server_create_multiple_streams,
        firehose,
        unknown,
    };

    /// The peer's send credit as the firehose last saw it.
    const Credit = struct {
        quic_max_data: u64 = 0,
        quic_max_uni: u64 = 0,
        wt_max_uni: ?u64 = null,
        wt_max_data: ?u64 = null,
    };

    const SessionInfo = struct {
        handler: Handler = .unknown,
        session_id: u64 = 0,
        path: [512]u8 = undefined,
        path_len: u16 = 0,
        /// `?code=` from the path, for handlers that act on stream events
        /// rather than on a deferred tick.
        arg_code: u32 = 0,
        /// server-create-multiple-streams: how many uni streams are still owed
        /// and which index comes next. A peer's initial MAX_STREAMS credit can
        /// be as low as a handful — Firefox 148 grants five, three of which the
        /// H3 control and QPACK streams already spend — so the rest have to
        /// wait for credit rather than being dropped.
        streams_owed: u32 = 0,
        streams_next: u32 = 0,
        /// firehose: WebKit 319818's traffic — one FIN'd uni stream of
        /// `fh_size` bytes per FIREHOSE_INTERVAL_NS — and what the peer's
        /// credit did while its page read them.
        fh_size: u32 = 0,
        fh_start_ns: i64 = 0,
        fh_next_ns: i64 = 0,
        fh_next_log_ns: i64 = 0,
        fh_streams: u64 = 0,
        fh_bytes: u64 = 0,
        fh_held: bool = false,
        /// `unbounded=1`: queue past the peer's credit rather than hold. That
        /// is the bug's memory reproduction; the default is how an
        /// application should behave.
        fh_unbounded: bool = false,
        /// `single=1`: one long stream instead of a FIN'd stream per chunk.
        /// Only this can outgrow the peer's credit without bound; a stream
        /// per chunk runs into MAX_STREAMS once the streams stop finishing.
        fh_single: bool = false,
        fh_stream: ?u64 = null,
        fh_last_err: []const u8 = "",
        fh_seen: Credit = .{},
        close_code: ?u32 = null,
        close_reason_buf: [256]u8 = undefined,
        close_reason_len: u16 = 0,
        token_buf: [128]u8 = undefined,
        token_len: u8 = 0,
        // Deferred action: counts down ticks, executes at 0
        deferred_ticks: u16 = 0,
        deferred_code: u32 = 0,
        deferred_reason_buf: [256]u8 = undefined,
        deferred_reason_len: u8 = 0,

        fn getPath(self: *const SessionInfo) []const u8 {
            return self.path[0..self.path_len];
        }

        fn getToken(self: *const SessionInfo) []const u8 {
            return self.token_buf[0..self.token_len];
        }

        fn getDeferredReason(self: *const SessionInfo) []const u8 {
            return self.deferred_reason_buf[0..self.deferred_reason_len];
        }
    };

    fn init(allocator: std.mem.Allocator) WptHandler {
        return .{
            .allocator = allocator,
            .session_state = std.AutoHashMap(StateKey, SessionInfo).init(allocator),
            .stash = std.StringHashMap([]const u8).init(allocator),
            .uni_echo_streams = std.AutoHashMap(StateKey, u64).init(allocator),
        };
    }

    fn deinit(self: *WptHandler) void {
        self.session_state.deinit();
        self.uni_echo_streams.deinit();
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
        if (std.mem.endsWith(u8, path_only, "/server-drain.py") or
            std.mem.endsWith(u8, path_only, "/server-drain"))
            return .server_drain;
        if (std.mem.endsWith(u8, path_only, "/stop-sending.py") or
            std.mem.endsWith(u8, path_only, "/stop-sending"))
            return .stop_sending;
        if (std.mem.endsWith(u8, path_only, "/abort-echo.py") or
            std.mem.endsWith(u8, path_only, "/abort-echo"))
            return .abort_echo;
        if (std.mem.endsWith(u8, path_only, "/echo-datagram-length.py") or
            std.mem.endsWith(u8, path_only, "/echo-datagram-length"))
            return .echo_datagram_length;
        if (std.mem.endsWith(u8, path_only, "/server-create-multiple-streams.py") or
            std.mem.endsWith(u8, path_only, "/server-create-multiple-streams"))
            return .server_create_multiple_streams;
        if (std.mem.endsWith(u8, path_only, "/firehose"))
            return .firehose;

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

    fn executeDeferredActions(self: *WptHandler, session: *event_loop.Session) void {
        const wtc = session.entry.wt_conn orelse return;

        // Check each active WT session for deferred actions
        for (&wtc.sessions) |*wts| {
            if (!wts.occupied) continue;
            if (wts.state != .active) continue;
            const sid = wts.session_id;
            const info_ptr = self.session_state.getPtr(keyFor(session, sid)) orelse continue;
            if (info_ptr.deferred_ticks == 0) continue;

            info_ptr.deferred_ticks -= 1;
            if (info_ptr.deferred_ticks > 0) continue;

            // Execute deferred action
            std.log.info("[wpt] executing deferred {s}: session={d} code={d}", .{
                @tagName(info_ptr.handler), sid, info_ptr.deferred_code,
            });
            switch (info_ptr.handler) {
                .server_close => {
                    session.closeSessionWithError(sid, info_ptr.deferred_code, info_ptr.getDeferredReason()) catch {};
                },
                .server_connection_close => {
                    _ = session.openBidiStream(sid, null) catch {};
                    session.closeConnection();
                },
                .server_drain => {
                    // Drain, not close: the session stays usable and the peer's
                    // `draining` promise resolves.
                    session.drainSession(sid) catch {};
                },
                .server_create_multiple_streams => {
                    info_ptr.streams_owed = info_ptr.deferred_code;
                    info_ptr.streams_next = 0;
                },
                else => {},
            }
        }
    }

    // -- Event loop handler callbacks --

    pub fn onConnectRequest(
        self: *WptHandler,
        session: *event_loop.Session,
        session_id: u64,
        path: []const u8,
        headers: []const qpack.Header,
    ) void {
        const handler = parseHandler(path);
        std.log.info("[wpt] CONNECT session={d} handler={s} path={s}", .{
            session_id, @tagName(handler), path,
        });
        // Which draft the peer speaks, in its own words. A browser that opens
        // no stream is usually answered here: draft-13 §5.1 puts session flow
        // control in force off the back of WT_MAX_SESSIONS, and §9.2 makes an
        // absent credit a limit of zero.
        if (session.peerSettings()) |ps| {
            std.log.info("[wpt] peer settings: wt_max_sessions_v13={?d} legacy_max_sessions={?d} enable_wt={} initial_max_streams_bidi={?d} uni={?d} initial_max_data={?d} h3_datagram={} qpack_capacity={d} qpack_blocked={d}", .{
                ps.wt_max_sessions_v13,        ps.webtransport_max_sessions,
                ps.enable_webtransport,        ps.wt_initial_max_streams_bidi,
                ps.wt_initial_max_streams_uni, ps.wt_initial_max_data,
                ps.h3_datagram,                ps.qpack_max_table_capacity,
                ps.qpack_blocked_streams,
            });
        } else {
            std.log.info("[wpt] peer settings: none received yet", .{});
        }

        // Store session state
        var info = SessionInfo{
            .handler = handler,
            .session_id = session_id,
        };
        const copy_len = @min(path.len, info.path.len);
        @memcpy(info.path[0..copy_len], path[0..copy_len]);
        info.path_len = @intCast(copy_len);

        if (getQueryParam(path, "code")) |code| {
            info.arg_code = std.fmt.parseInt(u32, code, 10) catch 0;
        }

        // Extract token if present
        if (getQueryParam(path, "token")) |token| {
            const tlen = @min(token.len, info.token_buf.len);
            @memcpy(info.token_buf[0..tlen], token[0..tlen]);
            info.token_len = @intCast(tlen);
        }

        self.session_state.put(keyFor(session, session_id), info) catch {};

        // draft-13 §3.3: name one of the client's offered protocols on the
        // response, so a scenario can check the offer round-tripped.
        var scratch: [256]u8 = undefined;
        var value_buf: [64]u8 = undefined;
        const chosen: ?[]const u8 = if (wt_protocol.findHeader(headers, wt_protocol.HEADER_AVAILABLE)) |offer|
            wt_protocol.selectFromOffer(offer, &SUPPORTED_PROTOCOLS, &scratch)
        else
            null;

        if (chosen) |name| {
            std.log.info("[wpt] protocol negotiated: {s}", .{name});
            if (wt_protocol.encodeItem(name, &value_buf)) |encoded| {
                const extra = [_]qpack.Header{
                    .{ .name = wt_protocol.HEADER_SELECTED, .value = encoded },
                };
                session.acceptSessionWithHeaders(session_id, &extra) catch |err| {
                    std.log.err("[wpt] accept error: {any}", .{err});
                    return;
                };
            } else |_| {
                session.acceptSession(session_id) catch return;
            }
        } else {
            session.acceptSession(session_id) catch |err| {
                std.log.err("[wpt] accept error: {any}", .{err});
                return;
            };
        }

        // Defer server-initiated actions so the 200 response is flushed first.
        // Store deferred info in session_state (per-session, not shared).
        switch (handler) {
            .server_close => {
                const code_str = getQueryParam(path, "code") orelse "0";
                const code = std.fmt.parseInt(u32, code_str, 10) catch 0;
                const reason = getQueryParam(path, "reason") orelse "";
                if (self.session_state.getPtr(keyFor(session, session_id))) |si| {
                    si.deferred_ticks = 1; // execute on next processConnections call
                    si.deferred_code = code;
                    const rlen = @min(reason.len, si.deferred_reason_buf.len);
                    @memcpy(si.deferred_reason_buf[0..rlen], reason[0..rlen]);
                    si.deferred_reason_len = @intCast(rlen);
                }
                // Trigger a QUIC keepalive to ensure processConnections runs again soon
                session.sendKeepAlive();
            },
            .server_connection_close, .server_drain => {
                if (self.session_state.getPtr(keyFor(session, session_id))) |si| {
                    si.deferred_ticks = 1;
                }
                session.sendKeepAlive();
            },
            .server_create_multiple_streams => {
                const count_str = getQueryParam(path, "count") orelse "5";
                if (self.session_state.getPtr(keyFor(session, session_id))) |si| {
                    si.deferred_ticks = 1;
                    si.deferred_code = std.fmt.parseInt(u32, count_str, 10) catch 5;
                }
                session.sendKeepAlive();
            },
            .firehose => {
                const size_str = getQueryParam(path, "size") orelse "16384";
                const size = std.fmt.parseInt(u32, size_str, 10) catch 16384;
                if (self.session_state.getPtr(keyFor(session, session_id))) |si| {
                    const now = sys.nanoTimestamp();
                    si.fh_size = std.math.clamp(size, 1, @as(u32, firehose_chunk.len));
                    si.fh_start_ns = now;
                    si.fh_next_ns = now;
                    si.fh_unbounded = std.mem.eql(u8, getQueryParam(path, "unbounded") orelse "0", "1");
                    si.fh_single = std.mem.eql(u8, getQueryParam(path, "single") orelse "0", "1");
                }
                if (session.entry.conn.peer_params) |pp| {
                    std.log.info("[firehose] peer transport params: initial_max_data={d} initial_max_stream_data_uni={d} initial_max_streams_uni={d}", .{
                        pp.initial_max_data, pp.initial_max_stream_data_uni, pp.initial_max_streams_uni,
                    });
                }
                session.sendKeepAlive();
            },
            .query => {
                // Retrieve stashed data by token and send on a uni stream
                const token = getQueryParam(path, "token") orelse "";
                if (self.stash.get(token)) |data| {
                    if (session.openUniStream(session_id, null)) |stream_id| {
                        session.sendStreamData(stream_id, data) catch {};
                        session.closeStream(stream_id);
                    } else |_| {}
                } else {
                    if (session.openUniStream(session_id, null)) |stream_id| {
                        session.sendStreamData(stream_id, "{}") catch {};
                        session.closeStream(stream_id);
                    } else |_| {}
                }
            },
            else => {},
        }
    }

    /// The firehose keeps its own cadence, and a stalled one still has to log.
    pub const poll_interval_ms = 8;

    /// A held firehose asked to hear when its next stream fits.
    pub fn onWritable(self: *WptHandler, session: *event_loop.Session, session_id: u64, stream_id: ?u64) void {
        _ = stream_id;
        const info = self.session_state.getPtr(keyFor(session, session_id)) orelse return;
        if (info.handler != .firehose) return;
        const t = @as(f64, @floatFromInt(sys.nanoTimestamp() - info.fh_start_ns)) / 1e9;
        std.log.info("[firehose] t={d:.3}s writable again after a hold", .{t});
        self.pumpFirehoses(session);
    }

    pub fn onPollComplete(self: *WptHandler, session: *event_loop.Session) void {
        self.executeDeferredActions(session);
        self.openOwedStreams(session);
        self.pumpFirehoses(session);
    }

    const FIREHOSE_INTERVAL_NS: i64 = 8 * std.time.ns_per_ms; // server.py's ~2 MiB/s at 16 KiB
    const firehose_chunk = [_]u8{'x'} ** 65536;

    fn pumpFirehoses(self: *WptHandler, session: *event_loop.Session) void {
        const wtc = session.entry.wt_conn orelse return;
        const conn = session.entry.conn;
        const now = sys.nanoTimestamp();
        for (&wtc.sessions) |*wts| {
            if (!wts.occupied or wts.state != .active) continue;
            const info = self.session_state.getPtr(keyFor(session, wts.session_id)) orelse continue;
            if (info.handler != .firehose) continue;

            // After a hold, resume at the cadence rather than bursting to catch up.
            if (now - info.fh_next_ns > 100 * std.time.ns_per_ms) info.fh_next_ns = now;
            while (info.fh_next_ns <= now) {
                const cap = if (info.fh_stream) |sid|
                    session.streamSendCapacity(sid) orelse 0
                else
                    session.sendCapacity(wts.session_id);
                info.fh_held = !info.fh_unbounded and cap < info.fh_size;
                if (info.fh_held) {
                    session.notifyWritable(wts.session_id, info.fh_stream, info.fh_size) catch {};
                    break;
                }
                const sid = info.fh_stream orelse (session.openUniStream(wts.session_id, null) catch |err| {
                    info.fh_last_err = @errorName(err);
                    break;
                });
                if (session.sendStreamData(sid, firehose_chunk[0..info.fh_size])) {
                    info.fh_bytes += info.fh_size;
                } else |err| {
                    info.fh_last_err = @errorName(err);
                }
                if (info.fh_stream == null) info.fh_streams += 1;
                if (info.fh_single) {
                    info.fh_stream = sid;
                } else {
                    session.closeStream(sid);
                }
                info.fh_next_ns += FIREHOSE_INTERVAL_NS;
            }

            const t = @as(f64, @floatFromInt(now - info.fh_start_ns)) / 1e9;
            const credit: Credit = .{
                .quic_max_data = conn.conn_flow_ctrl.base.send_window,
                .quic_max_uni = conn.streams.max_uni_streams,
                .wt_max_uni = wts.fc.uni.max_send,
                .wt_max_data = if (wts.fc.data_limited) wts.fc.data.send_window else null,
            };
            if (!std.meta.eql(credit, info.fh_seen)) {
                std.log.info("[firehose] t={d:.3}s credit: MAX_DATA={d} MAX_STREAMS_UNI={d} | WT_MAX_DATA={?d} WT_MAX_STREAMS_UNI={?d}", .{
                    t, credit.quic_max_data, credit.quic_max_uni, credit.wt_max_data, credit.wt_max_uni,
                });
                info.fh_seen = credit;
            }
            if (now >= info.fh_next_log_ns) {
                info.fh_next_log_ns = now + std.time.ns_per_s;
                std.log.info("[firehose] t={d:.1}s streams={d} written={d:.2}MiB conn_sent={d} unsent={d} of MAX_DATA={d} uni_opened={d} of MAX_STREAMS_UNI={d} held={} last_err={s}", .{
                    t,
                    info.fh_streams,
                    @as(f64, @floatFromInt(info.fh_bytes)) / (1024 * 1024),
                    conn.conn_flow_ctrl.base.bytes_sent,
                    conn.streams.committedSendBytes() -| conn.conn_flow_ctrl.base.bytes_sent,
                    credit.quic_max_data,
                    conn.streams.next_uni_stream_id / 4,
                    credit.quic_max_uni,
                    info.fh_held,
                    info.fh_last_err,
                });
            }
        }
    }

    /// Open as many of the owed uni streams as the peer's current credit
    /// allows, and come back for the rest when MAX_STREAMS raises it.
    fn openOwedStreams(self: *WptHandler, session: *event_loop.Session) void {
        const wtc = session.entry.wt_conn orelse return;
        for (&wtc.sessions) |*wts| {
            if (!wts.occupied or wts.state != .active) continue;
            const info = self.session_state.getPtr(keyFor(session, wts.session_id)) orelse continue;
            while (info.streams_owed > 0) {
                const stream_id = session.openUniStream(wts.session_id, null) catch {
                    session.sendKeepAlive();
                    break; // out of credit; try again next poll
                };
                var buf: [32]u8 = undefined;
                // Each stream carries its own index so the client can prove
                // they arrived whole and distinct.
                const body = std.fmt.bufPrint(&buf, "stream-{d}", .{info.streams_next}) catch break;
                session.sendStreamData(stream_id, body) catch {};
                session.closeStream(stream_id);
                info.streams_next += 1;
                info.streams_owed -= 1;
            }
        }
    }

    pub fn onSessionReady(_: *WptHandler, _: *event_loop.Session, sid: u64) void {
        std.log.info("[wpt] session {d} ready", .{sid});
    }

    pub fn onBidiStream(self: *WptHandler, session: *event_loop.Session, session_id: u64, stream_id: u64) void {
        const info = self.session_state.get(keyFor(session, session_id)) orelse return;
        std.log.info("[wpt] bidi stream: handler={s} session={d} stream={d}", .{
            @tagName(info.handler), session_id, stream_id,
        });
    }

    pub fn onUniStream(self: *WptHandler, session: *event_loop.Session, session_id: u64, stream_id: u64) void {
        const info = self.session_state.get(keyFor(session, session_id)) orelse return;
        std.log.info("[wpt] uni stream: handler={s} session={d} stream={d}", .{
            @tagName(info.handler), session_id, stream_id,
        });
    }

    pub fn onStreamData(self: *WptHandler, session: *event_loop.Session, stream_id: u64, data: []const u8, fin: bool) void {
        // Find which session this stream belongs to
        const session_id = self.findSessionForStream(session) orelse return;
        const info = self.session_state.get(keyFor(session, session_id)) orelse return;

        if (data.len == 0 and !fin) return;

        std.log.info("[wpt] stream data: handler={s} stream={d} len={d}", .{
            @tagName(info.handler), stream_id, data.len,
        });

        switch (info.handler) {
            .echo, .echo_raw => {
                if (isUniStream(stream_id)) {
                    // Unidirectional: echo on a single outgoing uni stream per incoming stream.
                    const out_id: ?u64 = self.uni_echo_streams.get(keyFor(session, stream_id)) orelse blk: {
                        const new_id = session.openUniStream(session_id, null) catch |err| {
                            std.log.err("[wpt] openUniStream failed: {any}", .{err});
                            break :blk null;
                        };
                        self.uni_echo_streams.put(keyFor(session, stream_id), new_id) catch {};
                        break :blk new_id;
                    };
                    if (out_id) |oid| {
                        session.sendStreamData(oid, data) catch {};
                        if (fin) {
                            session.closeStream(oid);
                            _ = self.uni_echo_streams.remove(keyFor(session, stream_id));
                        }
                    }
                } else {
                    // Bidirectional: echo back on same stream
                    session.sendStreamData(stream_id, data) catch {};
                    if (fin) {
                        session.closeStream(stream_id);
                    }
                }
            },
            .server_read_then_close => {
                // Close session on first data
                session.closeSession(session_id);
            },
            .stop_sending => {
                // Refuse the rest of what the client is sending. Its writable
                // side should reject carrying this code.
                session.stopSending(stream_id, info.arg_code);
            },
            .abort_stream_from_server => {
                // Reset the stream the client opened, rather than a fresh one
                // of our own: the client already holds it, so the reset lands
                // on a live readable instead of racing its delivery.
                session.resetStream(stream_id, info.arg_code);
            },
            .abort_echo => {
                // Nothing to do until the client resets — see onStreamReset.
            },
            .client_close => {
                // Stash stream data for later query
            },
            else => {},
        }
    }

    pub fn onDatagram(self: *WptHandler, session: *event_loop.Session, session_id: u64, data: []const u8) void {
        const info = self.session_state.get(keyFor(session, session_id)) orelse return;

        std.log.info("[wpt] datagram: handler={s} session={d} len={d}", .{
            @tagName(info.handler), session_id, data.len,
        });

        switch (info.handler) {
            .echo, .echo_raw => {
                // Echo datagram back as-is
                session.sendDatagram(session_id, data) catch {};
            },
            .echo_datagram_length => {
                // Reply with the length we saw, which catches truncation that
                // an identical echo would hide.
                var buf: [24]u8 = undefined;
                const body = std.fmt.bufPrint(&buf, "{d}", .{data.len}) catch return;
                session.sendDatagram(session_id, body) catch {};
            },
            else => {},
        }
    }

    /// The client reset a stream. For abort-echo, report the code it used back
    /// on a fresh uni stream so the client can prove it survived the wire.
    pub fn onStreamReset(self: *WptHandler, session: *event_loop.Session, session_id: u64, stream_id: u64, error_code: u32) void {
        const info = self.session_state.get(keyFor(session, session_id)) orelse return;
        std.log.info("[wpt] stream {d} reset by client, code {d}", .{ stream_id, error_code });
        if (info.handler != .abort_echo) return;

        const out = session.openUniStream(session_id, null) catch return;
        var buf: [24]u8 = undefined;
        const body = std.fmt.bufPrint(&buf, "{d}", .{error_code}) catch return;
        session.sendStreamData(out, body) catch {};
        session.closeStream(out);
    }

    pub fn onSessionClosed(self: *WptHandler, session: *event_loop.Session, session_id: u64, error_code: u32, reason: []const u8) void {
        const info = self.session_state.get(keyFor(session, session_id)) orelse return;
        // Log CONNECT stream state for debugging
        var recv_finished: bool = false;
        var send_fin_sent: bool = false;
        if (session.entry.wt_conn) |wtc| {
            if (wtc.quic.streams.getStream(session_id)) |stream| {
                recv_finished = stream.recv.finished;
                send_fin_sent = stream.send.fin_sent;
            }
        }
        std.log.info("[wpt] session {d} closed (handler={s}, code={d}, reason={s}, recv_fin={}, send_fin={})", .{
            session_id, @tagName(info.handler), error_code, reason, recv_finished, send_fin_sent,
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

        _ = self.session_state.remove(keyFor(session, session_id));
    }

    pub fn onSessionDraining(self: *WptHandler, _: *event_loop.Session, session_id: u64) void {
        _ = self;
        std.log.info("[wpt] session {d} draining", .{session_id});
    }

    // -- Helpers --

    fn findSessionForStream(_: *WptHandler, session: *event_loop.Session) ?u64 {
        if (session.entry.wt_conn) |wtc| {
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

pub fn main(init: std.process.Init.Minimal) !void {
    // A server outlives its streams, so it needs an allocator that reuses what
    // they give back — an arena would grow for as long as the process runs.
    const alloc = std.heap.smp_allocator;

    // Parse args
    var port: u16 = 4433;
    var cert_path: []const u8 = "interop/browser/certs/server.crt";
    var key_path: []const u8 = "interop/browser/certs/server.key";

    var args = sys.argsIterator(init.args);
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
    const server_cert_pem = try sys.readFileAlloc(alloc, cert_path, 8192);
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
    std.debug.print("  /webtransport/handlers/server-drain.py\n", .{});
    std.debug.print("  /webtransport/handlers/stop-sending.py?code=N\n", .{});
    std.debug.print("  /webtransport/handlers/abort-echo.py\n", .{});
    std.debug.print("  /webtransport/handlers/echo-datagram-length.py\n", .{});
    std.debug.print("  /webtransport/handlers/server-create-multiple-streams.py?count=N\n", .{});
    std.debug.print("\n", .{});

    var handler = WptHandler.init(alloc);
    defer handler.deinit();

    // Draft knobs, so a run can ask exactly what a browser is being served.
    // WT_LEGACY=0 drops the pre-draft-13 SETTINGS. WT_CREDITS is the draft-13
    // §9.2 per-session stream credit: 0 withholds it, which also withholds
    // every WT_MAX_STREAMS capsule the session would have granted, and a small
    // number is how you watch a peer hit the limit and ask for more.
    // WT_SETTINGS_CREDITS=1 also announces the credits in SETTINGS, which
    // Safari 26.4 answers by refusing the session — see Config.wt_advertise_credits.
    const wt_fc = quic.webtransport_flow_control;
    const legacy = envFlag("WT_LEGACY", true);
    const advertise = envFlag("WT_SETTINGS_CREDITS", false);
    var credits = wt_fc.Credits.default;
    if (sys.getenv("WT_CREDITS")) |raw| {
        if (std.fmt.parseInt(u64, raw, 10)) |n| {
            credits.max_streams_bidi = n;
            credits.max_streams_uni = n;
            if (n == 0) credits.max_data = 0;
        } else |_| {}
    }

    var server = try event_loop.Server(WptHandler).init(alloc, &handler, .{
        .address = "0.0.0.0",
        .port = port,
        .cert_path = cert_path,
        .key_path = key_path,
        .wt_legacy_settings = legacy,
        .wt_credits = credits,
        .wt_advertise_credits = advertise,
    });
    defer server.deinit();

    std.debug.print("Listening on https://0.0.0.0:{d}\n\n", .{port});
    try server.run();
}
