const std = @import("std");
const quic = @import("quic");
const event_loop = quic.event_loop;
const qpack = quic.qpack;
const sys = quic.sys;
const wt_protocol = quic.webtransport_protocol;

// Advertised in server preference order; the first one the client also
// offered wins. "echo" exists so the negotiation has something to agree on
// when the peer is not a MoQ client.
const SUPPORTED_PROTOCOLS = [_][]const u8{ "moqt-18", "moqt-17", "echo" };

pub const std_options: std.Options = .{
    .log_level = .err,
};

/// `/race` — the packet race on netcode.io, which only netcode.io (and a
/// local dev server) may join. Every other path is the plain `"Echo: "`
/// service web-transport.dev uses.
///
/// Datagrams, integers big-endian:
///
///     PING      c→s→c  [0x01, 0, seq:u16]                  echoed verbatim
///     STATE     c→s    [0x02, boosts:u8, dgram_rtt_ms:u16,
///                       stream_rtt_ms:u16, loss_pct:u8, hue:u8]
///     SNAPSHOT  s→c    [0x03, your_slot:u8, count:u8,
///                       count × (slot:u8, STATE[1..8])]
///
/// `boosts` is a wrapping counter rather than a flag, so a lost SNAPSHOT
/// cannot swallow one. Bytes on a race session's bidi streams are echoed
/// verbatim; the client does its own framing.
const race = struct {
    const MSG_PING: u8 = 0x01;
    const MSG_STATE: u8 = 0x02;
    const MSG_SNAPSHOT: u8 = 0x03;
    const STATE_LEN = 7; // STATE without its type byte
    const MAX_RACERS = 64;
    const TICK_NS: i64 = 250 * std.time.ns_per_ms;
    const STALE_NS: i64 = 3 * std.time.ns_per_s;
    const MIN_STATE_GAP_NS: i64 = 150 * std.time.ns_per_ms;
    const MAX_STREAM_BACKLOG = 64 * 1024; // a peer that stops reading gets reset, not buffered for

    const ORIGINS = [_][]const u8{ "https://netcode.io", "https://www.netcode.io" };
    const DEV_ORIGINS = [_][]const u8{ "http://localhost", "http://127.0.0.1" }; // any port

    const Racer = struct {
        /// Dropped in `onSessionClosed` before its connection is freed.
        session: event_loop.Session,
        session_id: u64,
        state: [STATE_LEN]u8 = @splat(0),
        state_at_ns: i64 = 0, // 0 until the first STATE
    };

    fn isPath(path: []const u8) bool {
        const p = "/race";
        if (!std.mem.startsWith(u8, path, p)) return false;
        return path.len == p.len or path[p.len] == '?' or path[p.len] == '/';
    }

    fn originAllowed(origin: ?[]const u8) bool {
        const o = origin orelse return true; // only browsers send one, and anything else can forge it
        for (ORIGINS) |a| if (std.mem.eql(u8, o, a)) return true;
        for (DEV_ORIGINS) |d| {
            if (std.mem.startsWith(u8, o, d) and (o.len == d.len or o[d.len] == ':')) return true;
        }
        return false;
    }
};

const EchoHandler = struct {
    pub const protocol: event_loop.Protocol = .webtransport;
    pub const poll_interval_ms: u64 = 250; // race snapshots tick even when no packet arrives

    racers: [race.MAX_RACERS]?race.Racer = @splat(null),
    last_tick_ns: i64 = 0,

    fn findRacer(self: *EchoHandler, session: *const event_loop.Session, session_id: u64) ?usize {
        for (&self.racers, 0..) |*slot, i| {
            const r = if (slot.*) |*r| r else continue;
            if (r.session.entry == session.entry and r.session_id == session_id) return i;
        }
        return null;
    }

    fn isRaceStream(self: *EchoHandler, session: *const event_loop.Session, stream_id: u64) bool {
        const wtc = session.entry.wt_conn orelse return false;
        const session_id = wtc.wt_bidi_streams.get(stream_id) orelse return false;
        return self.findRacer(session, session_id) != null;
    }

    fn reject(session: *event_loop.Session, session_id: u64, status: []const u8) void {
        std.log.info("WT session {d} rejected: {s}", .{ session_id, status });
        const headers = [_]qpack.Header{.{ .name = ":status", .value = status }};
        session.sendResponse(session_id, &headers, "") catch {};
    }

    pub fn onConnectRequest(
        self: *EchoHandler,
        session: *event_loop.Session,
        session_id: u64,
        path: []const u8,
        headers: []const qpack.Header,
    ) void {
        std.log.info("WT session request (id={d}, path={s})", .{ session_id, path });

        if (race.isPath(path)) {
            if (!race.originAllowed(wt_protocol.findHeader(headers, "origin"))) return reject(session, session_id, "403");
            const slot = for (&self.racers) |*s| {
                if (s.* == null) break s;
            } else return reject(session, session_id, "503");
            slot.* = .{ .session = session.*, .session_id = session_id };
        }

        // draft-ietf-webtrans-http3-13 §3.3: pick one of the client's
        // offered application protocols and name it on the response.
        var scratch: [256]u8 = undefined;
        var value_buf: [64]u8 = undefined;
        const offer = wt_protocol.findHeader(headers, wt_protocol.HEADER_AVAILABLE);
        const chosen: ?[]const u8 = if (offer) |o|
            wt_protocol.selectFromOffer(o, &SUPPORTED_PROTOCOLS, &scratch)
        else
            null;

        if (chosen) |name| {
            std.log.info("WT protocol negotiated: {s}", .{name});
            const encoded = wt_protocol.encodeItem(name, &value_buf) catch {
                session.acceptSession(session_id) catch {};
                return;
            };
            const extra = [_]qpack.Header{
                .{ .name = wt_protocol.HEADER_SELECTED, .value = encoded },
            };
            session.acceptSessionWithHeaders(session_id, &extra) catch |err| {
                std.log.err("WT accept error: {any}", .{err});
            };
            return;
        }

        if (offer != null) std.log.info("WT protocol offer had no overlap; accepting without one", .{});
        session.acceptSession(session_id) catch |err| {
            std.log.err("WT accept error: {any}", .{err});
        };
    }

    pub fn onSessionReady(_: *EchoHandler, _: *event_loop.Session, sid: u64) void {
        std.log.info("WT session {d} ready", .{sid});
    }

    pub fn onStreamData(self: *EchoHandler, session: *event_loop.Session, stream_id: u64, data: []const u8, fin: bool) void {
        if (self.isRaceStream(session, stream_id)) {
            if (session.getSendStreamStats(stream_id)) |st| {
                if (st.bytes_written - st.bytes_acknowledged > race.MAX_STREAM_BACKLOG) return session.resetStream(stream_id, 0);
            }
            if (data.len > 0) session.sendStreamData(stream_id, data) catch return;
            if (fin) session.closeStream(stream_id);
            return;
        }
        if (data.len > 0) {
            var echo_buf: [1024]u8 = undefined;
            const echo_msg = std.fmt.bufPrint(&echo_buf, "Echo: {s}", .{data}) catch return;
            session.sendStreamData(stream_id, echo_msg) catch return;
        }
        if (fin) {
            session.closeStream(stream_id);
        }
    }

    pub fn onDatagram(self: *EchoHandler, session: *event_loop.Session, session_id: u64, data: []const u8) void {
        if (self.findRacer(session, session_id)) |i| {
            const r = &self.racers[i].?;
            if (data.len == 4 and data[0] == race.MSG_PING) {
                session.sendDatagram(session_id, data) catch {};
            } else if (data.len == 1 + race.STATE_LEN and data[0] == race.MSG_STATE) {
                const now = sys.nanoTimestamp();
                if (now - r.state_at_ns < race.MIN_STATE_GAP_NS) return;
                @memcpy(&r.state, data[1..]);
                r.state_at_ns = now;
            }
            return;
        }

        std.log.info("WT datagram session {d}: {s}", .{ session_id, data });
        var echo_buf: [1024]u8 = undefined;
        const echo_msg = std.fmt.bufPrint(&echo_buf, "Echo: {s}", .{data}) catch return;
        session.sendDatagram(session_id, echo_msg) catch |err| {
            std.log.err("sendDatagram error: {any}", .{err});
        };
    }

    pub fn onSessionClosed(self: *EchoHandler, session: *event_loop.Session, session_id: u64, error_code: u32, reason: []const u8) void {
        std.log.info("WT session {d} closed (code={d}, reason={s})", .{ session_id, error_code, reason });
        // A dead connection reports only session 0, and its entry is freed
        // right after, so every racer on it goes now.
        const dead = session.entry.conn.isClosed();
        for (&self.racers) |*slot| {
            const r = if (slot.*) |*r| r else continue;
            if (r.session.entry == session.entry and (dead or r.session_id == session_id)) slot.* = null;
        }
    }

    /// Runs once per connection per loop pass; the timestamp gate turns that
    /// into one snapshot for everyone per tick.
    pub fn onPollComplete(self: *EchoHandler, _: *event_loop.Session) void {
        const now = sys.nanoTimestamp();
        if (now - self.last_tick_ns < race.TICK_NS) return;
        self.last_tick_ns = now;

        var buf: [3 + race.MAX_RACERS * (1 + race.STATE_LEN)]u8 = undefined;
        buf[0] = race.MSG_SNAPSHOT;
        var len: usize = 3;
        var count: u8 = 0;
        for (self.racers, 0..) |slot, i| {
            const r = slot orelse continue;
            if (r.state_at_ns == 0 or now - r.state_at_ns > race.STALE_NS) continue;
            buf[len] = @intCast(i);
            @memcpy(buf[len + 1 ..][0..race.STATE_LEN], &r.state);
            len += 1 + race.STATE_LEN;
            count += 1;
        }
        if (count == 0) return;
        buf[2] = count;

        for (&self.racers, 0..) |*slot, i| {
            const r = if (slot.*) |*r| r else continue;
            if (r.session.isDatagramSendQueueFull()) continue;
            buf[1] = @intCast(i); // sendDatagram copies, so one buffer serves everyone
            r.session.sendDatagram(r.session_id, buf[0..len]) catch {};
        }
    }
};

pub fn main(init: std.process.Init.Minimal) !void {
    // A server outlives its streams, so it needs an allocator that reuses what
    // they give back — an arena would grow for as long as the process runs.
    const alloc = std.heap.smp_allocator;

    var args_iter = std.process.Args.Iterator.init(init.args);
    _ = args_iter.next(); // skip program name

    var cert_path: []const u8 = "/etc/letsencrypt/live/echo.web-transport.dev/fullchain.pem";
    var key_path: []const u8 = "/etc/letsencrypt/live/echo.web-transport.dev/privkey.pem";
    var port: u16 = 4433;

    while (args_iter.next()) |arg| {
        if (std.mem.eql(u8, arg, "--cert")) {
            if (args_iter.next()) |v| cert_path = v;
        } else if (std.mem.eql(u8, arg, "--key")) {
            if (args_iter.next()) |v| key_path = v;
        } else if (std.mem.eql(u8, arg, "--port")) {
            if (args_iter.next()) |v| port = std.fmt.parseInt(u16, v, 10) catch 4433;
        }
    }

    std.log.info("WebTransport echo server starting on 0.0.0.0:{d}", .{port});
    std.log.info("cert: {s}", .{cert_path});
    std.log.info("key:  {s}", .{key_path});

    var handler = EchoHandler{};
    var server = try event_loop.Server(EchoHandler).init(alloc, &handler, .{
        .address = "0.0.0.0",
        .port = port,
        .cert_path = cert_path,
        .key_path = key_path,
    });
    defer server.deinit();

    try server.run();
}
