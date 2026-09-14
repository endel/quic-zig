//! Zig half of the shared WebTransport conformance suite.
//!
//! Runs the scenarios in interop/conformance/scenarios.json against
//! `wpt-server`, the same server the browsers are pointed at, and reports in
//! the same vocabulary the browser runner uses (`PASS:<id>` / `FAIL:<id>`), so
//! the two sides land in one matrix.
//!
//! Each scenario gets a fresh connection: a session that ends badly must not
//! colour the next one.
//!
//!   ./zig-out/bin/wpt-client                    # every scenario
//!   ./zig-out/bin/wpt-client --scenario uni-echo
//!   ./zig-out/bin/wpt-client --port 4433 --cert interop/browser/certs/server.crt

const std = @import("std");
const quic = @import("quic");
const event_loop = quic.event_loop;
const qpack = quic.qpack;
const tls13 = quic.tls13;
const sys = quic.sys;
const wt_protocol = quic.webtransport_protocol;

pub const std_options: std.Options = .{
    .log_level = .err,
};

const MANIFEST_JSON = @embedFile("conformance_scenarios");

/// One per manifest id. The names are the ids with '-' spelled '_', and
/// `idOf`/`fromId` are the only places that mapping lives.
const Scenario = enum {
    connect_echo,
    client_close_code,
    server_close_code0,
    server_close_code42,
    server_close_code3999,
    server_connection_close,
    bidi_echo_small,
    bidi_echo_3_streams,
    bidi_echo_64kb,
    uni_echo,
    uni_echo_64kb,
    uni_multiple_streams,
    datagram_echo,
    datagram_maxsize,
    datagram_length_echo,
    server_abort_stream,
    client_abort_stream,
    server_stop_sending,
    server_drain,
    wt_protocol_negotiation,

    fn idOf(self: Scenario, buf: []u8) []const u8 {
        const name = @tagName(self);
        const n = @min(name.len, buf.len);
        for (name[0..n], 0..) |c, i| buf[i] = if (c == '_') '-' else c;
        return buf[0..n];
    }

    fn fromId(id: []const u8) ?Scenario {
        var buf: [64]u8 = undefined;
        inline for (@typeInfo(Scenario).@"enum".fields) |f| {
            const candidate = @field(Scenario, f.name).idOf(&buf);
            if (std.mem.eql(u8, candidate, id)) return @field(Scenario, f.name);
        }
        return null;
    }
};

const LARGE = 65536;

const Outcome = union(enum) {
    pass: void,
    fail: void,
};

/// Drives one scenario on one connection.
///
/// The scenarios share a small vocabulary — bytes accumulated per stream,
/// incoming uni payloads in arrival order, the last datagram, the codes a peer
/// abort carried — rather than each keeping its own bookkeeping.
const Runner = struct {
    pub const protocol: event_loop.Protocol = .webtransport;

    alloc: std.mem.Allocator,
    scenario: Scenario,

    session_id: u64 = 0,
    ready: bool = false,
    outcome: ?Outcome = null,
    detail: std.ArrayList(u8),

    /// Bytes seen so far per stream, and which of them have had their FIN.
    bufs: std.AutoHashMap(u64, std.ArrayList(u8)),
    finished: std.AutoHashMap(u64, void),
    /// Streams we opened, in the order we opened them.
    opened: std.ArrayList(u64),
    /// Payloads of incoming unidirectional streams that have finished.
    uni_done: std.ArrayList([]u8),

    last_datagram: ?[]u8 = null,
    reset_code: ?u32 = null,
    stop_code: ?u32 = null,
    draining: bool = false,
    negotiated: std.ArrayList(u8),
    closed_code: ?u32 = null,
    closed_reason: std.ArrayList(u8),
    /// server-stop-sending writes until the peer objects; this caps the effort.
    writes_left: u32 = 400,
    /// datagram-length-echo gets a length back, so it has to remember what it
    /// sent to know whether anything was lost on the way.
    expected_datagram_len: usize = 0,
    /// client-abort-stream resets once, after the header lands.
    reset_sent: bool = false,

    fn init(alloc: std.mem.Allocator, scenario: Scenario) Runner {
        return .{
            .alloc = alloc,
            .scenario = scenario,
            .detail = .empty,
            .bufs = std.AutoHashMap(u64, std.ArrayList(u8)).init(alloc),
            .finished = std.AutoHashMap(u64, void).init(alloc),
            .opened = .empty,
            .uni_done = .empty,
            .negotiated = .empty,
            .closed_reason = .empty,
        };
    }

    fn deinit(self: *Runner) void {
        var it = self.bufs.iterator();
        while (it.next()) |e| e.value_ptr.deinit(self.alloc);
        self.bufs.deinit();
        self.finished.deinit();
        self.opened.deinit(self.alloc);
        for (self.uni_done.items) |p| self.alloc.free(p);
        self.uni_done.deinit(self.alloc);
        if (self.last_datagram) |d| self.alloc.free(d);
        self.detail.deinit(self.alloc);
        self.negotiated.deinit(self.alloc);
        self.closed_reason.deinit(self.alloc);
    }

    // -- outcome helpers --

    fn pass(self: *Runner, comptime fmt: []const u8, args: anytype) void {
        if (self.outcome != null) return;
        self.detail.clearRetainingCapacity();
        self.detail.print(self.alloc, fmt, args) catch {};
        self.outcome = .pass;
    }

    fn fail(self: *Runner, comptime fmt: []const u8, args: anytype) void {
        if (self.outcome != null) return;
        self.detail.clearRetainingCapacity();
        self.detail.print(self.alloc, fmt, args) catch {};
        self.outcome = .fail;
    }

    fn expectEql(self: *Runner, got: []const u8, want: []const u8) void {
        if (std.mem.eql(u8, got, want)) {
            self.pass("ok", .{});
        } else {
            self.fail("got \"{s}\", want \"{s}\"", .{ got, want });
        }
    }

    fn bufFor(self: *Runner, stream_id: u64) ?*std.ArrayList(u8) {
        const gop = self.bufs.getOrPut(stream_id) catch return null;
        if (!gop.found_existing) gop.value_ptr.* = .empty;
        return gop.value_ptr;
    }

    fn bytesOf(self: *Runner, stream_id: u64) []const u8 {
        if (self.bufs.getPtr(stream_id)) |b| return b.items;
        return &.{};
    }

    // -- callbacks --

    pub fn onSessionReady(
        self: *Runner,
        session: *event_loop.ClientSession,
        session_id: u64,
        headers: []const qpack.Header,
    ) void {
        self.session_id = session_id;
        self.ready = true;

        if (wt_protocol.findHeader(headers, wt_protocol.HEADER_SELECTED)) |raw| {
            var scratch: [64]u8 = undefined;
            if (wt_protocol.decodeItem(raw, &scratch)) |name| {
                self.negotiated.appendSlice(self.alloc, name) catch {};
            } else |_| {}
        }

        switch (self.scenario) {
            .connect_echo => session.closeSessionWithError(session_id, 0, "") catch |e| {
                self.fail("close failed: {any}", .{e});
            },
            .client_close_code => session.closeSessionWithError(session_id, 7, "done") catch |e| {
                self.fail("close failed: {any}", .{e});
            },

            .bidi_echo_small => self.openAndSend(session, "hello"),
            .bidi_echo_64kb => self.sendLargeBidi(session),
            .bidi_echo_3_streams => {
                var i: u8 = 0;
                while (i < 3) : (i += 1) {
                    var msg: [8]u8 = undefined;
                    const text = std.fmt.bufPrint(&msg, "msg{d}", .{i}) catch continue;
                    self.openAndSend(session, text);
                }
            },

            .uni_echo => self.openUniAndSend(session, "uni-test"),
            .uni_echo_64kb => self.sendLargeUni(session),

            .datagram_echo => session.sendDatagram(session_id, "dg-test") catch |e| {
                self.fail("sendDatagram failed: {any}", .{e});
            },
            .datagram_maxsize => {
                const sz = session.maxDatagramPayloadSize(session_id) orelse 0;
                if (sz > 0) self.pass("ok ({d})", .{sz}) else self.fail("maxDatagramSize={d}", .{sz});
            },
            .datagram_length_echo => {
                const sz = session.maxDatagramPayloadSize(session_id) orelse 0;
                if (sz == 0) return self.fail("maxDatagramSize=0", .{});
                const payload = self.alloc.alloc(u8, sz) catch return;
                defer self.alloc.free(payload);
                @memset(payload, 0);
                self.expected_datagram_len = sz;
                session.sendDatagram(session_id, payload) catch |e| {
                    self.fail("sendDatagram failed: {any}", .{e});
                };
            },

            // The handler resets whatever stream it hears from, so this reset
            // lands on a stream we already hold rather than racing delivery.
            .server_abort_stream => self.openAndSend(session, "go"),
            .server_stop_sending => self.openAndSend(session, "start"),
            // The reset waits for an ack — see onPollComplete. Sending it now
            // would race the stream header, and a stream the peer never saw
            // cannot carry a reset code back.
            .client_abort_stream => self.openAndSend(session, "x"),

            .wt_protocol_negotiation => {
                if (self.negotiated.items.len == 0) {
                    self.fail("server named no protocol", .{});
                } else {
                    self.expectEql(self.negotiated.items, "echo");
                }
            },

            // Nothing to send: the server acts first.
            .server_close_code0,
            .server_close_code42,
            .server_close_code3999,
            .server_connection_close,
            .uni_multiple_streams,
            .server_drain,
            => {},
        }
    }

    fn openAndSend(self: *Runner, session: *event_loop.ClientSession, data: []const u8) void {
        const id = session.openBidiStream(self.session_id, null) catch |e| {
            return self.fail("openBidiStream: {any}", .{e});
        };
        self.opened.append(self.alloc, id) catch {};
        session.sendStreamData(id, data) catch |e| {
            return self.fail("sendStreamData: {any}", .{e});
        };
        // stop-sending and abort scenarios keep the stream open on purpose:
        // a FIN would end it before the peer has a chance to object.
        switch (self.scenario) {
            .server_stop_sending, .server_abort_stream, .client_abort_stream => {},
            else => session.closeStream(id),
        }
    }

    fn sendLargeBidi(self: *Runner, session: *event_loop.ClientSession) void {
        const id = session.openBidiStream(self.session_id, null) catch |e| {
            return self.fail("openBidiStream: {any}", .{e});
        };
        self.opened.append(self.alloc, id) catch {};
        self.sendPattern(session, id);
    }

    fn openUniAndSend(self: *Runner, session: *event_loop.ClientSession, data: []const u8) void {
        const id = session.openUniStream(self.session_id, null) catch |e| {
            return self.fail("openUniStream: {any}", .{e});
        };
        self.opened.append(self.alloc, id) catch {};
        session.sendStreamData(id, data) catch |e| {
            return self.fail("sendStreamData: {any}", .{e});
        };
        session.closeStream(id);
    }

    fn sendLargeUni(self: *Runner, session: *event_loop.ClientSession) void {
        const id = session.openUniStream(self.session_id, null) catch |e| {
            return self.fail("openUniStream: {any}", .{e});
        };
        self.opened.append(self.alloc, id) catch {};
        self.sendPattern(session, id);
    }

    fn sendPattern(self: *Runner, session: *event_loop.ClientSession, id: u64) void {
        const payload = self.alloc.alloc(u8, LARGE) catch return;
        defer self.alloc.free(payload);
        for (payload, 0..) |*b, i| b.* = @truncate(i);
        session.sendStreamData(id, payload) catch |e| {
            return self.fail("sendStreamData: {any}", .{e});
        };
        session.closeStream(id);
    }

    pub fn onStreamData(
        self: *Runner,
        _: *event_loop.ClientSession,
        stream_id: u64,
        data: []const u8,
        fin: bool,
    ) void {
        if (data.len > 0) {
            if (self.bufFor(stream_id)) |b| b.appendSlice(self.alloc, data) catch {};
        }
        if (fin) {
            self.finished.put(stream_id, {}) catch {};
            if (isUni(stream_id)) {
                const copy = self.alloc.dupe(u8, self.bytesOf(stream_id)) catch return;
                self.uni_done.append(self.alloc, copy) catch self.alloc.free(copy);
            }
        }
        self.evaluate();
    }

    pub fn onDatagram(self: *Runner, _: *event_loop.ClientSession, _: u64, data: []const u8) void {
        if (self.last_datagram) |d| self.alloc.free(d);
        self.last_datagram = self.alloc.dupe(u8, data) catch null;
        self.evaluate();
    }

    pub fn onStreamReset(self: *Runner, _: *event_loop.ClientSession, _: u64, _: u64, error_code: u32) void {
        self.reset_code = error_code;
        self.evaluate();
    }

    pub fn onStopSending(self: *Runner, _: *event_loop.ClientSession, _: u64, _: u64, error_code: u32) void {
        self.stop_code = error_code;
        self.evaluate();
    }

    pub fn onSessionDraining(self: *Runner, session: *event_loop.ClientSession, _: u64) void {
        self.draining = true;
        if (self.scenario == .server_drain) {
            // Draining is a warning, not a close: the session must still work.
            self.openAndSend(session, "still here");
            if (self.outcome == null) self.pass("ok", .{});
        }
    }

    pub fn onSessionClosed(
        self: *Runner,
        _: *event_loop.ClientSession,
        _: u64,
        error_code: u32,
        reason: []const u8,
    ) void {
        self.closed_code = error_code;
        self.closed_reason.clearRetainingCapacity();
        self.closed_reason.appendSlice(self.alloc, reason) catch {};

        switch (self.scenario) {
            .connect_echo => self.pass("ok", .{}),
            .client_close_code => self.expectCloseInfo(7, "done"),
            .server_close_code0 => self.expectCloseInfo(0, "bye"),
            .server_close_code42 => self.expectCloseInfo(42, "test"),
            .server_close_code3999 => self.expectCloseInfo(3999, "max"),
            else => self.fail("session closed unexpectedly (code={d})", .{error_code}),
        }
    }

    pub fn onSessionRejected(self: *Runner, _: *event_loop.ClientSession, _: u64, status: []const u8) void {
        self.fail("CONNECT rejected with status {s}", .{status});
    }

    fn expectCloseInfo(self: *Runner, want_code: u32, want_reason: []const u8) void {
        const code = self.closed_code orelse 0;
        if (code != want_code) return self.fail("code={d}, want {d}", .{ code, want_code });
        if (!std.mem.eql(u8, self.closed_reason.items, want_reason)) {
            return self.fail("reason=\"{s}\", want \"{s}\"", .{ self.closed_reason.items, want_reason });
        }
        self.pass("ok", .{});
    }

    pub fn onPollComplete(self: *Runner, session: *event_loop.ClientSession) void {
        if (self.outcome != null or !self.ready) return;

        // Reset only once the peer has acknowledged the stream header,
        // otherwise RESET_STREAM lets it discard a stream it never surfaced.
        if (self.scenario == .client_abort_stream and !self.reset_sent) {
            if (self.firstOpened()) |id| {
                const acked = if (session.getSendStreamStats(id)) |st| st.bytes_acknowledged > 0 else false;
                if (acked) {
                    session.resetStream(id, 42);
                    self.reset_sent = true;
                }
            }
        }

        // Keep writing until the peer's STOP_SENDING lands on our side.
        if (self.scenario == .server_stop_sending and self.writes_left > 0) {
            if (self.opened.items.len > 0) {
                self.writes_left -= 1;
                var chunk: [4096]u8 = undefined;
                @memset(&chunk, 'x');
                session.sendStreamData(self.opened.items[0], &chunk) catch {};
            }
        }
        self.evaluate();
    }

    /// Decide whether what has arrived so far settles the scenario. Called
    /// after every event rather than at fixed points, so a scenario finishes as
    /// soon as its evidence is in.
    fn evaluate(self: *Runner) void {
        if (self.outcome != null) return;
        switch (self.scenario) {
            .bidi_echo_small => {
                const id = self.firstOpened() orelse return;
                if (!self.finished.contains(id)) return;
                self.expectEql(self.bytesOf(id), "hello");
            },
            .bidi_echo_3_streams => {
                if (self.opened.items.len < 3) return;
                for (self.opened.items) |id| {
                    if (!self.finished.contains(id)) return;
                }
                for (self.opened.items, 0..) |id, i| {
                    var want: [8]u8 = undefined;
                    const text = std.fmt.bufPrint(&want, "msg{d}", .{i}) catch return;
                    if (!std.mem.eql(u8, self.bytesOf(id), text)) {
                        return self.fail("stream {d}: \"{s}\"", .{ i, self.bytesOf(id) });
                    }
                }
                self.pass("msg0,msg1,msg2", .{});
            },
            .bidi_echo_64kb => {
                const id = self.firstOpened() orelse return;
                self.checkPattern(self.bytesOf(id), self.finished.contains(id));
            },
            .uni_echo => {
                if (self.uni_done.items.len == 0) return;
                self.expectEql(self.uni_done.items[0], "uni-test");
            },
            .uni_echo_64kb => {
                if (self.uni_done.items.len == 0) return;
                self.checkPattern(self.uni_done.items[0], true);
            },
            .uni_multiple_streams => {
                if (self.uni_done.items.len < 5) return;
                // WebTransport gives no ordering guarantee across streams, so
                // check the set, not the sequence.
                var seen = [_]bool{false} ** 5;
                for (self.uni_done.items) |p| {
                    for (0..5) |i| {
                        var want: [16]u8 = undefined;
                        const text = std.fmt.bufPrint(&want, "stream-{d}", .{i}) catch continue;
                        if (std.mem.eql(u8, p, text)) seen[i] = true;
                    }
                }
                for (seen, 0..) |ok, i| {
                    if (!ok) return self.fail("missing stream-{d}", .{i});
                }
                self.pass("ok", .{});
            },
            .datagram_echo => {
                const d = self.last_datagram orelse return;
                self.expectEql(d, "dg-test");
            },
            .datagram_length_echo => {
                const d = self.last_datagram orelse return;
                const got = std.fmt.parseInt(usize, d, 10) catch
                    return self.fail("server replied \"{s}\"", .{d});
                // A datagram at maxDatagramSize must arrive whole or not at
                // all — silent truncation is the failure this catches.
                if (got != self.expected_datagram_len) {
                    return self.fail("sent {d}, server saw {d}", .{ self.expected_datagram_len, got });
                }
                self.pass("ok ({d}B)", .{got});
            },
            .server_abort_stream => {
                const code = self.reset_code orelse return;
                if (code != 42) return self.fail("streamErrorCode={d}", .{code});
                self.pass("ok: reset {d}", .{code});
            },
            .server_stop_sending => {
                const code = self.stop_code orelse return;
                if (code != 19) return self.fail("streamErrorCode={d}", .{code});
                self.pass("ok: stopped {d}", .{code});
            },
            .client_abort_stream => {
                if (self.uni_done.items.len == 0) return;
                // The server reports back what code it saw, so this proves the
                // reset reached it rather than merely that resetStream returned.
                self.expectEql(self.uni_done.items[0], "42");
            },
            else => {},
        }
    }

    fn firstOpened(self: *Runner) ?u64 {
        if (self.opened.items.len == 0) return null;
        return self.opened.items[0];
    }

    fn checkPattern(self: *Runner, got: []const u8, done: bool) void {
        if (got.len < LARGE) {
            if (done) self.fail("{d} bytes, want {d}", .{ got.len, LARGE });
            return;
        }
        for (got[0..LARGE], 0..) |b, i| {
            if (b != @as(u8, @truncate(i))) return self.fail("corrupt at {d}", .{i});
        }
        self.pass("ok ({d}B)", .{got.len});
    }

};

fn isUni(stream_id: u64) bool {
    return (stream_id & 0x2) != 0;
}

/// The manifest is the authority on which scenarios exist. Refuse to run a
/// partial suite: a scenario that exists on only one side is the exact drift
/// this file is meant to prevent.
fn manifestScenarios(alloc: std.mem.Allocator) ![]Scenario {
    const parsed = try std.json.parseFromSlice(std.json.Value, alloc, MANIFEST_JSON, .{});
    defer parsed.deinit();

    const list = parsed.value.object.get("scenarios").?.array;
    var out: std.ArrayList(Scenario) = .empty;
    errdefer out.deinit(alloc);

    var missing: std.ArrayList(u8) = .empty;
    defer missing.deinit(alloc);

    for (list.items) |entry| {
        const obj = entry.object;
        var runs_here = false;
        for (obj.get("runners").?.array.items) |r| {
            if (std.mem.eql(u8, r.string, "zig")) runs_here = true;
        }
        if (!runs_here) continue;

        const id = obj.get("id").?.string;
        if (Scenario.fromId(id)) |s| {
            try out.append(alloc, s);
        } else {
            if (missing.items.len > 0) try missing.appendSlice(alloc, ", ");
            try missing.appendSlice(alloc, id);
        }
    }

    if (missing.items.len > 0) {
        std.debug.print(
            "wpt-client is out of step with scenarios.json\n  no implementation for: {s}\n",
            .{missing.items},
        );
        return error.ScenarioMissing;
    }
    return out.toOwnedSlice(alloc);
}

fn certHash(alloc: std.mem.Allocator, path: []const u8) ![32]u8 {
    const pem = try sys.readFileAlloc(alloc, path, 1 << 16);
    defer alloc.free(pem);
    var der_buf: [8192]u8 = undefined;
    const der = try tls13.parsePemCert(pem, &der_buf);
    var out: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(der, &out, .{});
    return out;
}

const Report = struct { id: []const u8, passed: bool, detail: []const u8 };

fn runScenario(
    alloc: std.mem.Allocator,
    scenario: Scenario,
    port: u16,
    pins: []const [32]u8,
    timeout_ms: i64,
) !Report {
    var id_buf: [64]u8 = undefined;
    const id = scenario.idOf(&id_buf);

    var path_buf: [160]u8 = undefined;
    const path = try std.fmt.bufPrint(&path_buf, "/webtransport/handlers/{s}", .{handlerFor(scenario)});

    var offer_buf: [128]u8 = undefined;
    const offered = [_][]const u8{ "nonesuch", "echo" };
    const offer = try wt_protocol.encodeList(&offered, &offer_buf);
    const connect_headers = [_]qpack.Header{
        .{ .name = wt_protocol.HEADER_AVAILABLE, .value = offer },
    };

    var runner = Runner.init(alloc, scenario);
    defer runner.deinit();

    var client = try event_loop.Client(Runner).init(alloc, &runner, .{
        .port = port,
        .path = path,
        .ca = .{ .pinned_hashes = pins },
        .connect_headers = if (scenario == .wt_protocol_negotiation) &connect_headers else &.{},
    });
    defer client.deinit();

    client.start();
    const deadline = sys.nanoTimestamp() + timeout_ms * std.time.ns_per_ms;
    while (runner.outcome == null and sys.nanoTimestamp() < deadline) {
        try client.tick();
        if (client.conn.isClosed()) {
            // An abrupt QUIC close is the whole point of one scenario and a
            // failure everywhere else.
            if (scenario == .server_connection_close) {
                runner.pass("ok: connection closed", .{});
            } else {
                runner.fail("connection closed before the scenario finished", .{});
            }
            break;
        }
    }

    const detail = if (runner.outcome == null)
        try std.fmt.allocPrint(alloc, "timeout ({d}ms)", .{timeout_ms})
    else
        try alloc.dupe(u8, runner.detail.items);

    return .{
        .id = try alloc.dupe(u8, id),
        .passed = runner.outcome != null and runner.outcome.? == .pass,
        .detail = detail,
    };
}

fn handlerFor(scenario: Scenario) []const u8 {
    return switch (scenario) {
        .connect_echo,
        .client_close_code,
        .bidi_echo_small,
        .bidi_echo_3_streams,
        .bidi_echo_64kb,
        .uni_echo,
        .uni_echo_64kb,
        .datagram_echo,
        .datagram_maxsize,
        .wt_protocol_negotiation,
        => "echo.py",
        .server_close_code0 => "server-close.py?code=0&reason=bye",
        .server_close_code42 => "server-close.py?code=42&reason=test",
        .server_close_code3999 => "server-close.py?code=3999&reason=max",
        .server_connection_close => "server-connection-close.py",
        .uni_multiple_streams => "server-create-multiple-streams.py?count=5",
        .datagram_length_echo => "echo-datagram-length.py",
        .server_abort_stream => "abort-stream-from-server.py?code=42",
        .client_abort_stream => "abort-echo.py",
        .server_stop_sending => "stop-sending.py?code=19",
        .server_drain => "server-drain.py",
    };
}

pub fn main(init: std.process.Init.Minimal) !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    var port: u16 = 4433;
    var cert_path: []const u8 = "interop/browser/certs/server.crt";
    var only: ?[]const u8 = null;
    var timeout_ms: i64 = 8000;

    var args = sys.argsIterator(init.args);
    _ = args.next();
    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--port")) {
            if (args.next()) |v| port = std.fmt.parseInt(u16, v, 10) catch port;
        } else if (std.mem.eql(u8, arg, "--cert")) {
            if (args.next()) |v| cert_path = v;
        } else if (std.mem.eql(u8, arg, "--scenario")) {
            only = args.next();
        } else if (std.mem.eql(u8, arg, "--timeout")) {
            if (args.next()) |v| timeout_ms = std.fmt.parseInt(i64, v, 10) catch timeout_ms;
        }
    }

    const scenarios = try manifestScenarios(alloc);
    const pins = [_][32]u8{try certHash(alloc, cert_path)};

    std.debug.print("\nServer:    127.0.0.1:{d}\nCert:      {s}\nRunner:    zig\n\n", .{ port, cert_path });

    var passed: usize = 0;
    var failed: usize = 0;
    for (scenarios) |scenario| {
        var id_buf: [64]u8 = undefined;
        const id = scenario.idOf(&id_buf);
        if (only) |want| {
            if (std.mem.indexOf(u8, id, want) == null) continue;
        }

        const report = runScenario(alloc, scenario, port, &pins, timeout_ms) catch |err| {
            std.debug.print("  FAIL:{s} {any}\n", .{ id, err });
            failed += 1;
            continue;
        };

        if (report.passed) {
            passed += 1;
            std.debug.print("  PASS:{s} {s}\n", .{ report.id, report.detail });
        } else {
            failed += 1;
            std.debug.print("  FAIL:{s} {s}\n", .{ report.id, report.detail });
        }
    }

    std.debug.print("\n  {d} passed  {d} failed\n\n", .{ passed, failed });
    if (failed > 0) std.process.exit(1);
}
