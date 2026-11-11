// MoQ interop test client — https://github.com/englishm/moq-interop-runner
//
// Drives the runner's control-plane test cases against a relay and reports
// TAP version 14 on stdout. The runner reads only the TAP; anything else we
// want to say goes to stderr.
//
//   moq-test-client [--relay URL] [--test NAME] [--list]
//                   [--verbose] [--tls-disable-verify]
//
// Env (the runner sets these, flags win):
//   RELAY_URL, TESTCASE, TLS_DISABLE_VERIFY, VERBOSE
//
// Exit: 0 all passed, 1 one or more failed, 127 role/test unsupported.
//
// The scheme picks the transport: https:// is WebTransport, moqt:// is
// native QUIC. See src/moq/url.zig.

const std = @import("std");
const posix = std.posix;
const quic = @import("quic");
const io_compat = quic.io_compat;
const sys = quic.sys;
const event_loop = quic.event_loop;
const qpack = quic.qpack;
const wt_protocol = quic.webtransport_protocol;

const moq_msg = quic.moq.message;
const moq_codes = quic.moq.message_codes;
const moq_obj = quic.moq.object;
const moq_wire = quic.moq.wire;
const moq_session = quic.moq.session;
const moq_url = quic.moq.url;
const moq_version = quic.moq.version;

pub const std_options: std.Options = .{ .log_level = .err };

/// Reported to the runner as `implementation_version`. Tracks the version
/// in build.zig.zon, which is what a reader would go looking for.
const VERSION = "0.3.0";

// Fixed by the test spec, not passed in.
const TEST_NAMESPACE = [_][]const u8{ "moq-test", "interop" };
const MISSING_NAMESPACE = [_][]const u8{ "nonexistent", "namespace" };
const RENDEZVOUS_NAMESPACE = [_][]const u8{ "nonexistent", "rendezvous" };
const TEST_TRACK = "test-track";

const TestCase = enum {
    setup_only,
    announce_only,
    publish_namespace_done,
    subscribe_error,
    rendezvous_timeout,
    announce_subscribe,
    subscribe_before_announce,
    subscribe_namespace_lifecycle,
    publish_namespace_multi_publisher_retention,
    data_subgroup_basic,

    fn name(self: TestCase) []const u8 {
        return switch (self) {
            .setup_only => "setup-only",
            .announce_only => "announce-only",
            .publish_namespace_done => "publish-namespace-done",
            .subscribe_error => "subscribe-error",
            .rendezvous_timeout => "rendezvous-timeout",
            .announce_subscribe => "announce-subscribe",
            .subscribe_before_announce => "subscribe-before-announce",
            .subscribe_namespace_lifecycle => "subscribe-namespace-lifecycle",
            .publish_namespace_multi_publisher_retention => "publish-namespace-multi-publisher-retention",
            .data_subgroup_basic => "data-subgroup-basic",
        };
    }

    fn fromName(s: []const u8) ?TestCase {
        inline for (comptime std.enums.values(TestCase)) |c| {
            if (std.mem.eql(u8, s, c.name())) return c;
        }
        return null;
    }

    /// Wall-clock budget from the spec.
    fn timeoutMs(self: TestCase) i64 {
        return switch (self) {
            .announce_subscribe => 3000,
            .subscribe_before_announce => 3500,
            // The specs give no figure; two namespace phases at most.
            .subscribe_namespace_lifecycle => 8000,
            .publish_namespace_multi_publisher_retention => 8000,
            // Two 5 s setup phases, then 10 s to deliver and drain.
            .data_subgroup_basic => 20000,
            else => 2000,
        };
    }

    /// For cases with a prose spec of their own (docs/tests in the runner).
    fn specRevision(self: TestCase) ?u32 {
        return switch (self) {
            .subscribe_namespace_lifecycle, .publish_namespace_multi_publisher_retention => 1,
            .data_subgroup_basic => 2,
            else => null,
        };
    }
};

const ALL_TESTS = std.enums.values(TestCase);

const Outcome = enum { pass, fail, skip };

const Result = struct {
    outcome: Outcome = .fail,
    duration_ms: i64 = 0,
    msg_buf: [192]u8 = undefined,
    msg_len: usize = 0,
    /// The MoQT version each session ended up on, for the YAML block.
    negotiated: [32]u8 = undefined,
    negotiated_len: usize = 0,

    fn setMsg(self: *Result, comptime fmt: []const u8, args: anytype) void {
        const s = std.fmt.bufPrint(&self.msg_buf, fmt, args) catch self.msg_buf[0..0];
        self.msg_len = s.len;
    }
    fn message(self: *const Result) []const u8 {
        return self.msg_buf[0..self.msg_len];
    }
    fn setNegotiated(self: *Result, v: []const u8) void {
        self.negotiated_len = @min(v.len, self.negotiated.len);
        @memcpy(self.negotiated[0..self.negotiated_len], v[0..self.negotiated_len]);
    }
    fn negotiatedSlice(self: *const Result) []const u8 {
        return self.negotiated[0..self.negotiated_len];
    }
};

const Role = enum { idle, publisher, subscriber, ns_subscriber };

/// A NAMESPACE or NAMESPACE_DONE seen on our SUBSCRIBE_NAMESPACE, with its
/// suffix flattened the way the relay keys namespaces (`a/b/`).
const NsEvent = struct {
    done: bool,
    suffix_buf: [128]u8 = undefined,
    suffix_len: usize = 0,

    fn suffix(self: *const NsEvent) []const u8 {
        return self.suffix_buf[0..self.suffix_len];
    }
};

// data-subgroup-basic's canonical MoQT Test tuple. The tuple is what a
// publisher generates from, so these constants restate it for the checks.
const DP_TUPLE = [_][]const u8{ "moq-test-00", "0", "0", "0", "2", "4", "5", "64", "32", "2", "1", "1", "0", "-1", "-1", "0" };
const DP_TRACK = "track";
const DP_GROUPS: usize = 3;
const DP_PER_GROUP: usize = 5;
const DP_OBJECTS = DP_GROUPS * DP_PER_GROUP;
const DP_INTERVAL_MS: i64 = 2;
const DP_PRIORITY: u8 = 128;
const DP_ALIAS: u64 = 1;
const DP_PAYLOAD: [64]u8 = @splat('t');

fn dpSize(object: u64) usize {
    return if (object == 0) 64 else 32;
}

/// One subgroup stream as the subscriber reads it.
const DataStream = struct {
    id: u64 = std.math.maxInt(u64),
    buf: [2048]u8 = undefined,
    len: usize = 0,
    header: ?moq_obj.SubgroupHeader = null,
    prev: ?u64 = null,
    first: ?u64 = null,
};

const ReceivedObject = struct {
    alias: u64,
    group: u64,
    subgroup: u64,
    id: u64,
    priority: u8,
    status: u64,
    len: usize,
    bytes_ok: bool,
};

/// Shared by both legs of data-subgroup-basic: the publisher's generator
/// state and what the subscriber received.
const DataPlane = struct {
    full_ns: []const []const u8,

    gen_stream: ?u64 = null,
    upstream_ns_ok: bool = false,
    upstream_seen: bool = false,
    gen_start_ms: i64 = 0,
    next: usize = 0,
    out: u64 = 0,
    out_ids: [DP_GROUPS]u64 = undefined,
    streams_opened: u64 = 0,
    last_object_ms: i64 = 0,
    done_sent: bool = false,

    streams: [8]DataStream = @splat(.{}),
    objects: [2 * DP_OBJECTS]ReceivedObject = undefined,
    objects_len: usize = 0,
    overflow: usize = 0,
    streams_finished: u64 = 0,
    sub_alias: ?u64 = null,
    got_done: bool = false,
    done_status: u64 = 0,
    done_count: u64 = 0,

    /// PUBLISH_DONE's count is exact unless it is the unknown sentinel.
    fn drained(self: *const DataPlane) bool {
        if (!self.got_done) return false;
        if (self.done_count >= (1 << 62) - 1) return false;
        return self.streams_finished >= self.done_count;
    }
};

fn nowMs() i64 {
    return @intCast(@divFloor(sys.nanoTimestamp(), 1_000_000));
}

// ─────────────────────────────────────────────────────────────────────
// Peer
//
// One connection. Doubles as the event_loop handler and as the transport
// the MoQ session writes through — the session is generic over the
// transport, and keeping them one type avoids a back-pointer that would
// have to be fixed up on every callback.
// ─────────────────────────────────────────────────────────────────────

fn Peer(comptime proto: event_loop.Protocol) type {
    return struct {
        const Self = @This();
        pub const protocol: event_loop.Protocol = proto;
        const Sess = moq_session.Session(*Self);
        const is_wt = proto == .webtransport;

        sess: Sess = undefined,
        role: Role = .idle,
        /// Set once the transport says which draft was negotiated.
        draft: moq_version.Draft = moq_version.DEFAULT,
        verbose: bool = false,

        // Valid only inside a callback: event_loop builds the session
        // wrapper on the stack per poll.
        cur: ?*event_loop.ClientSession = null,
        wt_session_id: u64 = 0,
        wt_ready: bool = false,

        /// §9.3.4: how long the relay should hold a subscription waiting
        /// for a publisher. Absent means 0 — answer immediately.
        rendezvous_timeout_ms: ?u64 = null,

        request_sid: ?u64 = null,
        request_sent: bool = false,
        cancel_after_ok: bool = false,
        cancelled: bool = false,

        got_request_ok: bool = false,
        got_request_error: bool = false,
        got_subscribe_ok: bool = false,
        /// Publisher side: we answered a relay's SUBSCRIBE for our track.
        served_subscribe: bool = false,
        error_code: u64 = 0,
        error_reason: [64]u8 = undefined,
        error_reason_len: usize = 0,

        peer_impl: [64]u8 = undefined,
        peer_impl_len: usize = 0,
        negotiated: [32]u8 = undefined,
        negotiated_len: usize = 0,

        failed: bool = false,
        fail_reason: [96]u8 = undefined,
        fail_reason_len: usize = 0,

        /// Which namespace the subscriber asks for — the error cases point
        /// at namespaces the relay is expected not to have.
        subscribe_namespace: []const []const u8 = &TEST_NAMESPACE,
        subscribe_track: []const u8 = TEST_TRACK,
        /// The data-plane stimulus: no FORWARD, SUBSCRIBER_PRIORITY or
        /// SUBSCRIPTION_FILTER, so the subscription is unfiltered.
        bare_subscribe: bool = false,

        /// .publisher announces this, and `extra_publish_ns` on a second
        /// request of its own when set.
        publish_ns: []const []const u8 = &TEST_NAMESPACE,
        extra_publish_ns: ?[]const []const u8 = null,
        extra_sid: ?u64 = null,
        got_extra_ok: bool = false,

        /// .ns_subscriber's SUBSCRIBE_NAMESPACE prefix, and what came back.
        ns_prefix: []const []const u8 = &.{},
        ns_events: [16]NsEvent = undefined,
        ns_events_len: usize = 0,

        dp: ?*DataPlane = null,

        fn note(self: *Self, comptime fmt: []const u8, args: anytype) void {
            if (!self.verbose) return;
            std.debug.print("# " ++ fmt ++ "\n", args);
        }

        fn fail(self: *Self, comptime fmt: []const u8, args: anytype) void {
            if (self.failed) return;
            self.failed = true;
            const s = std.fmt.bufPrint(&self.fail_reason, fmt, args) catch self.fail_reason[0..0];
            self.fail_reason_len = s.len;
        }

        // --- transport seam for moq_session.Session ---

        pub fn openUni(self: *Self) !u64 {
            const cs = self.cur orelse return error.NotConnected;
            return if (is_wt) cs.openUniStream(self.wt_session_id, null) else cs.openQuicUniStream();
        }

        pub fn openBidi(self: *Self) !u64 {
            const cs = self.cur orelse return error.NotConnected;
            return if (is_wt) cs.openBidiStream(self.wt_session_id, null) else cs.openStream();
        }

        pub fn write(self: *Self, stream_id: u64, data: []const u8) !void {
            const cs = self.cur orelse return error.NotConnected;
            return if (is_wt) cs.sendStreamData(stream_id, data) else cs.writeStream(stream_id, data);
        }

        pub fn finish(self: *Self, stream_id: u64) void {
            const cs = self.cur orelse return;
            if (is_wt) cs.closeStream(stream_id) else cs.closeQuicStream(stream_id);
        }

        pub fn reset(self: *Self, stream_id: u64, code: u64) void {
            const cs = self.cur orelse return;
            if (is_wt) cs.resetStream(stream_id, @truncate(code)) else cs.resetQuicStream(stream_id, code);
        }

        pub fn stopSending(self: *Self, stream_id: u64, code: u64) void {
            const cs = self.cur orelse return;
            if (is_wt) cs.stopSending(stream_id, @truncate(code)) else cs.stopSendingQuicStream(stream_id, code);
        }

        // --- event_loop callbacks ---

        pub fn onConnected(self: *Self, cs: *event_loop.ClientSession) void {
            if (is_wt) return; // WebTransport waits for the session to be ready
            self.cur = cs;
            defer self.cur = null;
            self.setNegotiatedFromAlpn();
            self.startSession();
        }

        pub fn onSessionReady(
            self: *Self,
            cs: *event_loop.ClientSession,
            session_id: u64,
            headers: []const qpack.Header,
        ) void {
            if (!is_wt) return;
            self.cur = cs;
            defer self.cur = null;
            self.wt_session_id = session_id;
            self.wt_ready = true;

            if (wt_protocol.findHeader(headers, wt_protocol.HEADER_SELECTED)) |raw| {
                var scratch: [64]u8 = undefined;
                if (wt_protocol.decodeItem(raw, &scratch)) |v| {
                    self.setNegotiated(v);
                    // The peer's choice decides the wire format from here.
                    if (moq_version.Draft.fromAlpn(v)) |d| self.useDraft(d);
                } else |_| {}
            } else {
                // No WT-Protocol means the server ignored the offer, which
                // in practice means an older peer: fall back to what we
                // asked for first.
                self.setNegotiated(self.draft.alpn());
            }
            self.startSession();
        }

        pub fn onSessionRejected(self: *Self, _: *event_loop.ClientSession, _: u64, status: []const u8) void {
            self.fail("WebTransport CONNECT rejected with {s}", .{status});
        }

        pub fn onStreamData(
            self: *Self,
            cs: *event_loop.ClientSession,
            stream_id: u64,
            data: []const u8,
            fin: bool,
        ) void {
            self.cur = cs;
            defer self.cur = null;

            if (self.dp) |dp| {
                if (self.role == .subscriber) {
                    if (self.dataStream(dp, stream_id, data)) |ds| return self.onData(dp, ds, data, fin);
                }
            }

            var events: [8]moq_session.Event = undefined;
            const n = self.sess.onStreamData(stream_id, data, fin, &events) catch |e| {
                self.fail("session error on stream {d}: {t}", .{ stream_id, e });
                return;
            };
            for (events[0..n]) |ev| self.handle(ev);
        }

        pub fn onSessionClosed(self: *Self, _: *event_loop.ClientSession, _: u64, code: u32, reason: []const u8) void {
            if (code != 0) self.fail("session closed: code={d} reason={s}", .{ code, reason });
        }

        // --- protocol ---

        fn setNegotiated(self: *Self, v: []const u8) void {
            self.negotiated_len = @min(v.len, self.negotiated.len);
            @memcpy(self.negotiated[0..self.negotiated_len], v[0..self.negotiated_len]);
        }

        /// Raw QUIC negotiates the MoQT version with the QUIC ALPN: the
        /// server picked one of ours, and the wire format follows it.
        fn setNegotiatedFromAlpn(self: *Self) void {
            const cs = self.cur orelse return;
            const alpn = cs.conn.negotiatedAlpn();
            if (moq_version.Draft.fromAlpn(alpn)) |d| self.useDraft(d);
            self.setNegotiated(self.draft.alpn());
        }

        fn useDraft(self: *Self, d: moq_version.Draft) void {
            self.draft = d;
            self.sess.draft = d;
        }

        pub fn negotiatedSlice(self: *const Self) []const u8 {
            return self.negotiated[0..self.negotiated_len];
        }

        /// Must run before the connection is created: a stream event can
        /// reach onStreamData ahead of the ready callback, and the session's
        /// stream table has to be initialised by then.
        pub fn prepare(self: *Self, target: *const Target) void {
            self.sess = Sess.init(self);
            self.sess.implementation = "quic-zig/moq-test-client";
            self.sess.draft = self.draft;
            if (!is_wt) {
                self.sess.path = target.locator.path;
                self.sess.authority = target.authoritySlice();
            }
        }

        fn startSession(self: *Self) void {
            self.sess.sendSetup() catch |e| {
                self.fail("could not send SETUP: {t}", .{e});
                return;
            };
            self.note("SETUP sent", .{});
        }

        fn handle(self: *Self, ev: moq_session.Event) void {
            switch (ev) {
                .peer_setup => |p| {
                    if (p.options.implementation) |impl| {
                        self.peer_impl_len = @min(impl.len, self.peer_impl.len);
                        @memcpy(self.peer_impl[0..self.peer_impl_len], impl[0..self.peer_impl_len]);
                    }
                    self.note("peer SETUP received", .{});
                    self.sendRoleRequest();
                },
                .request_ok => |r| {
                    if (self.extra_sid != null and r.stream_id == self.extra_sid.?) {
                        self.got_extra_ok = true;
                        return;
                    }
                    if (self.request_sid != null and r.stream_id != self.request_sid.?) return;
                    self.got_request_ok = true;
                    self.note("REQUEST_OK", .{});
                    if (self.cancel_after_ok and !self.cancelled) {
                        // draft-18 withdraws a namespace by cancelling the
                        // request stream rather than sending a DONE message.
                        self.sess.cancelRequest(r.stream_id, moq_session.ResetCode.CANCELLED);
                        self.cancelled = true;
                        self.note("request stream cancelled", .{});
                    }
                },
                .request_error => |r| {
                    if (self.extra_sid != null and r.stream_id == self.extra_sid.?) {
                        self.fail("second PUBLISH_NAMESPACE rejected: code={d}", .{r.err.error_code});
                        return;
                    }
                    if (self.request_sid != null and r.stream_id != self.request_sid.?) return;
                    self.got_request_error = true;
                    self.error_code = r.err.error_code;
                    self.error_reason_len = @min(r.err.reason.len, self.error_reason.len);
                    @memcpy(self.error_reason[0..self.error_reason_len], r.err.reason[0..self.error_reason_len]);
                    self.note("REQUEST_ERROR code={d}", .{r.err.error_code});
                },
                .subscribe_ok => |r| {
                    if (self.request_sid != null and r.stream_id != self.request_sid.?) return;
                    self.got_subscribe_ok = true;
                    if (self.dp) |dp| dp.sub_alias = r.ok.track_alias;
                    self.note("SUBSCRIBE_OK alias={d}", .{r.ok.track_alias});
                },
                .subscribe => |r| {
                    // A relay routes a subscription by asking the namespace's
                    // publisher for the track. announce-subscribe only
                    // completes if we answer.
                    if (self.role != .publisher) return;
                    if (self.dp) |dp| return self.serveData(dp, r.stream_id, r.subscribe);
                    var buf: [128]u8 = undefined;
                    var fbs = io_compat.fixedBufferStream(&buf);
                    moq_msg.writeSubscribeOk(&fbs, .{ .track_alias = 1 }) catch return;
                    self.sess.transport.write(r.stream_id, buf[0..fbs.seek]) catch return;
                    self.served_subscribe = true;
                    self.note("served a SUBSCRIBE on stream {d}", .{r.stream_id});
                },
                .namespace => |r| if (self.isOurRequest(r.stream_id)) self.recordNs(r.namespace.track_namespace_suffix, false),
                .namespace_done => |r| if (self.isOurRequest(r.stream_id)) self.recordNs(r.namespace.track_namespace_suffix, true),
                .publish_done => |r| if (self.isOurRequest(r.stream_id)) {
                    if (self.dp) |dp| {
                        dp.got_done = true;
                        dp.done_status = r.done.status_code;
                        dp.done_count = r.done.stream_count;
                    }
                    self.note("PUBLISH_DONE status={d} streams={d}", .{ r.done.status_code, r.done.stream_count });
                },
                .goaway => self.note("GOAWAY", .{}),
                .other => |o| self.note("message type=0x{x}", .{o.type}),
                else => {},
            }
        }

        fn sendRoleRequest(self: *Self) void {
            if (self.request_sent or self.role == .idle) return;
            self.request_sent = true;

            var buf: [512]u8 = undefined;
            var fbs = io_compat.fixedBufferStream(&buf);
            switch (self.role) {
                .publisher => moq_msg.writePublishNamespace(&fbs, .{
                    .track_namespace = self.publish_ns,
                }, self.draft) catch return,
                .subscriber => moq_msg.writeSubscribe(&fbs, .{
                    .track_namespace = self.subscribe_namespace,
                    .track_name = self.subscribe_track,
                    .rendezvous_timeout_ms = self.rendezvous_timeout_ms,
                    .forward = if (self.bare_subscribe) null else true,
                    .subscriber_priority = if (self.bare_subscribe) null else 128,
                    .filter = if (self.bare_subscribe) null else .{},
                }, self.draft) catch return,
                .ns_subscriber => moq_msg.writeSubscribeNamespace(&fbs, .{
                    .track_namespace_prefix = self.ns_prefix,
                }, self.draft) catch return,
                .idle => unreachable,
            }
            self.request_sid = self.sess.sendRequest(buf[0..fbs.seek]) catch |e| {
                self.fail("could not send request: {t}", .{e});
                return;
            };
            self.note("{s} request on stream {d}", .{ @tagName(self.role), self.request_sid.? });

            const extra = self.extra_publish_ns orelse return;
            fbs = io_compat.fixedBufferStream(&buf);
            // A client's Request IDs are even and step by 2 (§10.1); a repeat
            // is a session-ending INVALID_REQUEST_ID.
            moq_msg.writePublishNamespace(&fbs, .{ .request_id = 2, .track_namespace = extra }, self.draft) catch return;
            self.extra_sid = self.sess.sendRequest(buf[0..fbs.seek]) catch |e| {
                self.fail("could not send request: {t}", .{e});
                return;
            };
        }

        fn isOurRequest(self: *const Self, sid: u64) bool {
            return self.request_sid != null and sid == self.request_sid.?;
        }

        fn recordNs(self: *Self, suffix: []const []const u8, done: bool) void {
            if (self.ns_events_len == self.ns_events.len) return;
            const ev = &self.ns_events[self.ns_events_len];
            ev.* = .{ .done = done };
            ev.suffix_len = moq_wire.flattenNamespace(suffix, &ev.suffix_buf) orelse return;
            self.ns_events_len += 1;
            self.note("{s} \"{s}\"", .{ if (done) "NAMESPACE_DONE" else "NAMESPACE", ev.suffix() });
        }

        /// Position of the first NAMESPACE (or, with `done`, NAMESPACE_DONE)
        /// for `suffix`.
        pub fn nsIndex(self: *const Self, done: bool, suffix: []const u8) ?usize {
            for (self.ns_events[0..self.ns_events_len], 0..) |*ev, i| {
                if (ev.done == done and std.mem.eql(u8, ev.suffix(), suffix)) return i;
            }
            return null;
        }

        // --- data plane: publisher ---

        /// The relay's SUBSCRIBE for the tuple under our prefix: accept it
        /// and start generating.
        fn serveData(self: *Self, dp: *DataPlane, sid: u64, sub: moq_msg.Subscribe) void {
            var buf: [256]u8 = undefined;
            var fbs = io_compat.fixedBufferStream(&buf);
            dp.upstream_seen = true;
            const ok = dp.gen_stream == null and std.mem.eql(u8, sub.track_name, DP_TRACK) and nsEql(sub.track_namespace, dp.full_ns);
            if (!ok) {
                moq_msg.writeRequestError(&fbs, .{ .error_code = moq_codes.ERR_DOES_NOT_EXIST, .reason = "not this run's tuple" }) catch return;
                self.write(sid, buf[0..fbs.seek]) catch {};
                return;
            }
            moq_msg.writeSubscribeOk(&fbs, .{ .track_alias = DP_ALIAS }) catch return;
            self.write(sid, buf[0..fbs.seek]) catch return;
            dp.upstream_ns_ok = true;
            dp.gen_stream = sid;
            dp.gen_start_ms = nowMs();
            self.served_subscribe = true;
        }

        /// Sends whatever objects are due, one subgroup stream per group,
        /// then PUBLISH_DONE with the exact Stream Count.
        pub fn pumpData(self: *Self, cs: *event_loop.ClientSession) void {
            const dp = self.dp orelse return;
            const sid = dp.gen_stream orelse return;
            if (dp.done_sent or self.failed) return;
            self.cur = cs;
            defer self.cur = null;

            const now = nowMs();
            while (dp.next < DP_OBJECTS and now >= dp.gen_start_ms + @as(i64, @intCast(dp.next)) * DP_INTERVAL_MS) {
                const g: u64 = dp.next / DP_PER_GROUP;
                const o: u64 = dp.next % DP_PER_GROUP;
                var buf: [128]u8 = undefined;
                var fbs = io_compat.fixedBufferStream(&buf);
                if (o == 0) {
                    dp.out = self.openUni() catch |e| return self.fail("could not open a data stream: {t}", .{e});
                    dp.out_ids[@intCast(dp.streams_opened)] = dp.out;
                    dp.streams_opened += 1;
                    moq_obj.writeSubgroupHeader(&fbs, .{
                        .track_alias = DP_ALIAS,
                        .group = g,
                        .subgroup = 0,
                        .publisher_priority = DP_PRIORITY,
                        .end_of_group = false,
                        .per_object_properties = false,
                        .first_object = true,
                    }, self.draft) catch return;
                }
                moq_obj.writeSubgroupObject(&fbs, .{ .id = o, .payload = DP_PAYLOAD[0..dpSize(o)] }, if (o == 0) null else o - 1, false) catch return;
                self.write(dp.out, buf[0..fbs.seek]) catch |e| return self.fail("data write failed: {t}", .{e});
                if (o == DP_PER_GROUP - 1) self.finish(dp.out);
                dp.next += 1;
                dp.last_object_ms = now;
            }
            if (dp.next < DP_OBJECTS) return;
            // A relay that ends the subscription on PUBLISH_DONE drops what
            // is still in flight (imquic does), so it waits for the data to
            // be acknowledged, though never long.
            if (!dataAcked(cs, dp) and now - dp.last_object_ms < 2000) return;

            var buf: [128]u8 = undefined;
            var fbs = io_compat.fixedBufferStream(&buf);
            moq_msg.writePublishDone(&fbs, .{
                .status_code = moq_codes.DONE_TRACK_ENDED,
                .stream_count = dp.streams_opened,
                .reason = "",
            }) catch return;
            self.write(sid, buf[0..fbs.seek]) catch return;
            self.finish(sid);
            dp.done_sent = true;
        }

        // --- data plane: subscriber ---

        /// A peer-opened uni stream that isn't the control stream carries
        /// objects, which the control session must not see.
        fn dataStream(self: *Self, dp: *DataPlane, stream_id: u64, data: []const u8) ?*DataStream {
            for (&dp.streams) |*ds| {
                if (ds.id == stream_id) return ds;
            }
            if (stream_id & 0x2 == 0 or data.len == 0) return null;
            if (self.sess.kindOf(stream_id) != null) return null;
            var peek = io_compat.fixedBufferStream(data);
            const t = moq_wire.readVarInt(&peek) catch return null;
            if (t == moq_codes.MSG_SETUP) return null;
            for (&dp.streams) |*ds| {
                if (ds.id != std.math.maxInt(u64)) continue;
                ds.* = .{ .id = stream_id };
                return ds;
            }
            self.fail("more data streams than the scenario opens", .{});
            return null;
        }

        fn onData(self: *Self, dp: *DataPlane, ds: *DataStream, data: []const u8, fin: bool) void {
            if (ds.len + data.len > ds.buf.len) return self.fail("data stream {d} overran its buffer", .{ds.id});
            @memcpy(ds.buf[ds.len..][0..data.len], data);
            ds.len += data.len;

            var pos: usize = 0;
            if (ds.header == null) {
                var fbs = io_compat.fixedBufferStream(@as([]const u8, ds.buf[0..ds.len]));
                const parsed = moq_obj.readSubgroupHeader(&fbs, self.draft) catch |e| {
                    if (e == moq_wire.Error.BufferTooShort and !fin) return;
                    return self.fail("bad subgroup header: {t} (stream {d} starts {x})", .{ e, ds.id, ds.buf[0..@min(ds.len, 12)] });
                };
                ds.header = parsed.header;
                pos = fbs.seek;
            }
            const h = ds.header.?;
            while (true) {
                const r = moq_obj.readSubgroupObject(ds.buf[pos..ds.len], ds.prev, h.per_object_properties) catch |e|
                    return self.fail("bad object on stream {d}: {t}", .{ ds.id, e });
                const read = r orelse break;
                const o = read.object;
                if (ds.first == null) ds.first = o.id;
                ds.prev = o.id;
                pos += read.consumed;
                if (dp.objects_len == dp.objects.len) {
                    dp.overflow += 1;
                    continue;
                }
                dp.objects[dp.objects_len] = .{
                    .alias = h.track_alias,
                    .group = h.group,
                    .subgroup = h.subgroup orelse ds.first.?,
                    .id = o.id,
                    .priority = h.publisher_priority orelse DP_PRIORITY,
                    .status = o.status,
                    .len = o.payload.len,
                    .bytes_ok = std.mem.allEqual(u8, o.payload, 't'),
                };
                dp.objects_len += 1;
            }
            std.mem.copyForwards(u8, ds.buf[0 .. ds.len - pos], ds.buf[pos..ds.len]);
            ds.len -= pos;

            if (fin) {
                if (ds.len != 0) self.fail("stream {d} ended mid-object", .{ds.id});
                dp.streams_finished += 1;
            }
        }

        /// Cancels a still-open announcement or subscription, so a relay that
        /// is slow to notice the close does not carry it into the next test.
        pub fn withdraw(self: *Self, cs: *event_loop.ClientSession) void {
            const sid = self.request_sid orelse return;
            if (self.cancelled or self.failed) return;
            self.cur = cs;
            defer self.cur = null;
            self.sess.cancelRequest(sid, moq_session.ResetCode.CANCELLED);
            if (self.extra_sid) |x| self.sess.cancelRequest(x, moq_session.ResetCode.CANCELLED);
            self.cancelled = true;
        }
    };
}

/// Every data stream we opened has had its FIN acknowledged. A fully
/// acknowledged uni stream is freed, so one that is gone counts too.
fn dataAcked(cs: *event_loop.ClientSession, dp: *const DataPlane) bool {
    for (dp.out_ids[0..@intCast(dp.streams_opened)]) |id| {
        if (cs.conn.streams.send_streams.get(id)) |ss| if (!ss.fin_acked) return false;
    }
    return true;
}

fn nsEql(a: []const []const u8, b: []const []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |x, y| if (!std.mem.eql(u8, x, y)) return false;
    return true;
}

// ─────────────────────────────────────────────────────────────────────
// Runner
// ─────────────────────────────────────────────────────────────────────

const Target = struct {
    locator: moq_url.Locator,
    /// Numeric form of `locator.host`, since the event loop does not resolve.
    address: [64]u8 = undefined,
    address_len: usize = 0,
    ipv6: bool = false,
    tls_disable_verify: bool = false,
    verbose: bool = false,
    /// Offered newest first; the peer picks. `--draft` narrows it to one,
    /// for running a matrix at each.
    drafts: []const moq_version.Draft = moq_version.PREFERRED,
    /// `host:port`, for the raw-QUIC SETUP's AUTHORITY.
    authority: [280]u8 = undefined,
    authority_len: usize = 0,

    fn addressSlice(self: *const Target) []const u8 {
        return self.address[0..self.address_len];
    }
    fn authoritySlice(self: *const Target) []const u8 {
        return self.authority[0..self.authority_len];
    }
};

fn resolve(target: *Target) !void {
    const host = moq_url.bareHost(target.locator.host);

    // Numeric fast path, then getaddrinfo — the runner's compose network
    // hands out names like "relay".
    if (quic.sockaddr.Address.parseIp4(host, target.locator.port)) |_| {
        @memcpy(target.address[0..host.len], host);
        target.address_len = host.len;
        target.ipv6 = false;
        return;
    } else |_| {}
    if (quic.sockaddr.Address.parseIp6(host, target.locator.port)) |_| {
        @memcpy(target.address[0..host.len], host);
        target.address_len = host.len;
        target.ipv6 = true;
        return;
    } else |_| {}

    const storage = try sys.resolveHost(host, target.locator.port);
    const family = storage.family;
    if (family == posix.AF.INET) {
        const in: *const posix.sockaddr.in = @ptrCast(@alignCast(&storage));
        const b: [4]u8 = @bitCast(in.addr);
        const s = try std.fmt.bufPrint(&target.address, "{d}.{d}.{d}.{d}", .{ b[0], b[1], b[2], b[3] });
        target.address_len = s.len;
        target.ipv6 = false;
    } else if (family == posix.AF.INET6) {
        const in6: *const posix.sockaddr.in6 = @ptrCast(@alignCast(&storage));
        var w: usize = 0;
        for (0..8) |i| {
            const group = std.mem.readInt(u16, in6.addr[i * 2 ..][0..2], .big);
            const s = try std.fmt.bufPrint(target.address[w..], "{s}{x}", .{ if (i == 0) "" else ":", group });
            w += s.len;
        }
        target.address_len = w;
        target.ipv6 = true;
    } else {
        return error.UnsupportedAddressFamily;
    }
}

/// One test, over one transport. `proto` is fixed at comptime because the
/// event loop's handler protocol is.
fn Runner(comptime proto: event_loop.Protocol) type {
    return struct {
        const P = Peer(proto);
        const C = event_loop.Client(P);
        const MAX_LEGS = 5;

        const Leg = struct {
            peer: P = .{},
            client: ?C = null,
            start_at_ms: i64 = 0,
            started: bool = false,

            fn tick(self: *Leg) void {
                if (self.client) |*c| c.tick() catch {};
            }
            /// Cancels the leg's requests now, mid-test.
            fn withdraw(self: *Leg) void {
                if (self.client) |*c| {
                    var cs = c.clientSession();
                    self.peer.withdraw(&cs);
                }
            }
            fn pump(self: *Leg) void {
                if (self.client) |*c| {
                    var cs = c.clientSession();
                    self.peer.pumpData(&cs);
                }
            }
            fn deinit(self: *Leg) void {
                if (self.client) |*c| {
                    var cs = c.clientSession();
                    self.peer.withdraw(&cs);
                    c.flush(); // the withdrawal goes out ahead of CONNECTION_CLOSE
                    c.stop();
                    for (0..20) |_| c.tick() catch break;
                    c.deinit();
                    self.client = null;
                }
            }
        };

        fn makeConfig(target: *const Target, connect_headers: []const qpack.Header, alpns: []const []const u8) event_loop.ClientConfig {
            return .{
                .address = target.addressSlice(),
                .port = target.locator.port,
                .server_name = moq_url.bareHost(target.locator.host),
                .path = target.locator.path,
                .ipv6 = target.ipv6,
                .alpns = if (proto == .quic) alpns else &.{},
                .skip_cert_verify = target.tls_disable_verify,
                .connect_headers = connect_headers,
            };
        }

        fn run(
            alloc: std.mem.Allocator,
            target: *const Target,
            case: TestCase,
            result: *Result,
        ) void {
            // Offered on the CONNECT for WebTransport; for raw QUIC the
            // ALPN carries the same information.
            var offer_buf: [128]u8 = undefined;
            var alpn_buf: [4][]const u8 = undefined;
            const alpns = moq_version.alpnOffer(target.drafts, &alpn_buf);
            const offer = wt_protocol.encodeList(alpns, &offer_buf) catch "";
            const connect_headers = [_]qpack.Header{
                .{ .name = wt_protocol.HEADER_AVAILABLE, .value = offer },
            };
            const cfg_headers: []const qpack.Header =
                if (proto == .webtransport) &connect_headers else &.{};

            // A session is half a megabyte of stream buffers: five legs
            // don't belong on the stack.
            const legs_all = std.heap.page_allocator.alloc(Leg, MAX_LEGS) catch {
                result.setMsg("out of memory", .{});
                return;
            };
            defer std.heap.page_allocator.free(legs_all);
            for (legs_all) |*l| l.* = .{};
            var leg_count: usize = 1;
            const legs = legs_all;
            const start = nowMs();

            // Unique per run, so state another run left at the relay can't
            // satisfy this one (data-plane "Test Identity").
            var run_bytes: [16]u8 = undefined;
            sys.randomBytes(&run_bytes);
            const run_hex = std.fmt.bytesToHex(run_bytes, .lower);
            const run_id: []const u8 = &run_hex;

            const lc_ns = [_][]const u8{ "moq-test", "interop", "subscribe-namespace-lifecycle", run_id };
            const rt_prefix = [_][]const u8{ "moq-test", "multi-publisher-retention", run_id };
            const rt_shared = rt_prefix ++ [_][]const u8{"shared"};
            const rt_sync = rt_prefix ++ [_][]const u8{"sync"};
            const dp_prefix = [_][]const u8{ "moq-test", "data-subgroup-basic", run_id };
            const dp_full = dp_prefix ++ DP_TUPLE;
            var dp: DataPlane = .{ .full_ns = &dp_full };

            switch (case) {
                .setup_only => legs[0].peer.role = .idle,
                .announce_only => legs[0].peer.role = .publisher,
                .publish_namespace_done => {
                    legs[0].peer.role = .publisher;
                    legs[0].peer.cancel_after_ok = true;
                },
                .subscribe_error => {
                    legs[0].peer.role = .subscriber;
                    legs[0].peer.subscribe_namespace = &MISSING_NAMESPACE;
                },
                .rendezvous_timeout => {
                    legs[0].peer.role = .subscriber;
                    legs[0].peer.subscribe_namespace = &RENDEZVOUS_NAMESPACE;
                    legs[0].peer.rendezvous_timeout_ms = 500;
                },
                .announce_subscribe => {
                    legs[0].peer.role = .publisher;
                    legs[1].peer.role = .subscriber;
                    leg_count = 2;
                },
                .subscribe_before_announce => {
                    legs[0].peer.role = .subscriber;
                    legs[1].peer.role = .publisher;
                    legs[1].start_at_ms = 500; // the spec's only hard offset
                    leg_count = 2;
                },
                .subscribe_namespace_lifecycle => {
                    legs[0].peer.role = .ns_subscriber;
                    legs[0].peer.ns_prefix = &lc_ns;
                    legs[1].peer.role = .publisher;
                    legs[1].peer.publish_ns = &lc_ns;
                    leg_count = 2;
                },
                .publish_namespace_multi_publisher_retention => {
                    // observer, first publisher, duplicate publisher, and
                    // the two late subscribers the retention is for.
                    legs[0].peer.role = .ns_subscriber;
                    legs[0].peer.ns_prefix = &rt_prefix;
                    legs[1].peer.role = .publisher;
                    legs[1].peer.publish_ns = &rt_shared;
                    legs[2].peer.role = .publisher;
                    legs[2].peer.publish_ns = &rt_shared;
                    legs[2].peer.extra_publish_ns = &rt_sync;
                    for (legs[3..5]) |*l| {
                        l.peer.role = .ns_subscriber;
                        l.peer.ns_prefix = &rt_prefix;
                    }
                    leg_count = 5;
                },
                .data_subgroup_basic => {
                    legs[0].peer.role = .publisher;
                    legs[0].peer.publish_ns = &dp_prefix;
                    legs[0].peer.dp = &dp;
                    legs[1].peer.role = .subscriber;
                    legs[1].peer.subscribe_namespace = &dp_full;
                    legs[1].peer.subscribe_track = DP_TRACK;
                    legs[1].peer.bare_subscribe = true;
                    legs[1].peer.dp = &dp;
                    leg_count = 2;
                },
            }

            for (legs[0..leg_count]) |*l| {
                l.peer.verbose = target.verbose;
                l.peer.draft = target.drafts[0];
                l.peer.prepare(target);
            }
            defer for (legs[0..leg_count]) |*l| l.deinit();

            const deadline = start + case.timeoutMs();
            var done = false;

            while (nowMs() < deadline and !done) {
                for (legs[0..leg_count], 0..) |*l, i| {
                    if (!l.started and nowMs() - start >= l.start_at_ms and canStart(case, i, legs)) {
                        l.client = C.init(alloc, &l.peer, makeConfig(target, cfg_headers, alpns)) catch |e| {
                            result.outcome = .fail;
                            result.setMsg("connect failed: {t}", .{e});
                            return;
                        };
                        l.started = true;
                    }
                    l.tick();
                }
                advance(case, legs[0..leg_count]);
                done = complete(case, legs[0..leg_count]);
            }

            result.duration_ms = nowMs() - start;
            result.setNegotiated(legs[0].peer.negotiatedSlice());

            for (legs[0..leg_count]) |*l| {
                if (l.peer.failed) {
                    result.outcome = .fail;
                    result.setMsg("{s}", .{l.peer.fail_reason[0..l.peer.fail_reason_len]});
                    return;
                }
            }
            judge(case, legs[0..leg_count], result);
        }

        /// Multi-leg cases sequence on what earlier legs have seen, not on
        /// timers.
        fn canStart(case: TestCase, i: usize, legs: []Leg) bool {
            const a = &legs[0].peer;
            return switch (case) {
                // The subscriber only starts once the publisher's
                // announcement has been acknowledged.
                .announce_subscribe, .data_subgroup_basic => i == 0 or a.got_request_ok,
                .subscribe_namespace_lifecycle => i == 0 or a.got_request_ok,
                .publish_namespace_multi_publisher_retention => switch (i) {
                    0 => true,
                    1 => a.got_request_ok,
                    2 => a.nsIndex(false, "shared/") != null,
                    else => a.nsIndex(true, "sync/") != null,
                },
                else => true,
            };
        }

        /// The withdrawals and data the scenario drives between ticks.
        fn advance(case: TestCase, legs: []Leg) void {
            const a = &legs[0].peer;
            switch (case) {
                .subscribe_namespace_lifecycle => {
                    const p = &legs[1];
                    if (!p.peer.cancelled and a.nsIndex(false, "") != null) p.withdraw();
                },
                .publish_namespace_multi_publisher_retention => {
                    // The duplicate withdraws once the observer has seen
                    // both of its namespaces; the first publisher once
                    // both late subscribers found what it kept alive.
                    if (!legs[2].peer.cancelled and a.nsIndex(false, "sync/") != null) legs[2].withdraw();
                    if (!legs[1].peer.cancelled and
                        legs[3].peer.nsIndex(false, "shared/") != null and
                        legs[4].peer.nsIndex(false, "shared/") != null) legs[1].withdraw();
                },
                .data_subgroup_basic => legs[0].pump(),
                else => {},
            }
        }

        /// True once the outcome can no longer change, so a passing test
        /// does not burn its whole timeout.
        fn complete(case: TestCase, legs: []Leg) bool {
            for (legs) |*l| if (l.peer.failed) return true;
            const a = &legs[0].peer;
            return switch (case) {
                .setup_only => a.sess.setup_received,
                .announce_only => a.got_request_ok or a.got_request_error,
                .publish_namespace_done => a.cancelled or a.got_request_error,
                .subscribe_error, .rendezvous_timeout => a.got_request_error or a.got_subscribe_ok,
                .announce_subscribe => legs[1].peer.got_subscribe_ok or legs[1].peer.got_request_error,
                .subscribe_before_announce => a.got_subscribe_ok or a.got_request_error,
                .subscribe_namespace_lifecycle => a.got_request_error or a.nsIndex(true, "") != null,
                .publish_namespace_multi_publisher_retention => a.got_request_error or
                    (legs[3].peer.nsIndex(true, "shared/") != null and legs[4].peer.nsIndex(true, "shared/") != null),
                .data_subgroup_basic => legs[1].peer.got_request_error or legs[1].peer.dp.?.drained(),
            };
        }

        fn judge(case: TestCase, legs: []Leg, result: *Result) void {
            const a = &legs[0].peer;
            switch (case) {
                .setup_only => {
                    if (!a.sess.setup_sent) {
                        result.outcome = .fail;
                        result.setMsg("never sent SETUP (no connection)", .{});
                    } else if (!a.sess.setup_received) {
                        result.outcome = .fail;
                        result.setMsg("no SETUP from peer", .{});
                    } else {
                        result.outcome = .pass;
                    }
                },
                .announce_only, .publish_namespace_done => {
                    if (a.got_request_ok) {
                        result.outcome = .pass;
                    } else if (a.got_request_error) {
                        result.outcome = .fail;
                        result.setMsg("PUBLISH_NAMESPACE rejected: code={d} {s}", .{
                            a.error_code, a.error_reason[0..a.error_reason_len],
                        });
                    } else if (!a.sess.setup_received) {
                        result.outcome = .fail;
                        result.setMsg("no SETUP from peer", .{});
                    } else {
                        result.outcome = .fail;
                        result.setMsg("no REQUEST_OK for PUBLISH_NAMESPACE", .{});
                    }
                },
                .subscribe_error => {
                    if (a.got_request_error) {
                        result.outcome = .pass;
                    } else if (a.got_subscribe_ok) {
                        result.outcome = .fail;
                        result.setMsg("received SUBSCRIBE_OK instead of REQUEST_ERROR", .{});
                    } else if (!a.sess.setup_received) {
                        result.outcome = .fail;
                        result.setMsg("no SETUP from peer", .{});
                    } else {
                        result.outcome = .fail;
                        result.setMsg("no response to SUBSCRIBE", .{});
                    }
                },
                .rendezvous_timeout => {
                    if (a.got_request_error) {
                        if (a.error_code == moq_codes.ERR_TIMEOUT) {
                            result.outcome = .pass;
                        } else {
                            // The relay answered, but not the way §9.3.4 says.
                            result.outcome = .fail;
                            result.setMsg("REQUEST_ERROR code={d}, expected TIMEOUT ({d})", .{
                                a.error_code, moq_codes.ERR_TIMEOUT,
                            });
                        }
                    } else if (a.got_subscribe_ok) {
                        result.outcome = .fail;
                        result.setMsg("received SUBSCRIBE_OK instead of REQUEST_ERROR", .{});
                    } else if (!a.sess.setup_received) {
                        result.outcome = .fail;
                        result.setMsg("no SETUP from peer", .{});
                    } else {
                        result.outcome = .fail;
                        result.setMsg("relay never timed out the rendezvous", .{});
                    }
                },
                .announce_subscribe => {
                    const sub = &legs[1].peer;
                    if (!a.got_request_ok) {
                        result.outcome = .fail;
                        result.setMsg("publisher never got REQUEST_OK", .{});
                    } else if (sub.got_subscribe_ok) {
                        result.outcome = .pass;
                    } else if (sub.got_request_error) {
                        result.outcome = .fail;
                        result.setMsg("relay did not route the subscription: code={d}", .{sub.error_code});
                    } else {
                        result.outcome = .fail;
                        result.setMsg("subscriber got no response", .{});
                    }
                },
                .subscribe_before_announce => {
                    // The spec accepts either: a relay may buffer the
                    // pending subscription or reject it outright.
                    if (a.got_subscribe_ok or a.got_request_error) {
                        result.outcome = .pass;
                        if (a.got_request_error) result.setMsg("rejected pending subscription (allowed)", .{});
                    } else if (!a.sess.setup_received) {
                        result.outcome = .fail;
                        result.setMsg("no SETUP from peer", .{});
                    } else {
                        result.outcome = .fail;
                        result.setMsg("subscriber got no response", .{});
                    }
                },
                .subscribe_namespace_lifecycle => judgeLifecycle(legs, result),
                .publish_namespace_multi_publisher_retention => judgeRetention(legs, result),
                .data_subgroup_basic => judgeData(legs, result),
            }
        }

        fn judgeLifecycle(legs: []Leg, result: *Result) void {
            const a = &legs[0].peer;
            result.outcome = .fail;
            const seen = a.nsIndex(false, "");
            const gone = a.nsIndex(true, "");
            if (a.got_request_error) {
                result.setMsg("SUBSCRIBE_NAMESPACE rejected: code={d}", .{a.error_code});
            } else if (!a.got_request_ok) {
                result.setMsg("no REQUEST_OK for SUBSCRIBE_NAMESPACE", .{});
            } else if (!legs[1].peer.got_request_ok) {
                result.setMsg("publisher never got REQUEST_OK", .{});
            } else if (seen == null) {
                result.setMsg("no NAMESPACE after the publisher announced", .{});
            } else if (gone == null) {
                result.setMsg("no NAMESPACE_DONE after the publisher withdrew", .{});
            } else if (gone.? < seen.?) {
                result.setMsg("NAMESPACE_DONE arrived before NAMESPACE", .{});
            } else {
                result.outcome = .pass;
            }
        }

        fn judgeRetention(legs: []Leg, result: *Result) void {
            const a = &legs[0].peer;
            result.outcome = .fail;
            if (a.got_request_error) return result.setMsg("observer's SUBSCRIBE_NAMESPACE rejected: code={d}", .{a.error_code});
            if (a.nsIndex(false, "shared/") == null) return result.setMsg("observer never saw the first publisher's NAMESPACE", .{});
            if (a.nsIndex(false, "sync/") == null) return result.setMsg("observer never saw the duplicate publisher's sync NAMESPACE", .{});
            if (a.nsIndex(true, "sync/") == null) return result.setMsg("no NAMESPACE_DONE for sync after the duplicate withdrew", .{});
            for (legs[3..5], 1..) |*l, n| {
                const p = &l.peer;
                if (p.got_request_error) return result.setMsg("subscriber {d}'s SUBSCRIBE_NAMESPACE rejected: code={d}", .{ n, p.error_code });
                if (p.nsIndex(false, "shared/") == null) return result.setMsg("subscriber {d} never discovered the retained namespace", .{n});
                if (p.nsIndex(true, "shared/") == null) return result.setMsg("subscriber {d} saw no NAMESPACE_DONE after the last publisher left", .{n});
            }
            result.outcome = .pass;
        }

        fn judgeData(legs: []Leg, result: *Result) void {
            const sub = &legs[1].peer;
            const dp = sub.dp.?;
            result.outcome = .fail;
            if (!legs[0].peer.got_request_ok) return result.setMsg("publisher never got REQUEST_OK", .{});
            if (sub.got_request_error) return result.setMsg("SUBSCRIBE rejected: code={d}", .{sub.error_code});
            if (!dp.upstream_seen) return result.setMsg("no upstream SUBSCRIBE reached the publisher", .{});
            if (!dp.upstream_ns_ok) return result.setMsg("upstream SUBSCRIBE did not carry the 19-field namespace", .{});
            if (!sub.got_subscribe_ok) return result.setMsg("no SUBSCRIBE_OK downstream", .{});
            if (dp.overflow > 0) return result.setMsg("{d} more objects than the scenario sends", .{dp.objects_len + dp.overflow});

            var seen: [DP_GROUPS][DP_PER_GROUP]bool = @splat(@splat(false));
            var data: usize = 0;
            for (dp.objects[0..dp.objects_len]) |o| {
                // Status objects (End of Group, End of Track) aren't data
                // objects; the data-plane conventions leave their placement open.
                if (o.status != 0) continue;
                data += 1;
                if (o.group >= DP_GROUPS or o.id >= DP_PER_GROUP) return result.setMsg("unexpected object ({d}, {d})", .{ o.group, o.id });
                const slot = &seen[@intCast(o.group)][@intCast(o.id)];
                if (slot.*) return result.setMsg("duplicate object ({d}, {d})", .{ o.group, o.id });
                slot.* = true;
                if (o.subgroup != 0) return result.setMsg("object ({d}, {d}) on subgroup {d}", .{ o.group, o.id, o.subgroup });
                if (o.priority != DP_PRIORITY) return result.setMsg("object ({d}, {d}) priority {d}", .{ o.group, o.id, o.priority });
                if (o.len != dpSize(o.id)) return result.setMsg("object ({d}, {d}) is {d} bytes, expected {d}", .{ o.group, o.id, o.len, dpSize(o.id) });
                if (!o.bytes_ok) return result.setMsg("object ({d}, {d}) payload corrupt", .{ o.group, o.id });
                if (dp.sub_alias) |al| if (o.alias != al) return result.setMsg("object ({d}, {d}) on alias {d}, SUBSCRIBE_OK said {d}", .{ o.group, o.id, o.alias, al });
            }
            var missing: usize = 0;
            var first: ?[2]usize = null;
            for (seen, 0..) |row, g| for (row, 0..) |got, o| if (!got) {
                missing += 1;
                if (first == null) first = .{ g, o };
            };
            if (first) |f| return result.setMsg("missing {d} objects, first ({d}, {d})", .{ missing, f[0], f[1] });
            if (!dp.got_done) return result.setMsg("all objects arrived but no PUBLISH_DONE", .{});
            if (dp.done_status != moq_codes.DONE_TRACK_ENDED) return result.setMsg("PUBLISH_DONE status {d}, expected TRACK_ENDED", .{dp.done_status});
            result.outcome = .pass;
            result.setMsg("{d} objects, PUBLISH_DONE TRACK_ENDED, Stream Count {d}", .{ data, dp.done_count });
        }
    };
}

// ─────────────────────────────────────────────────────────────────────
// TAP 14 output and main
// ─────────────────────────────────────────────────────────────────────

// TAP goes to stdout and nothing else does — the runner parses it.
// Diagnostics go through std.debug.print, which is stderr.
fn out(comptime fmt: []const u8, args: anytype) void {
    var buf: [512]u8 = undefined;
    const s = std.fmt.bufPrint(&buf, fmt, args) catch return;
    sys.stdout().writeAll(s) catch {};
}

fn reportTap(
    index: usize,
    case: TestCase,
    r: *const Result,
    relay_url: []const u8,
) void {
    switch (r.outcome) {
        .pass => out("ok {d} - {s}\n", .{ index, case.name() }),
        .skip => {
            out("ok {d} - {s} # SKIP {s}\n", .{ index, case.name(), r.message() });
            return;
        },
        .fail => out("not ok {d} - {s}\n", .{ index, case.name() }),
    }

    // YAML diagnostics, indented two spaces relative to the test point.
    out("  ---\n", .{});
    out("  duration_ms: {d}\n", .{r.duration_ms});
    if (r.msg_len > 0) out("  message: \"{s}\"\n", .{r.message()});
    out("  implementation_version: \"quic-zig/{s}\"\n", .{VERSION});
    if (case.specRevision()) |rev| out("  test_spec_revision: {d}\n", .{rev});
    if (r.negotiated_len > 0) {
        out("  sessions:\n", .{});
        out("    client:\n", .{});
        out("      moqt_version: \"{s}\"\n", .{r.negotiatedSlice()});
        out("      transport: \"{s}\"\n", .{
            if (std.mem.startsWith(u8, relay_url, "moqt://")) "quic" else "webtransport-h3",
        });
    }
    out("  ...\n", .{});
}

fn envFlag(name: [*:0]const u8) bool {
    const v = sys.getenv(name) orelse return false;
    return std.mem.eql(u8, v, "1") or std.ascii.eqlIgnoreCase(v, "true");
}

pub fn main(init: std.process.Init.Minimal) !u8 {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    var relay_url: []const u8 = sys.getenv("RELAY_URL") orelse "https://localhost:4443";
    var only: ?[]const u8 = sys.getenv("TESTCASE");
    var list = false;
    var verbose = envFlag("VERBOSE");
    var tls_disable_verify = envFlag("TLS_DISABLE_VERIFY");
    var only_draft: [1]moq_version.Draft = undefined;
    var drafts: []const moq_version.Draft = moq_version.PREFERRED;

    var args = sys.argsIterator(init.args);
    _ = args.next();
    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--relay") or std.mem.eql(u8, arg, "-r")) {
            if (args.next()) |v| relay_url = v;
        } else if (std.mem.eql(u8, arg, "--test") or std.mem.eql(u8, arg, "-t")) {
            if (args.next()) |v| only = v;
        } else if (std.mem.eql(u8, arg, "--list") or std.mem.eql(u8, arg, "-l")) {
            list = true;
        } else if (std.mem.eql(u8, arg, "--verbose") or std.mem.eql(u8, arg, "-v")) {
            verbose = true;
        } else if (std.mem.eql(u8, arg, "--draft")) {
            if (args.next()) |v| {
                const n = std.fmt.parseInt(u8, v, 10) catch 0;
                only_draft[0] = switch (n) {
                    17 => .draft_17,
                    18 => .draft_18,
                    22 => .draft_22,
                    else => {
                        std.debug.print("unknown draft: {s} (17, 18 or 22)\n", .{v});
                        return 127;
                    },
                };
                drafts = &only_draft;
            }
        } else if (std.mem.eql(u8, arg, "--tls-disable-verify")) {
            tls_disable_verify = true;
        } else if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) {
            out("moq-test-client [--relay URL] [--test NAME] [--list] [--verbose]\n" ++
                "                [--tls-disable-verify] [--draft 17|18|22]\n", .{});
            return 0;
        }
    }

    // --list is a plain identifier per line, not TAP.
    if (list) {
        for (ALL_TESTS) |c| out("{s}\n", .{c.name()});
        return 0;
    }

    // An empty TESTCASE from the runner means "all", not a name to match.
    if (only) |o| {
        if (o.len == 0) only = null;
    }

    var selected: [ALL_TESTS.len]TestCase = undefined;
    var selected_len: usize = 0;
    if (only) |name| {
        const c = TestCase.fromName(name) orelse {
            std.debug.print("unknown test case: {s}\n", .{name});
            return 127;
        };
        selected[0] = c;
        selected_len = 1;
    } else {
        for (ALL_TESTS, 0..) |c, i| selected[i] = c;
        selected_len = ALL_TESTS.len;
    }

    var target = Target{
        .locator = moq_url.parse(relay_url) catch |e| {
            out("TAP version 14\n", .{});
            out("Bail out! bad RELAY_URL {s}: {t}\n", .{ relay_url, e });
            return 1;
        },
        .tls_disable_verify = tls_disable_verify,
        .verbose = verbose,
        .drafts = drafts,
    };
    if (std.fmt.bufPrint(&target.authority, "{s}:{d}", .{ target.locator.host, target.locator.port })) |a| {
        target.authority_len = a.len;
    } else |_| {}
    resolve(&target) catch |e| {
        out("TAP version 14\n", .{});
        out("Bail out! cannot resolve {s}: {t}\n", .{ target.locator.host, e });
        return 1;
    };

    out("TAP version 14\n", .{});
    out("# moq-test-client v{s}\n", .{VERSION});
    out("# Relay: {s}\n", .{relay_url});
    for (drafts, 0..) |d, i| out("{s}draft-{d}", .{ if (i == 0) "# Offered: " else ", ", d.number() });
    out("\n", .{});
    out("1..{d}\n", .{selected_len});

    var failures: usize = 0;
    for (selected[0..selected_len], 1..) |case, i| {
        var r = Result{};

        switch (target.locator.defaultTransport()) {
            .quic => Runner(.quic).run(alloc, &target, case, &r),
            .webtransport => Runner(.webtransport).run(alloc, &target, case, &r),
        }

        if (r.outcome == .fail) failures += 1;
        reportTap(i, case, &r, relay_url);
    }

    return if (failures == 0) 0 else 1;
}
