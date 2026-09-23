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

    fn name(self: TestCase) []const u8 {
        return switch (self) {
            .setup_only => "setup-only",
            .announce_only => "announce-only",
            .publish_namespace_done => "publish-namespace-done",
            .subscribe_error => "subscribe-error",
            .rendezvous_timeout => "rendezvous-timeout",
            .announce_subscribe => "announce-subscribe",
            .subscribe_before_announce => "subscribe-before-announce",
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
            else => 2000,
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

const Role = enum { idle, publisher, subscriber };

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
            if (is_wt) {
                cs.resetStream(stream_id, @truncate(code));
            } else if (cs.conn.streams.getStream(stream_id)) |s| {
                s.send.reset(code);
            }
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
                    if (moq_version.Draft.fromAlpn(v)) |d| self.draft = d;
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

        fn setNegotiatedFromAlpn(self: *Self) void {
            // Raw QUIC negotiates the MoQT version with the QUIC ALPN, which
            // is what we asked for; record it so the YAML block can report it.
            self.setNegotiated(self.draft.alpn());
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
                    self.note("SUBSCRIBE_OK alias={d}", .{r.ok.track_alias});
                },
                .subscribe => |r| {
                    // A relay routes a subscription by asking the namespace's
                    // publisher for the track. announce-subscribe only
                    // completes if we answer.
                    if (self.role != .publisher) return;
                    var buf: [128]u8 = undefined;
                    var fbs = io_compat.fixedBufferStream(&buf);
                    moq_msg.writeSubscribeOk(&fbs, .{ .track_alias = 1 }) catch return;
                    self.sess.transport.write(r.stream_id, buf[0..fbs.seek]) catch return;
                    self.served_subscribe = true;
                    self.note("served a SUBSCRIBE on stream {d}", .{r.stream_id});
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
                    .track_namespace = &TEST_NAMESPACE,
                }, self.draft) catch return,
                .subscriber => moq_msg.writeSubscribe(&fbs, .{
                    .track_namespace = self.subscribe_namespace,
                    .track_name = TEST_TRACK,
                    .rendezvous_timeout_ms = self.rendezvous_timeout_ms,
                }, self.draft) catch return,
                .idle => unreachable,
            }
            self.request_sid = self.sess.sendRequest(buf[0..fbs.seek]) catch |e| {
                self.fail("could not send request: {t}", .{e});
                return;
            };
            self.note("{s} request on stream {d}", .{ @tagName(self.role), self.request_sid.? });
        }

        /// Cancels a still-open announcement or subscription, so a relay that
        /// is slow to notice the close does not carry it into the next test.
        pub fn withdraw(self: *Self, cs: *event_loop.ClientSession) void {
            const sid = self.request_sid orelse return;
            if (self.cancelled or self.failed) return;
            self.cur = cs;
            defer self.cur = null;
            self.sess.cancelRequest(sid, moq_session.ResetCode.CANCELLED);
            self.cancelled = true;
        }

    };
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
    /// One draft per run. The runner has no way to ask for a version, so
    /// this is a flag rather than something it controls.
    draft: moq_version.Draft = moq_version.DEFAULT,
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

        const Leg = struct {
            peer: P = .{},
            client: ?C = null,
            start_at_ms: i64 = 0,
            started: bool = false,

            fn tick(self: *Leg) void {
                if (self.client) |*c| c.tick() catch {};
            }
            fn deinit(self: *Leg) void {
                if (self.client) |*c| {
                    var cs = c.clientSession();
                    self.peer.withdraw(&cs);
                    c.stop();
                    for (0..20) |_| c.tick() catch break;
                    c.deinit();
                    self.client = null;
                }
            }
        };

        fn makeConfig(target: *const Target, connect_headers: []const qpack.Header) event_loop.ClientConfig {
            return .{
                .address = target.addressSlice(),
                .port = target.locator.port,
                .server_name = moq_url.bareHost(target.locator.host),
                .path = target.locator.path,
                .ipv6 = target.ipv6,
                .alpn = if (proto == .quic) target.draft.alpn() else null,
                .skip_cert_verify = target.tls_disable_verify,
                .ca = if (target.tls_disable_verify) .none else .system,
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
            const one = [_]moq_version.Draft{target.draft};
            const alpns = moq_version.alpnOffer(&one, &alpn_buf);
            const offer = wt_protocol.encodeList(alpns, &offer_buf) catch "";
            const connect_headers = [_]qpack.Header{
                .{ .name = wt_protocol.HEADER_AVAILABLE, .value = offer },
            };
            const cfg_headers: []const qpack.Header =
                if (proto == .webtransport) &connect_headers else &.{};

            var legs: [2]Leg = .{ .{}, .{} };
            var leg_count: usize = 1;
            const start = nowMs();

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
            }

            for (legs[0..leg_count]) |*l| {
                l.peer.verbose = target.verbose;
                l.peer.draft = target.draft;
                l.peer.prepare(target);
            }
            defer for (legs[0..leg_count]) |*l| l.deinit();

            const deadline = start + case.timeoutMs();
            var done = false;

            while (nowMs() < deadline and !done) {
                for (legs[0..leg_count], 0..) |*l, i| {
                    if (!l.started and nowMs() - start >= l.start_at_ms) {
                        // announce-subscribe sequences on state, not a
                        // timer: the subscriber only starts once the
                        // publisher's announcement has been acknowledged.
                        if (case == .announce_subscribe and i == 1 and !legs[0].peer.got_request_ok) {
                            continue;
                        }
                        l.client = C.init(alloc, &l.peer, makeConfig(target, cfg_headers)) catch |e| {
                            result.outcome = .fail;
                            result.setMsg("connect failed: {t}", .{e});
                            return;
                        };
                        l.started = true;
                    }
                    l.tick();
                }
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

        /// True once the outcome can no longer change, so a passing test
        /// does not burn its whole timeout.
        fn complete(case: TestCase, legs: []Leg) bool {
            const a = &legs[0].peer;
            return switch (case) {
                .setup_only => a.sess.setup_received,
                .announce_only => a.got_request_ok or a.got_request_error,
                .publish_namespace_done => a.cancelled or a.got_request_error,
                .subscribe_error, .rendezvous_timeout => a.got_request_error or a.got_subscribe_ok,
                .announce_subscribe => legs[1].peer.got_subscribe_ok or legs[1].peer.got_request_error,
                .subscribe_before_announce => a.got_subscribe_ok or a.got_request_error,
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
            }
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
    (sys.File{ .fd = 1 }).writeAll(s) catch {};
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
    var draft: moq_version.Draft = moq_version.DEFAULT;

    var args = std.process.Args.Iterator.init(init.args);
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
                draft = switch (n) {
                    17 => .draft_17,
                    18 => .draft_18,
                    else => {
                        std.debug.print("unknown draft: {s} (17 or 18)\n", .{v});
                        return 127;
                    },
                };
            }
        } else if (std.mem.eql(u8, arg, "--tls-disable-verify")) {
            tls_disable_verify = true;
        } else if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) {
            out("moq-test-client [--relay URL] [--test NAME] [--list] [--verbose]\n" ++
                "                [--tls-disable-verify] [--draft 17|18]\n", .{});
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
        .draft = draft,
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
    out("# Draft: draft-{d}\n", .{draft.number()});
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
