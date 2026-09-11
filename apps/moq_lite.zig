// moq-lite client — draft-lcurley-moq-lite-05.
//
//   moq-lite publish   --url <URL> --broadcast <path> [--track <name>]
//   moq-lite subscribe --url <URL> --broadcast <path> [--track <name>]
//   moq-lite announce  --url <URL> [--prefix <path>]
//   moq-lite serve     --port <N>  --broadcast <path> [--track <name>]
//
// `serve` is an origin, not a relay: it publishes one synthetic track to
// whoever subscribes. It exists so a subscriber has something to talk to
// without a relay in the middle, ours or moq-rs's.
//
// The URL scheme picks the transport: https:// is WebTransport, moqt:// is
// native QUIC. Shaped to cross directly with moq-rs's `moq-clock`, which
// publishes one group per minute whose frames are the seconds.

const std = @import("std");
const posix = std.posix;
const quic = @import("quic");
const io_compat = quic.io_compat;
const sys = quic.sys;
const event_loop = quic.event_loop;
const qpack = quic.qpack;
const wt_protocol = quic.webtransport_protocol;

const lite = quic.moq.lite;
const lite_msg = lite.message;
const lite_session = lite.session;
const lite_version = lite.version;
const moq_url = quic.moq.url;

pub const std_options: std.Options = .{ .log_level = .err };

const Mode = enum { publish, subscribe, announce, serve };

fn nowMs() i64 {
    return @intCast(@divFloor(sys.nanoTimestamp(), 1_000_000));
}

fn print(comptime fmt: []const u8, args: anytype) void {
    std.debug.print(fmt, args);
}

// ─────────────────────────────────────────────────────────────────────
// Peer — event_loop handler and moq-lite transport in one type, so the
// session does not need a back-pointer fixed up on every callback.
// ─────────────────────────────────────────────────────────────────────

fn Peer(comptime proto: event_loop.Protocol) type {
    return struct {
        const Self = @This();
        pub const protocol: event_loop.Protocol = proto;
        /// Publishers have their own tick to keep; the loop otherwise only
        /// wakes on peer traffic.
        pub const poll_interval_ms: u64 = 100;
        const Sess = lite_session.Session(*Self);
        const is_wt = proto == .webtransport;

        sess: Sess = undefined,
        mode: Mode = .subscribe,
        broadcast: []const u8 = "",
        track: []const u8 = "clock",
        prefix: []const u8 = "",

        cur: ?*event_loop.ClientSession = null,
        wt_session_id: u64 = 0,
        started: bool = false,

        // Subscriber state.
        subscribe_stream: ?u64 = null,
        subscribe_id: u64 = 0,
        frames: lite_session.FrameReader = undefined,
        frame_buf: [256 * 1024]u8 = undefined,
        groups_seen: u64 = 0,
        frames_seen: u64 = 0,

        // Publisher state: one group per tick, frames within it.
        announce_stream: ?u64 = null,
        subscriber_stream: ?u64 = null,
        subscriber_id: u64 = 0,
        group_stream: ?u64 = null,
        group_seq: u64 = 0,
        frame_in_group: u64 = 0,
        last_tick_ms: i64 = 0,

        // --- transport seam ------------------------------------------

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

        // --- lifecycle -----------------------------------------------

        pub fn prepare(self: *Self, path: ?[]const u8) void {
            self.sess = Sess.init(self);
            // §7.2.1: PATH is for bindings with no request URI. Over
            // WebTransport the CONNECT already carried it.
            self.sess.path = if (is_wt) null else path;
            self.frames = lite_session.FrameReader.init(&self.frame_buf);
        }

        pub fn onConnected(self: *Self, cs: *event_loop.ClientSession) void {
            if (is_wt) return;
            self.cur = cs;
            defer self.cur = null;
            self.begin();
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
            if (wt_protocol.findHeader(headers, wt_protocol.HEADER_SELECTED)) |raw| {
                var scratch: [64]u8 = undefined;
                if (wt_protocol.decodeItem(raw, &scratch)) |v| {
                    print("negotiated: {s}\n", .{v});
                } else |_| {}
            }
            self.begin();
        }

        fn begin(self: *Self) void {
            if (self.started) return;
            self.started = true;
            self.sess.sendSetup() catch |e| {
                print("SETUP failed: {t}\n", .{e});
                return;
            };
            switch (self.mode) {
                .subscribe => {
                    const opened = self.sess.openSubscribe(.{
                        .broadcast = self.broadcast,
                        .track = self.track,
                        .ordered = true,
                    }) catch |e| {
                        print("SUBSCRIBE failed: {t}\n", .{e});
                        return;
                    };
                    self.subscribe_stream = opened.stream_id;
                    self.subscribe_id = opened.id;
                    print("subscribed to {s}/{s} (id {d})\n", .{ self.broadcast, self.track, opened.id });
                },
                .announce => {
                    self.announce_stream = self.sess.openAnnounce(.{ .prefix = self.prefix }) catch |e| {
                        print("ANNOUNCE_REQUEST failed: {t}\n", .{e});
                        return;
                    };
                    print("watching for broadcasts under \"{s}\"\n", .{self.prefix});
                },
                .publish => {
                    // A publisher waits to be asked: it answers the peer's
                    // announce stream, then serves the subscribe it brings.
                    print("publishing {s}/{s}\n", .{ self.broadcast, self.track });
                },
                .serve => unreachable, // serve runs the Server handler, not this
            }
        }

        pub fn onBidiStream(self: *Self, _: *event_loop.ClientSession, _: u64, stream_id: u64) void {
            self.sess.onPeerStream(stream_id, true) catch {};
        }

        pub fn onUniStream(self: *Self, _: *event_loop.ClientSession, _: u64, stream_id: u64) void {
            self.sess.onPeerStream(stream_id, false) catch {};
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

            var events: [16]lite_session.Event = undefined;
            const n = self.sess.onStreamData(stream_id, data, fin, &events) catch |e| {
                print("stream {d}: {t}\n", .{ stream_id, e });
                return;
            };
            for (events[0..n]) |ev| self.handle(ev);
        }

        fn handle(self: *Self, ev: lite_session.Event) void {
            switch (ev) {
                .peer_setup => |p| {
                    print("peer SETUP (probe={?})\n", .{p.setup.probe});
                },
                .announce_ok => |a| print("announce stream open (hop {d}, {d} active)\n", .{
                    a.ok.hop_id, a.ok.active_count,
                }),
                .announce_broadcast => |a| print("{s}: {s}\n", .{
                    if (a.broadcast.status == .active) "broadcast" else "gone     ",
                    a.broadcast.suffix,
                }),
                .subscribe_response => |r| switch (r.response) {
                    .ok => |v| print("SUBSCRIBE_OK, starting at group {d}\n", .{v.group}),
                    .end => |v| print("SUBSCRIBE_END before group {d}\n", .{v.group}),
                    .drop => |v| print("groups {d}..{d} dropped (error {d})\n", .{
                        v.group_start, v.group_end, v.error_code,
                    }),
                },
                .announce_request => |a| self.serveAnnounce(a.stream_id, a.request),
                .subscribe_request => |sr| self.serveSubscribe(sr.stream_id, sr.subscribe),
                .track_request => |tr| {
                    self.sess.sendTrackInfo(tr.stream_id, .{ .timescale = 1000 }) catch {};
                },
                .group_start => |g| {
                    self.groups_seen += 1;
                    self.frames = lite_session.FrameReader.init(&self.frame_buf);
                    print("group {d}\n", .{g.group.sequence});
                },
                .group_data => |g| {
                    self.frames.push(g.data) catch {
                        print("frame buffer overflow\n", .{});
                        return;
                    };
                    while (self.frames.next() catch null) |item| {
                        self.frames_seen += 1;
                        // Absolute, not a delta, and in the track's
                        // timescale — which TRACK_INFO carries and we do
                        // not ask for, so it is printed raw.
                        print("  ts={d} {s}\n", .{ item.timestamp, item.payload });
                    }
                },
                .group_end => {},
                .probe => |p| print("probe: {d} bps, {d} ms rtt\n", .{ p.probe.bitrate, p.probe.rtt_ms }),
                .goaway => |g| print("GOAWAY: {s}\n", .{g.goaway.uri}),
                else => {},
            }
        }

        fn serveAnnounce(self: *Self, stream_id: u64, req: lite_msg.AnnounceRequest) void {
            // A relay asks everyone, including subscribers. Only a
            // publisher has anything to say.
            const active: u64 = if (self.mode == .publish) 1 else 0;
            self.sess.sendAnnounceOk(stream_id, .{ .hop_id = 1, .active_count = active }) catch return;
            if (self.mode != .publish) return;
            const suffix = lite.wire.stripPathPrefix(self.broadcast, req.prefix) orelse {
                // Nothing under this prefix; the stream stays open in case
                // something appears later.
                return;
            };
            self.sess.sendAnnounceBroadcast(stream_id, .{
                .status = .active,
                .suffix = suffix,
            }) catch {};
            print("announced \"{s}\" to a subscriber\n", .{self.broadcast});
        }

        fn serveSubscribe(self: *Self, stream_id: u64, sub: lite_msg.Subscribe) void {
            if (self.mode != .publish or
                !std.mem.eql(u8, sub.broadcast, self.broadcast) or
                !std.mem.eql(u8, sub.track, self.track))
            {
                // §5.1.2: a refusal is a stream reset, not a message.
                self.sess.resetStream(stream_id, lite_session.ResetCode.NOT_FOUND);
                print("rejected {s}/{s}\n", .{ sub.broadcast, sub.track });
                return;
            }
            self.subscriber_stream = stream_id;
            self.subscriber_id = sub.id;
            self.sess.sendSubscribeResponse(stream_id, .{ .ok = .{ .group = self.group_seq } }) catch {};
            print("serving subscription {d}\n", .{sub.id});
        }

        pub fn onPollComplete(self: *Self, cs: *event_loop.ClientSession) void {
            if (self.mode != .publish or self.subscriber_stream == null) return;
            const now = nowMs();
            if (now - self.last_tick_ms < 1000) return;
            self.last_tick_ms = now;

            self.cur = cs;
            defer self.cur = null;

            // One group per ten ticks, mirroring moq-clock's group-per-minute
            // shape without the wait.
            if (self.group_stream == null or self.frame_in_group >= 10) {
                if (self.group_stream) |g| self.sess.finishGroup(g);
                self.group_stream = self.sess.openGroup(.{
                    .subscribe_id = self.subscriber_id,
                    .sequence = self.group_seq,
                }) catch return;
                self.group_seq += 1;
                self.frame_in_group = 0;
            }

            var buf: [64]u8 = undefined;
            const payload = std.fmt.bufPrint(&buf, "tick {d}", .{self.frames_seen}) catch return;
            self.frames_seen += 1;
            self.sess.sendFrame(self.group_stream.?, .{
                .timestamp_delta = if (self.frame_in_group == 0) 0 else 1000,
                .payload = payload,
            }) catch return;
            self.frame_in_group += 1;
            print("sent {s} in group {d}\n", .{ payload, self.group_seq - 1 });
        }
    };
}

// ─────────────────────────────────────────────────────────────────────
// serve — a moq-lite origin
//
// One synthetic track, published to whoever subscribes. The handler is
// also the transport for every client's session; `cur` is the connection
// whose callback is running, which is the only one a callback ever writes
// to, so no cross-connection plumbing is needed.
// ─────────────────────────────────────────────────────────────────────

const MAX_CLIENTS: usize = 8;

const TICK_MS: i64 = 200;
const FRAMES_PER_GROUP: u64 = 5;

fn Server(comptime proto: event_loop.Protocol) type {
    return struct {
        const Self = @This();
        pub const protocol: event_loop.Protocol = proto;
        pub const poll_interval_ms: u64 = 50;
        const is_wt = proto == .webtransport;
        const Sess = lite_session.Session(*Ref);

        /// What a session writes through. Every write happens inside a
        /// callback for one connection, which `owner.cur` names.
        const Ref = struct {
            owner: *Self,
            idx: usize,

            pub fn openUni(self: *Ref) !u64 {
                const s = self.owner.cur orelse return error.NotConnected;
                return if (is_wt) s.openUniStream(self.owner.clients[self.idx].wt_session_id, null) else s.openStream();
            }
            pub fn openBidi(self: *Ref) !u64 {
                const s = self.owner.cur orelse return error.NotConnected;
                return if (is_wt) s.openBidiStream(self.owner.clients[self.idx].wt_session_id, null) else s.openStream();
            }
            pub fn write(self: *Ref, stream_id: u64, data: []const u8) !void {
                const s = self.owner.cur orelse return error.NotConnected;
                return if (is_wt) s.sendStreamData(stream_id, data) else s.writeStream(stream_id, data);
            }
            pub fn finish(self: *Ref, stream_id: u64) void {
                const s = self.owner.cur orelse return;
                if (is_wt) s.closeStream(stream_id) else s.closeQuicStream(stream_id);
            }
            pub fn reset(self: *Ref, stream_id: u64, code: u64) void {
                const s = self.owner.cur orelse return;
                s.resetStream(stream_id, @truncate(code));
            }
        };

        const ClientState = struct {
            active: bool = false,
            conn: ?*anyopaque = null,
            wt_session_id: u64 = 0,
            ref: Ref = undefined,
            sess: Sess = undefined,
            setup_sent: bool = false,
            // The subscription we are serving, if any.
            sub_stream: ?u64 = null,
            sub_id: u64 = 0,
            group_stream: ?u64 = null,
            group_seq: u64 = 0,
            frame_in_group: u64 = 0,
            last_tick_ms: i64 = 0,
        };

        broadcast: []const u8 = "clock",
        track: []const u8 = "clock",
        clients: [MAX_CLIENTS]ClientState = [_]ClientState{.{}} ** MAX_CLIENTS,
        cur: ?*event_loop.Session = null,
        cur_idx: usize = 0,

        fn key(session: *event_loop.Session) *anyopaque {
            return @ptrCast(session.entry.conn);
        }

        fn find(self: *Self, session: *event_loop.Session) ?usize {
            const k = key(session);
            for (&self.clients, 0..) |*c, i| if (c.active and c.conn == k) return i;
            return null;
        }

        fn admit(self: *Self, session: *event_loop.Session) ?usize {
            if (self.find(session)) |i| return i;
            for (&self.clients, 0..) |*c, i| {
                if (c.active) continue;
                c.* = .{ .active = true, .conn = key(session) };
                c.ref = .{ .owner = self, .idx = i };
                c.sess = Sess.init(&self.clients[i].ref);
                return i;
            }
            return null;
        }

        fn enter(self: *Self, session: *event_loop.Session) ?usize {
            const i = self.admit(session) orelse return null;
            self.cur = session;
            self.cur_idx = i;
            return i;
        }

        fn greet(self: *Self, i: usize) void {
            const c = &self.clients[i];
            if (c.setup_sent) return;
            c.sess.sendSetup() catch |e| {
                print("client {d}: SETUP failed: {t}\n", .{ i, e });
                return;
            };
            c.setup_sent = true;
        }

        pub fn onConnectRequest(
            _: *Self,
            session: *event_loop.Session,
            session_id: u64,
            _: []const u8,
            headers: []const qpack.Header,
        ) void {
            if (!is_wt) return;
            var alpn_buf: [4][]const u8 = undefined;
            const supported = lite_version.alpnOffer(lite_version.PREFERRED, &alpn_buf);

            var scratch: [256]u8 = undefined;
            var value_buf: [64]u8 = undefined;
            if (wt_protocol.findHeader(headers, wt_protocol.HEADER_AVAILABLE)) |offer| {
                if (wt_protocol.selectFromOffer(offer, supported, &scratch)) |name| {
                    print("negotiated {s}\n", .{name});
                    if (wt_protocol.encodeItem(name, &value_buf)) |encoded| {
                        const extra = [_]qpack.Header{
                            .{ .name = wt_protocol.HEADER_SELECTED, .value = encoded },
                        };
                        session.acceptSessionWithHeaders(session_id, &extra) catch {};
                        return;
                    } else |_| {}
                }
                // §3.1: the version rides the ALPN, so no overlap means no
                // shared protocol. Better to refuse than to guess.
                print("no shared moq-lite version; rejecting\n", .{});
                session.closeSession(session_id);
                return;
            }
            session.acceptSession(session_id) catch {};
        }

        pub fn onSessionReady(self: *Self, session: *event_loop.Session, session_id: u64) void {
            const i = self.enter(session) orelse return;
            defer self.cur = null;
            self.clients[i].wt_session_id = session_id;
            self.greet(i);
        }

        pub fn onBidiStream(self: *Self, session: *event_loop.Session, _: u64, stream_id: u64) void {
            const i = self.enter(session) orelse return;
            defer self.cur = null;
            self.clients[i].sess.onPeerStream(stream_id, true) catch {};
        }

        pub fn onUniStream(self: *Self, session: *event_loop.Session, _: u64, stream_id: u64) void {
            const i = self.enter(session) orelse return;
            defer self.cur = null;
            self.clients[i].sess.onPeerStream(stream_id, false) catch {};
        }

        pub fn onStreamData(
            self: *Self,
            session: *event_loop.Session,
            stream_id: u64,
            data: []const u8,
            fin: bool,
        ) void {
            const i = self.enter(session) orelse return;
            defer self.cur = null;
            // Raw QUIC has no session-ready callback, so this is where a
            // connection first announces itself.
            if (!is_wt) self.greet(i);

            var events: [16]lite_session.Event = undefined;
            const n = self.clients[i].sess.onStreamData(stream_id, data, fin, &events) catch |e| {
                print("client {d} stream {d}: {t}\n", .{ i, stream_id, e });
                return;
            };
            for (events[0..n]) |ev| self.handle(i, ev);
        }

        pub fn onSessionClosed(self: *Self, session: *event_loop.Session, _: u64, _: u32, _: []const u8) void {
            const i = self.find(session) orelse return;
            print("client {d} gone\n", .{i});
            self.clients[i] = .{};
        }

        fn handle(self: *Self, i: usize, ev: lite_session.Event) void {
            const c = &self.clients[i];
            switch (ev) {
                .peer_setup => print("client {d}: SETUP\n", .{i}),
                .announce_request => |a| {
                    c.sess.sendAnnounceOk(a.stream_id, .{ .hop_id = 1, .active_count = 1 }) catch return;
                    if (lite.wire.stripPathPrefix(self.broadcast, a.request.prefix)) |suffix| {
                        c.sess.sendAnnounceBroadcast(a.stream_id, .{
                            .status = .active,
                            .suffix = suffix,
                        }) catch {};
                        print("client {d}: announced \"{s}\"\n", .{ i, self.broadcast });
                    }
                },
                .track_request => |t| {
                    c.sess.sendTrackInfo(t.stream_id, .{ .timescale = 1000 }) catch {};
                },
                .subscribe_request => |sr| {
                    const sub = sr.subscribe;
                    if (!std.mem.eql(u8, sub.broadcast, self.broadcast) or
                        !std.mem.eql(u8, sub.track, self.track))
                    {
                        c.sess.resetStream(sr.stream_id, lite_session.ResetCode.NOT_FOUND);
                        print("client {d}: no such track {s}/{s}\n", .{ i, sub.broadcast, sub.track });
                        return;
                    }
                    c.sub_stream = sr.stream_id;
                    c.sub_id = sub.id;
                    c.sess.sendSubscribeResponse(sr.stream_id, .{ .ok = .{ .group = c.group_seq } }) catch {};
                    print("client {d}: serving {s}/{s} as subscription {d}\n", .{
                        i, sub.broadcast, sub.track, sub.id,
                    });
                },
                .fetch_request => |f| {
                    // §5.1.3 has no error message: refusing is a reset.
                    c.sess.resetStream(f.stream_id, lite_session.ResetCode.NOT_FOUND);
                },
                .stream_finished => |f| {
                    if (c.sub_stream == f.stream_id) {
                        print("client {d}: unsubscribed\n", .{i});
                        c.sub_stream = null;
                        if (c.group_stream) |g| c.sess.finishGroup(g);
                        c.group_stream = null;
                    }
                },
                else => {},
            }
        }

        pub fn onPollComplete(self: *Self, session: *event_loop.Session) void {
            const i = self.find(session) orelse return;
            const c = &self.clients[i];
            if (c.sub_stream == null) return;

            const now = nowMs();
            if (now - c.last_tick_ms < TICK_MS) return;
            c.last_tick_ms = now;

            self.cur = session;
            self.cur_idx = i;
            defer self.cur = null;

            if (c.group_stream == null or c.frame_in_group >= FRAMES_PER_GROUP) {
                if (c.group_stream) |g| c.sess.finishGroup(g);
                c.group_stream = c.sess.openGroup(.{
                    .subscribe_id = c.sub_id,
                    .sequence = c.group_seq,
                }) catch return;
                c.group_seq += 1;
                c.frame_in_group = 0;
            }

            var buf: [64]u8 = undefined;
            const payload = std.fmt.bufPrint(&buf, "{d}", .{now}) catch return;
            c.sess.sendFrame(c.group_stream.?, .{
                .timestamp_delta = if (c.frame_in_group == 0) 0 else TICK_MS,
                .payload = payload,
            }) catch return;
            c.frame_in_group += 1;
        }
    };
}

// ─────────────────────────────────────────────────────────────────────
// main
// ─────────────────────────────────────────────────────────────────────

fn resolveNumeric(host: []const u8, port: u16, out: []u8) !struct { addr: []const u8, ipv6: bool } {
    if (quic.sockaddr.Address.parseIp4(host, port)) |_| {
        @memcpy(out[0..host.len], host);
        return .{ .addr = out[0..host.len], .ipv6 = false };
    } else |_| {}
    if (quic.sockaddr.Address.parseIp6(host, port)) |_| {
        @memcpy(out[0..host.len], host);
        return .{ .addr = out[0..host.len], .ipv6 = true };
    } else |_| {}

    const storage = try sys.resolveHost(host, port);
    if (storage.family == posix.AF.INET) {
        const in: *const posix.sockaddr.in = @ptrCast(@alignCast(&storage));
        const b: [4]u8 = @bitCast(in.addr);
        const s = try std.fmt.bufPrint(out, "{d}.{d}.{d}.{d}", .{ b[0], b[1], b[2], b[3] });
        return .{ .addr = s, .ipv6 = false };
    }
    if (storage.family == posix.AF.INET6) {
        const in6: *const posix.sockaddr.in6 = @ptrCast(@alignCast(&storage));
        var w: usize = 0;
        for (0..8) |i| {
            const group = std.mem.readInt(u16, in6.addr[i * 2 ..][0..2], .big);
            const s = try std.fmt.bufPrint(out[w..], "{s}{x}", .{ if (i == 0) "" else ":", group });
            w += s.len;
        }
        return .{ .addr = out[0..w], .ipv6 = true };
    }
    return error.UnsupportedAddressFamily;
}

fn Run(comptime proto: event_loop.Protocol) type {
    return struct {
        fn go(
            alloc: std.mem.Allocator,
            loc: moq_url.Locator,
            address: []const u8,
            ipv6: bool,
            handler: *Peer(proto),
            skip_verify: bool,
            seconds: u64,
        ) !void {
            var offer_buf: [128]u8 = undefined;
            var alpn_buf: [4][]const u8 = undefined;
            const alpns = lite_version.alpnOffer(lite_version.PREFERRED, &alpn_buf);
            const offer = try wt_protocol.encodeList(alpns, &offer_buf);
            const connect_headers = [_]qpack.Header{
                .{ .name = wt_protocol.HEADER_AVAILABLE, .value = offer },
            };

            handler.prepare(loc.path);

            var client = try event_loop.Client(Peer(proto)).init(alloc, handler, .{
                .address = address,
                .port = loc.port,
                .server_name = moq_url.bareHost(loc.host),
                .path = loc.path,
                .ipv6 = ipv6,
                // Native QUIC picks the version with the ALPN; WebTransport
                // keeps "h3" and negotiates it on the CONNECT instead.
                .alpn = if (proto == .quic) lite_version.DEFAULT.alpn() else null,
                .skip_cert_verify = skip_verify,
                .connect_headers = if (proto == .webtransport) &connect_headers else &.{},
            });
            defer client.deinit();

            const deadline = nowMs() + @as(i64, @intCast(seconds)) * 1000;
            while (nowMs() < deadline) {
                try client.tick();
            }
            client.stop();
            // stop() queues the CONNECTION_CLOSE; flush puts it on the
            // wire, so the peer frees the session now rather than at its
            // idle timeout.
            client.flush();
            for (0..20) |_| client.tick() catch break;
        }
    };
}

pub fn main(init: std.process.Init.Minimal) !u8 {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    var mode: ?Mode = null;
    var url: []const u8 = "https://localhost:4443/anon";
    var broadcast: []const u8 = "clock";
    var track: []const u8 = "clock";
    var prefix: []const u8 = "";
    var seconds: u64 = 10;
    var skip_verify = false;
    var port: u16 = 4447;
    var cert_path: []const u8 = "interop/certs/server.crt";
    var key_path: []const u8 = "interop/certs/server.key";

    var args = std.process.Args.Iterator.init(init.args);
    _ = args.next();
    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "publish")) {
            mode = .publish;
        } else if (std.mem.eql(u8, arg, "subscribe")) {
            mode = .subscribe;
        } else if (std.mem.eql(u8, arg, "announce")) {
            mode = .announce;
        } else if (std.mem.eql(u8, arg, "serve")) {
            mode = .serve;
        } else if (std.mem.eql(u8, arg, "--port")) {
            if (args.next()) |v| port = std.fmt.parseInt(u16, v, 10) catch 4447;
        } else if (std.mem.eql(u8, arg, "--cert")) {
            if (args.next()) |v| cert_path = v;
        } else if (std.mem.eql(u8, arg, "--key")) {
            if (args.next()) |v| key_path = v;
        } else if (std.mem.eql(u8, arg, "--url")) {
            if (args.next()) |v| url = v;
        } else if (std.mem.eql(u8, arg, "--broadcast")) {
            if (args.next()) |v| broadcast = v;
        } else if (std.mem.eql(u8, arg, "--track")) {
            if (args.next()) |v| track = v;
        } else if (std.mem.eql(u8, arg, "--prefix")) {
            if (args.next()) |v| prefix = v;
        } else if (std.mem.eql(u8, arg, "--seconds")) {
            if (args.next()) |v| seconds = std.fmt.parseInt(u64, v, 10) catch 10;
        } else if (std.mem.eql(u8, arg, "--tls-disable-verify")) {
            skip_verify = true;
        } else if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) {
            print(
                \\moq-lite <publish|subscribe|announce> [options]
                \\  --url URL                 https:// for WebTransport, moqt:// for QUIC
                \\  --broadcast PATH          broadcast path (default "clock")
                \\  --track NAME              track name (default "clock")
                \\  --prefix PATH             announce: prefix to watch (default "")
                \\  --seconds N               how long to run (default 10)
                \\  --tls-disable-verify
                \\
                \\serve options:
                \\  --port N                  listen port (default 4447)
                \\  --cert PATH --key PATH    TLS material
                \\
            , .{});
            return 0;
        }
    }

    const m = mode orelse {
        print("usage: moq-lite <publish|subscribe|announce> --url URL [...]\n", .{});
        return 2;
    };

    if (m == .serve) return serveMain(alloc, port, cert_path, key_path, broadcast, track);

    const loc = moq_url.parse(url) catch |e| {
        print("bad --url {s}: {t}\n", .{ url, e });
        return 2;
    };

    var addr_buf: [64]u8 = undefined;
    const resolved = resolveNumeric(moq_url.bareHost(loc.host), loc.port, &addr_buf) catch |e| {
        print("cannot resolve {s}: {t}\n", .{ loc.host, e });
        return 2;
    };

    print("=== moq-lite ({s}) ===\n", .{lite_version.DEFAULT.alpn()});
    print("{s} {s} via {s}\n\n", .{ @tagName(m), url, @tagName(loc.defaultTransport()) });

    switch (loc.defaultTransport()) {
        .quic => {
            var handler = Peer(.quic){ .mode = m, .broadcast = broadcast, .track = track, .prefix = prefix };
            try Run(.quic).go(alloc, loc, resolved.addr, resolved.ipv6, &handler, skip_verify, seconds);
            print("\n{d} groups, {d} frames\n", .{ handler.groups_seen, handler.frames_seen });
        },
        .webtransport => {
            var handler = Peer(.webtransport){ .mode = m, .broadcast = broadcast, .track = track, .prefix = prefix };
            try Run(.webtransport).go(alloc, loc, resolved.addr, resolved.ipv6, &handler, skip_verify, seconds);
            print("\n{d} groups, {d} frames\n", .{ handler.groups_seen, handler.frames_seen });
        },
    }
    return 0;
}

/// Runs the origin. WebTransport, because that is what a browser and
/// moq-rs both reach for; raw-QUIC moq-lite servers can follow when
/// something needs one.
fn serveMain(
    alloc: std.mem.Allocator,
    port: u16,
    cert_path: []const u8,
    key_path: []const u8,
    broadcast: []const u8,
    track: []const u8,
) !u8 {
    const H = Server(.webtransport);
    // On the heap: one session per client is MAX_STREAMS control buffers,
    // which overflows the stack well before the client limit.
    const handler = try alloc.create(H);
    handler.* = .{ .broadcast = broadcast, .track = track };

    var server = event_loop.Server(H).init(alloc, handler, .{
        .port = port,
        .cert_path = cert_path,
        .key_path = key_path,
    }) catch |e| {
        print("cannot listen on {d}: {t}\n", .{ port, e });
        return 1;
    };
    defer server.deinit();

    print("=== moq-lite origin ({s}) ===\n", .{lite_version.DEFAULT.alpn()});
    print("https://0.0.0.0:{d}  serving {s}/{s}\n\n", .{ port, broadcast, track });

    try server.run();
    return 0;
}
