// moq-lite relay — draft-lcurley-moq-lite-05.
//
//   moq-lite-relay [--port N] [--cert PATH] [--key PATH]
//
// WebTransport, because that is what browsers and the moq-dev tools reach
// for. A session that announces a broadcast becomes its origin; a session
// that subscribes to one gets an upstream subscription opened to that
// origin on its behalf, and the origin's group streams are forwarded with
// the subscribe id rewritten.
//
// Fixed-size throughout, like the other relays here: no allocation on the
// data path, and the limits are the admission control.

const std = @import("std");
const quic = @import("quic");
const io_compat = quic.io_compat;
const sys = quic.sys;
const event_loop = quic.event_loop;
const qpack = quic.qpack;
const cm = quic.connection_manager;
const wt = quic.webtransport;
const wt_protocol = quic.webtransport_protocol;

const lite = quic.moq.lite;
const lite_msg = lite.message;
const lite_session = lite.session;
const lite_version = lite.version;

pub const std_options: std.Options = .{ .log_level = .err };

const MAX_CLIENTS: usize = 16;
const MAX_BROADCASTS: usize = 64;
const MAX_SUBSCRIPTIONS: usize = 64;
const MAX_FLOWS: usize = 64;
const MAX_PATH: usize = 128;
const MAX_NAME: usize = 64;
const NONE: usize = std.math.maxInt(usize);

fn print(comptime fmt: []const u8, args: anytype) void {
    std.debug.print(fmt, args);
}

/// A broadcast someone has announced, and who to ask for it.
const Broadcast = struct {
    path: [MAX_PATH]u8 = undefined,
    path_len: usize = 0,
    origin: usize = NONE,
    active: bool = false,

    fn name(self: *const Broadcast) []const u8 {
        return self.path[0..self.path_len];
    }
};

/// A downstream subscription, paired with the upstream one serving it.
const Subscription = struct {
    active: bool = false,
    down_ci: usize = NONE,
    down_stream: u64 = 0,
    down_id: u64 = 0,
    up_ci: usize = NONE,
    up_stream: u64 = 0,
    up_id: u64 = 0,
    /// Set once the origin has answered, so a late SUBSCRIBE_OK is not
    /// forwarded twice.
    answered: bool = false,
};

/// One group stream being copied from an origin to a subscriber.
const Flow = struct {
    active: bool = false,
    in_ci: usize = NONE,
    in_stream: u64 = 0,
    out_ci: usize = NONE,
    out_stream: u64 = 0,
};

/// A session that asked us to announce broadcasts under a prefix.
const AnnounceWatch = struct {
    active: bool = false,
    ci: usize = NONE,
    stream: u64 = 0,
    prefix: [MAX_PATH]u8 = undefined,
    prefix_len: usize = 0,

    fn name(self: *const AnnounceWatch) []const u8 {
        return self.prefix[0..self.prefix_len];
    }
};

const Relay = struct {
    pub const protocol: event_loop.Protocol = .webtransport;
    const Self = @This();
    const Sess = lite_session.Session(*Ref);

    /// The seam a session writes through. Unlike a client, a relay writes
    /// to sessions other than the one whose callback is running, so this
    /// reaches the connection through its entry rather than through the
    /// event loop's per-poll Session.
    const Ref = struct {
        owner: *Self,
        idx: usize,

        fn wtc(self: *Ref) ?*wt.WebTransportConnection {
            const c = &self.owner.clients[self.idx];
            const entry = c.entry orelse return null;
            return entry.wt_conn;
        }

        pub fn openUni(self: *Ref) !u64 {
            const w = self.wtc() orelse return error.NotConnected;
            return w.openUniStream(self.owner.clients[self.idx].wt_session_id, null);
        }
        pub fn openBidi(self: *Ref) !u64 {
            const w = self.wtc() orelse return error.NotConnected;
            return w.openBidiStream(self.owner.clients[self.idx].wt_session_id, null);
        }
        pub fn write(self: *Ref, stream_id: u64, data: []const u8) !void {
            const w = self.wtc() orelse return error.NotConnected;
            return w.sendStreamData(stream_id, data);
        }
        pub fn finish(self: *Ref, stream_id: u64) void {
            const w = self.wtc() orelse return;
            w.closeStream(stream_id);
        }
        pub fn reset(self: *Ref, stream_id: u64, code: u64) void {
            const w = self.wtc() orelse return;
            w.resetStream(stream_id, @truncate(code));
        }
    };

    const Client = struct {
        active: bool = false,
        entry: ?*cm.ConnEntry = null,
        wt_session_id: u64 = 0,
        ref: Ref = undefined,
        sess: Sess = undefined,
        /// The announce stream we opened to this session to learn what it
        /// publishes. A relay is a subscriber to everyone.
        discover_stream: ?u64 = null,
        next_sub_id: u64 = 0,
    };

    clients: [MAX_CLIENTS]Client = [_]Client{.{}} ** MAX_CLIENTS,
    broadcasts: [MAX_BROADCASTS]Broadcast = [_]Broadcast{.{}} ** MAX_BROADCASTS,
    subs: [MAX_SUBSCRIPTIONS]Subscription = [_]Subscription{.{}} ** MAX_SUBSCRIPTIONS,
    flows: [MAX_FLOWS]Flow = [_]Flow{.{}} ** MAX_FLOWS,
    watches: [MAX_SUBSCRIPTIONS]AnnounceWatch = [_]AnnounceWatch{.{}} ** MAX_SUBSCRIPTIONS,
    hop_id: u64 = 1,

    // --- client table --------------------------------------------------

    fn find(self: *Self, entry: *cm.ConnEntry) ?usize {
        for (&self.clients, 0..) |*c, i| if (c.active and c.entry == entry) return i;
        return null;
    }

    fn admit(self: *Self, entry: *cm.ConnEntry) ?usize {
        if (self.find(entry)) |i| return i;
        for (&self.clients, 0..) |*c, i| {
            if (c.active) continue;
            c.* = .{ .active = true, .entry = entry };
            c.ref = .{ .owner = self, .idx = i };
            c.sess = Sess.init(&self.clients[i].ref);
            return i;
        }
        return null;
    }

    // --- event_loop callbacks -------------------------------------------

    /// A server sees no session_ready — that event is the client learning
    /// its CONNECT was accepted — so the session starts here, right after
    /// the accept.
    pub fn onConnectRequest(
        self: *Self,
        session: *event_loop.Session,
        session_id: u64,
        _: []const u8,
        headers: []const qpack.Header,
    ) void {
        var alpn_buf: [4][]const u8 = undefined;
        const supported = lite_version.alpnOffer(lite_version.PREFERRED, &alpn_buf);
        var scratch: [256]u8 = undefined;
        var value_buf: [64]u8 = undefined;

        if (wt_protocol.findHeader(headers, wt_protocol.HEADER_AVAILABLE)) |offer| {
            if (wt_protocol.selectFromOffer(offer, supported, &scratch)) |name| {
                if (wt_protocol.encodeItem(name, &value_buf)) |encoded| {
                    const extra = [_]qpack.Header{
                        .{ .name = wt_protocol.HEADER_SELECTED, .value = encoded },
                    };
                    session.acceptSessionWithHeaders(session_id, &extra) catch return;
                    self.start(session, session_id);
                    return;
                } else |_| {}
            }
            // §3.1: the version rides the ALPN, so no overlap means no
            // shared protocol.
            print("rejecting a session with no shared moq-lite version\n", .{});
            session.closeSession(session_id);
            return;
        }
        session.acceptSession(session_id) catch return;
        self.start(session, session_id);
    }

    fn start(self: *Self, session: *event_loop.Session, session_id: u64) void {
        const i = self.admit(session.entry) orelse {
            session.closeSession(session_id);
            return;
        };
        const c = &self.clients[i];
        c.wt_session_id = session_id;
        c.sess.sendSetup() catch |e| {
            print("client {d}: SETUP failed: {t}\n", .{ i, e });
            return;
        };
        // Ask what this session publishes. Everything under the root, so
        // one stream covers whatever it announces later.
        c.discover_stream = c.sess.openAnnounce(.{ .prefix = "" }) catch null;
        print("client {d} connected\n", .{i});
    }

    pub fn onBidiStream(self: *Self, session: *event_loop.Session, _: u64, stream_id: u64) void {
        const i = self.find(session.entry) orelse return;
        self.clients[i].sess.onPeerStream(stream_id, true) catch {};
    }

    pub fn onUniStream(self: *Self, session: *event_loop.Session, _: u64, stream_id: u64) void {
        const i = self.find(session.entry) orelse return;
        self.clients[i].sess.onPeerStream(stream_id, false) catch {};
    }

    pub fn onStreamData(
        self: *Self,
        session: *event_loop.Session,
        stream_id: u64,
        data: []const u8,
        fin: bool,
    ) void {
        const i = self.find(session.entry) orelse return;
        var events: [16]lite_session.Event = undefined;
        const n = self.clients[i].sess.onStreamData(stream_id, data, fin, &events) catch |e| {
            print("client {d} stream {d}: {t}\n", .{ i, stream_id, e });
            return;
        };
        for (events[0..n]) |ev| self.handle(i, ev);
    }

    pub fn onSessionClosed(self: *Self, session: *event_loop.Session, _: u64, _: u32, _: []const u8) void {
        const i = self.find(session.entry) orelse return;
        self.releaseClient(i);
    }

    // --- routing ---------------------------------------------------------

    fn handle(self: *Self, ci: usize, ev: lite_session.Event) void {
        switch (ev) {
            .peer_setup => print("client {d}: SETUP\n", .{ci}),

            // Someone wants to know what we carry.
            .announce_request => |a| self.serveAnnounceRequest(ci, a.stream_id, a.request),

            // An origin telling us what it carries, on the stream we opened.
            .announce_broadcast => |a| self.originAnnounced(ci, a.broadcast),

            .subscribe_request => |s| self.serveSubscribe(ci, s.stream_id, s.subscribe),
            .subscribe_response => |r| self.upstreamResponded(ci, r.stream_id, r.response),

            .group_start => |g| self.startFlow(ci, g.stream_id, g.group),
            .group_data => |g| self.forwardFlow(ci, g.stream_id, g.data),
            .group_end => |g| self.endFlow(ci, g.stream_id),

            .track_request => |t| {
                // We do not cache track metadata, so answer with the
                // defaults rather than leaving the stream hanging.
                self.clients[ci].sess.sendTrackInfo(t.stream_id, .{}) catch {};
            },
            .fetch_request => |f| {
                self.clients[ci].sess.resetStream(f.stream_id, lite_session.ResetCode.NOT_FOUND);
            },
            .stream_finished => |f| self.streamGone(ci, f.stream_id),
            else => {},
        }
    }

    fn serveAnnounceRequest(self: *Self, ci: usize, stream_id: u64, req: lite_msg.AnnounceRequest) void {
        var active: u64 = 0;
        for (&self.broadcasts) |*b| {
            if (b.active and lite.wire.hasPathPrefix(b.name(), req.prefix)) active += 1;
        }

        const c = &self.clients[ci];
        c.sess.sendAnnounceOk(stream_id, .{ .hop_id = self.hop_id, .active_count = active }) catch return;
        for (&self.broadcasts) |*b| {
            if (!b.active) continue;
            const suffix = lite.wire.stripPathPrefix(b.name(), req.prefix) orelse continue;
            c.sess.sendAnnounceBroadcast(stream_id, .{ .status = .active, .suffix = suffix }) catch {};
        }

        // Remember them so later announcements reach this stream too.
        for (&self.watches) |*w| {
            if (w.active) continue;
            w.* = .{ .active = true, .ci = ci, .stream = stream_id };
            w.prefix_len = @min(req.prefix.len, MAX_PATH);
            @memcpy(w.prefix[0..w.prefix_len], req.prefix[0..w.prefix_len]);
            break;
        }
        print("client {d}: watching \"{s}\" ({d} active)\n", .{ ci, req.prefix, active });
    }

    fn originAnnounced(self: *Self, ci: usize, b: lite_msg.AnnounceBroadcast) void {
        // The suffix is relative to the prefix we asked for, which is "".
        if (b.status == .ended) {
            self.dropBroadcast(b.suffix);
            self.notifyWatchers(b.suffix, .ended);
            print("client {d}: unannounced \"{s}\"\n", .{ ci, b.suffix });
            return;
        }

        if (b.suffix.len > MAX_PATH) return;
        for (&self.broadcasts) |*e| {
            if (e.active and std.mem.eql(u8, e.name(), b.suffix)) {
                e.origin = ci; // a newer origin takes over
                return;
            }
        }
        for (&self.broadcasts) |*e| {
            if (e.active) continue;
            @memcpy(e.path[0..b.suffix.len], b.suffix);
            e.path_len = b.suffix.len;
            e.origin = ci;
            e.active = true;
            print("client {d}: announced \"{s}\"\n", .{ ci, b.suffix });
            self.notifyWatchers(b.suffix, .active);
            return;
        }
        print("broadcast table full; dropping \"{s}\"\n", .{b.suffix});
    }

    fn notifyWatchers(self: *Self, path: []const u8, status: lite_msg.AnnounceStatus) void {
        for (&self.watches) |*w| {
            if (!w.active) continue;
            const suffix = lite.wire.stripPathPrefix(path, w.name()) orelse continue;
            self.clients[w.ci].sess.sendAnnounceBroadcast(w.stream, .{
                .status = status,
                .suffix = suffix,
            }) catch {};
        }
    }

    fn dropBroadcast(self: *Self, path: []const u8) void {
        for (&self.broadcasts) |*b| {
            if (b.active and std.mem.eql(u8, b.name(), path)) b.active = false;
        }
    }

    fn originOf(self: *Self, path: []const u8) ?usize {
        for (&self.broadcasts) |*b| {
            if (b.active and std.mem.eql(u8, b.name(), path)) {
                if (b.origin != NONE and self.clients[b.origin].active) return b.origin;
            }
        }
        return null;
    }

    fn serveSubscribe(self: *Self, ci: usize, stream_id: u64, sub: lite_msg.Subscribe) void {
        const origin = self.originOf(sub.broadcast) orelse {
            // §5.1.2: refusing is a stream reset, not a message.
            self.clients[ci].sess.resetStream(stream_id, lite_session.ResetCode.NOT_FOUND);
            print("client {d}: no origin for \"{s}\"\n", .{ ci, sub.broadcast });
            return;
        };
        if (origin == ci) {
            self.clients[ci].sess.resetStream(stream_id, lite_session.ResetCode.NOT_FOUND);
            return;
        }

        const slot = for (&self.subs) |*s| {
            if (!s.active) break s;
        } else {
            self.clients[ci].sess.resetStream(stream_id, lite_session.ResetCode.INTERNAL);
            return;
        };

        // Subscribe upstream on the downstream subscriber's behalf, keeping
        // its delivery preferences.
        const up = self.clients[origin].sess.openSubscribe(.{
            .broadcast = sub.broadcast,
            .track = sub.track,
            .priority = sub.priority,
            .ordered = sub.ordered,
            .max_latency_ms = sub.max_latency_ms,
            .group_start = sub.group_start,
            .group_end = sub.group_end,
        }) catch {
            self.clients[ci].sess.resetStream(stream_id, lite_session.ResetCode.INTERNAL);
            return;
        };

        slot.* = .{
            .active = true,
            .down_ci = ci,
            .down_stream = stream_id,
            .down_id = sub.id,
            .up_ci = origin,
            .up_stream = up.stream_id,
            .up_id = up.id,
        };
        print("client {d}: subscribed to \"{s}\"/{s} via client {d}\n", .{
            ci, sub.broadcast, sub.track, origin,
        });
    }

    fn subByUpstream(self: *Self, up_ci: usize, up_stream: u64) ?*Subscription {
        for (&self.subs) |*s| {
            if (s.active and s.up_ci == up_ci and s.up_stream == up_stream) return s;
        }
        return null;
    }

    fn subByUpstreamId(self: *Self, up_ci: usize, up_id: u64) ?*Subscription {
        for (&self.subs) |*s| {
            if (s.active and s.up_ci == up_ci and s.up_id == up_id) return s;
        }
        return null;
    }

    fn upstreamResponded(self: *Self, ci: usize, stream_id: u64, r: lite_msg.SubscribeResponse) void {
        const s = self.subByUpstream(ci, stream_id) orelse return;
        // Pass it through: OK, END and DROP all mean the same downstream.
        self.clients[s.down_ci].sess.sendSubscribeResponse(s.down_stream, r) catch {};
        if (std.meta.activeTag(r) == .ok) s.answered = true;
    }

    fn startFlow(self: *Self, ci: usize, stream_id: u64, g: lite_msg.Group) void {
        const s = self.subByUpstreamId(ci, g.subscribe_id) orelse return;
        const out = self.clients[s.down_ci].sess.openGroup(.{
            .subscribe_id = s.down_id,
            .sequence = g.sequence,
        }) catch return;

        for (&self.flows) |*f| {
            if (f.active) continue;
            f.* = .{
                .active = true,
                .in_ci = ci,
                .in_stream = stream_id,
                .out_ci = s.down_ci,
                .out_stream = out,
            };
            return;
        }
        // No slot: better to reset the outbound stream than to leave a
        // subscriber waiting on a group that will never arrive.
        self.clients[s.down_ci].sess.resetStream(out, lite_session.ResetCode.INTERNAL);
    }

    fn flowOf(self: *Self, ci: usize, stream_id: u64) ?*Flow {
        for (&self.flows) |*f| {
            if (f.active and f.in_ci == ci and f.in_stream == stream_id) return f;
        }
        return null;
    }

    fn forwardFlow(self: *Self, ci: usize, stream_id: u64, data: []const u8) void {
        const f = self.flowOf(ci, stream_id) orelse return;
        // Frames pass through untouched: only the GROUP header needed
        // rewriting, and that happened when the flow was opened.
        self.clients[f.out_ci].ref.write(f.out_stream, data) catch {
            f.active = false;
        };
    }

    fn endFlow(self: *Self, ci: usize, stream_id: u64) void {
        const f = self.flowOf(ci, stream_id) orelse return;
        self.clients[f.out_ci].sess.finishGroup(f.out_stream);
        f.active = false;
    }

    fn streamGone(self: *Self, ci: usize, stream_id: u64) void {
        // A downstream subscriber closing its subscribe stream unsubscribes;
        // tear the upstream one down with it.
        for (&self.subs) |*s| {
            if (!s.active) continue;
            if (s.down_ci == ci and s.down_stream == stream_id) {
                self.clients[s.up_ci].sess.finishStream(s.up_stream);
                s.active = false;
                print("client {d}: unsubscribed\n", .{ci});
            } else if (s.up_ci == ci and s.up_stream == stream_id) {
                self.clients[s.down_ci].sess.finishStream(s.down_stream);
                s.active = false;
            }
        }
        for (&self.watches) |*w| {
            if (w.active and w.ci == ci and w.stream == stream_id) w.active = false;
        }
    }

    fn releaseClient(self: *Self, ci: usize) void {
        print("client {d} gone\n", .{ci});

        for (&self.broadcasts) |*b| {
            if (b.active and b.origin == ci) {
                self.notifyWatchers(b.name(), .ended);
                b.active = false;
            }
        }
        for (&self.subs) |*s| {
            if (!s.active) continue;
            if (s.down_ci == ci) {
                if (self.clients[s.up_ci].active) self.clients[s.up_ci].sess.finishStream(s.up_stream);
                s.active = false;
            } else if (s.up_ci == ci) {
                // The origin left: end the subscription rather than leave
                // the subscriber waiting on a group that cannot come.
                if (self.clients[s.down_ci].active) {
                    self.clients[s.down_ci].sess.sendSubscribeResponse(s.down_stream, .{
                        .end = .{ .group = 0 },
                    }) catch {};
                }
                s.active = false;
            }
        }
        for (&self.flows) |*f| {
            if (f.active and (f.in_ci == ci or f.out_ci == ci)) f.active = false;
        }
        for (&self.watches) |*w| {
            if (w.active and w.ci == ci) w.active = false;
        }
        self.clients[ci] = .{};
    }
};

pub fn main(init: std.process.Init.Minimal) !void {
    const alloc = std.heap.smp_allocator;

    var port: u16 = 4450;
    var cert_path: []const u8 = "interop/browser/certs/server.crt";
    var key_path: []const u8 = "interop/browser/certs/server.key";

    var args = std.process.Args.Iterator.init(init.args);
    _ = args.next();
    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--port")) {
            if (args.next()) |v| port = std.fmt.parseInt(u16, v, 10) catch 4450;
        } else if (std.mem.eql(u8, arg, "--cert")) {
            if (args.next()) |v| cert_path = v;
        } else if (std.mem.eql(u8, arg, "--key")) {
            if (args.next()) |v| key_path = v;
        }
    }

    // On the heap: a session is MAX_STREAMS control buffers and there are
    // MAX_CLIENTS of them, which the stack will not hold.
    const handler = try alloc.create(Relay);
    defer alloc.destroy(handler);
    handler.* = .{};

    var server = try event_loop.Server(Relay).init(alloc, handler, .{
        .port = port,
        .cert_path = cert_path,
        .key_path = key_path,
    });
    defer server.deinit();

    print("=== moq-lite relay ({s}) ===\n", .{lite_version.DEFAULT.alpn()});
    print("https://0.0.0.0:{d}\n\n", .{port});

    try server.run();
}
