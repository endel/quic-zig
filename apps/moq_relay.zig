// MoQ Transport relay, draft-17 and draft-18, over WebTransport and native
// QUIC on one port: a connection's ALPN picks — `h3` is WebTransport, with
// the MoQT version chosen by WT-Protocol; `moqt-NN` is native QUIC.
//
// Multi-session relay:
//  - Clients connect, exchange MoQ SETUP
//  - Publishers: PUBLISH on bidi + objects on uni streams
//  - Subscribers: SUBSCRIBE on bidi + receive objects on uni streams
//  - Relay forwards publisher uni streams to matching subscribers with alias remap

const std = @import("std");
const quic = @import("quic");
const io_compat = @import("quic").io_compat;
const sys = quic.sys;
const event_loop = quic.event_loop;
const tls13 = quic.tls13;
const connection_mod = quic.connection;
const cm = quic.connection_manager;
const wt = quic.webtransport;
const wt_protocol = quic.webtransport_protocol;
const qpack = quic.qpack;

const moq_wire = quic.moq.wire;
const moq_msg = quic.moq.message;
const moq_codes = quic.moq.message_codes;
const moq_obj = quic.moq.object;
const moq_version = quic.moq.version;
const relay_test = @import("relay_test.zig");

pub const std_options: std.Options = .{ .log_level = .err };

// A connection lingers in draining after its session closes, so a relay
// that also serves a test suite needs headroom over its concurrent peers.
const MAX_CLIENTS: usize = 32;
const MAX_TRACKS: usize = 32;
// A closed connection holds its slot until QUIC finishes draining, so
// these bound concurrent-plus-draining peers, not concurrent ones.
const MAX_SUBS_PER_TRACK: usize = 32;
const MAX_STREAMS_PER_CLIENT: usize = 64;
const MAX_NAMESPACES: usize = 32;
const MAX_PENDING_SUBS: usize = 16;
const MAX_NAMESPACE_SUBS: usize = 16;
const DUMP_HEAD_BYTES: usize = 48; // of an undecodable message, for the log
const STREAM_BUF_SIZE: usize = 65_536; // VP8 keyframes typically ≤ 16 KB
const N_CACHED_GROUPS: usize = 2; // number of completed groups retained per track
const CACHE_GROUP_SIZE: usize = 256 * 1024; // 256 KB of object payload per group
/// Unsent bytes on one output stream past which its subscriber is too far
/// behind to go on queueing for (§9.3.3): it loses the subscription.
const MAX_OUT_BACKLOG: usize = 1024 * 1024;
/// Unsent bytes on a subscriber's connection past which it is replayed no
/// cached groups on top.
const MAX_SUB_BACKLOG: usize = 4 * 1024 * 1024;
/// How long a data stream naming an alias we don't know yet waits for the
/// control message that establishes it (§11.4.2: "a brief period").
const HELD_STREAM_MS: i128 = 2000;
/// Datagrams waiting the same way (§11.3); the oldest goes when full.
const MAX_HELD_DATAGRAMS: usize = 32;
const HELD_DATAGRAM_SIZE: usize = 1500;

/// `upstream`: a SUBSCRIBE the relay sent a namespace's publisher, whose
/// answer comes back on the same stream. `offer`: a PUBLISH the relay sent
/// a SUBSCRIBE_TRACKS subscriber, answered the same way.
const StreamRole = enum { control, request, upstream, offer, data, unknown };

// One completed (or in-progress) group's worth of object payload bytes cached
// at the relay, with the header the publisher opened the stream with — a late
// subscriber is replayed the same stream under its own track alias.
const CachedGroup = struct {
    valid: bool = false,
    hdr: moq_obj.SubgroupHeader = .{
        .track_alias = 0,
        .group = 0,
        .subgroup = 0,
        .publisher_priority = 128,
        .end_of_group = true,
        .per_object_properties = false,
    },
    payload: [CACHE_GROUP_SIZE]u8 = undefined,
    payload_len: usize = 0,

    fn reset(self: *CachedGroup) void {
        self.valid = false;
        self.payload_len = 0;
    }
};

/// One subscriber of a track.
const Sub = struct {
    client_idx: usize = 0,
    alias: u64 = 0,
    /// Its SUBSCRIBE stream — where its PUBLISH_DONE goes.
    stream_id: u64 = 0,
    /// Data streams opened for it, for PUBLISH_DONE's Stream Count.
    streams: u64 = 0,
    /// False while its SUBSCRIBE waits on the publisher's answer upstream.
    answered: bool = true,
    /// FORWARD (§9.3): 0 keeps the subscription but delivers no objects,
    /// until a REQUEST_UPDATE turns it on.
    forward: bool = true,
};

const Track = struct {
    namespace_buf: [256]u8 = undefined,
    namespace_len: usize = 0,
    name_buf: [128]u8 = undefined,
    name_len: usize = 0,
    publisher_idx: ?usize = null,
    pub_alias: u64 = 0,
    /// The bidi stream the publisher's PUBLISH arrived on; its PUBLISH_DONE
    /// comes back on the same one.
    pub_stream_id: ?u64 = null,
    /// The namespace publisher the relay subscribed to on its subscribers'
    /// behalf; `pub_stream_id` is that SUBSCRIBE's stream. Null for a track
    /// its publisher pushed with PUBLISH.
    upstream_idx: ?usize = null,
    /// SUBSCRIBE sent upstream, no answer yet.
    upstream_pending: bool = false,
    active: bool = false,
    /// Moves on whenever the slot's publication changes, reuse included: a
    /// data stream feeds the cache only while the one it began in stands.
    gen: u32 = 0,
    subs: [MAX_SUBS_PER_TRACK]Sub = @splat(.{}),
    sub_count: usize = 0,

    // Completed groups cached for late subscribers.
    cached: [N_CACHED_GROUPS]CachedGroup = @splat(.{}),
    next_cache_idx: usize = 0,
    // The live group being assembled from the publisher's current stream.
    live: CachedGroup = .{},
    /// The stream feeding `live`. A newer group's stream takes it over; the
    /// one it displaces goes uncached rather than mixed into the newer one.
    live_owner: ?struct { ci: usize, sid: u64 } = null,

    fn ownsLive(self: *const Track, ci: usize, sid: u64) bool {
        const o = self.live_owner orelse return false;
        return o.ci == ci and o.sid == sid;
    }

    fn removeSub(self: *Track, si: usize) void {
        self.sub_count -= 1;
        self.subs[si] = self.subs[self.sub_count];
    }

    /// Nobody publishes it and nobody wants it: the slot goes back.
    fn reapIfIdle(self: *Track) void {
        if (self.publisher_idx == null and self.upstream_idx == null and self.sub_count == 0) self.active = false;
    }

    fn matchesNsName(self: *const Track, ns: []const u8, name: []const u8) bool {
        return std.mem.eql(u8, self.namespace_buf[0..self.namespace_len], ns) and
            std.mem.eql(u8, self.name_buf[0..self.name_len], name);
    }

    // Forget everything the departed publisher left behind. The cache exists
    // so a late subscriber joins mid-broadcast without waiting for the next
    // group — but once the publisher is gone there is no broadcast, and
    // replaying it hands the next subscriber content from a session that has
    // already ended. moq-rs's test client catches this as
    // `publish-track-subscribe` receiving `publish-track-only`'s payload.
    fn dropPublisherState(self: *Track) void {
        self.gen +%= 1;
        self.publisher_idx = null;
        self.pub_alias = 0;
        self.pub_stream_id = null;
        self.upstream_idx = null;
        self.upstream_pending = false;
        for (&self.cached) |*g| g.valid = false;
        self.next_cache_idx = 0;
        self.live = .{};
        self.live_owner = null;
    }

    // Store a completed group; oldest entry is overwritten.
    fn cacheGroup(self: *Track, src: *const CachedGroup) void {
        self.cached[self.next_cache_idx] = src.*;
        self.cached[self.next_cache_idx].valid = true;
        self.next_cache_idx = (self.next_cache_idx + 1) % N_CACHED_GROUPS;
    }

    // Iterate cached groups from oldest to newest.
    fn cachedInOrder(self: *const Track, out: *[N_CACHED_GROUPS]*const CachedGroup) usize {
        var count: usize = 0;
        // Start at next_cache_idx (oldest slot) and walk forward.
        var i: usize = 0;
        while (i < N_CACHED_GROUPS) : (i += 1) {
            const idx = (self.next_cache_idx + i) % N_CACHED_GROUPS;
            if (self.cached[idx].valid) {
                out[count] = &self.cached[idx];
                count += 1;
            }
        }
        return count;
    }
};

/// One client's transport: its WebTransport session's streams, or, for a
/// native-QUIC client, the connection's own.
const Link = struct {
    s: event_loop.Session,
    raw: bool,
    wt_session_id: u64,

    fn send(self: *Link, stream_id: u64, bytes: []const u8) !void {
        return if (self.raw) self.s.writeStream(stream_id, bytes) else self.s.sendStreamData(stream_id, bytes);
    }
    fn openUni(self: *Link) !u64 {
        return if (self.raw) self.s.openQuicUniStream() else self.s.openUniStream(self.wt_session_id, null);
    }
    fn openBidi(self: *Link) !u64 {
        return if (self.raw) self.s.openStream() else self.s.openBidiStream(self.wt_session_id, null);
    }
    fn finish(self: *Link, stream_id: u64) void {
        if (self.raw) self.s.closeQuicStream(stream_id) else self.s.closeStream(stream_id);
    }
    fn reset(self: *Link, stream_id: u64, code: u64) void {
        if (self.raw) self.s.resetQuicStream(stream_id, code) else self.s.resetStream(stream_id, @truncate(code));
    }
    fn stopSending(self: *Link, stream_id: u64, code: u64) void {
        if (self.raw) {
            if (self.s.entry.conn.streams.getStream(stream_id)) |st| st.recv.stopSending(code);
            self.s.entry.wake();
        } else self.s.stopSending(stream_id, @truncate(code));
    }
    fn datagram(self: *Link, bytes: []const u8) !void {
        return if (self.raw) self.s.sendQuicDatagram(bytes) else self.s.sendDatagram(self.wt_session_id, bytes);
    }
    /// Ends the MoQ session with an application error: the WT session, or
    /// the whole connection for native QUIC, where they are one and the same.
    fn closeWithError(self: *Link, code: u64, reason: []const u8) void {
        if (self.raw) {
            self.s.entry.conn.close(code, reason);
            self.s.entry.wake();
        } else {
            self.s.closeSessionWithError(self.wt_session_id, @intCast(code), reason) catch self.s.closeSession(self.wt_session_id);
        }
    }
};

const Client = struct {
    active: bool = false,
    entry: ?*cm.ConnEntry = null,
    /// Native QUIC (`moqt-NN` ALPN) rather than a WebTransport session.
    raw: bool = false,
    /// Negotiated on the CONNECT. A peer that offers nothing gets
    /// draft-17, which is what the demo pages speak.
    draft: moq_version.Draft = .draft_17,
    wt_session_id: u64 = 0,
    control_out: ?u64 = null,
    setup_sent: bool = false,
    setup_received: bool = false,
    next_alias: u64 = 1,
    /// Requests the relay originates: odd, as the server's are.
    next_request_id: u64 = 1,
    stream_ids: [MAX_STREAMS_PER_CLIENT]u64 = @splat(std.math.maxInt(u64)),
    stream_roles: [MAX_STREAMS_PER_CLIENT]StreamRole = @splat(.unknown),
    stream_bufs: [MAX_STREAMS_PER_CLIENT]StreamBuf = @splat(.{}),
    fwd_states: [MAX_STREAMS_PER_CLIENT]FwdState = @splat(.{}),

    fn slotOf(self: *const Client, sid: u64) ?usize {
        return std.mem.indexOfScalar(u64, &self.stream_ids, sid);
    }

    fn findOrAddSlot(self: *Client, sid: u64) ?usize {
        for (self.stream_ids[0..], 0..) |id, i| {
            if (id == sid) return i;
        }
        for (self.stream_ids[0..], 0..) |id, i| {
            if (id == std.math.maxInt(u64)) {
                self.stream_ids[i] = sid;
                return i;
            }
        }
        return null;
    }

    fn setRole(self: *Client, sid: u64, role: StreamRole) void {
        if (self.findOrAddSlot(sid)) |i| self.stream_roles[i] = role;
    }
    fn getRole(self: *Client, sid: u64) StreamRole {
        if (self.findOrAddSlot(sid)) |i| return self.stream_roles[i];
        return .unknown;
    }
    fn buffer(self: *Client, sid: u64) ?*StreamBuf {
        if (self.findOrAddSlot(sid)) |i| return &self.stream_bufs[i];
        return null;
    }
    fn fwdState(self: *Client, sid: u64) ?*FwdState {
        if (self.findOrAddSlot(sid)) |i| return &self.fwd_states[i];
        return null;
    }
    fn clearSlot(self: *Client, sid: u64) void {
        for (self.stream_ids[0..], 0..) |id, i| {
            if (id == sid) {
                self.stream_ids[i] = std.math.maxInt(u64);
                self.stream_roles[i] = .unknown;
                self.stream_bufs[i].len = 0;
                self.fwd_states[i] = .{};
                return;
            }
        }
    }
};

const StreamBuf = struct {
    data: [STREAM_BUF_SIZE]u8 = undefined,
    len: usize = 0,

    fn append(self: *StreamBuf, bytes: []const u8) void {
        const n = @min(bytes.len, self.data.len - self.len);
        @memcpy(self.data[self.len .. self.len + n], bytes[0..n]);
        self.len += n;
    }
    fn reset(self: *StreamBuf) void {
        self.len = 0;
    }
    fn slice(self: *const StreamBuf) []const u8 {
        return self.data[0..self.len];
    }
};

// Per-input-stream forwarding state: remembers output streams to subscribers
// so we can forward incrementally as publisher data arrives (no need to wait
// for FIN).
const FwdState = struct {
    active: bool = false,
    header_parsed: bool = false,
    forwarded_pos: usize = 0, // byte offset in publisher stream (after subgroup header)
    track_idx: ?usize = null,
    track_gen: u32 = 0,
    out_stream_ids: [MAX_SUBS_PER_TRACK]u64 = @splat(0),
    out_sub_idx: [MAX_SUBS_PER_TRACK]usize = @splat(0),
    out_count: usize = 0,
    /// Set while the header names an alias nothing has established yet.
    held_since_ns: i128 = 0,
    /// The peer finished the stream while it was held.
    fin_seen: bool = false,
};

/// A namespace a client advertised with PUBLISH_NAMESPACE. A track under
/// an announced prefix can be subscribed to before its publisher opens it;
/// anything else does not exist here.
const AnnouncedNamespace = struct {
    buf: [256]u8 = undefined,
    len: usize = 0,
    client_idx: usize = 0,
    /// The PUBLISH_NAMESPACE (or PUBLISH) request stream; resetting it
    /// withdraws the namespace (§3.3.3).
    stream_id: u64 = 0,
    /// Registration order: of two announcers, the newer is routed to.
    seq: u64 = 0,
    /// Implied by a PUBLISH rather than announced: its stream's FIN ends a
    /// publication, which PUBLISH_DONE says, not a namespace.
    via_publish: bool = false,
    active: bool = false,

    fn key(self: *const AnnouncedNamespace) []const u8 {
        return self.buf[0..self.len];
    }
};

/// A SUBSCRIBE_NAMESPACE or SUBSCRIBE_TRACKS: this client wants to hear
/// about every namespace (NAMESPACE) or every track (PUBLISH) under a
/// prefix, the ones already here and the ones that arrive later (§6.1).
/// draft-17 asked for either or both in one message.
const NamespaceSub = struct {
    prefix_buf: [256]u8 = undefined,
    prefix_len: usize = 0,
    client_idx: usize = 0,
    stream_id: u64 = 0,
    namespaces: bool = true,
    tracks: bool = false,
    /// FORWARD on the request, copied into each PUBLISH it yields (§10.19).
    forward: bool = true,
    /// Overlap is checked within one space: draft-18's two messages each
    /// have their own (§10.19), draft-17's one message has one.
    space: enum { legacy, namespaces, tracks } = .legacy,
    active: bool = false,

    fn prefix(self: *const NamespaceSub) []const u8 {
        return self.prefix_buf[0..self.prefix_len];
    }
};

/// A SUBSCRIBE for an unannounced namespace, held open because the
/// subscriber sent a non-zero RENDEZVOUS_TIMEOUT (§9.3.4).
const PendingSub = struct {
    ns_buf: [256]u8 = undefined,
    ns_len: usize = 0,
    name_buf: [128]u8 = undefined,
    name_len: usize = 0,
    client_idx: usize = 0,
    stream_id: u64 = 0,
    deadline_ns: i128 = 0,
    forward: bool = true,
    filter: ?moq_msg.Filter = null,
    active: bool = false,
};

const HeldDatagram = struct {
    active: bool = false,
    client_idx: usize = 0,
    since_ns: i128 = 0,
    len: usize = 0,
    data: [HELD_DATAGRAM_SIZE]u8 = undefined,
};

const RelayHandler = struct {
    pub const protocol: event_loop.Protocol = .webtransport;
    /// Also take native-QUIC MoQT on the same port; see the header.
    pub const raw_quic = true;
    /// Rendezvous timeouts are ours to keep, and the loop otherwise only
    /// wakes on peer traffic.
    pub const poll_interval_ms: u64 = 50;

    clients: [MAX_CLIENTS]Client = @splat(.{}),
    tracks: [MAX_TRACKS]Track = @splat(.{}),
    track_count: usize = 0,
    namespaces: [MAX_NAMESPACES]AnnouncedNamespace = @splat(.{}),
    pending: [MAX_PENDING_SUBS]PendingSub = @splat(.{}),
    ns_subs: [MAX_NAMESPACE_SUBS]NamespaceSub = @splat(.{}),
    ns_seq: u64 = 0,
    held_dgrams: [MAX_HELD_DATAGRAMS]HeldDatagram = @splat(.{}),

    /// A WebTransport client is its one session.
    pub fn onSessionClosed(self: *RelayHandler, session: *event_loop.Session, _: u64, _: u32, _: []const u8) void {
        self.dropClient(session.entry);
    }

    /// The loop frees the entry right after this, so it stops being a valid
    /// key the moment we return: a native-QUIC client, which has no session
    /// to report, goes here. Without it a relay runs out of client slots.
    pub fn onConnectionClosed(self: *RelayHandler, session: *event_loop.Session) void {
        self.dropClient(session.entry);
    }

    fn dropClient(self: *RelayHandler, entry: *cm.ConnEntry) void {
        const ci = blk: {
            for (&self.clients, 0..) |*c, i| if (c.active and c.entry == entry) break :blk i;
            return;
        };
        std.debug.print("[relay] client {d} gone\n", .{ci});

        for (self.tracks[0..self.track_count]) |*t| {
            if (!t.active) continue;
            if (t.upstream_pending and t.upstream_idx == ci) {
                self.failWaitingSubs(t, moq_codes.ERR_INTERNAL_ERROR, "publisher gone");
            }
            if (t.publisher_idx == ci) {
                // §10.11: a subscription state is not destroyed until its
                // publisher says so. The publisher is gone and cannot, so the
                // relay says it on its behalf.
                self.endPublication(t, moq_codes.DONE_TRACK_ENDED, "publisher gone");
            }
            var si: usize = 0;
            while (si < t.sub_count) {
                if (t.subs[si].client_idx != ci) {
                    si += 1;
                    continue;
                }
                t.removeSub(si);
            }
            if (t.sub_count == 0 and t.upstream_idx != null and t.upstream_idx != ci) self.unsubscribeUpstream(t);
            t.reapIfIdle();
        }
        for (&self.ns_subs) |*n| {
            if (n.active and n.client_idx == ci) n.active = false;
        }
        for (&self.namespaces) |*n| {
            if (!n.active or n.client_idx != ci) continue;
            n.active = false;
            // Nobody else announced it, so as far as this relay is concerned
            // the namespace is gone and its subscribers should hear so.
            if (!self.namespaceHeld(n.key())) self.announceNamespace(n.key(), true);
        }
        for (&self.pending) |*pn| {
            if (pn.active and pn.client_idx == ci) pn.active = false;
        }
        // The slot's next client would have these read under its aliases.
        for (&self.held_dgrams) |*d| {
            if (d.active and d.client_idx == ci) d.active = false;
        }
        // Outputs other clients forward to it: the slot is about to be
        // reused, and its stream ids would name a newcomer's streams.
        for (&self.clients) |*c| {
            if (!c.active) continue;
            for (&c.fwd_states) |*fs| {
                var i: usize = 0;
                while (i < fs.out_count) {
                    if (fs.out_sub_idx[i] != ci) {
                        i += 1;
                        continue;
                    }
                    fs.out_count -= 1;
                    fs.out_sub_idx[i] = fs.out_sub_idx[fs.out_count];
                    fs.out_stream_ids[i] = fs.out_stream_ids[fs.out_count];
                }
            }
        }
        self.clients[ci] = .{};
    }

    fn findOrCreateClient(self: *RelayHandler, entry: *cm.ConnEntry) ?usize {
        for (&self.clients, 0..) |*c, i| {
            if (c.active and c.entry == entry) return i;
        }
        for (&self.clients, 0..) |*c, i| {
            if (!c.active) {
                c.* = .{ .active = true, .entry = entry };
                return i;
            }
        }
        return null;
    }

    /// The transport to reach client `ci`, whichever connection is being
    /// polled: replies to one peer are often triggered by another.
    fn link(self: *RelayHandler, ci: usize) ?Link {
        const c = &self.clients[ci];
        if (!c.active) return null;
        const entry = c.entry orelse return null;
        if (!c.raw and entry.wt_conn == null) return null;
        return .{ .s = .{ .entry = entry }, .raw = c.raw, .wt_session_id = c.wt_session_id };
    }

    /// A native-QUIC client: the ALPN already chose its draft, and both sides
    /// open a control stream with SETUP on it straight away.
    pub fn onQuicConnected(self: *RelayHandler, session: *event_loop.Session) void {
        const draft = moq_version.Draft.fromAlpn(session.alpn()) orelse {
            session.closeConnection();
            return;
        };
        const ci = self.findOrCreateClient(session.entry) orelse {
            std.debug.print("[relay] client table full; refusing connection\n", .{});
            session.closeConnection();
            return;
        };
        self.clients[ci].raw = true;
        self.clients[ci].draft = draft;
        self.sendSetup(ci) catch return;
        std.debug.print("[relay] client {d} connected (QUIC, {s})\n", .{ ci, draft.alpn() });
    }

    fn sendSetup(self: *RelayHandler, ci: usize) !void {
        var l = self.link(ci) orelse return error.NotConnected;
        const ctrl = l.openUni() catch |e| {
            std.debug.print("[relay] client {d}: no control stream: {t}\n", .{ ci, e });
            return e;
        };
        self.clients[ci].control_out = ctrl;

        var buf: [256]u8 = undefined;
        var fbs = io_compat.fixedBufferStream(&buf);
        try moq_msg.writeSetup(&fbs, .{ .implementation = "quic-zig/moq-relay" });
        l.send(ctrl, buf[0..fbs.seek]) catch |e| {
            std.debug.print("[relay] client {d}: SETUP not sent: {t}\n", .{ ci, e });
            return e;
        };
        self.clients[ci].setup_sent = true;
    }

    fn findTrack(self: *RelayHandler, ns_key: []const u8, name: []const u8) ?usize {
        for (self.tracks[0..self.track_count], 0..) |*t, i| {
            if (t.active and t.matchesNsName(ns_key, name)) return i;
        }
        return null;
    }

    pub fn onConnectRequest(
        self: *RelayHandler,
        session: *event_loop.Session,
        session_id: u64,
        _: []const u8,
        headers: []const qpack.Header,
    ) void {
        // draft-ietf-webtrans-http3-13 §3.3 is how a MoQ version is chosen
        // over WebTransport; the QUIC ALPN stays "h3".
        var alpn_buf: [4][]const u8 = undefined;
        const supported = moq_version.alpnOffer(moq_version.PREFERRED, &alpn_buf);
        var scratch: [256]u8 = undefined;
        var value_buf: [64]u8 = undefined;

        var chosen: moq_version.Draft = .draft_17;
        var accepted = false;
        if (wt_protocol.findHeader(headers, wt_protocol.HEADER_AVAILABLE)) |offer| {
            if (wt_protocol.selectFromOffer(offer, supported, &scratch)) |name| {
                chosen = moq_version.Draft.fromAlpn(name) orelse .draft_17;
                if (wt_protocol.encodeItem(name, &value_buf)) |encoded| {
                    const extra = [_]qpack.Header{
                        .{ .name = wt_protocol.HEADER_SELECTED, .value = encoded },
                    };
                    session.acceptSessionWithHeaders(session_id, &extra) catch return;
                    accepted = true;
                } else |_| {}
            }
        }
        if (!accepted) session.acceptSession(session_id) catch return;

        const ci = self.findOrCreateClient(session.entry) orelse {
            var live: usize = 0;
            for (&self.clients) |*c| {
                if (c.active) live += 1;
            }
            std.debug.print("[relay] client table full ({d} active); refusing session\n", .{live});
            session.closeSession(session_id);
            return;
        };
        self.clients[ci].wt_session_id = session_id;
        self.clients[ci].draft = chosen;
        self.sendSetup(ci) catch return;
        std.debug.print("[relay] client {d} connected (WT session {d}, {s})\n", .{
            ci, session_id, self.clients[ci].draft.alpn(),
        });
    }

    pub fn onUniStream(_: *RelayHandler, _: *event_loop.Session, _: u64, _: u64) void {}

    pub fn onBidiStream(self: *RelayHandler, session: *event_loop.Session, _: u64, stream_id: u64) void {
        const ci = self.findOrCreateClient(session.entry) orelse return;
        self.clients[ci].setRole(stream_id, .request);
    }

    pub fn onStreamData(self: *RelayHandler, session: *event_loop.Session, stream_id: u64, data: []const u8, fin: bool) void {
        const ci = self.findOrCreateClient(session.entry) orelse return;

        if (data.len > 0) {
            const buf = self.clients[ci].buffer(stream_id) orelse return;
            buf.append(data);
        }

        // Native QUIC has no onBidiStream: a client-opened bidi stream is a
        // request, the same thing a WebTransport one is.
        if (self.clients[ci].raw and self.clients[ci].getRole(stream_id) == .unknown and stream_id & 0x2 == 0) {
            self.clients[ci].setRole(stream_id, .request);
        }

        const role = self.clients[ci].getRole(stream_id);
        switch (role) {
            .unknown => self.tryParseNewStream(ci, session, stream_id, fin),
            .control => {},
            .request => self.tryParseRequest(ci, session, stream_id),
            .upstream => self.tryParseUpstream(ci, stream_id),
            .offer => self.tryParseOffer(ci, stream_id),
            .data => self.tryForwardData(ci, stream_id, fin),
        }

        // Reclaim slot when stream is done — data streams close after each object.
        if (fin) {
            const c = &self.clients[ci];
            switch (c.getRole(stream_id)) {
                .upstream => {
                    self.upstreamFinished(ci, stream_id);
                    c.clearSlot(stream_id);
                },
                .data => if (!self.holdUnrouted(ci, stream_id)) c.clearSlot(stream_id),
                .unknown => c.clearSlot(stream_id),
                .request => if (moq_version.Rules.of(c.draft).fin_withdraws_request) self.requestFinished(ci, stream_id),
                .control, .offer => {},
            }
        }
    }

    /// A finished stream whose header names an alias nothing has established
    /// yet keeps its bytes: the publisher's answer that does may be right
    /// behind it (§11.4.2). Returns whether it was held.
    fn holdUnrouted(self: *RelayHandler, ci: usize, stream_id: u64) bool {
        const fs = self.clients[ci].fwdState(stream_id) orelse return false;
        if (fs.header_parsed or fs.held_since_ns == 0) return false;
        fs.fin_seen = true;
        return true;
    }

    /// An alias was just established for publisher `ci`: forward whatever
    /// was waiting on it.
    fn retryHeld(self: *RelayHandler, ci: usize) void {
        const c = &self.clients[ci];
        for (0..MAX_STREAMS_PER_CLIENT) |i| {
            const fs = &c.fwd_states[i];
            if (c.stream_roles[i] != .data or fs.header_parsed or fs.held_since_ns == 0) continue;
            const sid = c.stream_ids[i];
            const fin = fs.fin_seen;
            self.tryForwardData(ci, sid, fin);
            if (fin and fs.header_parsed) c.clearSlot(sid);
        }
        for (&self.held_dgrams) |*d| {
            if (!d.active or d.client_idx != ci) continue;
            if (self.forwardDatagram(ci, d.data[0..d.len])) d.active = false;
        }
    }

    fn expireHeld(self: *RelayHandler, now: i128) void {
        for (&self.held_dgrams) |*d| {
            if (d.active and now - d.since_ns >= HELD_STREAM_MS * std.time.ns_per_ms) d.active = false;
        }
        for (&self.clients, 0..) |*c, ci| {
            if (!c.active) continue;
            for (0..MAX_STREAMS_PER_CLIENT) |i| {
                const fs = &c.fwd_states[i];
                if (c.stream_roles[i] != .data or fs.header_parsed or fs.held_since_ns == 0) continue;
                if (now - fs.held_since_ns < HELD_STREAM_MS * std.time.ns_per_ms) continue;
                const sid = c.stream_ids[i];
                if (!fs.fin_seen) {
                    if (self.link(ci)) |l_| {
                        var l = l_;
                        l.stopSending(sid, 0x1); // CANCELLED
                    }
                }
                std.debug.print("[relay] client {d} stream {d}: alias never established; dropped\n", .{ ci, sid });
                c.clearSlot(sid);
            }
        }
    }

    /// Drafts 17 and 18: a requester's FIN withdraws what it announced or
    /// subscribed to on that stream. A SUBSCRIBE or PUBLISH is left alone —
    /// their ends are said with PUBLISH_DONE or a reset.
    fn requestFinished(self: *RelayHandler, ci: usize, stream_id: u64) void {
        var ended = false;
        for (&self.namespaces) |*n| {
            if (!n.active or n.via_publish or n.client_idx != ci or n.stream_id != stream_id) continue;
            n.active = false;
            ended = true;
            std.debug.print("[relay] namespace \"{s}\" withdrawn by client {d}\n", .{ n.key(), ci });
            if (!self.namespaceHeld(n.key())) self.announceNamespace(n.key(), true);
        }
        for (&self.ns_subs) |*n| {
            if (!n.active or n.client_idx != ci or n.stream_id != stream_id) continue;
            n.active = false;
            ended = true;
        }
        if (!ended) return;
        self.closeClientStream(ci, stream_id);
        self.clients[ci].clearSlot(stream_id);
    }

    fn tryParseNewStream(self: *RelayHandler, ci: usize, session: *event_loop.Session, stream_id: u64, fin: bool) void {
        // This only runs for peer-initiated UNI streams (bidi streams get .request
        // set in onBidiStream). Uni streams carry either SETUP (first one) or
        // object data (subgroup streams).
        _ = session;
        const buf = self.clients[ci].buffer(stream_id) orelse return;
        if (buf.len < 3) return;

        // Peek at the type varint to distinguish SETUP from a subgroup header.
        // SETUP (0x2F00) is a 2-byte varint; subgroup stream types are single
        // bytes in 0x10..0x3D. If the first byte has the 0x80 bit set and is
        // one of the SETUP pattern bytes, treat as control. Otherwise data.
        var peek = io_compat.fixedBufferStream(@as([]const u8, buf.slice()));
        const first_varint = moq_wire.readVarInt(&peek) catch {
            self.clients[ci].setRole(stream_id, .data);
            self.tryForwardData(ci, stream_id, fin);
            return;
        };

        if (first_varint == moq_codes.MSG_SETUP) {
            // Confirm by parsing the full envelope.
            if (moq_msg.parseEnvelope(buf.slice())) |parsed| {
                self.clients[ci].setRole(stream_id, .control);
                self.clients[ci].setup_received = true;
                std.debug.print("[relay] client {d} SETUP received\n", .{ci});
                const remaining = buf.slice()[parsed.consumed..];
                std.mem.copyForwards(u8, &buf.data, remaining);
                buf.len = remaining.len;
                return;
            } else |_| return; // need more data
        }

        // Data stream (subgroup header).
        self.clients[ci].setRole(stream_id, .data);
        self.tryForwardData(ci, stream_id, fin);
    }

    fn tryParseRequest(self: *RelayHandler, ci: usize, session: *event_loop.Session, stream_id: u64) void {
        const buf = self.clients[ci].buffer(stream_id) orelse return;
        // A peer may coalesce a request with the update that follows it.
        while (buf.len >= 3) {
            const parsed = moq_msg.parseEnvelope(buf.slice()) catch return;
            self.handleRequest(ci, session, stream_id, parsed.env);
            const remaining = buf.slice()[parsed.consumed..];
            std.mem.copyForwards(u8, &buf.data, remaining);
            buf.len = remaining.len;
        }
    }

    fn handleRequest(self: *RelayHandler, ci: usize, session: *event_loop.Session, stream_id: u64, env: moq_msg.Envelope) void {
        switch (env.type) {
            moq_codes.MSG_SUBSCRIBE => self.handleSubscribe(ci, session, stream_id, env.payload),
            moq_codes.MSG_PUBLISH => self.handlePublish(ci, session, stream_id, env.payload),
            moq_codes.MSG_PUBLISH_NAMESPACE => self.handlePublishNamespace(ci, session, stream_id, env.payload),
            moq_codes.MSG_PUBLISH_DONE => self.handlePublishDone(ci, stream_id, env.payload),
            moq_codes.MSG_SUBSCRIBE_NAMESPACE,
            moq_codes.MSG_SUBSCRIBE_NAMESPACE_18,
            => self.handleSubscribeNamespace(ci, session, stream_id, env.type, env.payload),
            moq_codes.MSG_SUBSCRIBE_TRACKS => if (moq_version.Rules.of(self.clients[ci].draft).has_subscribe_tracks) {
                self.handleSubscribeNamespace(ci, session, stream_id, env.type, env.payload);
            } else {
                std.debug.print("[relay] client {d} SUBSCRIBE_TRACKS before draft-18\n", .{ci});
            },
            moq_codes.MSG_REQUEST_UPDATE => self.handleRequestUpdate(ci, stream_id, env.payload),
            else => std.debug.print("[relay] client {d} request type=0x{x}\n", .{ ci, env.type }),
        }
    }

    /// §9.10: an update rides the stream of the subscription it changes.
    fn handleRequestUpdate(self: *RelayHandler, ci: usize, stream_id: u64, payload: []const u8) void {
        const u = moq_msg.decodeRequestUpdate(payload, self.clients[ci].draft) catch |e| {
            std.debug.print("[relay] undecodable REQUEST_UPDATE client={d}: {t}\n", .{ ci, e });
            return;
        };
        const fwd = u.forward orelse return;
        for (self.tracks[0..self.track_count]) |*t| {
            if (!t.active) continue;
            for (t.subs[0..t.sub_count]) |*sub| {
                if (sub.client_idx != ci or sub.stream_id != stream_id) continue;
                sub.forward = fwd;
                std.debug.print("[relay] REQUEST_UPDATE client={d} forward={}\n", .{ ci, fwd });
            }
        }
    }

    fn sendOnStream(_: *RelayHandler, session: *event_loop.Session, stream_id: u64, bytes: []const u8) void {
        if (session.isRawQuic()) {
            session.writeStream(stream_id, bytes) catch {};
        } else {
            session.sendStreamData(stream_id, bytes) catch {};
        }
    }

    /// Sends to a client other than the one being polled. onPollComplete
    /// runs per connection, so a held subscription's deadline can expire
    /// while some unrelated peer's session is the one in hand.
    fn sendToClient(self: *RelayHandler, ci: usize, stream_id: u64, bytes: []const u8) void {
        var l = self.link(ci) orelse return;
        l.send(stream_id, bytes) catch {};
    }

    fn sendToClientError(self: *RelayHandler, ci: usize, stream_id: u64, code: u64, reason: []const u8) void {
        var buf: [256]u8 = undefined;
        var fbs = io_compat.fixedBufferStream(&buf);
        moq_msg.writeRequestError(&fbs, .{ .error_code = code, .reason = reason }) catch return;
        self.sendToClient(ci, stream_id, buf[0..fbs.seek]);
    }

    fn sendRequestOk(self: *RelayHandler, session: *event_loop.Session, stream_id: u64) void {
        var buf: [64]u8 = undefined;
        var fbs = io_compat.fixedBufferStream(&buf);
        moq_msg.writeRequestOk(&fbs, .{}) catch return;
        self.sendOnStream(session, stream_id, buf[0..fbs.seek]);
    }

    fn sendRequestError(self: *RelayHandler, session: *event_loop.Session, stream_id: u64, code: u64, reason: []const u8) void {
        var buf: [256]u8 = undefined;
        var fbs = io_compat.fixedBufferStream(&buf);
        moq_msg.writeRequestError(&fbs, .{ .error_code = code, .reason = reason }) catch return;
        self.sendOnStream(session, stream_id, buf[0..fbs.seek]);
        std.debug.print("[relay] REQUEST_ERROR → client: code={d} {s}\n", .{ code, reason });
    }

    /// What a request we could not decode earns. Values the draft says MUST
    /// close the session with PROTOCOL_VIOLATION — an undefined Subscription
    /// Filter type (§5.1.2), an unknown Message Parameter (§10.2), a
    /// GROUP_ORDER or FORWARD outside its range — are told apart from a
    /// message that is merely malformed by the codec, not by each call site.
    fn rejectRequest(
        self: *RelayHandler,
        ci: usize,
        session: *event_loop.Session,
        stream_id: u64,
        e: anyerror,
        what: []const u8,
        payload: []const u8,
    ) void {
        // Bounded: the envelope allows 64 KB and a peer can send malformed
        // messages in a loop, so the head is what gets logged.
        std.debug.print("[relay] undecodable {s} client={d}: {t} payload({d}B)={x}\n", .{
            what, ci, e, payload.len, payload[0..@min(payload.len, DUMP_HEAD_BYTES)],
        });
        if (e == error.ProtocolViolation) {
            std.debug.print("[relay] PROTOCOL_VIOLATION → client {d}: {s}\n", .{ ci, what });
            if (self.link(ci)) |l_| {
                var l = l_;
                l.closeWithError(moq_codes.SESSION_PROTOCOL_VIOLATION, what);
            }
        } else {
            self.sendRequestError(session, stream_id, moq_codes.ERR_MALFORMED_TRACK, what);
        }
    }

    /// §6.1 discovery: answer REQUEST_OK, then NAMESPACE for every namespace
    /// (SUBSCRIBE_NAMESPACE) or PUBLISH for every track (SUBSCRIBE_TRACKS)
    /// already under the prefix. Later arrivals are pushed by
    /// announceNamespace and offerToWatchers.
    fn handleSubscribeNamespace(self: *RelayHandler, ci: usize, session: *event_loop.Session, stream_id: u64, msg_type: u64, payload: []const u8) void {
        const draft = self.clients[ci].draft;
        var ns_buf: moq_msg.NamespaceBuf = undefined;
        const sn = moq_msg.decodeSubscribeNamespace(payload, &ns_buf, draft) catch |e| {
            self.rejectRequest(ci, session, stream_id, e, "subscribe_namespace", payload);
            return;
        };

        var req: NamespaceSub = .{ .client_idx = ci, .stream_id = stream_id, .forward = sn.forward orelse true };
        if (moq_version.Rules.of(draft).has_subscribe_tracks) {
            const tracks = msg_type == moq_codes.MSG_SUBSCRIBE_TRACKS;
            req.namespaces = !tracks;
            req.tracks = tracks;
            req.space = if (tracks) .tracks else .namespaces;
        } else {
            req.namespaces = sn.options != .publish;
            req.tracks = sn.options != .namespace;
        }
        req.prefix_len = moq_wire.flattenNamespace(sn.track_namespace_prefix, &req.prefix_buf) orelse {
            self.sendRequestError(session, stream_id, moq_codes.ERR_NAMESPACE_TOO_LARGE, "namespace prefix too long");
            return;
        };
        // §10.18/§10.19: nested prefixes in one space, one session.
        for (&self.ns_subs) |*n| {
            if (!n.active or n.client_idx != ci or n.space != req.space) continue;
            if (std.mem.startsWith(u8, n.prefix(), req.prefix()) or std.mem.startsWith(u8, req.prefix(), n.prefix())) {
                self.sendRequestError(session, stream_id, moq_codes.ERR_PREFIX_OVERLAP, "prefix overlaps an existing subscription");
                return;
            }
        }
        const slot = for (&self.ns_subs) |*n| {
            if (!n.active) break n;
        } else {
            self.sendRequestError(session, stream_id, moq_codes.ERR_EXCESSIVE_LOAD, "too many namespace subscriptions");
            return;
        };
        slot.* = req;
        slot.active = true;

        self.sendRequestOk(session, stream_id);
        std.debug.print("[relay] {s} client={d} prefix=\"{s}\"\n", .{
            if (msg_type == moq_codes.MSG_SUBSCRIBE_TRACKS) "SUBSCRIBE_TRACKS" else "SUBSCRIBE_NAMESPACE", ci, slot.prefix(),
        });

        if (slot.namespaces) {
            var sent: usize = 0;
            for (&self.namespaces) |*n| {
                if (!n.active) continue;
                if (!std.mem.startsWith(u8, n.key(), slot.prefix())) continue;
                self.sendNamespace(slot, n.key(), false);
                sent += 1;
            }
            if (sent > 0) std.debug.print("[relay] → {d} NAMESPACE to client {d}\n", .{ sent, ci });
        }
        if (slot.tracks) {
            for (self.tracks[0..self.track_count]) |*t| {
                if (self.offerable(t, slot)) self.offerPublish(t, slot);
            }
        }
    }

    /// §6.1: a track under the watcher's prefix that someone else publishes
    /// and the watcher doesn't already take.
    fn offerable(self: *RelayHandler, t: *const Track, w: *const NamespaceSub) bool {
        _ = self;
        if (!t.active or !w.active or !w.tracks) return false;
        const publisher = t.publisher_idx orelse return false;
        if (publisher == w.client_idx) return false;
        if (!std.mem.startsWith(u8, t.namespace_buf[0..t.namespace_len], w.prefix())) return false;
        for (t.subs[0..t.sub_count]) |sub| {
            if (sub.client_idx == w.client_idx) return false;
        }
        return true;
    }

    /// Every SUBSCRIBE_TRACKS that matches `t` gets a PUBLISH for it.
    fn offerToWatchers(self: *RelayHandler, t: *Track) void {
        for (&self.ns_subs) |*w| {
            if (self.offerable(t, w)) self.offerPublish(t, w);
        }
    }

    /// The relay publishes `t` to the watcher on a bidi stream of its own,
    /// and forwards nothing until the watcher accepts.
    fn offerPublish(self: *RelayHandler, t: *Track, w: *const NamespaceSub) void {
        if (t.sub_count >= MAX_SUBS_PER_TRACK) return;
        const ci = w.client_idx;
        var l = self.link(ci) orelse return;
        const c = &self.clients[ci];
        const alias = c.next_alias;

        var parts: [moq_wire.MAX_TUPLE_PARTS][]const u8 = undefined;
        var fields: [256]u8 = undefined;
        var buf: [512]u8 = undefined;
        var fbs = io_compat.fixedBufferStream(&buf);
        moq_msg.writePublish(&fbs, .{
            .request_id = c.next_request_id,
            .track_namespace = moq_wire.splitNamespace(t.namespace_buf[0..t.namespace_len], &parts, &fields),
            .track_name = t.name_buf[0..t.name_len],
            .track_alias = alias,
            .forward = if (w.forward) null else false,
        }, c.draft) catch return;
        const sid = l.openBidi() catch return;
        l.send(sid, buf[0..fbs.seek]) catch return;
        c.next_request_id += 2;
        c.next_alias += 1;
        c.setRole(sid, .offer);
        t.subs[t.sub_count] = .{
            .client_idx = ci,
            .alias = alias,
            .stream_id = sid,
            .answered = false,
            .forward = w.forward,
        };
        t.sub_count += 1;
        std.debug.print("[relay] PUBLISH → client {d} ns=\"{s}\" track=\"{s}\" alias={d}\n", .{
            ci, t.namespace_buf[0..t.namespace_len], t.name_buf[0..t.name_len], alias,
        });
    }

    /// The watcher's answer to a PUBLISH the relay offered it.
    fn tryParseOffer(self: *RelayHandler, ci: usize, stream_id: u64) void {
        const buf = self.clients[ci].buffer(stream_id) orelse return;
        while (true) {
            const parsed = moq_msg.parseEnvelope(buf.slice()) catch return;
            const ok_type: u64 = if (moq_version.Rules.of(self.clients[ci].draft).publish_ok_is_own_message)
                moq_codes.MSG_PUBLISH_OK
            else
                moq_codes.MSG_REQUEST_OK;
            const found = self.findSub(ci, stream_id);
            if (parsed.env.type == ok_type) {
                if (found) |f| if (!f.sub.answered) {
                    const ok = moq_msg.decodePublishOk(parsed.env.payload) catch moq_msg.PublishOk{};
                    f.sub.answered = true;
                    if (ok.forward) |fwd| f.sub.forward = fwd;
                    std.debug.print("[relay] PUBLISH accepted by client {d} alias={d}\n", .{ ci, f.sub.alias });
                    self.replayCachedGroups(f.track, f.sub);
                };
            } else if (parsed.env.type == moq_codes.MSG_REQUEST_ERROR) {
                std.debug.print("[relay] PUBLISH refused by client {d}\n", .{ci});
                self.requestWithdrawn(ci, stream_id);
                return self.endUpstream(ci, stream_id);
            } else if (parsed.env.type == moq_codes.MSG_REQUEST_UPDATE) {
                self.handleRequestUpdate(ci, stream_id, parsed.env.payload);
            } else {
                std.debug.print("[relay] offer client {d} type=0x{x}\n", .{ ci, parsed.env.type });
            }
            const remaining = buf.slice()[parsed.consumed..];
            std.mem.copyForwards(u8, &buf.data, remaining);
            buf.len = remaining.len;
        }
    }

    fn findSub(self: *RelayHandler, ci: usize, stream_id: u64) ?struct { track: *Track, sub: *Sub } {
        for (self.tracks[0..self.track_count]) |*t| {
            if (!t.active) continue;
            for (t.subs[0..t.sub_count]) |*sub| {
                if (sub.client_idx == ci and sub.stream_id == stream_id) return .{ .track = t, .sub = sub };
            }
        }
        return null;
    }

    /// NAMESPACE / NAMESPACE_DONE carry only what follows the prefix the
    /// subscription asked for (§10.16), so the suffix is cut here rather than
    /// the whole namespace being echoed back.
    fn sendNamespace(self: *RelayHandler, sub: *const NamespaceSub, ns_key: []const u8, done: bool) void {
        var parts: [moq_wire.MAX_TUPLE_PARTS][]const u8 = undefined;
        var fields: [256]u8 = undefined;
        var buf: [512]u8 = undefined;
        var fbs = io_compat.fixedBufferStream(&buf);
        const msg = moq_msg.Namespace{
            .track_namespace_suffix = moq_wire.splitNamespace(ns_key[sub.prefix_len..], &parts, &fields),
        };
        if (done) {
            moq_msg.writeNamespaceDone(&fbs, msg) catch return;
        } else {
            moq_msg.writeNamespace(&fbs, msg) catch return;
        }
        self.sendToClient(sub.client_idx, sub.stream_id, buf[0..fbs.seek]);
    }

    /// Tell every namespace subscription whose prefix matches that `ns_key`
    /// has appeared (or, with `done`, gone).
    fn announceNamespace(self: *RelayHandler, ns_key: []const u8, done: bool) void {
        for (&self.ns_subs) |*n| {
            if (!n.active) continue;
            if (!std.mem.startsWith(u8, ns_key, n.prefix())) continue;
            self.sendNamespace(n, ns_key, done);
        }
    }

    fn handlePublishNamespace(self: *RelayHandler, ci: usize, session: *event_loop.Session, stream_id: u64, payload: []const u8) void {
        var ns_buf: moq_msg.NamespaceBuf = undefined;
        const pn = moq_msg.decodePublishNamespace(payload, &ns_buf, self.clients[ci].draft) catch |e| {
            self.rejectRequest(ci, session, stream_id, e, "publish_namespace", payload);
            return;
        };
        var key: [256]u8 = undefined;
        const key_len = moq_wire.flattenNamespace(pn.track_namespace, &key) orelse {
            self.sendRequestError(session, stream_id, moq_codes.ERR_NAMESPACE_TOO_LARGE, "namespace too long");
            return;
        };
        std.debug.print("[relay] PUBLISH_NAMESPACE client={d} ns=\"{s}\"\n", .{ ci, key[0..key_len] });

        const outcome = self.registerNamespace(ci, stream_id, key[0..key_len], false);
        if (outcome == .full) {
            self.sendRequestError(session, stream_id, moq_codes.ERR_EXCESSIVE_LOAD, "namespace table full");
            return;
        }
        self.sendRequestOk(session, stream_id);
        // §6.2: a relay holding a namespace MUST tell anyone subscribed to a
        // prefix of it — once, when it appears, not again per announcer.
        if (outcome == .added) self.announceNamespace(key[0..key_len], false);
        self.resolvePending(key[0..key_len]);
    }

    const Registered = enum { added, already_held, full };

    /// One pass answers both questions the caller has: is there room, and is
    /// this namespace new here? It is new only if nobody else holds it, which
    /// is what keeps NAMESPACE to one per namespace rather than one per
    /// announcer.
    fn registerNamespace(self: *RelayHandler, ci: usize, stream_id: u64, key: []const u8, via_publish: bool) Registered {
        if (key.len > 256) return .full;
        var free: ?*AnnouncedNamespace = null;
        var held_by_other = false;
        for (&self.namespaces) |*n| {
            if (!n.active) {
                if (free == null) free = n;
            } else if (std.mem.eql(u8, n.key(), key)) {
                if (n.client_idx == ci) return .already_held;
                held_by_other = true;
            }
        }
        const slot = free orelse return .full;
        @memcpy(slot.buf[0..key.len], key);
        slot.len = key.len;
        slot.client_idx = ci;
        slot.stream_id = stream_id;
        slot.via_publish = via_publish;
        self.ns_seq += 1;
        slot.seq = self.ns_seq;
        slot.active = true;
        return if (held_by_other) .already_held else .added;
    }

    /// Someone still announces exactly `key`. NAMESPACE names one namespace,
    /// so a publisher of a shorter prefix doesn't keep it alive.
    fn namespaceHeld(self: *RelayHandler, key: []const u8) bool {
        for (&self.namespaces) |*n| {
            if (n.active and std.mem.eql(u8, n.key(), key)) return true;
        }
        return false;
    }

    fn namespaceAnnounced(self: *RelayHandler, ns: []const u8) bool {
        for (&self.namespaces) |*n| {
            if (n.active and std.mem.startsWith(u8, ns, n.key())) return true;
        }
        return false;
    }

    fn holdPending(self: *RelayHandler, ci: usize, stream_id: u64, ns: []const u8, name: []const u8, wait_ms: u64, forward: bool, filter: ?moq_msg.Filter) bool {
        if (ns.len > 256 or name.len > 128) return false;
        for (&self.pending) |*p| {
            if (p.active) continue;
            @memcpy(p.ns_buf[0..ns.len], ns);
            p.ns_len = ns.len;
            @memcpy(p.name_buf[0..name.len], name);
            p.name_len = name.len;
            p.client_idx = ci;
            p.stream_id = stream_id;
            p.deadline_ns = sys.nanoTimestamp() + @as(i128, @intCast(wait_ms)) * 1_000_000;
            p.forward = forward;
            p.filter = filter;
            p.active = true;
            return true;
        }
        return false;
    }

    /// Answers any held subscription this namespace now satisfies. The
    /// waiting subscriber is a different connection from the publisher
    /// whose PUBLISH_NAMESPACE got us here, so replies go through its own.
    fn resolvePending(self: *RelayHandler, ns_key: []const u8) void {
        for (&self.pending) |*p| {
            if (!p.active) continue;
            if (!std.mem.startsWith(u8, p.ns_buf[0..p.ns_len], ns_key)) continue;
            p.active = false;
            self.admitSubscriber(p.client_idx, p.stream_id, p.ns_buf[0..p.ns_len], p.name_buf[0..p.name_len], p.forward, p.filter);
        }
    }

    pub fn onPollComplete(self: *RelayHandler, _: *event_loop.Session) void {
        const now = sys.nanoTimestamp();
        self.expireHeld(now);
        for (&self.pending) |*p| {
            if (!p.active or now < p.deadline_ns) continue;
            p.active = false;
            var buf: [256]u8 = undefined;
            var fbs = io_compat.fixedBufferStream(&buf);
            moq_msg.writeRequestError(&fbs, .{
                .error_code = moq_codes.ERR_TIMEOUT,
                .reason = "rendezvous timeout",
            }) catch continue;
            self.sendToClient(p.client_idx, p.stream_id, buf[0..fbs.seek]);
            std.debug.print("[relay] rendezvous timeout → client {d}\n", .{p.client_idx});
        }
    }

    fn handleSubscribe(self: *RelayHandler, ci: usize, session: *event_loop.Session, stream_id: u64, payload: []const u8) void {
        var ns_buf: moq_msg.NamespaceBuf = undefined;
        // moxygen sends its private LargestGroup filter (250); serving it the
        // latest object beats closing its session over it.
        const sub = moq_msg.decodeSubscribeWith(payload, &ns_buf, self.clients[ci].draft, .{
            .unknown_filter_as = .latest_object,
        }) catch |e| {
            self.rejectRequest(ci, session, stream_id, e, "subscribe", payload);
            return;
        };

        var ns_key: [256]u8 = undefined;
        const ns_len = moq_wire.flattenNamespace(sub.track_namespace, &ns_key) orelse {
            self.sendRequestError(session, stream_id, moq_codes.ERR_NAMESPACE_TOO_LARGE, "namespace too long");
            return;
        };
        std.debug.print("[relay] SUBSCRIBE client={d} ns=\"{s}\" track=\"{s}\"\n", .{ ci, ns_key[0..ns_len], sub.track_name });

        // §9.3.4: with no RENDEZVOUS_TIMEOUT — the default is 0 — a
        // subscriber wants DOES_NOT_EXIST now, not an open subscription.
        if (self.findTrack(ns_key[0..ns_len], sub.track_name) == null and
            !self.namespaceAnnounced(ns_key[0..ns_len]))
        {
            const wait_ms = sub.rendezvous_timeout_ms orelse 0;
            if (wait_ms == 0) {
                self.sendRequestError(session, stream_id, moq_codes.ERR_DOES_NOT_EXIST, "no such namespace");
                return;
            }
            if (!self.holdPending(ci, stream_id, ns_key[0..ns_len], sub.track_name, wait_ms, sub.forward orelse true, sub.filter)) {
                self.sendRequestError(session, stream_id, moq_codes.ERR_EXCESSIVE_LOAD, "too many pending subscriptions");
            }
            return;
        }

        self.admitSubscriber(ci, stream_id, ns_key[0..ns_len], sub.track_name, sub.forward orelse true, sub.filter);
    }

    /// A free track slot, reusing one a finished track left behind.
    fn allocTrack(self: *RelayHandler, ns_key: []const u8, name: []const u8) ?usize {
        if (ns_key.len > 256 or name.len > 128) return null;
        const idx = for (self.tracks[0..self.track_count], 0..) |*t, i| {
            if (!t.active) break i;
        } else blk: {
            if (self.track_count >= MAX_TRACKS) return null;
            self.track_count += 1;
            break :blk self.track_count - 1;
        };
        const t = &self.tracks[idx];
        t.* = .{ .active = true, .gen = t.gen +% 1 };
        @memcpy(t.namespace_buf[0..ns_key.len], ns_key);
        t.namespace_len = ns_key.len;
        @memcpy(t.name_buf[0..name.len], name);
        t.name_len = name.len;
        return idx;
    }

    /// The client that announced the longest prefix of `ns`: the one a
    /// subscription under it is routed to.
    fn namespaceOwner(self: *RelayHandler, ns: []const u8) ?usize {
        var best: ?*const AnnouncedNamespace = null;
        for (&self.namespaces) |*n| {
            if (!n.active or !std.mem.startsWith(u8, ns, n.key())) continue;
            // A closing connection keeps its slot until QUIC finishes
            // draining, but it will never answer a SUBSCRIBE.
            if (!self.clientLive(n.client_idx)) continue;
            if (best == null or n.len > best.?.len or (n.len == best.?.len and n.seq > best.?.seq)) best = n;
        }
        return if (best) |b| b.client_idx else null;
    }

    fn clientLive(self: *RelayHandler, ci: usize) bool {
        const c = &self.clients[ci];
        const entry = c.entry orelse return false;
        if (!c.active) return false;
        return switch (entry.conn.state) {
            .closing, .draining, .terminated => false,
            else => true,
        };
    }

    /// The peer cancelled a request by resetting its stream: an announcement,
    /// a subscription, or a namespace subscription it no longer wants.
    pub fn onStreamReset(self: *RelayHandler, session: *event_loop.Session, _: u64, stream_id: u64, code: u32) void {
        const ci = for (&self.clients, 0..) |*c, i| {
            if (c.active and c.entry == session.entry) break i;
        } else return;
        self.abandonForward(ci, stream_id, code);
        self.requestWithdrawn(ci, stream_id);
        self.clients[ci].clearSlot(stream_id);
    }

    /// A publisher's data stream reset mid-group: reset what it fed, and
    /// drop the part-built group rather than cache it.
    fn abandonForward(self: *RelayHandler, ci: usize, stream_id: u64, code: u64) void {
        const c = &self.clients[ci];
        const slot = c.slotOf(stream_id) orelse return;
        if (c.stream_roles[slot] != .data) return;
        const fs = &c.fwd_states[slot];
        for (fs.out_stream_ids[0..fs.out_count], fs.out_sub_idx[0..fs.out_count]) |out, sub_ci| {
            var l = self.link(sub_ci) orelse continue;
            l.reset(out, code);
        }
        fs.out_count = 0;
        if (self.fwdTrack(fs)) |t| if (t.ownsLive(ci, stream_id)) {
            t.live.reset();
            t.live_owner = null;
        };
    }

    /// The track a data stream feeds, while it still carries the publication
    /// the stream began in.
    fn fwdTrack(self: *RelayHandler, fs: *FwdState) ?*Track {
        const ti = fs.track_idx orelse return null;
        const t = &self.tracks[ti];
        if (t.active and t.gen == fs.track_gen) return t;
        fs.track_idx = null;
        return null;
    }

    fn requestWithdrawn(self: *RelayHandler, ci: usize, stream_id: u64) void {
        for (&self.namespaces) |*n| {
            if (!n.active or n.client_idx != ci or n.stream_id != stream_id) continue;
            n.active = false;
            std.debug.print("[relay] namespace \"{s}\" withdrawn by client {d}\n", .{ n.key(), ci });
            if (!self.namespaceHeld(n.key())) self.announceNamespace(n.key(), true);
        }
        for (self.tracks[0..self.track_count]) |*t| {
            if (!t.active) continue;
            // Its PUBLISH, or the publisher's answer to our SUBSCRIBE: the
            // publication is over for everyone it served.
            if (t.pub_stream_id == stream_id and (t.publisher_idx == ci or t.upstream_idx == ci)) {
                if (t.upstream_pending) {
                    self.failWaitingSubs(t, moq_codes.ERR_INTERNAL_ERROR, "publisher gone");
                } else {
                    self.endPublication(t, moq_codes.DONE_TRACK_ENDED, "publisher gone");
                }
                continue;
            }
            var si: usize = 0;
            while (si < t.sub_count) {
                if (t.subs[si].client_idx == ci and t.subs[si].stream_id == stream_id) {
                    t.removeSub(si);
                } else si += 1;
            }
            if (t.sub_count == 0 and t.upstream_idx != null and t.upstream_idx != ci) self.unsubscribeUpstream(t);
            t.reapIfIdle();
        }
        for (&self.ns_subs) |*n| {
            if (n.active and n.client_idx == ci and n.stream_id == stream_id) n.active = false;
        }
        for (&self.pending) |*p| {
            if (p.active and p.client_idx == ci and p.stream_id == stream_id) p.active = false;
        }
    }

    /// §5.1: a relay with no publisher for a track asks the namespace's
    /// publisher for it, and answers its own subscribers once that answers.
    fn subscribeUpstream(self: *RelayHandler, t: *Track, owner: usize, filter: ?moq_msg.Filter) bool {
        var l = self.link(owner) orelse return false;
        var parts: [moq_wire.MAX_TUPLE_PARTS][]const u8 = undefined;
        var fields: [256]u8 = undefined;
        var buf: [512]u8 = undefined;
        var fbs = io_compat.fixedBufferStream(&buf);
        moq_msg.writeSubscribe(&fbs, .{
            .request_id = self.clients[owner].next_request_id,
            .track_namespace = moq_wire.splitNamespace(t.namespace_buf[0..t.namespace_len], &parts, &fields),
            .track_name = t.name_buf[0..t.name_len],
            .filter = filter,
        }, self.clients[owner].draft) catch return false;
        const sid = l.openBidi() catch return false;
        l.send(sid, buf[0..fbs.seek]) catch return false;
        self.clients[owner].next_request_id += 2;
        self.clients[owner].setRole(sid, .upstream);
        t.upstream_idx = owner;
        t.upstream_pending = true;
        t.pub_stream_id = sid;
        std.debug.print("[relay] SUBSCRIBE → publisher client {d} ns=\"{s}\" track=\"{s}\"\n", .{
            owner, t.namespace_buf[0..t.namespace_len], t.name_buf[0..t.name_len],
        });
        return true;
    }

    /// Nobody downstream wants the track any more: cancel the relay's own
    /// subscription (§3.3.3, a withdrawn request is a reset stream).
    fn unsubscribeUpstream(self: *RelayHandler, t: *Track) void {
        const owner = t.upstream_idx orelse return;
        if (t.pub_stream_id) |sid| {
            if (self.link(owner)) |l_| {
                var l = l_;
                l.reset(sid, 0x1);
                l.stopSending(sid, 0x1);
            }
            self.clients[owner].clearSlot(sid);
        }
        t.dropPublisherState();
        t.active = false;
    }

    fn failWaitingSubs(self: *RelayHandler, t: *Track, code: u64, reason: []const u8) void {
        var si: usize = 0;
        while (si < t.sub_count) {
            const sub = t.subs[si];
            if (sub.answered) {
                si += 1;
                continue;
            }
            var buf: [256]u8 = undefined;
            var fbs = io_compat.fixedBufferStream(&buf);
            if (moq_msg.writeRequestError(&fbs, .{ .error_code = code, .reason = reason })) |_| {
                self.sendToClient(sub.client_idx, sub.stream_id, buf[0..fbs.seek]);
            } else |_| {}
            t.removeSub(si);
        }
        t.dropPublisherState();
        t.reapIfIdle();
    }

    /// The namespace publisher's answer to a SUBSCRIBE the relay sent it.
    fn tryParseUpstream(self: *RelayHandler, ci: usize, stream_id: u64) void {
        const buf = self.clients[ci].buffer(stream_id) orelse return;
        while (true) {
            const parsed = moq_msg.parseEnvelope(buf.slice()) catch return;
            const t = for (self.tracks[0..self.track_count]) |*t| {
                if (t.active and t.upstream_idx == ci and t.pub_stream_id == stream_id) break t;
            } else null;

            if (t) |tr| switch (parsed.env.type) {
                moq_codes.MSG_SUBSCRIBE_OK => if (tr.upstream_pending) {
                    if (moq_msg.decodeSubscribeOk(parsed.env.payload)) |ok| {
                        tr.upstream_pending = false;
                        tr.publisher_idx = ci;
                        tr.pub_alias = ok.track_alias;
                        std.debug.print("[relay] SUBSCRIBE_OK ← publisher client {d} alias={d}\n", .{ ci, ok.track_alias });
                        for (tr.subs[0..tr.sub_count]) |*sub| {
                            if (sub.answered) continue;
                            sub.answered = true;
                            self.sendSubscribeOk(sub);
                        }
                        self.retryHeld(ci);
                    } else |e| {
                        std.debug.print("[relay] undecodable upstream SUBSCRIBE_OK client={d}: {t}\n", .{ ci, e });
                        self.failWaitingSubs(tr, moq_codes.ERR_INTERNAL_ERROR, "publisher answer undecodable");
                        return self.endUpstream(ci, stream_id);
                    }
                },
                moq_codes.MSG_REQUEST_ERROR => {
                    const e = moq_msg.decodeRequestError(parsed.env.payload) catch moq_msg.RequestError{ .error_code = moq_codes.ERR_INTERNAL_ERROR, .reason = "" };
                    std.debug.print("[relay] REQUEST_ERROR ← publisher client {d} code={d}\n", .{ ci, e.error_code });
                    self.failWaitingSubs(tr, e.error_code, e.reason);
                    return self.endUpstream(ci, stream_id);
                },
                moq_codes.MSG_PUBLISH_DONE => {
                    if (tr.upstream_pending) {
                        self.failWaitingSubs(tr, moq_codes.ERR_INTERNAL_ERROR, "publisher gave no answer");
                    } else {
                        self.handlePublishDone(ci, stream_id, parsed.env.payload);
                    }
                    return self.endUpstream(ci, stream_id);
                },
                else => std.debug.print("[relay] upstream client {d} type=0x{x}\n", .{ ci, parsed.env.type }),
            };

            const remaining = buf.slice()[parsed.consumed..];
            std.mem.copyForwards(u8, &buf.data, remaining);
            buf.len = remaining.len;
        }
    }

    /// Nothing more comes on an upstream SUBSCRIBE's stream: close our half
    /// and free its slot, buffer included.
    fn endUpstream(self: *RelayHandler, ci: usize, stream_id: u64) void {
        if (self.link(ci)) |l_| {
            var l = l_;
            l.finish(stream_id);
        }
        self.clients[ci].clearSlot(stream_id);
    }

    /// The publisher finished the stream our SUBSCRIBE went out on; if it
    /// never answered, it won't.
    fn upstreamFinished(self: *RelayHandler, ci: usize, stream_id: u64) void {
        for (self.tracks[0..self.track_count]) |*t| {
            if (t.active and t.upstream_pending and t.upstream_idx == ci and t.pub_stream_id == stream_id) {
                self.failWaitingSubs(t, moq_codes.ERR_INTERNAL_ERROR, "publisher gave no answer");
            }
        }
    }

    fn sendSubscribeOk(self: *RelayHandler, sub: *const Sub) void {
        var buf: [256]u8 = undefined;
        var fbs = io_compat.fixedBufferStream(&buf);
        moq_msg.writeSubscribeOk(&fbs, .{ .track_alias = sub.alias }) catch return;
        self.sendToClient(sub.client_idx, sub.stream_id, buf[0..fbs.seek]);
    }

    /// `filter` is the subscriber's, null when it sent none; the first
    /// subscriber's goes upstream as it came (§10.2.9: absent is unfiltered).
    fn admitSubscriber(self: *RelayHandler, ci: usize, stream_id: u64, ns_key: []const u8, track_name: []const u8, forward: bool, filter: ?moq_msg.Filter) void {
        const ti = self.findTrack(ns_key, track_name) orelse
            self.allocTrack(ns_key, track_name) orelse {
            self.sendToClientError(ci, stream_id, moq_codes.ERR_EXCESSIVE_LOAD, "track table full");
            return;
        };

        var t = &self.tracks[ti];
        if (t.publisher_idx == null and !t.upstream_pending) {
            if (self.namespaceOwner(ns_key)) |owner| {
                if (owner != ci) _ = self.subscribeUpstream(t, owner, filter);
            }
        }
        if (t.sub_count < MAX_SUBS_PER_TRACK) {
            const alias = self.clients[ci].next_alias;
            self.clients[ci].next_alias += 1;
            t.subs[t.sub_count] = .{
                .client_idx = ci,
                .alias = alias,
                .stream_id = stream_id,
                .answered = !t.upstream_pending,
                .forward = forward,
            };
            t.sub_count += 1;
            if (t.upstream_pending) return; // answered once the publisher does

            var buf: [256]u8 = undefined;
            var fbs = io_compat.fixedBufferStream(&buf);
            moq_msg.writeSubscribeOk(&fbs, .{ .track_alias = alias }) catch return;
            self.sendToClient(ci, stream_id, buf[0..fbs.seek]);
            std.debug.print("[relay] SUBSCRIBE_OK → client {d} alias={d} (track {d}, {d} subs, pub={?d})\n", .{
                ci, alias, ti, t.sub_count, t.publisher_idx,
            });

            // Replay any cached groups to this new subscriber so it starts
            // playback immediately instead of waiting for the next keyframe.
            self.replayCachedGroups(t, &t.subs[t.sub_count - 1]);
        }
    }

    /// §9.3.3: a subscriber too slow for the relay to go on queueing for
    /// loses its subscriptions to `t`, rather than have its backlog held.
    fn dropSlowSubscriber(self: *RelayHandler, t: *Track, sub_ci: usize) void {
        const status = moq_version.Rules.of(self.clients[sub_ci].draft).done_too_far_behind;
        var si: usize = 0;
        while (si < t.sub_count) {
            const sub = t.subs[si];
            if (sub.client_idx != sub_ci) {
                si += 1;
                continue;
            }
            var buf: [256]u8 = undefined;
            var fbs = io_compat.fixedBufferStream(&buf);
            if (moq_msg.writePublishDone(&fbs, .{
                .status_code = status,
                .stream_count = sub.streams,
                .reason = "too far behind",
            })) |_| {
                self.sendToClient(sub_ci, sub.stream_id, buf[0..fbs.seek]);
                self.closeClientStream(sub_ci, sub.stream_id);
            } else |_| {}
            t.removeSub(si);
        }
        std.debug.print("[relay] client {d} too far behind; subscription dropped\n", .{sub_ci});
        for (&self.clients) |*c| {
            if (!c.active) continue;
            for (&c.fwd_states) |*fs| {
                const ti = fs.track_idx orelse continue;
                if (&self.tracks[ti] == t) self.resetOutputs(fs, sub_ci);
            }
        }
        if (t.sub_count == 0 and t.upstream_idx != null) self.unsubscribeUpstream(t);
        t.reapIfIdle();
    }

    fn resetOutputs(self: *RelayHandler, fs: *FwdState, sub_ci: usize) void {
        var i: usize = 0;
        while (i < fs.out_count) {
            if (fs.out_sub_idx[i] != sub_ci) {
                i += 1;
                continue;
            }
            if (self.link(sub_ci)) |l_| {
                var l = l_;
                l.reset(fs.out_stream_ids[i], moq_codes.STREAM_RESET_TOO_FAR_BEHIND);
            }
            fs.out_count -= 1;
            fs.out_sub_idx[i] = fs.out_sub_idx[fs.out_count];
            fs.out_stream_ids[i] = fs.out_stream_ids[fs.out_count];
        }
    }

    // Replay every cached complete group to a freshly-subscribed subscriber.
    // Each cached group is sent as a fresh uni stream on the subscriber's WT
    // session with the subscriber's track alias remapped.
    fn replayCachedGroups(self: *RelayHandler, t: *const Track, sub: *Sub) void {
        if (!sub.forward) return;
        const sub_ci = sub.client_idx;
        var l = self.link(sub_ci) orelse return;
        // Resubscribing in a loop without reading would have us queue a
        // replay per turn.
        if (l.s.sendBufferedBytes() > MAX_SUB_BACKLOG) return;

        var slots: [N_CACHED_GROUPS]*const CachedGroup = undefined;
        const n = t.cachedInOrder(&slots);
        for (0..n) |i| {
            const cg = slots[i];
            const out = l.openUni() catch continue;
            sub.streams += 1;

            var out_hdr = cg.hdr;
            out_hdr.track_alias = sub.alias;
            var hdr_buf: [128]u8 = undefined;
            var hdr_fbs = io_compat.fixedBufferStream(&hdr_buf);
            moq_obj.writeSubgroupHeader(&hdr_fbs, out_hdr, self.clients[sub_ci].draft) catch continue;
            l.send(out, hdr_buf[0..hdr_fbs.seek]) catch continue;
            l.send(out, cg.payload[0..cg.payload_len]) catch {};
            l.finish(out);
        }
        if (n > 0) std.debug.print("[relay] Replayed {d} cached groups to client {d}\n", .{ n, sub_ci });
    }

    fn handlePublish(self: *RelayHandler, ci: usize, session: *event_loop.Session, stream_id: u64, payload: []const u8) void {
        var ns_buf: moq_msg.NamespaceBuf = undefined;
        const pub_msg = moq_msg.decodePublish(payload, &ns_buf, self.clients[ci].draft) catch |e| {
            self.rejectRequest(ci, session, stream_id, e, "publish", payload);
            return;
        };

        var ns_key: [256]u8 = undefined;
        const ns_len = moq_wire.flattenNamespace(pub_msg.track_namespace, &ns_key) orelse {
            self.sendRequestError(session, stream_id, moq_codes.ERR_NAMESPACE_TOO_LARGE, "namespace too long");
            return;
        };
        std.debug.print("[relay] PUBLISH client={d} ns=\"{s}\" track=\"{s}\" alias={d}\n", .{
            ci, ns_key[0..ns_len], pub_msg.track_name, pub_msg.track_alias,
        });

        const ti = self.findTrack(ns_key[0..ns_len], pub_msg.track_name) orelse
            self.allocTrack(ns_key[0..ns_len], pub_msg.track_name) orelse return;
        var t = &self.tracks[ti];
        t.active = true;
        @memcpy(t.namespace_buf[0..ns_len], ns_key[0..ns_len]);
        t.namespace_len = ns_len;
        @memcpy(t.name_buf[0..pub_msg.track_name.len], pub_msg.track_name);
        t.name_len = pub_msg.track_name.len;
        // A different publisher taking the track over makes everything the
        // last one left behind stale — it belongs to a broadcast that is no
        // longer this one. Dropping it only when the old publisher's session
        // closes is too late: it may still be connected, and the next
        // subscriber would be replayed the previous broadcast's groups.
        if (t.publisher_idx) |prev| {
            if (prev != ci) t.dropPublisherState();
        }
        t.publisher_idx = ci;
        t.pub_alias = pub_msg.track_alias;
        t.pub_stream_id = stream_id;
        // A PUBLISH means this namespace exists here, so a later SUBSCRIBE
        // under it is legitimate even if the publisher never announced.
        _ = self.registerNamespace(ci, stream_id, ns_key[0..ns_len], true);

        var buf: [256]u8 = undefined;
        var fbs = io_compat.fixedBufferStream(&buf);
        moq_msg.writePublishOk(&fbs, .{}, self.clients[ci].draft) catch return;
        self.sendOnStream(session, stream_id, buf[0..fbs.seek]);
        std.debug.print("[relay] PUBLISH_OK → client {d} (track {d}, {d} subs)\n", .{ ci, ti, t.sub_count });

        // A held subscriber may be waiting on this track (§9.3.4); it takes
        // the SUBSCRIBE it sent, not a PUBLISH as well.
        self.resolvePending(ns_key[0..ns_len]);
        self.offerToWatchers(t);
        self.retryHeld(ci);
    }

    /// §10.11: the upstream publication has ended. Each downstream
    /// subscription is a separate one, so each gets its own PUBLISH_DONE with
    /// the number of data streams *we* opened for it — not the count upstream
    /// sent us. Without this a subscriber waits for objects that will never
    /// come; it is the relay, not the original publisher, that has to say so.
    fn handlePublishDone(self: *RelayHandler, ci: usize, stream_id: u64, payload: []const u8) void {
        const done = moq_msg.decodePublishDone(payload) catch |e| {
            std.debug.print("[relay] undecodable PUBLISH_DONE client={d}: {t}\n", .{ ci, e });
            return;
        };
        for (self.tracks[0..self.track_count]) |*t| {
            if (!t.active or t.publisher_idx != ci) continue;
            if (t.pub_stream_id != stream_id) continue;
            self.endPublication(t, done.status_code, done.reason);
        }
    }

    /// Sends PUBLISH_DONE to every subscriber of `t`, then forgets both them
    /// and the publisher — a publication cannot end for one and not the other.
    /// The draft asks for a FIN on each subscription's bidi stream right after.
    fn endPublication(self: *RelayHandler, t: *Track, status: u64, reason: []const u8) void {
        for (t.subs[0..t.sub_count]) |sub| {
            var buf: [256]u8 = undefined;
            var fbs = io_compat.fixedBufferStream(&buf);
            if (moq_msg.writePublishDone(&fbs, .{
                .status_code = status,
                .stream_count = sub.streams,
                .reason = reason,
            })) |_| {
                self.sendToClient(sub.client_idx, sub.stream_id, buf[0..fbs.seek]);
                self.closeClientStream(sub.client_idx, sub.stream_id);
                std.debug.print("[relay] PUBLISH_DONE → client {d} status={d} streams={d}\n", .{
                    sub.client_idx, status, sub.streams,
                });
            } else |_| {}
        }
        t.sub_count = 0;
        t.dropPublisherState();
        t.active = false;
    }

    fn closeClientStream(self: *RelayHandler, ci: usize, stream_id: u64) void {
        var l = self.link(ci) orelse return;
        l.finish(stream_id);
    }

    fn tryForwardData(self: *RelayHandler, ci: usize, stream_id: u64, fin: bool) void {
        const buf = self.clients[ci].buffer(stream_id) orelse return;
        const fs = self.clients[ci].fwdState(stream_id) orelse return;

        // First: parse the header and open sub-streams once per input stream.
        if (!fs.header_parsed) {
            if (buf.len < 3) return; // need more bytes
            var fbs = io_compat.fixedBufferStream(@as([]const u8, buf.slice()));
            const parsed = moq_obj.readSubgroupHeader(&fbs, self.clients[ci].draft) catch return; // need more bytes or bad
            const h = parsed.header;

            // Find the track by publisher alias.
            var track_idx: ?usize = null;
            for (self.tracks[0..self.track_count], 0..) |*t, ti| {
                if (t.active and t.publisher_idx == ci and t.pub_alias == h.track_alias) {
                    track_idx = ti;
                    break;
                }
            }
            const ti = track_idx orelse {
                if (fs.held_since_ns == 0) fs.held_since_ns = sys.nanoTimestamp();
                return;
            };
            fs.held_since_ns = 0;
            const t = &self.tracks[ti];
            fs.track_idx = ti;
            fs.track_gen = t.gen;

            // Initialize the live cache for this group on the track.
            t.live.reset();
            t.live.valid = false;
            t.live.hdr = h;
            t.live_owner = .{ .ci = ci, .sid = stream_id };

            // Open a subscriber output stream for each subscriber, write rewritten header.
            fs.out_count = 0;
            for (t.subs[0..t.sub_count]) |*sub| {
                if (!sub.forward or !sub.answered) continue;
                const sub_ci = sub.client_idx;
                var l = self.link(sub_ci) orelse continue;

                const out = l.openUni() catch |e| {
                    std.debug.print("[relay] openUniStream failed for sub {d}: {}\n", .{ sub_ci, e });
                    continue;
                };
                // Counted at the open, not after the header: PUBLISH_DONE's
                // Stream Count has to cover every stream the subscriber sees.
                sub.streams += 1;

                var out_hdr = h;
                out_hdr.track_alias = sub.alias;
                var hdr_buf: [128]u8 = undefined;
                var hdr_fbs = io_compat.fixedBufferStream(&hdr_buf);
                moq_obj.writeSubgroupHeader(&hdr_fbs, out_hdr, self.clients[sub_ci].draft) catch continue;
                l.send(out, hdr_buf[0..hdr_fbs.seek]) catch continue;

                fs.out_stream_ids[fs.out_count] = out;
                fs.out_sub_idx[fs.out_count] = sub_ci;
                fs.out_count += 1;
            }
            std.debug.print("[relay] stream from client {d} → {d} subs (group={d})\n", .{ ci, fs.out_count, h.group });

            fs.header_parsed = true;
            fs.forwarded_pos = fbs.seek;
        }

        // Forward any newly arrived bytes AND append them to the live cache.
        if (fs.forwarded_pos < buf.len) {
            const chunk = buf.slice()[fs.forwarded_pos..];
            // Append to live cache (so late subscribers can catch up later).
            if (self.fwdTrack(fs)) |t| if (t.ownsLive(ci, stream_id)) {
                const free = t.live.payload.len - t.live.payload_len;
                const copy_n = @min(chunk.len, free);
                if (copy_n > 0) {
                    @memcpy(t.live.payload[t.live.payload_len .. t.live.payload_len + copy_n], chunk[0..copy_n]);
                    t.live.payload_len += copy_n;
                }
            };
            // Forward to currently-attached subscribers.
            var slow: [MAX_SUBS_PER_TRACK]usize = undefined;
            var n_slow: usize = 0;
            for (0..fs.out_count) |i| {
                const sub_ci = fs.out_sub_idx[i];
                var l = self.link(sub_ci) orelse continue;
                if ((l.s.streamBufferedBytes(fs.out_stream_ids[i]) orelse 0) + chunk.len > MAX_OUT_BACKLOG) {
                    slow[n_slow] = sub_ci;
                    n_slow += 1;
                    continue;
                }
                l.send(fs.out_stream_ids[i], chunk) catch |e| {
                    std.debug.print("[relay] fwd chunk to sub {d}: {}\n", .{ sub_ci, e });
                };
            }
            fs.forwarded_pos = buf.len;
            for (slow[0..n_slow]) |sub_ci| {
                if (self.fwdTrack(fs)) |t| self.dropSlowSubscriber(t, sub_ci) else self.resetOutputs(fs, sub_ci);
            }
        }

        // On FIN: close all sub-streams and commit the live cache.
        if (fin) {
            for (0..fs.out_count) |i| {
                const sub_ci = fs.out_sub_idx[i];
                var l = self.link(sub_ci) orelse continue;
                l.finish(fs.out_stream_ids[i]);
            }
            if (self.fwdTrack(fs)) |t| if (t.ownsLive(ci, stream_id)) {
                if (t.live.payload_len > 0) {
                    t.cacheGroup(&t.live);
                    std.debug.print("[relay] cached group {d} for track {d} ({d} bytes)\n", .{
                        t.live.hdr.group, fs.track_idx.?, t.live.payload_len,
                    });
                }
                t.live.reset();
                t.live_owner = null;
            };
        }

        // Compact the buffer: once we've forwarded bytes, we can drop them.
        if (fs.forwarded_pos > 0) {
            const remaining = buf.slice()[fs.forwarded_pos..];
            std.mem.copyForwards(u8, &buf.data, remaining);
            buf.len = remaining.len;
            fs.forwarded_pos = 0;
        }
    }

    /// §10.3.1 object datagrams, forwarded unreliably to each subscriber.
    /// Only the type and alias are rewritten; everything after the alias —
    /// properties included — goes out as it came in.
    pub fn onDatagram(self: *RelayHandler, session: *event_loop.Session, _: u64, data: []const u8) void {
        const ci = for (&self.clients, 0..) |*c, i| {
            if (c.active and c.entry == session.entry) break i;
        } else return;
        if (self.forwardDatagram(ci, data) or data.len > HELD_DATAGRAM_SIZE) return;

        // §11.3: an alias nothing has established yet may be the publisher's
        // answer still on its way; keep the datagram briefly.
        var slot = &self.held_dgrams[0];
        for (&self.held_dgrams) |*d| {
            if (!d.active) {
                slot = d;
                break;
            }
            if (d.since_ns < slot.since_ns) slot = d;
        }
        slot.* = .{ .active = true, .client_idx = ci, .since_ns = sys.nanoTimestamp(), .len = data.len };
        @memcpy(slot.data[0..data.len], data);
    }

    /// Forwards one object datagram from publisher `ci`. False when its alias
    /// names no track of theirs yet; true when it was dealt with, garbage
    /// included.
    fn forwardDatagram(self: *RelayHandler, ci: usize, data: []const u8) bool {
        var fbs = io_compat.fixedBufferStream(data);
        const dtype = moq_wire.readVarInt(&fbs) catch return true;
        const alias = moq_wire.readVarInt(&fbs) catch return true;
        if (!moq_codes.isDatagramObjectType(dtype)) return true;
        const rest = data[fbs.seek..];

        const t = for (self.tracks[0..self.track_count]) |*t| {
            if (t.active and t.publisher_idx == ci and t.pub_alias == alias) break t;
        } else return false;

        for (t.subs[0..t.sub_count]) |sub| {
            if (!sub.forward or !sub.answered) continue;
            var l = self.link(sub.client_idx) orelse continue;
            var buf: [1600]u8 = undefined;
            var out = io_compat.fixedBufferStream(&buf);
            moq_wire.writeVarInt(&out, dtype) catch continue;
            moq_wire.writeVarInt(&out, sub.alias) catch continue;
            out.writeAll(rest) catch continue;
            l.datagram(buf[0..out.seek]) catch {};
        }
        return true;
    }
};

// h3 first: a browser offers only that, and a MoQ client offering both is
// happy either way.
const ALPNS = [_][]const u8{ "h3", "moqt-18", "moqt-17" };

pub fn main(init: std.process.Init.Minimal) !void {
    // A server outlives its streams, so it needs an allocator that reuses what
    // they give back — an arena would grow for as long as the process runs.
    const alloc = std.heap.smp_allocator;

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

    const server_cert_pem = try sys.readFileAlloc(alloc, cert_path, 8192);
    var cert_der_buf: [4096]u8 = undefined;
    const cert_der = try tls13.parsePemCert(server_cert_pem, &cert_der_buf);
    var cert_hash: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(cert_der, &cert_hash, .{});

    std.debug.print("\n=== MoQ Relay (draft-17/18, WebTransport + QUIC) ===\n", .{});
    std.debug.print("Certificate SHA-256: ", .{});
    for (cert_hash) |byte| std.debug.print("{x:0>2}", .{byte});
    std.debug.print("\n\n", .{});

    const handler = try alloc.create(RelayHandler);
    handler.* = RelayHandler{};
    var server = try event_loop.Server(RelayHandler).init(alloc, handler, .{
        .address = "0.0.0.0",
        .port = port,
        .cert_path = cert_path,
        .key_path = key_path,
        .conn_config = .{ .max_datagram_frame_size = 65536 },
        .alpn = &ALPNS,
        .http1 = .{ .static_dir = "interop/browser" },
    });
    defer server.deinit();

    std.debug.print("Listening on https://0.0.0.0:{d}\n", .{port});
    std.debug.print("Video demo: https://127.0.0.1:{d}/moq_video.html\n", .{port});
    std.debug.print("Clock demo: https://127.0.0.1:{d}/moq.html\n\n", .{port});
    try server.run();
}

test "a subscriber leaving takes its outputs with it" {
    // Forwarding named subscribers by table index: the next client in the
    // slot got the rest of the group on the leaver's stream ids, which could
    // be its own streams for another track.
    const r = try std.testing.allocator.create(RelayHandler);
    defer std.testing.allocator.destroy(r);
    r.* = .{};
    var entries: [3]cm.ConnEntry = undefined;
    for (0..3) |i| r.clients[i] = .{ .active = true, .entry = &entries[i] };
    const fs = r.clients[0].fwdState(3).?;
    fs.* = .{ .active = true, .out_count = 2 };
    fs.out_sub_idx[0] = 1;
    fs.out_stream_ids[0] = 7;
    fs.out_sub_idx[1] = 2;
    fs.out_stream_ids[1] = 11;

    var gone: event_loop.Session = .{ .entry = &entries[1] };
    r.onSessionClosed(&gone, 0, 0, "");
    try std.testing.expectEqual(@as(usize, 1), fs.out_count);
    try std.testing.expectEqual(@as(usize, 2), fs.out_sub_idx[0]);
    try std.testing.expectEqual(@as(u64, 11), fs.out_stream_ids[0]);
}

/// Native-QUIC client 0 publishes track 0 under alias 5 from its request
/// stream 0; client 1 subscribes to it from its request stream 4.
const TestRelay = struct {
    r: *RelayHandler,
    conns: [2]*connection_mod.Connection,
    entries: [2]cm.ConnEntry,

    fn init(self: *TestRelay) !void {
        self.r = try std.testing.allocator.create(RelayHandler);
        self.r.* = .{};
        for (0..2) |i| {
            self.conns[i] = try relay_test.conn();
            self.entries[i] = .{ .conn = self.conns[i], .raw_quic = true };
            self.r.clients[i] = .{ .active = true, .entry = &self.entries[i], .raw = true };
        }
        _ = try self.conns[1].streams.getOrCreateStream(4);
        const t = &self.r.tracks[0];
        t.* = .{ .active = true, .publisher_idx = 0, .pub_alias = 5, .pub_stream_id = 0, .sub_count = 1 };
        t.subs[0] = .{ .client_idx = 1, .alias = 9, .stream_id = 4 };
        self.r.track_count = 1;
        self.r.clients[0].setRole(0, .request);
        self.r.clients[1].setRole(4, .request);
    }

    fn deinit(self: *TestRelay) void {
        for (self.conns) |c| relay_test.free(c);
        std.testing.allocator.destroy(self.r);
    }

    fn session(self: *TestRelay, i: usize) event_loop.Session {
        return .{ .entry = &self.entries[i] };
    }

    /// Opens a group on the publisher's uni stream `sid`, with one object.
    fn openGroup(self: *TestRelay, sid: u64) !void {
        var buf: [64]u8 = undefined;
        var fbs = io_compat.fixedBufferStream(&buf);
        try moq_obj.writeSubgroupHeader(&fbs, .{
            .track_alias = 5,
            .group = 1,
            .subgroup = 0,
            .publisher_priority = 128,
            .end_of_group = false,
            .per_object_properties = false,
        }, .draft_17);
        try fbs.writeAll("object");
        var s = self.session(0);
        self.r.onStreamData(&s, sid, buf[0..fbs.seek], false);
    }
};

test "a publisher's reset reaches its subscribers" {
    // Its streams were forgotten, not reset, so subscribers waited on a
    // group, or a publication, that would never finish.
    var tr: TestRelay = undefined;
    try tr.init();
    defer tr.deinit();
    var publisher = tr.session(0);

    try tr.openGroup(2);
    const out = tr.conns[1].streams.send_streams.get(3) orelse return error.NoOutput;
    tr.r.onStreamReset(&publisher, 0, 2, 7);
    try std.testing.expectEqual(@as(?u64, 7), out.reset_err);

    // Withdrawing the PUBLISH ends the publication for its subscribers.
    tr.r.onStreamReset(&publisher, 0, 0, 0);
    try std.testing.expectEqual(@as(usize, 0), tr.r.tracks[0].sub_count);
    try std.testing.expect(tr.conns[1].streams.getStream(4).?.send.fin_queued);
}

test "an upstream subscription gives its stream slot back when it ends" {
    // Refused, done or finished, the relay's SUBSCRIBE to a namespace's
    // publisher kept its slot, and 64 of them used the publisher up.
    var tr: TestRelay = undefined;
    try tr.init();
    defer tr.deinit();
    const r = tr.r;
    var publisher = tr.session(0);
    const t = &r.tracks[0];
    var buf: [256]u8 = undefined;

    // Refused.
    t.dropPublisherState();
    t.subs[0].answered = false;
    try std.testing.expect(r.subscribeUpstream(t, 0, null));
    const refused = t.pub_stream_id.?;
    var fbs = io_compat.fixedBufferStream(&buf);
    try moq_msg.writeRequestError(&fbs, .{ .error_code = moq_codes.ERR_DOES_NOT_EXIST, .reason = "" });
    r.onStreamData(&publisher, refused, buf[0..fbs.seek], false);
    try std.testing.expectEqual(@as(?usize, null), r.clients[0].slotOf(refused));
    try std.testing.expect(tr.conns[0].streams.getStream(refused).?.send.fin_queued);

    // Answered, then done.
    t.* = .{ .active = true, .sub_count = 1 };
    t.subs[0] = .{ .client_idx = 1, .alias = 9, .stream_id = 4, .answered = false };
    try std.testing.expect(r.subscribeUpstream(t, 0, null));
    const done = t.pub_stream_id.?;
    fbs = io_compat.fixedBufferStream(&buf);
    try moq_msg.writeSubscribeOk(&fbs, .{ .track_alias = 5 });
    try moq_msg.writePublishDone(&fbs, .{ .status_code = moq_codes.DONE_TRACK_ENDED, .stream_count = 0, .reason = "" });
    r.onStreamData(&publisher, done, buf[0..fbs.seek], false);
    try std.testing.expectEqual(@as(?usize, null), r.clients[0].slotOf(done));

    // Finished by the publisher with nothing more to say.
    t.* = .{ .active = true, .sub_count = 1 };
    t.subs[0] = .{ .client_idx = 1, .alias = 9, .stream_id = 4, .answered = false };
    try std.testing.expect(r.subscribeUpstream(t, 0, null));
    const finished = t.pub_stream_id.?;
    r.onStreamData(&publisher, finished, "", true);
    try std.testing.expectEqual(@as(?usize, null), r.clients[0].slotOf(finished));
}

test "a track with no publisher and no subscribers gives its slot back" {
    // Ended publications and abandoned subscriptions kept their tracks, and
    // the 32 slots filled for good.
    var tr: TestRelay = undefined;
    try tr.init();
    defer tr.deinit();
    const r = tr.r;
    const t = &r.tracks[0];

    var buf: [64]u8 = undefined;
    var fbs = io_compat.fixedBufferStream(&buf);
    try moq_msg.writePublishDone(&fbs, .{ .status_code = moq_codes.DONE_TRACK_ENDED, .stream_count = 0, .reason = "" });
    var publisher = tr.session(0);
    r.onStreamData(&publisher, 0, buf[0..fbs.seek], false);
    try std.testing.expect(!t.active);

    // Waiting on a publisher that never came, until its subscriber left.
    t.* = .{ .active = true, .sub_count = 1 };
    t.subs[0] = .{ .client_idx = 1, .alias = 9, .stream_id = 4 };
    var subscriber = tr.session(1);
    r.onStreamReset(&subscriber, 0, 4, 0);
    try std.testing.expect(!t.active);
}

test "a group outliving its track caches nothing into the track that took the slot" {
    // A data stream kept the index it resolved at its header, so bytes sent
    // after the publication ended were cached, and replayed, as whichever
    // track reused the slot.
    var tr: TestRelay = undefined;
    try tr.init();
    defer tr.deinit();
    const r = tr.r;
    var publisher = tr.session(0);

    try tr.openGroup(2);
    var buf: [64]u8 = undefined;
    var fbs = io_compat.fixedBufferStream(&buf);
    try moq_msg.writePublishDone(&fbs, .{ .status_code = moq_codes.DONE_TRACK_ENDED, .stream_count = 1, .reason = "" });
    r.onStreamData(&publisher, 0, buf[0..fbs.seek], false);
    try std.testing.expectEqual(@as(?usize, 0), r.allocTrack("other", "track"));

    r.onStreamData(&publisher, 2, "late bytes", true);
    for (r.tracks[0].cached) |g| try std.testing.expect(!g.valid);
    try std.testing.expectEqual(@as(usize, 0), r.tracks[0].live.payload_len);
}

test "a subscriber that can't keep up is dropped, not queued for" {
    // Every chunk went to every subscriber, read or not, so one that granted
    // no flow control grew the relay's send buffers without end.
    var tr: TestRelay = undefined;
    try tr.init();
    defer tr.deinit();
    const r = tr.r;
    var publisher = tr.session(0);

    try tr.openGroup(2);
    const out = tr.conns[1].streams.send_streams.get(3).?;
    // Nothing is ever sent in a test, so every byte stays queued.
    const chunk: [60 * 1024]u8 = @splat('v');
    for (0..32) |_| {
        r.onStreamData(&publisher, 2, &chunk, false);
        if (r.tracks[0].sub_count == 0) break;
    }
    try std.testing.expectEqual(@as(usize, 0), r.tracks[0].sub_count);
    try std.testing.expectEqual(@as(?u64, moq_codes.STREAM_RESET_TOO_FAR_BEHIND), out.reset_err);
    try std.testing.expect(tr.conns[1].streams.getStream(4).?.send.fin_queued);
}

test "resubscribing can't make the relay queue replays without end" {
    // Each SUBSCRIBE replayed up to two cached groups on fresh streams, so a
    // subscriber that subscribed and reset in a loop without reading grew
    // the relay's send buffers by half a megabyte a turn.
    var tr: TestRelay = undefined;
    try tr.init();
    defer tr.deinit();
    const r = tr.r;
    const t = &r.tracks[0];
    t.sub_count = 0;
    for (&t.cached) |*g| {
        g.valid = true;
        g.payload_len = CACHE_GROUP_SIZE;
        @memset(&g.payload, 'c');
    }
    var subscriber = tr.session(1);
    for (0..20) |i| {
        const sid: u64 = 8 + 4 * i;
        r.admitSubscriber(1, sid, "", "", true, null);
        r.onStreamReset(&subscriber, 0, sid, 0);
    }
    try std.testing.expect(tr.conns[1].sendBufferedBytes() <= MAX_SUB_BACKLOG + N_CACHED_GROUPS * CACHE_GROUP_SIZE + 4096);
}

/// The message types queued on stream `sid` of `c`, in order.
fn sentTypes(c: *connection_mod.Connection, sid: u64, out: []u64) []u64 {
    var data: []const u8 = if (c.streams.getStream(sid)) |st|
        st.send.write_buffer.items
    else if (c.streams.send_streams.get(sid)) |ss|
        ss.write_buffer.items
    else
        return out[0..0];
    var n: usize = 0;
    while (n < out.len) {
        const p = moq_msg.parseEnvelope(data) catch break;
        out[n] = p.env.type;
        n += 1;
        data = data[p.consumed..];
    }
    return out[0..n];
}

/// Client `i` sends one request on its bidi stream `sid`.
fn sendRequest(tr: *TestRelay, i: usize, sid: u64, comptime write: anytype, msg: anytype) !void {
    _ = try tr.conns[i].streams.getOrCreateStream(sid);
    var buf: [512]u8 = undefined;
    var fbs = io_compat.fixedBufferStream(&buf);
    try write(&fbs, msg, tr.r.clients[i].draft);
    var s = tr.session(i);
    tr.r.onStreamData(&s, sid, buf[0..fbs.seek], false);
}

fn setDraft(tr: *TestRelay, d: moq_version.Draft) void {
    for (tr.r.clients[0..2]) |*c| c.draft = d;
}

test "a FIN on a draft-18 PUBLISH_NAMESPACE withdraws it" {
    // moq-net withdraws by finishing the stream, the way drafts 17 and 18
    // left it once PUBLISH_NAMESPACE_DONE was gone. Only a reset counted,
    // so the namespace outlived its publisher and its subscribers never
    // heard NAMESPACE_DONE.
    var tr: TestRelay = undefined;
    try tr.init();
    defer tr.deinit();
    setDraft(&tr, .draft_18);
    const ns: []const []const u8 = &.{ "moq-test", "lifecycle" };

    try sendRequest(&tr, 1, 8, moq_msg.writeSubscribeNamespace, moq_msg.SubscribeNamespace{ .track_namespace_prefix = ns });
    try sendRequest(&tr, 0, 8, moq_msg.writePublishNamespace, moq_msg.PublishNamespace{ .track_namespace = ns });
    var types: [4]u64 = undefined;
    try std.testing.expectEqualSlices(u64, &.{ moq_codes.MSG_REQUEST_OK, moq_codes.MSG_NAMESPACE }, sentTypes(tr.conns[1], 8, &types));

    var publisher = tr.session(0);
    tr.r.onStreamData(&publisher, 8, "", true);
    try std.testing.expect(!tr.r.namespaceAnnounced("moq-test/lifecycle/"));
    try std.testing.expectEqualSlices(u64, &.{
        moq_codes.MSG_REQUEST_OK, moq_codes.MSG_NAMESPACE, moq_codes.MSG_NAMESPACE_DONE,
    }, sentTypes(tr.conns[1], 8, &types));
}

test "a FIN on a draft-18 SUBSCRIBE_NAMESPACE ends it" {
    // §6.1 lets the subscriber cancel with a FIN as well as a reset.
    var tr: TestRelay = undefined;
    try tr.init();
    defer tr.deinit();
    setDraft(&tr, .draft_18);
    try sendRequest(&tr, 1, 8, moq_msg.writeSubscribeNamespace, moq_msg.SubscribeNamespace{ .track_namespace_prefix = &.{"a"} });
    var subscriber = tr.session(1);
    tr.r.onStreamData(&subscriber, 8, "", true);
    for (tr.r.ns_subs) |n| try std.testing.expect(!n.active);
}

/// Publisher client 0's track 0, renamed `ns/` + `t`, with no subscribers.
fn namedTrack(tr: *TestRelay) *Track {
    const t = &tr.r.tracks[0];
    t.sub_count = 0;
    @memcpy(t.namespace_buf[0..3], "ns/");
    t.namespace_len = 3;
    t.name_buf[0] = 't';
    t.name_len = 1;
    return t;
}

test "SUBSCRIBE_TRACKS is answered with a PUBLISH per matching track" {
    // 0x51 fell through to "request type=0x51" and got no answer at all, so
    // aiomoqt's namespace-discovery waited out its timeout.
    var tr: TestRelay = undefined;
    try tr.init();
    defer tr.deinit();
    setDraft(&tr, .draft_18);
    const t = namedTrack(&tr);

    try sendRequest(&tr, 1, 8, moq_msg.writeSubscribeTracks, moq_msg.SubscribeNamespace{ .track_namespace_prefix = &.{"ns"} });
    var types: [4]u64 = undefined;
    try std.testing.expectEqualSlices(u64, &.{moq_codes.MSG_REQUEST_OK}, sentTypes(tr.conns[1], 8, &types));

    // The PUBLISH rides a bidi stream of the relay's own.
    try std.testing.expectEqual(@as(usize, 1), t.sub_count);
    const offer = t.subs[0].stream_id;
    try std.testing.expectEqual(@as(u64, 1), offer & 0x3);
    try std.testing.expectEqualSlices(u64, &.{moq_codes.MSG_PUBLISH}, sentTypes(tr.conns[1], offer, &types));
    const st = tr.conns[1].streams.getStream(offer).?;
    const env = (try moq_msg.parseEnvelope(st.send.write_buffer.items)).env;
    var ns_buf: moq_msg.NamespaceBuf = undefined;
    const p = try moq_msg.decodePublish(env.payload, &ns_buf, .draft_18);
    try std.testing.expectEqual(@as(usize, 1), p.track_namespace.len);
    try std.testing.expectEqualStrings("ns", p.track_namespace[0]);
    try std.testing.expectEqualStrings("t", p.track_name);
    try std.testing.expectEqual(t.subs[0].alias, p.track_alias);

    // Nothing is forwarded until the subscriber accepts.
    try std.testing.expect(!t.subs[0].answered);
    var buf: [64]u8 = undefined;
    var fbs = io_compat.fixedBufferStream(&buf);
    try moq_msg.writePublishOk(&fbs, .{ .forward = true }, .draft_18);
    var subscriber = tr.session(1);
    tr.r.onStreamData(&subscriber, offer, buf[0..fbs.seek], false);
    try std.testing.expect(t.subs[0].answered);

    try tr.openGroup(2);
    var out_found = false;
    var it = tr.conns[1].streams.send_streams.iterator();
    while (it.next()) |e| {
        if (e.key_ptr.* & 0x3 == 0x3 and std.mem.endsWith(u8, e.value_ptr.*.write_buffer.items, "object")) out_found = true;
    }
    try std.testing.expect(out_found);
}

test "a PUBLISH after SUBSCRIBE_TRACKS is offered to the watcher, not back to its publisher" {
    var tr: TestRelay = undefined;
    try tr.init();
    defer tr.deinit();
    setDraft(&tr, .draft_18);
    tr.r.tracks[0].sub_count = 0;

    try sendRequest(&tr, 0, 12, moq_msg.writeSubscribeTracks, moq_msg.SubscribeNamespace{ .track_namespace_prefix = &.{"live"} });
    try sendRequest(&tr, 1, 8, moq_msg.writeSubscribeTracks, moq_msg.SubscribeNamespace{ .track_namespace_prefix = &.{"live"} });
    try sendRequest(&tr, 0, 8, moq_msg.writePublish, moq_msg.Publish{
        .track_namespace = &.{ "live", "room" },
        .track_name = "cam",
        .track_alias = 6,
    });

    const ti = tr.r.findTrack("live/room/", "cam").?;
    const t = &tr.r.tracks[ti];
    try std.testing.expectEqual(@as(usize, 1), t.sub_count);
    try std.testing.expectEqual(@as(usize, 1), t.subs[0].client_idx);
    var types: [4]u64 = undefined;
    try std.testing.expectEqualSlices(u64, &.{moq_codes.MSG_PUBLISH}, sentTypes(tr.conns[1], t.subs[0].stream_id, &types));
}

test "overlapping SUBSCRIBE_TRACKS in one session is refused" {
    // §10.19: PREFIX_OVERLAP. SUBSCRIBE_NAMESPACE has a space of its own.
    var tr: TestRelay = undefined;
    try tr.init();
    defer tr.deinit();
    setDraft(&tr, .draft_18);
    try sendRequest(&tr, 1, 8, moq_msg.writeSubscribeTracks, moq_msg.SubscribeNamespace{ .track_namespace_prefix = &.{"a"} });
    try sendRequest(&tr, 1, 12, moq_msg.writeSubscribeNamespace, moq_msg.SubscribeNamespace{ .track_namespace_prefix = &.{"a"} });
    try sendRequest(&tr, 1, 16, moq_msg.writeSubscribeTracks, moq_msg.SubscribeNamespace{ .track_namespace_prefix = &.{ "a", "b" } });
    var types: [4]u64 = undefined;
    try std.testing.expectEqualSlices(u64, &.{moq_codes.MSG_REQUEST_OK}, sentTypes(tr.conns[1], 12, &types));
    try std.testing.expectEqualSlices(u64, &.{moq_codes.MSG_REQUEST_ERROR}, sentTypes(tr.conns[1], 16, &types));
}

test "a group that beats its SUBSCRIBE_OK is held, not dropped" {
    // The publisher answers the relay's SUBSCRIBE and opens a group at once;
    // when the whole group, FIN included, was read before the answer, its
    // alias was unknown and the stream was freed. moq-rs's data-subgroup-
    // basic lost object (0,0) to it.
    var tr: TestRelay = undefined;
    try tr.init();
    defer tr.deinit();
    const r = tr.r;
    const t = &r.tracks[0];
    t.dropPublisherState();
    t.subs[0].answered = false;
    try std.testing.expect(r.subscribeUpstream(t, 0, null));
    const upstream = t.pub_stream_id.?;

    var buf: [64]u8 = undefined;
    var fbs = io_compat.fixedBufferStream(&buf);
    try moq_obj.writeSubgroupHeader(&fbs, .{
        .track_alias = 5,
        .group = 0,
        .subgroup = 0,
        .publisher_priority = 128,
        .end_of_group = false,
        .per_object_properties = false,
    }, .draft_17);
    try fbs.writeAll("object");
    var publisher = tr.session(0);
    r.onStreamData(&publisher, 2, buf[0..fbs.seek], true);

    fbs = io_compat.fixedBufferStream(&buf);
    try moq_msg.writeSubscribeOk(&fbs, .{ .track_alias = 5 });
    r.onStreamData(&publisher, upstream, buf[0..fbs.seek], false);

    const out = tr.conns[1].streams.send_streams.get(3) orelse return error.GroupDropped;
    try std.testing.expect(std.mem.endsWith(u8, out.write_buffer.items, "object"));
    try std.testing.expect(out.fin_queued);
    try std.testing.expectEqual(@as(?usize, null), r.clients[0].slotOf(2));
}

test "a held group whose alias never comes is let go" {
    var tr: TestRelay = undefined;
    try tr.init();
    defer tr.deinit();
    const r = tr.r;
    var buf: [64]u8 = undefined;
    var fbs = io_compat.fixedBufferStream(&buf);
    try moq_obj.writeSubgroupHeader(&fbs, .{
        .track_alias = 77,
        .group = 0,
        .subgroup = 0,
        .publisher_priority = 128,
        .end_of_group = false,
        .per_object_properties = false,
    }, .draft_17);
    var publisher = tr.session(0);
    r.onStreamData(&publisher, 2, buf[0..fbs.seek], true);
    try std.testing.expect(r.clients[0].slotOf(2) != null);

    r.clients[0].fwdState(2).?.held_since_ns -= HELD_STREAM_MS * std.time.ns_per_ms + 1;
    r.onPollComplete(&publisher);
    try std.testing.expectEqual(@as(?usize, null), r.clients[0].slotOf(2));
}

test "the upstream SUBSCRIBE carries the subscriber's filter, absence included" {
    // §10.2.9: no SUBSCRIPTION_FILTER means unfiltered. The relay asked
    // upstream for Largest Object instead, so a publisher that had already
    // produced (0,0) started after it, and moq-rs's data-subgroup-basic
    // missed that object.
    var tr: TestRelay = undefined;
    try tr.init();
    defer tr.deinit();
    setDraft(&tr, .draft_18);
    tr.r.tracks[0] = .{};
    tr.r.track_count = 0;
    const ns: []const []const u8 = &.{ "moq-test", "dp" };
    try sendRequest(&tr, 0, 8, moq_msg.writePublishNamespace, moq_msg.PublishNamespace{ .track_namespace = ns });

    const cases = [_]?moq_msg.Filter{ null, .{ .type = .next_group_start } };
    for (cases, 0..) |want, i| {
        const name: []const u8 = if (i == 0) "a" else "b";
        try sendRequest(&tr, 1, 12 + 4 * i, moq_msg.writeSubscribe, moq_msg.Subscribe{
            .track_namespace = ns,
            .track_name = name,
            .filter = want,
        });
        const t = &tr.r.tracks[tr.r.findTrack("moq-test/dp/", name).?];
        const st = tr.conns[0].streams.getStream(t.pub_stream_id.?).?;
        const env = (try moq_msg.parseEnvelope(st.send.write_buffer.items)).env;
        var ns_buf: moq_msg.NamespaceBuf = undefined;
        const up = try moq_msg.decodeSubscribe(env.payload, &ns_buf, .draft_18);
        try std.testing.expectEqual(want, up.filter);
    }
}

test "withdrawing a namespace under someone else's prefix still ends it" {
    // Whether anyone still holds the namespace was asked by prefix, so a
    // publisher of `a` kept `a/b` alive for its subscribers after `a/b`'s
    // own publisher withdrew it.
    var tr: TestRelay = undefined;
    try tr.init();
    defer tr.deinit();
    setDraft(&tr, .draft_18);
    try sendRequest(&tr, 1, 8, moq_msg.writeSubscribeNamespace, moq_msg.SubscribeNamespace{ .track_namespace_prefix = &.{"a"} });
    try sendRequest(&tr, 0, 8, moq_msg.writePublishNamespace, moq_msg.PublishNamespace{ .track_namespace = &.{"a"} });
    try sendRequest(&tr, 1, 12, moq_msg.writePublishNamespace, moq_msg.PublishNamespace{ .track_namespace = &.{ "a", "b" } });
    var types: [6]u64 = undefined;
    try std.testing.expectEqualSlices(u64, &.{
        moq_codes.MSG_REQUEST_OK, moq_codes.MSG_NAMESPACE, moq_codes.MSG_NAMESPACE,
    }, sentTypes(tr.conns[1], 8, &types));

    var other = tr.session(1);
    tr.r.onStreamReset(&other, 0, 12, 0);
    try std.testing.expectEqualSlices(u64, &.{
        moq_codes.MSG_REQUEST_OK, moq_codes.MSG_NAMESPACE, moq_codes.MSG_NAMESPACE, moq_codes.MSG_NAMESPACE_DONE,
    }, sentTypes(tr.conns[1], 8, &types));
}

test "two groups in flight at once don't share a cache entry" {
    // The track had one live cache. A second group's stream opening reset
    // it, the first group's later bytes were appended to the second's, and
    // the first one's FIN cached the mixture as the second group: a late
    // subscriber was replayed bytes from both.
    var tr: TestRelay = undefined;
    try tr.init();
    defer tr.deinit();
    const r = tr.r;
    var publisher = tr.session(0);

    try tr.openGroup(2); // group 1: "object"
    var buf: [64]u8 = undefined;
    var fbs = io_compat.fixedBufferStream(&buf);
    try moq_obj.writeSubgroupHeader(&fbs, .{
        .track_alias = 5,
        .group = 2,
        .subgroup = 0,
        .publisher_priority = 128,
        .end_of_group = false,
        .per_object_properties = false,
    }, .draft_17);
    try fbs.writeAll("second");
    r.onStreamData(&publisher, 6, buf[0..fbs.seek], false);
    r.onStreamData(&publisher, 2, "-more", true);
    r.onStreamData(&publisher, 6, "", true);

    for (r.tracks[0].cached) |g| {
        if (!g.valid) continue;
        const want: []const u8 = if (g.hdr.group == 1) "object-more" else "second";
        try std.testing.expectEqualStrings(want, g.payload[0..g.payload_len]);
    }
}

test "a datagram that beats its SUBSCRIBE_OK is held, not dropped" {
    // Datagrams aren't ordered against the publisher's answer on its request
    // stream, so the first object of a datagram track often arrived under an
    // alias nothing had established yet, and was dropped: moq-rs's
    // moq-test-datagram missed (0,0).
    var tr: TestRelay = undefined;
    try tr.init();
    defer tr.deinit();
    const r = tr.r;
    tr.conns[1].datagrams_enabled = true;
    const t = &r.tracks[0];
    t.dropPublisherState();
    t.subs[0].answered = false;
    try std.testing.expect(r.subscribeUpstream(t, 0, null));
    const upstream = t.pub_stream_id.?;

    var buf: [64]u8 = undefined;
    var fbs = io_compat.fixedBufferStream(&buf);
    try moq_obj.writeDatagramObject(&fbs, .{
        .track_alias = 5,
        .group = 0,
        .object = 0,
        .publisher_priority = 128,
        .end_of_group = false,
        .body = .{ .payload = "first" },
    });
    var publisher = tr.session(0);
    r.onDatagram(&publisher, 0, buf[0..fbs.seek]);
    try std.testing.expectEqual(@as(usize, 0), tr.conns[1].datagram_send_queue.count);

    fbs = io_compat.fixedBufferStream(&buf);
    try moq_msg.writeSubscribeOk(&fbs, .{ .track_alias = 5 });
    r.onStreamData(&publisher, upstream, buf[0..fbs.seek], false);
    try std.testing.expectEqual(@as(usize, 1), tr.conns[1].datagram_send_queue.count);
}
