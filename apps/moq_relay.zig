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

/// `upstream`: a SUBSCRIBE the relay sent a namespace's publisher, whose
/// answer comes back on the same stream.
const StreamRole = enum { control, request, upstream, data, unknown };

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
    subs: [MAX_SUBS_PER_TRACK]Sub = [_]Sub{.{}} ** MAX_SUBS_PER_TRACK,
    sub_count: usize = 0,

    // Completed groups cached for late subscribers.
    cached: [N_CACHED_GROUPS]CachedGroup = [_]CachedGroup{.{}} ** N_CACHED_GROUPS,
    next_cache_idx: usize = 0,
    // The live group being assembled from the publisher's current stream.
    live: CachedGroup = .{},

    fn removeSub(self: *Track, si: usize) void {
        self.sub_count -= 1;
        self.subs[si] = self.subs[self.sub_count];
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
        self.publisher_idx = null;
        self.pub_alias = 0;
        self.pub_stream_id = null;
        self.upstream_idx = null;
        self.upstream_pending = false;
        for (&self.cached) |*g| g.valid = false;
        self.next_cache_idx = 0;
        self.live = .{};
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
    stream_ids: [MAX_STREAMS_PER_CLIENT]u64 = [_]u64{std.math.maxInt(u64)} ** MAX_STREAMS_PER_CLIENT,
    stream_roles: [MAX_STREAMS_PER_CLIENT]StreamRole = [_]StreamRole{.unknown} ** MAX_STREAMS_PER_CLIENT,
    stream_bufs: [MAX_STREAMS_PER_CLIENT]StreamBuf = [_]StreamBuf{.{}} ** MAX_STREAMS_PER_CLIENT,
    fwd_states: [MAX_STREAMS_PER_CLIENT]FwdState = [_]FwdState{.{}} ** MAX_STREAMS_PER_CLIENT,

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
    out_stream_ids: [MAX_SUBS_PER_TRACK]u64 = [_]u64{0} ** MAX_SUBS_PER_TRACK,
    out_sub_idx: [MAX_SUBS_PER_TRACK]usize = [_]usize{0} ** MAX_SUBS_PER_TRACK,
    out_count: usize = 0,
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
    active: bool = false,

    fn key(self: *const AnnouncedNamespace) []const u8 {
        return self.buf[0..self.len];
    }
};

/// A SUBSCRIBE_NAMESPACE: this client wants to hear about every namespace
/// under a prefix, the ones already here and the ones that arrive later
/// (§6.1). §6.2 makes answering it a MUST for a relay holding the namespace.
const NamespaceSub = struct {
    prefix_buf: [256]u8 = undefined,
    prefix_len: usize = 0,
    client_idx: usize = 0,
    stream_id: u64 = 0,
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
    active: bool = false,
};

const RelayHandler = struct {
    pub const protocol: event_loop.Protocol = .webtransport;
    /// Also take native-QUIC MoQT on the same port; see the header.
    pub const raw_quic = true;
    /// Rendezvous timeouts are ours to keep, and the loop otherwise only
    /// wakes on peer traffic.
    pub const poll_interval_ms: u64 = 50;

    clients: [MAX_CLIENTS]Client = [_]Client{.{}} ** MAX_CLIENTS,
    tracks: [MAX_TRACKS]Track = [_]Track{.{}} ** MAX_TRACKS,
    track_count: usize = 0,
    namespaces: [MAX_NAMESPACES]AnnouncedNamespace = [_]AnnouncedNamespace{.{}} ** MAX_NAMESPACES,
    pending: [MAX_PENDING_SUBS]PendingSub = [_]PendingSub{.{}} ** MAX_PENDING_SUBS,
    ns_subs: [MAX_NAMESPACE_SUBS]NamespaceSub = [_]NamespaceSub{.{}} ** MAX_NAMESPACE_SUBS,
    ns_seq: u64 = 0,

    /// The loop frees the connection right after this fires, so the entry
    /// pointer stops being a valid key the moment we return. Without it a
    /// relay simply runs out of client slots.
    pub fn onSessionClosed(self: *RelayHandler, session: *event_loop.Session, _: u64, _: u32, _: []const u8) void {
        const ci = blk: {
            for (&self.clients, 0..) |*c, i| if (c.active and c.entry == session.entry) break :blk i;
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
        }
        for (&self.ns_subs) |*n| {
            if (n.active and n.client_idx == ci) n.active = false;
        }
        for (&self.namespaces) |*n| {
            if (!n.active or n.client_idx != ci) continue;
            n.active = false;
            // Nobody else announced it, so as far as this relay is concerned
            // the namespace is gone and its subscribers should hear so.
            if (!self.namespaceAnnounced(n.key())) self.announceNamespace(n.key(), true);
        }
        for (&self.pending) |*pn| {
            if (pn.active and pn.client_idx == ci) pn.active = false;
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
            for (&self.clients) |*c| { if (c.active) live += 1; }
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
            .data => self.tryForwardData(ci, stream_id, fin),
        }

        // Reclaim slot when stream is done — data streams close after each object.
        if (fin) {
            const r = self.clients[ci].getRole(stream_id);
            if (r == .data or r == .unknown) self.clients[ci].clearSlot(stream_id);
        }
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
            => self.handleSubscribeNamespace(ci, session, stream_id, env.payload),
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

    /// §6.1 namespace discovery: answer REQUEST_OK, then NAMESPACE for every
    /// namespace already under the prefix. Later arrivals are pushed by
    /// announceNamespace.
    fn handleSubscribeNamespace(self: *RelayHandler, ci: usize, session: *event_loop.Session, stream_id: u64, payload: []const u8) void {
        var ns_buf: moq_msg.NamespaceBuf = undefined;
        const sn = moq_msg.decodeSubscribeNamespace(payload, &ns_buf, self.clients[ci].draft) catch |e| {
            self.rejectRequest(ci, session, stream_id, e, "subscribe_namespace", payload);
            return;
        };

        const slot = for (&self.ns_subs) |*n| {
            if (!n.active) break n;
        } else {
            self.sendRequestError(session, stream_id, moq_codes.ERR_EXCESSIVE_LOAD, "too many namespace subscriptions");
            return;
        };
        slot.prefix_len = moq_wire.flattenNamespace(sn.track_namespace_prefix, &slot.prefix_buf);
        slot.client_idx = ci;
        slot.stream_id = stream_id;
        slot.active = true;

        self.sendRequestOk(session, stream_id);
        std.debug.print("[relay] SUBSCRIBE_NAMESPACE client={d} prefix=\"{s}\"\n", .{ ci, slot.prefix() });

        var sent: usize = 0;
        for (&self.namespaces) |*n| {
            if (!n.active) continue;
            if (!std.mem.startsWith(u8, n.key(), slot.prefix())) continue;
            self.sendNamespace(slot, n.key(), false);
            sent += 1;
        }
        if (sent > 0) std.debug.print("[relay] → {d} NAMESPACE to client {d}\n", .{ sent, ci });
    }

    /// NAMESPACE / NAMESPACE_DONE carry only what follows the prefix the
    /// subscription asked for (§10.16), so the suffix is cut here rather than
    /// the whole namespace being echoed back.
    fn sendNamespace(self: *RelayHandler, sub: *const NamespaceSub, ns_key: []const u8, done: bool) void {
        var parts: [moq_wire.MAX_TUPLE_PARTS][]const u8 = undefined;
        var buf: [512]u8 = undefined;
        var fbs = io_compat.fixedBufferStream(&buf);
        const msg = moq_msg.Namespace{
            .track_namespace_suffix = moq_wire.splitNamespace(ns_key[sub.prefix_len..], &parts),
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
        const key_len = moq_wire.flattenNamespace(pn.track_namespace, &key);
        std.debug.print("[relay] PUBLISH_NAMESPACE client={d} ns=\"{s}\"\n", .{ ci, key[0..key_len] });

        const outcome = self.registerNamespace(ci, stream_id, key[0..key_len]);
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
    fn registerNamespace(self: *RelayHandler, ci: usize, stream_id: u64, key: []const u8) Registered {
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
        self.ns_seq += 1;
        slot.seq = self.ns_seq;
        slot.active = true;
        return if (held_by_other) .already_held else .added;
    }

    fn namespaceAnnounced(self: *RelayHandler, ns: []const u8) bool {
        for (&self.namespaces) |*n| {
            if (n.active and std.mem.startsWith(u8, ns, n.key())) return true;
        }
        return false;
    }

    fn holdPending(self: *RelayHandler, ci: usize, stream_id: u64, ns: []const u8, name: []const u8, wait_ms: u64, forward: bool) bool {
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
            self.admitSubscriber(p.client_idx, p.stream_id, p.ns_buf[0..p.ns_len], p.name_buf[0..p.name_len], p.forward);
        }
    }

    pub fn onPollComplete(self: *RelayHandler, _: *event_loop.Session) void {
        const now = sys.nanoTimestamp();
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
        const ns_len = moq_wire.flattenNamespace(sub.track_namespace, &ns_key);
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
            if (!self.holdPending(ci, stream_id, ns_key[0..ns_len], sub.track_name, wait_ms, sub.forward orelse true)) {
                self.sendRequestError(session, stream_id, moq_codes.ERR_EXCESSIVE_LOAD, "too many pending subscriptions");
            }
            return;
        }

        self.admitSubscriber(ci, stream_id, ns_key[0..ns_len], sub.track_name, sub.forward orelse true);
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
        t.* = .{ .active = true };
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
    pub fn onStreamReset(self: *RelayHandler, session: *event_loop.Session, _: u64, stream_id: u64, _: u32) void {
        const ci = for (&self.clients, 0..) |*c, i| {
            if (c.active and c.entry == session.entry) break i;
        } else return;
        self.requestWithdrawn(ci, stream_id);
        self.clients[ci].clearSlot(stream_id);
    }

    fn requestWithdrawn(self: *RelayHandler, ci: usize, stream_id: u64) void {
        for (&self.namespaces) |*n| {
            if (!n.active or n.client_idx != ci or n.stream_id != stream_id) continue;
            n.active = false;
            std.debug.print("[relay] namespace \"{s}\" withdrawn by client {d}\n", .{ n.key(), ci });
            if (!self.namespaceAnnounced(n.key())) self.announceNamespace(n.key(), true);
        }
        for (self.tracks[0..self.track_count]) |*t| {
            if (!t.active) continue;
            var si: usize = 0;
            while (si < t.sub_count) {
                if (t.subs[si].client_idx == ci and t.subs[si].stream_id == stream_id) {
                    t.removeSub(si);
                } else si += 1;
            }
            if (t.sub_count == 0 and t.upstream_idx != null and t.upstream_idx != ci) self.unsubscribeUpstream(t);
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
    fn subscribeUpstream(self: *RelayHandler, t: *Track, owner: usize) bool {
        var l = self.link(owner) orelse return false;
        var parts: [moq_wire.MAX_TUPLE_PARTS][]const u8 = undefined;
        var buf: [512]u8 = undefined;
        var fbs = io_compat.fixedBufferStream(&buf);
        moq_msg.writeSubscribe(&fbs, .{
            .request_id = self.clients[owner].next_request_id,
            .track_namespace = moq_wire.splitNamespace(t.namespace_buf[0..t.namespace_len], &parts),
            .track_name = t.name_buf[0..t.name_len],
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
        if (t.sub_count == 0) t.active = false;
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
                    } else |e| {
                        std.debug.print("[relay] undecodable upstream SUBSCRIBE_OK client={d}: {t}\n", .{ ci, e });
                        self.failWaitingSubs(tr, moq_codes.ERR_INTERNAL_ERROR, "publisher answer undecodable");
                    }
                },
                moq_codes.MSG_REQUEST_ERROR => {
                    const e = moq_msg.decodeRequestError(parsed.env.payload) catch moq_msg.RequestError{ .error_code = moq_codes.ERR_INTERNAL_ERROR, .reason = "" };
                    std.debug.print("[relay] REQUEST_ERROR ← publisher client {d} code={d}\n", .{ ci, e.error_code });
                    self.failWaitingSubs(tr, e.error_code, e.reason);
                },
                moq_codes.MSG_PUBLISH_DONE => self.handlePublishDone(ci, stream_id, parsed.env.payload),
                else => std.debug.print("[relay] upstream client {d} type=0x{x}\n", .{ ci, parsed.env.type }),
            };

            const remaining = buf.slice()[parsed.consumed..];
            std.mem.copyForwards(u8, &buf.data, remaining);
            buf.len = remaining.len;
        }
    }

    fn sendSubscribeOk(self: *RelayHandler, sub: *const Sub) void {
        var buf: [256]u8 = undefined;
        var fbs = io_compat.fixedBufferStream(&buf);
        moq_msg.writeSubscribeOk(&fbs, .{ .track_alias = sub.alias }) catch return;
        self.sendToClient(sub.client_idx, sub.stream_id, buf[0..fbs.seek]);
    }

    fn admitSubscriber(self: *RelayHandler, ci: usize, stream_id: u64, ns_key: []const u8, track_name: []const u8, forward: bool) void {
        const ti = self.findTrack(ns_key, track_name) orelse
            self.allocTrack(ns_key, track_name) orelse {
            self.sendToClientError(ci, stream_id, moq_codes.ERR_EXCESSIVE_LOAD, "track table full");
            return;
        };

        var t = &self.tracks[ti];
        if (t.publisher_idx == null and !t.upstream_pending) {
            if (self.namespaceOwner(ns_key)) |owner| {
                if (owner != ci) _ = self.subscribeUpstream(t, owner);
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

    // Replay every cached complete group to a freshly-subscribed subscriber.
    // Each cached group is sent as a fresh uni stream on the subscriber's WT
    // session with the subscriber's track alias remapped.
    fn replayCachedGroups(self: *RelayHandler, t: *const Track, sub: *Sub) void {
        if (!sub.forward) return;
        const sub_ci = sub.client_idx;
        var l = self.link(sub_ci) orelse return;

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
        const ns_len = moq_wire.flattenNamespace(pub_msg.track_namespace, &ns_key);
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
        _ = self.registerNamespace(ci, stream_id, ns_key[0..ns_len]);

        var buf: [256]u8 = undefined;
        var fbs = io_compat.fixedBufferStream(&buf);
        moq_msg.writePublishOk(&fbs, .{}, self.clients[ci].draft) catch return;
        self.sendOnStream(session, stream_id, buf[0..fbs.seek]);
        std.debug.print("[relay] PUBLISH_OK → client {d} (track {d}, {d} subs)\n", .{ ci, ti, t.sub_count });

        // A held subscriber may be waiting on this track (§9.3.4).
        self.resolvePending(ns_key[0..ns_len]);
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
            const ti = track_idx orelse return;
            const t = &self.tracks[ti];
            fs.track_idx = ti;

            // Initialize the live cache for this group on the track.
            t.live.reset();
            t.live.valid = false;
            t.live.hdr = h;

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
            if (fs.track_idx) |ti_cap| {
                const t = &self.tracks[ti_cap];
                const free = t.live.payload.len - t.live.payload_len;
                const copy_n = @min(chunk.len, free);
                if (copy_n > 0) {
                    @memcpy(t.live.payload[t.live.payload_len .. t.live.payload_len + copy_n], chunk[0..copy_n]);
                    t.live.payload_len += copy_n;
                }
            }
            // Forward to currently-attached subscribers.
            for (0..fs.out_count) |i| {
                const sub_ci = fs.out_sub_idx[i];
                var l = self.link(sub_ci) orelse continue;
                l.send(fs.out_stream_ids[i], chunk) catch |e| {
                    std.debug.print("[relay] fwd chunk to sub {d}: {}\n", .{ sub_ci, e });
                };
            }
            fs.forwarded_pos = buf.len;
        }

        // On FIN: close all sub-streams and commit the live cache.
        if (fin) {
            for (0..fs.out_count) |i| {
                const sub_ci = fs.out_sub_idx[i];
                var l = self.link(sub_ci) orelse continue;
                l.finish(fs.out_stream_ids[i]);
            }
            if (fs.track_idx) |ti_cap| {
                const t = &self.tracks[ti_cap];
                if (t.live.payload_len > 0) {
                    t.cacheGroup(&t.live);
                    std.debug.print("[relay] cached group {d} for track {d} ({d} bytes)\n", .{
                        t.live.hdr.group, ti_cap, t.live.payload_len,
                    });
                }
                t.live.reset();
            }
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

        var fbs = io_compat.fixedBufferStream(data);
        const dtype = moq_wire.readVarInt(&fbs) catch return;
        const alias = moq_wire.readVarInt(&fbs) catch return;
        if (!moq_codes.isDatagramObjectType(dtype)) return;
        const rest = data[fbs.seek..];

        const t = for (self.tracks[0..self.track_count]) |*t| {
            if (t.active and t.publisher_idx == ci and t.pub_alias == alias) break t;
        } else return;

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

    var args = std.process.Args.Iterator.init(init.args);
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
