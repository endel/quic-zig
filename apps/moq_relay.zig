// MoQ Transport draft-17 relay server.
//
// Accepts MoQ connections over raw QUIC. Publishers announce tracks via
// SUBSCRIBE (yes — in draft-17 the subscriber sends SUBSCRIBE, the
// relay forwards to the publisher side). The relay matches subscribers
// to publishers by track namespace + name, and forwards subgroup stream
// objects from publisher to subscriber.
//
// Simplified single-node relay for interop testing.
//
// Usage:
//   zig-out/bin/moq-relay --port 4443

const std = @import("std");
const quic = @import("quic");
const io_compat = @import("quic").io_compat;
const sys = quic.sys;
const event_loop = quic.event_loop;
const tls13 = quic.tls13;
const connection_mod = quic.connection;

const moq_wire = quic.moq.wire;
const moq_msg = quic.moq.message;
const moq_codes = quic.moq.message_codes;
const moq_obj = quic.moq.object;
const moq_version = quic.moq.version;
const moq_track = quic.moq.track;

pub const std_options: std.Options = .{ .log_level = .err };

const MAX_CLIENTS: usize = 32;
const MAX_TRACKS: usize = 64;
const MAX_NAMESPACES: usize = 64;
const MAX_PENDING_SUBS: usize = 32;
const MAX_SUBS_PER_TRACK: usize = 16;
const DUMP_HEAD_BYTES: usize = 48; // of an undecodable message, for the log

const StreamRole = enum { control, request, data, unknown };

const STREAM_BUF_SIZE: usize = 64 * 1024;
const MAX_STREAM_SLOTS: usize = 32;
const MAX_ROLE_SLOTS: usize = 128;
const NO_STREAM: u64 = std.math.maxInt(u64);

const StreamBuf = struct {
    data: [STREAM_BUF_SIZE]u8 = undefined,
    len: usize = 0,

    fn append(self: *StreamBuf, bytes: []const u8) void {
        const n = @min(bytes.len, self.data.len - self.len);
        @memcpy(self.data[self.len .. self.len + n], bytes[0..n]);
        self.len += n;
    }
    fn slice(self: *const StreamBuf) []const u8 {
        return self.data[0..self.len];
    }
    fn reset(self: *StreamBuf) void {
        self.len = 0;
    }
};

// A published track from a client.
/// One subscriber of a track.
const Sub = struct {
    client_idx: usize = 0,
    alias: u64 = 0,
    /// Its request stream, so PUBLISH_DONE can be sent on it.
    stream_id: u64 = 0,
    /// Data streams opened for it, for PUBLISH_DONE's Stream Count.
    streams: u64 = 0,
    /// Send this one its first tick on the next poll; see admitSubscriber.
    pending_initial: bool = false,
};

const Track = struct {
    namespace_buf: [256]u8 = undefined,
    namespace_len: usize = 0,
    name_buf: [128]u8 = undefined,
    name_len: usize = 0,
    publisher_idx: ?usize = null,
    pub_alias: u64 = 0,
    active: bool = false,
    // Subscribers waiting for objects on this track.
    subs: [MAX_SUBS_PER_TRACK]Sub = [_]Sub{.{}} ** MAX_SUBS_PER_TRACK,
    sub_count: usize = 0,
    /// The bidi stream the publisher's PUBLISH arrived on; its PUBLISH_DONE
    /// comes back on the same one.
    pub_stream_id: ?u64 = null,

    fn removeSub(self: *Track, si: usize) void {
        self.sub_count -= 1;
        self.subs[si] = self.subs[self.sub_count];
    }

    fn dropPublisherState(self: *Track) void {
        self.publisher_idx = null;
        self.pub_alias = 0;
        self.pub_stream_id = null;
    }

    fn matchesNsName(self: *const Track, ns: []const u8, name: []const u8) bool {
        return std.mem.eql(u8, self.namespace_buf[0..self.namespace_len], ns) and
            std.mem.eql(u8, self.name_buf[0..self.name_len], name);
    }
};

// A namespace a client has advertised with PUBLISH_NAMESPACE. Tracks under
// an announced prefix can be subscribed to before the publisher has opened
// them; anything else does not exist as far as this relay is concerned.
const AnnouncedNamespace = struct {
    buf: [256]u8 = undefined,
    len: usize = 0,
    client_idx: usize = 0,
    stream_id: u64 = 0,
    active: bool = false,

    fn key(self: *const AnnouncedNamespace) []const u8 {
        return self.buf[0..self.len];
    }
};

// A SUBSCRIBE for a namespace nobody has announced, held open because the
// subscriber sent a non-zero RENDEZVOUS_TIMEOUT (§9.3.4).
const PendingSub = struct {
    ns_buf: [256]u8 = undefined,
    ns_len: usize = 0,
    name_buf: [128]u8 = undefined,
    name_len: usize = 0,
    client_idx: usize = 0,
    stream_id: u64 = 0,
    deadline_ns: i128 = 0,
    active: bool = false,
};

// Per-client connection state.
const Client = struct {
    active: bool = false,
    conn: ?*connection_mod.Connection = null,
    /// Which draft this peer chose, read off the ALPN it negotiated.
    draft: moq_version.Draft = moq_version.DEFAULT,
    setup_done: bool = false,
    impl_name: [64]u8 = undefined,
    impl_len: usize = 0,
    control_out: ?u64 = null,
    next_alias: u64 = 1,
    // Roles are keyed by stream id, not indexed by it: a long-lived connection
    // runs past any fixed id ceiling. Entries are released on FIN.
    role_ids: [MAX_ROLE_SLOTS]u64 = [_]u64{NO_STREAM} ** MAX_ROLE_SLOTS,
    role_vals: [MAX_ROLE_SLOTS]StreamRole = [_]StreamRole{.unknown} ** MAX_ROLE_SLOTS,
    // Slot-based buffer for streams currently being identified (role=.unknown)
    // or accumulating request messages that span multiple chunks.
    slot_ids: [MAX_STREAM_SLOTS]u64 = [_]u64{NO_STREAM} ** MAX_STREAM_SLOTS,
    slot_bufs: [MAX_STREAM_SLOTS]StreamBuf = [_]StreamBuf{.{}} ** MAX_STREAM_SLOTS,

    // Returns false when the table is full — the caller must then drop the
    // stream rather than leave it unclassified and re-parsed on every chunk.
    fn setRole(self: *Client, sid: u64, role: StreamRole) bool {
        for (&self.role_ids, 0..) |id, i| if (id == sid) {
            self.role_vals[i] = role;
            return true;
        };
        for (&self.role_ids, 0..) |id, i| if (id == NO_STREAM) {
            self.role_ids[i] = sid;
            self.role_vals[i] = role;
            return true;
        };
        return false;
    }
    fn getRole(self: *Client, sid: u64) StreamRole {
        for (&self.role_ids, 0..) |id, i| if (id == sid) return self.role_vals[i];
        return .unknown;
    }
    fn clearRole(self: *Client, sid: u64) void {
        for (&self.role_ids, 0..) |id, i| if (id == sid) {
            self.role_ids[i] = NO_STREAM;
            self.role_vals[i] = .unknown;
            return;
        };
    }
    fn slotFor(self: *Client, sid: u64) ?*StreamBuf {
        for (&self.slot_ids, 0..) |id, i| if (id == sid) return &self.slot_bufs[i];
        for (&self.slot_ids, 0..) |id, i| {
            if (id == NO_STREAM) {
                self.slot_ids[i] = sid;
                self.slot_bufs[i].reset();
                return &self.slot_bufs[i];
            }
        }
        return null;
    }
    fn freeSlot(self: *Client, sid: u64) void {
        for (&self.slot_ids, 0..) |id, i| {
            if (id == sid) {
                self.slot_ids[i] = NO_STREAM;
                self.slot_bufs[i].reset();
                return;
            }
        }
    }
};

const RelayHandler = struct {
    pub const protocol: event_loop.Protocol = .quic;
    /// Rendezvous timeouts and the synthetic clock tick both need the loop
    /// to come back even when the connection is idle.
    pub const poll_interval_ms: u64 = 50;

    clients: [MAX_CLIENTS]Client = [_]Client{.{}} ** MAX_CLIENTS,
    namespaces: [MAX_NAMESPACES]AnnouncedNamespace = [_]AnnouncedNamespace{.{}} ** MAX_NAMESPACES,
    pending: [MAX_PENDING_SUBS]PendingSub = [_]PendingSub{.{}} ** MAX_PENDING_SUBS,
    tracks: [MAX_TRACKS]Track = [_]Track{.{}} ** MAX_TRACKS,
    track_count: usize = 0,
    group_id: u64 = 0,
    last_tick_ns: i128 = 0,

    fn draftOf(self: *RelayHandler, ci: usize) moq_version.Draft {
        return self.clients[ci].draft;
    }

    fn findOrCreateClient(self: *RelayHandler, conn: *connection_mod.Connection) ?usize {
        // Check if this connection is already tracked.
        for (&self.clients, 0..) |*c, i| {
            if (c.active and c.conn == conn) return i;
        }
        // Allocate a new slot.
        for (&self.clients, 0..) |*c, i| {
            if (!c.active) {
                c.* = .{
                    .active = true,
                    .conn = conn,
                    .draft = moq_version.Draft.fromAlpn(conn.negotiatedAlpn()) orelse moq_version.DEFAULT,
                };
                std.debug.print("[relay] client {d} speaks {s}\n", .{ i, c.draft.alpn() });
                return i;
            }
        }
        return null; // full
    }

    fn clientIdx(self: *RelayHandler, conn: *connection_mod.Connection) ?usize {
        for (&self.clients, 0..) |*c, i| {
            if (c.active and c.conn == conn) return i;
        }
        return null;
    }

    fn findTrack(self: *RelayHandler, ns_key: []const u8, name: []const u8) ?usize {
        for (self.tracks[0..self.track_count], 0..) |*t, i| {
            if (t.active and t.matchesNsName(ns_key, name)) return i;
        }
        return null;
    }

    pub fn onStreamData(self: *RelayHandler, session: *event_loop.Session, stream_id: u64, data: []const u8, fin: bool) void {
        const conn = session.entry.conn;
        const ci = self.findOrCreateClient(conn) orelse return;
        defer if (fin) {
            self.clients[ci].clearRole(stream_id);
            self.clients[ci].freeSlot(stream_id);
        };
        if (data.len == 0) return;

        const role = self.clients[ci].getRole(stream_id);
        switch (role) {
            .unknown => self.handleNewStream(ci, stream_id, data),
            .control => {},
            .request => self.handleRequest(ci, stream_id, data),
            .data => self.handleDataStream(ci, stream_id, data),
        }
    }

    fn handleNewStream(self: *RelayHandler, ci: usize, stream_id: u64, data: []const u8) void {
        // Buffer the stream bytes until we can identify its role.
        const buf = self.clients[ci].slotFor(stream_id) orelse {
            // Slots exhausted: abandon this stream.
            _ = self.clients[ci].setRole(stream_id, .data);
            return;
        };
        buf.append(data);

        // Need at least 3 bytes to parse envelope (varint type + u16 length).
        if (buf.len < 3) return;

        const parsed = moq_msg.parseEnvelope(buf.slice()) catch {
            // If we already have enough bytes but envelope parsing still
            // fails, treat it as a data stream (publisher subgroup header).
            if (buf.len >= 3) {
                if (!self.clients[ci].setRole(stream_id, .data)) {
                    self.clients[ci].freeSlot(stream_id);
                    return;
                }
                self.handleDataStream(ci, stream_id, buf.slice());
                self.clients[ci].freeSlot(stream_id);
            }
            return;
        };

        if (parsed.env.type == moq_codes.MSG_SETUP) {
            if (!self.clients[ci].setRole(stream_id, .control)) {
                self.clients[ci].freeSlot(stream_id);
                return;
            }
            const opts = moq_msg.decodeSetupPayload(parsed.env.payload) catch return;
            if (opts.implementation) |impl| {
                const len = @min(impl.len, 64);
                @memcpy(self.clients[ci].impl_name[0..len], impl[0..len]);
                self.clients[ci].impl_len = len;
            }
            std.debug.print("[relay] SETUP from client {d}", .{ci});
            if (self.clients[ci].impl_len > 0)
                std.debug.print(" impl=\"{s}\"", .{self.clients[ci].impl_name[0..self.clients[ci].impl_len]});
            std.debug.print("\n", .{});

            // Send SETUP back on our control uni stream.
            const conn = self.clients[ci].conn orelse return;
            const ctrl = conn.openUniStream() catch return;
            self.clients[ci].control_out = ctrl.stream_id;

            var setup_buf: [256]u8 = undefined;
            var fbs = io_compat.fixedBufferStream(&setup_buf);
            moq_msg.writeSetup(&fbs, .{
                .implementation = "quic-zig/moq-relay",
            }) catch return;
            ctrl.writeData(setup_buf[0..fbs.seek]) catch return;
            self.clients[ci].setup_done = true;
            std.debug.print("[relay] Sent SETUP to client {d}\n", .{ci});
            self.clients[ci].freeSlot(stream_id);
        } else {
            // It's a request on a bidi stream. Pass the buffered payload to
            // the request handler so it has the full envelope.
            if (!self.clients[ci].setRole(stream_id, .request)) {
                self.clients[ci].freeSlot(stream_id);
                return;
            }
            const full = self.clients[ci].slotFor(stream_id).?.slice();
            // Copy slice before freeing the slot.
            var req_buf: [STREAM_BUF_SIZE]u8 = undefined;
            @memcpy(req_buf[0..full.len], full);
            const full_len = full.len;
            self.clients[ci].freeSlot(stream_id);
            self.handleRequest(ci, stream_id, req_buf[0..full_len]);
        }
    }

    fn handleRequest(self: *RelayHandler, ci: usize, stream_id: u64, data: []const u8) void {
        const parsed = moq_msg.parseEnvelope(data) catch return;
        switch (parsed.env.type) {
            moq_codes.MSG_SUBSCRIBE => self.handleSubscribe(ci, stream_id, parsed.env.payload),
            moq_codes.MSG_PUBLISH => self.handlePublish(ci, stream_id, parsed.env.payload),
            moq_codes.MSG_SUBSCRIBE_NAMESPACE,
            moq_codes.MSG_SUBSCRIBE_NAMESPACE_18,
            => self.handleSubscribeNamespace(ci, stream_id, parsed.env.payload),
            moq_codes.MSG_PUBLISH_NAMESPACE => self.handlePublishNamespace(ci, stream_id, parsed.env.payload),
            moq_codes.MSG_PUBLISH_DONE => self.handlePublishDone(ci, stream_id, parsed.env.payload),
            else => std.debug.print("[relay] Request type=0x{x} from client {d}\n", .{ parsed.env.type, ci }),
        }
    }

    fn handleSubscribeNamespace(self: *RelayHandler, ci: usize, stream_id: u64, payload: []const u8) void {
        var ns_buf: moq_msg.NamespaceBuf = undefined;
        const sn = moq_msg.decodeSubscribeNamespace(payload, &ns_buf, self.draftOf(ci)) catch |e| {
            std.debug.print("[relay] undecodable SUBSCRIBE_NAMESPACE from client {d}: {t}\n", .{ ci, e });
            if (e == error.ProtocolViolation) {
                self.closeSessionViolation(ci, "invalid subscribe_namespace parameter");
            } else {
                self.sendRequestError(ci, stream_id, moq_codes.ERR_MALFORMED_TRACK, "malformed subscribe_namespace");
            }
            return;
        };

        var prefix_key: [256]u8 = undefined;
        const prefix_len = moq_wire.flattenNamespace(sn.track_namespace_prefix, &prefix_key);
        std.debug.print("[relay] SUBSCRIBE_NAMESPACE client={d} prefix=\"{s}\"\n", .{ ci, prefix_key[0..prefix_len] });

        self.sendRequestOk(ci, stream_id);

        // Push NAMESPACE for each currently-known track whose namespace
        // starts with this prefix.
        var sent: usize = 0;
        for (self.tracks[0..self.track_count]) |*t| {
            if (!t.active) continue;
            const tns = t.namespace_buf[0..t.namespace_len];
            if (tns.len < prefix_len) continue;
            if (!std.mem.startsWith(u8, tns, prefix_key[0..prefix_len])) continue;
            self.sendNamespaceOnStream(stream_id, ci, tns[prefix_len..]) catch continue;
            sent += 1;
        }
        std.debug.print("[relay] sent {d} NAMESPACE entries for prefix\n", .{sent});
    }

    /// §10.16: NAMESPACE carries only what follows the prefix the subscription
    /// asked for, so `suffix_flat` is already cut to it.
    fn sendNamespaceOnStream(self: *RelayHandler, stream_id: u64, ci: usize, suffix_flat: []const u8) !void {
        var parts_buf: [moq_wire.MAX_TUPLE_PARTS][]const u8 = undefined;
        var buf: [512]u8 = undefined;
        var ns_fbs = io_compat.fixedBufferStream(&buf);
        try moq_msg.writeNamespace(&ns_fbs, .{
            .track_namespace_suffix = moq_wire.splitNamespace(suffix_flat, &parts_buf),
        });
        self.sendOnStream(ci, stream_id, buf[0..ns_fbs.seek]);
    }

    fn handlePublishNamespace(self: *RelayHandler, ci: usize, stream_id: u64, payload: []const u8) void {
        var ns_buf: moq_msg.NamespaceBuf = undefined;
        const pn = moq_msg.decodePublishNamespace(payload, &ns_buf, self.draftOf(ci)) catch |e| {
            std.debug.print("[relay] malformed PUBLISH_NAMESPACE from client {d}: {t}\n", .{ ci, e });
            self.sendRequestError(ci, stream_id, moq_codes.ERR_MALFORMED_TRACK, "malformed namespace");
            return;
        };

        var key: [256]u8 = undefined;
        const key_len = moq_wire.flattenNamespace(pn.track_namespace, &key);
        std.debug.print("[relay] PUBLISH_NAMESPACE client={d} ns=\"{s}\"\n", .{ ci, key[0..key_len] });

        if (self.registerNamespace(ci, stream_id, key[0..key_len])) {
            self.sendRequestOk(ci, stream_id);
            // Anything that was waiting on this namespace can be answered now.
            self.resolvePending(key[0..key_len]);
        } else {
            self.sendRequestError(ci, stream_id, moq_codes.ERR_EXCESSIVE_LOAD, "namespace table full");
        }
    }

    fn registerNamespace(self: *RelayHandler, ci: usize, stream_id: u64, key: []const u8) bool {
        if (key.len > 256) return false;
        for (&self.namespaces) |*n| {
            if (n.active and std.mem.eql(u8, n.key(), key) and n.client_idx == ci) return true;
        }
        for (&self.namespaces) |*n| {
            if (n.active) continue;
            @memcpy(n.buf[0..key.len], key);
            n.len = key.len;
            n.client_idx = ci;
            n.stream_id = stream_id;
            n.active = true;
            return true;
        }
        return false;
    }

    /// True when some client has announced a namespace that `ns` falls under.
    fn namespaceAnnounced(self: *RelayHandler, ns: []const u8) bool {
        for (&self.namespaces) |*n| {
            if (!n.active) continue;
            if (std.mem.startsWith(u8, ns, n.key())) return true;
        }
        return false;
    }

    fn sendOnStream(self: *RelayHandler, ci: usize, stream_id: u64, bytes: []const u8) void {
        const conn = self.clients[ci].conn orelse return;
        const stream = conn.streams.getStream(stream_id) orelse return;
        stream.send.writeData(bytes) catch {};
    }

    fn sendRequestOk(self: *RelayHandler, ci: usize, stream_id: u64) void {
        var buf: [64]u8 = undefined;
        var fbs = io_compat.fixedBufferStream(&buf);
        moq_msg.writeRequestOk(&fbs, .{}) catch return;
        self.sendOnStream(ci, stream_id, buf[0..fbs.seek]);
    }

    fn sendRequestError(self: *RelayHandler, ci: usize, stream_id: u64, code: u64, reason: []const u8) void {
        var buf: [256]u8 = undefined;
        var fbs = io_compat.fixedBufferStream(&buf);
        moq_msg.writeRequestError(&fbs, .{ .error_code = code, .reason = reason }) catch return;
        self.sendOnStream(ci, stream_id, buf[0..fbs.seek]);
        std.debug.print("[relay] REQUEST_ERROR to client {d}: code={d} {s}\n", .{ ci, code, reason });
    }

    /// Several fields carry values the draft says MUST close the session with
    /// PROTOCOL_VIOLATION rather than be answered with REQUEST_ERROR — an
    /// undefined Subscription Filter type (§5.1.2), an unknown Message
    /// Parameter (§10.2), a GROUP_ORDER or FORWARD outside its range.
    fn closeSessionViolation(self: *RelayHandler, ci: usize, reason: []const u8) void {
        std.debug.print("[relay] PROTOCOL_VIOLATION to client {d}: {s}\n", .{ ci, reason });
        const conn = self.clients[ci].conn orelse return;
        conn.close(moq_codes.SESSION_PROTOCOL_VIOLATION, reason);
    }

    fn handleSubscribe(self: *RelayHandler, ci: usize, stream_id: u64, payload: []const u8) void {
        var ns_buf: moq_msg.NamespaceBuf = undefined;
        const sub = moq_msg.decodeSubscribe(payload, &ns_buf, self.draftOf(ci)) catch |e| {
            std.debug.print("[relay] undecodable SUBSCRIBE from client {d}: {t} payload({d}B)={x}\n", .{ ci, e, payload.len, payload });
            if (e == error.ProtocolViolation) {
                self.closeSessionViolation(ci, "invalid subscribe parameter");
            } else {
                self.sendRequestError(ci, stream_id, moq_codes.ERR_MALFORMED_TRACK, "malformed subscribe");
            }
            return;
        };

        var ns_key: [256]u8 = undefined;
        const ns_len = moq_wire.flattenNamespace(sub.track_namespace, &ns_key);

        std.debug.print("[relay] SUBSCRIBE from client {d}: ns=\"{s}\" track=\"{s}\"\n", .{
            ci, ns_key[0..ns_len], sub.track_name,
        });

        // A track we already carry, or a namespace someone has announced,
        // can be served. Anything else does not exist here — §9.3.4 says a
        // subscriber that sent no RENDEZVOUS_TIMEOUT (default 0) wants that
        // answer immediately rather than an open subscription.
        if (self.findTrack(ns_key[0..ns_len], sub.track_name) == null and
            !self.namespaceAnnounced(ns_key[0..ns_len]))
        {
            const wait_ms = sub.rendezvous_timeout_ms orelse 0;
            if (wait_ms == 0) {
                self.sendRequestError(ci, stream_id, moq_codes.ERR_DOES_NOT_EXIST, "no such namespace");
                return;
            }
            if (!self.holdPending(ci, stream_id, ns_key[0..ns_len], sub.track_name, wait_ms)) {
                self.sendRequestError(ci, stream_id, moq_codes.ERR_EXCESSIVE_LOAD, "too many pending subscriptions");
            }
            return;
        }

        self.acceptSubscribe(ci, stream_id, ns_key[0..ns_len], sub.track_name);
    }

    /// Holds a subscription open for `wait_ms` waiting for a publisher.
    fn holdPending(self: *RelayHandler, ci: usize, stream_id: u64, ns: []const u8, name: []const u8, wait_ms: u64) bool {
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
            p.active = true;
            std.debug.print("[relay] holding SUBSCRIBE from client {d} for {d}ms\n", .{ ci, wait_ms });
            return true;
        }
        return false;
    }

    /// Answers any held subscription that `ns_key` now satisfies.
    fn resolvePending(self: *RelayHandler, ns_key: []const u8) void {
        for (&self.pending) |*p| {
            if (!p.active) continue;
            if (!std.mem.startsWith(u8, p.ns_buf[0..p.ns_len], ns_key)) continue;
            p.active = false;
            self.acceptSubscribe(p.client_idx, p.stream_id, p.ns_buf[0..p.ns_len], p.name_buf[0..p.name_len]);
        }
    }

    /// Fails any held subscription whose rendezvous timeout has run out.
    fn expirePending(self: *RelayHandler) void {
        const now = sys.nanoTimestamp();
        for (&self.pending) |*p| {
            if (!p.active or now < p.deadline_ns) continue;
            p.active = false;
            self.sendRequestError(p.client_idx, p.stream_id, moq_codes.ERR_TIMEOUT, "rendezvous timeout");
        }
    }

    fn acceptSubscribe(self: *RelayHandler, ci: usize, stream_id: u64, ns_key: []const u8, name: []const u8) void {
        const ns_len = ns_key.len;

        // Find or create a track entry.
        const ti = self.findTrack(ns_key, name) orelse blk: {
            if (self.track_count >= MAX_TRACKS) return;
            const idx = self.track_count;
            self.track_count += 1;
            var t = &self.tracks[idx];
            t.active = true;
            @memcpy(t.namespace_buf[0..ns_len], ns_key);
            t.namespace_len = ns_len;
            @memcpy(t.name_buf[0..name.len], name);
            t.name_len = name.len;
            break :blk idx;
        };

        // Add this subscriber.
        var t = &self.tracks[ti];
        if (t.sub_count < MAX_SUBS_PER_TRACK) {
            const alias = self.clients[ci].next_alias;
            self.clients[ci].next_alias += 1;
            // pending_initial: send its first tick on the next poll.
            t.subs[t.sub_count] = .{
                .client_idx = ci,
                .alias = alias,
                .stream_id = stream_id,
                .pending_initial = true,
            };
            t.sub_count += 1;

            // Send SUBSCRIBE_OK back on the bidi stream.
            const conn = self.clients[ci].conn orelse return;
            const stream = conn.streams.getStream(stream_id) orelse return;
            var buf: [256]u8 = undefined;
            var fbs = io_compat.fixedBufferStream(&buf);
            moq_msg.writeSubscribeOk(&fbs, .{ .track_alias = alias }) catch return;
            stream.send.writeData(buf[0..fbs.seek]) catch return;

            std.debug.print("[relay] SUBSCRIBE_OK to client {d} alias={d} (track {d}, {d} subs)\n", .{
                ci, alias, ti, t.sub_count,
            });

            // NOTE: we deliberately do NOT publish an object immediately.
            // The subscriber must first read SUBSCRIBE_OK on the bidi stream
            // to register the track_alias mapping. Marker is set so the
            // next onPollComplete fires one object to this subscriber;
            // that gives SUBSCRIBE_OK time to flush to the network before
            // the uni-stream subgroup data arrives on the wire.
        }
    }

    /// §10.11: the upstream publication has ended. Each downstream
    /// subscription is a separate one, so each gets its own PUBLISH_DONE with
    /// the number of data streams *we* opened for it — not the count upstream
    /// sent us. Without this a subscriber waits for objects that will never
    /// come; it is the relay, not the original publisher, that has to say so.
    fn handlePublishDone(self: *RelayHandler, ci: usize, stream_id: u64, payload: []const u8) void {
        const done = moq_msg.decodePublishDone(payload) catch |e| {
            std.debug.print("[relay] undecodable PUBLISH_DONE from client {d}: {t}\n", .{ ci, e });
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
    fn endPublication(self: *RelayHandler, t: *Track, status: u64, reason: []const u8) void {
        for (t.subs[0..t.sub_count]) |sub| {
            if (!self.clients[sub.client_idx].active) continue;
            var buf: [256]u8 = undefined;
            var fbs = io_compat.fixedBufferStream(&buf);
            moq_msg.writePublishDone(&fbs, .{
                .status_code = status,
                .stream_count = sub.streams,
                .reason = reason,
            }) catch continue;
            self.sendOnStream(sub.client_idx, sub.stream_id, buf[0..fbs.seek]);
            std.debug.print("[relay] PUBLISH_DONE to client {d} status={d} streams={d}\n", .{
                sub.client_idx, status, sub.streams,
            });
        }
        t.sub_count = 0;
        t.dropPublisherState();
    }

    fn handlePublish(self: *RelayHandler, ci: usize, stream_id: u64, payload: []const u8) void {
        var ns_buf: moq_msg.NamespaceBuf = undefined;
        const pub_msg = moq_msg.decodePublish(payload, &ns_buf, self.draftOf(ci)) catch return;

        var ns_key: [256]u8 = undefined;
        const ns_len = moq_wire.flattenNamespace(pub_msg.track_namespace, &ns_key);

        std.debug.print("[relay] PUBLISH from client {d}: ns=\"{s}\" track=\"{s}\" alias={d}\n", .{
            ci, ns_key[0..ns_len], pub_msg.track_name, pub_msg.track_alias,
        });

        // Register the track.
        const ti = self.findTrack(ns_key[0..ns_len], pub_msg.track_name) orelse blk: {
            if (self.track_count >= MAX_TRACKS) return;
            const idx = self.track_count;
            self.track_count += 1;
            break :blk idx;
        };
        var t = &self.tracks[ti];
        t.active = true;
        @memcpy(t.namespace_buf[0..ns_len], ns_key[0..ns_len]);
        t.namespace_len = ns_len;
        @memcpy(t.name_buf[0..pub_msg.track_name.len], pub_msg.track_name);
        t.name_len = pub_msg.track_name.len;
        t.publisher_idx = ci;
        t.pub_alias = pub_msg.track_alias;
        t.pub_stream_id = stream_id;
        // A PUBLISH means this namespace exists here, so a later SUBSCRIBE
        // under it is legitimate even if the publisher never announced.
        _ = self.registerNamespace(ci, stream_id, ns_key[0..ns_len]);

        // Send PUBLISH_OK back.
        const conn = self.clients[ci].conn orelse return;
        const stream = conn.streams.getStream(stream_id) orelse return;
        var buf: [256]u8 = undefined;
        var fbs = io_compat.fixedBufferStream(&buf);
        moq_msg.writePublishOk(&fbs, .{}, self.draftOf(ci)) catch return;
        stream.send.writeData(buf[0..fbs.seek]) catch return;

        std.debug.print("[relay] PUBLISH_OK to client {d} (track {d})\n", .{ ci, ti });
    }

    fn handleDataStream(self: *RelayHandler, ci: usize, _: u64, data: []const u8) void {
        // Parse subgroup header to get track_alias → find track → fan out to subscribers.
        var fbs = io_compat.fixedBufferStream(data);
        const parsed = moq_obj.readSubgroupHeader(&fbs, self.draftOf(ci)) catch return;
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

        std.debug.print("[relay] Data: track {d} group={d} sub={?d} → {d} subscribers\n", .{
            ti, h.group, h.subgroup, t.sub_count,
        });

        // Fan out: open a uni stream to each subscriber and write the data.
        for (t.subs[0..t.sub_count]) |*sub| {
            const sub_ci = sub.client_idx;
            const sub_conn = self.clients[sub_ci].conn orelse continue;

            const out = sub_conn.openUniStream() catch continue;
            sub.streams += 1;

            // Rewrite the subgroup header with the subscriber's alias.
            var out_buf: [512]u8 = undefined;
            var out_fbs = io_compat.fixedBufferStream(&out_buf);
            const w = &out_fbs;

            moq_obj.writeSubgroupHeader(w, .{
                .track_alias = sub.alias,
                .group = h.group,
                .subgroup = h.subgroup,
                .publisher_priority = h.publisher_priority,
                .end_of_group = h.end_of_group,
                .per_object_properties = h.per_object_properties,
                .first_object = h.first_object,
            }, self.draftOf(sub_ci)) catch continue;

            // Copy the object data (everything after the subgroup header).
            w.writeAll(data[fbs.seek..]) catch continue;

            out.writeData(out_buf[0..out_fbs.seek]) catch continue;
            out.close();
        }
    }

    /// The event loop frees a connection right after this fires, so this is
    /// the last moment the pointer is good — anything that needs it has to
    /// happen here rather than on a later poll.
    pub fn onSessionClosed(self: *RelayHandler, session: *event_loop.Session, _: u64, _: u32, _: []const u8) void {
        const conn = session.entry.conn;
        const ci = self.clientIdx(conn) orelse return;
        self.releaseClient(ci);
    }

    fn releaseClient(self: *RelayHandler, ci: usize) void {
        const c = &self.clients[ci];
        if (!c.active) return;
        std.debug.print("[relay] Client {d} gone — releasing its tracks\n", .{ci});

        for (self.tracks[0..self.track_count]) |*t| {
            if (!t.active) continue;

            // Tracks this client published: tell the subscribers, then free
            // the publisher slot so a new one can take over.
            if (t.publisher_idx == ci) {
                self.endPublication(t, moq_codes.DONE_TRACK_ENDED, "publisher disconnected");
            }

            // Drop this client's subscriptions, closing the gap in place.
            var si: usize = 0;
            while (si < t.sub_count) {
                if (t.subs[si].client_idx != ci) {
                    si += 1;
                    continue;
                }
                t.removeSub(si);
            }
        }

        for (&self.namespaces) |*n| {
            if (n.active and n.client_idx == ci) n.active = false;
        }
        for (&self.pending) |*pn| {
            if (pn.active and pn.client_idx == ci) pn.active = false;
        }

        c.active = false;
        c.conn = null;
    }

    // Send one synthetic clock object to one subscriber.
    fn sendOneObject(self: *RelayHandler, sub: *Sub, group_id: u64) void {
        const sub_ci = sub.client_idx;
        const sub_conn = self.clients[sub_ci].conn orelse return;

        const out = sub_conn.openUniStream() catch return;
        sub.streams += 1;

        var payload_buf: [128]u8 = undefined;
        const payload = std.fmt.bufPrint(&payload_buf, "tick {d}", .{group_id}) catch return;

        var buf: [256]u8 = undefined;
        var fbs = io_compat.fixedBufferStream(&buf);
        const w = &fbs;
        moq_obj.writeSubgroupHeader(w, .{
            .track_alias = sub.alias,
            .group = group_id,
            .subgroup = 0,
            .publisher_priority = 128,
            .end_of_group = true,
            .per_object_properties = false,
            .first_object = true,
        }, self.draftOf(sub_ci)) catch return;
        moq_wire.writeVarInt(w, 0) catch return;
        moq_wire.writeVarInt(w, payload.len) catch return;
        w.writeAll(payload) catch return;

        out.writeData(buf[0..fbs.seek]) catch return;
        out.close();
    }

    /// §10.3.1 datagram objects. A relay forwards them to every subscriber
    /// of the track, rewriting the alias as it does for subgroup streams —
    /// unreliably, which is the point of sending one.
    pub fn onDatagram(self: *RelayHandler, session: *event_loop.Session, _: u64, data: []const u8) void {
        const conn = session.entry.conn;
        const ci = self.clientIdx(conn) orelse return;

        const obj = moq_obj.readDatagramObject(data) catch return;
        const ti = self.trackByPublisherAlias(ci, obj.track_alias) orelse return;
        const t = &self.tracks[ti];

        for (t.subs[0..t.sub_count]) |sub| {
            const sub_ci = sub.client_idx;
            if (sub_ci == ci) continue;
            if (!self.clients[sub_ci].active) continue;
            const sub_conn = self.clients[sub_ci].conn orelse continue;

            var out = obj;
            out.track_alias = sub.alias;
            var buf: [1500]u8 = undefined;
            var fbs = io_compat.fixedBufferStream(&buf);
            moq_obj.writeDatagramObject(&fbs, out) catch continue;
            sub_conn.sendDatagram(buf[0..fbs.seek]) catch continue;
        }
    }

    fn trackByPublisherAlias(self: *RelayHandler, ci: usize, alias: u64) ?usize {
        for (self.tracks[0..self.track_count], 0..) |*t, i| {
            if (t.active and t.publisher_idx == ci and t.pub_alias == alias) return i;
        }
        return null;
    }

    pub fn onPollComplete(self: *RelayHandler, _: *event_loop.Session) void {
        self.expirePending();

        // First: flush any pending-initial subscribers (fire-once-fast so
        // SUBSCRIBE_OK has time to land on the wire before the first object
        // arrives on its uni stream).
        for (self.tracks[0..self.track_count]) |*t| {
            if (!t.active) continue;
            for (t.subs[0..t.sub_count]) |*sub| {
                if (!sub.pending_initial) continue;
                sub.pending_initial = false;
                self.sendOneObject(sub, self.group_id);
            }
        }

        // Check if any track has subscribers.
        var has_subs = false;
        for (self.tracks[0..self.track_count]) |*t| {
            if (t.active and t.sub_count > 0) { has_subs = true; break; }
        }
        if (!has_subs) return;

        const now: i128 = sys.nanoTimestamp();
        if (self.last_tick_ns == 0) self.last_tick_ns = now;
        if (now - self.last_tick_ns < 1_000_000_000) return;
        self.last_tick_ns = now;

        for (self.tracks[0..self.track_count]) |*t| {
            if (!t.active or t.sub_count == 0) continue;
            for (t.subs[0..t.sub_count]) |*sub| self.sendOneObject(sub, self.group_id);
        }

        std.debug.print("[relay] Published group {d} to {d} tracks\n", .{ self.group_id, self.track_count });
        self.group_id += 1;
    }
};

pub fn main(init: std.process.Init.Minimal) !void {
    // A server outlives its streams, so it needs an allocator that reuses what
    // they give back — an arena would grow for as long as the process runs.
    const alloc = std.heap.smp_allocator;

    var port: u16 = 4443;
    var cert_path: []const u8 = "interop/certs/server.crt";
    var key_path: []const u8 = "interop/certs/server.key";

    var args = std.process.Args.Iterator.init(init.args);
    _ = args.next();
    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--port")) {
            if (args.next()) |v| port = std.fmt.parseInt(u16, v, 10) catch 4443;
        } else if (std.mem.eql(u8, arg, "--cert")) {
            if (args.next()) |v| cert_path = v;
        } else if (std.mem.eql(u8, arg, "--key")) {
            if (args.next()) |v| key_path = v;
        }
    }

    // Build TLS config with moqt-17 ALPN.
    const server_cert_pem = try sys.readFileAlloc(alloc, cert_path, 8192);
    const server_key_pem = try sys.readFileAlloc(alloc, key_path, 8192);
    const cert_chain = try tls13.parsePemCertChain(alloc, server_cert_pem);
    var key_der_buf: [4096]u8 = undefined;
    const key_der = try tls13.parsePemPrivateKey(server_key_pem, &key_der_buf);
    const ec_key = tls13.extractEcPrivateKey(key_der) catch try tls13.extractPkcs8EcPrivateKey(key_der);
    const key_owned = try alloc.dupe(u8, ec_key);

    // Advertise every draft we implement and let the peer choose; the TLS
    // layer records which one matched and each client is served at that
    // draft. Newest first, so a peer that speaks both gets the newer.
    const alpn = try alloc.alloc([]const u8, moq_version.PREFERRED.len);
    _ = moq_version.alpnOffer(moq_version.PREFERRED, alpn);

    var ticket_key: [16]u8 = undefined;
    sys.randomBytes(&ticket_key);

    std.debug.print("\n=== MoQ Relay ===\n", .{});
    std.debug.print("Listening on 0.0.0.0:{d}  ALPN:", .{port});
    for (alpn) |a| std.debug.print(" {s}", .{a});
    std.debug.print("\n\n", .{});

    const handler = try alloc.create(RelayHandler);
    handler.* = RelayHandler{};

    // Pre-register synthetic origin tracks so SUBSCRIBE_NAMESPACE discovery
    // returns something even before any client publishes. This makes the
    // relay usable as a standalone origin for interop tests (e.g. moq-rs
    // `moq-clock --broadcast moq-clock subscribe`).
    const origin_tracks = [_]struct { ns: []const u8, name: []const u8 }{
        .{ .ns = "moq-clock/", .name = "seconds" },
        .{ .ns = "test/", .name = "seconds" },
        // Extra tracks under the "demo" namespace for multi-track testing.
        .{ .ns = "demo/", .name = "video" },
        .{ .ns = "demo/", .name = "audio" },
        .{ .ns = "demo/", .name = "game-state" },
    };
    for (origin_tracks) |t| {
        if (handler.track_count >= MAX_TRACKS) break;
        const idx = handler.track_count;
        handler.track_count += 1;
        var tk = &handler.tracks[idx];
        tk.active = true;
        @memcpy(tk.namespace_buf[0..t.ns.len], t.ns);
        tk.namespace_len = t.ns.len;
        @memcpy(tk.name_buf[0..t.name.len], t.name);
        tk.name_len = t.name.len;
        std.debug.print("[relay] Pre-registered synthetic track: {s}/{s}\n", .{ t.ns, t.name });
    }

    var server = try event_loop.Server(RelayHandler).init(alloc, handler, .{
        .address = "0.0.0.0",
        .port = port,
        .cert_path = cert_path,
        .key_path = key_path,
        .tls_config = .{
            .cert_chain_der = cert_chain,
            .private_key_bytes = key_owned,
            .alpn = alpn,
            .ticket_key = ticket_key,
        },
    });
    defer server.deinit();
    try server.run();
}
