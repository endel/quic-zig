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
const MAX_SUBS_PER_TRACK: usize = 16;

const StreamRole = enum { control, request, data, unknown };

const STREAM_BUF_SIZE: usize = 64 * 1024;
const MAX_STREAM_SLOTS: usize = 32;

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
const Track = struct {
    namespace_buf: [256]u8 = undefined,
    namespace_len: usize = 0,
    name_buf: [128]u8 = undefined,
    name_len: usize = 0,
    publisher_idx: ?usize = null,
    pub_alias: u64 = 0,
    active: bool = false,
    // Subscribers waiting for objects on this track.
    sub_client_idx: [MAX_SUBS_PER_TRACK]usize = [_]usize{0} ** MAX_SUBS_PER_TRACK,
    sub_alias: [MAX_SUBS_PER_TRACK]u64 = [_]u64{0} ** MAX_SUBS_PER_TRACK,
    sub_pending_initial: [MAX_SUBS_PER_TRACK]bool = [_]bool{false} ** MAX_SUBS_PER_TRACK,
    sub_count: usize = 0,

    fn matchesNsName(self: *const Track, ns: []const u8, name: []const u8) bool {
        return std.mem.eql(u8, self.namespace_buf[0..self.namespace_len], ns) and
            std.mem.eql(u8, self.name_buf[0..self.name_len], name);
    }
};

// Per-client connection state.
const Client = struct {
    active: bool = false,
    conn: ?*connection_mod.Connection = null,
    setup_done: bool = false,
    impl_name: [64]u8 = undefined,
    impl_len: usize = 0,
    control_out: ?u64 = null,
    next_alias: u64 = 1,
    stream_roles: [256]StreamRole = [_]StreamRole{.unknown} ** 256,
    // Slot-based buffer for streams currently being identified (role=.unknown)
    // or accumulating request messages that span multiple chunks.
    slot_ids: [MAX_STREAM_SLOTS]u64 = [_]u64{std.math.maxInt(u64)} ** MAX_STREAM_SLOTS,
    slot_bufs: [MAX_STREAM_SLOTS]StreamBuf = [_]StreamBuf{.{}} ** MAX_STREAM_SLOTS,

    fn setRole(self: *Client, sid: u64, role: StreamRole) void {
        if (sid < 256) self.stream_roles[@intCast(sid)] = role;
    }
    fn getRole(self: *Client, sid: u64) StreamRole {
        if (sid < 256) return self.stream_roles[@intCast(sid)];
        return .unknown;
    }
    fn slotFor(self: *Client, sid: u64) ?*StreamBuf {
        for (&self.slot_ids, 0..) |id, i| if (id == sid) return &self.slot_bufs[i];
        for (&self.slot_ids, 0..) |id, i| {
            if (id == std.math.maxInt(u64)) {
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
                self.slot_ids[i] = std.math.maxInt(u64);
                self.slot_bufs[i].reset();
                return;
            }
        }
    }
};

const RelayHandler = struct {
    pub const protocol: event_loop.Protocol = .quic;

    clients: [MAX_CLIENTS]Client = [_]Client{.{}} ** MAX_CLIENTS,
    tracks: [MAX_TRACKS]Track = [_]Track{.{}} ** MAX_TRACKS,
    track_count: usize = 0,
    group_id: u64 = 0,
    last_tick_ns: i128 = 0,

    fn findOrCreateClient(self: *RelayHandler, conn: *connection_mod.Connection) ?usize {
        // Check if this connection is already tracked.
        for (&self.clients, 0..) |*c, i| {
            if (c.active and c.conn == conn) return i;
        }
        // Allocate a new slot.
        for (&self.clients, 0..) |*c, i| {
            if (!c.active) {
                c.* = .{ .active = true, .conn = conn };
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

    // Serialize track namespace tuple to a flat key for matching.
    fn serializeNs(ns: []const []const u8, buf: []u8) usize {
        var off: usize = 0;
        for (ns) |part| {
            if (off + part.len + 1 > buf.len) break;
            @memcpy(buf[off .. off + part.len], part);
            off += part.len;
            buf[off] = '/';
            off += 1;
        }
        return off;
    }

    fn findTrack(self: *RelayHandler, ns_key: []const u8, name: []const u8) ?usize {
        for (self.tracks[0..self.track_count], 0..) |*t, i| {
            if (t.active and t.matchesNsName(ns_key, name)) return i;
        }
        return null;
    }

    pub fn onStreamData(self: *RelayHandler, session: *event_loop.Session, stream_id: u64, data: []const u8, _: bool) void {
        if (data.len == 0) return;
        const conn = session.entry.conn;
        const ci = self.findOrCreateClient(conn) orelse return;

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
            self.clients[ci].setRole(stream_id, .data);
            return;
        };
        buf.append(data);

        // Need at least 3 bytes to parse envelope (varint type + u16 length).
        if (buf.len < 3) return;

        const parsed = moq_msg.parseEnvelope(buf.slice()) catch {
            // If we already have enough bytes but envelope parsing still
            // fails, treat it as a data stream (publisher subgroup header).
            if (buf.len >= 3) {
                self.clients[ci].setRole(stream_id, .data);
                self.handleDataStream(ci, stream_id, buf.slice());
                self.clients[ci].freeSlot(stream_id);
            }
            return;
        };

        if (parsed.env.type == moq_codes.MSG_SETUP) {
            self.clients[ci].setRole(stream_id, .control);
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
            self.clients[ci].setRole(stream_id, .request);
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
            moq_codes.MSG_SUBSCRIBE_NAMESPACE => self.handleSubscribeNamespace(ci, stream_id, parsed.env.payload),
            moq_codes.MSG_PUBLISH_NAMESPACE => self.handlePublishNamespace(ci, stream_id, parsed.env.payload),
            else => std.debug.print("[relay] Request type=0x{x} from client {d}\n", .{ parsed.env.type, ci }),
        }
    }

    fn handleSubscribeNamespace(self: *RelayHandler, ci: usize, stream_id: u64, payload: []const u8) void {
        // Parse prefix tuple from payload.
        var fbs = io_compat.fixedBufferStream(payload);
        const reader = &fbs;
        // request_id + delta (draft-17 request messages start with these).
        _ = moq_wire.readVarInt(reader) catch return; // request_id
        _ = moq_wire.readVarInt(reader) catch return; // required_request_id_delta
        // Namespace prefix tuple.
        const count = moq_wire.readVarInt(reader) catch return;
        if (count > 32) return;
        var prefix_parts: [32][]const u8 = undefined;
        for (0..@as(usize, @intCast(count))) |i| {
            prefix_parts[i] = moq_wire.readVarBytesZc(&fbs) catch return;
        }

        var prefix_key: [256]u8 = undefined;
        const prefix_len = serializeNs(prefix_parts[0..@as(usize, @intCast(count))], &prefix_key);
        std.debug.print("[relay] SUBSCRIBE_NAMESPACE client={d} prefix=\"{s}\"\n", .{ ci, prefix_key[0..prefix_len] });

        const conn = self.clients[ci].conn orelse return;
        const stream = conn.streams.getStream(stream_id) orelse return;

        // Reply REQUEST_OK on the same bidi stream.
        var buf: [64]u8 = undefined;
        var ok_fbs = io_compat.fixedBufferStream(&buf);
        moq_msg.writeRequestOk(&ok_fbs, .{}) catch return;
        stream.send.writeData(buf[0..ok_fbs.seek]) catch return;

        // Push NAMESPACE for each currently-known track whose namespace
        // starts with this prefix.
        var sent: usize = 0;
        for (self.tracks[0..self.track_count]) |*t| {
            if (!t.active) continue;
            const tns = t.namespace_buf[0..t.namespace_len];
            if (tns.len < prefix_len) continue;
            if (!std.mem.startsWith(u8, tns, prefix_key[0..prefix_len])) continue;
            self.sendNamespaceOnStream(stream_id, ci, tns) catch continue;
            sent += 1;
        }
        std.debug.print("[relay] sent {d} NAMESPACE entries for prefix\n", .{sent});
    }

    fn sendNamespaceOnStream(self: *RelayHandler, stream_id: u64, ci: usize, ns_flat: []const u8) !void {
        // ns_flat is "a/b/c/" (slash-separated). Split back into tuple parts.
        var parts_buf: [32][]const u8 = undefined;
        var n_parts: usize = 0;
        var it = std.mem.splitScalar(u8, ns_flat, '/');
        while (it.next()) |p| {
            if (p.len == 0) continue;
            if (n_parts >= 32) break;
            parts_buf[n_parts] = p;
            n_parts += 1;
        }

        const conn = self.clients[ci].conn orelse return;
        const stream = conn.streams.getStream(stream_id) orelse return;

        var buf: [512]u8 = undefined;
        var ns_fbs = io_compat.fixedBufferStream(&buf);
        try moq_msg.writeNamespace(&ns_fbs, .{ .track_namespace = parts_buf[0..n_parts] });
        try stream.send.writeData(buf[0..ns_fbs.seek]);
    }

    fn handlePublishNamespace(self: *RelayHandler, ci: usize, stream_id: u64, payload: []const u8) void {
        _ = payload; // parsing not required — we accept any prefix
        std.debug.print("[relay] PUBLISH_NAMESPACE client={d}\n", .{ci});

        const conn = self.clients[ci].conn orelse return;
        const stream = conn.streams.getStream(stream_id) orelse return;

        var buf: [64]u8 = undefined;
        var ok_fbs = io_compat.fixedBufferStream(&buf);
        moq_msg.writeRequestOk(&ok_fbs, .{}) catch return;
        stream.send.writeData(buf[0..ok_fbs.seek]) catch return;
        std.debug.print("[relay] sent REQUEST_OK for publish_namespace\n", .{});
    }

    fn handleSubscribe(self: *RelayHandler, ci: usize, stream_id: u64, payload: []const u8) void {
        var ns_buf: moq_msg.NamespaceBuf = undefined;
        const sub = moq_msg.decodeSubscribe(payload, &ns_buf) catch return;

        var ns_key: [256]u8 = undefined;
        const ns_len = serializeNs(sub.track_namespace, &ns_key);

        std.debug.print("[relay] SUBSCRIBE from client {d}: ns=\"{s}\" track=\"{s}\"\n", .{
            ci, ns_key[0..ns_len], sub.track_name,
        });

        // Find or create a track entry.
        const ti = self.findTrack(ns_key[0..ns_len], sub.track_name) orelse blk: {
            if (self.track_count >= MAX_TRACKS) return;
            const idx = self.track_count;
            self.track_count += 1;
            var t = &self.tracks[idx];
            t.active = true;
            @memcpy(t.namespace_buf[0..ns_len], ns_key[0..ns_len]);
            t.namespace_len = ns_len;
            @memcpy(t.name_buf[0..sub.track_name.len], sub.track_name);
            t.name_len = sub.track_name.len;
            break :blk idx;
        };

        // Add this subscriber.
        var t = &self.tracks[ti];
        if (t.sub_count < MAX_SUBS_PER_TRACK) {
            const alias = self.clients[ci].next_alias;
            self.clients[ci].next_alias += 1;
            t.sub_client_idx[t.sub_count] = ci;
            t.sub_alias[t.sub_count] = alias;
            t.sub_pending_initial[t.sub_count] = true; // send first tick on next poll
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

    fn publishToSubscriber(self: *RelayHandler, ti: usize, si: usize) void {
        const t = &self.tracks[ti];
        const sub_ci = t.sub_client_idx[si];
        const sub_alias = t.sub_alias[si];
        const sub_conn = self.clients[sub_ci].conn orelse return;

        const out = sub_conn.openUniStream() catch return;

        var payload_buf: [128]u8 = undefined;
        const payload = std.fmt.bufPrint(&payload_buf, "tick {d} (track {d})", .{ self.group_id, ti }) catch return;

        var buf: [256]u8 = undefined;
        var fbs = io_compat.fixedBufferStream(&buf);
        const w = &fbs;
        moq_obj.writeSubgroupHeader(w, .{
            .track_alias = sub_alias,
            .group = self.group_id,
            .subgroup = 0,
            .publisher_priority = 128,
            .end_of_group = true,
            .per_object_properties = false,
        }) catch return;
        moq_wire.writeVarInt(w, 0) catch return;
        moq_wire.writeVarInt(w, payload.len) catch return;
        w.writeAll(payload) catch return;

        out.writeData(buf[0..fbs.seek]) catch return;
        out.close();
        std.debug.print("[relay] Sent object to client {d} (track {d}, group {d})\n", .{ sub_ci, ti, self.group_id });
    }

    fn handlePublish(self: *RelayHandler, ci: usize, stream_id: u64, payload: []const u8) void {
        var ns_buf: moq_msg.NamespaceBuf = undefined;
        const pub_msg = moq_msg.decodePublish(payload, &ns_buf) catch return;

        var ns_key: [256]u8 = undefined;
        const ns_len = serializeNs(pub_msg.track_namespace, &ns_key);

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

        // Send PUBLISH_OK back.
        const conn = self.clients[ci].conn orelse return;
        const stream = conn.streams.getStream(stream_id) orelse return;
        var buf: [256]u8 = undefined;
        var fbs = io_compat.fixedBufferStream(&buf);
        moq_msg.writePublishOk(&fbs, .{}) catch return;
        stream.send.writeData(buf[0..fbs.seek]) catch return;

        std.debug.print("[relay] PUBLISH_OK to client {d} (track {d})\n", .{ ci, ti });
    }

    fn handleDataStream(self: *RelayHandler, ci: usize, _: u64, data: []const u8) void {
        // Parse subgroup header to get track_alias → find track → fan out to subscribers.
        var fbs = io_compat.fixedBufferStream(data);
        const parsed = moq_obj.readSubgroupHeader(&fbs) catch return;
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
        for (0..t.sub_count) |si| {
            const sub_ci = t.sub_client_idx[si];
            const sub_alias = t.sub_alias[si];
            const sub_conn = self.clients[sub_ci].conn orelse continue;

            const out = sub_conn.openUniStream() catch continue;

            // Rewrite the subgroup header with the subscriber's alias.
            var out_buf: [512]u8 = undefined;
            var out_fbs = io_compat.fixedBufferStream(&out_buf);
            const w = &out_fbs;

            moq_obj.writeSubgroupHeader(w, .{
                .track_alias = sub_alias,
                .group = h.group,
                .subgroup = h.subgroup,
                .publisher_priority = h.publisher_priority,
                .end_of_group = h.end_of_group,
                .per_object_properties = h.per_object_properties,
            }) catch continue;

            // Copy the object data (everything after the subgroup header).
            w.writeAll(data[fbs.seek..]) catch continue;

            out.writeData(out_buf[0..out_fbs.seek]) catch continue;
            out.close();
        }
    }

    fn sweepDeadPublishers(self: *RelayHandler) void {
        for (&self.clients, 0..) |*c, ci| {
            if (!c.active) continue;
            const conn = c.conn orelse continue;
            if (!conn.isClosed()) continue;

            // Client's connection is closed. Clean up.
            std.debug.print("[relay] Client {d} connection closed — sweeping tracks\n", .{ci});

            // For each track this client published, notify subscribers with
            // PUBLISH_DONE on their subscribe bidi stream and clear publisher.
            for (self.tracks[0..self.track_count]) |*t| {
                if (!t.active) continue;
                if (t.publisher_idx != ci) continue;

                std.debug.print("[relay]   track ns=\"{s}\" name=\"{s}\" publisher gone, {d} subs\n", .{
                    t.namespace_buf[0..t.namespace_len], t.name_buf[0..t.name_len], t.sub_count,
                });

                var buf: [128]u8 = undefined;
                var fbs = io_compat.fixedBufferStream(&buf);
                moq_msg.writePublishDone(&fbs, .{
                    .status_code = 1, // producer disconnected
                    .reason = "publisher disconnected",
                }) catch continue;
                const done_bytes = buf[0..fbs.seek];

                for (0..t.sub_count) |si| {
                    const sub_ci = t.sub_client_idx[si];
                    if (sub_ci == ci) continue; // skip the gone client itself
                    const sub = &self.clients[sub_ci];
                    if (!sub.active) continue;
                    const sub_conn = sub.conn orelse continue;
                    if (sub_conn.isClosed()) continue;
                    // Find the subscribe bidi stream for this subscriber (we
                    // don't track it explicitly; send on the first request
                    // stream we see. Simplification for now.)
                    _ = done_bytes;
                    // TODO: needs per-sub subscribe_bidi tracking to send on
                    // correct stream. Leaving marker log for now.
                    std.debug.print("[relay]   (PUBLISH_DONE scheduled for client {d})\n", .{sub_ci});
                }

                // Clear publisher slot so the track is free for a new one.
                t.publisher_idx = null;
                t.pub_alias = 0;
            }

            // Deactivate the client.
            c.active = false;
            c.conn = null;
        }
    }

    // Send one synthetic clock object to a specific (track, subscriber).
    fn sendOneObject(self: *RelayHandler, t: *Track, si: usize, group_id: u64) void {
        const sub_ci = t.sub_client_idx[si];
        const sub_alias = t.sub_alias[si];
        const sub_conn = self.clients[sub_ci].conn orelse return;

        const out = sub_conn.openUniStream() catch return;

        var payload_buf: [128]u8 = undefined;
        const payload = std.fmt.bufPrint(&payload_buf, "tick {d}", .{group_id}) catch return;

        var buf: [256]u8 = undefined;
        var fbs = io_compat.fixedBufferStream(&buf);
        const w = &fbs;
        moq_obj.writeSubgroupHeader(w, .{
            .track_alias = sub_alias,
            .group = group_id,
            .subgroup = 0,
            .publisher_priority = 128,
            .end_of_group = true,
            .per_object_properties = false,
        }) catch return;
        moq_wire.writeVarInt(w, 0) catch return;
        moq_wire.writeVarInt(w, payload.len) catch return;
        w.writeAll(payload) catch return;

        out.writeData(buf[0..fbs.seek]) catch return;
        out.close();
    }

    pub fn onPollComplete(self: *RelayHandler, _: *event_loop.Session) void {
        self.sweepDeadPublishers();

        // First: flush any pending-initial subscribers (fire-once-fast so
        // SUBSCRIBE_OK has time to land on the wire before the first object
        // arrives on its uni stream).
        for (self.tracks[0..self.track_count]) |*t| {
            if (!t.active) continue;
            for (0..t.sub_count) |si| {
                if (!t.sub_pending_initial[si]) continue;
                t.sub_pending_initial[si] = false;
                self.sendOneObject(t, si, self.group_id);
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
            for (0..t.sub_count) |si| self.sendOneObject(t, si, self.group_id);
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

    const alpn = try alloc.alloc([]const u8, 1);
    alpn[0] = moq_version.ALPN;

    var ticket_key: [16]u8 = undefined;
    sys.randomBytes(&ticket_key);

    std.debug.print("\n=== MoQ Relay (draft-17) ===\n", .{});
    std.debug.print("Listening on 0.0.0.0:{d}  ALPN: {s}\n\n", .{ port, moq_version.ALPN });

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
