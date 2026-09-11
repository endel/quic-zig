// MoQ Transport draft-17 client over raw QUIC.
//
// Connects to a MoQ relay/server, exchanges SETUP, sends SUBSCRIBE
// for a given track, and prints received objects. For interop testing
// against moq-rs.
//
// Usage:
//   zig-out/bin/moq-client --addr localhost:4443 --ns moq-clock --track seconds

const std = @import("std");
const quic = @import("quic");
const io_compat = @import("quic").io_compat;
const sys = quic.sys;
const event_loop = quic.event_loop;

const moq_wire = quic.moq.wire;
const moq_msg = quic.moq.message;
const moq_codes = quic.moq.message_codes;
const moq_obj = quic.moq.object;
const moq_version = quic.moq.version;

pub const std_options: std.Options = .{ .log_level = .err };

const StreamRole = enum { control, request, data, unknown };

const Mode = enum { subscribe, publish };

const MAX_TRACKS_PER_SESSION: usize = 8;

const TrackSub = struct {
    ns_parts: []const []const u8,
    name: []const u8,
    subscribe_bidi: ?u64 = null,
    alias: ?u64 = null,
    subscribed: bool = false,
    objects_received: u64 = 0,
};

const MoqClientHandler = struct {
    pub const protocol: event_loop.Protocol = .quic;
    /// The publish tick is ours, not QUIC's, so the loop has to be woken
    /// on a cadence rather than only when the peer sends something.
    pub const poll_interval_ms: u64 = 100;

    mode: Mode = .subscribe,
    /// §10.3.1: publish objects as datagrams instead of on subgroup
    /// streams. Unreliable, unordered, and one object per datagram.
    use_datagrams: bool = false,
    // Legacy single-track fields (kept for publish mode + backward compat).
    ns_parts: []const []const u8,
    track_name: []const u8,
    // Multi-subscribe: tracks the client wants to subscribe to in subscribe mode.
    tracks: [MAX_TRACKS_PER_SESSION]TrackSub = undefined,
    track_count: usize = 0,

    control_out: ?u64 = null,
    peer_control: ?u64 = null,
    publish_bidi: ?u64 = null,
    setup_sent: bool = false,
    setup_received: bool = false,
    published: bool = false,
    group_id: u64 = 0,
    last_tick_ns: i128 = 0,

    stream_roles: [256]StreamRole = [_]StreamRole{.unknown} ** 256,

    fn setRole(self: *MoqClientHandler, sid: u64, role: StreamRole) void {
        if (sid < 256) self.stream_roles[@intCast(sid)] = role;
    }
    fn getRole(self: *MoqClientHandler, sid: u64) StreamRole {
        if (sid < 256) return self.stream_roles[@intCast(sid)];
        return .unknown;
    }

    pub fn onConnected(self: *MoqClientHandler, session: *event_loop.ClientSession) void {
        std.debug.print("[MoQ] QUIC connected, sending SETUP...\n", .{});

        // Open control uni stream and send SETUP.
        const ctrl = session.openQuicUniStream() catch |e| {
            std.debug.print("[MoQ] Failed to open uni stream: {}\n", .{e});
            return;
        };
        self.control_out = ctrl;
        self.setRole(ctrl, .control);

        var buf: [256]u8 = undefined;
        var fbs = io_compat.fixedBufferStream(&buf);
        moq_msg.writeSetup(&fbs, .{
            .implementation = "quic-zig/moq",
        }) catch return;
        session.writeStream(ctrl, buf[0..fbs.seek]) catch return;
        self.setup_sent = true;
        std.debug.print("[MoQ] Sent SETUP on stream {d}\n", .{ctrl});
    }

    pub fn onDatagram(self: *MoqClientHandler, _: *event_loop.ClientSession, _: u64, data: []const u8) void {
        const obj = moq_obj.readDatagramObject(data) catch |e| {
            std.debug.print("[MoQ] bad datagram object: {t}\n", .{e});
            return;
        };
        const name = if (self.trackByAlias(obj.track_alias)) |ts| ts.name else "?";
        switch (obj.body) {
            .payload => |pl| std.debug.print("[MoQ] Datagram track=\"{s}\" group={d} payload=\"{s}\"\n", .{
                name, obj.group, pl,
            }),
            .status => |st| std.debug.print("[MoQ] Datagram track=\"{s}\" group={d} status={t}\n", .{
                name, obj.group, st,
            }),
        }
    }

    pub fn onStreamData(self: *MoqClientHandler, session: *event_loop.ClientSession, stream_id: u64, data: []const u8, _: bool) void {
        if (data.len == 0) return;

        const role = self.getRole(stream_id);
        switch (role) {
            .unknown => self.handleNewStream(session, stream_id, data),
            .control => self.handleControl(stream_id, data),
            .request => self.handleRequest(stream_id, data),
            .data => self.handleDataStream(stream_id, data),
        }
    }

    fn handleNewStream(self: *MoqClientHandler, session: *event_loop.ClientSession, stream_id: u64, data: []const u8) void {
        // Try to parse as control message (SETUP from server).
        const parsed = moq_msg.parseEnvelope(data) catch {
            // Could be a data stream (subgroup header).
            self.setRole(stream_id, .data);
            self.handleDataStream(stream_id, data);
            return;
        };

        if (parsed.env.type == moq_codes.MSG_SETUP) {
            self.peer_control = stream_id;
            self.setRole(stream_id, .control);
            self.setup_received = true;
            const opts = moq_msg.decodeSetupPayload(parsed.env.payload) catch return;
            std.debug.print("[MoQ] Received SETUP", .{});
            if (opts.implementation) |impl| std.debug.print(" impl=\"{s}\"", .{impl});
            std.debug.print("\n", .{});

            if (self.setup_sent and self.setup_received) {
                switch (self.mode) {
                    .subscribe => self.sendAllSubscribes(session),
                    .publish => if (!self.published) self.sendPublish(session),
                }
            }
        } else {
            // Some other message on a new stream — probably a bidi request response.
            self.setRole(stream_id, .request);
            self.handleRequest(stream_id, data);
        }
    }

    fn handleControl(self: *MoqClientHandler, stream_id: u64, data: []const u8) void {
        const parsed = moq_msg.parseEnvelope(data) catch return;
        std.debug.print("[MoQ] Control msg type=0x{x} on stream {d}\n", .{ parsed.env.type, stream_id });
        _ = self;
    }

    fn handleRequest(self: *MoqClientHandler, stream_id: u64, data: []const u8) void {
        const parsed = moq_msg.parseEnvelope(data) catch return;
        switch (parsed.env.type) {
            moq_codes.MSG_SUBSCRIBE_OK => {
                const ok = moq_msg.decodeSubscribeOk(parsed.env.payload) catch return;
                if (self.trackByBidi(stream_id)) |ts| {
                    ts.alias = ok.track_alias;
                    std.debug.print("[MoQ] SUBSCRIBE_OK alias={d} track=\"{s}\"\n", .{ ok.track_alias, ts.name });
                } else {
                    std.debug.print("[MoQ] SUBSCRIBE_OK alias={d} (no bidi match)\n", .{ok.track_alias});
                }
            },
            moq_codes.MSG_REQUEST_OK => {
                std.debug.print("[MoQ] REQUEST_OK on stream {d}\n", .{stream_id});
            },
            moq_codes.MSG_REQUEST_ERROR => {
                const err = moq_msg.decodeRequestError(parsed.env.payload) catch return;
                std.debug.print("[MoQ] REQUEST_ERROR code={d} reason=\"{s}\"\n", .{ err.error_code, err.reason });
            },
            else => {
                std.debug.print("[MoQ] Response type=0x{x} on stream {d}\n", .{ parsed.env.type, stream_id });
            },
        }
    }

    fn handleDataStream(self: *MoqClientHandler, stream_id: u64, data: []const u8) void {
        var fbs = io_compat.fixedBufferStream(data);
        const parsed = moq_obj.readSubgroupHeader(&fbs) catch {
            std.debug.print("[MoQ] Data stream {d}: {d} bytes (parse deferred)\n", .{ stream_id, data.len });
            return;
        };
        const h = parsed.header;
        const track_name: []const u8 = if (self.trackByAlias(h.track_alias)) |ts| ts.name else "?";
        std.debug.print("[MoQ] Subgroup: alias={d} track=\"{s}\" group={d} sub={?d}\n", .{
            h.track_alias, track_name, h.group, h.subgroup,
        });

        // Read objects from remainder.
        const rest = data[fbs.seek..];
        var off: usize = 0;
        while (off < rest.len) {
            var obj_fbs = io_compat.fixedBufferStream(rest[off..]);
            const obj_reader = &obj_fbs;
            const obj_id = moq_wire.readVarInt(obj_reader) catch break;
            const payload_len = moq_wire.readVarInt(obj_reader) catch break;
            const plen: usize = @intCast(payload_len);
            const hdr_len = obj_fbs.seek;
            if (off + hdr_len + plen > rest.len) break;
            const payload = rest[off + hdr_len .. off + hdr_len + plen];
            std.debug.print("[MoQ] Object track=\"{s}\" group={d} obj={d} payload=\"{s}\"\n", .{ track_name, h.group, obj_id, payload });
            if (self.trackByAlias(h.track_alias)) |ts| ts.objects_received += 1;
            off += hdr_len + plen;
        }
    }

    fn sendAllSubscribes(self: *MoqClientHandler, session: *event_loop.ClientSession) void {
        for (self.tracks[0..self.track_count]) |*ts| {
            if (ts.subscribed) continue;
            const bidi = session.openStream() catch |e| {
                std.debug.print("[MoQ] Failed to open bidi stream: {}\n", .{e});
                return;
            };
            ts.subscribe_bidi = bidi;
            ts.subscribed = true;
            self.setRole(bidi, .request);

            var buf: [512]u8 = undefined;
            var fbs = io_compat.fixedBufferStream(&buf);
            moq_msg.writeSubscribe(&fbs, .{
                .track_namespace = ts.ns_parts,
                .track_name = ts.name,
                .subscriber_priority = 128,
                .group_order = .ascending,
                .filter = .{ .type = .latest_object },
            }) catch return;
            session.writeStream(bidi, buf[0..fbs.seek]) catch return;
            std.debug.print("[MoQ] Sent SUBSCRIBE on bidi {d} for track \"{s}\"\n", .{ bidi, ts.name });
        }
    }

    // Route received SUBSCRIBE_OK to the correct track entry by bidi stream.
    fn trackByBidi(self: *MoqClientHandler, stream_id: u64) ?*TrackSub {
        for (self.tracks[0..self.track_count]) |*ts| {
            if (ts.subscribe_bidi == stream_id) return ts;
        }
        return null;
    }

    // Route incoming data-stream objects to the track entry by alias.
    fn trackByAlias(self: *MoqClientHandler, alias: u64) ?*TrackSub {
        for (self.tracks[0..self.track_count]) |*ts| {
            if (ts.alias == alias) return ts;
        }
        return null;
    }

    fn sendPublish(self: *MoqClientHandler, session: *event_loop.ClientSession) void {
        const bidi = session.openStream() catch return;
        self.publish_bidi = bidi;
        self.setRole(bidi, .request);
        self.published = true;

        var buf: [512]u8 = undefined;
        var fbs = io_compat.fixedBufferStream(&buf);
        moq_msg.writePublish(&fbs, .{
            .track_namespace = self.ns_parts,
            .track_name = self.track_name,
            .track_alias = 1,
            .forward = true,
        }) catch return;
        session.writeStream(bidi, buf[0..fbs.seek]) catch return;
        std.debug.print("[MoQ] Sent PUBLISH on bidi stream {d}\n", .{bidi});
    }

    pub fn onPollComplete(self: *MoqClientHandler, session: *event_loop.ClientSession) void {
        if (self.mode != .publish or !self.published) return;

        const now: i128 = sys.nanoTimestamp();
        if (self.last_tick_ns == 0) self.last_tick_ns = now;
        if (now - self.last_tick_ns < 1_000_000_000) return;
        self.last_tick_ns = now;

        var payload_buf: [128]u8 = undefined;
        const payload = std.fmt.bufPrint(&payload_buf, "pub tick {d}", .{self.group_id}) catch return;

        if (self.use_datagrams) {
            var dbuf: [256]u8 = undefined;
            var dfbs = io_compat.fixedBufferStream(&dbuf);
            moq_obj.writeDatagramObject(&dfbs, .{
                .track_alias = 1,
                .group = self.group_id,
                .object = null,
                .publisher_priority = 128,
                .end_of_group = true,
                .body = .{ .payload = payload },
            }) catch return;
            session.sendDatagram(0, dbuf[0..dfbs.seek]) catch |e| {
                std.debug.print("[MoQ] datagram send failed: {t}\n", .{e});
                return;
            };
            std.debug.print("[MoQ] Published tick {d} as a datagram\n", .{self.group_id});
            self.group_id += 1;
            return;
        }

        // Publish a tick object on a new uni stream.
        const out_id = session.openQuicUniStream() catch return;

        var buf: [256]u8 = undefined;
        var fbs = io_compat.fixedBufferStream(&buf);
        const w = &fbs;
        moq_obj.writeSubgroupHeader(w, .{
            .track_alias = 1,
            .group = self.group_id,
            .subgroup = 0,
            .publisher_priority = 128,
            .end_of_group = true,
            .per_object_properties = false,
        }) catch return;
        moq_wire.writeVarInt(w, 0) catch return;
        moq_wire.writeVarInt(w, payload.len) catch return;
        w.writeAll(payload) catch return;

        session.writeStream(out_id, buf[0..fbs.seek]) catch return;
        session.closeQuicStream(out_id);
        std.debug.print("[MoQ] Published tick {d}\n", .{self.group_id});
        self.group_id += 1;
    }
};

pub fn main(init: std.process.Init.Minimal) !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    var address: []const u8 = "127.0.0.1";
    var port: u16 = 4443;
    var server_name: []const u8 = "localhost";
    var ns_str: []const u8 = "moq-clock";
    var track_name: []const u8 = "seconds";
    var mode: Mode = .subscribe;
    var use_datagrams = false;

    // For multi-track subscribe: repeated --track flags accumulate here.
    var track_names = std.ArrayList([]const u8){ .items = &.{}, .capacity = 0 };
    defer track_names.deinit(alloc);

    var args = std.process.Args.Iterator.init(init.args);
    _ = args.next();
    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--addr")) {
            if (args.next()) |v| {
                if (std.mem.lastIndexOf(u8, v, ":")) |colon| {
                    address = v[0..colon];
                    port = std.fmt.parseInt(u16, v[colon + 1 ..], 10) catch 4443;
                } else {
                    address = v;
                }
            }
        } else if (std.mem.eql(u8, arg, "--ns")) {
            if (args.next()) |v| ns_str = v;
        } else if (std.mem.eql(u8, arg, "--track")) {
            if (args.next()) |v| {
                track_name = v;
                try track_names.append(alloc, v);
            }
        } else if (std.mem.eql(u8, arg, "--server-name")) {
            if (args.next()) |v| server_name = v;
        } else if (std.mem.eql(u8, arg, "--datagrams")) {
            use_datagrams = true;
        } else if (std.mem.eql(u8, arg, "--mode")) {
            if (args.next()) |v| {
                if (std.mem.eql(u8, v, "publish")) mode = .publish;
            }
        }
    }

    // If no --track was given explicitly, use the default.
    if (track_names.items.len == 0) {
        try track_names.append(alloc, track_name);
    }

    // Parse namespace: "moq-clock" → ["moq-clock"], "a,b" → ["a","b"]
    var ns_list = std.ArrayList([]const u8){ .items = &.{}, .capacity = 0 };
    var ns_it = std.mem.splitScalar(u8, ns_str, ',');
    while (ns_it.next()) |part| {
        if (part.len > 0) try ns_list.append(alloc, part);
    }

    std.debug.print("\n=== MoQ Client (draft-17, raw QUIC) ===\n", .{});
    std.debug.print("Target: {s}:{d}  ALPN: {s}\n", .{ address, port, moq_version.ALPN });
    std.debug.print("Namespace: [", .{});
    for (ns_list.items, 0..) |p, i| {
        if (i > 0) std.debug.print(",", .{});
        std.debug.print("{s}", .{p});
    }
    std.debug.print("]\n", .{});
    std.debug.print("Tracks ({d}): ", .{track_names.items.len});
    for (track_names.items, 0..) |n, i| {
        if (i > 0) std.debug.print(", ", .{});
        std.debug.print("{s}", .{n});
    }
    std.debug.print("\n\n", .{});

    var handler = MoqClientHandler{
        .mode = mode,
        .use_datagrams = use_datagrams,
        .ns_parts = ns_list.items,
        .track_name = track_name,
    };
    for (track_names.items) |n| {
        if (handler.track_count >= MAX_TRACKS_PER_SESSION) break;
        handler.tracks[handler.track_count] = .{
            .ns_parts = ns_list.items,
            .name = n,
        };
        handler.track_count += 1;
    }

    var client = try event_loop.Client(MoqClientHandler).init(alloc, &handler, .{
        .address = address,
        .port = port,
        .server_name = server_name,
        .alpn = moq_version.ALPN,
        .skip_cert_verify = true,
    });
    defer client.deinit();
    try client.run();
}
