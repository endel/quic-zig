// MoQ Transport draft-17 server over raw QUIC.
//
// Accepts MoQ client connections, exchanges SETUP, handles SUBSCRIBE,
// publishes a synthetic clock track. For interop testing against moq-rs.
//
// Usage:
//   zig-out/bin/moq-server --port 4443

const std = @import("std");
const quic = @import("quic");
const io_compat = @import("quic").io_compat;
const sys = quic.sys;
const event_loop = quic.event_loop;
const tls13 = quic.tls13;

const moq_wire = quic.moq.wire;
const moq_msg = quic.moq.message;
const moq_codes = quic.moq.message_codes;
const moq_obj = quic.moq.object;
const moq_version = quic.moq.version;

pub const std_options: std.Options = .{ .log_level = .debug };

const StreamRole = enum { control, request, data, unknown };

const MAX_SUBSCRIBERS: usize = 16;
const Subscriber = struct {
    active: bool = false,
    track_alias: u64 = 0,
};

const MoqServerHandler = struct {
    pub const protocol: event_loop.Protocol = .quic;

    control_out: ?u64 = null,
    peer_control: ?u64 = null,
    setup_sent: bool = false,
    setup_received: bool = false,
    subscribers: [MAX_SUBSCRIBERS]Subscriber = [_]Subscriber{.{}} ** MAX_SUBSCRIBERS,
    subscriber_count: usize = 0,
    group_id: u64 = 0,
    last_tick_ns: i128 = 0,

    stream_roles: [256]StreamRole = [_]StreamRole{.unknown} ** 256,

    fn setRole(self: *MoqServerHandler, sid: u64, role: StreamRole) void {
        if (sid < 256) self.stream_roles[@intCast(sid)] = role;
    }
    fn getRole(self: *MoqServerHandler, sid: u64) StreamRole {
        if (sid < 256) return self.stream_roles[@intCast(sid)];
        return .unknown;
    }

    pub fn onStreamData(self: *MoqServerHandler, session: *event_loop.Session, stream_id: u64, data: []const u8, _: bool) void {
        if (data.len == 0) return;

        const role = self.getRole(stream_id);
        switch (role) {
            .unknown => self.handleNewStream(session, stream_id, data),
            .control => self.handleControl(stream_id, data),
            .request => self.handleRequest(session, stream_id, data),
            .data => {},
        }
    }

    fn handleNewStream(self: *MoqServerHandler, session: *event_loop.Session, stream_id: u64, data: []const u8) void {
        const parsed = moq_msg.parseEnvelope(data) catch return;

        if (parsed.env.type == moq_codes.MSG_SETUP) {
            self.peer_control = stream_id;
            self.setRole(stream_id, .control);
            self.setup_received = true;
            const opts = moq_msg.decodeSetupPayload(parsed.env.payload) catch return;
            std.debug.print("[MoQ] Received SETUP", .{});
            if (opts.implementation) |impl| std.debug.print(" impl=\"{s}\"", .{impl});
            std.debug.print("\n", .{});

            if (!self.setup_sent) {
                // Open our control uni stream and send SETUP back.
                const conn = session.entry.conn;
                const send_stream = conn.openUniStream() catch return;
                self.control_out = send_stream.stream_id;

                var buf: [256]u8 = undefined;
                var fbs = io_compat.fixedBufferStream(&buf);
                moq_msg.writeSetup(&fbs, .{
                    .implementation = "quic-zig/moq-server",
                }) catch return;
                send_stream.writeData(buf[0..fbs.seek]) catch return;
                self.setup_sent = true;
                std.debug.print("[MoQ] Sent SETUP on stream {d}\n", .{send_stream.stream_id});
            }
        } else {
            // Bidi request stream.
            self.setRole(stream_id, .request);
            self.handleRequest(session, stream_id, data);
        }
    }

    fn handleControl(self: *MoqServerHandler, stream_id: u64, data: []const u8) void {
        const parsed = moq_msg.parseEnvelope(data) catch return;
        std.debug.print("[MoQ] Control msg type=0x{x} on stream {d}\n", .{ parsed.env.type, stream_id });
        _ = self;
    }

    fn handleRequest(self: *MoqServerHandler, session: *event_loop.Session, stream_id: u64, data: []const u8) void {
        const parsed = moq_msg.parseEnvelope(data) catch return;
        switch (parsed.env.type) {
            moq_codes.MSG_SUBSCRIBE => self.handleSubscribe(session, stream_id, parsed.env.payload),
            else => std.debug.print("[MoQ] Request type=0x{x} on stream {d}\n", .{ parsed.env.type, stream_id }),
        }
    }

    fn handleSubscribe(self: *MoqServerHandler, session: *event_loop.Session, stream_id: u64, payload: []const u8) void {
        const sub = moq_msg.decodeSubscribe(payload) catch return;
        std.debug.print("[MoQ] SUBSCRIBE ns_parts={d} name=\"{s}\"\n", .{ sub.track_namespace.len, sub.track_name });

        const alias: u64 = self.subscriber_count + 1;

        // Send SUBSCRIBE_OK on the same bidi stream.
        const conn = session.entry.conn;
        const stream = conn.streams.getStream(stream_id) orelse return;
        var buf: [256]u8 = undefined;
        var fbs = io_compat.fixedBufferStream(&buf);
        moq_msg.writeSubscribeOk(&fbs, .{
            .track_alias = alias,
        }) catch return;
        stream.send.writeData(buf[0..fbs.seek]) catch return;

        if (self.subscriber_count < MAX_SUBSCRIBERS) {
            self.subscribers[self.subscriber_count] = .{ .active = true, .track_alias = alias };
            self.subscriber_count += 1;
        }
        std.debug.print("[MoQ] Sent SUBSCRIBE_OK alias={d}\n", .{alias});

        // Publish first object immediately.
        self.publishOneTick(conn);
    }

    fn publishOneTick(self: *MoqServerHandler, conn: *@import("quic").connection.Connection) void {
        var payload_buf: [128]u8 = undefined;
        const payload = std.fmt.bufPrint(&payload_buf, "tick {d}", .{self.group_id}) catch return;

        for (self.subscribers[0..self.subscriber_count]) |*sub| {
            if (!sub.active) continue;

            const data_stream = conn.openUniStream() catch |e| {
                std.debug.print("[MoQ] openUniStream failed: {}\n", .{e});
                continue;
            };

            var buf: [256]u8 = undefined;
            var fbs = io_compat.fixedBufferStream(&buf);
            const w = &fbs;

            moq_obj.writeSubgroupHeader(w, .{
                .track_alias = sub.track_alias,
                .group = self.group_id,
                .subgroup = 0,
                .publisher_priority = 128,
                .end_of_group = true,
                .per_object_properties = false,
            }) catch continue;

            moq_wire.writeVarInt(w, 0) catch continue;
            moq_wire.writeVarInt(w, payload.len) catch continue;
            w.writeAll(payload) catch continue;

            data_stream.writeData(buf[0..fbs.seek]) catch |e| {
                std.debug.print("[MoQ] writeData failed: {}\n", .{e});
                continue;
            };
            data_stream.close();
        }

        std.debug.print("[MoQ] Published group {d}\n", .{self.group_id});
        self.group_id += 1;
    }

    pub fn onPollComplete(self: *MoqServerHandler, session: *event_loop.Session) void {
        if (!self.setup_sent or !self.setup_received) return;
        if (self.subscriber_count == 0) return;

        const now: i128 = sys.nanoTimestamp();
        if (self.last_tick_ns == 0) self.last_tick_ns = now;
        if (now - self.last_tick_ns < 1_000_000_000) return;
        self.last_tick_ns = now;

        self.publishOneTick(session.entry.conn);
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

    // Build TLS config with both "moqt-17" and "h3" ALPNs.
    const server_cert_pem = try sys.readFileAlloc(alloc, cert_path, 8192);
    const server_key_pem = try sys.readFileAlloc(alloc, key_path, 8192);
    const cert_chain = try tls13.parsePemCertChain(alloc, server_cert_pem);
    var key_der_buf: [4096]u8 = undefined;
    const key_der = try tls13.parsePemPrivateKey(server_key_pem, &key_der_buf);
    const ec_key = tls13.extractEcPrivateKey(key_der) catch try tls13.extractPkcs8EcPrivateKey(key_der);
    const key_owned = try alloc.dupe(u8, ec_key);

    const alpn = try alloc.alloc([]const u8, 1);
    alpn[0] = moq_version.ALPN; // "moqt-17"

    var ticket_key: [16]u8 = undefined;
    sys.randomBytes(&ticket_key);

    std.debug.print("\n=== MoQ Server (draft-17, raw QUIC) ===\n", .{});
    std.debug.print("Listening on 0.0.0.0:{d}  ALPN: {s}, h3\n\n", .{ port, moq_version.ALPN });

    var handler = MoqServerHandler{};
    var server = try event_loop.Server(MoqServerHandler).init(alloc, &handler, .{
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
