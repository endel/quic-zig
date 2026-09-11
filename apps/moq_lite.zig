// moq-lite client — draft-lcurley-moq-lite-05.
//
//   moq-lite publish   --url <URL> --broadcast <path> [--track <name>]
//   moq-lite subscribe --url <URL> --broadcast <path> [--track <name>]
//   moq-lite announce  --url <URL> [--prefix <path>]
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

const Mode = enum { publish, subscribe, announce };

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
                        print("  +{d}ms {s}\n", .{ item.timestamp, item.payload });
                    }
                },
                .group_end => {},
                .probe => |p| print("probe: {d} bps, {d} ms rtt\n", .{ p.probe.bitrate, p.probe.rtt_ms }),
                .goaway => |g| print("GOAWAY: {s}\n", .{g.goaway.uri}),
                else => {},
            }
        }

        fn serveAnnounce(self: *Self, stream_id: u64, req: lite_msg.AnnounceRequest) void {
            // Announce our one broadcast if it falls under the prefix.
            self.sess.sendAnnounceOk(stream_id, .{ .hop_id = 1, .active_count = 1 }) catch return;
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
            if (!std.mem.eql(u8, sub.broadcast, self.broadcast) or
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

    var args = std.process.Args.Iterator.init(init.args);
    _ = args.next();
    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "publish")) {
            mode = .publish;
        } else if (std.mem.eql(u8, arg, "subscribe")) {
            mode = .subscribe;
        } else if (std.mem.eql(u8, arg, "announce")) {
            mode = .announce;
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
            , .{});
            return 0;
        }
    }

    const m = mode orelse {
        print("usage: moq-lite <publish|subscribe|announce> --url URL [...]\n", .{});
        return 2;
    };

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
