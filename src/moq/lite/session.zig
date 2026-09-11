// moq-lite session state machine — draft-lcurley-moq-lite-05.
//
// A stream's first varint names what it is; everything after that is fixed
// by position, so this is a per-stream state machine rather than a message
// dispatcher. Control streams are bidirectional and (Goaway aside) always
// opened by the subscriber; data streams are unidirectional and opened by
// the publisher.
//
// Generic over the transport, like src/moq/session.zig. The transport must
// provide:
//
//     openUni() !u64
//     openBidi() !u64
//     write(stream_id: u64, data: []const u8) !void
//     finish(stream_id: u64) void
//     reset(stream_id: u64, code: u64) void
//
// Group payloads are surfaced as raw bytes rather than parsed frames. A
// relay wants to forward them untouched, and a subscriber can drive
// FrameReader over the same bytes — parsing them here would force every
// group through a buffer large enough for its biggest frame.

const std = @import("std");
const testing = std.testing;

const io = @import("../../io_compat.zig");
const wire = @import("wire.zig");
const msg = @import("message.zig");
const version = @import("version.zig");

pub const MAX_STREAMS: usize = 32;
/// Enough for any control message we exchange — they carry paths and track
/// names, not media. Group payloads never pass through it, so this bounds
/// a session at MAX_STREAMS * CONTROL_BUF_SIZE, which a server multiplies
/// by its client count. Keep it small enough to sit in one allocation.
pub const CONTROL_BUF_SIZE: usize = 2 * 1024;

const NO_STREAM: u64 = std.math.maxInt(u64);

pub const Error = error{
    TooManyStreams,
    NotConnected,
    ProtocolViolation,
} || msg.Error;

/// Application error codes for stream resets. moq-lite leaves these to the
/// application except that a reset is never fatal to the session.
pub const ResetCode = struct {
    pub const CANCEL: u64 = 0;
    pub const NOT_FOUND: u64 = 1;
    pub const UNAUTHORIZED: u64 = 2;
    pub const INTERNAL: u64 = 3;
};

/// What a stream is, and how far through it we are.
const Role = enum {
    /// Nothing read yet — the first varint decides.
    unknown_uni,
    unknown_bidi,

    setup_in,
    /// A group stream whose GROUP header has been read; the rest is frames.
    group_in,
    /// A group stream we are still waiting for the header on.
    group_in_header,

    // Streams we opened, waiting for the peer's side.
    announce_out,
    subscribe_out,
    track_out,
    fetch_out,
    probe_out,
    goaway_out,

    // Streams the peer opened.
    announce_in,
    subscribe_in,
    track_in,
    fetch_in,
    probe_in,
    goaway_in,
};

pub const Event = union(enum) {
    peer_setup: struct { setup: msg.Setup },

    // Publisher side: what a subscriber asked us for.
    announce_request: struct { stream_id: u64, request: msg.AnnounceRequest },
    subscribe_request: struct { stream_id: u64, subscribe: msg.Subscribe },
    subscribe_update: struct { stream_id: u64, update: msg.SubscribeUpdate },
    track_request: struct { stream_id: u64, track: msg.Track },
    fetch_request: struct { stream_id: u64, fetch: msg.Fetch },

    // Subscriber side: what a publisher told us.
    announce_ok: struct { stream_id: u64, ok: msg.AnnounceOk },
    announce_broadcast: struct { stream_id: u64, broadcast: msg.AnnounceBroadcast },
    subscribe_response: struct { stream_id: u64, response: msg.SubscribeResponse },
    track_info: struct { stream_id: u64, info: msg.TrackInfo },

    probe: struct { stream_id: u64, probe: msg.Probe },
    goaway: struct { stream_id: u64, goaway: msg.Goaway },

    /// A group stream opened and named its subscription.
    group_start: struct { stream_id: u64, group: msg.Group },
    /// Raw group bytes: zero or more whole or partial FRAMEs, in order.
    group_data: struct { stream_id: u64, data: []const u8 },
    /// FIN on a group stream. A group that is reset instead is incomplete,
    /// which is normal under congestion.
    group_end: struct { stream_id: u64 },

    stream_finished: struct { stream_id: u64 },
};

const StreamState = struct {
    id: u64 = NO_STREAM,
    role: Role = .unknown_uni,
    buf: [CONTROL_BUF_SIZE]u8 = undefined,
    len: usize = 0,
    /// Set once a subscribe stream has produced its first response, so a
    /// later one can be told apart from the mandatory first.
    started: bool = false,

    fn append(self: *StreamState, bytes: []const u8) void {
        const n = @min(bytes.len, self.buf.len - self.len);
        @memcpy(self.buf[self.len..][0..n], bytes[0..n]);
        self.len += n;
    }

    fn consume(self: *StreamState, n: usize) void {
        std.mem.copyForwards(u8, self.buf[0 .. self.len - n], self.buf[n..self.len]);
        self.len -= n;
    }

    fn slice(self: *const StreamState) []const u8 {
        return self.buf[0..self.len];
    }
};

pub fn Session(comptime Transport: type) type {
    return struct {
        const Self = @This();

        transport: Transport,
        ver: version.Version = version.DEFAULT,
        /// Sent in our SETUP. Absent over WebTransport, where the CONNECT
        /// URI carries the path instead.
        path: ?[]const u8 = null,
        probe_level: ?msg.ProbeLevel = null,

        setup_sent: bool = false,
        setup_received: bool = false,
        peer_setup: msg.Setup = .{},

        streams: [MAX_STREAMS]StreamState = [_]StreamState{.{}} ** MAX_STREAMS,
        hop_buf: [msg.MAX_HOPS]u64 = undefined,
        next_subscribe_id: u64 = 0,

        pub fn init(transport: Transport) Self {
            return .{ .transport = transport };
        }

        // --- stream table --------------------------------------------

        fn slot(self: *Self, id: u64) ?*StreamState {
            for (&self.streams) |*s| if (s.id == id) return s;
            return null;
        }

        fn claim(self: *Self, id: u64, role: Role) ?*StreamState {
            if (self.slot(id)) |s| return s;
            for (&self.streams) |*s| if (s.id == NO_STREAM) {
                s.* = .{ .id = id, .role = role };
                return s;
            };
            return null;
        }

        pub fn release(self: *Self, id: u64) void {
            if (self.slot(id)) |s| s.* = .{};
        }

        pub fn roleOf(self: *Self, id: u64) ?Role {
            if (self.slot(id)) |s| return s.role;
            return null;
        }

        // --- opening streams -----------------------------------------

        /// §6.3.1: both endpoints open a Setup Stream immediately and FIN
        /// it. Neither waits for the other, so this never blocks.
        pub fn sendSetup(self: *Self) !void {
            const sid = try self.transport.openUni();
            var buf: [512]u8 = undefined;
            var fbs = io.fixedBufferStream(&buf);
            try msg.writeStreamType(&fbs, @intFromEnum(msg.DataType.setup));
            try msg.writeSetup(&fbs, .{ .probe = self.probe_level, .path = self.path });
            try self.transport.write(sid, buf[0..fbs.seek]);
            self.transport.finish(sid);
            self.setup_sent = true;
        }

        fn openControl(self: *Self, kind: msg.ControlType, role: Role) !u64 {
            const sid = try self.transport.openBidi();
            _ = self.claim(sid, role) orelse return Error.TooManyStreams;
            var buf: [8]u8 = undefined;
            var fbs = io.fixedBufferStream(&buf);
            try msg.writeStreamType(&fbs, @intFromEnum(kind));
            try self.transport.write(sid, buf[0..fbs.seek]);
            return sid;
        }

        fn writeMessage(self: *Self, sid: u64, comptime W: anytype, value: anytype) !void {
            var buf: [CONTROL_BUF_SIZE]u8 = undefined;
            var fbs = io.fixedBufferStream(&buf);
            try W(&fbs, value);
            try self.transport.write(sid, buf[0..fbs.seek]);
        }

        /// Asks the peer to announce broadcasts under `prefix`.
        pub fn openAnnounce(self: *Self, request: msg.AnnounceRequest) !u64 {
            const sid = try self.openControl(.announce, .announce_out);
            try self.writeMessage(sid, msg.writeAnnounceRequest, request);
            return sid;
        }

        /// Subscribes to a track. The returned stream is the subscription:
        /// closing it unsubscribes, and there is no separate message for it.
        pub fn openSubscribe(self: *Self, subscribe: msg.Subscribe) !struct { stream_id: u64, id: u64 } {
            var s = subscribe;
            s.id = self.next_subscribe_id;
            self.next_subscribe_id += 1;
            const sid = try self.openControl(.subscribe, .subscribe_out);
            try self.writeMessage(sid, msg.writeSubscribe, s);
            return .{ .stream_id = sid, .id = s.id };
        }

        pub fn sendSubscribeUpdate(self: *Self, stream_id: u64, update: msg.SubscribeUpdate) !void {
            return self.writeMessage(stream_id, msg.writeSubscribeUpdate, update);
        }

        /// Asks for a track's metadata (§5.1.6).
        pub fn openTrack(self: *Self, track: msg.Track) !u64 {
            const sid = try self.openControl(.track, .track_out);
            try self.writeMessage(sid, msg.writeTrack, track);
            return sid;
        }

        pub fn openFetch(self: *Self, fetch: msg.Fetch) !u64 {
            const sid = try self.openControl(.fetch, .fetch_out);
            try self.writeMessage(sid, msg.writeFetch, fetch);
            return sid;
        }

        pub fn openProbe(self: *Self) !u64 {
            return self.openControl(.probe, .probe_out);
        }

        pub fn openGoaway(self: *Self, goaway: msg.Goaway) !u64 {
            const sid = try self.openControl(.goaway, .goaway_out);
            try self.writeMessage(sid, msg.writeGoaway, goaway);
            return sid;
        }

        // --- publisher replies ---------------------------------------

        pub fn sendAnnounceOk(self: *Self, stream_id: u64, ok: msg.AnnounceOk) !void {
            return self.writeMessage(stream_id, msg.writeAnnounceOk, ok);
        }

        pub fn sendAnnounceBroadcast(self: *Self, stream_id: u64, b: msg.AnnounceBroadcast) !void {
            return self.writeMessage(stream_id, msg.writeAnnounceBroadcast, b);
        }

        pub fn sendSubscribeResponse(self: *Self, stream_id: u64, r: msg.SubscribeResponse) !void {
            return self.writeMessage(stream_id, msg.writeSubscribeResponse, r);
        }

        pub fn sendTrackInfo(self: *Self, stream_id: u64, info: msg.TrackInfo) !void {
            try self.writeMessage(stream_id, msg.writeTrackInfo, info);
            self.transport.finish(stream_id); // §5.1.6: one reply, then FIN
        }

        pub fn sendProbe(self: *Self, stream_id: u64, p: msg.Probe) !void {
            return self.writeMessage(stream_id, msg.writeProbe, p);
        }

        // --- group streams -------------------------------------------

        /// Opens a data stream for one group. Frames follow via sendFrame;
        /// FIN with finishGroup, or reset to abandon it.
        pub fn openGroup(self: *Self, group: msg.Group) !u64 {
            const sid = try self.transport.openUni();
            var buf: [64]u8 = undefined;
            var fbs = io.fixedBufferStream(&buf);
            try msg.writeStreamType(&fbs, @intFromEnum(msg.DataType.group));
            try msg.writeGroup(&fbs, group);
            try self.transport.write(sid, buf[0..fbs.seek]);
            return sid;
        }

        /// Writes a frame header, then the payload. Splitting the two lets
        /// a caller stream a payload it does not hold contiguously.
        pub fn sendFrame(self: *Self, stream_id: u64, f: msg.Frame) !void {
            var hdr: [32]u8 = undefined;
            var fbs = io.fixedBufferStream(&hdr);
            try wire.writeZigzag(&fbs, f.timestamp_delta);
            try wire.writeVarInt(&fbs, f.payload.len);
            try self.transport.write(stream_id, hdr[0..fbs.seek]);
            if (f.payload.len > 0) try self.transport.write(stream_id, f.payload);
        }

        pub fn finishGroup(self: *Self, stream_id: u64) void {
            self.transport.finish(stream_id);
        }

        pub fn resetStream(self: *Self, stream_id: u64, code: u64) void {
            self.transport.reset(stream_id, code);
            self.release(stream_id);
        }

        pub fn finishStream(self: *Self, stream_id: u64) void {
            self.transport.finish(stream_id);
        }

        // --- receiving -----------------------------------------------

        /// Call when the peer opens a stream. Without it the stream is
        /// assumed unidirectional, and a control stream's type byte will
        /// not decode — event loops surface the direction, so pass it on.
        pub fn onPeerStream(self: *Self, stream_id: u64, bidi: bool) !void {
            _ = self.claim(stream_id, if (bidi) .unknown_bidi else .unknown_uni) orelse
                return Error.TooManyStreams;
        }

        /// Feeds one read into the session, filling `out` with the events it
        /// produced. Events borrow from the stream buffer and from `self`,
        /// so consume them before calling again.
        pub fn onStreamData(
            self: *Self,
            stream_id: u64,
            data: []const u8,
            fin: bool,
            out: []Event,
        ) !usize {
            var n: usize = 0;

            if (data.len > 0) {
                const s = self.claim(stream_id, .unknown_uni) orelse return Error.TooManyStreams;

                // Group payloads are forwarded, not buffered: a keyframe is
                // larger than any control message we are willing to hold.
                if (s.role == .group_in) {
                    if (n < out.len) {
                        out[n] = .{ .group_data = .{ .stream_id = stream_id, .data = data } };
                        n += 1;
                    }
                } else {
                    s.append(data);
                    n += try self.drain(stream_id, s, out[n..]);
                }
            }

            if (fin) {
                const role = if (self.slot(stream_id)) |s| s.role else null;
                if (n < out.len) {
                    out[n] = if (role == .group_in or role == .group_in_header)
                        .{ .group_end = .{ .stream_id = stream_id } }
                    else
                        .{ .stream_finished = .{ .stream_id = stream_id } };
                    n += 1;
                }
                self.release(stream_id);
            }
            return n;
        }

        fn drain(self: *Self, stream_id: u64, s: *StreamState, out: []Event) !usize {
            var n: usize = 0;
            while (n < out.len) {
                switch (s.role) {
                    .unknown_uni, .unknown_bidi => {
                        var fbs = io.fixedBufferStream(s.slice());
                        const raw = wire.readVarInt(&fbs) catch break;
                        if (s.role == .unknown_uni) {
                            const t = msg.DataType.fromInt(raw) orelse return Error.UnknownStreamType;
                            s.role = switch (t) {
                                .setup => .setup_in,
                                .group => .group_in_header,
                            };
                        } else {
                            const t = msg.ControlType.fromInt(raw) orelse return Error.UnknownStreamType;
                            s.role = switch (t) {
                                .announce => .announce_in,
                                .subscribe => .subscribe_in,
                                .fetch => .fetch_in,
                                .probe => .probe_in,
                                .goaway => .goaway_in,
                                .track => .track_in,
                            };
                        }
                        s.consume(fbs.seek);
                    },
                    // Once a group stream's header is read the rest is
                    // payload, not messages: hand over whatever is still
                    // buffered and let onStreamData forward the rest.
                    .group_in => {
                        if (s.len == 0) break;
                        out[n] = .{ .group_data = .{ .stream_id = stream_id, .data = s.slice() } };
                        n += 1;
                        // The slice aliases the buffer, so it has to be
                        // consumed by the caller before the next read; that
                        // is the same contract every event here has.
                        s.len = 0;
                        break;
                    },
                    else => {
                        const ev = (try self.next(stream_id, s)) orelse break;
                        if (ev) |e| {
                            out[n] = e;
                            n += 1;
                        }
                    },
                }
            }
            return n;
        }

        /// Reads the next message on an already-classified stream. Returns
        /// null when the buffer does not hold a whole one yet, and an
        /// optional event because some messages only advance state.
        fn next(self: *Self, stream_id: u64, s: *StreamState) Error!?(?Event) {
            // Subscribe responses carry a type varint ahead of the length.
            if (s.role == .subscribe_out) {
                var fbs = io.fixedBufferStream(s.slice());
                const raw = wire.readVarInt(&fbs) catch return null;
                const kind = msg.ResponseType.fromInt(raw) orelse return Error.ProtocolViolation;
                const f = (try msg.frame(s.buf[fbs.seek..s.len])) orelse return null;
                const r = try msg.decodeSubscribeResponse(kind, f.body);
                s.consume(fbs.seek + f.consumed);
                s.started = true;
                return Event{ .subscribe_response = .{ .stream_id = stream_id, .response = r } };
            }

            const f = (try msg.frame(s.slice())) orelse return null;
            const body = f.body;
            const ev: ?Event = switch (s.role) {
                .setup_in => blk: {
                    self.peer_setup = try msg.decodeSetup(body);
                    self.setup_received = true;
                    break :blk Event{ .peer_setup = .{ .setup = self.peer_setup } };
                },
                .group_in_header => blk: {
                    s.role = .group_in;
                    break :blk Event{ .group_start = .{
                        .stream_id = stream_id,
                        .group = try msg.decodeGroup(body),
                    } };
                },
                .announce_in => Event{ .announce_request = .{
                    .stream_id = stream_id,
                    .request = try msg.decodeAnnounceRequest(body),
                } },
                .announce_out => blk: {
                    // ANNOUNCE_OK comes exactly once, first.
                    if (!s.started) {
                        s.started = true;
                        break :blk Event{ .announce_ok = .{
                            .stream_id = stream_id,
                            .ok = try msg.decodeAnnounceOk(body),
                        } };
                    }
                    break :blk Event{ .announce_broadcast = .{
                        .stream_id = stream_id,
                        .broadcast = try msg.decodeAnnounceBroadcast(body, &self.hop_buf),
                    } };
                },
                .subscribe_in => blk: {
                    // SUBSCRIBE first, then any number of updates.
                    if (!s.started) {
                        s.started = true;
                        break :blk Event{ .subscribe_request = .{
                            .stream_id = stream_id,
                            .subscribe = try msg.decodeSubscribe(body),
                        } };
                    }
                    break :blk Event{ .subscribe_update = .{
                        .stream_id = stream_id,
                        .update = try msg.decodeSubscribeUpdate(body),
                    } };
                },
                .track_in => Event{ .track_request = .{
                    .stream_id = stream_id,
                    .track = try msg.decodeTrack(body),
                } },
                .track_out => Event{ .track_info = .{
                    .stream_id = stream_id,
                    .info = try msg.decodeTrackInfo(body),
                } },
                .fetch_in => Event{ .fetch_request = .{
                    .stream_id = stream_id,
                    .fetch = try msg.decodeFetch(body),
                } },
                .probe_in, .probe_out => Event{ .probe = .{
                    .stream_id = stream_id,
                    .probe = try msg.decodeProbe(body),
                } },
                .goaway_in, .goaway_out => Event{ .goaway = .{
                    .stream_id = stream_id,
                    .goaway = try msg.decodeGoaway(body),
                } },
                // A fetch response is bare frames, surfaced like group data.
                .fetch_out => Event{ .group_data = .{ .stream_id = stream_id, .data = body } },
                // These are handled before next() is reached.
                .subscribe_out, .group_in, .unknown_uni, .unknown_bidi => null,
            };
            s.consume(f.consumed);
            return ev;
        }

        pub fn isEstablished(self: *const Self) bool {
            return self.setup_sent and self.setup_received;
        }
    };
}

/// Turns the byte stream of a group into frames. Groups arrive as raw
/// bytes so a relay can forward them without parsing; a subscriber runs
/// them through this.
///
/// A returned payload aliases the reader's buffer and stays valid until the
/// next push(), which is when consumed bytes are compacted away.
pub const FrameReader = struct {
    buf: []u8,
    len: usize = 0,
    pos: usize = 0,
    /// Running timestamp in the track's timescale. Deltas are relative to
    /// the previous frame, and the first is relative to zero.
    timestamp: i64 = 0,

    pub fn init(buf: []u8) FrameReader {
        return .{ .buf = buf };
    }

    pub fn push(self: *FrameReader, data: []const u8) error{Overflow}!void {
        if (self.pos > 0) {
            const rest = self.len - self.pos;
            std.mem.copyForwards(u8, self.buf[0..rest], self.buf[self.pos..self.len]);
            self.len = rest;
            self.pos = 0;
        }
        if (data.len > self.buf.len - self.len) return error.Overflow;
        @memcpy(self.buf[self.len..][0..data.len], data);
        self.len += data.len;
    }

    pub const Item = struct { timestamp: i64, payload: []const u8 };

    /// The next whole frame, or null when more bytes are needed.
    pub fn next(self: *FrameReader) msg.Error!?Item {
        const r = (try msg.readFrame(self.buf[self.pos..self.len])) orelse return null;
        self.timestamp += r.frame.timestamp_delta;
        self.pos += r.consumed;
        return .{ .timestamp = self.timestamp, .payload = r.frame.payload };
    }

    /// Bytes held but not yet forming a whole frame.
    pub fn buffered(self: *const FrameReader) usize {
        return self.len - self.pos;
    }
};

// --- tests ----------------------------------------------------------------

const FakeTransport = struct {
    next_uni: u64 = 2,
    next_bidi: u64 = 0,
    written: [16384]u8 = undefined,
    written_len: usize = 0,
    finished: [32]u64 = undefined,
    finished_len: usize = 0,
    last_reset: ?struct { id: u64, code: u64 } = null,

    fn openUni(self: *FakeTransport) !u64 {
        defer self.next_uni += 4;
        return self.next_uni;
    }
    fn openBidi(self: *FakeTransport) !u64 {
        defer self.next_bidi += 4;
        return self.next_bidi;
    }
    fn write(self: *FakeTransport, _: u64, data: []const u8) !void {
        @memcpy(self.written[self.written_len..][0..data.len], data);
        self.written_len += data.len;
    }
    fn finish(self: *FakeTransport, id: u64) void {
        self.finished[self.finished_len] = id;
        self.finished_len += 1;
    }
    fn reset(self: *FakeTransport, id: u64, code: u64) void {
        self.last_reset = .{ .id = id, .code = code };
    }
    fn sent(self: *const FakeTransport) []const u8 {
        return self.written[0..self.written_len];
    }
    fn wasFinished(self: *const FakeTransport, id: u64) bool {
        for (self.finished[0..self.finished_len]) |f| if (f == id) return true;
        return false;
    }
};

const TestSession = Session(*FakeTransport);

/// Feeds `bytes` one at a time, so every test also exercises reassembly.
fn feedByByte(s: *TestSession, stream_id: u64, bytes: []const u8, out: []Event) !usize {
    var n: usize = 0;
    for (bytes) |b| {
        const one = [_]u8{b};
        n += try s.onStreamData(stream_id, &one, false, out[n..]);
    }
    return n;
}

test "SETUP goes out on a uni stream that is then finished" {
    var t = FakeTransport{};
    var s = TestSession.init(&t);
    s.path = "/anon";
    s.probe_level = .report;
    try s.sendSetup();

    try testing.expect(s.setup_sent);
    try testing.expect(t.wasFinished(2));

    // Stream type 0x1, then the framed SETUP.
    const bytes = t.sent();
    try testing.expectEqual(@as(u8, 0x01), bytes[0]);
    const f = (try msg.frame(bytes[1..])).?;
    const setup = try msg.decodeSetup(f.body);
    try testing.expectEqualStrings("/anon", setup.path.?);
    try testing.expectEqual(msg.ProbeLevel.report, setup.probe.?);
}

test "the peer's SETUP completes the handshake" {
    var t = FakeTransport{};
    var s = TestSession.init(&t);
    try s.sendSetup();
    try testing.expect(!s.isEstablished());

    var buf: [128]u8 = undefined;
    var fbs = io.fixedBufferStream(&buf);
    try msg.writeStreamType(&fbs, @intFromEnum(msg.DataType.setup));
    try msg.writeSetup(&fbs, .{ .probe = .increase });

    try s.onPeerStream(3, false);
    var events: [4]Event = undefined;
    const n = try feedByByte(&s, 3, buf[0..fbs.seek], &events);
    try testing.expectEqual(@as(usize, 1), n);
    try testing.expectEqual(msg.ProbeLevel.increase, events[0].peer_setup.setup.probe.?);
    try testing.expect(s.isEstablished());
}

test "an unknown stream type is a protocol error, not a guess" {
    var t = FakeTransport{};
    var s = TestSession.init(&t);
    var events: [2]Event = undefined;
    try testing.expectError(Error.UnknownStreamType, s.onStreamData(3, &.{0x09}, false, &events));
}

test "a subscribe stream carries the request then its updates" {
    var t = FakeTransport{};
    var s = TestSession.init(&t);

    var buf: [256]u8 = undefined;
    var fbs = io.fixedBufferStream(&buf);
    try msg.writeStreamType(&fbs, @intFromEnum(msg.ControlType.subscribe));
    try msg.writeSubscribe(&fbs, .{ .id = 3, .broadcast = "room", .track = "video", .priority = 7 });
    try msg.writeSubscribeUpdate(&fbs, .{ .priority = 9, .ordered = true });

    try s.onPeerStream(1, true);
    var events: [8]Event = undefined;
    const n = try feedByByte(&s, 1, buf[0..fbs.seek], &events);
    try testing.expectEqual(@as(usize, 2), n);
    try testing.expectEqual(@as(u64, 3), events[0].subscribe_request.subscribe.id);
    try testing.expectEqualStrings("video", events[0].subscribe_request.subscribe.track);
    try testing.expectEqual(@as(u8, 9), events[1].subscribe_update.update.priority);
}

test "subscribe responses come back typed" {
    var t = FakeTransport{};
    var s = TestSession.init(&t);
    const opened = try s.openSubscribe(.{ .broadcast = "room", .track = "video" });
    try testing.expectEqual(@as(u64, 0), opened.id);

    var buf: [256]u8 = undefined;
    var fbs = io.fixedBufferStream(&buf);
    try msg.writeSubscribeResponse(&fbs, .{ .ok = .{ .group = 5 } });
    try msg.writeSubscribeResponse(&fbs, .{ .drop = .{ .group_start = 5, .group_end = 6, .error_code = 1 } });
    try msg.writeSubscribeResponse(&fbs, .{ .end = .{ .group = 9 } });

    var events: [8]Event = undefined;
    const n = try feedByByte(&s, opened.stream_id, buf[0..fbs.seek], &events);
    try testing.expectEqual(@as(usize, 3), n);
    try testing.expectEqual(@as(u64, 5), events[0].subscribe_response.response.ok.group);
    try testing.expectEqual(@as(u64, 1), events[1].subscribe_response.response.drop.error_code);
    try testing.expectEqual(@as(u64, 9), events[2].subscribe_response.response.end.group);
}

test "subscribe ids are allocated per session" {
    var t = FakeTransport{};
    var s = TestSession.init(&t);
    try testing.expectEqual(@as(u64, 0), (try s.openSubscribe(.{})).id);
    try testing.expectEqual(@as(u64, 1), (try s.openSubscribe(.{})).id);
    try testing.expectEqual(@as(u64, 2), (try s.openSubscribe(.{})).id);
}

test "an announce stream gives ANNOUNCE_OK once, then broadcasts" {
    var t = FakeTransport{};
    var s = TestSession.init(&t);
    const sid = try s.openAnnounce(.{ .prefix = "room" });

    var buf: [256]u8 = undefined;
    var fbs = io.fixedBufferStream(&buf);
    try msg.writeAnnounceOk(&fbs, .{ .hop_id = 2, .active_count = 1 });
    try msg.writeAnnounceBroadcast(&fbs, .{ .status = .active, .suffix = "alice" });
    try msg.writeAnnounceBroadcast(&fbs, .{ .status = .ended, .suffix = "alice" });

    var events: [8]Event = undefined;
    const n = try feedByByte(&s, sid, buf[0..fbs.seek], &events);
    try testing.expectEqual(@as(usize, 3), n);
    try testing.expectEqual(@as(u64, 2), events[0].announce_ok.ok.hop_id);
    try testing.expectEqualStrings("alice", events[1].announce_broadcast.broadcast.suffix);
    try testing.expectEqual(msg.AnnounceStatus.ended, events[2].announce_broadcast.broadcast.status);
}

test "frames arriving with the group header are not swallowed" {
    // Regression: the bytes left in the buffer after the GROUP header were
    // framed as if they were another control message, and dropped.
    var t = FakeTransport{};
    var s = TestSession.init(&t);

    var buf: [128]u8 = undefined;
    var fbs = io.fixedBufferStream(&buf);
    try msg.writeStreamType(&fbs, @intFromEnum(msg.DataType.group));
    try msg.writeGroup(&fbs, .{ .subscribe_id = 1, .sequence = 0 });
    const header_len = fbs.seek;
    try msg.writeFrame(&fbs, .{ .timestamp_delta = 0, .payload = "first" });

    try s.onPeerStream(7, false);
    var events: [8]Event = undefined;
    const n = try s.onStreamData(7, buf[0..fbs.seek], false, &events);
    try testing.expectEqual(@as(usize, 2), n);
    try testing.expectEqual(@as(u64, 0), events[0].group_start.group.sequence);

    var rbuf: [128]u8 = undefined;
    var reader = FrameReader.init(&rbuf);
    try reader.push(events[1].group_data.data);
    const item = (try reader.next()).?;
    try testing.expectEqualStrings("first", item.payload);
    try testing.expectEqual(@as(i64, 0), item.timestamp);
    try testing.expectEqual(fbs.seek - header_len, events[1].group_data.data.len);
}

test "a group stream names its subscription, then forwards bytes" {
    var t = FakeTransport{};
    var s = TestSession.init(&t);

    var hdr: [64]u8 = undefined;
    var hfbs = io.fixedBufferStream(&hdr);
    try msg.writeStreamType(&hfbs, @intFromEnum(msg.DataType.group));
    try msg.writeGroup(&hfbs, .{ .subscribe_id = 4, .sequence = 17 });

    try s.onPeerStream(7, false);
    var events: [8]Event = undefined;
    var n = try feedByByte(&s, 7, hdr[0..hfbs.seek], &events);
    try testing.expectEqual(@as(usize, 1), n);
    try testing.expectEqual(@as(u64, 4), events[0].group_start.group.subscribe_id);
    try testing.expectEqual(@as(u64, 17), events[0].group_start.group.sequence);

    // Everything after the header is handed over untouched.
    n = try s.onStreamData(7, "raw frame bytes", false, &events);
    try testing.expectEqual(@as(usize, 1), n);
    try testing.expectEqualStrings("raw frame bytes", events[0].group_data.data);

    n = try s.onStreamData(7, &.{}, true, &events);
    try testing.expectEqual(@as(usize, 1), n);
    try testing.expectEqual(@as(u64, 7), events[0].group_end.stream_id);
    try testing.expectEqual(@as(?Role, null), s.roleOf(7));
}

test "publishing a group writes the header then frames" {
    var t = FakeTransport{};
    var s = TestSession.init(&t);
    const sid = try s.openGroup(.{ .subscribe_id = 1, .sequence = 2 });
    try s.sendFrame(sid, .{ .timestamp_delta = 0, .payload = "first" });
    try s.sendFrame(sid, .{ .timestamp_delta = 33, .payload = "second" });
    s.finishGroup(sid);
    try testing.expect(t.wasFinished(sid));

    // Read it back the way a subscriber would.
    const bytes = t.sent();
    var fbs = io.fixedBufferStream(bytes);
    try testing.expectEqual(@as(u64, 0), try wire.readVarInt(&fbs));
    const f = (try msg.frame(bytes[fbs.seek..])).?;
    const g = try msg.decodeGroup(f.body);
    try testing.expectEqual(@as(u64, 2), g.sequence);

    var rbuf: [256]u8 = undefined;
    var reader = FrameReader.init(&rbuf);
    try reader.push(bytes[fbs.seek + f.consumed ..]);
    const one = (try reader.next()).?;
    try testing.expectEqual(@as(i64, 0), one.timestamp);
    try testing.expectEqualStrings("first", one.payload);
    const two = (try reader.next()).?;
    try testing.expectEqual(@as(i64, 33), two.timestamp);
    try testing.expectEqualStrings("second", two.payload);
    try testing.expectEqual(@as(?FrameReader.Item, null), try reader.next());
}

test "FrameReader accumulates timestamps and survives split pushes" {
    var buf: [256]u8 = undefined;
    var fbs = io.fixedBufferStream(&buf);
    try msg.writeFrame(&fbs, .{ .timestamp_delta = 100, .payload = "aaa" });
    try msg.writeFrame(&fbs, .{ .timestamp_delta = -40, .payload = "bb" });
    const encoded = buf[0..fbs.seek];

    var rbuf: [256]u8 = undefined;
    var reader = FrameReader.init(&rbuf);
    var got: usize = 0;
    var last: i64 = 0;
    for (encoded) |b| {
        try reader.push(&[_]u8{b});
        while (try reader.next()) |item| {
            got += 1;
            last = item.timestamp;
        }
    }
    try testing.expectEqual(@as(usize, 2), got);
    try testing.expectEqual(@as(i64, 60), last); // 100 then -40
    try testing.expectEqual(@as(usize, 0), reader.buffered());
}

test "FrameReader refuses to overflow its buffer" {
    var rbuf: [8]u8 = undefined;
    var reader = FrameReader.init(&rbuf);
    try testing.expectError(error.Overflow, reader.push("123456789"));
}

test "a track stream answers once and finishes" {
    var t = FakeTransport{};
    var s = TestSession.init(&t);

    var buf: [128]u8 = undefined;
    var fbs = io.fixedBufferStream(&buf);
    try msg.writeStreamType(&fbs, @intFromEnum(msg.ControlType.track));
    try msg.writeTrack(&fbs, .{ .broadcast = "room", .track = "video" });

    try s.onPeerStream(9, true);
    var events: [4]Event = undefined;
    const n = try feedByByte(&s, 9, buf[0..fbs.seek], &events);
    try testing.expectEqual(@as(usize, 1), n);
    try testing.expectEqualStrings("video", events[0].track_request.track.track);

    try s.sendTrackInfo(9, .{ .timescale = 90000 });
    try testing.expect(t.wasFinished(9));
}

test "probe and goaway streams decode in both directions" {
    var t = FakeTransport{};
    var s = TestSession.init(&t);

    var buf: [128]u8 = undefined;
    var fbs = io.fixedBufferStream(&buf);
    try msg.writeStreamType(&fbs, @intFromEnum(msg.ControlType.probe));
    try msg.writeProbe(&fbs, .{ .bitrate = 2_000_000, .rtt_ms = 12 });

    try s.onPeerStream(11, true);
    var events: [4]Event = undefined;
    var n = try feedByByte(&s, 11, buf[0..fbs.seek], &events);
    try testing.expectEqual(@as(usize, 1), n);
    try testing.expectEqual(@as(u64, 2_000_000), events[0].probe.probe.bitrate);

    var gbuf: [128]u8 = undefined;
    var gfbs = io.fixedBufferStream(&gbuf);
    try msg.writeStreamType(&gfbs, @intFromEnum(msg.ControlType.goaway));
    try msg.writeGoaway(&gfbs, .{ .uri = "https://other/moq" });
    try s.onPeerStream(13, true);
    n = try feedByByte(&s, 13, gbuf[0..gfbs.seek], &events);
    try testing.expectEqual(@as(usize, 1), n);
    try testing.expectEqualStrings("https://other/moq", events[0].goaway.goaway.uri);
}

test "resetting a stream releases its slot" {
    var t = FakeTransport{};
    var s = TestSession.init(&t);
    const sid = try s.openAnnounce(.{ .prefix = "x" });
    try testing.expect(s.roleOf(sid) != null);
    s.resetStream(sid, ResetCode.NOT_FOUND);
    try testing.expectEqual(sid, t.last_reset.?.id);
    try testing.expectEqual(ResetCode.NOT_FOUND, t.last_reset.?.code);
    try testing.expectEqual(@as(?Role, null), s.roleOf(sid));
}

test "the stream table refuses to overflow" {
    var t = FakeTransport{};
    var s = TestSession.init(&t);
    for (0..MAX_STREAMS) |i| try s.onPeerStream(@intCast(i), false);
    try testing.expectError(Error.TooManyStreams, s.onPeerStream(9999, false));
}
