// moq-lite control and data messages — draft-lcurley-moq-lite-05.
//
// There is no global message-type table. A message's identity comes from
// the stream it is on plus its position in that stream, so this module
// exposes one codec per message and leaves sequencing to session.zig.
//
// Every control message is `varint Message Length || body`, and the decoder
// must consume exactly Length — a short read is as much an error as a long
// one, because the next message starts immediately after.

const std = @import("std");
const testing = std.testing;

const io = @import("../../io_compat.zig");
const wire = @import("wire.zig");

pub const Error = error{
    MalformedMessage,
    UnknownStreamType,
    MessageTooLarge,
    /// A reader ran off the end of the buffer mid-value.
    EndOfStream,
} || wire.Error;

// --- stream types (§5.1, §6.3) --------------------------------------------

pub const ControlType = enum(u64) {
    announce = 0x1,
    subscribe = 0x2,
    fetch = 0x3,
    probe = 0x4,
    goaway = 0x5,
    track = 0x6,

    pub fn fromInt(v: u64) ?ControlType {
        return switch (v) {
            0x1 => .announce,
            0x2 => .subscribe,
            0x3 => .fetch,
            0x4 => .probe,
            0x5 => .goaway,
            0x6 => .track,
            else => null,
        };
    }
};

pub const DataType = enum(u64) {
    group = 0x0,
    setup = 0x1,

    pub fn fromInt(v: u64) ?DataType {
        return switch (v) {
            0x0 => .group,
            0x1 => .setup,
            else => null,
        };
    }
};

pub fn writeStreamType(writer: anytype, t: u64) !void {
    return wire.writeVarInt(writer, t);
}

// --- framing --------------------------------------------------------------

/// A message body sliced out of a buffer, plus how many bytes the whole
/// message occupied. Returns null when the buffer does not yet hold a
/// complete message, which is the normal case mid-stream.
pub const Framed = struct {
    body: []const u8,
    consumed: usize,
};

pub fn frame(data: []const u8) Error!?Framed {
    var fbs = io.fixedBufferStream(data);
    const len = wire.readVarInt(&fbs) catch return null;
    if (len > wire.MAX_MESSAGE_SIZE) return Error.MessageTooLarge;
    const size = std.math.cast(usize, len) orelse return Error.MessageTooLarge;
    const start = fbs.seek;
    if (data.len - start < size) return null;
    return .{ .body = data[start..][0..size], .consumed = start + size };
}

/// Encodes `body` with its length prefix.
fn writeFramed(writer: anytype, body: []const u8) !void {
    try wire.writeVarInt(writer, body.len);
    try writer.writeAll(body);
}

/// Scratch big enough for any control message this module writes. Group
/// payloads do not pass through here — they stream.
const SCRATCH: usize = 4096;

fn encode(writer: anytype, comptime body: anytype, value: anytype) !void {
    var buf: [SCRATCH]u8 = undefined;
    var fbs = io.fixedBufferStream(&buf);
    try body(&fbs, value);
    try writeFramed(writer, buf[0..fbs.seek]);
}

// --- SETUP (§7.2) ---------------------------------------------------------
//
// Sent on a unidirectional Setup Stream (0x1) which is then FINed. Neither
// side waits for the other's, so there is no handshake to block on.

pub const SetupParamType = struct {
    pub const PROBE: u64 = 0x1;
    pub const PATH: u64 = 0x2;
};

/// §7.2.1: what the peer may do with a Probe stream.
pub const ProbeLevel = enum(u64) {
    none = 0,
    report = 1,
    increase = 2,

    pub fn fromInt(v: u64) ?ProbeLevel {
        return switch (v) {
            0 => .none,
            1 => .report,
            2 => .increase,
            else => null,
        };
    }
};

pub const Setup = struct {
    probe: ?ProbeLevel = null,
    /// Client-only, and MUST NOT be sent over WebTransport — the CONNECT
    /// URI already carries the path there.
    path: ?[]const u8 = null,
};

fn encodeSetup(w: anytype, s: Setup) !void {
    var count: u64 = 0;
    if (s.probe != null) count += 1;
    if (s.path != null) count += 1;
    try wire.writeVarInt(w, count);
    if (s.probe) |p| {
        try wire.writeVarInt(w, SetupParamType.PROBE);
        var vbuf: [8]u8 = undefined;
        var vfbs = io.fixedBufferStream(&vbuf);
        try wire.writeVarInt(&vfbs, @intFromEnum(p));
        try wire.writeBytes(w, vbuf[0..vfbs.seek]);
    }
    if (s.path) |p| {
        try wire.writeVarInt(w, SetupParamType.PATH);
        try wire.writeBytes(w, p);
    }
}

pub fn writeSetup(writer: anytype, s: Setup) !void {
    return encode(writer, encodeSetup, s);
}

pub fn decodeSetup(body: []const u8) !Setup {
    var fbs = io.fixedBufferStream(body);
    var s = Setup{};
    const count = try wire.readVarInt(&fbs);
    if (count > 64) return Error.MalformedMessage;
    for (0..@as(usize, @intCast(count))) |_| {
        const t = try wire.readVarInt(&fbs);
        const value = try wire.readBytesZc(&fbs);
        switch (t) {
            SetupParamType.PROBE => {
                var vfbs = io.fixedBufferStream(value);
                s.probe = ProbeLevel.fromInt(try wire.readVarInt(&vfbs)) orelse
                    return Error.MalformedMessage;
            },
            SetupParamType.PATH => s.path = value,
            // §7.2: unknown parameters MUST be ignored. They are
            // length-prefixed, so unlike moq-transport they can be skipped.
            else => {},
        }
    }
    return s;
}

// --- Announce stream (§5.1.1, §7.3-7.5) -----------------------------------

pub const AnnounceRequest = struct {
    prefix: []const u8 = "",
    /// Non-zero asks the publisher to skip announcements whose hop list
    /// contains this ID, which is how a relay mesh avoids loops.
    exclude_hop: u64 = 0,
};

fn encodeAnnounceRequest(w: anytype, a: AnnounceRequest) !void {
    try wire.writeString(w, a.prefix);
    try wire.writeVarInt(w, a.exclude_hop);
}

pub fn writeAnnounceRequest(writer: anytype, a: AnnounceRequest) !void {
    return encode(writer, encodeAnnounceRequest, a);
}

pub fn decodeAnnounceRequest(body: []const u8) !AnnounceRequest {
    var fbs = io.fixedBufferStream(body);
    return .{
        .prefix = try wire.readStringZc(&fbs),
        .exclude_hop = try wire.readVarInt(&fbs),
    };
}

pub const AnnounceOk = struct {
    /// The publisher's own hop ID: the implicit trailing entry of every
    /// ANNOUNCE_BROADCAST hop list on this stream.
    hop_id: u64 = 0,
    /// How many ANNOUNCE_BROADCASTs describe the state at subscribe time,
    /// before live updates begin.
    active_count: u64 = 0,
};

fn encodeAnnounceOk(w: anytype, a: AnnounceOk) !void {
    try wire.writeVarInt(w, a.hop_id);
    try wire.writeVarInt(w, a.active_count);
}

pub fn writeAnnounceOk(writer: anytype, a: AnnounceOk) !void {
    return encode(writer, encodeAnnounceOk, a);
}

pub fn decodeAnnounceOk(body: []const u8) !AnnounceOk {
    var fbs = io.fixedBufferStream(body);
    return .{
        .hop_id = try wire.readVarInt(&fbs),
        .active_count = try wire.readVarInt(&fbs),
    };
}

pub const AnnounceStatus = enum(u64) {
    ended = 0,
    active = 1,

    pub fn fromInt(v: u64) ?AnnounceStatus {
        return switch (v) {
            0 => .ended,
            1 => .active,
            else => null,
        };
    }
};

pub const MAX_HOPS: usize = 32;

pub const AnnounceBroadcast = struct {
    status: AnnounceStatus = .active,
    /// Relative to the ANNOUNCE_REQUEST prefix.
    suffix: []const u8 = "",
    hops: []const u64 = &.{},
};

fn encodeAnnounceBroadcast(w: anytype, a: AnnounceBroadcast) !void {
    try wire.writeVarInt(w, @intFromEnum(a.status));
    try wire.writeString(w, a.suffix);
    if (a.hops.len > MAX_HOPS) return Error.MalformedMessage;
    try wire.writeVarInt(w, a.hops.len);
    for (a.hops) |h| try wire.writeVarInt(w, h);
}

pub fn writeAnnounceBroadcast(writer: anytype, a: AnnounceBroadcast) !void {
    return encode(writer, encodeAnnounceBroadcast, a);
}

/// `hop_buf` receives the hop list, so it must outlive the result.
pub fn decodeAnnounceBroadcast(body: []const u8, hop_buf: *[MAX_HOPS]u64) !AnnounceBroadcast {
    var fbs = io.fixedBufferStream(body);
    const status = AnnounceStatus.fromInt(try wire.readVarInt(&fbs)) orelse
        return Error.MalformedMessage;
    const suffix = try wire.readStringZc(&fbs);
    const count = try wire.readVarInt(&fbs);
    if (count > MAX_HOPS) return Error.MalformedMessage;
    const n: usize = @intCast(count);
    for (0..n) |i| hop_buf[i] = try wire.readVarInt(&fbs);
    return .{ .status = status, .suffix = suffix, .hops = hop_buf[0..n] };
}

// --- Subscribe stream (§5.1.2, §7.6-7.9) ----------------------------------

pub const Subscribe = struct {
    id: u64 = 0,
    broadcast: []const u8 = "",
    track: []const u8 = "",
    priority: u8 = 0,
    /// True delivers older groups first; false (the default) newest first.
    ordered: bool = false,
    max_latency_ms: u64 = 0,
    /// null means "start at the latest group".
    group_start: ?u64 = null,
    /// null means unbounded.
    group_end: ?u64 = null,
};

fn encodeSubscribe(w: anytype, s: Subscribe) !void {
    try wire.writeVarInt(w, s.id);
    try wire.writeString(w, s.broadcast);
    try wire.writeString(w, s.track);
    try w.writeByte(s.priority);
    try w.writeByte(@intFromBool(s.ordered));
    try wire.writeVarInt(w, s.max_latency_ms);
    try wire.writeOptionalGroup(w, s.group_start);
    try wire.writeOptionalGroup(w, s.group_end);
}

pub fn writeSubscribe(writer: anytype, s: Subscribe) !void {
    return encode(writer, encodeSubscribe, s);
}

pub fn decodeSubscribe(body: []const u8) !Subscribe {
    var fbs = io.fixedBufferStream(body);
    return .{
        .id = try wire.readVarInt(&fbs),
        .broadcast = try wire.readStringZc(&fbs),
        .track = try wire.readStringZc(&fbs),
        .priority = fbs.takeByte() catch return Error.BufferTooShort,
        .ordered = (fbs.takeByte() catch return Error.BufferTooShort) != 0,
        .max_latency_ms = try wire.readVarInt(&fbs),
        .group_start = try wire.readOptionalGroup(&fbs),
        .group_end = try wire.readOptionalGroup(&fbs),
    };
}

pub const SubscribeUpdate = struct {
    priority: u8 = 0,
    ordered: bool = false,
    max_latency_ms: u64 = 0,
    group_start: ?u64 = null,
    group_end: ?u64 = null,
};

fn encodeSubscribeUpdate(w: anytype, s: SubscribeUpdate) !void {
    try w.writeByte(s.priority);
    try w.writeByte(@intFromBool(s.ordered));
    try wire.writeVarInt(w, s.max_latency_ms);
    try wire.writeOptionalGroup(w, s.group_start);
    try wire.writeOptionalGroup(w, s.group_end);
}

pub fn writeSubscribeUpdate(writer: anytype, s: SubscribeUpdate) !void {
    return encode(writer, encodeSubscribeUpdate, s);
}

pub fn decodeSubscribeUpdate(body: []const u8) !SubscribeUpdate {
    var fbs = io.fixedBufferStream(body);
    return .{
        .priority = fbs.takeByte() catch return Error.BufferTooShort,
        .ordered = (fbs.takeByte() catch return Error.BufferTooShort) != 0,
        .max_latency_ms = try wire.readVarInt(&fbs),
        .group_start = try wire.readOptionalGroup(&fbs),
        .group_end = try wire.readOptionalGroup(&fbs),
    };
}

/// Responses on a Subscribe stream carry a type discriminator ahead of the
/// length prefix. There is no error response: a rejected subscription is a
/// stream reset.
pub const ResponseType = enum(u64) {
    ok = 0x0,
    end = 0x1,
    drop = 0x2,

    pub fn fromInt(v: u64) ?ResponseType {
        return switch (v) {
            0x0 => .ok,
            0x1 => .end,
            0x2 => .drop,
            else => null,
        };
    }
};

pub const SubscribeResponse = union(ResponseType) {
    /// The first group that will be delivered.
    ok: struct { group: u64 = 0 },
    /// The exclusive end: no group at or after this will be produced. The
    /// -05 text says inclusive, but the reference implementation treats it
    /// as exclusive and the -06 changelog records that as the correction.
    end: struct { group: u64 = 0 },
    drop: struct { group_start: u64 = 0, group_end: u64 = 0, error_code: u64 = 0 },
};

pub fn writeSubscribeResponse(writer: anytype, r: SubscribeResponse) !void {
    try wire.writeVarInt(writer, @intFromEnum(std.meta.activeTag(r)));
    var buf: [SCRATCH]u8 = undefined;
    var fbs = io.fixedBufferStream(&buf);
    switch (r) {
        .ok => |v| try wire.writeVarInt(&fbs, v.group),
        .end => |v| try wire.writeVarInt(&fbs, v.group),
        .drop => |v| {
            try wire.writeVarInt(&fbs, v.group_start);
            try wire.writeVarInt(&fbs, v.group_end);
            try wire.writeVarInt(&fbs, v.error_code);
        },
    }
    try writeFramed(writer, buf[0..fbs.seek]);
}

pub fn decodeSubscribeResponse(kind: ResponseType, body: []const u8) !SubscribeResponse {
    var fbs = io.fixedBufferStream(body);
    return switch (kind) {
        .ok => .{ .ok = .{ .group = try wire.readVarInt(&fbs) } },
        .end => .{ .end = .{ .group = try wire.readVarInt(&fbs) } },
        .drop => .{ .drop = .{
            .group_start = try wire.readVarInt(&fbs),
            .group_end = try wire.readVarInt(&fbs),
            .error_code = try wire.readVarInt(&fbs),
        } },
    };
}

// --- Track stream (§5.1.6, §7.10-7.11) ------------------------------------

pub const Track = struct {
    broadcast: []const u8 = "",
    track: []const u8 = "",
};

fn encodeTrack(w: anytype, t: Track) !void {
    try wire.writeString(w, t.broadcast);
    try wire.writeString(w, t.track);
}

pub fn writeTrack(writer: anytype, t: Track) !void {
    return encode(writer, encodeTrack, t);
}

pub fn decodeTrack(body: []const u8) !Track {
    var fbs = io.fixedBufferStream(body);
    return .{
        .broadcast = try wire.readStringZc(&fbs),
        .track = try wire.readStringZc(&fbs),
    };
}

pub const TrackInfo = struct {
    priority: u8 = 0,
    ordered: bool = false,
    max_latency_ms: u64 = 5000,
    /// Timestamp units per second. MUST be non-zero.
    timescale: u64 = 1000,
};

fn encodeTrackInfo(w: anytype, t: TrackInfo) !void {
    if (t.timescale == 0) return Error.MalformedMessage;
    try w.writeByte(t.priority);
    try w.writeByte(@intFromBool(t.ordered));
    try wire.writeVarInt(w, t.max_latency_ms);
    try wire.writeVarInt(w, t.timescale);
}

pub fn writeTrackInfo(writer: anytype, t: TrackInfo) !void {
    return encode(writer, encodeTrackInfo, t);
}

pub fn decodeTrackInfo(body: []const u8) !TrackInfo {
    var fbs = io.fixedBufferStream(body);
    const t = TrackInfo{
        .priority = fbs.takeByte() catch return Error.BufferTooShort,
        .ordered = (fbs.takeByte() catch return Error.BufferTooShort) != 0,
        .max_latency_ms = try wire.readVarInt(&fbs),
        .timescale = try wire.readVarInt(&fbs),
    };
    if (t.timescale == 0) return Error.MalformedMessage;
    return t;
}

// --- Fetch stream (§5.1.3, §7.12) -----------------------------------------
//
// HTTP-shaped: one request, then bare FRAMEs, then FIN. No response header
// and no error message — a refusal is a stream reset.

pub const Fetch = struct {
    broadcast: []const u8 = "",
    track: []const u8 = "",
    priority: u8 = 0,
    group: u64 = 0,
};

fn encodeFetch(w: anytype, f: Fetch) !void {
    try wire.writeString(w, f.broadcast);
    try wire.writeString(w, f.track);
    try w.writeByte(f.priority);
    try wire.writeVarInt(w, f.group);
}

pub fn writeFetch(writer: anytype, f: Fetch) !void {
    return encode(writer, encodeFetch, f);
}

pub fn decodeFetch(body: []const u8) !Fetch {
    var fbs = io.fixedBufferStream(body);
    return .{
        .broadcast = try wire.readStringZc(&fbs),
        .track = try wire.readStringZc(&fbs),
        .priority = fbs.takeByte() catch return Error.BufferTooShort,
        .group = try wire.readVarInt(&fbs),
    };
}

// --- Probe stream (§5.1.4, §7.13) -----------------------------------------

pub const Probe = struct {
    /// Bits per second; 0 means unknown.
    bitrate: u64 = 0,
    /// Smoothed RTT in milliseconds; 0 means unknown.
    rtt_ms: u64 = 0,
};

fn encodeProbe(w: anytype, p: Probe) !void {
    try wire.writeVarInt(w, p.bitrate);
    try wire.writeVarInt(w, p.rtt_ms);
}

pub fn writeProbe(writer: anytype, p: Probe) !void {
    return encode(writer, encodeProbe, p);
}

pub fn decodeProbe(body: []const u8) !Probe {
    var fbs = io.fixedBufferStream(body);
    return .{
        .bitrate = try wire.readVarInt(&fbs),
        .rtt_ms = try wire.readVarInt(&fbs),
    };
}

// --- Goaway stream (§5.1.5, §7.14) ----------------------------------------

pub const Goaway = struct {
    /// Empty means "no redirect, just shutting down".
    uri: []const u8 = "",
};

fn encodeGoaway(w: anytype, g: Goaway) !void {
    try wire.writeString(w, g.uri);
}

pub fn writeGoaway(writer: anytype, g: Goaway) !void {
    return encode(writer, encodeGoaway, g);
}

pub fn decodeGoaway(body: []const u8) !Goaway {
    var fbs = io.fixedBufferStream(body);
    return .{ .uri = try wire.readStringZc(&fbs) };
}

// --- Group stream (§6.1, §7.17-7.18) --------------------------------------

pub const Group = struct {
    subscribe_id: u64 = 0,
    sequence: u64 = 0,
};

fn encodeGroup(w: anytype, g: Group) !void {
    try wire.writeVarInt(w, g.subscribe_id);
    try wire.writeVarInt(w, g.sequence);
}

pub fn writeGroup(writer: anytype, g: Group) !void {
    return encode(writer, encodeGroup, g);
}

pub fn decodeGroup(body: []const u8) !Group {
    var fbs = io.fixedBufferStream(body);
    return .{
        .subscribe_id = try wire.readVarInt(&fbs),
        .sequence = try wire.readVarInt(&fbs),
    };
}

/// A frame's timestamp delta sits *outside* the length prefix, so a frame
/// is not a plain framed message and does not go through `frame()`.
pub const Frame = struct {
    timestamp_delta: i64 = 0,
    payload: []const u8 = "",
};

pub fn writeFrame(writer: anytype, f: Frame) !void {
    try wire.writeZigzag(writer, f.timestamp_delta);
    try wire.writeVarInt(writer, f.payload.len);
    try writer.writeAll(f.payload);
}

/// Returns null when `data` does not yet hold a whole frame.
pub fn readFrame(data: []const u8) Error!?struct { frame: Frame, consumed: usize } {
    var fbs = io.fixedBufferStream(data);
    const delta = wire.readZigzag(&fbs) catch return null;
    const len_raw = wire.readVarInt(&fbs) catch return null;
    if (len_raw > wire.MAX_MESSAGE_SIZE) return Error.MessageTooLarge;
    const len = std.math.cast(usize, len_raw) orelse return Error.MessageTooLarge;
    const start = fbs.seek;
    if (data.len - start < len) return null;
    return .{
        .frame = .{ .timestamp_delta = delta, .payload = data[start..][0..len] },
        .consumed = start + len,
    };
}

// --- Datagram (§6.4) ------------------------------------------------------
//
// No length prefix: the datagram boundary delimits the payload.

pub const Datagram = struct {
    subscribe_id: u64 = 0,
    sequence: u64 = 0,
    timestamp: u64 = 0,
    payload: []const u8 = "",
};

pub fn writeDatagram(writer: anytype, d: Datagram) !void {
    try wire.writeVarInt(writer, d.subscribe_id);
    try wire.writeVarInt(writer, d.sequence);
    try wire.writeVarInt(writer, d.timestamp);
    try writer.writeAll(d.payload);
}

pub fn decodeDatagram(data: []const u8) !Datagram {
    var fbs = io.fixedBufferStream(data);
    const id = try wire.readVarInt(&fbs);
    const seq = try wire.readVarInt(&fbs);
    const ts = try wire.readVarInt(&fbs);
    return .{
        .subscribe_id = id,
        .sequence = seq,
        .timestamp = ts,
        .payload = data[fbs.seek..],
    };
}

// --- tests ----------------------------------------------------------------

fn roundTrip(comptime W: anytype, comptime D: anytype, value: anytype) !@TypeOf(value) {
    var buf: [512]u8 = undefined;
    var fbs = io.fixedBufferStream(&buf);
    try W(&fbs, value);
    const f = (try frame(buf[0..fbs.seek])).?;
    try testing.expectEqual(fbs.seek, f.consumed);
    return D(f.body);
}

test "TRACK_INFO matches the reference implementation byte for byte" {
    // From rs/moq-net/src/lite/track.rs: the default TrackInfo on lite-05.
    // len=6 | priority=0 | ordered=0 | max_latency=5000ms | timescale=1000.
    var buf: [32]u8 = undefined;
    var fbs = io.fixedBufferStream(&buf);
    try writeTrackInfo(&fbs, .{});
    try testing.expectEqualSlices(
        u8,
        &.{ 0x06, 0x00, 0x00, 0x53, 0x88, 0x43, 0xe8 },
        buf[0..fbs.seek],
    );

    const back = try roundTrip(writeTrackInfo, decodeTrackInfo, TrackInfo{});
    try testing.expectEqual(@as(u64, 5000), back.max_latency_ms);
    try testing.expectEqual(@as(u64, 1000), back.timescale);
}

test "TRACK_INFO rejects a zero timescale" {
    var buf: [32]u8 = undefined;
    var fbs = io.fixedBufferStream(&buf);
    try testing.expectError(Error.MalformedMessage, writeTrackInfo(&fbs, .{ .timescale = 0 }));

    // And on the way in, where a peer could send it.
    const bad = [_]u8{ 0x00, 0x00, 0x00, 0x00 };
    try testing.expectError(Error.MalformedMessage, decodeTrackInfo(&bad));
}

test "framing reports a partial message rather than guessing" {
    var buf: [64]u8 = undefined;
    var fbs = io.fixedBufferStream(&buf);
    try writeGoaway(&fbs, .{ .uri = "https://elsewhere/moq" });
    const full = buf[0..fbs.seek];

    for (0..full.len) |n| {
        try testing.expectEqual(@as(?Framed, null), try frame(full[0..n]));
    }
    const f = (try frame(full)).?;
    try testing.expectEqual(full.len, f.consumed);
    try testing.expectEqualStrings("https://elsewhere/moq", (try decodeGoaway(f.body)).uri);
}

test "framing leaves trailing bytes for the next message" {
    var buf: [128]u8 = undefined;
    var fbs = io.fixedBufferStream(&buf);
    try writeProbe(&fbs, .{ .bitrate = 1, .rtt_ms = 2 });
    const first_len = fbs.seek;
    try writeProbe(&fbs, .{ .bitrate = 3, .rtt_ms = 4 });

    const f = (try frame(buf[0..fbs.seek])).?;
    try testing.expectEqual(first_len, f.consumed);
    try testing.expectEqual(@as(u64, 1), (try decodeProbe(f.body)).bitrate);

    const g = (try frame(buf[f.consumed..fbs.seek])).?;
    try testing.expectEqual(@as(u64, 3), (try decodeProbe(g.body)).bitrate);
}

test "stream types map both ways" {
    try testing.expectEqual(ControlType.subscribe, ControlType.fromInt(0x2).?);
    try testing.expectEqual(ControlType.track, ControlType.fromInt(0x6).?);
    try testing.expectEqual(@as(?ControlType, null), ControlType.fromInt(0x0));
    try testing.expectEqual(@as(?ControlType, null), ControlType.fromInt(0x7));
    try testing.expectEqual(DataType.group, DataType.fromInt(0x0).?);
    try testing.expectEqual(DataType.setup, DataType.fromInt(0x1).?);
    try testing.expectEqual(@as(?DataType, null), DataType.fromInt(0x2));
}

test "SETUP round-trips its parameters" {
    const s = try roundTrip(writeSetup, decodeSetup, Setup{
        .probe = .report,
        .path = "/anon",
    });
    try testing.expectEqual(ProbeLevel.report, s.probe.?);
    try testing.expectEqualStrings("/anon", s.path.?);

    const empty = try roundTrip(writeSetup, decodeSetup, Setup{});
    try testing.expectEqual(@as(?ProbeLevel, null), empty.probe);
    try testing.expectEqual(@as(?[]const u8, null), empty.path);
}

test "SETUP ignores parameters it does not know" {
    // count=1, type=0x7f, length-prefixed value — skippable, unlike a
    // moq-transport message parameter.
    const body = [_]u8{ 0x01, 0x40, 0x7f, 0x02, 0xaa, 0xbb };
    const s = try decodeSetup(&body);
    try testing.expectEqual(@as(?ProbeLevel, null), s.probe);
}

test "ANNOUNCE messages round-trip" {
    const req = try roundTrip(writeAnnounceRequest, decodeAnnounceRequest, AnnounceRequest{
        .prefix = "room/alice",
        .exclude_hop = 7,
    });
    try testing.expectEqualStrings("room/alice", req.prefix);
    try testing.expectEqual(@as(u64, 7), req.exclude_hop);

    const ok = try roundTrip(writeAnnounceOk, decodeAnnounceOk, AnnounceOk{
        .hop_id = 3,
        .active_count = 2,
    });
    try testing.expectEqual(@as(u64, 3), ok.hop_id);
    try testing.expectEqual(@as(u64, 2), ok.active_count);
}

test "ANNOUNCE_BROADCAST carries its hop list" {
    var buf: [128]u8 = undefined;
    var fbs = io.fixedBufferStream(&buf);
    const hops = [_]u64{ 1, 2, 3 };
    try writeAnnounceBroadcast(&fbs, .{ .status = .active, .suffix = "video", .hops = &hops });

    const f = (try frame(buf[0..fbs.seek])).?;
    var hop_buf: [MAX_HOPS]u64 = undefined;
    const a = try decodeAnnounceBroadcast(f.body, &hop_buf);
    try testing.expectEqual(AnnounceStatus.active, a.status);
    try testing.expectEqualStrings("video", a.suffix);
    try testing.expectEqualSlices(u64, &hops, a.hops);
}

test "ANNOUNCE_BROADCAST refuses an oversized hop list" {
    var body: [80]u8 = undefined;
    var fbs = io.fixedBufferStream(&body);
    try wire.writeVarInt(&fbs, 1); // active
    try wire.writeString(&fbs, "x");
    try wire.writeVarInt(&fbs, MAX_HOPS + 1);
    var hop_buf: [MAX_HOPS]u64 = undefined;
    try testing.expectError(Error.MalformedMessage, decodeAnnounceBroadcast(body[0..fbs.seek], &hop_buf));
}

test "SUBSCRIBE round-trips, defaults included" {
    const s = try roundTrip(writeSubscribe, decodeSubscribe, Subscribe{
        .id = 4,
        .broadcast = "room/alice",
        .track = "video",
        .priority = 200,
        .ordered = true,
        .max_latency_ms = 2000,
        .group_start = 10,
        .group_end = 20,
    });
    try testing.expectEqual(@as(u64, 4), s.id);
    try testing.expectEqualStrings("room/alice", s.broadcast);
    try testing.expectEqualStrings("video", s.track);
    try testing.expectEqual(@as(u8, 200), s.priority);
    try testing.expect(s.ordered);
    try testing.expectEqual(@as(u64, 2000), s.max_latency_ms);
    try testing.expectEqual(@as(?u64, 10), s.group_start);
    try testing.expectEqual(@as(?u64, 20), s.group_end);

    // The default subscription: latest group, unbounded.
    const d = try roundTrip(writeSubscribe, decodeSubscribe, Subscribe{ .broadcast = "b", .track = "t" });
    try testing.expectEqual(@as(?u64, null), d.group_start);
    try testing.expectEqual(@as(?u64, null), d.group_end);
    try testing.expect(!d.ordered);
}

test "group 0 is not the same as no group" {
    const s = try roundTrip(writeSubscribe, decodeSubscribe, Subscribe{
        .broadcast = "b",
        .track = "t",
        .group_start = 0,
    });
    try testing.expectEqual(@as(?u64, 0), s.group_start);
}

test "SUBSCRIBE_UPDATE round-trips" {
    const u = try roundTrip(writeSubscribeUpdate, decodeSubscribeUpdate, SubscribeUpdate{
        .priority = 9,
        .ordered = true,
        .max_latency_ms = 100,
        .group_start = 1,
    });
    try testing.expectEqual(@as(u8, 9), u.priority);
    try testing.expect(u.ordered);
    try testing.expectEqual(@as(?u64, 1), u.group_start);
    try testing.expectEqual(@as(?u64, null), u.group_end);
}

test "subscribe responses carry their type ahead of the length" {
    var buf: [64]u8 = undefined;

    for ([_]SubscribeResponse{
        .{ .ok = .{ .group = 7 } },
        .{ .end = .{ .group = 9 } },
        .{ .drop = .{ .group_start = 1, .group_end = 3, .error_code = 5 } },
    }) |r| {
        var fbs = io.fixedBufferStream(&buf);
        try writeSubscribeResponse(&fbs, r);

        var rfbs = io.fixedBufferStream(@as([]const u8, buf[0..fbs.seek]));
        const kind = ResponseType.fromInt(try wire.readVarInt(&rfbs)).?;
        const f = (try frame(buf[rfbs.seek..fbs.seek])).?;
        const back = try decodeSubscribeResponse(kind, f.body);
        try testing.expectEqual(std.meta.activeTag(r), std.meta.activeTag(back));
    }

    // DROP moved from 0x1 to 0x2 in lite-05; the older number is END now.
    var fbs = io.fixedBufferStream(&buf);
    try writeSubscribeResponse(&fbs, .{ .drop = .{} });
    try testing.expectEqual(@as(u8, 0x02), buf[0]);
}

test "TRACK and FETCH round-trip" {
    const t = try roundTrip(writeTrack, decodeTrack, Track{ .broadcast = "b", .track = "audio" });
    try testing.expectEqualStrings("audio", t.track);

    const f = try roundTrip(writeFetch, decodeFetch, Fetch{
        .broadcast = "b",
        .track = "audio",
        .priority = 3,
        .group = 42,
    });
    try testing.expectEqual(@as(u64, 42), f.group);
    try testing.expectEqual(@as(u8, 3), f.priority);
}

test "PROBE and GOAWAY round-trip" {
    const p = try roundTrip(writeProbe, decodeProbe, Probe{ .bitrate = 1_500_000, .rtt_ms = 42 });
    try testing.expectEqual(@as(u64, 1_500_000), p.bitrate);
    try testing.expectEqual(@as(u64, 42), p.rtt_ms);

    const g = try roundTrip(writeGoaway, decodeGoaway, Goaway{});
    try testing.expectEqualStrings("", g.uri);
}

test "GROUP round-trips" {
    const g = try roundTrip(writeGroup, decodeGroup, Group{ .subscribe_id = 2, .sequence = 99 });
    try testing.expectEqual(@as(u64, 2), g.subscribe_id);
    try testing.expectEqual(@as(u64, 99), g.sequence);
}

test "frames put the timestamp delta outside the length prefix" {
    var buf: [128]u8 = undefined;
    var fbs = io.fixedBufferStream(&buf);
    try writeFrame(&fbs, .{ .timestamp_delta = -16, .payload = "abc" });

    // zigzag(-16) = 31, which is a one-byte varint, then length 3, then
    // the payload — the delta is not inside the length-delimited body.
    try testing.expectEqualSlices(u8, &.{ 31, 3, 'a', 'b', 'c' }, buf[0..fbs.seek]);

    const r = (try readFrame(buf[0..fbs.seek])).?;
    try testing.expectEqual(@as(i64, -16), r.frame.timestamp_delta);
    try testing.expectEqualStrings("abc", r.frame.payload);
    try testing.expectEqual(fbs.seek, r.consumed);
}

test "a partial frame is not a frame" {
    var buf: [128]u8 = undefined;
    var fbs = io.fixedBufferStream(&buf);
    try writeFrame(&fbs, .{ .timestamp_delta = 1000, .payload = "0123456789" });
    for (0..fbs.seek) |n| {
        try testing.expectEqual(@as(?@TypeOf((try readFrame(buf[0..fbs.seek])).?), null), try readFrame(buf[0..n]));
    }
}

test "several frames come out of one group stream buffer" {
    var buf: [256]u8 = undefined;
    var fbs = io.fixedBufferStream(&buf);
    try writeFrame(&fbs, .{ .timestamp_delta = 0, .payload = "one" });
    try writeFrame(&fbs, .{ .timestamp_delta = 33, .payload = "two" });
    try writeFrame(&fbs, .{ .timestamp_delta = 33, .payload = "" });

    var rest: []const u8 = buf[0..fbs.seek];
    var seen: usize = 0;
    var ts: i64 = 0;
    while (try readFrame(rest)) |r| {
        ts += r.frame.timestamp_delta;
        seen += 1;
        rest = rest[r.consumed..];
    }
    try testing.expectEqual(@as(usize, 3), seen);
    try testing.expectEqual(@as(i64, 66), ts);
    try testing.expectEqual(@as(usize, 0), rest.len);
}

test "datagrams have no length prefix" {
    var buf: [128]u8 = undefined;
    var fbs = io.fixedBufferStream(&buf);
    try writeDatagram(&fbs, .{
        .subscribe_id = 3,
        .sequence = 7,
        .timestamp = 1234,
        .payload = "payload bytes",
    });
    const d = try decodeDatagram(buf[0..fbs.seek]);
    try testing.expectEqual(@as(u64, 3), d.subscribe_id);
    try testing.expectEqual(@as(u64, 7), d.sequence);
    try testing.expectEqual(@as(u64, 1234), d.timestamp);
    try testing.expectEqualStrings("payload bytes", d.payload);
}

test "an oversized declared length is rejected, not allocated for" {
    // A varint claiming 2^30 bytes. frame() must refuse rather than wait
    // for a buffer that will never arrive.
    var buf: [16]u8 = undefined;
    var fbs = io.fixedBufferStream(&buf);
    try wire.writeVarInt(&fbs, 1 << 30);
    try testing.expectError(Error.MessageTooLarge, frame(buf[0..fbs.seek]));
}
