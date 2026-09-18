const std = @import("std");
const testing = std.testing;
const io = @import("../io_compat.zig");
const packet = @import("../quic/packet.zig");

/// HTTP/3 frame types (RFC 9114 Section 7.2).
pub const H3FrameType = enum(u64) {
    data = 0x00,
    headers = 0x01,
    cancel_push = 0x03, // not used (server push not implemented)
    settings = 0x04,
    push_promise = 0x05, // not used
    goaway = 0x07,
    max_push_id = 0x0d, // not used
    priority_update = 0xF0700, // RFC 9218
    close_webtransport_session = 0x2843, // draft-ietf-webtrans-http3
    drain_webtransport_session = 0x78ae, // draft-ietf-webtrans-http3
    // draft-ietf-webtrans-http3-13 §5.6 session flow control. Capsules, not
    // H3 frames: they travel inside DATA on a session's CONNECT stream, which
    // is the same TLV grammar, so they share this table.
    wt_max_data = 0x190B4D3D,
    wt_max_streams_bidi = 0x190B4D3F,
    wt_max_streams_uni = 0x190B4D40,
    wt_data_blocked = 0x190B4D41,
    wt_streams_blocked_bidi = 0x190B4D43,
    wt_streams_blocked_uni = 0x190B4D44,
    // Sentinel for frame types not recognized by this implementation.
    // Never sent on the wire; constructed only when parse() encounters an
    // unknown type (e.g. RFC 9114 GREASE frames 0x1f*N+0x21).
    unknown = std.math.maxInt(u64),

    pub fn fromInt(v: u64) ?H3FrameType {
        return switch (v) {
            0x00 => .data,
            0x01 => .headers,
            0x03 => .cancel_push,
            0x04 => .settings,
            0x05 => .push_promise,
            0x07 => .goaway,
            0x0d => .max_push_id,
            0xF0700 => .priority_update,
            0x2843 => .close_webtransport_session,
            0x78ae => .drain_webtransport_session,
            0x190B4D3D => .wt_max_data,
            0x190B4D3F => .wt_max_streams_bidi,
            0x190B4D40 => .wt_max_streams_uni,
            0x190B4D41 => .wt_data_blocked,
            0x190B4D43 => .wt_streams_blocked_bidi,
            0x190B4D44 => .wt_streams_blocked_uni,
            else => null,
        };
    }
};

/// Reserved HTTP/2 frame types that MUST cause H3_FRAME_UNEXPECTED (RFC 9114 Section 7.2.8).
fn isReservedH2FrameType(frame_type: u64) bool {
    return switch (frame_type) {
        0x02, 0x06, 0x08, 0x09 => true,
        else => false,
    };
}

/// Reserved HTTP/2 settings IDs that MUST cause H3_SETTINGS_ERROR (RFC 9114 Section 7.2.4.1).
fn isReservedH2SettingsId(id: u64) bool {
    return switch (id) {
        0x00, 0x02, 0x03, 0x04, 0x05 => true,
        else => false,
    };
}

/// HTTP/3 SETTINGS identifiers (RFC 9114 Section 7.2.4.1).
pub const SettingsId = enum(u64) {
    qpack_max_table_capacity = 0x01,
    max_field_section_size = 0x06,
    qpack_blocked_streams = 0x07,
    enable_connect_protocol = 0x08,
    h3_datagram = 0x33,
    enable_webtransport = 0x2b603742, // draft-06 and earlier
    wt_enabled = 0x2c7cf000, // SETTINGS_WT_ENABLED (intermediate draft)
    webtransport_max_sessions = 0xc671706a, // pre-draft-13
    // draft-ietf-webtrans-http3-13 §9.2.
    // Safari 26.4+ implements this draft; WT_MAX_SESSIONS moved to the value
    // below and the new per-session stream/data credits must be advertised or
    // the peer refuses to open WT streams / fully establish the session.
    wt_max_sessions_v13 = 0x14e9cd29,
    wt_initial_max_data = 0x2b61,
    wt_initial_max_streams_uni = 0x2b64,
    wt_initial_max_streams_bidi = 0x2b65,

    pub fn fromInt(v: u64) ?SettingsId {
        return switch (v) {
            0x01 => .qpack_max_table_capacity,
            0x06 => .max_field_section_size,
            0x07 => .qpack_blocked_streams,
            0x08 => .enable_connect_protocol,
            0x33 => .h3_datagram,
            0x2b603742 => .enable_webtransport,
            0x2c7cf000 => .wt_enabled,
            0xc671706a => .webtransport_max_sessions,
            0x14e9cd29 => .wt_max_sessions_v13,
            0x2b61 => .wt_initial_max_data,
            0x2b64 => .wt_initial_max_streams_uni,
            0x2b65 => .wt_initial_max_streams_bidi,
            else => null,
        };
    }
};

/// HTTP/3 SETTINGS (RFC 9114 Section 7.2.4.1).
pub const Settings = struct {
    qpack_max_table_capacity: u64 = 0,
    max_field_section_size: ?u64 = null,
    qpack_blocked_streams: u64 = 0,
    enable_connect_protocol: bool = false,
    h3_datagram: bool = false,
    enable_webtransport: bool = false,
    webtransport_max_sessions: ?u64 = null,
    /// draft-13 renamed this codepoint. Set independently of the legacy field
    /// so a peer can be served one draft, the other, or both.
    wt_max_sessions_v13: ?u64 = null,
    // draft-ietf-webtrans-http3-13 §9.2 per-session credits.
    // Null = not advertised, which the peer reads as the spec default of 0 —
    // i.e. it may not open WT streams or send session bytes at all.
    wt_initial_max_data: ?u64 = null,
    wt_initial_max_streams_bidi: ?u64 = null,
    wt_initial_max_streams_uni: ?u64 = null,
};

/// PRIORITY_UPDATE payload (RFC 9218).
pub const PriorityUpdate = struct {
    stream_id: u64,
    field_value: []const u8,
};

/// CLOSE_WEBTRANSPORT_SESSION payload (draft-ietf-webtrans-http3).
pub const CloseWebtransportSession = struct {
    error_code: u32,
    reason: []const u8, // optional UTF-8 reason phrase
};

/// HTTP/3 frame (RFC 9114 Section 7).
pub const H3Frame = union(H3FrameType) {
    data: []const u8,
    headers: []const u8,
    cancel_push: u64,
    settings: Settings,
    push_promise: void,
    goaway: u64,
    max_push_id: u64,
    priority_update: PriorityUpdate,
    close_webtransport_session: CloseWebtransportSession,
    drain_webtransport_session: void,
    /// §5.6.4: cumulative bytes the peer may send on the session.
    wt_max_data: u64,
    /// §5.6.2: cumulative streams of that type the peer may open.
    wt_max_streams_bidi: u64,
    wt_max_streams_uni: u64,
    /// §5.6.5, §5.6.3: the limit the sender was sitting at when it blocked.
    wt_data_blocked: u64,
    wt_streams_blocked_bidi: u64,
    wt_streams_blocked_uni: u64,
    unknown: void,
};

/// HTTP/3 unidirectional stream types (RFC 9114 Section 6.2).
pub const UniStreamType = enum(u64) {
    control = 0x00,
    push = 0x01,
    qpack_encoder = 0x02,
    qpack_decoder = 0x03,

    pub fn fromInt(v: u64) ?UniStreamType {
        return switch (v) {
            0x00 => .control,
            0x01 => .push,
            0x02 => .qpack_encoder,
            0x03 => .qpack_decoder,
            else => null,
        };
    }
};

/// A frame's type and payload length, read ahead of its payload.
pub const FrameHeader = struct {
    frame_type: u64,
    length: u64,
    /// Bytes the type and length varints took.
    len: usize,
};

/// Read the frame header at the front of `data`, or null if it is not all
/// there yet. Lets a reader decide what to do with a frame — stream it, cap
/// it, skip it — before its payload arrives.
pub fn parseHeader(data: []const u8) error{H3FrameUnexpected}!?FrameHeader {
    var fbs = io.fixedBufferStream(data);
    const frame_type = packet.readVarInt(&fbs) catch return null;
    if (isReservedH2FrameType(frame_type)) return error.H3FrameUnexpected;
    const length = packet.readVarInt(&fbs) catch return null;
    return .{ .frame_type = frame_type, .length = length, .len = fbs.seek };
}

/// Parse one HTTP/3 frame from a byte buffer.
/// Returns the parsed frame and the number of bytes consumed.
pub fn parse(data: []const u8) !struct { frame: H3Frame, consumed: usize } {
    if (data.len == 0) return error.BufferTooShort;

    var fbs = io.fixedBufferStream(data);
    const reader = &fbs;

    // Type (varint)
    const frame_type_raw = packet.readVarInt(reader) catch return error.BufferTooShort;

    // Reject reserved HTTP/2 frame types
    if (isReservedH2FrameType(frame_type_raw)) {
        return error.H3FrameUnexpected;
    }

    // Length (varint)
    const length = packet.readVarInt(reader) catch return error.BufferTooShort;

    const header_size = fbs.seek;
    const total_size = header_size + length;

    if (data.len < total_size) return error.BufferTooShort;

    const payload = data[header_size..total_size];

    const frame_type = H3FrameType.fromInt(frame_type_raw) orelse {
        // Unknown frame types MUST be ignored (RFC 9114 §7.2.8).
        // Return a distinct .unknown variant so callers don't confuse this
        // with a real .data frame (which would be rejected on the control
        // stream per RFC 9114 §7.2.1).
        return .{
            .frame = .{ .unknown = {} },
            .consumed = total_size,
        };
    };

    const frame: H3Frame = switch (frame_type) {
        .data => .{ .data = payload },
        .headers => .{ .headers = payload },
        .settings => blk: {
            var settings = Settings{};
            var sfbs = io.fixedBufferStream(payload);
            const sreader = &sfbs;

            while (sfbs.seek < payload.len) {
                const id_raw = packet.readVarInt(sreader) catch break;
                const value = packet.readVarInt(sreader) catch return error.MalformedSettings;

                // RFC 9114 §7.2.4.1: reserved HTTP/2 settings MUST cause H3_SETTINGS_ERROR
                if (isReservedH2SettingsId(id_raw)) {
                    return error.H3SettingsError;
                }

                if (SettingsId.fromInt(id_raw)) |id| {
                    switch (id) {
                        .qpack_max_table_capacity => settings.qpack_max_table_capacity = value,
                        .max_field_section_size => settings.max_field_section_size = value,
                        .qpack_blocked_streams => settings.qpack_blocked_streams = value,
                        .enable_connect_protocol => settings.enable_connect_protocol = (value != 0),
                        .h3_datagram => settings.h3_datagram = (value != 0),
                        .enable_webtransport, .wt_enabled => settings.enable_webtransport = (value != 0),
                        .webtransport_max_sessions, .wt_max_sessions_v13 => {
                            settings.webtransport_max_sessions = value;
                            if (id == .wt_max_sessions_v13) settings.wt_max_sessions_v13 = value;
                            // Draft-13 §9.2: max_sessions > 0 IS the enablement signal
                            // (SETTINGS_WT_ENABLED was removed). Mirror to the legacy
                            // flag so existing call sites work regardless of draft.
                            if (value > 0) settings.enable_webtransport = true;
                        },
                        .wt_initial_max_data => settings.wt_initial_max_data = value,
                        .wt_initial_max_streams_bidi => settings.wt_initial_max_streams_bidi = value,
                        .wt_initial_max_streams_uni => settings.wt_initial_max_streams_uni = value,
                    }
                }
                // Unknown settings are ignored (RFC 9114 Section 7.2.4.1)
            }
            break :blk .{ .settings = settings };
        },
        .goaway => blk: {
            var gfbs = io.fixedBufferStream(payload);
            const greader = &gfbs;
            const id = packet.readVarInt(greader) catch return error.MalformedGoaway;
            break :blk .{ .goaway = id };
        },
        .cancel_push => blk: {
            // CANCEL_PUSH requires a Push ID, but tolerate empty payload
            // so the H3 layer can properly reject it as H3_FRAME_UNEXPECTED
            // on request streams (RFC 9114 §7.2.5)
            if (payload.len == 0) {
                break :blk .{ .cancel_push = 0 };
            }
            var cfbs = io.fixedBufferStream(payload);
            const creader = &cfbs;
            const id = packet.readVarInt(creader) catch return error.MalformedFrame;
            break :blk .{ .cancel_push = id };
        },
        .max_push_id => blk: {
            var mfbs = io.fixedBufferStream(payload);
            const mreader = &mfbs;
            const id = packet.readVarInt(mreader) catch return error.MalformedFrame;
            break :blk .{ .max_push_id = id };
        },
        .push_promise => .{ .push_promise = {} },
        .priority_update => blk: {
            var pfbs = io.fixedBufferStream(payload);
            const preader = &pfbs;
            const prioritized_id = packet.readVarInt(preader) catch return error.MalformedFrame;
            const fv_start = pfbs.seek;
            break :blk .{ .priority_update = .{
                .stream_id = prioritized_id,
                .field_value = payload[fv_start..],
            } };
        },
        .close_webtransport_session => blk: {
            if (payload.len < 4) return error.MalformedFrame;
            const error_code = std.mem.readInt(u32, payload[0..4], .big);
            const reason = if (payload.len > 4) payload[4..] else &[_]u8{};
            break :blk .{ .close_webtransport_session = .{
                .error_code = error_code,
                .reason = reason,
            } };
        },
        .drain_webtransport_session => .{ .drain_webtransport_session = {} },
        // §5.6: every flow control capsule is one varint. A longer payload is
        // legal padding and is skipped by `consumed`, not by this read.
        inline .wt_max_data,
        .wt_max_streams_bidi,
        .wt_max_streams_uni,
        .wt_data_blocked,
        .wt_streams_blocked_bidi,
        .wt_streams_blocked_uni,
        => |t| blk: {
            var vfbs = io.fixedBufferStream(payload);
            const value = packet.readVarInt(&vfbs) catch return error.MalformedFrame;
            break :blk @unionInit(H3Frame, @tagName(t), value);
        },
        .unknown => unreachable, // .unknown is only produced by the fromInt fallback above
    };

    return .{
        .frame = frame,
        .consumed = total_size,
    };
}

/// Write one HTTP/3 frame to a writer.
pub fn write(frame: H3Frame, writer: anytype) !void {
    switch (frame) {
        .data => |payload| {
            try packet.writeVarInt(writer, 0x00);
            try packet.writeVarInt(writer, payload.len);
            try writer.writeAll(payload);
        },
        .headers => |payload| {
            try packet.writeVarInt(writer, 0x01);
            try packet.writeVarInt(writer, payload.len);
            try writer.writeAll(payload);
        },
        .settings => |s| {
            // Serialize settings to a temp buffer to get length
            var buf: [128]u8 = undefined;
            var sfbs = io.fixedBufferStream(&buf);
            const sw = &sfbs;

            // Always write qpack settings (even if 0, to be explicit)
            try packet.writeVarInt(sw, @intFromEnum(SettingsId.qpack_max_table_capacity));
            try packet.writeVarInt(sw, s.qpack_max_table_capacity);

            try packet.writeVarInt(sw, @intFromEnum(SettingsId.qpack_blocked_streams));
            try packet.writeVarInt(sw, s.qpack_blocked_streams);

            if (s.max_field_section_size) |max_size| {
                try packet.writeVarInt(sw, @intFromEnum(SettingsId.max_field_section_size));
                try packet.writeVarInt(sw, max_size);
            }

            if (s.enable_connect_protocol) {
                try packet.writeVarInt(sw, @intFromEnum(SettingsId.enable_connect_protocol));
                try packet.writeVarInt(sw, 1);
            }

            if (s.h3_datagram) {
                try packet.writeVarInt(sw, @intFromEnum(SettingsId.h3_datagram));
                try packet.writeVarInt(sw, 1);
            }

            if (s.enable_webtransport) {
                try packet.writeVarInt(sw, @intFromEnum(SettingsId.enable_webtransport));
                try packet.writeVarInt(sw, 1);
                try packet.writeVarInt(sw, @intFromEnum(SettingsId.wt_enabled));
                try packet.writeVarInt(sw, 1);
            }
            if (s.webtransport_max_sessions) |max_sessions| {
                try packet.writeVarInt(sw, @intFromEnum(SettingsId.webtransport_max_sessions));
                try packet.writeVarInt(sw, max_sessions);
            }
            if (s.wt_max_sessions_v13) |max_sessions| {
                try packet.writeVarInt(sw, @intFromEnum(SettingsId.wt_max_sessions_v13));
                try packet.writeVarInt(sw, max_sessions);
            }
            // draft-13 §9.2 per-session WT credits. Default 0 = peer refuses to
            // open WT streams / send bytes. Required for Safari 26.4 bidi.
            if (s.wt_initial_max_data) |n| {
                try packet.writeVarInt(sw, @intFromEnum(SettingsId.wt_initial_max_data));
                try packet.writeVarInt(sw, n);
            }
            if (s.wt_initial_max_streams_bidi) |n| {
                try packet.writeVarInt(sw, @intFromEnum(SettingsId.wt_initial_max_streams_bidi));
                try packet.writeVarInt(sw, n);
            }
            if (s.wt_initial_max_streams_uni) |n| {
                try packet.writeVarInt(sw, @intFromEnum(SettingsId.wt_initial_max_streams_uni));
                try packet.writeVarInt(sw, n);
            }

            const settings_payload = sfbs.buffered();
            try packet.writeVarInt(writer, 0x04);
            try packet.writeVarInt(writer, settings_payload.len);
            try writer.writeAll(settings_payload);
        },
        .goaway => |id| {
            // Serialize id to get its varint length
            var buf: [8]u8 = undefined;
            var gfbs = io.fixedBufferStream(&buf);
            try packet.writeVarInt(&gfbs, id);
            const payload_len = gfbs.seek;

            try packet.writeVarInt(writer, 0x07);
            try packet.writeVarInt(writer, payload_len);
            try packet.writeVarInt(writer, id);
        },
        .cancel_push => |id| {
            var buf: [8]u8 = undefined;
            var cfbs = io.fixedBufferStream(&buf);
            try packet.writeVarInt(&cfbs, id);
            const payload_len = cfbs.seek;

            try packet.writeVarInt(writer, 0x03);
            try packet.writeVarInt(writer, payload_len);
            try packet.writeVarInt(writer, id);
        },
        .max_push_id => |id| {
            var buf: [8]u8 = undefined;
            var mfbs = io.fixedBufferStream(&buf);
            try packet.writeVarInt(&mfbs, id);
            const payload_len = mfbs.seek;

            try packet.writeVarInt(writer, 0x0d);
            try packet.writeVarInt(writer, payload_len);
            try packet.writeVarInt(writer, id);
        },
        .push_promise => {},
        .priority_update => |pu| {
            // Compute payload length: varint(stream_id) + field_value bytes
            var id_buf: [8]u8 = undefined;
            var id_fbs = io.fixedBufferStream(&id_buf);
            try packet.writeVarInt(&id_fbs, pu.stream_id);
            const payload_len = id_fbs.seek + pu.field_value.len;

            try packet.writeVarInt(writer, 0xF0700);
            try packet.writeVarInt(writer, payload_len);
            try packet.writeVarInt(writer, pu.stream_id);
            try writer.writeAll(pu.field_value);
        },
        .close_webtransport_session => |cls| {
            const payload_len: u64 = 4 + cls.reason.len;
            try packet.writeVarInt(writer, 0x2843);
            try packet.writeVarInt(writer, payload_len);
            try writer.writeInt(u32, cls.error_code, .big);
            if (cls.reason.len > 0) {
                try writer.writeAll(cls.reason);
            }
        },
        .drain_webtransport_session => {
            try packet.writeVarInt(writer, 0x78ae);
            try packet.writeVarInt(writer, 0); // zero-length payload
        },
        .wt_max_data,
        .wt_max_streams_bidi,
        .wt_max_streams_uni,
        .wt_data_blocked,
        .wt_streams_blocked_bidi,
        .wt_streams_blocked_uni,
        => |n, capsule| try writeVarIntCapsule(writer, capsule, n),
        .unknown => {}, // never serialized
    }
}

/// Type + length + one varint: the shape every §5.6 flow control capsule has.
fn writeVarIntCapsule(writer: anytype, capsule: H3FrameType, value: u64) !void {
    try packet.writeVarInt(writer, @intFromEnum(capsule));
    try packet.writeVarInt(writer, packet.varIntLength(value));
    try packet.writeVarInt(writer, value);
}

/// Drop the `n` bytes a parse consumed from the front of a stream buffer.
/// Both the HTTP/3 request/control streams and the WebTransport capsule stream
/// parse out of an ArrayList they then have to compact.
pub fn consumeFromBuf(buf: *std.ArrayList(u8), n: usize) void {
    const remaining = buf.items.len - n;
    if (remaining > 0) std.mem.copyForwards(u8, buf.items[0..remaining], buf.items[n..]);
    buf.items.len = remaining;
}

/// Write a uni stream type byte to a writer.
pub fn writeUniStreamType(writer: anytype, stream_type: UniStreamType) !void {
    try packet.writeVarInt(writer, @intFromEnum(stream_type));
}

/// Read a uni stream type from a reader.
pub fn readUniStreamType(reader: anytype) !UniStreamType {
    const raw = try packet.readVarInt(reader);
    return UniStreamType.fromInt(raw) orelse error.UnknownStreamType;
}

// Tests

test "H3Frame: unknown frame type parsed as .unknown (RFC 9114 §7.2.8 GREASE)" {
    // GREASE frame type 0x1f*1+0x21 = 0x40 with 3-byte payload.
    // Encoded: type=0x40 (2-byte varint), length=3, payload=0xaa 0xbb 0xcc, then
    // a trailing real SETTINGS frame to verify consumed advances past the GREASE.
    const grease_with_settings = [_]u8{
        0x40, 0x40, // type 0x40 as 2-byte varint
        0x03, // length 3
        0xaa, 0xbb, 0xcc, // random payload
        0x04, 0x00, // SETTINGS type=0x04, length=0 (empty settings)
    };

    const result = try parse(&grease_with_settings);
    try testing.expectEqual(H3FrameType.unknown, std.meta.activeTag(result.frame));
    try testing.expectEqual(@as(usize, 6), result.consumed);

    // The next frame should parse as SETTINGS.
    const next = try parse(grease_with_settings[result.consumed..]);
    try testing.expectEqual(H3FrameType.settings, std.meta.activeTag(next.frame));
}

test "H3Frame: flow control capsules match the draft-13 §9.6 codepoints" {
    // Asserted as bytes, not round-tripped: a round trip against our own
    // encoder proves self-consistency, and these codepoints are how a browser
    // recognises the capsule at all. 4-byte varint, prefix 0b10.
    const cases = [_]struct { frame: H3Frame, bytes: []const u8 }{
        .{ .frame = .{ .wt_max_data = 0x1234 }, .bytes = &.{ 0x99, 0x0b, 0x4d, 0x3d, 0x02, 0x52, 0x34 } },
        .{ .frame = .{ .wt_max_streams_bidi = 100 }, .bytes = &.{ 0x99, 0x0b, 0x4d, 0x3f, 0x02, 0x40, 0x64 } },
        .{ .frame = .{ .wt_max_streams_uni = 100 }, .bytes = &.{ 0x99, 0x0b, 0x4d, 0x40, 0x02, 0x40, 0x64 } },
        .{ .frame = .{ .wt_data_blocked = 0 }, .bytes = &.{ 0x99, 0x0b, 0x4d, 0x41, 0x01, 0x00 } },
        .{ .frame = .{ .wt_streams_blocked_bidi = 0 }, .bytes = &.{ 0x99, 0x0b, 0x4d, 0x43, 0x01, 0x00 } },
        .{ .frame = .{ .wt_streams_blocked_uni = 7 }, .bytes = &.{ 0x99, 0x0b, 0x4d, 0x44, 0x01, 0x07 } },
    };

    for (cases) |c| {
        var buf: [32]u8 = undefined;
        var fbs = io.fixedBufferStream(&buf);
        try write(c.frame, &fbs);
        try testing.expectEqualSlices(u8, c.bytes, fbs.buffered());

        const parsed = try parse(c.bytes);
        try testing.expectEqual(c.bytes.len, parsed.consumed);
        try testing.expectEqualDeep(c.frame, parsed.frame);
    }
}

test "H3Frame: a padded flow control capsule reads its value and skips the rest" {
    // The Length may exceed the varint (§5.6 says nothing about padding, and
    // RFC 9297 capsules carry their own length): read one varint, consume all.
    const padded = [_]u8{ 0x99, 0x0b, 0x4d, 0x3f, 0x04, 0x40, 0x2a, 0xff, 0xff };
    const parsed = try parse(&padded);
    try testing.expectEqual(@as(u64, 42), parsed.frame.wt_max_streams_bidi);
    try testing.expectEqual(@as(usize, 9), parsed.consumed);
}

test "H3Frame: an empty flow control capsule is malformed" {
    const truncated = [_]u8{ 0x99, 0x0b, 0x4d, 0x3d, 0x00 };
    try testing.expectError(error.MalformedFrame, parse(&truncated));
}

test "H3Frame: write and parse DATA" {
    var buf: [256]u8 = undefined;
    var fbs = io.fixedBufferStream(&buf);

    const payload = "hello world";
    try write(.{ .data = payload }, &fbs);

    const written = fbs.buffered();
    const result = try parse(written);

    try testing.expectEqual(H3FrameType.data, std.meta.activeTag(result.frame));
    try testing.expectEqualStrings(payload, result.frame.data);
    try testing.expectEqual(written.len, result.consumed);
}

test "H3Frame: write and parse HEADERS" {
    var buf: [256]u8 = undefined;
    var fbs = io.fixedBufferStream(&buf);

    const headers_data = &[_]u8{ 0x00, 0x00, 0xc0 | 17 }; // prefix + indexed :method GET
    try write(.{ .headers = headers_data }, &fbs);

    const written = fbs.buffered();
    const result = try parse(written);

    try testing.expectEqual(H3FrameType.headers, std.meta.activeTag(result.frame));
    try testing.expectEqualSlices(u8, headers_data, result.frame.headers);
}

test "H3Frame: write and parse SETTINGS" {
    var buf: [256]u8 = undefined;
    var fbs = io.fixedBufferStream(&buf);

    const settings = Settings{
        .qpack_max_table_capacity = 0,
        .qpack_blocked_streams = 0,
        .max_field_section_size = 4096,
    };
    try write(.{ .settings = settings }, &fbs);

    const written = fbs.buffered();
    const result = try parse(written);

    try testing.expectEqual(H3FrameType.settings, std.meta.activeTag(result.frame));
    try testing.expectEqual(@as(u64, 0), result.frame.settings.qpack_max_table_capacity);
    try testing.expectEqual(@as(u64, 0), result.frame.settings.qpack_blocked_streams);
    try testing.expectEqual(@as(u64, 4096), result.frame.settings.max_field_section_size.?);
}

test "H3Frame: write and parse GOAWAY" {
    var buf: [256]u8 = undefined;
    var fbs = io.fixedBufferStream(&buf);

    try write(.{ .goaway = 42 }, &fbs);

    const written = fbs.buffered();
    const result = try parse(written);

    try testing.expectEqual(H3FrameType.goaway, std.meta.activeTag(result.frame));
    try testing.expectEqual(@as(u64, 42), result.frame.goaway);
}

test "H3Frame: reject reserved HTTP/2 frame types" {
    // Frame type 0x02 (PRIORITY in HTTP/2) is reserved
    var buf: [16]u8 = undefined;
    var fbs = io.fixedBufferStream(&buf);
    try packet.writeVarInt(&fbs, 0x02); // type
    try packet.writeVarInt(&fbs, 0); // length

    const result = parse(fbs.buffered());
    try testing.expectError(error.H3FrameUnexpected, result);
}

test "H3Frame: buffer too short" {
    const result = parse(&[_]u8{});
    try testing.expectError(error.BufferTooShort, result);
}

test "H3Frame: partial frame" {
    // DATA frame type + length=100, but only 5 bytes of payload
    var buf: [16]u8 = undefined;
    var fbs = io.fixedBufferStream(&buf);
    try packet.writeVarInt(&fbs, 0x00); // DATA
    try packet.writeVarInt(&fbs, 100); // length = 100

    const result = parse(fbs.buffered());
    try testing.expectError(error.BufferTooShort, result);
}

test "H3Frame: empty SETTINGS" {
    var buf: [16]u8 = undefined;
    var fbs = io.fixedBufferStream(&buf);
    try packet.writeVarInt(&fbs, 0x04); // SETTINGS
    try packet.writeVarInt(&fbs, 0); // length = 0

    const result = try parse(fbs.buffered());
    try testing.expectEqual(H3FrameType.settings, std.meta.activeTag(result.frame));
    try testing.expectEqual(@as(u64, 0), result.frame.settings.qpack_max_table_capacity);
    try testing.expect(result.frame.settings.max_field_section_size == null);
}

test "H3Frame: write and parse SETTINGS with WebTransport fields" {
    var buf: [256]u8 = undefined;
    var fbs = io.fixedBufferStream(&buf);

    const settings = Settings{
        .qpack_max_table_capacity = 0,
        .qpack_blocked_streams = 0,
        .enable_connect_protocol = true,
        .h3_datagram = true,
        .enable_webtransport = true,
        .webtransport_max_sessions = 1,
    };
    try write(.{ .settings = settings }, &fbs);

    const written = fbs.buffered();
    const result = try parse(written);

    try testing.expectEqual(H3FrameType.settings, std.meta.activeTag(result.frame));
    try testing.expect(result.frame.settings.enable_connect_protocol);
    try testing.expect(result.frame.settings.h3_datagram);
    try testing.expect(result.frame.settings.enable_webtransport);
    try testing.expectEqual(@as(u64, 1), result.frame.settings.webtransport_max_sessions.?);
}

test "H3Frame: write and parse PRIORITY_UPDATE" {
    var buf: [256]u8 = undefined;
    var fbs = io.fixedBufferStream(&buf);

    try write(.{ .priority_update = .{
        .stream_id = 4,
        .field_value = "u=1, i",
    } }, &fbs);

    const written = fbs.buffered();
    const result = try parse(written);

    try testing.expectEqual(H3FrameType.priority_update, std.meta.activeTag(result.frame));
    try testing.expectEqual(@as(u64, 4), result.frame.priority_update.stream_id);
    try testing.expectEqualStrings("u=1, i", result.frame.priority_update.field_value);
    try testing.expectEqual(written.len, result.consumed);
}

test "H3Frame: write and parse PRIORITY_UPDATE empty field value" {
    var buf: [256]u8 = undefined;
    var fbs = io.fixedBufferStream(&buf);

    try write(.{ .priority_update = .{
        .stream_id = 0,
        .field_value = "",
    } }, &fbs);

    const written = fbs.buffered();
    const result = try parse(written);

    try testing.expectEqual(H3FrameType.priority_update, std.meta.activeTag(result.frame));
    try testing.expectEqual(@as(u64, 0), result.frame.priority_update.stream_id);
    try testing.expectEqualStrings("", result.frame.priority_update.field_value);
}

test "H3Frame: write and parse CLOSE_WEBTRANSPORT_SESSION" {
    var buf: [256]u8 = undefined;
    var fbs = io.fixedBufferStream(&buf);

    try write(.{ .close_webtransport_session = .{
        .error_code = 42,
        .reason = "goodbye",
    } }, &fbs);

    const written = fbs.buffered();
    const result = try parse(written);

    try testing.expectEqual(H3FrameType.close_webtransport_session, std.meta.activeTag(result.frame));
    try testing.expectEqual(@as(u32, 42), result.frame.close_webtransport_session.error_code);
    try testing.expectEqualStrings("goodbye", result.frame.close_webtransport_session.reason);
    try testing.expectEqual(written.len, result.consumed);
}

test "H3Frame: write and parse CLOSE_WEBTRANSPORT_SESSION no reason" {
    var buf: [256]u8 = undefined;
    var fbs = io.fixedBufferStream(&buf);

    try write(.{ .close_webtransport_session = .{
        .error_code = 0,
        .reason = "",
    } }, &fbs);

    const written = fbs.buffered();
    const result = try parse(written);

    try testing.expectEqual(H3FrameType.close_webtransport_session, std.meta.activeTag(result.frame));
    try testing.expectEqual(@as(u32, 0), result.frame.close_webtransport_session.error_code);
    try testing.expectEqualStrings("", result.frame.close_webtransport_session.reason);
}

test "UniStreamType: write and read" {
    var buf: [8]u8 = undefined;
    var fbs = io.fixedBufferStream(&buf);
    try writeUniStreamType(&fbs, .control);

    var rfbs = io.fixedBufferStream(fbs.buffered());
    const st = try readUniStreamType(&rfbs);
    try testing.expectEqual(UniStreamType.control, st);
}

// ── Adversarial tests (RFC 9114 §7) ───────────────────────────────────

// All reserved HTTP/2 frame types MUST be rejected (RFC 9114 §7.2.8).
test "H3Frame: all reserved HTTP/2 frame types rejected" {
    const reserved = [_]u8{ 0x02, 0x06, 0x08, 0x09 };
    for (reserved) |t| {
        var buf: [4]u8 = undefined;
        var fbs = io.fixedBufferStream(&buf);
        try packet.writeVarInt(&fbs, t);
        try packet.writeVarInt(&fbs, 0);
        try testing.expectError(error.H3FrameUnexpected, parse(fbs.buffered()));
    }
}

// All reserved HTTP/2 SETTINGS identifiers (§7.2.4.1) MUST be rejected.
test "H3Frame: all reserved HTTP/2 SETTINGS ids rejected" {
    const reserved_ids = [_]u8{ 0x00, 0x02, 0x03, 0x04, 0x05 };
    for (reserved_ids) |id| {
        var buf: [8]u8 = undefined;
        var fbs = io.fixedBufferStream(&buf);
        try packet.writeVarInt(&fbs, 0x04); // SETTINGS
        try packet.writeVarInt(&fbs, 2); // length = 2 bytes (id + value)
        try packet.writeVarInt(&fbs, id);
        try packet.writeVarInt(&fbs, 0);
        try testing.expectError(error.H3SettingsError, parse(fbs.buffered()));
    }
}

// DATA frame with length=0 is structurally valid (empty payload).
test "H3Frame: zero-length DATA is accepted" {
    const bytes = [_]u8{ 0x00, 0x00 }; // type=0, length=0
    const result = try parse(&bytes);
    try testing.expectEqual(H3FrameType.data, std.meta.activeTag(result.frame));
    try testing.expectEqual(@as(usize, 0), result.frame.data.len);
    try testing.expectEqual(@as(usize, 2), result.consumed);
}

// HEADERS frame with length=0 is accepted (empty QPACK block handled by decoder).
test "H3Frame: zero-length HEADERS is accepted" {
    const bytes = [_]u8{ 0x01, 0x00 };
    const result = try parse(&bytes);
    try testing.expectEqual(H3FrameType.headers, std.meta.activeTag(result.frame));
    try testing.expectEqual(@as(usize, 0), result.frame.headers.len);
}

// CLOSE_WEBTRANSPORT_SESSION payload must be ≥4 bytes (32-bit error code).
test "H3Frame: CLOSE_WEBTRANSPORT_SESSION with <4 byte payload rejected" {
    // type = 0x2843 (2-byte varint), length = 3, payload = 3 bytes
    var buf: [16]u8 = undefined;
    var fbs = io.fixedBufferStream(&buf);
    try packet.writeVarInt(&fbs, 0x2843);
    try packet.writeVarInt(&fbs, 3);
    try fbs.writeAll(&[_]u8{ 0xaa, 0xbb, 0xcc });
    try testing.expectError(error.MalformedFrame, parse(fbs.buffered()));
}

// CLOSE_WEBTRANSPORT_SESSION with exactly 4 bytes (error code, no reason).
test "H3Frame: CLOSE_WEBTRANSPORT_SESSION no reason accepted" {
    var buf: [16]u8 = undefined;
    var fbs = io.fixedBufferStream(&buf);
    try packet.writeVarInt(&fbs, 0x2843);
    try packet.writeVarInt(&fbs, 4);
    try fbs.writeInt(u32, 0xdeadbeef, .big);

    const result = try parse(fbs.buffered());
    try testing.expectEqual(H3FrameType.close_webtransport_session, std.meta.activeTag(result.frame));
    try testing.expectEqual(@as(u32, 0xdeadbeef), result.frame.close_webtransport_session.error_code);
    try testing.expectEqualStrings("", result.frame.close_webtransport_session.reason);
}

// PRIORITY_UPDATE with a truncated stream_id varint inside the payload.
test "H3Frame: PRIORITY_UPDATE with truncated stream_id rejected" {
    // type = 0xF0700 (4-byte varint), length = 1, payload = 0xc0
    // 0xc0 begins an 8-byte varint but only 1 payload byte is present.
    var buf: [16]u8 = undefined;
    var fbs = io.fixedBufferStream(&buf);
    try packet.writeVarInt(&fbs, 0xF0700);
    try packet.writeVarInt(&fbs, 1);
    try fbs.writeByte(0xc0);
    try testing.expectError(error.MalformedFrame, parse(fbs.buffered()));
}

// Length field that claims more bytes than available.
test "H3Frame: length exceeding available bytes rejected" {
    // DATA type + length = 2^62-1 (max varint). Buffer is tiny.
    var buf: [16]u8 = undefined;
    var fbs = io.fixedBufferStream(&buf);
    try packet.writeVarInt(&fbs, 0x00);
    try packet.writeVarInt(&fbs, 0x3fffffffffffffff); // 8-byte max varint
    try testing.expectError(error.BufferTooShort, parse(fbs.buffered()));
}

// Multiple GREASE frames before SETTINGS must all be skipped consistently.
test "H3Frame: multiple sequential GREASE frames all skip" {
    var buf: [32]u8 = undefined;
    var fbs = io.fixedBufferStream(&buf);
    // Three grease frames with varying types and payloads:
    try packet.writeVarInt(&fbs, 0x1f + 0x21); // 0x40
    try packet.writeVarInt(&fbs, 0);
    try packet.writeVarInt(&fbs, 0x1f * 2 + 0x21); // 0x5f
    try packet.writeVarInt(&fbs, 1);
    try fbs.writeByte(0xaa);
    try packet.writeVarInt(&fbs, 0x1f * 3 + 0x21); // 0x7e
    try packet.writeVarInt(&fbs, 0);

    const written = fbs.buffered();
    var offset: usize = 0;
    var count: usize = 0;
    while (offset < written.len) {
        const r = try parse(written[offset..]);
        try testing.expectEqual(H3FrameType.unknown, std.meta.activeTag(r.frame));
        offset += r.consumed;
        count += 1;
    }
    try testing.expectEqual(@as(usize, 3), count);
    try testing.expectEqual(written.len, offset);
}

// Empty input — must not panic.
test "H3Frame: empty input returns BufferTooShort" {
    try testing.expectError(error.BufferTooShort, parse(&[_]u8{}));
}
