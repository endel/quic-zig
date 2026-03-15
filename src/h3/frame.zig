const std = @import("std");
const testing = std.testing;
const io = std.io;
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
    enable_webtransport = 0x2b603742,
    webtransport_max_sessions = 0xc671706a,

    pub fn fromInt(v: u64) ?SettingsId {
        return switch (v) {
            0x01 => .qpack_max_table_capacity,
            0x06 => .max_field_section_size,
            0x07 => .qpack_blocked_streams,
            0x08 => .enable_connect_protocol,
            0x33 => .h3_datagram,
            0x2b603742 => .enable_webtransport,
            0xc671706a => .webtransport_max_sessions,
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

/// Parse one HTTP/3 frame from a byte buffer.
/// Returns the parsed frame and the number of bytes consumed.
pub fn parse(data: []const u8) !struct { frame: H3Frame, consumed: usize } {
    if (data.len == 0) return error.BufferTooShort;

    var fbs = io.fixedBufferStream(data);
    const reader = fbs.reader();

    // Type (varint)
    const frame_type_raw = packet.readVarInt(reader) catch return error.BufferTooShort;

    // Reject reserved HTTP/2 frame types
    if (isReservedH2FrameType(frame_type_raw)) {
        return error.H3FrameUnexpected;
    }

    // Length (varint)
    const length = packet.readVarInt(reader) catch return error.BufferTooShort;

    const header_size = fbs.pos;
    const total_size = header_size + length;

    if (data.len < total_size) return error.BufferTooShort;

    const payload = data[header_size..total_size];

    const frame_type = H3FrameType.fromInt(frame_type_raw) orelse {
        // Unknown frame types MUST be ignored (RFC 9114 Section 7.2.8)
        return .{
            .frame = .{ .data = &.{} }, // placeholder
            .consumed = total_size,
        };
    };

    const frame: H3Frame = switch (frame_type) {
        .data => .{ .data = payload },
        .headers => .{ .headers = payload },
        .settings => blk: {
            var settings = Settings{};
            var sfbs = io.fixedBufferStream(payload);
            const sreader = sfbs.reader();

            while (sfbs.pos < payload.len) {
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
                        .enable_webtransport => settings.enable_webtransport = (value != 0),
                        .webtransport_max_sessions => settings.webtransport_max_sessions = value,
                    }
                }
                // Unknown settings are ignored (RFC 9114 Section 7.2.4.1)
            }
            break :blk .{ .settings = settings };
        },
        .goaway => blk: {
            var gfbs = io.fixedBufferStream(payload);
            const greader = gfbs.reader();
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
            const creader = cfbs.reader();
            const id = packet.readVarInt(creader) catch return error.MalformedFrame;
            break :blk .{ .cancel_push = id };
        },
        .max_push_id => blk: {
            var mfbs = io.fixedBufferStream(payload);
            const mreader = mfbs.reader();
            const id = packet.readVarInt(mreader) catch return error.MalformedFrame;
            break :blk .{ .max_push_id = id };
        },
        .push_promise => .{ .push_promise = {} },
        .priority_update => blk: {
            var pfbs = io.fixedBufferStream(payload);
            const preader = pfbs.reader();
            const prioritized_id = packet.readVarInt(preader) catch return error.MalformedFrame;
            const fv_start = pfbs.pos;
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
            const sw = sfbs.writer();

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
            }

            if (s.webtransport_max_sessions) |max_sessions| {
                try packet.writeVarInt(sw, @intFromEnum(SettingsId.webtransport_max_sessions));
                try packet.writeVarInt(sw, max_sessions);
            }

            const settings_payload = sfbs.getWritten();
            try packet.writeVarInt(writer, 0x04);
            try packet.writeVarInt(writer, settings_payload.len);
            try writer.writeAll(settings_payload);
        },
        .goaway => |id| {
            // Serialize id to get its varint length
            var buf: [8]u8 = undefined;
            var gfbs = io.fixedBufferStream(&buf);
            try packet.writeVarInt(gfbs.writer(), id);
            const payload_len = gfbs.pos;

            try packet.writeVarInt(writer, 0x07);
            try packet.writeVarInt(writer, payload_len);
            try packet.writeVarInt(writer, id);
        },
        .cancel_push => |id| {
            var buf: [8]u8 = undefined;
            var cfbs = io.fixedBufferStream(&buf);
            try packet.writeVarInt(cfbs.writer(), id);
            const payload_len = cfbs.pos;

            try packet.writeVarInt(writer, 0x03);
            try packet.writeVarInt(writer, payload_len);
            try packet.writeVarInt(writer, id);
        },
        .max_push_id => |id| {
            var buf: [8]u8 = undefined;
            var mfbs = io.fixedBufferStream(&buf);
            try packet.writeVarInt(mfbs.writer(), id);
            const payload_len = mfbs.pos;

            try packet.writeVarInt(writer, 0x0d);
            try packet.writeVarInt(writer, payload_len);
            try packet.writeVarInt(writer, id);
        },
        .push_promise => {},
        .priority_update => |pu| {
            // Compute payload length: varint(stream_id) + field_value bytes
            var id_buf: [8]u8 = undefined;
            var id_fbs = io.fixedBufferStream(&id_buf);
            try packet.writeVarInt(id_fbs.writer(), pu.stream_id);
            const payload_len = id_fbs.pos + pu.field_value.len;

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
    }
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

/// Read a raw uni stream type varint without mapping to enum.
/// Used by WebTransport to identify WT-specific stream types (0x41, 0x54).
pub fn readUniStreamTypeRaw(reader: anytype) !u64 {
    return try packet.readVarInt(reader);
}

// Tests

test "H3Frame: write and parse DATA" {
    var buf: [256]u8 = undefined;
    var fbs = io.fixedBufferStream(&buf);

    const payload = "hello world";
    try write(.{ .data = payload }, fbs.writer());

    const written = fbs.getWritten();
    const result = try parse(written);

    try testing.expectEqual(H3FrameType.data, std.meta.activeTag(result.frame));
    try testing.expectEqualStrings(payload, result.frame.data);
    try testing.expectEqual(written.len, result.consumed);
}

test "H3Frame: write and parse HEADERS" {
    var buf: [256]u8 = undefined;
    var fbs = io.fixedBufferStream(&buf);

    const headers_data = &[_]u8{ 0x00, 0x00, 0xc0 | 17 }; // prefix + indexed :method GET
    try write(.{ .headers = headers_data }, fbs.writer());

    const written = fbs.getWritten();
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
    try write(.{ .settings = settings }, fbs.writer());

    const written = fbs.getWritten();
    const result = try parse(written);

    try testing.expectEqual(H3FrameType.settings, std.meta.activeTag(result.frame));
    try testing.expectEqual(@as(u64, 0), result.frame.settings.qpack_max_table_capacity);
    try testing.expectEqual(@as(u64, 0), result.frame.settings.qpack_blocked_streams);
    try testing.expectEqual(@as(u64, 4096), result.frame.settings.max_field_section_size.?);
}

test "H3Frame: write and parse GOAWAY" {
    var buf: [256]u8 = undefined;
    var fbs = io.fixedBufferStream(&buf);

    try write(.{ .goaway = 42 }, fbs.writer());

    const written = fbs.getWritten();
    const result = try parse(written);

    try testing.expectEqual(H3FrameType.goaway, std.meta.activeTag(result.frame));
    try testing.expectEqual(@as(u64, 42), result.frame.goaway);
}

test "H3Frame: reject reserved HTTP/2 frame types" {
    // Frame type 0x02 (PRIORITY in HTTP/2) is reserved
    var buf: [16]u8 = undefined;
    var fbs = io.fixedBufferStream(&buf);
    try packet.writeVarInt(fbs.writer(), 0x02); // type
    try packet.writeVarInt(fbs.writer(), 0); // length

    const result = parse(fbs.getWritten());
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
    try packet.writeVarInt(fbs.writer(), 0x00); // DATA
    try packet.writeVarInt(fbs.writer(), 100); // length = 100

    const result = parse(fbs.getWritten());
    try testing.expectError(error.BufferTooShort, result);
}

test "H3Frame: empty SETTINGS" {
    var buf: [16]u8 = undefined;
    var fbs = io.fixedBufferStream(&buf);
    try packet.writeVarInt(fbs.writer(), 0x04); // SETTINGS
    try packet.writeVarInt(fbs.writer(), 0); // length = 0

    const result = try parse(fbs.getWritten());
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
    try write(.{ .settings = settings }, fbs.writer());

    const written = fbs.getWritten();
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
    } }, fbs.writer());

    const written = fbs.getWritten();
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
    } }, fbs.writer());

    const written = fbs.getWritten();
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
    } }, fbs.writer());

    const written = fbs.getWritten();
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
    } }, fbs.writer());

    const written = fbs.getWritten();
    const result = try parse(written);

    try testing.expectEqual(H3FrameType.close_webtransport_session, std.meta.activeTag(result.frame));
    try testing.expectEqual(@as(u32, 0), result.frame.close_webtransport_session.error_code);
    try testing.expectEqualStrings("", result.frame.close_webtransport_session.reason);
}

test "UniStreamType: write and read" {
    var buf: [8]u8 = undefined;
    var fbs = io.fixedBufferStream(&buf);
    try writeUniStreamType(fbs.writer(), .control);

    var rfbs = io.fixedBufferStream(fbs.getWritten());
    const st = try readUniStreamType(rfbs.reader());
    try testing.expectEqual(UniStreamType.control, st);
}
