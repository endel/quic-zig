const std = @import("std");
const io = std.io;

const packet = @import("packet.zig");

pub const FrameError = error{
    FrameEncodingError,
};

pub const FrameType = enum(u64) {
    padding = 0x00,
    ping = 0x01,
    ack = 0x02,
    ack_ecn = 0x03,
    reset_stream = 0x04,
    stop_sending = 0x05,
    crypto = 0x06,
    new_token = 0x07,
    stream = 0x08,
    max_data = 0x10,
    max_stream_data = 0x11,
    max_streams_bidi = 0x12,
    max_streams_uni = 0x13,
    data_blocked = 0x14,
    stream_data_blocked = 0x15,
    streams_blocked_bidi = 0x16,
    streams_blocked_uni = 0x17,
    new_connection_id = 0x18,
    retire_connection_id = 0x19,
    path_challenge = 0x1a,
    path_response = 0x1b,
    connection_close = 0x1c,
    application_close = 0x1d,
    handshake_done = 0x1e,
    datagram = 0x30,
    datagram_with_length = 0x31,
    _,
};

/// ACK range: represents a contiguous range of acknowledged packet numbers.
pub const AckRange = struct {
    /// Smallest packet number in this range.
    start: u64,
    /// Largest packet number in this range.
    end: u64,
};

/// Maximum number of additional ACK ranges stored inline (avoids allocation).
pub const MAX_ACK_RANGES: usize = 32;

pub const Frame = union(FrameType) {
    padding: usize,

    ping: void,

    ack: struct {
        largest_ack: u64,
        ack_delay: u64,
        first_ack_range: u64,
        ack_range_count: u8 = 0,
        ack_ranges: [MAX_ACK_RANGES]AckRange = undefined,
    },

    ack_ecn: struct {
        largest_ack: u64,
        ack_delay: u64,
        first_ack_range: u64,
        ack_range_count: u8 = 0,
        ack_ranges: [MAX_ACK_RANGES]AckRange = undefined,
        ecn_ect0: u64,
        ecn_ect1: u64,
        ecn_ce: u64,
    },

    reset_stream: struct {
        stream_id: u64,
        error_code: u64,
        final_size: u64,
    },

    stop_sending: struct {
        stream_id: u64,
        error_code: u64,
    },

    crypto: struct {
        offset: u64,
        data: []u8,
    },
    new_token: []u8,

    stream: struct {
        stream_id: u64,
        offset: u64,
        length: u64,
        fin: bool,
        data: []u8,
    },

    max_data: u64,

    max_stream_data: struct {
        stream_id: u64,
        max: u64,
    },

    max_streams_bidi: u64,
    max_streams_uni: u64,
    data_blocked: u64,

    stream_data_blocked: struct {
        stream_id: u64,
        limit: u64,
    },

    streams_blocked_bidi: u64,
    streams_blocked_uni: u64,

    new_connection_id: struct {
        seq_num: u64,
        retire_prior_to: u64,
        conn_id: []u8,
        stateless_reset_token: [16]u8,
    },

    retire_connection_id: struct {
        seq_num: u64,
    },

    path_challenge: [8]u8,
    path_response: [8]u8,

    connection_close: struct {
        error_code: u64,
        frame_type: u64,
        reason: []u8,
    },

    application_close: struct {
        error_code: u64,
        reason: []u8,
    },

    handshake_done: void,

    datagram: struct {
        data: []u8,
    },

    datagram_with_length: struct {
        data: []u8,
    },

    /// Parse a single frame from a byte buffer. Returns the frame and advances
    /// the stream position.
    pub fn parse(bytes: []u8) !Frame {
        var stream = io.fixedBufferStream(bytes);
        var reader = stream.reader();

        const frame_type = try packet.readVarInt(reader);

        return switch (frame_type) {
            // padding
            0x00 => .{
                .padding = blk: {
                    var len: usize = 1;

                    while (stream.pos < bytes.len) {
                        if (try reader.readByte() != 0x00) {
                            break;
                        }
                        len += 1;
                    }

                    break :blk len;
                },
            },

            // ping
            0x01 => .{
                .ping = {},
            },

            // ack (0x02) and ack_ecn (0x03)
            0x02, 0x03 => blk: {
                const is_ecn = (frame_type == 0x03);
                const largest_ack = try packet.readVarInt(reader);
                const ack_delay = try packet.readVarInt(reader);
                const ack_range_count = try packet.readVarInt(reader);
                const first_ack_range = try packet.readVarInt(reader);

                // Parse additional ACK ranges, computing absolute PN ranges
                var additional_ranges: [MAX_ACK_RANGES]AckRange = undefined;
                var range_count: u8 = 0;
                var smallest = largest_ack -| first_ack_range;

                var i: u64 = 0;
                while (i < ack_range_count) : (i += 1) {
                    const gap = try packet.readVarInt(reader);
                    const ack_range_len = try packet.readVarInt(reader);
                    if (range_count < MAX_ACK_RANGES) {
                        const range_largest = smallest -| gap -| 2;
                        const range_smallest = range_largest -| ack_range_len;
                        additional_ranges[range_count] = .{ .start = range_smallest, .end = range_largest };
                        range_count += 1;
                        smallest = range_smallest;
                    }
                }

                var ecn_ect0: u64 = 0;
                var ecn_ect1: u64 = 0;
                var ecn_ce: u64 = 0;
                if (is_ecn) {
                    ecn_ect0 = try packet.readVarInt(reader);
                    ecn_ect1 = try packet.readVarInt(reader);
                    ecn_ce = try packet.readVarInt(reader);
                }

                if (is_ecn) {
                    break :blk .{
                        .ack_ecn = .{
                            .largest_ack = largest_ack,
                            .ack_delay = ack_delay,
                            .first_ack_range = first_ack_range,
                            .ack_range_count = range_count,
                            .ack_ranges = additional_ranges,
                            .ecn_ect0 = ecn_ect0,
                            .ecn_ect1 = ecn_ect1,
                            .ecn_ce = ecn_ce,
                        },
                    };
                } else {
                    break :blk .{
                        .ack = .{
                            .largest_ack = largest_ack,
                            .ack_delay = ack_delay,
                            .first_ack_range = first_ack_range,
                            .ack_range_count = range_count,
                            .ack_ranges = additional_ranges,
                        },
                    };
                }
            },

            // reset_stream
            0x04 => .{
                .reset_stream = .{
                    .stream_id = try packet.readVarInt(reader),
                    .error_code = try packet.readVarInt(reader),
                    .final_size = try packet.readVarInt(reader),
                },
            },

            // stop_sending
            0x05 => .{
                .stop_sending = .{
                    .stream_id = try packet.readVarInt(reader),
                    .error_code = try packet.readVarInt(reader),
                },
            },

            // crypto
            0x06 => {
                const offset = try packet.readVarInt(reader);
                const length = try packet.readVarInt(reader);

                return .{
                    .crypto = .{
                        .offset = offset,
                        .data = bytes[stream.pos..(stream.pos + length)],
                    },
                };
            },

            // new token
            0x07 => {
                const len = try packet.readVarInt(reader);
                return .{
                    .new_token = bytes[stream.pos..(stream.pos + len)],
                };
            },

            // stream frame (0x08 - 0x0f)
            0x08...0x0f => blk: {
                const type_byte: u8 = @intCast(frame_type);
                const has_offset = (type_byte & 0x04) != 0;
                const has_length = (type_byte & 0x02) != 0;
                const has_fin = (type_byte & 0x01) != 0;

                const stream_id = try packet.readVarInt(reader);
                const offset: u64 = if (has_offset) try packet.readVarInt(reader) else 0;
                const data_length: u64 = if (has_length)
                    try packet.readVarInt(reader)
                else
                    bytes.len - stream.pos;

                break :blk .{ .stream = .{
                    .stream_id = stream_id,
                    .offset = offset,
                    .length = data_length,
                    .fin = has_fin,
                    .data = bytes[stream.pos..@min(stream.pos + data_length, bytes.len)],
                } };
            },

            // max data
            0x10 => .{
                .max_data = try packet.readVarInt(reader),
            },

            // max stream data
            0x11 => .{
                .max_stream_data = .{
                    .stream_id = try packet.readVarInt(reader),
                    .max = try packet.readVarInt(reader),
                },
            },

            // max streams bidi
            0x12 => .{
                .max_streams_bidi = try packet.readVarInt(reader),
            },

            // max streams uni
            0x13 => .{
                .max_streams_uni = try packet.readVarInt(reader),
            },

            // data blocked
            0x14 => .{
                .data_blocked = try packet.readVarInt(reader),
            },

            // stream data blocked
            0x15 => .{
                .stream_data_blocked = .{
                    .stream_id = try packet.readVarInt(reader),
                    .limit = try packet.readVarInt(reader),
                },
            },

            // streams blocked bidi
            0x16 => .{
                .streams_blocked_bidi = try packet.readVarInt(reader),
            },

            // streams blocked uni
            0x17 => .{
                .streams_blocked_uni = try packet.readVarInt(reader),
            },

            // new connection id
            0x18 => {
                var conn_id_len: u8 = undefined;

                return .{
                    .new_connection_id = .{
                        .seq_num = try packet.readVarInt(reader),
                        .retire_prior_to = try packet.readVarInt(reader),
                        .conn_id = blk: {
                            conn_id_len = try reader.readByte();

                            if (conn_id_len < 1 or conn_id_len > 20) {
                                return error.FrameEncodingError;
                            }

                            const conn_id = bytes[stream.pos..(stream.pos + conn_id_len)];
                            try stream.seekBy(conn_id_len);

                            break :blk conn_id;
                        },
                        .stateless_reset_token = try reader.readBytesNoEof(16),
                    },
                };
            },

            // retire connection id
            0x19 => .{
                .retire_connection_id = .{
                    .seq_num = try packet.readVarInt(reader),
                },
            },

            // path challenge
            0x1a => .{
                .path_challenge = try reader.readBytesNoEof(8),
            },

            // path response
            0x1b => .{
                .path_response = try reader.readBytesNoEof(8),
            },

            // connection close
            0x1c => .{
                .connection_close = .{
                    .error_code = try packet.readVarInt(reader),
                    .frame_type = try packet.readVarInt(reader),
                    .reason = blk: {
                        const len = try packet.readVarInt(reader);
                        break :blk bytes[stream.pos..(stream.pos + len)];
                    },
                },
            },

            // application close
            0x1d => .{
                .application_close = .{
                    .error_code = try packet.readVarInt(reader),
                    .reason = blk: {
                        const len = try packet.readVarInt(reader);
                        break :blk bytes[stream.pos..(stream.pos + len)];
                    },
                },
            },

            // handshake done
            0x1e => .{ .handshake_done = {} },

            // datagram without length (0x30) — data is rest of packet
            0x30 => .{ .datagram = .{
                .data = bytes[stream.pos..],
            } },

            // datagram with length (0x31) — varint length prefix
            0x31 => blk: {
                const length = try packet.readVarInt(reader);
                break :blk .{ .datagram_with_length = .{
                    .data = bytes[stream.pos..@min(stream.pos + length, bytes.len)],
                } };
            },

            else => return error.FrameEncodingError,
        };
    }

    /// Write a frame to the given writer.
    pub fn write(self: Frame, writer: anytype) !void {
        switch (self) {
            .padding => |size| {
                var i: usize = 0;
                while (i < size) : (i += 1) {
                    try writer.writeByte(0x00);
                }
            },

            .ping => {
                try packet.writeVarInt(writer, 0x01);
            },

            .ack => |ack| {
                try packet.writeVarInt(writer, 0x02);
                try packet.writeVarInt(writer, ack.largest_ack);
                try packet.writeVarInt(writer, ack.ack_delay);
                try packet.writeVarInt(writer, @as(u64, ack.ack_range_count));
                try packet.writeVarInt(writer, ack.first_ack_range);

                // Convert absolute ranges back to gap/ack_range wire format
                var prev_smallest = ack.largest_ack -| ack.first_ack_range;
                for (ack.ack_ranges[0..ack.ack_range_count]) |r| {
                    const gap = prev_smallest -| r.end -| 2;
                    const ack_range_len = r.end - r.start;
                    try packet.writeVarInt(writer, gap);
                    try packet.writeVarInt(writer, ack_range_len);
                    prev_smallest = r.start;
                }
            },

            .ack_ecn => |ack| {
                try packet.writeVarInt(writer, 0x03);
                try packet.writeVarInt(writer, ack.largest_ack);
                try packet.writeVarInt(writer, ack.ack_delay);
                try packet.writeVarInt(writer, @as(u64, ack.ack_range_count));
                try packet.writeVarInt(writer, ack.first_ack_range);

                var prev_smallest = ack.largest_ack -| ack.first_ack_range;
                for (ack.ack_ranges[0..ack.ack_range_count]) |r| {
                    const gap = prev_smallest -| r.end -| 2;
                    const ack_range_len = r.end - r.start;
                    try packet.writeVarInt(writer, gap);
                    try packet.writeVarInt(writer, ack_range_len);
                    prev_smallest = r.start;
                }

                try packet.writeVarInt(writer, ack.ecn_ect0);
                try packet.writeVarInt(writer, ack.ecn_ect1);
                try packet.writeVarInt(writer, ack.ecn_ce);
            },

            .reset_stream => |rs| {
                try packet.writeVarInt(writer, 0x04);
                try packet.writeVarInt(writer, rs.stream_id);
                try packet.writeVarInt(writer, rs.error_code);
                try packet.writeVarInt(writer, rs.final_size);
            },

            .stop_sending => |ss| {
                try packet.writeVarInt(writer, 0x05);
                try packet.writeVarInt(writer, ss.stream_id);
                try packet.writeVarInt(writer, ss.error_code);
            },

            .crypto => |c| {
                try packet.writeVarInt(writer, 0x06);
                try packet.writeVarInt(writer, c.offset);
                try packet.writeVarInt(writer, c.data.len);
                try writer.writeAll(c.data);
            },

            .new_token => |token| {
                try packet.writeVarInt(writer, 0x07);
                try packet.writeVarInt(writer, token.len);
                try writer.writeAll(token);
            },

            .stream => |s| {
                var type_byte: u8 = 0x08;
                if (s.offset > 0) type_byte |= 0x04;
                if (s.length > 0) type_byte |= 0x02;
                if (s.fin) type_byte |= 0x01;

                try packet.writeVarInt(writer, type_byte);
                try packet.writeVarInt(writer, s.stream_id);
                if (s.offset > 0) try packet.writeVarInt(writer, s.offset);
                if (s.length > 0) try packet.writeVarInt(writer, s.length);
                try writer.writeAll(s.data);
            },

            .max_data => |max| {
                try packet.writeVarInt(writer, 0x10);
                try packet.writeVarInt(writer, max);
            },

            .max_stream_data => |msd| {
                try packet.writeVarInt(writer, 0x11);
                try packet.writeVarInt(writer, msd.stream_id);
                try packet.writeVarInt(writer, msd.max);
            },

            .max_streams_bidi => |max| {
                try packet.writeVarInt(writer, 0x12);
                try packet.writeVarInt(writer, max);
            },

            .max_streams_uni => |max| {
                try packet.writeVarInt(writer, 0x13);
                try packet.writeVarInt(writer, max);
            },

            .data_blocked => |limit| {
                try packet.writeVarInt(writer, 0x14);
                try packet.writeVarInt(writer, limit);
            },

            .stream_data_blocked => |sdb| {
                try packet.writeVarInt(writer, 0x15);
                try packet.writeVarInt(writer, sdb.stream_id);
                try packet.writeVarInt(writer, sdb.limit);
            },

            .streams_blocked_bidi => |max| {
                try packet.writeVarInt(writer, 0x16);
                try packet.writeVarInt(writer, max);
            },

            .streams_blocked_uni => |max| {
                try packet.writeVarInt(writer, 0x17);
                try packet.writeVarInt(writer, max);
            },

            .new_connection_id => |ncid| {
                try packet.writeVarInt(writer, 0x18);
                try packet.writeVarInt(writer, ncid.seq_num);
                try packet.writeVarInt(writer, ncid.retire_prior_to);
                try writer.writeByte(@intCast(ncid.conn_id.len));
                try writer.writeAll(ncid.conn_id);
                try writer.writeAll(&ncid.stateless_reset_token);
            },

            .retire_connection_id => |rcid| {
                try packet.writeVarInt(writer, 0x19);
                try packet.writeVarInt(writer, rcid.seq_num);
            },

            .path_challenge => |data| {
                try packet.writeVarInt(writer, 0x1a);
                try writer.writeAll(&data);
            },

            .path_response => |data| {
                try packet.writeVarInt(writer, 0x1b);
                try writer.writeAll(&data);
            },

            .connection_close => |cc| {
                try packet.writeVarInt(writer, 0x1c);
                try packet.writeVarInt(writer, cc.error_code);
                try packet.writeVarInt(writer, cc.frame_type);
                try packet.writeVarInt(writer, cc.reason.len);
                try writer.writeAll(cc.reason);
            },

            .application_close => |ac| {
                try packet.writeVarInt(writer, 0x1d);
                try packet.writeVarInt(writer, ac.error_code);
                try packet.writeVarInt(writer, ac.reason.len);
                try writer.writeAll(ac.reason);
            },

            .handshake_done => {
                try packet.writeVarInt(writer, 0x1e);
            },

            .datagram => |d| {
                try packet.writeVarInt(writer, 0x30);
                try writer.writeAll(d.data);
            },

            .datagram_with_length => |d| {
                try packet.writeVarInt(writer, 0x31);
                try packet.writeVarInt(writer, d.data.len);
                try writer.writeAll(d.data);
            },
        }
    }

    pub fn isAckEliciting(self: Frame) bool {
        return switch (self) {
            .padding, .ack, .ack_ecn, .connection_close, .application_close => false,
            .datagram, .datagram_with_length => true,
            else => true,
        };
    }

    pub fn isProbing(self: Frame) bool {
        return switch (self) {
            .padding, .new_connection_id, .path_challenge, .path_response => true,
            else => false,
        };
    }
};

/// Parse multiple frames from a payload buffer. Calls handler for each frame.
pub fn parseFrames(bytes: []u8, comptime handler: fn (Frame) anyerror!void) !void {
    var stream = io.fixedBufferStream(bytes);
    const reader = stream.reader();

    while (stream.pos < bytes.len) {
        const frame_type = try packet.readVarInt(reader);

        // Skip padding bytes efficiently
        if (frame_type == 0x00) {
            while (stream.pos < bytes.len) {
                if (try reader.readByte() != 0x00) {
                    stream.pos -= 1;
                    break;
                }
            }
            continue;
        }

        // For other frame types, rewind and parse the full frame
        // (We already consumed the type byte, so we need to reconstruct)
        // Instead, parse from the remaining bytes including type
        const frame_start = stream.pos - packet.varIntLength(frame_type);
        const frame = try Frame.parse(bytes[frame_start..]);
        try handler(frame);

        // Advance past this frame's data
        // TODO: track exact frame size for accurate advancement
    }
}

/// A pending control frame to be sent in the next outgoing packet.
/// Uses value types only (no slices) to avoid dangling references.
pub const PendingControlFrame = union(enum) {
    ping: void,
    path_challenge: [8]u8,
    path_response: [8]u8,
    retire_connection_id: u64,
    connection_close: struct {
        error_code: u64,
        frame_type: u64,
        is_app: bool,
    },
    max_data: u64,
    max_stream_data: struct {
        stream_id: u64,
        max: u64,
    },

    /// Convert to a Frame for writing on the wire.
    pub fn toFrame(self: PendingControlFrame) Frame {
        return switch (self) {
            .ping => .{ .ping = {} },
            .path_challenge => |data| .{ .path_challenge = data },
            .path_response => |data| .{ .path_response = data },
            .retire_connection_id => |seq| .{ .retire_connection_id = .{ .seq_num = seq } },
            .connection_close => |cc| if (cc.is_app)
                .{ .application_close = .{ .error_code = cc.error_code, .reason = &.{} } }
            else
                .{ .connection_close = .{ .error_code = cc.error_code, .frame_type = cc.frame_type, .reason = &.{} } },
            .max_data => |max| .{ .max_data = max },
            .max_stream_data => |msd| .{ .max_stream_data = .{ .stream_id = msd.stream_id, .max = msd.max } },
        };
    }
};

/// Fixed-capacity queue for pending control frames.
pub const PendingFrameQueue = struct {
    items: [16]PendingControlFrame = undefined,
    len: u8 = 0,

    pub fn push(self: *PendingFrameQueue, frame: PendingControlFrame) void {
        if (self.len < 16) {
            self.items[self.len] = frame;
            self.len += 1;
        }
    }

    pub fn pop(self: *PendingFrameQueue) ?PendingControlFrame {
        if (self.len == 0) return null;
        const item = self.items[0];
        self.len -= 1;
        // Shift remaining items
        var i: u8 = 0;
        while (i < self.len) : (i += 1) {
            self.items[i] = self.items[i + 1];
        }
        return item;
    }
};

// Tests

test "parse padding frame" {
    {
        var bytes = [_]u8{0x00};
        switch (try Frame.parse(&bytes)) {
            FrameType.padding => |padding| try std.testing.expect(1 == padding),
            else => unreachable,
        }
    }
    {
        var bytes = [_]u8{ 0x00, 0x00, 0x01 };
        switch (try Frame.parse(&bytes)) {
            FrameType.padding => |padding| try std.testing.expect(2 == padding),
            else => unreachable,
        }
    }
    {
        var bytes = [_]u8{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 };
        switch (try Frame.parse(&bytes)) {
            FrameType.padding => |padding| try std.testing.expect(10 == padding),
            else => unreachable,
        }
    }
}

test "parse ping frame" {
    var bytes = [_]u8{ 0x01, 0x00 };
    switch (try Frame.parse(&bytes)) {
        FrameType.ping => try std.testing.expect(true),
        else => unreachable,
    }
}

test "parse ack frame" {
    {
        // ACK frame: largest=10, delay=5, range_count=0, first_range=3
        var bytes = [_]u8{ 0x02, 0x0a, 0x05, 0x00, 0x03 };
        switch (try Frame.parse(&bytes)) {
            FrameType.ack => |ack| {
                try std.testing.expectEqual(@as(u64, 10), ack.largest_ack);
                try std.testing.expectEqual(@as(u64, 5), ack.ack_delay);
                try std.testing.expectEqual(@as(u64, 3), ack.first_ack_range);
            },
            else => unreachable,
        }
    }
    {
        // ACK-ECN frame
        var bytes = [_]u8{ 0x03, 0x0a, 0x05, 0x00, 0x03, 0x01, 0x02, 0x03 };
        switch (try Frame.parse(&bytes)) {
            FrameType.ack_ecn => |ack| {
                try std.testing.expectEqual(@as(u64, 10), ack.largest_ack);
                try std.testing.expectEqual(@as(u64, 1), ack.ecn_ect0);
                try std.testing.expectEqual(@as(u64, 2), ack.ecn_ect1);
                try std.testing.expectEqual(@as(u64, 3), ack.ecn_ce);
            },
            else => unreachable,
        }
    }
}

test "parse reset_stream frame" {
    var bytes = [_]u8{
        0x04,
        0x00, 0x00, 0x00, 0x00, // Stream ID
        0x00, 0x00, 0x00, 0x00, // Application Protocol Error Code
        0x00, 0x00, 0x00, 0x00, // Final Size
    };
    switch (try Frame.parse(&bytes)) {
        FrameType.reset_stream => try std.testing.expect(true),
        else => unreachable,
    }
}

test "parse stop_sending frame" {
    var bytes = [_]u8{
        0x05,
        0x00, 0x00, 0x00, 0x00, // Stream ID
        0x00, 0x00, 0x00, 0x00, // Error Code
    };
    switch (try Frame.parse(&bytes)) {
        FrameType.stop_sending => try std.testing.expect(true),
        else => unreachable,
    }
}

test "parse crypto frame" {
    var bytes = [_]u8{
        0x06,
        0x00, // Offset: 0
        0x04, // Data Length: 4
        0xde, 0xad, 0xbe, 0xef, // Data
    };
    switch (try Frame.parse(&bytes)) {
        FrameType.crypto => |crypto| {
            try std.testing.expectEqual(@as(u64, 0), crypto.offset);
            try std.testing.expectEqualSlices(u8, &[_]u8{ 0xde, 0xad, 0xbe, 0xef }, crypto.data);
        },
        else => unreachable,
    }
}

test "parse new_token frame" {
    var bytes = [_]u8{
        0x07,
        16, // size
        97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, // "abcdefghijklmnop"
    };
    switch (try Frame.parse(&bytes)) {
        FrameType.new_token => |frame| {
            try std.testing.expectEqualStrings("abcdefghijklmnop", frame);
            try std.testing.expect(true);
        },
        else => unreachable,
    }
}

test "parse stream frame with all flags" {
    // Stream frame type 0x0f = FIN + LEN + OFF
    var bytes = [_]u8{
        0x0f,
        0x04, // stream id: 4
        0x0a, // offset: 10
        0x03, // length: 3
        0x41, 0x42, 0x43, // data: "ABC"
    };
    switch (try Frame.parse(&bytes)) {
        FrameType.stream => |s| {
            try std.testing.expectEqual(@as(u64, 4), s.stream_id);
            try std.testing.expectEqual(@as(u64, 10), s.offset);
            try std.testing.expectEqual(@as(u64, 3), s.length);
            try std.testing.expect(s.fin);
            try std.testing.expectEqualSlices(u8, &[_]u8{ 0x41, 0x42, 0x43 }, s.data);
        },
        else => unreachable,
    }
}

test "parse stream frame minimal (no offset, no length, no fin)" {
    // Stream frame type 0x08 = no flags
    var bytes = [_]u8{
        0x08,
        0x00, // stream id: 0
        0xAA, 0xBB, // remaining data (no length field, so all remaining)
    };
    switch (try Frame.parse(&bytes)) {
        FrameType.stream => |s| {
            try std.testing.expectEqual(@as(u64, 0), s.stream_id);
            try std.testing.expectEqual(@as(u64, 0), s.offset);
            try std.testing.expect(!s.fin);
            try std.testing.expectEqualSlices(u8, &[_]u8{ 0xAA, 0xBB }, s.data);
        },
        else => unreachable,
    }
}

test "parse max_data frame" {
    var bytes = [_]u8{ 0x10, 0x9d, 0x7f, 0x3e, 0x7d }; // 494878333
    switch (try Frame.parse(&bytes)) {
        FrameType.max_data => |max_data| {
            try std.testing.expect(max_data == 494878333);
        },
        else => unreachable,
    }
}

test "parse max_stream_data frame" {
    var bytes = [_]u8{
        0x11,
        0x00, // stream id: 0
        0x7b, 0xbd, // max: 15293
    };
    switch (try Frame.parse(&bytes)) {
        FrameType.max_stream_data => |max_stream_data| {
            try std.testing.expect(max_stream_data.stream_id == 0);
            try std.testing.expect(max_stream_data.max == 15293);
        },
        else => unreachable,
    }
}

test "parse max_streams_bidi frame" {
    var bytes = [_]u8{ 0x12, 0x9d, 0x7f, 0x3e, 0x7d }; // 494878333
    switch (try Frame.parse(&bytes)) {
        FrameType.max_streams_bidi => |value| {
            try std.testing.expect(value == 494878333);
        },
        else => unreachable,
    }
}

test "parse max_streams_uni frame" {
    var bytes = [_]u8{ 0x13, 0x9d, 0x7f, 0x3e, 0x7d }; // 494878333
    switch (try Frame.parse(&bytes)) {
        FrameType.max_streams_uni => |value| {
            try std.testing.expect(value == 494878333);
        },
        else => unreachable,
    }
}

test "parse data_blocked frame" {
    var bytes = [_]u8{ 0x14, 0x9d, 0x7f, 0x3e, 0x7d }; // 494878333
    switch (try Frame.parse(&bytes)) {
        FrameType.data_blocked => |value| {
            try std.testing.expect(value == 494878333);
        },
        else => unreachable,
    }
}

test "parse stream_data_blocked frame" {
    var bytes = [_]u8{
        0x15,
        0x00, // stream id: 0
        0x7b, 0xbd, // limit: 15293
    };
    switch (try Frame.parse(&bytes)) {
        FrameType.stream_data_blocked => |stream_data_blocked| {
            try std.testing.expect(stream_data_blocked.stream_id == 0);
            try std.testing.expect(stream_data_blocked.limit == 15293);
        },
        else => unreachable,
    }
}

test "parse streams_blocked_bidi frame" {
    var bytes = [_]u8{ 0x16, 0x9d, 0x7f, 0x3e, 0x7d }; // 494878333
    switch (try Frame.parse(&bytes)) {
        FrameType.streams_blocked_bidi => |value| {
            try std.testing.expect(value == 494878333);
        },
        else => unreachable,
    }
}

test "parse streams_blocked_uni frame" {
    var bytes = [_]u8{ 0x17, 0x9d, 0x7f, 0x3e, 0x7d }; // 494878333
    switch (try Frame.parse(&bytes)) {
        FrameType.streams_blocked_uni => |value| {
            try std.testing.expect(value == 494878333);
        },
        else => unreachable,
    }
}

test "parse new_connection_id frame" {
    var bytes = [_]u8{
        0x18, // Type
        0x00, // Sequence Number: 0
        0x01, // Retire Prior To: 0
        0x02, // Length (8)
        0x00, 0x01, // Connection ID (8..160)
        97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, // Stateless Reset Token
    };

    switch (try Frame.parse(&bytes)) {
        FrameType.new_connection_id => |new_connection_id| {
            try std.testing.expect(new_connection_id.seq_num == 0);
            try std.testing.expect(new_connection_id.retire_prior_to == 1);
            try std.testing.expectFmt("{ 0, 1 }", "{any}", .{new_connection_id.conn_id});
            try std.testing.expectEqualStrings("abcdefghijklmnop", &new_connection_id.stateless_reset_token);
        },
        else => unreachable,
    }
}

test "parse retire_connection_id frame" {
    var bytes = [_]u8{
        0x19, // Type
        0x02, // Sequence Number: 0
    };
    switch (try Frame.parse(&bytes)) {
        FrameType.retire_connection_id => |retire_connection_id| {
            try std.testing.expect(retire_connection_id.seq_num == 2);
        },
        else => unreachable,
    }
}

test "parse path_challenge frame" {
    var bytes = [_]u8{ 0x1a, 1, 2, 3, 4, 5, 6, 7, 8 };
    switch (try Frame.parse(&bytes)) {
        FrameType.path_challenge => |data| {
            try std.testing.expectFmt("{ 1, 2, 3, 4, 5, 6, 7, 8 }", "{any}", .{data});
        },
        else => unreachable,
    }
}

test "parse path_response frame" {
    var bytes = [_]u8{ 0x1b, 1, 2, 3, 4, 5, 6, 7, 8 };
    switch (try Frame.parse(&bytes)) {
        FrameType.path_response => |data| {
            try std.testing.expectFmt("{ 1, 2, 3, 4, 5, 6, 7, 8 }", "{any}", .{data});
        },
        else => unreachable,
    }
}

test "parse connection_close frame" {
    var bytes = [_]u8{ 0x1c, 0x10, @intFromEnum(FrameType.max_data), 16, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112 };

    switch (try Frame.parse(&bytes)) {
        FrameType.connection_close => |connection_close| {
            try std.testing.expect(connection_close.error_code == 0x10);
            try std.testing.expect(connection_close.frame_type == @intFromEnum(FrameType.max_data));
            try std.testing.expectEqualStrings("abcdefghijklmnop", connection_close.reason);
        },
        else => unreachable,
    }
}

test "parse application_close frame" {
    var bytes = [_]u8{ 0x1d, 0x10, 16, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112 };

    switch (try Frame.parse(&bytes)) {
        FrameType.application_close => |connection_close| {
            try std.testing.expect(connection_close.error_code == 0x10);
            try std.testing.expectEqualStrings("abcdefghijklmnop", connection_close.reason);
        },
        else => unreachable,
    }
}

test "parse handshake_done frame" {
    var bytes = [_]u8{0x1e};
    switch (try Frame.parse(&bytes)) {
        FrameType.handshake_done => try std.testing.expect(true),
        else => unreachable,
    }
}

test "write and parse ping frame roundtrip" {
    var buf: [64]u8 = undefined;
    var fbs = io.fixedBufferStream(&buf);
    const frame = Frame{ .ping = {} };
    try frame.write(fbs.writer());
    const written = fbs.getWritten();
    var written_mut: [64]u8 = undefined;
    @memcpy(written_mut[0..written.len], written);
    const parsed = try Frame.parse(written_mut[0..written.len]);
    try std.testing.expectEqual(FrameType.ping, parsed);
}

test "write and parse max_data frame roundtrip" {
    var buf: [64]u8 = undefined;
    var fbs = io.fixedBufferStream(&buf);
    const frame = Frame{ .max_data = 999999 };
    try frame.write(fbs.writer());
    const written = fbs.getWritten();
    var written_mut: [64]u8 = undefined;
    @memcpy(written_mut[0..written.len], written);
    const parsed = try Frame.parse(written_mut[0..written.len]);
    switch (parsed) {
        .max_data => |val| try std.testing.expectEqual(@as(u64, 999999), val),
        else => unreachable,
    }
}
