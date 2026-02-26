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
    // crypto_header,
    new_token = 0x07,
    stream = 0x08,
    // stream_header,
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
    connection_close = 0x1c, // signal errors at only the QUIC layer, or the absence of errors (with the NO_ERROR code)
    application_close = 0x1d, // signal an error with the application that uses QUIC.
    handshake_done = 0x1e,
    // datagram = 0x30,
    // datagram_header = 0x31, (with length)
    _,
};

pub const Frame = union(FrameType) {
    padding: usize,

    ping: void,
    ack: void,
    ack_ecn: void,

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

    pub fn parse(bytes: []u8) !Frame {
        var stream = io.fixedBufferStream(bytes);
        var reader = stream.reader();

        const frame_type = try packet.readVarInt(reader);
        std.log.info("frame_type: {any}", .{frame_type});

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

            // ack
            // TODO: parse
            0x02...0x03 => .{
                .ack = {},
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

                //
                // TODO: Support coalesced packets
                //
                // Because packets could be reordered on the wire, QUIC
                // uses the packet type to indicate which keys were used to
                // protect a given packet, as shown in Table 1. When packets of
                // different types need to be sent, endpoints SHOULD use
                // coalesced packets to send them in the same UDP datagram
                //

                return .{
                    .crypto = .{
                        .offset = offset,
                        .data = bytes[stream.pos..(stream.pos + offset + length)],
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
            // 0x07 => {
            //     var len = try packet.readVarInt(reader);
            //     std.debug.print("\nlen: {any}\n", .{len});
            //     return .{
            //         .new_token = bytes[stream.pos..(stream.pos + len)],
            //     };
            // },

            // stream frame
            // TODO: parse
            0x08...0x0f => .{ .stream = .{
                .stream_id = 0,
                .data = bytes,
            } },

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

                            //
                            // Values less than 1 and greater than 20 are
                            // invalid and MUST be treated as a connection
                            // error of type FRAME_ENCODING_ERROR
                            //
                            if (conn_id_len < 1 or conn_id_len > 20) {
                                return error.FrameEncodingError;
                            }

                            const conn_id = bytes[stream.pos..(stream.pos + conn_id_len)];
                            try stream.seekBy(conn_id_len);

                            break :blk conn_id;
                        },
                        .stateless_reset_token = try reader.readBytesNoEof(16),
                        // {
                        //     // throw error if check out of bounds
                        //     if (bytes.len < stream.pos + 16) {
                        //         return error.InvalidPacket;
                        //     }
                        //
                        //     return bytes[stream.pos..16];
                        // },
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
            0x1e => .{ .handshake_done = undefined },

            // 0x30 => (self._handle_datagram_frame, EPOCHS("01")),
            // 0x31 => (self._handle_datagram_frame, EPOCHS("01")),

            else => unreachable,
        };
    }

    pub fn isAckEliciting(self: Frame) bool {
        return switch (self) {
            .padding, .ack, .connection_close, .application_close => false,
            else => true,
        };
    }

    pub fn isProbing(self: Frame) bool {
        return switch (self) {
            .padding, .new_connection_id, .path_challenge, .path_response => false,
            else => true,
        };
    }

    // pub fn format(self: @This(), comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
    //     _ = self;
    //     _ = fmt;
    //     _ = options;
    //     _ = writer;
    //     try writer.print("Frame.padding, {}", .{0});
    // }
};

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
        var bytes = [_]u8{0x02};
        switch (try Frame.parse(&bytes)) {
            FrameType.ack => try std.testing.expect(true),
            else => unreachable,
        }
    }
    {
        var bytes = [_]u8{0x03};
        switch (try Frame.parse(&bytes)) {
            FrameType.ack => try std.testing.expect(true),
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
        0x00, 0x00, 0x00, 0x00, // Offset
        0x00, 0x00, 0x00, 0x00, // Data Length
        0x00, 0x00, 0x00, 0x00, // Data
    };
    switch (try Frame.parse(&bytes)) {
        FrameType.crypto => |crypto| {
            try std.testing.expect(crypto.offset == 0);
            try std.testing.expectFmt("{  }", "{any}", .{crypto.data});
            try std.testing.expect(true);
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

test "parse stream frame" {
    {
        var bytes = [_]u8{0x08};
        switch (try Frame.parse(&bytes)) {
            FrameType.stream => try std.testing.expect(true),
            else => unreachable,
        }
    }
    {
        var bytes = [_]u8{0x0f};
        switch (try Frame.parse(&bytes)) {
            FrameType.stream => try std.testing.expect(true),
            else => unreachable,
        }
    }
}

test "parse max_data frame" {
    var bytes = [_]u8{ 0x10, 0x9d, 0x7f, 0x3e, 0x7d }; // 494878333
    switch (try Frame.parse(&bytes)) {
        FrameType.max_data => |max_data| {
            try std.testing.expect(max_data == 494878333);
            try std.testing.expect(true);
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
            try std.testing.expect(true);
        },
        else => unreachable,
    }
}

test "parse max_streams_bidi frame" {
    var bytes = [_]u8{ 0x12, 0x9d, 0x7f, 0x3e, 0x7d }; // 494878333
    switch (try Frame.parse(&bytes)) {
        FrameType.max_streams_bidi => |value| {
            try std.testing.expect(value == 494878333);
            try std.testing.expect(true);
        },
        else => unreachable,
    }
}

test "parse max_streams_uni frame" {
    var bytes = [_]u8{ 0x13, 0x9d, 0x7f, 0x3e, 0x7d }; // 494878333
    switch (try Frame.parse(&bytes)) {
        FrameType.max_streams_uni => |value| {
            try std.testing.expect(value == 494878333);
            try std.testing.expect(true);
        },
        else => unreachable,
    }
}

test "parse data_blocked frame" {
    var bytes = [_]u8{ 0x14, 0x9d, 0x7f, 0x3e, 0x7d }; // 494878333
    switch (try Frame.parse(&bytes)) {
        FrameType.data_blocked => |value| {
            try std.testing.expect(value == 494878333);
            try std.testing.expect(true);
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
            try std.testing.expect(true);
        },
        else => unreachable,
    }
}

test "parse streams_blocked_bidi frame" {
    var bytes = [_]u8{ 0x16, 0x9d, 0x7f, 0x3e, 0x7d }; // 494878333
    switch (try Frame.parse(&bytes)) {
        FrameType.streams_blocked_bidi => |value| {
            try std.testing.expect(value == 494878333);
            try std.testing.expect(true);
        },
        else => unreachable,
    }
}

test "parse streams_blocked_uni frame" {
    var bytes = [_]u8{ 0x17, 0x9d, 0x7f, 0x3e, 0x7d }; // 494878333
    switch (try Frame.parse(&bytes)) {
        FrameType.streams_blocked_uni => |value| {
            try std.testing.expect(value == 494878333);
            try std.testing.expect(true);
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
            try std.testing.expect(true);
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
            try std.testing.expect(true);
        },
        else => unreachable,
    }
}

test "parse path_challenge frame" {
    var bytes = [_]u8{ 0x1a, 1, 2, 3, 4, 5, 6, 7, 8 };
    switch (try Frame.parse(&bytes)) {
        FrameType.path_challenge => |data| {
            try std.testing.expectFmt("{ 1, 2, 3, 4, 5, 6, 7, 8 }", "{any}", .{data});
            try std.testing.expect(true);
        },
        else => unreachable,
    }
}

test "parse path_response frame" {
    var bytes = [_]u8{ 0x1b, 1, 2, 3, 4, 5, 6, 7, 8 };
    switch (try Frame.parse(&bytes)) {
        FrameType.path_response => |data| {
            try std.testing.expectFmt("{ 1, 2, 3, 4, 5, 6, 7, 8 }", "{any}", .{data});
            try std.testing.expect(true);
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
            try std.testing.expect(true);
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
            try std.testing.expect(true);
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
