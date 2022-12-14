const std = @import("std");
const io = std.io;

const packet = @import("packet.zig");

pub const FrameType = enum {
    padding,
    ping,
    ack,
    reset_stream,
    stop_sending,
    crypto,
    // crypto_header,
    new_token,
    stream,
    // stream_header,
    max_data,
    max_stream_data,
    max_streams_bidi,
    max_streams_uni,
    data_blocked,
    stream_data_blocked,
    streams_blocked_bidi,
    streams_blocked_uni,
    new_connection_id,
    retire_connection_id,
    path_challenge,
    path_response,
    connection_close,
    // application_close,
    handshake_done,
    // datagram,
    // datagram_header,
};

pub const NotImplementedFrame = struct {};

pub const Frame = union(FrameType) {
    padding: usize,

    ping: void,
    ack: NotImplementedFrame,

    reset_stream: struct {
        stream_id: u64,
        error_code: u64,
        final_size: u64,
    },

    stop_sending: struct {
        stream_id: u64,
        error_code: u64,
    },

    crypto: []u8,
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
        reset_token: [16]u8,
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
                .ack = .{},
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
            0x06 => .{
                .crypto = bytes[stream.pos..try packet.readVarInt(reader)],
            },

            // new token
            0x07 => .{
                .new_token = bytes[0..(try packet.readVarInt(reader))],
            },

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

                            var conn_id = bytes[0..conn_id_len];
                            try stream.seekBy(conn_id_len);

                            break :blk conn_id;
                        },
                        .reset_token = try reader.readBytesNoEof(16),
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
                    .reason = bytes[stream.pos..(try packet.readVarInt(reader))],
                },
            },

            0x1e => .{ .handshake_done = undefined },

            // 0x1c => (self._handle_connection_close_frame, EPOCHS("IH01")),
            // 0x1d => (self._handle_connection_close_frame, EPOCHS("01")),
            // 0x30 => (self._handle_datagram_frame, EPOCHS("01")),
            // 0x31 => (self._handle_datagram_frame, EPOCHS("01")),

            else => unreachable,
        };
    }
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

// test "parse ack frame" {}
//
// test "parse reset_stream frame" {}
//
// test "parse stop_sending frame" {}
//
// test "parse crypto frame" {}
//
// test "parse new_token frame" {}
//
// test "parse stream frame" {}
//
// test "parse max_data frame" {}
//
// test "parse max_stream_data frame" {}
//
// test "parse max_streams_bidi frame" {}
//
// test "parse max_streams_uni frame" {}
//
// test "parse data_blocked frame" {}
//
// test "parse stream_data_blocked frame" {}
//
// test "parse streams_blocked_bidi frame" {}
//
// test "parse streams_blocked_uni frame" {}
//
// test "parse new_connection_id frame" {}
//
// test "parse retire_connection_id frame" {}
//
// test "parse path_challenge frame" {}
//
// test "parse path_response frame" {}
//
// test "parse connection_close frame" {}
//
// test "parse handshake_done frame" {}
//
