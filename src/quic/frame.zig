const std = @import("std");
const io = std.io;

const packet = @import("packet.zig");

pub const FrameType = enum(u64) {
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
    padding: struct { len: usize },

    ping: NotImplementedFrame,
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

    crypto: struct {
        data: []u8,
    },

    new_token: NotImplementedFrame,
    stream: NotImplementedFrame,
    max_data: NotImplementedFrame,
    max_stream_data: NotImplementedFrame,
    max_streams_bidi: NotImplementedFrame,
    max_streams_uni: NotImplementedFrame,
    data_blocked: NotImplementedFrame,
    stream_data_blocked: NotImplementedFrame,
    streams_blocked_bidi: NotImplementedFrame,
    streams_blocked_uni: NotImplementedFrame,
    new_connection_id: NotImplementedFrame,
    retire_connection_id: NotImplementedFrame,
    path_challenge: NotImplementedFrame,
    path_response: NotImplementedFrame,
    connection_close: NotImplementedFrame,
    handshake_done: NotImplementedFrame,

    pub fn parse(bytes: []u8) !Frame {
        var stream = io.fixedBufferStream(bytes);
        var reader = stream.reader();

        const frame_type = try packet.readVarInt(reader);
        std.log.info("frame_type: {any}", .{frame_type});

        return switch (frame_type) {
            // padding
            0x00 => {
                var len: usize = 1;

                while (stream.pos < bytes.len) {
                    if (try reader.readByte() != 0x00) {
                        break;
                    }
                    len += 1;
                }

                return .{ .padding = .{ .len = len } };
            },

            // ping
            0x01 => .{ .ping = .{} },

            // ack
            // TODO: parse ack frame
            0x02...0x03 => .{ .ack = .{} },

            // Reset stream
            0x04 => .{ .reset_stream = .{
                .stream_id = try packet.readVarInt(reader),
                .error_code = try packet.readVarInt(reader),
                .final_size = try packet.readVarInt(reader),
            } },

            // Stop Sending
            0x05 => .{ .stop_sending = .{
                .stream_id = try packet.readVarInt(reader),
                .error_code = try packet.readVarInt(reader),
            } },

            0x06 => {
                const offset = try packet.readVarInt(reader);
                return .{ .crypto = .{ .data = bytes[stream.pos..offset] } };
            },

            // 0x07 => (self._handle_new_token_frame, EPOCHS("1")),
            // 0x08 => (self._handle_stream_frame, EPOCHS("01")),
            // 0x09 => (self._handle_stream_frame, EPOCHS("01")),
            // 0x0a => (self._handle_stream_frame, EPOCHS("01")),
            // 0x0b => (self._handle_stream_frame, EPOCHS("01")),
            // 0x0c => (self._handle_stream_frame, EPOCHS("01")),
            // 0x0d => (self._handle_stream_frame, EPOCHS("01")),
            // 0x0e => (self._handle_stream_frame, EPOCHS("01")),
            // 0x0f => (self._handle_stream_frame, EPOCHS("01")),
            // 0x10 => (self._handle_max_data_frame, EPOCHS("01")),
            // 0x11 => (self._handle_max_stream_data_frame, EPOCHS("01")),
            // 0x12 => (self._handle_max_streams_bidi_frame, EPOCHS("01")),
            // 0x13 => (self._handle_max_streams_uni_frame, EPOCHS("01")),
            // 0x14 => (self._handle_data_blocked_frame, EPOCHS("01")),
            // 0x15 => (self._handle_stream_data_blocked_frame, EPOCHS("01")),
            // 0x16 => (self._handle_streams_blocked_frame, EPOCHS("01")),
            // 0x17 => (self._handle_streams_blocked_frame, EPOCHS("01")),
            // 0x18 => (self._handle_new_connection_id_frame, EPOCHS("01")),
            // 0x19 => (self._handle_retire_connection_id_frame, EPOCHS("01")),
            // 0x1a => (self._handle_path_challenge_frame, EPOCHS("01")),
            // 0x1b => (self._handle_path_response_frame, EPOCHS("01")),
            // 0x1c => (self._handle_connection_close_frame, EPOCHS("IH01")),
            // 0x1d => (self._handle_connection_close_frame, EPOCHS("01")),
            // 0x1e => (self._handle_handshake_done_frame, EPOCHS("1")),
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
            FrameType.padding => |frame| try std.testing.expect(1 == frame.len),
            else => unreachable,
        }
    }
    {
        var bytes = [_]u8{ 0x00, 0x00, 0x01 };
        switch (try Frame.parse(&bytes)) {
            FrameType.padding => |frame| try std.testing.expect(2 == frame.len),
            else => unreachable,
        }
    }
    {
        var bytes = [_]u8{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 };
        switch (try Frame.parse(&bytes)) {
            FrameType.padding => |frame| try std.testing.expect(10 == frame.len),
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
