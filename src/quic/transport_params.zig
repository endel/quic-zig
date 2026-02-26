const std = @import("std");
const testing = std.testing;

const packet = @import("packet.zig");

/// QUIC Transport Parameter IDs (RFC 9000 Section 18.2).
pub const ParamId = enum(u64) {
    original_destination_connection_id = 0x00,
    max_idle_timeout = 0x01,
    stateless_reset_token = 0x02,
    max_udp_payload_size = 0x03,
    initial_max_data = 0x04,
    initial_max_stream_data_bidi_local = 0x05,
    initial_max_stream_data_bidi_remote = 0x06,
    initial_max_stream_data_uni = 0x07,
    initial_max_streams_bidi = 0x08,
    initial_max_streams_uni = 0x09,
    ack_delay_exponent = 0x0a,
    max_ack_delay = 0x0b,
    disable_active_migration = 0x0c,
    preferred_address = 0x0d,
    active_connection_id_limit = 0x0e,
    initial_source_connection_id = 0x0f,
    retry_source_connection_id = 0x10,
    max_datagram_frame_size = 0x20,
    _,
};

/// QUIC Transport Parameters (RFC 9000 Section 18).
pub const TransportParams = struct {
    original_destination_connection_id: ?[]const u8 = null,
    max_idle_timeout: u64 = 0,
    stateless_reset_token: ?[16]u8 = null,
    max_udp_payload_size: u64 = 65527,
    initial_max_data: u64 = 0,
    initial_max_stream_data_bidi_local: u64 = 0,
    initial_max_stream_data_bidi_remote: u64 = 0,
    initial_max_stream_data_uni: u64 = 0,
    initial_max_streams_bidi: u64 = 0,
    initial_max_streams_uni: u64 = 0,
    ack_delay_exponent: u64 = 3,
    max_ack_delay: u64 = 25,
    disable_active_migration: bool = false,
    active_connection_id_limit: u64 = 2,
    initial_source_connection_id: ?[]const u8 = null,
    retry_source_connection_id: ?[]const u8 = null,
    max_datagram_frame_size: ?u64 = null,

    /// Encode transport parameters into a buffer.
    pub fn encode(self: *const TransportParams, writer: anytype) !void {
        // Helper to write a single parameter
        const Helper = struct {
            fn writeParam(w: anytype, id: ParamId, value: u64) !void {
                try packet.writeVarInt(w, @intFromEnum(id));
                const len = packet.varIntLength(value);
                try packet.writeVarInt(w, len);
                try packet.writeVarInt(w, value);
            }

            fn writeParamBytes(w: anytype, id: ParamId, data: []const u8) !void {
                try packet.writeVarInt(w, @intFromEnum(id));
                try packet.writeVarInt(w, data.len);
                try w.writeAll(data);
            }

            fn writeParamEmpty(w: anytype, id: ParamId) !void {
                try packet.writeVarInt(w, @intFromEnum(id));
                try packet.writeVarInt(w, 0);
            }
        };

        if (self.original_destination_connection_id) |cid| {
            try Helper.writeParamBytes(writer, .original_destination_connection_id, cid);
        }

        if (self.max_idle_timeout > 0) {
            try Helper.writeParam(writer, .max_idle_timeout, self.max_idle_timeout);
        }

        if (self.stateless_reset_token) |token| {
            try packet.writeVarInt(writer, @intFromEnum(ParamId.stateless_reset_token));
            try packet.writeVarInt(writer, 16);
            try writer.writeAll(&token);
        }

        if (self.max_udp_payload_size != 65527) {
            try Helper.writeParam(writer, .max_udp_payload_size, self.max_udp_payload_size);
        }

        if (self.initial_max_data > 0) {
            try Helper.writeParam(writer, .initial_max_data, self.initial_max_data);
        }

        if (self.initial_max_stream_data_bidi_local > 0) {
            try Helper.writeParam(writer, .initial_max_stream_data_bidi_local, self.initial_max_stream_data_bidi_local);
        }

        if (self.initial_max_stream_data_bidi_remote > 0) {
            try Helper.writeParam(writer, .initial_max_stream_data_bidi_remote, self.initial_max_stream_data_bidi_remote);
        }

        if (self.initial_max_stream_data_uni > 0) {
            try Helper.writeParam(writer, .initial_max_stream_data_uni, self.initial_max_stream_data_uni);
        }

        if (self.initial_max_streams_bidi > 0) {
            try Helper.writeParam(writer, .initial_max_streams_bidi, self.initial_max_streams_bidi);
        }

        if (self.initial_max_streams_uni > 0) {
            try Helper.writeParam(writer, .initial_max_streams_uni, self.initial_max_streams_uni);
        }

        if (self.ack_delay_exponent != 3) {
            try Helper.writeParam(writer, .ack_delay_exponent, self.ack_delay_exponent);
        }

        if (self.max_ack_delay != 25) {
            try Helper.writeParam(writer, .max_ack_delay, self.max_ack_delay);
        }

        if (self.disable_active_migration) {
            try Helper.writeParamEmpty(writer, .disable_active_migration);
        }

        if (self.active_connection_id_limit != 2) {
            try Helper.writeParam(writer, .active_connection_id_limit, self.active_connection_id_limit);
        }

        if (self.initial_source_connection_id) |cid| {
            try Helper.writeParamBytes(writer, .initial_source_connection_id, cid);
        }

        if (self.retry_source_connection_id) |cid| {
            try Helper.writeParamBytes(writer, .retry_source_connection_id, cid);
        }

        if (self.max_datagram_frame_size) |size| {
            try Helper.writeParam(writer, .max_datagram_frame_size, size);
        }
    }

    /// Decode transport parameters from a buffer.
    pub fn decode(data: []const u8) !TransportParams {
        var params = TransportParams{};
        var fbs = std.io.fixedBufferStream(data);
        const reader = fbs.reader();

        while (fbs.pos < data.len) {
            const param_id = try packet.readVarInt(reader);
            const param_len = try packet.readVarInt(reader);
            const param_start = fbs.pos;

            switch (param_id) {
                @intFromEnum(ParamId.original_destination_connection_id) => {
                    params.original_destination_connection_id = data[fbs.pos..][0..param_len];
                    fbs.pos += param_len;
                },
                @intFromEnum(ParamId.max_idle_timeout) => {
                    params.max_idle_timeout = try packet.readVarInt(reader);
                },
                @intFromEnum(ParamId.stateless_reset_token) => {
                    if (param_len != 16) return error.TransportParameterError;
                    var token: [16]u8 = undefined;
                    _ = try reader.readAll(&token);
                    params.stateless_reset_token = token;
                },
                @intFromEnum(ParamId.max_udp_payload_size) => {
                    params.max_udp_payload_size = try packet.readVarInt(reader);
                },
                @intFromEnum(ParamId.initial_max_data) => {
                    params.initial_max_data = try packet.readVarInt(reader);
                },
                @intFromEnum(ParamId.initial_max_stream_data_bidi_local) => {
                    params.initial_max_stream_data_bidi_local = try packet.readVarInt(reader);
                },
                @intFromEnum(ParamId.initial_max_stream_data_bidi_remote) => {
                    params.initial_max_stream_data_bidi_remote = try packet.readVarInt(reader);
                },
                @intFromEnum(ParamId.initial_max_stream_data_uni) => {
                    params.initial_max_stream_data_uni = try packet.readVarInt(reader);
                },
                @intFromEnum(ParamId.initial_max_streams_bidi) => {
                    params.initial_max_streams_bidi = try packet.readVarInt(reader);
                },
                @intFromEnum(ParamId.initial_max_streams_uni) => {
                    params.initial_max_streams_uni = try packet.readVarInt(reader);
                },
                @intFromEnum(ParamId.ack_delay_exponent) => {
                    params.ack_delay_exponent = try packet.readVarInt(reader);
                },
                @intFromEnum(ParamId.max_ack_delay) => {
                    params.max_ack_delay = try packet.readVarInt(reader);
                },
                @intFromEnum(ParamId.disable_active_migration) => {
                    params.disable_active_migration = true;
                },
                @intFromEnum(ParamId.active_connection_id_limit) => {
                    params.active_connection_id_limit = try packet.readVarInt(reader);
                },
                @intFromEnum(ParamId.initial_source_connection_id) => {
                    params.initial_source_connection_id = data[fbs.pos..][0..param_len];
                    fbs.pos += param_len;
                },
                @intFromEnum(ParamId.retry_source_connection_id) => {
                    params.retry_source_connection_id = data[fbs.pos..][0..param_len];
                    fbs.pos += param_len;
                },
                @intFromEnum(ParamId.max_datagram_frame_size) => {
                    params.max_datagram_frame_size = try packet.readVarInt(reader);
                },
                else => {
                    // Unknown parameter - skip
                    fbs.pos = param_start + param_len;
                },
            }

            // Ensure we consumed exactly param_len bytes
            if (fbs.pos != param_start + param_len) {
                fbs.pos = param_start + param_len;
            }
        }

        return params;
    }
};

// Tests

test "TransportParams: encode and decode roundtrip" {
    const original = TransportParams{
        .max_idle_timeout = 30000,
        .initial_max_data = 1048576,
        .initial_max_stream_data_bidi_local = 65536,
        .initial_max_stream_data_bidi_remote = 65536,
        .initial_max_stream_data_uni = 65536,
        .initial_max_streams_bidi = 100,
        .initial_max_streams_uni = 100,
        .active_connection_id_limit = 4,
        .max_datagram_frame_size = 65536,
    };

    var buf: [512]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    try original.encode(fbs.writer());

    const encoded = fbs.getWritten();
    const decoded = try TransportParams.decode(encoded);

    try testing.expectEqual(original.max_idle_timeout, decoded.max_idle_timeout);
    try testing.expectEqual(original.initial_max_data, decoded.initial_max_data);
    try testing.expectEqual(original.initial_max_stream_data_bidi_local, decoded.initial_max_stream_data_bidi_local);
    try testing.expectEqual(original.initial_max_streams_bidi, decoded.initial_max_streams_bidi);
    try testing.expectEqual(original.initial_max_streams_uni, decoded.initial_max_streams_uni);
    try testing.expectEqual(original.active_connection_id_limit, decoded.active_connection_id_limit);
    try testing.expectEqual(original.max_datagram_frame_size, decoded.max_datagram_frame_size);
}

test "TransportParams: default values" {
    const params = TransportParams{};
    try testing.expectEqual(@as(u64, 65527), params.max_udp_payload_size);
    try testing.expectEqual(@as(u64, 3), params.ack_delay_exponent);
    try testing.expectEqual(@as(u64, 25), params.max_ack_delay);
    try testing.expectEqual(@as(u64, 2), params.active_connection_id_limit);
    try testing.expect(!params.disable_active_migration);
}

test "TransportParams: encode empty params" {
    const params = TransportParams{};
    var buf: [512]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    try params.encode(fbs.writer());

    // Empty params should produce minimal output
    const encoded = fbs.getWritten();
    const decoded = try TransportParams.decode(encoded);

    try testing.expectEqual(@as(u64, 65527), decoded.max_udp_payload_size);
    try testing.expectEqual(@as(u64, 3), decoded.ack_delay_exponent);
}
