const std = @import("std");
const testing = std.testing;

const posix = std.posix;

const packet = @import("packet.zig");
const protocol = @import("protocol.zig");

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
    version_information = 0x11, // RFC 9368
    max_datagram_frame_size = 0x20,
    min_ack_delay = 0xff04de1b, // draft-ietf-quic-ack-frequency (provisional)
    _,
};

/// Server's Preferred Address (RFC 9000 §9.6, §18.2).
pub const PreferredAddress = struct {
    ipv4_addr: [4]u8 = .{0} ** 4,
    ipv4_port: u16 = 0,
    ipv6_addr: [16]u8 = .{0} ** 16,
    ipv6_port: u16 = 0,
    cid_buf: [20]u8 = .{0} ** 20,
    cid_len: u8 = 0,
    stateless_reset_token: [16]u8 = .{0} ** 16,

    pub fn hasIpv4(self: *const PreferredAddress) bool {
        return self.ipv4_port != 0;
    }

    pub fn hasIpv6(self: *const PreferredAddress) bool {
        return self.ipv6_port != 0;
    }

    pub fn getCid(self: *const PreferredAddress) []const u8 {
        return self.cid_buf[0..self.cid_len];
    }

    pub fn toSockaddrV4(self: *const PreferredAddress) posix.sockaddr.storage {
        var storage: posix.sockaddr.storage = std.mem.zeroes(posix.sockaddr.storage);
        const addr_in: *posix.sockaddr.in = @ptrCast(@alignCast(&storage));
        addr_in.* = .{
            .port = std.mem.nativeToBig(u16, self.ipv4_port),
            .addr = @bitCast(self.ipv4_addr),
        };
        return storage;
    }

    pub fn toSockaddrV6(self: *const PreferredAddress) posix.sockaddr.storage {
        var storage: posix.sockaddr.storage = std.mem.zeroes(posix.sockaddr.storage);
        const addr_in6: *posix.sockaddr.in6 = @ptrCast(@alignCast(&storage));
        addr_in6.port = std.mem.nativeToBig(u16, self.ipv6_port);
        addr_in6.addr = self.ipv6_addr;
        return storage;
    }
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
    preferred_address: ?PreferredAddress = null,
    active_connection_id_limit: u64 = 2,
    initial_source_connection_id: ?[]const u8 = null,
    retry_source_connection_id: ?[]const u8 = null,
    max_datagram_frame_size: ?u64 = null,

    // draft-ietf-quic-ack-frequency: minimum ACK delay in microseconds.
    // null = does not support ACK frequency extension.
    min_ack_delay: ?u64 = null,

    /// RFC 9368 version_information transport parameter.
    /// chosen_version: the version used for this connection.
    /// available_versions: list of all supported versions (up to 8).
    version_info_chosen: ?u32 = null,
    version_info_available: [8]u32 = .{0} ** 8,
    version_info_available_count: u8 = 0,

    /// Check if a version is listed in the peer's available versions.
    pub fn hasAvailableVersion(self: *const TransportParams, version: u32) bool {
        for (0..self.version_info_available_count) |i| {
            if (self.version_info_available[i] == version) return true;
        }
        return false;
    }

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

        if (self.preferred_address) |pref| {
            try packet.writeVarInt(writer, @intFromEnum(ParamId.preferred_address));
            // Length: 4+2 + 16+2 + 1+cid_len + 16 = 41 + cid_len
            const pref_len: u64 = 41 + @as(u64, pref.cid_len);
            try packet.writeVarInt(writer, pref_len);
            try writer.writeAll(&pref.ipv4_addr);
            try writer.writeAll(&std.mem.toBytes(std.mem.nativeToBig(u16, pref.ipv4_port)));
            try writer.writeAll(&pref.ipv6_addr);
            try writer.writeAll(&std.mem.toBytes(std.mem.nativeToBig(u16, pref.ipv6_port)));
            try writer.writeByte(pref.cid_len);
            try writer.writeAll(pref.cid_buf[0..pref.cid_len]);
            try writer.writeAll(&pref.stateless_reset_token);
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

        if (self.min_ack_delay) |delay| {
            try Helper.writeParam(writer, .min_ack_delay, delay);
        }

        // RFC 9000 §18.1: Transport parameter greasing — send a reserved parameter
        // with ID of form 31*N+27 so peers learn to ignore unknown parameters.
        {
            var grease_entropy: [6]u8 = undefined;
            std.crypto.random.bytes(&grease_entropy);
            // Pick N in [0..255], giving IDs like 27, 58, 89, ...
            const n: u64 = @as(u64, grease_entropy[0]);
            const grease_id: u64 = 31 * n + 27;
            // Value: 1-4 random bytes
            const grease_val_len: u64 = @as(u64, grease_entropy[1] & 0x03) + 1;
            try packet.writeVarInt(writer, grease_id);
            try packet.writeVarInt(writer, grease_val_len);
            try writer.writeAll(grease_entropy[2..][0..grease_val_len]);
        }

        // RFC 9368: version_information
        if (self.version_info_chosen) |chosen| {
            const n = self.version_info_available_count;
            const param_len: u64 = 4 + @as(u64, n) * 4; // chosen(4) + available(n*4)
            try packet.writeVarInt(writer, @intFromEnum(ParamId.version_information));
            try packet.writeVarInt(writer, param_len);
            try writer.writeInt(u32, chosen, .big);
            for (0..n) |i| {
                try writer.writeInt(u32, self.version_info_available[i], .big);
            }
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
                @intFromEnum(ParamId.preferred_address) => {
                    // IPv4 addr (4) + port (2) + IPv6 addr (16) + port (2) + CID len (1) + CID + reset token (16)
                    var pref = PreferredAddress{};
                    _ = try reader.readAll(&pref.ipv4_addr);
                    var ipv4_port_bytes: [2]u8 = undefined;
                    _ = try reader.readAll(&ipv4_port_bytes);
                    pref.ipv4_port = std.mem.bigToNative(u16, @bitCast(ipv4_port_bytes));
                    _ = try reader.readAll(&pref.ipv6_addr);
                    var ipv6_port_bytes: [2]u8 = undefined;
                    _ = try reader.readAll(&ipv6_port_bytes);
                    pref.ipv6_port = std.mem.bigToNative(u16, @bitCast(ipv6_port_bytes));
                    pref.cid_len = try reader.readByte();
                    if (pref.cid_len > 20) return error.TransportParameterError;
                    _ = try reader.readAll(pref.cid_buf[0..pref.cid_len]);
                    _ = try reader.readAll(&pref.stateless_reset_token);
                    params.preferred_address = pref;
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
                @intFromEnum(ParamId.min_ack_delay) => {
                    params.min_ack_delay = try packet.readVarInt(reader);
                },
                @intFromEnum(ParamId.version_information) => {
                    if (param_len < 4 or (param_len % 4) != 0) {
                        fbs.pos = param_start + param_len;
                    } else {
                        params.version_info_chosen = try reader.readInt(u32, .big);
                        const avail_count = (param_len - 4) / 4;
                        const n: u8 = @intCast(@min(avail_count, 8));
                        for (0..n) |i| {
                            params.version_info_available[i] = try reader.readInt(u32, .big);
                        }
                        params.version_info_available_count = n;
                        // Skip any extra versions beyond our buffer
                        if (avail_count > 8) {
                            fbs.pos = param_start + param_len;
                        }
                    }
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

// PreferredAddress encode/decode roundtrip
test "TransportParams: preferred_address roundtrip" {
    var pref = PreferredAddress{};
    pref.ipv4_addr = .{ 10, 0, 0, 1 };
    pref.ipv4_port = 4433;
    pref.ipv6_addr = .{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01 };
    pref.ipv6_port = 4434;
    pref.cid_len = 8;
    @memset(pref.cid_buf[0..8], 0xAB);
    @memset(&pref.stateless_reset_token, 0xCD);

    const original = TransportParams{
        .max_idle_timeout = 30000,
        .preferred_address = pref,
    };

    var buf: [512]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    try original.encode(fbs.writer());

    const decoded = try TransportParams.decode(fbs.getWritten());
    try testing.expect(decoded.preferred_address != null);

    const dp = decoded.preferred_address.?;
    try testing.expectEqualSlices(u8, &pref.ipv4_addr, &dp.ipv4_addr);
    try testing.expectEqual(pref.ipv4_port, dp.ipv4_port);
    try testing.expectEqualSlices(u8, &pref.ipv6_addr, &dp.ipv6_addr);
    try testing.expectEqual(pref.ipv6_port, dp.ipv6_port);
    try testing.expectEqual(pref.cid_len, dp.cid_len);
    try testing.expectEqualSlices(u8, pref.cid_buf[0..8], dp.cid_buf[0..8]);
    try testing.expectEqualSlices(u8, &pref.stateless_reset_token, &dp.stateless_reset_token);
}

// PreferredAddress sockaddr helpers
test "PreferredAddress: toSockaddrV4" {
    var pref = PreferredAddress{};
    pref.ipv4_addr = .{ 127, 0, 0, 1 };
    pref.ipv4_port = 4433;

    try testing.expect(pref.hasIpv4());
    try testing.expect(!pref.hasIpv6());

    const sa = pref.toSockaddrV4();
    const sa_in: *const posix.sockaddr.in = @ptrCast(@alignCast(&sa));
    try testing.expectEqual(posix.AF.INET, sa_in.family);
    try testing.expectEqual(std.mem.nativeToBig(u16, 4433), sa_in.port);
}

test "TransportParams: disable_active_migration roundtrip" {
    const original = TransportParams{
        .disable_active_migration = true,
        .max_idle_timeout = 10000,
    };

    var buf: [512]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    try original.encode(fbs.writer());

    const decoded = try TransportParams.decode(fbs.getWritten());
    try testing.expect(decoded.disable_active_migration);
    try testing.expectEqual(@as(u64, 10000), decoded.max_idle_timeout);
}

test "TransportParams: version_information roundtrip" {
    var original = TransportParams{
        .max_idle_timeout = 5000,
    };
    original.version_info_chosen = protocol.QUIC_V1;
    original.version_info_available = .{ protocol.QUIC_V2, protocol.QUIC_V1, 0, 0, 0, 0, 0, 0 };
    original.version_info_available_count = 2;

    var buf: [512]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    try original.encode(fbs.writer());

    const decoded = try TransportParams.decode(fbs.getWritten());
    try testing.expectEqual(protocol.QUIC_V1, decoded.version_info_chosen);
    try testing.expectEqual(@as(u8, 2), decoded.version_info_available_count);
    try testing.expectEqual(protocol.QUIC_V2, decoded.version_info_available[0]);
    try testing.expectEqual(protocol.QUIC_V1, decoded.version_info_available[1]);
}

test "TransportParams: connection IDs roundtrip" {
    const scid = [_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
    const odcid = [_]u8{ 0x11, 0x12, 0x13, 0x14 };

    const original = TransportParams{
        .initial_source_connection_id = &scid,
        .original_destination_connection_id = &odcid,
        .max_idle_timeout = 30000,
    };

    var buf: [512]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    try original.encode(fbs.writer());

    const decoded = try TransportParams.decode(fbs.getWritten());
    try testing.expect(decoded.initial_source_connection_id != null);
    try testing.expectEqualSlices(u8, &scid, decoded.initial_source_connection_id.?);
    try testing.expect(decoded.original_destination_connection_id != null);
    try testing.expectEqualSlices(u8, &odcid, decoded.original_destination_connection_id.?);
}

// RFC 9000 §18.1: greased transport parameters are encoded and decode is tolerant
test "TransportParams: greasing roundtrip" {
    const original = TransportParams{
        .max_idle_timeout = 30000,
        .initial_max_data = 1048576,
    };

    var buf: [512]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    try original.encode(fbs.writer());

    // Decode should succeed — unknown params (greased) are silently ignored
    const decoded = try TransportParams.decode(fbs.getWritten());
    try std.testing.expectEqual(@as(u64, 30000), decoded.max_idle_timeout);
    try std.testing.expectEqual(@as(u64, 1048576), decoded.initial_max_data);

    // Encode twice — greased IDs are random so encoded length may differ,
    // but both must decode to same semantic values
    var buf2: [512]u8 = undefined;
    var fbs2 = std.io.fixedBufferStream(&buf2);
    try original.encode(fbs2.writer());
    const decoded2 = try TransportParams.decode(fbs2.getWritten());
    try std.testing.expectEqual(@as(u64, 30000), decoded2.max_idle_timeout);
}
