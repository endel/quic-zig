const std = @import("std");
const io = @import("../io_compat.zig");
const sys = @import("../sys.zig");
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
    ipv4_addr: [4]u8 = @splat(0),
    ipv4_port: u16 = 0,
    ipv6_addr: [16]u8 = @splat(0),
    ipv6_port: u16 = 0,
    cid_buf: [20]u8 = @splat(0),
    cid_len: u8 = 0,
    stateless_reset_token: [16]u8 = @splat(0),

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

/// A connection ID held by value: params are copied between TLS and the
/// connection, and a slice would point into a buffer since reused.
pub const ConnectionId = struct {
    buf: [20]u8 = undefined,
    len: u8 = 0,

    /// At most 20 bytes; decode refuses longer ones before getting here.
    pub fn init(bytes: []const u8) ConnectionId {
        std.debug.assert(bytes.len <= 20);
        var c: ConnectionId = .{ .len = @intCast(bytes.len) };
        @memcpy(c.buf[0..bytes.len], bytes);
        return c;
    }

    pub fn slice(self: *const ConnectionId) []const u8 {
        return self.buf[0..self.len];
    }
};

/// QUIC Transport Parameters (RFC 9000 Section 18).
pub const TransportParams = struct {
    original_destination_connection_id: ?ConnectionId = null,
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
    initial_source_connection_id: ?ConnectionId = null,
    retry_source_connection_id: ?ConnectionId = null,
    max_datagram_frame_size: ?u64 = null,

    // draft-ietf-quic-ack-frequency: minimum ACK delay in microseconds.
    // null = does not support ACK frequency extension.
    min_ack_delay: ?u64 = null,

    /// RFC 9368 version_information transport parameter.
    /// chosen_version: the version used for this connection.
    /// available_versions: list of all supported versions (up to 8).
    version_info_chosen: ?u32 = null,
    version_info_available: [8]u32 = @splat(0),
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
                try packet.writeVarInt(w, @backingInt(id));
                const len = packet.varIntLength(value);
                try packet.writeVarInt(w, len);
                try packet.writeVarInt(w, value);
            }

            fn writeParamBytes(w: anytype, id: ParamId, data: []const u8) !void {
                try packet.writeVarInt(w, @backingInt(id));
                try packet.writeVarInt(w, data.len);
                try w.writeAll(data);
            }

            fn writeParamEmpty(w: anytype, id: ParamId) !void {
                try packet.writeVarInt(w, @backingInt(id));
                try packet.writeVarInt(w, 0);
            }
        };

        if (self.original_destination_connection_id) |*cid| {
            try Helper.writeParamBytes(writer, .original_destination_connection_id, cid.slice());
        }

        if (self.max_idle_timeout > 0) {
            try Helper.writeParam(writer, .max_idle_timeout, self.max_idle_timeout);
        }

        if (self.stateless_reset_token) |token| {
            try packet.writeVarInt(writer, @backingInt(ParamId.stateless_reset_token));
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
            try packet.writeVarInt(writer, @backingInt(ParamId.preferred_address));
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

        if (self.initial_source_connection_id) |*cid| {
            try Helper.writeParamBytes(writer, .initial_source_connection_id, cid.slice());
        }

        if (self.retry_source_connection_id) |*cid| {
            try Helper.writeParamBytes(writer, .retry_source_connection_id, cid.slice());
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
            sys.randomBytes(&grease_entropy);
            // Pick N in [0..255], giving IDs like 27, 58, 89, ...
            const n: u64 = @as(u64, grease_entropy[0]);
            const grease_id: u64 = 31 * n + 27;
            // Value: 1-4 random bytes
            const grease_val_len: u64 = @as(u64, grease_entropy[1] & 0x03) + 1;
            try packet.writeVarInt(writer, grease_id);
            try packet.writeVarInt(writer, grease_val_len);
            try writer.writeAll(grease_entropy[2..][0..@intCast(grease_val_len)]);
        }

        // RFC 9368: version_information
        if (self.version_info_chosen) |chosen| {
            const n = self.version_info_available_count;
            const param_len: u64 = 4 + @as(u64, n) * 4; // chosen(4) + available(n*4)
            try packet.writeVarInt(writer, @backingInt(ParamId.version_information));
            try packet.writeVarInt(writer, param_len);
            try writer.writeInt(u32, chosen, .big);
            for (0..n) |i| {
                try writer.writeInt(u32, self.version_info_available[i], .big);
            }
        }
    }

    /// Decode transport parameters from a buffer.
    /// RFC 9000 §18.2: a connection ID parameter longer than 20 bytes is invalid.
    fn readCid(bytes: []const u8) error{TransportParameterError}!ConnectionId {
        if (bytes.len > 20) return error.TransportParameterError;
        return ConnectionId.init(bytes);
    }

    pub fn decode(data: []const u8) !TransportParams {
        var params = TransportParams{};
        var fbs = io.fixedBufferStream(data);
        const reader = &fbs;
        // RFC 9000 §7.4: each parameter we know at most once. Their IDs are
        // 0x00-0x11 and 0x20, bar min_ack_delay's.
        var seen = std.bit_set.Static(0x21).empty;
        var seen_min_ack_delay = false;

        while (fbs.seek < data.len) {
            const param_id = try packet.readVarInt(reader);
            // A parameter cannot extend past the buffer it was decoded from,
            // and its varint length has to survive a 32-bit usize.
            const param_len = packet.readVarIntUsize(reader) catch
                return error.TransportParameterError;
            if (param_len > data.len - fbs.seek) return error.TransportParameterError;
            // Each value is read from its own bytes and must fill them.
            const value = data[fbs.seek..][0..param_len];
            fbs.seek += param_len;

            if (param_id == @backingInt(ParamId.min_ack_delay)) {
                if (seen_min_ack_delay) return error.TransportParameterError;
                seen_min_ack_delay = true;
            } else if (param_id <= @backingInt(ParamId.version_information) or
                param_id == @backingInt(ParamId.max_datagram_frame_size))
            {
                if (seen.isSet(@intCast(param_id))) return error.TransportParameterError;
                seen.set(@intCast(param_id));
            }

            switch (param_id) {
                @backingInt(ParamId.original_destination_connection_id) => params.original_destination_connection_id = try readCid(value),
                @backingInt(ParamId.max_idle_timeout) => params.max_idle_timeout = try readVarIntParam(value),
                @backingInt(ParamId.stateless_reset_token) => {
                    if (value.len != 16) return error.TransportParameterError;
                    params.stateless_reset_token = value[0..16].*;
                },
                @backingInt(ParamId.max_udp_payload_size) => {
                    params.max_udp_payload_size = try readVarIntParam(value);
                    if (params.max_udp_payload_size < 1200) return error.TransportParameterError;
                },
                @backingInt(ParamId.initial_max_data) => params.initial_max_data = try readVarIntParam(value),
                @backingInt(ParamId.initial_max_stream_data_bidi_local) => params.initial_max_stream_data_bidi_local = try readVarIntParam(value),
                @backingInt(ParamId.initial_max_stream_data_bidi_remote) => params.initial_max_stream_data_bidi_remote = try readVarIntParam(value),
                @backingInt(ParamId.initial_max_stream_data_uni) => params.initial_max_stream_data_uni = try readVarIntParam(value),
                @backingInt(ParamId.initial_max_streams_bidi) => params.initial_max_streams_bidi = try readVarIntParam(value),
                @backingInt(ParamId.initial_max_streams_uni) => params.initial_max_streams_uni = try readVarIntParam(value),
                @backingInt(ParamId.ack_delay_exponent) => params.ack_delay_exponent = try readVarIntParam(value),
                @backingInt(ParamId.max_ack_delay) => params.max_ack_delay = try readVarIntParam(value),
                @backingInt(ParamId.disable_active_migration) => {
                    if (value.len != 0) return error.TransportParameterError;
                    params.disable_active_migration = true;
                },
                @backingInt(ParamId.preferred_address) => params.preferred_address = try readPreferredAddress(value),
                @backingInt(ParamId.active_connection_id_limit) => {
                    params.active_connection_id_limit = try readVarIntParam(value);
                    if (params.active_connection_id_limit < 2) return error.TransportParameterError;
                },
                @backingInt(ParamId.initial_source_connection_id) => params.initial_source_connection_id = try readCid(value),
                @backingInt(ParamId.retry_source_connection_id) => params.retry_source_connection_id = try readCid(value),
                @backingInt(ParamId.max_datagram_frame_size) => params.max_datagram_frame_size = try readVarIntParam(value),
                @backingInt(ParamId.min_ack_delay) => params.min_ack_delay = try readVarIntParam(value),
                @backingInt(ParamId.version_information) => {
                    // A malformed one is skipped, as before; up to 8 versions kept.
                    if (value.len >= 4 and value.len % 4 == 0) {
                        params.version_info_chosen = std.mem.readInt(u32, value[0..4], .big);
                        const n: u8 = @intCast(@min((value.len - 4) / 4, 8));
                        for (0..n) |i| {
                            params.version_info_available[i] = std.mem.readInt(u32, value[4 + 4 * i ..][0..4], .big);
                        }
                        params.version_info_available_count = n;
                    }
                },
                else => {}, // unknown parameters are ignored (§7.4.2)
            }
        }

        return params;
    }

    /// A varint parameter's value must be exactly one varint.
    fn readVarIntParam(value: []const u8) error{TransportParameterError}!u64 {
        var v = io.fixedBufferStream(value);
        const n = packet.readVarInt(&v) catch return error.TransportParameterError;
        if (v.seek != value.len) return error.TransportParameterError;
        return n;
    }

    /// IPv4 addr (4) + port (2) + IPv6 addr (16) + port (2) + CID len (1) +
    /// CID + reset token (16). RFC 9000 §18.2: the CID is not empty.
    fn readPreferredAddress(value: []const u8) error{TransportParameterError}!PreferredAddress {
        if (value.len < 25) return error.TransportParameterError;
        var pref = PreferredAddress{};
        pref.ipv4_addr = value[0..4].*;
        pref.ipv4_port = std.mem.readInt(u16, value[4..6], .big);
        pref.ipv6_addr = value[6..22].*;
        pref.ipv6_port = std.mem.readInt(u16, value[22..24], .big);
        pref.cid_len = value[24];
        if (pref.cid_len == 0 or pref.cid_len > 20 or value.len != 25 + @as(usize, pref.cid_len) + 16)
            return error.TransportParameterError;
        @memcpy(pref.cid_buf[0..pref.cid_len], value[25..][0..pref.cid_len]);
        pref.stateless_reset_token = value[25 + @as(usize, pref.cid_len) ..][0..16].*;
        return pref;
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
    var fbs = io.fixedBufferStream(&buf);
    try original.encode(&fbs);

    const encoded = fbs.buffered();
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
    var fbs = io.fixedBufferStream(&buf);
    try params.encode(&fbs);

    // Empty params should produce minimal output
    const encoded = fbs.buffered();
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
    var fbs = io.fixedBufferStream(&buf);
    try original.encode(&fbs);

    const decoded = try TransportParams.decode(fbs.buffered());
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
    var fbs = io.fixedBufferStream(&buf);
    try original.encode(&fbs);

    const decoded = try TransportParams.decode(fbs.buffered());
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
    var fbs = io.fixedBufferStream(&buf);
    try original.encode(&fbs);

    const decoded = try TransportParams.decode(fbs.buffered());
    try testing.expectEqual(protocol.QUIC_V1, decoded.version_info_chosen);
    try testing.expectEqual(@as(u8, 2), decoded.version_info_available_count);
    try testing.expectEqual(protocol.QUIC_V2, decoded.version_info_available[0]);
    try testing.expectEqual(protocol.QUIC_V1, decoded.version_info_available[1]);
}

test "TransportParams: connection IDs roundtrip" {
    const scid = [_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
    const odcid = [_]u8{ 0x11, 0x12, 0x13, 0x14 };

    const original = TransportParams{
        .initial_source_connection_id = ConnectionId.init(&scid),
        .original_destination_connection_id = ConnectionId.init(&odcid),
        .max_idle_timeout = 30000,
    };

    var buf: [512]u8 = undefined;
    var fbs = io.fixedBufferStream(&buf);
    try original.encode(&fbs);

    const decoded = try TransportParams.decode(fbs.buffered());
    try testing.expect(decoded.initial_source_connection_id != null);
    try testing.expectEqualSlices(u8, &scid, decoded.initial_source_connection_id.?.slice());
    try testing.expect(decoded.original_destination_connection_id != null);
    try testing.expectEqualSlices(u8, &odcid, decoded.original_destination_connection_id.?.slice());
}

// RFC 9000 §18.1: greased transport parameters are encoded and decode is tolerant
test "TransportParams: decoded connection IDs outlive the bytes they came from" {
    // TLS reads the peer's params out of a buffer the next handshake message reuses.
    const odcid = [_]u8{ 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88 };
    var buf: [256]u8 = undefined;
    var fbs = io.fixedBufferStream(&buf);
    try (TransportParams{
        .original_destination_connection_id = ConnectionId.init(&odcid),
        .initial_source_connection_id = ConnectionId.init(&odcid),
        .retry_source_connection_id = ConnectionId.init(&odcid),
    }).encode(&fbs);
    const decoded = try TransportParams.decode(buf[0..fbs.seek]);
    @memset(&buf, 0xee);
    try std.testing.expectEqualSlices(u8, &odcid, decoded.original_destination_connection_id.?.slice());
    try std.testing.expectEqualSlices(u8, &odcid, decoded.initial_source_connection_id.?.slice());
    try std.testing.expectEqualSlices(u8, &odcid, decoded.retry_source_connection_id.?.slice());
}

test "TransportParams: values RFC 9000 18.2 rules out are TRANSPORT_PARAMETER_ERROR" {
    const bad = [_][]const u8{
        &.{ 0x01, 0x01, 0x0a, 0x01, 0x01, 0x0b }, // max_idle_timeout twice
        &.{ 0x0e, 0x01, 0x01 }, // active_connection_id_limit 1
        &.{ 0x03, 0x02, 0x44, 0x00 }, // max_udp_payload_size 1024
        &.{ 0x0c, 0x01, 0x00 }, // disable_active_migration with a value
        &.{ 0x04, 0x02, 0x05, 0x00 }, // a varint shorter than its length
        &.{ 0x04, 0x01, 0x40, 0x10 }, // a varint longer than its length
        &.{ 0x0d, 41, 0, 0, 0, 0, 0x11, 0x51, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x11, 0x51, 0x00, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa }, // preferred_address with no CID
    };
    for (bad) |b| try testing.expectError(error.TransportParameterError, TransportParams.decode(b));
    _ = try TransportParams.decode(&.{ 0x0e, 0x01, 0x02, 0x0c, 0x00, 0x03, 0x02, 0x44, 0xb0 });
}

test "TransportParams: greasing roundtrip" {
    const original = TransportParams{
        .max_idle_timeout = 30000,
        .initial_max_data = 1048576,
    };

    var buf: [512]u8 = undefined;
    var fbs = io.fixedBufferStream(&buf);
    try original.encode(&fbs);

    // Decode should succeed — unknown params (greased) are silently ignored
    const decoded = try TransportParams.decode(fbs.buffered());
    try std.testing.expectEqual(@as(u64, 30000), decoded.max_idle_timeout);
    try std.testing.expectEqual(@as(u64, 1048576), decoded.initial_max_data);

    // Encode twice — greased IDs are random so encoded length may differ,
    // but both must decode to same semantic values
    var buf2: [512]u8 = undefined;
    var fbs2 = io.fixedBufferStream(&buf2);
    try original.encode(&fbs2);
    const decoded2 = try TransportParams.decode(fbs2.buffered());
    try std.testing.expectEqual(@as(u64, 30000), decoded2.max_idle_timeout);
}

test "transport parameter longer than the buffer is rejected" {
    // id=0x00 (original_destination_connection_id), len=16383, 2 bytes present.
    const params = [_]u8{ 0x00, 0x7f, 0xff, 0xaa, 0xbb };
    try std.testing.expectError(error.TransportParameterError, TransportParams.decode(&params));
}
