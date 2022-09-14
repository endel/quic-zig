const std = @import("std");
const io = std.io;
const log = std.log;

const protocol = @import("protocol.zig");

// network byte order
const endian = std.builtin.Endian.Big;

pub const PACKET_LONG_HEADER = 0x80;
pub const PACKET_FIXED_BIT = 0x40;
pub const PACKET_SPIN_BIT = 0x20;
pub const PACKET_TYPE_MASK = 0xF0;

pub const MAX_PACKET_LEN = 1536;
pub const MAX_PACKET_NUMBER_LEN = 4; // maxlength of a "packet number"

// Header protection
const SAMPLE_LEN = 16;

pub const PacketType = enum(u8) {
    /// Initial packet
    Initial = PACKET_LONG_HEADER | PACKET_FIXED_BIT | 0x00,

    /// Retry packet
    Retry = PACKET_LONG_HEADER | PACKET_FIXED_BIT | 0x30,

    /// Handshake packet
    Handshake = PACKET_LONG_HEADER | PACKET_FIXED_BIT | 0x20,

    /// 0-RTT packet
    ZeroRTT = PACKET_LONG_HEADER | PACKET_FIXED_BIT | 0x10,

    /// Version negotiation packet
    VersionNegotiation = 0,

    /// 1-RTT short header packet
    OneRTT = PACKET_FIXED_BIT,
};

// pub const Epoch = enum(u8) {
//     Initial = 0,
//     Handshake = 1,
//     Application = 2,
//     Count = 3,
// };
// // pub const Epoch = enum(u8) { Initial = 0, ZeroRTT = 1, Handshake = 2, OneRTT = 3 };

pub const CONNECTION_ID_MAX_SIZE: u8 = 20;
pub const PACKET_NUMBER_MAX_SIZE = 4;

pub const RETRY_INTEGRITY_TAG_SIZE = 16;
pub const STATELESS_RESET_TOKEN_SIZE = 16;

pub const PacketError = error{
    InvalidVersion,
    InvalidPacket,
    InvalidVarLength,
};

pub const QuicErrorCode = enum(u8) {
    NO_ERROR = 0x0,
    INTERNAL_ERROR = 0x1,
    CONNECTION_REFUSED = 0x2,
    FLOW_CONTROL_ERROR = 0x3,
    STREAM_LIMIT_ERROR = 0x4,
    STREAM_STATE_ERROR = 0x5,
    FINAL_SIZE_ERROR = 0x6,
    FRAME_ENCODING_ERROR = 0x7,
    TRANSPORT_PARAMETER_ERROR = 0x8,
    CONNECTION_ID_LIMIT_ERROR = 0x9,
    PROTOCOL_VIOLATION = 0xA,
    INVALID_TOKEN = 0xB,
    APPLICATION_ERROR = 0xC,
    CRYPTO_BUFFER_EXCEEDED = 0xD,
    KEY_UPDATE_ERROR = 0xE,
    AEAD_LIMIT_REACHED = 0xF,
    CRYPTO_ERROR = 0x100,
};

/// A QUIC packet's header.
pub const Header = struct {
    const Self = @This();

    version: protocol.Version = undefined,
    packet_type: PacketType = undefined,

    /// Destination Connection ID
    dcid: []const u8 = undefined,

    /// Source Connection ID
    scid: []const u8 = undefined,

    /// The address verification token of the packet. Only present in `Initial`
    /// and `Retry` packets.
    token: ?[]const u8 = null,
    remainder_len: usize = undefined,

    /// The packet number. It's only meaningful after the header protection is
    /// removed.
    packet_number: u64 = 0,

    /// The length of the packet number. It's only meaningful after the header
    /// protection is removed.
    packet_number_len: usize = 0,

    // TODO: version negotiation
    // versions: ProtocolVersion = undefined,

    pub fn parse(stream: anytype) !Header {
        return parseQuicHeader(stream);
    }

    pub fn decrypt(self: *Self, stream: anytype) !void {
        _ = self;

        // const encrypted_offset = stream.pos;
        // const end_offset = stream.pos + self.remainder_len;

        // try stream.seekBy(@intCast(i64, self.remainder_len));
        // std.log.info("seekBy... {any}", .{self.remainder_len});

        const pn_and_sample = stream.buffer[stream.pos..(stream.pos + (MAX_PACKET_NUMBER_LEN + SAMPLE_LEN))];
        std.log.info("pn_and_sample: {any}", .{pn_and_sample});

        var ciphertext = pn_and_sample[0..MAX_PACKET_NUMBER_LEN];
        var sample = pn_and_sample[MAX_PACKET_NUMBER_LEN..];

        const first = pn_and_sample[0];
        if (isLongHeader(first)) {
            first ^= mask[0] & 0x0f;
        } else {
            first ^= mask[0] & 0x1f;
        }

        if (self.long)
            std.log.info("ciphertext: {any}", .{ciphertext});
        std.log.info("sample: {any}", .{sample});
        std.log.info("first: {any}", .{first});
    }
};

pub fn parseIncoming(bytes: []const u8) void {
    _ = bytes;
}

// inline
pub fn isLongHeader(first_byte: u8) bool {
    return (first_byte & PACKET_LONG_HEADER) == PACKET_LONG_HEADER;
}

pub fn parseQuicHeader(stream: anytype) !Header {
    const reader = stream.reader();

    const first_byte = try reader.readByte();
    var packet_header = Header{};

    if (isLongHeader(first_byte)) {
        log.info("LONG HEADER!", .{});

        var version = try reader.readInt(u32, endian);
        log.info("version: {any}", .{version});
        packet_header.version = @intToEnum(protocol.Version, version);
        log.info("(enum) version: {any}", .{packet_header.version});

        const dcid_length = try reader.readByte();
        if (dcid_length > CONNECTION_ID_MAX_SIZE) {
            std.log.err("Destination CID is too long ({any} bytes)", .{dcid_length});
            return error.PacketError;
        }

        std.log.info("stream.pos: {any}, cid length: {any}", .{ stream.pos, dcid_length });

        packet_header.dcid = stream.buffer[stream.pos..(stream.pos + dcid_length)];
        std.log.info("dcid: {s} ({any})", .{ packet_header.dcid, packet_header.dcid });

        // advance dcid_length
        try stream.seekBy(dcid_length);

        const scid_length = try reader.readByte();
        if (scid_length > CONNECTION_ID_MAX_SIZE) {
            std.log.err("Source CID is too long ({any} bytes)", .{scid_length});
            return error.InvalidPacket;
        }

        std.log.info("stream.pos: {any}, cid length: {any}", .{ stream.pos, scid_length });
        packet_header.scid = stream.buffer[stream.pos..(stream.pos + scid_length)];
        std.log.info("scid: {s} ({any})", .{ packet_header.scid, packet_header.scid });

        // advance scid_length
        try stream.seekBy(scid_length);

        if (packet_header.version == protocol.Version.NEGOTIATION) {
            // version negotiation
            //
            // TODO:
            // remainder_len = @intCast(u32, bytes.len) - @intCast(u32, stream.pos);
        } else {
            if ((first_byte & PACKET_FIXED_BIT) == 0) {
                std.log.err("Packet fixed bit is zero", .{});
                return error.InvalidPacket;
            }

            packet_header.packet_type = @intToEnum(PacketType, (first_byte & PACKET_TYPE_MASK));
            std.log.info("packet_type => {any}", .{packet_header.packet_type});

            switch (packet_header.packet_type) {
                PacketType.Initial => {
                    //
                    // Clients MUST ensure that UDP datagrams containing Initial packets
                    // have UDP payloads of at least 1200 bytes,
                    //
                    // https://datatracker.ietf.org/doc/html/rfc9000#section-8.1
                    //
                    if (stream.buffer.len < 1200) {
                        std.log.warn("Initial packet length must be 1200 bytes or higher. (actual length {})", .{stream.buffer.len});
                        return error.InvalidPacket;
                    }

                    var token_length = try reader.readByte();
                    if (token_length == 0) {
                        std.log.warn("no token!", .{});
                    } else {
                        //
                        // Token:  The value of the token that was previously provided in a
                        //    Retry packet or NEW_TOKEN frame; see Section 8.1.
                        //
                        packet_header.token = stream.buffer[stream.pos..(stream.pos + token_length)];
                        try stream.seekBy(@intCast(i64, token_length));
                    }

                    packet_header.remainder_len = try readVarInt(reader);
                },

                PacketType.Retry => {
                    // var token_length = len - stream.pos - RETRY_INTEGRITY_TAG_SIZE;
                    // var token = bytes[stream.pos..(stream.pos + token_length)];
                    // try stream.seekBy(@intCast(i64, token_length));

                    // packet_header.token = token;
                },

                PacketType.VersionNegotiation => {
                    // TODO: implement version negotiation packets
                    std.log.warn("TODO: VersionNegotiation not implemented yet!", .{});

                    while (stream.pos - stream.buffer.len > 0) {
                        _ = try reader.readInt(u32, endian); // const version = reader.readInt(u32, endian);
                        // std.log.info("PacketType.VersionNegotiation, accepts: {any}", .{version});
                    }
                },

                else => {
                    std.log.err("Packet type not recognized: {any}", .{packet_header.packet_type});
                    packet_header.remainder_len = try readVarInt(reader);
                },
            }

            // // check remainder length
            // if (packet_header.remainder_len > bytes.len - stream.pos) {
            //     std.log.err("Packet payload is truncated", .{});
            //     return error.InvalidPacket;
            // }

        }

        //
    } else {
        log.info("SHORT HEADER!", .{});
    }

    return packet_header;
}

fn readVarInt(reader: anytype) !u64 {
    //
    // https://datatracker.ietf.org/doc/html/draft-ietf-quic-transport-16#section-16
    //
    //     For example, the eight octet sequence c2 19 7c 5e ff 14 e8 8c (in
    //     hexadecimal) decodes to the decimal value 151288809941952652; the
    //     four octet sequence 9d 7f 3e 7d decodes to 494878333; the two octet
    //     sequence 7b bd decodes to 15293; and the single octet 25 decodes to
    //     37 (as does the two octet sequence 40 25).
    //
    const first_byte = try reader.readByte();

    // the first two bits of the first byte encode the length
    var len = @as(i32, 1) << @intCast(u5, (first_byte & 0xc0) >> 6);
    len = len - 1;

    var value: u64 = first_byte & 0x3F;
    while (len > 0) {
        len = len - 1;
        value = (value << 8);
        value = value + try reader.readByte();
    }

    return value;
}

test "QUIC: Variable-Length Integer Decoding" {
    var fbs = io.fixedBufferStream(&[_]u8{ 194, 25, 124, 94, 255, 20, 232, 140 });
    try std.testing.expect(151288809941952652 == try readVarInt(fbs.reader()));

    fbs = io.fixedBufferStream(&[_]u8{ 0x9d, 0x7f, 0x3e, 0x7d });
    try std.testing.expect(494878333 == try readVarInt(fbs.reader()));

    fbs = io.fixedBufferStream(&[_]u8{ 0x7b, 0xbd });
    try std.testing.expect(15293 == try readVarInt(fbs.reader()));

    fbs = io.fixedBufferStream(&[_]u8{0x25});
    try std.testing.expect(37 == try readVarInt(fbs.reader()));

    fbs = io.fixedBufferStream(&[_]u8{ 0x40, 0x25 });
    try std.testing.expect(37 == try readVarInt(fbs.reader()));
}

//
// Recover a packet number from a truncated packet number.
//
// See: Appendix A - Sample Packet Number Decoding Algorithm
// (https://datatracker.ietf.org/doc/html/rfc9000#appendix-A.3)
//
pub fn decodePacketNumber(truncated: u64, num_bits: u64, expected: u64) u64 {
    _ = truncated;
    _ = num_bits;
    _ = expected;

    // window = 1 << num_bits
    // half_window = window // 2
    // candidate = (expected & ~(window - 1)) | truncated
    // if candidate <= expected - half_window and candidate < (1 << 62) - window:
    //     return candidate + window
    // elif candidate > expected + half_window and candidate >= window:
    //     return candidate - window
    // else:
    //     return candidate
    return 0;
}
