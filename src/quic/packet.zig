const std = @import("std");
const io = std.io;
const log = std.log;

// network byte order
const endian = std.builtin.Endian.Big;

pub const PACKET_LONG_HEADER = 0x80;
pub const PACKET_FIXED_BIT = 0x40;
pub const PACKET_SPIN_BIT = 0x20;
pub const PACKET_TYPE_MASK = 0xF0;

pub const MAX_PACKET_SIZE = 1536;

pub const PacketType = enum(u8) {
    Initial = PACKET_LONG_HEADER | PACKET_FIXED_BIT | 0x00,
    ZeroRTT = PACKET_LONG_HEADER | PACKET_FIXED_BIT | 0x10,
    Handshake = PACKET_LONG_HEADER | PACKET_FIXED_BIT | 0x20,
    Retry = PACKET_LONG_HEADER | PACKET_FIXED_BIT | 0x30,
    OneRTT = PACKET_FIXED_BIT,
};

pub const Epoch = enum(u8) { Initial = 0, ZeroRTT = 1, Handshake = 2, OneRTT = 3 };

pub const CONNECTION_ID_MAX_SIZE: u8 = 20;
pub const PACKET_NUMBER_MAX_SIZE = 4;
// pub const RETRY_AEAD_KEY_DRAFT_29 = binascii.unhexlify("ccce187ed09a09d05728155a6cb96be1");
// pub const RETRY_AEAD_KEY_VERSION_1 = binascii.unhexlify("be0c690b9f66575a1d766b54e368c84e");
// pub const RETRY_AEAD_NONCE_DRAFT_29 = binascii.unhexlify("e54930f97f2136f0530a8c1c");
// pub const RETRY_AEAD_NONCE_VERSION_1 = binascii.unhexlify("461599d35d632bf2239825bb");
pub const RETRY_INTEGRITY_TAG_SIZE = 16;
pub const STATELESS_RESET_TOKEN_SIZE = 16;

pub const PacketError = error{
    InvalidVersion,
    ConnectionIDTooLong,
    FixedBitZero, //
    PayloadTruncated,
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

pub const ProtocolVersion = enum(u32) {
    NEGOTIATION = 0,
    VERSION_1 = 0x00000001,
    VERSION_2 = 0x709a50c4,
    DRAFT_29 = 0xFF00001D,
    DRAFT_30 = 0xFF00001E,
    DRAFT_31 = 0xFF00001F,
    DRAFT_32 = 0xFF000020,
};

/// QuicPacketHeader
pub const QuicPacketHeader = struct {
    // bytes: []const u8,

    version: ProtocolVersion = undefined,
    epoch: Epoch = undefined,

    packet_type: PacketType = undefined,
    // payload_length: i32 = undefined,

    source_cid: []const u8 = undefined,
    destination_cid: []const u8 = undefined,

    token: []const u8 = undefined,
    remainder_length: u64 = undefined,

    // pub fn parseFrom(reader: anytype) !QuicPacketHeader {
    //     return parseQuicHeader(reader);
    // }
    pub fn parseFrom(bytes: []const u8) !QuicPacketHeader {
        return parseQuicHeader(bytes);
    }
};

pub fn parseIncoming(bytes: []const u8) void {
    _ = bytes;
}

// inline
pub fn isLongHeader(first_byte: u8) bool {
    return (first_byte & PACKET_LONG_HEADER) == PACKET_LONG_HEADER;
}

pub fn parseQuicHeader(bytes: []const u8) !QuicPacketHeader {
    var stream = io.fixedBufferStream(bytes);
    const reader = stream.reader();

    const first_byte = try reader.readByte();
    var packet_header = QuicPacketHeader{};

    if (isLongHeader(first_byte)) {
        log.info("LONG HEADER!", .{});

        packet_header.version = @intToEnum(ProtocolVersion, try reader.readInt(u32, endian));
        log.info("version: {any}", .{packet_header.version});

        const destination_cid_length = try reader.readByte();
        if (destination_cid_length > CONNECTION_ID_MAX_SIZE) {
            std.log.err("Destination CID is too long ({any} bytes)", .{destination_cid_length});
            return error.ConnectionIDTooLong;
        }

        std.log.info("stream.pos: {any}, cid length: {any}", .{ stream.pos, destination_cid_length });

        packet_header.destination_cid = bytes[stream.pos..(stream.pos + destination_cid_length)];
        std.log.info("destination_cid: {s} ({any})", .{ packet_header.destination_cid, packet_header.destination_cid });

        // advance destination_cid_length
        try stream.seekBy(destination_cid_length);

        const source_cid_length = try reader.readByte();
        if (source_cid_length > CONNECTION_ID_MAX_SIZE) {
            std.log.err("Source CID is too long ({any} bytes)", .{source_cid_length});
            return error.ConnectionIDTooLong;
        }

        std.log.info("stream.pos: {any}, cid length: {any}", .{ stream.pos, source_cid_length });
        packet_header.source_cid = bytes[stream.pos..(stream.pos + source_cid_length)];
        std.log.info("source_cid: {s} ({any})", .{ packet_header.source_cid, packet_header.source_cid });

        // advance source_cid_length
        try stream.seekBy(source_cid_length);

        packet_header.packet_type = @intToEnum(PacketType, (first_byte & PACKET_TYPE_MASK));
        std.log.info("packet_type => {any}", .{packet_header.packet_type});

        if (packet_header.version == ProtocolVersion.NEGOTIATION) {
            // version negotiation
            //
            // TODO:
            // remainder_length = @intCast(u32, bytes.len) - @intCast(u32, stream.pos);
        } else {
            if ((first_byte & PACKET_FIXED_BIT) == 0) {
                std.log.err("Packet fixed bit is zero", .{});
                return error.FixedBitZero;
            }

            packet_header.packet_type = @intToEnum(PacketType, (first_byte & PACKET_TYPE_MASK));
            std.log.info("packet_type => {any}", .{packet_header.packet_type});

            switch (packet_header.packet_type) {
                PacketType.Initial => {
                    var token_length = try reader.readByte();
                    if (token_length == 0) {
                        std.log.warn("no token!", .{});
                    }

                    //
                    // Token:  The value of the token that was previously provided in a
                    //    Retry packet or NEW_TOKEN frame; see Section 8.1.
                    //
                    packet_header.token = bytes[stream.pos..(stream.pos + token_length)];
                    try stream.seekBy(@intCast(i64, token_length));

                    packet_header.remainder_length = try readVarInt(reader);
                    packet_header.epoch = Epoch.Initial;
                },

                PacketType.ZeroRTT => {
                    packet_header.epoch = Epoch.ZeroRTT;
                },

                PacketType.Handshake => {
                    packet_header.epoch = Epoch.Handshake;
                },

                PacketType.Retry => {
                    // var token_length = len - stream.pos - RETRY_INTEGRITY_TAG_SIZE;
                    // var token = bytes[stream.pos..(stream.pos + token_length)];
                    // try stream.seekBy(@intCast(i64, token_length));

                    // packet_header.token = token;
                    packet_header.epoch = Epoch.Initial;
                },

                else => {
                    std.log.err("Packet type not recognized: {any}", .{packet_header.packet_type});
                    packet_header.remainder_length = try readVarInt(reader);
                },
            }

            // check remainder length
            if (packet_header.remainder_length > bytes.len - stream.pos) {
                std.log.err("Packet payload is truncated", .{});
                return error.PayloadTruncated;
            }
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
    var reader = io.fixedBufferStream(&[_]u8{ 194, 25, 124, 94, 255, 20, 232, 140 }).reader();
    try std.testing.expect(151288809941952652 == try readVarInt(reader));

    reader = io.fixedBufferStream(&[_]u8{ 0x9d, 0x7f, 0x3e, 0x7d }).reader();
    try std.testing.expect(494878333 == try readVarInt(reader));

    reader = io.fixedBufferStream(&[_]u8{ 0x7b, 0xbd }).reader();
    try std.testing.expect(15293 == try readVarInt(reader));

    reader = io.fixedBufferStream(&[_]u8{0x25}).reader();
    try std.testing.expect(37 == try readVarInt(reader));

    reader = io.fixedBufferStream(&[_]u8{ 0x40, 0x25 }).reader();
    try std.testing.expect(37 == try readVarInt(reader));
}
