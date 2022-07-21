const std = @import("std");
const io = std.io;
const log = std.log;

// network byte order
const endian = std.builtin.Endian.Big;

pub const PACKET_LONG_HEADER = 0x80;
pub const PACKET_FIXED_BIT = 0x40;
pub const PACKET_SPIN_BIT = 0x20;

pub const PacketType = enum(u8) {
    None = null,
    Initial = PACKET_LONG_HEADER | PACKET_FIXED_BIT | 0x00,
    ZeroRTT = PACKET_LONG_HEADER | PACKET_FIXED_BIT | 0x10,
    Handshake = PACKET_LONG_HEADER | PACKET_FIXED_BIT | 0x20,
    Retry = PACKET_LONG_HEADER | PACKET_FIXED_BIT | 0x30,
    OneRTT = PACKET_FIXED_BIT,
    Mask = 0xF0,
};

pub const CONNECTION_ID_MAX_SIZE: u8 = 20;
pub const PACKET_NUMBER_MAX_SIZE = 4;
// pub const RETRY_AEAD_KEY_DRAFT_29 = binascii.unhexlify("ccce187ed09a09d05728155a6cb96be1");
// pub const RETRY_AEAD_KEY_VERSION_1 = binascii.unhexlify("be0c690b9f66575a1d766b54e368c84e");
// pub const RETRY_AEAD_NONCE_DRAFT_29 = binascii.unhexlify("e54930f97f2136f0530a8c1c");
// pub const RETRY_AEAD_NONCE_VERSION_1 = binascii.unhexlify("461599d35d632bf2239825bb");
pub const RETRY_INTEGRITY_TAG_SIZE = 16;
pub const STATELESS_RESET_TOKEN_SIZE = 16;

pub const PacketError = error{
    ConnectionIDTooLong,
    FixedBitZero, //
    PayloadTruncated,
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

pub const QuicProtocolVersion = enum(u8) {
    NEGOTIATION = 0,
    VERSION_1 = 0x00000001,
    DRAFT_29 = 0xFF00001D,
    DRAFT_30 = 0xFF00001E,
    DRAFT_31 = 0xFF00001F,
    DRAFT_32 = 0xFF000020,
};

// pub const QuicPacketHeader = struct {
//     payload_length: i32,
// };

pub fn isLongHeader(first_byte: u8) bool {
    return (first_byte & PACKET_LONG_HEADER) != 0;
}

pub fn readQuicHeader(bytes: []const u8) !void {
    var stream = io.fixedBufferStream(bytes);
    const reader = stream.reader();

    const first_byte = try reader.readByte();

    if (isLongHeader(first_byte)) {
        log.info("LONG HEADER!", .{});

        const version = reader.readInt(u32, endian);
        log.info("version: {any}", .{version});

        const destination_cid_length = try reader.readByte();
        if (destination_cid_length > CONNECTION_ID_MAX_SIZE) {
            std.log.err("Destination CID is too long ({any} bytes)", .{destination_cid_length});
            return error.ConnectionIDTooLong;
        }

        std.log.info("stream.pos: {any}, cid length: {any}", .{ stream.pos, destination_cid_length });

        const destination_cid = bytes[stream.pos..(stream.pos + destination_cid_length)];
        std.log.info("destination_cid: {s} ({any})", .{ destination_cid, destination_cid });

        // advance destination_cid_length
        try stream.seekBy(destination_cid_length);

        const source_cid_length = try reader.readByte();
        if (source_cid_length > CONNECTION_ID_MAX_SIZE) {
            std.log.err("Source CID is too long ({any} bytes)", .{source_cid_length});
            return error.ConnectionIDTooLong;
        }

        std.log.info("stream.pos: {any}, cid length: {any}", .{ stream.pos, source_cid_length });
        const source_cid = bytes[stream.pos..(stream.pos + source_cid_length)];
        std.log.info("source_cid: {s} ({any})", .{ source_cid, source_cid });

        // advance source_cid_length
        try stream.seekBy(source_cid_length);

        var remainder_length: i32 = undefined;
        var packet_type: PacketType = PacketType.None;
        var integrity_tag: [RETRY_INTEGRITY_TAG_SIZE][]const u8 = "";

        if (version == QuicProtocolVersion.NEGOTIATION) {
            // version negotiation
            remainder_length = bytes.len - stream.pos;
        } else {
            if ((first_byte & PACKET_FIXED_BIT) != 0) {
                std.log.err("Packet fixed bit is zero", .{});
                return error.FixedBitZero;
            }

            packet_type = (first_byte & PacketType.Mask);

            if (packet_type == PacketType.Initial) {
                var token_length = try reader.readByte();
                var token = bytes[stream.pos..(stream.pos + token_length)];
                try stream.seekBy(token_length);

                remainder_length = reader.readVarInt(u32, endian); // FIXME

            } else if (packet_type == PacketType.Retry) {
                var token_length = bytes.len - stream.pos - RETRY_INTEGRITY_TAG_SIZE;
                var token = bytes[stream.pos..(stream.pos + token_length)];
                try stream.seekBy(token_length);

                integrity_tag = bytes[stream.pos..(stream.pos + RETRY_INTEGRITY_TAG_SIZE)];
                remainder_length = 0;

            } else {
                remainder_length = reader.readVarInt(u32, endian); // FIXME
            }

            // check remainder length
            if (remainder_length > bytes.len - stream.pos) {
                std.log.err("Packet payload is truncated", .{});
                return error.PayloadTruncated;
            }

        }

        //
    } else {
        log.info("SHORT HEADER!", .{});
    }
}
