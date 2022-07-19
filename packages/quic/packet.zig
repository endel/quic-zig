const std = @import("std");
const io = std.io;
const log = std.log;

pub const PACKET_LONG_HEADER = 0x80;
pub const PACKET_FIXED_BIT = 0x40;
pub const PACKET_SPIN_BIT = 0x20;

pub const PACKET_TYPE_INITIAL = PACKET_LONG_HEADER | PACKET_FIXED_BIT | 0x00;
pub const PACKET_TYPE_ZERO_RTT = PACKET_LONG_HEADER | PACKET_FIXED_BIT | 0x10;
pub const PACKET_TYPE_HANDSHAKE = PACKET_LONG_HEADER | PACKET_FIXED_BIT | 0x20;
pub const PACKET_TYPE_RETRY = PACKET_LONG_HEADER | PACKET_FIXED_BIT | 0x30;
pub const PACKET_TYPE_ONE_RTT = PACKET_FIXED_BIT;
pub const PACKET_TYPE_MASK = 0xF0;

pub const CONNECTION_ID_MAX_SIZE = 20;
pub const PACKET_NUMBER_MAX_SIZE = 4;
// pub const RETRY_AEAD_KEY_DRAFT_29 = binascii.unhexlify("ccce187ed09a09d05728155a6cb96be1");
// pub const RETRY_AEAD_KEY_VERSION_1 = binascii.unhexlify("be0c690b9f66575a1d766b54e368c84e");
// pub const RETRY_AEAD_NONCE_DRAFT_29 = binascii.unhexlify("e54930f97f2136f0530a8c1c");
// pub const RETRY_AEAD_NONCE_VERSION_1 = binascii.unhexlify("461599d35d632bf2239825bb");
pub const RETRY_INTEGRITY_TAG_SIZE = 16;
pub const STATELESS_RESET_TOKEN_SIZE = 16;

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

pub fn isLongHeader(first_byte: u8) bool {
    return (first_byte & PACKET_LONG_HEADER) != 0;
}

pub fn readQuicHeader(bytes: []const u8) !void {
    var stream = io.fixedBufferStream(bytes);
    const reader = stream.reader();
    const first_byte = try reader.readByte();

    if (isLongHeader(first_byte)) {
        log.info("LONG HEADER!", .{});
    } else {
        log.info("SHORT HEADER!", .{});
    }
}
