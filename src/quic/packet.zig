const std = @import("std");
const io = std.io;
const log = std.log;
const time = std.time;
const assert = std.debug.assert;

const protocol = @import("protocol.zig");
const crypto = @import("crypto.zig");
const util = @import("util.zig");

// network byte order
const endian = std.builtin.Endian.Big;

pub const PACKET_LONG_HEADER = 0x80;
pub const PACKET_FIXED_BIT = 0x40;
pub const PACKET_SPIN_BIT = 0x20;
pub const PACKET_TYPE_MASK = 0xF0;

const PACKET_NUM_MASK: u8 = 0x03;

pub const MAX_PACKET_LEN = 1536;
pub const MAX_PACKET_NUMBER_LEN = 4; // maxlength of a "packet number"

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

pub const Epoch = enum(u8) {
    INITIAL = 0,
    ZERO_RTT = 1,
    HANDSHAKE = 2,
    ONE_RTT = 3,

    pub fn fromPacketType(int: PacketType) !Epoch {
        return switch (int) {
            PacketType.Initial => Epoch.INITIAL,
            PacketType.ZeroRTT => Epoch.ZERO_RTT,
            PacketType.Handshake => Epoch.HANDSHAKE,
            PacketType.OneRTT => Epoch.ONE_RTT,
            else => (error{InvalidPacketType}).InvalidPacketType,
        };
    }
};

test "Epoch fromPacketType" {
    try std.testing.expectEqual(Epoch.fromPacketType(PacketType.Initial), Epoch.INITIAL);
    try std.testing.expectEqual(Epoch.fromPacketType(PacketType.ZeroRTT), Epoch.ZERO_RTT);
    try std.testing.expectEqual(Epoch.fromPacketType(PacketType.Handshake), Epoch.HANDSHAKE);
    try std.testing.expectEqual(Epoch.fromPacketType(PacketType.OneRTT), Epoch.ONE_RTT);

    const err = Epoch.fromPacketType(PacketType.Retry);
    try std.testing.expectError(error.InvalidPacketType, err);
}

pub const CONNECTION_ID_MAX_SIZE: u8 = 20;
pub const PACKET_NUMBER_MAX_SIZE = 4;

pub const RETRY_INTEGRITY_TAG_SIZE = 16;
pub const STATELESS_RESET_TOKEN_SIZE = 16;

pub const PacketError = error{
    InvalidVersion,
    InvalidPacket,
    InvalidVarLength,
};

pub const ErrorCode = enum(u8) {
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
};

pub const PktNumWindow = struct {
    lower: u64,
    window: u128,
};

pub const PacketNumSpace = struct {
    // largest_rx_pkt_num: u64,
    // largest_rx_pkt_time: time.Instant,
    //
    // next_pkt_num: u64,
    // // recv_pkt_need_ack: ranges::RangeSet,
    //
    // recv_pkt_num: PktNumWindow,
    // ack_elicited: bool,
    next_packet_number: u64 = 0, // TODO: largest_recv_packet_number

    crypto_open: ?crypto.Open = undefined,
    crypto_seal: ?crypto.Seal = undefined,

    // crypto_open: Option<crypto::Open>,
    // crypto_seal: Option<crypto::Seal>,
    //
    // crypto_0rtt_open: Option<crypto::Open>,
    // crypto_0rtt_seal: Option<crypto::Seal>,
    //
    // crypto_stream: stream::Stream,

    pub fn setupInitial(self: *PacketNumSpace, dcid: []const u8, version: protocol.Version, comptime is_client: bool) !void {
        var keys = try crypto.deriveInitialKeyMaterial(dcid, version, is_client);
        self.crypto_open = keys[0];
        self.crypto_seal = keys[1];
    }
};

pub fn parseIncoming(bytes: []const u8) void {
    _ = bytes;
}

pub fn decrypt(header: *Header, stream: anytype, space: PacketNumSpace) !void {
    std.log.info("\n\nheader.remainder_len: {any}", .{header.remainder_len});
    const pn_and_sample_len = MAX_PACKET_NUMBER_LEN + crypto.SAMPLE_LEN;
    const pn_and_sample = stream.buffer[stream.pos..(stream.pos + pn_and_sample_len)];

    // advance stream position
    try stream.seekBy(pn_and_sample_len);

    var ciphertext = pn_and_sample[0..MAX_PACKET_NUMBER_LEN];
    var sample = pn_and_sample[MAX_PACKET_NUMBER_LEN..(MAX_PACKET_NUMBER_LEN + crypto.SAMPLE_LEN)];

    var first_byte = stream.buffer[0];

    // unprotect header
    var aead = space.crypto_open.?;
    var mask = aead.newMask(sample);

    if (isLongHeader(first_byte)) {
        first_byte ^= (mask[0] & 0x0f);
    } else {
        first_byte ^= (mask[0] & 0x1f);
    }

    header.packet_number_len = @intCast(usize, (first_byte & PACKET_NUM_MASK)) + 1;

    // unprotect packer number
    var unprotected_pkt_num = [_]u8{0x00} ** MAX_PACKET_NUMBER_LEN;
    var i: usize = 0;
    while (i < header.packet_number_len) : (i += 1) {
        unprotected_pkt_num[i] = ciphertext.*[i] ^ mask[1 + i];
    }

    var truncated_packet_number = try switch (header.packet_number_len) {
        1 => @intCast(u64, std.mem.readInt(u8, unprotected_pkt_num[0..util.sizeOf(u8)], endian)),
        2 => @intCast(u64, std.mem.readInt(u16, unprotected_pkt_num[0..util.sizeOf(u16)], endian)),
        3 => @intCast(u64, std.mem.readInt(u24, unprotected_pkt_num[0..util.sizeOf(u24)], endian)),
        4 => @intCast(u64, std.mem.readInt(u32, unprotected_pkt_num[0..util.sizeOf(u32)], endian)),
        else => error.InvalidPacket,
    };

    // Write decrypted first byte back into the input buffer.
    stream.buffer[0] = first_byte;

    //
    // RFC 9000
    // 17.1. Packet Number Encoding and Decoding
    // ------
    // https://www.rfc-editor.org/rfc/rfc9000.html#name-packet-number-encoding-and-
    //
    header.packet_number = decodePacketNumber(space.next_packet_number, truncated_packet_number, header.packet_number_len * 8);

    // var payload = stream.buffer[stream.pos..(stream.pos + header.remainder_len - pn_and_sample_len)];
    var encrypted_payload = stream.buffer[stream.pos..(stream.pos + header.remainder_len)];
    var header_bytes = stream.buffer[0..stream.pos];

    // var payload: []u8 = undefined;
    try aead.decryptPayload(header.packet_number, header_bytes, encrypted_payload);
    // try aead.decryptPayload(header.packet_number, pn_and_sample, encrypted_payload, payload);

    // std.log.info("final payload: (len: {any}) {any}", .{ payload.len, payload });
}

// inline
pub fn isLongHeader(first_byte: u8) bool {
    return (first_byte & PACKET_LONG_HEADER) == PACKET_LONG_HEADER;
}

pub fn parseQuicHeader(stream: anytype) !Header {
    const reader = stream.reader();
    const first_byte = try reader.readByte();

    var header = Header{};

    if (isLongHeader(first_byte)) {
        log.info("LONG HEADER!", .{});

        var version = try reader.readInt(u32, endian);
        log.info("version: {any}", .{version});
        header.version = @intToEnum(protocol.Version, version);
        log.info("(enum) version: {any}", .{header.version});

        const dcid_length = try reader.readByte();
        if (dcid_length > CONNECTION_ID_MAX_SIZE) {
            std.log.err("Destination CID is too long ({any} bytes)", .{dcid_length});
            return error.PacketError;
        }

        std.log.info("stream.pos: {any}, dcid length: {any}", .{ stream.pos, dcid_length });

        header.dcid = stream.buffer[stream.pos..(stream.pos + dcid_length)];
        std.log.info("dcid: {any}", .{header.dcid});

        // advance length
        try stream.seekBy(dcid_length);

        const scid_length = try reader.readByte();
        if (scid_length > CONNECTION_ID_MAX_SIZE) {
            std.log.err("Source CID is too long ({any} bytes)", .{scid_length});
            return error.InvalidPacket;
        }

        std.log.info("stream.pos: {any}, scid length: {any}", .{ stream.pos, scid_length });
        header.scid = stream.buffer[stream.pos..(stream.pos + scid_length)];
        std.log.info("scid: {s} ({any})", .{ header.scid, header.scid });

        // advance scid_length
        try stream.seekBy(scid_length);

        if (header.version == protocol.Version.NEGOTIATION) {
            // version negotiation
            //
            // TODO:
            // remainder_len = @intCast(u32, bytes.len) - @intCast(u32, stream.pos);
        } else {
            if ((first_byte & PACKET_FIXED_BIT) == 0) {
                std.log.err("Packet fixed bit is zero", .{});
                return error.InvalidPacket;
            }

            header.packet_type = @intToEnum(PacketType, (first_byte & PACKET_TYPE_MASK));
            std.log.info("packet_type => {any}", .{header.packet_type});

            switch (header.packet_type) {
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
                        header.token = stream.buffer[stream.pos..(stream.pos + token_length)];
                        try stream.seekBy(@intCast(i64, token_length));
                    }

                    header.remainder_len = try readVarInt(reader);
                },

                PacketType.Retry => {
                    // var token_length = len - stream.pos - RETRY_INTEGRITY_TAG_SIZE;
                    // var token = bytes[stream.pos..(stream.pos + token_length)];
                    // try stream.seekBy(@intCast(i64, token_length));

                    // header.token = token;
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
                    std.log.err("Packet type not recognized: {any}", .{header.packet_type});
                    header.remainder_len = try readVarInt(reader);
                },
            }

            // // check remainder length
            // if (header.remainder_len > bytes.len - stream.pos) {
            //     std.log.err("Packet payload is truncated", .{});
            //     return error.InvalidPacket;
            // }

        }

        //
    } else {
        log.info("SHORT HEADER!", .{});

        header.remainder_len = stream.buffer.len;
    }

    return header;
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

        var red = try reader.readByte();
        value = value + red;
    }

    return value;
}

test "QUIC: Variable-Length Integer Decoding" {
    var fbs = io.fixedBufferStream(&[_]u8{ 0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c });
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
fn decodePacketNumber(expected_pkt_num: u64, truncated_pkt_num: u64, num_bits: usize) u64 {
    assert(num_bits <= 32); // The maximum length of a encoded packet number is 32 in bits.

    const window = @intCast(u64, 1) << @intCast(u5, num_bits);
    const half_window = window / 2;
    const pkt_num_mask = window - 1;

    const candidate = (expected_pkt_num & ~pkt_num_mask) | truncated_pkt_num;

    if ((candidate + half_window <= expected_pkt_num) and (candidate < (1 << 62) - window)) {
        return candidate + window;
    }

    if ((candidate > expected_pkt_num + half_window) and (candidate >= window)) {
        return candidate - window;
    }

    return candidate;
}
