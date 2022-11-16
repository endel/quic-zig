const std = @import("std");
const io = std.io;
const log = std.log;
const time = std.time;
const assert = std.debug.assert;
const random = std.crypto.random;

const protocol = @import("protocol.zig");
const crypto = @import("crypto.zig");
const util = @import("util.zig");

// network byte order
const endian = std.builtin.Endian.Big;

pub const LONG_HEADER_BIT: u8 = 0x80;
pub const FIXED_BIT: u8 = 0x40;
pub const KEY_PHASE_BIT: u8 = 0x04;

pub const PACKET_SPIN_BIT = 0x20;
pub const PACKET_TYPE_MASK = 0xF0;

pub const MAX_PACKET_LEN = 1536;
pub const MAX_PACKET_NUMBER_LEN = 4; // maxlength of a "packet number"

pub const CONNECTION_ID_MAX_SIZE: u8 = 20;

const PACKET_NUM_MASK: u8 = 0x03;

pub const STATELESS_RESET_TOKEN_SIZE = 16; // aren't these 2 the same?
const RETRY_INTEGRITY_TAG_SIZE = 16;
const RETRY_INTEGRITY_KEY_V1: [crypto.key_len]u8 = .{ 0xbe, 0x0c, 0x69, 0x0b, 0x9f, 0x66, 0x57, 0x5a, 0x1d, 0x76, 0x6b, 0x54, 0xe3, 0x68, 0xc8, 0x4e };
const RETRY_INTEGRITY_NONCE_V1: [crypto.nonce_len]u8 = .{ 0x46, 0x15, 0x99, 0xd3, 0x5d, 0x63, 0x2b, 0xf2, 0x23, 0x98, 0x25, 0xbb };

pub const PacketType = enum(u8) {
    /// Initial packet
    Initial = LONG_HEADER_BIT | FIXED_BIT | 0x00,

    /// Retry packet
    Retry = LONG_HEADER_BIT | FIXED_BIT | 0x30,

    /// Handshake packet
    Handshake = LONG_HEADER_BIT | FIXED_BIT | 0x20,

    /// 0-RTT packet
    ZeroRTT = LONG_HEADER_BIT | FIXED_BIT | 0x10,

    /// Version negotiation packet
    VersionNegotiation = 0,

    /// 1-RTT short header packet
    OneRTT = FIXED_BIT,
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

    version: u32 = undefined,
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

    /// The key phase bit of the packet. It's only meaningful after the header
    /// protection is removed.
    key_phase: bool = false,

    pub fn parse(stream: anytype) !Header {
        return parseQuicHeader(stream);
    }

    pub fn encode(self: *Self, writer: anytype) !void {
        var first: usize = 0;

        // encode pkt num length.
        first |= (self.packet_number_len -| 1); // (saturating sub)

        // encode short header
        if (self.packet_type == PacketType.OneRTT) {
            // unset form bit for short header
            first &= ~LONG_HEADER_BIT; // bitwise NOT

            // set fixed bit
            first |= FIXED_BIT;

            // set key phase bit
            if (self.key_phase) {
                first |= KEY_PHASE_BIT;
            } else {
                first &= ~KEY_PHASE_BIT; // bitwise NOT
            }

            try writer.writeByte(@intCast(u8, first));
            try writer.writeAll(self.dcid);

            return;
        }

        // encode long header
        const ty: u8 = switch (self.packet_type) {
            PacketType.Initial => 0x00,
            PacketType.ZeroRTT => 0x01,
            PacketType.Handshake => 0x02,
            PacketType.Retry => 0x03,
            else => return error.InvalidPacket,
        };

        first |= LONG_HEADER_BIT | FIXED_BIT | (ty << 4);

        try writer.writeByte(@intCast(u8, first));
        try writer.writeInt(u32, self.version, endian);

        try writer.writeByte(@intCast(u8, self.dcid.len));
        try writer.writeAll(self.dcid);

        try writer.writeByte(@intCast(u8, self.scid.len));
        try writer.writeAll(self.scid);

        // Only Initial and Retry packets have a token.
        switch (self.packet_type) {
            PacketType.Initial => {
                if (self.token == null or self.token.?.len == 0) {
                    try writeVarInt(writer, self.token.?.len);
                    try writer.writeAll(self.token.?);
                } else {
                    // no token, 0 length
                    try writeVarInt(writer, 0);
                }
            },

            PacketType.Retry => {
                // retry packets don't have a token length.
                try writer.writeAll(self.token.?);
            },

            else => {}, // do nothing
        }
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

    pub fn setupInitial(self: *PacketNumSpace, dcid: []const u8, version: u32, comptime is_client: bool) !void {
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
    // try stream.seekBy(pn_and_sample_len);
    // try stream.seekBy(MAX_PACKET_NUMBER_LEN);

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

    // try stream.seekBy(@intCast(i64, (first_byte & PACKET_NUM_MASK)));
    try stream.seekBy(@intCast(i64, header.packet_number_len));

    //
    // RFC 9000
    // 17.1. Packet Number Encoding and Decoding
    // ------
    // https://www.rfc-editor.org/rfc/rfc9000.html#name-packet-number-encoding-and-
    //
    header.packet_number = decodePacketNumber(space.next_packet_number, truncated_packet_number, header.packet_number_len * 8);

    // var payload = stream.buffer[stream.pos..(stream.pos + header.remainder_len - pn_and_sample_len)];

    // TODO: both of these may be wrong
    var header_bytes = stream.buffer[0 .. (stream.pos + crypto.SAMPLE_LEN) + 14];
    var encrypted_payload = stream.buffer[((stream.pos + crypto.SAMPLE_LEN) + 14)..(stream.pos + header.remainder_len)];

    // var payload: []u8 = undefined;
    try aead.decryptPayload(header.packet_number, header_bytes, encrypted_payload);
    // try aead.decryptPayload(header.packet_number, pn_and_sample, encrypted_payload, payload);

    // std.log.info("final payload: (len: {any}) {any}", .{ payload.len, payload });
}

// inline
pub fn isLongHeader(first_byte: u8) bool {
    return (first_byte & LONG_HEADER_BIT) == LONG_HEADER_BIT;
}

pub fn parseQuicHeader(stream: anytype) !Header {
    const reader = stream.reader();
    const first_byte = try reader.readByte();

    var header = Header{};

    if (isLongHeader(first_byte)) {
        log.info("LONG HEADER!", .{});

        var version = try reader.readInt(u32, endian);
        header.version = version;

        log.info("version: {any}", .{header.version});

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
        std.log.info("scid: {any}", .{header.scid});

        // advance scid_length
        try stream.seekBy(scid_length);

        if (header.version == undefined) {
            // version negotiation
            //
            // TODO:
            // remainder_len = @intCast(u32, bytes.len) - @intCast(u32, stream.pos);
            std.log.info("TODO: negotiation!", .{});
        } else {
            if ((first_byte & FIXED_BIT) == 0) {
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

                    var token_length = try readVarInt(reader);
                    if (token_length > 0) {
                        //
                        // Token:  The value of the token that was previously provided in a
                        //    Retry packet or NEW_TOKEN frame; see Section 8.1.
                        //
                        header.token = stream.buffer[stream.pos..(stream.pos + token_length)];
                        try stream.seekBy(@intCast(i64, token_length));
                    } else {
                        std.log.warn("no token!", .{});
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

pub fn negotiateVersion(header: Header, writer: anytype) !void {
    try writer.writeByte(random.int(u8) | LONG_HEADER_BIT);
    try writer.writeInt(u32, 0, endian);

    try writer.writeByte(@intCast(u8, header.scid.len));
    try writer.writeAll(header.scid);

    try writer.writeByte(@intCast(u8, header.dcid.len));
    try writer.writeAll(header.dcid);

    for (protocol.SUPPORTED_VERSIONS) |version| {
        try writer.writeInt(u32, version, endian);
    }
}

pub fn retry(
    header: Header,
    new_scid: []u8, // original destination connection id
    token: []u8,
    writer: anytype,
) !void {
    var hdr = Header{
        .version = header.version,
        .packet_type = PacketType.Retry,
        .dcid = header.scid,
        .scid = new_scid,
        .token = token,
        .packet_number = 0,
        .packet_number_len = 0,
    };

    try hdr.encode(writer);

    const integrity_tag = try computeRetryIntegrityTag(writer.context.getWritten(), header.dcid, header.version);
    std.log.info("integrity_tag: {any}", .{integrity_tag});

    try writer.writeAll(&integrity_tag);
}

///
/// Compute the integrity tag for a RETRY packet.
///
/// ---------------------------------------------
///
/// Retry packets carry a Retry Integrity Tag that provides two properties: it
/// allows the discarding of packets that have accidentally been corrupted by the
/// network, and only an entity that observes an Initial packet can send a valid
/// Retry packet.
///
/// - Retry Packets: https://datatracker.ietf.org/doc/html/rfc9000#section-17.2.5
/// - Retry Packet Integrity: https://datatracker.ietf.org/doc/html/rfc9001#section-5.8
///
fn computeRetryIntegrityTag(
    packet_bytes_without_tag: []u8,
    odcid: []const u8,
    version: u32,
) ![crypto.Aead.tag_length]u8 {
    _ = version;

    //
    // The secret key and the nonce are values derived by calling HKDF-
    // Expand-Label using
    // 0xd9c9943e6101fd200021506bcc02814c73030f25c79d71ce876eca876e6fca8e as
    // the secret, with labels being "quic key" and "quic iv" (Section 5.1).
    //
    // https://datatracker.ietf.org/doc/html/rfc9001#section-5.8
    //

    // Implementation references
    // - aiortc/aioquic: https://github.com/aiortc/aioquic/blob/444be09157aed3c81881d18647484165dd07139c/src/aioquic/quic/packet.py#L92-L116
    // - lucas-clemente/quic-go: https://github.com/lucas-clemente/quic-go/blob/2de4af00d06891b8b110965a2aa44b0a84dcc71b/internal/handshake/retry.go#L43-L62

    var key = RETRY_INTEGRITY_KEY_V1;
    var nonce = RETRY_INTEGRITY_NONCE_V1;

    // TODO: avoid using dynamic allocation
    const allocator = std.heap.page_allocator;
    var buf = try allocator.alloc(u8, odcid.len + packet_bytes_without_tag.len + 1);
    defer allocator.free(buf);

    var stream = io.fixedBufferStream(buf);
    var buf_writer = stream.writer();
    try buf_writer.writeByte(@intCast(u8, odcid.len));
    try buf_writer.writeAll(odcid);
    try buf_writer.writeAll(packet_bytes_without_tag);

    // encrypt with associated data only
    const m = "";
    var c: [m.len]u8 = undefined;
    var tag: [crypto.Aead.tag_length]u8 = undefined;
    crypto.Aead.encrypt(&c, &tag, m, buf_writer.context.buffer, nonce, key);

    return tag;
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

fn writeVarInt(writer: anytype, value: u64) !void {
    _ = writer;
    _ = value;

    std.log.err("TODO: writeVarInt not implemented yet.", .{});

    // /// Writes the given integer as variable-length encoded, into the current position of the buffer,
    // /// advancing the position.
    // pub fn putVarInt(self: *Self, value: u64) Error!void {
    //     const length = varIntLength(value);
    //
    //     try self.putVarIntWithLength(value, length);
    // }
    //
    // /// Writes the given integer as variable-length encoded in the specified length, into the current
    // /// position of the buffer, advancing the position.
    // pub fn putVarIntWithLength(self: *Self, value: u64, length: usize) Error!void {
    //     var rest = self.buf[self.pos..];
    //     if (rest.len < length)
    //         return Error.BufferTooShort;
    //
    //     switch (length) {
    //         1 => try self.put(u8, @truncate(u8, value) | (0b00 << 6)),
    //         2 => try self.put(u16, @truncate(u16, value) | (0b01 << 14)),
    //         4 => try self.put(u32, @truncate(u32, value) | (0b10 << 30)),
    //         8 => try self.put(u64, value | (0b11 << 62)),
    //         else => unreachable,
    //     }
    // }
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
