const std = @import("std");
const io = std.io;
const posix = std.posix;
const log = std.log;
const time = std.time;
const assert = std.debug.assert;
const random = std.crypto.random;
// const tls = std.crypto.tls;

const protocol = @import("protocol.zig");
const crypto = @import("crypto.zig");
const util = @import("util.zig");
const stream = @import("stream.zig");

// network byte order
pub const ENDIAN = std.builtin.Endian.big;

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
pub const RETRY_INTEGRITY_TAG_SIZE = 16;
const RETRY_INTEGRITY_KEY_V1: [crypto.key_len]u8 = .{ 0xbe, 0x0c, 0x69, 0x0b, 0x9f, 0x66, 0x57, 0x5a, 0x1d, 0x76, 0x6b, 0x54, 0xe3, 0x68, 0xc8, 0x4e };
const RETRY_INTEGRITY_NONCE_V1: [crypto.nonce_len]u8 = .{ 0x46, 0x15, 0x99, 0xd3, 0x5d, 0x63, 0x2b, 0xf2, 0x23, 0x98, 0x25, 0xbb };

pub const PacketType = enum(u8) {
    /// Initial packet
    initial = LONG_HEADER_BIT | FIXED_BIT | 0x00,

    /// Retry packet
    retry = LONG_HEADER_BIT | FIXED_BIT | 0x30,

    /// Handshake packet
    handshake = LONG_HEADER_BIT | FIXED_BIT | 0x20,

    /// 0-RTT packet
    zero_rtt = LONG_HEADER_BIT | FIXED_BIT | 0x10,

    /// Version negotiation packet
    version_negotiation = 0,

    /// 1-RTT short header packet
    one_rtt = FIXED_BIT,

    _,
};

pub const Epoch = enum(u8) {
    initial = 0,
    zero_rtt = 1,
    handshake = 2,
    application = 3,

    pub fn fromPacketType(int: PacketType) !Epoch {
        return switch (int) {
            PacketType.initial => Epoch.initial,
            PacketType.zero_rtt => Epoch.zero_rtt,
            PacketType.handshake => Epoch.handshake,
            PacketType.one_rtt => Epoch.application,
            else => error.InvalidPacketType,
        };
    }
};

test "Epoch fromPacketType" {
    try std.testing.expectEqual(Epoch.fromPacketType(PacketType.initial), Epoch.initial);
    try std.testing.expectEqual(Epoch.fromPacketType(PacketType.zero_rtt), Epoch.zero_rtt);
    try std.testing.expectEqual(Epoch.fromPacketType(PacketType.handshake), Epoch.handshake);
    try std.testing.expectEqual(Epoch.fromPacketType(PacketType.one_rtt), Epoch.application);

    const err = Epoch.fromPacketType(PacketType.retry);
    try std.testing.expectError(error.InvalidPacketType, err);
}

pub const PacketError = error{
    InvalidVersion,
    InvalidPacket,
    InvalidPacketType,
    InvalidVarLength,
};

pub const ErrorCode = enum(u16) {
    no_error = 0x0,
    internal_error = 0x1,
    connection_refused = 0x2,
    flow_control_error = 0x3,
    stream_limit_error = 0x4,
    stream_state_error = 0x5,
    final_size_error = 0x6,
    frame_encoding_error = 0x7,
    transport_parameter_error = 0x8,
    connection_id_limit_error = 0x9,
    protocol_violation = 0xa,
    invalid_token = 0xb,
    application_error = 0xc,
    crypto_buffer_exceeded = 0xd,
    key_update_error = 0xe,
    aead_limit_reached = 0xf,
    crypto_error = 0x100,
};

/// A QUIC packet's header.
pub const Header = struct {
    const Self = @This();

    version: u32 = 0,
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

    /// The spin bit for passive RTT measurement (RFC 9000 §17.4).
    /// Only meaningful for short (1-RTT) headers.
    spin_bit: bool = false,

    /// The offset of this packet's first byte within the buffer.
    /// Used to correctly handle coalesced packets.
    packet_start: usize = 0,

    pub fn parse(fbs: anytype, short_dcid_len: u8) !Header {
        return parseQuicHeader(fbs, short_dcid_len);
    }

    pub fn encode(self: *Self, writer: anytype) !void {
        var first: usize = 0;

        // encode pkt num length.
        first |= (self.packet_number_len -| 1); // (saturating sub)

        // encode short header
        if (self.packet_type == PacketType.one_rtt) {
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

            try writer.writeByte(@intCast(first));
            try writer.writeAll(self.dcid);

            return;
        }

        // encode long header https://datatracker.ietf.org/doc/html/rfc9000#long-packet-types
        const ty: u8 = switch (self.packet_type) {
            PacketType.initial => 0x00,
            PacketType.zero_rtt => 0x01,
            PacketType.handshake => 0x02,
            PacketType.retry => 0x03,
            else => return error.InvalidPacket,
        };

        first |= LONG_HEADER_BIT | FIXED_BIT | (ty << 4);

        try writer.writeByte(@intCast(first));
        try writer.writeInt(u32, self.version, ENDIAN);

        try writer.writeByte(@intCast(self.dcid.len));
        try writer.writeAll(self.dcid);

        try writer.writeByte(@intCast(self.scid.len));
        try writer.writeAll(self.scid);

        // Only Initial and Retry packets have a token.
        switch (self.packet_type) {
            PacketType.initial => {
                if (self.token) |t| {
                    try writeVarInt(writer, t.len);
                    try writer.writeAll(t);
                } else {
                    try writeVarInt(writer, 0);
                }
            },

            PacketType.retry => {
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

    crypto_open: ?crypto.Open = null,
    crypto_seal: ?crypto.Seal = null,

    // crypto_0rtt_open: Option<crypto::Open>,
    // crypto_0rtt_seal: Option<crypto::Seal>,

    // crypto_stream: stream.Stream = stream.Stream{},
    crypto_stream: stream.Stream = undefined,

    pub fn cryptoTagLen(self: *PacketNumSpace) usize {
        _ = self;
        return crypto.Aead.tag_length;
    }

    pub fn setupInitial(self: *PacketNumSpace, dcid: []const u8, version: u32, comptime is_server: bool) !void {
        const keys = try crypto.deriveInitialKeyMaterial(dcid, version, is_server);
        self.crypto_open = keys[0];
        self.crypto_seal = keys[1];
    }
};

pub fn parseIncoming(bytes: []const u8) void {
    _ = bytes;
}

pub fn decrypt(header: *Header, fbs: anytype, space: PacketNumSpace) ![]u8 {
    // We need at least 4 bytes for packet number + 16 for sample
    if (fbs.pos + 4 + crypto.SAMPLE_LEN > fbs.buffer.len) {
        std.log.err("Not enough data for packet number + sample: pos={d}, buffer.len={d}", .{ fbs.pos, fbs.buffer.len });
        return error.InvalidPacket;
    }

    var first_byte = fbs.buffer[header.packet_start];

    // unprotect header
    var aead = space.crypto_open.?;

    // RFC 9001 Section 5.4.2: Sample is taken 4 bytes after START of packet number field
    const sample_offset = fbs.pos + 4;
    if (sample_offset + crypto.SAMPLE_LEN > fbs.buffer.len) {
        std.log.err("Not enough data for sample: offset={d}, buffer.len={d}", .{ sample_offset, fbs.buffer.len });
        return error.InvalidPacket;
    }

    var sample_buf: [crypto.SAMPLE_LEN]u8 = undefined;
    @memcpy(&sample_buf, fbs.buffer[sample_offset..][0..crypto.SAMPLE_LEN]);

    const mask = aead.newMask(&sample_buf);

    if (isLongHeader(first_byte)) {
        first_byte ^= (mask[0] & 0x0f);
    } else {
        first_byte ^= (mask[0] & 0x1f);
    }

    // Extract key phase and spin bits from unprotected short header (RFC 9001 §5.4.1, RFC 9000 §17.4)
    if (!isLongHeader(first_byte)) {
        header.key_phase = (first_byte & KEY_PHASE_BIT) != 0;
        header.spin_bit = (first_byte & PACKET_SPIN_BIT) != 0;
    }

    // Calculate packet number length from the unprotected first byte BEFORE using it
    header.packet_number_len = @as(usize, @intCast(first_byte & PACKET_NUM_MASK)) + 1;

    // Remove header protection from packet number bytes
    var i: usize = 0;
    while (i < header.packet_number_len) : (i += 1) {
        fbs.buffer[fbs.pos + i] ^= mask[1 + i];
    }

    // Now extract the decrypted packet number
    const pn_ciphertext: *const [MAX_PACKET_NUMBER_LEN]u8 = fbs.buffer[fbs.pos..][0..MAX_PACKET_NUMBER_LEN];

    // read truncated/raw packet number
    const truncated_packet_number: u64 = try switch (header.packet_number_len) {
        1 => @as(u64, std.mem.readInt(u8, pn_ciphertext.*[0..util.sizeOf(u8)], ENDIAN)),
        2 => @as(u64, std.mem.readInt(u16, pn_ciphertext.*[0..util.sizeOf(u16)], ENDIAN)),
        3 => @as(u64, std.mem.readInt(u24, pn_ciphertext.*[0..util.sizeOf(u24)], ENDIAN)),
        4 => @as(u64, std.mem.readInt(u32, pn_ciphertext.*[0..util.sizeOf(u32)], ENDIAN)),
        else => error.InvalidPacket,
    };

    // Skip the packet number bytes in the buffer
    try fbs.seekBy(@intCast(header.packet_number_len));

    const payload_len = header.remainder_len - header.packet_number_len;

    // RFC 9001 Section 5.2: AD includes the unprotected first byte and everything up to and including packet number
    // For coalesced packets, use packet_start to get the correct offset within the buffer
    const pkt_start = header.packet_start;
    const header_len = fbs.pos - pkt_start; // total header length including packet number
    var header_bytes_buf: [512]u8 = undefined;
    // Copy first byte as unprotected
    header_bytes_buf[0] = first_byte;
    // Copy the rest of the header and packet number (from byte after first to current position)
    @memcpy(header_bytes_buf[1..][0..(header_len - 1)], fbs.buffer[(pkt_start + 1)..fbs.pos]);
    const header_bytes = header_bytes_buf[0..header_len];
    const encrypted_payload = fbs.buffer[(fbs.pos)..(fbs.pos + payload_len)];

    // Decode packet number
    header.packet_number = decodePacketNumber(space.next_packet_number, truncated_packet_number, header.packet_number_len * 8);

    const decrypted = try aead.decryptPayload(
        header.packet_number,
        header_bytes,
        encrypted_payload,
    );

    // Write decrypted first byte back into the input buffer for further processing.
    fbs.buffer[header.packet_start] = first_byte;

    return decrypted;
}

/// Decrypt a 1-RTT packet using the KeyUpdateManager for key phase handling.
/// Uses the (unchanging) HP key for header unprotection, then selects the
/// appropriate AEAD keys based on the key phase bit (RFC 9001 Section 6).
pub fn decryptWithKeyUpdate(header: *Header, fbs: anytype, space: *PacketNumSpace, ku: *crypto.KeyUpdateManager) ![]u8 {
    if (fbs.pos + 4 + crypto.SAMPLE_LEN > fbs.buffer.len) {
        return error.InvalidPacket;
    }

    var first_byte = fbs.buffer[header.packet_start];

    // Use the HP open key (never changes across key updates)
    const sample_offset = fbs.pos + 4;
    if (sample_offset + crypto.SAMPLE_LEN > fbs.buffer.len) {
        return error.InvalidPacket;
    }

    var sample_buf: [crypto.SAMPLE_LEN]u8 = undefined;
    @memcpy(&sample_buf, fbs.buffer[sample_offset..][0..crypto.SAMPLE_LEN]);

    // Generate mask using the invariant HP key (cipher-suite-aware)
    const mask_arr = crypto.computeHpMask(&sample_buf, ku.hp_open, ku.cipher_suite);
    const mask = &mask_arr;

    // Short header unmasking
    first_byte ^= (mask[0] & 0x1f);

    // Extract key phase and spin bits from unprotected first byte
    header.key_phase = (first_byte & KEY_PHASE_BIT) != 0;
    header.spin_bit = (first_byte & PACKET_SPIN_BIT) != 0;

    header.packet_number_len = @as(usize, @intCast(first_byte & PACKET_NUM_MASK)) + 1;

    // Unmask packet number bytes
    var i: usize = 0;
    while (i < header.packet_number_len) : (i += 1) {
        fbs.buffer[fbs.pos + i] ^= mask[1 + i];
    }

    // Extract truncated packet number
    const pn_ciphertext: *const [MAX_PACKET_NUMBER_LEN]u8 = fbs.buffer[fbs.pos..][0..MAX_PACKET_NUMBER_LEN];
    const truncated_packet_number: u64 = try switch (header.packet_number_len) {
        1 => @as(u64, std.mem.readInt(u8, pn_ciphertext.*[0..util.sizeOf(u8)], ENDIAN)),
        2 => @as(u64, std.mem.readInt(u16, pn_ciphertext.*[0..util.sizeOf(u16)], ENDIAN)),
        3 => @as(u64, std.mem.readInt(u24, pn_ciphertext.*[0..util.sizeOf(u24)], ENDIAN)),
        4 => @as(u64, std.mem.readInt(u32, pn_ciphertext.*[0..util.sizeOf(u32)], ENDIAN)),
        else => error.InvalidPacket,
    };

    try fbs.seekBy(@intCast(header.packet_number_len));

    const payload_len = header.remainder_len - header.packet_number_len;

    // Build associated data
    const pkt_start = header.packet_start;
    const header_len = fbs.pos - pkt_start;
    var header_bytes_buf: [512]u8 = undefined;
    header_bytes_buf[0] = first_byte;
    @memcpy(header_bytes_buf[1..][0..(header_len - 1)], fbs.buffer[(pkt_start + 1)..fbs.pos]);
    const header_bytes = header_bytes_buf[0..header_len];
    const encrypted_payload = fbs.buffer[(fbs.pos)..(fbs.pos + payload_len)];

    // Decode packet number
    header.packet_number = decodePacketNumber(space.next_packet_number, truncated_packet_number, header.packet_number_len * 8);

    // Select the right Open keys based on key phase
    var aead = ku.getOpenKeys(header.key_phase) orelse return error.InvalidPacket;

    const decrypted = try aead.decryptPayload(
        header.packet_number,
        header_bytes,
        encrypted_payload,
    );

    fbs.buffer[header.packet_start] = first_byte;

    return decrypted;
}

// inline
pub fn isLongHeader(first_byte: u8) bool {
    return (first_byte & LONG_HEADER_BIT) == LONG_HEADER_BIT;
}

pub fn parseQuicHeader(fbs: anytype, short_dcid_len: u8) !Header {
    const packet_start_pos = fbs.pos;
    const reader = fbs.reader();
    const first_byte = try reader.readByte();

    var header = Header{};
    header.packet_start = packet_start_pos;

    if (isLongHeader(first_byte)) {
        // Long header packet

        const version = try reader.readInt(u32, ENDIAN);
        header.version = version;

        const dcid_length = try reader.readByte();
        if (dcid_length > CONNECTION_ID_MAX_SIZE) {
            std.log.err("Destination CID is too long ({any} bytes)", .{dcid_length});
            return error.PacketError;
        }

        header.dcid = fbs.buffer[fbs.pos..(fbs.pos + dcid_length)];

        // advance length
        try fbs.seekBy(dcid_length);

        const scid_length = try reader.readByte();
        if (scid_length > CONNECTION_ID_MAX_SIZE) {
            std.log.err("Source CID is too long ({any} bytes)", .{scid_length});
            return error.InvalidPacket;
        }

        header.scid = fbs.buffer[fbs.pos..(fbs.pos + scid_length)];

        // advance scid_length
        try fbs.seekBy(scid_length);

        if ((first_byte & FIXED_BIT) == 0) {
            std.log.err("Packet fixed bit is zero", .{});
            return error.InvalidPacket;
        }

        header.packet_type = @enumFromInt(first_byte & PACKET_TYPE_MASK);

        switch (header.packet_type) {
            PacketType.initial => {
                // NOTE: RFC 9000 Section 8.1 requires clients to send Initial packets
                // with at least 1200 bytes payload. This is validated when sending (in packet_packer),
                // not when receiving, since the server may send smaller Initial packets.

                const token_length = try readVarInt(reader);
                if (token_length > 0) {
                    header.token = fbs.buffer[fbs.pos..(fbs.pos + token_length)];
                    try fbs.seekBy(@intCast(token_length));
                }

                header.remainder_len = try readVarInt(reader);
            },

            PacketType.retry => {
                // Retry packet: everything after header, before 16-byte integrity tag, is the token
                const remaining = fbs.buffer.len - fbs.pos;
                if (remaining > RETRY_INTEGRITY_TAG_SIZE) {
                    header.token = fbs.buffer[fbs.pos .. fbs.buffer.len - RETRY_INTEGRITY_TAG_SIZE];
                }
                header.remainder_len = 0;
            },

            PacketType.version_negotiation => {},

            PacketType.handshake, PacketType.zero_rtt => {
                // Long header packets (like Initial but without Token field)
                header.remainder_len = try readVarInt(reader);
            },

            PacketType.one_rtt => {
                // Short header packet (1-RTT)
                if (fbs.pos + short_dcid_len <= fbs.buffer.len) {
                    header.dcid = fbs.buffer[fbs.pos..(fbs.pos + short_dcid_len)];
                    try fbs.seekBy(short_dcid_len);
                }

                header.remainder_len = fbs.buffer.len - fbs.pos;
            },

            else => {
                std.log.err("Packet type not recognized: {any}", .{header.packet_type});
                header.remainder_len = try readVarInt(reader);
            },
        }
    } else {
        // Short header (1-RTT) packet

        header.packet_type = PacketType.one_rtt;

        // Short header: first_byte + DCID (known length from connection state) + payload
        if (fbs.pos + short_dcid_len <= fbs.buffer.len) {
            header.dcid = fbs.buffer[fbs.pos..(fbs.pos + short_dcid_len)];
            try fbs.seekBy(short_dcid_len);
        }

        header.remainder_len = fbs.buffer.len - fbs.pos;
    }

    return header;
}

pub fn negotiateVersion(header: Header, writer: anytype) !void {
    try writer.writeByte(random.int(u8) | LONG_HEADER_BIT);
    try writer.writeInt(u32, 0, ENDIAN);

    try writer.writeByte(@intCast(header.scid.len));
    try writer.writeAll(header.scid);

    try writer.writeByte(@intCast(header.dcid.len));
    try writer.writeAll(header.dcid);

    for (protocol.SUPPORTED_VERSIONS) |version| {
        try writer.writeInt(u32, version, ENDIAN);
    }
}

pub fn retry(
    header: Header,
    new_scid: []u8, // original destination connection id
    token: []u8,
    fbs: anytype,
) !void {
    const writer = fbs.writer();
    var hdr = Header{
        .version = header.version,
        .packet_type = PacketType.retry,
        .dcid = header.scid,
        .scid = new_scid,
        .token = token,
        .packet_number = 0,
        .packet_number_len = 0,
    };

    try hdr.encode(writer);

    const integrity_tag = try computeRetryIntegrityTag(fbs.getWritten(), header.dcid, header.version);

    try writer.writeAll(&integrity_tag);
}

pub fn packetNumberLength(pn: u64) !usize {
    if (pn < std.math.maxInt(u8)) {
        return 1;
    } else if (pn < std.math.maxInt(u16)) {
        return 2;
    } else if (pn < std.math.maxInt(u32)) {
        return 4;
    } else {
        return error.InvalidPacket;
    }
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
pub fn computeRetryIntegrityTag(
    packet_bytes_without_tag: []const u8,
    odcid: []const u8,
    version: u32,
) ![crypto.Aead.tag_length]u8 {
    _ = version;

    const key = RETRY_INTEGRITY_KEY_V1;
    const nonce = RETRY_INTEGRITY_NONCE_V1;

    // Use stack buffer: 1 (odcid_len) + 20 (max odcid) + ~1300 (max packet) = 1321
    var buf: [1400]u8 = undefined;
    var inner_fbs = io.fixedBufferStream(&buf);
    const buf_writer = inner_fbs.writer();
    try buf_writer.writeByte(@intCast(odcid.len));
    try buf_writer.writeAll(odcid);
    try buf_writer.writeAll(packet_bytes_without_tag);

    const m = "";
    var c: [m.len]u8 = undefined;
    var tag: [crypto.Aead.tag_length]u8 = undefined;
    crypto.Aead.encrypt(&c, &tag, m, inner_fbs.getWritten(), nonce, key);

    return tag;
}

// Verify the integrity tag of a received Retry packet.
pub fn verifyRetryIntegrity(
    raw_packet: []const u8,
    odcid: []const u8,
    version: u32,
) !bool {
    if (raw_packet.len < RETRY_INTEGRITY_TAG_SIZE) return false;
    const packet_without_tag = raw_packet[0 .. raw_packet.len - RETRY_INTEGRITY_TAG_SIZE];
    const received_tag = raw_packet[raw_packet.len - RETRY_INTEGRITY_TAG_SIZE ..];
    const expected_tag = try computeRetryIntegrityTag(packet_without_tag, odcid, version);
    return std.mem.eql(u8, received_tag, &expected_tag);
}

// Encrypted Retry token format:
// nonce(12) || AES-128-GCM-encrypt(plaintext) || tag(16)
// Plaintext: odcid_len(1) + odcid(<=20) + retry_scid_len(1) + retry_scid(<=20) + timestamp_ns(8) + addr_data(14)
pub const TOKEN_NONCE_LEN = 12;
pub const TOKEN_TAG_LEN = 16;
pub const TOKEN_MAX_PLAINTEXT_LEN = 1 + 20 + 1 + 20 + 8 + 14; // 64
pub const TOKEN_MAX_LEN = TOKEN_NONCE_LEN + TOKEN_MAX_PLAINTEXT_LEN + TOKEN_TAG_LEN; // 92

pub fn generateRetryToken(
    out: []u8,
    odcid: []const u8,
    retry_scid: []const u8,
    client_addr: posix.sockaddr,
    token_key: [crypto.key_len]u8,
) !usize {
    if (out.len < TOKEN_MAX_LEN) return error.BufferTooSmall;

    // Generate random nonce
    var nonce: [TOKEN_NONCE_LEN]u8 = undefined;
    random.bytes(&nonce);
    @memcpy(out[0..TOKEN_NONCE_LEN], &nonce);

    // Build plaintext
    var plaintext: [TOKEN_MAX_PLAINTEXT_LEN]u8 = undefined;
    var pt_fbs = io.fixedBufferStream(&plaintext);
    const pt_writer = pt_fbs.writer();
    try pt_writer.writeByte(@intCast(odcid.len));
    try pt_writer.writeAll(odcid);
    try pt_writer.writeByte(@intCast(retry_scid.len));
    try pt_writer.writeAll(retry_scid);
    const now: i64 = @intCast(time.nanoTimestamp());
    try pt_writer.writeInt(i64, now, ENDIAN);
    // Write first 14 bytes of sockaddr.data (covers IPv4 port+addr)
    try pt_writer.writeAll(client_addr.data[0..14]);

    const pt_len = pt_fbs.pos;
    const pt_data = plaintext[0..pt_len];

    // Encrypt: no AD, just nonce+key
    var ciphertext_buf: [TOKEN_MAX_PLAINTEXT_LEN]u8 = undefined;
    var tag: [TOKEN_TAG_LEN]u8 = undefined;
    crypto.Aead.encrypt(
        ciphertext_buf[0..pt_len],
        &tag,
        pt_data,
        "",
        nonce,
        token_key,
    );

    @memcpy(out[TOKEN_NONCE_LEN..][0..pt_len], ciphertext_buf[0..pt_len]);
    @memcpy(out[TOKEN_NONCE_LEN + pt_len ..][0..TOKEN_TAG_LEN], &tag);

    return TOKEN_NONCE_LEN + pt_len + TOKEN_TAG_LEN;
}

pub const ValidatedToken = struct {
    odcid_buf: [20]u8 = .{0} ** 20,
    odcid_len: u8 = 0,
    retry_scid_buf: [20]u8 = .{0} ** 20,
    retry_scid_len: u8 = 0,

    pub fn getOdcid(self: *const ValidatedToken) []const u8 {
        return self.odcid_buf[0..self.odcid_len];
    }

    pub fn getRetryScid(self: *const ValidatedToken) []const u8 {
        return self.retry_scid_buf[0..self.retry_scid_len];
    }
};

// Token validity duration: 60 seconds
const TOKEN_MAX_AGE_NS: i64 = 60 * std.time.ns_per_s;

pub fn validateRetryToken(
    token_data: []const u8,
    client_addr: posix.sockaddr,
    token_key: [crypto.key_len]u8,
) !?ValidatedToken {
    if (token_data.len < TOKEN_NONCE_LEN + TOKEN_TAG_LEN + 2) return null;

    const nonce = token_data[0..TOKEN_NONCE_LEN].*;
    const ct_len = token_data.len - TOKEN_NONCE_LEN - TOKEN_TAG_LEN;
    const ciphertext = token_data[TOKEN_NONCE_LEN..][0..ct_len];
    const tag = token_data[token_data.len - TOKEN_TAG_LEN ..][0..TOKEN_TAG_LEN].*;

    // Decrypt
    var plaintext: [TOKEN_MAX_PLAINTEXT_LEN]u8 = undefined;
    crypto.Aead.decrypt(
        plaintext[0..ct_len],
        ciphertext,
        tag,
        "",
        nonce,
        token_key,
    ) catch return null; // decryption failed = invalid token

    // Parse plaintext
    var pt_fbs = io.fixedBufferStream(plaintext[0..ct_len]);
    const pt_reader = pt_fbs.reader();

    var result = ValidatedToken{};

    // Read ODCID
    result.odcid_len = pt_reader.readByte() catch return null;
    if (result.odcid_len > 20) return null;
    _ = pt_reader.readAll(result.odcid_buf[0..result.odcid_len]) catch return null;

    // Read retry SCID
    result.retry_scid_len = pt_reader.readByte() catch return null;
    if (result.retry_scid_len > 20) return null;
    _ = pt_reader.readAll(result.retry_scid_buf[0..result.retry_scid_len]) catch return null;

    // Read timestamp and check age
    const timestamp = pt_reader.readInt(i64, ENDIAN) catch return null;
    const now: i64 = @intCast(time.nanoTimestamp());
    if (now - timestamp > TOKEN_MAX_AGE_NS or timestamp > now) return null;

    // Check address
    var addr_data: [14]u8 = undefined;
    _ = pt_reader.readAll(&addr_data) catch return null;
    if (!std.mem.eql(u8, &addr_data, client_addr.data[0..14])) return null;

    return result;
}

// NEW_TOKEN token format (RFC 9000 §8.1.3):
// nonce(12) || AES-128-GCM-encrypt(plaintext) || tag(16)
// Plaintext: timestamp_ns(8) + addr_data(14) = 22 bytes
// Distinguishable from Retry tokens by shorter ciphertext.
const NEW_TOKEN_PLAINTEXT_LEN: usize = 8 + 14; // timestamp + addr
const NEW_TOKEN_MAX_LEN: usize = TOKEN_NONCE_LEN + NEW_TOKEN_PLAINTEXT_LEN + TOKEN_TAG_LEN; // 50

pub fn generateNewToken(
    out: []u8,
    client_addr: posix.sockaddr,
    token_key: [crypto.key_len]u8,
) !usize {
    if (out.len < NEW_TOKEN_MAX_LEN) return error.BufferTooSmall;

    var nonce: [TOKEN_NONCE_LEN]u8 = undefined;
    random.bytes(&nonce);
    @memcpy(out[0..TOKEN_NONCE_LEN], &nonce);

    var plaintext: [NEW_TOKEN_PLAINTEXT_LEN]u8 = undefined;
    var pt_fbs = io.fixedBufferStream(&plaintext);
    const pt_writer = pt_fbs.writer();
    const now: i64 = @intCast(time.nanoTimestamp());
    try pt_writer.writeInt(i64, now, ENDIAN);
    try pt_writer.writeAll(client_addr.data[0..14]);

    var ciphertext_buf: [NEW_TOKEN_PLAINTEXT_LEN]u8 = undefined;
    var tag: [TOKEN_TAG_LEN]u8 = undefined;
    crypto.Aead.encrypt(
        &ciphertext_buf,
        &tag,
        &plaintext,
        "",
        nonce,
        token_key,
    );

    @memcpy(out[TOKEN_NONCE_LEN..][0..NEW_TOKEN_PLAINTEXT_LEN], &ciphertext_buf);
    @memcpy(out[TOKEN_NONCE_LEN + NEW_TOKEN_PLAINTEXT_LEN ..][0..TOKEN_TAG_LEN], &tag);

    return NEW_TOKEN_MAX_LEN;
}

pub fn validateNewToken(
    token_data: []const u8,
    client_addr: posix.sockaddr,
    token_key: [crypto.key_len]u8,
) bool {
    if (token_data.len != NEW_TOKEN_MAX_LEN) return false;

    const nonce = token_data[0..TOKEN_NONCE_LEN].*;
    const ciphertext = token_data[TOKEN_NONCE_LEN..][0..NEW_TOKEN_PLAINTEXT_LEN];
    const tag = token_data[token_data.len - TOKEN_TAG_LEN ..][0..TOKEN_TAG_LEN].*;

    var plaintext: [NEW_TOKEN_PLAINTEXT_LEN]u8 = undefined;
    crypto.Aead.decrypt(
        &plaintext,
        ciphertext,
        tag,
        "",
        nonce,
        token_key,
    ) catch return false;

    var pt_fbs = io.fixedBufferStream(&plaintext);
    const pt_reader = pt_fbs.reader();

    const timestamp = pt_reader.readInt(i64, ENDIAN) catch return false;
    const now: i64 = @intCast(time.nanoTimestamp());
    if (now - timestamp > TOKEN_MAX_AGE_NS or timestamp > now) return false;

    var addr_data: [14]u8 = undefined;
    _ = pt_reader.readAll(&addr_data) catch return false;
    if (!std.mem.eql(u8, &addr_data, client_addr.data[0..14])) return false;

    return true;
}

pub fn readVarInt(reader: anytype) !u64 {
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
    var len: i32 = @as(i32, 1) << @intCast((first_byte & 0xc0) >> 6);
    len = len - 1;

    var value: u64 = first_byte & 0x3F;
    while (len > 0) {
        len = len - 1;
        value = (value << 8);

        const red = try reader.readByte();
        value = value + red;
    }

    return value;
}

/// Returns the number of bytes needed to encode a value as a QUIC variable-length integer.
pub fn varIntLength(value: u64) usize {
    if (value <= 63) return 1;
    if (value <= 16383) return 2;
    if (value <= 1073741823) return 4;
    return 8;
}

/// Writes a QUIC variable-length integer (RFC 9000 Section 16).
pub fn writeVarInt(writer: anytype, value: u64) !void {
    if (value <= 63) {
        // 1-byte encoding: 00xxxxxx
        try writer.writeByte(@intCast(value));
    } else if (value <= 16383) {
        // 2-byte encoding: 01xxxxxx xxxxxxxx
        try writer.writeInt(u16, @intCast(value | (0b01 << 14)), ENDIAN);
    } else if (value <= 1073741823) {
        // 4-byte encoding: 10xxxxxx xxxxxxxx xxxxxxxx xxxxxxxx
        try writer.writeInt(u32, @intCast(value | (0b10 << 30)), ENDIAN);
    } else if (value <= 4611686018427387903) {
        // 8-byte encoding: 11xxxxxx xxxxxxxx ... xxxxxxxx
        try writer.writeInt(u64, value | (0b11 << 62), ENDIAN);
    } else {
        return error.VarIntTooLarge;
    }
}

test "QUIC: Variable-Length Integer Encoding" {
    // 1-byte encoding
    {
        var buf: [8]u8 = undefined;
        var fbs = io.fixedBufferStream(&buf);
        try writeVarInt(fbs.writer(), 37);
        try std.testing.expectEqualSlices(u8, &[_]u8{0x25}, fbs.getWritten());
    }
    // 2-byte encoding
    {
        var buf: [8]u8 = undefined;
        var fbs = io.fixedBufferStream(&buf);
        try writeVarInt(fbs.writer(), 15293);
        try std.testing.expectEqualSlices(u8, &[_]u8{ 0x7b, 0xbd }, fbs.getWritten());
    }
    // 4-byte encoding
    {
        var buf: [8]u8 = undefined;
        var fbs = io.fixedBufferStream(&buf);
        try writeVarInt(fbs.writer(), 494878333);
        try std.testing.expectEqualSlices(u8, &[_]u8{ 0x9d, 0x7f, 0x3e, 0x7d }, fbs.getWritten());
    }
    // 8-byte encoding
    {
        var buf: [8]u8 = undefined;
        var fbs = io.fixedBufferStream(&buf);
        try writeVarInt(fbs.writer(), 151288809941952652);
        try std.testing.expectEqualSlices(u8, &[_]u8{ 0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c }, fbs.getWritten());
    }
}

test "QUIC: varIntLength" {
    try std.testing.expectEqual(@as(usize, 1), varIntLength(0));
    try std.testing.expectEqual(@as(usize, 1), varIntLength(63));
    try std.testing.expectEqual(@as(usize, 2), varIntLength(64));
    try std.testing.expectEqual(@as(usize, 2), varIntLength(16383));
    try std.testing.expectEqual(@as(usize, 4), varIntLength(16384));
    try std.testing.expectEqual(@as(usize, 4), varIntLength(1073741823));
    try std.testing.expectEqual(@as(usize, 8), varIntLength(1073741824));
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

    const window: u64 = @as(u64, 1) << @intCast(num_bits);
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

// Retry token roundtrip test
test "Retry token: generate and validate roundtrip" {
    var token_key: [crypto.key_len]u8 = undefined;
    random.bytes(&token_key);

    const odcid = &[_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
    const retry_scid = &[_]u8{ 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18 };
    var addr: posix.sockaddr = std.mem.zeroes(posix.sockaddr);
    addr.family = posix.AF.INET;
    addr.data[0] = 0x11; // port high byte
    addr.data[1] = 0x51; // port low byte
    addr.data[2] = 127;
    addr.data[3] = 0;
    addr.data[4] = 0;
    addr.data[5] = 1;

    var out: [TOKEN_MAX_LEN]u8 = undefined;
    const token_len = try generateRetryToken(&out, odcid, retry_scid, addr, token_key);
    try std.testing.expect(token_len > TOKEN_NONCE_LEN + TOKEN_TAG_LEN);

    const validated = try validateRetryToken(out[0..token_len], addr, token_key);
    try std.testing.expect(validated != null);
    const v = validated.?;
    try std.testing.expectEqualSlices(u8, odcid, v.getOdcid());
    try std.testing.expectEqualSlices(u8, retry_scid, v.getRetryScid());
}

// Retry token: wrong address should fail
test "Retry token: wrong address rejected" {
    var token_key: [crypto.key_len]u8 = undefined;
    random.bytes(&token_key);

    const odcid = &[_]u8{ 0x01, 0x02, 0x03, 0x04 };
    const retry_scid = &[_]u8{ 0x11, 0x12, 0x13, 0x14 };
    var addr1: posix.sockaddr = std.mem.zeroes(posix.sockaddr);
    addr1.family = posix.AF.INET;
    addr1.data[2] = 127;
    addr1.data[5] = 1;

    var out: [TOKEN_MAX_LEN]u8 = undefined;
    const token_len = try generateRetryToken(&out, odcid, retry_scid, addr1, token_key);

    // Different address
    var addr2 = addr1;
    addr2.data[2] = 10;
    const validated = try validateRetryToken(out[0..token_len], addr2, token_key);
    try std.testing.expect(validated == null);
}

// Retry token: wrong key should fail
test "Retry token: wrong key rejected" {
    var token_key: [crypto.key_len]u8 = undefined;
    random.bytes(&token_key);

    const odcid = &[_]u8{ 0x01, 0x02, 0x03, 0x04 };
    const retry_scid = &[_]u8{ 0x11, 0x12, 0x13, 0x14 };
    var addr: posix.sockaddr = std.mem.zeroes(posix.sockaddr);
    addr.family = posix.AF.INET;

    var out: [TOKEN_MAX_LEN]u8 = undefined;
    const token_len = try generateRetryToken(&out, odcid, retry_scid, addr, token_key);

    // Different key
    var wrong_key: [crypto.key_len]u8 = undefined;
    random.bytes(&wrong_key);
    const validated = try validateRetryToken(out[0..token_len], addr, wrong_key);
    try std.testing.expect(validated == null);
}

// Retry integrity tag verification
test "Retry: integrity tag compute and verify" {
    const odcid = &[_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };

    // Build a minimal Retry-like packet (header only, no tag yet)
    var pkt_buf: [128]u8 = undefined;
    var pkt_fbs = io.fixedBufferStream(&pkt_buf);
    const pkt_writer = pkt_fbs.writer();

    // First byte: Retry packet type
    try pkt_writer.writeByte(@intFromEnum(PacketType.retry));
    // Version
    try pkt_writer.writeInt(u32, 0x00000001, ENDIAN);
    // DCID
    try pkt_writer.writeByte(4);
    try pkt_writer.writeAll(&[_]u8{ 0x01, 0x02, 0x03, 0x04 });
    // SCID
    try pkt_writer.writeByte(4);
    try pkt_writer.writeAll(&[_]u8{ 0x05, 0x06, 0x07, 0x08 });
    // Token
    try pkt_writer.writeAll("some_token_data");

    const pkt_without_tag = pkt_fbs.getWritten();

    // Compute tag
    const tag = try computeRetryIntegrityTag(pkt_without_tag, odcid, 0x00000001);

    // Build full packet with tag
    var full_pkt: [256]u8 = undefined;
    @memcpy(full_pkt[0..pkt_without_tag.len], pkt_without_tag);
    @memcpy(full_pkt[pkt_without_tag.len..][0..RETRY_INTEGRITY_TAG_SIZE], &tag);
    const full_len = pkt_without_tag.len + RETRY_INTEGRITY_TAG_SIZE;

    // Verify
    const valid = try verifyRetryIntegrity(full_pkt[0..full_len], odcid, 0x00000001);
    try std.testing.expect(valid);

    // Tamper with packet and verify fails
    full_pkt[10] ^= 0xFF;
    const invalid = try verifyRetryIntegrity(full_pkt[0..full_len], odcid, 0x00000001);
    try std.testing.expect(!invalid);
}
