const std = @import("std");
const Allocator = std.mem.Allocator;
const testing = std.testing;
const io = std.io;

const packet_mod = @import("packet.zig");
const crypto_mod = @import("crypto.zig");
const Frame = @import("frame.zig").Frame;
const ack_handler = @import("ack_handler.zig");
const crypto_stream = @import("crypto_stream.zig");
const stream_mod = @import("stream.zig");

/// Maximum QUIC packet size (UDP payload).
const MAX_PACKET_SIZE: usize = 1200;

/// Minimum Initial packet size for client.
const MIN_INITIAL_PACKET_SIZE: usize = 1200;

/// AEAD tag length (AES-128-GCM).
const AEAD_TAG_LEN: usize = crypto_mod.Aead.tag_length;

/// Maximum packet number length.
const MAX_PN_LEN: usize = 4;

/// Header protection sample length.
const SAMPLE_LEN: usize = crypto_mod.SAMPLE_LEN;

/// The packet packer assembles outgoing QUIC packets.
///
/// It handles:
/// - Coalescing multiple encryption levels into one UDP datagram
/// - Collecting frames (ACK, CRYPTO, STREAM, control)
/// - Applying payload encryption and header protection
/// - Padding Initial packets to minimum 1200 bytes
pub const PacketPacker = struct {
    allocator: Allocator,
    is_server: bool,

    /// Source connection ID (owned buffer to avoid dangling slices).
    scid_buf: [20]u8 = .{0} ** 20,
    scid_len: u8 = 0,

    /// Destination connection ID (owned buffer to avoid dangling slices).
    dcid_buf: [20]u8 = .{0} ** 20,
    dcid_len: u8 = 0,

    /// QUIC version.
    version: u32,

    /// Token for Initial packets (from Retry).
    initial_token: ?[]const u8 = null,

    /// Whether to send HANDSHAKE_DONE frame in the next 1-RTT packet (server only).
    send_handshake_done: bool = false,

    pub fn init(
        allocator: Allocator,
        is_server: bool,
        scid: []const u8,
        dcid: []const u8,
        version: u32,
    ) PacketPacker {
        var packer = PacketPacker{
            .allocator = allocator,
            .is_server = is_server,
            .scid_len = @intCast(scid.len),
            .dcid_len = @intCast(dcid.len),
            .version = version,
        };
        @memcpy(packer.scid_buf[0..scid.len], scid);
        @memcpy(packer.dcid_buf[0..dcid.len], dcid);
        return packer;
    }

    pub fn getScid(self: *const PacketPacker) []const u8 {
        return self.scid_buf[0..self.scid_len];
    }

    pub fn getDcid(self: *const PacketPacker) []const u8 {
        return self.dcid_buf[0..self.dcid_len];
    }

    pub fn updateDcid(self: *PacketPacker, new_dcid: []const u8) void {
        @memcpy(self.dcid_buf[0..new_dcid.len], new_dcid);
        self.dcid_len = @intCast(new_dcid.len);
    }

    /// Pack a coalesced packet (Initial + Handshake + 1-RTT).
    /// Returns the number of bytes written to out_buf.
    pub fn packCoalesced(
        self: *PacketPacker,
        out_buf: []u8,
        pkt_handler: *ack_handler.PacketHandler,
        crypto_mgr: *crypto_stream.CryptoStreamManager,
        streams: *stream_mod.StreamsMap,
        initial_seal: ?crypto_mod.Seal,
        handshake_seal: ?crypto_mod.Seal,
        app_seal: ?crypto_mod.Seal,
        now: i64,
    ) !usize {
        var offset: usize = 0;

        // Try packing Initial packet
        if (initial_seal != null) {
            const initial_len = try self.packSinglePacket(
                out_buf[offset..],
                .initial,
                pkt_handler,
                crypto_mgr,
                streams,
                initial_seal.?,
                now,
                true, // pad to minimum size
            );
            offset += initial_len;
        }

        // Try packing Handshake packet
        if (handshake_seal != null and offset < out_buf.len) {
            const hs_len = try self.packSinglePacket(
                out_buf[offset..],
                .handshake,
                pkt_handler,
                crypto_mgr,
                streams,
                handshake_seal.?,
                now,
                false,
            );
            offset += hs_len;
        }

        // Try packing 1-RTT packet
        if (app_seal != null and offset < out_buf.len) {
            const app_len = try self.packSinglePacket(
                out_buf[offset..],
                .application,
                pkt_handler,
                crypto_mgr,
                streams,
                app_seal.?,
                now,
                false,
            );
            offset += app_len;
        }

        return offset;
    }

    /// Pack a single packet at the given encryption level.
    /// Returns the total packet size including header, encrypted payload, and AEAD tag.
    fn packSinglePacket(
        self: *PacketPacker,
        buf: []u8,
        level: ack_handler.EncLevel,
        pkt_handler: *ack_handler.PacketHandler,
        crypto_mgr: *crypto_stream.CryptoStreamManager,
        streams: *stream_mod.StreamsMap,
        seal: crypto_mod.Seal,
        now: i64,
        pad_to_min: bool,
    ) !usize {
        std.log.info("packSinglePacket: level={s} buf.len={d}", .{ @tagName(level), buf.len });
        if (buf.len < 64) return 0; // Not enough space

        // We build the packet in a temporary buffer, then encrypt into buf
        var tmp: [MAX_PACKET_SIZE]u8 = undefined;
        var fbs = io.fixedBufferStream(&tmp);
        const writer = fbs.writer();

        // Get packet number and encode it
        const pn = pkt_handler.nextPacketNumber(level);
        const largest_acked = pkt_handler.getLargestAcked(level);
        var pn_buf: [4]u8 = undefined;
        const pn_len = crypto_mod.encodePacketNumber(pn, largest_acked, &pn_buf);

        // Write header
        const header_start: usize = 0;
        const pkt_type = switch (level) {
            .initial => packet_mod.PacketType.initial,
            .handshake => packet_mod.PacketType.handshake,
            .application => packet_mod.PacketType.one_rtt,
        };

        var length_offset: usize = 0; // where the payload length field is (long headers only)

        if (pkt_type == .one_rtt) {
            // Short header: 1 byte + DCID
            var first_byte: u8 = packet_mod.FIXED_BIT;
            first_byte |= @as(u8, @intCast(pn_len - 1));
            try writer.writeByte(first_byte);
            try writer.writeAll(self.getDcid());
        } else {
            // Long header
            var first_byte: u8 = packet_mod.LONG_HEADER_BIT | packet_mod.FIXED_BIT;
            first_byte |= switch (pkt_type) {
                .initial => @as(u8, 0x00),
                .handshake => @as(u8, 0x20),
                .zero_rtt => @as(u8, 0x10),
                else => @as(u8, 0x00),
            };
            first_byte |= @as(u8, @intCast(pn_len - 1));
            try writer.writeByte(first_byte);
            try writer.writeInt(u32, self.version, .big);

            try writer.writeByte(@intCast(self.getDcid().len));
            try writer.writeAll(self.getDcid());
            try writer.writeByte(@intCast(self.getScid().len));
            try writer.writeAll(self.getScid());

            std.log.info("packInitial: writing dcid={any}, scid={any}", .{ self.getDcid(), self.getScid() });

            // Token (Initial only)
            if (pkt_type == .initial) {
                if (self.initial_token) |token| {
                    try packet_mod.writeVarInt(writer, token.len);
                    try writer.writeAll(token);
                } else {
                    try packet_mod.writeVarInt(writer, 0);
                }
            }

            // Payload length placeholder - use 2-byte varint (can hold up to 16383)
            length_offset = fbs.pos;
            try writer.writeInt(u16, 0, .big); // placeholder
        }

        // Write packet number
        const pn_offset = fbs.pos;
        try writer.writeAll(pn_buf[0..pn_len]);

        // Record where the plaintext payload starts
        const payload_start = fbs.pos;

        // Collect frames
        var ack_eliciting = false;

        // 1. ACK frame (always first if pending)
        const ack_delay_exp: u64 = 3;
        if (pkt_handler.getAckFrame(level, now, ack_delay_exp)) |ack_frame| {
            try ack_frame.write(writer);
        }

        // 2. CRYPTO frames
        const crypto_level_idx: u8 = switch (level) {
            .initial => 0,
            .handshake => 2,
            .application => 3,
        };
        const cs = crypto_mgr.getStream(crypto_level_idx);
        const remaining = tmp.len - fbs.pos - AEAD_TAG_LEN - 4;
        if (remaining > 0) {
            if (cs.popCryptoFrame(remaining)) |crypto_frame| {
                try crypto_frame.write(writer);
                ack_eliciting = true;
            }
        }

        // 3. HANDSHAKE_DONE frame (server only, 1-RTT)
        if (level == .application and self.send_handshake_done) {
            try writer.writeByte(0x1e); // HANDSHAKE_DONE frame type
            self.send_handshake_done = false;
            ack_eliciting = true;
            std.log.info("packing HANDSHAKE_DONE frame", .{});
        }

        // 4. Stream frames (only in 1-RTT)
        if (level == .application) {
            var stream_it = streams.streams.valueIterator();
            while (stream_it.next()) |s_ptr| {
                const s = s_ptr.*;
                if (fbs.pos + AEAD_TAG_LEN + 16 >= tmp.len) break;
                const max_stream_data = tmp.len - fbs.pos - AEAD_TAG_LEN - 8;
                if (s.send.popStreamFrame(max_stream_data)) |stream_frame| {
                    const sf = stream_frame.stream;
                    std.log.info("packing STREAM frame: id={d}, offset={d}, len={d}, fin={}, data_len={d}", .{
                        sf.stream_id, sf.offset, sf.length, sf.fin, sf.data.len,
                    });
                    try stream_frame.write(writer);
                    ack_eliciting = true;
                }
            }
        }

        // Check if we have any payload
        var payload_len = fbs.pos - payload_start;
        if (payload_len == 0 and !pad_to_min) {
            std.log.info("packSinglePacket: level={s} returning 0 - no payload", .{ @tagName(level) });
            return 0; // Nothing to send
        }
        std.log.info("packSinglePacket: level={s} has payload_len={d}", .{ @tagName(level), payload_len });

        // RFC 9001 Section 5.4: ensure Initial packets have at least 5 bytes plaintext for header protection
        // (5 bytes plaintext + 16 bytes AEAD tag = 21 bytes encrypted minimum >= 20 required)
        if (pkt_type == .initial and payload_len < 5) {
            const min_pad = 5 - payload_len;
            var p: usize = 0;
            while (p < min_pad) : (p += 1) {
                try writer.writeByte(0x00); // PADDING frame
            }
            payload_len = 5;
        }

        // Pad to minimum size for Initial packets (client only)
        if (pad_to_min and pkt_type == .initial and !self.is_server) {
            const current_total = fbs.pos - header_start + AEAD_TAG_LEN;
            if (current_total < MIN_INITIAL_PACKET_SIZE) {
                const pad_needed = MIN_INITIAL_PACKET_SIZE - current_total;
                var p: usize = 0;
                while (p < pad_needed) : (p += 1) {
                    try writer.writeByte(0x00); // PADDING frame
                }
            }
        }

        // The plaintext payload is tmp[payload_start..fbs.pos]
        const plaintext_payload = tmp[payload_start..fbs.pos];
        const header_bytes = tmp[header_start..payload_start];

        // Fill in the payload length field for long headers
        // Length = pn_len + plaintext_payload.len + AEAD_TAG_LEN
        if (pkt_type != .one_rtt) {
            const total_payload_len: u16 = @intCast(pn_len + plaintext_payload.len + AEAD_TAG_LEN);
            // Encode as 2-byte varint (set high 2 bits to 01)
            std.mem.writeInt(u16, tmp[length_offset..][0..2], total_payload_len | (0x40 << 8), .big);
        }

        // Copy header to output buffer
        const out_header = buf[header_start..][0..header_bytes.len];
        @memcpy(out_header, header_bytes);

        // Copy packet number to output buffer
        @memcpy(buf[pn_offset..][0..pn_len], pn_buf[0..pn_len]);

        // Encrypt payload into output buffer (after pn)
        const encrypted_start = pn_offset + pn_len;
        // RFC 9001 Section 5.2: AD is the header up to and including the packet number field
        const ad = buf[header_start..][0..(pn_offset - header_start + pn_len)];
        std.log.info("packSinglePacket encrypt: pn={d}, ad.len={d}, ad={any}", .{ pn, ad.len, ad });
        std.log.info("packSinglePacket encrypt: plaintext_payload.len={d}", .{plaintext_payload.len});
        const encrypted_len = seal.encryptPayload(
            pn,
            ad,
            plaintext_payload,
            buf[encrypted_start..],
        );
        std.log.info("packSinglePacket encrypt: encrypted_len={d}", .{encrypted_len});

        const total_packet_len = encrypted_start + encrypted_len;

        // Apply header protection
        crypto_mod.applyHeaderProtection(
            buf[header_start..total_packet_len],
            pn_offset - header_start,
            pn_len,
            seal.hp_key,
        );

        // Record the packet as sent
        try pkt_handler.onPacketSent(.{
            .pn = pn,
            .time_sent = now,
            .size = @intCast(total_packet_len),
            .ack_eliciting = ack_eliciting,
            .in_flight = ack_eliciting,
            .enc_level = level,
        });

        return total_packet_len;
    }

    /// Pack a CONNECTION_CLOSE frame.
    pub fn packConnectionClose(
        self: *PacketPacker,
        buf: []u8,
        error_code: u64,
        reason: []const u8,
        seal: crypto_mod.Seal,
    ) !usize {
        _ = seal;

        var fbs = io.fixedBufferStream(buf);
        const writer = fbs.writer();

        // Short header (if 1-RTT keys available)
        const first_byte: u8 = packet_mod.FIXED_BIT | 0x03; // 4-byte pn
        try writer.writeByte(first_byte);
        try writer.writeAll(self.getDcid());

        // Packet number (0 for close)
        try writer.writeInt(u32, 0, .big);

        // CONNECTION_CLOSE frame
        const frame = Frame{
            .connection_close = .{
                .error_code = error_code,
                .frame_type = 0,
                .reason = @constCast(reason),
            },
        };
        try frame.write(writer);

        return fbs.pos;
    }
};

// Tests

test "PacketPacker: basic init" {
    const scid = &[_]u8{ 0x01, 0x02, 0x03, 0x04 };
    const dcid = &[_]u8{ 0x05, 0x06, 0x07, 0x08 };
    const packer = PacketPacker.init(
        testing.allocator,
        false,
        scid,
        dcid,
        0x00000001,
    );
    try testing.expectEqualSlices(u8, scid, packer.getScid());
    try testing.expectEqualSlices(u8, dcid, packer.getDcid());
}
