const std = @import("std");
const Allocator = std.mem.Allocator;
const testing = std.testing;
const io = std.io;

const packet_mod = @import("packet.zig");
const crypto_mod = @import("crypto.zig");
const frame_mod = @import("frame.zig");
const Frame = frame_mod.Frame;
const ack_handler = @import("ack_handler.zig");
const crypto_stream = @import("crypto_stream.zig");
const stream_mod = @import("stream.zig");
const conn_mod = @import("connection.zig");

/// Default QUIC packet size (UDP payload).
const DEFAULT_MAX_PACKET_SIZE: usize = 1200;

/// Absolute maximum packet size we ever assemble (probes included).
const ABSOLUTE_MAX_PACKET_SIZE: usize = 1500;

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

    /// Current key phase bit for 1-RTT packets (toggled on key update).
    key_phase: bool = false,

    /// Spin bit for passive RTT measurement (RFC 9000 §17.4).
    spin_bit: bool = false,

    /// Maximum packet size for regular (non-probe) packets.
    max_packet_size: usize = DEFAULT_MAX_PACKET_SIZE,

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

    /// Pack a coalesced packet (Initial + 0-RTT + Handshake + 1-RTT).
    /// Returns the number of bytes written to out_buf.
    /// When ack_only is true, only ACK/CRYPTO/HANDSHAKE_DONE/control frames are packed (no stream/datagram data).
    pub fn packCoalesced(
        self: *PacketPacker,
        out_buf: []u8,
        pkt_handler: *ack_handler.PacketHandler,
        crypto_mgr: *crypto_stream.CryptoStreamManager,
        streams: *stream_mod.StreamsMap,
        pending_frames: *frame_mod.PendingFrameQueue,
        initial_seal: ?crypto_mod.Seal,
        early_seal: ?crypto_mod.Seal,
        handshake_seal: ?crypto_mod.Seal,
        app_seal: ?crypto_mod.Seal,
        now: i64,
        datagram_queue: ?*conn_mod.DatagramQueue,
        ack_only: bool,
    ) !usize {
        var offset: usize = 0;

        // Try packing Initial packet
        // When coalescing with 0-RTT, don't pad the Initial — let 0-RTT use the space
        if (initial_seal != null) {
            const pad_target: usize = if (early_seal == null) MIN_INITIAL_PACKET_SIZE else 0;
            const initial_len = try self.packSinglePacket(
                out_buf[offset..],
                .initial,
                pkt_handler,
                crypto_mgr,
                streams,
                pending_frames,
                initial_seal.?,
                now,
                pad_target,
                null,
                false,
                ack_only,
            );
            offset += initial_len;
        }

        // Try packing 0-RTT packet (Long Header, type 0x10)
        // When coalesced after an unpadded Initial, pad the 0-RTT so the
        // total datagram reaches the 1200-byte minimum (RFC 9000 §14.1)
        if (early_seal != null and offset < out_buf.len and !ack_only) {
            const pad_target: usize = if (initial_seal != null and offset > 0)
                MIN_INITIAL_PACKET_SIZE -| offset
            else
                0;
            const early_len = try self.packSinglePacket(
                out_buf[offset..],
                .application,
                pkt_handler,
                crypto_mgr,
                streams,
                pending_frames,
                early_seal.?,
                now,
                pad_target,
                datagram_queue,
                true, // zero_rtt = true
                false,
            );
            offset += early_len;
        }

        // Try packing Handshake packet
        if (handshake_seal != null and offset < out_buf.len) {
            const hs_len = try self.packSinglePacket(
                out_buf[offset..],
                .handshake,
                pkt_handler,
                crypto_mgr,
                streams,
                pending_frames,
                handshake_seal.?,
                now,
                0,
                null,
                false,
                ack_only,
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
                pending_frames,
                app_seal.?,
                now,
                0,
                datagram_queue,
                false,
                ack_only,
            );
            offset += app_len;
        }

        return offset;
    }

    /// Pack a single packet at the given encryption level.
    /// Returns the total packet size including header, encrypted payload, and AEAD tag.
    /// When zero_rtt=true, packs a 0-RTT Long Header packet (type 0x10) with only STREAM/DATAGRAM frames.
    /// When ack_only=true, skips stream and datagram frames (used when congestion-limited).
    fn packSinglePacket(
        self: *PacketPacker,
        buf: []u8,
        level: ack_handler.EncLevel,
        pkt_handler: *ack_handler.PacketHandler,
        crypto_mgr: *crypto_stream.CryptoStreamManager,
        streams: *stream_mod.StreamsMap,
        pending_frames: *frame_mod.PendingFrameQueue,
        seal: crypto_mod.Seal,
        now: i64,
        pad_target: usize, // 0 = no padding, >0 = target packet size for this packet
        datagram_queue: ?*conn_mod.DatagramQueue,
        zero_rtt: bool,
        ack_only: bool,
    ) !usize {
        if (buf.len < 64) return 0; // Not enough space

        // We build the packet in a temporary buffer, then encrypt into buf
        var tmp: [ABSOLUTE_MAX_PACKET_SIZE]u8 = undefined;
        // Account for output buffer size: encrypted output = fbs.pos + AEAD_TAG_LEN
        const effective_max = @min(self.max_packet_size, @min(tmp.len, buf.len -| AEAD_TAG_LEN));
        var fbs = io.fixedBufferStream(tmp[0..effective_max]);
        const writer = fbs.writer();

        // Get packet number and encode it
        const pn = pkt_handler.nextPacketNumber(level);
        const largest_acked = pkt_handler.getLargestAcked(level);
        var pn_buf: [4]u8 = undefined;
        const pn_len = crypto_mod.encodePacketNumber(pn, largest_acked, &pn_buf);

        // Write header
        const header_start: usize = 0;
        const pkt_type = if (zero_rtt)
            packet_mod.PacketType.zero_rtt
        else switch (level) {
            .initial => packet_mod.PacketType.initial,
            .handshake => packet_mod.PacketType.handshake,
            .application => packet_mod.PacketType.one_rtt,
        };

        var length_offset: usize = 0; // where the payload length field is (long headers only)

        if (pkt_type == .one_rtt) {
            // Short header: 1 byte + DCID
            var first_byte: u8 = packet_mod.FIXED_BIT;
            if (self.key_phase) first_byte |= packet_mod.KEY_PHASE_BIT;
            if (self.spin_bit) first_byte |= packet_mod.PACKET_SPIN_BIT;
            first_byte |= @as(u8, @intCast(pn_len - 1));
            try writer.writeByte(first_byte);
            try writer.writeAll(self.getDcid());
        } else {
            // Long header
            var first_byte: u8 = packet_mod.encodeLongHeaderTypeBits(pkt_type, self.version);
            first_byte |= @as(u8, @intCast(pn_len - 1));
            try writer.writeByte(first_byte);
            try writer.writeInt(u32, self.version, .big);

            try writer.writeByte(@intCast(self.getDcid().len));
            try writer.writeAll(self.getDcid());
            try writer.writeByte(@intCast(self.getScid().len));
            try writer.writeAll(self.getScid());

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
        var has_crypto_data = false;

        // 0-RTT packets only contain STREAM and DATAGRAM frames — skip ACK, CRYPTO, control
        if (!zero_rtt) {
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
            const remaining_space = effective_max - fbs.pos - AEAD_TAG_LEN - 4;
            if (remaining_space > 0) {
                if (cs.popCryptoFrame(remaining_space)) |crypto_frame| {
                    try crypto_frame.write(writer);
                    ack_eliciting = true;
                    has_crypto_data = true;
                }
            }

            // 3. HANDSHAKE_DONE frame (server only, 1-RTT)
            if (level == .application and self.send_handshake_done) {
                try writer.writeByte(0x1e); // HANDSHAKE_DONE frame type
                self.send_handshake_done = false;
                ack_eliciting = true;
                std.log.info("packing HANDSHAKE_DONE frame", .{});
            }

            // 4. Pending control frames (only in 1-RTT)
            if (level == .application) {
                while (pending_frames.pop()) |pcf| {
                    try pcf.write(writer);
                    ack_eliciting = true;
                }
            }
        }

        // 5. Stream frames (only in 1-RTT or 0-RTT, skip when ack_only)
        // Track stream frames for retransmission on loss
        var stream_frame_infos: [ack_handler.MAX_STREAM_FRAMES_PER_PACKET]ack_handler.StreamFrameInfo = undefined;
        var stream_frame_info_count: u8 = 0;

        if (level == .application and !ack_only) {
            // Bidirectional streams
            var stream_it = streams.streams.valueIterator();
            while (stream_it.next()) |s_ptr| {
                const s = s_ptr.*;
                if (fbs.pos + AEAD_TAG_LEN + 16 >= effective_max) break;
                const max_stream_data = effective_max - fbs.pos - AEAD_TAG_LEN - 8;
                if (s.send.popStreamFrame(max_stream_data)) |stream_frame| {
                    try stream_frame.write(writer);
                    ack_eliciting = true;
                    // Record for retransmission tracking
                    if (stream_frame_info_count < ack_handler.MAX_STREAM_FRAMES_PER_PACKET) {
                        stream_frame_infos[stream_frame_info_count] = .{
                            .stream_id = stream_frame.stream.stream_id,
                            .offset = stream_frame.stream.offset,
                            .length = stream_frame.stream.length,
                            .fin = stream_frame.stream.fin,
                        };
                        stream_frame_info_count += 1;
                    }
                }
            }

            // Unidirectional send streams
            var uni_it = streams.send_streams.valueIterator();
            while (uni_it.next()) |s_ptr| {
                const s = s_ptr.*;
                if (fbs.pos + AEAD_TAG_LEN + 16 >= effective_max) break;
                const max_stream_data = effective_max - fbs.pos - AEAD_TAG_LEN - 8;
                if (s.popStreamFrame(max_stream_data)) |stream_frame| {
                    try stream_frame.write(writer);
                    ack_eliciting = true;
                    // Record for retransmission tracking
                    if (stream_frame_info_count < ack_handler.MAX_STREAM_FRAMES_PER_PACKET) {
                        stream_frame_infos[stream_frame_info_count] = .{
                            .stream_id = stream_frame.stream.stream_id,
                            .offset = stream_frame.stream.offset,
                            .length = stream_frame.stream.length,
                            .fin = stream_frame.stream.fin,
                        };
                        stream_frame_info_count += 1;
                    }
                }
            }

            // 6. DATAGRAM frames (RFC 9221, skip when ack_only)
            if (datagram_queue) |dq| {
                var dgram_buf: [conn_mod.DatagramQueue.MAX_DATAGRAM_SIZE]u8 = undefined;
                while (fbs.pos + AEAD_TAG_LEN + 16 < effective_max) {
                    const dgram_len = dq.pop(&dgram_buf) orelse break;
                    // Use DATAGRAM_WITH_LENGTH (0x31) so multiple datagrams can coexist in one packet
                    const dgram_frame = Frame{ .datagram_with_length = .{
                        .data = dgram_buf[0..dgram_len],
                    } };
                    try dgram_frame.write(writer);
                    ack_eliciting = true;
                }
            }
        }

        // Check if we have any payload
        var payload_len = fbs.pos - payload_start;
        if (payload_len == 0 and pad_target == 0) {
            return 0; // Nothing to send
        }

        // RFC 9001 Section 5.4: ensure long-header packets have at least 5 bytes plaintext for header protection
        // (5 bytes plaintext + 16 bytes AEAD tag = 21 bytes encrypted minimum >= 20 required for sample)
        if (pkt_type != .one_rtt and payload_len < 5) {
            const min_pad = 5 - payload_len;
            var p: usize = 0;
            while (p < min_pad) : (p += 1) {
                try writer.writeByte(0x00); // PADDING frame
            }
            payload_len = 5;
        }

        // Pad to target size for Initial or 0-RTT packets (client only, RFC 9000 §14.1)
        if (pad_target > 0 and (pkt_type == .initial or pkt_type == .zero_rtt) and !self.is_server) {
            const current_total = fbs.pos - header_start + AEAD_TAG_LEN;
            if (current_total < pad_target) {
                const pad_needed = pad_target - current_total;
                var p: usize = 0;
                while (p < pad_needed) : (p += 1) {
                    writer.writeByte(0x00) catch break; // PADDING frame (best-effort)
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
        const encrypted_len = seal.encryptPayload(
            pn,
            ad,
            plaintext_payload,
            buf[encrypted_start..],
        );

        const total_packet_len = encrypted_start + encrypted_len;

        // Apply header protection
        crypto_mod.applyHeaderProtection(
            buf[header_start..total_packet_len],
            pn_offset - header_start,
            pn_len,
            seal.hp_key,
            seal.cipher_suite,
        );

        // Record the packet as sent, including stream frame info for retransmission
        var sent_pkt = ack_handler.SentPacket{
            .pn = pn,
            .time_sent = now,
            .size = @intCast(total_packet_len),
            .ack_eliciting = ack_eliciting,
            .in_flight = ack_eliciting,
            .enc_level = level,
            .has_crypto_data = has_crypto_data,
        };
        // Copy stream frame records into the SentPacket
        for (stream_frame_infos[0..stream_frame_info_count]) |info| {
            sent_pkt.addStreamFrame(info);
        }
        try pkt_handler.onPacketSent(sent_pkt);

        return total_packet_len;
    }

    /// Pack an MTU probe packet (1-RTT PING + PADDING to target size).
    /// Returns the total bytes written and the packet number used.
    pub fn packMtuProbe(
        self: *PacketPacker,
        buf: []u8,
        target_size: usize,
        pkt_handler: *ack_handler.PacketHandler,
        seal: crypto_mod.Seal,
        now: i64,
    ) !struct { bytes_written: usize, pn: u64 } {
        if (buf.len < target_size or target_size < 64) return .{ .bytes_written = 0, .pn = 0 };

        var tmp: [ABSOLUTE_MAX_PACKET_SIZE]u8 = undefined;
        const effective_max = @min(target_size, tmp.len);
        var fbs = io.fixedBufferStream(tmp[0..effective_max]);
        const writer = fbs.writer();

        const pn = pkt_handler.nextPacketNumber(.application);
        const largest_acked = pkt_handler.getLargestAcked(.application);
        var pn_buf: [4]u8 = undefined;
        const pn_len = crypto_mod.encodePacketNumber(pn, largest_acked, &pn_buf);

        // Short header (1-RTT)
        var first_byte: u8 = packet_mod.FIXED_BIT;
        if (self.key_phase) first_byte |= packet_mod.KEY_PHASE_BIT;
        if (self.spin_bit) first_byte |= packet_mod.PACKET_SPIN_BIT;
        first_byte |= @as(u8, @intCast(pn_len - 1));
        try writer.writeByte(first_byte);
        try writer.writeAll(self.getDcid());

        const pn_offset = fbs.pos;
        try writer.writeAll(pn_buf[0..pn_len]);

        const payload_start = fbs.pos;

        // PING frame (makes it ACK-eliciting)
        try packet_mod.writeVarInt(writer, 0x01);

        // Fill remaining space with PADDING to reach target_size
        const overhead = payload_start + AEAD_TAG_LEN;
        if (target_size > overhead) {
            const pad_needed = target_size - overhead - (fbs.pos - payload_start);
            var p: usize = 0;
            while (p < pad_needed) : (p += 1) {
                try writer.writeByte(0x00);
            }
        }

        const plaintext_payload = tmp[payload_start..fbs.pos];
        const header_bytes = tmp[0..payload_start];

        // Copy header
        @memcpy(buf[0..header_bytes.len], header_bytes);
        @memcpy(buf[pn_offset..][0..pn_len], pn_buf[0..pn_len]);

        // Encrypt
        const encrypted_start = pn_offset + pn_len;
        const ad = buf[0..(pn_offset + pn_len)];
        const encrypted_len = seal.encryptPayload(pn, ad, plaintext_payload, buf[encrypted_start..]);
        const total_len = encrypted_start + encrypted_len;

        // Apply header protection
        crypto_mod.applyHeaderProtection(buf[0..total_len], pn_offset, pn_len, seal.hp_key, seal.cipher_suite);

        // Record as sent (in_flight but special — caller handles probe loss separately)
        try pkt_handler.onPacketSent(.{
            .pn = pn,
            .time_sent = now,
            .size = @intCast(total_len),
            .ack_eliciting = true,
            .in_flight = true,
            .enc_level = .application,
        });

        return .{ .bytes_written = total_len, .pn = pn };
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
