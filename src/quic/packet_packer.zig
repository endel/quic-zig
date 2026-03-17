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
const flow_control = @import("flow_control.zig");

/// Calculate the overhead of a STREAM frame header (type + stream_id + offset + length varints).
/// This accounts for the LEN flag always being set.
fn streamFrameHeaderOverhead(stream_id: u64, offset: u64, max_data_len: u64) usize {
    return 1 // type byte (always 1 byte, value 0x08-0x0F)
    + packet_mod.varIntLength(stream_id) + (if (offset > 0) packet_mod.varIntLength(offset) else 0) + packet_mod.varIntLength(max_data_len); // length field (always present with LEN flag)
}

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

    /// Whether outgoing 1-RTT packets should be marked as ECN (ECT(0)).
    /// Set by connection before packing based on ECN validator state.
    ecn_mark: bool = false,

    /// Connection-level flow controller (for send-side limit enforcement).
    conn_flow_ctrl: ?*flow_control.ConnectionFlowController = null,

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
        // Both client and server MUST pad UDP datagrams carrying ack-eliciting Initial
        // packets to >= 1200 bytes (RFC 9000 §14.1).
        // Client: pad the Initial itself (0-RTT/Handshake go in next datagram).
        // Server: don't pad the Initial here — pad the Handshake portion below
        // so the coalesced datagram reaches 1200 bytes without overflowing.
        if (initial_seal != null) {
            const pad_target: usize = if (!self.is_server) MIN_INITIAL_PACKET_SIZE else 0;
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
        // If coalesced after a padded Initial, no extra padding needed (already >= 1200)
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
        // Padding logic:
        // - Server: pad Handshake so coalesced datagram (Initial+Handshake) reaches 1200 bytes.
        // - Client (standalone Handshake, no Initial coalesced): pad to 1200 bytes so
        //   the server gets amplification credit and peers don't reject small datagrams
        //   (RFC 9000 §14.1 recommends padding during handshake).
        if (handshake_seal != null and offset < out_buf.len) {
            const hs_pad: usize = if (self.is_server and offset > 0)
                MIN_INITIAL_PACKET_SIZE -| offset
            else if (!self.is_server and offset == 0 and initial_seal == null)
                MIN_INITIAL_PACKET_SIZE
            else
                0;
            const hs_len = try self.packSinglePacket(
                out_buf[offset..],
                .handshake,
                pkt_handler,
                crypto_mgr,
                streams,
                pending_frames,
                handshake_seal.?,
                now,
                hs_pad,
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
        var has_handshake_done = false;

        // Track the largest_ack we send in this packet's ACK frame (for ACK-of-ACK pruning)
        var ack_largest_sent: ?u64 = null;

        // 0-RTT packets only contain STREAM and DATAGRAM frames — skip ACK, CRYPTO, control
        if (!zero_rtt) {
            // 1. ACK frame (always first if pending)
            const ack_delay_exp: u64 = 3;
            if (pkt_handler.getAckFrame(level, now, ack_delay_exp)) |ack_frame| {
                // Record the largest_ack for ACK-of-ACK pruning (RFC 9000 §13.2.4)
                switch (ack_frame) {
                    .ack => |a| ack_largest_sent = a.largest_ack,
                    .ack_ecn => |a| ack_largest_sent = a.largest_ack,
                    else => {},
                }
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

            // 2b. PING and CONNECTION_CLOSE for Initial/Handshake packets
            // PING: PTO probes need ack-eliciting frames (RFC 9002 §6.2.4)
            // CONNECTION_CLOSE: valid at all levels (RFC 9000 §10.2.3)
            if (level == .initial or level == .handshake) {
                var remaining_pf = pending_frames.len;
                while (remaining_pf > 0) : (remaining_pf -= 1) {
                    const pcf = pending_frames.pop() orelse break;
                    switch (pcf) {
                        .ping => {
                            if (!ack_eliciting) {
                                try writer.writeByte(0x01); // PING frame
                                ack_eliciting = true;
                            } else {
                                pending_frames.push(pcf);
                            }
                        },
                        .connection_close => {
                            try pcf.write(writer);
                            ack_eliciting = true;
                            // Keep CONNECTION_CLOSE for higher encryption levels too
                            // (RFC 9000 §10.2.3: send at all available levels)
                            pending_frames.push(pcf);
                        },
                        else => {
                            // Put it back — other control frames go in 1-RTT
                            pending_frames.push(pcf);
                        },
                    }
                }
            }

            // 3. HANDSHAKE_DONE frame (server only, 1-RTT)
            // Sent once per trigger (initial handshake completion or PTO/loss re-arm).
            // Connection clears send_handshake_done after packing to prevent flooding
            // the CC window with HANDSHAKE_DONE-only packets in burst loops.
            // Skip when ack_only (congestion-limited).
            if (level == .application and self.send_handshake_done and !ack_only) {
                try writer.writeByte(0x1e); // HANDSHAKE_DONE frame type
                has_handshake_done = true;
                ack_eliciting = true;
                self.send_handshake_done = false; // One-shot: PTO/loss will re-arm
            }

            // 4. Pending control frames (only in 1-RTT)
            // PATH_CHALLENGE/PATH_RESPONSE are always sent (path probing is exempt from CC).
            // Other control frames are skipped when ack_only (congestion-limited).
            if (level == .application) {
                var remaining = pending_frames.len;
                while (remaining > 0) : (remaining -= 1) {
                    const pcf = pending_frames.pop() orelse break;
                    const is_path_probing = switch (pcf) {
                        .path_challenge, .path_response => true,
                        else => false,
                    };
                    if (is_path_probing or !ack_only) {
                        try pcf.write(writer);
                        ack_eliciting = true;
                    } else {
                        // Re-queue non-probing frames when congestion-limited
                        pending_frames.push(pcf);
                    }
                }
            }
        }

        // 5. Stream frames (only in 1-RTT or 0-RTT, skip when ack_only)
        // Track stream frames for retransmission on loss
        var stream_frame_infos: [ack_handler.MAX_STREAM_FRAMES_PER_PACKET]ack_handler.StreamFrameInfo = undefined;
        var stream_frame_info_count: u8 = 0;

        if (level == .application and !ack_only) {
            // Connection-level flow control budget for this packet
            var conn_budget: u64 = if (self.conn_flow_ctrl) |cfc| cfc.sendWindowSize() else std.math.maxInt(u64);

            // Bidirectional streams — scheduled by RFC 9218 priority
            var sched_buf: [stream_mod.StreamsMap.MAX_SCHEDULABLE]*stream_mod.Stream = undefined;
            const sched_count = streams.getScheduledStreams(&sched_buf);
            for (sched_buf[0..sched_count]) |s| {
                if (fbs.pos + AEAD_TAG_LEN + 16 >= effective_max) break;
                if (conn_budget == 0) break;
                if (stream_frame_info_count >= ack_handler.MAX_STREAM_FRAMES_PER_PACKET) break;
                const remaining = effective_max - fbs.pos - AEAD_TAG_LEN;
                const header_overhead = streamFrameHeaderOverhead(s.send.stream_id, s.send.send_offset, remaining);
                if (remaining <= header_overhead) break;
                const max_stream_data = @min(remaining - header_overhead, conn_budget);
                const prev_send_offset = s.send.send_offset;
                if (s.send.popStreamFrame(max_stream_data)) |stream_frame| {
                    try stream_frame.write(writer);
                    ack_eliciting = true;
                    // Only count NEW data against connection flow control (not retransmissions)
                    const new_bytes = s.send.send_offset - prev_send_offset;
                    if (new_bytes > 0) {
                        conn_budget -= @min(conn_budget, new_bytes);
                        if (self.conn_flow_ctrl) |cfc| cfc.base.addBytesSent(new_bytes);
                    }
                    // Record for retransmission tracking
                    stream_frame_infos[stream_frame_info_count] = .{
                        .stream_id = stream_frame.stream.stream_id,
                        .offset = stream_frame.stream.offset,
                        .length = stream_frame.stream.length,
                        .fin = stream_frame.stream.fin,
                    };
                    stream_frame_info_count += 1;
                }
            }

            // Unidirectional send streams
            if (streams.send_streams.count() > 0) {
            var uni_it = streams.send_streams.valueIterator();
            while (uni_it.next()) |s_ptr| {
                const s = s_ptr.*;
                if (fbs.pos + AEAD_TAG_LEN + 16 >= effective_max) break;
                if (conn_budget == 0) break;
                if (stream_frame_info_count >= ack_handler.MAX_STREAM_FRAMES_PER_PACKET) break;
                const remaining_uni = effective_max - fbs.pos - AEAD_TAG_LEN;
                const uni_header_overhead = streamFrameHeaderOverhead(s.stream_id, s.send_offset, remaining_uni);
                if (remaining_uni <= uni_header_overhead) break;
                const max_stream_data = @min(remaining_uni - uni_header_overhead, conn_budget);
                const prev_uni_offset = s.send_offset;
                if (s.popStreamFrame(max_stream_data)) |stream_frame| {
                    try stream_frame.write(writer);
                    ack_eliciting = true;
                    // Only count NEW data against connection flow control
                    const new_bytes_uni = s.send_offset - prev_uni_offset;
                    if (new_bytes_uni > 0) {
                        conn_budget -= @min(conn_budget, new_bytes_uni);
                        if (self.conn_flow_ctrl) |cfc| cfc.base.addBytesSent(new_bytes_uni);
                    }
                    // Record for retransmission tracking
                    stream_frame_infos[stream_frame_info_count] = .{
                        .stream_id = stream_frame.stream.stream_id,
                        .offset = stream_frame.stream.offset,
                        .length = stream_frame.stream.length,
                        .fin = stream_frame.stream.fin,
                    };
                    stream_frame_info_count += 1;
                }
            }
            } // send_streams.count() > 0

        }

        // 6. DATAGRAM frames (RFC 9221) — subject to congestion control (RFC 9221 §5)
        // Only pack datagrams when CC allows (i.e. not in ack_only mode).
        if (level == .application and !ack_only) {
            if (datagram_queue) |dq| {
                var dgram_buf: [conn_mod.DatagramQueue.MAX_DATAGRAM_SIZE]u8 = undefined;
                while (true) {
                    // Peek at the next datagram's size before popping to avoid
                    // consuming datagrams that won't fit in the packet.
                    const peek_len = dq.peekLen() orelse break;
                    // DATAGRAM_WITH_LENGTH frame: type(1) + varint(len) + payload
                    const varint_overhead: usize = if (peek_len <= 63) 1 else 2;
                    const frame_size = 1 + varint_overhead + peek_len;
                    if (fbs.pos + frame_size + AEAD_TAG_LEN > effective_max) break;
                    const dgram_len = dq.pop(&dgram_buf) orelse break;
                    const dgram_frame = Frame{ .datagram_with_length = .{
                        .data = dgram_buf[0..dgram_len],
                    } };
                    try dgram_frame.write(writer);
                    ack_eliciting = true;
                }
            }
        }

        // Note: RFC 9002 loss detection deadlock prevention is handled by the PTO
        // mechanism in ack_handler.zig, which sends PING probes when the PTO timer
        // fires. No need to inject PINGs into every ACK-only packet here — doing so
        // creates an ACK amplification loop (ACK+PING → server ACKs → client ACK+PING → ...).

        // Check if we have any payload
        var payload_len = fbs.pos - payload_start;
        if (payload_len == 0) {
            // Roll back the packet number we consumed — no packet will be sent.
            // This applies even with pad_target > 0: sending a padded Initial with
            // no ACK/CRYPTO content just wastes PNs and pushes the PTO forward.
            const idx = @intFromEnum(level);
            pkt_handler.next_pn[idx] -= 1;
            return 0; // Nothing to send
        }

        // RFC 9001 §5.4.2: The header protection sample starts 4 bytes after the PN offset.
        // We need pn_offset + 4 + SAMPLE_LEN(16) <= total packet length.
        // Equivalently: plaintext_payload >= 4 - pn_len (minimum to place the sample).
        // For safety, ensure at least 4 bytes of plaintext regardless of PN length.
        const min_plaintext: usize = 4;
        if (payload_len < min_plaintext) {
            const min_pad = min_plaintext - payload_len;
            @memset(tmp[fbs.pos..][0..min_pad], 0x00);
            fbs.pos += min_pad;
            payload_len = min_plaintext;
        }

        // Pad to target size (RFC 9000 §14.1): Initial, 0-RTT, or Handshake
        // when used to pad a coalesced server datagram to 1200 bytes.
        if (pad_target > 0 and (pkt_type == .initial or pkt_type == .zero_rtt or pkt_type == .handshake)) {
            const current_total = fbs.pos - header_start + AEAD_TAG_LEN;
            if (current_total < pad_target) {
                const pad_needed = @min(pad_target - current_total, tmp.len - fbs.pos);
                @memset(tmp[fbs.pos..][0..pad_needed], 0x00);
                fbs.pos += pad_needed;
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
            .has_handshake_done = has_handshake_done,
            .ecn_marked = level == .application and self.ecn_mark,
            .largest_acked = ack_largest_sent,
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
            @memset(tmp[fbs.pos..][0..pad_needed], 0x00);
            fbs.pos += pad_needed;
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

test "PacketPacker: updateDcid" {
    const scid = &[_]u8{ 0x01, 0x02, 0x03, 0x04 };
    const dcid = &[_]u8{ 0x05, 0x06, 0x07, 0x08 };
    var packer = PacketPacker.init(testing.allocator, false, scid, dcid, 0x00000001);
    const new_dcid = &[_]u8{ 0xAA, 0xBB, 0xCC };
    packer.updateDcid(new_dcid);
    try testing.expectEqualSlices(u8, new_dcid, packer.getDcid());
}

// Helper: derive Initial crypto keys for packer tests (client side)
fn testClientKeys() !struct { seal: crypto_mod.Seal, open: crypto_mod.Open } {
    const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const keys = try crypto_mod.deriveInitialKeyMaterial(&dcid, 0x00000001, false);
    return .{ .seal = keys[1], .open = keys[0] };
}

// Helper: derive Initial crypto keys for packer tests (server side)
fn testServerKeys() !struct { seal: crypto_mod.Seal, open: crypto_mod.Open } {
    const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const keys = try crypto_mod.deriveInitialKeyMaterial(&dcid, 0x00000001, true);
    return .{ .seal = keys[1], .open = keys[0] };
}

test "PacketPacker: pack Initial with CRYPTO data" {
    // Setup: client packer with Initial keys and CRYPTO data to send
    const scid = &[_]u8{0x01};
    const dcid = &[_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    var packer = PacketPacker.init(testing.allocator, false, scid, dcid, 0x00000001);

    var pkt_handler = ack_handler.PacketHandler.init(testing.allocator);
    defer pkt_handler.deinit();

    var crypto_mgr = crypto_stream.CryptoStreamManager.init(testing.allocator);
    defer crypto_mgr.deinit();

    var streams = stream_mod.StreamsMap.init(testing.allocator, false);
    defer streams.deinit();

    var pending_frames = frame_mod.PendingFrameQueue{};

    // Write some CRYPTO data (simulates ClientHello)
    const crypto_data = "test ClientHello data for packer";
    try crypto_mgr.getStream(0).writeData(crypto_data);

    const keys = try testClientKeys();

    var out_buf: [1500]u8 = undefined;
    const written = try packer.packCoalesced(
        &out_buf,
        &pkt_handler,
        &crypto_mgr,
        &streams,
        &pending_frames,
        keys.seal, // initial_seal
        null, // early_seal
        null, // handshake_seal
        null, // app_seal
        1000,
        null, // datagram_queue
        false, // ack_only
    );

    // Client Initial packets MUST be >= 1200 bytes (RFC 9000 §14.1)
    try testing.expect(written >= MIN_INITIAL_PACKET_SIZE);

    // Verify it's a Long Header Initial packet (high bit set, form bit set)
    try testing.expect(out_buf[0] & 0x80 != 0); // Long header

    // Verify packet was tracked
    try testing.expectEqual(@as(u64, 1), pkt_handler.next_pn[0]); // Used PN 0

    // Verify sent packet was recorded
    try testing.expectEqual(@as(usize, 1), pkt_handler.sent[0].sent_packets.count());
}

test "PacketPacker: pack 1-RTT with stream data" {
    const scid = &[_]u8{0x01};
    const dcid = &[_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    var packer = PacketPacker.init(testing.allocator, false, scid, dcid, 0x00000001);

    var pkt_handler = ack_handler.PacketHandler.init(testing.allocator);
    defer pkt_handler.deinit();

    var crypto_mgr = crypto_stream.CryptoStreamManager.init(testing.allocator);
    defer crypto_mgr.deinit();

    var streams = stream_mod.StreamsMap.init(testing.allocator, false);
    defer streams.deinit();

    var pending_frames = frame_mod.PendingFrameQueue{};

    // Create a stream and write data
    streams.setMaxStreams(10, 10);
    streams.setPeerInitialMaxStreamData(65536, 65536, 65536);
    const s = try streams.openBidiStream();
    try s.send.writeData("Hello from stream");

    const keys = try testClientKeys();

    var out_buf: [1500]u8 = undefined;
    const written = try packer.packCoalesced(
        &out_buf,
        &pkt_handler,
        &crypto_mgr,
        &streams,
        &pending_frames,
        null, // no initial
        null, // no early
        null, // no handshake
        keys.seal, // app_seal
        1000,
        null,
        false,
    );

    // Should have produced a packet with stream data
    try testing.expect(written > 0);

    // Verify it's a Short Header (1-RTT) packet (high bit clear)
    try testing.expect(out_buf[0] & 0x80 == 0);

    // Verify sent packet tracking
    const app_idx = @intFromEnum(ack_handler.EncLevel.application);
    try testing.expectEqual(@as(usize, 1), pkt_handler.sent[app_idx].sent_packets.count());
}

test "PacketPacker: no data produces no packet" {
    const scid = &[_]u8{0x01};
    const dcid = &[_]u8{0x02};
    var packer = PacketPacker.init(testing.allocator, false, scid, dcid, 0x00000001);

    var pkt_handler = ack_handler.PacketHandler.init(testing.allocator);
    defer pkt_handler.deinit();

    var crypto_mgr = crypto_stream.CryptoStreamManager.init(testing.allocator);
    defer crypto_mgr.deinit();

    var streams = stream_mod.StreamsMap.init(testing.allocator, false);
    defer streams.deinit();

    var pending_frames = frame_mod.PendingFrameQueue{};

    const keys = try testClientKeys();

    var out_buf: [1500]u8 = undefined;
    // No crypto data, no stream data, no ACKs — should produce nothing
    const written = try packer.packCoalesced(
        &out_buf,
        &pkt_handler,
        &crypto_mgr,
        &streams,
        &pending_frames,
        keys.seal, // initial_seal
        null,
        null,
        null,
        1000,
        null,
        false,
    );

    try testing.expectEqual(@as(usize, 0), written);
}

test "PacketPacker: ack_only skips stream data" {
    const scid = &[_]u8{0x01};
    const dcid = &[_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    var packer = PacketPacker.init(testing.allocator, false, scid, dcid, 0x00000001);

    var pkt_handler = ack_handler.PacketHandler.init(testing.allocator);
    defer pkt_handler.deinit();

    var crypto_mgr = crypto_stream.CryptoStreamManager.init(testing.allocator);
    defer crypto_mgr.deinit();

    var streams = stream_mod.StreamsMap.init(testing.allocator, false);
    defer streams.deinit();

    var pending_frames = frame_mod.PendingFrameQueue{};

    // Create a stream with data
    streams.setMaxStreams(10, 10);
    streams.setPeerInitialMaxStreamData(65536, 65536, 65536);
    const s = try streams.openBidiStream();
    try s.send.writeData("This data should be skipped");

    // Register 2 received packets to trigger immediate ACK (ACK_ELICITING_THRESHOLD=2)
    try pkt_handler.recv[2].onPacketReceived(0, true, 1000, 0);
    try pkt_handler.recv[2].onPacketReceived(1, true, 1000, 0);

    const keys = try testClientKeys();

    var out_buf: [1500]u8 = undefined;
    const written = try packer.packCoalesced(
        &out_buf,
        &pkt_handler,
        &crypto_mgr,
        &streams,
        &pending_frames,
        null,
        null,
        null,
        keys.seal, // app_seal
        1000,
        null,
        true, // ack_only = true
    );

    // Should produce an ACK-only packet
    try testing.expect(written > 0);

    // Stream data should still be waiting (not consumed)
    try testing.expect(s.send.hasData());
}

test "PacketPacker: coalesced Initial + Handshake" {
    const scid = &[_]u8{0x01};
    const dcid = &[_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    var packer = PacketPacker.init(testing.allocator, true, scid, dcid, 0x00000001); // server

    var pkt_handler = ack_handler.PacketHandler.init(testing.allocator);
    defer pkt_handler.deinit();

    var crypto_mgr = crypto_stream.CryptoStreamManager.init(testing.allocator);
    defer crypto_mgr.deinit();

    var streams = stream_mod.StreamsMap.init(testing.allocator, true);
    defer streams.deinit();

    var pending_frames = frame_mod.PendingFrameQueue{};

    // Write CRYPTO data for Initial and Handshake levels
    try crypto_mgr.getStream(0).writeData("Initial crypto");
    try crypto_mgr.getStream(2).writeData("Handshake crypto"); // handshake = index 2

    const keys = try testServerKeys();

    var out_buf: [1500]u8 = undefined;
    const written = try packer.packCoalesced(
        &out_buf,
        &pkt_handler,
        &crypto_mgr,
        &streams,
        &pending_frames,
        keys.seal, // initial_seal
        null, // no early
        keys.seal, // handshake_seal (reuse same keys for test)
        null, // no app
        1000,
        null,
        false,
    );

    // Should have coalesced both levels
    try testing.expect(written > 0);

    // Both Initial and Handshake packet numbers should have been used
    try testing.expectEqual(@as(u64, 1), pkt_handler.next_pn[0]); // Initial PN 0 used
    try testing.expectEqual(@as(u64, 1), pkt_handler.next_pn[1]); // Handshake PN 0 used
}

test "PacketPacker: HANDSHAKE_DONE frame packed in 1-RTT" {
    const scid = &[_]u8{0x01};
    const dcid = &[_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    var packer = PacketPacker.init(testing.allocator, true, scid, dcid, 0x00000001);
    packer.send_handshake_done = true;

    var pkt_handler = ack_handler.PacketHandler.init(testing.allocator);
    defer pkt_handler.deinit();

    var crypto_mgr = crypto_stream.CryptoStreamManager.init(testing.allocator);
    defer crypto_mgr.deinit();

    var streams = stream_mod.StreamsMap.init(testing.allocator, true);
    defer streams.deinit();

    var pending_frames = frame_mod.PendingFrameQueue{};
    const keys = try testServerKeys();

    var out_buf: [1500]u8 = undefined;
    const written = try packer.packCoalesced(
        &out_buf,
        &pkt_handler,
        &crypto_mgr,
        &streams,
        &pending_frames,
        null,
        null,
        null,
        keys.seal, // app_seal
        1000,
        null,
        false,
    );

    try testing.expect(written > 0);

    // HANDSHAKE_DONE is one-shot: cleared by packer after writing, re-armed by PTO/loss
    try testing.expect(!packer.send_handshake_done);

    // Sent packet should be tracked as ack-eliciting with handshake_done
    const app_idx = @intFromEnum(ack_handler.EncLevel.application);
    try testing.expectEqual(@as(usize, 1), pkt_handler.sent[app_idx].sent_packets.count());
    var it = pkt_handler.sent[app_idx].sent_packets.iterator();
    const pkt = it.next().?.value_ptr;
    try testing.expect(pkt.ack_eliciting);
    try testing.expect(pkt.has_handshake_done);
}

test "PacketPacker: ecn_mark propagates to SentPacket" {
    const scid = &[_]u8{0x01};
    const dcid = &[_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    var packer = PacketPacker.init(testing.allocator, false, scid, dcid, 0x00000001);
    packer.ecn_mark = true;

    var pkt_handler = ack_handler.PacketHandler.init(testing.allocator);
    defer pkt_handler.deinit();

    var crypto_mgr = crypto_stream.CryptoStreamManager.init(testing.allocator);
    defer crypto_mgr.deinit();

    var streams = stream_mod.StreamsMap.init(testing.allocator, false);
    defer streams.deinit();

    var pending_frames = frame_mod.PendingFrameQueue{};

    // Need ack-eliciting content — add stream data
    streams.setMaxStreams(10, 10);
    streams.setPeerInitialMaxStreamData(65536, 65536, 65536);
    const s = try streams.openBidiStream();
    try s.send.writeData("ecn test data");

    const keys = try testClientKeys();

    var out_buf: [1500]u8 = undefined;
    const written = try packer.packCoalesced(
        &out_buf,
        &pkt_handler,
        &crypto_mgr,
        &streams,
        &pending_frames,
        null,
        null,
        null,
        keys.seal,
        1000,
        null,
        false,
    );

    try testing.expect(written > 0);

    // Check the sent packet has ecn_marked set
    const app_idx = @intFromEnum(ack_handler.EncLevel.application);
    var it = pkt_handler.sent[app_idx].sent_packets.iterator();
    const pkt = it.next().?.value_ptr;
    try testing.expect(pkt.ecn_marked);
    try testing.expect(pkt.ack_eliciting);
}

test "PacketPacker: key_phase bit in short header" {
    const scid = &[_]u8{0x01};
    const dcid = &[_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    var packer = PacketPacker.init(testing.allocator, false, scid, dcid, 0x00000001);

    var pkt_handler = ack_handler.PacketHandler.init(testing.allocator);
    defer pkt_handler.deinit();

    var crypto_mgr = crypto_stream.CryptoStreamManager.init(testing.allocator);
    defer crypto_mgr.deinit();

    var streams = stream_mod.StreamsMap.init(testing.allocator, false);
    defer streams.deinit();

    var pending_frames = frame_mod.PendingFrameQueue{};

    // Add stream data so we produce a packet
    streams.setMaxStreams(10, 10);
    streams.setPeerInitialMaxStreamData(65536, 65536, 65536);
    const s = try streams.openBidiStream();
    try s.send.writeData("test data");

    const keys = try testClientKeys();

    // Pack with key_phase = false
    packer.key_phase = false;
    var out1: [1500]u8 = undefined;
    _ = try packer.packCoalesced(&out1, &pkt_handler, &crypto_mgr, &streams, &pending_frames, null, null, null, keys.seal, 1000, null, false);

    // Write more data and pack with key_phase = true
    try s.send.writeData("more data");
    packer.key_phase = true;
    var out2: [1500]u8 = undefined;
    _ = try packer.packCoalesced(&out2, &pkt_handler, &crypto_mgr, &streams, &pending_frames, null, null, null, keys.seal, 1000, null, false);

    // After header protection is applied, the key_phase bit is masked.
    // But the two packets should differ (different key phase + different content).
    // Just verify both produced output and used different PNs.
    const app_idx = @intFromEnum(ack_handler.EncLevel.application);
    try testing.expectEqual(@as(u64, 2), pkt_handler.next_pn[app_idx]);
}

test "PacketPacker: pending control frames in 1-RTT" {
    const scid = &[_]u8{0x01};
    const dcid = &[_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    var packer = PacketPacker.init(testing.allocator, false, scid, dcid, 0x00000001);

    var pkt_handler = ack_handler.PacketHandler.init(testing.allocator);
    defer pkt_handler.deinit();

    var crypto_mgr = crypto_stream.CryptoStreamManager.init(testing.allocator);
    defer crypto_mgr.deinit();

    var streams = stream_mod.StreamsMap.init(testing.allocator, false);
    defer streams.deinit();

    var pending_frames = frame_mod.PendingFrameQueue{};

    // Queue a PATH_CHALLENGE control frame
    const challenge = [_]u8{ 0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE };
    pending_frames.push(.{ .path_challenge = challenge });

    const keys = try testClientKeys();

    var out_buf: [1500]u8 = undefined;
    const written = try packer.packCoalesced(
        &out_buf,
        &pkt_handler,
        &crypto_mgr,
        &streams,
        &pending_frames,
        null,
        null,
        null,
        keys.seal,
        1000,
        null,
        false,
    );

    try testing.expect(written > 0);

    // Control frame should be consumed from the queue
    try testing.expectEqual(@as(?frame_mod.PendingControlFrame, null), pending_frames.pop());

    // Sent packet should be ack-eliciting
    const app_idx = @intFromEnum(ack_handler.EncLevel.application);
    var it = pkt_handler.sent[app_idx].sent_packets.iterator();
    const pkt = it.next().?.value_ptr;
    try testing.expect(pkt.ack_eliciting);
}

test "PacketPacker: stream frame info tracked in SentPacket" {
    const scid = &[_]u8{0x01};
    const dcid = &[_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    var packer = PacketPacker.init(testing.allocator, false, scid, dcid, 0x00000001);

    var pkt_handler = ack_handler.PacketHandler.init(testing.allocator);
    defer pkt_handler.deinit();

    var crypto_mgr = crypto_stream.CryptoStreamManager.init(testing.allocator);
    defer crypto_mgr.deinit();

    var streams = stream_mod.StreamsMap.init(testing.allocator, false);
    defer streams.deinit();

    var pending_frames = frame_mod.PendingFrameQueue{};

    streams.setMaxStreams(10, 10);
    streams.setPeerInitialMaxStreamData(65536, 65536, 65536);
    const s = try streams.openBidiStream();
    try s.send.writeData("stream data for tracking");

    const keys = try testClientKeys();

    var out_buf: [1500]u8 = undefined;
    _ = try packer.packCoalesced(
        &out_buf,
        &pkt_handler,
        &crypto_mgr,
        &streams,
        &pending_frames,
        null,
        null,
        null,
        keys.seal,
        1000,
        null,
        false,
    );

    // Verify stream frame info was recorded in SentPacket
    const app_idx = @intFromEnum(ack_handler.EncLevel.application);
    var it = pkt_handler.sent[app_idx].sent_packets.iterator();
    const pkt = it.next().?.value_ptr;
    const sf = pkt.getStreamFrames();
    try testing.expect(sf.len > 0);
    try testing.expectEqual(@as(u64, 0), sf[0].stream_id);
    try testing.expectEqual(@as(u64, 0), sf[0].offset);
    try testing.expect(sf[0].length > 0);
}
