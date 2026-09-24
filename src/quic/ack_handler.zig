const std = @import("std");
const assert = std.debug.assert;
const sys = @import("../sys.zig");
const Allocator = std.mem.Allocator;
const testing = std.testing;

const ranges = @import("ranges.zig");
const RangeSet = ranges.RangeSet;
const rtt_mod = @import("rtt.zig");
const RttStats = rtt_mod.RttStats;
const frame_mod = @import("frame.zig");
const Frame = frame_mod.Frame;
const AckRange = frame_mod.AckRange;
const MAX_ACK_RANGES = frame_mod.MAX_ACK_RANGES;

/// Encryption level / packet number space.
pub const EncLevel = enum(u2) {
    initial = 0,
    handshake = 1,
    application = 2,
};

/// Application packet numbers between skips, at first and at most.
const SKIP_INITIAL_PERIOD: u64 = 24;
const SKIP_MAX_PERIOD: u64 = 10_000;

/// The number of packet-reordering threshold for declaring loss (RFC 9002).
const PACKET_THRESHOLD: u64 = 3;

/// Maximum number of ACK-eliciting packets before forcing an ACK.
const ACK_ELICITING_THRESHOLD: u32 = 2;

/// Default max ACK delay (25ms in nanoseconds).
const DEFAULT_MAX_ACK_DELAY: i64 = 25_000_000;

/// Maximum PTO (60 seconds in nanoseconds).
const MAX_PTO: i64 = 60_000_000_000;

/// Maximum PTO for Initial/Handshake spaces (3 seconds in nanoseconds).
/// Caps backoff to ensure timely retransmission under extreme packet loss.
const MAX_HANDSHAKE_PTO: i64 = 3_000_000_000;

/// Maximum number of stream frame records per sent packet.
/// Must be large enough to track all stream frames in a packet (e.g., many small 0-RTT streams).
// Cap inline stream-frame records per sent packet. Each is 32 bytes and lives
// inside SentPacket (one per in-flight packet). A 1200-byte MTU can't fit many
// usefully-sized stream frames anyway — 12 is generous for real traffic and
// keeps SentPacket at ~432 bytes instead of ~1.6KB.
pub const MAX_STREAM_FRAMES_PER_PACKET: usize = 12;

/// Retransmittable control frames recorded per sent packet. A packet that
/// has used them all takes no more such frames; they wait for the next one.
pub const MAX_CONTROL_FRAMES_PER_PACKET: usize = 4;

/// A control frame RFC 9000 13.3 has us repeat when its packet is lost. Flow
/// control credit is recorded by kind only: on loss the current value is sent,
/// never the stale one. RESET_STREAM keeps everything, because a reset uni
/// stream is freed as soon as the frame is queued.
pub const SentControlFrame = union(enum) {
    max_data: void,
    max_stream_data: u64,
    max_streams_bidi: void,
    max_streams_uni: void,
    data_blocked: u64,
    stream_data_blocked: struct { stream_id: u64, limit: u64 },
    streams_blocked_bidi: u64,
    streams_blocked_uni: u64,
    reset_stream: struct { stream_id: u64, error_code: u64, final_size: u64 },
    stop_sending: struct { stream_id: u64, error_code: u64 },
    new_connection_id: u64,
    retire_connection_id: u64,
    new_token: void,

    /// The record for a queued frame, or null for one that is never repeated
    /// (PING, PATH_*, CONNECTION_CLOSE, ACK_FREQUENCY, IMMEDIATE_ACK).
    pub fn from(pcf: frame_mod.PendingControlFrame) ?SentControlFrame {
        return switch (pcf) {
            .max_data => .max_data,
            .max_stream_data => |m| .{ .max_stream_data = m.stream_id },
            .max_streams_bidi => .max_streams_bidi,
            .max_streams_uni => .max_streams_uni,
            .data_blocked => |l| .{ .data_blocked = l },
            .stream_data_blocked => |b| .{ .stream_data_blocked = .{ .stream_id = b.stream_id, .limit = b.limit } },
            .streams_blocked_bidi => |l| .{ .streams_blocked_bidi = l },
            .streams_blocked_uni => |l| .{ .streams_blocked_uni = l },
            .reset_stream => |r| .{ .reset_stream = .{ .stream_id = r.stream_id, .error_code = r.error_code, .final_size = r.final_size } },
            .stop_sending => |ss| .{ .stop_sending = .{ .stream_id = ss.stream_id, .error_code = ss.error_code } },
            .new_connection_id => |n| .{ .new_connection_id = n.seq_num },
            .retire_connection_id => |seq| .{ .retire_connection_id = seq },
            .new_token => .new_token,
            .ping, .path_challenge, .path_response, .connection_close, .ack_frequency, .immediate_ack => null,
        };
    }
};

/// Tracks which stream data was carried in a sent packet for retransmission on loss.
pub const StreamFrameInfo = struct {
    stream_id: u64,
    offset: u64,
    length: u64,
    fin: bool,
};

/// Metadata stored for each sent packet.
pub const SentPacket = struct {
    pn: u64,
    time_sent: i64,
    size: u64,
    ack_eliciting: bool,
    in_flight: bool,
    enc_level: EncLevel,
    largest_acked: ?u64 = null,
    ecn_marked: bool = false,

    /// Stream frames carried by this packet (for retransmission on loss).
    stream_frames: [MAX_STREAM_FRAMES_PER_PACKET]StreamFrameInfo = undefined,
    stream_frame_count: u8 = 0,

    /// Whether this packet contains CRYPTO frame data (for retransmission on loss).
    has_crypto_data: bool = false,

    /// Whether this packet contains HANDSHAKE_DONE (for retransmission on loss).
    has_handshake_done: bool = false,

    /// Whether this packet contains DATAGRAM frames (for stats tracking on loss).
    has_datagram: bool = false,

    /// Control frames to repeat if this packet is lost.
    control_frames: [MAX_CONTROL_FRAMES_PER_PACKET]SentControlFrame = undefined,
    control_frame_count: u8 = 0,

    pub fn getControlFrames(self: *const SentPacket) []const SentControlFrame {
        return self.control_frames[0..self.control_frame_count];
    }

    /// Record a stream frame carried by this packet.
    pub fn addStreamFrame(self: *SentPacket, info: StreamFrameInfo) void {
        if (self.stream_frame_count < MAX_STREAM_FRAMES_PER_PACKET) {
            self.stream_frames[self.stream_frame_count] = info;
            self.stream_frame_count += 1;
        }
    }

    /// Get the recorded stream frames.
    pub fn getStreamFrames(self: *const SentPacket) []const StreamFrameInfo {
        return self.stream_frames[0..self.stream_frame_count];
    }
};

/// Heap-backed list of SentPackets for ACK results.
///
/// Bulk benchmark rows can acknowledge or declare lost thousands of packets in
/// a single ACK/loss pass after ACK compression or loss bursts. A fixed small
/// result buffer silently dropped the excess packets, which left
/// bytes_in_flight and stream ack_offset accounting stale even though packets
/// had been removed from the sent-packet map.
pub const SentPacketList = struct {
    items: std.ArrayListUnmanaged(*SentPacket) = .empty,

    pub fn deinit(self: *SentPacketList, allocator: Allocator) void {
        self.items.deinit(allocator);
    }

    pub fn clearRetainingCapacity(self: *SentPacketList) void {
        self.items.clearRetainingCapacity();
    }

    pub fn append(self: *SentPacketList, allocator: Allocator, item: *SentPacket) !void {
        try self.items.append(allocator, item);
    }

    pub fn constSlice(self: *const SentPacketList) []const *SentPacket {
        return self.items.items;
    }

    pub fn count(self: *const SentPacketList) usize {
        return self.items.items.len;
    }
};

/// Heap-backed list of u64 for tracking packet numbers.
const PnList = struct {
    items: std.ArrayListUnmanaged(u64) = .empty,

    pub fn deinit(self: *PnList, allocator: Allocator) void {
        self.items.deinit(allocator);
    }

    pub fn append(self: *PnList, allocator: Allocator, item: u64) !void {
        try self.items.append(allocator, item);
    }

    pub fn constSlice(self: *const PnList) []const u64 {
        return self.items.items;
    }
};

/// Result of processing an ACK frame.
/// The packets an ACK or a loss pass took out of a tracker. They belong to
/// that tracker's pool until `release`, which the caller runs once done.
pub const AckResult = struct {
    acked: SentPacketList = .{},
    lost: SentPacketList = .{},
    persistent_congestion: bool = false,
    owner: ?*SentPacketTracker = null,

    pub fn deinit(self: *AckResult, allocator: Allocator) void {
        self.reset();
        self.acked.deinit(allocator);
        self.lost.deinit(allocator);
    }

    /// Return the packets to their tracker and empty the lists.
    pub fn reset(self: *AckResult) void {
        if (self.owner) |t| {
            for (self.acked.constSlice()) |pkt| t.pool.destroy(pkt);
            for (self.lost.constSlice()) |pkt| t.pool.destroy(pkt);
            t.live -= self.acked.count() + self.lost.count();
        }
        self.owner = null;
        self.acked.clearRetainingCapacity();
        self.lost.clearRetainingCapacity();
        self.persistent_congestion = false;
    }

    /// `reset`, keeping room for a typical ACK and freeing what a burst grew.
    pub fn release(self: *AckResult, allocator: Allocator) void {
        const owner = self.owner;
        self.reset();
        // Callers release before the next result is taken: nothing else holds any.
        if (std.debug.runtime_safety) if (owner) |t| {
            if (t.live != t.sent_packets.count()) std.debug.panic("{d} SentPackets outstanding", .{t.live - t.sent_packets.count()});
        };
        const keep = 64;
        inline for (.{ &self.acked, &self.lost }) |list| {
            if (list.items.capacity > keep) {
                list.deinit(allocator);
                list.* = .{};
            }
        }
    }
};

/// Tracks sent packets and handles loss detection for a single packet number space.
pub const SentPacketTracker = struct {
    allocator: Allocator,
    /// Dense array-backed map: no tombstones on removal, so iterator() is always
    /// O(count) not O(capacity). Critical for detectLostPackets() which iterates
    /// on every ACK — with AutoHashMap, tombstone bloat after thousands of
    /// insert/remove cycles caused progressive latency degradation.
    /// Values point into `pool`: removal moves a pointer, not a 568-byte record.
    sent_packets: std.AutoArrayHashMapUnmanaged(u64, *SentPacket),
    pool: std.heap.MemoryPool(SentPacket) = .empty,
    /// Packets taken from `pool` and not yet returned, in the map or a result.
    live: usize = 0,
    largest_sent: ?u64 = null,
    largest_acked: ?u64 = null,
    loss_time: ?i64 = null,
    ack_eliciting_in_flight: u32 = 0,
    /// Time of the most recent ack-eliciting packet sent in this space.
    /// Used as PTO baseline when ack_eliciting_in_flight drops to 0 during handshake.
    last_ack_eliciting_sent_time: ?i64 = null,
    /// Per-space PTO count (exponential backoff). Reset when ACK is received
    /// for this space. Separate from other spaces to allow independent backoff.
    pto_count: u32 = 0,

    pub fn init(allocator: Allocator) SentPacketTracker {
        return .{
            .allocator = allocator,
            .sent_packets = .{},
        };
    }

    pub fn deinit(self: *SentPacketTracker) void {
        self.sent_packets.deinit(self.allocator);
        self.pool.deinit(self.allocator);
    }

    /// Forget every packet, keeping the pool: an AckResult may still hold some.
    pub fn clear(self: *SentPacketTracker) void {
        for (self.sent_packets.values()) |pkt| self.pool.destroy(pkt);
        const live = self.live - self.sent_packets.count();
        self.sent_packets.clearAndFree(self.allocator);
        const allocator = self.allocator;
        const pool = self.pool;
        self.* = .{ .allocator = allocator, .sent_packets = .{}, .pool = pool, .live = live };
    }

    pub fn onPacketSent(self: *SentPacketTracker, pkt: SentPacket) !void {
        if (self.largest_sent == null or pkt.pn > self.largest_sent.?) {
            self.largest_sent = pkt.pn;
        }
        if (pkt.ack_eliciting) {
            self.ack_eliciting_in_flight += 1;
            self.last_ack_eliciting_sent_time = pkt.time_sent;
        }
        const p = try self.pool.create(self.allocator);
        errdefer self.pool.destroy(p);
        p.* = pkt;
        try self.sent_packets.put(self.allocator, pkt.pn, p);
        self.live += 1;
    }

    pub fn onAckReceived(
        self: *SentPacketTracker,
        largest_ack: u64,
        ack_delay_ns: i64,
        ack_ranges: []const AckRange,
        first_ack_range: u64,
        rtt_stats: *RttStats,
        now: i64,
        result: *AckResult,
    ) !void {
        result.reset();
        result.owner = self;

        if (self.largest_acked == null or largest_ack > self.largest_acked.?) {
            self.largest_acked = largest_ack;
        }

        // ACK ranges can span hundreds of thousands of packet numbers after ACK
        // compression. Iterate the packets still in flight instead of walking
        // every packet number in the encoded ranges.
        const first_range_start = largest_ack -| first_ack_range;
        var i: usize = 0;
        while (i < self.sent_packets.count()) {
            const pn = self.sent_packets.keys()[i];
            var acked = pn >= first_range_start and pn <= largest_ack;
            if (!acked) {
                for (ack_ranges) |range| {
                    if (pn >= range.start and pn <= range.end) {
                        acked = true;
                        break;
                    }
                }
            }
            if (!acked) {
                i += 1;
                continue;
            }

            const pkt = self.sent_packets.fetchSwapRemove(pn).?.value;
            if (pkt.ack_eliciting) {
                self.ack_eliciting_in_flight -|= 1;
            }

            if (pkt.pn == largest_ack) {
                const send_delta = now - pkt.time_sent;
                rtt_stats.updateRtt(send_delta, ack_delay_ns, true);
            }

            try result.acked.append(self.allocator, pkt);
        }

        // Detect lost packets
        try self.detectLostPackets(rtt_stats, now, result);
    }

    fn detectLostPackets(self: *SentPacketTracker, rtt_stats: *RttStats, now: i64, result: *AckResult) !void {
        assert(result.owner == null or result.owner == self);
        result.owner = self;
        self.loss_time = null;
        const loss_delay = rtt_stats.lossDelay();
        const lost_send_time = now - loss_delay;

        var to_remove: PnList = .{};
        defer to_remove.deinit(self.allocator);

        // Track earliest and latest send times of lost ack-eliciting packets
        // for persistent congestion detection (RFC 9002 §7.6.2)
        var earliest_lost_time: ?i64 = null;
        var latest_lost_time: ?i64 = null;

        var it = self.sent_packets.iterator();
        while (it.next()) |entry| {
            const pkt = entry.value_ptr.*;
            if (self.largest_acked == null or pkt.pn > self.largest_acked.?) {
                continue;
            }

            if (pkt.time_sent <= lost_send_time) {
                try result.lost.append(self.allocator, pkt);
                try to_remove.append(self.allocator, pkt.pn);
                if (pkt.ack_eliciting) {
                    if (earliest_lost_time == null or pkt.time_sent < earliest_lost_time.?) {
                        earliest_lost_time = pkt.time_sent;
                    }
                    if (latest_lost_time == null or pkt.time_sent > latest_lost_time.?) {
                        latest_lost_time = pkt.time_sent;
                    }
                }
                continue;
            }

            if (self.largest_acked.? >= PACKET_THRESHOLD and
                pkt.pn <= self.largest_acked.? - PACKET_THRESHOLD)
            {
                try result.lost.append(self.allocator, pkt);
                try to_remove.append(self.allocator, pkt.pn);
                if (pkt.ack_eliciting) {
                    if (earliest_lost_time == null or pkt.time_sent < earliest_lost_time.?) {
                        earliest_lost_time = pkt.time_sent;
                    }
                    if (latest_lost_time == null or pkt.time_sent > latest_lost_time.?) {
                        latest_lost_time = pkt.time_sent;
                    }
                }
                continue;
            }

            const loss_time_for_pkt = pkt.time_sent + loss_delay;
            if (self.loss_time == null or loss_time_for_pkt < self.loss_time.?) {
                self.loss_time = loss_time_for_pkt;
            }
        }

        for (to_remove.constSlice()) |pn| {
            _ = self.sent_packets.swapRemove(pn);
        }

        // Persistent congestion: if the time span of lost ack-eliciting packets
        // exceeds the persistent congestion threshold (RFC 9002 §7.6.2)
        if (earliest_lost_time != null and latest_lost_time != null) {
            const span = latest_lost_time.? - earliest_lost_time.?;
            if (span > rtt_stats.persistentCongestionThreshold()) {
                result.persistent_congestion = true;
            }
        }
    }
};

/// Received-packet ranges kept per space; the oldest go first. An ACK frame
/// carries at most `MAX_ACK_RANGES` + 1 of them anyway.
pub const MAX_RECEIVED_RANGES: usize = 64;

/// Tracks received packets for generating ACK frames.
pub const ReceivedPacketTracker = struct {
    allocator: Allocator,
    received: RangeSet,
    largest_received: ?u64 = null,
    largest_received_time: i64 = 0,
    ack_eliciting_since_last_ack: u32 = 0,
    ack_queued: bool = false,
    ack_alarm: ?i64 = null,
    ecn_ect0: u64 = 0,
    ecn_ect1: u64 = 0,
    ecn_ce: u64 = 0,
    /// Highest PN that was pruned — any PN at or below this is a duplicate
    largest_pruned: ?u64 = null,

    // draft-ietf-quic-ack-frequency: configurable ACK generation parameters
    ack_eliciting_threshold: u32 = ACK_ELICITING_THRESHOLD,
    max_ack_delay_ns: i64 = DEFAULT_MAX_ACK_DELAY,
    reordering_threshold: u64 = 1, // 0 = no reorder-triggered ACKs
    ack_frequency_seq: u64 = 0, // highest received ACK_FREQUENCY sequence number

    pub fn init(allocator: Allocator) ReceivedPacketTracker {
        return .{
            .allocator = allocator,
            .received = RangeSet.init(allocator),
        };
    }

    pub fn deinit(self: *ReceivedPacketTracker) void {
        self.received.deinit();
    }

    pub fn onPacketReceived(self: *ReceivedPacketTracker, pn: u64, ack_eliciting: bool, now: i64, ecn: u2) !void {
        if (self.received.contains(pn)) return;
        try self.received.add(pn);
        // A peer skipping every other PN would otherwise grow this without
        // bound. Packets in the gaps we forget read as duplicates from here on.
        const tracked = self.received.getRanges();
        if (tracked.len > MAX_RECEIVED_RANGES) {
            self.pruneAckedRanges(tracked[MAX_RECEIVED_RANGES - 1].start);
        }

        if (self.largest_received == null or pn > self.largest_received.?) {
            self.largest_received = pn;
            self.largest_received_time = now;
        }

        // Increment ECN counters (RFC 9000 §13.4.2)
        switch (ecn) {
            0b10 => self.ecn_ect0 += 1, // ECT(0)
            0b01 => self.ecn_ect1 += 1, // ECT(1)
            0b11 => self.ecn_ce += 1, // CE
            0b00 => {}, // Not-ECT
        }

        if (ack_eliciting) {
            self.ack_eliciting_since_last_ack += 1;

            // Reordering-based immediate ACK (draft-ietf-quic-ack-frequency)
            if (self.largest_received != null and pn < self.largest_received.?) {
                if (self.reordering_threshold > 0) {
                    const gap = self.largest_received.? - pn;
                    if (gap >= self.reordering_threshold) {
                        self.ack_queued = true;
                        self.ack_alarm = null;
                    }
                }
                // If reordering_threshold == 0, don't trigger immediate ACK on reorder
            } else if (self.ack_eliciting_since_last_ack >= self.ack_eliciting_threshold) {
                self.ack_queued = true;
                self.ack_alarm = null;
            } else {
                if (self.ack_alarm == null) {
                    self.ack_alarm = now + self.max_ack_delay_ns;
                }
            }
        }
    }

    /// Apply ACK_FREQUENCY frame parameters (draft-ietf-quic-ack-frequency).
    /// Ignores frames with sequence numbers not greater than the last applied.
    pub fn applyAckFrequency(self: *ReceivedPacketTracker, seq: u64, threshold: u64, max_delay_us: u64, reorder_threshold: u64) bool {
        if (self.ack_frequency_seq > 0 and seq < self.ack_frequency_seq) return false;
        self.ack_frequency_seq = seq + 1; // store next expected (> current)
        self.ack_eliciting_threshold = @intCast(@max(1, @min(threshold, 256)));
        self.max_ack_delay_ns = @intCast(max_delay_us * 1000); // µs → ns
        self.reordering_threshold = reorder_threshold;
        return true;
    }

    /// Force immediate ACK transmission (IMMEDIATE_ACK frame, draft-ietf-quic-ack-frequency).
    pub fn triggerImmediateAck(self: *ReceivedPacketTracker) void {
        if (self.largest_received != null) {
            self.ack_queued = true;
            self.ack_alarm = null;
        }
    }

    pub fn isDuplicate(self: *const ReceivedPacketTracker, pn: u64) bool {
        // Any PN at or below the largest pruned value is a duplicate
        // (we already ACKed it and the peer confirmed receipt).
        if (self.largest_pruned) |lp| {
            if (pn <= lp) return true;
        }
        return self.received.contains(pn);
    }

    /// Prune received ranges below the given packet number (RFC 9000 §13.2.4).
    /// Called when the peer ACKs a packet that contained our ACK for ranges up to this value.
    pub fn pruneAckedRanges(self: *ReceivedPacketTracker, below: u64) void {
        self.received.removeBelow(below);
        if (below > 0) {
            const pruned = below - 1;
            if (self.largest_pruned == null or pruned > self.largest_pruned.?) {
                self.largest_pruned = pruned;
            }
        }
    }

    /// Check if there are any unacknowledged ack-eliciting packets.
    /// Used by the packet packer to piggyback ACKs on outgoing data packets.
    pub fn hasUnackedAckEliciting(self: *const ReceivedPacketTracker) bool {
        return self.ack_eliciting_since_last_ack > 0;
    }

    pub fn getAckFrame(self: *ReceivedPacketTracker, now: i64, ack_delay_exponent: u64) ?Frame {
        return self.getAckFrameImpl(now, ack_delay_exponent, false);
    }

    /// Generate an ACK frame regardless of threshold/alarm timers.
    /// Used to piggyback ACKs on outgoing data packets (RFC 9000 §13.2.1).
    pub fn getAckFrameForced(self: *ReceivedPacketTracker, now: i64, ack_delay_exponent: u64) ?Frame {
        return self.getAckFrameImpl(now, ack_delay_exponent, true);
    }

    fn getAckFrameImpl(self: *ReceivedPacketTracker, now: i64, ack_delay_exponent: u64, force: bool) ?Frame {
        if (!force and !self.ack_queued) {
            if (self.ack_alarm) |alarm| {
                if (now < alarm) return null;
            } else {
                return null;
            }
        }

        const largest = self.largest_received orelse return null;
        const recv_ranges = self.received.getRanges();
        if (recv_ranges.len == 0) return null;

        const first_range = recv_ranges[0];
        const first_ack_range = largest - first_range.start;

        const ack_delay_ns = now - self.largest_received_time;
        const ack_delay_us: u64 = @intCast(@max(0, @divTrunc(ack_delay_ns, 1000)));
        const ack_delay_encoded = ack_delay_us >> @intCast(ack_delay_exponent);

        self.ack_queued = false;
        self.ack_alarm = null;
        self.ack_eliciting_since_last_ack = 0;

        // Populate additional ACK ranges from received range set
        var ack_ranges: [MAX_ACK_RANGES]AckRange = undefined;
        var ack_range_count: u8 = 0;
        if (recv_ranges.len > 1) {
            for (recv_ranges[1..]) |r| {
                if (ack_range_count >= MAX_ACK_RANGES) break;
                ack_ranges[ack_range_count] = .{ .start = r.start, .end = r.end };
                ack_range_count += 1;
            }
        }

        // Use ACK_ECN when any ECN counter is non-zero (RFC 9000 §13.4.2)
        if (self.ecn_ect0 > 0 or self.ecn_ect1 > 0 or self.ecn_ce > 0) {
            return Frame{
                .ack_ecn = .{
                    .largest_ack = largest,
                    .ack_delay = ack_delay_encoded,
                    .first_ack_range = first_ack_range,
                    .ack_range_count = ack_range_count,
                    .ack_ranges = ack_ranges,
                    .ecn_ect0 = self.ecn_ect0,
                    .ecn_ect1 = self.ecn_ect1,
                    .ecn_ce = self.ecn_ce,
                },
            };
        }

        return Frame{
            .ack = .{
                .largest_ack = largest,
                .ack_delay = ack_delay_encoded,
                .first_ack_range = first_ack_range,
                .ack_range_count = ack_range_count,
                .ack_ranges = ack_ranges,
            },
        };
    }
};

/// Top-level packet handler that manages all three packet number spaces.
pub const PacketHandler = struct {
    allocator: Allocator,
    sent: [3]SentPacketTracker,
    recv: [3]ReceivedPacketTracker,
    rtt_stats: RttStats = .{},
    bytes_in_flight: u64 = 0,
    pto_count: u32 = 0,
    next_pn: [3]u64 = .{ 0, 0, 0 },

    /// RFC 9000 21.4: the application space leaves the odd packet number
    /// unsent, so a peer acking what it never received (to inflate our
    /// window) names one of these and is caught. The gap between skips
    /// doubles, as quic-go's does, so the cost fades on long connections.
    skip_pn: u64 = SKIP_INITIAL_PERIOD,
    skip_period: u64 = SKIP_INITIAL_PERIOD,
    skipped_pns: [2]?u64 = .{ null, null },

    pub fn init(allocator: Allocator) PacketHandler {
        return .{
            .allocator = allocator,
            .sent = .{
                SentPacketTracker.init(allocator),
                SentPacketTracker.init(allocator),
                SentPacketTracker.init(allocator),
            },
            .recv = .{
                ReceivedPacketTracker.init(allocator),
                ReceivedPacketTracker.init(allocator),
                ReceivedPacketTracker.init(allocator),
            },
        };
    }

    pub fn deinit(self: *PacketHandler) void {
        for (&self.sent) |*s| s.deinit();
        for (&self.recv) |*r| r.deinit();
    }

    pub fn nextPacketNumber(self: *PacketHandler, level: EncLevel) u64 {
        const idx = @intFromEnum(level);
        if (level == .application and self.next_pn[idx] == self.skip_pn) {
            self.skipped_pns = .{ self.skip_pn, self.skipped_pns[0] };
            self.next_pn[idx] += 1;
            self.skip_period = @min(self.skip_period * 2, SKIP_MAX_PERIOD);
            const half = self.skip_period / 2;
            self.skip_pn = self.next_pn[idx] + half + sys.randomInt(u64) % half;
        }
        const pn = self.next_pn[idx];
        self.next_pn[idx] += 1;
        return pn;
    }

    /// Whether an ACK claims a packet we never sent: one past the last we
    /// numbered, or one we skipped. RFC 9000 13.1 makes either a
    /// PROTOCOL_VIOLATION.
    pub fn acksUnsentPacket(
        self: *const PacketHandler,
        level: EncLevel,
        largest_ack: u64,
        first_ack_range: u64,
        ack_ranges: []const AckRange,
    ) bool {
        if (largest_ack >= self.next_pn[@intFromEnum(level)]) return true;
        if (level != .application) return false;
        for (self.skipped_pns) |maybe| {
            const skipped = maybe orelse continue;
            if (skipped <= largest_ack and skipped >= largest_ack -| first_ack_range) return true;
            for (ack_ranges) |r| {
                if (skipped >= r.start and skipped <= r.end) return true;
            }
        }
        return false;
    }

    /// Return the largest packet number acknowledged by the peer for this level.
    pub fn getLargestAcked(self: *const PacketHandler, level: EncLevel) ?u64 {
        const idx = @intFromEnum(level);
        return self.sent[idx].largest_acked;
    }

    pub fn onPacketSent(self: *PacketHandler, pkt: SentPacket) !void {
        const idx = @intFromEnum(pkt.enc_level);
        try self.sent[idx].onPacketSent(pkt);
        if (pkt.in_flight) {
            self.bytes_in_flight += pkt.size;
        }
    }

    pub fn onPacketReceived(self: *PacketHandler, level: EncLevel, pn: u64, ack_eliciting: bool, now: i64, ecn: u2) !void {
        const idx = @intFromEnum(level);
        try self.recv[idx].onPacketReceived(pn, ack_eliciting, now, ecn);
    }

    pub fn onAckReceived(
        self: *PacketHandler,
        level: EncLevel,
        largest_ack: u64,
        ack_delay_encoded: u64,
        ack_delay_exponent: u6,
        ack_ranges: []const AckRange,
        first_ack_range: u64,
        now: i64,
        result: *AckResult,
    ) !void {
        const idx = @intFromEnum(level);

        const ack_delay_us = ack_delay_encoded << ack_delay_exponent;
        const ack_delay_ns: i64 = @intCast(ack_delay_us * 1000);

        try self.sent[idx].onAckReceived(
            largest_ack,
            ack_delay_ns,
            ack_ranges,
            first_ack_range,
            &self.rtt_stats,
            now,
            result,
        );

        // ACK-of-ACK pruning (RFC 9000 §13.2.4): when an acked packet contained
        // our ACK frame, prune received ranges below that ACK's largest_ack
        var max_ack_of_ack: ?u64 = null;
        for (result.acked.constSlice()) |pkt| {
            if (pkt.in_flight) {
                self.bytes_in_flight -|= pkt.size;
            }
            if (pkt.largest_acked) |la| {
                if (max_ack_of_ack == null or la > max_ack_of_ack.?) {
                    max_ack_of_ack = la;
                }
            }
        }
        if (max_ack_of_ack) |prune_below| {
            self.recv[idx].pruneAckedRanges(prune_below);
        }

        for (result.lost.constSlice()) |pkt| {
            if (pkt.in_flight) {
                self.bytes_in_flight -|= pkt.size;
            }
        }

        self.pto_count = 0;
        self.sent[idx].pto_count = 0;
    }

    pub fn getAckFrame(self: *PacketHandler, level: EncLevel, now: i64, ack_delay_exponent: u64) ?Frame {
        const idx = @intFromEnum(level);
        return self.recv[idx].getAckFrame(now, ack_delay_exponent);
    }

    /// Generate an ACK frame regardless of threshold/alarm timers.
    /// Used to piggyback ACKs when the packet already carries data.
    pub fn getAckFrameForced(self: *PacketHandler, level: EncLevel, now: i64, ack_delay_exponent: u64) ?Frame {
        const idx = @intFromEnum(level);
        return self.recv[idx].getAckFrameForced(now, ack_delay_exponent);
    }

    /// Check if there are unacked ack-eliciting packets at the given level.
    pub fn hasUnackedAckEliciting(self: *const PacketHandler, level: EncLevel) bool {
        const idx = @intFromEnum(level);
        return self.recv[idx].hasUnackedAckEliciting();
    }

    /// Compute PTO deadline for a single packet number space.
    /// Returns null if the space should not arm PTO (no data, application space idle).
    /// RFC 9002 §6.2.2.1: handshake spaces arm PTO even with no packets in flight.
    pub fn spacePtoDeadline(self: *const PacketHandler, tracker: SentPacketTracker, idx: usize) ?i64 {
        const is_handshake_space = (idx != @intFromEnum(EncLevel.application));
        if (tracker.ack_eliciting_in_flight == 0) {
            if (!(is_handshake_space and tracker.last_ack_eliciting_sent_time != null)) {
                return null;
            }
        }

        const base_time = if (tracker.ack_eliciting_in_flight > 0) blk: {
            const largest_sent = tracker.largest_sent orelse return null;
            // Packet may have been removed from sent_packets after loss detection.
            // Fall back to last_ack_eliciting_sent_time which is always maintained.
            const sent_pkt = tracker.sent_packets.get(largest_sent) orelse
                break :blk tracker.last_ack_eliciting_sent_time orelse return null;
            break :blk sent_pkt.time_sent;
        } else blk: {
            break :blk tracker.last_ack_eliciting_sent_time.?;
        };

        var pto_duration = if (idx == @intFromEnum(EncLevel.application))
            self.rtt_stats.pto()
        else
            self.rtt_stats.ptoNoAckDelay();

        // Use per-space PTO count for independent backoff per encryption level
        const shift: u6 = @intCast(@min(tracker.pto_count, 30));
        pto_duration = pto_duration << shift;
        const max_pto = if (idx == @intFromEnum(EncLevel.application)) MAX_PTO else MAX_HANDSHAKE_PTO;
        pto_duration = @min(pto_duration, max_pto);

        return base_time + pto_duration;
    }

    pub fn getPtoTimeout(self: *const PacketHandler) ?i64 {
        var earliest: ?i64 = null;

        for (self.sent, 0..) |tracker, idx| {
            if (tracker.loss_time) |lt| {
                if (earliest == null or lt < earliest.?) {
                    earliest = lt;
                }
                continue;
            }

            const timeout = self.spacePtoDeadline(tracker, idx) orelse continue;
            if (earliest == null or timeout < earliest.?) {
                earliest = timeout;
            }
        }

        return earliest;
    }

    /// Check if any loss_time has expired. Returns the enc level if so.
    /// RFC 9002 §6.2.1: loss timers fire before PTO and should run loss
    /// detection without incrementing pto_count.
    pub fn getExpiredLossTime(self: *PacketHandler, now: i64) ?EncLevel {
        var earliest: ?i64 = null;
        var result: ?EncLevel = null;
        for (self.sent, 0..) |tracker, idx| {
            if (tracker.loss_time) |lt| {
                if (lt <= now and (earliest == null or lt < earliest.?)) {
                    earliest = lt;
                    result = @enumFromInt(idx);
                }
            }
        }
        return result;
    }

    /// Run loss detection for a specific packet number space (called when loss_time fires).
    /// Returns the lost packets for congestion control processing.
    pub fn detectLossesForSpace(self: *PacketHandler, level: EncLevel, now: i64, result: *AckResult) !void {
        const idx = @intFromEnum(level);
        result.reset();
        try self.sent[idx].detectLostPackets(&self.rtt_stats, now, result);
        for (result.lost.constSlice()) |pkt| {
            if (pkt.in_flight) {
                self.bytes_in_flight -|= pkt.size;
            }
        }
    }

    /// Get the encryption level where PTO should fire (the one with earliest timeout).
    pub fn getPtoSpace(self: *PacketHandler) ?EncLevel {
        var earliest: ?i64 = null;
        var result: ?EncLevel = null;

        for (self.sent, 0..) |tracker, idx| {
            if (tracker.loss_time != null) continue;
            const timeout = self.spacePtoDeadline(tracker, idx) orelse continue;
            if (earliest == null or timeout < earliest.?) {
                earliest = timeout;
                result = @enumFromInt(idx);
            }
        }

        return result;
    }

    pub fn dropSpace(self: *PacketHandler, level: EncLevel) void {
        const idx = @intFromEnum(level);

        var it = self.sent[idx].sent_packets.iterator();
        while (it.next()) |entry| {
            if (entry.value_ptr.*.in_flight) {
                self.bytes_in_flight -|= entry.value_ptr.*.size;
            }
        }

        self.sent[idx].clear();
        self.recv[idx].deinit();
        self.recv[idx] = ReceivedPacketTracker.init(self.allocator);
    }
};

// Tests

test "SentPacketTracker: basic send and ack" {
    var tracker = SentPacketTracker.init(testing.allocator);
    defer tracker.deinit();

    var rtt_stats = RttStats{};
    const now: i64 = 1_000_000_000;

    try tracker.onPacketSent(.{
        .pn = 0,
        .time_sent = now,
        .size = 1200,
        .ack_eliciting = true,
        .in_flight = true,
        .enc_level = .initial,
    });

    try testing.expectEqual(@as(u32, 1), tracker.ack_eliciting_in_flight);

    const ack_time = now + 50_000_000;
    var result: AckResult = .{};
    defer result.deinit(testing.allocator);
    try tracker.onAckReceived(0, 0, &.{}, 0, &rtt_stats, ack_time, &result);

    try testing.expectEqual(@as(usize, 1), result.acked.count());
    try testing.expectEqual(@as(u64, 0), result.acked.constSlice()[0].pn);
    try testing.expectEqual(@as(u32, 0), tracker.ack_eliciting_in_flight);
    try testing.expect(rtt_stats.has_measurement);
}

test "ReceivedPacketTracker: immediate ACK on reorder" {
    var tracker = ReceivedPacketTracker.init(testing.allocator);
    defer tracker.deinit();

    const now: i64 = 1_000_000_000;

    try tracker.onPacketReceived(0, true, now, 0);
    try tracker.onPacketReceived(1, true, now + 1_000_000, 0);

    try testing.expect(tracker.ack_queued);
}

test "SentPacketTracker: large ACK range scans in-flight packets" {
    var tracker = SentPacketTracker.init(testing.allocator);
    defer tracker.deinit();

    var rtt_stats = RttStats{};
    const now: i64 = 1_000_000_000;

    try tracker.onPacketSent(.{
        .pn = 10,
        .time_sent = now,
        .size = 1200,
        .ack_eliciting = true,
        .in_flight = true,
        .enc_level = .application,
    });
    try tracker.onPacketSent(.{
        .pn = 1_000_000,
        .time_sent = now + 1_000,
        .size = 1200,
        .ack_eliciting = true,
        .in_flight = true,
        .enc_level = .application,
    });

    var result: AckResult = .{};
    defer result.deinit(testing.allocator);
    try tracker.onAckReceived(1_000_000, 0, &.{}, 999_990, &rtt_stats, now + 50_000_000, &result);

    try testing.expectEqual(@as(usize, 2), result.acked.count());
    try testing.expectEqual(@as(usize, 0), tracker.sent_packets.count());
    try testing.expectEqual(@as(u32, 0), tracker.ack_eliciting_in_flight);
}

test "PacketHandler: integration" {
    var handler = PacketHandler.init(testing.allocator);
    defer handler.deinit();

    const now: i64 = 1_000_000_000;

    const pn = handler.nextPacketNumber(.initial);
    try handler.onPacketSent(.{
        .pn = pn,
        .time_sent = now,
        .size = 1200,
        .ack_eliciting = true,
        .in_flight = true,
        .enc_level = .initial,
    });

    try testing.expectEqual(@as(u64, 1200), handler.bytes_in_flight);

    try handler.onPacketReceived(.initial, 0, true, now, 0);

    const ack_time = now + 50_000_000;
    var result: AckResult = .{};
    defer result.deinit(testing.allocator);
    try handler.onAckReceived(.initial, 0, 0, 3, &.{}, 0, ack_time, &result);

    try testing.expectEqual(@as(u64, 0), handler.bytes_in_flight);
}

test "ReceivedPacketTracker: ECN counters and ACK_ECN generation" {
    var tracker = ReceivedPacketTracker.init(testing.allocator);
    defer tracker.deinit();

    const now: i64 = 1_000_000_000;

    // Receive packets with ECN marks
    try tracker.onPacketReceived(0, true, now, 0b10); // ECT(0)
    try tracker.onPacketReceived(1, true, now + 1_000_000, 0b10); // ECT(0)
    try tracker.onPacketReceived(2, true, now + 2_000_000, 0b11); // CE

    try testing.expectEqual(@as(u64, 2), tracker.ecn_ect0);
    try testing.expectEqual(@as(u64, 0), tracker.ecn_ect1);
    try testing.expectEqual(@as(u64, 1), tracker.ecn_ce);

    // getAckFrame should return ACK_ECN when ECN counters are non-zero
    const frame = tracker.getAckFrame(now + 3_000_000, 3);
    try testing.expect(frame != null);
    switch (frame.?) {
        .ack_ecn => |ack_ecn| {
            try testing.expectEqual(@as(u64, 2), ack_ecn.largest_ack);
            try testing.expectEqual(@as(u64, 2), ack_ecn.ecn_ect0);
            try testing.expectEqual(@as(u64, 0), ack_ecn.ecn_ect1);
            try testing.expectEqual(@as(u64, 1), ack_ecn.ecn_ce);
        },
        else => return error.TestUnexpectedResult,
    }
}

test "ReceivedPacketTracker: no ECN returns plain ACK" {
    var tracker = ReceivedPacketTracker.init(testing.allocator);
    defer tracker.deinit();

    const now: i64 = 1_000_000_000;

    // Receive packets without ECN marks
    try tracker.onPacketReceived(0, true, now, 0); // Not-ECT
    try tracker.onPacketReceived(1, true, now + 1_000_000, 0); // Not-ECT

    // getAckFrame should return plain ACK
    const frame = tracker.getAckFrame(now + 2_000_000, 3);
    try testing.expect(frame != null);
    switch (frame.?) {
        .ack => {},
        else => return error.TestUnexpectedResult,
    }
}

test "SentPacket: stream frame tracking" {
    var pkt = SentPacket{
        .pn = 0,
        .time_sent = 0,
        .size = 1200,
        .ack_eliciting = true,
        .in_flight = true,
        .enc_level = .application,
    };

    pkt.addStreamFrame(.{ .stream_id = 0, .offset = 0, .length = 100, .fin = false });
    pkt.addStreamFrame(.{ .stream_id = 4, .offset = 50, .length = 200, .fin = true });

    try testing.expectEqual(@as(u8, 2), pkt.stream_frame_count);
    const frames = pkt.getStreamFrames();
    try testing.expectEqual(@as(usize, 2), frames.len);
    try testing.expectEqual(@as(u64, 0), frames[0].stream_id);
    try testing.expectEqual(@as(u64, 0), frames[0].offset);
    try testing.expectEqual(@as(u64, 100), frames[0].length);
    try testing.expect(!frames[0].fin);
    try testing.expectEqual(@as(u64, 4), frames[1].stream_id);
    try testing.expectEqual(@as(u64, 50), frames[1].offset);
    try testing.expectEqual(@as(u64, 200), frames[1].length);
    try testing.expect(frames[1].fin);
}

test "SentPacket: stream frame capacity limit" {
    var pkt = SentPacket{
        .pn = 0,
        .time_sent = 0,
        .size = 1200,
        .ack_eliciting = true,
        .in_flight = true,
        .enc_level = .application,
    };

    // Add MAX_STREAM_FRAMES_PER_PACKET frames
    var i: u64 = 0;
    while (i < MAX_STREAM_FRAMES_PER_PACKET) : (i += 1) {
        pkt.addStreamFrame(.{ .stream_id = i * 4, .offset = 0, .length = 10, .fin = false });
    }

    // Adding one more should be silently ignored (no crash)
    pkt.addStreamFrame(.{ .stream_id = 100, .offset = 0, .length = 10, .fin = false });
    try testing.expectEqual(@as(u8, MAX_STREAM_FRAMES_PER_PACKET), pkt.stream_frame_count);
}

// ACK-of-ACK pruning (RFC 9000 §13.2.4)
test "PacketHandler: skipped application packet numbers are never sent, and an ACK naming one is caught" {
    var handler = PacketHandler.init(testing.allocator);
    defer handler.deinit();

    var last: u64 = 0;
    var gaps: usize = 0;
    var i: usize = 0;
    while (i < 200) : (i += 1) {
        const pn = handler.nextPacketNumber(.application);
        if (i > 0 and pn != last + 1) {
            gaps += 1;
            try testing.expectEqual(last + 2, pn);
            try testing.expect(handler.acksUnsentPacket(.application, pn, 1, &.{}));
            try testing.expect(!handler.acksUnsentPacket(.application, pn, 0, &.{}));
            try testing.expect(handler.acksUnsentPacket(.application, pn, 0, &.{.{ .start = last + 1, .end = last + 1 }}));
        }
        last = pn;
    }
    try testing.expect(gaps >= 2);
    // Handshake spaces number densely: the peer's ACKs there come too early
    // to matter, and those spaces are short-lived.
    try testing.expectEqual(@as(u64, 0), handler.nextPacketNumber(.initial));
    try testing.expectEqual(@as(u64, 1), handler.nextPacketNumber(.initial));
}

test "ReceivedPacketTracker: range count is capped, oldest dropped" {
    var tracker = ReceivedPacketTracker.init(testing.allocator);
    defer tracker.deinit();

    // Every other PN: one range per packet.
    var pn: u64 = 0;
    while (pn < 4 * MAX_RECEIVED_RANGES) : (pn += 2) {
        try tracker.onPacketReceived(pn, true, 0, 0);
    }
    try testing.expectEqual(MAX_RECEIVED_RANGES, tracker.received.len());
    // The newest survive; a forgotten gap now reads as a duplicate.
    try testing.expect(tracker.received.contains(pn - 2));
    try testing.expect(tracker.isDuplicate(1));
    try testing.expect(!tracker.isDuplicate(pn - 1));
}

test "ReceivedPacketTracker: pruneAckedRanges removes old ranges" {
    var tracker = ReceivedPacketTracker.init(testing.allocator);
    defer tracker.deinit();

    // Receive packets 0..9
    var i: u64 = 0;
    while (i < 10) : (i += 1) {
        try tracker.onPacketReceived(i, true, 1000 + @as(i64, @intCast(i)), 0);
    }

    // Ranges should cover 0..9
    try testing.expectEqual(@as(usize, 1), tracker.received.getRanges().len);
    try testing.expectEqual(@as(u64, 0), tracker.received.getRanges()[0].start);

    // Prune below 5 — ranges should now start at 5
    tracker.pruneAckedRanges(5);
    try testing.expectEqual(@as(usize, 1), tracker.received.getRanges().len);
    try testing.expectEqual(@as(u64, 5), tracker.received.getRanges()[0].start);
    try testing.expectEqual(@as(u64, 9), tracker.received.getRanges()[0].end);
}

// App-limited cwnd suppression (RFC 9002 §7.8)
test "NewReno: app_limited suppresses cwnd growth" {
    const cc_mod = @import("congestion.zig");
    var cc = cc_mod.NewReno.init();

    // Normal growth in slow start
    const initial = cc.congestion_window;
    cc.onPacketAcked(1200, 100);
    try testing.expect(cc.congestion_window > initial);

    // Set app_limited — no further growth
    const after_ack = cc.congestion_window;
    cc.app_limited = true;
    cc.onPacketAcked(1200, 200);
    try testing.expectEqual(after_ack, cc.congestion_window);

    // Clear app_limited — growth resumes
    cc.app_limited = false;
    cc.onPacketAcked(1200, 300);
    try testing.expect(cc.congestion_window > after_ack);
}

test "AckResult.release keeps a typical ACK's room and frees a burst's" {
    var result: AckResult = .{};
    defer result.deinit(testing.allocator);
    var pkt: SentPacket = .{ .pn = 0, .time_sent = 0, .size = 1200, .ack_eliciting = true, .in_flight = true, .enc_level = .application };
    for (0..8) |_| try result.acked.append(testing.allocator, &pkt);
    result.release(testing.allocator);
    try testing.expect(result.acked.items.capacity >= 8);

    for (0..1000) |_| try result.lost.append(testing.allocator, &pkt);
    result.release(testing.allocator);
    try testing.expectEqual(@as(usize, 0), result.lost.items.capacity);
    try testing.expect(result.acked.items.capacity >= 8);
}

test "SentPacketTracker: every packet taken from the pool goes back" {
    var ph = PacketHandler.init(testing.allocator);
    defer ph.deinit();
    var result: AckResult = .{};
    defer result.deinit(testing.allocator);
    const app = &ph.sent[@intFromEnum(EncLevel.application)];

    var pn: u64 = 0;
    var now: i64 = 1_000_000;
    for (0..50) |round| {
        // Ten packets; the peer acks all but the first two, which go lost.
        const first = pn;
        for (0..10) |_| {
            try ph.onPacketSent(.{ .pn = pn, .time_sent = now, .size = 1200, .ack_eliciting = true, .in_flight = true, .enc_level = .application });
            pn += 1;
        }
        now += 10_000_000;
        try ph.onAckReceived(.application, pn - 1, 0, 3, &.{}, pn - 1 - (first + 2), now, &result);
        try testing.expectEqual(@as(usize, 8), result.acked.count());
        result.release(testing.allocator);
        // The two left behind are declared lost by the timer, or already were.
        now += 1_000_000_000;
        try ph.detectLossesForSpace(.application, now, &result);
        result.release(testing.allocator);
        try testing.expectEqual(@as(usize, 0), app.sent_packets.count());
        try testing.expectEqual(@as(usize, 0), app.live);
        _ = round;
    }

    // A space dropped while a result still holds its packets.
    try ph.onPacketSent(.{ .pn = pn, .time_sent = now, .size = 1200, .ack_eliciting = true, .in_flight = true, .enc_level = .handshake });
    try ph.onPacketSent(.{ .pn = pn + 1, .time_sent = now, .size = 1200, .ack_eliciting = true, .in_flight = true, .enc_level = .handshake });
    try ph.onAckReceived(.handshake, pn, 0, 3, &.{}, 0, now + 1000, &result);
    ph.dropSpace(.handshake);
    try testing.expectEqual(@as(u64, pn), result.acked.constSlice()[0].pn); // still readable
    result.release(testing.allocator);
    try testing.expectEqual(@as(usize, 0), ph.sent[@intFromEnum(EncLevel.handshake)].live);
}
