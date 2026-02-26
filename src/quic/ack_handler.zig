const std = @import("std");
const Allocator = std.mem.Allocator;
const testing = std.testing;

const ranges = @import("ranges.zig");
const RangeSet = ranges.RangeSet;
const rtt_mod = @import("rtt.zig");
const RttStats = rtt_mod.RttStats;
const Frame = @import("frame.zig").Frame;
const AckRange = @import("frame.zig").AckRange;

/// Encryption level / packet number space.
pub const EncLevel = enum(u2) {
    initial = 0,
    handshake = 1,
    application = 2,
};

/// The number of packet-reordering threshold for declaring loss (RFC 9002).
const PACKET_THRESHOLD: u64 = 3;

/// Maximum number of ACK-eliciting packets before forcing an ACK.
const ACK_ELICITING_THRESHOLD: u32 = 2;

/// Default max ACK delay (25ms in nanoseconds).
const DEFAULT_MAX_ACK_DELAY: i64 = 25_000_000;

/// Maximum PTO (60 seconds in nanoseconds).
const MAX_PTO: i64 = 60_000_000_000;

/// Maximum number of packets tracked per ACK result.
const MAX_ACK_RESULT: usize = 256;

/// Metadata stored for each sent packet.
pub const SentPacket = struct {
    pn: u64,
    time_sent: i64,
    size: u64,
    ack_eliciting: bool,
    in_flight: bool,
    enc_level: EncLevel,
    largest_acked: ?u64 = null,
};

/// Fixed-capacity list of SentPackets for ACK results.
pub const SentPacketList = struct {
    buf: [MAX_ACK_RESULT]SentPacket = undefined,
    len: usize = 0,

    pub fn append(self: *SentPacketList, item: SentPacket) void {
        if (self.len < MAX_ACK_RESULT) {
            self.buf[self.len] = item;
            self.len += 1;
        }
    }

    pub fn constSlice(self: *const SentPacketList) []const SentPacket {
        return self.buf[0..self.len];
    }
};

/// Fixed-capacity list of u64 for tracking packet numbers.
const PnList = struct {
    buf: [MAX_ACK_RESULT]u64 = undefined,
    len: usize = 0,

    pub fn append(self: *PnList, item: u64) void {
        if (self.len < MAX_ACK_RESULT) {
            self.buf[self.len] = item;
            self.len += 1;
        }
    }

    pub fn constSlice(self: *const PnList) []const u64 {
        return self.buf[0..self.len];
    }
};

/// Result of processing an ACK frame.
pub const AckResult = struct {
    acked: SentPacketList = .{},
    lost: SentPacketList = .{},
};

/// Tracks sent packets and handles loss detection for a single packet number space.
pub const SentPacketTracker = struct {
    allocator: Allocator,
    sent_packets: std.AutoHashMap(u64, SentPacket),
    largest_sent: ?u64 = null,
    largest_acked: ?u64 = null,
    loss_time: ?i64 = null,
    ack_eliciting_in_flight: u32 = 0,

    pub fn init(allocator: Allocator) SentPacketTracker {
        return .{
            .allocator = allocator,
            .sent_packets = std.AutoHashMap(u64, SentPacket).init(allocator),
        };
    }

    pub fn deinit(self: *SentPacketTracker) void {
        self.sent_packets.deinit();
    }

    pub fn onPacketSent(self: *SentPacketTracker, pkt: SentPacket) !void {
        if (self.largest_sent == null or pkt.pn > self.largest_sent.?) {
            self.largest_sent = pkt.pn;
        }
        if (pkt.ack_eliciting) {
            self.ack_eliciting_in_flight += 1;
        }
        try self.sent_packets.put(pkt.pn, pkt);
    }

    pub fn onAckReceived(
        self: *SentPacketTracker,
        largest_ack: u64,
        ack_delay_ns: i64,
        ack_ranges: []const AckRange,
        first_ack_range: u64,
        rtt_stats: *RttStats,
        now: i64,
    ) !AckResult {
        var result = AckResult{};

        if (self.largest_acked == null or largest_ack > self.largest_acked.?) {
            self.largest_acked = largest_ack;
        }

        // Process the first ACK range: [largest_ack - first_ack_range, largest_ack]
        {
            const range_start = largest_ack -| first_ack_range;
            var pn = range_start;
            while (pn <= largest_ack) : (pn += 1) {
                if (self.sent_packets.fetchRemove(pn)) |kv| {
                    const pkt = kv.value;
                    if (pkt.ack_eliciting) {
                        self.ack_eliciting_in_flight -|= 1;
                    }

                    if (pkt.pn == largest_ack) {
                        const send_delta = now - pkt.time_sent;
                        rtt_stats.updateRtt(send_delta, ack_delay_ns, true);
                    }

                    result.acked.append(pkt);
                }
                if (pn == largest_ack) break;
            }
        }

        _ = ack_ranges; // TODO: process additional ranges

        // Detect lost packets
        self.detectLostPackets(rtt_stats, now, &result);

        return result;
    }

    fn detectLostPackets(self: *SentPacketTracker, rtt_stats: *RttStats, now: i64, result: *AckResult) void {
        self.loss_time = null;
        const loss_delay = rtt_stats.lossDelay();
        const lost_send_time = now - loss_delay;

        var to_remove: PnList = .{};

        var it = self.sent_packets.iterator();
        while (it.next()) |entry| {
            const pkt = entry.value_ptr.*;
            if (self.largest_acked == null or pkt.pn > self.largest_acked.?) {
                continue;
            }

            if (pkt.time_sent <= lost_send_time) {
                result.lost.append(pkt);
                to_remove.append(pkt.pn);
                continue;
            }

            if (self.largest_acked.? >= PACKET_THRESHOLD and
                pkt.pn <= self.largest_acked.? - PACKET_THRESHOLD)
            {
                result.lost.append(pkt);
                to_remove.append(pkt.pn);
                continue;
            }

            const loss_time_for_pkt = pkt.time_sent + loss_delay;
            if (self.loss_time == null or loss_time_for_pkt < self.loss_time.?) {
                self.loss_time = loss_time_for_pkt;
            }
        }

        for (to_remove.constSlice()) |pn| {
            _ = self.sent_packets.remove(pn);
        }
    }
};

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

    pub fn init(allocator: Allocator) ReceivedPacketTracker {
        return .{
            .allocator = allocator,
            .received = RangeSet.init(allocator),
        };
    }

    pub fn deinit(self: *ReceivedPacketTracker) void {
        self.received.deinit();
    }

    pub fn onPacketReceived(self: *ReceivedPacketTracker, pn: u64, ack_eliciting: bool, now: i64) !void {
        if (self.received.contains(pn)) return;
        try self.received.add(pn);

        if (self.largest_received == null or pn > self.largest_received.?) {
            self.largest_received = pn;
            self.largest_received_time = now;
        }

        if (ack_eliciting) {
            self.ack_eliciting_since_last_ack += 1;

            if (self.largest_received != null and pn < self.largest_received.?) {
                self.ack_queued = true;
                self.ack_alarm = null;
            } else if (self.ack_eliciting_since_last_ack >= ACK_ELICITING_THRESHOLD) {
                self.ack_queued = true;
                self.ack_alarm = null;
            } else {
                if (self.ack_alarm == null) {
                    self.ack_alarm = now + DEFAULT_MAX_ACK_DELAY;
                }
            }
        }
    }

    pub fn isDuplicate(self: *const ReceivedPacketTracker, pn: u64) bool {
        return self.received.contains(pn);
    }

    pub fn getAckFrame(self: *ReceivedPacketTracker, now: i64, ack_delay_exponent: u64) ?Frame {
        if (!self.ack_queued) {
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

        return Frame{
            .ack = .{
                .largest_ack = largest,
                .ack_delay = ack_delay_encoded,
                .first_ack_range = first_ack_range,
                .ranges = &.{},
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
        const pn = self.next_pn[idx];
        self.next_pn[idx] += 1;
        return pn;
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

    pub fn onPacketReceived(self: *PacketHandler, level: EncLevel, pn: u64, ack_eliciting: bool, now: i64) !void {
        const idx = @intFromEnum(level);
        try self.recv[idx].onPacketReceived(pn, ack_eliciting, now);
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
    ) !AckResult {
        const idx = @intFromEnum(level);

        const ack_delay_us = ack_delay_encoded << ack_delay_exponent;
        const ack_delay_ns: i64 = @intCast(ack_delay_us * 1000);

        const result = try self.sent[idx].onAckReceived(
            largest_ack,
            ack_delay_ns,
            ack_ranges,
            first_ack_range,
            &self.rtt_stats,
            now,
        );

        for (result.acked.constSlice()) |pkt| {
            if (pkt.in_flight) {
                self.bytes_in_flight -|= pkt.size;
            }
        }
        for (result.lost.constSlice()) |pkt| {
            if (pkt.in_flight) {
                self.bytes_in_flight -|= pkt.size;
            }
        }

        self.pto_count = 0;

        return result;
    }

    pub fn getAckFrame(self: *PacketHandler, level: EncLevel, now: i64, ack_delay_exponent: u64) ?Frame {
        const idx = @intFromEnum(level);
        return self.recv[idx].getAckFrame(now, ack_delay_exponent);
    }

    pub fn getPtoTimeout(self: *PacketHandler) ?i64 {
        var earliest: ?i64 = null;

        for (self.sent, 0..) |tracker, idx| {
            if (tracker.loss_time) |lt| {
                if (earliest == null or lt < earliest.?) {
                    earliest = lt;
                }
                continue;
            }

            if (tracker.ack_eliciting_in_flight == 0) continue;

            const largest_sent = tracker.largest_sent orelse continue;
            const sent_pkt = tracker.sent_packets.get(largest_sent) orelse continue;

            var pto_duration = if (idx == @intFromEnum(EncLevel.application))
                self.rtt_stats.pto()
            else
                self.rtt_stats.ptoNoAckDelay();

            pto_duration = pto_duration << @intCast(self.pto_count);
            pto_duration = @min(pto_duration, MAX_PTO);

            const timeout = sent_pkt.time_sent + pto_duration;
            if (earliest == null or timeout < earliest.?) {
                earliest = timeout;
            }
        }

        return earliest;
    }

    pub fn dropSpace(self: *PacketHandler, level: EncLevel) void {
        const idx = @intFromEnum(level);

        var it = self.sent[idx].sent_packets.iterator();
        while (it.next()) |entry| {
            if (entry.value_ptr.in_flight) {
                self.bytes_in_flight -|= entry.value_ptr.size;
            }
        }

        self.sent[idx].deinit();
        self.recv[idx].deinit();
        self.sent[idx] = SentPacketTracker.init(self.allocator);
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
    const result = try tracker.onAckReceived(0, 0, &.{}, 0, &rtt_stats, ack_time);

    try testing.expectEqual(@as(usize, 1), result.acked.len);
    try testing.expectEqual(@as(u64, 0), result.acked.constSlice()[0].pn);
    try testing.expectEqual(@as(u32, 0), tracker.ack_eliciting_in_flight);
    try testing.expect(rtt_stats.has_measurement);
}

test "ReceivedPacketTracker: immediate ACK on reorder" {
    var tracker = ReceivedPacketTracker.init(testing.allocator);
    defer tracker.deinit();

    const now: i64 = 1_000_000_000;

    try tracker.onPacketReceived(0, true, now);
    try tracker.onPacketReceived(1, true, now + 1_000_000);

    try testing.expect(tracker.ack_queued);
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

    try handler.onPacketReceived(.initial, 0, true, now);

    const ack_time = now + 50_000_000;
    const result = try handler.onAckReceived(.initial, 0, 0, 3, &.{}, 0, ack_time);

    _ = result;
    try testing.expectEqual(@as(u64, 0), handler.bytes_in_flight);
}
