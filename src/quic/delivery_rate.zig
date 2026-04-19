//! Delivery-rate sampler (RFC 9002 §B / draft-cheng-iccrg-delivery-rate-estimation).
//!
//! Per-ACK estimate of the connection's delivery rate. Each transmitted packet
//! captures a snapshot of the cumulative `delivered` counter and the timestamp
//! of the most recent delivery. When the packet is acked, the snapshot is
//! compared against the current cumulative state to produce a `RateSample`
//! that BBR (and other model-based controllers) consume.
//!
//! The sampler also tracks "application-limited" intervals: if the sender is
//! ever throttled by application data shortage, packets sent during that
//! interval are flagged so BBR ignores their (artificially low) delivery rate.

const std = @import("std");
const ack_handler = @import("ack_handler.zig");
const SentPacket = ack_handler.SentPacket;

/// One sample produced when an acked packet is consumed by the sampler.
pub const RateSample = struct {
    /// Estimated delivery rate in bytes/second (0 if unmeasurable).
    delivery_rate_bps: u64,
    /// Bytes delivered in the sample interval.
    delivered: u64,
    /// Bytes delivered prior to this sample's send-snapshot.
    prior_delivered: u64,
    /// Wall-clock interval used to compute `delivery_rate_bps` (nanoseconds).
    interval_ns: i64,
    /// Time spent sending the sample (delivered_time - first_sent_time).
    send_elapsed_ns: i64,
    /// Time spent acking the sample (now - delivered_time_at_send).
    ack_elapsed_ns: i64,
    /// True if any packet contributing to the sample was sent app-limited.
    is_app_limited: bool,
    /// Round-trip time observed for the acked packet (nanoseconds).
    rtt_ns: i64,
};

pub const RateSampler = struct {
    /// Cumulative bytes delivered (acked) across the connection's lifetime.
    delivered: u64 = 0,
    /// Timestamp of the most recent delivery (nanoseconds).
    delivered_time: i64 = 0,
    /// Send-time of the most recent packet contributing to a delivery (nanoseconds).
    first_sent_time: i64 = 0,
    /// `delivered` counter snapshot at the start of the current app-limited
    /// interval. Packets sent before this counter is matched (delivered <
    /// app_limited_until) are flagged. 0 = not currently app-limited.
    app_limited_until: u64 = 0,

    /// Stamp delivery-rate snapshot fields into a packet at send time.
    /// `bytes_in_flight` is the pre-send count — when zero, this packet
    /// starts a new send burst, and the sampler resets `first_sent_time`/
    /// `delivered_time` to `now` so the next sample's interval starts here.
    pub fn onPacketSent(
        self: *RateSampler,
        pkt: *SentPacket,
        bytes_in_flight: u64,
        now: i64,
    ) void {
        if (bytes_in_flight == 0) {
            self.first_sent_time = now;
            self.delivered_time = now;
        }
        pkt.first_sent_time_at_send = self.first_sent_time;
        pkt.delivered_time_at_send = self.delivered_time;
        pkt.delivered_at_send = self.delivered;
        pkt.is_app_limited_at_send = self.app_limited_until != 0;
    }

    /// Update sampler state for an acked packet and return a RateSample
    /// describing the interval since this packet was sent.
    pub fn onPacketAcked(
        self: *RateSampler,
        pkt: *const SentPacket,
        rtt_ns: i64,
        now: i64,
    ) RateSample {
        // Advance cumulative delivered counter.
        self.delivered += pkt.size;
        self.delivered_time = now;

        // Advance first_sent_time to this packet's send time so that subsequent
        // samples measure the most recent send-burst.
        if (pkt.time_sent > self.first_sent_time) {
            self.first_sent_time = pkt.time_sent;
        }

        // If this ACK satisfied the app-limited condition, clear the flag.
        if (self.app_limited_until != 0 and self.delivered > self.app_limited_until) {
            self.app_limited_until = 0;
        }

        const send_elapsed = pkt.time_sent - pkt.first_sent_time_at_send;
        const ack_elapsed = self.delivered_time - pkt.delivered_time_at_send;
        // Use the larger of the two intervals — RFC 9002 §B guidance to avoid
        // overestimating when ACK compression shortens ack_elapsed.
        const interval = @max(send_elapsed, ack_elapsed);

        const delivered_in_sample = self.delivered - pkt.delivered_at_send;

        var bps: u64 = 0;
        if (interval > 0 and delivered_in_sample > 0) {
            // bytes/sec = delivered_in_sample * 1e9 / interval_ns
            bps = @intCast(@divTrunc(
                @as(u128, delivered_in_sample) * std.time.ns_per_s,
                @as(u128, @intCast(interval)),
            ));
        }

        return .{
            .delivery_rate_bps = bps,
            .delivered = delivered_in_sample,
            .prior_delivered = pkt.delivered_at_send,
            .interval_ns = interval,
            .send_elapsed_ns = send_elapsed,
            .ack_elapsed_ns = ack_elapsed,
            .is_app_limited = pkt.is_app_limited_at_send,
            .rtt_ns = rtt_ns,
        };
    }

    /// Mark the sender as application-limited. Subsequent packets sent until
    /// `delivered` advances past `last_sent_pn_delivered` are flagged.
    pub fn onAppLimited(self: *RateSampler, last_sent_pn_delivered: u64) void {
        self.app_limited_until = if (last_sent_pn_delivered == 0) 1 else last_sent_pn_delivered;
    }
};

// ── Tests ──

const testing = std.testing;

fn makePkt(pn: u64, size: u64, time_sent: i64) SentPacket {
    return .{
        .pn = pn,
        .time_sent = time_sent,
        .size = size,
        .ack_eliciting = true,
        .in_flight = true,
        .enc_level = .application,
    };
}

test "RateSampler: produces correct rate for steady stream" {
    var s = RateSampler{};
    var p1 = makePkt(1, 1000, 0);
    var p2 = makePkt(2, 1000, 10_000_000); // +10ms
    var p3 = makePkt(3, 1000, 20_000_000);

    // Send three packets back-to-back (bytes_in_flight grows).
    s.onPacketSent(&p1, 0, 0);
    s.onPacketSent(&p2, 1000, 10_000_000);
    s.onPacketSent(&p3, 2000, 20_000_000);

    // Ack them at +50ms, +60ms, +70ms (50ms RTT)
    _ = s.onPacketAcked(&p1, 50_000_000, 50_000_000);
    _ = s.onPacketAcked(&p2, 50_000_000, 60_000_000);
    const sample = s.onPacketAcked(&p3, 50_000_000, 70_000_000);

    // 3000 bytes delivered total, send interval 20ms, ack interval 70ms.
    // Sample for p3: delivered_in_sample = 3000, interval = max(send=20ms, ack=70ms) = 70ms.
    try testing.expectEqual(@as(u64, 3000), sample.delivered);
    try testing.expectEqual(@as(i64, 70_000_000), sample.interval_ns);
    // Rate ≈ 3000 / 0.07s ≈ 42857 B/s
    try testing.expect(sample.delivery_rate_bps > 40_000);
    try testing.expect(sample.delivery_rate_bps < 45_000);
}

test "RateSampler: app-limited flag propagates" {
    var s = RateSampler{};
    s.onAppLimited(500); // currently app-limited until delivered > 500

    var p = makePkt(1, 200, 0);
    s.onPacketSent(&p, 0, 0);
    try testing.expect(p.is_app_limited_at_send);

    const sample = s.onPacketAcked(&p, 50_000_000, 50_000_000);
    try testing.expect(sample.is_app_limited);
    // delivered is now 200, still under 500 → still app-limited
    try testing.expect(s.app_limited_until != 0);

    var p2 = makePkt(2, 600, 60_000_000);
    s.onPacketSent(&p2, 0, 60_000_000);
    _ = s.onPacketAcked(&p2, 50_000_000, 110_000_000);
    // delivered is now 800 > 500 → flag cleared
    try testing.expectEqual(@as(u64, 0), s.app_limited_until);
}

test "RateSampler: reorder still produces monotonic delivered" {
    var s = RateSampler{};
    var p1 = makePkt(1, 1000, 0);
    var p2 = makePkt(2, 1000, 10_000_000);

    s.onPacketSent(&p1, 0, 0);
    s.onPacketSent(&p2, 1000, 10_000_000);

    // Ack p2 first, then p1 (reordered)
    _ = s.onPacketAcked(&p2, 50_000_000, 60_000_000);
    try testing.expectEqual(@as(u64, 1000), s.delivered);

    _ = s.onPacketAcked(&p1, 60_000_000, 70_000_000);
    try testing.expectEqual(@as(u64, 2000), s.delivered);
}

test "RateSampler: zero interval yields zero rate" {
    var s = RateSampler{};
    var p = makePkt(1, 1000, 100);
    s.onPacketSent(&p, 0, 100);
    const sample = s.onPacketAcked(&p, 0, 100); // same instant
    try testing.expectEqual(@as(u64, 0), sample.delivery_rate_bps);
}
