const std = @import("std");
const testing = std.testing;

/// Timer granularity (1 ms) as nanoseconds.
const TIMER_GRANULARITY: i64 = 1_000_000;

/// Default initial RTT (100 ms) as nanoseconds, per RFC 9002.
const DEFAULT_INITIAL_RTT: i64 = 100_000_000;

/// RTT statistics tracker following RFC 9002 Section 5.
///
/// Maintains smoothed RTT, RTT variance, minimum RTT, and latest RTT.
/// Used by loss detection and congestion control.
pub const RttStats = struct {
    /// The most recent RTT measurement (nanoseconds).
    latest_rtt: i64 = 0,

    /// Exponentially-weighted moving average of RTT (nanoseconds).
    smoothed_rtt: i64 = 0,

    /// Mean deviation of RTT samples (nanoseconds).
    rtt_var: i64 = 0,

    /// Minimum RTT observed over the connection lifetime (nanoseconds).
    min_rtt: i64 = 0,

    /// Maximum ACK delay indicated by the peer's transport parameters (nanoseconds).
    max_ack_delay: i64 = 25_000_000, // 25ms default

    /// Whether we have taken the first RTT sample.
    has_measurement: bool = false,

    /// Update RTT statistics with a new measurement.
    ///
    /// `send_delta` is the time between sending the packet and receiving the ACK (nanoseconds).
    /// `ack_delay` is the peer's reported ACK delay (nanoseconds).
    /// `handshake_confirmed` indicates if the handshake is confirmed (affects ack_delay usage).
    pub fn updateRtt(self: *RttStats, send_delta: i64, ack_delay: i64, handshake_confirmed: bool) void {
        if (send_delta <= 0) return;

        self.latest_rtt = send_delta;

        if (!self.has_measurement) {
            // First measurement
            self.min_rtt = send_delta;
            self.smoothed_rtt = send_delta;
            self.rtt_var = @divTrunc(send_delta, 2);
            self.has_measurement = true;
            return;
        }

        // Update minimum RTT
        if (send_delta < self.min_rtt) {
            self.min_rtt = send_delta;
        }

        // Adjust for ACK delay per RFC 9002 Section 5.3
        var adjusted_rtt = send_delta;
        if (handshake_confirmed) {
            const effective_ack_delay = @min(ack_delay, self.max_ack_delay);
            if (adjusted_rtt > self.min_rtt + effective_ack_delay) {
                adjusted_rtt -= effective_ack_delay;
            }
        }

        // RFC 9002 Section 5.3: Exponentially-weighted moving average
        // rttvar = 3/4 * rttvar + 1/4 * |smoothed_rtt - adjusted_rtt|
        const rtt_diff = @as(i64, @intCast(@abs(self.smoothed_rtt - adjusted_rtt)));
        self.rtt_var = @divTrunc(3 * self.rtt_var, 4) + @divTrunc(rtt_diff, 4);

        // smoothed_rtt = 7/8 * smoothed_rtt + 1/8 * adjusted_rtt
        self.smoothed_rtt = @divTrunc(7 * self.smoothed_rtt, 8) + @divTrunc(adjusted_rtt, 8);
    }

    /// Calculate the Probe Timeout (PTO) value per RFC 9002 Section 6.2.1.
    pub fn pto(self: *const RttStats) i64 {
        if (!self.has_measurement) {
            return 2 * DEFAULT_INITIAL_RTT;
        }
        return self.smoothed_rtt + @max(4 * self.rtt_var, TIMER_GRANULARITY) + self.max_ack_delay;
    }

    /// Calculate the PTO without ACK delay (for Initial/Handshake spaces).
    pub fn ptoNoAckDelay(self: *const RttStats) i64 {
        if (!self.has_measurement) {
            return 2 * DEFAULT_INITIAL_RTT;
        }
        return self.smoothed_rtt + @max(4 * self.rtt_var, TIMER_GRANULARITY);
    }

    /// Return the loss delay threshold (9/8 * max(smoothed_rtt, latest_rtt)).
    /// Minimum is timer granularity.
    pub fn lossDelay(self: *const RttStats) i64 {
        const rtt = @max(self.smoothed_rtt, self.latest_rtt);
        const delay = @divTrunc(rtt * 9, 8);
        return @max(delay, TIMER_GRANULARITY);
    }

    /// Get the smoothed RTT, or the default initial RTT if no measurement yet.
    pub fn smoothedRttOrDefault(self: *const RttStats) i64 {
        if (!self.has_measurement) return DEFAULT_INITIAL_RTT;
        return self.smoothed_rtt;
    }

    // Persistent congestion threshold (RFC 9002 §7.6.1).
    // Duration = 3 * (smoothed_rtt + max(4*rttvar, granularity) + max_ack_delay)
    // This equals 3 * PTO (without backoff).
    pub fn persistentCongestionThreshold(self: *const RttStats) i64 {
        if (!self.has_measurement) {
            return 3 * 2 * DEFAULT_INITIAL_RTT;
        }
        return 3 * (self.smoothed_rtt + @max(4 * self.rtt_var, TIMER_GRANULARITY) + self.max_ack_delay);
    }
};

// Tests

test "RttStats: initial state" {
    const rtt = RttStats{};
    try testing.expect(!rtt.has_measurement);
    try testing.expectEqual(@as(i64, 2 * DEFAULT_INITIAL_RTT), rtt.pto());
    try testing.expectEqual(DEFAULT_INITIAL_RTT, rtt.smoothedRttOrDefault());
}

test "RttStats: first measurement" {
    var rtt = RttStats{};
    rtt.updateRtt(100_000_000, 0, false); // 100ms

    try testing.expect(rtt.has_measurement);
    try testing.expectEqual(@as(i64, 100_000_000), rtt.smoothed_rtt);
    try testing.expectEqual(@as(i64, 100_000_000), rtt.min_rtt);
    try testing.expectEqual(@as(i64, 50_000_000), rtt.rtt_var); // initial_rtt / 2
}

test "RttStats: subsequent measurements converge" {
    var rtt = RttStats{};
    rtt.updateRtt(100_000_000, 0, false); // 100ms

    // Send several similar measurements
    rtt.updateRtt(110_000_000, 0, true); // 110ms
    rtt.updateRtt(95_000_000, 0, true); // 95ms
    rtt.updateRtt(105_000_000, 0, true); // 105ms

    // Smoothed RTT should be close to 100ms
    try testing.expect(rtt.smoothed_rtt > 90_000_000);
    try testing.expect(rtt.smoothed_rtt < 115_000_000);
    try testing.expectEqual(@as(i64, 95_000_000), rtt.min_rtt);
}

test "RttStats: ack_delay adjustment" {
    var rtt = RttStats{};
    rtt.updateRtt(100_000_000, 0, false); // 100ms baseline

    // With ack delay, adjusted RTT should be lower
    rtt.updateRtt(130_000_000, 20_000_000, true); // 130ms with 20ms ack delay
    // adjusted_rtt = 110ms, smoothed_rtt = 7/8*100 + 1/8*110 = 101.25ms
    try testing.expect(rtt.smoothed_rtt > 100_000_000);
    try testing.expect(rtt.smoothed_rtt < 105_000_000);
}

test "RttStats: loss delay" {
    var rtt = RttStats{};
    rtt.updateRtt(100_000_000, 0, false); // 100ms

    const delay = rtt.lossDelay();
    // 9/8 * 100ms = 112.5ms
    try testing.expectEqual(@as(i64, 112_500_000), delay);
}

test "RttStats: persistent congestion threshold" {
    var rtt = RttStats{};
    rtt.updateRtt(100_000_000, 0, false); // 100ms, rtt_var = 50ms

    // 3 * (100ms + max(4*50ms, 1ms) + 25ms) = 3 * 325ms = 975ms
    const threshold = rtt.persistentCongestionThreshold();
    try testing.expectEqual(@as(i64, 975_000_000), threshold);
}
