const std = @import("std");
const testing = std.testing;

const rtt_mod = @import("rtt.zig");
const RttStats = rtt_mod.RttStats;

/// Default initial congestion window in bytes (10 * max_datagram_size per RFC 9002).
const INITIAL_WINDOW_PACKETS: u64 = 10;

/// Minimum congestion window in bytes (2 * max_datagram_size per RFC 9002).
const MIN_WINDOW_PACKETS: u64 = 2;

/// Default max datagram size.
const DEFAULT_MAX_DATAGRAM_SIZE: u64 = 1200;

/// Beta for NewReno multiplicative decrease (per RFC 9002 recommendation).
const NEWRENO_BETA: u64 = 7; // Numerator (divide by 10 for 0.7)
const NEWRENO_BETA_DENOM: u64 = 10;

/// Maximum burst size for pacer (in packets).
const MAX_BURST_PACKETS: u64 = 10;

/// Bandwidth multiplier for pacer (1.25x) expressed as fraction.
const PACER_BANDWIDTH_NUM: u64 = 5;
const PACER_BANDWIDTH_DENOM: u64 = 4;

/// Congestion controller using NewReno algorithm (RFC 9002 Appendix B).
///
/// NewReno is simpler than CUBIC and a good starting point. It uses:
/// - Slow start: exponential growth until ssthresh
/// - Congestion avoidance: linear growth (1 MSS per RTT)
/// - On loss: multiplicative decrease (window * beta)
pub const NewReno = struct {
    /// Current congestion window in bytes.
    congestion_window: u64,

    /// Slow start threshold.
    ssthresh: u64 = std.math.maxInt(u64),

    /// Maximum datagram size (affects window calculations).
    max_datagram_size: u64 = DEFAULT_MAX_DATAGRAM_SIZE,

    /// Largest packet number sent at the time of the last congestion event.
    /// Used to detect recovery period.
    largest_sent_at_last_cutback: ?u64 = null,

    /// Bytes acknowledged in the current round trip (for congestion avoidance).
    bytes_acked_in_round: u64 = 0,

    /// Whether we are in slow start.
    pub fn inSlowStart(self: *const NewReno) bool {
        return self.congestion_window < self.ssthresh;
    }

    /// Initialize with default values.
    pub fn init() NewReno {
        return .{
            .congestion_window = INITIAL_WINDOW_PACKETS * DEFAULT_MAX_DATAGRAM_SIZE,
        };
    }

    /// Initialize with a specific max datagram size.
    pub fn initWithMds(max_datagram_size: u64) NewReno {
        return .{
            .congestion_window = INITIAL_WINDOW_PACKETS * max_datagram_size,
            .max_datagram_size = max_datagram_size,
        };
    }

    /// Called when a packet is acknowledged.
    pub fn onPacketAcked(self: *NewReno, acked_bytes: u64, pn: u64) void {
        // Don't grow window during recovery
        if (self.largest_sent_at_last_cutback) |cutback_pn| {
            if (pn <= cutback_pn) return;
        }

        if (self.inSlowStart()) {
            // Slow start: increase by acked_bytes
            self.congestion_window += acked_bytes;
        } else {
            // Congestion avoidance: increase by MSS per RTT
            // Accumulate bytes and increase by MSS when a full window is acked
            self.bytes_acked_in_round += acked_bytes;
            if (self.bytes_acked_in_round >= self.congestion_window) {
                self.congestion_window += self.max_datagram_size;
                self.bytes_acked_in_round -= self.congestion_window;
            }
        }
    }

    /// Called on congestion event (packet loss detected).
    pub fn onCongestionEvent(self: *NewReno, largest_sent_pn: u64) void {
        // Avoid multiple cutbacks in the same recovery period
        if (self.largest_sent_at_last_cutback) |cutback_pn| {
            if (largest_sent_pn <= cutback_pn) return;
        }

        self.largest_sent_at_last_cutback = largest_sent_pn;

        // Multiplicative decrease
        self.ssthresh = self.congestion_window * NEWRENO_BETA / NEWRENO_BETA_DENOM;
        self.congestion_window = @max(
            self.ssthresh,
            MIN_WINDOW_PACKETS * self.max_datagram_size,
        );
        self.bytes_acked_in_round = 0;
    }

    /// Called when the PTO fires (probe timeout).
    pub fn onPtoExpired(self: *NewReno) void {
        _ = self;
        // NewReno doesn't adjust window on PTO, only on loss
    }

    /// Get the current send window (bytes that can be in flight).
    pub fn sendWindow(self: *const NewReno) u64 {
        return self.congestion_window;
    }

    /// Update the max datagram size (e.g., after PMTUD).
    pub fn setMaxDatagramSize(self: *NewReno, size: u64) void {
        self.max_datagram_size = size;
    }
};

/// Pacer for spacing out packet sends to avoid bursts.
///
/// Uses a token bucket algorithm similar to quic-go's pacer.
pub const Pacer = struct {
    /// Available budget in bytes.
    budget: u64,

    /// Max burst size in bytes.
    max_burst: u64,

    /// Last time a packet was sent (nanoseconds).
    last_sent_time: i64 = 0,

    /// Adjusted bandwidth in bytes per second.
    bandwidth: u64 = 0,

    /// Max datagram size.
    max_datagram_size: u64 = DEFAULT_MAX_DATAGRAM_SIZE,

    pub fn init() Pacer {
        const max_burst = MAX_BURST_PACKETS * DEFAULT_MAX_DATAGRAM_SIZE;
        return .{
            .budget = max_burst,
            .max_burst = max_burst,
        };
    }

    /// Update the pacer's bandwidth based on the congestion window and RTT.
    pub fn setBandwidth(self: *Pacer, cwnd: u64, rtt_stats: *const RttStats) void {
        const srtt = rtt_stats.smoothedRttOrDefault();
        if (srtt <= 0) return;

        // bandwidth = cwnd / srtt (bytes per nanosecond)
        // Multiply by 1.25 to prevent underutilization
        // Store as bytes per second for easier computation
        self.bandwidth = @intCast(@divTrunc(
            @as(i128, @intCast(cwnd)) * 1_000_000_000 * PACER_BANDWIDTH_NUM,
            @as(i128, @intCast(srtt)) * PACER_BANDWIDTH_DENOM,
        ));
    }

    /// Called when a packet is sent. Deducts from the budget.
    pub fn onPacketSent(self: *Pacer, size: u64, now: i64) void {
        self.replenish(now);
        self.budget -|= size;
        self.last_sent_time = now;
    }

    /// Returns the time when the next packet can be sent, or 0 if it can be sent now.
    pub fn timeUntilSend(self: *Pacer, now: i64) i64 {
        self.replenish(now);
        if (self.budget >= self.max_datagram_size) {
            return 0; // Can send now
        }

        if (self.bandwidth == 0) return 0;

        // Time to accumulate enough budget for one packet
        const deficit = self.max_datagram_size - self.budget;
        const delay_ns: i64 = @intCast(@divTrunc(
            @as(u128, deficit) * 1_000_000_000,
            @as(u128, self.bandwidth),
        ));
        return delay_ns;
    }

    /// Replenish budget based on elapsed time.
    fn replenish(self: *Pacer, now: i64) void {
        if (self.last_sent_time == 0 or self.bandwidth == 0) {
            self.budget = self.max_burst;
            return;
        }

        const elapsed = now - self.last_sent_time;
        if (elapsed <= 0) return;

        const new_budget: u64 = @intCast(@divTrunc(
            @as(u128, self.bandwidth) * @as(u128, @intCast(elapsed)),
            1_000_000_000,
        ));
        self.budget = @min(self.budget + new_budget, self.max_burst);
    }
};

// Tests

test "NewReno: initial state" {
    const cc = NewReno.init();
    try testing.expect(cc.inSlowStart());
    try testing.expectEqual(
        INITIAL_WINDOW_PACKETS * DEFAULT_MAX_DATAGRAM_SIZE,
        cc.congestion_window,
    );
}

test "NewReno: slow start growth" {
    var cc = NewReno.init();
    const initial_window = cc.congestion_window;

    // ACK 1200 bytes
    cc.onPacketAcked(1200, 0);
    try testing.expectEqual(initial_window + 1200, cc.congestion_window);
    try testing.expect(cc.inSlowStart());
}

test "NewReno: congestion event reduces window" {
    var cc = NewReno.init();
    const initial_window = cc.congestion_window;

    cc.onCongestionEvent(10);

    // Window should be reduced by beta (0.7)
    const expected = initial_window * NEWRENO_BETA / NEWRENO_BETA_DENOM;
    try testing.expectEqual(expected, cc.congestion_window);
    try testing.expect(!cc.inSlowStart()); // ssthresh = reduced window
}

test "NewReno: recovery period prevents double cutback" {
    var cc = NewReno.init();

    cc.onCongestionEvent(10);
    const after_first = cc.congestion_window;

    // Second loss in recovery should not reduce further
    cc.onCongestionEvent(5);
    try testing.expectEqual(after_first, cc.congestion_window);

    // Loss after recovery should reduce
    cc.onCongestionEvent(15);
    try testing.expect(cc.congestion_window < after_first);
}

test "NewReno: minimum window enforced" {
    var cc = NewReno.init();

    // Force tiny window
    cc.congestion_window = 3000;
    cc.largest_sent_at_last_cutback = null;
    cc.onCongestionEvent(100);

    try testing.expect(cc.congestion_window >= MIN_WINDOW_PACKETS * DEFAULT_MAX_DATAGRAM_SIZE);
}

test "Pacer: initial burst allowed" {
    var pacer = Pacer.init();
    try testing.expectEqual(@as(i64, 0), pacer.timeUntilSend(1_000_000_000));
}

test "Pacer: rate limiting after burst" {
    var pacer = Pacer.init();
    var rtt = RttStats{};
    rtt.updateRtt(50_000_000, 0, false); // 50ms RTT

    pacer.setBandwidth(12000, &rtt); // 12KB window

    const now: i64 = 1_000_000_000;

    // Exhaust budget
    var i: u32 = 0;
    while (i < MAX_BURST_PACKETS + 1) : (i += 1) {
        pacer.onPacketSent(1200, now);
    }

    // Should now be rate-limited
    const delay = pacer.timeUntilSend(now);
    try testing.expect(delay > 0);
}
