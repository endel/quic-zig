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

    /// Time at which the current recovery period started (RFC 9002 §B.7).
    /// Losses of packets sent before this time don't trigger new recovery.
    congestion_recovery_start_time: ?i64 = null,

    /// Bytes acknowledged in the current round trip (for congestion avoidance).
    bytes_acked_in_round: u64 = 0,

    /// RFC 9002 §7.8: Application-limited — suppress cwnd growth when the
    /// sender is not fully utilizing the congestion window.
    app_limited: bool = false,

    /// Whether we are in slow start.
    pub fn inSlowStart(self: *const NewReno) bool {
        return self.congestion_window < self.ssthresh;
    }

    /// Check if a packet sent at `sent_time` is from the current recovery period.
    pub fn inCongestionRecovery(self: *const NewReno, sent_time: i64) bool {
        if (self.congestion_recovery_start_time) |start| {
            return sent_time <= start;
        }
        return false;
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
    pub fn onPacketAcked(self: *NewReno, acked_bytes: u64, sent_time: i64) void {
        // Don't grow window during recovery
        if (self.inCongestionRecovery(sent_time)) return;

        // RFC 9002 §7.8: Don't increase cwnd when application-limited
        if (self.app_limited) return;

        if (self.inSlowStart()) {
            // Slow start: increase by acked_bytes
            self.congestion_window += acked_bytes;
        } else {
            // Congestion avoidance: increase by MSS per RTT
            // Accumulate bytes and increase by MSS when a full window is acked
            self.bytes_acked_in_round += acked_bytes;
            if (self.bytes_acked_in_round >= self.congestion_window) {
                self.bytes_acked_in_round -= self.congestion_window;
                self.congestion_window += self.max_datagram_size;
            }
        }
    }

    /// Called on congestion event (packet loss detected).
    /// `sent_time` is the sent time of the lost packet.
    /// `now` is the current time (becomes the new recovery start time).
    pub fn onCongestionEvent(self: *NewReno, sent_time: i64, now: i64) void {
        // Don't trigger new recovery for packets sent during current recovery (RFC 9002 §B.7)
        if (self.inCongestionRecovery(sent_time)) return;

        self.congestion_recovery_start_time = now;

        // Multiplicative decrease
        self.ssthresh = self.congestion_window * NEWRENO_BETA / NEWRENO_BETA_DENOM;
        self.congestion_window = @max(
            self.ssthresh,
            MIN_WINDOW_PACKETS * self.max_datagram_size,
        );
        self.bytes_acked_in_round = 0;
    }

    // Persistent congestion detected (RFC 9002 §7.6.2).
    // Reset to minimum window with slow start (exponential) recovery,
    // similar to TCP RTO behavior (RFC 5681): cwnd = minimum, ssthresh = infinity
    // so that slow start can quickly probe available capacity.
    // Sets congestion_recovery_start_time = now so that subsequent loss events
    // for old packets (sent before this point) are suppressed via inCongestionRecovery.
    pub fn onPersistentCongestion(self: *NewReno, now: i64) void {
        self.congestion_window = MIN_WINDOW_PACKETS * self.max_datagram_size;
        self.ssthresh = std.math.maxInt(u64);
        self.congestion_recovery_start_time = now;
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

/// CUBIC congestion control (RFC 8312).
///
/// CUBIC uses a cubic function for window growth, providing better
/// bandwidth utilization on high-BDP networks compared to NewReno.
/// Key properties:
/// - Window growth is a cubic function of time since last congestion event
/// - Provides a TCP-friendly region for fairness with Reno flows
/// - Beta = 0.7 (multiplicative decrease factor)
/// - C = 0.4 (cubic scaling constant)
pub const Cubic = struct {
    /// Current congestion window in bytes.
    congestion_window: u64,

    /// Slow start threshold.
    ssthresh: u64 = std.math.maxInt(u64),

    /// Maximum datagram size (affects window calculations).
    max_datagram_size: u64 = DEFAULT_MAX_DATAGRAM_SIZE,

    /// Time at which the current recovery period started (RFC 9002 §B.7).
    congestion_recovery_start_time: ?i64 = null,

    /// Bytes acknowledged in the current round trip (for slow start / TCP-friendly).
    bytes_acked_in_round: u64 = 0,

    /// RFC 9002 §7.8: Application-limited — suppress cwnd growth when the
    /// sender is not fully utilizing the congestion window.
    app_limited: bool = false,

    // ── CUBIC-specific state ──

    /// W_max: congestion window at the time of the last congestion event (in bytes).
    w_max: u64 = 0,

    /// Epoch start time: when the current CUBIC epoch began (nanoseconds).
    /// Reset on each congestion event.
    epoch_start: ?i64 = null,

    /// K: the time period for the cubic function to reach W_max (in nanoseconds).
    /// K = cbrt(W_max * (1 - beta) / C) but we store it pre-computed.
    k_ns: i64 = 0,

    /// W_est: estimated TCP-friendly window (for TCP-friendly region).
    w_est: u64 = 0,

    // ── Constants ──
    // Beta = 0.7 (RFC 8312 §4.5 recommends 0.7 for QUIC)
    const BETA_NUM: u64 = 7;
    const BETA_DENOM: u64 = 10;

    // C = 0.4 (RFC 8312 §5)
    // We scale by 1000 to avoid floating point: C_SCALED = 400
    const C_SCALED: u64 = 400;
    const C_DENOM: u64 = 1000;

    pub fn inSlowStart(self: *const Cubic) bool {
        return self.congestion_window < self.ssthresh;
    }

    pub fn inCongestionRecovery(self: *const Cubic, sent_time: i64) bool {
        if (self.congestion_recovery_start_time) |start| {
            return sent_time <= start;
        }
        return false;
    }

    pub fn init() Cubic {
        return .{
            .congestion_window = INITIAL_WINDOW_PACKETS * DEFAULT_MAX_DATAGRAM_SIZE,
        };
    }

    pub fn initWithMds(max_datagram_size: u64) Cubic {
        return .{
            .congestion_window = INITIAL_WINDOW_PACKETS * max_datagram_size,
            .max_datagram_size = max_datagram_size,
        };
    }

    /// Called when a packet is acknowledged.
    pub fn onPacketAcked(self: *Cubic, acked_bytes: u64, sent_time: i64) void {
        // Don't grow window during recovery
        if (self.inCongestionRecovery(sent_time)) return;

        // RFC 9002 §7.8: Don't increase cwnd when application-limited
        if (self.app_limited) return;

        if (self.inSlowStart()) {
            // Slow start: increase by acked_bytes (same as NewReno)
            self.congestion_window += acked_bytes;
            return;
        }

        // Congestion avoidance: use CUBIC function
        self.cubicUpdate(acked_bytes);
    }

    /// CUBIC window update during congestion avoidance.
    fn cubicUpdate(self: *Cubic, acked_bytes: u64) void {
        // Initialize epoch on first ACK after congestion event
        if (self.epoch_start == null) {
            self.epoch_start = @intCast(std.time.nanoTimestamp());
            if (self.congestion_window < self.w_max) {
                // Compute K = cbrt(W_max * (1-beta) / C) in MSS units, then convert to nanoseconds
                // K_mss = cbrt((W_max/MSS) * 0.3 / 0.4) = cbrt((W_max/MSS) * 3/4)
                const w_max_mss = self.w_max / self.max_datagram_size;
                const numerator = w_max_mss * 3; // (1 - beta) = 0.3, scaled by 10 = 3
                const denominator: u64 = 4; // C = 0.4, scaled by 10 = 4
                const k_mss_cubed = numerator / denominator;
                // cbrt using integer approximation
                self.k_ns = @intCast(icbrt(k_mss_cubed) * 1_000_000_000); // seconds → ns
            } else {
                self.k_ns = 0;
            }
            // Initialize TCP-friendly estimate
            self.w_est = self.congestion_window;
        }

        const now: i64 = @intCast(std.time.nanoTimestamp());
        const t_ns = now - (self.epoch_start orelse now); // time since epoch start in ns

        // W_cubic(t) = C * (t - K)^3 + W_max
        // All in bytes. t and K are in nanoseconds, so we need to convert to seconds.
        // t_sec = t_ns / 1e9, K_sec = K_ns / 1e9
        // W_cubic = C * ((t_ns - K_ns) / 1e9)^3 + W_max
        //         = C * (t_ns - K_ns)^3 / 1e27 + W_max
        // To avoid overflow, compute in MSS units:
        // W_cubic_mss = C * ((t_sec - K_sec))^3 + W_max_mss

        const t_minus_k_ns = t_ns - self.k_ns;
        const t_minus_k_sec_10 = @divTrunc(t_minus_k_ns, 100_000_000); // in 0.1 second units

        // (t-K)^3 in units of 0.001 seconds^3
        const t_cubed = t_minus_k_sec_10 * t_minus_k_sec_10 * t_minus_k_sec_10;

        // W_cubic = C * (t-K)^3 + W_max
        // With our scaling: C=0.4, t in 0.1s units, so (t/10)^3 = t^3/1000
        // W_cubic_bytes = 0.4 * t_cubed / 1000 * MSS + W_max
        // = t_cubed * MSS * 4 / 10000 + W_max
        const w_cubic_bytes: u64 = if (t_cubed >= 0)
            @as(u64, @intCast(t_cubed)) * self.max_datagram_size * 4 / 10000 + self.w_max
        else
            self.w_max -| @as(u64, @intCast(-t_cubed)) * self.max_datagram_size * 4 / 10000;

        // TCP-friendly estimate: W_est grows linearly (1 MSS per RTT) after recovery
        // W_est += 3 * beta / (2 - beta) * (acked_bytes / cwnd) per ACK
        // Simplified: ~= acked_bytes * 3 * 7 / (10 * (2*10 - 7)) * MSS / cwnd
        // ≈ acked_bytes * 21 / 130 * MSS / cwnd
        // Even simpler: grow by MSS per cwnd acked (like NewReno)
        self.bytes_acked_in_round += acked_bytes;
        if (self.bytes_acked_in_round >= self.congestion_window) {
            self.bytes_acked_in_round -= self.congestion_window;
            self.w_est += self.max_datagram_size;
        }

        // Use the larger of CUBIC and TCP-friendly targets
        const target = @max(w_cubic_bytes, self.w_est);

        // Increase cwnd toward target
        if (target > self.congestion_window) {
            // Increase proportionally to acked_bytes
            const increase = (target - self.congestion_window) * acked_bytes / self.congestion_window;
            self.congestion_window += @max(increase, 1);
        }
    }

    /// Called on congestion event (packet loss detected).
    pub fn onCongestionEvent(self: *Cubic, sent_time: i64, now: i64) void {
        if (self.inCongestionRecovery(sent_time)) return;

        self.congestion_recovery_start_time = now;
        self.epoch_start = null; // Reset CUBIC epoch

        // Fast convergence (RFC 8312 §4.6):
        // If W_max decreased, the available bandwidth is shrinking
        if (self.congestion_window < self.w_max) {
            // Reduce W_max further to probe lower
            self.w_max = self.congestion_window * (BETA_NUM + BETA_DENOM) / (2 * BETA_DENOM);
        } else {
            self.w_max = self.congestion_window;
        }

        // Multiplicative decrease: cwnd = cwnd * beta
        self.ssthresh = self.congestion_window * BETA_NUM / BETA_DENOM;
        self.congestion_window = @max(
            self.ssthresh,
            MIN_WINDOW_PACKETS * self.max_datagram_size,
        );
        self.bytes_acked_in_round = 0;
    }

    /// Persistent congestion: reset to minimum window (RFC 9002 §7.6.2).
    pub fn onPersistentCongestion(self: *Cubic, now: i64) void {
        self.congestion_window = MIN_WINDOW_PACKETS * self.max_datagram_size;
        self.ssthresh = std.math.maxInt(u64);
        self.congestion_recovery_start_time = now;
        self.epoch_start = null;
        self.w_max = 0;
        self.bytes_acked_in_round = 0;
    }

    /// PTO does not reduce window (RFC 9002 §7.5).
    pub fn onPtoExpired(self: *Cubic) void {
        _ = self;
    }

    /// Enter recovery mode for NAT rebinding migration.
    /// Pre-migration packets sent to the old address will appear as losses,
    /// but they are path losses not congestion losses. Setting the recovery
    /// start time to now prevents onCongestionEvent from reducing CWND for
    /// those packets (since inCongestionRecovery(sent_time) will be true).
    pub fn enterRecoveryForMigration(self: *Cubic, now: i64) void {
        self.congestion_recovery_start_time = now;
    }

    pub fn sendWindow(self: *const Cubic) u64 {
        return self.congestion_window;
    }

    pub fn setMaxDatagramSize(self: *Cubic, size: u64) void {
        self.max_datagram_size = size;
    }
};

/// Integer cube root approximation (Newton's method).
fn icbrt(x: u64) u64 {
    if (x == 0) return 0;
    if (x <= 7) return 1;

    // Initial guess using bit shifting
    var guess: u64 = 1;
    var shift: u6 = 0;
    var temp = x;
    while (temp > 0) : (shift += 1) {
        temp >>= 1;
    }
    guess = @as(u64, 1) << (shift / 3 + 1);

    // Newton iterations: guess = (2*guess + x/(guess*guess)) / 3
    var i: u32 = 0;
    while (i < 10) : (i += 1) {
        const g2 = guess * guess;
        if (g2 == 0) break;
        const new_guess = (2 * guess + x / g2) / 3;
        if (new_guess >= guess) break;
        guess = new_guess;
    }

    // Verify and adjust
    while (guess * guess * guess > x) {
        guess -= 1;
    }

    return guess;
}

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

    // ACK 1200 bytes (sent at time 100)
    cc.onPacketAcked(1200, 100);
    try testing.expectEqual(initial_window + 1200, cc.congestion_window);
    try testing.expect(cc.inSlowStart());
}

test "NewReno: congestion event reduces window" {
    var cc = NewReno.init();
    const initial_window = cc.congestion_window;

    // Lost packet sent at time 100, detected at time 200
    cc.onCongestionEvent(100, 200);

    // Window should be reduced by beta (0.7)
    const expected = initial_window * NEWRENO_BETA / NEWRENO_BETA_DENOM;
    try testing.expectEqual(expected, cc.congestion_window);
    try testing.expect(!cc.inSlowStart()); // ssthresh = reduced window
}

test "NewReno: recovery period prevents double cutback" {
    var cc = NewReno.init();

    // First loss: packet sent at time 100, detected at time 200
    cc.onCongestionEvent(100, 200);
    const after_first = cc.congestion_window;

    // Second loss of a packet also sent before recovery (time 150 < 200) — should NOT cut
    cc.onCongestionEvent(150, 250);
    try testing.expectEqual(after_first, cc.congestion_window);

    // Loss of packet sent AFTER recovery started (time 300 > 200) — should cut
    cc.onCongestionEvent(300, 400);
    try testing.expect(cc.congestion_window < after_first);
}

test "NewReno: minimum window enforced" {
    var cc = NewReno.init();

    // Force tiny window
    cc.congestion_window = 3000;
    cc.congestion_recovery_start_time = null;
    cc.onCongestionEvent(100, 200);

    try testing.expect(cc.congestion_window >= MIN_WINDOW_PACKETS * DEFAULT_MAX_DATAGRAM_SIZE);
}

test "NewReno: persistent congestion resets to minimum" {
    var cc = NewReno.init();
    const initial_window = cc.congestion_window;
    try testing.expect(initial_window > MIN_WINDOW_PACKETS * DEFAULT_MAX_DATAGRAM_SIZE);

    const now: i64 = 1_000_000_000;
    cc.onPersistentCongestion(now);

    // Window should be at minimum (2 * MSS)
    try testing.expectEqual(MIN_WINDOW_PACKETS * DEFAULT_MAX_DATAGRAM_SIZE, cc.congestion_window);
    // ssthresh should be maxInt to allow slow start recovery (exponential growth)
    try testing.expectEqual(std.math.maxInt(u64), cc.ssthresh);
    // Should be in slow start after persistent congestion
    try testing.expect(cc.inSlowStart());
    // Recovery start time should be set to prevent re-triggering for old packets
    try testing.expectEqual(@as(?i64, now), cc.congestion_recovery_start_time);
    // Packets sent after 'now' should NOT be in recovery (can grow window)
    try testing.expect(!cc.inCongestionRecovery(now + 1));
    // Packets sent at or before 'now' SHOULD be in recovery (suppressed)
    try testing.expect(cc.inCongestionRecovery(now));
}

// ── CUBIC tests ──

test "Cubic: initial state" {
    const cc = Cubic.init();
    try testing.expect(cc.inSlowStart());
    try testing.expectEqual(
        INITIAL_WINDOW_PACKETS * DEFAULT_MAX_DATAGRAM_SIZE,
        cc.congestion_window,
    );
}

test "Cubic: slow start growth" {
    var cc = Cubic.init();
    const initial_window = cc.congestion_window;

    cc.onPacketAcked(1200, 100);
    try testing.expectEqual(initial_window + 1200, cc.congestion_window);
    try testing.expect(cc.inSlowStart());
}

test "Cubic: congestion event reduces window by beta" {
    var cc = Cubic.init();
    const initial_window = cc.congestion_window;

    cc.onCongestionEvent(100, 200);

    // Window should be reduced by beta (0.7)
    const expected = initial_window * Cubic.BETA_NUM / Cubic.BETA_DENOM;
    try testing.expectEqual(expected, cc.congestion_window);
    try testing.expect(!cc.inSlowStart());
    // W_max should be saved
    try testing.expectEqual(initial_window, cc.w_max);
}

test "Cubic: recovery period prevents double cutback" {
    var cc = Cubic.init();

    cc.onCongestionEvent(100, 200);
    const after_first = cc.congestion_window;

    // Packet sent before recovery — should NOT cut
    cc.onCongestionEvent(150, 250);
    try testing.expectEqual(after_first, cc.congestion_window);

    // Packet sent AFTER recovery — should cut
    cc.onCongestionEvent(300, 400);
    try testing.expect(cc.congestion_window < after_first);
}

test "Cubic: minimum window enforced" {
    var cc = Cubic.init();
    cc.congestion_window = 3000;
    cc.congestion_recovery_start_time = null;
    cc.onCongestionEvent(100, 200);

    try testing.expect(cc.congestion_window >= MIN_WINDOW_PACKETS * DEFAULT_MAX_DATAGRAM_SIZE);
}

test "Cubic: persistent congestion resets to minimum" {
    var cc = Cubic.init();
    const now: i64 = 1_000_000_000;
    cc.onPersistentCongestion(now);

    try testing.expectEqual(MIN_WINDOW_PACKETS * DEFAULT_MAX_DATAGRAM_SIZE, cc.congestion_window);
    try testing.expectEqual(std.math.maxInt(u64), cc.ssthresh);
    try testing.expect(cc.inSlowStart());
    try testing.expectEqual(@as(?i64, now), cc.congestion_recovery_start_time);
    try testing.expect(cc.epoch_start == null);
    try testing.expectEqual(@as(u64, 0), cc.w_max);
}

test "Cubic: fast convergence reduces W_max" {
    var cc = Cubic.init();

    // First loss: W_max = initial window
    cc.onCongestionEvent(100, 200);
    const first_w_max = cc.w_max;
    try testing.expectEqual(INITIAL_WINDOW_PACKETS * DEFAULT_MAX_DATAGRAM_SIZE, first_w_max);

    // Second loss with smaller window: fast convergence should reduce W_max
    // Current cwnd < w_max, so fast convergence kicks in
    cc.congestion_recovery_start_time = null; // Allow new congestion event
    const cwnd_before = cc.congestion_window;
    cc.onCongestionEvent(300, 400);
    // W_max should be reduced: cwnd * (beta + 1) / 2
    const expected_w_max = cwnd_before * (Cubic.BETA_NUM + Cubic.BETA_DENOM) / (2 * Cubic.BETA_DENOM);
    try testing.expectEqual(expected_w_max, cc.w_max);
}

test "Cubic: epoch resets on congestion event" {
    var cc = Cubic.init();
    cc.epoch_start = 12345;

    cc.onCongestionEvent(100, 200);
    try testing.expect(cc.epoch_start == null);
}

test "Cubic: setMaxDatagramSize" {
    var cc = Cubic.init();
    cc.setMaxDatagramSize(1400);
    try testing.expectEqual(@as(u64, 1400), cc.max_datagram_size);
}

test "Cubic: PTO does not reduce window" {
    var cc = Cubic.init();
    const window_before = cc.congestion_window;
    cc.onPtoExpired();
    try testing.expectEqual(window_before, cc.congestion_window);
}

// ── icbrt tests ──

test "icbrt: basic cube roots" {
    try testing.expectEqual(@as(u64, 0), icbrt(0));
    try testing.expectEqual(@as(u64, 1), icbrt(1));
    try testing.expectEqual(@as(u64, 1), icbrt(7));
    try testing.expectEqual(@as(u64, 2), icbrt(8));
    try testing.expectEqual(@as(u64, 2), icbrt(26));
    try testing.expectEqual(@as(u64, 3), icbrt(27));
    try testing.expectEqual(@as(u64, 10), icbrt(1000));
    try testing.expectEqual(@as(u64, 10), icbrt(1100));
    try testing.expectEqual(@as(u64, 100), icbrt(1000000));
}

// ── Pacer tests ──

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
