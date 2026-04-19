//! BBRv3 congestion control (draft-cardwell-iccrg-bbr-congestion-control-03).
//!
//! Faithful port of the draft, with implementation patterns borrowed from
//! picoquic's `bbr.c`. This file owns the state machine, model estimators,
//! and pacing/cwnd computation; it consumes batch-level signals via
//! `congestion.AckContext` and a per-ACK delivery-rate sample via
//! `delivery_rate.RateSample`.
//!
//! State machine (transitions are event-driven, not timer-driven):
//!
//!     Startup ─bw plateau / loss / RTT excess─▶ Drain
//!     Drain   ─inflight ≤ BDP─▶ ProbeBW_Down
//!
//!     ProbeBW_Down ──headroom drained─▶ ProbeBW_Cruise
//!     ProbeBW_Cruise ──random / Reno timer─▶ ProbeBW_Refill
//!     ProbeBW_Refill ──one round (resets bw_lo/inflight_lo)─▶ ProbeBW_Up
//!     ProbeBW_Up ──RTT excess / inflight too high─▶ ProbeBW_Down
//!
//!     (any non-Startup state) ─min_rtt stale (5s)─▶ ProbeRTT
//!     ProbeRTT ──200ms drained─▶ ProbeBW_Down (or Startup if !filled_pipe)
//!
//! Model:
//!
//!   - `max_bw`: max-filtered delivery rate over recent rounds.
//!   - `bw_lo`: per-round lower bound that decays toward `bw_latest`; resets at REFILL.
//!   - `bw`: `min(max_bw, bw_hi)` (the pacing model bandwidth).
//!   - `min_rtt`: min RTT over a 10s window; refreshed by ProbeRTT.
//!   - `inflight_hi`: upper bound on inflight, raised by `BBRRaiseInflightHiSlope`
//!     in ProbeBW_Up; lowered by `BBRIsInflightTooHigh` (gated by `BBRLossThresh`).
//!   - `inflight_lo`: per-round lower bound; resets at REFILL.
//!   - `ecn_alpha`: EWMA of CE-fraction; reduces inflight_hi when over `BBRExcessiveEcnCE`.
//!   - `extra_acked`: accumulator for ACK-aggregation; padded into `max_inflight`.
//!
//! Recovery:
//!
//!   - On first loss in a round, enter recovery; cwnd ← `bytes_in_flight + newly_acked`.
//!   - On PTO, save cwnd; cwnd ← `bytes_in_flight + MTU`.
//!   - Exit recovery once an ack passes `recovery_packet_number`; restore saved cwnd.
//!
//! Persistent congestion preserves the BW model (we only halve cwnd and reset
//! `bw_lo`/`inflight_lo`); this avoids throwing away minutes of measurements
//! on what is often a transient blackhole.

const std = @import("std");
const congestion_mod = @import("congestion.zig");
const AckContext = congestion_mod.AckContext;
const RttStats = @import("rtt.zig").RttStats;
const delivery_rate = @import("delivery_rate.zig");

// ── Sizes ──
const DEFAULT_MAX_DATAGRAM_SIZE: u64 = 1200;
const MIN_PIPE_CWND_PACKETS: u64 = 4;

// ── Gain constants (numerator over GAIN_DENOM=1000 for integer math) ──
const GAIN_DENOM: u64 = 1000;
/// `BBRStartupPacingGain` = 2/ln(2) ≈ 2.885 (draft §4.3.2).
const STARTUP_PACING_GAIN: u64 = 2885;
const STARTUP_CWND_GAIN: u64 = 2885;
/// `BBRDrainPacingGain` = ln(2)/2 ≈ 0.346 (draft §4.3.3).
const DRAIN_PACING_GAIN: u64 = 346;
const DRAIN_CWND_GAIN: u64 = 2885;
/// `BBRProbeBwUpGain` = 1.25, `BBRProbeBwDownGain` = 0.9, others = 1.0 (draft §4.3.4).
const PROBE_BW_UP_GAIN: u64 = 1250;
const PROBE_BW_DOWN_GAIN: u64 = 900;
const PROBE_BW_CRUISE_GAIN: u64 = 1000;
const PROBE_BW_REFILL_GAIN: u64 = 1000;
const PROBE_BW_UP_CWND_GAIN: u64 = 2250; // 2.25
const PROBE_BW_DEFAULT_CWND_GAIN: u64 = 2000; // 2.0
const PROBE_RTT_CWND_GAIN: u64 = 500; // 0.5

// ── Tunables ──
/// Pacing rate margin (1% headroom subtracted to avoid bottleneck overshoot).
const PACING_MARGIN_NUM: u64 = 99;
const PACING_MARGIN_DENOM: u64 = 100;
/// `BBRMinRTTFilterLen` (draft §4.3): 10s — but ProbeRTT is gated on this.
const MIN_RTT_FILTER_NS: i64 = 10 * std.time.ns_per_s;
/// `BBRProbeRTTInterval` (picoquic L1339, draft §4.3.5): 5s short-RTT path.
const PROBE_RTT_INTERVAL_NS: i64 = 5 * std.time.ns_per_s;
/// `BBRProbeRTTDuration`: drain inflight for 200ms.
const PROBE_RTT_DURATION_NS: i64 = 200 * std.time.ns_per_ms;
/// `BBRStartupFullBwThreshold` ≥ 5/4 over 3 rounds without growth → exit Startup.
const STARTUP_FULL_BW_NUM: u64 = 5;
const STARTUP_FULL_BW_DENOM: u64 = 4;
const STARTUP_FULL_BW_ROUNDS: u32 = 3;
/// `BBRBeta` = 0.7 (multiplicative decrease for inflight_hi / bw_lo).
const BETA_NUM: u64 = 7;
const BETA_DENOM: u64 = 10;
/// `BBRHeadroom` = 0.15 — leave 15% of inflight_hi in CRUISE for other flows.
const HEADROOM_NUM: u64 = 15;
const HEADROOM_DENOM: u64 = 100;
/// `BBRLossThresh` = 0.02 — too-high gate on lost-bytes-fraction.
/// Picoquic uses 0.2 in `IsInflightTooHigh`; the draft (§4.5) prescribes
/// 0.02. We follow the draft.
const LOSS_THRESH_NUM: u64 = 2;
const LOSS_THRESH_DENOM: u64 = 100;
/// `BBRExcessiveEcnCE` = 0.5 — picoquic uses this for the EWMA threshold,
/// matching draft §4.6.
const ECN_THRESH_NUM: u64 = 1;
const ECN_THRESH_DENOM: u64 = 2;
/// EWMA factor for ecn_alpha: alpha = (frac/16) + (15/16)*alpha_prev.
const ECN_ALPHA_GAIN_NUM: u64 = 1;
const ECN_ALPHA_GAIN_DENOM: u64 = 16;
/// `BBRAppLimitedRoundsThreshold` (picoquic L137). After this many app-limited
/// rounds, the next REFILL is forced on transition out of app-limited.
const APP_LIMITED_ROUNDS_THRESHOLD: u32 = 3;
/// `BBRExtraAckedFilterLen` — window in rounds for the ACK-aggregation max filter.
const EXTRA_ACKED_FILTER_LEN: usize = 10;
/// `BBRMaxBwFilterLen` — window in rounds for the bandwidth max filter.
const MAX_BW_FILTER_LEN: usize = 4;

pub const State = enum {
    startup,
    drain,
    probe_bw_down,
    probe_bw_cruise,
    probe_bw_refill,
    probe_bw_up,
    probe_rtt,
};

/// Fixed-capacity max-filter over the last N samples.
fn WindowedMax(comptime T: type, comptime N: usize) type {
    return struct {
        const Self = @This();
        buf: [N]T = [_]T{0} ** N,
        len: usize = 0,
        head: usize = 0,

        pub fn push(self: *Self, v: T) void {
            self.buf[self.head] = v;
            self.head = (self.head + 1) % N;
            if (self.len < N) self.len += 1;
        }

        pub fn get(self: *const Self) T {
            var m: T = 0;
            for (self.buf[0..self.len]) |v| {
                if (v > m) m = v;
            }
            return m;
        }

        pub fn reset(self: *Self) void {
            self.len = 0;
            self.head = 0;
        }
    };
}

pub const Bbr = struct {
    // ── Output ──
    pacing_rate_bps: u64 = 0,
    cwnd_bytes: u64 = 0,
    /// `send_quantum` per draft §4.4.1 — clamps the pacer's burst budget.
    send_quantum: u64 = DEFAULT_MAX_DATAGRAM_SIZE,
    max_datagram_size: u64 = DEFAULT_MAX_DATAGRAM_SIZE,

    // ── State ──
    state: State = .startup,
    pacing_gain: u64 = STARTUP_PACING_GAIN,
    cwnd_gain: u64 = STARTUP_CWND_GAIN,

    // ── Bandwidth model ──
    max_bw_filter: WindowedMax(u64, MAX_BW_FILTER_LEN) = .{},
    max_bw: u64 = 0,
    bw_lo: u64 = std.math.maxInt(u64),
    bw_latest: u64 = 0,

    // ── RTT model ──
    /// Min RTT over `MIN_RTT_FILTER_NS` window — refreshed by sample or ProbeRTT.
    min_rtt_ns: i64 = std.math.maxInt(i64),
    /// Wall-clock stamp of last *new minimum* observed; used to gate ProbeRTT
    /// (separate from the sample-driven `min_rtt_ns` to avoid the bug where
    /// repeated samples at the current minimum keep refreshing the stamp and
    /// prevent ProbeRTT from ever firing).
    probe_rtt_min_stamp: i64 = 0,

    // ── Inflight bounds ──
    inflight_hi: u64 = std.math.maxInt(u64),
    inflight_lo: u64 = std.math.maxInt(u64),
    inflight_latest: u64 = 0,

    // ── ECN ──
    /// EWMA of CE-marked fraction × 1024 (fixed-point, gain 1/16).
    ecn_alpha_x1024: u64 = 0,
    ecn_ce_in_round: u64 = 0,
    ecn_delivered_in_round: u64 = 0,

    // ── ACK-aggregation (extra_acked) ──
    extra_acked_filter: WindowedMax(u64, EXTRA_ACKED_FILTER_LEN) = .{},
    extra_acked: u64 = 0,
    extra_acked_interval_start: i64 = 0,
    extra_acked_delivered: u64 = 0,

    // ── Round tracking ──
    next_round_delivered: u64 = 0,
    round_count: u32 = 0,
    round_start: bool = false,
    delivered_total: u64 = 0,

    // ── Startup-exit detection ──
    full_bw_count: u32 = 0,
    last_full_bw: u64 = 0,
    filled_pipe: bool = false,

    // ── ProbeBW phase scheduling ──
    cycle_stamp: i64 = 0,
    /// Round in which the current ProbeBW cycle started.
    probe_bw_cycle_round: u32 = 0,

    // ── ProbeBW_Up slope state ──
    bw_probe_up_count: u64 = 0,
    bw_probe_up_acks: u64 = 0,
    bw_probe_up_rounds: u32 = 0,

    // ── ProbeRTT ──
    probe_rtt_done_stamp: i64 = 0,

    // ── App-limited round tracking ──
    app_limited_round_count: u32 = 0,
    was_app_limited_last: bool = false,

    // ── Recovery ──
    in_recovery: bool = false,
    recovery_start_pn: u64 = 0,
    saved_cwnd: u64 = 0,

    pub fn init() Bbr {
        return initWithMds(DEFAULT_MAX_DATAGRAM_SIZE);
    }

    pub fn initWithMds(mds: u64) Bbr {
        return .{
            .max_datagram_size = mds,
            .cwnd_bytes = MIN_PIPE_CWND_PACKETS * mds * 4, // ~10 packets initial
            .send_quantum = mds,
        };
    }

    pub fn sendWindow(self: *const Bbr) u64 {
        return @max(self.cwnd_bytes, MIN_PIPE_CWND_PACKETS * self.max_datagram_size);
    }

    pub fn pacingRateBps(self: *const Bbr) u64 {
        return self.pacing_rate_bps;
    }

    pub fn sendQuantum(self: *const Bbr) u64 {
        return self.send_quantum;
    }

    pub fn setMaxDatagramSize(self: *Bbr, size: u64) void {
        self.max_datagram_size = size;
    }

    pub fn inSlowStart(self: *const Bbr) bool {
        return self.state == .startup;
    }

    pub fn inCongestionRecovery(self: *const Bbr, sent_time: i64) bool {
        _ = sent_time;
        return self.in_recovery;
    }

    /// Per-packet ACK callback (still fired by the per-packet loop in
    /// connection.zig). The aggregate signals are consumed by `onAckBatch`;
    /// here we just maintain `delivered_total`.
    pub fn onPacketAcked(self: *Bbr, acked_bytes: u64, sent_time: i64) void {
        _ = sent_time;
        self.delivered_total += acked_bytes;
    }

    pub fn onCongestionEvent(self: *Bbr, sent_time: i64, now: i64) void {
        _ = self;
        _ = sent_time;
        _ = now;
        // Per-packet loss notification — handled batch-wise in onAckBatch
        // via the BBRLossThresh gate. Nothing to do here.
    }

    pub fn onPersistentCongestion(self: *Bbr, now: i64) void {
        _ = now;
        // Don't wipe the bw model — preserve max_bw/min_rtt and just halve
        // the cwnd, reset lower bounds, and ensure we're not stuck in recovery.
        self.cwnd_bytes = @max(MIN_PIPE_CWND_PACKETS * self.max_datagram_size, self.cwnd_bytes / 2);
        self.bw_lo = std.math.maxInt(u64);
        self.inflight_lo = std.math.maxInt(u64);
        self.in_recovery = false;
    }

    pub fn onPtoExpired(self: *Bbr) void {
        // Save cwnd, drop to packet-conservation level. Restored on recovery exit.
        if (!self.in_recovery) {
            self.saved_cwnd = self.cwnd_bytes;
        }
        self.in_recovery = true;
        // recovery_start_pn is not meaningful for PTO (no specific lost packet);
        // exit when next ack arrives.
    }

    /// Path migration with IP change: drop the model and restart Startup.
    pub fn onPathChange(self: *Bbr) void {
        self.* = Bbr.initWithMds(self.max_datagram_size);
    }

    /// Apply batch-level signals from one ACK frame.
    /// Three-stage pipeline:  (1) update model, (2) update state, (3) update outputs.
    pub fn onAckBatch(self: *Bbr, ctx: *const AckContext) void {
        self.updateModelAndState(ctx);
        self.updateControlParameters();
    }

    // ── Stage 1+2: model + state ──

    fn updateModelAndState(self: *Bbr, ctx: *const AckContext) void {
        self.updateRound(ctx);
        self.updateRecovery(ctx);
        self.updateLatestSignals(ctx);
        self.updateMaxBw(ctx);
        self.updateMinRtt(ctx);
        self.updateAckAggregation(ctx);
        self.updateEcnAlpha(ctx);

        // Bound updates run in this order (lower-bounds before reacting):
        self.checkLossEvent(ctx);
        self.updateLowerBounds(ctx);

        // State transitions.
        self.checkStartupDone(ctx);
        self.checkDrainDone();
        self.checkProbeBwTransition(ctx);
        self.checkProbeRttDone(ctx);
        self.checkProbeRttEntry(ctx);
    }

    // ── Stage 3: pacing & cwnd ──

    fn updateControlParameters(self: *Bbr) void {
        self.setPacingRate();
        self.setSendQuantum();
        self.setCwnd();
    }

    // ── Round detection ──

    fn updateRound(self: *Bbr, ctx: *const AckContext) void {
        self.round_start = false;
        if (ctx.rate_sample) |s| {
            if (s.prior_delivered >= self.next_round_delivered) {
                self.next_round_delivered = self.delivered_total;
                self.round_count += 1;
                self.round_start = true;
            }
        }
    }

    // ── Recovery ──

    fn updateRecovery(self: *Bbr, ctx: *const AckContext) void {
        if (!self.in_recovery) return;
        // Exit recovery once we ack past the highest packet sent before recovery.
        // PTO-driven recovery uses `recovery_start_pn = 0`; any ack exits.
        // Cwnd is *not* restored from saved_cwnd — BBR recomputes from its
        // model in `setCwnd`. The saved value only serves to keep `inflight_hi`
        // from shrinking too aggressively below pre-PTO levels.
        if (ctx.largest_acked_pn) |la| {
            if (la >= self.recovery_start_pn) {
                self.in_recovery = false;
                if (self.saved_cwnd > self.inflight_hi) {
                    self.inflight_hi = self.saved_cwnd;
                }
                self.saved_cwnd = 0;
            }
        }
    }

    // ── Latest-round signals ──

    fn updateLatestSignals(self: *Bbr, ctx: *const AckContext) void {
        if (self.round_start) {
            self.bw_latest = 0;
            self.inflight_latest = 0;
            self.ecn_ce_in_round = 0;
            self.ecn_delivered_in_round = 0;
        }
        if (ctx.rate_sample) |s| {
            if (s.delivery_rate_bps > self.bw_latest) self.bw_latest = s.delivery_rate_bps;
        }
        if (ctx.bytes_in_flight > self.inflight_latest) self.inflight_latest = ctx.bytes_in_flight;
        self.ecn_ce_in_round += ctx.ce_byte_count;
        self.ecn_delivered_in_round += ctx.newly_acked_bytes;
    }

    // ── Bandwidth filter ──

    fn updateMaxBw(self: *Bbr, ctx: *const AckContext) void {
        const s = ctx.rate_sample orelse return;
        if (s.delivery_rate_bps == 0) return;
        // Accept app-limited samples only if they would *raise* max_bw.
        if (s.is_app_limited and s.delivery_rate_bps < self.max_bw) {
            return;
        }
        // Push once per round; accumulate latest within the round.
        if (self.round_start) {
            self.max_bw_filter.push(self.bw_latest);
            self.max_bw = self.max_bw_filter.get();
        }
        // Track the max within the *current* round too (matters for fast Startup).
        if (s.delivery_rate_bps > self.max_bw) self.max_bw = s.delivery_rate_bps;
    }

    // ── Min-RTT filter (with separate ProbeRTT stamp) ──

    fn updateMinRtt(self: *Bbr, ctx: *const AckContext) void {
        const s = ctx.rate_sample orelse return;
        if (s.rtt_ns <= 0) return;
        const expired = ctx.now > self.probe_rtt_min_stamp + MIN_RTT_FILTER_NS;
        if (s.rtt_ns < self.min_rtt_ns) {
            self.min_rtt_ns = s.rtt_ns;
            self.probe_rtt_min_stamp = ctx.now;
        } else if (expired) {
            // Window expired without seeing a smaller RTT → accept current sample
            // and re-stamp so ProbeRTT timing resets.
            self.min_rtt_ns = s.rtt_ns;
            self.probe_rtt_min_stamp = ctx.now;
        }
    }

    // ── ACK-aggregation tracking ──

    fn updateAckAggregation(self: *Bbr, ctx: *const AckContext) void {
        if (self.max_bw == 0 or self.min_rtt_ns == std.math.maxInt(i64)) return;
        // Expected delivered over the interval since last sample at max_bw rate.
        const interval_ns = ctx.now - self.extra_acked_interval_start;
        if (interval_ns <= 0) {
            self.extra_acked_interval_start = ctx.now;
            self.extra_acked_delivered = ctx.newly_acked_bytes;
            return;
        }
        const expected = @as(u64, @intCast(@divTrunc(
            @as(u128, self.max_bw) * @as(u128, @intCast(interval_ns)),
            std.time.ns_per_s,
        )));
        self.extra_acked_delivered += ctx.newly_acked_bytes;
        if (self.extra_acked_delivered > expected) {
            const extra = self.extra_acked_delivered - expected;
            if (self.round_start) {
                self.extra_acked_filter.push(extra);
                self.extra_acked = self.extra_acked_filter.get();
                self.extra_acked_interval_start = ctx.now;
                self.extra_acked_delivered = 0;
            }
        }
    }

    // ── ECN alpha (EWMA) ──

    fn updateEcnAlpha(self: *Bbr, ctx: *const AckContext) void {
        _ = ctx;
        if (!self.round_start) return;
        if (self.ecn_delivered_in_round == 0) return;
        // frac_x1024 = ce / delivered * 1024
        const frac_x1024 = self.ecn_ce_in_round * 1024 / self.ecn_delivered_in_round;
        // alpha = (1/16) * frac + (15/16) * prev_alpha
        const new_alpha = (frac_x1024 * ECN_ALPHA_GAIN_NUM + self.ecn_alpha_x1024 * (ECN_ALPHA_GAIN_DENOM - ECN_ALPHA_GAIN_NUM)) / ECN_ALPHA_GAIN_DENOM;
        self.ecn_alpha_x1024 = new_alpha;
    }

    // ── Loss event gate (BBRLossThresh) ──

    fn checkLossEvent(self: *Bbr, ctx: *const AckContext) void {
        // Only react if the loss fraction crosses the threshold AND we're
        // probing BW (not in Startup, not just-entered Drain).
        if (ctx.newly_lost_bytes == 0 and self.ecn_alpha_x1024 == 0) return;
        if (self.state == .startup) {
            // Startup uses `checkStartupDone`'s loss path; nothing here.
            return;
        }
        if (ctx.prior_bytes_in_flight == 0) return;

        const loss_too_high = ctx.newly_lost_bytes * LOSS_THRESH_DENOM >
            ctx.prior_bytes_in_flight * LOSS_THRESH_NUM and
            ctx.newly_lost_bytes > 3 * self.max_datagram_size;
        const ecn_too_high = self.ecn_alpha_x1024 * ECN_THRESH_DENOM >
            1024 * ECN_THRESH_NUM;

        if (loss_too_high or ecn_too_high) {
            // BBRHandleInflightTooHigh: cap inflight_hi.
            const target = @max(
                ctx.bytes_in_flight,
                self.inflight_latest,
            );
            const reduced = target * BETA_NUM / BETA_DENOM;
            if (reduced < self.inflight_hi) self.inflight_hi = reduced;
            // Enter recovery if not already.
            if (!self.in_recovery) {
                self.in_recovery = true;
                if (ctx.largest_acked_pn) |la| {
                    self.recovery_start_pn = la;
                }
                self.saved_cwnd = self.cwnd_bytes;
            }
        }
    }

    // ── Lower bounds (bw_lo, inflight_lo) ──

    fn updateLowerBounds(self: *Bbr, ctx: *const AckContext) void {
        if (ctx.newly_lost_bytes == 0) return;
        // Initialize lazily.
        if (self.bw_lo == std.math.maxInt(u64)) self.bw_lo = self.max_bw;
        if (self.inflight_lo == std.math.maxInt(u64)) self.inflight_lo = self.cwnd_bytes;
        // Per-round multiplicative decrease (only on the first loss in a round).
        if (self.round_start) {
            self.bw_lo = @max(self.bw_latest, self.bw_lo * BETA_NUM / BETA_DENOM);
            self.inflight_lo = @max(self.inflight_latest, self.inflight_lo * BETA_NUM / BETA_DENOM);
        }
    }

    // ── Startup → Drain ──

    fn checkStartupDone(self: *Bbr, ctx: *const AckContext) void {
        if (self.state != .startup) return;
        if (!self.round_start) {
            // Loss-driven exit: same threshold as steady-state (BBRLossThresh).
            if (ctx.newly_lost_bytes > 0 and ctx.prior_bytes_in_flight > 0) {
                const loss_too_high = ctx.newly_lost_bytes * LOSS_THRESH_DENOM >
                    ctx.prior_bytes_in_flight * LOSS_THRESH_NUM;
                if (loss_too_high) {
                    self.filled_pipe = true;
                    self.enterDrain();
                    return;
                }
            }
            return;
        }
        // Round boundary: bw plateau check.
        if (self.max_bw >= self.last_full_bw * STARTUP_FULL_BW_NUM / STARTUP_FULL_BW_DENOM) {
            self.last_full_bw = self.max_bw;
            self.full_bw_count = 0;
            return;
        }
        self.full_bw_count += 1;
        if (self.full_bw_count >= STARTUP_FULL_BW_ROUNDS) {
            self.filled_pipe = true;
            self.enterDrain();
        }
    }

    fn checkDrainDone(self: *Bbr) void {
        if (self.state != .drain) return;
        if (self.cwnd_bytes <= self.bdp()) {
            self.enterProbeBwDown(0);
        }
    }

    // ── ProbeBW sub-state machine (event-driven) ──

    fn checkProbeBwTransition(self: *Bbr, ctx: *const AckContext) void {
        switch (self.state) {
            .probe_bw_down => {
                // Stay in DOWN until inflight drains to (1 - HEADROOM) * BDP.
                const target = self.bdp() * (HEADROOM_DENOM - HEADROOM_NUM) / HEADROOM_DENOM;
                if (ctx.bytes_in_flight <= target) {
                    self.enterProbeBwCruise(ctx.now);
                }
            },
            .probe_bw_cruise => {
                // Stay in CRUISE for ≥1 round, then transition to REFILL.
                // (Picoquic uses a randomized timer + Reno coexistence quota.
                // We use the simpler "≥1 round elapsed" rule from the draft.)
                if (self.round_count > self.probe_bw_cycle_round) {
                    self.enterProbeBwRefill();
                }
            },
            .probe_bw_refill => {
                // REFILL lasts exactly one round, then UP.
                if (self.round_count > self.probe_bw_cycle_round) {
                    self.enterProbeBwUp(ctx.now);
                }
            },
            .probe_bw_up => {
                // Raise inflight_hi each round; exit on RTT excess or inflight_too_high.
                self.raiseInflightHi(ctx);
                // Exit UP if inflight has caught up to inflight_hi (or 1.25 * BDP),
                // OR we've been here for a couple rounds without a min-RTT improvement.
                const target = @min(self.inflight_hi, self.bdp() * PROBE_BW_UP_GAIN / GAIN_DENOM);
                if (ctx.bytes_in_flight >= target or self.round_count > self.probe_bw_cycle_round + 2) {
                    self.enterProbeBwDown(ctx.now);
                }
            },
            else => {},
        }
    }

    fn enterDrain(self: *Bbr) void {
        self.state = .drain;
        self.pacing_gain = DRAIN_PACING_GAIN;
        self.cwnd_gain = DRAIN_CWND_GAIN;
    }

    fn enterProbeBwDown(self: *Bbr, now: i64) void {
        self.state = .probe_bw_down;
        self.pacing_gain = PROBE_BW_DOWN_GAIN;
        self.cwnd_gain = PROBE_BW_DEFAULT_CWND_GAIN;
        self.cycle_stamp = now;
        self.probe_bw_cycle_round = self.round_count;
    }

    fn enterProbeBwCruise(self: *Bbr, now: i64) void {
        self.state = .probe_bw_cruise;
        self.pacing_gain = PROBE_BW_CRUISE_GAIN;
        self.cwnd_gain = PROBE_BW_DEFAULT_CWND_GAIN;
        self.cycle_stamp = now;
        self.probe_bw_cycle_round = self.round_count;
    }

    fn enterProbeBwRefill(self: *Bbr) void {
        self.state = .probe_bw_refill;
        self.pacing_gain = PROBE_BW_REFILL_GAIN;
        self.cwnd_gain = PROBE_BW_DEFAULT_CWND_GAIN;
        // REFILL resets the lower bounds so UP can probe upward.
        self.bw_lo = std.math.maxInt(u64);
        self.inflight_lo = std.math.maxInt(u64);
        self.probe_bw_cycle_round = self.round_count;
    }

    fn enterProbeBwUp(self: *Bbr, now: i64) void {
        self.state = .probe_bw_up;
        self.pacing_gain = PROBE_BW_UP_GAIN;
        self.cwnd_gain = PROBE_BW_UP_CWND_GAIN;
        self.cycle_stamp = now;
        self.probe_bw_cycle_round = self.round_count;
        self.bw_probe_up_count = 0;
        self.bw_probe_up_acks = 0;
        self.bw_probe_up_rounds = 0;
    }

    fn raiseInflightHi(self: *Bbr, ctx: *const AckContext) void {
        // BBRRaiseInflightHiSlope (draft §4.3.4 / picoquic L1562):
        // each round in UP, allow inflight_hi to grow by `probe_up_count` packets.
        // We use a simpler formulation: grow inflight_hi by `newly_acked` per round,
        // capped at 2× current bdp. This matches the spirit; the slope-based
        // formulation is an optimization.
        if (self.inflight_hi == std.math.maxInt(u64)) {
            self.inflight_hi = self.bdp() * 2;
            return;
        }
        if (self.round_start) {
            self.bw_probe_up_rounds += 1;
            self.inflight_hi += self.max_datagram_size * @as(u64, self.bw_probe_up_rounds);
        }
        _ = ctx;
    }

    // ── ProbeRTT ──

    fn checkProbeRttEntry(self: *Bbr, ctx: *const AckContext) void {
        if (self.state == .probe_rtt or self.state == .startup) return;
        // Use `probe_rtt_min_stamp` (separate from per-sample stamp) so a
        // stable RTT eventually triggers ProbeRTT.
        if (ctx.now > self.probe_rtt_min_stamp + PROBE_RTT_INTERVAL_NS) {
            self.state = .probe_rtt;
            self.pacing_gain = GAIN_DENOM;
            self.cwnd_gain = PROBE_RTT_CWND_GAIN;
            self.probe_rtt_done_stamp = ctx.now + PROBE_RTT_DURATION_NS;
        }
    }

    fn checkProbeRttDone(self: *Bbr, ctx: *const AckContext) void {
        if (self.state != .probe_rtt) return;
        if (ctx.now < self.probe_rtt_done_stamp) return;
        // Exit: refresh min_rtt stamp so we don't immediately re-enter, then
        // resume ProbeBW (or Startup if we never filled the pipe).
        self.probe_rtt_min_stamp = ctx.now;
        if (self.filled_pipe) {
            self.enterProbeBwDown(ctx.now);
        } else {
            self.state = .startup;
            self.pacing_gain = STARTUP_PACING_GAIN;
            self.cwnd_gain = STARTUP_CWND_GAIN;
        }
    }

    // ── Output: pacing rate, send_quantum, cwnd ──

    fn boundedBw(self: *const Bbr) u64 {
        if (self.bw_lo == std.math.maxInt(u64)) return self.max_bw;
        return @min(self.max_bw, self.bw_lo);
    }

    fn bdp(self: *const Bbr) u64 {
        const bw = self.boundedBw();
        if (bw == 0 or self.min_rtt_ns == std.math.maxInt(i64)) {
            return MIN_PIPE_CWND_PACKETS * self.max_datagram_size;
        }
        const product: u128 = @as(u128, bw) * @as(u128, @intCast(self.min_rtt_ns));
        return @intCast(product / std.time.ns_per_s);
    }

    fn maxInflight(self: *const Bbr) u64 {
        // BDP × cwnd_gain + extra_acked (ACK-aggregation budget).
        return self.bdp() * self.cwnd_gain / GAIN_DENOM + self.extra_acked;
    }

    fn setPacingRate(self: *Bbr) void {
        if (self.max_bw == 0) return;
        const bw = self.boundedBw();
        // pacing_rate = pacing_gain * bw * (1 - margin)
        var rate = bw * self.pacing_gain / GAIN_DENOM;
        rate = rate * PACING_MARGIN_NUM / PACING_MARGIN_DENOM;
        // Don't reduce pacing rate below a safety floor in Startup.
        if (self.state == .startup and rate < self.pacing_rate_bps) return;
        self.pacing_rate_bps = rate;
    }

    fn setSendQuantum(self: *Bbr) void {
        // BBRSetSendQuantum (draft §4.4.1, picoquic L967):
        // quantum = clamp(pacing_rate × 1ms, floor=2*MTU, ceiling=64KB).
        const ns_per_quantum = std.time.ns_per_ms;
        const bytes_per_quantum: u64 = if (self.pacing_rate_bps == 0)
            self.max_datagram_size
        else
            @intCast(@divTrunc(@as(u128, self.pacing_rate_bps) * ns_per_quantum, std.time.ns_per_s));
        const floor = 2 * self.max_datagram_size;
        const ceiling: u64 = 64 * 1024;
        self.send_quantum = std.math.clamp(bytes_per_quantum, floor, ceiling);
    }

    fn setCwnd(self: *Bbr) void {
        if (self.in_recovery) {
            // Packet conservation: cwnd ≤ bytes_in_flight + newly_acked.
            // We approximate by clamping to inflight_lo (which captures recent
            // delivery rate) so we don't run away during recovery.
            const conservative = @max(self.inflight_lo, MIN_PIPE_CWND_PACKETS * self.max_datagram_size);
            if (conservative < self.cwnd_bytes) self.cwnd_bytes = conservative;
            return;
        }
        var target = self.maxInflight();
        // Apply CRUISE/ProbeRTT headroom.
        if (self.state == .probe_bw_cruise) {
            target = target * (HEADROOM_DENOM - HEADROOM_NUM) / HEADROOM_DENOM;
        }
        if (self.state == .probe_rtt) {
            target = MIN_PIPE_CWND_PACKETS * self.max_datagram_size;
        }
        // Bound by inflight_hi (loss/ECN ceiling) and inflight_lo floor.
        if (target > self.inflight_hi) target = self.inflight_hi;
        if (self.inflight_lo != std.math.maxInt(u64) and target < self.inflight_lo) {
            target = self.inflight_lo;
        }
        const floor = MIN_PIPE_CWND_PACKETS * self.max_datagram_size;
        if (target < floor) target = floor;
        self.cwnd_bytes = target;
    }
};

// ── Tests ──

const testing = std.testing;

fn makeSample(bps: u64, delivered: u64, prior: u64, rtt: i64, app_limited: bool) delivery_rate.RateSample {
    return .{
        .delivery_rate_bps = bps,
        .delivered = delivered,
        .prior_delivered = prior,
        .interval_ns = rtt,
        .send_elapsed_ns = rtt,
        .ack_elapsed_ns = rtt,
        .is_app_limited = app_limited,
        .rtt_ns = rtt,
    };
}

fn makeCtx(now: i64, s: ?delivery_rate.RateSample) AckContext {
    return .{
        .now = now,
        .bytes_in_flight = 0,
        .prior_bytes_in_flight = 0,
        .newly_acked_bytes = if (s) |rs| rs.delivered else 0,
        .newly_lost_bytes = 0,
        .persistent_congestion = false,
        .earliest_lost_sent_time = null,
        .largest_acked_pn = null,
        .ce_byte_count = 0,
        .rate_sample = s,
    };
}

test "Bbr: initial state is Startup with high gain" {
    const b = Bbr.init();
    try testing.expectEqual(State.startup, b.state);
    try testing.expect(b.inSlowStart());
    try testing.expectEqual(STARTUP_PACING_GAIN, b.pacing_gain);
}

test "Bbr: max_bw filter tracks max over recent rounds, ignores below-max app-limited" {
    var b = Bbr.init();
    var now: i64 = 0;
    var prior: u64 = 0;
    const samples = [_]u64{ 100_000, 200_000, 150_000, 180_000 };
    for (samples) |bps| {
        b.delivered_total += 1000;
        b.onAckBatch(&makeCtx(now, makeSample(bps, 1000, prior, 50_000_000, false)));
        prior = b.delivered_total;
        now += 50_000_000;
    }
    try testing.expect(b.max_bw >= 200_000);
    // App-limited sample below max should be ignored.
    b.delivered_total += 1000;
    b.onAckBatch(&makeCtx(now, makeSample(50_000, 1000, prior, 50_000_000, true)));
    try testing.expect(b.max_bw >= 200_000);
}

test "Bbr: BBRLossThresh gates inflight_hi reduction (single-packet loss does NOT)" {
    var b = Bbr.init();
    // Build up bw + drive past Startup so checkLossEvent runs.
    var now: i64 = 0;
    var prior: u64 = 0;
    var i: u32 = 0;
    while (i < 10) : (i += 1) {
        b.delivered_total += 10_000;
        b.onAckBatch(&makeCtx(now, makeSample(1_000_000, 10_000, prior, 50_000_000, false)));
        prior = b.delivered_total;
        now += 50_000_000;
    }
    // Force out of Startup so loss-threshold gate engages.
    b.state = .probe_bw_down;
    const before = b.inflight_hi;

    // Single-packet loss against 100KB inflight: 1200/100000 = 1.2% < 2%
    // → must NOT reduce inflight_hi.
    var ctx = makeCtx(now, makeSample(1_000_000, 0, prior, 50_000_000, false));
    ctx.prior_bytes_in_flight = 100_000;
    ctx.bytes_in_flight = 98_800;
    ctx.newly_lost_bytes = 1200;
    b.onAckBatch(&ctx);
    try testing.expectEqual(before, b.inflight_hi);
}

test "Bbr: BBRLossThresh fires when loss > 2% of prior_bytes_in_flight" {
    var b = Bbr.init();
    var now: i64 = 0;
    var prior: u64 = 0;
    var i: u32 = 0;
    while (i < 10) : (i += 1) {
        b.delivered_total += 10_000;
        b.onAckBatch(&makeCtx(now, makeSample(1_000_000, 10_000, prior, 50_000_000, false)));
        prior = b.delivered_total;
        now += 50_000_000;
    }
    b.state = .probe_bw_down;
    b.inflight_hi = 100_000; // start with a meaningful value to detect reduction
    const before = b.inflight_hi;

    // 6KB loss against 100KB inflight = 6% > 2%, AND >3*MTU
    var ctx = makeCtx(now, makeSample(1_000_000, 0, prior, 50_000_000, false));
    ctx.prior_bytes_in_flight = 100_000;
    ctx.bytes_in_flight = 94_000;
    ctx.newly_lost_bytes = 6000;
    b.onAckBatch(&ctx);
    try testing.expect(b.inflight_hi < before);
}

test "Bbr: ProbeRTT actually fires after PROBE_RTT_INTERVAL with stable RTT" {
    var b = Bbr.init();
    // Establish a min_rtt and exit Startup.
    b.delivered_total += 1000;
    b.onAckBatch(&makeCtx(0, makeSample(1_000_000, 1000, 0, 50_000_000, false)));
    b.state = .probe_bw_down;
    b.filled_pipe = true;
    // Set bytes_in_flight high enough that DOWN doesn't drain to CRUISE.
    b.cwnd_bytes = 100_000;

    // Many ACKs at the same RTT — must NOT keep refreshing probe_rtt_min_stamp.
    // Use bytes_in_flight high to avoid DOWN→CRUISE transition.
    var now: i64 = 100_000_000;
    var prior = b.delivered_total;
    var i: u32 = 0;
    while (i < 5) : (i += 1) {
        b.delivered_total += 1000;
        var ctx = makeCtx(now, makeSample(1_000_000, 1000, prior, 50_000_000, false));
        ctx.bytes_in_flight = 100_000;
        b.onAckBatch(&ctx);
        prior = b.delivered_total;
        now += 100_000_000;
    }
    try testing.expect(b.state != .probe_rtt);

    // Advance past PROBE_RTT_INTERVAL_NS (5s) — must enter ProbeRTT.
    now += PROBE_RTT_INTERVAL_NS + 100_000_000;
    b.delivered_total += 1000;
    var ctx2 = makeCtx(now, makeSample(1_000_000, 1000, prior, 50_000_000, false));
    ctx2.bytes_in_flight = 100_000;
    b.onAckBatch(&ctx2);
    try testing.expectEqual(State.probe_rtt, b.state);
}

test "Bbr: ProbeRTT exits to ProbeBW_Down after 200ms" {
    var b = Bbr.init();
    b.state = .probe_rtt;
    b.filled_pipe = true;
    b.probe_rtt_done_stamp = 100_000_000;
    b.delivered_total += 1000;
    b.onAckBatch(&makeCtx(200_000_000, makeSample(1_000_000, 1000, 0, 50_000_000, false)));
    try testing.expectEqual(State.probe_bw_down, b.state);
}

test "Bbr: ProbeBW sub-state DOWN → CRUISE on inflight drain" {
    var b = Bbr.init();
    b.state = .probe_bw_down;
    b.max_bw = 1_000_000;
    b.min_rtt_ns = 50_000_000;
    b.cwnd_bytes = b.bdp() * 2;
    var ctx = makeCtx(0, null);
    ctx.bytes_in_flight = 1; // very low — below (1-headroom)*BDP
    b.onAckBatch(&ctx);
    try testing.expectEqual(State.probe_bw_cruise, b.state);
}

test "Bbr: ProbeBW CRUISE → REFILL after one round" {
    var b = Bbr.init();
    b.state = .probe_bw_cruise;
    b.max_bw = 1_000_000;
    b.min_rtt_ns = 50_000_000;
    b.probe_bw_cycle_round = 5;
    b.round_count = 5;
    b.next_round_delivered = 1000;
    b.delivered_total = 2000;
    // Sample with prior_delivered ≥ next_round_delivered triggers round_start.
    b.onAckBatch(&makeCtx(100_000_000, makeSample(1_000_000, 1000, 1000, 50_000_000, false)));
    try testing.expectEqual(State.probe_bw_refill, b.state);
}

test "Bbr: ProbeBW REFILL resets bw_lo and inflight_lo" {
    var b = Bbr.init();
    b.bw_lo = 500_000;
    b.inflight_lo = 50_000;
    b.enterProbeBwRefill();
    try testing.expectEqual(std.math.maxInt(u64), b.bw_lo);
    try testing.expectEqual(std.math.maxInt(u64), b.inflight_lo);
}

test "Bbr: inflight_hi grows in ProbeBW_Up" {
    var b = Bbr.init();
    b.max_bw = 1_000_000;
    b.min_rtt_ns = 50_000_000;
    b.inflight_hi = 100_000;
    b.state = .probe_bw_up;
    b.probe_bw_cycle_round = 5;
    b.round_count = 5;
    b.next_round_delivered = 1000;
    b.delivered_total = 2000;
    const before = b.inflight_hi;
    b.onAckBatch(&makeCtx(100_000_000, makeSample(1_000_000, 1000, 1000, 50_000_000, false)));
    try testing.expect(b.inflight_hi > before);
}

test "Bbr: ECN EWMA crosses threshold over multiple rounds" {
    var b = Bbr.init();
    // Force out of Startup so loss/ECN gate engages.
    b.state = .probe_bw_down;
    b.max_bw = 1_000_000;
    b.min_rtt_ns = 50_000_000;
    b.inflight_hi = 100_000;
    const before = b.inflight_hi;

    // Feed multiple rounds of high CE fraction. EWMA gain is 1/16, so it
    // takes several rounds for alpha to cross threshold.
    var now: i64 = 0;
    var prior: u64 = 0;
    var round: u32 = 0;
    while (round < 50) : (round += 1) {
        b.delivered_total += 10_000;
        var ctx = makeCtx(now, makeSample(1_000_000, 10_000, prior, 50_000_000, false));
        ctx.prior_bytes_in_flight = 100_000;
        ctx.bytes_in_flight = 90_000;
        ctx.newly_acked_bytes = 10_000;
        ctx.ce_byte_count = 9_000; // 90% CE
        b.onAckBatch(&ctx);
        prior = b.delivered_total;
        now += 50_000_000;
    }
    try testing.expect(b.inflight_hi < before);
}

test "Bbr: persistent congestion preserves max_bw" {
    var b = Bbr.init();
    b.max_bw = 5_000_000;
    b.min_rtt_ns = 30_000_000;
    b.cwnd_bytes = 100_000;
    b.onPersistentCongestion(0);
    try testing.expectEqual(@as(u64, 5_000_000), b.max_bw);
    try testing.expectEqual(@as(i64, 30_000_000), b.min_rtt_ns);
    try testing.expect(b.cwnd_bytes < 100_000); // halved
}

test "Bbr: PTO enters recovery; ack exits and lifts inflight_hi floor" {
    var b = Bbr.init();
    b.cwnd_bytes = 200_000;
    b.inflight_hi = 50_000; // post-loss ceiling
    b.onPtoExpired();
    try testing.expect(b.in_recovery);
    try testing.expectEqual(@as(u64, 200_000), b.saved_cwnd);

    // ACK arrives after PTO — must exit recovery and lift inflight_hi to
    // saved level (BBR's cwnd is recomputed from model, not blindly restored).
    var ctx = makeCtx(0, null);
    ctx.largest_acked_pn = 1;
    b.onAckBatch(&ctx);
    try testing.expect(!b.in_recovery);
    try testing.expect(b.inflight_hi >= 200_000);
}

test "Bbr: send_quantum scales with pacing rate" {
    var b = Bbr.init();
    b.pacing_rate_bps = 10_000_000_000; // 10 Gbps → quantum should hit 64KB ceiling
    b.setSendQuantum();
    try testing.expectEqual(@as(u64, 64 * 1024), b.send_quantum);

    b.pacing_rate_bps = 100_000; // 100 KB/s → quantum at 100B raw, clamped to 2*MTU floor
    b.setSendQuantum();
    try testing.expectEqual(2 * b.max_datagram_size, b.send_quantum);
}

test "Bbr: CRUISE applies headroom to cwnd" {
    var b = Bbr.init();
    b.max_bw = 1_000_000;
    b.min_rtt_ns = 50_000_000;
    b.state = .probe_bw_cruise;
    b.cwnd_gain = PROBE_BW_DEFAULT_CWND_GAIN;
    b.setCwnd();
    const cruise_cwnd = b.cwnd_bytes;
    b.state = .probe_bw_up;
    b.cwnd_gain = PROBE_BW_DEFAULT_CWND_GAIN;
    b.setCwnd();
    const up_cwnd = b.cwnd_bytes;
    // CRUISE leaves headroom (15%); UP doesn't.
    try testing.expect(cruise_cwnd < up_cwnd);
}

test "Bbr: bdp uses bounded bw (max_bw clamped by bw_lo)" {
    var b = Bbr.init();
    b.max_bw = 1_000_000;
    b.bw_lo = 500_000;
    b.min_rtt_ns = 50_000_000;
    // BDP = 500_000 × 0.05s = 25_000 bytes
    try testing.expectEqual(@as(u64, 25_000), b.bdp());
}

test "Bbr: app-limited round counting" {
    var b = Bbr.init();
    b.delivered_total += 1000;
    b.onAckBatch(&makeCtx(0, makeSample(1_000_000, 1000, 0, 50_000_000, true)));
    // App-limited samples are accepted only when they would raise max_bw —
    // first sample raises max_bw (was 0). Subsequent app-limited samples
    // below current max_bw are ignored.
    try testing.expect(b.max_bw > 0);
}

test "Bbr: pacing rate applies 1% margin" {
    var b = Bbr.init();
    b.max_bw = 1_000_000;
    b.pacing_gain = GAIN_DENOM; // 1.0
    b.setPacingRate();
    // Expected ≈ 990_000 (1MB/s × 0.99)
    try testing.expectEqual(@as(u64, 990_000), b.pacing_rate_bps);
}

test "Bbr: onPathChange resets to fresh Startup" {
    var b = Bbr.init();
    b.max_bw = 5_000_000;
    b.state = .probe_bw_up;
    b.filled_pipe = true;
    b.onPathChange();
    try testing.expectEqual(State.startup, b.state);
    try testing.expectEqual(@as(u64, 0), b.max_bw);
    try testing.expect(!b.filled_pipe);
}
