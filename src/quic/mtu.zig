const std = @import("std");
const testing = std.testing;

/// QUIC minimum datagram size — always works (RFC 9000 Section 14).
pub const BASE_PLPMTU: u16 = 1200;

/// Maximum PLPMTU to probe for (IPv6 over Ethernet: 1500 - 40 - 8 = 1452).
pub const MAX_PLPMTU: u16 = 1452;

/// Binary search termination threshold (bytes).
const MTU_SEARCH_STEP: u16 = 20;

/// Maximum consecutive failed probes before giving up on a size.
const MAX_PROBES: u8 = 3;

/// Multiplier for probe interval (5 × smoothed RTT).
const PROBE_DELAY_MULTIPLIER: i64 = 5;

/// Minimum probe interval (200ms in nanoseconds) to avoid probing too fast.
const MIN_PROBE_INTERVAL: i64 = 200_000_000;

/// Timer for re-probing after search completes (600 seconds = 10 minutes).
const RAISE_TIMER_NS: i64 = 600_000_000_000;

pub const MtuState = enum {
    /// Search not started yet (waiting for handshake).
    disabled,
    /// Actively probing for larger MTU via binary search.
    searching,
    /// Search converged; current PLPMTU is the best we found.
    search_complete,
};

/// Datagram Packetization Layer PMTU Discovery (DPLPMTUD) for QUIC.
///
/// After handshake completion, performs a binary search between BASE_PLPMTU
/// and MAX_PLPMTU to discover the largest packet size the path supports.
/// Probes are PING+PADDING packets; ACK confirms success, loss narrows range.
pub const MtuDiscoverer = struct {
    state: MtuState = .disabled,

    /// Current confirmed PLPMTU (largest size that was ACK'd).
    current_mtu: u16 = BASE_PLPMTU,

    /// Lower bound for binary search (last confirmed good size).
    search_min: u16 = BASE_PLPMTU,

    /// Upper bound for binary search.
    search_max: u16 = MAX_PLPMTU,

    /// Packet number of the last MTU probe sent (null if none outstanding).
    probe_pn: ?u64 = null,

    /// Size of the last probe sent.
    probe_size: u16 = 0,

    /// Number of consecutive failed probes at current probe_size.
    probe_count: u8 = 0,

    /// Time when the last probe was sent (nanoseconds).
    last_probe_time: i64 = 0,

    /// Time when search completed (for raise timer).
    search_complete_time: i64 = 0,

    /// Start MTU discovery (called after handshake completes).
    pub fn start(self: *MtuDiscoverer) void {
        if (self.state != .disabled) return;
        self.state = .searching;
        self.search_min = BASE_PLPMTU;
        self.search_max = MAX_PLPMTU;
        self.probe_count = 0;
    }

    /// Check if it's time to send a probe.
    pub fn shouldProbe(self: *const MtuDiscoverer, now: i64, smoothed_rtt: i64) bool {
        if (self.state != .searching) return false;
        // Don't probe if we have one outstanding
        if (self.probe_pn != null) return false;

        if (self.last_probe_time == 0) return true;

        const interval = @max(smoothed_rtt * PROBE_DELAY_MULTIPLIER, MIN_PROBE_INTERVAL);
        return (now - self.last_probe_time) >= interval;
    }

    /// Get the next probe size (binary search midpoint).
    pub fn nextProbeSize(self: *const MtuDiscoverer) u16 {
        return self.search_min + (self.search_max - self.search_min) / 2;
    }

    /// Record that a probe was sent.
    pub fn onProbeSent(self: *MtuDiscoverer, pn: u64, size: u16, now: i64) void {
        self.probe_pn = pn;
        self.probe_size = size;
        self.last_probe_time = now;
    }

    /// Called when the probe packet was ACK'd — the probed size works.
    pub fn onProbeAcked(self: *MtuDiscoverer, pn: u64, now: i64) bool {
        if (self.probe_pn == null or self.probe_pn.? != pn) return false;
        if (self.state != .searching) return false;

        // Confirmed: this size works
        self.current_mtu = self.probe_size;
        self.search_min = self.probe_size;
        self.probe_pn = null;
        self.probe_count = 0;

        // Check if search is done
        if (self.search_max - self.search_min <= MTU_SEARCH_STEP or
            self.current_mtu >= MAX_PLPMTU)
        {
            self.state = .search_complete;
            self.search_complete_time = now;
        }

        return true;
    }

    /// Called when the probe packet was declared lost — the probed size may not work.
    pub fn onProbeLost(self: *MtuDiscoverer, pn: u64, now: i64) bool {
        if (self.probe_pn == null or self.probe_pn.? != pn) return false;
        if (self.state != .searching) return false;

        self.probe_pn = null;
        self.probe_count += 1;

        if (self.probe_count >= MAX_PROBES) {
            // This size doesn't work — narrow the upper bound
            self.search_max = self.probe_size;
            self.probe_count = 0;

            // Check if search is done
            if (self.search_max - self.search_min <= MTU_SEARCH_STEP) {
                self.state = .search_complete;
                self.search_complete_time = now;
            }
        }

        return true;
    }

    /// Check if the raise timer has expired (re-probe after search_complete).
    pub fn checkRaiseTimer(self: *MtuDiscoverer, now: i64) void {
        if (self.state != .search_complete) return;
        if (now - self.search_complete_time >= RAISE_TIMER_NS) {
            // Re-enter searching to see if path MTU has increased
            self.state = .searching;
            self.search_max = MAX_PLPMTU;
            self.probe_count = 0;
        }
    }

    /// Reset to base (e.g., on connection migration with IP change).
    pub fn reset(self: *MtuDiscoverer) void {
        self.current_mtu = BASE_PLPMTU;
        self.search_min = BASE_PLPMTU;
        self.search_max = MAX_PLPMTU;
        self.probe_pn = null;
        self.probe_count = 0;
        self.state = .searching;
    }
};

// Tests

test "MtuDiscoverer: initial state" {
    const d = MtuDiscoverer{};
    try testing.expectEqual(MtuState.disabled, d.state);
    try testing.expectEqual(BASE_PLPMTU, d.current_mtu);
}

test "MtuDiscoverer: start begins searching" {
    var d = MtuDiscoverer{};
    d.start();
    try testing.expectEqual(MtuState.searching, d.state);
}

test "MtuDiscoverer: binary search midpoint" {
    var d = MtuDiscoverer{};
    d.start();
    // Midpoint of 1200..1452 = 1200 + (1452-1200)/2 = 1200 + 126 = 1326
    try testing.expectEqual(@as(u16, 1326), d.nextProbeSize());
}

test "MtuDiscoverer: probe ACK raises min and MTU" {
    var d = MtuDiscoverer{};
    d.start();

    const probe_size = d.nextProbeSize();
    d.onProbeSent(42, probe_size, 1000);
    try testing.expect(d.shouldProbe(2000, 100) == false); // outstanding probe

    const changed = d.onProbeAcked(42, 2000);
    try testing.expect(changed);
    try testing.expectEqual(probe_size, d.current_mtu);
    try testing.expectEqual(probe_size, d.search_min);
    try testing.expect(d.probe_pn == null);
}

test "MtuDiscoverer: probe loss narrows after MAX_PROBES" {
    var d = MtuDiscoverer{};
    d.start();

    const probe_size = d.nextProbeSize();
    var now: i64 = 1000;

    // Fail MAX_PROBES times
    var i: u8 = 0;
    while (i < MAX_PROBES) : (i += 1) {
        d.onProbeSent(i, probe_size, now);
        _ = d.onProbeLost(i, now);
        now += 1000;
    }

    // search_max should now be narrowed
    try testing.expectEqual(probe_size, d.search_max);
    try testing.expectEqual(BASE_PLPMTU, d.search_min);
}

test "MtuDiscoverer: converges to search_complete" {
    var d = MtuDiscoverer{};
    d.start();

    var pn: u64 = 0;
    var now: i64 = 1000;
    var iterations: usize = 0;

    while (d.state == .searching and iterations < 20) : (iterations += 1) {
        const size = d.nextProbeSize();
        d.onProbeSent(pn, size, now);
        // Simulate ACK for sizes <= 1400, loss for > 1400
        if (size <= 1400) {
            _ = d.onProbeAcked(pn, now + 100);
        } else {
            _ = d.onProbeLost(pn, now + 100);
            // Need MAX_PROBES failures to narrow
            var retry: u8 = 1;
            while (retry < MAX_PROBES and d.state == .searching) : (retry += 1) {
                pn += 1;
                d.onProbeSent(pn, size, now);
                _ = d.onProbeLost(pn, now + 100);
            }
        }
        pn += 1;
        now += 1000;
    }

    try testing.expectEqual(MtuState.search_complete, d.state);
    try testing.expect(d.current_mtu >= BASE_PLPMTU);
    try testing.expect(d.current_mtu <= 1400);
}

test "MtuDiscoverer: raise timer re-enters searching" {
    var d = MtuDiscoverer{};
    d.start();

    // Force to search_complete
    d.state = .search_complete;
    d.search_complete_time = 1000;
    d.current_mtu = 1400;

    // Not expired yet
    d.checkRaiseTimer(1000 + RAISE_TIMER_NS - 1);
    try testing.expectEqual(MtuState.search_complete, d.state);

    // Expired
    d.checkRaiseTimer(1000 + RAISE_TIMER_NS);
    try testing.expectEqual(MtuState.searching, d.state);
}

test "MtuDiscoverer: reset returns to base" {
    var d = MtuDiscoverer{};
    d.start();
    d.current_mtu = 1400;
    d.search_min = 1400;

    d.reset();
    try testing.expectEqual(BASE_PLPMTU, d.current_mtu);
    try testing.expectEqual(BASE_PLPMTU, d.search_min);
    try testing.expectEqual(MtuState.searching, d.state);
}

test "MtuDiscoverer: wrong PN ignored" {
    var d = MtuDiscoverer{};
    d.start();
    d.onProbeSent(10, 1326, 1000);

    try testing.expect(!d.onProbeAcked(99, 2000)); // wrong PN
    try testing.expect(d.probe_pn != null); // still outstanding
}

test "MtuDiscoverer: shouldProbe timing" {
    var d = MtuDiscoverer{};
    d.start();

    // First probe: always allowed
    try testing.expect(d.shouldProbe(1000, 50_000_000));

    d.onProbeSent(0, 1326, 1000);
    _ = d.onProbeAcked(0, 2000);

    // Too soon (5 × 50ms = 250ms, MIN_PROBE_INTERVAL = 200ms)
    try testing.expect(!d.shouldProbe(2000 + 100_000_000, 50_000_000));

    // After 250ms
    try testing.expect(d.shouldProbe(2000 + 250_000_001, 50_000_000));
}
