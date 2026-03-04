const std = @import("std");
const testing = std.testing;

/// ECN validation state machine (RFC 9000 §13.4.2.1).
///
/// Tracks whether the network path supports ECN by monitoring
/// peer-reported ECN counts in ACK_ECN frames against what we sent.
pub const EcnValidator = struct {
    state: State = .disabled,
    sent_ect0_count: u64 = 0,
    acked_ect0_count: u64 = 0,
    testing_count: u8 = 0,

    const TESTING_THRESHOLD: u8 = 10;

    pub const State = enum {
        disabled,
        testing,
        unknown,
        capable,
        failed,
    };

    /// Begin ECN validation (called after handshake confirmed).
    pub fn start(self: *EcnValidator) void {
        if (self.state == .disabled) {
            self.state = .testing;
            self.testing_count = 0;
            self.sent_ect0_count = 0;
            self.acked_ect0_count = 0;
        }
    }

    /// Called for each ack-eliciting packet sent with ECT(0) marking.
    pub fn onPacketSent(self: *EcnValidator) void {
        self.sent_ect0_count += 1;
        if (self.state == .testing) {
            self.testing_count += 1;
            if (self.testing_count >= TESTING_THRESHOLD) {
                self.state = .unknown;
            }
        }
    }

    /// Whether outgoing packets should be marked ECT(0).
    pub fn shouldMark(self: *const EcnValidator) bool {
        return switch (self.state) {
            .testing, .unknown, .capable => true,
            .disabled, .failed => false,
        };
    }

    /// Validate peer's ECN counts from an ACK_ECN frame.
    /// Returns true if valid; transitions to .failed on invalid.
    ///
    /// peer_ect0/ect1/ce: newly reported counts from ACK_ECN
    /// prev_ect0/ect1/prev_ce: previously stored counts for this PN space
    /// newly_acked_ect0: number of ECT(0)-marked packets acknowledged in this ACK
    pub fn validate(
        self: *EcnValidator,
        peer_ect0: u64,
        peer_ect1: u64,
        peer_ce: u64,
        prev_ect0: u64,
        prev_ect1: u64,
        prev_ce: u64,
        newly_acked_ect0: u64,
    ) bool {
        if (self.state == .disabled or self.state == .failed) return false;

        const ect0_delta = peer_ect0 -| prev_ect0;
        const ce_delta = peer_ce -| prev_ce;
        const ect1_delta = peer_ect1 -| prev_ect1;

        // ECT(1) must not increase — we never send ECT(1)
        if (ect1_delta > 0) {
            std.log.debug("ECN validation failed: ECT(1) increased by {d}", .{ect1_delta});
            self.state = .failed;
            return false;
        }

        // The sum of ECT(0) and CE increases must account for newly-acked ECT(0) packets
        if (newly_acked_ect0 > 0 and ect0_delta + ce_delta < newly_acked_ect0) {
            std.log.debug("ECN validation failed: ect0_delta({d})+ce_delta({d}) < newly_acked({d})", .{
                ect0_delta, ce_delta, newly_acked_ect0,
            });
            self.state = .failed;
            return false;
        }

        // Valid — transition unknown→capable
        if (self.state == .unknown and ect0_delta + ce_delta > 0) {
            self.state = .capable;
            std.log.info("ECN validation: path is ECN-capable", .{});
        }

        self.acked_ect0_count += newly_acked_ect0;
        return true;
    }

    /// Reset to disabled (called on path migration with IP change).
    pub fn reset(self: *EcnValidator) void {
        self.* = .{};
    }
};

// Tests

test "start transitions disabled→testing" {
    var v = EcnValidator{};
    try testing.expectEqual(EcnValidator.State.disabled, v.state);
    v.start();
    try testing.expectEqual(EcnValidator.State.testing, v.state);
}

test "after 10 packets, testing→unknown" {
    var v = EcnValidator{};
    v.start();
    var i: u8 = 0;
    while (i < 9) : (i += 1) {
        v.onPacketSent();
        try testing.expectEqual(EcnValidator.State.testing, v.state);
    }
    v.onPacketSent(); // 10th
    try testing.expectEqual(EcnValidator.State.unknown, v.state);
}

test "valid ACK_ECN: unknown→capable" {
    var v = EcnValidator{};
    v.start();
    // Send 10 packets to reach unknown
    var i: u8 = 0;
    while (i < 10) : (i += 1) v.onPacketSent();
    try testing.expectEqual(EcnValidator.State.unknown, v.state);

    // Peer reports 10 ECT(0), 0 ECT(1), 0 CE (prev all 0)
    const valid = v.validate(10, 0, 0, 0, 0, 0, 10);
    try testing.expect(valid);
    try testing.expectEqual(EcnValidator.State.capable, v.state);
}

test "invalid ACK_ECN (ect1 increase): →failed" {
    var v = EcnValidator{};
    v.start();
    var i: u8 = 0;
    while (i < 10) : (i += 1) v.onPacketSent();

    // Peer reports ECT(1) increase — invalid since we never send ECT(1)
    const valid = v.validate(5, 3, 0, 0, 0, 0, 5);
    try testing.expect(!valid);
    try testing.expectEqual(EcnValidator.State.failed, v.state);
}

test "shouldMark returns false when failed/disabled" {
    var v = EcnValidator{};
    try testing.expect(!v.shouldMark()); // disabled

    v.start();
    try testing.expect(v.shouldMark()); // testing

    v.state = .failed;
    try testing.expect(!v.shouldMark()); // failed
}

test "reset returns to disabled" {
    var v = EcnValidator{};
    v.start();
    var i: u8 = 0;
    while (i < 10) : (i += 1) v.onPacketSent();
    _ = v.validate(10, 0, 0, 0, 0, 0, 10);
    try testing.expectEqual(EcnValidator.State.capable, v.state);

    v.reset();
    try testing.expectEqual(EcnValidator.State.disabled, v.state);
    try testing.expectEqual(@as(u64, 0), v.sent_ect0_count);
}

test "validate: ect0+ce delta too small → failed" {
    var v = EcnValidator{};
    v.start();
    var i: u8 = 0;
    while (i < 10) : (i += 1) v.onPacketSent();

    // Sent 10 ECT(0) packets but peer only reports 3
    const valid = v.validate(3, 0, 0, 0, 0, 0, 10);
    try testing.expect(!valid);
    try testing.expectEqual(EcnValidator.State.failed, v.state);
}
