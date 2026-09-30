const std = @import("std");
const testing = std.testing;

const rtt_mod = @import("rtt.zig");
const RttStats = rtt_mod.RttStats;

/// Fraction of the receive window that triggers a window update.
/// When the consumed portion exceeds this fraction, send a window update.
const WINDOW_UPDATE_FRACTION: u64 = 4; // 1/4

/// Maximum auto-tuning window size (default 6MB).
const MAX_RECEIVE_WINDOW: u64 = 6 * 1024 * 1024;

/// Base flow controller shared by both stream and connection level.
pub const BaseFlowController = struct {
    // Send-side state
    bytes_sent: u64 = 0,
    send_window: u64 = 0,
    // Track the limit at which we last sent a blocked frame (avoid duplicates)
    blocked_at: ?u64 = null,

    // Receive-side state
    bytes_read: u64 = 0,
    highest_received: u64 = 0,
    receive_window: u64,
    receive_window_size: u64,
    max_receive_window_size: u64,

    // Auto-tuning state
    epoch_start_time: i64 = 0,
    epoch_start_offset: u64 = 0,

    pub fn init(receive_window: u64, max_receive_window: u64) BaseFlowController {
        return .{
            .receive_window = receive_window,
            .receive_window_size = receive_window,
            .max_receive_window_size = @max(max_receive_window, receive_window),
        };
    }

    /// Update the send window (from MAX_DATA or MAX_STREAM_DATA).
    pub fn updateSendWindow(self: *BaseFlowController, new_window: u64) void {
        if (new_window > self.send_window) {
            self.send_window = new_window;
            // Clear blocked_at so we can send a new blocked frame if we hit the new limit
            self.blocked_at = null;
        }
    }

    /// Returns the number of bytes available to send.
    pub fn sendWindowSize(self: *const BaseFlowController) u64 {
        if (self.bytes_sent >= self.send_window) return 0;
        return self.send_window - self.bytes_sent;
    }

    /// Record bytes being sent.
    pub fn addBytesSent(self: *BaseFlowController, n: u64) void {
        self.bytes_sent += n;
    }

    /// Check if sending is blocked.
    pub fn isBlocked(self: *const BaseFlowController) bool {
        return self.bytes_sent >= self.send_window;
    }

    // Check if we should send a BLOCKED frame and mark it as sent.
    // Returns the limit if a blocked frame should be sent, null otherwise.
    // BLOCKED frames are advisory. Emitting once per blocked limit avoids
    // packet storms while still re-arming when the peer raises credit.
    pub fn shouldSendBlocked(self: *BaseFlowController) ?u64 {
        if (self.bytes_sent >= self.send_window and self.blocked_at != self.send_window) {
            self.blocked_at = self.send_window;
            return self.send_window;
        }
        return null;
    }

    /// Record bytes received from the peer.
    pub fn addBytesReceived(self: *BaseFlowController, offset: u64) !void {
        if (offset > self.receive_window) {
            return error.FlowControlError;
        }
        if (offset > self.highest_received) {
            self.highest_received = offset;
        }
    }

    /// Record bytes consumed by the application.
    pub fn addBytesRead(self: *BaseFlowController, n: u64) void {
        self.bytes_read += n;
    }

    /// Check if we should send a window update to the peer.
    /// Returns the new window offset if an update should be sent, or null.
    pub fn getWindowUpdate(self: *BaseFlowController, rtt_stats: *const RttStats) ?u64 {
        const consumed = self.bytes_read;
        const window_end = self.receive_window;

        // Don't update until we've consumed a significant portion
        if (consumed + self.receive_window_size / WINDOW_UPDATE_FRACTION > window_end) {
            // Auto-tune the window size
            self.maybeAdjustWindowSize(rtt_stats);

            // Calculate new window
            const new_window = consumed + self.receive_window_size;
            if (new_window > self.receive_window) {
                self.receive_window = new_window;
                return new_window;
            }
        }
        return null;
    }

    /// Auto-tune the receive window based on throughput and RTT.
    fn maybeAdjustWindowSize(self: *BaseFlowController, rtt_stats: *const RttStats) void {
        if (!rtt_stats.has_measurement) return;

        const bytes_consumed = self.bytes_read - self.epoch_start_offset;
        if (bytes_consumed == 0) return;

        // Check if we're consuming data fast enough to justify a larger window
        // If consumption exceeds window_size / (4 * RTT) within the epoch,
        // double the window.
        const srtt = rtt_stats.smoothedRttOrDefault();
        if (srtt <= 0) return;

        // Threshold: if consumed > window_size * fraction / (4 * RTT) * RTT
        // Simplified: if consumed > window_size / 4
        if (bytes_consumed > self.receive_window_size / WINDOW_UPDATE_FRACTION) {
            self.receive_window_size = @min(
                self.receive_window_size * 2,
                self.max_receive_window_size,
            );
        }

        // Reset epoch
        self.epoch_start_offset = self.bytes_read;
    }
};

/// Connection-level flow controller.
pub const ConnectionFlowController = struct {
    base: BaseFlowController,

    pub fn init(receive_window: u64, max_receive_window: u64) ConnectionFlowController {
        return .{
            .base = BaseFlowController.init(receive_window, max_receive_window),
        };
    }

    pub fn updateSendWindow(self: *ConnectionFlowController, new_window: u64) void {
        self.base.updateSendWindow(new_window);
    }

    pub fn sendWindowSize(self: *const ConnectionFlowController) u64 {
        return self.base.sendWindowSize();
    }

    pub fn addBytesRead(self: *ConnectionFlowController, n: u64) void {
        self.base.addBytesRead(n);
    }

    pub fn getWindowUpdate(self: *ConnectionFlowController, rtt_stats: *const RttStats) ?u64 {
        return self.base.getWindowUpdate(rtt_stats);
    }

    pub fn isBlocked(self: *const ConnectionFlowController) bool {
        return self.base.isBlocked();
    }
};

// Tests

test "BaseFlowController: send window" {
    var fc = BaseFlowController.init(1000, MAX_RECEIVE_WINDOW);
    fc.send_window = 5000;

    try testing.expectEqual(@as(u64, 5000), fc.sendWindowSize());
    try testing.expect(!fc.isBlocked());

    fc.addBytesSent(3000);
    try testing.expectEqual(@as(u64, 2000), fc.sendWindowSize());

    fc.addBytesSent(2000);
    try testing.expect(fc.isBlocked());
    try testing.expectEqual(@as(u64, 0), fc.sendWindowSize());
}

test "BaseFlowController: receive window" {
    var fc = BaseFlowController.init(1000, MAX_RECEIVE_WINDOW);

    // Should accept data within window
    try fc.addBytesReceived(500);
    try fc.addBytesReceived(1000);

    // Should reject data outside window
    try testing.expectError(error.FlowControlError, fc.addBytesReceived(1001));
}

test "BaseFlowController: window update" {
    var fc = BaseFlowController.init(1000, MAX_RECEIVE_WINDOW);
    var rtt = RttStats{};
    rtt.updateRtt(50_000_000, 0, false); // 50ms

    try fc.addBytesReceived(1000);

    // Read enough to trigger update (> 1/4 of window)
    fc.addBytesRead(800);
    const update = fc.getWindowUpdate(&rtt);
    try testing.expect(update != null);
    try testing.expect(update.? > 1000);
}

test "ConnectionFlowController: basic" {
    var cfc = ConnectionFlowController.init(10000, MAX_RECEIVE_WINDOW);
    cfc.updateSendWindow(50000);

    try testing.expectEqual(@as(u64, 50000), cfc.sendWindowSize());
    try testing.expect(!cfc.isBlocked());
}

test "BaseFlowController: shouldSendBlocked emits once per blocked limit" {
    var fc = BaseFlowController.init(1000, MAX_RECEIVE_WINDOW);
    fc.send_window = 100;
    fc.addBytesSent(100);

    // First call should return the limit
    try testing.expectEqual(@as(?u64, 100), fc.shouldSendBlocked());
    // Repeated calls at the same blocked limit should not generate a packet storm.
    try testing.expectEqual(@as(?u64, null), fc.shouldSendBlocked());

    // After window update, should be able to send again
    fc.updateSendWindow(200);
    try testing.expect(!fc.isBlocked());
    fc.addBytesSent(100);
    try testing.expectEqual(@as(?u64, 200), fc.shouldSendBlocked());
}

test "BaseFlowController: updateSendWindow ignores smaller values" {
    var fc = BaseFlowController.init(1000, MAX_RECEIVE_WINDOW);
    fc.send_window = 5000;

    // Smaller window should be ignored
    fc.updateSendWindow(3000);
    try testing.expectEqual(@as(u64, 5000), fc.send_window);

    // Larger window should be accepted
    fc.updateSendWindow(8000);
    try testing.expectEqual(@as(u64, 8000), fc.send_window);
}

test "BaseFlowController: auto-tuning doubles window" {
    var fc = BaseFlowController.init(1000, MAX_RECEIVE_WINDOW);
    var rtt = RttStats{};
    rtt.updateRtt(50_000_000, 0, false);

    try fc.addBytesReceived(1000);
    // Read more than 1/4 of window to trigger auto-tuning
    fc.addBytesRead(800);
    _ = fc.getWindowUpdate(&rtt);

    // Window size should have doubled (up to max)
    try testing.expectEqual(@as(u64, 2000), fc.receive_window_size);
}
