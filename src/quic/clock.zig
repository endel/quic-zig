const std = @import("std");
const builtin = @import("builtin");

/// Read `CLOCK_MONOTONIC` in nanoseconds.
///
/// The Pacer uses this clock so its `last_sent_time` deltas are immune to
/// wall-clock jumps (NTP slews, daylight-saving, manual clock changes). Loss
/// detection, PTO, and idle-timeout code paths continue to use
/// `std.time.nanoTimestamp()` (REALTIME) — those only compare timestamps to
/// each other within short horizons where the gap matters but the absolute
/// drift does not.
pub fn monoNanos() i64 {
    // On Windows there is no POSIX CLOCK_MONOTONIC; fall back to the default
    // `nanoTimestamp()` so the pacer still works.
    if (comptime builtin.os.tag == .windows) {
        return @intCast(std.time.nanoTimestamp());
    }
    const ts = std.posix.clock_gettime(.MONOTONIC) catch {
        return @intCast(std.time.nanoTimestamp());
    };
    return @as(i64, ts.sec) * std.time.ns_per_s + @as(i64, ts.nsec);
}

test "monoNanos is non-decreasing" {
    const a = monoNanos();
    const b = monoNanos();
    try std.testing.expect(b >= a);
}
