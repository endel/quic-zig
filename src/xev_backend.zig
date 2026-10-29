//! The libxev backend every loop in the library runs on, and the helpers the
//! QUIC server and the HTTP/1.1 listener share for taking their socket
//! watches off a loop they don't own.

const std = @import("std");
const builtin = @import("builtin");
const xev_mod = @import("xev");

// Default backend: epoll on Linux, kqueue on macOS.
// io_uring init fails in some containers used by the interop runner.
pub const xev = if (builtin.target.os.tag == .linux) xev_mod.Epoll else xev_mod;

/// What a socket watch returns once its server has halted, with a cancel for
/// it queued. Epoll's cancel removes the fd unconditionally and panics if it
/// is already gone, so the watch must stay for it. Kqueue's cancel is a no-op
/// for a watch whose event already fired, so that watch must leave by itself.
pub const halted_poll_action: xev.CallbackAction = if (xev.backend == .epoll) .rearm else .disarm;

/// Kqueue's cancel skips a watch whose result is set, taking it to be queued
/// for its callback. Only the callback clears it, so a watch registered on an
/// already-readable socket would otherwise outlive the cancel in `stop()`.
/// Safe here: the loop has already handed the result to the callback.
pub fn forgetPollResult(c: *xev.Completion) void {
    if (comptime @hasField(xev.Completion, "result")) c.result = null;
}

/// Queue the removal of `target` from `loop`, unless it is already off it.
pub fn cancelCompletion(loop: *xev.Loop, target: *xev.Completion, c: *xev.Completion) void {
    if (target.state() == .dead) return;
    c.* = .{ .op = .{ .cancel = .{ .c = target } } };
    loop.add(c);
}

// Running a loop from a host's own (Node's libuv, in netcode-io): watch
// `pollFd`, tick without waiting when it turns readable, and tick again
// after `nextTimerMs`, or at once while `hasQueued`.

/// The fd another event loop can watch for this one: readable while the
/// loop has kernel events to collect.
pub fn pollFd(loop: *const xev.Loop) std.posix.fd_t {
    return switch (xev.backend) {
        .epoll => loop.fd,
        .kqueue => loop.kqueue_fd,
        else => @compileError("no fd to watch on this backend"),
    };
}

/// Whether the loop holds work for its next tick that `pollFd` won't
/// announce: completions added but not yet given to the kernel, and on
/// kqueue, results waiting for their callbacks.
pub fn hasQueued(loop: *const xev.Loop) bool {
    if (!loop.submissions.empty()) return true;
    return if (comptime @hasField(xev.Loop, "completions")) !loop.completions.empty() else false;
}

/// Milliseconds to the loop's earliest timer, rounded up; null without one.
/// A timer added since the last tick isn't on it yet: `hasQueued` is true.
pub fn nextTimerMs(loop: *xev.Loop) ?u64 {
    const t = loop.timers.peek() orelse return null;
    loop.update_now();
    const now = loop.cached_now;
    const ns = (@as(i128, t.next.sec) - now.sec) * std.time.ns_per_s + (t.next.nsec - now.nsec);
    if (ns <= 0) return 0;
    return @intCast(@divFloor(ns - 1, std.time.ns_per_ms) + 1);
}

const testing = std.testing;

fn readable(fd: std.posix.fd_t) bool {
    var fds = [_]std.c.pollfd{.{ .fd = fd, .events = std.c.POLL.IN, .revents = 0 }};
    return std.c.poll(&fds, 1, 0) == 1 and fds[0].revents & std.c.POLL.IN != 0;
}

test "a timer is queued until the loop ticks, then nextTimerMs counts down to it" {
    var loop = try xev.Loop.init(.{});
    defer loop.deinit();
    try testing.expect(nextTimerMs(&loop) == null);
    try testing.expect(!hasQueued(&loop));

    var timer = try xev.Timer.init();
    defer timer.deinit();
    var c: xev.Completion = .{};
    var fired = false;
    timer.run(&loop, &c, 50, bool, &fired, struct {
        fn cb(ud: ?*bool, _: *xev.Loop, _: *xev.Completion, _: xev.Timer.RunError!void) xev.CallbackAction {
            ud.?.* = true;
            return .disarm;
        }
    }.cb);
    try testing.expect(hasQueued(&loop));
    try testing.expect(nextTimerMs(&loop) == null);

    try loop.run(.no_wait);
    try testing.expect(!hasQueued(&loop));
    const ms = nextTimerMs(&loop).?;
    try testing.expect(ms > 0 and ms <= 50);

    try loop.run(.until_done);
    try testing.expect(fired);
    try testing.expect(nextTimerMs(&loop) == null);
}

test "pollFd is readable while the loop has an event to collect" {
    var loop = try xev.Loop.init(.{});
    defer loop.deinit();
    var wake = try xev.Async.init();
    defer wake.deinit();
    var c: xev.Completion = .{};
    var woken = false;
    wake.wait(&loop, &c, bool, &woken, struct {
        fn cb(ud: ?*bool, _: *xev.Loop, _: *xev.Completion, r: xev.Async.WaitError!void) xev.CallbackAction {
            _ = r catch unreachable;
            ud.?.* = true;
            return .disarm;
        }
    }.cb);
    try loop.run(.no_wait);
    try testing.expect(!readable(pollFd(&loop)));

    try wake.notify();
    try testing.expect(readable(pollFd(&loop)));
    try loop.run(.no_wait);
    try testing.expect(woken);
    try testing.expect(!readable(pollFd(&loop)));
}
