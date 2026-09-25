//! The libxev backend every loop in the library runs on, and the helpers the
//! QUIC server and the HTTP/1.1 listener share for taking their socket
//! watches off a loop they don't own.

const builtin = @import("builtin");
const xev_mod = @import("xev");

// Default backend: epoll on Linux, kqueue on macOS.
// io_uring init fails in some containers used by the interop runner.
pub const xev = if (builtin.os.tag == .linux) xev_mod.Epoll else xev_mod;

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
