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
    _ = cancelCompletionThen(loop, target, c, null, xev.noopCallback);
}

/// `cancelCompletion`, calling `callback` once the cancel is done. Whether
/// one was queued.
///
/// A cancelled completion isn't always called back: one added this tick is
/// dropped before it reaches the kernel, and epoll drops an active one too.
/// Whatever tracks `target` with a flag its callback clears must look at
/// `target.state()` from `callback` as well.
pub fn cancelCompletionThen(loop: *xev.Loop, target: *xev.Completion, c: *xev.Completion, userdata: ?*anyopaque, callback: xev.Callback) bool {
    if (target.state() == .dead) return false;
    c.* = .{ .op = .{ .cancel = .{ .c = target } }, .userdata = userdata, .callback = callback };
    loop.add(c);
    return true;
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

/// `pollFd` for a backend with no fd: a completion port can't be polled, so
/// a thread waits on it instead, calls `wake`, and waits for `rearm`: one
/// call per tick, however many packets the tick takes.
///
/// A completion port is signaled while it holds packets, and a wait on it
/// takes none: they stay where they are, in the order they came, for the
/// loop to collect. Windows doesn't document that; `start` fails where the
/// port can't be waited on. (Taking a packet and posting it back, as
/// Electron does with libuv's port, puts it behind any that came meanwhile,
/// so a tick's earliest event would run last.)
pub const PortWatch = struct {
    const windows = std.os.windows;
    const infinite: u32 = 0xFFFFFFFF;
    const wait_object_0: u32 = 0;
    const wait_failed: u32 = 0xFFFFFFFF;

    extern "kernel32" fn CreateEventW(attrs: ?*anyopaque, manual: i32, initial: i32, name: ?[*:0]const u16) callconv(.winapi) ?windows.HANDLE;
    extern "kernel32" fn SetEvent(event: windows.HANDLE) callconv(.winapi) i32;
    extern "kernel32" fn WaitForSingleObject(handle: windows.HANDLE, ms: u32) callconv(.winapi) u32;
    extern "kernel32" fn WaitForMultipleObjects(count: u32, handles: [*]const windows.HANDLE, all: i32, ms: u32) callconv(.winapi) u32;
    extern "kernel32" fn CloseHandle(handle: windows.HANDLE) callconv(.winapi) i32;

    port: windows.HANDLE,
    wake: *const fn (?*anyopaque) void,
    ctx: ?*anyopaque,
    rearmed: windows.HANDLE,
    /// Set by `stop`. First in every wait, so it wins over the others.
    stopped: windows.HANDLE,
    thread: std.Thread,

    /// `self` must stay put until `stop`.
    pub fn start(self: *PortWatch, loop: *const xev.Loop, wake: *const fn (?*anyopaque) void, ctx: ?*anyopaque) !void {
        if (WaitForSingleObject(loop.iocp_handle, 0) == wait_failed) return error.Unsupported;
        const rearmed = CreateEventW(null, 0, 0, null) orelse return error.SystemResources;
        errdefer _ = CloseHandle(rearmed);
        const stopped = CreateEventW(null, 1, 0, null) orelse return error.SystemResources;
        errdefer _ = CloseHandle(stopped);
        self.* = .{ .port = loop.iocp_handle, .wake = wake, .ctx = ctx, .rearmed = rearmed, .stopped = stopped, .thread = undefined };
        self.thread = try std.Thread.spawn(.{}, run, .{self});
    }

    pub fn rearm(self: *PortWatch) void {
        _ = SetEvent(self.rearmed);
    }

    /// Returns with the thread gone, so no `wake` follows.
    pub fn stop(self: *PortWatch) void {
        _ = SetEvent(self.stopped);
        self.thread.join();
        _ = CloseHandle(self.rearmed);
        _ = CloseHandle(self.stopped);
    }

    fn run(self: *PortWatch) void {
        while (self.waitFor(self.port)) {
            self.wake(self.ctx);
            if (!self.waitFor(self.rearmed)) return;
        }
    }

    /// Whether `handle` was signaled before `stopped`.
    fn waitFor(self: *PortWatch, handle: windows.HANDLE) bool {
        const handles = [2]windows.HANDLE{ self.stopped, handle };
        return WaitForMultipleObjects(handles.len, &handles, 0, infinite) == wait_object_0 + 1;
    }
};

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
    // IOCP keeps plain nanoseconds, the others a timespec.
    const ns: i128 = if (xev.backend == .iocp)
        @as(i128, t.next) - now
    else
        (@as(i128, t.next.sec) - now.sec) * std.time.ns_per_s + (t.next.nsec - now.nsec);
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

test "PortWatch wakes for packets and leaves them in the order they came" {
    if (xev.backend != .iocp) return error.SkipZigTest;
    var loop = try xev.Loop.init(.{});
    defer loop.deinit();
    const port = loop.iocp_handle;
    const k32 = struct {
        extern "kernel32" fn GetQueuedCompletionStatus(iocp: std.os.windows.HANDLE, bytes: *u32, key: *usize, overlapped: *?*anyopaque, ms: u32) callconv(.winapi) i32;
        extern "kernel32" fn PostQueuedCompletionStatus(iocp: std.os.windows.HANDLE, bytes: u32, key: usize, overlapped: ?*anyopaque) callconv(.winapi) i32;
    };
    // Both there when it first wakes.
    try testing.expect(k32.PostQueuedCompletionStatus(port, 1, 0, null) != 0);
    try testing.expect(k32.PostQueuedCompletionStatus(port, 2, 0, null) != 0);

    var woken: std.atomic.Value(u32) = .init(0);
    var watch: PortWatch = undefined;
    try watch.start(&loop, struct {
        fn wake(ctx: ?*anyopaque) void {
            _ = @as(*std.atomic.Value(u32), @ptrCast(@alignCast(ctx.?))).fetchAdd(1, .release);
        }
    }.wake, &woken);
    defer watch.stop();
    while (woken.load(.acquire) == 0) std.Thread.yield() catch {};

    for ([_]u32{ 1, 2 }) |want| {
        var bytes: u32 = 0;
        var key: usize = 0;
        var overlapped: ?*anyopaque = null;
        try testing.expect(k32.GetQueuedCompletionStatus(port, &bytes, &key, &overlapped, 0) != 0);
        try testing.expectEqual(want, bytes);
    }
    // Nothing more until it's rearmed, and then only for a new packet.
    try testing.expectEqual(1, woken.load(.acquire));
    watch.rearm();
    try testing.expect(k32.PostQueuedCompletionStatus(port, 3, 0, null) != 0);
    while (woken.load(.acquire) == 1) std.Thread.yield() catch {};
    try testing.expectEqual(2, woken.load(.acquire));
}

test "pollFd is readable while the loop has an event to collect" {
    if (xev.backend == .iocp) return error.SkipZigTest; // `PortWatch` instead
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
