const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const xev = @import("xev");
//const xev = @import("xev").Dynamic;

pub const std_options: std.Options = .{
    .log_level = .info,
};

// Tune-ables
pub const NUM_PINGS = 1000 * 1000;

pub fn main(init: std.process.Init) !void {
    try run(1, init.io);
}

pub fn run(comptime thread_count: comptime_int, io: Io) !void {
    var thread_pool = xev.ThreadPool.init(.{});
    defer thread_pool.deinit();
    defer thread_pool.shutdown();

    if (xev.dynamic) try xev.detect();
    var loop = try xev.Loop.init(.{
        .entries = std.math.pow(u13, 2, 12),
        .thread_pool = &thread_pool,
    });
    defer loop.deinit();

    // Create our async
    notifier = try xev.Async.init();
    defer notifier.deinit();

    const userdata: ?*void = null;
    var c: xev.Completion = undefined;
    notifier.wait(&loop, &c, void, userdata, &asyncCallback);

    // Initialize all our threads
    var threads: [thread_count]std.Thread = undefined;
    for (&threads) |*thr| {
        thr.* = try std.Thread.spawn(.{}, threadMain, .{});
    }

    const start_time = Io.Timestamp.now(io, .awake);
    try loop.run(.until_done);
    for (&threads) |thr| thr.join();
    const end_time = Io.Timestamp.now(io, .awake);

    const elapsed_ns: i128 = end_time.nanoseconds - start_time.nanoseconds;
    const elapsed: f64 = @floatFromInt(elapsed_ns);
    std.log.info("async_pummel_{d}: {d} callbacks in {d:.2} seconds ({d:.2}/sec)", .{
        thread_count,
        callbacks,
        elapsed / 1e9,
        @as(f64, @floatFromInt(callbacks)) / (elapsed / 1e9),
    });
}

var callbacks: usize = 0;
var notifier: xev.Async = undefined;
var state: enum { running, stop, stopped } = .running;

fn asyncCallback(
    _: ?*void,
    _: *xev.Loop,
    _: *xev.Completion,
    r: xev.Async.WaitError!void,
) xev.CallbackAction {
    _ = r catch unreachable;

    callbacks += 1;
    if (callbacks < NUM_PINGS) return .rearm;

    // We're done. Busy-wait for the worker thread to observe `.stop`
    // and flip to `.stopped`. `std.Thread.yield` is a kernel yield hint
    // (was `std.Thread.sleep(0)` pre-0.16); ignore errors since even
    // with no yield the spin still makes progress.
    state = .stop;
    while (state != .stopped) std.Thread.yield() catch {};
    return .disarm;
}

fn threadMain() !void {
    while (state == .running) try notifier.notify();
    state = .stopped;
}
