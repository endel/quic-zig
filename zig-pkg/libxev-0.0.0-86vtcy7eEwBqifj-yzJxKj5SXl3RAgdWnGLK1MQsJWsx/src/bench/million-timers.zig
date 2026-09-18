const std = @import("std");
const Io = std.Io;
const xev = @import("xev");
//const xev = @import("xev").Dynamic;

pub const NUM_TIMERS: usize = 10 * 1000 * 1000;

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    var thread_pool = xev.ThreadPool.init(.{});
    defer thread_pool.deinit();
    defer thread_pool.shutdown();

    if (xev.dynamic) try xev.detect();
    var loop = try xev.Loop.init(.{
        .entries = std.math.pow(u13, 2, 12),
        .thread_pool = &thread_pool,
    });
    defer loop.deinit();

    // GeneralPurposeAllocator was renamed to DebugAllocator in Zig 0.16.
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();

    var cs = try alloc.alloc(xev.Completion, NUM_TIMERS);
    defer alloc.free(cs);

    const before_all = Io.Timestamp.now(io, .awake);
    var i: usize = 0;
    var timeout: u64 = 1;
    while (i < NUM_TIMERS) : (i += 1) {
        if (i % 1000 == 0) timeout += 1;
        const timer = try xev.Timer.init();
        timer.run(&loop, &cs[i], timeout, void, null, timerCallback);
    }

    const before_run = Io.Timestamp.now(io, .awake);
    try loop.run(.until_done);
    const after_run = Io.Timestamp.now(io, .awake);
    const after_all = Io.Timestamp.now(io, .awake);

    std.log.info("{d:.2} seconds total", .{seconds(after_all, before_all)});
    std.log.info("{d:.2} seconds init", .{seconds(before_run, before_all)});
    std.log.info("{d:.2} seconds dispatch", .{seconds(after_run, before_run)});
    std.log.info("{d:.2} seconds cleanup", .{seconds(after_all, after_run)});
}

fn seconds(end: Io.Timestamp, start: Io.Timestamp) f64 {
    const ns: i128 = end.nanoseconds - start.nanoseconds;
    return @as(f64, @floatFromInt(ns)) / 1e9;
}

pub const std_options: std.Options = .{
    .log_level = .info,
};

var timer_callback_count: usize = 0;

fn timerCallback(
    _: ?*void,
    _: *xev.Loop,
    _: *xev.Completion,
    result: xev.Timer.RunError!void,
) xev.CallbackAction {
    _ = result catch unreachable;
    timer_callback_count += 1;
    return .disarm;
}
