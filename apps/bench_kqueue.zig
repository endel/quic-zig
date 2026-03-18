const std = @import("std");
const posix = std.posix;
const xev = @import("xev");

const PORT: u16 = 19876;

// ============================================================================
// Stats
// ============================================================================

const Stats = struct {
    samples: []const i64, // nanoseconds

    fn median(self: Stats) f64 {
        const sorted = std.heap.page_allocator.alloc(i64, self.samples.len) catch return 0;
        defer std.heap.page_allocator.free(sorted);
        @memcpy(sorted, self.samples);
        std.mem.sort(i64, sorted, {}, std.sort.asc(i64));
        return @as(f64, @floatFromInt(sorted[sorted.len / 2])) / 1e6;
    }

    fn avg(self: Stats) f64 {
        var sum: i128 = 0;
        for (self.samples) |s| sum += s;
        return @as(f64, @floatFromInt(@as(i64, @intCast(@divTrunc(sum, @as(i128, @intCast(self.samples.len))))))) / 1e6;
    }

    fn percentile(self: Stats, p: f64) f64 {
        const sorted = std.heap.page_allocator.alloc(i64, self.samples.len) catch return 0;
        defer std.heap.page_allocator.free(sorted);
        @memcpy(sorted, self.samples);
        std.mem.sort(i64, sorted, {}, std.sort.asc(i64));
        const idx = @min(@as(usize, @intFromFloat(p * @as(f64, @floatFromInt(sorted.len)))), sorted.len - 1);
        return @as(f64, @floatFromInt(sorted[idx])) / 1e6;
    }

    fn max(self: Stats) f64 {
        var m: i64 = 0;
        for (self.samples) |s| if (s > m) {
            m = s;
        };
        return @as(f64, @floatFromInt(m)) / 1e6;
    }

    fn min(self: Stats) f64 {
        var m: i64 = std.math.maxInt(i64);
        for (self.samples) |s| if (s < m) {
            m = s;
        };
        return @as(f64, @floatFromInt(m)) / 1e6;
    }

    fn stddev(self: Stats) f64 {
        const a = self.avg();
        var sum: f64 = 0;
        for (self.samples) |s| {
            const v = @as(f64, @floatFromInt(s)) / 1e6 - a;
            sum += v * v;
        }
        return @sqrt(sum / @as(f64, @floatFromInt(self.samples.len)));
    }

    fn spikesAbove(self: Stats, threshold_ms: f64) usize {
        var count: usize = 0;
        for (self.samples) |s| {
            if (@as(f64, @floatFromInt(s)) / 1e6 > threshold_ms) count += 1;
        }
        return count;
    }

    fn print(self: Stats, label: []const u8) void {
        const n = self.samples.len;
        const s5 = self.spikesAbove(5);
        const s20 = self.spikesAbove(20);
        std.debug.print("\n=== {s} ({d} iterations) ===\n", .{ label, n });
        std.debug.print("  med={d:.3}ms  avg={d:.3}ms  min={d:.3}ms  max={d:.3}ms\n", .{
            self.median(), self.avg(), self.min(), self.max(),
        });
        std.debug.print("  p95={d:.3}ms  p99={d:.3}ms  stddev={d:.3}ms\n", .{
            self.percentile(0.95), self.percentile(0.99), self.stddev(),
        });
        std.debug.print("  spikes >5ms: {d} ({d:.1}%)  >20ms: {d} ({d:.1}%)\n", .{
            s5,  @as(f64, @floatFromInt(s5)) / @as(f64, @floatFromInt(n)) * 100,
            s20, @as(f64, @floatFromInt(s20)) / @as(f64, @floatFromInt(n)) * 100,
        });
    }
};

// ============================================================================
// Shared: create bound UDP socket
// ============================================================================

fn createSocket(port: u16) posix.socket_t {
    const fd = posix.socket(posix.AF.INET, posix.SOCK.DGRAM | posix.SOCK.NONBLOCK, 0) catch @panic("socket");
    const yes: c_int = 1;
    posix.setsockopt(fd, posix.SOL.SOCKET, posix.SO.REUSEADDR, std.mem.asBytes(&yes)) catch {};
    var addr: posix.sockaddr.in = .{
        .port = std.mem.nativeToBig(u16, port),
        .addr = 0, // INADDR_ANY
    };
    posix.bind(fd, @ptrCast(&addr), @sizeOf(posix.sockaddr.in)) catch @panic("bind");
    return fd;
}

fn serverAddr() posix.sockaddr.in {
    return .{
        .port = std.mem.nativeToBig(u16, PORT),
        .addr = std.mem.nativeToBig(u32, 0x7f000001), // 127.0.0.1
    };
}

// Recv helper that works with both raw kqueue and xev modes
fn recvAndEcho(sockfd: posix.socket_t, recv_buf: []u8) void {
    while (true) {
        var from_addr: posix.sockaddr.in = undefined;
        var from_len: posix.socklen_t = @sizeOf(posix.sockaddr.in);
        const bytes = posix.recvfrom(sockfd, recv_buf, 0, @ptrCast(&from_addr), &from_len) catch break;
        if (bytes >= 16) {
            _ = posix.sendto(sockfd, recv_buf[0..bytes], 0, @ptrCast(&from_addr), from_len) catch {};
        }
    }
}

// ============================================================================
// Sender thread (shared by all modes)
// ============================================================================

const SenderArgs = struct {
    iterations: usize,
    interval_us: u64,
    rtts: []i64,
    ready: *std.atomic.Value(bool),
    done: *std.atomic.Value(bool),
};

fn senderThread(args: *SenderArgs) void {
    // Wait for server to be ready
    while (!args.ready.load(.acquire)) std.Thread.yield() catch {};

    const fd = posix.socket(posix.AF.INET, posix.SOCK.DGRAM, 0) catch @panic("sender socket");
    defer posix.close(fd);

    var dest = serverAddr();
    var recv_buf: [32]u8 = undefined;

    for (0..args.iterations) |i| {
        var pkt: [16]u8 = undefined;
        std.mem.writeInt(u64, pkt[0..8], @intCast(i), .little);
        const send_time: i64 = @intCast(std.time.nanoTimestamp());
        std.mem.writeInt(i64, pkt[8..16], send_time, .little);

        _ = posix.sendto(fd, &pkt, 0, @ptrCast(&dest), @sizeOf(posix.sockaddr.in)) catch continue;

        // Blocking recv with timeout
        var poll_fd = [1]posix.pollfd{.{
            .fd = fd,
            .events = posix.POLL.IN,
            .revents = 0,
        }};
        const poll_ret = posix.poll(&poll_fd, 100) catch 0; // 100ms timeout
        if (poll_ret > 0) {
            const n = posix.recvfrom(fd, &recv_buf, 0, null, null) catch 0;
            if (n >= 16) {
                const recv_time: i64 = @intCast(std.time.nanoTimestamp());
                const orig_send = std.mem.readInt(i64, recv_buf[8..16], .little);
                args.rtts[i] = recv_time - orig_send;
            } else {
                args.rtts[i] = 100_000_000; // timeout marker
            }
        } else {
            args.rtts[i] = 100_000_000;
        }

        if (args.interval_us > 0) std.Thread.sleep(args.interval_us * 1000);
    }
    args.done.store(true, .release);
}

// ============================================================================
// Mode 1: Raw kqueue
// ============================================================================

fn rawKqueueBench(iterations: usize, interval_us: u64) Stats {
    const sockfd = createSocket(PORT);
    defer posix.close(sockfd);

    const rtts = std.heap.page_allocator.alloc(i64, iterations) catch @panic("alloc");

    var ready = std.atomic.Value(bool).init(false);
    var done = std.atomic.Value(bool).init(false);
    var sender_args = SenderArgs{
        .iterations = iterations,
        .interval_us = interval_us,
        .rtts = rtts,
        .ready = &ready,
        .done = &done,
    };
    const sender = std.Thread.spawn(.{}, senderThread, .{&sender_args}) catch @panic("spawn");

    // Raw kqueue
    const kq = posix.kqueue() catch @panic("kqueue");
    defer posix.close(kq);

    var changelist = [1]std.c.Kevent{.{
        .ident = @intCast(sockfd),
        .filter = std.c.EVFILT.READ,
        .flags = std.c.EV.ADD | std.c.EV.ENABLE,
        .fflags = 0,
        .data = 0,
        .udata = 0,
    }};
    var events: [4]std.c.Kevent = undefined;

    // Register + wait in one call
    ready.store(true, .release);

    var recv_buf: [32]u8 = undefined;

    while (!done.load(.acquire)) {
        const timeout = std.c.timespec{ .sec = 0, .nsec = 10_000_000 }; // 10ms
        const n = std.c.kevent(kq, &changelist, 1, &events, 4, &timeout);
        // After first call, clear changelist
        changelist[0].flags = 0;
        if (n > 0) {
            recvAndEcho(sockfd, &recv_buf);
        }
    }

    sender.join();
    return .{ .samples = rtts };
}

// ============================================================================
// Mode 2: libxev File.poll + Timer
// ============================================================================

const XevState = struct {
    sockfd: posix.socket_t,
    recv_buf: [32]u8 = undefined,
    done: *std.atomic.Value(bool),
    timer_ms: u64,
    loop: *xev.Loop = undefined,
    timer: *xev.Timer = undefined,
    timer_completion: *xev.Completion = undefined,
    timer_cancel_completion: xev.Completion = undefined,
    timer_armed: bool = false,
};

fn xevOnReadable(
    state_opt: ?*XevState,
    _: *xev.Loop,
    _: *xev.Completion,
    _: xev.File,
    r: xev.PollError!xev.PollEvent,
) xev.CallbackAction {
    _ = r catch return .rearm;
    const state = state_opt orelse return .disarm;

    recvAndEcho(state.sockfd, &state.recv_buf);

    // Reschedule timer (like our real event loop's rescheduleTimer)
    xevRescheduleTimer(state);

    if (state.done.load(.acquire)) {
        state.loop.stop();
        return .disarm;
    }
    return .rearm;
}

fn xevOnTimer(
    state_opt: ?*XevState,
    _: *xev.Loop,
    _: *xev.Completion,
    r: xev.Timer.RunError!void,
) xev.CallbackAction {
    _ = r catch return .disarm;
    const state = state_opt orelse return .disarm;
    state.timer_armed = false;

    // Drain any packets that arrived (simulates our onTimer recv drain)
    recvAndEcho(state.sockfd, &state.recv_buf);

    // Reschedule timer
    xevRescheduleTimer(state);

    if (state.done.load(.acquire)) {
        state.loop.stop();
    }

    return .disarm; // one-shot; rescheduled via xevRescheduleTimer
}

fn xevRescheduleTimer(state: *XevState) void {
    if (state.timer_armed) {
        state.timer.reset(state.loop, state.timer_completion, &state.timer_cancel_completion, state.timer_ms, XevState, state, xevOnTimer);
    } else {
        state.timer.run(state.loop, state.timer_completion, state.timer_ms, XevState, state, xevOnTimer);
    }
    state.timer_armed = true;
}

fn xevBench(iterations: usize, interval_us: u64, timer_ms: u64) Stats {
    const sockfd = createSocket(PORT);
    defer posix.close(sockfd);

    const rtts = std.heap.page_allocator.alloc(i64, iterations) catch @panic("alloc");

    var ready = std.atomic.Value(bool).init(false);
    var done = std.atomic.Value(bool).init(false);
    var sender_args = SenderArgs{
        .iterations = iterations,
        .interval_us = interval_us,
        .rtts = rtts,
        .ready = &ready,
        .done = &done,
    };
    const sender = std.Thread.spawn(.{}, senderThread, .{&sender_args}) catch @panic("spawn");

    var state = XevState{
        .sockfd = sockfd,
        .done = &done,
        .timer_ms = timer_ms,
    };

    var loop = xev.Loop.init(.{}) catch @panic("loop init");
    defer loop.deinit();
    state.loop = &loop;

    var file = xev.File.initFd(sockfd);
    var poll_completion: xev.Completion = undefined;
    file.poll(&loop, &poll_completion, .read, XevState, &state, xevOnReadable);

    var timer = xev.Timer.init() catch @panic("timer init");
    defer timer.deinit();
    state.timer = &timer;
    var timer_completion: xev.Completion = undefined;
    state.timer_completion = &timer_completion;
    timer.run(&loop, &timer_completion, timer_ms, XevState, &state, xevOnTimer);
    state.timer_armed = true;

    ready.store(true, .release);

    loop.run(.until_done) catch {};

    sender.join();
    return .{ .samples = rtts };
}

// ============================================================================
// Mode 3: libxev with simulated work (busy-wait in callback)
// ============================================================================

fn xevOnReadableWithWork(
    state_opt: ?*XevState,
    _: *xev.Loop,
    _: *xev.Completion,
    _: xev.File,
    r: xev.PollError!xev.PollEvent,
) xev.CallbackAction {
    _ = r catch return .rearm;
    const state = state_opt orelse return .disarm;

    recvAndEcho(state.sockfd, &state.recv_buf);
    xevRescheduleTimer(state);

    // Simulate ~50us of QUIC processing work
    const start: i64 = @intCast(std.time.nanoTimestamp());
    while (true) {
        const now: i64 = @intCast(std.time.nanoTimestamp());
        if (now - start > 50_000) break; // 50us
    }

    if (state.done.load(.acquire)) {
        state.loop.stop();
        return .disarm;
    }
    return .rearm;
}

fn xevWorkBench(iterations: usize, interval_us: u64, timer_ms: u64) Stats {
    const sockfd = createSocket(PORT);
    defer posix.close(sockfd);

    const rtts = std.heap.page_allocator.alloc(i64, iterations) catch @panic("alloc");

    var ready = std.atomic.Value(bool).init(false);
    var done = std.atomic.Value(bool).init(false);
    var sender_args = SenderArgs{
        .iterations = iterations,
        .interval_us = interval_us,
        .rtts = rtts,
        .ready = &ready,
        .done = &done,
    };
    const sender = std.Thread.spawn(.{}, senderThread, .{&sender_args}) catch @panic("spawn");

    var state = XevState{
        .sockfd = sockfd,
        .done = &done,
        .timer_ms = timer_ms,
    };

    var loop = xev.Loop.init(.{}) catch @panic("loop init");
    defer loop.deinit();
    state.loop = &loop;

    var file = xev.File.initFd(sockfd);
    var poll_completion: xev.Completion = undefined;
    file.poll(&loop, &poll_completion, .read, XevState, &state, xevOnReadableWithWork);

    var timer = xev.Timer.init() catch @panic("timer init");
    defer timer.deinit();
    state.timer = &timer;
    var timer_completion: xev.Completion = undefined;
    state.timer_completion = &timer_completion;
    timer.run(&loop, &timer_completion, timer_ms, XevState, &state, xevOnTimer);
    state.timer_armed = true;

    ready.store(true, .release);

    loop.run(.until_done) catch {};

    sender.join();
    return .{ .samples = rtts };
}

// ============================================================================
// Main
// ============================================================================

pub fn main() !void {
    const iterations: usize = 1000;
    const interval_us: u64 = 1000; // 1ms between packets
    const timer_ms: u64 = 28; // Simulated PTO timer

    std.debug.print("kqueue latency benchmark: {d} iterations, {d}us interval, {d}ms timer\n", .{
        iterations, interval_us, timer_ms,
    });

    {
        std.debug.print("\nStarting: Raw kqueue...\n", .{});
        const stats = rawKqueueBench(iterations, interval_us);
        stats.print("Raw kqueue (baseline)");
    }

    std.Thread.sleep(100_000_000); // 100ms between modes

    {
        std.debug.print("\nStarting: libxev poll + timer...\n", .{});
        const stats = xevBench(iterations, interval_us, timer_ms);
        stats.print("libxev poll + 28ms timer");
    }

    std.Thread.sleep(100_000_000);

    {
        std.debug.print("\nStarting: libxev poll + timer + 50us work...\n", .{});
        const stats = xevWorkBench(iterations, interval_us, timer_ms);
        stats.print("libxev poll + 28ms timer + 50us work");
    }
}
