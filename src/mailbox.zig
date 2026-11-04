//! Work handed back to an event loop's thread from other threads: a pool's
//! finished job, say. The loop watches it only while a post is owed, so an
//! idle one costs nothing and keeps no loop running; one that is owed keeps
//! its server from stopping until it has come.

const std = @import("std");
const xev = @import("xev_backend.zig").xev;
const sys = @import("sys.zig");

pub const Mailbox = struct {
    loop: ?*xev.Loop = null,
    wake: xev.Async,
    wake_c: xev.Completion = .{},
    watching: bool = false,
    /// Posts promised (`expect`) and not yet run.
    owed: std.atomic.Value(u32) = .init(0),
    /// What came, newest first.
    posted: std.atomic.Value(?*Post) = .init(null),

    pub const Post = struct {
        run: *const fn (*Post) void,
        next: ?*Post = null,
    };

    pub fn init() !Mailbox {
        return .{ .wake = try xev.Async.init() };
    }

    /// On the loop's thread: a post will come, from any thread.
    pub fn expect(self: *Mailbox) void {
        _ = self.owed.fetchAdd(1, .monotonic);
        if (self.watching) return;
        const loop = self.loop orelse return; // not started: `deinit` runs it
        self.watching = true;
        self.wake.wait(loop, &self.wake_c, Mailbox, self, onWake);
    }

    /// On the loop's thread: an `expect` whose post won't come after all.
    pub fn forget(self: *Mailbox) void {
        // The last owed: wake the watch, so it sees nothing is and ends.
        if (self.owed.fetchSub(1, .monotonic) == 1 and self.watching) self.wake.notify() catch {};
    }

    /// Any thread: `p.run` runs on the loop's thread, soon.
    pub fn post(self: *Mailbox, p: *Post) void {
        var head = self.posted.load(.monotonic);
        while (true) {
            p.next = head;
            head = self.posted.cmpxchgWeak(head, p, .release, .monotonic) orelse break;
        }
        self.wake.notify() catch {};
    }

    /// Once its loop has stopped: waits for what's owed, and runs it here.
    pub fn deinit(self: *Mailbox) void {
        while (self.owed.load(.acquire) > 0) {
            if (!self.drain()) sys.sleepNs(std.time.ns_per_ms);
        }
        self.wake.deinit();
    }

    /// Runs what came, oldest first; false when nothing had.
    fn drain(self: *Mailbox) bool {
        var newest = self.posted.swap(null, .acquire) orelse return false;
        var oldest: ?*Post = null;
        while (true) {
            const next = newest.next;
            newest.next = oldest;
            oldest = newest;
            newest = next orelse break;
        }
        while (oldest) |p| {
            oldest = p.next;
            _ = self.owed.fetchSub(1, .monotonic);
            p.run(p);
        }
        return true;
    }

    fn onWake(self_opt: ?*Mailbox, _: *xev.Loop, _: *xev.Completion, r: xev.Async.WaitError!void) xev.CallbackAction {
        const self = self_opt orelse return .disarm;
        _ = r catch {};
        _ = self.drain();
        if (self.owed.load(.acquire) > 0) return .rearm;
        self.watching = false;
        return .disarm;
    }
};

test "posts from another thread run on the loop, oldest first; deinit waits for one owed" {
    var loop = try xev.Loop.init(.{});
    defer loop.deinit();
    var mb = try Mailbox.init();
    mb.loop = &loop;
    const Note = struct {
        post: Mailbox.Post = .{ .run = ran },
        order: *std.ArrayList(u8),
        tag: u8,
        fn ran(p: *Mailbox.Post) void {
            const n: *@This() = @fieldParentPtr("post", p);
            n.order.appendAssumeCapacity(n.tag);
        }
    };
    var order: std.ArrayList(u8) = try .initCapacity(std.testing.allocator, 4);
    defer order.deinit(std.testing.allocator);
    var notes = [_]Note{ .{ .order = &order, .tag = 'a' }, .{ .order = &order, .tag = 'b' }, .{ .order = &order, .tag = 'c' } };
    for (&notes) |_| mb.expect();
    const t = try std.Thread.spawn(.{}, struct {
        fn send(m: *Mailbox, ns: *[3]Note) void {
            m.post(&ns[0].post);
            m.post(&ns[1].post);
        }
    }.send, .{ &mb, &notes });
    t.join();
    while (order.items.len < 2) try loop.run(.once);
    try std.testing.expectEqualStrings("ab", order.items);
    try std.testing.expect(mb.watching); // one still owed

    const late = try std.Thread.spawn(.{}, struct {
        fn send(m: *Mailbox, n: *Note) void {
            sys.sleepNs(5 * std.time.ns_per_ms);
            m.post(&n.post);
        }
    }.send, .{ &mb, &notes[2] });
    defer late.join();
    mb.deinit();
    try std.testing.expectEqualStrings("abc", order.items);
}

test "a post forgotten ends the watch, so the loop can stop" {
    var loop = try xev.Loop.init(.{});
    defer loop.deinit();
    var mb = try Mailbox.init();
    defer mb.deinit();
    mb.loop = &loop;
    mb.expect();
    try std.testing.expect(mb.watching);
    mb.forget();
    try loop.run(.until_done);
    try std.testing.expect(!mb.watching);
}
