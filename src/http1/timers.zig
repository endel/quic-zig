//! Coarse deadlines and deferred callbacks for the HTTP/1.1 listener.
//!
//! Every timeout here (handshake, keep-alive, ping, close, linger) is in
//! seconds, so instead of one xev.Timer per connection — each needing its
//! own cancel completion — connections embed a `Deadline` and a single tick
//! scans the armed ones. The tick only runs while a deadline is armed, so an
//! idle listener never wakes the loop.
//!
//! Ported from routez's `timers.zig`.

const std = @import("std");
const sys = @import("../sys.zig");
const xev_backend = @import("../xev_backend.zig");
const xev = xev_backend.xev;

pub fn nowMs() i64 {
    return @divTrunc(sys.nanoTimestamp(), std.time.ns_per_ms);
}

pub const Deadline = struct {
    at_ms: i64 = 0,
    callback: *const fn (*Deadline) void,
    prev: ?*Deadline = null,
    next: ?*Deadline = null,
    fire_next: ?*Deadline = null,
    state: enum { idle, armed, firing } = .idle,

    pub fn armed(self: *const Deadline) bool {
        return self.state == .armed;
    }
};

/// Deferred work that must not run inside the caller's stack frame (freeing
/// an object whose method is still executing).
pub const Deferred = struct {
    callback: *const fn (*Deferred) void,
    next: ?*Deferred = null,
    queued: bool = false,
};

pub const Timers = struct {
    loop: *xev.Loop,
    tick_timer: xev.Timer,
    tick_c: xev.Completion = .{},
    tick_cancel_c: xev.Completion = .{},
    ticking: bool = false,
    /// Inside `onTick`, which disarms by itself; cancelling it there is not
    /// safe.
    in_tick: bool = false,
    defer_timer: xev.Timer,
    defer_c: xev.Completion = .{},
    defer_armed: bool = false,
    head: ?*Deadline = null,
    deferred_head: ?*Deferred = null,
    deferred_tail: ?*Deferred = null,
    stopped: bool = false,

    pub const tick_ms = 500;

    pub fn init(loop: *xev.Loop) !Timers {
        return .{
            .loop = loop,
            .tick_timer = try xev.Timer.init(),
            .defer_timer = try xev.Timer.init(),
        };
    }

    pub fn deinit(self: *Timers) void {
        self.tick_timer.deinit();
        self.defer_timer.deinit();
    }

    /// Stop the tick so the loop can run dry. Deferred work still runs:
    /// closing sockets needs it.
    pub fn stop(self: *Timers) void {
        self.stopped = true;
        if (self.ticking and !self.in_tick) xev_backend.cancelCompletion(self.loop, &self.tick_c, &self.tick_cancel_c);
    }

    /// Nothing of ours is left on the loop.
    pub fn isIdle(self: *const Timers) bool {
        return self.tick_c.state() == .dead and self.defer_c.state() == .dead and
            self.tick_cancel_c.state() == .dead;
    }

    /// Arm (or re-arm) `d` to fire `ms` from now.
    pub fn set(self: *Timers, d: *Deadline, ms: u32) void {
        d.at_ms = nowMs() + ms;
        if (d.state != .armed) {
            d.state = .armed;
            d.prev = null;
            d.next = self.head;
            if (self.head) |h| h.prev = d;
            self.head = d;
        }
        if (!self.ticking and !self.stopped) {
            self.ticking = true;
            self.tick_timer.run(self.loop, &self.tick_c, tick_ms, Timers, self, onTick);
        }
    }

    pub fn clear(self: *Timers, d: *Deadline) void {
        switch (d.state) {
            .idle => {},
            // Still on this tick's fire list; skip it there.
            .firing => d.state = .idle,
            .armed => self.unlink(d),
        }
    }

    fn unlink(self: *Timers, d: *Deadline) void {
        if (d.prev) |p| p.next = d.next else self.head = d.next;
        if (d.next) |n| n.prev = d.prev;
        d.prev = null;
        d.next = null;
        d.state = .idle;
    }

    /// Run `d.callback` on a later loop iteration.
    pub fn defer_(self: *Timers, d: *Deferred) void {
        if (d.queued) return;
        d.queued = true;
        d.next = null;
        if (self.deferred_tail) |t| t.next = d else self.deferred_head = d;
        self.deferred_tail = d;
        if (!self.defer_armed) {
            self.defer_armed = true;
            self.defer_timer.run(self.loop, &self.defer_c, 0, Timers, self, onDefer);
        }
    }

    /// Run whatever is deferred now, for a caller about to free what the
    /// callbacks would otherwise reach later (a loop that stops for good).
    pub fn runDeferred(self: *Timers) void {
        var d = self.deferred_head;
        self.deferred_head = null;
        self.deferred_tail = null;
        while (d) |cur| {
            d = cur.next;
            cur.queued = false;
            cur.next = null;
            cur.callback(cur);
        }
    }

    fn onDefer(ud: ?*Timers, _: *xev.Loop, _: *xev.Completion, r: xev.Timer.RunError!void) xev.CallbackAction {
        _ = r catch {};
        const self = ud.?;
        self.defer_armed = false;
        // Callbacks may queue more; those run on the next round.
        self.runDeferred();
        return .disarm;
    }

    fn onTick(ud: ?*Timers, _: *xev.Loop, c: *xev.Completion, r: xev.Timer.RunError!void) xev.CallbackAction {
        const self = ud.?;
        _ = r catch {
            // Cancelled by stop().
            self.ticking = false;
            return .disarm;
        };
        self.in_tick = true;
        self.fireExpired(nowMs());
        self.in_tick = false;
        if (self.stopped or self.head == null) {
            self.ticking = false;
            return .disarm;
        }
        self.tick_timer.run(self.loop, c, tick_ms, Timers, self, onTick);
        return .disarm;
    }

    fn fireExpired(self: *Timers, now_ms: i64) void {
        // Collect first: callbacks may clear or re-arm any deadline.
        var expired: ?*Deadline = null;
        var d = self.head;
        while (d) |cur| {
            d = cur.next;
            if (cur.at_ms <= now_ms) {
                self.unlink(cur);
                cur.state = .firing;
                cur.fire_next = expired;
                expired = cur;
            }
        }
        while (expired) |cur| {
            expired = cur.fire_next;
            cur.fire_next = null;
            if (cur.state != .firing) continue;
            cur.state = .idle;
            cur.callback(cur);
        }
    }
};
