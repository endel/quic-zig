const std = @import("std");
const testing = std.testing;

const quic_fc = @import("../quic/flow_control.zig");
const quic_connection = @import("../quic/connection.zig");
const RttStats = @import("../quic/rtt.zig").RttStats;

/// WebTransport session flow control, draft-ietf-webtrans-http3-13 §5.3-§5.6.
///
/// Session limits sit on top of QUIC's own: a stream may only be created when
/// both the session and the connection permit it. This module is the
/// accounting alone — `WebTransportConnection` owns the capsule I/O, so there
/// is one place that knows how a capsule reaches the wire.

/// What a session grants its peer. Taken from the QUIC connection's own
/// defaults so the session limit is never the tighter of the two by accident:
/// both slide by half a window, but a session's slides on streams *opened*
/// where QUIC's waits for them to close.
pub const Credits = struct {
    max_streams_bidi: u64 = 0,
    max_streams_uni: u64 = 0,
    max_data: u64 = 0,

    pub const default: Credits = .{
        .max_streams_bidi = (quic_connection.ConnectionConfig{}).initial_max_streams_bidi,
        .max_streams_uni = (quic_connection.ConnectionConfig{}).initial_max_streams_uni,
        .max_data = (quic_connection.ConnectionConfig{}).initial_max_data,
    };
};

/// A capsule the session owes its peer.
pub const Capsule = union(enum) {
    max_streams_bidi: u64,
    max_streams_uni: u64,
    max_data: u64,
    streams_blocked_bidi: u64,
    streams_blocked_uni: u64,
    data_blocked: u64,
};

/// One direction's cumulative stream limit (§5.6.2).
///
/// Maximum Streams counts every stream the session has ever opened, closed
/// ones included, so neither endpoint needs to agree on which are still open —
/// §5.3 notes that agreement would need reliable stream resets, which this
/// stack does not have yet.
pub const StreamLimit = struct {
    /// What the peer permits us, and how much of it we have spent.
    ///
    /// `null` means the peer never stated a limit. We read that as unlimited
    /// rather than as §9.2's default of zero: a peer that says nothing is far
    /// more often one that does not implement §5.6 at all than one that means
    /// to block us, and reading silence as zero would stop us opening a single
    /// stream to Chrome. An explicit zero we do honour.
    max_send: ?u64 = null,
    opened: u64 = 0,

    /// The limit a WT_STREAMS_BLOCKED has already named, so each goes out once,
    /// and the one waiting to go out.
    blocked_sent_at: ?u64 = null,
    blocked_pending: ?u64 = null,

    /// What we permit the peer, and the headroom we keep ahead of it.
    granted: u64,
    window: u64,
    peer_opened: u64 = 0,
    granted_initially: bool = false,

    pub fn init(window: u64) StreamLimit {
        return .{ .granted = window, .window = window };
    }

    /// A WT_MAX_STREAMS capsule, or an initial limit from the peer's SETTINGS
    /// (§5.5). Cumulative, so a smaller value is stale and ignored rather than
    /// treated as a withdrawal — which is also what keeps a re-read of the
    /// peer's SETTINGS from undoing a capsule that raised the limit.
    pub fn raiseSendLimit(self: *StreamLimit, limit: u64) void {
        if (self.max_send) |current| {
            if (limit <= current) return;
        }
        self.max_send = limit;
        self.blocked_sent_at = null; // a raised limit can block again
    }

    pub fn canOpen(self: *const StreamLimit) bool {
        const max = self.max_send orelse return true;
        return self.opened < max;
    }

    /// Spend one stream of credit. Only valid after `canOpen`.
    pub fn open(self: *StreamLimit) void {
        self.opened += 1;
    }

    /// Record an open the limit refused, so one WT_STREAMS_BLOCKED goes out
    /// naming the limit we are sitting at (§5.6.3).
    pub fn recordBlocked(self: *StreamLimit) void {
        const max = self.max_send orelse return;
        if (self.blocked_sent_at) |sent| {
            if (sent == max) return;
        }
        self.blocked_pending = max;
    }

    /// The peer opened a stream against the credit we granted.
    pub fn peerOpened(self: *StreamLimit) void {
        self.peer_opened += 1;
    }

    /// The cumulative limit to advertise, or null while the peer still holds
    /// more than half its window.
    pub fn windowUpdate(self: *StreamLimit) ?u64 {
        if (self.window == 0) return null;
        if (!self.granted_initially) {
            // §9.2: with no initial credit in SETTINGS a peer may not open
            // anything until a capsule says otherwise, so each session says so
            // once. Restating a credit already sent in SETTINGS is harmless —
            // the value is cumulative — and it is the only signal a peer that
            // reads just the capsules will see.
            self.granted_initially = true;
            return self.granted;
        }
        const spent = @min(self.peer_opened, self.granted);
        if (self.granted - spent > self.window / 2) return null;
        const next = self.peer_opened + self.window;
        if (next <= self.granted) return null;
        self.granted = next;
        return next;
    }

    /// Answer a WT_STREAMS_BLOCKED (§5.6.3). A peer held up at a limit below
    /// the one we granted either lost that grant or crossed it in flight, so
    /// state it again rather than wait for the window to slide.
    pub fn peerBlockedAt(self: *StreamLimit, limit: u64) void {
        if (limit < self.granted) self.granted_initially = false;
    }

    fn takeBlocked(self: *StreamLimit) ?u64 {
        const limit = self.blocked_pending orelse return null;
        self.blocked_pending = null;
        self.blocked_sent_at = limit;
        return limit;
    }
};

/// One session's flow control state.
pub const SessionFlowControl = struct {
    bidi: StreamLimit,
    uni: StreamLimit,

    /// §5.6.4 limits session bytes the way QUIC's MAX_DATA limits connection
    /// bytes, so it is the same controller — autotuning, blocked-once and all.
    data: quic_fc.BaseFlowController,
    /// Whether the peer stated a data limit; see `StreamLimit.max_send`.
    data_limited: bool = false,
    data_granted_initially: bool = false,
    /// The limit a WT_DATA_BLOCKED is waiting to name.
    data_blocked_pending: ?u64 = null,

    pub fn init(credits: Credits) SessionFlowControl {
        return .{
            .bidi = StreamLimit.init(credits.max_streams_bidi),
            .uni = StreamLimit.init(credits.max_streams_uni),
            .data = quic_fc.BaseFlowController.init(credits.max_data, credits.max_data * 4),
        };
    }

    /// Initial limits from the peer's SETTINGS (§5.5). Applied per session,
    /// since the setting applies to every session on the connection.
    pub fn applyPeerSettings(self: *SessionFlowControl, max_streams_bidi: ?u64, max_streams_uni: ?u64, max_data: ?u64) void {
        if (max_streams_bidi) |n| self.bidi.raiseSendLimit(n);
        if (max_streams_uni) |n| self.uni.raiseSendLimit(n);
        if (max_data) |n| self.raiseSendDataLimit(n);
    }

    /// A WT_MAX_DATA capsule (§5.6.4).
    pub fn raiseSendDataLimit(self: *SessionFlowControl, limit: u64) void {
        self.data_limited = true;
        self.data.updateSendWindow(limit);
    }

    /// Session bytes WT_MAX_DATA still admits; unbounded when the peer set none.
    pub fn sendCredit(self: *const SessionFlowControl) u64 {
        if (!self.data_limited) return std.math.maxInt(u64);
        return self.data.sendWindowSize();
    }

    pub fn canSend(self: *const SessionFlowControl, len: usize) bool {
        if (!self.data_limited) return true;
        return self.data.sendWindowSize() >= len;
    }

    pub fn recordSent(self: *SessionFlowControl, len: usize) void {
        self.data.addBytesSent(len);
    }

    /// Record a write the limit refused, so one WT_DATA_BLOCKED goes out
    /// naming the limit we are sitting at (§5.6.5).
    pub fn recordSendBlocked(self: *SessionFlowControl) void {
        if (!self.data_limited) return;
        if (self.data.shouldSendBlocked()) |limit| self.data_blocked_pending = limit;
    }

    /// Session bytes delivered to the application, which earns the peer more
    /// credit. §5.6.4 counts these without the stream header, which is already
    /// gone by the time a stream joins a session. The draft names no error for
    /// a peer that overruns the limit, so nothing here can fail: an overrun
    /// raises the window rather than the connection.
    pub fn recordReceived(self: *SessionFlowControl, len: usize) void {
        self.data.addBytesRead(len);
    }

    /// Answer a WT_DATA_BLOCKED (§5.6.5); see `StreamLimit.peerBlockedAt`.
    pub fn peerDataBlockedAt(self: *SessionFlowControl, limit: u64) void {
        if (limit < self.data.receive_window) self.data_granted_initially = false;
    }

    /// The next capsule this session owes its peer, or null. Drain in a loop.
    pub fn nextCapsule(self: *SessionFlowControl, rtt: *const RttStats) ?Capsule {
        if (self.bidi.windowUpdate()) |n| return .{ .max_streams_bidi = n };
        if (self.uni.windowUpdate()) |n| return .{ .max_streams_uni = n };
        if (self.dataWindowUpdate(rtt)) |n| return .{ .max_data = n };
        if (self.bidi.takeBlocked()) |n| return .{ .streams_blocked_bidi = n };
        if (self.uni.takeBlocked()) |n| return .{ .streams_blocked_uni = n };
        if (self.takeDataBlocked()) |n| return .{ .data_blocked = n };
        return null;
    }

    fn dataWindowUpdate(self: *SessionFlowControl, rtt: *const RttStats) ?u64 {
        if (self.data.receive_window == 0) return null; // nothing to grant
        if (!self.data_granted_initially) {
            self.data_granted_initially = true;
            return self.data.receive_window;
        }
        return self.data.getWindowUpdate(rtt);
    }

    fn takeDataBlocked(self: *SessionFlowControl) ?u64 {
        const limit = self.data_blocked_pending orelse return null;
        self.data_blocked_pending = null;
        return limit;
    }
};

// Tests

test "StreamLimit: a peer that states nothing does not limit us" {
    var limit = StreamLimit.init(100);
    for (0..1000) |_| {
        try testing.expect(limit.canOpen());
        limit.open();
    }
    limit.recordBlocked();
    try testing.expectEqual(@as(?u64, null), limit.takeBlocked());
}

test "StreamLimit: an explicit zero does limit us, and blocks once per limit" {
    var limit = StreamLimit.init(100);
    limit.raiseSendLimit(0);
    try testing.expect(!limit.canOpen());

    limit.recordBlocked();
    try testing.expectEqual(@as(?u64, 0), limit.takeBlocked());
    // Same limit, same complaint: one capsule is enough.
    limit.recordBlocked();
    try testing.expectEqual(@as(?u64, null), limit.takeBlocked());

    // A raised limit re-arms it.
    limit.raiseSendLimit(2);
    try testing.expect(limit.canOpen());
    limit.open();
    limit.open();
    try testing.expect(!limit.canOpen());
    limit.recordBlocked();
    try testing.expectEqual(@as(?u64, 2), limit.takeBlocked());
}

test "StreamLimit: a stale WT_MAX_STREAMS does not withdraw credit" {
    var limit = StreamLimit.init(100);
    limit.raiseSendLimit(10);
    limit.raiseSendLimit(4);
    try testing.expectEqual(@as(?u64, 10), limit.max_send);
}

test "StreamLimit: the first grant goes out even with credit already advertised" {
    var limit = StreamLimit.init(100);
    try testing.expectEqual(@as(?u64, 100), limit.windowUpdate());
    try testing.expectEqual(@as(?u64, null), limit.windowUpdate());
}

test "StreamLimit: the grant slides forward once the peer spends half its window" {
    var limit = StreamLimit.init(100);
    _ = limit.windowUpdate();

    for (0..49) |_| limit.peerOpened();
    try testing.expectEqual(@as(?u64, null), limit.windowUpdate());

    limit.peerOpened(); // half the window spent: top it back up
    try testing.expectEqual(@as(?u64, 150), limit.windowUpdate());
    try testing.expectEqual(@as(?u64, null), limit.windowUpdate());
}

test "StreamLimit: a zero window grants nothing" {
    var limit = StreamLimit.init(0);
    try testing.expectEqual(@as(?u64, null), limit.windowUpdate());
    limit.peerOpened();
    try testing.expectEqual(@as(?u64, null), limit.windowUpdate());
}

test "SessionFlowControl: an unstated data limit does not block a send" {
    var fc = SessionFlowControl.init(.{ .max_streams_bidi = 100, .max_streams_uni = 100, .max_data = 1024 });
    try testing.expect(fc.canSend(1 << 20));
    fc.recordSent(1 << 20);
    try testing.expect(fc.canSend(1 << 20));
}

test "StreamLimit: re-reading the peer's SETTINGS does not undo a capsule" {
    var fc = SessionFlowControl.init(.{ .max_streams_bidi = 100, .max_streams_uni = 100, .max_data = 1024 });
    fc.applyPeerSettings(4, 4, 1024);
    fc.bidi.raiseSendLimit(9);
    fc.applyPeerSettings(4, 4, 1024);
    try testing.expectEqual(@as(?u64, 9), fc.bidi.max_send);
}

test "SessionFlowControl: a stated data limit blocks, and WT_MAX_DATA unblocks" {
    var fc = SessionFlowControl.init(.{ .max_streams_bidi = 100, .max_streams_uni = 100, .max_data = 1024 });
    fc.applyPeerSettings(null, null, 10);
    try testing.expect(fc.canSend(10));
    fc.recordSent(10);
    try testing.expect(!fc.canSend(1));

    fc.recordSendBlocked();
    fc.raiseSendDataLimit(20);
    try testing.expect(fc.canSend(10));
}

test "SessionFlowControl: capsules come out in credit-then-complaint order" {
    var rtt = RttStats{};
    var fc = SessionFlowControl.init(.{ .max_streams_bidi = 4, .max_streams_uni = 4, .max_data = 1024 });

    // The initial grant for each of the three limits.
    try testing.expectEqualDeep(Capsule{ .max_streams_bidi = 4 }, fc.nextCapsule(&rtt).?);
    try testing.expectEqualDeep(Capsule{ .max_streams_uni = 4 }, fc.nextCapsule(&rtt).?);
    try testing.expectEqualDeep(Capsule{ .max_data = 1024 }, fc.nextCapsule(&rtt).?);
    try testing.expectEqual(@as(?Capsule, null), fc.nextCapsule(&rtt));

    // Then a complaint, once we are actually held up.
    fc.bidi.raiseSendLimit(0);
    fc.bidi.recordBlocked();
    fc.applyPeerSettings(null, null, 0);
    fc.recordSendBlocked();
    try testing.expectEqualDeep(Capsule{ .streams_blocked_bidi = 0 }, fc.nextCapsule(&rtt).?);
    try testing.expectEqualDeep(Capsule{ .data_blocked = 0 }, fc.nextCapsule(&rtt).?);
    try testing.expectEqual(@as(?Capsule, null), fc.nextCapsule(&rtt));
}

test "SessionFlowControl: a session with no window to grant says nothing" {
    var rtt = RttStats{};
    var fc = SessionFlowControl.init(.{});
    try testing.expectEqual(@as(?Capsule, null), fc.nextCapsule(&rtt));
    fc.recordReceived(10);
    try testing.expectEqual(@as(?Capsule, null), fc.nextCapsule(&rtt));
}

test "SessionFlowControl: reading data earns the peer a raised WT_MAX_DATA" {
    var rtt = RttStats{};
    var fc = SessionFlowControl.init(.{ .max_streams_bidi = 100, .max_streams_uni = 100, .max_data = 1000 });
    _ = fc.nextCapsule(&rtt); // bidi
    _ = fc.nextCapsule(&rtt); // uni
    try testing.expectEqualDeep(Capsule{ .max_data = 1000 }, fc.nextCapsule(&rtt).?);

    fc.recordReceived(900);
    const next = fc.nextCapsule(&rtt).?;
    try testing.expect(next.max_data > 1000);
}
