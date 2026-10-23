const std = @import("std");
const sys = @import("../sys.zig");
const Allocator = std.mem.Allocator;
const posix = std.posix;
const io = @import("../io_compat.zig");

const connection = @import("connection.zig");
const packet = @import("packet.zig");
const protocol = @import("protocol.zig");
const stateless_reset = @import("stateless_reset.zig");
const quic_lb = @import("quic_lb.zig");
const tls13 = @import("tls13.zig");
const h3 = @import("../h3/connection.zig");
const h0 = @import("../h0/connection.zig");
const wt = @import("../webtransport/session.zig");
const crypto = @import("crypto.zig");
const frame_mod = @import("frame.zig");

/// Fixed-size CID key for use in HashMap lookups.
pub const CidKey = struct {
    buf: [20]u8 = @splat(0),
    len: u8 = 0,

    pub fn fromSlice(s: []const u8) CidKey {
        var key = CidKey{};
        key.len = @intCast(@min(s.len, 20));
        @memcpy(key.buf[0..key.len], s[0..key.len]);
        return key;
    }

    pub fn getSlice(self: *const CidKey) []const u8 {
        return self.buf[0..self.len];
    }
};

/// A peer's stateless reset token under a keyed PRF: the map lookup then
/// cannot time-leak token bytes (RFC 9000 §10.3.1).
pub const ResetKey = [16]u8;

fn randomSeed() u64 {
    var b: [8]u8 = undefined;
    sys.randomBytes(&b);
    return std.mem.readInt(u64, &b, .little);
}

/// What `max_handshakes_per_source` counts by: an IPv4 address, or an IPv6
/// /64, the least a host is given, so moving between its own addresses
/// earns it nothing.
pub const SourceKey = [16]u8;

/// IPv4 stays whole, whichever socket family it arrived on; under a /64
/// every IPv4 client of a dual-stack socket would be one source.
fn sourceKey(addr: *const posix.sockaddr.storage) SourceKey {
    var key = packet.mappedIp(addr);
    if (!std.mem.eql(u8, key[0..12], &packet.v4_mapped_prefix)) @memset(key[8..], 0);
    return key;
}

pub const SourceKeyContext = struct {
    seed: u64 = 0,

    pub fn hash(self: SourceKeyContext, key: SourceKey) u64 {
        return std.hash.Wyhash.hash(self.seed, &key);
    }

    pub fn eql(_: SourceKeyContext, a: SourceKey, b: SourceKey) bool {
        return std.mem.eql(u8, &a, &b);
    }
};

/// Hash/equality context for CidKey in HashMap.
pub const CidKeyContext = struct {
    /// Random per manager: clients choose the DCIDs hashed, and under a
    /// fixed seed colliding ones can be computed offline.
    seed: u64 = 0,

    pub fn hash(self: CidKeyContext, key: CidKey) u64 {
        return std.hash.Wyhash.hash(self.seed, key.buf[0..key.len]);
    }

    pub fn eql(_: CidKeyContext, a: CidKey, b: CidKey) bool {
        if (a.len != b.len) return false;
        return std.mem.eql(u8, a.buf[0..a.len], b.buf[0..b.len]);
    }
};

/// Per-connection wrapper holding the heap-allocated Connection and H3 state.
///
/// Every protocol layer is a pointer, not a value: a raw-QUIC connection
/// would otherwise pay for the H3 and WebTransport state it never touches,
/// and the table holds up to `max_connections` of them.
///
/// Heap-allocated, so its address is stable from `acceptConnection` until
/// `freeDeadEntries` releases it.
pub const ConnEntry = struct {
    conn: *connection.Connection,
    /// Counted in `ConnectionManager.handshakes` until its handshake is done
    /// or it is removed.
    handshaking: bool = false,
    /// While `handshaking`, the source charged for it under
    /// `max_handshakes_per_source`; null when it proved no address.
    source: ?SourceKey = null,
    /// Unique per manager, never reused.
    id: u64 = 0,
    h3_conn: ?*h3.H3Connection = null,
    h3_initialized: bool = false,
    /// A `raw_quic` WebTransport server's connection that negotiated a
    /// non-h3 ALPN: served as plain QUIC streams, with no H3 layer.
    raw_quic: bool = false,
    h0_conn: ?*h0.H0Connection = null,
    wt_conn: ?*wt.WebTransportConnection = null,

    /// Type-erased handler pointer for zero-copy datagram callback.
    datagram_handler_ctx: ?*anyopaque = null,

    /// Called when something queued data on this connection, so the owner can
    /// send it without waiting for its next I/O event.
    wake_fn: ?*const fn (ctx: *anyopaque) void = null,
    wake_ctx: ?*anyopaque = null,

    /// Called when data already received became deliverable (a resumed
    /// request body), so the owner polls again with nothing new on the
    /// wire. Takes `wake_ctx`.
    repoll_fn: ?*const fn (ctx: *anyopaque) void = null,

    /// While a server drains: when to send the final GOAWAY. The first one
    /// promises nothing, so it goes out at once; this one names the last
    /// request served and waits a PTO for requests already in flight.
    drain_final_goaway_at: ?i64 = null,

    // For raw QUIC protocol: track streams whose fin has been delivered to handler
    finished_streams: std.AutoArrayHashMapUnmanaged(u64, void) = .empty,

    /// The connection's own CIDs this entry holds in the routing map: at most
    /// one per LocalCidPool slot.
    registered_cids: [connection.LocalCidPool.MAX_POOL_SIZE]CidKey = @splat(.{}),
    registered_cid_count: u8 = 0,
    /// The pool's `generation` when `syncCids` last routed all of it.
    cid_pool_gen: ?u32 = null,
    /// The DCID the client chose for its first Initial, which it keeps using
    /// until it learns ours. Not in LocalCidPool.
    initial_dcid: CidKey = .{},

    // Keys this connection holds in `reset_token_map`, one per peer CID.
    reset_keys: [8]ResetKey = undefined,
    reset_key_count: u8 = 0,
    reset_pool_gen: ?u32 = null,

    /// Something for the owner's next pass to look at: a packet arrived, or
    /// the application queued, read or resumed data. A pass may skip an
    /// entry without it whose `deadline` has not come. Set through `mark`.
    needs_visit: bool = true,
    /// The next visit must also poll the protocol layers for events: the
    /// application did something that can surface one with nothing new on
    /// the wire. Frames say so through `Connection.app_frames` instead. Kept
    /// until a poll, so it outlasts a pass that had already gone by.
    needs_poll: bool = true,
    /// `conn.nextTimeoutNsAt` as of the owner's last visit, and this entry's
    /// key in `ConnectionManager.timers`: set through `setDeadline`. Between
    /// visits only a packet or a close can move a timer, and either brings a
    /// visit, which sets it again.
    deadline: ?i64 = null,

    /// The manager whose `to_visit` `mark` adds this entry to. Null once
    /// removed, so a stale Session's write can't queue it again, and for an
    /// entry built by hand. The manager must not move while it has entries.
    mgr: ?*ConnectionManager = null,
    /// In `mgr.to_visit`.
    queued: bool = false,
    /// Where it sits in `mgr.timers`, while it has a `deadline` there.
    timer_slot: u32 = no_slot,

    /// Tell the owner there is data to send; see `wake_fn`. A write raises
    /// no event, so this asks for a send, not a poll.
    pub fn wake(self: *ConnEntry) void {
        self.mark(false);
        if (self.wake_fn) |f| f(self.wake_ctx orelse return);
    }

    /// Ask the owner for another poll pass; see `repoll_fn`.
    pub fn repoll(self: *ConnEntry) void {
        self.mark(true);
        if (self.repoll_fn) |f| f(self.wake_ctx orelse return);
    }

    /// Have the owner's next pass visit this entry, and with `poll` poll its
    /// protocol layers too. Arms nothing: `wake` and `repoll` do that.
    pub fn mark(self: *ConnEntry, poll: bool) void {
        self.needs_visit = true;
        if (poll) self.needs_poll = true;
        if (self.mgr) |m| m.enqueue(self);
    }

    fn addRegisteredCid(self: *ConnEntry, key: CidKey) void {
        if (self.registered_cid_count < self.registered_cids.len) {
            self.registered_cids[self.registered_cid_count] = key;
            self.registered_cid_count += 1;
        }
    }

    fn hasRegisteredCid(self: *const ConnEntry, key: CidKey) bool {
        for (self.registered_cids[0..self.registered_cid_count]) |registered| {
            if (CidKeyContext.eql(.{}, registered, key)) return true;
        }
        return false;
    }

    fn removeRegisteredCid(self: *ConnEntry, key: CidKey) void {
        var i: usize = 0;
        while (i < self.registered_cid_count) {
            if (CidKeyContext.eql(.{}, self.registered_cids[i], key)) {
                // Swap-remove
                self.registered_cid_count -= 1;
                if (i < self.registered_cid_count) {
                    self.registered_cids[i] = self.registered_cids[self.registered_cid_count];
                }
                self.registered_cids[self.registered_cid_count] = CidKey{};
                return;
            }
            i += 1;
        }
    }
};

const no_slot = std.math.maxInt(u32);

const Timer = struct { at: i64, entry: *ConnEntry };

/// An entry taken out of service, plus the protocol layers detached from it.
/// The layers are unhooked from the entry immediately so stale `Session`
/// handles see null, but stay allocated until `freeDeadEntries`.
const DeadEntry = struct {
    entry: *ConnEntry,
    h3_conn: ?*h3.H3Connection,
    h0_conn: ?*h0.H0Connection,
    wt_conn: ?*wt.WebTransportConnection,
};

/// WebTransport borrows the H3 connection, so it is torn down first.
pub fn destroyProtocols(
    allocator: Allocator,
    wt_conn: ?*wt.WebTransportConnection,
    h3_conn: ?*h3.H3Connection,
    h0_conn: ?*h0.H0Connection,
) void {
    if (wt_conn) |p| {
        p.deinit();
        allocator.destroy(p);
    }
    if (h3_conn) |p| {
        p.deinit();
        allocator.destroy(p);
    }
    if (h0_conn) |p| {
        p.deinit();
        allocator.destroy(p);
    }
}

/// Smallest datagram that may open a connection or earn a Version
/// Negotiation reply (RFC 9000 14.1, 6).
pub const MIN_INITIAL_DATAGRAM: usize = 1200;

/// Shortest client-chosen DCID on a connection's first Initial (RFC 9000 7.2).
pub const MIN_INITIAL_DCID_LEN: usize = 8;

/// Largest datagram a stateless reset is never sent for: anything this short
/// may itself be a reset, and answering one invites a loop (RFC 9000 10.3.3).
pub const MIN_RESET_TRIGGER: usize = 43;

/// Token bucket for the replies we send without connection state — Version
/// Negotiation, stateless reset, CONNECTION_REFUSED. Each costs a send an
/// off-path attacker can trigger with a spoofed source, so their rate is
/// capped server-wide rather than tied to what arrives.
pub const ReplyLimiter = struct {
    /// Replies allowed per second, and the burst held in reserve. Zero
    /// disables stateless replies altogether.
    per_second: u32 = 200,
    tokens: u32 = 200,
    last_refill_ns: i64 = 0,

    pub fn allow(self: *ReplyLimiter, now: i64) bool {
        if (self.per_second == 0) return false;
        const elapsed = now - self.last_refill_ns;
        if (elapsed > 0) {
            const earned: u64 = @intCast(@divTrunc(@as(i128, elapsed) * @as(i128, self.per_second), std.time.ns_per_s));
            if (earned > 0) {
                self.tokens = @intCast(@min(@as(u64, self.tokens) + earned, self.per_second));
                self.last_refill_ns = now;
            }
        } else if (elapsed < 0) {
            self.last_refill_ns = now;
        }
        if (self.tokens == 0) return false;
        self.tokens -= 1;
        return true;
    }
};

/// One `ReplyLimiter` per kind of stateless reply, so junk that triggers one
/// kind — spoofed short headers soliciting resets, say — cannot spend the
/// budget that CONNECTION_REFUSED or Version Negotiation owe real clients.
pub const ReplyLimits = struct {
    version_negotiation: ReplyLimiter = .{},
    stateless_reset: ReplyLimiter = .{},
    refusal: ReplyLimiter = .{},

    /// Each kind gets `per_second`, with a burst of the same size.
    pub fn init(per_second: u32) ReplyLimits {
        const l: ReplyLimiter = .{ .per_second = per_second, .tokens = per_second };
        return .{ .version_negotiation = l, .stateless_reset = l, .refusal = l };
    }
};

/// Manages multiple QUIC connections, routing packets by DCID.
pub const ConnectionManager = struct {
    pub const DEFAULT_MAX_CONNECTIONS: usize = 256;

    allocator: Allocator,

    /// New connections past this many live ones are refused.
    max_connections: usize = DEFAULT_MAX_CONNECTIONS,
    next_entry_id: u64 = 1,
    cid_map: std.HashMap(CidKey, *ConnEntry, CidKeyContext, 80),
    entries: std.ArrayList(*ConnEntry),
    /// The entries `ConnEntry.mark` asked a pass to look at, each once, so a
    /// pass costs what is active rather than everything connected. The pass
    /// keeps the ones still marked when it is done; see `settleVisits`.
    to_visit: std.ArrayList(*ConnEntry) = .empty,
    /// Entries with a `deadline`, as a binary min-heap on it: when the next
    /// timer is due, and which, without asking every connection. The key is
    /// kept inline, so ordering it reads no entry.
    timers: std.ArrayList(Timer) = .empty,

    /// Peer-issued stateless reset tokens, so a reset from a client that
    /// lost state finds its connection even though its DCID is random.
    reset_token_map: std.AutoHashMapUnmanaged(ResetKey, *ConnEntry) = .empty,
    reset_lookup_key: [16]u8,
    /// Removals from the two maps above since their tombstones were cleared.
    /// std's HashMap never clears them itself, and every connection ID a
    /// server hands out is inserted and later removed: see `noteRemovals`.
    removed_since_rehash: usize = 0,

    // Server-wide shared config
    tls_config: tls13.TlsConfig,
    conn_config: connection.ConnectionConfig,
    retry_token_key: [16]u8,
    static_reset_key: [16]u8,
    local_cid_len: u8 = 8,

    /// When true, Initial packets without a valid token get a Retry response.
    require_retry: bool = false,

    /// Also send Retry once this many connections are live, so a loaded
    /// server spends state only on clients that proved their address.
    retry_threshold: ?usize = null,

    /// Connections still in their handshake past which a new client must
    /// first answer a Retry: a flood of Initials from spoofed addresses, which
    /// never finish, then costs no state, and established connections keep
    /// their room under `max_connections`.
    max_handshakes: usize = DEFAULT_MAX_CONNECTIONS / 4,
    /// Half-open connections, as far as `route` has seen; see `openHandshakes`.
    handshakes: usize = 0,

    /// Handshakes one source may hold open on an address it has proven,
    /// with a Retry or NEW_TOKEN token. Retry stops spoofed floods, but a
    /// host that answers every Retry would otherwise fill `max_connections`
    /// alone; past this, its new Initials are dropped until one of its
    /// handshakes ends. A source is an IPv4 address or an IPv6 /64.
    max_handshakes_per_source: usize = DEFAULT_MAX_CONNECTIONS / 16,
    /// Handshakes per source counted under `max_handshakes_per_source`.
    /// Seeded like `cid_map`: IPv6 sources choose their keys too.
    source_handshakes: std.HashMap(SourceKey, u32, SourceKeyContext, 80),

    /// When true, every new connection is answered with CONNECTION_REFUSED,
    /// as it is at `max_connections`. Set while a server drains.
    refuse_new: bool = false,
    /// Connections refused at `max_connections` since the last warning.
    refused_full: u64 = 0,
    refused_full_warned_at: ?i64 = null,

    /// Budgets for stateless replies; see `ReplyLimits`.
    reply_limits: ReplyLimits = .{},

    /// Answer a 1-RTT packet for an unknown CID with a stateless reset. Off
    /// when servers sharing `static_reset_key` can't be sure a packet reaches
    /// its connection's owner: another one's reset would hand the sender that
    /// connection's token (RFC 9000 §21.11).
    reset_unknown: bool = true,

    /// Report packets for another server as `foreign` instead of answering
    /// them with a stateless reset. Needs `conn_config.quic_lb`: a
    /// Handshake or 1-RTT packet whose unknown DCID decodes, under the same
    /// config_id, to a server id other than ours belongs to a sibling server
    /// — typically another worker thread on the same port.
    steer_foreign: bool = false,
    foreign_id: [15]u8 = undefined,

    /// `RecvInfo.now` for the datagrams being routed: when they were read,
    /// if their reader knows. A server's loop sets it for each batch it
    /// reads and clears it after; null has each packet read the clock.
    recv_time: ?i64 = null,

    // Deferred free queue: entries invalidated by removeConnection are held
    // here until freeDeadEntries() is called after all event processing.
    // acceptConnection reserves a slot for every entry it creates, so
    // removeConnection can never fail to queue one.
    dead_entries: std.ArrayList(DeadEntry) = .empty,

    /// Where a new client's first packet is opened on trial, so the datagram
    /// itself stays untouched for the connection that then decrypts it.
    initial_scratch: std.ArrayList(u8) = .empty,

    pub fn init(
        allocator: Allocator,
        tls_config: tls13.TlsConfig,
        conn_config: connection.ConnectionConfig,
        retry_token_key: [16]u8,
        static_reset_key: [16]u8,
    ) ConnectionManager {
        var lookup_key: [16]u8 = undefined;
        sys.randomBytes(&lookup_key);
        // Connections must advertise tokens under the key our resets use.
        var cc = conn_config;
        cc.static_reset_key = static_reset_key;
        return .{
            .allocator = allocator,
            .cid_map = std.HashMap(CidKey, *ConnEntry, CidKeyContext, 80).initContext(allocator, .{ .seed = randomSeed() }),
            .entries = .empty,
            .source_handshakes = std.HashMap(SourceKey, u32, SourceKeyContext, 80).initContext(allocator, .{ .seed = randomSeed() }),
            .reset_lookup_key = lookup_key,
            .tls_config = tls_config,
            .conn_config = cc,
            .retry_token_key = retry_token_key,
            .static_reset_key = static_reset_key,
            .local_cid_len = if (conn_config.quic_lb) |lb| quic_lb.cidLength(&lb) else 8,
        };
    }

    pub fn deinit(self: *ConnectionManager) void {
        self.initial_scratch.deinit(self.allocator);
        // Free deferred-dead entries first
        self.freeDeadEntries();
        // Clean up all live connections
        for (self.entries.items) |entry| {
            destroyProtocols(self.allocator, entry.wt_conn, entry.h3_conn, entry.h0_conn);
            entry.finished_streams.deinit(self.allocator);
            entry.conn.deinit();
            self.allocator.destroy(entry.conn);
            self.allocator.destroy(entry);
        }
        self.entries.deinit(self.allocator);
        self.dead_entries.deinit(self.allocator);
        self.to_visit.deinit(self.allocator);
        self.timers.deinit(self.allocator);
        self.cid_map.deinit();
        self.reset_token_map.deinit(self.allocator);
        self.source_handshakes.deinit();
    }

    fn resetKey(self: *const ConnectionManager, token: *const [16]u8) ResetKey {
        var out: ResetKey = undefined;
        std.crypto.auth.siphash.SipHash128(1, 3).create(&out, token, &self.reset_lookup_key);
        return out;
    }

    /// The connection whose peer issued the reset token `datagram` ends in.
    pub fn findByResetToken(self: *ConnectionManager, datagram: []const u8) ?*ConnEntry {
        if (datagram.len < stateless_reset.MIN_PACKET_LEN) return null;
        const key = self.resetKey(datagram[datagram.len - stateless_reset.TOKEN_LEN ..][0..stateless_reset.TOKEN_LEN]);
        return self.reset_token_map.get(key);
    }

    fn dropResetKeys(self: *ConnectionManager, entry: *ConnEntry) void {
        for (entry.reset_keys[0..entry.reset_key_count]) |k| {
            if (self.reset_token_map.get(k)) |owner| {
                if (owner == entry) _ = self.reset_token_map.remove(k);
            }
        }
        self.noteRemovals(entry.reset_key_count);
        entry.reset_key_count = 0;
    }

    /// Rehash the routing maps in place once removals pass a quarter of their
    /// capacity. A removal leaves a tombstone and returns the slot to the
    /// free count, so a long-running server's maps never grow past them;
    /// they fill with tombstones, and every packet's lookup probes through
    /// them. O(1) per removal, amortised.
    fn noteRemovals(self: *ConnectionManager, n: usize) void {
        self.removed_since_rehash += n;
        const capacity = self.cid_map.capacity() + self.reset_token_map.capacity() + self.source_handshakes.capacity();
        if (self.removed_since_rehash <= capacity / 4) return;
        self.removed_since_rehash = 0;
        if (self.cid_map.capacity() > 0) self.cid_map.rehash();
        if (self.reset_token_map.capacity() > 0) self.reset_token_map.rehash(std.hash_map.AutoContext(ResetKey){});
        if (self.source_handshakes.capacity() > 0) self.source_handshakes.rehash();
    }

    /// Mirror the peer CID pool's reset tokens into `reset_token_map`.
    fn syncResetTokens(self: *ConnectionManager, entry: *ConnEntry) void {
        const pool = &entry.conn.peer_cid_pool;
        if (entry.reset_pool_gen == pool.generation) return;
        entry.reset_pool_gen = pool.generation;
        self.dropResetKeys(entry);
        for (&pool.entries) |*e| {
            if (!e.occupied) continue;
            const key = self.resetKey(&e.stateless_reset_token);
            self.reset_token_map.put(self.allocator, key, entry) catch continue;
            entry.reset_keys[entry.reset_key_count] = key;
            entry.reset_key_count += 1;
        }
    }

    /// Look up a connection entry by destination CID.
    pub fn findByDcid(self: *ConnectionManager, dcid: []const u8) ?*ConnEntry {
        const key = CidKey.fromSlice(dcid);
        return self.cid_map.get(key);
    }

    /// Accept a new incoming connection from an Initial packet.
    /// Heap-allocates the Connection for pointer stability (needed by H3Connection).
    ///
    /// An `odcid` means the address is proven, by a Retry or NEW_TOKEN token,
    /// and charges the connection to its source: `error.SourceBusy` once that
    /// source holds `max_handshakes_per_source`.
    pub fn acceptConnection(
        self: *ConnectionManager,
        header: packet.Header,
        local: posix.sockaddr.storage,
        remote: posix.sockaddr.storage,
        odcid: ?[]const u8,
        retry_scid: ?[]const u8,
    ) !*ConnEntry {
        if (self.entries.items.len >= self.max_connections) {
            return error.TooManyConnections;
        }
        // No Retry is left to ask of a proven address: this is its bound.
        const source: ?SourceKey = if (odcid != null) sourceKey(&remote) else null;
        if (source) |s| {
            if ((self.source_handshakes.get(s) orelse 0) >= self.max_handshakes_per_source) return error.SourceBusy;
            try self.source_handshakes.ensureUnusedCapacity(1);
        }
        try self.entries.ensureUnusedCapacity(self.allocator, 1);
        try self.dead_entries.ensureTotalCapacity(
            self.allocator,
            self.entries.items.len + self.dead_entries.items.len + 1,
        );
        // Each holds a live entry at most once, so neither has to grow later.
        try self.to_visit.ensureTotalCapacity(self.allocator, self.entries.items.len + 1);
        try self.timers.ensureTotalCapacity(self.allocator, self.entries.items.len + 1);

        // Heap-allocate Connection, then build it in place: the by-value
        // accept() would stage all ~185 KB on the stack first.
        const conn = try self.allocator.create(connection.Connection);
        errdefer self.allocator.destroy(conn);
        try connection.Connection.acceptInto(
            conn,
            self.allocator,
            header,
            local,
            remote,
            true, // is_server
            self.conn_config,
            self.tls_config,
            odcid,
            retry_scid,
        );

        // Create entry
        errdefer conn.deinit();
        const entry = try self.allocator.create(ConnEntry);
        errdefer self.allocator.destroy(entry);
        entry.* = .{ .conn = conn, .id = self.next_entry_id };
        self.next_entry_id += 1;

        // Register server's SCID in the routing map
        const scid_key = CidKey.fromSlice(conn.scid[0..conn.scid_len]);
        try self.cid_map.put(scid_key, entry);
        entry.addRegisteredCid(scid_key);
        errdefer _ = self.cid_map.remove(scid_key);

        // Also register the client's initial DCID so retransmitted Initials route correctly
        const client_dcid_key = CidKey.fromSlice(header.dcid);
        try self.cid_map.put(client_dcid_key, entry);
        entry.initial_dcid = client_dcid_key;

        self.entries.appendAssumeCapacity(entry);
        entry.mgr = self;
        entry.mark(true);
        entry.handshaking = true;
        self.handshakes += 1;
        if (source) |s| {
            const n = self.source_handshakes.getOrPutAssumeCapacity(s);
            n.value_ptr.* = if (n.found_existing) n.value_ptr.* + 1 else 1;
            entry.source = s;
        }

        return entry;
    }

    /// Synchronize the CID routing map with the connection's LocalCidPool.
    ///
    /// The pool can hand a retired CID's slot to its replacement before this
    /// runs, so what the entry registered is checked against the pool's active
    /// CIDs rather than read off the pool's retired flags.
    ///
    /// Runs for every packet, so it does nothing until the pool's generation
    /// moves, or while a CID it could not route last time is still waiting.
    pub fn syncCids(self: *ConnectionManager, entry: *ConnEntry) void {
        defer self.syncResetTokens(entry);
        const pool = &entry.conn.local_cid_pool;
        if (entry.cid_pool_gen == pool.generation) return;

        var removed: usize = 0;
        var i: usize = 0;
        while (i < entry.registered_cid_count) {
            const key = entry.registered_cids[i];
            if (poolHasActive(pool, key)) {
                i += 1;
                continue;
            }
            self.unrouteCid(key, entry);
            entry.removeRegisteredCid(key);
            removed += 1;
        }

        var unrouted: usize = 0;
        for (&pool.entries) |*cid_entry| {
            if (!cid_entry.occupied or cid_entry.retired or cid_entry.cid_len == 0) continue;
            const key = CidKey.fromSlice(cid_entry.getCid());
            if (entry.hasRegisteredCid(key)) continue;
            unrouted += 1;
            // Untracked, a map entry would outlive the connection.
            if (entry.registered_cid_count == entry.registered_cids.len) break;
            const slot = self.cid_map.getOrPut(key) catch continue;
            if (slot.found_existing and slot.value_ptr.* != entry) continue; // another connection's
            slot.value_ptr.* = entry;
            entry.addRegisteredCid(key);
            unrouted -= 1;
        }
        self.noteRemovals(removed);
        // One left out is tried again with the next packet.
        entry.cid_pool_gen = if (unrouted == 0) pool.generation else null;
    }

    fn poolHasActive(pool: *const connection.LocalCidPool, key: CidKey) bool {
        for (&pool.entries) |*c| {
            if (c.occupied and !c.retired and std.mem.eql(u8, c.getCid(), key.getSlice())) return true;
        }
        return false;
    }

    /// Removes `key` from routing only while it still routes to `entry`.
    fn unrouteCid(self: *ConnectionManager, key: CidKey, entry: *ConnEntry) void {
        if (self.cid_map.get(key)) |owner| {
            if (owner == entry) _ = self.cid_map.remove(key);
        }
    }

    /// Remove a terminated connection. Invalidates the entry immediately
    /// (nulls wt_conn, removes from routing) and defers memory freeing so
    /// that any stale Session pointers safely see wt_conn == null instead
    /// of accessing freed memory.
    pub fn removeConnection(self: *ConnectionManager, entry: *ConnEntry) void {
        // Unregister all CIDs from the routing map
        for (entry.registered_cids[0..entry.registered_cid_count]) |key| self.unrouteCid(key, entry);
        if (entry.initial_dcid.len > 0) self.unrouteCid(entry.initial_dcid, entry);
        self.noteRemovals(entry.registered_cid_count + 1);
        self.dropResetKeys(entry);

        // Detach the transport layers so stale Session pointers are safe:
        // Session.sendDatagram/sendStreamData check `if (entry.wt_conn)` and
        // skip the send rather than dereference. The objects themselves are
        // freed with the entry, not here.
        const dead: DeadEntry = .{
            .entry = entry,
            .h3_conn = entry.h3_conn,
            .h0_conn = entry.h0_conn,
            .wt_conn = entry.wt_conn,
        };
        entry.wt_conn = null;
        entry.h3_conn = null;
        entry.h0_conn = null;

        self.endHandshake(entry);

        // Out of both pass structures. A pass removes the entry it is
        // visiting and carries on at the same slot: `to_visit` shifts the
        // rest down, keeping their order, and `entries` below swaps its last in.
        if (entry.queued) {
            if (std.mem.indexOfScalar(*ConnEntry, self.to_visit.items, entry)) |i| _ = self.to_visit.orderedRemove(i);
            entry.queued = false;
        }
        self.setDeadline(entry, null);
        entry.mgr = null;

        // Swap-remove from entries list
        var idx: usize = 0;
        while (idx < self.entries.items.len) : (idx += 1) {
            if (self.entries.items[idx] == entry) {
                _ = self.entries.swapRemove(idx);
                break;
            }
        }

        // Queue for deferred free (entry memory stays valid until freeDeadEntries).
        // Never allocates for an entry acceptConnection made; only one added
        // by hand can hit OOM here, and freeing it now beats leaking it.
        self.dead_entries.append(self.allocator, dead) catch self.freeDead(dead);
    }

    /// Free entries that were invalidated by removeConnection.
    /// Call after all event processing is complete for the current cycle.
    pub fn freeDeadEntries(self: *ConnectionManager) void {
        for (self.dead_entries.items) |dead| self.freeDead(dead);
        self.dead_entries.clearRetainingCapacity();
    }

    fn freeDead(self: *ConnectionManager, dead: DeadEntry) void {
        destroyProtocols(self.allocator, dead.wt_conn, dead.h3_conn, dead.h0_conn);
        const entry = dead.entry;
        entry.finished_streams.deinit(self.allocator);
        entry.conn.deinit();
        self.allocator.destroy(entry.conn);
        self.allocator.destroy(entry);
    }

    fn enqueue(self: *ConnectionManager, e: *ConnEntry) void {
        if (e.queued) return;
        e.queued = true;
        self.to_visit.appendAssumeCapacity(e);
    }

    /// Put `to_visit` in connection order, by `ConnEntry.id`. A pass then
    /// sends to each peer at the same point in its batches as the last pass
    /// did, rather than wherever this pass's traffic happened to mark it,
    /// which at 2048 clients added 0.3 ms to the median tick's jitter.
    pub fn orderVisits(self: *ConnectionManager) void {
        std.sort.pdq(*ConnEntry, self.to_visit.items, {}, struct {
            fn lt(_: void, a: *ConnEntry, b: *ConnEntry) bool {
                return a.id < b.id;
            }
        }.lt);
    }

    /// Ends a pass over `to_visit`: what the pass finished with leaves it,
    /// and what was marked again, or still wants a visit, stays for the next.
    pub fn settleVisits(self: *ConnectionManager) void {
        var kept: usize = 0;
        for (self.to_visit.items) |e| {
            if (e.needs_visit or e.needs_poll) {
                self.to_visit.items[kept] = e;
                kept += 1;
            } else e.queued = false;
        }
        self.to_visit.shrinkRetainingCapacity(kept);
    }

    /// Set `entry.deadline`, keeping `timers` ordered on it. A removed or
    /// hand-built entry has no place there and gets only the field.
    pub fn setDeadline(self: *ConnectionManager, entry: *ConnEntry, deadline: ?i64) void {
        entry.deadline = deadline;
        const at = deadline orelse return self.dropTimer(entry);
        if (entry.mgr == null) return self.dropTimer(entry);
        if (entry.timer_slot == no_slot) {
            entry.timer_slot = @intCast(self.timers.items.len);
            self.timers.appendAssumeCapacity(.{ .at = at, .entry = entry });
        } else {
            const t = &self.timers.items[entry.timer_slot];
            if (t.at == at) return;
            t.at = at;
        }
        self.siftTimer(entry.timer_slot);
    }

    /// The earliest `deadline` among the entries.
    pub fn nextDeadline(self: *const ConnectionManager) ?i64 {
        return if (self.timers.items.len > 0) self.timers.items[0].at else null;
    }

    /// Queue every entry due by `now` for the pass, out of `timers` until
    /// its visit sets the next deadline.
    pub fn queueDue(self: *ConnectionManager, now: i64) void {
        while (self.timers.items.len > 0 and self.timers.items[0].at <= now) {
            const e = self.timers.items[0].entry;
            self.dropTimer(e);
            self.enqueue(e);
        }
    }

    fn dropTimer(self: *ConnectionManager, entry: *ConnEntry) void {
        const slot = entry.timer_slot;
        if (slot == no_slot) return;
        entry.timer_slot = no_slot;
        const last = self.timers.pop().?;
        if (last.entry == entry) return;
        self.timers.items[slot] = last;
        last.entry.timer_slot = slot;
        self.siftTimer(slot);
    }

    /// Move the timer at `slot` up or down to where its deadline belongs.
    fn siftTimer(self: *ConnectionManager, slot: u32) void {
        const items = self.timers.items;
        const t = items[slot];
        var i: usize = slot;
        while (i > 0) {
            const parent = (i - 1) / 2;
            if (items[parent].at <= t.at) break;
            items[i] = items[parent];
            items[i].entry.timer_slot = @intCast(i);
            i = parent;
        }
        while (true) {
            var child = 2 * i + 1;
            if (child >= items.len) break;
            if (child + 1 < items.len and items[child + 1].at < items[child].at) child += 1;
            if (items[child].at >= t.at) break;
            items[i] = items[child];
            items[i].entry.timer_slot = @intCast(i);
            i = child;
        }
        items[i] = t;
        t.entry.timer_slot = @intCast(i);
    }

    /// Result of processing a received UDP datagram.
    pub const RecvAction = union(enum) {
        /// Datagram was delivered to an existing or newly accepted connection.
        processed: *ConnEntry,
        /// A response packet (VN, Retry, or Stateless Reset) was written to
        /// out_buf and should be sent back to the source address.
        send_response: []const u8,
        /// Datagram was unroutable or invalid; no action needed.
        dropped: void,
        /// Its DCID names another server (see `steer_foreign`); nothing was
        /// processed. The QUIC-LB server id it decoded to, valid until the
        /// next call.
        foreign: []const u8,
    };

    /// Process a raw UDP datagram: route by DCID, handle version negotiation,
    /// retry tokens, stateless reset, accept new connections, and parse
    /// coalesced packets (RFC 9000 §12.2).
    ///
    /// The application should send `send_response` data back to the source.
    pub fn recvDatagram(
        self: *ConnectionManager,
        bytes: []u8,
        from: posix.sockaddr.storage,
        local: posix.sockaddr.storage,
        ecn_val: u2,
        out_buf: []u8,
    ) RecvAction {
        return self.route(bytes, from, local, ecn_val, out_buf, self.steer_foreign);
    }

    /// `recvDatagram` for a datagram another server already reported as
    /// `foreign` and handed to us: never reported as foreign again, so a
    /// DCID nobody owns cannot bounce between servers.
    pub fn recvHandedOver(
        self: *ConnectionManager,
        bytes: []u8,
        from: posix.sockaddr.storage,
        local: posix.sockaddr.storage,
        ecn_val: u2,
        out_buf: []u8,
    ) RecvAction {
        return self.route(bytes, from, local, ecn_val, out_buf, false);
    }

    fn route(
        self: *ConnectionManager,
        bytes: []u8,
        from: posix.sockaddr.storage,
        local: posix.sockaddr.storage,
        ecn_val: u2,
        out_buf: []u8,
        steer: bool,
    ) RecvAction {
        var fbs = io.fixedBufferStream(bytes);
        var current_entry: ?*ConnEntry = null;
        // Out here: the new connection's transport parameters point into it
        // until recv() below has answered the ClientHello.
        var retry_token: ?packet.ValidatedToken = null;

        while (fbs.seek < bytes.len) {
            // All valid QUIC packets have the fixed bit (0x40) set.
            if (bytes[fbs.seek] & 0x40 == 0) break;

            const pkt_start = fbs.seek;
            var header = packet.Header.parse(&fbs, self.local_cid_len) catch break;
            // Clamped: a Length past the datagram would wrap a 32-bit usize.
            const full_size = @min(fbs.seek - pkt_start +| header.remainder_len, bytes.len - pkt_start);

            // Version negotiation (RFC 9000 §6). Only for a datagram as large
            // as a real Initial, so it cannot amplify a spoofed small one.
            if (header.version != 0 and !protocol.isSupportedVersion(header.version)) {
                if (bytes.len < MIN_INITIAL_DATAGRAM) return .{ .dropped = {} };
                if (!self.reply_limits.version_negotiation.allow(sys.nanoTimestamp())) return .{ .dropped = {} };
                var vn_fbs = io.fixedBufferStream(out_buf);
                packet.negotiateVersion(header, &vn_fbs) catch return .{ .dropped = {} };
                return .{ .send_response = vn_fbs.buffered() };
            }

            // Route to existing connection by DCID
            var entry = current_entry orelse self.findByDcid(header.dcid);

            if (entry == null and current_entry == null and header.packet_type == .one_rtt) {
                if (self.findByResetToken(bytes)) |e| {
                    // Now draining: a visit sets the deadline that ends it.
                    if (e.conn.handleStatelessReset(bytes)) e.mark(false);
                    return .{ .processed = e };
                }
            }

            if (entry == null) {
                // Initials open a connection wherever they land, and 0-RTT
                // carries the client's own DCID, which encodes nothing.
                if (steer and current_entry == null and
                    (header.packet_type == .one_rtt or header.packet_type == .handshake))
                {
                    if (self.foreignServerId(header.dcid)) |id| return .{ .foreign = id };
                }
                if (header.packet_type != .initial) {
                    // Short-header for unknown CID: stateless reset (RFC 9000 §10.3)
                    if (header.packet_type == .one_rtt and full_size >= MIN_RESET_TRIGGER and self.reset_unknown and
                        self.reply_limits.stateless_reset.allow(sys.nanoTimestamp()))
                    {
                        // RFC 9000 §10.3.3: response SHOULD be smaller than the trigger
                        // packet to prevent loops (a reset responding to a reset).
                        // Also MUST NOT be 3x or more larger (amplification limit).
                        const sr_max = @min(full_size -| 1, out_buf.len);
                        const sr_len = stateless_reset.generatePacket(out_buf, sr_max, self.static_reset_key, header.dcid);
                        if (sr_len > 0) {
                            return .{ .send_response = out_buf[0..sr_len] };
                        }
                    }
                    return .{ .dropped = {} };
                }

                // RFC 9000 14.1, 7.2: a connection opens only from a full-size
                // datagram with an unpredictable DCID. Anything less is dropped
                // before it costs a connection's state.
                if (bytes.len < MIN_INITIAL_DATAGRAM or header.dcid.len < MIN_INITIAL_DCID_LEN) {
                    return .{ .dropped = {} };
                }
                if (!self.initialOpens(header, bytes[pkt_start..][0..full_size], fbs.seek - pkt_start)) {
                    return .{ .dropped = {} };
                }

                if (self.refuse_new or self.entries.items.len >= self.max_connections) {
                    if (!self.refuse_new) self.noteFull();
                    return self.refuse(header, out_buf);
                }

                // A token is honoured whether or not Retry is required now:
                // load may have dropped since we sent the Retry, and its
                // client will insist on seeing retry_source_connection_id.
                const token = header.token orelse &[_]u8{};
                const need_retry = self.require_retry or
                    (if (self.retry_threshold) |n| self.entries.items.len >= n else false) or
                    self.openHandshakes() >= self.max_handshakes;
                if (token.len > 0) {
                    retry_token = packet.validateRetryToken(token, header.dcid, from, self.retry_token_key) catch null;
                    if (retry_token) |*vt| {
                        entry = self.acceptConnection(header, local, from, vt.getOdcid(), vt.getRetryScid()) catch
                            return .{ .dropped = {} };
                    } else if (packet.validateNewToken(token, from, self.retry_token_key)) {
                        // Valid NEW_TOKEN — the address is proven already
                        entry = self.acceptConnection(header, local, from, header.dcid, null) catch
                            return .{ .dropped = {} };
                    } else if (need_retry) {
                        return .{ .dropped = {} };
                    }
                } else if (need_retry) {
                    var retry_scid: [8]u8 = undefined;
                    sys.randomBytes(&retry_scid);

                    var token_buf: [packet.TOKEN_MAX_LEN]u8 = undefined;
                    const token_len = packet.generateRetryToken(
                        &token_buf,
                        header.dcid,
                        &retry_scid,
                        from,
                        self.retry_token_key,
                    ) catch return .{ .dropped = {} };

                    var retry_fbs = io.fixedBufferStream(out_buf);
                    packet.retry(header, &retry_scid, token_buf[0..token_len], &retry_fbs) catch
                        return .{ .dropped = {} };
                    return .{ .send_response = retry_fbs.buffered() };
                }
                if (entry == null) {
                    entry = self.acceptConnection(header, local, from, null, null) catch
                        return .{ .dropped = {} };
                }
            }

            // ReleaseSmall has no safety checks, so `entry.?` on a null
            // optional is a wild dereference rather than a panic. Every branch
            // above assigns or returns; drop the datagram if that ever changes.
            const e = entry orelse return .{ .dropped = {} };
            // Only count datagram_size for the first packet in a coalesced datagram
            // to avoid double-counting in amplification limit calculations.
            const dg_size: u64 = if (current_entry == null) bytes.len else 0;
            current_entry = e;
            const recv_info: connection.RecvInfo = .{ .to = local, .from = from, .ecn = ecn_val, .datagram_size = dg_size, .now = self.recv_time };
            e.mark(false);
            e.conn.recv(&header, &fbs, recv_info) catch |err| {
                if (err == error.UndecryptablePacket and pkt_start == 0) _ = e.conn.handleStatelessReset(bytes);
                break;
            };
            self.syncCids(e);

            const next_pos = pkt_start + full_size;
            if (fbs.seek < next_pos) fbs.seek = next_pos;
        }

        if (current_entry) |e| {
            self.noteHandshakeDone(e);
            return .{ .processed = e };
        }
        return .{ .dropped = {} };
    }

    /// The server id `dcid` encodes, if it is another server's under our
    /// QUIC-LB config.
    fn foreignServerId(self: *ConnectionManager, dcid: []const u8) ?[]const u8 {
        const lb = &(self.conn_config.quic_lb orelse return null);
        if (dcid.len != quic_lb.cidLength(lb)) return null;
        if (quic_lb.extractConfigId(dcid[0]) != lb.config_id) return null;
        const n: usize = lb.server_id_len;
        if (!quic_lb.extractServerId(lb, dcid, &self.foreign_id)) return null;
        if (std.mem.eql(u8, self.foreign_id[0..n], lb.server_id[0..n])) return null;
        return self.foreign_id[0..n];
    }

    /// A full server turns clients away without them knowing why, so say
    /// so, at most every 10 s.
    fn noteFull(self: *ConnectionManager) void {
        self.refused_full += 1;
        const now = sys.nanoTimestamp();
        if (self.refused_full_warned_at) |at| if (now - at < 10 * std.time.ns_per_s) return;
        std.log.warn("max_connections ({d}) reached: refused {d} new connection(s)", .{ self.max_connections, self.refused_full });
        self.refused_full = 0;
        self.refused_full_warned_at = now;
    }

    /// Answer an Initial we will not serve with CONNECTION_REFUSED (RFC 9000
    /// 5.2.2), sealed with the Initial keys its own DCID derives, so the
    /// client fails fast instead of retransmitting into silence.
    fn noteHandshakeDone(self: *ConnectionManager, e: *ConnEntry) void {
        if (e.handshaking and e.conn.state == .connected) self.endHandshake(e);
    }

    /// Takes `e` out of `handshakes`, and out of its source's count.
    fn endHandshake(self: *ConnectionManager, e: *ConnEntry) void {
        if (!e.handshaking) return;
        e.handshaking = false;
        self.handshakes -= 1;
        const source = e.source orelse return;
        e.source = null;
        const n = self.source_handshakes.getPtr(source) orelse return;
        n.* -= 1;
        if (n.* == 0) {
            _ = self.source_handshakes.remove(source);
            self.noteRemovals(1);
        }
    }

    /// Half-open connections, recounted at the cap: a handshake can also
    /// finish outside `route`, when a held packet is replayed later.
    fn openHandshakes(self: *ConnectionManager) usize {
        if (self.handshakes < self.max_handshakes) return self.handshakes;
        for (self.entries.items) |e| self.noteHandshakeDone(e);
        return self.handshakes;
    }

    /// Whether `pkt`, an unknown client's first packet, opens under the
    /// Initial keys its DCID derives. They are public, so this proves only
    /// that the bytes are a QUIC Initial and not noise, which is what earns
    /// them a connection's state. `pn_offset` is where the header ends.
    fn initialOpens(self: *ConnectionManager, header: packet.Header, pkt: []const u8, pn_offset: usize) bool {
        const keys = crypto.deriveInitialKeyMaterial(header.dcid, header.version, true) catch return false;
        self.initial_scratch.resize(self.allocator, pkt.len) catch return false;
        const copy = self.initial_scratch.items;
        @memcpy(copy, pkt);
        var h = header;
        h.packet_start = 0;
        var fbs = io.fixedBufferStream(copy);
        fbs.seek = pn_offset;
        const space: packet.PacketNumSpace = .{ .crypto_open = keys[0] };
        _ = packet.decrypt(&h, &fbs, &space) catch return false;
        return true;
    }

    fn refuse(self: *ConnectionManager, header: packet.Header, out_buf: []u8) RecvAction {
        if (!self.reply_limits.refusal.allow(sys.nanoTimestamp())) return .{ .dropped = {} };
        const len = writeRefusal(header, out_buf) catch return .{ .dropped = {} };
        return .{ .send_response = out_buf[0..len] };
    }

    /// Process timeouts and remove a closed connection.
    /// Call this per-entry after app-specific polling (H3, WT, etc.).
    /// Returns true if the connection is still alive, false if it was removed
    /// (caller should `continue` without incrementing the index).
    pub fn tickEntry(self: *ConnectionManager, entry: *ConnEntry) bool {
        entry.conn.onTimeout() catch |err| {
            std.log.warn("onTimeout error: {}", .{err});
        };
        if (entry.conn.isClosed()) {
            self.removeConnection(entry);
            return false;
        }
        return true;
    }

    /// Return the number of active connections.
    pub fn connectionCount(self: *const ConnectionManager) usize {
        return self.entries.items.len;
    }
};

/// Write an Initial packet carrying CONNECTION_CLOSE(CONNECTION_REFUSED) in
/// reply to the client Initial `header`. Returns its length.
pub fn writeRefusal(header: packet.Header, out: []u8) !usize {
    const seal = (try crypto.deriveInitialKeyMaterial(header.dcid, header.version, true))[1];

    var fbs = io.fixedBufferStream(out);
    const w = &fbs;
    const pn_len = 1;
    try w.writeByte(packet.encodeLongHeaderTypeBits(.initial, header.version) | (pn_len - 1));
    try w.writeInt(u32, header.version, .big);
    try w.writeByte(@intCast(header.scid.len));
    try w.writeAll(header.scid);
    try w.writeByte(@intCast(header.dcid.len));
    try w.writeAll(header.dcid);
    try w.writeByte(0); // token length

    // CONNECTION_CLOSE (0x1c), CONNECTION_REFUSED, frame type 0, no reason.
    const payload = [_]u8{ 0x1c, @backingInt(frame_mod.TransportError.connection_refused), 0x00, 0x00 };
    const tag_len = 16;
    const length = pn_len + payload.len + tag_len;
    try packet.writeVarInt(w, length);
    const pn_offset = fbs.seek;
    try w.writeByte(0); // packet number 0

    const header_len = fbs.seek;
    if (out.len < header_len + payload.len + tag_len) return error.NoSpaceLeft;
    const sealed = seal.encryptPayload(0, out[0..header_len], &payload, out[header_len..]);
    const total = header_len + sealed;
    seal.applyHeaderProtection(out[0..total], pn_offset, pn_len);
    return total;
}

// Tests
test "the CID map hashes under a seed of its own" {
    // Clients choose the DCIDs it hashes; under a fixed seed, colliding ones
    // can be computed offline and every lookup made to walk them.
    var a = testManager(std.testing.allocator);
    defer a.deinit();
    var b = testManager(std.testing.allocator);
    defer b.deinit();
    const key = CidKey.fromSlice(&.{ 1, 2, 3, 4, 5, 6, 7, 8 });
    try std.testing.expect(a.cid_map.ctx.hash(key) != b.cid_map.ctx.hash(key));
}

test "CidKey roundtrip" {
    const cid = [_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
    const key = CidKey.fromSlice(&cid);
    try std.testing.expectEqual(@as(u8, 8), key.len);
    try std.testing.expectEqualSlices(u8, &cid, key.getSlice());
}

test "CidKey equality" {
    const a = CidKey.fromSlice(&[_]u8{ 0x01, 0x02, 0x03 });
    const b = CidKey.fromSlice(&[_]u8{ 0x01, 0x02, 0x03 });
    const c = CidKey.fromSlice(&[_]u8{ 0x01, 0x02, 0x04 });

    try std.testing.expect(CidKeyContext.eql(.{}, a, b));
    try std.testing.expect(!CidKeyContext.eql(.{}, a, c));
}

test "CidKey different lengths" {
    const a = CidKey.fromSlice(&[_]u8{ 0x01, 0x02, 0x03 });
    const b = CidKey.fromSlice(&[_]u8{ 0x01, 0x02, 0x03, 0x04 });

    try std.testing.expect(!CidKeyContext.eql(.{}, a, b));
}

test "ConnEntry registered CIDs" {
    var entry = ConnEntry{ .conn = undefined };

    const key1 = CidKey.fromSlice(&[_]u8{ 0x01, 0x02 });
    const key2 = CidKey.fromSlice(&[_]u8{ 0x03, 0x04 });

    entry.addRegisteredCid(key1);
    entry.addRegisteredCid(key2);
    try std.testing.expectEqual(@as(u8, 2), entry.registered_cid_count);
    try std.testing.expect(entry.hasRegisteredCid(key1));
    try std.testing.expect(entry.hasRegisteredCid(key2));

    entry.removeRegisteredCid(key1);
    try std.testing.expectEqual(@as(u8, 1), entry.registered_cid_count);
    try std.testing.expect(!entry.hasRegisteredCid(key1));
    try std.testing.expect(entry.hasRegisteredCid(key2));
}

test "removeConnection detaches the protocol layers, freeDeadEntries frees them" {
    const alloc = std.testing.allocator;

    const tls_config: tls13.TlsConfig = .{
        .cert_chain_der = &.{},
        .private_key_bytes = &.{},
        .alpn = &.{},
    };
    var mgr = ConnectionManager.init(alloc, tls_config, .{}, @splat(0), @splat(0));
    defer mgr.deinit();

    const conn = try alloc.create(connection.Connection);
    try connection.connectInto(conn, alloc, "example.com", .{}, null, null);

    const entry = try alloc.create(ConnEntry);
    entry.* = .{ .conn = conn };
    try mgr.entries.append(alloc, entry);

    const h3c = try alloc.create(h3.H3Connection);
    h3c.* = h3.H3Connection.init(alloc, conn, true);
    entry.h3_conn = h3c;

    const wtc = try alloc.create(wt.WebTransportConnection);
    wtc.* = wt.WebTransportConnection.init(alloc, h3c, conn, true);
    entry.wt_conn = wtc;

    mgr.removeConnection(entry);

    // Detached at once, so a Session still holding this entry sees null
    // rather than dereferencing a layer that is about to go away.
    try std.testing.expect(entry.h3_conn == null);
    try std.testing.expect(entry.wt_conn == null);
    try std.testing.expectEqual(@as(usize, 0), mgr.entries.items.len);

    // Freed only here — testing.allocator fails the test if either layer,
    // or the hash maps they own, is left behind.
    mgr.freeDeadEntries();
}

test "max_connections is configurable past 256, and every removed entry is freed" {
    const alloc = std.testing.allocator;
    const tls_config: tls13.TlsConfig = .{
        .cert_chain_der = &.{},
        .private_key_bytes = &.{},
        .alpn = &.{},
    };
    var mgr = ConnectionManager.init(alloc, tls_config, .{}, @splat(0), @splat(0));
    defer mgr.deinit();
    mgr.max_connections = 300;

    const local = std.mem.zeroes(posix.sockaddr.storage);
    var dcids: [301][8]u8 = undefined;
    const scid: [8]u8 = @splat(0xaa);
    for (&dcids, 0..) |*d, i| {
        std.mem.writeInt(u64, d, i + 1, .big);
        const header: packet.Header = .{
            .version = protocol.SUPPORTED_VERSIONS[0],
            .packet_type = .initial,
            .dcid = d,
            .scid = &scid,
        };
        const accepted = mgr.acceptConnection(header, local, local, null, null);
        if (i < 300) {
            const e = try accepted;
            try std.testing.expect(e.id != 0);
        } else {
            try std.testing.expectError(error.TooManyConnections, accepted);
        }
    }
    try std.testing.expectEqual(@as(usize, 300), mgr.connectionCount());

    // All at once, in one cycle: more than a fixed 256-slot queue would hold.
    while (mgr.entries.items.len > 0) mgr.removeConnection(mgr.entries.items[0]);
    try std.testing.expectEqual(@as(usize, 300), mgr.dead_entries.items.len);
    mgr.freeDeadEntries();
}

test "connections coming and going leave the CID map free slots to stop a lookup at" {
    const alloc = std.testing.allocator;
    var mgr = testManager(alloc);
    defer mgr.deinit();

    const local = std.mem.zeroes(posix.sockaddr.storage);
    const scid: [8]u8 = @splat(0xaa);
    var dcid: [8]u8 = undefined;
    for (0..3000) |i| {
        std.mem.writeInt(u64, &dcid, i + 1, .big);
        const header: packet.Header = .{
            .version = protocol.SUPPORTED_VERSIONS[0],
            .packet_type = .initial,
            .dcid = &dcid,
            .scid = &scid,
        };
        _ = try mgr.acceptConnection(header, local, local, null, null);
        if (mgr.entries.items.len > 4) mgr.removeConnection(mgr.entries.items[0]);
        mgr.freeDeadEntries();
    }
    const m = &mgr.cid_map.unmanaged;
    var free: usize = 0;
    for (m.metadata.?[0..m.capacity()]) |md| free += @intFromBool(md.isFree());
    // Tombstones never give their slot back on their own: without the
    // rehash, a map this churned has none free.
    try std.testing.expect(free >= m.capacity() - m.count() - m.capacity() / 4);
}

test "a CID the peer retires stops routing, and none outlive the connection" {
    const alloc = std.testing.allocator;
    var mgr = testManager(alloc);
    defer mgr.deinit();
    const local = std.mem.zeroes(posix.sockaddr.storage);
    const dcid: [8]u8 = @splat(0x11);
    const scid: [8]u8 = @splat(0xaa);
    const e = try mgr.acceptConnection(.{
        .version = protocol.SUPPORTED_VERSIONS[0],
        .packet_type = .initial,
        .dcid = &dcid,
        .scid = &scid,
    }, local, local, null, null);

    // Each retirement frees a pool slot, and its replacement takes that slot
    // within the same recv(), before the manager syncs.
    for (0..12) |seq| {
        var old: CidKey = undefined;
        for (&e.conn.local_cid_pool.entries) |*c| {
            if (c.occupied and c.seq_num == seq) old = CidKey.fromSlice(c.cid_buf[0..c.cid_len]);
        }
        try e.conn.processFrame(&.{ .retire_connection_id = .{ .seq_num = seq } }, .application, 0);
        mgr.syncCids(e);
        try std.testing.expect(mgr.findByDcid(old.getSlice()) == null);
        try std.testing.expect(mgr.findByDcid(&dcid) == e);
    }

    mgr.removeConnection(e);
    mgr.freeDeadEntries();
    try std.testing.expectEqual(@as(usize, 0), mgr.cid_map.count());
}

test "every change to a CID pool reaches routing, and a CID another connection holds is retried" {
    const alloc = std.testing.allocator;
    var mgr = testManager(alloc);
    defer mgr.deinit();
    const a = try acceptTest(&mgr, 1);
    const b = try acceptTest(&mgr, 2);
    mgr.syncCids(b);

    // Each CID the pool has held routes to `a` exactly while it is active.
    const pool = &a.conn.local_cid_pool;
    const preferred: [8]u8 = @splat(0x5a);
    const initial: [8]u8 = @splat(0x6b);
    var held: [16]CidKey = undefined;
    var n_held: usize = 0;
    for (0..6) |step| {
        switch (step) {
            0 => {},
            1 => pool.registerPreferredCid(&preferred, @splat(0)),
            2 => _ = pool.issueNewCid(8, null),
            3 => _ = pool.issueNewCidLb(&lbConfig(1), null),
            4 => pool.retireBySeq(0),
            5 => pool.registerInitialCid(&initial, null),
            else => unreachable,
        }
        for (&pool.entries) |*c| {
            if (!c.occupied) continue;
            const key = CidKey.fromSlice(c.getCid());
            for (held[0..n_held]) |k| {
                if (CidKeyContext.eql(.{}, k, key)) break;
            } else {
                held[n_held] = key;
                n_held += 1;
            }
        }
        mgr.syncCids(a);
        for (held[0..n_held]) |key| {
            try std.testing.expectEqual(ConnectionManager.poolHasActive(pool, key), mgr.findByDcid(key.getSlice()) == a);
        }
    }
    try std.testing.expectEqual(@as(usize, 5), n_held);

    // Handed one of `a`'s CIDs, `b` leaves it to `a`, and takes it with its
    // next packet once `a` is gone, though its own pool hasn't changed since.
    b.conn.local_cid_pool.registerPreferredCid(&preferred, @splat(0));
    mgr.syncCids(b);
    try std.testing.expect(mgr.findByDcid(&preferred) == a);
    mgr.removeConnection(a);
    mgr.syncCids(b);
    try std.testing.expect(mgr.findByDcid(&preferred) == b);
}

fn acceptTest(mgr: *ConnectionManager, n: u64) !*ConnEntry {
    var dcid: [8]u8 = undefined;
    std.mem.writeInt(u64, &dcid, n, .big);
    const scid: [8]u8 = @splat(0xaa);
    const local = std.mem.zeroes(posix.sockaddr.storage);
    return mgr.acceptConnection(.{
        .version = protocol.SUPPORTED_VERSIONS[0],
        .packet_type = .initial,
        .dcid = &dcid,
        .scid = &scid,
    }, local, local, null, null);
}

/// `timers` is a heap on `deadline` whose slots name their own places, and
/// a live entry with a deadline is in it or else queued for the visit that
/// sets the next.
fn expectTimersSound(mgr: *const ConnectionManager) !void {
    const items = mgr.timers.items;
    for (items, 0..) |t, i| {
        try std.testing.expectEqual(@as(u32, @intCast(i)), t.entry.timer_slot);
        try std.testing.expectEqual(t.entry.deadline, t.at);
        if (i > 0) try std.testing.expect(items[(i - 1) / 2].at <= t.at);
    }
    var timed: usize = 0;
    for (mgr.entries.items) |e| {
        if (e.timer_slot != no_slot) {
            timed += 1;
        } else if (e.deadline != null) try std.testing.expect(e.queued);
    }
    try std.testing.expectEqual(timed, items.len);
}

test "a removed entry leaves the pass structures, and a stale write can't put it back" {
    const alloc = std.testing.allocator;
    var mgr = testManager(alloc);
    defer mgr.deinit();
    const a = try acceptTest(&mgr, 1);
    const b = try acceptTest(&mgr, 2);
    const c = try acceptTest(&mgr, 3);

    // New entries wait for their first visit, each once however often marked.
    a.mark(false);
    a.repoll();
    try std.testing.expectEqualSlices(*ConnEntry, &.{ a, b, c }, mgr.to_visit.items);
    // A pass done with one drops it; one marked again stays.
    for ([_]*ConnEntry{ a, b, c }) |e| {
        e.needs_visit = false;
        e.needs_poll = false;
    }
    c.mark(false);
    mgr.settleVisits();
    try std.testing.expectEqualSlices(*ConnEntry, &.{c}, mgr.to_visit.items);
    try std.testing.expect(!a.queued and !b.queued and c.queued);

    mgr.setDeadline(a, 300);
    mgr.setDeadline(b, 100);
    mgr.setDeadline(c, 200);
    try std.testing.expectEqual(@as(?i64, 100), mgr.nextDeadline());
    try expectTimersSound(&mgr);

    // Due by 150: b joins the pass, out of the heap until its visit sets one.
    mgr.queueDue(150);
    try std.testing.expectEqualSlices(*ConnEntry, &.{ c, b }, mgr.to_visit.items);
    try std.testing.expectEqual(@as(?i64, 200), mgr.nextDeadline());
    mgr.setDeadline(b, 400);

    // Removed while queued and timed: out of both at once.
    mgr.removeConnection(c);
    try std.testing.expectEqualSlices(*ConnEntry, &.{b}, mgr.to_visit.items);
    try std.testing.expect(!c.queued and c.timer_slot == no_slot);
    try std.testing.expectEqual(@as(?i64, 300), mgr.nextDeadline());
    try expectTimersSound(&mgr);
    // A Session kept past onConnectionClosed writes to it: flags only.
    c.wake();
    mgr.setDeadline(c, 50);
    try std.testing.expectEqualSlices(*ConnEntry, &.{b}, mgr.to_visit.items);
    try std.testing.expectEqual(@as(?i64, 300), mgr.nextDeadline());

    mgr.removeConnection(a);
    mgr.removeConnection(b);
    try std.testing.expectEqual(@as(usize, 0), mgr.to_visit.items.len);
    try std.testing.expectEqual(@as(usize, 0), mgr.timers.items.len);
    mgr.freeDeadEntries();
}

test "a pass visits what is queued in the order it connected, and a removal keeps that" {
    const alloc = std.testing.allocator;
    var mgr = testManager(alloc);
    defer mgr.deinit();
    var e: [4]*ConnEntry = undefined;
    for (&e, 0..) |*x, i| {
        x.* = try acceptTest(&mgr, i + 1);
        x.*.needs_visit = false;
        x.*.needs_poll = false;
    }
    mgr.settleVisits();

    for ([_]usize{ 3, 1, 0, 2 }) |i| e[i].mark(false);
    mgr.orderVisits();
    try std.testing.expectEqualSlices(*ConnEntry, &e, mgr.to_visit.items);
    mgr.removeConnection(e[0]);
    try std.testing.expectEqualSlices(*ConnEntry, e[1..], mgr.to_visit.items);
    for (e[1..]) |x| mgr.removeConnection(x);
    mgr.freeDeadEntries();
}

test "timers stay a heap through deadlines set, moved, cleared and removed" {
    const alloc = std.testing.allocator;
    var mgr = testManager(alloc);
    defer mgr.deinit();
    mgr.max_connections = 64;
    for (0..64) |i| _ = try acceptTest(&mgr, i + 1);

    var prng: std.Random.DefaultPrng = .init(0x7123);
    const rand = prng.random();
    var next_id: u64 = 65;
    for (0..4000) |_| {
        const e = mgr.entries.items[rand.uintLessThan(usize, mgr.entries.items.len)];
        switch (rand.uintLessThan(u8, 10)) {
            0 => mgr.setDeadline(e, null),
            1 => {
                mgr.removeConnection(e);
                mgr.freeDeadEntries();
                _ = try acceptTest(&mgr, next_id);
                next_id += 1;
            },
            2 => mgr.queueDue(rand.intRangeAtMost(i64, 0, 1000)),
            else => mgr.setDeadline(e, rand.intRangeAtMost(i64, 0, 1000)),
        }
        try expectTimersSound(&mgr);
        var min: ?i64 = null;
        for (mgr.entries.items) |x| {
            if (x.timer_slot == no_slot) continue;
            if (min == null or x.deadline.? < min.?) min = x.deadline;
        }
        try std.testing.expectEqual(min, mgr.nextDeadline());
    }
}

fn testManager(alloc: Allocator) ConnectionManager {
    const tls_config: tls13.TlsConfig = .{
        .cert_chain_der = &.{},
        .private_key_bytes = &.{},
        .alpn = &.{},
    };
    return ConnectionManager.init(alloc, tls_config, .{}, @splat(0), @splat(0));
}

/// A real client's first datagram, padded to 1200 bytes as RFC 9000 14.1 asks.
fn clientInitial(alloc: Allocator, out: []u8) !struct { conn: *connection.Connection, len: usize } {
    const conn = try alloc.create(connection.Connection);
    errdefer alloc.destroy(conn);
    try connection.connectInto(conn, alloc, "example.com", .{}, null, null);
    const len = try conn.send(out);
    return .{ .conn = conn, .len = len };
}

/// A client Initial to `dcid` carrying a PING, sealed as a real client seals it.
fn pingInitial(alloc: Allocator, out: []u8, dcid: []const u8) !usize {
    const ack_handler = @import("ack_handler.zig");
    const crypto_stream = @import("crypto_stream.zig");
    const stream_mod = @import("stream.zig");
    const packet_packer = @import("packet_packer.zig");
    const version = protocol.SUPPORTED_VERSIONS[0];
    const seal = (try crypto.deriveInitialKeyMaterial(dcid, version, false))[1];
    var handler = ack_handler.PacketHandler.init(alloc);
    defer handler.deinit();
    var crypto_mgr = crypto_stream.CryptoStreamManager.init(alloc);
    defer crypto_mgr.deinit();
    var streams = stream_mod.StreamsMap.init(alloc, false);
    defer streams.deinit();
    const scid: [8]u8 = @splat(0xc1);
    var packer = packet_packer.PacketPacker.init(alloc, false, &scid, dcid, version);
    var pending: frame_mod.PendingFrameQueue = .{};
    pending.push(.ping);
    return packer.packCoalesced(out, &handler, &crypto_mgr, &streams, &pending, &seal, null, null, null, 0, null, false);
}

/// Hand-built long header: enough for routing, never decrypted.
fn fakeLongHeader(buf: []u8, version: u32, dcid: []const u8) usize {
    var fbs = io.fixedBufferStream(buf);
    const w = &fbs;
    w.writeByte(0xc0) catch unreachable;
    w.writeInt(u32, version, .big) catch unreachable;
    w.writeByte(@intCast(dcid.len)) catch unreachable;
    w.writeAll(dcid) catch unreachable;
    w.writeByte(0) catch unreachable; // scid
    w.writeByte(0) catch unreachable; // token
    packet.writeVarInt(w, 40) catch unreachable;
    return fbs.seek + 40;
}

test "an Initial in a datagram under 1200 bytes opens no connection" {
    const alloc = std.testing.allocator;
    var mgr = testManager(alloc);
    defer mgr.deinit();
    const addr = std.mem.zeroes(posix.sockaddr.storage);

    var buf: [1500]u8 = @splat(0);
    var out: [1500]u8 = undefined;
    const n = fakeLongHeader(&buf, protocol.SUPPORTED_VERSIONS[0], &@as([8]u8, @splat(0x11)));
    try std.testing.expect(mgr.recvDatagram(buf[0..n], addr, addr, 0, &out) == .dropped);
    try std.testing.expectEqual(@as(usize, 0), mgr.connectionCount());
}

test "an Initial that doesn't decrypt opens no connection" {
    // A connection was allocated before its first packet was opened, so
    // random bytes under a plausible header each held a slot until the idle
    // timeout.
    const alloc = std.testing.allocator;
    var mgr = testManager(alloc);
    defer mgr.deinit();
    const addr = std.mem.zeroes(posix.sockaddr.storage);
    const dcid: [8]u8 = @splat(0x11);
    var out: [1500]u8 = undefined;

    var junk: [1200]u8 = @splat(0);
    _ = fakeLongHeader(&junk, protocol.SUPPORTED_VERSIONS[0], &dcid);
    try std.testing.expect(mgr.recvDatagram(&junk, addr, addr, 0, &out) == .dropped);
    try std.testing.expectEqual(@as(usize, 0), mgr.connectionCount());

    var buf: [1500]u8 = undefined;
    const n = try pingInitial(alloc, &buf, &dcid);
    try std.testing.expect(n >= 1200);
    try std.testing.expect(mgr.recvDatagram(buf[0..n], addr, addr, 0, &out) == .processed);
    try std.testing.expectEqual(@as(usize, 1), mgr.connectionCount());
}

test "an Initial with a DCID under 8 bytes opens no connection" {
    const alloc = std.testing.allocator;
    var mgr = testManager(alloc);
    defer mgr.deinit();
    const addr = std.mem.zeroes(posix.sockaddr.storage);

    var buf: [1200]u8 = @splat(0);
    var out: [1500]u8 = undefined;
    _ = fakeLongHeader(&buf, protocol.SUPPORTED_VERSIONS[0], &@as([7]u8, @splat(0x11)));
    try std.testing.expect(mgr.recvDatagram(&buf, addr, addr, 0, &out) == .dropped);
    try std.testing.expectEqual(@as(usize, 0), mgr.connectionCount());
}

test "Version Negotiation only answers full-size datagrams, and is rate limited" {
    const alloc = std.testing.allocator;
    var mgr = testManager(alloc);
    defer mgr.deinit();
    mgr.reply_limits = .init(1);
    const addr = std.mem.zeroes(posix.sockaddr.storage);
    const unknown: u32 = 0x1a2a3a4a;

    var buf: [1200]u8 = @splat(0);
    var out: [1500]u8 = undefined;
    const n = fakeLongHeader(&buf, unknown, &@as([8]u8, @splat(0x11)));
    try std.testing.expect(mgr.recvDatagram(buf[0..n], addr, addr, 0, &out) == .dropped);
    try std.testing.expect(mgr.recvDatagram(&buf, addr, addr, 0, &out) == .send_response);
    // The bucket is spent; the refill needs a second to pass.
    try std.testing.expect(mgr.recvDatagram(&buf, addr, addr, 0, &out) == .dropped);
}

test "stateless reset answers only packets long enough not to be one" {
    const alloc = std.testing.allocator;
    var mgr = testManager(alloc);
    defer mgr.deinit();
    const addr = std.mem.zeroes(posix.sockaddr.storage);

    var buf = [_]u8{0x41} ++ @as([99]u8, @splat(0x22));
    var out: [1500]u8 = undefined;
    try std.testing.expect(mgr.recvDatagram(buf[0 .. MIN_RESET_TRIGGER - 1], addr, addr, 0, &out) == .dropped);
    switch (mgr.recvDatagram(&buf, addr, addr, 0, &out)) {
        .send_response => |r| try std.testing.expect(r.len < buf.len),
        else => return error.TestUnexpectedResult,
    }

    mgr.reply_limits = .init(0);
    try std.testing.expect(mgr.recvDatagram(&buf, addr, addr, 0, &out) == .dropped);
}

test "ReplyLimiter refills at its rate and caps the burst" {
    var l: ReplyLimiter = .{ .per_second = 10, .tokens = 10 };
    const t0: i64 = 5 * std.time.ns_per_s;
    var granted: usize = 0;
    while (l.allow(t0)) granted += 1;
    try std.testing.expectEqual(@as(usize, 10), granted);
    // 100 ms buys one more; ten seconds buys no more than the burst.
    try std.testing.expect(l.allow(t0 + 100 * std.time.ns_per_ms));
    try std.testing.expect(!l.allow(t0 + 100 * std.time.ns_per_ms));
    granted = 0;
    while (l.allow(t0 + 10 * std.time.ns_per_s)) granted += 1;
    try std.testing.expectEqual(@as(usize, 10), granted);
}

test "spoofed reset triggers do not spend the CONNECTION_REFUSED budget" {
    const alloc = std.testing.allocator;
    var mgr = testManager(alloc);
    defer mgr.deinit();
    mgr.reply_limits = .init(1);
    mgr.max_connections = 0;
    const addr = std.mem.zeroes(posix.sockaddr.storage);
    var out: [1500]u8 = undefined;

    var junk = [_]u8{0x41} ++ @as([99]u8, @splat(0x22));
    try std.testing.expect(mgr.recvDatagram(&junk, addr, addr, 0, &out) == .send_response);
    try std.testing.expect(mgr.recvDatagram(&junk, addr, addr, 0, &out) == .dropped);

    var buf: [1500]u8 = undefined;
    const client = try clientInitial(alloc, &buf);
    defer {
        client.conn.deinit();
        alloc.destroy(client.conn);
    }
    try std.testing.expect(mgr.recvDatagram(buf[0..client.len], addr, addr, 0, &out) == .send_response);
}

test "a server at capacity refuses a new client with CONNECTION_REFUSED" {
    const alloc = std.testing.allocator;
    var mgr = testManager(alloc);
    defer mgr.deinit();
    mgr.max_connections = 0;
    const addr = std.mem.zeroes(posix.sockaddr.storage);

    var buf: [1500]u8 = undefined;
    const client = try clientInitial(alloc, &buf);
    defer {
        client.conn.deinit();
        alloc.destroy(client.conn);
    }
    try std.testing.expect(client.len >= MIN_INITIAL_DATAGRAM);

    var out: [1500]u8 = undefined;
    const reply = switch (mgr.recvDatagram(buf[0..client.len], addr, addr, 0, &out)) {
        .send_response => |r| r,
        else => return error.TestUnexpectedResult,
    };
    try std.testing.expectEqual(@as(usize, 0), mgr.connectionCount());
    // Small, so a spoofed Initial cannot be turned into an amplifier.
    try std.testing.expect(reply.len < 100);

    // The client can read it: the Initial keys are its own.
    client.conn.handleDatagram(@constCast(reply), .{ .to = addr, .from = addr, .datagram_size = reply.len });
    try std.testing.expect(client.conn.isDraining());
    try std.testing.expectEqual(
        @as(u64, @backingInt(frame_mod.TransportError.connection_refused)),
        client.conn.local_err.?.code,
    );
}

test "refuse_new turns away new connections while existing ones keep routing" {
    const alloc = std.testing.allocator;
    var mgr = testManager(alloc);
    defer mgr.deinit();
    mgr.refuse_new = true;
    const addr = std.mem.zeroes(posix.sockaddr.storage);

    var buf: [1500]u8 = undefined;
    const client = try clientInitial(alloc, &buf);
    defer {
        client.conn.deinit();
        alloc.destroy(client.conn);
    }
    var out: [1500]u8 = undefined;
    try std.testing.expect(mgr.recvDatagram(buf[0..client.len], addr, addr, 0, &out) == .send_response);
    try std.testing.expectEqual(@as(usize, 0), mgr.connectionCount());
}

fn lbConfig(server_id: u8) quic_lb.Config {
    var cfg: quic_lb.Config = .{ .config_id = 0, .server_id_len = 1, .nonce_len = 6 };
    cfg.server_id[0] = server_id;
    return cfg;
}

fn steeringManager(alloc: Allocator, server_id: u8) ConnectionManager {
    const tls_config: tls13.TlsConfig = .{
        .cert_chain_der = &.{},
        .private_key_bytes = &.{},
        .alpn = &.{},
    };
    var mgr = ConnectionManager.init(alloc, tls_config, .{ .quic_lb = lbConfig(server_id) }, @splat(0), @splat(0));
    mgr.steer_foreign = true;
    return mgr;
}

/// A 1-RTT packet to `dcid`, long enough to earn a stateless reset.
fn shortPacket(buf: []u8, dcid: []const u8) []u8 {
    buf[0] = 0x41;
    @memcpy(buf[1 .. 1 + dcid.len], dcid);
    @memset(buf[1 + dcid.len .. 60], 0x22);
    return buf[0..60];
}

test "a 1-RTT packet for another QUIC-LB server id is reported, not reset" {
    const alloc = std.testing.allocator;
    var mgr = steeringManager(alloc, 1);
    defer mgr.deinit();
    const addr = std.mem.zeroes(posix.sockaddr.storage);
    var out: [1500]u8 = undefined;
    var buf: [64]u8 = undefined;

    var cid: [8]u8 = undefined;
    quic_lb.generateCid(&lbConfig(2), &cid);
    switch (mgr.recvDatagram(shortPacket(&buf, &cid), addr, addr, 0, &out)) {
        .foreign => |id| try std.testing.expectEqualSlices(u8, &.{2}, id),
        else => return error.TestUnexpectedResult,
    }

    // Handed over and still unknown: reset, never passed on again.
    try std.testing.expect(mgr.recvHandedOver(shortPacket(&buf, &cid), addr, addr, 0, &out) == .send_response);

    // Our own id with no connection behind it is simply gone.
    quic_lb.generateCid(&lbConfig(1), &cid);
    try std.testing.expect(mgr.recvDatagram(shortPacket(&buf, &cid), addr, addr, 0, &out) == .send_response);

    mgr.steer_foreign = false;
    quic_lb.generateCid(&lbConfig(2), &cid);
    try std.testing.expect(mgr.recvDatagram(shortPacket(&buf, &cid), addr, addr, 0, &out) == .send_response);
}

test "an Initial is accepted locally even when its DCID decodes to another server" {
    const alloc = std.testing.allocator;
    var mgr = steeringManager(alloc, 1);
    defer mgr.deinit();
    const addr = std.mem.zeroes(posix.sockaddr.storage);
    var out: [1500]u8 = undefined;

    var cid: [8]u8 = undefined;
    quic_lb.generateCid(&lbConfig(2), &cid);
    var buf: [1500]u8 = undefined;
    const n = try pingInitial(alloc, &buf, &cid);
    try std.testing.expect(mgr.recvDatagram(buf[0..n], addr, addr, 0, &out) == .processed);
    try std.testing.expectEqual(@as(usize, 1), mgr.connectionCount());
    // And the connection's own CID carries our id.
    const scid = mgr.entries.items[0].conn.scid[0..8];
    var id: [1]u8 = undefined;
    try std.testing.expect(quic_lb.extractServerId(&lbConfig(1), scid, &id));
    try std.testing.expectEqual(@as(u8, 1), id[0]);
}

test "past max_handshakes a new client gets Retry, and is served once it echoes the token" {
    // Half-open connections had no cap of their own: valid Initials from
    // spoofed sources, which never finish, filled max_connections and locked
    // real clients out.
    const alloc = std.testing.allocator;
    var mgr = testManager(alloc);
    defer mgr.deinit();
    mgr.max_handshakes = 1;
    const addr = std.mem.zeroes(posix.sockaddr.storage);
    var out: [1500]u8 = undefined;
    var buf: [1500]u8 = undefined;

    const first = try clientInitial(alloc, &buf);
    defer {
        first.conn.deinit();
        alloc.destroy(first.conn);
    }
    try std.testing.expect(mgr.recvDatagram(buf[0..first.len], addr, addr, 0, &out) == .processed);

    const second = try clientInitial(alloc, &buf);
    defer {
        second.conn.deinit();
        alloc.destroy(second.conn);
    }
    const retry = switch (mgr.recvDatagram(buf[0..second.len], addr, addr, 0, &out)) {
        .send_response => |r| r,
        else => return error.TestUnexpectedResult,
    };
    try std.testing.expectEqual(@as(usize, 1), mgr.connectionCount());
    second.conn.handleDatagram(@constCast(retry), .{ .to = addr, .from = addr, .datagram_size = retry.len });
    try std.testing.expect(second.conn.retry_received);

    // Its address proven, it is served with the cap still reached.
    var n = try second.conn.send(&buf);
    try std.testing.expect(mgr.recvDatagram(buf[0..n], addr, addr, 0, &out) == .processed);
    try std.testing.expectEqual(@as(usize, 2), mgr.connectionCount());

    // Handshakes that end, here by removal, give their places back.
    mgr.removeConnection(mgr.entries.items[1]);
    mgr.removeConnection(mgr.entries.items[0]);
    const third = try clientInitial(alloc, &buf);
    defer {
        third.conn.deinit();
        alloc.destroy(third.conn);
    }
    n = third.len;
    try std.testing.expect(mgr.recvDatagram(buf[0..n], addr, addr, 0, &out) == .processed);
}

test "past retry_threshold a new client gets Retry, and is served once it echoes the token" {
    const alloc = std.testing.allocator;
    var mgr = testManager(alloc);
    defer mgr.deinit();
    mgr.retry_threshold = 1;
    const addr = std.mem.zeroes(posix.sockaddr.storage);
    var out: [1500]u8 = undefined;

    // Under the threshold: served straight away.
    var buf: [1500]u8 = undefined;
    const first = try clientInitial(alloc, &buf);
    defer {
        first.conn.deinit();
        alloc.destroy(first.conn);
    }
    try std.testing.expect(mgr.recvDatagram(buf[0..first.len], addr, addr, 0, &out) == .processed);

    // At it: Retry, and no state kept.
    const second = try clientInitial(alloc, &buf);
    defer {
        second.conn.deinit();
        alloc.destroy(second.conn);
    }
    const retry = switch (mgr.recvDatagram(buf[0..second.len], addr, addr, 0, &out)) {
        .send_response => |r| r,
        else => return error.TestUnexpectedResult,
    };
    try std.testing.expectEqual(@as(usize, 1), mgr.connectionCount());
    second.conn.handleDatagram(@constCast(retry), .{ .to = addr, .from = addr, .datagram_size = retry.len });
    try std.testing.expect(second.conn.retry_received);

    // Load drops before the client comes back; its token still counts, so
    // the connection is set up as a retried one.
    mgr.removeConnection(mgr.entries.items[0]);
    const n = try second.conn.send(&buf);
    try std.testing.expect(mgr.recvDatagram(buf[0..n], addr, addr, 0, &out) == .processed);
    try std.testing.expectEqual(@as(usize, 1), mgr.connectionCount());
    try std.testing.expect(mgr.entries.items[0].conn.paths[0].is_validated);
}

fn testIn4(ip: [4]u8, port: u16) posix.sockaddr.storage {
    var in4: posix.sockaddr.in = std.mem.zeroes(posix.sockaddr.in);
    in4.family = posix.AF.INET;
    in4.port = std.mem.nativeToBig(u16, port);
    in4.addr = @bitCast(ip);
    return connection.sockaddrToStorage(@ptrCast(&in4));
}

fn testIn6(ip: [16]u8, port: u16) posix.sockaddr.storage {
    var in6: posix.sockaddr.in6 = std.mem.zeroes(posix.sockaddr.in6);
    in6.family = posix.AF.INET6;
    in6.port = std.mem.nativeToBig(u16, port);
    in6.addr = ip;
    return connection.sockaddrToStorage(@ptrCast(&in6));
}

fn destroyClient(alloc: Allocator, conn: *connection.Connection) void {
    conn.deinit();
    alloc.destroy(conn);
}

/// A client that answered the Retry `mgr` sent it at `from`; its Initial
/// echoing the token is in `out`.
fn retriedClient(alloc: Allocator, mgr: *ConnectionManager, from: posix.sockaddr.storage, out: []u8) !struct { conn: *connection.Connection, len: usize } {
    const client = try clientInitial(alloc, out);
    errdefer destroyClient(alloc, client.conn);
    var reply: [1500]u8 = undefined;
    const retry = switch (mgr.recvDatagram(out[0..client.len], from, from, 0, &reply)) {
        .send_response => |r| r,
        else => return error.TestUnexpectedResult,
    };
    client.conn.handleDatagram(@constCast(retry), .{ .to = from, .from = from, .datagram_size = retry.len });
    if (!client.conn.retry_received) return error.TestUnexpectedResult;
    return .{ .conn = client.conn, .len = try client.conn.send(out) };
}

test "a Retry token admits only the connection its Retry was for" {
    // Its DCID went unchecked, so one Retry let a client open connection
    // after connection under fresh DCIDs.
    const alloc = std.testing.allocator;
    var mgr = testManager(alloc);
    defer mgr.deinit();
    mgr.require_retry = true;
    const addr = std.mem.zeroes(posix.sockaddr.storage);
    var out: [1500]u8 = undefined;
    var buf: [1500]u8 = undefined;

    const client = try retriedClient(alloc, &mgr, addr, &buf);
    defer destroyClient(alloc, client.conn);
    try std.testing.expect(mgr.recvDatagram(buf[0..client.len], addr, addr, 0, &out) == .processed);

    const replay = try alloc.create(connection.Connection);
    defer alloc.destroy(replay);
    try connection.connectInto(replay, alloc, "example.com", .{}, null, client.conn.retry_token_buf[0..client.conn.retry_token_len]);
    defer replay.deinit();
    const n = try replay.send(&buf);
    try std.testing.expect(mgr.recvDatagram(buf[0..n], addr, addr, 0, &out) == .dropped);
    try std.testing.expectEqual(@as(usize, 1), mgr.connectionCount());
}

test "one source holds at most max_handshakes_per_source handshakes on a proven address" {
    // Retry proves an address, not good faith: a host answering every Retry
    // filled max_connections with handshakes it never finished, and every
    // other client was refused.
    const alloc = std.testing.allocator;
    var mgr = testManager(alloc);
    defer mgr.deinit();
    mgr.require_retry = true;
    mgr.max_handshakes_per_source = 2;
    var out: [1500]u8 = undefined;
    var buf: [1500]u8 = undefined;

    var clients: [4]*connection.Connection = undefined;
    var made: usize = 0;
    defer for (clients[0..made]) |c| destroyClient(alloc, c);

    // A port of its own each earns it nothing.
    for (0..2) |i| {
        const from = testIn4(.{ 198, 51, 100, 7 }, @intCast(1000 + i));
        const c = try retriedClient(alloc, &mgr, from, &buf);
        clients[made] = c.conn;
        made += 1;
        try std.testing.expect(mgr.recvDatagram(buf[0..c.len], from, from, 0, &out) == .processed);
    }
    const from = testIn4(.{ 198, 51, 100, 7 }, 1002);
    var held: [1500]u8 = undefined;
    const third = try retriedClient(alloc, &mgr, from, &held);
    clients[made] = third.conn;
    made += 1;
    try std.testing.expect(mgr.recvDatagram(held[0..third.len], from, from, 0, &out) == .dropped);
    try std.testing.expectEqual(@as(usize, 2), mgr.connectionCount());

    const other = testIn4(.{ 203, 0, 113, 9 }, 1000);
    const c = try retriedClient(alloc, &mgr, other, &buf);
    clients[made] = c.conn;
    made += 1;
    try std.testing.expect(mgr.recvDatagram(buf[0..c.len], other, other, 0, &out) == .processed);

    // A handshake that ends, here by removal, gives its source the place
    // back, and the client turned away gets in on its retransmission.
    mgr.removeConnection(mgr.entries.items[0]);
    try std.testing.expect(mgr.recvDatagram(held[0..third.len], from, from, 0, &out) == .processed);
    try std.testing.expectEqual(@as(usize, 3), mgr.connectionCount());
}

test "a source is an IPv4 address or an IPv6 /64, IPv4 on a dual-stack socket included" {
    const net = [_]u8{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 1 };
    const elsewhere = [_]u8{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 2 };
    const host: [8]u8 = @splat(0x11);
    try std.testing.expectEqual(sourceKey(&testIn6(net ++ host, 1)), sourceKey(&testIn6(net ++ @as([8]u8, @splat(0x22)), 2)));
    try std.testing.expect(!std.mem.eql(u8, &sourceKey(&testIn6(net ++ host, 1)), &sourceKey(&testIn6(elsewhere ++ host, 1))));

    const v4 = [_]u8{ 198, 51, 100, 7 };
    try std.testing.expectEqual(sourceKey(&testIn4(v4, 1)), sourceKey(&testIn6(packet.v4_mapped_prefix ++ v4, 2)));
    try std.testing.expect(!std.mem.eql(u8, &sourceKey(&testIn6(packet.v4_mapped_prefix ++ v4, 1)), &sourceKey(&testIn6(packet.v4_mapped_prefix ++ [_]u8{ 198, 51, 100, 8 }, 1))));
}
