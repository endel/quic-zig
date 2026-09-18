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
    buf: [20]u8 = .{0} ** 20,
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

/// Hash/equality context for CidKey in HashMap.
pub const CidKeyContext = struct {
    pub fn hash(_: CidKeyContext, key: CidKey) u64 {
        return std.hash.Wyhash.hash(0, key.buf[0..key.len]);
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
    /// Unique per manager, never reused.
    id: u64 = 0,
    h3_conn: ?*h3.H3Connection = null,
    h3_initialized: bool = false,
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
    finished_streams: std.AutoHashMapUnmanaged(u64, void) = .{},

    // Track which CIDs are registered in the routing map for this connection.
    // Max 8 from LocalCidPool + 1 initial client DCID = 9.
    registered_cids: [9]CidKey = .{CidKey{}} ** 9,
    registered_cid_count: u8 = 0,

    /// Tell the owner there is data to send; see `wake_fn`.
    pub fn wake(self: *ConnEntry) void {
        if (self.wake_fn) |f| f(self.wake_ctx orelse return);
    }

    /// Ask the owner for another poll pass; see `repoll_fn`.
    pub fn repoll(self: *ConnEntry) void {
        if (self.repoll_fn) |f| f(self.wake_ctx orelse return);
    }

    fn addRegisteredCid(self: *ConnEntry, key: CidKey) void {
        if (self.registered_cid_count < 9) {
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

    // Server-wide shared config
    tls_config: tls13.TlsConfig,
    conn_config: connection.ConnectionConfig,
    retry_token_key: [16]u8,
    static_reset_key: [16]u8,
    local_cid_len: u8 = 8,

    /// When true, Initial packets without a valid token get a Retry response.
    require_retry: bool = false,

    /// When true, every new connection is answered with CONNECTION_REFUSED,
    /// as it is at `max_connections`. Set while a server drains.
    refuse_new: bool = false,

    /// Budgets for stateless replies; see `ReplyLimits`.
    reply_limits: ReplyLimits = .{},

    // Deferred free queue: entries invalidated by removeConnection are held
    // here until freeDeadEntries() is called after all event processing.
    // acceptConnection reserves a slot for every entry it creates, so
    // removeConnection can never fail to queue one.
    dead_entries: std.ArrayList(DeadEntry) = .empty,

    pub fn init(
        allocator: Allocator,
        tls_config: tls13.TlsConfig,
        conn_config: connection.ConnectionConfig,
        retry_token_key: [16]u8,
        static_reset_key: [16]u8,
    ) ConnectionManager {
        return .{
            .allocator = allocator,
            .cid_map = std.HashMap(CidKey, *ConnEntry, CidKeyContext, 80).init(allocator),
            .entries = .{ .items = &.{}, .capacity = 0 },
            .tls_config = tls_config,
            .conn_config = conn_config,
            .retry_token_key = retry_token_key,
            .static_reset_key = static_reset_key,
            .local_cid_len = if (conn_config.quic_lb) |lb| quic_lb.cidLength(&lb) else 8,
        };
    }

    pub fn deinit(self: *ConnectionManager) void {
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
        self.cid_map.deinit();
    }

    /// Look up a connection entry by destination CID.
    pub fn findByDcid(self: *ConnectionManager, dcid: []const u8) ?*ConnEntry {
        const key = CidKey.fromSlice(dcid);
        return self.cid_map.get(key);
    }

    /// Accept a new incoming connection from an Initial packet.
    /// Heap-allocates the Connection for pointer stability (needed by H3Connection).
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
        try self.entries.ensureUnusedCapacity(self.allocator, 1);
        try self.dead_entries.ensureTotalCapacity(
            self.allocator,
            self.entries.items.len + self.dead_entries.items.len + 1,
        );

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
        entry.addRegisteredCid(client_dcid_key);

        self.entries.appendAssumeCapacity(entry);

        return entry;
    }

    /// Synchronize the CID routing map with the connection's LocalCidPool.
    /// Registers new CIDs and unregisters retired ones.
    pub fn syncCids(self: *ConnectionManager, entry: *ConnEntry) void {
        const pool = &entry.conn.local_cid_pool;

        for (&pool.entries) |*cid_entry| {
            const key = CidKey.fromSlice(cid_entry.cid_buf[0..cid_entry.cid_len]);
            if (key.len == 0) continue;

            if (cid_entry.occupied and !cid_entry.retired) {
                // Active CID — register if not already present
                if (!entry.hasRegisteredCid(key)) {
                    self.cid_map.put(key, entry) catch {};
                    entry.addRegisteredCid(key);
                }
            } else if (cid_entry.retired) {
                // Retired CID — unregister if present
                if (entry.hasRegisteredCid(key)) {
                    _ = self.cid_map.remove(key);
                    entry.removeRegisteredCid(key);
                }
            }
        }
    }

    /// Remove a terminated connection. Invalidates the entry immediately
    /// (nulls wt_conn, removes from routing) and defers memory freeing so
    /// that any stale Session pointers safely see wt_conn == null instead
    /// of accessing freed memory.
    pub fn removeConnection(self: *ConnectionManager, entry: *ConnEntry) void {
        // Unregister all CIDs from the routing map
        for (entry.registered_cids[0..entry.registered_cid_count]) |key| {
            _ = self.cid_map.remove(key);
        }

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

    /// Result of processing a received UDP datagram.
    pub const RecvAction = union(enum) {
        /// Datagram was delivered to an existing or newly accepted connection.
        processed: *ConnEntry,
        /// A response packet (VN, Retry, or Stateless Reset) was written to
        /// out_buf and should be sent back to the source address.
        send_response: []const u8,
        /// Datagram was unroutable or invalid; no action needed.
        dropped: void,
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
        var fbs = io.fixedBufferStream(bytes);
        var current_entry: ?*ConnEntry = null;

        while (fbs.seek < bytes.len) {
            // All valid QUIC packets have the fixed bit (0x40) set.
            if (bytes[fbs.seek] & 0x40 == 0) break;

            const pkt_start = fbs.seek;
            var header = packet.Header.parse(&fbs, self.local_cid_len) catch break;
            const full_size = fbs.seek - pkt_start + header.remainder_len;

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

            if (entry == null) {
                if (header.packet_type != .initial) {
                    // Short-header for unknown CID: stateless reset (RFC 9000 §10.3)
                    if (header.packet_type == .one_rtt and full_size >= MIN_RESET_TRIGGER and
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

                if (self.refuse_new or self.entries.items.len >= self.max_connections) {
                    return self.refuse(header, out_buf);
                }

                // Initial packet — check retry requirement
                if (self.require_retry) {
                    if (header.token == null or header.token.?.len == 0) {
                        // No token: send Retry
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

                    // Has token: validate as Retry token
                    const validated = packet.validateRetryToken(
                        header.token.?,
                        from,
                        self.retry_token_key,
                    ) catch null;

                    if (validated) |vt| {
                        entry = self.acceptConnection(header, local, from, vt.getOdcid(), vt.getRetryScid()) catch
                            return .{ .dropped = {} };
                    } else if (packet.validateNewToken(header.token.?, from, self.retry_token_key)) {
                        // Valid NEW_TOKEN — accept without retry
                        entry = self.acceptConnection(header, local, from, header.dcid, null) catch
                            return .{ .dropped = {} };
                    } else {
                        return .{ .dropped = {} };
                    }
                } else {
                    // No retry required — accept directly
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
            const recv_info: connection.RecvInfo = .{ .to = local, .from = from, .ecn = ecn_val, .datagram_size = dg_size };
            e.conn.recv(&header, &fbs, recv_info) catch break;
            self.syncCids(e);

            const next_pos = pkt_start + full_size;
            if (fbs.seek < next_pos) fbs.seek = next_pos;
        }

        if (current_entry) |e| {
            return .{ .processed = e };
        }
        return .{ .dropped = {} };
    }

    /// Answer an Initial we will not serve with CONNECTION_REFUSED (RFC 9000
    /// 5.2.2), sealed with the Initial keys its own DCID derives, so the
    /// client fails fast instead of retransmitting into silence.
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
    const payload = [_]u8{ 0x1c, @intFromEnum(frame_mod.TransportError.connection_refused), 0x00, 0x00 };
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
    var mgr = ConnectionManager.init(alloc, tls_config, .{}, .{0} ** 16, .{0} ** 16);
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
    var mgr = ConnectionManager.init(alloc, tls_config, .{}, .{0} ** 16, .{0} ** 16);
    defer mgr.deinit();
    mgr.max_connections = 300;

    const local = std.mem.zeroes(posix.sockaddr.storage);
    var dcids: [301][8]u8 = undefined;
    const scid = [_]u8{0xaa} ** 8;
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

fn testManager(alloc: Allocator) ConnectionManager {
    const tls_config: tls13.TlsConfig = .{
        .cert_chain_der = &.{},
        .private_key_bytes = &.{},
        .alpn = &.{},
    };
    return ConnectionManager.init(alloc, tls_config, .{}, .{0} ** 16, .{0} ** 16);
}

/// A real client's first datagram, padded to 1200 bytes as RFC 9000 14.1 asks.
fn clientInitial(alloc: Allocator, out: []u8) !struct { conn: *connection.Connection, len: usize } {
    const conn = try alloc.create(connection.Connection);
    errdefer alloc.destroy(conn);
    try connection.connectInto(conn, alloc, "example.com", .{}, null, null);
    const len = try conn.send(out);
    return .{ .conn = conn, .len = len };
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

    var buf = [_]u8{0} ** 1500;
    var out: [1500]u8 = undefined;
    const n = fakeLongHeader(&buf, protocol.SUPPORTED_VERSIONS[0], &([_]u8{0x11} ** 8));
    try std.testing.expect(mgr.recvDatagram(buf[0..n], addr, addr, 0, &out) == .dropped);
    try std.testing.expectEqual(@as(usize, 0), mgr.connectionCount());
}

test "an Initial with a DCID under 8 bytes opens no connection" {
    const alloc = std.testing.allocator;
    var mgr = testManager(alloc);
    defer mgr.deinit();
    const addr = std.mem.zeroes(posix.sockaddr.storage);

    var buf = [_]u8{0} ** 1200;
    var out: [1500]u8 = undefined;
    _ = fakeLongHeader(&buf, protocol.SUPPORTED_VERSIONS[0], &([_]u8{0x11} ** 7));
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

    var buf = [_]u8{0} ** 1200;
    var out: [1500]u8 = undefined;
    const n = fakeLongHeader(&buf, unknown, &([_]u8{0x11} ** 8));
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

    var buf = [_]u8{0x41} ++ [_]u8{0x22} ** 99;
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

    var junk = [_]u8{0x41} ++ [_]u8{0x22} ** 99;
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
        @as(u64, @intFromEnum(frame_mod.TransportError.connection_refused)),
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
