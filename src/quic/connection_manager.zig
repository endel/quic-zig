const std = @import("std");
const Allocator = std.mem.Allocator;
const posix = std.posix;
const io = std.io;

const connection = @import("connection.zig");
const packet = @import("packet.zig");
const protocol = @import("protocol.zig");
const stateless_reset = @import("stateless_reset.zig");
const quic_lb = @import("quic_lb.zig");
const tls13 = @import("tls13.zig");
const h3 = @import("../h3/connection.zig");
const h0 = @import("../h0/connection.zig");
const wt = @import("../webtransport/session.zig");

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
pub const ConnEntry = struct {
    conn: *connection.Connection,
    h3_conn: ?h3.H3Connection = null,
    h3_initialized: bool = false,
    h0_conn: ?*h0.H0Connection = null,
    wt_conn: ?wt.WebTransportConnection = null,

    /// Type-erased handler pointer for zero-copy datagram callback.
    datagram_handler_ctx: ?*anyopaque = null,

    // For raw QUIC protocol: track streams whose fin has been delivered to handler
    finished_streams: std.AutoHashMapUnmanaged(u64, void) = .{},

    // Track which CIDs are registered in the routing map for this connection.
    // Max 8 from LocalCidPool + 1 initial client DCID = 9.
    registered_cids: [9]CidKey = .{CidKey{}} ** 9,
    registered_cid_count: u8 = 0,

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

/// Manages multiple QUIC connections, routing packets by DCID.
pub const ConnectionManager = struct {
    const MAX_CONNECTIONS = 256;

    allocator: Allocator,
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

    // Deferred free queue: entries invalidated by removeConnection are held
    // here until freeDeadEntries() is called after all event processing.
    dead_entries_buf: [MAX_CONNECTIONS]*ConnEntry = undefined,
    dead_entry_count: usize = 0,

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
            entry.finished_streams.deinit(self.allocator);
            entry.conn.deinit();
            self.allocator.destroy(entry.conn);
            self.allocator.destroy(entry);
        }
        self.entries.deinit(self.allocator);
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
        if (self.entries.items.len >= MAX_CONNECTIONS) {
            return error.TooManyConnections;
        }

        // Heap-allocate Connection
        const conn = try self.allocator.create(connection.Connection);
        conn.* = try connection.Connection.accept(
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
        const entry = try self.allocator.create(ConnEntry);
        entry.* = ConnEntry{ .conn = conn };

        // Register server's SCID in the routing map
        const scid_key = CidKey.fromSlice(conn.scid[0..conn.scid_len]);
        try self.cid_map.put(scid_key, entry);
        entry.addRegisteredCid(scid_key);

        // Also register the client's initial DCID so retransmitted Initials route correctly
        const client_dcid_key = CidKey.fromSlice(header.dcid);
        try self.cid_map.put(client_dcid_key, entry);
        entry.addRegisteredCid(client_dcid_key);

        try self.entries.append(self.allocator, entry);

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

        // Invalidate transport layers so stale Session pointers are safe.
        // Session.sendDatagram/sendStreamData check `if (entry.wt_conn)`
        // and will skip the send instead of dereferencing freed sub-objects.
        entry.wt_conn = null;
        entry.h3_conn = null;

        // Swap-remove from entries list
        var idx: usize = 0;
        while (idx < self.entries.items.len) : (idx += 1) {
            if (self.entries.items[idx] == entry) {
                _ = self.entries.swapRemove(idx);
                break;
            }
        }

        // Queue for deferred free (entry memory stays valid until freeDeadEntries)
        self.dead_entries_buf[self.dead_entry_count] = entry;
        self.dead_entry_count = @min(self.dead_entry_count + 1, self.dead_entries_buf.len);
    }

    /// Free entries that were invalidated by removeConnection.
    /// Call after all event processing is complete for the current cycle.
    pub fn freeDeadEntries(self: *ConnectionManager) void {
        for (self.dead_entries_buf[0..self.dead_entry_count]) |entry| {
            entry.finished_streams.deinit(self.allocator);
            entry.conn.deinit();
            self.allocator.destroy(entry.conn);
            self.allocator.destroy(entry);
        }
        self.dead_entry_count = 0;
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

        while (fbs.pos < bytes.len) {
            // All valid QUIC packets have the fixed bit (0x40) set.
            if (bytes[fbs.pos] & 0x40 == 0) break;

            const pkt_start = fbs.pos;
            var header = packet.Header.parse(&fbs, self.local_cid_len) catch break;
            const full_size = fbs.pos - pkt_start + header.remainder_len;

            // Version negotiation (RFC 9000 §6)
            if (header.version != 0 and !protocol.isSupportedVersion(header.version)) {
                var vn_fbs = io.fixedBufferStream(out_buf);
                const vn_writer = vn_fbs.writer();
                packet.negotiateVersion(header, &vn_writer) catch return .{ .dropped = {} };
                return .{ .send_response = vn_fbs.getWritten() };
            }

            // Route to existing connection by DCID
            var entry = current_entry orelse self.findByDcid(header.dcid);

            if (entry == null) {
                if (header.packet_type != .initial) {
                    // Short-header for unknown CID: stateless reset (RFC 9000 §10.3)
                    if (header.packet_type == .one_rtt) {
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

                // Initial packet — check retry requirement
                if (self.require_retry) {
                    if (header.token == null or header.token.?.len == 0) {
                        // No token: send Retry
                        var retry_scid: [8]u8 = undefined;
                        std.crypto.random.bytes(&retry_scid);

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
                        return .{ .send_response = retry_fbs.getWritten() };
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

            const e = entry.?;
            // Only count datagram_size for the first packet in a coalesced datagram
            // to avoid double-counting in amplification limit calculations.
            const dg_size: u64 = if (current_entry == null) bytes.len else 0;
            current_entry = e;
            const recv_info: connection.RecvInfo = .{ .to = local, .from = from, .ecn = ecn_val, .datagram_size = dg_size };
            e.conn.recv(&header, &fbs, recv_info) catch break;
            self.syncCids(e);

            const next_pos = pkt_start + full_size;
            if (fbs.pos < next_pos) fbs.pos = next_pos;
        }

        if (current_entry) |e| {
            return .{ .processed = e };
        }
        return .{ .dropped = {} };
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
