const std = @import("std");
const Allocator = std.mem.Allocator;
const posix = std.posix;

const connection = @import("connection.zig");
const packet = @import("packet.zig");
const tls13 = @import("tls13.zig");
const h3 = @import("../h3/connection.zig");

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
        };
    }

    pub fn deinit(self: *ConnectionManager) void {
        // Clean up all connections
        for (self.entries.items) |entry| {
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
        local: posix.sockaddr,
        remote: posix.sockaddr,
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

    /// Remove a terminated connection, freeing all resources.
    pub fn removeConnection(self: *ConnectionManager, entry: *ConnEntry) void {
        // Unregister all CIDs from the routing map
        for (entry.registered_cids[0..entry.registered_cid_count]) |key| {
            _ = self.cid_map.remove(key);
        }

        // Swap-remove from entries list
        var idx: usize = 0;
        while (idx < self.entries.items.len) : (idx += 1) {
            if (self.entries.items[idx] == entry) {
                _ = self.entries.swapRemove(idx);
                break;
            }
        }

        // Free connection and entry
        entry.conn.deinit();
        self.allocator.destroy(entry.conn);
        self.allocator.destroy(entry);
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
