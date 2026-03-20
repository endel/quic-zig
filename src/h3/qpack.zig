const std = @import("std");
const testing = std.testing;
const huffman = @import("huffman.zig");

/// A single HTTP header field (name-value pair).
pub const Header = struct {
    name: []const u8,
    value: []const u8,
};

/// QPACK static table entry.
const StaticEntry = struct {
    name: []const u8,
    value: []const u8,
};

// QPACK static table (RFC 9204 Appendix A) — 99 entries, indices 0..98.
const static_table = [_]StaticEntry{
    .{ .name = ":authority", .value = "" }, // 0
    .{ .name = ":path", .value = "/" }, // 1
    .{ .name = "age", .value = "0" }, // 2
    .{ .name = "content-disposition", .value = "" }, // 3
    .{ .name = "content-length", .value = "0" }, // 4
    .{ .name = "cookie", .value = "" }, // 5
    .{ .name = "date", .value = "" }, // 6
    .{ .name = "etag", .value = "" }, // 7
    .{ .name = "if-modified-since", .value = "" }, // 8
    .{ .name = "if-none-match", .value = "" }, // 9
    .{ .name = "last-modified", .value = "" }, // 10
    .{ .name = "link", .value = "" }, // 11
    .{ .name = "location", .value = "" }, // 12
    .{ .name = "referer", .value = "" }, // 13
    .{ .name = "set-cookie", .value = "" }, // 14
    .{ .name = ":method", .value = "CONNECT" }, // 15
    .{ .name = ":method", .value = "DELETE" }, // 16
    .{ .name = ":method", .value = "GET" }, // 17
    .{ .name = ":method", .value = "HEAD" }, // 18
    .{ .name = ":method", .value = "OPTIONS" }, // 19
    .{ .name = ":method", .value = "POST" }, // 20
    .{ .name = ":method", .value = "PUT" }, // 21
    .{ .name = ":scheme", .value = "http" }, // 22
    .{ .name = ":scheme", .value = "https" }, // 23
    .{ .name = ":status", .value = "103" }, // 24
    .{ .name = ":status", .value = "200" }, // 25
    .{ .name = ":status", .value = "304" }, // 26
    .{ .name = ":status", .value = "404" }, // 27
    .{ .name = ":status", .value = "503" }, // 28
    .{ .name = "accept", .value = "*/*" }, // 29
    .{ .name = "accept", .value = "application/dns-message" }, // 30
    .{ .name = "accept-encoding", .value = "gzip, deflate, br" }, // 31
    .{ .name = "accept-ranges", .value = "bytes" }, // 32
    .{ .name = "access-control-allow-headers", .value = "cache-control" }, // 33
    .{ .name = "access-control-allow-headers", .value = "content-type" }, // 34
    .{ .name = "access-control-allow-origin", .value = "*" }, // 35
    .{ .name = "cache-control", .value = "max-age=0" }, // 36
    .{ .name = "cache-control", .value = "max-age=2592000" }, // 37
    .{ .name = "cache-control", .value = "max-age=604800" }, // 38
    .{ .name = "cache-control", .value = "no-cache" }, // 39
    .{ .name = "cache-control", .value = "no-store" }, // 40
    .{ .name = "cache-control", .value = "public, max-age=31536000" }, // 41
    .{ .name = "content-encoding", .value = "br" }, // 42
    .{ .name = "content-encoding", .value = "gzip" }, // 43
    .{ .name = "content-type", .value = "application/dns-message" }, // 44
    .{ .name = "content-type", .value = "application/javascript" }, // 45
    .{ .name = "content-type", .value = "application/json" }, // 46
    .{ .name = "content-type", .value = "application/x-www-form-urlencoded" }, // 47
    .{ .name = "content-type", .value = "image/gif" }, // 48
    .{ .name = "content-type", .value = "image/jpeg" }, // 49
    .{ .name = "content-type", .value = "image/png" }, // 50
    .{ .name = "content-type", .value = "text/css" }, // 51
    .{ .name = "content-type", .value = "text/html; charset=utf-8" }, // 52
    .{ .name = "content-type", .value = "text/plain" }, // 53
    .{ .name = "content-type", .value = "text/plain;charset=utf-8" }, // 54
    .{ .name = "range", .value = "bytes=0-" }, // 55
    .{ .name = "strict-transport-security", .value = "max-age=31536000" }, // 56
    .{ .name = "strict-transport-security", .value = "max-age=31536000; includesubdomains" }, // 57
    .{ .name = "strict-transport-security", .value = "max-age=31536000; includesubdomains; preload" }, // 58
    .{ .name = "vary", .value = "accept-encoding" }, // 59
    .{ .name = "vary", .value = "origin" }, // 60
    .{ .name = "x-content-type-options", .value = "nosniff" }, // 61
    .{ .name = "x-xss-protection", .value = "1; mode=block" }, // 62
    .{ .name = ":status", .value = "100" }, // 63
    .{ .name = ":status", .value = "204" }, // 64
    .{ .name = ":status", .value = "206" }, // 65
    .{ .name = ":status", .value = "302" }, // 66
    .{ .name = ":status", .value = "400" }, // 67
    .{ .name = ":status", .value = "403" }, // 68
    .{ .name = ":status", .value = "421" }, // 69
    .{ .name = ":status", .value = "425" }, // 70
    .{ .name = ":status", .value = "500" }, // 71
    .{ .name = "accept-language", .value = "" }, // 72
    .{ .name = "access-control-allow-credentials", .value = "FALSE" }, // 73
    .{ .name = "access-control-allow-credentials", .value = "TRUE" }, // 74
    .{ .name = "access-control-allow-headers", .value = "*" }, // 75
    .{ .name = "access-control-allow-methods", .value = "get" }, // 76
    .{ .name = "access-control-allow-methods", .value = "get, post, options" }, // 77
    .{ .name = "access-control-allow-methods", .value = "options" }, // 78
    .{ .name = "access-control-expose-headers", .value = "content-length" }, // 79
    .{ .name = "access-control-request-headers", .value = "content-type" }, // 80
    .{ .name = "access-control-request-method", .value = "get" }, // 81
    .{ .name = "access-control-request-method", .value = "post" }, // 82
    .{ .name = "alt-svc", .value = "clear" }, // 83
    .{ .name = "authorization", .value = "" }, // 84
    .{ .name = "content-security-policy", .value = "script-src 'none'; object-src 'none'; base-uri 'none'" }, // 85
    .{ .name = "early-data", .value = "1" }, // 86
    .{ .name = "expect-ct", .value = "" }, // 87
    .{ .name = "forwarded", .value = "" }, // 88
    .{ .name = "if-range", .value = "" }, // 89
    .{ .name = "origin", .value = "" }, // 90
    .{ .name = "purpose", .value = "prefetch" }, // 91
    .{ .name = "server", .value = "" }, // 92
    .{ .name = "timing-allow-origin", .value = "*" }, // 93
    .{ .name = "upgrade-insecure-requests", .value = "1" }, // 94
    .{ .name = "user-agent", .value = "" }, // 95
    .{ .name = "x-forwarded-for", .value = "" }, // 96
    .{ .name = "x-frame-options", .value = "deny" }, // 97
    .{ .name = "x-frame-options", .value = "sameorigin" }, // 98
};

/// Find the best static table match for a header.
/// Returns (index, name_and_value_match).
fn findStaticMatch(name: []const u8, value: []const u8) ?struct { index: u8, full_match: bool } {
    var name_match_idx: ?u8 = null;

    for (static_table, 0..) |entry, i| {
        if (std.mem.eql(u8, entry.name, name)) {
            if (std.mem.eql(u8, entry.value, value)) {
                return .{ .index = @intCast(i), .full_match = true };
            }
            if (name_match_idx == null) {
                name_match_idx = @intCast(i);
            }
        }
    }

    if (name_match_idx) |idx| {
        return .{ .index = idx, .full_match = false };
    }
    return null;
}

/// Encode a QPACK integer with the given prefix bit count.
/// RFC 9204 Section 4.1.1 (same as HPACK integer encoding).
fn encodeInteger(buf: []u8, pos: *usize, value: usize, prefix_bits: u4, first_byte: u8) void {
    const max_prefix: u8 = @intCast((@as(u16, 1) << prefix_bits) - 1);

    if (value < max_prefix) {
        buf[pos.*] = first_byte | @as(u8, @intCast(value));
        pos.* += 1;
    } else {
        buf[pos.*] = first_byte | max_prefix;
        pos.* += 1;
        var remaining = value - max_prefix;
        while (remaining >= 128) {
            buf[pos.*] = @as(u8, @intCast(remaining & 0x7f)) | 0x80;
            pos.* += 1;
            remaining >>= 7;
        }
        buf[pos.*] = @as(u8, @intCast(remaining));
        pos.* += 1;
    }
}

/// Decode a QPACK integer with the given prefix bit count.
fn decodeInteger(data: []const u8, pos: *usize, prefix_bits: u4) !usize {
    if (pos.* >= data.len) return error.BufferTooShort;

    const max_prefix: u8 = @intCast((@as(u16, 1) << prefix_bits) - 1);
    var value: usize = data[pos.*] & max_prefix;
    pos.* += 1;

    if (value < max_prefix) return value;

    var shift: u6 = 0;
    while (pos.* < data.len) {
        const b = data[pos.*];
        pos.* += 1;
        const shift_clamped = @as(std.math.Log2Int(usize), @intCast(@min(shift, @bitSizeOf(usize) - 1)));
        value += @as(usize, b & 0x7f) << shift_clamped;
        if (b & 0x80 == 0) return value;
        shift += 7;
    }
    return error.BufferTooShort;
}

/// Encode a string literal (no Huffman encoding).
fn encodeString(buf: []u8, pos: *usize, s: []const u8) void {
    // Length prefix with H=0 (no Huffman), 7-bit prefix
    encodeInteger(buf, pos, s.len, 7, 0x00);
    @memcpy(buf[pos.*..][0..s.len], s);
    pos.* += s.len;
}

/// Decode a string literal (plain or Huffman-encoded).
/// Huffman-decoded strings are written into `scratch` at `scratch_pos.*`,
/// which advances so each string gets its own stable slice.
fn decodeString(data: []const u8, pos: *usize, scratch: []u8, scratch_pos: *usize) ![]const u8 {
    if (pos.* >= data.len) return error.BufferTooShort;
    const is_huffman = (data[pos.*] & 0x80) != 0;

    const len = try decodeInteger(data, pos, 7);
    if (pos.* + len > data.len) return error.BufferTooShort;

    const raw = data[pos.*..][0..len];
    pos.* += len;

    if (is_huffman) {
        // Decode Huffman-encoded string into scratch buffer at current position
        var temp_buf: [4096]u8 = undefined;
        const decoded_len = huffman.decode(raw, &temp_buf) catch return error.InvalidEncoding;
        if (scratch_pos.* + decoded_len > scratch.len) return error.BufferTooSmall;
        @memcpy(scratch[scratch_pos.*..][0..decoded_len], temp_buf[0..decoded_len]);
        const result = scratch[scratch_pos.*..][0..decoded_len];
        scratch_pos.* += decoded_len;
        return result;
    }

    // Copy raw string to scratch buffer for lifetime safety
    // (source data buffer may be reused/shifted by caller)
    if (scratch_pos.* + len > scratch.len) return error.BufferTooSmall;
    @memcpy(scratch[scratch_pos.*..][0..len], raw);
    const result = scratch[scratch_pos.*..][0..len];
    scratch_pos.* += len;
    return result;
}

// ── Dynamic Table (RFC 9204 §3.2) ──────────────────────────────────────

/// Entry overhead per RFC 9204 §3.2.1: name.len + value.len + 32.
const ENTRY_OVERHEAD: usize = 32;

/// A single dynamic table entry with inline storage.
pub const DynEntry = struct {
    name_buf: [128]u8 = undefined,
    name_len: u8 = 0,
    value_buf: [512]u8 = undefined,
    value_len: u16 = 0,

    pub fn getName(self: *const DynEntry) []const u8 {
        return self.name_buf[0..self.name_len];
    }

    pub fn getValue(self: *const DynEntry) []const u8 {
        return self.value_buf[0..self.value_len];
    }

    pub fn entrySize(self: *const DynEntry) usize {
        return @as(usize, self.name_len) + @as(usize, self.value_len) + ENTRY_OVERHEAD;
    }
};

/// Compute entry size from name/value slices.
fn computeEntrySize(name: []const u8, value: []const u8) usize {
    return name.len + value.len + ENTRY_OVERHEAD;
}

/// FIFO dynamic table with ring buffer storage.
pub const DynamicTable = struct {
    const MAX_ENTRIES = 128;

    entries: [MAX_ENTRIES]DynEntry = undefined,
    head: usize = 0, // next write position (newest)
    count: usize = 0, // current entry count
    size: usize = 0, // current size in bytes
    capacity: usize = 0, // max size in bytes (from SETTINGS)
    insert_count: u64 = 0, // total insertions ever (absolute index base)

    /// Set the capacity, evicting entries if needed.
    pub fn setCapacity(self: *DynamicTable, cap: usize) void {
        self.capacity = cap;
        while (self.size > self.capacity and self.count > 0) {
            self.evict();
        }
    }

    /// Insert a new entry. Returns error if name/value too large for inline storage.
    pub fn insert(self: *DynamicTable, name: []const u8, value: []const u8) !void {
        if (name.len > 128) return error.NameTooLong;
        if (value.len > 512) return error.ValueTooLong;

        const entry_size = computeEntrySize(name, value);
        if (entry_size > self.capacity) return error.EntryTooLarge;

        // Evict until there's room
        while (self.size + entry_size > self.capacity and self.count > 0) {
            self.evict();
        }

        // Write at head
        var entry = &self.entries[self.head];
        @memcpy(entry.name_buf[0..name.len], name);
        entry.name_len = @intCast(name.len);
        @memcpy(entry.value_buf[0..value.len], value);
        entry.value_len = @intCast(value.len);

        self.head = (self.head + 1) % MAX_ENTRIES;
        self.count += 1;
        self.size += entry_size;
        self.insert_count += 1;
    }

    /// Evict the oldest entry (tail of the FIFO).
    fn evict(self: *DynamicTable) void {
        if (self.count == 0) return;
        // tail index: head points one past newest, so oldest is at head - count
        const tail = (self.head + MAX_ENTRIES - self.count) % MAX_ENTRIES;
        self.size -= self.entries[tail].entrySize();
        self.count -= 1;
    }

    /// Get entry by absolute index (0 = first ever inserted).
    /// Returns null if the entry has been evicted or not yet inserted.
    pub fn get(self: *const DynamicTable, abs_idx: u64) ?*const DynEntry {
        // Absolute index range of entries currently in the table:
        // oldest = insert_count - count, newest = insert_count - 1
        if (self.count == 0) return null;
        const oldest = self.insert_count - self.count;
        if (abs_idx < oldest or abs_idx >= self.insert_count) return null;

        // Map to ring buffer position
        // The newest entry is at (head - 1), abs_idx = insert_count - 1
        // offset from newest = (insert_count - 1) - abs_idx
        const offset_from_newest = self.insert_count - 1 - abs_idx;
        const ring_idx = @as(usize, @intCast((self.head + MAX_ENTRIES - 1 - offset_from_newest) % MAX_ENTRIES));
        return &self.entries[ring_idx];
    }

    /// Get entry by relative index from a given base.
    /// RFC 9204 §3.2.3: relative index = base - absolute_index - 1
    /// So absolute_index = base - relative_index - 1
    pub fn getRelative(self: *const DynamicTable, base: u64, rel_idx: u64) ?*const DynEntry {
        if (rel_idx >= base) return null;
        const abs_idx = base - rel_idx - 1;
        return self.get(abs_idx);
    }

    /// Get entry by post-base index.
    /// RFC 9204 §3.2.3: absolute_index = base + post_base_index
    pub fn getPostBase(self: *const DynamicTable, base: u64, post_base_idx: u64) ?*const DynEntry {
        const abs_idx = base + post_base_idx;
        return self.get(abs_idx);
    }

    /// Result of a dynamic table search.
    pub const MatchResult = struct {
        abs_index: u64,
        full_match: bool,
    };

    /// Search dynamic table for a match. Returns best match if any.
    pub fn findMatch(self: *const DynamicTable, name: []const u8, value: []const u8) ?MatchResult {
        if (self.count == 0) return null;

        var name_match: ?u64 = null;
        const oldest = self.insert_count - self.count;

        // Search from newest to oldest for best match
        var i: u64 = self.insert_count;
        while (i > oldest) {
            i -= 1;
            const entry = self.get(i) orelse continue;
            if (std.mem.eql(u8, entry.getName(), name)) {
                if (std.mem.eql(u8, entry.getValue(), value)) {
                    return .{ .abs_index = i, .full_match = true };
                }
                if (name_match == null) {
                    name_match = i;
                }
            }
        }

        if (name_match) |idx| {
            return .{ .abs_index = idx, .full_match = false };
        }
        return null;
    }

    /// Compute MaxEntries = floor(capacity / 32).
    pub fn maxEntries(self: *const DynamicTable) u64 {
        if (self.capacity == 0) return 0;
        return @intCast(self.capacity / ENTRY_OVERHEAD);
    }
};

/// Encode Required Insert Count per RFC 9204 §4.5.1.
fn encodeRequiredInsertCount(ric: u64, max_entries: u64) u64 {
    if (ric == 0) return 0;
    return (ric % (2 * max_entries)) + 1;
}

/// Decode Required Insert Count per RFC 9204 §4.5.1.
fn decodeRequiredInsertCount(encoded: u64, max_entries: u64, total_insert_count: u64) !u64 {
    if (encoded == 0) return 0;
    if (max_entries == 0) return error.InvalidRIC;

    const full_range = 2 * max_entries;
    if (encoded > full_range) return error.InvalidRIC;

    const max_value = total_insert_count + max_entries;
    const max_wrapped = max_value / full_range * full_range;
    var ric = max_wrapped + encoded - 1;

    if (ric > max_value) {
        if (ric < full_range) return error.InvalidRIC;
        ric -= full_range;
    }
    if (ric == 0) return error.InvalidRIC;
    return ric;
}

// ── QPACK Encoder (RFC 9204 §4.1) ─────────────────────────────────────

pub const QpackEncoder = struct {
    dynamic: DynamicTable = .{},
    max_capacity: usize = 0,
    instruction_buf: [4096]u8 = undefined,
    instruction_len: usize = 0,

    /// Set capacity from peer's SETTINGS_QPACK_MAX_TABLE_CAPACITY.
    pub fn setCapacity(self: *QpackEncoder, cap: usize) void {
        self.max_capacity = cap;
        self.dynamic.setCapacity(cap);
        // Emit Set Dynamic Table Capacity instruction: 001XXXXX (5-bit prefix)
        if (cap > 0) {
            var pos = self.instruction_len;
            encodeInteger(&self.instruction_buf, &pos, cap, 5, 0x20);
            self.instruction_len = pos;
        }
    }

    /// Encode headers into a QPACK header block, using dynamic table when possible.
    /// Returns the number of bytes written to buf.
    pub fn encode(self: *QpackEncoder, headers: []const Header, buf: []u8) !usize {
        if (self.max_capacity == 0) {
            // No dynamic table — use static-only encoding
            return encodeHeaders(headers, buf);
        }

        var pos: usize = 0;
        if (buf.len < 2) return error.BufferTooSmall;

        // We'll fill in the RIC prefix after encoding all headers
        // For now, track whether we used any dynamic refs
        var used_dynamic = false;
        const ric_start = self.dynamic.insert_count;

        // Reserve space for RIC + delta base (fill later)
        const prefix_start: usize = 0;
        pos = 2; // minimum 2 bytes for prefix, may grow

        // Encode each header
        var field_buf: [4096]u8 = undefined;
        var field_pos: usize = 0;

        for (headers) |h| {
            // 1. Check static table first
            if (findStaticMatch(h.name, h.value)) |smatch| {
                if (smatch.full_match) {
                    // Indexed static: 11NNNNNN
                    encodeInteger(&field_buf, &field_pos, smatch.index, 6, 0xc0);
                    continue;
                }

                // 2. Check dynamic table for full match
                if (self.dynamic.findMatch(h.name, h.value)) |dmatch| {
                    if (dmatch.full_match) {
                        // Indexed dynamic: 10NNNNNN (T=0, relative index)
                        const base = self.dynamic.insert_count;
                        const rel_idx = base - dmatch.abs_index - 1;
                        encodeInteger(&field_buf, &field_pos, rel_idx, 6, 0x80);
                        used_dynamic = true;
                        continue;
                    }
                }

                // Static name match — literal with static name ref + insert to dynamic
                encodeInteger(&field_buf, &field_pos, smatch.index, 4, 0x50);
                encodeString(&field_buf, &field_pos, h.value);

                // Try to insert into dynamic table + emit encoder instruction
                self.tryInsertWithStaticNameRef(smatch.index, h.value);
                continue;
            }

            // 3. Check dynamic table
            if (self.dynamic.findMatch(h.name, h.value)) |dmatch| {
                const base = self.dynamic.insert_count;
                if (dmatch.full_match) {
                    // Indexed dynamic: 10NNNNNN
                    const rel_idx = base - dmatch.abs_index - 1;
                    encodeInteger(&field_buf, &field_pos, rel_idx, 6, 0x80);
                    used_dynamic = true;
                    continue;
                }
                // Dynamic name match — literal with dynamic name ref
                const rel_idx = base - dmatch.abs_index - 1;
                encodeInteger(&field_buf, &field_pos, rel_idx, 4, 0x40);
                encodeString(&field_buf, &field_pos, h.value);

                // Try to insert with literal name
                self.tryInsertWithLiteralName(h.name, h.value);
                continue;
            }

            // 4. No match — literal with literal name
            encodeInteger(&field_buf, &field_pos, h.name.len, 3, 0x20);
            @memcpy(field_buf[field_pos..][0..h.name.len], h.name);
            field_pos += h.name.len;
            encodeString(&field_buf, &field_pos, h.value);

            // Try to insert for future use
            self.tryInsertWithLiteralName(h.name, h.value);
        }

        // Now build the prefix
        _ = prefix_start;
        var prefix_buf: [16]u8 = undefined;
        var prefix_pos: usize = 0;

        if (used_dynamic) {
            const ric = self.dynamic.insert_count;
            _ = ric_start;
            const max_entries = self.dynamic.maxEntries();
            const encoded_ric = encodeRequiredInsertCount(ric, max_entries);
            encodeInteger(&prefix_buf, &prefix_pos, encoded_ric, 8, 0x00);
            // Delta Base = 0 (base == RIC), sign = 0
            encodeInteger(&prefix_buf, &prefix_pos, 0, 7, 0x00);
        } else {
            // RIC = 0, Delta Base = 0
            prefix_buf[0] = 0x00;
            prefix_buf[1] = 0x00;
            prefix_pos = 2;
        }

        // Copy prefix + field lines to output
        if (prefix_pos + field_pos > buf.len) return error.BufferTooSmall;
        @memcpy(buf[0..prefix_pos], prefix_buf[0..prefix_pos]);
        @memcpy(buf[prefix_pos..][0..field_pos], field_buf[0..field_pos]);
        pos = prefix_pos + field_pos;

        return pos;
    }

    /// Try to insert an entry with a static name reference.
    /// Emits "Insert with Name Reference" encoder instruction.
    fn tryInsertWithStaticNameRef(self: *QpackEncoder, static_idx: u8, value: []const u8) void {
        if (value.len > 512) return; // too large for inline storage
        if (computeEntrySize(static_table[static_idx].name, value) > self.dynamic.capacity) return;

        self.dynamic.insert(static_table[static_idx].name, value) catch return;

        // Encoder instruction: 1TNNNNNN — T=1 for static, 6-bit index
        var pos = self.instruction_len;
        if (pos + 2 + value.len + 8 > self.instruction_buf.len) return;
        encodeInteger(&self.instruction_buf, &pos, static_idx, 6, 0xc0);
        encodeString(&self.instruction_buf, &pos, value);
        self.instruction_len = pos;
    }

    /// Try to insert an entry with a literal name.
    /// Emits "Insert with Literal Name" encoder instruction.
    fn tryInsertWithLiteralName(self: *QpackEncoder, name: []const u8, value: []const u8) void {
        if (name.len > 128 or value.len > 512) return;
        if (computeEntrySize(name, value) > self.dynamic.capacity) return;

        self.dynamic.insert(name, value) catch return;

        // Encoder instruction: 01NNNNNN — 5-bit name length prefix with H=0
        var pos = self.instruction_len;
        if (pos + 2 + name.len + value.len + 16 > self.instruction_buf.len) return;
        // 01HXXXXX — H=0 (no Huffman), 5-bit name length
        encodeInteger(&self.instruction_buf, &pos, name.len, 5, 0x40);
        @memcpy(self.instruction_buf[pos..][0..name.len], name);
        pos += name.len;
        encodeString(&self.instruction_buf, &pos, value);
        self.instruction_len = pos;
    }

    /// Get pending encoder instructions and clear the buffer.
    pub fn getInstructions(self: *QpackEncoder) []const u8 {
        const result = self.instruction_buf[0..self.instruction_len];
        self.instruction_len = 0;
        return result;
    }

    /// Process decoder instructions (Insert Count Increment, Header Ack, Stream Cancellation).
    pub fn processDecoderInstruction(self: *QpackEncoder, data: []const u8) !void {
        var pos: usize = 0;
        while (pos < data.len) {
            const first = data[pos];
            if (first & 0x80 != 0) {
                // Header Acknowledgment: 1XXXXXXX — 7-bit stream ID
                _ = try decodeInteger(data, &pos, 7);
                // We don't track per-stream state, so just consume
            } else if (first & 0xc0 == 0x40) {
                // Stream Cancellation: 01XXXXXX — 6-bit stream ID
                _ = try decodeInteger(data, &pos, 6);
            } else {
                // Insert Count Increment: 00XXXXXX — 6-bit increment
                const increment = try decodeInteger(data, &pos, 6);
                // RFC 9204 §4.4.3: increment of 0 is QPACK_DECODER_STREAM_ERROR
                if (increment == 0) return error.QpackDecoderStreamError;
                _ = self; // acknowledged, no action needed in our simple model
            }
        }
    }
};

// ── QPACK Decoder (RFC 9204 §4.2) ─────────────────────────────────────

pub const QpackDecoder = struct {
    dynamic: DynamicTable = .{},
    max_capacity: usize = 0,
    instruction_buf: [4096]u8 = undefined,
    instruction_len: usize = 0,

    /// Set local max capacity.
    pub fn setCapacity(self: *QpackDecoder, cap: usize) void {
        self.max_capacity = cap;
        // Don't set dynamic table capacity yet — wait for encoder's Set Capacity instruction
    }

    /// Decode a QPACK header block, resolving dynamic table references.
    /// Returns the number of headers decoded.
    pub fn decode(self: *QpackDecoder, data: []const u8, headers_buf: []Header, stream_id: u64) !usize {
        if (data.len < 2) return error.BufferTooShort;

        var pos: usize = 0;
        var scratch_pos: usize = 0;

        // Decode Required Insert Count
        const encoded_ric = try decodeInteger(data, &pos, 8);

        // Decode Delta Base
        const sign_bit = (data[pos] & 0x80) != 0;
        const delta_base = try decodeInteger(data, &pos, 7);

        // Compute RIC and Base
        var ric: u64 = 0;
        var base: u64 = 0;
        if (encoded_ric > 0) {
            const max_entries = self.dynamic.maxEntries();
            ric = try decodeRequiredInsertCount(encoded_ric, max_entries, self.dynamic.insert_count);
            if (sign_bit) {
                base = ric - delta_base - 1;
            } else {
                base = ric + delta_base;
            }
        }

        var count: usize = 0;

        while (pos < data.len) {
            if (count >= headers_buf.len) return error.TooManyHeaders;

            const first = data[pos];

            if (first & 0xc0 == 0xc0) {
                // Indexed static: 11NNNNNN
                const index = try decodeInteger(data, &pos, 6);
                if (index >= static_table.len) return error.InvalidIndex;
                headers_buf[count] = .{
                    .name = static_table[index].name,
                    .value = static_table[index].value,
                };
                count += 1;
            } else if (first & 0xc0 == 0x80) {
                // Indexed dynamic: 10NNNNNN (T=0, relative index from base)
                const rel_idx = try decodeInteger(data, &pos, 6);
                const entry = self.dynamic.getRelative(base, rel_idx) orelse return error.InvalidIndex;
                // Copy name/value from dynamic entry into scratch
                const n = entry.getName();
                const v = entry.getValue();
                if (scratch_pos + n.len + v.len > huffman_scratch.len) return error.BufferTooSmall;
                @memcpy(huffman_scratch[scratch_pos..][0..n.len], n);
                const name_slice = huffman_scratch[scratch_pos..][0..n.len];
                scratch_pos += n.len;
                @memcpy(huffman_scratch[scratch_pos..][0..v.len], v);
                const value_slice = huffman_scratch[scratch_pos..][0..v.len];
                scratch_pos += v.len;
                headers_buf[count] = .{ .name = name_slice, .value = value_slice };
                count += 1;
            } else if (first & 0xc0 == 0x40) {
                // Literal Field Line with Name Reference: 01NTNNNN (RFC 9204 §4.5.4)
                // N = never-indexed (bit 5), T = table type (bit 4): 1=static, 0=dynamic
                const is_static = (first & 0x10) != 0;
                if (is_static) {
                    const index = try decodeInteger(data, &pos, 4);
                    if (index >= static_table.len) return error.InvalidIndex;
                    const value = try decodeString(data, &pos, &huffman_scratch, &scratch_pos);
                    headers_buf[count] = .{
                        .name = static_table[index].name,
                        .value = value,
                    };
                    count += 1;
                } else {
                    const rel_idx = try decodeInteger(data, &pos, 4);
                    const entry = self.dynamic.getRelative(base, rel_idx) orelse return error.InvalidIndex;
                    const n = entry.getName();
                    if (scratch_pos + n.len > huffman_scratch.len) return error.BufferTooSmall;
                    @memcpy(huffman_scratch[scratch_pos..][0..n.len], n);
                    const name_slice = huffman_scratch[scratch_pos..][0..n.len];
                    scratch_pos += n.len;
                    const value = try decodeString(data, &pos, &huffman_scratch, &scratch_pos);
                    headers_buf[count] = .{ .name = name_slice, .value = value };
                    count += 1;
                }
            } else if (first & 0xe0 == 0x20) {
                // Literal with literal name: 001NHNNN
                const is_name_huffman = (first & 0x08) != 0;
                const name_len = try decodeInteger(data, &pos, 3);
                if (pos + name_len > data.len) return error.BufferTooShort;
                var name: []const u8 = undefined;
                if (is_name_huffman) {
                    var temp_buf: [4096]u8 = undefined;
                    const decoded_len = huffman.decode(data[pos..][0..name_len], &temp_buf) catch return error.InvalidEncoding;
                    if (scratch_pos + decoded_len > huffman_scratch.len) return error.BufferTooSmall;
                    @memcpy(huffman_scratch[scratch_pos..][0..decoded_len], temp_buf[0..decoded_len]);
                    name = huffman_scratch[scratch_pos..][0..decoded_len];
                    scratch_pos += decoded_len;
                } else {
                    // Copy raw name to scratch for lifetime safety
                    if (scratch_pos + name_len > huffman_scratch.len) return error.BufferTooSmall;
                    @memcpy(huffman_scratch[scratch_pos..][0..name_len], data[pos..][0..name_len]);
                    name = huffman_scratch[scratch_pos..][0..name_len];
                    scratch_pos += name_len;
                }
                pos += name_len;
                const value = try decodeString(data, &pos, &huffman_scratch, &scratch_pos);
                headers_buf[count] = .{ .name = name, .value = value };
                count += 1;
            } else if (first & 0xf0 == 0x10) {
                // Post-base indexed: 0001NNNN
                const post_idx = try decodeInteger(data, &pos, 4);
                const entry = self.dynamic.getPostBase(base, post_idx) orelse return error.InvalidIndex;
                const n = entry.getName();
                const v = entry.getValue();
                if (scratch_pos + n.len + v.len > huffman_scratch.len) return error.BufferTooSmall;
                @memcpy(huffman_scratch[scratch_pos..][0..n.len], n);
                const name_slice = huffman_scratch[scratch_pos..][0..n.len];
                scratch_pos += n.len;
                @memcpy(huffman_scratch[scratch_pos..][0..v.len], v);
                const value_slice = huffman_scratch[scratch_pos..][0..v.len];
                scratch_pos += v.len;
                headers_buf[count] = .{ .name = name_slice, .value = value_slice };
                count += 1;
            } else if (first & 0xf0 == 0x00) {
                // Literal with post-base name ref: 0000NNNN
                const post_idx = try decodeInteger(data, &pos, 3);
                const entry = self.dynamic.getPostBase(base, post_idx) orelse return error.InvalidIndex;
                const n = entry.getName();
                if (scratch_pos + n.len > huffman_scratch.len) return error.BufferTooSmall;
                @memcpy(huffman_scratch[scratch_pos..][0..n.len], n);
                const name_slice = huffman_scratch[scratch_pos..][0..n.len];
                scratch_pos += n.len;
                const value = try decodeString(data, &pos, &huffman_scratch, &scratch_pos);
                headers_buf[count] = .{ .name = name_slice, .value = value };
                count += 1;
            } else {
                pos += 1;
            }
        }

        // Emit Header Acknowledgment if we used dynamic refs
        if (ric > 0) {
            self.emitHeaderAck(stream_id);
        }

        return count;
    }

    /// Process encoder instructions from the encoder stream.
    pub fn processEncoderInstruction(self: *QpackDecoder, data: []const u8) !void {
        var pos: usize = 0;
        var scratch_pos: usize = 0;

        while (pos < data.len) {
            const first = data[pos];

            if (first & 0x80 != 0) {
                // Insert with Name Reference: 1TNNNNNN
                const is_static = (first & 0x40) != 0;
                const name_idx = try decodeInteger(data, &pos, 6);
                const value = try decodeString(data, &pos, &huffman_scratch, &scratch_pos);

                var name: []const u8 = undefined;
                if (is_static) {
                    if (name_idx >= static_table.len) return error.InvalidIndex;
                    name = static_table[name_idx].name;
                } else {
                    // Dynamic table name ref — absolute index
                    const entry = self.dynamic.get(name_idx) orelse return error.InvalidIndex;
                    name = entry.getName();
                }
                try self.dynamic.insert(name, value);
            } else if (first & 0xc0 == 0x40) {
                // Insert with Literal Name: 01HXXXXX
                const is_name_huffman = (first & 0x20) != 0;
                const name_len = try decodeInteger(data, &pos, 5);
                if (pos + name_len > data.len) return error.BufferTooShort;

                var name: []const u8 = undefined;
                if (is_name_huffman) {
                    var temp_buf: [4096]u8 = undefined;
                    const decoded_len = huffman.decode(data[pos..][0..name_len], &temp_buf) catch return error.InvalidEncoding;
                    if (scratch_pos + decoded_len > huffman_scratch.len) return error.BufferTooSmall;
                    @memcpy(huffman_scratch[scratch_pos..][0..decoded_len], temp_buf[0..decoded_len]);
                    name = huffman_scratch[scratch_pos..][0..decoded_len];
                    scratch_pos += decoded_len;
                } else {
                    name = data[pos..][0..name_len];
                }
                pos += name_len;

                const value = try decodeString(data, &pos, &huffman_scratch, &scratch_pos);
                try self.dynamic.insert(name, value);
            } else if (first & 0xe0 == 0x00) {
                // Duplicate: 000XXXXX — 5-bit index
                const idx = try decodeInteger(data, &pos, 5);
                const entry = self.dynamic.get(idx) orelse return error.InvalidIndex;
                const n = entry.getName();
                const v = entry.getValue();
                try self.dynamic.insert(n, v);
            } else if (first & 0xe0 == 0x20) {
                // Set Dynamic Table Capacity: 001XXXXX — 5-bit capacity
                const cap = try decodeInteger(data, &pos, 5);
                if (cap > self.max_capacity) return error.CapacityExceeded;
                self.dynamic.setCapacity(cap);
            } else {
                pos += 1;
            }
        }
    }

    /// Emit a Header Acknowledgment decoder instruction.
    fn emitHeaderAck(self: *QpackDecoder, stream_id: u64) void {
        var pos = self.instruction_len;
        if (pos + 8 > self.instruction_buf.len) return;
        // Header Ack: 1XXXXXXX — 7-bit stream ID
        encodeInteger(&self.instruction_buf, &pos, @as(usize, @intCast(stream_id)), 7, 0x80);
        self.instruction_len = pos;
    }

    /// Get pending decoder instructions and clear the buffer.
    pub fn getInstructions(self: *QpackDecoder) []const u8 {
        const result = self.instruction_buf[0..self.instruction_len];
        self.instruction_len = 0;
        return result;
    }
};

/// Encode HTTP headers into a QPACK header block (static-only, no Huffman).
/// Returns the number of bytes written.
pub fn encodeHeaders(headers: []const Header, buf: []u8) !usize {
    var pos: usize = 0;

    // Required Insert Count = 0, Delta Base = 0 (static-only mode)
    // Encoded as two bytes: 0x00 0x00
    if (buf.len < 2) return error.BufferTooSmall;
    buf[0] = 0x00;
    buf[1] = 0x00;
    pos = 2;

    for (headers) |h| {
        if (pos >= buf.len) return error.BufferTooSmall;

        if (findStaticMatch(h.name, h.value)) |match| {
            if (match.full_match) {
                // Indexed field line (static): 1TNNNNNN, T=1 for static
                // Pattern: 11NNNNNN (6-bit index)
                encodeInteger(buf, &pos, match.index, 6, 0xc0);
            } else {
                // Literal with name reference (static): 0101NNNN
                // 4-bit index prefix, T=1 for static
                encodeInteger(buf, &pos, match.index, 4, 0x50);
                encodeString(buf, &pos, h.value);
            }
        } else {
            // Literal with literal name: 001NHNNN
            // N=0 (allow indexing), H=0 (no Huffman for name), 3-bit name length prefix
            // Name length is encoded in the first byte's lower 3 bits
            encodeInteger(buf, &pos, h.name.len, 3, 0x20);
            @memcpy(buf[pos..][0..h.name.len], h.name);
            pos += h.name.len;
            // Value length + value (7-bit prefix, H=0)
            encodeString(buf, &pos, h.value);
        }
    }

    return pos;
}

/// Scratch buffer for Huffman-decoded strings within a single decodeHeaders call.
/// Each decoded string gets its own slice, so they don't overwrite each other.
var huffman_scratch: [16384]u8 = undefined;

/// Decode a QPACK header block into headers.
/// Returns the number of headers decoded.
pub fn decodeHeaders(data: []const u8, headers_buf: []Header) !usize {
    if (data.len < 2) return error.BufferTooShort;

    var pos: usize = 0;
    var scratch_pos: usize = 0;

    // Required Insert Count — accept any value (we ignore dynamic table refs)
    _ = try decodeInteger(data, &pos, 8);

    // Delta Base (sign bit + value) — accept any value
    _ = try decodeInteger(data, &pos, 7);

    var count: usize = 0;

    while (pos < data.len) {
        if (count >= headers_buf.len) return error.TooManyHeaders;

        const first = data[pos];

        if (first & 0xc0 == 0xc0) {
            // Indexed field line (static): 11NNNNNN
            const index = try decodeInteger(data, &pos, 6);
            if (index >= static_table.len) return error.InvalidIndex;
            headers_buf[count] = .{
                .name = static_table[index].name,
                .value = static_table[index].value,
            };
            count += 1;
        } else if (first & 0xc0 == 0x40) {
            // Literal Field Line with Name Reference: 01NTNNNN (RFC 9204 §4.5.4)
            // N = never-indexed (bit 5), T = table type (bit 4): 1=static, 0=dynamic
            const is_static = (first & 0x10) != 0;
            const index = try decodeInteger(data, &pos, 4);
            const value = try decodeString(data, &pos, &huffman_scratch, &scratch_pos);
            if (is_static) {
                if (index >= static_table.len) return error.InvalidIndex;
                headers_buf[count] = .{
                    .name = static_table[index].name,
                    .value = value,
                };
                count += 1;
            }
            // Dynamic refs (T=0): skip — value already consumed above
        } else if (first & 0xe0 == 0x20) {
            // Literal with literal name: 001NHNNN
            // H bit (bit 3) indicates Huffman for name, 3-bit name length prefix
            const is_name_huffman = (first & 0x08) != 0;
            const name_len = try decodeInteger(data, &pos, 3);
            if (pos + name_len > data.len) return error.BufferTooShort;
            var name: []const u8 = undefined;
            if (is_name_huffman) {
                var temp_buf: [4096]u8 = undefined;
                const decoded_len = huffman.decode(data[pos..][0..name_len], &temp_buf) catch return error.InvalidEncoding;
                if (scratch_pos + decoded_len > huffman_scratch.len) return error.BufferTooSmall;
                @memcpy(huffman_scratch[scratch_pos..][0..decoded_len], temp_buf[0..decoded_len]);
                name = huffman_scratch[scratch_pos..][0..decoded_len];
                scratch_pos += decoded_len;
            } else {
                // Copy raw name to scratch for lifetime safety
                if (scratch_pos + name_len > huffman_scratch.len) return error.BufferTooSmall;
                @memcpy(huffman_scratch[scratch_pos..][0..name_len], data[pos..][0..name_len]);
                name = huffman_scratch[scratch_pos..][0..name_len];
                scratch_pos += name_len;
            }
            pos += name_len;
            const value = try decodeString(data, &pos, &huffman_scratch, &scratch_pos);
            headers_buf[count] = .{
                .name = name,
                .value = value,
            };
            count += 1;
        } else if (first & 0x80 == 0x80) {
            // Indexed field line: 1TNNNNNN
            if (first & 0x40 == 0) {
                // T=0: dynamic table reference — skip (consume the integer)
                _ = try decodeInteger(data, &pos, 6);
                continue;
            }
            // T=1 already handled above (0xc0 check)
            _ = try decodeInteger(data, &pos, 6);
        } else if (first & 0xf0 == 0x10) {
            // Post-base indexed (dynamic): 0001NNNN — skip
            _ = try decodeInteger(data, &pos, 4);
        } else if (first & 0xf0 == 0x00) {
            // Literal with post-base name ref (dynamic): 0000NNNN — skip
            _ = try decodeInteger(data, &pos, 3);
            _ = try decodeString(data, &pos, &huffman_scratch, &scratch_pos);
        } else {
            // Unknown encoding pattern — skip byte
            pos += 1;
        }
    }

    return count;
}

// Tests

test "QPACK: encode and decode indexed header" {
    var buf: [256]u8 = undefined;
    const headers = [_]Header{
        .{ .name = ":method", .value = "GET" }, // static index 17
        .{ .name = ":path", .value = "/" }, // static index 1
        .{ .name = ":scheme", .value = "https" }, // static index 23
    };

    const encoded_len = try encodeHeaders(&headers, &buf);
    try testing.expect(encoded_len > 2);

    var decoded: [16]Header = undefined;
    const count = try decodeHeaders(buf[0..encoded_len], &decoded);
    try testing.expectEqual(@as(usize, 3), count);
    try testing.expectEqualStrings(":method", decoded[0].name);
    try testing.expectEqualStrings("GET", decoded[0].value);
    try testing.expectEqualStrings(":path", decoded[1].name);
    try testing.expectEqualStrings("/", decoded[1].value);
    try testing.expectEqualStrings(":scheme", decoded[2].name);
    try testing.expectEqualStrings("https", decoded[2].value);
}

test "QPACK: encode name reference with literal value" {
    var buf: [256]u8 = undefined;
    const headers = [_]Header{
        .{ .name = ":authority", .value = "example.com" }, // index 0, name match only
    };

    const encoded_len = try encodeHeaders(&headers, &buf);

    var decoded: [8]Header = undefined;
    const count = try decodeHeaders(buf[0..encoded_len], &decoded);
    try testing.expectEqual(@as(usize, 1), count);
    try testing.expectEqualStrings(":authority", decoded[0].name);
    try testing.expectEqualStrings("example.com", decoded[0].value);
}

test "QPACK: encode literal name and value" {
    var buf: [256]u8 = undefined;
    const headers = [_]Header{
        .{ .name = "x-custom", .value = "foobar" }, // no static match
    };

    const encoded_len = try encodeHeaders(&headers, &buf);

    var decoded: [8]Header = undefined;
    const count = try decodeHeaders(buf[0..encoded_len], &decoded);
    try testing.expectEqual(@as(usize, 1), count);
    try testing.expectEqualStrings("x-custom", decoded[0].name);
    try testing.expectEqualStrings("foobar", decoded[0].value);
}

test "QPACK: full GET request" {
    var buf: [512]u8 = undefined;
    const headers = [_]Header{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "localhost" },
        .{ .name = ":path", .value = "/" },
        .{ .name = "user-agent", .value = "quic-zig/1.0" },
    };

    const encoded_len = try encodeHeaders(&headers, &buf);

    var decoded: [16]Header = undefined;
    const count = try decodeHeaders(buf[0..encoded_len], &decoded);
    try testing.expectEqual(@as(usize, 5), count);

    try testing.expectEqualStrings(":method", decoded[0].name);
    try testing.expectEqualStrings("GET", decoded[0].value);
    try testing.expectEqualStrings(":scheme", decoded[1].name);
    try testing.expectEqualStrings("https", decoded[1].value);
    try testing.expectEqualStrings(":authority", decoded[2].name);
    try testing.expectEqualStrings("localhost", decoded[2].value);
    try testing.expectEqualStrings(":path", decoded[3].name);
    try testing.expectEqualStrings("/", decoded[3].value);
    try testing.expectEqualStrings("user-agent", decoded[4].name);
    try testing.expectEqualStrings("quic-zig/1.0", decoded[4].value);
}

test "QPACK: full 200 response" {
    var buf: [512]u8 = undefined;
    const headers = [_]Header{
        .{ .name = ":status", .value = "200" },
        .{ .name = "content-type", .value = "text/plain" },
        .{ .name = "content-length", .value = "5" },
    };

    const encoded_len = try encodeHeaders(&headers, &buf);

    var decoded: [16]Header = undefined;
    const count = try decodeHeaders(buf[0..encoded_len], &decoded);
    try testing.expectEqual(@as(usize, 3), count);
    try testing.expectEqualStrings(":status", decoded[0].name);
    try testing.expectEqualStrings("200", decoded[0].value);
    try testing.expectEqualStrings("content-type", decoded[1].name);
    try testing.expectEqualStrings("text/plain", decoded[1].value);
    try testing.expectEqualStrings("content-length", decoded[2].name);
    try testing.expectEqualStrings("5", decoded[2].value);
}

test "QPACK: static table has 99 entries" {
    try testing.expectEqual(@as(usize, 99), static_table.len);
}

test "QPACK: integer encoding edge cases" {
    // Test encoding values that require multi-byte integer representation
    var buf: [16]u8 = undefined;
    var pos: usize = 0;

    // Value 63 with 6-bit prefix (exactly at boundary)
    encodeInteger(&buf, &pos, 63, 6, 0xc0);
    try testing.expectEqual(@as(usize, 2), pos); // needs continuation

    // Decode it back
    var dpos: usize = 0;
    const val = try decodeInteger(&buf, &dpos, 6);
    try testing.expectEqual(@as(usize, 63), val);
}

// ── Dynamic Table Tests ────────────────────────────────────────────────

test "DynamicTable: insert and lookup" {
    var dt = DynamicTable{};
    dt.setCapacity(4096);

    try dt.insert(":authority", "example.com");
    try testing.expectEqual(@as(u64, 1), dt.insert_count);
    try testing.expectEqual(@as(usize, 1), dt.count);

    // Absolute index 0
    const entry = dt.get(0).?;
    try testing.expectEqualStrings(":authority", entry.getName());
    try testing.expectEqualStrings("example.com", entry.getValue());
}

test "DynamicTable: multiple inserts and relative indexing" {
    var dt = DynamicTable{};
    dt.setCapacity(4096);

    try dt.insert(":authority", "example.com"); // abs 0
    try dt.insert("user-agent", "quic-zig/1.0"); // abs 1
    try dt.insert("content-type", "text/plain"); // abs 2

    try testing.expectEqual(@as(usize, 3), dt.count);

    // Relative from base=3: rel 0 = abs 2, rel 1 = abs 1, rel 2 = abs 0
    const e0 = dt.getRelative(3, 0).?;
    try testing.expectEqualStrings("content-type", e0.getName());

    const e1 = dt.getRelative(3, 1).?;
    try testing.expectEqualStrings("user-agent", e1.getName());

    const e2 = dt.getRelative(3, 2).?;
    try testing.expectEqualStrings(":authority", e2.getName());
}

test "DynamicTable: eviction on capacity" {
    var dt = DynamicTable{};
    // Small capacity: only room for ~1-2 entries
    // ":authority" (10) + "example.com" (11) + 32 = 53 bytes
    dt.setCapacity(100);

    try dt.insert(":authority", "example.com"); // 53 bytes, abs 0
    try testing.expectEqual(@as(usize, 1), dt.count);

    try dt.insert("user-agent", "test"); // 10+4+32=46 bytes, abs 1
    // Total would be 53+46=99, fits in 100
    try testing.expectEqual(@as(usize, 2), dt.count);

    try dt.insert("x-custom", "value"); // 8+5+32=45 bytes, abs 2
    // 99+45=144 > 100, so oldest (abs 0) evicted, then 46+45=91 <= 100
    try testing.expectEqual(@as(usize, 2), dt.count);
    // abs 0 should be evicted
    try testing.expect(dt.get(0) == null);
    // abs 1 and 2 should exist
    try testing.expect(dt.get(1) != null);
    try testing.expect(dt.get(2) != null);
}

test "DynamicTable: findMatch" {
    var dt = DynamicTable{};
    dt.setCapacity(4096);

    try dt.insert(":authority", "example.com"); // abs 0
    try dt.insert(":authority", "other.com"); // abs 1

    // Full match
    const full = dt.findMatch(":authority", "example.com").?;
    try testing.expect(full.full_match);
    try testing.expectEqual(@as(u64, 0), full.abs_index);

    // Name-only match (returns newest)
    const name_only = dt.findMatch(":authority", "unknown.com").?;
    try testing.expect(!name_only.full_match);
    try testing.expectEqual(@as(u64, 1), name_only.abs_index);

    // No match
    try testing.expect(dt.findMatch("x-nonexist", "val") == null);
}

test "DynamicTable: entrySize calculation" {
    try testing.expectEqual(@as(usize, 42), computeEntrySize(":authority", ""));
    try testing.expectEqual(@as(usize, 53), computeEntrySize(":authority", "example.com"));
}

test "RIC: encode and decode roundtrip" {
    // maxEntries = 4096 / 32 = 128
    const max_entries: u64 = 128;

    // RIC = 0
    try testing.expectEqual(@as(u64, 0), encodeRequiredInsertCount(0, max_entries));

    // RIC = 1
    const encoded1 = encodeRequiredInsertCount(1, max_entries);
    try testing.expectEqual(@as(u64, 2), encoded1); // (1 % 256) + 1 = 2
    const decoded1 = try decodeRequiredInsertCount(encoded1, max_entries, 1);
    try testing.expectEqual(@as(u64, 1), decoded1);

    // RIC = 10
    const encoded10 = encodeRequiredInsertCount(10, max_entries);
    const decoded10 = try decodeRequiredInsertCount(encoded10, max_entries, 10);
    try testing.expectEqual(@as(u64, 10), decoded10);
}

test "QpackEncoder: static-only fallback when capacity=0" {
    var encoder = QpackEncoder{};

    const headers = [_]Header{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "/" },
    };

    var buf: [256]u8 = undefined;
    const len = try encoder.encode(&headers, &buf);
    try testing.expect(len > 2);

    // Should decode fine with static decoder
    var decoded: [16]Header = undefined;
    const count = try decodeHeaders(buf[0..len], &decoded);
    try testing.expectEqual(@as(usize, 2), count);
    try testing.expectEqualStrings(":method", decoded[0].name);
    try testing.expectEqualStrings("GET", decoded[0].value);
}

test "QpackEncoder: generates encoder instructions" {
    var encoder = QpackEncoder{};
    encoder.setCapacity(4096);

    const headers = [_]Header{
        .{ .name = ":method", .value = "GET" }, // static full match, no insert
        .{ .name = ":authority", .value = "example.com" }, // static name match, inserts
        .{ .name = "x-custom", .value = "foobar" }, // no match, inserts
    };

    var buf: [4096]u8 = undefined;
    _ = try encoder.encode(&headers, &buf);

    // Should have generated encoder instructions
    const instructions = encoder.getInstructions();
    try testing.expect(instructions.len > 0);

    // Dynamic table should have entries
    try testing.expect(encoder.dynamic.count >= 2);
}

test "QpackEncoder + QpackDecoder: instruction roundtrip" {
    var encoder = QpackEncoder{};
    encoder.setCapacity(4096);

    // First request — builds dynamic table
    const headers1 = [_]Header{
        .{ .name = ":authority", .value = "example.com" },
        .{ .name = "user-agent", .value = "quic-zig/1.0" },
    };

    var buf: [4096]u8 = undefined;
    _ = try encoder.encode(&headers1, &buf);

    // Get encoder instructions and feed to decoder
    const enc_instructions = encoder.getInstructions();
    try testing.expect(enc_instructions.len > 0);

    var decoder = QpackDecoder{};
    decoder.setCapacity(4096);
    try decoder.processEncoderInstruction(enc_instructions);

    // Decoder should now have the same entries
    try testing.expectEqual(encoder.dynamic.count, decoder.dynamic.count);

    // Verify decoder has the right entries
    const e0 = decoder.dynamic.get(0).?;
    try testing.expectEqualStrings(":authority", e0.getName());
    try testing.expectEqualStrings("example.com", e0.getValue());
}

test "QpackDecoder: decode with dynamic refs" {
    // Set up encoder and decoder with shared state
    var encoder = QpackEncoder{};
    encoder.setCapacity(4096);

    var decoder = QpackDecoder{};
    decoder.setCapacity(4096);

    // First encode — populates dynamic table but uses static refs
    const headers1 = [_]Header{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":authority", .value = "test.example.com" },
        .{ .name = "user-agent", .value = "quic-zig/1.0" },
    };

    var buf: [4096]u8 = undefined;
    const len1 = try encoder.encode(&headers1, &buf);

    // Sync encoder instructions to decoder
    const instr1 = encoder.getInstructions();
    try decoder.processEncoderInstruction(instr1);

    // First decode — static refs only, no header ack expected
    var decoded: [16]Header = undefined;
    const count1 = try decoder.decode(buf[0..len1], &decoded, 0);
    try testing.expectEqual(@as(usize, 3), count1);
    try testing.expectEqualStrings(":authority", decoded[1].name);
    try testing.expectEqualStrings("test.example.com", decoded[1].value);
    _ = decoder.getInstructions(); // drain

    // Second encode — should use dynamic refs for repeated headers
    var buf2: [4096]u8 = undefined;
    const len2 = try encoder.encode(&headers1, &buf2);

    // Sync any new encoder instructions
    const instr2 = encoder.getInstructions();
    if (instr2.len > 0) {
        try decoder.processEncoderInstruction(instr2);
    }

    // Second decode — should resolve dynamic refs
    var decoded2: [16]Header = undefined;
    const count2 = try decoder.decode(buf2[0..len2], &decoded2, 4);
    try testing.expectEqual(@as(usize, 3), count2);
    try testing.expectEqualStrings(":method", decoded2[0].name);
    try testing.expectEqualStrings("GET", decoded2[0].value);
    try testing.expectEqualStrings(":authority", decoded2[1].name);
    try testing.expectEqualStrings("test.example.com", decoded2[1].value);
    try testing.expectEqualStrings("user-agent", decoded2[2].name);
    try testing.expectEqualStrings("quic-zig/1.0", decoded2[2].value);

    // Should have emitted a header ack (dynamic refs were used)
    const dec_instr = decoder.getInstructions();
    try testing.expect(dec_instr.len > 0);
}

test "QpackDecoder: process Set Capacity instruction" {
    var decoder = QpackDecoder{};
    decoder.setCapacity(4096); // local max

    // Encoder sends Set Capacity: 001XXXXX with value 2048
    var instr_buf: [16]u8 = undefined;
    var pos: usize = 0;
    encodeInteger(&instr_buf, &pos, 2048, 5, 0x20);

    try decoder.processEncoderInstruction(instr_buf[0..pos]);
    try testing.expectEqual(@as(usize, 2048), decoder.dynamic.capacity);
}

test "QpackEncoder: second encode reuses dynamic table" {
    var encoder = QpackEncoder{};
    encoder.setCapacity(4096);

    // First encode
    const headers = [_]Header{
        .{ .name = ":authority", .value = "example.com" },
    };

    var buf1: [4096]u8 = undefined;
    const len1 = try encoder.encode(&headers, &buf1);

    // Drain instructions
    _ = encoder.getInstructions();

    // Second encode — same header, should find in dynamic table
    var buf2: [4096]u8 = undefined;
    const len2 = try encoder.encode(&headers, &buf2);

    // Second encoding should be smaller or equal (dynamic indexed vs literal)
    try testing.expect(len2 <= len1);

    // Should have no new encoder instructions (entry already exists)
    const instr2 = encoder.getInstructions();
    _ = instr2;
    // The entry is already in dynamic table so no new insert instruction
}
