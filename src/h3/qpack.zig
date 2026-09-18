const std = @import("std");
const limits = @import("../quic/limits.zig");
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
fn encodeInteger(buf: []u8, pos: *usize, value: usize, prefix_bits: u4, first_byte: u8) !void {
    const max_prefix: u8 = @intCast((@as(u16, 1) << prefix_bits) - 1);

    if (value < max_prefix) {
        try putByte(buf, pos, first_byte | @as(u8, @intCast(value)));
    } else {
        try putByte(buf, pos, first_byte | max_prefix);
        var remaining = value - max_prefix;
        while (remaining >= 128) {
            try putByte(buf, pos, @as(u8, @intCast(remaining & 0x7f)) | 0x80);
            remaining >>= 7;
        }
        try putByte(buf, pos, @as(u8, @intCast(remaining)));
    }
}

fn putByte(buf: []u8, pos: *usize, byte: u8) !void {
    if (pos.* >= buf.len) return error.BufferTooSmall;
    buf[pos.*] = byte;
    pos.* += 1;
}

/// Copies a header name or value in at `pos`. Both are peer-sized on a
/// proxy, so neither is bounded by anything but this check.
fn putBytes(buf: []u8, pos: *usize, s: []const u8) !void {
    if (pos.* > buf.len or s.len > buf.len - pos.*) return error.BufferTooSmall;
    @memcpy(buf[pos.*..][0..s.len], s);
    pos.* += s.len;
}

/// Decode a QPACK integer with the given prefix bit count.
fn decodeInteger(data: []const u8, pos: *usize, prefix_bits: u4) !usize {
    if (pos.* >= data.len) return error.BufferTooShort;

    const max_prefix: u8 = @intCast((@as(u16, 1) << prefix_bits) - 1);
    var value: usize = data[pos.*] & max_prefix;
    pos.* += 1;

    if (value < max_prefix) return value;

    // RFC 7541 5.1 puts no bound on the continuation run, so a peer picks how
    // long it is: ten bytes of 0x80 overflow the shift, and more overflow the
    // accumulator. Both are reachable from any HTTP/3 peer.
    var shift: u8 = 0;
    while (pos.* < data.len) {
        const b = data[pos.*];
        pos.* += 1;
        if (shift >= @bitSizeOf(usize)) return error.IntegerTooLarge;
        const add = std.math.shlExact(usize, @as(usize, b & 0x7f), @intCast(shift)) catch
            return error.IntegerTooLarge;
        value = std.math.add(usize, value, add) catch return error.IntegerTooLarge;
        if (b & 0x80 == 0) return value;
        shift += 7;
    }
    return error.BufferTooShort;
}

/// Encode a string literal (no Huffman encoding).
fn encodeString(buf: []u8, pos: *usize, s: []const u8) !void {
    // Length prefix with H=0 (no Huffman), 7-bit prefix
    try encodeInteger(buf, pos, s.len, 7, 0x00);
    try putBytes(buf, pos, s);
}

/// Decode a string literal (plain or Huffman-encoded).
/// Huffman-decoded strings are written into `scratch` at `scratch_pos.*`,
/// which advances so each string gets its own stable slice.
fn decodeString(data: []const u8, pos: *usize, scratch: []u8, scratch_pos: *usize) ![]const u8 {
    if (pos.* >= data.len) return error.BufferTooShort;
    const is_huffman = (data[pos.*] & 0x80) != 0;

    const len = try decodeInteger(data, pos, 7);
    // Subtract rather than add: `len` is an unchecked wire varint.
    if (len > data.len - pos.*) return error.BufferTooShort;

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

/// A view of one dynamic table entry. The slices point into the table's
/// arena and stay valid until that entry is evicted.
pub const DynEntry = struct {
    name: []const u8,
    value: []const u8,

    pub fn entrySize(self: DynEntry) usize {
        return self.name.len + self.value.len + ENTRY_OVERHEAD;
    }
};

/// Compute entry size from name/value slices.
fn computeEntrySize(name: []const u8, value: []const u8) usize {
    return name.len + value.len + ENTRY_OVERHEAD;
}

/// FIFO dynamic table (RFC 9204 §3.2).
///
/// Names and values live in one arena sized to the capacity we are willing
/// to advertise, indexed by a ring of small descriptors. The protocol bounds
/// total content by the negotiated capacity — `insert` enforces it — so the
/// arena cannot overflow, and there is no per-entry size limit beyond what
/// the capacity itself implies.
pub const DynamicTable = struct {
    /// Also the arena size: content can never exceed the capacity.
    pub const MAX_CAPACITY: usize = limits.qpack_table_capacity;
    /// An entry costs at least ENTRY_OVERHEAD, so this many is the most the
    /// capacity can ever hold.
    const MAX_ENTRIES: usize = MAX_CAPACITY / ENTRY_OVERHEAD;

    const Desc = struct {
        off: u32 = 0,
        name_len: u16 = 0,
        value_len: u16 = 0,
    };

    arena: [MAX_CAPACITY]u8 = undefined,
    descs: [MAX_ENTRIES]Desc = undefined,
    /// Bytes of arena consumed. Live content is always [tail.off, used).
    used: usize = 0,
    count: usize = 0, // current entry count
    size: usize = 0, // current size in bytes, per RFC accounting
    capacity: usize = 0, // max size in bytes (from SETTINGS)
    insert_count: u64 = 0, // total insertions ever (absolute index base)

    /// Descriptor slot the next insert takes. Derived rather than tracked:
    /// only insert advances it, in lockstep with insert_count.
    fn headIndex(self: *const DynamicTable) usize {
        return @intCast(self.insert_count % MAX_ENTRIES);
    }

    fn tailIndex(self: *const DynamicTable) usize {
        return (self.headIndex() + MAX_ENTRIES - self.count) % MAX_ENTRIES;
    }

    fn entryAt(self: *const DynamicTable, ring_idx: usize) DynEntry {
        const d = self.descs[ring_idx];
        return .{
            .name = self.arena[d.off..][0..d.name_len],
            .value = self.arena[d.off + d.name_len ..][0..d.value_len],
        };
    }

    /// Set the capacity, evicting entries if needed. A peer asking for more
    /// than we sized the arena for is clamped, not trusted.
    pub fn setCapacity(self: *DynamicTable, cap: usize) void {
        self.capacity = @min(cap, MAX_CAPACITY);
        while (self.size > self.capacity and self.count > 0) {
            self.evict();
        }
    }

    /// Slide the live entries back to the start of the arena. They are always
    /// contiguous — insertion only ever appends, eviction only ever drops the
    /// oldest — so this is one move plus an offset fixup.
    fn compact(self: *DynamicTable) void {
        const tail = self.tailIndex();
        const base = self.descs[tail].off;
        if (base == 0) return;
        const live = self.used - base;
        std.mem.copyForwards(u8, self.arena[0..live], self.arena[base..][0..live]);
        var i: usize = 0;
        while (i < self.count) : (i += 1) {
            const idx = (tail + i) % MAX_ENTRIES;
            self.descs[idx].off -= base;
        }
        self.used = live;
    }

    /// Insert a new entry, evicting oldest-first to make room.
    ///
    /// `name` and `value` may point into this table's own arena: the encoder
    /// stream's Duplicate and Insert With Name Reference both name an entry
    /// already in it (RFC 9204 4.3.4, 4.3.2). So they are staged out before
    /// anything moves — otherwise the copy below either overlaps its source,
    /// or reads from where `compact()` has just moved the entry away from,
    /// which puts one peer-chosen entry's bytes under another's name.
    pub fn insert(self: *DynamicTable, name: []const u8, value: []const u8) !void {
        const entry_size = computeEntrySize(name, value);
        if (entry_size > self.capacity) return error.EntryTooLarge;

        const content = name.len + value.len;
        if (content > MAX_CAPACITY) return error.EntryTooLarge;

        var staged: [MAX_CAPACITY]u8 = undefined;
        @memcpy(staged[0..name.len], name);
        @memcpy(staged[name.len..][0..value.len], value);

        while (self.size + entry_size > self.capacity and self.count > 0) {
            self.evict();
        }

        if (self.used + content > MAX_CAPACITY) self.compact();

        const off: u32 = @intCast(self.used);
        if (off + content > self.arena.len) return error.EntryTooLarge;
        @memcpy(self.arena[off..][0..content], staged[0..content]);

        // Before insert_count moves — headIndex() is derived from it.
        self.descs[self.headIndex()] = .{
            .off = off,
            .name_len = @intCast(name.len),
            .value_len = @intCast(value.len),
        };
        self.used += content;
        self.count += 1;
        self.size += entry_size;
        self.insert_count += 1;
    }

    /// Evict the oldest entry (tail of the FIFO). Arena space is reclaimed
    /// lazily by `compact`.
    fn evict(self: *DynamicTable) void {
        if (self.count == 0) return;
        const tail = self.tailIndex();
        self.size -= self.entryAt(tail).entrySize();
        self.count -= 1;
        if (self.count == 0) self.used = 0;
    }

    /// Get entry by absolute index (0 = first ever inserted).
    /// Returns null if the entry has been evicted or not yet inserted.
    pub fn get(self: *const DynamicTable, abs_idx: u64) ?DynEntry {
        if (self.count == 0) return null;
        const oldest = self.insert_count - self.count;
        if (abs_idx < oldest or abs_idx >= self.insert_count) return null;

        const offset_from_newest = self.insert_count - 1 - abs_idx;
        const ring_idx = (self.headIndex() + MAX_ENTRIES - 1 - @as(usize, @intCast(offset_from_newest))) % MAX_ENTRIES;
        return self.entryAt(ring_idx);
    }

    /// Get entry by relative index from a given base.
    /// RFC 9204 §3.2.3: relative index = base - absolute_index - 1
    pub fn getRelative(self: *const DynamicTable, base: u64, rel_idx: u64) ?DynEntry {
        if (rel_idx >= base) return null;
        return self.get(base - rel_idx - 1);
    }

    /// Get entry by post-base index.
    /// RFC 9204 §3.2.3: absolute_index = base + post_base_index
    pub fn getPostBase(self: *const DynamicTable, base: u64, post_base_idx: u64) ?DynEntry {
        const abs = std.math.add(u64, base, post_base_idx) catch return null;
        return self.get(abs);
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

        var i: u64 = self.insert_count;
        while (i > oldest) {
            i -= 1;
            const entry = self.get(i) orelse continue;
            if (std.mem.eql(u8, entry.name, name)) {
                if (std.mem.eql(u8, entry.value, value)) {
                    return .{ .abs_index = i, .full_match = true };
                }
                if (name_match == null) name_match = i;
            }
        }

        if (name_match) |idx| return .{ .abs_index = idx, .full_match = false };
        return null;
    }

    /// Compute MaxEntries = floor(capacity / 32).
    pub fn maxEntries(self: *const DynamicTable) u64 {
        if (self.capacity == 0) return 0;
        return @intCast(self.capacity / ENTRY_OVERHEAD);
    }
};

/// RFC 9204 3.2.5: relative index `rel` counts back from `base`.
fn relativeToAbsolute(base: u64, rel: u64) ?u64 {
    if (rel >= base) return null;
    return base - rel - 1;
}

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

/// Widest encoded field section prefix: two prefixed integers.
const PREFIX_RESERVE: usize = 20;

/// An upper bound on the encoded size of `headers`, by either encoder: a
/// literal name and value plus two worst-case integer prefixes per line.
pub fn maxEncodedLen(headers: []const Header) usize {
    var n: usize = PREFIX_RESERVE;
    for (headers) |h| n += h.name.len + h.value.len + 24;
    return n;
}

pub const QpackEncoder = struct {
    dynamic: DynamicTable = .{},
    instruction_buf: [4096]u8 = undefined,
    instruction_len: usize = 0,

    /// Set capacity from peer's SETTINGS_QPACK_MAX_TABLE_CAPACITY.
    pub fn setCapacity(self: *QpackEncoder, cap: usize) void {
        self.dynamic.setCapacity(cap);
        // Announce what we will actually hold, not what was asked for:
        // setCapacity clamps to the arena size.
        const effective = self.dynamic.capacity;
        if (effective > 0) {
            var pos = self.instruction_len;
            // instruction_len is only advanced on success, so a full buffer
            // drops this instruction rather than truncating one.
            encodeInteger(&self.instruction_buf, &pos, effective, 5, 0x20) catch return;
            self.instruction_len = pos;
        }
    }

    /// Encode headers into a QPACK header block, using dynamic table when possible.
    /// Returns the number of bytes written to buf. A buffer of
    /// `maxEncodedLen(headers)` bytes always suffices.
    pub fn encode(self: *QpackEncoder, headers: []const Header, buf: []u8) !usize {
        if (self.dynamic.capacity == 0) {
            // No dynamic table — use static-only encoding
            return encodeHeaders(headers, buf);
        }

        // Field lines go straight into `buf` past room for the widest prefix,
        // then slide down once the prefix length is known.
        if (buf.len < PREFIX_RESERVE) return error.BufferTooSmall;
        const field_buf = buf[PREFIX_RESERVE..];
        var field_pos: usize = 0;
        var used_dynamic = false;

        for (headers) |h| {
            // 1. Check static table first
            if (findStaticMatch(h.name, h.value)) |smatch| {
                if (smatch.full_match) {
                    // Indexed static: 11NNNNNN
                    try encodeInteger(field_buf, &field_pos, smatch.index, 6, 0xc0);
                    continue;
                }

                // 2. Check dynamic table for full match
                if (self.dynamic.findMatch(h.name, h.value)) |dmatch| {
                    if (dmatch.full_match) {
                        // Indexed dynamic: 10NNNNNN (T=0, relative index)
                        const base = self.dynamic.insert_count;
                        const rel_idx = base - dmatch.abs_index - 1;
                        try encodeInteger(field_buf, &field_pos, rel_idx, 6, 0x80);
                        used_dynamic = true;
                        continue;
                    }
                }

                // Static name match — literal with static name ref + insert to dynamic
                try encodeInteger(field_buf, &field_pos, smatch.index, 4, 0x50);
                try encodeString(field_buf, &field_pos, h.value);

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
                    try encodeInteger(field_buf, &field_pos, rel_idx, 6, 0x80);
                    used_dynamic = true;
                    continue;
                }
                // Dynamic name match — literal with dynamic name ref
                const rel_idx = base - dmatch.abs_index - 1;
                try encodeInteger(field_buf, &field_pos, rel_idx, 4, 0x40);
                try encodeString(field_buf, &field_pos, h.value);

                // Try to insert with literal name
                self.tryInsertWithLiteralName(h.name, h.value);
                continue;
            }

            // 4. No match — literal with literal name
            try encodeInteger(field_buf, &field_pos, h.name.len, 3, 0x20);
            try putBytes(field_buf, &field_pos, h.name);
            try encodeString(field_buf, &field_pos, h.value);

            // Try to insert for future use
            self.tryInsertWithLiteralName(h.name, h.value);
        }

        var prefix_buf: [PREFIX_RESERVE]u8 = undefined;
        var prefix_pos: usize = 0;

        if (used_dynamic) {
            const ric = self.dynamic.insert_count;
            const max_entries = self.dynamic.maxEntries();
            const encoded_ric = encodeRequiredInsertCount(ric, max_entries);
            try encodeInteger(&prefix_buf, &prefix_pos, encoded_ric, 8, 0x00);
            // Delta Base = 0 (base == RIC), sign = 0
            try encodeInteger(&prefix_buf, &prefix_pos, 0, 7, 0x00);
        } else {
            // RIC = 0, Delta Base = 0
            prefix_buf[0] = 0x00;
            prefix_buf[1] = 0x00;
            prefix_pos = 2;
        }

        std.mem.copyForwards(u8, buf[prefix_pos..][0..field_pos], field_buf[0..field_pos]);
        @memcpy(buf[0..prefix_pos], prefix_buf[0..prefix_pos]);
        return prefix_pos + field_pos;
    }

    /// Try to insert an entry with a static name reference.
    /// Emits "Insert with Name Reference" encoder instruction.
    fn tryInsertWithStaticNameRef(self: *QpackEncoder, static_idx: u8, value: []const u8) void {
        // Stage the instruction first: an entry the peer never hears about
        // turns every later reference to it into a decode failure.
        var pos = self.instruction_len;
        encodeInteger(&self.instruction_buf, &pos, static_idx, 6, 0xc0) catch return;
        encodeString(&self.instruction_buf, &pos, value) catch return;
        self.dynamic.insert(static_table[static_idx].name, value) catch return;
        self.instruction_len = pos;
    }

    /// Try to insert an entry with a literal name.
    /// Emits "Insert with Literal Name" encoder instruction.
    fn tryInsertWithLiteralName(self: *QpackEncoder, name: []const u8, value: []const u8) void {
        // Stage the instruction first; see tryInsertWithStaticNameRef.
        var pos = self.instruction_len;
        // 01HXXXXX — H=0 (no Huffman), 5-bit name length
        encodeInteger(&self.instruction_buf, &pos, name.len, 5, 0x40) catch return;
        putBytes(&self.instruction_buf, &pos, name) catch return;
        encodeString(&self.instruction_buf, &pos, value) catch return;
        self.dynamic.insert(name, value) catch return;
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

/// Enough scratch for one header block's decoded names and values.
pub const SCRATCH_SIZE = 16384;

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
    /// Decoded `Header` names/values are copied into `scratch` and point there;
    /// they stay valid only until the next decode using the same buffer.
    pub fn decode(
        self: *QpackDecoder,
        data: []const u8,
        headers_buf: []Header,
        scratch: []u8,
        stream_id: u64,
    ) !usize {
        if (data.len < 2) return error.BufferTooShort;

        var pos: usize = 0;
        var scratch_pos: usize = 0;

        // Decode Required Insert Count
        const encoded_ric = try decodeInteger(data, &pos, 8);

        // Decode Delta Base; a multi-byte RIC can use up the whole block.
        if (pos >= data.len) return error.BufferTooShort;
        const sign_bit = (data[pos] & 0x80) != 0;
        const delta_base = try decodeInteger(data, &pos, 7);

        // Compute RIC and Base
        var ric: u64 = 0;
        var base: u64 = 0;
        if (encoded_ric > 0) {
            const max_entries = self.dynamic.maxEntries();
            ric = try decodeRequiredInsertCount(encoded_ric, max_entries, self.dynamic.insert_count);
            if (sign_bit) {
                // RFC 9204 4.5.1.2: Base = RIC - DeltaBase - 1 must not go negative.
                if (delta_base >= ric) return error.InvalidBase;
                base = ric - delta_base - 1;
            } else {
                base = std.math.add(u64, ric, delta_base) catch return error.InvalidBase;
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
                const entry = try self.fieldRef(ric, relativeToAbsolute(base, rel_idx));
                // Copy name/value from dynamic entry into scratch
                const n = entry.name;
                const v = entry.value;
                if (scratch_pos + n.len + v.len > scratch.len) return error.BufferTooSmall;
                @memcpy(scratch[scratch_pos..][0..n.len], n);
                const name_slice = scratch[scratch_pos..][0..n.len];
                scratch_pos += n.len;
                @memcpy(scratch[scratch_pos..][0..v.len], v);
                const value_slice = scratch[scratch_pos..][0..v.len];
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
                    const value = try decodeString(data, &pos, scratch, &scratch_pos);
                    headers_buf[count] = .{
                        .name = static_table[index].name,
                        .value = value,
                    };
                    count += 1;
                } else {
                    const rel_idx = try decodeInteger(data, &pos, 4);
                    const entry = try self.fieldRef(ric, relativeToAbsolute(base, rel_idx));
                    const n = entry.name;
                    if (scratch_pos + n.len > scratch.len) return error.BufferTooSmall;
                    @memcpy(scratch[scratch_pos..][0..n.len], n);
                    const name_slice = scratch[scratch_pos..][0..n.len];
                    scratch_pos += n.len;
                    const value = try decodeString(data, &pos, scratch, &scratch_pos);
                    headers_buf[count] = .{ .name = name_slice, .value = value };
                    count += 1;
                }
            } else if (first & 0xe0 == 0x20) {
                // Literal with literal name: 001NHNNN
                const is_name_huffman = (first & 0x08) != 0;
                const name_len = try decodeInteger(data, &pos, 3);
                if (name_len > data.len - pos) return error.BufferTooShort;
                var name: []const u8 = undefined;
                if (is_name_huffman) {
                    var temp_buf: [4096]u8 = undefined;
                    const decoded_len = huffman.decode(data[pos..][0..name_len], &temp_buf) catch return error.InvalidEncoding;
                    if (scratch_pos + decoded_len > scratch.len) return error.BufferTooSmall;
                    @memcpy(scratch[scratch_pos..][0..decoded_len], temp_buf[0..decoded_len]);
                    name = scratch[scratch_pos..][0..decoded_len];
                    scratch_pos += decoded_len;
                } else {
                    // Copy raw name to scratch for lifetime safety
                    if (scratch_pos + name_len > scratch.len) return error.BufferTooSmall;
                    @memcpy(scratch[scratch_pos..][0..name_len], data[pos..][0..name_len]);
                    name = scratch[scratch_pos..][0..name_len];
                    scratch_pos += name_len;
                }
                pos += name_len;
                const value = try decodeString(data, &pos, scratch, &scratch_pos);
                headers_buf[count] = .{ .name = name, .value = value };
                count += 1;
            } else if (first & 0xf0 == 0x10) {
                // Post-base indexed: 0001NNNN
                const post_idx = try decodeInteger(data, &pos, 4);
                const entry = try self.fieldRef(ric, std.math.add(u64, base, post_idx) catch null);
                const n = entry.name;
                const v = entry.value;
                if (scratch_pos + n.len + v.len > scratch.len) return error.BufferTooSmall;
                @memcpy(scratch[scratch_pos..][0..n.len], n);
                const name_slice = scratch[scratch_pos..][0..n.len];
                scratch_pos += n.len;
                @memcpy(scratch[scratch_pos..][0..v.len], v);
                const value_slice = scratch[scratch_pos..][0..v.len];
                scratch_pos += v.len;
                headers_buf[count] = .{ .name = name_slice, .value = value_slice };
                count += 1;
            } else if (first & 0xf0 == 0x00) {
                // Literal with post-base name ref: 0000NNNN
                const post_idx = try decodeInteger(data, &pos, 3);
                const entry = try self.fieldRef(ric, std.math.add(u64, base, post_idx) catch null);
                const n = entry.name;
                if (scratch_pos + n.len > scratch.len) return error.BufferTooSmall;
                @memcpy(scratch[scratch_pos..][0..n.len], n);
                const name_slice = scratch[scratch_pos..][0..n.len];
                scratch_pos += n.len;
                const value = try decodeString(data, &pos, scratch, &scratch_pos);
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

    /// Resolve a field line's dynamic reference. RFC 9204 4.5.1: an entry at
    /// or past the block's Required Insert Count is a decompression failure,
    /// even if the table already holds it.
    fn fieldRef(self: *const QpackDecoder, ric: u64, abs_idx: ?u64) !DynEntry {
        const abs = abs_idx orelse return error.InvalidIndex;
        if (abs >= ric) return error.InvalidIndex;
        return self.dynamic.get(abs) orelse error.InvalidIndex;
    }

    /// Process encoder instructions from the encoder stream.
    pub fn processEncoderInstruction(self: *QpackDecoder, data: []const u8) !void {
        var pos: usize = 0;
        // Staging for one instruction's name/value: both are copied into the
        // dynamic table before the iteration ends, so nothing outlives it and
        // the position rewinds each time. An entry too large to stage here is
        // also too large for the table (insert would return EntryTooLarge).
        var scratch: [limits.qpack_table_capacity]u8 = undefined;
        var scratch_pos: usize = 0;

        while (pos < data.len) {
            scratch_pos = 0;
            const first = data[pos];

            if (first & 0x80 != 0) {
                // Insert with Name Reference: 1TNNNNNN
                const is_static = (first & 0x40) != 0;
                const name_idx = try decodeInteger(data, &pos, 6);
                const value = try decodeString(data, &pos, &scratch, &scratch_pos);

                var name: []const u8 = undefined;
                if (is_static) {
                    if (name_idx >= static_table.len) return error.InvalidIndex;
                    name = static_table[name_idx].name;
                } else {
                    // Dynamic table name ref — absolute index
                    const entry = self.dynamic.get(name_idx) orelse return error.InvalidIndex;
                    name = entry.name;
                }
                try self.dynamic.insert(name, value);
            } else if (first & 0xc0 == 0x40) {
                // Insert with Literal Name: 01HXXXXX
                const is_name_huffman = (first & 0x20) != 0;
                const name_len = try decodeInteger(data, &pos, 5);
                if (name_len > data.len - pos) return error.BufferTooShort;

                var name: []const u8 = undefined;
                if (is_name_huffman) {
                    var temp_buf: [4096]u8 = undefined;
                    const decoded_len = huffman.decode(data[pos..][0..name_len], &temp_buf) catch return error.InvalidEncoding;
                    if (scratch_pos + decoded_len > scratch.len) return error.BufferTooSmall;
                    @memcpy(scratch[scratch_pos..][0..decoded_len], temp_buf[0..decoded_len]);
                    name = scratch[scratch_pos..][0..decoded_len];
                    scratch_pos += decoded_len;
                } else {
                    name = data[pos..][0..name_len];
                }
                pos += name_len;

                const value = try decodeString(data, &pos, &scratch, &scratch_pos);
                try self.dynamic.insert(name, value);
            } else if (first & 0xe0 == 0x00) {
                // Duplicate: 000XXXXX — 5-bit index
                const idx = try decodeInteger(data, &pos, 5);
                const entry = self.dynamic.get(idx) orelse return error.InvalidIndex;
                const n = entry.name;
                const v = entry.value;
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
        encodeInteger(&self.instruction_buf, &pos, stream_id, 7, 0x80) catch return;
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
        if (findStaticMatch(h.name, h.value)) |match| {
            if (match.full_match) {
                // Indexed field line (static): 1TNNNNNN, T=1 for static
                // Pattern: 11NNNNNN (6-bit index)
                try encodeInteger(buf, &pos, match.index, 6, 0xc0);
            } else {
                // Literal with name reference (static): 0101NNNN
                // 4-bit index prefix, T=1 for static
                try encodeInteger(buf, &pos, match.index, 4, 0x50);
                try encodeString(buf, &pos, h.value);
            }
        } else {
            // Literal with literal name: 001NHNNN
            // N=0 (allow indexing), H=0 (no Huffman for name), 3-bit name length prefix
            // Name length is encoded in the first byte's lower 3 bits
            try encodeInteger(buf, &pos, h.name.len, 3, 0x20);
            try putBytes(buf, &pos, h.name);
            // Value length + value (7-bit prefix, H=0)
            try encodeString(buf, &pos, h.value);
        }
    }

    return pos;
}

/// Decode a QPACK header block into headers, resolving static-table
/// references only. Returns the number of headers decoded.
///
/// Names/values are copied into `scratch` and point there; they stay valid
/// only until the next decode using the same buffer. Size it `SCRATCH_SIZE`.
pub fn decodeHeaders(data: []const u8, headers_buf: []Header, scratch: []u8) !usize {
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
            const value = try decodeString(data, &pos, scratch, &scratch_pos);
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
            if (name_len > data.len - pos) return error.BufferTooShort;
            var name: []const u8 = undefined;
            if (is_name_huffman) {
                var temp_buf: [4096]u8 = undefined;
                const decoded_len = huffman.decode(data[pos..][0..name_len], &temp_buf) catch return error.InvalidEncoding;
                if (scratch_pos + decoded_len > scratch.len) return error.BufferTooSmall;
                @memcpy(scratch[scratch_pos..][0..decoded_len], temp_buf[0..decoded_len]);
                name = scratch[scratch_pos..][0..decoded_len];
                scratch_pos += decoded_len;
            } else {
                // Copy raw name to scratch for lifetime safety
                if (scratch_pos + name_len > scratch.len) return error.BufferTooSmall;
                @memcpy(scratch[scratch_pos..][0..name_len], data[pos..][0..name_len]);
                name = scratch[scratch_pos..][0..name_len];
                scratch_pos += name_len;
            }
            pos += name_len;
            const value = try decodeString(data, &pos, scratch, &scratch_pos);
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
            _ = try decodeString(data, &pos, scratch, &scratch_pos);
        } else {
            // Unknown encoding pattern — skip byte
            pos += 1;
        }
    }

    return count;
}

// Tests

// Tests run sequentially and never hold header slices across calls.
var test_scratch: [SCRATCH_SIZE]u8 = undefined;

test "decodeInteger rejects a continuation run that overflows" {
    // 0x7f opens a 7-bit-prefix integer at its maximum; every 0x80 after it
    // asks for another 7 bits, and the peer decides how many it sends.
    var data: [32]u8 = undefined;
    data[0] = 0x7f;
    @memset(data[1..], 0x80);

    var pos: usize = 0;
    try testing.expectError(error.IntegerTooLarge, decodeInteger(&data, &pos, 7));
}

test "encodeHeaders reports a buffer too small for the headers" {
    const headers = [_]Header{.{ .name = "x-custom", .value = "0123456789" }};
    var buf: [8]u8 = undefined;
    try testing.expectError(error.BufferTooSmall, encodeHeaders(&headers, &buf));
}

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
    const count = try decodeHeaders(buf[0..encoded_len], &decoded, &test_scratch);
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
    const count = try decodeHeaders(buf[0..encoded_len], &decoded, &test_scratch);
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
    const count = try decodeHeaders(buf[0..encoded_len], &decoded, &test_scratch);
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
    const count = try decodeHeaders(buf[0..encoded_len], &decoded, &test_scratch);
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
    const count = try decodeHeaders(buf[0..encoded_len], &decoded, &test_scratch);
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
    try encodeInteger(&buf, &pos, 63, 6, 0xc0);
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
    try testing.expectEqualStrings(":authority", entry.name);
    try testing.expectEqualStrings("example.com", entry.value);
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
    try testing.expectEqualStrings("content-type", e0.name);

    const e1 = dt.getRelative(3, 1).?;
    try testing.expectEqualStrings("user-agent", e1.name);

    const e2 = dt.getRelative(3, 2).?;
    try testing.expectEqualStrings(":authority", e2.name);
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
    const count = try decodeHeaders(buf[0..len], &decoded, &test_scratch);
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
    try testing.expectEqualStrings(":authority", e0.name);
    try testing.expectEqualStrings("example.com", e0.value);
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
    const count1 = try decoder.decode(buf[0..len1], &decoded, &test_scratch, 0);
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
    const count2 = try decoder.decode(buf2[0..len2], &decoded2, &test_scratch, 4);
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
    try encodeInteger(&instr_buf, &pos, 2048, 5, 0x20);

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

// ── Adversarial / malformed input tests (RFC 9204) ────────────────────

test "decodeHeaders: truncated prefix" {
    // Only 1 byte — prefix requires ≥2 bytes (RIC + Delta Base)
    var decoded: [4]Header = undefined;
    const r0 = decodeHeaders(&[_]u8{}, &decoded, &test_scratch);
    try testing.expectError(error.BufferTooShort, r0);

    const r1 = decodeHeaders(&[_]u8{0x00}, &decoded, &test_scratch);
    try testing.expectError(error.BufferTooShort, r1);
}

test "decodeHeaders: invalid static index" {
    // Indexed static (11NNNNNN) with index 99 is invalid (table is 0..98).
    // Encoding: prefix 0x00 0x00, then 11_111111 (=0x3f, index 63+continuation)
    // so we build one directly with a 6-bit value == 99 (valid range end),
    // and another with 100 (invalid).
    var decoded: [4]Header = undefined;

    // index = 100: 11 prefix + 6-bit 0x3f=63 + continuation byte 100-63=37
    const bad = [_]u8{ 0x00, 0x00, 0xff, 37 };
    try testing.expectError(error.InvalidIndex, decodeHeaders(&bad, &decoded, &test_scratch));
}

test "decodeHeaders: truncated literal value length" {
    // 001NHNNN literal-with-literal-name: 001_0_0001 name_len=1,
    // then claim name="x", then value length varint truncated.
    var decoded: [4]Header = undefined;
    // 7-bit length prefix continuation marker with no following byte:
    const bad = [_]u8{ 0x00, 0x00, 0x21, 'x', 0xff };
    const r = decodeHeaders(&bad, &decoded, &test_scratch);
    try testing.expect(std.meta.isError(r));
}

test "decodeHeaders: TooManyHeaders when buffer too small" {
    // Encode 5 headers but decode with a 3-slot buffer.
    var encode_buf: [256]u8 = undefined;
    const headers = [_]Header{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/" },
        .{ .name = ":authority", .value = "example.com" },
        .{ .name = ":status", .value = "200" },
    };
    const enc_len = try encodeHeaders(&headers, &encode_buf);

    var decoded: [3]Header = undefined;
    try testing.expectError(error.TooManyHeaders, decodeHeaders(encode_buf[0..enc_len], &decoded, &test_scratch));
}

test "QpackDecoder: Insert Count Increment of 0 is a stream error" {
    // RFC 9204 §4.4.3: decoder MUST treat increment=0 as QPACK_DECODER_STREAM_ERROR.
    // processDecoderInstruction is on the encoder side (it processes messages FROM
    // the peer's decoder). Instruction 00xxxxxx with value 0 = 0x00.
    var encoder = QpackEncoder{};
    try testing.expectError(
        error.QpackDecoderStreamError,
        encoder.processDecoderInstruction(&[_]u8{0x00}),
    );
}

test "QpackDecoder: Set Capacity above local max is rejected" {
    var decoder = QpackDecoder{};
    decoder.setCapacity(1024); // local max = 1024

    // Encoder instruction "Set Dynamic Table Capacity" with value 2048:
    // 001 prefix, 5-bit prefix = 31 marker, then continuation for 2048-31=2017.
    var buf: [16]u8 = undefined;
    var pos: usize = 0;
    try encodeInteger(&buf, &pos, 2048, 5, 0x20);

    try testing.expectError(
        error.CapacityExceeded,
        decoder.processEncoderInstruction(buf[0..pos]),
    );
}

test "QpackDecoder: invalid dynamic name reference" {
    // Decoder with empty dynamic table. Encode a field-line that references
    // dynamic-name index 0 (which doesn't exist).
    var decoder = QpackDecoder{};
    decoder.setCapacity(4096);

    // Prefix: RIC=1 (encoded via encodeRIC), Delta Base=0. We need a block
    // whose RIC decode advances past the table. Forge a block claiming RIC=0
    // (so dynamic refs fail), then literal-with-dynamic-name-ref (01N0NNNN),
    // index 0, value="x".
    // bytes: 0x00 (RIC=0), 0x00 (delta base=0), 0x40 (01 000000 → dynamic ref idx 0),
    // then value string: 0x01 'x'
    const bad = [_]u8{ 0x00, 0x00, 0x40, 0x01, 'x' };
    var out: [4]Header = undefined;
    try testing.expectError(error.InvalidIndex, decoder.decode(&bad, &out, &test_scratch, 0));
}

test "decodeHeaders: empty block (prefix only)" {
    // Valid: RIC=0, Delta Base=0, no fields → 0 headers.
    var decoded: [4]Header = undefined;
    const count = try decodeHeaders(&[_]u8{ 0x00, 0x00 }, &decoded, &test_scratch);
    try testing.expectEqual(@as(usize, 0), count);
}

test "decodeHeaders: literal with zero-length name and value" {
    // 001_0_0000 → literal name, H=0, name_len=0; then value length=0.
    // Encoded: prefix (00,00) + 0x20 (literal name, len=0) + 0x00 (value len=0).
    var decoded: [4]Header = undefined;
    const input = [_]u8{ 0x00, 0x00, 0x20, 0x00 };
    const count = try decodeHeaders(&input, &decoded, &test_scratch);
    try testing.expectEqual(@as(usize, 1), count);
    try testing.expectEqualStrings("", decoded[0].name);
    try testing.expectEqualStrings("", decoded[0].value);
}

test "DynamicTable: setCapacity(0) evicts everything" {
    var dt = DynamicTable{};
    dt.setCapacity(4096);
    try dt.insert(":authority", "example.com");
    try dt.insert("user-agent", "quic-zig/1.0");
    try testing.expectEqual(@as(usize, 2), dt.count);

    dt.setCapacity(0);
    try testing.expectEqual(@as(usize, 0), dt.count);
    try testing.expectEqual(@as(usize, 0), dt.size);
}

test "DynamicTable: insert entry larger than capacity fails" {
    var dt = DynamicTable{};
    dt.setCapacity(64); // small

    // 50-byte name+value+32 = 82 > 64 → EntryTooLarge
    const big_name = "x" ** 40;
    try testing.expectError(
        error.EntryTooLarge,
        dt.insert(big_name, "value"),
    );
}

test "DynamicTable: capacity is the only size limit" {
    var dt = DynamicTable{};
    dt.setCapacity(DynamicTable.MAX_CAPACITY);

    // Names and values used to be capped at 128 and 512 bytes by their inline
    // buffers, so a long-but-legal header could not be indexed at all.
    const long_name = "x" ** 200;
    const long_value = "v" ** 600;
    try dt.insert(long_name, long_value);
    const e = dt.get(0).?;
    try testing.expectEqualStrings(long_name, e.name);
    try testing.expectEqualStrings(long_value, e.value);

    // What does not fit in the capacity is still rejected.
    try testing.expectError(error.EntryTooLarge, dt.insert("n", "v" ** (DynamicTable.MAX_CAPACITY)));
}

test "DynamicTable: arena is reused as entries are evicted" {
    var dt = DynamicTable{};
    dt.setCapacity(DynamicTable.MAX_CAPACITY);

    // Churn far more content than the arena holds, forcing repeated eviction
    // and compaction, and check the survivors stay intact throughout.
    var buf: [64]u8 = undefined;
    var i: usize = 0;
    while (i < 500) : (i += 1) {
        const name = try std.fmt.bufPrint(&buf, "header-{d}", .{i});
        var vbuf: [200]u8 = undefined;
        const value = try std.fmt.bufPrint(&vbuf, "value-{d}-{s}", .{ i, "p" ** 100 });
        try dt.insert(name, value);

        // The newest entry must always read back exactly.
        const newest = dt.get(dt.insert_count - 1).?;
        try testing.expectEqualStrings(name, newest.name);
        try testing.expectEqualStrings(value, newest.value);
        try testing.expect(dt.size <= dt.capacity);
        try testing.expect(dt.used <= DynamicTable.MAX_CAPACITY);
    }

    // Every entry still counted must decode to something well-formed.
    const oldest = dt.insert_count - dt.count;
    var k = oldest;
    while (k < dt.insert_count) : (k += 1) {
        const e = dt.get(k).?;
        try testing.expect(std.mem.startsWith(u8, e.name, "header-"));
        try testing.expect(std.mem.startsWith(u8, e.value, "value-"));
    }
}

test "DynamicTable: capacity beyond the arena is clamped, not trusted" {
    var dt = DynamicTable{};
    dt.setCapacity(1 << 30);
    try testing.expectEqual(DynamicTable.MAX_CAPACITY, dt.capacity);

    // Filling a clamped table must not run past the descriptor ring.
    var i: usize = 0;
    while (i < DynamicTable.MAX_CAPACITY / 32 + 50) : (i += 1) {
        dt.insert("n", "v") catch break;
        try testing.expect(dt.count <= DynamicTable.MAX_CAPACITY / 32);
    }
}

test "an encoder-stream Duplicate copies an entry out of the arena it writes to" {
    // RFC 9204 4.3.4: Duplicate names an entry the table already holds, so
    // insert() is handed a slice of the arena it is about to write into. Here
    // the duplicate does not fit alongside the original, so inserting it
    // evicts the original first — and the arena offset resets to where the
    // bytes being read from live. Source and destination are then the same
    // address, which is an aliasing @memcpy and, once compaction is in play,
    // one entry's bytes filed under another's name.
    var dec = QpackDecoder{};
    dec.setCapacity(4096);

    // Set Dynamic Table Capacity (001XXXXX, 5-bit prefix) to 41 — exactly one
    // "name"/"value" entry, 9 bytes of content plus the RFC's 32 of overhead.
    try dec.processEncoderInstruction(&[_]u8{ 0x20 | 31, 10 });
    try testing.expectEqual(@as(usize, 41), dec.dynamic.capacity);

    // Insert With Literal Name: 01H0NNNN, 5-bit name length, then a string.
    try dec.processEncoderInstruction(&[_]u8{
        0x40 | 4, 'n', 'a', 'm', 'e',
        5,        'v', 'a', 'l', 'u', 'e',
    });
    try testing.expectEqual(@as(usize, 1), dec.dynamic.count);

    // Duplicate the entry, repeatedly — each one evicts the one it copies.
    for (0..4) |i| {
        const idx: u8 = @intCast(i);
        try dec.processEncoderInstruction(&[_]u8{idx});

        const newest = dec.dynamic.get(dec.dynamic.insert_count - 1) orelse
            return error.TestUnexpectedResult;
        try testing.expectEqualStrings("name", newest.name);
        try testing.expectEqualStrings("value", newest.value);
    }
    try testing.expectEqual(@as(u64, 5), dec.dynamic.insert_count);
}

test "QpackEncoder: header blocks past 4 KiB round-trip" {
    var encoder = QpackEncoder{};
    encoder.setCapacity(4096);
    var decoder = QpackDecoder{};
    decoder.setCapacity(4096);

    var headers: [100]Header = undefined;
    headers[0] = .{ .name = ":status", .value = "200" };
    headers[1] = .{ .name = "cookie", .value = "a" ** 6000 };
    headers[2] = .{ .name = "set-cookie", .value = "b" ** 3000 };
    for (headers[3..]) |*h| h.* = .{ .name = "x-filler", .value = "some value" };

    const buf = try testing.allocator.alloc(u8, maxEncodedLen(&headers));
    defer testing.allocator.free(buf);
    const len = try encoder.encode(&headers, buf);
    try testing.expect(len > 9000);

    try decoder.processEncoderInstruction(encoder.getInstructions());
    var decoded: [128]Header = undefined;
    const count = try decoder.decode(buf[0..len], &decoded, &test_scratch, 0);
    try testing.expectEqual(headers.len, count);
    for (headers, decoded[0..count]) |want, got| {
        try testing.expectEqualStrings(want.name, got.name);
        try testing.expectEqualStrings(want.value, got.value);
    }
}

test "QpackEncoder: an entry is inserted only along with its instruction" {
    // Three ~1.5 KB insertions overflow the 4 KB instruction buffer. An entry
    // the peer never hears of makes any later reference to it undecodable.
    var encoder = QpackEncoder{};
    encoder.setCapacity(4096);
    var decoder = QpackDecoder{};
    decoder.setCapacity(4096);
    try decoder.processEncoderInstruction(encoder.getInstructions());

    const headers = [_]Header{
        .{ .name = "x-a", .value = "a" ** 1500 },
        .{ .name = "x-b", .value = "b" ** 1500 },
        .{ .name = "x-c", .value = "c" ** 1500 },
    };
    var buf: [8192]u8 = undefined;
    _ = try encoder.encode(&headers, &buf);

    try decoder.processEncoderInstruction(encoder.getInstructions());
    try testing.expectEqual(encoder.dynamic.insert_count, decoder.dynamic.insert_count);
}

// Encoder instructions for a decoder whose peer has set a 4096-byte table.
const set_capacity_4096 = [_]u8{ 0x3f, 0xe1, 0x1f };

test "QpackDecoder: a literal name length near usize max is rejected, not wrapped" {
    // 001NHNNN with a name length of maxInt(usize): pos + len would wrap.
    const block = [_]u8{ 0x00, 0x00, 0x27, 0xf8, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01 };
    var decoder = QpackDecoder{};
    var out: [8]Header = undefined;
    try testing.expectError(error.BufferTooShort, decoder.decode(&block, &out, &test_scratch, 0));
    try testing.expectError(error.BufferTooShort, decodeHeaders(&block, &out, &test_scratch));
}

test "QpackDecoder: an encoder-stream literal name length near usize max is rejected" {
    // 01HXXXXX Insert With Literal Name, same wrapping length.
    const instr = [_]u8{ 0x5f, 0xe0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01 };
    var decoder = QpackDecoder{};
    decoder.setCapacity(4096);
    try decoder.processEncoderInstruction(&set_capacity_4096);
    try testing.expectError(error.BufferTooShort, decoder.processEncoderInstruction(&instr));
}

test "QpackDecoder: a negative Delta Base reaching below zero is rejected" {
    var decoder = QpackDecoder{};
    decoder.setCapacity(4096);
    try decoder.processEncoderInstruction(&set_capacity_4096);
    try decoder.processEncoderInstruction(&[_]u8{ 0x41, 'n', 0x01, 'v' });
    var out: [8]Header = undefined;
    // RIC 1 (encoded 2), sign set, Delta Base 1: Base = 1 - 1 - 1.
    try testing.expectError(error.InvalidBase, decoder.decode(&[_]u8{ 0x02, 0x81, 0xd1 }, &out, &test_scratch, 0));
    // Delta Base 0 is the smallest legal negative one: Base = 0.
    const n = try decoder.decode(&[_]u8{ 0x02, 0x80, 0x10 }, &out, &test_scratch, 0);
    try testing.expectEqual(@as(usize, 1), n);
    try testing.expectEqualStrings("n", out[0].name);
    try testing.expectEqualStrings("v", out[0].value);
}

test "QpackDecoder: a Delta Base or post-base index that overflows is rejected" {
    var decoder = QpackDecoder{};
    decoder.setCapacity(4096);
    try decoder.processEncoderInstruction(&set_capacity_4096);
    try decoder.processEncoderInstruction(&[_]u8{ 0x41, 'n', 0x01, 'v' });
    var out: [8]Header = undefined;

    // RIC 1, positive Delta Base of maxInt(u64).
    const big_base = [_]u8{ 0x02, 0x7f, 0x80, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01, 0xc0 | 17 };
    try testing.expectError(error.InvalidBase, decoder.decode(&big_base, &out, &test_scratch, 0));

    // RIC 1, Base 1, post-base index of maxInt(u64): Base + index wraps to 0.
    const big_post = [_]u8{ 0x02, 0x00, 0x1f, 0xf0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01 };
    try testing.expectError(error.InvalidIndex, decoder.decode(&big_post, &out, &test_scratch, 0));
}

test "QpackDecoder: a reference at or past Required Insert Count is rejected" {
    var decoder = QpackDecoder{};
    decoder.setCapacity(4096);
    try decoder.processEncoderInstruction(&set_capacity_4096);
    try decoder.processEncoderInstruction(&[_]u8{ 0x41, 'a', 0x01, '1' });
    try decoder.processEncoderInstruction(&[_]u8{ 0x41, 'b', 0x01, '2' });
    var out: [8]Header = undefined;
    // RIC 1, Base 1, post-base index 0 = absolute 1: in the table, but not
    // covered by the block's Required Insert Count.
    try testing.expectError(error.InvalidIndex, decoder.decode(&[_]u8{ 0x02, 0x00, 0x10 }, &out, &test_scratch, 0));
}

test "QpackDecoder: a prefix without its Delta Base byte is rejected" {
    var decoder = QpackDecoder{};
    var out: [8]Header = undefined;
    // A two-byte Required Insert Count uses up the block.
    try testing.expectError(error.BufferTooShort, decoder.decode(&[_]u8{ 0xff, 0x01 }, &out, &test_scratch, 0));
}
