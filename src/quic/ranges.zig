const std = @import("std");
const Allocator = std.mem.Allocator;
const testing = std.testing;

/// A range [start, end] (inclusive on both ends) of packet numbers.
pub const Range = struct {
    start: u64,
    end: u64,

    pub fn contains(self: Range, val: u64) bool {
        return val >= self.start and val <= self.end;
    }

    pub fn size(self: Range) u64 {
        return self.end - self.start + 1;
    }
};

/// A set of non-overlapping, non-adjacent ranges stored in descending order
/// (largest first). This is the core data structure for tracking received
/// packet numbers, ACK ranges, and byte ranges.
///
/// Following quic-go's approach of maintaining ranges in descending order
/// for efficient ACK frame generation.
pub const RangeSet = struct {
    allocator: Allocator,
    ranges: std.ArrayList(Range),

    pub fn init(allocator: Allocator) RangeSet {
        return .{
            .allocator = allocator,
            .ranges = .{ .items = &.{}, .capacity = 0 },
        };
    }

    pub fn deinit(self: *RangeSet) void {
        self.ranges.deinit(self.allocator);
    }

    /// Returns the number of ranges.
    pub fn len(self: *const RangeSet) usize {
        return self.ranges.items.len;
    }

    /// Returns the largest value in the set, or null if empty.
    pub fn largest(self: *const RangeSet) ?u64 {
        if (self.ranges.items.len == 0) return null;
        return self.ranges.items[0].end;
    }

    /// Returns the smallest value in the set, or null if empty.
    pub fn smallest(self: *const RangeSet) ?u64 {
        if (self.ranges.items.len == 0) return null;
        return self.ranges.items[self.ranges.items.len - 1].start;
    }

    /// Check if a value is contained in any range.
    pub fn contains(self: *const RangeSet, val: u64) bool {
        for (self.ranges.items) |r| {
            if (val > r.end) return false; // ranges are descending, no point continuing
            if (r.contains(val)) return true;
        }
        return false;
    }

    /// Add a single value to the range set. Merges adjacent/overlapping ranges.
    pub fn add(self: *RangeSet, val: u64) !void {
        try self.addRange(val, val);
    }

    /// Add a range [start, end] to the set. Merges with existing ranges as needed.
    pub fn addRange(self: *RangeSet, start: u64, end: u64) !void {
        if (start > end) return;

        const items = self.ranges.items;

        if (items.len == 0) {
            try self.ranges.append(self.allocator, .{ .start = start, .end = end });
            return;
        }

        // Find insertion point (ranges are in descending order by start)
        var insert_idx: usize = items.len;
        for (items, 0..) |r, i| {
            if (end >= r.start) {
                insert_idx = i;
                break;
            }
        }

        // Check if we can extend an existing range or need to insert new
        var merge_start = insert_idx;
        var merge_end = insert_idx; // exclusive
        var new_start = start;
        var new_end = end;

        // Look for ranges to merge with
        for (items[insert_idx..], insert_idx..) |r, i| {
            if (new_start > r.end + 1) break; // gap too large, no more merges
            merge_end = i + 1;
            if (r.start < new_start) new_start = r.start;
            if (r.end > new_end) new_end = r.end;
        }

        // Also check the range before insert_idx for adjacency
        if (merge_start > 0) {
            const prev = items[merge_start - 1];
            if (new_end + 1 >= prev.start) {
                merge_start -= 1;
                if (prev.end > new_end) new_end = prev.end;
                if (prev.start < new_start) new_start = prev.start;
            }
        }

        // Replace merged ranges with the new combined range
        if (merge_start < merge_end) {
            items[merge_start] = .{ .start = new_start, .end = new_end };
            // Remove extra merged ranges
            if (merge_end - merge_start > 1) {
                const remove_count = merge_end - merge_start - 1;
                std.mem.copyForwards(
                    Range,
                    items[merge_start + 1 ..],
                    items[merge_start + 1 + remove_count ..],
                );
                self.ranges.shrinkRetainingCapacity(items.len - remove_count);
            }
        } else {
            // Insert new range at the right position
            try self.ranges.insert(self.allocator, insert_idx, .{ .start = new_start, .end = new_end });
        }
    }

    /// Remove all values below (exclusive) the given value.
    pub fn removeBelow(self: *RangeSet, val: u64) void {
        const items = self.ranges.items;
        if (items.len == 0) return;

        // Ranges are in descending order. Iterate from the end (smallest first)
        // and remove/trim as needed.
        var new_len: usize = items.len;
        var i: usize = items.len;
        while (i > 0) {
            i -= 1;
            if (items[i].end < val) {
                // Entirely below val - remove
                new_len = i;
            } else if (items[i].start < val) {
                // Partially overlapping - trim and stop
                items[i].start = val;
                break;
            } else {
                // Entirely above val - stop
                break;
            }
        }

        if (new_len < items.len) {
            self.ranges.shrinkRetainingCapacity(new_len);
        }
    }

    /// Get ranges as a slice (descending order - largest first).
    pub fn getRanges(self: *const RangeSet) []const Range {
        return self.ranges.items;
    }
};

/// Sliding-window bitmap for O(1) packet number tracking.
/// Replaces RangeSet for received packet number duplicate detection.
///
/// Design (inspired by lxin/quic kernel pnspace.c):
/// - Fixed 4096-bit bitmap (512 bytes, no heap allocation)
/// - O(1) contains() via bit test
/// - O(1) mark() via bit set
/// - getRanges() scans bitmap to produce descending Range array for ACK frames
/// - removeBelow() shifts the window forward
pub const PacketNumberBitmap = struct {
    const BITMAP_BITS: usize = 4096;
    const MaskInt = std.DynamicBitSet.MaskInt;
    const MASK_BITS = @bitSizeOf(MaskInt);
    const NUM_MASKS: usize = BITMAP_BITS / MASK_BITS;

    /// The bitmap, stored inline (512 bytes for 4096 bits).
    masks: [NUM_MASKS]MaskInt = [_]MaskInt{0} ** NUM_MASKS,

    /// Base packet number: bitmap[0] corresponds to this PN.
    base: u64 = 0,

    /// Highest marked packet number (for fast largest() query).
    highest: ?u64 = null,

    /// Number of set bits.
    count: u32 = 0,

    /// Mark a packet number as received. Returns true if newly added (not duplicate).
    pub fn mark(self: *PacketNumberBitmap, pn: u64) bool {
        if (self.highest != null and pn < self.base) return false; // too old

        // If pn is beyond current window, shift the window forward
        if (pn >= self.base + BITMAP_BITS) {
            self.shiftTo(pn);
        }

        const offset = pn - self.base;
        const idx = @as(usize, @intCast(offset / MASK_BITS));
        const bit: std.math.Log2Int(MaskInt) = @intCast(offset % MASK_BITS);

        if (self.masks[idx] & (@as(MaskInt, 1) << bit) != 0) {
            return false; // duplicate
        }

        self.masks[idx] |= @as(MaskInt, 1) << bit;
        self.count += 1;

        if (self.highest == null or pn > self.highest.?) {
            self.highest = pn;
        }
        return true;
    }

    /// O(1) duplicate detection.
    pub fn contains(self: *const PacketNumberBitmap, pn: u64) bool {
        if (self.highest == null) return false;
        if (pn < self.base or pn >= self.base + BITMAP_BITS) return false;

        const offset = pn - self.base;
        const idx = @as(usize, @intCast(offset / MASK_BITS));
        const bit: std.math.Log2Int(MaskInt) = @intCast(offset % MASK_BITS);

        return self.masks[idx] & (@as(MaskInt, 1) << bit) != 0;
    }

    pub fn largest(self: *const PacketNumberBitmap) ?u64 {
        return self.highest;
    }

    /// Remove all entries below `val` by shifting the base forward.
    pub fn removeBelow(self: *PacketNumberBitmap, val: u64) void {
        if (val <= self.base) return;

        const shift_by = val - self.base;
        if (shift_by >= BITMAP_BITS) {
            // Clear everything
            @memset(&self.masks, 0);
            self.base = val;
            self.count = 0;
            // highest stays — it may be above val
            return;
        }

        const word_shift = @as(usize, @intCast(shift_by / MASK_BITS));
        const bit_shift: std.math.Log2Int(MaskInt) = @intCast(shift_by % MASK_BITS);

        // Count bits being removed (for accurate count tracking)
        var removed: u32 = 0;
        if (word_shift > 0) {
            for (self.masks[0..word_shift]) |w| {
                removed += @popCount(w);
            }
        }
        // Count bits in the partial word that are being shifted out
        if (bit_shift > 0 and word_shift < NUM_MASKS) {
            const partial_mask = (@as(MaskInt, 1) << bit_shift) - 1;
            removed += @popCount(self.masks[word_shift] & partial_mask);
        }
        self.count -|= removed;

        // Shift words
        if (word_shift > 0) {
            var i: usize = 0;
            while (i + word_shift < NUM_MASKS) : (i += 1) {
                self.masks[i] = self.masks[i + word_shift];
            }
            // Zero the trailing words
            @memset(self.masks[NUM_MASKS - word_shift ..], 0);
        }

        // Shift bits within words
        if (bit_shift > 0) {
            const anti_shift: std.math.Log2Int(MaskInt) = @intCast(MASK_BITS - @as(usize, bit_shift));
            var i: usize = 0;
            while (i < NUM_MASKS - 1) : (i += 1) {
                self.masks[i] = (self.masks[i] >> bit_shift) | (self.masks[i + 1] << anti_shift);
            }
            self.masks[NUM_MASKS - 1] >>= bit_shift;
        }

        self.base = val;
    }

    /// Produce up to `max_ranges` ranges in descending order for ACK frame generation.
    /// Scans the bitmap from highest to base, finding contiguous runs of 1s.
    pub fn getRanges(self: *const PacketNumberBitmap, out: []Range) usize {
        const hi = self.highest orelse return 0;
        if (hi < self.base) return 0;

        var range_count: usize = 0;
        const max_offset = hi - self.base;

        var pos: u64 = max_offset;
        while (range_count < out.len) {
            // Find next set bit at or below pos (scanning downward)
            const end_off = self.findPrevSet(pos) orelse break;
            // Find the start of this contiguous run
            const start_off = self.findRunStart(end_off);

            out[range_count] = .{
                .start = self.base + start_off,
                .end = self.base + end_off,
            };
            range_count += 1;

            if (start_off == 0) break;
            pos = start_off - 1;
        }

        return range_count;
    }

    /// Find the highest set bit at or below `offset` (scanning downward).
    fn findPrevSet(self: *const PacketNumberBitmap, offset: u64) ?u64 {
        var pos: i64 = @intCast(offset);
        while (pos >= 0) {
            const p: usize = @intCast(pos);
            const idx = p / MASK_BITS;
            const bit_in_word = p % MASK_BITS;

            // Mask off bits above our position
            const mask = self.masks[idx] & ((@as(MaskInt, 2) << @as(std.math.Log2Int(MaskInt), @intCast(bit_in_word))) -% 1);
            if (mask != 0) {
                const highest_bit = MASK_BITS - 1 - @as(usize, @clz(mask));
                return @intCast(idx * MASK_BITS + highest_bit);
            }
            // Move to end of previous word
            if (idx == 0) break;
            pos = @as(i64, @intCast(idx * MASK_BITS)) - 1;
        }
        return null;
    }

    /// Find the lowest offset in a contiguous run of set bits ending at `end_offset`.
    fn findRunStart(self: *const PacketNumberBitmap, end_offset: u64) u64 {
        if (end_offset == 0) {
            return if (self.masks[0] & 1 != 0) 0 else end_offset;
        }

        var pos: u64 = end_offset;
        while (pos > 0) {
            pos -= 1;
            const idx = @as(usize, @intCast(pos / MASK_BITS));
            const bit: std.math.Log2Int(MaskInt) = @intCast(pos % MASK_BITS);
            if (self.masks[idx] & (@as(MaskInt, 1) << bit) == 0) {
                return pos + 1;
            }
        }
        // Bit 0 is also set — run starts at 0
        return 0;
    }

    /// Shift the window so that `pn` fits. Preserves as much history as possible.
    fn shiftTo(self: *PacketNumberBitmap, pn: u64) void {
        // Shift base so pn fits within the window, leaving some room for reordering.
        // Place pn at 3/4 of the window to leave room for future packets.
        const new_base = if (pn >= BITMAP_BITS * 3 / 4) pn - BITMAP_BITS * 3 / 4 else 0;
        if (new_base > self.base) {
            self.removeBelow(new_base);
        }
    }
};

// Tests

test "RangeSet: add single values" {
    var rs = RangeSet.init(testing.allocator);
    defer rs.deinit();

    try rs.add(5);
    try testing.expectEqual(@as(usize, 1), rs.len());
    try testing.expectEqual(@as(u64, 5), rs.largest().?);

    try rs.add(3);
    try testing.expectEqual(@as(usize, 2), rs.len());

    // Add adjacent - should merge
    try rs.add(4);
    try testing.expectEqual(@as(usize, 1), rs.len());
    try testing.expectEqual(@as(u64, 3), rs.smallest().?);
    try testing.expectEqual(@as(u64, 5), rs.largest().?);
}

test "RangeSet: add merges overlapping" {
    var rs = RangeSet.init(testing.allocator);
    defer rs.deinit();

    try rs.addRange(1, 3);
    try rs.addRange(7, 9);
    try testing.expectEqual(@as(usize, 2), rs.len());

    // Bridge the gap
    try rs.addRange(4, 6);
    try testing.expectEqual(@as(usize, 1), rs.len());
    try testing.expectEqual(@as(u64, 1), rs.smallest().?);
    try testing.expectEqual(@as(u64, 9), rs.largest().?);
}

test "RangeSet: contains" {
    var rs = RangeSet.init(testing.allocator);
    defer rs.deinit();

    try rs.addRange(3, 7);
    try rs.addRange(10, 15);

    try testing.expect(rs.contains(3));
    try testing.expect(rs.contains(5));
    try testing.expect(rs.contains(7));
    try testing.expect(!rs.contains(8));
    try testing.expect(!rs.contains(9));
    try testing.expect(rs.contains(10));
    try testing.expect(rs.contains(15));
    try testing.expect(!rs.contains(16));
    try testing.expect(!rs.contains(2));
}

test "RangeSet: removeBelow" {
    var rs = RangeSet.init(testing.allocator);
    defer rs.deinit();

    try rs.addRange(1, 3);
    try rs.addRange(5, 8);
    try rs.addRange(10, 15);

    rs.removeBelow(6);
    // Range [1,3] removed entirely, [5,8] trimmed to [6,8], [10,15] unchanged
    try testing.expectEqual(@as(usize, 2), rs.len());
    try testing.expectEqual(@as(u64, 6), rs.smallest().?);
}

test "RangeSet: ascending inserts (packet number pattern)" {
    var rs = RangeSet.init(testing.allocator);
    defer rs.deinit();

    // Simulate receiving packets 0, 1, 2, 3, 4 in order
    try rs.add(0);
    try rs.add(1);
    try rs.add(2);
    try rs.add(3);
    try rs.add(4);

    try testing.expectEqual(@as(usize, 1), rs.len());
    try testing.expectEqual(@as(u64, 0), rs.smallest().?);
    try testing.expectEqual(@as(u64, 4), rs.largest().?);
}

test "RangeSet: out-of-order with gaps" {
    var rs = RangeSet.init(testing.allocator);
    defer rs.deinit();

    // Simulate out-of-order: 0, 2, 4 (gaps at 1, 3)
    try rs.add(0);
    try rs.add(2);
    try rs.add(4);
    try testing.expectEqual(@as(usize, 3), rs.len());

    // Fill gap at 1
    try rs.add(1);
    try testing.expectEqual(@as(usize, 2), rs.len());

    // Fill gap at 3
    try rs.add(3);
    try testing.expectEqual(@as(usize, 1), rs.len());
}

// PacketNumberBitmap tests

test "PacketNumberBitmap: mark and contains" {
    var bm = PacketNumberBitmap{};

    try testing.expect(bm.mark(0));
    try testing.expect(bm.contains(0));
    try testing.expect(!bm.contains(1));

    // Duplicate returns false
    try testing.expect(!bm.mark(0));

    try testing.expect(bm.mark(5));
    try testing.expect(bm.contains(5));
    try testing.expect(!bm.contains(3));
    try testing.expectEqual(@as(u64, 5), bm.largest().?);
}

test "PacketNumberBitmap: sequential packets" {
    var bm = PacketNumberBitmap{};

    var i: u64 = 0;
    while (i < 100) : (i += 1) {
        try testing.expect(bm.mark(i));
    }
    try testing.expectEqual(@as(u32, 100), bm.count);
    try testing.expectEqual(@as(u64, 99), bm.largest().?);

    // All should be present
    i = 0;
    while (i < 100) : (i += 1) {
        try testing.expect(bm.contains(i));
    }
    try testing.expect(!bm.contains(100));
}

test "PacketNumberBitmap: getRanges descending" {
    var bm = PacketNumberBitmap{};

    // Create ranges: [0,2], gap, [5,7], gap, [10,12]
    _ = bm.mark(0);
    _ = bm.mark(1);
    _ = bm.mark(2);
    _ = bm.mark(5);
    _ = bm.mark(6);
    _ = bm.mark(7);
    _ = bm.mark(10);
    _ = bm.mark(11);
    _ = bm.mark(12);

    var out: [10]Range = undefined;
    const n = bm.getRanges(&out);
    try testing.expectEqual(@as(usize, 3), n);

    // Descending order: highest first
    try testing.expectEqual(@as(u64, 10), out[0].start);
    try testing.expectEqual(@as(u64, 12), out[0].end);
    try testing.expectEqual(@as(u64, 5), out[1].start);
    try testing.expectEqual(@as(u64, 7), out[1].end);
    try testing.expectEqual(@as(u64, 0), out[2].start);
    try testing.expectEqual(@as(u64, 2), out[2].end);
}

test "PacketNumberBitmap: removeBelow" {
    var bm = PacketNumberBitmap{};

    var i: u64 = 0;
    while (i < 20) : (i += 1) {
        _ = bm.mark(i);
    }

    bm.removeBelow(10);
    try testing.expectEqual(@as(u64, 10), bm.base);

    // 0-9 should be gone
    i = 0;
    while (i < 10) : (i += 1) {
        try testing.expect(!bm.contains(i));
    }
    // 10-19 should still be present
    while (i < 20) : (i += 1) {
        try testing.expect(bm.contains(i));
    }
    try testing.expectEqual(@as(u32, 10), bm.count);
}

test "PacketNumberBitmap: out-of-order with gaps" {
    var bm = PacketNumberBitmap{};

    _ = bm.mark(0);
    _ = bm.mark(2);
    _ = bm.mark(4);

    try testing.expect(bm.contains(0));
    try testing.expect(!bm.contains(1));
    try testing.expect(bm.contains(2));
    try testing.expect(!bm.contains(3));
    try testing.expect(bm.contains(4));

    var out: [10]Range = undefined;
    const n = bm.getRanges(&out);
    try testing.expectEqual(@as(usize, 3), n);
    try testing.expectEqual(@as(u64, 4), out[0].start);
    try testing.expectEqual(@as(u64, 4), out[0].end);
    try testing.expectEqual(@as(u64, 2), out[1].start);
    try testing.expectEqual(@as(u64, 2), out[1].end);
    try testing.expectEqual(@as(u64, 0), out[2].start);
    try testing.expectEqual(@as(u64, 0), out[2].end);

    // Fill gaps
    _ = bm.mark(1);
    _ = bm.mark(3);
    const n2 = bm.getRanges(&out);
    try testing.expectEqual(@as(usize, 1), n2);
    try testing.expectEqual(@as(u64, 0), out[0].start);
    try testing.expectEqual(@as(u64, 4), out[0].end);
}

test "PacketNumberBitmap: large packet numbers" {
    var bm = PacketNumberBitmap{};

    // Start at high PN
    _ = bm.mark(1_000_000);
    _ = bm.mark(1_000_001);
    _ = bm.mark(1_000_002);

    try testing.expect(bm.contains(1_000_000));
    try testing.expect(bm.contains(1_000_001));
    try testing.expect(bm.contains(1_000_002));
    try testing.expect(!bm.contains(999_999));
    try testing.expectEqual(@as(u64, 1_000_002), bm.largest().?);
}

test "PacketNumberBitmap: window shift on large jump" {
    var bm = PacketNumberBitmap{};

    // Mark some early packets
    _ = bm.mark(0);
    _ = bm.mark(1);
    _ = bm.mark(2);

    // Jump far ahead — forces window shift
    _ = bm.mark(10000);
    try testing.expect(bm.contains(10000));
    // Early packets should be gone (shifted out)
    try testing.expect(!bm.contains(0));
    try testing.expect(!bm.contains(1));
    try testing.expect(!bm.contains(2));
}

test "PacketNumberBitmap: getRanges limited output" {
    var bm = PacketNumberBitmap{};

    // Create many ranges
    _ = bm.mark(0);
    _ = bm.mark(2);
    _ = bm.mark(4);
    _ = bm.mark(6);
    _ = bm.mark(8);

    // Only ask for 2 ranges (should get the highest 2)
    var out: [2]Range = undefined;
    const n = bm.getRanges(&out);
    try testing.expectEqual(@as(usize, 2), n);
    try testing.expectEqual(@as(u64, 8), out[0].start);
    try testing.expectEqual(@as(u64, 6), out[1].start);
}
