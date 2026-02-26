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
