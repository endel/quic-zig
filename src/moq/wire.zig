// MoQ Transport draft-17 wire primitives.
//
// MoQ defines its own variable-integer encoding (§1.4.1) that is *not*
// the QUIC varint from RFC 9000. It uses a leading-ones prefix on the
// first byte to indicate total length:
//
//   0xxxxxxx               → 1 byte   (7 value bits)
//   10xxxxxx xxxxxxxx      → 2 bytes  (14 bits)
//   110xxxxx + 2 more      → 3 bytes  (21)
//   1110xxxx + 3 more      → 4 bytes  (28)
//   11110xxx + 4 more      → 5 bytes  (35)
//   111110xx + 5 more      → 6 bytes  (42)
//   1111110x               → INVALID  (7-byte encoding excluded)
//   11111110 + 7 more      → 8 bytes  (56)
//   11111111 + 8 more      → 9 bytes  (64)
//
// Value bits are concatenated big-endian after stripping the prefix.
// This module also provides helpers for length-prefixed byte strings,
// tuples (used by Track Namespace), and the delta-encoded Key-Value-Pair
// list of §1.4.3 used by SETUP options and message parameters.

const std = @import("std");
const io = @import("../io_compat.zig");
const testing = std.testing;

pub const Error = error{
    InvalidVarInt, // 7-byte encoding or malformed prefix
    VarIntTooLarge, // value exceeds 64 bits (cannot happen for u64)
    BufferTooShort,
    DeltaOverflow,
    KeyOrderViolation,
    ValueTooLong,
};

pub fn varIntLength(value: u64) usize {
    if (value <= 0x7F) return 1;
    if (value <= 0x3FFF) return 2;
    if (value <= 0x1F_FFFF) return 3;
    if (value <= 0x0FFF_FFFF) return 4;
    if (value <= 0x07_FFFF_FFFF) return 5;
    if (value <= 0x03_FFFF_FFFF_FF) return 6;
    if (value <= 0xFF_FFFF_FFFF_FFFF) return 8; // 7-byte encoding skipped
    return 9;
}

pub fn writeVarInt(writer: anytype, value: u64) !void {
    switch (varIntLength(value)) {
        1 => try writer.writeByte(@as(u8, @intCast(value))),
        2 => {
            var buf: [2]u8 = .{
                0x80 | @as(u8, @intCast(value >> 8)),
                @as(u8, @intCast(value & 0xFF)),
            };
            try writer.writeAll(&buf);
        },
        3 => {
            var buf: [3]u8 = .{
                0xC0 | @as(u8, @intCast(value >> 16)),
                @as(u8, @intCast((value >> 8) & 0xFF)),
                @as(u8, @intCast(value & 0xFF)),
            };
            try writer.writeAll(&buf);
        },
        4 => {
            var buf: [4]u8 = .{
                0xE0 | @as(u8, @intCast(value >> 24)),
                @as(u8, @intCast((value >> 16) & 0xFF)),
                @as(u8, @intCast((value >> 8) & 0xFF)),
                @as(u8, @intCast(value & 0xFF)),
            };
            try writer.writeAll(&buf);
        },
        5 => {
            var buf: [5]u8 = undefined;
            buf[0] = 0xF0 | @as(u8, @intCast(value >> 32));
            std.mem.writeInt(u32, buf[1..5], @as(u32, @intCast(value & 0xFFFF_FFFF)), .big);
            try writer.writeAll(&buf);
        },
        6 => {
            var buf: [6]u8 = undefined;
            buf[0] = 0xF8 | @as(u8, @intCast(value >> 40));
            buf[1] = @as(u8, @intCast((value >> 32) & 0xFF));
            std.mem.writeInt(u32, buf[2..6], @as(u32, @intCast(value & 0xFFFF_FFFF)), .big);
            try writer.writeAll(&buf);
        },
        8 => {
            var buf: [8]u8 = undefined;
            buf[0] = 0xFE;
            buf[1] = @as(u8, @intCast((value >> 48) & 0xFF));
            buf[2] = @as(u8, @intCast((value >> 40) & 0xFF));
            buf[3] = @as(u8, @intCast((value >> 32) & 0xFF));
            std.mem.writeInt(u32, buf[4..8], @as(u32, @intCast(value & 0xFFFF_FFFF)), .big);
            try writer.writeAll(&buf);
        },
        9 => {
            var buf: [9]u8 = undefined;
            buf[0] = 0xFF;
            std.mem.writeInt(u64, buf[1..9], value, .big);
            try writer.writeAll(&buf);
        },
        else => unreachable,
    }
}

pub fn readVarInt(reader: anytype) !u64 {
    @setEvalBranchQuota(10000);
    const first = reader.takeByte() catch return Error.BufferTooShort;
    const leading: u4 = @intCast(@clz(~first));
    return switch (leading) {
        0 => @as(u64, first),
        1 => blk: {
            const b = reader.takeByte() catch return Error.BufferTooShort;
            break :blk (@as(u64, first & 0x3F) << 8) | @as(u64, b);
        },
        2 => blk: {
            var buf: [2]u8 = undefined;
            reader.readSliceAll(&buf) catch return Error.BufferTooShort;
            break :blk (@as(u64, first & 0x1F) << 16) |
                (@as(u64, buf[0]) << 8) | @as(u64, buf[1]);
        },
        3 => blk: {
            var buf: [3]u8 = undefined;
            reader.readSliceAll(&buf) catch return Error.BufferTooShort;
            break :blk (@as(u64, first & 0x0F) << 24) |
                (@as(u64, buf[0]) << 16) |
                (@as(u64, buf[1]) << 8) | @as(u64, buf[2]);
        },
        4 => blk: {
            var buf: [4]u8 = undefined;
            reader.readSliceAll(&buf) catch return Error.BufferTooShort;
            const lo = std.mem.readInt(u32, &buf, .big);
            break :blk (@as(u64, first & 0x07) << 32) | @as(u64, lo);
        },
        5 => blk: {
            var buf: [5]u8 = undefined;
            reader.readSliceAll(&buf) catch return Error.BufferTooShort;
            const lo = std.mem.readInt(u32, buf[1..5], .big);
            break :blk (@as(u64, first & 0x03) << 40) |
                (@as(u64, buf[0]) << 32) | @as(u64, lo);
        },
        6 => Error.InvalidVarInt, // 0xFC / 0xFD — 7-byte encoding is excluded.
        7 => blk: {
            var buf: [7]u8 = undefined;
            reader.readSliceAll(&buf) catch return Error.BufferTooShort;
            break :blk (@as(u64, buf[0]) << 48) |
                (@as(u64, buf[1]) << 40) |
                (@as(u64, buf[2]) << 32) |
                @as(u64, std.mem.readInt(u32, buf[3..7], .big));
        },
        8 => blk: {
            var buf: [8]u8 = undefined;
            reader.readSliceAll(&buf) catch return Error.BufferTooShort;
            break :blk std.mem.readInt(u64, &buf, .big);
        },
        else => unreachable,
    };
}

// Length-prefixed byte string: varint(len) + bytes.
pub fn writeVarBytes(writer: anytype, bytes: []const u8) !void {
    try writeVarInt(writer, bytes.len);
    try writer.writeAll(bytes);
}

// Reads into caller-provided buffer; returns the slice consumed.
// Errors if declared length exceeds `buf.len`.
pub fn readVarBytesInto(reader: anytype, buf: []u8) ![]u8 {
    const len = try readVarInt(reader);
    if (len > buf.len) return Error.ValueTooLong;
    const dst = buf[0..@as(usize, @intCast(len))];
    reader.readSliceAll(dst) catch return Error.BufferTooShort;
    return dst;
}

// For zero-copy decoding off a FixedBufferStream.
pub fn readVarBytesZc(fbs: *io.FixedBufferStream([]const u8)) ![]const u8 {
    // Compare by subtraction, never `seek + len`: a hostile 64-bit length
    // wraps the addition and passes the check. Same rule as frame.body().
    const len = std.math.cast(usize, try readVarInt(fbs)) orelse return Error.BufferTooShort;
    if (len > fbs.buffer.len - fbs.seek) return Error.BufferTooShort;
    const slice = fbs.buffer[fbs.seek..][0..len];
    fbs.seek += len;
    return slice;
}

// --- Key-Value-Pair list (§1.4.3) ---
//
// Encodes a sequence of (Type, Value) pairs where Type is delta-encoded
// (current = prev + delta_varint, starting from 0). Even Types carry a
// single varint value; odd Types carry a length-prefixed byte slice.
// No count prefix — the list fills the enclosing length.

pub const KvValue = union(enum) {
    varint: u64,
    bytes: []const u8,
};

pub const KvEntry = struct {
    key: u64,
    value: KvValue,
};

pub fn encodeKvList(writer: anytype, entries: []const KvEntry) !void {
    var prev: u64 = 0;
    var first = true;
    for (entries) |e| {
        if (!first and e.key <= prev) return Error.KeyOrderViolation;
        const delta = if (first) e.key else e.key - prev;
        try writeVarInt(writer, delta);
        switch (e.value) {
            .varint => |v| {
                if ((e.key & 1) != 0) return Error.KeyOrderViolation; // odd key must carry bytes
                try writeVarInt(writer, v);
            },
            .bytes => |b| {
                if ((e.key & 1) == 0) return Error.KeyOrderViolation; // even key must carry varint
                if (b.len > std.math.maxInt(u16)) return Error.ValueTooLong;
                try writeVarBytes(writer, b);
            },
        }
        prev = e.key;
        first = false;
    }
}

// Iterator-style decoder for a KV list occupying the full slice.
pub const KvIterator = struct {
    fbs: io.FixedBufferStream([]const u8),
    prev: u64 = 0,
    first: bool = true,

    pub fn init(data: []const u8) KvIterator {
        return .{ .fbs = io.fixedBufferStream(data) };
    }

    pub fn next(self: *KvIterator) !?KvEntry {
        if (self.fbs.seek >= self.fbs.buffer.len) return null;
        const delta = try readVarInt(&self.fbs);
        const key = if (self.first) delta else blk: {
            const sum = std.math.add(u64, self.prev, delta) catch
                return Error.DeltaOverflow;
            break :blk sum;
        };
        self.first = false;
        self.prev = key;

        const value: KvValue = if ((key & 1) == 0)
            .{ .varint = try readVarInt(&self.fbs) }
        else blk: {
            const bytes = try readVarBytesZc(&self.fbs);
            if (bytes.len > std.math.maxInt(u16)) return Error.ValueTooLong;
            break :blk .{ .bytes = bytes };
        };
        return .{ .key = key, .value = value };
    }
};

// Track Namespace tuple: count (varint) followed by N length-prefixed parts.
// Spec caps the tuple at 32 parts.
pub const MAX_TUPLE_PARTS: usize = 32;

pub fn writeTuple(writer: anytype, parts: []const []const u8) !void {
    if (parts.len > MAX_TUPLE_PARTS) return Error.ValueTooLong;
    try writeVarInt(writer, parts.len);
    for (parts) |p| try writeVarBytes(writer, p);
}

// Reads a tuple into a caller-provided buffer, so the returned slice of
// slices outlives the call. The parts themselves point into `fbs.buffer`.
pub fn readTuple(fbs: *io.FixedBufferStream([]const u8), out: [][]const u8) ![][]const u8 {
    const count = try readVarInt(fbs);
    if (count > out.len) return Error.ValueTooLong;
    const n: usize = @intCast(count);
    for (0..n) |i| out[i] = try readVarBytesZc(fbs);
    return out[0..n];
}

pub fn tupleEncodedLen(parts: []const []const u8) usize {
    var n: usize = varIntLength(parts.len);
    for (parts) |p| n += varIntLength(p.len) + p.len;
    return n;
}

// Round-trip tests.
test "varint round-trip at each length boundary" {
    const cases = [_]u64{
        0,
        1,
        127, // max 1-byte
        128, // min 2-byte
        16383, // max 2-byte
        16384, // min 3-byte
        2097151,
        2097152,
        268435455,
        268435456,
        34359738367,
        34359738368,
        4398046511103,
        4398046511104,
        72057594037927935, // max 8-byte
        72057594037927936, // min 9-byte
        std.math.maxInt(u64),
    };
    for (cases) |v| {
        var buf: [16]u8 = undefined;
        var fbs = io.fixedBufferStream(&buf);
        try writeVarInt(&fbs, v);
        const written = fbs.seek;
        try testing.expectEqual(varIntLength(v), written);
        fbs.seek = 0;
        const got = try readVarInt(&fbs);
        try testing.expectEqual(v, got);
    }
}

test "varint rejects 7-byte encoding" {
    // First byte 0xFC or 0xFD means "6 leading 1s, then 0" → length 7, invalid.
    for ([_]u8{ 0xFC, 0xFD }) |first| {
        var buf = [_]u8{ first, 0, 0, 0, 0, 0, 0 };
        var fbs = io.fixedBufferStream(@as([]const u8, &buf));
        try testing.expectError(Error.InvalidVarInt, readVarInt(&fbs));
    }
}

test "varint length table" {
    try testing.expectEqual(@as(usize, 1), varIntLength(0));
    try testing.expectEqual(@as(usize, 1), varIntLength(127));
    try testing.expectEqual(@as(usize, 2), varIntLength(128));
    try testing.expectEqual(@as(usize, 3), varIntLength(16384));
    try testing.expectEqual(@as(usize, 4), varIntLength(2097152));
    try testing.expectEqual(@as(usize, 5), varIntLength(268435456));
    try testing.expectEqual(@as(usize, 6), varIntLength(34359738368));
    try testing.expectEqual(@as(usize, 8), varIntLength(4398046511104));
    try testing.expectEqual(@as(usize, 9), varIntLength(72057594037927936));
    try testing.expectEqual(@as(usize, 9), varIntLength(std.math.maxInt(u64)));
}

test "varbytes round-trip" {
    var buf: [64]u8 = undefined;
    var fbs = io.fixedBufferStream(&buf);
    try writeVarBytes(&fbs, "hello");
    try writeVarBytes(&fbs, "");
    try writeVarBytes(&fbs, "world!");
    const written = fbs.seek;

    var rb = io.fixedBufferStream(@as([]const u8, buf[0..written]));
    const a = try readVarBytesZc(&rb);
    const b = try readVarBytesZc(&rb);
    const c = try readVarBytesZc(&rb);
    try testing.expectEqualStrings("hello", a);
    try testing.expectEqualStrings("", b);
    try testing.expectEqualStrings("world!", c);
}

test "tuple round-trip" {
    var buf: [64]u8 = undefined;
    var fbs = io.fixedBufferStream(&buf);
    const parts = [_][]const u8{ "moq", "demo", "camera" };
    try writeTuple(&fbs, &parts);
    const written = fbs.seek;

    var rb = io.fixedBufferStream(@as([]const u8, buf[0..written]));
    const count = try readVarInt(&rb);
    try testing.expectEqual(@as(u64, 3), count);
    const p0 = try readVarBytesZc(&rb);
    const p1 = try readVarBytesZc(&rb);
    const p2 = try readVarBytesZc(&rb);
    try testing.expectEqualStrings("moq", p0);
    try testing.expectEqualStrings("demo", p1);
    try testing.expectEqualStrings("camera", p2);
}

test "kv list round-trip with delta encoding" {
    var buf: [128]u8 = undefined;
    var fbs = io.fixedBufferStream(&buf);
    const entries = [_]KvEntry{
        .{ .key = 2, .value = .{ .varint = 0x1234 } },
        .{ .key = 3, .value = .{ .bytes = "path" } },
        .{ .key = 7, .value = .{ .bytes = "impl-x" } },
    };
    try encodeKvList(&fbs, &entries);
    const written = fbs.seek;

    // First delta must be 2, then 1, then 4 — verify on the wire.
    try testing.expectEqual(@as(u8, 0x02), buf[0]);

    var it = KvIterator.init(buf[0..written]);
    var count: usize = 0;
    while (try it.next()) |e| : (count += 1) {
        try testing.expectEqual(entries[count].key, e.key);
        switch (entries[count].value) {
            .varint => |v| try testing.expectEqual(v, e.value.varint),
            .bytes => |b| try testing.expectEqualStrings(b, e.value.bytes),
        }
    }
    try testing.expectEqual(@as(usize, 3), count);
}

test "kv encoder rejects descending keys" {
    var buf: [32]u8 = undefined;
    var fbs = io.fixedBufferStream(&buf);
    const entries = [_]KvEntry{
        .{ .key = 4, .value = .{ .varint = 1 } },
        .{ .key = 3, .value = .{ .bytes = "x" } },
    };
    try testing.expectError(Error.KeyOrderViolation, encodeKvList(&fbs, &entries));
}
