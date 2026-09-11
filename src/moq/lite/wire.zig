// moq-lite wire primitives — draft-lcurley-moq-lite-05.
//
// Unlike IETF moq-transport, moq-lite uses the **QUIC varint** (RFC 9000
// §16), so this reuses src/quic/packet.zig rather than src/moq/wire.zig.
// Mixing the two silently produces frames that look almost valid, so the
// two modules deliberately do not share a namespace.
//
// Primitive encodings (§4):
//   (i)  varint         — QUIC varint
//   (8)  uint8/bool     — one raw byte, NOT a varint
//   (s)  string / path  — varint length + UTF-8 bytes
//   (b)  bytes          — varint length + bytes
//   zigzag (i)          — signed, (n << 1) ^ (n >> 63)
//   optional group      — 0 means "default", otherwise sequence + 1

const std = @import("std");
const testing = std.testing;

const io = @import("../../io_compat.zig");
const quic_varint = @import("../../quic/packet.zig");

pub const readVarInt = quic_varint.readVarInt;
pub const writeVarInt = quic_varint.writeVarInt;
pub const varIntLength = quic_varint.varIntLength;

pub const Error = error{
    BufferTooShort,
    ValueTooLong,
    TooManyParts,
    InvalidUtf8,
};

/// §4: the largest value a QUIC varint can carry.
pub const MAX_VARINT: u64 = (1 << 62) - 1;

/// §7.1: a control message may not exceed 64 MiB.
pub const MAX_MESSAGE_SIZE: usize = 64 * 1024 * 1024;

// --- zigzag ---------------------------------------------------------------

pub fn zigzagEncode(v: i64) u64 {
    return @bitCast((v << 1) ^ (v >> 63));
}

pub fn zigzagDecode(v: u64) i64 {
    const shifted: i64 = @bitCast(v >> 1);
    const sign: i64 = -@as(i64, @intCast(v & 1));
    return shifted ^ sign;
}

pub fn writeZigzag(writer: anytype, v: i64) !void {
    return writeVarInt(writer, zigzagEncode(v));
}

pub fn readZigzag(reader: anytype) !i64 {
    return zigzagDecode(try readVarInt(reader));
}

// --- strings and bytes ----------------------------------------------------

pub fn writeBytes(writer: anytype, bytes: []const u8) !void {
    try writeVarInt(writer, bytes.len);
    try writer.writeAll(bytes);
}

/// Zero-copy read: the result aliases `fbs.buffer`.
pub fn readBytesZc(fbs: *io.FixedBufferStream([]const u8)) ![]const u8 {
    // Compare by subtraction: a hostile 64-bit length wraps `seek + len`.
    const len = std.math.cast(usize, try readVarInt(fbs)) orelse return Error.BufferTooShort;
    if (len > fbs.buffer.len - fbs.seek) return Error.BufferTooShort;
    const slice = fbs.buffer[fbs.seek..][0..len];
    fbs.seek += len;
    return slice;
}

pub const writeString = writeBytes;

/// Like readBytesZc, but rejects anything that is not valid UTF-8 — paths
/// and track names are strings in moq-lite, not opaque byte arrays.
pub fn readStringZc(fbs: *io.FixedBufferStream([]const u8)) ![]const u8 {
    const s = try readBytesZc(fbs);
    if (!std.unicode.utf8ValidateSlice(s)) return Error.InvalidUtf8;
    return s;
}

// --- optional group sequences ---------------------------------------------

/// §7.7: 0 means "default" (latest / unbounded), otherwise sequence + 1.
pub fn writeOptionalGroup(writer: anytype, group: ?u64) !void {
    const raw = if (group) |g| (std.math.add(u64, g, 1) catch return Error.ValueTooLong) else 0;
    return writeVarInt(writer, raw);
}

pub fn readOptionalGroup(reader: anytype) !?u64 {
    const raw = try readVarInt(reader);
    return if (raw == 0) null else raw - 1;
}

// --- paths ----------------------------------------------------------------
//
// A broadcast path is a '/'-separated relative path. Leading and trailing
// slashes are trimmed and runs collapse, so "/a//b/" and "a/b" are the same
// path. Prefix matching respects separators: "foo" does not prefix "foobar".

pub const MAX_PATH_PARTS: usize = 32;

/// Normalises in place into `out`, returning the normalised slice.
pub fn normalizePath(path: []const u8, out: []u8) ![]const u8 {
    var n: usize = 0;
    var parts: usize = 0;
    var it = std.mem.splitScalar(u8, path, '/');
    while (it.next()) |part| {
        if (part.len == 0) continue;
        parts += 1;
        if (parts > MAX_PATH_PARTS) return Error.TooManyParts;
        if (n > 0) {
            if (n + 1 > out.len) return Error.ValueTooLong;
            out[n] = '/';
            n += 1;
        }
        if (n + part.len > out.len) return Error.ValueTooLong;
        @memcpy(out[n..][0..part.len], part);
        n += part.len;
    }
    return out[0..n];
}

/// True when `path` is `prefix`, or lies beneath it. Both are assumed
/// normalised; an empty prefix matches everything.
pub fn hasPathPrefix(path: []const u8, prefix: []const u8) bool {
    if (prefix.len == 0) return true;
    if (!std.mem.startsWith(u8, path, prefix)) return false;
    return path.len == prefix.len or path[prefix.len] == '/';
}

/// The part of `path` below `prefix`, or null when it is not beneath it.
pub fn stripPathPrefix(path: []const u8, prefix: []const u8) ?[]const u8 {
    if (!hasPathPrefix(path, prefix)) return null;
    if (prefix.len == 0) return path;
    if (path.len == prefix.len) return path[path.len..];
    return path[prefix.len + 1 ..];
}

/// Joins `prefix` and `suffix` into `out`, collapsing the separator when
/// either side is empty.
pub fn joinPath(prefix: []const u8, suffix: []const u8, out: []u8) ![]const u8 {
    if (prefix.len == 0) {
        if (suffix.len > out.len) return Error.ValueTooLong;
        @memcpy(out[0..suffix.len], suffix);
        return out[0..suffix.len];
    }
    if (suffix.len == 0) {
        if (prefix.len > out.len) return Error.ValueTooLong;
        @memcpy(out[0..prefix.len], prefix);
        return out[0..prefix.len];
    }
    const total = prefix.len + 1 + suffix.len;
    if (total > out.len) return Error.ValueTooLong;
    @memcpy(out[0..prefix.len], prefix);
    out[prefix.len] = '/';
    @memcpy(out[prefix.len + 1 ..][0..suffix.len], suffix);
    return out[0..total];
}

// --- tests ----------------------------------------------------------------

test "moq-lite uses the QUIC varint, not the draft-17 one" {
    // 0x40 0x25 is 37 in QUIC's two-byte form; the leading-ones varint in
    // src/moq/wire.zig would read the same bytes as 0x0025.
    var buf = [_]u8{ 0x40, 0x25 };
    var fbs = io.fixedBufferStream(@as([]const u8, &buf));
    try testing.expectEqual(@as(u64, 37), try readVarInt(&fbs));
}

test "zigzag round-trips both signs" {
    const cases = [_]i64{ 0, -1, 1, -2, 2, 63, -64, 1_000_000, -1_000_000, std.math.maxInt(i32), std.math.minInt(i32) };
    for (cases) |v| {
        try testing.expectEqual(v, zigzagDecode(zigzagEncode(v)));
    }
    // The mapping the draft spells out: 0→0, -1→1, 1→2, -2→3, 2→4.
    try testing.expectEqual(@as(u64, 0), zigzagEncode(0));
    try testing.expectEqual(@as(u64, 1), zigzagEncode(-1));
    try testing.expectEqual(@as(u64, 2), zigzagEncode(1));
    try testing.expectEqual(@as(u64, 3), zigzagEncode(-2));
    try testing.expectEqual(@as(u64, 4), zigzagEncode(2));
}

test "zigzag small magnitudes fit in one byte" {
    var buf: [8]u8 = undefined;
    for ([_]i64{ -32, -1, 0, 1, 31 }) |v| {
        var fbs = io.fixedBufferStream(&buf);
        try writeZigzag(&fbs, v);
        try testing.expectEqual(@as(usize, 1), fbs.seek);
    }
}

test "strings round-trip and reject invalid utf-8" {
    var buf: [64]u8 = undefined;
    var fbs = io.fixedBufferStream(&buf);
    try writeString(&fbs, "hello/world");
    var rfbs = io.fixedBufferStream(@as([]const u8, buf[0..fbs.seek]));
    try testing.expectEqualStrings("hello/world", try readStringZc(&rfbs));

    const bad = [_]u8{ 0x02, 0xff, 0xfe };
    var bfbs = io.fixedBufferStream(@as([]const u8, &bad));
    try testing.expectError(Error.InvalidUtf8, readStringZc(&bfbs));
}

test "a length past the buffer does not wrap" {
    // varint 0x3f = 63 bytes claimed, one byte present.
    const bytes = [_]u8{ 0x3f, 0xaa };
    var fbs = io.fixedBufferStream(@as([]const u8, &bytes));
    try testing.expectError(Error.BufferTooShort, readBytesZc(&fbs));
}

test "optional group uses 0 for default" {
    var buf: [8]u8 = undefined;

    var fbs = io.fixedBufferStream(&buf);
    try writeOptionalGroup(&fbs, null);
    try testing.expectEqualSlices(u8, &.{0x00}, buf[0..fbs.seek]);

    fbs = io.fixedBufferStream(&buf);
    try writeOptionalGroup(&fbs, 0);
    try testing.expectEqualSlices(u8, &.{0x01}, buf[0..fbs.seek]);

    for ([_]?u64{ null, 0, 1, 41 }) |g| {
        var w = io.fixedBufferStream(&buf);
        try writeOptionalGroup(&w, g);
        var r = io.fixedBufferStream(@as([]const u8, buf[0..w.seek]));
        try testing.expectEqual(g, try readOptionalGroup(&r));
    }
}

test "paths normalise to a canonical form" {
    var buf: [64]u8 = undefined;
    try testing.expectEqualStrings("a/b", try normalizePath("/a/b/", &buf));
    try testing.expectEqualStrings("a/b", try normalizePath("a//b", &buf));
    try testing.expectEqualStrings("a/b", try normalizePath("///a///b///", &buf));
    try testing.expectEqualStrings("", try normalizePath("/", &buf));
    try testing.expectEqualStrings("a", try normalizePath("a", &buf));
}

test "normalizePath enforces the 32-part cap" {
    var buf: [512]u8 = undefined;
    var long: [200]u8 = undefined;
    var n: usize = 0;
    for (0..33) |i| {
        long[n] = if (i == 0) 'x' else '/';
        n += 1;
        if (i > 0) {
            long[n] = 'x';
            n += 1;
        }
    }
    try testing.expectError(Error.TooManyParts, normalizePath(long[0..n], &buf));
}

test "prefix matching respects separators" {
    try testing.expect(hasPathPrefix("foo/bar", "foo"));
    try testing.expect(hasPathPrefix("foo", "foo"));
    try testing.expect(hasPathPrefix("anything", ""));
    // The whole point: a prefix is a path, not a substring.
    try testing.expect(!hasPathPrefix("foobar", "foo"));
    try testing.expect(!hasPathPrefix("fo", "foo"));
}

test "stripping a prefix leaves the suffix" {
    try testing.expectEqualStrings("bar", stripPathPrefix("foo/bar", "foo").?);
    try testing.expectEqualStrings("bar/baz", stripPathPrefix("foo/bar/baz", "foo").?);
    try testing.expectEqualStrings("", stripPathPrefix("foo", "foo").?);
    try testing.expectEqualStrings("foo/bar", stripPathPrefix("foo/bar", "").?);
    try testing.expectEqual(@as(?[]const u8, null), stripPathPrefix("foobar", "foo"));
}

test "joining is the inverse of stripping" {
    var buf: [64]u8 = undefined;
    try testing.expectEqualStrings("foo/bar", try joinPath("foo", "bar", &buf));
    try testing.expectEqualStrings("bar", try joinPath("", "bar", &buf));
    try testing.expectEqualStrings("foo", try joinPath("foo", "", &buf));

    const full = "room/alice/video";
    const suffix = stripPathPrefix(full, "room").?;
    try testing.expectEqualStrings(full, try joinPath("room", suffix, &buf));
}
