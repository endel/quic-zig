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
        value += @as(usize, b & 0x7f) << shift;
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
fn decodeString(data: []const u8, pos: *usize) ![]const u8 {
    if (pos.* >= data.len) return error.BufferTooShort;
    const is_huffman = (data[pos.*] & 0x80) != 0;

    const len = try decodeInteger(data, pos, 7);
    if (pos.* + len > data.len) return error.BufferTooShort;

    const raw = data[pos.*..][0..len];
    pos.* += len;

    if (is_huffman) {
        // Decode Huffman-encoded string into thread-local buffer
        const decoded_len = huffman.decode(raw, &huffman_decode_buf) catch return error.InvalidEncoding;
        return huffman_decode_buf[0..decoded_len];
    }

    return raw;
}

// Thread-local buffer for Huffman decoded strings.
// Huffman decoding expands data, so we need a generous buffer.
var huffman_decode_buf: [8192]u8 = undefined;

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
            // Literal with literal name: 0010HNNN
            // H=0 (no Huffman), 3-bit name length prefix
            buf[pos] = 0x20;
            pos += 1;
            // Name length + name
            encodeString(buf, &pos, h.name);
            // Value length + value
            encodeString(buf, &pos, h.value);
        }
    }

    return pos;
}

/// Decode a QPACK header block into headers.
/// Returns the number of headers decoded.
pub fn decodeHeaders(data: []const u8, headers_buf: []Header) !usize {
    if (data.len < 2) return error.BufferTooShort;

    var pos: usize = 0;

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
        } else if (first & 0xf0 == 0x50) {
            // Literal with name reference (static): 0101NNNN
            const index = try decodeInteger(data, &pos, 4);
            if (index >= static_table.len) return error.InvalidIndex;
            const value = try decodeString(data, &pos);
            headers_buf[count] = .{
                .name = static_table[index].name,
                .value = value,
            };
            count += 1;
        } else if (first & 0xf0 == 0x40) {
            // Literal with name reference (static, never-indexed): 0100NNNN
            const index = try decodeInteger(data, &pos, 4);
            if (index >= static_table.len) return error.InvalidIndex;
            const value = try decodeString(data, &pos);
            headers_buf[count] = .{
                .name = static_table[index].name,
                .value = value,
            };
            count += 1;
        } else if (first & 0xe0 == 0x20) {
            // Literal with literal name: 001NNNNN
            pos += 1; // skip first byte (pattern byte)
            const name = try decodeString(data, &pos);
            const value = try decodeString(data, &pos);
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
            _ = try decodeString(data, &pos);
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
