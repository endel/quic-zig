// WebTransport application-protocol negotiation
// (draft-ietf-webtrans-http3-13 §3.3).
//
// The client lists what it speaks on the extended CONNECT request:
//
//     WT-Available-Protocols: "moqt-18", "moqt-17"
//
// and the server names its choice on the response:
//
//     WT-Protocol: "moqt-17"
//
// Both are RFC 8941 Structured Fields whose only valid item type is String,
// so values are double-quoted. We parse the subset that reaches the wire in
// practice — quoted strings, comma-separated, optional whitespace — and
// reject anything else rather than guessing, since a misread protocol name
// silently selects the wrong wire format.

const std = @import("std");
const testing = std.testing;

pub const HEADER_AVAILABLE: []const u8 = "wt-available-protocols";
pub const HEADER_SELECTED: []const u8 = "wt-protocol";

pub const Error = error{
    MalformedStructuredField,
    BufferTooShort,
    TooManyProtocols,
};

// RFC 8941 §3.3.3: a String holds printable ASCII, with `\` and `"` escaped.
fn isValidStringChar(c: u8) bool {
    return c >= 0x20 and c <= 0x7e;
}

fn needsEscape(c: u8) bool {
    return c == '"' or c == '\\';
}

// Renders `protocols` as a Structured Field List of Strings into `buf`.
pub fn encodeList(protocols: []const []const u8, buf: []u8) ![]const u8 {
    var n: usize = 0;
    for (protocols, 0..) |p, i| {
        if (i > 0) {
            if (n + 2 > buf.len) return Error.BufferTooShort;
            buf[n] = ',';
            buf[n + 1] = ' ';
            n += 2;
        }
        if (n + 1 > buf.len) return Error.BufferTooShort;
        buf[n] = '"';
        n += 1;
        for (p) |c| {
            if (!isValidStringChar(c)) return Error.MalformedStructuredField;
            if (needsEscape(c)) {
                if (n + 1 > buf.len) return Error.BufferTooShort;
                buf[n] = '\\';
                n += 1;
            }
            if (n + 1 > buf.len) return Error.BufferTooShort;
            buf[n] = c;
            n += 1;
        }
        if (n + 1 > buf.len) return Error.BufferTooShort;
        buf[n] = '"';
        n += 1;
    }
    return buf[0..n];
}

// Renders a single protocol as a Structured Field Item.
pub fn encodeItem(protocol: []const u8, buf: []u8) ![]const u8 {
    const one = [_][]const u8{protocol};
    return encodeList(&one, buf);
}

// Parses a List of Strings. Unescaped values are written into `scratch`;
// `out` receives slices into it, so both must outlive the result.
pub fn decodeList(value: []const u8, out: [][]const u8, scratch: []u8) ![][]const u8 {
    var count: usize = 0;
    var used: usize = 0;
    var i: usize = 0;

    while (i < value.len) {
        while (i < value.len and (value[i] == ' ' or value[i] == '\t')) i += 1;
        if (i >= value.len) break;
        if (value[i] != '"') return Error.MalformedStructuredField;
        i += 1;

        const start = used;
        while (true) {
            if (i >= value.len) return Error.MalformedStructuredField; // unterminated
            const c = value[i];
            if (c == '"') {
                i += 1;
                break;
            }
            if (c == '\\') {
                i += 1;
                if (i >= value.len) return Error.MalformedStructuredField;
                if (!needsEscape(value[i])) return Error.MalformedStructuredField;
            } else if (!isValidStringChar(c)) {
                return Error.MalformedStructuredField;
            }
            if (used >= scratch.len) return Error.BufferTooShort;
            scratch[used] = value[i];
            used += 1;
            i += 1;
        }

        if (count >= out.len) return Error.TooManyProtocols;
        out[count] = scratch[start..used];
        count += 1;

        while (i < value.len and (value[i] == ' ' or value[i] == '\t')) i += 1;
        if (i >= value.len) break;
        if (value[i] != ',') return Error.MalformedStructuredField;
        i += 1;
    }

    return out[0..count];
}

// Parses a single Item. Rejects a list of more than one, which would be
// ambiguous rather than merely sloppy.
pub fn decodeItem(value: []const u8, scratch: []u8) ![]const u8 {
    var out: [2][]const u8 = undefined;
    const parsed = try decodeList(value, &out, scratch);
    if (parsed.len != 1) return Error.MalformedStructuredField;
    return parsed[0];
}

// Picks the first entry of `supported` that the client also offered, so the
// server's preference order wins. Returns null when there is no overlap —
// the caller decides whether that is fatal.
pub fn selectFromOffer(offer_value: []const u8, supported: []const []const u8, scratch: []u8) ?[]const u8 {
    var offered: [16][]const u8 = undefined;
    const list = decodeList(offer_value, &offered, scratch) catch return null;
    for (supported) |s| {
        for (list) |o| {
            if (std.mem.eql(u8, s, o)) return s;
        }
    }
    return null;
}

// Case-insensitive lookup of a header value. HTTP/3 header names are
// lowercase on the wire, but peers and test harnesses are not always.
pub fn findHeader(headers: []const Header, name: []const u8) ?[]const u8 {
    for (headers) |h| {
        if (h.name.len != name.len) continue;
        if (std.ascii.eqlIgnoreCase(h.name, name)) return h.value;
    }
    return null;
}

pub const Header = @import("../h3/qpack.zig").Header;

test "encode and decode a protocol list" {
    var buf: [128]u8 = undefined;
    const protocols = [_][]const u8{ "moqt-18", "moqt-17" };
    const encoded = try encodeList(&protocols, &buf);
    try testing.expectEqualStrings("\"moqt-18\", \"moqt-17\"", encoded);

    var out: [4][]const u8 = undefined;
    var scratch: [64]u8 = undefined;
    const decoded = try decodeList(encoded, &out, &scratch);
    try testing.expectEqual(@as(usize, 2), decoded.len);
    try testing.expectEqualStrings("moqt-18", decoded[0]);
    try testing.expectEqualStrings("moqt-17", decoded[1]);
}

test "encode and decode a single item" {
    var buf: [64]u8 = undefined;
    try testing.expectEqualStrings("\"moqt-17\"", try encodeItem("moqt-17", &buf));

    var scratch: [64]u8 = undefined;
    try testing.expectEqualStrings("moqt-17", try decodeItem("\"moqt-17\"", &scratch));
    try testing.expectError(Error.MalformedStructuredField, decodeItem("\"a\", \"b\"", &scratch));
    try testing.expectError(Error.MalformedStructuredField, decodeItem("moqt-17", &scratch));
}

test "decode tolerates whitespace and rejects malformed input" {
    var out: [4][]const u8 = undefined;
    var scratch: [64]u8 = undefined;

    const loose = try decodeList("  \"a\" ,\t\"b\"  ", &out, &scratch);
    try testing.expectEqual(@as(usize, 2), loose.len);
    try testing.expectEqualStrings("b", loose[1]);

    try testing.expectError(Error.MalformedStructuredField, decodeList("\"unterminated", &out, &scratch));
    try testing.expectError(Error.MalformedStructuredField, decodeList("\"a\" \"b\"", &out, &scratch));
    try testing.expectError(Error.MalformedStructuredField, decodeList("bare", &out, &scratch));
    try testing.expectEqual(@as(usize, 0), (try decodeList("", &out, &scratch)).len);
}

test "escapes survive a round-trip" {
    var buf: [64]u8 = undefined;
    const protocols = [_][]const u8{"a\"b\\c"};
    const encoded = try encodeList(&protocols, &buf);
    try testing.expectEqualStrings("\"a\\\"b\\\\c\"", encoded);

    var out: [2][]const u8 = undefined;
    var scratch: [64]u8 = undefined;
    const decoded = try decodeList(encoded, &out, &scratch);
    try testing.expectEqualStrings("a\"b\\c", decoded[0]);
}

test "selection follows the server's preference, not the client's" {
    var scratch: [64]u8 = undefined;
    const supported = [_][]const u8{ "moqt-17", "moqt-18" };
    // Client prefers 18, server prefers 17: the server wins.
    try testing.expectEqualStrings(
        "moqt-17",
        selectFromOffer("\"moqt-18\", \"moqt-17\"", &supported, &scratch).?,
    );
    try testing.expectEqual(
        @as(?[]const u8, null),
        selectFromOffer("\"h3\"", &supported, &scratch),
    );
    try testing.expectEqual(
        @as(?[]const u8, null),
        selectFromOffer("garbage", &supported, &scratch),
    );
}

test "header lookup ignores case" {
    const headers = [_]Header{
        .{ .name = ":method", .value = "CONNECT" },
        .{ .name = "WT-Available-Protocols", .value = "\"moqt-17\"" },
    };
    try testing.expectEqualStrings("\"moqt-17\"", findHeader(&headers, HEADER_AVAILABLE).?);
    try testing.expectEqual(@as(?[]const u8, null), findHeader(&headers, HEADER_SELECTED));
}
