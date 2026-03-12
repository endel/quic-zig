const std = @import("std");
const testing = std.testing;

/// Stream priority parameters per RFC 9218 (Extensible Prioritization Scheme for HTTP).
/// urgency: 0 (highest) to 7 (lowest), default 3
/// incremental: false = sequential delivery, true = interleaved (round-robin)
pub const StreamPriority = struct {
    urgency: u3 = 3,
    incremental: bool = false,
};

/// Parse an RFC 9218 Priority field value.
/// Examples: "u=5, i", "u=0, i=?0", "u=7", "i", "i=?1"
/// Unknown parameters are ignored per the spec.
pub fn parse(value: []const u8) StreamPriority {
    var result = StreamPriority{};

    var rest = value;
    while (rest.len > 0) {
        // Trim leading whitespace and commas
        rest = trimLeading(rest);
        if (rest.len == 0) break;
        if (rest[0] == ',') {
            rest = rest[1..];
            continue;
        }

        // Parse parameter name
        const name_end = findParamEnd(rest);
        const name = rest[0..name_end];
        rest = rest[name_end..];

        // Check for '=' value
        rest = trimLeading(rest);
        if (rest.len > 0 and rest[0] == '=') {
            rest = rest[1..]; // skip '='
            rest = trimLeading(rest);
            const val_end = findValueEnd(rest);
            const val = rest[0..val_end];
            rest = rest[val_end..];

            if (std.mem.eql(u8, name, "u")) {
                // u=N where N is 0-7
                if (val.len == 1 and val[0] >= '0' and val[0] <= '7') {
                    result.urgency = @intCast(val[0] - '0');
                }
            } else if (std.mem.eql(u8, name, "i")) {
                // i=?1 or i=?0 (structured field boolean)
                if (std.mem.eql(u8, val, "?1")) {
                    result.incremental = true;
                } else if (std.mem.eql(u8, val, "?0")) {
                    result.incremental = false;
                }
            }
            // Unknown parameters ignored
        } else {
            // Bare parameter (no value) — boolean true
            if (std.mem.eql(u8, name, "i")) {
                result.incremental = true;
            }
            // Unknown bare parameters ignored
        }
    }

    return result;
}

/// Serialize a StreamPriority to RFC 9218 field value format.
/// Returns the number of bytes written.
pub fn serialize(prio: StreamPriority, buf: []u8) usize {
    var pos: usize = 0;

    // Always write urgency if not default, or if incremental is set (for clarity)
    if (prio.urgency != 3) {
        if (pos + 3 > buf.len) return pos;
        buf[pos] = 'u';
        pos += 1;
        buf[pos] = '=';
        pos += 1;
        buf[pos] = '0' + @as(u8, prio.urgency);
        pos += 1;
    }

    if (prio.incremental) {
        if (pos > 0) {
            if (pos + 2 > buf.len) return pos;
            buf[pos] = ',';
            pos += 1;
            buf[pos] = ' ';
            pos += 1;
        }
        if (pos + 1 > buf.len) return pos;
        buf[pos] = 'i';
        pos += 1;
    }

    return pos;
}

fn trimLeading(s: []const u8) []const u8 {
    var i: usize = 0;
    while (i < s.len and (s[i] == ' ' or s[i] == '\t')) : (i += 1) {}
    return s[i..];
}

fn findParamEnd(s: []const u8) usize {
    var i: usize = 0;
    while (i < s.len and s[i] != '=' and s[i] != ',' and s[i] != ' ' and s[i] != '\t') : (i += 1) {}
    return i;
}

fn findValueEnd(s: []const u8) usize {
    var i: usize = 0;
    while (i < s.len and s[i] != ',' and s[i] != ' ' and s[i] != '\t') : (i += 1) {}
    return i;
}

// Tests

test "priority: default values" {
    const p = parse("");
    try testing.expectEqual(@as(u3, 3), p.urgency);
    try testing.expect(!p.incremental);
}

test "priority: urgency only" {
    const p = parse("u=5");
    try testing.expectEqual(@as(u3, 5), p.urgency);
    try testing.expect(!p.incremental);
}

test "priority: urgency 0" {
    const p = parse("u=0");
    try testing.expectEqual(@as(u3, 0), p.urgency);
}

test "priority: urgency 7" {
    const p = parse("u=7");
    try testing.expectEqual(@as(u3, 7), p.urgency);
}

test "priority: incremental bare" {
    const p = parse("i");
    try testing.expectEqual(@as(u3, 3), p.urgency);
    try testing.expect(p.incremental);
}

test "priority: urgency and incremental" {
    const p = parse("u=5, i");
    try testing.expectEqual(@as(u3, 5), p.urgency);
    try testing.expect(p.incremental);
}

test "priority: incremental with explicit true" {
    const p = parse("u=2, i=?1");
    try testing.expectEqual(@as(u3, 2), p.urgency);
    try testing.expect(p.incremental);
}

test "priority: incremental with explicit false" {
    const p = parse("u=4, i=?0");
    try testing.expectEqual(@as(u3, 4), p.urgency);
    try testing.expect(!p.incremental);
}

test "priority: unknown parameters ignored" {
    const p = parse("u=1, foo=bar, i, baz");
    try testing.expectEqual(@as(u3, 1), p.urgency);
    try testing.expect(p.incremental);
}

test "priority: no spaces" {
    const p = parse("u=3,i");
    try testing.expectEqual(@as(u3, 3), p.urgency);
    try testing.expect(p.incremental);
}

test "priority: extra whitespace" {
    const p = parse("  u=6 ,  i  ");
    try testing.expectEqual(@as(u3, 6), p.urgency);
    try testing.expect(p.incremental);
}

test "priority: serialize default (empty)" {
    var buf: [32]u8 = undefined;
    const len = serialize(.{}, &buf);
    try testing.expectEqual(@as(usize, 0), len);
}

test "priority: serialize urgency only" {
    var buf: [32]u8 = undefined;
    const len = serialize(.{ .urgency = 5 }, &buf);
    try testing.expectEqualStrings("u=5", buf[0..len]);
}

test "priority: serialize incremental only" {
    var buf: [32]u8 = undefined;
    const len = serialize(.{ .incremental = true }, &buf);
    try testing.expectEqualStrings("i", buf[0..len]);
}

test "priority: serialize both" {
    var buf: [32]u8 = undefined;
    const len = serialize(.{ .urgency = 0, .incremental = true }, &buf);
    try testing.expectEqualStrings("u=0, i", buf[0..len]);
}
