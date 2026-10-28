//! JA4 client fingerprints (FoxIO, https://github.com/FoxIO-LLC/ja4): what
//! a ClientHello says about the TLS stack that sent it, whatever the client
//! claims elsewhere. The text form is `a_b_c`, 36 characters:
//!
//! - `a`: `t` for TCP or `q` for QUIC; the highest version offered (`13`);
//!   `d` with SNI, `i` without; the cipher suite and extension counts, two
//!   digits each, at most 99; the first and last character of the first
//!   ALPN protocol, `00` without one.
//! - `b`: the first 12 hex digits of SHA-256 over the cipher suites, sorted,
//!   as comma-separated four-digit hex.
//! - `c`: the same over the extensions, sorted, without SNI and ALPN, then
//!   `_` and the signature algorithms in the order offered.
//!
//! GREASE values (RFC 8701) count nowhere. A list past 128 entries is hashed
//! by its first 128, so a padded ClientHello still has a fingerprint; no
//! real client sends that many.
const std = @import("std");
const common = @import("common.zig");

const Sha256 = std.crypto.hash.sha2.Sha256;
const Parser = common.Parser;
const ext = common.ext;

pub const Transport = enum { tcp, quic };

pub const Ja4 = struct {
    a: [10]u8,
    /// The hashes, truncated to 6 bytes: 12 hex digits.
    b: [6]u8,
    c: [6]u8,

    pub const text_len = 36;

    pub fn text(self: *const Ja4) [text_len]u8 {
        var out: [text_len]u8 = undefined;
        out[0..10].* = self.a;
        out[10] = '_';
        out[11..23].* = std.fmt.bytesToHex(self.b, .lower);
        out[23] = '_';
        out[24..36].* = std.fmt.bytesToHex(self.c, .lower);
        return out;
    }

    /// The text form back; null when `s` isn't one.
    pub fn parse(s: []const u8) ?Ja4 {
        if (s.len != text_len or s[10] != '_' or s[23] != '_') return null;
        var fp: Ja4 = .{ .a = s[0..10].*, .b = undefined, .c = undefined };
        for (fp.a) |ch| if (!std.ascii.isAlphanumeric(ch)) return null;
        _ = std.fmt.hexToBytes(&fp.b, s[11..23]) catch return null;
        _ = std.fmt.hexToBytes(&fp.c, s[24..36]) catch return null;
        return fp;
    }

    pub fn format(self: Ja4, w: *std.Io.Writer) std.Io.Writer.Error!void {
        try w.writeAll(&self.text());
    }
};

/// Asked with each connection's fingerprint once its ClientHello is in,
/// before any key exchange: false fails the handshake.
pub const Filter = struct {
    ctx: ?*anyopaque = null,
    func: *const fn (ctx: ?*anyopaque, fp: *const Ja4) bool,
};

/// The fingerprint of a ClientHello's `body` (the message after its 4-byte
/// header); null when it doesn't parse.
pub fn compute(body: []const u8, transport: Transport) ?Ja4 {
    return fingerprint(body, transport) catch null;
}

const max_list = 128;

const List = struct {
    items: [max_list]u16 = undefined,
    len: usize = 0,
    /// Every value added, kept or not.
    seen: usize = 0,

    fn add(l: *List, v: u16) void {
        l.seen += 1;
        if (l.len == max_list) return;
        l.items[l.len] = v;
        l.len += 1;
    }
};

fn fingerprint(body: []const u8, transport: Transport) common.Error!Ja4 {
    var p: Parser = .{ .buf = body };
    var version = try p.int(u16);
    _ = try p.take(32); // random
    _ = try p.vec(u8); // legacy_session_id
    var suites: Parser = .{ .buf = try p.vec(u16) };
    _ = try p.vec(u8); // legacy_compression_methods
    // A pre-1.3 ClientHello may end here.
    var exts: Parser = .{ .buf = if (p.rest() == 0) "" else try p.vec(u16) };
    if (p.rest() != 0) return error.DecodeError;

    var ciphers: List = .{};
    while (suites.rest() > 0) {
        const cs = try suites.int(u16);
        if (!isGrease(cs)) ciphers.add(cs);
    }

    var hashed: List = .{};
    var n_ext: usize = 0;
    var sni = false;
    var alpn: [2]u8 = "00".*;
    var sig_algs: List = .{};
    while (exts.rest() > 0) {
        const kind = try exts.int(u16);
        var data: Parser = .{ .buf = try exts.vec(u16) };
        if (isGrease(kind)) continue;
        n_ext += 1;
        if (kind != ext.server_name and kind != ext.alpn) hashed.add(kind);
        switch (kind) {
            ext.server_name => sni = true,
            ext.alpn => {
                var list: Parser = .{ .buf = try data.vec(u16) };
                if (list.rest() > 0) alpn = alpnChars(try list.vec(u8));
            },
            ext.signature_algorithms => {
                var list: Parser = .{ .buf = try data.vec(u16) };
                while (list.rest() > 0) {
                    const alg = try list.int(u16);
                    if (!isGrease(alg)) sig_algs.add(alg);
                }
            },
            ext.supported_versions => {
                var list: Parser = .{ .buf = try data.vec(u8) };
                var highest: u16 = 0;
                while (list.rest() > 0) {
                    const v = try list.int(u16);
                    if (!isGrease(v)) highest = @max(highest, v);
                }
                if (highest != 0) version = highest;
            },
            else => {},
        }
    }

    var fp: Ja4 = .{ .a = undefined, .b = @splat(0), .c = @splat(0) };
    fp.a[0] = switch (transport) {
        .tcp => 't',
        .quic => 'q',
    };
    fp.a[1..3].* = versionText(version);
    fp.a[3] = if (sni) 'd' else 'i';
    fp.a[4..6].* = twoDigits(ciphers.seen);
    fp.a[6..8].* = twoDigits(n_ext);
    fp.a[8..10].* = alpn;

    if (ciphers.len > 0) {
        var h: Sha256 = .init(.{});
        hashSorted(&h, &ciphers);
        const d = h.finalResult();
        fp.b = d[0..6].*;
    }
    if (hashed.len > 0) {
        var h: Sha256 = .init(.{});
        hashSorted(&h, &hashed);
        if (sig_algs.len > 0) {
            h.update("_");
            hashList(&h, sig_algs.items[0..sig_algs.len]);
        }
        const d = h.finalResult();
        fp.c = d[0..6].*;
    }
    return fp;
}

fn isGrease(v: u16) bool {
    return v & 0x0f0f == 0x0a0a and v >> 8 == v & 0xff;
}

fn hashSorted(h: *Sha256, l: *List) void {
    const items = l.items[0..l.len];
    std.mem.sort(u16, items, {}, std.sort.asc(u16));
    hashList(h, items);
}

fn hashList(h: *Sha256, items: []const u16) void {
    for (items, 0..) |v, i| {
        if (i > 0) h.update(",");
        var be: [2]u8 = undefined;
        std.mem.writeInt(u16, &be, v, .big);
        h.update(&std.fmt.bytesToHex(be, .lower));
    }
}

fn versionText(v: u16) [2]u8 {
    return switch (v) {
        0x0304 => "13".*,
        0x0303 => "12".*,
        0x0302 => "11".*,
        0x0301 => "10".*,
        0x0300 => "s3".*,
        0x0002 => "s2".*,
        else => "00".*,
    };
}

fn twoDigits(n: usize) [2]u8 {
    const v: u8 = @intCast(@min(n, 99));
    return .{ '0' + v / 10, '0' + v % 10 };
}

/// The first and last character of `proto`; when either isn't
/// alphanumeric, the first hex digit of the first byte and the last of
/// the last.
fn alpnChars(proto: []const u8) [2]u8 {
    if (proto.len == 0) return "00".*;
    const first = proto[0];
    const last = proto[proto.len - 1];
    if (std.ascii.isAlphanumeric(first) and std.ascii.isAlphanumeric(last)) return .{ first, last };
    const hex = "0123456789abcdef";
    return .{ hex[first >> 4], hex[last & 0x0f] };
}

const testing = std.testing;

/// A ClientHello body with `ciphers`, then `exts` as (type, data) pairs.
fn testHello(buf: []u8, ciphers: []const u16, exts: []const struct { u16, []const u8 }) []const u8 {
    var w: std.Io.Writer = .fixed(buf);
    w.writeInt(u16, 0x0303, .big) catch unreachable;
    w.splatByteAll(0x11, 32) catch unreachable;
    w.writeByte(0) catch unreachable;
    w.writeInt(u16, @intCast(ciphers.len * 2), .big) catch unreachable;
    for (ciphers) |c| w.writeInt(u16, c, .big) catch unreachable;
    w.writeAll(&.{ 1, 0 }) catch unreachable;
    var len: usize = 0;
    for (exts) |e| len += 4 + e[1].len;
    w.writeInt(u16, @intCast(len), .big) catch unreachable;
    for (exts) |e| {
        w.writeInt(u16, e[0], .big) catch unreachable;
        w.writeInt(u16, @intCast(e[1].len), .big) catch unreachable;
        w.writeAll(e[1]) catch unreachable;
    }
    return w.buffered();
}

test "the README's example: t13d1516h2_8daaf6152771_e5627efa2ab1" {
    // Its lists, shuffled and with GREASE added: neither may change a thing.
    const ciphers = [_]u16{ 0x1a1a, 0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035 };
    const sig_algs = [_]u8{ 0, 16, 0x04, 0x03, 0x08, 0x04, 0x04, 0x01, 0x05, 0x03, 0x08, 0x05, 0x05, 0x01, 0x08, 0x06, 0x06, 0x01 };
    const versions = [_]u8{ 6, 0x7a, 0x7a, 0x03, 0x04, 0x03, 0x03 };
    const alpn = [_]u8{ 0, 12, 2, 'h', '2', 8, 'h', 't', 't', 'p', '/', '1', '.', '1' };
    var buf: [512]u8 = undefined;
    const body = testHello(&buf, &ciphers, &.{
        .{ 0x2a2a, "" },                     .{ 0x0000, "\x00\x0e\x00\x00\x0bexample.com" },
        .{ 0x0017, "" },                     .{ 0xff01, "\x00" },
        .{ 0x000a, "\x00\x02\x00\x1d" },     .{ 0x000b, "\x01\x00" },
        .{ 0x0023, "" },                     .{ 0x0010, &alpn },
        .{ 0x0005, "\x01\x00\x00\x00\x00" }, .{ 0x000d, &sig_algs },
        .{ 0x0012, "" },                     .{ 0x0033, "\x00\x00" },
        .{ 0x002d, "\x01\x01" },             .{ 0x002b, &versions },
        .{ 0x001b, "\x02\x00\x02" },         .{ 0x4469, "" },
        .{ 0x0015, "\x00" },
    });
    const fp = compute(body, .tcp).?;
    try testing.expectEqualStrings("t13d1516h2_8daaf6152771_e5627efa2ab1", &fp.text());
    try testing.expectEqual(fp, Ja4.parse(&fp.text()).?);
    var out: [64]u8 = undefined;
    try testing.expectEqualStrings("t13d1516h2_8daaf6152771_e5627efa2ab1", try std.fmt.bufPrint(&out, "{f}", .{fp}));
}

test "no SNI, no ALPN, no extensions at all, QUIC" {
    var buf: [256]u8 = undefined;
    // TLS 1.2 by legacy_version alone; zeros for the hashes of empty lists.
    const bare = compute(testHello(&buf, &.{0x002f}, &.{}), .quic).?;
    try testing.expectEqualStrings("q12i010000_ba72b8082249_000000000000", &bare.text());
    // A ClientHello may also stop before its extensions.
    var short = buf;
    const n = 2 + 32 + 1 + 2 + 2 + 2;
    try testing.expectEqual(bare, compute(short[0..n], .quic).?);
}

test "ALPN characters" {
    try testing.expectEqualStrings("h2", &alpnChars("h2"));
    try testing.expectEqualStrings("h1", &alpnChars("http/1.1"));
    try testing.expectEqualStrings("hh", &alpnChars("h"));
    try testing.expectEqualStrings("ab", &alpnChars("\xab"));
    try testing.expectEqualStrings("ad", &alpnChars("\xab\xcd"));
    try testing.expectEqualStrings("6f", &alpnChars("h2\xff"));
}

test "counts stop at 99; lists past 128 are hashed by their first 128" {
    var ciphers: [150]u16 = undefined;
    for (&ciphers, 0..) |*c, i| c.* = @intCast(0x0100 + i);
    var buf: [1024]u8 = undefined;
    const many = compute(testHello(&buf, &ciphers, &.{}), .tcp).?;
    try testing.expectEqualStrings("t12i990000", &many.a);
    var buf2: [1024]u8 = undefined;
    const fewer = compute(testHello(&buf2, ciphers[0..128], &.{}), .tcp).?;
    try testing.expectEqual(many.b, fewer.b);
}

test "malformed ClientHellos have no fingerprint" {
    var buf: [256]u8 = undefined;
    const body = testHello(&buf, &.{0x1301}, &.{.{ 0x0010, "\x00\x03\x02h2" }});
    for (0..body.len) |n| {
        if (n == 2 + 32 + 1 + 2 + 2 + 2) continue; // stopping before the extensions is fine
        try testing.expect(compute(body[0..n], .tcp) == null);
    }
    try testing.expect(compute(body, .tcp) != null);
    for ([_][]const u8{ "", "t13d1516h2_8daaf6152771_e5627efa2ab", "t13d1516h2-8daaf6152771_e5627efa2ab1", "t13d1516h2_8daaf615277g_e5627efa2ab1", "t13d1516h!_8daaf6152771_e5627efa2ab1" }) |bad| {
        try testing.expect(Ja4.parse(bad) == null);
    }
}
