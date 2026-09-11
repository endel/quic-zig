// moq-lite versions — draft-lcurley-moq-lite-05.
//
// From lite-03 onward the version *is* the ALPN string: there is no
// version code on the wire and no negotiation inside SETUP. Over
// WebTransport the QUIC ALPN stays "h3" and the same token travels in the
// WT-Available-Protocols / WT-Protocol CONNECT headers (§3.1).
//
// The 0xff0dad0X codes below are only reachable through the legacy "moql"
// ALPN, which lite-01 and lite-02 used to negotiate in SETUP. We do not
// implement those versions; the codes are here because peers log them.

const std = @import("std");
const testing = std.testing;

pub const Version = enum(u8) {
    lite_03 = 3,
    lite_04 = 4,
    lite_05 = 5,

    pub fn alpn(self: Version) []const u8 {
        return switch (self) {
            .lite_03 => "moq-lite-03",
            .lite_04 => "moq-lite-04",
            .lite_05 => "moq-lite-05",
        };
    }

    pub fn code(self: Version) u64 {
        return 0xff0d_ad00 | @as(u64, @intFromEnum(self));
    }

    pub fn fromAlpn(token: []const u8) ?Version {
        inline for (comptime std.enums.values(Version)) |v| {
            if (std.mem.eql(u8, token, v.alpn())) return v;
        }
        return null;
    }
};

/// The ALPN lite-01 and lite-02 shared, before the version moved into the
/// ALPN itself. Offered by peers we do not negotiate with.
pub const ALPN_LEGACY: []const u8 = "moql";

/// What we offer. Only lite-05 is implemented — lite-04 has no Setup or
/// Track stream, no ANNOUNCE_OK and a different SUBSCRIBE_OK body — so
/// offering the older ALPNs would negotiate a version we cannot speak.
pub const PREFERRED: []const Version = &.{.lite_05};

/// Every version this module can name, implemented or not.
pub const ALL: []const Version = &.{ .lite_05, .lite_04, .lite_03 };

pub const DEFAULT: Version = .lite_05;

pub fn alpnOffer(versions: []const Version, out: [][]const u8) [][]const u8 {
    const n = @min(versions.len, out.len);
    for (versions[0..n], out[0..n]) |v, *slot| slot.* = v.alpn();
    return out[0..n];
}

test "the alpn string is the version" {
    try testing.expectEqualStrings("moq-lite-05", Version.lite_05.alpn());
    try testing.expectEqual(Version.lite_05, Version.fromAlpn("moq-lite-05").?);
    try testing.expectEqual(Version.lite_03, Version.fromAlpn("moq-lite-03").?);
    // "moql" is shared by lite-01 and lite-02, so it names no version.
    try testing.expectEqual(@as(?Version, null), Version.fromAlpn(ALPN_LEGACY));
    try testing.expectEqual(@as(?Version, null), Version.fromAlpn("moqt-17"));
}

test "legacy codes match the reference implementation" {
    try testing.expectEqual(@as(u64, 0xff0dad03), Version.lite_03.code());
    try testing.expectEqual(@as(u64, 0xff0dad05), Version.lite_05.code());
}

test "the offer names only what is implemented" {
    var buf: [4][]const u8 = undefined;
    const offer = alpnOffer(PREFERRED, &buf);
    try testing.expectEqual(@as(usize, 1), offer.len);
    try testing.expectEqualStrings("moq-lite-05", offer[0]);
}

test "alpn offer is newest first and clamps to the buffer" {
    var buf: [4][]const u8 = undefined;
    const offer = alpnOffer(ALL, &buf);
    try testing.expectEqual(@as(usize, 3), offer.len);
    try testing.expectEqualStrings("moq-lite-05", offer[0]);
    try testing.expectEqualStrings("moq-lite-03", offer[2]);

    var small: [1][]const u8 = undefined;
    try testing.expectEqual(@as(usize, 1), alpnOffer(ALL, &small).len);
}
