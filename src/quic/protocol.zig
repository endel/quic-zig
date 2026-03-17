pub const QUIC_V1: u32 = 0x00000001;
pub const QUIC_V2: u32 = 0x6b3343cf; // RFC 9369

pub const SUPPORTED_VERSIONS = [_]u32{ QUIC_V1, QUIC_V2 };

pub fn isSupportedVersion(version: u32) bool {
    for (SUPPORTED_VERSIONS) |v| {
        if (version == v) return true;
    }
    return false;
}

/// Returns true if the version uses QUIC v2 cryptographic constants.
pub fn isV2(version: u32) bool {
    return version == QUIC_V2;
}

/// Return the appropriate HKDF label for a given version.
/// v1: "quic key", "quic iv", "quic hp", "quic ku"
/// v2: "quicv2 key", "quicv2 iv", "quicv2 hp", "quicv2 ku"
pub fn quicLabel(version: u32, comptime base: enum { key, iv, hp, ku }) []const u8 {
    return if (isV2(version)) switch (base) {
        .key => "quicv2 key",
        .iv => "quicv2 iv",
        .hp => "quicv2 hp",
        .ku => "quicv2 ku",
    } else switch (base) {
        .key => "quic key",
        .iv => "quic iv",
        .hp => "quic hp",
        .ku => "quic ku",
    };
}

const testing = @import("std").testing;

test "isSupportedVersion" {
    try testing.expect(isSupportedVersion(QUIC_V1));
    try testing.expect(isSupportedVersion(QUIC_V2));
    try testing.expect(!isSupportedVersion(0xdeadbeef));
    try testing.expect(!isSupportedVersion(0));
}

test "isV2" {
    try testing.expect(!isV2(QUIC_V1));
    try testing.expect(isV2(QUIC_V2));
}

test "quicLabel: v1 vs v2" {
    try testing.expectEqualStrings("quic key", quicLabel(QUIC_V1, .key));
    try testing.expectEqualStrings("quicv2 key", quicLabel(QUIC_V2, .key));
    try testing.expectEqualStrings("quic iv", quicLabel(QUIC_V1, .iv));
    try testing.expectEqualStrings("quicv2 hp", quicLabel(QUIC_V2, .hp));
    try testing.expectEqualStrings("quic ku", quicLabel(QUIC_V1, .ku));
}
