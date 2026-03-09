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
