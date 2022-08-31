pub const Version = enum(u32) {
    NEGOTIATION = 0, // TODO: refactor me!
    VERSION_1 = 0x00000001,
    VERSION_2 = 0x709a50c4,
    DRAFT_29 = 0xFF00001D,
    DRAFT_30 = 0xFF00001E,
    DRAFT_31 = 0xFF00001F,
    DRAFT_32 = 0xFF000020,
};

pub const ConnectionProtocol = struct {};

pub fn isSupportedVersion(version: Version) bool {
    return version == Version.VERSION_1 or version == Version.VERSION_2;
}
