pub const SUPPORTED_VERSIONS = [_]u32{ 0x00000001, 0x709a50c4 };

pub fn isSupportedVersion(version: u32) bool {
    return (version == SUPPORTED_VERSIONS[0] or
        version == SUPPORTED_VERSIONS[1]);
}
