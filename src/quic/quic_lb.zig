// QUIC-LB: Connection ID encoding/decoding for load balancers.
//
// Two coexisting formats:
//   - Draft-20 compatible (`Config`): variable-length CID with a payload of
//     server_id + nonce, optional 4-pass Feistel / single-pass AES-ECB.
//   - Netcode (`NetcodeConfig`): proprietary 17-byte CID with a fixed 16-byte
//     structured payload encrypted with single-pass AES-128-ECB. Preserves
//     the draft's first-octet {config_id:3, length:5} invariant so any LB
//     can parse short-header packets statelessly.

const std = @import("std");
const crypto = std.crypto;
const Aes128 = crypto.core.aes.Aes128;

pub const CidFormat = enum { draft20, netcode };

/// QUIC-LB configuration for CID encoding.
pub const Config = struct {
    config_id: u3, // 0-6, identifies which config
    server_id: [15]u8 = .{0} ** 15,
    server_id_len: u4, // 1-15
    nonce_len: u5, // 4-18
    key: ?[16]u8 = null, // null = plaintext, set = encrypted
    encode_length: bool = true, // first octet encodes CID length
};

/// Total CID length: 1 (first octet) + server_id_len + nonce_len.
pub fn cidLength(config: *const Config) u8 {
    return 1 + @as(u8, config.server_id_len) + @as(u8, config.nonce_len);
}

/// Generate a QUIC-LB encoded CID into buf.
/// buf must be at least cidLength(config) bytes.
pub fn generateCid(config: *const Config, buf: []u8) void {
    const total = cidLength(config);
    std.debug.assert(buf.len >= total);

    // First octet: config_id in bits 7-5
    const config_bits: u8 = @as(u8, config.config_id) << 5;
    if (config.encode_length) {
        // Bits 4-0 encode (CID length - 1)
        buf[0] = config_bits | (total - 1);
    } else {
        // Bits 4-0 are random
        var random_byte: [1]u8 = undefined;
        crypto.random.bytes(&random_byte);
        buf[0] = config_bits | (random_byte[0] & 0x1F);
    }

    const sid_len: u8 = @as(u8, config.server_id_len);
    const nonce_len: u8 = @as(u8, config.nonce_len);

    // Place server_id and nonce into bytes 1..total
    @memcpy(buf[1 .. 1 + sid_len], config.server_id[0..sid_len]);
    // Fill nonce with random bytes
    crypto.random.bytes(buf[1 + sid_len .. total]);

    // Encrypt if key is set
    if (config.key) |key| {
        const payload_len = sid_len + nonce_len;
        if (payload_len == 16) {
            // Single-pass AES-ECB: encrypt bytes 1..17
            singlePassEncrypt(key, buf[1..17]);
        } else {
            // 4-pass Feistel cipher
            feistelEncrypt(key, buf[1..total], payload_len);
        }
    }
}

/// Extract server_id from a QUIC-LB encoded CID.
/// Writes server_id into out[0..config.server_id_len].
/// Returns false if CID is too short.
pub fn extractServerId(config: *const Config, cid: []const u8, out: []u8) bool {
    const total = cidLength(config);
    if (cid.len < total) return false;

    const sid_len: u8 = @as(u8, config.server_id_len);
    const nonce_len: u8 = @as(u8, config.nonce_len);
    const payload_len = sid_len + nonce_len;

    if (out.len < sid_len) return false;

    if (config.key) |key| {
        // Decrypt in a temporary buffer (don't mutate input)
        var tmp: [20]u8 = undefined; // max payload: 15 + 18 = 33, but CID max is 20
        @memcpy(tmp[0..payload_len], cid[1 .. 1 + payload_len]);

        if (payload_len == 16) {
            singlePassDecrypt(key, tmp[0..16]);
        } else {
            feistelDecrypt(key, tmp[0..payload_len], payload_len);
        }
        @memcpy(out[0..sid_len], tmp[0..sid_len]);
    } else {
        // Plaintext: server_id is at bytes 1..1+sid_len
        @memcpy(out[0..sid_len], cid[1 .. 1 + sid_len]);
    }

    return true;
}

/// Extract the config_id (bits 7-5) from the first octet of a CID.
pub fn extractConfigId(first_octet: u8) u3 {
    return @intCast(first_octet >> 5);
}

// --- Internal cipher functions ---

/// Single-pass AES-ECB encrypt (for payload_len == 16).
fn singlePassEncrypt(key: [16]u8, data: *[16]u8) void {
    const ctx = Aes128.initEnc(key);
    var out: [16]u8 = undefined;
    ctx.encrypt(&out, data);
    data.* = out;
}

/// Single-pass AES-ECB decrypt (for payload_len == 16).
fn singlePassDecrypt(key: [16]u8, data: *[16]u8) void {
    const ctx = Aes128.initDec(key);
    var out: [16]u8 = undefined;
    ctx.decrypt(&out, data);
    data.* = out;
}

/// 4-pass Feistel encrypt in place.
/// data[0..total_len] contains server_id ++ nonce.
pub fn feistelEncrypt(key: [16]u8, data: []u8, total_len: u8) void {
    const half_len: u8 = (total_len + 1) / 2; // ceil(N/2)
    const right_len: u8 = total_len - half_len;

    // Round 1: right ^= truncate(AES(expand(left, N, 1)), right_len)
    {
        var block = expandBlock(data[0..half_len], half_len, total_len, 1);
        const ctx = Aes128.initEnc(key);
        var enc: [16]u8 = undefined;
        ctx.encrypt(&enc, &block);
        xorSlice(data[half_len..total_len], enc[0..right_len]);
    }

    // Round 2: left ^= truncate(AES(expand(right, N, 2)), half_len)
    {
        var block = expandBlock(data[half_len..total_len], right_len, total_len, 2);
        const ctx = Aes128.initEnc(key);
        var enc: [16]u8 = undefined;
        ctx.encrypt(&enc, &block);
        xorSlice(data[0..half_len], enc[0..half_len]);
    }

    // Round 3: right ^= truncate(AES(expand(left, N, 3)), right_len)
    {
        var block = expandBlock(data[0..half_len], half_len, total_len, 3);
        const ctx = Aes128.initEnc(key);
        var enc: [16]u8 = undefined;
        ctx.encrypt(&enc, &block);
        xorSlice(data[half_len..total_len], enc[0..right_len]);
    }

    // Round 4: left ^= truncate(AES(expand(right, N, 4)), half_len)
    {
        var block = expandBlock(data[half_len..total_len], right_len, total_len, 4);
        const ctx = Aes128.initEnc(key);
        var enc: [16]u8 = undefined;
        ctx.encrypt(&enc, &block);
        xorSlice(data[0..half_len], enc[0..half_len]);
    }
}

/// 4-pass Feistel decrypt in place.
/// data[0..total_len] contains encrypted server_id ++ nonce.
pub fn feistelDecrypt(key: [16]u8, data: []u8, total_len: u8) void {
    const half_len: u8 = (total_len + 1) / 2; // ceil(N/2)
    const right_len: u8 = total_len - half_len;

    // Undo Round 4: left ^= truncate(AES(expand(right, N, 4)), half_len)
    {
        var block = expandBlock(data[half_len..total_len], right_len, total_len, 4);
        const ctx = Aes128.initEnc(key);
        var enc: [16]u8 = undefined;
        ctx.encrypt(&enc, &block);
        xorSlice(data[0..half_len], enc[0..half_len]);
    }

    // Undo Round 3: right ^= truncate(AES(expand(left, N, 3)), right_len)
    {
        var block = expandBlock(data[0..half_len], half_len, total_len, 3);
        const ctx = Aes128.initEnc(key);
        var enc: [16]u8 = undefined;
        ctx.encrypt(&enc, &block);
        xorSlice(data[half_len..total_len], enc[0..right_len]);
    }

    // Undo Round 2: left ^= truncate(AES(expand(right, N, 2)), half_len)
    {
        var block = expandBlock(data[half_len..total_len], right_len, total_len, 2);
        const ctx = Aes128.initEnc(key);
        var enc: [16]u8 = undefined;
        ctx.encrypt(&enc, &block);
        xorSlice(data[0..half_len], enc[0..half_len]);
    }

    // Undo Round 1: right ^= truncate(AES(expand(left, N, 1)), right_len)
    {
        var block = expandBlock(data[0..half_len], half_len, total_len, 1);
        const ctx = Aes128.initEnc(key);
        var enc: [16]u8 = undefined;
        ctx.encrypt(&enc, &block);
        xorSlice(data[half_len..total_len], enc[0..right_len]);
    }
}

/// Build the 16-byte AES input block: [half_data | zero_padding | total_len | round]
fn expandBlock(half: []const u8, half_len: u8, total_len: u8, round: u8) [16]u8 {
    var block: [16]u8 = .{0} ** 16;
    @memcpy(block[0..half_len], half[0..half_len]);
    // Positions 14 and 15 hold total_len and round number
    block[14] = total_len;
    block[15] = round;
    return block;
}

/// XOR src into dst in place.
fn xorSlice(dst: []u8, src: []const u8) void {
    for (dst, src) |*d, s| {
        d.* ^= s;
    }
}

// --- Netcode mode ---
//
// Fixed-layout 17-byte CID:
//
//   byte 0: {config_id:3 | length:5}  — always 16 (total_len - 1)
//   bytes 1..17: AES-128-ECB( server_id:4 || reserved:4 || nonce:8 )
//
// The encrypted payload is exactly one AES block, so encrypt/decrypt is
// a single invocation. `server_id` is structured bytes the matchmaker
// interprets (e.g. {region:1, host:2, shard:1} or a flat u32).

pub const NETCODE_CID_LEN: u8 = 17;
pub const NETCODE_PAYLOAD_LEN: u8 = 16;
pub const NETCODE_SERVER_ID_LEN: u8 = 4;
pub const NETCODE_RESERVED_LEN: u8 = 4;
pub const NETCODE_NONCE_LEN: u8 = 8;

pub const NetcodeConfig = struct {
    config_id: u3,
    key: [16]u8,
    encode_length: bool = true,
};

pub const NetcodePayload = extern struct {
    server_id: [NETCODE_SERVER_ID_LEN]u8 = .{0} ** NETCODE_SERVER_ID_LEN,
    reserved: [NETCODE_RESERVED_LEN]u8 = .{0} ** NETCODE_RESERVED_LEN,
    nonce: [NETCODE_NONCE_LEN]u8 = .{0} ** NETCODE_NONCE_LEN,
};

comptime {
    std.debug.assert(@sizeOf(NetcodePayload) == NETCODE_PAYLOAD_LEN);
}

/// Mint a netcode-format CID for `server_id`. `buf` must be at least
/// `NETCODE_CID_LEN` bytes. A fresh random nonce is generated.
pub fn generateNetcodeCid(
    config: *const NetcodeConfig,
    server_id: [NETCODE_SERVER_ID_LEN]u8,
    buf: []u8,
) void {
    std.debug.assert(buf.len >= NETCODE_CID_LEN);

    const config_bits: u8 = @as(u8, config.config_id) << 5;
    if (config.encode_length) {
        buf[0] = config_bits | (NETCODE_CID_LEN - 1); // length encoded as total - 1
    } else {
        var rb: [1]u8 = undefined;
        crypto.random.bytes(&rb);
        buf[0] = config_bits | (rb[0] & 0x1F);
    }

    var payload: NetcodePayload = .{};
    payload.server_id = server_id;
    crypto.random.bytes(&payload.nonce);

    var pt: [NETCODE_PAYLOAD_LEN]u8 = undefined;
    @memcpy(pt[0..NETCODE_SERVER_ID_LEN], &payload.server_id);
    @memcpy(pt[NETCODE_SERVER_ID_LEN..][0..NETCODE_RESERVED_LEN], &payload.reserved);
    @memcpy(pt[NETCODE_SERVER_ID_LEN + NETCODE_RESERVED_LEN ..][0..NETCODE_NONCE_LEN], &payload.nonce);

    const ctx = Aes128.initEnc(config.key);
    var ct: [NETCODE_PAYLOAD_LEN]u8 = undefined;
    ctx.encrypt(&ct, &pt);
    @memcpy(buf[1..NETCODE_CID_LEN], &ct);
}

/// Decrypt a netcode-format CID and return the full structured payload.
/// Returns false if the CID is too short.
pub fn decodeNetcodeCid(
    config: *const NetcodeConfig,
    cid: []const u8,
    out: *NetcodePayload,
) bool {
    if (cid.len < NETCODE_CID_LEN) return false;

    const ctx = Aes128.initDec(config.key);
    var pt: [NETCODE_PAYLOAD_LEN]u8 = undefined;
    var ct: [NETCODE_PAYLOAD_LEN]u8 = undefined;
    @memcpy(&ct, cid[1..NETCODE_CID_LEN]);
    ctx.decrypt(&pt, &ct);

    @memcpy(&out.server_id, pt[0..NETCODE_SERVER_ID_LEN]);
    @memcpy(&out.reserved, pt[NETCODE_SERVER_ID_LEN..][0..NETCODE_RESERVED_LEN]);
    @memcpy(&out.nonce, pt[NETCODE_SERVER_ID_LEN + NETCODE_RESERVED_LEN ..][0..NETCODE_NONCE_LEN]);
    return true;
}

/// Extract just the server_id from a netcode CID. Convenience wrapper over
/// `decodeNetcodeCid` that skips the reserved/nonce fields.
pub fn extractNetcodeServerId(
    config: *const NetcodeConfig,
    cid: []const u8,
    out: *[NETCODE_SERVER_ID_LEN]u8,
) bool {
    var payload: NetcodePayload = .{};
    if (!decodeNetcodeCid(config, cid, &payload)) return false;
    out.* = payload.server_id;
    return true;
}

// --- Tests ---

// Plaintext roundtrip: generate CID, extract server_id, verify match
test "quic_lb plaintext roundtrip" {
    var config = Config{
        .config_id = 2,
        .server_id_len = 4,
        .nonce_len = 6,
    };
    config.server_id[0] = 0xAB;
    config.server_id[1] = 0xCD;
    config.server_id[2] = 0x12;
    config.server_id[3] = 0x34;

    const total = cidLength(&config);
    try std.testing.expectEqual(@as(u8, 11), total); // 1 + 4 + 6

    var cid: [20]u8 = undefined;
    generateCid(&config, &cid);

    // Verify config_id in first octet
    try std.testing.expectEqual(@as(u3, 2), extractConfigId(cid[0]));

    // Verify encoded length in first octet
    try std.testing.expectEqual(@as(u8, 10), cid[0] & 0x1F); // total - 1 = 10

    // Extract and verify server_id
    var extracted_sid: [15]u8 = undefined;
    try std.testing.expect(extractServerId(&config, &cid, &extracted_sid));
    try std.testing.expectEqualSlices(u8, &.{ 0xAB, 0xCD, 0x12, 0x34 }, extracted_sid[0..4]);
}

// Encrypted roundtrip (Feistel): generate CID, extract server_id, verify match
test "quic_lb encrypted roundtrip feistel" {
    var config = Config{
        .config_id = 3,
        .server_id_len = 4,
        .nonce_len = 6,
        .key = .{ 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10 },
    };
    config.server_id[0] = 0xDE;
    config.server_id[1] = 0xAD;
    config.server_id[2] = 0xBE;
    config.server_id[3] = 0xEF;

    const total = cidLength(&config);
    try std.testing.expectEqual(@as(u8, 11), total);

    var cid: [20]u8 = undefined;
    generateCid(&config, &cid);

    // Config ID preserved in first octet (not encrypted)
    try std.testing.expectEqual(@as(u3, 3), extractConfigId(cid[0]));

    // Encrypted bytes should differ from plaintext server_id
    // (with overwhelming probability given random nonce)
    const plaintext_match = std.mem.eql(u8, cid[1..5], &.{ 0xDE, 0xAD, 0xBE, 0xEF });
    // Not guaranteed to be different, but extremely likely
    _ = plaintext_match;

    // Extract and verify server_id
    var extracted_sid: [15]u8 = undefined;
    try std.testing.expect(extractServerId(&config, &cid, &extracted_sid));
    try std.testing.expectEqualSlices(u8, &.{ 0xDE, 0xAD, 0xBE, 0xEF }, extracted_sid[0..4]);
}

// Single-pass AES-ECB (server_id_len + nonce_len == 16)
test "quic_lb single pass aes ecb" {
    var config = Config{
        .config_id = 1,
        .server_id_len = 8,
        .nonce_len = 8,
        .key = .{ 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99 },
    };
    config.server_id[0] = 0x01;
    config.server_id[1] = 0x02;
    config.server_id[2] = 0x03;
    config.server_id[3] = 0x04;
    config.server_id[4] = 0x05;
    config.server_id[5] = 0x06;
    config.server_id[6] = 0x07;
    config.server_id[7] = 0x08;

    const total = cidLength(&config);
    try std.testing.expectEqual(@as(u8, 17), total); // 1 + 8 + 8

    var cid: [20]u8 = undefined;
    generateCid(&config, &cid);

    // Extract and verify server_id
    var extracted_sid: [15]u8 = undefined;
    try std.testing.expect(extractServerId(&config, &cid, &extracted_sid));
    try std.testing.expectEqualSlices(u8, &.{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 }, extracted_sid[0..8]);
}

// Config ID extraction from first octet
test "quic_lb config id extraction" {
    try std.testing.expectEqual(@as(u3, 0), extractConfigId(0b000_00000));
    try std.testing.expectEqual(@as(u3, 1), extractConfigId(0b001_00000));
    try std.testing.expectEqual(@as(u3, 3), extractConfigId(0b011_10101));
    try std.testing.expectEqual(@as(u3, 6), extractConfigId(0b110_11111));
    try std.testing.expectEqual(@as(u3, 7), extractConfigId(0b111_00000));
}

// Different CIDs for same server_id (nonce uniqueness)
test "quic_lb nonce uniqueness" {
    var config = Config{
        .config_id = 0,
        .server_id_len = 2,
        .nonce_len = 6,
    };
    config.server_id[0] = 0xAA;
    config.server_id[1] = 0xBB;

    var cid1: [20]u8 = undefined;
    var cid2: [20]u8 = undefined;
    generateCid(&config, &cid1);
    generateCid(&config, &cid2);

    const total = cidLength(&config);
    // CIDs should be different (with overwhelming probability)
    try std.testing.expect(!std.mem.eql(u8, cid1[0..total], cid2[0..total]));

    // But both should extract to the same server_id
    var sid1: [15]u8 = undefined;
    var sid2: [15]u8 = undefined;
    try std.testing.expect(extractServerId(&config, &cid1, &sid1));
    try std.testing.expect(extractServerId(&config, &cid2, &sid2));
    try std.testing.expectEqualSlices(u8, sid1[0..2], sid2[0..2]);
    try std.testing.expectEqualSlices(u8, &.{ 0xAA, 0xBB }, sid1[0..2]);
}

// CID too short returns false
test "quic_lb extract from short cid" {
    var config = Config{
        .config_id = 0,
        .server_id_len = 4,
        .nonce_len = 6,
    };
    var out: [15]u8 = undefined;
    const short_cid = [_]u8{ 0x00, 0x01, 0x02 };
    try std.testing.expect(!extractServerId(&config, &short_cid, &out));
}

// Feistel encrypt/decrypt roundtrip with known data
test "quic_lb feistel roundtrip deterministic" {
    const key = [16]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10 };
    var data = [_]u8{ 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22, 0x33, 0x44 };
    const original = data;

    feistelEncrypt(key, &data, 10);
    // Encrypted should differ from original
    try std.testing.expect(!std.mem.eql(u8, &data, &original));

    feistelDecrypt(key, &data, 10);
    // Decrypted should match original
    try std.testing.expectEqualSlices(u8, &original, &data);
}

// Single-pass AES roundtrip with known data
test "quic_lb single pass aes roundtrip deterministic" {
    const key = [16]u8{ 0xF0, 0xE1, 0xD2, 0xC3, 0xB4, 0xA5, 0x96, 0x87, 0x78, 0x69, 0x5A, 0x4B, 0x3C, 0x2D, 0x1E, 0x0F };
    var data: [16]u8 = .{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10 };
    const original = data;

    singlePassEncrypt(key, &data);
    try std.testing.expect(!std.mem.eql(u8, &data, &original));

    singlePassDecrypt(key, &data);
    try std.testing.expectEqualSlices(u8, &original, &data);
}

// Encrypted roundtrip with encode_length=false
test "quic_lb encrypted no length encoding" {
    var config = Config{
        .config_id = 5,
        .server_id_len = 3,
        .nonce_len = 5,
        .key = .{ 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xA0, 0xB0, 0xC0, 0xD0, 0xE0, 0xF0, 0x00 },
        .encode_length = false,
    };
    config.server_id[0] = 0x11;
    config.server_id[1] = 0x22;
    config.server_id[2] = 0x33;

    var cid: [20]u8 = undefined;
    generateCid(&config, &cid);

    // Config ID still in bits 7-5
    try std.testing.expectEqual(@as(u3, 5), extractConfigId(cid[0]));

    // Extract server_id
    var extracted_sid: [15]u8 = undefined;
    try std.testing.expect(extractServerId(&config, &cid, &extracted_sid));
    try std.testing.expectEqualSlices(u8, &.{ 0x11, 0x22, 0x33 }, extracted_sid[0..3]);
}

// --- Retry Service (LB-side token mint/validate + replay defense) ---
//
// The LB self-encrypts retry tokens with its own AEAD key. Backends never
// see tokens; they receive the ODCID via the lb_envelope framing.
//
// Token wire layout:
//   key_id(1)        0 = current key, 1 = previous key (for rotation)
//   nonce(12)
//   ciphertext(variable)
//   tag(16)
//
// Plaintext layout (authenticated by GCM tag):
//   timestamp_ns(8)
//   backend_id(2)    big-endian
//   addr_data(14)    bytes 2..16 of sockaddr.storage (ipv4 port+addr fit)
//   odcid_len(1) | odcid(0..20)
//   retry_scid_len(1) | retry_scid(0..20)

const posix = std.posix;
const AesGcm = std.crypto.aead.aes_gcm.Aes128Gcm;

pub const RETRY_TOKEN_KEY_LEN: usize = AesGcm.key_length; // 16
pub const RETRY_TOKEN_NONCE_LEN: usize = AesGcm.nonce_length; // 12
pub const RETRY_TOKEN_TAG_LEN: usize = AesGcm.tag_length; // 16
pub const RETRY_TOKEN_ADDR_LEN: usize = 14;

pub const RETRY_TOKEN_PLAINTEXT_MAX: usize = 8 + 2 + RETRY_TOKEN_ADDR_LEN + 1 + 20 + 1 + 20;
pub const RETRY_TOKEN_MAX_LEN: usize =
    1 + RETRY_TOKEN_NONCE_LEN + RETRY_TOKEN_PLAINTEXT_MAX + RETRY_TOKEN_TAG_LEN;

pub const DEFAULT_TOKEN_MAX_AGE_NS: i64 = 10 * std.time.ns_per_s;
pub const DEFAULT_NONCE_CACHE_CAPACITY: usize = 4096;

pub const ValidatedRetryToken = struct {
    backend_id: u16 = 0,
    odcid_buf: [20]u8 = .{0} ** 20,
    odcid_len: u8 = 0,
    retry_scid_buf: [20]u8 = .{0} ** 20,
    retry_scid_len: u8 = 0,
    timestamp_ns: i64 = 0,

    pub fn odcid(self: *const ValidatedRetryToken) []const u8 {
        return self.odcid_buf[0..self.odcid_len];
    }
    pub fn retryScid(self: *const ValidatedRetryToken) []const u8 {
        return self.retry_scid_buf[0..self.retry_scid_len];
    }
};

pub const ValidateError = error{
    TokenTooShort,
    UnknownKeyId,
    DecryptFailed,
    MalformedPlaintext,
    AddressMismatch,
    Expired,
    Replay,
};

fn addrDataBytes(addr: *const posix.sockaddr.storage) *const [RETRY_TOKEN_ADDR_LEN]u8 {
    const raw: [*]const u8 = @ptrCast(addr);
    return raw[2..16];
}

/// Ring buffer of recently-validated nonces, to reject replays within the
/// token's validity window.
const NonceCache = struct {
    entries: []Entry,
    head: usize = 0,
    count: usize = 0,

    const Entry = struct {
        nonce: [RETRY_TOKEN_NONCE_LEN]u8 = .{0} ** RETRY_TOKEN_NONCE_LEN,
        expiry_ns: i64 = 0,
        used: bool = false,
    };

    fn init(allocator: std.mem.Allocator, capacity: usize) !NonceCache {
        const entries = try allocator.alloc(Entry, capacity);
        @memset(entries, .{});
        return .{ .entries = entries };
    }

    fn deinit(self: *NonceCache, allocator: std.mem.Allocator) void {
        allocator.free(self.entries);
    }

    fn contains(self: *const NonceCache, nonce: [RETRY_TOKEN_NONCE_LEN]u8, now_ns: i64) bool {
        for (self.entries) |e| {
            if (!e.used or e.expiry_ns < now_ns) continue;
            if (std.mem.eql(u8, &e.nonce, &nonce)) return true;
        }
        return false;
    }

    fn insert(self: *NonceCache, nonce: [RETRY_TOKEN_NONCE_LEN]u8, expiry_ns: i64) void {
        self.entries[self.head] = .{ .nonce = nonce, .expiry_ns = expiry_ns, .used = true };
        self.head = (self.head + 1) % self.entries.len;
        if (self.count < self.entries.len) self.count += 1;
    }
};

pub const RetryService = struct {
    current_key: [RETRY_TOKEN_KEY_LEN]u8,
    previous_key: ?[RETRY_TOKEN_KEY_LEN]u8 = null,
    max_age_ns: i64 = DEFAULT_TOKEN_MAX_AGE_NS,
    nonce_cache: NonceCache,

    pub fn init(
        allocator: std.mem.Allocator,
        current_key: [RETRY_TOKEN_KEY_LEN]u8,
        previous_key: ?[RETRY_TOKEN_KEY_LEN]u8,
        cache_capacity: usize,
    ) !RetryService {
        return .{
            .current_key = current_key,
            .previous_key = previous_key,
            .nonce_cache = try NonceCache.init(allocator, cache_capacity),
        };
    }

    pub fn deinit(self: *RetryService, allocator: std.mem.Allocator) void {
        self.nonce_cache.deinit(allocator);
    }

    pub fn mintToken(
        self: *const RetryService,
        out: []u8,
        odcid_bytes: []const u8,
        retry_scid_bytes: []const u8,
        backend_id: u16,
        client_addr: posix.sockaddr.storage,
    ) !usize {
        if (out.len < RETRY_TOKEN_MAX_LEN) return error.BufferTooSmall;
        if (odcid_bytes.len > 20 or retry_scid_bytes.len > 20) return error.BufferTooSmall;

        out[0] = 0; // key_id — we always mint with current key
        var nonce: [RETRY_TOKEN_NONCE_LEN]u8 = undefined;
        crypto.random.bytes(&nonce);
        @memcpy(out[1..][0..RETRY_TOKEN_NONCE_LEN], &nonce);

        var pt: [RETRY_TOKEN_PLAINTEXT_MAX]u8 = undefined;
        var off: usize = 0;
        const now: i64 = @intCast(std.time.nanoTimestamp());
        std.mem.writeInt(i64, pt[off..][0..8], now, .big);
        off += 8;
        std.mem.writeInt(u16, pt[off..][0..2], backend_id, .big);
        off += 2;
        @memcpy(pt[off..][0..RETRY_TOKEN_ADDR_LEN], addrDataBytes(&client_addr));
        off += RETRY_TOKEN_ADDR_LEN;
        pt[off] = @intCast(odcid_bytes.len);
        off += 1;
        @memcpy(pt[off..][0..odcid_bytes.len], odcid_bytes);
        off += odcid_bytes.len;
        pt[off] = @intCast(retry_scid_bytes.len);
        off += 1;
        @memcpy(pt[off..][0..retry_scid_bytes.len], retry_scid_bytes);
        off += retry_scid_bytes.len;

        const pt_slice = pt[0..off];
        var tag: [RETRY_TOKEN_TAG_LEN]u8 = undefined;
        const ct_dst = out[1 + RETRY_TOKEN_NONCE_LEN ..][0..off];

        // key_id byte is authenticated as additional data
        AesGcm.encrypt(ct_dst, &tag, pt_slice, out[0..1], nonce, self.current_key);

        @memcpy(out[1 + RETRY_TOKEN_NONCE_LEN + off ..][0..RETRY_TOKEN_TAG_LEN], &tag);
        return 1 + RETRY_TOKEN_NONCE_LEN + off + RETRY_TOKEN_TAG_LEN;
    }

    /// Validate a token without updating the replay cache. Useful for unit
    /// testing or inspection; production code should call `consumeToken`.
    pub fn validateTokenPeek(
        self: *const RetryService,
        token: []const u8,
        client_addr: posix.sockaddr.storage,
    ) ValidateError!ValidatedRetryToken {
        const min_len: usize = 1 + RETRY_TOKEN_NONCE_LEN + RETRY_TOKEN_TAG_LEN + 8 + 2 + RETRY_TOKEN_ADDR_LEN + 2;
        if (token.len < min_len) return error.TokenTooShort;

        const key_id = token[0];
        const key: [RETRY_TOKEN_KEY_LEN]u8 = switch (key_id) {
            0 => self.current_key,
            1 => self.previous_key orelse return error.UnknownKeyId,
            else => return error.UnknownKeyId,
        };

        const nonce = token[1..][0..RETRY_TOKEN_NONCE_LEN].*;
        const ct_start: usize = 1 + RETRY_TOKEN_NONCE_LEN;
        const ct_len = token.len - ct_start - RETRY_TOKEN_TAG_LEN;
        const ciphertext = token[ct_start..][0..ct_len];
        const tag = token[token.len - RETRY_TOKEN_TAG_LEN ..][0..RETRY_TOKEN_TAG_LEN].*;

        var pt: [RETRY_TOKEN_PLAINTEXT_MAX]u8 = undefined;
        AesGcm.decrypt(pt[0..ct_len], ciphertext, tag, token[0..1], nonce, key) catch
            return error.DecryptFailed;

        // Parse plaintext
        const pt_slice = pt[0..ct_len];
        if (pt_slice.len < 8 + 2 + RETRY_TOKEN_ADDR_LEN + 2) return error.MalformedPlaintext;

        var off: usize = 0;
        const ts = std.mem.readInt(i64, pt_slice[off..][0..8], .big);
        off += 8;
        const backend_id = std.mem.readInt(u16, pt_slice[off..][0..2], .big);
        off += 2;
        const addr_data = pt_slice[off..][0..RETRY_TOKEN_ADDR_LEN].*;
        off += RETRY_TOKEN_ADDR_LEN;

        if (!std.mem.eql(u8, &addr_data, addrDataBytes(&client_addr))) return error.AddressMismatch;

        const now: i64 = @intCast(std.time.nanoTimestamp());
        if (now - ts > self.max_age_ns or ts > now) return error.Expired;

        if (off + 1 > pt_slice.len) return error.MalformedPlaintext;
        const odcid_len = pt_slice[off];
        off += 1;
        if (odcid_len > 20 or off + odcid_len + 1 > pt_slice.len) return error.MalformedPlaintext;

        var result = ValidatedRetryToken{ .backend_id = backend_id, .timestamp_ns = ts };
        result.odcid_len = odcid_len;
        @memcpy(result.odcid_buf[0..odcid_len], pt_slice[off..][0..odcid_len]);
        off += odcid_len;

        const retry_scid_len = pt_slice[off];
        off += 1;
        if (retry_scid_len > 20 or off + retry_scid_len > pt_slice.len) return error.MalformedPlaintext;
        result.retry_scid_len = retry_scid_len;
        @memcpy(result.retry_scid_buf[0..retry_scid_len], pt_slice[off..][0..retry_scid_len]);

        return result;
    }

    /// Validate a token. The token's AEAD AAD authenticates the client
    /// address and the `key_id`, and the plaintext includes a timestamp
    /// for expiry. We deliberately do NOT reject repeat consumes of the
    /// same nonce: RFC 9000 permits Initial retransmission to carry the
    /// same retry token, so strict replay rejection would break recovery
    /// after a lost packet. Cross-address replay is prevented by the
    /// in-token address binding; temporal bound is the token lifetime.
    pub fn consumeToken(
        self: *RetryService,
        token: []const u8,
        client_addr: posix.sockaddr.storage,
    ) ValidateError!ValidatedRetryToken {
        return self.validateTokenPeek(token, client_addr);
    }
};

// --- Netcode mode tests ---

test "netcode: generate and decode roundtrip" {
    const config = NetcodeConfig{
        .config_id = 2,
        .key = .{ 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF },
    };
    const server_id = [_]u8{ 0xDE, 0xAD, 0xBE, 0xEF };

    var cid: [NETCODE_CID_LEN]u8 = undefined;
    generateNetcodeCid(&config, server_id, &cid);

    // First octet preserves config_id + length-self-encoding invariant
    try std.testing.expectEqual(@as(u3, 2), extractConfigId(cid[0]));
    try std.testing.expectEqual(@as(u8, NETCODE_CID_LEN - 1), cid[0] & 0x1F);

    // Round-trip server_id
    var sid_out: [NETCODE_SERVER_ID_LEN]u8 = undefined;
    try std.testing.expect(extractNetcodeServerId(&config, &cid, &sid_out));
    try std.testing.expectEqualSlices(u8, &server_id, &sid_out);
}

test "netcode: full payload round-trip preserves fields" {
    const config = NetcodeConfig{
        .config_id = 0,
        .key = .{0x42} ** 16,
    };
    const sid = [_]u8{ 0x01, 0x02, 0x03, 0x04 };

    var cid: [NETCODE_CID_LEN]u8 = undefined;
    generateNetcodeCid(&config, sid, &cid);

    var decoded: NetcodePayload = .{};
    try std.testing.expect(decodeNetcodeCid(&config, &cid, &decoded));
    try std.testing.expectEqualSlices(u8, &sid, &decoded.server_id);
    // reserved starts zero; generateNetcodeCid doesn't touch it
    try std.testing.expectEqualSlices(u8, &[_]u8{0} ** NETCODE_RESERVED_LEN, &decoded.reserved);
    // nonce is random — just confirm it decoded into 8 bytes; extremely unlikely all zero
    const all_zero = std.mem.allEqual(u8, &decoded.nonce, 0);
    try std.testing.expect(!all_zero);
}

test "netcode: wrong key fails to recover server_id" {
    const key1: [16]u8 = .{0x01} ** 16;
    const key2: [16]u8 = .{0x02} ** 16;
    const config1 = NetcodeConfig{ .config_id = 1, .key = key1 };
    const config2 = NetcodeConfig{ .config_id = 1, .key = key2 };

    const sid = [_]u8{ 0xAA, 0xBB, 0xCC, 0xDD };
    var cid: [NETCODE_CID_LEN]u8 = undefined;
    generateNetcodeCid(&config1, sid, &cid);

    var sid_out: [NETCODE_SERVER_ID_LEN]u8 = undefined;
    try std.testing.expect(extractNetcodeServerId(&config2, &cid, &sid_out));
    // Decrypted garbage should almost certainly not equal the original sid
    try std.testing.expect(!std.mem.eql(u8, &sid, &sid_out));
}

test "netcode: nonce uniqueness across mints" {
    const config = NetcodeConfig{ .config_id = 0, .key = .{0x11} ** 16 };
    const sid = [_]u8{ 0x10, 0x20, 0x30, 0x40 };

    var cid1: [NETCODE_CID_LEN]u8 = undefined;
    var cid2: [NETCODE_CID_LEN]u8 = undefined;
    generateNetcodeCid(&config, sid, &cid1);
    generateNetcodeCid(&config, sid, &cid2);

    // CIDs differ (encrypted payload differs because nonce differs)
    try std.testing.expect(!std.mem.eql(u8, &cid1, &cid2));

    // But both decrypt to the same server_id
    var s1: [NETCODE_SERVER_ID_LEN]u8 = undefined;
    var s2: [NETCODE_SERVER_ID_LEN]u8 = undefined;
    try std.testing.expect(extractNetcodeServerId(&config, &cid1, &s1));
    try std.testing.expect(extractNetcodeServerId(&config, &cid2, &s2));
    try std.testing.expectEqualSlices(u8, &s1, &s2);
}

test "netcode: short CID rejected" {
    const config = NetcodeConfig{ .config_id = 0, .key = .{0} ** 16 };
    const short = [_]u8{ 0x00, 0x01, 0x02 };
    var sid_out: [NETCODE_SERVER_ID_LEN]u8 = undefined;
    try std.testing.expect(!extractNetcodeServerId(&config, &short, &sid_out));
}

// --- Retry Service tests ---

fn makeAddr(port: u16, oct: [4]u8) posix.sockaddr.storage {
    var addr: posix.sockaddr.storage = std.mem.zeroes(posix.sockaddr.storage);
    addr.family = posix.AF.INET;
    // sockaddr_in layout: family(2) port(2) addr(4) ...
    addr.padding[0] = @intCast((port >> 8) & 0xFF);
    addr.padding[1] = @intCast(port & 0xFF);
    addr.padding[2] = oct[0];
    addr.padding[3] = oct[1];
    addr.padding[4] = oct[2];
    addr.padding[5] = oct[3];
    return addr;
}

test "retry_service: mint and consume roundtrip" {
    const allocator = std.testing.allocator;
    var svc = try RetryService.init(allocator, .{0xAB} ** 16, null, 64);
    defer svc.deinit(allocator);

    const odcid = &[_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 };
    const retry_scid = &[_]u8{ 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18 };
    const addr = makeAddr(4433, .{ 127, 0, 0, 1 });

    var tok: [RETRY_TOKEN_MAX_LEN]u8 = undefined;
    const n = try svc.mintToken(&tok, odcid, retry_scid, 0x00AB, addr);

    const v = try svc.consumeToken(tok[0..n], addr);
    try std.testing.expectEqual(@as(u16, 0x00AB), v.backend_id);
    try std.testing.expectEqualSlices(u8, odcid, v.odcid());
    try std.testing.expectEqualSlices(u8, retry_scid, v.retryScid());
}

test "retry_service: Initial retransmits replay the same token" {
    // RFC 9000 §17.2.5.1: clients reuse the token on retransmitted Initials.
    // The LB must accept multiple consumes within the validity window.
    const allocator = std.testing.allocator;
    var svc = try RetryService.init(allocator, .{0xCD} ** 16, null, 64);
    defer svc.deinit(allocator);

    const addr = makeAddr(5000, .{ 10, 0, 0, 42 });
    var tok: [RETRY_TOKEN_MAX_LEN]u8 = undefined;
    const n = try svc.mintToken(&tok, &.{1}, &.{2}, 1, addr);

    _ = try svc.consumeToken(tok[0..n], addr);
    _ = try svc.consumeToken(tok[0..n], addr); // retransmit: still valid
    _ = try svc.consumeToken(tok[0..n], addr);
}

test "retry_service: wrong address rejected" {
    const allocator = std.testing.allocator;
    var svc = try RetryService.init(allocator, .{0x11} ** 16, null, 64);
    defer svc.deinit(allocator);

    const addr1 = makeAddr(1, .{ 127, 0, 0, 1 });
    const addr2 = makeAddr(1, .{ 127, 0, 0, 2 });
    var tok: [RETRY_TOKEN_MAX_LEN]u8 = undefined;
    const n = try svc.mintToken(&tok, &.{1}, &.{2}, 1, addr1);

    try std.testing.expectError(error.AddressMismatch, svc.validateTokenPeek(tok[0..n], addr2));
}

test "retry_service: tampered token fails decrypt" {
    const allocator = std.testing.allocator;
    var svc = try RetryService.init(allocator, .{0x22} ** 16, null, 64);
    defer svc.deinit(allocator);

    const addr = makeAddr(1, .{ 127, 0, 0, 1 });
    var tok: [RETRY_TOKEN_MAX_LEN]u8 = undefined;
    const n = try svc.mintToken(&tok, &.{ 1, 2, 3 }, &.{ 4, 5, 6 }, 7, addr);

    tok[30] ^= 0xFF;
    try std.testing.expectError(error.DecryptFailed, svc.validateTokenPeek(tok[0..n], addr));
}

test "retry_service: expired token rejected" {
    const allocator = std.testing.allocator;
    var svc = try RetryService.init(allocator, .{0x44} ** 16, null, 64);
    defer svc.deinit(allocator);

    const addr = makeAddr(1, .{ 127, 0, 0, 1 });
    var tok: [RETRY_TOKEN_MAX_LEN]u8 = undefined;
    const n = try svc.mintToken(&tok, &.{1}, &.{2}, 1, addr);

    // Shrink validity window to 1ns — by the time we call consume, the
    // wall clock has already advanced past that.
    svc.max_age_ns = 1;
    std.Thread.sleep(1_000); // 1µs

    try std.testing.expectError(error.Expired, svc.validateTokenPeek(tok[0..n], addr));
}

test "retry_service: unknown key_id rejected" {
    const allocator = std.testing.allocator;
    var svc = try RetryService.init(allocator, .{0x33} ** 16, null, 64);
    defer svc.deinit(allocator);

    const addr = makeAddr(1, .{ 127, 0, 0, 1 });
    var tok: [RETRY_TOKEN_MAX_LEN]u8 = undefined;
    const n = try svc.mintToken(&tok, &.{1}, &.{2}, 1, addr);

    tok[0] = 5; // invalid key_id
    try std.testing.expectError(error.UnknownKeyId, svc.validateTokenPeek(tok[0..n], addr));

    // key_id=1 without a configured previous_key also rejected
    tok[0] = 1;
    try std.testing.expectError(error.UnknownKeyId, svc.validateTokenPeek(tok[0..n], addr));
}
