// QUIC-LB: Connection ID encoding/decoding for load balancers
// Implements draft-ietf-quic-load-balancers CID generation with
// plaintext and encrypted (4-pass Feistel / single-pass AES-ECB) modes.

const std = @import("std");
const crypto = std.crypto;
const Aes128 = crypto.core.aes.Aes128;

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
