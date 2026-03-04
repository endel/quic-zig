const std = @import("std");
const crypto = std.crypto;
const HmacSha256 = crypto.auth.hmac.sha2.HmacSha256;

pub const TOKEN_LEN: usize = 16;
pub const MIN_PACKET_LEN: usize = 21; // RFC 9000 §10.3: at least 1 byte header + 4 random + 16 token

// Compute a deterministic stateless reset token from a static key and connection ID.
// HMAC-SHA256(static_key, conn_id), truncated to 16 bytes.
pub fn computeToken(static_key: [16]u8, conn_id: []const u8) [TOKEN_LEN]u8 {
    var mac: [HmacSha256.mac_length]u8 = undefined;
    HmacSha256.create(&mac, conn_id, &static_key);
    return mac[0..TOKEN_LEN].*;
}

// Generate a stateless reset packet (RFC 9000 §10.3).
// Format: random header bytes (looks like short header) + stateless_reset_token as last 16 bytes.
// Returns the number of bytes written, or 0 if max_size is too small.
pub fn generatePacket(out: []u8, max_size: usize, static_key: [16]u8, conn_id: []const u8) usize {
    const size = @min(max_size, out.len);
    if (size < MIN_PACKET_LEN) return 0;

    // Fill entire packet with random bytes
    crypto.random.bytes(out[0..size]);

    // First byte: must look like short header (bit 7 clear = 0, fixed bit 6 = random already)
    // Clear the long header bit (0x80)
    out[0] &= 0x7F;
    // Set the fixed bit (0x40) — RFC 9000 §10.3 says it SHOULD be set to avoid being
    // discarded, but the RFC also says "An endpoint MUST treat any packet ending in a
    // valid stateless reset token as a Stateless Reset". We set it for compatibility.
    out[0] |= 0x40;

    // Write the stateless reset token as the last 16 bytes
    const token = computeToken(static_key, conn_id);
    @memcpy(out[size - TOKEN_LEN .. size], &token);

    return size;
}

// Check if a received packet is a stateless reset by comparing its last 16 bytes
// against known peer reset tokens.
pub fn isStatelessReset(data: []const u8, tokens: []const [TOKEN_LEN]u8) bool {
    if (data.len < MIN_PACKET_LEN) return false;

    const packet_token = data[data.len - TOKEN_LEN ..][0..TOKEN_LEN];
    for (tokens) |known_token| {
        if (std.mem.eql(u8, packet_token, &known_token)) return true;
    }
    return false;
}

// Token determinism: same key + CID produces same token
test "computeToken deterministic" {
    const key = [_]u8{0x01} ** 16;
    const cid = [_]u8{ 0xAA, 0xBB, 0xCC, 0xDD };

    const t1 = computeToken(key, &cid);
    const t2 = computeToken(key, &cid);
    try std.testing.expectEqualSlices(u8, &t1, &t2);
}

// Different CIDs produce different tokens
test "computeToken different CIDs" {
    const key = [_]u8{0x01} ** 16;
    const cid1 = [_]u8{ 0xAA, 0xBB, 0xCC, 0xDD };
    const cid2 = [_]u8{ 0xAA, 0xBB, 0xCC, 0xDE };

    const t1 = computeToken(key, &cid1);
    const t2 = computeToken(key, &cid2);
    try std.testing.expect(!std.mem.eql(u8, &t1, &t2));
}

// Generate + detect roundtrip
test "generatePacket and isStatelessReset roundtrip" {
    const key = [_]u8{0x42} ** 16;
    const cid = [_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };

    var buf: [64]u8 = undefined;
    const size = generatePacket(&buf, 64, key, &cid);
    try std.testing.expect(size == 64);

    // First byte should look like short header
    try std.testing.expect(buf[0] & 0x80 == 0); // not long header
    try std.testing.expect(buf[0] & 0x40 != 0); // fixed bit set

    // Should be detected with matching token
    const token = computeToken(key, &cid);
    const tokens = [_][TOKEN_LEN]u8{token};
    try std.testing.expect(isStatelessReset(buf[0..size], &tokens));
}

// Wrong token not detected
test "isStatelessReset wrong token" {
    const key = [_]u8{0x42} ** 16;
    const cid = [_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };

    var buf: [64]u8 = undefined;
    const size = generatePacket(&buf, 64, key, &cid);

    // Try with a different token
    const wrong_token = [_]u8{0xFF} ** TOKEN_LEN;
    const tokens = [_][TOKEN_LEN]u8{wrong_token};
    try std.testing.expect(!isStatelessReset(buf[0..size], &tokens));
}

// Minimum size enforcement
test "isStatelessReset minimum size" {
    const token = [_]u8{0xAA} ** TOKEN_LEN;
    const tokens = [_][TOKEN_LEN]u8{token};

    // 20 bytes is too small (need at least 21)
    var small_buf: [20]u8 = undefined;
    @memcpy(small_buf[4..20], &token);
    try std.testing.expect(!isStatelessReset(&small_buf, &tokens));

    // 21 bytes is the minimum
    var min_buf: [21]u8 = undefined;
    @memcpy(min_buf[5..21], &token);
    try std.testing.expect(isStatelessReset(&min_buf, &tokens));
}

// generatePacket too small
test "generatePacket too small" {
    const key = [_]u8{0x01} ** 16;
    const cid = [_]u8{0x01};

    var buf: [64]u8 = undefined;
    // max_size < MIN_PACKET_LEN should return 0
    const size = generatePacket(&buf, 20, key, &cid);
    try std.testing.expect(size == 0);
}
