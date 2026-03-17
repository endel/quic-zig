const std = @import("std");
const protocol = @import("protocol.zig");
const packet = @import("packet.zig");
const assert = std.debug.assert;

const crypto = std.crypto;
const HkdfSha256 = crypto.kdf.hkdf.HkdfSha256;
const HmacSha256 = crypto.auth.hmac.sha2.HmacSha256;
const Aes128Gcm = crypto.aead.aes_gcm.Aes128Gcm;
const Aes128 = crypto.core.aes.Aes128;
const Aes256 = crypto.core.aes.Aes256;
const ChaCha20Poly1305 = crypto.aead.chacha_poly.ChaCha20Poly1305;
const ChaCha20IETF = crypto.stream.chacha.ChaCha20IETF;

// RFC 9001 §5.2: QUIC v1 initial salt
const INITIAL_SALT_V1 = [_]u8{ 0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a };
// RFC 9369 §3.1: QUIC v2 initial salt
const INITIAL_SALT_V2 = [_]u8{ 0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb, 0xf9, 0xbd, 0x2e, 0xd9 };

// Header protection sample length
pub const SAMPLE_LEN = 16;
pub const MASK_LEN = 5;

pub const Aead = Aes128Gcm;
const Hmac = HmacSha256;

// AES-128-GCM key length (used for initial keys which are always AES)
pub const key_len = 16;
pub const nonce_len = 12;
// Max key length across all cipher suites (ChaCha20 = 32 bytes)
pub const max_key_len = 32;

pub const CipherSuite = enum(u16) {
    aes_128_gcm_sha256 = 0x1301,
    chacha20_poly1305_sha256 = 0x1303,

    pub fn keyLen(self: CipherSuite) usize {
        return switch (self) {
            .aes_128_gcm_sha256 => 16,
            .chacha20_poly1305_sha256 => 32,
        };
    }

    pub fn hpKeyLen(self: CipherSuite) usize {
        return switch (self) {
            .aes_128_gcm_sha256 => 16,
            .chacha20_poly1305_sha256 => 32,
        };
    }

    /// Confidentiality limit: max packets before key rotation required.
    /// RFC 9001 Section 6.6: 2^23 for AES-128-GCM, 2^62 for ChaCha20.
    pub fn confidentialityLimit(self: CipherSuite) u64 {
        return switch (self) {
            .aes_128_gcm_sha256 => 1 << 23,
            .chacha20_poly1305_sha256 => 1 << 62,
        };
    }
};

// Note: similar to packet.Epoch (4 values, maps to packet types) and
// ack_handler.EncLevel (3 values, maps to PN spaces — no 0-RTT space).
// Kept separate because the value mappings and cardinalities differ.
pub const EncryptionLevel = enum(u8) {
    initial = 0,
    early_data,
    handshake,
    application,
};

pub const Open = struct {
    key: [max_key_len]u8 = .{0} ** max_key_len,
    hp_key: [max_key_len]u8 = .{0} ** max_key_len,
    nonce: [nonce_len]u8,
    cipher_suite: CipherSuite = .aes_128_gcm_sha256,

    /// Generate a new QUIC Header Protection mask.
    pub fn newMask(self: *const Open, sample: *const [SAMPLE_LEN]u8) [MASK_LEN]u8 {
        return computeHpMask(sample, self.hp_key, self.cipher_suite);
    }

    pub fn decryptPayload(
        self: *Open,
        packet_number: u64,
        associated_data: []const u8,
        payload: []u8,
    ) error{ AuthenticationFailed, OutOfMemory }![]u8 {
        const tag_len = 16; // Same for both AES-128-GCM and ChaCha20-Poly1305
        const payload_len = payload.len;

        assert(payload_len >= tag_len);

        const tag: [tag_len]u8 = tag: {
            var t: [tag_len]u8 = undefined;
            @memcpy(&t, payload[(payload_len - tag_len)..payload_len]);
            break :tag t;
        };

        const aead_nonce = makeNonce(self.nonce, packet_number);
        const bytes = payload[0..(payload_len - tag_len)];

        switch (self.cipher_suite) {
            .aes_128_gcm_sha256 => {
                Aes128Gcm.decrypt(bytes, bytes, tag, associated_data, aead_nonce, self.key[0..16].*) catch |err| {
                    std.log.err("AES-128-GCM decryption failed: {any}", .{err});
                    return err;
                };
            },
            .chacha20_poly1305_sha256 => {
                ChaCha20Poly1305.decrypt(bytes, bytes, tag, associated_data, aead_nonce, self.key) catch |err| {
                    std.log.err("ChaCha20-Poly1305 decryption failed: {any}", .{err});
                    return err;
                };
            },
        }

        return bytes;
    }
};

pub const Seal = struct {
    key: [max_key_len]u8 = .{0} ** max_key_len,
    hp_key: [max_key_len]u8 = .{0} ** max_key_len,
    nonce: [nonce_len]u8,
    cipher_suite: CipherSuite = .aes_128_gcm_sha256,

    /// Generate a new QUIC Header Protection mask.
    pub fn newMask(self: *const Seal, sample: *const [SAMPLE_LEN]u8) [MASK_LEN]u8 {
        return computeHpMask(sample, self.hp_key, self.cipher_suite);
    }

    /// Encrypt a QUIC packet payload using AEAD.
    /// Writes ciphertext + tag into `out` (which must be plaintext.len + tag_length).
    /// Returns the total output length (plaintext.len + tag_length).
    pub fn encryptPayload(
        self: *const Seal,
        packet_number: u64,
        associated_data: []const u8,
        plaintext: []const u8,
        out: []u8,
    ) usize {
        const aead_nonce = makeNonce(self.nonce, packet_number);
        const tag_len = 16; // Same for both

        assert(out.len >= plaintext.len + tag_len);

        var tag: [tag_len]u8 = undefined;
        switch (self.cipher_suite) {
            .aes_128_gcm_sha256 => {
                Aes128Gcm.encrypt(out[0..plaintext.len], &tag, plaintext, associated_data, aead_nonce, self.key[0..16].*);
            },
            .chacha20_poly1305_sha256 => {
                ChaCha20Poly1305.encrypt(out[0..plaintext.len], &tag, plaintext, associated_data, aead_nonce, self.key);
            },
        }
        @memcpy(out[plaintext.len..][0..tag_len], &tag);

        return plaintext.len + tag_len;
    }
};

/// Construct the AEAD nonce by XORing the IV with the packet number.
/// RFC 9001 Section 5.3.
fn makeNonce(iv: [nonce_len]u8, packet_number: u64) [nonce_len]u8 {
    var n = iv;
    var pn_bytes: [nonce_len]u8 = .{0} ** nonce_len;
    std.mem.writeInt(u64, pn_bytes[4..nonce_len], packet_number, .big);
    for (0..nonce_len) |i| {
        n[i] ^= pn_bytes[i];
    }
    return n;
}

/// Compute a QUIC Header Protection mask from a sample.
/// AES: AES-ECB encrypt the sample, take first 5 bytes.
/// ChaCha20: counter=sample[0..4] LE, nonce=sample[4..16], encrypt 5 zero bytes.
pub fn computeHpMask(sample: *const [SAMPLE_LEN]u8, hp_key: [max_key_len]u8, cipher_suite: CipherSuite) [MASK_LEN]u8 {
    switch (cipher_suite) {
        .aes_128_gcm_sha256 => {
            const ctx = Aes128.initEnc(hp_key[0..16].*);
            var encrypted_out: [SAMPLE_LEN]u8 = undefined;
            ctx.encrypt(&encrypted_out, sample);
            return encrypted_out[0..MASK_LEN].*;
        },
        .chacha20_poly1305_sha256 => {
            // RFC 9001 §5.4.4: counter=sample[0..4] LE, nonce=sample[4..16]
            const counter = std.mem.readInt(u32, sample[0..4], .little);
            const nonce: [12]u8 = sample[4..16].*;
            var zeros: [MASK_LEN]u8 = .{0} ** MASK_LEN;
            var mask: [MASK_LEN]u8 = undefined;
            ChaCha20IETF.xor(&mask, &zeros, counter, hp_key, nonce);
            return mask;
        },
    }
}

/// Apply header protection to an outgoing packet.
/// RFC 9001 Section 5.4.
pub fn applyHeaderProtection(
    pkt_buf: []u8,
    pn_offset: usize,
    pn_len: usize,
    hp_key: [max_key_len]u8,
    cipher_suite: CipherSuite,
) void {
    const sample_offset = pn_offset + 4;
    if (sample_offset + SAMPLE_LEN > pkt_buf.len) return;

    const sample: *const [SAMPLE_LEN]u8 = pkt_buf[sample_offset..][0..SAMPLE_LEN];
    const mask = computeHpMask(sample, hp_key, cipher_suite);

    // Apply mask to first byte
    if (isLongHeader(pkt_buf[0])) {
        pkt_buf[0] ^= (mask[0] & 0x0f);
    } else {
        pkt_buf[0] ^= (mask[0] & 0x1f);
    }

    // Apply mask to packet number bytes
    for (0..pn_len) |i| {
        pkt_buf[pn_offset + i] ^= mask[1 + i];
    }
}

/// Remove header protection from an incoming packet.
/// Returns the decoded packet number length (1-4) from the first byte.
pub fn removeHeaderProtection(
    pkt_buf: []u8,
    pn_offset: usize,
    hp_key: [max_key_len]u8,
    cipher_suite: CipherSuite,
) usize {
    const sample_offset = pn_offset + 4;
    if (sample_offset + SAMPLE_LEN > pkt_buf.len) return 0;

    const sample: *const [SAMPLE_LEN]u8 = pkt_buf[sample_offset..][0..SAMPLE_LEN];
    const mask = computeHpMask(sample, hp_key, cipher_suite);

    // Unmask first byte
    if (isLongHeader(pkt_buf[0])) {
        pkt_buf[0] ^= (mask[0] & 0x0f);
    } else {
        pkt_buf[0] ^= (mask[0] & 0x1f);
    }

    const pn_len: usize = (pkt_buf[0] & 0x03) + 1;

    // Unmask packet number bytes
    for (0..pn_len) |i| {
        pkt_buf[pn_offset + i] ^= mask[1 + i];
    }

    return pn_len;
}

fn isLongHeader(first_byte: u8) bool {
    return (first_byte & 0x80) == 0x80;
}

/// Encode a packet number using the minimum number of bytes.
/// RFC 9000 Appendix A.2.
/// Returns the number of bytes used (1-4) and writes to `out`.
pub fn encodePacketNumber(pn: u64, largest_acked: ?u64, out: *[4]u8) usize {
    // Calculate the number of bits needed
    const num_unacked: u64 = if (largest_acked) |la|
        (pn -| la) // saturating sub
    else
        pn + 1;

    // We need enough bits so that 2*num_unacked fits
    const min_bits: usize = if (num_unacked == 0)
        8
    else blk: {
        const needed = 64 - @clz(2 * num_unacked);
        break :blk if (needed <= 8) 8 else if (needed <= 16) 16 else if (needed <= 24) 24 else 32;
    };

    const pn_len = min_bits / 8;

    switch (pn_len) {
        1 => out[0] = @truncate(pn),
        2 => std.mem.writeInt(u16, out[0..2], @truncate(pn), .big),
        3 => {
            out[0] = @truncate(pn >> 16);
            out[1] = @truncate(pn >> 8);
            out[2] = @truncate(pn);
        },
        4 => std.mem.writeInt(u32, out[0..4], @truncate(pn), .big),
        else => unreachable,
    }

    return pn_len;
}

pub fn deriveInitialKeyMaterial(
    cid: []const u8,
    version: u32,
    comptime is_server: bool,
) !std.meta.Tuple(&.{ Open, Seal }) {
    if (!protocol.isSupportedVersion(version)) {
        std.log.err("unsupported QUIC version: 0x{x:0>8}", .{version});
        return error.InvalidVersion;
    }

    // RFC 9001 §5.2 / RFC 9369 §3.1: version-specific initial salt
    const salt = if (protocol.isV2(version)) &INITIAL_SALT_V2 else &INITIAL_SALT_V1;
    const label_key = protocol.quicLabel(version, .key);
    const label_iv = protocol.quicLabel(version, .iv);
    const label_hp = protocol.quicLabel(version, .hp);

    const initial_secret = HkdfSha256.extract(salt, cid);
    var secret: [32]u8 = undefined;

    // Client (Initial keys are always AES-128-GCM)
    secret = hkdfExpandLabel(initial_secret, "client in", "", Hmac.key_length);
    const client_key_16 = hkdfExpandLabelRuntime(secret, label_key, "", key_len);
    const client_iv = hkdfExpandLabelRuntime(secret, label_iv, "", nonce_len);
    const client_hp_16 = hkdfExpandLabelRuntime(secret, label_hp, "", key_len);
    var client_key: [max_key_len]u8 = .{0} ** max_key_len;
    @memcpy(client_key[0..key_len], &client_key_16);
    var client_hp_key: [max_key_len]u8 = .{0} ** max_key_len;
    @memcpy(client_hp_key[0..key_len], &client_hp_16);

    // Server
    secret = hkdfExpandLabel(initial_secret, "server in", "", Hmac.key_length);
    const server_key_16 = hkdfExpandLabelRuntime(secret, label_key, "", key_len);
    const server_iv = hkdfExpandLabelRuntime(secret, label_iv, "", nonce_len);
    const server_hp_16 = hkdfExpandLabelRuntime(secret, label_hp, "", key_len);
    var server_key: [max_key_len]u8 = .{0} ** max_key_len;
    @memcpy(server_key[0..key_len], &server_key_16);
    var server_hp_key: [max_key_len]u8 = .{0} ** max_key_len;
    @memcpy(server_hp_key[0..key_len], &server_hp_16);

    return if (is_server) .{
        Open{ .key = client_key, .hp_key = client_hp_key, .nonce = client_iv },
        Seal{ .key = server_key, .hp_key = server_hp_key, .nonce = server_iv },
    } else .{
        Open{ .key = server_key, .hp_key = server_hp_key, .nonce = server_iv },
        Seal{ .key = client_key, .hp_key = client_hp_key, .nonce = client_iv },
    };
}

// https://www.rfc-editor.org/rfc/rfc9001#section-a.1
test "a.1: keys - initial secret" {
    {
        const expected = [_]u8{ 0x7d, 0xb5, 0xdf, 0x06, 0xe7, 0xa6, 0x9e, 0x43, 0x24, 0x96, 0xad, 0xed, 0xb0, 0x08, 0x51, 0x92, 0x35, 0x95, 0x22, 0x15, 0x96, 0xae, 0x2a, 0xe9, 0xfb, 0x81, 0x15, 0xc1, 0xe9, 0xed, 0x0a, 0x44 };
        const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
        const out = HkdfSha256.extract(&INITIAL_SALT_V1, &dcid);
        try std.testing.expectEqualSlices(u8, &expected, &out);
    }
    {
        const expected = [_]u8{ 0xf0, 0x16, 0xbb, 0x2d, 0xc9, 0x97, 0x6d, 0xea, 0x27, 0x26, 0xc4, 0xe6, 0x1e, 0x73, 0x8a, 0x1e, 0x36, 0x80, 0xa2, 0x48, 0x75, 0x91, 0xdc, 0x76, 0xb2, 0xae, 0xe2, 0xed, 0x75, 0x98, 0x22, 0xf6 };
        const dcid = [_]u8{ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 };
        const out = HkdfSha256.extract(&INITIAL_SALT_V1, &dcid);
        try std.testing.expectEqualSlices(u8, &expected, &out);
    }
}

// https://www.rfc-editor.org/rfc/rfc9001#section-a.1
test "a.1: keys - server initial secret" {
    {
        const expected = [_]u8{ 0x3c, 0x19, 0x98, 0x28, 0xfd, 0x13, 0x9e, 0xfd, 0x21, 0x6c, 0x15, 0x5a, 0xd8, 0x44, 0xcc, 0x81, 0xfb, 0x82, 0xfa, 0x8d, 0x74, 0x46, 0xfa, 0x7d, 0x78, 0xbe, 0x80, 0x3a, 0xcd, 0xda, 0x95, 0x1b };
        const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
        const initial_secret = HkdfSha256.extract(&INITIAL_SALT_V1, &dcid);
        var out = hkdfExpandLabel(initial_secret, "server in", "", Hmac.key_length);
        try std.testing.expectEqualSlices(u8, &expected, &out);
    }
    {
        // This test case is brought from https://quic.xargs.org/
        const expected = [_]u8{ 0xad, 0xc1, 0x99, 0x5b, 0x5c, 0xee, 0x8f, 0x03, 0x74, 0x6b, 0xf8, 0x30, 0x9d, 0x02, 0xd5, 0xea, 0x27, 0x15, 0x9c, 0x1e, 0xd6, 0x91, 0x54, 0x03, 0xb3, 0x63, 0x18, 0xd5, 0xa0, 0x3a, 0xfe, 0xb8 };
        const dcid = [_]u8{ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 };
        const initial_secret = HkdfSha256.extract(&INITIAL_SALT_V1, &dcid);
        var out = hkdfExpandLabel(initial_secret, "server in", "", Hmac.key_length);
        try std.testing.expectEqualSlices(u8, &expected, &out);
    }
}

test "a.1: keys - client initial secret" {
    {
        const expected = [_]u8{ 0xc0, 0x0c, 0xf1, 0x51, 0xca, 0x5b, 0xe0, 0x75, 0xed, 0x0e, 0xbf, 0xb5, 0xc8, 0x03, 0x23, 0xc4, 0x2d, 0x6b, 0x7d, 0xb6, 0x78, 0x81, 0x28, 0x9a, 0xf4, 0x00, 0x8f, 0x1f, 0x6c, 0x35, 0x7a, 0xea };
        const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
        const initial_secret = HkdfSha256.extract(&INITIAL_SALT_V1, &dcid);
        var out = hkdfExpandLabel(initial_secret, "client in", "", Hmac.key_length);
        try std.testing.expectEqualSlices(u8, &expected, &out);
    }

    {
        // This test case is brought from https://quic.xargs.org/
        const expected = [_]u8{ 0x47, 0xc6, 0xa6, 0x38, 0xd4, 0x96, 0x85, 0x95, 0xcc, 0x20, 0xb7, 0xc8, 0xbc, 0x5f, 0xbf, 0xbf, 0xd0, 0x2d, 0x7c, 0x17, 0xcc, 0x67, 0xfa, 0x54, 0x8c, 0x04, 0x3e, 0xcb, 0x54, 0x7b, 0x0e, 0xaa };
        const dcid = [_]u8{ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 };
        const initial_secret = HkdfSha256.extract(&INITIAL_SALT_V1, &dcid);
        var out = hkdfExpandLabel(initial_secret, "client in", "", Hmac.key_length);
        try std.testing.expectEqualSlices(u8, &expected, &out);
    }
}

test "AEAD key" {
    {
        // This test case is brought from https://www.rfc-editor.org/rfc/rfc9001#section-a.1
        const server_initial_secret = [_]u8{ 0x3c, 0x19, 0x98, 0x28, 0xfd, 0x13, 0x9e, 0xfd, 0x21, 0x6c, 0x15, 0x5a, 0xd8, 0x44, 0xcc, 0x81, 0xfb, 0x82, 0xfa, 0x8d, 0x74, 0x46, 0xfa, 0x7d, 0x78, 0xbe, 0x80, 0x3a, 0xcd, 0xda, 0x95, 0x1b };
        const expected = [_]u8{ 0xcf, 0x3a, 0x53, 0x31, 0x65, 0x3c, 0x36, 0x4c, 0x88, 0xf0, 0xf3, 0x79, 0xb6, 0x06, 0x7e, 0x37 };
        const out = hkdfExpandLabel(server_initial_secret, "quic key", "", key_len);
        try std.testing.expectEqualSlices(u8, &expected, &out);
    }
    {
        // This test case is brought from https://www.rfc-editor.org/rfc/rfc9001#section-a.1
        const client_initial_secret = [_]u8{ 0xc0, 0x0c, 0xf1, 0x51, 0xca, 0x5b, 0xe0, 0x75, 0xed, 0x0e, 0xbf, 0xb5, 0xc8, 0x03, 0x23, 0xc4, 0x2d, 0x6b, 0x7d, 0xb6, 0x78, 0x81, 0x28, 0x9a, 0xf4, 0x00, 0x8f, 0x1f, 0x6c, 0x35, 0x7a, 0xea };
        const expected = [_]u8{ 0x1f, 0x36, 0x96, 0x13, 0xdd, 0x76, 0xd5, 0x46, 0x77, 0x30, 0xef, 0xcb, 0xe3, 0xb1, 0xa2, 0x2d };
        const out = hkdfExpandLabel(client_initial_secret, "quic key", "", key_len);
        try std.testing.expectEqualSlices(u8, &expected, &out);
    }
    {
        const server_initial_secret = [_]u8{ 0xad, 0xc1, 0x99, 0x5b, 0x5c, 0xee, 0x8f, 0x03, 0x74, 0x6b, 0xf8, 0x30, 0x9d, 0x02, 0xd5, 0xea, 0x27, 0x15, 0x9c, 0x1e, 0xd6, 0x91, 0x54, 0x03, 0xb3, 0x63, 0x18, 0xd5, 0xa0, 0x3a, 0xfe, 0xb8 };
        const expected = [_]u8{ 0xd7, 0x7f, 0xc4, 0x05, 0x6f, 0xcf, 0xa3, 0x2b, 0xd1, 0x30, 0x24, 0x69, 0xee, 0x6e, 0xbf, 0x90 };
        const out = hkdfExpandLabel(server_initial_secret, "quic key", "", key_len);
        try std.testing.expectEqualSlices(u8, &expected, &out);
    }
    {
        // This test case is brought from https://quic.xargs.org/
        const client_initial_secret = [_]u8{ 0x47, 0xc6, 0xa6, 0x38, 0xd4, 0x96, 0x85, 0x95, 0xcc, 0x20, 0xb7, 0xc8, 0xbc, 0x5f, 0xbf, 0xbf, 0xd0, 0x2d, 0x7c, 0x17, 0xcc, 0x67, 0xfa, 0x54, 0x8c, 0x04, 0x3e, 0xcb, 0x54, 0x7b, 0x0e, 0xaa };
        const expected = [_]u8{ 0xb1, 0x4b, 0x91, 0x81, 0x24, 0xfd, 0xa5, 0xc8, 0xd7, 0x98, 0x47, 0x60, 0x2f, 0xa3, 0x52, 0x0b };
        const out = hkdfExpandLabel(client_initial_secret, "quic key", "", key_len);
        try std.testing.expectEqualSlices(u8, &expected, &out);
    }
}

test "IV (initialization vector)" {
    {
        // This test case is brought from https://www.rfc-editor.org/rfc/rfc9001#section-a.1
        const expected = [_]u8{ 0x0a, 0xc1, 0x49, 0x3c, 0xa1, 0x90, 0x58, 0x53, 0xb0, 0xbb, 0xa0, 0x3e };
        const server_initial_secret = [_]u8{ 0x3c, 0x19, 0x98, 0x28, 0xfd, 0x13, 0x9e, 0xfd, 0x21, 0x6c, 0x15, 0x5a, 0xd8, 0x44, 0xcc, 0x81, 0xfb, 0x82, 0xfa, 0x8d, 0x74, 0x46, 0xfa, 0x7d, 0x78, 0xbe, 0x80, 0x3a, 0xcd, 0xda, 0x95, 0x1b };
        const out = hkdfExpandLabel(server_initial_secret, "quic iv", "", nonce_len);
        try std.testing.expectEqualSlices(u8, &expected, &out);
    }
    {
        const expected = [_]u8{ 0xfa, 0x04, 0x4b, 0x2f, 0x42, 0xa3, 0xfd, 0x3b, 0x46, 0xfb, 0x25, 0x5c };
        const client_initial_secret = [_]u8{ 0xc0, 0x0c, 0xf1, 0x51, 0xca, 0x5b, 0xe0, 0x75, 0xed, 0x0e, 0xbf, 0xb5, 0xc8, 0x03, 0x23, 0xc4, 0x2d, 0x6b, 0x7d, 0xb6, 0x78, 0x81, 0x28, 0x9a, 0xf4, 0x00, 0x8f, 0x1f, 0x6c, 0x35, 0x7a, 0xea };
        const out = hkdfExpandLabel(client_initial_secret, "quic iv", "", nonce_len);
        try std.testing.expectEqualSlices(u8, &expected, &out);
    }
    {
        const expected = [_]u8{ 0xfc, 0xb7, 0x48, 0xe3, 0x7f, 0xf7, 0x98, 0x60, 0xfa, 0xa0, 0x74, 0x77 };
        const server_initial_secret = [_]u8{ 0xad, 0xc1, 0x99, 0x5b, 0x5c, 0xee, 0x8f, 0x03, 0x74, 0x6b, 0xf8, 0x30, 0x9d, 0x02, 0xd5, 0xea, 0x27, 0x15, 0x9c, 0x1e, 0xd6, 0x91, 0x54, 0x03, 0xb3, 0x63, 0x18, 0xd5, 0xa0, 0x3a, 0xfe, 0xb8 };
        const out = hkdfExpandLabel(server_initial_secret, "quic iv", "", nonce_len);
        try std.testing.expectEqualSlices(u8, &expected, &out);
    }
    {
        const expected = [_]u8{ 0xdd, 0xbc, 0x15, 0xde, 0xa8, 0x09, 0x25, 0xa5, 0x56, 0x86, 0xa7, 0xdf };
        const client_initial_secret = [_]u8{ 0x47, 0xc6, 0xa6, 0x38, 0xd4, 0x96, 0x85, 0x95, 0xcc, 0x20, 0xb7, 0xc8, 0xbc, 0x5f, 0xbf, 0xbf, 0xd0, 0x2d, 0x7c, 0x17, 0xcc, 0x67, 0xfa, 0x54, 0x8c, 0x04, 0x3e, 0xcb, 0x54, 0x7b, 0x0e, 0xaa };
        const out = hkdfExpandLabel(client_initial_secret, "quic iv", "", nonce_len);
        try std.testing.expectEqualSlices(u8, &expected, &out);
    }
}

test "header protection key" {
    {
        const expected = [_]u8{ 0xc2, 0x06, 0xb8, 0xd9, 0xb9, 0xf0, 0xf3, 0x76, 0x44, 0x43, 0x0b, 0x49, 0x0e, 0xea, 0xa3, 0x14 };
        const server_initial_secret = [_]u8{ 0x3c, 0x19, 0x98, 0x28, 0xfd, 0x13, 0x9e, 0xfd, 0x21, 0x6c, 0x15, 0x5a, 0xd8, 0x44, 0xcc, 0x81, 0xfb, 0x82, 0xfa, 0x8d, 0x74, 0x46, 0xfa, 0x7d, 0x78, 0xbe, 0x80, 0x3a, 0xcd, 0xda, 0x95, 0x1b };
        const out = hkdfExpandLabel(server_initial_secret, "quic hp", "", key_len);
        try std.testing.expectEqualSlices(u8, &expected, &out);
    }
    {
        const expected = [_]u8{ 0x9f, 0x50, 0x44, 0x9e, 0x04, 0xa0, 0xe8, 0x10, 0x28, 0x3a, 0x1e, 0x99, 0x33, 0xad, 0xed, 0xd2 };
        const client_initial_secret = [_]u8{ 0xc0, 0x0c, 0xf1, 0x51, 0xca, 0x5b, 0xe0, 0x75, 0xed, 0x0e, 0xbf, 0xb5, 0xc8, 0x03, 0x23, 0xc4, 0x2d, 0x6b, 0x7d, 0xb6, 0x78, 0x81, 0x28, 0x9a, 0xf4, 0x00, 0x8f, 0x1f, 0x6c, 0x35, 0x7a, 0xea };
        const out = hkdfExpandLabel(client_initial_secret, "quic hp", "", key_len);
        try std.testing.expectEqualSlices(u8, &expected, &out);
    }
    {
        const expected = [_]u8{ 0x44, 0x0b, 0x27, 0x25, 0xe9, 0x1d, 0xc7, 0x9b, 0x37, 0x07, 0x11, 0xef, 0x79, 0x2f, 0xaa, 0x3d };
        const server_initial_secret = [_]u8{ 0xad, 0xc1, 0x99, 0x5b, 0x5c, 0xee, 0x8f, 0x03, 0x74, 0x6b, 0xf8, 0x30, 0x9d, 0x02, 0xd5, 0xea, 0x27, 0x15, 0x9c, 0x1e, 0xd6, 0x91, 0x54, 0x03, 0xb3, 0x63, 0x18, 0xd5, 0xa0, 0x3a, 0xfe, 0xb8 };
        const out = hkdfExpandLabel(server_initial_secret, "quic hp", "", key_len);
        try std.testing.expectEqualSlices(u8, &expected, &out);
    }
    {
        const expected = [_]u8{ 0x6d, 0xf4, 0xe9, 0xd7, 0x37, 0xcd, 0xf7, 0x14, 0x71, 0x1d, 0x7c, 0x61, 0x7e, 0xe8, 0x29, 0x81 };
        const client_initial_secret = [_]u8{ 0x47, 0xc6, 0xa6, 0x38, 0xd4, 0x96, 0x85, 0x95, 0xcc, 0x20, 0xb7, 0xc8, 0xbc, 0x5f, 0xbf, 0xbf, 0xd0, 0x2d, 0x7c, 0x17, 0xcc, 0x67, 0xfa, 0x54, 0x8c, 0x04, 0x3e, 0xcb, 0x54, 0x7b, 0x0e, 0xaa };
        const out = hkdfExpandLabel(client_initial_secret, "quic hp", "", key_len);
        try std.testing.expectEqualSlices(u8, &expected, &out);
    }
}

/// Uses hkdf's expand to generate a derived key.
/// Constructs a hkdf context by generating a hkdf-label
/// which consists of `length`, the label "tls13 " ++ `label` and the given
/// `context`.
pub fn hkdfExpandLabel(
    secret: [32]u8,
    comptime label: []const u8,
    context: []const u8,
    comptime length: u16,
) [length]u8 {
    // return tls.hkdfExpandLabel(HkdfSha256, secret, label, context, length);

    std.debug.assert(label.len <= 255 and label.len > 0);
    std.debug.assert(context.len <= 255);
    const full_label = "tls13 " ++ label;

    // length, label, context
    var buf: [2 + 255 + 255]u8 = undefined;
    std.mem.writeInt(u16, buf[0..2], length, .big);
    buf[2] = full_label.len;
    @memcpy(buf[3..][0..full_label.len], full_label);
    buf[3 + full_label.len] = @intCast(context.len);
    @memcpy(buf[4 + full_label.len ..][0..context.len], context);
    const actual_context = buf[0 .. 4 + full_label.len + context.len];

    var out: [32]u8 = undefined;
    HkdfSha256.expand(&out, actual_context, secret);
    return out[0..length].*;
}

/// Runtime version of hkdfExpandLabel for version-dependent labels.
pub fn hkdfExpandLabelRuntime(
    secret: [32]u8,
    label: []const u8,
    context: []const u8,
    comptime length: u16,
) [length]u8 {
    std.debug.assert(label.len <= 249 and label.len > 0);
    std.debug.assert(context.len <= 255);

    var buf: [2 + 1 + 6 + 249 + 1 + 255]u8 = undefined;
    std.mem.writeInt(u16, buf[0..2], length, .big);
    // "tls13 " prefix (6 bytes) + label
    const prefix = "tls13 ";
    const full_len: u8 = @intCast(prefix.len + label.len);
    buf[2] = full_len;
    @memcpy(buf[3..][0..prefix.len], prefix);
    @memcpy(buf[3 + prefix.len ..][0..label.len], label);
    const label_end = 3 + prefix.len + label.len;
    buf[label_end] = @intCast(context.len);
    @memcpy(buf[label_end + 1 ..][0..context.len], context);
    const actual_context = buf[0 .. label_end + 1 + context.len];

    var out: [32]u8 = undefined;
    HkdfSha256.expand(&out, actual_context, secret);
    return out[0..length].*;
}

/// Derive a QUIC key and pad to max_key_len.
/// `actual_len` is the real key length (16 for AES, 32 for ChaCha20).
pub fn deriveKeyPaddedV(secret: [32]u8, actual_len: usize, version: u32) [max_key_len]u8 {
    return deriveKeyPaddedL(secret, actual_len, protocol.quicLabel(version, .key));
}

// Derive key with an explicit label string (runtime).
fn deriveKeyPaddedL(secret: [32]u8, actual_len: usize, label: []const u8) [max_key_len]u8 {
    var result: [max_key_len]u8 = .{0} ** max_key_len;
    if (actual_len == 32) {
        result = hkdfExpandLabelRuntime(secret, label, "", 32);
    } else {
        const k16 = hkdfExpandLabelRuntime(secret, label, "", 16);
        @memcpy(result[0..16], &k16);
    }
    return result;
}

pub fn deriveHpKeyPaddedV(secret: [32]u8, actual_len: usize, version: u32) [max_key_len]u8 {
    const label = protocol.quicLabel(version, .hp);
    var result: [max_key_len]u8 = .{0} ** max_key_len;
    if (actual_len == 32) {
        result = hkdfExpandLabelRuntime(secret, label, "", 32);
    } else {
        const k16 = hkdfExpandLabelRuntime(secret, label, "", 16);
        @memcpy(result[0..16], &k16);
    }
    return result;
}

/// AES-128-GCM confidentiality limit: 2^23 packets (~8M).
/// After this many packets, keys must be rotated to maintain security.
pub const CONFIDENTIALITY_LIMIT: u64 = 1 << 23;

/// Derive the next traffic secret for key update.
/// RFC 9001 Section 6.1:
///   secret_<n+1> = HKDF-Expand-Label(secret_<n>, "quic ku", "", 32)
pub fn deriveNextTrafficSecret(current: [32]u8) [32]u8 {
    return deriveNextTrafficSecretV(current, protocol.QUIC_V1);
}

pub fn deriveNextTrafficSecretV(current: [32]u8, version: u32) [32]u8 {
    return hkdfExpandLabelRuntime(current, protocol.quicLabel(version, .ku), "", 32);
}

/// Manages QUIC key update (RFC 9001 Section 6).
///
/// Holds three generations of keys (previous/current/next) to handle
/// packet reordering during key transitions. The header protection key
/// never changes across updates (RFC 9001 Section 6.6).
pub const KeyUpdateManager = struct {
    // Current keys for decrypt/encrypt
    current_open: Open,
    current_seal: Seal,

    // Previous open keys for decrypting reordered packets from the prior generation
    prev_open: ?Open = null,

    // Pre-computed next keys for fast key update processing
    next_open: Open,
    next_seal: Seal,

    // Current key phase bit (toggled on each update)
    key_phase: bool = false,

    // Header protection keys (never change across updates)
    hp_open: [max_key_len]u8,
    hp_seal: [max_key_len]u8,

    // Cipher suite for this key generation
    cipher_suite: CipherSuite = .aes_128_gcm_sha256,

    // QUIC version (affects HKDF labels: "quic ku" vs "quicv2 ku")
    version: u32 = protocol.QUIC_V1,

    // Traffic secrets for deriving next-generation keys
    recv_secret: [32]u8,
    send_secret: [32]u8,

    // Timestamp when previous keys expire (now + 3×PTO)
    prev_open_expires: ?i64 = null,

    // Packet number of first packet sent with current keys
    first_sent_with_current: ?u64 = null,

    // Whether a packet sent with current keys has been ACKed
    first_acked_with_current: bool = false,

    // Number of packets sent with current keys
    packets_sent_with_current: u64 = 0,

    /// Initialize the key update manager from initial traffic secrets.
    /// `recv_secret` is the peer's traffic secret (for decryption).
    /// `send_secret` is our traffic secret (for encryption).
    pub fn init(recv_secret: [32]u8, send_secret: [32]u8, recv_hp: [max_key_len]u8, send_hp: [max_key_len]u8) KeyUpdateManager {
        return initWithCipherSuite(recv_secret, send_secret, recv_hp, send_hp, .aes_128_gcm_sha256);
    }

    pub fn initWithCipherSuite(recv_secret: [32]u8, send_secret: [32]u8, recv_hp: [max_key_len]u8, send_hp: [max_key_len]u8, cipher_suite: CipherSuite) KeyUpdateManager {
        return initFull(recv_secret, send_secret, recv_hp, send_hp, cipher_suite, protocol.QUIC_V1);
    }

    pub fn initFull(recv_secret: [32]u8, send_secret: [32]u8, recv_hp: [max_key_len]u8, send_hp: [max_key_len]u8, cipher_suite: CipherSuite, version: u32) KeyUpdateManager {
        const kl = cipher_suite.keyLen();
        const label_key = protocol.quicLabel(version, .key);
        const label_iv = protocol.quicLabel(version, .iv);

        // Derive current Open/Seal from the initial secrets
        const recv_key = deriveKeyPaddedL(recv_secret, kl, label_key);
        const recv_iv = hkdfExpandLabelRuntime(recv_secret, label_iv, "", nonce_len);
        const send_key = deriveKeyPaddedL(send_secret, kl, label_key);
        const send_iv = hkdfExpandLabelRuntime(send_secret, label_iv, "", nonce_len);

        // Pre-compute next generation secrets and keys
        const next_recv_secret = deriveNextTrafficSecretV(recv_secret, version);
        const next_send_secret = deriveNextTrafficSecretV(send_secret, version);
        const next_recv_key = deriveKeyPaddedL(next_recv_secret, kl, label_key);
        const next_recv_iv = hkdfExpandLabelRuntime(next_recv_secret, label_iv, "", nonce_len);
        const next_send_key = deriveKeyPaddedL(next_send_secret, kl, label_key);
        const next_send_iv = hkdfExpandLabelRuntime(next_send_secret, label_iv, "", nonce_len);

        return .{
            .current_open = .{ .key = recv_key, .hp_key = recv_hp, .nonce = recv_iv, .cipher_suite = cipher_suite },
            .current_seal = .{ .key = send_key, .hp_key = send_hp, .nonce = send_iv, .cipher_suite = cipher_suite },
            .next_open = .{ .key = next_recv_key, .hp_key = recv_hp, .nonce = next_recv_iv, .cipher_suite = cipher_suite },
            .next_seal = .{ .key = next_send_key, .hp_key = send_hp, .nonce = next_send_iv, .cipher_suite = cipher_suite },
            .hp_open = recv_hp,
            .hp_seal = send_hp,
            .cipher_suite = cipher_suite,
            .version = version,
            .recv_secret = recv_secret,
            .send_secret = send_secret,
        };
    }

    /// Rotate keys: prev←current, current←next, pre-compute new next.
    /// Toggles the key phase bit. Sets prev_open expiry to now + 3×PTO.
    pub fn rollKeys(self: *KeyUpdateManager, now: i64, pto_ns: i64) void {
        // Move current → previous
        self.prev_open = self.current_open;
        self.prev_open_expires = now + 3 * pto_ns;

        // Move next → current
        self.current_open = self.next_open;
        self.current_seal = self.next_seal;

        // Advance secrets (version-aware labels)
        self.recv_secret = deriveNextTrafficSecretV(self.recv_secret, self.version);
        self.send_secret = deriveNextTrafficSecretV(self.send_secret, self.version);

        // Pre-compute new next-generation keys
        const kl = self.cipher_suite.keyLen();
        const label_key = protocol.quicLabel(self.version, .key);
        const label_iv = protocol.quicLabel(self.version, .iv);
        const next_recv_secret = deriveNextTrafficSecretV(self.recv_secret, self.version);
        const next_send_secret = deriveNextTrafficSecretV(self.send_secret, self.version);
        self.next_open = .{
            .key = deriveKeyPaddedL(next_recv_secret, kl, label_key),
            .hp_key = self.hp_open,
            .nonce = hkdfExpandLabelRuntime(next_recv_secret, label_iv, "", nonce_len),
            .cipher_suite = self.cipher_suite,
        };
        self.next_seal = .{
            .key = deriveKeyPaddedL(next_send_secret, kl, label_key),
            .hp_key = self.hp_seal,
            .nonce = hkdfExpandLabelRuntime(next_send_secret, label_iv, "", nonce_len),
            .cipher_suite = self.cipher_suite,
        };

        // Toggle key phase
        self.key_phase = !self.key_phase;

        // Reset tracking for the new generation
        self.first_sent_with_current = null;
        self.first_acked_with_current = false;
        self.packets_sent_with_current = 0;
    }

    /// Get the Open keys for decrypting a packet based on its key phase bit.
    /// Returns null if the key phase doesn't match any available generation.
    pub fn getOpenKeys(self: *KeyUpdateManager, key_phase_bit: bool) ?*Open {
        if (key_phase_bit == self.key_phase) {
            return &self.current_open;
        }
        // Key phase differs from current:
        // 1. If prev_open exists → reordered packet from previous generation
        // 2. Otherwise → peer-initiated key update, use next_open (RFC 9001 §6.1)
        if (self.prev_open != null) {
            return &self.prev_open.?;
        }
        return &self.next_open;
    }

    /// Get the current Seal keys and key phase bit for encrypting a packet.
    pub fn getSealAndPhase(self: *KeyUpdateManager) struct { seal: *const Seal, key_phase: bool } {
        return .{ .seal = &self.current_seal, .key_phase = self.key_phase };
    }

    /// Record that a packet was sent with current keys.
    pub fn onPacketSent(self: *KeyUpdateManager, pn: u64) void {
        if (self.first_sent_with_current == null) {
            self.first_sent_with_current = pn;
        }
        self.packets_sent_with_current += 1;
    }

    /// Drop previous-generation keys if they have expired.
    pub fn maybeDropPrevKeys(self: *KeyUpdateManager, now: i64) void {
        if (self.prev_open_expires) |expires| {
            if (now >= expires) {
                self.prev_open = null;
                self.prev_open_expires = null;
            }
        }
    }

    /// Check if we should proactively initiate a key update.
    /// Returns true if packets sent with current keys >= confidentiality limit.
    pub fn shouldInitiateUpdate(self: *const KeyUpdateManager) bool {
        return self.packets_sent_with_current >= self.cipher_suite.confidentialityLimit();
    }

    /// Check if we are allowed to initiate a key update.
    /// Must have sent and received ACK for a packet with current keys.
    pub fn canUpdate(self: *const KeyUpdateManager) bool {
        return self.first_acked_with_current;
    }
};

// Key update tests
test "deriveNextTrafficSecret produces different secret" {
    const initial_secret = [_]u8{
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
    };
    const next = deriveNextTrafficSecret(initial_secret);

    // Next secret must differ from original
    try std.testing.expect(!std.mem.eql(u8, &initial_secret, &next));

    // Deterministic: same input → same output
    const next2 = deriveNextTrafficSecret(initial_secret);
    try std.testing.expectEqualSlices(u8, &next, &next2);

    // Chaining: deriving again gives a third distinct secret
    const next3 = deriveNextTrafficSecret(next);
    try std.testing.expect(!std.mem.eql(u8, &next, &next3));
    try std.testing.expect(!std.mem.eql(u8, &initial_secret, &next3));
}

test "KeyUpdateManager: init and basic operations" {
    const recv_secret = [_]u8{0xAA} ** 32;
    const send_secret = [_]u8{0xBB} ** 32;
    const recv_hp = [_]u8{0xCC} ** max_key_len;
    const send_hp = [_]u8{0xDD} ** max_key_len;

    var mgr = KeyUpdateManager.init(recv_secret, send_secret, recv_hp, send_hp);

    // Initial key phase is false
    try std.testing.expect(!mgr.key_phase);

    // Current keys should match key phase
    const open = mgr.getOpenKeys(false);
    try std.testing.expect(open != null);

    // Get seal should return current seal and phase
    const seal_info = mgr.getSealAndPhase();
    try std.testing.expect(!seal_info.key_phase);

    // HP keys should match
    try std.testing.expectEqualSlices(u8, &recv_hp, &mgr.hp_open);
    try std.testing.expectEqualSlices(u8, &send_hp, &mgr.hp_seal);

    // Should not initiate update yet (0 packets sent)
    try std.testing.expect(!mgr.shouldInitiateUpdate());
    try std.testing.expect(!mgr.canUpdate());
}

test "KeyUpdateManager: roll keys" {
    const recv_secret = [_]u8{0xAA} ** 32;
    const send_secret = [_]u8{0xBB} ** 32;
    const recv_hp = [_]u8{0xCC} ** max_key_len;
    const send_hp = [_]u8{0xDD} ** max_key_len;

    var mgr = KeyUpdateManager.init(recv_secret, send_secret, recv_hp, send_hp);
    const orig_open_key = mgr.current_open.key;
    const orig_seal_key = mgr.current_seal.key;

    // Roll keys
    const now: i64 = 1_000_000_000;
    const pto: i64 = 100_000_000; // 100ms
    mgr.rollKeys(now, pto);

    // Key phase should toggle
    try std.testing.expect(mgr.key_phase);

    // Current keys should be different
    try std.testing.expect(!std.mem.eql(u8, &orig_open_key, &mgr.current_open.key));
    try std.testing.expect(!std.mem.eql(u8, &orig_seal_key, &mgr.current_seal.key));

    // Previous open should exist
    try std.testing.expect(mgr.prev_open != null);
    try std.testing.expectEqualSlices(u8, &orig_open_key, &mgr.prev_open.?.key);

    // Previous should expire at now + 3*PTO
    try std.testing.expectEqual(now + 3 * pto, mgr.prev_open_expires.?);

    // HP keys should not change
    try std.testing.expectEqualSlices(u8, &recv_hp, &mgr.current_open.hp_key);
    try std.testing.expectEqualSlices(u8, &send_hp, &mgr.current_seal.hp_key);

    // Counters should be reset
    try std.testing.expect(mgr.first_sent_with_current == null);
    try std.testing.expect(!mgr.first_acked_with_current);
    try std.testing.expectEqual(@as(u64, 0), mgr.packets_sent_with_current);
}

test "KeyUpdateManager: prev key expiry" {
    const recv_secret = [_]u8{0xAA} ** 32;
    const send_secret = [_]u8{0xBB} ** 32;
    const recv_hp = [_]u8{0xCC} ** max_key_len;
    const send_hp = [_]u8{0xDD} ** max_key_len;

    var mgr = KeyUpdateManager.init(recv_secret, send_secret, recv_hp, send_hp);

    const now: i64 = 1_000_000_000;
    const pto: i64 = 100_000_000;
    mgr.rollKeys(now, pto);

    // Before expiry: prev keys should exist
    mgr.maybeDropPrevKeys(now + 2 * pto);
    try std.testing.expect(mgr.prev_open != null);

    // After expiry: prev keys should be dropped
    mgr.maybeDropPrevKeys(now + 3 * pto);
    try std.testing.expect(mgr.prev_open == null);
    try std.testing.expect(mgr.prev_open_expires == null);
}

test "KeyUpdateManager: encrypt/decrypt roundtrip across key update" {
    // Simulate two sides: client and server with swapped secrets
    const client_recv = [_]u8{0x11} ** 32; // = server_send
    const client_send = [_]u8{0x22} ** 32; // = server_recv
    const hp_a = [_]u8{0x33} ** max_key_len;
    const hp_b = [_]u8{0x44} ** max_key_len;

    var client = KeyUpdateManager.init(client_recv, client_send, hp_a, hp_b);
    var server = KeyUpdateManager.init(client_send, client_recv, hp_b, hp_a);

    // Client encrypts, server decrypts (generation 0)
    const plaintext = "hello key update";
    const ad = "associated data";
    var ciphertext: [plaintext.len + Aead.tag_length]u8 = undefined;
    _ = client.current_seal.encryptPayload(0, ad, plaintext, &ciphertext);

    const open_keys = server.getOpenKeys(false).?;
    const decrypted = try open_keys.decryptPayload(0, ad, &ciphertext);
    try std.testing.expectEqualStrings(plaintext, decrypted);

    // Roll both sides
    client.rollKeys(1_000_000_000, 100_000_000);
    server.rollKeys(1_000_000_000, 100_000_000);

    // Client encrypts with new keys, server decrypts (generation 1)
    var ciphertext2: [plaintext.len + Aead.tag_length]u8 = undefined;
    _ = client.current_seal.encryptPayload(1, ad, plaintext, &ciphertext2);

    const open_keys2 = server.getOpenKeys(true).?;
    const decrypted2 = try open_keys2.decryptPayload(1, ad, &ciphertext2);
    try std.testing.expectEqualStrings(plaintext, decrypted2);
}

test "Seal/Open encrypt/decrypt roundtrip" {
    const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const keys = try deriveInitialKeyMaterial(&dcid, 0x00000001, true);
    _ = keys[0]; // client keys (we're server, so we open client packets)
    const seal_key = keys[1]; // server keys (we seal server packets)

    // Encrypt a payload
    const plaintext = "Hello QUIC";
    const ad = "associated_data";
    const pn: u64 = 42;
    var ciphertext: [plaintext.len + Aead.tag_length]u8 = undefined;
    const enc_len = seal_key.encryptPayload(pn, ad, plaintext, &ciphertext);
    try std.testing.expectEqual(plaintext.len + Aead.tag_length, enc_len);

    // Verify ciphertext differs from plaintext
    try std.testing.expect(!std.mem.eql(u8, plaintext, ciphertext[0..plaintext.len]));

    // Decrypt - need to use Open with the server's keys
    // Derive server's open keys (from client perspective)
    const client_keys = try deriveInitialKeyMaterial(&dcid, 0x00000001, false);
    var client_open = client_keys[0]; // server keys opened by client
    const decrypted = try client_open.decryptPayload(pn, ad, &ciphertext);
    try std.testing.expectEqualStrings(plaintext, decrypted);
}

test "header protection roundtrip" {
    const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const server_keys = try deriveInitialKeyMaterial(&dcid, 0x00000001, true);
    const seal_key = server_keys[1]; // server seal (server's hp_key)
    // Client opens server packets using the same server hp_key
    const client_keys = try deriveInitialKeyMaterial(&dcid, 0x00000001, false);
    const open_key = client_keys[0]; // client open = server keys

    // Simulate a packet: long header byte + some header + 4-byte pn + 20 bytes of "encrypted payload"
    var pkt: [40]u8 = undefined;
    pkt[0] = 0xC3; // long header, Initial, pn_len=4 (first_byte & 0x03 = 3, means 4 bytes)
    // Fill header bytes 1..6
    for (1..6) |i| pkt[i] = @intCast(i);
    // pn at offset 6
    const pn_offset: usize = 6;
    const pn_len: usize = 4;
    std.mem.writeInt(u32, pkt[pn_offset..][0..4], 0x00000002, .big);
    // Fill "ciphertext" with non-zero data so the sample is not all zeros
    for (pkt[pn_offset + pn_len ..]) |*b| b.* = 0xAB;

    // Save original first byte and pn bytes
    const orig_first = pkt[0];
    var orig_pn: [4]u8 = undefined;
    @memcpy(&orig_pn, pkt[pn_offset..][0..4]);

    // Apply header protection
    applyHeaderProtection(&pkt, pn_offset, pn_len, seal_key.hp_key, seal_key.cipher_suite);

    // Verify something changed
    try std.testing.expect(pkt[0] != orig_first or !std.mem.eql(u8, &orig_pn, pkt[pn_offset..][0..4]));

    // Remove header protection
    const recovered_pn_len = removeHeaderProtection(&pkt, pn_offset, open_key.hp_key, open_key.cipher_suite);
    try std.testing.expectEqual(pn_len, recovered_pn_len);

    // Verify we got back the original values
    try std.testing.expectEqual(orig_first, pkt[0]);
    try std.testing.expectEqualSlices(u8, &orig_pn, pkt[pn_offset..][0..4]);
}

test "encodePacketNumber" {
    var out: [4]u8 = undefined;

    // First packet, no acked: pn=0
    try std.testing.expectEqual(@as(usize, 1), encodePacketNumber(0, null, &out));
    try std.testing.expectEqual(@as(u8, 0), out[0]);

    // pn=1, largest_acked=0: num_unacked=1, need 8 bits
    try std.testing.expectEqual(@as(usize, 1), encodePacketNumber(1, 0, &out));
    try std.testing.expectEqual(@as(u8, 1), out[0]);

    // pn=256, largest_acked=200: num_unacked=56, 2*56=112 fits in 8 bits
    try std.testing.expectEqual(@as(usize, 1), encodePacketNumber(256, 200, &out));

    // pn=300, largest_acked=0: num_unacked=300, 2*300=600 needs >8 bits → 16 bits
    try std.testing.expectEqual(@as(usize, 2), encodePacketNumber(300, 0, &out));
}

test "hkdfExpandLabel" {
    const early_secret = HkdfSha256.extract(&.{}, &[_]u8{0} ** 32);
    var empty_hash: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash("", &empty_hash, .{});
    const derived_secret = hkdfExpandLabel(early_secret, "derived", &empty_hash, 32);
    try std.testing.expectEqualSlices(u8, &.{
        0x6f, 0x26, 0x15, 0xa1, 0x08, 0xc7, 0x02,
        0xc5, 0x67, 0x8f, 0x54, 0xfc, 0x9d, 0xba,
        0xb6, 0x97, 0x16, 0xc0, 0x76, 0x18, 0x9c,
        0x48, 0x25, 0x0c, 0xeb, 0xea, 0xc3, 0x57,
        0x6c, 0x36, 0x11, 0xba,
    }, &derived_secret);
}

// RFC 9001 Appendix A.2: Client Initial packet protection test.
// Verifies full packet protection pipeline (AEAD + header protection)
// produces output consistent with the known test vectors.
test "RFC 9001 A.2: Client Initial packet protection" {
    const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };

    // Derive client keys (from client perspective: is_server=false means client seals with client keys)
    const keys = try deriveInitialKeyMaterial(&dcid, 0x00000001, false);
    const seal = keys[1]; // client seal keys

    // Verify derived keys match RFC 9001 A.1 (AES-128-GCM: 16-byte keys padded to 32)
    try std.testing.expectEqualSlices(u8, &[_]u8{
        0x1f, 0x36, 0x96, 0x13, 0xdd, 0x76, 0xd5, 0x46,
        0x77, 0x30, 0xef, 0xcb, 0xe3, 0xb1, 0xa2, 0x2d,
    }, seal.key[0..16]);
    try std.testing.expectEqualSlices(u8, &[_]u8{
        0xfa, 0x04, 0x4b, 0x2f, 0x42, 0xa3, 0xfd, 0x3b,
        0x46, 0xfb, 0x25, 0x5c,
    }, &seal.nonce);
    try std.testing.expectEqualSlices(u8, &[_]u8{
        0x9f, 0x50, 0x44, 0x9e, 0x04, 0xa0, 0xe8, 0x10,
        0x28, 0x3a, 0x1e, 0x99, 0x33, 0xad, 0xed, 0xd2,
    }, seal.hp_key[0..16]);

    // Build the Client Initial header (RFC 9001 A.2)
    // First byte: 0xc0 (long header, Initial type, 0-length pn encoding)
    // But we'll set pn_len=4, so first byte = 0xC3
    // Version: 0x00000001
    // DCID len: 0x08, DCID: 8394c8f03e515708
    // SCID len: 0x00
    // Token len: 0x00
    // Payload length: varint (includes pn + payload + tag)
    var pkt_buf: [1200]u8 = undefined;
    var pos: usize = 0;

    // First byte (will be modified by header protection later)
    pkt_buf[0] = 0xc0 | 0x03; // Long header, Initial, pn_len=4
    pos = 1;

    // Version
    std.mem.writeInt(u32, pkt_buf[pos..][0..4], 0x00000001, .big);
    pos += 4;

    // DCID
    pkt_buf[pos] = 0x08;
    pos += 1;
    @memcpy(pkt_buf[pos..][0..8], &dcid);
    pos += 8;

    // SCID (empty)
    pkt_buf[pos] = 0x00;
    pos += 1;

    // Token (empty)
    pkt_buf[pos] = 0x00;
    pos += 1;

    // Payload length placeholder - the RFC uses a specific 2-byte varint
    const length_offset = pos;
    pos += 2; // will fill in after we know the sizes

    // Packet number offset
    const pn_offset = pos;

    // Packet number = 2, encoded as 4 bytes
    std.mem.writeInt(u32, pkt_buf[pos..][0..4], 0x00000002, .big);
    pos += 4;

    const payload_start = pos;

    // Plaintext payload: CRYPTO frame with ClientHello + padding
    // The CRYPTO frame starts with: 06 00 40 f1 (type=0x06, offset=0, length=0x40f1=241)
    const crypto_frame_header = [_]u8{ 0x06, 0x00, 0x40, 0xf1 };
    @memcpy(pkt_buf[pos..][0..crypto_frame_header.len], &crypto_frame_header);
    pos += crypto_frame_header.len;

    // ClientHello data (241 bytes from the RFC)
    const client_hello = [_]u8{
        0x01, 0x00, 0x00, 0xed, 0x03, 0x03, 0xeb, 0xf8,
        0xfa, 0x56, 0xf1, 0x29, 0x39, 0xb9, 0x58, 0x4a,
        0x38, 0x96, 0x47, 0x2e, 0xc4, 0x0b, 0xb8, 0x63,
        0xcf, 0xd3, 0xe8, 0x68, 0x04, 0xfe, 0x3a, 0x47,
        0xf0, 0x6a, 0x2b, 0x69, 0x48, 0x4c, 0x00, 0x00,
        0x04, 0x13, 0x01, 0x13, 0x02, 0x01, 0x00, 0x00,
        0xc0, 0x00, 0x00, 0x00, 0x10, 0x00, 0x0e, 0x00,
        0x00, 0x0b, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c,
        0x65, 0x2e, 0x63, 0x6f, 0x6d, 0xff, 0x01, 0x00,
        0x01, 0x00, 0x00, 0x0a, 0x00, 0x08, 0x00, 0x06,
        0x00, 0x1d, 0x00, 0x17, 0x00, 0x18, 0x00, 0x10,
        0x00, 0x07, 0x00, 0x05, 0x04, 0x61, 0x6c, 0x70,
        0x6e, 0x00, 0x05, 0x00, 0x05, 0x01, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x33, 0x00, 0x26, 0x00, 0x24,
        0x00, 0x1d, 0x00, 0x20, 0x93, 0x70, 0xb2, 0xc9,
        0xca, 0xa4, 0x7f, 0xba, 0xba, 0xf4, 0x55, 0x9f,
        0xed, 0xba, 0x75, 0x3d, 0xe1, 0x71, 0xfa, 0x71,
        0xf5, 0x0f, 0x1c, 0xe1, 0x5d, 0x43, 0xe9, 0x94,
        0xec, 0x74, 0xd7, 0x48, 0x00, 0x2b, 0x00, 0x03,
        0x02, 0x03, 0x04, 0x00, 0x0d, 0x00, 0x10, 0x00,
        0x0e, 0x04, 0x03, 0x05, 0x03, 0x06, 0x03, 0x02,
        0x03, 0x08, 0x04, 0x08, 0x05, 0x08, 0x06, 0x00,
        0x2d, 0x00, 0x02, 0x01, 0x01, 0x00, 0x1c, 0x00,
        0x02, 0x40, 0x01, 0x00, 0x39, 0x00, 0x32, 0x04,
        0x08, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x05, 0x04, 0x80, 0x00, 0xff, 0xff, 0x07,
        0x04, 0x80, 0x00, 0xff, 0xff, 0x08, 0x01, 0x10,
        0x01, 0x04, 0x80, 0x00, 0x75, 0x30, 0x09, 0x01,
        0x10, 0x0f, 0x08, 0x83, 0x94, 0xc8, 0xf0, 0x3e,
        0x51, 0x57, 0x08, 0x06, 0x04, 0x80, 0x00, 0xff,
        0xff,
    };
    @memcpy(pkt_buf[pos..][0..client_hello.len], &client_hello);
    pos += client_hello.len;

    // Padding to fill to 1200 bytes total
    // Total = header + pn_len + plaintext + AEAD_tag = 1200
    const header_len = pn_offset; // bytes before pn
    const tag_len = Aead.tag_length; // 16
    const target_plaintext = 1200 - header_len - 4 - tag_len; // 4 = pn_len
    while (pos - payload_start < target_plaintext) {
        pkt_buf[pos] = 0x00; // PADDING frame
        pos += 1;
    }

    const plaintext = pkt_buf[payload_start..pos];

    // Fill in the payload length (2-byte varint)
    // Length = pn_len(4) + plaintext.len + tag_len(16)
    const payload_length: u16 = @intCast(4 + plaintext.len + tag_len);
    // 2-byte varint: set top 2 bits to 01
    std.mem.writeInt(u16, pkt_buf[length_offset..][0..2], payload_length | 0x4000, .big);

    // Associated data = everything from first byte up to and including packet number
    const ad = pkt_buf[0 .. pn_offset + 4];

    // Encrypt the payload
    var encrypted_payload: [1200]u8 = undefined;
    const enc_len = seal.encryptPayload(2, ad, plaintext, &encrypted_payload);
    try std.testing.expectEqual(plaintext.len + tag_len, enc_len);

    // Copy encrypted payload back into packet
    @memcpy(pkt_buf[payload_start..][0..enc_len], encrypted_payload[0..enc_len]);
    const total_len = payload_start + enc_len;

    // Apply header protection
    applyHeaderProtection(pkt_buf[0..total_len], pn_offset, 4, seal.hp_key, seal.cipher_suite);

    // Verify the first few bytes of the protected packet match the RFC output
    // RFC 9001 A.2 encrypted packet starts with: c000000001088394c8f03e5157080000
    // First byte after protection should have been XORed with mask
    try std.testing.expectEqual(@as(usize, 1200), total_len);

    // Verify the version, DCID are still readable (not encrypted, not protected)
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x00, 0x00, 0x00, 0x01 }, pkt_buf[1..5]);
    try std.testing.expectEqual(@as(u8, 0x08), pkt_buf[5]); // DCID len
    try std.testing.expectEqualSlices(u8, &dcid, pkt_buf[6..14]);

    // Now decrypt it (server-side: is_server=true gives Open=client keys)
    const server_keys = try deriveInitialKeyMaterial(&dcid, 0x00000001, true);
    var server_open = server_keys[0]; // opens client packets

    // Remove header protection
    const recovered_pn_len = removeHeaderProtection(pkt_buf[0..total_len], pn_offset, server_open.hp_key, server_open.cipher_suite);
    try std.testing.expectEqual(@as(usize, 4), recovered_pn_len);

    // Read packet number
    const recovered_pn = std.mem.readInt(u32, pkt_buf[pn_offset..][0..4], .big);
    try std.testing.expectEqual(@as(u32, 2), recovered_pn);

    // Decrypt the payload
    const server_ad = pkt_buf[0 .. pn_offset + 4]; // decrypted header as AD
    const decrypted = try server_open.decryptPayload(
        2,
        server_ad,
        pkt_buf[payload_start..total_len],
    );

    // Verify the decrypted payload starts with the CRYPTO frame
    try std.testing.expectEqualSlices(u8, &crypto_frame_header, decrypted[0..4]);
    // And contains the ClientHello
    try std.testing.expectEqualSlices(u8, client_hello[0..16], decrypted[4..20]);
}
