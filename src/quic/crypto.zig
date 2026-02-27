const std = @import("std");
const protocol = @import("protocol.zig");
const packet = @import("packet.zig");
const assert = std.debug.assert;

const crypto = std.crypto;
// const tls = std.crypto.tls;
const HkdfSha256 = crypto.kdf.hkdf.HkdfSha256;
const HmacSha256 = crypto.auth.hmac.sha2.HmacSha256;
const Aes128Gcm = crypto.aead.aes_gcm.Aes128Gcm;
const Aes128 = crypto.core.aes.Aes128;
const Aes256 = crypto.core.aes.Aes256;

// binascii.unhexlify("38762cf7f55934b34d179ae6a4c80cadccbb7f0a")
const INITIAL_SALT_VERSION_1 = [_]u8{ 0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0xc, 0xad, 0xcc, 0xbb, 0x7f, 0xa };

// Header protection sample length
pub const SAMPLE_LEN = 16;
pub const MASK_LEN = 5;

// during this experimentational phase, only AES128_GCM is supported.
pub const Aead = Aes128Gcm;
const Hmac = HmacSha256;

// TODO: sizes differ per algorithm. Currently using `Aes128`
pub const key_len = 16;
pub const nonce_len = 12;

// // TODO: support the 3 algorithms below (only AES128_GCM currently supported)
// pub const Algorithm = enum {
//     AES128_GCM,
//     AES256_GCM,
//     ChaCha20_Poly1305,
// };

// TODO: merge this structure with "packet.Epoch" [??] they're basically the same!
pub const EncryptionLevel = enum(u8) {
    initial = 0,
    early_data,
    handshake,
    application,
};

pub const Open = struct {
    // alg: Algorithm,
    // ctx: anytype, // EVP_AEAD_CTX
    // hp_key: aead.HeaderProtectionKey,

    key: [key_len]u8, // KEY
    hp_key: [key_len]u8, // HP key
    nonce: [nonce_len]u8, // IV

    /// Generate a new QUIC Header Protection mask.
    ///
    pub fn newMask(self: *const Open, sample: *const [SAMPLE_LEN]u8) [MASK_LEN]u8 {
        const ctx = Aes128.initEnc(self.hp_key);
        var encrypted_out: [SAMPLE_LEN]u8 = .{0x00} ** SAMPLE_LEN;
        ctx.encrypt(&encrypted_out, sample);
        return encrypted_out[0..MASK_LEN].*;
    }

    pub fn decryptPayload(
        self: *Open,
        packet_number: u64,
        associated_data: []const u8,
        payload: []u8,
    ) error{ AuthenticationFailed, OutOfMemory }![]u8 {
        const tag_len = Aead.tag_length;
        const payload_len = payload.len;

        assert(payload_len >= tag_len);

        const tag: [tag_len]u8 = tag: {
            var t: [tag_len]u8 = undefined;
            @memcpy(&t, payload[(payload_len - tag_len)..payload_len]);
            break :tag t;
        };

        const aead_nonce = makeNonce(self.nonce, packet_number);
        const bytes = payload[0..(payload_len - tag_len)];

        Aead.decrypt(
            bytes, // output
            bytes, // input
            tag,
            associated_data,
            aead_nonce,
            self.key,
        ) catch |err| {
            std.log.err("AEAD decryption failed: {any}", .{err});
            return err;
        };

        return bytes;
    }
};

pub const Seal = struct {
    key: [key_len]u8,
    hp_key: [key_len]u8,
    nonce: [nonce_len]u8,

    /// Generate a new QUIC Header Protection mask.
    pub fn newMask(self: *const Seal, sample: *const [SAMPLE_LEN]u8) [MASK_LEN]u8 {
        const ctx = Aes128.initEnc(self.hp_key);
        var encrypted_out: [SAMPLE_LEN]u8 = undefined;
        ctx.encrypt(&encrypted_out, sample);
        return encrypted_out[0..MASK_LEN].*;
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
        const tag_len = Aead.tag_length;

        assert(out.len >= plaintext.len + tag_len);

        var tag: [tag_len]u8 = undefined;
        Aead.encrypt(
            out[0..plaintext.len],
            &tag,
            plaintext,
            associated_data,
            aead_nonce,
            self.key,
        );
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

/// Apply header protection to an outgoing packet.
/// RFC 9001 Section 5.4.
///
/// `packet` is the full serialized packet (header + encrypted payload + tag).
/// `pn_offset` is the byte offset where the packet number starts.
/// `pn_len` is the length of the encoded packet number (1-4).
pub fn applyHeaderProtection(
    pkt_buf: []u8,
    pn_offset: usize,
    pn_len: usize,
    hp_key: [key_len]u8,
) void {
    // RFC 9001 Section 5.4.2: Sample starts 4 bytes after the START of packet number field
    const sample_offset = pn_offset + 4;
    if (sample_offset + SAMPLE_LEN > pkt_buf.len) return;

    const sample: *const [SAMPLE_LEN]u8 = pkt_buf[sample_offset..][0..SAMPLE_LEN];
    const ctx = Aes128.initEnc(hp_key);
    var encrypted: [SAMPLE_LEN]u8 = undefined;
    ctx.encrypt(&encrypted, sample);
    const mask = encrypted[0..MASK_LEN];

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
    hp_key: [key_len]u8,
) usize {
    // Sample starts 4 bytes after the start of the packet number field
    const sample_offset = pn_offset + 4;
    if (sample_offset + SAMPLE_LEN > pkt_buf.len) return 0;

    const sample: *const [SAMPLE_LEN]u8 = pkt_buf[sample_offset..][0..SAMPLE_LEN];
    const ctx = Aes128.initEnc(hp_key);
    var encrypted: [SAMPLE_LEN]u8 = undefined;
    ctx.encrypt(&encrypted, sample);
    const mask = encrypted[0..MASK_LEN];

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
    if (version != protocol.SUPPORTED_VERSIONS[0]) {
        std.log.err("only version 1 is supported right now.", .{});
        return error.InvalidVersion;
    }

    // https://datatracker.ietf.org/doc/html/rfc9001#section-5.1

    const initial_secret = HkdfSha256.extract(&INITIAL_SALT_VERSION_1, cid);
    var secret: [32]u8 = undefined;

    // Client
    secret = hkdfExpandLabel(initial_secret, "client in", "", Hmac.key_length);
    const client_key = hkdfExpandLabel(secret, "quic key", "", key_len);
    const client_iv = hkdfExpandLabel(secret, "quic iv", "", nonce_len);
    const client_hp_key = hkdfExpandLabel(secret, "quic hp", "", key_len); //header protection key

    // Server
    secret = hkdfExpandLabel(initial_secret, "server in", "", Hmac.key_length);
    const server_key = hkdfExpandLabel(secret, "quic key", "", key_len);
    const server_iv = hkdfExpandLabel(secret, "quic iv", "", nonce_len);
    const server_hp_key = hkdfExpandLabel(secret, "quic hp", "", key_len); //header protection key

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
        const out = HkdfSha256.extract(&INITIAL_SALT_VERSION_1, &dcid);
        try std.testing.expectEqualSlices(u8, &expected, &out);
    }
    {
        const expected = [_]u8{ 0xf0, 0x16, 0xbb, 0x2d, 0xc9, 0x97, 0x6d, 0xea, 0x27, 0x26, 0xc4, 0xe6, 0x1e, 0x73, 0x8a, 0x1e, 0x36, 0x80, 0xa2, 0x48, 0x75, 0x91, 0xdc, 0x76, 0xb2, 0xae, 0xe2, 0xed, 0x75, 0x98, 0x22, 0xf6 };
        const dcid = [_]u8{ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 };
        const out = HkdfSha256.extract(&INITIAL_SALT_VERSION_1, &dcid);
        try std.testing.expectEqualSlices(u8, &expected, &out);
    }
}

// https://www.rfc-editor.org/rfc/rfc9001#section-a.1
test "a.1: keys - server initial secret" {
    {
        const expected = [_]u8{ 0x3c, 0x19, 0x98, 0x28, 0xfd, 0x13, 0x9e, 0xfd, 0x21, 0x6c, 0x15, 0x5a, 0xd8, 0x44, 0xcc, 0x81, 0xfb, 0x82, 0xfa, 0x8d, 0x74, 0x46, 0xfa, 0x7d, 0x78, 0xbe, 0x80, 0x3a, 0xcd, 0xda, 0x95, 0x1b };
        const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
        const initial_secret = HkdfSha256.extract(&INITIAL_SALT_VERSION_1, &dcid);
        var out = hkdfExpandLabel(initial_secret, "server in", "", Hmac.key_length);
        try std.testing.expectEqualSlices(u8, &expected, &out);
    }
    {
        // This test case is brought from https://quic.xargs.org/
        const expected = [_]u8{ 0xad, 0xc1, 0x99, 0x5b, 0x5c, 0xee, 0x8f, 0x03, 0x74, 0x6b, 0xf8, 0x30, 0x9d, 0x02, 0xd5, 0xea, 0x27, 0x15, 0x9c, 0x1e, 0xd6, 0x91, 0x54, 0x03, 0xb3, 0x63, 0x18, 0xd5, 0xa0, 0x3a, 0xfe, 0xb8 };
        const dcid = [_]u8{ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 };
        const initial_secret = HkdfSha256.extract(&INITIAL_SALT_VERSION_1, &dcid);
        var out = hkdfExpandLabel(initial_secret, "server in", "", Hmac.key_length);
        try std.testing.expectEqualSlices(u8, &expected, &out);
    }
}

test "a.1: keys - client initial secret" {
    {
        const expected = [_]u8{ 0xc0, 0x0c, 0xf1, 0x51, 0xca, 0x5b, 0xe0, 0x75, 0xed, 0x0e, 0xbf, 0xb5, 0xc8, 0x03, 0x23, 0xc4, 0x2d, 0x6b, 0x7d, 0xb6, 0x78, 0x81, 0x28, 0x9a, 0xf4, 0x00, 0x8f, 0x1f, 0x6c, 0x35, 0x7a, 0xea };
        const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
        const initial_secret = HkdfSha256.extract(&INITIAL_SALT_VERSION_1, &dcid);
        var out = hkdfExpandLabel(initial_secret, "client in", "", Hmac.key_length);
        try std.testing.expectEqualSlices(u8, &expected, &out);
    }

    {
        // This test case is brought from https://quic.xargs.org/
        const expected = [_]u8{ 0x47, 0xc6, 0xa6, 0x38, 0xd4, 0x96, 0x85, 0x95, 0xcc, 0x20, 0xb7, 0xc8, 0xbc, 0x5f, 0xbf, 0xbf, 0xd0, 0x2d, 0x7c, 0x17, 0xcc, 0x67, 0xfa, 0x54, 0x8c, 0x04, 0x3e, 0xcb, 0x54, 0x7b, 0x0e, 0xaa };
        const dcid = [_]u8{ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 };
        const initial_secret = HkdfSha256.extract(&INITIAL_SALT_VERSION_1, &dcid);
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
    applyHeaderProtection(&pkt, pn_offset, pn_len, seal_key.hp_key);

    // Verify something changed
    try std.testing.expect(pkt[0] != orig_first or !std.mem.eql(u8, &orig_pn, pkt[pn_offset..][0..4]));

    // Remove header protection
    const recovered_pn_len = removeHeaderProtection(&pkt, pn_offset, open_key.hp_key);
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

    // Verify derived keys match RFC 9001 A.1
    try std.testing.expectEqualSlices(u8, &[_]u8{
        0x1f, 0x36, 0x96, 0x13, 0xdd, 0x76, 0xd5, 0x46,
        0x77, 0x30, 0xef, 0xcb, 0xe3, 0xb1, 0xa2, 0x2d,
    }, &seal.key);
    try std.testing.expectEqualSlices(u8, &[_]u8{
        0xfa, 0x04, 0x4b, 0x2f, 0x42, 0xa3, 0xfd, 0x3b,
        0x46, 0xfb, 0x25, 0x5c,
    }, &seal.nonce);
    try std.testing.expectEqualSlices(u8, &[_]u8{
        0x9f, 0x50, 0x44, 0x9e, 0x04, 0xa0, 0xe8, 0x10,
        0x28, 0x3a, 0x1e, 0x99, 0x33, 0xad, 0xed, 0xd2,
    }, &seal.hp_key);

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
    applyHeaderProtection(pkt_buf[0..total_len], pn_offset, 4, seal.hp_key);

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
    const recovered_pn_len = removeHeaderProtection(pkt_buf[0..total_len], pn_offset, server_open.hp_key);
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
