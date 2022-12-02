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

// binascii.unhexlify("38762cf7f55934b34d179ae6a4c80cadccbb7f0a")
const INITIAL_SALT_VERSION_1 = [_]u8{ 0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0xc, 0xad, 0xcc, 0xbb, 0x7f, 0xa };

// Header protection sample length
pub const SAMPLE_LEN = 16;

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

pub const Open = struct {
    // alg: Algorithm,
    // ctx: anytype, // EVP_AEAD_CTX
    // hp_key: aead.HeaderProtectionKey,

    key: [key_len]u8, // KEY
    hp_key: [key_len]u8, // HP key
    nonce: [nonce_len]u8, // IV

    /// Generate a new QUIC Header Protection mask.
    ///
    pub fn newMask(self: *const Open, sample: *[SAMPLE_LEN]u8) *[5]u8 {
        const ctx = Aes128.initEnc(self.hp_key);
        // const ctx = Aes256.initEnc(self.hp_key);

        var encrypted_out: [SAMPLE_LEN]u8 = .{0x00} ** SAMPLE_LEN;
        ctx.encrypt(&encrypted_out, sample);
        return encrypted_out[0..5];
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

        // the tag is on last bytes of the payload
        const tag: [tag_len]u8 = tag: {
            var t: [tag_len]u8 = undefined;
            std.mem.copy(u8, &t, payload[(payload_len - tag_len)..payload_len]);
            break :tag t;
        };

        //
        // https://datatracker.ietf.org/doc/html/rfc9001#section-5.3
        //
        // The nonce, N, is formed by combining the packet protection IV with the packet
        // number. The 62 bits of the reconstructed QUIC packet number in network byte
        // order are left-padded with zeros to the size of the IV. The exclusive OR of the
        // padded packet number and the IV forms the AEAD nonce.
        //
        const aead_nonce = nonce: {
            var n: [nonce_len]u8 = undefined;
            std.mem.copy(u8, &n, &self.nonce);

            var pn: [nonce_len]u8 = .{0x0} ** nonce_len;
            std.mem.writeIntSliceBig(u64, pn[4..nonce_len], packet_number);

            var i: usize = 4;
            while (i < nonce_len) {
                n[i] ^= pn[i];
                i = i + 1;
            }

            break :nonce n;
        };

        var bytes = payload[0..(payload_len - tag_len)];

        try Aead.decrypt(
            bytes, // output
            bytes, // input
            tag,
            associated_data,
            aead_nonce,
            self.key,
        );

        return bytes;
    }
};

pub const Seal = struct {
    // Hmac: Algorithm,
    // ctx: anytype, // EVP_AEAD_CTX
    // hp_key: aead.HeaderProtectionKey,
    key: [key_len]u8,
    hp_key: [key_len]u8,
    nonce: [nonce_len]u8,
};

// pub fn aeadEncrypt(bytes: []u8, ad: []u8, nonce: []u8, key: []u8) void {
//     const tag_len = key_len;
//     const tag: [tag_len]u8 = tag: {
//         var t: [tag_len]u8 = undefined;
//         std.mem.copy(u8, &t, bytes[(bytes.len - tag_len)..bytes.len]);
//         break :tag t;
//     };
//
//     // TODO: avoid using dynamic allocation
//     const allocator = std.heap.page_allocator;
//     var encrypted = try allocator.alloc(u8, bytes.len);
//     defer allocator.free(encrypted);
//
//     return Aead.encrypt(encrypted, bytes, tag, "", nonce, key);
// }

pub fn deriveInitialKeyMaterial(
    cid: []const u8,
    version: u32,
    comptime is_client: bool,
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

    return if (is_client) .{
        Open{
            .key = server_key,
            .hp_key = server_hp_key,
            .nonce = server_iv,
        },
        Seal{
            .key = client_key,
            .hp_key = client_hp_key,
            .nonce = client_iv,
        },
    } else .{
        Open{
            .key = client_key,
            .hp_key = client_hp_key,
            .nonce = client_iv,
        },
        Seal{
            .key = server_key,
            .hp_key = server_hp_key,
            .nonce = server_iv,
        },
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
fn hkdfExpandLabel(
    secret: [32]u8,
    comptime label: []const u8,
    context: []const u8,
    comptime length: u16,
) [length]u8 {
    std.debug.assert(label.len <= 255 and label.len > 0);
    std.debug.assert(context.len <= 255);
    const full_label = "tls13 " ++ label;

    // length, label, context
    var buf: [2 + 255 + 255]u8 = undefined;
    std.mem.writeIntBig(u16, buf[0..2], length);
    buf[2] = full_label.len;
    std.mem.copy(u8, buf[3..], full_label);
    buf[3 + full_label.len] = @intCast(u8, context.len);
    std.mem.copy(u8, buf[4 + full_label.len ..], context);
    const actual_context = buf[0 .. 4 + full_label.len + context.len];

    var out: [32]u8 = undefined;
    HkdfSha256.expand(&out, actual_context, secret);
    return out[0..length].*;
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
