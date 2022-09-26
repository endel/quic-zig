const std = @import("std");
const protocol = @import("protocol.zig");
const quictls = @import("quictls.zig");
const tls = @import("../tls/tls.zig");
const ciphers = @import("../tls/ciphers.zig");
const packet = @import("packet.zig");
const aead = @import("aead.zig");

const crypto = std.crypto;
const HkdfSha256 = crypto.kdf.hkdf.HkdfSha256;
const HmacSha256 = crypto.auth.hmac.sha2.HmacSha256;
const Aes128Gcm = crypto.aead.aes_gcm.Aes128Gcm;

// binascii.unhexlify("38762cf7f55934b34d179ae6a4c80cadccbb7f0a")
const INITIAL_SALT_VERSION_1: [20]u8 = .{ 0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0xc, 0xad, 0xcc, 0xbb, 0x7f, 0xa };

// Header protection sample length
pub const SAMPLE_LEN = 16;

// TODO: support the 3 algorithms
// during this experimentational phase, only AES128_GCM is supported.
const alg = HmacSha256;
const key_len = alg.key_length;
const nonce_len = 12;

pub const Algorithm = enum {
    AES128_GCM,
    AES256_GCM,
    ChaCha20_Poly1305,
};

pub const Open = struct {
    // alg: Algorithm,
    // ctx: anytype, // EVP_AEAD_CTX
    // hp_key: aead.HeaderProtectionKey,
    key: [key_len]u8,
    hp_key: [key_len]u8,
    nonce: [nonce_len]u8,

    /// Generate a new QUIC Header Protection mask.
    ///
    /// `sample` must be exactly `self.algorithm().sample_len()` bytes long.
    // pub fn newMask(self: *const Open, sample: [packet.MAX_PACKET_NUMBER_LEN]u8) ![5]u8 {
    pub fn newMask(self: *const Open, sample: []u8) ![5]u8 {
        _ = self;
        _ = sample;
        return .{ 1, 2, 3, 4, 5 };
    }
};

pub const Seal = struct {
    // alg: Algorithm,
    // ctx: anytype, // EVP_AEAD_CTX
    // hp_key: aead.HeaderProtectionKey,
    key: [key_len]u8,
    hp_key: [key_len]u8,
    nonce: [nonce_len]u8,
};

pub fn deriveInitialKeyMaterial(
    cid: []const u8,
    version: protocol.Version,
    comptime is_client: bool,
) !std.meta.Tuple(&.{ Open, Seal }) {
    if (version != protocol.Version.VERSION_1) {
        std.log.err("only VERSION_1 is supported right now.", .{});
        return error.InvalidVersion;
    }

    const initial_salt = INITIAL_SALT_VERSION_1;
    const initial_secret = HkdfSha256.extract(&initial_salt, cid);

    // https://datatracker.ietf.org/doc/html/rfc9001#section-5.1

    var secret: [32]u8 = hkdfExpandLabel(initial_secret, "client in", "", alg.key_length);

    // Client
    const client_key = hkdfExpandLabel(secret, "quic key", "", key_len);
    const client_iv = hkdfExpandLabel(secret, "quic iv", "", nonce_len);
    const client_hp_key = hkdfExpandLabel(secret, "quic hp", "", key_len); //header protection key

    // Server
    secret = hkdfExpandLabel(initial_secret, "server in", "", alg.key_length);
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

pub const CryptoContext = struct {
    const Self = @This();

    version: protocol.Version = undefined,
    secret: []const u8 = undefined,
    cipher_suite: tls.CipherSuite = tls.CipherSuite.tls_aes_256_gcm_sha384,

    cipher: ciphers.Aes128.Context = undefined,
    key_data: ciphers.KeyStorage = ciphers.KeyStorage{},

    // aead: Optional[AEAD] = None
    // cipher_suite: Optional[CipherSuite] = None
    // hp: Optional[HeaderProtection] = None
    // key_phase = key_phase
    // secret: Optional[bytes] = None
    // version: Optional[int] = None
    // _setup_cb = setup_cb
    // _teardown_cb = teardown_cb

    pub fn setup(self: *Self, cipher_suite: tls.CipherSuite, secret: [32]u8, version: protocol.Version) void {
        const key_size = 16;
        // const key_size: u16 = switch (cipher_suite) {
        //     tls.CipherSuite.tls_aes_256_gcm_sha384, tls.CipherSuite.tls_chacha20_poly1305_sha256 => 32,
        //     else => 16,
        // };

        // https://datatracker.ietf.org/doc/html/rfc9001#section-5.1
        // (derive_key_iv_hp)
        const key = hkdfExpandLabel(secret, "quic key", "", key_size);
        const iv = hkdfExpandLabel(secret, "quic iv", "", 12);
        const hp = hkdfExpandLabel(secret, "quic hp", "", key_size);

        // hp = Header Protection
        const hp_cipher_name = switch (cipher_suite) {
            tls.CipherSuite.tls_aes_128_gcm_sha256 => "aes-128-ecb",
            else => "",
        };

        std.log.info("hp_cipher_name: {s}", .{hp_cipher_name});

        // AEAD = Authenticated Encryption with Associated Data
        const aead_cipher_name = switch (cipher_suite) {
            tls.CipherSuite.tls_aes_128_gcm_sha256 => "aes-128-gcm",
            else => "",
        };

        // self.secret = secret;
        // self.version = version;
        self.cipher_suite = cipher_suite;

        // self.cipher = ciphers.Aes128.init(self.key_data)

        _ = self;
        _ = version;
        _ = key;
        _ = iv;
        _ = hp;
        _ = hp_cipher_name;
        _ = aead_cipher_name;

        // , aead_cipher_name = CIPHER_SUITES[cipher_suite]

        // self.aead = AEAD(aead_cipher_name, key, iv)

        // hp_cipher_name, aead_cipher_name = CIPHER_SUITES[cipher_suite]
        //
        // key, iv, hp = derive_key_iv_hp(cipher_suite, secret)
        // self.aead = AEAD(aead_cipher_name, key, iv)
        // self.cipher_suite = cipher_suite
        // self.hp = HeaderProtection(hp_cipher_name, hp)
        // self.secret = secret
        // self.version = version
        //
        // # trigger callback
        // self._setup_cb("tls")
    }

    pub fn decryptPacket(self: *CryptoContext, decrypted_bytes: *[]u8, bytes: []const u8, encrypted_offset: usize, expected_packet_number: u64) !void {
        // if (self.aead == null) {
        //     return (error{DecryptPacketError}).DecryptPacketError;
        // }

        _ = try self.removeHeaderProtection(decrypted_bytes, bytes, encrypted_offset);

        _ = bytes;
        _ = expected_packet_number;

        // // header protection
        // plain_header, packet_number = self.hp.remove(packet, encrypted_offset)
        // first_byte = plain_header[0]
        //
        // // packet number
        // pn_length = (first_byte & 0x03) + 1
        // packet_number = packet.decodePacketNumber(packet_number, pn_length * 8, expected_packet_number);
        //
        // // packet_number = decode_packet_number(
        // //     packet_number, pn_length * 8, expected_packet_number
        // // )
        //
        // // detect key phase change
        // crypto = self
        // if not is_long_header(first_byte):
        //     key_phase = (first_byte & 4) >> 2
        //     if key_phase != self.key_phase:
        //         crypto = next_key_phase(self)
        //
        // // payload protection
        // payload = crypto.aead.decrypt(
        //     packet[len(plain_header) :], plain_header, packet_number
        // )
        //
        // return plain_header, payload, packet_number, crypto != self
    }

    pub fn removeHeaderProtection(self: *CryptoContext, decrypted_bytes: *[]u8, bytes: []const u8, encrypted_offset: u64) !void {
        _ = bytes;
        _ = encrypted_offset;
        _ = self;
        _ = decrypted_bytes;

        //
        //     const first = bytes[0];
        //     const pn_and_sample = bytes[0..]
        // let mut pn_and_sample = b.peek_bytes_mut(MAX_PKT_NUM_LEN + SAMPLE_LEN)?;
        //
        //     std.log.info("removeHeaderProtection...", .{});
        //
        //     const mask_length: usize = 5;
        //     const sample_offset: usize = encrypted_offset + 4;
        //
        //     const mask_bytes: []const u8 = .{ 0, 0, 0, 0, 0 };

        //
        // // TODO: check if (sample_offset + sample_size > header length)
        //
        // const first_mask = if ((first_byte & 0x80) == 0x80) 0x0F else 0x1F;
        // var pn_l: u8 = undefined; // packet number length
        // var pn_val: u8 = 0; // packet number value
        //
        // std.mem.copy(u8, decrypted_bytes, bytes);
        // // memcpy(decrypted_bytes, bytes, ph->pn_offset);
        //
        // picoquic_pn_encrypt(pn_enc, bytes + sample_offset, mask_bytes, mask_bytes, mask_length);
        // /* Decode the first byte */
        // first_byte ^= (mask_bytes[0] & first_mask);
        // pn_l = (first_byte & 3) + 1;
        // ph->pnmask = (0xFFFFFFFFFFFFFFFFull);
        // decrypted_bytes[0] = first_byte;
        //
        // /* Packet encoding is 1 to 4 bytes */
        // for (uint8_t i = 1; i <= pn_l; i++) {
        //     pn_val <<= 8;
        //     decrypted_bytes[ph->offset] = bytes[ph->offset]^mask_bytes[i];
        //     pn_val += decrypted_bytes[ph->offset++];
        //     ph->pnmask <<= 8;
        // }
        //
        // ph->pn = pn_val;
        // ph->payload_length -= pn_l;
        //
        //
        // const key: [Aes128Gcm.key_length]u8 = [_]u8{0x69} ** Aes128Gcm.key_length;
        // const nonce: [Aes128Gcm.nonce_length]u8 = [_]u8{0x42} ** Aes128Gcm.nonce_length;
        // const m = "Test with message";
        // const ad = "Test with associated data";
        // var c: [bytes.len]u8 = undefined;
        // var m2: [bytes.len]u8 = undefined;
        // var tag: [Aes128Gcm.tag_length]u8 = undefined;
        //
        // Aes128Gcm.encrypt(&c, &tag, m, ad, nonce, key);
        // try Aes128Gcm.decrypt(&m2, &c, tag, ad, nonce, key);
        //
        // std.log.info("m2: {any}", .{m2});
        // std.log.info("c: {any}", .{c});
    }

    pub fn encryptPacket() void {}
};

pub const CryptoPair = struct {
    recv: CryptoContext = CryptoContext{},
    send: CryptoContext = CryptoContext{},

    aead_tag_size: u8 = 16,
    _update_key_requested: bool = false,

    pub fn setupInitial(self: *CryptoPair, cid: []const u8, version: protocol.Version, comptime is_client: bool) void {

        // TODO: invert this for client
        // only server side is implemented for now
        // const recv_label: []const u8 = "server in";
        // const send_label: []const u8 = "client in";
        const recv_label: []const u8 = if (is_client) "client in" else "server in";
        const send_label: []const u8 = if (is_client) "server in" else "client in";

        const initial_salt = INITIAL_SALT_VERSION_1;
        const initial_secret = HkdfSha256.extract(&initial_salt, cid);

        const recv_secret = hkdfExpandLabel(initial_secret, recv_label, "", HmacSha256.key_length);
        self.recv.setup(tls.CipherSuite.tls_aes_128_gcm_sha256, recv_secret, version);

        const send_secret = hkdfExpandLabel(initial_secret, send_label, "", HmacSha256.key_length);
        self.send.setup(tls.CipherSuite.tls_aes_128_gcm_sha256, send_secret, version);
    }

    pub fn decryptPacket(self: *CryptoPair, decrypted_bytes: *[]u8, bytes: []const u8, encrypted_offset: usize, expected_packet_number: u32) !void {
        _ = self;
        _ = bytes;
        _ = encrypted_offset;
        _ = expected_packet_number;

        std.log.info("decryptPacket ...", .{});
        try self.recv.decryptPacket(decrypted_bytes, bytes, encrypted_offset, expected_packet_number);

        // def decrypt_packet(
        //     self, packet: bytes, encrypted_offset: int, expected_packet_number: int
        // ) -> Tuple[bytes, bytes, int]:
        //     plain_header, payload, packet_number, update_key = self.recv.decrypt_packet(
        //         packet, encrypted_offset, expected_packet_number
        //     )
        //     if update_key:
        //         self._update_key("remote_update")
        //     return plain_header, payload, packet_number

    }
};

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

test "CryptoContext setup" {
    var context = CryptoContext{};

    const initial_secret = HkdfSha256.extract(&INITIAL_SALT_VERSION_1, "dummy_source_id");
    const secret = hkdfExpandLabel(initial_secret, "server in", "", HmacSha256.key_length);

    context.setup(tls.CipherSuite.tls_aes_128_gcm_sha256, secret, protocol.Version.VERSION_1);
}

pub fn headerProtectionMask(sample: []const u8) void {
    _ = sample;

    // int outlen;
    // if (self->is_chacha20) {
    //     return EVP_CipherInit_ex(self->ctx, NULL, NULL, NULL, sample, 1) &&
    //            EVP_CipherUpdate(self->ctx, self->mask, &outlen, self->zero, sizeof(self->zero));
    // } else {
    //     return EVP_CipherUpdate(self->ctx, self->mask, &outlen, sample, SAMPLE_LENGTH);
    // }
}
