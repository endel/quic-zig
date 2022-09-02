const std = @import("std");
const protocol = @import("protocol.zig");
const quictls = @import("quictls.zig");
const tls = @import("../tls/tls.zig");
const ciphers = @import("../tls/ciphers.zig");

const crypto = std.crypto;
const HkdfSha256 = crypto.kdf.hkdf.HkdfSha256;
const HmacSha256 = crypto.auth.hmac.sha2.HmacSha256;

// binascii.unhexlify("38762cf7f55934b34d179ae6a4c80cadccbb7f0a")
const INITIAL_SALT_VERSION_1: [20]u8 = .{ 0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0xc, 0xad, 0xcc, 0xbb, 0x7f, 0xa };

pub const CryptoContext = struct {
    const Self = @This();

    version: protocol.Version = undefined,
    secret: []const u8 = undefined,
    cipher_suite: tls.CipherSuite = tls.CipherSuite.tls_aes_256_gcm_sha384,

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

        // AEAD = Authenticated Encryption with Associated Data
        const aead_cipher_name = switch (cipher_suite) {
            tls.CipherSuite.tls_aes_128_gcm_sha256 => "aes-128-gcm",
            else => "",
        };

        // self.secret = secret;
        // self.version = version;
        self.cipher_suite = cipher_suite;

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
};

pub const CryptoPair = struct {
    recv: CryptoContext = CryptoContext{},
    send: CryptoContext = CryptoContext{},

    aead_tag_size: u8 = 16,
    _update_key_requested: bool = false,

    pub fn setupInitial(self: *CryptoPair, cid: []const u8, version: protocol.Version, comptime is_client: bool) void {
        _ = is_client;

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

// class CryptoContext:
//     def __init__(
//         self,
//         key_phase: int = 0,
//         setup_cb: Callback = NoCallback,
//         teardown_cb: Callback = NoCallback,
//     ) -> None:
//         self.aead: Optional[AEAD] = None
//         self.cipher_suite: Optional[CipherSuite] = None
//         self.hp: Optional[HeaderProtection] = None
//         self.key_phase = key_phase
//         self.secret: Optional[bytes] = None
//         self.version: Optional[int] = None
//         self._setup_cb = setup_cb
//         self._teardown_cb = teardown_cb
//
//     def decrypt_packet(
//         self, packet: bytes, encrypted_offset: int, expected_packet_number: int
//     ) -> Tuple[bytes, bytes, int, bool]:
//         if self.aead is None:
//             raise KeyUnavailableError("Decryption key is not available")
//
//         # header protection
//         plain_header, packet_number = self.hp.remove(packet, encrypted_offset)
//         first_byte = plain_header[0]
//
//         # packet number
//         pn_length = (first_byte & 0x03) + 1
//         packet_number = decode_packet_number(
//             packet_number, pn_length * 8, expected_packet_number
//         )
//
//         # detect key phase change
//         crypto = self
//         if not is_long_header(first_byte):
//             key_phase = (first_byte & 4) >> 2
//             if key_phase != self.key_phase:
//                 crypto = next_key_phase(self)
//
//         # payload protection
//         payload = crypto.aead.decrypt(
//             packet[len(plain_header) :], plain_header, packet_number
//         )
//
//         return plain_header, payload, packet_number, crypto != self
//
//     def encrypt_packet(
//         self, plain_header: bytes, plain_payload: bytes, packet_number: int
//     ) -> bytes:
//         assert self.is_valid(), "Encryption key is not available"
//
//         # payload protection
//         protected_payload = self.aead.encrypt(
//             plain_payload, plain_header, packet_number
//         )
//
//         # header protection
//         return self.hp.apply(plain_header, protected_payload)
//
//     def is_valid(self) -> bool:
//         return self.aead is not None
//
//     def setup(self, cipher_suite: CipherSuite, secret: bytes, version: int) -> None:
//         hp_cipher_name, aead_cipher_name = CIPHER_SUITES[cipher_suite]
//
//         key, iv, hp = derive_key_iv_hp(cipher_suite, secret)
//         self.aead = AEAD(aead_cipher_name, key, iv)
//         self.cipher_suite = cipher_suite
//         self.hp = HeaderProtection(hp_cipher_name, hp)
//         self.secret = secret
//         self.version = version
//
//         # trigger callback
//         self._setup_cb("tls")
//
//     def teardown(self) -> None:
//         self.aead = None
//         self.cipher_suite = None
//         self.hp = None
//         self.secret = None
//
//         # trigger callback
//         self._teardown_cb("tls")
//
