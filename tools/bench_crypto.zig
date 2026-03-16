// Isolated benchmark of the cryptographic primitives used in QUIC TLS 1.3.
// Compare with tools/bench_crypto.go for apples-to-apples Zig vs Go comparison.
//
// Usage:
//   zig build-exe -OReleaseFast tools/bench_crypto.zig && ./bench_crypto
//
// Operations benchmarked (in order of handshake hot-path impact):
//   1. ECDSA P-256 Sign        (CertificateVerify, server per-handshake)
//   2. ECDSA P-256 Verify      (CertificateVerify, client per-handshake)
//   3. X25519 scalarmult        (Key exchange, both sides per-handshake)
//   4. AES-128-GCM encrypt      (Every outgoing packet)
//   5. AES-128-GCM decrypt      (Every incoming packet)
//   6. HKDF-SHA256 extract      (Key derivation, per-handshake)
//   7. HKDF-SHA256 expand       (Key derivation, multiple per-handshake)
//   8. AES-128-ECB (HP mask)    (Header protection, every packet)

const std = @import("std");
const crypto = std.crypto;
const time = std.time;

const EcdsaP256Sha256 = crypto.sign.ecdsa.EcdsaP256Sha256;
const X25519 = crypto.dh.X25519;
const Aes128Gcm = crypto.aead.aes_gcm.Aes128Gcm;
const HkdfSha256 = crypto.kdf.hkdf.HkdfSha256;
const Aes128 = crypto.core.aes.Aes128;

fn benchNs(comptime f: anytype, args: anytype, iterations: u32) f64 {
    // Warmup
    var warmup: u32 = 0;
    while (warmup < 10) : (warmup += 1) {
        _ = @call(.auto, f, args);
    }

    const start = time.nanoTimestamp();
    var i: u32 = 0;
    while (i < iterations) : (i += 1) {
        _ = @call(.auto, f, args);
    }
    const elapsed = time.nanoTimestamp() - start;
    return @as(f64, @floatFromInt(elapsed)) / @as(f64, @floatFromInt(iterations));
}

// ── ECDSA P-256 Sign ──

fn ecdsaSign(key_pair: EcdsaP256Sha256.KeyPair, msg: *const [130]u8) EcdsaP256Sha256.Signature {
    return key_pair.sign(msg, null) catch unreachable;
}

// ── ECDSA P-256 Verify ──

fn ecdsaVerify(sig: EcdsaP256Sha256.Signature, msg: *const [130]u8, pub_key: EcdsaP256Sha256.PublicKey) bool {
    sig.verify(msg, pub_key) catch return false;
    return true;
}

// ── X25519 ──

fn x25519Scalarmult(secret: *const [32]u8, public: *const [32]u8) [32]u8 {
    return X25519.scalarmult(secret.*, public.*) catch unreachable;
}

// ── AES-128-GCM Encrypt ──

fn aesGcmEncrypt(
    key: *const [16]u8,
    nonce: *const [12]u8,
    plaintext: *const [1200]u8,
    ad: *const [20]u8,
    out: *[1200]u8,
    tag: *[16]u8,
) void {
    Aes128Gcm.encrypt(out, tag, plaintext, ad, nonce.*, key.*);
}

// ── AES-128-GCM Decrypt ──

fn aesGcmDecrypt(
    key: *const [16]u8,
    nonce: *const [12]u8,
    ciphertext: *const [1200]u8,
    ad: *const [20]u8,
    tag: *const [16]u8,
    out: *[1200]u8,
) bool {
    Aes128Gcm.decrypt(out, ciphertext, tag.*, ad, nonce.*, key.*) catch return false;
    return true;
}

// ── HKDF Extract ──

fn hkdfExtract(salt: *const [32]u8, ikm: *const [32]u8) [32]u8 {
    return HkdfSha256.extract(salt, ikm);
}

// ── HKDF Expand ──

fn hkdfExpand(prk: *const [32]u8, info: *const [50]u8) [32]u8 {
    var out: [32]u8 = undefined;
    HkdfSha256.expand(&out, info, prk.*);
    return out;
}

// ── AES-128-ECB (Header Protection) ──

fn aesEcbEncrypt(ctx: @TypeOf(Aes128.initEnc(undefined)), sample: *const [16]u8) [16]u8 {
    var out: [16]u8 = undefined;
    ctx.encrypt(&out, sample);
    return out;
}

pub fn main() !void {
    std.debug.print("═══════════════════════════════════════════════════════\n", .{});
    std.debug.print("  Crypto Primitive Benchmark (Zig std.crypto)\n", .{});
    std.debug.print("  Compare with: go run tools/bench_crypto.go\n", .{});
    std.debug.print("═══════════════════════════════════════════════════════\n\n", .{});

    // Setup keys
    var rng_buf: [128]u8 = undefined;
    crypto.random.bytes(&rng_buf);

    // ECDSA P-256
    const ecdsa_kp = EcdsaP256Sha256.KeyPair.generate();
    var sign_content: [130]u8 = undefined;
    @memset(sign_content[0..64], 0x20);
    @memcpy(sign_content[64..97], "TLS 1.3, server CertificateVerify");
    sign_content[97] = 0x00;
    @memset(sign_content[98..130], 0xAA); // fake transcript hash (32 bytes)

    const sig = ecdsaSign(ecdsa_kp, &sign_content);

    // X25519
    var x25519_secret: [32]u8 = undefined;
    var x25519_public: [32]u8 = undefined;
    crypto.random.bytes(&x25519_secret);
    x25519_public = X25519.recoverPublicKey(x25519_secret) catch unreachable;

    // AES-128-GCM
    var aes_key: [16]u8 = undefined;
    var aes_nonce: [12]u8 = undefined;
    var plaintext: [1200]u8 = undefined;
    var ciphertext: [1200]u8 = undefined;
    var aes_tag: [16]u8 = undefined;
    var ad: [20]u8 = undefined;
    crypto.random.bytes(&aes_key);
    crypto.random.bytes(&aes_nonce);
    crypto.random.bytes(&plaintext);
    crypto.random.bytes(&ad);
    Aes128Gcm.encrypt(&ciphertext, &aes_tag, &plaintext, &ad, aes_nonce, aes_key);

    // HKDF
    var hkdf_salt: [32]u8 = undefined;
    var hkdf_ikm: [32]u8 = undefined;
    var hkdf_info: [50]u8 = undefined;
    crypto.random.bytes(&hkdf_salt);
    crypto.random.bytes(&hkdf_ikm);
    crypto.random.bytes(&hkdf_info);
    const prk = HkdfSha256.extract(&hkdf_salt, &hkdf_ikm);

    // AES-128-ECB
    const aes_ctx = Aes128.initEnc(aes_key);
    var hp_sample: [16]u8 = undefined;
    crypto.random.bytes(&hp_sample);

    // ── Run benchmarks ──

    const N_SIGN: u32 = 1000;
    const N_VERIFY: u32 = 1000;
    const N_X25519: u32 = 5000;
    const N_AES: u32 = 100_000;
    const N_HKDF: u32 = 100_000;
    const N_HP: u32 = 500_000;

    var dec_out: [1200]u8 = undefined;

    const sign_ns = benchNs(ecdsaSign, .{ ecdsa_kp, &sign_content }, N_SIGN);
    const verify_ns = benchNs(ecdsaVerify, .{ sig, &sign_content, ecdsa_kp.public_key }, N_VERIFY);
    const x25519_ns = benchNs(x25519Scalarmult, .{ &x25519_secret, &x25519_public }, N_X25519);
    const enc_ns = benchNs(aesGcmEncrypt, .{ &aes_key, &aes_nonce, &plaintext, &ad, &ciphertext, &aes_tag }, N_AES);
    const dec_ns = benchNs(aesGcmDecrypt, .{ &aes_key, &aes_nonce, &ciphertext, &ad, &aes_tag, &dec_out }, N_AES);
    const extract_ns = benchNs(hkdfExtract, .{ &hkdf_salt, &hkdf_ikm }, N_HKDF);
    const expand_ns = benchNs(hkdfExpand, .{ &prk, &hkdf_info }, N_HKDF);
    const hp_ns = benchNs(aesEcbEncrypt, .{ aes_ctx, &hp_sample }, N_HP);

    std.debug.print("  {s:<28} {s:>10}  {s:>10}\n", .{ "Operation", "ns/op", "ops/sec" });
    std.debug.print("  ────────────────────────── ──────────  ──────────\n", .{});

    const ops = [_]struct { name: []const u8, ns: f64 }{
        .{ .name = "ECDSA P-256 Sign", .ns = sign_ns },
        .{ .name = "ECDSA P-256 Verify", .ns = verify_ns },
        .{ .name = "X25519 scalarmult", .ns = x25519_ns },
        .{ .name = "AES-128-GCM encrypt (1200B)", .ns = enc_ns },
        .{ .name = "AES-128-GCM decrypt (1200B)", .ns = dec_ns },
        .{ .name = "HKDF-SHA256 extract", .ns = extract_ns },
        .{ .name = "HKDF-SHA256 expand", .ns = expand_ns },
        .{ .name = "AES-128-ECB (HP mask)", .ns = hp_ns },
    };

    for (ops) |op| {
        const ops_sec = 1_000_000_000.0 / op.ns;
        std.debug.print("  {s:<28} {d:>10.0}  {d:>10.0}\n", .{ op.name, op.ns, ops_sec });
    }

    std.debug.print("\n  Handshake estimate (sign + verify + x25519 + 4×HKDF):\n", .{});
    const hs_ns = sign_ns + verify_ns + x25519_ns + 4 * (extract_ns + expand_ns);
    std.debug.print("  {d:.0}µs per handshake ({d:.0} handshakes/s)\n", .{ hs_ns / 1000.0, 1_000_000_000.0 / hs_ns });

    std.debug.print("\n═══════════════════════════════════════════════════════\n", .{});
}
