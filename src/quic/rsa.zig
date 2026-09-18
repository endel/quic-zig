//! RSA private keys and RSASSA-PSS signing (RFC 8017), for TLS 1.3
//! CertificateVerify with the rsa_pss_rsae_* schemes (RFC 8446 §4.2.3).
//!
//! Signing runs on `std.crypto.ff`, whose modular exponentiation is constant
//! time in the exponent, and uses the CRT. Each signature is checked against
//! the public exponent before it is returned, so a fault in one CRT half
//! cannot hand out a signature that factors the modulus (Boneh-DeMillo-Lipton).

const std = @import("std");
const sys = @import("../sys.zig");
const ff = std.crypto.ff;
const mem = std.mem;

pub const min_bits = 2048;
pub const max_bits = 4096;
/// Longest signature: one modulus length.
pub const max_signature_len = max_bits / 8;

const Modulus = ff.Modulus(max_bits);
const PrimeModulus = ff.Modulus(max_bits / 2);
const max_prime_len = max_bits / 16;

// 1.2.840.113549.1.1.1
const rsa_encryption_oid = [_]u8{ 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01 };

pub const Error = error{
    /// Not a well-formed key encoding.
    DecodeError,
    /// Well formed, but not a two-prime RSA key of 2048–4096 bits.
    UnsupportedKey,
    /// The key's numbers do not fit together.
    InvalidKey,
};

/// A two-prime RSA private key. The fields are big-endian magnitudes without
/// leading zeros, borrowed from the DER the key was parsed from.
pub const PrivateKey = struct {
    n: []const u8,
    e: []const u8,
    p: []const u8,
    q: []const u8,
    /// d mod (p - 1)
    dp: []const u8,
    /// d mod (q - 1)
    dq: []const u8,
    /// q^-1 mod p
    qinv: []const u8,

    /// Parses a PKCS#1 RSAPrivateKey (RFC 8017 A.1.2). Checks the structure
    /// and sizes only; `check` proves the numbers belong together.
    pub fn parsePkcs1(der: []const u8) Error!PrivateKey {
        var outer: Reader = .{ .buf = der };
        var r: Reader = .{ .buf = try outer.element(tag_sequence) };
        if (!outer.done()) return error.DecodeError;

        const version = try r.unsigned();
        // Version 1 carries otherPrimeInfos: multi-prime keys.
        if (version.len != 0) return error.UnsupportedKey;
        var key: PrivateKey = undefined;
        key.n = try r.unsigned();
        key.e = try r.unsigned();
        _ = try r.unsigned(); // d: the CRT values below replace it
        key.p = try r.unsigned();
        key.q = try r.unsigned();
        key.dp = try r.unsigned();
        key.dq = try r.unsigned();
        key.qinv = try r.unsigned();
        if (!r.done()) return error.DecodeError;

        const bits = key.modulusBits();
        if (bits < min_bits or bits > max_bits) return error.UnsupportedKey;
        if (key.n[key.n.len - 1] & 1 == 0) return error.InvalidKey;
        // std's verifier, and so our self-check, takes exponents below 2^32.
        if (key.e.len > 4) return error.UnsupportedKey;
        if (key.e[key.e.len - 1] & 1 == 0 or (key.e.len == 1 and key.e[0] < 3)) return error.InvalidKey;
        for ([_][]const u8{ key.p, key.q, key.dp, key.dq, key.qinv }) |v| {
            if (v.len == 0 or v.len > max_prime_len) return error.InvalidKey;
        }
        if (key.p[key.p.len - 1] & 1 == 0 or key.q[key.q.len - 1] & 1 == 0) return error.InvalidKey;
        return key;
    }

    /// Returns the PKCS#1 RSAPrivateKey inside a PKCS#8 PrivateKeyInfo
    /// (RFC 5208) whose algorithm is rsaEncryption.
    pub fn pkcs1FromPkcs8(der: []const u8) Error![]const u8 {
        var outer: Reader = .{ .buf = der };
        var r: Reader = .{ .buf = try outer.element(tag_sequence) };
        if (!outer.done()) return error.DecodeError;

        const version = try r.unsigned();
        if (version.len > 1 or (version.len == 1 and version[0] > 1)) return error.DecodeError;
        var alg: Reader = .{ .buf = try r.element(tag_sequence) };
        if (!mem.eql(u8, try alg.element(tag_oid), &rsa_encryption_oid)) return error.UnsupportedKey;
        if (!alg.done()) {
            if ((try alg.element(tag_null)).len != 0 or !alg.done()) return error.DecodeError;
        }
        // Attributes and a public key may follow; neither is needed.
        return r.element(tag_octet_string);
    }

    pub fn modulusBits(self: PrivateKey) usize {
        if (self.n.len == 0) return 0;
        return self.n.len * 8 - @clz(self.n[0]);
    }

    /// Signature length: the modulus length in bytes.
    pub fn signatureLength(self: PrivateKey) usize {
        return self.n.len;
    }

    /// Signs one message, proving the key's numbers fit together. A private
    /// key that fails here would fail every handshake.
    pub fn check(self: PrivateKey) Error!void {
        var sig: [max_signature_len]u8 = undefined;
        const salt: [32]u8 = @splat(0);
        _ = self.signPssWithSalt(std.crypto.hash.sha2.Sha256, "key check", &salt, &sig) catch return error.InvalidKey;
    }

    /// RSASSA-PSS with MGF1 over `Hash` and a salt as long as the digest,
    /// the parameters TLS 1.3 requires. Returns the signature, `out[0..n.len]`.
    pub fn signPss(self: PrivateKey, comptime Hash: type, msg: []const u8, out: *[max_signature_len]u8) Error![]const u8 {
        var salt: [Hash.digest_length]u8 = undefined;
        sys.randomBytes(&salt);
        return self.signPssWithSalt(Hash, msg, &salt, out);
    }

    fn signPssWithSalt(
        self: PrivateKey,
        comptime Hash: type,
        msg: []const u8,
        salt: *const [Hash.digest_length]u8,
        out: *[max_signature_len]u8,
    ) Error![]const u8 {
        const k = self.n.len;
        if (k > max_signature_len) return error.UnsupportedKey;
        var em: [max_signature_len]u8 = undefined;
        try encodePss(Hash, msg, salt, self.modulusBits() - 1, em[0..k]);
        try self.privateOp(em[0..k], out[0..k]);
        return out[0..k];
    }

    /// out = in^d mod n, via the CRT, verified with the public exponent.
    fn privateOp(self: PrivateKey, in: []const u8, out: []u8) Error!void {
        const k = self.n.len;
        const n = Modulus.fromBytes(self.n, .big) catch return error.InvalidKey;
        const p = PrimeModulus.fromBytes(self.p, .big) catch return error.InvalidKey;
        const q = PrimeModulus.fromBytes(self.q, .big) catch return error.InvalidKey;
        const m_wide = ff.Uint(max_bits).fromBytes(in, .big) catch return error.InvalidKey;

        // Pad the exponents to the prime's length so their size leaks nothing.
        var exp_buf: [max_prime_len]u8 = undefined;
        defer std.crypto.secureZero(u8, &exp_buf);
        const m1 = p.powWithEncodedExponent(p.reduce(m_wide), try padded(&exp_buf, self.dp, self.p.len), .big) catch return error.InvalidKey;
        const m2 = q.powWithEncodedExponent(q.reduce(m_wide), try padded(&exp_buf, self.dq, self.q.len), .big) catch return error.InvalidKey;

        // h = qinv * (m1 - m2) mod p; s = m2 + h * q, which is below n.
        var bytes: [PrimeModulus.Fe.encoded_bytes]u8 = undefined;
        defer std.crypto.secureZero(u8, &bytes);
        m2.toBytes(&bytes, .big) catch return error.InvalidKey;
        const m2_mod_p = p.reduce(ff.Uint(max_bits / 2).fromBytes(&bytes, .big) catch return error.InvalidKey);
        const m2_mod_n = Modulus.Fe.fromBytes(n, &bytes, .big) catch return error.InvalidKey;
        const qinv = PrimeModulus.Fe.fromBytes(p, self.qinv, .big) catch return error.InvalidKey;
        const h = p.mul(qinv, p.sub(m1, m2_mod_p));
        h.toBytes(&bytes, .big) catch return error.InvalidKey;
        const h_mod_n = Modulus.Fe.fromBytes(n, &bytes, .big) catch return error.InvalidKey;
        const q_mod_n = Modulus.Fe.fromBytes(n, self.q, .big) catch return error.InvalidKey;
        const s = n.add(n.mul(h_mod_n, q_mod_n), m2_mod_n);

        s.toBytes(out[0..k], .big) catch return error.InvalidKey;
        var recovered: [max_signature_len]u8 = undefined;
        const back = n.powWithEncodedPublicExponent(s, self.e, .big) catch return error.InvalidKey;
        back.toBytes(recovered[0..k], .big) catch return error.InvalidKey;
        if (!mem.eql(u8, recovered[0..k], in)) {
            @memset(out[0..k], 0);
            return error.InvalidKey;
        }
    }
};

fn padded(buf: *[max_prime_len]u8, v: []const u8, len: usize) Error![]const u8 {
    if (v.len > len) return error.InvalidKey;
    @memset(buf[0 .. len - v.len], 0);
    @memcpy(buf[len - v.len ..][0..v.len], v);
    return buf[0..len];
}

/// EMSA-PSS-ENCODE (RFC 8017 §9.1.1), written right-aligned into `out`,
/// which is the modulus length: a leading zero byte when em_bits is a
/// multiple of 8.
fn encodePss(comptime Hash: type, msg: []const u8, salt: *const [Hash.digest_length]u8, em_bits: usize, out: []u8) Error!void {
    const h_len = Hash.digest_length;
    const em_len = (em_bits + 7) / 8;
    if (em_len < 2 * h_len + 2 or em_len > out.len) return error.UnsupportedKey;
    @memset(out[0 .. out.len - em_len], 0);
    const em = out[out.len - em_len ..];

    var m_hash: [h_len]u8 = undefined;
    Hash.hash(msg, &m_hash, .{});
    var h: [h_len]u8 = undefined;
    var hasher: Hash = .init(.{});
    hasher.update(&@as([8]u8, @splat(0)));
    hasher.update(&m_hash);
    hasher.update(salt);
    hasher.final(&h);

    // DB = PS || 0x01 || salt, masked with MGF1(H).
    const db = em[0 .. em_len - h_len - 1];
    @memset(db[0 .. db.len - h_len - 1], 0);
    db[db.len - h_len - 1] = 0x01;
    @memcpy(db[db.len - h_len ..], salt);
    var counter: u32 = 0;
    var i: usize = 0;
    while (i < db.len) : (counter += 1) {
        var block: [h_len]u8 = undefined;
        var mgf: Hash = .init(.{});
        mgf.update(&h);
        var c: [4]u8 = undefined;
        mem.writeInt(u32, &c, counter, .big);
        mgf.update(&c);
        mgf.final(&block);
        const n = @min(h_len, db.len - i);
        for (db[i..][0..n], block[0..n]) |*d, b| d.* ^= b;
        i += n;
    }
    db[0] &= @as(u8, 0xff) >> @intCast(8 * em_len - em_bits);
    @memcpy(em[em_len - h_len - 1 ..][0..h_len], &h);
    em[em_len - 1] = 0xbc;
}

const tag_sequence = 0x30;
const tag_integer = 0x02;
const tag_octet_string = 0x04;
const tag_null = 0x05;
const tag_oid = 0x06;

/// Minimal DER reader: definite lengths only, every read bounds-checked.
const Reader = struct {
    buf: []const u8,
    pos: usize = 0,

    fn done(r: *const Reader) bool {
        return r.pos == r.buf.len;
    }

    fn element(r: *Reader, tag: u8) Error![]const u8 {
        if (r.buf.len - r.pos < 2 or r.buf[r.pos] != tag) return error.DecodeError;
        var len: usize = r.buf[r.pos + 1];
        r.pos += 2;
        if (len & 0x80 != 0) {
            const n = len & 0x7f;
            // Keys are far below 16 MiB.
            if (n == 0 or n > 3 or r.buf.len - r.pos < n) return error.DecodeError;
            len = 0;
            for (r.buf[r.pos..][0..n]) |b| len = (len << 8) | b;
            r.pos += n;
        }
        if (r.buf.len - r.pos < len) return error.DecodeError;
        defer r.pos += len;
        return r.buf[r.pos..][0..len];
    }

    /// A non-negative INTEGER's magnitude, leading zeros stripped (so zero
    /// is empty).
    fn unsigned(r: *Reader) Error![]const u8 {
        const v = try r.element(tag_integer);
        if (v.len == 0 or v[0] & 0x80 != 0) return error.DecodeError;
        return mem.trimStart(u8, v, &.{0});
    }
};

// ─── Tests ───────────────────────────────────────────────────────────

const testing = std.testing;
const test_certs = @import("../tls/test_certs.zig");
const Sha256 = std.crypto.hash.sha2.Sha256;
const Sha384 = std.crypto.hash.sha2.Sha384;
const Sha512 = std.crypto.hash.sha2.Sha512;
const Certificate = std.crypto.Certificate;

fn pemDer(pem: []const u8, label: []const u8, out: []u8) ![]const u8 {
    var it = mem.splitScalar(u8, pem, '\n');
    var b64: [4096]u8 = undefined;
    var len: usize = 0;
    var inside = false;
    while (it.next()) |line| {
        if (mem.startsWith(u8, line, "-----BEGIN ")) {
            inside = mem.indexOf(u8, line, label) != null;
        } else if (mem.startsWith(u8, line, "-----END ")) {
            inside = false;
        } else if (inside) {
            @memcpy(b64[len..][0..line.len], line);
            len += line.len;
        }
    }
    const n = try std.base64.standard.Decoder.calcSizeForSlice(b64[0..len]);
    try std.base64.standard.Decoder.decode(out[0..n], b64[0..len]);
    return out[0..n];
}

fn testKey(buf: []u8) !PrivateKey {
    return PrivateKey.parsePkcs1(try pemDer(test_certs.test_rsa_key_pkcs1_pem, "RSA PRIVATE KEY", buf));
}

fn leafPublicKey(buf: []u8) !Certificate.rsa.PublicKey {
    const cert_der = try pemDer(test_certs.test_rsa_pem, "CERTIFICATE", buf);
    const parsed = try (Certificate{ .buffer = cert_der, .index = 0 }).parse();
    const pk = try Certificate.rsa.PublicKey.parseDer(parsed.pubKey());
    return Certificate.rsa.PublicKey.fromBytes(pk.exponent, pk.modulus);
}

test "PKCS#1 and PKCS#8 encodings parse to the same key" {
    var buf1: [2048]u8 = undefined;
    var buf8: [2048]u8 = undefined;
    const k1 = try testKey(&buf1);
    const k8 = try PrivateKey.parsePkcs1(try PrivateKey.pkcs1FromPkcs8(try pemDer(test_certs.test_rsa_key_pem, "PRIVATE KEY", &buf8)));
    try testing.expectEqual(2048, k1.modulusBits());
    inline for (.{ "n", "e", "p", "q", "dp", "dq", "qinv" }) |f| {
        try testing.expectEqualSlices(u8, @field(k1, f), @field(k8, f));
    }
    try k1.check();

    // The key is the certificate's.
    var cert_buf: [2048]u8 = undefined;
    const cert_der = try pemDer(test_certs.test_rsa_pem, "CERTIFICATE", &cert_buf);
    const parsed = try (Certificate{ .buffer = cert_der, .index = 0 }).parse();
    const pk = try Certificate.rsa.PublicKey.parseDer(parsed.pubKey());
    try testing.expectEqualSlices(u8, k1.n, pk.modulus);
}

test "PSS signatures verify with std's verifier, for every TLS hash" {
    var buf: [2048]u8 = undefined;
    const key = try testKey(&buf);
    var cert_buf: [2048]u8 = undefined;
    const public = try leafPublicKey(&cert_buf);
    var sig: [max_signature_len]u8 = undefined;
    inline for (.{ Sha256, Sha384, Sha512 }) |H| {
        const s = try key.signPss(H, "message", &sig);
        try testing.expectEqual(256, s.len);
        try Certificate.rsa.PSSSignature.verify(256, s[0..256].*, "message", public, H);
        try testing.expectError(error.InvalidSignature, Certificate.rsa.PSSSignature.verify(256, s[0..256].*, "massage", public, H));
    }
}

test "a PSS signature matches one OpenSSL verified" {
    // `openssl pkeyutl -verify -pkeyopt rsa_padding_mode:pss -pkeyopt
    // rsa_pss_saltlen:32 -pkeyopt digest:sha256` accepts this signature of
    // "quic-zig rsa-pss fixture" under test_rsa_pem's key, salt 0x00..0x1f.
    var buf: [2048]u8 = undefined;
    const key = try testKey(&buf);
    var salt: [32]u8 = undefined;
    for (&salt, 0..) |*b, i| b.* = @intCast(i);
    var sig: [max_signature_len]u8 = undefined;
    const s = try key.signPssWithSalt(Sha256, "quic-zig rsa-pss fixture", &salt, &sig);
    var expected: [256]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected, test_certs.test_rsa_pss_fixture_hex);
    try testing.expectEqualSlices(u8, &expected, s);
}

test "keys that do not fit together are rejected" {
    var buf: [2048]u8 = undefined;
    const good = try testKey(&buf);

    var bad = good;
    bad.dp = good.dq; // wrong CRT exponent
    try testing.expectError(error.InvalidKey, bad.check());

    bad = good;
    bad.qinv = good.dp;
    try testing.expectError(error.InvalidKey, bad.check());

    // Swapped primes keep p*q but break qinv.
    bad = good;
    bad.p = good.q;
    bad.q = good.p;
    bad.dp = good.dq;
    bad.dq = good.dp;
    try testing.expectError(error.InvalidKey, bad.check());
}

test "malformed and unsupported encodings" {
    var buf: [2048]u8 = undefined;
    const der = try pemDer(test_certs.test_rsa_key_pkcs1_pem, "RSA PRIVATE KEY", &buf);
    // Every truncation fails cleanly.
    for (0..der.len) |n| try testing.expect(std.meta.isError(PrivateKey.parsePkcs1(der[0..n])));

    // Multi-prime (version 1).
    var copy: [2048]u8 = undefined;
    @memcpy(copy[0..der.len], der);
    const version_at = mem.indexOf(u8, der[0..8], &.{ 0x02, 0x01, 0x00 }).?;
    copy[version_at + 2] = 1;
    try testing.expectError(error.UnsupportedKey, PrivateKey.parsePkcs1(copy[0..der.len]));

    // An EC PKCS#8 key is not RSA.
    var ec_buf: [256]u8 = undefined;
    const ed = try pemDer(test_certs.test_ed25519_key_pem, "PRIVATE KEY", &ec_buf);
    try testing.expectError(error.UnsupportedKey, PrivateKey.pkcs1FromPkcs8(ed));
}
