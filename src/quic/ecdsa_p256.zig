//! ECDSA P-256 with SHA-256 signing, with k·G from a precomputed table.
//!
//! std's `EcdsaP256Sha256` multiplies the base point the way it multiplies any
//! point: 64 additions and 252 doublings, 440 µs on an x86_64 server core, most
//! of a TLS or QUIC handshake's server-side cost. Signing only ever multiplies
//! the base point, so this keeps every multiple j·16^i·G (i < 64, 0 < j < 16)
//! as affine coordinates and adds one per nibble of k: 64 mixed additions and
//! no doublings. Each nibble's point is picked by a conditional-move scan of
//! all 15, so which one is read does not depend on k.
//!
//! The table (60 KiB) is built on first use, in about a millisecond. A
//! signature asked for while another thread builds it multiplies the std way
//! instead of waiting.
//!
//! Everything else follows std's `Signer.finalizePrehashed` (Zig 0.16.0) step
//! for step, including its hedged deterministic nonce, so for the same key,
//! message and noise the signature is byte-identical to std's; the tests hold
//! it to that. See DECISIONS/zig_std_divergences.md.

const std = @import("std");
const crypto = std.crypto;
const P256 = crypto.ecc.P256;
const Fe = P256.Fe;
const Scalar = P256.scalar.Scalar;
/// Not exported by `std.crypto`; `affineCoordinates` names it.
const AffineCoordinates = @typeInfo(@TypeOf(P256.affineCoordinates)).@"fn".return_type.?;
const Ecdsa = crypto.sign.ecdsa.EcdsaP256Sha256;
const Sha256 = crypto.hash.sha2.Sha256;
const Prf = crypto.auth.hmac.Hmac(Sha256);

pub const noise_length = Ecdsa.noise_length;

/// `j·16^i·G` at `[i][j - 1]`.
var table: [64][15]AffineCoordinates = undefined;
var table_state: std.atomic.Value(u8) = .init(unbuilt);
const unbuilt = 0;
const building = 1;
const built = 2;

fn buildTable() void {
    // Projective first, then one field inversion for all 960 points
    // (Montgomery's trick): an inversion each took 35 ms in a release build
    // and seconds in a debug one, all of it in the first handshake.
    var points: [64 * 15]P256 = undefined;
    var base = P256.basePoint; // 16^i·G
    for (0..64) |i| {
        var p = base;
        for (0..15) |j| {
            if (j > 0) p = p.add(base);
            points[i * 15 + j] = p;
        }
        base = base.dbl().dbl().dbl().dbl();
    }
    // prefix[n] = z_0 · … · z_n; none is zero, as no j·16^i·G is the identity.
    var prefix: [points.len]Fe = undefined;
    var acc = Fe.one;
    for (points, &prefix) |p, *pre| {
        acc = acc.mul(p.z);
        pre.* = acc;
    }
    var inv = acc.invert(); // 1 / (z_0 · … · z_last)
    var n = points.len;
    while (n > 0) {
        n -= 1;
        const zinv = if (n > 0) inv.mul(prefix[n - 1]) else inv;
        inv = inv.mul(points[n].z);
        table[n / 15][n % 15] = .{ .x = points[n].x.mul(zinv), .y = points[n].y.mul(zinv) };
    }
}

/// The table, built by this call if nobody has; null while another thread
/// is building it.
fn readyTable() ?*const [64][15]AffineCoordinates {
    switch (table_state.load(.acquire)) {
        built => return &table,
        building => return null,
        else => {},
    }
    if (table_state.cmpxchgStrong(unbuilt, building, .acquire, .acquire) != null) {
        return if (table_state.load(.acquire) == built) &table else null;
    }
    buildTable();
    table_state.store(built, .release);
    return &table;
}

/// k·G for a scalar in little-endian bytes, in constant time.
fn mulBase(t: *const [64][15]AffineCoordinates, k: [32]u8) P256 {
    var q = P256.identityElement;
    for (t, 0..) |*row, i| {
        const digit: u8 = (k[i / 2] >> @intCast(4 * (i % 2))) & 0xf;
        // x = 0 is `addMixed`'s identity: nibble 0 adds nothing.
        var pick: AffineCoordinates = .{ .x = Fe.zero, .y = Fe.zero };
        for (row, 1..) |*entry, j| {
            const hit: u1 = @intFromBool(digit == j);
            pick.x.cMov(entry.x, hit);
            pick.y.cMov(entry.y, hit);
        }
        q = q.addMixed(pick);
    }
    return q;
}

/// std's `Ecdsa.KeyPair.sign` for P-256/SHA-256, from the secret key alone.
pub fn sign(secret_key: [32]u8, msg: []const u8, noise: ?[noise_length]u8) (crypto.errors.IdentityElementError || crypto.errors.NonCanonicalError)!Ecdsa.Signature {
    var msg_hash: [Sha256.digest_length]u8 = undefined;
    Sha256.hash(msg, &msg_hash, .{});

    const z = reduceToScalar(msg_hash);
    const k = deterministicScalar(msg_hash, secret_key, noise);

    const p = if (readyTable()) |t|
        mulBase(t, k.toBytes(.little))
    else
        try P256.basePoint.mul(k.toBytes(.big), .big);
    const r = reduceToScalar(p.affineCoordinates().x.toBytes(.big));
    if (r.isZero()) return error.IdentityElement;

    const k_inv = k.invert();
    const zrs = z.add(r.mul(try Scalar.fromBytes(secret_key, .big)));
    const s = k_inv.mul(zrs);
    if (s.isZero()) return error.IdentityElement;

    return .{ .r = r.toBytes(.big), .s = s.toBytes(.big) };
}

fn reduceToScalar(s: [32]u8) Scalar {
    var xs: [48]u8 = @splat(0);
    @memcpy(xs[xs.len - s.len ..], s[0..]);
    return Scalar.fromBytes48(xs, .big);
}

/// std's, verbatim but for the types: the "Deterministic ECDSA and EdDSA
/// Signatures with Additional Randomness" construction.
fn deterministicScalar(h: [Sha256.digest_length]u8, secret_key: [32]u8, noise: ?[noise_length]u8) Scalar {
    var k: [h.len]u8 = @splat(0x00);
    var m: [(h.len + 1 + noise_length + secret_key.len + h.len)]u8 = @splat(0x00);
    var t: [P256.scalar.encoded_length]u8 = @splat(0x00);
    const m_v = m[0..h.len];
    const m_i = &m[m_v.len];
    const m_z = m[m_v.len + 1 ..][0..noise_length];
    const m_x = m[m_v.len + 1 + noise_length ..][0..secret_key.len];
    const m_h = m[m.len - h.len ..];

    @memset(m_v, 0x01);
    m_i.* = 0x00;
    if (noise) |n| @memcpy(m_z, &n);
    @memcpy(m_x, &secret_key);
    @memcpy(m_h, &h);
    Prf.create(&k, &m, &k);
    Prf.create(m_v, m_v, &k);
    m_i.* = 0x01;
    Prf.create(&k, &m, &k);
    Prf.create(m_v, m_v, &k);
    while (true) {
        var t_off: usize = 0;
        while (t_off < t.len) : (t_off += m_v.len) {
            const t_end = @min(t_off + m_v.len, t.len);
            Prf.create(m_v, m_v, &k);
            @memcpy(t[t_off..t_end], m_v[0 .. t_end - t_off]);
        }
        if (Scalar.fromBytes(t, .big)) |s| return s else |_| {}
        m_i.* = 0x00;
        Prf.create(&k, m[0 .. m_v.len + 1], &k);
        Prf.create(m_v, m_v, &k);
    }
}

const testing = std.testing;

test "the table's k·G is std's, for scalars from 1 to near the order" {
    const t = readyTable().?;
    var prng = std.Random.DefaultPrng.init(0x256);
    const r = prng.random();
    var cases: [300][32]u8 = undefined;
    for (&cases, 0..) |*c, n| switch (n) {
        0 => c.* = Scalar.one.toBytes(.little),
        1 => c.* = Scalar.one.neg().toBytes(.little), // n - 1
        2 => c.* = Scalar.one.add(Scalar.one).toBytes(.little),
        else => {
            var wide: [48]u8 = undefined;
            r.bytes(&wide);
            c.* = Scalar.fromBytes48(wide, .big).toBytes(.little);
        },
    };
    for (cases) |k| {
        const ours = mulBase(t, k);
        const theirs = try P256.basePoint.mul(k, .little);
        try testing.expect(ours.equivalent(theirs));
    }
}

test "signatures are byte-identical to std's and verify" {
    var prng = std.Random.DefaultPrng.init(0x6979);
    const r = prng.random();
    for (0..40) |n| {
        var seed: [32]u8 = undefined;
        r.bytes(&seed);
        const kp = try Ecdsa.KeyPair.generateDeterministic(seed);
        var msg: [200]u8 = undefined;
        r.bytes(&msg);
        const len = r.uintAtMost(usize, msg.len);
        var noise: [noise_length]u8 = undefined;
        r.bytes(&noise);
        const nz: ?[noise_length]u8 = if (n % 3 == 0) null else noise;

        const ours = try sign(kp.secret_key.toBytes(), msg[0..len], nz);
        const theirs = try kp.sign(msg[0..len], nz);
        try testing.expectEqualSlices(u8, &theirs.r, &ours.r);
        try testing.expectEqualSlices(u8, &theirs.s, &ours.s);
        try ours.verify(msg[0..len], kp.public_key);
    }
}
