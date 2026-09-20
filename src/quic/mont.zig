//! Montgomery modular exponentiation for RSA's two CRT halves.
//!
//! `std.crypto.ff` is general and correct but pays for it three times over on
//! this path: it carries 63-bit limbs (so a 1024-bit half needs 17 of them, not
//! 16), and unless `side_channels_mitigations` is `.none` it synthesises every
//! 64x64 product from four 32x32 multiplies to defend against cores whose
//! multiplier is data dependent. aarch64 and x86-64 both multiply in constant
//! time, so that costs about half the inner loop and buys nothing.
//!
//! This is the narrow replacement: full 64-bit limbs, one `u128` product per
//! limb pair, and a 4-bit window. Turning the mitigation off globally is not an
//! alternative, because it also turns `ff`'s window table lookup into a
//! secret-indexed load, which leaks the private exponent through the cache.
//!
//! Constant time in the exponent and the base: the number of multiplications
//! depends only on the modulus and exponent *lengths*, the window table is read
//! with a conditional-move scan rather than an index, and every conditional
//! subtraction is done by masking.

const std = @import("std");
const assert = std.debug.assert;

/// Widest modulus, in bits. RSA-4096's CRT halves are 2048 bits.
pub const max_bits = 2048;
pub const max_limbs = max_bits / 64;

const window_bits = 4;
const table_len = 1 << window_bits;

pub const Error = error{
    /// Not an odd modulus of 1 to `max_limbs` limbs, or an operand wider than it.
    InvalidModulus,
};

/// Little-endian limbs of a number the size of one modulus.
const Limbs = [max_limbs]u64;

/// An odd modulus, prepared once: Montgomery needs -m^-1 mod 2^64.
pub const Modulus = struct {
    limbs: Limbs,
    /// Limbs in use; the rest are zero.
    len: usize,
    /// -m[0]^-1 mod 2^64.
    n0inv: u64,

    /// `bytes` is a big-endian magnitude. Leading zeros are allowed.
    pub fn fromBytes(bytes: []const u8) Error!Modulus {
        var self: Modulus = .{ .limbs = @splat(0), .len = 0, .n0inv = 0 };
        try bytesToLimbs(&self.limbs, bytes);
        self.len = limbsUsed(&self.limbs);
        if (self.len == 0 or self.limbs[0] & 1 == 0) return error.InvalidModulus;
        self.n0inv = 0 -% invMod64(self.limbs[0]);
        return self;
    }

    /// Bytes needed to hold a residue: the modulus length, rounded up.
    pub fn byteLength(self: *const Modulus) usize {
        return self.len * 8;
    }

    /// out = base^exp mod m, both big-endian magnitudes. `out` is written
    /// right-aligned and zero-padded, so its length fixes the encoding. The
    /// exponent's encoded length sets the work done, so pad it to hide the
    /// exponent's own size.
    pub fn pow(self: *const Modulus, base: []const u8, exp: []const u8, out: []u8) Error!void {
        var b: Limbs = @splat(0);
        try bytesToLimbs(&b, base);
        defer std.crypto.secureZero(u64, &b);
        // A base at or above the modulus would leave the table outside the
        // residue class; callers reduce first, so this is a contract check.
        if (limbsUsed(&b) > self.len or cmp(&b, &self.limbs, self.len) >= 0) return error.InvalidModulus;

        // base * R mod m, by doubling: it avoids needing R^2 mod m at all.
        var table: [table_len]Limbs = undefined;
        defer for (&table) |*t| std.crypto.secureZero(u64, t);
        table[1] = b;
        for (0..self.len * 64) |_| self.double(&table[1]);

        // table[0] is 1 in Montgomery form, which is R mod m: 1 doubled as often.
        table[0] = @splat(0);
        table[0][0] = 1;
        for (0..self.len * 64) |_| self.double(&table[0]);
        for (2..table_len) |i| table[i] = self.mul(&table[i - 1], &table[1]);

        var acc = table[0];
        defer std.crypto.secureZero(u64, &acc);
        var first = true;
        for (exp) |byte| {
            for ([2]u3{ 4, 0 }) |shift| {
                if (!first) {
                    for (0..window_bits) |_| acc = self.mul(&acc, &acc);
                }
                first = false;
                const w: u64 = (byte >> shift) & (table_len - 1);
                var chosen: Limbs = @splat(0);
                for (&table, 0..) |*t, i| cmov(&chosen, t, eq(i, w), self.len);
                acc = self.mul(&acc, &chosen);
                std.crypto.secureZero(u64, &chosen);
            }
        }

        // Out of Montgomery form: multiply by 1.
        var one: Limbs = @splat(0);
        one[0] = 1;
        const r = self.mul(&acc, &one);
        limbsToBytes(out, &r, self.len);
    }

    /// x = 2x mod m, for x below m.
    fn double(self: *const Modulus, x: *Limbs) void {
        var carry: u64 = 0;
        for (x[0..self.len]) |*limb| {
            const top = limb.* >> 63;
            limb.* = (limb.* << 1) | carry;
            carry = top;
        }
        // Subtract when the shift overflowed, or the result reached the modulus.
        var t: Limbs = @splat(0);
        const borrow = sub(&t, x, &self.limbs, self.len);
        cmov(x, &t, carry | (1 - borrow), self.len);
    }

    /// Montgomery product: a * b * R^-1 mod m, for a and b below m.
    ///
    /// Dispatched on the limb count so the inner loops have a comptime length:
    /// 16, 24 and 32 limbs are the CRT halves of 2048-, 3072- and 4096-bit keys,
    /// which is every size this library accepts. A runtime length falls through
    /// to the same code, just without unrolling.
    fn mul(self: *const Modulus, a: *const Limbs, b: *const Limbs) Limbs {
        return switch (self.len) {
            inline 16, 24, 32 => |fixed| mulLen(self, a, b, fixed),
            else => mulLen(self, a, b, null),
        };
    }

    fn mulLen(self: *const Modulus, a: *const Limbs, b: *const Limbs, comptime fixed: ?usize) Limbs {
        const len = if (fixed) |f| f else self.len;
        // One limb of headroom above the modulus, plus one for the carry out.
        var t: [max_limbs + 2]u64 = @splat(0);
        defer std.crypto.secureZero(u64, &t);
        for (0..len) |i| {
            var carry: u64 = 0;
            for (0..len) |j| {
                // Each term is at most (2^64-1)^2 + 2(2^64-1), which is u128's range.
                const p = @as(u128, a.*[j]) * b.*[i] + t[j] + carry;
                t[j] = @truncate(p);
                carry = @intCast(p >> 64);
            }
            var s = @as(u128, t[len]) + carry;
            t[len] = @truncate(s);
            t[len + 1] +%= @intCast(s >> 64);

            const u = t[0] *% self.n0inv;
            carry = 0;
            for (0..len) |j| {
                const p = @as(u128, u) * self.limbs[j] + t[j] + carry;
                t[j] = @truncate(p);
                carry = @intCast(p >> 64);
            }
            s = @as(u128, t[len]) + carry;
            t[len] = @truncate(s);
            t[len + 1] +%= @intCast(s >> 64);
            // t[0] is now zero by construction: shift one limb down.
            for (0..len + 1) |j| t[j] = t[j + 1];
            t[len + 1] = 0;
        }

        var r: Limbs = @splat(0);
        @memcpy(r[0..len], t[0..len]);
        // The result is below 2m, and t[len] holds the bit above it.
        var reduced: Limbs = @splat(0);
        const borrow = sub(&reduced, &r, &self.limbs, len);
        cmov(&r, &reduced, t[len] | (1 - borrow), len);
        return r;
    }
};

/// dst = a - b, returning 1 when it borrowed, i.e. when a < b.
fn sub(dst: *Limbs, a: *const Limbs, b: *const Limbs, len: usize) u64 {
    var borrow: u64 = 0;
    for (0..len) |i| {
        const d = @as(u128, a.*[i]) -% @as(u128, b.*[i]) -% borrow;
        dst.*[i] = @truncate(d);
        borrow = @intCast((d >> 64) & 1);
    }
    return borrow;
}

/// -1, 0 or 1, in constant time for a fixed length.
fn cmp(a: *const Limbs, b: *const Limbs, len: usize) i2 {
    var gt: u64 = 0;
    var lt: u64 = 0;
    for (0..len) |i| {
        const x = a.*[len - 1 - i];
        const y = b.*[len - 1 - i];
        const decided = gt | lt;
        gt |= @intFromBool(x > y) & (1 -% decided);
        lt |= @intFromBool(x < y) & (1 -% decided);
    }
    if (gt != 0) return 1;
    if (lt != 0) return -1;
    return 0;
}

/// dst = src where `take` is 1, unchanged where it is 0.
fn cmov(dst: *Limbs, src: *const Limbs, take: u64, len: usize) void {
    const mask = 0 -% take;
    for (0..len) |i| dst.*[i] = (dst.*[i] & ~mask) | (src.*[i] & mask);
}

/// 1 when i equals w, without branching on either.
fn eq(i: usize, w: u64) u64 {
    return @intFromBool((@as(u64, @intCast(i)) ^ w) == 0);
}

/// a^-1 mod 2^64, for odd a, by Newton's method: each step doubles the bits.
fn invMod64(a: u64) u64 {
    var x: u64 = 1;
    for (0..6) |_| x = x *% (2 -% a *% x);
    return x;
}

fn bytesToLimbs(out: *Limbs, bytes: []const u8) Error!void {
    out.* = @splat(0);
    if (bytes.len > max_limbs * 8) {
        // Wider only by leading zeros is still fine.
        for (bytes[0 .. bytes.len - max_limbs * 8]) |b| if (b != 0) return error.InvalidModulus;
    }
    const tail = bytes[if (bytes.len > max_limbs * 8) bytes.len - max_limbs * 8 else 0..];
    for (tail, 0..) |b, i| {
        const from_end = tail.len - 1 - i;
        out.*[from_end / 8] |= @as(u64, b) << @intCast((from_end % 8) * 8);
    }
}

fn limbsToBytes(out: []u8, limbs: *const Limbs, len: usize) void {
    @memset(out, 0);
    for (0..len) |i| {
        const limb = limbs.*[i];
        for (0..8) |j| {
            const from_end = i * 8 + j;
            if (from_end >= out.len) break;
            out[out.len - 1 - from_end] = @truncate(limb >> @intCast(j * 8));
        }
    }
}

fn limbsUsed(limbs: *const Limbs) usize {
    var n: usize = max_limbs;
    while (n > 0 and limbs.*[n - 1] == 0) n -= 1;
    return n;
}

const ff = std.crypto.ff;

// Agrees with std.crypto.ff on random odd moduli, bases and exponents, at the
// widths RSA's CRT halves actually take.
test "matches std.crypto.ff" {
    var prng = std.Random.DefaultPrng.init(0x5eed);
    const rand = prng.random();
    inline for ([_]usize{ 1024, 1536, 2048 }) |bits| {
        const Ff = ff.Modulus(bits);
        const bytes = bits / 8;
        for (0..8) |_| {
            var m_bytes: [bytes]u8 = undefined;
            rand.bytes(&m_bytes);
            m_bytes[0] |= 0x80; // full width
            m_bytes[bytes - 1] |= 1; // odd
            var base: [bytes]u8 = undefined;
            rand.bytes(&base);
            base[0] &= 0x7f; // below the modulus
            var exp: [bytes]u8 = undefined;
            rand.bytes(&exp);

            const fm = try Ff.fromBytes(&m_bytes, .big);
            const want_fe = try fm.powWithEncodedExponent(try Ff.Fe.fromBytes(fm, &base, .big), &exp, .big);
            var want: [bytes]u8 = undefined;
            try want_fe.toBytes(&want, .big);

            const mm = try Modulus.fromBytes(&m_bytes);
            var got: [bytes]u8 = undefined;
            try mm.pow(&base, &exp, &got);
            try std.testing.expectEqualSlices(u8, &want, &got);
        }
    }
}

test "small values by hand" {
    // 3^7 mod 2753 = 2187; 2^10 mod 2753 = 1024.
    const m = [_]u8{ 0x0a, 0xc1 }; // 2753
    const mm = try Modulus.fromBytes(&m);
    var out: [2]u8 = undefined;
    try mm.pow(&[_]u8{ 0, 3 }, &[_]u8{7}, &out);
    try std.testing.expectEqual(@as(u16, 2187), std.mem.readInt(u16, &out, .big));
    try mm.pow(&[_]u8{ 0, 2 }, &[_]u8{10}, &out);
    try std.testing.expectEqual(@as(u16, 1024), std.mem.readInt(u16, &out, .big));
    // x^0 is 1, and 1^x is 1.
    try mm.pow(&[_]u8{ 0, 5 }, &[_]u8{0}, &out);
    try std.testing.expectEqual(@as(u16, 1), std.mem.readInt(u16, &out, .big));
    try mm.pow(&[_]u8{ 0, 1 }, &[_]u8{ 0xff, 0xff }, &out);
    try std.testing.expectEqual(@as(u16, 1), std.mem.readInt(u16, &out, .big));
    // Zero stays zero.
    try mm.pow(&[_]u8{ 0, 0 }, &[_]u8{5}, &out);
    try std.testing.expectEqual(@as(u16, 0), std.mem.readInt(u16, &out, .big));
}

test "the exponent's encoded length sets the work, not its value" {
    const m = [_]u8{ 0x0a, 0xc1 };
    const mm = try Modulus.fromBytes(&m);
    var a: [2]u8 = undefined;
    var b: [2]u8 = undefined;
    try mm.pow(&[_]u8{ 0, 3 }, &[_]u8{7}, &a);
    try mm.pow(&[_]u8{ 0, 3 }, &[_]u8{ 0, 0, 0, 7 }, &b);
    try std.testing.expectEqualSlices(u8, &a, &b);
}

test "rejects an even modulus and an out-of-range base" {
    try std.testing.expectError(error.InvalidModulus, Modulus.fromBytes(&[_]u8{ 0x0a, 0xc0 }));
    try std.testing.expectError(error.InvalidModulus, Modulus.fromBytes(&[_]u8{0}));
    const mm = try Modulus.fromBytes(&[_]u8{ 0x0a, 0xc1 });
    var out: [2]u8 = undefined;
    try std.testing.expectError(error.InvalidModulus, mm.pow(&[_]u8{ 0x0a, 0xc1 }, &[_]u8{3}, &out));
}
