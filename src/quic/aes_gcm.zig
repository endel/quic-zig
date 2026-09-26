//! AES-128-GCM with the per-key work done once. std's `Aes128Gcm` takes the
//! raw key on every call, so each packet re-expands the AES key, re-derives
//! H and recomputes H's powers for GHASH. A packet protection key encrypts
//! millions of packets, so `Ctx` does that at key installation.
//!
//! The per-message steps follow std's `AesGcm.encrypt`/`decrypt` (Zig
//! 0.16.0), including checking the tag before decrypting.
//!
//! With hardware AES, CTR runs 8 blocks at a time with the round keys held in
//! registers, and the tail as one batch of exactly the blocks left, with the
//! tag mask as one more lane. On arm64 each round is `aese` with the round key
//! plus `aesmc`, a pair the core fuses. std's armcrypto rounds are `aese` with
//! a zero key, `aesmc`, then an `eor` of the round key, with operands limited
//! to v0-v15, so 6+ blocks and 11 round keys don't fit and keys get reloaded.
//! On arm64 GHASH also runs in vector registers (see `vec_ghash`). Elsewhere
//! GHASH is `ghash.zig`, and without hardware AES, CTR is std's.
//! See DECISIONS/zig_std_divergences.md.

const std = @import("std");
const builtin = @import("builtin");
const crypto = std.crypto;
const mem = std.mem;
const Aes128 = crypto.core.aes.Aes128;
const Block = crypto.core.aes.Block;
const Ghash = @import("ghash.zig").Ghash;

/// AES-NI or ARMv8 crypto: both store a block as this vector.
const fast = crypto.core.aes.has_hardware_support and builtin.zig_backend != .stage2_c and
    builtin.cpu.arch.endian() == .little;
const V = @Vector(2, u64);
/// Blocks per CTR step. 8 in flight plus 11 round keys fit arm64's 32 vector
/// registers.
const wide = 8;
const RoundKeys = [Aes128.rounds + 1]Block;

/// arm64: GHASH in vector registers. `ghash.zig` does its arithmetic on u128,
/// which LLVM keeps in general registers, so every multiply moves operands
/// across and back. Same multiply and reduction, on vectors.
const vec_ghash = fast and builtin.cpu.arch == .aarch64 and builtin.mode != .ReleaseSmall;
/// Powers of H that `Ghash.init` computes: H, H^2, ... H^16.
const pc_count = @typeInfo(@FieldType(Ghash, "hx")).array.len;
/// Byte order of GHASH's big-endian 128-bit integers.
const reversed: [16]i32 = blk: {
    var r: [16]i32 = undefined;
    for (&r, 0..) |*x, i| x.* = 15 - @as(i32, @intCast(i));
    break :blk r;
};

inline fn loadBlock(b: *const [16]u8) V {
    return @bitCast(@shuffle(u8, @as(@Vector(16, u8), b.*), undefined, reversed));
}

inline fn pmullLo(x: V, y: V) V {
    return asm ("pmull %[o].1q, %[x].1d, %[y].1d"
        : [o] "=w" (-> V),
        : [x] "w" (x),
          [y] "w" (y),
    );
}

inline fn pmullHi(x: V, y: V) V {
    return asm ("pmull2 %[o].1q, %[x].2d, %[y].2d"
        : [o] "=w" (-> V),
        : [x] "w" (x),
          [y] "w" (y),
    );
}

inline fn swapHalves(x: V) V {
    return @shuffle(u64, x, undefined, [2]i32{ 1, 0 });
}

/// (acc ^ b[0])·H^k ^ b[1]·H^(k-1) ^ ... ^ b[k-1]·H, reduced once. The
/// schoolbook product and `reduce` of `ghash.zig`.
inline fn ghashBatch(comptime k: usize, hx: *const [pc_count]V, acc: V, b: [k]V) V {
    var lo: V = @splat(0);
    var hi: V = @splat(0);
    var mid: V = @splat(0);
    inline for (0..k) |j| {
        const x = if (j == 0) b[0] ^ acc else b[j];
        const h = hx[k - 1 - j];
        lo ^= pmullLo(x, h);
        hi ^= pmullHi(x, h);
        const xs = swapHalves(x);
        mid ^= pmullLo(xs, h) ^ pmullHi(xs, h);
    }
    const zero: V = @splat(0);
    hi ^= @shuffle(u64, mid, zero, [2]i32{ 1, -1 }); // mid >> 64
    lo ^= @shuffle(u64, mid, zero, [2]i32{ -1, 0 }); // mid << 64
    const p64: V = .{ 0xc200000000000000, 0 };
    const r = swapHalves(lo) ^ pmullLo(lo, p64);
    return swapHalves(r) ^ pmullLo(r, p64) ^ hi;
}

/// GHASH `msg` into `acc`, its last block zero-padded. `extra`, when given,
/// is one more block hashed in the same final batch.
fn ghashBlocks(hx: *const [pc_count]V, acc0: V, msg: []const u8, extra: ?V) V {
    var acc = acc0;
    var i: usize = 0;
    while (i + 16 * wide <= msg.len) : (i += 16 * wide) {
        var b: [wide]V = undefined;
        inline for (0..wide) |j| b[j] = loadBlock(msg[i + 16 * j ..][0..16]);
        acc = ghashBatch(wide, hx, acc, b);
    }
    switch ((msg.len - i + 15) / 16) {
        inline 0...wide => |k| {
            var b: [k + 1]V = undefined;
            if (k > 0) {
                inline for (0..k - 1) |j| b[j] = loadBlock(msg[i + 16 * j ..][0..16]);
                const last = i + 16 * (k - 1);
                var buf: [16]u8 = @splat(0);
                @memcpy(buf[0 .. msg.len - last], msg[last..]);
                b[k - 1] = loadBlock(&buf);
            }
            if (extra) |e| {
                b[k] = e;
                return ghashBatch(k + 1, hx, acc, b);
            }
            if (k == 0) return acc;
            return ghashBatch(k, hx, acc, b[0..k].*);
        },
        else => unreachable,
    }
}

pub const tag_length = 16;
pub const nonce_length = 12;
pub const key_length = 16;

pub const Ctx = struct {
    aes: @TypeOf(Aes128.initEnc(@as([key_length]u8, undefined))),
    h: [16]u8,
    /// GHASH keyed with H, all powers precomputed. The arm64 path only reads
    /// the powers; elsewhere this is copied per message.
    mac: Ghash,

    pub fn init(key: [key_length]u8) Ctx {
        const aes = Aes128.initEnc(key);
        var h: [16]u8 = undefined;
        aes.encrypt(&h, &@as([16]u8, @splat(0)));
        return .{ .aes = aes, .h = h, .mac = Ghash.init(&h) };
    }

    /// `c` and `m` may be the same buffer.
    pub fn encrypt(self: *const Ctx, c: []u8, tag: *[tag_length]u8, m: []const u8, ad: []const u8, npub: [nonce_length]u8) void {
        std.debug.assert(c.len == m.len);
        std.debug.assert(m.len <= 16 * ((1 << 32) - 2));

        const t = self.ctr(true, c, m, npub);
        tag.* = self.ghashTag(ad, c[0..m.len], t);
    }

    /// `m` and `c` may be the same buffer. Contents of `m` are undefined if
    /// an error is returned.
    pub fn decrypt(self: *const Ctx, m: []u8, c: []const u8, tag: [tag_length]u8, ad: []const u8, npub: [nonce_length]u8) crypto.errors.AuthenticationError!void {
        std.debug.assert(c.len == m.len);

        var computed_tag = self.ghashTag(ad, c, self.counterBlock(npub, 1));
        const verify = crypto.timing_safe.eql([tag_length]u8, computed_tag, tag);
        if (!verify) {
            crypto.secureZero(u8, &computed_tag);
            @memset(m, undefined);
            return error.AuthenticationFailed;
        }

        _ = self.ctr(false, m, c, npub);
    }

    /// GHASH(ad, c) XOR `mask`: the tag.
    fn ghashTag(self: *const Ctx, ad: []const u8, c: []const u8, mask: [16]u8) [16]u8 {
        var s: [16]u8 = undefined;
        if (vec_ghash) {
            const hx: *const [pc_count]V = @ptrCast(&self.mac.hx);
            const len_block = loadBlock(&lengthBlock(ad.len, c.len));
            const acc = ghashBlocks(hx, ghashBlocks(hx, @splat(0), ad, null), c, len_block);
            s = @bitCast(@shuffle(u8, @as(@Vector(16, u8), @bitCast(acc)), undefined, reversed));
        } else {
            var mac = self.mac;
            mac.update(ad);
            mac.pad();
            mac.update(c);
            mac.pad();
            mac.update(&lengthBlock(ad.len, c.len));
            mac.final(&s);
        }
        for (&s, mask) |*x, y| x.* ^= y;
        return s;
    }

    /// E(K, npub || BE32(n)).
    fn counterBlock(self: *const Ctx, npub: [nonce_length]u8, n: u32) [16]u8 {
        var out: [16]u8 = undefined;
        if (fast) {
            const rk = self.aes.key_schedule.round_keys;
            out = @bitCast(encryptBlocks(1, &rk, counters(1, counterBase(npub), n))[0]);
        } else {
            var j: [16]u8 = undefined;
            j[0..nonce_length].* = npub;
            mem.writeInt(u32, j[nonce_length..][0..4], n, .big);
            self.aes.encrypt(&out, &j);
        }
        return out;
    }

    /// GCM's CTR: counter blocks npub || BE32(2), BE32(3), ... `dst` and
    /// `src` may be the same buffer. With `mask`, also returns E(K, npub ||
    /// BE32(1)), the tag mask; otherwise the result is undefined.
    fn ctr(self: *const Ctx, comptime mask: bool, dst: []u8, src: []const u8, npub: [nonce_length]u8) [16]u8 {
        std.debug.assert(dst.len >= src.len);
        if (fast) return ctrFast(mask, &self.aes.key_schedule.round_keys, dst, src, npub);
        var j: [16]u8 = undefined;
        j[0..nonce_length].* = npub;
        mem.writeInt(u32, j[nonce_length..][0..4], 2, .big);
        crypto.core.modes.ctr(@TypeOf(self.aes), self.aes, dst, src, j, .big);
        return if (mask) self.counterBlock(npub, 1) else undefined;
    }

    fn ctrFast(comptime mask: bool, round_keys: *const RoundKeys, dst: []u8, src: []const u8, npub: [nonce_length]u8) [16]u8 {
        const rk = round_keys.*; // a local, so stores to dst can't alias it
        const base = counterBase(npub);
        var n: u32 = 2;
        var i: usize = 0;
        while (i + 16 * wide <= src.len) : (i += 16 * wide) {
            const ks = encryptBlocks(wide, &rk, counters(wide, base, n));
            n +%= wide;
            inline for (0..wide) |b| xorBlock(dst[i + 16 * b ..][0..16], src[i + 16 * b ..][0..16], ks[b]);
        }
        // The rest in one batch, the mask riding along as its last lane.
        switch ((src.len - i + 15) / 16) {
            inline 0...wide => |k| {
                const lanes = k + @intFromBool(mask);
                if (lanes == 0) return undefined;
                var ctrs: [lanes]V = undefined;
                ctrs[0..k].* = counters(k, base, n);
                if (mask) ctrs[k] = counters(1, base, 1)[0];
                const ks = encryptBlocks(lanes, &rk, ctrs);
                if (k > 0) {
                    inline for (0..k - 1) |b| xorBlock(dst[i + 16 * b ..][0..16], src[i + 16 * b ..][0..16], ks[b]);
                    const last = i + 16 * (k - 1);
                    const r = src.len - last;
                    var buf: [16]u8 = @splat(0);
                    @memcpy(buf[0..r], src[last..]);
                    xorBlock(&buf, &buf, ks[k - 1]);
                    @memcpy(dst[last..][0..r], buf[0..r]);
                }
                return if (mask) @bitCast(ks[k]) else undefined;
            },
            else => unreachable,
        }
    }

    inline fn xorBlock(dst: *[16]u8, src: *const [16]u8, ks: V) void {
        dst.* = @bitCast(@as(V, @bitCast(src.*)) ^ ks);
    }

    /// npub || 00000000, so a counter is OR-ed into the top half of lane 1.
    inline fn counterBase(npub: [nonce_length]u8) V {
        return @bitCast(npub ++ [_]u8{0} ** 4);
    }

    inline fn counters(comptime k: usize, base: V, n: u32) [k]V {
        var out: [k]V = undefined;
        inline for (0..k) |b| out[b] = base | V{ 0, @as(u64, @byteSwap(n +% @as(u32, b))) << 32 };
        return out;
    }

    /// AES-128 over `k` blocks, round by round so the blocks' rounds overlap.
    inline fn encryptBlocks(comptime k: usize, rk: *const RoundKeys, in: [k]V) [k]V {
        var s = in;
        if (builtin.cpu.arch == .aarch64) {
            inline for (0..Aes128.rounds - 1) |r| {
                inline for (0..k) |b| s[b] = asm (
                    \\ aese  %[s].16b, %[rk].16b
                    \\ aesmc %[s].16b, %[s].16b
                    : [s] "=w" (-> V),
                    : [_] "0" (s[b]),
                      [rk] "w" (rk[r].repr),
                );
            }
            inline for (0..k) |b| s[b] = asm (
                \\ aese %[s].16b, %[rk].16b
                : [s] "=w" (-> V),
                : [_] "0" (s[b]),
                  [rk] "w" (rk[Aes128.rounds - 1].repr),
            ) ^ rk[Aes128.rounds].repr;
        } else {
            inline for (0..k) |b| s[b] ^= rk[0].repr;
            inline for (1..Aes128.rounds) |r| {
                inline for (0..k) |b| s[b] = (Block{ .repr = s[b] }).encrypt(rk[r]).repr;
            }
            inline for (0..k) |b| s[b] = (Block{ .repr = s[b] }).encryptLast(rk[Aes128.rounds]).repr;
        }
        return s;
    }

    fn lengthBlock(ad_len: usize, m_len: usize) [16]u8 {
        var b: [16]u8 = undefined;
        mem.writeInt(u64, b[0..8], @as(u64, ad_len) * 8, .big);
        mem.writeInt(u64, b[8..16], @as(u64, m_len) * 8, .big);
        return b;
    }
};

const testing = std.testing;
const StdGcm = crypto.aead.aes_gcm.Aes128Gcm;

/// Seals `m` with `ctx` and std, in place and not, and checks they agree;
/// then opens it, and checks that a flipped tag, message or AD bit is refused.
fn checkAgainstStd(ctx: *const Ctx, key: [16]u8, npub: [12]u8, m: []const u8, ad: []u8, flip: usize) !void {
    var c_ours: [2048]u8 = undefined;
    var c_std: [2048]u8 = undefined;
    var tag_ours: [16]u8 = undefined;
    var tag_std: [16]u8 = undefined;
    ctx.encrypt(c_ours[0..m.len], &tag_ours, m, ad, npub);
    StdGcm.encrypt(c_std[0..m.len], &tag_std, m, ad, npub, key);
    try testing.expectEqualSlices(u8, c_std[0..m.len], c_ours[0..m.len]);
    try testing.expectEqualSlices(u8, &tag_std, &tag_ours);

    // in place, as packet protection uses it
    var buf: [2048]u8 = undefined;
    @memcpy(buf[0..m.len], m);
    var tag_in_place: [16]u8 = undefined;
    ctx.encrypt(buf[0..m.len], &tag_in_place, buf[0..m.len], ad, npub);
    try testing.expectEqualSlices(u8, c_std[0..m.len], buf[0..m.len]);
    try testing.expectEqualSlices(u8, &tag_std, &tag_in_place);
    try ctx.decrypt(buf[0..m.len], buf[0..m.len], tag_std, ad, npub);
    try testing.expectEqualSlices(u8, m, buf[0..m.len]);

    var bad_tag = tag_std;
    bad_tag[flip % 16] ^= 1;
    @memcpy(buf[0..m.len], c_std[0..m.len]);
    try testing.expectError(error.AuthenticationFailed, ctx.decrypt(buf[0..m.len], buf[0..m.len], bad_tag, ad, npub));
    if (m.len > 0) {
        @memcpy(buf[0..m.len], c_std[0..m.len]);
        buf[flip % m.len] ^= 0x80;
        try testing.expectError(error.AuthenticationFailed, ctx.decrypt(buf[0..m.len], buf[0..m.len], tag_std, ad, npub));
    }
    if (ad.len > 0) {
        @memcpy(buf[0..m.len], c_std[0..m.len]);
        ad[flip % ad.len] ^= 0x01;
        defer ad[flip % ad.len] ^= 0x01;
        try testing.expectError(error.AuthenticationFailed, ctx.decrypt(buf[0..m.len], buf[0..m.len], tag_std, ad, npub));
    }
}

test "Ctx matches std Aes128Gcm across lengths that cross every aggregation width" {
    var prng = std.Random.DefaultPrng.init(0x9e3779b97f4a7c15);
    const rand = prng.random();
    var m: [2048]u8 = undefined;
    var ad: [600]u8 = undefined;
    for (0..600) |iter| {
        var key: [16]u8 = undefined;
        var npub: [12]u8 = undefined;
        rand.bytes(&key);
        rand.bytes(&npub);
        // lengths around 4/8/16-way thresholds (in 16 B blocks), plus odd tails
        const m_len = if (iter < 200) iter * 7 else rand.uintAtMost(usize, m.len);
        const ad_len = if (iter % 3 == 0) rand.uintAtMost(usize, ad.len) else rand.uintAtMost(usize, 64);
        rand.bytes(m[0..m_len]);
        rand.bytes(ad[0..ad_len]);
        const ctx = Ctx.init(key);
        try checkAgainstStd(&ctx, key, npub, m[0..m_len], ad[0..ad_len], iter);
    }
}

test "Ctx matches std Aes128Gcm for every message length up to 20 blocks" {
    var prng = std.Random.DefaultPrng.init(0x2545f4914f6cdd1d);
    const rand = prng.random();
    var key: [16]u8 = undefined;
    var npub: [12]u8 = undefined;
    var m: [320]u8 = undefined;
    var ad: [300]u8 = undefined;
    rand.bytes(&key);
    rand.bytes(&npub);
    rand.bytes(&m);
    rand.bytes(&ad);
    const ctx = Ctx.init(key);
    for ([_]usize{ 0, 1, 15, 16, 17, 20, 127, 128, 129, 255, 256, 257, 300 }) |ad_len| {
        for (0..m.len + 1) |m_len| {
            try checkAgainstStd(&ctx, key, npub, m[0..m_len], ad[0..ad_len], m_len + ad_len);
        }
    }
}

test "Ctx passes Wycheproof's AES-128-GCM vectors (96-bit IV, 128-bit tag)" {
    for (@import("aes_gcm_vectors.zig").vectors) |v| {
        var key: [16]u8 = undefined;
        var iv: [12]u8 = undefined;
        var tag: [16]u8 = undefined;
        var aad_buf: [1024]u8 = undefined;
        var msg_buf: [1024]u8 = undefined;
        var ct_buf: [1024]u8 = undefined;
        _ = try std.fmt.hexToBytes(&key, v.key);
        _ = try std.fmt.hexToBytes(&iv, v.iv);
        _ = try std.fmt.hexToBytes(&tag, v.tag);
        const aad = try std.fmt.hexToBytes(&aad_buf, v.aad);
        const msg = try std.fmt.hexToBytes(&msg_buf, v.msg);
        const ct = try std.fmt.hexToBytes(&ct_buf, v.ct);
        const ctx = Ctx.init(key);
        errdefer std.debug.print("Wycheproof tcId {d}\n", .{v.id});

        if (v.valid) {
            var out: [1024]u8 = undefined;
            var out_tag: [16]u8 = undefined;
            ctx.encrypt(out[0..msg.len], &out_tag, msg, aad, iv);
            try testing.expectEqualSlices(u8, ct, out[0..msg.len]);
            try testing.expectEqualSlices(u8, &tag, &out_tag);
        }
        var buf: [1024]u8 = undefined;
        @memcpy(buf[0..ct.len], ct);
        const opened = ctx.decrypt(buf[0..ct.len], buf[0..ct.len], tag, aad, iv);
        if (v.valid) {
            try opened;
            try testing.expectEqualSlices(u8, msg, buf[0..ct.len]);
        } else {
            try testing.expectError(error.AuthenticationFailed, opened);
        }
    }
}
