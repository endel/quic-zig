//! AES-128-GCM with the per-key work done once. std's `Aes128Gcm` takes the
//! raw key on every call, so each packet re-expands the AES key, re-derives
//! H and recomputes H's powers for GHASH. A packet protection key encrypts
//! millions of packets, so `Ctx` does that at key installation.
//!
//! The per-message steps follow std's `AesGcm.encrypt`/`decrypt` (Zig
//! 0.16.0), except with `stitch`: CTR and GHASH then share one pass, so
//! decrypting writes the plaintext before the tag is checked, and wipes it
//! when the check fails, as OpenSSL and BoringSSL do.
//!
//! With hardware AES, CTR runs 8 blocks at a time with the round keys held in
//! registers, and the tail as one batch of exactly the blocks left, with the
//! tag mask as one more lane. On arm64 each round is `aese` with the round key
//! plus `aesmc`, a pair the core fuses. std's armcrypto rounds are `aese` with
//! a zero key, `aesmc`, then an `eor` of the round key, with operands limited
//! to v0-v15, so 6+ blocks and 11 round keys don't fit and keys get reloaded.
//! With PMULL (arm64) or PCLMUL (x86_64), GHASH also runs in vector registers
//! (see `vec_ghash`). Elsewhere GHASH is `ghash.zig`, and without hardware
//! AES, CTR is std's.
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
    builtin.target.cpu.arch.endian() == .little;
const V = @Vector(2, u64);
/// Blocks per CTR step. 8 in flight plus 11 round keys fit arm64's 32 vector
/// registers.
const wide = 8;
const RoundKeys = [Aes128.rounds + 1]Block;

/// GHASH in vector registers. `ghash.zig` does its arithmetic on u128, which
/// LLVM keeps in general registers, so every multiply moves operands across
/// and back. Same multiply and reduction, on vectors.
const vec_ghash = fast and builtin.mode != .small and switch (builtin.target.cpu.arch) {
    .aarch64 => true,
    // ghash.zig's own conditions for vpclmulqdq
    .x86_64 => builtin.target.cpu.has(.x86, .pclmul) and builtin.target.cpu.has(.x86, .avx),
    else => false,
};
/// CTR and GHASH in one loop, so one batch's AES overlaps another's GHASH:
/// AES-NI and PCLMUL issue on different ports, and arm64 has the pipes too.
const stitch = vec_ghash;
/// x86: a batch's GHASH between the AES rounds of the next (`RoundHash`).
/// On arm64 that measured 5% slower than hashing after the AES: its four
/// SIMD pipes all run both, and the extra live registers spill.
const per_round_ghash = builtin.target.cpu.arch == .x86_64;
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

/// GHASH's big-endian block from its bytes in memory order, and back.
inline fn reverse(x: V) V {
    return @bitCast(@shuffle(u8, @as(@Vector(16, u8), @bitCast(x)), undefined, reversed));
}

/// Copy a block's tail, at most 16 bytes, in fixed-size moves: @memcpy of a
/// runtime length is a call into compiler_rt, which costs more than the copy.
inline fn copyTail(dst: []u8, src: []const u8) void {
    var o: usize = 0;
    inline for (.{ 16, 8, 4, 2, 1 }) |w| {
        if (dst.len & w != 0) {
            dst[o..][0..w].* = src[o..][0..w].*;
            o += w;
        }
    }
}

/// Carryless product of the low lanes of `x` and `y`.
inline fn pmullLo(x: V, y: V) V {
    if (builtin.target.cpu.arch == .x86_64) return asm ("vpclmulqdq $0x00, %[x], %[y], %[o]"
        : [o] "=x" (-> V),
        : [x] "x" (x),
          [y] "x" (y),
    );
    return asm ("pmull %[o].1q, %[x].1d, %[y].1d"
        : [o] "=w" (-> V),
        : [x] "w" (x),
          [y] "w" (y),
    );
}

/// Carryless product of the high lanes of `x` and `y`.
inline fn pmullHi(x: V, y: V) V {
    if (builtin.target.cpu.arch == .x86_64) return asm ("vpclmulqdq $0x11, %[x], %[y], %[o]"
        : [o] "=x" (-> V),
        : [x] "x" (x),
          [y] "x" (y),
    );
    return asm ("pmull2 %[o].1q, %[x].2d, %[y].2d"
        : [o] "=w" (-> V),
        : [x] "w" (x),
          [y] "w" (y),
    );
}

/// x.hi·y.lo ^ x.lo·y.hi. x86's PCLMUL picks either lane of each operand;
/// PMULL only pairs like lanes, so arm64 swaps `x`'s halves first.
inline fn pmullCross(x: V, y: V) V {
    if (builtin.target.cpu.arch == .x86_64) return asm ("vpclmulqdq $0x01, %[x], %[y], %[o]"
        : [o] "=x" (-> V),
        : [x] "x" (x),
          [y] "x" (y),
    ) ^ asm ("vpclmulqdq $0x10, %[x], %[y], %[o]"
        : [o] "=x" (-> V),
        : [x] "x" (x),
          [y] "x" (y),
    );
    const xs = swapHalves(x);
    return pmullLo(xs, y) ^ pmullHi(xs, y);
}

inline fn swapHalves(x: V) V {
    return @shuffle(u64, x, undefined, [2]i32{ 1, 0 });
}

/// (acc ^ b[0])·H^k ^ b[1]·H^(k-1) ^ ... ^ b[k-1]·H, reduced once. The
/// schoolbook product and `reduce` of `ghash.zig`.
inline fn ghashBatch(comptime k: usize, hx: *const [pc_count]V, acc: V, b: [k]V) V {
    var p: Products = .{};
    inline for (0..k) |j| p.add(if (j == 0) b[0] ^ acc else b[j], hx[k - 1 - j]);
    return p.reduce();
}

/// A batch's unreduced product, summed a block at a time.
const Products = struct {
    lo: V = @splat(0),
    hi: V = @splat(0),
    mid: V = @splat(0),

    inline fn add(p: *Products, x: V, h: V) void {
        p.lo ^= pmullLo(x, h);
        p.hi ^= pmullHi(x, h);
        p.mid ^= pmullCross(x, h);
    }

    inline fn reduce(p: Products) V {
        const zero: V = @splat(0);
        const hi = p.hi ^ @shuffle(u64, p.mid, zero, [2]i32{ 1, -1 }); // mid >> 64
        const lo = p.lo ^ @shuffle(u64, p.mid, zero, [2]i32{ -1, 0 }); // mid << 64
        const p64: V = .{ 0xc200000000000000, 0 };
        const r = swapHalves(lo) ^ pmullLo(lo, p64);
        return swapHalves(r) ^ pmullLo(r, p64) ^ hi;
    }
};

/// One batch's GHASH spread over another batch's AES rounds, a block's
/// multiplies per round and the reduction in the last, as OpenSSL orders
/// them: with the AES and GHASH halves apart, x86 dispatches GHASH's XORs to
/// port 0, which every AES round needs. `b[0]` already holds the running
/// hash.
const RoundHash = struct {
    hx: *const [pc_count]V,
    b: [wide]V,
    p: Products = .{},
    acc: V = undefined,

    inline fn round(self: *RoundHash, comptime r: usize) void {
        if (r < wide) self.p.add(self.b[r], self.hx[wide - 1 - r]);
        if (r == wide) self.acc = self.p.reduce();
    }

    /// Every step at once, for a batch hashed apart from AES.
    inline fn all(self: *RoundHash) V {
        inline for (0..wide + 1) |r| self.round(r);
        return self.acc;
    }

    comptime {
        std.debug.assert(wide < Aes128.rounds - 1); // a middle round left for the reduction
    }
};

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
                copyTail(buf[0 .. msg.len - last], msg[last..]);
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
    /// GHASH keyed with H, all powers precomputed. `vec_ghash` only reads
    /// the powers; otherwise this is copied per message.
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

        if (stitch) {
            tag.* = self.ctrGhash(true, c, m, ad, npub);
            return;
        }
        const t = self.ctr(true, c, m, npub);
        tag.* = self.ghashTag(ad, c[0..m.len], t);
    }

    /// `m` and `c` may be the same buffer. Contents of `m` are undefined if
    /// an error is returned.
    pub fn decrypt(self: *const Ctx, m: []u8, c: []const u8, tag: [tag_length]u8, ad: []const u8, npub: [nonce_length]u8) crypto.errors.AuthenticationError!void {
        std.debug.assert(c.len == m.len);

        if (stitch) {
            var computed_tag = self.ctrGhash(false, m, c, ad, npub);
            if (!crypto.timing_safe.eql([tag_length]u8, computed_tag, tag)) {
                crypto.secureZero(u8, &computed_tag);
                crypto.secureZero(u8, m);
                return error.AuthenticationFailed;
            }
            return;
        }
        var computed_tag = self.ghashTag(ad, c, self.counterBlock(npub, 1));
        const verify = crypto.timing_safe.eql([tag_length]u8, computed_tag, tag);
        if (!verify) {
            crypto.secureZero(u8, &computed_tag);
            @memset(m, undefined);
            return error.AuthenticationFailed;
        }

        _ = self.ctr(false, m, c, npub);
    }

    /// CTR from `src` into `dst`, GHASHing the ciphertext in the same loop;
    /// returns the tag. Sealing, a batch's ciphertext is hashed in the next
    /// iteration, so GHASH never waits on the AES beside it. Opening hashes
    /// each batch before its plaintext is stored, which may overwrite it.
    fn ctrGhash(self: *const Ctx, comptime seal: bool, dst: []u8, src: []const u8, ad: []const u8, npub: [nonce_length]u8) [16]u8 {
        const rk = self.aes.key_schedule.round_keys; // a local, so stores to dst can't alias it
        const hx: *const [pc_count]V = @ptrCast(&self.mac.hx);
        const base = counterBase(npub);
        var acc = ghashBlocks(hx, @splat(0), ad, null);
        var n: u32 = 2;
        var i: usize = 0;
        // sealing: ciphertext waiting to be hashed
        var prev: [wide]V = @splat(@splat(0));
        var pending = false;
        while (i + 16 * wide <= src.len) : (i += 16 * wide) {
            var rh: RoundHash = .{ .hx = hx, .b = prev };
            if (!seal) inline for (0..wide) |j| {
                rh.b[j] = loadBlock(src[i + 16 * j ..][0..16]);
            };
            rh.b[0] ^= acc;
            const hashing = !seal or pending;
            const ks = if (per_round_ghash and hashing)
                encryptBlocks(wide, &rk, counters(wide, base, n), &rh)
            else
                encryptBlocks(wide, &rk, counters(wide, base, n), null);
            if (hashing) acc = if (per_round_ghash) rh.acc else rh.all();
            n +%= wide;
            inline for (0..wide) |j| {
                const ct = xorBlock(dst[i + 16 * j ..][0..16], src[i + 16 * j ..][0..16], ks[j]);
                if (seal) prev[j] = reverse(ct);
            }
            pending = seal;
        }
        if (pending) acc = ghashBatch(wide, hx, acc, prev);
        const len_block = loadBlock(&lengthBlock(ad.len, src.len));
        if (!seal) acc = ghashBlocks(hx, acc, src[i..], len_block);
        const t = ctrTail(true, &rk, dst[i..], src[i..], base, n);
        if (seal) acc = ghashBlocks(hx, acc, dst[i..src.len], len_block);
        return @as([16]u8, @bitCast(reverse(acc) ^ @as(V, @bitCast(t))));
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
            out = @bitCast(encryptBlocks(1, &rk, counters(1, counterBase(npub), n), null)[0]);
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
            const ks = encryptBlocks(wide, &rk, counters(wide, base, n), null);
            n +%= wide;
            inline for (0..wide) |b| _ = xorBlock(dst[i + 16 * b ..][0..16], src[i + 16 * b ..][0..16], ks[b]);
        }
        return ctrTail(mask, &rk, dst[i..], src[i..], base, n);
    }

    /// CTR over `src`, fewer than `wide` blocks, in one batch, the mask
    /// riding along as its last lane. `n` is the first block's counter.
    fn ctrTail(comptime mask: bool, rk: *const RoundKeys, dst: []u8, src: []const u8, base: V, n: u32) [16]u8 {
        switch ((src.len + 15) / 16) {
            inline 0...wide => |k| {
                const lanes = k + @intFromBool(mask);
                if (lanes == 0) return undefined;
                var ctrs: [lanes]V = undefined;
                ctrs[0..k].* = counters(k, base, n);
                if (mask) ctrs[k] = counters(1, base, 1)[0];
                const ks = encryptBlocks(lanes, rk, ctrs, null);
                if (k > 0) {
                    inline for (0..k - 1) |b| _ = xorBlock(dst[16 * b ..][0..16], src[16 * b ..][0..16], ks[b]);
                    const last = 16 * (k - 1);
                    const r = src.len - last;
                    var buf: [16]u8 = @splat(0);
                    copyTail(buf[0..r], src[last..]);
                    _ = xorBlock(&buf, &buf, ks[k - 1]);
                    copyTail(dst[last..][0..r], &buf);
                }
                return if (mask) @bitCast(ks[k]) else undefined;
            },
            else => unreachable,
        }
    }

    /// Unaligned vector load and store: on Zig 0.17-dev, `@bitCast(src.*)`
    /// compiles to 16 byte loads, which doubles the cost of CTR. Returns
    /// what it stored.
    inline fn xorBlock(dst: *[16]u8, src: *const [16]u8, ks: V) V {
        const in: *align(1) const V = @ptrCast(src);
        const out: *align(1) V = @ptrCast(dst);
        const v = in.* ^ ks;
        out.* = v;
        return v;
    }

    /// npub || 00000000, so a counter is OR-ed into the top half of lane 1.
    inline fn counterBase(npub: [nonce_length]u8) V {
        return @bitCast(npub ++ @as([4]u8, @splat(0)));
    }

    inline fn counters(comptime k: usize, base: V, n: u32) [k]V {
        var out: [k]V = undefined;
        // Byte 15, the counter's low byte, is the top of lane 1: while it
        // doesn't carry, a vector add steps it without a general-register
        // round trip (vpinsrq shares PCLMUL's port).
        if (k > 1 and (n & 0xff) + (k - 1) <= 0xff) {
            const first = base | V{ 0, @as(u64, @byteSwap(n)) << 32 };
            inline for (0..k) |b| out[b] = first +% V{ 0, @as(u64, b) << 56 };
            return out;
        }
        inline for (0..k) |b| out[b] = base | V{ 0, @as(u64, @byteSwap(n +% @as(u32, b))) << 32 };
        return out;
    }

    /// AES-128 over `k` blocks, round by round so the blocks' rounds overlap.
    /// `hash`, when given, takes a step after each of the 9 middle rounds.
    inline fn encryptBlocks(comptime k: usize, rk: *const RoundKeys, in: [k]V, hash: ?*RoundHash) [k]V {
        var s = in;
        if (builtin.target.cpu.arch == .aarch64) {
            inline for (0..Aes128.rounds - 1) |r| {
                inline for (0..k) |b| s[b] = asm (
                    \\ aese  %[s].16b, %[rk].16b
                    \\ aesmc %[s].16b, %[s].16b
                    : [s] "=w" (-> V),
                    : [_] "0" (s[b]),
                      [rk] "w" (rk[r].repr),
                );
                if (hash) |h| h.round(r);
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
                if (hash) |h| h.round(r - 1);
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

/// A TLS record's plaintext, with room past it.
const check_max = 16384 + 256;

/// Seals `m` with `ctx` and std, in place and not, and checks they agree;
/// then opens it, and checks that a flipped tag, message or AD bit is refused.
fn checkAgainstStd(ctx: *const Ctx, key: [16]u8, npub: [12]u8, m: []const u8, ad: []u8, flip: usize) !void {
    var c_ours: [check_max]u8 = undefined;
    var c_std: [check_max]u8 = undefined;
    var tag_ours: [16]u8 = undefined;
    var tag_std: [16]u8 = undefined;
    ctx.encrypt(c_ours[0..m.len], &tag_ours, m, ad, npub);
    StdGcm.encrypt(c_std[0..m.len], &tag_std, m, ad, npub, key);
    try testing.expectEqualSlices(u8, c_std[0..m.len], c_ours[0..m.len]);
    try testing.expectEqualSlices(u8, &tag_std, &tag_ours);

    // in place, as packet protection uses it
    var buf: [check_max]u8 = undefined;
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
    // stitched, the plaintext was written before the tag failed
    if (stitch) try testing.expect(mem.allEqual(u8, buf[0..m.len], 0));
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

test "Ctx matches std Aes128Gcm where a batch's counters carry out of their low byte" {
    // Counters start at 2, so the batch from 250 carries first: lengths
    // around it put that batch mid-message or in the tail.
    var prng = std.Random.DefaultPrng.init(0x853c49e6748fea9b);
    const rand = prng.random();
    var m: [check_max]u8 = undefined;
    var ad: [13]u8 = undefined;
    for (0..80) |iter| {
        var key: [16]u8 = undefined;
        var npub: [12]u8 = undefined;
        rand.bytes(&key);
        rand.bytes(&npub);
        const m_len = if (iter < 48) (240 + iter / 2) * 16 + iter % 2 * 9 else rand.uintAtMost(usize, m.len);
        rand.bytes(m[0..m_len]);
        rand.bytes(&ad);
        const ctx = Ctx.init(key);
        try checkAgainstStd(&ctx, key, npub, m[0..m_len], &ad, iter);
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
