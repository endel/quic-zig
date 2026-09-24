//! AES-128-GCM with the per-key work done once. std's `Aes128Gcm` takes the
//! raw key on every call, so each packet re-expands the AES key, re-derives
//! H and recomputes H's powers for GHASH. A packet protection key encrypts
//! millions of packets, so `Ctx` does that at key installation.
//!
//! The per-message steps are std's `AesGcm.encrypt`/`decrypt` (Zig 0.16.0)
//! line for line, over the tuned GHASH in `ghash.zig` and 0.16's CTR loop.
//! Zig master's CTR (after 0.16) encrypts a whole parallel batch for the
//! tail and XORs it bytewise: 161 → 215 ns at 1200 B, 9 → 38 ns at 64 B.

const std = @import("std");
const crypto = std.crypto;
const mem = std.mem;
const Aes128 = crypto.core.aes.Aes128;
const Ghash = @import("ghash.zig").Ghash;

pub const tag_length = 16;
pub const nonce_length = 12;
pub const key_length = 16;

pub const Ctx = struct {
    aes: @TypeOf(Aes128.initEnc(@as([key_length]u8, undefined))),
    h: [16]u8,
    /// GHASH keyed with H, all powers precomputed; copied per message.
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

        var t: [16]u8 = undefined;
        var j: [16]u8 = undefined;
        j[0..nonce_length].* = npub;
        mem.writeInt(u32, j[nonce_length..][0..4], 1, .big);
        self.aes.encrypt(&t, &j);

        var mac = self.mac;
        mac.update(ad);
        mac.pad();

        mem.writeInt(u32, j[nonce_length..][0..4], 2, .big);
        ctr(self.aes, c, m, j);
        mac.update(c[0..m.len]);
        mac.pad();

        mac.update(&lengthBlock(ad.len, m.len));
        mac.final(tag);
        for (t, 0..) |x, i| tag[i] ^= x;
    }

    /// `m` and `c` may be the same buffer. Contents of `m` are undefined if
    /// an error is returned.
    pub fn decrypt(self: *const Ctx, m: []u8, c: []const u8, tag: [tag_length]u8, ad: []const u8, npub: [nonce_length]u8) crypto.errors.AuthenticationError!void {
        std.debug.assert(c.len == m.len);

        var t: [16]u8 = undefined;
        var j: [16]u8 = undefined;
        j[0..nonce_length].* = npub;
        mem.writeInt(u32, j[nonce_length..][0..4], 1, .big);
        self.aes.encrypt(&t, &j);

        var mac = self.mac;
        mac.update(ad);
        mac.pad();
        mac.update(c);
        mac.pad();

        mac.update(&lengthBlock(ad.len, m.len));
        var computed_tag: [tag_length]u8 = undefined;
        mac.final(&computed_tag);
        for (t, 0..) |x, i| computed_tag[i] ^= x;

        const verify = crypto.timing_safe.eql([tag_length]u8, computed_tag, tag);
        if (!verify) {
            crypto.secureZero(u8, &computed_tag);
            @memset(m, undefined);
            return error.AuthenticationFailed;
        }

        mem.writeInt(u32, j[nonce_length..][0..4], 2, .big);
        ctr(self.aes, m, c, j);
    }

    /// std.crypto.core.modes.ctr from Zig 0.16.0, whole block as a big-endian
    /// counter, with the batch increment made wrapping as master has it.
    fn ctr(aes: anytype, dst: []u8, src: []const u8, iv: [16]u8) void {
        std.debug.assert(dst.len >= src.len);
        const block_length = 16;
        const parallel_count = @TypeOf(aes).block.parallel.optimal_parallel_blocks;
        const wide_block_length = parallel_count * block_length;

        var counter_block = iv;
        var i: usize = 0;
        var cnt_val = mem.readInt(u128, &counter_block, .big);
        if (src.len >= wide_block_length) {
            var counters: [wide_block_length]u8 = undefined;
            while (i + wide_block_length <= src.len) : (i += wide_block_length) {
                inline for (0..parallel_count) |k| {
                    mem.writeInt(u128, counters[k * block_length ..][0..block_length], cnt_val +% k, .big);
                }
                cnt_val +%= parallel_count;
                aes.xorWide(parallel_count, dst[i..][0..wide_block_length], src[i..][0..wide_block_length], counters);
            }
            mem.writeInt(u128, &counter_block, cnt_val, .big);
        }
        while (i + block_length <= src.len) : (i += block_length) {
            aes.xor(dst[i..][0..block_length], src[i..][0..block_length], counter_block);
            cnt_val +%= 1;
            mem.writeInt(u128, &counter_block, cnt_val, .big);
        }
        if (i < src.len) {
            var pad: [block_length]u8 = @splat(0);
            const rest = src[i..];
            @memcpy(pad[0..rest.len], rest);
            aes.xor(&pad, &pad, counter_block);
            @memcpy(dst[i..][0..rest.len], pad[0..rest.len]);
        }
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

test "Ctx matches std Aes128Gcm across lengths that cross every GHASH aggregation width" {
    var prng = std.Random.DefaultPrng.init(0x9e3779b97f4a7c15);
    const rand = prng.random();
    var m: [2048]u8 = undefined;
    var ad: [64]u8 = undefined;
    for (0..400) |iter| {
        var key: [16]u8 = undefined;
        var npub: [12]u8 = undefined;
        rand.bytes(&key);
        rand.bytes(&npub);
        // lengths around 4/8/16-way thresholds (in 16 B blocks), plus odd tails
        const m_len = if (iter < 200) iter * 7 else rand.uintAtMost(usize, m.len);
        const ad_len = rand.uintAtMost(usize, ad.len);
        rand.bytes(m[0..m_len]);
        rand.bytes(ad[0..ad_len]);

        const ctx = Ctx.init(key);
        var c_ours: [2048]u8 = undefined;
        var c_std: [2048]u8 = undefined;
        var tag_ours: [16]u8 = undefined;
        var tag_std: [16]u8 = undefined;
        ctx.encrypt(c_ours[0..m_len], &tag_ours, m[0..m_len], ad[0..ad_len], npub);
        StdGcm.encrypt(c_std[0..m_len], &tag_std, m[0..m_len], ad[0..ad_len], npub, key);
        try testing.expectEqualSlices(u8, c_std[0..m_len], c_ours[0..m_len]);
        try testing.expectEqualSlices(u8, &tag_std, &tag_ours);

        // in place, as packet protection uses it
        var buf: [2048]u8 = undefined;
        @memcpy(buf[0..m_len], c_ours[0..m_len]);
        try ctx.decrypt(buf[0..m_len], buf[0..m_len], tag_ours, ad[0..ad_len], npub);
        try testing.expectEqualSlices(u8, m[0..m_len], buf[0..m_len]);

        var bad_tag = tag_ours;
        bad_tag[iter % 16] ^= 1;
        @memcpy(buf[0..m_len], c_ours[0..m_len]);
        try testing.expectError(error.AuthenticationFailed, ctx.decrypt(buf[0..m_len], buf[0..m_len], bad_tag, ad[0..ad_len], npub));
        if (m_len > 0) {
            @memcpy(buf[0..m_len], c_ours[0..m_len]);
            buf[iter % m_len] ^= 0x80;
            try testing.expectError(error.AuthenticationFailed, ctx.decrypt(buf[0..m_len], buf[0..m_len], tag_ours, ad[0..ad_len], npub));
        }
    }
}
