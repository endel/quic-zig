//! Contains imlementations of cipher suites, required (or supported)
//! for TLS 1.3
//! All implementations are done, with 'streaming' support, required
//! to be able to read in parts from a connection as users may not always
//! provide a buffer large enough that entails the entire payload.

const std = @import("std");
const tls = @import("tls.zig");
const mem = std.mem;
const crypto = std.crypto;
const modes = crypto.core.modes;
const Ghash = crypto.onetimeauth.Ghash;

fn ReturnType(comptime T: type) type {
    return @typeInfo(T).Fn.return_type.?;
}

/// Supported cipher suites
pub const supported = [_]type{
    Aes128,
};

/// Type for our key data
pub const KeyStorage = KeyData(&supported);

/// Returns the type of a cipher based on a given `tls.CipherSuite`.
///
/// It is illegal to provide a suite that is not part of the supported
/// cipher suites found in `supported`.
pub fn TypeFromSuite(comptime suite: tls.CipherSuite) type {
    return for (supported) |cipher| {
        if (cipher.suite == suite) {
            break cipher.Context;
        }
    } else unreachable; // given `suite` is not supported.
}

/// Checks if a given `tls.CipherSuite` is supported and implemented.
pub fn isSupported(suite: tls.CipherSuite) bool {
    return inline for (supported) |cipher| {
        if (cipher.suite == suite) break true;
    } else false;
}

pub const Aes128 = struct {
    const Aes128Gcm = crypto.aead.aes_gcm.Aes128Gcm;
    const StdAes128 = crypto.core.aes.Aes128;

    pub const suite: tls.CipherSuite = .tls_aes_128_gcm_sha256;
    pub const tag_length = Aes128Gcm.tag_length;
    pub const nonce_length = Aes128Gcm.nonce_length;
    pub const key_length = Aes128Gcm.key_length;

    pub const Context = struct {
        ctx: ReturnType(@TypeOf(StdAes128.initEnc)),
        mac: crypto.onetimeauth.Ghash,
        t: u128,
        j: u128,
    };

    /// Creates a new `Context` for the Aes128Gcm cipher, setting the initiual values
    /// using the keys provided and the current `sequence.
    pub fn init(key_data: *KeyStorage, sequence: u64, ad: []const u8) Context {
        const ctx = StdAes128.initEnc(key_data.clientKey(Aes128).*);
        var h: [16]u8 = undefined;
        ctx.encrypt(&h, &[_]u8{0} ** 16);

        var iv_copy = key_data.clientIv(Aes128).*;
        xorIv(&iv_copy, sequence);

        var t: [16]u8 = undefined;
        var j: [16]u8 = undefined;
        mem.copy(u8, j[0..nonce_length], &iv_copy);
        mem.writeIntBig(u32, j[nonce_length..][0..4], 1);
        ctx.encrypt(&t, &j);

        var mac = Ghash.init(&h);
        mac.update(ad);
        mac.pad();

        mem.writeIntBig(u32, j[nonce_length..][0..4], 2);
        return .{
            .ctx = ctx,
            .mac = mac,
            .t = mem.readIntBig(u128, &t),
            .j = mem.readIntBig(u128, &j),
        };
    }

    /// Decrypts a partial message, writing the decrypted data to `out`.
    /// Also writes the read length to `idx`.
    /// NOTE: This does not validate the data.
    /// Ensure all data is correct by calling `verify` once all data is received.
    pub fn decryptPartial(context: *Context, out: []u8, data: []const u8, idx: *usize) void {
        context.mac.update(data);
        ctr(@TypeOf(context.ctx), context.ctx, out, data, &context.j, idx, .Big);
    }

    /// Verifies that all decrypted data til this point was valid.
    pub fn verify(context: *Context, auth_tag: [tag_length]u8, message_length: usize) !void {
        context.mac.pad();
        var final_block: [16]u8 = undefined;
        mem.writeIntBig(u64, final_block[0..8], 5 * 8); // RecordHeader is always 5 bytes.
        mem.writeIntBig(u64, final_block[8..16], message_length * 8); // message length we have decrypted til this point.
        context.mac.update(&final_block);
        var computed_tag: [Ghash.mac_length]u8 = undefined;
        context.mac.final(&computed_tag);
        var t: [16]u8 = undefined;
        mem.writeIntBig(u128, &t, context.t);
        for (t) |x, i| {
            computed_tag[i] ^= x;
        }

        var acc: u8 = 0;
        for (computed_tag) |_, i| {
            acc |= (computed_tag[i] ^ auth_tag[i]);
        }
        if (acc != 0) {
            return error.AuthenticationFailed;
        }
    }

    /// Encrypts the given `data` and writes it to `out`. Asserts `out` has the same length as `data`.
    /// An authentication tag is written to `tag`, allowing a peer to verify the data.
    /// The given `sequence` will be xor'd with the server IV, stored in given `KeyStorage`.
    pub fn encrypt(
        /// Contains all keys of the client and server, to encrypt/decrypt the data
        key_storage: *KeyStorage,
        /// The buffer that will have the encrypted data written to
        out: []u8,
        /// The message to be encrypted
        data: []const u8,
        /// Additional data to encrypt with the message, in TLS this is the record header
        ad: []const u8,
        /// The sequence of the total amount of encrypted data we've transmitted.
        /// This will be xor'd with the server nonce.
        sequence: u64,
        /// The authentication tag created during the encryption of the data.
        /// Can be used by the peer to verify the data.
        tag: *[tag_length]u8,
    ) void {
        var iv = key_storage.serverIv(Aes128).*;
        xorIv(&iv, sequence);

        Aes128Gcm.encrypt(out, tag, data, ad, iv, key_storage.serverKey(Aes128).*);
    }

    /// xor's the sequence with a key_iv.
    fn xorIv(iv: *[nonce_length]u8, sequence: u64) void {
        var i: u5 = 0;
        while (i < 8) : (i += 1) {
            iv[nonce_length - 1 - i] ^= @intCast(u8, (sequence >> (i *% 8)) & 0xFF);
        }
    }
};

/// Counter mode.
///
/// This mode creates a key stream by encrypting an incrementing counter using a block cipher, and adding it to the source material.
///
/// Important: the counter mode doesn't provide authenticated encryption: the ciphertext can be trivially modified without this being detected.
/// As a result, applications should generally never use it directly, but only in a construction that includes a MAC.
///
/// Original from: https://github.com/alexnask/iguanaTLS/blob/master/src/crypto.zig#L159
pub fn ctr(
    comptime BlockCipher: anytype,
    block_cipher: BlockCipher,
    dst: []u8,
    src: []const u8,
    counterInt: *u128,
    idx: *usize,
    endian: std.builtin.Endian,
) void {
    std.debug.assert(dst.len >= src.len);
    const block_length = BlockCipher.block_length;
    var cur_idx: usize = 0;

    const offset = idx.* % block_length;
    if (offset != 0) {
        const part_len = std.math.min(block_length - offset, src.len);

        var counter: [BlockCipher.block_length]u8 = undefined;
        mem.writeInt(u128, &counter, counterInt.*, endian);
        var pad = [_]u8{0} ** block_length;
        mem.copy(u8, pad[offset..], src[0..part_len]);
        block_cipher.xor(&pad, &pad, counter);
        mem.copy(u8, dst[0..part_len], pad[offset..][0..part_len]);
        cur_idx += part_len;
        idx.* += part_len;
        if (idx.* % block_length == 0)
            counterInt.* += 1;
    }

    const start_idx = cur_idx;
    const remaining = src.len - cur_idx;
    cur_idx = 0;

    const parallel_count = BlockCipher.block.parallel.optimal_parallel_blocks;
    const wide_block_length = parallel_count * 16;
    if (remaining >= wide_block_length) {
        var counters: [parallel_count * 16]u8 = undefined;
        while (cur_idx + wide_block_length <= remaining) : (cur_idx += wide_block_length) {
            comptime var j = 0;
            inline while (j < parallel_count) : (j += 1) {
                mem.writeInt(u128, counters[j * 16 .. j * 16 + 16], counterInt.*, endian);
                counterInt.* +%= 1;
            }
            block_cipher.xorWide(
                parallel_count,
                dst[start_idx..][cur_idx..][0..wide_block_length],
                src[start_idx..][cur_idx..][0..wide_block_length],
                counters,
            );
            idx.* += wide_block_length;
        }
    }
    while (cur_idx + block_length <= remaining) : (cur_idx += block_length) {
        var counter: [BlockCipher.block_length]u8 = undefined;
        mem.writeInt(u128, &counter, counterInt.*, endian);
        counterInt.* +%= 1;
        block_cipher.xor(
            dst[start_idx..][cur_idx..][0..block_length],
            src[start_idx..][cur_idx..][0..block_length],
            counter,
        );
        idx.* += block_length;
    }
    if (cur_idx < remaining) {
        std.debug.assert(idx.* % block_length == 0);
        var counter: [BlockCipher.block_length]u8 = undefined;
        mem.writeInt(u128, &counter, counterInt.*, endian);

        var pad = [_]u8{0} ** block_length;
        mem.copy(u8, &pad, src[start_idx..][cur_idx..]);
        block_cipher.xor(&pad, &pad, counter);
        mem.copy(u8, dst[start_idx..][cur_idx..], pad[0 .. remaining - cur_idx]);

        idx.* += remaining - cur_idx;
        if (idx.* % block_length == 0)
            counterInt.* +%= 1;
    }
}

test "Aes128 - single message" {
    var key_data = KeyStorage{};
    const key: [Aes128.key_length]u8 = [_]u8{0x69} ** Aes128.key_length;
    key_data.setClientKey(Aes128, key);
    const nonce: [Aes128.nonce_length]u8 = [_]u8{0x42} ** Aes128.nonce_length;
    key_data.setClientIv(Aes128, nonce);
    const m = "Test with message only";
    const record: tls.Record = .{ .record_type = .application_data, .len = m.len };
    var c: [m.len]u8 = undefined;
    var m2: [m.len]u8 = undefined;
    var tag: [Aes128.tag_length]u8 = undefined;

    crypto.aead.aes_gcm.Aes128Gcm.encrypt(&c, &tag, m, &record.toBytes(), nonce, key);
    var state = Aes128.init(&key_data, 0, &record.toBytes());
    var idx: usize = 0;
    Aes128.decryptPartial(&state, &m2, &c, &idx);
    try Aes128.verify(&state, tag, m.len);
    try std.testing.expectEqualSlices(u8, m[0..], m2[0..]);
    try std.testing.expectEqual(m.len, idx);
}

test "Aes128 - multiple messages" {
    var key_data = KeyStorage{};
    const key: [Aes128.key_length]u8 = [_]u8{0x69} ** Aes128.key_length;
    key_data.setClientKey(Aes128, key);
    const nonce: [Aes128.nonce_length]u8 = [_]u8{0x42} ** Aes128.nonce_length;
    key_data.setClientIv(Aes128, nonce);
    const m = "Test with message only";
    const half_length = m.len / 2;
    var idx: usize = 0;
    const record: tls.Record = .{ .record_type = .application_data, .len = m.len };
    var c: [m.len]u8 = undefined;
    var m2: [m.len]u8 = undefined;
    var tag: [Aes128.tag_length]u8 = undefined;

    crypto.aead.aes_gcm.Aes128Gcm.encrypt(&c, &tag, m, &record.toBytes(), nonce, key);
    var state = Aes128.init(&key_data, 0, &record.toBytes());
    Aes128.decryptPartial(&state, m2[0..half_length], c[0..half_length], &idx);
    try std.testing.expectEqual(half_length, idx);
    Aes128.decryptPartial(&state, m2[half_length..], c[half_length..], &idx);
    try std.testing.expectEqual(m.len, idx);
    try Aes128.verify(&state, tag, m.len);
    try std.testing.expectEqualSlices(u8, m[0..], m2[0..]);
}

/// Manages storage of key data, generic over a slice
/// of cipher types. Allowing us to store and read key data
/// in correct lengths.
pub fn KeyData(comptime ciphers: []const type) type {
    comptime var max_length: usize = 0;
    inline for (ciphers) |cipher| {
        var total = cipher.nonce_length + cipher.key_length;
        total *= 2;
        if (total > max_length) {
            max_length = total;
        }
    }

    return struct {
        const Self = @This();

        data: [max_length]u8 = undefined,

        /// Returns the server IV array based on a given cipher type
        pub fn serverIv(self: *Self, comptime cipher: type) *[cipher.nonce_length]u8 {
            const start_index = cipher.key_length * 2;
            return self.data[start_index..][0..cipher.nonce_length];
        }

        /// Returns the client IV array based on a given cipher type
        pub fn clientIv(self: *Self, comptime cipher: type) *[cipher.nonce_length]u8 {
            const start_index = (cipher.key_length * 2) + cipher.nonce_length;
            return self.data[start_index..][0..cipher.nonce_length];
        }

        /// Returns the server secret key of a given cipher type
        pub fn serverKey(self: *Self, comptime cipher: type) *[cipher.key_length]u8 {
            return self.data[0..cipher.key_length];
        }

        /// Returns the client secret key of a given cipher type
        pub fn clientKey(self: *Self, comptime cipher: type) *[cipher.key_length]u8 {
            return self.data[cipher.key_length..][0..cipher.key_length];
        }

        /// Sets the server IV
        pub fn setServerIv(self: *Self, comptime cipher: type, data: [cipher.nonce_length]u8) void {
            const start_index = cipher.key_length * 2;
            self.data[start_index..][0..cipher.nonce_length].* = data;
        }

        /// Sets the client IV
        pub fn setClientIv(self: *Self, comptime cipher: type, data: [cipher.nonce_length]u8) void {
            const start_index = (cipher.key_length * 2) + cipher.nonce_length;
            self.data[start_index..][0..cipher.nonce_length].* = data;
        }

        /// Sets the client IV
        pub fn setServerKey(self: *Self, comptime cipher: type, data: [cipher.key_length]u8) void {
            self.data[0..cipher.key_length].* = data;
        }

        /// Sets the client IV
        pub fn setClientKey(self: *Self, comptime cipher: type, data: [cipher.key_length]u8) void {
            self.data[cipher.key_length..][0..cipher.key_length].* = data;
        }
    };
}
