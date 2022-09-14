//
// QUIC Header Protection
// (AEAD: Authenticated Encryption with Associated Data)
// --------------------------------------------
// Inspired by briansmith/ring (https://briansmith.org/rustdoc/ring/aead/index.html)
//

const std = @import("std");
const crypto = std.crypto;

const HkdfSha256 = crypto.kdf.hkdf.HkdfSha256;
const HmacSha256 = crypto.auth.hmac.sha2.HmacSha256;
const Aes128Gcm = crypto.aead.aes_gcm.Aes128Gcm;

pub const SAMPLE_LEN = 16;

pub const AlgorithmID = enum { AES_128, AES_256, CHACHA20 };
pub const KeyInner = enum { Aes, Chacha20 };

pub const HeaderProtectionKey = struct {
    inner: KeyInner,
    algorithm: Algorithm,

    pub fn newMask(self: *HeaderProtectionKey, sample: [SAMPLE_LEN]u8) ![5]u8 {
        return self.algorithm.new_mask(self.inner, sample);
    }
};

/// A QUIC Header Protection Algorithm.
pub const Algorithm = struct {
    // TODO fix this on stage2 compiler:
    // *const fn
    init: fn (key: []const u8) anyerror!KeyInner,
    new_mask: fn (key: KeyInner, sample: [SAMPLE_LEN]u8) [5]u8,
    key_len: usize,
    id: AlgorithmID,
};

pub const AEAD = struct {};
