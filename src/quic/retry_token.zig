// Retry and NEW_TOKEN encryption/validation (RFC 9000 §8.1.2, §8.1.3).
//
// Tokens are self-contained: nonce || AES-128-GCM(plaintext) || tag.
// The validating endpoint needs only the shared token_key — no per-connection state.

const std = @import("std");
const io = std.io;
const posix = std.posix;
const time = std.time;
const random = std.crypto.random;

const crypto = @import("crypto.zig");

pub const ENDIAN = std.builtin.Endian.big;

// Retry token format:
//   nonce(12) || AES-128-GCM-encrypt(plaintext) || tag(16)
// Plaintext:
//   odcid_len(1) + odcid(<=20) + retry_scid_len(1) + retry_scid(<=20) + timestamp_ns(8) + addr_data(14)
pub const TOKEN_NONCE_LEN = 12;
pub const TOKEN_TAG_LEN = 16;
pub const TOKEN_MAX_PLAINTEXT_LEN = 1 + 20 + 1 + 20 + 8 + 14; // 64
pub const TOKEN_MAX_LEN = TOKEN_NONCE_LEN + TOKEN_MAX_PLAINTEXT_LEN + TOKEN_TAG_LEN; // 92

// Token validity duration: 60 seconds.
const TOKEN_MAX_AGE_NS: i64 = 60 * std.time.ns_per_s;

// NEW_TOKEN is distinguishable from Retry tokens by shorter ciphertext.
const NEW_TOKEN_PLAINTEXT_LEN: usize = 8 + 14; // timestamp + addr
const NEW_TOKEN_MAX_LEN: usize = TOKEN_NONCE_LEN + NEW_TOKEN_PLAINTEXT_LEN + TOKEN_TAG_LEN; // 50

/// Extract the 14 address-data bytes from a sockaddr.storage (same layout as sockaddr.data).
fn addrDataBytes(addr: *const posix.sockaddr.storage) *const [14]u8 {
    const raw: [*]const u8 = @ptrCast(addr);
    return raw[2..16];
}

pub fn generateRetryToken(
    out: []u8,
    odcid: []const u8,
    retry_scid: []const u8,
    client_addr: posix.sockaddr.storage,
    token_key: [crypto.key_len]u8,
) !usize {
    if (out.len < TOKEN_MAX_LEN) return error.BufferTooSmall;

    var nonce: [TOKEN_NONCE_LEN]u8 = undefined;
    random.bytes(&nonce);
    @memcpy(out[0..TOKEN_NONCE_LEN], &nonce);

    var plaintext: [TOKEN_MAX_PLAINTEXT_LEN]u8 = undefined;
    var pt_fbs = io.fixedBufferStream(&plaintext);
    const pt_writer = pt_fbs.writer();
    try pt_writer.writeByte(@intCast(odcid.len));
    try pt_writer.writeAll(odcid);
    try pt_writer.writeByte(@intCast(retry_scid.len));
    try pt_writer.writeAll(retry_scid);
    const now: i64 = @intCast(time.nanoTimestamp());
    try pt_writer.writeInt(i64, now, ENDIAN);
    try pt_writer.writeAll(addrDataBytes(&client_addr));

    const pt_len = pt_fbs.pos;
    const pt_data = plaintext[0..pt_len];

    var ciphertext_buf: [TOKEN_MAX_PLAINTEXT_LEN]u8 = undefined;
    var tag: [TOKEN_TAG_LEN]u8 = undefined;
    crypto.Aead.encrypt(
        ciphertext_buf[0..pt_len],
        &tag,
        pt_data,
        "",
        nonce,
        token_key,
    );

    @memcpy(out[TOKEN_NONCE_LEN..][0..pt_len], ciphertext_buf[0..pt_len]);
    @memcpy(out[TOKEN_NONCE_LEN + pt_len ..][0..TOKEN_TAG_LEN], &tag);

    return TOKEN_NONCE_LEN + pt_len + TOKEN_TAG_LEN;
}

pub const ValidatedToken = struct {
    odcid_buf: [20]u8 = .{0} ** 20,
    odcid_len: u8 = 0,
    retry_scid_buf: [20]u8 = .{0} ** 20,
    retry_scid_len: u8 = 0,

    pub fn getOdcid(self: *const ValidatedToken) []const u8 {
        return self.odcid_buf[0..self.odcid_len];
    }

    pub fn getRetryScid(self: *const ValidatedToken) []const u8 {
        return self.retry_scid_buf[0..self.retry_scid_len];
    }
};

pub fn validateRetryToken(
    token_data: []const u8,
    client_addr: posix.sockaddr.storage,
    token_key: [crypto.key_len]u8,
) !?ValidatedToken {
    if (token_data.len < TOKEN_NONCE_LEN + TOKEN_TAG_LEN + 2) return null;

    const nonce = token_data[0..TOKEN_NONCE_LEN].*;
    const ct_len = token_data.len - TOKEN_NONCE_LEN - TOKEN_TAG_LEN;
    const ciphertext = token_data[TOKEN_NONCE_LEN..][0..ct_len];
    const tag = token_data[token_data.len - TOKEN_TAG_LEN ..][0..TOKEN_TAG_LEN].*;

    var plaintext: [TOKEN_MAX_PLAINTEXT_LEN]u8 = undefined;
    crypto.Aead.decrypt(
        plaintext[0..ct_len],
        ciphertext,
        tag,
        "",
        nonce,
        token_key,
    ) catch return null;

    var pt_fbs = io.fixedBufferStream(plaintext[0..ct_len]);
    const pt_reader = pt_fbs.reader();

    var result = ValidatedToken{};

    result.odcid_len = pt_reader.readByte() catch return null;
    if (result.odcid_len > 20) return null;
    _ = pt_reader.readAll(result.odcid_buf[0..result.odcid_len]) catch return null;

    result.retry_scid_len = pt_reader.readByte() catch return null;
    if (result.retry_scid_len > 20) return null;
    _ = pt_reader.readAll(result.retry_scid_buf[0..result.retry_scid_len]) catch return null;

    const timestamp = pt_reader.readInt(i64, ENDIAN) catch return null;
    const now: i64 = @intCast(time.nanoTimestamp());
    if (now - timestamp > TOKEN_MAX_AGE_NS or timestamp > now) return null;

    var addr_data: [14]u8 = undefined;
    _ = pt_reader.readAll(&addr_data) catch return null;
    if (!std.mem.eql(u8, &addr_data, addrDataBytes(&client_addr))) return null;

    return result;
}

pub fn generateNewToken(
    out: []u8,
    client_addr: posix.sockaddr.storage,
    token_key: [crypto.key_len]u8,
) !usize {
    if (out.len < NEW_TOKEN_MAX_LEN) return error.BufferTooSmall;

    var nonce: [TOKEN_NONCE_LEN]u8 = undefined;
    random.bytes(&nonce);
    @memcpy(out[0..TOKEN_NONCE_LEN], &nonce);

    var plaintext: [NEW_TOKEN_PLAINTEXT_LEN]u8 = undefined;
    var pt_fbs = io.fixedBufferStream(&plaintext);
    const pt_writer = pt_fbs.writer();
    const now: i64 = @intCast(time.nanoTimestamp());
    try pt_writer.writeInt(i64, now, ENDIAN);
    try pt_writer.writeAll(addrDataBytes(&client_addr));

    var ciphertext_buf: [NEW_TOKEN_PLAINTEXT_LEN]u8 = undefined;
    var tag: [TOKEN_TAG_LEN]u8 = undefined;
    crypto.Aead.encrypt(
        &ciphertext_buf,
        &tag,
        &plaintext,
        "",
        nonce,
        token_key,
    );

    @memcpy(out[TOKEN_NONCE_LEN..][0..NEW_TOKEN_PLAINTEXT_LEN], &ciphertext_buf);
    @memcpy(out[TOKEN_NONCE_LEN + NEW_TOKEN_PLAINTEXT_LEN ..][0..TOKEN_TAG_LEN], &tag);

    return NEW_TOKEN_MAX_LEN;
}

pub fn validateNewToken(
    token_data: []const u8,
    client_addr: posix.sockaddr.storage,
    token_key: [crypto.key_len]u8,
) bool {
    if (token_data.len != NEW_TOKEN_MAX_LEN) return false;

    const nonce = token_data[0..TOKEN_NONCE_LEN].*;
    const ciphertext = token_data[TOKEN_NONCE_LEN..][0..NEW_TOKEN_PLAINTEXT_LEN];
    const tag = token_data[token_data.len - TOKEN_TAG_LEN ..][0..TOKEN_TAG_LEN].*;

    var plaintext: [NEW_TOKEN_PLAINTEXT_LEN]u8 = undefined;
    crypto.Aead.decrypt(
        &plaintext,
        ciphertext,
        tag,
        "",
        nonce,
        token_key,
    ) catch return false;

    var pt_fbs = io.fixedBufferStream(&plaintext);
    const pt_reader = pt_fbs.reader();

    const timestamp = pt_reader.readInt(i64, ENDIAN) catch return false;
    const now: i64 = @intCast(time.nanoTimestamp());
    if (now - timestamp > TOKEN_MAX_AGE_NS or timestamp > now) return false;

    var addr_data: [14]u8 = undefined;
    _ = pt_reader.readAll(&addr_data) catch return false;
    if (!std.mem.eql(u8, &addr_data, addrDataBytes(&client_addr))) return false;

    return true;
}

test "Retry token: generate and validate roundtrip" {
    var token_key: [crypto.key_len]u8 = undefined;
    random.bytes(&token_key);

    const odcid = &[_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
    const retry_scid = &[_]u8{ 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18 };
    var addr: posix.sockaddr.storage = std.mem.zeroes(posix.sockaddr.storage);
    addr.family = posix.AF.INET;
    addr.padding[0] = 0x11;
    addr.padding[1] = 0x51;
    addr.padding[2] = 127;
    addr.padding[3] = 0;
    addr.padding[4] = 0;
    addr.padding[5] = 1;

    var out: [TOKEN_MAX_LEN]u8 = undefined;
    const token_len = try generateRetryToken(&out, odcid, retry_scid, addr, token_key);
    try std.testing.expect(token_len > TOKEN_NONCE_LEN + TOKEN_TAG_LEN);

    const validated = try validateRetryToken(out[0..token_len], addr, token_key);
    try std.testing.expect(validated != null);
    const v = validated.?;
    try std.testing.expectEqualSlices(u8, odcid, v.getOdcid());
    try std.testing.expectEqualSlices(u8, retry_scid, v.getRetryScid());
}

test "Retry token: wrong address rejected" {
    var token_key: [crypto.key_len]u8 = undefined;
    random.bytes(&token_key);

    const odcid = &[_]u8{ 0x01, 0x02, 0x03, 0x04 };
    const retry_scid = &[_]u8{ 0x11, 0x12, 0x13, 0x14 };
    var addr1: posix.sockaddr.storage = std.mem.zeroes(posix.sockaddr.storage);
    addr1.family = posix.AF.INET;
    addr1.padding[2] = 127;
    addr1.padding[5] = 1;

    var out: [TOKEN_MAX_LEN]u8 = undefined;
    const token_len = try generateRetryToken(&out, odcid, retry_scid, addr1, token_key);

    var addr2 = addr1;
    addr2.padding[2] = 10;
    const validated = try validateRetryToken(out[0..token_len], addr2, token_key);
    try std.testing.expect(validated == null);
}

test "Retry token: wrong key rejected" {
    var token_key: [crypto.key_len]u8 = undefined;
    random.bytes(&token_key);

    const odcid = &[_]u8{ 0x01, 0x02, 0x03, 0x04 };
    const retry_scid = &[_]u8{ 0x11, 0x12, 0x13, 0x14 };
    var addr: posix.sockaddr.storage = std.mem.zeroes(posix.sockaddr.storage);
    addr.family = posix.AF.INET;

    var out: [TOKEN_MAX_LEN]u8 = undefined;
    const token_len = try generateRetryToken(&out, odcid, retry_scid, addr, token_key);

    var wrong_key: [crypto.key_len]u8 = undefined;
    random.bytes(&wrong_key);
    const validated = try validateRetryToken(out[0..token_len], addr, wrong_key);
    try std.testing.expect(validated == null);
}
