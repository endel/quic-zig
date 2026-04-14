// Proprietary LB↔backend UDP framing used when QUIC-LB is in netcode mode.
//
// When the LB decides to forward a validated post-Retry Initial (or any
// packet that carries out-of-band context the backend needs), it prepends
// this envelope to the datagram. The backend strips the envelope before
// feeding the inner bytes into its normal QUIC parser.
//
// Wire layout:
//
//   magic(4)       = 'N','C','N','R'   (0x4E434E52 big-endian)
//   version(1)     = 1
//   flags(1)       = bit0 was_retried | bit1 has_hmac
//   odcid_len(1)   = 0..20
//   odcid(odcid_len)
//   retry_scid_len(1) = 0..20
//   retry_scid(retry_scid_len)
//   hmac(16)       if flags.has_hmac (HMAC-SHA256 truncated to 16 bytes)
//   quic_payload(...)  the original UDP payload
//
// HMAC covers: magic || version || flags || odcid_len || odcid ||
//              retry_scid_len || retry_scid || quic_payload
// (Excludes the hmac field itself.)
//
// This framing is opaque to clients — it lives strictly on the LB↔backend
// leg and assumes that leg is either private network or authenticated via
// HMAC.

const std = @import("std");
const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
const lb_adapter = @import("lb_adapter.zig");

pub const MAGIC: [4]u8 = .{ 'N', 'C', 'N', 'R' };
pub const VERSION: u8 = 1;
pub const HMAC_LEN: usize = 16;
pub const MAX_CID_LEN: usize = 20;

pub const FLAG_WAS_RETRIED: u8 = 0x01;
pub const FLAG_HAS_HMAC: u8 = 0x02;

pub const MIN_HEADER_LEN: usize = 4 + 1 + 1 + 1 + 1; // magic..retry_scid_len, empty CIDs
pub const MAX_HEADER_LEN: usize = 4 + 1 + 1 + 1 + MAX_CID_LEN + 1 + MAX_CID_LEN + HMAC_LEN;

pub const EncodeError = error{ BufferTooSmall, CidTooLong };
pub const DecodeError = error{
    TooShort,
    BadMagic,
    UnsupportedVersion,
    CidTooLong,
    Truncated,
    HmacMismatch,
    HmacRequired,
};

pub const Decoded = struct {
    flags: u8,
    odcid_buf: [MAX_CID_LEN]u8 = .{0} ** MAX_CID_LEN,
    odcid_len: u8 = 0,
    retry_scid_buf: [MAX_CID_LEN]u8 = .{0} ** MAX_CID_LEN,
    retry_scid_len: u8 = 0,
    payload_offset: usize,

    pub fn odcid(self: *const Decoded) []const u8 {
        return self.odcid_buf[0..self.odcid_len];
    }
    pub fn retryScid(self: *const Decoded) []const u8 {
        return self.retry_scid_buf[0..self.retry_scid_len];
    }
    pub fn wasRetried(self: *const Decoded) bool {
        return (self.flags & FLAG_WAS_RETRIED) != 0;
    }
};

/// Quick magic check without full parsing. Useful for the receive path,
/// where non-enveloped packets should fall through to the normal QUIC parser.
pub fn hasMagic(buf: []const u8) bool {
    return buf.len >= 4 and std.mem.eql(u8, buf[0..4], &MAGIC);
}

/// Write an envelope header into `out`, followed by `payload`. Returns the
/// total number of bytes written. If `hmac_key` is non-null, a FLAG_HAS_HMAC
/// authentication tag is included.
pub fn encode(
    out: []u8,
    odcid: []const u8,
    retry_scid: []const u8,
    was_retried: bool,
    hmac_key: ?[32]u8,
    payload: []const u8,
) EncodeError!usize {
    if (odcid.len > MAX_CID_LEN or retry_scid.len > MAX_CID_LEN) return error.CidTooLong;

    var flags: u8 = 0;
    if (was_retried) flags |= FLAG_WAS_RETRIED;
    if (hmac_key != null) flags |= FLAG_HAS_HMAC;

    const header_len: usize = 4 + 1 + 1 + 1 + odcid.len + 1 + retry_scid.len +
        (if (hmac_key != null) HMAC_LEN else 0);
    const total = header_len + payload.len;
    if (out.len < total) return error.BufferTooSmall;

    var i: usize = 0;
    @memcpy(out[i..][0..4], &MAGIC);
    i += 4;
    out[i] = VERSION;
    i += 1;
    out[i] = flags;
    i += 1;
    out[i] = @intCast(odcid.len);
    i += 1;
    @memcpy(out[i..][0..odcid.len], odcid);
    i += odcid.len;
    out[i] = @intCast(retry_scid.len);
    i += 1;
    @memcpy(out[i..][0..retry_scid.len], retry_scid);
    i += retry_scid.len;

    // HMAC slot (if any) — we fill it after writing the payload.
    const hmac_slot_start: usize = i;
    if (hmac_key != null) {
        @memset(out[i..][0..HMAC_LEN], 0);
        i += HMAC_LEN;
    }

    @memcpy(out[i..][0..payload.len], payload);
    i += payload.len;

    if (hmac_key) |k| {
        var mac: [HmacSha256.mac_length]u8 = undefined;
        var hmac = HmacSha256.init(&k);
        hmac.update(out[0..hmac_slot_start]); // magic..retry_scid (header without hmac)
        hmac.update(out[hmac_slot_start + HMAC_LEN .. i]); // payload
        hmac.final(&mac);
        @memcpy(out[hmac_slot_start..][0..HMAC_LEN], mac[0..HMAC_LEN]);
    }

    return i;
}

/// Parse an envelope from `buf`. On success returns the parsed metadata and
/// the offset at which the inner QUIC payload begins. If `hmac_key` is
/// non-null, any envelope without FLAG_HAS_HMAC is rejected with
/// `error.HmacRequired`; any envelope with a bad tag is rejected with
/// `error.HmacMismatch`.
pub fn decode(buf: []const u8, hmac_key: ?[32]u8) DecodeError!Decoded {
    if (buf.len < MIN_HEADER_LEN) return error.TooShort;
    if (!std.mem.eql(u8, buf[0..4], &MAGIC)) return error.BadMagic;

    var i: usize = 4;
    const version = buf[i];
    i += 1;
    if (version != VERSION) return error.UnsupportedVersion;

    const flags = buf[i];
    i += 1;

    const odcid_len = buf[i];
    i += 1;
    if (odcid_len > MAX_CID_LEN) return error.CidTooLong;
    if (buf.len < i + odcid_len + 1) return error.Truncated;

    var d = Decoded{ .flags = flags, .payload_offset = 0, .odcid_len = odcid_len };
    @memcpy(d.odcid_buf[0..odcid_len], buf[i..][0..odcid_len]);
    i += odcid_len;

    const retry_scid_len = buf[i];
    i += 1;
    if (retry_scid_len > MAX_CID_LEN) return error.CidTooLong;
    if (buf.len < i + retry_scid_len) return error.Truncated;
    d.retry_scid_len = retry_scid_len;
    @memcpy(d.retry_scid_buf[0..retry_scid_len], buf[i..][0..retry_scid_len]);
    i += retry_scid_len;

    const has_hmac = (flags & FLAG_HAS_HMAC) != 0;
    if (hmac_key != null and !has_hmac) return error.HmacRequired;
    if (has_hmac) {
        if (buf.len < i + HMAC_LEN) return error.Truncated;
        const hmac_slot_start = i;
        i += HMAC_LEN;
        if (hmac_key) |k| {
            var mac: [HmacSha256.mac_length]u8 = undefined;
            var hmac = HmacSha256.init(&k);
            hmac.update(buf[0..hmac_slot_start]);
            hmac.update(buf[i..]);
            hmac.final(&mac);
            const received = buf[hmac_slot_start..][0..HMAC_LEN];
            if (!std.crypto.timing_safe.eql([HMAC_LEN]u8, mac[0..HMAC_LEN].*, received.*)) {
                return error.HmacMismatch;
            }
        }
        // If hmac_key is null but has_hmac is set, we accept and skip the tag —
        // trust model choice: LB advertises hmac but backend isn't configured
        // to verify. Documented: configure both sides consistently.
    }

    d.payload_offset = i;
    return d;
}

// --- LbAdapter implementation ---

/// Owns the configuration (HMAC key) and exposes a generic `LbAdapter`.
/// The adapter is the plug point the ConnectionManager uses to strip LB
/// framing without knowing the wire format.
pub const Adapter = struct {
    hmac_key: ?[32]u8 = null,

    pub fn lbAdapter(self: *const Adapter) lb_adapter.LbAdapter {
        return .{
            .ctx = @constCast(@ptrCast(self)),
            .unwrap_fn = unwrapImpl,
        };
    }

    fn unwrapImpl(ctx: *anyopaque, buf: []const u8) lb_adapter.UnwrapResult {
        const self: *const Adapter = @ptrCast(@alignCast(ctx));
        if (!hasMagic(buf)) return .passthrough;
        const decoded = decode(buf, self.hmac_key) catch return .drop;

        var result: lb_adapter.InjectedContext = .{
            .payload_offset = decoded.payload_offset,
            .was_retried = decoded.wasRetried(),
            .odcid_len = decoded.odcid_len,
            .retry_scid_len = decoded.retry_scid_len,
        };
        @memcpy(result.odcid_buf[0..decoded.odcid_len], decoded.odcid());
        @memcpy(result.retry_scid_buf[0..decoded.retry_scid_len], decoded.retryScid());
        return .{ .injected = result };
    }
};

// --- Tests ---

test "envelope: encode/decode roundtrip no hmac" {
    const odcid = [_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
    const retry_scid = [_]u8{ 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA };
    const payload = "hello quic payload";

    var buf: [512]u8 = undefined;
    const n = try encode(&buf, &odcid, &retry_scid, true, null, payload);

    const d = try decode(buf[0..n], null);
    try std.testing.expect(d.wasRetried());
    try std.testing.expectEqualSlices(u8, &odcid, d.odcid());
    try std.testing.expectEqualSlices(u8, &retry_scid, d.retryScid());
    try std.testing.expectEqualSlices(u8, payload, buf[d.payload_offset..n]);
}

test "envelope: encode/decode roundtrip with hmac" {
    const key: [32]u8 = .{0x42} ** 32;
    const odcid = [_]u8{ 0xAA, 0xBB };
    const retry_scid = [_]u8{ 0xCC, 0xDD, 0xEE };
    const payload = "integrity-protected";

    var buf: [512]u8 = undefined;
    const n = try encode(&buf, &odcid, &retry_scid, true, key, payload);

    const d = try decode(buf[0..n], key);
    try std.testing.expect(d.wasRetried());
    try std.testing.expectEqualSlices(u8, &odcid, d.odcid());
    try std.testing.expectEqualSlices(u8, &retry_scid, d.retryScid());
    try std.testing.expectEqualSlices(u8, payload, buf[d.payload_offset..n]);
}

test "envelope: tampered payload fails hmac" {
    const key: [32]u8 = .{0x01} ** 32;
    const payload = "data-to-protect";

    var buf: [512]u8 = undefined;
    const n = try encode(&buf, &.{}, &.{}, false, key, payload);
    // Flip a bit inside the payload
    buf[n - 1] ^= 0x80;

    try std.testing.expectError(error.HmacMismatch, decode(buf[0..n], key));
}

test "envelope: tampered header fails hmac" {
    const key: [32]u8 = .{0x01} ** 32;
    const payload = "data";

    var buf: [512]u8 = undefined;
    const n = try encode(&buf, &[_]u8{ 1, 2, 3 }, &.{}, true, key, payload);
    // Flip a flag bit
    buf[5] ^= FLAG_WAS_RETRIED;

    try std.testing.expectError(error.HmacMismatch, decode(buf[0..n], key));
}

test "envelope: hasMagic detects framed packets" {
    const key: [32]u8 = .{0} ** 32;
    var buf: [64]u8 = undefined;
    const n = try encode(&buf, &.{}, &.{}, false, key, "x");
    try std.testing.expect(hasMagic(buf[0..n]));

    const plain = [_]u8{ 0xc0, 0x00, 0x00, 0x00, 0x01 };
    try std.testing.expect(!hasMagic(&plain));
}

test "envelope: bad magic rejected" {
    const bad = [_]u8{ 'X', 'X', 'X', 'X', 1, 0, 0, 0 };
    try std.testing.expectError(error.BadMagic, decode(&bad, null));
}

test "envelope: wrong version rejected" {
    var buf: [32]u8 = undefined;
    @memcpy(buf[0..4], &MAGIC);
    buf[4] = 99; // version
    buf[5] = 0; // flags
    buf[6] = 0; // odcid_len
    buf[7] = 0; // retry_scid_len
    try std.testing.expectError(error.UnsupportedVersion, decode(buf[0..8], null));
}

test "envelope: truncated rejected" {
    var buf: [32]u8 = undefined;
    @memcpy(buf[0..4], &MAGIC);
    buf[4] = VERSION;
    buf[5] = 0;
    buf[6] = 20; // odcid_len=20 — header claims 20-byte ODCID follows
    // Buffer length is 10, which is > MIN_HEADER_LEN=8 (so passes initial check)
    // but less than 7 + 20 + 1, so the odcid bounds check trips.
    try std.testing.expectError(error.Truncated, decode(buf[0..10], null));
}

test "Adapter: passthrough on plain QUIC" {
    const adapter_cfg = Adapter{ .hmac_key = null };
    const adapter = adapter_cfg.lbAdapter();
    const plain = [_]u8{ 0xc0, 0x00, 0x00, 0x00, 0x01 };
    try std.testing.expectEqual(lb_adapter.UnwrapResult.passthrough, adapter.unwrap(&plain));
}

test "Adapter: injects context on valid enveloped datagram" {
    const key: [32]u8 = .{0x77} ** 32;
    const adapter_cfg = Adapter{ .hmac_key = key };
    const adapter = adapter_cfg.lbAdapter();

    const odcid = [_]u8{ 0x01, 0x02, 0x03, 0x04 };
    const retry_scid = [_]u8{ 0xaa, 0xbb };
    const payload = "INITIAL_BYTES";
    var buf: [256]u8 = undefined;
    const n = try encode(&buf, &odcid, &retry_scid, true, key, payload);

    switch (adapter.unwrap(buf[0..n])) {
        .injected => |ctx| {
            try std.testing.expect(ctx.was_retried);
            try std.testing.expectEqualSlices(u8, &odcid, ctx.odcid());
            try std.testing.expectEqualSlices(u8, &retry_scid, ctx.retryScid());
            try std.testing.expectEqualSlices(u8, payload, buf[ctx.payload_offset..n]);
        },
        else => try std.testing.expect(false),
    }
}

test "Adapter: drops on bad hmac" {
    const key: [32]u8 = .{0x88} ** 32;
    const adapter_cfg = Adapter{ .hmac_key = key };
    const adapter = adapter_cfg.lbAdapter();

    var buf: [128]u8 = undefined;
    const n = try encode(&buf, &.{}, &.{}, false, key, "data");
    buf[n - 1] ^= 0xFF;
    try std.testing.expectEqual(lb_adapter.UnwrapResult.drop, adapter.unwrap(buf[0..n]));
}

test "envelope: hmac required if key configured and flag absent" {
    const key: [32]u8 = .{0x01} ** 32;
    var buf: [64]u8 = undefined;
    const n = try encode(&buf, &.{}, &.{}, false, null, "data"); // no HMAC flag
    try std.testing.expectError(error.HmacRequired, decode(buf[0..n], key));
}
