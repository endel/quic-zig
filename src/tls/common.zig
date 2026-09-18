//! Record layer, key schedule and wire helpers shared by the sans-IO TLS 1.3
//! `tls_server` and `tls_client`.
const std = @import("std");

const crypto = std.crypto;
const tls = crypto.tls;
const mem = std.mem;
const Allocator = mem.Allocator;

/// Errors the shared helpers can return; a subset of both endpoints' sets.
pub const Error = error{
    DecodeError,
    UnexpectedMessage,
    BadRecordMac,
    RecordOverflow,
    InternalError,
    OutOfMemory,
};

pub const CipherSuite = enum(u16) {
    aes_128_gcm_sha256 = 0x1301,
    aes_256_gcm_sha384 = 0x1302,
    chacha20_poly1305_sha256 = 0x1303,
};

pub const Group = enum(u16) {
    secp256r1 = 0x0017,
    x25519 = 0x001d,
};

pub const max_plaintext = tls.max_ciphertext_inner_record_len; // 2^14
pub const max_handshake_msg = 1 << 16;
// RFC 8446 §5.5: AES-GCM is safe for 2^24.5 records per key; rotate well before.
pub const key_update_after: u64 = 1 << 23;

pub const hs_client_hello: u8 = @intFromEnum(tls.HandshakeType.client_hello);
pub const hs_server_hello: u8 = @intFromEnum(tls.HandshakeType.server_hello);
pub const hs_new_session_ticket: u8 = @intFromEnum(tls.HandshakeType.new_session_ticket);
pub const hs_encrypted_extensions: u8 = @intFromEnum(tls.HandshakeType.encrypted_extensions);
pub const hs_certificate: u8 = @intFromEnum(tls.HandshakeType.certificate);
pub const hs_certificate_verify: u8 = @intFromEnum(tls.HandshakeType.certificate_verify);
pub const hs_finished: u8 = @intFromEnum(tls.HandshakeType.finished);
pub const hs_key_update: u8 = @intFromEnum(tls.HandshakeType.key_update);
pub const hs_message_hash: u8 = @intFromEnum(tls.HandshakeType.message_hash);

pub const ct_ccs: u8 = @intFromEnum(tls.ContentType.change_cipher_spec);
pub const ct_alert: u8 = @intFromEnum(tls.ContentType.alert);
pub const ct_handshake: u8 = @intFromEnum(tls.ContentType.handshake);
pub const ct_app_data: u8 = @intFromEnum(tls.ContentType.application_data);

pub const ext = struct {
    pub const server_name: u16 = @intFromEnum(tls.ExtensionType.server_name);
    pub const supported_groups: u16 = @intFromEnum(tls.ExtensionType.supported_groups);
    pub const signature_algorithms: u16 = @intFromEnum(tls.ExtensionType.signature_algorithms);
    pub const alpn: u16 = @intFromEnum(tls.ExtensionType.application_layer_protocol_negotiation);
    pub const pre_shared_key: u16 = @intFromEnum(tls.ExtensionType.pre_shared_key);
    pub const psk_key_exchange_modes: u16 = @intFromEnum(tls.ExtensionType.psk_key_exchange_modes);
    pub const early_data: u16 = @intFromEnum(tls.ExtensionType.early_data);
    pub const supported_versions: u16 = @intFromEnum(tls.ExtensionType.supported_versions);
    pub const cookie: u16 = @intFromEnum(tls.ExtensionType.cookie);
    pub const key_share: u16 = @intFromEnum(tls.ExtensionType.key_share);
};

pub const tls13_version: u16 = @intFromEnum(tls.ProtocolVersion.tls_1_3);

// ─── Per-suite primitives ────────────────────────────────────────────

pub fn Suite(comptime cs: CipherSuite) type {
    return struct {
        pub const Hash = switch (cs) {
            .aes_256_gcm_sha384 => crypto.hash.sha2.Sha384,
            else => crypto.hash.sha2.Sha256,
        };
        pub const Hmac = crypto.auth.hmac.Hmac(Hash);
        pub const Hkdf = crypto.kdf.hkdf.Hkdf(Hmac);
        pub const Aead = switch (cs) {
            .aes_128_gcm_sha256 => crypto.aead.aes_gcm.Aes128Gcm,
            .aes_256_gcm_sha384 => crypto.aead.aes_gcm.Aes256Gcm,
            .chacha20_poly1305_sha256 => crypto.aead.chacha_poly.ChaCha20Poly1305,
        };
        pub const hash_len = Hash.digest_length;

        pub fn expand(secret: []const u8, label: []const u8, context: []const u8, comptime len: usize) [len]u8 {
            return tls.hkdfExpandLabel(Hkdf, secret[0..hash_len].*, label, context, len);
        }
    };
}

pub fn hashLen(cs: CipherSuite) usize {
    return switch (cs) {
        inline else => |c| Suite(c).hash_len,
    };
}

/// Big enough for any suite's hash / secret; only the first `hashLen` bytes count.
pub const Secret = [48]u8;

pub const Transcript = union(enum) {
    sha256: crypto.hash.sha2.Sha256,
    sha384: crypto.hash.sha2.Sha384,

    pub fn init(cs: CipherSuite) Transcript {
        return switch (cs) {
            .aes_256_gcm_sha384 => .{ .sha384 = .init(.{}) },
            else => .{ .sha256 = .init(.{}) },
        };
    }

    pub fn update(t: *Transcript, bytes: []const u8) void {
        switch (t.*) {
            inline else => |*h| h.update(bytes),
        }
    }

    pub fn peek(t: *const Transcript) Secret {
        var out: Secret = @splat(0);
        switch (t.*) {
            inline else => |h| {
                var copy = h;
                copy.final(out[0..@TypeOf(h).digest_length]);
            },
        }
        return out;
    }
};

pub const TrafficKeys = struct {
    secret: Secret,
    key: [32]u8,
    iv: [12]u8,
    seq: u64 = 0,

    pub fn derive(cs: CipherSuite, secret: Secret) TrafficKeys {
        switch (cs) {
            inline else => |c| {
                const S = Suite(c);
                var k: TrafficKeys = .{ .secret = secret, .key = @splat(0), .iv = S.expand(&secret, "iv", "", 12) };
                k.key[0..S.Aead.key_length].* = S.expand(&secret, "key", "", S.Aead.key_length);
                return k;
            },
        }
    }

    pub fn next(k: *const TrafficKeys, cs: CipherSuite) TrafficKeys {
        var secret: Secret = @splat(0);
        switch (cs) {
            inline else => |c| {
                const S = Suite(c);
                secret[0..S.hash_len].* = S.expand(&k.secret, "traffic upd", "", S.hash_len);
            },
        }
        return derive(cs, secret);
    }

    pub fn nonce(k: *const TrafficKeys) [12]u8 {
        var n = k.iv;
        const seq: [8]u8 = @bitCast(mem.nativeToBig(u64, k.seq));
        for (seq, 0..) |b, i| n[4 + i] ^= b;
        return n;
    }
};

// Heap-allocated on first use so `Conn` itself stays small enough to embed.
pub const Buffers = struct {
    in: [tls.max_ciphertext_record_len]u8,
    scratch: [tls.max_ciphertext_len]u8,
};

// ─── Record protection and key schedule ──────────────────────────────

pub fn sealedLen(cs: CipherSuite, content_len: usize) usize {
    return switch (cs) {
        inline else => |c| tls.record_header_len + content_len + 1 + Suite(c).Aead.tag_length,
    };
}

/// Seals `content` as one TLSCiphertext into `dst` (exactly `sealedLen`
/// bytes), staging the inner plaintext in `scratch`.
pub fn sealInto(cs: CipherSuite, keys: *TrafficKeys, inner: tls.ContentType, content: []const u8, scratch: []u8, dst: []u8) void {
    std.debug.assert(content.len <= max_plaintext);
    const pt = scratch[0 .. content.len + 1];
    @memcpy(pt[0..content.len], content);
    pt[content.len] = @intFromEnum(inner);
    switch (cs) {
        inline else => |c| {
            const A = Suite(c).Aead;
            const hdr = dst[0..tls.record_header_len];
            hdr.* = .{ ct_app_data, 0x03, 0x03, 0, 0 };
            mem.writeInt(u16, hdr[3..5], @intCast(pt.len + A.tag_length), .big);
            const body = dst[tls.record_header_len..];
            A.encrypt(body[0..pt.len], body[pt.len..][0..A.tag_length], pt, hdr, keys.nonce(), keys.key[0..A.key_length].*);
        },
    }
    keys.seq += 1;
}

/// Opens one TLSCiphertext into `out`; returns the TLSInnerPlaintext.
pub fn openWith(cs: CipherSuite, keys: *TrafficKeys, record: []const u8, out: []u8) Error![]u8 {
    if (keys.seq == std.math.maxInt(u64)) return error.UnexpectedMessage;
    const payload = record[tls.record_header_len..];
    const plain = switch (cs) {
        inline else => |c| blk: {
            const A = Suite(c).Aead;
            if (payload.len < A.tag_length + 1) return error.BadRecordMac;
            const n = payload.len - A.tag_length;
            if (n > max_plaintext + 1) return error.RecordOverflow;
            A.decrypt(
                out[0..n],
                payload[0..n],
                payload[n..][0..A.tag_length].*,
                record[0..tls.record_header_len],
                keys.nonce(),
                keys.key[0..A.key_length].*,
            ) catch return error.BadRecordMac;
            break :blk out[0..n];
        },
    };
    keys.seq += 1;
    return plain;
}

pub const HandshakeSecrets = struct { handshake: Secret, client: Secret, server: Secret };

pub fn handshakeSecrets(cs: CipherSuite, psk: ?*const Secret, th: Secret, shared: []const u8) HandshakeSecrets {
    var out: HandshakeSecrets = .{ .handshake = @splat(0), .client = @splat(0), .server = @splat(0) };
    switch (cs) {
        inline else => |c| {
            const S = Suite(c);
            const L = S.hash_len;
            const zeros: [L]u8 = @splat(0);
            const early = S.Hkdf.extract(&.{}, if (psk) |k| k[0..L] else &zeros);
            const derived = S.expand(&early, "derived", &tls.emptyHash(S.Hash), L);
            const hs = S.Hkdf.extract(&derived, shared);
            out.handshake[0..L].* = hs;
            out.client[0..L].* = S.expand(&hs, "c hs traffic", th[0..L], L);
            out.server[0..L].* = S.expand(&hs, "s hs traffic", th[0..L], L);
        },
    }
    return out;
}

pub fn appSecrets(cs: CipherSuite, handshake_secret: Secret, th: Secret) struct { client: Secret, server: Secret, master: Secret } {
    var client: Secret = @splat(0);
    var server: Secret = @splat(0);
    var master_out: Secret = @splat(0);
    switch (cs) {
        inline else => |c| {
            const S = Suite(c);
            const L = S.hash_len;
            const derived = S.expand(&handshake_secret, "derived", &tls.emptyHash(S.Hash), L);
            const zeros: [L]u8 = @splat(0);
            const master = S.Hkdf.extract(&derived, &zeros);
            master_out[0..L].* = master;
            client[0..L].* = S.expand(&master, "c ap traffic", th[0..L], L);
            server[0..L].* = S.expand(&master, "s ap traffic", th[0..L], L);
        },
    }
    return .{ .client = client, .server = server, .master = master_out };
}

/// Finished verify_data over transcript hash `th` (RFC 8446 §4.4.4).
pub fn finishedMac(cs: CipherSuite, base_key: *const Secret, th: Secret) Secret {
    var out: Secret = @splat(0);
    switch (cs) {
        inline else => |c| {
            const S = Suite(c);
            const key = S.expand(base_key, "finished", "", S.hash_len);
            out[0..S.hash_len].* = tls.hmac(S.Hmac, th[0..S.hash_len], key);
        },
    }
    return out;
}

pub const Parser = struct {
    buf: []const u8,
    pos: usize = 0,

    pub fn rest(p: *const Parser) usize {
        return p.buf.len - p.pos;
    }
    pub fn take(p: *Parser, n: usize) Error![]const u8 {
        if (p.rest() < n) return error.DecodeError;
        defer p.pos += n;
        return p.buf[p.pos..][0..n];
    }
    pub fn int(p: *Parser, comptime T: type) Error!T {
        const n = @divExact(@typeInfo(T).int.bits, 8);
        return mem.readInt(T, (try p.take(n))[0..n], .big);
    }
    pub fn vec(p: *Parser, comptime Len: type) Error![]const u8 {
        return p.take(try p.int(Len));
    }
};

pub fn u16List(data: []const u8, comptime Len: type) Error![]const u8 {
    var p: Parser = .{ .buf = data };
    const list = try p.vec(Len);
    if (p.rest() != 0 or list.len < 2 or list.len % 2 != 0) return error.DecodeError;
    return list;
}

pub fn containsU16(list: []const u8, value: u16) bool {
    var i: usize = 0;
    while (i + 2 <= list.len) : (i += 2) {
        if (mem.readInt(u16, list[i..][0..2], .big) == value) return true;
    }
    return false;
}

pub fn alpnListContains(list: []const u8, proto: []const u8) bool {
    var p: Parser = .{ .buf = list };
    while (p.rest() > 0) {
        const name = p.vec(u8) catch return false;
        if (mem.eql(u8, name, proto)) return true;
    }
    return false;
}

pub const Builder = struct {
    list: *std.ArrayList(u8),
    gpa: Allocator,

    pub fn u8_(b: *Builder, v: u8) Error!void {
        try b.list.append(b.gpa, v);
    }
    pub fn u16_(b: *Builder, v: u16) Error!void {
        try b.list.appendSlice(b.gpa, &mem.toBytes(mem.nativeToBig(u16, v)));
    }
    pub fn u24_(b: *Builder, v: u24) Error!void {
        var tmp: [3]u8 = undefined;
        mem.writeInt(u24, &tmp, v, .big);
        try b.list.appendSlice(b.gpa, &tmp);
    }
    pub fn bytes(b: *Builder, v: []const u8) Error!void {
        try b.list.appendSlice(b.gpa, v);
    }
    /// Reserves a `Len`-sized length prefix; close it with `end`.
    pub fn begin(b: *Builder, comptime Len: type) Error!usize {
        try b.list.appendNTimes(b.gpa, 0, @divExact(@typeInfo(Len).int.bits, 8));
        return b.list.items.len;
    }
    pub fn end(b: *Builder, comptime Len: type, start: usize) Error!void {
        const n = @divExact(@typeInfo(Len).int.bits, 8);
        const len = b.list.items.len - start;
        if (len > std.math.maxInt(Len)) return error.InternalError;
        mem.writeInt(Len, b.list.items[start - n ..][0..n], @intCast(len), .big);
    }
};
