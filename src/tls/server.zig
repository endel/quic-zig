//! Sans-IO TLS 1.3 server connection (RFC 8446) for TLS over TCP.
//!
//! `Conn` never touches a socket: the caller feeds it the ciphertext it read,
//! flushes `pendingOutput()` to the peer, and moves plaintext with `read` /
//! `write`. That makes it usable from any event loop.
//!
//! Supported:
//! - TLS 1.3 only; a client that does not offer it gets a `protocol_version`
//!   alert.
//! - TLS_AES_128_GCM_SHA256, TLS_CHACHA20_POLY1305_SHA256,
//!   TLS_AES_256_GCM_SHA384, picked in the server's preference order.
//! - X25519 and secp256r1 key exchange, with HelloRetryRequest when the
//!   client's key_share has no group we accept but supported_groups does.
//! - ECDSA P-256 / SHA-256 and Ed25519 certificates, selected by SNI.
//! - ALPN, middlebox compatibility mode, KeyUpdate in both directions.
//! - With `Config.ticket_key`: stateless session tickets and PSK-DHE
//!   resumption (psk_dhe_ke; the key exchange still runs).
//!
//! Not supported, by design: TLS 1.2 and earlier, client certificates,
//! 0-RTT (early data offered by a client is skipped), psk_ke resumption
//! without (EC)DHE, external PSKs, RSA certificates, record size limit and
//! other optional extensions.

const std = @import("std");
const sys = @import("../sys.zig");
const tls13 = @import("../quic/tls13.zig");

const crypto = std.crypto;
const tls = crypto.tls;
const mem = std.mem;
const Allocator = mem.Allocator;
const X25519 = crypto.dh.X25519;
const P256 = crypto.ecc.P256;
const EcdsaP256Sha256 = crypto.sign.ecdsa.EcdsaP256Sha256;
const Ed25519 = crypto.sign.Ed25519;

pub const Certificate = tls13.ServerCertificate;
pub const CertEntry = tls13.CertEntry;
pub const PrivateKeyAlgorithm = tls13.PrivateKeyAlgorithm;

pub const CipherSuite = enum(u16) {
    aes_128_gcm_sha256 = 0x1301,
    aes_256_gcm_sha384 = 0x1302,
    chacha20_poly1305_sha256 = 0x1303,
};

pub const Group = enum(u16) {
    secp256r1 = 0x0017,
    x25519 = 0x001d,
};

pub const Config = struct {
    /// Certificates chosen by SNI (exact name, then a one-label wildcard);
    /// `certs[0]` is the default when the client sends no SNI or an unknown
    /// name. Must not be empty.
    certs: []const CertEntry,
    /// Server preference order. When the client offers ALPN and none of these
    /// match, the handshake fails with `no_application_protocol`. Empty means
    /// ALPN is ignored.
    alpn: []const []const u8 = &.{},
    /// Server preference order.
    cipher_suites: []const CipherSuite = &.{ .aes_128_gcm_sha256, .chacha20_poly1305_sha256, .aes_256_gcm_sha384 },
    /// Server preference order. A group the client already sent a key share
    /// for wins over a preferred one that would cost a HelloRetryRequest.
    groups: []const Group = &.{ .x25519, .secp256r1 },
    /// Enables session tickets: after each handshake the client gets one
    /// ticket, sealed with this AES-128-GCM key, that lets it resume with
    /// PSK-DHE. Every server that should accept a ticket needs the same key;
    /// rotating it invalidates outstanding tickets. Tickets are bound to the
    /// SNI they were issued under.
    ticket_key: ?[16]u8 = null,
    /// How long a ticket stays valid, in seconds (RFC 8446 caps it at 7 days).
    ticket_lifetime_s: u32 = 24 * 3600,
};

pub const Error = error{
    // Protocol violations by the peer; each queues the matching alert.
    DecodeError,
    IllegalParameter,
    UnexpectedMessage,
    HandshakeFailure,
    ProtocolVersion,
    NoApplicationProtocol,
    MissingExtension,
    BadRecordMac,
    RecordOverflow,
    DecryptError,
    InternalError,
    /// The peer sent a fatal alert; see `peerAlert()`.
    PeerAlert,
    /// An earlier `feed` already failed; the connection is dead.
    ConnectionFailed,
    /// `write` before the handshake completed or after `close`.
    NotConnected,
    OutOfMemory,
};

const max_plaintext = tls.max_ciphertext_inner_record_len; // 2^14
const max_handshake_msg = 1 << 16;
// RFC 8446 §5.5: AES-GCM is safe for 2^24.5 records per key; rotate well before.
const key_update_after: u64 = 1 << 23;
// Budget for skipping 0-RTT records we never agreed to (RFC 8446 §4.2.10).
const early_data_skip_budget: usize = 1 << 16;

const hs_client_hello: u8 = @intFromEnum(tls.HandshakeType.client_hello);
const hs_server_hello: u8 = @intFromEnum(tls.HandshakeType.server_hello);
const hs_new_session_ticket: u8 = @intFromEnum(tls.HandshakeType.new_session_ticket);
const hs_encrypted_extensions: u8 = @intFromEnum(tls.HandshakeType.encrypted_extensions);
const hs_certificate: u8 = @intFromEnum(tls.HandshakeType.certificate);
const hs_certificate_verify: u8 = @intFromEnum(tls.HandshakeType.certificate_verify);
const hs_finished: u8 = @intFromEnum(tls.HandshakeType.finished);
const hs_key_update: u8 = @intFromEnum(tls.HandshakeType.key_update);
const hs_message_hash: u8 = @intFromEnum(tls.HandshakeType.message_hash);

const ct_ccs: u8 = @intFromEnum(tls.ContentType.change_cipher_spec);
const ct_alert: u8 = @intFromEnum(tls.ContentType.alert);
const ct_handshake: u8 = @intFromEnum(tls.ContentType.handshake);
const ct_app_data: u8 = @intFromEnum(tls.ContentType.application_data);

const ext = struct {
    const server_name: u16 = @intFromEnum(tls.ExtensionType.server_name);
    const supported_groups: u16 = @intFromEnum(tls.ExtensionType.supported_groups);
    const signature_algorithms: u16 = @intFromEnum(tls.ExtensionType.signature_algorithms);
    const alpn: u16 = @intFromEnum(tls.ExtensionType.application_layer_protocol_negotiation);
    const pre_shared_key: u16 = @intFromEnum(tls.ExtensionType.pre_shared_key);
    const psk_key_exchange_modes: u16 = @intFromEnum(tls.ExtensionType.psk_key_exchange_modes);
    const early_data: u16 = @intFromEnum(tls.ExtensionType.early_data);
    const supported_versions: u16 = @intFromEnum(tls.ExtensionType.supported_versions);
    const cookie: u16 = @intFromEnum(tls.ExtensionType.cookie);
    const key_share: u16 = @intFromEnum(tls.ExtensionType.key_share);
};

const tls13_version: u16 = @intFromEnum(tls.ProtocolVersion.tls_1_3);

// ─── Per-suite primitives ────────────────────────────────────────────

fn Suite(comptime cs: CipherSuite) type {
    return struct {
        const Hash = switch (cs) {
            .aes_256_gcm_sha384 => crypto.hash.sha2.Sha384,
            else => crypto.hash.sha2.Sha256,
        };
        const Hmac = crypto.auth.hmac.Hmac(Hash);
        const Hkdf = crypto.kdf.hkdf.Hkdf(Hmac);
        const Aead = switch (cs) {
            .aes_128_gcm_sha256 => crypto.aead.aes_gcm.Aes128Gcm,
            .aes_256_gcm_sha384 => crypto.aead.aes_gcm.Aes256Gcm,
            .chacha20_poly1305_sha256 => crypto.aead.chacha_poly.ChaCha20Poly1305,
        };
        const hash_len = Hash.digest_length;

        fn expand(secret: []const u8, label: []const u8, context: []const u8, comptime len: usize) [len]u8 {
            return tls.hkdfExpandLabel(Hkdf, secret[0..hash_len].*, label, context, len);
        }
    };
}

fn hashLen(cs: CipherSuite) usize {
    return switch (cs) {
        inline else => |c| Suite(c).hash_len,
    };
}

/// Big enough for any suite's hash / secret; only the first `hashLen` bytes count.
const Secret = [48]u8;

const Transcript = union(enum) {
    sha256: crypto.hash.sha2.Sha256,
    sha384: crypto.hash.sha2.Sha384,

    fn init(cs: CipherSuite) Transcript {
        return switch (cs) {
            .aes_256_gcm_sha384 => .{ .sha384 = .init(.{}) },
            else => .{ .sha256 = .init(.{}) },
        };
    }

    fn update(t: *Transcript, bytes: []const u8) void {
        switch (t.*) {
            inline else => |*h| h.update(bytes),
        }
    }

    fn peek(t: *const Transcript) Secret {
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

const TrafficKeys = struct {
    secret: Secret,
    key: [32]u8,
    iv: [12]u8,
    seq: u64 = 0,

    fn derive(cs: CipherSuite, secret: Secret) TrafficKeys {
        switch (cs) {
            inline else => |c| {
                const S = Suite(c);
                var k: TrafficKeys = .{ .secret = secret, .key = @splat(0), .iv = S.expand(&secret, "iv", "", 12) };
                k.key[0..S.Aead.key_length].* = S.expand(&secret, "key", "", S.Aead.key_length);
                return k;
            },
        }
    }

    fn next(k: *const TrafficKeys, cs: CipherSuite) TrafficKeys {
        var secret: Secret = @splat(0);
        switch (cs) {
            inline else => |c| {
                const S = Suite(c);
                secret[0..S.hash_len].* = S.expand(&k.secret, "traffic upd", "", S.hash_len);
            },
        }
        return derive(cs, secret);
    }

    fn nonce(k: *const TrafficKeys) [12]u8 {
        var n = k.iv;
        const seq: [8]u8 = @bitCast(mem.nativeToBig(u64, k.seq));
        for (seq, 0..) |b, i| n[4 + i] ^= b;
        return n;
    }
};

// ─── Connection ──────────────────────────────────────────────────────

const State = enum {
    wait_client_hello,
    wait_client_hello_retry,
    wait_finished,
    connected,
    failed,
};

// Heap-allocated on first use so `Conn` itself stays small enough to embed.
const Buffers = struct {
    in: [tls.max_ciphertext_record_len]u8,
    scratch: [tls.max_ciphertext_len]u8,
};

pub const Conn = struct {
    allocator: Allocator,
    config: *const Config,
    state: State = .wait_client_hello,

    suite: CipherSuite = .aes_128_gcm_sha256,
    group: Group = .x25519,
    transcript: Transcript = .{ .sha256 = .init(.{}) },
    read_keys: ?TrafficKeys = null,
    write_keys: ?TrafficKeys = null,
    client_hs_secret: Secret = @splat(0),
    client_app_secret: Secret = @splat(0),
    // Held from our Finished to the client's, for the resumption secret.
    master_secret: Secret = @splat(0),
    resumed: bool = false,

    bufs: ?*Buffers = null,
    in_len: usize = 0,
    hs_in: std.ArrayList(u8) = .empty,
    hs_out: std.ArrayList(u8) = .empty,
    app_in: std.ArrayList(u8) = .empty,
    app_in_pos: usize = 0,
    out: std.ArrayList(u8) = .empty,
    out_pos: usize = 0,

    hrr_group: ?Group = null,
    ccs_sent: bool = false,
    early_data_skip: usize = 0,
    peer_closed: bool = false,
    close_sent: bool = false,
    /// The peer asked for a KeyUpdate; one is sent before our next record,
    /// however many requests arrive first (RFC 8446 4.6.3).
    key_update_owed: bool = false,
    peer_alert: ?tls.Alert.Description = null,

    selected_alpn: ?[]const u8 = null,
    server_name_buf: [255]u8 = undefined,
    server_name_len: ?u8 = null,

    pub fn init(allocator: Allocator, config: *const Config) Conn {
        return .{ .allocator = allocator, .config = config };
    }

    pub fn deinit(self: *Conn) void {
        const gpa = self.allocator;
        if (self.bufs) |b| {
            crypto.secureZero(u8, &b.scratch);
            gpa.destroy(b);
        }
        self.hs_in.deinit(gpa);
        self.hs_out.deinit(gpa);
        self.app_in.deinit(gpa);
        self.out.deinit(gpa);
        crypto.secureZero(u8, mem.asBytes(&self.client_hs_secret));
        crypto.secureZero(u8, mem.asBytes(&self.client_app_secret));
        crypto.secureZero(u8, mem.asBytes(&self.master_secret));
        if (self.read_keys) |*k| crypto.secureZero(u8, mem.asBytes(k));
        if (self.write_keys) |*k| crypto.secureZero(u8, mem.asBytes(k));
        self.* = undefined;
    }

    /// Feed ciphertext read from the socket. Partial records are buffered.
    /// On a protocol error the matching alert is queued in `pendingOutput()`
    /// — flush it, then close the socket.
    ///
    /// Decrypted application data accumulates until `read`; a caller that
    /// stops reading should stop feeding.
    pub fn feed(self: *Conn, data: []const u8) Error!void {
        if (self.state == .failed) return error.ConnectionFailed;
        self.feedRecords(data) catch |err| {
            self.fail(err);
            return err;
        };
    }

    /// Copies out decrypted application data; returns 0 when none is buffered.
    pub fn read(self: *Conn, buf: []u8) usize {
        const avail = self.app_in.items[self.app_in_pos..];
        const n = @min(avail.len, buf.len);
        @memcpy(buf[0..n], avail[0..n]);
        self.app_in_pos += n;
        if (self.app_in_pos == self.app_in.items.len) {
            self.app_in.clearRetainingCapacity();
            self.app_in_pos = 0;
        }
        return n;
    }

    /// Encrypts application data into the output queue, in records of at
    /// most 16 KiB. Only valid once `handshakeComplete()`.
    pub fn write(self: *Conn, data: []const u8) Error!void {
        if (self.state != .connected or self.close_sent) return error.NotConnected;
        if (data.len == 0) return;
        var rest = data;
        while (true) {
            const n = @min(rest.len, max_plaintext);
            try self.maybeRotateWriteKeys();
            try self.sealRecord(.application_data, rest[0..n]);
            rest = rest[n..];
            if (rest.len == 0) break;
        }
    }

    /// Ciphertext waiting to be sent to the socket.
    pub fn pendingOutput(self: *const Conn) []const u8 {
        return self.out.items[self.out_pos..];
    }

    /// Marks the first `n` bytes of `pendingOutput()` as sent.
    pub fn consumeOutput(self: *Conn, n: usize) void {
        std.debug.assert(n <= self.out.items.len - self.out_pos);
        self.out_pos += n;
        if (self.out_pos == self.out.items.len) {
            self.out.clearRetainingCapacity();
            self.out_pos = 0;
        }
    }

    /// Queues a close_notify alert. Reading may continue until the peer
    /// answers with its own (`peerClosed()`).
    pub fn close(self: *Conn) void {
        if (self.close_sent or self.state == .failed) return;
        self.queueAlert(.warning, .close_notify) catch {};
        self.close_sent = true;
    }

    pub fn handshakeComplete(self: *const Conn) bool {
        return self.state == .connected;
    }

    /// The peer sent close_notify; no more application data will arrive.
    pub fn peerClosed(self: *const Conn) bool {
        return self.peer_closed;
    }

    /// The fatal alert behind an `error.PeerAlert`.
    pub fn peerAlert(self: *const Conn) ?tls.Alert.Description {
        return self.peer_alert;
    }

    /// The negotiated protocol, pointing into `Config.alpn`.
    pub fn alpn(self: *const Conn) ?[]const u8 {
        return self.selected_alpn;
    }

    /// The host name the client sent in SNI, whether or not a certificate
    /// matched it.
    pub fn serverName(self: *const Conn) ?[]const u8 {
        const len = self.server_name_len orelse return null;
        return self.server_name_buf[0..len];
    }

    /// The negotiated cipher suite, once the ServerHello is out.
    pub fn cipherSuite(self: *const Conn) ?CipherSuite {
        return if (self.write_keys != null) self.suite else null;
    }

    /// The handshake resumed a session from a ticket.
    pub fn isResumed(self: *const Conn) bool {
        return self.resumed;
    }

    /// The negotiated key exchange group, once the ServerHello is out.
    pub fn keyExchangeGroup(self: *const Conn) ?Group {
        return if (self.write_keys != null) self.group else null;
    }

    // ─── Record layer ────────────────────────────────────────────────

    fn buffers(self: *Conn) Error!*Buffers {
        if (self.bufs) |b| return b;
        const b = try self.allocator.create(Buffers);
        self.bufs = b;
        return b;
    }

    fn feedRecords(self: *Conn, data: []const u8) Error!void {
        const bufs = try self.buffers();
        var rest = data;
        while (rest.len > 0) {
            // RFC 8446 §6.1: anything after close_notify is ignored.
            if (self.peer_closed) return;
            const n = @min(rest.len, bufs.in.len - self.in_len);
            @memcpy(bufs.in[self.in_len..][0..n], rest[0..n]);
            self.in_len += n;
            rest = rest[n..];

            var off: usize = 0;
            while (self.in_len - off >= tls.record_header_len and !self.peer_closed) {
                // Checked before the body arrives, so plain HTTP fails fast.
                if (bufs.in[off] < ct_ccs or bufs.in[off] > ct_app_data) return error.UnexpectedMessage;
                const len = mem.readInt(u16, bufs.in[off + 3 ..][0..2], .big);
                if (len > tls.max_ciphertext_len) return error.RecordOverflow;
                const total = tls.record_header_len + len;
                if (self.in_len - off < total) break;
                try self.processRecord(bufs.in[off..][0..total]);
                off += total;
            }
            mem.copyForwards(u8, bufs.in[0 .. self.in_len - off], bufs.in[off..self.in_len]);
            self.in_len -= off;
        }
    }

    fn processRecord(self: *Conn, record: []const u8) Error!void {
        const payload = record[tls.record_header_len..];
        switch (record[0]) {
            ct_ccs => {
                // Middlebox compat (RFC 8446 §5): one unprotected 0x01 between
                // the first ClientHello and the client Finished, then ignored.
                const in_handshake = self.state == .wait_client_hello_retry or self.state == .wait_finished;
                if (!in_handshake or payload.len != 1 or payload[0] != 1) return error.UnexpectedMessage;
            },
            ct_alert => {
                // Unprotected alerts only before the handshake is done: a client
                // that cannot derive our keys can only complain in the clear.
                if (self.state == .connected) return error.UnexpectedMessage;
                if (payload.len > max_plaintext) return error.RecordOverflow;
                try self.handleAlert(payload);
            },
            ct_handshake => {
                if (self.read_keys != null) return error.UnexpectedMessage;
                if (payload.len == 0) return error.UnexpectedMessage;
                if (payload.len > max_plaintext) return error.RecordOverflow;
                try self.handleHandshakeBytes(payload);
            },
            ct_app_data => {
                if (self.read_keys == null) {
                    // 0-RTT after a HelloRetryRequest: skip it.
                    if (self.state == .wait_client_hello_retry and payload.len <= self.early_data_skip) {
                        self.early_data_skip -= payload.len;
                        return;
                    }
                    return error.UnexpectedMessage;
                }
                const plain = self.openRecord(record) catch |err| {
                    // 0-RTT sealed with keys we never derived: skip it.
                    if (err == error.BadRecordMac and self.state == .wait_finished and payload.len <= self.early_data_skip) {
                        self.early_data_skip -= payload.len;
                        return;
                    }
                    return err;
                };
                var end = plain.len;
                while (end > 0 and plain[end - 1] == 0) end -= 1;
                if (end == 0) return error.UnexpectedMessage;
                const content = plain[0 .. end - 1];
                switch (plain[end - 1]) {
                    ct_handshake => {
                        if (content.len == 0) return error.UnexpectedMessage;
                        try self.handleHandshakeBytes(content);
                    },
                    ct_alert => try self.handleAlert(content),
                    ct_app_data => {
                        if (self.state != .connected) return error.UnexpectedMessage;
                        try self.appendAppData(content);
                    },
                    else => return error.UnexpectedMessage,
                }
            },
            else => return error.UnexpectedMessage,
        }
    }

    fn appendAppData(self: *Conn, content: []const u8) Error!void {
        if (content.len == 0) return;
        if (self.app_in_pos > 0 and self.app_in_pos >= self.app_in.items.len / 2) {
            const live = self.app_in.items[self.app_in_pos..];
            mem.copyForwards(u8, self.app_in.items[0..live.len], live);
            self.app_in.shrinkRetainingCapacity(live.len);
            self.app_in_pos = 0;
        }
        try self.app_in.appendSlice(self.allocator, content);
    }

    fn handleAlert(self: *Conn, payload: []const u8) Error!void {
        if (payload.len != 2) return error.DecodeError;
        const desc: tls.Alert.Description = @enumFromInt(payload[1]);
        switch (desc) {
            .close_notify => self.peer_closed = true,
            .user_canceled => {},
            else => {
                self.peer_alert = desc;
                return error.PeerAlert;
            },
        }
    }

    fn openRecord(self: *Conn, record: []const u8) Error![]u8 {
        return openWith(self.suite, &self.read_keys.?, record, &self.bufs.?.scratch);
    }

    /// Encrypts one record of at most 2^14 bytes with the write keys.
    fn sealRecord(self: *Conn, inner: tls.ContentType, content: []const u8) Error!void {
        const keys = &self.write_keys.?;
        if (keys.seq == std.math.maxInt(u64)) return error.InternalError;
        const bufs = try self.buffers();
        const dst = try self.reserveOutput(sealedLen(self.suite, content.len));
        sealInto(self.suite, keys, inner, content, &bufs.scratch, dst);
    }

    fn writePlainRecords(self: *Conn, content_type: u8, data: []const u8) Error!void {
        var rest = data;
        while (true) {
            const n = @min(rest.len, max_plaintext);
            const dst = try self.reserveOutput(tls.record_header_len + n);
            dst[0..3].* = .{ content_type, 0x03, 0x03 };
            mem.writeInt(u16, dst[3..5], @intCast(n), .big);
            @memcpy(dst[tls.record_header_len..], rest[0..n]);
            rest = rest[n..];
            if (rest.len == 0) break;
        }
    }

    fn writeProtected(self: *Conn, inner: tls.ContentType, data: []const u8) Error!void {
        var rest = data;
        while (true) {
            const n = @min(rest.len, max_plaintext);
            try self.sealRecord(inner, rest[0..n]);
            rest = rest[n..];
            if (rest.len == 0) break;
        }
    }

    fn reserveOutput(self: *Conn, n: usize) Error![]u8 {
        if (self.out_pos > 0 and self.out_pos >= self.out.items.len / 2) {
            const live = self.out.items[self.out_pos..];
            mem.copyForwards(u8, self.out.items[0..live.len], live);
            self.out.shrinkRetainingCapacity(live.len);
            self.out_pos = 0;
        }
        return self.out.addManyAsSlice(self.allocator, n);
    }

    fn queueAlert(self: *Conn, level: tls.Alert.Level, desc: tls.Alert.Description) Error!void {
        const body = [2]u8{ @intFromEnum(level), @intFromEnum(desc) };
        if (self.write_keys != null) {
            try self.sealRecord(.alert, &body);
        } else {
            try self.writePlainRecords(ct_alert, &body);
        }
    }

    fn fail(self: *Conn, err: Error) void {
        self.state = .failed;
        if (alertFor(err)) |desc| self.queueAlert(.fatal, desc) catch {};
    }

    fn maybeRotateWriteKeys(self: *Conn) Error!void {
        if (!self.key_update_owed and self.write_keys.?.seq < key_update_after) return;
        self.key_update_owed = false;
        try self.sendKeyUpdate(false);
    }

    fn sendKeyUpdate(self: *Conn, request_peer: bool) Error!void {
        const msg = [5]u8{ hs_key_update, 0, 0, 1, @intFromBool(request_peer) };
        try self.sealRecord(.handshake, &msg);
        self.write_keys = self.write_keys.?.next(self.suite);
    }

    // ─── Handshake ───────────────────────────────────────────────────

    fn handleHandshakeBytes(self: *Conn, bytes: []const u8) Error!void {
        if (self.hs_in.items.len + bytes.len > max_handshake_msg + 4) return error.DecodeError;
        try self.hs_in.appendSlice(self.allocator, bytes);
        var pos: usize = 0;
        defer {
            const rest = self.hs_in.items.len - pos;
            mem.copyForwards(u8, self.hs_in.items[0..rest], self.hs_in.items[pos..]);
            self.hs_in.shrinkRetainingCapacity(rest);
        }
        while (self.hs_in.items.len - pos >= 4) {
            const len = mem.readInt(u24, self.hs_in.items[pos + 1 ..][0..3], .big);
            if (len > max_handshake_msg) return error.DecodeError;
            if (self.hs_in.items.len - pos < 4 + len) break;
            const msg = self.hs_in.items[pos..][0 .. 4 + len];
            pos += 4 + len;
            try self.handleHandshakeMessage(msg);
            // Every message we accept changes keys or state, and RFC 8446
            // §5.1 forbids a message sharing a record across a key change.
            if (pos != self.hs_in.items.len) return error.UnexpectedMessage;
        }
    }

    fn handleHandshakeMessage(self: *Conn, msg: []const u8) Error!void {
        const kind = msg[0];
        switch (self.state) {
            .wait_client_hello, .wait_client_hello_retry => {
                if (kind != hs_client_hello) return error.UnexpectedMessage;
                try self.onClientHello(msg);
            },
            .wait_finished => {
                if (kind != hs_finished) return error.UnexpectedMessage;
                try self.onClientFinished(msg);
            },
            .connected => {
                if (kind != hs_key_update) return error.UnexpectedMessage;
                try self.onKeyUpdate(msg[4..]);
            },
            .failed => return error.ConnectionFailed,
        }
    }

    fn onClientHello(self: *Conn, msg: []const u8) Error!void {
        const retry = self.state == .wait_client_hello_retry;
        const ch = try ClientHello.parse(msg[4..]);
        const config = self.config;

        const versions = ch.supported_versions orelse return error.ProtocolVersion;
        if (!containsU16(versions, tls13_version)) return error.ProtocolVersion;
        if (ch.compression_methods.len != 1 or ch.compression_methods[0] != 0) return error.IllegalParameter;

        if (retry) {
            // RFC 8446 §4.1.4: the suite in the HelloRetryRequest stands.
            if (!containsU16(ch.cipher_suites, @intFromEnum(self.suite))) return error.IllegalParameter;
            if (ch.cookie) return error.IllegalParameter; // we never send one
        } else {
            self.suite = for (config.cipher_suites) |cs| {
                if (containsU16(ch.cipher_suites, @intFromEnum(cs))) break cs;
            } else return error.HandshakeFailure;
        }

        if (ch.server_name) |name| {
            if (name.len > self.server_name_buf.len) return error.DecodeError;
            @memcpy(self.server_name_buf[0..name.len], name);
            self.server_name_len = @intCast(name.len);
        } else self.server_name_len = null;
        const selection = tls13.selectCertificate(config.certs, ch.server_name) orelse return error.InternalError;
        const cert = &selection.entry.cert;

        self.selected_alpn = null;
        if (ch.alpn) |offered| {
            if (config.alpn.len > 0) {
                self.selected_alpn = for (config.alpn) |proto| {
                    if (alpnListContains(offered, proto)) break proto;
                } else return error.NoApplicationProtocol;
            }
        }

        // psk_dhe_ke still needs a key share, so groups come first either way.
        const client_groups = ch.supported_groups orelse return error.MissingExtension;
        const shares = ch.key_shares orelse return error.MissingExtension;
        const chosen: ?KeyShare = for (config.groups) |g| {
            if (findKeyShare(shares, g)) |ks| break ks;
        } else null;
        const share = chosen orelse {
            if (retry) return error.IllegalParameter;
            const g = for (config.groups) |g| {
                if (containsU16(client_groups, @intFromEnum(g))) break g;
            } else return error.HandshakeFailure;
            return self.sendHelloRetryRequest(msg, ch, g);
        };
        if (retry) {
            // Exactly the one share we asked for.
            if (share.group != self.hrr_group.? or shares.len != 4 + share.key.len) return error.IllegalParameter;
        }
        self.group = share.group;

        // RFC 8446 §4.2.9: a PSK offer must say how it may be used.
        if (ch.psk_identities != null and ch.psk_modes == null) return error.MissingExtension;
        var psk: ?Resumption = null;
        if (config.ticket_key) |key| {
            if (ch.psk_identities != null and mem.indexOfScalar(u8, ch.psk_modes.?, psk_dhe_ke) != null)
                psk = try self.acceptTicket(key, msg, ch);
        }
        self.resumed = psk != null;

        if (psk == null) {
            const sig_algs = ch.signature_algorithms orelse return error.MissingExtension;
            const scheme: tls.SignatureScheme = switch (cert.private_key_algorithm) {
                .ecdsa_p256_sha256 => .ecdsa_secp256r1_sha256,
                .ed25519 => .ed25519,
            };
            if (!containsU16(sig_algs, @intFromEnum(scheme))) return error.HandshakeFailure;
        }

        var shared_buf: [32]u8 = undefined;
        var our_public_buf: [65]u8 = undefined;
        const our_public = try keyExchange(share, &shared_buf, &our_public_buf);
        defer crypto.secureZero(u8, &shared_buf);

        if (!retry) self.transcript = .init(self.suite);
        self.transcript.update(msg);
        if (ch.early_data) self.early_data_skip = early_data_skip_budget;

        // ServerHello, in the clear.
        self.hs_out.clearRetainingCapacity();
        {
            var b: Builder = .{ .list = &self.hs_out, .gpa = self.allocator };
            var random: [32]u8 = undefined;
            sys.randomBytes(&random);
            try buildServerHello(&b, random, ch.session_id, self.suite, .{ .group = self.group, .key = our_public }, if (psk) |r| r.index else null);
        }
        self.transcript.update(self.hs_out.items);
        try self.writePlainRecords(ct_handshake, self.hs_out.items);
        if (!self.ccs_sent) try self.writePlainRecords(ct_ccs, &[_]u8{1});
        self.ccs_sent = true;

        // Handshake keys.
        const hs_secrets = handshakeSecrets(self.suite, if (psk) |*r| &r.psk else null, self.transcript.peek(), &shared_buf);
        var server_hs_secret = hs_secrets.server;
        defer crypto.secureZero(u8, &server_hs_secret);
        self.client_hs_secret = hs_secrets.client;
        self.write_keys = .derive(self.suite, hs_secrets.server);
        self.read_keys = .derive(self.suite, hs_secrets.client);

        // EncryptedExtensions, Certificate, CertificateVerify, Finished.
        self.hs_out.clearRetainingCapacity();
        var b: Builder = .{ .list = &self.hs_out, .gpa = self.allocator };
        var start = self.hs_out.items.len;
        try buildEncryptedExtensions(&b, self.selected_alpn, selection.matched);
        self.transcript.update(self.hs_out.items[start..]);

        if (psk == null) {
            start = self.hs_out.items.len;
            try buildCertificate(&b, cert.cert_chain_der);
            self.transcript.update(self.hs_out.items[start..]);

            start = self.hs_out.items.len;
            const th_cert = self.transcript.peek();
            try buildCertificateVerify(&b, cert, th_cert[0..hashLen(self.suite)]);
            self.transcript.update(self.hs_out.items[start..]);
        }

        start = self.hs_out.items.len;
        const verify_data = finishedMac(self.suite, &server_hs_secret, self.transcript.peek());
        try b.u8_(hs_finished);
        try b.u24_(@intCast(hashLen(self.suite)));
        try b.bytes(verify_data[0..hashLen(self.suite)]);
        self.transcript.update(self.hs_out.items[start..]);

        try self.writeProtected(.handshake, self.hs_out.items);
        crypto.secureZero(u8, self.hs_out.items);
        self.hs_out.clearRetainingCapacity();

        // Application secrets: ours now, the client's after its Finished.
        const app = appSecrets(self.suite, hs_secrets.handshake, self.transcript.peek());
        self.write_keys = .derive(self.suite, app.server);
        self.client_app_secret = app.client;
        self.master_secret = app.master;

        self.state = .wait_finished;
    }

    fn sendHelloRetryRequest(self: *Conn, ch_msg: []const u8, ch: ClientHello, group: Group) Error!void {
        // RFC 8446 §4.4.1: ClientHello1 enters the transcript as its hash.
        self.transcript = .init(self.suite);
        {
            var ch_hash = Transcript.init(self.suite);
            ch_hash.update(ch_msg);
            const h = ch_hash.peek();
            const len = hashLen(self.suite);
            self.transcript.update(&.{ hs_message_hash, 0, 0, @intCast(len) });
            self.transcript.update(h[0..len]);
        }

        self.hs_out.clearRetainingCapacity();
        var b: Builder = .{ .list = &self.hs_out, .gpa = self.allocator };
        try buildServerHello(&b, tls.hello_retry_request_sequence, ch.session_id, self.suite, .{ .group = group, .key = null }, null);
        self.transcript.update(self.hs_out.items);
        try self.writePlainRecords(ct_handshake, self.hs_out.items);
        self.hs_out.clearRetainingCapacity();
        try self.writePlainRecords(ct_ccs, &[_]u8{1});
        self.ccs_sent = true;

        self.hrr_group = group;
        if (ch.early_data) self.early_data_skip = early_data_skip_budget;
        self.state = .wait_client_hello_retry;
    }

    fn onClientFinished(self: *Conn, msg: []const u8) Error!void {
        const len = hashLen(self.suite);
        if (msg.len != 4 + len) return error.DecodeError;
        const expected = finishedMac(self.suite, &self.client_hs_secret, self.transcript.peek());
        var got: Secret = @splat(0);
        @memcpy(got[0..len], msg[4..]);
        if (!crypto.timing_safe.eql(Secret, got, expected)) return error.DecryptError;
        self.transcript.update(msg);

        self.read_keys = .derive(self.suite, self.client_app_secret);
        crypto.secureZero(u8, &self.client_hs_secret);
        crypto.secureZero(u8, &self.client_app_secret);
        self.early_data_skip = 0;
        self.state = .connected;

        if (self.config.ticket_key) |key| try self.sendTicket(key);
        crypto.secureZero(u8, &self.master_secret);
    }

    fn sendTicket(self: *Conn, key: [16]u8) Error!void {
        const len = hashLen(self.suite);
        const nonce = [1]u8{0}; // one ticket per connection
        var psk: Secret = @splat(0);
        defer crypto.secureZero(u8, &psk);
        switch (self.suite) {
            inline else => |c| {
                const S = Suite(c);
                const th = self.transcript.peek();
                var res_master = S.expand(&self.master_secret, "res master", th[0..S.hash_len], S.hash_len);
                defer crypto.secureZero(u8, &res_master);
                psk[0..S.hash_len].* = S.expand(&res_master, "resumption", &nonce, S.hash_len);
            },
        }
        var age_add: [4]u8 = undefined;
        sys.randomBytes(&age_add);

        var ticket_buf: [max_ticket_len]u8 = undefined;
        const ticket = sealTicket(key, .{
            .suite = self.suite,
            .issued_s = sys.realtimeSeconds(),
            .server_name = self.serverName() orelse "",
            .psk = psk[0..len],
        }, &ticket_buf);

        self.hs_out.clearRetainingCapacity();
        var b: Builder = .{ .list = &self.hs_out, .gpa = self.allocator };
        try b.u8_(hs_new_session_ticket);
        const msg = try b.begin(u24);
        try b.bytes(&mem.toBytes(mem.nativeToBig(u32, self.config.ticket_lifetime_s)));
        try b.bytes(&age_add);
        try b.u8_(nonce.len);
        try b.bytes(&nonce);
        try b.u16_(@intCast(ticket.len));
        try b.bytes(ticket);
        try b.u16_(0); // no early_data: we never accept 0-RTT
        try b.end(u24, msg);
        try self.writeProtected(.handshake, self.hs_out.items);
        self.hs_out.clearRetainingCapacity();
    }

    const Resumption = struct { psk: Secret, index: u16 };

    /// Picks the first offered ticket we sealed that is still valid for this
    /// suite's hash and SNI. Its binder must verify (RFC 8446 §4.2.11.2).
    fn acceptTicket(self: *Conn, key: [16]u8, ch_msg: []const u8, ch: ClientHello) Error!?Resumption {
        var ids: Parser = .{ .buf = ch.psk_identities.? };
        var binders: Parser = .{ .buf = ch.psk_binders.? };
        var index: u16 = 0;
        var plain: [max_ticket_len]u8 = undefined;
        var t: Ticket = undefined;
        var binder: []const u8 = undefined;
        while (true) : (index += 1) {
            if (ids.rest() == 0) return null;
            const identity = try ids.vec(u16);
            _ = try ids.int(u32); // obfuscated_ticket_age: only 0-RTT needs it
            binder = try binders.vec(u8);
            t = openTicket(key, identity, &plain) orelse continue;
            if (hashLen(t.suite) != hashLen(self.suite)) continue;
            const now = sys.realtimeSeconds();
            if (now < t.issued_s or now - t.issued_s > self.config.ticket_lifetime_s) continue;
            if (!std.ascii.eqlIgnoreCase(t.server_name, ch.server_name orelse "")) continue;
            break;
        }

        var r: Resumption = .{ .psk = @splat(0), .index = index };
        @memcpy(r.psk[0..t.psk.len], t.psk);
        crypto.secureZero(u8, &plain);

        // Binders cover the ClientHello up to the binders list, after any HRR.
        var transcript = if (self.state == .wait_client_hello_retry) self.transcript else Transcript.init(self.suite);
        transcript.update(ch_msg[0 .. ch_msg.len - ch.psk_binders_len]);
        var expected: Secret = @splat(0);
        switch (self.suite) {
            inline else => |c| {
                const S = Suite(c);
                const early = S.Hkdf.extract(&.{}, r.psk[0..S.hash_len]);
                var binder_key: Secret = @splat(0);
                binder_key[0..S.hash_len].* = S.expand(&early, "res binder", &tls.emptyHash(S.Hash), S.hash_len);
                expected = finishedMac(c, &binder_key, transcript.peek());
            },
        }
        var got: Secret = @splat(0);
        if (binder.len != hashLen(self.suite)) return error.DecryptError;
        @memcpy(got[0..binder.len], binder);
        if (!crypto.timing_safe.eql(Secret, got, expected)) return error.DecryptError;
        return r;
    }

    fn onKeyUpdate(self: *Conn, body: []const u8) Error!void {
        if (body.len != 1) return error.DecodeError;
        if (body[0] > 1) return error.IllegalParameter;
        self.read_keys = self.read_keys.?.next(self.suite);
        // Owed rather than sent now, so a peer that floods requests and never
        // reads gets one reply per record we write, not one per request.
        if (body[0] == 1) self.key_update_owed = true;
    }
};

fn alertFor(err: Error) ?tls.Alert.Description {
    return switch (err) {
        error.DecodeError => .decode_error,
        error.IllegalParameter => .illegal_parameter,
        error.UnexpectedMessage => .unexpected_message,
        error.HandshakeFailure => .handshake_failure,
        error.ProtocolVersion => .protocol_version,
        error.NoApplicationProtocol => .no_application_protocol,
        error.MissingExtension => .missing_extension,
        error.BadRecordMac => .bad_record_mac,
        error.RecordOverflow => .record_overflow,
        error.DecryptError => .decrypt_error,
        error.InternalError, error.OutOfMemory => .internal_error,
        error.PeerAlert, error.ConnectionFailed, error.NotConnected => null,
    };
}

// ─── Record protection and key schedule ──────────────────────────────

fn sealedLen(cs: CipherSuite, content_len: usize) usize {
    return switch (cs) {
        inline else => |c| tls.record_header_len + content_len + 1 + Suite(c).Aead.tag_length,
    };
}

/// Seals `content` as one TLSCiphertext into `dst` (exactly `sealedLen`
/// bytes), staging the inner plaintext in `scratch`.
fn sealInto(cs: CipherSuite, keys: *TrafficKeys, inner: tls.ContentType, content: []const u8, scratch: []u8, dst: []u8) void {
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
fn openWith(cs: CipherSuite, keys: *TrafficKeys, record: []const u8, out: []u8) Error![]u8 {
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

const HandshakeSecrets = struct { handshake: Secret, client: Secret, server: Secret };

fn handshakeSecrets(cs: CipherSuite, psk: ?*const Secret, th: Secret, shared: []const u8) HandshakeSecrets {
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

fn appSecrets(cs: CipherSuite, handshake_secret: Secret, th: Secret) struct { client: Secret, server: Secret, master: Secret } {
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
fn finishedMac(cs: CipherSuite, base_key: *const Secret, th: Secret) Secret {
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

// ─── Key exchange ────────────────────────────────────────────────────

const KeyShare = struct { group: Group, key: []const u8 };

/// Returns our public key share; writes the shared secret to `shared`.
fn keyExchange(share: KeyShare, shared: *[32]u8, public_buf: *[65]u8) Error![]const u8 {
    switch (share.group) {
        .x25519 => {
            if (share.key.len != X25519.public_length) return error.IllegalParameter;
            var seed: [X25519.seed_length]u8 = undefined;
            sys.randomBytes(&seed);
            const kp = X25519.KeyPair.generateDeterministic(seed) catch return error.InternalError;
            crypto.secureZero(u8, &seed);
            shared.* = X25519.scalarmult(kp.secret_key, share.key[0..32].*) catch return error.IllegalParameter;
            public_buf[0..32].* = kp.public_key;
            return public_buf[0..32];
        },
        .secp256r1 => {
            // RFC 8446 §4.2.8.2: uncompressed points only.
            if (share.key.len != 65 or share.key[0] != 0x04) return error.IllegalParameter;
            const peer = P256.fromSec1(share.key) catch return error.IllegalParameter;
            var seed: [EcdsaP256Sha256.KeyPair.seed_length]u8 = undefined;
            sys.randomBytes(&seed);
            const kp = EcdsaP256Sha256.KeyPair.generateDeterministic(seed) catch return error.InternalError;
            crypto.secureZero(u8, &seed);
            const point = peer.mul(kp.secret_key.bytes, .big) catch return error.IllegalParameter;
            shared.* = point.toUncompressedSec1()[1..33].*;
            public_buf.* = kp.public_key.toUncompressedSec1();
            return public_buf[0..65];
        },
    }
}

// ─── ClientHello parsing ─────────────────────────────────────────────

const Parser = struct {
    buf: []const u8,
    pos: usize = 0,

    fn rest(p: *const Parser) usize {
        return p.buf.len - p.pos;
    }
    fn take(p: *Parser, n: usize) Error![]const u8 {
        if (p.rest() < n) return error.DecodeError;
        defer p.pos += n;
        return p.buf[p.pos..][0..n];
    }
    fn int(p: *Parser, comptime T: type) Error!T {
        const n = @divExact(@typeInfo(T).int.bits, 8);
        return mem.readInt(T, (try p.take(n))[0..n], .big);
    }
    fn vec(p: *Parser, comptime Len: type) Error![]const u8 {
        return p.take(try p.int(Len));
    }
};

const ClientHello = struct {
    session_id: []const u8,
    cipher_suites: []const u8,
    compression_methods: []const u8,
    supported_versions: ?[]const u8 = null,
    supported_groups: ?[]const u8 = null,
    /// KeyShareEntry list, already checked to be well formed.
    key_shares: ?[]const u8 = null,
    signature_algorithms: ?[]const u8 = null,
    server_name: ?[]const u8 = null,
    /// ProtocolNameList body, already checked to be well formed.
    alpn: ?[]const u8 = null,
    early_data: bool = false,
    cookie: bool = false,
    psk_modes: ?[]const u8 = null,
    /// PskIdentity list and PskBinderEntry list, already checked to pair up.
    psk_identities: ?[]const u8 = null,
    psk_binders: ?[]const u8 = null,
    /// Bytes at the end of the message that binders do not cover.
    psk_binders_len: usize = 0,

    fn parse(body: []const u8) Error!ClientHello {
        var p: Parser = .{ .buf = body };
        _ = try p.int(u16); // legacy_version
        _ = try p.take(32); // random
        var ch: ClientHello = .{
            .session_id = try p.vec(u8),
            .cipher_suites = try p.vec(u16),
            .compression_methods = try p.vec(u8),
        };
        if (ch.session_id.len > 32) return error.IllegalParameter;
        if (ch.cipher_suites.len < 2 or ch.cipher_suites.len % 2 != 0) return error.DecodeError;
        if (ch.compression_methods.len == 0) return error.DecodeError;
        // A pre-1.3 ClientHello may stop here; it has no supported_versions.
        if (p.rest() == 0) return ch;

        var exts: Parser = .{ .buf = try p.vec(u16) };
        if (p.rest() != 0) return error.DecodeError;

        var seen: [64]u16 = undefined;
        var n_seen: usize = 0;
        while (exts.rest() > 0) {
            const kind = try exts.int(u16);
            const data = try exts.vec(u16);
            if (containsSlice(seen[0..n_seen], kind)) return error.IllegalParameter;
            if (n_seen == seen.len) return error.DecodeError;
            seen[n_seen] = kind;
            n_seen += 1;

            switch (kind) {
                ext.supported_versions => ch.supported_versions = try u16List(data, u8),
                ext.supported_groups => ch.supported_groups = try u16List(data, u16),
                ext.signature_algorithms => ch.signature_algorithms = try u16List(data, u16),
                ext.key_share => {
                    var d: Parser = .{ .buf = data };
                    const list = try d.vec(u16);
                    if (d.rest() != 0) return error.DecodeError;
                    var l: Parser = .{ .buf = list };
                    while (l.rest() > 0) {
                        _ = try l.int(u16);
                        if ((try l.vec(u16)).len == 0) return error.DecodeError;
                    }
                    ch.key_shares = list;
                },
                ext.server_name => ch.server_name = tls13.parseServerNameExtension(data) catch return error.DecodeError,
                ext.alpn => {
                    var d: Parser = .{ .buf = data };
                    const list = try d.vec(u16);
                    if (d.rest() != 0 or list.len == 0) return error.DecodeError;
                    var l: Parser = .{ .buf = list };
                    while (l.rest() > 0) {
                        if ((try l.vec(u8)).len == 0) return error.DecodeError;
                    }
                    ch.alpn = list;
                },
                ext.early_data => {
                    if (data.len != 0) return error.DecodeError;
                    ch.early_data = true;
                },
                ext.cookie => ch.cookie = true,
                ext.psk_key_exchange_modes => {
                    var d: Parser = .{ .buf = data };
                    const modes = try d.vec(u8);
                    if (d.rest() != 0 or modes.len == 0) return error.DecodeError;
                    ch.psk_modes = modes;
                },
                ext.pre_shared_key => {
                    // RFC 8446 §4.2.11: pre_shared_key must be last.
                    if (exts.rest() != 0) return error.IllegalParameter;
                    var d: Parser = .{ .buf = data };
                    const ids = try d.vec(u16);
                    const binders = try d.vec(u16);
                    if (d.rest() != 0 or ids.len == 0) return error.DecodeError;
                    var i: Parser = .{ .buf = ids };
                    var bs: Parser = .{ .buf = binders };
                    while (i.rest() > 0) {
                        if ((try i.vec(u16)).len == 0) return error.DecodeError;
                        _ = try i.int(u32);
                        if ((try bs.vec(u8)).len < 32) return error.DecodeError;
                    }
                    if (bs.rest() != 0) return error.IllegalParameter;
                    ch.psk_identities = ids;
                    ch.psk_binders = binders;
                    ch.psk_binders_len = 2 + binders.len;
                },
                else => {},
            }
        }
        return ch;
    }
};

fn u16List(data: []const u8, comptime Len: type) Error![]const u8 {
    var p: Parser = .{ .buf = data };
    const list = try p.vec(Len);
    if (p.rest() != 0 or list.len < 2 or list.len % 2 != 0) return error.DecodeError;
    return list;
}

fn containsU16(list: []const u8, value: u16) bool {
    var i: usize = 0;
    while (i + 2 <= list.len) : (i += 2) {
        if (mem.readInt(u16, list[i..][0..2], .big) == value) return true;
    }
    return false;
}

fn containsSlice(list: []const u16, value: u16) bool {
    return mem.indexOfScalar(u16, list, value) != null;
}

fn findKeyShare(shares: []const u8, group: Group) ?KeyShare {
    var p: Parser = .{ .buf = shares };
    while (p.rest() > 0) {
        const g = p.int(u16) catch return null;
        const key = p.vec(u16) catch return null;
        if (g == @intFromEnum(group)) return .{ .group = group, .key = key };
    }
    return null;
}

fn alpnListContains(list: []const u8, proto: []const u8) bool {
    var p: Parser = .{ .buf = list };
    while (p.rest() > 0) {
        const name = p.vec(u8) catch return false;
        if (mem.eql(u8, name, proto)) return true;
    }
    return false;
}

// ─── Session tickets ─────────────────────────────────────────────────

const psk_dhe_ke: u8 = 1;
const ticket_version: u8 = 1;
const ticket_ad = "quic-zig tls_server ticket";
const Aes128Gcm = crypto.aead.aes_gcm.Aes128Gcm;
// nonce | version, suite, issued, sni, psk | tag
const max_ticket_len = Aes128Gcm.nonce_length + 1 + 2 + 8 + 1 + 255 + 48 + Aes128Gcm.tag_length;

const Ticket = struct {
    suite: CipherSuite,
    issued_s: i64,
    server_name: []const u8,
    psk: []const u8,
};

fn sealTicket(key: [16]u8, t: Ticket, out: *[max_ticket_len]u8) []const u8 {
    const nonce = out[0..Aes128Gcm.nonce_length];
    sys.randomBytes(nonce);
    var plain: [max_ticket_len]u8 = undefined;
    defer crypto.secureZero(u8, &plain);
    var n: usize = 0;
    plain[n] = ticket_version;
    n += 1;
    mem.writeInt(u16, plain[n..][0..2], @intFromEnum(t.suite), .big);
    n += 2;
    mem.writeInt(i64, plain[n..][0..8], t.issued_s, .big);
    n += 8;
    plain[n] = @intCast(t.server_name.len);
    n += 1;
    @memcpy(plain[n..][0..t.server_name.len], t.server_name);
    n += t.server_name.len;
    @memcpy(plain[n..][0..t.psk.len], t.psk);
    n += t.psk.len;

    const ct = out[Aes128Gcm.nonce_length..][0..n];
    const tag = out[Aes128Gcm.nonce_length + n ..][0..Aes128Gcm.tag_length];
    Aes128Gcm.encrypt(ct, tag, plain[0..n], ticket_ad, nonce.*, key);
    return out[0 .. Aes128Gcm.nonce_length + n + Aes128Gcm.tag_length];
}

/// Opens a ticket we sealed; null for anything else. Slices point into `plain`.
fn openTicket(key: [16]u8, blob: []const u8, plain: *[max_ticket_len]u8) ?Ticket {
    const overhead = Aes128Gcm.nonce_length + Aes128Gcm.tag_length;
    if (blob.len <= overhead or blob.len > max_ticket_len) return null;
    const n = blob.len - overhead;
    const ct = blob[Aes128Gcm.nonce_length..][0..n];
    const tag = blob[Aes128Gcm.nonce_length + n ..][0..Aes128Gcm.tag_length];
    Aes128Gcm.decrypt(plain[0..n], ct, tag.*, ticket_ad, blob[0..Aes128Gcm.nonce_length].*, key) catch return null;

    var p: Parser = .{ .buf = plain[0..n] };
    if ((p.int(u8) catch return null) != ticket_version) return null;
    const suite: CipherSuite = switch (p.int(u16) catch return null) {
        0x1301 => .aes_128_gcm_sha256,
        0x1302 => .aes_256_gcm_sha384,
        0x1303 => .chacha20_poly1305_sha256,
        else => return null,
    };
    const issued = p.int(i64) catch return null;
    const sni = p.vec(u8) catch return null;
    if (p.rest() != hashLen(suite)) return null;
    return .{ .suite = suite, .issued_s = issued, .server_name = sni, .psk = p.buf[p.pos..] };
}

// ─── Message builders ────────────────────────────────────────────────

const Builder = struct {
    list: *std.ArrayList(u8),
    gpa: Allocator,

    fn u8_(b: *Builder, v: u8) Error!void {
        try b.list.append(b.gpa, v);
    }
    fn u16_(b: *Builder, v: u16) Error!void {
        try b.list.appendSlice(b.gpa, &mem.toBytes(mem.nativeToBig(u16, v)));
    }
    fn u24_(b: *Builder, v: u24) Error!void {
        var tmp: [3]u8 = undefined;
        mem.writeInt(u24, &tmp, v, .big);
        try b.list.appendSlice(b.gpa, &tmp);
    }
    fn bytes(b: *Builder, v: []const u8) Error!void {
        try b.list.appendSlice(b.gpa, v);
    }
    /// Reserves a `Len`-sized length prefix; close it with `end`.
    fn begin(b: *Builder, comptime Len: type) Error!usize {
        try b.list.appendNTimes(b.gpa, 0, @divExact(@typeInfo(Len).int.bits, 8));
        return b.list.items.len;
    }
    fn end(b: *Builder, comptime Len: type, start: usize) Error!void {
        const n = @divExact(@typeInfo(Len).int.bits, 8);
        const len = b.list.items.len - start;
        if (len > std.math.maxInt(Len)) return error.InternalError;
        mem.writeInt(Len, b.list.items[start - n ..][0..n], @intCast(len), .big);
    }
};

const ServerKeyShare = struct { group: Group, key: ?[]const u8 };

/// ServerHello, or a HelloRetryRequest when `random` is the HRR sentinel and
/// `share.key` is null.
fn buildServerHello(b: *Builder, random: [32]u8, session_id: []const u8, suite: CipherSuite, share: ServerKeyShare, psk_index: ?u16) Error!void {
    try b.u8_(hs_server_hello);
    const msg = try b.begin(u24);
    try b.u16_(0x0303);
    try b.bytes(&random);
    try b.u8_(@intCast(session_id.len));
    try b.bytes(session_id);
    try b.u16_(@intFromEnum(suite));
    try b.u8_(0);
    const exts = try b.begin(u16);
    try b.u16_(ext.supported_versions);
    try b.u16_(2);
    try b.u16_(tls13_version);
    try b.u16_(ext.key_share);
    const ks = try b.begin(u16);
    try b.u16_(@intFromEnum(share.group));
    if (share.key) |key| {
        try b.u16_(@intCast(key.len));
        try b.bytes(key);
    }
    try b.end(u16, ks);
    if (psk_index) |i| {
        try b.u16_(ext.pre_shared_key);
        try b.u16_(2);
        try b.u16_(i);
    }
    try b.end(u16, exts);
    try b.end(u24, msg);
}

fn buildEncryptedExtensions(b: *Builder, alpn: ?[]const u8, sni_matched: bool) Error!void {
    try b.u8_(hs_encrypted_extensions);
    const msg = try b.begin(u24);
    const exts = try b.begin(u16);
    if (alpn) |proto| {
        try b.u16_(ext.alpn);
        const e = try b.begin(u16);
        const list = try b.begin(u16);
        try b.u8_(@intCast(proto.len));
        try b.bytes(proto);
        try b.end(u16, list);
        try b.end(u16, e);
    }
    // RFC 6066 §3: an empty server_name tells the client its SNI was used.
    if (sni_matched) {
        try b.u16_(ext.server_name);
        try b.u16_(0);
    }
    try b.end(u16, exts);
    try b.end(u24, msg);
}

fn buildCertificate(b: *Builder, chain: []const []const u8) Error!void {
    try b.u8_(hs_certificate);
    const msg = try b.begin(u24);
    try b.u8_(0); // certificate_request_context
    const list = try b.begin(u24);
    for (chain) |der| {
        if (der.len > std.math.maxInt(u24)) return error.InternalError;
        try b.u24_(@intCast(der.len));
        try b.bytes(der);
        try b.u16_(0); // extensions
    }
    try b.end(u24, list);
    try b.end(u24, msg);
}

fn buildCertificateVerify(b: *Builder, cert: *const Certificate, transcript_hash: []const u8) Error!void {
    const context = "TLS 1.3, server CertificateVerify";
    var content: [64 + context.len + 1 + 48]u8 = undefined;
    @memset(content[0..64], 0x20);
    content[64..][0..context.len].* = context.*;
    content[64 + context.len] = 0;
    @memcpy(content[64 + context.len + 1 ..][0..transcript_hash.len], transcript_hash);
    const signed = content[0 .. 64 + context.len + 1 + transcript_hash.len];

    const key = cert.private_key_bytes;
    if (key.len != 32) return error.InternalError;
    var noise: [32]u8 = undefined;
    sys.randomBytes(&noise);

    try b.u8_(hs_certificate_verify);
    const msg = try b.begin(u24);
    switch (cert.private_key_algorithm) {
        .ecdsa_p256_sha256 => {
            const sk = EcdsaP256Sha256.SecretKey.fromBytes(key[0..32].*) catch return error.InternalError;
            const kp = EcdsaP256Sha256.KeyPair.fromSecretKey(sk) catch return error.InternalError;
            const sig = kp.sign(signed, noise) catch return error.InternalError;
            var der_buf: [EcdsaP256Sha256.Signature.der_encoded_length_max]u8 = undefined;
            const der = sig.toDer(&der_buf);
            try b.u16_(@intFromEnum(tls.SignatureScheme.ecdsa_secp256r1_sha256));
            try b.u16_(@intCast(der.len));
            try b.bytes(der);
        },
        .ed25519 => {
            const kp = Ed25519.KeyPair.generateDeterministic(key[0..32].*) catch return error.InternalError;
            const sig = kp.sign(signed, noise) catch return error.InternalError;
            try b.u16_(@intFromEnum(tls.SignatureScheme.ed25519));
            try b.u16_(Ed25519.Signature.encoded_length);
            try b.bytes(&sig.toBytes());
        },
    }
    try b.end(u24, msg);
}

// ─── Tests ───────────────────────────────────────────────────────────

const testing = std.testing;

// Self-signed, valid to 2056. localhost and *.example.com share one P-256 key.
const test_ec_key_pem =
    \\-----BEGIN EC PRIVATE KEY-----
    \\MHcCAQEEIAKIla+65TNSSfs8RKsI9dq3KKp/WC0RUKceTUDNQYgPoAoGCCqGSM49
    \\AwEHoUQDQgAETSp/wPgU7+juILb0Ugk7IpUQd/TAcTd69dibi8gbAY23ktARkE9C
    \\53VIGla7Uzbu4gkotGeZg8ufOEbX4cC44w==
    \\-----END EC PRIVATE KEY-----
;
const test_localhost_pem =
    \\-----BEGIN CERTIFICATE-----
    \\MIIBlTCCATugAwIBAgIUJ0VVpBMXbR+m2qeJVtlLPwMGrS8wCgYIKoZIzj0EAwIw
    \\FDESMBAGA1UEAwwJbG9jYWxob3N0MCAXDTI2MDkxODAyMjc1MVoYDzIwNTYwOTEw
    \\MDIyNzUxWjAUMRIwEAYDVQQDDAlsb2NhbGhvc3QwWTATBgcqhkjOPQIBBggqhkjO
    \\PQMBBwNCAARNKn/A+BTv6O4gtvRSCTsilRB39MBxN3r12JuLyBsBjbeS0BGQT0Ln
    \\dUgaVrtTNu7iCSi0Z5mDy584RtfhwLjjo2kwZzAdBgNVHQ4EFgQUgsQXmkDpwyyD
    \\DE+urWAkJzlvp4gwHwYDVR0jBBgwFoAUgsQXmkDpwyyDDE+urWAkJzlvp4gwDwYD
    \\VR0TAQH/BAUwAwEB/zAUBgNVHREEDTALgglsb2NhbGhvc3QwCgYIKoZIzj0EAwID
    \\SAAwRQIhAL/ObOrd87Ioq197659prUHNDVOQ8y9LpqKlXroBCK0+AiBu5JczdLo0
    \\paz/2uMhZZ65w/QAplKh2+e0QSDAcZreyA==
    \\-----END CERTIFICATE-----
;
const test_wildcard_pem =
    \\-----BEGIN CERTIFICATE-----
    \\MIIBnDCCAUOgAwIBAgIUBeGIcIZGlWQDw9k8EVl0eQn+0i8wCgYIKoZIzj0EAwIw
    \\FjEUMBIGA1UEAwwLZXhhbXBsZS5jb20wIBcNMjYwOTE4MDIyNzUxWhgPMjA1NjA5
    \\MTAwMjI3NTFaMBYxFDASBgNVBAMMC2V4YW1wbGUuY29tMFkwEwYHKoZIzj0CAQYI
    \\KoZIzj0DAQcDQgAETSp/wPgU7+juILb0Ugk7IpUQd/TAcTd69dibi8gbAY23ktAR
    \\kE9C53VIGla7Uzbu4gkotGeZg8ufOEbX4cC446NtMGswHQYDVR0OBBYEFILEF5pA
    \\6cMsgwxPrq1gJCc5b6eIMB8GA1UdIwQYMBaAFILEF5pA6cMsgwxPrq1gJCc5b6eI
    \\MA8GA1UdEwEB/wQFMAMBAf8wGAYDVR0RBBEwD4INKi5leGFtcGxlLmNvbTAKBggq
    \\hkjOPQQDAgNHADBEAiBaUMdxsQOU9V2gfaL6EW0cblAScC1OvxJl+4P07YUxDAIg
    \\ffw63xlHzM5X1n+gB6U2k9pqnk+IQYwD2pyylUk/I74=
    \\-----END CERTIFICATE-----
;
const test_ed25519_key_pem =
    \\-----BEGIN PRIVATE KEY-----
    \\MC4CAQAwBQYDK2VwBCIEIC7QOG4KwXQFSsbxdpxWvVUO5ON7JPjpewzoDqKPZSoO
    \\-----END PRIVATE KEY-----
;
const test_ed25519_pem =
    \\-----BEGIN CERTIFICATE-----
    \\MIIBTzCCAQGgAwIBAgIUElLBZ3M+v85vUwlfAtwMIFA8fvQwBQYDK2VwMBIxEDAO
    \\BgNVBAMMB2VkLnRlc3QwIBcNMjYwOTE4MDIyNzUxWhgPMjA1NjA5MTAwMjI3NTFa
    \\MBIxEDAOBgNVBAMMB2VkLnRlc3QwKjAFBgMrZXADIQDDb3XnRnNGl7VnUxtvlAM3
    \\Wx++JEtaulpTtA6HsXZ5HaNnMGUwHQYDVR0OBBYEFLT9KJDLMqFxXjDiduG7N1zR
    \\HoZTMB8GA1UdIwQYMBaAFLT9KJDLMqFxXjDiduG7N1zRHoZTMA8GA1UdEwEB/wQF
    \\MAMBAf8wEgYDVR0RBAswCYIHZWQudGVzdDAFBgMrZXADQQCnjUP9Av1Ugtg6dE+7
    \\VljHsDK78pyjUZWFgeuzx/aQ2obYNKv3HLka/NYNWMQNiNeEFVpfwqDhBCAUe9ia
    \\angI
    \\-----END CERTIFICATE-----
;

const TestCerts = struct {
    der: [3][1024]u8,
    chains: [3][1][]const u8,
    key_der: [2][256]u8,
    entries: [3]CertEntry,

    /// Entry 0 (default) is localhost, 1 is *.example.com, 2 is Ed25519 ed.test.
    fn load(self: *TestCerts) !void {
        const pems = [3][]const u8{ test_localhost_pem, test_wildcard_pem, test_ed25519_pem };
        for (pems, 0..) |pem, i| self.chains[i] = .{try tls13.parsePemCert(pem, &self.der[i])};
        const ec = try tls13.extractEcPrivateKey(try tls13.parsePemPrivateKey(test_ec_key_pem, &self.key_der[0]));
        const ed = try tls13.extractEd25519PrivateKey(try tls13.parsePemPrivateKey(test_ed25519_key_pem, &self.key_der[1]));
        self.entries = .{
            .{ .server_names = &.{"localhost"}, .cert = .{ .cert_chain_der = &self.chains[0], .private_key_bytes = ec } },
            .{ .server_names = &.{"*.example.com"}, .cert = .{ .cert_chain_der = &self.chains[1], .private_key_bytes = ec } },
            .{ .server_names = &.{"ed.test"}, .cert = .{
                .cert_chain_der = &self.chains[2],
                .private_key_bytes = ed,
                .private_key_algorithm = .ed25519,
            } },
        };
    }
};

/// std.crypto.tls.Client wired straight to a `Conn`: whatever the client
/// flushes is fed to the server, whatever the server queues is what the
/// client reads.
const StdClientPipe = struct {
    conn: *Conn,
    /// Feed the server this many bytes at a time.
    chunk: usize = std.math.maxInt(usize),
    feed_err: ?Error = null,
    to_server: std.Io.Writer,
    from_server: std.Io.Reader,
    to_buf: [tls.Client.min_buffer_len]u8 = undefined,
    from_buf: [tls.Client.min_buffer_len]u8 = undefined,
    client_read_buf: [tls.Client.min_buffer_len]u8 = undefined,
    client_write_buf: [tls.Client.min_buffer_len]u8 = undefined,

    fn create(gpa: Allocator, conn: *Conn) !*StdClientPipe {
        const p = try gpa.create(StdClientPipe);
        p.* = .{
            .conn = conn,
            .to_server = .{ .vtable = &.{ .drain = drain }, .buffer = &p.to_buf },
            .from_server = .{ .vtable = &.{ .stream = stream }, .buffer = &p.from_buf, .seek = 0, .end = 0 },
        };
        return p;
    }

    fn connect(p: *StdClientPipe, host: ?[]const u8) !tls.Client {
        var entropy: [tls.Client.Options.entropy_len]u8 = undefined;
        sys.randomBytes(&entropy);
        return tls.Client.init(&p.from_server, &p.to_server, .{
            .host = if (host) |h| .{ .explicit = h } else .no_verification,
            .ca = .no_verification,
            .write_buffer = &p.client_write_buf,
            .read_buffer = &p.client_read_buf,
            .entropy = &entropy,
            .realtime_now = .{ .nanoseconds = 0 },
        });
    }

    fn feed(p: *StdClientPipe, bytes: []const u8) std.Io.Writer.Error!void {
        var rest = bytes;
        while (rest.len > 0) {
            const n = @min(rest.len, p.chunk);
            p.conn.feed(rest[0..n]) catch |err| {
                p.feed_err = err;
                return error.WriteFailed;
            };
            rest = rest[n..];
        }
    }

    fn drain(w: *std.Io.Writer, data: []const []const u8, splat: usize) std.Io.Writer.Error!usize {
        const p: *StdClientPipe = @alignCast(@fieldParentPtr("to_server", w));
        try p.feed(w.buffer[0..w.end]);
        w.end = 0;
        var n: usize = 0;
        for (data[0 .. data.len - 1]) |d| {
            try p.feed(d);
            n += d.len;
        }
        for (0..splat) |_| try p.feed(data[data.len - 1]);
        return n + data[data.len - 1].len * splat;
    }

    fn stream(r: *std.Io.Reader, w: *std.Io.Writer, limit: std.Io.Limit) std.Io.Reader.StreamError!usize {
        const p: *StdClientPipe = @alignCast(@fieldParentPtr("from_server", r));
        const pending = p.conn.pendingOutput();
        if (pending.len == 0) return error.EndOfStream;
        const n = w.write(limit.sliceConst(pending)) catch return error.WriteFailed;
        p.conn.consumeOutput(n);
        return n;
    }

    /// Client → server application data.
    fn send(p: *StdClientPipe, client: *tls.Client, data: []const u8) !void {
        try client.writer.writeAll(data);
        try client.writer.flush();
        try p.to_server.flush();
    }
};

fn expectStdClientRoundTrip(config: *const Config, chunk: usize) !struct { CipherSuite, Group } {
    const gpa = testing.allocator;
    var conn = Conn.init(gpa, config);
    defer conn.deinit();
    const pipe = try StdClientPipe.create(gpa, &conn);
    defer gpa.destroy(pipe);
    pipe.chunk = chunk;

    var client = try pipe.connect(null);
    try testing.expect(conn.handshakeComplete());

    try pipe.send(&client, "ping");
    var buf: [64]u8 = undefined;
    try testing.expectEqualStrings("ping", buf[0..conn.read(&buf)]);
    try testing.expectEqual(@as(usize, 0), conn.read(&buf));

    // Bigger than one record, so the server has to fragment.
    const big = try gpa.alloc(u8, 40_000);
    defer gpa.free(big);
    for (big, 0..) |*b, i| b.* = @truncate(i *% 7);
    try conn.write(big);
    const got = try gpa.alloc(u8, big.len);
    defer gpa.free(got);
    try client.reader.readSliceAll(got);
    try testing.expectEqualSlices(u8, big, got);

    // And the other way, several records in one flush.
    try pipe.send(&client, big);
    var total: usize = 0;
    while (true) {
        const n = conn.read(got[total..]);
        if (n == 0) break;
        total += n;
    }
    try testing.expectEqualSlices(u8, big, got[0..total]);

    try client.end();
    try pipe.to_server.flush();
    try testing.expect(conn.peerClosed());
    conn.close();
    try testing.expectError(error.NotConnected, conn.write("late"));
    try testing.expectError(error.EndOfStream, client.reader.takeByte());

    return .{ conn.cipherSuite().?, conn.keyExchangeGroup().? };
}

test "std.crypto.tls.Client completes a handshake for every suite and group" {
    var certs: TestCerts = undefined;
    try certs.load();
    for ([_]CipherSuite{ .aes_128_gcm_sha256, .chacha20_poly1305_sha256, .aes_256_gcm_sha384 }) |cs| {
        for ([_]Group{ .x25519, .secp256r1 }) |g| {
            const config: Config = .{ .certs = &certs.entries, .cipher_suites = &.{cs}, .groups = &.{g} };
            const got_cs, const got_g = try expectStdClientRoundTrip(&config, std.math.maxInt(usize));
            try testing.expectEqual(cs, got_cs);
            try testing.expectEqual(g, got_g);
        }
    }
}

test "the default preference is AES-128-GCM over X25519" {
    var certs: TestCerts = undefined;
    try certs.load();
    const config: Config = .{ .certs = &certs.entries };
    const cs, const g = try expectStdClientRoundTrip(&config, std.math.maxInt(usize));
    try testing.expectEqual(CipherSuite.aes_128_gcm_sha256, cs);
    try testing.expectEqual(Group.x25519, g);
}

test "a handshake fed one byte at a time" {
    var certs: TestCerts = undefined;
    try certs.load();
    const config: Config = .{ .certs = &certs.entries, .cipher_suites = &.{.aes_256_gcm_sha384} };
    _ = try expectStdClientRoundTrip(&config, 1);
}

test "an Ed25519 certificate is served to a client that accepts it" {
    // std.crypto.tls.Client cannot verify Ed25519 in TLS 1.3, hence MiniClient.
    var certs: TestCerts = undefined;
    try certs.load();
    const config: Config = .{ .certs = &certs.entries };
    const ed = @intFromEnum(tls.SignatureScheme.ed25519);
    {
        var conn = Conn.init(testing.allocator, &config);
        defer conn.deinit();
        var client: MiniClient = .{ .gpa = testing.allocator, .sni = "ed.test", .sig_algs = &.{ed} };
        defer client.deinit();
        try client.handshake(&conn);
        try testing.expect(conn.handshakeComplete());
        try testing.expect(client.cv_verified);
        try testing.expectEqualSlices(u8, certs.chains[2][0], client.leaf.items);
    }
    {
        var conn = Conn.init(testing.allocator, &config);
        defer conn.deinit();
        var client: MiniClient = .{ .gpa = testing.allocator, .sni = "ed.test" };
        defer client.deinit();
        try testing.expectError(error.HandshakeFailure, client.handshake(&conn));
    }
}

test "the server rotates its keys before AES-GCM's record limit" {
    var certs: TestCerts = undefined;
    try certs.load();
    const config: Config = .{ .certs = &certs.entries };
    const gpa = testing.allocator;
    var conn = Conn.init(gpa, &config);
    defer conn.deinit();
    const pipe = try StdClientPipe.create(gpa, &conn);
    defer gpa.destroy(pipe);
    var client = try pipe.connect(null);

    conn.write_keys.?.seq = key_update_after;
    client.read_seq = key_update_after;
    const old_key = conn.write_keys.?.key;
    try conn.write("after rotation");
    try testing.expect(!mem.eql(u8, &old_key, &conn.write_keys.?.key));
    try testing.expectEqual(@as(u64, 1), conn.write_keys.?.seq);
    var buf: [14]u8 = undefined;
    try client.reader.readSliceAll(&buf);
    try testing.expectEqualStrings("after rotation", &buf);
}

/// A hand-rolled TLS 1.3 client for what std.crypto.tls.Client cannot be made
/// to do: HelloRetryRequest, pinned offers, KeyUpdate, and malformed input.
const MiniClient = struct {
    gpa: Allocator,
    suites: []const CipherSuite = &.{.aes_128_gcm_sha256},
    /// Groups to send a key share for; 0x0018 (secp384r1) gets a dummy share.
    shares: []const u16 = &.{@intFromEnum(Group.x25519)},
    groups: []const u16 = &.{ @intFromEnum(Group.x25519), @intFromEnum(Group.secp256r1) },
    sig_algs: []const u16 = &.{@intFromEnum(tls.SignatureScheme.ecdsa_secp256r1_sha256)},
    versions: []const u16 = &.{tls13_version},
    sni: ?[]const u8 = null,
    alpn: []const []const u8 = &.{},
    /// ClientHello2 shares this group instead of the one the HRR asked for.
    hrr_wrong_group: ?u16 = null,
    corrupt_finished: bool = false,
    early_data: bool = false,
    /// Ticket to offer for resumption.
    offer: ?ClientTicket = null,
    corrupt_binder: bool = false,
    omit_psk_modes: bool = false,

    x25519: X25519.KeyPair = undefined,
    p256: EcdsaP256Sha256.KeyPair = undefined,
    ch1: std.ArrayList(u8) = .empty,
    suite: CipherSuite = .aes_128_gcm_sha256,
    transcript: Transcript = undefined,
    read_keys: ?TrafficKeys = null,
    write_keys: ?TrafficKeys = null,
    got_hrr: bool = false,
    leaf: std.ArrayList(u8) = .empty,
    alpn_got: std.ArrayList(u8) = .empty,
    sni_acked: bool = false,
    cv_verified: bool = false,
    resuming: bool = false,
    master: Secret = @splat(0),
    received: ?ClientTicket = null,
    app_data: std.ArrayList(u8) = .empty,
    alert: ?tls.Alert.Description = null,
    server_closed: bool = false,
    scratch: [tls.max_ciphertext_len]u8 = undefined,

    fn deinit(c: *MiniClient) void {
        c.ch1.deinit(c.gpa);
        c.leaf.deinit(c.gpa);
        c.alpn_got.deinit(c.gpa);
        c.app_data.deinit(c.gpa);
    }

    fn generateKeys(c: *MiniClient) void {
        var seed: [32]u8 = undefined;
        sys.randomBytes(&seed);
        c.x25519 = X25519.KeyPair.generateDeterministic(seed) catch unreachable;
        sys.randomBytes(&seed);
        c.p256 = EcdsaP256Sha256.KeyPair.generateDeterministic(seed) catch unreachable;
    }

    fn clientHello(c: *MiniClient, list: *std.ArrayList(u8), only_group: ?u16) !void {
        const msg_start = list.items.len;
        var b: Builder = .{ .list = list, .gpa = c.gpa };
        try b.u8_(hs_client_hello);
        const msg = try b.begin(u24);
        try b.u16_(0x0303);
        var random: [32]u8 = undefined;
        sys.randomBytes(&random);
        try b.bytes(&random);
        try b.u8_(32);
        try b.bytes(&([_]u8{0xab} ** 32));
        const cs = try b.begin(u16);
        for (c.suites) |s| try b.u16_(@intFromEnum(s));
        try b.end(u16, cs);
        try b.bytes(&.{ 1, 0 });
        const exts = try b.begin(u16);

        try b.u16_(ext.supported_versions);
        const sv = try b.begin(u16);
        const sv_list = try b.begin(u8);
        for (c.versions) |v| try b.u16_(v);
        try b.end(u8, sv_list);
        try b.end(u16, sv);

        try b.u16_(ext.supported_groups);
        const sg = try b.begin(u16);
        const sg_list = try b.begin(u16);
        for (c.groups) |g| try b.u16_(g);
        try b.end(u16, sg_list);
        try b.end(u16, sg);

        try b.u16_(ext.signature_algorithms);
        const sa = try b.begin(u16);
        const sa_list = try b.begin(u16);
        for (c.sig_algs) |a| try b.u16_(a);
        try b.end(u16, sa_list);
        try b.end(u16, sa);

        try b.u16_(ext.key_share);
        const ks = try b.begin(u16);
        const ks_list = try b.begin(u16);
        const one = [_]u16{only_group orelse 0};
        for (if (only_group != null) &one else c.shares) |g| {
            try b.u16_(g);
            if (g == @intFromEnum(Group.x25519)) {
                try b.u16_(32);
                try b.bytes(&c.x25519.public_key);
            } else if (g == @intFromEnum(Group.secp256r1)) {
                try b.u16_(65);
                try b.bytes(&c.p256.public_key.toUncompressedSec1());
            } else {
                try b.u16_(97);
                try b.bytes(&([_]u8{4} ** 97));
            }
        }
        try b.end(u16, ks_list);
        try b.end(u16, ks);

        if (c.sni) |name| {
            try b.u16_(ext.server_name);
            const sn = try b.begin(u16);
            const sn_list = try b.begin(u16);
            try b.u8_(0);
            try b.u16_(@intCast(name.len));
            try b.bytes(name);
            try b.end(u16, sn_list);
            try b.end(u16, sn);
        }
        if (c.early_data) {
            try b.u16_(ext.early_data);
            try b.u16_(0);
        }
        if (c.alpn.len > 0) {
            try b.u16_(ext.alpn);
            const a = try b.begin(u16);
            const a_list = try b.begin(u16);
            for (c.alpn) |p| {
                try b.u8_(@intCast(p.len));
                try b.bytes(p);
            }
            try b.end(u16, a_list);
            try b.end(u16, a);
        }
        if (c.offer) |*t| {
            if (!c.omit_psk_modes) try b.bytes(&.{ 0, ext.psk_key_exchange_modes, 0, 2, 1, psk_dhe_ke });
            const L = hashLen(t.suite);
            try b.u16_(ext.pre_shared_key);
            const e = try b.begin(u16);
            const ids = try b.begin(u16);
            try b.u16_(@intCast(t.len));
            try b.bytes(t.identity[0..t.len]);
            try b.bytes(&.{ 0, 0, 0, 0 });
            try b.end(u16, ids);
            try b.u16_(@intCast(1 + L));
            try b.u8_(@intCast(L));
            try b.list.appendNTimes(c.gpa, 0, L);
            try b.end(u16, e);
            try b.end(u16, exts);
            try b.end(u24, msg);

            var transcript = if (c.got_hrr) c.transcript else Transcript.init(t.suite);
            transcript.update(list.items[msg_start .. list.items.len - (2 + 1 + L)]);
            var early: Secret = @splat(0);
            switch (t.suite) {
                inline else => |suite| {
                    const S = Suite(suite);
                    early[0..S.hash_len].* = S.Hkdf.extract(&.{}, t.psk[0..S.hash_len]);
                },
            }
            const binder_key = testExpand(t.suite, &early, "res binder", emptyHashOf(t.suite)[0..L]);
            var binder = finishedMac(t.suite, &binder_key, transcript.peek());
            if (c.corrupt_binder) binder[0] ^= 1;
            @memcpy(list.items[list.items.len - L ..], binder[0..L]);
            return;
        }
        try b.end(u16, exts);
        try b.end(u24, msg);
    }

    fn sendPlain(c: *MiniClient, conn: *Conn, content_type: u8, data: []const u8) !void {
        _ = c;
        var hdr: [5]u8 = .{ content_type, 3, 1, 0, 0 };
        mem.writeInt(u16, hdr[3..5], @intCast(data.len), .big);
        try conn.feed(&hdr);
        try conn.feed(data);
    }

    fn sendProtected(c: *MiniClient, conn: *Conn, inner: tls.ContentType, data: []const u8) !void {
        var rec: [tls.max_ciphertext_record_len]u8 = undefined;
        const len = sealedLen(c.suite, data.len);
        sealInto(c.suite, &c.write_keys.?, inner, data, &c.scratch, rec[0..len]);
        try conn.feed(rec[0..len]);
    }

    /// Runs the handshake up to (and including) our Finished.
    fn handshake(c: *MiniClient, conn: *Conn) !void {
        c.generateKeys();
        try c.clientHello(&c.ch1, null);
        try c.sendPlain(conn, ct_handshake, c.ch1.items);
        try c.pump(conn);
    }

    /// Consumes everything the server queued.
    fn pump(c: *MiniClient, conn: *Conn) !void {
        var hs: std.ArrayList(u8) = .empty;
        defer hs.deinit(c.gpa);
        while (conn.pendingOutput().len >= 5) {
            const out = conn.pendingOutput();
            const len = mem.readInt(u16, out[3..5], .big);
            var rec: [tls.max_ciphertext_record_len]u8 = undefined;
            @memcpy(rec[0 .. 5 + len], out[0 .. 5 + len]);
            conn.consumeOutput(5 + len);
            const record = rec[0 .. 5 + len];
            var content: []const u8 = record[5..];
            var ct = record[0];
            if (ct == ct_ccs) continue;
            if (ct == ct_app_data) {
                const plain = try openWith(c.suite, &c.read_keys.?, record, &c.scratch);
                var end = plain.len;
                while (plain[end - 1] == 0) end -= 1;
                ct = plain[end - 1];
                content = plain[0 .. end - 1];
            }
            switch (ct) {
                ct_alert => {
                    if (content[1] == 0) c.server_closed = true else c.alert = @enumFromInt(content[1]);
                },
                ct_app_data => try c.app_data.appendSlice(c.gpa, content),
                ct_handshake => {
                    try hs.appendSlice(c.gpa, content);
                    while (hs.items.len >= 4) {
                        const mlen = mem.readInt(u24, hs.items[1..4], .big);
                        if (hs.items.len < 4 + mlen) break;
                        const msg = try c.gpa.dupe(u8, hs.items[0 .. 4 + mlen]);
                        defer c.gpa.free(msg);
                        hs.replaceRangeAssumeCapacity(0, 4 + mlen, &.{});
                        try c.onHandshake(conn, msg);
                    }
                },
                else => return error.UnexpectedMessage,
            }
        }
    }

    var client_hs_secret: Secret = undefined;
    var server_hs_secret: Secret = undefined;
    var handshake_secret: Secret = undefined;

    fn onHandshake(c: *MiniClient, conn: *Conn, msg: []const u8) !void {
        var p: Parser = .{ .buf = msg[4..] };
        switch (msg[0]) {
            hs_server_hello => {
                _ = try p.int(u16);
                const random = try p.take(32);
                _ = try p.vec(u8);
                c.suite = @enumFromInt(try p.int(u16));
                _ = try p.int(u8);
                var exts: Parser = .{ .buf = try p.vec(u16) };
                var group: u16 = 0;
                var key: []const u8 = &.{};
                while (exts.rest() > 0) {
                    const kind = try exts.int(u16);
                    var data: Parser = .{ .buf = try exts.vec(u16) };
                    if (kind == ext.key_share) {
                        group = try data.int(u16);
                        if (data.rest() > 0) key = try data.vec(u16);
                    } else if (kind == ext.pre_shared_key) {
                        try testing.expectEqual(@as(u16, 0), try data.int(u16));
                        c.resuming = true;
                    }
                }
                if (mem.eql(u8, random, &tls.hello_retry_request_sequence)) {
                    try testing.expect(!c.got_hrr);
                    c.got_hrr = true;
                    c.transcript = .init(c.suite);
                    var h = Transcript.init(c.suite);
                    h.update(c.ch1.items);
                    const digest = h.peek();
                    c.transcript.update(&.{ hs_message_hash, 0, 0, @intCast(hashLen(c.suite)) });
                    c.transcript.update(digest[0..hashLen(c.suite)]);
                    c.transcript.update(msg);
                    var ch2: std.ArrayList(u8) = .empty;
                    defer ch2.deinit(c.gpa);
                    try c.clientHello(&ch2, c.hrr_wrong_group orelse group);
                    c.transcript.update(ch2.items);
                    try c.sendPlain(conn, ct_ccs, &.{1});
                    try c.sendPlain(conn, ct_handshake, ch2.items);
                    return;
                }
                if (!c.got_hrr) {
                    c.transcript = .init(c.suite);
                    c.transcript.update(c.ch1.items);
                }
                c.transcript.update(msg);
                var shared: [32]u8 = undefined;
                if (group == @intFromEnum(Group.x25519)) {
                    shared = try X25519.scalarmult(c.x25519.secret_key, key[0..32].*);
                } else {
                    const point = try (try P256.fromSec1(key)).mul(c.p256.secret_key.bytes, .big);
                    shared = point.toUncompressedSec1()[1..33].*;
                }
                const s = handshakeSecrets(c.suite, if (c.resuming) &c.offer.?.psk else null, c.transcript.peek(), &shared);
                client_hs_secret = s.client;
                server_hs_secret = s.server;
                handshake_secret = s.handshake;
                c.read_keys = .derive(c.suite, s.server);
                c.write_keys = .derive(c.suite, s.client);
            },
            hs_encrypted_extensions => {
                c.transcript.update(msg);
                var exts: Parser = .{ .buf = try p.vec(u16) };
                while (exts.rest() > 0) {
                    const kind = try exts.int(u16);
                    var data: Parser = .{ .buf = try exts.vec(u16) };
                    if (kind == ext.alpn) {
                        var l: Parser = .{ .buf = try data.vec(u16) };
                        try c.alpn_got.appendSlice(c.gpa, try l.vec(u8));
                    } else if (kind == ext.server_name) c.sni_acked = true;
                }
            },
            hs_certificate => {
                c.transcript.update(msg);
                _ = try p.vec(u8);
                var list: Parser = .{ .buf = try p.vec(u24) };
                try c.leaf.appendSlice(c.gpa, try list.vec(u24));
            },
            hs_certificate_verify => {
                const scheme: tls.SignatureScheme = @enumFromInt(try p.int(u16));
                const sig = try p.vec(u16);
                const context = "TLS 1.3, server CertificateVerify";
                const th = c.transcript.peek();
                var content: [64 + context.len + 1 + 48]u8 = undefined;
                @memset(content[0..64], 0x20);
                content[64..][0..context.len].* = context.*;
                content[64 + context.len] = 0;
                @memcpy(content[64 + context.len + 1 ..][0..hashLen(c.suite)], th[0..hashLen(c.suite)]);
                const signed = content[0 .. 64 + context.len + 1 + hashLen(c.suite)];
                const leaf = try (crypto.Certificate{ .buffer = c.leaf.items, .index = 0 }).parse();
                const pk = leaf.pubKey();
                switch (scheme) {
                    .ecdsa_secp256r1_sha256 => try (try EcdsaP256Sha256.Signature.fromDer(sig)).verify(signed, try EcdsaP256Sha256.PublicKey.fromSec1(pk)),
                    .ed25519 => try Ed25519.Signature.fromBytes(sig[0..64].*).verify(signed, try Ed25519.PublicKey.fromBytes(pk[0..32].*)),
                    else => return error.UnexpectedMessage,
                }
                c.cv_verified = true;
                c.transcript.update(msg);
            },
            hs_finished => {
                const expected = finishedMac(c.suite, &server_hs_secret, c.transcript.peek());
                try testing.expectEqualSlices(u8, expected[0..hashLen(c.suite)], msg[4..]);
                c.transcript.update(msg);
                const app = appSecrets(c.suite, handshake_secret, c.transcript.peek());
                c.master = app.master;

                var fin = finishedMac(c.suite, &client_hs_secret, c.transcript.peek());
                if (c.corrupt_finished) fin[0] ^= 1;
                var fin_msg: [4 + 48]u8 = undefined;
                fin_msg[0..4].* = .{ hs_finished, 0, 0, @intCast(hashLen(c.suite)) };
                @memcpy(fin_msg[4..][0..hashLen(c.suite)], fin[0..hashLen(c.suite)]);
                // The server's answer, even an alert, comes under its app keys.
                c.read_keys = .derive(c.suite, app.server);
                try c.sendPlain(conn, ct_ccs, &.{1});
                c.transcript.update(fin_msg[0 .. 4 + hashLen(c.suite)]);
                try c.sendProtected(conn, .handshake, fin_msg[0 .. 4 + hashLen(c.suite)]);
                c.write_keys = .derive(c.suite, app.client);
            },
            hs_key_update => c.read_keys = c.read_keys.?.next(c.suite),
            hs_new_session_ticket => {
                _ = try p.int(u32); // lifetime
                _ = try p.int(u32); // age_add
                const nonce = try p.vec(u8);
                const ticket = try p.vec(u16);
                try testing.expectEqual(@as(usize, 0), (try p.vec(u16)).len);
                const res_master = testExpand(c.suite, &c.master, "res master", c.transcript.peek()[0..hashLen(c.suite)]);
                var t: ClientTicket = .{ .suite = c.suite, .psk = testExpand(c.suite, &res_master, "resumption", nonce), .len = ticket.len };
                @memcpy(t.identity[0..ticket.len], ticket);
                c.received = t;
            },
            else => return error.UnexpectedMessage,
        }
    }
};

/// The last record queued is a plaintext alert `desc`.
const ClientTicket = struct {
    suite: CipherSuite,
    psk: Secret,
    identity: [max_ticket_len]u8 = undefined,
    len: usize,
};

fn testExpand(cs: CipherSuite, secret: *const Secret, label: []const u8, context: []const u8) Secret {
    var out: Secret = @splat(0);
    switch (cs) {
        inline else => |c| {
            const S = Suite(c);
            out[0..S.hash_len].* = S.expand(secret, label, context, S.hash_len);
        },
    }
    return out;
}

fn emptyHashOf(cs: CipherSuite) Secret {
    var out: Secret = @splat(0);
    switch (cs) {
        inline else => |c| out[0..Suite(c).hash_len].* = tls.emptyHash(Suite(c).Hash),
    }
    return out;
}

fn expectAlert(conn: *const Conn, desc: tls.Alert.Description) !void {
    var out = conn.pendingOutput();
    while (out.len > 7) out = out[5 + mem.readInt(u16, out[3..5], .big) ..];
    try testing.expectEqual(@as(usize, 7), out.len);
    try testing.expectEqual(ct_alert, out[0]);
    try testing.expectEqual(@intFromEnum(desc), out[6]);
}

test "HelloRetryRequest when the client's key share is for a group we refuse" {
    var certs: TestCerts = undefined;
    try certs.load();
    for ([_]CipherSuite{ .aes_128_gcm_sha256, .chacha20_poly1305_sha256, .aes_256_gcm_sha384 }) |cs| {
        // Server only does P-256; client guessed X25519.
        const config: Config = .{ .certs = &certs.entries, .groups = &.{.secp256r1} };
        var conn = Conn.init(testing.allocator, &config);
        defer conn.deinit();
        var client: MiniClient = .{ .gpa = testing.allocator, .suites = &.{cs} };
        defer client.deinit();
        try client.handshake(&conn);
        try client.pump(&conn);
        try testing.expect(client.got_hrr);
        try testing.expect(conn.handshakeComplete());
        try testing.expectEqual(Group.secp256r1, conn.keyExchangeGroup().?);
        try testing.expectEqual(cs, conn.cipherSuite().?);

        try client.sendProtected(&conn, .application_data, "hello");
        var buf: [16]u8 = undefined;
        try testing.expectEqualStrings("hello", buf[0..conn.read(&buf)]);
        try conn.write("world");
        try client.pump(&conn);
        try testing.expectEqualStrings("world", client.app_data.items);
    }
}

test "HelloRetryRequest when the client shares only a group we do not implement" {
    var certs: TestCerts = undefined;
    try certs.load();
    const config: Config = .{ .certs = &certs.entries };
    var conn = Conn.init(testing.allocator, &config);
    defer conn.deinit();
    var client: MiniClient = .{
        .gpa = testing.allocator,
        .shares = &.{0x0018},
        .groups = &.{ 0x0018, @intFromEnum(Group.x25519) },
    };
    defer client.deinit();
    try client.handshake(&conn);
    try testing.expect(client.got_hrr);
    try testing.expect(conn.handshakeComplete());
    try testing.expectEqual(Group.x25519, conn.keyExchangeGroup().?);
}

test "a second ClientHello with the wrong key share is rejected" {
    var certs: TestCerts = undefined;
    try certs.load();
    const config: Config = .{ .certs = &certs.entries, .groups = &.{.secp256r1} };
    var conn = Conn.init(testing.allocator, &config);
    defer conn.deinit();
    var client: MiniClient = .{ .gpa = testing.allocator, .hrr_wrong_group = @intFromEnum(Group.x25519) };
    defer client.deinit();
    try testing.expectError(error.IllegalParameter, client.handshake(&conn));
    try expectAlert(&conn, .illegal_parameter);
    try testing.expectError(error.ConnectionFailed, conn.feed("x"));
}

test "no group in common is a handshake_failure" {
    var certs: TestCerts = undefined;
    try certs.load();
    const config: Config = .{ .certs = &certs.entries };
    var conn = Conn.init(testing.allocator, &config);
    defer conn.deinit();
    var client: MiniClient = .{ .gpa = testing.allocator, .shares = &.{0x0018}, .groups = &.{0x0018} };
    defer client.deinit();
    try testing.expectError(error.HandshakeFailure, client.handshake(&conn));
    try expectAlert(&conn, .handshake_failure);
}

test "SNI picks the certificate: exact, wildcard, default" {
    var certs: TestCerts = undefined;
    try certs.load();
    const config: Config = .{ .certs = &certs.entries };
    const cases = [_]struct { ?[]const u8, usize, bool }{
        .{ "localhost", 0, true },
        .{ "www.example.com", 1, true },
        .{ "a.b.example.com", 0, false },
        .{ "unknown.test", 0, false },
        .{ null, 0, false },
    };
    for (cases) |case| {
        var conn = Conn.init(testing.allocator, &config);
        defer conn.deinit();
        var client: MiniClient = .{ .gpa = testing.allocator, .sni = case[0] };
        defer client.deinit();
        try client.handshake(&conn);
        try testing.expect(conn.handshakeComplete());
        try testing.expect(client.cv_verified);
        try testing.expectEqualSlices(u8, certs.chains[case[1]][0], client.leaf.items);
        try testing.expectEqual(case[2], client.sni_acked);
        if (case[0]) |name| try testing.expectEqualStrings(name, conn.serverName().?) else try testing.expect(conn.serverName() == null);
    }
}

test "a client that cannot verify our key type gets handshake_failure" {
    var certs: TestCerts = undefined;
    try certs.load();
    const config: Config = .{ .certs = &certs.entries };
    var conn = Conn.init(testing.allocator, &config);
    defer conn.deinit();
    var client: MiniClient = .{ .gpa = testing.allocator, .sig_algs = &.{@intFromEnum(tls.SignatureScheme.rsa_pss_rsae_sha256)} };
    defer client.deinit();
    try testing.expectError(error.HandshakeFailure, client.handshake(&conn));
    try expectAlert(&conn, .handshake_failure);
}

test "ALPN: server preference wins, a mismatch is fatal, no offer means none" {
    var certs: TestCerts = undefined;
    try certs.load();
    const config: Config = .{ .certs = &certs.entries, .alpn = &.{ "h2", "http/1.1" } };
    {
        var conn = Conn.init(testing.allocator, &config);
        defer conn.deinit();
        var client: MiniClient = .{ .gpa = testing.allocator, .alpn = &.{ "http/1.1", "h2" } };
        defer client.deinit();
        try client.handshake(&conn);
        try testing.expectEqualStrings("h2", conn.alpn().?);
        try testing.expectEqualStrings("h2", client.alpn_got.items);
    }
    {
        var conn = Conn.init(testing.allocator, &config);
        defer conn.deinit();
        var client: MiniClient = .{ .gpa = testing.allocator, .alpn = &.{"h3"} };
        defer client.deinit();
        try testing.expectError(error.NoApplicationProtocol, client.handshake(&conn));
        try expectAlert(&conn, .no_application_protocol);
    }
    {
        var conn = Conn.init(testing.allocator, &config);
        defer conn.deinit();
        var client: MiniClient = .{ .gpa = testing.allocator };
        defer client.deinit();
        try client.handshake(&conn);
        try testing.expect(conn.alpn() == null);
        try testing.expectEqual(@as(usize, 0), client.alpn_got.items.len);
    }
}

test "KeyUpdate from the client, with and without update_requested" {
    var certs: TestCerts = undefined;
    try certs.load();
    const config: Config = .{ .certs = &certs.entries, .cipher_suites = &.{.aes_256_gcm_sha384} };
    var conn = Conn.init(testing.allocator, &config);
    defer conn.deinit();
    var client: MiniClient = .{ .gpa = testing.allocator, .suites = &.{.aes_256_gcm_sha384} };
    defer client.deinit();
    try client.handshake(&conn);

    for ([_]u8{ 0, 1, 1 }) |requested| {
        try client.sendProtected(&conn, .handshake, &.{ hs_key_update, 0, 0, 1, requested });
        client.write_keys = client.write_keys.?.next(client.suite);
        try client.sendProtected(&conn, .application_data, "after");
        var buf: [16]u8 = undefined;
        try testing.expectEqualStrings("after", buf[0..conn.read(&buf)]);

        // A requested update is answered before our next record.
        try conn.write("reply");
        client.app_data.clearRetainingCapacity();
        try client.pump(&conn);
        try testing.expectEqualStrings("reply", client.app_data.items);
    }

    // update_requested must be 0 or 1.
    try testing.expectError(error.IllegalParameter, client.sendProtected(&conn, .handshake, &.{ hs_key_update, 0, 0, 1, 2 }));
}

test "repeated KeyUpdate requests are answered once, before our next record" {
    var certs: TestCerts = undefined;
    try certs.load();
    const config: Config = .{ .certs = &certs.entries };
    var conn = Conn.init(testing.allocator, &config);
    defer conn.deinit();
    var client: MiniClient = .{ .gpa = testing.allocator };
    defer client.deinit();
    try client.handshake(&conn);
    conn.consumeOutput(conn.pendingOutput().len);

    for (0..1000) |_| {
        try client.sendProtected(&conn, .handshake, &.{ hs_key_update, 0, 0, 1, 1 });
        client.write_keys = client.write_keys.?.next(client.suite);
    }
    try testing.expectEqual(@as(usize, 0), conn.pendingOutput().len);

    try conn.write("reply");
    try client.pump(&conn);
    try testing.expectEqualStrings("reply", client.app_data.items);
}

test "KeyUpdate sharing a record with more handshake data is rejected" {
    var certs: TestCerts = undefined;
    try certs.load();
    const config: Config = .{ .certs = &certs.entries };
    var conn = Conn.init(testing.allocator, &config);
    defer conn.deinit();
    var client: MiniClient = .{ .gpa = testing.allocator };
    defer client.deinit();
    try client.handshake(&conn);
    try testing.expectError(error.UnexpectedMessage, client.sendProtected(&conn, .handshake, &.{ hs_key_update, 0, 0, 1, 0, hs_key_update, 0 }));
}

test "close_notify in both directions" {
    var certs: TestCerts = undefined;
    try certs.load();
    const config: Config = .{ .certs = &certs.entries };
    var conn = Conn.init(testing.allocator, &config);
    defer conn.deinit();
    var client: MiniClient = .{ .gpa = testing.allocator };
    defer client.deinit();
    try client.handshake(&conn);

    conn.close();
    conn.close(); // idempotent
    try client.pump(&conn);
    try testing.expect(client.server_closed);
    try testing.expectError(error.NotConnected, conn.write("x"));

    // Still readable after our close_notify, until the peer's.
    try client.sendProtected(&conn, .application_data, "last words");
    try client.sendProtected(&conn, .alert, &tls.close_notify_alert);
    try testing.expect(conn.peerClosed());
    var buf: [32]u8 = undefined;
    try testing.expectEqualStrings("last words", buf[0..conn.read(&buf)]);
    // Anything after close_notify is ignored.
    try conn.feed("garbage that is not even a record");
}

test "a wrong client Finished is decrypt_error" {
    var certs: TestCerts = undefined;
    try certs.load();
    const config: Config = .{ .certs = &certs.entries };
    var conn = Conn.init(testing.allocator, &config);
    defer conn.deinit();
    var client: MiniClient = .{ .gpa = testing.allocator, .corrupt_finished = true };
    defer client.deinit();
    try testing.expectError(error.DecryptError, client.handshake(&conn));
    // Encrypted under our application keys, which the client now reads with.
    try client.pump(&conn);
    try testing.expectEqual(tls.Alert.Description.decrypt_error, client.alert.?);
}

test "a tampered record is bad_record_mac" {
    var certs: TestCerts = undefined;
    try certs.load();
    const config: Config = .{ .certs = &certs.entries };
    var conn = Conn.init(testing.allocator, &config);
    defer conn.deinit();
    var client: MiniClient = .{ .gpa = testing.allocator };
    defer client.deinit();
    try client.handshake(&conn);

    var rec: [64]u8 = undefined;
    const len = sealedLen(client.suite, 5);
    sealInto(client.suite, &client.write_keys.?, .application_data, "hello", &client.scratch, rec[0..len]);
    rec[7] ^= 0x80;
    try testing.expectError(error.BadRecordMac, conn.feed(rec[0..len]));
    try client.pump(&conn);
    try testing.expectEqual(tls.Alert.Description.bad_record_mac, client.alert.?);
}

test "a peer's fatal alert fails the connection without an answer" {
    var certs: TestCerts = undefined;
    try certs.load();
    const config: Config = .{ .certs = &certs.entries };
    var conn = Conn.init(testing.allocator, &config);
    defer conn.deinit();
    try testing.expectError(error.PeerAlert, conn.feed(&.{ ct_alert, 3, 3, 0, 2, 2, 40 }));
    try testing.expectEqual(tls.Alert.Description.handshake_failure, conn.peerAlert().?);
    try testing.expectEqual(@as(usize, 0), conn.pendingOutput().len);
}

test "malformed input returns an error and queues an alert" {
    var certs: TestCerts = undefined;
    try certs.load();
    const config: Config = .{ .certs = &certs.entries };
    const Case = struct { []const u8, Error, tls.Alert.Description };
    const cases = [_]Case{
        // Plain HTTP on the TLS port.
        .{ "GET / HTTP/1.1\r\n\r\n", error.UnexpectedMessage, .unexpected_message },
        // Record longer than 2^14 + 256.
        .{ &.{ ct_handshake, 3, 1, 0x41, 0x01 }, error.RecordOverflow, .record_overflow },
        // Application data before any keys.
        .{ &.{ ct_app_data, 3, 3, 0, 1, 0 }, error.UnexpectedMessage, .unexpected_message },
        // Zero-length handshake record.
        .{ &.{ ct_handshake, 3, 1, 0, 0 }, error.UnexpectedMessage, .unexpected_message },
        // CCS before the ClientHello.
        .{ &.{ ct_ccs, 3, 3, 0, 1, 1 }, error.UnexpectedMessage, .unexpected_message },
        // A Finished where the ClientHello belongs.
        .{ &.{ ct_handshake, 3, 1, 0, 5, hs_finished, 0, 0, 1, 0 }, error.UnexpectedMessage, .unexpected_message },
        // ClientHello body cut short.
        .{ &.{ ct_handshake, 3, 1, 0, 7, hs_client_hello, 0, 0, 3, 3, 3, 0 }, error.DecodeError, .decode_error },
        // Handshake message claiming more than we will buffer.
        .{ &.{ ct_handshake, 3, 1, 0, 4, hs_client_hello, 0xff, 0xff, 0xff }, error.DecodeError, .decode_error },
    };
    for (cases) |case| {
        var conn = Conn.init(testing.allocator, &config);
        defer conn.deinit();
        try testing.expectError(case[1], conn.feed(case[0]));
        try expectAlert(&conn, case[2]);
        try testing.expectError(error.ConnectionFailed, conn.feed(case[0]));
    }
}

test "a TLS 1.2-only client gets protocol_version" {
    var certs: TestCerts = undefined;
    try certs.load();
    const config: Config = .{ .certs = &certs.entries };
    var conn = Conn.init(testing.allocator, &config);
    defer conn.deinit();
    var client: MiniClient = .{ .gpa = testing.allocator, .versions = &.{0x0303} };
    defer client.deinit();
    try testing.expectError(error.ProtocolVersion, client.handshake(&conn));
    try expectAlert(&conn, .protocol_version);
}

test "mutated ClientHellos never crash the server" {
    var certs: TestCerts = undefined;
    try certs.load();
    const config: Config = .{ .certs = &certs.entries };
    var proto: MiniClient = .{ .gpa = testing.allocator, .sni = "localhost", .alpn = &.{"h2"}, .shares = &.{ 0x0018, @intFromEnum(Group.x25519), @intFromEnum(Group.secp256r1) } };
    defer proto.deinit();
    proto.generateKeys();
    var ch: std.ArrayList(u8) = .empty;
    defer ch.deinit(testing.allocator);
    try ch.appendSlice(testing.allocator, &.{ ct_handshake, 3, 1, 0, 0 });
    try proto.clientHello(&ch, null);
    mem.writeInt(u16, ch.items[3..5], @intCast(ch.items.len - 5), .big);

    var prng: std.Random.DefaultPrng = .init(0x7153);
    const rand = prng.random();
    const mutated = try testing.allocator.dupe(u8, ch.items);
    defer testing.allocator.free(mutated);
    for (0..3000) |_| {
        @memcpy(mutated, ch.items);
        for (0..rand.intRangeAtMost(usize, 1, 4)) |_| {
            mutated[rand.uintLessThan(usize, mutated.len)] = rand.int(u8);
        }
        const cut = if (rand.boolean()) mutated.len else rand.uintLessThan(usize, mutated.len);
        var conn = Conn.init(testing.allocator, &config);
        defer conn.deinit();
        conn.feed(mutated[0..cut]) catch {};
    }
}

test "a ClientHello split across records, coalesced in one feed" {
    var certs: TestCerts = undefined;
    try certs.load();
    const config: Config = .{ .certs = &certs.entries };
    var conn = Conn.init(testing.allocator, &config);
    defer conn.deinit();
    var client: MiniClient = .{ .gpa = testing.allocator, .sni = "localhost" };
    defer client.deinit();
    client.generateKeys();
    try client.clientHello(&client.ch1, null);

    var wire: std.ArrayList(u8) = .empty;
    defer wire.deinit(testing.allocator);
    const ch = client.ch1.items;
    for ([_][]const u8{ ch[0..3], ch[3..40], ch[40..] }) |part| {
        try wire.appendSlice(testing.allocator, &.{ ct_handshake, 3, 1, 0, @intCast(part.len) });
        try wire.appendSlice(testing.allocator, part);
    }
    try conn.feed(wire.items);
    try client.pump(&conn);
    try testing.expect(conn.handshakeComplete());
}

test "0-RTT the client sends anyway is skipped, before and after HelloRetryRequest" {
    var certs: TestCerts = undefined;
    try certs.load();
    const junk = [_]u8{ ct_app_data, 3, 3, 0, 32 } ++ [_]u8{0x5a} ** 32;
    for ([_]bool{ false, true }) |hrr| {
        const config: Config = .{ .certs = &certs.entries, .groups = if (hrr) &.{.secp256r1} else &.{.x25519} };
        var conn = Conn.init(testing.allocator, &config);
        defer conn.deinit();
        var client: MiniClient = .{ .gpa = testing.allocator, .early_data = true };
        defer client.deinit();
        client.generateKeys();
        try client.clientHello(&client.ch1, null);
        try client.sendPlain(&conn, ct_handshake, client.ch1.items);
        try conn.feed(&junk);
        try conn.feed(&junk);
        if (hrr) client.early_data = false;
        try client.pump(&conn);
        try testing.expect(conn.handshakeComplete());
        try testing.expectEqual(@as(usize, 0), conn.read(&.{}));

        // Once the handshake is done, the same record is an error.
        try testing.expectError(error.BadRecordMac, conn.feed(&junk));
    }
}

test "a certificate chain larger than one record" {
    var certs: TestCerts = undefined;
    try certs.load();
    // std's client caps a handshake message at one record, hence MiniClient.
    const filler = try testing.allocator.alloc(u8, 40_000);
    defer testing.allocator.free(filler);
    @memset(filler, 0x30);
    const chain = [_][]const u8{ certs.chains[0][0], filler };
    const entries = [_]CertEntry{.{ .server_names = &.{}, .cert = .{
        .cert_chain_der = &chain,
        .private_key_bytes = certs.entries[0].cert.private_key_bytes,
    } }};
    const config: Config = .{ .certs = &entries };
    var conn = Conn.init(testing.allocator, &config);
    defer conn.deinit();
    var client: MiniClient = .{ .gpa = testing.allocator };
    defer client.deinit();
    try client.handshake(&conn);
    try testing.expect(conn.handshakeComplete());
    try testing.expect(client.cv_verified);
}

fn fullHandshakeForTicket(config: *const Config, suite: CipherSuite, sni: ?[]const u8) !ClientTicket {
    var conn = Conn.init(testing.allocator, config);
    defer conn.deinit();
    var client: MiniClient = .{ .gpa = testing.allocator, .suites = &.{suite}, .sni = sni };
    defer client.deinit();
    try client.handshake(&conn);
    try testing.expect(!conn.isResumed());
    try client.pump(&conn);
    return client.received.?;
}

test "a ticket resumes the session with PSK-DHE, for every suite and across HRR" {
    var certs: TestCerts = undefined;
    try certs.load();
    for ([_]CipherSuite{ .aes_128_gcm_sha256, .chacha20_poly1305_sha256, .aes_256_gcm_sha384 }) |cs| {
        for ([_]bool{ false, true }) |hrr| {
            const config: Config = .{ .certs = &certs.entries, .ticket_key = @splat(7) };
            const ticket = try fullHandshakeForTicket(&config, cs, "localhost");

            const config2: Config = .{ .certs = &certs.entries, .ticket_key = @splat(7), .groups = if (hrr) &.{.secp256r1} else &.{.x25519} };
            var conn = Conn.init(testing.allocator, &config2);
            defer conn.deinit();
            var client: MiniClient = .{ .gpa = testing.allocator, .suites = &.{cs}, .sni = "localhost", .offer = ticket };
            defer client.deinit();
            try client.handshake(&conn);
            try testing.expect(conn.handshakeComplete());
            try testing.expect(conn.isResumed());
            try testing.expect(client.resuming);
            try testing.expectEqual(hrr, client.got_hrr);
            try testing.expectEqual(@as(usize, 0), client.leaf.items.len);

            try client.sendProtected(&conn, .application_data, "resumed");
            var buf: [16]u8 = undefined;
            try testing.expectEqualStrings("resumed", buf[0..conn.read(&buf)]);
            try conn.write("yes");
            try client.pump(&conn);
            try testing.expectEqualStrings("yes", client.app_data.items);
            // A resumed session hands out a fresh ticket too.
            try testing.expect(client.received != null);
        }
    }
}

test "tickets that do not fit fall back to a full handshake" {
    var certs: TestCerts = undefined;
    try certs.load();
    const config: Config = .{ .certs = &certs.entries, .ticket_key = @splat(7), .cipher_suites = &.{ .aes_128_gcm_sha256, .aes_256_gcm_sha384 } };
    const ticket = try fullHandshakeForTicket(&config, .aes_128_gcm_sha256, "localhost");

    const Case = struct { Config, []const CipherSuite, ?[]const u8 };
    var other_key = config;
    other_key.ticket_key = @splat(8);
    const cases = [_]Case{
        .{ other_key, &.{.aes_128_gcm_sha256}, "localhost" },
        .{ config, &.{.aes_128_gcm_sha256}, "www.example.com" },
        .{ config, &.{.aes_256_gcm_sha384}, "localhost" },
        .{ .{ .certs = &certs.entries }, &.{.aes_128_gcm_sha256}, "localhost" },
    };
    for (cases) |case| {
        var conn = Conn.init(testing.allocator, &case[0]);
        defer conn.deinit();
        var t = ticket;
        t.suite = case[1][0]; // the client binds with this suite's hash
        var client: MiniClient = .{ .gpa = testing.allocator, .suites = case[1], .sni = case[2], .offer = t };
        defer client.deinit();
        try client.handshake(&conn);
        try testing.expect(conn.handshakeComplete());
        try testing.expect(!conn.isResumed());
        try testing.expect(client.cv_verified);
    }

    // Expired: sealed an hour ago with a one-minute lifetime.
    var short = config;
    short.ticket_lifetime_s = 60;
    var sealed: [max_ticket_len]u8 = undefined;
    const blob = sealTicket(config.ticket_key.?, .{
        .suite = .aes_128_gcm_sha256,
        .issued_s = sys.realtimeSeconds() - 3600,
        .server_name = "localhost",
        .psk = ticket.psk[0..32],
    }, &sealed);
    var old: ClientTicket = .{ .suite = .aes_128_gcm_sha256, .psk = ticket.psk, .len = blob.len };
    @memcpy(old.identity[0..blob.len], blob);
    var conn = Conn.init(testing.allocator, &short);
    defer conn.deinit();
    var client: MiniClient = .{ .gpa = testing.allocator, .sni = "localhost", .offer = old };
    defer client.deinit();
    try client.handshake(&conn);
    try testing.expect(!conn.isResumed());
}

test "a bad binder is decrypt_error, a PSK without modes is missing_extension" {
    var certs: TestCerts = undefined;
    try certs.load();
    const config: Config = .{ .certs = &certs.entries, .ticket_key = @splat(7) };
    const ticket = try fullHandshakeForTicket(&config, .aes_128_gcm_sha256, null);
    {
        var conn = Conn.init(testing.allocator, &config);
        defer conn.deinit();
        var client: MiniClient = .{ .gpa = testing.allocator, .offer = ticket, .corrupt_binder = true };
        defer client.deinit();
        try testing.expectError(error.DecryptError, client.handshake(&conn));
        try expectAlert(&conn, .decrypt_error);
    }
    {
        var conn = Conn.init(testing.allocator, &config);
        defer conn.deinit();
        var client: MiniClient = .{ .gpa = testing.allocator, .offer = ticket, .omit_psk_modes = true };
        defer client.deinit();
        try testing.expectError(error.MissingExtension, client.handshake(&conn));
        try expectAlert(&conn, .missing_extension);
    }
}
