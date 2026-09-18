//! Sans-IO TLS 1.3 client connection (RFC 8446) for TLS over TCP.
//!
//! The counterpart of `tls_server`: `init` queues the ClientHello, the caller
//! flushes `pendingOutput()` to the socket, feeds `feed` the ciphertext it
//! reads, and moves plaintext with `read` / `write`. Nothing blocks, so it
//! runs from any event loop.
//!
//! Supported:
//! - TLS 1.3 only; a server that answers with an older version fails with
//!   `error.ProtocolVersion`.
//! - TLS_AES_128_GCM_SHA256, TLS_CHACHA20_POLY1305_SHA256,
//!   TLS_AES_256_GCM_SHA384.
//! - X25519 and secp256r1 key exchange, with one HelloRetryRequest (cookie
//!   echoed).
//! - Server authentication against a caller-supplied CA bundle: each link's
//!   signature and validity dates, CA:TRUE / keyCertSign / pathLenConstraint
//!   on issuers, the host name (DNS SAN or CN, or an IP SAN for an IP
//!   literal), and CertificateVerify with ECDSA P-256 / P-384, Ed25519 or
//!   RSA-PSS.
//! - SNI, ALPN, middlebox compatibility mode, KeyUpdate in both directions.
//!
//! Not supported, by design: TLS 1.2 and earlier, session resumption and
//! 0-RTT (NewSessionTicket is ignored), client certificates (a
//! CertificateRequest gets an empty Certificate), revocation checks.
const std = @import("std");
const sys = @import("../sys.zig");
const tls13 = @import("../quic/tls13.zig");
const common = @import("common.zig");

const crypto = std.crypto;
const tls = crypto.tls;
const mem = std.mem;
const Allocator = mem.Allocator;
const Certificate = crypto.Certificate;
const X25519 = crypto.dh.X25519;
const P256 = crypto.ecc.P256;
const EcdsaP256Sha256 = crypto.sign.ecdsa.EcdsaP256Sha256;

pub const CipherSuite = common.CipherSuite;
pub const Group = common.Group;

const max_plaintext = common.max_plaintext;
const max_handshake_msg = common.max_handshake_msg;
const key_update_after = common.key_update_after;
const hs_client_hello = common.hs_client_hello;
const hs_server_hello = common.hs_server_hello;
const hs_new_session_ticket = common.hs_new_session_ticket;
const hs_encrypted_extensions = common.hs_encrypted_extensions;
const hs_certificate = common.hs_certificate;
const hs_certificate_verify = common.hs_certificate_verify;
const hs_finished = common.hs_finished;
const hs_key_update = common.hs_key_update;
const hs_message_hash = common.hs_message_hash;
const hs_certificate_request: u8 = @intFromEnum(tls.HandshakeType.certificate_request);
const ct_ccs = common.ct_ccs;
const ct_alert = common.ct_alert;
const ct_handshake = common.ct_handshake;
const ct_app_data = common.ct_app_data;
const ext = common.ext;
const tls13_version = common.tls13_version;
const hashLen = common.hashLen;
const Secret = common.Secret;
const Transcript = common.Transcript;
const TrafficKeys = common.TrafficKeys;
const Buffers = common.Buffers;
const Parser = common.Parser;
const Builder = common.Builder;

pub const Config = struct {
    /// Host name sent as SNI and matched against the certificate. An IP
    /// address is matched against the certificate's IP addresses instead,
    /// and never sent as SNI (RFC 6066 §3).
    server_name: ?[]const u8 = null,
    /// Offered in this order. A server that picks none leaves `alpn()` null.
    alpn: []const []const u8 = &.{},
    /// Trust anchors for authenticating the server; requires `server_name`.
    /// Null skips every certificate check: the connection is encrypted, but
    /// to whoever answered.
    ca_bundle: ?*const Certificate.Bundle = null,
    /// Offered in this order.
    cipher_suites: []const CipherSuite = &.{ .aes_128_gcm_sha256, .chacha20_poly1305_sha256, .aes_256_gcm_sha384 },
    /// The first gets a key share in the ClientHello; the server may ask for
    /// another through HelloRetryRequest.
    groups: []const Group = &.{ .x25519, .secp256r1 },
};

pub const Error = error{
    // Protocol violations by the peer; each queues the matching alert.
    DecodeError,
    IllegalParameter,
    UnexpectedMessage,
    UnsupportedExtension,
    ProtocolVersion,
    MissingExtension,
    BadRecordMac,
    RecordOverflow,
    DecryptError,
    InternalError,
    /// The chain is malformed, breaks a constraint, or uses an algorithm we
    /// cannot check.
    BadCertificate,
    /// The chain does not lead to a certificate in `Config.ca_bundle`.
    UnknownCa,
    /// A certificate in the chain is expired or not yet valid.
    CertificateExpired,
    /// The certificate is not for `Config.server_name`.
    CertificateHostMismatch,
    /// The peer sent a fatal alert; see `peerAlert()`.
    PeerAlert,
    /// An earlier `feed` already failed; the connection is dead.
    ConnectionFailed,
    /// `write` after `close` or a failure.
    NotConnected,
    OutOfMemory,
};

/// Offered in signature_algorithms. The rsa_pkcs1 entries cover certificate
/// signatures only; TLS 1.3 never uses them for CertificateVerify.
const signature_schemes = [_]tls.SignatureScheme{
    .ecdsa_secp256r1_sha256,
    .ecdsa_secp384r1_sha384,
    .ed25519,
    .rsa_pss_rsae_sha256,
    .rsa_pss_rsae_sha384,
    .rsa_pss_rsae_sha512,
    .rsa_pkcs1_sha256,
    .rsa_pkcs1_sha384,
    .rsa_pkcs1_sha512,
};

/// Longest chain we walk, leaf included.
const max_chain = 10;

const State = enum {
    wait_server_hello,
    wait_encrypted_extensions,
    wait_certificate,
    wait_certificate_verify,
    wait_finished,
    connected,
    failed,
};

pub const Conn = struct {
    allocator: Allocator,
    config: *const Config,
    state: State = .wait_server_hello,

    suite: CipherSuite = .aes_128_gcm_sha256,
    /// Group of the key share we sent.
    group: Group = .x25519,
    key_secret: [32]u8 = @splat(0),
    session_id: [32]u8 = undefined,
    /// The first ClientHello, until the ServerHello names the transcript hash.
    client_hello: std.ArrayList(u8) = .empty,
    hrr_seen: bool = false,
    transcript: Transcript = .{ .sha256 = .init(.{}) },
    read_keys: ?TrafficKeys = null,
    write_keys: ?TrafficKeys = null,
    handshake_secret: Secret = @splat(0),
    client_hs_secret: Secret = @splat(0),
    server_hs_secret: Secret = @splat(0),
    certificate_requested: bool = false,
    leaf_key_buf: [1100]u8 = undefined,
    leaf_key_len: usize = 0,
    leaf_key_algo: Certificate.AlgorithmCategory = undefined,

    bufs: ?*Buffers = null,
    in_len: usize = 0,
    hs_in: std.ArrayList(u8) = .empty,
    hs_out: std.ArrayList(u8) = .empty,
    app_in: std.ArrayList(u8) = .empty,
    app_in_pos: usize = 0,
    out: std.ArrayList(u8) = .empty,
    out_pos: usize = 0,
    /// Written before the handshake finished; sealed once it does.
    early_app: std.ArrayList(u8) = .empty,

    ccs_sent: bool = false,
    peer_closed: bool = false,
    close_sent: bool = false,
    /// The peer asked for a KeyUpdate; one is sent before our next record.
    key_update_owed: bool = false,
    peer_alert: ?tls.Alert.Description = null,
    selected_alpn: ?[]const u8 = null,

    /// Starts a handshake: the ClientHello is in `pendingOutput()` on return.
    /// `config` must outlive the connection.
    pub fn init(allocator: Allocator, config: *const Config) Error!Conn {
        if (config.cipher_suites.len == 0 or config.groups.len == 0) return error.InternalError;
        if (config.ca_bundle != null and config.server_name == null) return error.InternalError;
        for (config.alpn) |proto| if (proto.len == 0 or proto.len > 255) return error.InternalError;
        if (config.server_name) |name| if (name.len == 0 or name.len > 255) return error.InternalError;

        var self: Conn = .{ .allocator = allocator, .config = config, .group = config.groups[0] };
        errdefer self.deinit();
        sys.randomBytes(&self.session_id);
        try self.sendClientHello(null);
        return self;
    }

    pub fn deinit(self: *Conn) void {
        const gpa = self.allocator;
        if (self.bufs) |b| {
            crypto.secureZero(u8, &b.scratch);
            gpa.destroy(b);
        }
        self.client_hello.deinit(gpa);
        self.hs_in.deinit(gpa);
        self.hs_out.deinit(gpa);
        self.app_in.deinit(gpa);
        self.out.deinit(gpa);
        crypto.secureZero(u8, self.early_app.items);
        self.early_app.deinit(gpa);
        crypto.secureZero(u8, &self.key_secret);
        crypto.secureZero(u8, &self.handshake_secret);
        crypto.secureZero(u8, &self.client_hs_secret);
        crypto.secureZero(u8, &self.server_hs_secret);
        if (self.read_keys) |*k| crypto.secureZero(u8, mem.asBytes(k));
        if (self.write_keys) |*k| crypto.secureZero(u8, mem.asBytes(k));
        self.* = undefined;
    }

    /// Feed ciphertext read from the socket. Partial records are buffered.
    /// On a protocol or certificate error the matching alert is queued in
    /// `pendingOutput()`: flush it, then close the socket.
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
    /// most 16 KiB. Before the handshake completes the data is held and sent
    /// right after our Finished.
    pub fn write(self: *Conn, data: []const u8) Error!void {
        if (self.state == .failed or self.close_sent) return error.NotConnected;
        if (self.state != .connected) return self.early_app.appendSlice(self.allocator, data);
        var records = mem.window(u8, data, max_plaintext, max_plaintext);
        while (records.next()) |record| {
            try self.maybeRotateWriteKeys();
            try self.sealRecord(.application_data, record);
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

    /// Queues a close_notify alert; data written before the handshake
    /// completed is dropped. Reading may continue until the peer answers
    /// with its own (`peerClosed()`).
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

    /// The protocol the server picked, pointing into `Config.alpn`.
    pub fn alpn(self: *const Conn) ?[]const u8 {
        return self.selected_alpn;
    }

    /// The negotiated cipher suite, once the ServerHello arrived.
    pub fn cipherSuite(self: *const Conn) ?CipherSuite {
        return if (self.read_keys != null) self.suite else null;
    }

    /// The negotiated key exchange group, once the ServerHello arrived.
    pub fn keyExchangeGroup(self: *const Conn) ?Group {
        return if (self.read_keys != null) self.group else null;
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
                // Checked before the body arrives, so a plain-HTTP server fails fast.
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
        // RFC 8446 §5.1: nothing comes between a handshake message's records.
        if (self.hs_in.items.len > 0 and record[0] != ct_handshake and
            (record[0] != ct_app_data or self.read_keys == null)) return error.UnexpectedMessage;
        switch (record[0]) {
            ct_ccs => {
                // Middlebox compat (RFC 8446 §5): the server's comes after its
                // first hello; ignored until the handshake is done.
                const in_handshake = self.state != .connected and (self.read_keys != null or self.hrr_seen);
                if (!in_handshake or payload.len != 1 or payload[0] != 1) return error.UnexpectedMessage;
            },
            ct_alert => {
                // Unprotected alerts only before the server has keys.
                if (self.read_keys != null) return error.UnexpectedMessage;
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
                if (self.read_keys == null) return error.UnexpectedMessage;
                const plain = try common.openWith(self.suite, &self.read_keys.?, record, &self.bufs.?.scratch);
                var end = plain.len;
                while (end > 0 and plain[end - 1] == 0) end -= 1;
                if (end == 0) return error.UnexpectedMessage;
                const content = plain[0 .. end - 1];
                if (self.hs_in.items.len > 0 and plain[end - 1] != ct_handshake) return error.UnexpectedMessage;
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

    fn sealRecord(self: *Conn, inner: tls.ContentType, content: []const u8) Error!void {
        const keys = &self.write_keys.?;
        if (keys.seq == std.math.maxInt(u64)) return error.InternalError;
        const bufs = try self.buffers();
        const dst = try self.reserveOutput(common.sealedLen(self.suite, content.len));
        common.sealInto(self.suite, keys, inner, content, &bufs.scratch, dst);
    }

    fn writePlainRecords(self: *Conn, content_type: u8, data: []const u8) Error!void {
        var records = mem.window(u8, data, max_plaintext, max_plaintext);
        while (records.next()) |record| {
            const dst = try self.reserveOutput(tls.record_header_len + record.len);
            // RFC 8446 §5.1: 0x0301 in the first ClientHello's record, for old middleboxes.
            const minor: u8 = if (content_type == ct_handshake and !self.hrr_seen) 1 else 3;
            dst[0..3].* = .{ content_type, 0x03, minor };
            mem.writeInt(u16, dst[3..5], @intCast(record.len), .big);
            @memcpy(dst[tls.record_header_len..], record);
        }
    }

    fn writeProtected(self: *Conn, inner: tls.ContentType, data: []const u8) Error!void {
        var records = mem.window(u8, data, max_plaintext, max_plaintext);
        while (records.next()) |record| try self.sealRecord(inner, record);
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
        const msg = [5]u8{ hs_key_update, 0, 0, 1, 0 };
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
            const keys_changed = try self.handleHandshakeMessage(msg);
            // RFC 8446 §5.1: a message may not share a record across a key change.
            if (keys_changed and pos != self.hs_in.items.len) return error.UnexpectedMessage;
        }
    }

    /// True when the message changed the read keys.
    fn handleHandshakeMessage(self: *Conn, msg: []const u8) Error!bool {
        const kind = msg[0];
        switch (self.state) {
            .wait_server_hello => {
                if (kind != hs_server_hello) return error.UnexpectedMessage;
                return self.onServerHello(msg);
            },
            .wait_encrypted_extensions => {
                if (kind != hs_encrypted_extensions) return error.UnexpectedMessage;
                try self.onEncryptedExtensions(msg);
            },
            .wait_certificate => {
                if (kind == hs_certificate_request and !self.certificate_requested) {
                    self.certificate_requested = true;
                    self.transcript.update(msg);
                } else if (kind == hs_certificate) {
                    try self.onCertificate(msg);
                } else return error.UnexpectedMessage;
            },
            .wait_certificate_verify => {
                if (kind != hs_certificate_verify) return error.UnexpectedMessage;
                try self.onCertificateVerify(msg);
            },
            .wait_finished => {
                if (kind != hs_finished) return error.UnexpectedMessage;
                try self.onServerFinished(msg);
                return true;
            },
            .connected => switch (kind) {
                hs_new_session_ticket => {},
                hs_key_update => {
                    try self.onKeyUpdate(msg[4..]);
                    return true;
                },
                else => return error.UnexpectedMessage,
            },
            .failed => return error.ConnectionFailed,
        }
        return false;
    }

    /// The host name for SNI: `server_name` unless it is an IP literal.
    fn sniName(self: *const Conn) ?[]const u8 {
        const name = self.config.server_name orelse return null;
        if (std.Io.net.IpAddress.parse(name, 0)) |_| return null else |_| return name;
    }

    fn sendClientHello(self: *Conn, cookie: ?[]const u8) Error!void {
        const cfg = self.config;
        var public_buf: [65]u8 = undefined;
        const public = try self.newKeyShare(&public_buf);

        self.hs_out.clearRetainingCapacity();
        var b: Builder = .{ .list = &self.hs_out, .gpa = self.allocator };
        try b.u8_(hs_client_hello);
        const msg = try b.begin(u24);
        try b.u16_(0x0303);
        var random: [32]u8 = undefined;
        sys.randomBytes(&random);
        try b.bytes(&random);
        // A session id makes this middlebox compatibility mode (RFC 8446 §D.4).
        try b.u8_(self.session_id.len);
        try b.bytes(&self.session_id);
        const suites = try b.begin(u16);
        for (cfg.cipher_suites) |cs| try b.u16_(@intFromEnum(cs));
        try b.end(u16, suites);
        try b.bytes(&.{ 1, 0 }); // null compression only

        const exts = try b.begin(u16);
        if (self.sniName()) |name| {
            try b.u16_(ext.server_name);
            const e = try b.begin(u16);
            const list = try b.begin(u16);
            try b.u8_(0); // host_name
            try b.u16_(@intCast(name.len));
            try b.bytes(name);
            try b.end(u16, list);
            try b.end(u16, e);
        }
        try b.u16_(ext.supported_versions);
        try b.bytes(&.{ 0, 3, 2 });
        try b.u16_(tls13_version);
        {
            try b.u16_(ext.supported_groups);
            const e = try b.begin(u16);
            const list = try b.begin(u16);
            for (cfg.groups) |g| try b.u16_(@intFromEnum(g));
            try b.end(u16, list);
            try b.end(u16, e);
        }
        {
            try b.u16_(ext.signature_algorithms);
            const e = try b.begin(u16);
            const list = try b.begin(u16);
            for (signature_schemes) |s| try b.u16_(@intFromEnum(s));
            try b.end(u16, list);
            try b.end(u16, e);
        }
        {
            try b.u16_(ext.key_share);
            const e = try b.begin(u16);
            const list = try b.begin(u16);
            try b.u16_(@intFromEnum(self.group));
            try b.u16_(@intCast(public.len));
            try b.bytes(public);
            try b.end(u16, list);
            try b.end(u16, e);
        }
        if (cfg.alpn.len > 0) {
            try b.u16_(ext.alpn);
            const e = try b.begin(u16);
            const list = try b.begin(u16);
            for (cfg.alpn) |proto| {
                try b.u8_(@intCast(proto.len));
                try b.bytes(proto);
            }
            try b.end(u16, list);
            try b.end(u16, e);
        }
        if (cookie) |c| {
            try b.u16_(ext.cookie);
            const e = try b.begin(u16);
            try b.u16_(@intCast(c.len));
            try b.bytes(c);
            try b.end(u16, e);
        }
        try b.end(u16, exts);
        try b.end(u24, msg);

        if (self.hrr_seen) {
            self.transcript.update(self.hs_out.items);
        } else {
            try self.client_hello.appendSlice(self.allocator, self.hs_out.items);
        }
        try self.writePlainRecords(ct_handshake, self.hs_out.items);
        self.hs_out.clearRetainingCapacity();
    }

    /// A fresh key pair for `self.group`; returns the public share.
    fn newKeyShare(self: *Conn, public_buf: *[65]u8) Error![]const u8 {
        var seed: [32]u8 = undefined;
        sys.randomBytes(&seed);
        defer crypto.secureZero(u8, &seed);
        switch (self.group) {
            .x25519 => {
                const kp = X25519.KeyPair.generateDeterministic(seed) catch return error.InternalError;
                self.key_secret = kp.secret_key;
                public_buf[0..32].* = kp.public_key;
                return public_buf[0..32];
            },
            .secp256r1 => {
                const kp = EcdsaP256Sha256.KeyPair.generateDeterministic(seed) catch return error.InternalError;
                self.key_secret = kp.secret_key.bytes;
                public_buf.* = kp.public_key.toUncompressedSec1();
                return public_buf[0..65];
            },
        }
    }

    fn sharedSecret(self: *Conn, server_key: []const u8) Error![32]u8 {
        defer crypto.secureZero(u8, &self.key_secret);
        switch (self.group) {
            .x25519 => {
                if (server_key.len != X25519.public_length) return error.IllegalParameter;
                return X25519.scalarmult(self.key_secret, server_key[0..32].*) catch error.IllegalParameter;
            },
            .secp256r1 => {
                // RFC 8446 §4.2.8.2: uncompressed points only.
                if (server_key.len != 65 or server_key[0] != 0x04) return error.IllegalParameter;
                const peer = P256.fromSec1(server_key) catch return error.IllegalParameter;
                const point = peer.mul(self.key_secret, .big) catch return error.IllegalParameter;
                return point.toUncompressedSec1()[1..33].*;
            },
        }
    }

    /// True for a ServerHello (read keys installed), false for a HelloRetryRequest.
    fn onServerHello(self: *Conn, msg: []const u8) Error!bool {
        var p: Parser = .{ .buf = msg[4..] };
        if (try p.int(u16) != 0x0303) return error.ProtocolVersion;
        const random = try p.take(32);
        const session_id = try p.vec(u8);
        const suite_id = try p.int(u16);
        const compression = try p.int(u8);
        const exts = try p.vec(u16);
        if (p.rest() != 0) return error.DecodeError;

        const hrr = mem.eql(u8, random, &tls.hello_retry_request_sequence);
        var version: ?u16 = null;
        var share_group: ?u16 = null;
        var share_key: ?[]const u8 = null;
        var cookie: ?[]const u8 = null;
        var e: Parser = .{ .buf = exts };
        while (e.rest() > 0) {
            const kind = try e.int(u16);
            var body: Parser = .{ .buf = try e.vec(u16) };
            if (kind == ext.supported_versions) {
                if (version != null) return error.IllegalParameter;
                version = try body.int(u16);
            } else if (kind == ext.key_share) {
                if (share_group != null) return error.IllegalParameter;
                share_group = try body.int(u16);
                if (!hrr) share_key = try body.vec(u16);
            } else if (kind == ext.cookie and hrr) {
                if (cookie != null) return error.IllegalParameter;
                cookie = try body.vec(u16);
                if (cookie.?.len == 0) return error.DecodeError;
            } else return error.UnsupportedExtension;
            if (body.rest() != 0) return error.DecodeError;
        }

        // Without supported_versions the server speaks TLS 1.2 or older.
        if (version != tls13_version) return error.ProtocolVersion;
        if (!mem.eql(u8, session_id, &self.session_id)) return error.IllegalParameter;
        if (compression != 0) return error.IllegalParameter;
        const suite = for (self.config.cipher_suites) |cs| {
            if (@intFromEnum(cs) == suite_id) break cs;
        } else return error.IllegalParameter;
        if (self.hrr_seen and suite != self.suite) return error.IllegalParameter;

        if (hrr) {
            if (self.hrr_seen) return error.UnexpectedMessage;
            self.hrr_seen = true;
            self.suite = suite;
            if (share_group) |id| {
                // RFC 8446 §4.1.4: a group we offered, and not the one we sent.
                const g = for (self.config.groups) |g| {
                    if (@intFromEnum(g) == id) break g;
                } else return error.IllegalParameter;
                if (g == self.group) return error.IllegalParameter;
                self.group = g;
            } else if (cookie == null) {
                // A retry that changes nothing.
                return error.IllegalParameter;
            }
            // RFC 8446 §4.4.1: ClientHello1 enters the transcript as its hash.
            self.transcript = .init(suite);
            var ch_hash = Transcript.init(suite);
            ch_hash.update(self.client_hello.items);
            const h = ch_hash.peek();
            const len = hashLen(suite);
            self.transcript.update(&.{ hs_message_hash, 0, 0, @intCast(len) });
            self.transcript.update(h[0..len]);
            self.transcript.update(msg);
            self.client_hello.clearAndFree(self.allocator);

            if (!self.ccs_sent) try self.writePlainRecords(ct_ccs, &.{1});
            self.ccs_sent = true;
            try self.sendClientHello(cookie);
            return false;
        }

        if (share_group != @intFromEnum(self.group)) return error.IllegalParameter;
        const key = share_key orelse return error.MissingExtension;
        self.suite = suite;
        if (!self.hrr_seen) {
            self.transcript = .init(suite);
            self.transcript.update(self.client_hello.items);
            self.client_hello.clearAndFree(self.allocator);
        }
        self.transcript.update(msg);

        var shared = try self.sharedSecret(key);
        defer crypto.secureZero(u8, &shared);
        const secrets = common.handshakeSecrets(suite, null, self.transcript.peek(), &shared);
        self.handshake_secret = secrets.handshake;
        self.client_hs_secret = secrets.client;
        self.server_hs_secret = secrets.server;
        self.read_keys = .derive(suite, secrets.server);
        self.state = .wait_encrypted_extensions;
        return true;
    }

    fn onEncryptedExtensions(self: *Conn, msg: []const u8) Error!void {
        var p: Parser = .{ .buf = msg[4..] };
        var e: Parser = .{ .buf = try p.vec(u16) };
        if (p.rest() != 0) return error.DecodeError;
        while (e.rest() > 0) {
            const kind = try e.int(u16);
            const body = try e.vec(u16);
            if (kind != ext.alpn) continue;
            if (self.selected_alpn != null) return error.IllegalParameter;
            if (self.config.alpn.len == 0) return error.UnsupportedExtension;
            // Exactly one protocol, and one we offered.
            var b: Parser = .{ .buf = body };
            var list: Parser = .{ .buf = try b.vec(u16) };
            const proto = try list.vec(u8);
            if (b.rest() != 0 or list.rest() != 0) return error.DecodeError;
            self.selected_alpn = for (self.config.alpn) |offered| {
                if (mem.eql(u8, offered, proto)) break offered;
            } else return error.IllegalParameter;
        }
        self.transcript.update(msg);
        self.state = .wait_certificate;
    }

    fn onCertificate(self: *Conn, msg: []const u8) Error!void {
        var p: Parser = .{ .buf = msg[4..] };
        if ((try p.vec(u8)).len != 0) return error.IllegalParameter;
        var list: Parser = .{ .buf = try p.vec(u24) };
        if (p.rest() != 0) return error.DecodeError;
        var chain: [max_chain][]const u8 = undefined;
        var n: usize = 0;
        while (list.rest() > 0) {
            const der = try list.vec(u24);
            _ = try list.vec(u16); // per-certificate extensions
            if (n == max_chain) return error.BadCertificate;
            chain[n] = der;
            n += 1;
        }
        // RFC 8446 §4.4.2.4.
        if (n == 0) return error.DecodeError;
        if (self.config.ca_bundle) |bundle| try self.verifyChain(chain[0..n], bundle);
        self.transcript.update(msg);
        self.state = .wait_certificate_verify;
    }

    fn verifyChain(self: *Conn, chain: []const []const u8, bundle: *const Certificate.Bundle) Error!void {
        const now = sys.realtimeSeconds();
        var child: ?Certificate.Parsed = null;
        var last_err: Error = error.UnknownCa;
        for (chain, 0..) |der, i| {
            const cert: Certificate = .{ .buffer = der, .index = 0 };
            const parsed = cert.parse() catch return error.BadCertificate;
            if (child) |c| {
                c.verify(parsed, now) catch |err| return certError(err);
                if (!tls13.issuerConstraintsOk(der, i)) return error.BadCertificate;
            } else {
                try self.checkName(parsed);
                const key = parsed.pubKey();
                if (key.len > self.leaf_key_buf.len) return error.BadCertificate;
                @memcpy(self.leaf_key_buf[0..key.len], key);
                self.leaf_key_len = key.len;
                self.leaf_key_algo = std.meta.activeTag(parsed.pub_key_algo);
            }
            // Anchored as soon as one link is signed by a trusted CA; what the
            // server sent beyond it (a cross-signed root, say) is not needed.
            if (bundle.verify(parsed, now)) |_| return else |err| last_err = certError(err);
            child = parsed;
        }
        return last_err;
    }

    fn checkName(self: *Conn, leaf: Certificate.Parsed) Error!void {
        const name = self.config.server_name.?;
        var ip = std.Io.net.IpAddress.parse(name, 0) catch {
            leaf.verifyHostName(name) catch return error.CertificateHostMismatch;
            return;
        };
        const want: []const u8 = switch (ip) {
            .ip4 => |*a| &a.bytes,
            .ip6 => |*a| &a.bytes,
        };
        // RFC 5280 §4.2.1.6: iPAddress is context tag 7, the raw octets.
        const der = Certificate.der;
        const san = leaf.subjectAltName();
        if (san.len == 0) return error.CertificateHostMismatch;
        const names = der.Element.parse(san, 0) catch return error.BadCertificate;
        var i = names.slice.start;
        while (i < names.slice.end) {
            const gn = der.Element.parse(san, i) catch return error.BadCertificate;
            i = gn.slice.end;
            if (@intFromEnum(gn.identifier.tag) == 7 and mem.eql(u8, san[gn.slice.start..gn.slice.end], want)) return;
        }
        return error.CertificateHostMismatch;
    }

    fn onCertificateVerify(self: *Conn, msg: []const u8) Error!void {
        if (self.config.ca_bundle != null) {
            var p: Parser = .{ .buf = msg[4..] };
            const scheme = try p.int(u16);
            const sig = try p.vec(u16);
            if (p.rest() != 0) return error.DecodeError;

            const context = "TLS 1.3, server CertificateVerify";
            const len = hashLen(self.suite);
            var content: [64 + context.len + 1 + 48]u8 = undefined;
            @memset(content[0..64], 0x20);
            content[64..][0..context.len].* = context.*;
            content[64 + context.len] = 0;
            const th = self.transcript.peek();
            @memcpy(content[64 + context.len + 1 ..][0..len], th[0..len]);
            tls13.verifyCertificateVerifySignature(
                self.leaf_key_buf[0..self.leaf_key_len],
                self.leaf_key_algo,
                scheme,
                sig,
                content[0 .. 64 + context.len + 1 + len],
            ) catch return error.DecryptError;
        }
        self.transcript.update(msg);
        self.state = .wait_finished;
    }

    fn onServerFinished(self: *Conn, msg: []const u8) Error!void {
        const len = hashLen(self.suite);
        if (msg.len != 4 + len) return error.DecodeError;
        const expected = common.finishedMac(self.suite, &self.server_hs_secret, self.transcript.peek());
        var got: Secret = @splat(0);
        @memcpy(got[0..len], msg[4..]);
        if (!crypto.timing_safe.eql(Secret, got, expected)) return error.DecryptError;
        self.transcript.update(msg);
        var app = common.appSecrets(self.suite, self.handshake_secret, self.transcript.peek());
        defer crypto.secureZero(u8, mem.asBytes(&app));

        // Our second flight, under the client handshake keys.
        if (!self.ccs_sent) try self.writePlainRecords(ct_ccs, &.{1});
        self.ccs_sent = true;
        self.write_keys = .derive(self.suite, self.client_hs_secret);
        self.hs_out.clearRetainingCapacity();
        var b: Builder = .{ .list = &self.hs_out, .gpa = self.allocator };
        if (self.certificate_requested) {
            // No client certificate: an empty list, context echoed (always empty here).
            try b.bytes(&.{ hs_certificate, 0, 0, 4, 0, 0, 0, 0 });
            self.transcript.update(self.hs_out.items);
        }
        const verify_data = common.finishedMac(self.suite, &self.client_hs_secret, self.transcript.peek());
        try b.u8_(hs_finished);
        try b.u24_(@intCast(len));
        try b.bytes(verify_data[0..len]);
        try self.writeProtected(.handshake, self.hs_out.items);
        crypto.secureZero(u8, self.hs_out.items);
        self.hs_out.clearRetainingCapacity();

        self.write_keys = .derive(self.suite, app.client);
        self.read_keys = .derive(self.suite, app.server);
        crypto.secureZero(u8, &self.handshake_secret);
        crypto.secureZero(u8, &self.client_hs_secret);
        crypto.secureZero(u8, &self.server_hs_secret);
        self.state = .connected;

        if (self.early_app.items.len > 0 and !self.close_sent) {
            try self.write(self.early_app.items);
            crypto.secureZero(u8, self.early_app.items);
            self.early_app.clearAndFree(self.allocator);
        }
    }

    fn onKeyUpdate(self: *Conn, body: []const u8) Error!void {
        if (body.len != 1) return error.DecodeError;
        if (body[0] > 1) return error.IllegalParameter;
        self.read_keys = self.read_keys.?.next(self.suite);
        if (body[0] == 1) self.key_update_owed = true;
    }
};

fn certError(err: anyerror) Error {
    return switch (err) {
        error.CertificateIssuerNotFound => error.UnknownCa,
        error.CertificateExpired, error.CertificateNotYetValid => error.CertificateExpired,
        else => error.BadCertificate,
    };
}

fn alertFor(err: Error) ?tls.Alert.Description {
    return switch (err) {
        error.DecodeError => .decode_error,
        error.IllegalParameter => .illegal_parameter,
        error.UnexpectedMessage => .unexpected_message,
        error.UnsupportedExtension => .unsupported_extension,
        error.ProtocolVersion => .protocol_version,
        error.MissingExtension => .missing_extension,
        error.BadRecordMac => .bad_record_mac,
        error.RecordOverflow => .record_overflow,
        error.DecryptError => .decrypt_error,
        error.BadCertificate, error.CertificateHostMismatch => .bad_certificate,
        error.UnknownCa => .unknown_ca,
        error.CertificateExpired => .certificate_expired,
        error.InternalError, error.OutOfMemory => .internal_error,
        error.PeerAlert, error.ConnectionFailed, error.NotConnected => null,
    };
}

// ─── Tests ───────────────────────────────────────────────────────────

const testing = std.testing;
const tls_server = @import("server.zig");
const test_certs = @import("test_certs.zig");

/// A client and a `tls_server` wired back to back in memory.
const Pair = struct {
    client: Conn,
    server: tls_server.Conn,

    fn init(client_config: *const Config, server_config: *const tls_server.Config) !Pair {
        return .{
            .client = try Conn.init(testing.allocator, client_config),
            .server = tls_server.Conn.init(testing.allocator, server_config),
        };
    }

    fn deinit(p: *Pair) void {
        p.client.deinit();
        p.server.deinit();
    }

    /// Moves bytes both ways until neither side has anything to send.
    fn pump(p: *Pair) !void {
        while (true) {
            const to_server = p.client.pendingOutput();
            const to_client = p.server.pendingOutput();
            if (to_server.len == 0 and to_client.len == 0) return;
            if (to_server.len > 0) {
                const n = to_server.len;
                const res = p.server.feed(to_server);
                p.client.consumeOutput(n);
                try res;
            }
            const out = p.server.pendingOutput();
            if (out.len > 0) {
                const n = out.len;
                const res = p.client.feed(out);
                p.server.consumeOutput(n);
                try res;
            }
        }
    }

    /// Everything the server received, as plaintext.
    fn serverRead(p: *Pair, buf: []u8) []u8 {
        var total: usize = 0;
        while (true) {
            const n = p.server.read(buf[total..]);
            if (n == 0) return buf[0..total];
            total += n;
        }
    }

    fn clientRead(p: *Pair, buf: []u8) []u8 {
        var total: usize = 0;
        while (true) {
            const n = p.client.read(buf[total..]);
            if (n == 0) return buf[0..total];
            total += n;
        }
    }
};

/// A bundle trusting exactly `pem`.
fn testBundle(pem: []const u8) !Certificate.Bundle {
    const gpa = testing.allocator;
    var bundle: Certificate.Bundle = .empty;
    errdefer bundle.deinit(gpa);
    var der_buf: [2048]u8 = undefined;
    const der = try tls13.parsePemCert(pem, &der_buf);
    const start: u32 = @intCast(bundle.bytes.items.len);
    try bundle.bytes.appendSlice(gpa, der);
    try bundle.parseCert(gpa, start, sys.realtimeSeconds());
    return bundle;
}

fn expectRoundTrip(p: *Pair) !void {
    const gpa = testing.allocator;
    try p.pump();
    try testing.expect(p.client.handshakeComplete());
    try testing.expect(p.server.handshakeComplete());

    const big = try gpa.alloc(u8, 40_000);
    defer gpa.free(big);
    for (big, 0..) |*b, i| b.* = @truncate(i *% 7);
    const got = try gpa.alloc(u8, big.len);
    defer gpa.free(got);

    try p.client.write(big);
    try p.pump();
    try testing.expectEqualSlices(u8, big, p.serverRead(got));

    try p.server.write(big);
    try p.pump();
    try testing.expectEqualSlices(u8, big, p.clientRead(got));
}

test "a handshake with tls_server for every suite and group, HelloRetryRequest included" {
    var certs: test_certs.TestCerts = undefined;
    try certs.load();
    for ([_]CipherSuite{ .aes_128_gcm_sha256, .chacha20_poly1305_sha256, .aes_256_gcm_sha384 }) |cs| {
        for ([_]Group{ .x25519, .secp256r1 }) |g| {
            const server_config: tls_server.Config = .{ .certs = &certs.entries, .cipher_suites = &.{cs}, .groups = &.{g} };
            const client_config: Config = .{ .server_name = "localhost" };
            var p = try Pair.init(&client_config, &server_config);
            defer p.deinit();
            try expectRoundTrip(&p);
            try testing.expectEqual(cs, p.client.cipherSuite().?);
            try testing.expectEqual(g, p.client.keyExchangeGroup().?);
            // Our first share is X25519, so a P-256-only server retries.
            try testing.expectEqual(g == .secp256r1, p.client.hrr_seen);
        }
    }
}

test "the certificate is verified against the CA bundle, P-256 and Ed25519" {
    var certs: test_certs.TestCerts = undefined;
    try certs.load();
    const server_config: tls_server.Config = .{ .certs = &certs.entries };
    const cases = [_]struct { pem: []const u8, name: []const u8 }{
        .{ .pem = test_certs.test_localhost_pem, .name = "localhost" },
        .{ .pem = test_certs.test_wildcard_pem, .name = "api.example.com" },
        .{ .pem = test_certs.test_ed25519_pem, .name = "ed.test" },
    };
    for (cases) |c| {
        var bundle = try testBundle(c.pem);
        defer bundle.deinit(testing.allocator);
        const client_config: Config = .{ .server_name = c.name, .ca_bundle = &bundle };
        var p = try Pair.init(&client_config, &server_config);
        defer p.deinit();
        try expectRoundTrip(&p);
    }
}

test "a CA-signed chain, and IP literals matched against IP SANs" {
    var der_buf: [1024]u8 = undefined;
    var key_buf: [256]u8 = undefined;
    const chain = [_][]const u8{try tls13.parsePemCert(test_certs.interop_server_pem, &der_buf)};
    const key = try tls13.extractEcPrivateKey(try tls13.parsePemPrivateKey(test_certs.interop_server_key_pem, &key_buf));
    const entries = [_]tls_server.CertEntry{.{ .server_names = &.{"localhost"}, .cert = .{ .cert_chain_der = &chain, .private_key_bytes = key } }};
    const server_config: tls_server.Config = .{ .certs = &entries };
    var bundle = try testBundle(test_certs.interop_ca_pem);
    defer bundle.deinit(testing.allocator);
    for ([_][]const u8{ "localhost", "127.0.0.1", "::1" }) |name| {
        var p = try Pair.init(&.{ .server_name = name, .ca_bundle = &bundle }, &server_config);
        defer p.deinit();
        try expectRoundTrip(&p);
    }
    var p = try Pair.init(&.{ .server_name = "127.0.0.2", .ca_bundle = &bundle }, &server_config);
    defer p.deinit();
    try testing.expectError(error.CertificateHostMismatch, p.pump());
}

test "KeyUpdate both ways, at the AES-GCM record limit" {
    var certs: test_certs.TestCerts = undefined;
    try certs.load();
    const server_config: tls_server.Config = .{ .certs = &certs.entries };
    var p = try Pair.init(&.{ .server_name = "localhost" }, &server_config);
    defer p.deinit();
    try p.pump();
    // Both ends agree on the sequence numbers, as if that many records had passed.
    p.client.write_keys.?.seq = key_update_after;
    p.server.read_keys.?.seq = key_update_after;
    p.server.write_keys.?.seq = key_update_after;
    p.client.read_keys.?.seq = key_update_after;
    try expectRoundTrip(&p);
    try testing.expect(p.client.write_keys.?.seq < 10);
    try testing.expect(p.client.read_keys.?.seq < 10);
}

fn expectRejected(client_config: *const Config, want: Error, alert: tls.Alert.Description) !void {
    var certs: test_certs.TestCerts = undefined;
    try certs.load();
    const server_config: tls_server.Config = .{ .certs = &certs.entries };
    var p = try Pair.init(client_config, &server_config);
    defer p.deinit();
    // The client fails first; the alert it queued then fails the server.
    try testing.expectError(want, p.pump());
    try testing.expect(!p.client.handshakeComplete());
    try testing.expectError(error.PeerAlert, p.server.feed(p.client.pendingOutput()));
    try testing.expectEqual(alert, p.server.peerAlert().?);
    try testing.expectError(error.ConnectionFailed, p.client.feed("x"));
}

test "a certificate from another CA is unknown_ca" {
    var bundle = try testBundle(test_certs.test_wildcard_pem);
    defer bundle.deinit(testing.allocator);
    try expectRejected(&.{ .server_name = "localhost", .ca_bundle = &bundle }, error.UnknownCa, .unknown_ca);
}

test "a certificate for another host name is bad_certificate" {
    var bundle = try testBundle(test_certs.test_localhost_pem);
    defer bundle.deinit(testing.allocator);
    // Unknown SNI: the server falls back to its localhost certificate.
    try expectRejected(&.{ .server_name = "other.test", .ca_bundle = &bundle }, error.CertificateHostMismatch, .bad_certificate);
    // An IP literal needs an IP SAN, which the test certificate lacks.
    try expectRejected(&.{ .server_name = "127.0.0.1", .ca_bundle = &bundle }, error.CertificateHostMismatch, .bad_certificate);
}

test "a verified client needs a server name" {
    var bundle = try testBundle(test_certs.test_localhost_pem);
    defer bundle.deinit(testing.allocator);
    try testing.expectError(error.InternalError, Conn.init(testing.allocator, &.{ .ca_bundle = &bundle }));
}

test "an IP literal is not sent as SNI" {
    var certs: test_certs.TestCerts = undefined;
    try certs.load();
    const server_config: tls_server.Config = .{ .certs = &certs.entries };
    inline for (.{ "127.0.0.1", "::1", "localhost" }) |name| {
        var p = try Pair.init(&.{ .server_name = name }, &server_config);
        defer p.deinit();
        try p.pump();
        try testing.expect(p.client.handshakeComplete());
        const want: ?[]const u8 = if (comptime mem.eql(u8, name, "localhost")) name else null;
        if (want) |w| try testing.expectEqualStrings(w, p.server.serverName().?) else try testing.expect(p.server.serverName() == null);
    }
}

test "ALPN: the server's pick among ours, none when it has none" {
    var certs: test_certs.TestCerts = undefined;
    try certs.load();
    const client_config: Config = .{ .server_name = "localhost", .alpn = &.{ "h2", "http/1.1" } };
    {
        const server_config: tls_server.Config = .{ .certs = &certs.entries, .alpn = &.{"http/1.1"} };
        var p = try Pair.init(&client_config, &server_config);
        defer p.deinit();
        try p.pump();
        try testing.expectEqualStrings("http/1.1", p.client.alpn().?);
    }
    {
        const server_config: tls_server.Config = .{ .certs = &certs.entries };
        var p = try Pair.init(&client_config, &server_config);
        defer p.deinit();
        try p.pump();
        try testing.expect(p.client.handshakeComplete());
        try testing.expect(p.client.alpn() == null);
    }
}

test "data written before the handshake completes follows the client Finished" {
    var certs: test_certs.TestCerts = undefined;
    try certs.load();
    const server_config: tls_server.Config = .{ .certs = &certs.entries };
    var p = try Pair.init(&.{ .server_name = "localhost" }, &server_config);
    defer p.deinit();
    try p.client.write("GET / HTTP/1.1\r\n");
    try p.client.write("\r\n");
    try p.pump();
    var buf: [64]u8 = undefined;
    try testing.expectEqualStrings("GET / HTTP/1.1\r\n\r\n", p.serverRead(&buf));
}

test "close_notify in both directions, and a closed client refuses writes" {
    var certs: test_certs.TestCerts = undefined;
    try certs.load();
    const server_config: tls_server.Config = .{ .certs = &certs.entries };
    var p = try Pair.init(&.{ .server_name = "localhost" }, &server_config);
    defer p.deinit();
    try p.pump();
    try p.server.write("bye");
    p.server.close();
    try p.pump();
    var buf: [8]u8 = undefined;
    try testing.expectEqualStrings("bye", p.clientRead(&buf));
    try testing.expect(p.client.peerClosed());
    p.client.close();
    try p.pump();
    try testing.expect(p.server.peerClosed());
    try testing.expectError(error.NotConnected, p.client.write("late"));
}

test "a tampered server record is bad_record_mac" {
    var certs: test_certs.TestCerts = undefined;
    try certs.load();
    const server_config: tls_server.Config = .{ .certs = &certs.entries };
    var p = try Pair.init(&.{ .server_name = "localhost" }, &server_config);
    defer p.deinit();
    try p.pump();
    try p.server.write("hello");
    const out = p.server.pendingOutput();
    var copy: [64]u8 = undefined;
    @memcpy(copy[0..out.len], out);
    copy[out.len - 1] ^= 1;
    try testing.expectError(error.BadRecordMac, p.client.feed(copy[0..out.len]));
}

test "a TLS 1.2 ServerHello is protocol_version" {
    var client = try Conn.init(testing.allocator, &.{ .server_name = "localhost" });
    defer client.deinit();
    // Echo our session id in a ServerHello with no supported_versions.
    var sh: [5 + 4 + 2 + 32 + 1 + 32 + 2 + 1 + 2]u8 = undefined;
    sh[0..5].* = .{ ct_handshake, 3, 3, 0, sh.len - 5 };
    sh[5..9].* = .{ hs_server_hello, 0, 0, sh.len - 9 };
    sh[9..11].* = .{ 3, 3 };
    @memset(sh[11..43], 0x42);
    sh[43] = 32;
    @memcpy(sh[44..76], &client.session_id);
    sh[76..78].* = .{ 0x13, 0x01 };
    sh[78] = 0;
    sh[79..81].* = .{ 0, 0 };
    client.consumeOutput(client.pendingOutput().len);
    try testing.expectError(error.ProtocolVersion, client.feed(&sh));
    try testing.expectEqualSlices(u8, &.{ ct_alert, 3, 3, 0, 2, 2, @intFromEnum(tls.Alert.Description.protocol_version) }, client.pendingOutput());
}

test "a server flight fed one byte at a time" {
    var certs: test_certs.TestCerts = undefined;
    try certs.load();
    const server_config: tls_server.Config = .{ .certs = &certs.entries };
    var p = try Pair.init(&.{ .server_name = "localhost" }, &server_config);
    defer p.deinit();
    try p.server.feed(p.client.pendingOutput());
    p.client.consumeOutput(p.client.pendingOutput().len);
    for (p.server.pendingOutput()) |byte| try p.client.feed(&.{byte});
    p.server.consumeOutput(p.server.pendingOutput().len);
    try testing.expect(p.client.handshakeComplete());
    try p.pump();
    try testing.expect(p.server.handshakeComplete());
}

/// Makes `dst` the client that sent `src`'s ClientHello, so it can take the reply.
fn copyHelloState(dst: *Conn, src: *const Conn) !void {
    dst.session_id = src.session_id;
    dst.key_secret = src.key_secret;
    dst.client_hello.clearRetainingCapacity();
    try dst.client_hello.appendSlice(testing.allocator, src.client_hello.items);
}

test "mutated server flights never crash the client" {
    var certs: test_certs.TestCerts = undefined;
    try certs.load();
    var bundle = try testBundle(test_certs.test_localhost_pem);
    defer bundle.deinit(testing.allocator);
    const server_config: tls_server.Config = .{ .certs = &certs.entries };
    const client_config: Config = .{ .server_name = "localhost", .ca_bundle = &bundle, .alpn = &.{"http/1.1"} };

    // One real server flight; each mutation replays it into a fresh client,
    // which fails on the Finished MAC at the latest, never on a crash.
    var p = try Pair.init(&client_config, &server_config);
    defer p.deinit();
    try p.server.feed(p.client.pendingOutput());
    const flight = try testing.allocator.dupe(u8, p.server.pendingOutput());
    defer testing.allocator.free(flight);

    {
        var client = try Conn.init(testing.allocator, &client_config);
        defer client.deinit();
        try copyHelloState(&client, &p.client);
        try client.feed(flight);
        try testing.expect(client.handshakeComplete());
    }

    var prng: std.Random.DefaultPrng = .init(0x7c11);
    const rand = prng.random();
    const mutated = try testing.allocator.dupe(u8, flight);
    defer testing.allocator.free(mutated);
    for (0..2000) |_| {
        @memcpy(mutated, flight);
        for (0..rand.intRangeAtMost(usize, 1, 4)) |_| {
            mutated[rand.uintLessThan(usize, mutated.len)] = rand.int(u8);
        }
        const cut = if (rand.boolean()) mutated.len else rand.uintLessThan(usize, mutated.len);
        var client = try Conn.init(testing.allocator, &client_config);
        defer client.deinit();
        try copyHelloState(&client, &p.client);
        client.feed(mutated[0..cut]) catch {};
    }
}
