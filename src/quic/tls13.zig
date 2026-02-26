// TLS 1.3 handshake for QUIC (RFC 8446 + RFC 9001)
//
// Supports TLS_AES_128_GCM_SHA256 (0x1301) only.
// ECDSA P-256 for signatures, X25519 for key exchange.
// No certificate chain validation (accepts self-signed).

const std = @import("std");
const crypto = std.crypto;
const quic_crypto = @import("crypto.zig");
const transport_params = @import("transport_params.zig");

const HkdfSha256 = crypto.kdf.hkdf.HkdfSha256;
const HmacSha256 = crypto.auth.hmac.sha2.HmacSha256;
const Sha256 = crypto.hash.sha2.Sha256;
const X25519 = crypto.dh.X25519;
const EcdsaP256Sha256 = crypto.sign.ecdsa.EcdsaP256Sha256;
const Aes128Gcm = crypto.aead.aes_gcm.Aes128Gcm;

// TLS 1.3 handshake message types
const MsgType = enum(u8) {
    client_hello = 1,
    server_hello = 2,
    encrypted_extensions = 8,
    certificate = 11,
    certificate_verify = 15,
    finished = 20,
};

// TLS extension types
const ExtType = enum(u16) {
    server_name = 0,
    supported_groups = 10,
    signature_algorithms = 13,
    application_layer_protocol_negotiation = 16,
    supported_versions = 43,
    key_share = 51,
    quic_transport_parameters = 57,
    _,
};

// Signature algorithm: ecdsa_secp256r1_sha256
const SIG_ECDSA_P256_SHA256: u16 = 0x0403;

// Named group: x25519
const GROUP_X25519: u16 = 0x001d;

// TLS 1.3 version
const TLS13_VERSION: u16 = 0x0304;

// Cipher suite: TLS_AES_128_GCM_SHA256
const CIPHER_SUITE_AES128_GCM_SHA256: u16 = 0x1301;

pub const EncryptionLevel = quic_crypto.EncryptionLevel;

// ─── TranscriptHash ──────────────────────────────────────────────────

pub const TranscriptHash = struct {
    state: Sha256,

    pub fn init() TranscriptHash {
        return .{ .state = Sha256.init(.{}) };
    }

    // Update with a raw TLS handshake message (type + 3-byte length + body).
    pub fn update(self: *TranscriptHash, msg: []const u8) void {
        self.state.update(msg);
    }

    pub fn current(self: *const TranscriptHash) [32]u8 {
        // Copy the state to get a snapshot without consuming it
        var copy = self.state;
        return copy.finalResult();
    }
};

// ─── KeySchedule ─────────────────────────────────────────────────────

pub const KeySchedule = struct {
    early_secret: [32]u8,
    handshake_secret: [32]u8,
    master_secret: [32]u8,
    client_handshake_traffic_secret: [32]u8,
    server_handshake_traffic_secret: [32]u8,
    client_app_traffic_secret: [32]u8,
    server_app_traffic_secret: [32]u8,
    computed_handshake: bool = false,
    computed_app: bool = false,

    pub fn init() KeySchedule {
        var ks: KeySchedule = undefined;
        ks.computed_handshake = false;
        ks.computed_app = false;
        // early_secret = HKDF-Extract(salt=0, IKM=0)
        const zero_key: [32]u8 = .{0} ** 32;
        ks.early_secret = HkdfSha256.extract(&(.{0} ** 1), &zero_key);
        return ks;
    }

    // Derive handshake secrets from the shared secret and transcript hash.
    pub fn deriveHandshakeSecrets(self: *KeySchedule, shared_secret: []const u8, transcript_hash: [32]u8) void {
        // derived1 = Derive-Secret(early_secret, "derived", Hash(""))
        var empty_hash: [32]u8 = undefined;
        Sha256.hash("", &empty_hash, .{});
        const derived1 = deriveSecret(self.early_secret, "derived", empty_hash);

        // handshake_secret = HKDF-Extract(derived1, shared_secret)
        self.handshake_secret = HkdfSha256.extract(&derived1, shared_secret);

        // c_hs_traffic = Derive-Secret(handshake_secret, "c hs traffic", transcript)
        self.client_handshake_traffic_secret = deriveSecret(self.handshake_secret, "c hs traffic", transcript_hash);

        // s_hs_traffic = Derive-Secret(handshake_secret, "s hs traffic", transcript)
        self.server_handshake_traffic_secret = deriveSecret(self.handshake_secret, "s hs traffic", transcript_hash);

        self.computed_handshake = true;
    }

    // Derive application secrets from the transcript hash after server Finished.
    pub fn deriveAppSecrets(self: *KeySchedule, transcript_hash: [32]u8) void {
        // derived2 = Derive-Secret(handshake_secret, "derived", Hash(""))
        var empty_hash: [32]u8 = undefined;
        Sha256.hash("", &empty_hash, .{});
        const derived2 = deriveSecret(self.handshake_secret, "derived", empty_hash);

        // master_secret = HKDF-Extract(derived2, 0)
        const zero_key: [32]u8 = .{0} ** 32;
        self.master_secret = HkdfSha256.extract(&derived2, &zero_key);

        // c_ap_traffic = Derive-Secret(master_secret, "c ap traffic", transcript)
        self.client_app_traffic_secret = deriveSecret(self.master_secret, "c ap traffic", transcript_hash);

        // s_ap_traffic = Derive-Secret(master_secret, "s ap traffic", transcript)
        self.server_app_traffic_secret = deriveSecret(self.master_secret, "s ap traffic", transcript_hash);

        self.computed_app = true;
    }

    // Derive QUIC Open/Seal keys from a traffic secret.
    pub fn deriveQuicKeys(traffic_secret: [32]u8) struct { key: [16]u8, iv: [12]u8, hp: [16]u8 } {
        return .{
            .key = quic_crypto.hkdfExpandLabel(traffic_secret, "quic key", "", 16),
            .iv = quic_crypto.hkdfExpandLabel(traffic_secret, "quic iv", "", 12),
            .hp = quic_crypto.hkdfExpandLabel(traffic_secret, "quic hp", "", 16),
        };
    }

    pub fn makeOpen(traffic_secret: [32]u8) quic_crypto.Open {
        const keys = deriveQuicKeys(traffic_secret);
        return .{ .key = keys.key, .nonce = keys.iv, .hp_key = keys.hp };
    }

    pub fn makeSeal(traffic_secret: [32]u8) quic_crypto.Seal {
        const keys = deriveQuicKeys(traffic_secret);
        return .{ .key = keys.key, .nonce = keys.iv, .hp_key = keys.hp };
    }

    // Compute the Finished verify_data.
    pub fn computeFinishedVerifyData(base_key: [32]u8, transcript_hash: [32]u8) [32]u8 {
        const finished_key = quic_crypto.hkdfExpandLabel(base_key, "finished", "", 32);
        var hmac: [32]u8 = undefined;
        var h = HmacSha256.init(&finished_key);
        h.update(&transcript_hash);
        h.final(&hmac);
        return hmac;
    }

    fn deriveSecret(secret: [32]u8, comptime label: []const u8, transcript_hash: [32]u8) [32]u8 {
        return quic_crypto.hkdfExpandLabel(secret, label, &transcript_hash, 32);
    }
};

// ─── TLS Config ──────────────────────────────────────────────────────

pub const TlsConfig = struct {
    cert_chain_der: []const []const u8, // DER-encoded certificates
    private_key_bytes: []const u8, // Raw ECDSA P-256 private key (32 bytes)
    alpn: []const []const u8,
    server_name: ?[]const u8 = null, // SNI (client only)
};

// ─── Handshake state machine ─────────────────────────────────────────

pub const HandshakeError = error{
    UnexpectedMessage,
    DecodeError,
    BadCertificate,
    BadCertificateVerify,
    BadFinished,
    InternalError,
    KeyScheduleError,
    NoKeyShare,
    UnsupportedVersion,
};

pub const Action = union(enum) {
    send_data: SendData,
    install_keys: InstallKeys,
    wait_for_data,
    complete,
    // Internal: signal to continue processing
    _continue,
};

pub const SendData = struct {
    level: EncryptionLevel,
    data: []const u8,
};

pub const InstallKeys = struct {
    level: EncryptionLevel,
    open: quic_crypto.Open,
    seal: quic_crypto.Seal,
};

const HandshakeState = enum {
    // Client states
    client_start,
    client_wait_server_hello,
    client_wait_encrypted_extensions,
    client_wait_certificate,
    client_wait_certificate_verify,
    client_wait_finished,
    client_send_finished,

    // Server states
    server_wait_client_hello,
    server_send_server_hello,
    server_send_encrypted_extensions,
    server_send_certificate,
    server_send_certificate_verify,
    server_send_finished,
    server_wait_client_finished,

    // Shared
    connected,
};

pub const Tls13Handshake = struct {
    state: HandshakeState,
    is_server: bool,
    transcript: TranscriptHash,
    key_schedule: KeySchedule,
    config: TlsConfig,
    local_transport_params: transport_params.TransportParams,
    peer_transport_params: ?transport_params.TransportParams = null,

    // X25519 key pair
    x25519_secret: [32]u8 = undefined,
    x25519_public: [32]u8 = undefined,
    peer_x25519_public: [32]u8 = undefined,

    // Output buffer for built messages
    out_buf: [4096]u8 = undefined,
    out_len: usize = 0,

    // Pending actions returned by step()
    pending_install_handshake: bool = false,
    pending_install_app: bool = false,
    handshake_keys_installed: bool = false,
    app_keys_installed: bool = false,

    // Buffered incoming data
    in_buf: [8192]u8 = undefined,
    in_len: usize = 0,
    in_offset: usize = 0,

    // Client random for ServerHello matching
    client_random: [32]u8 = undefined,

    // Server hello random
    server_random: [32]u8 = undefined,

    // Transcript hash at server Finished for app key derivation
    transcript_at_server_finished: [32]u8 = undefined,

    pub fn initClient(
        config: TlsConfig,
        local_tp: transport_params.TransportParams,
    ) Tls13Handshake {
        var self: Tls13Handshake = undefined;
        self.state = .client_start;
        self.is_server = false;
        self.transcript = TranscriptHash.init();
        self.key_schedule = KeySchedule.init();
        self.config = config;
        self.local_transport_params = local_tp;
        self.peer_transport_params = null;
        self.out_len = 0;
        self.in_len = 0;
        self.in_offset = 0;
        self.pending_install_handshake = false;
        self.pending_install_app = false;
        self.handshake_keys_installed = false;
        self.app_keys_installed = false;

        // Generate X25519 key pair
        crypto.random.bytes(&self.x25519_secret);
        self.x25519_public = X25519.recoverPublicKey(self.x25519_secret) catch blk: {
            // If key is bad (unlikely), regenerate
            crypto.random.bytes(&self.x25519_secret);
            break :blk X25519.recoverPublicKey(self.x25519_secret) catch unreachable;
        };

        return self;
    }

    pub fn initServer(
        config: TlsConfig,
        local_tp: transport_params.TransportParams,
    ) Tls13Handshake {
        var self: Tls13Handshake = undefined;
        self.state = .server_wait_client_hello;
        self.is_server = true;
        self.transcript = TranscriptHash.init();
        self.key_schedule = KeySchedule.init();
        self.config = config;
        self.local_transport_params = local_tp;
        self.peer_transport_params = null;
        self.out_len = 0;
        self.in_len = 0;
        self.in_offset = 0;
        self.pending_install_handshake = false;
        self.pending_install_app = false;
        self.handshake_keys_installed = false;
        self.app_keys_installed = false;

        // Generate X25519 key pair
        crypto.random.bytes(&self.x25519_secret);
        self.x25519_public = X25519.recoverPublicKey(self.x25519_secret) catch blk: {
            crypto.random.bytes(&self.x25519_secret);
            break :blk X25519.recoverPublicKey(self.x25519_secret) catch unreachable;
        };

        return self;
    }

    // Provide incoming crypto stream data to the handshake.
    pub fn provideData(self: *Tls13Handshake, data: []const u8) void {
        const available = self.in_buf.len - self.in_len;
        const copy_len = @min(data.len, available);
        @memcpy(self.in_buf[self.in_len..][0..copy_len], data[0..copy_len]);
        self.in_len += copy_len;
    }

    // Step the handshake state machine. Returns an action for the caller.
    // Call repeatedly until you get wait_for_data or complete.
    pub fn step(self: *Tls13Handshake) !Action {
        // If we need to install handshake keys, do that first
        if (self.pending_install_handshake) {
            self.pending_install_handshake = false;
            self.handshake_keys_installed = true;
            if (self.is_server) {
                return Action{ .install_keys = .{
                    .level = .handshake,
                    .open = KeySchedule.makeOpen(self.key_schedule.client_handshake_traffic_secret),
                    .seal = KeySchedule.makeSeal(self.key_schedule.server_handshake_traffic_secret),
                } };
            } else {
                return Action{ .install_keys = .{
                    .level = .handshake,
                    .open = KeySchedule.makeOpen(self.key_schedule.server_handshake_traffic_secret),
                    .seal = KeySchedule.makeSeal(self.key_schedule.client_handshake_traffic_secret),
                } };
            }
        }

        // If we need to install app keys, do that
        if (self.pending_install_app) {
            self.pending_install_app = false;
            self.app_keys_installed = true;
            if (self.is_server) {
                return Action{ .install_keys = .{
                    .level = .application,
                    .open = KeySchedule.makeOpen(self.key_schedule.client_app_traffic_secret),
                    .seal = KeySchedule.makeSeal(self.key_schedule.server_app_traffic_secret),
                } };
            } else {
                return Action{ .install_keys = .{
                    .level = .application,
                    .open = KeySchedule.makeOpen(self.key_schedule.server_app_traffic_secret),
                    .seal = KeySchedule.makeSeal(self.key_schedule.client_app_traffic_secret),
                } };
            }
        }

        switch (self.state) {
            .client_start => return self.clientBuildHello(),
            .client_wait_server_hello => return self.clientProcessServerHello(),
            .client_wait_encrypted_extensions => return self.clientProcessEncryptedExtensions(),
            .client_wait_certificate => return self.clientProcessCertificate(),
            .client_wait_certificate_verify => return self.clientProcessCertificateVerify(),
            .client_wait_finished => return self.clientProcessFinished(),
            .client_send_finished => return self.clientSendFinished(),

            .server_wait_client_hello => return self.serverProcessClientHello(),
            .server_send_server_hello => return self.serverBuildServerHello(),
            .server_send_encrypted_extensions => return self.serverBuildEncryptedExtensions(),
            .server_send_certificate => return self.serverBuildCertificate(),
            .server_send_certificate_verify => return self.serverBuildCertificateVerify(),
            .server_send_finished => return self.serverBuildFinished(),
            .server_wait_client_finished => return self.serverProcessClientFinished(),

            .connected => return .complete,
        }
    }

    pub fn isComplete(self: *const Tls13Handshake) bool {
        return self.state == .connected;
    }

    // ─── Client states ───────────────────────────────────────────────

    fn clientBuildHello(self: *Tls13Handshake) !Action {
        crypto.random.bytes(&self.client_random);

        var buf: [4096]u8 = undefined;
        const msg = buildClientHello(
            &buf,
            &self.client_random,
            &self.x25519_public,
            self.config.alpn,
            self.config.server_name,
            &self.local_transport_params,
        ) catch return error.InternalError;

        self.transcript.update(msg);

        @memcpy(self.out_buf[0..msg.len], msg);
        self.out_len = msg.len;

        self.state = .client_wait_server_hello;
        return Action{ .send_data = .{
            .level = .initial,
            .data = self.out_buf[0..self.out_len],
        } };
    }

    fn clientProcessServerHello(self: *Tls13Handshake) !Action {
        const msg = self.readHandshakeMsg() orelse return .wait_for_data;

        if (msg[0] != @intFromEnum(MsgType.server_hello)) return error.UnexpectedMessage;

        // Parse ServerHello
        const body = msg[4..]; // skip type + 3-byte length
        if (body.len < 2 + 32 + 1) return error.DecodeError;

        // legacy_version(2) + random(32) + session_id_len(1) + session_id + cipher_suite(2) + compression(1) + extensions
        var pos: usize = 0;
        pos += 2; // legacy_version = 0x0303
        @memcpy(&self.server_random, body[pos..][0..32]);
        pos += 32;

        const session_id_len = body[pos];
        pos += 1;
        pos += session_id_len; // skip session_id echo

        if (pos + 3 > body.len) return error.DecodeError;
        const cipher_suite = readU16(body[pos..]);
        pos += 2;
        if (cipher_suite != CIPHER_SUITE_AES128_GCM_SHA256) return error.UnsupportedVersion;

        pos += 1; // compression_method = 0

        // Parse extensions
        if (pos + 2 > body.len) return error.DecodeError;
        const ext_len = readU16(body[pos..]);
        pos += 2;

        var found_key_share = false;
        var ext_pos: usize = 0;
        const ext_data = body[pos..][0..ext_len];
        while (ext_pos + 4 <= ext_data.len) {
            const etype = readU16(ext_data[ext_pos..]);
            ext_pos += 2;
            const elen = readU16(ext_data[ext_pos..]);
            ext_pos += 2;

            if (etype == @intFromEnum(ExtType.key_share)) {
                // key_share: named_group(2) + key_exchange_length(2) + key_exchange(32)
                if (elen < 36) return error.DecodeError;
                const group = readU16(ext_data[ext_pos..]);
                if (group != GROUP_X25519) return error.NoKeyShare;
                const kelen = readU16(ext_data[ext_pos + 2 ..]);
                if (kelen != 32) return error.NoKeyShare;
                @memcpy(&self.peer_x25519_public, ext_data[ext_pos + 4 ..][0..32]);
                found_key_share = true;
            }
            ext_pos += elen;
        }

        if (!found_key_share) return error.NoKeyShare;

        // Update transcript with ServerHello
        self.transcript.update(msg);

        // Compute shared secret
        const shared_secret = X25519.scalarmult(self.x25519_secret, self.peer_x25519_public) catch return error.KeyScheduleError;

        // Derive handshake secrets
        const transcript_hash = self.transcript.current();
        self.key_schedule.deriveHandshakeSecrets(&shared_secret, transcript_hash);

        // Signal to install handshake keys
        self.pending_install_handshake = true;
        self.state = .client_wait_encrypted_extensions;
        return ._continue;
    }

    fn clientProcessEncryptedExtensions(self: *Tls13Handshake) !Action {
        const msg = self.readHandshakeMsg() orelse return .wait_for_data;

        if (msg[0] != @intFromEnum(MsgType.encrypted_extensions)) return error.UnexpectedMessage;

        // Parse EncryptedExtensions to extract transport params + ALPN
        self.parseEncryptedExtensions(msg[4..]) catch {};

        self.transcript.update(msg);
        self.state = .client_wait_certificate;
        return ._continue;
    }

    fn clientProcessCertificate(self: *Tls13Handshake) !Action {
        const msg = self.readHandshakeMsg() orelse return .wait_for_data;

        if (msg[0] != @intFromEnum(MsgType.certificate)) return error.UnexpectedMessage;

        // We don't validate the certificate chain - just record in transcript
        // In a production implementation, you would verify the chain here.
        self.transcript.update(msg);
        self.state = .client_wait_certificate_verify;
        return ._continue;
    }

    fn clientProcessCertificateVerify(self: *Tls13Handshake) !Action {
        const msg = self.readHandshakeMsg() orelse return .wait_for_data;

        if (msg[0] != @intFromEnum(MsgType.certificate_verify)) return error.UnexpectedMessage;

        // We skip actual signature verification for now (no cert validation)
        self.transcript.update(msg);
        self.state = .client_wait_finished;
        return ._continue;
    }

    fn clientProcessFinished(self: *Tls13Handshake) !Action {
        const msg = self.readHandshakeMsg() orelse return .wait_for_data;

        if (msg[0] != @intFromEnum(MsgType.finished)) return error.UnexpectedMessage;

        const body = msg[4..];
        if (body.len != 32) return error.BadFinished;

        // Verify server Finished
        const transcript_hash = self.transcript.current();
        const expected = KeySchedule.computeFinishedVerifyData(
            self.key_schedule.server_handshake_traffic_secret,
            transcript_hash,
        );

        if (!std.mem.eql(u8, body, &expected)) return error.BadFinished;

        // Update transcript with server Finished
        self.transcript.update(msg);

        // Save transcript hash for app key derivation
        self.transcript_at_server_finished = self.transcript.current();

        // Derive application secrets
        self.key_schedule.deriveAppSecrets(self.transcript_at_server_finished);
        self.pending_install_app = true;

        self.state = .client_send_finished;
        return ._continue;
    }

    fn clientSendFinished(self: *Tls13Handshake) !Action {
        // Compute client Finished
        const transcript_hash = self.transcript.current();
        const verify_data = KeySchedule.computeFinishedVerifyData(
            self.key_schedule.client_handshake_traffic_secret,
            transcript_hash,
        );

        // Build Finished message: type(1) + length(3) + verify_data(32)
        var msg: [36]u8 = undefined;
        msg[0] = @intFromEnum(MsgType.finished);
        msg[1] = 0;
        msg[2] = 0;
        msg[3] = 32;
        @memcpy(msg[4..][0..32], &verify_data);

        self.transcript.update(&msg);

        @memcpy(self.out_buf[0..36], &msg);
        self.out_len = 36;

        self.state = .connected;
        return Action{ .send_data = .{
            .level = .handshake,
            .data = self.out_buf[0..self.out_len],
        } };
    }

    // ─── Server states ───────────────────────────────────────────────

    fn serverProcessClientHello(self: *Tls13Handshake) !Action {
        const msg = self.readHandshakeMsg() orelse return .wait_for_data;

        if (msg[0] != @intFromEnum(MsgType.client_hello)) return error.UnexpectedMessage;

        const body = msg[4..];
        if (body.len < 2 + 32 + 1) return error.DecodeError;

        var pos: usize = 0;
        pos += 2; // legacy_version
        @memcpy(&self.client_random, body[pos..][0..32]);
        pos += 32;

        const session_id_len = body[pos];
        pos += 1;
        pos += session_id_len; // skip session_id

        // Cipher suites
        if (pos + 2 > body.len) return error.DecodeError;
        const cs_len = readU16(body[pos..]);
        pos += 2;
        pos += cs_len; // skip cipher suites

        // Compression methods
        if (pos >= body.len) return error.DecodeError;
        const cm_len = body[pos];
        pos += 1;
        pos += cm_len;

        // Extensions
        if (pos + 2 > body.len) return error.DecodeError;
        const ext_len = readU16(body[pos..]);
        pos += 2;

        var found_key_share = false;
        var ext_pos: usize = 0;
        const ext_data = body[pos..][0..@min(ext_len, body.len - pos)];
        while (ext_pos + 4 <= ext_data.len) {
            const etype = readU16(ext_data[ext_pos..]);
            ext_pos += 2;
            const elen = readU16(ext_data[ext_pos..]);
            ext_pos += 2;

            if (ext_pos + elen > ext_data.len) break;

            if (etype == @intFromEnum(ExtType.key_share)) {
                // client_shares_len(2) + [named_group(2) + key_len(2) + key(32)]
                if (elen >= 2) {
                    var share_pos: usize = 2; // skip client_shares_len
                    while (share_pos + 4 <= elen) {
                        const group = readU16(ext_data[ext_pos + share_pos ..]);
                        const kelen = readU16(ext_data[ext_pos + share_pos + 2 ..]);
                        share_pos += 4;
                        if (group == GROUP_X25519 and kelen == 32 and share_pos + 32 <= elen) {
                            @memcpy(&self.peer_x25519_public, ext_data[ext_pos + share_pos ..][0..32]);
                            found_key_share = true;
                            break;
                        }
                        share_pos += kelen;
                    }
                }
            } else if (etype == @intFromEnum(ExtType.quic_transport_parameters)) {
                const tp_data = ext_data[ext_pos..][0..elen];
                self.peer_transport_params = transport_params.TransportParams.decode(tp_data) catch null;
            }
            ext_pos += elen;
        }

        if (!found_key_share) return error.NoKeyShare;

        // Update transcript with ClientHello
        self.transcript.update(msg);

        self.state = .server_send_server_hello;
        return ._continue;
    }

    fn serverBuildServerHello(self: *Tls13Handshake) !Action {
        crypto.random.bytes(&self.server_random);

        var buf: [512]u8 = undefined;
        const msg = buildServerHello(
            &buf,
            &self.server_random,
            &self.x25519_public,
            &self.client_random, // echo session_id as empty (we use 0-len)
        ) catch return error.InternalError;

        self.transcript.update(msg);

        // Compute shared secret
        const shared_secret = X25519.scalarmult(self.x25519_secret, self.peer_x25519_public) catch return error.KeyScheduleError;

        // Derive handshake secrets
        const transcript_hash = self.transcript.current();
        self.key_schedule.deriveHandshakeSecrets(&shared_secret, transcript_hash);

        @memcpy(self.out_buf[0..msg.len], msg);
        self.out_len = msg.len;

        // Signal to install handshake keys, then send EE at handshake level
        self.pending_install_handshake = true;
        self.state = .server_send_encrypted_extensions;
        return Action{ .send_data = .{
            .level = .initial,
            .data = self.out_buf[0..self.out_len],
        } };
    }

    fn serverBuildEncryptedExtensions(self: *Tls13Handshake) !Action {
        var buf: [1024]u8 = undefined;
        const msg = buildEncryptedExtensions(
            &buf,
            self.config.alpn,
            &self.local_transport_params,
        ) catch return error.InternalError;

        self.transcript.update(msg);

        @memcpy(self.out_buf[0..msg.len], msg);
        self.out_len = msg.len;

        self.state = .server_send_certificate;
        return Action{ .send_data = .{
            .level = .handshake,
            .data = self.out_buf[0..self.out_len],
        } };
    }

    fn serverBuildCertificate(self: *Tls13Handshake) !Action {
        var buf: [4096]u8 = undefined;
        const msg = buildCertificate(&buf, self.config.cert_chain_der) catch return error.InternalError;

        self.transcript.update(msg);

        @memcpy(self.out_buf[0..msg.len], msg);
        self.out_len = msg.len;

        self.state = .server_send_certificate_verify;
        return Action{ .send_data = .{
            .level = .handshake,
            .data = self.out_buf[0..self.out_len],
        } };
    }

    fn serverBuildCertificateVerify(self: *Tls13Handshake) !Action {
        const transcript_hash = self.transcript.current();

        var buf: [512]u8 = undefined;
        const msg = buildCertificateVerify(
            &buf,
            transcript_hash,
            self.config.private_key_bytes,
            true, // is_server
        ) catch return error.InternalError;

        self.transcript.update(msg);

        @memcpy(self.out_buf[0..msg.len], msg);
        self.out_len = msg.len;

        self.state = .server_send_finished;
        return Action{ .send_data = .{
            .level = .handshake,
            .data = self.out_buf[0..self.out_len],
        } };
    }

    fn serverBuildFinished(self: *Tls13Handshake) !Action {
        const transcript_hash = self.transcript.current();
        const verify_data = KeySchedule.computeFinishedVerifyData(
            self.key_schedule.server_handshake_traffic_secret,
            transcript_hash,
        );

        var msg: [36]u8 = undefined;
        msg[0] = @intFromEnum(MsgType.finished);
        msg[1] = 0;
        msg[2] = 0;
        msg[3] = 32;
        @memcpy(msg[4..][0..32], &verify_data);

        self.transcript.update(&msg);

        // Save transcript for app keys
        self.transcript_at_server_finished = self.transcript.current();
        self.key_schedule.deriveAppSecrets(self.transcript_at_server_finished);
        self.pending_install_app = true;

        @memcpy(self.out_buf[0..36], &msg);
        self.out_len = 36;

        self.state = .server_wait_client_finished;
        return Action{ .send_data = .{
            .level = .handshake,
            .data = self.out_buf[0..self.out_len],
        } };
    }

    fn serverProcessClientFinished(self: *Tls13Handshake) !Action {
        const msg = self.readHandshakeMsg() orelse return .wait_for_data;

        if (msg[0] != @intFromEnum(MsgType.finished)) return error.UnexpectedMessage;

        const body = msg[4..];
        if (body.len != 32) return error.BadFinished;

        // Verify client Finished
        const transcript_hash = self.transcript.current();
        const expected = KeySchedule.computeFinishedVerifyData(
            self.key_schedule.client_handshake_traffic_secret,
            transcript_hash,
        );

        if (!std.mem.eql(u8, body, &expected)) return error.BadFinished;

        self.transcript.update(msg);
        self.state = .connected;
        return .complete;
    }

    // ─── Helpers ─────────────────────────────────────────────────────

    // Try to read a complete handshake message from the input buffer.
    // Returns the full message (type + 3-byte length + body) or null.
    fn readHandshakeMsg(self: *Tls13Handshake) ?[]const u8 {
        const available = self.in_len - self.in_offset;
        if (available < 4) return null;

        const msg_len = (@as(usize, self.in_buf[self.in_offset + 1]) << 16) |
            (@as(usize, self.in_buf[self.in_offset + 2]) << 8) |
            @as(usize, self.in_buf[self.in_offset + 3]);

        const total_len = 4 + msg_len;
        if (available < total_len) return null;

        const msg = self.in_buf[self.in_offset..][0..total_len];
        self.in_offset += total_len;

        // Compact the buffer if we've consumed everything
        if (self.in_offset == self.in_len) {
            self.in_offset = 0;
            self.in_len = 0;
        }

        return msg;
    }

    fn parseEncryptedExtensions(self: *Tls13Handshake, body: []const u8) !void {
        if (body.len < 2) return;
        const ext_len = readU16(body[0..]);
        var ext_pos: usize = 0;
        const ext_data = body[2..][0..@min(ext_len, body.len - 2)];
        while (ext_pos + 4 <= ext_data.len) {
            const etype = readU16(ext_data[ext_pos..]);
            ext_pos += 2;
            const elen = readU16(ext_data[ext_pos..]);
            ext_pos += 2;
            if (ext_pos + elen > ext_data.len) break;

            if (etype == @intFromEnum(ExtType.quic_transport_parameters)) {
                const tp_data = ext_data[ext_pos..][0..elen];
                self.peer_transport_params = transport_params.TransportParams.decode(tp_data) catch null;
            }
            ext_pos += elen;
        }
    }
};

// ─── Message builders ────────────────────────────────────────────────

fn buildClientHello(
    buf: []u8,
    client_random: *const [32]u8,
    x25519_pub: *const [32]u8,
    alpn_list: []const []const u8,
    server_name: ?[]const u8,
    local_tp: *const transport_params.TransportParams,
) ![]const u8 {
    // Build the body first, then wrap with type + length
    var pos: usize = 4; // reserve space for type + 3-byte length

    // legacy_version = 0x0303
    buf[pos] = 0x03;
    buf[pos + 1] = 0x03;
    pos += 2;

    // random
    @memcpy(buf[pos..][0..32], client_random);
    pos += 32;

    // session_id (empty, but TLS 1.3 middlebox compat says 32 bytes)
    // For QUIC, we use empty session_id per RFC 9001 Section 4.1.2
    buf[pos] = 0; // session_id_len = 0
    pos += 1;

    // cipher_suites: 2 bytes length + TLS_AES_128_GCM_SHA256
    writeU16(buf[pos..], 2);
    pos += 2;
    writeU16(buf[pos..], CIPHER_SUITE_AES128_GCM_SHA256);
    pos += 2;

    // compression_methods: 1 byte length + null compression
    buf[pos] = 1;
    pos += 1;
    buf[pos] = 0;
    pos += 1;

    // Extensions
    const ext_start = pos;
    pos += 2; // extensions length placeholder

    // supported_versions extension
    pos = writeExtHeader(buf, pos, @intFromEnum(ExtType.supported_versions), 3);
    buf[pos] = 2; // list length
    pos += 1;
    writeU16(buf[pos..], TLS13_VERSION);
    pos += 2;

    // key_share extension (X25519)
    pos = writeExtHeader(buf, pos, @intFromEnum(ExtType.key_share), 2 + 2 + 2 + 32);
    writeU16(buf[pos..], 2 + 2 + 32); // client_shares length
    pos += 2;
    writeU16(buf[pos..], GROUP_X25519);
    pos += 2;
    writeU16(buf[pos..], 32); // key_exchange length
    pos += 2;
    @memcpy(buf[pos..][0..32], x25519_pub);
    pos += 32;

    // signature_algorithms extension
    pos = writeExtHeader(buf, pos, @intFromEnum(ExtType.signature_algorithms), 2 + 2);
    writeU16(buf[pos..], 2); // list length
    pos += 2;
    writeU16(buf[pos..], SIG_ECDSA_P256_SHA256);
    pos += 2;

    // supported_groups extension
    pos = writeExtHeader(buf, pos, @intFromEnum(ExtType.supported_groups), 2 + 2);
    writeU16(buf[pos..], 2); // list length
    pos += 2;
    writeU16(buf[pos..], GROUP_X25519);
    pos += 2;

    // SNI extension
    if (server_name) |sni| {
        const sni_ext_len = 2 + 1 + 2 + sni.len; // server_name_list_len + type + host_name_len + host_name
        pos = writeExtHeader(buf, pos, @intFromEnum(ExtType.server_name), sni_ext_len);
        const list_len: u16 = @intCast(1 + 2 + sni.len);
        writeU16(buf[pos..], list_len);
        pos += 2;
        buf[pos] = 0; // host_name type
        pos += 1;
        writeU16(buf[pos..], @intCast(sni.len));
        pos += 2;
        @memcpy(buf[pos..][0..sni.len], sni);
        pos += sni.len;
    }

    // ALPN extension
    if (alpn_list.len > 0) {
        var alpn_total: usize = 0;
        for (alpn_list) |proto| {
            alpn_total += 1 + proto.len;
        }
        pos = writeExtHeader(buf, pos, @intFromEnum(ExtType.application_layer_protocol_negotiation), 2 + alpn_total);
        writeU16(buf[pos..], @intCast(alpn_total));
        pos += 2;
        for (alpn_list) |proto| {
            buf[pos] = @intCast(proto.len);
            pos += 1;
            @memcpy(buf[pos..][0..proto.len], proto);
            pos += proto.len;
        }
    }

    // QUIC transport parameters extension
    var tp_buf_arr: [256]u8 = undefined;
    var tp_fbs = std.io.fixedBufferStream(&tp_buf_arr);
    try local_tp.encode(tp_fbs.writer());
    const tp_data = tp_fbs.getWritten();
    pos = writeExtHeader(buf, pos, @intFromEnum(ExtType.quic_transport_parameters), tp_data.len);
    @memcpy(buf[pos..][0..tp_data.len], tp_data);
    pos += tp_data.len;

    // Fill in extensions length
    const ext_len: u16 = @intCast(pos - ext_start - 2);
    writeU16(buf[ext_start..], ext_len);

    // Fill in message header
    const body_len: u24 = @intCast(pos - 4);
    buf[0] = @intFromEnum(MsgType.client_hello);
    buf[1] = @intCast(body_len >> 16);
    buf[2] = @intCast((body_len >> 8) & 0xff);
    buf[3] = @intCast(body_len & 0xff);

    return buf[0..pos];
}

fn buildServerHello(
    buf: []u8,
    server_random: *const [32]u8,
    x25519_pub: *const [32]u8,
    _: *const [32]u8, // client_random (unused, was for session_id echo)
) ![]const u8 {
    var pos: usize = 4; // reserve for header

    // legacy_version = 0x0303
    buf[pos] = 0x03;
    buf[pos + 1] = 0x03;
    pos += 2;

    // random
    @memcpy(buf[pos..][0..32], server_random);
    pos += 32;

    // session_id (empty for QUIC)
    buf[pos] = 0;
    pos += 1;

    // cipher_suite
    writeU16(buf[pos..], CIPHER_SUITE_AES128_GCM_SHA256);
    pos += 2;

    // compression_method
    buf[pos] = 0;
    pos += 1;

    // Extensions
    const ext_start = pos;
    pos += 2; // extensions length placeholder

    // supported_versions
    pos = writeExtHeader(buf, pos, @intFromEnum(ExtType.supported_versions), 2);
    writeU16(buf[pos..], TLS13_VERSION);
    pos += 2;

    // key_share (server's key)
    pos = writeExtHeader(buf, pos, @intFromEnum(ExtType.key_share), 2 + 2 + 32);
    writeU16(buf[pos..], GROUP_X25519);
    pos += 2;
    writeU16(buf[pos..], 32);
    pos += 2;
    @memcpy(buf[pos..][0..32], x25519_pub);
    pos += 32;

    // Fill in extensions length
    const ext_len: u16 = @intCast(pos - ext_start - 2);
    writeU16(buf[ext_start..], ext_len);

    // Fill in message header
    const body_len: u24 = @intCast(pos - 4);
    buf[0] = @intFromEnum(MsgType.server_hello);
    buf[1] = @intCast(body_len >> 16);
    buf[2] = @intCast((body_len >> 8) & 0xff);
    buf[3] = @intCast(body_len & 0xff);

    return buf[0..pos];
}

fn buildEncryptedExtensions(
    buf: []u8,
    alpn_list: []const []const u8,
    local_tp: *const transport_params.TransportParams,
) ![]const u8 {
    var pos: usize = 4; // reserve for header

    // Extensions list
    const ext_list_start = pos;
    pos += 2; // extensions length placeholder

    // ALPN
    if (alpn_list.len > 0) {
        var alpn_total: usize = 0;
        for (alpn_list) |proto| {
            alpn_total += 1 + proto.len;
        }
        pos = writeExtHeader(buf, pos, @intFromEnum(ExtType.application_layer_protocol_negotiation), 2 + alpn_total);
        writeU16(buf[pos..], @intCast(alpn_total));
        pos += 2;
        for (alpn_list) |proto| {
            buf[pos] = @intCast(proto.len);
            pos += 1;
            @memcpy(buf[pos..][0..proto.len], proto);
            pos += proto.len;
        }
    }

    // QUIC transport parameters
    var tp_buf_arr: [256]u8 = undefined;
    var tp_fbs = std.io.fixedBufferStream(&tp_buf_arr);
    try local_tp.encode(tp_fbs.writer());
    const tp_data = tp_fbs.getWritten();
    pos = writeExtHeader(buf, pos, @intFromEnum(ExtType.quic_transport_parameters), tp_data.len);
    @memcpy(buf[pos..][0..tp_data.len], tp_data);
    pos += tp_data.len;

    // Fill in extensions length
    const ext_len: u16 = @intCast(pos - ext_list_start - 2);
    writeU16(buf[ext_list_start..], ext_len);

    // Fill in message header
    const body_len: u24 = @intCast(pos - 4);
    buf[0] = @intFromEnum(MsgType.encrypted_extensions);
    buf[1] = @intCast(body_len >> 16);
    buf[2] = @intCast((body_len >> 8) & 0xff);
    buf[3] = @intCast(body_len & 0xff);

    return buf[0..pos];
}

fn buildCertificate(buf: []u8, cert_chain: []const []const u8) ![]const u8 {
    var pos: usize = 4; // reserve for header

    // certificate_request_context (empty for server)
    buf[pos] = 0;
    pos += 1;

    // certificate_list length placeholder
    const cert_list_start = pos;
    pos += 3; // 3-byte length

    for (cert_chain) |cert_der| {
        // cert_data length (3 bytes)
        const cert_len: u24 = @intCast(cert_der.len);
        buf[pos] = @intCast(cert_len >> 16);
        buf[pos + 1] = @intCast((cert_len >> 8) & 0xff);
        buf[pos + 2] = @intCast(cert_len & 0xff);
        pos += 3;

        // cert_data
        @memcpy(buf[pos..][0..cert_der.len], cert_der);
        pos += cert_der.len;

        // extensions (empty)
        writeU16(buf[pos..], 0);
        pos += 2;
    }

    // Fill in certificate_list length
    const cert_list_len: u24 = @intCast(pos - cert_list_start - 3);
    buf[cert_list_start] = @intCast(cert_list_len >> 16);
    buf[cert_list_start + 1] = @intCast((cert_list_len >> 8) & 0xff);
    buf[cert_list_start + 2] = @intCast(cert_list_len & 0xff);

    // Fill in message header
    const body_len: u24 = @intCast(pos - 4);
    buf[0] = @intFromEnum(MsgType.certificate);
    buf[1] = @intCast(body_len >> 16);
    buf[2] = @intCast((body_len >> 8) & 0xff);
    buf[3] = @intCast(body_len & 0xff);

    return buf[0..pos];
}

fn buildCertificateVerify(
    buf: []u8,
    transcript_hash: [32]u8,
    private_key_bytes: []const u8,
    is_server: bool,
) ![]const u8 {
    // Build the content to sign:
    // 0x20 repeated 64 times + context_string + 0x00 + transcript_hash
    var sign_content: [64 + 34 + 1 + 32]u8 = undefined;
    @memset(sign_content[0..64], 0x20);
    const context_str = if (is_server) "TLS 1.3, server CertificateVerify" else "TLS 1.3, client CertificateVerify";
    @memcpy(sign_content[64..][0..33], context_str);
    sign_content[64 + 33] = 0x00;
    @memcpy(sign_content[64 + 34 ..][0..32], &transcript_hash);

    // Sign with ECDSA P-256
    if (private_key_bytes.len != 32) return error.InternalError;
    const secret_key = EcdsaP256Sha256.SecretKey.fromBytes(private_key_bytes[0..32].*) catch return error.InternalError;
    const key_pair = EcdsaP256Sha256.KeyPair.fromSecretKey(secret_key) catch return error.InternalError;

    const sig = key_pair.sign(&sign_content, null) catch return error.InternalError;
    var der_buf: [EcdsaP256Sha256.Signature.der_encoded_length_max]u8 = undefined;
    const sig_bytes = sig.toDer(&der_buf);

    // Build message
    var pos: usize = 4; // reserve for header

    // signature_algorithm
    writeU16(buf[pos..], SIG_ECDSA_P256_SHA256);
    pos += 2;

    // signature length + signature
    writeU16(buf[pos..], @intCast(sig_bytes.len));
    pos += 2;
    @memcpy(buf[pos..][0..sig_bytes.len], sig_bytes);
    pos += sig_bytes.len;

    // Fill in message header
    const body_len: u24 = @intCast(pos - 4);
    buf[0] = @intFromEnum(MsgType.certificate_verify);
    buf[1] = @intCast(body_len >> 16);
    buf[2] = @intCast((body_len >> 8) & 0xff);
    buf[3] = @intCast(body_len & 0xff);

    return buf[0..pos];
}

// ─── Utility functions ───────────────────────────────────────────────

fn writeExtHeader(buf: []u8, pos: usize, ext_type: u16, ext_len: usize) usize {
    writeU16(buf[pos..], ext_type);
    writeU16(buf[pos + 2 ..], @intCast(ext_len));
    return pos + 4;
}

fn readU16(data: []const u8) u16 {
    return (@as(u16, data[0]) << 8) | @as(u16, data[1]);
}

fn writeU16(buf: []u8, val: u16) void {
    buf[0] = @intCast(val >> 8);
    buf[1] = @intCast(val & 0xff);
}

// ─── Minimal PEM parser ──────────────────────────────────────────────

pub fn parsePemCert(pem_data: []const u8, out: []u8) ![]const u8 {
    return parsePemSection(pem_data, "CERTIFICATE", out);
}

pub fn parsePemPrivateKey(pem_data: []const u8, out: []u8) ![]const u8 {
    // Try EC PRIVATE KEY first, then PRIVATE KEY (PKCS#8)
    return parsePemSection(pem_data, "EC PRIVATE KEY", out) catch
        parsePemSection(pem_data, "PRIVATE KEY", out);
}

fn parsePemSection(pem_data: []const u8, comptime label: []const u8, out: []u8) ![]const u8 {
    const begin_marker = "-----BEGIN " ++ label ++ "-----";
    const end_marker = "-----END " ++ label ++ "-----";

    const begin_idx = std.mem.indexOf(u8, pem_data, begin_marker) orelse return error.DecodeError;
    const after_begin = begin_idx + begin_marker.len;
    const end_idx = std.mem.indexOf(u8, pem_data[after_begin..], end_marker) orelse return error.DecodeError;
    const base64_data = pem_data[after_begin..][0..end_idx];

    // Strip whitespace and decode base64
    var clean: [8192]u8 = undefined;
    var clean_len: usize = 0;
    for (base64_data) |c| {
        if (c != '\n' and c != '\r' and c != ' ' and c != '\t') {
            clean[clean_len] = c;
            clean_len += 1;
        }
    }

    const decoded_len = std.base64.standard.Decoder.calcSizeForSlice(clean[0..clean_len]) catch return error.DecodeError;
    if (decoded_len > out.len) return error.DecodeError;
    std.base64.standard.Decoder.decode(out[0..decoded_len], clean[0..clean_len]) catch return error.DecodeError;
    return out[0..decoded_len];
}

// Extract the 32-byte raw private key from a DER-encoded EC private key.
// RFC 5915: ECPrivateKey ::= SEQUENCE { version, privateKey, ... }
pub fn extractEcPrivateKey(der: []const u8) ![]const u8 {
    // Simple DER walk: SEQUENCE -> version INTEGER -> OCTET STRING (the key)
    if (der.len < 2) return error.DecodeError;
    if (der[0] != 0x30) return error.DecodeError; // SEQUENCE

    var pos: usize = 2;
    // skip length byte(s)
    if (der[1] & 0x80 != 0) {
        const num_len_bytes = der[1] & 0x7f;
        pos += num_len_bytes;
    }

    // version: INTEGER
    if (pos >= der.len or der[pos] != 0x02) return error.DecodeError;
    pos += 1;
    const ver_len = der[pos];
    pos += 1 + ver_len;

    // privateKey: OCTET STRING
    if (pos >= der.len or der[pos] != 0x04) return error.DecodeError;
    pos += 1;
    const key_len = der[pos];
    pos += 1;
    if (key_len != 32) return error.DecodeError;
    if (pos + 32 > der.len) return error.DecodeError;
    return der[pos..][0..32];
}

// Extract the 32-byte raw private key from a PKCS#8 DER-encoded private key.
// PKCS#8: SEQUENCE { version, AlgorithmIdentifier, OCTET STRING { ECPrivateKey } }
pub fn extractPkcs8EcPrivateKey(der: []const u8) ![]const u8 {
    // Walk the outer SEQUENCE
    if (der.len < 2 or der[0] != 0x30) return error.DecodeError;

    var pos: usize = 2;
    if (der[1] & 0x80 != 0) {
        pos += der[1] & 0x7f;
    }

    // Skip version INTEGER
    if (pos >= der.len or der[pos] != 0x02) return error.DecodeError;
    pos += 1;
    const ver_len = der[pos];
    pos += 1 + ver_len;

    // Skip AlgorithmIdentifier SEQUENCE
    if (pos >= der.len or der[pos] != 0x30) return error.DecodeError;
    pos += 1;
    const alg_len = der[pos];
    pos += 1 + alg_len;

    // OCTET STRING containing ECPrivateKey
    if (pos >= der.len or der[pos] != 0x04) return error.DecodeError;
    pos += 1;
    var octet_len: usize = der[pos];
    pos += 1;
    if (octet_len & 0x80 != 0) {
        const num = octet_len & 0x7f;
        octet_len = 0;
        for (0..num) |i| {
            octet_len = (octet_len << 8) | der[pos + i];
        }
        pos += num;
    }

    // The contained value is an ECPrivateKey
    return extractEcPrivateKey(der[pos..][0..octet_len]);
}

// ─── Tests ───────────────────────────────────────────────────────────

test "TranscriptHash: basic usage" {
    var th = TranscriptHash.init();

    const msg1 = [_]u8{ 0x01, 0x00, 0x00, 0x03, 0xaa, 0xbb, 0xcc };
    th.update(&msg1);

    const h1 = th.current();
    const h2 = th.current();
    // Same snapshot should give same hash
    try std.testing.expectEqualSlices(u8, &h1, &h2);

    // After more data, hash should change
    th.update(&msg1);
    const h3 = th.current();
    try std.testing.expect(!std.mem.eql(u8, &h1, &h3));
}

test "KeySchedule: derive-secret produces known output for zeros" {
    // Verify early_secret matches the known value
    var ks = KeySchedule.init();
    const zero_key: [32]u8 = .{0} ** 32;

    // early_secret should be HKDF-Extract(salt=0x00, IKM=0x00*32)
    const expected_early = HkdfSha256.extract(&(.{0} ** 1), &zero_key);
    try std.testing.expectEqualSlices(u8, &expected_early, &ks.early_secret);

    // Derive handshake with a fake shared secret and transcript
    var fake_shared: [32]u8 = undefined;
    @memset(&fake_shared, 0x42);
    var fake_transcript: [32]u8 = undefined;
    @memset(&fake_transcript, 0x01);
    ks.deriveHandshakeSecrets(&fake_shared, fake_transcript);

    // Verify secrets are not all-zero (sanity check)
    try std.testing.expect(!std.mem.eql(u8, &ks.client_handshake_traffic_secret, &(.{0} ** 32)));
    try std.testing.expect(!std.mem.eql(u8, &ks.server_handshake_traffic_secret, &(.{0} ** 32)));

    // Derive app secrets
    ks.deriveAppSecrets(fake_transcript);
    try std.testing.expect(!std.mem.eql(u8, &ks.client_app_traffic_secret, &(.{0} ** 32)));
}

test "KeySchedule: finished verify_data" {
    const secret: [32]u8 = .{0x42} ** 32;
    const transcript: [32]u8 = .{0x01} ** 32;
    const vd = KeySchedule.computeFinishedVerifyData(secret, transcript);

    // Verify it's deterministic
    const vd2 = KeySchedule.computeFinishedVerifyData(secret, transcript);
    try std.testing.expectEqualSlices(u8, &vd, &vd2);

    // Different inputs produce different output
    const vd3 = KeySchedule.computeFinishedVerifyData(secret, .{0x02} ** 32);
    try std.testing.expect(!std.mem.eql(u8, &vd, &vd3));
}

test "buildClientHello: produces valid message" {
    var random: [32]u8 = undefined;
    @memset(&random, 0xAA);
    var pub_key: [32]u8 = undefined;
    @memset(&pub_key, 0xBB);

    const tp = transport_params.TransportParams{
        .initial_max_data = 1048576,
        .initial_max_streams_bidi = 100,
    };

    var buf: [4096]u8 = undefined;
    const msg = try buildClientHello(
        &buf,
        &random,
        &pub_key,
        &[_][]const u8{"h3"},
        "example.com",
        &tp,
    );

    // Check message type
    try std.testing.expectEqual(@as(u8, @intFromEnum(MsgType.client_hello)), msg[0]);

    // Check length consistency
    const body_len = (@as(usize, msg[1]) << 16) | (@as(usize, msg[2]) << 8) | @as(usize, msg[3]);
    try std.testing.expectEqual(msg.len - 4, body_len);

    // Check legacy_version
    try std.testing.expectEqual(@as(u8, 0x03), msg[4]);
    try std.testing.expectEqual(@as(u8, 0x03), msg[5]);
}

test "buildServerHello: produces valid message" {
    var random: [32]u8 = undefined;
    @memset(&random, 0xCC);
    var pub_key: [32]u8 = undefined;
    @memset(&pub_key, 0xDD);
    var client_random: [32]u8 = undefined;
    @memset(&client_random, 0xAA);

    var buf: [512]u8 = undefined;
    const msg = try buildServerHello(&buf, &random, &pub_key, &client_random);

    try std.testing.expectEqual(@as(u8, @intFromEnum(MsgType.server_hello)), msg[0]);
    const body_len = (@as(usize, msg[1]) << 16) | (@as(usize, msg[2]) << 8) | @as(usize, msg[3]);
    try std.testing.expectEqual(msg.len - 4, body_len);
}

test "loopback handshake: client and server complete" {
    // Generate an ECDSA P-256 key pair for the server
    const server_key_pair = EcdsaP256Sha256.KeyPair.generate();
    const secret_key_bytes = server_key_pair.secret_key.toBytes();

    // Create a dummy self-signed certificate (just the public key info, not a real X.509)
    // For our handshake test we just need any DER bytes in the certificate chain
    const pub_key_bytes = server_key_pair.public_key.toUncompressedSec1();
    const fake_cert = pub_key_bytes;

    const server_config = TlsConfig{
        .cert_chain_der = &[_][]const u8{&fake_cert},
        .private_key_bytes = &secret_key_bytes,
        .alpn = &[_][]const u8{"h3"},
    };

    const client_config = TlsConfig{
        .cert_chain_der = &.{},
        .private_key_bytes = &.{},
        .alpn = &[_][]const u8{"h3"},
        .server_name = "localhost",
    };

    const server_tp = transport_params.TransportParams{
        .initial_max_data = 1048576,
        .initial_max_streams_bidi = 100,
    };
    const client_tp = transport_params.TransportParams{
        .initial_max_data = 1048576,
        .initial_max_streams_bidi = 100,
    };

    var server = Tls13Handshake.initServer(server_config, server_tp);
    var client = Tls13Handshake.initClient(client_config, client_tp);

    // Drive the handshake to completion
    var client_done = false;
    var server_done = false;
    var iterations: usize = 0;

    while ((!client_done or !server_done) and iterations < 100) {
        iterations += 1;

        // Step client
        if (!client_done) {
            const action = try client.step();
            switch (action) {
                .send_data => |sd| {
                    if (sd.level == .initial) {
                        server.provideData(sd.data);
                    } else {
                        server.provideData(sd.data);
                    }
                },
                .install_keys => {},
                .wait_for_data => {},
                .complete => client_done = true,
                ._continue => {},
            }
        }

        // Step server
        if (!server_done) {
            const action = try server.step();
            switch (action) {
                .send_data => |sd| {
                    _ = sd;
                    // Server sends at initial level (ServerHello) and handshake level
                    // Route to client input
                    client.provideData(server.out_buf[0..server.out_len]);
                },
                .install_keys => {},
                .wait_for_data => {},
                .complete => server_done = true,
                ._continue => {},
            }
        }
    }

    try std.testing.expect(client_done);
    try std.testing.expect(server_done);
    try std.testing.expect(client.isComplete());
    try std.testing.expect(server.isComplete());

    // Verify both sides derived the same application secrets
    try std.testing.expectEqualSlices(
        u8,
        &client.key_schedule.client_app_traffic_secret,
        &server.key_schedule.client_app_traffic_secret,
    );
    try std.testing.expectEqualSlices(
        u8,
        &client.key_schedule.server_app_traffic_secret,
        &server.key_schedule.server_app_traffic_secret,
    );
}
