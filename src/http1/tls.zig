// TLS 1.3 server over TCP (RFC 8446).
//
// Performs TLS 1.3 handshake on a TCP stream and provides encrypted read/write.
// Reuses KeySchedule, TranscriptHash, and hkdfExpandLabel from the QUIC TLS
// implementation — those are standard TLS 1.3, not QUIC-specific.
//
// Supports: TLS_AES_128_GCM_SHA256, X25519 key exchange, ECDSA P-256 signatures.

const std = @import("std");
const crypto = std.crypto;
const posix = std.posix;
const net = std.net;
const Aes128Gcm = crypto.aead.aes_gcm.Aes128Gcm;
const X25519 = crypto.dh.X25519;
const EcdsaP256Sha256 = crypto.sign.ecdsa.EcdsaP256Sha256;
const Sha256 = crypto.hash.sha2.Sha256;
const HmacSha256 = crypto.auth.hmac.sha2.HmacSha256;
const P256 = crypto.ecc.P256;

const tls13 = @import("../quic/tls13.zig");
const quic_crypto = @import("../quic/crypto.zig");
const KeySchedule = tls13.KeySchedule;
const TranscriptHash = tls13.TranscriptHash;

// TLS record content types
const CT_CHANGE_CIPHER_SPEC: u8 = 20;
const CT_ALERT: u8 = 21;
const CT_HANDSHAKE: u8 = 22;
const CT_APPLICATION_DATA: u8 = 23;

// TLS version for record layer (always 0x0303 for compat)
const TLS12_VERSION = [2]u8{ 0x03, 0x03 };
const TLS10_VERSION = [2]u8{ 0x03, 0x01 };

// Handshake message types
const HS_CLIENT_HELLO: u8 = 1;
const HS_SERVER_HELLO: u8 = 2;
const HS_ENCRYPTED_EXTENSIONS: u8 = 8;
const HS_CERTIFICATE: u8 = 11;
const HS_CERTIFICATE_VERIFY: u8 = 15;
const HS_FINISHED: u8 = 20;

// Extension types
const EXT_SERVER_NAME: u16 = 0;
const EXT_SUPPORTED_GROUPS: u16 = 10;
const EXT_SIGNATURE_ALGORITHMS: u16 = 13;
const EXT_ALPN: u16 = 16;
const EXT_SUPPORTED_VERSIONS: u16 = 43;
const EXT_KEY_SHARE: u16 = 51;

// Constants
const GROUP_X25519: u16 = 0x001d;
const GROUP_SECP256R1: u16 = 0x0017;
const TLS13_VERSION: u16 = 0x0304;
const CIPHER_AES128_GCM: u16 = 0x1301;
const SIG_ECDSA_P256_SHA256: u16 = 0x0403;
const TAG_LEN = Aes128Gcm.tag_length; // 16

pub const TlsServerConfig = struct {
    cert_chain_der: []const []const u8,
    private_key_bytes: []const u8,
    alpn: []const []const u8 = &.{},
};

pub const TlsStream = struct {
    fd: posix.fd_t,
    // Encryption state
    write_key: [16]u8,
    write_iv: [12]u8,
    write_seq: u64 = 0,
    read_key: [16]u8,
    read_iv: [12]u8,
    read_seq: u64 = 0,
    // Decrypted read buffer (TLS records may contain more data than the caller reads)
    dec_buf: [16384 + 256]u8 = undefined,
    dec_start: usize = 0,
    dec_end: usize = 0,

    /// Perform TLS 1.3 handshake on an accepted TCP connection.
    /// Returns a TlsStream ready for encrypted read/write, or error.
    pub fn handshake(fd: posix.fd_t, config: TlsServerConfig) !TlsStream {
        var transcript = TranscriptHash.init();

        // 1. Read ClientHello record
        var rec_buf: [16384]u8 = undefined;
        const ch_rec = try readRecord(fd, &rec_buf);
        if (ch_rec.content_type != CT_HANDSHAKE) return error.UnexpectedMessage;
        const ch_msg = ch_rec.payload;
        if (ch_msg.len < 4 or ch_msg[0] != HS_CLIENT_HELLO) return error.UnexpectedMessage;

        // Parse ClientHello
        const ch = try parseClientHello(ch_msg);

        // Update transcript with ClientHello
        transcript.update(ch_msg);

        // 2. X25519 key exchange
        var x25519_secret: [32]u8 = undefined;
        crypto.random.bytes(&x25519_secret);
        const x25519_public = try X25519.recoverPublicKey(x25519_secret);

        var shared_secret: [32]u8 = undefined;
        if (ch.key_share_group == GROUP_X25519) {
            shared_secret = X25519.scalarmult(x25519_secret, ch.x25519_public) catch return error.KeyExchangeFailed;
        } else if (ch.key_share_group == GROUP_SECP256R1) {
            const peer_point = P256.fromSec1(&ch.p256_public) catch return error.KeyExchangeFailed;
            var p256_secret: [32]u8 = undefined;
            crypto.random.bytes(&p256_secret);
            const shared_point = peer_point.mulPublic(p256_secret, .big) catch return error.KeyExchangeFailed;
            const shared_uncompressed = shared_point.toUncompressedSec1();
            @memcpy(&shared_secret, shared_uncompressed[1..33]);
            // For P-256, we'd need to send p256_public in ServerHello — not implemented yet
            return error.UnsupportedGroup;
        } else {
            return error.UnsupportedGroup;
        }

        // 3. Build and send ServerHello
        var sh_buf: [512]u8 = undefined;
        var server_random: [32]u8 = undefined;
        crypto.random.bytes(&server_random);
        const sh_msg = buildServerHello(&sh_buf, &server_random, &x25519_public, ch.session_id[0..ch.session_id_len]);
        transcript.update(sh_msg);
        try sendRecord(fd, CT_HANDSHAKE, sh_msg);

        // 4. Send ChangeCipherSpec (middlebox compatibility, RFC 8446 §5.1)
        try sendRecord(fd, CT_CHANGE_CIPHER_SPEC, &[_]u8{1});

        // 5. Derive handshake keys
        var ks = KeySchedule.init();
        const transcript_after_sh = transcript.current();
        ks.deriveHandshakeSecrets(&shared_secret, transcript_after_sh);

        const server_hs_key = deriveTlsKey(ks.server_handshake_traffic_secret);
        const server_hs_iv = deriveTlsIv(ks.server_handshake_traffic_secret);
        const client_hs_key = deriveTlsKey(ks.client_handshake_traffic_secret);
        const client_hs_iv = deriveTlsIv(ks.client_handshake_traffic_secret);

        // 6. Send encrypted server handshake messages
        var server_hs_seq: u64 = 0;

        // EncryptedExtensions
        var ee_buf: [512]u8 = undefined;
        const ee_msg = buildEncryptedExtensions(&ee_buf, config.alpn);
        transcript.update(ee_msg);
        try sendEncryptedRecord(fd, CT_HANDSHAKE, ee_msg, server_hs_key, server_hs_iv, &server_hs_seq);

        // Certificate
        var cert_buf: [16384]u8 = undefined;
        const cert_msg = buildCertificate(&cert_buf, config.cert_chain_der);
        transcript.update(cert_msg);
        try sendEncryptedRecord(fd, CT_HANDSHAKE, cert_msg, server_hs_key, server_hs_iv, &server_hs_seq);

        // CertificateVerify
        var cv_buf: [512]u8 = undefined;
        const cv_msg = try buildCertificateVerify(&cv_buf, transcript.current(), config.private_key_bytes);
        transcript.update(cv_msg);
        try sendEncryptedRecord(fd, CT_HANDSHAKE, cv_msg, server_hs_key, server_hs_iv, &server_hs_seq);

        // Finished
        const server_finished_vd = KeySchedule.computeFinishedVerifyData(
            ks.server_handshake_traffic_secret,
            transcript.current(),
        );
        var fin_msg: [36]u8 = undefined;
        fin_msg[0] = HS_FINISHED;
        fin_msg[1] = 0;
        fin_msg[2] = 0;
        fin_msg[3] = 32;
        @memcpy(fin_msg[4..][0..32], &server_finished_vd);
        transcript.update(&fin_msg);

        // Derive app keys BEFORE sending Finished (per RFC 8446)
        const transcript_after_sf = transcript.current();
        ks.deriveAppSecrets(transcript_after_sf);

        try sendEncryptedRecord(fd, CT_HANDSHAKE, &fin_msg, server_hs_key, server_hs_iv, &server_hs_seq);

        // 7. Read client messages (ChangeCipherSpec + Finished)
        var client_hs_seq: u64 = 0;
        var got_finished = false;
        while (!got_finished) {
            const crec = try readRecord(fd, &rec_buf);
            if (crec.content_type == CT_CHANGE_CIPHER_SPEC) {
                continue; // Skip CCS
            }
            if (crec.content_type != CT_APPLICATION_DATA) return error.UnexpectedMessage;

            // Decrypt
            var dec_buf2: [16384]u8 = undefined;
            const plaintext = try decryptRecord(crec.payload, &dec_buf2, client_hs_key, client_hs_iv, &client_hs_seq);
            if (plaintext.len == 0) return error.DecryptionFailed;

            // Find inner content type (last non-zero byte)
            var inner_len = plaintext.len;
            while (inner_len > 0 and plaintext[inner_len - 1] == 0) inner_len -= 1;
            if (inner_len == 0) return error.DecryptionFailed;
            const inner_ct = plaintext[inner_len - 1];
            const inner_data = plaintext[0 .. inner_len - 1];

            if (inner_ct == CT_HANDSHAKE) {
                if (inner_data.len < 4 or inner_data[0] != HS_FINISHED) return error.UnexpectedMessage;
                // Verify client Finished
                const expected_vd = KeySchedule.computeFinishedVerifyData(
                    ks.client_handshake_traffic_secret,
                    transcript.current(),
                );
                if (inner_data.len < 36) return error.BadFinished;
                if (!std.mem.eql(u8, inner_data[4..36], &expected_vd)) return error.BadFinished;
                transcript.update(inner_data);
                got_finished = true;
            }
        }

        // 8. Derive application traffic keys
        const app_write_key = deriveTlsKey(ks.server_app_traffic_secret);
        const app_write_iv = deriveTlsIv(ks.server_app_traffic_secret);
        const app_read_key = deriveTlsKey(ks.client_app_traffic_secret);
        const app_read_iv = deriveTlsIv(ks.client_app_traffic_secret);

        return TlsStream{
            .fd = fd,
            .write_key = app_write_key,
            .write_iv = app_write_iv,
            .read_key = app_read_key,
            .read_iv = app_read_iv,
        };
    }

    /// Read decrypted application data. Returns 0 on EOF/close.
    pub fn read(self: *TlsStream, buf: []u8) !usize {
        // Return buffered data first
        if (self.dec_start < self.dec_end) {
            const available = self.dec_end - self.dec_start;
            const n = @min(available, buf.len);
            @memcpy(buf[0..n], self.dec_buf[self.dec_start..][0..n]);
            self.dec_start += n;
            return n;
        }

        // Read next TLS record
        var rec_buf: [16384 + 256]u8 = undefined;
        const rec = readRecord(self.fd, &rec_buf) catch return 0;

        if (rec.content_type == CT_ALERT) return 0;
        if (rec.content_type != CT_APPLICATION_DATA) return 0;

        // Decrypt
        const plaintext = decryptRecord(rec.payload, &self.dec_buf, self.read_key, self.read_iv, &self.read_seq) catch return 0;
        if (plaintext.len == 0) return 0;

        // Strip inner content type
        var inner_len = plaintext.len;
        while (inner_len > 0 and self.dec_buf[inner_len - 1] == 0) inner_len -= 1;
        if (inner_len == 0) return 0;
        const inner_ct = self.dec_buf[inner_len - 1];
        if (inner_ct == CT_ALERT) return 0;
        if (inner_ct != CT_APPLICATION_DATA) return 0;
        const data_len = inner_len - 1;

        // Copy to caller's buffer, buffer the rest
        const n = @min(data_len, buf.len);
        @memcpy(buf[0..n], self.dec_buf[0..n]);
        if (n < data_len) {
            self.dec_start = n;
            self.dec_end = data_len;
        } else {
            self.dec_start = 0;
            self.dec_end = 0;
        }
        return n;
    }

    /// Write application data as encrypted TLS record(s).
    pub fn write(self: *TlsStream, data: []const u8) !void {
        try sendEncryptedRecord(self.fd, CT_APPLICATION_DATA, data, self.write_key, self.write_iv, &self.write_seq);
    }

    /// Send close_notify alert.
    pub fn close(self: *TlsStream) void {
        const alert = [_]u8{ 1, 0 }; // warning, close_notify
        sendEncryptedRecord(self.fd, CT_ALERT, &alert, self.write_key, self.write_iv, &self.write_seq) catch {};
    }
};

// ─── TLS Record I/O ──────────────────────────────────────────────────

const Record = struct {
    content_type: u8,
    payload: []const u8,
};

fn readRecord(fd: posix.fd_t, buf: []u8) !Record {
    // Read 5-byte header
    var hdr: [5]u8 = undefined;
    try readExact(fd, &hdr);

    const ct = hdr[0];
    const length = (@as(u16, hdr[3]) << 8) | @as(u16, hdr[4]);
    if (length > buf.len) return error.RecordTooLarge;

    try readExact(fd, buf[0..length]);

    return .{
        .content_type = ct,
        .payload = buf[0..length],
    };
}

fn readExact(fd: posix.fd_t, buf: []u8) !void {
    var total: usize = 0;
    while (total < buf.len) {
        const n = posix.read(fd, buf[total..]) catch return error.ConnectionClosed;
        if (n == 0) return error.ConnectionClosed;
        total += n;
    }
}

fn sendRecord(fd: posix.fd_t, content_type: u8, payload: []const u8) !void {
    var hdr: [5]u8 = undefined;
    hdr[0] = content_type;
    // Use TLS 1.0 for ClientHello compat, TLS 1.2 for the rest
    if (content_type == CT_HANDSHAKE) {
        hdr[1] = TLS12_VERSION[0];
        hdr[2] = TLS12_VERSION[1];
    } else {
        hdr[1] = TLS12_VERSION[0];
        hdr[2] = TLS12_VERSION[1];
    }
    hdr[3] = @intCast(payload.len >> 8);
    hdr[4] = @intCast(payload.len & 0xff);
    _ = try posix.write(fd, &hdr);
    _ = try posix.write(fd, payload);
}

fn sendEncryptedRecord(
    fd: posix.fd_t,
    inner_content_type: u8,
    plaintext: []const u8,
    key: [16]u8,
    base_iv: [12]u8,
    seq: *u64,
) !void {
    // TLS 1.3 encrypted record: inner content = plaintext + content_type byte
    // Outer record: CT_APPLICATION_DATA, encrypted payload + tag
    const inner_len = plaintext.len + 1; // +1 for inner content type
    const ciphertext_len = inner_len + TAG_LEN;

    if (ciphertext_len > 16384 + 256) return error.RecordTooLarge;

    // Build AAD (record header with ciphertext length)
    var aad: [5]u8 = undefined;
    aad[0] = CT_APPLICATION_DATA;
    aad[1] = TLS12_VERSION[0];
    aad[2] = TLS12_VERSION[1];
    aad[3] = @intCast(ciphertext_len >> 8);
    aad[4] = @intCast(ciphertext_len & 0xff);

    // Build nonce: base_iv XOR sequence number
    var nonce: [12]u8 = base_iv;
    const seq_bytes = std.mem.toBytes(std.mem.nativeTo(u64, seq.*, .big));
    for (0..8) |i| {
        nonce[4 + i] ^= seq_bytes[i];
    }

    // Build plaintext + inner content type
    var pt_buf: [16384 + 1]u8 = undefined;
    @memcpy(pt_buf[0..plaintext.len], plaintext);
    pt_buf[plaintext.len] = inner_content_type;

    // Encrypt
    var ct_buf: [16384 + 1]u8 = undefined;
    var tag: [TAG_LEN]u8 = undefined;
    Aes128Gcm.encrypt(ct_buf[0..inner_len], &tag, pt_buf[0..inner_len], &aad, nonce, key);

    seq.* += 1;

    // Send: header + ciphertext + tag
    _ = try posix.write(fd, &aad);
    _ = try posix.write(fd, ct_buf[0..inner_len]);
    _ = try posix.write(fd, &tag);
}

fn decryptRecord(
    ciphertext_with_tag: []const u8,
    out: []u8,
    key: [16]u8,
    base_iv: [12]u8,
    seq: *u64,
) ![]const u8 {
    if (ciphertext_with_tag.len < TAG_LEN) return error.DecryptionFailed;

    const ct_len = ciphertext_with_tag.len - TAG_LEN;

    // Build AAD
    var aad: [5]u8 = undefined;
    aad[0] = CT_APPLICATION_DATA;
    aad[1] = TLS12_VERSION[0];
    aad[2] = TLS12_VERSION[1];
    aad[3] = @intCast(ciphertext_with_tag.len >> 8);
    aad[4] = @intCast(ciphertext_with_tag.len & 0xff);

    // Build nonce
    var nonce: [12]u8 = base_iv;
    const seq_bytes = std.mem.toBytes(std.mem.nativeTo(u64, seq.*, .big));
    for (0..8) |i| {
        nonce[4 + i] ^= seq_bytes[i];
    }

    const tag = ciphertext_with_tag[ct_len..][0..TAG_LEN].*;

    Aes128Gcm.decrypt(out[0..ct_len], ciphertext_with_tag[0..ct_len], tag, &aad, nonce, key) catch return error.DecryptionFailed;

    seq.* += 1;
    return out[0..ct_len];
}

// ─── Key derivation (standard TLS 1.3 labels) ───────────────────────

fn deriveTlsKey(traffic_secret: [32]u8) [16]u8 {
    return quic_crypto.hkdfExpandLabel(traffic_secret, "key", "", 16);
}

fn deriveTlsIv(traffic_secret: [32]u8) [12]u8 {
    return quic_crypto.hkdfExpandLabel(traffic_secret, "iv", "", 12);
}

// ─── Handshake message builders ──────────────────────────────────────

const ClientHelloInfo = struct {
    session_id: [32]u8 = undefined,
    session_id_len: u8 = 0,
    x25519_public: [32]u8 = undefined,
    p256_public: [65]u8 = undefined,
    key_share_group: u16 = 0,
};

fn parseClientHello(msg: []const u8) !ClientHelloInfo {
    var info = ClientHelloInfo{};

    if (msg.len < 4) return error.DecodeError;
    const body_len = (@as(usize, msg[1]) << 16) | (@as(usize, msg[2]) << 8) | @as(usize, msg[3]);
    const body = msg[4..@min(4 + body_len, msg.len)];
    if (body.len < 35) return error.DecodeError;

    var pos: usize = 2; // skip legacy_version
    pos += 32; // skip client_random

    // Session ID
    const sid_len = body[pos];
    pos += 1;
    if (sid_len <= 32 and pos + sid_len <= body.len) {
        info.session_id_len = sid_len;
        @memcpy(info.session_id[0..sid_len], body[pos..][0..sid_len]);
    }
    pos += sid_len;

    // Cipher suites (skip)
    if (pos + 2 > body.len) return error.DecodeError;
    const cs_len = readU16(body[pos..]);
    pos += 2 + cs_len;

    // Compression (skip)
    if (pos >= body.len) return error.DecodeError;
    pos += 1 + body[pos];

    // Extensions
    if (pos + 2 > body.len) return error.DecodeError;
    const ext_len = readU16(body[pos..]);
    pos += 2;

    const ext_data = body[pos..@min(pos + ext_len, body.len)];
    var ext_pos: usize = 0;
    while (ext_pos + 4 <= ext_data.len) {
        const etype = readU16(ext_data[ext_pos..]);
        ext_pos += 2;
        const elen = readU16(ext_data[ext_pos..]);
        ext_pos += 2;
        if (ext_pos + elen > ext_data.len) break;

        if (etype == EXT_KEY_SHARE and elen >= 2) {
            var share_pos: usize = 2; // skip client_shares_len
            while (share_pos + 4 <= elen) {
                const group = readU16(ext_data[ext_pos + share_pos ..]);
                const kelen = readU16(ext_data[ext_pos + share_pos + 2 ..]);
                share_pos += 4;
                if (group == GROUP_X25519 and kelen == 32 and share_pos + 32 <= elen) {
                    @memcpy(&info.x25519_public, ext_data[ext_pos + share_pos ..][0..32]);
                    info.key_share_group = GROUP_X25519;
                    break;
                } else if (group == GROUP_SECP256R1 and kelen == 65 and share_pos + 65 <= elen) {
                    @memcpy(&info.p256_public, ext_data[ext_pos + share_pos ..][0..65]);
                    if (info.key_share_group == 0) info.key_share_group = GROUP_SECP256R1;
                }
                share_pos += kelen;
            }
        }
        ext_pos += elen;
    }

    if (info.key_share_group == 0) return error.NoKeyShare;
    return info;
}

fn buildServerHello(buf: []u8, server_random: *const [32]u8, x25519_pub: *const [32]u8, session_id_echo: []const u8) []const u8 {
    var pos: usize = 4; // reserve for header

    // legacy_version = 0x0303
    buf[pos] = 0x03;
    buf[pos + 1] = 0x03;
    pos += 2;

    // random
    @memcpy(buf[pos..][0..32], server_random);
    pos += 32;

    // session_id_echo
    buf[pos] = @intCast(session_id_echo.len);
    pos += 1;
    if (session_id_echo.len > 0) {
        @memcpy(buf[pos..][0..session_id_echo.len], session_id_echo);
        pos += session_id_echo.len;
    }

    // cipher_suite
    writeU16(buf[pos..], CIPHER_AES128_GCM);
    pos += 2;

    // compression_method
    buf[pos] = 0;
    pos += 1;

    // Extensions
    const ext_start = pos;
    pos += 2;

    // supported_versions
    writeU16(buf[pos..], EXT_SUPPORTED_VERSIONS);
    writeU16(buf[pos + 2 ..], 2);
    pos += 4;
    writeU16(buf[pos..], TLS13_VERSION);
    pos += 2;

    // key_share (X25519)
    const ks_data_len: u16 = 2 + 2 + 32;
    writeU16(buf[pos..], EXT_KEY_SHARE);
    writeU16(buf[pos + 2 ..], ks_data_len);
    pos += 4;
    writeU16(buf[pos..], GROUP_X25519);
    pos += 2;
    writeU16(buf[pos..], 32);
    pos += 2;
    @memcpy(buf[pos..][0..32], x25519_pub);
    pos += 32;

    // Fill in extensions length
    writeU16(buf[ext_start..], @intCast(pos - ext_start - 2));

    // Fill in message header
    const body_len: u24 = @intCast(pos - 4);
    buf[0] = HS_SERVER_HELLO;
    buf[1] = @intCast(body_len >> 16);
    buf[2] = @intCast((body_len >> 8) & 0xff);
    buf[3] = @intCast(body_len & 0xff);

    return buf[0..pos];
}

fn buildEncryptedExtensions(buf: []u8, alpn_list: []const []const u8) []const u8 {
    var pos: usize = 4;

    const ext_list_start = pos;
    pos += 2;

    // ALPN
    if (alpn_list.len > 0) {
        var alpn_total: usize = 0;
        for (alpn_list) |proto| alpn_total += 1 + proto.len;

        writeU16(buf[pos..], EXT_ALPN);
        writeU16(buf[pos + 2 ..], @intCast(2 + alpn_total));
        pos += 4;
        writeU16(buf[pos..], @intCast(alpn_total));
        pos += 2;
        for (alpn_list) |proto| {
            buf[pos] = @intCast(proto.len);
            pos += 1;
            @memcpy(buf[pos..][0..proto.len], proto);
            pos += proto.len;
        }
    }

    writeU16(buf[ext_list_start..], @intCast(pos - ext_list_start - 2));

    const body_len: u24 = @intCast(pos - 4);
    buf[0] = HS_ENCRYPTED_EXTENSIONS;
    buf[1] = @intCast(body_len >> 16);
    buf[2] = @intCast((body_len >> 8) & 0xff);
    buf[3] = @intCast(body_len & 0xff);

    return buf[0..pos];
}

fn buildCertificate(buf: []u8, cert_chain: []const []const u8) []const u8 {
    var pos: usize = 4;

    // certificate_request_context (empty)
    buf[pos] = 0;
    pos += 1;

    // certificate_list length placeholder
    const cert_list_start = pos;
    pos += 3;

    for (cert_chain) |cert_der| {
        const cert_len: u24 = @intCast(cert_der.len);
        buf[pos] = @intCast(cert_len >> 16);
        buf[pos + 1] = @intCast((cert_len >> 8) & 0xff);
        buf[pos + 2] = @intCast(cert_len & 0xff);
        pos += 3;
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

    const body_len: u24 = @intCast(pos - 4);
    buf[0] = HS_CERTIFICATE;
    buf[1] = @intCast(body_len >> 16);
    buf[2] = @intCast((body_len >> 8) & 0xff);
    buf[3] = @intCast(body_len & 0xff);

    return buf[0..pos];
}

fn buildCertificateVerify(buf: []u8, transcript_hash: [32]u8, private_key_bytes: []const u8) ![]const u8 {
    // Sign: 64×0x20 + "TLS 1.3, server CertificateVerify" + 0x00 + transcript_hash
    var sign_content: [64 + 33 + 1 + 32]u8 = undefined;
    @memset(sign_content[0..64], 0x20);
    const context_str = "TLS 1.3, server CertificateVerify";
    @memcpy(sign_content[64..][0..33], context_str);
    sign_content[64 + 33] = 0x00;
    @memcpy(sign_content[64 + 34 ..][0..32], &transcript_hash);

    if (private_key_bytes.len != 32) return error.InvalidKey;
    const secret_key = EcdsaP256Sha256.SecretKey.fromBytes(private_key_bytes[0..32].*) catch return error.InvalidKey;
    const key_pair = EcdsaP256Sha256.KeyPair.fromSecretKey(secret_key) catch return error.InvalidKey;
    const sig = key_pair.sign(&sign_content, null) catch return error.SignatureFailed;

    var der_buf: [EcdsaP256Sha256.Signature.der_encoded_length_max]u8 = undefined;
    const sig_bytes = sig.toDer(&der_buf);

    var pos: usize = 4;

    // signature_algorithm
    writeU16(buf[pos..], SIG_ECDSA_P256_SHA256);
    pos += 2;

    // signature
    writeU16(buf[pos..], @intCast(sig_bytes.len));
    pos += 2;
    @memcpy(buf[pos..][0..sig_bytes.len], sig_bytes);
    pos += sig_bytes.len;

    const body_len: u24 = @intCast(pos - 4);
    buf[0] = HS_CERTIFICATE_VERIFY;
    buf[1] = @intCast(body_len >> 16);
    buf[2] = @intCast((body_len >> 8) & 0xff);
    buf[3] = @intCast(body_len & 0xff);

    return buf[0..pos];
}

// ─── Helpers ─────────────────────────────────────────────────────────

fn readU16(data: []const u8) u16 {
    return (@as(u16, data[0]) << 8) | @as(u16, data[1]);
}

fn writeU16(buf: []u8, val: u16) void {
    buf[0] = @intCast(val >> 8);
    buf[1] = @intCast(val & 0xff);
}
