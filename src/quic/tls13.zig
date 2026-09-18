// TLS 1.3 handshake for QUIC (RFC 8446 + RFC 9001)
//
// Supports TLS_AES_128_GCM_SHA256 (0x1301) only.
// ECDSA P-256 or Ed25519 for signatures, X25519 for key exchange.
// X.509 certificate chain validation via std.crypto.Certificate.

const std = @import("std");
const sys = @import("../sys.zig");
const io = @import("../io_compat.zig");
const crypto = std.crypto;
const tls = std.crypto.tls;
const quic_crypto = @import("crypto.zig");
const protocol = @import("protocol.zig");
const transport_params = @import("transport_params.zig");
const limits = @import("limits.zig");

const Certificate = std.crypto.Certificate;

const HkdfSha256 = crypto.kdf.hkdf.HkdfSha256;
const HmacSha256 = crypto.auth.hmac.sha2.HmacSha256;
const Sha256 = crypto.hash.sha2.Sha256;
const Sha384 = crypto.hash.sha2.Sha384;
const Sha512 = crypto.hash.sha2.Sha512;
const X25519 = crypto.dh.X25519;
const EcdsaP256Sha256 = crypto.sign.ecdsa.EcdsaP256Sha256;
const Ed25519 = crypto.sign.Ed25519;
const Aes128Gcm = crypto.aead.aes_gcm.Aes128Gcm;

// Handshake message types, extension types, signature schemes, named groups,
// cipher suites and protocol version all come from std.crypto.tls enums
// (HandshakeType, ExtensionType, SignatureScheme, NamedGroup, CipherSuite,
// ProtocolVersion) at their use sites.

const P256 = crypto.ecc.P256;

pub const EncryptionLevel = quic_crypto.EncryptionLevel;

pub const PrivateKeyAlgorithm = enum {
    ecdsa_p256_sha256,
    ed25519,
};

// ─── CertificateVerify signature verification ────────────────────────

/// Checks a CertificateVerify signature made with the leaf's public key.
pub fn verifyCertificateVerifySignature(
    pub_key_bytes: []const u8,
    pub_key_algo: Certificate.AlgorithmCategory,
    sig_algo: u16,
    sig_bytes: []const u8,
    signed_content: []const u8,
) HandshakeError!void {
    const scheme: tls.SignatureScheme = @enumFromInt(sig_algo);
    switch (scheme) {
        .ecdsa_secp256r1_sha256 => {
            if (pub_key_algo != .X9_62_id_ecPublicKey) return error.BadCertificateVerify;
            const pub_key = EcdsaP256Sha256.PublicKey.fromSec1(pub_key_bytes) catch return error.BadCertificateVerify;
            const sig = EcdsaP256Sha256.Signature.fromDer(sig_bytes) catch return error.BadCertificateVerify;
            sig.verify(signed_content, pub_key) catch return error.BadCertificateVerify;
        },
        .ecdsa_secp384r1_sha384 => {
            if (pub_key_algo != .X9_62_id_ecPublicKey) return error.BadCertificateVerify;
            const P384 = crypto.sign.ecdsa.EcdsaP384Sha384;
            const pub_key = P384.PublicKey.fromSec1(pub_key_bytes) catch return error.BadCertificateVerify;
            const sig = P384.Signature.fromDer(sig_bytes) catch return error.BadCertificateVerify;
            sig.verify(signed_content, pub_key) catch return error.BadCertificateVerify;
        },
        .ed25519 => {
            if (pub_key_algo != .curveEd25519) return error.BadCertificateVerify;
            if (pub_key_bytes.len != Ed25519.PublicKey.encoded_length) return error.BadCertificateVerify;
            if (sig_bytes.len != Ed25519.Signature.encoded_length) return error.BadCertificateVerify;
            const pub_key = Ed25519.PublicKey.fromBytes(pub_key_bytes[0..Ed25519.PublicKey.encoded_length].*) catch return error.BadCertificateVerify;
            const sig = Ed25519.Signature.fromBytes(sig_bytes[0..Ed25519.Signature.encoded_length].*);
            sig.verify(signed_content, pub_key) catch return error.BadCertificateVerify;
        },
        .rsa_pss_rsae_sha256 => verifyRsaPss(pub_key_bytes, pub_key_algo, sig_bytes, signed_content, Sha256) catch return error.BadCertificateVerify,
        .rsa_pss_rsae_sha384 => verifyRsaPss(pub_key_bytes, pub_key_algo, sig_bytes, signed_content, Sha384) catch return error.BadCertificateVerify,
        .rsa_pss_rsae_sha512 => verifyRsaPss(pub_key_bytes, pub_key_algo, sig_bytes, signed_content, Sha512) catch return error.BadCertificateVerify,
        else => return error.BadCertificateVerify,
    }
}

fn verifyRsaPss(
    pub_key_bytes: []const u8,
    pub_key_algo: Certificate.AlgorithmCategory,
    sig_bytes: []const u8,
    signed_content: []const u8,
    comptime Hash: type,
) !void {
    if (pub_key_algo != .rsaEncryption) return error.BadCertificateVerify;
    const rsa = Certificate.rsa;
    const pk_components = rsa.PublicKey.parseDer(pub_key_bytes) catch return error.BadCertificateVerify;
    const public_key = rsa.PublicKey.fromBytes(pk_components.exponent, pk_components.modulus) catch return error.BadCertificateVerify;

    switch (pk_components.modulus.len) {
        inline 128, 256, 384, 512 => |modulus_len| {
            if (sig_bytes.len != modulus_len) return error.BadCertificateVerify;
            rsa.PSSSignature.verify(modulus_len, sig_bytes[0..modulus_len].*, signed_content, public_key, Hash) catch return error.BadCertificateVerify;
        },
        else => return error.BadCertificateVerify,
    }
}

// ─── X.509 extension parsing for chain validation (RFC 5280) ─────────

const X509Extensions = struct {
    /// basicConstraints: CA flag (RFC 5280 §4.2.1.9)
    is_ca: ?bool = null,
    /// basicConstraints: pathLenConstraint
    path_len_constraint: ?u32 = null,
    /// keyUsage bit field (RFC 5280 §4.2.1.3), MSB-first
    key_usage: ?u16 = null,

    /// Check if the keyCertSign bit is set.
    /// RFC 5280: keyCertSign is bit 5 in the KeyUsage BIT STRING.
    /// In DER encoding: byte[1] bit 2 = 0x04, stored as ku = byte[1]<<8 | byte[2].
    fn hasKeyCertSign(self: X509Extensions) bool {
        if (self.key_usage) |ku| {
            return (ku & 0x0400) != 0;
        }
        // If keyUsage extension is absent, no restriction applies
        return true;
    }
};

/// RFC 5280 constraints on a certificate that signed the one below it in a
/// peer's chain, `depth` certificates above the leaf (1 for the leaf's
/// issuer): basicConstraints CA:TRUE (§4.2.1.9) and keyCertSign in keyUsage
/// (§4.2.1.3) when those extensions are present, and pathLenConstraint.
pub fn issuerConstraintsOk(issuer_der: []const u8, depth: usize) bool {
    const exts = parseX509Extensions(issuer_der);
    if (exts.is_ca) |is_ca| if (!is_ca) return false;
    if (!exts.hasKeyCertSign()) return false;
    // `depth - 1` intermediates sit below this issuer.
    if (exts.path_len_constraint) |max_len| if (depth > max_len + 1) return false;
    return true;
}

/// Parse X.509 v3 extensions from a DER certificate buffer.
/// Uses the same DER walking approach as std.crypto.Certificate.parse().
fn parseX509Extensions(cert_der: []const u8) X509Extensions {
    const der = Certificate.der;
    var result = X509Extensions{};

    // Parse top-level Certificate SEQUENCE
    const cert_seq = der.Element.parse(cert_der, 0) catch return result;

    // Parse TBSCertificate SEQUENCE
    const tbs = der.Element.parse(cert_der, cert_seq.slice.start) catch return result;

    // Walk TBSCertificate fields to find extensions
    // version [0] EXPLICIT INTEGER
    var pos: u32 = tbs.slice.start;
    const version_outer = der.Element.parse(cert_der, pos) catch return result;

    // Check if this is an explicit tag [0] (context-specific, constructed)
    if (version_outer.identifier.class == .context_specific) {
        pos = version_outer.slice.end;
    }
    // Otherwise v1 cert, no version field — pos stays

    // serialNumber INTEGER
    const serial = der.Element.parse(cert_der, pos) catch return result;
    pos = serial.slice.end;

    // signature AlgorithmIdentifier
    const sig_algo = der.Element.parse(cert_der, pos) catch return result;
    pos = sig_algo.slice.end;

    // issuer Name
    const issuer = der.Element.parse(cert_der, pos) catch return result;
    pos = issuer.slice.end;

    // validity Validity
    const validity = der.Element.parse(cert_der, pos) catch return result;
    pos = validity.slice.end;

    // subject Name
    const subject = der.Element.parse(cert_der, pos) catch return result;
    pos = subject.slice.end;

    // subjectPublicKeyInfo
    const pub_key_info = der.Element.parse(cert_der, pos) catch return result;
    pos = pub_key_info.slice.end;

    // Extensions are [3] EXPLICIT SEQUENCE, after optional issuerUniqueID [1] and subjectUniqueID [2]
    while (pos < tbs.slice.end) {
        const elem = der.Element.parse(cert_der, pos) catch return result;
        pos = elem.slice.end;

        if (elem.identifier.class == .context_specific) {
            if (@intFromEnum(elem.identifier.tag) == 3) {
                // Extensions SEQUENCE
                const extensions = der.Element.parse(cert_der, elem.slice.start) catch return result;
                var ext_i = extensions.slice.start;
                while (ext_i < extensions.slice.end) {
                    const extension = der.Element.parse(cert_der, ext_i) catch return result;
                    ext_i = extension.slice.end;

                    const oid_elem = der.Element.parse(cert_der, extension.slice.start) catch continue;
                    if (oid_elem.identifier.tag != .object_identifier) continue;

                    // Skip optional critical BOOLEAN
                    const next_elem = der.Element.parse(cert_der, oid_elem.slice.end) catch continue;
                    const value_elem = if (next_elem.identifier.tag == .boolean)
                        der.Element.parse(cert_der, next_elem.slice.end) catch continue
                    else
                        next_elem;

                    // value_elem should be OCTET STRING wrapping the extension value
                    if (value_elem.identifier.tag != .octetstring) continue;

                    const oid_bytes = cert_der[oid_elem.slice.start..oid_elem.slice.end];

                    // basicConstraints: OID 2.5.29.19 = { 0x55, 0x1D, 0x13 }
                    if (oid_bytes.len == 3 and oid_bytes[0] == 0x55 and oid_bytes[1] == 0x1D and oid_bytes[2] == 0x13) {
                        parseBasicConstraints(cert_der, value_elem, &result);
                    }

                    // keyUsage: OID 2.5.29.15 = { 0x55, 0x1D, 0x0F }
                    if (oid_bytes.len == 3 and oid_bytes[0] == 0x55 and oid_bytes[1] == 0x1D and oid_bytes[2] == 0x0F) {
                        parseKeyUsage(cert_der, value_elem, &result);
                    }
                }
                break;
            }
        }
    }

    return result;
}

fn parseBasicConstraints(cert_der: []const u8, octet_elem: Certificate.der.Element, result: *X509Extensions) void {
    const der = Certificate.der;
    // OCTET STRING contains: SEQUENCE { BOOLEAN (cA), INTEGER (pathLen) OPTIONAL }
    const seq = der.Element.parse(cert_der, octet_elem.slice.start) catch return;
    if (seq.identifier.tag != .sequence) return;

    if (seq.slice.start >= seq.slice.end) {
        // Empty sequence means CA:FALSE (default)
        result.is_ca = false;
        return;
    }

    const ca_elem = der.Element.parse(cert_der, seq.slice.start) catch return;
    if (ca_elem.identifier.tag == .boolean) {
        result.is_ca = cert_der[ca_elem.slice.start] != 0;

        // Optional pathLenConstraint INTEGER
        if (ca_elem.slice.end < seq.slice.end) {
            const path_len_elem = der.Element.parse(cert_der, ca_elem.slice.end) catch return;
            if (path_len_elem.identifier.tag == .integer) {
                const len = path_len_elem.slice.end - path_len_elem.slice.start;
                if (len == 1) {
                    result.path_len_constraint = cert_der[path_len_elem.slice.start];
                }
            }
        }
    } else {
        // No BOOLEAN means CA:FALSE (default is FALSE per RFC 5280)
        result.is_ca = false;
    }
}

fn parseKeyUsage(cert_der: []const u8, octet_elem: Certificate.der.Element, result: *X509Extensions) void {
    const der = Certificate.der;
    // OCTET STRING contains: BIT STRING with key usage bits
    const bit_str = der.Element.parse(cert_der, octet_elem.slice.start) catch return;
    if (bit_str.identifier.tag != .bitstring) return;

    const content = cert_der[bit_str.slice.start..bit_str.slice.end];
    if (content.len < 2) return;

    // First byte is number of unused bits in last byte
    // Second byte has the key usage bits (MSB first):
    //   bit 0: digitalSignature
    //   bit 1: contentCommitment (nonRepudiation)
    //   bit 2: keyEncipherment
    //   bit 3: dataEncipherment
    //   bit 4: keyAgreement
    //   bit 5: keyCertSign
    //   bit 6: cRLSign
    //   bit 7: encipherOnly
    var ku: u16 = @as(u16, content[1]) << 8;
    if (content.len >= 3) {
        ku |= content[2];
    }
    result.key_usage = ku;
}

/// Load system root CA certificates into a Certificate.Bundle.
/// The caller owns the returned bundle and must call bundle.deinit(allocator).
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
    resumption_master_secret: [32]u8 = .{0} ** 32,
    client_early_traffic_secret: [32]u8 = .{0} ** 32,
    computed_handshake: bool = false,
    computed_app: bool = false,

    pub fn init() KeySchedule {
        var ks: KeySchedule = undefined;
        ks.computed_handshake = false;
        ks.computed_app = false;
        ks.resumption_master_secret = .{0} ** 32;
        ks.client_early_traffic_secret = .{0} ** 32;
        // early_secret = HKDF-Extract(salt=0, IKM=0)
        const zero_key: [32]u8 = .{0} ** 32;
        ks.early_secret = HkdfSha256.extract(&(.{0} ** 1), &zero_key);
        return ks;
    }

    // Initialize with a PSK (for session resumption)
    pub fn initWithPsk(psk: [32]u8) KeySchedule {
        var ks: KeySchedule = undefined;
        ks.computed_handshake = false;
        ks.computed_app = false;
        ks.resumption_master_secret = .{0} ** 32;
        ks.client_early_traffic_secret = .{0} ** 32;
        // early_secret = HKDF-Extract(salt=0, IKM=PSK)
        ks.early_secret = HkdfSha256.extract(&(.{0} ** 1), &psk);
        return ks;
    }

    // Derive client early traffic secret for 0-RTT data
    pub fn deriveEarlyDataSecret(self: *KeySchedule, transcript_hash: [32]u8) void {
        self.client_early_traffic_secret = deriveSecret(self.early_secret, "c e traffic", transcript_hash);
    }

    // Derive resumption master secret (after full handshake transcript)
    pub fn deriveResumptionMasterSecret(self: *KeySchedule, transcript_hash: [32]u8) void {
        self.resumption_master_secret = deriveSecret(self.master_secret, "res master", transcript_hash);
    }

    // Derive handshake secrets from the shared secret and transcript hash.
    pub fn deriveHandshakeSecrets(self: *KeySchedule, shared_secret: []const u8, transcript_hash: [32]u8) void {
        // derived1 = Derive-Secret(early_secret, "derived", Hash(""))
        const empty_hash = tls.emptyHash(Sha256);
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
        const empty_hash = tls.emptyHash(Sha256);
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

    // Derive QUIC Open/Seal keys from a traffic secret (AES-128-GCM, 16-byte keys).
    pub fn deriveQuicKeys(traffic_secret: [32]u8) struct { key: [16]u8, iv: [12]u8, hp: [16]u8 } {
        return .{
            .key = quic_crypto.hkdfExpandLabel(traffic_secret, "quic key", "", 16),
            .iv = quic_crypto.hkdfExpandLabel(traffic_secret, "quic iv", "", 12),
            .hp = quic_crypto.hkdfExpandLabel(traffic_secret, "quic hp", "", 16),
        };
    }

    pub fn makeOpen(traffic_secret: [32]u8) quic_crypto.Open {
        return makeOpenWithCipher(traffic_secret, .aes_128_gcm_sha256);
    }

    pub fn makeSeal(traffic_secret: [32]u8) quic_crypto.Seal {
        return makeSealWithCipher(traffic_secret, .aes_128_gcm_sha256);
    }

    pub fn makeOpenWithCipher(traffic_secret: [32]u8, cipher: quic_crypto.CipherSuite) quic_crypto.Open {
        return makeOpenFull(traffic_secret, cipher, protocol.QUIC_V1);
    }

    pub fn makeSealWithCipher(traffic_secret: [32]u8, cipher: quic_crypto.CipherSuite) quic_crypto.Seal {
        return makeSealFull(traffic_secret, cipher, protocol.QUIC_V1);
    }

    pub fn makeOpenFull(traffic_secret: [32]u8, cipher: quic_crypto.CipherSuite, version: u32) quic_crypto.Open {
        const kl = cipher.keyLen();
        const label_iv = protocol.quicLabel(version, .iv);
        var open: quic_crypto.Open = .{
            .key = quic_crypto.deriveKeyPaddedV(traffic_secret, kl, version),
            .nonce = quic_crypto.hkdfExpandLabel(traffic_secret, label_iv, "", 12),
            .hp_key = quic_crypto.deriveHpKeyPaddedV(traffic_secret, cipher.hpKeyLen(), version),
            .cipher_suite = cipher,
        };
        open.prepareHpCtx();
        return open;
    }

    pub fn makeSealFull(traffic_secret: [32]u8, cipher: quic_crypto.CipherSuite, version: u32) quic_crypto.Seal {
        const kl = cipher.keyLen();
        const label_iv = protocol.quicLabel(version, .iv);
        var seal: quic_crypto.Seal = .{
            .key = quic_crypto.deriveKeyPaddedV(traffic_secret, kl, version),
            .nonce = quic_crypto.hkdfExpandLabel(traffic_secret, label_iv, "", 12),
            .hp_key = quic_crypto.deriveHpKeyPaddedV(traffic_secret, cipher.hpKeyLen(), version),
            .cipher_suite = cipher,
        };
        seal.prepareHpCtx();
        return seal;
    }

    // Compute the Finished verify_data.
    pub fn computeFinishedVerifyData(base_key: [32]u8, transcript_hash: [32]u8) [32]u8 {
        const finished_key = quic_crypto.hkdfExpandLabel(base_key, "finished", "", 32);
        return tls.hmac(HmacSha256, &transcript_hash, finished_key);
    }

    fn deriveSecret(secret: [32]u8, comptime label: []const u8, transcript_hash: [32]u8) [32]u8 {
        return quic_crypto.hkdfExpandLabel(secret, label, &transcript_hash, 32);
    }
};

// ─── Session Ticket (0-RTT resumption) ───────────────────────────────

pub const SessionTicket = struct {
    psk: [32]u8, // Pre-shared key derived from resumption_master_secret
    ticket: [512]u8 = .{0} ** 512, // Opaque ticket data (encrypted by server)
    ticket_len: u16 = 0,
    ticket_age_add: u32 = 0, // Age obfuscation value
    creation_time: i64 = 0, // Seconds since epoch
    lifetime: u32 = 0, // Seconds
    max_early_data_size: u32 = 0, // From early_data extension
    alpn: [16]u8 = .{0} ** 16, // Negotiated ALPN
    alpn_len: u8 = 0,

    // RFC 9000 §7.4.1: remembered transport parameters for 0-RTT
    initial_max_data: u64 = 0,
    initial_max_stream_data_bidi_local: u64 = 0,
    initial_max_stream_data_bidi_remote: u64 = 0,
    initial_max_stream_data_uni: u64 = 0,
    initial_max_streams_bidi: u64 = 0,
    initial_max_streams_uni: u64 = 0,
    active_connection_id_limit: u64 = 2,

    pub fn getTicket(self: *const SessionTicket) []const u8 {
        return self.ticket[0..self.ticket_len];
    }

    pub fn getAlpn(self: *const SessionTicket) []const u8 {
        return self.alpn[0..self.alpn_len];
    }

    pub fn isExpired(self: *const SessionTicket) bool {
        const now_sec = sys.realtimeSeconds();
        return (now_sec - self.creation_time) > @as(i64, self.lifetime);
    }
};

// ─── Server certificates / SNI ───────────────────────────────────────

/// A certificate chain and the private key for its leaf.
pub const ServerCertificate = struct {
    /// DER-encoded certificates, leaf first.
    cert_chain_der: []const []const u8,
    /// Raw P-256 scalar or Ed25519 seed (32 bytes), as `extractEcPrivateKey`
    /// / `extractEd25519PrivateKey` return it.
    private_key_bytes: []const u8,
    private_key_algorithm: PrivateKeyAlgorithm = .ecdsa_p256_sha256,
};

/// A certificate served for a set of host names. Shared by the QUIC server
/// (`TlsConfig.certs`) and the TCP TLS server (`tls_server.Config.certs`).
pub const CertEntry = struct {
    /// Host names this certificate is served for. `"*.example.com"` matches
    /// exactly one label (`a.example.com`, not `example.com` or
    /// `a.b.example.com`). Matching is ASCII case-insensitive.
    server_names: []const []const u8,
    cert: ServerCertificate,
};

pub const CertSelection = struct {
    entry: *const CertEntry,
    /// False when the client sent no SNI or nothing matched it, so the first
    /// entry was used as the default.
    matched: bool,
};

/// Picks the certificate for a ClientHello's SNI: an exact name first, then a
/// one-label wildcard, then `entries[0]`. Returns null only when `entries` is
/// empty.
pub fn selectCertificate(entries: []const CertEntry, sni: ?[]const u8) ?CertSelection {
    if (entries.len == 0) return null;
    const raw = sni orelse return .{ .entry = &entries[0], .matched = false };
    // A trailing dot names the same host (RFC 6066 forbids it, clients still send it).
    const name = if (raw.len > 0 and raw[raw.len - 1] == '.') raw[0 .. raw.len - 1] else raw;
    if (name.len == 0) return .{ .entry = &entries[0], .matched = false };

    for (entries) |*e| {
        for (e.server_names) |n| {
            if (std.ascii.eqlIgnoreCase(n, name)) return .{ .entry = e, .matched = true };
        }
    }
    if (std.mem.indexOfScalar(u8, name, '.')) |dot| {
        if (dot > 0) {
            const parent = name[dot..]; // ".example.com"
            for (entries) |*e| {
                for (e.server_names) |n| {
                    if (n.len > 2 and n[0] == '*' and n[1] == '.' and std.ascii.eqlIgnoreCase(n[1..], parent))
                        return .{ .entry = e, .matched = true };
                }
            }
        }
    }
    return .{ .entry = &entries[0], .matched = false };
}

/// Parses the host_name out of a server_name extension body (RFC 6066 §3).
/// Returns null for a list with no host_name entry.
pub fn parseServerNameExtension(data: []const u8) error{DecodeError}!?[]const u8 {
    if (data.len < 2) return error.DecodeError;
    const list_len: usize = readU16(data); // widened: + 2 overflows u16 at 0xFFFF
    if (list_len + 2 != data.len or list_len == 0) return error.DecodeError;
    var pos: usize = 2;
    var host: ?[]const u8 = null;
    while (pos < data.len) {
        if (pos + 3 > data.len) return error.DecodeError;
        const name_type = data[pos];
        const len = readU16(data[pos + 1 ..]);
        pos += 3;
        if (pos + len > data.len) return error.DecodeError;
        if (name_type == 0) {
            if (host != null or len == 0) return error.DecodeError;
            host = data[pos..][0..len];
        }
        pos += len;
    }
    return host;
}

// ─── TLS Config ──────────────────────────────────────────────────────

pub const TlsConfig = struct {
    cert_chain_der: []const []const u8, // DER-encoded certificates
    private_key_bytes: []const u8, // Raw P-256 scalar or Ed25519 seed (32 bytes)
    private_key_algorithm: PrivateKeyAlgorithm = .ecdsa_p256_sha256,
    /// Server only: certificates chosen by the ClientHello's SNI (see
    /// `selectCertificate`). When non-empty, this replaces `cert_chain_der` /
    /// `private_key_bytes` / `private_key_algorithm`, with `certs[0]` as the
    /// default for a client that sends no SNI or an unknown name.
    certs: []const CertEntry = &.{},
    alpn: []const []const u8,
    server_name: ?[]const u8 = null, // SNI (client only)
    skip_cert_verify: bool = true, // Skip X.509 chain + CertificateVerify validation
    /// SHA-256 fingerprints of acceptable leaf certificates — the
    /// `serverCertificateHashes` bargain from the W3C WebTransport API. When
    /// set, the fingerprint stands in for the chain, the hostname and the
    /// validity dates, and none of those are checked. Requires
    /// `skip_cert_verify = false`, or CertificateVerify never runs and the pin
    /// proves only that someone copied a public certificate.
    cert_hashes: ?[]const [32]u8 = null,
    ca_bundle: ?*Certificate.Bundle = null, // Caller-owned CA bundle for trust anchor verification
    session_ticket: ?*const SessionTicket = null, // Stored ticket from previous connection (client)
    ticket_key: ?[16]u8 = null, // AES-128-GCM key for encrypting/decrypting tickets (server)
    keylog_file: ?@import("../sys.zig").File = null, // SSLKEYLOGFILE output (NSS Key Log format)
    cipher_suite_only: ?quic_crypto.CipherSuite = null, // If set, offer ONLY this cipher suite
    quic_version: u32 = protocol.QUIC_V1, // QUIC version (affects HKDF labels)
};

// ─── SSLKEYLOGFILE support (NSS Key Log format) ─────────────────────

fn hexByte(b: u8) [2]u8 {
    const hex = "0123456789abcdef";
    return .{ hex[b >> 4], hex[b & 0x0f] };
}

fn writeKeylogLine(file: @import("../sys.zig").File, label: []const u8, client_random: *const [32]u8, secret: *const [32]u8) void {
    // Format: "LABEL <client_random_hex> <secret_hex>\n"
    var buf: [256]u8 = undefined;
    var pos: usize = 0;

    @memcpy(buf[pos..][0..label.len], label);
    pos += label.len;
    buf[pos] = ' ';
    pos += 1;

    for (client_random) |b| {
        const h = hexByte(b);
        buf[pos] = h[0];
        buf[pos + 1] = h[1];
        pos += 2;
    }
    buf[pos] = ' ';
    pos += 1;

    for (secret) |b| {
        const h = hexByte(b);
        buf[pos] = h[0];
        buf[pos + 1] = h[1];
        pos += 2;
    }
    buf[pos] = '\n';
    pos += 1;

    file.writeAll(buf[0..pos]) catch {};
}

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
    NoApplicationProtocol,
    MissingExtension,
    TransportParameterError,
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
    server_send_ticket,

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

    // P-256 key exchange
    p256_secret: [32]u8 = undefined,
    p256_public: [65]u8 = undefined, // our uncompressed public point
    peer_p256_public: [65]u8 = undefined, // peer's uncompressed public point
    negotiated_group: tls.NamedGroup = .x25519,

    // Outgoing flight, built in place; see limits.tls_handshake_out.
    out_buf: [limits.tls_handshake_out]u8 = undefined,
    out_len: usize = 0,

    // Pending actions returned by step()
    pending_install_handshake: bool = false,
    pending_install_app: bool = false,
    handshake_keys_installed: bool = false,
    app_keys_installed: bool = false,

    // Pre-encoded transport params (avoids dangling slice issues after struct move)
    tp_encoded: [256]u8 = undefined,
    tp_encoded_len: usize = 0,

    // Peer flight being reassembled; see limits.tls_handshake_in.
    in_buf: [limits.tls_handshake_in]u8 = undefined,
    in_len: usize = 0,
    in_offset: usize = 0,

    // Client random for ServerHello matching
    client_random: [32]u8 = undefined,

    // Peer's legacy_session_id from ClientHello (must be echoed in ServerHello)
    peer_session_id: [32]u8 = .{0} ** 32,
    peer_session_id_len: u8 = 0,

    // Server hello random
    server_random: [32]u8 = undefined,

    // Leaf certificate public key (extracted during Certificate processing)
    leaf_pub_key_buf: [600]u8 = undefined,
    leaf_pub_key_len: u16 = 0,
    leaf_pub_key_algo: Certificate.AlgorithmCategory = .X9_62_id_ecPublicKey,

    // Transcript hash at server Finished for app key derivation
    transcript_at_server_finished: [32]u8 = undefined,

    // Negotiated cipher suite (set during ServerHello processing)
    negotiated_cipher_suite: quic_crypto.CipherSuite = .aes_128_gcm_sha256,

    // PSK / 0-RTT fields
    using_psk: bool = false,

    /// Client: the server asked for a client certificate. We have none, and
    /// RFC 8446 4.4.2 says the answer is still a Certificate message — an
    /// empty one — which has to be in the transcript before Finished.
    certificate_requested: bool = false,

    /// Server: the ClientHello carried the early_data extension. RFC 8446
    /// 4.2.10 only lets EncryptedExtensions answer an extension the client
    /// offered, so accepting a PSK is not on its own a licence to send it.
    early_data_offered: bool = false,
    /// Server side: which of `config.alpn` the client also offered. A
    /// server advertising several has to echo the one that matched, not
    /// its own first choice.
    selected_alpn: [32]u8 = .{0} ** 32,
    selected_alpn_len: usize = 0,

    /// Server: the certificate we present — the config's single one, or the
    /// `config.certs` entry the ClientHello's SNI selected.
    server_cert: ServerCertificate = undefined,

    zero_rtt_accepted: bool = false,
    pending_install_early: bool = false,
    received_ticket: ?SessionTicket = null,
    ticket_nonce_counter: u32 = 0,

    /// The protocol in force: what the server matched, or — on a client,
    /// or before a match — the first one we offered.
    pub fn negotiatedAlpn(self: *const @This()) []const u8 {
        if (self.selected_alpn_len > 0) return self.selected_alpn[0..self.selected_alpn_len];
        return if (self.config.alpn.len > 0) self.config.alpn[0] else "";
    }

    /// Builds the client handshake in place. Tls13Handshake is ~52 KB, and
    /// returning it by value is the single largest contributor to the stack
    /// frame of anything that opens a connection — see quic/limits.zig.
    pub fn initClientInto(
        out: *Tls13Handshake,
        config: TlsConfig,
        local_tp: transport_params.TransportParams,
    ) void {
        const self = out;
        self.state = .client_start;
        self.is_server = false;
        self.transcript = TranscriptHash.init();
        self.key_schedule = if (config.session_ticket) |ticket|
            KeySchedule.initWithPsk(ticket.psk)
        else
            KeySchedule.init();
        self.config = config;
        self.local_transport_params = local_tp;
        self.peer_transport_params = null;
        self.out_len = 0;
        self.in_len = 0;
        self.in_offset = 0;
        self.pending_install_handshake = false;
        self.pending_install_app = false;
        self.pending_install_early = false;
        self.handshake_keys_installed = false;
        self.app_keys_installed = false;
        self.leaf_pub_key_len = 0;
        self.negotiated_cipher_suite = .aes_128_gcm_sha256;
        self.using_psk = false;
        self.certificate_requested = false;
        self.early_data_offered = false;
        self.selected_alpn_len = 0;
        self.zero_rtt_accepted = false;
        self.received_ticket = null;
        self.ticket_nonce_counter = 0;
        self.peer_session_id_len = 0;
        self.peer_session_id = .{0} ** 32;

        // Pre-encode transport params to avoid dangling slices after struct move
        var tp_fbs = io.fixedBufferStream(&self.tp_encoded);
        local_tp.encode(&tp_fbs) catch {};
        self.tp_encoded_len = tp_fbs.seek;

        // Generate X25519 key pair
        sys.randomBytes(&self.x25519_secret);
        self.x25519_public = X25519.recoverPublicKey(self.x25519_secret) catch blk: {
            // If key is bad (unlikely), regenerate
            sys.randomBytes(&self.x25519_secret);
            break :blk X25519.recoverPublicKey(self.x25519_secret) catch unreachable;
        };

        // Generate P-256 key pair (offered alongside X25519 in ClientHello)
        sys.randomBytes(&self.p256_secret);
        self.p256_public = (P256.basePoint.mulPublic(self.p256_secret, .big) catch blk: {
            sys.randomBytes(&self.p256_secret);
            break :blk P256.basePoint.mulPublic(self.p256_secret, .big) catch unreachable;
        }).toUncompressedSec1();
        self.negotiated_group = .x25519;
    }

    pub fn initClient(config: TlsConfig, local_tp: transport_params.TransportParams) Tls13Handshake {
        var self: Tls13Handshake = undefined;
        initClientInto(&self, config, local_tp);
        return self;
    }

    pub fn initServer(config: TlsConfig, local_tp: transport_params.TransportParams) Tls13Handshake {
        var self: Tls13Handshake = undefined;
        initServerInto(&self, config, local_tp);
        return self;
    }

    /// Builds the server handshake in place — see initClientInto.
    pub fn initServerInto(
        out: *Tls13Handshake,
        config: TlsConfig,
        local_tp: transport_params.TransportParams,
    ) void {
        const self = out;
        self.state = .server_wait_client_hello;
        self.is_server = true;
        self.transcript = TranscriptHash.init();
        self.key_schedule = KeySchedule.init();
        self.config = config;
        self.server_cert = if (config.certs.len > 0) config.certs[0].cert else .{
            .cert_chain_der = config.cert_chain_der,
            .private_key_bytes = config.private_key_bytes,
            .private_key_algorithm = config.private_key_algorithm,
        };
        self.local_transport_params = local_tp;
        self.peer_transport_params = null;
        self.out_len = 0;
        self.in_len = 0;
        self.in_offset = 0;
        self.pending_install_handshake = false;
        self.pending_install_app = false;
        self.pending_install_early = false;
        self.handshake_keys_installed = false;
        self.app_keys_installed = false;
        self.leaf_pub_key_len = 0;
        self.negotiated_cipher_suite = .aes_128_gcm_sha256;
        self.using_psk = false;
        self.certificate_requested = false;
        self.early_data_offered = false;
        self.selected_alpn_len = 0;
        self.zero_rtt_accepted = false;
        self.received_ticket = null;
        self.ticket_nonce_counter = 0;
        self.peer_session_id_len = 0;
        self.peer_session_id = .{0} ** 32;

        // Pre-encode transport params to avoid dangling slices after struct move
        var tp_fbs = io.fixedBufferStream(&self.tp_encoded);
        local_tp.encode(&tp_fbs) catch {};
        self.tp_encoded_len = tp_fbs.seek;

        // Generate X25519 key pair
        sys.randomBytes(&self.x25519_secret);
        self.x25519_public = X25519.recoverPublicKey(self.x25519_secret) catch blk: {
            sys.randomBytes(&self.x25519_secret);
            break :blk X25519.recoverPublicKey(self.x25519_secret) catch unreachable;
        };
        self.negotiated_group = .x25519;
    }

    // Provide incoming crypto stream data to the handshake.
    pub fn provideData(self: *Tls13Handshake, data: []const u8) void {
        // Compact buffer if we've consumed some data and need space
        if (self.in_offset > 0 and self.in_len - self.in_offset + data.len > self.in_buf.len - self.in_offset) {
            const remaining = self.in_len - self.in_offset;
            if (remaining > 0) {
                std.mem.copyForwards(u8, self.in_buf[0..remaining], self.in_buf[self.in_offset..self.in_len]);
            }
            self.in_len = remaining;
            self.in_offset = 0;
        }
        const available = self.in_buf.len - self.in_len;
        const copy_len = @min(data.len, available);
        @memcpy(self.in_buf[self.in_len..][0..copy_len], data[0..copy_len]);
        self.in_len += copy_len;
    }

    // Step the handshake state machine. Returns an action for the caller.
    // Call repeatedly until you get wait_for_data or complete.
    pub fn step(self: *Tls13Handshake) !Action {
        // If we need to install early (0-RTT) keys, do that first
        if (self.pending_install_early) {
            self.pending_install_early = false;
            const cs = self.negotiated_cipher_suite;
            const qv = self.config.quic_version;
            return Action{ .install_keys = .{
                .level = .early_data,
                .open = KeySchedule.makeOpenFull(self.key_schedule.client_early_traffic_secret, cs, qv),
                .seal = KeySchedule.makeSealFull(self.key_schedule.client_early_traffic_secret, cs, qv),
            } };
        }

        // If we need to install handshake keys, do that first
        // Handshake keys use the negotiated cipher suite (only Initial keys use AES-128-GCM)
        if (self.pending_install_handshake) {
            self.pending_install_handshake = false;
            self.handshake_keys_installed = true;
            const cs = self.negotiated_cipher_suite;
            const qv = self.config.quic_version;
            if (self.is_server) {
                return Action{ .install_keys = .{
                    .level = .handshake,
                    .open = KeySchedule.makeOpenFull(self.key_schedule.client_handshake_traffic_secret, cs, qv),
                    .seal = KeySchedule.makeSealFull(self.key_schedule.server_handshake_traffic_secret, cs, qv),
                } };
            } else {
                return Action{ .install_keys = .{
                    .level = .handshake,
                    .open = KeySchedule.makeOpenFull(self.key_schedule.server_handshake_traffic_secret, cs, qv),
                    .seal = KeySchedule.makeSealFull(self.key_schedule.client_handshake_traffic_secret, cs, qv),
                } };
            }
        }

        // If we need to install app keys, use the negotiated cipher suite
        if (self.pending_install_app) {
            self.pending_install_app = false;
            self.app_keys_installed = true;
            const cs = self.negotiated_cipher_suite;
            const qv = self.config.quic_version;
            if (self.is_server) {
                return Action{ .install_keys = .{
                    .level = .application,
                    .open = KeySchedule.makeOpenFull(self.key_schedule.client_app_traffic_secret, cs, qv),
                    .seal = KeySchedule.makeSealFull(self.key_schedule.server_app_traffic_secret, cs, qv),
                } };
            } else {
                return Action{ .install_keys = .{
                    .level = .application,
                    .open = KeySchedule.makeOpenFull(self.key_schedule.server_app_traffic_secret, cs, qv),
                    .seal = KeySchedule.makeSealFull(self.key_schedule.client_app_traffic_secret, cs, qv),
                } };
            }
        }

        switch (self.state) {
            .client_start => return self.clientBuildHello(),
            .client_wait_server_hello => return self.clientProcessServerHello(),
            .client_wait_encrypted_extensions => return self.clientProcessEncryptedExtensions(),
            .client_wait_certificate => {
                // If PSK was accepted, skip certificate and certificate_verify
                if (self.using_psk) {
                    self.state = .client_wait_finished;
                    return ._continue;
                }
                return self.clientProcessCertificate();
            },
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
            .server_send_ticket => return self.serverSendTicket(),

            .connected => {
                // Check for post-handshake messages
                if (self.readHandshakeMsg()) |msg| {
                    // RFC 9001 §6: KeyUpdate (24) MUST NOT be used in QUIC
                    if (msg[0] == 24) return error.UnexpectedMessage;
                    // RFC 9001 §8.3: EndOfEarlyData (5) MUST NOT be sent in QUIC
                    if (msg[0] == 5) return error.UnexpectedMessage;
                    if (!self.is_server and msg[0] == @intFromEnum(tls.HandshakeType.new_session_ticket)) {
                        self.parseNewSessionTicket(msg);
                        return ._continue;
                    }
                }
                return .complete;
            },
        }
    }

    pub fn isComplete(self: *const Tls13Handshake) bool {
        return self.state == .connected;
    }

    // ─── Client states ───────────────────────────────────────────────

    fn clientBuildHello(self: *Tls13Handshake) !Action {
        sys.randomBytes(&self.client_random);

        var buf: [4096]u8 = undefined;
        const msg = buildClientHello(
            &buf,
            &self.client_random,
            &self.x25519_public,
            &self.p256_public,
            self.config.alpn,
            self.config.server_name,
            self.tp_encoded[0..self.tp_encoded_len],
            self.config.session_ticket,
            &self.key_schedule,
            self.config.cipher_suite_only,
        ) catch return error.InternalError;

        self.transcript.update(msg);

        // If we have a session ticket, derive early data secret for 0-RTT
        if (self.config.session_ticket != null) {
            const transcript_hash = self.transcript.current();
            self.key_schedule.deriveEarlyDataSecret(transcript_hash);
            self.pending_install_early = true;

            // SSLKEYLOGFILE: write early traffic secret
            if (self.config.keylog_file) |f| {
                writeKeylogLine(f, "CLIENT_EARLY_TRAFFIC_SECRET", &self.client_random, &self.key_schedule.client_early_traffic_secret);
            }
        }

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

        if (msg[0] != @intFromEnum(tls.HandshakeType.server_hello)) return error.UnexpectedMessage;

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
        const cipher_suite_raw = readU16(body[pos..]);
        pos += 2;
        if (cipher_suite_raw == @intFromEnum(tls.CipherSuite.AES_128_GCM_SHA256)) {
            self.negotiated_cipher_suite = .aes_128_gcm_sha256;
        } else if (cipher_suite_raw == @intFromEnum(tls.CipherSuite.CHACHA20_POLY1305_SHA256)) {
            self.negotiated_cipher_suite = .chacha20_poly1305_sha256;
        } else {
            return error.UnsupportedVersion;
        }

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

            if (etype == @intFromEnum(tls.ExtensionType.key_share)) {
                // key_share: named_group(2) + key_exchange_length(2) + key_exchange(...)
                if (elen < 4) return error.DecodeError;
                const group = readU16(ext_data[ext_pos..]);
                const kelen = readU16(ext_data[ext_pos + 2 ..]);
                if (group == @intFromEnum(tls.NamedGroup.x25519) and kelen == 32 and ext_pos + 4 + 32 <= ext_data.len) {
                    @memcpy(&self.peer_x25519_public, ext_data[ext_pos + 4 ..][0..32]);
                    self.negotiated_group = .x25519;
                    found_key_share = true;
                } else if (group == @intFromEnum(tls.NamedGroup.secp256r1) and kelen == 65 and ext_pos + 4 + 65 <= ext_data.len) {
                    @memcpy(&self.peer_p256_public, ext_data[ext_pos + 4 ..][0..65]);
                    self.negotiated_group = .secp256r1;
                    found_key_share = true;
                } else {
                    return error.NoKeyShare;
                }
            } else if (etype == @intFromEnum(tls.ExtensionType.pre_shared_key)) {
                // Server accepted PSK: selected_identity(2) = 0x0000
                if (elen >= 2) {
                    const selected = readU16(ext_data[ext_pos..]);
                    if (selected == 0) {
                        self.using_psk = true;
                    }
                }
            }
            ext_pos += elen;
        }

        if (!found_key_share) return error.NoKeyShare;

        // Update transcript with ServerHello
        self.transcript.update(msg);

        // Compute shared secret based on negotiated group
        var shared_secret: [32]u8 = undefined;
        if (self.negotiated_group == .secp256r1) {
            const peer_point = P256.fromSec1(self.peer_p256_public[0..65]) catch return error.KeyScheduleError;
            const shared_point = peer_point.mulPublic(self.p256_secret, .big) catch return error.KeyScheduleError;
            const shared_uncompressed = shared_point.toUncompressedSec1();
            @memcpy(&shared_secret, shared_uncompressed[1..33]);
        } else {
            shared_secret = X25519.scalarmult(self.x25519_secret, self.peer_x25519_public) catch return error.KeyScheduleError;
        }

        // Derive handshake secrets
        const transcript_hash = self.transcript.current();
        self.key_schedule.deriveHandshakeSecrets(&shared_secret, transcript_hash);

        // SSLKEYLOGFILE: write handshake traffic secrets
        if (self.config.keylog_file) |f| {
            writeKeylogLine(f, "CLIENT_HANDSHAKE_TRAFFIC_SECRET", &self.client_random, &self.key_schedule.client_handshake_traffic_secret);
            writeKeylogLine(f, "SERVER_HANDSHAKE_TRAFFIC_SECRET", &self.client_random, &self.key_schedule.server_handshake_traffic_secret);
        }

        // Signal to install handshake keys
        self.pending_install_handshake = true;
        self.state = .client_wait_encrypted_extensions;
        return ._continue;
    }

    fn clientProcessEncryptedExtensions(self: *Tls13Handshake) !Action {
        const msg = self.readHandshakeMsg() orelse return .wait_for_data;

        if (msg[0] != @intFromEnum(tls.HandshakeType.encrypted_extensions)) return error.UnexpectedMessage;

        // Parse EncryptedExtensions to extract transport params + ALPN + early_data
        self.parseEncryptedExtensions(msg[4..]) catch {};

        // RFC 9001 §8.2: quic_transport_parameters extension MUST be present
        if (self.peer_transport_params == null) {
            return error.MissingExtension;
        }

        self.transcript.update(msg);
        self.state = .client_wait_certificate;
        return ._continue;
    }

    fn clientProcessCertificate(self: *Tls13Handshake) !Action {
        const msg = self.readHandshakeMsg() orelse return .wait_for_data;

        // RFC 8446 4.3.2: a server that wants a client certificate asks here,
        // between EncryptedExtensions and its own Certificate. Cloudflare's
        // edge does — `cdn.moq.dev` failed at this message — and refusing it
        // ends the handshake over a request we are allowed to decline.
        if (msg[0] == @intFromEnum(tls.HandshakeType.certificate_request)) {
            self.certificate_requested = true;
            self.transcript.update(msg);
            return ._continue;
        }

        if (msg[0] != @intFromEnum(tls.HandshakeType.certificate)) return error.UnexpectedMessage;

        const body = msg[4..];
        if (body.len < 4) return error.DecodeError;

        // Parse Certificate message body (RFC 8446 §4.4.2)
        const context_len = body[0];
        var pos: usize = 1 + context_len;
        if (pos + 3 > body.len) return error.DecodeError;

        const cert_list_len = (@as(usize, body[pos]) << 16) | (@as(usize, body[pos + 1]) << 8) | @as(usize, body[pos + 2]);
        pos += 3;

        if (pos + cert_list_len > body.len) return error.DecodeError;

        const cert_list_end = pos + cert_list_len;
        var cert_index: usize = 0;
        var prev_parsed: ?Certificate.Parsed = null;

        while (pos < cert_list_end) {
            if (pos + 3 > cert_list_end) return error.DecodeError;
            const cert_data_len = (@as(usize, body[pos]) << 16) | (@as(usize, body[pos + 1]) << 8) | @as(usize, body[pos + 2]);
            pos += 3;

            if (pos + cert_data_len > cert_list_end) return error.DecodeError;
            const cert_der = body[pos..][0..cert_data_len];
            pos += cert_data_len;

            // Skip per-certificate extensions
            if (pos + 2 > cert_list_end) return error.DecodeError;
            const ext_len = (@as(usize, body[pos]) << 8) | @as(usize, body[pos + 1]);
            pos += 2 + ext_len;

            if (self.config.cert_hashes) |hashes| {
                // Pinned by leaf fingerprint: only the leaf is examined, and
                // only to lift the public key CertificateVerify needs.
                if (cert_index == 0) {
                    const cert: Certificate = .{ .buffer = cert_der, .index = 0 };
                    const parsed = cert.parse() catch return error.BadCertificate;
                    const pub_key = parsed.pubKey();
                    if (pub_key.len <= self.leaf_pub_key_buf.len) {
                        @memcpy(self.leaf_pub_key_buf[0..pub_key.len], pub_key);
                        self.leaf_pub_key_len = @intCast(pub_key.len);
                        self.leaf_pub_key_algo = std.meta.activeTag(parsed.pub_key_algo);
                    }

                    var digest: [32]u8 = undefined;
                    std.crypto.hash.sha2.Sha256.hash(cert_der, &digest, .{});
                    var matched = false;
                    for (hashes) |h| {
                        if (std.mem.eql(u8, &h, &digest)) matched = true;
                    }
                    if (!matched) return error.BadCertificate;
                }
            } else if (!self.config.skip_cert_verify) {
                const cert: Certificate = .{ .buffer = cert_der, .index = 0 };
                const parsed = cert.parse() catch return error.BadCertificate;

                if (cert_index == 0) {
                    // Leaf cert: extract public key for CertificateVerify
                    const pub_key = parsed.pubKey();
                    if (pub_key.len <= self.leaf_pub_key_buf.len) {
                        @memcpy(self.leaf_pub_key_buf[0..pub_key.len], pub_key);
                        self.leaf_pub_key_len = @intCast(pub_key.len);
                        self.leaf_pub_key_algo = std.meta.activeTag(parsed.pub_key_algo);
                    }

                    // Verify hostname if SNI was set
                    if (self.config.server_name) |server_name| {
                        parsed.verifyHostName(server_name) catch return error.BadCertificate;
                    }
                }

                // Chain validation: verify each cert against its issuer
                if (prev_parsed) |prev| {
                    const now_sec = sys.realtimeSeconds();
                    prev.verify(parsed, now_sec) catch return error.BadCertificate;
                    if (!issuerConstraintsOk(cert_der, cert_index)) return error.BadCertificate;
                }

                // If this is the last cert, verify against CA bundle
                if (pos >= cert_list_end) {
                    if (self.config.ca_bundle) |bundle| {
                        const now_sec = sys.realtimeSeconds();
                        bundle.verify(parsed, now_sec) catch return error.BadCertificate;
                    }
                }

                prev_parsed = parsed;
            }

            cert_index += 1;
        }

        self.transcript.update(msg);
        self.state = .client_wait_certificate_verify;
        return ._continue;
    }

    fn clientProcessCertificateVerify(self: *Tls13Handshake) !Action {
        const msg = self.readHandshakeMsg() orelse return .wait_for_data;

        if (msg[0] != @intFromEnum(tls.HandshakeType.certificate_verify)) return error.UnexpectedMessage;

        if (!self.config.skip_cert_verify and self.leaf_pub_key_len > 0) {
            // Get transcript hash BEFORE updating with CertificateVerify
            const transcript_hash = self.transcript.current();

            const body = msg[4..];
            if (body.len < 4) return error.DecodeError;

            const sig_algo = (@as(u16, body[0]) << 8) | @as(u16, body[1]);
            const sig_len = (@as(usize, body[2]) << 8) | @as(usize, body[3]);
            if (body.len < 4 + sig_len) return error.DecodeError;
            const sig_bytes = body[4..][0..sig_len];

            // Build signed content: 64 spaces + label + 0x00 + transcript_hash
            const label = "TLS 1.3, server CertificateVerify";
            var signed_content: [64 + label.len + 1 + 32]u8 = undefined;
            @memset(signed_content[0..64], 0x20);
            @memcpy(signed_content[64..][0..label.len], label);
            signed_content[64 + label.len] = 0x00;
            @memcpy(signed_content[64 + label.len + 1 ..][0..32], &transcript_hash);

            verifyCertificateVerifySignature(
                self.leaf_pub_key_buf[0..self.leaf_pub_key_len],
                self.leaf_pub_key_algo,
                sig_algo,
                sig_bytes,
                &signed_content,
            ) catch return error.BadCertificateVerify;
        }

        self.transcript.update(msg);
        self.state = .client_wait_finished;
        return ._continue;
    }

    fn clientProcessFinished(self: *Tls13Handshake) !Action {
        const msg = self.readHandshakeMsg() orelse return .wait_for_data;

        if (msg[0] != @intFromEnum(tls.HandshakeType.finished)) return error.UnexpectedMessage;

        const body = msg[4..];
        if (body.len != 32) return error.BadFinished;

        // Verify server Finished
        const transcript_hash = self.transcript.current();
        const expected = KeySchedule.computeFinishedVerifyData(
            self.key_schedule.server_handshake_traffic_secret,
            transcript_hash,
        );

        // Constant-time MAC compare (RFC 8446 §4.4.4). Length is public
        // (fixed by the cipher suite hash), the verify_data is secret.
        if (body.len != expected.len or
            !crypto.timing_safe.eql([expected.len]u8, body[0..expected.len].*, expected)) return error.BadFinished;

        // Update transcript with server Finished
        self.transcript.update(msg);

        // Save transcript hash for app key derivation
        self.transcript_at_server_finished = self.transcript.current();

        // Derive application secrets
        self.key_schedule.deriveAppSecrets(self.transcript_at_server_finished);
        self.pending_install_app = true;

        // SSLKEYLOGFILE: write application traffic secrets
        if (self.config.keylog_file) |f| {
            writeKeylogLine(f, "CLIENT_TRAFFIC_SECRET_0", &self.client_random, &self.key_schedule.client_app_traffic_secret);
            writeKeylogLine(f, "SERVER_TRAFFIC_SECRET_0", &self.client_random, &self.key_schedule.server_app_traffic_secret);
        }

        self.state = .client_send_finished;
        return ._continue;
    }

    fn clientSendFinished(self: *Tls13Handshake) !Action {
        var pos: usize = 0;

        // RFC 8446 4.4.2: having been asked, the client answers even with
        // nothing to offer — an empty certificate_list, and no
        // CertificateVerify to go with it. The context is zero length:
        // 4.3.2 only allows a non-empty one for post-handshake auth, which
        // RFC 9001 4.4 forbids over QUIC anyway.
        if (self.certificate_requested) {
            const empty_cert = [_]u8{
                @intFromEnum(tls.HandshakeType.certificate),
                0, 0, 4, // length
                0, // certificate_request_context length
                0, 0, 0, // certificate_list length
            };
            self.transcript.update(&empty_cert);
            @memcpy(self.out_buf[pos..][0..empty_cert.len], &empty_cert);
            pos += empty_cert.len;
        }

        // Compute client Finished
        const transcript_hash = self.transcript.current();
        const verify_data = KeySchedule.computeFinishedVerifyData(
            self.key_schedule.client_handshake_traffic_secret,
            transcript_hash,
        );

        // Build Finished message: type(1) + length(3) + verify_data(32)
        var msg: [36]u8 = undefined;
        msg[0] = @intFromEnum(tls.HandshakeType.finished);
        msg[1] = 0;
        msg[2] = 0;
        msg[3] = 32;
        @memcpy(msg[4..][0..32], &verify_data);

        self.transcript.update(&msg);

        @memcpy(self.out_buf[pos..][0..36], &msg);
        self.out_len = pos + 36;

        self.state = .connected;
        return Action{ .send_data = .{
            .level = .handshake,
            .data = self.out_buf[0..self.out_len],
        } };
    }

    // ─── Server states ───────────────────────────────────────────────

    fn serverProcessClientHello(self: *Tls13Handshake) !Action {
        const msg = self.readHandshakeMsg() orelse return .wait_for_data;

        if (msg[0] != @intFromEnum(tls.HandshakeType.client_hello)) return error.UnexpectedMessage;

        const body = msg[4..];
        if (body.len < 2 + 32 + 1) return error.DecodeError;

        var pos: usize = 0;
        pos += 2; // legacy_version
        @memcpy(&self.client_random, body[pos..][0..32]);
        pos += 32;

        const session_id_len = body[pos];
        pos += 1;
        // Save peer's legacy_session_id for ServerHello echo (RFC 8446 §4.1.3)
        if (session_id_len > 0 and session_id_len <= 32) {
            self.peer_session_id_len = session_id_len;
            @memcpy(self.peer_session_id[0..session_id_len], body[pos..][0..session_id_len]);
            std.log.info("ClientHello: legacy_session_id len={d}", .{session_id_len});
        }
        pos += session_id_len; // skip session_id

        // Cipher suites — select the best one we support
        if (pos + 2 > body.len) return error.DecodeError;
        const cs_len = readU16(body[pos..]);
        pos += 2;
        {
            var cs_found = false;
            var cs_pos: usize = 0;
            while (cs_pos + 2 <= cs_len) : (cs_pos += 2) {
                const cs_id = readU16(body[pos + cs_pos ..]);
                // If cipher_suite_only is set, only accept that cipher
                if (self.config.cipher_suite_only) |required| {
                    if (cs_id == @intFromEnum(required)) {
                        self.negotiated_cipher_suite = required;
                        cs_found = true;
                        break;
                    }
                } else {
                    if (cs_id == @intFromEnum(tls.CipherSuite.AES_128_GCM_SHA256) and !cs_found) {
                        self.negotiated_cipher_suite = .aes_128_gcm_sha256;
                        cs_found = true;
                    } else if (cs_id == @intFromEnum(tls.CipherSuite.CHACHA20_POLY1305_SHA256) and !cs_found) {
                        self.negotiated_cipher_suite = .chacha20_poly1305_sha256;
                        cs_found = true;
                    }
                }
            }
            if (!cs_found) return error.UnsupportedVersion;
        }
        pos += cs_len;

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
        var psk_ext_offset: ?usize = null; // offset into ext_data where PSK extension starts
        var psk_ext_len: usize = 0;
        var ext_pos: usize = 0;
        const ext_data = body[pos..][0..@min(ext_len, body.len - pos)];
        while (ext_pos + 4 <= ext_data.len) {
            const etype = readU16(ext_data[ext_pos..]);
            ext_pos += 2;
            const elen = readU16(ext_data[ext_pos..]);
            ext_pos += 2;

            if (ext_pos + elen > ext_data.len) break;

            if (etype == @intFromEnum(tls.ExtensionType.key_share)) {
                // client_shares_len(2) + [named_group(2) + key_len(2) + key(...)]
                // Prefer X25519, fall back to secp256r1 (P-256)
                if (elen >= 2) {
                    var found_p256 = false;
                    var share_pos: usize = 2; // skip client_shares_len
                    while (share_pos + 4 <= elen) {
                        const group = readU16(ext_data[ext_pos + share_pos ..]);
                        const kelen = readU16(ext_data[ext_pos + share_pos + 2 ..]);
                        share_pos += 4;
                        if (group == @intFromEnum(tls.NamedGroup.x25519) and kelen == 32 and share_pos + 32 <= elen) {
                            @memcpy(&self.peer_x25519_public, ext_data[ext_pos + share_pos ..][0..32]);
                            self.negotiated_group = .x25519;
                            found_key_share = true;
                            break;
                        } else if (group == @intFromEnum(tls.NamedGroup.secp256r1) and kelen == 65 and share_pos + 65 <= elen) {
                            @memcpy(&self.peer_p256_public, ext_data[ext_pos + share_pos ..][0..65]);
                            found_p256 = true;
                        }
                        share_pos += kelen;
                    }
                    // Use P-256 if X25519 not found
                    if (!found_key_share and found_p256) {
                        self.negotiated_group = .secp256r1;
                        found_key_share = true;
                    }
                }
            } else if (etype == @intFromEnum(tls.ExtensionType.quic_transport_parameters)) {
                const tp_data = ext_data[ext_pos..][0..elen];
                self.peer_transport_params = transport_params.TransportParams.decode(tp_data) catch {
                    return error.TransportParameterError;
                };
            } else if (etype == @intFromEnum(tls.ExtensionType.application_layer_protocol_negotiation)) {
                // Parse client's ALPN list and try to match with our configured ALPNs
                if (elen >= 2) {
                    const list_len = readU16(ext_data[ext_pos..]);
                    var alpn_pos: usize = 2;
                    var matched = false;
                    while (alpn_pos < 2 + list_len and alpn_pos + 1 <= elen) {
                        const proto_len = ext_data[ext_pos + alpn_pos];
                        alpn_pos += 1;
                        if (alpn_pos + proto_len > elen) break;
                        const proto = ext_data[ext_pos + alpn_pos ..][0..proto_len];
                        for (self.config.alpn) |our_proto| {
                            if (std.mem.eql(u8, proto, our_proto)) {
                                matched = true;
                                const n = @min(proto.len, self.selected_alpn.len);
                                @memcpy(self.selected_alpn[0..n], proto[0..n]);
                                self.selected_alpn_len = n;
                                break;
                            }
                        }
                        if (matched) break;
                        alpn_pos += proto_len;
                    }
                    if (!matched and self.config.alpn.len > 0) {
                        return error.NoApplicationProtocol;
                    }
                }
            } else if (etype == @intFromEnum(tls.ExtensionType.pre_shared_key)) {
                // PSK extension must be the last one (RFC 8446 §4.2.11)
                psk_ext_offset = ext_pos;
                psk_ext_len = elen;
            } else if (etype == @intFromEnum(tls.ExtensionType.early_data)) {
                self.early_data_offered = true;
            } else if (etype == @intFromEnum(tls.ExtensionType.server_name) and self.config.certs.len > 0) {
                const sni = parseServerNameExtension(ext_data[ext_pos..][0..elen]) catch return error.DecodeError;
                self.server_cert = selectCertificate(self.config.certs, sni).?.entry.cert;
            }
            ext_pos += elen;
        }

        if (!found_key_share) return error.NoKeyShare;

        // RFC 9001 §8.2: quic_transport_parameters extension MUST be present
        if (self.peer_transport_params == null) {
            return error.MissingExtension;
        }

        // Try to process PSK extension if present and we have a ticket key
        if (psk_ext_offset != null and self.config.ticket_key != null) {
            std.log.info("PSK extension found, attempting PSK processing", .{});
            self.tryProcessPsk(msg, body, pos, ext_data, psk_ext_offset.?, psk_ext_len);
            if (self.using_psk) {
                std.log.info("PSK accepted, using resumption", .{});
            } else {
                std.log.info("PSK rejected, full handshake", .{});
            }
        }

        // Update transcript with ClientHello
        self.transcript.update(msg);
        std.log.info("transcript after CH: {x}", .{self.transcript.current()});

        // If PSK accepted, derive early data secret for 0-RTT decryption
        if (self.using_psk) {
            const transcript_hash = self.transcript.current();
            self.key_schedule.deriveEarlyDataSecret(transcript_hash);
            self.pending_install_early = true;

            // SSLKEYLOGFILE: write early traffic secret
            if (self.config.keylog_file) |f| {
                writeKeylogLine(f, "CLIENT_EARLY_TRAFFIC_SECRET", &self.client_random, &self.key_schedule.client_early_traffic_secret);
            }
        }

        // RFC 9368: Compatible Version Negotiation
        // If client sent version_information advertising v2 and we support v2, switch.
        if (self.peer_transport_params) |peer_tp| {
            if (peer_tp.version_info_chosen != null and self.local_transport_params.version_info_chosen != null) {
                // Check if client supports v2 and we do too
                if (peer_tp.hasAvailableVersion(protocol.QUIC_V2) and
                    self.local_transport_params.hasAvailableVersion(protocol.QUIC_V2))
                {
                    std.log.info("compatible version negotiation: switching to QUIC v2", .{});
                    self.config.quic_version = protocol.QUIC_V2;
                    // Update our version_information to reflect the chosen version
                    self.local_transport_params.version_info_chosen = protocol.QUIC_V2;
                    // Re-encode transport params so EncryptedExtensions carries the updated chosen_version
                    var tp_fbs = io.fixedBufferStream(&self.tp_encoded);
                    self.local_transport_params.encode(&tp_fbs) catch {};
                    self.tp_encoded_len = tp_fbs.seek;
                }
            }
        }

        self.state = .server_send_server_hello;
        return ._continue;
    }

    fn serverBuildServerHello(self: *Tls13Handshake) !Action {
        sys.randomBytes(&self.server_random);

        // Prepare key share based on negotiated group
        var ks_data_buf: [65]u8 = undefined;
        const ks_data: []const u8 = if (self.negotiated_group == .secp256r1) blk: {
            // Generate P-256 ephemeral key pair
            sys.randomBytes(&self.p256_secret);
            self.p256_public = (P256.basePoint.mulPublic(self.p256_secret, .big) catch return error.KeyScheduleError).toUncompressedSec1();
            @memcpy(&ks_data_buf, &self.p256_public);
            break :blk ks_data_buf[0..65];
        } else blk: {
            @memcpy(ks_data_buf[0..32], &self.x25519_public);
            break :blk ks_data_buf[0..32];
        };

        var buf: [512]u8 = undefined;
        const msg = buildServerHello(
            &buf,
            &self.server_random,
            self.negotiated_group,
            ks_data,
            self.peer_session_id[0..self.peer_session_id_len],
            self.using_psk,
            self.negotiated_cipher_suite,
        ) catch return error.InternalError;

        self.transcript.update(msg);
        std.log.info("server transcript after SH ({d} bytes): {x}", .{ msg.len, self.transcript.current() });

        // Compute shared secret based on negotiated group
        var shared_secret: [32]u8 = undefined;
        if (self.negotiated_group == .secp256r1) {
            // P-256 ECDH: multiply peer's public key by our secret
            const peer_point = P256.fromSec1(self.peer_p256_public[0..65]) catch return error.KeyScheduleError;
            const shared_point = peer_point.mulPublic(self.p256_secret, .big) catch return error.KeyScheduleError;
            // Extract X coordinate (bytes 1..33 of uncompressed point)
            const shared_uncompressed = shared_point.toUncompressedSec1();
            @memcpy(&shared_secret, shared_uncompressed[1..33]);
        } else {
            shared_secret = X25519.scalarmult(self.x25519_secret, self.peer_x25519_public) catch return error.KeyScheduleError;
        }

        // Derive handshake secrets
        const transcript_hash = self.transcript.current();
        self.key_schedule.deriveHandshakeSecrets(&shared_secret, transcript_hash);

        // SSLKEYLOGFILE: write handshake traffic secrets
        if (self.config.keylog_file) |f| {
            writeKeylogLine(f, "CLIENT_HANDSHAKE_TRAFFIC_SECRET", &self.client_random, &self.key_schedule.client_handshake_traffic_secret);
            writeKeylogLine(f, "SERVER_HANDSHAKE_TRAFFIC_SECRET", &self.client_random, &self.key_schedule.server_handshake_traffic_secret);
        }

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
        const msg = buildEncryptedExtensionsFromEncoded(
            &buf,
            self.config.alpn,
            self.tp_encoded[0..self.tp_encoded_len],
            self.zero_rtt_accepted, // early_data only answers a client that asked
        ) catch return error.InternalError;

        self.transcript.update(msg);
        {
            var ee_sha: [32]u8 = undefined;
            crypto.hash.sha2.Sha256.hash(msg, &ee_sha, .{});
            std.log.info("transcript after EE ({d} bytes): {x}, msg_sha256={x}", .{ msg.len, self.transcript.current(), ee_sha });
        }

        @memcpy(self.out_buf[0..msg.len], msg);
        self.out_len = msg.len;

        // If PSK was accepted, skip certificate and certificate_verify
        if (self.using_psk) {
            self.state = .server_send_finished;
        } else {
            self.state = .server_send_certificate;
        }
        return Action{ .send_data = .{
            .level = .handshake,
            .data = self.out_buf[0..self.out_len],
        } };
    }

    fn serverBuildCertificate(self: *Tls13Handshake) !Action {
        // Built straight into out_buf: a local of the same size would be a
        // 32 KB stack duplicate of a field we already own.
        const msg = buildCertificate(&self.out_buf, self.server_cert.cert_chain_der) catch return error.InternalError;
        self.out_len = msg.len;

        self.transcript.update(msg);
        {
            var cert_sha: [32]u8 = undefined;
            crypto.hash.sha2.Sha256.hash(msg, &cert_sha, .{});
            std.log.info("transcript after Cert ({d} bytes): {x}, msg_sha256={x}", .{ msg.len, self.transcript.current(), cert_sha });
        }

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
            self.server_cert.private_key_bytes,
            self.server_cert.private_key_algorithm,
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
        msg[0] = @intFromEnum(tls.HandshakeType.finished);
        msg[1] = 0;
        msg[2] = 0;
        msg[3] = 32;
        @memcpy(msg[4..][0..32], &verify_data);

        self.transcript.update(&msg);

        // Save transcript for app keys
        self.transcript_at_server_finished = self.transcript.current();
        self.key_schedule.deriveAppSecrets(self.transcript_at_server_finished);
        self.pending_install_app = true;

        // SSLKEYLOGFILE: write application traffic secrets
        if (self.config.keylog_file) |f| {
            writeKeylogLine(f, "CLIENT_TRAFFIC_SECRET_0", &self.client_random, &self.key_schedule.client_app_traffic_secret);
            writeKeylogLine(f, "SERVER_TRAFFIC_SECRET_0", &self.client_random, &self.key_schedule.server_app_traffic_secret);
        }

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

        if (msg[0] != @intFromEnum(tls.HandshakeType.finished)) return error.UnexpectedMessage;

        const body = msg[4..];
        if (body.len != 32) return error.BadFinished;

        // Verify client Finished
        const transcript_hash = self.transcript.current();
        const expected = KeySchedule.computeFinishedVerifyData(
            self.key_schedule.client_handshake_traffic_secret,
            transcript_hash,
        );

        // Constant-time MAC compare (RFC 8446 §4.4.4). Length is public
        // (fixed by the cipher suite hash), the verify_data is secret.
        if (body.len != expected.len or
            !crypto.timing_safe.eql([expected.len]u8, body[0..expected.len].*, expected)) return error.BadFinished;

        self.transcript.update(msg);

        // If we have a ticket key, send a NewSessionTicket before completing
        if (self.config.ticket_key != null) {
            self.state = .server_send_ticket;
            return ._continue;
        }

        self.state = .connected;
        return .complete;
    }

    // ─── Server: Send NewSessionTicket ──────────────────────────────

    fn serverSendTicket(self: *Tls13Handshake) !Action {
        const ticket_key = self.config.ticket_key orelse return error.InternalError;

        // Derive resumption master secret
        const transcript_hash = self.transcript.current();
        self.key_schedule.deriveResumptionMasterSecret(transcript_hash);

        // Generate ticket nonce
        var nonce_buf: [4]u8 = undefined;
        std.mem.writeInt(u32, &nonce_buf, self.ticket_nonce_counter, .big);
        self.ticket_nonce_counter += 1;

        // PSK = HKDF-Expand-Label(resumption_master_secret, "resumption", ticket_nonce, 32)
        const psk = quic_crypto.hkdfExpandLabel(self.key_schedule.resumption_master_secret, "resumption", &nonce_buf, 32);

        // Generate random ticket_age_add
        var ticket_age_add_bytes: [4]u8 = undefined;
        sys.randomBytes(&ticket_age_add_bytes);
        const ticket_age_add = std.mem.readInt(u32, &ticket_age_add_bytes, .big);

        // Build ticket plaintext: psk(32) || creation_time(8) || alpn_len(1) || alpn
        var ticket_plain: [64]u8 = .{0} ** 64;
        @memcpy(ticket_plain[0..32], &psk);
        const now_sec = sys.realtimeSeconds();
        std.mem.writeInt(i64, ticket_plain[32..40], now_sec, .big);
        const alpn_bytes = self.negotiatedAlpn();
        const alpn_copy_len: u8 = @intCast(@min(alpn_bytes.len, 16));
        ticket_plain[40] = alpn_copy_len;
        @memcpy(ticket_plain[41..][0..alpn_copy_len], alpn_bytes[0..alpn_copy_len]);
        const plaintext_len = 41 + @as(usize, alpn_copy_len);

        // Encrypt ticket with AES-128-GCM using ticket_key
        var nonce_for_ticket: [12]u8 = .{0} ** 12;
        @memcpy(nonce_for_ticket[8..12], &nonce_buf);
        var encrypted_ticket: [80]u8 = undefined; // plaintext + 16 tag
        var tag: [16]u8 = undefined;
        Aes128Gcm.encrypt(
            encrypted_ticket[0..plaintext_len],
            &tag,
            ticket_plain[0..plaintext_len],
            "",
            nonce_for_ticket,
            ticket_key,
        );
        @memcpy(encrypted_ticket[plaintext_len..][0..16], &tag);
        const encrypted_len = plaintext_len + 16;

        // Build NewSessionTicket message (RFC 8446 §4.6.1):
        // type(1) + length(3) + lifetime(4) + ticket_age_add(4) + nonce_len(1) + nonce(4) +
        // ticket_len(2) + ticket(N) + extensions_len(2) + early_data_ext(type=42, len=2+4, max=0xffffffff)
        const lifetime: u32 = 7 * 24 * 3600; // 7 days
        const ext_data_len: u16 = 4 + 4; // type(2) + len(2) + max_early_data(4)
        const nst_body_len: u24 = @intCast(4 + 4 + 1 + 4 + 2 + encrypted_len + 2 + ext_data_len);

        var nst: [256]u8 = undefined;
        var nst_pos: usize = 0;

        nst[0] = @intFromEnum(tls.HandshakeType.new_session_ticket);
        nst[1] = @intCast(nst_body_len >> 16);
        nst[2] = @intCast((nst_body_len >> 8) & 0xff);
        nst[3] = @intCast(nst_body_len & 0xff);
        nst_pos = 4;

        // lifetime
        std.mem.writeInt(u32, nst[nst_pos..][0..4], lifetime, .big);
        nst_pos += 4;

        // ticket_age_add
        std.mem.writeInt(u32, nst[nst_pos..][0..4], ticket_age_add, .big);
        nst_pos += 4;

        // nonce
        nst[nst_pos] = 4; // nonce length
        nst_pos += 1;
        @memcpy(nst[nst_pos..][0..4], &nonce_buf);
        nst_pos += 4;

        // ticket
        writeU16(nst[nst_pos..], @intCast(encrypted_len));
        nst_pos += 2;
        @memcpy(nst[nst_pos..][0..encrypted_len], encrypted_ticket[0..encrypted_len]);
        nst_pos += encrypted_len;

        // extensions: early_data with max_early_data_size = 0xffffffff
        writeU16(nst[nst_pos..], ext_data_len);
        nst_pos += 2;
        writeU16(nst[nst_pos..], @intFromEnum(tls.ExtensionType.early_data));
        nst_pos += 2;
        writeU16(nst[nst_pos..], 4); // extension data length
        nst_pos += 2;
        std.mem.writeInt(u32, nst[nst_pos..][0..4], 0xffffffff, .big);
        nst_pos += 4;

        @memcpy(self.out_buf[0..nst_pos], nst[0..nst_pos]);
        self.out_len = nst_pos;

        self.state = .connected;
        return Action{ .send_data = .{
            .level = .application,
            .data = self.out_buf[0..self.out_len],
        } };
    }

    // ─── Server: Try to process PSK from ClientHello ────────────────

    fn tryProcessPsk(
        self: *Tls13Handshake,
        msg: []const u8,
        body: []const u8,
        ext_start_in_body: usize,
        ext_data: []const u8,
        psk_ext_offset: usize,
        psk_ext_len: usize,
    ) void {
        const ticket_key = self.config.ticket_key orelse return;

        if (psk_ext_len < 6) return;
        const psk_data = ext_data[psk_ext_offset..][0..psk_ext_len];

        // Parse identities list
        const identities_len = readU16(psk_data[0..]);
        if (2 + identities_len > psk_ext_len) return;

        // Parse first identity
        var id_pos: usize = 2;
        if (id_pos + 2 > 2 + identities_len) return;
        const identity_len = readU16(psk_data[id_pos..]);
        id_pos += 2;
        if (id_pos + identity_len + 4 > 2 + identities_len) return;
        const identity = psk_data[id_pos..][0..identity_len];

        // Parse binders list (after identities)
        var binders_start: usize = 2 + identities_len;
        if (binders_start + 2 > psk_ext_len) return;
        const binders_len = readU16(psk_data[binders_start..]);
        binders_start += 2;
        if (binders_start + binders_len > psk_ext_len) return;

        // First binder
        if (binders_start >= psk_ext_len) return;
        const binder_len = psk_data[binders_start];
        if (binder_len != 32) return;
        if (binders_start + 1 + 32 > psk_ext_len) return;
        const received_binder = psk_data[binders_start + 1 ..][0..32];

        // Decrypt ticket identity to get PSK
        if (identity_len < 16 + 1) return; // at least tag + 1 byte
        const ciphertext_len = identity_len - 16;

        // Reconstruct nonce from ticket (we use the last 4 bytes of identity as hint)
        var ticket_nonce: [12]u8 = .{0} ** 12;
        // Use zeros as nonce — server encrypts with incrementing nonce_buf in [8..12]
        // We need to try nonce counter values. For simplicity, try a few.
        var decrypted: [64]u8 = undefined;
        var psk_found = false;
        var found_psk: [32]u8 = undefined;

        for (0..256) |nonce_try| {
            std.mem.writeInt(u32, ticket_nonce[8..12], @intCast(nonce_try), .big);
            var ct_copy: [80]u8 = undefined;
            @memcpy(ct_copy[0..identity_len], identity[0..identity_len]);
            const tag_start = ciphertext_len;
            const tag: [16]u8 = ct_copy[tag_start..][0..16].*;

            Aes128Gcm.decrypt(
                decrypted[0..ciphertext_len],
                ct_copy[0..ciphertext_len],
                tag,
                "",
                ticket_nonce,
                ticket_key,
            ) catch continue;

            // Decrypted successfully
            if (ciphertext_len >= 32) {
                @memcpy(&found_psk, decrypted[0..32]);
                psk_found = true;
                break;
            }
        }

        if (!psk_found) return;

        // Compute binder key from PSK WITHOUT modifying self.key_schedule yet
        // (if binder fails, we must leave key_schedule untouched)
        const temp_ks = KeySchedule.initWithPsk(found_psk);

        // Verify binder
        // binder_key = Derive-Secret(early_secret, "res binder", Hash(""))
        const empty_hash = tls.emptyHash(Sha256);
        const binder_key = quic_crypto.hkdfExpandLabel(temp_ks.early_secret, "res binder", &empty_hash, 32);

        // Partial ClientHello = up to and including identities field (RFC 8446 §4.2.11.2)
        // Exclude: binders_len_field(2) + binder_entries(binders_len)
        const partial_len = msg.len - @as(usize, binders_len) - 2;
        _ = body;
        _ = ext_start_in_body;

        var partial_hash: Sha256 = Sha256.init(.{});
        partial_hash.update(msg[0..partial_len]);
        var partial_transcript = partial_hash.finalResult();

        const expected_binder = KeySchedule.computeFinishedVerifyData(binder_key, partial_transcript);
        _ = &partial_transcript;

        // Constant-time compare of the PSK binder HMAC (RFC 8446 §4.2.11.2).
        if (!crypto.timing_safe.eql([expected_binder.len]u8, received_binder.*, expected_binder)) {
            std.log.warn("PSK binder verification failed, falling back to full handshake", .{});
            return;
        }

        // Binder verified — now safe to install PSK key schedule
        self.key_schedule = temp_ks;
        self.using_psk = true;
        self.zero_rtt_accepted = self.early_data_offered;
        std.log.info("PSK resumption accepted (0-RTT {s})", .{
            if (self.zero_rtt_accepted) @as([]const u8, "enabled") else "not offered",
        });
    }

    // ─── Client: Parse NewSessionTicket ──────────────────────────────

    fn parseNewSessionTicket(self: *Tls13Handshake, msg: []const u8) void {
        const body = msg[4..];
        if (body.len < 13) return; // minimum: lifetime(4) + age_add(4) + nonce_len(1) + nonce(>=0) + ticket_len(2)

        var pos: usize = 0;
        const lifetime = std.mem.readInt(u32, body[pos..][0..4], .big);
        pos += 4;
        const ticket_age_add = std.mem.readInt(u32, body[pos..][0..4], .big);
        pos += 4;

        const nonce_len = body[pos];
        pos += 1;
        if (pos + nonce_len > body.len) return;
        const nonce_data = body[pos..][0..nonce_len];
        pos += nonce_len;

        if (pos + 2 > body.len) return;
        const ticket_len = readU16(body[pos..]);
        pos += 2;
        if (pos + ticket_len > body.len) return;
        const ticket_data = body[pos..][0..ticket_len];
        pos += ticket_len;

        // Parse extensions
        var max_early_data: u32 = 0;
        if (pos + 2 <= body.len) {
            const ext_len = readU16(body[pos..]);
            pos += 2;
            var ext_pos: usize = 0;
            const ext_end = @min(pos + ext_len, body.len);
            const ext_buf = body[pos..ext_end];
            while (ext_pos + 4 <= ext_buf.len) {
                const etype = readU16(ext_buf[ext_pos..]);
                ext_pos += 2;
                const elen = readU16(ext_buf[ext_pos..]);
                ext_pos += 2;
                if (ext_pos + elen > ext_buf.len) break;
                if (etype == @intFromEnum(tls.ExtensionType.early_data) and elen >= 4) {
                    max_early_data = std.mem.readInt(u32, ext_buf[ext_pos..][0..4], .big);
                }
                ext_pos += elen;
            }
        }

        // Derive PSK from resumption_master_secret + nonce
        // First compute resumption_master_secret if not yet done
        if (!self.key_schedule.computed_app) return;
        const full_transcript = self.transcript.current();
        self.key_schedule.deriveResumptionMasterSecret(full_transcript);

        const psk = quic_crypto.hkdfExpandLabel(self.key_schedule.resumption_master_secret, "resumption", nonce_data, 32);

        var ticket: SessionTicket = .{ .psk = psk };
        ticket.lifetime = lifetime;
        ticket.ticket_age_add = ticket_age_add;
        ticket.creation_time = sys.realtimeSeconds();
        ticket.max_early_data_size = max_early_data;

        const copy_len: u16 = @intCast(@min(ticket_data.len, ticket.ticket.len));
        @memcpy(ticket.ticket[0..copy_len], ticket_data[0..copy_len]);
        ticket.ticket_len = copy_len;

        // Store ALPN from config
        if (self.config.alpn.len > 0) {
            const alpn_src = self.config.alpn[0];
            const alpn_copy: u8 = @intCast(@min(alpn_src.len, 16));
            @memcpy(ticket.alpn[0..alpn_copy], alpn_src[0..alpn_copy]);
            ticket.alpn_len = alpn_copy;
        }

        // RFC 9000 §7.4.1: remember server's transport params for 0-RTT resumption
        if (self.peer_transport_params) |peer_tp| {
            ticket.initial_max_data = peer_tp.initial_max_data;
            ticket.initial_max_stream_data_bidi_local = peer_tp.initial_max_stream_data_bidi_local;
            ticket.initial_max_stream_data_bidi_remote = peer_tp.initial_max_stream_data_bidi_remote;
            ticket.initial_max_stream_data_uni = peer_tp.initial_max_stream_data_uni;
            ticket.initial_max_streams_bidi = peer_tp.initial_max_streams_bidi;
            ticket.initial_max_streams_uni = peer_tp.initial_max_streams_uni;
            ticket.active_connection_id_limit = peer_tp.active_connection_id_limit;
        }

        self.received_ticket = ticket;
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

            if (etype == @intFromEnum(tls.ExtensionType.quic_transport_parameters)) {
                const tp_data = ext_data[ext_pos..][0..elen];
                self.peer_transport_params = transport_params.TransportParams.decode(tp_data) catch {
                    return error.TransportParameterError;
                };
            } else if (etype == @intFromEnum(tls.ExtensionType.early_data)) {
                // Server accepted early data (0-RTT)
                self.zero_rtt_accepted = true;
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
    p256_pub: *const [65]u8,
    alpn_list: []const []const u8,
    server_name: ?[]const u8,
    tp_encoded_data: []const u8,
    session_ticket: ?*const SessionTicket,
    key_schedule: *KeySchedule,
    cipher_suite_only: ?quic_crypto.CipherSuite,
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

    // cipher_suites
    if (cipher_suite_only) |cs| {
        // Offer only the specified cipher suite (e.g., for chacha20 interop test)
        writeU16(buf[pos..], 2);
        pos += 2;
        writeU16(buf[pos..], @intFromEnum(cs));
        pos += 2;
    } else {
        // Offer both AES-128-GCM and ChaCha20-Poly1305
        writeU16(buf[pos..], 4);
        pos += 2;
        writeU16(buf[pos..], @intFromEnum(tls.CipherSuite.AES_128_GCM_SHA256));
        pos += 2;
        writeU16(buf[pos..], @intFromEnum(tls.CipherSuite.CHACHA20_POLY1305_SHA256));
        pos += 2;
    }

    // compression_methods: 1 byte length + null compression
    buf[pos] = 1;
    pos += 1;
    buf[pos] = 0;
    pos += 1;

    // Extensions
    const ext_start = pos;
    pos += 2; // extensions length placeholder

    // supported_versions extension
    pos = writeExtHeader(buf, pos, @intFromEnum(tls.ExtensionType.supported_versions), 3);
    buf[pos] = 2; // list length
    pos += 1;
    writeU16(buf[pos..], @intFromEnum(tls.ProtocolVersion.tls_1_3));
    pos += 2;

    // key_share extension (X25519 + P-256)
    const x25519_share_len = 2 + 2 + 32; // group(2) + len(2) + key(32)
    const p256_share_len = 2 + 2 + 65; // group(2) + len(2) + key(65)
    const shares_total: u16 = x25519_share_len + p256_share_len;
    pos = writeExtHeader(buf, pos, @intFromEnum(tls.ExtensionType.key_share), 2 + shares_total);
    writeU16(buf[pos..], shares_total); // client_shares length
    pos += 2;
    // X25519 share (preferred)
    writeU16(buf[pos..], @intFromEnum(tls.NamedGroup.x25519));
    pos += 2;
    writeU16(buf[pos..], 32);
    pos += 2;
    @memcpy(buf[pos..][0..32], x25519_pub);
    pos += 32;
    // P-256 share (fallback)
    writeU16(buf[pos..], @intFromEnum(tls.NamedGroup.secp256r1));
    pos += 2;
    writeU16(buf[pos..], 65);
    pos += 2;
    @memcpy(buf[pos..][0..65], p256_pub);
    pos += 65;

    // signature_algorithms extension
    pos = writeExtHeader(buf, pos, @intFromEnum(tls.ExtensionType.signature_algorithms), 2 + 10);
    writeU16(buf[pos..], 10); // list length (5 algorithms x 2 bytes)
    pos += 2;
    writeU16(buf[pos..], @intFromEnum(tls.SignatureScheme.ed25519));
    pos += 2;
    writeU16(buf[pos..], @intFromEnum(tls.SignatureScheme.ecdsa_secp256r1_sha256));
    pos += 2;
    writeU16(buf[pos..], @intFromEnum(tls.SignatureScheme.rsa_pss_rsae_sha256));
    pos += 2;
    writeU16(buf[pos..], @intFromEnum(tls.SignatureScheme.rsa_pss_rsae_sha384));
    pos += 2;
    writeU16(buf[pos..], @intFromEnum(tls.SignatureScheme.rsa_pss_rsae_sha512));
    pos += 2;

    // supported_groups extension
    pos = writeExtHeader(buf, pos, @intFromEnum(tls.ExtensionType.supported_groups), 2 + 4);
    writeU16(buf[pos..], 4); // list length (2 groups x 2 bytes)
    pos += 2;
    writeU16(buf[pos..], @intFromEnum(tls.NamedGroup.x25519));
    pos += 2;
    writeU16(buf[pos..], @intFromEnum(tls.NamedGroup.secp256r1));
    pos += 2;

    // SNI extension
    if (server_name) |sni| {
        const sni_ext_len = 2 + 1 + 2 + sni.len; // server_name_list_len + type + host_name_len + host_name
        pos = writeExtHeader(buf, pos, @intFromEnum(tls.ExtensionType.server_name), sni_ext_len);
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
        pos = writeExtHeader(buf, pos, @intFromEnum(tls.ExtensionType.application_layer_protocol_negotiation), 2 + alpn_total);
        writeU16(buf[pos..], @intCast(alpn_total));
        pos += 2;
        for (alpn_list) |proto| {
            buf[pos] = @intCast(proto.len);
            pos += 1;
            @memcpy(buf[pos..][0..proto.len], proto);
            pos += proto.len;
        }
    }

    // QUIC transport parameters extension (pre-encoded)
    pos = writeExtHeader(buf, pos, @intFromEnum(tls.ExtensionType.quic_transport_parameters), tp_encoded_data.len);
    @memcpy(buf[pos..][0..tp_encoded_data.len], tp_encoded_data);
    pos += tp_encoded_data.len;

    // psk_key_exchange_modes extension (type=45) — always included so
    // servers know we support session tickets and can send NewSessionTicket.
    // modes_list_len(1) + mode(1)=0x01 (psk_dhe_ke)
    pos = writeExtHeader(buf, pos, @intFromEnum(tls.ExtensionType.psk_key_exchange_modes), 2);
    buf[pos] = 1; // modes list length
    pos += 1;
    buf[pos] = 0x01; // psk_dhe_ke
    pos += 1;

    // PSK extensions (must be last, per RFC 8446 §4.2.11)
    if (session_ticket) |ticket| {
        // early_data extension (RFC 8446 §4.2.10) — empty payload in ClientHello
        // Tells the server we intend to send 0-RTT data
        pos = writeExtHeader(buf, pos, @intFromEnum(tls.ExtensionType.early_data), 0);

        // pre_shared_key extension (type=41) - MUST be last
        const ticket_bytes = ticket.getTicket();
        const obfuscated_age: u32 = blk: {
            const now_sec = sys.realtimeSeconds();
            // RFC 8446 4.2.11: the obfuscated age is mod 2^32, so a ticket
            // older than ~49 days wraps rather than aborting.
            const age_ms: u32 = @truncate(@as(u64, @intCast(@max(0, now_sec - ticket.creation_time))) *% 1000);
            break :blk age_ms +% ticket.ticket_age_add;
        };

        // identities: identities_len(2) + [identity_len(2) + identity + obfuscated_age(4)]
        const identities_len: u16 = @intCast(2 + ticket_bytes.len + 4);
        // binders: binders_len(2) + [binder_len(1) + binder(32)]
        const binders_len: u16 = 1 + 32;
        const psk_ext_total: u16 = 2 + identities_len + 2 + binders_len;

        pos = writeExtHeader(buf, pos, @intFromEnum(tls.ExtensionType.pre_shared_key), psk_ext_total);

        // Identities
        writeU16(buf[pos..], identities_len);
        pos += 2;
        writeU16(buf[pos..], @intCast(ticket_bytes.len));
        pos += 2;
        @memcpy(buf[pos..][0..ticket_bytes.len], ticket_bytes);
        pos += ticket_bytes.len;
        std.mem.writeInt(u32, buf[pos..][0..4], obfuscated_age, .big);
        pos += 4;

        // Binders placeholder (32 zero bytes, will be replaced)
        writeU16(buf[pos..], binders_len);
        pos += 2;
        buf[pos] = 32; // binder length
        pos += 1;
        const binder_value_offset = pos;
        @memset(buf[pos..][0..32], 0);
        pos += 32;

        // Fill in extensions length and message header BEFORE computing binder
        const ext_len: u16 = @intCast(pos - ext_start - 2);
        writeU16(buf[ext_start..], ext_len);

        const body_len: u24 = @intCast(pos - 4);
        buf[0] = @intFromEnum(tls.HandshakeType.client_hello);
        buf[1] = @intCast(body_len >> 16);
        buf[2] = @intCast((body_len >> 8) & 0xff);
        buf[3] = @intCast(body_len & 0xff);

        // Now compute the real binder
        // binder_key = Derive-Secret(early_secret, "res binder", Hash(""))
        const empty_hash = tls.emptyHash(Sha256);
        const binder_key = quic_crypto.hkdfExpandLabel(key_schedule.early_secret, "res binder", &empty_hash, 32);

        // partial_ch = everything up to and including identities (RFC 8446 §4.2.11.2)
        // Exclude: binders_len_field(2) + binder_len(1) + binder_value(32) = 35 bytes
        const partial_len = pos - 2 - binders_len;
        var partial_hasher = Sha256.init(.{});
        partial_hasher.update(buf[0..partial_len]);
        const partial_hash = partial_hasher.finalResult();

        const binder = KeySchedule.computeFinishedVerifyData(binder_key, partial_hash);
        @memcpy(buf[binder_value_offset..][0..32], &binder);

        return buf[0..pos];
    }

    // Fill in extensions length
    const ext_len: u16 = @intCast(pos - ext_start - 2);
    writeU16(buf[ext_start..], ext_len);

    // Fill in message header
    const body_len: u24 = @intCast(pos - 4);
    buf[0] = @intFromEnum(tls.HandshakeType.client_hello);
    buf[1] = @intCast(body_len >> 16);
    buf[2] = @intCast((body_len >> 8) & 0xff);
    buf[3] = @intCast(body_len & 0xff);

    return buf[0..pos];
}

fn buildServerHello(
    buf: []u8,
    server_random: *const [32]u8,
    key_share_group: tls.NamedGroup,
    key_share_data: []const u8,
    session_id_echo: []const u8,
    using_psk: bool,
    cipher_suite: quic_crypto.CipherSuite,
) ![]const u8 {
    var pos: usize = 4; // reserve for header

    // legacy_version = 0x0303
    buf[pos] = 0x03;
    buf[pos + 1] = 0x03;
    pos += 2;

    // random
    @memcpy(buf[pos..][0..32], server_random);
    pos += 32;

    // legacy_session_id_echo (RFC 8446 §4.1.3: echo the client's value)
    buf[pos] = @intCast(session_id_echo.len);
    pos += 1;
    if (session_id_echo.len > 0) {
        @memcpy(buf[pos..][0..session_id_echo.len], session_id_echo);
        pos += session_id_echo.len;
    }

    // cipher_suite (use negotiated from ClientHello)
    writeU16(buf[pos..], @intFromEnum(cipher_suite));
    pos += 2;

    // compression_method
    buf[pos] = 0;
    pos += 1;

    // Extensions
    const ext_start = pos;
    pos += 2; // extensions length placeholder

    // supported_versions
    pos = writeExtHeader(buf, pos, @intFromEnum(tls.ExtensionType.supported_versions), 2);
    writeU16(buf[pos..], @intFromEnum(tls.ProtocolVersion.tls_1_3));
    pos += 2;

    // key_share (server's key)
    const ks_len: u16 = @intCast(2 + 2 + key_share_data.len);
    pos = writeExtHeader(buf, pos, @intFromEnum(tls.ExtensionType.key_share), ks_len);
    writeU16(buf[pos..], @intFromEnum(key_share_group));
    pos += 2;
    writeU16(buf[pos..], @intCast(key_share_data.len));
    pos += 2;
    @memcpy(buf[pos..][0..key_share_data.len], key_share_data);
    pos += key_share_data.len;

    // pre_shared_key extension (selected_identity = 0)
    if (using_psk) {
        pos = writeExtHeader(buf, pos, @intFromEnum(tls.ExtensionType.pre_shared_key), 2);
        writeU16(buf[pos..], 0); // selected_identity = 0
        pos += 2;
    }

    // Fill in extensions length
    const ext_len: u16 = @intCast(pos - ext_start - 2);
    writeU16(buf[ext_start..], ext_len);

    // Fill in message header
    const body_len: u24 = @intCast(pos - 4);
    buf[0] = @intFromEnum(tls.HandshakeType.server_hello);
    buf[1] = @intCast(body_len >> 16);
    buf[2] = @intCast((body_len >> 8) & 0xff);
    buf[3] = @intCast(body_len & 0xff);

    return buf[0..pos];
}

fn buildEncryptedExtensionsFromEncoded(
    buf: []u8,
    alpn_list: []const []const u8,
    tp_encoded_data: []const u8,
    include_early_data: bool,
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
        pos = writeExtHeader(buf, pos, @intFromEnum(tls.ExtensionType.application_layer_protocol_negotiation), 2 + alpn_total);
        writeU16(buf[pos..], @intCast(alpn_total));
        pos += 2;
        for (alpn_list) |proto| {
            buf[pos] = @intCast(proto.len);
            pos += 1;
            @memcpy(buf[pos..][0..proto.len], proto);
            pos += proto.len;
        }
    }

    // QUIC transport parameters (pre-encoded)
    pos = writeExtHeader(buf, pos, @intFromEnum(tls.ExtensionType.quic_transport_parameters), tp_encoded_data.len);
    @memcpy(buf[pos..][0..tp_encoded_data.len], tp_encoded_data);
    pos += tp_encoded_data.len;

    // early_data extension (empty payload in EE, per RFC 8446 §4.2.10)
    if (include_early_data) {
        pos = writeExtHeader(buf, pos, @intFromEnum(tls.ExtensionType.early_data), 0);
    }

    // Fill in extensions length
    const ext_len: u16 = @intCast(pos - ext_list_start - 2);
    writeU16(buf[ext_list_start..], ext_len);

    // Fill in message header
    const body_len: u24 = @intCast(pos - 4);
    buf[0] = @intFromEnum(tls.HandshakeType.encrypted_extensions);
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
        // 5 = 3-byte length + 2-byte empty extensions
        if (cert_der.len + 5 > buf.len - pos) return error.CertChainTooLarge;

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
    buf[0] = @intFromEnum(tls.HandshakeType.certificate);
    buf[1] = @intCast(body_len >> 16);
    buf[2] = @intCast((body_len >> 8) & 0xff);
    buf[3] = @intCast(body_len & 0xff);

    return buf[0..pos];
}

fn buildCertificateVerify(
    buf: []u8,
    transcript_hash: [32]u8,
    private_key_bytes: []const u8,
    private_key_algorithm: PrivateKeyAlgorithm,
    is_server: bool,
) ![]const u8 {
    // Build the content to sign:
    // 0x20 repeated 64 times + context_string + 0x00 + transcript_hash
    var sign_content: [64 + 33 + 1 + 32]u8 = undefined;
    @memset(sign_content[0..64], 0x20);
    const context_str = if (is_server) "TLS 1.3, server CertificateVerify" else "TLS 1.3, client CertificateVerify";
    @memcpy(sign_content[64..][0..33], context_str);
    sign_content[64 + 33] = 0x00;
    @memcpy(sign_content[64 + 34 ..][0..32], &transcript_hash);

    if (private_key_bytes.len != 32) return error.InternalError;

    var sig_storage: [EcdsaP256Sha256.Signature.der_encoded_length_max]u8 = undefined;
    var sig_len: usize = 0;
    const sig_algo: u16 = switch (private_key_algorithm) {
        .ecdsa_p256_sha256 => sig_algo: {
            const secret_key = EcdsaP256Sha256.SecretKey.fromBytes(private_key_bytes[0..32].*) catch return error.InternalError;
            const key_pair = EcdsaP256Sha256.KeyPair.fromSecretKey(secret_key) catch return error.InternalError;
            const sig = key_pair.sign(&sign_content, null) catch return error.InternalError;
            const sig_bytes = sig.toDer(&sig_storage);
            sig_len = sig_bytes.len;
            break :sig_algo @intFromEnum(tls.SignatureScheme.ecdsa_secp256r1_sha256);
        },
        .ed25519 => sig_algo: {
            const key_pair = Ed25519.KeyPair.generateDeterministic(private_key_bytes[0..32].*) catch return error.InternalError;
            const sig = key_pair.sign(&sign_content, null) catch return error.InternalError;
            const sig_bytes = sig.toBytes();
            @memcpy(sig_storage[0..sig_bytes.len], &sig_bytes);
            sig_len = sig_bytes.len;
            break :sig_algo @intFromEnum(tls.SignatureScheme.ed25519);
        },
    };

    // Build message
    var pos: usize = 4; // reserve for header

    // signature_algorithm
    writeU16(buf[pos..], sig_algo);
    pos += 2;

    // signature length + signature
    writeU16(buf[pos..], @intCast(sig_len));
    pos += 2;
    @memcpy(buf[pos..][0..sig_len], sig_storage[0..sig_len]);
    pos += sig_len;

    // Fill in message header
    const body_len: u24 = @intCast(pos - 4);
    buf[0] = @intFromEnum(tls.HandshakeType.certificate_verify);
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
    return std.mem.readInt(u16, data[0..2], .big);
}

fn writeU16(buf: []u8, val: u16) void {
    std.mem.writeInt(u16, buf[0..2], val, .big);
}

// ─── Minimal PEM parser ──────────────────────────────────────────────

pub fn parsePemCert(pem_data: []const u8, out: []u8) ![]const u8 {
    return parsePemSection(pem_data, "CERTIFICATE", out);
}

/// Parse all PEM certificates from a PEM file containing a certificate chain.
/// Returns a slice of DER-encoded certificates using the provided allocator.
pub fn parsePemCertChain(alloc: std.mem.Allocator, pem_data: []const u8) ![][]const u8 {
    const begin_marker = "-----BEGIN CERTIFICATE-----";
    const end_marker = "-----END CERTIFICATE-----";

    // Count certificates
    var count: usize = 0;
    {
        var search: usize = 0;
        while (std.mem.indexOf(u8, pem_data[search..], begin_marker)) |idx| {
            count += 1;
            search += idx + begin_marker.len;
            search += std.mem.indexOf(u8, pem_data[search..], end_marker) orelse break;
            search += end_marker.len;
        }
    }

    if (count == 0) return error.DecodeError;

    const chain = try alloc.alloc([]u8, count);
    var search: usize = 0;
    for (0..count) |i| {
        const begin_idx = std.mem.indexOf(u8, pem_data[search..], begin_marker) orelse return error.DecodeError;
        const abs_begin = search + begin_idx + begin_marker.len;
        const end_idx = std.mem.indexOf(u8, pem_data[abs_begin..], end_marker) orelse return error.DecodeError;
        const base64_data = pem_data[abs_begin..][0..end_idx];

        // Strip whitespace and decode base64
        var clean: [8192]u8 = undefined;
        var clean_len: usize = 0;
        for (base64_data) |c| {
            if (c != '\n' and c != '\r' and c != ' ' and c != '\t') {
                if (clean_len >= clean.len) return error.DecodeError;
                clean[clean_len] = c;
                clean_len += 1;
            }
        }

        const decoded_len = std.base64.standard.Decoder.calcSizeForSlice(clean[0..clean_len]) catch return error.DecodeError;
        const cert_buf = try alloc.alloc(u8, decoded_len);
        std.base64.standard.Decoder.decode(cert_buf, clean[0..clean_len]) catch return error.DecodeError;
        chain[i] = cert_buf;

        search = abs_begin + end_idx + end_marker.len;
    }

    // Return as [][]const u8
    return @ptrCast(chain);
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

    // Skip AlgorithmIdentifier SEQUENCE (handle multi-byte length)
    if (pos >= der.len or der[pos] != 0x30) return error.DecodeError;
    pos += 1;
    var alg_len: usize = der[pos];
    pos += 1;
    if (alg_len & 0x80 != 0) {
        const num = alg_len & 0x7f;
        alg_len = 0;
        for (0..num) |i| {
            alg_len = (alg_len << 8) | der[pos + i];
        }
        pos += num;
    }
    pos += alg_len;

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

fn readDerValue(der: []const u8, pos: *usize, expected_tag: u8) ![]const u8 {
    if (pos.* >= der.len or der[pos.*] != expected_tag) return error.DecodeError;
    pos.* += 1;
    if (pos.* >= der.len) return error.DecodeError;

    var len: usize = der[pos.*];
    pos.* += 1;
    if (len & 0x80 != 0) {
        const num = len & 0x7f;
        if (num == 0 or num > @sizeOf(usize) or pos.* + num > der.len) return error.DecodeError;
        len = 0;
        for (0..num) |i| {
            len = (len << 8) | der[pos.* + i];
        }
        pos.* += num;
    }

    if (pos.* + len > der.len) return error.DecodeError;
    const value = der[pos.*..][0..len];
    pos.* += len;
    return value;
}

// Extract the 32-byte Ed25519 seed from a PKCS#8 DER-encoded private key.
// RFC 8410: AlgorithmIdentifier OID 1.3.101.112, PrivateKey OCTET STRING.
pub fn extractEd25519PrivateKey(der: []const u8) ![]const u8 {
    var outer_pos: usize = 0;
    const outer = try readDerValue(der, &outer_pos, 0x30);

    var pos: usize = 0;
    _ = try readDerValue(outer, &pos, 0x02); // version

    const algorithm = try readDerValue(outer, &pos, 0x30);
    var algorithm_pos: usize = 0;
    const oid = try readDerValue(algorithm, &algorithm_pos, 0x06);
    if (!std.mem.eql(u8, oid, &.{ 0x2b, 0x65, 0x70 })) return error.DecodeError;
    if (algorithm_pos != algorithm.len) return error.DecodeError;

    const private_key = try readDerValue(outer, &pos, 0x04);
    if (private_key.len == 32) return private_key;

    var nested_pos: usize = 0;
    const nested = try readDerValue(private_key, &nested_pos, 0x04);
    if (nested_pos != private_key.len or nested.len != 32) return error.DecodeError;
    return nested;
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

    // Pre-encode transport params
    var tp_enc_buf: [256]u8 = undefined;
    var tp_fbs = io.fixedBufferStream(&tp_enc_buf);
    try tp.encode(&tp_fbs);
    const tp_encoded = tp_fbs.buffered();

    var ks = KeySchedule.init();
    var buf: [4096]u8 = undefined;
    var p256_pub: [65]u8 = undefined;
    @memset(&p256_pub, 0xCC);
    const msg = try buildClientHello(
        &buf,
        &random,
        &pub_key,
        &p256_pub,
        &[_][]const u8{"h3"},
        "example.com",
        tp_encoded,
        null,
        &ks,
        null,
    );

    // Check message type
    try std.testing.expectEqual(@as(u8, @intFromEnum(tls.HandshakeType.client_hello)), msg[0]);

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
    const msg = try buildServerHello(&buf, &random, .x25519, &pub_key, &client_random, false, .aes_128_gcm_sha256);

    try std.testing.expectEqual(@as(u8, @intFromEnum(tls.HandshakeType.server_hello)), msg[0]);
    const body_len = (@as(usize, msg[1]) << 16) | (@as(usize, msg[2]) << 8) | @as(usize, msg[3]);
    try std.testing.expectEqual(msg.len - 4, body_len);
}

test "loopback handshake: client and server complete" {
    // Generate an ECDSA P-256 key pair for the server
    const server_key_pair = EcdsaP256Sha256.KeyPair.generate(std.testing.io);
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

// PSK binder computation test
test "PSK binder computation: deterministic and correct" {
    const psk: [32]u8 = .{0x42} ** 32;
    var ks = KeySchedule.initWithPsk(psk);

    // early_secret should differ from zero-PSK init
    var ks_zero = KeySchedule.init();
    try std.testing.expect(!std.mem.eql(u8, &ks.early_secret, &ks_zero.early_secret));
    _ = &ks_zero;

    // binder_key = Derive-Secret(early_secret, "res binder", Hash(""))
    const empty_hash = tls.emptyHash(Sha256);
    const binder_key = quic_crypto.hkdfExpandLabel(ks.early_secret, "res binder", &empty_hash, 32);

    // Compute binder for a fake partial transcript
    const fake_transcript: [32]u8 = .{0x01} ** 32;
    const binder = KeySchedule.computeFinishedVerifyData(binder_key, fake_transcript);

    // Deterministic
    const binder2 = KeySchedule.computeFinishedVerifyData(binder_key, fake_transcript);
    try std.testing.expectEqualSlices(u8, &binder, &binder2);

    // Different transcript produces different binder
    const binder3 = KeySchedule.computeFinishedVerifyData(binder_key, .{0x02} ** 32);
    try std.testing.expect(!std.mem.eql(u8, &binder, &binder3));
}

// Early key derivation test
test "early key derivation: client_early_traffic_secret from PSK" {
    const psk: [32]u8 = .{0xAA} ** 32;
    var ks = KeySchedule.initWithPsk(psk);

    const transcript: [32]u8 = .{0xBB} ** 32;
    ks.deriveEarlyDataSecret(transcript);

    // Should produce a non-zero secret
    try std.testing.expect(!std.mem.eql(u8, &ks.client_early_traffic_secret, &(.{0} ** 32)));

    // Derive QUIC keys from early traffic secret
    const keys = KeySchedule.deriveQuicKeys(ks.client_early_traffic_secret);
    try std.testing.expect(!std.mem.eql(u8, &keys.key, &(.{0} ** 16)));
    try std.testing.expect(!std.mem.eql(u8, &keys.iv, &(.{0} ** 12)));
}

// Loopback PSK resumption test: full handshake → ticket → PSK handshake
test "loopback PSK resumption: two handshakes with session ticket" {

    // Generate server key pair
    const server_key_pair = EcdsaP256Sha256.KeyPair.generate(std.testing.io);
    const secret_key_bytes = server_key_pair.secret_key.toBytes();
    const pub_key_bytes = server_key_pair.public_key.toUncompressedSec1();
    const fake_cert = pub_key_bytes;

    // Generate ticket key for server
    var ticket_key: [16]u8 = undefined;
    sys.randomBytes(&ticket_key);

    const server_config = TlsConfig{
        .cert_chain_der = &[_][]const u8{&fake_cert},
        .private_key_bytes = &secret_key_bytes,
        .alpn = &[_][]const u8{"h3"},
        .ticket_key = ticket_key,
    };

    const client_config = TlsConfig{
        .cert_chain_der = &.{},
        .private_key_bytes = &.{},
        .alpn = &[_][]const u8{"h3"},
        .server_name = "localhost",
    };

    const tp = transport_params.TransportParams{
        .initial_max_data = 1048576,
        .initial_max_streams_bidi = 100,
    };

    // ─── First handshake: full (no PSK) ─────────────
    var server1 = Tls13Handshake.initServer(server_config, tp);
    var client1 = Tls13Handshake.initClient(client_config, tp);

    var client_done = false;
    var server_done = false;
    var iterations: usize = 0;

    while ((!client_done or !server_done) and iterations < 100) {
        iterations += 1;

        if (!client_done) {
            const action = try client1.step();
            switch (action) {
                .send_data => |sd| {
                    _ = sd;
                    server1.provideData(client1.out_buf[0..client1.out_len]);
                },
                .install_keys => {},
                .wait_for_data => {},
                .complete => client_done = true,
                ._continue => {},
            }
        }

        if (!server_done) {
            const action = try server1.step();
            switch (action) {
                .send_data => |sd| {
                    _ = sd;
                    // Feed server output to client (including post-handshake NST)
                    client1.provideData(server1.out_buf[0..server1.out_len]);
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

    // Step client a few more times to process post-handshake messages (NST)
    var post_hs: usize = 0;
    while (post_hs < 10) : (post_hs += 1) {
        const action = try client1.step();
        switch (action) {
            .complete => break,
            ._continue => continue,
            else => break,
        }
    }

    // Client should have received a session ticket
    try std.testing.expect(client1.received_ticket != null);
    const ticket = client1.received_ticket.?;
    try std.testing.expect(ticket.ticket_len > 0);
    try std.testing.expect(ticket.lifetime > 0);

    // ─── Second handshake: PSK resumption ─────────────
    var psk_client_config = client_config;
    psk_client_config.session_ticket = &ticket;

    var server2 = Tls13Handshake.initServer(server_config, tp);
    var client2 = Tls13Handshake.initClient(psk_client_config, tp);

    client_done = false;
    server_done = false;
    iterations = 0;
    var client_got_early_keys = false;
    var server_got_early_keys = false;
    var server_used_psk = false;

    while ((!client_done or !server_done) and iterations < 100) {
        iterations += 1;

        if (!client_done) {
            const action = try client2.step();
            switch (action) {
                .send_data => |sd| {
                    _ = sd;
                    server2.provideData(client2.out_buf[0..client2.out_len]);
                },
                .install_keys => |ik| {
                    if (ik.level == .early_data) client_got_early_keys = true;
                },
                .wait_for_data => {},
                .complete => client_done = true,
                ._continue => {},
            }
        }

        if (!server_done) {
            const action = try server2.step();
            switch (action) {
                .send_data => |sd| {
                    _ = sd;
                    client2.provideData(server2.out_buf[0..server2.out_len]);
                },
                .install_keys => |ik| {
                    if (ik.level == .early_data) server_got_early_keys = true;
                },
                .wait_for_data => {},
                .complete => server_done = true,
                ._continue => {},
            }
        }
    }

    try std.testing.expect(client_done);
    try std.testing.expect(server_done);

    // Verify PSK was used (server skipped cert)
    server_used_psk = server2.using_psk;
    try std.testing.expect(server_used_psk);
    try std.testing.expect(client2.using_psk);

    // Early keys should have been installed on both sides
    try std.testing.expect(client_got_early_keys);
    try std.testing.expect(server_got_early_keys);

    // Both sides should have matching app secrets
    try std.testing.expectEqualSlices(
        u8,
        &client2.key_schedule.client_app_traffic_secret,
        &server2.key_schedule.client_app_traffic_secret,
    );
    try std.testing.expectEqualSlices(
        u8,
        &client2.key_schedule.server_app_traffic_secret,
        &server2.key_schedule.server_app_traffic_secret,
    );
}

// NewSessionTicket roundtrip test
test "NewSessionTicket: build and parse roundtrip" {
    const psk: [32]u8 = .{0x55} ** 32;
    const ticket_data = [_]u8{0xAA} ** 64;

    // Build a SessionTicket manually
    var original = SessionTicket{ .psk = psk };
    original.lifetime = 86400;
    original.ticket_age_add = 0x12345678;
    original.creation_time = sys.realtimeSeconds();
    original.max_early_data_size = 0xffffffff;
    @memcpy(original.ticket[0..64], &ticket_data);
    original.ticket_len = 64;
    @memcpy(original.alpn[0..2], "h3");
    original.alpn_len = 2;

    // Verify accessors
    try std.testing.expectEqual(@as(u16, 64), original.ticket_len);
    try std.testing.expectEqualSlices(u8, "h3", original.getAlpn());
    try std.testing.expect(!original.isExpired());

    // Verify PSK is stored correctly
    try std.testing.expectEqualSlices(u8, &psk, &original.psk);
}

// ─── X.509 extension parsing tests ─────────────────────────────────

test "parseX509Extensions: CA certificate with basicConstraints and keyUsage" {
    // v3 CA cert with basicConstraints=CA:TRUE and keyUsage=keyCertSign,cRLSign
    const ca_der = @embedFile("testdata/test_ca.der");
    const exts = parseX509Extensions(ca_der);

    // CA cert should have basicConstraints CA:TRUE
    try std.testing.expect(exts.is_ca != null);
    try std.testing.expect(exts.is_ca.?);
    // CA cert should have keyCertSign in keyUsage
    try std.testing.expect(exts.key_usage != null);
    try std.testing.expect(exts.hasKeyCertSign());
}

test "parseX509Extensions: leaf certificate is not CA" {
    // v3 leaf cert with basicConstraints=CA:FALSE and keyUsage=digitalSignature
    const leaf_der = @embedFile("testdata/test_leaf.der");
    const exts = parseX509Extensions(leaf_der);

    // Leaf cert should have basicConstraints CA:FALSE
    try std.testing.expect(exts.is_ca != null);
    try std.testing.expect(!exts.is_ca.?);
    // Leaf cert should NOT have keyCertSign
    try std.testing.expect(exts.key_usage != null);
    try std.testing.expect(!exts.hasKeyCertSign());
}

test "parseX509Extensions: v1 certificate has no extensions" {
    // v1 cert has no extensions at all
    const v1_der = @embedFile("testdata/v1_ca.der");
    const exts = parseX509Extensions(v1_der);

    // v1 cert should have no extensions parsed
    try std.testing.expect(exts.is_ca == null);
    try std.testing.expect(exts.key_usage == null);
    // hasKeyCertSign defaults to true when no extension present
    try std.testing.expect(exts.hasKeyCertSign());
}

test "X509Extensions: hasKeyCertSign defaults to true when no keyUsage" {
    const exts = X509Extensions{};
    // No keyUsage extension present — no restriction, returns true
    try std.testing.expect(exts.hasKeyCertSign());
}

test "X509Extensions: hasKeyCertSign with keyCertSign bit set" {
    // keyCertSign = bit 5 in RFC 5280 = byte[1] bit 2 = 0x04
    // In our u16 (byte[1]<<8 | byte[2]): keyCertSign = 0x0400
    var exts = X509Extensions{};

    // keyCertSign + cRLSign (typical CA): byte[1] = 0x06 → ku = 0x0600
    exts.key_usage = 0x0600;
    try std.testing.expect(exts.hasKeyCertSign());

    // digitalSignature only (leaf cert): byte[1] = 0x80 → ku = 0x8000
    exts.key_usage = 0x8000;
    try std.testing.expect(!exts.hasKeyCertSign());

    // keyCertSign alone: 0x0400
    exts.key_usage = 0x0400;
    try std.testing.expect(exts.hasKeyCertSign());
}

test "server: early_data in EncryptedExtensions only answers a client that offered it" {
    var buf: [512]u8 = undefined;
    const alpn = [_][]const u8{"h3"};

    const without = try buildEncryptedExtensionsFromEncoded(&buf, &alpn, &.{}, false);
    const len_without = without.len;

    var buf2: [512]u8 = undefined;
    const with = try buildEncryptedExtensionsFromEncoded(&buf2, &alpn, &.{}, true);

    // The extension is 4 bytes of header and no payload (RFC 8446 §4.2.10).
    try std.testing.expectEqual(len_without + 4, with.len);
}

test "client answers a CertificateRequest with an empty Certificate" {
    // Cloudflare's edge asks for a client certificate — cdn.moq.dev failed
    // here with UnexpectedMessage — and RFC 8446 4.4.2 says the answer is a
    // Certificate message even with nothing to put in it.
    var client = Tls13Handshake.initClient(.{
        .cert_chain_der = &.{},
        .private_key_bytes = &.{},
        .alpn = &[_][]const u8{"h3"},
        .server_name = "localhost",
    }, .{});

    client.state = .client_wait_certificate;
    client.provideData(&[_]u8{
        0x0d, 0x00, 0x00, 0x1d, // CertificateRequest, 29 bytes
        0x00, // certificate_request_context: empty
        0x00, 0x1a, // extensions, 26 bytes
        0x00, 0x0d, 0x00, 0x16, 0x00, 0x14, // signature_algorithms, 10 of them
        0x05, 0x03, 0x04, 0x03, 0x08, 0x07,
        0x08, 0x06, 0x08, 0x05, 0x08, 0x04,
        0x06, 0x01, 0x05, 0x01, 0x04, 0x01,
        0x02, 0x01,
    });

    try std.testing.expect(try client.step() == ._continue);
    try std.testing.expect(client.certificate_requested);

    // The empty Certificate goes out ahead of Finished and into the
    // transcript with it, or the server rejects our Finished.
    client.state = .client_send_finished;
    const action = try client.step();
    const out = action.send_data.data;

    try std.testing.expectEqual(@as(usize, 8 + 36), out.len);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x0b, 0, 0, 4, 0, 0, 0, 0 }, out[0..8]);
    try std.testing.expectEqual(@intFromEnum(tls.HandshakeType.finished), out[8]);
}

test "client without a CertificateRequest sends only Finished" {
    var client = Tls13Handshake.initClient(.{
        .cert_chain_der = &.{},
        .private_key_bytes = &.{},
        .alpn = &[_][]const u8{"h3"},
        .server_name = "localhost",
    }, .{});

    client.state = .client_send_finished;
    const action = try client.step();
    try std.testing.expectEqual(@as(usize, 36), action.send_data.data.len);
}

test "the *Into constructors leave no bool to chance" {
    // They assign field by field onto memory the caller allocated, so a field
    // added with a default is silently never written. certificate_requested
    // read as garbage that way and made the client answer a CertificateRequest
    // no server had sent — which only showed up on one platform, because the
    // byte happened to be zero on the other.
    const config = TlsConfig{
        .cert_chain_der = &.{},
        .private_key_bytes = &.{},
        .alpn = &[_][]const u8{"h3"},
        .server_name = "localhost",
    };

    const hs = try std.testing.allocator.create(Tls13Handshake);
    defer std.testing.allocator.destroy(hs);

    inline for (.{ true, false }) |server| {
        // 0x01, not a poison byte: an uninitialised bool has to read back
        // as a *valid* `true` for the assertion below to mean anything.
        @memset(std.mem.asBytes(hs), 0x01);
        if (server) {
            Tls13Handshake.initServerInto(hs, config, .{});
        } else {
            Tls13Handshake.initClientInto(hs, config, .{});
        }

        inline for (@typeInfo(Tls13Handshake).@"struct".fields) |f| {
            if (f.type == bool and !std.mem.eql(u8, f.name, "is_server")) {
                if (comptime f.defaultValue()) |dflt| {
                    try std.testing.expectEqual(dflt, @field(hs, f.name));
                }
            }
        }
        try std.testing.expectEqual(server, hs.is_server);
    }
}

// A three-level chain valid to 2046: root (a trust anchor), intermediate
// (sent on the wire), leaf (sent on the wire). Every other certificate in the
// tree is a lone self-signed leaf, so without these nothing exercises a chain
// walk — and a chain is the shape every real deployment has. Let's Encrypt is
// exactly this: ISRG Root in the store, E5 and the leaf in fullchain.pem.
const fixture_leaf =
    \\-----BEGIN CERTIFICATE-----
    \\MIIBVjCB/qADAgECAgkA2A1zZvnL+u8wCgYIKoZIzj0EAwIwKDEmMCQGA1UEAwwd
    \\cXVpYy16aWcgZml4dHVyZSBpbnRlcm1lZGlhdGUwHhcNMjYwOTExMTM0MTU2WhcN
    \\NDYwOTA2MTM0MTU2WjAVMRMwEQYDVQQDDApyZWxheS50ZXN0MFkwEwYHKoZIzj0C
    \\AQYIKoZIzj0DAQcDQgAEJzmLFpJZ9az9Dg6V9u9Mke0X/8j01EuVVO8I0DVdAeHb
    \\0QPE8QCyFas9qJhVXHRjtN+5nNXvRli6iY+HOUsINaMkMCIwFQYDVR0RBA4wDIIK
    \\cmVsYXkudGVzdDAJBgNVHRMEAjAAMAoGCCqGSM49BAMCA0cAMEQCIAcEdrG8ry9P
    \\YxcHAI/ds49yad7swdrwqjCHUqyCapg1AiAQDVqSjXrWRgAeqm/J3P97HdI/h6yi
    \\/AcoDYvs2Yb/bQ==
    \\-----END CERTIFICATE-----
;
const fixture_intermediate =
    \\-----BEGIN CERTIFICATE-----
    \\MIIBZTCCAQugAwIBAgIJAKHq7AjLsUNqMAoGCCqGSM49BAMCMCAxHjAcBgNVBAMM
    \\FXF1aWMtemlnIGZpeHR1cmUgcm9vdDAeFw0yNjA5MTExMzQxNTZaFw00NjA5MDYx
    \\MzQxNTZaMCgxJjAkBgNVBAMMHXF1aWMtemlnIGZpeHR1cmUgaW50ZXJtZWRpYXRl
    \\MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEP0EB+lxfpqCqzJl98QH7O0HLIfCJ
    \\890l8e3IFcKGzDhHzwfb9ePmv0CKyAU+g0LYlAYzS3IF419OMs9orzEizKMmMCQw
    \\EgYDVR0TAQH/BAgwBgEB/wIBADAOBgNVHQ8BAf8EBAMCAQYwCgYIKoZIzj0EAwID
    \\SAAwRQIgfG8RhWW/ZqVtQKhWR76Q6hcbTodlRK0PzOVsRLPqkXoCIQD6G7a1s0eZ
    \\Fb0qKJtYGzVWkzgzx508kEZ3gk3RKexeBA==
    \\-----END CERTIFICATE-----
;
const fixture_root =
    \\-----BEGIN CERTIFICATE-----
    \\MIIBLzCB1gIJAKVkZyJDeY6aMAoGCCqGSM49BAMCMCAxHjAcBgNVBAMMFXF1aWMt
    \\emlnIGZpeHR1cmUgcm9vdDAeFw0yNjA5MTExMzQxNTZaFw00NjA5MDYxMzQxNTZa
    \\MCAxHjAcBgNVBAMMFXF1aWMtemlnIGZpeHR1cmUgcm9vdDBZMBMGByqGSM49AgEG
    \\CCqGSM49AwEHA0IABFpmS92sjxWx4Qhg2OMKyX/mgCCGFNdxxQaezXDhbbpxOcCP
    \\AjyNLmhIt7XDDOvVwMYY4eW4d0ZVbjYXLFXuCNowCgYIKoZIzj0EAwIDSAAwRQIg
    \\C9dJETrUnxyNjcpk2EHfRM7vSeCMUfUM4crZhgVWKl4CIQDqUJLhcW2mREVSRQVv
    \\luhi6v7Gxy8HKYIcmzCZDIUHfg==
    \\-----END CERTIFICATE-----
;
const fixture_leaf_key =
    \\-----BEGIN EC PRIVATE KEY-----
    \\MHcCAQEEIPlZKSaxENtfhyr7zS8jSd0Ih9+bRiz8mxzuByRfU6kaoAoGCCqGSM49
    \\AwEHoUQDQgAEJzmLFpJZ9az9Dg6V9u9Mke0X/8j01EuVVO8I0DVdAeHb0QPE8QCy
    \\Fas9qJhVXHRjtN+5nNXvRli6iY+HOUsINQ==
    \\-----END EC PRIVATE KEY-----
;

fn fixtureBundle(gpa: std.mem.Allocator) !Certificate.Bundle {
    var bundle: Certificate.Bundle = .empty;
    errdefer bundle.deinit(gpa);
    var der_buf: [4096]u8 = undefined;
    const der = try parsePemCert(fixture_root, &der_buf);
    try bundle.bytes.appendSlice(gpa, der);
    try bundle.parseCert(gpa, 0, sys.realtimeSeconds());
    return bundle;
}

fn fixtureHandshake(gpa: std.mem.Allocator, chain: []const []const u8) !bool {
    var key_buf: [4096]u8 = undefined;
    const key_der = try parsePemPrivateKey(fixture_leaf_key, &key_buf);
    const key_scalar = extractEcPrivateKey(key_der) catch try extractPkcs8EcPrivateKey(key_der);
    return fixtureHandshakeWith(gpa, .{
        .cert_chain_der = chain,
        .private_key_bytes = key_scalar,
        .alpn = &[_][]const u8{"h3"},
    });
}

fn fixtureHandshakeWith(gpa: std.mem.Allocator, server_config: TlsConfig) !bool {
    var bundle = try fixtureBundle(gpa);
    defer bundle.deinit(gpa);

    const tp = transport_params.TransportParams{ .initial_max_data = 1 << 20, .initial_max_streams_bidi = 10 };
    const server = try gpa.create(Tls13Handshake);
    defer gpa.destroy(server);
    const client = try gpa.create(Tls13Handshake);
    defer gpa.destroy(client);

    Tls13Handshake.initServerInto(server, server_config, tp);
    Tls13Handshake.initClientInto(client, .{
        .cert_chain_der = &.{},
        .private_key_bytes = &.{},
        .alpn = &[_][]const u8{"h3"},
        .server_name = "relay.test",
        .skip_cert_verify = false,
        .ca_bundle = &bundle,
    }, tp);

    var client_done = false;
    var server_done = false;
    var i: usize = 0;
    while ((!client_done or !server_done) and i < 100) : (i += 1) {
        if (!client_done) {
            const action = client.step() catch return false;
            switch (action) {
                .send_data => |sd| server.provideData(sd.data),
                .complete => client_done = true,
                else => {},
            }
        }
        if (!server_done) {
            const action = server.step() catch return false;
            switch (action) {
                .send_data => client.provideData(server.out_buf[0..server.out_len]),
                .complete => server_done = true,
                else => {},
            }
        }
    }
    return client_done and server_done;
}

test "a server serves its full chain and the client roots it in a trust anchor" {
    const gpa = std.testing.allocator;

    var pem_buf: [8192]u8 = undefined;
    const full = try std.fmt.bufPrint(&pem_buf, "{s}\n{s}\n", .{ fixture_leaf, fixture_intermediate });
    const chain = try parsePemCertChain(gpa, full);
    defer {
        for (chain) |der| gpa.free(der);
        gpa.free(chain);
    }
    try std.testing.expectEqual(@as(usize, 2), chain.len);

    try std.testing.expect(try fixtureHandshake(gpa, chain));
}

test "a server that sends only its leaf cannot be verified" {
    // The intermediate is not in the trust store and never will be, so a
    // server that omits it leaves the client with nothing to build on. This
    // is the failure mode of deploying cert.pem where fullchain.pem was meant.
    const gpa = std.testing.allocator;

    var pem_buf: [8192]u8 = undefined;
    const full = try std.fmt.bufPrint(&pem_buf, "{s}\n", .{fixture_leaf});
    const chain = try parsePemCertChain(gpa, full);
    defer {
        for (chain) |der| gpa.free(der);
        gpa.free(chain);
    }
    try std.testing.expectEqual(@as(usize, 1), chain.len);

    try std.testing.expect(!try fixtureHandshake(gpa, chain));
}

test "selectCertificate: exact, then one-label wildcard, then the first entry" {
    const cert: ServerCertificate = .{ .cert_chain_der = &.{}, .private_key_bytes = &.{} };
    const entries = [_]CertEntry{
        .{ .server_names = &.{"default.test"}, .cert = cert },
        .{ .server_names = &.{"*.example.com"}, .cert = cert },
        .{ .server_names = &.{ "api.example.com", "Other.Test" }, .cert = cert },
    };
    const T = struct {
        fn pick(e: []const CertEntry, sni: ?[]const u8) struct { usize, bool } {
            const sel = selectCertificate(e, sni).?;
            return .{ (@intFromPtr(sel.entry) - @intFromPtr(e.ptr)) / @sizeOf(CertEntry), sel.matched };
        }
    };
    try std.testing.expectEqual(.{ 2, true }, T.pick(&entries, "api.example.com"));
    try std.testing.expectEqual(.{ 2, true }, T.pick(&entries, "other.test"));
    try std.testing.expectEqual(.{ 1, true }, T.pick(&entries, "www.EXAMPLE.com"));
    try std.testing.expectEqual(.{ 1, true }, T.pick(&entries, "www.example.com."));
    try std.testing.expectEqual(.{ 0, false }, T.pick(&entries, "a.b.example.com"));
    try std.testing.expectEqual(.{ 0, false }, T.pick(&entries, "example.com"));
    try std.testing.expectEqual(.{ 0, false }, T.pick(&entries, ".example.com"));
    try std.testing.expectEqual(.{ 0, true }, T.pick(&entries, "default.test"));
    try std.testing.expectEqual(.{ 0, false }, T.pick(&entries, null));
    try std.testing.expect(selectCertificate(&.{}, "x") == null);
}

test "server_name: a list length of 0xFFFF is a decode error, not an overflow" {
    var ext: [2 + 3 + 9]u8 = undefined;
    ext[0..2].* = .{ 0xff, 0xff };
    ext[2] = 0;
    ext[3..5].* = .{ 0, 9 };
    @memcpy(ext[5..], "localhost");
    try std.testing.expectError(error.DecodeError, parseServerNameExtension(&ext));

    std.mem.writeInt(u16, ext[0..2], ext.len - 2, .big);
    try std.testing.expectEqualStrings("localhost", (try parseServerNameExtension(&ext)).?);
}

test "a QUIC server picks its certificate by SNI" {
    const gpa = std.testing.allocator;

    var pem_buf: [8192]u8 = undefined;
    const full = try std.fmt.bufPrint(&pem_buf, "{s}\n{s}\n", .{ fixture_leaf, fixture_intermediate });
    const chain = try parsePemCertChain(gpa, full);
    defer {
        for (chain) |der| gpa.free(der);
        gpa.free(chain);
    }
    var key_buf: [4096]u8 = undefined;
    const key_der = try parsePemPrivateKey(fixture_leaf_key, &key_buf);
    const key_scalar = try extractEcPrivateKey(key_der);

    // The leaf alone does not verify (see above), so only the full-chain
    // entry lets the client, which asks for relay.test, finish.
    const good: ServerCertificate = .{ .cert_chain_der = chain, .private_key_bytes = key_scalar };
    const bad: ServerCertificate = .{ .cert_chain_der = chain[0..1], .private_key_bytes = key_scalar };

    const by_name = [_]CertEntry{
        .{ .server_names = &.{"other.test"}, .cert = bad },
        .{ .server_names = &.{"*.test"}, .cert = good },
    };
    try std.testing.expect(try fixtureHandshakeWith(gpa, .{
        .cert_chain_der = &.{},
        .private_key_bytes = &.{},
        .alpn = &[_][]const u8{"h3"},
        .certs = &by_name,
    }));

    const default_first = [_]CertEntry{
        .{ .server_names = &.{"unrelated.example"}, .cert = good },
        .{ .server_names = &.{"other.test"}, .cert = bad },
    };
    try std.testing.expect(try fixtureHandshakeWith(gpa, .{
        .cert_chain_der = &.{},
        .private_key_bytes = &.{},
        .alpn = &[_][]const u8{"h3"},
        .certs = &default_first,
    }));

    const wrong_default = [_]CertEntry{
        .{ .server_names = &.{"unrelated.example"}, .cert = bad },
        .{ .server_names = &.{"other.test"}, .cert = good },
    };
    try std.testing.expect(!try fixtureHandshakeWith(gpa, .{
        .cert_chain_der = &.{},
        .private_key_bytes = &.{},
        .alpn = &[_][]const u8{"h3"},
        .certs = &wrong_default,
    }));
}
