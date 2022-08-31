//! Contains data constructs related to the TLS protocol.
const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;
const crypto = std.crypto;
const HkdfSha256 = crypto.kdf.hkdf.HkdfSha256;
/// Target cpu's endianness. Use this to check if byte swapping is required.
const target_endianness = @import("builtin").cpu.arch.endian();

/// Record header. TLS sessions are broken into the sending
/// and receiving of records, which are blocks of data with a type,
/// protocol version and a length.
pub const Record = extern struct {
    /// The type of record we're receiving or sending
    record_type: RecordType,
    /// The (legacy) protocol version.
    /// This is *always* 0x0303 (TLS 1.2) even for TLS 1.3
    /// as the supported versions are part of an extension in TLS 1.3,
    /// rather than the `Record` header.
    protocol_version: u16 = 0x0303,
    /// The length of the bytes that are left for reading.
    /// The length MUST not exceed 2^14 bytes.
    len: u16,

    /// Supported record types by TLS 1.3
    pub const RecordType = enum(u8) {
        change_cipher_spec = 20,
        alert = 21,
        handshake = 22,
        application_data = 23,

        pub fn int(self: RecordType) u8 {
            return @enumToInt(self);
        }
    };

    /// Initializes a new `Record` that always has its `protocol_version` set to 0x0303.
    pub fn init(record_type: RecordType, len: u16) Record {
        return .{ .record_type = record_type, .len = len };
    }

    /// Writes a `Record` to a given `writer`.
    pub fn writeTo(self: Record, writer: anytype) !void {
        try writer.writeByte(@enumToInt(self.record_type));
        try writer.writeIntBig(u16, self.protocol_version);
        try writer.writeIntBig(u16, self.len);
    }

    /// Reads from a given `reader` to initialize a new `Record`.
    /// It's up to the user to verify correctness of the data (such as protocol version).
    pub fn readFrom(reader: anytype) !Record {
        return Record{
            .record_type = @intToEnum(RecordType, try reader.readByte()),
            .protocol_version = try reader.readIntBig(u16),
            .len = try reader.readIntBig(u16),
        };
    }

    /// Represents a `Record` as an array
    pub fn toBytes(self: Record) [5]u8 {
        var bytes: [5]u8 = undefined;
        bytes[0] = @enumToInt(self.record_type);
        mem.writeIntBig(u16, bytes[1..3], self.protocol_version);
        mem.writeIntBig(u16, bytes[3..5], self.len);
        return bytes;
    }
};

pub const Alert = struct {
    severity: Severity,
    tag: Tag,

    /// Initializes a new `Alert` of a given type `Tag` with its severity set
    /// to `severity`.
    pub fn init(tag: Tag, severity: Severity) Alert {
        return .{ .tag = tag, .severity = severity };
    }

    /// Reads an alert from a given `reader`
    pub fn readFrom(reader: anytype) (@TypeOf(reader).Error || error{EndOfStream})!Alert {
        return Alert{
            .severity = @intToEnum(Severity, try reader.readByte()),
            .tag = @intToEnum(Tag, try reader.readByte()),
        };
    }

    /// Initializes a new `Alert` from a given byte array.
    pub fn fromBytes(bytes: [2]u8) Alert {
        return Alert{
            .severity = @intToEnum(Severity, bytes[0]),
            .tag = @intToEnum(Tag, bytes[1]),
        };
    }

    /// Writes the Alert to a given `writer` stream.
    pub fn writeTo(self: Alert, writer: anytype) @TypeOf(writer).Error!void {
        try writer.writeByte(self.severity.int());
        try writer.writeByte(self.tag.int());
    }

    /// Returns the `Tag` of an `Alert` as an `Error`. Can be used
    /// inside functions that receive an alert as response from the peer.
    pub fn toError(self: Alert) Error {
        return switch (self.tag) {
            .close_notify => error.CloseNotify,
            .unexpected_message => error.UnexpectedMessage,
            .bad_record_mac => error.BadRecordMac,
            .record_overflow => error.RecordOverflow,
            .handshake_failure => error.HandshakeFailure,
            .bad_certificate => error.BadCertificate,
            .unsupported_certificate => error.UnsupportedCertificate,
            .certificate_revoked => error.CertificateRevoked,
            .certificate_expired => error.CertificateExpired,
            .certificate_unknown => error.CertificateUnknown,
            .illegal_parameter => error.IllegalParameter,
            .unknown_ca => error.UnknownCA,
            .access_denied => error.AccessDenied,
            .decode_error => error.DecodeError,
            .decrypt_error => error.DecryptError,
            .protocol_version => error.ProtocolVersion,
            .insufficient_security => error.InsufficientSecurity,
            .internal_error => error.InternalError,
            .inappropriate_fallback => error.InappropiateFallback,
            .user_canceled => error.UserCanceled,
            .missing_extension => error.MissingExtension,
            .unsupported_extension => error.UnsupportedExtension,
            .unrecognized_name => error.UnrecognizedName,
            .bad_certificate_status_response => error.BadCertificateStatusResponse,
            .unknown_psk_identity => error.UnknownPskIdentity,
            .certificate_required => error.CertificateRequired,
            .no_application_protocol => error.NoApplicationProtocol,
        };
    }

    /// Types of alerts we can emit or receive
    /// Known as AlertDescription by TLS
    pub const Tag = enum(u8) {
        close_notify = 0,
        unexpected_message = 10,
        bad_record_mac = 20,
        record_overflow = 22,
        handshake_failure = 40,
        bad_certificate = 42,
        unsupported_certificate = 43,
        certificate_revoked = 44,
        certificate_expired = 45,
        certificate_unknown = 46,
        illegal_parameter = 47,
        unknown_ca = 48,
        access_denied = 49,
        decode_error = 50,
        decrypt_error = 51,
        protocol_version = 70,
        insufficient_security = 71,
        internal_error = 80,
        inappropriate_fallback = 86,
        user_canceled = 90,
        missing_extension = 109,
        unsupported_extension = 110,
        unrecognized_name = 112,
        bad_certificate_status_response = 113,
        unknown_psk_identity = 115,
        certificate_required = 116,
        no_application_protocol = 120,

        pub fn int(self: Tag) u8 {
            return @enumToInt(self);
        }
    };

    /// Represents the severity of the alert.
    /// When the level is `fatal`, no more data must be read
    /// or written to the connection.
    pub const Severity = enum(u8) {
        warning = 1,
        fatal = 2,

        pub fn int(self: Severity) u8 {
            return @enumToInt(self);
        }
    };

    /// All alert errors/warnings specified by RFC 8446
    pub const Error = error{
        CloseNotify,
        UnexpectedMessage,
        BadRecordMac,
        RecordOverflow,
        HandshakeFailure,
        BadCertificate,
        UnsupportedCertificate,
        CertificateRevoked,
        CertificateExpired,
        CertificateUnknown,
        IllegalParameter,
        UnknownCA,
        AccessDenied,
        DecodeError,
        DecryptError,
        ProtocolVersion,
        InsufficientSecurity,
        InternalError,
        InappropiateFallback,
        UserCanceled,
        MissingExtension,
        UnsupportedExtension,
        UnrecognizedName,
        BadCertificateStatusResponse,
        UnknownPskIdentity,
        CertificateRequired,
        NoApplicationProtocol,
    };
};

/// Represents the key exchange that is supported by the client or server
/// Prior to TLS 1.3 this was called 'elliptic_curves' and only contained elliptic curve groups.
pub const NamedGroup = enum(u16) {
    secp256r1 = 0x0017,
    secp384r1 = 0x0018,
    secp521r1 = 0x0019,
    x25519 = 0x001D,
    x448 = 0x001E,
    ffdhe2048 = 0x0100,
    ffdhe3072 = 0x0101,
    ffdhe4096 = 0x0102,
    ffdhe_private_use_start = 0x01FC,
    ffdhe_private_use_end = 0x01FF,
    ecdhe_private_use_start = 0xFE00,
    ecdhe_private_use_end = 0xFEFF,
    /// reserved and unsupported values
    /// as they're part of earlier TLS version.
    _,

    pub fn int(self: NamedGroup) u16 {
        return @enumToInt(self);
    }
};

/// Provides a list of supported `NamedGroup` by this library
/// that have been implemented. Meaning this may contain only
/// a subset of all groups that TLS 1.3 may support.
pub const supported_named_groups = struct {
    pub const set: []const NamedGroup = &.{
        .x25519,
    };

    /// Verifies if a given `NamedGroup` is supported by this library.
    /// Returns false if the group isn't implemented/supported yet.
    pub fn isSupported(group: NamedGroup) bool {
        return for (set) |g| {
            if (g == group) break true;
        } else false;
    }
};

pub const SignatureAlgorithm = enum(u16) {
    // RSASSA-PKCS1-v1_5 algorithms
    rsa_pkcs1_sha256 = 0x0401,
    rsa_pkcs1_sha384 = 0x0501,
    rsa_pkcs1_sha512 = 0x0601,

    // ECDSA algorithms
    ecdsa_secp256r1_sha256 = 0x0403,
    ecdsa_secp384r1_sha384 = 0x0503,
    ecdsa_secp521r1_sha512 = 0x0603,

    // RSASSA-PSS algorithms with public key OID rsaEncryption
    rsa_pss_rsae_sha256 = 0x0804,
    rsa_pss_rsae_sha384 = 0x0805,
    rsa_pss_rsae_sha512 = 0x0806,

    // EdDSA algorithms
    ed25519 = 0x0807,
    ed448 = 0x0808,

    // RSASSA-PSS algorithms with public key OID RSASSA-PSS
    rsa_pss_pss_sha256 = 0x0809,
    rsa_pss_pss_sha384 = 0x080a,
    rsa_pss_pss_sha512 = 0x080b,

    // Legacy algorithms
    rsa_pkcs1_sha1 = 0x0201,
    ecdsa_sha1 = 0x0203,

    /// Reserved Code Points
    _,

    pub fn int(self: SignatureAlgorithm) u16 {
        return @enumToInt(self);
    }
};

/// Table of supported `SignatureAlgorithm` of this library
/// This may only include a subset of the enum values found in
/// `SignatureAlgorithm` itself.
pub const supported_signature_algorithms = struct {
    pub const set: []const SignatureAlgorithm = &.{
        .ecdsa_secp256r1_sha256,
    };

    /// Checks if a given `SignatureAlgorithm` is supported by the library.
    pub fn isSupported(signature: SignatureAlgorithm) bool {
        return for (set) |alg| {
            if (alg == signature) break true;
        } else false;
    }
};

/// Supported cipher suites by TLS 1.3
/// https://datatracker.ietf.org/doc/html/rfc8446#appendix-B.4
pub const CipherSuite = enum(u16) {
    tls_aes_128_gcm_sha256 = 0x1301,
    tls_aes_256_gcm_sha384 = 0x1302,
    tls_chacha20_poly1305_sha256 = 0x1303,
    tls_aes_128_ccm_sha256 = 0x1304,
    tls_aes_128_ccm_8_sha256 = 0x1305,
    /// Unsupported, legacy suites
    _,

    pub fn int(self: CipherSuite) u16 {
        return @enumToInt(self);
    }
};

/// Pre-shared Key Exchange Modes as described in section 4.2.9
/// https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.9
pub const PskKeyExchangeMode = enum(u8) {
    psk_ke = 0,
    psk_dhe_ke = 1,
};

/// Reads big endian bytes into a typed slice of `T`.
/// Converts each element's bytes to target cpu's endianness.
///
/// Note: Given type `T` must be representable as an integer type,
/// meaning if an Enum type is given, it must be tagged.
pub fn bytesToTypedSlice(comptime T: type, bytes: anytype) []const T {
    const IntType = switch (@typeInfo(T)) {
        .Enum => |info| info.tag_type,
        .Int => T,
        else => @compileLog("Given type " ++ @typeName(T) ++ " is not representable as an Integer type."),
    };

    var slice = std.mem.bytesAsSlice(IntType, bytes);
    if (target_endianness == .Little) for (slice) |*element| {
        element.* = @byteSwap(IntType, element.*);
    };
    return @bitCast([]const T, slice);
}

/// Keyshare represents the key exchange used to generate
/// its public key, and the actual public key.
pub const KeyShare = struct {
    /// The key exchange (i.e. curve25519)
    named_group: NamedGroup,
    /// The public key of the client
    key_exchange: [32]u8,

    /// Returns the total bytes it will write to a TLS connection
    /// during a handshake
    pub fn byteLen(self: KeyShare) u16 {
        return self.key_exchange.len + 8;
    }

    /// Ensures the correct bytes are written to the writer
    /// based on a given `KeyShare`.
    pub fn writeTo(self: KeyShare, writer: anytype) !void {
        try writer.writeIntBig(u16, Extension.Tag.key_share.int());
        try writer.writeIntBig(u16, 0x0024); // length (36 bytes)
        try writer.writeIntBig(u16, self.named_group.int());
        try writer.writeIntBig(u16, 0x20); // public key length (32 bytes)
        try writer.writeAll(&self.key_exchange);
    }
};

/// Extension define what the client requests for extended functionality from servers.
/// Note that some extensions are required for TLS 1.3 itself,
/// while others are optional.
pub const Extension = union(Tag) {
    /// The supported TLS versions of the client.
    supported_versions: []const u16,
    /// The PSK key exchange modes the client supports
    psk_key_exchange_modes: []const PskKeyExchangeMode,
    /// List of public keys and the key exchange required for them.
    key_share: []const KeyShare,
    /// A list of signature algorithms the client supports
    signature_algorithms: []const SignatureAlgorithm,
    /// The groups of curve types the client supports
    supported_groups: []const NamedGroup,
    /// Hostname of the server the client wants to connect to
    /// TLS uses this to determine which server certificate to use,
    /// rather than requiring multiple servers.
    server_name: []const u8,

    // TODO: Implement the other types. Currently,
    // they're just void types.
    max_gragment_length,
    status_request,
    use_srtp,
    heartbeat,
    application_layer_protocol_negotation,
    signed_certificate_timestamp,
    client_certificate_type,
    server_certificate_type,
    pre_shared_key,
    early_data,
    cookie,
    certificate_authorities,
    oid_filters,
    post_handshake_auth,
    signature_algorithms_cert,

    /// All extensions that are compatible with TLS 1.3
    /// Some may be specified as an external rfc.
    pub const Tag = enum(u16) {
        server_name = 0,
        max_gragment_length = 1,
        status_request = 5,
        supported_groups = 10,
        signature_algorithms = 13,
        use_srtp = 14,
        heartbeat = 15,
        application_layer_protocol_negotation = 16,
        signed_certificate_timestamp = 18,
        client_certificate_type = 19,
        server_certificate_type = 20,
        pre_shared_key = 41,
        early_data = 42,
        supported_versions = 43,
        cookie = 44,
        psk_key_exchange_modes = 45,
        certificate_authorities = 47,
        oid_filters = 48,
        post_handshake_auth = 49,
        signature_algorithms_cert = 50,
        key_share = 51,
        /// Unsupported 'legacy' extensions
        _,

        pub fn int(self: Tag) u16 {
            return @enumToInt(self);
        }
    };

    /// Constructs extensions as they are parsed.
    /// Allowing to to reduce the need for allocations.
    pub const Iterator = struct {
        /// Mutable slice as we may require
        /// to byteswap elements to ensure correct endianness
        data: []u8,
        /// Current index into `data`
        index: usize,

        /// Initializes a new instance of `Iterator` with given data.
        pub fn init(data: []u8) Iterator {
            return .{ .data = data, .index = 0 };
        }

        /// Sets `index` to '0', allowing to re-iterate over the extensions present in `data`.
        pub fn reset(self: *Iterator) void {
            self.index = 0;
        }

        /// Parses the next extension, returning `null` when all extensions have been parsed.
        /// Will return `UnsupportedExtension` when an extension is not supported by TLS 1.3,
        /// or simply isn't implemented yet.
        pub fn next(self: *Iterator, gpa: Allocator) error{ OutOfMemory, UnsupportedExtension }!?Extension {
            if (self.index >= self.data.len) return null;

            const tag_byte = mem.readIntBig(u16, self.data[self.index..][0..2]);
            self.index += 2;
            const extension_length = mem.readIntBig(u16, self.data[self.index..][0..2]);
            self.index += 2;
            const extension_data = self.data[self.index .. self.index + extension_length];
            self.index += extension_data.len;

            switch (@intToEnum(Extension.Tag, tag_byte)) {
                .supported_versions => return Extension{ .supported_versions = bytesToTypedSlice(u16, extension_data[1..]) },
                .psk_key_exchange_modes => return Extension{ .psk_key_exchange_modes = @bitCast(
                    []const PskKeyExchangeMode,
                    extension_data[1..],
                ) },
                .key_share => {
                    const len = mem.readIntBig(u16, extension_data[0..2]);
                    var keys = std.ArrayList(KeyShare).init(gpa);
                    defer keys.deinit();

                    var i: usize = 0;
                    while (i < len) {
                        // allocate memory for a new key
                        const key = try keys.addOne();

                        // get the slice for current data
                        const data = extension_data[i + 2 ..];

                        // read named_group and the amount of bytes of public key
                        const named_group = mem.readIntBig(u16, data[0..2]);
                        const key_len = mem.readIntBig(u16, data[2..4]);
                        _ = key_len;

                        // update pointer's value
                        key.* = .{
                            .named_group = @intToEnum(NamedGroup, named_group),
                            .key_exchange = data[4..][0..32].*,
                        };
                        i += key_len + 4;
                    }

                    return Extension{ .key_share = keys.toOwnedSlice() };
                },
                // For TLS 1.3 only 1 hostname can be provided which is always
                // of type DNS hostname. This means the hostname is the remaining
                // bytes after the 5th element.
                .server_name => return Extension{ .server_name = extension_data[5..] },
                .supported_groups => return Extension{ .supported_groups = bytesToTypedSlice(
                    NamedGroup,
                    extension_data[2..],
                ) },
                .signature_algorithms => return Extension{ .signature_algorithms = bytesToTypedSlice(
                    SignatureAlgorithm,
                    extension_data[2..],
                ) },
                else => {
                    std.log.info("Extension: {any}", .{tag_byte});
                    return error.UnsupportedExtension;
                },
            }
        }
    };
};

test "Extension iterator" {
    var extension_bytes = [_]u8{
        // Extension - Server name
        0x00, 0x00, 0x00, 0x18, 0x00, 0x16, 0x00, 0x00,
        0x13, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65,
        0x2e, 0x75, 0x6c, 0x66, 0x68, 0x65, 0x69, 0x6d,
        0x2e, 0x6e, 0x65, 0x74,
        // Extension - Support groups
        0x00, 0x0a, 0x00, 0x08,
        0x00, 0x06, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x18,
        // Extension - Signature Algorithms
        0x00, 0x0d, 0x00, 0x14, 0x00, 0x12, 0x04, 0x03,
        0x08, 0x04, 0x04, 0x01, 0x05, 0x03, 0x08, 0x05,
        0x05, 0x01, 0x08, 0x06, 0x06, 0x01, 0x02, 0x01,
        // Extensions - Key Share
        0x00, 0x33, 0x00, 0x26, 0x00, 0x24, 0x00, 0x1d,
        0x00, 0x20, 0x35, 0x80, 0x72, 0xd6, 0x36, 0x58,
        0x80, 0xd1, 0xae, 0xea, 0x32, 0x9a, 0xdf, 0x91,
        0x21, 0x38, 0x38, 0x51, 0xed, 0x21, 0xa2, 0x8e,
        0x3b, 0x75, 0xe9, 0x65, 0xd0, 0xd2, 0xcd, 0x16,
        0x62, 0x54,
        // Extension - PSK Key Exchange modes
        0x00, 0x2d, 0x00, 0x02, 0x01, 0x01,
        // Extension - Supported versions
        0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04,
    };

    var it = Extension.Iterator{
        .data = &extension_bytes,
        .index = 0,
    };

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    while (try it.next(arena.allocator())) |ext| {
        switch (ext) {
            .server_name => |name| try std.testing.expectEqualStrings("example.ulfheim.net", name),
            .supported_groups => |groups| try std.testing.expectEqualSlices(
                NamedGroup,
                &.{ .x25519, .secp256r1, .secp384r1 },
                groups,
            ),
            .signature_algorithms => |algs| try std.testing.expectEqualSlices(
                SignatureAlgorithm,
                &.{
                    .ecdsa_secp256r1_sha256, .rsa_pss_rsae_sha256, .rsa_pkcs1_sha256,
                    .ecdsa_secp384r1_sha384, .rsa_pss_rsae_sha384, .rsa_pkcs1_sha384,
                    .rsa_pss_rsae_sha512,    .rsa_pkcs1_sha512,    .rsa_pkcs1_sha1,
                },
                algs,
            ),
            .psk_key_exchange_modes => |modes| try std.testing.expectEqualSlices(
                PskKeyExchangeMode,
                &.{.psk_dhe_ke},
                modes,
            ),
            else => {}, //TODO: Implement all extensions
        }
    }
}

/// Represents a private and public key for either the server
/// or a client.
pub const KeyExchange = struct {
    private_key: [32]u8,
    public_key: [32]u8,

    /// Generates a new private/public key pair using the given curve.
    pub fn fromCurve(curve: *Curve) Curve.Error!KeyExchange {
        var exchange: KeyExchange = undefined;
        crypto.random.bytes(&exchange.private_key);
        try curve.generateKey(exchange.private_key, &exchange.public_key);
        return exchange;
    }
};

/// Curve allows us to generate a public key for a given
/// private key, using a generation function provided
/// by an implementation.
pub const Curve = struct {
    /// Error which can occur when generating the public key
    pub const Error = crypto.errors.IdentityElementError;
    genFn: fn (*Curve, [32]u8, *[32]u8) Error!void,

    /// Generates a new public key from a given private key.
    /// Writes the output of the curve function to `public_key_out`.
    pub fn generateKey(self: *Curve, private_key: [32]u8, public_key_out: *[32]u8) Error!void {
        try self.genFn(self, private_key, public_key_out);
    }
};

/// Namespace of implemented curves, that can be used
/// to generate keys.
pub const curves = struct {
    const _x25519 = struct {
        var state = Curve{ .genFn = gen };

        fn gen(curve: *Curve, private_key: [32]u8, public_key_out: *[32]u8) !void {
            _ = curve;
            public_key_out.* = try crypto.dh.X25519.recoverPublicKey(private_key);
        }
    };
    /// Provides a x25519 elliptic curve to construct a private/public key-pair.
    pub const x25519 = &_x25519.state;

    /// From a given `NamedGroup` returns a `Curve`, used to generate
    /// a KeyExchange containing a public and private key component.
    pub fn fromNamedGroup(group: NamedGroup) *Curve {
        return switch (group) {
            .x25519 => x25519,
            else => @panic("TODO: Implement more curves"),
        };
    }
};

test "x25519 curve" {
    const x_curve = curves.x25519;
    const private_key = [_]u8{
        0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
        0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f,
        0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
        0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
    };

    const expected_public_key = [_]u8{
        0x9f, 0xd7, 0xad, 0x6d, 0xcf, 0xf4, 0x29, 0x8d,
        0xd3, 0xf9, 0x6d, 0x5b, 0x1b, 0x2a, 0xf9, 0x10,
        0xa0, 0x53, 0x5b, 0x14, 0x88, 0xd7, 0xf8, 0xfa,
        0xbb, 0x34, 0x9a, 0x98, 0x28, 0x80, 0xb6, 0x15,
    };

    var public_key: [32]u8 = undefined;
    try x_curve.generateKey(private_key, &public_key);

    try std.testing.expectEqualSlices(u8, &expected_public_key, &public_key);

    const exchange = try KeyExchange.fromCurve(x_curve);
    var test_key: [32]u8 = undefined;
    try x_curve.generateKey(exchange.private_key, &test_key);
    try std.testing.expectEqualSlices(u8, &exchange.public_key, &test_key);
}

/// Uses hkdf's expand to generate a derived key.
/// Constructs a hkdf context by generating a hkdf-label
/// which consists of `length`, the label "tls13 " ++ `label` and the given
/// `context`.
pub fn hkdfExpandLabel(
    secret: [32]u8,
    comptime label: []const u8,
    context: []const u8,
    comptime length: u16,
) [length]u8 {
    std.debug.assert(label.len <= 255 and label.len > 0);
    std.debug.assert(context.len <= 255);
    const full_label = "tls13 " ++ label;

    // length, label, context
    var buf: [2 + 255 + 255]u8 = undefined;
    std.mem.writeIntBig(u16, buf[0..2], length);
    buf[2] = full_label.len;
    std.mem.copy(u8, buf[3..], full_label);
    buf[3 + full_label.len] = @intCast(u8, context.len);
    std.mem.copy(u8, buf[4 + full_label.len ..], context);
    const actual_context = buf[0 .. 4 + full_label.len + context.len];

    var out: [32]u8 = undefined;
    HkdfSha256.expand(&out, actual_context, secret);
    return out[0..length].*;
}

test "hkdfExpandLabel" {
    const early_secret = HkdfSha256.extract(&.{}, &[_]u8{0} ** 32);
    var empty_hash: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash("", &empty_hash, .{});
    const derived_secret = hkdfExpandLabel(early_secret, "derived", &empty_hash, 32);
    try std.testing.expectEqualSlices(u8, &.{
        0x6f, 0x26, 0x15, 0xa1, 0x08, 0xc7, 0x02,
        0xc5, 0x67, 0x8f, 0x54, 0xfc, 0x9d, 0xba,
        0xb6, 0x97, 0x16, 0xc0, 0x76, 0x18, 0x9c,
        0x48, 0x25, 0x0c, 0xeb, 0xea, 0xc3, 0x57,
        0x6c, 0x36, 0x11, 0xba,
    }, &derived_secret);
}

test "runtime cipher suite" {
    // var suite_we_want: CipherSuite = .tls_aes_128_gcm_sha256;
    // inline for (supported_cipher_suites.set) |supported| {
    //     if (supported == suite_we_want) {
    //         const CipherType = ciphers.TypeFromSuite(supported);
    //         var selected_cipher = CipherType.default;
    //         const cipher: *Cipher = selected_cipher.cipher();
    //         try std.testing.expectEqual(CipherSuite.tls_aes_128_gcm_sha256, cipher.cipher_suite);
    //     }
    // }
}
