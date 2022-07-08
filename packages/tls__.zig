// https://github.com/aiortc/aioquic/blob/main/src/aioquic/tls.py

const std = @import("std");

pub const TLS_VERSION = enum(i32) {
    TLS_1_2 = 0x0303,
    TLS_1_3 = 0x0304,
    TLS_1_3_DRAFT_28 = 0x7F1C,
    TLS_1_3_DRAFT_27 = 0x7F1B,
    TLS_1_3_DRAFT_26 = 0x7F1A,
};

const AlertDescription = enum (i32) {
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
};

const Direction = enum (i32) {
    DECRYPT = 0,
    ENCRYPT = 1,
};

const Epoch = enum (i32) {
    INITIAL = 0,
    ZERO_RTT = 1,
    HANDSHAKE = 2,
    ONE_RTT = 3,
};

const State = enum (i32) {
    CLIENT_HANDSHAKE_START = 0,
    CLIENT_EXPECT_SERVER_HELLO = 1,
    CLIENT_EXPECT_ENCRYPTED_EXTENSIONS = 2,
    CLIENT_EXPECT_CERTIFICATE_REQUEST_OR_CERTIFICATE = 3,
    CLIENT_EXPECT_CERTIFICATE_CERTIFICATE = 4,
    CLIENT_EXPECT_CERTIFICATE_VERIFY = 5,
    CLIENT_EXPECT_FINISHED = 6,
    CLIENT_POST_HANDSHAKE = 7,

    SERVER_EXPECT_CLIENT_HELLO = 8,
    SERVER_EXPECT_FINISHED = 9,
    SERVER_POST_HANDSHAKE = 10,
};
