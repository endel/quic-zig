const std = @import("std");
const string = []const u8;

pub const Epoch = enum(u8) {
    INITIAL = 0,
    ZERO_RTT = 1,
    HANDSHAKE = 2,
    ONE_RTT = 3,
};

pub const CipherSuite = enum(u32) {
    AES_128_GCM_SHA256 = 0x1301,
    AES_256_GCM_SHA384 = 0x1302,
    CHACHA20_POLY1305_SHA256 = 0x1303,
    EMPTY_RENEGOTIATION_INFO_SCSV = 0x00FF,
};

pub const State = enum(u8) {
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

//
// A TLS session ticket for session resumption.
//
pub const SessionTicket = struct {
    age_add: u32,
    cipher_suite: CipherSuite,
    not_valid_after: i64, // datetime.datetime
    not_valid_before: i64, // datetime.datetime
    resumption_secret: []const u8,
    server_name: string,
    ticket: []const u8,

    max_early_data_size: u32 = undefined,

    // other_extensions: List[Tuple[int, bytes]] = field(default_factory=list)

    pub fn isValid(self: SessionTicket) bool {
        const now = std.time.milliTimestamp();
        return now >= self.not_valid_before and now <= self.not_valid_after;
    }

    // @property
    // def obfuscated_age(self) -> int:
    //     age = int((utcnow() - self.not_valid_before).total_seconds() * 1000)
    //     return (age + self.age_add) % (1 << 32)

};
