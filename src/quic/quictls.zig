const std = @import("std");
const string = []const u8;
const tls = @import("../tls/tls.zig");
const packet = @import("packet.zig");

const PTLS_MAX_DIGEST_SIZE = 42;
const CRYPTO_BUFFER_SIZE = 16384;

pub const Epoch = enum(u8) {
    INITIAL = 0,
    ZERO_RTT = 1,
    HANDSHAKE = 2,
    ONE_RTT = 3,

    pub fn fromPacketType(int: packet.PacketType) !Epoch {
        return switch (int) {
            packet.PacketType.Initial => Epoch.INITIAL,
            packet.PacketType.ZeroRTT => Epoch.ZERO_RTT,
            packet.PacketType.Handshake => Epoch.HANDSHAKE,
            packet.PacketType.OneRTT => Epoch.ONE_RTT,
            else => (error{InvalidPacketType}).InvalidPacketType,
        };
    }
};

test "Epoch fromPacketType" {
    try std.testing.expectEqual(Epoch.fromPacketType(packet.PacketType.Initial), Epoch.INITIAL);
    try std.testing.expectEqual(Epoch.fromPacketType(packet.PacketType.ZeroRTT), Epoch.ZERO_RTT);
    try std.testing.expectEqual(Epoch.fromPacketType(packet.PacketType.Handshake), Epoch.HANDSHAKE);
    try std.testing.expectEqual(Epoch.fromPacketType(packet.PacketType.OneRTT), Epoch.ONE_RTT);

    const err = Epoch.fromPacketType(packet.PacketType.Retry);
    try std.testing.expectError(error.InvalidPacketType, err);
}

pub const CipherSuite = tls.CipherSuite;
// enum(u32) {
//     AES_128_GCM_SHA256 = 0x1301,
//     AES_256_GCM_SHA384 = 0x1302,
//     CHACHA20_POLY1305_SHA256 = 0x1303,
//     EMPTY_RENEGOTIATION_INFO_SCSV = 0x00FF,
// };

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

pub const Context = struct {
    state: State,
    is_client: bool,

    // ptls_t* tls;
    // picoquic_cnx_t* cnx;
    // int client_mode;
    // ptls_raw_extension_t ext[2];
    // ptls_handshake_properties_t handshake_properties;
    // ptls_iovec_t* alpn_vec;
    // size_t alpn_vec_size;
    // size_t alpn_count;
    // uint8_t* ext_data;
    // size_t ext_data_size;
    // uint16_t esni_version;
    // uint8_t esni_nonce[PICOQUIC_ESNI_NONCE_SIZE];
    // uint8_t app_secret_enc[PTLS_MAX_DIGEST_SIZE];
    // uint8_t app_secret_dec[PTLS_MAX_DIGEST_SIZE];

    pub fn init(comptime is_client: bool) Context {
        return .{
            .state = if (is_client) State.CLIENT_HANDSHAKE_START else State.SERVER_EXPECT_CLIENT_HELLO,
            .is_client = is_client,
        };
    }

    pub fn handleMessage(self: Context) void {
        if (self.state == State.CLIENT_HANDSHAKE_START) {
            std.log.info("State.CLIENT_HANDSHAKE_START");
            // TODO: send ClientHello
            return;
        }
    }
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
