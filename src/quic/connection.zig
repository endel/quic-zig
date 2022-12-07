const std = @import("std");
const net = std.net;
const os = std.os;
const random = std.crypto.random;

const protocol = @import("protocol.zig");
const crypto = @import("crypto.zig");
const packet = @import("packet.zig");

pub const State = enum(u8) {
    FirstFlight = 0,
    Connected = 1,
    Closing = 2,
    Draining = 3,
    Terminated = 4,
};

// pub const ConnectionId = struct {};

pub const RecoveryConfig = struct {};

pub const NetworkPath = struct {
    local_addr: os.sockaddr,
    peer_addr: os.sockaddr,
    is_initial: bool,
    // recovery_config: RecoveryConfig,

    // bytes_received: u32,
    // bytes_sent: u32,
    // is_validated: bool,
    // local_challenge: []u8,
    // remote_challenge: []u8,

    pub fn init(
        local_addr: os.sockaddr, // net.Address,
        peer_addr: os.sockaddr, // net.Address,
        is_initial: bool,
    ) NetworkPath {
        return .{
            .local_addr = local_addr,
            .peer_addr = peer_addr,
            .is_initial = is_initial,
        };
    }

    // pub fn canSend(self: NetworkPath, size: u32) bool {
    //     // TODO: this math looks suspicious!
    //     return self.is_validated || (self.bytes_sent + size) <= 3 * self.bytes_received;
    // }
};

pub const TransportParams = struct {
    original_destination_connection_id: []u8,
    max_idle_timeout: u64,
    stateless_reset_token: ?u128,
    max_udp_payload_size: u64,
    initial_max_data: u64,
    initial_max_stream_data_bidi_local: u64,
    initial_max_stream_data_bidi_remote: u64,
    initial_max_stream_data_uni: u64,
    initial_max_streams_bidi: u64,
    initial_max_streams_uni: u64,
    ack_delay_exponent: u64,
    max_ack_delay: u64,
    disable_active_migration: bool,

    active_conn_id_limit: u64,
    initial_source_connection_id: ?[]u8,
    retry_source_connection_id: ?[]u8,
    max_datagram_frame_size: ?u64,

    pub fn default() TransportParams {
        return TransportParams{
            .original_destination_connection_id = undefined,
            .max_idle_timeout = 0,
            .stateless_reset_token = undefined,
            .max_udp_payload_size = 65527,
            .initial_max_data = 0,
            .initial_max_stream_data_bidi_local = 0,
            .initial_max_stream_data_bidi_remote = 0,
            .initial_max_stream_data_uni = 0,
            .initial_max_streams_bidi = 0,
            .initial_max_streams_uni = 0,
            .ack_delay_exponent = 3,
            .max_ack_delay = 25,
            .disable_active_migration = false,
            .active_conn_id_limit = 2,
            .initial_source_connection_id = undefined,
            .retry_source_connection_id = undefined,
            .max_datagram_frame_size = undefined,
        };
    }
};

///
/// A Quic connection
///
pub const Connection = struct {
    version: u32 = undefined,

    dcid: []const u8,
    scid: []const u8,

    is_server: bool,

    state: State = State.FirstFlight,
    paths: [1]NetworkPath = .{undefined} ** 1, // TODO: support multiple paths

    pkt_num_spaces: [3]packet.PacketNumSpace = .{
        packet.PacketNumSpace{}, // packet.Epoch.INITIAL
        packet.PacketNumSpace{}, // packet.Epoch.ZERO_RTT // TODO: this one is never used!
        packet.PacketNumSpace{}, // packet.Epoch.HANDSHAKE
        // packet.PacketNumSpace{}, // packet.Epoch.ONE_RTT
    },

    got_peer_conn_id: bool = false,

    // stats
    recv_count: u32 = 0,
    sent_count: u32 = 0,
    retrans_count: u32 = 0,
    sent_bytes: u32 = 0,
    recv_bytes: u32 = 0,

    rx_data: u64 = 0,

    // dgram_recv_queue: dgram::DatagramQueue::new(
    //     config.dgram_recv_max_queue_len,
    // ),
    //
    // dgram_send_queue: dgram::DatagramQueue::new(
    //     config.dgram_send_max_queue_len,
    // ),

    // _cryptos: [4]crypto.CryptoPair = .{
    //     crypto.CryptoPair{}, // packet.Epoch.INITIAL
    //     crypto.CryptoPair{}, // packet.Epoch.ZERO_RTT
    //     crypto.CryptoPair{}, // packet.Epoch.HANDSHAKE
    //     crypto.CryptoPair{}, // packet.Epoch.ONE_RTT
    // },

    pub fn decryptPacket(self: *Connection, header: *packet.Header, stream: anytype) ![]u8 {
        var epoch = try packet.Epoch.fromPacketType(header.*.packet_type);
        var space = self.pkt_num_spaces[@as(usize, @enumToInt(epoch))];

        return try packet.decrypt(header, stream, space);
    }
};

// 0x00: (self._handle_padding_frame, EPOCHS("IH01")),
// 0x01: (self._handle_ping_frame, EPOCHS("IH01")),
// 0x02: (self._handle_ack_frame, EPOCHS("IH1")),
// 0x03: (self._handle_ack_frame, EPOCHS("IH1")),
// 0x04: (self._handle_reset_stream_frame, EPOCHS("01")),
// 0x05: (self._handle_stop_sending_frame, EPOCHS("01")),
// 0x06: (self._handle_crypto_frame, EPOCHS("IH1")),
// 0x07: (self._handle_new_token_frame, EPOCHS("1")),
// 0x08: (self._handle_stream_frame, EPOCHS("01")),
// 0x09: (self._handle_stream_frame, EPOCHS("01")),
// 0x0A: (self._handle_stream_frame, EPOCHS("01")),
// 0x0B: (self._handle_stream_frame, EPOCHS("01")),
// 0x0C: (self._handle_stream_frame, EPOCHS("01")),
// 0x0D: (self._handle_stream_frame, EPOCHS("01")),
// 0x0E: (self._handle_stream_frame, EPOCHS("01")),
// 0x0F: (self._handle_stream_frame, EPOCHS("01")),
// 0x10: (self._handle_max_data_frame, EPOCHS("01")),
// 0x11: (self._handle_max_stream_data_frame, EPOCHS("01")),
// 0x12: (self._handle_max_streams_bidi_frame, EPOCHS("01")),
// 0x13: (self._handle_max_streams_uni_frame, EPOCHS("01")),
// 0x14: (self._handle_data_blocked_frame, EPOCHS("01")),
// 0x15: (self._handle_stream_data_blocked_frame, EPOCHS("01")),
// 0x16: (self._handle_streams_blocked_frame, EPOCHS("01")),
// 0x17: (self._handle_streams_blocked_frame, EPOCHS("01")),
// 0x18: (self._handle_new_connection_id_frame, EPOCHS("01")),
// 0x19: (self._handle_retire_connection_id_frame, EPOCHS("01")),
// 0x1A: (self._handle_path_challenge_frame, EPOCHS("01")),
// 0x1B: (self._handle_path_response_frame, EPOCHS("01")),
// 0x1C: (self._handle_connection_close_frame, EPOCHS("IH01")),
// 0x1D: (self._handle_connection_close_frame, EPOCHS("01")),
// 0x1E: (self._handle_handshake_done_frame, EPOCHS("1")),
// 0x30: (self._handle_datagram_frame, EPOCHS("01")),
// 0x31: (self._handle_datagram_frame, EPOCHS("01")),
//

/// Generates a new connection id
pub fn generateConnectionId(size: usize) []u8 {
    // OPTIMIZE: potentially wasting compute here in order to avoid dynamic mem allocation
    var cid: [packet.CONNECTION_ID_MAX_SIZE]u8 = undefined;
    random.bytes(&cid);
    return cid[0..size];
}

test "init connection" {
    var conn = Connection{
        .dcid = "dest1234",
        .scid = "src12345",
        .version = protocol.SUPPORTED_VERSIONS[0],
        .state = State.FirstFlight,
    };

    try std.testing.expectEqual(conn.dcid, "dest1234");
    try std.testing.expectEqual(conn.scid, "src12345");
}
