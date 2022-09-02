const std = @import("std");
const protocol = @import("protocol.zig");
const quictls = @import("quictls.zig");
const crypto = @import("crypto.zig");
const recovery = @import("recovery.zig");

pub const ConnectionState = enum(u8) {
    FirstFlight = 0,
    Connected = 1,
    Closing = 2,
    Draining = 3,
    Terminated = 4,
};

pub const ConnectionId = struct {};

///
/// A Quic connection
///
pub const Connection = struct {
    version: ?protocol.Version = null,

    dcid: []const u8,
    scid: []const u8,

    state: ConnectionState = ConnectionState.FirstFlight,

    // stats
    recv_count: u32 = 0,
    sent_count: u32 = 0,
    retrans_count: u32 = 0,
    sent_bytes: u32 = 0,
    recv_bytes: u32 = 0,

    context: quictls.Context,

    _cryptos: [4]crypto.CryptoPair = .{
        crypto.CryptoPair{}, // quictls.Epoch.INITIAL
        crypto.CryptoPair{}, // quictls.Epoch.ZERO_RTT
        crypto.CryptoPair{}, // quictls.Epoch.HANDSHAKE
        crypto.CryptoPair{}, // quictls.Epoch.ONE_RTT
    },

    _spaces: [4]recovery.QuicPacketSpace = .{
        recovery.QuicPacketSpace{}, // quictls.Epoch.INITIAL
        recovery.QuicPacketSpace{}, // quictls.Epoch.ZERO_RTT TODO: this one is never used!
        recovery.QuicPacketSpace{}, // quictls.Epoch.HANDSHAKE
        recovery.QuicPacketSpace{}, // quictls.Epoch.ONE_RTT
    },

    // pkt_num_spaces: u32,
    // handshake: quictls,
    // is_client: bool = false,

    // fn initTLS(self: Connection) void {
    //     _ = self;
    //     // self._spaces.add
    // }
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

test "init connection" {
    var context = quictls.Context.init(false);

    var conn = Connection{
        .dcid = "dest1234",
        .scid = "src12345",
        .version = protocol.Version.VERSION_1,
        .context = context,
        .state = ConnectionState.FirstFlight,
    };

    try std.testing.expectEqual(conn.dcid, "dest1234");
    try std.testing.expectEqual(conn.scid, "src12345");
}
