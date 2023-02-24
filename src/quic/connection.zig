const std = @import("std");
const net = std.net;
const os = std.os;
const crypto = std.crypto;

const protocol = @import("protocol.zig");
// const crypto = @import("crypto.zig");
const packet = @import("packet.zig");
const tls = @import("tls.zig");
const Frame = @import("frame.zig").Frame;
const Client = @import("handshake/Client.zig");

pub const State = enum(u8) {
    first_flight = 0,
    connected = 1,
    closing = 2,
    draining = 3,
    terminated = 4,
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

    pub fn encode() void {
        // TODO: encode TransportParams
    }
};

pub const ConnectionError = struct {
    is_app: bool,
    code: u64,
    reason: []const u8,
};

pub const RecvInfo = struct {
    to: os.sockaddr,
    from: os.sockaddr,
};

///
/// A Quic connection
///
pub const Connection = struct {
    version: u32 = undefined,

    dcid: [packet.CONNECTION_ID_MAX_SIZE]u8 = .{0} ** packet.CONNECTION_ID_MAX_SIZE,
    scid: [packet.CONNECTION_ID_MAX_SIZE]u8 = .{0} ** packet.CONNECTION_ID_MAX_SIZE,

    handshake: tls.Handshake = .{},

    is_server: bool,
    transport_params: TransportParams = TransportParams.default(),
    local_err: ?ConnectionError = null,

    state: State = State.first_flight,
    paths: [1]NetworkPath = .{undefined} ** 1, // TODO: support multiple paths

    pkt_num_spaces: [3]packet.PacketNumSpace = .{
        packet.PacketNumSpace{}, // packet.Epoch.INITIAL
        packet.PacketNumSpace{}, // packet.Epoch.ZERO_RTT // TODO: this one is never used!
        packet.PacketNumSpace{}, // packet.Epoch.HANDSHAKE
        // packet.PacketNumSpace{}, // packet.Epoch.ONE_RTT
    },

    got_peer_conn_id: bool = false,

    allocator: std.mem.Allocator,

    tmp_handshake_loop: u8 = 0,

    pub fn accept(
        allocator: std.mem.Allocator,
        header: packet.Header,
        local: os.sockaddr, // net.Address,
        remote: os.sockaddr, // net.Address,
        comptime is_server: bool,
    ) !Connection {
        var initial_path = NetworkPath.init(local, remote, true);

        var conn = Connection{
            .allocator = allocator,
            // .dcid = header.dcid,
            // .scid = header.scid,
            .version = header.version,
            .is_server = is_server,
            .paths = .{initial_path},
        };

        @memcpy(&conn.dcid, header.dcid.ptr, header.dcid.len);
        @memcpy(&conn.scid, header.scid.ptr, header.scid.len);

        // https://datatracker.ietf.org/doc/html/rfc9001#section-5.1
        // TODO: improve me!
        try conn.pkt_num_spaces[@enumToInt(packet.Epoch.initial)].setupInitial(header.dcid, header.version, is_server);

        return conn;
    }

    pub fn deinit(self: Connection) void {
        _ = self;
        // self.allocator
    }

    pub fn recv(self: *Connection, header: *packet.Header, fbs: anytype, info: RecvInfo) !void {
        _ = info;
        std.log.info("fbs.pos: {any}, header.remainder_len: {any}", .{ fbs.pos, header.remainder_len });

        // TODO:
        const epoch = try packet.Epoch.fromPacketType(header.packet_type);
        if (epoch == packet.Epoch.zero_rtt) {
            std.log.info("TODO: implement zero rtt", .{});
            return error.NotImplemented;
        }

        var space = self.pkt_num_spaces[@enumToInt(epoch)];
        var payload = packet.decrypt(header, fbs, space) catch |err| {
            std.log.err("can't decrypt packet. {any}", .{err});
            return error.InvalidPacket;
        };

        // TODO: ignore duplicate packets (aka "num spaces")
        // (check against local cache of packet numbers)
        // ...

        // no frames. skip invalid packet!
        if (payload.len == 0) {
            std.log.info("no frames. skip invalid packet!", .{});
            return error.InvalidPacket;
        }

        // TODO: determine path / support multiple paths (+ multipath extension)
        const path_idx = path_idx: {
            var idx: usize = undefined;

            if (header.packet_type == packet.PacketType.zero_rtt and
                self.got_peer_conn_id)
            {
                // let pkt_dcid = ConnectionId::from_ref(&hdr.dcid);
                // get_or_create_recv_path_id(recv_pid, &pkt_dcid, buf_len, info)

            } else {
                // we are on handshake, use the initial path.
                idx = 0;
                // get_active_path_id()
            }

            break :path_idx idx;
        };

        if (!self.is_server and !self.got_peer_conn_id) {
            // TODO: Replace the randomly generated destination connection ID
            // with the one supplied by the server.
        }

        if (self.is_server and !self.got_peer_conn_id) {
            self.setInitialDCID(header.scid, path_idx, undefined);

            // TODO: local transport params (+encode it)

            self.got_peer_conn_id = true;
        }
        std.log.info("payload ({any}): {any}", .{ payload.len, payload });

        // To avoid sending an ACK in response to an ACK-only packet, we need
        // to keep track of whether this packet contains any frame other than
        // ACK and PADDING.
        var ack_elicited = false;

        // To know if the peer migrated the connection, we need to keep track
        // whether this is a non-probing packet.
        var is_probing = false;

        // process payload frames
        const frame = try Frame.parse(payload);

        if (frame.isAckEliciting()) {
            ack_elicited = true;
        }

        if (frame.isProbing()) {
            is_probing = true;
        }

        try self.processFrame(frame, epoch);

        // build response
    }

    pub fn send(self: *Connection, out_writer: anytype) !void {
        std.log.info("> SEND() ...", .{});
        if (self.local_err != null) {
            self.doHandshake(out_writer.context.buffer);
        }
    }

    pub fn sendSingle(self: *Connection, out_writer: anytype) !void {
        // var is_closing = self.isDraining();

        // TODO: process lost frames/recovery [?]

        var packet_type: packet.PacketType = switch (self.handshake.write_level) {
            .initial => .initial,
            .early_data => unreachable,
            .handshake => .handshake,
            .application => .one_rtt,
        };
        if (packet_type == .one_rtt and self.handshake.is_completed) {
            packet_type = .handshake;
        }

        var epoch = packet.Epoch.fromPacketType(packet_type);
        var num_space = self.pkt_num_spaces[epoch];

        var pn = num_space.next_packet_number;
        var pn_len = packet.packetNumberLength(pn);

        var crypto_tag_len = num_space.cryptoTagLen();

        // FIXME: allow to select different network path
        var send_path_id = 0;
        var path = self.paths[send_path_id];

        _ = out_writer;
        _ = path;
        _ = crypto_tag_len;
        _ = pn_len;
        // var pn =

    }

    pub fn isClosed() bool {
        // TODO
        return false;
    }

    ///
    /// Returns true if the connection is waiting for all data to be sent and
    /// received before closing, false otherwise.
    ///
    pub fn isDraining() bool {
        // TODO
        return false;
    }

    pub fn setInitialDCID(self: Connection, cid: []const u8, path_id: usize, reset_token: ?[]u8) void {
        _ = self;
        _ = cid;
        _ = reset_token;
        _ = path_id;
    }

    pub fn processFrame(self: *Connection, frame: Frame, epoch: packet.Epoch) !void {
        var space = self.pkt_num_spaces[@enumToInt(epoch)];

        switch (frame) {
            .padding => |size| {
                std.log.info("Padding, size: {}", .{size});
            },
            .ping => {
                std.log.info("Ping...", .{});
            },

            .ack => {},
            .ack_ecn => {},

            .reset_stream => {},
            .stop_sending => {},

            .crypto => |crypto_frame| {

                //
                // CRYPTO frames are functionally identical to STREAM frames,
                // except that they do not bear a stream identifier; they are
                // not flow controlled; and they do not carry markers for
                // optional offset, optional length, and the end of the stream
                //
                // => https://datatracker.ietf.org/doc/html/rfc9000#name-crypto-frames
                //

                space.crypto_stream.recv(crypto_frame.data);

                std.log.info("processing crypto frame: {any}", .{crypto_frame});

                // var crypto_stream = space.crypto_stream;
                // crypto_stream.recv(crypto_frame.data);

                self.handshake.provideData(crypto_frame.data, @enumToInt(epoch));

                try self.handshake.perform(self.is_server);

                // var tls_client = try Client.init(&crypto_stream, ca_bundle, "");
                // std.log.info("TLS Client: {any}", .{tls_client});
            },

            .new_token => {},
            .stream => {},
            .max_data => {},
            .max_stream_data => {},
            .max_streams_bidi => {},
            .max_streams_uni => {},
            .data_blocked => {},
            .stream_data_blocked => {},
            .streams_blocked_bidi => {},
            .streams_blocked_uni => {},
            .new_connection_id => {},
            .retire_connection_id => {},
            .path_challenge => {},
            .path_response => {},
            .connection_close => {},
            .application_close => {},
            .handshake_done => {},
        }
    }

    fn doHandshake(self: *Connection, data: []u8) void {
        _ = self;
        _ = data;
    }
};

/// Generates a new connection id
pub fn generateConnectionId(size: usize) []u8 {
    // OPTIMIZE: potentially wasting compute here in order to avoid dynamic mem allocation
    var cid: [packet.CONNECTION_ID_MAX_SIZE]u8 = undefined;
    crypto.random.bytes(&cid);
    return cid[0..size];
}

test "init connection" {
    var conn = Connection{
        .allocator = std.testing.allocator,
        .is_server = true,
        .dcid = "dest1234",
        .scid = "src12345",
        .version = protocol.SUPPORTED_VERSIONS[0],
    };

    try std.testing.expectEqual(conn.dcid, "dest1234");
    try std.testing.expectEqual(conn.scid, "src12345");
}
