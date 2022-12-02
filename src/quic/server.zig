const std = @import("std");
const os = std.os;
const io = std.io;

const connection = @import("connection.zig");
const packet = @import("packet.zig");
const crypto = @import("crypto.zig");

const Connection = connection.Connection;
const ConnectionState = connection.ConnectionState;

pub const Server = struct {
    // config: structs.QuicConfiguration,

    // pub fn init(config: QuicConfiguration) Server {
    pub fn init() Server {
        return .{};
    }

    pub fn accept(self: Server, header: packet.Header) !Connection {
        // , scid: []const u8, dcid: []const u8
        _ = self;
        // _ = scid;
        // _ = dcid;

        const is_client = false;

        // // init quictls context
        // var context = quictls.Context.init(is_client);

        var conn = Connection{
            .dcid = header.dcid,
            .scid = header.scid,
            .version = header.version,
            // .context = context,
            .state = ConnectionState.FirstFlight,
            .is_server = !is_client,
        };

        // https://datatracker.ietf.org/doc/html/rfc9001#section-5.1
        // TODO: improve me!
        const INITIAL = @as(usize, @enumToInt(packet.Epoch.INITIAL));
        try conn.pkt_num_spaces[INITIAL].setupInitial(header.dcid, header.version, is_client);

        return conn;
    }

    pub fn listen(_: Server, addr: std.net.Address) !i32 {
        const sockfd = try os.socket(os.AF.INET, os.SOCK.DGRAM | os.SOCK.CLOEXEC | os.SOCK.NONBLOCK, 0);

        try os.bind(sockfd, &addr.any, @sizeOf(os.sockaddr.in));
        std.log.info("socket bound at {any}", .{addr});

        return sockfd;
    }
};
