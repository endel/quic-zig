const std = @import("std");
const os = std.os;

const connection = @import("connection.zig");
const structs = @import("structs.zig");
const packet = @import("packet.zig");
const quictls = @import("quictls.zig");

const TicketStore = std.StringHashMap(quictls.SessionTicket);

const Connection = connection.Connection;
const ConnectionState = connection.ConnectionState;

pub const Server = struct {
    config: structs.QuicConfiguration,
    ticket_store: TicketStore,

    pub fn init(config: structs.QuicConfiguration, ticket_store: TicketStore) Server {
        return .{ .config = config, .ticket_store = ticket_store };
    }

    pub fn accept(self: Server, header: packet.Header) Connection {
        // , scid: []const u8, dcid: []const u8
        _ = self;
        // _ = scid;
        // _ = dcid;

        std.log.info("ACCEPT!", .{});

        const is_client = false;

        // init quictls context
        var context = quictls.Context.init(is_client);

        var conn = Connection{
            .dcid = header.dcid,
            .scid = header.scid,
            .version = header.version,
            .context = context,
            .state = ConnectionState.FirstFlight,
        };

        // https://datatracker.ietf.org/doc/html/rfc9001#section-5.1
        conn._cryptos[@as(usize, @enumToInt(quictls.Epoch.INITIAL))].setupInitial(header.dcid, header.version, is_client);

        return conn;
    }

    pub fn listen(_: Server, addr: std.net.Address) !i32 {
        const sockfd = try os.socket(os.AF.INET, os.SOCK.DGRAM | os.SOCK.CLOEXEC | os.SOCK.NONBLOCK, 0);

        try os.bind(sockfd, &addr.any, @sizeOf(os.sockaddr.in));
        std.log.info("socket bound at {any}", .{addr});

        return sockfd;
    }
};
