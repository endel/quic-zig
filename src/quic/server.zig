const std = @import("std");
const os = std.os;

const Connection = @import("connection.zig").Connection;
const structs = @import("structs.zig");
const tlsStructs = @import("structs_tls.zig");

const TicketStore = std.StringHashMap(tlsStructs.SessionTicket);

pub const Server = struct {
    config: structs.QuicConfiguration,
    ticket_store: TicketStore,

    pub fn init(config: structs.QuicConfiguration, ticket_store: TicketStore) Server {
        return .{ .config = config, .ticket_store = ticket_store };
    }

    pub fn accept(self: Server) Connection {
        _ = self;
        std.log.info("ACCEPT!", .{});
        return Connection.init();
    }

    pub fn listen(_: Server, addr: std.net.Address) !i32 {
        const sockfd = try os.socket(os.AF.INET, os.SOCK.DGRAM | os.SOCK.CLOEXEC | os.SOCK.NONBLOCK, 0);

        try os.bind(sockfd, &addr.any, @sizeOf(os.sockaddr.in));
        std.log.info("socket bound at {any}", .{addr});

        return sockfd;
    }
};
