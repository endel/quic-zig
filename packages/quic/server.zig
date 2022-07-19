const std = @import("std");
const os = std.os;

const structs = @import("structs.zig");
const tlsStructs = @import("structs_tls.zig");

const TicketStore = std.StringHashMap(tlsStructs.SessionTicket);

pub const QuicServer = struct {
    configuration: structs.QuicConfiguration,
    ticket_store: TicketStore,

    pub fn init(configuration: structs.QuicConfiguration, ticket_store: TicketStore) QuicServer {
        return .{ .configuration = configuration, .ticket_store = ticket_store };
    }

    pub fn listen(_: QuicServer, addr: std.net.Address) !i32 {
        const sockfd = try os.socket(os.AF.INET, os.SOCK.DGRAM | os.SOCK.CLOEXEC | os.SOCK.NONBLOCK, 0);

        try os.bind(sockfd, &addr.any, @sizeOf(os.sockaddr.in));
        std.log.info("socket bound at {any}", .{addr});

        return sockfd;
    }
};

// serve(
//     args.host,
//     args.port,
//     configuration=configuration,
//     create_protocol=HttpServerProtocol,
//     session_ticket_fetcher=ticket_store.pop,
//     session_ticket_handler=ticket_store.add,
//     retry=args.retry,
// )
