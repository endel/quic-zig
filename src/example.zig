const std = @import("std");
const net = std.net;
const fs = std.fs;
const io = std.io;
const os = std.os;
const mem = std.mem;
const Queue = std.atomic.Queue;

const tls = @import("tls/feilich.zig");
const QuicServer = @import("quic/server.zig").QuicServer;
const QuicConfiguration = @import("quic/structs.zig").QuicConfiguration;
const packet = @import("quic/packet.zig");

const h0 = @import("h0/connection.zig");
const h3 = @import("h3/connection.zig");
const tlsStructs = @import("quic/structs_tls.zig");

// pub const io_mode = .evented;

pub fn main() anyerror!void {
    // var alloc = std.heap.GeneralPurposeAllocator(.{}){};
    // defer _ = alloc.deinit();
    var alloc = std.heap.page_allocator;
    var ticket_store = std.StringHashMap(tlsStructs.SessionTicket).init(alloc);

    var server = QuicServer.init(.{
        .alpn_protocols = h3.ALPN ++ h0.ALPN ++ [_][]const u8{"siduck"},
        .is_client = true,
        .max_datagram_frame_size = 65536,
    }, ticket_store);

    try server.configuration.readCertChain(alloc, .{
        .certfile = "self-signed/aioquic/ssl_cert.pem",
        .keyfile = "self-signed/aioquic/ssl_key.pem",
        // .certfile = @embedFile("../self-signed/aioquic/ssl_cert.pem"),
        // .keyfile = @embedFile("../self-signed/aioquic/ssl_key.pem"),
    });

    const sockfd = try server.listen(try std.net.Address.parseIp4("127.0.0.1", 8080));
    defer os.close(sockfd);

    while (true) {
        os.nanosleep(0, 100 * 1000 * 1000);

        var bytes: [8192]u8 = undefined;

        var src_addr: os.sockaddr = undefined;
        var addr_size: std.os.socklen_t = @sizeOf(os.sockaddr);

        const packet_length = os.recvfrom(sockfd, &bytes, 0, &src_addr, &addr_size) catch {
            continue;
        };

        std.log.info("packet length {} => {}", .{ packet_length, src_addr });
        std.log.info("packet received {any}", .{bytes[0..packet_length]});

        // try packet.parseIncoming(bytes[0..packet_length]);

        // var stream = io.fixedBufferStream(bytes[0..packet_length]);
        // const reader = stream.reader();

        var packet_header = try packet.QuicPacketHeader.parseFrom(bytes[0..packet_length]);
        std.log.info("quicPacketHeader => {}", .{packet_header});

        const sent_size = try os.sendto(sockfd, bytes[0..packet_length], 0, &src_addr, addr_size);
        std.log.info("sendto, size => {}", .{sent_size});
    }

    // // reading buffer
    // var bytes: [8192]u8 = undefined;
    //
    // while (true) {
    //     os.nanosleep(0, 100 * 1000 * 1000);
    //
    //     const len = os.recvfrom(sockfd, &bytes, 0, null, null) catch {
    //         continue;
    //     };
    //
    //     // take a pre-allocated buffers
    //     const packet = Packet{
    //         // .payload = try std.heap.page_allocator.alloc(u8, packet_size),
    //         .payload = bytes[0..len],
    //         .len = len,
    //     };
    //
    //     // tls_server.connect(reader, )
    //     var it: usize = 0;
    //     while (it < len) {
    //         const byte = bytes[it];
    //         std.log.info("reading... {}", .{byte});
    //         it += 1;
    //     }
    //
    //     std.log.info("packet received {any}", .{packet});
    //     std.log.info("packet received {any}", .{packet});
    //
    //     // // copy the data
    //     // std.mem.copy(u8, packet.payload[0..len], buf[0..len]);
    //
    //     // send it for processing
    //     // queue.put(packet);
    //
    //     // const tmp = std.time.milliTimestamp() - last_drop_message;
    //     // if (tmp > 10000) {
    //     //     last_drop_message = std.time.milliTimestamp();
    //     //     std.log.warn("drops: {}/s\n", .{@divTrunc(drops, @divTrunc(tmp, 1000))});
    //     //     drops = 0;
    //     // }
    // }
}

test {
    _ = @import("quic/packet.zig");
}
