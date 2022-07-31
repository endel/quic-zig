const std = @import("std");
const net = std.net;
const fs = std.fs;
const io = std.io;
const os = std.os;
const mem = std.mem;
const Queue = std.atomic.Queue;

const tls = @import("tls/feilich.zig");
const QuicServer = @import("quic/server.zig").Server;
const QuicConfig = @import("quic/config.zig").Config;
const QuicConnection = @import("quic/connection.zig").Connection;
const packet = @import("quic/packet.zig");

const h0 = @import("h0/connection.zig");
const h3 = @import("h3/connection.zig");
const tlsStructs = @import("quic/structs_tls.zig");

const hmac = std.crypto.auth.hmac;

// pub const io_mode = .evented;

pub fn main() anyerror!void {
    // var alloc = std.heap.GeneralPurposeAllocator(.{}){};
    // defer _ = alloc.deinit();
    var alloc = std.heap.page_allocator;
    var ticket_store = std.StringHashMap(tlsStructs.SessionTicket).init(alloc);

    var server = QuicServer.init(.{
        .alpn_protocols = h3.ALPN ++ h0.ALPN ++ [_][]const u8{"siduck"},
        // .is_client = false,
        .max_datagram_frame_size = 65536,
    }, ticket_store);

    try server.config.readCertChain(alloc, .{
        .certfile = "self-signed/aioquic/ssl_cert.pem",
        .keyfile = "self-signed/aioquic/ssl_key.pem",
        // .certfile = @embedFile("../self-signed/aioquic/ssl_cert.pem"),
        // .keyfile = @embedFile("../self-signed/aioquic/ssl_key.pem"),
    });

    // var rnd: [hmac.sha2.HmacSha256.mac_length]u8 = undefined;
    // std.crypto.random.bytes(&rnd);
    //
    // var connection_id_seed: [hmac.sha2.HmacSha256.mac_length]u8 = undefined;
    // hmac.sha2.HmacSha256.create(connection_id_seed[0..], "", "");

    const sockfd = try server.listen(try std.net.Address.parseIp4("127.0.0.1", 8080));
    defer os.close(sockfd);

    var clients = std.StringHashMap(QuicConnection).init(alloc);

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

        // var stream = io.fixedBufferStream(bytes[0..packet_length]);
        // const reader = stream.reader();

        var header = try packet.Header.parse(bytes[0..packet_length]);

        // TODO: hmac sign `destination_cid` to avoid clients having full
        // control which ID is being used.
        // let conn_id = ring::hmac::sign(&conn_id_seed, &hdr.dcid);

        const conn_pair = try clients.getOrPut(header.destination_cid);
        if (!conn_pair.found_existing) {
            if (header.packet_type != packet.PacketType.Initial) {
                std.log.err("Packet is not initial!", .{});
                continue;
            }

            //
            // TODO: Version negotiation
            //
            if (header.version != packet.ProtocolVersion.VERSION_1 and
                header.version != packet.ProtocolVersion.VERSION_2)
            {
                std.log.warn("TODO: CLIENT WANTS TO USE VERSION {}, let's negotiate the version...", .{header.version});
            }

            if (header.token == null) {
                // TODO: Do stateless retry if the client didn't send a token.
                std.log.warn("TODO: Do stateless retry!", .{});
            }

            conn_pair.value_ptr.* = server.accept();
            //
        } else {
            std.log.warn("HAS CONNECTION!", .{});
        }

        const conn = conn_pair.value_ptr.*;
        _ = conn;

        if (header.packet_type == packet.PacketType.Initial) {}

        // const sent_size = try os.sendto(sockfd, bytes[0..packet_length], 0, &src_addr, addr_size);
        // std.log.info("sendto, size => {}", .{sent_size});
    }
}

test {
    _ = @import("quic/packet.zig");
}
