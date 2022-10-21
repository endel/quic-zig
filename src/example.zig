const std = @import("std");
const net = std.net;
const fs = std.fs;
const io = std.io;
const os = std.os;
const mem = std.mem;
const Queue = std.atomic.Queue;

const QuicServer = @import("quic/server.zig").Server;
const Connection = @import("quic/connection.zig").Connection;
const packet = @import("quic/packet.zig");
const protocol = @import("quic/protocol.zig");

const h0 = @import("h0/connection.zig");
const h3 = @import("h3/connection.zig");
const quictls = @import("quic/quictls.zig");

const hmac = std.crypto.auth.hmac;

// pub const io_mode = .evented;

pub fn main() anyerror!void {
    // var alloc = std.heap.GeneralPurposeAllocator(.{}){};
    // defer _ = alloc.deinit();
    var alloc = std.heap.page_allocator;
    var ticket_store = std.StringHashMap(quictls.SessionTicket).init(alloc);

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

    const sockfd = try server.listen(try std.net.Address.parseIp4("127.0.0.1", 4433));
    defer os.close(sockfd);

    var connections = std.StringHashMap(Connection).init(alloc);
    defer connections.clearAndFree();

    while (true) {
        os.nanosleep(0, 100 * 1000 * 1000);

        var bytes: [8192]u8 = undefined;

        var src_addr: os.sockaddr = undefined;
        var addr_size: std.os.socklen_t = @sizeOf(os.sockaddr);

        const packet_length = os.recvfrom(sockfd, &bytes, 0, &src_addr, &addr_size) catch {
            continue;
        };

        std.log.info("packet received, length {} => {}", .{ packet_length, src_addr });
        std.log.info("packet received {any}", .{bytes[0..packet_length]});

        // var stream = io.fixedBufferStream(bytes[0..packet_length]);
        // const reader = stream.reader();
        var stream = io.fixedBufferStream(bytes[0..packet_length]);
        var header = try packet.Header.parse(&stream);

        // make sure payload is not higher than received packet  length
        std.log.info("remainder_len: {any} / {any} (packet_length)", .{ header.remainder_len, packet_length });
        if (header.remainder_len > packet_length) {
            std.log.warn("remaining length is higher than packet length!", .{});
            continue;
        }

        // TODO: hmac sign `destination_cid` to avoid connections having full
        // control which ID is being used.
        // let conn_id = ring::hmac::sign(&conn_id_seed, &hdr.dcid);
        const conn_id = header.dcid;

        const conn_pair = try connections.getOrPut(conn_id);
        if (!conn_pair.found_existing) {
            if (header.packet_type != packet.PacketType.Initial) {
                std.log.err("Packet is not initial!", .{});
                continue;
            }

            //
            // TODO: Version negotiation
            //

            if (!protocol.isSupportedVersion(header.version)) {
                std.log.warn("TODO: CLIENT WANTS TO USE VERSION {}, let's negotiate the version...", .{header.version});
            }

            if (header.token == null or header.token.?.len == 0) {
                // TODO: Do stateless retry if the client didn't send a token.
                std.log.warn("TODO: Do stateless retry!", .{});
            }

            std.log.info("header.scid: ({}) {any}", .{ header.scid.len, header.scid });
            std.log.info("header.dcid: ({}) {any}", .{ header.dcid.len, header.dcid });

            if (header.scid.len != header.dcid.len) {
                std.log.err("Invalid destination connection ID", .{});
            }

            var conn = try server.accept(header);
            conn_pair.value_ptr.* = conn;

            //
        } else {
            std.log.warn("HAS CONNECTION!", .{});
        }

        var conn = conn_pair.value_ptr.*;

        const epoch = try packet.Epoch.fromPacketType(header.packet_type);

        if (epoch == packet.Epoch.ZERO_RTT) {
            std.log.info("TODO: implement zero rtt", .{});
            continue;
        }

        std.log.info("stream.pos: {any}, header.remainder_len: {any}", .{ stream.pos, header.remainder_len });

        conn.decrypt_packet(&header, &stream) catch |err| {
            std.log.err("decrypt error: {any}", .{err});
            break;
        };

        // var decrypted_bytes: [packet.MAX_PACKET_LEN]u8 = undefined;
        // try crypto.decryptPacket(&decrypted_bytes, stream.buffer[0..end_offset], encrypted_offset, space.expected_packet_number);

        // var crypto = conn._cryptos[@as(usize, @enumToInt(epoch))];
        // var space = conn._spaces[@as(usize, @enumToInt(epoch))];
        // _ = crypto;
        // _ = space;

        // network_path = self._find_network_path(addr)

        if (header.packet_type == packet.PacketType.Initial) {}

        // const sent_size = try os.sendto(sockfd, bytes[0..packet_length], 0, &src_addr, addr_size);
        // std.log.info("sendto, size => {}", .{sent_size});
    }
}

test {
    _ = @import("quic/packet.zig");
    _ = @import("quic/connection.zig");
}
