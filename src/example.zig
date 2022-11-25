const std = @import("std");
const net = std.net;
const fs = std.fs;
const io = std.io;
const os = std.os;
const mem = std.mem;
const Queue = std.atomic.Queue;

const Server = @import("quic/server.zig").Server;
const connection = @import("quic/connection.zig");
const packet = @import("quic/packet.zig");
const protocol = @import("quic/protocol.zig");
const token = @import("quic/handshake/token.zig");

const h0 = @import("h0/connection.zig");
const h3 = @import("h3/connection.zig");
const quictls = @import("quic/quictls.zig");

const hmac = std.crypto.auth.hmac;

// pub const io_mode = .evented;
const MAX_DATAGRAM_SIZE: usize = 1350;

pub fn main() anyerror!void {
    // var alloc = std.heap.GeneralPurposeAllocator(.{}){};
    // defer _ = alloc.deinit();
    var alloc = std.heap.page_allocator;
    var ticket_store = std.StringHashMap(quictls.SessionTicket).init(alloc);

    var server = Server.init(.{
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
    // const sockfd = try server.listen(try std.net.Address.parseIp6("::1", 4433));
    defer os.close(sockfd);

    var connections = std.StringHashMap(connection.Connection).init(alloc);
    defer connections.clearAndFree();

    // out/write buffer
    var out: [MAX_DATAGRAM_SIZE]u8 = undefined;
    var out_buff = io.fixedBufferStream(&out);
    var out_writer = out_buff.writer();

    var prevTimestamp = std.time.timestamp();

    while (true) {
        os.nanosleep(0, 100 * 1000 * 1000);

        // reset write position
        try out_buff.seekTo(0);

        var bytes: [8192]u8 = undefined;

        var src_addr: os.sockaddr = undefined;
        var addr_size: std.os.socklen_t = @sizeOf(os.sockaddr);

        const packet_length = os.recvfrom(sockfd, &bytes, 0, &src_addr, &addr_size) catch {
            continue;
        };

        std.log.info("\n<<-\nRECEIVED PACKET ({}ms) from {} (addr size: {})", .{ (std.time.timestamp() - prevTimestamp), src_addr, addr_size });
        prevTimestamp = std.time.timestamp();
        std.log.info("FULL PACKET: (len: {}) {any}", .{ packet_length, bytes[0..packet_length] });

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

        std.log.info("packet type: {any}", .{header.packet_type});
        if (header.packet_type != packet.PacketType.Initial) {
            std.log.err("Packet is not initial!", .{});
            continue;
        }

        //
        // TODO: Version negotiation
        //

        if (!protocol.isSupportedVersion(header.version)) {
            std.log.warn("client wants to use unsupported version {}, let's negotiate version...", .{header.version});
            try packet.negotiateVersion(header, &out_writer);

            var bytes_to_send = out_buff.getWritten();
            const bytes_sent = try os.sendto(sockfd, bytes_to_send, 0, &src_addr, addr_size);
            std.log.info("\n->>\nSENT VERSION NEGOTIATION PACKET (sent: {} bytes) => {any}", .{ bytes_sent, bytes_to_send });

            continue;
        }

        if (header.token == null or header.token.?.len == 0) {
            // TODO: Do stateless retry if the client didn't send a token.
            std.log.warn("(->) PREPPING RETRY PACKET", .{});

            // generates a random original destination connection id
            var new_scid = connection.generateConnectionId(header.scid.len);
            var retry_token = try token.generateRetryToken(header, new_scid, src_addr);

            std.log.info("new scid: {any}", .{new_scid});
            std.log.warn("retry token: {any}", .{retry_token});

            try packet.retry(header, new_scid, retry_token, &out_writer);

            var bytes_to_send = out_buff.getWritten();

            const bytes_sent = try os.sendto(sockfd, bytes_to_send, 0, &src_addr, addr_size);
            std.log.info("\n->>\nRETRY PACKET (sent: {} bytes)\n{any}", .{ bytes_sent, bytes_to_send });

            continue;
        }

        std.log.info("retry token length: {}", .{header.token.?.len});

        const conn_pair = try connections.getOrPut(header.scid);
        if (!conn_pair.found_existing) {
            if (header.scid.len != header.dcid.len) {
                std.log.err("Invalid destination connection ID", .{});
            }

            std.log.info("ACCEPT CONNECTION!", .{});
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

        var decrypted = conn.decrypt_packet(&header, &stream) catch |err| {
            std.log.err("decrypt error: {any}", .{err});
            break;
        };

        // TODO: ignore duplicate packets (aka "num spaces")
        // (check against local cache of packet numbers)
        std.log.info("payload ({any}): {any}", .{ decrypted.len, decrypted });

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
