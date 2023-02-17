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
const Frame = @import("quic/frame.zig").Frame;
const tls = @import("quic/tls.zig");

const h0 = @import("h0/connection.zig");
const h3 = @import("h3/connection.zig");

const hmac = std.crypto.auth.hmac;

// pub const io_mode = .evented;
const MAX_DATAGRAM_SIZE: usize = 1350;

pub fn main() anyerror!void {
    // var allocator = std.heap.GeneralPurposeAllocator(.{}){};
    // defer _ = allocator.deinit();
    var allocator = std.heap.page_allocator;

    tls.setSupportedALPN(&[_][]const u8{"h3"});
    var server = try Server.init(allocator, "/Users/endel/Projects/netcode.io/quic-zig/self-signed/cert.crt");

    // .{
    //     .alpn_protocols = h3.ALPN ++ h0.ALPN ++ [_][]const u8{"siduck"},
    //     // .is_client = false,
    //     .max_datagram_frame_size = 65536,
    // }
    //

    // try server.config.readCertChain(alloc, .{
    //     .certfile = "self-signed/aioquic/ssl_cert.pem",
    //     .keyfile = "self-signed/aioquic/ssl_key.pem",
    //     // .certfile = @embedFile("../self-signed/aioquic/ssl_cert.pem"),
    //     // .keyfile = @embedFile("../self-signed/aioquic/ssl_key.pem"),
    // });

    // var rnd: [hmac.sha2.HmacSha256.mac_length]u8 = undefined;
    // std.crypto.random.bytes(&rnd);
    //
    // var connection_id_seed: [hmac.sha2.HmacSha256.mac_length]u8 = undefined;
    // hmac.sha2.HmacSha256.create(connection_id_seed[0..], "", "");

    const local_addr = try std.net.Address.parseIp4("127.0.0.1", 4433);
    // const local_addr = try std.net.Address.parseIp6("::1", 4433);

    const sockfd = try server.listen(local_addr);
    defer os.close(sockfd);

    var connections = std.StringHashMap(connection.Connection).init(allocator);
    defer connections.clearAndFree();

    // out/write buffer
    var out: [MAX_DATAGRAM_SIZE]u8 = undefined;
    var out_buff = io.fixedBufferStream(&out);
    var out_writer = out_buff.writer();

    var prevTimestamp = std.time.timestamp();

    while (true) {
        os.nanosleep(0, 100 * 1000 * 1000);

        udp_read: while (true) {
            // reset write position
            try out_buff.seekTo(0);

            var bytes: [8192]u8 = undefined;

            var remote_addr: os.sockaddr = undefined;
            var addr_size: std.os.socklen_t = @sizeOf(os.sockaddr);

            const packet_length = os.recvfrom(sockfd, &bytes, 0, &remote_addr, &addr_size) catch {
                std.log.info("No more packets to read. Break read loop!", .{});
                break :udp_read;
            };

            std.log.info("\n<<-\nRECEIVED PACKET ({}ms) from {} (addr size: {})", .{ (std.time.timestamp() - prevTimestamp), remote_addr, addr_size });
            prevTimestamp = std.time.timestamp();
            std.log.info("FULL PACKET: (len: {}) {any}", .{ packet_length, bytes[0..packet_length] });

            // var fbs = io.fixedBufferStream(bytes[0..packet_length]);
            // const reader = fbs.reader();
            var fbs = io.fixedBufferStream(bytes[0..packet_length]);
            var header = try packet.Header.parse(&fbs);
            std.log.info("FBS POS => {any}", .{fbs.pos});

            // make sure payload is not higher than received packet  length
            std.log.info("remainder_len: {any} / {any} (packet_length)", .{ header.remainder_len, packet_length });
            if (header.remainder_len > packet_length) {
                std.log.warn("remaining length is higher than packet length!", .{});
                continue :udp_read;
            }

            std.log.info("packet type: {any}", .{header.packet_type});
            if (header.packet_type != packet.PacketType.initial) {
                std.log.err("Packet is not initial!", .{});
                continue :udp_read;
            }

            //
            // TODO: Version negotiation
            //

            if (!protocol.isSupportedVersion(header.version)) {
                std.log.warn("client wants to use unsupported version {}, let's negotiate version...", .{header.version});
                try packet.negotiateVersion(header, &out_writer);

                var bytes_to_send = out_buff.getWritten();
                const bytes_sent = try os.sendto(sockfd, bytes_to_send, 0, &remote_addr, addr_size);
                std.log.info("\n->>\nSENT VERSION NEGOTIATION PACKET (sent: {} bytes) => {any}", .{ bytes_sent, bytes_to_send });

                continue :udp_read;
            }

            if (header.token == null or header.token.?.len == 0) {
                // TODO: Do stateless retry if the client didn't send a token.
                std.log.warn("(->) PREPPING RETRY PACKET", .{});

                // generates a random original destination connection id
                var new_scid = connection.generateConnectionId(header.scid.len);
                var retry_token = try packet.generateRetryToken(header, new_scid, remote_addr);

                std.log.info("new scid: {any}", .{new_scid});
                std.log.warn("retry token: {any}", .{retry_token});

                try packet.retry(header, new_scid, retry_token, &out_writer);

                var bytes_to_send = out_buff.getWritten();

                const bytes_sent = try os.sendto(sockfd, bytes_to_send, 0, &remote_addr, addr_size);
                std.log.info("\n->>\nRETRY PACKET (sent: {} bytes)\n{any}", .{ bytes_sent, bytes_to_send });

                continue :udp_read;
            }

            std.log.info("retry token length: {}", .{header.token.?.len});

            const conn_pair = try connections.getOrPut(header.scid);
            if (!conn_pair.found_existing) {
                if (header.scid.len != header.dcid.len) {
                    std.log.err("Invalid destination connection ID", .{});
                }

                std.log.info("ACCEPT CONNECTION!", .{});
                var conn = try connection.Connection.accept(allocator, header, local_addr.any, remote_addr, true);
                defer conn.deinit();

                conn_pair.value_ptr.* = conn;

                //
            } else {
                std.log.warn("HAS CONNECTION!", .{});
            }

            var recv_info: connection.RecvInfo = .{
                .to = local_addr.any,
                .from = remote_addr,
            };

            // receive packet + process frames
            var conn = conn_pair.value_ptr.*;
            conn.recv(&header, &fbs, recv_info) catch |e| {
                std.log.err("RECV ERROR -> {any}", .{e});
                continue :udp_read;
            };
        }

        var conn_it = connections.iterator();
        while (conn_it.next()) |kv| {
            var scid = kv.key_ptr.*;
            var conn = kv.value_ptr.*;
            std.log.info("looping through connections... key: {any} => {any}", .{ scid, conn });
        }

        // TODO: garbage collect closed connections ...
    }
}

test {
    _ = @import("quic/server.zig");
    _ = @import("quic/connection.zig");
    _ = @import("quic/packet.zig");
    _ = @import("quic/protocol.zig");
    _ = @import("quic/frame.zig");
}
