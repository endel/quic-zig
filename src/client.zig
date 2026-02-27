const std = @import("std");
const posix = std.posix;
const io = std.io;
const net = std.net;

const connection = @import("quic/connection.zig");
const packet = @import("quic/packet.zig");
const protocol = @import("quic/protocol.zig");
const tls13 = @import("quic/tls13.zig");
const stream_mod = @import("quic/stream.zig");

const MAX_DATAGRAM_SIZE: usize = 1350;

pub fn main() !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    // Connect to quic-go v0.59.0 server at localhost:4434
    const server_addr = try net.Address.parseIp4("127.0.0.1", 4434);
    // const server_addr = try net.Address.parseIp4("127.0.0.1", 4433);
    const sockfd = try posix.socket(posix.AF.INET, posix.SOCK.DGRAM | posix.SOCK.NONBLOCK, 0);
    defer posix.close(sockfd);

    // Create a local socket with any available port
    const local_addr = try net.Address.parseIp4("127.0.0.1", 0);
    try posix.bind(sockfd, &local_addr.any, local_addr.getOsSockLen());
    std.log.info("QUIC client connecting to localhost:4434 (quic-go v0.59.0) - sockfd={d}", .{sockfd});

    // Create TLS config for the client
    // (Clients don't need certificates - empty arrays are fine)
    const alpn = try alloc.alloc([]const u8, 1);
    alpn[0] = "h3";

    const tls_config: tls13.TlsConfig = .{
        .cert_chain_der = &.{},
        .private_key_bytes = &.{},
        .alpn = alpn,
    };

    // Create client connection with TLS config
    var conn = try connection.connect(
        alloc,
        "localhost",
        .{},
        tls_config,
    );

    var remote_addr = server_addr.any;
    var addr_size: posix.socklen_t = server_addr.getOsSockLen();
    var out: [MAX_DATAGRAM_SIZE]u8 = undefined;

    // Send initial packets and wait for handshake to complete
    var handshake_complete = false;
    var send_count: usize = 0;
    const max_iterations: usize = 1000;
    var iteration: usize = 0;

    while (!handshake_complete and iteration < max_iterations) : (iteration += 1) {
        std.Thread.sleep(1 * std.time.ns_per_ms);

        // Send any pending packets
        if (!handshake_complete) {
            const bytes_written = conn.send(&out) catch |err| {
                std.log.err("send error: {any}", .{err});
                break;
            };
            if (bytes_written > 0) {
                send_count += 1;
                const sent = posix.sendto(sockfd, out[0..bytes_written], 0, &remote_addr, addr_size) catch |err| {
                    std.log.err("sendto failed: {any}", .{err});
                    continue;
                };
                std.log.info("sent {d} bytes (packet #{d}), sendto returned {d}", .{ bytes_written, send_count, sent });
            }
        }

        // Try to read response packets
        read_loop: while (true) {
            var bytes: [8192]u8 = undefined;
            addr_size = @sizeOf(posix.sockaddr);

            const packet_length = posix.recvfrom(sockfd, &bytes, 0, &remote_addr, &addr_size) catch {
                break :read_loop;
            };

            var fbs = io.fixedBufferStream(bytes[0..packet_length]);

            // Process all coalesced packets in the UDP datagram
            while (fbs.pos < packet_length) {
                const packet_start_pos = fbs.pos;
                var header = packet.Header.parse(&fbs) catch |err| {
                    std.log.err("header parse error: {any}", .{err});
                    break;
                };

                const header_end_pos = fbs.pos;
                const encrypted_payload_size = header.remainder_len;
                const full_packet_size = header_end_pos - packet_start_pos + encrypted_payload_size;

                std.log.info("recv {any} packet at offset {d}, header_size={d}, encrypted_size={d}, full_size={d}", .{ header.packet_type, packet_start_pos, header_end_pos - packet_start_pos, encrypted_payload_size, full_packet_size });

                // Save first response packet for debugging
                if (header.packet_type == .initial and fbs.pos == 0) {
                    std.debug.print("\n=== RECEIVED INITIAL PACKET BYTES ===\n", .{});
                    for (bytes[0..@min(116, packet_length)], 0..) |byte, i| {
                        if (i % 16 == 0) std.debug.print("\n{x:0>3}: ", .{i});
                        std.debug.print("{x:0>2} ", .{byte});
                    }
                    std.debug.print("\n\n", .{});
                }

                conn.recv(&header, &fbs, .{
                    .to = local_addr.any,
                    .from = remote_addr,
                }) catch |err| {
                    std.log.err("recv error: {any}", .{err});
                    break;
                };

                // Ensure fbs is positioned at the start of the next packet
                const expected_next_pos = packet_start_pos + full_packet_size;
                if (fbs.pos < expected_next_pos) {
                    std.log.info("advancing fbs from {d} to {d}", .{ fbs.pos, expected_next_pos });
                    fbs.pos = expected_next_pos;
                }
            }

            // Check if connection is established
            if (conn.state == .connected) {
                handshake_complete = true;
            }
        }
    }

    if (!handshake_complete) {
        std.log.err("handshake did not complete after {d} iterations", .{iteration});
        return;
    }

    std.log.info("handshake complete, connection active", .{});

    // Now open a stream and send test data
    const test_data = "Hello from Zig QUIC client!";
    var stream = try conn.openStream();
    try stream.send.writeData(test_data);
    stream.send.close();
    std.log.info("sent test data: {s}", .{test_data});

    // Send the packet with the stream data
    const bytes_written = conn.send(&out) catch |err| {
        std.log.err("send error: {any}", .{err});
        return;
    };
    if (bytes_written > 0) {
        _ = try posix.sendto(sockfd, out[0..bytes_written], 0, &remote_addr, addr_size);
        std.log.info("sent {d} bytes with stream data", .{bytes_written});
    }

    // Read response
    var response_data: ?[]const u8 = null;

    read_response: while (response_data == null and iteration < max_iterations) : (iteration += 1) {
        std.Thread.sleep(10 * std.time.ns_per_ms);

        read_loop: while (true) {
            var bytes: [8192]u8 = undefined;
            addr_size = @sizeOf(posix.sockaddr);

            const packet_length = posix.recvfrom(sockfd, &bytes, 0, &remote_addr, &addr_size) catch {
                break :read_loop;
            };

            var fbs = io.fixedBufferStream(bytes[0..packet_length]);
            var header = packet.Header.parse(&fbs) catch {
                continue :read_loop;
            };

            conn.recv(&header, &fbs, .{
                .to = local_addr.any,
                .from = remote_addr,
            }) catch {
                continue :read_loop;
            };
        }

        // Try to read from stream
        response_data = stream.recv.read();
        if (response_data != null) {
            break :read_response;
        }
    }

    if (response_data) |data| {
        std.log.info("received response: {s}", .{data});
        std.debug.print("Response: {s}\n", .{data});
    } else {
        std.log.warn("no response received", .{});
    }

    // Close connection
    conn.close(0, "done");
    const final_bytes = conn.send(&out) catch 0;
    if (final_bytes > 0) {
        _ = try posix.sendto(sockfd, out[0..final_bytes], 0, &remote_addr, addr_size);
    }
}
