const std = @import("std");
const posix = std.posix;
const io = std.io;
const net = std.net;

const connection = @import("quic/connection.zig");
const packet = @import("quic/packet.zig");
const protocol = @import("quic/protocol.zig");
const tls13 = @import("quic/tls13.zig");
const stateless_reset = @import("quic/stateless_reset.zig");
const ecn_socket = @import("quic/ecn_socket.zig");
const h3 = @import("h3/connection.zig");
const qpack = @import("h3/qpack.zig");
const Certificate = std.crypto.Certificate;

const MAX_DATAGRAM_SIZE: usize = 1500;

pub fn main() !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const server_addr = try net.Address.parseIp4("127.0.0.1", 4434);
    const sockfd = try posix.socket(posix.AF.INET, posix.SOCK.DGRAM | posix.SOCK.NONBLOCK, 0);
    defer posix.close(sockfd);

    // Create a local socket with any available port
    const local_addr = try net.Address.parseIp4("127.0.0.1", 0);
    try posix.bind(sockfd, &local_addr.any, local_addr.getOsSockLen());
    ecn_socket.enableEcnRecv(sockfd) catch {};
    std.log.info("QUIC H3 client connecting to 127.0.0.1:4434", .{});

    // Create TLS config for the client
    const alpn = try alloc.alloc([]const u8, 1);
    alpn[0] = "h3";

    // Load CA bundle for certificate verification
    var ca_bundle: Certificate.Bundle = .{};
    defer ca_bundle.deinit(alloc);
    try ca_bundle.addCertsFromFilePath(alloc, std.fs.cwd(), "interop/certs/ca.crt");

    const tls_config: tls13.TlsConfig = .{
        .cert_chain_der = &.{},
        .private_key_bytes = &.{},
        .alpn = alpn,
        .server_name = "localhost",
        .skip_cert_verify = false,
        .ca_bundle = &ca_bundle,
    };

    // Create client connection with TLS config
    var conn = try connection.connect(
        alloc,
        "localhost",
        .{},
        tls_config,
        null, // no NEW_TOKEN from previous connection
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
                ecn_socket.setEcnMark(sockfd, conn.getEcnMark()) catch {};
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

            const recv_result = ecn_socket.recvmsgEcn(sockfd, &bytes) catch {
                break :read_loop;
            };
            const packet_length = recv_result.bytes_read;
            remote_addr = recv_result.from_addr;
            addr_size = recv_result.addr_len;

            var fbs = io.fixedBufferStream(bytes[0..packet_length]);

            // Process all coalesced packets in the UDP datagram
            while (fbs.pos < packet_length) {
                if (bytes[fbs.pos] & 0x40 == 0) break;

                const packet_start_pos = fbs.pos;
                var header = packet.Header.parse(&fbs, conn.scid_len) catch |err| {
                    std.log.err("header parse error: {any}", .{err});
                    break;
                };

                const header_end_pos = fbs.pos;
                const encrypted_payload_size = header.remainder_len;
                const full_packet_size = header_end_pos - packet_start_pos + encrypted_payload_size;

                conn.recv(&header, &fbs, .{
                    .to = local_addr.any,
                    .from = remote_addr,
                    .ecn = recv_result.ecn,
                }) catch |err| {
                    std.log.err("recv error: {any}", .{err});
                    break;
                };

                const expected_next_pos = packet_start_pos + full_packet_size;
                if (fbs.pos < expected_next_pos) {
                    fbs.pos = expected_next_pos;
                }
            }

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

    // Send any pending handshake packets (Finished, ACKs)
    const hs_bytes = conn.send(&out) catch |err| {
        std.log.err("send error (handshake): {any}", .{err});
        return;
    };
    if (hs_bytes > 0) {
        ecn_socket.setEcnMark(sockfd, conn.getEcnMark()) catch {};
        _ = try posix.sendto(sockfd, out[0..hs_bytes], 0, &remote_addr, addr_size);
        std.log.info("sent {d} bytes (handshake completion)", .{hs_bytes});
    }

    // Sync remote_addr from active path (may have changed due to preferred address migration)
    remote_addr = conn.paths[conn.active_path_idx].peer_addr;

    // Clear Initial keys — Handshake keys kept until HANDSHAKE_DONE (RFC 9001 §4.9.2)
    conn.pkt_num_spaces[0].crypto_open = null;
    conn.pkt_num_spaces[0].crypto_seal = null;

    // Small delay for the server to process the Finished
    std.Thread.sleep(50 * std.time.ns_per_ms);

    // Initialize HTTP/3 connection
    var h3_conn = h3.H3Connection.init(alloc, &conn, false);
    defer h3_conn.deinit();
    try h3_conn.initConnection();
    std.log.info("HTTP/3 connection initialized", .{});

    // Send HTTP/3 GET request
    const req_headers = [_]qpack.Header{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "localhost" },
        .{ .name = ":path", .value = "/" },
        .{ .name = "user-agent", .value = "quic-zig/1.0" },
    };
    const req_stream_id = try h3_conn.sendRequest(&req_headers, null);
    std.log.info("H3: sent GET / request on stream {d}", .{req_stream_id});

    // Send the H3 control streams + request data
    const data_bytes = conn.send(&out) catch |err| {
        std.log.err("send error: {any}", .{err});
        return;
    };
    if (data_bytes > 0) {
        ecn_socket.setEcnMark(sockfd, conn.getEcnMark()) catch {};
        _ = try posix.sendto(sockfd, out[0..data_bytes], 0, &remote_addr, addr_size);
        std.log.info("sent {d} bytes with H3 data", .{data_bytes});
    }

    // Keep sending until all stream data is flushed
    var flush_count: usize = 0;
    while (flush_count < 10) : (flush_count += 1) {
        const more = conn.send(&out) catch break;
        if (more == 0) break;
        ecn_socket.setEcnMark(sockfd, conn.getEcnMark()) catch {};
        _ = posix.sendto(sockfd, out[0..more], 0, &remote_addr, addr_size) catch break;
        std.log.info("sent {d} more bytes (flush #{d})", .{ more, flush_count + 1 });
    }

    // Read response
    var got_response = false;
    var response_iteration: usize = 0;
    const max_response_iterations: usize = 500;

    while (!got_response and response_iteration < max_response_iterations) : (response_iteration += 1) {
        std.Thread.sleep(10 * std.time.ns_per_ms);

        // Read QUIC packets
        while (true) {
            var bytes: [8192]u8 = undefined;

            const recv_result = ecn_socket.recvmsgEcn(sockfd, &bytes) catch break;
            const packet_length = recv_result.bytes_read;
            remote_addr = recv_result.from_addr;
            addr_size = recv_result.addr_len;

            var fbs = io.fixedBufferStream(bytes[0..packet_length]);

            while (fbs.pos < packet_length) {
                if (bytes[fbs.pos] & 0x40 == 0) break;

                const packet_start_pos = fbs.pos;
                var header = packet.Header.parse(&fbs, conn.scid_len) catch break;

                const header_end_pos = fbs.pos;
                const full_packet_size = header_end_pos - packet_start_pos + header.remainder_len;

                conn.recv(&header, &fbs, .{
                    .to = local_addr.any,
                    .from = remote_addr,
                    .ecn = recv_result.ecn,
                }) catch {
                    // Check if this is a stateless reset (RFC 9000 §10.3)
                    if (conn.matchesStatelessReset(bytes[0..packet_length])) {
                        std.log.info("received stateless reset, closing connection", .{});
                        conn.state = .draining;
                        got_response = true;
                        break;
                    }
                    break;
                };

                const expected_next_pos = packet_start_pos + full_packet_size;
                if (fbs.pos < expected_next_pos) {
                    fbs.pos = expected_next_pos;
                }
            }

            if (conn.state == .draining) break;
        }

        // Send ACKs
        const ack_bytes = conn.send(&out) catch continue;
        if (ack_bytes > 0) {
            ecn_socket.setEcnMark(sockfd, conn.getEcnMark()) catch {};
            _ = posix.sendto(sockfd, out[0..ack_bytes], 0, &remote_addr, addr_size) catch {};
        }

        // Poll for H3 events
        while (true) {
            const event = h3_conn.poll() catch break;
            if (event == null) break;

            switch (event.?) {
                .settings => |settings| {
                    std.log.info("H3: received peer SETTINGS (qpack_max_table_capacity={d})", .{settings.qpack_max_table_capacity});
                },
                .headers => |hdr| {
                    std.log.info("H3: received response headers on stream {d}", .{hdr.stream_id});
                    for (hdr.headers) |h_item| {
                        std.log.info("  {s}: {s}", .{ h_item.name, h_item.value });
                    }
                },
                .data => |d| {
                    std.log.info("H3: received response body ({d} bytes)", .{d.data.len});
                    std.debug.print("Response: {s}\n", .{d.data});
                    got_response = true;
                },
                .finished => |stream_id| {
                    std.log.info("H3: stream {d} finished", .{stream_id});
                    got_response = true;
                },
                .goaway => |id| {
                    std.log.info("H3: received GOAWAY (id={d})", .{id});
                },
                .connect_request => {},
            }
        }
    }

    if (!got_response) {
        std.log.warn("no H3 response received", .{});
    }

    // Check for session ticket (for 0-RTT resumption on next connection)
    if (conn.session_ticket) |ticket| {
        std.log.info("received session ticket (len={d}, lifetime={d}s) - can use for 0-RTT resumption", .{ ticket.ticket_len, ticket.lifetime });
    }

    // Close connection
    conn.close(0, "done");
    const final_bytes = conn.send(&out) catch 0;
    if (final_bytes > 0) {
        _ = try posix.sendto(sockfd, out[0..final_bytes], 0, &remote_addr, addr_size);
    }

    // Wait for draining period to complete
    var drain_iter: usize = 0;
    while (!conn.isClosed() and drain_iter < 100) : (drain_iter += 1) {
        std.Thread.sleep(10 * std.time.ns_per_ms);
        conn.onTimeout() catch break;

        // Read and discard any incoming packets (triggers close retransmit)
        while (true) {
            var bytes: [8192]u8 = undefined;
            const drain_recv = ecn_socket.recvmsgEcn(sockfd, &bytes) catch break;
            remote_addr = drain_recv.from_addr;
            addr_size = drain_recv.addr_len;

            var fbs = io.fixedBufferStream(bytes[0..drain_recv.bytes_read]);
            while (fbs.pos < drain_recv.bytes_read) {
                if (bytes[fbs.pos] & 0x40 == 0) break;
                const pkt_start = fbs.pos;
                var header = packet.Header.parse(&fbs, conn.scid_len) catch break;
                const full_size = fbs.pos - pkt_start + header.remainder_len;
                conn.recv(&header, &fbs, .{ .to = local_addr.any, .from = remote_addr, .ecn = drain_recv.ecn }) catch break;
                const next_pos = pkt_start + full_size;
                if (fbs.pos < next_pos) fbs.pos = next_pos;
            }
        }

        // Send retransmit if triggered
        const retransmit_bytes = conn.send(&out) catch 0;
        if (retransmit_bytes > 0) {
            _ = posix.sendto(sockfd, out[0..retransmit_bytes], 0, &remote_addr, addr_size) catch {};
        }
    }
    std.log.info("connection closed cleanly", .{});
}
