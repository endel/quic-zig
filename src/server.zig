const std = @import("std");
const posix = std.posix;
const io = std.io;

const connection = @import("quic/connection.zig");
const packet = @import("quic/packet.zig");
const protocol = @import("quic/protocol.zig");
const tls13 = @import("quic/tls13.zig");
const h3 = @import("h3/connection.zig");
const qpack = @import("h3/qpack.zig");

const MAX_DATAGRAM_SIZE: usize = 1500;

pub fn main() !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    // Read cert files at runtime
    const server_cert_pem = try std.fs.cwd().readFileAlloc(alloc, "interop/certs/server.crt", 8192);
    const server_key_pem = try std.fs.cwd().readFileAlloc(alloc, "interop/certs/server.key", 8192);

    // Parse PEM → DER
    var cert_der_buf: [4096]u8 = undefined;
    const cert_der = try tls13.parsePemCert(server_cert_pem, &cert_der_buf);

    var key_der_buf: [4096]u8 = undefined;
    const key_der = try tls13.parsePemPrivateKey(server_key_pem, &key_der_buf);
    const ec_private_key = try tls13.extractEcPrivateKey(key_der);

    // Build TLS config
    const cert_chain = try alloc.alloc([]const u8, 1);
    cert_chain[0] = cert_der;

    const alpn = try alloc.alloc([]const u8, 1);
    alpn[0] = "h3";

    const tls_config: tls13.TlsConfig = .{
        .cert_chain_der = cert_chain,
        .private_key_bytes = ec_private_key,
        .alpn = alpn,
    };

    // Create UDP socket
    const local_addr = try std.net.Address.parseIp4("127.0.0.1", 4434);
    const sockfd = try posix.socket(posix.AF.INET, posix.SOCK.DGRAM | posix.SOCK.NONBLOCK, 0);
    defer posix.close(sockfd);
    try posix.bind(sockfd, &local_addr.any, local_addr.getOsSockLen());
    std.log.info("QUIC H3 server listening on 127.0.0.1:4434 (sockfd={d})", .{sockfd});

    // Try recvfrom immediately to verify socket is open
    var test_addr: posix.sockaddr = undefined;
    var test_addr_size: posix.socklen_t = @sizeOf(posix.sockaddr);
    var test_buf: [100]u8 = undefined;
    _ = posix.recvfrom(sockfd, &test_buf, 0, &test_addr, &test_addr_size) catch |err| {
        std.log.debug("First recvfrom (expected WouldBlock): {any}", .{err});
    };

    var conn_state: ?connection.Connection = null;
    var h3_conn: ?h3.H3Connection = null;
    var h3_initialized = false;
    var remote_addr: posix.sockaddr = undefined;
    var addr_size: posix.socklen_t = @sizeOf(posix.sockaddr);
    var out: [MAX_DATAGRAM_SIZE]u8 = undefined;

    var loop_count: usize = 0;
    while (true) {
        std.Thread.sleep(1 * std.time.ns_per_ms);
        loop_count += 1;
        if (loop_count % 1000 == 0) {
            std.log.debug("server loop iteration {d}", .{loop_count});
        }

        // Read loop: process all available UDP packets
        read_loop: while (true) {
            var bytes: [8192]u8 = undefined;
            addr_size = @sizeOf(posix.sockaddr);

            const packet_length = posix.recvfrom(sockfd, &bytes, 0, &remote_addr, &addr_size) catch |err| {
                // WouldBlock is expected on non-blocking socket when no data available
                if (err == error.WouldBlock) {
                    break :read_loop;
                }
                // Other errors are unexpected
                std.log.err("recvfrom error: {any}", .{err});
                break :read_loop;
            };

            var fbs = io.fixedBufferStream(bytes[0..packet_length]);

            // Process all coalesced packets in the UDP datagram
            while (fbs.pos < packet_length) {
                // All valid QUIC packets have the fixed bit (0x40) set in the first byte.
                // If not set, remaining bytes are datagram padding — stop parsing.
                if (bytes[fbs.pos] & 0x40 == 0) break;

                const packet_start_pos = fbs.pos;
                var header = packet.Header.parse(&fbs, if (conn_state) |*cs| cs.scid_len else 8) catch |err| {
                    std.log.err("header parse error: {any}", .{err});
                    break;
                };

                const header_end_pos = fbs.pos;
                const encrypted_payload_size = header.remainder_len;
                const full_packet_size = header_end_pos - packet_start_pos + encrypted_payload_size;

                std.log.info("recv {any} packet at offset {d}, full_size={d}", .{ header.packet_type, packet_start_pos, full_packet_size });

                // Version negotiation
                if (header.version != 0 and !protocol.isSupportedVersion(header.version)) {
                    var vn_buf: [MAX_DATAGRAM_SIZE]u8 = undefined;
                    var vn_fbs = io.fixedBufferStream(&vn_buf);
                    const vn_writer = vn_fbs.writer();
                    try packet.negotiateVersion(header, &vn_writer);
                    const vn_bytes = vn_fbs.getWritten();
                    _ = try posix.sendto(sockfd, vn_bytes, 0, &remote_addr, addr_size);
                    std.log.info("sent version negotiation", .{});
                    break;
                }

                // Accept connection on first Initial (skip retry)
                if (conn_state == null) {
                    if (header.packet_type != .initial) {
                        std.log.warn("ignoring non-initial before connection established", .{});
                        break;
                    }
                    conn_state = try connection.Connection.accept(
                        alloc,
                        header,
                        local_addr.any,
                        remote_addr,
                        true,
                        .{},
                        tls_config,
                    );
                    std.log.info("accepted new connection", .{});
                }

                var conn = &conn_state.?;
                const recv_info: connection.RecvInfo = .{
                    .to = local_addr.any,
                    .from = remote_addr,
                };

                conn.recv(&header, &fbs, recv_info) catch |err| {
                    std.log.err("recv error: {any}", .{err});
                    break;
                };

                // Ensure fbs is positioned at the start of the next packet
                const expected_next_pos = packet_start_pos + full_packet_size;
                if (fbs.pos < expected_next_pos) {
                    fbs.pos = expected_next_pos;
                }

                // Send response packets after processing each coalesced packet
                const bytes_written = conn.send(&out) catch |err| {
                    std.log.err("send error: {any}", .{err});
                    break;
                };
                if (bytes_written > 0) {
                    const send_addr = &conn.paths[conn.active_path_idx].peer_addr;
                    _ = try posix.sendto(sockfd, out[0..bytes_written], 0, send_addr, @sizeOf(posix.sockaddr));
                    std.log.info("sent {d} bytes", .{bytes_written});
                }
            }
        }

        // HTTP/3 processing
        if (conn_state != null) {
            var conn = &conn_state.?;

            if (conn.isEstablished() and !h3_initialized) {
                h3_conn = h3.H3Connection.init(alloc, conn, true);
                h3_conn.?.initConnection() catch |err| {
                    std.log.err("H3 init error: {any}", .{err});
                    continue;
                };
                h3_initialized = true;
                std.log.info("HTTP/3 connection initialized", .{});
            }

            if (h3_conn != null) {
                var h3c = &h3_conn.?;

                // Poll for H3 events
                while (true) {
                    const event = h3c.poll() catch |err| {
                        std.log.err("H3 poll error: {any}", .{err});
                        break;
                    };

                    if (event == null) break;

                    switch (event.?) {
                        .settings => |settings| {
                            std.log.info("H3: received peer SETTINGS (qpack_max_table_capacity={d})", .{settings.qpack_max_table_capacity});
                        },
                        .headers => |hdr| {
                            std.log.info("H3: received request headers on stream {d}", .{hdr.stream_id});
                            var method: []const u8 = "?";
                            var path: []const u8 = "?";
                            for (hdr.headers) |h_item| {
                                std.log.info("  {s}: {s}", .{ h_item.name, h_item.value });
                                if (std.mem.eql(u8, h_item.name, ":method")) method = h_item.value;
                                if (std.mem.eql(u8, h_item.name, ":path")) path = h_item.value;
                            }

                            // Send HTTP response
                            const body = std.fmt.allocPrint(alloc, "Hello from Zig HTTP/3 server! You requested {s} {s}\n", .{ method, path }) catch continue;
                            const resp_headers = [_]qpack.Header{
                                .{ .name = ":status", .value = "200" },
                                .{ .name = "content-type", .value = "text/plain" },
                            };
                            h3c.sendResponse(hdr.stream_id, &resp_headers, body) catch |err| {
                                std.log.err("H3 sendResponse error: {any}", .{err});
                                continue;
                            };
                            std.log.info("H3: sent 200 response on stream {d} ({d} bytes body)", .{ hdr.stream_id, body.len });
                        },
                        .data => |d| {
                            std.log.info("H3: received {d} bytes of data on stream {d}", .{ d.data.len, d.stream_id });
                        },
                        .finished => |stream_id| {
                            std.log.info("H3: stream {d} finished", .{stream_id});
                        },
                        .goaway => |id| {
                            std.log.info("H3: received GOAWAY (id={d})", .{id});
                        },
                    }
                }
            }

            // Periodic send for retransmissions/ACKs/stream data
            const bytes_written = conn.send(&out) catch |err| {
                std.log.err("periodic send error: {any}", .{err});
                continue;
            };
            if (bytes_written > 0) {
                const send_addr = &conn.paths[conn.active_path_idx].peer_addr;
                _ = try posix.sendto(sockfd, out[0..bytes_written], 0, send_addr, @sizeOf(posix.sockaddr));
                std.log.info("periodic sent {d} bytes", .{bytes_written});
            }
        }
    }
}

test {
    _ = @import("quic/connection.zig");
    _ = @import("quic/packet.zig");
    _ = @import("quic/protocol.zig");
    _ = @import("quic/frame.zig");
    _ = @import("quic/ranges.zig");
    _ = @import("quic/rtt.zig");
    _ = @import("quic/ack_handler.zig");
    _ = @import("quic/congestion.zig");
    _ = @import("quic/flow_control.zig");
    _ = @import("quic/transport_params.zig");
    _ = @import("quic/stream.zig");
    _ = @import("quic/crypto_stream.zig");
    _ = @import("quic/packet_packer.zig");
    _ = @import("quic/tls13.zig");
    _ = @import("quic/mtu.zig");
    _ = @import("h3/frame.zig");
    _ = @import("h3/qpack.zig");
    _ = @import("h3/connection.zig");
}
