const std = @import("std");
const posix = std.posix;

const connection = @import("quic/connection.zig");
const connection_manager = @import("quic/connection_manager.zig");
const tls13 = @import("quic/tls13.zig");
const ecn_socket = @import("quic/ecn_socket.zig");
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

    // Generate random ticket key for session ticket encryption (0-RTT support)
    var ticket_key: [16]u8 = undefined;
    std.crypto.random.bytes(&ticket_key);

    // Generate random key for Retry token encryption
    var retry_token_key: [16]u8 = undefined;
    std.crypto.random.bytes(&retry_token_key);

    // Generate static key for stateless reset tokens (RFC 9000 §10.3)
    var static_reset_key: [16]u8 = undefined;
    std.crypto.random.bytes(&static_reset_key);

    const tls_config: tls13.TlsConfig = .{
        .cert_chain_der = cert_chain,
        .private_key_bytes = ec_private_key,
        .alpn = alpn,
        .ticket_key = ticket_key,
    };

    // Create UDP socket
    const local_addr = try std.net.Address.parseIp4("127.0.0.1", 4434);
    const sockfd = try posix.socket(posix.AF.INET, posix.SOCK.DGRAM | posix.SOCK.NONBLOCK, 0);
    defer posix.close(sockfd);
    try posix.bind(sockfd, &local_addr.any, local_addr.getOsSockLen());
    ecn_socket.enableEcnRecv(sockfd) catch {};
    std.log.info("QUIC H3 server listening on 127.0.0.1:4434 (sockfd={d})", .{sockfd});

    // Try recvfrom immediately to verify socket is open
    var test_addr: posix.sockaddr = undefined;
    var test_addr_size: posix.socklen_t = @sizeOf(posix.sockaddr);
    var test_buf: [100]u8 = undefined;
    _ = posix.recvfrom(sockfd, &test_buf, 0, &test_addr, &test_addr_size) catch |err| {
        std.log.debug("First recvfrom (expected WouldBlock): {any}", .{err});
    };

    var conn_mgr = connection_manager.ConnectionManager.init(
        alloc,
        tls_config,
        .{ .token_key = retry_token_key },
        retry_token_key,
        static_reset_key,
    );
    conn_mgr.require_retry = true;
    defer conn_mgr.deinit();

    var remote_addr: posix.sockaddr.storage = std.mem.zeroes(posix.sockaddr.storage);
    var addr_size: posix.socklen_t = @sizeOf(posix.sockaddr);
    var out: [MAX_DATAGRAM_SIZE]u8 = undefined;

    var loop_count: usize = 0;
    while (true) {
        std.Thread.sleep(1 * std.time.ns_per_ms);
        loop_count += 1;
        if (loop_count % 1000 == 0) {
            std.log.debug("server loop iteration {d} ({d} connections)", .{ loop_count, conn_mgr.connectionCount() });
        }

        // Read loop: process all available UDP packets
        read_loop: while (true) {
            var bytes: [8192]u8 = undefined;
            addr_size = @sizeOf(posix.sockaddr);

            const recv_result = ecn_socket.recvmsgEcn(sockfd, &bytes) catch |err| {
                if (err == error.WouldBlock) {
                    break :read_loop;
                }
                std.log.err("recvmsg error: {any}", .{err});
                break :read_loop;
            };
            remote_addr = recv_result.from_addr;
            addr_size = recv_result.addr_len;

            switch (conn_mgr.recvDatagram(bytes[0..recv_result.bytes_read], remote_addr, connection.sockaddrToStorage(&local_addr.any), recv_result.ecn, &out)) {
                .processed => |entry| {
                    const conn = entry.conn;
                    const bytes_written = conn.send(&out) catch continue;
                    if (bytes_written > 0) {
                        ecn_socket.setEcnMark(sockfd, conn.getEcnMark()) catch {};
                        const send_addr = conn.peerAddress();
                        _ = posix.sendto(sockfd, out[0..bytes_written], 0, @ptrCast(send_addr), connection.sockaddrLen(send_addr)) catch {};
                    }
                },
                .send_response => |data| {
                    _ = posix.sendto(sockfd, data, 0, @ptrCast(&remote_addr), addr_size) catch {};
                },
                .dropped => {},
            }
        }

        // Per-connection processing: H3, timeouts, periodic sends
        var i: usize = 0;
        while (i < conn_mgr.entries.items.len) {
            const entry = conn_mgr.entries.items[i];
            const conn = entry.conn;

            // Initialize H3 once handshake completes
            if (conn.isEstablished() and !entry.h3_initialized) {
                entry.h3_conn = h3.H3Connection.init(alloc, conn, true);
                entry.h3_conn.?.initConnection() catch |err| {
                    std.log.err("H3 init error: {any}", .{err});
                    i += 1;
                    continue;
                };
                entry.h3_initialized = true;
                std.log.info("HTTP/3 connection initialized (total: {d})", .{conn_mgr.connectionCount()});
            }

            // Poll for H3 events
            if (entry.h3_conn != null) {
                var h3c = &entry.h3_conn.?;
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

                            const body = std.fmt.allocPrint(alloc, "Hello from Zig HTTP/3 server! You requested {s} {s}\n", .{ method, path }) catch {
                                i += 1;
                                continue;
                            };
                            const resp_headers = [_]qpack.Header{
                                .{ .name = ":status", .value = "200" },
                                .{ .name = "content-type", .value = "text/plain" },
                            };
                            h3c.sendResponse(hdr.stream_id, &resp_headers, body) catch |err| {
                                std.log.err("H3 sendResponse error: {any}", .{err});
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
                        .connect_request => |req| {
                            std.log.info("H3: received CONNECT request on stream {d} (protocol={s})", .{ req.stream_id, req.protocol });
                        },
                        .shutdown_complete => {},
                        .request_cancelled => {},
                    }
                }
            }

            // Timeouts + close check
            if (!conn_mgr.tickEntry(entry)) continue;

            // Burst send — drain queued data
            var send_count: usize = 0;
            while (send_count < 100) : (send_count += 1) {
                const bytes_written = conn.send(&out) catch break;
                if (bytes_written == 0) break;
                ecn_socket.setEcnMark(sockfd, conn.getEcnMark()) catch {};
                const send_addr = conn.peerAddress();
                _ = posix.sendto(sockfd, out[0..bytes_written], 0, @ptrCast(send_addr), connection.sockaddrLen(send_addr)) catch {};
            }

            i += 1;
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
    _ = @import("quic/stateless_reset.zig");
    _ = @import("quic/connection_manager.zig");
    _ = @import("quic/ecn.zig");
    _ = @import("quic/ecn_socket.zig");
    _ = @import("h3/frame.zig");
    _ = @import("h3/qpack.zig");
    _ = @import("h3/huffman.zig");
    _ = @import("h3/connection.zig");
    _ = @import("webtransport/session.zig");
}
