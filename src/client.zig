const std = @import("std");
const posix = std.posix;
const net = std.net;

const connection = @import("quic/connection.zig");
const tls13 = @import("quic/tls13.zig");
const ecn_socket = @import("quic/ecn_socket.zig");
const h3 = @import("h3/connection.zig");
const qpack = @import("h3/qpack.zig");
const Certificate = std.crypto.Certificate;

const MAX_DATAGRAM_SIZE: usize = 1500;

fn recvAll(sockfd: posix.socket_t, conn: *connection.Connection, local_addr: *const net.Address, remote_addr: *posix.sockaddr.storage, addr_size: *posix.socklen_t) void {
    while (true) {
        var bytes: [8192]u8 = undefined;
        const recv_result = ecn_socket.recvmsgEcn(sockfd, &bytes) catch break;
        remote_addr.* = recv_result.from_addr;
        addr_size.* = recv_result.addr_len;
        conn.handleDatagram(bytes[0..recv_result.bytes_read], .{
            .to = connection.sockaddrToStorage(&local_addr.any),
            .from = remote_addr.*,
            .ecn = recv_result.ecn,
            .datagram_size = recv_result.bytes_read,
        });
    }
}

fn sendAll(sockfd: posix.socket_t, conn: *connection.Connection, out: []u8, remote_addr: *const posix.sockaddr.storage, addr_size: posix.socklen_t) void {
    var count: usize = 0;
    while (count < 20) : (count += 1) {
        const n = conn.send(out) catch break;
        if (n == 0) break;
        ecn_socket.setEcnMark(sockfd, conn.getEcnMark()) catch {};
        _ = posix.sendto(sockfd, out[0..n], 0, @ptrCast(remote_addr), addr_size) catch break;
    }
}

pub fn main() !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    // Parse --port argument
    var port: u16 = 4434;
    var args = std.process.args();
    _ = args.next(); // skip program name
    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--port")) {
            if (args.next()) |port_str| {
                port = std.fmt.parseInt(u16, port_str, 10) catch 4434;
            }
        }
    }

    const server_addr = try net.Address.parseIp4("127.0.0.1", port);
    const sockfd = try posix.socket(posix.AF.INET, posix.SOCK.DGRAM | posix.SOCK.NONBLOCK, 0);
    defer posix.close(sockfd);

    // Create a local socket with any available port
    const local_addr = try net.Address.parseIp4("127.0.0.1", 0);
    try posix.bind(sockfd, &local_addr.any, local_addr.getOsSockLen());
    ecn_socket.enableEcnRecv(sockfd) catch {};
    std.log.info("QUIC H3 client connecting to 127.0.0.1:{d}", .{port});

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

    var remote_addr = connection.sockaddrToStorage(&server_addr.any);
    var addr_size: posix.socklen_t = connection.sockaddrLen(&remote_addr);
    var out: [MAX_DATAGRAM_SIZE]u8 = undefined;

    // === Handshake ===
    var iteration: usize = 0;
    while (conn.state != .connected and iteration < 1000) : (iteration += 1) {
        conn.onTimeout() catch {};
        sendAll(sockfd, &conn, &out, &remote_addr, addr_size);
        recvAll(sockfd, &conn, &local_addr, &remote_addr, &addr_size);
        if (conn.state == .connected) break;
        std.Thread.sleep(1 * std.time.ns_per_ms);
    }

    if (conn.state != .connected) {
        std.log.err("handshake did not complete after {d} iterations", .{iteration});
        return;
    }
    std.log.info("handshake complete, connection active", .{});

    // Send handshake completion packets (Finished, ACKs) and let server process them
    sendAll(sockfd, &conn, &out, &remote_addr, addr_size);
    std.Thread.sleep(5 * std.time.ns_per_ms);
    recvAll(sockfd, &conn, &local_addr, &remote_addr, &addr_size);
    conn.onTimeout() catch {};
    sendAll(sockfd, &conn, &out, &remote_addr, addr_size);

    // Sync remote_addr from active path (may have changed due to preferred address migration)
    remote_addr = conn.peerAddress().*;

    // === HTTP/3 request ===
    var h3_conn = h3.H3Connection.init(alloc, &conn, false);
    defer h3_conn.deinit();
    try h3_conn.initConnection();

    const req_headers = [_]qpack.Header{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "localhost" },
        .{ .name = ":path", .value = "/" },
        .{ .name = "user-agent", .value = "quic-zig/1.0" },
    };
    const req_stream_id = try h3_conn.sendRequest(&req_headers, null);
    std.log.info("H3: sent GET / request on stream {d}", .{req_stream_id});

    // Flush all pending data (H3 control streams + request)
    sendAll(sockfd, &conn, &out, &remote_addr, addr_size);

    // === Read response ===
    var got_response = false;
    var response_iteration: usize = 0;

    while (!got_response and response_iteration < 200) : (response_iteration += 1) {
        recvAll(sockfd, &conn, &local_addr, &remote_addr, &addr_size);
        conn.onTimeout() catch {};
        sendAll(sockfd, &conn, &out, &remote_addr, addr_size);

        if (conn.state == .draining) break;

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
                    std.log.info("H3: received response body ({d} bytes)", .{d.len});
                    var body_buf: [8192]u8 = undefined;
                    while (true) {
                        const n = h3_conn.recvBody(&body_buf);
                        if (n == 0) break;
                        std.debug.print("Response: {s}\n", .{body_buf[0..n]});
                    }
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
                .shutdown_complete => {},
                .request_cancelled => {},
            }
        }

        if (!got_response) {
            std.Thread.sleep(1 * std.time.ns_per_ms);
        }
    }

    if (!got_response) {
        std.log.warn("no H3 response received", .{});
    }

    // Check for session ticket (for 0-RTT resumption on next connection)
    if (conn.session_ticket) |ticket| {
        std.log.info("received session ticket (len={d}, lifetime={d}s) - can use for 0-RTT resumption", .{ ticket.ticket_len, ticket.lifetime });
    }

    // === Close connection ===
    conn.close(0, "done");
    sendAll(sockfd, &conn, &out, &remote_addr, addr_size);

    // Drain: wait for connection to terminate (3×PTO)
    var drain_iter: usize = 0;
    while (!conn.isClosed() and drain_iter < 30) : (drain_iter += 1) {
        std.Thread.sleep(5 * std.time.ns_per_ms);
        conn.onTimeout() catch break;

        recvAll(sockfd, &conn, &local_addr, &remote_addr, &addr_size);
        sendAll(sockfd, &conn, &out, &remote_addr, addr_size);
    }
    std.log.info("connection closed cleanly", .{});
}
