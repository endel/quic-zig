const std = @import("std");
const posix = std.posix;
const net = std.net;

const connection = @import("quic/connection.zig");
const tls13 = @import("quic/tls13.zig");
const ecn_socket = @import("quic/ecn_socket.zig");
const h3 = @import("h3/connection.zig");
const qpack = @import("h3/qpack.zig");
const wt = @import("webtransport/session.zig");
const Certificate = std.crypto.Certificate;

const MAX_DATAGRAM_SIZE: usize = 1500;

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

    const local_addr = try net.Address.parseIp4("127.0.0.1", 0);
    try posix.bind(sockfd, &local_addr.any, local_addr.getOsSockLen());
    ecn_socket.enableEcnRecv(sockfd) catch {};
    std.debug.print("WebTransport client connecting to 127.0.0.1:{d}\n", .{port});

    // Create TLS config
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

    // Create client connection with datagram support
    var conn = try connection.connect(
        alloc,
        "localhost",
        .{
            .max_datagram_frame_size = 65536,
        },
        tls_config,
        null,
    );

    var remote_addr = connection.sockaddrToStorage(&server_addr.any);
    var addr_size: posix.socklen_t = connection.sockaddrLen(&remote_addr);
    var out: [MAX_DATAGRAM_SIZE]u8 = undefined;

    // Handshake loop
    var handshake_complete = false;
    var iteration: usize = 0;
    const max_iterations: usize = 1000;

    while (!handshake_complete and iteration < max_iterations) : (iteration += 1) {
        std.Thread.sleep(1 * std.time.ns_per_ms);

        const bytes_written = conn.send(&out) catch break;
        if (bytes_written > 0) {
            ecn_socket.setEcnMark(sockfd, conn.getEcnMark()) catch {};
            _ = posix.sendto(sockfd, out[0..bytes_written], 0, @ptrCast(&remote_addr), addr_size) catch continue;
        }

        while (true) {
            var bytes: [8192]u8 = undefined;
            const recv_result = ecn_socket.recvmsgEcn(sockfd, &bytes) catch break;
            remote_addr = recv_result.from_addr;
            addr_size = recv_result.addr_len;

            conn.handleDatagram(bytes[0..recv_result.bytes_read], .{
                .to = connection.sockaddrToStorage(&local_addr.any),
                .from = remote_addr,
                .ecn = recv_result.ecn,
                .datagram_size = recv_result.bytes_read,
            });

            if (conn.state == .connected) handshake_complete = true;
        }
    }

    if (!handshake_complete) {
        std.debug.print("Handshake failed\n", .{});
        return;
    }

    std.debug.print("Handshake complete\n", .{});

    // Send pending handshake packets
    const hs_bytes = conn.send(&out) catch 0;
    if (hs_bytes > 0) {
        ecn_socket.setEcnMark(sockfd, conn.getEcnMark()) catch {};
        _ = try posix.sendto(sockfd, out[0..hs_bytes], 0, @ptrCast(&remote_addr), addr_size);
    }

    // Sync remote_addr from active path (may have changed due to preferred address migration)
    remote_addr = conn.peerAddress().*;

    std.Thread.sleep(50 * std.time.ns_per_ms);

    // Initialize HTTP/3 + WebTransport
    var h3_conn = h3.H3Connection.init(alloc, &conn, false);
    defer h3_conn.deinit();
    h3_conn.local_settings = .{
        .enable_connect_protocol = true,
        .h3_datagram = true,
        .enable_webtransport = true,
        .webtransport_max_sessions = 1,
    };
    try h3_conn.initConnection();

    var wt_conn = wt.WebTransportConnection.init(alloc, &h3_conn, &conn, false);
    defer wt_conn.deinit();

    // Send Extended CONNECT to establish WebTransport session
    const session_id = try wt_conn.connect("localhost", "/.well-known/webtransport");
    std.debug.print("WebTransport CONNECT sent (session_id={d})\n", .{session_id});

    // Flush H3 control streams + CONNECT request
    var flush_count: usize = 0;
    while (flush_count < 10) : (flush_count += 1) {
        const more = conn.send(&out) catch break;
        if (more == 0) break;
        ecn_socket.setEcnMark(sockfd, conn.getEcnMark()) catch {};
        _ = posix.sendto(sockfd, out[0..more], 0, @ptrCast(&remote_addr), addr_size) catch break;
    }

    // Wait for session to be accepted
    var session_ready = false;
    var response_iter: usize = 0;
    const max_response_iter: usize = 500;

    while (!session_ready and response_iter < max_response_iter) : (response_iter += 1) {
        std.Thread.sleep(10 * std.time.ns_per_ms);

        // Read QUIC packets
        while (true) {
            var bytes: [8192]u8 = undefined;
            const recv_result = ecn_socket.recvmsgEcn(sockfd, &bytes) catch break;
            remote_addr = recv_result.from_addr;
            addr_size = recv_result.addr_len;

            conn.handleDatagram(bytes[0..recv_result.bytes_read], .{
                .to = connection.sockaddrToStorage(&local_addr.any),
                .from = remote_addr,
                .ecn = recv_result.ecn,
                .datagram_size = recv_result.bytes_read,
            });
        }

        // Send ACKs
        const ack_bytes = conn.send(&out) catch continue;
        if (ack_bytes > 0) {
            ecn_socket.setEcnMark(sockfd, conn.getEcnMark()) catch {};
            _ = posix.sendto(sockfd, out[0..ack_bytes], 0, @ptrCast(&remote_addr), addr_size) catch {};
        }

        // Poll for WT events
        while (true) {
            const event = wt_conn.poll() catch break;
            if (event == null) break;

            switch (event.?) {
                .session_ready => |sid| {
                    std.debug.print("WebTransport session ready (session_id={d})\n", .{sid});
                    session_ready = true;
                },
                .session_rejected => |rej| {
                    std.debug.print("WebTransport session rejected: {s}\n", .{rej.status});
                    return;
                },
                else => {},
            }
        }
    }

    if (!session_ready) {
        std.debug.print("WebTransport session not established\n", .{});
        return;
    }

    // Open a bidi stream and send data
    const stream_id = try wt_conn.openBidiStream(session_id);
    const msg = "Hello from Zig WebTransport!";
    try wt_conn.sendStreamData(stream_id, msg);
    wt_conn.closeStream(stream_id);
    std.debug.print("Sent on bidi stream {d}: {s}\n", .{ stream_id, msg });

    // Also send a datagram
    if (conn.datagrams_enabled) {
        wt_conn.sendDatagram(session_id, "Hello via datagram!") catch |err| {
            std.debug.print("Datagram send failed (expected if peer doesn't support): {any}\n", .{err});
        };
        std.debug.print("Sent datagram\n", .{});
    } else {
        std.debug.print("Datagrams not enabled by peer\n", .{});
    }

    // Flush data
    flush_count = 0;
    while (flush_count < 10) : (flush_count += 1) {
        const more = conn.send(&out) catch break;
        if (more == 0) break;
        ecn_socket.setEcnMark(sockfd, conn.getEcnMark()) catch {};
        _ = posix.sendto(sockfd, out[0..more], 0, @ptrCast(&remote_addr), addr_size) catch break;
    }

    // Read echo response
    var got_response = false;
    response_iter = 0;

    while (!got_response and response_iter < max_response_iter) : (response_iter += 1) {
        std.Thread.sleep(10 * std.time.ns_per_ms);

        while (true) {
            var bytes: [8192]u8 = undefined;
            const recv_result = ecn_socket.recvmsgEcn(sockfd, &bytes) catch break;
            remote_addr = recv_result.from_addr;
            addr_size = recv_result.addr_len;

            conn.handleDatagram(bytes[0..recv_result.bytes_read], .{
                .to = connection.sockaddrToStorage(&local_addr.any),
                .from = remote_addr,
                .ecn = recv_result.ecn,
                .datagram_size = recv_result.bytes_read,
            });
        }

        const ack_bytes = conn.send(&out) catch continue;
        if (ack_bytes > 0) {
            ecn_socket.setEcnMark(sockfd, conn.getEcnMark()) catch {};
            _ = posix.sendto(sockfd, out[0..ack_bytes], 0, @ptrCast(&remote_addr), addr_size) catch {};
        }

        // Poll for WT events
        while (true) {
            const event = wt_conn.poll() catch break;
            if (event == null) break;

            switch (event.?) {
                .stream_data => |sd| {
                    std.debug.print("Response on stream {d}: {s}\n", .{ sd.stream_id, sd.data });
                    got_response = true;
                },
                .datagram => |dg| {
                    std.debug.print("Datagram response (session={d}): {s}\n", .{ dg.session_id, dg.data });
                    got_response = true;
                },
                .session_closed => |cls| {
                    std.debug.print("Session {d} closed (code={d}, reason={s})\n", .{
                        cls.session_id, cls.error_code, cls.reason,
                    });
                },
                else => {},
            }
        }
    }

    if (!got_response) {
        std.debug.print("No WebTransport echo response received\n", .{});
    }

    // Close
    conn.close(0, "done");
    const final_bytes = conn.send(&out) catch 0;
    if (final_bytes > 0) {
        _ = try posix.sendto(sockfd, out[0..final_bytes], 0, @ptrCast(&remote_addr), addr_size);
    }
}
