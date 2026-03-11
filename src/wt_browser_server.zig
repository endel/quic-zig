const std = @import("std");
const posix = std.posix;

const connection = @import("quic/connection.zig");
const connection_manager = @import("quic/connection_manager.zig");
const tls13 = @import("quic/tls13.zig");
const ecn_socket = @import("quic/ecn_socket.zig");
const h3 = @import("h3/connection.zig");
const wt = @import("webtransport/session.zig");

const MAX_DATAGRAM_SIZE: usize = 1500;

pub fn main() !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    // Read cert files at runtime
    const server_cert_pem = try std.fs.cwd().readFileAlloc(alloc, "interop/browser/certs/server.crt", 8192);
    const server_key_pem = try std.fs.cwd().readFileAlloc(alloc, "interop/browser/certs/server.key", 8192);

    // Parse PEM -> DER
    var cert_der_buf: [4096]u8 = undefined;
    const cert_der = try tls13.parsePemCert(server_cert_pem, &cert_der_buf);

    var key_der_buf: [4096]u8 = undefined;
    const key_der = try tls13.parsePemPrivateKey(server_key_pem, &key_der_buf);
    const ec_private_key = try tls13.extractEcPrivateKey(key_der);

    // Compute and print SHA-256 hash of DER certificate
    var cert_hash: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(cert_der, &cert_hash, .{});
    std.debug.print("\n=== Browser WebTransport Server ===\n", .{});
    std.debug.print("Certificate SHA-256: ", .{});
    for (cert_hash) |byte| {
        std.debug.print("{x:0>2}", .{byte});
    }
    std.debug.print("\n", .{});

    // Print as JS Uint8Array for easy copy-paste
    std.debug.print("JS: new Uint8Array([", .{});
    for (cert_hash, 0..) |byte, idx| {
        if (idx > 0) std.debug.print(", ", .{});
        std.debug.print("{d}", .{byte});
    }
    std.debug.print("])\n\n", .{});

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

    // Generate random keys
    var retry_token_key: [16]u8 = undefined;
    std.crypto.random.bytes(&retry_token_key);

    var static_reset_key: [16]u8 = undefined;
    std.crypto.random.bytes(&static_reset_key);

    // Create UDP socket - listen on 0.0.0.0 for browser connections
    const local_addr = try std.net.Address.parseIp4("0.0.0.0", 4433);
    const sockfd = try posix.socket(posix.AF.INET, posix.SOCK.DGRAM | posix.SOCK.NONBLOCK, 0);
    defer posix.close(sockfd);
    try posix.bind(sockfd, &local_addr.any, local_addr.getOsSockLen());
    ecn_socket.enableEcnRecv(sockfd) catch {};
    std.debug.print("Listening on https://0.0.0.0:4433\n\n", .{});

    var conn_mgr = connection_manager.ConnectionManager.init(
        alloc,
        tls_config,
        .{
            .max_datagram_frame_size = 65536,
            .token_key = retry_token_key,
        },
        retry_token_key,
        static_reset_key,
    );
    defer conn_mgr.deinit();

    var remote_addr: posix.sockaddr = undefined;
    var addr_size: posix.socklen_t = @sizeOf(posix.sockaddr);
    var out: [MAX_DATAGRAM_SIZE]u8 = undefined;

    var loop_count: usize = 0;
    while (true) {
        std.Thread.sleep(1 * std.time.ns_per_ms);
        loop_count += 1;
        if (loop_count % 5000 == 0) {
            std.log.debug("server loop iteration {d} ({d} connections)", .{ loop_count, conn_mgr.connectionCount() });
        }

        // Read loop: process all available UDP packets
        read_loop: while (true) {
            var bytes: [8192]u8 = undefined;
            addr_size = @sizeOf(posix.sockaddr);

            const recv_result = ecn_socket.recvmsgEcn(sockfd, &bytes) catch |err| {
                if (err == error.WouldBlock) break :read_loop;
                std.log.err("recvmsg error: {any}", .{err});
                break :read_loop;
            };
            remote_addr = recv_result.from_addr;
            addr_size = recv_result.addr_len;

            switch (conn_mgr.recvDatagram(bytes[0..recv_result.bytes_read], remote_addr, local_addr.any, recv_result.ecn, &out)) {
                .processed => |entry| {
                    const conn = entry.conn;
                    const bytes_written = conn.send(&out) catch continue;
                    if (bytes_written > 0) {
                        ecn_socket.setEcnMark(sockfd, conn.getEcnMark()) catch {};
                        const send_addr = conn.peerAddress();
                        _ = posix.sendto(sockfd, out[0..bytes_written], 0, send_addr, @sizeOf(posix.sockaddr)) catch {};
                    }
                },
                .send_response => |data| {
                    _ = posix.sendto(sockfd, data, 0, &remote_addr, addr_size) catch {};
                },
                .dropped => {},
            }
        }

        // Per-connection processing: H3+WT init, events, timeouts, periodic sends
        var i: usize = 0;
        while (i < conn_mgr.entries.items.len) {
            const entry = conn_mgr.entries.items[i];
            const conn = entry.conn;

            // Initialize H3+WT once handshake completes
            if (conn.isEstablished() and !entry.h3_initialized) {
                entry.h3_conn = h3.H3Connection.init(alloc, conn, true);
                entry.h3_conn.?.local_settings = .{
                    .enable_connect_protocol = true,
                    .h3_datagram = true,
                    .enable_webtransport = true,
                    .webtransport_max_sessions = 1,
                };
                entry.h3_conn.?.initConnection() catch |err| {
                    std.log.err("H3 init error: {any}", .{err});
                    i += 1;
                    continue;
                };
                entry.wt_conn = wt.WebTransportConnection.init(alloc, &entry.h3_conn.?, conn, true);
                entry.h3_initialized = true;
                std.debug.print("HTTP/3 + WebTransport initialized (total: {d})\n", .{conn_mgr.connectionCount()});
            }

            // Poll WT events
            if (entry.wt_conn != null) {
                var wtc = &entry.wt_conn.?;

                while (true) {
                    const event = wtc.poll() catch break;
                    if (event == null) break;

                    switch (event.?) {
                        .connect_request => |req| {
                            std.debug.print("WT session request on stream {d} (protocol={s}, path={s})\n", .{
                                req.session_id, req.protocol, req.path,
                            });
                            wtc.acceptSession(req.session_id) catch |err| {
                                std.log.err("WT accept error: {any}", .{err});
                                continue;
                            };
                            std.debug.print("WT session accepted (session_id={d})\n", .{req.session_id});
                        },
                        .bidi_stream => |bs| {
                            std.debug.print("WT: bidi stream {d} (session={d})\n", .{ bs.stream_id, bs.session_id });
                        },
                        .uni_stream => |us| {
                            std.debug.print("WT: uni stream {d} (session={d})\n", .{ us.stream_id, us.session_id });
                        },
                        .stream_data => |sd| {
                            std.debug.print("WT: stream {d} data: {s}\n", .{ sd.stream_id, sd.data });
                            var echo_buf: [1024]u8 = undefined;
                            const echo_msg = std.fmt.bufPrint(&echo_buf, "Echo: {s}", .{sd.data}) catch continue;
                            wtc.sendStreamData(sd.stream_id, echo_msg) catch |err| {
                                std.log.err("WT sendStreamData error: {any}", .{err});
                            };
                            wtc.closeStream(sd.stream_id);
                        },
                        .datagram => |dg| {
                            std.debug.print("WT: datagram from session {d}: {s}\n", .{ dg.session_id, dg.data });
                            var echo_buf: [1024]u8 = undefined;
                            const echo_msg = std.fmt.bufPrint(&echo_buf, "Echo: {s}", .{dg.data}) catch continue;
                            wtc.sendDatagram(dg.session_id, echo_msg) catch |err| {
                                std.log.err("WT sendDatagram error: {any}", .{err});
                            };
                        },
                        .session_ready => |sid| {
                            std.debug.print("WT: session {d} ready\n", .{sid});
                        },
                        .session_rejected => |rej| {
                            std.debug.print("WT: session {d} rejected ({s})\n", .{ rej.session_id, rej.status });
                        },
                        .session_closed => |sid| {
                            std.debug.print("WT: session {d} closed\n", .{sid});
                        },
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
                _ = posix.sendto(sockfd, out[0..bytes_written], 0, send_addr, @sizeOf(posix.sockaddr)) catch {};
            }

            i += 1;
        }
    }
}
