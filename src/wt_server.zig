const std = @import("std");
const posix = std.posix;
const io = std.io;

const connection = @import("quic/connection.zig");
const packet = @import("quic/packet.zig");
const protocol = @import("quic/protocol.zig");
const tls13 = @import("quic/tls13.zig");
const h3 = @import("h3/connection.zig");
const h3_frame = @import("h3/frame.zig");
const qpack = @import("h3/qpack.zig");
const wt = @import("webtransport/session.zig");

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
    std.debug.print("WebTransport server listening on 127.0.0.1:4434\n", .{});

    var conn_state: ?connection.Connection = null;
    var h3_conn: ?h3.H3Connection = null;
    var wt_conn: ?wt.WebTransportConnection = null;
    var h3_initialized = false;
    var remote_addr: posix.sockaddr = undefined;
    var addr_size: posix.socklen_t = @sizeOf(posix.sockaddr);
    var out: [MAX_DATAGRAM_SIZE]u8 = undefined;

    while (true) {
        std.Thread.sleep(1 * std.time.ns_per_ms);

        // Read loop: process all available UDP packets
        read_loop: while (true) {
            var bytes: [8192]u8 = undefined;
            addr_size = @sizeOf(posix.sockaddr);

            const packet_length = posix.recvfrom(sockfd, &bytes, 0, &remote_addr, &addr_size) catch |err| {
                if (err == error.WouldBlock) break :read_loop;
                std.log.err("recvfrom error: {any}", .{err});
                break :read_loop;
            };

            var fbs = io.fixedBufferStream(bytes[0..packet_length]);

            while (fbs.pos < packet_length) {
                if (bytes[fbs.pos] & 0x40 == 0) break;

                const packet_start_pos = fbs.pos;
                var header = packet.Header.parse(&fbs, if (conn_state) |*cs| cs.scid_len else 8) catch |err| {
                    std.log.err("header parse error: {any}", .{err});
                    break;
                };

                const header_end_pos = fbs.pos;
                const encrypted_payload_size = header.remainder_len;
                const full_packet_size = header_end_pos - packet_start_pos + encrypted_payload_size;

                // Version negotiation
                if (header.version != 0 and !protocol.isSupportedVersion(header.version)) {
                    var vn_buf: [MAX_DATAGRAM_SIZE]u8 = undefined;
                    var vn_fbs = io.fixedBufferStream(&vn_buf);
                    const vn_writer = vn_fbs.writer();
                    try packet.negotiateVersion(header, &vn_writer);
                    const vn_bytes = vn_fbs.getWritten();
                    _ = try posix.sendto(sockfd, vn_bytes, 0, &remote_addr, addr_size);
                    break;
                }

                // Accept connection on first Initial
                if (conn_state == null) {
                    if (header.packet_type != .initial) break;
                    conn_state = try connection.Connection.accept(
                        alloc,
                        header,
                        local_addr.any,
                        remote_addr,
                        true,
                        .{
                            .max_datagram_frame_size = 65536,
                        },
                        tls_config,
                    );
                    std.log.info("accepted new connection", .{});
                }

                var conn = &conn_state.?;
                conn.recv(&header, &fbs, .{
                    .to = local_addr.any,
                    .from = remote_addr,
                }) catch |err| {
                    std.log.err("recv error: {any}", .{err});
                    break;
                };

                const expected_next_pos = packet_start_pos + full_packet_size;
                if (fbs.pos < expected_next_pos) fbs.pos = expected_next_pos;

                const bytes_written = conn.send(&out) catch |err| {
                    std.log.err("send error: {any}", .{err});
                    break;
                };
                if (bytes_written > 0) {
                    const send_addr = &conn.paths[conn.active_path_idx].peer_addr;
                    _ = try posix.sendto(sockfd, out[0..bytes_written], 0, send_addr, @sizeOf(posix.sockaddr));
                }
            }
        }

        // WebTransport processing
        if (conn_state != null) {
            var conn = &conn_state.?;

            if (conn.isEstablished() and !h3_initialized) {
                h3_conn = h3.H3Connection.init(alloc, conn, true);
                h3_conn.?.local_settings = .{
                    .enable_connect_protocol = true,
                    .h3_datagram = true,
                    .webtransport_max_sessions = 1,
                };
                h3_conn.?.initConnection() catch |err| {
                    std.log.err("H3 init error: {any}", .{err});
                    continue;
                };
                wt_conn = wt.WebTransportConnection.init(alloc, &h3_conn.?, conn, true);
                h3_initialized = true;
                std.debug.print("HTTP/3 + WebTransport connection initialized\n", .{});
            }

            if (wt_conn != null) {
                var wtc = &wt_conn.?;

                // First poll H3 for connect_request events
                while (true) {
                    const h3_event = h3_conn.?.poll() catch break;
                    if (h3_event == null) break;

                    switch (h3_event.?) {
                        .settings => |settings| {
                            std.log.info("H3: received peer SETTINGS (enable_connect={}, h3_datagram={})", .{
                                settings.enable_connect_protocol, settings.h3_datagram,
                            });
                        },
                        .connect_request => |req| {
                            std.debug.print("WebTransport session request on stream {d} (protocol={s}, path={s})\n", .{
                                req.stream_id, req.protocol, req.path,
                            });
                            // Accept the session
                            wtc.acceptSession(req.stream_id) catch |err| {
                                std.log.err("WT accept error: {any}", .{err});
                                continue;
                            };
                            std.debug.print("WebTransport session accepted (session_id={d})\n", .{req.stream_id});
                        },
                        .headers => |hdr| {
                            std.log.info("H3: headers on stream {d}", .{hdr.stream_id});
                        },
                        .data => |d| {
                            std.log.info("H3: data on stream {d} ({d} bytes)", .{ d.stream_id, d.data.len });
                        },
                        .finished => |stream_id| {
                            std.log.info("H3: stream {d} finished", .{stream_id});
                        },
                        .goaway => {},
                    }
                }

                // Poll WT events
                while (true) {
                    const event = wtc.poll() catch break;
                    if (event == null) break;

                    switch (event.?) {
                        .bidi_stream => |bs| {
                            std.debug.print("WT: new bidi stream {d} (session={d})\n", .{ bs.stream_id, bs.session_id });
                        },
                        .uni_stream => |us| {
                            std.debug.print("WT: new uni stream {d} (session={d})\n", .{ us.stream_id, us.session_id });
                        },
                        .stream_data => |sd| {
                            std.debug.print("WT: stream {d} data: {s}\n", .{ sd.stream_id, sd.data });
                            // Echo back on the same stream
                            var echo_buf: [1024]u8 = undefined;
                            const echo_msg = std.fmt.bufPrint(&echo_buf, "Echo: {s}", .{sd.data}) catch continue;
                            wtc.sendStreamData(sd.stream_id, echo_msg) catch |err| {
                                std.log.err("WT sendStreamData error: {any}", .{err});
                            };
                            wtc.closeStream(sd.stream_id);
                        },
                        .datagram => |dg| {
                            std.debug.print("WT: datagram from session {d}: {s}\n", .{ dg.session_id, dg.data });
                            // Echo back as datagram
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

            // Periodic send
            const bytes_written = conn.send(&out) catch |err| {
                std.log.err("periodic send error: {any}", .{err});
                continue;
            };
            if (bytes_written > 0) {
                const send_addr = &conn.paths[conn.active_path_idx].peer_addr;
                _ = try posix.sendto(sockfd, out[0..bytes_written], 0, send_addr, @sizeOf(posix.sockaddr));
            }
        }
    }
}
