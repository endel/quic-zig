// WebTransport Browser Server — Manual (non-event-loop) version
//
// Equivalent to wt_browser_server.zig but uses raw UDP sockets and
// ConnectionManager directly, like interop_server_manual.zig.
//
// Echoes bidi stream data and datagrams back to the browser client.
// Prints the certificate SHA-256 hash for browser pinning.
//
// Usage: zig build run-wt-browser-server-manual -- [--port PORT] [--cert PATH] [--key PATH]

const std = @import("std");
const posix = std.posix;

const lib = @import("quic");
const sys = lib.sys;
const net = lib.sockaddr;
const connection = lib.connection;
const connection_manager = lib.connection_manager;
const tls13 = lib.tls13;
const ecn_socket = lib.ecn_socket;
const h3 = lib.h3;
const qpack = lib.qpack;
const wt = lib.webtransport;

const MAX_DATAGRAM_SIZE: usize = 1500;

// One QPACK decode buffer for every connection this process serves: the
// header slices it hands back live only until the next decode.
var qpack_scratch: [qpack.SCRATCH_SIZE]u8 = undefined;

pub fn main(init: std.process.Init.Minimal) !void {
    // A server outlives its streams, so it needs an allocator that reuses what
    // they give back — an arena would grow for as long as the process runs.
    const alloc = std.heap.smp_allocator;

    // Parse args
    var port: u16 = 4433;
    var cert_path: []const u8 = "interop/browser/certs/server.crt";
    var key_path: []const u8 = "interop/browser/certs/server.key";

    var args = sys.argsIterator(init.args);
    _ = args.next();
    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--port")) {
            if (args.next()) |v| port = std.fmt.parseInt(u16, v, 10) catch 4433;
        } else if (std.mem.eql(u8, arg, "--cert")) {
            if (args.next()) |v| cert_path = v;
        } else if (std.mem.eql(u8, arg, "--key")) {
            if (args.next()) |v| key_path = v;
        }
    }

    // Print certificate SHA-256 hash for browser pinning
    const server_cert_pem = try sys.readFileAlloc(alloc, cert_path, 8192);
    var cert_der_buf: [4096]u8 = undefined;
    const cert_der = try tls13.parsePemCert(server_cert_pem, &cert_der_buf);

    var cert_hash: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(cert_der, &cert_hash, .{});
    std.debug.print("\n=== Manual WebTransport Browser Server ===\n", .{});
    std.debug.print("Certificate SHA-256: ", .{});
    for (cert_hash) |byte| {
        std.debug.print("{x:0>2}", .{byte});
    }
    std.debug.print("\n", .{});

    std.debug.print("JS: new Uint8Array([", .{});
    for (cert_hash, 0..) |byte, idx| {
        if (idx > 0) std.debug.print(", ", .{});
        std.debug.print("{d}", .{byte});
    }
    std.debug.print("])\n\n", .{});

    // Load certificates
    const cert_pem = try sys.readFileAlloc(alloc, cert_path, 8192);
    const key_pem = try sys.readFileAlloc(alloc, key_path, 8192);

    const cert_chain = try tls13.parsePemCertChain(alloc, cert_pem);
    var key_der_buf: [4096]u8 = undefined;
    const key_der = try tls13.parsePemPrivateKey(key_pem, &key_der_buf);
    const ec_private_key = try tls13.extractEcPrivateKey(key_der);

    const alpn = try alloc.alloc([]const u8, 1);
    alpn[0] = "h3";

    var ticket_key: [16]u8 = undefined;
    sys.randomBytes(&ticket_key);
    var retry_token_key: [16]u8 = undefined;
    sys.randomBytes(&retry_token_key);
    var static_reset_key: [16]u8 = undefined;
    sys.randomBytes(&static_reset_key);

    const tls_config: tls13.TlsConfig = .{
        .cert_chain_der = cert_chain,
        .private_key_bytes = ec_private_key,
        .alpn = alpn,
        .ticket_key = ticket_key,
    };

    const conn_config: connection.ConnectionConfig = .{
        .token_key = retry_token_key,
        .max_datagram_frame_size = 65536,
    };

    // Create UDP socket (dual-stack: try IPv6 first, fall back to IPv4)
    const sockfd, const local_addr = blk: {
        for ([_]net.Address{
            try net.Address.parseIp6("::", port),
            try net.Address.parseIp4("0.0.0.0", port),
        }) |addr| {
            const fd = sys.udpSocket(addr.any.family, .{}) catch continue;
            sys.bind(fd, &addr.any, addr.getOsSockLen()) catch {
                sys.close(fd);
                continue;
            };
            break :blk .{ fd, addr };
        }
        return error.BindFailed;
    };
    defer sys.close(sockfd);
    ecn_socket.enableEcnRecv(sockfd) catch {};

    var conn_mgr = connection_manager.ConnectionManager.init(
        alloc,
        tls_config,
        conn_config,
        retry_token_key,
        static_reset_key,
    );
    defer conn_mgr.deinit();

    std.debug.print("Listening on https://0.0.0.0:{d} (QUIC/WebTransport) [manual mode]\n\n", .{port});

    var remote_addr: posix.sockaddr.storage = std.mem.zeroes(posix.sockaddr.storage);
    var addr_size: posix.socklen_t = @sizeOf(posix.sockaddr);
    var out: [MAX_DATAGRAM_SIZE]u8 = undefined;

    while (true) {
        // Read loop: process all available UDP packets
        var packets_received: usize = 0;
        read_loop: while (true) {
            var bytes: [MAX_DATAGRAM_SIZE]u8 = undefined;
            addr_size = @sizeOf(posix.sockaddr);

            const recv_result = ecn_socket.recvmsgEcn(sockfd, &bytes) catch |err| {
                if (err == error.WouldBlock) break :read_loop;
                std.log.err("recvmsg error: {any}", .{err});
                break :read_loop;
            };
            packets_received += 1;
            remote_addr = recv_result.from_addr;
            addr_size = recv_result.addr_len;

            switch (conn_mgr.recvDatagram(bytes[0..recv_result.bytes_read], remote_addr, connection.sockaddrToStorage(&local_addr.any), recv_result.ecn, &out)) {
                .processed => |entry| {
                    const bytes_written = entry.conn.send(&out) catch continue;
                    if (bytes_written > 0) {
                        ecn_socket.setEcnMark(sockfd, entry.conn.getEcnMark()) catch {};
                        const send_addr = entry.conn.peerAddress();
                        _ = sys.sendto(sockfd, out[0..bytes_written], 0, @ptrCast(send_addr), connection.sockaddrLen(send_addr)) catch {};
                    }
                },
                .send_response => |data| {
                    _ = sys.sendto(sockfd, data, 0, @ptrCast(&remote_addr), addr_size) catch {};
                },
                .dropped => {},
            }
        }

        // Per-connection processing
        var i: usize = 0;
        while (i < conn_mgr.entries.items.len) {
            const entry = conn_mgr.entries.items[i];
            const conn = entry.conn;

            // Initialize H3 + WT layers once handshake completes
            if (conn.isEstablished() and !entry.h3_initialized) {
                const h3c = alloc.create(h3.H3Connection) catch {
                    i += 1;
                    continue;
                };
                h3c.* = h3.H3Connection.init(alloc, conn, true);
                h3c.qpack_scratch = &qpack_scratch;
                h3c.local_settings = .{
                    .enable_connect_protocol = true,
                    .h3_datagram = true,
                    .enable_webtransport = true,
                    .webtransport_max_sessions = 4,
                };
                entry.h3_conn = h3c;
                h3c.initConnection() catch {
                    i += 1;
                    continue;
                };
                const wtc_new = alloc.create(wt.WebTransportConnection) catch {
                    i += 1;
                    continue;
                };
                wtc_new.* = wt.WebTransportConnection.init(alloc, h3c, conn, true);
                entry.wt_conn = wtc_new;
                entry.h3_initialized = true;
                std.debug.print("connection established (total: {d})\n", .{conn_mgr.connectionCount()});
            }

            // Poll WebTransport events
            if (entry.wt_conn) |wtc| {

                // Drain datagrams
                while (wtc.pollDatagrams()) |dg_event| {
                    switch (dg_event) {
                        .datagram => |dg| {
                            std.debug.print("WT datagram from session {d}: {s}\n", .{ dg.session_id, dg.data });
                            var echo_buf: [1024]u8 = undefined;
                            const echo_msg = std.fmt.bufPrint(&echo_buf, "Echo: {s}", .{dg.data}) catch continue;
                            wtc.sendDatagram(dg.session_id, echo_msg) catch |err| {
                                std.log.err("sendDatagram error: {any}", .{err});
                            };
                        },
                        else => {},
                    }
                }

                // Drain WT events
                while (true) {
                    const event = wtc.poll() catch break;
                    if (event == null) break;

                    switch (event.?) {
                        .connect_request => |req| {
                            std.debug.print("WT CONNECT request: session_id={d} path={s}\n", .{ req.session_id, req.path });
                            wtc.acceptSession(req.session_id) catch |err| {
                                std.log.err("acceptSession error: {any}", .{err});
                                continue;
                            };
                            std.debug.print("WT session {d} accepted\n", .{req.session_id});
                        },
                        .session_ready => |sr| {
                            std.debug.print("WT session {d} ready\n", .{sr.session_id});
                        },
                        .stream_data => |sd| {
                            if (sd.data.len > 0) {
                                std.debug.print("WT stream {d} data: {s}\n", .{ sd.stream_id, sd.data });
                                var echo_buf: [1024]u8 = undefined;
                                const echo_msg = std.fmt.bufPrint(&echo_buf, "Echo: {s}", .{sd.data}) catch continue;
                                wtc.sendStreamData(sd.stream_id, echo_msg) catch |err| {
                                    std.log.err("sendStreamData error: {any}", .{err});
                                    continue;
                                };
                            }
                            if (sd.fin) {
                                wtc.closeStream(sd.stream_id);
                            }
                        },
                        .datagram => |dg| {
                            std.debug.print("WT datagram (poll) from session {d}: {s}\n", .{ dg.session_id, dg.data });
                            var echo_buf: [1024]u8 = undefined;
                            const echo_msg = std.fmt.bufPrint(&echo_buf, "Echo: {s}", .{dg.data}) catch continue;
                            wtc.sendDatagram(dg.session_id, echo_msg) catch |err| {
                                std.log.err("sendDatagram error: {any}", .{err});
                            };
                        },
                        .session_closed => |cls| {
                            std.debug.print("WT session {d} closed (code={d}, reason={s})\n", .{ cls.session_id, cls.error_code, cls.reason });
                        },
                        .session_draining => |drain| {
                            std.debug.print("WT session {d} draining\n", .{drain.session_id});
                        },
                        .bidi_stream => |bs| {
                            std.debug.print("WT new bidi stream {d} on session {d}\n", .{ bs.stream_id, bs.session_id });
                        },
                        .uni_stream => |us| {
                            std.debug.print("WT new uni stream {d} on session {d}\n", .{ us.stream_id, us.session_id });
                        },
                        .stream_reset => |rst| {
                            std.debug.print("WT stream {d} reset by peer (code={d})\n", .{ rst.stream_id, rst.error_code });
                        },
                        .stream_stop_sending => |ss| {
                            std.debug.print("WT stream {d} STOP_SENDING from peer (code={d})\n", .{ ss.stream_id, ss.error_code });
                        },
                        .writable => {}, // never asked for: no notifyWritable here
                        .session_rejected => {},
                    }
                }

                // Drain disposal queue
                wtc.drainDisposalQueue();
            }
            conn.streams.drainDisposalQueue();

            // Timeouts + close check
            if (!conn_mgr.tickEntry(entry)) {
                continue; // entry was removed, don't increment
            }

            // Burst send — drain queued data
            var send_count: usize = 0;
            while (send_count < 100) : (send_count += 1) {
                const bytes_written = conn.send(&out) catch break;
                if (bytes_written == 0) break;
                ecn_socket.setEcnMark(sockfd, conn.getEcnMark()) catch {};
                const send_addr = conn.peerAddress();
                _ = sys.sendto(sockfd, out[0..bytes_written], 0, @ptrCast(send_addr), connection.sockaddrLen(send_addr)) catch {};
            }

            i += 1;
        }

        // Sleep only when idle
        if (packets_received == 0) sys.sleepNs(200 * std.time.ns_per_us);
    }
}
