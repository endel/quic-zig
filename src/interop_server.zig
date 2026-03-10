// QUIC Interop Runner - Server Endpoint
//
// Reads environment variables set by the interop runner:
//   TESTCASE    - which test to run (handshake, transfer, retry, etc.)
//   SSLKEYLOGFILE - path to write TLS key log
//   QLOGDIR     - path to write qlog files (not yet implemented)
//
// Serves files from /www/ using HTTP/0.9 (hq-interop) or HTTP/3.
// Listens on 0.0.0.0:443.
// Loads certs from /certs/cert.pem and /certs/priv.key.

const std = @import("std");
const posix = std.posix;
const io = std.io;

const connection = @import("quic/connection.zig");
const connection_manager = @import("quic/connection_manager.zig");
const quic_crypto = @import("quic/crypto.zig");
const packet = @import("quic/packet.zig");
const protocol = @import("quic/protocol.zig");
const tls13 = @import("quic/tls13.zig");
const stateless_reset = @import("quic/stateless_reset.zig");
const ecn_socket = @import("quic/ecn_socket.zig");
const h3 = @import("h3/connection.zig");
const h0 = @import("h0/connection.zig");
const qpack = @import("h3/qpack.zig");

const MAX_DATAGRAM_SIZE: usize = 1500;

const TestCase = enum {
    handshake,
    transfer,
    multiconnect,
    retry,
    resumption,
    zerortt,
    http3,
    keyupdate,
    ecn,
    connectionmigration,
    chacha20,
    v2,
    unsupported,
};

fn parseTestCase(name: []const u8) TestCase {
    if (std.mem.eql(u8, name, "handshake")) return .handshake;
    if (std.mem.eql(u8, name, "transfer")) return .transfer;
    if (std.mem.eql(u8, name, "multiconnect")) return .multiconnect;
    if (std.mem.eql(u8, name, "retry")) return .retry;
    if (std.mem.eql(u8, name, "resumption")) return .resumption;
    if (std.mem.eql(u8, name, "zerortt")) return .zerortt;
    if (std.mem.eql(u8, name, "http3")) return .http3;
    if (std.mem.eql(u8, name, "keyupdate")) return .keyupdate;
    if (std.mem.eql(u8, name, "ecn")) return .ecn;
    if (std.mem.eql(u8, name, "connectionmigration")) return .connectionmigration;
    if (std.mem.eql(u8, name, "chacha20")) return .chacha20;
    if (std.mem.eql(u8, name, "v2")) return .v2;
    return .unsupported;
}

pub fn main() !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    // Read environment variables
    const testcase_str = std.posix.getenv("TESTCASE") orelse "handshake";
    const testcase = parseTestCase(testcase_str);
    const sslkeylogfile_path = std.posix.getenv("SSLKEYLOGFILE");
    const www_dir = std.posix.getenv("WWW") orelse "/www";
    const certs_dir = std.posix.getenv("CERTS") orelse "/certs";
    const port_str = std.posix.getenv("PORT") orelse "443";

    std.log.info("interop server: testcase={s}", .{testcase_str});

    if (testcase == .unsupported) {
        std.log.err("unsupported test case: {s}", .{testcase_str});
        std.process.exit(127);
    }

    // Open SSLKEYLOGFILE if requested
    const keylog_file: ?std.fs.File = if (sslkeylogfile_path) |path|
        std.fs.cwd().createFile(path, .{}) catch null
    else
        null;
    defer if (keylog_file) |f| f.close();

    // Load certificates
    var cert_path_buf: [256]u8 = undefined;
    const cert_path = std.fmt.bufPrint(&cert_path_buf, "{s}/cert.pem", .{certs_dir}) catch "/certs/cert.pem";
    var key_path_buf: [256]u8 = undefined;
    const key_path = std.fmt.bufPrint(&key_path_buf, "{s}/priv.key", .{certs_dir}) catch "/certs/priv.key";

    const cert_pem = loadFile(alloc, cert_path) catch |err| {
        std.log.err("failed to load {s}: {any}", .{ cert_path, err });
        return err;
    };
    const key_pem = loadFile(alloc, key_path) catch |err| {
        std.log.err("failed to load {s}: {any}", .{ key_path, err });
        return err;
    };

    var cert_der_buf: [4096]u8 = undefined;
    const cert_der = try tls13.parsePemCert(cert_pem, &cert_der_buf);

    var key_der_buf: [4096]u8 = undefined;
    const key_der = try tls13.parsePemPrivateKey(key_pem, &key_der_buf);
    const ec_private_key = try tls13.extractEcPrivateKey(key_der);

    // Build TLS config
    const cert_chain = try alloc.alloc([]const u8, 1);
    cert_chain[0] = cert_der;

    const use_h3 = (testcase == .http3);
    const alpn = try alloc.alloc([]const u8, 1);
    alpn[0] = if (use_h3) "h3" else "hq-interop";

    var ticket_key: [16]u8 = undefined;
    std.crypto.random.bytes(&ticket_key);

    var retry_token_key: [16]u8 = undefined;
    std.crypto.random.bytes(&retry_token_key);

    var static_reset_key: [16]u8 = undefined;
    std.crypto.random.bytes(&static_reset_key);

    const cipher_only: ?quic_crypto.CipherSuite = if (testcase == .chacha20) .chacha20_poly1305_sha256 else null;

    const tls_config: tls13.TlsConfig = .{
        .cert_chain_der = cert_chain,
        .private_key_bytes = ec_private_key,
        .alpn = alpn,
        .ticket_key = ticket_key,
        .keylog_file = keylog_file,
        .cipher_suite_only = cipher_only,
    };

    // Create UDP socket
    const listen_port: u16 = std.fmt.parseInt(u16, port_str, 10) catch 443;
    const local_addr = try std.net.Address.parseIp4("0.0.0.0", listen_port);
    const sockfd = try posix.socket(posix.AF.INET, posix.SOCK.DGRAM | posix.SOCK.NONBLOCK, 0);
    defer posix.close(sockfd);
    try posix.bind(sockfd, &local_addr.any, local_addr.getOsSockLen());
    ecn_socket.enableEcnRecv(sockfd) catch {};
    std.log.info("interop server listening on 0.0.0.0:{d} (ALPN={s})", .{ listen_port, alpn[0] });

    var conn_mgr = connection_manager.ConnectionManager.init(
        alloc,
        tls_config,
        .{ .token_key = retry_token_key, .enable_v2 = (testcase == .v2) },
        retry_token_key,
        static_reset_key,
    );
    defer conn_mgr.deinit();

    // Track H0 connections per entry (keyed by conn pointer)
    var h0_conns = std.AutoHashMap(usize, *h0.H0Connection).init(alloc);
    defer h0_conns.deinit();

    var remote_addr: posix.sockaddr = undefined;
    var addr_size: posix.socklen_t = @sizeOf(posix.sockaddr);
    var out: [MAX_DATAGRAM_SIZE]u8 = undefined;

    var loop_count: usize = 0;
    while (true) {
        loop_count += 1;

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
            const packet_length = recv_result.bytes_read;
            remote_addr = recv_result.from_addr;
            addr_size = recv_result.addr_len;

            var fbs = io.fixedBufferStream(bytes[0..packet_length]);

            while (fbs.pos < packet_length) {
                if (bytes[fbs.pos] & 0x40 == 0) break;

                const packet_start_pos = fbs.pos;
                var header = packet.Header.parse(&fbs, conn_mgr.local_cid_len) catch |err| {
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

                // Route packet to existing connection
                var entry = conn_mgr.findByDcid(header.dcid);

                if (entry == null) {
                    if (header.packet_type != .initial) {
                        if (header.packet_type == .one_rtt) {
                            var sr_buf: [MAX_DATAGRAM_SIZE]u8 = undefined;
                            const sr_max = @min(full_packet_size, sr_buf.len);
                            const sr_len = stateless_reset.generatePacket(&sr_buf, sr_max, conn_mgr.static_reset_key, header.dcid);
                            if (sr_len > 0) {
                                _ = posix.sendto(sockfd, sr_buf[0..sr_len], 0, &remote_addr, addr_size) catch {};
                            }
                        }
                        break;
                    }

                    // Retry test: require token
                    if (testcase == .retry) {
                        if (header.token == null or header.token.?.len == 0) {
                            // Send Retry
                            var retry_scid: [8]u8 = undefined;
                            std.crypto.random.bytes(&retry_scid);

                            var token_buf: [packet.TOKEN_MAX_LEN]u8 = undefined;
                            const token_len = packet.generateRetryToken(
                                &token_buf,
                                header.dcid,
                                &retry_scid,
                                remote_addr,
                                retry_token_key,
                            ) catch break;

                            var retry_buf: [MAX_DATAGRAM_SIZE]u8 = undefined;
                            var retry_fbs = io.fixedBufferStream(&retry_buf);
                            packet.retry(header, &retry_scid, token_buf[0..token_len], &retry_fbs) catch break;
                            const retry_bytes = retry_fbs.getWritten();
                            _ = try posix.sendto(sockfd, retry_bytes, 0, &remote_addr, addr_size);
                            std.log.info("sent Retry packet", .{});
                            break;
                        }

                        // Validate Retry token
                        const validated = packet.validateRetryToken(header.token.?, remote_addr, retry_token_key) catch null;
                        if (validated) |vt| {
                            entry = conn_mgr.acceptConnection(header, local_addr.any, remote_addr, vt.getOdcid(), vt.getRetryScid()) catch break;
                        } else {
                            std.log.warn("invalid retry token", .{});
                            break;
                        }
                    } else {
                        // No retry: accept directly
                        entry = conn_mgr.acceptConnection(header, local_addr.any, remote_addr, header.dcid, null) catch break;
                    }
                    std.log.info("accepted new connection", .{});
                }

                const e = entry.?;
                const conn = e.conn;
                const recv_info: connection.RecvInfo = .{
                    .to = local_addr.any,
                    .from = remote_addr,
                    .ecn = recv_result.ecn,
                };

                conn.recv(&header, &fbs, recv_info) catch |err| {
                    std.log.err("recv error: {any}", .{err});
                    break;
                };

                conn_mgr.syncCids(e);

                const expected_next_pos = packet_start_pos + full_packet_size;
                if (fbs.pos < expected_next_pos) {
                    fbs.pos = expected_next_pos;
                }

                // Send response packets
                const bytes_written = conn.send(&out) catch break;
                if (bytes_written > 0) {
                    ecn_socket.setEcnMark(sockfd, conn.getEcnMark()) catch {};
                    const send_addr = &conn.paths[conn.active_path_idx].peer_addr;
                    _ = posix.sendto(sockfd, out[0..bytes_written], 0, send_addr, @sizeOf(posix.sockaddr)) catch break;
                }
            }
        }

        // Per-connection processing
        var i: usize = 0;
        while (i < conn_mgr.entries.items.len) {
            const entry = conn_mgr.entries.items[i];
            const conn = entry.conn;
            const conn_key = @intFromPtr(conn);

            if (conn.isEstablished() and !entry.h3_initialized) {
                if (use_h3) {
                    // HTTP/3 mode
                    entry.h3_conn = h3.H3Connection.init(alloc, conn, true);
                    entry.h3_conn.?.initConnection() catch |err| {
                        std.log.err("H3 init error: {any}", .{err});
                        i += 1;
                        continue;
                    };
                } else {
                    // HTTP/0.9 mode
                    const h0c = alloc.create(h0.H0Connection) catch {
                        i += 1;
                        continue;
                    };
                    h0c.* = h0.H0Connection.init(alloc, conn, true);
                    h0_conns.put(conn_key, h0c) catch {};
                }
                entry.h3_initialized = true;
                std.log.info("connection established (total: {d})", .{conn_mgr.connectionCount()});
            }

            // Poll for protocol events
            if (use_h3) {
                if (entry.h3_conn != null) {
                    pollH3Server(&entry.h3_conn.?, alloc, www_dir);
                }
            } else {
                if (h0_conns.get(conn_key)) |h0c| {
                    pollH0Server(h0c, www_dir);
                }
            }

            // Timeouts
            conn.onTimeout() catch {};

            // Remove closed connections
            if (conn.isClosed()) {
                std.log.info("connection closed (remaining: {d})", .{conn_mgr.connectionCount() - 1});
                _ = h0_conns.remove(conn_key);
                conn_mgr.removeConnection(entry);
                continue;
            }

            // Burst send — drain queued data up to congestion/pacer limits
            var send_count: usize = 0;
            while (send_count < 100) : (send_count += 1) {
                const bytes_written = conn.send(&out) catch break;
                if (bytes_written == 0) break;
                ecn_socket.setEcnMark(sockfd, conn.getEcnMark()) catch {};
                const send_addr = &conn.paths[conn.active_path_idx].peer_addr;
                _ = posix.sendto(sockfd, out[0..bytes_written], 0, send_addr, @sizeOf(posix.sockaddr)) catch {};
            }

            i += 1;
        }

        // Only sleep when idle (no packets received and no sends happened)
        if (packets_received == 0) std.Thread.sleep(200 * std.time.ns_per_us);
    }
}

fn pollH3Server(h3c: *h3.H3Connection, alloc: std.mem.Allocator, www_dir: []const u8) void {
    while (true) {
        const event = h3c.poll() catch break;
        if (event == null) break;

        switch (event.?) {
            .headers => |hdr| {
                var path: []const u8 = "/";
                for (hdr.headers) |h_item| {
                    if (std.mem.eql(u8, h_item.name, ":path")) path = h_item.value;
                }

                // Read file and send response
                const file_data = readFileFromWww(alloc, www_dir, path) catch {
                    // Send 404
                    const resp_headers = [_]qpack.Header{
                        .{ .name = ":status", .value = "404" },
                    };
                    h3c.sendResponse(hdr.stream_id, &resp_headers, "Not Found\n") catch {};
                    continue;
                };
                defer alloc.free(file_data);

                const resp_headers = [_]qpack.Header{
                    .{ .name = ":status", .value = "200" },
                };
                h3c.sendResponse(hdr.stream_id, &resp_headers, file_data) catch {};
            },
            .settings, .data, .finished, .goaway, .connect_request => {},
        }
    }
}

fn pollH0Server(h0c: *h0.H0Connection, www_dir: []const u8) void {
    while (true) {
        const event = h0c.poll() catch break;
        if (event == null) break;

        switch (event.?) {
            .request => |req| {
                std.log.info("H0: request for {s} on stream {d}", .{ req.path, req.stream_id });
                h0c.serveFile(req.stream_id, www_dir, req.path) catch |err| {
                    std.log.err("H0: serveFile error: {any}", .{err});
                };
            },
            .data, .finished => {},
        }
    }
}

fn readFileFromWww(alloc: std.mem.Allocator, www_dir: []const u8, path: []const u8) ![]u8 {
    var clean_path = path;
    while (clean_path.len > 0 and clean_path[0] == '/') {
        clean_path = clean_path[1..];
    }
    if (clean_path.len == 0) clean_path = "index.html";

    var full_path_buf: [4096]u8 = undefined;
    var pos: usize = 0;
    @memcpy(full_path_buf[pos..][0..www_dir.len], www_dir);
    pos += www_dir.len;
    if (www_dir.len > 0 and www_dir[www_dir.len - 1] != '/') {
        full_path_buf[pos] = '/';
        pos += 1;
    }
    @memcpy(full_path_buf[pos..][0..clean_path.len], clean_path);
    pos += clean_path.len;

    return std.fs.cwd().readFileAlloc(alloc, full_path_buf[0..pos], 10 * 1024 * 1024);
}

fn loadFile(alloc: std.mem.Allocator, path: []const u8) ![]u8 {
    return std.fs.cwd().readFileAlloc(alloc, path, 65536);
}
