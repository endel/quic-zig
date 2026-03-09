// QUIC Interop Runner - Client Endpoint
//
// Reads environment variables set by the interop runner:
//   TESTCASE      - which test to run (handshake, transfer, retry, etc.)
//   SSLKEYLOGFILE - path to write TLS key log
//   QLOGDIR       - path to write qlog files (not yet implemented)
//   REQUESTS      - space-separated URLs to download (CLI args)
//
// Downloads files via HTTP/0.9 (hq-interop) or HTTP/3 and saves to /downloads/.

const std = @import("std");
const posix = std.posix;
const io = std.io;
const net = std.net;
const mem = std.mem;

const connection = @import("quic/connection.zig");
const quic_crypto = @import("quic/crypto.zig");
const packet = @import("quic/packet.zig");
const protocol = @import("quic/protocol.zig");
const tls13 = @import("quic/tls13.zig");
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
    if (mem.eql(u8, name, "handshake")) return .handshake;
    if (mem.eql(u8, name, "transfer")) return .transfer;
    if (mem.eql(u8, name, "multiconnect")) return .multiconnect;
    if (mem.eql(u8, name, "retry")) return .retry;
    if (mem.eql(u8, name, "resumption")) return .resumption;
    if (mem.eql(u8, name, "zerortt")) return .zerortt;
    if (mem.eql(u8, name, "http3")) return .http3;
    if (mem.eql(u8, name, "keyupdate")) return .keyupdate;
    if (mem.eql(u8, name, "ecn")) return .ecn;
    if (mem.eql(u8, name, "connectionmigration")) return .connectionmigration;
    if (mem.eql(u8, name, "chacha20")) return .chacha20;
    if (mem.eql(u8, name, "v2")) return .v2;
    return .unsupported;
}

/// Parsed URL components.
const ParsedUrl = struct {
    host: []const u8,
    port: u16,
    path: []const u8,
};

fn parseUrl(url: []const u8) ?ParsedUrl {
    // Expected format: https://host:port/path or https://host/path
    var rest = url;
    if (mem.startsWith(u8, rest, "https://")) {
        rest = rest[8..];
    } else if (mem.startsWith(u8, rest, "http://")) {
        rest = rest[7..];
    }

    // Find path separator
    const path_start = mem.indexOf(u8, rest, "/") orelse rest.len;
    const host_port = rest[0..path_start];
    const path = if (path_start < rest.len) rest[path_start..] else "/";

    // Parse host:port
    if (mem.indexOf(u8, host_port, ":")) |colon| {
        const port = std.fmt.parseInt(u16, host_port[colon + 1 ..], 10) catch 443;
        return .{ .host = host_port[0..colon], .port = port, .path = path };
    }
    return .{ .host = host_port, .port = 443, .path = path };
}

fn basename(path: []const u8) []const u8 {
    if (mem.lastIndexOf(u8, path, "/")) |idx| {
        return path[idx + 1 ..];
    }
    return path;
}

pub fn main() !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    // Read environment variables
    const testcase_str = posix.getenv("TESTCASE") orelse "handshake";
    const testcase = parseTestCase(testcase_str);
    const sslkeylogfile_path = posix.getenv("SSLKEYLOGFILE");
    const download_dir = posix.getenv("DOWNLOADS") orelse "/downloads";

    std.log.info("interop client: testcase={s}", .{testcase_str});

    if (testcase == .unsupported) {
        std.log.err("unsupported test case: {s}", .{testcase_str});
        std.process.exit(127);
    }

    // Open SSLKEYLOGFILE if requested
    var keylog_file: ?std.fs.File = null;
    if (sslkeylogfile_path) |path| {
        keylog_file = std.fs.cwd().createFile(path, .{}) catch null;
    }
    defer if (keylog_file) |f| f.close();

    // Parse request URLs from CLI args
    const args = try std.process.argsAlloc(alloc);
    var urls: std.ArrayList(ParsedUrl) = .{ .items = &.{}, .capacity = 0 };
    for (args[1..]) |arg| {
        if (parseUrl(arg)) |url| {
            try urls.append(alloc, url);
        }
    }

    if (urls.items.len == 0) {
        std.log.err("no URLs provided", .{});
        std.process.exit(1);
    }

    const use_h3 = (testcase == .http3);
    const cipher_only: ?quic_crypto.CipherSuite = if (testcase == .chacha20) .chacha20_poly1305_sha256 else null;

    const v2 = (testcase == .v2);
    switch (testcase) {
        .handshake, .transfer, .ecn, .connectionmigration, .chacha20 => {
            _ = try downloadAll(alloc, urls.items, use_h3, keylog_file, download_dir, null, false, cipher_only, false);
        },
        .keyupdate => {
            _ = try downloadAll(alloc, urls.items, use_h3, keylog_file, download_dir, null, true, cipher_only, false);
        },
        .retry => {
            _ = try downloadAll(alloc, urls.items, use_h3, keylog_file, download_dir, null, false, cipher_only, false);
        },
        .multiconnect => {
            for (urls.items) |url| {
                const single = [_]ParsedUrl{url};
                _ = try downloadAll(alloc, &single, use_h3, keylog_file, download_dir, null, false, cipher_only, false);
            }
        },
        .resumption, .zerortt => {
            if (urls.items.len > 0) {
                const first = [_]ParsedUrl{urls.items[0]};
                const ticket = try downloadAll(alloc, &first, use_h3, keylog_file, download_dir, null, false, cipher_only, false);
                if (urls.items.len > 1) {
                    if (ticket) |*t| {
                        std.log.info("resuming with session ticket (lifetime={d}s)", .{t.lifetime});
                        _ = try downloadAll(alloc, urls.items[1..], use_h3, keylog_file, download_dir, t, false, cipher_only, false);
                    } else {
                        std.log.warn("no session ticket received, falling back to full handshake", .{});
                        _ = try downloadAll(alloc, urls.items[1..], use_h3, keylog_file, download_dir, null, false, cipher_only, false);
                    }
                }
            }
        },
        .v2 => {
            _ = try downloadAll(alloc, urls.items, use_h3, keylog_file, download_dir, null, false, cipher_only, v2);
        },
        .http3 => {
            _ = try downloadAll(alloc, urls.items, true, keylog_file, download_dir, null, false, cipher_only, false);
        },
        .unsupported => unreachable,
    }

    std.log.info("interop client: all downloads complete", .{});
}

fn downloadAll(
    alloc: std.mem.Allocator,
    urls: []const ParsedUrl,
    use_h3: bool,
    keylog_file: ?std.fs.File,
    download_dir: []const u8,
    session_ticket: ?*const tls13.SessionTicket,
    force_key_update: bool,
    cipher_suite_only: ?quic_crypto.CipherSuite,
    enable_v2: bool,
) !?tls13.SessionTicket {
    if (urls.len == 0) return null;

    const host = urls[0].host;
    const port = urls[0].port;

    // Resolve server address (supports hostnames via DNS)
    const server_addr = blk: {
        // Try numeric IP first
        break :blk net.Address.resolveIp(host, port) catch {
            // Fall back to DNS resolution
            const list = net.getAddressList(alloc, host, port) catch |err| {
                std.log.err("failed to resolve {s}:{d}: {any}", .{ host, port, err });
                return err;
            };
            defer list.deinit();
            if (list.addrs.len == 0) {
                std.log.err("no addresses for {s}:{d}", .{ host, port });
                return error.UnknownHostName;
            }
            break :blk list.addrs[0];
        };
    };

    const sockfd = try posix.socket(posix.AF.INET, posix.SOCK.DGRAM | posix.SOCK.NONBLOCK, 0);
    defer posix.close(sockfd);

    const local_addr = try net.Address.parseIp4("0.0.0.0", 0);
    try posix.bind(sockfd, &local_addr.any, local_addr.getOsSockLen());
    ecn_socket.enableEcnRecv(sockfd) catch {};

    // Build TLS config
    const alpn = try alloc.alloc([]const u8, 1);
    alpn[0] = if (use_h3) "h3" else "hq-interop";

    const tls_config: tls13.TlsConfig = .{
        .cert_chain_der = &.{},
        .private_key_bytes = &.{},
        .alpn = alpn,
        .server_name = host,
        .skip_cert_verify = true,
        .keylog_file = keylog_file,
        .session_ticket = session_ticket,
        .cipher_suite_only = cipher_suite_only,
    };

    var conn = try connection.connect(alloc, host, .{ .enable_v2 = enable_v2 }, tls_config, null);

    var remote_addr = server_addr.any;
    var addr_size: posix.socklen_t = server_addr.getOsSockLen();
    var out: [MAX_DATAGRAM_SIZE]u8 = undefined;

    // Handshake phase
    var handshake_complete = false;
    var iteration: usize = 0;
    const max_iterations: usize = 2000;

    while (!handshake_complete and iteration < max_iterations) : (iteration += 1) {
        std.Thread.sleep(1 * std.time.ns_per_ms);

        const bytes_written = conn.send(&out) catch break;
        if (bytes_written > 0) {
            ecn_socket.setEcnMark(sockfd, conn.getEcnMark()) catch {};
            _ = posix.sendto(sockfd, out[0..bytes_written], 0, &remote_addr, addr_size) catch continue;
        }

        // Read response packets
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
                const full_packet_size = fbs.pos - packet_start_pos + header.remainder_len;

                conn.recv(&header, &fbs, .{
                    .to = local_addr.any,
                    .from = remote_addr,
                    .ecn = recv_result.ecn,
                }) catch break;

                const expected_next_pos = packet_start_pos + full_packet_size;
                if (fbs.pos < expected_next_pos) fbs.pos = expected_next_pos;
            }

            if (conn.state == .connected) handshake_complete = true;
        }
    }

    if (!handshake_complete) {
        std.log.err("handshake failed after {d} iterations", .{iteration});
        std.process.exit(1);
    }

    std.log.info("handshake complete", .{});

    // Send pending handshake packets
    const hs_bytes = conn.send(&out) catch 0;
    if (hs_bytes > 0) {
        ecn_socket.setEcnMark(sockfd, conn.getEcnMark()) catch {};
        _ = posix.sendto(sockfd, out[0..hs_bytes], 0, &remote_addr, addr_size) catch {};
    }

    // Sync remote_addr from active path
    remote_addr = conn.paths[conn.active_path_idx].peer_addr;

    // Clear Initial and Handshake keys
    conn.pkt_num_spaces[0].crypto_open = null;
    conn.pkt_num_spaces[0].crypto_seal = null;
    conn.pkt_num_spaces[1].crypto_open = null;
    conn.pkt_num_spaces[1].crypto_seal = null;

    std.Thread.sleep(50 * std.time.ns_per_ms);

    if (use_h3) {
        try downloadH3(alloc, &conn, sockfd, &remote_addr, addr_size, local_addr, urls, download_dir, force_key_update);
    } else {
        try downloadH0(alloc, &conn, sockfd, &remote_addr, addr_size, local_addr, urls, download_dir, force_key_update);
    }

    // Wait briefly for NewSessionTicket if we don't have one yet
    if (conn.session_ticket == null) {
        var ticket_iter: usize = 0;
        while (conn.session_ticket == null and ticket_iter < 100) : (ticket_iter += 1) {
            std.Thread.sleep(5 * std.time.ns_per_ms);
            drainRecv(&conn, sockfd, local_addr, &remote_addr, &addr_size);
            const more = conn.send(&out) catch 0;
            if (more > 0) {
                _ = posix.sendto(sockfd, out[0..more], 0, &remote_addr, addr_size) catch {};
            }
        }
    }

    // Capture session ticket before closing
    const result_ticket = conn.session_ticket;

    // Close connection
    conn.close(0, "done");
    const final_bytes = conn.send(&out) catch 0;
    if (final_bytes > 0) {
        _ = posix.sendto(sockfd, out[0..final_bytes], 0, &remote_addr, addr_size) catch {};
    }

    // Drain
    var drain_iter: usize = 0;
    while (!conn.isClosed() and drain_iter < 50) : (drain_iter += 1) {
        std.Thread.sleep(10 * std.time.ns_per_ms);
        conn.onTimeout() catch break;
        drainRecv(&conn, sockfd, local_addr, &remote_addr, &addr_size);
        const retransmit_bytes = conn.send(&out) catch 0;
        if (retransmit_bytes > 0) {
            _ = posix.sendto(sockfd, out[0..retransmit_bytes], 0, &remote_addr, addr_size) catch {};
        }
    }

    return result_ticket;
}

fn downloadH0(
    alloc: std.mem.Allocator,
    conn: *connection.Connection,
    sockfd: posix.fd_t,
    remote_addr: *posix.sockaddr,
    addr_size: posix.socklen_t,
    local_addr: net.Address,
    urls: []const ParsedUrl,
    download_dir: []const u8,
    force_key_update: bool,
) !void {
    var h0c = h0.H0Connection.init(alloc, conn, false);
    defer h0c.deinit();

    // Track downloads: stream_id -> file data accumulator
    var downloads = std.AutoHashMap(u64, std.ArrayList(u8)).init(alloc);
    defer {
        var it = downloads.iterator();
        while (it.next()) |entry| {
            entry.value_ptr.deinit(alloc);
        }
        downloads.deinit();
    }

    // Stream ID to URL path mapping
    var stream_paths = std.AutoHashMap(u64, []const u8).init(alloc);
    defer stream_paths.deinit();

    // Send all requests
    for (urls) |url| {
        const stream_id = h0c.sendRequest(url.path) catch |err| {
            std.log.err("H0: sendRequest error for {s}: {any}", .{ url.path, err });
            continue;
        };
        try downloads.put(stream_id, std.ArrayList(u8){ .items = &.{}, .capacity = 0 });
        try stream_paths.put(stream_id, url.path);
        std.log.info("H0: requested {s} on stream {d}", .{ url.path, stream_id });
    }

    // Flush
    var out: [MAX_DATAGRAM_SIZE]u8 = undefined;
    var flush_count: usize = 0;
    while (flush_count < 10) : (flush_count += 1) {
        const more = conn.send(&out) catch break;
        if (more == 0) break;
        ecn_socket.setEcnMark(sockfd, conn.getEcnMark()) catch {};
        _ = posix.sendto(sockfd, out[0..more], 0, remote_addr, addr_size) catch break;
    }

    // Read responses
    var completed: usize = 0;
    var resp_iter: usize = 0;
    const max_resp_iters: usize = 5000;
    var total_bytes_received: usize = 0;
    var key_update_done = false;

    while (completed < urls.len and resp_iter < max_resp_iters) : (resp_iter += 1) {
        std.Thread.sleep(1 * std.time.ns_per_ms);

        // Read packets
        while (true) {
            var bytes: [8192]u8 = undefined;
            const recv_result = ecn_socket.recvmsgEcn(sockfd, &bytes) catch break;
            var fbs = io.fixedBufferStream(bytes[0..recv_result.bytes_read]);
            while (fbs.pos < recv_result.bytes_read) {
                if (bytes[fbs.pos] & 0x40 == 0) break;
                const pkt_start = fbs.pos;
                var header = packet.Header.parse(&fbs, conn.scid_len) catch break;
                const full_size = fbs.pos - pkt_start + header.remainder_len;
                conn.recv(&header, &fbs, .{
                    .to = local_addr.any,
                    .from = recv_result.from_addr,
                    .ecn = recv_result.ecn,
                }) catch break;
                const next_pos = pkt_start + full_size;
                if (fbs.pos < next_pos) fbs.pos = next_pos;
            }
        }

        // Force key update early in the connection for keyupdate test
        if (force_key_update and !key_update_done and total_bytes_received > 0) {
            if (conn.key_update) |*ku| {
                if (ku.canUpdate()) {
                    const now = @as(i64, @intCast(std.time.nanoTimestamp()));
                    const pto_ns = conn.pkt_handler.rtt_stats.pto();
                    ku.rollKeys(now, pto_ns);
                    conn.packer.key_phase = ku.key_phase;
                    key_update_done = true;
                    std.log.info("key update: forced for interop test, new key_phase={}", .{ku.key_phase});
                }
            }
        }

        // Send ACKs
        const ack_bytes = conn.send(&out) catch continue;
        if (ack_bytes > 0) {
            ecn_socket.setEcnMark(sockfd, conn.getEcnMark()) catch {};
            _ = posix.sendto(sockfd, out[0..ack_bytes], 0, remote_addr, addr_size) catch {};
        }

        // Poll H0 events
        while (true) {
            const event = h0c.poll() catch break;
            if (event == null) break;

            switch (event.?) {
                .data => |d| {
                    if (downloads.getPtr(d.stream_id)) |buf| {
                        buf.appendSlice(alloc, d.data) catch {};
                        total_bytes_received += d.data.len;
                    }
                },
                .finished => |stream_id| {
                    completed += 1;
                    std.log.info("H0: stream {d} finished ({d}/{d})", .{ stream_id, completed, urls.len });
                    // Save file
                    if (stream_paths.get(stream_id)) |path| {
                        if (downloads.get(stream_id)) |buf| {
                            saveFile(download_dir, basename(path), buf.items) catch |err| {
                                std.log.err("failed to save {s}: {any}", .{ path, err });
                            };
                        }
                    }
                },
                .request => {},
            }
        }
    }
}

fn downloadH3(
    alloc: std.mem.Allocator,
    conn: *connection.Connection,
    sockfd: posix.fd_t,
    remote_addr: *posix.sockaddr,
    addr_size: posix.socklen_t,
    local_addr: net.Address,
    urls: []const ParsedUrl,
    download_dir: []const u8,
    force_key_update: bool,
) !void {
    var h3c = h3.H3Connection.init(alloc, conn, false);
    defer h3c.deinit();
    try h3c.initConnection();

    // Track downloads
    var downloads = std.AutoHashMap(u64, std.ArrayList(u8)).init(alloc);
    defer {
        var it = downloads.iterator();
        while (it.next()) |entry| {
            entry.value_ptr.deinit(alloc);
        }
        downloads.deinit();
    }
    var stream_paths = std.AutoHashMap(u64, []const u8).init(alloc);
    defer stream_paths.deinit();

    // Send all requests
    for (urls) |url| {
        const req_headers = [_]qpack.Header{
            .{ .name = ":method", .value = "GET" },
            .{ .name = ":scheme", .value = "https" },
            .{ .name = ":authority", .value = url.host },
            .{ .name = ":path", .value = url.path },
        };
        const stream_id = h3c.sendRequest(&req_headers, null) catch |err| {
            std.log.err("H3: sendRequest error for {s}: {any}", .{ url.path, err });
            continue;
        };
        try downloads.put(stream_id, std.ArrayList(u8){ .items = &.{}, .capacity = 0 });
        try stream_paths.put(stream_id, url.path);
        std.log.info("H3: requested {s} on stream {d}", .{ url.path, stream_id });
    }

    // Flush
    var out: [MAX_DATAGRAM_SIZE]u8 = undefined;
    var flush_count: usize = 0;
    while (flush_count < 10) : (flush_count += 1) {
        const more = conn.send(&out) catch break;
        if (more == 0) break;
        ecn_socket.setEcnMark(sockfd, conn.getEcnMark()) catch {};
        _ = posix.sendto(sockfd, out[0..more], 0, remote_addr, addr_size) catch break;
    }

    // Read responses
    var completed: usize = 0;
    var resp_iter: usize = 0;
    const max_resp_iters: usize = 5000;
    var total_bytes_received: usize = 0;
    var key_update_done = false;

    while (completed < urls.len and resp_iter < max_resp_iters) : (resp_iter += 1) {
        std.Thread.sleep(1 * std.time.ns_per_ms);

        // Read packets
        while (true) {
            var bytes: [8192]u8 = undefined;
            const recv_result = ecn_socket.recvmsgEcn(sockfd, &bytes) catch break;
            var fbs = io.fixedBufferStream(bytes[0..recv_result.bytes_read]);
            while (fbs.pos < recv_result.bytes_read) {
                if (bytes[fbs.pos] & 0x40 == 0) break;
                const pkt_start = fbs.pos;
                var header = packet.Header.parse(&fbs, conn.scid_len) catch break;
                const full_size = fbs.pos - pkt_start + header.remainder_len;
                conn.recv(&header, &fbs, .{
                    .to = local_addr.any,
                    .from = recv_result.from_addr,
                    .ecn = recv_result.ecn,
                }) catch break;
                const next_pos = pkt_start + full_size;
                if (fbs.pos < next_pos) fbs.pos = next_pos;
            }
        }

        // Force key update early in the connection for keyupdate test
        if (force_key_update and !key_update_done and total_bytes_received > 0) {
            if (conn.key_update) |*ku| {
                if (ku.canUpdate()) {
                    const now = @as(i64, @intCast(std.time.nanoTimestamp()));
                    const pto_ns = conn.pkt_handler.rtt_stats.pto();
                    ku.rollKeys(now, pto_ns);
                    conn.packer.key_phase = ku.key_phase;
                    key_update_done = true;
                    std.log.info("key update: forced for interop test, new key_phase={}", .{ku.key_phase});
                }
            }
        }

        // Send ACKs
        const ack_bytes = conn.send(&out) catch continue;
        if (ack_bytes > 0) {
            ecn_socket.setEcnMark(sockfd, conn.getEcnMark()) catch {};
            _ = posix.sendto(sockfd, out[0..ack_bytes], 0, remote_addr, addr_size) catch {};
        }

        // Poll H3 events
        while (true) {
            const event = h3c.poll() catch break;
            if (event == null) break;

            switch (event.?) {
                .data => |d| {
                    if (downloads.getPtr(d.stream_id)) |buf| {
                        buf.appendSlice(alloc, d.data) catch {};
                        total_bytes_received += d.data.len;
                    }
                },
                .finished => |stream_id| {
                    completed += 1;
                    std.log.info("H3: stream {d} finished ({d}/{d})", .{ stream_id, completed, urls.len });
                    if (stream_paths.get(stream_id)) |path| {
                        if (downloads.get(stream_id)) |buf| {
                            saveFile(download_dir, basename(path), buf.items) catch |err| {
                                std.log.err("failed to save {s}: {any}", .{ path, err });
                            };
                        }
                    }
                },
                .headers => |hdr| {
                    std.log.info("H3: response headers on stream {d}", .{hdr.stream_id});
                },
                .settings, .goaway, .connect_request => {},
            }
        }
    }
}

fn saveFile(dir: []const u8, filename: []const u8, data: []const u8) !void {
    var path_buf: [4096]u8 = undefined;
    var pos: usize = 0;
    @memcpy(path_buf[pos..][0..dir.len], dir);
    pos += dir.len;
    if (dir.len > 0 and dir[dir.len - 1] != '/') {
        path_buf[pos] = '/';
        pos += 1;
    }
    @memcpy(path_buf[pos..][0..filename.len], filename);
    pos += filename.len;

    const path = path_buf[0..pos];
    const file = try std.fs.cwd().createFile(path, .{});
    defer file.close();
    try file.writeAll(data);
    std.log.info("saved {s} ({d} bytes)", .{ path, data.len });
}

fn drainRecv(
    conn: *connection.Connection,
    sockfd: posix.fd_t,
    local_addr: net.Address,
    remote_addr: *posix.sockaddr,
    addr_size: *posix.socklen_t,
) void {
    while (true) {
        var bytes: [8192]u8 = undefined;
        const recv_result = ecn_socket.recvmsgEcn(sockfd, &bytes) catch break;
        remote_addr.* = recv_result.from_addr;
        addr_size.* = recv_result.addr_len;

        var fbs = io.fixedBufferStream(bytes[0..recv_result.bytes_read]);
        while (fbs.pos < recv_result.bytes_read) {
            if (bytes[fbs.pos] & 0x40 == 0) break;
            const pkt_start = fbs.pos;
            var header = packet.Header.parse(&fbs, conn.scid_len) catch break;
            const full_size = fbs.pos - pkt_start + header.remainder_len;
            conn.recv(&header, &fbs, .{
                .to = local_addr.any,
                .from = recv_result.from_addr,
                .ecn = recv_result.ecn,
            }) catch break;
            const next_pos = pkt_start + full_size;
            if (fbs.pos < next_pos) fbs.pos = next_pos;
        }
    }
}
