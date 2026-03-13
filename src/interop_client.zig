// QUIC Interop Runner - Client Endpoint
//
// Reads environment variables set by the interop runner:
//   TESTCASE      - which test to run (handshake, transfer, retry, etc.)
//   SSLKEYLOGFILE - path to write TLS key log
//   QLOGDIR       - path to write qlog files (.sqlog JSON-SEQ format)
//   REQUESTS      - space-separated URLs to download (CLI args)
//
// Downloads files via HTTP/0.9 (hq-interop) or HTTP/3 and saves to /downloads/.

const std = @import("std");
const posix = std.posix;
const net = std.net;
const mem = std.mem;

const connection = @import("quic/connection.zig");
const quic_crypto = @import("quic/crypto.zig");
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
    longrtt,
    multiplexing,
    blackhole,
    handshakeloss,
    transferloss,
    handshakecorruption,
    transfercorruption,
    amplificationlimit,
    ipv6,
    versionnegotiation,
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
    if (mem.eql(u8, name, "longrtt")) return .longrtt;
    if (mem.eql(u8, name, "multiplexing")) return .multiplexing;
    if (mem.eql(u8, name, "blackhole")) return .blackhole;
    if (mem.eql(u8, name, "handshakeloss")) return .handshakeloss;
    if (mem.eql(u8, name, "transferloss")) return .transferloss;
    if (mem.eql(u8, name, "handshakecorruption")) return .handshakecorruption;
    if (mem.eql(u8, name, "transfercorruption")) return .transfercorruption;
    if (mem.eql(u8, name, "amplificationlimit")) return .amplificationlimit;
    if (mem.eql(u8, name, "ipv6")) return .ipv6;
    if (mem.eql(u8, name, "versionnegotiation")) return .versionnegotiation;
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
    const qlog_dir = posix.getenv("QLOGDIR");
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
        .handshake,
        .transfer,
        .ecn,
        .chacha20,
        .longrtt,
        .blackhole,
        .transferloss,
        .transfercorruption,
        .amplificationlimit,
        .ipv6,
        .versionnegotiation,
        => {
            _ = try downloadAll(alloc, urls.items, use_h3, keylog_file, download_dir, null, false, cipher_only, false, false, false, qlog_dir, false);
        },
        .connectionmigration => {
            _ = try downloadAll(alloc, urls.items, use_h3, keylog_file, download_dir, null, false, cipher_only, false, false, false, qlog_dir, true);
        },
        .multiplexing => {
            _ = try downloadAll(alloc, urls.items, use_h3, keylog_file, download_dir, null, false, cipher_only, false, false, false, qlog_dir, false);
        },
        .keyupdate => {
            _ = try downloadAll(alloc, urls.items, use_h3, keylog_file, download_dir, null, true, cipher_only, false, false, false, qlog_dir, false);
        },
        .retry => {
            _ = try downloadAll(alloc, urls.items, use_h3, keylog_file, download_dir, null, false, cipher_only, false, false, false, qlog_dir, false);
        },
        .multiconnect, .handshakeloss, .handshakecorruption => {
            for (urls.items) |url| {
                const single = [_]ParsedUrl{url};
                _ = try downloadAll(alloc, &single, use_h3, keylog_file, download_dir, null, false, cipher_only, false, false, true, qlog_dir, false);
            }
        },
        .resumption => {
            if (urls.items.len > 0) {
                const first = [_]ParsedUrl{urls.items[0]};
                const ticket = try downloadAll(alloc, &first, use_h3, keylog_file, download_dir, null, false, cipher_only, false, false, false, qlog_dir, false);
                if (urls.items.len > 1) {
                    if (ticket) |*t| {
                        std.log.info("resuming with session ticket (lifetime={d}s)", .{t.lifetime});
                        _ = try downloadAll(alloc, urls.items[1..], use_h3, keylog_file, download_dir, t, false, cipher_only, false, false, false, qlog_dir, false);
                    } else {
                        std.log.warn("no session ticket received, falling back to full handshake", .{});
                        _ = try downloadAll(alloc, urls.items[1..], use_h3, keylog_file, download_dir, null, false, cipher_only, false, false, false, qlog_dir, false);
                    }
                }
            }
        },
        .zerortt => {
            if (urls.items.len > 0) {
                const first = [_]ParsedUrl{urls.items[0]};
                const ticket = try downloadAll(alloc, &first, use_h3, keylog_file, download_dir, null, false, cipher_only, false, false, false, qlog_dir, false);
                if (urls.items.len > 1) {
                    if (ticket) |*t| {
                        std.log.info("resuming with 0-RTT (lifetime={d}s)", .{t.lifetime});
                        _ = try downloadAll(alloc, urls.items[1..], use_h3, keylog_file, download_dir, t, false, cipher_only, false, true, false, qlog_dir, false);
                    } else {
                        std.log.warn("no session ticket received, falling back to full handshake", .{});
                        _ = try downloadAll(alloc, urls.items[1..], use_h3, keylog_file, download_dir, null, false, cipher_only, false, false, false, qlog_dir, false);
                    }
                }
            }
        },
        .v2 => {
            _ = try downloadAll(alloc, urls.items, use_h3, keylog_file, download_dir, null, false, cipher_only, v2, false, false, qlog_dir, false);
        },
        .http3 => {
            _ = try downloadAll(alloc, urls.items, true, keylog_file, download_dir, null, false, cipher_only, false, false, false, qlog_dir, false);
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
    allow_0rtt: bool,
    skip_ticket_and_drain: bool,
    qlog_dir_param: ?[]const u8,
    do_migration: bool,
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

    // Always create IPv6 dual-stack socket to support preferred_address migration across families.
    // If the initial server address is IPv4, sendto converts it to IPv4-mapped IPv6 automatically.
    const sockfd = try posix.socket(posix.AF.INET6, posix.SOCK.DGRAM | posix.SOCK.NONBLOCK, 0);
    defer posix.close(sockfd);
    // Disable IPV6_V6ONLY to allow dual-stack (IPv4 and IPv6 on same socket)
    const IPV6_V6ONLY: u32 = if (@import("builtin").os.tag == .linux) 26 else 27;
    const zero: c_int = 0;
    posix.setsockopt(sockfd, posix.IPPROTO.IPV6, IPV6_V6ONLY, std.mem.asBytes(&zero)) catch {};

    const local_addr = try net.Address.parseIp6("::", 0);
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

    var conn = try connection.connect(alloc, host, .{ .enable_v2 = enable_v2, .disable_pmtud = true, .qlog_dir = qlog_dir_param }, tls_config, null);
    defer conn.deinit();

    var remote_addr = connection.sockaddrToStorage(&server_addr.any);
    // Convert IPv4 to IPv4-mapped IPv6 for dual-stack socket compatibility
    mapV4ToV6(&remote_addr);
    var addr_size: posix.socklen_t = connection.sockaddrLen(&remote_addr);
    var out: [MAX_DATAGRAM_SIZE]u8 = undefined;

    // Send 0-RTT early data if we have a session ticket (before handshake completes)
    var early_data_sent = false;
    if (allow_0rtt and session_ticket != null and conn.early_data_seal != null and !use_h3) {
        // Open streams and send requests as 0-RTT data
        for (urls) |url| {
            const s = conn.openStream() catch break;
            const req = std.fmt.allocPrint(alloc, "GET {s}\r\n", .{url.path}) catch break;
            s.send.writeData(req) catch break;
            s.send.close();
            std.log.info("0-RTT: sent early request for {s} on stream {d}", .{ url.path, s.stream_id });
        }
        early_data_sent = true;
    }

    // Handshake phase — shorter timeout for multiconnect (many sequential connections)
    var handshake_complete = false;
    const handshake_start = std.time.nanoTimestamp();
    const handshake_timeout_ns: i128 = if (skip_ticket_and_drain) 10 * std.time.ns_per_s else 120 * std.time.ns_per_s;

    while (!handshake_complete and (std.time.nanoTimestamp() - handshake_start) < handshake_timeout_ns) {
        // Fire PTO timer for handshake retransmissions
        conn.onTimeout() catch {};

        // Send packets (burst up to 10 to handle coalesced Initial+Handshake)
        var sent_any = false;
        {
            var sc: usize = 0;
            while (sc < 10) : (sc += 1) {
                const bytes_written = conn.send(&out) catch break;
                if (bytes_written == 0) break;
                ecn_socket.setEcnMark(sockfd, conn.getEcnMark()) catch {};
                _ = posix.sendto(sockfd, out[0..bytes_written], 0, @ptrCast(&remote_addr), addr_size) catch {};
                sent_any = true;
            }
        }

        // Read response packets
        var received_any = false;
        while (true) {
            var bytes: [8192]u8 = undefined;
            const recv_result = ecn_socket.recvmsgEcn(sockfd, &bytes) catch break;
            received_any = true;
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

        // Only sleep when idle (nothing to send or receive)
        if (!sent_any and !received_any) std.Thread.sleep(1 * std.time.ns_per_ms);
    }

    if (!handshake_complete) {
        const elapsed_ms = @divTrunc(std.time.nanoTimestamp() - handshake_start, std.time.ns_per_ms);
        std.log.err("handshake failed after {d}ms", .{elapsed_ms});
        std.process.exit(1);
    }

    std.log.info("handshake complete", .{});

    // Send pending handshake packets
    const hs_bytes = conn.send(&out) catch 0;
    if (hs_bytes > 0) {
        ecn_socket.setEcnMark(sockfd, conn.getEcnMark()) catch {};
        _ = posix.sendto(sockfd, out[0..hs_bytes], 0, @ptrCast(&remote_addr), addr_size) catch {};
    }

    // Sync remote_addr from active path (may have changed due to preferred_address migration)
    remote_addr = conn.peerAddress().*;
    mapV4ToV6(&remote_addr);
    addr_size = connection.sockaddrLen(&remote_addr);

    if (use_h3) {
        try downloadH3(alloc, &conn, sockfd, &remote_addr, addr_size, local_addr, urls, download_dir, force_key_update);
    } else {
        try downloadH0(alloc, &conn, sockfd, &remote_addr, &addr_size, local_addr, urls, download_dir, force_key_update, early_data_sent, do_migration, skip_ticket_and_drain);
    }

    // Wait for NewSessionTicket if we don't have one yet.
    if (!skip_ticket_and_drain and conn.session_ticket == null) {
        var ticket_iter: usize = 0;
        while (conn.session_ticket == null and ticket_iter < 100) : (ticket_iter += 1) {
            std.Thread.sleep(5 * std.time.ns_per_ms);
            drainRecv(&conn, sockfd, local_addr, &remote_addr, &addr_size);
            const more = conn.send(&out) catch 0;
            if (more > 0) {
                _ = posix.sendto(sockfd, out[0..more], 0, @ptrCast(&remote_addr), addr_size) catch {};
            }
        }
    }

    // Capture session ticket before closing
    const result_ticket = conn.session_ticket;

    // Close connection
    conn.close(0, "done");
    const final_bytes = conn.send(&out) catch 0;
    if (final_bytes > 0) {
        _ = posix.sendto(sockfd, out[0..final_bytes], 0, @ptrCast(&remote_addr), addr_size) catch {};
    }

    if (!skip_ticket_and_drain) {
        // Drain — brief drain to send CONNECTION_CLOSE, don't wait for full 3×PTO
        var drain_iter: usize = 0;
        while (!conn.isClosed() and drain_iter < 10) : (drain_iter += 1) {
            std.Thread.sleep(5 * std.time.ns_per_ms);
            conn.onTimeout() catch break;
            drainRecv(&conn, sockfd, local_addr, &remote_addr, &addr_size);
            const retransmit_bytes = conn.send(&out) catch 0;
            if (retransmit_bytes > 0) {
                _ = posix.sendto(sockfd, out[0..retransmit_bytes], 0, @ptrCast(&remote_addr), addr_size) catch {};
            }
        }
    }

    return result_ticket;
}

fn downloadH0(
    alloc: std.mem.Allocator,
    conn: *connection.Connection,
    sockfd_param: posix.fd_t,
    remote_addr: *posix.sockaddr.storage,
    addr_size_ptr: *posix.socklen_t,
    local_addr: net.Address,
    urls: []const ParsedUrl,
    download_dir: []const u8,
    force_key_update: bool,
    requests_already_sent: bool,
    do_migration: bool,
    quick_mode: bool,
) !void {
    var sockfd = sockfd_param;
    var migrated_sockfd: ?posix.fd_t = null;
    defer if (migrated_sockfd) |fd| posix.close(fd);
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

    // Track how many URLs have been opened as streams
    var next_url_idx: usize = 0;

    if (requests_already_sent) {
        // 0-RTT: streams were already opened before handshake; register them for tracking
        for (urls, 0..) |url, idx| {
            const stream_id: u64 = @intCast(idx * 4); // client bidi stream IDs: 0, 4, 8, ...
            try downloads.put(stream_id, std.ArrayList(u8){ .items = &.{}, .capacity = 0 });
            try stream_paths.put(stream_id, url.path);
            std.log.info("H0: tracking 0-RTT stream {d} for {s}", .{ stream_id, url.path });
        }
        next_url_idx = urls.len;
    } else {
        // Open streams up to the server's stream limit
        while (next_url_idx < urls.len) {
            const url = urls[next_url_idx];
            const stream_id = h0c.sendRequest(url.path) catch break; // break on limit
            try downloads.put(stream_id, std.ArrayList(u8){ .items = &.{}, .capacity = 0 });
            try stream_paths.put(stream_id, url.path);
            next_url_idx += 1;
        }
    }

    // Flush
    var out: [MAX_DATAGRAM_SIZE]u8 = undefined;
    {
        var flush_count: usize = 0;
        while (flush_count < 10) : (flush_count += 1) {
            const more = conn.send(&out) catch break;
            if (more == 0) break;
            ecn_socket.setEcnMark(sockfd, conn.getEcnMark()) catch {};
            _ = posix.sendto(sockfd, out[0..more], 0, @ptrCast(remote_addr), addr_size_ptr.*) catch break;
        }
    }

    // Read responses — shorter timeout for multiconnect (many sequential connections)
    var completed: usize = 0;
    var total_bytes_received: usize = 0;
    var key_update_done = false;
    var migration_done = false;
    var h0_last_progress: usize = 0;
    const download_start = std.time.nanoTimestamp();
    const download_timeout_ns: i128 = if (quick_mode) 10 * std.time.ns_per_s else 120 * std.time.ns_per_s;

    while (completed < urls.len and (std.time.nanoTimestamp() - download_start) < download_timeout_ns) {
        // Exit early if connection is dead
        if (conn.isClosed() or conn.isDraining()) {
            std.log.warn("H0: connection terminated during download, completed {d}/{d}", .{ completed, urls.len });
            break;
        }

        // Try to open more streams as the limit increases (MAX_STREAMS from server)
        while (next_url_idx < urls.len) {
            const url = urls[next_url_idx];
            const stream_id = h0c.sendRequest(url.path) catch break; // break on limit
            downloads.put(stream_id, std.ArrayList(u8){ .items = &.{}, .capacity = 0 }) catch break;
            stream_paths.put(stream_id, url.path) catch break;
            next_url_idx += 1;
        }

        // Read packets (batch up to 100 datagrams per loop)
        var packets_received: usize = 0;
        {
            var rb: usize = 0;
            while (rb < 100) : (rb += 1) {
                var bytes: [MAX_DATAGRAM_SIZE]u8 = undefined;
                const recv_result = ecn_socket.recvmsgEcn(sockfd, &bytes) catch break;
                packets_received += 1;
                conn.handleDatagram(bytes[0..recv_result.bytes_read], .{
                    .to = connection.sockaddrToStorage(&local_addr.any),
                    .from = recv_result.from_addr,
                    .ecn = recv_result.ecn,
                    .datagram_size = recv_result.bytes_read,
                });
            }
        }
        if (packets_received == 0) std.Thread.sleep(1 * std.time.ns_per_ms);

        // Connection migration: rebind to a new port after receiving some data
        if (do_migration and !migration_done and total_bytes_received > 100 * 1024) {
            // Switch DCID before migrating (RFC 9000 §9.5)
            if (conn.initiateClientMigration()) {
                // Create a new socket bound to a different port
                const new_sockfd = posix.socket(posix.AF.INET6, posix.SOCK.DGRAM | posix.SOCK.NONBLOCK, 0) catch null;
                if (new_sockfd) |nfd| {
                    const IPV6_V6ONLY: u32 = if (@import("builtin").os.tag == .linux) 26 else 27;
                    const zero: c_int = 0;
                    posix.setsockopt(nfd, posix.IPPROTO.IPV6, IPV6_V6ONLY, std.mem.asBytes(&zero)) catch {};
                    const new_local = net.Address.parseIp6("::", 0) catch unreachable;
                    posix.bind(nfd, &new_local.any, new_local.getOsSockLen()) catch {
                        posix.close(nfd);
                    };
                    ecn_socket.enableEcnRecv(nfd) catch {};
                    migrated_sockfd = nfd;
                    sockfd = nfd;
                    migration_done = true;
                    std.log.info("connection migration: rebound to new socket", .{});
                }
            }
        }

        // Force key update after receiving some data (not too early, so in-flight
        // old-key packets don't confuse tshark's QUIC decryption)
        if (force_key_update and !key_update_done and total_bytes_received > 100 * 1024) {
            if (conn.initiateKeyUpdate()) {
                key_update_done = true;
                std.log.info("key update: forced for interop test after {d} bytes", .{total_bytes_received});
            }
        }

        // Fire PTO timer for loss detection and retransmission
        conn.onTimeout() catch {};

        // Burst send ACKs + any queued data (including retransmissions)
        {
            var sc: usize = 0;
            while (sc < 10) : (sc += 1) {
                const ack_bytes = conn.send(&out) catch break;
                if (ack_bytes == 0) break;
                ecn_socket.setEcnMark(sockfd, conn.getEcnMark()) catch {};
                _ = posix.sendto(sockfd, out[0..ack_bytes], 0, @ptrCast(remote_addr), addr_size_ptr.*) catch {};
            }
        }

        // Log progress periodically
        if (total_bytes_received > h0_last_progress + 1_000_000) {
            std.log.info("H0 download progress: {d} bytes received, {d}/{d} complete", .{ total_bytes_received, completed, urls.len });
            h0_last_progress = total_bytes_received;
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

    if (completed < urls.len) {
        std.log.warn("H0: download timeout, completed {d}/{d}", .{ completed, urls.len });
    }
}

fn downloadH3(
    alloc: std.mem.Allocator,
    conn: *connection.Connection,
    sockfd: posix.fd_t,
    remote_addr: *posix.sockaddr.storage,
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
        _ = posix.sendto(sockfd, out[0..more], 0, @ptrCast(remote_addr), addr_size) catch break;
    }

    // Read responses — use time-based timeout (60s)
    var completed: usize = 0;
    var total_bytes_received: usize = 0;
    var key_update_done = false;
    const h3_download_start = std.time.nanoTimestamp();
    const h3_download_timeout_ns: i128 = 120 * std.time.ns_per_s;

    while (completed < urls.len and (std.time.nanoTimestamp() - h3_download_start) < h3_download_timeout_ns) {
        // Exit early if connection is dead
        if (conn.isClosed() or conn.isDraining()) {
            std.log.warn("H3: connection terminated during download, completed {d}/{d}", .{ completed, urls.len });
            break;
        }

        // Read packets (batch up to 100 datagrams per loop)
        var packets_received: usize = 0;
        {
            var rb: usize = 0;
            while (rb < 100) : (rb += 1) {
                var bytes: [MAX_DATAGRAM_SIZE]u8 = undefined;
                const recv_result = ecn_socket.recvmsgEcn(sockfd, &bytes) catch break;
                packets_received += 1;
                conn.handleDatagram(bytes[0..recv_result.bytes_read], .{
                    .to = connection.sockaddrToStorage(&local_addr.any),
                    .from = recv_result.from_addr,
                    .ecn = recv_result.ecn,
                    .datagram_size = recv_result.bytes_read,
                });
            }
        }
        if (packets_received == 0) std.Thread.sleep(1 * std.time.ns_per_ms);

        // Force key update after receiving some data (not too early, so in-flight
        // old-key packets don't confuse tshark's QUIC decryption)
        if (force_key_update and !key_update_done and total_bytes_received > 100 * 1024) {
            if (conn.initiateKeyUpdate()) {
                key_update_done = true;
                std.log.info("key update: forced for interop test after {d} bytes", .{total_bytes_received});
            }
        }

        // Fire PTO timer for loss detection and retransmission
        conn.onTimeout() catch {};

        // Burst send ACKs + any queued data (including retransmissions)
        {
            var sc: usize = 0;
            while (sc < 10) : (sc += 1) {
                const ack_bytes = conn.send(&out) catch break;
                if (ack_bytes == 0) break;
                ecn_socket.setEcnMark(sockfd, conn.getEcnMark()) catch {};
                _ = posix.sendto(sockfd, out[0..ack_bytes], 0, @ptrCast(remote_addr), addr_size) catch {};
            }
        }

        // Poll H3 events
        while (true) {
            const event = h3c.poll() catch break;
            if (event == null) break;

            switch (event.?) {
                .data => |d| {
                    if (downloads.getPtr(d.stream_id)) |dl_buf| {
                        var body_buf: [8192]u8 = undefined;
                        var remaining = d.len;
                        while (remaining > 0) {
                            const n = h3c.recvBody(&body_buf);
                            if (n == 0) break;
                            dl_buf.appendSlice(alloc, body_buf[0..n]) catch {};
                            total_bytes_received += n;
                            remaining -= n;
                        }
                    }
                },
                .finished => |stream_id| {
                    completed += 1;
                    std.log.info("H3: stream {d} finished ({d}/{d})", .{ stream_id, completed, urls.len });
                    if (stream_paths.get(stream_id)) |path| {
                        if (downloads.get(stream_id)) |dl_buf| {
                            saveFile(download_dir, basename(path), dl_buf.items) catch |err| {
                                std.log.err("failed to save {s}: {any}", .{ path, err });
                            };
                        }
                    }
                },
                .headers => |hdr| {
                    std.log.info("H3: response headers on stream {d}", .{hdr.stream_id});
                },
                .settings, .goaway, .connect_request, .shutdown_complete, .request_cancelled => {},
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
    remote_addr: *posix.sockaddr.storage,
    addr_size: *posix.socklen_t,
) void {
    while (true) {
        var bytes: [8192]u8 = undefined;
        const recv_result = ecn_socket.recvmsgEcn(sockfd, &bytes) catch break;
        remote_addr.* = recv_result.from_addr;
        addr_size.* = recv_result.addr_len;
        conn.handleDatagram(bytes[0..recv_result.bytes_read], .{
            .to = connection.sockaddrToStorage(&local_addr.any),
            .from = recv_result.from_addr,
            .ecn = recv_result.ecn,
            .datagram_size = recv_result.bytes_read,
        });
    }
}

const mapV4ToV6 = ecn_socket.mapV4ToV6;
