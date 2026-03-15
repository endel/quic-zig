const std = @import("std");
const posix = std.posix;
const net = std.net;

const quic = @import("quic");
const connection = quic.connection;
const tls13 = quic.tls13;
const ecn_socket = quic.ecn_socket;
const h3 = quic.h3;
const qpack = quic.qpack;

const MAX_DATAGRAM_SIZE: usize = 1500;

const BenchConfig = struct {
    num_connections: u32 = 1,
    requests_per_conn: u32 = 100,
    port: u16 = 4434,
    zerortt: bool = false,
};

const ConnState = struct {
    conn: connection.Connection,
    sockfd: posix.socket_t,
    local_addr: net.Address,
    remote_addr: posix.sockaddr.storage,
    addr_size: posix.socklen_t,
    out: [MAX_DATAGRAM_SIZE]u8 = undefined,
    handshake_start: i64 = 0,
    handshake_end: i64 = 0,
};

fn recvAll(cs: *ConnState) void {
    while (true) {
        var bytes: [8192]u8 = undefined;
        const recv_result = ecn_socket.recvmsgEcn(cs.sockfd, &bytes) catch break;
        cs.remote_addr = recv_result.from_addr;
        cs.addr_size = recv_result.addr_len;
        cs.conn.handleDatagram(bytes[0..recv_result.bytes_read], .{
            .to = connection.sockaddrToStorage(&cs.local_addr.any),
            .from = cs.remote_addr,
            .ecn = recv_result.ecn,
            .datagram_size = recv_result.bytes_read,
        });
    }
}

fn sendAll(cs: *ConnState) void {
    var count: usize = 0;
    while (count < 50) : (count += 1) {
        const n = cs.conn.send(&cs.out) catch break;
        if (n == 0) break;
        ecn_socket.setEcnMark(cs.sockfd, cs.conn.getEcnMark()) catch {};
        _ = posix.sendto(cs.sockfd, cs.out[0..n], 0, @ptrCast(&cs.remote_addr), cs.addr_size) catch break;
    }
}

fn timestamp() i64 {
    return @intCast(std.time.nanoTimestamp());
}

fn doHandshake(cs: *ConnState) bool {
    var iter: usize = 0;
    while (cs.conn.state != .connected and iter < 500) : (iter += 1) {
        cs.conn.onTimeout() catch {};
        sendAll(cs);
        recvAll(cs);
        if (cs.conn.state == .connected) break;
        std.Thread.sleep(200 * std.time.ns_per_us);
    }
    return cs.conn.state == .connected;
}

fn flushPostHandshake(cs: *ConnState) void {
    sendAll(cs);
    std.Thread.sleep(1 * std.time.ns_per_ms);
    recvAll(cs);
    cs.conn.onTimeout() catch {};
    sendAll(cs);
    cs.remote_addr = cs.conn.peerAddress().*;
}

fn doRequests(
    cs: *ConnState,
    h3_conn: *h3.H3Connection,
    count: u32,
    latencies: []i64,
    latency_offset: *u32,
    total_bytes: *u64,
) void {
    var req_idx: u32 = 0;
    while (req_idx < count) : (req_idx += 1) {
        const req_start = timestamp();

        const req_headers = [_]qpack.Header{
            .{ .name = ":method", .value = "GET" },
            .{ .name = ":scheme", .value = "https" },
            .{ .name = ":authority", .value = "localhost" },
            .{ .name = ":path", .value = "/" },
        };
        _ = h3_conn.sendRequest(&req_headers, null) catch break;
        sendAll(cs);

        var got_response = false;
        var wait: usize = 0;
        while (!got_response and wait < 200) : (wait += 1) {
            recvAll(cs);
            cs.conn.onTimeout() catch {};
            sendAll(cs);

            while (true) {
                const event = h3_conn.poll() catch break;
                if (event == null) break;
                switch (event.?) {
                    .data => |d| {
                        var body_buf: [8192]u8 = undefined;
                        while (h3_conn.recvBody(&body_buf) > 0) {}
                        total_bytes.* += d.len;
                    },
                    .finished => {
                        got_response = true;
                    },
                    .headers, .settings => {},
                    else => {},
                }
            }

            if (!got_response) std.Thread.sleep(100 * std.time.ns_per_us);
        }

        if (got_response and latency_offset.* < latencies.len) {
            latencies[latency_offset.*] = timestamp() - req_start;
            latency_offset.* += 1;
        }
    }
}

fn printResults(
    label: []const u8,
    config: BenchConfig,
    latencies: []i64,
    latency_count: u32,
    total_bytes: u64,
    handshake_total_ns: i64,
    handshakes_completed: u32,
    bench_duration_ns: i64,
) void {
    const bench_duration_s: f64 = @as(f64, @floatFromInt(bench_duration_ns)) / 1_000_000_000.0;

    std.debug.print("\n", .{});
    std.debug.print("═══════════════════════════════════════════\n", .{});
    std.debug.print("  {s}\n", .{label});
    std.debug.print("═══════════════════════════════════════════\n", .{});
    std.debug.print("  Connections:    {d}\n", .{config.num_connections});
    std.debug.print("  Requests/conn:  {d}\n", .{config.requests_per_conn});
    std.debug.print("  Total requests: {d} ({d} completed)\n", .{ config.num_connections * config.requests_per_conn, latency_count });
    std.debug.print("  Total time:     {d:.2}s\n", .{bench_duration_s});
    std.debug.print("───────────────────────────────────────────\n", .{});

    if (handshakes_completed > 0) {
        const avg_hs_us: f64 = @as(f64, @floatFromInt(handshake_total_ns)) / @as(f64, @floatFromInt(handshakes_completed)) / 1000.0;
        const hs_per_sec: f64 = @as(f64, @floatFromInt(handshakes_completed)) / bench_duration_s;
        std.debug.print("  Handshake avg:  {d:.0}µs\n", .{avg_hs_us});
        std.debug.print("  Handshakes/s:   {d:.0}\n", .{hs_per_sec});
    }

    if (latency_count > 0) {
        const lc = latency_count;
        std.mem.sort(i64, latencies[0..lc], {}, std.sort.asc(i64));

        const p50 = latencies[lc / 2];
        const p99 = latencies[@min(lc - 1, lc * 99 / 100)];
        const p999 = latencies[@min(lc - 1, lc * 999 / 1000)];

        var sum: i128 = 0;
        for (latencies[0..lc]) |l| sum += l;
        const avg: f64 = @as(f64, @floatFromInt(sum)) / @as(f64, @floatFromInt(lc)) / 1000.0;

        const rps: f64 = @as(f64, @floatFromInt(lc)) / bench_duration_s;
        const throughput_mb: f64 = @as(f64, @floatFromInt(total_bytes)) / bench_duration_s / 1_048_576.0;

        std.debug.print("  Requests/s:     {d:.0}\n", .{rps});
        std.debug.print("  Throughput:     {d:.2} MB/s\n", .{throughput_mb});
        std.debug.print("───────────────────────────────────────────\n", .{});
        std.debug.print("  Latency (µs):\n", .{});
        std.debug.print("    min:   {d:.0}\n", .{@as(f64, @floatFromInt(latencies[0])) / 1000.0});
        std.debug.print("    avg:   {d:.0}\n", .{avg});
        std.debug.print("    p50:   {d:.0}\n", .{@as(f64, @floatFromInt(p50)) / 1000.0});
        std.debug.print("    p99:   {d:.0}\n", .{@as(f64, @floatFromInt(p99)) / 1000.0});
        std.debug.print("    p99.9: {d:.0}\n", .{@as(f64, @floatFromInt(p999)) / 1000.0});
        std.debug.print("    max:   {d:.0}\n", .{@as(f64, @floatFromInt(latencies[lc - 1])) / 1000.0});
    }
    std.debug.print("═══════════════════════════════════════════\n", .{});
}

fn runBench(alloc: std.mem.Allocator, config: BenchConfig) !void {
    const server_addr = try net.Address.parseIp4("127.0.0.1", config.port);

    const alpn = try alloc.alloc([]const u8, 1);
    alpn[0] = "h3";

    var saved_ticket: ?tls13.SessionTicket = null;
    const total_requests = config.num_connections * config.requests_per_conn;
    const all_latencies = try alloc.alloc(i64, total_requests);
    var latency_count: u32 = 0;
    var total_bytes: u64 = 0;
    var handshake_total_ns: i64 = 0;
    var handshakes_completed: u32 = 0;

    // === 0-RTT warmup: get a session ticket ===
    if (config.zerortt) {
        std.debug.print("  0-RTT warmup: establishing session...\n", .{});
        const warmup_tls: tls13.TlsConfig = .{
            .cert_chain_der = &.{},
            .private_key_bytes = &.{},
            .alpn = alpn,
            .server_name = "localhost",
            .skip_cert_verify = true,
        };

        const sockfd = try posix.socket(posix.AF.INET, posix.SOCK.DGRAM | posix.SOCK.NONBLOCK, 0);
        defer posix.close(sockfd);
        const local_addr = try net.Address.parseIp4("127.0.0.1", 0);
        try posix.bind(sockfd, &local_addr.any, local_addr.getOsSockLen());
        ecn_socket.enableEcnRecv(sockfd) catch {};

        var cs = ConnState{
            .conn = try connection.connect(alloc, "localhost", .{}, warmup_tls, null),
            .sockfd = sockfd,
            .local_addr = local_addr,
            .remote_addr = connection.sockaddrToStorage(&server_addr.any),
            .addr_size = server_addr.getOsSockLen(),
        };

        if (!doHandshake(&cs)) {
            std.debug.print("  0-RTT warmup: handshake failed!\n", .{});
            return;
        }
        flushPostHandshake(&cs);

        // Wait for NewSessionTicket
        var ticket_wait: usize = 0;
        while (cs.conn.session_ticket == null and ticket_wait < 50) : (ticket_wait += 1) {
            std.Thread.sleep(1 * std.time.ns_per_ms);
            recvAll(&cs);
            cs.conn.onTimeout() catch {};
            sendAll(&cs);
        }

        if (cs.conn.session_ticket) |ticket| {
            saved_ticket = ticket;
            std.debug.print("  0-RTT warmup: got session ticket (lifetime={d}s)\n", .{ticket.lifetime});
        } else {
            std.debug.print("  0-RTT warmup: no session ticket received, falling back to 1-RTT\n", .{});
        }

        cs.conn.close(0, "warmup done");
        sendAll(&cs);
        std.Thread.sleep(5 * std.time.ns_per_ms);
    }

    // === Main benchmark ===
    const bench_start = timestamp();

    var conn_idx: u32 = 0;
    while (conn_idx < config.num_connections) : (conn_idx += 1) {
        const sockfd = try posix.socket(posix.AF.INET, posix.SOCK.DGRAM | posix.SOCK.NONBLOCK, 0);
        defer posix.close(sockfd);
        const local_addr = try net.Address.parseIp4("127.0.0.1", 0);
        try posix.bind(sockfd, &local_addr.any, local_addr.getOsSockLen());
        ecn_socket.enableEcnRecv(sockfd) catch {};

        const tls_config: tls13.TlsConfig = .{
            .cert_chain_der = &.{},
            .private_key_bytes = &.{},
            .alpn = alpn,
            .server_name = "localhost",
            .skip_cert_verify = true,
            .session_ticket = if (saved_ticket) |*t| t else null,
        };

        var cs = ConnState{
            .conn = try connection.connect(alloc, "localhost", .{}, tls_config, null),
            .sockfd = sockfd,
            .local_addr = local_addr,
            .remote_addr = connection.sockaddrToStorage(&server_addr.any),
            .addr_size = server_addr.getOsSockLen(),
            .handshake_start = timestamp(),
        };

        if (!doHandshake(&cs)) {
            std.debug.print("  connection {d}: handshake failed\n", .{conn_idx});
            continue;
        }

        cs.handshake_end = timestamp();
        handshake_total_ns += cs.handshake_end - cs.handshake_start;
        handshakes_completed += 1;
        flushPostHandshake(&cs);

        // Refresh session ticket from this connection
        if (config.zerortt) {
            var ticket_wait: usize = 0;
            while (cs.conn.session_ticket == null and ticket_wait < 20) : (ticket_wait += 1) {
                std.Thread.sleep(1 * std.time.ns_per_ms);
                recvAll(&cs);
                cs.conn.onTimeout() catch {};
                sendAll(&cs);
            }
            if (cs.conn.session_ticket) |ticket| {
                saved_ticket = ticket;
            }
        }

        // === H3 requests ===
        var h3_conn = h3.H3Connection.init(alloc, &cs.conn, false);
        defer h3_conn.deinit();
        h3_conn.initConnection() catch continue;
        sendAll(&cs);
        std.Thread.sleep(1 * std.time.ns_per_ms);
        recvAll(&cs);
        cs.conn.onTimeout() catch {};
        sendAll(&cs);

        doRequests(&cs, &h3_conn, config.requests_per_conn, all_latencies, &latency_count, &total_bytes);

        cs.conn.close(0, "bench done");
        sendAll(&cs);
    }

    const bench_end = timestamp();
    const mode = if (config.zerortt) "0-RTT resumption" else "1-RTT full handshake";
    printResults(
        mode,
        config,
        all_latencies,
        latency_count,
        total_bytes,
        handshake_total_ns,
        handshakes_completed,
        bench_end - bench_start,
    );
}

pub fn main() !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    var config = BenchConfig{};

    var args = std.process.args();
    _ = args.next();
    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--port")) {
            if (args.next()) |v| config.port = std.fmt.parseInt(u16, v, 10) catch 4434;
        } else if (std.mem.eql(u8, arg, "--connections") or std.mem.eql(u8, arg, "-c")) {
            if (args.next()) |v| config.num_connections = std.fmt.parseInt(u32, v, 10) catch 1;
        } else if (std.mem.eql(u8, arg, "--requests") or std.mem.eql(u8, arg, "-n")) {
            if (args.next()) |v| config.requests_per_conn = std.fmt.parseInt(u32, v, 10) catch 100;
        } else if (std.mem.eql(u8, arg, "--zerortt") or std.mem.eql(u8, arg, "-z")) {
            config.zerortt = true;
        } else if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) {
            std.debug.print("Usage: bench [options]\n", .{});
            std.debug.print("  --port PORT        Server port (default: 4434)\n", .{});
            std.debug.print("  -c, --connections N Number of connections (default: 1)\n", .{});
            std.debug.print("  -n, --requests N   Requests per connection (default: 100)\n", .{});
            std.debug.print("  -z, --zerortt      Enable 0-RTT session resumption\n", .{});
            return;
        }
    }

    std.debug.print("quic-zig bench: {d} conn × {d} req, {s} → 127.0.0.1:{d}\n", .{
        config.num_connections, config.requests_per_conn,
        if (config.zerortt) @as([]const u8, "0-RTT") else @as([]const u8, "1-RTT"),
        config.port,
    });

    try runBench(alloc, config);
}
