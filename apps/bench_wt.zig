// WebTransport Benchmark Client
//
// Measures handshake latency, stream throughput, and datagram throughput.
// Methodology matches webtransport-bun for direct comparison.
//
// Usage:
//   bench-wt [--mode handshake|stream|datagram|all] [--port PORT]
//            [--rounds N] [--duration S] [--json]

const std = @import("std");
const posix = std.posix;
const net = std.net;

// Suppress verbose QUIC/TLS debug logging during benchmarks
pub const std_options: std.Options = .{
    .log_level = .err,
};

const quic = @import("quic");
const connection = quic.connection;
const Connection = connection.Connection;
const tls13 = quic.tls13;
const ecn_socket = quic.ecn_socket;
const h3 = quic.h3;
const wt = quic.webtransport;

const MAX_UDP: usize = 1500;

const Mode = enum { handshake, stream, datagram, all };

const Config = struct {
    port: u16 = 4434,
    mode: Mode = .all,
    handshake_n: u32 = 50,
    stream_rounds: u32 = 50,
    stream_payload: u32 = 1024,
    datagram_duration_s: u32 = 10,
    json: bool = false,
};

// ════════════════════════════════════════════════════════
// Utilities
// ════════════════════════════════════════════════════════

fn timestamp() i64 {
    return @intCast(std.time.nanoTimestamp());
}

fn nsToMs(ns: i64) f64 {
    return @as(f64, @floatFromInt(ns)) / 1_000_000.0;
}

fn percentile(sorted: []const i64, p: f64) i64 {
    if (sorted.len == 0) return 0;
    const raw = @ceil(p / 100.0 * @as(f64, @floatFromInt(sorted.len)));
    const idx = @as(usize, @intFromFloat(raw)) -| 1;
    return sorted[@min(idx, sorted.len - 1)];
}

// ════════════════════════════════════════════════════════
// I/O helpers
// ════════════════════════════════════════════════════════

fn createSocket() !struct { fd: posix.socket_t, addr: net.Address } {
    const fd = try posix.socket(posix.AF.INET, posix.SOCK.DGRAM | posix.SOCK.NONBLOCK, 0);
    const addr = try net.Address.parseIp4("127.0.0.1", 0);
    try posix.bind(fd, &addr.any, addr.getOsSockLen());
    ecn_socket.enableEcnRecv(fd) catch {};
    return .{ .fd = fd, .addr = addr };
}

fn recvAll(
    fd: posix.socket_t,
    conn: *Connection,
    local: net.Address,
    remote: *posix.sockaddr.storage,
    asz: *posix.socklen_t,
) void {
    while (true) {
        var buf: [8192]u8 = undefined;
        const r = ecn_socket.recvmsgEcn(fd, &buf) catch break;
        remote.* = r.from_addr;
        asz.* = r.addr_len;
        conn.handleDatagram(buf[0..r.bytes_read], .{
            .to = connection.sockaddrToStorage(&local.any),
            .from = remote.*,
            .ecn = r.ecn,
            .datagram_size = r.bytes_read,
        });
    }
}

fn flushSend(fd: posix.socket_t, conn: *Connection, remote: *const posix.sockaddr.storage, asz: posix.socklen_t) void {
    var out: [MAX_UDP]u8 = undefined;
    var i: usize = 0;
    while (i < 50) : (i += 1) {
        const n = conn.send(&out) catch break;
        if (n == 0) break;
        ecn_socket.setEcnMark(fd, conn.getEcnMark()) catch {};
        _ = posix.sendto(fd, out[0..n], 0, @ptrCast(remote), asz) catch break;
    }
}

fn ioTick(
    fd: posix.socket_t,
    conn: *Connection,
    local: net.Address,
    remote: *posix.sockaddr.storage,
    asz: *posix.socklen_t,
) void {
    recvAll(fd, conn, local, remote, asz);
    conn.onTimeout() catch {};
    flushSend(fd, conn, remote, asz.*);
}

// ════════════════════════════════════════════════════════
// Full QUIC + H3 + WT session establishment
// ════════════════════════════════════════════════════════

fn establishSession(
    alloc: std.mem.Allocator,
    port: u16,
    tls_config: tls13.TlsConfig,
    conn: *Connection,
    h3c: *h3.H3Connection,
    wtc: *wt.WebTransportConnection,
    fd: posix.socket_t,
    local: net.Address,
    remote: *posix.sockaddr.storage,
    asz: *posix.socklen_t,
) !u64 {
    const server_addr = try net.Address.parseIp4("127.0.0.1", port);
    remote.* = connection.sockaddrToStorage(&server_addr.any);
    asz.* = server_addr.getOsSockLen();

    conn.* = try connection.connect(alloc, "localhost", .{
        .max_datagram_frame_size = 65536,
    }, tls_config, null);

    // QUIC handshake
    var iter: usize = 0;
    while (conn.state != .connected and iter < 500) : (iter += 1) {
        conn.onTimeout() catch {};
        flushSend(fd, conn, remote, asz.*);
        recvAll(fd, conn, local, remote, asz);
        if (conn.state == .connected) break;
        std.Thread.sleep(200 * std.time.ns_per_us);
    }
    if (conn.state != .connected) return error.HandshakeFailed;

    // Post-handshake flush
    flushSend(fd, conn, remote, asz.*);
    std.Thread.sleep(2 * std.time.ns_per_ms);
    recvAll(fd, conn, local, remote, asz);
    conn.onTimeout() catch {};
    flushSend(fd, conn, remote, asz.*);
    remote.* = conn.peerAddress().*;

    // H3 init
    h3c.* = h3.H3Connection.init(alloc, conn, false);
    h3c.local_settings = .{
        .enable_connect_protocol = true,
        .h3_datagram = true,
        .enable_webtransport = true,
        .webtransport_max_sessions = 1,
    };
    try h3c.initConnection();

    // WT init + CONNECT
    wtc.* = wt.WebTransportConnection.init(alloc, h3c, conn, false);
    const sid = try wtc.connect("localhost", "/.well-known/webtransport");

    // Flush CONNECT request
    var f: usize = 0;
    while (f < 10) : (f += 1) {
        flushSend(fd, conn, remote, asz.*);
    }

    // Wait for session_ready
    iter = 0;
    while (iter < 500) : (iter += 1) {
        std.Thread.sleep(1 * std.time.ns_per_ms);
        ioTick(fd, conn, local, remote, asz);

        while (true) {
            const ev = wtc.poll() catch break;
            if (ev == null) break;
            switch (ev.?) {
                .session_ready => return sid,
                .session_rejected => return error.SessionRejected,
                else => {},
            }
        }
    }
    return error.SessionTimeout;
}

// ════════════════════════════════════════════════════════
// Handshake Latency Benchmark
// ════════════════════════════════════════════════════════

fn benchHandshake(alloc: std.mem.Allocator, config: Config) !void {
    std.debug.print("\n  Handshake Latency (n={d})\n  ─────────────────────────\n", .{config.handshake_n});

    const latencies = try alloc.alloc(i64, config.handshake_n);
    var ok: u32 = 0;
    var fail: u32 = 0;

    const alpn = try alloc.alloc([]const u8, 1);
    alpn[0] = "h3";
    const tls_config: tls13.TlsConfig = .{
        .cert_chain_der = &.{},
        .private_key_bytes = &.{},
        .alpn = alpn,
        .server_name = "localhost",
        .skip_cert_verify = true,
    };

    var i: u32 = 0;
    while (i < config.handshake_n) : (i += 1) {
        const start = timestamp();
        const sock = createSocket() catch {
            fail += 1;
            continue;
        };
        defer posix.close(sock.fd);

        var conn: Connection = undefined;
        var h3c: h3.H3Connection = undefined;
        var wtc: wt.WebTransportConnection = undefined;
        var remote: posix.sockaddr.storage = undefined;
        var asz: posix.socklen_t = 0;

        if (establishSession(alloc, config.port, tls_config, &conn, &h3c, &wtc, sock.fd, sock.addr, &remote, &asz)) |_| {
            latencies[ok] = timestamp() - start;
            ok += 1;
            conn.close(0, "done");
            flushSend(sock.fd, &conn, &remote, asz);
        } else |_| {
            fail += 1;
        }
    }

    if (ok == 0) {
        std.debug.print("    FAIL: no successful connections\n", .{});
        return;
    }

    std.mem.sort(i64, latencies[0..ok], {}, std.sort.asc(i64));
    const p50 = nsToMs(percentile(latencies[0..ok], 50));
    const p95 = nsToMs(percentile(latencies[0..ok], 95));
    const p99 = nsToMs(percentile(latencies[0..ok], 99));

    std.debug.print("    p50:    {d:.1} ms\n", .{p50});
    std.debug.print("    p95:    {d:.1} ms   (webtransport-bun threshold: <500ms)\n", .{p95});
    std.debug.print("    p99:    {d:.1} ms   (webtransport-bun target: <300ms)\n", .{p99});
    if (fail > 0) std.debug.print("    failed: {d}/{d}\n", .{ fail, config.handshake_n });

    if (config.json) {
        std.debug.print("{{\"name\":\"handshake-latency\",\"n\":{d},\"p50_ms\":{d:.1},\"p95_ms\":{d:.1},\"p99_ms\":{d:.1}}}\n", .{ ok, p50, p95, p99 });
    }
}

// ════════════════════════════════════════════════════════
// Stream Throughput Benchmark
// ════════════════════════════════════════════════════════

fn benchStream(alloc: std.mem.Allocator, config: Config) !void {
    std.debug.print("\n  Stream Throughput ({d} rounds x {d}B)\n  ──────────────────────────────────────\n", .{ config.stream_rounds, config.stream_payload });

    const sock = try createSocket();
    defer posix.close(sock.fd);

    const alpn = try alloc.alloc([]const u8, 1);
    alpn[0] = "h3";
    const tls_config: tls13.TlsConfig = .{
        .cert_chain_der = &.{},
        .private_key_bytes = &.{},
        .alpn = alpn,
        .server_name = "localhost",
        .skip_cert_verify = true,
    };

    var conn: Connection = undefined;
    var h3c: h3.H3Connection = undefined;
    var wtc: wt.WebTransportConnection = undefined;
    var remote: posix.sockaddr.storage = undefined;
    var asz: posix.socklen_t = 0;

    const sid = try establishSession(alloc, config.port, tls_config, &conn, &h3c, &wtc, sock.fd, sock.addr, &remote, &asz);

    const payload = try alloc.alloc(u8, config.stream_payload);
    @memset(payload, 'x');

    // Open one bidi stream for all rounds (like webtransport-bun's pipeTo pattern)
    const stream_id = try wtc.openBidiStream(sid, null);

    var bytes_sent: u64 = 0;
    var total_received: usize = 0;
    const start = timestamp();

    var round: u32 = 0;
    while (round < config.stream_rounds) : (round += 1) {
        try wtc.sendStreamData(stream_id, payload);
        bytes_sent += payload.len;
        flushSend(sock.fd, &conn, &remote, asz);

        // Wait for echo (total received >= total sent)
        var spin: usize = 0;
        while (total_received < bytes_sent and spin < 20000) : (spin += 1) {
            recvAll(sock.fd, &conn, sock.addr, &remote, &asz);
            conn.onTimeout() catch {};
            flushSend(sock.fd, &conn, &remote, asz);

            while (true) {
                const ev = wtc.poll() catch break;
                if (ev == null) break;
                switch (ev.?) {
                    .stream_data => |sd| {
                        total_received += sd.data.len;
                        if (sd.data.len > 0) alloc.free(sd.data);
                    },
                    .datagram => |dg| alloc.free(dg.data),
                    else => {},
                }
            }

            if (total_received >= bytes_sent) break;
            std.Thread.sleep(50 * std.time.ns_per_us);
        }
    }

    const elapsed_ns = timestamp() - start;
    const elapsed_s = @as(f64, @floatFromInt(elapsed_ns)) / 1_000_000_000.0;
    const mbps = @as(f64, @floatFromInt(bytes_sent)) / (1024.0 * 1024.0) / elapsed_s;

    std.debug.print("    Throughput: {d:.2} MB/s\n", .{mbps});
    std.debug.print("    Elapsed:    {d:.3}s\n", .{elapsed_s});
    std.debug.print("    Bytes:      {d}\n", .{bytes_sent});
    std.debug.print("    (webtransport-bun threshold: >0.5 MB/s)\n", .{});

    if (config.json) {
        std.debug.print("{{\"name\":\"stream-throughput\",\"rounds\":{d},\"bytes\":{d},\"elapsed_s\":{d:.3},\"throughput_mbps\":{d:.2}}}\n", .{ config.stream_rounds, bytes_sent, elapsed_s, mbps });
    }

    conn.close(0, "done");
    flushSend(sock.fd, &conn, &remote, asz);
}

// ════════════════════════════════════════════════════════
// Datagram Throughput Benchmark
// ════════════════════════════════════════════════════════

fn benchDatagram(alloc: std.mem.Allocator, config: Config) !void {
    std.debug.print("\n  Datagram Throughput ({d}s)\n  ─────────────────────────\n", .{config.datagram_duration_s});

    const sock = try createSocket();
    defer posix.close(sock.fd);

    const alpn = try alloc.alloc([]const u8, 1);
    alpn[0] = "h3";
    const tls_config: tls13.TlsConfig = .{
        .cert_chain_der = &.{},
        .private_key_bytes = &.{},
        .alpn = alpn,
        .server_name = "localhost",
        .skip_cert_verify = true,
    };

    var conn: Connection = undefined;
    var h3c: h3.H3Connection = undefined;
    var wtc: wt.WebTransportConnection = undefined;
    var remote: posix.sockaddr.storage = undefined;
    var asz: posix.socklen_t = 0;

    const sid = try establishSession(alloc, config.port, tls_config, &conn, &h3c, &wtc, sock.fd, sock.addr, &remote, &asz);

    var payload: [100]u8 = undefined;
    @memset(&payload, 'd');

    var sent: u64 = 0;
    var recv_count: u64 = 0;
    var send_fail: u64 = 0;
    const deadline = timestamp() + @as(i64, @intCast(config.datagram_duration_s)) * 1_000_000_000;
    const start = timestamp();

    while (timestamp() < deadline) {
        // Queue a batch of datagrams
        var batch: u32 = 0;
        while (batch < 50) : (batch += 1) {
            wtc.sendDatagram(sid, &payload) catch {
                send_fail += 1;
                break;
            };
            sent += 1;
        }

        // I/O cycle
        flushSend(sock.fd, &conn, &remote, asz);
        recvAll(sock.fd, &conn, sock.addr, &remote, &asz);
        conn.onTimeout() catch {};
        flushSend(sock.fd, &conn, &remote, asz);

        // Drain received datagrams
        while (true) {
            const ev = wtc.poll() catch break;
            if (ev == null) break;
            switch (ev.?) {
                .datagram => |dg| {
                    recv_count += 1;
                    alloc.free(dg.data);
                },
                else => {},
            }
        }

        if (batch == 0) std.Thread.sleep(100 * std.time.ns_per_us);
    }

    const elapsed_ns = timestamp() - start;
    const elapsed_s = @as(f64, @floatFromInt(elapsed_ns)) / 1_000_000_000.0;
    const throughput = @as(f64, @floatFromInt(sent)) / elapsed_s;

    std.debug.print("    Sent:       {d} dgrams\n", .{sent});
    std.debug.print("    Received:   {d} dgrams\n", .{recv_count});
    if (send_fail > 0) std.debug.print("    Send fail:  {d}\n", .{send_fail});
    std.debug.print("    Throughput: {d:.0} dgram/s\n", .{throughput});
    std.debug.print("    Payload:    {d}B\n", .{payload.len});

    if (config.json) {
        std.debug.print("{{\"name\":\"datagram-throughput\",\"duration_s\":{d},\"sent\":{d},\"received\":{d},\"throughput_dps\":{d:.0}}}\n", .{ config.datagram_duration_s, sent, recv_count, throughput });
    }

    conn.close(0, "done");
    flushSend(sock.fd, &conn, &remote, asz);
}

// ════════════════════════════════════════════════════════
// Main
// ════════════════════════════════════════════════════════

pub fn main() !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    var config = Config{};
    var args = std.process.args();
    _ = args.next();
    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--port")) {
            if (args.next()) |v| config.port = std.fmt.parseInt(u16, v, 10) catch 4434;
        } else if (std.mem.eql(u8, arg, "--mode")) {
            if (args.next()) |v| {
                if (std.mem.eql(u8, v, "handshake")) {
                    config.mode = .handshake;
                } else if (std.mem.eql(u8, v, "stream")) {
                    config.mode = .stream;
                } else if (std.mem.eql(u8, v, "datagram")) {
                    config.mode = .datagram;
                } else {
                    config.mode = .all;
                }
            }
        } else if (std.mem.eql(u8, arg, "--rounds") or std.mem.eql(u8, arg, "-n")) {
            if (args.next()) |v| {
                const n = std.fmt.parseInt(u32, v, 10) catch 50;
                config.handshake_n = n;
                config.stream_rounds = n;
            }
        } else if (std.mem.eql(u8, arg, "--duration")) {
            if (args.next()) |v| config.datagram_duration_s = std.fmt.parseInt(u32, v, 10) catch 10;
        } else if (std.mem.eql(u8, arg, "--json")) {
            config.json = true;
        }
    }

    std.debug.print("═══════════════════════════════════════════════════════\n", .{});
    std.debug.print("  WebTransport Benchmark (quic-zig)\n", .{});
    std.debug.print("  Comparable with webtransport-bun benchmark suite\n", .{});
    std.debug.print("═══════════════════════════════════════════════════════\n", .{});

    switch (config.mode) {
        .handshake => try benchHandshake(alloc, config),
        .stream => try benchStream(alloc, config),
        .datagram => try benchDatagram(alloc, config),
        .all => {
            benchHandshake(alloc, config) catch |e| std.debug.print("  handshake bench error: {any}\n", .{e});
            benchStream(alloc, config) catch |e| std.debug.print("  stream bench error: {any}\n", .{e});
            benchDatagram(alloc, config) catch |e| std.debug.print("  datagram bench error: {any}\n", .{e});
        },
    }

    std.debug.print("\n═══════════════════════════════════════════════════════\n", .{});
}
