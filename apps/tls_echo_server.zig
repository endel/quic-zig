// Blocking TCP driver for quic.tls_server — the sans-IO TLS 1.3 server.
//
// One thread per connection: read the socket, feed the Conn, flush its
// output. An HTTP request gets a fixed HTTP/1.1 response; anything else is
// echoed back.
//
//   zig build run-tls-echo-server -- --port 8443
//   openssl s_client -tls1_3 -connect 127.0.0.1:8443
//   curl -k --tlsv1.3 https://127.0.0.1:8443/
//
// --tickets enables session tickets under a per-process random key.

const std = @import("std");
const posix = std.posix;
const quic = @import("quic");
const sys = quic.sys;
const tls13 = quic.tls13;
const tls_server = quic.tls_server;

const log = std.log.scoped(.tls_echo);

pub fn main(init: std.process.Init.Minimal) !void {
    const gpa = std.heap.smp_allocator;

    var port: u16 = 8443;
    var cert_path: []const u8 = "interop/certs/server.crt";
    var key_path: []const u8 = "interop/certs/server.key";
    var tickets = false;
    var args = std.process.Args.Iterator.init(init.args);
    _ = args.next();
    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--port")) {
            if (args.next()) |v| port = try std.fmt.parseInt(u16, v, 10);
        } else if (std.mem.eql(u8, arg, "--cert")) {
            if (args.next()) |v| cert_path = v;
        } else if (std.mem.eql(u8, arg, "--key")) {
            if (args.next()) |v| key_path = v;
        } else if (std.mem.eql(u8, arg, "--tickets")) {
            tickets = true;
        }
    }

    const cert_pem = try sys.readFileAlloc(gpa, cert_path, 1 << 20);
    const chain = try tls13.parsePemCertChain(gpa, cert_pem);
    const key_pem = try sys.readFileAlloc(gpa, key_path, 1 << 20);
    var key_der_buf: [4096]u8 = undefined;
    const key_der = try tls13.parsePemPrivateKey(key_pem, &key_der_buf);
    const key = tls13.extractEcPrivateKey(key_der) catch try tls13.extractPkcs8EcPrivateKey(key_der);

    const entries = [_]tls_server.CertEntry{.{
        .server_names = &.{"localhost"},
        .cert = .{ .cert_chain_der = chain, .private_key_bytes = key },
    }};
    var config: tls_server.Config = .{ .certs = &entries, .alpn = &.{"http/1.1"} };
    if (tickets) {
        var ticket_key: [16]u8 = undefined;
        sys.randomBytes(&ticket_key);
        config.ticket_key = ticket_key;
    }

    const addr = try quic.sockaddr.Address.parseIp4("127.0.0.1", port);
    const listener = try sys.socket(posix.AF.INET, posix.SOCK.STREAM, 0);
    const yes: c_int = 1;
    posix.setsockopt(listener, posix.SOL.SOCKET, posix.SO.REUSEADDR, std.mem.asBytes(&yes)) catch {};
    try sys.bind(listener, &addr.any, addr.getOsSockLen());
    try sys.listen(listener, 128);
    log.info("listening on 127.0.0.1:{d}", .{port});

    while (true) {
        const fd = sys.accept(listener) catch continue;
        const t = std.Thread.spawn(.{}, serve, .{ gpa, &config, fd }) catch {
            sys.close(fd);
            continue;
        };
        t.detach();
    }
}

fn serve(gpa: std.mem.Allocator, config: *const tls_server.Config, fd: sys.socket_t) void {
    defer sys.close(fd);
    var conn = tls_server.Conn.init(gpa, config);
    defer conn.deinit();

    var request: std.ArrayList(u8) = .empty;
    defer request.deinit(gpa);
    var was_complete = false;
    var buf: [16 * 1024]u8 = undefined;

    while (true) {
        const n = sys.read(fd, &buf) catch break;
        if (n == 0) break;
        const fed = conn.feed(buf[0..n]);
        if (!was_complete and conn.handshakeComplete()) {
            was_complete = true;
            log.info("handshake: suite={t} group={t} sni={?s} alpn={?s} resumed={}", .{
                conn.cipherSuite().?, conn.keyExchangeGroup().?, conn.serverName(), conn.alpn(), conn.isResumed(),
            });
        }
        fed catch |err| {
            log.warn("feed: {t}", .{err});
            flush(&conn, fd) catch {};
            return;
        };

        while (true) {
            const got = conn.read(&buf);
            if (got == 0) break;
            const data = buf[0..got];
            if (looksLikeHttp(request.items, data)) {
                if (request.items.len + data.len > max_request_head) return;
                request.appendSlice(gpa, data) catch return;
                if (std.mem.indexOf(u8, request.items, "\r\n\r\n") != null) {
                    const body = "Hello from quic-zig tls_server\n";
                    const response = std.fmt.bufPrint(&buf, "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {d}\r\nConnection: close\r\n\r\n{s}", .{ body.len, body }) catch return;
                    conn.write(response) catch return;
                    conn.close();
                    flush(&conn, fd) catch {};
                    return;
                }
            } else {
                conn.write(data) catch return;
            }
        }
        flush(&conn, fd) catch return;
        if (conn.peerClosed()) {
            conn.close();
            flush(&conn, fd) catch {};
            return;
        }
    }
}

/// A request head that never ends is dropped rather than buffered forever.
const max_request_head = 16 * 1024;

fn looksLikeHttp(seen: []const u8, data: []const u8) bool {
    if (seen.len > 0) return true;
    inline for (.{ "GET ", "HEAD ", "POST ", "PUT ", "DELETE ", "OPTIONS " }) |m| {
        if (std.mem.startsWith(u8, data, m)) return true;
    }
    return false;
}

fn flush(conn: *tls_server.Conn, fd: sys.socket_t) !void {
    while (conn.pendingOutput().len > 0) {
        const n = try sys.write(fd, conn.pendingOutput());
        conn.consumeOutput(n);
    }
}
