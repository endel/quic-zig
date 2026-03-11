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

const connection = @import("quic/connection.zig");
const connection_manager = @import("quic/connection_manager.zig");
const quic_crypto = @import("quic/crypto.zig");
const tls13 = @import("quic/tls13.zig");
const ecn_socket = @import("quic/ecn_socket.zig");
const h3 = @import("h3/connection.zig");
const h0 = @import("h0/connection.zig");
const qpack = @import("h3/qpack.zig");

const transport_params = @import("quic/transport_params.zig");

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

    const cert_chain = try tls13.parsePemCertChain(alloc, cert_pem);
    std.log.info("loaded {d} certificate(s)", .{cert_chain.len});

    var key_der_buf: [4096]u8 = undefined;
    const key_der = try tls13.parsePemPrivateKey(key_pem, &key_der_buf);
    const ec_private_key = try tls13.extractEcPrivateKey(key_der);

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

    // Create UDP socket (dual-stack: try IPv6 first, fall back to IPv4)
    const listen_port: u16 = std.fmt.parseInt(u16, port_str, 10) catch 443;
    const sockfd, const local_addr = blk: {
        // Try IPv6 dual-stack socket first (handles both IPv4 and IPv6)
        const addr6 = try std.net.Address.parseIp6("::", listen_port);
        const fd6 = posix.socket(posix.AF.INET6, posix.SOCK.DGRAM | posix.SOCK.NONBLOCK, 0) catch {
            // Fall back to IPv4-only
            const addr4 = try std.net.Address.parseIp4("0.0.0.0", listen_port);
            const fd4 = try posix.socket(posix.AF.INET, posix.SOCK.DGRAM | posix.SOCK.NONBLOCK, 0);
            posix.bind(fd4, &addr4.any, addr4.getOsSockLen()) catch {
                posix.close(fd4);
                return error.BindFailed;
            };
            break :blk .{ fd4, addr4 };
        };
        // Allow dual-stack (disable IPV6_V6ONLY)
        const IPV6_V6ONLY: u32 = if (@import("builtin").os.tag == .linux) 26 else 27;
        const zero: c_int = 0;
        posix.setsockopt(fd6, posix.IPPROTO.IPV6, IPV6_V6ONLY, std.mem.asBytes(&zero)) catch {};
        posix.bind(fd6, &addr6.any, addr6.getOsSockLen()) catch {
            posix.close(fd6);
            // Fall back to IPv4-only
            const addr4 = try std.net.Address.parseIp4("0.0.0.0", listen_port);
            const fd4 = try posix.socket(posix.AF.INET, posix.SOCK.DGRAM | posix.SOCK.NONBLOCK, 0);
            posix.bind(fd4, &addr4.any, addr4.getOsSockLen()) catch {
                posix.close(fd4);
                return error.BindFailed;
            };
            break :blk .{ fd4, addr4 };
        };
        break :blk .{ fd6, addr6 };
    };
    defer posix.close(sockfd);
    ecn_socket.enableEcnRecv(sockfd) catch {};
    std.log.info("interop server listening on [::]:{d} (ALPN={s})", .{ listen_port, alpn[0] });

    // Build preferred_address for connectionmigration test case
    var preferred_addr: ?transport_params.PreferredAddress = null;
    if (testcase == .connectionmigration) {
        const addrs = getServerAddresses();
        if (addrs.ipv4 != null or addrs.ipv6 != null) {
            var pref = transport_params.PreferredAddress{};
            if (addrs.ipv4) |v4| {
                pref.ipv4_addr = v4;
                pref.ipv4_port = listen_port;
            }
            if (addrs.ipv6) |v6| {
                pref.ipv6_addr = v6;
                pref.ipv6_port = listen_port;
            }
            // Generate a CID for the preferred address
            pref.cid_len = 8;
            std.crypto.random.bytes(pref.cid_buf[0..8]);
            // Generate stateless reset token for this CID
            const stateless_reset = @import("quic/stateless_reset.zig");
            pref.stateless_reset_token = stateless_reset.computeToken(static_reset_key, pref.cid_buf[0..8]);
            preferred_addr = pref;
            std.log.info("connectionmigration: preferred_address ipv4={any} ipv6={any} cid_len={d}", .{
                addrs.ipv4, addrs.ipv6, pref.cid_len,
            });
        } else {
            std.log.warn("connectionmigration: could not determine server addresses for preferred_address", .{});
        }
    }

    var conn_mgr = connection_manager.ConnectionManager.init(
        alloc,
        tls_config,
        .{
            .token_key = retry_token_key,
            .enable_v2 = (testcase == .v2),
            .disable_pmtud = true,
            .preferred_address = preferred_addr,
        },
        retry_token_key,
        static_reset_key,
    );
    conn_mgr.require_retry = (testcase == .retry);
    defer conn_mgr.deinit();

    // Track H0 connections per entry (keyed by conn pointer)
    var h0_conns = std.AutoHashMap(usize, *h0.H0Connection).init(alloc);
    defer h0_conns.deinit();

    var remote_addr: posix.sockaddr.storage = std.mem.zeroes(posix.sockaddr.storage);
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
            remote_addr = recv_result.from_addr;
            addr_size = recv_result.addr_len;

            switch (conn_mgr.recvDatagram(bytes[0..recv_result.bytes_read], remote_addr, connection.sockaddrToStorage(&local_addr.any), recv_result.ecn, &out)) {
                .processed => |entry| {
                    // Send response packets
                    const bytes_written = entry.conn.send(&out) catch continue;
                    if (bytes_written > 0) {
                        ecn_socket.setEcnMark(sockfd, entry.conn.getEcnMark()) catch {};
                        const send_addr = entry.conn.peerAddress();
                        _ = posix.sendto(sockfd, out[0..bytes_written], 0, @ptrCast(send_addr), connection.sockaddrLen(send_addr)) catch {};
                    }
                },
                .send_response => |data| {
                    _ = posix.sendto(sockfd, data, 0, @ptrCast(&remote_addr), addr_size) catch {};
                },
                .dropped => {},
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

            // Timeouts + close check
            if (!conn_mgr.tickEntry(entry)) {
                _ = h0_conns.remove(conn_key);
                continue;
            }

            // Burst send — drain queued data up to congestion/pacer limits
            var send_count: usize = 0;
            while (send_count < 100) : (send_count += 1) {
                const bytes_written = conn.send(&out) catch break;
                if (bytes_written == 0) break;
                ecn_socket.setEcnMark(sockfd, conn.getEcnMark()) catch {};
                const send_addr = conn.peerAddress();
                _ = posix.sendto(sockfd, out[0..bytes_written], 0, @ptrCast(send_addr), connection.sockaddrLen(send_addr)) catch {};
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

/// Discover the server's non-loopback IPv4 and IPv6 addresses from network interfaces.
/// Uses C getifaddrs() which works on Linux (Docker containers).
fn getServerAddresses() struct { ipv4: ?[4]u8, ipv6: ?[16]u8 } {
    const IfAddrs = extern struct {
        ifa_next: ?*@This(),
        ifa_name: [*:0]const u8,
        ifa_flags: c_uint,
        ifa_addr: ?*posix.sockaddr.storage,
        ifa_netmask: ?*posix.sockaddr.storage,
        ifa_ifu: ?*posix.sockaddr.storage,
        ifa_data: ?*anyopaque,
    };

    const getifaddrs_c = struct {
        extern "c" fn getifaddrs(ifap: *?*IfAddrs) c_int;
        extern "c" fn freeifaddrs(ifa: *IfAddrs) void;
    };

    var ifap: ?*IfAddrs = null;
    if (getifaddrs_c.getifaddrs(&ifap) != 0) return .{ .ipv4 = null, .ipv6 = null };
    defer if (ifap) |p| getifaddrs_c.freeifaddrs(p);

    var ipv4: ?[4]u8 = null;
    var ipv6: ?[16]u8 = null;

    var ifa = ifap;
    while (ifa) |a| {
        defer ifa = a.ifa_next;
        const addr = a.ifa_addr orelse continue;
        if (addr.family == posix.AF.INET) {
            const in_addr: *const posix.sockaddr.in = @ptrCast(@alignCast(addr));
            const bytes: [4]u8 = @bitCast(in_addr.addr);
            if (bytes[0] != 127) { // skip loopback
                ipv4 = bytes;
            }
        } else if (addr.family == posix.AF.INET6) {
            const in6_addr: *const posix.sockaddr.in6 = @ptrCast(@alignCast(addr));
            // Skip loopback (::1) and link-local (fe80::)
            if (in6_addr.addr[0] == 0 and in6_addr.addr[1] == 0 and
                in6_addr.addr[2] == 0 and in6_addr.addr[3] == 0 and
                in6_addr.addr[4] == 0 and in6_addr.addr[5] == 0 and
                in6_addr.addr[6] == 0 and in6_addr.addr[7] == 0 and
                in6_addr.addr[8] == 0 and in6_addr.addr[9] == 0 and
                in6_addr.addr[10] == 0 and in6_addr.addr[11] == 0 and
                in6_addr.addr[12] == 0 and in6_addr.addr[13] == 0 and
                in6_addr.addr[14] == 0)
            {
                continue; // ::0 or ::1
            }
            if (in6_addr.addr[0] == 0xfe and (in6_addr.addr[1] & 0xc0) == 0x80) {
                continue; // link-local fe80::
            }
            ipv6 = in6_addr.addr;
        }
    }

    return .{ .ipv4 = ipv4, .ipv6 = ipv6 };
}
