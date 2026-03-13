// QUIC Interop Runner - Server Endpoint
//
// Reads environment variables set by the interop runner:
//   TESTCASE    - which test to run (handshake, transfer, retry, etc.)
//   SSLKEYLOGFILE - path to write TLS key log
//   QLOGDIR     - path to write qlog files (.sqlog JSON-SEQ format)
//
// Serves files from /www/ using HTTP/0.9 (hq-interop) or HTTP/3.
// Listens on 0.0.0.0:443.
// Loads certs from /certs/cert.pem and /certs/priv.key.

const std = @import("std");
const posix = std.posix;

const event_loop = @import("event_loop.zig");
const connection = @import("quic/connection.zig");
const quic_crypto = @import("quic/crypto.zig");
const tls13 = @import("quic/tls13.zig");
const qpack = @import("h3/qpack.zig");
const transport_params = @import("quic/transport_params.zig");

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
    if (std.mem.eql(u8, name, "longrtt")) return .longrtt;
    if (std.mem.eql(u8, name, "multiplexing")) return .multiplexing;
    if (std.mem.eql(u8, name, "blackhole")) return .blackhole;
    if (std.mem.eql(u8, name, "handshakeloss")) return .handshakeloss;
    if (std.mem.eql(u8, name, "transferloss")) return .transferloss;
    if (std.mem.eql(u8, name, "handshakecorruption")) return .handshakecorruption;
    if (std.mem.eql(u8, name, "transfercorruption")) return .transfercorruption;
    if (std.mem.eql(u8, name, "amplificationlimit")) return .amplificationlimit;
    if (std.mem.eql(u8, name, "ipv6")) return .ipv6;
    if (std.mem.eql(u8, name, "versionnegotiation")) return .versionnegotiation;
    return .unsupported;
}

// --- H3 Handler ---

const H3InteropHandler = struct {
    pub const protocol: event_loop.Protocol = .h3;

    alloc: std.mem.Allocator,
    www_dir: []const u8,

    pub fn onRequest(self: *H3InteropHandler, session: *event_loop.Session, stream_id: u64, headers: []const qpack.Header) void {
        var path: []const u8 = "/";
        for (headers) |h_item| {
            if (std.mem.eql(u8, h_item.name, ":path")) path = h_item.value;
        }

        // Read file and send response
        const file_data = readFileFromWww(self.alloc, self.www_dir, path) catch {
            const resp_headers = [_]qpack.Header{
                .{ .name = ":status", .value = "404" },
            };
            session.sendResponse(stream_id, &resp_headers, "Not Found\n") catch {};
            return;
        };
        defer self.alloc.free(file_data);

        const resp_headers = [_]qpack.Header{
            .{ .name = ":status", .value = "200" },
        };
        session.sendResponse(stream_id, &resp_headers, file_data) catch {};
    }
};

// --- H0 Handler ---

const H0InteropHandler = struct {
    pub const protocol: event_loop.Protocol = .h0;

    www_dir: []const u8,

    pub fn onH0Request(self: *H0InteropHandler, session: *event_loop.Session, stream_id: u64, path: []const u8) void {
        std.log.info("H0: request for {s} on stream {d}", .{ path, stream_id });
        session.serveFile(stream_id, self.www_dir, path) catch |err| {
            std.log.err("H0: serveFile error: {any}", .{err});
        };
    }
};

pub fn main() !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    // Read environment variables
    const testcase_str = std.posix.getenv("TESTCASE") orelse "handshake";
    const testcase = parseTestCase(testcase_str);
    const sslkeylogfile_path = std.posix.getenv("SSLKEYLOGFILE");
    const qlog_dir = std.posix.getenv("QLOGDIR");
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

    // Build preferred_address for connectionmigration test case
    var preferred_addr: ?transport_params.PreferredAddress = null;
    if (testcase == .connectionmigration) {
        const addrs = getServerAddresses();
        if (addrs.ipv4 != null or addrs.ipv6 != null) {
            const listen_port: u16 = std.fmt.parseInt(u16, port_str, 10) catch 443;
            var pref = transport_params.PreferredAddress{};
            if (addrs.ipv4) |v4| {
                pref.ipv4_addr = v4;
                pref.ipv4_port = listen_port;
            }
            if (addrs.ipv6) |v6| {
                pref.ipv6_addr = v6;
                pref.ipv6_port = listen_port;
            }
            pref.cid_len = 8;
            std.crypto.random.bytes(pref.cid_buf[0..8]);
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

    const listen_port: u16 = std.fmt.parseInt(u16, port_str, 10) catch 443;

    const conn_config: connection.ConnectionConfig = .{
        .token_key = retry_token_key,
        .enable_v2 = (testcase == .v2),
        .disable_pmtud = true,
        .preferred_address = preferred_addr,
        .qlog_dir = qlog_dir,
        .initial_max_streams_bidi = 1000,
        .initial_max_streams_uni = 1000,
    };

    const config: event_loop.Config = .{
        .port = listen_port,
        .ipv6 = true,
        .require_retry = (testcase == .retry),
        .tls_config = tls_config,
        .conn_config = conn_config,
        .retry_token_key = retry_token_key,
        .static_reset_key = static_reset_key,
    };

    std.log.info("interop server listening on [::]:{d} (ALPN={s})", .{ listen_port, alpn[0] });

    if (use_h3) {
        var handler = H3InteropHandler{ .alloc = alloc, .www_dir = www_dir };
        var server = try event_loop.Server(H3InteropHandler).init(alloc, &handler, config);
        defer server.deinit();
        try server.run();
    } else {
        var handler = H0InteropHandler{ .www_dir = www_dir };
        var server = try event_loop.Server(H0InteropHandler).init(alloc, &handler, config);
        defer server.deinit();
        try server.run();
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
            if (bytes[0] != 127) {
                ipv4 = bytes;
            }
        } else if (addr.family == posix.AF.INET6) {
            const in6_addr: *const posix.sockaddr.in6 = @ptrCast(@alignCast(addr));
            if (in6_addr.addr[0] == 0 and in6_addr.addr[1] == 0 and
                in6_addr.addr[2] == 0 and in6_addr.addr[3] == 0 and
                in6_addr.addr[4] == 0 and in6_addr.addr[5] == 0 and
                in6_addr.addr[6] == 0 and in6_addr.addr[7] == 0 and
                in6_addr.addr[8] == 0 and in6_addr.addr[9] == 0 and
                in6_addr.addr[10] == 0 and in6_addr.addr[11] == 0 and
                in6_addr.addr[12] == 0 and in6_addr.addr[13] == 0 and
                in6_addr.addr[14] == 0)
            {
                continue;
            }
            if (in6_addr.addr[0] == 0xfe and (in6_addr.addr[1] & 0xc0) == 0x80) {
                continue;
            }
            ipv6 = in6_addr.addr;
        }
    }

    return .{ .ipv4 = ipv4, .ipv6 = ipv6 };
}
