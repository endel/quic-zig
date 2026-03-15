// QUIC Load Balancer — standalone UDP packet forwarder
//
// Reads a config file, binds to a listen address, and routes
// incoming QUIC packets to backend servers based on the server_id
// extracted from QUIC-LB encoded connection IDs.
//
// Config file format (one directive per line):
//   listen 0.0.0.0:443
//   config_id 0
//   server_id_len 2
//   nonce_len 6
//   key 0123456789abcdef0123456789abcdef
//   server 0001 10.0.0.1:4433
//   server 0002 10.0.0.2:4433

const std = @import("std");
const posix = std.posix;
const net = std.net;
const quic = @import("quic");
const quic_lb = quic.quic_lb;

const MAX_PACKET_SIZE: usize = 1500;
const MAX_SERVERS: usize = 256;
const MAX_CLIENTS: usize = 4096;

/// Mapping: server_id (hex) → backend address
const ServerMapping = struct {
    server_id: [15]u8 = .{0} ** 15,
    server_id_len: u4 = 0,
    addr: net.Address,
};

/// Mapping: client address → backend address (for return traffic)
const ClientMapping = struct {
    client_addr: posix.sockaddr.storage = std.mem.zeroes(posix.sockaddr.storage),
    backend_addr: posix.sockaddr.storage = std.mem.zeroes(posix.sockaddr.storage),
    occupied: bool = false,
    last_seen: i64 = 0,
};

const LbConfig = struct {
    listen_addr: net.Address = net.Address.initIp4(.{ 0, 0, 0, 0 }, 443),
    lb_config: quic_lb.Config = .{
        .config_id = 0,
        .server_id_len = 2,
        .nonce_len = 6,
    },
    servers: [MAX_SERVERS]ServerMapping = undefined,
    server_count: usize = 0,
};

fn parseConfigFile(path: []const u8, allocator: std.mem.Allocator) !LbConfig {
    var config = LbConfig{};

    const file_data = try std.fs.cwd().readFileAlloc(allocator, path, 64 * 1024);
    defer allocator.free(file_data);

    var line_iter = std.mem.splitScalar(u8, file_data, '\n');
    while (line_iter.next()) |line| {
        const trimmed = std.mem.trim(u8, line, &std.ascii.whitespace);
        if (trimmed.len == 0 or trimmed[0] == '#') continue;

        if (std.mem.startsWith(u8, trimmed, "listen ")) {
            const addr_str = std.mem.trim(u8, trimmed["listen ".len..], &std.ascii.whitespace);
            config.listen_addr = parseAddress(addr_str) orelse {
                std.log.err("invalid listen address: {s}", .{addr_str});
                return error.InvalidConfig;
            };
        } else if (std.mem.startsWith(u8, trimmed, "config_id ")) {
            const val = std.mem.trim(u8, trimmed["config_id ".len..], &std.ascii.whitespace);
            config.lb_config.config_id = std.fmt.parseInt(u3, val, 10) catch {
                std.log.err("invalid config_id: {s}", .{val});
                return error.InvalidConfig;
            };
        } else if (std.mem.startsWith(u8, trimmed, "server_id_len ")) {
            const val = std.mem.trim(u8, trimmed["server_id_len ".len..], &std.ascii.whitespace);
            config.lb_config.server_id_len = std.fmt.parseInt(u4, val, 10) catch {
                std.log.err("invalid server_id_len: {s}", .{val});
                return error.InvalidConfig;
            };
        } else if (std.mem.startsWith(u8, trimmed, "nonce_len ")) {
            const val = std.mem.trim(u8, trimmed["nonce_len ".len..], &std.ascii.whitespace);
            config.lb_config.nonce_len = std.fmt.parseInt(u5, val, 10) catch {
                std.log.err("invalid nonce_len: {s}", .{val});
                return error.InvalidConfig;
            };
        } else if (std.mem.startsWith(u8, trimmed, "key ")) {
            const hex = std.mem.trim(u8, trimmed["key ".len..], &std.ascii.whitespace);
            if (hex.len != 32) {
                std.log.err("key must be 32 hex chars (16 bytes), got {d}", .{hex.len});
                return error.InvalidConfig;
            }
            var key: [16]u8 = undefined;
            _ = std.fmt.hexToBytes(&key, hex) catch {
                std.log.err("invalid hex key: {s}", .{hex});
                return error.InvalidConfig;
            };
            config.lb_config.key = key;
        } else if (std.mem.startsWith(u8, trimmed, "server ")) {
            const rest = std.mem.trim(u8, trimmed["server ".len..], &std.ascii.whitespace);
            // Parse: <server_id_hex> <backend_addr>
            const space_idx = std.mem.indexOf(u8, rest, " ") orelse {
                std.log.err("invalid server line: {s}", .{rest});
                return error.InvalidConfig;
            };
            const sid_hex = rest[0..space_idx];
            const addr_str = std.mem.trim(u8, rest[space_idx + 1 ..], &std.ascii.whitespace);

            if (config.server_count >= MAX_SERVERS) {
                std.log.err("too many servers (max {d})", .{MAX_SERVERS});
                return error.InvalidConfig;
            }

            var mapping = &config.servers[config.server_count];
            const sid_len = config.lb_config.server_id_len;
            if (sid_hex.len != @as(usize, sid_len) * 2) {
                std.log.err("server_id hex length mismatch: expected {d} chars, got {d}", .{ @as(usize, sid_len) * 2, sid_hex.len });
                return error.InvalidConfig;
            }
            _ = std.fmt.hexToBytes(mapping.server_id[0..sid_len], sid_hex) catch {
                std.log.err("invalid server_id hex: {s}", .{sid_hex});
                return error.InvalidConfig;
            };
            mapping.server_id_len = sid_len;
            mapping.addr = parseAddress(addr_str) orelse {
                std.log.err("invalid server address: {s}", .{addr_str});
                return error.InvalidConfig;
            };
            config.server_count += 1;
        }
    }

    return config;
}

fn parseAddress(addr_str: []const u8) ?net.Address {
    // Find last ':' for port separator
    const colon_idx = std.mem.lastIndexOf(u8, addr_str, ":") orelse return null;
    const host = addr_str[0..colon_idx];
    const port_str = addr_str[colon_idx + 1 ..];
    const port = std.fmt.parseInt(u16, port_str, 10) catch return null;

    // Try IPv4
    const ipv4 = net.Address.parseIp4(host, port) catch {
        // Try IPv6
        return net.Address.parseIp6(host, port) catch null;
    };
    return ipv4;
}

fn findBackend(config: *const LbConfig, server_id: []const u8) ?net.Address {
    const sid_len: usize = @as(usize, config.lb_config.server_id_len);
    for (config.servers[0..config.server_count]) |mapping| {
        if (std.mem.eql(u8, mapping.server_id[0..sid_len], server_id[0..sid_len])) {
            return mapping.addr;
        }
    }
    return null;
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Parse command-line args
    var args = std.process.args();
    _ = args.next(); // skip program name
    const config_path = args.next() orelse {
        std.log.err("usage: quic-lb <config-file>", .{});
        return;
    };

    const config = parseConfigFile(config_path, allocator) catch |err| {
        std.log.err("failed to parse config: {any}", .{err});
        return;
    };

    std.log.info("QUIC-LB: config_id={d}, server_id_len={d}, nonce_len={d}, encrypted={}", .{
        config.lb_config.config_id,
        config.lb_config.server_id_len,
        config.lb_config.nonce_len,
        config.lb_config.key != null,
    });
    std.log.info("QUIC-LB: {d} backend server(s) configured", .{config.server_count});

    // Create UDP socket
    const sock = try posix.socket(posix.AF.INET, posix.SOCK.DGRAM | posix.SOCK.NONBLOCK, 0);
    defer posix.close(sock);

    // Bind to listen address
    try posix.bind(sock, &config.listen_addr.any, config.listen_addr.getOsSockLen());
    std.log.info("QUIC-LB: listening on port {d}", .{config.listen_addr.getPort()});

    // Client mappings for return traffic
    var client_mappings: [MAX_CLIENTS]ClientMapping = .{ClientMapping{}} ** MAX_CLIENTS;

    var recv_buf: [MAX_PACKET_SIZE]u8 = undefined;
    var src_addr: posix.sockaddr.storage = std.mem.zeroes(posix.sockaddr.storage);
    var addr_len: posix.socklen_t = @sizeOf(posix.sockaddr.storage);

    while (true) {
        // Try to receive a packet
        addr_len = @sizeOf(posix.sockaddr.storage);
        const recv_result = posix.recvfrom(sock, &recv_buf, 0, @ptrCast(&src_addr), &addr_len);
        const n = recv_result catch |err| {
            if (err == error.WouldBlock) {
                // No data, sleep briefly
                std.Thread.sleep(1_000_000); // 1ms
                continue;
            }
            std.log.err("recvfrom error: {any}", .{err});
            continue;
        };

        if (n < 1) continue;

        const now: i64 = @intCast(std.time.nanoTimestamp());

        // Check if this is from a known backend (return traffic)
        if (findClientForBackend(&client_mappings, &src_addr)) |client_entry| {
            // Forward back to client
            const client_sa: *const posix.sockaddr = @ptrCast(&client_entry.client_addr);
            const client_addr_len: posix.socklen_t = if (client_entry.client_addr.family == posix.AF.INET6)
                @sizeOf(posix.sockaddr.in6)
            else
                @sizeOf(posix.sockaddr.in);
            _ = posix.sendto(sock, recv_buf[0..n], 0, client_sa, client_addr_len) catch |err| {
                std.log.err("sendto client error: {any}", .{err});
                continue;
            };
            continue;
        }

        // This is from a client — extract server_id from CID
        // QUIC long header: byte 0 has form bit (1), then DCID starts at offset 6 (after version+len)
        // QUIC short header: byte 0 has form bit (0), DCID starts at offset 1
        const is_long_header = (recv_buf[0] & 0x80) != 0;

        var dcid_offset: usize = undefined;
        var dcid_len: usize = undefined;

        if (is_long_header) {
            // Long header: byte 5 = DCID length, DCID starts at byte 6
            if (n < 6) continue;
            dcid_len = recv_buf[5];
            dcid_offset = 6;
            if (n < dcid_offset + dcid_len) continue;
        } else {
            // Short header: DCID starts at byte 1, length from config
            dcid_len = quic_lb.cidLength(&config.lb_config);
            dcid_offset = 1;
            if (n < dcid_offset + dcid_len) continue;
        }

        const dcid = recv_buf[dcid_offset .. dcid_offset + dcid_len];

        // Check config_id matches
        if (dcid.len < 1) continue;
        const pkt_config_id = quic_lb.extractConfigId(dcid[0]);
        if (pkt_config_id != config.lb_config.config_id) {
            std.log.warn("unknown config_id {d} in packet, dropping", .{pkt_config_id});
            continue;
        }

        // Extract server_id
        var server_id: [15]u8 = undefined;
        if (!quic_lb.extractServerId(&config.lb_config, dcid, &server_id)) {
            std.log.warn("failed to extract server_id from CID, dropping", .{});
            continue;
        }

        // Look up backend
        const backend_addr = findBackend(&config, &server_id) orelse {
            std.log.warn("no backend for server_id (first 2 bytes: {x:0>2}{x:0>2})", .{ server_id[0], server_id[1] });
            continue;
        };

        // Store client → backend mapping for return traffic
        storeClientMapping(&client_mappings, &src_addr, &backend_addr.any, now);

        // Forward to backend
        _ = posix.sendto(sock, recv_buf[0..n], 0, &backend_addr.any, backend_addr.getOsSockLen()) catch |err| {
            std.log.err("sendto backend error: {any}", .{err});
            continue;
        };
    }
}

fn findClientForBackend(mappings: []ClientMapping, backend_addr: *const posix.sockaddr.storage) ?*ClientMapping {
    for (mappings) |*m| {
        if (m.occupied and sockaddrEql(&m.backend_addr, backend_addr)) {
            return m;
        }
    }
    return null;
}

fn storeClientMapping(mappings: []ClientMapping, client_addr: *const posix.sockaddr.storage, backend_addr: *const posix.sockaddr, now: i64) void {
    // Try to find existing or empty slot
    var oldest_idx: usize = 0;
    var oldest_time: i64 = std.math.maxInt(i64);

    for (mappings, 0..) |*m, i| {
        if (!m.occupied) {
            m.occupied = true;
            m.client_addr = client_addr.*;
            @memcpy(std.mem.asBytes(&m.backend_addr)[0..@sizeOf(posix.sockaddr)], std.mem.asBytes(backend_addr));
            m.last_seen = now;
            return;
        }
        if (sockaddrEql(&m.client_addr, client_addr)) {
            // Update existing mapping
            @memcpy(std.mem.asBytes(&m.backend_addr)[0..@sizeOf(posix.sockaddr)], std.mem.asBytes(backend_addr));
            m.last_seen = now;
            return;
        }
        if (m.last_seen < oldest_time) {
            oldest_time = m.last_seen;
            oldest_idx = i;
        }
    }

    // Evict oldest
    mappings[oldest_idx].occupied = true;
    mappings[oldest_idx].client_addr = client_addr.*;
    @memcpy(std.mem.asBytes(&mappings[oldest_idx].backend_addr)[0..@sizeOf(posix.sockaddr)], std.mem.asBytes(backend_addr));
    mappings[oldest_idx].last_seen = now;
}

fn sockaddrEql(a: *const posix.sockaddr.storage, b: *const posix.sockaddr.storage) bool {
    if (a.family != b.family) return false;
    if (a.family == posix.AF.INET) {
        const sa: *const posix.sockaddr.in = @ptrCast(@alignCast(a));
        const sb: *const posix.sockaddr.in = @ptrCast(@alignCast(b));
        return sa.port == sb.port and sa.addr == sb.addr;
    } else if (a.family == posix.AF.INET6) {
        const sa: *const posix.sockaddr.in6 = @ptrCast(@alignCast(a));
        const sb: *const posix.sockaddr.in6 = @ptrCast(@alignCast(b));
        return sa.port == sb.port and std.mem.eql(u8, &sa.addr, &sb.addr);
    }
    return false;
}
