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
const lb_envelope = @import("quic").lb_envelope;

const MAX_PACKET_SIZE: usize = 1500;
const MAX_SERVERS: usize = 256;
const MAX_CLIENTS: usize = 4096;

const CidFormat = enum { draft20, netcode };

/// Mapping: server_id (hex) → backend address
const ServerMapping = struct {
    server_id: [15]u8 = .{0} ** 15,
    server_id_len: u4 = 0,
    addr: net.Address,
};

/// Mapping: connection ID → client address (for return traffic)
/// We store the client's SCID (which becomes the server's DCID in responses)
const ClientMapping = struct {
    /// Client's SCID (the DCID the server will use when responding)
    cid: [20]u8 = .{0} ** 20,
    cid_len: u8 = 0,
    client_addr: posix.sockaddr.storage = std.mem.zeroes(posix.sockaddr.storage),
    backend_addr: posix.sockaddr.storage = std.mem.zeroes(posix.sockaddr.storage),
    occupied: bool = false,
    last_seen: i64 = 0,
};

const LbConfig = struct {
    listen_addr: net.Address = net.Address.initIp4(.{ 0, 0, 0, 0 }, 443),
    cid_format: CidFormat = .draft20,

    lb_config: quic_lb.Config = .{
        .config_id = 0,
        .server_id_len = 2,
        .nonce_len = 6,
    },
    netcode_config: quic_lb.NetcodeConfig = .{ .config_id = 0, .key = .{0} ** 16 },

    servers: [MAX_SERVERS]ServerMapping = undefined,
    server_count: usize = 0,

    // Retry offload (netcode mode): when true, the LB forces clients through
    // a Retry and validates tokens before forwarding.
    require_retry: bool = false,
    retry_key: [16]u8 = .{0} ** 16,

    // LB↔backend envelope framing. When `envelope_hmac_key` is non-null the
    // envelope is HMAC-authenticated end-to-end.
    envelope_enabled: bool = false,
    envelope_hmac_key: ?[32]u8 = null,
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
        } else if (std.mem.startsWith(u8, trimmed, "cid_format ")) {
            const val = std.mem.trim(u8, trimmed["cid_format ".len..], &std.ascii.whitespace);
            if (std.mem.eql(u8, val, "netcode")) {
                config.cid_format = .netcode;
                config.lb_config.server_id_len = quic_lb.NETCODE_SERVER_ID_LEN;
                config.lb_config.nonce_len = quic_lb.NETCODE_NONCE_LEN + quic_lb.NETCODE_RESERVED_LEN;
            } else if (std.mem.eql(u8, val, "draft20")) {
                config.cid_format = .draft20;
            } else {
                std.log.err("invalid cid_format: {s}", .{val});
                return error.InvalidConfig;
            }
        } else if (std.mem.startsWith(u8, trimmed, "netcode_key ")) {
            const hex = std.mem.trim(u8, trimmed["netcode_key ".len..], &std.ascii.whitespace);
            if (hex.len != 32) {
                std.log.err("netcode_key must be 32 hex chars, got {d}", .{hex.len});
                return error.InvalidConfig;
            }
            _ = std.fmt.hexToBytes(&config.netcode_config.key, hex) catch {
                std.log.err("invalid hex netcode_key", .{});
                return error.InvalidConfig;
            };
        } else if (std.mem.startsWith(u8, trimmed, "require_retry ")) {
            const val = std.mem.trim(u8, trimmed["require_retry ".len..], &std.ascii.whitespace);
            config.require_retry = std.mem.eql(u8, val, "true") or std.mem.eql(u8, val, "1");
        } else if (std.mem.startsWith(u8, trimmed, "retry_key ")) {
            const hex = std.mem.trim(u8, trimmed["retry_key ".len..], &std.ascii.whitespace);
            if (hex.len != 32) {
                std.log.err("retry_key must be 32 hex chars", .{});
                return error.InvalidConfig;
            }
            _ = std.fmt.hexToBytes(&config.retry_key, hex) catch {
                std.log.err("invalid hex retry_key", .{});
                return error.InvalidConfig;
            };
        } else if (std.mem.startsWith(u8, trimmed, "envelope_hmac_key ")) {
            const hex = std.mem.trim(u8, trimmed["envelope_hmac_key ".len..], &std.ascii.whitespace);
            if (hex.len != 64) {
                std.log.err("envelope_hmac_key must be 64 hex chars (32 bytes)", .{});
                return error.InvalidConfig;
            }
            var key: [32]u8 = undefined;
            _ = std.fmt.hexToBytes(&key, hex) catch {
                std.log.err("invalid hex envelope_hmac_key", .{});
                return error.InvalidConfig;
            };
            config.envelope_hmac_key = key;
            config.envelope_enabled = true;
        } else if (std.mem.startsWith(u8, trimmed, "envelope_enabled ")) {
            const val = std.mem.trim(u8, trimmed["envelope_enabled ".len..], &std.ascii.whitespace);
            config.envelope_enabled = std.mem.eql(u8, val, "true") or std.mem.eql(u8, val, "1");
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

fn findBackendIndex(config: *const LbConfig, server_id: [quic_lb.NETCODE_SERVER_ID_LEN]u8) ?u16 {
    const sid_len: usize = quic_lb.NETCODE_SERVER_ID_LEN;
    for (config.servers[0..config.server_count], 0..) |mapping, i| {
        if (mapping.server_id_len >= sid_len and
            std.mem.eql(u8, mapping.server_id[0..sid_len], &server_id))
        {
            return @intCast(i);
        }
    }
    return null;
}

// --- Minimal QUIC Initial / Retry wire helpers for the LB ---

const Initial = struct {
    version: u32,
    dcid: []const u8,
    scid: []const u8,
    token: []const u8,
    // Offset at which "Length" varint begins (for decrypting pkt number).
    // Unused for retry-offload.
    length_off: usize = 0,
};

fn parseInitial(pkt: []const u8) ?Initial {
    if (pkt.len < 7) return null;
    // First byte: 0x80 form | 0x40 fixed | 0x00 type(Initial) | PN-len bits
    if ((pkt[0] & 0xC0) != 0xC0) return null;
    // Long packet type bits 5-4: 00=Initial. 01=0-RTT, 10=Handshake, 11=Retry.
    if ((pkt[0] & 0x30) != 0x00) return null;

    const version = std.mem.readInt(u32, pkt[1..5], .big);
    if (version == 0) return null; // Version negotiation

    var i: usize = 5;
    if (i >= pkt.len) return null;
    const dcid_len = pkt[i];
    i += 1;
    if (dcid_len > 20 or i + dcid_len > pkt.len) return null;
    const dcid = pkt[i..][0..dcid_len];
    i += dcid_len;

    if (i >= pkt.len) return null;
    const scid_len = pkt[i];
    i += 1;
    if (scid_len > 20 or i + scid_len > pkt.len) return null;
    const scid = pkt[i..][0..scid_len];
    i += scid_len;

    // Token length varint
    const tok_len = readVarInt(pkt, &i) orelse return null;
    if (tok_len > 1024 or i + tok_len > pkt.len) return null;
    const token = pkt[i..][0..@intCast(tok_len)];
    i += @intCast(tok_len);

    return .{ .version = version, .dcid = dcid, .scid = scid, .token = token, .length_off = i };
}

fn readVarInt(buf: []const u8, pos: *usize) ?u64 {
    if (pos.* >= buf.len) return null;
    const first = buf[pos.*];
    const len_bits = first >> 6;
    const len: usize = @as(usize, 1) << @intCast(len_bits);
    if (pos.* + len > buf.len) return null;
    var v: u64 = first & 0x3F;
    var j: usize = 1;
    while (j < len) : (j += 1) {
        v = (v << 8) | buf[pos.* + j];
    }
    pos.* += len;
    return v;
}

// --- Retry packet construction ---
// Matches the existing quic.packet.retry builder; inlined here so the LB
// binary doesn't need to depend on the QUIC packet module's mutable Header.

const RETRY_INTEGRITY_KEY_V1: [16]u8 = .{ 0xbe, 0x0c, 0x69, 0x0b, 0x9f, 0x66, 0x57, 0x5a, 0x1d, 0x76, 0x6b, 0x54, 0xe3, 0x68, 0xc8, 0x4e };
const RETRY_INTEGRITY_NONCE_V1: [12]u8 = .{ 0x46, 0x15, 0x99, 0xd3, 0x5d, 0x63, 0x2b, 0xf2, 0x23, 0x98, 0x25, 0xbb };

/// Build a Retry packet in `out` in response to `initial`. `retry_scid`
/// becomes the client's next DCID; the token is opaque to the client.
fn buildRetryPacket(
    out: []u8,
    initial: Initial,
    retry_scid: []const u8,
    token: []const u8,
) !usize {
    var i: usize = 0;
    if (out.len < 1 + 4 + 1 + initial.scid.len + 1 + retry_scid.len + token.len + 16) return error.BufferTooSmall;

    // First byte: long(0x80) | fixed(0x40) | retry type(0x30) | unused 4 bits (random)
    out[i] = 0xC0 | 0x30;
    i += 1;
    std.mem.writeInt(u32, out[i..][0..4], initial.version, .big);
    i += 4;
    out[i] = @intCast(initial.scid.len);
    i += 1;
    @memcpy(out[i..][0..initial.scid.len], initial.scid);
    i += initial.scid.len;
    out[i] = @intCast(retry_scid.len);
    i += 1;
    @memcpy(out[i..][0..retry_scid.len], retry_scid);
    i += retry_scid.len;
    @memcpy(out[i..][0..token.len], token);
    i += token.len;

    // Retry integrity tag over pseudo-packet = ODCID-length(1) || ODCID || Retry packet body
    var pseudo: [256]u8 = undefined;
    var pp: usize = 0;
    pseudo[pp] = @intCast(initial.dcid.len);
    pp += 1;
    @memcpy(pseudo[pp..][0..initial.dcid.len], initial.dcid);
    pp += initial.dcid.len;
    @memcpy(pseudo[pp..][0..i], out[0..i]);
    pp += i;

    var tag: [16]u8 = undefined;
    const AesGcm = std.crypto.aead.aes_gcm.Aes128Gcm;
    AesGcm.encrypt(
        &[_]u8{}, // no ciphertext output
        &tag,
        &[_]u8{}, // empty plaintext
        pseudo[0..pp],
        RETRY_INTEGRITY_NONCE_V1,
        RETRY_INTEGRITY_KEY_V1,
    );
    @memcpy(out[i..][0..16], &tag);
    i += 16;
    return i;
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

    std.log.info("QUIC-LB: cid_format={s}, config_id={d}, server_id_len={d}, nonce_len={d}, encrypted={}", .{
        @tagName(config.cid_format),
        config.lb_config.config_id,
        config.lb_config.server_id_len,
        config.lb_config.nonce_len,
        config.lb_config.key != null,
    });
    std.log.info("QUIC-LB: require_retry={}, envelope_enabled={}, hmac_auth={}", .{
        config.require_retry,
        config.envelope_enabled,
        config.envelope_hmac_key != null,
    });
    std.log.info("QUIC-LB: {d} backend server(s) configured", .{config.server_count});

    // Optional retry service (netcode mode only)
    var retry_svc: ?quic_lb.RetryService = null;
    if (config.require_retry and config.cid_format == .netcode) {
        retry_svc = try quic_lb.RetryService.init(allocator, config.retry_key, null, quic_lb.DEFAULT_NONCE_CACHE_CAPACITY);
    }
    defer if (retry_svc) |*svc| svc.deinit(allocator);

    // Create UDP socket
    const sock = try posix.socket(posix.AF.INET, posix.SOCK.DGRAM | posix.SOCK.NONBLOCK, 0);
    defer posix.close(sock);

    // Bind to listen address
    try posix.bind(sock, &config.listen_addr.any, config.listen_addr.getOsSockLen());
    std.log.info("QUIC-LB: listening on port {d}", .{config.listen_addr.getPort()});

    // Client mappings for return traffic
    var client_mappings: [MAX_CLIENTS]ClientMapping = .{ClientMapping{}} ** MAX_CLIENTS;

    var next_rr: usize = 0; // round-robin index for Initial packets
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
        if (isFromBackend(&config, &src_addr)) {
            // Find client by: 1) DCID in response, 2) fallback to backend address
            const resp_dcid = extractDcid(recv_buf[0..n]);
            const client_entry = if (resp_dcid) |dcid|
                findClientByCid(&client_mappings, dcid) orelse findMappingForBackend(&client_mappings, &src_addr)
            else
                findMappingForBackend(&client_mappings, &src_addr);

            if (client_entry) |entry| {
                const client_sa: *const posix.sockaddr = @ptrCast(&entry.client_addr);
                const client_addr_len: posix.socklen_t = if (entry.client_addr.family == posix.AF.INET6)
                    @sizeOf(posix.sockaddr.in6)
                else
                    @sizeOf(posix.sockaddr.in);
                _ = posix.sendto(sock, recv_buf[0..n], 0, client_sa, client_addr_len) catch |err| {
                    std.log.err("sendto client error: {any}", .{err});
                    continue;
                };
            }
            continue;
        }

        // From a client. Route based on CID format.
        const is_long_header = (recv_buf[0] & 0x80) != 0;

        var backend_addr: ?net.Address = null;
        var backend_id: u16 = 0;

        if (config.cid_format == .netcode) {
            // Netcode path: LB can perform retry offload. Try to extract a
            // backend routing hint from the DCID first.
            var dcid_offset: usize = undefined;
            var dcid_len: usize = undefined;
            if (is_long_header) {
                if (n < 6) continue;
                dcid_len = recv_buf[5];
                dcid_offset = 6;
                if (n < dcid_offset + dcid_len) continue;
            } else {
                dcid_len = quic_lb.NETCODE_CID_LEN;
                dcid_offset = 1;
                if (n < dcid_offset + dcid_len) continue;
            }
            const dcid = recv_buf[dcid_offset .. dcid_offset + dcid_len];

            // If DCID is a netcode-format CID, decode it and route.
            if (dcid.len >= quic_lb.NETCODE_CID_LEN) {
                var sid: [quic_lb.NETCODE_SERVER_ID_LEN]u8 = undefined;
                if (quic_lb.extractNetcodeServerId(&config.netcode_config, dcid, &sid)) {
                    if (findBackendIndex(&config, sid)) |idx| {
                        backend_addr = config.servers[idx].addr;
                        backend_id = idx;
                    }
                }
            }

            // Retry-offload: intercept Initial packets.
            if (is_long_header) {
                const initial_opt = parseInitial(recv_buf[0..n]);
                if (initial_opt) |initial| {
                    if (retry_svc) |*svc| {
                        if (initial.token.len == 0) {
                            // No token → mint Retry.
                            // Choose backend: CID-routed if we already have one,
                            // else round-robin.
                            if (backend_addr == null) {
                                if (config.server_count == 0) continue;
                                backend_id = @intCast(next_rr);
                                next_rr = (next_rr + 1) % config.server_count;
                                backend_addr = config.servers[backend_id].addr;
                            }

                            // Mint new retry SCID for chosen backend.
                            var retry_scid: [quic_lb.NETCODE_CID_LEN]u8 = undefined;
                            var sid_bytes: [quic_lb.NETCODE_SERVER_ID_LEN]u8 = undefined;
                            @memcpy(&sid_bytes, config.servers[backend_id].server_id[0..quic_lb.NETCODE_SERVER_ID_LEN]);
                            quic_lb.generateNetcodeCid(&config.netcode_config, sid_bytes, &retry_scid);

                            // Mint retry token.
                            var tok_buf: [quic_lb.RETRY_TOKEN_MAX_LEN]u8 = undefined;
                            const tok_len = svc.mintToken(&tok_buf, initial.dcid, &retry_scid, backend_id, src_addr) catch {
                                std.log.warn("retry mint failed", .{});
                                continue;
                            };

                            // Build Retry packet.
                            var retry_buf: [1500]u8 = undefined;
                            const retry_len = buildRetryPacket(&retry_buf, initial, &retry_scid, tok_buf[0..tok_len]) catch {
                                std.log.warn("buildRetryPacket failed", .{});
                                continue;
                            };

                            const src_len: posix.socklen_t = if (src_addr.family == posix.AF.INET6)
                                @sizeOf(posix.sockaddr.in6)
                            else
                                @sizeOf(posix.sockaddr.in);
                            _ = posix.sendto(sock, retry_buf[0..retry_len], 0, @ptrCast(&src_addr), src_len) catch |err| {
                                std.log.warn("sendto retry failed: {any}", .{err});
                            };
                            continue;
                        }

                        // Has token → validate.
                        const validated = svc.consumeToken(initial.token, src_addr) catch |err| {
                            std.log.warn("retry token invalid: {any}", .{err});
                            continue;
                        };

                        if (validated.backend_id >= config.server_count) {
                            std.log.warn("retry token backend_id={d} out of range", .{validated.backend_id});
                            continue;
                        }
                        backend_id = validated.backend_id;
                        backend_addr = config.servers[backend_id].addr;

                        // Forward as enveloped datagram carrying ODCID + retry_scid.
                        const dest_ok = backend_addr.?;
                        var envelope_buf: [MAX_PACKET_SIZE + 128]u8 = undefined;
                        const env_len = lb_envelope.encode(
                            &envelope_buf,
                            validated.odcid(),
                            validated.retryScid(),
                            true,
                            config.envelope_hmac_key,
                            recv_buf[0..n],
                        ) catch {
                            std.log.warn("envelope encode failed", .{});
                            continue;
                        };

                        storeClientMapping(&client_mappings, initial.scid, &src_addr, &dest_ok.any, now);

                        _ = posix.sendto(sock, envelope_buf[0..env_len], 0, &dest_ok.any, dest_ok.getOsSockLen()) catch |err| {
                            std.log.warn("sendto backend (enveloped) failed: {any}", .{err});
                        };
                        continue;
                    }
                }
            }

            // Non-Initial netcode packet (or retry disabled): CID-routed.
            if (backend_addr == null) {
                if (findMappingForClient(&client_mappings, &src_addr)) |existing| {
                    for (config.servers[0..config.server_count]) |mapping| {
                        if (sockaddrEql(&existing.backend_addr, &addrToStorage(&mapping.addr.any))) {
                            backend_addr = mapping.addr;
                            break;
                        }
                    }
                }
                if (backend_addr == null and config.server_count > 0) {
                    backend_addr = config.servers[next_rr].addr;
                    next_rr = (next_rr + 1) % config.server_count;
                }
            }
            const dest = backend_addr orelse continue;

            if (is_long_header and n > dcid_offset + dcid_len + 1) {
                const scid_len_pos = dcid_offset + dcid_len;
                const scid_len_val = recv_buf[scid_len_pos];
                if (n > scid_len_pos + 1 + scid_len_val) {
                    const scid = recv_buf[scid_len_pos + 1 .. scid_len_pos + 1 + scid_len_val];
                    storeClientMapping(&client_mappings, scid, &src_addr, &dest.any, now);
                }
            }

            _ = posix.sendto(sock, recv_buf[0..n], 0, &dest.any, dest.getOsSockLen()) catch |err| {
                std.log.err("sendto backend error: {any}", .{err});
                continue;
            };
            continue;
        }

        // --- draft20 path (unchanged) ---
        var dcid_offset: usize = undefined;
        var dcid_len: usize = undefined;

        if (is_long_header) {
            if (n < 6) continue;
            dcid_len = recv_buf[5];
            dcid_offset = 6;
            if (n < dcid_offset + dcid_len) continue;
        } else {
            dcid_len = quic_lb.cidLength(&config.lb_config);
            dcid_offset = 1;
            if (n < dcid_offset + dcid_len) continue;
        }

        const dcid = recv_buf[dcid_offset .. dcid_offset + dcid_len];

        if (dcid.len >= quic_lb.cidLength(&config.lb_config)) {
            var server_id: [15]u8 = undefined;
            if (quic_lb.extractServerId(&config.lb_config, dcid, &server_id)) {
                backend_addr = findBackend(&config, &server_id);
            }
        }

        if (backend_addr == null) {
            if (findMappingForClient(&client_mappings, &src_addr)) |existing| {
                for (config.servers[0..config.server_count]) |mapping| {
                    if (sockaddrEql(&existing.backend_addr, &addrToStorage(&mapping.addr.any))) {
                        backend_addr = mapping.addr;
                        break;
                    }
                }
            }
            if (backend_addr == null and config.server_count > 0) {
                backend_addr = config.servers[next_rr].addr;
                next_rr = (next_rr + 1) % config.server_count;
            }
        }

        const dest = backend_addr orelse continue;

        if (is_long_header and n > dcid_offset + dcid_len + 1) {
            const scid_len_pos = dcid_offset + dcid_len;
            const scid_len_val = recv_buf[scid_len_pos];
            if (n > scid_len_pos + 1 + scid_len_val) {
                const scid = recv_buf[scid_len_pos + 1 .. scid_len_pos + 1 + scid_len_val];
                storeClientMapping(&client_mappings, scid, &src_addr, &dest.any, now);
            }
        }

        _ = posix.sendto(sock, recv_buf[0..n], 0, &dest.any, dest.getOsSockLen()) catch |err| {
            std.log.err("sendto backend error: {any}", .{err});
            continue;
        };
    }
}

fn isFromBackend(config: *const LbConfig, addr: *const posix.sockaddr.storage) bool {
    const src_port = std.mem.readInt(u16, std.mem.asBytes(addr)[2..4], .big);
    for (config.servers[0..config.server_count]) |mapping| {
        if (mapping.addr.getPort() == src_port) {
            std.log.info("LB: return traffic from backend port {d}", .{src_port});
            return true;
        }
    }
    std.log.debug("LB: packet from port {d} (not a backend)", .{src_port});
    return false;
}

fn extractDcid(pkt: []const u8) ?[]const u8 {
    if (pkt.len < 2) return null;
    if (pkt[0] & 0x80 != 0) {
        // Long header: DCID len at byte 5, DCID at byte 6
        if (pkt.len < 6) return null;
        const dcid_len = pkt[5];
        if (pkt.len < 6 + dcid_len) return null;
        return pkt[6 .. 6 + dcid_len];
    } else {
        // Short header: DCID at byte 1, but we don't know the length.
        // Use the client's known CID length — typically 8 bytes for our implementation.
        const dcid_len: usize = @min(8, pkt.len - 1);
        return pkt[1 .. 1 + dcid_len];
    }
}

fn findClientByCid(mappings: []ClientMapping, dcid: []const u8) ?*ClientMapping {
    for (mappings) |*m| {
        if (m.occupied and m.cid_len > 0 and m.cid_len <= dcid.len) {
            if (std.mem.eql(u8, m.cid[0..m.cid_len], dcid[0..m.cid_len])) return m;
        }
    }
    if (dcid.len >= 4) {
        const stored_cid = if (countOccupied(mappings) > 0) blk: {
            for (mappings) |*m| {
                if (m.occupied and m.cid_len > 0) break :blk m.cid[0..@min(4, m.cid_len)];
            }
            break :blk @as([]const u8, &.{});
        } else @as([]const u8, &.{});
        std.log.debug("LB: CID mismatch, dcid={x}, stored={x}", .{ dcid[0..@min(4, dcid.len)], stored_cid });
    }
    return null;
}

fn countOccupied(mappings: []const ClientMapping) usize {
    var n: usize = 0;
    for (mappings) |m| {
        if (m.occupied) n += 1;
    }
    return n;
}

fn findMappingForClient(mappings: []ClientMapping, client_addr: *const posix.sockaddr.storage) ?*ClientMapping {
    for (mappings) |*m| {
        if (m.occupied and sockaddrEql(&m.client_addr, client_addr)) return m;
    }
    return null;
}

fn findMappingForBackend(mappings: []ClientMapping, backend_addr: *const posix.sockaddr.storage) ?*ClientMapping {
    const src_port = std.mem.readInt(u16, std.mem.asBytes(backend_addr)[2..4], .big);
    var best: ?*ClientMapping = null;
    var best_time: i64 = 0;
    for (mappings) |*m| {
        if (m.occupied and m.last_seen >= best_time) {
            const m_port = std.mem.readInt(u16, std.mem.asBytes(&m.backend_addr)[2..4], .big);
            if (m_port == src_port) {
                best = m;
                best_time = m.last_seen;
            }
        }
    }
    return best;
}

fn storeClientMapping(mappings: []ClientMapping, client_scid: []const u8, client_addr: *const posix.sockaddr.storage, backend_addr: *const posix.sockaddr, now: i64) void {
    var oldest_idx: usize = 0;
    var oldest_time: i64 = std.math.maxInt(i64);

    for (mappings, 0..) |*m, i| {
        // Update existing by CID match
        if (m.occupied and m.cid_len > 0 and m.cid_len == client_scid.len and
            std.mem.eql(u8, m.cid[0..m.cid_len], client_scid))
        {
            m.client_addr = client_addr.*;
            @memcpy(std.mem.asBytes(&m.backend_addr)[0..@sizeOf(posix.sockaddr)], std.mem.asBytes(backend_addr));
            m.last_seen = now;
            return;
        }
        if (!m.occupied) {
            m.occupied = true;
            m.cid_len = @intCast(@min(client_scid.len, 20));
            @memcpy(m.cid[0..m.cid_len], client_scid[0..m.cid_len]);
            m.client_addr = client_addr.*;
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
    const m = &mappings[oldest_idx];
    m.occupied = true;
    m.cid_len = @intCast(@min(client_scid.len, 20));
    @memcpy(m.cid[0..m.cid_len], client_scid[0..m.cid_len]);
    m.client_addr = client_addr.*;
    @memcpy(std.mem.asBytes(&m.backend_addr)[0..@sizeOf(posix.sockaddr)], std.mem.asBytes(backend_addr));
    m.last_seen = now;
}

fn addrToStorage(sa: *const posix.sockaddr) posix.sockaddr.storage {
    var storage: posix.sockaddr.storage = std.mem.zeroes(posix.sockaddr.storage);
    const src = std.mem.asBytes(sa);
    const dst = std.mem.asBytes(&storage);
    const len: usize = if (sa.family == posix.AF.INET6) @sizeOf(posix.sockaddr.in6) else @sizeOf(posix.sockaddr.in);
    @memcpy(dst[0..len], src[0..len]);
    return storage;
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
