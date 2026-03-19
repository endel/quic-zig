const std = @import("std");
const quic = @import("quic");
const event_loop = quic.event_loop;
const tls13 = quic.tls13;
const connection = quic.connection;
const quic_lb = quic.quic_lb;

const EchoHandler = struct {
    pub const protocol: event_loop.Protocol = .webtransport;
    pub fn onConnectRequest(_: *EchoHandler, session: *event_loop.Session, session_id: u64, _: []const u8) void {
        session.acceptSession(session_id) catch return;
    }

    pub fn onStreamData(_: *EchoHandler, session: *event_loop.Session, stream_id: u64, data: []const u8) void {
        if (data.len == 0) return;
        var echo_buf: [1024]u8 = undefined;
        const echo_msg = std.fmt.bufPrint(&echo_buf, "Echo: {s}", .{data}) catch return;
        session.sendStreamData(stream_id, echo_msg) catch return;
        session.closeStream(stream_id);
    }

    pub fn onDatagram(_: *EchoHandler, session: *event_loop.Session, session_id: u64, data: []const u8) void {
        var echo_buf: [1024]u8 = undefined;
        const echo_msg = std.fmt.bufPrint(&echo_buf, "Echo: {s}", .{data}) catch return;
        session.sendDatagram(session_id, echo_msg) catch return;
    }
};

pub fn main() !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    // Parse args
    var port: u16 = 4433;
    var cert_path: []const u8 = "interop/browser/certs/server.crt";
    var key_path: []const u8 = "interop/browser/certs/server.key";
    var server_id_hex: ?[]const u8 = null;
    var lb_key_hex: ?[]const u8 = null;

    var args = std.process.args();
    _ = args.next();
    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--port")) {
            if (args.next()) |v| port = std.fmt.parseInt(u16, v, 10) catch 4433;
        } else if (std.mem.eql(u8, arg, "--cert")) {
            if (args.next()) |v| cert_path = v;
        } else if (std.mem.eql(u8, arg, "--key")) {
            if (args.next()) |v| key_path = v;
        } else if (std.mem.eql(u8, arg, "--server-id")) {
            if (args.next()) |v| server_id_hex = v;
        } else if (std.mem.eql(u8, arg, "--lb-key")) {
            if (args.next()) |v| lb_key_hex = v;
        }
    }

    // Build QUIC-LB config if --server-id is provided
    var lb_config: ?quic_lb.Config = null;
    var conn_config: ?connection.ConnectionConfig = null;
    if (server_id_hex) |sid_hex| {
        var cfg = quic_lb.Config{
            .config_id = 0,
            .server_id_len = @intCast(sid_hex.len / 2),
            .nonce_len = 6,
        };
        _ = std.fmt.hexToBytes(cfg.server_id[0..cfg.server_id_len], sid_hex) catch {
            std.log.err("invalid --server-id hex: {s}", .{sid_hex});
            return;
        };
        if (lb_key_hex) |khex| {
            if (khex.len != 32) {
                std.log.err("--lb-key must be 32 hex chars", .{});
                return;
            }
            var key: [16]u8 = undefined;
            _ = std.fmt.hexToBytes(&key, khex) catch {
                std.log.err("invalid --lb-key hex", .{});
                return;
            };
            cfg.key = key;
        }
        lb_config = cfg;
        conn_config = .{ .quic_lb = cfg };
        std.debug.print("QUIC-LB: server_id={s}, nonce_len={d}, encrypted={}\n", .{
            sid_hex, cfg.nonce_len, cfg.key != null,
        });
    }

    // Print certificate SHA-256 hash for browser pinning
    const server_cert_pem = try std.fs.cwd().readFileAlloc(alloc, cert_path, 8192);
    var cert_der_buf: [4096]u8 = undefined;
    const cert_der = try tls13.parsePemCert(server_cert_pem, &cert_der_buf);

    var cert_hash: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(cert_der, &cert_hash, .{});
    std.debug.print("\n=== Browser WebTransport Server ===\n", .{});
    std.debug.print("Certificate SHA-256: ", .{});
    for (cert_hash) |byte| {
        std.debug.print("{x:0>2}", .{byte});
    }
    std.debug.print("\n", .{});

    std.debug.print("JS: new Uint8Array([", .{});
    for (cert_hash, 0..) |byte, idx| {
        if (idx > 0) std.debug.print(", ", .{});
        std.debug.print("{d}", .{byte});
    }
    std.debug.print("])\n\n", .{});

    var handler = EchoHandler{};
    var server = try event_loop.Server(EchoHandler).init(alloc, &handler, .{
        .address = "0.0.0.0",
        .port = port,
        .cert_path = cert_path,
        .key_path = key_path,
        .conn_config = conn_config,
        .http1 = .{ .static_dir = "interop/browser" },
    });
    defer server.deinit();

    std.debug.print("Listening on https://0.0.0.0:{d} (QUIC/WebTransport)\n", .{port});
    std.debug.print("Serving static files on https://0.0.0.0:{d} (HTTP/1.1+TLS)\n\n", .{port});
    try server.run();
}
