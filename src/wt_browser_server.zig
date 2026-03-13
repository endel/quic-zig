const std = @import("std");
const event_loop = @import("event_loop.zig");
const tls13 = @import("quic/tls13.zig");

const EchoHandler = struct {
    pub const protocol: event_loop.Protocol = .webtransport;

    pub fn onConnectRequest(_: *EchoHandler, session: *event_loop.Session, session_id: u64, path: []const u8) void {
        std.debug.print("WT session request (session_id={d}, path={s})\n", .{ session_id, path });
        session.acceptSession(session_id) catch |err| {
            std.log.err("WT accept error: {any}", .{err});
            return;
        };
        std.debug.print("WT session accepted (session_id={d})\n", .{session_id});
    }

    pub fn onSessionReady(_: *EchoHandler, _: *event_loop.Session, sid: u64) void {
        std.debug.print("WT: session {d} ready\n", .{sid});
    }

    pub fn onStreamData(_: *EchoHandler, session: *event_loop.Session, stream_id: u64, data: []const u8) void {
        std.debug.print("WT: stream {d} data: {s}\n", .{ stream_id, data });
        var echo_buf: [1024]u8 = undefined;
        const echo_msg = std.fmt.bufPrint(&echo_buf, "Echo: {s}", .{data}) catch return;
        session.sendStreamData(stream_id, echo_msg) catch |err| {
            std.log.err("WT sendStreamData error: {any}", .{err});
        };
        session.closeStream(stream_id);
    }

    pub fn onDatagram(_: *EchoHandler, session: *event_loop.Session, session_id: u64, data: []const u8) void {
        std.debug.print("WT: datagram from session {d}: {s}\n", .{ session_id, data });
        var echo_buf: [1024]u8 = undefined;
        const echo_msg = std.fmt.bufPrint(&echo_buf, "Echo: {s}", .{data}) catch return;
        session.sendDatagram(session_id, echo_msg) catch |err| {
            std.log.err("WT sendDatagram error: {any}", .{err});
        };
    }

    pub fn onSessionClosed(_: *EchoHandler, _: *event_loop.Session, session_id: u64, error_code: u32, reason: []const u8) void {
        std.debug.print("WT: session {d} closed (code={d}, reason={s})\n", .{ session_id, error_code, reason });
    }
};

pub fn main() !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    // Print certificate SHA-256 hash for browser pinning
    const server_cert_pem = try std.fs.cwd().readFileAlloc(alloc, "interop/browser/certs/server.crt", 8192);
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

    // Print as JS Uint8Array for easy copy-paste
    std.debug.print("JS: new Uint8Array([", .{});
    for (cert_hash, 0..) |byte, idx| {
        if (idx > 0) std.debug.print(", ", .{});
        std.debug.print("{d}", .{byte});
    }
    std.debug.print("])\n\n", .{});

    var handler = EchoHandler{};
    var server = try event_loop.Server(EchoHandler).init(alloc, &handler, .{
        .address = "0.0.0.0",
        .port = 4433,
        .cert_path = "interop/browser/certs/server.crt",
        .key_path = "interop/browser/certs/server.key",
    });
    defer server.deinit();

    std.debug.print("Listening on https://0.0.0.0:4433\n\n", .{});
    try server.run();
}
