const std = @import("std");
const quic = @import("quic");
const event_loop = quic.event_loop;

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

    // Parse --port argument
    var port: u16 = 4434;
    var args = std.process.args();
    _ = args.next(); // skip program name
    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--port")) {
            if (args.next()) |port_str| {
                port = std.fmt.parseInt(u16, port_str, 10) catch 4434;
            }
        }
    }

    var handler = EchoHandler{};
    var server = try event_loop.Server(EchoHandler).init(alloc, &handler, .{
        .port = port,
        .cert_path = "interop/certs/server.crt",
        .key_path = "interop/certs/server.key",
    });
    defer server.deinit();

    std.debug.print("WebTransport server listening on 127.0.0.1:{d}\n", .{port});
    try server.run();
}
