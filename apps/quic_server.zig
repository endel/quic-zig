const std = @import("std");
const quic = @import("quic");
const event_loop = quic.event_loop;

const QuicEchoHandler = struct {
    pub const protocol: event_loop.Protocol = .quic;

    pub fn onStreamData(_: *QuicEchoHandler, session: *event_loop.Session, stream_id: u64, data: []const u8, fin: bool) void {
        if (data.len > 0) {
            std.log.info("stream {d} received: {s}", .{ stream_id, data });
            // Echo back
            session.writeStream(stream_id, data) catch |err| {
                std.log.err("writeStream error: {any}", .{err});
                return;
            };
            std.log.info("stream {d} echoed {d} bytes", .{ stream_id, data.len });
        }
        if (fin) {
            session.closeQuicStream(stream_id);
            std.log.info("stream {d} finished", .{stream_id});
        }
    }
};

pub fn main() !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    var port: u16 = 4434;
    var args = std.process.args();
    _ = args.next();
    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--port")) {
            if (args.next()) |v| port = std.fmt.parseInt(u16, v, 10) catch 4434;
        }
    }

    var handler = QuicEchoHandler{};
    var server = try event_loop.Server(QuicEchoHandler).init(alloc, &handler, .{
        .port = port,
        .cert_path = "interop/certs/server.crt",
        .key_path = "interop/certs/server.key",
    });
    defer server.deinit();

    std.log.info("QUIC echo server listening on 127.0.0.1:{d}", .{port});
    try server.run();
}
