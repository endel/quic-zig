const std = @import("std");
const quic = @import("quic");
const event_loop = quic.event_loop;
const qpack = quic.qpack;

const H3Handler = struct {
    pub const protocol: event_loop.Protocol = .h3;

    alloc: std.mem.Allocator,

    pub fn onRequest(self: *H3Handler, session: *event_loop.Session, stream_id: u64, headers: []const qpack.Header) void {
        var method: []const u8 = "?";
        var path: []const u8 = "?";
        for (headers) |h_item| {
            std.log.info("  {s}: {s}", .{ h_item.name, h_item.value });
            if (std.mem.eql(u8, h_item.name, ":method")) method = h_item.value;
            if (std.mem.eql(u8, h_item.name, ":path")) path = h_item.value;
        }

        const body = std.fmt.allocPrint(self.alloc, "Hello from Zig HTTP/3 server! You requested {s} {s}\n", .{ method, path }) catch return;
        const resp_headers = [_]qpack.Header{
            .{ .name = ":status", .value = "200" },
            .{ .name = "content-type", .value = "text/plain" },
        };
        session.sendResponse(stream_id, &resp_headers, body) catch |err| {
            std.log.err("H3 sendResponse error: {any}", .{err});
        };
        std.log.info("H3: sent 200 response on stream {d}", .{stream_id});
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

    var handler = H3Handler{ .alloc = alloc };
    var server = try event_loop.Server(H3Handler).init(alloc, &handler, .{
        .port = port,
        .cert_path = "interop/certs/server.crt",
        .key_path = "interop/certs/server.key",
        .require_retry = true,
    });
    defer server.deinit();

    std.log.info("QUIC H3 server listening on 127.0.0.1:{d}", .{port});
    try server.run();
}
