const std = @import("std");
const event_loop = @import("event_loop.zig");
const qpack = @import("h3/qpack.zig");

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

    var handler = H3Handler{ .alloc = alloc };
    var server = try event_loop.Server(H3Handler).init(alloc, &handler, .{
        .port = 4434,
        .cert_path = "interop/certs/server.crt",
        .key_path = "interop/certs/server.key",
        .require_retry = true,
    });
    defer server.deinit();

    std.log.info("QUIC H3 server listening on 127.0.0.1:4434", .{});
    try server.run();
}

test {
    _ = @import("quic/connection.zig");
    _ = @import("quic/packet.zig");
    _ = @import("quic/protocol.zig");
    _ = @import("quic/frame.zig");
    _ = @import("quic/ranges.zig");
    _ = @import("quic/rtt.zig");
    _ = @import("quic/ack_handler.zig");
    _ = @import("quic/congestion.zig");
    _ = @import("quic/flow_control.zig");
    _ = @import("quic/transport_params.zig");
    _ = @import("quic/stream.zig");
    _ = @import("quic/crypto_stream.zig");
    _ = @import("quic/packet_packer.zig");
    _ = @import("quic/tls13.zig");
    _ = @import("quic/mtu.zig");
    _ = @import("quic/stateless_reset.zig");
    _ = @import("quic/connection_manager.zig");
    _ = @import("quic/ecn.zig");
    _ = @import("quic/ecn_socket.zig");
    _ = @import("h3/frame.zig");
    _ = @import("h3/qpack.zig");
    _ = @import("h3/huffman.zig");
    _ = @import("h3/connection.zig");
    _ = @import("webtransport/session.zig");
    _ = @import("h3/capsule.zig");
}
