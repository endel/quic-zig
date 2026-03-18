const std = @import("std");
const quic = @import("quic");
const event_loop = quic.event_loop;
const qpack = quic.qpack;

const H3Client = struct {
    pub const protocol: event_loop.Protocol = .h3;

    alloc: std.mem.Allocator,
    got_response: bool = false,
    request_sent: bool = false,
    path: []const u8 = "/",

    pub fn onConnected(self: *H3Client, session: *event_loop.ClientSession) void {
        std.debug.print("H3 connection established\n", .{});

        const req_headers = [_]qpack.Header{
            .{ .name = ":method", .value = "GET" },
            .{ .name = ":scheme", .value = "https" },
            .{ .name = ":authority", .value = "localhost" },
            .{ .name = ":path", .value = self.path },
            .{ .name = "user-agent", .value = "quic-zig/1.0" },
        };
        const stream_id = session.sendRequest(&req_headers, null) catch |err| {
            std.debug.print("sendRequest error: {any}\n", .{err});
            return;
        };
        self.request_sent = true;
        std.debug.print("H3: sent GET {s} on stream {d}\n", .{ self.path, stream_id });
    }

    pub fn onHeaders(_: *H3Client, _: *event_loop.ClientSession, stream_id: u64, headers: []const qpack.Header) void {
        std.debug.print("H3: response headers on stream {d}:\n", .{stream_id});
        for (headers) |h| {
            std.debug.print("  {s}: {s}\n", .{ h.name, h.value });
        }
    }

    pub fn onData(self: *H3Client, session: *event_loop.ClientSession, stream_id: u64, len: usize) void {
        _ = stream_id;
        _ = len;
        var body_buf: [8192]u8 = undefined;
        while (true) {
            const n = session.recvBody(&body_buf);
            if (n == 0) break;
            std.debug.print("Response: {s}", .{body_buf[0..n]});
        }
        self.got_response = true;
    }

    pub fn onFinished(self: *H3Client, session: *event_loop.ClientSession, stream_id: u64) void {
        std.debug.print("H3: stream {d} finished\n", .{stream_id});
        if (self.got_response) {
            session.closeConnection();
        }
    }
};

pub fn main() !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    var port: u16 = 4434;
    var path: []const u8 = "/";
    var insecure = false;
    var args = std.process.args();
    _ = args.next();
    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--port")) {
            if (args.next()) |v| port = std.fmt.parseInt(u16, v, 10) catch 4434;
        } else if (std.mem.eql(u8, arg, "--path")) {
            if (args.next()) |v| path = v;
        } else if (std.mem.eql(u8, arg, "--insecure")) {
            insecure = true;
        }
    }

    std.debug.print("H3 client connecting to 127.0.0.1:{d}\n", .{port});

    var handler = H3Client{ .alloc = alloc, .path = path };
    var client = try event_loop.Client(H3Client).init(alloc, &handler, .{
        .port = port,
        .ca_cert_path = if (insecure) null else "interop/certs/ca.crt",
        .skip_cert_verify = insecure,
    });
    defer client.deinit();

    try client.run();
}
