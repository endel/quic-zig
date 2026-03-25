const std = @import("std");
const quic = @import("quic");
const event_loop = quic.event_loop;

const QuicEchoClient = struct {
    pub const protocol: event_loop.Protocol = .quic;

    got_response: bool = false,
    stream_id: ?u64 = null,
    message: []const u8 = "Hello from Zig QUIC client!",

    pub fn onConnected(self: *QuicEchoClient, session: *event_loop.ClientSession) void {
        std.debug.print("QUIC connection established\n", .{});

        const sid = session.openStream() catch |err| {
            std.debug.print("openStream error: {any}\n", .{err});
            return;
        };
        self.stream_id = sid;

        session.writeStream(sid, self.message) catch |err| {
            std.debug.print("writeStream error: {any}\n", .{err});
            return;
        };
        session.closeQuicStream(sid);
        std.debug.print("Sent on stream {d}: {s}\n", .{ sid, self.message });
    }

    pub fn onStreamData(self: *QuicEchoClient, session: *event_loop.ClientSession, stream_id: u64, data: []const u8, fin: bool) void {
        if (data.len > 0) {
            std.debug.print("Response on stream {d}: {s}\n", .{ stream_id, data });
            self.got_response = true;
        }
        if (fin and self.got_response) {
            std.debug.print("Stream {d} finished\n", .{stream_id});
            session.closeConnection();
        }
    }
};

pub fn main() !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    var port: u16 = 4434;
    var insecure = false;
    var args = std.process.args();
    _ = args.next();
    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--port")) {
            if (args.next()) |v| port = std.fmt.parseInt(u16, v, 10) catch 4434;
        } else if (std.mem.eql(u8, arg, "--insecure")) {
            insecure = true;
        }
    }

    std.debug.print("QUIC echo client connecting to 127.0.0.1:{d}\n", .{port});

    var handler = QuicEchoClient{};
    var client = try event_loop.Client(QuicEchoClient).init(alloc, &handler, .{
        .port = port,
        .ca_cert_path = if (insecure) null else "interop/certs/ca.crt",
        .skip_cert_verify = insecure,
    });
    defer client.deinit();

    try client.run();
}
