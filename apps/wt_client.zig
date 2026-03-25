const std = @import("std");
const quic = @import("quic");
const event_loop = quic.event_loop;

const EchoClient = struct {
    pub const protocol: event_loop.Protocol = .webtransport;

    got_response: bool = false,

    pub fn onSessionReady(self: *EchoClient, session: *event_loop.ClientSession, session_id: u64) void {
        _ = self;
        std.debug.print("WebTransport session ready (session_id={d})\n", .{session_id});

        // Open a bidi stream and send data
        const stream_id = session.openBidiStream(session_id) catch |err| {
            std.debug.print("openBidiStream error: {any}\n", .{err});
            return;
        };
        const msg = "Hello from Zig WebTransport!";
        session.sendStreamData(stream_id, msg) catch |err| {
            std.debug.print("sendStreamData error: {any}\n", .{err});
            return;
        };
        session.closeStream(stream_id);
        std.debug.print("Sent on bidi stream {d}: {s}\n", .{ stream_id, msg });

        // Also send a datagram
        session.sendDatagram(session_id, "Hello via datagram!") catch |err| {
            std.debug.print("Datagram send failed: {any}\n", .{err});
            return;
        };
        std.debug.print("Sent datagram\n", .{});
    }

    pub fn onStreamData(self: *EchoClient, session: *event_loop.ClientSession, stream_id: u64, data: []const u8, _: bool) void {
        if (data.len == 0) return;
        std.debug.print("Response on stream {d}: {s}\n", .{ stream_id, data });
        self.got_response = true;
        session.closeConnection();
    }

    pub fn onDatagram(self: *EchoClient, session: *event_loop.ClientSession, session_id: u64, data: []const u8) void {
        std.debug.print("Datagram response (session={d}): {s}\n", .{ session_id, data });
        self.got_response = true;
        session.closeConnection();
    }

    pub fn onSessionRejected(_: *EchoClient, session: *event_loop.ClientSession, _: u64, status: []const u8) void {
        std.debug.print("WebTransport session rejected: {s}\n", .{status});
        session.closeConnection();
    }

    pub fn onSessionClosed(_: *EchoClient, _: *event_loop.ClientSession, session_id: u64, error_code: u32, reason: []const u8) void {
        std.debug.print("Session {d} closed (code={d}, reason={s})\n", .{ session_id, error_code, reason });
    }
};

pub fn main() !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    // Parse --port argument
    var port: u16 = 4434;
    var args = std.process.args();
    _ = args.next();
    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--port")) {
            if (args.next()) |port_str| {
                port = std.fmt.parseInt(u16, port_str, 10) catch 4434;
            }
        }
    }

    std.debug.print("WebTransport client connecting to 127.0.0.1:{d}\n", .{port});

    var handler = EchoClient{};
    var client = try event_loop.Client(EchoClient).init(alloc, &handler, .{
        .port = port,
        .ca_cert_path = "interop/certs/ca.crt",
    });
    defer client.deinit();

    try client.run();
}
