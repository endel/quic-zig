const std = @import("std");
const quic = @import("quic");
const event_loop = quic.event_loop;

pub const std_options: std.Options = .{
    .log_level = .err,
};

const EchoHandler = struct {
    pub const protocol: event_loop.Protocol = .webtransport;

    pub fn onConnectRequest(_: *EchoHandler, session: *event_loop.Session, session_id: u64, path: []const u8) void {
        std.log.info("WT session request (id={d}, path={s})", .{ session_id, path });
        session.acceptSession(session_id) catch |err| {
            std.log.err("WT accept error: {any}", .{err});
            return;
        };
    }

    pub fn onSessionReady(_: *EchoHandler, _: *event_loop.Session, sid: u64) void {
        std.log.info("WT session {d} ready", .{sid});
    }

    pub fn onStreamData(_: *EchoHandler, session: *event_loop.Session, stream_id: u64, data: []const u8, fin: bool) void {
        if (data.len > 0) {
            var echo_buf: [1024]u8 = undefined;
            const echo_msg = std.fmt.bufPrint(&echo_buf, "Echo: {s}", .{data}) catch return;
            session.sendStreamData(stream_id, echo_msg) catch return;
        }
        if (fin) {
            session.closeStream(stream_id);
        }
    }

    pub fn onDatagram(_: *EchoHandler, session: *event_loop.Session, session_id: u64, data: []const u8) void {
        std.log.info("WT datagram session {d}: {s}", .{ session_id, data });
        var echo_buf: [1024]u8 = undefined;
        const echo_msg = std.fmt.bufPrint(&echo_buf, "Echo: {s}", .{data}) catch return;
        session.sendDatagram(session_id, echo_msg) catch |err| {
            std.log.err("sendDatagram error: {any}", .{err});
        };
    }

    pub fn onSessionClosed(_: *EchoHandler, _: *event_loop.Session, session_id: u64, error_code: u32, reason: []const u8) void {
        std.log.info("WT session {d} closed (code={d}, reason={s})", .{ session_id, error_code, reason });
    }
};

pub fn main() !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const args = try std.process.argsAlloc(alloc);

    var cert_path: []const u8 = "/etc/letsencrypt/live/echo.web-transport.dev/fullchain.pem";
    var key_path: []const u8 = "/etc/letsencrypt/live/echo.web-transport.dev/privkey.pem";
    var port: u16 = 4433;

    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        if (std.mem.eql(u8, args[i], "--cert") and i + 1 < args.len) {
            i += 1;
            cert_path = args[i];
        } else if (std.mem.eql(u8, args[i], "--key") and i + 1 < args.len) {
            i += 1;
            key_path = args[i];
        } else if (std.mem.eql(u8, args[i], "--port") and i + 1 < args.len) {
            i += 1;
            port = std.fmt.parseInt(u16, args[i], 10) catch 4433;
        }
    }

    std.log.info("WebTransport echo server starting on 0.0.0.0:{d}", .{port});
    std.log.info("cert: {s}", .{cert_path});
    std.log.info("key:  {s}", .{key_path});

    var handler = EchoHandler{};
    var server = try event_loop.Server(EchoHandler).init(alloc, &handler, .{
        .address = "0.0.0.0",
        .port = port,
        .cert_path = cert_path,
        .key_path = key_path,
    });
    defer server.deinit();

    try server.run();
}
