// Benchmark WebTransport echo server.
// Raw echo: no prefix, no stream close (supports multi-round-trip streams).
// Matches webtransport-bun's server.pipeTo() behavior for fair comparison.

const std = @import("std");
const quic = @import("quic");
const event_loop = quic.event_loop;

const RawEchoHandler = struct {
    pub const protocol: event_loop.Protocol = .webtransport;

    pub fn onConnectRequest(_: *RawEchoHandler, session: *event_loop.Session, session_id: u64, _: []const u8) void {
        session.acceptSession(session_id) catch return;
    }

    pub fn onSessionReady(_: *RawEchoHandler, _: *event_loop.Session, _: u64) void {}

    pub fn onStreamData(_: *RawEchoHandler, session: *event_loop.Session, stream_id: u64, data: []const u8, _: bool) void {
        if (data.len == 0) return;
        session.sendStreamData(stream_id, data) catch {};
        // Do NOT close stream - allows multi-round-trip benchmarks
    }

    pub fn onDatagram(_: *RawEchoHandler, session: *event_loop.Session, session_id: u64, data: []const u8) void {
        session.sendDatagram(session_id, data) catch {};
    }

    pub fn onSessionClosed(_: *RawEchoHandler, _: *event_loop.Session, _: u64, _: u32, _: []const u8) void {}
};

pub fn main(init: std.process.Init.Minimal) !void {
    // A server outlives its streams, so it needs an allocator that reuses what
    // they give back — an arena would grow for as long as the process runs.
    const alloc = std.heap.smp_allocator;

    var port: u16 = 4434;
    var cert_path: []const u8 = "interop/certs/server.crt";
    var key_path: []const u8 = "interop/certs/server.key";
    var args = quic.sys.argsIterator(init.args);
    _ = args.next();
    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--port")) {
            if (args.next()) |v| port = std.fmt.parseInt(u16, v, 10) catch 4434;
        } else if (std.mem.eql(u8, arg, "--cert")) {
            if (args.next()) |v| cert_path = v;
        } else if (std.mem.eql(u8, arg, "--key")) {
            if (args.next()) |v| key_path = v;
        }
    }

    var handler = RawEchoHandler{};
    var server = try event_loop.Server(RawEchoHandler).init(alloc, &handler, .{
        .port = port,
        .cert_path = cert_path,
        .key_path = key_path,
    });
    defer server.deinit();

    std.debug.print("Benchmark echo server on 127.0.0.1:{d}\n", .{port});
    try server.run();
}
