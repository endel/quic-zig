//! WebSocket and WebTransport echo from one handler on one port: WebSocket
//! over TCP (the HTTP/1.1 listener), WebTransport over QUIC, both on the
//! same event loop.
//!
//!   zig build run-ws-echo-server -- [--port 4433] [--plain] [--static DIR]
//!                                   [--address 0.0.0.0] [--cert F --key F]
//!
//! `--plain` serves ws:// and http:// instead of wss:// and https://; it is
//! what the Autobahn test suite connects to. Message limits are raised for
//! its 16 MiB cases.

const std = @import("std");
const quic = @import("quic");
const event_loop = quic.event_loop;

pub const std_options: std.Options = .{
    .log_level = .err,
};

const EchoHandler = struct {
    pub const protocol: event_loop.Protocol = .webtransport;

    pub fn onWsUpgrade(_: *EchoHandler, req: *event_loop.WsRequest, _: []const u8) void {
        _ = req.accept(.{}) catch return;
    }

    pub fn onWsMessage(_: *EchoHandler, ws: *event_loop.WsConn, data: []const u8, kind: event_loop.WsMessageKind) void {
        switch (kind) {
            .binary => ws.send(data) catch {},
            .text => ws.sendText(data) catch {},
        }
    }

    pub fn onWsClose(_: *EchoHandler, _: *event_loop.WsConn, _: u16, _: []const u8) void {}

    pub fn onConnectRequest(_: *EchoHandler, session: *event_loop.Session, session_id: u64, _: []const u8) void {
        session.acceptSession(session_id) catch return;
    }

    pub fn onStreamData(_: *EchoHandler, session: *event_loop.Session, stream_id: u64, data: []const u8, fin: bool) void {
        if (data.len > 0) session.sendStreamData(stream_id, data) catch return;
        if (fin) session.closeStream(stream_id);
    }

    pub fn onDatagram(_: *EchoHandler, session: *event_loop.Session, session_id: u64, data: []const u8) void {
        session.sendDatagram(session_id, data) catch return;
    }
};

pub fn main(init: std.process.Init.Minimal) !void {
    const alloc = std.heap.smp_allocator;

    var port: u16 = 4433;
    var address: []const u8 = "0.0.0.0";
    var cert_path: []const u8 = "interop/browser/certs/server.crt";
    var key_path: []const u8 = "interop/browser/certs/server.key";
    var static_dir: ?[]const u8 = null;
    var plain = false;

    var args = std.process.Args.Iterator.init(init.args);
    _ = args.next();
    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--port")) {
            if (args.next()) |v| port = std.fmt.parseInt(u16, v, 10) catch 4433;
        } else if (std.mem.eql(u8, arg, "--address")) {
            if (args.next()) |v| address = v;
        } else if (std.mem.eql(u8, arg, "--cert")) {
            if (args.next()) |v| cert_path = v;
        } else if (std.mem.eql(u8, arg, "--key")) {
            if (args.next()) |v| key_path = v;
        } else if (std.mem.eql(u8, arg, "--static")) {
            if (args.next()) |v| static_dir = v;
        } else if (std.mem.eql(u8, arg, "--plain")) {
            plain = true;
        }
    }

    var handler = EchoHandler{};
    var server = try event_loop.Server(EchoHandler).init(alloc, &handler, .{
        .address = address,
        .port = port,
        .cert_path = cert_path,
        .key_path = key_path,
        .http1 = .{
            .static_dir = static_dir,
            .tls = !plain,
            .websocket = .{ .max_message_size = 64 << 20, .max_send_buffer = 128 << 20 },
        },
    });
    defer server.deinit();

    const scheme = if (plain) "ws" else "wss";
    std.debug.print("WebSocket echo on {s}://{s}:{d}/ (TCP)\n", .{ scheme, address, port });
    std.debug.print("WebTransport echo on https://{s}:{d}/ (QUIC)\n", .{ address, port });
    if (static_dir) |d| std.debug.print("Static files from {s} on {s}://{s}:{d}/\n", .{ d, if (plain) "http" else "https", address, port });
    try server.run();
}
