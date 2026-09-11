const std = @import("std");
const quic = @import("quic");
const event_loop = quic.event_loop;
const qpack = quic.qpack;
const wt_protocol = quic.webtransport_protocol;

// Advertised in server preference order; the first one the client also
// offered wins. "echo" exists so the negotiation has something to agree on
// when the peer is not a MoQ client.
const SUPPORTED_PROTOCOLS = [_][]const u8{ "moqt-18", "moqt-17", "echo" };

pub const std_options: std.Options = .{
    .log_level = .err,
};

const EchoHandler = struct {
    pub const protocol: event_loop.Protocol = .webtransport;

    pub fn onConnectRequest(
        _: *EchoHandler,
        session: *event_loop.Session,
        session_id: u64,
        path: []const u8,
        headers: []const qpack.Header,
    ) void {
        std.log.info("WT session request (id={d}, path={s})", .{ session_id, path });

        // draft-ietf-webtrans-http3-13 §3.3: pick one of the client's
        // offered application protocols and name it on the response.
        var scratch: [256]u8 = undefined;
        var value_buf: [64]u8 = undefined;
        const offer = wt_protocol.findHeader(headers, wt_protocol.HEADER_AVAILABLE);
        const chosen: ?[]const u8 = if (offer) |o|
            wt_protocol.selectFromOffer(o, &SUPPORTED_PROTOCOLS, &scratch)
        else
            null;

        if (chosen) |name| {
            std.log.info("WT protocol negotiated: {s}", .{name});
            const encoded = wt_protocol.encodeItem(name, &value_buf) catch {
                session.acceptSession(session_id) catch {};
                return;
            };
            const extra = [_]qpack.Header{
                .{ .name = wt_protocol.HEADER_SELECTED, .value = encoded },
            };
            session.acceptSessionWithHeaders(session_id, &extra) catch |err| {
                std.log.err("WT accept error: {any}", .{err});
            };
            return;
        }

        if (offer != null) std.log.info("WT protocol offer had no overlap; accepting without one", .{});
        session.acceptSession(session_id) catch |err| {
            std.log.err("WT accept error: {any}", .{err});
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

pub fn main(init: std.process.Init.Minimal) !void {
    // A server outlives its streams, so it needs an allocator that reuses what
    // they give back — an arena would grow for as long as the process runs.
    const alloc = std.heap.smp_allocator;

    var args_iter = std.process.Args.Iterator.init(init.args);
    _ = args_iter.next(); // skip program name

    var cert_path: []const u8 = "/etc/letsencrypt/live/echo.web-transport.dev/fullchain.pem";
    var key_path: []const u8 = "/etc/letsencrypt/live/echo.web-transport.dev/privkey.pem";
    var port: u16 = 4433;

    while (args_iter.next()) |arg| {
        if (std.mem.eql(u8, arg, "--cert")) {
            if (args_iter.next()) |v| cert_path = v;
        } else if (std.mem.eql(u8, arg, "--key")) {
            if (args_iter.next()) |v| key_path = v;
        } else if (std.mem.eql(u8, arg, "--port")) {
            if (args_iter.next()) |v| port = std.fmt.parseInt(u16, v, 10) catch 4433;
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
