const std = @import("std");
const Allocator = std.mem.Allocator;
const testing = std.testing;
const io = std.io;

const quic_connection = @import("../quic/connection.zig");
const stream_mod = @import("../quic/stream.zig");
const packet = @import("../quic/packet.zig");
const h3_frame = @import("frame.zig");
const qpack = @import("qpack.zig");

pub const ALPN = [_][]const u8{ "h3", "h3-32", "h3-31", "h3-30", "h3-29" };

/// HTTP/3 error codes (RFC 9114 Section 8.1).
pub const H3Error = enum(u64) {
    no_error = 0x0100,
    general_protocol_error = 0x0101,
    internal_error = 0x0102,
    stream_creation_error = 0x0103,
    closed_critical_stream = 0x0104,
    frame_unexpected = 0x0105,
    frame_error = 0x0106,
    excessive_load = 0x0107,
    id_error = 0x0108,
    settings_error = 0x0109,
    missing_settings = 0x010a,
    request_rejected = 0x010b,
    request_cancelled = 0x010c,
    request_incomplete = 0x010d,
    message_error = 0x010e,
    connect_error = 0x010f,
    version_fallback = 0x0110,
};

/// Events returned by poll().
pub const H3Event = union(enum) {
    settings: h3_frame.Settings,
    headers: struct { stream_id: u64, headers: []const qpack.Header },
    data: struct { stream_id: u64, data: []const u8 },
    finished: u64,
    goaway: u64,
    connect_request: struct {
        stream_id: u64,
        protocol: []const u8,
        authority: []const u8,
        path: []const u8,
        headers: []const qpack.Header,
    },
};

/// Maximum number of headers we'll decode from a single HEADERS frame.
const MAX_HEADERS: usize = 64;

/// HTTP/3 connection state machine.
/// Wraps a QUIC connection and manages H3 framing, control streams, and QPACK.
pub const H3Connection = struct {
    allocator: Allocator,
    quic_conn: *quic_connection.Connection,
    is_server: bool,

    // Our control streams (send-only uni)
    local_control_stream: ?*stream_mod.SendStream = null,
    local_qpack_enc_stream: ?*stream_mod.SendStream = null,
    local_qpack_dec_stream: ?*stream_mod.SendStream = null,

    // Peer's control streams (identified by stream type byte)
    peer_control_stream_id: ?u64 = null,
    peer_qpack_enc_stream_id: ?u64 = null,
    peer_qpack_dec_stream_id: ?u64 = null,
    peer_settings_received: bool = false,
    peer_settings: h3_frame.Settings = .{},

    // Local settings
    local_settings: h3_frame.Settings = .{},

    // Initialization state
    initialized: bool = false,

    // Decoded headers buffer (reused across calls)
    headers_buf: [MAX_HEADERS]qpack.Header = undefined,

    // Per-stream partial frame buffer for streams that haven't delivered a complete frame yet
    // Key: stream_id, Value: accumulated bytes
    stream_bufs: std.AutoHashMap(u64, std.ArrayList(u8)),

    // Streams that have been reported as finished (avoid duplicate events)
    finished_streams: std.AutoHashMap(u64, void),

    pub fn init(allocator: Allocator, quic_conn: *quic_connection.Connection, is_server: bool) H3Connection {
        return .{
            .allocator = allocator,
            .quic_conn = quic_conn,
            .is_server = is_server,
            .stream_bufs = std.AutoHashMap(u64, std.ArrayList(u8)).init(allocator),
            .finished_streams = std.AutoHashMap(u64, void).init(allocator),
        };
    }

    pub fn deinit(self: *H3Connection) void {
        var it = self.stream_bufs.valueIterator();
        while (it.next()) |buf| {
            buf.deinit(self.allocator);
        }
        self.stream_bufs.deinit();
        self.finished_streams.deinit();
    }

    /// Initialize the HTTP/3 connection: open control + QPACK streams, send SETTINGS.
    /// Must be called after the QUIC handshake completes.
    pub fn initConnection(self: *H3Connection) !void {
        if (self.initialized) return;

        // Open control stream (type 0x00)
        const ctrl = try self.quic_conn.openUniStream();
        self.local_control_stream = ctrl;
        // Write stream type
        var type_buf: [8]u8 = undefined;
        var type_fbs = io.fixedBufferStream(&type_buf);
        try h3_frame.writeUniStreamType(type_fbs.writer(), .control);
        try ctrl.writeData(type_fbs.getWritten());

        // Send SETTINGS frame on control stream
        var settings_buf: [128]u8 = undefined;
        var settings_fbs = io.fixedBufferStream(&settings_buf);
        try h3_frame.write(.{ .settings = self.local_settings }, settings_fbs.writer());
        try ctrl.writeData(settings_fbs.getWritten());

        // Open QPACK encoder stream (type 0x02) — empty for static-only
        const enc = try self.quic_conn.openUniStream();
        self.local_qpack_enc_stream = enc;
        type_fbs = io.fixedBufferStream(&type_buf);
        try h3_frame.writeUniStreamType(type_fbs.writer(), .qpack_encoder);
        try enc.writeData(type_fbs.getWritten());

        // Open QPACK decoder stream (type 0x03) — empty for static-only
        const dec = try self.quic_conn.openUniStream();
        self.local_qpack_dec_stream = dec;
        type_fbs = io.fixedBufferStream(&type_buf);
        try h3_frame.writeUniStreamType(type_fbs.writer(), .qpack_decoder);
        try dec.writeData(type_fbs.getWritten());

        self.initialized = true;
    }

    /// Send an HTTP request (client-side).
    /// Opens a new bidirectional stream, sends HEADERS + optional DATA, returns stream ID.
    pub fn sendRequest(self: *H3Connection, headers: []const qpack.Header, body: ?[]const u8) !u64 {
        const stream = try self.quic_conn.openStream();
        const stream_id = stream.stream_id;

        // Encode HEADERS frame
        var qpack_buf: [4096]u8 = undefined;
        const qpack_len = try qpack.encodeHeaders(headers, &qpack_buf);

        var frame_buf: [4096 + 16]u8 = undefined;
        var fbs = io.fixedBufferStream(&frame_buf);
        try h3_frame.write(.{ .headers = qpack_buf[0..qpack_len] }, fbs.writer());
        try stream.send.writeData(fbs.getWritten());

        // Send DATA frame if body provided
        if (body) |b| {
            var data_buf: [8192]u8 = undefined;
            var dfbs = io.fixedBufferStream(&data_buf);
            try h3_frame.write(.{ .data = b }, dfbs.writer());
            try stream.send.writeData(dfbs.getWritten());
        }

        stream.send.close();
        return stream_id;
    }

    /// Send an Extended CONNECT request (RFC 9220).
    /// Opens a bidi stream, sends HEADERS with :method=CONNECT, :protocol, etc.
    /// Does NOT close the stream — session lifetime = stream lifetime.
    pub fn sendConnectRequest(self: *H3Connection, protocol_name: []const u8, authority: []const u8, path: []const u8) !u64 {
        const stream = try self.quic_conn.openStream();
        const stream_id = stream.stream_id;

        const req_headers = [_]qpack.Header{
            .{ .name = ":method", .value = "CONNECT" },
            .{ .name = ":protocol", .value = protocol_name },
            .{ .name = ":scheme", .value = "https" },
            .{ .name = ":authority", .value = authority },
            .{ .name = ":path", .value = path },
        };

        var qpack_buf: [4096]u8 = undefined;
        const qpack_len = try qpack.encodeHeaders(&req_headers, &qpack_buf);

        var frame_buf: [4096 + 16]u8 = undefined;
        var fbs = io.fixedBufferStream(&frame_buf);
        try h3_frame.write(.{ .headers = qpack_buf[0..qpack_len] }, fbs.writer());
        try stream.send.writeData(fbs.getWritten());

        // Do NOT close the stream — session stays open
        return stream_id;
    }

    /// Send a CONNECT response (server-side, RFC 9220).
    /// Sends :status response HEADERS, does NOT close the stream.
    pub fn sendConnectResponse(self: *H3Connection, stream_id: u64, status: []const u8) !void {
        const stream = self.quic_conn.streams.getStream(stream_id) orelse return error.StreamNotFound;

        const resp_headers = [_]qpack.Header{
            .{ .name = ":status", .value = status },
        };

        var qpack_buf: [4096]u8 = undefined;
        const qpack_len = try qpack.encodeHeaders(&resp_headers, &qpack_buf);

        var frame_buf: [4096 + 16]u8 = undefined;
        var fbs = io.fixedBufferStream(&frame_buf);
        try h3_frame.write(.{ .headers = qpack_buf[0..qpack_len] }, fbs.writer());
        try stream.send.writeData(fbs.getWritten());

        // Do NOT close the stream — session stays open
    }

    /// Send an HTTP response (server-side).
    pub fn sendResponse(
        self: *H3Connection,
        stream_id: u64,
        headers: []const qpack.Header,
        body: ?[]const u8,
    ) !void {
        const stream = self.quic_conn.streams.getStream(stream_id) orelse return error.StreamNotFound;

        // Encode HEADERS frame
        var qpack_buf: [4096]u8 = undefined;
        const qpack_len = try qpack.encodeHeaders(headers, &qpack_buf);

        var frame_buf: [4096 + 16]u8 = undefined;
        var fbs = io.fixedBufferStream(&frame_buf);
        try h3_frame.write(.{ .headers = qpack_buf[0..qpack_len] }, fbs.writer());
        try stream.send.writeData(fbs.getWritten());

        // Send DATA frame if body provided
        if (body) |b| {
            var data_buf: [8192]u8 = undefined;
            var dfbs = io.fixedBufferStream(&data_buf);
            try h3_frame.write(.{ .data = b }, dfbs.writer());
            try stream.send.writeData(dfbs.getWritten());
        }

        stream.send.close();
    }

    /// Poll for the next HTTP/3 event.
    /// Processes incoming QUIC stream data and returns H3 events.
    pub fn poll(self: *H3Connection) !?H3Event {
        // First, identify any new peer uni streams
        if (try self.identifyPeerUniStreams()) |event| {
            return event;
        }

        // Check control stream for SETTINGS/GOAWAY
        if (try self.pollControlStream()) |event| {
            return event;
        }

        // Check bidirectional streams for request/response data
        if (try self.pollBidiStreams()) |event| {
            return event;
        }

        return null;
    }

    /// Identify peer-initiated unidirectional streams by reading their type byte.
    fn identifyPeerUniStreams(self: *H3Connection) !?H3Event {
        var recv_it = self.quic_conn.streams.recv_streams.iterator();
        while (recv_it.next()) |entry| {
            const stream_id = entry.key_ptr.*;
            const recv_stream = entry.value_ptr.*;

            // Skip already-identified streams
            if (self.peer_control_stream_id != null and self.peer_control_stream_id.? == stream_id) continue;
            if (self.peer_qpack_enc_stream_id != null and self.peer_qpack_enc_stream_id.? == stream_id) continue;
            if (self.peer_qpack_dec_stream_id != null and self.peer_qpack_dec_stream_id.? == stream_id) continue;

            // Try to read type byte
            const data = recv_stream.read() orelse continue;
            if (data.len == 0) continue;

            var fbs = io.fixedBufferStream(data);
            const stream_type = h3_frame.readUniStreamType(fbs.reader()) catch continue;

            switch (stream_type) {
                .control => {
                    self.peer_control_stream_id = stream_id;
                    // If there's remaining data, buffer it for SETTINGS parsing
                    if (fbs.pos < data.len) {
                        const remaining = data[fbs.pos..];
                        var buf = std.ArrayList(u8){ .items = &.{}, .capacity = 0 };
                        try buf.appendSlice(self.allocator, remaining);
                        try self.stream_bufs.put(stream_id, buf);
                    }
                },
                .qpack_encoder => self.peer_qpack_enc_stream_id = stream_id,
                .qpack_decoder => self.peer_qpack_dec_stream_id = stream_id,
                .push => {}, // ignore server push
            }
        }

        return null;
    }

    /// Poll the peer's control stream for SETTINGS/GOAWAY frames.
    fn pollControlStream(self: *H3Connection) !?H3Event {
        const ctrl_id = self.peer_control_stream_id orelse return null;

        // Read more data from control stream
        if (self.quic_conn.streams.recv_streams.get(ctrl_id)) |recv_stream| {
            if (recv_stream.read()) |data| {
                var buf = self.stream_bufs.getPtr(ctrl_id) orelse blk: {
                    const new_buf = std.ArrayList(u8){ .items = &.{}, .capacity = 0 };
                    try self.stream_bufs.put(ctrl_id, new_buf);
                    break :blk self.stream_bufs.getPtr(ctrl_id).?;
                };
                try buf.appendSlice(self.allocator, data);
            }
        }

        // Try to parse a frame from buffered data
        const buf = self.stream_bufs.getPtr(ctrl_id) orelse return null;
        if (buf.items.len == 0) return null;

        const result = h3_frame.parse(buf.items) catch |err| {
            if (err == error.BufferTooShort) return null;
            return err;
        };

        // Consume the parsed frame
        const remaining = buf.items.len - result.consumed;
        if (remaining > 0) {
            std.mem.copyForwards(u8, buf.items[0..remaining], buf.items[result.consumed..]);
        }
        buf.items.len = remaining;

        switch (result.frame) {
            .settings => |settings| {
                if (self.peer_settings_received) {
                    return error.H3SettingsError; // Duplicate SETTINGS
                }
                self.peer_settings_received = true;
                self.peer_settings = settings;
                return .{ .settings = settings };
            },
            .goaway => |id| {
                return .{ .goaway = id };
            },
            else => return null, // Ignore other frames on control stream
        }
    }

    /// Poll bidirectional streams for HEADERS/DATA frames.
    fn pollBidiStreams(self: *H3Connection) !?H3Event {
        var stream_it = self.quic_conn.streams.streams.iterator();
        while (stream_it.next()) |entry| {
            const stream_id = entry.key_ptr.*;
            const stream = entry.value_ptr.*;

            // Skip already-finished streams
            if (self.finished_streams.contains(stream_id)) continue;

            // Read incoming data
            const data = stream.recv.read() orelse {
                // Check if stream is finished
                if (stream.recv.finished) {
                    try self.finished_streams.put(stream_id, {});
                    return .{ .finished = stream_id };
                }
                continue;
            };

            // Buffer the data
            var buf = self.stream_bufs.getPtr(stream_id) orelse blk: {
                const new_buf = std.ArrayList(u8){ .items = &.{}, .capacity = 0 };
                try self.stream_bufs.put(stream_id, new_buf);
                break :blk self.stream_bufs.getPtr(stream_id).?;
            };
            try buf.appendSlice(self.allocator, data);

            // Try to parse H3 frames from buffered data
            while (buf.items.len > 0) {
                const result = h3_frame.parse(buf.items) catch |err| {
                    if (err == error.BufferTooShort) break;
                    return err;
                };

                // Consume the parsed frame
                const remaining = buf.items.len - result.consumed;
                if (remaining > 0) {
                    std.mem.copyForwards(u8, buf.items[0..remaining], buf.items[result.consumed..]);
                }
                buf.items.len = remaining;

                switch (result.frame) {
                    .headers => |qpack_data| {
                        const count = qpack.decodeHeaders(qpack_data, &self.headers_buf) catch |err| {
                            std.log.err("QPACK decode error on stream {d}: {}", .{ stream_id, err });
                            continue;
                        };
                        const hdrs = self.headers_buf[0..count];

                        // Check for Extended CONNECT (:method=CONNECT + :protocol)
                        var method: ?[]const u8 = null;
                        var proto: ?[]const u8 = null;
                        var authority: []const u8 = "";
                        var path: []const u8 = "";
                        for (hdrs) |h_item| {
                            if (std.mem.eql(u8, h_item.name, ":method")) method = h_item.value;
                            if (std.mem.eql(u8, h_item.name, ":protocol")) proto = h_item.value;
                            if (std.mem.eql(u8, h_item.name, ":authority")) authority = h_item.value;
                            if (std.mem.eql(u8, h_item.name, ":path")) path = h_item.value;
                        }

                        if (method != null and std.mem.eql(u8, method.?, "CONNECT") and proto != null) {
                            return .{ .connect_request = .{
                                .stream_id = stream_id,
                                .protocol = proto.?,
                                .authority = authority,
                                .path = path,
                                .headers = hdrs,
                            } };
                        }

                        return .{ .headers = .{
                            .stream_id = stream_id,
                            .headers = hdrs,
                        } };
                    },
                    .data => |payload| {
                        return .{ .data = .{
                            .stream_id = stream_id,
                            .data = payload,
                        } };
                    },
                    else => continue, // ignore unexpected frames on bidi streams
                }
            }
        }

        return null;
    }
};

// Tests

test "H3Connection: init and deinit" {
    // Just verify struct construction doesn't crash
    var conn: H3Connection = undefined;
    conn.stream_bufs = std.AutoHashMap(u64, std.ArrayList(u8)).init(testing.allocator);
    conn.finished_streams = std.AutoHashMap(u64, void).init(testing.allocator);
    conn.deinit();
}
