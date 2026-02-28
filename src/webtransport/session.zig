const std = @import("std");
const io = std.io;

const quic_connection = @import("../quic/connection.zig");
const stream_mod = @import("../quic/stream.zig");
const packet = @import("../quic/packet.zig");
const h3_conn = @import("../h3/connection.zig");
const h3_frame = @import("../h3/frame.zig");
const qpack = @import("../h3/qpack.zig");

/// WebTransport stream type prefixes (draft-ietf-webtrans-http3).
const WT_UNI_STREAM_TYPE: u64 = 0x54;
const WT_BIDI_STREAM_TYPE: u64 = 0x41;

/// Maximum number of concurrent WebTransport sessions.
const MAX_SESSIONS: usize = 4;

/// WebTransport session state.
pub const SessionState = enum {
    connecting,
    active,
    closing,
    closed,
};

/// A WebTransport session (maps to a single CONNECT stream).
pub const Session = struct {
    session_id: u64 = 0, // = CONNECT stream ID
    state: SessionState = .closed,
    occupied: bool = false,
};

/// Events returned by WebTransportConnection.poll().
pub const WtEvent = union(enum) {
    session_ready: u64, // session_id
    session_rejected: struct { session_id: u64, status: []const u8 },
    bidi_stream: struct { session_id: u64, stream_id: u64 },
    uni_stream: struct { session_id: u64, stream_id: u64 },
    stream_data: struct { stream_id: u64, data: []const u8 },
    datagram: struct { session_id: u64, data: []const u8 },
    session_closed: u64, // session_id
};

/// WebTransport connection wrapping H3Connection + QUIC Connection.
pub const WebTransportConnection = struct {
    h3: *h3_conn.H3Connection,
    quic: *quic_connection.Connection,
    is_server: bool,
    sessions: [MAX_SESSIONS]Session = .{Session{}} ** MAX_SESSIONS,

    // Track which bidi/uni streams belong to WT sessions
    // Key: stream_id -> session_id
    wt_bidi_streams: std.AutoHashMap(u64, u64),
    wt_uni_streams: std.AutoHashMap(u64, u64),

    // Streams whose type prefix hasn't been read yet
    pending_uni_streams: std.AutoHashMap(u64, void),

    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator, h3: *h3_conn.H3Connection, quic: *quic_connection.Connection, is_server: bool) WebTransportConnection {
        return .{
            .h3 = h3,
            .quic = quic,
            .is_server = is_server,
            .wt_bidi_streams = std.AutoHashMap(u64, u64).init(allocator),
            .wt_uni_streams = std.AutoHashMap(u64, u64).init(allocator),
            .pending_uni_streams = std.AutoHashMap(u64, void).init(allocator),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *WebTransportConnection) void {
        self.wt_bidi_streams.deinit();
        self.wt_uni_streams.deinit();
        self.pending_uni_streams.deinit();
    }

    /// Find a session by ID.
    fn getSession(self: *WebTransportConnection, session_id: u64) ?*Session {
        for (&self.sessions) |*s| {
            if (s.occupied and s.session_id == session_id) return s;
        }
        return null;
    }

    /// Allocate a session slot.
    fn allocateSession(self: *WebTransportConnection, session_id: u64, state: SessionState) ?*Session {
        for (&self.sessions) |*s| {
            if (!s.occupied) {
                s.* = .{
                    .session_id = session_id,
                    .state = state,
                    .occupied = true,
                };
                return s;
            }
        }
        return null; // All slots full
    }

    /// Client: initiate a WebTransport session via Extended CONNECT.
    pub fn connect(self: *WebTransportConnection, authority: []const u8, path: []const u8) !u64 {
        const session_id = try self.h3.sendConnectRequest("webtransport", authority, path);
        _ = self.allocateSession(session_id, .connecting) orelse return error.TooManySessions;
        return session_id;
    }

    /// Server: accept a WebTransport session (send 200 response).
    pub fn acceptSession(self: *WebTransportConnection, session_id: u64) !void {
        try self.h3.sendConnectResponse(session_id, "200");
        if (self.getSession(session_id)) |s| {
            s.state = .active;
        } else {
            _ = self.allocateSession(session_id, .active) orelse return error.TooManySessions;
        }
    }

    /// Open a WT bidirectional stream: write type prefix 0x41 + session_id varint.
    pub fn openBidiStream(self: *WebTransportConnection, session_id: u64) !u64 {
        const stream = try self.quic.openStream();
        const stream_id = stream.stream_id;

        // Write WT bidi stream type prefix
        var prefix_buf: [16]u8 = undefined;
        var fbs = io.fixedBufferStream(&prefix_buf);
        const w = fbs.writer();
        try packet.writeVarInt(w, WT_BIDI_STREAM_TYPE);
        try packet.writeVarInt(w, session_id);
        try stream.send.writeData(fbs.getWritten());

        try self.wt_bidi_streams.put(stream_id, session_id);
        return stream_id;
    }

    /// Open a WT unidirectional stream: write type prefix 0x54 + session_id varint.
    pub fn openUniStream(self: *WebTransportConnection, session_id: u64) !u64 {
        const send_stream = try self.quic.openUniStream();
        const stream_id = send_stream.stream_id;

        // Write WT uni stream type prefix
        var prefix_buf: [16]u8 = undefined;
        var fbs = io.fixedBufferStream(&prefix_buf);
        const w = fbs.writer();
        try packet.writeVarInt(w, WT_UNI_STREAM_TYPE);
        try packet.writeVarInt(w, session_id);
        try send_stream.writeData(fbs.getWritten());

        try self.wt_uni_streams.put(stream_id, session_id);
        return stream_id;
    }

    /// Send data on a WT stream (wraps it in a DATA frame).
    pub fn sendStreamData(self: *WebTransportConnection, stream_id: u64, data: []const u8) !void {
        // Check if it's a bidi stream we own
        if (self.quic.streams.getStream(stream_id)) |stream| {
            try stream.send.writeData(data);
            return;
        }
        // Check if it's a uni send stream
        if (self.quic.streams.send_streams.get(stream_id)) |send_stream| {
            try send_stream.writeData(data);
            return;
        }
        return error.StreamNotFound;
    }

    /// Close a WT stream with FIN.
    pub fn closeStream(self: *WebTransportConnection, stream_id: u64) void {
        if (self.quic.streams.getStream(stream_id)) |stream| {
            stream.send.close();
            return;
        }
        if (self.quic.streams.send_streams.get(stream_id)) |send_stream| {
            send_stream.close();
        }
    }

    /// Send a QUIC DATAGRAM carrying WT session data.
    /// Format: quarter_stream_id (varint) + payload.
    pub fn sendDatagram(self: *WebTransportConnection, session_id: u64, data: []const u8) !void {
        const quarter_id = session_id / 4;
        var dgram_buf: [quic_connection.DatagramQueue.MAX_DATAGRAM_SIZE]u8 = undefined;
        var fbs = io.fixedBufferStream(&dgram_buf);
        const w = fbs.writer();
        try packet.writeVarInt(w, quarter_id);
        try w.writeAll(data);
        try self.quic.sendDatagram(fbs.getWritten());
    }

    /// Close a WebTransport session (close the CONNECT stream).
    pub fn closeSession(self: *WebTransportConnection, session_id: u64) void {
        if (self.getSession(session_id)) |s| {
            s.state = .closed;
            s.occupied = false;
        }
        // Close the CONNECT stream
        if (self.quic.streams.getStream(session_id)) |stream| {
            stream.send.close();
        }
    }

    /// Poll for the next WebTransport event.
    pub fn poll(self: *WebTransportConnection) !?WtEvent {
        // 1. Check for incoming WT datagrams
        if (self.pollDatagrams()) |event| return event;

        // 2. Check for incoming WT uni streams with type prefix
        if (try self.identifyWtUniStreams()) |event| return event;

        // 3. Check for incoming WT bidi streams with type prefix
        if (try self.identifyWtBidiStreams()) |event| return event;

        // 4. Check for data on known WT streams
        if (self.pollWtStreamData()) |event| return event;

        // 5. Poll H3 for events (settings, connect requests, responses)
        if (try self.pollH3Events()) |event| return event;

        return null;
    }

    /// Check for incoming QUIC DATAGRAM frames and demux by quarter_stream_id.
    fn pollDatagrams(self: *WebTransportConnection) ?WtEvent {
        var dgram_buf: [quic_connection.DatagramQueue.MAX_DATAGRAM_SIZE]u8 = undefined;
        const dgram_len = self.quic.recvDatagram(&dgram_buf) orelse return null;
        if (dgram_len == 0) return null;

        // Parse quarter_stream_id
        var fbs = io.fixedBufferStream(dgram_buf[0..dgram_len]);
        const reader = fbs.reader();
        const quarter_id = packet.readVarInt(reader) catch return null;
        const session_id = quarter_id * 4;

        if (self.getSession(session_id)) |_| {
            return .{ .datagram = .{
                .session_id = session_id,
                .data = dgram_buf[fbs.pos..dgram_len],
            } };
        }

        return null;
    }

    /// Identify incoming WT unidirectional streams by reading type prefix.
    fn identifyWtUniStreams(self: *WebTransportConnection) !?WtEvent {
        var recv_it = self.quic.streams.recv_streams.iterator();
        while (recv_it.next()) |entry| {
            const stream_id = entry.key_ptr.*;
            const recv_stream = entry.value_ptr.*;

            // Skip already-identified streams
            if (self.wt_uni_streams.contains(stream_id)) continue;
            // Skip H3 control/QPACK streams
            if (self.h3.peer_control_stream_id != null and self.h3.peer_control_stream_id.? == stream_id) continue;
            if (self.h3.peer_qpack_enc_stream_id != null and self.h3.peer_qpack_enc_stream_id.? == stream_id) continue;
            if (self.h3.peer_qpack_dec_stream_id != null and self.h3.peer_qpack_dec_stream_id.? == stream_id) continue;
            if (self.pending_uni_streams.contains(stream_id)) continue;

            // Try to read data
            const data = recv_stream.read() orelse continue;
            if (data.len == 0) continue;

            var fbs = io.fixedBufferStream(data);
            const reader = fbs.reader();
            const stream_type = packet.readVarInt(reader) catch continue;

            if (stream_type == WT_UNI_STREAM_TYPE) {
                const session_id = packet.readVarInt(reader) catch continue;
                if (self.getSession(session_id) != null) {
                    try self.wt_uni_streams.put(stream_id, session_id);
                    return .{ .uni_stream = .{
                        .session_id = session_id,
                        .stream_id = stream_id,
                    } };
                }
            }
            // Not a WT stream — let H3 handle it by marking as pending
            try self.pending_uni_streams.put(stream_id, {});
        }
        return null;
    }

    /// Identify incoming WT bidirectional streams by reading type prefix.
    fn identifyWtBidiStreams(self: *WebTransportConnection) !?WtEvent {
        var stream_it = self.quic.streams.streams.iterator();
        while (stream_it.next()) |entry| {
            const stream_id = entry.key_ptr.*;
            const stream = entry.value_ptr.*;

            // Skip already-identified streams
            if (self.wt_bidi_streams.contains(stream_id)) continue;
            // Skip streams we opened (they don't have type prefix to read)
            if (self.h3.finished_streams.contains(stream_id)) continue;

            // Try to read prefix data
            const data = stream.recv.read() orelse continue;
            if (data.len == 0) continue;

            var fbs = io.fixedBufferStream(data);
            const reader = fbs.reader();
            const stream_type = packet.readVarInt(reader) catch continue;

            if (stream_type == WT_BIDI_STREAM_TYPE) {
                const session_id = packet.readVarInt(reader) catch continue;
                if (self.getSession(session_id) != null) {
                    try self.wt_bidi_streams.put(stream_id, session_id);

                    // If there's remaining data after the prefix, buffer it back
                    if (fbs.pos < data.len) {
                        const remaining = data[fbs.pos..];
                        var buf = self.h3.stream_bufs.getPtr(stream_id) orelse blk: {
                            const new_buf = std.ArrayList(u8){ .items = &.{}, .capacity = 0 };
                            try self.h3.stream_bufs.put(stream_id, new_buf);
                            break :blk self.h3.stream_bufs.getPtr(stream_id).?;
                        };
                        try buf.appendSlice(self.allocator, remaining);
                    }

                    return .{ .bidi_stream = .{
                        .session_id = session_id,
                        .stream_id = stream_id,
                    } };
                }
            }
            // Not a WT stream — buffer for H3 to handle
            var buf = self.h3.stream_bufs.getPtr(stream_id) orelse blk: {
                const new_buf = std.ArrayList(u8){ .items = &.{}, .capacity = 0 };
                try self.h3.stream_bufs.put(stream_id, new_buf);
                break :blk self.h3.stream_bufs.getPtr(stream_id).?;
            };
            try buf.appendSlice(self.allocator, data);
        }
        return null;
    }

    /// Poll known WT streams for data.
    fn pollWtStreamData(self: *WebTransportConnection) ?WtEvent {
        // Check bidi streams
        var bidi_it = self.wt_bidi_streams.iterator();
        while (bidi_it.next()) |entry| {
            const stream_id = entry.key_ptr.*;
            if (self.quic.streams.getStream(stream_id)) |stream| {
                if (stream.recv.read()) |data| {
                    return .{ .stream_data = .{
                        .stream_id = stream_id,
                        .data = data,
                    } };
                }
            }
        }

        // Check uni recv streams
        var uni_it = self.wt_uni_streams.iterator();
        while (uni_it.next()) |entry| {
            const stream_id = entry.key_ptr.*;
            if (self.quic.streams.recv_streams.get(stream_id)) |recv_stream| {
                if (recv_stream.read()) |data| {
                    return .{ .stream_data = .{
                        .stream_id = stream_id,
                        .data = data,
                    } };
                }
            }
        }

        return null;
    }

    /// Poll H3 events and translate to WT events.
    fn pollH3Events(self: *WebTransportConnection) !?WtEvent {
        const event = try self.h3.poll();
        if (event == null) return null;

        switch (event.?) {
            .connect_request => |req| {
                if (std.mem.eql(u8, req.protocol, "webtransport")) {
                    // Register as a connecting session
                    _ = self.allocateSession(req.stream_id, .connecting);
                    // Return the connect_request as-is for the server to accept/reject
                    // The caller should use acceptSession() or closeSession()
                    return .{ .bidi_stream = .{
                        .session_id = req.stream_id,
                        .stream_id = req.stream_id,
                    } };
                }
            },
            .headers => |hdr| {
                // Client: check if this is a response to our CONNECT
                if (self.getSession(hdr.stream_id)) |session| {
                    if (session.state == .connecting) {
                        // Check status code
                        for (hdr.headers) |h_item| {
                            if (std.mem.eql(u8, h_item.name, ":status")) {
                                if (std.mem.eql(u8, h_item.value, "200")) {
                                    session.state = .active;
                                    return .{ .session_ready = hdr.stream_id };
                                } else {
                                    session.state = .closed;
                                    session.occupied = false;
                                    return .{ .session_rejected = .{
                                        .session_id = hdr.stream_id,
                                        .status = h_item.value,
                                    } };
                                }
                            }
                        }
                    }
                }
            },
            .settings => {}, // H3 settings — handled by H3 layer
            .data => {},
            .finished => |stream_id| {
                if (self.getSession(stream_id)) |session| {
                    session.state = .closed;
                    session.occupied = false;
                    return .{ .session_closed = stream_id };
                }
            },
            .goaway => {},
        }

        return null;
    }
};

// Tests

test "Session: basic init" {
    const s = Session{};
    try std.testing.expect(!s.occupied);
    try std.testing.expectEqual(SessionState.closed, s.state);
}

test "DatagramQueue used by WT" {
    var q = quic_connection.DatagramQueue{};
    const data = "hello";
    try std.testing.expect(q.push(data));
    var buf: [1200]u8 = undefined;
    const len = q.pop(&buf).?;
    try std.testing.expectEqual(@as(usize, 5), len);
    try std.testing.expectEqualStrings("hello", buf[0..len]);
}
