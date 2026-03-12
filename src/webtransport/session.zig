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
    draining, // CLOSE_WEBTRANSPORT_SESSION sent or received, awaiting FIN
    closed,
};

/// A WebTransport session (maps to a single CONNECT stream).
pub const Session = struct {
    session_id: u64 = 0, // = CONNECT stream ID
    state: SessionState = .closed,
    occupied: bool = false,
    close_error_code: u32 = 0,
    close_reason_buf: [128]u8 = undefined,
    close_reason_len: u8 = 0,
};

/// Events returned by WebTransportConnection.poll().
pub const WtEvent = union(enum) {
    session_ready: u64, // session_id
    session_rejected: struct { session_id: u64, status: []const u8 },
    connect_request: struct { session_id: u64, protocol: []const u8, authority: []const u8, path: []const u8 },
    bidi_stream: struct { session_id: u64, stream_id: u64 },
    uni_stream: struct { session_id: u64, stream_id: u64 },
    stream_data: struct { stream_id: u64, data: []const u8 },
    datagram: struct { session_id: u64, data: []const u8 },
    session_closed: struct { session_id: u64, error_code: u32, reason: []const u8 },
};

/// WebTransport connection wrapping H3Connection + QUIC Connection.
pub const WebTransportConnection = struct {
    h3: *h3_conn.H3Connection,
    quic: *quic_connection.Connection,
    is_server: bool,
    sessions: [MAX_SESSIONS]Session = .{Session{}} ** MAX_SESSIONS,
    active_session_count: u32 = 0,

    // Track which bidi/uni streams belong to WT sessions
    // Key: stream_id -> session_id
    wt_bidi_streams: std.AutoHashMap(u64, u64),
    wt_uni_streams: std.AutoHashMap(u64, u64),

    // Streams whose type prefix hasn't been read yet
    pending_uni_streams: std.AutoHashMap(u64, void),

    // Buffered data for WT streams (data after type prefix, or data read before poll)
    stream_bufs: std.AutoHashMap(u64, std.ArrayList(u8)),

    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator, h3: *h3_conn.H3Connection, quic: *quic_connection.Connection, is_server: bool) WebTransportConnection {
        return .{
            .h3 = h3,
            .quic = quic,
            .is_server = is_server,
            .wt_bidi_streams = std.AutoHashMap(u64, u64).init(allocator),
            .wt_uni_streams = std.AutoHashMap(u64, u64).init(allocator),
            .pending_uni_streams = std.AutoHashMap(u64, void).init(allocator),
            .stream_bufs = std.AutoHashMap(u64, std.ArrayList(u8)).init(allocator),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *WebTransportConnection) void {
        // Free all buffered stream data
        var buf_it = self.stream_bufs.iterator();
        while (buf_it.next()) |entry| {
            entry.value_ptr.deinit(self.allocator);
        }
        self.stream_bufs.deinit();
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

    /// Get the peer's maximum allowed sessions from negotiated settings.
    fn peerMaxSessions(self: *WebTransportConnection) u64 {
        return self.h3.peer_settings.webtransport_max_sessions orelse 1;
    }

    /// Client: initiate a WebTransport session via Extended CONNECT.
    pub fn connect(self: *WebTransportConnection, authority: []const u8, path: []const u8) !u64 {
        // Enforce peer's session limit
        if (self.active_session_count >= self.peerMaxSessions()) return error.TooManySessions;
        const session_id = try self.h3.sendConnectRequest("webtransport", authority, path);
        _ = self.allocateSession(session_id, .connecting) orelse return error.TooManySessions;
        self.active_session_count += 1;
        return session_id;
    }

    /// Server: accept a WebTransport session (send 200 response).
    pub fn acceptSession(self: *WebTransportConnection, session_id: u64) !void {
        try self.h3.sendConnectResponse(session_id, "200");
        if (self.getSession(session_id)) |s| {
            if (s.state != .active) {
                s.state = .active;
            }
        } else {
            _ = self.allocateSession(session_id, .active) orelse return error.TooManySessions;
            self.active_session_count += 1;
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

    /// Close a WebTransport session with error code 0 and no reason.
    pub fn closeSession(self: *WebTransportConnection, session_id: u64) void {
        self.closeSessionWithError(session_id, 0, "") catch {};
    }

    /// Close a WebTransport session with an application error code and reason.
    /// Sends CLOSE_WEBTRANSPORT_SESSION frame on the CONNECT stream, then FIN.
    pub fn closeSessionWithError(self: *WebTransportConnection, session_id: u64, error_code: u32, reason: []const u8) !void {
        const session = self.getSession(session_id) orelse return;
        if (session.state == .draining or session.state == .closed) return;

        // Send CLOSE_WEBTRANSPORT_SESSION on the CONNECT stream
        if (self.quic.streams.getStream(session_id)) |stream| {
            var frame_buf: [256]u8 = undefined;
            var fbs = io.fixedBufferStream(&frame_buf);
            h3_frame.write(.{ .close_webtransport_session = .{
                .error_code = error_code,
                .reason = reason,
            } }, fbs.writer()) catch {};
            stream.send.writeData(fbs.getWritten()) catch {};
            stream.send.close();
        }

        session.state = .draining;

        // Clean up streams belonging to this session
        self.cleanupSessionStreams(session_id);
    }

    /// Mark a session as fully closed and release its slot.
    fn finalizeSession(self: *WebTransportConnection, session: *Session) void {
        session.state = .closed;
        session.occupied = false;
        self.active_session_count -|= 1;
    }

    /// Reset all streams belonging to a session and free their buffers.
    fn cleanupSessionStreams(self: *WebTransportConnection, session_id: u64) void {
        // Collect stream IDs to remove (can't remove during iteration)
        var bidi_to_remove: [64]u64 = undefined;
        var bidi_count: usize = 0;
        var bidi_it = self.wt_bidi_streams.iterator();
        while (bidi_it.next()) |entry| {
            if (entry.value_ptr.* == session_id) {
                if (bidi_count < 64) {
                    bidi_to_remove[bidi_count] = entry.key_ptr.*;
                    bidi_count += 1;
                }
            }
        }
        for (bidi_to_remove[0..bidi_count]) |sid| {
            _ = self.wt_bidi_streams.remove(sid);
            _ = self.h3.excluded_bidi_streams.remove(sid);
            // Reset the stream if still open
            if (self.quic.streams.getStream(sid)) |s| {
                if (!s.send.fin_sent) {
                    s.send.reset(0);
                }
                s.recv.stopSending(0);
            }
            // Free buffered data
            if (self.stream_bufs.getPtr(sid)) |buf| {
                buf.deinit(self.allocator);
                _ = self.stream_bufs.remove(sid);
            }
        }

        var uni_to_remove: [64]u64 = undefined;
        var uni_count: usize = 0;
        var uni_it = self.wt_uni_streams.iterator();
        while (uni_it.next()) |entry| {
            if (entry.value_ptr.* == session_id) {
                if (uni_count < 64) {
                    uni_to_remove[uni_count] = entry.key_ptr.*;
                    uni_count += 1;
                }
            }
        }
        for (uni_to_remove[0..uni_count]) |sid| {
            _ = self.wt_uni_streams.remove(sid);
            if (self.quic.streams.recv_streams.get(sid)) |recv_stream| {
                recv_stream.stopSending(0);
            }
            if (self.stream_bufs.getPtr(sid)) |buf| {
                buf.deinit(self.allocator);
                _ = self.stream_bufs.remove(sid);
            }
        }
    }

    /// Poll for the next WebTransport event.
    pub fn poll(self: *WebTransportConnection) !?WtEvent {
        // 1. Check CONNECT streams for CLOSE_WEBTRANSPORT_SESSION
        if (self.pollSessionStreams()) |event| return event;

        // 2. Check for incoming WT datagrams
        if (self.pollDatagrams()) |event| return event;

        // 3. Check for incoming WT uni streams with type prefix
        if (try self.identifyWtUniStreams()) |event| return event;

        // 4. Check for incoming WT bidi streams with type prefix
        if (try self.identifyWtBidiStreams()) |event| return event;

        // 5. Check for data on known WT streams
        if (self.pollWtStreamData()) |event| return event;

        // 6. Poll H3 for events (settings, connect requests, responses)
        if (try self.pollH3Events()) |event| return event;

        return null;
    }

    /// Poll active session CONNECT streams for CLOSE_WEBTRANSPORT_SESSION frames or FIN.
    fn pollSessionStreams(self: *WebTransportConnection) ?WtEvent {
        for (&self.sessions) |*session| {
            if (!session.occupied) continue;
            if (session.state != .active and session.state != .draining) continue;

            const stream = self.quic.streams.getStream(session.session_id) orelse continue;
            const data = stream.recv.read() orelse {
                // No data — check if stream received FIN
                if (stream.recv.finished) {
                    const sid = session.session_id;
                    if (session.state == .draining) {
                        // Drain complete — peer acknowledged close
                        const code = session.close_error_code;
                        const reason_len = session.close_reason_len;
                        self.finalizeSession(session);
                        return .{ .session_closed = .{
                            .session_id = sid,
                            .error_code = code,
                            .reason = session.close_reason_buf[0..reason_len],
                        } };
                    } else {
                        // Peer closed without CLOSE frame — clean close with code 0
                        self.cleanupSessionStreams(sid);
                        self.finalizeSession(session);
                        return .{ .session_closed = .{
                            .session_id = sid,
                            .error_code = 0,
                            .reason = "",
                        } };
                    }
                }
                continue;
            };

            // Try to parse CLOSE_WEBTRANSPORT_SESSION frame
            const result = h3_frame.parse(data) catch continue;
            switch (result.frame) {
                .close_webtransport_session => |cls| {
                    const sid = session.session_id;
                    session.close_error_code = cls.error_code;
                    const copy_len = @min(cls.reason.len, session.close_reason_buf.len);
                    @memcpy(session.close_reason_buf[0..copy_len], cls.reason[0..copy_len]);
                    session.close_reason_len = @intCast(copy_len);

                    // Send our own FIN (echo close) if we haven't already
                    if (session.state == .active) {
                        if (self.quic.streams.getStream(sid)) |s| {
                            s.send.close();
                        }
                        self.cleanupSessionStreams(sid);
                    }

                    self.finalizeSession(session);
                    return .{ .session_closed = .{
                        .session_id = sid,
                        .error_code = cls.error_code,
                        .reason = session.close_reason_buf[0..copy_len],
                    } };
                },
                else => {}, // Ignore other frames on CONNECT stream
            }
        }
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
            // Skip streams initiated by us (client: even IDs, server: odd IDs)
            // WT type prefix only appears on peer-initiated bidi streams
            const is_client_initiated = (stream_id % 4) == 0;
            if (is_client_initiated and !self.is_server) continue;
            if (!is_client_initiated and self.is_server) continue;
            // Also skip our CONNECT session streams
            if (self.getSession(stream_id) != null) continue;

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
                    // Exclude from H3 processing
                    try self.h3.excluded_bidi_streams.put(stream_id, {});

                    // If there's remaining data after the prefix, buffer it in WT buffer
                    if (fbs.pos < data.len) {
                        const remaining = data[fbs.pos..];
                        var buf = self.stream_bufs.getPtr(stream_id) orelse blk: {
                            const new_buf = std.ArrayList(u8){ .items = &.{}, .capacity = 0 };
                            try self.stream_bufs.put(stream_id, new_buf);
                            break :blk self.stream_bufs.getPtr(stream_id).?;
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

            // First check WT buffer for data left over from prefix parsing
            if (self.stream_bufs.getPtr(stream_id)) |buf| {
                if (buf.items.len > 0) {
                    // Return buffered data; will be consumed on next call
                    const data_slice = self.allocator.dupe(u8, buf.items) catch continue;
                    buf.items.len = 0;
                    return .{ .stream_data = .{
                        .stream_id = stream_id,
                        .data = data_slice,
                    } };
                }
            }

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

            // First check WT buffer
            if (self.stream_bufs.getPtr(stream_id)) |buf| {
                if (buf.items.len > 0) {
                    const data_slice = self.allocator.dupe(u8, buf.items) catch continue;
                    buf.items.len = 0;
                    return .{ .stream_data = .{
                        .stream_id = stream_id,
                        .data = data_slice,
                    } };
                }
            }

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
                    // Exclude this stream from H3 bidi processing
                    try self.h3.excluded_bidi_streams.put(req.stream_id, {});
                    return .{ .connect_request = .{
                        .session_id = req.stream_id,
                        .protocol = req.protocol,
                        .authority = req.authority,
                        .path = req.path,
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
                                    // Exclude CONNECT stream from H3 — WT layer owns it now
                                    self.h3.excluded_bidi_streams.put(hdr.stream_id, {}) catch {};
                                    return .{ .session_ready = hdr.stream_id };
                                } else {
                                    self.finalizeSession(session);
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
                    // CONNECT stream finished via H3 — session closed without close frame
                    self.cleanupSessionStreams(stream_id);
                    self.finalizeSession(session);
                    return .{ .session_closed = .{
                        .session_id = stream_id,
                        .error_code = 0,
                        .reason = "",
                    } };
                }
            },
            .goaway => {},
            .shutdown_complete => {},
            .request_cancelled => {},
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
