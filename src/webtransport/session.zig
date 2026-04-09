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

/// WebTransport error codes (draft-ietf-webtrans-http3).
pub const WEBTRANSPORT_SESSION_GONE: u64 = 0x170d7b68;
pub const WEBTRANSPORT_BUFFERED_STREAM_REJECTED: u64 = 0x3994bd84;

/// WebTransport application error code range for H3 stream resets.
/// Maps 32-bit app error codes to range starting at 0x52e4a40fa8db,
/// skipping reserved codepoints of form 0x1f * N + 0x21 (RFC 9114 §8.1).
pub fn appErrorCodeToH3(error_code: u32) u64 {
    const base: u64 = 0x52e4a40fa8db;
    const code: u64 = @intCast(error_code);
    // For every 0x1e consecutive codes, we skip one reserved codepoint.
    return base + code + (code / 0x1e);
}

/// Inverse: extract the 32-bit app error code from an H3 error code.
pub fn h3ToAppErrorCode(h3_code: u64) ?u32 {
    const base: u64 = 0x52e4a40fa8db;
    if (h3_code < base) return null;
    const diff = h3_code - base;
    // Check if this falls on a reserved codepoint (0x1f * N + 0x21)
    if ((h3_code -% 0x21) % 0x1f == 0) return null;
    // Inverse: code + code/0x1e = diff → code = diff - diff/0x1f
    const code = diff - (diff / 0x1f);
    if (code > 0xffffffff) return null;
    // Verify round-trip
    if (appErrorCodeToH3(@intCast(code)) != h3_code) return null;
    return @intCast(code);
}

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
    close_reason_buf: [1024]u8 = undefined,
    close_reason_len: u16 = 0,
};

/// Events returned by WebTransportConnection.poll().
pub const WtEvent = union(enum) {
    session_ready: struct { session_id: u64, headers: []const qpack.Header = &.{} },
    session_rejected: struct { session_id: u64, status: []const u8 },
    connect_request: struct { session_id: u64, protocol: []const u8, authority: []const u8, path: []const u8, headers: []const qpack.Header = &.{} },
    bidi_stream: struct { session_id: u64, stream_id: u64 },
    uni_stream: struct { session_id: u64, stream_id: u64 },
    stream_data: struct { stream_id: u64, data: []const u8, fin: bool = false },
    datagram: struct { session_id: u64, data: []const u8 },
    session_closed: struct { session_id: u64, error_code: u32, reason: []const u8 },
    session_draining: struct { session_id: u64 },
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

    // Next peer-initiated bidi stream ID to examine for WT type prefix.
    // Peer-initiated bidi IDs are sequential: server sees 0, 4, 8, 12...
    // This counter advances as streams are identified, giving O(1) discovery
    // per new stream — same pattern as quic-go's nextStreamToAccept.
    next_peer_bidi_to_examine: u64 = 0,

    // Persistent buffer for datagram polling — avoids heap allocation per datagram.
    // Valid until the next pollDatagrams() call.
    dgram_poll_buf: [quic_connection.DatagramQueue.MAX_DATAGRAM_SIZE]u8 = undefined,

    // Buffered data for WT streams (data after type prefix, or data read before poll)
    stream_bufs: std.AutoHashMap(u64, std.ArrayList(u8)),

    // Streams that have already delivered their FIN event (prevents repeated fin events)
    fin_delivered: std.AutoHashMap(u64, void),

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
            .fin_delivered = std.AutoHashMap(u64, void).init(allocator),
            // Peer-initiated bidi stream IDs: server examines 0, 4, 8...
            // client examines 1, 5, 9... (RFC 9000 §2.1)
            .next_peer_bidi_to_examine = if (is_server) 0 else 1,
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
        self.fin_delivered.deinit();
        self.wt_bidi_streams.deinit();
        self.wt_uni_streams.deinit();
        self.pending_uni_streams.deinit();
    }

    /// Find a session by ID.
    pub fn getSession(self: *WebTransportConnection, session_id: u64) ?*Session {
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

    /// Client: initiate a WebTransport session with extra headers (e.g. sec-webtransport-protocol).
    pub fn connectWithHeaders(self: *WebTransportConnection, authority: []const u8, path: []const u8, extra_headers: []const qpack.Header) !u64 {
        if (self.active_session_count >= self.peerMaxSessions()) return error.TooManySessions;
        const session_id = try self.h3.sendConnectRequestWithHeaders("webtransport", authority, path, extra_headers);
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

    /// Server: accept a WebTransport session with extra response headers (e.g., sub-protocol).
    pub fn acceptSessionWithHeaders(self: *WebTransportConnection, session_id: u64, extra_headers: []const qpack.Header) !void {
        try self.h3.sendConnectResponseWithHeaders(session_id, "200", extra_headers);
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

    /// Returns true if the datagram send queue is full.
    pub fn isDatagramSendQueueFull(self: *const WebTransportConnection) bool {
        return self.quic.isDatagramSendQueueFull();
    }

    /// Returns the maximum WT datagram payload size, subtracting the
    /// quarter_stream_id varint overhead from the QUIC-level budget.
    pub fn maxDatagramPayloadSize(self: *const WebTransportConnection, session_id: u64) ?usize {
        const quic_max = self.quic.maxDatagramPayloadSize() orelse return null;
        const quarter_id = session_id / 4;
        const varint_len = packet.varIntLength(quarter_id);
        if (varint_len >= quic_max) return null;
        return quic_max - varint_len;
    }

    /// Close a WebTransport session with error code 0 and no reason.
    pub fn closeSession(self: *WebTransportConnection, session_id: u64) void {
        self.closeSessionWithError(session_id, 0, "") catch {};
    }

    /// Close a WebTransport session with an application error code and reason.
    /// Sends CLOSE_WEBTRANSPORT_SESSION capsule on the CONNECT stream, then FIN.
    /// Reason is truncated to 1024 bytes per spec.
    pub fn closeSessionWithError(self: *WebTransportConnection, session_id: u64, error_code: u32, reason: []const u8) !void {
        const session = self.getSession(session_id) orelse return;
        if (session.state == .draining or session.state == .closed) return;

        // Truncate reason to spec limit (1024 bytes)
        const truncated_reason = if (reason.len > 1024) reason[0..1024] else reason;

        // Send CLOSE_WEBTRANSPORT_SESSION capsule on the CONNECT stream, then FIN.
        if (self.quic.streams.getStream(session_id)) |stream| {
            var frame_buf: [1100]u8 = undefined;
            var fbs = io.fixedBufferStream(&frame_buf);
            h3_frame.write(.{ .close_webtransport_session = .{
                .error_code = error_code,
                .reason = truncated_reason,
            } }, fbs.writer()) catch {};
            stream.send.writeData(fbs.getWritten()) catch {};
            stream.send.close();
        }

        // Store our close code/reason so pollSessionStreams reports it correctly
        // when the draining state is finalized
        session.close_error_code = error_code;
        const reason_copy_len: u16 = @intCast(@min(truncated_reason.len, session.close_reason_buf.len));
        @memcpy(session.close_reason_buf[0..reason_copy_len], truncated_reason[0..reason_copy_len]);
        session.close_reason_len = reason_copy_len;

        session.state = .draining;

        // Clean up streams belonging to this session
        self.cleanupSessionStreams(session_id);
    }

    /// Send DRAIN_WEBTRANSPORT_SESSION capsule — signals graceful shutdown intent.
    /// The peer MAY continue using the session and MAY open new streams,
    /// but should begin winding down.
    pub fn drainSession(self: *WebTransportConnection, session_id: u64) !void {
        const session = self.getSession(session_id) orelse return;
        if (session.state != .active) return;

        if (self.quic.streams.getStream(session_id)) |stream| {
            var frame_buf: [16]u8 = undefined;
            var fbs = io.fixedBufferStream(&frame_buf);
            h3_frame.write(.{ .drain_webtransport_session = {} }, fbs.writer()) catch {};
            stream.send.writeData(fbs.getWritten()) catch {};
        }
    }

    /// Reset a WT stream with an application error code.
    /// The error code is mapped to the WEBTRANSPORT_APPLICATION_ERROR range.
    pub fn resetStream(self: *WebTransportConnection, stream_id: u64, error_code: u32) void {
        const h3_code = appErrorCodeToH3(error_code);
        if (self.quic.streams.getStream(stream_id)) |stream| {
            if (!stream.send.fin_sent) {
                stream.send.reset(h3_code);
            }
            stream.recv.stopSending(h3_code);
            return;
        }
        if (self.quic.streams.send_streams.get(stream_id)) |send_stream| {
            if (!send_stream.fin_sent) {
                send_stream.reset(h3_code);
            }
        }
        if (self.quic.streams.recv_streams.get(stream_id)) |recv_stream| {
            recv_stream.stopSending(h3_code);
        }
    }

    /// Stop receiving on a WT stream (sends STOP_SENDING to peer).
    /// Equivalent to browser's ReadableStream.cancel().
    /// Unlike resetStream(), this does NOT reset the send side.
    pub fn stopSending(self: *WebTransportConnection, stream_id: u64, error_code: u32) void {
        const h3_code = appErrorCodeToH3(error_code);
        if (self.quic.streams.getStream(stream_id)) |stream| {
            stream.recv.stopSending(h3_code);
            return;
        }
        if (self.quic.streams.recv_streams.get(stream_id)) |recv_stream| {
            recv_stream.stopSending(h3_code);
        }
    }

    /// Mark a session as fully closed and release its slot.
    fn finalizeSession(self: *WebTransportConnection, session: *Session) void {
        session.state = .closed;
        session.occupied = false;
        self.active_session_count -|= 1;
    }

    /// Reset all streams belonging to a session and free their buffers.
    /// Uses WEBTRANSPORT_SESSION_GONE error code per draft-ietf-webtrans-http3.
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
            // Reset the stream with WEBTRANSPORT_SESSION_GONE
            if (self.quic.streams.getStream(sid)) |s| {
                if (!s.send.fin_sent) {
                    s.send.reset(WEBTRANSPORT_SESSION_GONE);
                }
                s.recv.stopSending(WEBTRANSPORT_SESSION_GONE);
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
            // Reset send side if we opened it
            if (self.quic.streams.send_streams.get(sid)) |send_stream| {
                if (!send_stream.fin_sent) {
                    send_stream.reset(WEBTRANSPORT_SESSION_GONE);
                }
            }
            if (self.quic.streams.recv_streams.get(sid)) |recv_stream| {
                recv_stream.stopSending(WEBTRANSPORT_SESSION_GONE);
            }
            if (self.stream_bufs.getPtr(sid)) |buf| {
                buf.deinit(self.allocator);
                _ = self.stream_bufs.remove(sid);
            }
        }
    }

    /// Drain the QUIC-layer disposal queue and clean up corresponding WT bookkeeping.
    /// O(k) where k = number of streams just disposed (typically 0-2 per cycle).
    pub fn drainDisposalQueue(self: *WebTransportConnection) void {
        const disposed = self.quic.streams.disposal_queue[0..self.quic.streams.disposal_count];
        for (disposed) |id| {
            _ = self.wt_bidi_streams.remove(id);
            _ = self.wt_uni_streams.remove(id);
            _ = self.fin_delivered.remove(id);
            _ = self.h3.excluded_bidi_streams.remove(id);
            _ = self.h3.finished_streams.remove(id);
            _ = self.h3.headers_received_streams.remove(id);
            if (self.stream_bufs.fetchRemove(id)) |kv| {
                var buf = kv.value;
                buf.deinit(self.allocator);
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

    /// Poll active session CONNECT streams for CLOSE/DRAIN_WEBTRANSPORT_SESSION capsules or FIN.
    fn pollSessionStreams(self: *WebTransportConnection) ?WtEvent {
        for (&self.sessions) |*session| {
            if (!session.occupied) continue;
            if (session.state != .active and session.state != .draining) continue;

            const stream = self.quic.streams.getStream(session.session_id) orelse continue;
            // read() transfers ownership of heap-allocated data from FrameSorter
            const data = stream.recv.read() orelse {
                // No data — check if stream received FIN
                if (stream.recv.finished) {
                    if (session.state == .draining) {
                        // Drain complete — peer acknowledged our close
                        const sid = session.session_id;
                        const code = session.close_error_code;
                        const reason_len = session.close_reason_len;
                        self.finalizeSession(session);
                        return .{ .session_closed = .{
                            .session_id = sid,
                            .error_code = code,
                            .reason = session.close_reason_buf[0..reason_len],
                        } };
                    }
                    // Active state: FIN on the CONNECT stream recv side is normal
                    // (HTTP/3 CONNECT requests close their send side after headers).
                    // Session termination requires CLOSE_WEBTRANSPORT_SESSION capsule
                    // or RESET_STREAM — a bare FIN just means no more request body.
                }
                continue;
            };

            defer self.allocator.free(data);

            // Try to parse capsules on the CONNECT stream.
            // Per RFC 9297 §3.3, capsules may be wrapped in H3 DATA frames
            // (Chrome does this), or sent as bare capsule TLVs (Zig/Go clients).
            // Try parsing the outer frame first, then unwrap DATA if needed.
            const capsule_data = blk: {
                const result = h3_frame.parse(data) catch break :blk data;
                switch (result.frame) {
                    // Bare capsule — already the right type
                    .close_webtransport_session, .drain_webtransport_session => break :blk data,
                    // DATA frame wrapping a capsule (RFC 9297 §3.3)
                    .data => |payload| break :blk payload,
                    else => {
                        // Unexpected frame on CONNECT stream while draining
                        if (session.state == .draining) {
                            if (self.quic.streams.getStream(session.session_id)) |s| {
                                s.send.reset(@intFromEnum(h3_conn.H3Error.message_error));
                            }
                        }
                        continue;
                    },
                }
            };

            const result = h3_frame.parse(capsule_data) catch continue;
            switch (result.frame) {
                .close_webtransport_session => |cls| {
                    const sid = session.session_id;
                    session.close_error_code = cls.error_code;
                    const copy_len: u16 = @intCast(@min(cls.reason.len, session.close_reason_buf.len));
                    @memcpy(session.close_reason_buf[0..copy_len], cls.reason[0..copy_len]);
                    session.close_reason_len = copy_len;

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
                .drain_webtransport_session => {
                    // Graceful shutdown signal from peer
                    if (session.state == .active) {
                        return .{ .session_draining = .{
                            .session_id = session.session_id,
                        } };
                    }
                },
                else => {
                    // Unexpected capsule on CONNECT stream while draining
                    if (session.state == .draining) {
                        if (self.quic.streams.getStream(session.session_id)) |s| {
                            s.send.reset(@intFromEnum(h3_conn.H3Error.message_error));
                        }
                    }
                },
            }
        }
        return null;
    }

    /// Check for incoming QUIC DATAGRAM frames and demux by quarter_stream_id.
    pub fn pollDatagrams(self: *WebTransportConnection) ?WtEvent {
        // Pop datagram into persistent member buffer — one copy, no heap allocation.
        // The slice is valid until the next pollDatagrams() call.
        const dgram_len = self.quic.recvDatagram(&self.dgram_poll_buf) orelse return null;
        if (dgram_len == 0) return null;

        // Parse quarter_stream_id
        var fbs = io.fixedBufferStream(self.dgram_poll_buf[0..dgram_len]);
        const reader = fbs.reader();
        const quarter_id = packet.readVarInt(reader) catch return null;
        const session_id = quarter_id * 4;

        if (self.getSession(session_id)) |_| {
            return .{ .datagram = .{
                .session_id = session_id,
                .data = self.dgram_poll_buf[fbs.pos..dgram_len],
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

            // Try to read data (read() transfers ownership)
            const data = recv_stream.read() orelse continue;
            defer self.allocator.free(data);
            if (data.len == 0) continue;

            var fbs = io.fixedBufferStream(data);
            const reader = fbs.reader();
            const stream_type = packet.readVarInt(reader) catch continue;

            if (stream_type == WT_UNI_STREAM_TYPE) {
                const session_id = packet.readVarInt(reader) catch continue;

                // Validate session ID: must be a client-initiated bidi stream (divisible by 4)
                if (session_id % 4 != 0) {
                    // Invalid session ID — close connection with H3_ID_ERROR
                    self.h3.closeWithError(.id_error, "invalid WT session ID");
                    return null;
                }

                // Register the stream (even if session not yet accepted).
                try self.wt_uni_streams.put(stream_id, session_id);

                // Buffer remaining data after the type prefix
                if (fbs.pos < data.len) {
                    const remaining = data[fbs.pos..];
                    var buf = self.stream_bufs.getPtr(stream_id) orelse blk: {
                        const new_buf = std.ArrayList(u8){ .items = &.{}, .capacity = 0 };
                        try self.stream_bufs.put(stream_id, new_buf);
                        break :blk self.stream_bufs.getPtr(stream_id).?;
                    };
                    buf.appendSlice(self.allocator, remaining) catch {};
                }

                return .{ .uni_stream = .{
                    .session_id = session_id,
                    .stream_id = stream_id,
                } };
            }
            // Not a WT stream — let H3 handle it by marking as pending
            try self.pending_uni_streams.put(stream_id, {});
        }
        return null;
    }

    /// Identify incoming WT bidirectional streams by reading type prefix.
    fn identifyWtBidiStreams(self: *WebTransportConnection) !?WtEvent {
        const highest = self.quic.streams.highest_peer_bidi_stream_id orelse return null;
        while (self.next_peer_bidi_to_examine <= highest) {
            const stream_id = self.next_peer_bidi_to_examine;
            self.next_peer_bidi_to_examine += 4; // Next peer-initiated bidi ID

            // Skip already-identified streams
            if (self.wt_bidi_streams.contains(stream_id)) continue;
            if (self.h3.finished_streams.contains(stream_id)) continue;
            if (self.getSession(stream_id) != null) continue;

            const stream = self.quic.streams.getStream(stream_id) orelse continue;

            // Try to read prefix data (read() transfers ownership)
            const data = stream.recv.read() orelse continue;
            defer self.allocator.free(data);
            if (data.len == 0) continue;

            var fbs = io.fixedBufferStream(data);
            const reader = fbs.reader();
            const stream_type = packet.readVarInt(reader) catch continue;

            if (stream_type == WT_BIDI_STREAM_TYPE) {
                const session_id = packet.readVarInt(reader) catch continue;

                // Validate session ID: must be a client-initiated bidi stream (divisible by 4)
                if (session_id % 4 != 0) {
                    self.h3.closeWithError(.id_error, "invalid WT session ID");
                    return null;
                }

                // Register the stream (even if session not yet accepted —
                // the Go client may open bidi streams before CONNECT is processed).
                try self.wt_bidi_streams.put(stream_id, session_id);
                try self.h3.excluded_bidi_streams.put(stream_id, {});

                // Buffer remaining data for delivery via pollWtStreamData.
                // Always return .bidi_stream first so the application can register
                // the stream before receiving .stream_data events.
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
            } else {
                // Not a WT stream — buffer for H3 to handle
                var buf = self.h3.stream_bufs.getPtr(stream_id) orelse blk: {
                    const new_buf = std.ArrayList(u8){ .items = &.{}, .capacity = 0 };
                    try self.h3.stream_bufs.put(stream_id, new_buf);
                    break :blk self.h3.stream_bufs.getPtr(stream_id).?;
                };
                try buf.appendSlice(self.allocator, data);
            }
        }
        return null;
    }

    /// Poll known WT streams for data.
    /// The `fin` field is set when the peer has finished sending (FIN received
    /// and all data consumed). A final event with empty data + fin=true is
    /// emitted when FIN arrives after the last data chunk.
    fn pollWtStreamData(self: *WebTransportConnection) ?WtEvent {
        // Check bidi streams
        var bidi_it = self.wt_bidi_streams.iterator();
        while (bidi_it.next()) |entry| {
            const stream_id = entry.key_ptr.*;

            // First check WT buffer for data left over from prefix parsing
            if (self.stream_bufs.getPtr(stream_id)) |buf| {
                if (buf.items.len > 0) {
                    const data_slice = self.allocator.dupe(u8, buf.items) catch {
                        std.log.err("WT bidi stream data alloc failed (OOM)", .{});
                        continue;
                    };
                    buf.items.len = 0;
                    const fin = if (self.quic.streams.getStream(stream_id)) |stream|
                        stream.recv.finished or stream.recv.sorter.isComplete()
                    else
                        false;
                    if (fin) self.fin_delivered.put(stream_id, {}) catch {};
                    return .{ .stream_data = .{
                        .stream_id = stream_id,
                        .data = data_slice,
                        .fin = fin,
                    } };
                }
            }

            if (self.quic.streams.getStream(stream_id)) |stream| {
                if (stream.recv.read()) |data| {
                    const fin = stream.recv.finished or stream.recv.sorter.isComplete();
                    if (fin) self.fin_delivered.put(stream_id, {}) catch {};
                    return .{ .stream_data = .{
                        .stream_id = stream_id,
                        .data = data,
                        .fin = fin,
                    } };
                } else if (stream.recv.finished and !self.fin_delivered.contains(stream_id)) {
                    self.fin_delivered.put(stream_id, {}) catch {};
                    return .{ .stream_data = .{
                        .stream_id = stream_id,
                        .data = &[_]u8{},
                        .fin = true,
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
                    const data_slice = self.allocator.dupe(u8, buf.items) catch {
                        std.log.err("WT uni stream data alloc failed (OOM)", .{});
                        continue;
                    };
                    buf.items.len = 0;
                    const fin = if (self.quic.streams.recv_streams.get(stream_id)) |recv_stream|
                        recv_stream.finished or recv_stream.sorter.isComplete()
                    else
                        false;
                    if (fin) self.fin_delivered.put(stream_id, {}) catch {};
                    return .{ .stream_data = .{
                        .stream_id = stream_id,
                        .data = data_slice,
                        .fin = fin,
                    } };
                }
            }

            if (self.quic.streams.recv_streams.get(stream_id)) |recv_stream| {
                if (recv_stream.read()) |data| {
                    const fin = recv_stream.finished or recv_stream.sorter.isComplete();
                    if (fin) self.fin_delivered.put(stream_id, {}) catch {};
                    return .{ .stream_data = .{
                        .stream_id = stream_id,
                        .data = data,
                        .fin = fin,
                    } };
                } else if (recv_stream.finished and !self.fin_delivered.contains(stream_id)) {
                    self.fin_delivered.put(stream_id, {}) catch {};
                    return .{ .stream_data = .{
                        .stream_id = stream_id,
                        .data = &[_]u8{},
                        .fin = true,
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
                    self.active_session_count += 1;
                    // Exclude this stream from H3 bidi processing
                    try self.h3.excluded_bidi_streams.put(req.stream_id, {});
                    return .{ .connect_request = .{
                        .session_id = req.stream_id,
                        .protocol = req.protocol,
                        .authority = req.authority,
                        .path = req.path,
                        .headers = req.headers,
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
                                    return .{ .session_ready = .{ .session_id = hdr.stream_id, .headers = hdr.headers } };
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
            .data => {
                // Drain body to clear pending state
                var sink: [4096]u8 = undefined;
                while (self.h3.recvBody(&sink) > 0) {}
            },
            .finished => |stream_id| {
                if (self.getSession(stream_id)) |session| {
                    // H3 finished on CONNECT stream — only close if we're draining
                    // (waiting for peer to acknowledge our CLOSE capsule).
                    // In active state, the peer's FIN just means no more request body.
                    if (session.state == .draining) {
                        const sid = session.session_id;
                        const code = session.close_error_code;
                        const reason_len = session.close_reason_len;
                        self.finalizeSession(session);
                        return .{ .session_closed = .{
                            .session_id = sid,
                            .error_code = code,
                            .reason = session.close_reason_buf[0..reason_len],
                        } };
                    }
                }
            },
            .goaway => {
                // H3 GOAWAY signals shutdown — drain all active WT sessions.
                // New session creation will be blocked by H3 layer (GOAWAY stream ID).
                // Signal draining on the first active session found.
                for (&self.sessions) |*session| {
                    if (session.occupied and session.state == .active) {
                        return .{ .session_draining = .{
                            .session_id = session.session_id,
                        } };
                    }
                }
            },
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

// =============================================================================
// WebTransport integration tests via stream-level injection
// =============================================================================

const testing = std.testing;
const ack_handler = @import("../quic/ack_handler.zig");
const flow_control = @import("../quic/flow_control.zig");
const crypto_stream = @import("../quic/crypto_stream.zig");
const packet_packer = @import("../quic/packet_packer.zig");
const protocol = @import("../quic/protocol.zig");

fn createTestQuicConn(is_server: bool) quic_connection.Connection {
    const dcid = "testdcid" ++ ([_]u8{0} ** 12);
    const scid = "testscid" ++ ([_]u8{0} ** 12);

    var conn = quic_connection.Connection{
        .allocator = testing.allocator,
        .is_server = is_server,
        .dcid = dcid.*,
        .dcid_len = 8,
        .scid = scid.*,
        .scid_len = 8,
        .version = protocol.SUPPORTED_VERSIONS[0],
        .pkt_handler = ack_handler.PacketHandler.init(testing.allocator),
        .conn_flow_ctrl = flow_control.ConnectionFlowController.init(1048576, 6 * 1024 * 1024),
        .streams = stream_mod.StreamsMap.init(testing.allocator, is_server),
        .crypto_streams = crypto_stream.CryptoStreamManager.init(testing.allocator),
        .packer = packet_packer.PacketPacker.init(
            testing.allocator,
            is_server,
            dcid[0..8],
            scid[0..8],
            protocol.SUPPORTED_VERSIONS[0],
        ),
    };
    conn.streams.setMaxStreams(100, 100);
    conn.streams.setMaxIncomingStreams(100, 100);
    conn.streams.peer_initial_max_stream_data_bidi_local = 1048576;
    conn.streams.peer_initial_max_stream_data_bidi_remote = 1048576;
    conn.streams.peer_initial_max_stream_data_uni = 1048576;
    conn.conn_flow_ctrl.base.send_window = 1048576;
    conn.datagrams_enabled = true;
    return conn;
}

// Build control stream type byte + WT-enabled SETTINGS
fn buildWtControlPayload(buf: []u8) usize {
    var fbs = io.fixedBufferStream(buf);
    h3_frame.writeUniStreamType(fbs.writer(), .control) catch unreachable;
    h3_frame.write(.{ .settings = .{
        .enable_connect_protocol = true,
        .h3_datagram = true,
        .enable_webtransport = true,
        .webtransport_max_sessions = 4,
    } }, fbs.writer()) catch unreachable;
    return fbs.pos;
}

fn injectPeerControlStream(quic_conn: *quic_connection.Connection, h3: *h3_conn.H3Connection, is_server: bool) !void {
    const peer_uni_id: u64 = if (is_server) 2 else 3;
    var buf: [128]u8 = undefined;
    const len = buildWtControlPayload(&buf);
    const rs = try quic_conn.streams.getOrCreateRecvStream(peer_uni_id);
    try rs.handleStreamFrame(0, buf[0..len], false);
    const ev = try h3.poll();
    if (ev) |e| {
        switch (e) {
            .settings => {},
            else => return error.UnexpectedEvent,
        }
    } else return error.ExpectedSettingsEvent;
}

// Build a QPACK-encoded Extended CONNECT request
fn buildConnectRequest(buf: []u8, path: []const u8) usize {
    const headers = [_]qpack.Header{
        .{ .name = ":method", .value = "CONNECT" },
        .{ .name = ":protocol", .value = "webtransport" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = path },
        .{ .name = ":authority", .value = "example.com" },
    };
    var qpack_buf: [256]u8 = undefined;
    const qpack_len = qpack.encodeHeaders(&headers, &qpack_buf) catch unreachable;
    var fbs = io.fixedBufferStream(buf);
    h3_frame.write(.{ .headers = qpack_buf[0..qpack_len] }, fbs.writer()) catch unreachable;
    return fbs.pos;
}

// Build a QPACK-encoded 200 response
fn buildConnectResponse(buf: []u8) usize {
    const headers = [_]qpack.Header{
        .{ .name = ":status", .value = "200" },
    };
    var qpack_buf: [256]u8 = undefined;
    const qpack_len = qpack.encodeHeaders(&headers, &qpack_buf) catch unreachable;
    var fbs = io.fixedBufferStream(buf);
    h3_frame.write(.{ .headers = qpack_buf[0..qpack_len] }, fbs.writer()) catch unreachable;
    return fbs.pos;
}

// Build WT bidi stream type prefix: 0x41 + session_id
fn buildWtBidiPrefix(buf: []u8, session_id: u64) usize {
    var fbs = io.fixedBufferStream(buf);
    const w = fbs.writer();
    packet.writeVarInt(w, WT_BIDI_STREAM_TYPE) catch unreachable;
    packet.writeVarInt(w, session_id) catch unreachable;
    return fbs.pos;
}

// Build WT uni stream type prefix: 0x54 + session_id
fn buildWtUniPrefix(buf: []u8, session_id: u64) usize {
    var fbs = io.fixedBufferStream(buf);
    const w = fbs.writer();
    packet.writeVarInt(w, WT_UNI_STREAM_TYPE) catch unreachable;
    packet.writeVarInt(w, session_id) catch unreachable;
    return fbs.pos;
}

// Full setup: QUIC conn + H3 + WT + peer control stream + active session.
// Returns the session_id of the active session.
const WtTestSetup = struct {
    quic_conn: quic_connection.Connection,
    h3: h3_conn.H3Connection,
    wt: WebTransportConnection,

    fn initServer(self: *WtTestSetup) !u64 {
        self.quic_conn = createTestQuicConn(true);
        self.h3 = h3_conn.H3Connection.init(testing.allocator, &self.quic_conn, true);
        self.h3.local_settings.enable_connect_protocol = true;
        self.h3.local_settings.enable_webtransport = true;
        self.h3.local_settings.h3_datagram = true;
        try self.h3.initConnection();
        try injectPeerControlStream(&self.quic_conn, &self.h3, true);
        self.wt = WebTransportConnection.init(testing.allocator, &self.h3, &self.quic_conn, true);

        // Inject CONNECT request on client bidi stream 0
        var req_buf: [512]u8 = undefined;
        const req_len = buildConnectRequest(&req_buf, "/wt");
        const stream = try self.quic_conn.streams.getOrCreateStream(0);
        try stream.recv.handleStreamFrame(0, req_buf[0..req_len], false);

        // Poll WT to get connect_request event
        const ev = try self.wt.poll();
        if (ev) |e| {
            switch (e) {
                .connect_request => {},
                else => return error.UnexpectedEvent,
            }
        } else return error.ExpectedConnectRequest;

        // Accept the session
        try self.wt.acceptSession(0);
        return 0;
    }

    fn initClient(self: *WtTestSetup) !u64 {
        self.quic_conn = createTestQuicConn(false);
        self.h3 = h3_conn.H3Connection.init(testing.allocator, &self.quic_conn, false);
        self.h3.local_settings.enable_connect_protocol = true;
        self.h3.local_settings.enable_webtransport = true;
        self.h3.local_settings.h3_datagram = true;
        try self.h3.initConnection();
        try injectPeerControlStream(&self.quic_conn, &self.h3, false);
        self.wt = WebTransportConnection.init(testing.allocator, &self.h3, &self.quic_conn, false);

        // Client initiates connect
        const session_id = try self.wt.connect("example.com", "/wt");

        // Inject 200 response from server on the CONNECT stream
        var resp_buf: [256]u8 = undefined;
        const resp_len = buildConnectResponse(&resp_buf);
        const stream = self.quic_conn.streams.getStream(session_id).?;
        const offset = stream.recv.sorter.highestReceived();
        try stream.recv.handleStreamFrame(offset, resp_buf[0..resp_len], false);

        // Poll to get session_ready
        const ev = try self.wt.poll();
        if (ev) |e| {
            switch (e) {
                .session_ready => {},
                else => return error.UnexpectedEvent,
            }
        } else return error.ExpectedSessionReady;

        return session_id;
    }

    fn deinit(self: *WtTestSetup) void {
        self.wt.deinit();
        self.h3.deinit();
        self.quic_conn.deinit();
    }
};

// ---- Group A: Session management ----

test "WT integration: connect initiates session" {
    var quic_conn = createTestQuicConn(false);
    defer quic_conn.deinit();
    var h3 = h3_conn.H3Connection.init(testing.allocator, &quic_conn, false);
    defer h3.deinit();
    h3.local_settings.enable_connect_protocol = true;
    try h3.initConnection();
    try injectPeerControlStream(&quic_conn, &h3, false);
    var wt = WebTransportConnection.init(testing.allocator, &h3, &quic_conn, false);
    defer wt.deinit();

    const session_id = try wt.connect("example.com", "/wt");
    // Session should be allocated in connecting state
    const session = wt.getSession(session_id).?;
    try testing.expectEqual(SessionState.connecting, session.state);
    try testing.expectEqual(@as(u32, 1), wt.active_session_count);
}

test "WT integration: acceptSession activates session" {
    var setup: WtTestSetup = undefined;
    const session_id = try setup.initServer();
    defer setup.deinit();

    const session = setup.wt.getSession(session_id).?;
    try testing.expectEqual(SessionState.active, session.state);
    try testing.expectEqual(@as(u32, 1), setup.wt.active_session_count);
}

test "WT integration: session limit enforced" {
    var quic_conn = createTestQuicConn(false);
    defer quic_conn.deinit();
    var h3 = h3_conn.H3Connection.init(testing.allocator, &quic_conn, false);
    defer h3.deinit();
    h3.local_settings.enable_connect_protocol = true;
    try h3.initConnection();
    try injectPeerControlStream(&quic_conn, &h3, false);
    var wt = WebTransportConnection.init(testing.allocator, &h3, &quic_conn, false);
    defer wt.deinit();

    // Peer advertised webtransport_max_sessions = 4
    // Connect up to the limit
    var i: u32 = 0;
    while (i < 4) : (i += 1) {
        _ = try wt.connect("example.com", "/wt");
    }

    // Next connect should fail
    const result = wt.connect("example.com", "/wt");
    try testing.expectError(error.TooManySessions, result);
}

test "WT integration: closeSession sends CLOSE frame and FIN" {
    var setup: WtTestSetup = undefined;
    const session_id = try setup.initServer();
    defer setup.deinit();

    setup.wt.closeSession(session_id);

    const session = setup.wt.getSession(session_id);
    // Session should be in draining state or finalized
    if (session) |s| {
        try testing.expect(s.state == .draining or s.state == .closed);
    }

    // CONNECT stream should have FIN queued
    const stream = setup.quic_conn.streams.getStream(session_id).?;
    try testing.expect(stream.send.fin_queued);
    // Write buffer should contain CLOSE_WEBTRANSPORT_SESSION frame
    try testing.expect(stream.send.write_buffer.items.len > 0);
}

// ---- Group B: Stream opening ----

test "WT integration: openBidiStream writes type prefix" {
    var setup: WtTestSetup = undefined;
    const session_id = try setup.initServer();
    defer setup.deinit();

    const stream_id = try setup.wt.openBidiStream(session_id);
    const stream = setup.quic_conn.streams.getStream(stream_id).?;

    // Write buffer should contain WT bidi prefix: 0x41 + session_id
    try testing.expect(stream.send.write_buffer.items.len >= 2);
    // Parse the prefix
    var fbs = io.fixedBufferStream(stream.send.write_buffer.items);
    const reader = fbs.reader();
    const stream_type = packet.readVarInt(reader) catch unreachable;
    try testing.expectEqual(WT_BIDI_STREAM_TYPE, stream_type);
    const sid = packet.readVarInt(reader) catch unreachable;
    try testing.expectEqual(session_id, sid);

    // Should be tracked in wt_bidi_streams
    try testing.expect(setup.wt.wt_bidi_streams.contains(stream_id));
}

test "WT integration: openUniStream writes type prefix" {
    var setup: WtTestSetup = undefined;
    const session_id = try setup.initServer();
    defer setup.deinit();

    const stream_id = try setup.wt.openUniStream(session_id);
    const send_stream = setup.quic_conn.streams.send_streams.get(stream_id).?;

    // Write buffer should contain WT uni prefix: 0x54 + session_id
    try testing.expect(send_stream.write_buffer.items.len >= 2);
    var fbs = io.fixedBufferStream(send_stream.write_buffer.items);
    const reader = fbs.reader();
    const stream_type = packet.readVarInt(reader) catch unreachable;
    try testing.expectEqual(WT_UNI_STREAM_TYPE, stream_type);
    const sid = packet.readVarInt(reader) catch unreachable;
    try testing.expectEqual(session_id, sid);

    try testing.expect(setup.wt.wt_uni_streams.contains(stream_id));
}

test "WT integration: sendStreamData writes to bidi stream" {
    var setup: WtTestSetup = undefined;
    const session_id = try setup.initServer();
    defer setup.deinit();

    const stream_id = try setup.wt.openBidiStream(session_id);
    try setup.wt.sendStreamData(stream_id, "Hello WT!");

    const stream = setup.quic_conn.streams.getStream(stream_id).?;
    // Write buffer should contain prefix + "Hello WT!"
    const items = stream.send.write_buffer.items;
    try testing.expect(items.len > 9);
    // The payload should end with "Hello WT!"
    try testing.expectEqualStrings("Hello WT!", items[items.len - 9 ..]);
}

test "WT integration: closeStream sends FIN" {
    var setup: WtTestSetup = undefined;
    const session_id = try setup.initServer();
    defer setup.deinit();

    const stream_id = try setup.wt.openBidiStream(session_id);
    setup.wt.closeStream(stream_id);

    const stream = setup.quic_conn.streams.getStream(stream_id).?;
    try testing.expect(stream.send.fin_queued);
}

// ---- Group C: Incoming stream identification ----

test "WT integration: identifies incoming WT bidi stream" {
    var setup: WtTestSetup = undefined;
    const session_id = try setup.initServer();
    defer setup.deinit();

    // Inject WT bidi prefix on client-initiated bidi stream 4
    var prefix_buf: [16]u8 = undefined;
    const prefix_len = buildWtBidiPrefix(&prefix_buf, session_id);
    const stream = try setup.quic_conn.streams.getOrCreateStream(4);
    try stream.recv.handleStreamFrame(0, prefix_buf[0..prefix_len], false);

    const ev = try setup.wt.poll();
    try testing.expect(ev != null);
    switch (ev.?) {
        .bidi_stream => |bs| {
            try testing.expectEqual(session_id, bs.session_id);
            try testing.expectEqual(@as(u64, 4), bs.stream_id);
        },
        else => return error.UnexpectedEvent,
    }

    // Should be tracked and excluded from H3
    try testing.expect(setup.wt.wt_bidi_streams.contains(4));
    try testing.expect(setup.h3.excluded_bidi_streams.contains(4));
}

test "WT integration: identifies incoming WT uni stream" {
    var setup: WtTestSetup = undefined;
    const session_id = try setup.initServer();
    defer setup.deinit();

    // Inject WT uni prefix on client-initiated uni stream
    // Client uni streams for server: 2, 6, 10, ...
    // Stream 2 is already used by peer control stream, 6 and 10 might be QPACK
    // Use a higher one: 14
    var prefix_buf: [16]u8 = undefined;
    const prefix_len = buildWtUniPrefix(&prefix_buf, session_id);
    const rs = try setup.quic_conn.streams.getOrCreateRecvStream(14);
    try rs.handleStreamFrame(0, prefix_buf[0..prefix_len], false);

    const ev = try setup.wt.poll();
    try testing.expect(ev != null);
    switch (ev.?) {
        .uni_stream => |us| {
            try testing.expectEqual(session_id, us.session_id);
            try testing.expectEqual(@as(u64, 14), us.stream_id);
        },
        else => return error.UnexpectedEvent,
    }

    try testing.expect(setup.wt.wt_uni_streams.contains(14));
}

test "WT integration: bidi stream with trailing data buffers remainder" {
    var setup: WtTestSetup = undefined;
    const session_id = try setup.initServer();
    defer setup.deinit();

    // Inject WT bidi prefix + "extra data" in one shot
    var buf: [64]u8 = undefined;
    const prefix_len = buildWtBidiPrefix(&buf, session_id);
    const extra = "extra data";
    @memcpy(buf[prefix_len..][0..extra.len], extra);
    const total_len = prefix_len + extra.len;

    const stream = try setup.quic_conn.streams.getOrCreateStream(4);
    try stream.recv.handleStreamFrame(0, buf[0..total_len], false);

    // First poll: bidi_stream event (identification)
    const ev1 = try setup.wt.poll();
    try testing.expect(ev1 != null);
    switch (ev1.?) {
        .bidi_stream => |bs| {
            try testing.expectEqual(@as(u64, session_id), bs.session_id);
            try testing.expectEqual(@as(u64, 4), bs.stream_id);
        },
        else => return error.UnexpectedEvent,
    }

    // Second poll: stream_data with buffered remainder
    const ev2 = try setup.wt.poll();
    try testing.expect(ev2 != null);
    switch (ev2.?) {
        .stream_data => |sd| {
            try testing.expectEqual(@as(u64, 4), sd.stream_id);
            try testing.expectEqualStrings(extra, sd.data);
            try testing.expect(!sd.fin);
            // Caller owns this data — free it
            testing.allocator.free(sd.data);
        },
        else => return error.UnexpectedEvent,
    }
}

// ---- Group D: Datagram handling ----

test "WT integration: sendDatagram writes quarter_stream_id + payload" {
    var setup: WtTestSetup = undefined;
    const session_id = try setup.initServer();
    defer setup.deinit();

    try setup.wt.sendDatagram(session_id, "dgram payload");

    // Read from QUIC datagram send queue
    var dgram_buf: [1200]u8 = undefined;
    const dgram_len = setup.quic_conn.datagram_send_queue.pop(&dgram_buf).?;

    // Parse quarter_stream_id
    var fbs = io.fixedBufferStream(dgram_buf[0..dgram_len]);
    const quarter_id = packet.readVarInt(fbs.reader()) catch unreachable;
    try testing.expectEqual(session_id / 4, quarter_id);
    // Rest is payload
    try testing.expectEqualStrings("dgram payload", dgram_buf[fbs.pos..dgram_len]);
}

test "WT integration: poll receives datagram demuxed by session" {
    var setup: WtTestSetup = undefined;
    const session_id = try setup.initServer();
    defer setup.deinit();

    // Manually push a datagram into the QUIC recv queue
    const quarter_id = session_id / 4;
    var dgram_buf: [64]u8 = undefined;
    var fbs = io.fixedBufferStream(&dgram_buf);
    packet.writeVarInt(fbs.writer(), quarter_id) catch unreachable;
    fbs.writer().writeAll("hello dgram") catch unreachable;
    try testing.expect(setup.quic_conn.datagram_recv_queue.push(dgram_buf[0..fbs.pos]));

    const ev = try setup.wt.poll();
    try testing.expect(ev != null);
    switch (ev.?) {
        .datagram => |dg| {
            try testing.expectEqual(session_id, dg.session_id);
            try testing.expectEqualStrings("hello dgram", dg.data);
        },
        else => return error.UnexpectedEvent,
    }
}

// ---- Group E: H3 event translation ----

test "WT integration: server receives connect_request from H3" {
    var quic_conn = createTestQuicConn(true);
    defer quic_conn.deinit();
    var h3 = h3_conn.H3Connection.init(testing.allocator, &quic_conn, true);
    defer h3.deinit();
    h3.local_settings.enable_connect_protocol = true;
    try h3.initConnection();
    try injectPeerControlStream(&quic_conn, &h3, true);
    var wt = WebTransportConnection.init(testing.allocator, &h3, &quic_conn, true);
    defer wt.deinit();

    // Inject CONNECT request
    var req_buf: [512]u8 = undefined;
    const req_len = buildConnectRequest(&req_buf, "/webtransport");
    const stream = try quic_conn.streams.getOrCreateStream(0);
    try stream.recv.handleStreamFrame(0, req_buf[0..req_len], false);

    const ev = try wt.poll();
    try testing.expect(ev != null);
    switch (ev.?) {
        .connect_request => |cr| {
            try testing.expectEqual(@as(u64, 0), cr.session_id);
            try testing.expectEqualStrings("webtransport", cr.protocol);
            try testing.expectEqualStrings("/webtransport", cr.path);
            try testing.expectEqualStrings("example.com", cr.authority);
        },
        else => return error.UnexpectedEvent,
    }
}

test "WT integration: client receives session_ready on 200 response" {
    var setup: WtTestSetup = undefined;
    // initClient already does the full connect+200 flow and verifies session_ready
    const session_id = try setup.initClient();
    defer setup.deinit();

    const session = setup.wt.getSession(session_id).?;
    try testing.expectEqual(SessionState.active, session.state);
}

test "WT integration: client receives session_rejected on non-200" {
    var quic_conn = createTestQuicConn(false);
    defer quic_conn.deinit();
    var h3 = h3_conn.H3Connection.init(testing.allocator, &quic_conn, false);
    defer h3.deinit();
    h3.local_settings.enable_connect_protocol = true;
    try h3.initConnection();
    try injectPeerControlStream(&quic_conn, &h3, false);
    var wt = WebTransportConnection.init(testing.allocator, &h3, &quic_conn, false);
    defer wt.deinit();

    const session_id = try wt.connect("example.com", "/wt");

    // Inject 403 response
    const resp_headers = [_]qpack.Header{
        .{ .name = ":status", .value = "403" },
    };
    var qpack_buf: [256]u8 = undefined;
    const qpack_len = qpack.encodeHeaders(&resp_headers, &qpack_buf) catch unreachable;
    var frame_buf: [512]u8 = undefined;
    var fbs = io.fixedBufferStream(&frame_buf);
    h3_frame.write(.{ .headers = qpack_buf[0..qpack_len] }, fbs.writer()) catch unreachable;

    const stream = quic_conn.streams.getStream(session_id).?;
    const offset = stream.recv.sorter.highestReceived();
    try stream.recv.handleStreamFrame(offset, fbs.getWritten(), false);

    const ev = try wt.poll();
    try testing.expect(ev != null);
    switch (ev.?) {
        .session_rejected => |rej| {
            try testing.expectEqual(session_id, rej.session_id);
            try testing.expectEqualStrings("403", rej.status);
        },
        else => return error.UnexpectedEvent,
    }
}

// ---- Group F: Session close ----

test "WT integration: closeSessionWithError sends CLOSE frame" {
    var setup: WtTestSetup = undefined;
    const session_id = try setup.initServer();
    defer setup.deinit();

    // Record write buffer length before close (response HEADERS already written)
    const stream = setup.quic_conn.streams.getStream(session_id).?;
    const pre_len = stream.send.write_buffer.items.len;

    try setup.wt.closeSessionWithError(session_id, 42, "test error");

    try testing.expect(stream.send.fin_queued);
    // Parse the CLOSE frame from the portion written after acceptSession's response
    const close_data = stream.send.write_buffer.items[pre_len..];
    try testing.expect(close_data.len > 0);
    const result = h3_frame.parse(close_data) catch unreachable;
    switch (result.frame) {
        .close_webtransport_session => |cls| {
            try testing.expectEqual(@as(u32, 42), cls.error_code);
            try testing.expectEqualStrings("test error", cls.reason);
        },
        else => return error.UnexpectedEvent,
    }
}

test "WT integration: receiving CLOSE_WEBTRANSPORT_SESSION produces session_closed" {
    var setup: WtTestSetup = undefined;
    const session_id = try setup.initServer();
    defer setup.deinit();

    // Build and inject CLOSE_WEBTRANSPORT_SESSION frame on the CONNECT stream
    var frame_buf: [256]u8 = undefined;
    var fbs = io.fixedBufferStream(&frame_buf);
    h3_frame.write(.{ .close_webtransport_session = .{
        .error_code = 7,
        .reason = "goodbye",
    } }, fbs.writer()) catch unreachable;

    const stream = setup.quic_conn.streams.getStream(session_id).?;
    const offset = stream.recv.sorter.highestReceived();
    try stream.recv.handleStreamFrame(offset, fbs.getWritten(), false);

    const ev = try setup.wt.poll();
    try testing.expect(ev != null);
    switch (ev.?) {
        .session_closed => |sc| {
            try testing.expectEqual(session_id, sc.session_id);
            try testing.expectEqual(@as(u32, 7), sc.error_code);
            try testing.expectEqualStrings("goodbye", sc.reason);
        },
        else => return error.UnexpectedEvent,
    }
}

// Bare FIN on CONNECT stream recv side is normal (HTTP/3 CONNECT closes send side
// after headers). It should NOT close the WT session — only CLOSE capsule does that.
test "WT integration: bare FIN on CONNECT recv does not close session" {
    var setup: WtTestSetup = undefined;
    const session_id = try setup.initServer();
    defer setup.deinit();

    // Send FIN on the CONNECT stream (no CLOSE frame)
    const stream = setup.quic_conn.streams.getStream(session_id).?;
    const offset = stream.recv.sorter.highestReceived();
    try stream.recv.handleStreamFrame(offset, "", true);

    // Poll should NOT produce session_closed
    const ev = try setup.wt.poll();
    // Should be null (no event) — session stays active
    try testing.expect(ev == null);
    // Session should still be active
    const session = setup.wt.getSession(session_id).?;
    try testing.expectEqual(SessionState.active, session.state);
}

test "WT integration: session cleanup resets associated streams" {
    var setup: WtTestSetup = undefined;
    const session_id = try setup.initServer();
    defer setup.deinit();

    // Open a bidi stream belonging to this session
    const wt_stream_id = try setup.wt.openBidiStream(session_id);
    try testing.expect(setup.wt.wt_bidi_streams.contains(wt_stream_id));

    // Close the session — should clean up associated streams
    setup.wt.closeSession(session_id);

    // The WT bidi stream should be removed from tracking
    try testing.expect(!setup.wt.wt_bidi_streams.contains(wt_stream_id));
}

// ---- Group G: Stream data ----

test "WT integration: poll returns stream_data on known bidi stream" {
    var setup: WtTestSetup = undefined;
    const session_id = try setup.initServer();
    defer setup.deinit();

    // Inject WT bidi prefix on client-initiated bidi stream 4
    var prefix_buf: [16]u8 = undefined;
    const prefix_len = buildWtBidiPrefix(&prefix_buf, session_id);
    const stream = try setup.quic_conn.streams.getOrCreateStream(4);
    try stream.recv.handleStreamFrame(0, prefix_buf[0..prefix_len], false);

    // Poll to identify the stream
    const ev1 = try setup.wt.poll();
    try testing.expect(ev1 != null);
    switch (ev1.?) {
        .bidi_stream => {},
        else => return error.UnexpectedEvent,
    }

    // Now inject more data on the same stream
    const offset = stream.recv.sorter.highestReceived();
    try stream.recv.handleStreamFrame(offset, "stream payload", false);

    const ev2 = try setup.wt.poll();
    try testing.expect(ev2 != null);
    switch (ev2.?) {
        .stream_data => |sd| {
            try testing.expectEqual(@as(u64, 4), sd.stream_id);
            try testing.expectEqualStrings("stream payload", sd.data);
            try testing.expect(!sd.fin);
            // Caller owns data from FrameSorter — free it
            testing.allocator.free(sd.data);
        },
        else => return error.UnexpectedEvent,
    }
}

test "WT integration: poll returns stream_data on known uni stream" {
    var setup: WtTestSetup = undefined;
    const session_id = try setup.initServer();
    defer setup.deinit();

    // Inject WT uni prefix on client uni stream 14
    var prefix_buf: [16]u8 = undefined;
    const prefix_len = buildWtUniPrefix(&prefix_buf, session_id);
    const rs = try setup.quic_conn.streams.getOrCreateRecvStream(14);
    try rs.handleStreamFrame(0, prefix_buf[0..prefix_len], false);

    // Poll to identify
    const ev1 = try setup.wt.poll();
    try testing.expect(ev1 != null);
    switch (ev1.?) {
        .uni_stream => {},
        else => return error.UnexpectedEvent,
    }

    // Inject more data
    const offset = rs.sorter.highestReceived();
    try rs.handleStreamFrame(offset, "uni payload", false);

    const ev2 = try setup.wt.poll();
    try testing.expect(ev2 != null);
    switch (ev2.?) {
        .stream_data => |sd| {
            try testing.expectEqual(@as(u64, 14), sd.stream_id);
            try testing.expectEqualStrings("uni payload", sd.data);
            try testing.expect(!sd.fin);
            testing.allocator.free(sd.data);
        },
        else => return error.UnexpectedEvent,
    }
}

test "WT integration: poll returns stream_data with fin on completed bidi stream" {
    var setup: WtTestSetup = undefined;
    const session_id = try setup.initServer();
    defer setup.deinit();

    var prefix_buf: [16]u8 = undefined;
    const prefix_len = buildWtBidiPrefix(&prefix_buf, session_id);
    const stream = try setup.quic_conn.streams.getOrCreateStream(4);
    try stream.recv.handleStreamFrame(0, prefix_buf[0..prefix_len], false);

    const ev1 = try setup.wt.poll();
    try testing.expect(ev1 != null);
    switch (ev1.?) {
        .bidi_stream => {},
        else => return error.UnexpectedEvent,
    }

    const offset = stream.recv.sorter.highestReceived();
    try stream.recv.handleStreamFrame(offset, "done", true);

    const ev2 = try setup.wt.poll();
    try testing.expect(ev2 != null);
    switch (ev2.?) {
        .stream_data => |sd| {
            try testing.expectEqual(@as(u64, 4), sd.stream_id);
            try testing.expectEqualStrings("done", sd.data);
            try testing.expect(sd.fin);
            testing.allocator.free(sd.data);
        },
        else => return error.UnexpectedEvent,
    }

    const ev3 = try setup.wt.poll();
    try testing.expect(ev3 == null);
}

test "WT integration: poll returns empty fin event when stream ends after buffered data" {
    var setup: WtTestSetup = undefined;
    const session_id = try setup.initServer();
    defer setup.deinit();

    var prefix_buf: [16]u8 = undefined;
    const prefix_len = buildWtUniPrefix(&prefix_buf, session_id);
    const rs = try setup.quic_conn.streams.getOrCreateRecvStream(14);
    try rs.handleStreamFrame(0, prefix_buf[0..prefix_len], false);

    const ev1 = try setup.wt.poll();
    try testing.expect(ev1 != null);
    switch (ev1.?) {
        .uni_stream => {},
        else => return error.UnexpectedEvent,
    }

    const offset = rs.sorter.highestReceived();
    try rs.handleStreamFrame(offset, "tail", false);

    const ev2 = try setup.wt.poll();
    try testing.expect(ev2 != null);
    switch (ev2.?) {
        .stream_data => |sd| {
            try testing.expectEqual(@as(u64, 14), sd.stream_id);
            try testing.expectEqualStrings("tail", sd.data);
            try testing.expect(!sd.fin);
            testing.allocator.free(sd.data);
        },
        else => return error.UnexpectedEvent,
    }

    const fin_offset = rs.sorter.highestReceived();
    try rs.handleStreamFrame(fin_offset, "", true);

    const ev3 = try setup.wt.poll();
    try testing.expect(ev3 != null);
    switch (ev3.?) {
        .stream_data => |sd| {
            try testing.expectEqual(@as(u64, 14), sd.stream_id);
            try testing.expectEqual(@as(usize, 0), sd.data.len);
            try testing.expect(sd.fin);
        },
        else => return error.UnexpectedEvent,
    }
}

test "WT integration: sendStreamData on uni stream" {
    var setup: WtTestSetup = undefined;
    const session_id = try setup.initServer();
    defer setup.deinit();

    const stream_id = try setup.wt.openUniStream(session_id);
    try setup.wt.sendStreamData(stream_id, "uni data");

    const send_stream = setup.quic_conn.streams.send_streams.get(stream_id).?;
    const items = send_stream.write_buffer.items;
    // Should end with "uni data"
    try testing.expectEqualStrings("uni data", items[items.len - 8 ..]);
}

// ---- Group H: Draft-ietf-webtrans-http3 protocol features ----

test "WT: appErrorCodeToH3 and h3ToAppErrorCode round-trip" {
    // Error code 0
    const h3_0 = appErrorCodeToH3(0);
    try testing.expectEqual(@as(u64, 0x52e4a40fa8db), h3_0);
    try testing.expectEqual(@as(?u32, 0), h3ToAppErrorCode(h3_0));

    // Error code 1
    const h3_1 = appErrorCodeToH3(1);
    try testing.expect(h3_1 > h3_0);
    try testing.expectEqual(@as(?u32, 1), h3ToAppErrorCode(h3_1));

    // Error code 42
    const h3_42 = appErrorCodeToH3(42);
    try testing.expectEqual(@as(?u32, 42), h3ToAppErrorCode(h3_42));

    // Reserved codepoints should return null
    try testing.expectEqual(@as(?u32, null), h3ToAppErrorCode(0x21));

    // Values below base should return null
    try testing.expectEqual(@as(?u32, null), h3ToAppErrorCode(0));
}

test "WT: WEBTRANSPORT_SESSION_GONE used in stream cleanup" {
    var setup: WtTestSetup = undefined;
    const session_id = try setup.initServer();
    defer setup.deinit();

    // Open a bidi stream
    const wt_stream_id = try setup.wt.openBidiStream(session_id);

    // Close the session
    setup.wt.closeSession(session_id);

    // The stream should have been reset with WEBTRANSPORT_SESSION_GONE
    const stream = setup.quic_conn.streams.getStream(wt_stream_id).?;
    try testing.expectEqual(@as(?u64, WEBTRANSPORT_SESSION_GONE), stream.send.reset_err);
    try testing.expectEqual(@as(?u64, WEBTRANSPORT_SESSION_GONE), stream.recv.stop_sending_err);
}

test "WT: drainSession sends DRAIN_WEBTRANSPORT_SESSION capsule" {
    var setup: WtTestSetup = undefined;
    const session_id = try setup.initServer();
    defer setup.deinit();

    const stream = setup.quic_conn.streams.getStream(session_id).?;
    const pre_len = stream.send.write_buffer.items.len;

    try setup.wt.drainSession(session_id);

    // Should have written DRAIN capsule (type 0x78ae, length 0)
    const drain_data = stream.send.write_buffer.items[pre_len..];
    try testing.expect(drain_data.len > 0);
    const result = h3_frame.parse(drain_data) catch unreachable;
    try testing.expectEqual(h3_frame.H3FrameType.drain_webtransport_session, std.meta.activeTag(result.frame));
}

test "WT: receiving DRAIN_WEBTRANSPORT_SESSION produces session_draining event" {
    var setup: WtTestSetup = undefined;
    const session_id = try setup.initServer();
    defer setup.deinit();

    // Inject DRAIN capsule on the CONNECT stream
    var frame_buf: [16]u8 = undefined;
    var fbs = io.fixedBufferStream(&frame_buf);
    h3_frame.write(.{ .drain_webtransport_session = {} }, fbs.writer()) catch unreachable;

    const stream = setup.quic_conn.streams.getStream(session_id).?;
    const offset = stream.recv.sorter.highestReceived();
    try stream.recv.handleStreamFrame(offset, fbs.getWritten(), false);

    const ev = try setup.wt.poll();
    try testing.expect(ev != null);
    switch (ev.?) {
        .session_draining => |sd| {
            try testing.expectEqual(session_id, sd.session_id);
        },
        else => return error.UnexpectedEvent,
    }

    // Session should still be active (drain is advisory)
    const session = setup.wt.getSession(session_id).?;
    try testing.expectEqual(SessionState.active, session.state);
}

test "WT: resetStream maps app error code to H3 range" {
    var setup: WtTestSetup = undefined;
    const session_id = try setup.initServer();
    defer setup.deinit();

    const stream_id = try setup.wt.openBidiStream(session_id);
    setup.wt.resetStream(stream_id, 42);

    const stream = setup.quic_conn.streams.getStream(stream_id).?;
    try testing.expectEqual(@as(?u64, appErrorCodeToH3(42)), stream.send.reset_err);
    try testing.expectEqual(@as(?u64, appErrorCodeToH3(42)), stream.recv.stop_sending_err);
}

test "WT: close reason supports up to 1024 bytes" {
    var setup: WtTestSetup = undefined;
    const session_id = try setup.initServer();
    defer setup.deinit();

    // Create a 1024-byte reason
    var long_reason: [1024]u8 = undefined;
    @memset(&long_reason, 'X');

    const stream = setup.quic_conn.streams.getStream(session_id).?;
    const pre_len = stream.send.write_buffer.items.len;

    try setup.wt.closeSessionWithError(session_id, 99, &long_reason);

    // Parse the CLOSE frame
    const close_data = stream.send.write_buffer.items[pre_len..];
    const result = h3_frame.parse(close_data) catch unreachable;
    switch (result.frame) {
        .close_webtransport_session => |cls| {
            try testing.expectEqual(@as(u32, 99), cls.error_code);
            try testing.expectEqual(@as(usize, 1024), cls.reason.len);
        },
        else => return error.UnexpectedEvent,
    }
}

test "WT: invalid session ID triggers H3_ID_ERROR on bidi stream" {
    var setup: WtTestSetup = undefined;
    _ = try setup.initServer();
    defer setup.deinit();

    // Inject WT bidi prefix with an odd session ID (invalid — must be client-initiated bidi = 4*n)
    var prefix_buf: [16]u8 = undefined;
    var fbs = io.fixedBufferStream(&prefix_buf);
    packet.writeVarInt(fbs.writer(), WT_BIDI_STREAM_TYPE) catch unreachable;
    packet.writeVarInt(fbs.writer(), 1) catch unreachable; // Invalid: not divisible by 4

    const stream = try setup.quic_conn.streams.getOrCreateStream(4);
    try stream.recv.handleStreamFrame(0, fbs.getWritten(), false);

    const ev = try setup.wt.poll();
    // Should return null (connection closed with H3_ID_ERROR)
    try testing.expect(ev == null);
    // Connection should be closing
    try testing.expect(setup.quic_conn.local_err != null);
}

test "WT: uni stream to unknown session gets BUFFERED_STREAM_REJECTED" {
    var setup: WtTestSetup = undefined;
    _ = try setup.initServer();
    defer setup.deinit();

    // Inject WT uni prefix referencing non-existent session 8
    var prefix_buf: [16]u8 = undefined;
    var fbs = io.fixedBufferStream(&prefix_buf);
    packet.writeVarInt(fbs.writer(), WT_UNI_STREAM_TYPE) catch unreachable;
    packet.writeVarInt(fbs.writer(), 8) catch unreachable; // Valid format but session doesn't exist

    const rs = try setup.quic_conn.streams.getOrCreateRecvStream(14);
    try rs.handleStreamFrame(0, fbs.getWritten(), false);

    const ev = try setup.wt.poll();
    // Stream is registered even for unknown sessions (may arrive before CONNECT)
    try testing.expect(ev != null);
    switch (ev.?) {
        .uni_stream => |us| {
            try testing.expectEqual(@as(u64, 8), us.session_id);
            try testing.expectEqual(@as(u64, 14), us.stream_id);
        },
        else => return error.UnexpectedEvent,
    }
}

test "H3Frame: write and parse DRAIN_WEBTRANSPORT_SESSION" {
    var buf: [16]u8 = undefined;
    var fbs = io.fixedBufferStream(&buf);
    try h3_frame.write(.{ .drain_webtransport_session = {} }, fbs.writer());
    const written = fbs.getWritten();
    try testing.expect(written.len > 0);

    const result = try h3_frame.parse(written);
    try testing.expectEqual(h3_frame.H3FrameType.drain_webtransport_session, std.meta.activeTag(result.frame));
}
