const std = @import("std");
const io = @import("../io_compat.zig");

const quic_connection = @import("../quic/connection.zig");
const stream_mod = @import("../quic/stream.zig");
const packet = @import("../quic/packet.zig");
const h3_conn = @import("../h3/connection.zig");
const h3_frame = @import("../h3/frame.zig");
const qpack = @import("../h3/qpack.zig");
const fc_mod = @import("flow_control.zig");

/// WebTransport stream type prefixes (draft-ietf-webtrans-http3).
const WT_UNI_STREAM_TYPE: u64 = 0x54;
const WT_BIDI_STREAM_TYPE: u64 = 0x41;

/// Maximum number of concurrent WebTransport sessions.
pub const MAX_SESSIONS: usize = 4;

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

/// A capsule with a longer payload than this is skipped rather than buffered:
/// the peer chooses Length, and holding on to whatever it names would let it
/// name 2^62. The largest we parse is WT_CLOSE_SESSION, whose reason §6 caps at
/// 1024 bytes.
const MAX_CAPSULE_PAYLOAD: u64 = 4096;

/// The type and payload length at the front of a capsule, without needing the
/// payload itself to have arrived.
fn peekCapsuleHeader(data: []const u8) ?struct { frame_type: u64, length: u64, header_len: usize } {
    var fbs = io.fixedBufferStream(data);
    const frame_type = packet.readVarInt(&fbs) catch return null;
    const length = packet.readVarInt(&fbs) catch return null;
    return .{ .frame_type = frame_type, .length = length, .header_len = fbs.seek };
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
    /// Bytes still to discard from an over-long capsule; see MAX_CAPSULE_PAYLOAD.
    capsule_skip: u64 = 0,
    /// draft-13 §5.3-§5.6 session flow control, sized by `allocateSession`
    /// from the connection's grant. An unallocated slot grants nothing.
    fc: fc_mod.SessionFlowControl = fc_mod.SessionFlowControl.init(.{}),
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
    /// The peer reset its send side: no more data is coming on this stream.
    /// Mirrors the browser rejecting the ReadableStream with a
    /// WebTransportError carrying `streamErrorCode`.
    stream_reset: struct { session_id: u64, stream_id: u64, error_code: u32 },
    /// The peer asked us to stop sending. Mirrors the browser rejecting the
    /// WritableStream with a WebTransportError.
    stream_stop_sending: struct { session_id: u64, stream_id: u64, error_code: u32 },
};

/// Which halves of a stream have already reported a peer-side abort, so each
/// one surfaces exactly once.
const ResetDelivery = struct {
    reset: bool = false,
    stop_sending: bool = false,
};

/// Per-stream send statistics (matches browser WebTransportSendStream.getStats()).
pub const SendStreamStats = struct {
    bytes_written: u64,
    bytes_sent: u64,
    bytes_acknowledged: u64,
};

/// Per-stream receive statistics (matches browser WebTransportReceiveStream.getStats()).
pub const RecvStreamStats = struct {
    bytes_received: u64,
    bytes_read: u64,
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

    // Streams that have already reported a peer RESET_STREAM / STOP_SENDING.
    reset_delivered: std.AutoHashMap(u64, ResetDelivery),

    /// The draft-13 §5.6 window each session grants its peer. Separate from
    /// `h3.local_settings`, which only decides whether the same numbers are
    /// *also* announced in SETTINGS — one shipping browser refuses a session
    /// that sees those identifiers, and the capsule reaches everyone anyway.
    grants: fc_mod.Credits = .{},

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
            .reset_delivered = std.AutoHashMap(u64, ResetDelivery).init(allocator),
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
        self.reset_delivered.deinit();
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
                    .fc = fc_mod.SessionFlowControl.init(self.grants),
                };
                // The peer's own credit, if its SETTINGS have landed. A client
                // can send CONNECT before they do, which §5.1 allows for: what
                // is unknown stays unlimited.
                self.applyPeerCredit(&s.fc);
                return s;
            }
        }
        return null; // All slots full
    }

    /// draft-13 §5.1: session flow control binds only when both endpoints
    /// advertise WT_MAX_SESSIONS above one. Until then a peer may not have seen
    /// our SETTINGS, so its capsules mean nothing and MUST be ignored — and,
    /// more to the point, a peer that never sent the setting (Chrome, quic-go,
    /// our own client) must not be read as granting us a limit of zero.
    fn flowControlEnabled(self: *const WebTransportConnection) bool {
        const local = self.h3.local_settings.wt_max_sessions_v13 orelse 0;
        const peer = self.h3.peer_settings.wt_max_sessions_v13 orelse 0;
        return local > 1 and peer > 1;
    }

    /// Whether to spend capsules granting this peer credit. Deliberately wider
    /// than `flowControlEnabled`: §5.1 gates flow control on *both* sides
    /// advertising more than one session, and a peer reading that gate as "the
    /// server said more than one" waits for a credit we would otherwise never
    /// send. A capsule the peer must ignore costs a dozen bytes on the CONNECT
    /// stream; the deadlock costs every client-initiated stream.
    fn grantsCredit(self: *const WebTransportConnection) bool {
        return self.h3.peer_settings.wt_max_sessions_v13 != null;
    }

    /// §5.5 initial limits from the peer's SETTINGS. Idempotent: a
    /// capsule-raised limit outranks a setting, so this can be re-applied when
    /// SETTINGS arrive after the session did.
    fn applyPeerCredit(self: *const WebTransportConnection, fc: *fc_mod.SessionFlowControl) void {
        if (!self.h3.peer_settings_received or !self.flowControlEnabled()) return;
        fc.applyPeerSettings(
            self.h3.peer_settings.wt_initial_max_streams_bidi,
            self.h3.peer_settings.wt_initial_max_streams_uni,
            self.h3.peer_settings.wt_initial_max_data,
        );
    }

    /// Take one stream of §5.6.2 credit, or refuse and ask the peer for more.
    fn spendStreamCredit(limit: *fc_mod.StreamLimit) !void {
        if (limit.canOpen()) return;
        limit.recordBlocked();
        return error.WtStreamLimitReached;
    }

    /// The session whose §5.6 limits bind this stream, or null when session
    /// flow control is not in force — the common case, and the cheap exit.
    fn limitedSessionForStream(self: *WebTransportConnection, stream_id: u64) ?*Session {
        if (!self.flowControlEnabled()) return null;
        // RFC 9000 §2.1 puts the direction in bit 1, so only one map can hold it.
        const streams = if (stream_id & 0x2 != 0) &self.wt_uni_streams else &self.wt_bidi_streams;
        return self.getSession(streams.get(stream_id) orelse return null);
    }

    /// As above, for a session we already have the id of.
    fn limitedSession(self: *WebTransportConnection, session_id: u64) ?*Session {
        if (!self.flowControlEnabled()) return null;
        return self.getSession(session_id);
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
    /// Fails with `error.WtStreamLimitReached` when the session's §5.6.2 credit
    /// is spent; a WT_STREAMS_BLOCKED then asks the peer for more.
    pub fn openBidiStream(self: *WebTransportConnection, session_id: u64, send_order: ?i64) !u64 {
        const session = self.limitedSession(session_id);
        if (session) |sess| try spendStreamCredit(&sess.fc.bidi);
        const stream = try self.quic.openStream();
        const stream_id = stream.stream_id;
        stream.send.send_order = send_order;
        // WT streams have no defined inter-stream ordering; round-robin
        // interleaving is the correct scheduling (also the quicperf path).
        stream.send.incremental = true;

        // Write WT bidi stream type prefix
        var prefix_buf: [16]u8 = undefined;
        var fbs = io.fixedBufferStream(&prefix_buf);
        const w = &fbs;
        try packet.writeVarInt(w, WT_BIDI_STREAM_TYPE);
        try packet.writeVarInt(w, session_id);
        try stream.send.writeData(fbs.buffered());

        try self.wt_bidi_streams.put(stream_id, session_id);
        if (session) |sess| sess.fc.bidi.open();
        return stream_id;
    }

    /// Open a WT unidirectional stream: write type prefix 0x54 + session_id varint.
    /// Fails with `error.WtStreamLimitReached` when the session's §5.6.2 credit
    /// is spent; a WT_STREAMS_BLOCKED then asks the peer for more.
    pub fn openUniStream(self: *WebTransportConnection, session_id: u64, send_order: ?i64) !u64 {
        const session = self.limitedSession(session_id);
        if (session) |sess| try spendStreamCredit(&sess.fc.uni);
        const send_stream = try self.quic.openUniStream();
        const stream_id = send_stream.stream_id;
        send_stream.send_order = send_order;
        // WT streams have no defined inter-stream ordering; round-robin
        // interleaving is the correct scheduling (also the quicperf path).
        send_stream.incremental = true;

        // Write WT uni stream type prefix
        var prefix_buf: [16]u8 = undefined;
        var fbs = io.fixedBufferStream(&prefix_buf);
        const w = &fbs;
        try packet.writeVarInt(w, WT_UNI_STREAM_TYPE);
        try packet.writeVarInt(w, session_id);
        try send_stream.writeData(fbs.buffered());

        try self.wt_uni_streams.put(stream_id, session_id);
        if (session) |sess| sess.fc.uni.open();
        return stream_id;
    }

    /// Dynamically update the sendOrder on a stream. Higher values transmitted first.
    pub fn setSendOrder(self: *WebTransportConnection, stream_id: u64, send_order: ?i64) void {
        if (self.quic.streams.getStream(stream_id)) |stream| {
            stream.send.send_order = send_order;
            return;
        }
        if (self.quic.streams.send_streams.get(stream_id)) |send_stream| {
            send_stream.send_order = send_order;
        }
    }

    /// Send data on a WT stream.
    /// Fails with `error.WtDataLimitReached` when the write would exceed the
    /// session's §5.6.4 credit; a WT_DATA_BLOCKED then asks the peer for more.
    pub fn sendStreamData(self: *WebTransportConnection, stream_id: u64, data: []const u8) !void {
        const session = self.limitedSessionForStream(stream_id);
        if (session) |sess| {
            if (!sess.fc.canSend(data.len)) {
                sess.fc.recordSendBlocked();
                return error.WtDataLimitReached;
            }
        }

        // A bidi stream we own, or a uni send stream.
        if (self.quic.streams.getStream(stream_id)) |stream| {
            try stream.send.writeData(data);
        } else if (self.quic.streams.send_streams.get(stream_id)) |send_stream| {
            try send_stream.writeData(data);
        } else {
            return error.StreamNotFound;
        }

        if (session) |sess| sess.fc.recordSent(data.len);
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
        const w = &fbs;
        try packet.writeVarInt(w, quarter_id);
        try w.writeAll(data);
        try self.quic.sendDatagram(fbs.buffered());
    }

    /// Returns connection-level statistics (matches browser WebTransport.getStats()).
    pub fn getStats(self: *const WebTransportConnection) quic_connection.Connection.Stats {
        return self.quic.getStats();
    }

    /// Get per-stream send statistics (bytesWritten, bytesSent, bytesAcknowledged).
    pub fn getSendStreamStats(self: *const WebTransportConnection, stream_id: u64) ?SendStreamStats {
        if (self.quic.streams.getStream(stream_id)) |stream| {
            return .{
                .bytes_written = stream.send.write_offset,
                .bytes_sent = stream.send.send_offset,
                .bytes_acknowledged = stream.send.ack_offset,
            };
        }
        if (self.quic.streams.send_streams.get(stream_id)) |send_stream| {
            return .{
                .bytes_written = send_stream.write_offset,
                .bytes_sent = send_stream.send_offset,
                .bytes_acknowledged = send_stream.ack_offset,
            };
        }
        return null;
    }

    /// Get per-stream receive statistics (bytesReceived, bytesRead).
    pub fn getRecvStreamStats(self: *const WebTransportConnection, stream_id: u64) ?RecvStreamStats {
        if (self.quic.streams.getStream(stream_id)) |stream| {
            return .{
                .bytes_received = stream.recv.sorter.highestReceived(),
                .bytes_read = stream.recv.bytes_read,
            };
        }
        if (self.quic.streams.recv_streams.get(stream_id)) |recv_stream| {
            return .{
                .bytes_received = recv_stream.sorter.highestReceived(),
                .bytes_read = recv_stream.bytes_read,
            };
        }
        return null;
    }

    /// Set max age for incoming datagrams (milliseconds). null = no limit.
    pub fn setIncomingDatagramMaxAge(self: *WebTransportConnection, max_age_ms: ?u64) void {
        self.quic.setIncomingDatagramMaxAge(max_age_ms);
    }

    /// Set max age for outgoing datagrams (milliseconds). null = no limit.
    pub fn setOutgoingDatagramMaxAge(self: *WebTransportConnection, max_age_ms: ?u64) void {
        self.quic.setOutgoingDatagramMaxAge(max_age_ms);
    }

    /// Set high water mark for incoming datagram queue (count).
    pub fn setIncomingDatagramHighWaterMark(self: *WebTransportConnection, count: usize) void {
        self.quic.setIncomingDatagramHighWaterMark(count);
    }

    /// Set high water mark for outgoing datagram queue (count).
    pub fn setOutgoingDatagramHighWaterMark(self: *WebTransportConnection, count: usize) void {
        self.quic.setOutgoingDatagramHighWaterMark(count);
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

    /// Write a capsule onto a session's CONNECT stream.
    ///
    /// RFC 9297 §3.2: the capsule stream is the HTTP message content, and in
    /// HTTP/3 content travels in DATA frames — so the capsule is wrapped, not
    /// written bare. A bare capsule reaches the peer as an unknown H3 frame
    /// type, which RFC 9114 §9 tells it to ignore: the session then ends on the
    /// FIN alone and the close code is lost.
    fn writeCapsule(self: *WebTransportConnection, session_id: u64, capsule: []const u8) void {
        const stream = self.quic.streams.getStream(session_id) orelse return;
        var hdr_buf: [16]u8 = undefined;
        var hdr = io.fixedBufferStream(&hdr_buf);
        packet.writeVarInt(&hdr, @intFromEnum(h3_frame.H3FrameType.data)) catch return;
        packet.writeVarInt(&hdr, capsule.len) catch return;
        stream.send.writeData(hdr.buffered()) catch return;
        stream.send.writeData(capsule) catch {};
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
        var frame_buf: [1100]u8 = undefined;
        var fbs = io.fixedBufferStream(&frame_buf);
        h3_frame.write(.{ .close_webtransport_session = .{
            .error_code = error_code,
            .reason = truncated_reason,
        } }, &fbs) catch {};
        self.writeCapsule(session_id, fbs.buffered());
        if (self.quic.streams.getStream(session_id)) |stream| stream.send.close();

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

        var frame_buf: [16]u8 = undefined;
        var fbs = io.fixedBufferStream(&frame_buf);
        h3_frame.write(.{ .drain_webtransport_session = {} }, &fbs) catch {};
        self.writeCapsule(session_id, fbs.buffered());
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
        if (self.stream_bufs.fetchRemove(session.session_id)) |kv| {
            var buf = kv.value;
            buf.deinit(self.allocator);
        }
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
            _ = self.reset_delivered.remove(sid);
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
            _ = self.reset_delivered.remove(sid);
        }
    }

    /// Drain the QUIC-layer disposal queue and clean up corresponding WT bookkeeping.
    /// O(k) where k = number of streams just disposed (typically 0-2 per cycle).
    pub fn drainDisposalQueue(self: *WebTransportConnection) void {
        self.h3.drainDisposalQueue();
        const disposed = self.quic.streams.disposal_queue[0..self.quic.streams.disposal_count];
        for (disposed) |id| {
            _ = self.wt_bidi_streams.remove(id);
            _ = self.wt_uni_streams.remove(id);
            _ = self.fin_delivered.remove(id);
            _ = self.reset_delivered.remove(id);
            if (self.stream_bufs.fetchRemove(id)) |kv| {
                var buf = kv.value;
                buf.deinit(self.allocator);
            }
        }
    }

    /// Poll for the next WebTransport event.
    pub fn poll(self: *WebTransportConnection) !?WtEvent {
        // 0. Hand out session flow control credit. First, so a peer holding a
        //    stream back for want of it is unblocked before we look for one.
        self.flushFlowControl();

        // 1. Check CONNECT streams for capsules
        if (self.pollSessionStreams()) |event| return event;

        // 2. Check for incoming WT datagrams
        if (self.pollDatagrams()) |event| return event;

        // 3. Check for incoming WT uni streams with type prefix
        if (try self.identifyWtUniStreams()) |event| return event;

        // 4. Check for incoming WT bidi streams with type prefix
        if (try self.identifyWtBidiStreams()) |event| return event;

        // 5. Check for data on known WT streams
        if (self.pollWtStreamData()) |event| return event;

        // 6. Report peer aborts — after data, so whatever arrived before the
        //    reset is delivered first.
        if (self.pollWtStreamAborts()) |event| return event;

        // 7. Poll H3 for events (settings, connect requests, responses)
        if (try self.pollH3Events()) |event| return event;

        return null;
    }

    /// Poll active session CONNECT streams for capsules and FIN.
    fn pollSessionStreams(self: *WebTransportConnection) ?WtEvent {
        for (&self.sessions) |*session| {
            if (!session.occupied) continue;
            if (session.state != .active and session.state != .draining) continue;

            const stream = self.quic.streams.getStream(session.session_id) orelse continue;

            // Buffer whatever arrived: one read can carry several capsules, or
            // half of one. read() transfers ownership of the FrameSorter's copy.
            if (stream.recv.read()) |data| {
                defer self.allocator.free(data);
                if (self.streamBuf(session.session_id)) |buf| {
                    buf.appendSlice(self.allocator, data) catch {};
                } else |_| {}
            }

            if (self.consumeCapsules(session)) |event| return event;

            // A FIN with nothing left to parse ends a session we are draining.
            if (stream.recv.finished and session.state == .draining) {
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
            // In the active state a FIN on the CONNECT stream recv side is
            // normal — an HTTP/3 CONNECT closes its send side after headers.
            // §6 makes a clean close equivalent to WT_CLOSE_SESSION(0), which
            // the QUIC layer reports as the connection closing.
        }
        return null;
    }

    /// The buffer holding a stream's not-yet-parsed bytes, created on first
    /// use. A session's CONNECT stream is keyed here like any other, and freed
    /// by the same disposal path.
    fn streamBuf(self: *WebTransportConnection, stream_id: u64) !*std.ArrayList(u8) {
        const gop = try self.stream_bufs.getOrPut(stream_id);
        if (!gop.found_existing) gop.value_ptr.* = .{ .items = &.{}, .capacity = 0 };
        return gop.value_ptr;
    }

    /// Parse and act on every whole capsule buffered for a session.
    ///
    /// RFC 9297 §3.2 puts the capsule stream in the HTTP message content, so in
    /// HTTP/3 capsules travel inside DATA frames; a Zig or Go peer writes them
    /// bare. Both framings are accepted. A DATA frame is assumed to hold whole
    /// capsules — which is what every peer we have met writes — so unwrapping is
    /// just dropping the frame header.
    fn consumeCapsules(self: *WebTransportConnection, session: *Session) ?WtEvent {
        while (true) {
            const buf = self.stream_bufs.getPtr(session.session_id) orelse return null;

            // Finish discarding a capsule we decided not to hold on to.
            if (session.capsule_skip > 0) {
                const n = @min(session.capsule_skip, buf.items.len);
                h3_frame.consumeFromBuf(buf, n);
                session.capsule_skip -= n;
                if (session.capsule_skip > 0) return null;
                continue;
            }
            if (buf.items.len == 0) return null;

            const header = peekCapsuleHeader(buf.items) orelse return null;

            // A DATA frame is the RFC 9297 container, not a capsule: drop the
            // header and what follows is the capsule stream itself.
            if (header.frame_type == @intFromEnum(h3_frame.H3FrameType.data)) {
                h3_frame.consumeFromBuf(buf, header.header_len);
                continue;
            }

            if (header.length > MAX_CAPSULE_PAYLOAD) {
                h3_frame.consumeFromBuf(buf, header.header_len);
                session.capsule_skip = header.length;
                continue;
            }
            if (buf.items.len < header.header_len + header.length) return null; // more to come

            const result = h3_frame.parse(buf.items) catch {
                buf.clearRetainingCapacity();
                self.rejectCapsuleStream(session);
                return null;
            };

            // Act before consuming: a capsule's payload points into the buffer.
            // A close releases the session and its buffer with it, so the
            // pointer is re-read rather than reused.
            const event = self.handleCapsule(session, result.frame);
            if (self.stream_bufs.getPtr(session.session_id)) |live| {
                h3_frame.consumeFromBuf(live, result.consumed);
            }
            if (event) |e| return e;
        }
    }

    /// §6: stream data after a WT_CLOSE_SESSION is a MUST-reset with
    /// H3_MESSAGE_ERROR. Only meaningful while draining — before that, an
    /// unexpected capsule is one we simply do not know.
    fn rejectCapsuleStream(self: *WebTransportConnection, session: *Session) void {
        if (session.state != .draining) return;
        if (self.quic.streams.getStream(session.session_id)) |s| {
            s.send.reset(@intFromEnum(h3_conn.H3Error.message_error));
        }
    }

    /// Act on one capsule from a session's CONNECT stream.
    fn handleCapsule(self: *WebTransportConnection, session: *Session, frame: h3_frame.H3Frame) ?WtEvent {
        // §5.1: capsules that arrive while flow control is not in force MUST be
        // ignored — the peer may have sent them before seeing our SETTINGS.
        const fc_live = self.flowControlEnabled();
        switch (frame) {
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
                    return .{ .session_draining = .{ .session_id = session.session_id } };
                }
            },
            .wt_max_streams_bidi => |n| if (fc_live) session.fc.bidi.raiseSendLimit(n),
            .wt_max_streams_uni => |n| if (fc_live) session.fc.uni.raiseSendLimit(n),
            .wt_max_data => |n| if (fc_live) session.fc.raiseSendDataLimit(n),
            .wt_streams_blocked_bidi => |n| if (fc_live) session.fc.bidi.peerBlockedAt(n),
            .wt_streams_blocked_uni => |n| if (fc_live) session.fc.uni.peerBlockedAt(n),
            .wt_data_blocked => |n| if (fc_live) session.fc.peerDataBlockedAt(n),
            else => self.rejectCapsuleStream(session),
        }
        return null;
    }

    /// Write the flow control capsules the active sessions owe their peers
    /// (§5.6): the credit each one starts with, and every raise it has earned.
    fn flushFlowControl(self: *WebTransportConnection) void {
        if (!self.grantsCredit()) return;
        const rtt = &self.quic.pkt_handler.rtt_stats;

        for (&self.sessions) |*session| {
            if (!session.occupied or session.state != .active) continue;

            while (session.fc.nextCapsule(rtt)) |capsule| {
                var buf: [32]u8 = undefined;
                var fbs = io.fixedBufferStream(&buf);
                const frame: h3_frame.H3Frame = switch (capsule) {
                    .max_streams_bidi => |n| .{ .wt_max_streams_bidi = n },
                    .max_streams_uni => |n| .{ .wt_max_streams_uni = n },
                    .max_data => |n| .{ .wt_max_data = n },
                    .streams_blocked_bidi => |n| .{ .wt_streams_blocked_bidi = n },
                    .streams_blocked_uni => |n| .{ .wt_streams_blocked_uni = n },
                    .data_blocked => |n| .{ .wt_data_blocked = n },
                };
                h3_frame.write(frame, &fbs) catch continue;
                self.writeCapsule(session.session_id, fbs.buffered());
            }
        }
    }

    /// Check for incoming QUIC DATAGRAM frames and demux by quarter_stream_id.
    pub fn pollDatagrams(self: *WebTransportConnection) ?WtEvent {
        // Pop datagram into persistent member buffer — one copy, no heap allocation.
        // The slice is valid until the next pollDatagrams() call.
        const dgram_len = self.quic.recvDatagram(&self.dgram_poll_buf) orelse return null;
        if (dgram_len == 0) return null;

        // Parse quarter_stream_id
        var fbs = io.fixedBufferStream(self.dgram_poll_buf[0..dgram_len]);
        const reader = &fbs;
        const quarter_id = packet.readVarInt(reader) catch return null;
        const session_id = quarter_id * 4;

        if (self.getSession(session_id)) |_| {
            return .{ .datagram = .{
                .session_id = session_id,
                .data = self.dgram_poll_buf[fbs.seek..dgram_len],
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
            const data = recv_stream.read() orelse {
                // FIN with nothing to identify it by — no layer will claim it.
                if (recv_stream.finished) self.quic.streams.releaseRecvStream(stream_id);
                continue;
            };
            defer self.allocator.free(data);
            if (data.len == 0) continue;

            var fbs = io.fixedBufferStream(data);
            const reader = &fbs;
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
                if (self.getSession(session_id)) |session| session.fc.uni.peerOpened();

                // Buffer remaining data after the type prefix
                if (fbs.seek < data.len) {
                    const buf = try self.streamBuf(stream_id);
                    buf.appendSlice(self.allocator, data[fbs.seek..]) catch {};
                }

                return .{ .uni_stream = .{
                    .session_id = session_id,
                    .stream_id = stream_id,
                } };
            }
            // Not a WT stream. The read took the bytes H3 identifies it by —
            // the peer's control stream carries its SETTINGS in that first read
            // — so hand them over rather than drop them.
            try self.h3.adoptUniStream(stream_id, data);
            try self.pending_uni_streams.put(stream_id, {});
        }
        return null;
    }

    /// Identify incoming WT bidirectional streams by reading type prefix.
    fn identifyWtBidiStreams(self: *WebTransportConnection) !?WtEvent {
        const highest = self.quic.streams.highest_peer_bidi_stream_id orelse return null;
        while (self.next_peer_bidi_to_examine <= highest) {
            const stream_id = self.next_peer_bidi_to_examine;

            // Already-classified streams: advance past them.
            if (self.wt_bidi_streams.contains(stream_id) or
                self.h3.finished_streams.contains(stream_id) or
                self.getSession(stream_id) != null)
            {
                self.next_peer_bidi_to_examine += 4;
                continue;
            }

            const stream = self.quic.streams.getStream(stream_id) orelse break;

            // Need prefix bytes to identify. If nothing readable yet (e.g. stream
            // opened but first STREAM frame not yet contiguous at offset 0),
            // defer — do NOT advance the cursor, or we'll skip the stream forever.
            const data = stream.recv.read() orelse break;
            defer self.allocator.free(data);

            // Prefix bytes arrived: commit the advance.
            self.next_peer_bidi_to_examine += 4;

            if (data.len == 0) continue;

            var fbs = io.fixedBufferStream(data);
            const reader = &fbs;
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
                if (self.getSession(session_id)) |session| session.fc.bidi.peerOpened();

                // Buffer remaining data for delivery via pollWtStreamData.
                // Always return .bidi_stream first so the application can register
                // the stream before receiving .stream_data events.
                if (fbs.seek < data.len) {
                    const buf = try self.streamBuf(stream_id);
                    try buf.appendSlice(self.allocator, data[fbs.seek..]);
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

    /// Poll known WT streams for data, counting what arrives against the
    /// session's §5.6.4 window. The stream header is not counted: it is
    /// consumed before the stream joins a session, which is what §5.4 requires.
    fn pollWtStreamData(self: *WebTransportConnection) ?WtEvent {
        const event = self.readWtStreamData() orelse return null;
        const data = switch (event) {
            .stream_data => |sd| sd,
            else => return event,
        };
        if (data.data.len > 0) {
            if (self.limitedSessionForStream(data.stream_id)) |session| {
                session.fc.recordReceived(data.data.len);
            }
        }
        return event;
    }

    /// The `fin` field is set when the peer has finished sending (FIN received
    /// and all data consumed). A final event with empty data + fin=true is
    /// emitted when FIN arrives after the last data chunk.
    fn readWtStreamData(self: *WebTransportConnection) ?WtEvent {
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
                    if (fin) {
                        self.fin_delivered.put(stream_id, {}) catch {};
                        self.quic.streams.releaseRecvStream(stream_id);
                    }
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
                    if (fin) {
                        self.fin_delivered.put(stream_id, {}) catch {};
                        self.quic.streams.releaseRecvStream(stream_id);
                    }
                    return .{ .stream_data = .{
                        .stream_id = stream_id,
                        .data = data,
                        .fin = fin,
                    } };
                } else if (recv_stream.finished and !self.fin_delivered.contains(stream_id)) {
                    self.fin_delivered.put(stream_id, {}) catch {};
                    self.quic.streams.releaseRecvStream(stream_id);
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

    /// Report a peer RESET_STREAM or STOP_SENDING on a WT stream, once each.
    ///
    /// The QUIC layer records these but goes quiet about them: a reset recv
    /// stream returns null from `read()` and never flips `finished`, so without
    /// this pass the application never learns the stream died, let alone with
    /// what code.
    fn pollWtStreamAborts(self: *WebTransportConnection) ?WtEvent {
        var bidi_it = self.wt_bidi_streams.iterator();
        while (bidi_it.next()) |entry| {
            const stream_id = entry.key_ptr.*;
            const session_id = entry.value_ptr.*;
            const stream = self.quic.streams.getStream(stream_id) orelse continue;
            if (self.abortEvent(session_id, stream_id, stream.recv.reset_err, stream.send.peer_stop_sending)) |ev| {
                return ev;
            }
        }

        var uni_it = self.wt_uni_streams.iterator();
        while (uni_it.next()) |entry| {
            const stream_id = entry.key_ptr.*;
            const session_id = entry.value_ptr.*;
            const recv_err = if (self.quic.streams.recv_streams.get(stream_id)) |r| r.reset_err else null;
            const send_err = if (self.quic.streams.send_streams.get(stream_id)) |sn| sn.peer_stop_sending else null;
            if (self.abortEvent(session_id, stream_id, recv_err, send_err)) |ev| return ev;
        }

        return null;
    }

    /// Turn a not-yet-reported abort code into an event and mark it delivered.
    /// H3 codes outside the WebTransport range map to 0, matching the browser's
    /// treatment of a reset it cannot attribute to the application.
    fn abortEvent(
        self: *WebTransportConnection,
        session_id: u64,
        stream_id: u64,
        recv_err: ?u64,
        send_err: ?u64,
    ) ?WtEvent {
        if (recv_err == null and send_err == null) return null;
        const gop = self.reset_delivered.getOrPut(stream_id) catch return null;
        if (!gop.found_existing) gop.value_ptr.* = .{};

        if (recv_err) |code| {
            if (!gop.value_ptr.reset) {
                gop.value_ptr.reset = true;
                return .{ .stream_reset = .{
                    .session_id = session_id,
                    .stream_id = stream_id,
                    .error_code = h3ToAppErrorCode(code) orelse 0,
                } };
            }
        }
        if (send_err) |code| {
            if (!gop.value_ptr.stop_sending) {
                gop.value_ptr.stop_sending = true;
                return .{ .stream_stop_sending = .{
                    .session_id = session_id,
                    .stream_id = stream_id,
                    .error_code = h3ToAppErrorCode(code) orelse 0,
                } };
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
            .settings => {
                // §5.5 credits arrive with the peer's SETTINGS, once per
                // connection — a session opened before they landed is holding
                // "unknown, so unlimited" and is corrected here.
                for (&self.sessions) |*session| {
                    if (session.occupied) self.applyPeerCredit(&session.fc);
                }
            },
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
    h3_frame.writeUniStreamType(&fbs, .control) catch unreachable;
    h3_frame.write(.{ .settings = .{
        .enable_connect_protocol = true,
        .h3_datagram = true,
        .enable_webtransport = true,
        .webtransport_max_sessions = 4,
    } }, &fbs) catch unreachable;
    return fbs.seek;
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
    h3_frame.write(.{ .headers = qpack_buf[0..qpack_len] }, &fbs) catch unreachable;
    return fbs.seek;
}

// Build a QPACK-encoded 200 response
fn buildConnectResponse(buf: []u8) usize {
    const headers = [_]qpack.Header{
        .{ .name = ":status", .value = "200" },
    };
    var qpack_buf: [256]u8 = undefined;
    const qpack_len = qpack.encodeHeaders(&headers, &qpack_buf) catch unreachable;
    var fbs = io.fixedBufferStream(buf);
    h3_frame.write(.{ .headers = qpack_buf[0..qpack_len] }, &fbs) catch unreachable;
    return fbs.seek;
}

// Build WT bidi stream type prefix: 0x41 + session_id
fn buildWtBidiPrefix(buf: []u8, session_id: u64) usize {
    var fbs = io.fixedBufferStream(buf);
    const w = &fbs;
    packet.writeVarInt(w, WT_BIDI_STREAM_TYPE) catch unreachable;
    packet.writeVarInt(w, session_id) catch unreachable;
    return fbs.seek;
}

// Build WT uni stream type prefix: 0x54 + session_id
fn buildWtUniPrefix(buf: []u8, session_id: u64) usize {
    var fbs = io.fixedBufferStream(buf);
    const w = &fbs;
    packet.writeVarInt(w, WT_UNI_STREAM_TYPE) catch unreachable;
    packet.writeVarInt(w, session_id) catch unreachable;
    return fbs.seek;
}

/// The two halves of a flow-controlled setup: the window we grant the peer,
/// and the one its SETTINGS granted us. The peer's arrive before the session
/// does, as they do on the wire.
const FcCredits = struct {
    streams: u64,
    data: u64,
    peer_bidi: ?u64 = null,
    peer_uni: ?u64 = null,
    peer_data: ?u64 = null,
};

// Full setup: QUIC conn + H3 + WT + peer control stream + active session.
// Returns the session_id of the active session.
const WtTestSetup = struct {
    quic_conn: quic_connection.Connection,
    h3: h3_conn.H3Connection,
    wt: WebTransportConnection,

    fn initServer(self: *WtTestSetup) !u64 {
        return self.initServerWith(null);
    }

    /// `credits` turns draft-13 §5.1 session flow control on: both endpoints
    /// advertise WT_MAX_SESSIONS above one on the draft-13 codepoint — which is
    /// what makes the limits bind at all — and we advertise that per-session
    /// window. Without it the peer looks like Chrome: WebTransport over the
    /// pre-draft-13 settings, and no session flow control anywhere.
    fn initServerWith(self: *WtTestSetup, credits: ?FcCredits) !u64 {
        self.quic_conn = createTestQuicConn(true);
        self.h3 = h3_conn.H3Connection.init(testing.allocator, &self.quic_conn, true);
        self.h3.local_settings.enable_connect_protocol = true;
        self.h3.local_settings.enable_webtransport = true;
        self.h3.local_settings.h3_datagram = true;
        if (credits != null) self.h3.local_settings.wt_max_sessions_v13 = MAX_SESSIONS;
        try self.h3.initConnection();
        try injectPeerControlStream(&self.quic_conn, &self.h3, true);
        if (credits) |c| {
            self.h3.peer_settings.wt_max_sessions_v13 = MAX_SESSIONS;
            self.h3.peer_settings.wt_initial_max_streams_bidi = c.peer_bidi;
            self.h3.peer_settings.wt_initial_max_streams_uni = c.peer_uni;
            self.h3.peer_settings.wt_initial_max_data = c.peer_data;
        }
        self.wt = WebTransportConnection.init(testing.allocator, &self.h3, &self.quic_conn, true);
        if (credits) |c| self.wt.grants = .{
            .max_streams_bidi = c.streams,
            .max_streams_uni = c.streams,
            .max_data = c.data,
        };

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

    const stream_id = try setup.wt.openBidiStream(session_id, null);
    const stream = setup.quic_conn.streams.getStream(stream_id).?;

    // Write buffer should contain WT bidi prefix: 0x41 + session_id
    try testing.expect(stream.send.write_buffer.items.len >= 2);
    // Parse the prefix
    var fbs = io.fixedBufferStream(stream.send.write_buffer.items);
    const reader = &fbs;
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

    const stream_id = try setup.wt.openUniStream(session_id, null);
    const send_stream = setup.quic_conn.streams.send_streams.get(stream_id).?;

    // Write buffer should contain WT uni prefix: 0x54 + session_id
    try testing.expect(send_stream.write_buffer.items.len >= 2);
    var fbs = io.fixedBufferStream(send_stream.write_buffer.items);
    const reader = &fbs;
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

    const stream_id = try setup.wt.openBidiStream(session_id, null);
    try setup.wt.sendStreamData(stream_id, "Hello WT!");

    const stream = setup.quic_conn.streams.getStream(stream_id).?;
    // Write buffer should contain prefix + "Hello WT!"
    const items = stream.send.write_buffer.items;
    try testing.expect(items.len > 9);
    // The payload should end with "Hello WT!"
    try testing.expectEqualStrings("Hello WT!", items[items.len - 9 ..]);
}

test "WT integration: getSendStreamStats returns byte counters" {
    var setup: WtTestSetup = undefined;
    const session_id = try setup.initServer();
    defer setup.deinit();

    const stream_id = try setup.wt.openBidiStream(session_id, null);
    try setup.wt.sendStreamData(stream_id, "Hello WT!");

    const stats = setup.wt.getSendStreamStats(stream_id).?;
    // write_offset includes WT type prefix + session_id varint + "Hello WT!"
    try testing.expect(stats.bytes_written > 9);
    // Nothing sent to network yet (no packet packing happened)
    try testing.expectEqual(@as(u64, 0), stats.bytes_sent);
    try testing.expectEqual(@as(u64, 0), stats.bytes_acknowledged);
}

test "WT integration: getRecvStreamStats returns byte counters" {
    var setup: WtTestSetup = undefined;
    const session_id = try setup.initServer();
    defer setup.deinit();

    const stream_id = try setup.wt.openBidiStream(session_id, null);
    const stats = setup.wt.getRecvStreamStats(stream_id).?;
    // Fresh stream — no data received or read
    try testing.expectEqual(@as(u64, 0), stats.bytes_received);
    try testing.expectEqual(@as(u64, 0), stats.bytes_read);
}

test "WT integration: stream stats returns null for unknown stream" {
    var setup: WtTestSetup = undefined;
    _ = try setup.initServer();
    defer setup.deinit();

    try testing.expect(setup.wt.getSendStreamStats(999) == null);
    try testing.expect(setup.wt.getRecvStreamStats(999) == null);
}

test "WT integration: closeStream sends FIN" {
    var setup: WtTestSetup = undefined;
    const session_id = try setup.initServer();
    defer setup.deinit();

    const stream_id = try setup.wt.openBidiStream(session_id, null);
    setup.wt.closeStream(stream_id);

    const stream = setup.quic_conn.streams.getStream(stream_id).?;
    try testing.expect(stream.send.fin_queued);
}

test "WT integration: stopSending sets stop_sending_err without resetting send" {
    var setup: WtTestSetup = undefined;
    const session_id = try setup.initServer();
    defer setup.deinit();

    const stream_id = try setup.wt.openBidiStream(session_id, null);
    try setup.wt.sendStreamData(stream_id, "data");

    // stopSending should set recv stop_sending_err but NOT reset the send side
    setup.wt.stopSending(stream_id, 42);

    const stream = setup.quic_conn.streams.getStream(stream_id).?;
    try testing.expect(stream.recv.stop_sending_err != null);
    try testing.expect(stream.send.reset_err == null); // send side untouched
    try testing.expect(!stream.send.fin_queued); // FIN not queued either
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
    const quarter_id = packet.readVarInt(&fbs) catch unreachable;
    try testing.expectEqual(session_id / 4, quarter_id);
    // Rest is payload
    try testing.expectEqualStrings("dgram payload", dgram_buf[fbs.seek..dgram_len]);
}

test "WT integration: poll receives datagram demuxed by session" {
    var setup: WtTestSetup = undefined;
    const session_id = try setup.initServer();
    defer setup.deinit();

    // Manually push a datagram into the QUIC recv queue
    const quarter_id = session_id / 4;
    var dgram_buf: [64]u8 = undefined;
    var fbs = io.fixedBufferStream(&dgram_buf);
    packet.writeVarInt(&fbs, quarter_id) catch unreachable;
    fbs.writeAll("hello dgram") catch unreachable;
    try testing.expect(setup.quic_conn.datagram_recv_queue.push(dgram_buf[0..fbs.seek]));

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
    h3_frame.write(.{ .headers = qpack_buf[0..qpack_len] }, &fbs) catch unreachable;

    const stream = quic_conn.streams.getStream(session_id).?;
    const offset = stream.recv.sorter.highestReceived();
    try stream.recv.handleStreamFrame(offset, fbs.buffered(), false);

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


/// Unwrap a capsule written to a CONNECT stream. Asserts the DATA wrapper is
/// there: sent bare, the peer ignores the capsule as an unknown H3 frame type.
fn expectCapsulePayload(written: []const u8) ![]const u8 {
    const outer = try h3_frame.parse(written);
    switch (outer.frame) {
        .data => |payload| return payload,
        else => return error.CapsuleNotWrappedInDataFrame,
    }
}

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
    const close_data = try expectCapsulePayload(stream.send.write_buffer.items[pre_len..]);
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
    } }, &fbs) catch unreachable;

    const stream = setup.quic_conn.streams.getStream(session_id).?;
    const offset = stream.recv.sorter.highestReceived();
    try stream.recv.handleStreamFrame(offset, fbs.buffered(), false);

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
    const wt_stream_id = try setup.wt.openBidiStream(session_id, null);
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

    const stream_id = try setup.wt.openUniStream(session_id, null);
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
    const wt_stream_id = try setup.wt.openBidiStream(session_id, null);

    // Close the session
    setup.wt.closeSession(session_id);

    // The stream should have been reset with WEBTRANSPORT_SESSION_GONE
    const stream = setup.quic_conn.streams.getStream(wt_stream_id).?;
    try testing.expectEqual(@as(?u64, WEBTRANSPORT_SESSION_GONE), stream.send.reset_err);
    try testing.expectEqual(@as(?u64, WEBTRANSPORT_SESSION_GONE), stream.recv.stop_sending_err);
}

/// Poll until the connection yields `want`, or give up. Events arrive in a
/// fixed order, so the one under test may sit behind a couple of others.
fn pollFor(wt: *WebTransportConnection, comptime want: std.meta.Tag(WtEvent)) !WtEvent {
    var tries: usize = 0;
    while (tries < 16) : (tries += 1) {
        const ev = (try wt.poll()) orelse continue;
        if (std.meta.activeTag(ev) == want) return ev;
        if (ev == .stream_data and ev.stream_data.data.len > 0) {
            testing.allocator.free(ev.stream_data.data);
        }
    }
    return error.EventNotSeen;
}

test "WT integration: a peer RESET_STREAM surfaces with its application code" {
    var setup: WtTestSetup = undefined;
    const session_id = try setup.initServer();
    defer setup.deinit();

    const stream_id = try setup.wt.openBidiStream(session_id, null);
    const stream = setup.quic_conn.streams.getStream(stream_id).?;
    try stream.recv.handleResetStream(appErrorCodeToH3(42), 0);

    const ev = try pollFor(&setup.wt, .stream_reset);
    try testing.expectEqual(stream_id, ev.stream_reset.stream_id);
    try testing.expectEqual(session_id, ev.stream_reset.session_id);
    try testing.expectEqual(@as(u32, 42), ev.stream_reset.error_code);

    // Once reported, it stays reported once — a reset is news, not a state to
    // re-announce on every poll.
    try testing.expectError(error.EventNotSeen, pollFor(&setup.wt, .stream_reset));
}

test "WT integration: a peer STOP_SENDING surfaces with its application code" {
    var setup: WtTestSetup = undefined;
    const session_id = try setup.initServer();
    defer setup.deinit();

    const stream_id = try setup.wt.openBidiStream(session_id, null);
    const stream = setup.quic_conn.streams.getStream(stream_id).?;
    // What Connection.handleFrame does on an inbound STOP_SENDING.
    stream.send.reset(appErrorCodeToH3(19));
    stream.send.peer_stop_sending = appErrorCodeToH3(19);

    const ev = try pollFor(&setup.wt, .stream_stop_sending);
    try testing.expectEqual(stream_id, ev.stream_stop_sending.stream_id);
    try testing.expectEqual(@as(u32, 19), ev.stream_stop_sending.error_code);
}

test "WT integration: our own resetStream does not echo back as a peer abort" {
    var setup: WtTestSetup = undefined;
    const session_id = try setup.initServer();
    defer setup.deinit();

    const stream_id = try setup.wt.openBidiStream(session_id, null);
    setup.wt.resetStream(stream_id, 42);

    // resetStream sets the send side's reset_err, which is also where an
    // inbound STOP_SENDING lands. Only `peer_stop_sending` distinguishes them.
    try testing.expectError(error.EventNotSeen, pollFor(&setup.wt, .stream_stop_sending));
    try testing.expectError(error.EventNotSeen, pollFor(&setup.wt, .stream_reset));
}

test "WT integration: a reset code outside the WebTransport range reports 0" {
    var setup: WtTestSetup = undefined;
    const session_id = try setup.initServer();
    defer setup.deinit();

    const stream_id = try setup.wt.openBidiStream(session_id, null);
    const stream = setup.quic_conn.streams.getStream(stream_id).?;
    // An H3-level code, not an application one: there is no app code to report,
    // and the peer still needs to hear the stream died.
    try stream.recv.handleResetStream(@intFromEnum(h3_conn.H3Error.request_cancelled), 0);

    const ev = try pollFor(&setup.wt, .stream_reset);
    try testing.expectEqual(@as(u32, 0), ev.stream_reset.error_code);
}

test "WT: drainSession sends DRAIN_WEBTRANSPORT_SESSION capsule" {
    var setup: WtTestSetup = undefined;
    const session_id = try setup.initServer();
    defer setup.deinit();

    const stream = setup.quic_conn.streams.getStream(session_id).?;
    const pre_len = stream.send.write_buffer.items.len;

    try setup.wt.drainSession(session_id);

    // Should have written DRAIN capsule (type 0x78ae, length 0)
    const drain_data = try expectCapsulePayload(stream.send.write_buffer.items[pre_len..]);
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
    h3_frame.write(.{ .drain_webtransport_session = {} }, &fbs) catch unreachable;

    const stream = setup.quic_conn.streams.getStream(session_id).?;
    const offset = stream.recv.sorter.highestReceived();
    try stream.recv.handleStreamFrame(offset, fbs.buffered(), false);

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

    const stream_id = try setup.wt.openBidiStream(session_id, null);
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
    const close_data = try expectCapsulePayload(stream.send.write_buffer.items[pre_len..]);
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
    packet.writeVarInt(&fbs, WT_BIDI_STREAM_TYPE) catch unreachable;
    packet.writeVarInt(&fbs, 1) catch unreachable; // Invalid: not divisible by 4

    const stream = try setup.quic_conn.streams.getOrCreateStream(4);
    try stream.recv.handleStreamFrame(0, fbs.buffered(), false);

    const ev = try setup.wt.poll();
    // Should return null (connection closed with H3_ID_ERROR)
    try testing.expect(ev == null);
    // Connection should be closing with H3_ID_ERROR (RFC 9114 §8.1)
    try testing.expect(setup.quic_conn.local_err != null);
    try testing.expect(setup.quic_conn.local_err.?.is_app);
    try testing.expectEqual(@intFromEnum(h3_conn.H3Error.id_error), setup.quic_conn.local_err.?.code);
}

test "WT: invalid session ID triggers H3_ID_ERROR on uni stream" {
    var setup: WtTestSetup = undefined;
    _ = try setup.initServer();
    defer setup.deinit();

    // Inject WT uni prefix with an invalid session ID (1 — not a client-initiated bidi = 4*n)
    var prefix_buf: [16]u8 = undefined;
    var fbs = io.fixedBufferStream(&prefix_buf);
    packet.writeVarInt(&fbs, WT_UNI_STREAM_TYPE) catch unreachable;
    packet.writeVarInt(&fbs, 1) catch unreachable; // Invalid: not divisible by 4

    const rs = try setup.quic_conn.streams.getOrCreateRecvStream(14);
    try rs.handleStreamFrame(0, fbs.buffered(), false);

    const ev = try setup.wt.poll();
    // Should return null (connection closed with H3_ID_ERROR)
    try testing.expect(ev == null);
    // Connection should be closing with H3_ID_ERROR (RFC 9114 §8.1)
    try testing.expect(setup.quic_conn.local_err != null);
    try testing.expect(setup.quic_conn.local_err.?.is_app);
    try testing.expectEqual(@intFromEnum(h3_conn.H3Error.id_error), setup.quic_conn.local_err.?.code);
}

test "WT: uni stream to unknown session gets BUFFERED_STREAM_REJECTED" {
    var setup: WtTestSetup = undefined;
    _ = try setup.initServer();
    defer setup.deinit();

    // Inject WT uni prefix referencing non-existent session 8
    var prefix_buf: [16]u8 = undefined;
    var fbs = io.fixedBufferStream(&prefix_buf);
    packet.writeVarInt(&fbs, WT_UNI_STREAM_TYPE) catch unreachable;
    packet.writeVarInt(&fbs, 8) catch unreachable; // Valid format but session doesn't exist

    const rs = try setup.quic_conn.streams.getOrCreateRecvStream(14);
    try rs.handleStreamFrame(0, fbs.buffered(), false);

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
    try h3_frame.write(.{ .drain_webtransport_session = {} }, &fbs);
    const written = fbs.buffered();
    try testing.expect(written.len > 0);

    const result = try h3_frame.parse(written);
    try testing.expectEqual(h3_frame.H3FrameType.drain_webtransport_session, std.meta.activeTag(result.frame));
}

test "WT integration: finished uni streams are reclaimed, not retained for the connection" {
    var setup: WtTestSetup = undefined;
    const session_id = try setup.initServer();
    defer setup.deinit();

    // The H3 control stream is the one uni stream that must survive.
    const baseline = setup.quic_conn.streams.recv_streams.count();
    try testing.expectEqual(@as(u32, 1), baseline);

    // 40 short-lived uni streams, the shape MoQ puts objects on.
    var i: u64 = 0;
    while (i < 40) : (i += 1) {
        const stream_id = 6 + i * 4; // client uni: 2, 6, 10, ... (2 is control)
        var prefix_buf: [16]u8 = undefined;
        const prefix_len = buildWtUniPrefix(&prefix_buf, session_id);
        const rs = try setup.quic_conn.streams.getOrCreateRecvStream(stream_id);
        try rs.handleStreamFrame(0, prefix_buf[0..prefix_len], false);
        try rs.handleStreamFrame(prefix_len, "object", true);

        // Drain every event this stream produces, then reclaim as the loop does.
        while (try setup.wt.poll()) |ev| {
            switch (ev) {
                .stream_data => |sd| testing.allocator.free(sd.data),
                else => {},
            }
        }
        setup.wt.drainDisposalQueue();
        setup.quic_conn.streams.drainDisposalQueue();
    }

    try testing.expectEqual(baseline, setup.quic_conn.streams.recv_streams.count());
    // The per-stream bookkeeping the WT layer keeps alongside them goes too.
    try testing.expectEqual(@as(u32, 0), setup.wt.wt_uni_streams.count());
    try testing.expectEqual(@as(u32, 0), setup.wt.fin_delivered.count());
}

// ---- Group H: draft-13 session flow control ----

/// Parse everything written to a CONNECT stream, asserting each capsule is
/// wrapped in a DATA frame (RFC 9297 §3.2) and unwrapping it.
fn collectCapsules(written: []const u8, out: []h3_frame.H3Frame) ![]h3_frame.H3Frame {
    var pos: usize = 0;
    var count: usize = 0;
    while (pos < written.len) {
        const outer = try h3_frame.parse(written[pos..]);
        pos += outer.consumed;
        const payload = switch (outer.frame) {
            .data => |p| p,
            else => return error.CapsuleNotWrappedInDataFrame,
        };
        var inner: usize = 0;
        while (inner < payload.len) {
            const capsule = try h3_frame.parse(payload[inner..]);
            inner += capsule.consumed;
            if (count == out.len) return error.TooManyCapsules;
            out[count] = capsule.frame;
            count += 1;
        }
    }
    return out[0..count];
}

/// Feed bytes to a session's CONNECT stream as if the peer had sent them.
fn injectOnConnectStream(setup: *WtTestSetup, session_id: u64, data: []const u8) !void {
    const stream = setup.quic_conn.streams.getStream(session_id).?;
    try stream.recv.handleStreamFrame(stream.recv.sorter.highestReceived(), data, false);
}

/// Wrap capsules in the DATA frame RFC 9297 §3.2 asks for.
fn wrapCapsules(buf: []u8, frames: []const h3_frame.H3Frame) []const u8 {
    var inner_buf: [256]u8 = undefined;
    var inner = io.fixedBufferStream(&inner_buf);
    for (frames) |f| h3_frame.write(f, &inner) catch unreachable;

    var fbs = io.fixedBufferStream(buf);
    h3_frame.write(.{ .data = inner.buffered() }, &fbs) catch unreachable;
    return fbs.buffered();
}

test "WT flow control: a draft-13 session is granted its window, once" {
    var setup: WtTestSetup = undefined;
    const session_id = try setup.initServerWith(.{ .streams = 8, .data = 4096 });
    defer setup.deinit();

    const stream = setup.quic_conn.streams.getStream(session_id).?;
    const pre_len = stream.send.write_buffer.items.len;
    _ = try setup.wt.poll();

    var buf: [8]h3_frame.H3Frame = undefined;
    const capsules = try collectCapsules(stream.send.write_buffer.items[pre_len..], &buf);
    try testing.expectEqualDeep(&[_]h3_frame.H3Frame{
        .{ .wt_max_streams_bidi = 8 },
        .{ .wt_max_streams_uni = 8 },
        .{ .wt_max_data = 4096 },
    }, capsules);

    // §5.6.2 values are cumulative: restating them every poll would be noise.
    const after = stream.send.write_buffer.items.len;
    _ = try setup.wt.poll();
    try testing.expectEqual(after, stream.send.write_buffer.items.len);
}

test "WT flow control: a peer without draft-13 settings is left alone" {
    // The Chrome and quic-go shape: WebTransport over the pre-draft-13
    // settings. Granting credit there would be noise, and reading the absent
    // credit as §9.2's default of zero would stop us opening a single stream.
    var setup: WtTestSetup = undefined;
    const session_id = try setup.initServer();
    defer setup.deinit();

    const stream = setup.quic_conn.streams.getStream(session_id).?;
    const pre_len = stream.send.write_buffer.items.len;
    _ = try setup.wt.poll();
    try testing.expectEqual(pre_len, stream.send.write_buffer.items.len);

    setup.h3.peer_settings.wt_initial_max_streams_bidi = 0;
    setup.h3.peer_settings.wt_initial_max_data = 0;
    _ = try setup.wt.poll();
    _ = try setup.wt.openBidiStream(session_id, null);
}

test "WT flow control: a spent stream credit blocks the open and complains once" {
    var setup: WtTestSetup = undefined;
    const session_id = try setup.initServerWith(.{
        .streams = 8,
        .data = 4096,
        .peer_bidi = 1,
        .peer_uni = 0,
    });
    defer setup.deinit();

    _ = try setup.wt.poll(); // drain the grant this session starts with
    _ = try setup.wt.openBidiStream(session_id, null);
    try testing.expectError(error.WtStreamLimitReached, setup.wt.openBidiStream(session_id, null));
    try testing.expectError(error.WtStreamLimitReached, setup.wt.openUniStream(session_id, null));

    const stream = setup.quic_conn.streams.getStream(session_id).?;
    const pre_len = stream.send.write_buffer.items.len;
    _ = try setup.wt.poll();

    var buf: [8]h3_frame.H3Frame = undefined;
    const capsules = try collectCapsules(stream.send.write_buffer.items[pre_len..], &buf);
    try testing.expectEqualDeep(&[_]h3_frame.H3Frame{
        .{ .wt_streams_blocked_bidi = 1 },
        .{ .wt_streams_blocked_uni = 0 },
    }, capsules);

    // The limit has not moved, so neither has anything worth saying.
    const after = stream.send.write_buffer.items.len;
    try testing.expectError(error.WtStreamLimitReached, setup.wt.openBidiStream(session_id, null));
    _ = try setup.wt.poll();
    try testing.expectEqual(after, stream.send.write_buffer.items.len);
}

test "WT flow control: WT_MAX_STREAMS from the peer unblocks the open" {
    var setup: WtTestSetup = undefined;
    const session_id = try setup.initServerWith(.{ .streams = 8, .data = 4096, .peer_bidi = 0 });
    defer setup.deinit();

    try testing.expectError(error.WtStreamLimitReached, setup.wt.openBidiStream(session_id, null));

    var wire: [64]u8 = undefined;
    try injectOnConnectStream(&setup, session_id, wrapCapsules(&wire, &.{.{ .wt_max_streams_bidi = 3 }}));
    _ = try setup.wt.poll();

    _ = try setup.wt.openBidiStream(session_id, null);
    _ = try setup.wt.openBidiStream(session_id, null);
    _ = try setup.wt.openBidiStream(session_id, null);
    try testing.expectError(error.WtStreamLimitReached, setup.wt.openBidiStream(session_id, null));
}

test "WT flow control: a spent data credit blocks the write, and WT_MAX_DATA frees it" {
    var setup: WtTestSetup = undefined;
    const session_id = try setup.initServerWith(.{ .streams = 8, .data = 4096, .peer_data = 4 });
    defer setup.deinit();

    _ = try setup.wt.poll(); // drain the grant this session starts with
    const stream_id = try setup.wt.openBidiStream(session_id, null);
    try setup.wt.sendStreamData(stream_id, "abcd");
    try testing.expectError(error.WtDataLimitReached, setup.wt.sendStreamData(stream_id, "e"));

    const stream = setup.quic_conn.streams.getStream(session_id).?;
    const pre_len = stream.send.write_buffer.items.len;
    _ = try setup.wt.poll();
    var buf: [4]h3_frame.H3Frame = undefined;
    const capsules = try collectCapsules(stream.send.write_buffer.items[pre_len..], &buf);
    try testing.expectEqualDeep(&[_]h3_frame.H3Frame{.{ .wt_data_blocked = 4 }}, capsules);

    var wire: [64]u8 = undefined;
    try injectOnConnectStream(&setup, session_id, wrapCapsules(&wire, &.{.{ .wt_max_data = 8 }}));
    _ = try setup.wt.poll();
    try setup.wt.sendStreamData(stream_id, "efgh");
    try testing.expectError(error.WtDataLimitReached, setup.wt.sendStreamData(stream_id, "i"));
}

test "WT flow control: capsules sharing one read are all acted on" {
    // The CONNECT stream read used to yield one frame and drop the rest, so a
    // close that shared a packet with a credit update was never seen.
    var setup: WtTestSetup = undefined;
    const session_id = try setup.initServerWith(.{ .streams = 8, .data = 4096 });
    defer setup.deinit();

    var wire: [128]u8 = undefined;
    const framed = wrapCapsules(&wire, &.{
        .{ .wt_max_streams_bidi = 2 },
        .{ .close_webtransport_session = .{ .error_code = 7, .reason = "done" } },
    });
    try injectOnConnectStream(&setup, session_id, framed);

    const ev = try pollFor(&setup.wt, .session_closed);
    try testing.expectEqual(@as(u32, 7), ev.session_closed.error_code);
    try testing.expectEqualStrings("done", ev.session_closed.reason);
}

test "WT flow control: the peer's opens slide our grant forward" {
    var setup: WtTestSetup = undefined;
    const session_id = try setup.initServerWith(.{ .streams = 2, .data = 4096 });
    defer setup.deinit();

    const stream = setup.quic_conn.streams.getStream(session_id).?;
    _ = try setup.wt.poll(); // initial grant

    // Peer opens one of its two bidi streams: half the window, so top it up.
    var prefix: [16]u8 = undefined;
    const len = buildWtBidiPrefix(&prefix, session_id);
    const peer_stream = try setup.quic_conn.streams.getOrCreateStream(4);
    try peer_stream.recv.handleStreamFrame(0, prefix[0..len], false);

    const pre_len = stream.send.write_buffer.items.len;
    _ = try setup.wt.poll();
    _ = try setup.wt.poll();

    var buf: [4]h3_frame.H3Frame = undefined;
    const capsules = try collectCapsules(stream.send.write_buffer.items[pre_len..], &buf);
    try testing.expectEqualDeep(&[_]h3_frame.H3Frame{.{ .wt_max_streams_bidi = 3 }}, capsules);
}
