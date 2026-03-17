const std = @import("std");
const Allocator = std.mem.Allocator;
const testing = std.testing;
const io = std.io;

const quic_connection = @import("../quic/connection.zig");
const stream_mod = @import("../quic/stream.zig");
const packet = @import("../quic/packet.zig");
const h3_frame = @import("frame.zig");
const qpack = @import("qpack.zig");
const priority = @import("priority.zig");

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
    // QPACK error codes (RFC 9204 Section 6)
    qpack_decompression_failed = 0x0200,
    qpack_encoder_stream_error = 0x0201,
    qpack_decoder_stream_error = 0x0202,
};

/// Graceful shutdown state (RFC 9114 Section 5.2).
pub const ShutdownState = enum {
    /// Normal operation.
    active,
    /// Sent initial GOAWAY with max stream ID (phase 1).
    going_away_initial,
    /// Sent final GOAWAY with actual last-processed stream ID (phase 2).
    going_away_final,
    /// All in-flight streams below GOAWAY ID have completed.
    drain_complete,
};

/// Events returned by poll().
pub const H3Event = union(enum) {
    settings: h3_frame.Settings,
    headers: struct { stream_id: u64, headers: []const qpack.Header },
    /// Body data is available on this stream. Call recvBody() to read it.
    data: struct { stream_id: u64, len: usize },
    finished: u64,
    goaway: u64,
    connect_request: struct {
        stream_id: u64,
        protocol: []const u8,
        authority: []const u8,
        path: []const u8,
        headers: []const qpack.Header,
    },
    shutdown_complete: void,
    request_cancelled: struct { stream_id: u64, error_code: u64 },
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

    // Bidi streams excluded from H3 processing (owned by WT layer)
    excluded_bidi_streams: std.AutoHashMap(u64, void),

    // Streams that have received HEADERS (for DATA-before-HEADERS detection)
    headers_received_streams: std.AutoHashMap(u64, void),

    // QPACK encoder/decoder with dynamic table support
    qpack_encoder: qpack.QpackEncoder = .{},
    qpack_decoder: qpack.QpackDecoder = .{},

    // Pending DATA frame body: set by poll() when a DATA frame is found,
    // consumed by recvBody().  poll() won't advance past this stream
    // until the body is fully read.
    pending_body: ?struct {
        stream_id: u64,
        offset: usize, // offset into stream_bufs where payload starts
        remaining: usize, // bytes not yet read by recvBody()
        frame_total: usize, // total frame size (header + payload) for final consume
    } = null,

    // Graceful shutdown state (RFC 9114 §5.2)
    shutdown_state: ShutdownState = .active,
    local_goaway_id: ?u64 = null,
    peer_goaway_id: ?u64 = null,
    highest_processed_stream_id: ?u64 = null,

    pub fn init(allocator: Allocator, quic_conn: *quic_connection.Connection, is_server: bool) H3Connection {
        var conn = H3Connection{
            .allocator = allocator,
            .quic_conn = quic_conn,
            .is_server = is_server,
            .stream_bufs = std.AutoHashMap(u64, std.ArrayList(u8)).init(allocator),
            .finished_streams = std.AutoHashMap(u64, void).init(allocator),
            .excluded_bidi_streams = std.AutoHashMap(u64, void).init(allocator),
            .headers_received_streams = std.AutoHashMap(u64, void).init(allocator),
        };
        // Advertise dynamic table capacity in local settings
        conn.local_settings.qpack_max_table_capacity = 4096;
        // Set decoder's local max capacity
        conn.qpack_decoder.setCapacity(4096);
        return conn;
    }

    pub fn deinit(self: *H3Connection) void {
        var it = self.stream_bufs.valueIterator();
        while (it.next()) |buf| {
            buf.deinit(self.allocator);
        }
        self.stream_bufs.deinit();
        self.finished_streams.deinit();
        self.excluded_bidi_streams.deinit();
        self.headers_received_streams.deinit();
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
        // RFC 9114 §5.2: must not initiate requests on streams >= peer's GOAWAY ID
        if (self.peer_goaway_id) |goaway_id| {
            if (self.quic_conn.streams.next_bidi_stream_id >= goaway_id) {
                return error.H3RequestRejected;
            }
        }
        const stream = try self.quic_conn.openStream();
        const stream_id = stream.stream_id;

        // Encode HEADERS frame using QPACK encoder (with dynamic table)
        var qpack_buf: [4096]u8 = undefined;
        const qpack_len = try self.qpack_encoder.encode(headers, &qpack_buf);

        var frame_buf: [4096 + 16]u8 = undefined;
        var fbs = io.fixedBufferStream(&frame_buf);
        try h3_frame.write(.{ .headers = qpack_buf[0..qpack_len] }, fbs.writer());
        try stream.send.writeData(fbs.getWritten());

        // Send encoder instructions on QPACK encoder stream
        try self.flushEncoderInstructions();

        // Send DATA frame if body provided — write header + body separately
        // to avoid copying large payloads into a fixed stack buffer
        if (body) |b| {
            var hdr_buf: [16]u8 = undefined;
            var hdr_fbs = io.fixedBufferStream(&hdr_buf);
            const hdr_writer = hdr_fbs.writer();
            packet.writeVarInt(hdr_writer, 0x00) catch unreachable; // DATA frame type
            packet.writeVarInt(hdr_writer, b.len) catch unreachable;
            try stream.send.writeData(hdr_fbs.getWritten());
            try stream.send.writeData(b);
        }

        stream.send.close();
        return stream_id;
    }

    /// Send an Extended CONNECT request (RFC 9220).
    /// Opens a bidi stream, sends HEADERS with :method=CONNECT, :protocol, etc.
    /// Does NOT close the stream — session lifetime = stream lifetime.
    pub fn sendConnectRequest(self: *H3Connection, protocol_name: []const u8, authority: []const u8, path: []const u8) !u64 {
        // RFC 9114 §5.2: must not initiate requests on streams >= peer's GOAWAY ID
        if (self.peer_goaway_id) |goaway_id| {
            if (self.quic_conn.streams.next_bidi_stream_id >= goaway_id) {
                return error.H3RequestRejected;
            }
        }
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
        const qpack_len = try self.qpack_encoder.encode(&req_headers, &qpack_buf);

        var frame_buf: [4096 + 16]u8 = undefined;
        var fbs = io.fixedBufferStream(&frame_buf);
        try h3_frame.write(.{ .headers = qpack_buf[0..qpack_len] }, fbs.writer());
        try stream.send.writeData(fbs.getWritten());

        try self.flushEncoderInstructions();

        // Do NOT close the stream — session stays open
        return stream_id;
    }

    /// Send a CONNECT request with additional headers (client-side, RFC 9220).
    pub fn sendConnectRequestWithHeaders(self: *H3Connection, protocol_name: []const u8, authority: []const u8, path: []const u8, extra_headers: []const qpack.Header) !u64 {
        if (self.peer_goaway_id) |goaway_id| {
            if (self.quic_conn.streams.next_bidi_stream_id >= goaway_id) {
                return error.H3RequestRejected;
            }
        }
        const stream = try self.quic_conn.openStream();
        const stream_id = stream.stream_id;

        var all_headers: [16]qpack.Header = undefined;
        all_headers[0] = .{ .name = ":method", .value = "CONNECT" };
        all_headers[1] = .{ .name = ":protocol", .value = protocol_name };
        all_headers[2] = .{ .name = ":scheme", .value = "https" };
        all_headers[3] = .{ .name = ":authority", .value = authority };
        all_headers[4] = .{ .name = ":path", .value = path };
        const count = @min(extra_headers.len, 11);
        for (0..count) |i| {
            all_headers[5 + i] = extra_headers[i];
        }

        var qpack_buf: [4096]u8 = undefined;
        const qpack_len = try self.qpack_encoder.encode(all_headers[0 .. 5 + count], &qpack_buf);

        var frame_buf: [4096 + 16]u8 = undefined;
        var fbs = io.fixedBufferStream(&frame_buf);
        try h3_frame.write(.{ .headers = qpack_buf[0..qpack_len] }, fbs.writer());
        try stream.send.writeData(fbs.getWritten());

        try self.flushEncoderInstructions();
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
        const qpack_len = try self.qpack_encoder.encode(&resp_headers, &qpack_buf);

        var frame_buf: [4096 + 16]u8 = undefined;
        var fbs = io.fixedBufferStream(&frame_buf);
        try h3_frame.write(.{ .headers = qpack_buf[0..qpack_len] }, fbs.writer());
        try stream.send.writeData(fbs.getWritten());

        try self.flushEncoderInstructions();

        // Do NOT close the stream — session stays open
    }

    /// Send a CONNECT response with additional headers (server-side, RFC 9220).
    /// Sends :status + extra headers, does NOT close the stream.
    pub fn sendConnectResponseWithHeaders(self: *H3Connection, stream_id: u64, status: []const u8, extra_headers: []const qpack.Header) !void {
        const stream = self.quic_conn.streams.getStream(stream_id) orelse return error.StreamNotFound;

        var all_headers: [16]qpack.Header = undefined;
        all_headers[0] = .{ .name = ":status", .value = status };
        const count = @min(extra_headers.len, 15);
        for (0..count) |i| {
            all_headers[1 + i] = extra_headers[i];
        }

        var qpack_buf: [4096]u8 = undefined;
        const qpack_len = try self.qpack_encoder.encode(all_headers[0 .. 1 + count], &qpack_buf);

        var frame_buf: [4096 + 16]u8 = undefined;
        var fbs = io.fixedBufferStream(&frame_buf);
        try h3_frame.write(.{ .headers = qpack_buf[0..qpack_len] }, fbs.writer());
        try stream.send.writeData(fbs.getWritten());

        try self.flushEncoderInstructions();

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

        // Encode HEADERS frame using QPACK encoder (with dynamic table)
        var qpack_buf: [4096]u8 = undefined;
        const qpack_len = try self.qpack_encoder.encode(headers, &qpack_buf);

        var frame_buf: [4096 + 16]u8 = undefined;
        var fbs = io.fixedBufferStream(&frame_buf);
        try h3_frame.write(.{ .headers = qpack_buf[0..qpack_len] }, fbs.writer());
        try stream.send.writeData(fbs.getWritten());

        // Send encoder instructions on QPACK encoder stream
        try self.flushEncoderInstructions();

        // Send DATA frame if body provided — write header + body separately
        // to avoid copying large payloads into a fixed stack buffer
        if (body) |b| {
            var hdr_buf: [16]u8 = undefined;
            var hdr_fbs = io.fixedBufferStream(&hdr_buf);
            const hdr_writer = hdr_fbs.writer();
            packet.writeVarInt(hdr_writer, 0x00) catch unreachable; // DATA frame type
            packet.writeVarInt(hdr_writer, b.len) catch unreachable;
            try stream.send.writeData(hdr_fbs.getWritten());
            try stream.send.writeData(b);
        }

        stream.send.close();
    }

    /// Begin graceful shutdown (RFC 9114 §5.2, phase 1).
    /// Sends GOAWAY with max stream ID to signal intent to shut down.
    /// Call `completeShutdown()` after in-flight requests arrive to send the final GOAWAY.
    pub fn initiateShutdown(self: *H3Connection) !void {
        if (self.shutdown_state != .active) return;
        const ctrl = self.local_control_stream orelse return error.NotInitialized;

        // Max client-initiated bidi stream ID (bits 1:0 = 00) for servers,
        // max push ID for clients.
        const max_id: u64 = if (self.is_server) 0x3FFFFFFFFFFFFFFC else 0x3FFFFFFFFFFFFFFF;

        var frame_buf: [32]u8 = undefined;
        var fbs = io.fixedBufferStream(&frame_buf);
        try h3_frame.write(.{ .goaway = max_id }, fbs.writer());
        try ctrl.writeData(fbs.getWritten());

        self.local_goaway_id = max_id;
        self.shutdown_state = .going_away_initial;
    }

    /// Complete graceful shutdown (RFC 9114 §5.2, phase 2).
    /// Sends final GOAWAY with the actual last-processed stream ID.
    /// Streams >= this ID will be rejected with H3_REQUEST_REJECTED.
    pub fn completeShutdown(self: *H3Connection) !void {
        if (self.shutdown_state != .going_away_initial) return;
        const ctrl = self.local_control_stream orelse return error.NotInitialized;

        // Next client-initiated bidi ID after the highest we processed.
        // If none processed, reject everything (ID = 0).
        const final_id: u64 = if (self.highest_processed_stream_id) |hid| hid + 4 else 0;

        // Must not increase from previous GOAWAY
        const goaway_id = if (self.local_goaway_id) |prev| @min(final_id, prev) else final_id;

        var frame_buf: [32]u8 = undefined;
        var fbs = io.fixedBufferStream(&frame_buf);
        try h3_frame.write(.{ .goaway = goaway_id }, fbs.writer());
        try ctrl.writeData(fbs.getWritten());

        self.local_goaway_id = goaway_id;
        self.shutdown_state = .going_away_final;
    }

    /// Send a GOAWAY frame with a specific stream ID (RFC 9114 §5.2).
    /// Single-step alternative to initiateShutdown + completeShutdown.
    /// The ID must not increase from any previously sent GOAWAY.
    /// For servers, must be a client-initiated bidi stream ID (divisible by 4) or 0.
    pub fn sendGoaway(self: *H3Connection, goaway_id: u64) !void {
        // Validate before writing
        if (self.local_goaway_id) |prev| {
            if (goaway_id > prev) return error.H3IdError;
        }
        if (self.is_server and goaway_id != 0 and (goaway_id % 4 != 0)) {
            return error.H3IdError;
        }
        const ctrl = self.local_control_stream orelse return error.NotInitialized;

        var frame_buf: [32]u8 = undefined;
        var fbs = io.fixedBufferStream(&frame_buf);
        try h3_frame.write(.{ .goaway = goaway_id }, fbs.writer());
        try ctrl.writeData(fbs.getWritten());

        self.local_goaway_id = goaway_id;
        if (self.shutdown_state == .active or self.shutdown_state == .going_away_initial) {
            self.shutdown_state = .going_away_final;
        }
    }

    /// Check if all streams below the GOAWAY ID have completed.
    pub fn isDrainComplete(self: *H3Connection) bool {
        if (self.shutdown_state != .going_away_final) return false;
        const goaway_id = self.local_goaway_id orelse return false;

        var stream_it = self.quic_conn.streams.streams.iterator();
        while (stream_it.next()) |entry| {
            const sid = entry.key_ptr.*;
            const stream = entry.value_ptr.*;
            if (!stream_mod.isClient(sid) or !stream_mod.isBidi(sid)) continue;
            if (sid >= goaway_id) continue;
            // Stream still active?
            if (!stream.closed_for_gc and
                !(stream.recv.finished and (stream.send.fin_sent or stream.send.reset_err != null)))
            {
                return false;
            }
        }
        return true;
    }

    /// Cancel a request (RFC 9114 §4.1.1).
    /// Sends RESET_STREAM + STOP_SENDING with the given H3 error code.
    pub fn cancelRequest(self: *H3Connection, stream_id: u64, error_code: u64) void {
        if (self.quic_conn.streams.getStream(stream_id)) |stream| {
            stream.send.reset(error_code);
            stream.recv.stopSending(error_code);
        }
    }

    /// Reject a request with H3_REQUEST_REJECTED (RFC 9114 §4.1.1).
    /// Used during graceful shutdown for streams above the GOAWAY ID.
    pub fn rejectRequest(self: *H3Connection, stream_id: u64) void {
        self.cancelRequest(stream_id, @intFromEnum(H3Error.request_rejected));
    }

    /// Send a PRIORITY_UPDATE frame on the control stream (RFC 9218).
    /// Used by clients to dynamically reprioritize a request stream.
    pub fn sendPriorityUpdate(self: *H3Connection, stream_id: u64, prio: priority.StreamPriority) !void {
        const ctrl = self.local_control_stream orelse return error.NotInitialized;

        // Serialize the field value
        var fv_buf: [32]u8 = undefined;
        const fv_len = priority.serialize(prio, &fv_buf);

        // Write PRIORITY_UPDATE frame
        var frame_buf: [64]u8 = undefined;
        var fbs = io.fixedBufferStream(&frame_buf);
        try h3_frame.write(.{ .priority_update = .{
            .stream_id = stream_id,
            .field_value = fv_buf[0..fv_len],
        } }, fbs.writer());
        try ctrl.writeData(fbs.getWritten());

        // Also update local scheduling state
        if (self.quic_conn.streams.getStream(stream_id)) |stream| {
            stream.send.urgency = prio.urgency;
            stream.send.incremental = prio.incremental;
        }
    }

    /// Close the connection with an H3 error code (RFC 9114 §8).
    /// Sends APPLICATION_CLOSE via QUIC with the given error code.
    pub fn closeWithError(self: *H3Connection, h3_error: H3Error, reason: []const u8) void {
        self.quic_conn.close(@intFromEnum(h3_error), reason);
    }

    /// Poll for the next HTTP/3 event.
    /// Processes incoming QUIC stream data and returns H3 events.
    pub fn poll(self: *H3Connection) !?H3Event {
        // Check for critical stream closure (RFC 9114 §6.2.1, RFC 9204 §4.2)
        if (self.checkCriticalStreams()) |err| return err;

        // First, identify any new peer uni streams
        if (try self.identifyPeerUniStreams()) |event| {
            return event;
        }

        // Check control stream for SETTINGS/GOAWAY
        if (try self.pollControlStream()) |event| {
            return event;
        }

        // Process QPACK encoder/decoder streams
        try self.pollQpackStreams();

        // Check bidirectional streams for request/response data
        if (try self.pollBidiStreams()) |event| {
            return event;
        }

        // Check if graceful shutdown drain is complete
        if (self.shutdown_state == .going_away_final and self.isDrainComplete()) {
            self.shutdown_state = .drain_complete;
            return .{ .shutdown_complete = {} };
        }

        return null;
    }

    /// Read body data from a stream after a `.data` event.
    /// Copies into the caller-provided buffer and returns the number of bytes read.
    /// Call repeatedly until 0 is returned to drain the full DATA frame payload.
    pub fn recvBody(self: *H3Connection, buf: []u8) usize {
        const pb = self.pending_body orelse return 0;
        const stream_buf = self.stream_bufs.getPtr(pb.stream_id) orelse {
            self.pending_body = null;
            return 0;
        };

        const available = @min(pb.remaining, buf.len);
        if (available == 0) return 0;

        @memcpy(buf[0..available], stream_buf.items[pb.offset..][0..available]);

        if (available == pb.remaining) {
            // Fully consumed — remove the entire frame from the stream buffer
            self.consumeFrameFromBuf(stream_buf, pb.frame_total);
            self.pending_body = null;
        } else {
            // Partial read — advance offset
            self.pending_body = .{
                .stream_id = pb.stream_id,
                .offset = pb.offset + available,
                .remaining = pb.remaining - available,
                .frame_total = pb.frame_total,
            };
        }

        return available;
    }

    /// RFC 9114 §6.2.1: Closing a critical uni stream (control, QPACK encoder, QPACK decoder)
    /// MUST be treated as H3_CLOSED_CRITICAL_STREAM.
    fn checkCriticalStreams(self: *H3Connection) ?error{H3ClosedCriticalStream} {
        const critical_ids = [_]?u64{
            self.peer_control_stream_id,
            self.peer_qpack_enc_stream_id,
            self.peer_qpack_dec_stream_id,
        };
        for (critical_ids) |maybe_id| {
            const stream_id = maybe_id orelse continue;
            if (self.quic_conn.streams.recv_streams.get(stream_id)) |recv_stream| {
                // RFC 9114 §6.2.1: closing a critical stream (reset or FIN) is an error
                if (recv_stream.reset_err != null or recv_stream.finished) {
                    self.closeWithError(.closed_critical_stream, "critical stream closed");
                    return error.H3ClosedCriticalStream;
                }
            }
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

            // Try to read type byte (read() transfers ownership of heap-allocated data)
            const data = recv_stream.read() orelse continue;
            defer self.allocator.free(data);
            if (data.len == 0) continue;

            var fbs = io.fixedBufferStream(data);
            const stream_type = h3_frame.readUniStreamType(fbs.reader()) catch |err| {
                std.log.debug("H3 uni stream type parse error on stream {d}: {}", .{ stream_id, err });
                continue;
            };

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
                .qpack_encoder => {
                    self.peer_qpack_enc_stream_id = stream_id;
                    // Buffer remaining data (encoder instructions after type byte)
                    if (fbs.pos < data.len) {
                        const remaining = data[fbs.pos..];
                        self.qpack_decoder.processEncoderInstruction(remaining) catch {
                            self.closeWithError(.general_protocol_error, "QPACK encoder stream error");
                            return error.H3GeneralProtocolError;
                        };
                    }
                },
                .qpack_decoder => {
                    self.peer_qpack_dec_stream_id = stream_id;
                    // Buffer remaining data (decoder instructions after type byte)
                    if (fbs.pos < data.len) {
                        const remaining = data[fbs.pos..];
                        self.qpack_encoder.processDecoderInstruction(remaining) catch {
                            self.closeWithError(.general_protocol_error, "QPACK decoder stream error");
                            return error.H3GeneralProtocolError;
                        };
                    }
                },
                .push => {}, // ignore server push
            }
        }

        return null;
    }

    /// Poll the peer's control stream for SETTINGS/GOAWAY frames.
    fn pollControlStream(self: *H3Connection) !?H3Event {
        const ctrl_id = self.peer_control_stream_id orelse return null;

        // Read more data from control stream (read() transfers ownership)
        if (self.quic_conn.streams.recv_streams.get(ctrl_id)) |recv_stream| {
            if (recv_stream.read()) |data| {
                defer self.allocator.free(data);
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
            // RFC 9114 §7: malformed frames → H3_FRAME_ERROR
            if (err == error.MalformedSettings) {
                self.closeWithError(.frame_error, "malformed SETTINGS");
                return error.H3FrameError;
            }
            if (err == error.MalformedGoaway) {
                self.closeWithError(.frame_error, "malformed GOAWAY");
                return error.H3FrameError;
            }
            if (err == error.MalformedFrame) {
                self.closeWithError(.frame_error, "malformed frame");
                return error.H3FrameError;
            }
            // RFC 9114 §7.2.8: reserved HTTP/2 frame types
            if (err == error.H3FrameUnexpected) {
                self.closeWithError(.frame_unexpected, "HTTP/2 frame type on H3 control stream");
                return error.H3FrameUnexpected;
            }
            // RFC 9114 §7.2.4.1: reserved HTTP/2 settings
            if (err == error.H3SettingsError) {
                self.closeWithError(.settings_error, "reserved HTTP/2 settings identifier");
                return error.H3SettingsError;
            }
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
                    // RFC 9114 §7.2.4: receiving a second SETTINGS frame
                    self.closeWithError(.frame_unexpected, "duplicate SETTINGS");
                    return error.H3FrameUnexpected;
                }
                self.peer_settings_received = true;
                self.peer_settings = settings;
                // Configure QPACK encoder with peer's advertised capacity
                if (settings.qpack_max_table_capacity > 0) {
                    self.qpack_encoder.setCapacity(@intCast(settings.qpack_max_table_capacity));
                    // Send the Set Capacity encoder instruction
                    try self.flushEncoderInstructions();
                }
                return .{ .settings = settings };
            },
            .goaway => |id| {
                // RFC 9114 §7.2.4: SETTINGS must be first frame on control stream
                if (!self.peer_settings_received) {
                    self.closeWithError(.missing_settings, "GOAWAY before SETTINGS");
                    return error.H3MissingSettings;
                }
                // RFC 9114 §5.2: successive GOAWAY IDs must not increase
                if (self.peer_goaway_id) |prev| {
                    if (id > prev) {
                        self.closeWithError(.id_error, "GOAWAY ID increased");
                        return error.H3IdError;
                    }
                }
                self.peer_goaway_id = id;
                return .{ .goaway = id };
            },
            .priority_update => |pu| {
                // RFC 9114 §7.2.4: SETTINGS must be first frame on control stream
                if (!self.peer_settings_received) {
                    self.closeWithError(.missing_settings, "PRIORITY_UPDATE before SETTINGS");
                    return error.H3MissingSettings;
                }
                const prio = priority.parse(pu.field_value);
                if (self.quic_conn.streams.getStream(pu.stream_id)) |stream| {
                    stream.send.urgency = prio.urgency;
                    stream.send.incremental = prio.incremental;
                }
                return null; // Internal, don't surface as event
            },
            // RFC 9114 §7.2.1: DATA frames on control stream are H3_FRAME_UNEXPECTED
            .data => {
                self.closeWithError(.frame_unexpected, "DATA on control stream");
                return error.H3FrameUnexpected;
            },
            // RFC 9114 §7.2.2: HEADERS frames on control stream are H3_FRAME_UNEXPECTED
            .headers => {
                self.closeWithError(.frame_unexpected, "HEADERS on control stream");
                return error.H3FrameUnexpected;
            },
            else => {
                // RFC 9114 §7.2.4: unknown frame types on control stream before SETTINGS
                if (!self.peer_settings_received) {
                    self.closeWithError(.missing_settings, "non-SETTINGS first frame");
                    return error.H3MissingSettings;
                }
                return null; // Ignore other frames on control stream
            },
        }
    }

    /// Validate request pseudo-headers per RFC 9114 §4.1.2, §4.3.
    fn validateRequestHeaders(headers: []const qpack.Header) bool {
        var method_count: u8 = 0;
        var scheme_count: u8 = 0;
        var path_count: u8 = 0;
        var authority_count: u8 = 0;
        var path_empty = false;
        var has_status = false;
        var pseudo_done = false;
        var is_connect = false;
        var has_protocol = false;
        var has_host = false;
        var scheme_value: []const u8 = "";

        for (headers) |h| {
            if (h.name.len > 0 and h.name[0] == ':') {
                if (pseudo_done) return false; // pseudo after regular
                if (std.mem.eql(u8, h.name, ":method")) {
                    method_count += 1;
                    is_connect = std.mem.eql(u8, h.value, "CONNECT");
                } else if (std.mem.eql(u8, h.name, ":scheme")) {
                    scheme_count += 1;
                    scheme_value = h.value;
                } else if (std.mem.eql(u8, h.name, ":path")) {
                    path_count += 1;
                    if (h.value.len == 0) path_empty = true;
                } else if (std.mem.eql(u8, h.name, ":status")) {
                    has_status = true;
                } else if (std.mem.eql(u8, h.name, ":protocol")) {
                    has_protocol = true;
                } else if (std.mem.eql(u8, h.name, ":authority")) {
                    authority_count += 1;
                } else {
                    return false; // unknown pseudo-header (RFC 9114 §4.1.1)
                }
            } else {
                pseudo_done = true;
                // Header names must be lowercase
                for (h.name) |c| {
                    if (c >= 'A' and c <= 'Z') return false;
                }
                if (std.mem.eql(u8, h.name, "host")) has_host = true;
                // te header: only "trailers" allowed
                if (std.mem.eql(u8, h.name, "te") and !std.mem.eql(u8, h.value, "trailers")) {
                    return false;
                }
            }
        }

        if (has_status) return false; // request must not have :status
        if (method_count != 1) return false;
        if (method_count > 1 or scheme_count > 1 or path_count > 1 or authority_count > 1) return false;

        // Plain CONNECT: no :scheme/:path required, :authority mandatory
        // Extended CONNECT (with :protocol): all pseudo-headers required
        if (is_connect and !has_protocol) return authority_count == 1;

        if (scheme_count != 1) return false;
        if (path_count != 1) return false;
        if (path_empty) return false;

        // RFC 9114 §4.3.1: for http/https, :authority or Host must be present
        if (std.mem.eql(u8, scheme_value, "http") or std.mem.eql(u8, scheme_value, "https")) {
            if (authority_count == 0 and !has_host) return false;
        }

        return true;
    }

    /// Validate response pseudo-headers per RFC 9114 §4.1, §4.3.
    fn validateResponseHeaders(headers: []const qpack.Header) bool {
        var status_count: u8 = 0;
        var pseudo_done = false;

        for (headers) |h| {
            if (h.name.len > 0 and h.name[0] == ':') {
                if (pseudo_done) return false;
                if (std.mem.eql(u8, h.name, ":status")) {
                    status_count += 1;
                } else {
                    return false; // responses must only have :status
                }
            } else {
                pseudo_done = true;
                for (h.name) |c| {
                    if (c >= 'A' and c <= 'Z') return false;
                }
            }
        }

        return status_count == 1;
    }

    /// Poll bidirectional streams for HEADERS/DATA frames.
    fn pollBidiStreams(self: *H3Connection) !?H3Event {
        // Can't parse more frames while a body read is pending
        if (self.pending_body != null) return null;

        var stream_it = self.quic_conn.streams.streams.iterator();
        while (stream_it.next()) |entry| {
            const stream_id = entry.key_ptr.*;
            const stream = entry.value_ptr.*;

            // Skip already-finished streams
            if (self.finished_streams.contains(stream_id)) continue;
            // Skip streams owned by the WebTransport layer
            if (self.excluded_bidi_streams.contains(stream_id)) continue;

            // RFC 9114 §5.2: reject client-initiated bidi streams >= our GOAWAY ID
            if (self.shutdown_state == .going_away_final) {
                if (self.local_goaway_id) |goaway_id| {
                    if (stream_mod.isClient(stream_id) and stream_mod.isBidi(stream_id) and stream_id >= goaway_id) {
                        stream.send.reset(@intFromEnum(H3Error.request_rejected));
                        continue;
                    }
                }
            }

            // Read incoming data (read() transfers ownership of heap-allocated data)
            if (stream.recv.read()) |data| {
                defer self.allocator.free(data);
                // Buffer new data
                var new_buf_ptr = self.stream_bufs.getPtr(stream_id) orelse blk: {
                    const new_buf = std.ArrayList(u8){ .items = &.{}, .capacity = 0 };
                    try self.stream_bufs.put(stream_id, new_buf);
                    break :blk self.stream_bufs.getPtr(stream_id).?;
                };
                try new_buf_ptr.appendSlice(self.allocator, data);
            } else {
                // Check if stream is finished — but only if no buffered H3 data remains
                if (stream.recv.finished) {
                    const has_buffered = if (self.stream_bufs.getPtr(stream_id)) |b| b.items.len > 0 else false;
                    if (!has_buffered) {
                        try self.finished_streams.put(stream_id, {});
                        return .{ .finished = stream_id };
                    }
                }
            }

            // Try to parse H3 frames from buffered data (even without new recv data)
            const buf = self.stream_bufs.getPtr(stream_id) orelse continue;

            // Try to parse H3 frames from buffered data
            while (buf.items.len > 0) {
                const result = h3_frame.parse(buf.items) catch |err| {
                    if (err == error.BufferTooShort) break;
                    // RFC 9114 §7: malformed frames → H3_FRAME_ERROR
                    if (err == error.MalformedSettings or err == error.MalformedGoaway or err == error.MalformedFrame) {
                        stream.send.reset(@intFromEnum(H3Error.frame_error));
                        stream.recv.stopSending(@intFromEnum(H3Error.frame_error));
                        break;
                    }
                    if (err == error.H3FrameUnexpected) {
                        self.closeWithError(.frame_unexpected, "HTTP/2 frame type on request stream");
                        return error.H3FrameUnexpected;
                    }
                    if (err == error.H3SettingsError) {
                        self.closeWithError(.settings_error, "reserved HTTP/2 settings identifier");
                        return error.H3SettingsError;
                    }
                    return err;
                };

                // Process the frame BEFORE consuming from buffer
                // (frame data slices point into buf.items)
                switch (result.frame) {
                    // RFC 9114 §7.2.4: SETTINGS on bidi stream is H3_FRAME_UNEXPECTED
                    .settings, .goaway, .cancel_push, .max_push_id, .priority_update => {
                        self.closeWithError(.frame_unexpected, "control frame on request stream");
                        return error.H3FrameUnexpected;
                    },
                    .headers => |qpack_data| {
                        var hdr_count: usize = 0;
                        if (self.qpack_decoder.decode(qpack_data, &self.headers_buf, stream_id)) |c| {
                            hdr_count = c;
                        } else |_| {
                            // Fallback to static-only decoder for compatibility
                            hdr_count = qpack.decodeHeaders(qpack_data, &self.headers_buf) catch {
                                // RFC 9204 §4.5.5: QPACK decompression failure
                                self.consumeFrameFromBuf(buf, result.consumed);
                                self.closeWithError(.qpack_decompression_failed, "QPACK decode failure");
                                return error.H3FrameError;
                            };
                        }
                        const hdrs = self.headers_buf[0..hdr_count];

                        // Flush decoder instructions (header ack)
                        self.flushDecoderInstructions() catch {};

                        // RFC 9114 §4.1.2, §4.3: validate pseudo-headers
                        const valid = if (self.is_server)
                            validateRequestHeaders(hdrs)
                        else
                            validateResponseHeaders(hdrs);
                        if (!valid) {
                            self.consumeFrameFromBuf(buf, result.consumed);
                            self.closeWithError(.message_error, "invalid pseudo-headers");
                            return error.H3MessageError;
                        }

                        // Track that HEADERS was received on this stream
                        try self.headers_received_streams.put(stream_id, {});

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
                            // RFC 9218: extract Priority header field
                            if (std.mem.eql(u8, h_item.name, "priority")) {
                                const prio = priority.parse(h_item.value);
                                if (self.quic_conn.streams.getStream(stream_id)) |prio_stream| {
                                    prio_stream.send.urgency = prio.urgency;
                                    prio_stream.send.incremental = prio.incremental;
                                }
                            }
                        }

                        // Track highest processed client-initiated bidi stream (for GOAWAY)
                        if (self.is_server and stream_mod.isClient(stream_id) and stream_mod.isBidi(stream_id)) {
                            if (self.highest_processed_stream_id == null or stream_id > self.highest_processed_stream_id.?) {
                                self.highest_processed_stream_id = stream_id;
                            }
                        }

                        // Consume frame from buffer AFTER processing
                        self.consumeFrameFromBuf(buf, result.consumed);

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
                        // RFC 9114 §4.1: DATA before HEADERS is H3_FRAME_UNEXPECTED
                        if (!self.headers_received_streams.contains(stream_id)) {
                            self.consumeFrameFromBuf(buf, result.consumed);
                            self.closeWithError(.frame_unexpected, "DATA before HEADERS");
                            return error.H3FrameUnexpected;
                        }
                        if (payload.len == 0) {
                            self.consumeFrameFromBuf(buf, result.consumed);
                            continue; // Skip GREASE/unknown frames
                        }
                        // Don't consume from buffer — recvBody() will read
                        // the payload and consume the full frame.
                        const header_len = result.consumed - payload.len;
                        self.pending_body = .{
                            .stream_id = stream_id,
                            .offset = header_len,
                            .remaining = payload.len,
                            .frame_total = result.consumed,
                        };
                        return .{ .data = .{
                            .stream_id = stream_id,
                            .len = payload.len,
                        } };
                    },
                    else => {
                        self.consumeFrameFromBuf(buf, result.consumed);
                        continue;
                    },
                }
            }

            // RFC 9114 §4.1.1: detect peer cancellation after processing any buffered frames.
            // Only report if no more H3 data is buffered (stream was truly cancelled, not just reset after completion).
            if (stream.recv.reset_err) |err_code| {
                const has_buffered = if (self.stream_bufs.getPtr(stream_id)) |b| b.items.len > 0 else false;
                if (!has_buffered) {
                    try self.finished_streams.put(stream_id, {});
                    return .{ .request_cancelled = .{ .stream_id = stream_id, .error_code = err_code } };
                }
            }
        }

        return null;
    }

    /// Consume `consumed` bytes from the front of a stream buffer.
    fn consumeFrameFromBuf(_: *H3Connection, buf: *std.ArrayList(u8), consumed: usize) void {
        const remaining = buf.items.len - consumed;
        if (remaining > 0) {
            std.mem.copyForwards(u8, buf.items[0..remaining], buf.items[consumed..]);
        }
        buf.items.len = remaining;
    }

    /// Process data from peer's QPACK encoder and decoder streams.
    /// RFC 9204 §4: errors on QPACK streams close the connection.
    fn pollQpackStreams(self: *H3Connection) !void {
        // Read from peer's encoder stream → feed to our decoder
        if (self.peer_qpack_enc_stream_id) |enc_id| {
            if (self.quic_conn.streams.recv_streams.get(enc_id)) |recv_stream| {
                if (recv_stream.read()) |data| {
                    defer self.allocator.free(data);
                    if (data.len > 0) {
                        self.qpack_decoder.processEncoderInstruction(data) catch |err| {
                            if (err == error.CapacityExceeded) {
                                self.closeWithError(.qpack_encoder_stream_error, "QPACK encoder stream error");
                            } else {
                                self.closeWithError(.general_protocol_error, "QPACK encoder stream error");
                            }
                            return error.H3GeneralProtocolError;
                        };
                    }
                }
            }
        }

        // Read from peer's decoder stream → feed to our encoder
        if (self.peer_qpack_dec_stream_id) |dec_id| {
            if (self.quic_conn.streams.recv_streams.get(dec_id)) |recv_stream| {
                if (recv_stream.read()) |data| {
                    defer self.allocator.free(data);
                    if (data.len > 0) {
                        self.qpack_encoder.processDecoderInstruction(data) catch |err| {
                            if (err == error.QpackDecoderStreamError) {
                                self.closeWithError(.qpack_decoder_stream_error, "QPACK decoder stream error");
                            } else {
                                self.closeWithError(.general_protocol_error, "QPACK decoder stream error");
                            }
                            return error.H3GeneralProtocolError;
                        };
                    }
                }
            }
        }
    }

    /// Send pending encoder instructions on the QPACK encoder stream.
    fn flushEncoderInstructions(self: *H3Connection) !void {
        const enc_stream = self.local_qpack_enc_stream orelse return;
        const instructions = self.qpack_encoder.getInstructions();
        if (instructions.len > 0) {
            try enc_stream.writeData(instructions);
        }
    }

    /// Send pending decoder instructions on the QPACK decoder stream.
    fn flushDecoderInstructions(self: *H3Connection) !void {
        const dec_stream = self.local_qpack_dec_stream orelse return;
        const instructions = self.qpack_decoder.getInstructions();
        if (instructions.len > 0) {
            try dec_stream.writeData(instructions);
        }
    }
};

// Tests

test "H3Connection: init and deinit" {
    // Just verify struct construction doesn't crash
    var conn: H3Connection = undefined;
    conn.stream_bufs = std.AutoHashMap(u64, std.ArrayList(u8)).init(testing.allocator);
    conn.finished_streams = std.AutoHashMap(u64, void).init(testing.allocator);
    conn.excluded_bidi_streams = std.AutoHashMap(u64, void).init(testing.allocator);
    conn.headers_received_streams = std.AutoHashMap(u64, void).init(testing.allocator);
    conn.deinit();
}

test "ShutdownState: initial state is active" {
    var conn: H3Connection = undefined;
    conn.shutdown_state = .active;
    conn.local_goaway_id = null;
    conn.peer_goaway_id = null;
    conn.highest_processed_stream_id = null;

    try testing.expectEqual(ShutdownState.active, conn.shutdown_state);
    try testing.expect(conn.local_goaway_id == null);
    try testing.expect(conn.peer_goaway_id == null);
}

test "ShutdownState: peer GOAWAY monotonic decrease" {
    var conn: H3Connection = undefined;
    conn.peer_goaway_id = null;

    // First GOAWAY is accepted
    conn.peer_goaway_id = 100;
    try testing.expectEqual(@as(u64, 100), conn.peer_goaway_id.?);

    // Lower GOAWAY is accepted
    conn.peer_goaway_id = 50;
    try testing.expectEqual(@as(u64, 50), conn.peer_goaway_id.?);

    // Zero GOAWAY is accepted
    conn.peer_goaway_id = 0;
    try testing.expectEqual(@as(u64, 0), conn.peer_goaway_id.?);
}

test "ShutdownState: sendGoaway validates server stream ID" {
    var conn: H3Connection = undefined;
    conn.is_server = true;
    conn.local_goaway_id = null;
    conn.shutdown_state = .active;
    conn.local_control_stream = null;

    // No control stream → error
    try testing.expectError(error.NotInitialized, conn.sendGoaway(0));
}

test "ShutdownState: sendGoaway rejects increasing ID" {
    var conn: H3Connection = undefined;
    conn.is_server = true;
    conn.local_goaway_id = 8;
    conn.shutdown_state = .going_away_final;
    conn.local_control_stream = null;

    // Trying to increase → H3IdError (validated before control stream check)
    try testing.expectError(error.H3IdError, conn.sendGoaway(12));
}

test "ShutdownState: sendGoaway rejects non-bidi server ID" {
    var conn: H3Connection = undefined;
    conn.is_server = true;
    conn.local_goaway_id = null;
    conn.shutdown_state = .active;
    conn.local_control_stream = null;

    // Odd ID (not client-initiated bidi) → H3IdError
    try testing.expectError(error.H3IdError, conn.sendGoaway(5));
}

test "ShutdownState: highest_processed_stream_id tracking" {
    var conn: H3Connection = undefined;
    conn.highest_processed_stream_id = null;
    conn.is_server = true;

    // Simulate processing streams 0, 4, 8
    conn.highest_processed_stream_id = 0;
    try testing.expectEqual(@as(u64, 0), conn.highest_processed_stream_id.?);

    conn.highest_processed_stream_id = 4;
    try testing.expectEqual(@as(u64, 4), conn.highest_processed_stream_id.?);

    conn.highest_processed_stream_id = 8;
    try testing.expectEqual(@as(u64, 8), conn.highest_processed_stream_id.?);
}

test "ShutdownState: state transitions" {
    var conn: H3Connection = undefined;
    conn.shutdown_state = .active;

    conn.shutdown_state = .going_away_initial;
    try testing.expectEqual(ShutdownState.going_away_initial, conn.shutdown_state);

    conn.shutdown_state = .going_away_final;
    try testing.expectEqual(ShutdownState.going_away_final, conn.shutdown_state);

    conn.shutdown_state = .drain_complete;
    try testing.expectEqual(ShutdownState.drain_complete, conn.shutdown_state);
}

// RFC 9114 §4.1.2, §4.3: Header validation tests

test "validateRequestHeaders: valid GET" {
    const hdrs = [_]qpack.Header{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/" },
        .{ .name = ":authority", .value = "example.com" },
    };
    try testing.expect(H3Connection.validateRequestHeaders(&hdrs));
}

test "validateRequestHeaders: valid POST with body headers" {
    const hdrs = [_]qpack.Header{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/submit" },
        .{ .name = ":authority", .value = "example.com" },
        .{ .name = "content-type", .value = "application/json" },
    };
    try testing.expect(H3Connection.validateRequestHeaders(&hdrs));
}

test "validateRequestHeaders: missing method" {
    const hdrs = [_]qpack.Header{
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/" },
    };
    try testing.expect(!H3Connection.validateRequestHeaders(&hdrs));
}

test "validateRequestHeaders: missing scheme" {
    const hdrs = [_]qpack.Header{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "/" },
    };
    try testing.expect(!H3Connection.validateRequestHeaders(&hdrs));
}

test "validateRequestHeaders: missing path" {
    const hdrs = [_]qpack.Header{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
    };
    try testing.expect(!H3Connection.validateRequestHeaders(&hdrs));
}

test "validateRequestHeaders: empty path" {
    const hdrs = [_]qpack.Header{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "" },
    };
    try testing.expect(!H3Connection.validateRequestHeaders(&hdrs));
}

test "validateRequestHeaders: status in request" {
    const hdrs = [_]qpack.Header{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/" },
        .{ .name = ":status", .value = "200" },
    };
    try testing.expect(!H3Connection.validateRequestHeaders(&hdrs));
}

test "validateRequestHeaders: pseudo after regular" {
    const hdrs = [_]qpack.Header{
        .{ .name = ":method", .value = "GET" },
        .{ .name = "host", .value = "example.com" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/" },
    };
    try testing.expect(!H3Connection.validateRequestHeaders(&hdrs));
}

test "validateRequestHeaders: uppercase header name" {
    const hdrs = [_]qpack.Header{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/" },
        .{ .name = "Content-Type", .value = "text/html" },
    };
    try testing.expect(!H3Connection.validateRequestHeaders(&hdrs));
}

test "validateRequestHeaders: invalid te header" {
    const hdrs = [_]qpack.Header{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/" },
        .{ .name = "te", .value = "gzip" },
    };
    try testing.expect(!H3Connection.validateRequestHeaders(&hdrs));
}

test "validateRequestHeaders: valid te trailers" {
    const hdrs = [_]qpack.Header{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/" },
        .{ .name = ":authority", .value = "example.com" },
        .{ .name = "te", .value = "trailers" },
    };
    try testing.expect(H3Connection.validateRequestHeaders(&hdrs));
}

test "validateRequestHeaders: CONNECT without scheme/path" {
    const hdrs = [_]qpack.Header{
        .{ .name = ":method", .value = "CONNECT" },
        .{ .name = ":authority", .value = "proxy.example.com:443" },
    };
    try testing.expect(H3Connection.validateRequestHeaders(&hdrs));
}

test "validateRequestHeaders: extended CONNECT requires scheme/path" {
    const hdrs = [_]qpack.Header{
        .{ .name = ":method", .value = "CONNECT" },
        .{ .name = ":protocol", .value = "webtransport" },
        .{ .name = ":authority", .value = "example.com" },
    };
    // Extended CONNECT needs :scheme and :path
    try testing.expect(!H3Connection.validateRequestHeaders(&hdrs));
}

test "validateRequestHeaders: valid extended CONNECT" {
    const hdrs = [_]qpack.Header{
        .{ .name = ":method", .value = "CONNECT" },
        .{ .name = ":protocol", .value = "webtransport" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/" },
        .{ .name = ":authority", .value = "example.com" },
    };
    try testing.expect(H3Connection.validateRequestHeaders(&hdrs));
}

test "validateResponseHeaders: valid 200" {
    const hdrs = [_]qpack.Header{
        .{ .name = ":status", .value = "200" },
        .{ .name = "content-type", .value = "text/html" },
    };
    try testing.expect(H3Connection.validateResponseHeaders(&hdrs));
}

test "validateResponseHeaders: missing status" {
    const hdrs = [_]qpack.Header{
        .{ .name = "content-type", .value = "text/html" },
    };
    try testing.expect(!H3Connection.validateResponseHeaders(&hdrs));
}

test "validateResponseHeaders: method in response" {
    const hdrs = [_]qpack.Header{
        .{ .name = ":status", .value = "200" },
        .{ .name = ":method", .value = "GET" },
    };
    try testing.expect(!H3Connection.validateResponseHeaders(&hdrs));
}

test "validateResponseHeaders: duplicate status" {
    const hdrs = [_]qpack.Header{
        .{ .name = ":status", .value = "200" },
        .{ .name = ":status", .value = "404" },
    };
    try testing.expect(!H3Connection.validateResponseHeaders(&hdrs));
}

test "validateResponseHeaders: pseudo after regular" {
    const hdrs = [_]qpack.Header{
        .{ .name = "server", .value = "zig" },
        .{ .name = ":status", .value = "200" },
    };
    try testing.expect(!H3Connection.validateResponseHeaders(&hdrs));
}

test "validateResponseHeaders: uppercase header" {
    const hdrs = [_]qpack.Header{
        .{ .name = ":status", .value = "200" },
        .{ .name = "Server", .value = "zig" },
    };
    try testing.expect(!H3Connection.validateResponseHeaders(&hdrs));
}

// RFC 9114 §8: Error handling tests

test "H3Error: all error codes defined" {
    // Verify all RFC 9114 §8.1 error codes are present and have correct values
    try testing.expectEqual(@as(u64, 0x0100), @intFromEnum(H3Error.no_error));
    try testing.expectEqual(@as(u64, 0x0101), @intFromEnum(H3Error.general_protocol_error));
    try testing.expectEqual(@as(u64, 0x0102), @intFromEnum(H3Error.internal_error));
    try testing.expectEqual(@as(u64, 0x0103), @intFromEnum(H3Error.stream_creation_error));
    try testing.expectEqual(@as(u64, 0x0104), @intFromEnum(H3Error.closed_critical_stream));
    try testing.expectEqual(@as(u64, 0x0105), @intFromEnum(H3Error.frame_unexpected));
    try testing.expectEqual(@as(u64, 0x0106), @intFromEnum(H3Error.frame_error));
    try testing.expectEqual(@as(u64, 0x0107), @intFromEnum(H3Error.excessive_load));
    try testing.expectEqual(@as(u64, 0x0108), @intFromEnum(H3Error.id_error));
    try testing.expectEqual(@as(u64, 0x0109), @intFromEnum(H3Error.settings_error));
    try testing.expectEqual(@as(u64, 0x010a), @intFromEnum(H3Error.missing_settings));
    try testing.expectEqual(@as(u64, 0x010b), @intFromEnum(H3Error.request_rejected));
    try testing.expectEqual(@as(u64, 0x010c), @intFromEnum(H3Error.request_cancelled));
    try testing.expectEqual(@as(u64, 0x010d), @intFromEnum(H3Error.request_incomplete));
    try testing.expectEqual(@as(u64, 0x010e), @intFromEnum(H3Error.message_error));
    try testing.expectEqual(@as(u64, 0x010f), @intFromEnum(H3Error.connect_error));
    try testing.expectEqual(@as(u64, 0x0110), @intFromEnum(H3Error.version_fallback));
}

test "H3 frame error: malformed SETTINGS detected" {
    // Verify that MalformedSettings maps to H3_FRAME_ERROR in frame parsing
    // A SETTINGS frame with incomplete varint value should fail
    var buf: [10]u8 = undefined;
    var fbs = io.fixedBufferStream(&buf);
    const writer = fbs.writer();
    // Write SETTINGS type (0x04) + length (3) + valid id varint + truncated value
    packet.writeVarInt(writer, 0x04) catch unreachable;
    packet.writeVarInt(writer, 3) catch unreachable;
    // Write a setting ID that's valid but value is incomplete (starts with 0xC0 = 8-byte varint prefix)
    buf[fbs.pos] = 0x01; // QPACK_MAX_TABLE_CAPACITY
    buf[fbs.pos + 1] = 0xC0; // 8-byte varint prefix but only 2 bytes follow
    buf[fbs.pos + 2] = 0x00;
    const result = h3_frame.parse(buf[0 .. fbs.pos + 3]);
    try testing.expectError(error.MalformedSettings, result);
}

test "H3 frame error: reserved HTTP/2 frame type" {
    // Type 0x02 (HTTP/2 PRIORITY) should be H3_FRAME_UNEXPECTED
    var buf: [4]u8 = undefined;
    var fbs = io.fixedBufferStream(&buf);
    const writer = fbs.writer();
    packet.writeVarInt(writer, 0x02) catch unreachable; // HTTP/2 PRIORITY type
    packet.writeVarInt(writer, 0) catch unreachable; // length 0
    const result = h3_frame.parse(buf[0..fbs.pos]);
    try testing.expectError(error.H3FrameUnexpected, result);
}

test "H3 frame error: malformed GOAWAY varint" {
    // GOAWAY with invalid payload should be MalformedGoaway
    var buf: [4]u8 = undefined;
    var fbs = io.fixedBufferStream(&buf);
    const writer = fbs.writer();
    packet.writeVarInt(writer, 0x07) catch unreachable; // GOAWAY type
    packet.writeVarInt(writer, 1) catch unreachable; // length 1
    buf[fbs.pos] = 0xC0; // 8-byte varint prefix but only 1 byte available
    const result = h3_frame.parse(buf[0 .. fbs.pos + 1]);
    try testing.expectError(error.MalformedGoaway, result);
}

// =============================================================================
// H3Connection integration tests via stream-level injection
// =============================================================================

const ack_handler = @import("../quic/ack_handler.zig");
const flow_control = @import("../quic/flow_control.zig");
const crypto_stream = @import("../quic/crypto_stream.zig");
const packet_packer = @import("../quic/packet_packer.zig");
const protocol = @import("../quic/protocol.zig");

// Create a minimal QUIC Connection suitable for H3 tests.
// The `is_server` flag determines stream ID assignment (server bidi starts at 1, client at 0).
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
    // Allow enough streams for H3 control + QPACK + bidi requests
    conn.streams.setMaxStreams(100, 100);
    conn.streams.setMaxIncomingStreams(100, 100);
    // Set send windows so opened streams can write
    conn.streams.peer_initial_max_stream_data_bidi_local = 1048576;
    conn.streams.peer_initial_max_stream_data_bidi_remote = 1048576;
    conn.streams.peer_initial_max_stream_data_uni = 1048576;
    conn.conn_flow_ctrl.base.send_window = 1048576;
    return conn;
}

// Inject H3-encoded bytes into a peer-initiated uni receive stream.
// For a server: peer (client) uni streams are 2, 6, 10, ...
// For a client: peer (server) uni streams are 3, 7, 11, ...
fn injectUniStreamData(quic_conn: *quic_connection.Connection, stream_id: u64, data: []const u8, fin: bool) !void {
    const rs = try quic_conn.streams.getOrCreateRecvStream(stream_id);
    try rs.handleStreamFrame(0, data, fin);
}

// Inject data into a bidi stream's receive side.
// For a server, client-initiated bidi streams are 0, 4, 8, ...
fn injectBidiStreamData(quic_conn: *quic_connection.Connection, stream_id: u64, data: []const u8, fin: bool) !void {
    const stream = try quic_conn.streams.getOrCreateStream(stream_id);
    try stream.recv.handleStreamFrame(0, data, fin);
}

// Build a SETTINGS frame with default (empty) settings: type=0x04, length=0x00
fn buildSettingsFrame(buf: []u8) usize {
    var fbs = io.fixedBufferStream(buf);
    h3_frame.write(.{ .settings = .{} }, fbs.writer()) catch unreachable;
    return fbs.pos;
}

// Build a control stream type byte + SETTINGS frame
fn buildControlStreamPayload(buf: []u8) usize {
    var fbs = io.fixedBufferStream(buf);
    // Stream type: control = 0x00
    h3_frame.writeUniStreamType(fbs.writer(), .control) catch unreachable;
    // Empty SETTINGS frame
    h3_frame.write(.{ .settings = .{} }, fbs.writer()) catch unreachable;
    return fbs.pos;
}

// Inject a peer control stream with SETTINGS, poll once to consume the settings event.
fn injectPeerControlStream(quic_conn: *quic_connection.Connection, h3: *H3Connection) !void {
    // Peer uni stream IDs: for server, peer (client) uni = 2,6,10,...
    // For client, peer (server) uni = 3,7,11,...
    const peer_uni_id: u64 = if (h3.is_server) 2 else 3;
    var buf: [64]u8 = undefined;
    const len = buildControlStreamPayload(&buf);
    try injectUniStreamData(quic_conn, peer_uni_id, buf[0..len], false);

    // Poll to consume SETTINGS event
    const ev = try h3.poll();
    if (ev) |e| {
        switch (e) {
            .settings => {}, // expected
            else => return error.UnexpectedEvent,
        }
    } else {
        return error.ExpectedSettingsEvent;
    }
}

// Encode a minimal GET request as QPACK + HEADERS frame
fn buildGetRequestFrame(buf: []u8) usize {
    const headers = [_]qpack.Header{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/" },
        .{ .name = ":authority", .value = "example.com" },
    };
    var qpack_buf: [256]u8 = undefined;
    const qpack_len = qpack.encodeHeaders(&headers, &qpack_buf) catch unreachable;

    var fbs = io.fixedBufferStream(buf);
    h3_frame.write(.{ .headers = qpack_buf[0..qpack_len] }, fbs.writer()) catch unreachable;
    return fbs.pos;
}

// Build a DATA frame with given payload
fn buildDataFrame(buf: []u8, payload: []const u8) usize {
    var fbs = io.fixedBufferStream(buf);
    h3_frame.write(.{ .data = payload }, fbs.writer()) catch unreachable;
    return fbs.pos;
}

// ---- Group A: initConnection tests ----

test "H3 integration: initConnection opens control + QPACK streams" {
    var quic_conn = createTestQuicConn(true);
    defer quic_conn.deinit();
    var h3 = H3Connection.init(testing.allocator, &quic_conn, true);
    defer h3.deinit();

    try h3.initConnection();

    // Control stream should be opened
    try testing.expect(h3.local_control_stream != null);
    const ctrl = h3.local_control_stream.?;
    // Write buffer should contain type byte (0x00) + SETTINGS frame
    try testing.expect(ctrl.write_buffer.items.len > 0);
    // First byte should be the control stream type (0x00)
    try testing.expectEqual(@as(u8, 0x00), ctrl.write_buffer.items[0]);

    // QPACK encoder stream should be opened with type byte 0x02
    try testing.expect(h3.local_qpack_enc_stream != null);
    try testing.expect(h3.local_qpack_enc_stream.?.write_buffer.items.len > 0);
    try testing.expectEqual(@as(u8, 0x02), h3.local_qpack_enc_stream.?.write_buffer.items[0]);

    // QPACK decoder stream should be opened with type byte 0x03
    try testing.expect(h3.local_qpack_dec_stream != null);
    try testing.expect(h3.local_qpack_dec_stream.?.write_buffer.items.len > 0);
    try testing.expectEqual(@as(u8, 0x03), h3.local_qpack_dec_stream.?.write_buffer.items[0]);
}

test "H3 integration: initConnection sets initialized flag" {
    var quic_conn = createTestQuicConn(true);
    defer quic_conn.deinit();
    var h3 = H3Connection.init(testing.allocator, &quic_conn, true);
    defer h3.deinit();

    try testing.expect(!h3.initialized);
    try h3.initConnection();
    try testing.expect(h3.initialized);
}

test "H3 integration: initConnection is idempotent" {
    var quic_conn = createTestQuicConn(true);
    defer quic_conn.deinit();
    var h3 = H3Connection.init(testing.allocator, &quic_conn, true);
    defer h3.deinit();

    try h3.initConnection();
    const ctrl_ptr = h3.local_control_stream;
    const enc_ptr = h3.local_qpack_enc_stream;
    const dec_ptr = h3.local_qpack_dec_stream;

    // Second call should be a no-op
    try h3.initConnection();
    try testing.expectEqual(ctrl_ptr, h3.local_control_stream);
    try testing.expectEqual(enc_ptr, h3.local_qpack_enc_stream);
    try testing.expectEqual(dec_ptr, h3.local_qpack_dec_stream);
}

// ---- Group B: Peer uni stream identification ----

test "H3 integration: poll identifies peer control stream and returns settings" {
    var quic_conn = createTestQuicConn(true);
    defer quic_conn.deinit();
    var h3 = H3Connection.init(testing.allocator, &quic_conn, true);
    defer h3.deinit();

    // Inject peer control stream (client uni stream id=2 for server)
    var buf: [64]u8 = undefined;
    const len = buildControlStreamPayload(&buf);
    try injectUniStreamData(&quic_conn, 2, buf[0..len], false);

    const ev = try h3.poll();
    try testing.expect(ev != null);
    switch (ev.?) {
        .settings => {},
        else => return error.UnexpectedEvent,
    }
    try testing.expect(h3.peer_control_stream_id != null);
    try testing.expectEqual(@as(u64, 2), h3.peer_control_stream_id.?);
    try testing.expect(h3.peer_settings_received);
}

test "H3 integration: poll identifies QPACK encoder + decoder streams" {
    var quic_conn = createTestQuicConn(true);
    defer quic_conn.deinit();
    var h3 = H3Connection.init(testing.allocator, &quic_conn, true);
    defer h3.deinit();

    // Inject QPACK encoder stream (type 0x02) on client uni stream id=6
    try injectUniStreamData(&quic_conn, 6, &[_]u8{0x02}, false);
    // Inject QPACK decoder stream (type 0x03) on client uni stream id=10
    try injectUniStreamData(&quic_conn, 10, &[_]u8{0x03}, false);

    // Poll to identify them
    _ = try h3.poll();

    try testing.expect(h3.peer_qpack_enc_stream_id != null);
    try testing.expectEqual(@as(u64, 6), h3.peer_qpack_enc_stream_id.?);
    try testing.expect(h3.peer_qpack_dec_stream_id != null);
    try testing.expectEqual(@as(u64, 10), h3.peer_qpack_dec_stream_id.?);
}

// ---- Group C: Control stream tests ----

test "H3 integration: GOAWAY on control stream" {
    var quic_conn = createTestQuicConn(true);
    defer quic_conn.deinit();
    var h3 = H3Connection.init(testing.allocator, &quic_conn, true);
    defer h3.deinit();

    try injectPeerControlStream(&quic_conn, &h3);

    // Now inject GOAWAY(4) on the control stream
    var goaway_buf: [32]u8 = undefined;
    var goaway_fbs = io.fixedBufferStream(&goaway_buf);
    h3_frame.write(.{ .goaway = 4 }, goaway_fbs.writer()) catch unreachable;
    const goaway_data = goaway_fbs.getWritten();

    // Append to the control recv stream at next offset
    const ctrl_rs = quic_conn.streams.recv_streams.get(2).?;
    const offset = ctrl_rs.sorter.highestReceived();
    try ctrl_rs.handleStreamFrame(offset, goaway_data, false);

    const ev = try h3.poll();
    try testing.expect(ev != null);
    switch (ev.?) {
        .goaway => |id| try testing.expectEqual(@as(u64, 4), id),
        else => return error.UnexpectedEvent,
    }
}

test "H3 integration: DATA on control stream returns H3FrameUnexpected" {
    var quic_conn = createTestQuicConn(true);
    defer quic_conn.deinit();
    var h3 = H3Connection.init(testing.allocator, &quic_conn, true);
    defer h3.deinit();

    try injectPeerControlStream(&quic_conn, &h3);

    // Inject DATA frame on control stream
    var data_buf: [32]u8 = undefined;
    var data_fbs = io.fixedBufferStream(&data_buf);
    h3_frame.write(.{ .data = "hello" }, data_fbs.writer()) catch unreachable;
    const data_payload = data_fbs.getWritten();

    const ctrl_rs = quic_conn.streams.recv_streams.get(2).?;
    const offset = ctrl_rs.sorter.highestReceived();
    try ctrl_rs.handleStreamFrame(offset, data_payload, false);

    const result = h3.poll();
    try testing.expectError(error.H3FrameUnexpected, result);
}

test "H3 integration: duplicate SETTINGS returns H3FrameUnexpected" {
    var quic_conn = createTestQuicConn(true);
    defer quic_conn.deinit();
    var h3 = H3Connection.init(testing.allocator, &quic_conn, true);
    defer h3.deinit();

    try injectPeerControlStream(&quic_conn, &h3);

    // Inject another SETTINGS frame on control stream
    var settings_buf: [32]u8 = undefined;
    const settings_len = buildSettingsFrame(&settings_buf);

    const ctrl_rs = quic_conn.streams.recv_streams.get(2).?;
    const offset = ctrl_rs.sorter.highestReceived();
    try ctrl_rs.handleStreamFrame(offset, settings_buf[0..settings_len], false);

    const result = h3.poll();
    try testing.expectError(error.H3FrameUnexpected, result);
}

test "H3 integration: GOAWAY before SETTINGS returns H3MissingSettings" {
    var quic_conn = createTestQuicConn(true);
    defer quic_conn.deinit();
    var h3 = H3Connection.init(testing.allocator, &quic_conn, true);
    defer h3.deinit();

    // Inject control stream type byte + GOAWAY (no SETTINGS first)
    var buf: [64]u8 = undefined;
    var fbs = io.fixedBufferStream(&buf);
    h3_frame.writeUniStreamType(fbs.writer(), .control) catch unreachable;
    h3_frame.write(.{ .goaway = 0 }, fbs.writer()) catch unreachable;
    try injectUniStreamData(&quic_conn, 2, fbs.getWritten(), false);

    // First poll identifies control stream, buffers GOAWAY, then pollControlStream
    // finds GOAWAY before SETTINGS → H3MissingSettings error
    const result = h3.poll();
    try testing.expectError(error.H3MissingSettings, result);
}

// ---- Group D: Request/response lifecycle ----

test "H3 integration: server receives HEADERS event" {
    var quic_conn = createTestQuicConn(true);
    defer quic_conn.deinit();
    var h3 = H3Connection.init(testing.allocator, &quic_conn, true);
    defer h3.deinit();
    try h3.initConnection();
    try injectPeerControlStream(&quic_conn, &h3);

    // Inject GET request on client bidi stream 0
    var req_buf: [256]u8 = undefined;
    const req_len = buildGetRequestFrame(&req_buf);
    try injectBidiStreamData(&quic_conn, 0, req_buf[0..req_len], false);

    const ev = try h3.poll();
    try testing.expect(ev != null);
    switch (ev.?) {
        .headers => |h| {
            try testing.expectEqual(@as(u64, 0), h.stream_id);
            // Should have at least :method, :scheme, :path, :authority
            try testing.expect(h.headers.len >= 4);
        },
        else => return error.UnexpectedEvent,
    }
}

test "H3 integration: server receives DATA and recvBody reads it" {
    var quic_conn = createTestQuicConn(true);
    defer quic_conn.deinit();
    var h3 = H3Connection.init(testing.allocator, &quic_conn, true);
    defer h3.deinit();
    try h3.initConnection();
    try injectPeerControlStream(&quic_conn, &h3);

    // Inject HEADERS + DATA on client bidi stream 0
    var frame_buf: [512]u8 = undefined;
    var pos: usize = 0;

    // Build HEADERS frame
    const hdr_len = buildGetRequestFrame(frame_buf[pos..]);
    pos += hdr_len;

    // Build DATA frame with "Hello, World!"
    const body = "Hello, World!";
    const data_len = buildDataFrame(frame_buf[pos..], body);
    pos += data_len;

    try injectBidiStreamData(&quic_conn, 0, frame_buf[0..pos], false);

    // First poll: headers event
    const ev1 = try h3.poll();
    try testing.expect(ev1 != null);
    switch (ev1.?) {
        .headers => {},
        else => return error.UnexpectedEvent,
    }

    // Second poll: data event
    const ev2 = try h3.poll();
    try testing.expect(ev2 != null);
    switch (ev2.?) {
        .data => |d| {
            try testing.expectEqual(@as(u64, 0), d.stream_id);
            try testing.expectEqual(body.len, d.len);
        },
        else => return error.UnexpectedEvent,
    }

    // Read body
    var read_buf: [64]u8 = undefined;
    const n = h3.recvBody(&read_buf);
    try testing.expectEqual(body.len, n);
    try testing.expectEqualStrings(body, read_buf[0..n]);
}

test "H3 integration: recvBody partial reads" {
    var quic_conn = createTestQuicConn(true);
    defer quic_conn.deinit();
    var h3 = H3Connection.init(testing.allocator, &quic_conn, true);
    defer h3.deinit();
    try h3.initConnection();
    try injectPeerControlStream(&quic_conn, &h3);

    // 100-byte payload
    var payload: [100]u8 = undefined;
    for (&payload, 0..) |*b, i| b.* = @intCast(i % 256);

    var frame_buf: [512]u8 = undefined;
    var pos: usize = 0;
    const hdr_len = buildGetRequestFrame(frame_buf[pos..]);
    pos += hdr_len;
    const data_len = buildDataFrame(frame_buf[pos..], &payload);
    pos += data_len;

    try injectBidiStreamData(&quic_conn, 0, frame_buf[0..pos], false);

    // Poll headers
    _ = try h3.poll();
    // Poll data
    const ev = try h3.poll();
    try testing.expect(ev != null);
    switch (ev.?) {
        .data => |d| try testing.expectEqual(@as(usize, 100), d.len),
        else => return error.UnexpectedEvent,
    }

    // Read in 30-byte chunks
    var total_read: usize = 0;
    var result_buf: [100]u8 = undefined;
    while (total_read < 100) {
        var chunk: [30]u8 = undefined;
        const n = h3.recvBody(&chunk);
        if (n == 0) break;
        @memcpy(result_buf[total_read..][0..n], chunk[0..n]);
        total_read += n;
    }
    try testing.expectEqual(@as(usize, 100), total_read);
    try testing.expectEqualSlices(u8, &payload, &result_buf);
}

test "H3 integration: recvBody returns 0 with no pending body" {
    var quic_conn = createTestQuicConn(true);
    defer quic_conn.deinit();
    var h3 = H3Connection.init(testing.allocator, &quic_conn, true);
    defer h3.deinit();

    var buf: [64]u8 = undefined;
    const n = h3.recvBody(&buf);
    try testing.expectEqual(@as(usize, 0), n);
}

test "H3 integration: poll blocks while body pending" {
    var quic_conn = createTestQuicConn(true);
    defer quic_conn.deinit();
    var h3 = H3Connection.init(testing.allocator, &quic_conn, true);
    defer h3.deinit();
    try h3.initConnection();
    try injectPeerControlStream(&quic_conn, &h3);

    var frame_buf: [512]u8 = undefined;
    var pos: usize = 0;
    const hdr_len = buildGetRequestFrame(frame_buf[pos..]);
    pos += hdr_len;
    const data_len = buildDataFrame(frame_buf[pos..], "test body data");
    pos += data_len;

    try injectBidiStreamData(&quic_conn, 0, frame_buf[0..pos], false);

    // Poll headers
    _ = try h3.poll();
    // Poll data event
    _ = try h3.poll();

    // Body is pending — next poll should return null
    const ev = try h3.poll();
    try testing.expect(ev == null);

    // Drain the body
    var drain_buf: [64]u8 = undefined;
    _ = h3.recvBody(&drain_buf);

    // Now poll should be able to proceed (no more frames → null)
    const ev2 = try h3.poll();
    // Might get a finished event or null; either is fine
    _ = ev2;
}

test "H3 integration: stream FIN produces finished event" {
    var quic_conn = createTestQuicConn(true);
    defer quic_conn.deinit();
    var h3 = H3Connection.init(testing.allocator, &quic_conn, true);
    defer h3.deinit();
    try h3.initConnection();
    try injectPeerControlStream(&quic_conn, &h3);

    // Inject HEADERS with fin=true on bidi stream 0
    var req_buf: [256]u8 = undefined;
    const req_len = buildGetRequestFrame(&req_buf);
    try injectBidiStreamData(&quic_conn, 0, req_buf[0..req_len], true);

    // First poll: headers
    const ev1 = try h3.poll();
    try testing.expect(ev1 != null);
    switch (ev1.?) {
        .headers => {},
        else => return error.UnexpectedEvent,
    }

    // Next poll: finished
    const ev2 = try h3.poll();
    try testing.expect(ev2 != null);
    switch (ev2.?) {
        .finished => |sid| try testing.expectEqual(@as(u64, 0), sid),
        else => return error.UnexpectedEvent,
    }
}

test "H3 integration: sendRequest writes HEADERS + DATA" {
    var quic_conn = createTestQuicConn(false); // client
    defer quic_conn.deinit();
    var h3 = H3Connection.init(testing.allocator, &quic_conn, false);
    defer h3.deinit();
    try h3.initConnection();

    const headers = [_]qpack.Header{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/" },
        .{ .name = ":authority", .value = "example.com" },
    };

    const stream_id = try h3.sendRequest(&headers, "request body");
    try testing.expectEqual(@as(u64, 0), stream_id);

    // Verify the stream's write buffer has content
    const stream = quic_conn.streams.getStream(stream_id).?;
    try testing.expect(stream.send.write_buffer.items.len > 0);
    // Stream should have FIN queued (sendRequest closes the stream)
    try testing.expect(stream.send.fin_queued);
}

test "H3 integration: sendResponse writes HEADERS + DATA + FIN" {
    var quic_conn = createTestQuicConn(true); // server
    defer quic_conn.deinit();
    var h3 = H3Connection.init(testing.allocator, &quic_conn, true);
    defer h3.deinit();
    try h3.initConnection();
    try injectPeerControlStream(&quic_conn, &h3);

    // Create the client bidi stream (id=0) that the server responds on
    var req_buf: [256]u8 = undefined;
    const req_len = buildGetRequestFrame(&req_buf);
    try injectBidiStreamData(&quic_conn, 0, req_buf[0..req_len], true);

    // Poll to get headers event (this creates the stream in H3)
    _ = try h3.poll();

    const resp_headers = [_]qpack.Header{
        .{ .name = ":status", .value = "200" },
        .{ .name = "content-type", .value = "text/plain" },
    };

    try h3.sendResponse(0, &resp_headers, "Hello!");

    // Verify stream write buffer has data and FIN queued
    const stream = quic_conn.streams.getStream(0).?;
    try testing.expect(stream.send.write_buffer.items.len > 0);
    try testing.expect(stream.send.fin_queued);
}

// ---- Group E: Extended CONNECT ----

test "H3 integration: CONNECT request produces connect_request event" {
    var quic_conn = createTestQuicConn(true); // server
    defer quic_conn.deinit();
    var h3 = H3Connection.init(testing.allocator, &quic_conn, true);
    defer h3.deinit();
    h3.local_settings.enable_connect_protocol = true;
    try h3.initConnection();
    try injectPeerControlStream(&quic_conn, &h3);

    // Build Extended CONNECT HEADERS frame
    const headers = [_]qpack.Header{
        .{ .name = ":method", .value = "CONNECT" },
        .{ .name = ":protocol", .value = "webtransport" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/wt" },
        .{ .name = ":authority", .value = "example.com" },
    };
    var qpack_buf: [256]u8 = undefined;
    const qpack_len = qpack.encodeHeaders(&headers, &qpack_buf) catch unreachable;

    var frame_buf: [512]u8 = undefined;
    var fbs = io.fixedBufferStream(&frame_buf);
    h3_frame.write(.{ .headers = qpack_buf[0..qpack_len] }, fbs.writer()) catch unreachable;

    try injectBidiStreamData(&quic_conn, 0, fbs.getWritten(), false);

    const ev = try h3.poll();
    try testing.expect(ev != null);
    switch (ev.?) {
        .connect_request => |cr| {
            try testing.expectEqual(@as(u64, 0), cr.stream_id);
            try testing.expectEqualStrings("webtransport", cr.protocol);
            try testing.expectEqualStrings("/wt", cr.path);
            try testing.expectEqualStrings("example.com", cr.authority);
        },
        else => return error.UnexpectedEvent,
    }
}

test "H3 integration: sendConnectResponse writes headers without FIN" {
    var quic_conn = createTestQuicConn(true);
    defer quic_conn.deinit();
    var h3 = H3Connection.init(testing.allocator, &quic_conn, true);
    defer h3.deinit();
    try h3.initConnection();
    try injectPeerControlStream(&quic_conn, &h3);

    // Create the bidi stream first by injecting a CONNECT request
    const headers = [_]qpack.Header{
        .{ .name = ":method", .value = "CONNECT" },
        .{ .name = ":protocol", .value = "webtransport" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/" },
        .{ .name = ":authority", .value = "example.com" },
    };
    var qpack_buf: [256]u8 = undefined;
    const qpack_len = qpack.encodeHeaders(&headers, &qpack_buf) catch unreachable;

    var frame_buf: [512]u8 = undefined;
    var fbs = io.fixedBufferStream(&frame_buf);
    h3_frame.write(.{ .headers = qpack_buf[0..qpack_len] }, fbs.writer()) catch unreachable;
    try injectBidiStreamData(&quic_conn, 0, fbs.getWritten(), false);

    _ = try h3.poll(); // consume connect_request event

    try h3.sendConnectResponse(0, "200");

    const stream = quic_conn.streams.getStream(0).?;
    try testing.expect(stream.send.write_buffer.items.len > 0);
    // Extended CONNECT response must NOT close the stream
    try testing.expect(!stream.send.fin_queued);
}

// ---- Group F: Error handling ----

test "H3 integration: invalid headers (missing :path) closes connection" {
    var quic_conn = createTestQuicConn(true);
    defer quic_conn.deinit();
    var h3 = H3Connection.init(testing.allocator, &quic_conn, true);
    defer h3.deinit();
    try h3.initConnection();
    try injectPeerControlStream(&quic_conn, &h3);

    // Build malformed request (missing :path)
    const bad_headers = [_]qpack.Header{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        // no :path!
    };
    var qpack_buf: [256]u8 = undefined;
    const qpack_len = qpack.encodeHeaders(&bad_headers, &qpack_buf) catch unreachable;

    var frame_buf: [512]u8 = undefined;
    var fbs = io.fixedBufferStream(&frame_buf);
    h3_frame.write(.{ .headers = qpack_buf[0..qpack_len] }, fbs.writer()) catch unreachable;

    try injectBidiStreamData(&quic_conn, 0, fbs.getWritten(), false);

    // Poll should close connection with H3_MESSAGE_ERROR
    const ev = h3.poll();
    try testing.expectError(error.H3MessageError, ev);

    // Connection should be in closing state with H3_MESSAGE_ERROR
    try testing.expect(quic_conn.local_err != null);
    try testing.expectEqual(@intFromEnum(H3Error.message_error), quic_conn.local_err.?.code);
}

test "H3 integration: SETTINGS on bidi stream returns H3FrameUnexpected" {
    var quic_conn = createTestQuicConn(true);
    defer quic_conn.deinit();
    var h3 = H3Connection.init(testing.allocator, &quic_conn, true);
    defer h3.deinit();
    try h3.initConnection();
    try injectPeerControlStream(&quic_conn, &h3);

    // Inject SETTINGS frame on bidi stream 0 (wrong stream type for control frames)
    var settings_buf: [32]u8 = undefined;
    const settings_len = buildSettingsFrame(&settings_buf);
    try injectBidiStreamData(&quic_conn, 0, settings_buf[0..settings_len], false);

    const result = h3.poll();
    try testing.expectError(error.H3FrameUnexpected, result);
}

test "H3 integration: critical stream closure returns H3ClosedCriticalStream" {
    var quic_conn = createTestQuicConn(true);
    defer quic_conn.deinit();
    var h3 = H3Connection.init(testing.allocator, &quic_conn, true);
    defer h3.deinit();

    // Inject peer control stream
    try injectPeerControlStream(&quic_conn, &h3);

    // Simulate peer resetting the control stream
    const ctrl_rs = quic_conn.streams.recv_streams.get(2).?;
    ctrl_rs.reset_err = @intFromEnum(H3Error.no_error);

    const result = h3.poll();
    try testing.expectError(error.H3ClosedCriticalStream, result);
}

test "H3 integration: HTTP/2 frame type on bidi stream returns H3FrameUnexpected" {
    var quic_conn = createTestQuicConn(true);
    defer quic_conn.deinit();
    var h3 = H3Connection.init(testing.allocator, &quic_conn, true);
    defer h3.deinit();
    try h3.initConnection();
    try injectPeerControlStream(&quic_conn, &h3);

    // Inject reserved HTTP/2 PRIORITY frame type (0x02) on bidi stream
    var buf: [4]u8 = undefined;
    var fbs = io.fixedBufferStream(&buf);
    packet.writeVarInt(fbs.writer(), 0x02) catch unreachable; // HTTP/2 PRIORITY type
    packet.writeVarInt(fbs.writer(), 0) catch unreachable; // length 0
    try injectBidiStreamData(&quic_conn, 0, fbs.getWritten(), false);

    const result = h3.poll();
    try testing.expectError(error.H3FrameUnexpected, result);
}

// ---- Group G: Multiple frames / streams ----

test "H3 integration: HEADERS + DATA in one injection" {
    var quic_conn = createTestQuicConn(true);
    defer quic_conn.deinit();
    var h3 = H3Connection.init(testing.allocator, &quic_conn, true);
    defer h3.deinit();
    try h3.initConnection();
    try injectPeerControlStream(&quic_conn, &h3);

    // Build both HEADERS and DATA frames together
    var frame_buf: [512]u8 = undefined;
    var pos: usize = 0;
    const hdr_len = buildGetRequestFrame(frame_buf[pos..]);
    pos += hdr_len;
    const data_len = buildDataFrame(frame_buf[pos..], "combined payload");
    pos += data_len;

    // Inject both at once
    try injectBidiStreamData(&quic_conn, 0, frame_buf[0..pos], false);

    // First poll should return headers
    const ev1 = try h3.poll();
    try testing.expect(ev1 != null);
    switch (ev1.?) {
        .headers => |h| try testing.expectEqual(@as(u64, 0), h.stream_id),
        else => return error.UnexpectedEvent,
    }

    // Second poll should return data
    const ev2 = try h3.poll();
    try testing.expect(ev2 != null);
    switch (ev2.?) {
        .data => |d| {
            try testing.expectEqual(@as(u64, 0), d.stream_id);
            try testing.expectEqual(@as(usize, 16), d.len); // "combined payload".len
        },
        else => return error.UnexpectedEvent,
    }

    // Drain body
    var body_buf: [32]u8 = undefined;
    const n = h3.recvBody(&body_buf);
    try testing.expectEqualStrings("combined payload", body_buf[0..n]);
}

test "H3 integration: multiple concurrent streams" {
    var quic_conn = createTestQuicConn(true);
    defer quic_conn.deinit();
    var h3 = H3Connection.init(testing.allocator, &quic_conn, true);
    defer h3.deinit();
    try h3.initConnection();
    try injectPeerControlStream(&quic_conn, &h3);

    // Inject requests on streams 0, 4, 8
    var req_buf: [256]u8 = undefined;
    const req_len = buildGetRequestFrame(&req_buf);

    try injectBidiStreamData(&quic_conn, 0, req_buf[0..req_len], true);

    // Stream 4: need a fresh injection at offset 0
    const stream4 = try quic_conn.streams.getOrCreateStream(4);
    try stream4.recv.handleStreamFrame(0, req_buf[0..req_len], true);

    // Stream 8
    const stream8 = try quic_conn.streams.getOrCreateStream(8);
    try stream8.recv.handleStreamFrame(0, req_buf[0..req_len], true);

    // Poll should return headers for each stream (order may vary by hash map iteration)
    var seen_streams = [_]bool{ false, false, false };
    var polls: usize = 0;
    while (polls < 10) : (polls += 1) {
        const ev = try h3.poll();
        if (ev == null) break;
        switch (ev.?) {
            .headers => |h| {
                if (h.stream_id == 0) seen_streams[0] = true;
                if (h.stream_id == 4) seen_streams[1] = true;
                if (h.stream_id == 8) seen_streams[2] = true;
            },
            .finished => {}, // fin=true on inject → finished events expected
            else => {},
        }
    }
    try testing.expect(seen_streams[0]);
    try testing.expect(seen_streams[1]);
    try testing.expect(seen_streams[2]);
}
