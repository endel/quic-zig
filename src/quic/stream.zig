const std = @import("std");
const Allocator = std.mem.Allocator;
const testing = std.testing;

const flow_control = @import("flow_control.zig");
const Frame = @import("frame.zig").Frame;

/// Stream ID encoding per RFC 9000 Section 2.1:
///   Bit 0: initiator (0 = client, 1 = server)
///   Bit 1: directionality (0 = bidirectional, 1 = unidirectional)
pub const StreamType = enum(u2) {
    client_bidi = 0b00,
    server_bidi = 0b01,
    client_uni = 0b10,
    server_uni = 0b11,
};

/// Returns the type of a stream from its ID.
pub fn streamType(stream_id: u64) StreamType {
    return @enumFromInt(@as(u2, @truncate(stream_id)));
}

/// Returns true if the stream is bidirectional.
pub fn isBidi(stream_id: u64) bool {
    return (stream_id & 0x02) == 0;
}

/// Returns true if the stream was initiated by the client.
pub fn isClient(stream_id: u64) bool {
    return (stream_id & 0x01) == 0;
}

/// Returns true if the stream was locally initiated.
pub fn isLocal(stream_id: u64, is_server: bool) bool {
    const server_initiated = (stream_id & 0x01) != 0;
    return server_initiated == is_server;
}

/// Gap-based frame sorter for out-of-order reassembly of stream data.
/// Tracks received byte ranges and returns contiguous data starting from read_pos.
pub const FrameSorter = struct {
    allocator: Allocator,

    /// Buffered data chunks, keyed by offset.
    chunks: std.AutoArrayHashMap(u64, []const u8),

    /// Next offset to be read by the application.
    read_pos: u64 = 0,

    /// The final offset (set when FIN is received).
    fin_offset: ?u64 = null,

    pub fn init(allocator: Allocator) FrameSorter {
        return .{
            .allocator = allocator,
            .chunks = std.AutoArrayHashMap(u64, []const u8).init(allocator),
        };
    }

    pub fn deinit(self: *FrameSorter) void {
        // Free any owned data
        for (self.chunks.values()) |data| {
            self.allocator.free(data);
        }
        self.chunks.deinit();
    }

    /// Return the highest byte offset buffered (or read_pos if no chunks).
    pub fn highestReceived(self: *const FrameSorter) u64 {
        var highest = self.read_pos;
        for (self.chunks.keys(), self.chunks.values()) |off, val| {
            const end = off + val.len;
            if (end > highest) highest = end;
        }
        return highest;
    }

    /// Push received data at the given offset.
    pub fn push(self: *FrameSorter, offset: u64, data: []const u8, fin: bool) !void {
        if (fin) {
            const new_fin = offset + data.len;
            // RFC 9000 §4.5: final size cannot change once known
            if (self.fin_offset) |existing| {
                if (existing != new_fin) return error.FinalSizeError;
            }
            self.fin_offset = new_fin;
        }

        // RFC 9000 §4.5: data cannot exceed known final size
        if (self.fin_offset) |fs| {
            if (offset + data.len > fs) return error.FinalSizeError;
        }

        if (data.len == 0) return;

        // Skip data that's already been read
        if (offset + data.len <= self.read_pos) return;

        // Trim data that partially overlaps with already-read region
        var effective_offset = offset;
        var effective_data = data;
        if (offset < self.read_pos) {
            const skip = self.read_pos - offset;
            effective_data = data[skip..];
            effective_offset = self.read_pos;
        }

        // Check if there's already a chunk at this offset.
        // Don't overwrite a longer chunk with a shorter one (retransmission
        // with different fragmentation boundaries). Also free old data to
        // prevent memory leaks.
        if (self.chunks.get(effective_offset)) |existing| {
            if (existing.len >= effective_data.len) {
                // Existing chunk covers at least as much data — skip.
                return;
            }
            // New chunk is longer — free old, overwrite below.
            self.allocator.free(existing);
        }

        // Copy data to owned buffer
        const owned = try self.allocator.dupe(u8, effective_data);
        errdefer self.allocator.free(owned);

        try self.chunks.put(effective_offset, owned);
    }

    /// Pop the next contiguous chunk of data from the read position.
    /// Returns null if there's no data available at the current read position.
    pub fn pop(self: *FrameSorter) ?[]const u8 {
        if (self.chunks.get(self.read_pos)) |data| {
            _ = self.chunks.orderedRemove(self.read_pos);
            self.read_pos += data.len;
            return data;
        }
        return null;
    }

    /// Check if all data has been received (FIN reached and all data consumed).
    pub fn isComplete(self: *const FrameSorter) bool {
        if (self.fin_offset) |fin| {
            return self.read_pos >= fin;
        }
        return false;
    }
};

/// Fraction of receive window that triggers a MAX_STREAM_DATA update.
const STREAM_WINDOW_UPDATE_FRACTION: u64 = 4; // send update when 1/4 consumed

/// A QUIC receive stream.
pub const ReceiveStream = struct {
    stream_id: u64,
    sorter: FrameSorter,

    /// Final offset (set when FIN received).
    fin_received: bool = false,

    /// Error code from RESET_STREAM.
    reset_err: ?u64 = null,

    /// Error code for STOP_SENDING frame to send to peer.
    stop_sending_err: ?u64 = null,

    /// Whether the STOP_SENDING frame has been queued.
    stop_sending_sent: bool = false,

    /// Whether all data has been read.
    finished: bool = false,

    // Receive-side flow control (for generating MAX_STREAM_DATA)
    bytes_read: u64 = 0,
    receive_window: u64 = 0,
    receive_window_size: u64 = 0,

    pub fn init(allocator: Allocator, stream_id: u64) ReceiveStream {
        return .{
            .stream_id = stream_id,
            .sorter = FrameSorter.init(allocator),
        };
    }

    pub fn initWithWindow(allocator: Allocator, stream_id: u64, window: u64) ReceiveStream {
        return .{
            .stream_id = stream_id,
            .sorter = FrameSorter.init(allocator),
            .receive_window = window,
            .receive_window_size = window,
        };
    }

    pub fn deinit(self: *ReceiveStream) void {
        self.sorter.deinit();
    }

    /// Handle an incoming STREAM frame.
    pub fn handleStreamFrame(self: *ReceiveStream, offset: u64, data: []const u8, fin: bool) !void {
        if (self.reset_err != null) return; // Ignore data after reset
        if (fin) self.fin_received = true;
        try self.sorter.push(offset, data, fin);
    }

    /// Handle a RESET_STREAM frame.
    /// Returns FinalSizeError if final_size conflicts with known data.
    pub fn handleResetStream(self: *ReceiveStream, error_code: u64, final_size: u64) !void {
        // RFC 9000 §4.5: final size cannot change once known
        if (self.sorter.fin_offset) |existing| {
            if (existing != final_size) return error.FinalSizeError;
        }
        // RFC 9000 §4.5: final size cannot be less than data already received
        if (final_size < self.sorter.highestReceived()) return error.FinalSizeError;

        self.reset_err = error_code;
        self.sorter.fin_offset = final_size;
    }

    /// Read contiguous data from the stream.
    /// Returns the data slice or null if no data is available.
    pub fn read(self: *ReceiveStream) ?[]const u8 {
        if (self.reset_err != null) return null;

        const data = self.sorter.pop();
        if (data) |d| {
            self.bytes_read += d.len;
        } else if (self.sorter.isComplete()) {
            self.finished = true;
        }
        return data;
    }

    /// Check if a MAX_STREAM_DATA update should be sent.
    /// Returns the new window offset, or null if no update needed.
    pub fn getWindowUpdate(self: *ReceiveStream) ?u64 {
        if (self.receive_window == 0) return null; // no flow control configured
        if (self.fin_received) return null; // no point updating after FIN

        // Send update when consumed portion exceeds threshold
        const threshold = self.receive_window_size / STREAM_WINDOW_UPDATE_FRACTION;
        if (self.bytes_read + threshold > self.receive_window) {
            const new_window = self.bytes_read + self.receive_window_size;
            if (new_window > self.receive_window) {
                self.receive_window = new_window;
                return new_window;
            }
        }
        return null;
    }

    /// Request that the peer stop sending on this stream (sends STOP_SENDING).
    pub fn stopSending(self: *ReceiveStream, error_code: u64) void {
        self.stop_sending_err = error_code;
    }
};

/// Maximum number of retransmit ranges per SendStream.
const MAX_RETRANSMIT_RANGES: usize = 16;

/// A range of stream data that needs to be retransmitted.
const RetransmitRange = struct {
    offset: u64,
    length: u64,
    fin: bool,
};

/// A QUIC send stream.
pub const SendStream = struct {
    stream_id: u64,
    allocator: Allocator,

    /// Data buffered for sending.
    write_buffer: std.ArrayList(u8),

    /// Current write offset (total bytes written).
    write_offset: u64 = 0,

    /// Next offset to be sent.
    send_offset: u64 = 0,

    /// Maximum data the peer allows us to send on this stream.
    send_window: u64 = std.math.maxInt(u64),

    // Track the limit at which we last sent STREAM_DATA_BLOCKED (avoid duplicates)
    blocked_at: ?u64 = null,

    /// RFC 9218 priority: urgency (0=highest, 7=lowest, default 3).
    urgency: u3 = 3,

    /// RFC 9218 priority: incremental streams are interleaved round-robin.
    incremental: bool = false,

    /// Whether FIN has been queued.
    fin_queued: bool = false,

    /// Whether FIN has been sent.
    fin_sent: bool = false,

    /// Whether the stream has been reset.
    reset_err: ?u64 = null,

    /// Whether a RESET_STREAM frame has been queued for sending.
    reset_stream_sent: bool = false,

    /// Retransmission queue: ranges of data that were lost and need resending.
    retransmit_ranges: [MAX_RETRANSMIT_RANGES]RetransmitRange = undefined,
    retransmit_count: u8 = 0,

    /// Whether a FIN that was previously sent was lost and needs retransmission.
    fin_lost: bool = false,

    pub fn init(allocator: Allocator, stream_id: u64) SendStream {
        return .{
            .stream_id = stream_id,
            .allocator = allocator,
            .write_buffer = .{ .items = &.{}, .capacity = 0 },
        };
    }

    pub fn deinit(self: *SendStream) void {
        self.write_buffer.deinit(self.allocator);
    }

    /// Write data to the stream. Buffers it for later sending.
    pub fn writeData(self: *SendStream, data: []const u8) !void {
        try self.write_buffer.appendSlice(self.allocator, data);
        self.write_offset += data.len;
    }

    /// Close the stream (queue FIN).
    pub fn close(self: *SendStream) void {
        self.fin_queued = true;
    }

    /// Cancel the stream with an error code (sends RESET_STREAM).
    pub fn reset(self: *SendStream, error_code: u64) void {
        self.reset_err = error_code;
    }

    /// Update the send window from a MAX_STREAM_DATA frame.
    pub fn updateSendWindow(self: *SendStream, new_max: u64) void {
        if (new_max > self.send_window) {
            self.send_window = new_max;
            self.blocked_at = null;
        }
    }

    // Check if we should send STREAM_DATA_BLOCKED. Returns the limit if yes.
    // Only triggers once per limit to avoid duplicates.
    pub fn shouldSendBlocked(self: *SendStream) ?u64 {
        if (self.send_offset >= self.send_window and self.hasData()) {
            if (self.blocked_at == null or self.blocked_at.? != self.send_window) {
                self.blocked_at = self.send_window;
                return self.send_window;
            }
        }
        return null;
    }

    /// Queue a range of stream data for retransmission (called when a packet is declared lost).
    pub fn queueRetransmit(self: *SendStream, offset: u64, length: u64, fin: bool) void {
        if (self.reset_err != null) return;

        // If FIN was in the lost packet, mark it for retransmission
        if (fin) {
            self.fin_lost = true;
            self.fin_sent = false; // Allow FIN to be re-sent
        }

        // Don't queue zero-length ranges (unless it was a FIN-only frame, handled above)
        if (length == 0) return;

        // Check if this range overlaps with or is adjacent to an existing retransmit range
        // and merge if possible
        for (self.retransmit_ranges[0..self.retransmit_count]) |*existing| {
            const e_end = existing.offset + existing.length;
            const n_end = offset + length;

            // Check overlap or adjacency
            if (offset <= e_end and existing.offset <= n_end) {
                const new_start = @min(existing.offset, offset);
                const new_end = @max(e_end, n_end);
                existing.offset = new_start;
                existing.length = new_end - new_start;
                if (fin) existing.fin = true;
                return;
            }
        }

        // Add as a new range if there's space
        if (self.retransmit_count < MAX_RETRANSMIT_RANGES) {
            self.retransmit_ranges[self.retransmit_count] = .{
                .offset = offset,
                .length = length,
                .fin = fin,
            };
            self.retransmit_count += 1;
        } else {
            // Queue overflow: fall back to resending from the earliest lost offset.
            // Find minimum offset across all queued ranges and the new range,
            // then reset send_offset so the packer resends everything from there.
            // The receiver's FrameSorter deduplicates any already-received data.
            var min_offset = offset;
            var has_fin = fin;
            for (self.retransmit_ranges[0..self.retransmit_count]) |r| {
                min_offset = @min(min_offset, r.offset);
                if (r.fin) has_fin = true;
            }
            self.send_offset = @min(self.send_offset, min_offset);
            self.retransmit_count = 0;
            if (has_fin) {
                self.fin_lost = true;
                self.fin_sent = false;
            }
        }
    }

    /// Check if there's data available to send (including retransmissions).
    pub fn hasData(self: *const SendStream) bool {
        return self.retransmit_count > 0 or
            self.fin_lost or
            self.send_offset < self.write_offset or
            (self.fin_queued and !self.fin_sent);
    }

    /// Pop a STREAM frame with at most max_len bytes of payload.
    /// Prioritizes retransmissions over new data.
    /// Returns null if there's nothing to send.
    pub fn popStreamFrame(self: *SendStream, max_len: u64) ?Frame {
        if (self.reset_err != null) return null;

        // Priority 1: Retransmissions
        if (self.retransmit_count > 0) {
            return self.popRetransmitFrame(max_len);
        }

        // Priority 2: FIN-only retransmission (FIN was lost but no data range to retransmit)
        if (self.fin_lost and self.retransmit_count == 0) {
            self.fin_lost = false;
            self.fin_sent = true;
            return Frame{
                .stream = .{
                    .stream_id = self.stream_id,
                    .offset = self.write_offset,
                    .length = 0,
                    .fin = true,
                    .data = @constCast(&[_]u8{}),
                },
            };
        }

        // Priority 3: New data
        return self.popNewDataFrame(max_len);
    }

    /// Pop a retransmission frame from the retransmit queue.
    fn popRetransmitFrame(self: *SendStream, max_len: u64) ?Frame {
        if (self.retransmit_count == 0) return null;

        const range = &self.retransmit_ranges[0];
        const buffered = self.write_buffer.items;

        // Clamp to available buffer and max_len
        const available = if (range.offset < buffered.len)
            @min(range.length, buffered.len - range.offset)
        else
            0;
        const data_len = @min(available, max_len);

        if (data_len == 0 and !range.fin) {
            // Nothing useful to retransmit - remove this range
            self.removeRetransmitRange(0);
            return null;
        }

        // Save the original offset before modifying the range
        const frame_offset = range.offset;
        const data = if (data_len > 0) buffered[frame_offset..][0..data_len] else &[_]u8{};
        // FIN should be set if this range had FIN and we're sending all of its data
        const fin = range.fin and (frame_offset + data_len == self.write_offset);

        // Update or remove the range
        if (data_len >= range.length) {
            // Fully consumed this range
            self.removeRetransmitRange(0);
        } else {
            // Partially consumed - advance the range
            range.offset += data_len;
            range.length -= data_len;
        }

        if (fin) {
            self.fin_sent = true;
            self.fin_lost = false;
        }

        return Frame{
            .stream = .{
                .stream_id = self.stream_id,
                .offset = frame_offset,
                .length = data_len,
                .fin = fin,
                .data = @constCast(data),
            },
        };
    }

    /// Pop a new data frame (original send path).
    fn popNewDataFrame(self: *SendStream, max_len: u64) ?Frame {
        const buffered = self.write_buffer.items;
        const unsent_start = self.send_offset;
        const unsent_len = self.write_offset - self.send_offset;

        if (unsent_len == 0 and !(self.fin_queued and !self.fin_sent)) {
            return null;
        }

        // Constrain by both max_len and send_window
        const window_remaining = if (self.send_window > self.send_offset)
            self.send_window - self.send_offset
        else
            0;
        const data_len = @min(unsent_len, @min(max_len, window_remaining));
        const fin = self.fin_queued and !self.fin_sent and (unsent_start + data_len == self.write_offset);

        // Don't produce useless zero-length non-FIN frames — they lack the LEN flag
        // and would cause the receiver to interpret following frame bytes as stream data
        if (data_len == 0 and !fin) return null;

        const data = if (data_len > 0) buffered[unsent_start..][0..data_len] else &[_]u8{};

        self.send_offset += data_len;
        if (fin) self.fin_sent = true;

        return Frame{
            .stream = .{
                .stream_id = self.stream_id,
                .offset = unsent_start,
                .length = data_len,
                .fin = fin,
                .data = @constCast(data),
            },
        };
    }

    /// Remove a retransmit range by index, shifting remaining ranges down.
    fn removeRetransmitRange(self: *SendStream, idx: usize) void {
        if (idx >= self.retransmit_count) return;
        const count = self.retransmit_count;
        // Shift remaining ranges down
        var i = idx;
        while (i + 1 < count) : (i += 1) {
            self.retransmit_ranges[i] = self.retransmit_ranges[i + 1];
        }
        self.retransmit_count -= 1;
    }
};

/// A bidirectional QUIC stream combining send and receive.
pub const Stream = struct {
    stream_id: u64,
    send: SendStream,
    recv: ReceiveStream,
    /// Set when closeStream has been called for consumed stream counting.
    /// Prevents double-counting while keeping the stream in the map for retransmission.
    closed_for_gc: bool = false,

    pub fn init(allocator: Allocator, stream_id: u64) Stream {
        return .{
            .stream_id = stream_id,
            .send = SendStream.init(allocator, stream_id),
            .recv = ReceiveStream.init(allocator, stream_id),
        };
    }

    pub fn deinit(self: *Stream) void {
        self.send.deinit();
        self.recv.deinit();
    }
};

/// Manages all streams for a connection.
pub const StreamsMap = struct {
    allocator: Allocator,
    is_server: bool,

    /// All active streams indexed by stream ID.
    streams: std.AutoHashMap(u64, *Stream),

    /// Send-only streams (unidirectional, locally initiated).
    send_streams: std.AutoHashMap(u64, *SendStream),

    /// Receive-only streams (unidirectional, peer initiated).
    recv_streams: std.AutoHashMap(u64, *ReceiveStream),

    /// Next outgoing stream IDs.
    next_bidi_stream_id: u64,
    next_uni_stream_id: u64,

    /// Maximum stream counts from peer's transport parameters.
    max_bidi_streams: u64 = 0,
    max_uni_streams: u64 = 0,

    /// Peer's initial max stream data limits (from transport parameters).
    /// These set the send_window on newly created streams.
    /// "bidi_local" = peer's limit for streams THEY initiated (we send on peer-initiated bidi)
    /// "bidi_remote" = peer's limit for streams WE initiated (we send on our-initiated bidi)
    peer_initial_max_stream_data_bidi_local: u64 = std.math.maxInt(u64),
    peer_initial_max_stream_data_bidi_remote: u64 = std.math.maxInt(u64),
    peer_initial_max_stream_data_uni: u64 = std.math.maxInt(u64),

    /// Local receive window limits (our advertised limits, for MAX_STREAM_DATA generation).
    local_max_stream_data_bidi_local: u64 = 0,
    local_max_stream_data_bidi_remote: u64 = 0,
    local_max_stream_data_uni: u64 = 0,

    /// Maximum stream IDs from peer.
    max_incoming_bidi_streams: u64 = 0,
    max_incoming_uni_streams: u64 = 0,

    /// Number of open streams.
    open_bidi_streams: u64 = 0,
    open_uni_streams: u64 = 0,

    /// Number of consumed (fully closed) incoming streams, for MAX_STREAMS sliding window.
    consumed_bidi_streams: u64 = 0,
    consumed_uni_streams: u64 = 0,

    /// Last MAX_STREAMS values sent, to avoid redundant frames.
    last_sent_max_bidi: u64 = 0,
    last_sent_max_uni: u64 = 0,

    /// Initial stream limits (fixed threshold for MAX_STREAMS sliding window).
    initial_max_incoming_bidi: u64 = 0,
    initial_max_incoming_uni: u64 = 0,

    /// Round-robin index for fair scheduling of incremental streams (RFC 9218).
    rr_index: u64 = 0,

    pub fn init(allocator: Allocator, is_server: bool) StreamsMap {
        // Stream IDs: client bidi = 0, 4, 8, ...; server bidi = 1, 5, 9, ...
        // Client uni = 2, 6, 10, ...; server uni = 3, 7, 11, ...
        const bidi_base: u64 = if (is_server) 1 else 0;
        const uni_base: u64 = if (is_server) 3 else 2;

        return .{
            .allocator = allocator,
            .is_server = is_server,
            .streams = std.AutoHashMap(u64, *Stream).init(allocator),
            .send_streams = std.AutoHashMap(u64, *SendStream).init(allocator),
            .recv_streams = std.AutoHashMap(u64, *ReceiveStream).init(allocator),
            .next_bidi_stream_id = bidi_base,
            .next_uni_stream_id = uni_base,
        };
    }

    pub fn deinit(self: *StreamsMap) void {
        // Free all stream objects
        var stream_it = self.streams.valueIterator();
        while (stream_it.next()) |s| {
            s.*.deinit();
            self.allocator.destroy(s.*);
        }
        self.streams.deinit();

        var send_it = self.send_streams.valueIterator();
        while (send_it.next()) |s| {
            s.*.deinit();
            self.allocator.destroy(s.*);
        }
        self.send_streams.deinit();

        var recv_it = self.recv_streams.valueIterator();
        while (recv_it.next()) |s| {
            s.*.deinit();
            self.allocator.destroy(s.*);
        }
        self.recv_streams.deinit();
    }

    /// Update the maximum stream limits from peer's transport parameters.
    pub fn setMaxStreams(self: *StreamsMap, max_bidi: u64, max_uni: u64) void {
        self.max_bidi_streams = max_bidi;
        self.max_uni_streams = max_uni;
    }

    /// Set the peer's initial max stream data limits (from their transport parameters).
    pub fn setPeerInitialMaxStreamData(self: *StreamsMap, bidi_local: u64, bidi_remote: u64, uni: u64) void {
        self.peer_initial_max_stream_data_bidi_local = bidi_local;
        self.peer_initial_max_stream_data_bidi_remote = bidi_remote;
        self.peer_initial_max_stream_data_uni = uni;
    }

    /// Set the maximum incoming stream limits (our advertised limits).
    pub fn setMaxIncomingStreams(self: *StreamsMap, max_bidi: u64, max_uni: u64) void {
        self.max_incoming_bidi_streams = max_bidi;
        self.max_incoming_uni_streams = max_uni;
        // Record initial limits for fixed-threshold MAX_STREAMS sliding window.
        // Also set last_sent since the initial limit is conveyed in transport params.
        if (self.initial_max_incoming_bidi == 0) {
            self.initial_max_incoming_bidi = max_bidi;
            self.last_sent_max_bidi = max_bidi;
        }
        if (self.initial_max_incoming_uni == 0) {
            self.initial_max_incoming_uni = max_uni;
            self.last_sent_max_uni = max_uni;
        }
    }

    /// Open a new bidirectional stream. Returns error if stream limit reached.
    pub fn openBidiStream(self: *StreamsMap) !*Stream {
        // MAX_STREAMS is cumulative: check total streams opened, not concurrent count
        if (self.next_bidi_stream_id / 4 >= self.max_bidi_streams) {
            return error.StreamLimitError;
        }

        const id = self.next_bidi_stream_id;
        self.next_bidi_stream_id += 4;
        self.open_bidi_streams += 1;

        const s = try self.allocator.create(Stream);
        s.* = Stream.init(self.allocator, id);
        // We initiated this stream → peer's "bidi_remote" limit applies to our sends
        s.send.send_window = self.peer_initial_max_stream_data_bidi_remote;
        // Our local receive window for streams we initiated
        s.recv.receive_window = self.local_max_stream_data_bidi_local;
        s.recv.receive_window_size = self.local_max_stream_data_bidi_local;
        try self.streams.put(id, s);
        return s;
    }

    /// Open a new unidirectional send stream. Returns error if stream limit reached.
    pub fn openUniStream(self: *StreamsMap) !*SendStream {
        // MAX_STREAMS is cumulative: check total streams opened, not concurrent count
        if (self.next_uni_stream_id / 4 >= self.max_uni_streams) {
            return error.StreamLimitError;
        }

        const id = self.next_uni_stream_id;
        self.next_uni_stream_id += 4;
        self.open_uni_streams += 1;

        const s = try self.allocator.create(SendStream);
        s.* = SendStream.init(self.allocator, id);
        s.send_window = self.peer_initial_max_stream_data_uni;
        try self.send_streams.put(id, s);
        return s;
    }

    /// Get or create a stream from an incoming STREAM frame.
    pub fn getOrCreateStream(self: *StreamsMap, stream_id: u64) !*Stream {
        if (self.streams.get(stream_id)) |existing| {
            return existing;
        }

        // Verify this is a valid peer-initiated stream
        if (isLocal(stream_id, self.is_server)) {
            return error.StreamStateError; // We don't have this stream
        }

        if (!isBidi(stream_id)) {
            return error.StreamStateError; // Uni streams should use recv_streams
        }

        const s = try self.allocator.create(Stream);
        s.* = Stream.init(self.allocator, stream_id);
        // Peer initiated this stream → peer's "bidi_local" limit applies to our sends
        s.send.send_window = self.peer_initial_max_stream_data_bidi_local;
        // Our local receive window for peer-initiated streams
        s.recv.receive_window = self.local_max_stream_data_bidi_remote;
        s.recv.receive_window_size = self.local_max_stream_data_bidi_remote;
        try self.streams.put(stream_id, s);
        self.open_bidi_streams += 1;
        return s;
    }

    /// Get or create a receive stream for an incoming unidirectional stream.
    pub fn getOrCreateRecvStream(self: *StreamsMap, stream_id: u64) !*ReceiveStream {
        if (self.recv_streams.get(stream_id)) |existing| {
            return existing;
        }

        const s = try self.allocator.create(ReceiveStream);
        s.* = ReceiveStream.initWithWindow(self.allocator, stream_id, self.local_max_stream_data_uni);
        try self.recv_streams.put(stream_id, s);
        self.open_uni_streams += 1;
        return s;
    }

    /// Get a stream by ID.
    pub fn getStream(self: *StreamsMap, stream_id: u64) ?*Stream {
        return self.streams.get(stream_id);
    }

    /// Maximum number of streams returned by getScheduledStreams().
    pub const MAX_SCHEDULABLE: usize = 48;

    /// Select bidi streams to send data on according to RFC 9218 priority.
    /// Pass 1: find the minimum urgency level with data ready.
    /// Pass 2: collect streams at that urgency.
    ///   - Non-incremental: only the first one (sequential delivery).
    ///   - Incremental: all of them (round-robin interleaved).
    /// Returns the count of streams written to `out`.
    pub fn getScheduledStreams(self: *StreamsMap, out: *[MAX_SCHEDULABLE]*Stream) usize {
        // Pass 1: find minimum urgency among streams with data
        // Include closed_for_gc streams that have retransmit data — PTO probes
        // must carry the actual stream data, not just PINGs.
        var min_urgency: u3 = 7;
        var has_any = false;
        var it1 = self.streams.valueIterator();
        while (it1.next()) |sp| {
            const s = sp.*;
            if (s.send.hasData() and (!s.closed_for_gc or s.send.retransmit_count > 0)) {
                if (s.send.urgency < min_urgency) min_urgency = s.send.urgency;
                has_any = true;
            }
        }
        if (!has_any) return 0;

        // Pass 2: collect streams at min_urgency
        var count: usize = 0;
        var found_non_incremental = false;
        var it2 = self.streams.valueIterator();
        while (it2.next()) |sp| {
            const s = sp.*;
            if (s.send.urgency != min_urgency or !s.send.hasData() or (s.closed_for_gc and s.send.retransmit_count == 0)) continue;
            if (!s.send.incremental) {
                if (!found_non_incremental) {
                    if (count >= MAX_SCHEDULABLE) break;
                    out[count] = s;
                    count += 1;
                    found_non_incremental = true;
                }
                // Skip additional non-incremental streams (sequential rule)
            } else {
                if (count >= MAX_SCHEDULABLE) break;
                out[count] = s;
                count += 1;
            }
        }

        // Rotate incremental streams for fairness
        if (count > 1) {
            const rotation = self.rr_index % count;
            if (rotation > 0) {
                // Simple in-place rotation using a temp buffer
                var tmp: [MAX_SCHEDULABLE]*Stream = undefined;
                for (0..count) |i| {
                    tmp[i] = out[(i + rotation) % count];
                }
                for (0..count) |i| {
                    out[i] = tmp[i];
                }
            }
        }
        self.rr_index +%= 1;
        return count;
    }

    /// Mark a stream as fully closed and update consumed counters.
    /// Only counts peer-initiated streams (those count against our MAX_STREAMS limit).
    /// Scan bidi streams for ones that are fully closed (both FIN sent and FIN received)
    /// and call closeStream for each. This ensures consumed_*_streams advances even when
    /// the close was never triggered by a received STREAM/RESET_STREAM frame.
    pub fn collectClosedStreams(self: *StreamsMap) void {
        // Mark fully-closed streams for consumed counting. Streams stay in the map
        // so that loss detection can still find them for retransmission.
        var it = self.streams.iterator();
        while (it.next()) |kv| {
            const s = kv.value_ptr.*;
            if (!s.closed_for_gc and (s.recv.finished or s.recv.fin_received) and s.send.fin_sent)
            {
                s.closed_for_gc = true;
                self.closeStream(s.stream_id);
            }
        }
    }

    pub fn closeStream(self: *StreamsMap, stream_id: u64) void {
        const peer_initiated = !isLocal(stream_id, self.is_server);
        if (isBidi(stream_id)) {
            if (self.open_bidi_streams > 0) self.open_bidi_streams -= 1;
            if (peer_initiated) self.consumed_bidi_streams += 1;
        } else {
            if (self.open_uni_streams > 0) self.open_uni_streams -= 1;
            if (peer_initiated) self.consumed_uni_streams += 1;
        }
    }

    /// Check if MAX_STREAMS updates should be sent (sliding window pattern).
    /// Returns new limits when consumed streams reach half the current max.
    pub const MaxStreamsUpdate = struct {
        bidi: ?u64 = null,
        uni: ?u64 = null,
    };

    pub fn getMaxStreamsUpdates(self: *StreamsMap) MaxStreamsUpdate {
        var result = MaxStreamsUpdate{};

        // Use fixed threshold based on initial limit (not growing max_incoming).
        // This prevents the threshold from outgrowing batch sizes and stalling.
        if (self.max_incoming_bidi_streams > 0) {
            const threshold = @max(self.initial_max_incoming_bidi / 4, 1);
            if (self.consumed_bidi_streams >= threshold) {
                const new_max = self.last_sent_max_bidi + self.consumed_bidi_streams;
                if (new_max > self.last_sent_max_bidi) {
                    result.bidi = new_max;
                    self.last_sent_max_bidi = new_max;
                    self.max_incoming_bidi_streams = new_max;
                    self.consumed_bidi_streams = 0;
                }
            }
        }

        // Uni: same fixed-threshold sliding window
        if (self.max_incoming_uni_streams > 0) {
            const threshold = @max(self.initial_max_incoming_uni / 4, 1);
            if (self.consumed_uni_streams >= threshold) {
                const new_max = self.last_sent_max_uni + self.consumed_uni_streams;
                if (new_max > self.last_sent_max_uni) {
                    result.uni = new_max;
                    self.last_sent_max_uni = new_max;
                    self.max_incoming_uni_streams = new_max;
                    self.consumed_uni_streams = 0;
                }
            }
        }

        return result;
    }
};

// Tests

test "FrameSorter: in-order data" {
    var sorter = FrameSorter.init(testing.allocator);
    defer sorter.deinit();

    try sorter.push(0, "hello", false);
    try sorter.push(5, " world", true);

    const chunk1 = sorter.pop();
    try testing.expect(chunk1 != null);
    try testing.expectEqualStrings("hello", chunk1.?);
    testing.allocator.free(chunk1.?);

    const chunk2 = sorter.pop();
    try testing.expect(chunk2 != null);
    try testing.expectEqualStrings(" world", chunk2.?);
    testing.allocator.free(chunk2.?);

    try testing.expect(sorter.isComplete());
}

test "FrameSorter: out-of-order data" {
    var sorter = FrameSorter.init(testing.allocator);
    defer sorter.deinit();

    // Receive second chunk first
    try sorter.push(5, " world", false);

    // Nothing available yet (gap at offset 0)
    try testing.expect(sorter.pop() == null);

    // Receive first chunk
    try sorter.push(0, "hello", false);

    const chunk1 = sorter.pop();
    try testing.expect(chunk1 != null);
    try testing.expectEqualStrings("hello", chunk1.?);
    testing.allocator.free(chunk1.?);

    const chunk2 = sorter.pop();
    try testing.expect(chunk2 != null);
    try testing.expectEqualStrings(" world", chunk2.?);
    testing.allocator.free(chunk2.?);
}

// RFC 9000 §4.5: final size validation
test "FrameSorter: conflicting final size from FIN" {
    var sorter = FrameSorter.init(testing.allocator);
    defer sorter.deinit();

    try sorter.push(0, "hello", true); // fin_offset = 5
    try testing.expectEqual(@as(?u64, 5), sorter.fin_offset);

    // Different FIN offset must fail
    const err = sorter.push(0, "hi", true); // would set fin_offset = 2
    try testing.expectError(error.FinalSizeError, err);
}

test "FrameSorter: data beyond final size" {
    var sorter = FrameSorter.init(testing.allocator);
    defer sorter.deinit();

    try sorter.push(0, "hello", true); // fin_offset = 5
    // Data extending past final size must fail
    const err = sorter.push(3, "xyzw", false); // offset 3 + len 4 = 7 > 5
    try testing.expectError(error.FinalSizeError, err);
}

test "ReceiveStream: RESET_STREAM final size mismatch" {
    var rs = ReceiveStream.init(testing.allocator, 1024);
    defer rs.deinit();

    try rs.handleStreamFrame(0, "data", false); // received 4 bytes
    // RESET_STREAM with final_size < already received must fail
    const err = rs.handleResetStream(0x01, 2);
    try testing.expectError(error.FinalSizeError, err);
}

test "ReceiveStream: RESET_STREAM consistent with FIN" {
    var rs = ReceiveStream.init(testing.allocator, 1024);
    defer rs.deinit();

    try rs.handleStreamFrame(0, "hello", true); // fin at offset 5
    // RESET_STREAM with same final_size should succeed
    try rs.handleResetStream(0x01, 5);
    // RESET_STREAM with different final_size must fail
    const err = rs.handleResetStream(0x02, 10);
    try testing.expectError(error.FinalSizeError, err);
}

test "SendStream: basic write and pop" {
    var ss = SendStream.init(testing.allocator, 0);
    defer ss.deinit();

    try ss.writeData("hello");
    try testing.expect(ss.hasData());

    const frame = ss.popStreamFrame(100);
    try testing.expect(frame != null);
    switch (frame.?) {
        .stream => |s| {
            try testing.expectEqual(@as(u64, 0), s.stream_id);
            try testing.expectEqual(@as(u64, 0), s.offset);
            try testing.expectEqualSlices(u8, "hello", s.data);
            try testing.expect(!s.fin);
        },
        else => unreachable,
    }
}

test "SendStream: write with FIN" {
    var ss = SendStream.init(testing.allocator, 4);
    defer ss.deinit();

    try ss.writeData("data");
    ss.close();

    const frame = ss.popStreamFrame(100);
    try testing.expect(frame != null);
    switch (frame.?) {
        .stream => |s| {
            try testing.expect(s.fin);
        },
        else => unreachable,
    }
}

test "StreamsMap: open and manage streams" {
    var sm = StreamsMap.init(testing.allocator, false); // client
    defer sm.deinit();

    sm.setMaxStreams(10, 10);

    // Open a bidi stream
    const s = try sm.openBidiStream();
    try testing.expectEqual(@as(u64, 0), s.stream_id); // Client bidi: 0, 4, 8, ...

    // Open another
    const s2 = try sm.openBidiStream();
    try testing.expectEqual(@as(u64, 4), s2.stream_id);

    // Open uni stream
    const us = try sm.openUniStream();
    try testing.expectEqual(@as(u64, 2), us.stream_id); // Client uni: 2, 6, 10, ...
}

test "StreamsMap: server stream IDs" {
    var sm = StreamsMap.init(testing.allocator, true); // server
    defer sm.deinit();

    sm.setMaxStreams(10, 10);

    const s = try sm.openBidiStream();
    try testing.expectEqual(@as(u64, 1), s.stream_id); // Server bidi: 1, 5, 9, ...

    const us = try sm.openUniStream();
    try testing.expectEqual(@as(u64, 3), us.stream_id); // Server uni: 3, 7, 11, ...
}

test "streamType" {
    try testing.expectEqual(StreamType.client_bidi, streamType(0));
    try testing.expectEqual(StreamType.server_bidi, streamType(1));
    try testing.expectEqual(StreamType.client_uni, streamType(2));
    try testing.expectEqual(StreamType.server_uni, streamType(3));
    try testing.expectEqual(StreamType.client_bidi, streamType(4));
    try testing.expectEqual(StreamType.server_bidi, streamType(5));
}

test "StreamsMap: closeStream decrements open count for peer-initiated bidi" {
    // Server perspective: client-initiated bidi stream (id=0) is peer-initiated
    var sm = StreamsMap.init(testing.allocator, true);
    defer sm.deinit();

    sm.setMaxIncomingStreams(10, 10);

    // Simulate peer opening a bidi stream
    _ = try sm.getOrCreateStream(0); // client bidi id=0
    try testing.expectEqual(@as(u64, 1), sm.open_bidi_streams);
    try testing.expectEqual(@as(u64, 0), sm.consumed_bidi_streams);

    // Close the stream
    sm.closeStream(0);
    try testing.expectEqual(@as(u64, 0), sm.open_bidi_streams);
    try testing.expectEqual(@as(u64, 1), sm.consumed_bidi_streams);
}

test "StreamsMap: closeStream does not count locally-initiated streams as consumed" {
    // Client perspective: client-initiated bidi stream is local
    var sm = StreamsMap.init(testing.allocator, false);
    defer sm.deinit();

    sm.setMaxStreams(10, 10);
    sm.setMaxIncomingStreams(10, 10);

    _ = try sm.openBidiStream(); // id=0 (local)
    try testing.expectEqual(@as(u64, 1), sm.open_bidi_streams);

    sm.closeStream(0);
    try testing.expectEqual(@as(u64, 0), sm.open_bidi_streams);
    // Not consumed because it's locally-initiated
    try testing.expectEqual(@as(u64, 0), sm.consumed_bidi_streams);
}

test "StreamsMap: closeStream for uni streams" {
    // Server perspective: client uni stream (id=2) is peer-initiated
    var sm = StreamsMap.init(testing.allocator, true);
    defer sm.deinit();

    sm.setMaxIncomingStreams(10, 10);

    _ = try sm.getOrCreateRecvStream(2); // client uni id=2
    try testing.expectEqual(@as(u64, 1), sm.open_uni_streams);

    sm.closeStream(2);
    try testing.expectEqual(@as(u64, 0), sm.open_uni_streams);
    try testing.expectEqual(@as(u64, 1), sm.consumed_uni_streams);
}

test "StreamsMap: getMaxStreamsUpdates returns null below threshold" {
    var sm = StreamsMap.init(testing.allocator, true);
    defer sm.deinit();

    sm.setMaxIncomingStreams(10, 10);

    // Consume 1 stream (< quarter of 10 = 2), no update should be sent
    sm.consumed_bidi_streams = 1;
    sm.consumed_uni_streams = 1;

    const update = sm.getMaxStreamsUpdates();
    try testing.expect(update.bidi == null);
    try testing.expect(update.uni == null);
}

test "StreamsMap: getMaxStreamsUpdates triggers at threshold" {
    var sm = StreamsMap.init(testing.allocator, true);
    defer sm.deinit();

    sm.setMaxIncomingStreams(10, 10);

    // Consume 2 streams (= quarter of 10), update should trigger
    sm.consumed_bidi_streams = 2;

    const update = sm.getMaxStreamsUpdates();
    // New max = consumed(2) + max_incoming(10) = 12
    try testing.expectEqual(@as(u64, 12), update.bidi.?);
    try testing.expect(update.uni == null);

    // consumed should be reset after update
    try testing.expectEqual(@as(u64, 0), sm.consumed_bidi_streams);
    // max_incoming should be updated
    try testing.expectEqual(@as(u64, 12), sm.max_incoming_bidi_streams);
    // last_sent tracked
    try testing.expectEqual(@as(u64, 12), sm.last_sent_max_bidi);
}

test "StreamsMap: getMaxStreamsUpdates sliding window advances" {
    var sm = StreamsMap.init(testing.allocator, true);
    defer sm.deinit();

    sm.setMaxIncomingStreams(8, 8);

    // First round: consume 2 (>= 8/4=2)
    sm.consumed_bidi_streams = 2;
    const upd1 = sm.getMaxStreamsUpdates();
    try testing.expectEqual(@as(u64, 10), upd1.bidi.?); // 2 + 8 = 10

    // After first update: max_incoming=10, consumed=0
    // Second round: consume 3 (>= 8/4=2)
    sm.consumed_bidi_streams = 3;
    const upd2 = sm.getMaxStreamsUpdates();
    try testing.expectEqual(@as(u64, 13), upd2.bidi.?); // 3 + 10 = 13

    // No redundant update if consumed hasn't reached threshold
    sm.consumed_bidi_streams = 0;
    const upd3 = sm.getMaxStreamsUpdates();
    try testing.expect(upd3.bidi == null);
}

test "StreamsMap: getMaxStreamsUpdates no duplicate sends" {
    var sm = StreamsMap.init(testing.allocator, true);
    defer sm.deinit();

    sm.setMaxIncomingStreams(4, 0);

    sm.consumed_bidi_streams = 2;
    const upd_a = sm.getMaxStreamsUpdates();
    try testing.expect(upd_a.bidi != null);

    // Calling again without consuming more should not re-send
    const upd_b = sm.getMaxStreamsUpdates();
    try testing.expect(upd_b.bidi == null);
}

test "StreamsMap: getMaxStreamsUpdates uni direction" {
    var sm = StreamsMap.init(testing.allocator, true);
    defer sm.deinit();

    sm.setMaxIncomingStreams(0, 6);

    sm.consumed_uni_streams = 3; // >= 6/2=3
    const update = sm.getMaxStreamsUpdates();
    try testing.expect(update.bidi == null);
    try testing.expectEqual(@as(u64, 9), update.uni.?); // 3 + 6 = 9
}

test "StreamsMap: getMaxStreamsUpdates both directions simultaneously" {
    var sm = StreamsMap.init(testing.allocator, true);
    defer sm.deinit();

    sm.setMaxIncomingStreams(4, 6);

    sm.consumed_bidi_streams = 2;
    sm.consumed_uni_streams = 4;

    const update = sm.getMaxStreamsUpdates();
    try testing.expectEqual(@as(u64, 6), update.bidi.?);
    try testing.expectEqual(@as(u64, 10), update.uni.?);
}

test "StreamsMap: closeStream and getMaxStreamsUpdates integration" {
    // Server: client opens 4 bidi streams, we close them, MAX_STREAMS should trigger
    var sm = StreamsMap.init(testing.allocator, true);
    defer sm.deinit();

    sm.setMaxIncomingStreams(4, 0);

    // Client opens 4 bidi streams (ids 0, 4, 8, 12)
    _ = try sm.getOrCreateStream(0);
    _ = try sm.getOrCreateStream(4);

    try testing.expectEqual(@as(u64, 2), sm.open_bidi_streams);

    // Close both — peer-initiated so consumed increments
    sm.closeStream(0);
    sm.closeStream(4);

    try testing.expectEqual(@as(u64, 0), sm.open_bidi_streams);
    try testing.expectEqual(@as(u64, 2), sm.consumed_bidi_streams);

    // 2 >= 4/2=2, so MAX_STREAMS update should fire
    const update = sm.getMaxStreamsUpdates();
    try testing.expectEqual(@as(u64, 6), update.bidi.?); // 2 + 4 = 6
}

// Retransmission tests

test "SendStream: retransmit prioritized over new data" {
    var ss = SendStream.init(testing.allocator, 0);
    defer ss.deinit();

    // Write 10 bytes of data
    try ss.writeData("helloworld");
    // Pop the first 5 bytes (simulating they were sent)
    const frame1 = ss.popStreamFrame(5);
    try testing.expect(frame1 != null);
    try testing.expectEqualSlices(u8, "hello", frame1.?.stream.data);
    try testing.expectEqual(@as(u64, 0), frame1.?.stream.offset);

    // Now simulate packet loss for the first 5 bytes
    ss.queueRetransmit(0, 5, false);

    // The next popStreamFrame should return the retransmitted data, not new data
    const frame2 = ss.popStreamFrame(100);
    try testing.expect(frame2 != null);
    try testing.expectEqualSlices(u8, "hello", frame2.?.stream.data);
    try testing.expectEqual(@as(u64, 0), frame2.?.stream.offset);
    try testing.expect(!frame2.?.stream.fin);

    // Now new data should be returned
    const frame3 = ss.popStreamFrame(100);
    try testing.expect(frame3 != null);
    try testing.expectEqualSlices(u8, "world", frame3.?.stream.data);
    try testing.expectEqual(@as(u64, 5), frame3.?.stream.offset);
}

test "SendStream: FIN retransmission" {
    var ss = SendStream.init(testing.allocator, 4);
    defer ss.deinit();

    try ss.writeData("data");
    ss.close();

    // Pop the frame with FIN
    const frame1 = ss.popStreamFrame(100);
    try testing.expect(frame1 != null);
    try testing.expect(frame1.?.stream.fin);
    try testing.expectEqualSlices(u8, "data", frame1.?.stream.data);
    try testing.expect(ss.fin_sent);

    // Nothing more to send
    try testing.expect(!ss.hasData());

    // Simulate packet loss - the entire frame (data + FIN) was lost
    ss.queueRetransmit(0, 4, true);

    // Should have data to send again
    try testing.expect(ss.hasData());

    // Retransmission should include FIN
    const frame2 = ss.popStreamFrame(100);
    try testing.expect(frame2 != null);
    try testing.expectEqualSlices(u8, "data", frame2.?.stream.data);
    try testing.expectEqual(@as(u64, 0), frame2.?.stream.offset);
    try testing.expect(frame2.?.stream.fin);
}

test "SendStream: FIN-only retransmission" {
    var ss = SendStream.init(testing.allocator, 4);
    defer ss.deinit();

    try ss.writeData("data");

    // Pop data first (no FIN yet)
    const frame1 = ss.popStreamFrame(100);
    try testing.expect(frame1 != null);
    try testing.expect(!frame1.?.stream.fin);

    // Close stream and pop FIN
    ss.close();
    const frame2 = ss.popStreamFrame(100);
    try testing.expect(frame2 != null);
    try testing.expect(frame2.?.stream.fin);
    try testing.expectEqual(@as(u64, 0), frame2.?.stream.length);
    try testing.expectEqual(@as(u64, 4), frame2.?.stream.offset);

    // Simulate FIN-only frame loss (zero-length range with fin=true)
    ss.queueRetransmit(4, 0, true);

    try testing.expect(ss.hasData());

    // Should retransmit just the FIN
    const frame3 = ss.popStreamFrame(100);
    try testing.expect(frame3 != null);
    try testing.expect(frame3.?.stream.fin);
    try testing.expectEqual(@as(u64, 0), frame3.?.stream.length);
    try testing.expectEqual(@as(u64, 4), frame3.?.stream.offset);
}

test "SendStream: retransmit range merging" {
    var ss = SendStream.init(testing.allocator, 0);
    defer ss.deinit();

    try ss.writeData("helloworldtest");
    // Send all the data
    _ = ss.popStreamFrame(100);

    // Queue two adjacent retransmit ranges - they should merge
    ss.queueRetransmit(0, 5, false); // "hello"
    ss.queueRetransmit(5, 5, false); // "world"

    // Should have merged into a single range
    try testing.expectEqual(@as(u8, 1), ss.retransmit_count);

    const frame = ss.popStreamFrame(100);
    try testing.expect(frame != null);
    try testing.expectEqual(@as(u64, 0), frame.?.stream.offset);
    try testing.expectEqual(@as(u64, 10), frame.?.stream.length);
    try testing.expectEqualSlices(u8, "helloworld", frame.?.stream.data);
}

test "SendStream: multiple retransmit ranges" {
    var ss = SendStream.init(testing.allocator, 0);
    defer ss.deinit();

    try ss.writeData("helloworldtest!!");
    // Send all the data
    _ = ss.popStreamFrame(100);

    // Queue two non-adjacent ranges
    ss.queueRetransmit(0, 5, false); // "hello"
    ss.queueRetransmit(10, 4, false); // "test"

    try testing.expectEqual(@as(u8, 2), ss.retransmit_count);

    // First retransmit
    const frame1 = ss.popStreamFrame(100);
    try testing.expect(frame1 != null);
    try testing.expectEqual(@as(u64, 0), frame1.?.stream.offset);
    try testing.expectEqualSlices(u8, "hello", frame1.?.stream.data);

    // Second retransmit
    const frame2 = ss.popStreamFrame(100);
    try testing.expect(frame2 != null);
    try testing.expectEqual(@as(u64, 10), frame2.?.stream.offset);
    try testing.expectEqualSlices(u8, "test", frame2.?.stream.data);

    // No more retransmits, no new data
    try testing.expect(!ss.hasData());
}

test "SendStream: retransmit ignored after reset" {
    var ss = SendStream.init(testing.allocator, 0);
    defer ss.deinit();

    try ss.writeData("hello");
    _ = ss.popStreamFrame(100);

    // Reset the stream
    ss.reset(0x01);

    // Queue retransmit - should be ignored
    ss.queueRetransmit(0, 5, false);
    try testing.expectEqual(@as(u8, 0), ss.retransmit_count);

    // No data to send
    try testing.expect(ss.popStreamFrame(100) == null);
}

test "SendStream: partial retransmit due to max_len" {
    var ss = SendStream.init(testing.allocator, 0);
    defer ss.deinit();

    try ss.writeData("helloworld");
    // Send all the data
    _ = ss.popStreamFrame(100);

    // Queue retransmit of all 10 bytes
    ss.queueRetransmit(0, 10, false);

    // Pop with max_len=5 - should get partial retransmit
    const frame1 = ss.popStreamFrame(5);
    try testing.expect(frame1 != null);
    try testing.expectEqual(@as(u64, 0), frame1.?.stream.offset);
    try testing.expectEqualSlices(u8, "hello", frame1.?.stream.data);

    // Remaining retransmit
    const frame2 = ss.popStreamFrame(100);
    try testing.expect(frame2 != null);
    try testing.expectEqual(@as(u64, 5), frame2.?.stream.offset);
    try testing.expectEqualSlices(u8, "world", frame2.?.stream.data);

    try testing.expect(!ss.hasData());
}

// Retransmit queue overflow: when MAX_RETRANSMIT_RANGES is exceeded,
// send_offset is lowered to cover all lost data (no silent data loss).
test "SendStream: retransmit queue overflow falls back to send_offset" {
    var ss = SendStream.init(testing.allocator, 0);
    defer ss.deinit();

    // Write enough data to cover all ranges
    const data = "x" ** 2048;
    try ss.writeData(data);
    // Simulate having sent all data
    ss.send_offset = 2048;

    // Fill the retransmit queue with non-adjacent ranges (simulating random
    // hash-map iteration order during mass loss detection)
    var i: u8 = 0;
    while (i < MAX_RETRANSMIT_RANGES) : (i += 1) {
        // Non-adjacent: offset 0, 100, 200, ... with length 50 each (gaps of 50)
        ss.queueRetransmit(@as(u64, i) * 100, 50, false);
    }
    try testing.expectEqual(@as(u8, MAX_RETRANSMIT_RANGES), ss.retransmit_count);
    try testing.expectEqual(@as(u64, 2048), ss.send_offset);

    // Queue one more — should trigger overflow fallback
    ss.queueRetransmit(1700, 50, false);

    // After overflow: retransmit queue is cleared, send_offset lowered to earliest
    try testing.expectEqual(@as(u8, 0), ss.retransmit_count);
    try testing.expectEqual(@as(u64, 0), ss.send_offset); // min of all range offsets
    try testing.expect(ss.hasData()); // still has data to send
}

// RFC 9218 priority scheduling tests

test "StreamsMap: getScheduledStreams returns highest priority stream" {
    var sm = StreamsMap.init(testing.allocator, false);
    defer sm.deinit();
    sm.setMaxStreams(10, 10);

    const s0 = try sm.openBidiStream(); // id=0
    const s4 = try sm.openBidiStream(); // id=4

    try s0.send.writeData("low");
    s0.send.urgency = 5;

    try s4.send.writeData("high");
    s4.send.urgency = 1;

    var out: [StreamsMap.MAX_SCHEDULABLE]*Stream = undefined;
    const count = sm.getScheduledStreams(&out);
    try testing.expectEqual(@as(usize, 1), count);
    try testing.expectEqual(@as(u64, 4), out[0].stream_id);
}

test "StreamsMap: getScheduledStreams non-incremental is sequential" {
    var sm = StreamsMap.init(testing.allocator, false);
    defer sm.deinit();
    sm.setMaxStreams(10, 10);

    const s0 = try sm.openBidiStream();
    const s4 = try sm.openBidiStream();

    try s0.send.writeData("aaa");
    s0.send.urgency = 3;
    s0.send.incremental = false;

    try s4.send.writeData("bbb");
    s4.send.urgency = 3;
    s4.send.incremental = false;

    var out: [StreamsMap.MAX_SCHEDULABLE]*Stream = undefined;
    const count = sm.getScheduledStreams(&out);
    // Non-incremental: only one stream at a time
    try testing.expectEqual(@as(usize, 1), count);
}

test "StreamsMap: getScheduledStreams incremental returns all" {
    var sm = StreamsMap.init(testing.allocator, false);
    defer sm.deinit();
    sm.setMaxStreams(10, 10);

    const s0 = try sm.openBidiStream();
    const s4 = try sm.openBidiStream();

    try s0.send.writeData("aaa");
    s0.send.urgency = 2;
    s0.send.incremental = true;

    try s4.send.writeData("bbb");
    s4.send.urgency = 2;
    s4.send.incremental = true;

    var out: [StreamsMap.MAX_SCHEDULABLE]*Stream = undefined;
    const count = sm.getScheduledStreams(&out);
    // Incremental: all streams at same urgency
    try testing.expectEqual(@as(usize, 2), count);
}

test "StreamsMap: getScheduledStreams skips streams without data" {
    var sm = StreamsMap.init(testing.allocator, false);
    defer sm.deinit();
    sm.setMaxStreams(10, 10);

    const s0 = try sm.openBidiStream();
    _ = try sm.openBidiStream(); // no data

    try s0.send.writeData("data");
    s0.send.urgency = 3;

    var out: [StreamsMap.MAX_SCHEDULABLE]*Stream = undefined;
    const count = sm.getScheduledStreams(&out);
    try testing.expectEqual(@as(usize, 1), count);
    try testing.expectEqual(@as(u64, 0), out[0].stream_id);
}

test "StreamsMap: getScheduledStreams returns empty when no data" {
    var sm = StreamsMap.init(testing.allocator, false);
    defer sm.deinit();
    sm.setMaxStreams(10, 10);

    _ = try sm.openBidiStream();
    _ = try sm.openBidiStream();

    var out: [StreamsMap.MAX_SCHEDULABLE]*Stream = undefined;
    const count = sm.getScheduledStreams(&out);
    try testing.expectEqual(@as(usize, 0), count);
}

test "StreamsMap: getScheduledStreams mixed incremental and non-incremental" {
    var sm = StreamsMap.init(testing.allocator, false);
    defer sm.deinit();
    sm.setMaxStreams(10, 10);

    const s0 = try sm.openBidiStream();
    const s4 = try sm.openBidiStream();
    const s8 = try sm.openBidiStream();

    // One non-incremental + two incremental at same urgency
    try s0.send.writeData("aaa");
    s0.send.urgency = 2;
    s0.send.incremental = false;

    try s4.send.writeData("bbb");
    s4.send.urgency = 2;
    s4.send.incremental = true;

    try s8.send.writeData("ccc");
    s8.send.urgency = 2;
    s8.send.incremental = true;

    var out: [StreamsMap.MAX_SCHEDULABLE]*Stream = undefined;
    const count = sm.getScheduledStreams(&out);
    // 1 non-incremental + 2 incremental = 3
    try testing.expectEqual(@as(usize, 3), count);
}
