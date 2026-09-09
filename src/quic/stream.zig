const std = @import("std");
const Allocator = std.mem.Allocator;
const testing = std.testing;

const flow_control = @import("flow_control.zig");
const Frame = @import("frame.zig").Frame;
const ranges = @import("ranges.zig");

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
    chunks: std.AutoArrayHashMapUnmanaged(u64, []const u8),

    /// Next offset to be read by the application.
    read_pos: u64 = 0,

    /// The final offset (set when FIN is received).
    fin_offset: ?u64 = null,

    /// Highest byte offset ever buffered. Maintained incrementally to avoid
    /// scanning all chunks on every push().
    highest_buffered: u64 = 0,

    pub fn init(allocator: Allocator) FrameSorter {
        return .{
            .allocator = allocator,
            .chunks = .{},
        };
    }

    pub fn deinit(self: *FrameSorter) void {
        // Free any owned data
        for (self.chunks.values()) |data| {
            self.allocator.free(data);
        }
        self.chunks.deinit(self.allocator);
    }

    /// Return the highest byte offset buffered (or read_pos if no chunks).
    pub fn highestReceived(self: *const FrameSorter) u64 {
        return @max(self.read_pos, self.highest_buffered);
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

        // Fast path for the dominant receive case: new STREAM data appends at
        // or beyond the highest byte ever buffered. It cannot overlap an
        // existing chunk, so avoid scanning the full chunk map for every packet.
        if (effective_offset >= self.highest_buffered) {
            const owned = try self.allocator.dupe(u8, effective_data);
            errdefer self.allocator.free(owned);
            try self.chunks.put(self.allocator, effective_offset, owned);
            self.highest_buffered = effective_offset + owned.len;
            return;
        }

        while (true) {
            const new_start = effective_offset;
            const new_end = effective_offset + effective_data.len;
            var changed = false;
            var i: usize = 0;
            while (i < self.chunks.count()) {
                const existing_offset = self.chunks.keys()[i];
                const existing = self.chunks.values()[i];
                const existing_end = existing_offset + existing.len;
                if (existing_end <= new_start or existing_offset >= new_end) {
                    i += 1;
                    continue;
                }

                if (existing_offset <= new_start and existing_end >= new_end) {
                    return;
                }

                if (existing_offset <= new_start and existing_end > new_start) {
                    const skip: usize = @intCast(existing_end - new_start);
                    effective_offset = existing_end;
                    effective_data = effective_data[skip..];
                    if (effective_data.len == 0) return;
                    changed = true;
                    break;
                }

                if (existing_offset < new_end and existing_end > new_end) {
                    const suffix_start: usize = @intCast(new_end - existing_offset);
                    const suffix = existing[suffix_start..];
                    const owned_suffix = try self.allocator.dupe(u8, suffix);
                    errdefer self.allocator.free(owned_suffix);
                    _ = self.chunks.swapRemove(existing_offset);
                    self.allocator.free(existing);
                    try self.chunks.put(self.allocator, new_end, owned_suffix);
                    changed = true;
                    break;
                }

                _ = self.chunks.swapRemove(existing_offset);
                self.allocator.free(existing);
                changed = true;
                break;
            }
            if (!changed) break;
        }

        // Copy data to owned buffer
        const owned = try self.allocator.dupe(u8, effective_data);
        errdefer self.allocator.free(owned);

        try self.chunks.put(self.allocator, effective_offset, owned);

        const end_offset = effective_offset + owned.len;
        if (end_offset > self.highest_buffered) self.highest_buffered = end_offset;
    }

    /// Pop the next contiguous chunk of data from the read position.
    /// Returns null if there's no data available at the current read position.
    pub fn pop(self: *FrameSorter) ?[]const u8 {
        if (self.chunks.fetchSwapRemove(self.read_pos)) |entry| {
            self.read_pos += entry.value.len;
            return entry.value;
        }

        var best_index: ?usize = null;
        var best_end: u64 = 0;
        for (self.chunks.keys(), 0..) |offset, index| {
            const data = self.chunks.values()[index];
            const end = offset + data.len;
            if (offset <= self.read_pos and self.read_pos < end and end > best_end) {
                best_index = index;
                best_end = end;
            }
        }
        if (best_index) |index| {
            const offset = self.chunks.keys()[index];
            const data = self.chunks.values()[index];
            _ = self.chunks.swapRemove(offset);
            const skip: usize = @intCast(self.read_pos - offset);
            const readable = data[skip..];
            const owned = if (skip == 0)
                data
            else blk: {
                const copy = self.allocator.dupe(u8, readable) catch {
                    self.allocator.free(data);
                    return null;
                };
                self.allocator.free(data);
                break :blk copy;
            };
            self.read_pos += readable.len;
            return owned;
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

    /// Highest contiguous offset acknowledged by the peer.
    /// Used by PTO to determine what needs retransmission — data between
    /// ack_offset and write_offset may not have been received.
    ack_offset: u64 = 0,

    /// STREAM frame ACKs can arrive out of order because packet ACK ranges are
    /// not equivalent to contiguous stream-byte delivery. Track acknowledged
    /// byte ranges and only advance ack_offset through a contiguous prefix.
    acked_ranges: ranges.RangeSet,

    /// Maximum data the peer allows us to send on this stream.
    send_window: u64 = std.math.maxInt(u64),

    // Track the limit at which we last sent STREAM_DATA_BLOCKED (avoid duplicates)
    blocked_at: ?u64 = null,

    /// RFC 9218 priority: urgency (0=highest, 7=lowest, default 3).
    urgency: u3 = 3,

    /// RFC 9218 priority: incremental streams are interleaved round-robin.
    /// RFC 9218 §4.2: the default is non-incremental (sequential). Protocol
    /// adapters that want round-robin multiplexing (WebTransport, HTTP/0.9)
    /// opt in explicitly at their stream-open boundary.
    incremental: bool = false,

    /// WebTransport sendOrder: higher values transmitted first. When set,
    /// takes precedence over RFC 9218 urgency for scheduling.
    send_order: ?i64 = null,

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
            .acked_ranges = ranges.RangeSet.init(allocator),
        };
    }

    pub fn deinit(self: *SendStream) void {
        self.acked_ranges.deinit();
        self.write_buffer.deinit(self.allocator);
    }

    /// Write data to the stream. Buffers it for later sending.
    pub fn writeData(self: *SendStream, data: []const u8) !void {
        // Once the stream has buffered more than a few small writes, jump
        // capacity to 4 KiB in one shot. Avoids the 8→16→32→… realloc cascade
        // for streaming workloads (measured 2-5× faster on multi-write patterns)
        // while leaving small one-shot writes on the default growth path.
        const new_total = self.write_buffer.items.len + data.len;
        if (self.write_buffer.capacity < 4096 and new_total > 256) {
            try self.write_buffer.ensureTotalCapacity(
                self.allocator,
                @max(new_total, @as(usize, 4096)),
            );
        }
        try self.write_buffer.appendSlice(self.allocator, data);
        self.write_offset += data.len;
    }

    /// Close the stream (queue FIN).
    pub fn close(self: *SendStream) void {
        self.fin_queued = true;
    }

    /// Update the acknowledged offset when a packet carrying stream frames is ACKed.
    pub fn onAck(self: *SendStream, offset: u64, length: u64) !void {
        if (length == 0) {
            return;
        }
        const end = offset + length;
        if (end <= self.ack_offset) {
            return;
        }

        try self.acked_ranges.addRange(@max(offset, self.ack_offset), end - 1);
        while (true) {
            var advanced = false;
            for (self.acked_ranges.getRanges()) |range| {
                if (range.start <= self.ack_offset and self.ack_offset <= range.end) {
                    self.ack_offset = range.end + 1;
                    self.acked_ranges.removeBelow(self.ack_offset);
                    advanced = true;
                    break;
                }
            }
            if (!advanced) {
                break;
            }
        }
        self.trimRetransmitRangesBelow(self.ack_offset);
        self.send_offset = @max(self.send_offset, self.ack_offset);
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
    // STREAM_DATA_BLOCKED is advisory; emit once per blocked limit and re-arm
    // when MAX_STREAM_DATA advances the send window.
    pub fn shouldSendBlocked(self: *SendStream) ?u64 {
        if (self.send_offset >= self.send_window and self.hasData() and self.blocked_at != self.send_window) {
            self.blocked_at = self.send_window;
            return self.send_window;
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
            // Queue overflow: coalesce to one broad retransmit range. Do not
            // rewind send_offset: retransmitted bytes have already consumed
            // connection-level flow-control credit and must stay on the
            // retransmit path.
            var min_offset = offset;
            var max_end = offset + length;
            var has_fin = fin;
            for (self.retransmit_ranges[0..self.retransmit_count]) |r| {
                min_offset = @min(min_offset, r.offset);
                max_end = @max(max_end, r.offset + r.length);
                if (r.fin) has_fin = true;
            }
            self.retransmit_ranges[0] = .{
                .offset = min_offset,
                .length = max_end - min_offset,
                .fin = has_fin,
            };
            self.retransmit_count = 1;
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

    /// Check if the next send is retransmission-only data. Retransmitted bytes
    /// were already counted against connection flow control when first sent, so
    /// packet assembly must not block them behind exhausted MAX_DATA credit.
    pub fn hasRetransmitData(self: *const SendStream) bool {
        return self.retransmit_count > 0 or self.fin_lost;
    }

    /// Check if there's data that has been sent but not yet acknowledged.
    /// Used by PTO to determine if retransmission is needed.
    pub fn hasUnackedData(self: *const SendStream) bool {
        return self.ack_offset < self.write_offset or
            (self.fin_queued and self.ack_offset < self.write_offset + 1);
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

    fn trimRetransmitRangesBelow(self: *SendStream, acked_offset: u64) void {
        var i: usize = 0;
        while (i < self.retransmit_count) {
            const end = self.retransmit_ranges[i].offset + self.retransmit_ranges[i].length;
            if (end <= acked_offset) {
                self.removeRetransmitRange(i);
                continue;
            }
            if (self.retransmit_ranges[i].offset < acked_offset) {
                self.retransmit_ranges[i].length = end - acked_offset;
                self.retransmit_ranges[i].offset = acked_offset;
            }
            i += 1;
        }
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

    /// Targeted disposal queue: stream IDs ready for removal. Populated by
    /// queueDisposal() at the point where a stream is known to be fully done,
    /// drained by drainDisposalQueue() once per event loop cycle. O(k) not O(n).
    disposal_queue: [64]u64 = undefined,
    disposal_count: usize = 0,

    /// Highest peer-initiated bidi stream ID that has been opened.
    /// Upper layers (WT/H3) compare this with their own "next to examine"
    /// counter to discover new streams in O(1) — same pattern as quic-go's
    /// nextStreamToAccept / nextStreamToOpen.
    highest_peer_bidi_stream_id: ?u64 = null,

    /// Flag: set when a stream's FIN is received or sent, indicating that
    /// collectClosedStreams() needs to scan. Cleared after scan completes.
    /// Avoids O(n) scan on every send() when no streams are closing.
    needs_gc_scan: bool = false,

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
        self.needs_gc_scan = true; // New stream will eventually need GC
        // Track highest peer-initiated bidi stream ID for O(1) discovery
        if (self.highest_peer_bidi_stream_id == null or stream_id > self.highest_peer_bidi_stream_id.?) {
            self.highest_peer_bidi_stream_id = stream_id;
        }
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

    /// Select bidi streams to send data on, respecting both WebTransport sendOrder
    /// and RFC 9218 priority. Two tiers:
    ///   Tier 1: streams with send_order set — sorted descending (higher = more urgent).
    ///   Tier 2: streams without send_order — RFC 9218 urgency-based scheduling.
    /// Returns the count of streams written to `out`.
    pub fn getScheduledStreams(self: *StreamsMap, out: *[MAX_SCHEDULABLE]*Stream) usize {
        // Tier 1: collect streams with send_order set
        var ordered_count: usize = 0;
        var it = self.streams.valueIterator();
        while (it.next()) |sp| {
            const s = sp.*;
            // closed_for_gc signals "FIN sent + peer FIN received", but FIN-sent
            // does not imply FIN-acked. Under loss, PTO resets send_offset to
            // ack_offset to retransmit unACKed data — making hasData() true even
            // though retransmit_count stays 0. So the hasData() check is the
            // authoritative signal; closed_for_gc alone must not suppress it.
            if (!s.send.hasData()) continue;
            if (s.send.send_order != null) {
                if (ordered_count >= MAX_SCHEDULABLE) continue;
                out[ordered_count] = s;
                ordered_count += 1;
            }
        }
        // Sort tier 1 descending by send_order (higher first)
        if (ordered_count > 1) {
            sortStreamsBySendOrder(out[0..ordered_count]);
        }

        // Tier 2: streams without send_order — RFC 9218 urgency scheduling
        var min_urgency: u3 = 7;
        var urgency_count: usize = 0;
        var found_non_incremental = false;
        var urgency_buf: [MAX_SCHEDULABLE]*Stream = undefined;
        var it2 = self.streams.valueIterator();
        while (it2.next()) |sp| {
            const s = sp.*;
            // See tier 1: hasData() is authoritative, closed_for_gc alone can't suppress.
            if (!s.send.hasData()) continue;
            if (s.send.send_order != null) continue; // already in tier 1

            if (s.send.urgency < min_urgency) {
                min_urgency = s.send.urgency;
                urgency_count = 0;
                found_non_incremental = false;
            }

            if (s.send.urgency != min_urgency) continue;

            if (!s.send.incremental) {
                if (!found_non_incremental) {
                    if (urgency_count >= MAX_SCHEDULABLE) continue;
                    urgency_buf[urgency_count] = s;
                    urgency_count += 1;
                    found_non_incremental = true;
                }
            } else {
                if (urgency_count >= MAX_SCHEDULABLE) continue;
                urgency_buf[urgency_count] = s;
                urgency_count += 1;
            }
        }

        // Rotate tier 2 incremental streams for fairness
        if (urgency_count > 1) {
            const rotation = self.rr_index % urgency_count;
            if (rotation > 0) {
                var tmp: [MAX_SCHEDULABLE]*Stream = undefined;
                for (0..urgency_count) |i| {
                    tmp[i] = urgency_buf[(i + rotation) % urgency_count];
                }
                for (0..urgency_count) |i| {
                    urgency_buf[i] = tmp[i];
                }
            }
        }
        if (urgency_count > 0) self.rr_index +%= 1;

        // Append tier 2 after tier 1
        const total = @min(ordered_count + urgency_count, MAX_SCHEDULABLE);
        for (ordered_count..total) |i| {
            out[i] = urgency_buf[i - ordered_count];
        }
        return total;
    }

    /// Select uni send streams to send data on, sorted by send_order (higher first).
    /// Streams without send_order are appended after ordered ones.
    pub fn getScheduledUniStreams(self: *StreamsMap, out: *[MAX_SCHEDULABLE]*SendStream) usize {
        var ordered_count: usize = 0;
        var unordered_count: usize = 0;
        var unordered_buf: [MAX_SCHEDULABLE]*SendStream = undefined;

        var it = self.send_streams.valueIterator();
        while (it.next()) |s_ptr| {
            const s = s_ptr.*;
            if (!s.hasData()) continue;
            if (s.send_order != null) {
                if (ordered_count < MAX_SCHEDULABLE) {
                    out[ordered_count] = s;
                    ordered_count += 1;
                }
            } else {
                if (unordered_count < MAX_SCHEDULABLE) {
                    unordered_buf[unordered_count] = s;
                    unordered_count += 1;
                }
            }
        }

        // Sort ordered streams descending by send_order
        if (ordered_count > 1) {
            sortSendStreamsBySendOrder(out[0..ordered_count]);
        }

        // Append unordered after ordered
        const total = @min(ordered_count + unordered_count, MAX_SCHEDULABLE);
        for (ordered_count..total) |i| {
            out[i] = unordered_buf[i - ordered_count];
        }
        return total;
    }

    /// Mark a stream as fully closed and update consumed counters.
    /// Only counts peer-initiated streams (those count against our MAX_STREAMS limit).
    /// Scan bidi streams for ones that are fully closed (both FIN sent and FIN received)
    /// and call closeStream for each. This ensures consumed_*_streams advances even when
    /// the close was never triggered by a received STREAM/RESET_STREAM frame.
    pub fn collectClosedStreams(self: *StreamsMap) void {
        if (!self.needs_gc_scan) return; // No FIN events since last scan

        // Mark fully-closed streams for consumed counting and queue for disposal.
        var found_pending = false;
        var it = self.streams.iterator();
        while (it.next()) |kv| {
            const s = kv.value_ptr.*;
            if (!s.closed_for_gc and (s.recv.finished or s.recv.fin_received) and s.send.fin_sent) {
                s.closed_for_gc = true;
                self.closeStream(s.stream_id);
                // Delay disposal: keep the stream in the map so PTO can
                // reset send_offset for retransmission under loss.
                // Stream will be cleaned up when the connection closes.
            } else if (!s.closed_for_gc) {
                // At least one stream is still pending close
                found_pending = true;
            }
        }
        // Clear flag only if no unclosed streams remain
        if (!found_pending) self.needs_gc_scan = false;
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

    /// Queue a stream for removal. O(1) — called when a stream is known to be
    /// fully closed (closed_for_gc set, no pending retransmissions).
    pub fn queueDisposal(self: *StreamsMap, stream_id: u64) void {
        if (self.disposal_count < self.disposal_queue.len) {
            self.disposal_queue[self.disposal_count] = stream_id;
            self.disposal_count += 1;
        }
    }

    /// Drain the disposal queue: remove queued streams from the maps. O(k)
    /// where k = number of streams queued since last drain (typically 0-2).
    pub fn drainDisposalQueue(self: *StreamsMap) void {
        if (self.disposal_count == 0) return;
        for (self.disposal_queue[0..self.disposal_count]) |id| {
            if (self.streams.fetchRemove(id)) |kv| {
                var s = kv.value;
                s.deinit();
                self.allocator.destroy(s);
            }
            if (self.recv_streams.fetchRemove(id)) |kv| {
                var rs = kv.value;
                rs.deinit();
                self.allocator.destroy(rs);
            }
        }
        self.disposal_count = 0;
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

/// Sort bidi streams descending by send_order (higher first).
/// Stable: equal send_order preserves arrival order.
fn sortStreamsBySendOrder(streams: []*Stream) void {
    const C = struct {
        fn moreUrgent(_: void, a: *Stream, b: *Stream) bool {
            return (a.send.send_order orelse 0) > (b.send.send_order orelse 0);
        }
    };
    std.sort.insertion(*Stream, streams, {}, C.moreUrgent);
}

/// Sort uni send streams descending by send_order (higher first).
/// Stable: equal send_order preserves arrival order.
fn sortSendStreamsBySendOrder(streams: []*SendStream) void {
    const C = struct {
        fn moreUrgent(_: void, a: *SendStream, b: *SendStream) bool {
            return (a.send_order orelse 0) > (b.send_order orelse 0);
        }
    };
    std.sort.insertion(*SendStream, streams, {}, C.moreUrgent);
}

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

test "FrameSorter: sequential append fast path remains readable" {
    var sorter = FrameSorter.init(testing.allocator);
    defer sorter.deinit();

    try sorter.push(0, "hello", false);
    try sorter.push(5, " ", false);
    try sorter.push(6, "world", true);

    const chunk1 = sorter.pop();
    try testing.expect(chunk1 != null);
    try testing.expectEqualStrings("hello", chunk1.?);
    testing.allocator.free(chunk1.?);

    const chunk2 = sorter.pop();
    try testing.expect(chunk2 != null);
    try testing.expectEqualStrings(" ", chunk2.?);
    testing.allocator.free(chunk2.?);

    const chunk3 = sorter.pop();
    try testing.expect(chunk3 != null);
    try testing.expectEqualStrings("world", chunk3.?);
    testing.allocator.free(chunk3.?);

    try testing.expect(sorter.isComplete());
}

test "FrameSorter: out-of-order gap still accepts sequential tail" {
    var sorter = FrameSorter.init(testing.allocator);
    defer sorter.deinit();

    try sorter.push(6, "world", true);
    try sorter.push(0, "hello", false);
    try sorter.push(5, " ", false);

    const chunk1 = sorter.pop();
    try testing.expect(chunk1 != null);
    try testing.expectEqualStrings("hello", chunk1.?);
    testing.allocator.free(chunk1.?);

    const chunk2 = sorter.pop();
    try testing.expect(chunk2 != null);
    try testing.expectEqualStrings(" ", chunk2.?);
    testing.allocator.free(chunk2.?);

    const chunk3 = sorter.pop();
    try testing.expect(chunk3 != null);
    try testing.expectEqualStrings("world", chunk3.?);
    testing.allocator.free(chunk3.?);

    try testing.expect(sorter.isComplete());
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

test "ReceiveStream: read returns final chunk before finished flips" {
    var rs = ReceiveStream.init(testing.allocator, 1024);
    defer rs.deinit();

    try rs.handleStreamFrame(0, "done", true);

    const data = rs.read();
    try testing.expect(data != null);
    try testing.expectEqualStrings("done", data.?);
    try testing.expect(!rs.finished);
    testing.allocator.free(data.?);

    try testing.expect(rs.read() == null);
    try testing.expect(rs.finished);
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
// lost data is coalesced without rewinding send_offset.
test "SendStream: retransmit queue overflow coalesces ranges" {
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

    // After overflow: retransmit queue is coalesced, while send_offset stays at
    // the real high-water mark so flow-control credit is not double-counted.
    try testing.expectEqual(@as(u8, 1), ss.retransmit_count);
    try testing.expectEqual(@as(u64, 0), ss.retransmit_ranges[0].offset);
    try testing.expectEqual(@as(u64, 1750), ss.retransmit_ranges[0].length);
    try testing.expectEqual(@as(u64, 2048), ss.send_offset);
    try testing.expect(ss.hasRetransmitData());
}

test "SendStream: contiguous ACK advances send offset after retransmit" {
    var ss = SendStream.init(testing.allocator, 0);
    defer ss.deinit();

    const data = "x" ** 100;
    try ss.writeData(data);
    ss.send_offset = 20;

    ss.queueRetransmit(20, 80, false);
    const retransmit = ss.popStreamFrame(100).?;
    try testing.expectEqual(@as(u64, 20), retransmit.stream.offset);
    try testing.expectEqual(@as(u64, 80), retransmit.stream.length);
    try testing.expectEqual(@as(u64, 20), ss.send_offset);

    try ss.onAck(0, 100);

    try testing.expectEqual(@as(u64, 100), ss.ack_offset);
    try testing.expectEqual(@as(u64, 100), ss.send_offset);
    try testing.expect(!ss.hasData());
    try testing.expect(ss.popStreamFrame(100) == null);
}

test "SendStream: ACK progress trims stale retransmit ranges" {
    var ss = SendStream.init(testing.allocator, 0);
    defer ss.deinit();

    const data = "x" ** 100;
    try ss.writeData(data);
    ss.send_offset = 100;
    ss.queueRetransmit(0, 80, false);

    try ss.onAck(0, 32);

    try testing.expectEqual(@as(u8, 1), ss.retransmit_count);
    try testing.expectEqual(@as(u64, 32), ss.retransmit_ranges[0].offset);
    try testing.expectEqual(@as(u64, 48), ss.retransmit_ranges[0].length);

    try ss.onAck(32, 48);
    try testing.expectEqual(@as(u8, 0), ss.retransmit_count);
}

test "SendStream: shouldSendBlocked emits once per blocked limit" {
    var ss = SendStream.init(testing.allocator, 0);
    defer ss.deinit();

    ss.send_window = 4;
    try ss.writeData("abcdefgh");
    _ = ss.popStreamFrame(16).?;

    try testing.expectEqual(@as(?u64, 4), ss.shouldSendBlocked());
    try testing.expectEqual(@as(?u64, null), ss.shouldSendBlocked());

    ss.updateSendWindow(6);
    _ = ss.popStreamFrame(16).?;
    try testing.expectEqual(@as(?u64, 6), ss.shouldSendBlocked());
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

// sendOrder scheduling tests

test "StreamsMap: send_order streams scheduled before urgency-based" {
    var sm = StreamsMap.init(testing.allocator, false);
    defer sm.deinit();
    sm.setMaxStreams(10, 10);

    const s0 = try sm.openBidiStream();
    const s4 = try sm.openBidiStream();

    // s0: urgency 0 (highest RFC 9218 priority), no send_order
    try s0.send.writeData("urgency");
    s0.send.urgency = 0;

    // s4: urgency 7 (lowest), but has send_order
    try s4.send.writeData("ordered");
    s4.send.urgency = 7;
    s4.send.send_order = 10;

    var out: [StreamsMap.MAX_SCHEDULABLE]*Stream = undefined;
    const count = sm.getScheduledStreams(&out);
    try testing.expectEqual(@as(usize, 2), count);
    // send_order stream comes first (tier 1)
    try testing.expectEqual(@as(u64, 4), out[0].stream_id);
    // urgency-based stream second (tier 2)
    try testing.expectEqual(@as(u64, 0), out[1].stream_id);
}

test "StreamsMap: send_order higher value scheduled first" {
    var sm = StreamsMap.init(testing.allocator, false);
    defer sm.deinit();
    sm.setMaxStreams(10, 10);

    const s0 = try sm.openBidiStream();
    const s4 = try sm.openBidiStream();
    const s8 = try sm.openBidiStream();

    try s0.send.writeData("low");
    s0.send.send_order = -5;

    try s4.send.writeData("high");
    s4.send.send_order = 100;

    try s8.send.writeData("mid");
    s8.send.send_order = 50;

    var out: [StreamsMap.MAX_SCHEDULABLE]*Stream = undefined;
    const count = sm.getScheduledStreams(&out);
    try testing.expectEqual(@as(usize, 3), count);
    try testing.expectEqual(@as(u64, 4), out[0].stream_id); // send_order=100
    try testing.expectEqual(@as(u64, 8), out[1].stream_id); // send_order=50
    try testing.expectEqual(@as(u64, 0), out[2].stream_id); // send_order=-5
}

test "StreamsMap: getScheduledUniStreams respects send_order" {
    var sm = StreamsMap.init(testing.allocator, false);
    defer sm.deinit();
    sm.setMaxStreams(10, 10);

    const uni_a = try sm.openUniStream();
    const uni_b = try sm.openUniStream();
    const uni_c = try sm.openUniStream();

    try uni_a.writeData("low");
    uni_a.send_order = 1;

    try uni_b.writeData("high");
    uni_b.send_order = 100;

    try uni_c.writeData("none"); // no send_order

    var out: [StreamsMap.MAX_SCHEDULABLE]*SendStream = undefined;
    const count = sm.getScheduledUniStreams(&out);
    try testing.expectEqual(@as(usize, 3), count);
    // uni stream IDs for client: 2, 6, 10
    try testing.expectEqual(@as(u64, 6), out[0].stream_id); // send_order=100
    try testing.expectEqual(@as(u64, 2), out[1].stream_id); // send_order=1
    // out[2] is uni_c (no send_order, appended after ordered)
    try testing.expectEqual(@as(u64, 10), out[2].stream_id);
}

test "StreamsMap: setSendOrder dynamically changes scheduling" {
    var sm = StreamsMap.init(testing.allocator, false);
    defer sm.deinit();
    sm.setMaxStreams(10, 10);

    const s0 = try sm.openBidiStream();
    const s4 = try sm.openBidiStream();

    try s0.send.writeData("a");
    s0.send.send_order = 10;

    try s4.send.writeData("b");
    s4.send.send_order = 20;

    var out: [StreamsMap.MAX_SCHEDULABLE]*Stream = undefined;

    // s4 (send_order=20) should be first
    var count = sm.getScheduledStreams(&out);
    try testing.expectEqual(@as(usize, 2), count);
    try testing.expectEqual(@as(u64, 4), out[0].stream_id);

    // Dynamically change: s0 gets higher priority
    s0.send.send_order = 50;
    count = sm.getScheduledStreams(&out);
    try testing.expectEqual(@as(u64, 0), out[0].stream_id);
    try testing.expectEqual(@as(u64, 4), out[1].stream_id);
}

// ── Stream lifecycle / disposal tests ──────────────────────────────────

test "collectClosedStreams marks fully-closed bidi streams" {
    var sm = StreamsMap.init(testing.allocator, false);
    defer sm.deinit();
    sm.setMaxStreams(10, 10);

    const s = try sm.openBidiStream();
    try testing.expectEqual(@as(u64, 1), sm.open_bidi_streams);

    // Simulate both directions done: our FIN sent, peer FIN received
    s.send.fin_sent = true;
    s.recv.fin_received = true;

    // openBidiStream doesn't set needs_gc_scan (only getOrCreateStream does), so set it manually
    sm.needs_gc_scan = true;
    sm.collectClosedStreams();

    try testing.expect(s.closed_for_gc);
    // closeStream decremented open counter (locally-initiated, consumed not incremented)
    try testing.expectEqual(@as(u64, 0), sm.open_bidi_streams);
    try testing.expectEqual(@as(u64, 0), sm.consumed_bidi_streams);
}

test "queueDisposal + drainDisposalQueue lifecycle" {
    var sm = StreamsMap.init(testing.allocator, false);
    defer sm.deinit();
    sm.setMaxStreams(10, 10);

    const s = try sm.openBidiStream();
    const sid = s.stream_id;
    try testing.expect(sm.streams.get(sid) != null);

    // Queue — stream still in hashmap before drain
    sm.queueDisposal(sid);
    try testing.expect(sm.streams.get(sid) != null);

    // Drain — stream removed, memory freed
    sm.drainDisposalQueue();
    try testing.expect(sm.streams.get(sid) == null);
}

test "collectClosedStreams defers disposal when hasUnackedData" {
    var sm = StreamsMap.init(testing.allocator, false);
    defer sm.deinit();
    sm.setMaxStreams(10, 10);

    const s = try sm.openBidiStream();
    try s.send.writeData("x" ** 1000);
    s.send.send_offset = 1000; // all data "sent"
    s.send.fin_sent = true;
    s.recv.fin_received = true;

    // ack_offset is 0, so hasUnackedData returns true
    try testing.expect(s.send.hasUnackedData());

    // collectClosedStreams marks closed_for_gc but keeps stream in map (no disposal)
    sm.needs_gc_scan = true;
    sm.collectClosedStreams();
    try testing.expect(s.closed_for_gc);
    try testing.expect(sm.streams.get(s.stream_id) != null);

    // Simulate ACK for all data — advances ack_offset to 1000
    try s.send.onAck(0, 1000);
    try testing.expect(!s.send.hasUnackedData());
}

test "disposal guard: closed_for_gc + fully-acked -> disposed" {
    var sm = StreamsMap.init(testing.allocator, false);
    defer sm.deinit();
    sm.setMaxStreams(10, 10);

    const s = try sm.openBidiStream();
    try s.send.writeData("x" ** 100);
    s.send.send_offset = 100;
    s.send.fin_sent = true;
    s.recv.fin_received = true;

    // Mark closed_for_gc via collectClosedStreams
    sm.needs_gc_scan = true;
    sm.collectClosedStreams();
    try testing.expect(s.closed_for_gc);

    // Fully ACK all sent data (fin_queued not set, so hasUnackedData becomes false)
    try s.send.onAck(0, 100);
    try testing.expect(!s.send.hasUnackedData());
    try testing.expectEqual(@as(u8, 0), s.send.retransmit_count);

    // Same guard used by the onAck disposal check and the STREAM+FIN path
    // closed_for_gc && retransmit_count == 0 && !hasUnackedData()
    try testing.expect(s.closed_for_gc);
    try testing.expectEqual(@as(u8, 0), s.send.retransmit_count);
    try testing.expect(!s.send.hasUnackedData());

    // Queue disposal and drain — stream fully removed, no leaks
    const sid = s.stream_id;
    sm.queueDisposal(sid);
    sm.drainDisposalQueue();
    try testing.expect(sm.streams.get(sid) == null);
}
