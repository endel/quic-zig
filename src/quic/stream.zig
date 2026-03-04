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

    /// Push received data at the given offset.
    pub fn push(self: *FrameSorter, offset: u64, data: []const u8, fin: bool) !void {
        if (fin) {
            self.fin_offset = offset + data.len;
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

/// A QUIC receive stream.
pub const ReceiveStream = struct {
    stream_id: u64,
    sorter: FrameSorter,

    /// Final offset (set when FIN received).
    fin_received: bool = false,

    /// Error code from RESET_STREAM.
    reset_err: ?u64 = null,

    /// Whether all data has been read.
    finished: bool = false,

    pub fn init(allocator: Allocator, stream_id: u64) ReceiveStream {
        return .{
            .stream_id = stream_id,
            .sorter = FrameSorter.init(allocator),
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
    pub fn handleResetStream(self: *ReceiveStream, error_code: u64, final_size: u64) void {
        self.reset_err = error_code;
        self.sorter.fin_offset = final_size;
    }

    /// Read contiguous data from the stream.
    /// Returns the data slice or null if no data is available.
    pub fn read(self: *ReceiveStream) ?[]const u8 {
        if (self.reset_err != null) return null;

        const data = self.sorter.pop();
        if (data == null and self.sorter.isComplete()) {
            self.finished = true;
        }
        return data;
    }
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

    /// Whether FIN has been queued.
    fin_queued: bool = false,

    /// Whether FIN has been sent.
    fin_sent: bool = false,

    /// Whether the stream has been reset.
    reset_err: ?u64 = null,

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

    /// Check if there's data available to send.
    pub fn hasData(self: *const SendStream) bool {
        return self.send_offset < self.write_offset or
            (self.fin_queued and !self.fin_sent);
    }

    /// Pop a STREAM frame with at most max_len bytes of payload.
    /// Returns null if there's nothing to send.
    pub fn popStreamFrame(self: *SendStream, max_len: u64) ?Frame {
        if (self.reset_err != null) return null;

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
        const data = if (data_len > 0) buffered[unsent_start..][0..data_len] else &[_]u8{};
        const fin = self.fin_queued and !self.fin_sent and (unsent_start + data_len == self.write_offset);

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
};

/// A bidirectional QUIC stream combining send and receive.
pub const Stream = struct {
    stream_id: u64,
    send: SendStream,
    recv: ReceiveStream,

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

    /// Set the maximum incoming stream limits (our advertised limits).
    pub fn setMaxIncomingStreams(self: *StreamsMap, max_bidi: u64, max_uni: u64) void {
        self.max_incoming_bidi_streams = max_bidi;
        self.max_incoming_uni_streams = max_uni;
    }

    /// Open a new bidirectional stream. Returns error if stream limit reached.
    pub fn openBidiStream(self: *StreamsMap) !*Stream {
        if (self.open_bidi_streams >= self.max_bidi_streams) {
            return error.StreamLimitError;
        }

        const id = self.next_bidi_stream_id;
        self.next_bidi_stream_id += 4;
        self.open_bidi_streams += 1;

        const s = try self.allocator.create(Stream);
        s.* = Stream.init(self.allocator, id);
        try self.streams.put(id, s);
        return s;
    }

    /// Open a new unidirectional send stream. Returns error if stream limit reached.
    pub fn openUniStream(self: *StreamsMap) !*SendStream {
        if (self.open_uni_streams >= self.max_uni_streams) {
            return error.StreamLimitError;
        }

        const id = self.next_uni_stream_id;
        self.next_uni_stream_id += 4;
        self.open_uni_streams += 1;

        const s = try self.allocator.create(SendStream);
        s.* = SendStream.init(self.allocator, id);
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
        s.* = ReceiveStream.init(self.allocator, stream_id);
        try self.recv_streams.put(stream_id, s);
        self.open_uni_streams += 1;
        return s;
    }

    /// Get a stream by ID.
    pub fn getStream(self: *StreamsMap, stream_id: u64) ?*Stream {
        return self.streams.get(stream_id);
    }

    /// Mark a stream as fully closed and update consumed counters.
    /// Only counts peer-initiated streams (those count against our MAX_STREAMS limit).
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

        // Bidi: send update when consumed >= half of current max
        if (self.max_incoming_bidi_streams > 0) {
            const threshold = self.max_incoming_bidi_streams / 2;
            if (self.consumed_bidi_streams >= threshold) {
                const new_max = self.consumed_bidi_streams + self.max_incoming_bidi_streams;
                if (new_max > self.last_sent_max_bidi) {
                    result.bidi = new_max;
                    self.last_sent_max_bidi = new_max;
                    // Update our internal limit to allow the new streams
                    self.max_incoming_bidi_streams = new_max;
                    // Reset consumed so window slides
                    self.consumed_bidi_streams = 0;
                }
            }
        }

        // Uni: same sliding window
        if (self.max_incoming_uni_streams > 0) {
            const threshold = self.max_incoming_uni_streams / 2;
            if (self.consumed_uni_streams >= threshold) {
                const new_max = self.consumed_uni_streams + self.max_incoming_uni_streams;
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

    // Consume 4 streams (< half of 10), no update should be sent
    sm.consumed_bidi_streams = 4;
    sm.consumed_uni_streams = 4;

    const update = sm.getMaxStreamsUpdates();
    try testing.expect(update.bidi == null);
    try testing.expect(update.uni == null);
}

test "StreamsMap: getMaxStreamsUpdates triggers at threshold" {
    var sm = StreamsMap.init(testing.allocator, true);
    defer sm.deinit();

    sm.setMaxIncomingStreams(10, 10);

    // Consume 5 streams (= half of 10), update should trigger
    sm.consumed_bidi_streams = 5;

    const update = sm.getMaxStreamsUpdates();
    // New max = consumed(5) + max_incoming(10) = 15
    try testing.expectEqual(@as(u64, 15), update.bidi.?);
    try testing.expect(update.uni == null);

    // consumed should be reset after update
    try testing.expectEqual(@as(u64, 0), sm.consumed_bidi_streams);
    // max_incoming should be updated
    try testing.expectEqual(@as(u64, 15), sm.max_incoming_bidi_streams);
    // last_sent tracked
    try testing.expectEqual(@as(u64, 15), sm.last_sent_max_bidi);
}

test "StreamsMap: getMaxStreamsUpdates sliding window advances" {
    var sm = StreamsMap.init(testing.allocator, true);
    defer sm.deinit();

    sm.setMaxIncomingStreams(4, 4);

    // First round: consume 2 (>= 4/2=2)
    sm.consumed_bidi_streams = 2;
    const upd1 = sm.getMaxStreamsUpdates();
    try testing.expectEqual(@as(u64, 6), upd1.bidi.?); // 2 + 4 = 6

    // After first update: max_incoming=6, consumed=0
    // Second round: consume 3 (>= 6/2=3)
    sm.consumed_bidi_streams = 3;
    const upd2 = sm.getMaxStreamsUpdates();
    try testing.expectEqual(@as(u64, 9), upd2.bidi.?); // 3 + 6 = 9

    // No redundant update if consumed hasn't reached threshold
    sm.consumed_bidi_streams = 1;
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
