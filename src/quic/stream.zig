const std = @import("std");
const Allocator = std.mem.Allocator;
const testing = std.testing;

const flow_control = @import("flow_control.zig");
const Frame = @import("frame.zig").Frame;
const limits = @import("limits.zig");
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
    /// One buffered run of stream bytes.
    pub const Chunk = struct {
        offset: u64,
        data: []const u8,
        /// The allocation behind `data` when it has room to grow at either
        /// end; empty when it is exactly `data`.
        buf: []u8 = &.{},

        fn end(self: Chunk) u64 {
            return self.offset + self.data.len;
        }

        fn allocation(self: Chunk) []u8 {
            return if (self.buf.len > 0) self.buf else @constCast(self.data);
        }

        /// Room in front of `data`.
        fn head(self: Chunk) usize {
            return @intFromPtr(self.data.ptr) - @intFromPtr(self.allocation().ptr);
        }
    };

    /// A piece that abuts a neighbouring chunk is merged into it up to this
    /// size instead of kept on its own. Unread contiguous data — a paused
    /// consumer, a window's worth in flight, reordered or not — then costs a
    /// handful of chunks rather than one per frame: adjacent chunks always
    /// sum past it, so a contiguous run of n bytes holds at most
    /// 2n / MAX_COALESCED + 1 chunks.
    const MAX_COALESCED: usize = 64 * 1024;

    allocator: Allocator,

    /// Buffered data chunks, sorted ascending by offset and never overlapping.
    /// Sorted order is what keeps overlap resolution to a binary-search probe
    /// of the neighbouring run; a hash map has to scan every chunk instead,
    /// which goes quadratic under the reordering of RFC 9000 21.7.
    chunks: std.ArrayList(Chunk),

    /// Next offset to be read by the application.
    read_pos: u64 = 0,

    /// The final offset (set when FIN is received).
    fin_offset: ?u64 = null,

    /// Highest byte offset ever buffered. Maintained incrementally to avoid
    /// scanning all chunks on every push().
    highest_buffered: u64 = 0,

    /// Neighbouring chunks that do not abut: the holes between them. The
    /// reassembly cap is on holes, not chunks, since contiguous data costs
    /// chunks too (see MAX_COALESCED).
    breaks: usize = 0,

    pub fn init(allocator: Allocator) FrameSorter {
        return .{
            .allocator = allocator,
            .chunks = .{ .items = &.{}, .capacity = 0 },
        };
    }

    pub fn deinit(self: *FrameSorter) void {
        for (self.chunks.items) |c| self.allocator.free(c.allocation());
        self.chunks.deinit(self.allocator);
    }

    /// Index of the first chunk ending after `pos`, or `items.len` if none is.
    fn lowerBound(self: *const FrameSorter, pos: u64) usize {
        var lo: usize = 0;
        var hi: usize = self.chunks.items.len;
        while (lo < hi) {
            const mid = lo + (hi - lo) / 2;
            if (self.chunks.items[mid].end() <= pos) lo = mid + 1 else hi = mid;
        }
        return lo;
    }

    /// Holes in the buffered data: between chunks, plus the one in front of
    /// the first chunk when it starts past `read_pos`.
    pub fn holes(self: *const FrameSorter) usize {
        const items = self.chunks.items;
        return self.breaks + @intFromBool(items.len > 0 and items[0].offset > self.read_pos);
    }

    /// RFC 9000 21.7: a peer that withholds every other byte pins one chunk
    /// per hole, so the tracking structure needs a ceiling of its own.
    fn checkHoles(self: *const FrameSorter) error{TooManyChunks}!void {
        if (self.holes() > limits.max_reassembly_chunks) return error.TooManyChunks;
    }

    /// Chunks are non-empty, sorted, disjoint, at or past `read_pos`, and
    /// `breaks` matches a full recount. For tests and the fuzzer.
    pub fn isConsistent(self: *const FrameSorter) bool {
        const items = self.chunks.items;
        var n: usize = 0;
        for (items, 0..) |c, k| {
            if (c.data.len == 0 or c.offset < self.read_pos) return false;
            if (c.end() > self.highest_buffered) return false;
            if (k > 0) {
                if (items[k - 1].end() > c.offset) return false;
                if (items[k - 1].end() != c.offset) n += 1;
            }
        }
        return n == self.breaks;
    }

    /// Breaks between chunks from `from` through the last chunk starting at or
    /// before `upto`.
    fn breaksIn(self: *const FrameSorter, from: usize, upto: u64) usize {
        const items = self.chunks.items;
        var n: usize = 0;
        var m = from + 1;
        while (m < items.len and items[m].offset <= upto) : (m += 1) {
            if (items[m - 1].end() != items[m].offset) n += 1;
        }
        return n;
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
            effective_data = data[@intCast(skip)..];
            effective_offset = self.read_pos;
        }

        // Fast path for the dominant receive case: new STREAM data appends at
        // or beyond the highest byte ever buffered. It cannot overlap an
        // existing chunk, and sorts after every one already held.
        if (effective_offset >= self.highest_buffered) {
            var gap = false;
            if (self.chunks.items.len > 0) {
                const last = &self.chunks.items[self.chunks.items.len - 1];
                if (last.end() == effective_offset and last.data.len + effective_data.len <= MAX_COALESCED) {
                    try self.growChunk(last, effective_data);
                    self.highest_buffered = last.end();
                    return;
                }
                gap = last.end() != effective_offset;
            }
            if (gap) try self.checkHolesPlusOne();
            const owned = try self.allocator.dupe(u8, effective_data);
            errdefer self.allocator.free(owned);
            try self.chunks.append(self.allocator, .{ .offset = effective_offset, .data = owned });
            self.highest_buffered = effective_offset + owned.len;
            if (gap) self.breaks += 1;
            return;
        }

        // Chunks are sorted and disjoint, so only the run starting at the first
        // chunk ending past us can overlap this data.
        const new_end = effective_offset + effective_data.len;
        var i = self.lowerBound(effective_offset);

        // Everything this push can change lies between the chunk before the
        // overlap and the first one starting past it; recount breaks there.
        const span_lo: u64 = if (i > 0) self.chunks.items[i - 1].offset else effective_offset;
        const span_hi: u64 = blk: {
            var k = i;
            while (k < self.chunks.items.len and self.chunks.items[k].offset <= new_end) k += 1;
            break :blk if (k < self.chunks.items.len) self.chunks.items[k].offset else std.math.maxInt(u64);
        };
        const breaks_before = self.breaksIn(self.lowerBound(span_lo), span_hi);

        while (i < self.chunks.items.len and self.chunks.items[i].offset < new_end) {
            const existing = self.chunks.items[i];

            // Already held in full.
            if (existing.offset <= effective_offset and existing.end() >= new_end) return;

            // Existing covers our front: keep it, advance past it.
            if (existing.offset <= effective_offset and existing.end() > effective_offset) {
                const skip: usize = @intCast(existing.end() - effective_offset);
                effective_offset = existing.end();
                effective_data = effective_data[skip..];
                if (effective_data.len == 0) return;
                i += 1;
                continue;
            }

            // Existing covers our tail: keep it, and only our part before it.
            // Cutting ours costs nothing; cutting it would copy up to a whole
            // chunk per frame.
            if (existing.offset < new_end and existing.end() > new_end) {
                effective_data = effective_data[0..@intCast(existing.offset - effective_offset)];
                break;
            }

            // Existing lies wholly inside the new data.
            self.allocator.free(existing.allocation());
            _ = self.chunks.orderedRemove(i);
        }

        const inserted = self.insertMerged(i, effective_offset, effective_data);

        // Recount even on failure: a merge can fail halfway, after its first
        // half landed.
        const end_offset = effective_offset + effective_data.len;
        if (end_offset > self.highest_buffered) self.highest_buffered = end_offset;
        self.breaks = self.breaks - breaks_before + self.breaksIn(self.lowerBound(span_lo), span_hi);
        try inserted;
        // Past the cap the data stays buffered; the error closes the connection.
        try self.checkHoles();
    }

    fn checkHolesPlusOne(self: *const FrameSorter) error{TooManyChunks}!void {
        if (self.holes() + 1 > limits.max_reassembly_chunks) return error.TooManyChunks;
    }

    /// Insert `data` at index `i`, merging it into whichever neighbours it
    /// abuts while the result stays within MAX_COALESCED. Filling a hole
    /// joins the runs on both sides, so the chunk count tracks real holes
    /// rather than the order frames happened to arrive in.
    ///
    /// The smaller side is copied into the larger, which grows at either end,
    /// so a merge costs about what it adds: a hole filled a byte at a time
    /// from the back does not recopy the chunk behind it for each byte.
    fn insertMerged(self: *FrameSorter, i: usize, offset: u64, data: []const u8) !void {
        const items = self.chunks.items;
        const end = offset + data.len;
        const prev: ?*Chunk = if (i > 0 and items[i - 1].end() == offset and
            items[i - 1].data.len + data.len <= MAX_COALESCED) &items[i - 1] else null;
        const next: ?*Chunk = if (i < items.len and items[i].offset == end) &items[i] else null;

        if (prev) |p| {
            const n = next orelse return self.growChunk(p, data);
            if (p.data.len + data.len + n.data.len > MAX_COALESCED) return self.growChunk(p, data);
            if (p.data.len >= n.data.len) {
                try self.growChunk(p, data);
                try self.growChunk(p, n.data);
                self.allocator.free(n.allocation());
                _ = self.chunks.orderedRemove(i);
            } else {
                try self.prependChunk(n, data);
                try self.prependChunk(n, p.data);
                self.allocator.free(p.allocation());
                _ = self.chunks.orderedRemove(i - 1);
            }
            return;
        }
        if (next) |n| {
            if (data.len + n.data.len <= MAX_COALESCED) return self.prependChunk(n, data);
        }
        const owned = try self.allocator.dupe(u8, data);
        errdefer self.allocator.free(owned);
        try self.chunks.insert(self.allocator, i, .{ .offset = offset, .data = owned });
    }

    /// Append `bytes` to `c`, doubling its allocation as needed.
    fn growChunk(self: *FrameSorter, c: *Chunk, bytes: []const u8) !void {
        const head = c.head();
        const len = c.data.len;
        const need = head + len + bytes.len;
        var buf = c.allocation();
        if (need > buf.len) {
            const new_cap = @min(@max(need, buf.len * 2), head + MAX_COALESCED);
            buf = try self.allocator.realloc(buf, new_cap);
        }
        @memcpy(buf[head + len .. need], bytes);
        c.data = buf[head..need];
        c.buf = buf;
    }

    /// Put `bytes` in front of `c`, doubling the room there as needed.
    fn prependChunk(self: *FrameSorter, c: *Chunk, bytes: []const u8) !void {
        const head = c.head();
        const len = c.data.len;
        var buf = c.allocation();
        var start: usize = undefined;
        if (bytes.len <= head) {
            start = head - bytes.len;
        } else {
            const total = bytes.len + len;
            const size = @min(2 * total, MAX_COALESCED);
            const grown = try self.allocator.alloc(u8, size);
            start = size - total;
            @memcpy(grown[start + bytes.len ..][0..len], c.data);
            self.allocator.free(buf);
            buf = grown;
        }
        @memcpy(buf[start..][0..bytes.len], bytes);
        c.offset -= bytes.len;
        c.data = buf[start..][0 .. bytes.len + len];
        c.buf = buf;
    }

    /// Pop the next contiguous chunk of data from the read position.
    /// Returns null if there's no data available at the current read position.
    pub fn pop(self: *FrameSorter) ?[]const u8 {
        if (self.chunks.items.len == 0) return null;

        // Sorted and disjoint: only the first chunk can hold read_pos, and one
        // starting past it means the gap in front is still open.
        const first = self.chunks.items[0];
        if (first.offset > self.read_pos or first.end() <= self.read_pos) return null;

        if (self.chunks.items.len > 1 and first.end() != self.chunks.items[1].offset) self.breaks -= 1;
        _ = self.chunks.orderedRemove(0);
        const skip: usize = @intCast(self.read_pos - first.offset);
        const readable = first.data[skip..];
        // The caller frees what we return, so it must be a whole allocation;
        // a chunk grown with room to spare is shrunk in place where it can be.
        const whole = skip == 0 and first.head() == 0 and
            (first.allocation().len == first.data.len or self.allocator.resize(first.allocation(), first.data.len));
        const owned = if (whole)
            first.data
        else blk: {
            const copy = self.allocator.dupe(u8, readable) catch {
                self.allocator.free(first.allocation());
                return null;
            };
            self.allocator.free(first.allocation());
            break :blk copy;
        };
        self.read_pos += readable.len;
        return owned;
    }

    /// Check if all data has been received (FIN reached and all data consumed).
    /// Every byte up to the final size has arrived, read or not.
    pub fn isFullyReceived(self: *const FrameSorter) bool {
        const fin = self.fin_offset orelse return false;
        return self.holes() == 0 and self.highestReceived() >= fin;
    }

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

    /// Set once the consumer has been handed the FIN and will not read again.
    /// Reclamation waits on this rather than on `finished`: the protocol layers
    /// keep per-stream state keyed by ID (H3 critical streams, WT buffers) and
    /// `finished` flips inside their own read, before they have delivered it.
    released: bool = false,

    /// Already on the disposal queue — keeps releaseRecvStream() idempotent.
    disposal_queued: bool = false,

    /// FIN has been counted against the MAX_STREAMS window. A retransmitted
    /// FIN must not count a second time.
    closed_counted: bool = false,

    /// Receive-side flow control. `receive_window` is the highest offset we
    /// have allowed the peer (RFC 9000 4.1) and is enforced on every frame;
    /// `receive_window_size` is the increment MAX_STREAM_DATA re-grants as
    /// data is read, zero for a stream nothing configured, which never
    /// re-grants.
    bytes_read: u64 = 0,
    receive_window: u64 = std.math.maxInt(u64),
    receive_window_size: u64 = 0,

    /// Bytes a consumer has read out but still holds in a buffer of its own
    /// (an HTTP/3 frame not yet taken by the application). Flow control
    /// credits only what was read and then let go, so the peer is held to a
    /// window of what the application actually took.
    retained: u64 = 0,

    /// Connection-level flow control (RFC 9000 4.1): the highest offset, or
    /// final size, this stream has charged against MAX_DATA, and how much of
    /// that has been handed back as consumed or abandoned.
    conn_counted: u64 = 0,
    conn_credited: u64 = 0,

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
        if (offset + data.len > self.receive_window) return error.FlowControlError;
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
        if (final_size > self.receive_window) return error.FlowControlError;

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

    /// The peer can send nothing more: the FIN and every byte before it have
    /// arrived. A FIN alone is not enough while a hole before it is open —
    /// the retransmission filling it still has to find the stream.
    pub fn allReceived(self: *const ReceiveStream) bool {
        return self.finished or (self.reset_err == null and self.sorter.isFullyReceived());
    }

    /// Bytes the consumer has read and let go of.
    pub fn consumed(self: *const ReceiveStream) u64 {
        return self.bytes_read -| self.retained;
    }

    /// Connection credit newly earned since the last call: what the consumer
    /// has read, or everything charged once the peer has reset the stream
    /// (its unread data will never be read).
    pub fn takeConnCredit(self: *ReceiveStream) u64 {
        const upto = if (self.reset_err != null) self.conn_counted else @min(self.consumed(), self.conn_counted);
        if (upto <= self.conn_credited) return 0;
        const n = upto - self.conn_credited;
        self.conn_credited = upto;
        return n;
    }

    /// Connection credit still held by this stream, returned when it is freed.
    fn connCreditLeft(self: *const ReceiveStream) u64 {
        return self.conn_counted -| self.conn_credited;
    }

    /// Check if a MAX_STREAM_DATA update should be sent.
    /// Returns the new window offset, or null if no update needed.
    pub fn getWindowUpdate(self: *ReceiveStream) ?u64 {
        if (self.receive_window_size == 0) return null; // no flow control configured
        if (self.fin_received) return null; // no point updating after FIN

        // Send update when consumed portion exceeds threshold
        const threshold = self.receive_window_size / STREAM_WINDOW_UPDATE_FRACTION;
        if (self.consumed() + threshold > self.receive_window) {
            const new_window = self.consumed() + self.receive_window_size;
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

    /// Nothing more will ever be delivered from this stream: the FIN has been
    /// read out or the peer reset it. There is no send side to wait for an ACK
    /// on, so this is the whole condition for reclaiming it.
    pub fn isDisposable(self: *const ReceiveStream) bool {
        // `finished` only flips inside read(); a consumer that noticed the FIN
        // via the sorter is just as done, so check the sorter too.
        return self.released and
            (self.finished or self.reset_err != null or self.sorter.isComplete());
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

/// Stream bytes committed against the peer's MAX_DATA: everything written to
/// any stream, less what a reset abandoned unsent. That is what connection
/// credit will have been spent on once the buffers drain, so it says how far
/// ahead of the credit an application is before any of it goes out.
///
/// Shared by pointer because `writeData` is reached without the map, and
/// heap-allocated so the pointer survives a move of the owning connection.
pub const SendLedger = struct {
    committed: u64 = 0,
};

/// A QUIC send stream.
pub const SendStream = struct {
    stream_id: u64,
    allocator: Allocator,

    /// Data buffered for sending. Indexed relative to `buf_base`, not by
    /// absolute stream offset — use bufferedAt().
    write_buffer: std.ArrayList(u8),

    /// Stream offset of `write_buffer.items[0]`. Bytes below it were
    /// acknowledged and dropped; no send path can ask for them again.
    buf_base: u64 = 0,

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

    /// Set when an ACK covered the frame that carried our FIN. The FIN is not a
    /// byte, so `ack_offset` never reaches past the last one and cannot say this.
    fin_acked: bool = false,

    /// Whether FIN has been sent.
    fin_sent: bool = false,

    /// Whether the stream has been reset.
    reset_err: ?u64 = null,

    /// Code from a STOP_SENDING the peer sent us. `reset_err` is also set so the
    /// send side stops, but that field carries local intent too — only this one
    /// says the peer asked. WebTransport reports it as a distinct event.
    peer_stop_sending: ?u64 = null,

    /// The connection's; null for a stream built outside a StreamsMap.
    ledger: ?*SendLedger = null,

    /// Whether a RESET_STREAM frame has been queued for sending.
    reset_stream_sent: bool = false,

    /// Never reclaimed, whatever its state. For streams a protocol layer
    /// writes through a pointer it keeps for the whole connection: H3's
    /// control and QPACK streams, which a peer's STOP_SENDING would otherwise
    /// reset and free out from under it.
    pinned: bool = false,

    /// Already on the disposal queue; see `Stream.disposal_queued`.
    disposal_queued: bool = false,

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

    /// Write data to the stream. Buffers it for later sending. Dropped once the
    /// stream is reset: RFC 9000 §3.1 lets nothing follow RESET_STREAM.
    pub fn writeData(self: *SendStream, data: []const u8) !void {
        if (self.reset_err != null) return;
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
        if (self.ledger) |l| l.committed += data.len;
    }

    /// Drop the acknowledged prefix once it is worth the memmove. Without this
    /// a stream holds every byte it ever sent until it closes, so one long
    /// transfer holds the whole transfer.
    const COMPACT_THRESHOLD: usize = 64 * 1024;

    fn compactAcked(self: *SendStream) void {
        const buffered = self.write_buffer.items.len;
        // Clamped: ack_offset should never pass write_offset, but the value
        // comes from a peer's ACK ranges and the subtraction below would
        // underflow rather than fail politely.
        const prefix: usize = @intCast(@min(self.ack_offset - self.buf_base, buffered));
        if (prefix < COMPACT_THRESHOLD) return;
        // Move no more than we discard, so the copying is amortised O(1) per
        // byte. A flat threshold alone is quadratic against an application that
        // writes ahead: an 8 MB write acked in 64 KB steps memmoves ~512 MB and
        // costs two thirds of bulk throughput.
        if (prefix < buffered - prefix) return;

        const items = self.write_buffer.items;
        if (prefix >= buffered) {
            self.write_buffer.clearRetainingCapacity();
        } else {
            std.mem.copyForwards(u8, items[0 .. buffered - prefix], items[prefix..]);
            self.write_buffer.items.len = buffered - prefix;
        }
        self.buf_base += prefix;
    }

    /// The buffered bytes at `offset`, at most `max_len` of them. Empty when
    /// the offset names data that has been acknowledged and dropped, or data
    /// the application has not written yet.
    fn bufferedAt(self: *const SendStream, offset: u64, max_len: u64) []const u8 {
        if (offset < self.buf_base) return &.{};
        const rel: usize = @intCast(offset - self.buf_base);
        const items = self.write_buffer.items;
        if (rel >= items.len) return &.{};
        return items[rel..][0..@intCast(@min(max_len, items.len - rel))];
    }

    /// Close the stream (queue FIN).
    pub fn close(self: *SendStream) void {
        self.fin_queued = true;
    }

    /// Update the acknowledged offset when a packet carrying stream frames is
    /// ACKed. `fin` is the flag the acked frame was sent with.
    pub fn onAck(self: *SendStream, offset: u64, length: u64, fin: bool) !void {
        if (fin) self.fin_acked = true;
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
        self.compactAcked();
    }

    /// Cancel the stream with an error code (sends RESET_STREAM).
    pub fn reset(self: *SendStream, error_code: u64) void {
        // The unsent tail will never spend connection credit: RESET_STREAM
        // names send_offset as the final size.
        if (self.reset_err == null) {
            if (self.ledger) |l| l.committed -= self.write_offset - self.send_offset;
        }
        self.reset_err = error_code;
    }

    /// Update the send window from a MAX_STREAM_DATA frame.
    pub fn updateSendWindow(self: *SendStream, new_max: u64) void {
        if (new_max > self.send_window) {
            self.send_window = new_max;
            self.blocked_at = null;
        }
    }

    /// Bytes MAX_STREAM_DATA still admits past what is already written. Zero
    /// once the stream is reset or its FIN is queued: nothing more can go.
    pub fn sendCredit(self: *const SendStream) u64 {
        if (self.reset_err != null or self.fin_queued) return 0;
        return self.send_window -| self.write_offset;
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
    pub fn queueRetransmit(self: *SendStream, offset_in: u64, length_in: u64, fin: bool) void {
        if (self.reset_err != null) return;

        // If FIN was in the lost packet, mark it for retransmission
        if (fin) {
            self.fin_lost = true;
            self.fin_sent = false; // Allow FIN to be re-sent
        }

        // Don't queue zero-length ranges (unless it was a FIN-only frame, handled above)
        if (length_in == 0) return;

        // A lost packet can carry bytes a later ACK already covered, and those
        // bytes are gone from the buffer. Resending them would be waste even if
        // they were still there.
        var offset = offset_in;
        var length = length_in;
        if (offset < self.ack_offset) {
            const skip = self.ack_offset - offset;
            if (skip >= length) return;
            offset += skip;
            length -= skip;
        }

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
        // RFC 9000 §3.1: nothing follows RESET_STREAM, so unsent bytes stay unsent.
        if (self.reset_err != null) return false;
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
        // RESET_STREAM supersedes the data: RFC 9000 3.1 forbids sending STREAM
        // frames after it, so unacked bytes are never coming back.
        if (self.reset_err != null) return false;
        return self.ack_offset < self.write_offset or
            (self.fin_queued and !self.fin_acked);
    }

    /// Whether one of our uni streams can be removed and freed: the peer has
    /// every byte and the FIN (RFC 9000 §3.1 "Data Recvd"), or RESET_STREAM is
    /// queued. A queued RESET_STREAM carries all of its own state, so the
    /// stream holds nothing a resend of it would need. Bidi streams also wait
    /// on their receive half; see `Stream.isDisposable`.
    pub fn isDisposable(self: *const SendStream) bool {
        if (self.pinned) return false;
        if (self.reset_err != null) return self.reset_stream_sent;
        return self.fin_acked and self.ack_offset >= self.write_offset;
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

        // Clamp to available buffer and max_len
        const available = self.bufferedAt(range.offset, range.length).len;
        // A retransmit range can only cover bytes already sent, which were
        // inside the window when they went out. Clamp anyway: a caller that
        // queues past send_offset would otherwise walk past MAX_STREAM_DATA,
        // since this path has no other window check.
        const window_remaining = if (self.send_window > range.offset)
            self.send_window - range.offset
        else
            0;
        const data_len = @min(available, max_len, window_remaining);

        if (data_len == 0 and !range.fin) {
            // Nothing useful to retransmit - remove this range
            self.removeRetransmitRange(0);
            return null;
        }

        // Save the original offset before modifying the range
        const frame_offset = range.offset;
        const data = self.bufferedAt(frame_offset, data_len);
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

        const data = self.bufferedAt(unsent_start, data_len);

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

    /// Set once the stream is on the disposal queue, so the ACK path and the
    /// collectClosedStreams backstop cannot enqueue it twice.
    disposal_queued: bool = false,

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

    /// Whether the stream can be removed from the map and freed.
    ///
    /// `closed_for_gc` only means both FINs have crossed. The FIN we sent may
    /// still be lost, and PTO recovers it by resetting `send_offset` — which it
    /// cannot do once the stream is gone. Nothing is left to recover only when
    /// every byte is acknowledged and no retransmit range is outstanding.
    pub fn isDisposable(self: *const Stream) bool {
        return self.closed_for_gc and
            self.send.retransmit_count == 0 and
            !self.send.hasUnackedData();
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

    /// Created with the first stream; see `SendLedger`.
    send_ledger: ?*SendLedger = null,

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

    /// Local receive window limits (our advertised limits, enforced on
    /// receipt and re-granted by MAX_STREAM_DATA). `Connection` sets them from
    /// `ConnectionConfig`; the defaults match its defaults.
    local_max_stream_data_bidi_local: u64 = 6_291_456,
    local_max_stream_data_bidi_remote: u64 = 6_291_456,
    local_max_stream_data_uni: u64 = 1_048_576,

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

    /// Set when the queue was full and a settled stream could not be enqueued.
    /// The next drain re-arms the scan to pick it up; without that the scan
    /// would either stop and strand it, or never stop and cost O(n) per send.
    disposal_overflow: bool = false,

    /// Same, for receive streams. They need their own flag because nothing
    /// re-offers them: `collectClosedStreams` scans only bidi streams, and a
    /// released receive stream is released exactly once.
    recv_disposal_overflow: bool = false,

    /// Same, for our uni streams: nothing offers one again once its last ACK
    /// or its RESET_STREAM has gone by.
    send_disposal_overflow: bool = false,

    /// Every peer-initiated bidi ID below this has been opened. RFC 9000 §3.2:
    /// using a stream ID implicitly opens every lower one of the same type, so
    /// an ID under the watermark that is absent from the map was opened and
    /// reclaimed — not one we have yet to hear about.
    next_peer_bidi_to_open: u64,

    /// Highest peer-initiated bidi stream ID that has been opened.
    /// Upper layers (WT/H3) compare this with their own "next to examine"
    /// counter to discover new streams in O(1) — same pattern as quic-go's
    /// nextStreamToAccept / nextStreamToOpen.
    highest_peer_bidi_stream_id: ?u64 = null,

    /// The uni counterparts of the two fields above. Reclaimed receive streams
    /// make the same watermark necessary: without it a retransmitted STREAM
    /// frame would rebuild a stream nothing will ever read.
    next_peer_uni_to_open: u64,
    highest_peer_uni_stream_id: ?u64 = null,

    /// Flag: set when a stream's FIN is received or sent, indicating that
    /// collectClosedStreams() needs to scan. Cleared after scan completes.
    /// Avoids O(n) scan on every send() when no streams are closing.
    needs_gc_scan: bool = false,

    /// Connection credit held by receive streams that have since been freed.
    freed_conn_credit: u64 = 0,

    pub fn init(allocator: Allocator, is_server: bool) StreamsMap {
        // Stream IDs: client bidi = 0, 4, 8, ...; server bidi = 1, 5, 9, ...
        // Client uni = 2, 6, 10, ...; server uni = 3, 7, 11, ...
        const bidi_base: u64 = if (is_server) 1 else 0;
        const uni_base: u64 = if (is_server) 3 else 2;
        // Peer-initiated IDs are the other parity from our own.
        const peer_bidi_base: u64 = if (is_server) 0 else 1;
        const peer_uni_base: u64 = if (is_server) 2 else 3;

        return .{
            .allocator = allocator,
            .is_server = is_server,
            .streams = std.AutoHashMap(u64, *Stream).init(allocator),
            .send_streams = std.AutoHashMap(u64, *SendStream).init(allocator),
            .recv_streams = std.AutoHashMap(u64, *ReceiveStream).init(allocator),
            .next_bidi_stream_id = bidi_base,
            .next_peer_bidi_to_open = peer_bidi_base,
            .next_uni_stream_id = uni_base,
            .next_peer_uni_to_open = peer_uni_base,
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

        if (self.send_ledger) |l| self.allocator.destroy(l);
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

        const ledger = try self.sendLedger();
        const id = self.next_bidi_stream_id;
        self.next_bidi_stream_id += 4;
        self.open_bidi_streams += 1;

        const s = try self.allocator.create(Stream);
        s.* = Stream.init(self.allocator, id);
        s.send.ledger = ledger;
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

        const ledger = try self.sendLedger();
        const id = self.next_uni_stream_id;
        self.next_uni_stream_id += 4;
        self.open_uni_streams += 1;

        const s = try self.allocator.create(SendStream);
        s.* = SendStream.init(self.allocator, id);
        s.ledger = ledger;
        s.send_window = self.peer_initial_max_stream_data_uni;
        try self.send_streams.put(id, s);
        return s;
    }

    /// Get or create a stream from an incoming STREAM frame.
    pub fn getOrCreateStream(self: *StreamsMap, stream_id: u64) !*Stream {
        if (self.streams.get(stream_id)) |existing| {
            return existing;
        }

        if (isLocal(stream_id, self.is_server)) {
            // Below the watermark: ours, reclaimed, and the peer is retransmitting.
            return if (self.localNeverOpened(stream_id)) error.StreamStateError else error.StreamAlreadyClosed;
        }

        if (!isBidi(stream_id)) {
            return error.StreamStateError; // Uni streams should use recv_streams
        }

        // Below the watermark it was opened once and has since been reclaimed —
        // the peer is retransmitting data we acked just before it went away.
        // Building it again would leave a stream nothing will ever close and
        // count its close a second time against MAX_STREAMS.
        if (stream_id < self.next_peer_bidi_to_open) return error.StreamAlreadyClosed;

        // RFC 9000 §3.2: using a stream ID opens every lower one of the same
        // type. Materialising them is what makes the watermark above exact.
        // Bounded by the MAX_STREAMS credit we granted, which the caller checks
        // before we get here.
        var id = self.next_peer_bidi_to_open;
        while (id < stream_id) : (id += 4) _ = try self.openPeerBidiStream(id);
        self.next_peer_bidi_to_open = stream_id + 4;
        return try self.openPeerBidiStream(stream_id);
    }

    /// Build one peer-initiated bidi stream and add it to the map.
    fn openPeerBidiStream(self: *StreamsMap, stream_id: u64) !*Stream {
        const ledger = try self.sendLedger();
        const s = try self.allocator.create(Stream);
        s.* = Stream.init(self.allocator, stream_id);
        s.send.ledger = ledger;
        // Peer initiated this stream → peer's "bidi_local" limit applies to our sends
        s.send.send_window = self.peer_initial_max_stream_data_bidi_local;
        // Our local receive window for peer-initiated streams
        s.recv.receive_window = self.local_max_stream_data_bidi_remote;
        s.recv.receive_window_size = self.local_max_stream_data_bidi_remote;
        errdefer {
            s.deinit();
            self.allocator.destroy(s);
        }
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

        // Below the watermark it was opened once and has since been reclaimed —
        // the peer is retransmitting data the consumer already took. Rebuilding
        // it would leave a stream nothing reads and count its FIN twice.
        if (stream_id < self.next_peer_uni_to_open) return error.StreamAlreadyClosed;

        // RFC 9000 §3.2: using a stream ID opens every lower one of the same
        // type. Materialising them is what makes the watermark above exact.
        var id = self.next_peer_uni_to_open;
        while (id < stream_id) : (id += 4) _ = try self.openPeerUniStream(id);
        self.next_peer_uni_to_open = stream_id + 4;
        return try self.openPeerUniStream(stream_id);
    }

    /// Build one peer-initiated receive stream and add it to the map.
    fn openPeerUniStream(self: *StreamsMap, stream_id: u64) !*ReceiveStream {
        const s = try self.allocator.create(ReceiveStream);
        s.* = ReceiveStream.initWithWindow(self.allocator, stream_id, self.local_max_stream_data_uni);
        errdefer {
            s.deinit();
            self.allocator.destroy(s);
        }
        try self.recv_streams.put(stream_id, s);
        self.open_uni_streams += 1;
        if (self.highest_peer_uni_stream_id == null or stream_id > self.highest_peer_uni_stream_id.?) {
            self.highest_peer_uni_stream_id = stream_id;
        }
        return s;
    }

    /// The consumer has taken this receive stream's FIN and will not read it
    /// again. Queues it for reclamation once it is settled. O(1) and idempotent.
    pub fn releaseRecvStream(self: *StreamsMap, stream_id: u64) void {
        const rs = self.recv_streams.get(stream_id) orelse return;
        rs.released = true;
        if (rs.disposal_queued or !rs.isDisposable()) return;
        rs.disposal_queued = self.queueDisposal(stream_id);
        // Nothing will call release again for this stream, so a dropped enqueue
        // would strand it. The next drain re-scans instead.
        if (!rs.disposal_queued) self.recv_disposal_overflow = true;
    }

    /// Get a stream by ID.
    pub fn getStream(self: *StreamsMap, stream_id: u64) ?*Stream {
        return self.streams.get(stream_id);
    }

    /// Whether a locally-initiated `stream_id` lies above every ID we have
    /// opened. RFC 9000 §19 makes a frame naming one a STREAM_STATE_ERROR. One
    /// below the watermark that is missing from the maps was opened and has
    /// since been reclaimed, and a frame for it is merely late.
    pub fn localNeverOpened(self: *const StreamsMap, stream_id: u64) bool {
        const next = if (isBidi(stream_id)) self.next_bidi_stream_id else self.next_uni_stream_id;
        return stream_id >= next;
    }

    /// The send half of any stream we can send on: a bidi stream, or our uni.
    pub fn getSendStream(self: *const StreamsMap, stream_id: u64) ?*SendStream {
        if (self.streams.get(stream_id)) |s| return &s.send;
        return self.send_streams.get(stream_id);
    }

    /// The receive half of any stream we can receive on: a bidi stream, or
    /// the peer's uni.
    pub fn getRecvStream(self: *const StreamsMap, stream_id: u64) ?*ReceiveStream {
        if (self.streams.get(stream_id)) |s| return &s.recv;
        return self.recv_streams.get(stream_id);
    }

    /// Bytes written to every stream that will spend connection credit.
    pub fn committedSendBytes(self: *const StreamsMap) u64 {
        const l = self.send_ledger orelse return 0;
        return l.committed;
    }

    fn sendLedger(self: *StreamsMap) !*SendLedger {
        if (self.send_ledger) |l| return l;
        const l = try self.allocator.create(SendLedger);
        l.* = .{};
        self.send_ledger = l;
        return l;
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
                    tmp[i] = urgency_buf[@intCast((i + rotation) % urgency_count)];
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

        // Mark fully-closed streams for consumed counting, and reclaim any whose
        // send side has settled since the last scan.
        var found_pending = false;
        var it = self.streams.iterator();
        while (it.next()) |kv| {
            const s = kv.value_ptr.*;
            if (!s.closed_for_gc and s.recv.allReceived() and s.send.fin_sent) {
                s.closed_for_gc = true;
                self.closeStream(s.stream_id);
            }
            // Backstop for the ACK-time path: that one reclaims in O(1) but
            // drops entries once the queue is full, and a stream can settle
            // without any further ACK arriving to trigger the check.
            self.disposeIfSettled(s);
            // Keep scanning only for streams a future scan could still act on.
            // One that is settled but could not be enqueued is covered by
            // `disposal_overflow` instead, so a caller that never drains does
            // not leave us scanning the whole map on every send.
            if (!s.disposal_queued and !s.isDisposable()) found_pending = true;
        }
        // Stop scanning once every remaining stream is on its way out.
        self.needs_gc_scan = found_pending;
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

    /// Queue a stream for removal if it is closed and fully acknowledged.
    /// O(1) and idempotent, so the ACK path can call it per acked STREAM frame.
    pub fn disposeIfSettled(self: *StreamsMap, s: *Stream) void {
        if (s.disposal_queued or !s.isDisposable()) return;
        s.disposal_queued = self.queueDisposal(s.stream_id);
    }

    /// The same for one of our uni streams. O(1) and idempotent.
    pub fn disposeUniIfSettled(self: *StreamsMap, ss: *SendStream) void {
        std.debug.assert(!isBidi(ss.stream_id));
        if (ss.disposal_queued or !ss.isDisposable()) return;
        ss.disposal_queued = self.queueDisposal(ss.stream_id);
        if (!ss.disposal_queued) self.send_disposal_overflow = true;
    }

    /// Connection credit (RFC 9000 4.1) earned across all receive streams
    /// since the last call: data consumed, streams reset, streams freed.
    pub fn takeConnCredit(self: *StreamsMap) u64 {
        var n = self.freed_conn_credit;
        self.freed_conn_credit = 0;
        var it = self.streams.valueIterator();
        while (it.next()) |s| n += s.*.recv.takeConnCredit();
        var recv_it = self.recv_streams.valueIterator();
        while (recv_it.next()) |rs| n += rs.*.takeConnCredit();
        return n;
    }

    /// Queue a stream for removal. O(1) — called when a stream is known to be
    /// fully closed (closed_for_gc set, no pending retransmissions).
    /// Returns false when the queue is full; the caller must try again later.
    pub fn queueDisposal(self: *StreamsMap, stream_id: u64) bool {
        if (self.disposal_count >= self.disposal_queue.len) {
            self.disposal_overflow = true;
            return false;
        }
        self.disposal_queue[self.disposal_count] = stream_id;
        self.disposal_count += 1;
        return true;
    }

    /// Drain the disposal queue: remove queued streams from the maps. O(k)
    /// where k = number of streams queued since last drain (typically 0-2).
    pub fn drainDisposalQueue(self: *StreamsMap) void {
        if (self.disposal_count == 0) return;
        for (self.disposal_queue[0..self.disposal_count]) |id| {
            if (self.streams.fetchRemove(id)) |kv| {
                var s = kv.value;
                self.freed_conn_credit += s.recv.connCreditLeft();
                s.deinit();
                self.allocator.destroy(s);
            }
            if (self.recv_streams.fetchRemove(id)) |kv| {
                var rs = kv.value;
                self.freed_conn_credit += rs.connCreditLeft();
                rs.deinit();
                self.allocator.destroy(rs);
            }
            if (self.send_streams.fetchRemove(id)) |kv| {
                var ss = kv.value;
                ss.deinit();
                self.allocator.destroy(ss);
                self.closeStream(id);
            }
        }
        self.disposal_count = 0;
        if (self.disposal_overflow) {
            self.disposal_overflow = false;
            self.needs_gc_scan = true; // there was more than the queue could hold
        }
        if (self.recv_disposal_overflow) self.recv_disposal_overflow = self.requeueSettled(&self.recv_streams);
        if (self.send_disposal_overflow) self.send_disposal_overflow = self.requeueSettled(&self.send_streams);
    }

    /// Offer the queue the settled streams of `map` that it turned away while
    /// full. Returns whether some still do not fit.
    fn requeueSettled(self: *StreamsMap, map: anytype) bool {
        var it = map.valueIterator();
        while (it.next()) |p| {
            const s = p.*;
            if (s.disposal_queued or !s.isDisposable()) continue;
            s.disposal_queued = self.queueDisposal(s.stream_id);
            if (!s.disposal_queued) return true;
        }
        return false;
    }

    /// Check if MAX_STREAMS updates should be sent (sliding window pattern).
    /// Returns new limits when consumed streams reach half the current max.
    pub const MaxStreamsUpdate = struct {
        bidi: ?u64 = null,
        uni: ?u64 = null,
    };

    /// Hand the peer the credit that closed streams have earned, ignoring the
    /// batching threshold. Returns the new limit, or null when there is none
    /// to give. This is what answers STREAMS_BLOCKED.
    pub fn flushMaxStreams(self: *StreamsMap, comptime bidi: bool) ?u64 {
        const max_incoming = if (bidi) &self.max_incoming_bidi_streams else &self.max_incoming_uni_streams;
        const consumed = if (bidi) &self.consumed_bidi_streams else &self.consumed_uni_streams;
        const last_sent = if (bidi) &self.last_sent_max_bidi else &self.last_sent_max_uni;

        if (max_incoming.* == 0 or consumed.* == 0) return null;
        const new_max = last_sent.* + consumed.*;
        if (new_max <= last_sent.*) return null;
        last_sent.* = new_max;
        max_incoming.* = new_max;
        consumed.* = 0;
        return new_max;
    }

    /// Whether the sliding window is due for a grant on its own initiative.
    /// Batching by a fixed fraction of the initial limit leaves the last
    /// partial batch ungranted, so a peer sitting at the limit gets it early.
    /// IDs go 0,4,8..., so id/4 counts them for either role.
    fn maxStreamsDue(self: *const StreamsMap, comptime bidi: bool) bool {
        const consumed = if (bidi) self.consumed_bidi_streams else self.consumed_uni_streams;
        if (consumed == 0) return false;

        const initial = if (bidi) self.initial_max_incoming_bidi else self.initial_max_incoming_uni;
        if (consumed >= @max(initial / 4, 1)) return true;

        const highest = if (bidi) self.highest_peer_bidi_stream_id else self.highest_peer_uni_stream_id;
        const max_incoming = if (bidi) self.max_incoming_bidi_streams else self.max_incoming_uni_streams;
        return if (highest) |id| (id / 4) + 1 >= max_incoming else false;
    }

    pub fn getMaxStreamsUpdates(self: *StreamsMap) MaxStreamsUpdate {
        return .{
            .bidi = if (self.maxStreamsDue(true)) self.flushMaxStreams(true) else null,
            .uni = if (self.maxStreamsDue(false)) self.flushMaxStreams(false) else null,
        };
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

    // In-order frames coalesce, so one pop returns both.
    const chunk = sorter.pop();
    try testing.expect(chunk != null);
    try testing.expectEqualStrings("hello world", chunk.?);
    testing.allocator.free(chunk.?);

    try testing.expect(sorter.pop() == null);
    try testing.expect(sorter.isComplete());
}

test "FrameSorter: out-of-order data" {
    var sorter = FrameSorter.init(testing.allocator);
    defer sorter.deinit();

    // Receive second chunk first
    try sorter.push(5, " world", false);

    // Nothing available yet (gap at offset 0)
    try testing.expect(sorter.pop() == null);

    // Receive first chunk: it fills the hole and joins the run after it.
    try sorter.push(0, "hello", false);

    const chunk = sorter.pop();
    try testing.expect(chunk != null);
    try testing.expectEqualStrings("hello world", chunk.?);
    testing.allocator.free(chunk.?);
    try testing.expect(sorter.pop() == null);
}

test "FrameSorter: sequential append fast path remains readable" {
    var sorter = FrameSorter.init(testing.allocator);
    defer sorter.deinit();

    try sorter.push(0, "hello", false);
    const first = sorter.pop().?;
    try testing.expectEqualStrings("hello", first);
    testing.allocator.free(first);

    try sorter.push(5, " ", false);
    try sorter.push(6, "world", true);
    const rest = sorter.pop().?;
    try testing.expectEqualStrings(" world", rest);
    testing.allocator.free(rest);

    try testing.expect(sorter.isComplete());
}

test "FrameSorter: out-of-order gap still accepts sequential tail" {
    var sorter = FrameSorter.init(testing.allocator);
    defer sorter.deinit();

    try sorter.push(6, "world", true);
    try sorter.push(0, "hello", false);
    try testing.expectEqual(@as(usize, 1), sorter.holes());
    try sorter.push(5, " ", false);
    try testing.expectEqual(@as(usize, 0), sorter.holes());

    const chunk = sorter.pop();
    try testing.expect(chunk != null);
    try testing.expectEqualStrings("hello world", chunk.?);
    testing.allocator.free(chunk.?);

    try testing.expect(sorter.pop() == null);
    try testing.expect(sorter.isComplete());
}

test "FrameSorter: heavy reordering reassembles in order" {
    var sorter = FrameSorter.init(testing.allocator);
    defer sorter.deinit();

    // Deliver single bytes back to front: every push lands below the
    // high-water mark, the path that used to scan the whole chunk map.
    const n: usize = 512;
    var i: usize = n;
    while (i > 0) {
        i -= 1;
        const b = [_]u8{@intCast(i % 251)};
        try sorter.push(@intCast(i), &b, false);
    }

    var out: [n]u8 = undefined;
    var got: usize = 0;
    while (sorter.pop()) |chunk| {
        @memcpy(out[got..][0..chunk.len], chunk);
        got += chunk.len;
        testing.allocator.free(chunk);
    }
    try testing.expectEqual(n, got);
    for (out, 0..) |v, k| try testing.expectEqual(@as(u8, @intCast(k % 251)), v);
}

test "FrameSorter: unread in-order data coalesces instead of hitting the gap cap" {
    var sorter = FrameSorter.init(testing.allocator);
    defer sorter.deinit();

    // A window's worth of small in-order frames nobody reads yet.
    const n: usize = 20 * limits.max_reassembly_chunks;
    var i: usize = 0;
    while (i < n) : (i += 1) {
        const b = [_]u8{ @intCast(i % 251), @intCast((i * 7) % 251) };
        try sorter.push(i * 2, &b, false);
    }
    try testing.expect(sorter.chunks.items.len <= n * 2 / FrameSorter.MAX_COALESCED + 1);

    var got: usize = 0;
    while (sorter.pop()) |chunk| {
        for (chunk, got..) |v, k| {
            const idx = k / 2;
            const want: u8 = if (k % 2 == 0) @intCast(idx % 251) else @intCast((idx * 7) % 251);
            try testing.expectEqual(want, v);
        }
        got += chunk.len;
        testing.allocator.free(chunk);
    }
    try testing.expectEqual(n * 2, got);
}

test "FrameSorter: filling holes from the back costs what it adds" {
    var counting = std.testing.FailingAllocator.init(testing.allocator, .{});
    var sorter = FrameSorter.init(counting.allocator());
    defer sorter.deinit();
    var pattern: [FrameSorter.MAX_COALESCED]u8 = undefined;
    for (&pattern, 0..) |*b, o| b.* = @intCast(o % 251);

    // A ladder of 1-byte holes in front of a large chunk, filled back to
    // front: each fill joins a rung to the chunk behind it.
    const rungs: usize = 500;
    const big = FrameSorter.MAX_COALESCED - 2 * rungs - 8;
    try sorter.push(2 * rungs, pattern[2 * rungs ..][0..big], false);
    for (0..rungs) |j| try sorter.push(2 * j, pattern[2 * j ..][0..1], false);
    var j: usize = rungs;
    while (j > 0) {
        j -= 1;
        try sorter.push(2 * j + 1, pattern[2 * j + 1 ..][0..1], false);
    }
    try testing.expectEqual(@as(usize, 0), sorter.holes());

    // Then a run a byte at a time, backwards, each in front of what came before.
    const run_start = 2 * rungs + big;
    const n: usize = 3 * FrameSorter.MAX_COALESCED;
    var k: usize = run_start + n;
    while (k > run_start + 1) {
        k -= 1;
        try sorter.push(k, &.{@intCast(k % 251)}, false);
    }
    try sorter.push(run_start, &.{@intCast(run_start % 251)}, false);

    // Copying the chunk for every byte would take gigabytes.
    try testing.expect(counting.allocated_bytes < 8 * (run_start + n));

    var got: usize = 0;
    while (sorter.pop()) |chunk| {
        for (chunk, got..) |v, o| try testing.expectEqual(@as(u8, @intCast(o % 251)), v);
        got += chunk.len;
        counting.allocator().free(chunk);
    }
    try testing.expectEqual(run_start + n, got);
}

test "FrameSorter: a paused stream under jittered reordering keeps only its real gaps" {
    var sorter = FrameSorter.init(testing.allocator);
    defer sorter.deinit();

    // Several MB of small frames nobody reads yet, each delayed by a random
    // jitter of up to 64 frame slots, the way netem jitter reorders a flow.
    const total: usize = 4 << 20;
    const Piece = struct { offset: usize, len: usize, arrival: usize };
    var frames: std.ArrayList(Piece) = .empty;
    defer frames.deinit(testing.allocator);

    var prng = std.Random.DefaultPrng.init(0x72656f72);
    const rand = prng.random();
    var off: usize = 0;
    var slot: usize = 0;
    while (off < total) : (slot += 1) {
        const len = @min(rand.intRangeAtMost(usize, 1, 1400), total - off);
        try frames.append(testing.allocator, .{ .offset = off, .len = len, .arrival = slot + rand.uintLessThan(usize, 64) });
        // Some go out twice, the copy re-cut the way a retransmission may be.
        if (rand.uintLessThan(u8, 16) == 0) {
            const lo = off -| rand.uintLessThan(usize, 700);
            const hi = @min(off + len + rand.uintLessThan(usize, 700), total);
            try frames.append(testing.allocator, .{ .offset = lo, .len = hi - lo, .arrival = slot + rand.uintLessThan(usize, 128) });
        }
        off += len;
    }
    std.mem.sort(Piece, frames.items, {}, struct {
        fn lt(_: void, a: Piece, b: Piece) bool {
            return a.arrival < b.arrival;
        }
    }.lt);

    var payload: [2800]u8 = undefined;
    for (frames.items) |f| {
        for (payload[0..f.len], f.offset..) |*b, o| b.* = @intCast(o % 251);
        try sorter.push(f.offset, payload[0..f.len], false);
    }
    try testing.expectEqual(@as(usize, 0), sorter.holes());
    try testing.expect(sorter.chunks.items.len <= 2 * total / FrameSorter.MAX_COALESCED + 1);

    var got: usize = 0;
    while (sorter.pop()) |chunk| {
        for (chunk, got..) |v, o| try testing.expectEqual(@as(u8, @intCast(o % 251)), v);
        got += chunk.len;
        testing.allocator.free(chunk);
    }
    try testing.expectEqual(total, got);
}

test "FrameSorter: random overlaps, holes and reads match the byte stream" {
    var prng = std.Random.DefaultPrng.init(0x686f6c65);
    const rand = prng.random();
    var payload: [300]u8 = undefined;

    var trial: usize = 0;
    while (trial < 400) : (trial += 1) {
        var sorter = FrameSorter.init(testing.allocator);
        defer sorter.deinit();
        const span: usize = rand.intRangeAtMost(usize, 64, 4096);

        var read: usize = 0;
        var step: usize = 0;
        while (step < 300) : (step += 1) {
            if (rand.uintLessThan(u8, 5) == 0) {
                if (sorter.pop()) |chunk| {
                    for (chunk, read..) |v, o| try testing.expectEqual(@as(u8, @intCast(o % 251)), v);
                    read += chunk.len;
                    testing.allocator.free(chunk);
                }
            } else {
                const off = rand.uintLessThan(usize, span);
                const len = rand.intRangeAtMost(usize, 1, payload.len);
                for (payload[0..len], off..) |*b, o| b.* = @intCast(o % 251);
                try sorter.push(off, payload[0..len], false);
            }
            try testing.expect(sorter.isConsistent());
        }
    }
}

// RFC 9000 §21.7: bound the reassembly tracking structure.
test "FrameSorter: rejects more gaps than the reassembly cap" {
    var sorter = FrameSorter.init(testing.allocator);
    defer sorter.deinit();

    // The hole at 0 keeps everything buffered; each run lands past the last.
    var i: u64 = 0;
    while (i < limits.max_reassembly_chunks) : (i += 1) {
        try sorter.push(i * 2 + 2, "x", false);
    }
    try testing.expectEqual(limits.max_reassembly_chunks, sorter.chunks.items.len);
    try testing.expectError(error.TooManyChunks, sorter.push(1_000_000, "x", false));
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

    try ss.onAck(0, 100, false);

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

    try ss.onAck(0, 32, false);

    try testing.expectEqual(@as(u8, 1), ss.retransmit_count);
    try testing.expectEqual(@as(u64, 32), ss.retransmit_ranges[0].offset);
    try testing.expectEqual(@as(u64, 48), ss.retransmit_ranges[0].length);

    try ss.onAck(32, 48, false);
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

// ── Stream disposal ────────────────────────────────────────────────────

test "collectClosedStreams: marks a stream once both FINs have crossed" {
    var sm = StreamsMap.init(testing.allocator, false);
    defer sm.deinit();
    sm.setMaxStreams(10, 10);

    const s = try sm.openBidiStream();
    try testing.expectEqual(@as(u64, 1), sm.open_bidi_streams);

    s.send.fin_sent = true;
    try s.recv.handleStreamFrame(0, "", true);

    sm.needs_gc_scan = true;
    sm.collectClosedStreams();

    try testing.expect(s.closed_for_gc);
    // Locally initiated, so the open count drops but nothing is consumed.
    try testing.expectEqual(@as(u64, 0), sm.open_bidi_streams);
    try testing.expectEqual(@as(u64, 0), sm.consumed_bidi_streams);
}

test "collectClosedStreams: a FIN ahead of a hole keeps the stream until the hole fills" {
    var sm = StreamsMap.init(testing.allocator, true);
    defer sm.deinit();
    sm.setMaxStreams(10, 10);

    const s = try sm.getOrCreateStream(0);
    s.send.fin_sent = true;
    try s.recv.handleStreamFrame(5, "world", true);
    try testing.expect(!s.recv.allReceived());

    sm.needs_gc_scan = true;
    sm.collectClosedStreams();
    sm.drainDisposalQueue();
    try testing.expect(!s.closed_for_gc);
    try testing.expect(sm.streams.get(0) != null);
    try testing.expectEqual(@as(u64, 0), sm.consumed_bidi_streams);

    try s.recv.handleStreamFrame(0, "hello", false);
    try testing.expect(s.recv.allReceived());
    sm.collectClosedStreams();
    try testing.expect(s.closed_for_gc);
    try testing.expectEqual(@as(u64, 1), sm.consumed_bidi_streams);

    var body: [10]u8 = undefined;
    var n: usize = 0;
    while (s.recv.read()) |d| {
        @memcpy(body[n..][0..d.len], d);
        n += d.len;
        testing.allocator.free(d);
    }
    try testing.expectEqualStrings("helloworld", body[0..n]);
}

test "collectClosedStreams: keeps an unacked stream for PTO" {
    var sm = StreamsMap.init(testing.allocator, false);
    defer sm.deinit();
    sm.setMaxStreams(10, 10);

    const s = try sm.openBidiStream();
    try s.send.writeData("x" ** 1000);
    s.send.send_offset = 1000;
    s.send.fin_sent = true;
    try s.recv.handleStreamFrame(0, "", true);

    sm.needs_gc_scan = true;
    sm.collectClosedStreams();
    sm.drainDisposalQueue();

    try testing.expect(s.closed_for_gc);
    try testing.expect(!s.isDisposable());
    try testing.expect(sm.streams.get(s.stream_id) != null);
}

test "disposeIfSettled: reclaims a closed stream once the last byte is acked" {
    var sm = StreamsMap.init(testing.allocator, false);
    defer sm.deinit();
    sm.setMaxStreams(10, 10);

    const s = try sm.openBidiStream();
    const sid = s.stream_id;
    try s.send.writeData("x" ** 100);
    s.send.send_offset = 100;
    s.send.fin_sent = true;
    try s.recv.handleStreamFrame(0, "", true);

    sm.needs_gc_scan = true;
    sm.collectClosedStreams();
    try testing.expect(s.closed_for_gc);

    // Before the ACK there is still data PTO could have to resend.
    sm.disposeIfSettled(s);
    sm.drainDisposalQueue();
    try testing.expect(sm.streams.get(sid) != null);

    try s.send.onAck(0, 100, true);
    sm.disposeIfSettled(s);
    sm.drainDisposalQueue();
    try testing.expect(sm.streams.get(sid) == null);
}

test "disposeIfSettled: queues each stream once" {
    var sm = StreamsMap.init(testing.allocator, false);
    defer sm.deinit();
    sm.setMaxStreams(10, 10);

    const s = try sm.openBidiStream();
    s.send.fin_sent = true;
    try s.recv.handleStreamFrame(0, "", true);
    s.closed_for_gc = true;

    sm.disposeIfSettled(s);
    sm.disposeIfSettled(s);
    sm.disposeIfSettled(s);
    try testing.expectEqual(@as(usize, 1), sm.disposal_count);
}

test "SendStream.isDisposable: every byte and the FIN acked, or RESET_STREAM queued" {
    var ss = SendStream.init(testing.allocator, 3);
    defer ss.deinit();
    try ss.writeData("x" ** 10);
    _ = ss.popStreamFrame(5).?;
    try ss.onAck(0, 5, false);
    try testing.expect(!ss.isDisposable()); // still open

    ss.close();
    _ = ss.popStreamFrame(100).?;
    try ss.onAck(5, 5, true);
    try testing.expect(ss.isDisposable());

    // The FIN can be acked ahead of bytes a lost packet carried.
    var gap = SendStream.init(testing.allocator, 7);
    defer gap.deinit();
    try gap.writeData("x" ** 10);
    gap.close();
    _ = gap.popStreamFrame(5).?;
    _ = gap.popStreamFrame(100).?;
    try gap.onAck(5, 5, true);
    try testing.expect(!gap.isDisposable());

    var reset = SendStream.init(testing.allocator, 11);
    defer reset.deinit();
    try reset.writeData("x" ** 10);
    reset.reset(1);
    try testing.expect(!reset.isDisposable()); // RESET_STREAM not out yet
    reset.reset_stream_sent = true;
    try testing.expect(reset.isDisposable());
    reset.pinned = true;
    try testing.expect(!reset.isDisposable());
}

test "drainDisposalQueue: uni streams the full queue turned away are picked up" {
    var sm = StreamsMap.init(testing.allocator, true);
    defer sm.deinit();
    sm.setMaxStreams(1000, 1000);

    const total = sm.disposal_queue.len + 4;
    for (0..total) |_| {
        const ss = try sm.openUniStream();
        ss.reset(1);
        ss.reset_stream_sent = true;
        sm.disposeUniIfSettled(ss);
    }
    try testing.expect(sm.send_disposal_overflow);

    sm.drainDisposalQueue(); // frees what fit, re-queues the rest
    sm.drainDisposalQueue();
    try testing.expectEqual(@as(u32, 0), sm.send_streams.count());
    try testing.expectEqual(@as(u64, 0), sm.open_uni_streams);
}

test "collectClosedStreams: picks up streams the disposal queue could not hold" {
    var sm = StreamsMap.init(testing.allocator, false);
    defer sm.deinit();
    sm.setMaxStreams(1000, 1000);

    // One more settled stream than the queue has room for.
    const overflow = sm.disposal_queue.len + 1;
    for (0..overflow) |_| {
        const s = try sm.openBidiStream();
        s.send.fin_sent = true;
        try s.recv.handleStreamFrame(0, "", true);
    }

    sm.needs_gc_scan = true;
    sm.collectClosedStreams();
    try testing.expectEqual(sm.disposal_queue.len, sm.disposal_count);

    sm.drainDisposalQueue();
    try testing.expectEqual(@as(usize, 1), sm.streams.count());
    try testing.expect(sm.needs_gc_scan); // still work to do

    // The straggler is reclaimed on the next scan rather than leaking.
    sm.collectClosedStreams();
    sm.drainDisposalQueue();
    try testing.expectEqual(@as(usize, 0), sm.streams.count());
    try testing.expect(!sm.needs_gc_scan); // and the scan stands down again
}

test "StreamsMap: a caller that never drains does not keep the GC scan armed" {
    var sm = StreamsMap.init(testing.allocator, false);
    defer sm.deinit();
    sm.setMaxStreams(1000, 1000);

    for (0..sm.disposal_queue.len + 1) |_| {
        const s = try sm.openBidiStream();
        s.send.fin_sent = true;
        try s.recv.handleStreamFrame(0, "", true);
    }

    // Two scans with no drain in between: everything settled, the queue is
    // full, and nothing further can be achieved until someone drains.
    sm.needs_gc_scan = true;
    sm.collectClosedStreams();
    sm.collectClosedStreams();
    try testing.expect(!sm.needs_gc_scan);
    try testing.expect(sm.disposal_overflow);
}

test "getOrCreateStream: a reclaimed stream is not resurrected by a retransmit" {
    var sm = StreamsMap.init(testing.allocator, true); // server: peer bidi = 0, 4, 8
    defer sm.deinit();
    sm.setMaxStreams(10, 10);

    const s = try sm.getOrCreateStream(0);
    s.send.fin_sent = true;
    try s.recv.handleStreamFrame(0, "", true);
    s.closed_for_gc = true;
    sm.disposeIfSettled(s);
    sm.drainDisposalQueue();
    try testing.expect(sm.streams.get(0) == null);

    try testing.expectError(error.StreamAlreadyClosed, sm.getOrCreateStream(0));

    // RFC 9000 §3.2: reaching for 8 opens 4 as well, so an out-of-order frame
    // for 4 finds the stream already there rather than being turned away.
    _ = try sm.getOrCreateStream(8);
    try testing.expect(sm.streams.get(4) != null);
    _ = try sm.getOrCreateStream(4);
    try testing.expectEqual(@as(u64, 12), sm.next_peer_bidi_to_open);
}

test "SendStream: a closed stream stays unacked until the FIN itself is acked" {
    var ss = SendStream.init(testing.allocator, 0);
    defer ss.deinit();

    try ss.writeData("x" ** 100);
    ss.send_offset = 100;
    ss.close();

    // Every byte acknowledged, but the peer has not confirmed the FIN.
    try ss.onAck(0, 100, false);
    try testing.expectEqual(@as(u64, 100), ss.ack_offset);
    try testing.expect(ss.hasUnackedData());

    // The FIN rode a frame of its own, so its ACK carries no bytes.
    try ss.onAck(100, 0, true);
    try testing.expect(!ss.hasUnackedData());
}

test "SendStream: a reset stream has nothing left to retransmit" {
    var ss = SendStream.init(testing.allocator, 0);
    defer ss.deinit();

    try ss.writeData("x" ** 100);
    ss.send_offset = 100;
    ss.close();
    try testing.expect(ss.hasUnackedData());

    ss.reset(7);
    try testing.expect(!ss.hasUnackedData());
}

test "SendStream: a retransmit range never walks past MAX_STREAM_DATA" {
    var ss = SendStream.init(testing.allocator, 0);
    defer ss.deinit();

    try ss.writeData("x" ** 200);
    ss.send_window = 100;

    // Everything the window allows goes out.
    const first = ss.popStreamFrame(1000).?;
    try testing.expectEqual(@as(u64, 100), first.stream.length);
    try testing.expect(ss.popStreamFrame(1000) == null);

    // A caller that queues the whole buffer — PTO used to pass write_offset —
    // must still not push the 100 bytes the peer has not granted.
    ss.queueRetransmit(0, 200, false);
    const rt = ss.popStreamFrame(1000).?;
    try testing.expectEqual(@as(u64, 0), rt.stream.offset);
    try testing.expectEqual(@as(u64, 100), rt.stream.length);
}

test "StreamsMap: MAX_STREAMS grants a remainder below the batch threshold" {
    var sm = StreamsMap.init(testing.allocator, true); // server: peer bidi = 0,4,8...
    defer sm.deinit();
    sm.setMaxIncomingStreams(8, 8);

    // The peer opens every stream we allowed.
    var id: u64 = 0;
    while (id < 8 * 4) : (id += 4) _ = try sm.getOrCreateStream(id);

    // One of them finishes — a remainder far below the 8/4 = 2 threshold.
    sm.consumed_bidi_streams = 1;
    const upd = sm.getMaxStreamsUpdates();
    try testing.expect(upd.bidi != null);
    try testing.expectEqual(@as(u64, 9), upd.bidi.?);

    // And it does not keep firing once the peer has room again.
    try testing.expect(sm.getMaxStreamsUpdates().bidi == null);
}

// ── Receive-stream disposal ────────────────────────────────────────────

test "releaseRecvStream: reclaims a uni stream once the consumer took the FIN" {
    var sm = StreamsMap.init(testing.allocator, true); // server: peer uni = 2,6,10...
    defer sm.deinit();

    const rs = try sm.getOrCreateRecvStream(2);
    try rs.handleStreamFrame(0, "hi", true);
    try testing.expectEqual(@as(u64, 1), sm.open_uni_streams);

    // Consumer reads the payload, then reads again to see the FIN.
    const data = rs.read().?;
    testing.allocator.free(data);
    try testing.expect(rs.read() == null);
    try testing.expect(rs.finished);

    // Finished is not enough on its own: the protocol layer may still need it.
    sm.drainDisposalQueue();
    try testing.expect(sm.recv_streams.get(2) != null);

    sm.releaseRecvStream(2);
    sm.drainDisposalQueue();
    try testing.expect(sm.recv_streams.get(2) == null);
}

test "releaseRecvStream: leaves an unfinished stream alone" {
    var sm = StreamsMap.init(testing.allocator, true);
    defer sm.deinit();

    const rs = try sm.getOrCreateRecvStream(2);
    try rs.handleStreamFrame(0, "hi", false);

    sm.releaseRecvStream(2);
    sm.drainDisposalQueue();
    try testing.expect(sm.recv_streams.get(2) != null);
    try testing.expect(rs.released);
}

test "getOrCreateRecvStream: a reclaimed uni stream is not rebuilt" {
    var sm = StreamsMap.init(testing.allocator, true);
    defer sm.deinit();

    const rs = try sm.getOrCreateRecvStream(2);
    try rs.handleStreamFrame(0, "hi", true);
    const data = rs.read().?;
    testing.allocator.free(data);
    _ = rs.read();
    sm.releaseRecvStream(2);
    sm.drainDisposalQueue();

    // A retransmit of the same frame must not resurrect it.
    try testing.expectError(error.StreamAlreadyClosed, sm.getOrCreateRecvStream(2));
}

test "getOrCreateRecvStream: opens the uni IDs skipped over" {
    var sm = StreamsMap.init(testing.allocator, true);
    defer sm.deinit();

    // RFC 9000 §3.2: using ID 10 opens 2 and 6 as well.
    _ = try sm.getOrCreateRecvStream(10);
    try testing.expect(sm.recv_streams.get(2) != null);
    try testing.expect(sm.recv_streams.get(6) != null);
    try testing.expectEqual(@as(u64, 3), sm.open_uni_streams);
    try testing.expectEqual(@as(?u64, 10), sm.highest_peer_uni_stream_id);
    try testing.expectEqual(@as(u64, 14), sm.next_peer_uni_to_open);
}

test "drainDisposalQueue: an overflowed release is picked up on the next drain" {
    var sm = StreamsMap.init(testing.allocator, true);
    defer sm.deinit();

    const total = sm.disposal_queue.len + 4;
    var i: usize = 0;
    while (i < total) : (i += 1) {
        const id: u64 = 2 + @as(u64, i) * 4;
        const rs = try sm.getOrCreateRecvStream(id);
        try rs.handleStreamFrame(0, "x", true);
        const d = rs.read().?;
        testing.allocator.free(d);
        _ = rs.read();
        sm.releaseRecvStream(id);
    }
    try testing.expect(sm.recv_disposal_overflow);

    sm.drainDisposalQueue(); // clears the queue, re-queues the overflow
    sm.drainDisposalQueue();
    try testing.expectEqual(@as(usize, 0), sm.recv_streams.count());
}

test "StreamsMap: the uni window also grants its remainder at the limit" {
    var sm = StreamsMap.init(testing.allocator, true); // server: peer uni = 2,6,10...
    defer sm.deinit();
    sm.setMaxIncomingStreams(8, 8);

    // The peer opens every uni stream we allowed.
    _ = try sm.getOrCreateRecvStream(2 + 7 * 4);
    try testing.expectEqual(@as(?u64, 30), sm.highest_peer_uni_stream_id);

    // One finishes — far below the 8/4 = 2 threshold, but the peer is stuck.
    sm.consumed_uni_streams = 1;
    const upd = sm.getMaxStreamsUpdates();
    try testing.expectEqual(@as(?u64, 9), upd.uni);
    try testing.expect(sm.getMaxStreamsUpdates().uni == null);
}

// ── Send-buffer compaction ─────────────────────────────────────────────

test "SendStream: acked bytes are dropped and later offsets stay correct" {
    var ss = SendStream.init(testing.allocator, 0);
    defer ss.deinit();

    const chunk = "x" ** 32768;
    try ss.writeData(chunk);
    try ss.writeData(chunk);
    try ss.writeData("TAIL");

    // Send and acknowledge the first 64 KiB.
    ss.send_offset = 65536;
    try ss.onAck(0, 65536, false);

    try testing.expectEqual(@as(u64, 65536), ss.buf_base);
    try testing.expectEqual(@as(usize, 4), ss.write_buffer.items.len);

    // The tail still goes out at its true stream offset, with its true bytes.
    const f = ss.popStreamFrame(1000).?;
    try testing.expectEqual(@as(u64, 65536), f.stream.offset);
    try testing.expectEqualStrings("TAIL", f.stream.data);
}

test "SendStream: a long transfer does not grow without bound" {
    var ss = SendStream.init(testing.allocator, 0);
    defer ss.deinit();

    // 4 MB streamed in 8 KB chunks, acknowledged as it goes.
    const chunk = "y" ** 8192;
    var sent: u64 = 0;
    while (sent < 4 * 1024 * 1024) : (sent += chunk.len) {
        try ss.writeData(chunk);
        ss.send_offset = ss.write_offset;
        try ss.onAck(sent, chunk.len, false);
    }

    try testing.expectEqual(@as(u64, 4 * 1024 * 1024), ss.write_offset);
    // Bounded by the compaction threshold, not by the size of the transfer.
    try testing.expect(ss.write_buffer.items.len <= 2 * SendStream.COMPACT_THRESHOLD);
    try testing.expect(ss.write_buffer.capacity <= 4 * SendStream.COMPACT_THRESHOLD);
}

test "SendStream: a lost packet whose bytes were since acked is not requeued" {
    var ss = SendStream.init(testing.allocator, 0);
    defer ss.deinit();

    try ss.writeData("x" ** 200);
    ss.send_offset = 200;
    try ss.onAck(0, 100, false);

    // Loss detection reports the packet that first carried [0,100).
    ss.queueRetransmit(0, 100, false);
    try testing.expectEqual(@as(u8, 0), ss.retransmit_count);

    // A range straddling the ack boundary keeps only its unacked half.
    ss.queueRetransmit(50, 100, false);
    try testing.expectEqual(@as(u8, 1), ss.retransmit_count);
    try testing.expectEqual(@as(u64, 100), ss.retransmit_ranges[0].offset);
    try testing.expectEqual(@as(u64, 50), ss.retransmit_ranges[0].length);
}

test "SendStream: retransmission after compaction sends the right bytes" {
    var ss = SendStream.init(testing.allocator, 0);
    defer ss.deinit();

    try ss.writeData("a" ** 65536);
    try ss.writeData("bbbbbbbbbb");
    ss.send_offset = ss.write_offset;
    try ss.onAck(0, 65536, false);
    try testing.expectEqual(@as(u64, 65536), ss.buf_base);

    ss.queueRetransmit(65536, 10, false);
    const f = ss.popStreamFrame(1000).?;
    try testing.expectEqual(@as(u64, 65536), f.stream.offset);
    try testing.expectEqualStrings("bbbbbbbbbb", f.stream.data);
}

test "SendStream: compaction survives an ack past what was written" {
    var ss = SendStream.init(testing.allocator, 0);
    defer ss.deinit();

    try ss.writeData("z" ** 70000);
    ss.send_offset = ss.write_offset;
    // A peer that acknowledges more than we sent must not underflow the
    // buffered-length arithmetic.
    ss.ack_offset = ss.write_offset + 5000;
    ss.compactAcked();

    try testing.expectEqual(@as(usize, 0), ss.write_buffer.items.len);
    try testing.expectEqual(@as(u64, 70000), ss.buf_base);
}
