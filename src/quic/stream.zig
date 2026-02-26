const std = @import("std");
const os = std.io;
const mem = std.mem;

const MAX_DATA: usize = 512;

// allocator: std.mem.Allocator,

pub const Priority = enum(u8) {
    max = 0,
    high = 64,
    default = 127,
    low = 192,
    min = 255,
};

pub const Stream = struct {
    recv_buffer: RecvBuf = .{},
    send_buffer: SendBuffer = .{},

    is_bidi: bool = undefined, // is bidirectional?
    is_local: bool = undefined, // created by local endpoint?
    is_incremental: bool = true, // can be flushed incrementally? default is `true`

    data: [MAX_DATA]u8 = undefined,
    priority: u8 = @intFromEnum(Priority.default), // 0 = highest. default is `Priority.default`.

    pub fn recv(self: *Stream, data: []u8) void {
        for (data, 0..) |b, i| {
            self.recv_buffer.data[self.recv_buffer.pos + i] = b;
        }

        self.recv_buffer.pos += data.len;
        self.recv_buffer.len += data.len;

        std.log.info(".recv(), buf.data: {any}", .{self.recv_buffer.data});
    }

    // pub fn read(self: *Stream, buffer: []u8, len: usize) void {
    pub fn readAtLeast(self: *Stream, dest: []u8, len: usize) !usize {
        std.log.info(".readAtLeast(), len: {any}, buf.off: {any}, buf.data: {any}", .{ len, self.recv_buffer.off, self.recv_buffer.data });

        // TODO: check if off+len is a valid slice. (out of bounds?)
        const slice = self.recv_buffer.data[self.recv_buffer.off..(self.recv_buffer.off + len)];
        for (slice, 0..) |b, i| {
            dest[i] = b;
        }

        std.log.info(".readAtLeast(), off: {any}, slice: {any}", .{ self.recv_buffer.off, slice });

        self.recv_buffer.off += len;

        return len;
    }

    pub fn writevAll(self: *@This(), iovecs: []std.posix.iovec_const) !usize {
        for (iovecs) |iovec| {
            var i: usize = 0;
            while (i < iovec.len) : (i += 1) {
                self.send_buffer.data[self.send_buffer.off + i] = iovec.base[i];
            }

            self.send_buffer.off += iovec.len;
        }

        return self.send_buffer.off;
    }

    pub fn writeAll(self: *Stream, bytes: []const u8) !usize {
        for (bytes, 0..) |b, i| {
            self.send_buffer.data[self.send_buffer.off + i] = b;
        }

        self.send_buffer.off += bytes.len;

        return self.send_buffer.off;
    }

    // pub fn writeString(self: *Stream, data: []const u8) void {
    //     // write length
    //     self.send_buffer.data[self.send_buffer.off] = @intCast(u8, data.len);
    //     self.send_buffer.off += 1;
    //
    //     _ = self.write(data);
    // }
};

pub const RecvBuf = struct {
    data: [MAX_DATA]u8 = .{undefined} ** MAX_DATA, // BinaryHeap<RangeBuf>,
    // data_buf: std.io.FixedBufferStream = std.io.fixedBufferStream(&@This().data),

    pos: usize = 0, // writing data position (to be read later)
    off: u64 = 0, // lowest data offset that has yet to be read by the application.
    len: u64 = 0, // total length of data received on this stream

    // flow_control, // receiver flow controller

    fin_off: ?u64 = null, // final stream offset received from the peer, if any
    err: ?u64 = null, // error code received via RESET_STREAM
    is_draining: bool = false, // is incoming data validated but not buffered
};

pub const SendBuffer = struct {
    /// Chunks of data to be sent, ordered by offset
    data: [MAX_DATA]u8 = .{undefined} ** MAX_DATA, // VecDeque<RangeBuf>
    pos: usize = 0, // index of the buffer that needs to be sent next

    off: u64 = 0, // maximum offset of data buffered in the stream
    len: u64 = 0, // amount of data currently buffered

    max_data: u64 = MAX_DATA, // maximum offset we are allowed to send to the peer

    blocked_at: ?u64 = null, // last offset the stream was blocked at, if any
    fin_off: ?u64 = null, // final stream offset written to the stream, if any

    is_shutdown: bool = false, // whether sending has been shut down

    // // ranges::RangeSet,
    // acked: [MAX_DATA]u64, // range of data offsets that have been acked
    // err: ?u64, // error code received via STOP_SENDING
};
