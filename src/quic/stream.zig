const std = @import("std");

allocator: std.mem.Allocator,

pub const Priority = enum(u8) {
    max = 0,
    high = 64,
    default = 127,
    low = 192,
    min = 255,
};

pub const Stream = struct {
    recv_buffer: RecvBuf,
    send_buffer: SendBuffer,

    is_bidi: bool = undefined, // is bidirectional?
    is_local: bool = undefined, // created by local endpoint?
    is_incremental: bool = true, // can be flushed incrementally? default is `true`

    data: []u8 = undefined,
    priority: u8 = @enumToInt(Priority.default), // 0 = highest. default is `Priority.default`.
};

pub const RecvBuf = struct {
    data: []u8, // BinaryHeap<RangeBuf>,
    off: u64, // lowest data offset that has yet to be read by the application.
    len: u64, // total length of data received on this stream

    // flow_control, // receiver flow controller

    fin_off: ?u64, // final stream offset received from the peer, if any
    err: ?u64, // error code received via RESET_STREAM
    is_draining: bool, // is incoming data validated but not buffered
};

pub const SendBuffer = struct {
    /// Chunks of data to be sent, ordered by offset
    data: []u8, // VecDeque<RangeBuf>

    pos: usize, // index of the buffer that needs to be sent next

    off: u64, // maximum offset of data buffered in the stream
    len: u64, // amount of data currently buffered

    max_data: u64, // maximum offset we are allowed to send to the peer

    blocked_at: ?u64, // last offset the stream was blocked at, if any
    fin_off: ?u64, // final stream offset written to the stream, if any

    is_shutdown: bool, // whether sending has been shut down

    // ranges::RangeSet,
    acked: []u64, // range of data offsets that have been acked
    err: ?u64, // error code received via STOP_SENDING
};
