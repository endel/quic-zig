const std = @import("std");
const net = std.net;
const fs = std.fs;
const os = std.os;

// pub const io_mode = .evented;

pub const Packet = struct {
    payload: []u8,
    len: usize,
};

const Ctx = struct {
    queue: std.atomic.Queue(Packet) = undefined,
    buffer: std.atomic.Queue(Packet) = undefined,
};

pub fn listener(context: *Ctx) !void {
    _ = context;

    var currentId = std.Thread.getCurrentId();

    while (true) {
        os.nanosleep(0, 100 * 1000 * 1000);
        std.log.info("thread sleeping... id: {}", .{currentId});
    }
}

pub fn main() anyerror!void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();

    // queue communicating packets to parse
    var queue = std.atomic.Queue(Packet).init();

    // pre-alloc 4096 packets that will be re-used to contain the read data
    // these packets will do round-trips between the listener and the parser.
    var packet_buffers = std.atomic.Queue(Packet).init();

    var tx = Ctx {
        .queue = queue,
        .buffer = packet_buffers,
    };

    _ = try std.Thread.spawn(.{}, listener, .{&tx});
    _ = try std.Thread.spawn(.{}, listener, .{&tx});
    _ = try std.Thread.spawn(.{}, listener, .{&tx});
    _ = try std.Thread.spawn(.{}, listener, .{&tx});

    // var currentId = t1.getCurrentId();
    // std.log.info("thread id {}", .{currentId});

    std.log.info("is async?? {}", .{std.io.is_async});

    while (true) {
        os.nanosleep(0, 100 * 1000 * 1000);
        std.log.info("main sleeping...", .{});
    }
}
