const std = @import("std");
const net = std.net;
const fs = std.fs;
const os = std.os;
const Queue = std.atomic.Queue;

const socket = @import("lib/socket.zig");

pub const io_mode = .evented;

pub const Packet = struct {
    payload: []u8,
    len: usize,
};

pub fn main() anyerror!void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();

    const port = 50000;
    var sockfd: i32 = try os.socket(os.AF.INET, os.SOCK.DGRAM | os.SOCK.CLOEXEC | os.SOCK.NONBLOCK, 0);
    var addr = try std.net.Address.parseIp4("127.0.0.1", port);
    // defer os.closeSocket(sockfd);

    try os.bind(sockfd, &addr.any, @sizeOf(os.sockaddr.in));
    std.log.info("socket bound at {}", .{port});

    // reading buffer
    var array: [8192]u8 = undefined;
    var buf: []u8 = &array;

    // queue communicating packets to parse
    var queue = Queue(Packet).init();

    // pre-alloc `num_packet_buffers` packets that will be re-used to contain the read data
    // these packets will do round-trips between the listener and the parser.
    const num_packet_buffers = 8;
    const packet_size = 8;
    var packet_buffers = Queue(Packet).init();

    var i: usize = 0;
    while (i < num_packet_buffers) {
        var packet_node: *Queue(Packet).Node = try std.heap.page_allocator.create(Queue(Packet).Node);
        packet_node.data = Packet{
            .payload = try std.heap.page_allocator.alloc(u8, packet_size),
            .len = 0,
        };
        packet_buffers.put(packet_node);
        i += 1;
    }

    var drops: i64 = 0;
    var last_drop_message = std.time.milliTimestamp();

    while (true) {
        os.nanosleep(0, 100 * 1000 * 1000);

        const rlen = os.recvfrom(sockfd, buf, 0, null, null) catch {
            continue;
        };

        if (rlen == 0) {
            continue;
        }

        if (packet_buffers.isEmpty()) {
            drops += 1;

            std.log.info("packet dropped: length = {}, drops = {}\n", .{ rlen, drops });

            // no more pre-allocated buffers available, this packet will be dropped.
            continue;
        }

        // take a pre-allocated buffers
        var node = packet_buffers.get().?;

        // copy the data
        std.mem.copy(u8, node.data.payload[0..rlen], buf[0..rlen]);
        node.data.len = rlen;

        std.log.info("received: {}\n", .{node.data});

        // send it for processing
        queue.put(node);

        const tmp = std.time.milliTimestamp() - last_drop_message;
        if (tmp > 10000) {
            last_drop_message = std.time.milliTimestamp();
            std.log.warn("drops: {}/s\n", .{@divTrunc(drops, @divTrunc(tmp, 1000))});
            drops = 0;
        }
    }

    // // const allocator = gpa.allocator();

    // var server = net.StreamServer.init(.{});
    // defer server.deinit();

    // try server.listen(net.Address.parseIp("127.0.0.1", 8001) catch unreachable);
    // std.log.info("listening at {}\n", .{server.listen_address});
}
