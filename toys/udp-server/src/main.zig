const std = @import("std");
const net = std.net;
const fs = std.fs;
const os = std.os;

const socket = @import("socket.zig");

pub const io_mode = .evented;

pub fn main() anyerror!void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();

    const sockfd = try sockfd.open_socket();
    // defer os.closeSocket(sockfd);

    // reading buffer
    var array: [8192]u8 = undefined;
    var buf: []u8 = &array;

    var drops: i64 = 0;
    var last_drop_message = std.time.milliTimestamp();

    while (true) {
        os.nanosleep(0, 100 * 1000 * 1000);
        // os.recvfrom(sockfd, )
        os.recvfrom()
    }

    // // const allocator = gpa.allocator();

    // var server = net.StreamServer.init(.{});
    // defer server.deinit();

    // try server.listen(net.Address.parseIp("127.0.0.1", 8001) catch unreachable);
    // std.log.info("listening at {}\n", .{server.listen_address});
}
