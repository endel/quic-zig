const std = @import("std");
const os = std.os;
const io = std.io;
const net = std.net;

const connection = @import("connection.zig");
const packet = @import("packet.zig");
const crypto = @import("crypto.zig");

pub const Server = struct {
    // config: structs.QuicConfiguration,

    // pub fn init(config: QuicConfiguration) Server {
    pub fn init() Server {
        return .{};
    }

    pub fn listen(_: Server, addr: std.net.Address) !i32 {
        const sockfd = try os.socket(os.AF.INET, os.SOCK.DGRAM | os.SOCK.CLOEXEC | os.SOCK.NONBLOCK, 0);

        try os.bind(sockfd, &addr.any, @sizeOf(os.sockaddr.in));
        std.log.info("socket bound at {any}", .{addr});

        return sockfd;
    }
};
