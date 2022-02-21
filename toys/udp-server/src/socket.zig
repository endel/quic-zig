const std = @import("std");
const os = std.os;

pub fn open_socket(port: u16) !i32 {
    var sockfd: i32 = try os.socket(
        os.AF_INET,
        os.SOCK_DGRAM | os.SOCK_CLOEXEC | os.SOCK_NONBLOCK,
        0,
    );

    var addr = try std.net.Address.parseIp4("127.0.0.1", port);

    try os.bind(sockfd, &addr.any, @sizeOf(os.sockaddr_in));
    std.log.info("socket bound at {}", .{port});

    return sockfd;
}
