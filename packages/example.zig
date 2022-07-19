const tls = @import("tls/feilich.zig");
const std = @import("std");
const net = std.net;

pub fn main() !void {
    std.log.info("Hello, world!", .{});

    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();

    var server = net.StreamServer.init(.{ .reuse_address = true });
    defer server.deinit();

    // const addr = net.Address.initIp6(.{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, }, 8080);
    const addr = net.Address.initIp4(.{ 0, 0, 0, 0 }, 8080);
    try server.listen(addr);
    std.log.info("Listening on {}", .{addr});

    // const privateKey = @embedFile("../self-signed/localhost.key");
    // const publicKey = @embedFile("../self-signed/localhost.crt");

    const privateKey = @embedFile("../self-signed/aioquic/ssl_key.pem");
    const publicKey = @embedFile("../self-signed/aioquic/ssl_cert.pem");

    // std.log.info("cert: {s}", .{privateKey});
    // std.log.info("key: {s}", .{publicKey});

    const tls_server = tls.Server.init(std.heap.page_allocator, privateKey, publicKey);

    while (true) {
        const connection = try server.accept();
        const stream = connection.stream;

        std.log.info("Accepting connection... {any}", .{connection});

        tls_server.connect(stream.reader(), stream.writer()) catch |err| {
            std.log.debug("Error: {s}\n", .{@errorName(err)});
            return err;
        };
    }

    // while (true) {
    //     const connection = try server.accept();
    //     const stream = connection.stream;

    //     std.log.info("Accepting connection from {}", .{stream});

    //     // read!
    //     const reader = stream.reader();
    //     var bytes: [4096]u8 = undefined;
    //     var size = try reader.read(&bytes);

    //     std.log.info("size: {}, bytes: {any}", .{ size, bytes });

    //     // write!
    //     const writer = stream.writer();
    //     try writer.writeAll(&.{ 0, 1, 2, 3 });

    //     connection.stream.close();
    // }
}
