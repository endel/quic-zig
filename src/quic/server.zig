const std = @import("std");
const os = std.os;
const fs = std.fs;
const io = std.io;
const net = std.net;
const crypto = std.crypto;
const tls = crypto.tls;

const connection = @import("connection.zig");
const packet = @import("packet.zig");

pub const Server = struct {
    // config: structs.QuicConfiguration,
    ca_bundle: crypto.Certificate.Bundle = .{},

    // pub fn init(config: QuicConfiguration) Server {
    pub fn init(gpa: std.mem.Allocator, cert_filename: []const u8) !Server { // , key: []const u8
        var ca_bundle: crypto.Certificate.Bundle = .{};

        var cert_path = [_]u8{undefined} ** std.fs.MAX_PATH_BYTES;
        var path = try std.fs.realpath("self-signed", &cert_path);
        var cert_dir = try fs.openDirAbsolute(path, .{});

        try ca_bundle.addCertsFromFile(gpa, cert_dir, cert_filename);

        return .{ .ca_bundle = ca_bundle };

        // _ = gpa;
        // _ = cert_filename;
        // return .{};
    }

    pub fn deinit(self: *Server) void {
        self.ca_bundle.deinit();
        self.* = undefined;
    }

    pub fn listen(_: Server, addr: std.net.Address) !i32 {
        const sockfd = try os.socket(os.AF.INET, os.SOCK.DGRAM | os.SOCK.CLOEXEC | os.SOCK.NONBLOCK, 0);

        try os.bind(sockfd, &addr.any, @sizeOf(os.sockaddr.in));
        std.log.info("socket bound at {any}", .{addr});

        return sockfd;
    }
};

test "init" {
    _ = try Server.init(std.testing.allocator, "");
}
