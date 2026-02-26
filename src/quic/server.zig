const std = @import("std");
const posix = std.posix;
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
    alloc: std.mem.Allocator,

    pub fn init(gpa: std.mem.Allocator, cert_path: []const u8) !Server { // , key: []const u8
        var ca_bundle: crypto.Certificate.Bundle = .{};
        var cert_file = try fs.openFileAbsolute(cert_path, .{});
        defer cert_file.close();
        try ca_bundle.addCertsFromFile(gpa, cert_file);
        return .{
            .ca_bundle = ca_bundle,
            .alloc = gpa,
        };
        //
        // _ = gpa;
        // _ = cert_path;
        // return .{};
    }

    pub fn deinit(self: *Server) void {
        self.ca_bundle.deinit(self.alloc);
        self.* = undefined;
    }

    pub fn listen(_: Server, addr: std.net.Address) !posix.socket_t {
        const sockfd = try posix.socket(posix.AF.INET, posix.SOCK.DGRAM | posix.SOCK.CLOEXEC | posix.SOCK.NONBLOCK, 0);

        try posix.bind(sockfd, &addr.any, @sizeOf(posix.sockaddr.in));
        std.log.info("socket bound at {any}", .{addr});

        return sockfd;
    }
};

test "init" {
    var server = try Server.init(std.testing.allocator, "/Users/endel/Projects/netcode.io/quic-zig/self-signed/cert.crt");
    defer server.deinit();
}
