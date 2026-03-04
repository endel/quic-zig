const std = @import("std");
const posix = std.posix;
const builtin = @import("builtin");

// Platform-specific constants for ECN socket options (IPv4).
const IPPROTO_IP: u32 = 0;

const IP_TOS: u32 = switch (builtin.os.tag) {
    .macos => 3,
    .linux => 1,
    else => @compileError("unsupported OS for ECN"),
};

const IP_RECVTOS: u32 = switch (builtin.os.tag) {
    .macos => 27,
    .linux => 13,
    else => @compileError("unsupported OS for ECN"),
};

// cmsg header — Zig std doesn't expose this on macOS.
const CmsgHdr = extern struct {
    cmsg_len: switch (builtin.os.tag) {
        .macos => u32,
        else => usize,
    },
    cmsg_level: i32,
    cmsg_type: i32,
};

const CMSG_HDR_SIZE = @sizeOf(CmsgHdr);

// Aligned cmsg buffer size (header + 4 bytes data, padded to alignment).
const CMSG_SPACE = (CMSG_HDR_SIZE + 4 + @alignOf(CmsgHdr) - 1) & ~@as(usize, @alignOf(CmsgHdr) - 1);
const CMSG_BUF_SIZE = CMSG_SPACE * 2; // room for at least 2 cmsgs

/// Enable receiving ECN/TOS info on incoming packets.
pub fn enableEcnRecv(sockfd: posix.socket_t) !void {
    const val: u32 = 1;
    try posix.setsockopt(sockfd, IPPROTO_IP, IP_RECVTOS, std.mem.asBytes(&val));
}

/// Set the ECN codepoint for outgoing packets (low 2 bits of IP TOS).
pub fn setEcnMark(sockfd: posix.socket_t, ecn_mark: u2) !void {
    const tos: u32 = @as(u32, ecn_mark);
    try posix.setsockopt(sockfd, IPPROTO_IP, IP_TOS, std.mem.asBytes(&tos));
}

pub const RecvResult = struct {
    bytes_read: usize,
    from_addr: posix.sockaddr,
    addr_len: posix.socklen_t,
    ecn: u2,
};

/// Receive a UDP datagram and extract the ECN codepoint from ancillary data.
pub fn recvmsgEcn(sockfd: posix.socket_t, buf: []u8) !RecvResult {
    var iov = [1]posix.iovec{
        .{
            .base = buf.ptr,
            .len = buf.len,
        },
    };

    var cmsg_buf: [CMSG_BUF_SIZE]u8 align(@alignOf(CmsgHdr)) = .{0} ** CMSG_BUF_SIZE;
    var from_addr: posix.sockaddr = undefined;
    var addr_len: posix.socklen_t = @sizeOf(posix.sockaddr);

    var msg = std.c.msghdr{
        .name = &from_addr,
        .namelen = addr_len,
        .iov = &iov,
        .iovlen = 1,
        .control = &cmsg_buf,
        .controllen = CMSG_BUF_SIZE,
        .flags = 0,
    };

    const rc = std.c.recvmsg(sockfd, &msg, 0);
    if (rc < 0) {
        const err = std.posix.errno(rc);
        return switch (err) {
            .AGAIN => error.WouldBlock,
            .CONNREFUSED => error.ConnectionRefused,
            .NOTCONN => error.SocketNotConnected,
            else => posix.unexpectedErrno(err),
        };
    }

    const bytes_read: usize = @intCast(rc);
    addr_len = msg.namelen;

    // Parse cmsg for IP_TOS
    var ecn: u2 = 0;
    var offset: usize = 0;
    while (offset + CMSG_HDR_SIZE <= msg.controllen) {
        const hdr: *const CmsgHdr = @ptrCast(@alignCast(&cmsg_buf[offset]));
        const data_offset = offset + CMSG_HDR_SIZE;
        const data_len = @as(usize, hdr.cmsg_len) -| CMSG_HDR_SIZE;
        if (hdr.cmsg_level == @as(i32, @intCast(IPPROTO_IP)) and
            hdr.cmsg_type == @as(i32, @intCast(IP_RECVTOS)) and
            data_len >= 1 and data_offset < CMSG_BUF_SIZE)
        {
            ecn = @truncate(cmsg_buf[data_offset] & 0x03);
            break;
        }
        // Advance to next cmsg (aligned)
        const total = (CMSG_HDR_SIZE + data_len + @alignOf(CmsgHdr) - 1) & ~@as(usize, @alignOf(CmsgHdr) - 1);
        if (total == 0) break;
        offset += total;
    }

    return .{
        .bytes_read = bytes_read,
        .from_addr = from_addr,
        .addr_len = addr_len,
        .ecn = ecn,
    };
}

// Tests
test "enableEcnRecv on a real socket" {
    const sockfd = try posix.socket(posix.AF.INET, posix.SOCK.DGRAM | posix.SOCK.NONBLOCK, 0);
    defer posix.close(sockfd);

    const addr = try std.net.Address.parseIp4("127.0.0.1", 0);
    try posix.bind(sockfd, &addr.any, addr.getOsSockLen());

    try enableEcnRecv(sockfd);
}

test "setEcnMark on a real socket" {
    const sockfd = try posix.socket(posix.AF.INET, posix.SOCK.DGRAM | posix.SOCK.NONBLOCK, 0);
    defer posix.close(sockfd);

    const addr = try std.net.Address.parseIp4("127.0.0.1", 0);
    try posix.bind(sockfd, &addr.any, addr.getOsSockLen());

    // ECT(0) = 0b10 = 2
    try setEcnMark(sockfd, 0b10);
    // Not-ECT = 0b00 = 0
    try setEcnMark(sockfd, 0b00);
}

test "recvmsgEcn returns WouldBlock on empty socket" {
    const sockfd = try posix.socket(posix.AF.INET, posix.SOCK.DGRAM | posix.SOCK.NONBLOCK, 0);
    defer posix.close(sockfd);

    const addr = try std.net.Address.parseIp4("127.0.0.1", 0);
    try posix.bind(sockfd, &addr.any, addr.getOsSockLen());
    try enableEcnRecv(sockfd);

    var buf: [1500]u8 = undefined;
    const result = recvmsgEcn(sockfd, &buf);
    try std.testing.expectError(error.WouldBlock, result);
}
