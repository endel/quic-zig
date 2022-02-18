const std = @import("std");
const net = std.net;
const fs = std.fs;
const os = std.os;

pub const io_mode = .evented;

pub fn main() anyerror!void {
    var general_purpose_allocator = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = &general_purpose_allocator.allocator;

    var server = net.StreamServer.init(.{});
    defer server.deinit();

    // TODO handle concurrent accesses to this hash map
    var room = Room{ .clients = std.AutoHashMap(*Client, void).init(allocator) };

    try server.listen(net.Address.parseIp("127.0.0.1", 0) catch unreachable);
    std.debug.warn("listening at {}\n", .{server.listen_address});

    while (true) {
        const client = try allocator.create(Client);
        client.* = Client{
            .conn = try server.accept(),
            .handle_frame = async client.handle(&room),
        };
        try room.clients.putNoClobber(client, {});
    }
}
const Client = struct {
    conn: net.StreamServer.Connection,
    handle_frame: @Frame(handle),

    fn handle(self: *Client, room: *Room) !void {
        _ = try self.conn.stream.write("server: welcome to teh chat server\n");
        while (true) {
            var buf: [100]u8 = undefined;
            const amt = try self.conn.stream.read(&buf);
            const msg = buf[0..amt];
            room.broadcast(msg, self);
        }
    }
};
const Room = struct {
    clients: std.AutoHashMap(*Client, void),

    fn broadcast(room: *Room, msg: []const u8, sender: *Client) void {
        var it = room.clients.keyIterator();
        while (it.next()) |key_ptr| {
            const client = key_ptr.*;
            if (client == sender) continue;
            _ = client.conn.stream.write(msg) catch |e| std.debug.warn("unable to send: {}\n", .{e});
        }
    }
};
