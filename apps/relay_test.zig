//! Test fixtures shared by the relays' tests.

const std = @import("std");
const quic = @import("quic");
const Connection = quic.connection.Connection;

/// A server connection with nothing on the wire: enough to open, write,
/// finish and reset streams, every byte of which stays unsent.
pub fn conn() !*Connection {
    const alloc = std.testing.allocator;
    const cid = [_]u8{1} ** 20;
    const c = try alloc.create(Connection);
    c.* = .{
        .allocator = alloc,
        .is_server = true,
        .dcid = cid,
        .dcid_len = 8,
        .scid = cid,
        .scid_len = 8,
        .version = 1,
        .pkt_handler = @FieldType(Connection, "pkt_handler").init(alloc),
        .conn_flow_ctrl = @FieldType(Connection, "conn_flow_ctrl").init(1 << 20, 6 << 20),
        .streams = @FieldType(Connection, "streams").init(alloc, true),
        .crypto_streams = @FieldType(Connection, "crypto_streams").init(alloc),
        .packer = @FieldType(Connection, "packer").init(alloc, true, cid[0..8], cid[0..8], 1),
    };
    c.streams.setMaxStreams(100, 100);
    c.streams.setMaxIncomingStreams(100, 100);
    c.streams.peer_initial_max_stream_data_uni = 1 << 20;
    c.streams.peer_initial_max_stream_data_bidi_local = 1 << 20;
    c.streams.peer_initial_max_stream_data_bidi_remote = 1 << 20;
    c.conn_flow_ctrl.base.send_window = 1 << 20;
    return c;
}

pub fn free(c: *Connection) void {
    c.deinit();
    std.testing.allocator.destroy(c);
}
