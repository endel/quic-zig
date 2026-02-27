const std = @import("std");
const Allocator = std.mem.Allocator;
const testing = std.testing;

const Frame = @import("frame.zig").Frame;
const stream_mod = @import("stream.zig");
const FrameSorter = stream_mod.FrameSorter;

/// A crypto stream for TLS handshake data.
///
/// Unlike regular QUIC streams, crypto streams:
/// - Have no flow control
/// - Have no stream ID
/// - Exist at each encryption level (Initial, Handshake, 1-RTT)
/// - Carry CRYPTO frames instead of STREAM frames
pub const CryptoStream = struct {
    allocator: Allocator,

    /// Reassembly buffer for incoming CRYPTO frame data.
    recv_sorter: FrameSorter,

    /// Outgoing data buffer.
    send_buffer: std.ArrayList(u8),

    /// Next offset to send.
    send_offset: u64 = 0,

    /// Total bytes queued for sending.
    write_offset: u64 = 0,

    /// Whether all incoming data has been received.
    recv_complete: bool = false,

    pub fn init(allocator: Allocator) CryptoStream {
        return .{
            .allocator = allocator,
            .recv_sorter = FrameSorter.init(allocator),
            .send_buffer = .{ .items = &.{}, .capacity = 0 },
        };
    }

    pub fn deinit(self: *CryptoStream) void {
        self.recv_sorter.deinit();
        self.send_buffer.deinit(self.allocator);
    }

    /// Handle an incoming CRYPTO frame.
    pub fn handleCryptoFrame(self: *CryptoStream, offset: u64, data: []const u8) !void {
        std.log.info("CryptoStream.handleCryptoFrame: offset={d} len={d}", .{ offset, data.len });
        try self.recv_sorter.push(offset, data, false);
    }

    /// Read contiguous TLS handshake data from the receive buffer.
    /// Returns null if no complete data is available.
    pub fn read(self: *CryptoStream) ?[]const u8 {
        return self.recv_sorter.pop();
    }

    /// Queue TLS handshake data for sending.
    pub fn writeData(self: *CryptoStream, data: []const u8) !void {
        try self.send_buffer.appendSlice(self.allocator, data);
        self.write_offset += data.len;
    }

    /// Check if there's data to send.
    pub fn hasData(self: *const CryptoStream) bool {
        return self.send_offset < self.write_offset;
    }

    /// Pop a CRYPTO frame with at most max_len bytes of payload.
    pub fn popCryptoFrame(self: *CryptoStream, max_len: u64) ?Frame {
        const unsent_len = self.write_offset - self.send_offset;
        if (unsent_len == 0) return null;

        const data_len = @min(unsent_len, max_len);
        const offset = self.send_offset;
        const data = self.send_buffer.items[offset..][0..data_len];

        self.send_offset += data_len;

        return Frame{
            .crypto = .{
                .offset = offset,
                .data = @constCast(data),
            },
        };
    }
};

/// Manages crypto streams for all three encryption levels.
pub const CryptoStreamManager = struct {
    /// Crypto stream for Initial encryption level.
    initial: CryptoStream,

    /// Crypto stream for Handshake encryption level.
    handshake: CryptoStream,

    /// Crypto stream for 1-RTT (Application) encryption level.
    one_rtt: CryptoStream,

    pub fn init(allocator: Allocator) CryptoStreamManager {
        return .{
            .initial = CryptoStream.init(allocator),
            .handshake = CryptoStream.init(allocator),
            .one_rtt = CryptoStream.init(allocator),
        };
    }

    pub fn deinit(self: *CryptoStreamManager) void {
        self.initial.deinit();
        self.handshake.deinit();
        self.one_rtt.deinit();
    }

    /// Get the crypto stream for the given encryption level index.
    /// EncryptionLevel enum: initial=0, early_data=1, handshake=2, application=3
    pub fn getStream(self: *CryptoStreamManager, level: u8) *CryptoStream {
        return switch (level) {
            0 => &self.initial,       // initial
            1 => &self.initial,       // early_data (not used, reuse initial)
            2 => &self.handshake,     // handshake
            3 => &self.one_rtt,       // application (1-RTT)
            else => unreachable,
        };
    }

    /// Handle an incoming CRYPTO frame at the given encryption level.
    pub fn handleCryptoFrame(self: *CryptoStreamManager, level: u8, offset: u64, data: []const u8) !void {
        const stream = self.getStream(level);
        try stream.handleCryptoFrame(offset, data);
    }
};

// Tests

test "CryptoStream: write and pop" {
    var cs = CryptoStream.init(testing.allocator);
    defer cs.deinit();

    try cs.writeData("ClientHello");
    try testing.expect(cs.hasData());

    const frame = cs.popCryptoFrame(100);
    try testing.expect(frame != null);
    switch (frame.?) {
        .crypto => |c| {
            try testing.expectEqual(@as(u64, 0), c.offset);
            try testing.expectEqualSlices(u8, "ClientHello", c.data);
        },
        else => unreachable,
    }

    try testing.expect(!cs.hasData());
}

test "CryptoStream: receive and read" {
    var cs = CryptoStream.init(testing.allocator);
    defer cs.deinit();

    try cs.handleCryptoFrame(0, "ServerHello");

    const data = cs.read();
    try testing.expect(data != null);
    try testing.expectEqualStrings("ServerHello", data.?);
    testing.allocator.free(data.?);
}

test "CryptoStream: out-of-order receive" {
    var cs = CryptoStream.init(testing.allocator);
    defer cs.deinit();

    // Receive second part first
    try cs.handleCryptoFrame(5, "World");
    try testing.expect(cs.read() == null);

    // Receive first part
    try cs.handleCryptoFrame(0, "Hello");
    const data1 = cs.read();
    try testing.expect(data1 != null);
    try testing.expectEqualStrings("Hello", data1.?);
    testing.allocator.free(data1.?);

    const data2 = cs.read();
    try testing.expect(data2 != null);
    try testing.expectEqualStrings("World", data2.?);
    testing.allocator.free(data2.?);
}

test "CryptoStreamManager: route to correct stream" {
    var csm = CryptoStreamManager.init(testing.allocator);
    defer csm.deinit();

    try csm.handleCryptoFrame(0, 0, "Initial");
    try csm.handleCryptoFrame(2, 0, "Handshake");
    try csm.handleCryptoFrame(3, 0, "OneRTT");

    const d1 = csm.initial.read();
    try testing.expect(d1 != null);
    try testing.expectEqualStrings("Initial", d1.?);
    testing.allocator.free(d1.?);

    const d2 = csm.handshake.read();
    try testing.expect(d2 != null);
    try testing.expectEqualStrings("Handshake", d2.?);
    testing.allocator.free(d2.?);

    const d3 = csm.one_rtt.read();
    try testing.expect(d3 != null);
    try testing.expectEqualStrings("OneRTT", d3.?);
    testing.allocator.free(d3.?);
}
