const std = @import("std");
const testing = std.testing;
const io = std.io;
const packet = @import("../quic/packet.zig");

/// HTTP Capsule types (RFC 9297 Section 4.7).
pub const CapsuleType = enum(u64) {
    datagram = 0x00,

    pub fn fromInt(v: u64) ?CapsuleType {
        return switch (v) {
            0x00 => .datagram,
            else => null,
        };
    }
};

/// Check if a capsule type value is reserved for extension negotiation.
/// Reserved pattern: 0x29 * N + 0x17 for any non-negative integer N (RFC 9297 §4.7).
pub fn isReservedCapsuleType(capsule_type: u64) bool {
    if (capsule_type < 0x17) return false;
    return (capsule_type - 0x17) % 0x29 == 0;
}

/// Parsed capsule from stream data.
pub const Capsule = struct {
    capsule_type: u64,
    value: []const u8,
};

/// Parse one capsule from a byte buffer.
/// Returns the parsed capsule and the number of bytes consumed.
/// Unknown capsule types are returned as-is (caller decides to skip or process).
pub fn parse(data: []const u8) !struct { capsule: Capsule, consumed: usize } {
    if (data.len == 0) return error.BufferTooShort;

    var fbs = io.fixedBufferStream(data);
    const reader = fbs.reader();

    // Capsule Type (varint)
    const capsule_type = packet.readVarInt(reader) catch return error.BufferTooShort;

    // Capsule Length (varint)
    const length = packet.readVarInt(reader) catch return error.BufferTooShort;

    const header_size = fbs.pos;
    const total_size = header_size + length;

    if (data.len < total_size) return error.BufferTooShort;

    const value = data[header_size..total_size];

    return .{
        .capsule = .{
            .capsule_type = capsule_type,
            .value = value,
        },
        .consumed = total_size,
    };
}

/// Write a capsule to a writer.
pub fn write(writer: anytype, capsule_type: u64, value: []const u8) !void {
    try packet.writeVarInt(writer, capsule_type);
    try packet.writeVarInt(writer, value.len);
    if (value.len > 0) {
        try writer.writeAll(value);
    }
}

/// Write a DATAGRAM capsule (type 0x00) containing an HTTP Datagram Payload.
pub fn writeDatagram(writer: anytype, payload: []const u8) !void {
    try write(writer, @intFromEnum(CapsuleType.datagram), payload);
}

/// Iterator that parses sequential capsules from a byte buffer.
/// Use to process a capsule stream incrementally.
pub const CapsuleIterator = struct {
    data: []const u8,
    pos: usize = 0,

    pub fn init(data: []const u8) CapsuleIterator {
        return .{ .data = data };
    }

    /// Returns the next capsule, or null when no more complete capsules remain.
    /// Returns error.MalformedCapsule if the data is corrupt.
    pub fn next(self: *CapsuleIterator) !?Capsule {
        if (self.pos >= self.data.len) return null;

        const result = parse(self.data[self.pos..]) catch |err| {
            if (err == error.BufferTooShort) return null;
            return error.MalformedCapsule;
        };

        self.pos += result.consumed;
        return result.capsule;
    }

    /// Returns the number of unprocessed bytes remaining.
    pub fn remaining(self: *const CapsuleIterator) usize {
        return self.data.len - self.pos;
    }
};

// Tests

test "parse DATAGRAM capsule" {
    var buf: [256]u8 = undefined;
    var fbs = io.fixedBufferStream(&buf);

    const payload = "hello capsule";
    try writeDatagram(fbs.writer(), payload);

    const written = fbs.getWritten();
    const result = try parse(written);

    try testing.expectEqual(@as(u64, 0x00), result.capsule.capsule_type);
    try testing.expectEqualStrings(payload, result.capsule.value);
    try testing.expectEqual(written.len, result.consumed);
}

test "parse empty DATAGRAM capsule" {
    var buf: [16]u8 = undefined;
    var fbs = io.fixedBufferStream(&buf);

    try writeDatagram(fbs.writer(), "");

    const written = fbs.getWritten();
    const result = try parse(written);

    try testing.expectEqual(@as(u64, 0x00), result.capsule.capsule_type);
    try testing.expectEqual(@as(usize, 0), result.capsule.value.len);
}

test "write and parse generic capsule" {
    var buf: [256]u8 = undefined;
    var fbs = io.fixedBufferStream(&buf);

    const custom_type: u64 = 0x1234;
    const payload = "custom data";
    try write(fbs.writer(), custom_type, payload);

    const written = fbs.getWritten();
    const result = try parse(written);

    try testing.expectEqual(custom_type, result.capsule.capsule_type);
    try testing.expectEqualStrings(payload, result.capsule.value);
}

test "parse buffer too short - empty" {
    const result = parse(&[_]u8{});
    try testing.expectError(error.BufferTooShort, result);
}

test "parse buffer too short - truncated value" {
    var buf: [16]u8 = undefined;
    var fbs = io.fixedBufferStream(&buf);
    const w = fbs.writer();

    try packet.writeVarInt(w, 0x00); // type: DATAGRAM
    try packet.writeVarInt(w, 100); // length: 100 (but no payload follows)

    const result = parse(fbs.getWritten());
    try testing.expectError(error.BufferTooShort, result);
}

test "parse buffer too short - type only" {
    var buf: [8]u8 = undefined;
    var fbs = io.fixedBufferStream(&buf);
    try packet.writeVarInt(fbs.writer(), 0x00);

    // Only type varint, no length — should fail
    const result = parse(fbs.getWritten());
    // This might parse type=0, length=? depending on varint encoding
    // A single byte 0x00 is type=0 but no length byte follows
    // Actually 0x00 encodes as 1-byte varint. Next readVarInt needs at least 1 more byte.
    // The getWritten() is [0x00] which is 1 byte. First readVarInt reads type=0 consuming 1 byte.
    // Second readVarInt has 0 bytes left → BufferTooShort.
    try testing.expectError(error.BufferTooShort, result);
}

test "isReservedCapsuleType" {
    // 0x17 = 0x29*0 + 0x17 → reserved
    try testing.expect(isReservedCapsuleType(0x17));
    // 0x40 = 0x29*1 + 0x17 → reserved
    try testing.expect(isReservedCapsuleType(0x40));
    // 0x69 = 0x29*2 + 0x17 → reserved
    try testing.expect(isReservedCapsuleType(0x69));

    // Known types should not be reserved
    try testing.expect(!isReservedCapsuleType(0x00)); // DATAGRAM
    try testing.expect(!isReservedCapsuleType(0x01));
    try testing.expect(!isReservedCapsuleType(0x16));
    try testing.expect(!isReservedCapsuleType(0x18));
}

test "CapsuleIterator - multiple capsules" {
    var buf: [512]u8 = undefined;
    var fbs = io.fixedBufferStream(&buf);
    const w = fbs.writer();

    // Write 3 capsules
    try writeDatagram(w, "first");
    try writeDatagram(w, "second");
    try write(w, 0xFF, "custom");

    const data = fbs.getWritten();
    var iter = CapsuleIterator.init(data);

    // First capsule
    const c1 = (try iter.next()).?;
    try testing.expectEqual(@as(u64, 0x00), c1.capsule_type);
    try testing.expectEqualStrings("first", c1.value);

    // Second capsule
    const c2 = (try iter.next()).?;
    try testing.expectEqual(@as(u64, 0x00), c2.capsule_type);
    try testing.expectEqualStrings("second", c2.value);

    // Third capsule (custom type)
    const c3 = (try iter.next()).?;
    try testing.expectEqual(@as(u64, 0xFF), c3.capsule_type);
    try testing.expectEqualStrings("custom", c3.value);

    // No more capsules
    try testing.expect(try iter.next() == null);
    try testing.expectEqual(@as(usize, 0), iter.remaining());
}

test "CapsuleIterator - partial trailing data" {
    var buf: [256]u8 = undefined;
    var fbs = io.fixedBufferStream(&buf);
    const w = fbs.writer();

    try writeDatagram(w, "complete");

    var data_arr: [256]u8 = undefined;
    const written = fbs.getWritten();
    @memcpy(data_arr[0..written.len], written);
    // Add incomplete trailing capsule: type byte only
    data_arr[written.len] = 0x00;
    const data = data_arr[0 .. written.len + 1];

    var iter = CapsuleIterator.init(data);

    // First capsule parses fine
    const c1 = (try iter.next()).?;
    try testing.expectEqualStrings("complete", c1.value);

    // Second call returns null (incomplete)
    try testing.expect(try iter.next() == null);
    try testing.expectEqual(@as(usize, 1), iter.remaining());
}

test "large capsule payload" {
    var buf: [8200]u8 = undefined;
    var fbs = io.fixedBufferStream(&buf);

    // Write a capsule with 8000-byte payload
    var payload: [8000]u8 = undefined;
    @memset(&payload, 0xAB);
    try writeDatagram(fbs.writer(), &payload);

    const written = fbs.getWritten();
    const result = try parse(written);

    try testing.expectEqual(@as(u64, 0x00), result.capsule.capsule_type);
    try testing.expectEqual(@as(usize, 8000), result.capsule.value.len);
    try testing.expectEqual(@as(u8, 0xAB), result.capsule.value[0]);
    try testing.expectEqual(@as(u8, 0xAB), result.capsule.value[7999]);
}
