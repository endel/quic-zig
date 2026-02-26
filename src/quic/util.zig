const std = @import("std");

const endian = std.builtin.Endian.big;

pub fn sizeOf(comptime T: type) comptime_int {
    return switch (@typeInfo(T)) {
        .int => |i| @divExact(i.bits, 8),
        .array => |a| a.len * sizeOf(a.child),
        else => @compileError("`sizeOf` only supports `Int` or `Array`"),
    };
}

test "sizeOf" {
    try std.testing.expectEqual(1, sizeOf(u8));
    try std.testing.expectEqual(2, sizeOf(u16));
    try std.testing.expectEqual(3, sizeOf(u24));
    try std.testing.expectEqual(4, sizeOf(u32));
    try std.testing.expectEqual(8, sizeOf(u64));

    try std.testing.expectEqual(3, sizeOf([3]u8));
    try std.testing.expectEqual(4, sizeOf([2]u16));
    try std.testing.expectEqual(6, sizeOf([2]u24));
}

pub const StreamReader = struct {
    buf: []u8,
    idx: usize = 0,

    pub fn from(buf: []u8) StreamReader {
        return .{ .buf = buf };
    }

    pub fn eof(self: *StreamReader) bool {
        return self.idx == self.buf.len;
    }

    pub fn getSlicePrefixedLength(self: *StreamReader, comptime T: type) []u8 {
        return self.getSlice(self.get(T));
    }

    pub fn get(self: *StreamReader, comptime T: type) T {
        switch (@typeInfo(T)) {
            .int => |info| switch (info.bits) {
                8 => {
                    self.idx += 1;
                    return self.buf[self.idx - 1];
                },
                16 => {
                    self.idx += 2;
                    const b0: u16 = self.buf[self.idx - 2];
                    const b1: u16 = self.buf[self.idx - 1];
                    return (b0 << 8) | b1;
                },
                24 => {
                    self.idx += 3;
                    const b0: u24 = self.buf[self.idx - 3];
                    const b1: u24 = self.buf[self.idx - 2];
                    const b2: u24 = self.buf[self.idx - 1];
                    return (b0 << 16) | (b1 << 8) | b2;
                },
                else => @compileError("unsupported int type: " ++ @typeName(T)),
            },
            .@"enum" => |info| {
                const int = self.get(info.tag_type);
                if (info.is_exhaustive) @compileError("exhaustive enum cannot be used");
                return @enumFromInt(int);
            },
            else => @compileError("unsupported type: " ++ @typeName(T)),
        }
    }

    pub fn getSlice(self: *StreamReader, len: usize) []u8 {
        const value = self.buf[self.idx..(self.idx + len)];
        self.idx += len;
        return value;
    }

    pub fn skip(self: *StreamReader, v: usize) void {
        self.idx += v;
    }
};
