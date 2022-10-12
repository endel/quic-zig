const std = @import("std");

pub fn sizeOf(comptime T: type) comptime_int {
    return switch (@typeInfo(T)) {
        .Int => |i| @divExact(i.bits, 8),
        .Array => |a| a.len * sizeOf(a.child),
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
