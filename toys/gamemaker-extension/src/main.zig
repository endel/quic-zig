const std = @import("std");
const testing = std.testing;

export fn add(a: f64, b: f64) f64 {
    return a + b;
}

test "basic add functionality" {
    try testing.expect(add(3, 7) == 10);
}
