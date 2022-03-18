const std = @import("std");
// const picotls = @cImport("picotls-c/");

pub fn main() anyerror!void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();

    std.log.info("Hello world!", .{});
}
