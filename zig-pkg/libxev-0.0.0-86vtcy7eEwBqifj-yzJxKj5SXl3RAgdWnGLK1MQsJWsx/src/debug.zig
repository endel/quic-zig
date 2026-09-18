const std = @import("std");

inline fn indent(depth: usize, writer: anytype) !void {
    for (0..depth) |_| try writer.writeByte(' ');
}

pub fn describe(comptime T: type, writer: anytype, depth: usize) !void {
    const type_info = @typeInfo(T);
    switch (type_info) {
        .type,
        .void,
        .bool,
        .noreturn,
        .int,
        .float,
        .pointer,
        .array,
        .comptime_float,
        .comptime_int,
        .undefined,
        .null,
        .optional,
        .error_union,
        .error_set,
        .@"enum",
        .@"fn",
        .@"opaque",
        .frame,
        .@"anyframe",
        .vector,
        .enum_literal,
        => {
            try writer.print("{s} ({d} bytes)", .{ @typeName(T), @sizeOf(T) });
        },
        .@"union" => |s| {
            try writer.print("{s} ({d} bytes) {{\n", .{ @typeName(T), @sizeOf(T) });
            inline for (s.fields) |f| {
                try indent(depth + 4, writer);
                try writer.print("{s}: ", .{f.name});
                try describe(f.type, writer, depth + 4);
                try writer.writeByte('\n');
            }
            try indent(depth, writer);
            try writer.writeByte('}');
        },
        .@"struct" => |s| {
            try writer.print("{s} ({d} bytes) {{\n", .{ @typeName(T), @sizeOf(T) });
            inline for (s.fields) |f| {
                try indent(depth + 4, writer);
                try writer.print("{s}: ", .{f.name});
                try describe(f.type, writer, depth + 4);
                try writer.writeByte('\n');
            }
            try indent(depth, writer);
            try writer.writeByte('}');
        },
    }
}
