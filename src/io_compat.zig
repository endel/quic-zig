//! Fixed-buffer stream over a `[]u8` / `[]const u8`, exposing the
//! `std.Io.Reader` / `std.Io.Writer`-compatible method surface used by
//! our encode/decode paths (`takeByte`, `takeInt`, `readSliceAll`,
//! `readSliceShort`, `takeArray`, `writeAll`, `writeByte`, `writeInt`,
//! `buffered`).
//!
//! Zig 0.16 replaced `std.io.fixedBufferStream` with
//! `std.Io.Reader.fixed` / `std.Io.Writer.fixed`, but the stdlib split
//! reader and writer into separate types — inconvenient for the many
//! call sites that read and write the same buffer. This keeps a unified
//! FBS with the 0.16 method names, so callers can pass `&fbs` to any
//! `anytype` reader/writer parameter.

const std = @import("std");
const mem = std.mem;

pub fn FixedBufferStream(comptime Buffer: type) type {
    comptime std.debug.assert(@typeInfo(Buffer) == .pointer);
    const is_const_buf = @typeInfo(Buffer).pointer.attrs.@"const";
    const Slice = if (is_const_buf) []const u8 else []u8;

    return struct {
        buffer: Slice,
        seek: usize,

        const Self = @This();
        const is_const = is_const_buf;

        pub const ReadError = error{};
        pub const WriteError = error{NoSpaceLeft};

        pub fn takeByte(self: *Self) error{EndOfStream}!u8 {
            if (self.seek >= self.buffer.len) return error.EndOfStream;
            const b = self.buffer[self.seek];
            self.seek += 1;
            return b;
        }

        pub fn takeInt(self: *Self, comptime T: type, endian: std.builtin.Endian) error{EndOfStream}!T {
            const n = @divExact(@typeInfo(T).int.bits, 8);
            if (self.buffer.len - self.seek < n) return error.EndOfStream;
            const slice = self.buffer[self.seek..][0..n];
            self.seek += n;
            return mem.readInt(T, slice, endian);
        }

        pub fn readSliceAll(self: *Self, dest: []u8) error{EndOfStream}!void {
            if (self.buffer.len - self.seek < dest.len) return error.EndOfStream;
            @memcpy(dest, self.buffer[self.seek..][0..dest.len]);
            self.seek += dest.len;
        }

        pub fn readSliceShort(self: *Self, dest: []u8) ReadError!usize {
            const n = @min(dest.len, self.buffer.len - self.seek);
            @memcpy(dest[0..n], self.buffer[self.seek..][0..n]);
            self.seek += n;
            return n;
        }

        pub fn takeArray(self: *Self, comptime n: usize) error{EndOfStream}!*[n]u8 {
            if (self.buffer.len - self.seek < n) return error.EndOfStream;
            const ptr: *[n]u8 = @ptrCast(self.buffer[self.seek..][0..n].ptr);
            self.seek += n;
            return ptr;
        }

        pub fn writeAll(self: *Self, bytes: []const u8) WriteError!void {
            if (comptime is_const) return;
            if (bytes.len > self.buffer.len - self.seek) return error.NoSpaceLeft;
            @memcpy(self.buffer[self.seek..][0..bytes.len], bytes);
            self.seek += bytes.len;
        }

        pub fn writeByte(self: *Self, byte: u8) WriteError!void {
            if (comptime is_const) return;
            if (self.seek >= self.buffer.len) return error.NoSpaceLeft;
            self.buffer[self.seek] = byte;
            self.seek += 1;
        }

        pub fn writeInt(self: *Self, comptime T: type, value: T, endian: std.builtin.Endian) WriteError!void {
            if (comptime is_const) return;
            const n = @divExact(@typeInfo(T).int.bits, 8);
            if (self.buffer.len - self.seek < n) return error.NoSpaceLeft;
            mem.writeInt(T, self.buffer[self.seek..][0..n], value, endian);
            self.seek += n;
        }

        pub fn buffered(self: *const Self) Slice {
            return self.buffer[0..self.seek];
        }

        pub fn seekBy(self: *Self, offset: usize) error{NoSpaceLeft}!void {
            if (offset > self.buffer.len - self.seek) return error.NoSpaceLeft;
            self.seek += offset;
        }
    };
}

pub fn fixedBufferStream(buffer: anytype) FixedBufferStream(@TypeOf(buffer)) {
    return .{ .buffer = buffer[0..], .seek = 0 };
}
