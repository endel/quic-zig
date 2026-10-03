// Microbenchmark for the codec hot paths affected by the std.Io migration.
// Pure CPU loops — no sockets, no threads — so we measure the actual cost
// of fixedBufferStream shim vs. std.Io.Reader/Writer.
//
// Run: zig build run-bench-codec -Doptimize=ReleaseFast

const std = @import("std");
const quic = @import("quic");
const sys = quic.sys;
const packet = quic.packet;
const frame_mod = quic.frame;
const h3_frame = quic.h3.frame;
const io_compat = quic.io_compat;

const ITER: usize = 10_000_000;

/// Accumulator that the compiler cannot prove is unread — exported so the
/// optimizer keeps the loop body live. Printed at end of main().
var sink: u64 = 0;

fn escape(comptime T: type, ptr: *const T) void {
    // Compiler barrier — treat pointee as clobbered so stores aren't dead.
    asm volatile (""
        :
        : [p] "r" (ptr),
        : .{ .memory = true });
}

fn escapeVal(value: anytype) void {
    asm volatile (""
        :
        : [v] "r" (value),
        : .{ .memory = true });
}

fn now() i64 {
    return sys.nanoTimestamp();
}

fn reportOp(name: []const u8, iters: usize, elapsed_ns: i64) void {
    const per_op_f = @as(f64, @floatFromInt(elapsed_ns)) / @as(f64, @floatFromInt(iters));
    const ops_per_sec = @divTrunc(@as(i64, @intCast(iters)) * std.time.ns_per_s, elapsed_ns);
    std.debug.print("{s:<32} {d:>8.2} ns/op  {d:>12} ops/s\n", .{ name, per_op_f, ops_per_sec });
}

pub fn main(_: std.process.Init.Minimal) !void {
    std.debug.print("quic-zig codec microbench — {d} iterations/target\n\n", .{ITER});

    // ── varint read ──────────────────────────────────────────────────────
    inline for ([_]struct { name: []const u8, bytes: []const u8 }{
        .{ .name = "readVarInt (1 byte)", .bytes = &[_]u8{0x25} },
        .{ .name = "readVarInt (2 byte)", .bytes = &[_]u8{ 0x7b, 0xbd } },
        .{ .name = "readVarInt (4 byte)", .bytes = &[_]u8{ 0x9d, 0x7f, 0x3e, 0x7d } },
        .{ .name = "readVarInt (8 byte)", .bytes = &[_]u8{ 0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c } },
    }) |tc| {
        const N = tc.bytes.len;
        var scratch: [N]u8 = tc.bytes[0..N].*;
        const start = now();
        var acc: u64 = 0;
        var i: usize = 0;
        while (i < ITER) : (i += 1) {
            escape([N]u8, &scratch);
            var fbs = io_compat.fixedBufferStream(@as([]const u8, &scratch));
            const r = &fbs;
            acc +%= packet.readVarInt(r) catch 0;
            escapeVal(acc);
        }
        const elapsed = now() - start;
        sink +%= acc;
        reportOp(tc.name, ITER, elapsed);
    }

    // ── varint write ────────────────────────────────────────────────────
    inline for ([_]struct { name: []const u8, value: u64 }{
        .{ .name = "writeVarInt (1 byte)", .value = 37 },
        .{ .name = "writeVarInt (2 byte)", .value = 15293 },
        .{ .name = "writeVarInt (4 byte)", .value = 494878333 },
        .{ .name = "writeVarInt (8 byte)", .value = 151288809941952652 },
    }) |tc| {
        var buf: [8]u8 = undefined;
        const start = now();
        var i: usize = 0;
        while (i < ITER) : (i += 1) {
            escape([8]u8, &buf);
            var fbs = io_compat.fixedBufferStream(&buf);
            packet.writeVarInt(&fbs, tc.value +% @as(u64, i & 0xff)) catch {};
            escape([8]u8, &buf);
        }
        const elapsed = now() - start;
        reportOp(tc.name, ITER, elapsed);
    }

    // ── QUIC frame parse (STREAM) ───────────────────────────────────────
    var stream_frame_buf: [64]u8 = undefined;
    const stream_len = blk: {
        var fbs = io_compat.fixedBufferStream(&stream_frame_buf);
        try packet.writeVarInt(&fbs, 0x0f); // STREAM OFF+LEN+FIN
        try packet.writeVarInt(&fbs, 4);
        try packet.writeVarInt(&fbs, 100);
        try packet.writeVarInt(&fbs, 16);
        try fbs.writeAll(&@as([16]u8, @splat(0)));
        break :blk fbs.seek;
    };
    {
        const start = now();
        var acc: u64 = 0;
        var i: usize = 0;
        while (i < ITER) : (i += 1) {
            var scratch = stream_frame_buf;
            const f = frame_mod.Frame.parse(scratch[0..stream_len]) catch unreachable;
            acc +%= f.stream.offset;
        }
        const elapsed = now() - start;
        sink +%= acc;
        reportOp("Frame.parse (STREAM)", ITER, elapsed);
    }

    // ── QUIC frame parse (ACK) ──────────────────────────────────────────
    var ack_frame_buf: [16]u8 = undefined;
    const ack_len = blk: {
        var fbs = io_compat.fixedBufferStream(&ack_frame_buf);
        try packet.writeVarInt(&fbs, 2);
        try packet.writeVarInt(&fbs, 100);
        try packet.writeVarInt(&fbs, 10);
        try packet.writeVarInt(&fbs, 0);
        try packet.writeVarInt(&fbs, 5);
        break :blk fbs.seek;
    };
    {
        const start = now();
        var acc: u64 = 0;
        var i: usize = 0;
        while (i < ITER) : (i += 1) {
            var scratch = ack_frame_buf;
            const f = frame_mod.Frame.parse(scratch[0..ack_len]) catch unreachable;
            acc +%= f.ack.largest_ack;
        }
        const elapsed = now() - start;
        sink +%= acc;
        reportOp("Frame.parse (ACK)", ITER, elapsed);
    }

    // ── QUIC frame serialize (STREAM) ───────────────────────────────────
    var stream_data: [16]u8 = @splat(0);
    const stream_frame: frame_mod.Frame = .{ .stream = .{
        .stream_id = 4,
        .offset = 100,
        .length = 16,
        .fin = true,
        .data = &stream_data,
    } };
    var serialize_buf: [128]u8 = undefined;
    {
        const start = now();
        var i: usize = 0;
        while (i < ITER) : (i += 1) {
            escape([128]u8, &serialize_buf);
            var fbs = io_compat.fixedBufferStream(&serialize_buf);
            try stream_frame.write(&fbs);
            escape([128]u8, &serialize_buf);
        }
        const elapsed = now() - start;
        reportOp("Frame.write (STREAM)", ITER, elapsed);
    }

    // ── H3 frame parse (DATA) ───────────────────────────────────────────
    var h3_buf: [64]u8 = undefined;
    const h3_len = blk: {
        var fbs = io_compat.fixedBufferStream(&h3_buf);
        try packet.writeVarInt(&fbs, 0); // DATA
        try packet.writeVarInt(&fbs, 16);
        try fbs.writeAll(&@as([16]u8, @splat(0)));
        break :blk fbs.seek;
    };
    {
        const start = now();
        var acc: u64 = 0;
        var i: usize = 0;
        while (i < ITER) : (i += 1) {
            escape([64]u8, &h3_buf);
            const r = h3_frame.parse(h3_buf[0..h3_len]) catch unreachable;
            acc +%= r.consumed;
            escapeVal(acc);
        }
        const elapsed = now() - start;
        sink +%= acc;
        reportOp("H3 frame.parse (DATA)", ITER, elapsed);
    }

    // ── H3 frame write (DATA) ───────────────────────────────────────────
    var h3_data_bytes: [16]u8 = @splat(0);
    const h3_data = h3_frame.H3Frame{ .data = &h3_data_bytes };
    {
        var out: [64]u8 = undefined;
        const start = now();
        var i: usize = 0;
        while (i < ITER) : (i += 1) {
            escape([64]u8, &out);
            var fbs = io_compat.fixedBufferStream(&out);
            try h3_frame.write(h3_data, &fbs);
            escape([64]u8, &out);
        }
        const elapsed = now() - start;
        reportOp("H3 frame.write (DATA)", ITER, elapsed);
    }

    std.debug.print("\n(sink = {x})\n", .{sink});
}
