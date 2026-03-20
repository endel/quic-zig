// Platform abstraction layer for QUIC core.
//
// On native targets, delegates to std.posix and std.time.
// On wasm32-freestanding, provides compatible types and imports
// time/random from the JS host environment.

const std = @import("std");
const builtin = @import("builtin");

const is_wasm = builtin.cpu.arch == .wasm32 and builtin.os.tag == .freestanding;

// ── Socket address types ──────────────────────────────────────────────
//
// On native targets these are just aliases for std.posix types.
// On WASM they are layout-compatible structs (the actual values are
// opaque — WASM code never talks to a real network stack).

pub const socklen_t = if (is_wasm) u32 else std.posix.socklen_t;

pub const AF = if (is_wasm) struct {
    pub const INET: u16 = 2;
    pub const INET6: u16 = if (builtin.os.tag == .freestanding) 10 else 30; // Linux=10, match our default
} else struct {
    pub const INET = std.posix.AF.INET;
    pub const INET6 = std.posix.AF.INET6;
};

pub const sockaddr = if (is_wasm) WasmSockaddr else std.posix.sockaddr;
pub const sockaddr_storage = if (is_wasm) WasmSockaddrStorage else std.posix.sockaddr.storage;
pub const sockaddr_in = if (is_wasm) WasmSockaddrIn else std.posix.sockaddr.in;
pub const sockaddr_in6 = if (is_wasm) WasmSockaddrIn6 else std.posix.sockaddr.in6;

// Provide nested namespace matching std.posix.sockaddr.{storage, in, in6}
pub const sockaddr_ns = if (is_wasm) struct {
    pub const storage = WasmSockaddrStorage;
    pub const in = WasmSockaddrIn;
    pub const in6 = WasmSockaddrIn6;
} else std.posix.sockaddr;

// ── WASM sockaddr definitions ─────────────────────────────────────────
// Layout-compatible with Linux sockaddr structs so the same pointer
// casts work. The actual field values are only meaningful for the
// QUIC state machine's address-comparison logic.

const WasmSockaddr = extern struct {
    family: u16 align(1) = 0,
    data: [14]u8 align(1) = .{0} ** 14,
};

const WasmSockaddrIn = extern struct {
    family: u16 align(1) = 0,
    port: u16 align(1) = 0,
    addr: u32 align(1) = 0,
    zero: [8]u8 align(1) = .{0} ** 8,
};

const WasmSockaddrStorage = extern struct {
    family: u16 align(1) = 0,
    padding: [126]u8 align(1) = .{0} ** 126,
};

const WasmSockaddrIn6 = extern struct {
    family: u16 align(1) = 0,
    port: u16 align(1) = 0,
    flowinfo: u32 align(1) = 0,
    addr: [16]u8 align(1) = .{0} ** 16,
    scope_id: u32 align(1) = 0,
};

// ── Time ──────────────────────────────────────────────────────────────

pub fn nanoTimestamp() i64 {
    if (is_wasm) {
        return wasm_get_time_ns();
    } else {
        return @intCast(std.time.nanoTimestamp());
    }
}

pub fn timestamp() i64 {
    if (is_wasm) {
        return @divTrunc(wasm_get_time_ns(), std.time.ns_per_s);
    } else {
        return std.time.timestamp();
    }
}

pub const ns_per_s = std.time.ns_per_s;

// ── File abstraction (for keylog_file in TlsConfig) ──────────────────

pub const File = if (is_wasm) WasmFile else std.fs.File;

// Stub file type for WASM — write is a no-op (keylog is never set).
pub const WasmFile = struct {
    pub fn write(_: WasmFile, _: []const u8) error{}!usize {
        return 0;
    }
    pub fn close(_: WasmFile) void {}
};

// ── WASM imports ──────────────────────────────────────────────────────

extern "env" fn get_time_ns() i64;

fn wasm_get_time_ns() i64 {
    return get_time_ns();
}

// ── Tests ─────────────────────────────────────────────────────────────

test "platform: nanoTimestamp returns positive value" {
    const t = nanoTimestamp();
    try std.testing.expect(t > 0);
}

test "platform: sockaddr_storage size" {
    // Ensure our WASM types are at least as large as needed
    try std.testing.expect(@sizeOf(sockaddr_storage) >= 28); // at least fits in6
}

test "platform: AF constants" {
    try std.testing.expect(AF.INET != AF.INET6);
    try std.testing.expect(AF.INET == 2);
}
