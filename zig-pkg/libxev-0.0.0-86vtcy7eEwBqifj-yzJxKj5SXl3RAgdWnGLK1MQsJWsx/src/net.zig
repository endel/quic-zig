//! Minimal network address types carried over from `std.net` (which was
//! removed in Zig 0.16 when networking moved under `std.Io.net`). libxev
//! only needs a thin wrapper around the platform `sockaddr` structures
//! for its socket-level APIs; the `std.Io.net.IpAddress` surface carries
//! an `Io` parameter and a different layout that does not fit libxev's
//! completion-based proactor.
//!
//! The exposed API mirrors the subset of the pre-0.16 `std.net.Address`
//! that libxev's backends and watchers relied on: `parseIp4`, `parseIp6`,
//! `initPosix`, `getPort`, `setPort`, `getOsSockLen`, plus direct field
//! access to `.any`, `.in`, and `.in6`.

const std = @import("std");
const builtin = @import("builtin");
const native_endian = builtin.cpu.arch.endian();
const posix = std.posix;
const mem = std.mem;

/// Replacement for the removed `std.posix.ShutdownHow`. Kept as an alias
/// over `syscall.ShutdownHow` so the two sites agree at the type level —
/// otherwise passing `xev_net.ShutdownHow` into `posix.shutdown` fails.
pub const ShutdownHow = @import("syscall.zig").ShutdownHow;

const has_unix_sockets = switch (builtin.os.tag) {
    .linux, .macos, .ios, .freebsd, .netbsd, .openbsd, .dragonfly, .illumos, .watchos, .tvos, .visionos => true,
    else => false,
};

pub const Address = extern union {
    any: posix.sockaddr,
    in: Ip4Address,
    in6: Ip6Address,
    un: if (has_unix_sockets) posix.sockaddr.un else void,

    pub fn parseIp(name: []const u8, port: u16) !Address {
        if (parseIp4(name, port)) |ip4| return ip4 else |err| switch (err) {
            error.Overflow,
            error.InvalidEnd,
            error.InvalidCharacter,
            error.Incomplete,
            error.NonCanonical,
            => {},
        }
        if (parseIp6(name, port)) |ip6| return ip6 else |err| switch (err) {
            error.Overflow,
            error.InvalidEnd,
            error.InvalidCharacter,
            error.Incomplete,
            error.InvalidIpv4Mapping,
            => {},
        }
        return error.InvalidIPAddressFormat;
    }

    pub fn parseIp4(buf: []const u8, port: u16) !Address {
        return .{ .in = try Ip4Address.parse(buf, port) };
    }

    pub fn parseIp6(buf: []const u8, port: u16) !Address {
        return .{ .in6 = try Ip6Address.parse(buf, port) };
    }

    pub fn initIp4(addr: [4]u8, port: u16) Address {
        return .{ .in = Ip4Address.init(addr, port) };
    }

    pub fn initIp6(addr: [16]u8, port: u16, flowinfo: u32, scope_id: u32) Address {
        return .{ .in6 = Ip6Address.init(addr, port, flowinfo, scope_id) };
    }

    pub fn initPosix(addr: *align(4) const posix.sockaddr) Address {
        var result: Address = undefined;
        const len = @min(@sizeOf(Address), sockaddrLen(addr));
        @memcpy(std.mem.asBytes(&result)[0..len], @as([*]const u8, @ptrCast(addr))[0..len]);
        return result;
    }

    pub fn getPort(self: Address) u16 {
        return switch (self.any.family) {
            posix.AF.INET => self.in.getPort(),
            posix.AF.INET6 => self.in6.getPort(),
            else => unreachable,
        };
    }

    pub fn setPort(self: *Address, port: u16) void {
        switch (self.any.family) {
            posix.AF.INET => self.in.setPort(port),
            posix.AF.INET6 => self.in6.setPort(port),
            else => unreachable,
        }
    }

    pub fn getOsSockLen(self: Address) posix.socklen_t {
        return switch (self.any.family) {
            posix.AF.INET => @sizeOf(posix.sockaddr.in),
            posix.AF.INET6 => @sizeOf(posix.sockaddr.in6),
            posix.AF.UNIX => if (has_unix_sockets) @sizeOf(posix.sockaddr.un) else unreachable,
            else => unreachable,
        };
    }

    pub fn eql(a: Address, b: Address) bool {
        const a_bytes = @as([*]const u8, @ptrCast(&a.any))[0..a.getOsSockLen()];
        const b_bytes = @as([*]const u8, @ptrCast(&b.any))[0..b.getOsSockLen()];
        return mem.eql(u8, a_bytes, b_bytes);
    }

    fn sockaddrLen(addr: *align(4) const posix.sockaddr) usize {
        return switch (addr.family) {
            posix.AF.INET => @sizeOf(posix.sockaddr.in),
            posix.AF.INET6 => @sizeOf(posix.sockaddr.in6),
            posix.AF.UNIX => if (has_unix_sockets) @sizeOf(posix.sockaddr.un) else 0,
            else => @sizeOf(posix.sockaddr),
        };
    }
};

pub const Ip4Address = extern struct {
    sa: posix.sockaddr.in,

    pub const ParseError = error{
        Overflow,
        InvalidEnd,
        InvalidCharacter,
        Incomplete,
        NonCanonical,
    };

    pub fn init(addr: [4]u8, port: u16) Ip4Address {
        return .{ .sa = .{
            .port = mem.nativeToBig(u16, port),
            .addr = @as(*align(1) const u32, @ptrCast(&addr)).*,
        } };
    }

    pub fn parse(buf: []const u8, port: u16) ParseError!Ip4Address {
        var result: Ip4Address = .{ .sa = .{
            .port = mem.nativeToBig(u16, port),
            .addr = undefined,
        } };
        const out_ptr = @as(*[4]u8, @ptrCast(&result.sa.addr));

        var x: u8 = 0;
        var index: u8 = 0;
        var saw_any_digits = false;
        var has_zero_prefix = false;
        for (buf) |c| {
            if (c == '.') {
                if (!saw_any_digits) return error.InvalidCharacter;
                if (index == 3) return error.InvalidEnd;
                out_ptr[index] = x;
                index += 1;
                x = 0;
                saw_any_digits = false;
                has_zero_prefix = false;
            } else if (c >= '0' and c <= '9') {
                if (c == '0' and !saw_any_digits) {
                    has_zero_prefix = true;
                } else if (has_zero_prefix) {
                    return error.NonCanonical;
                }
                saw_any_digits = true;
                x = try std.math.mul(u8, x, 10);
                x = try std.math.add(u8, x, c - '0');
            } else {
                return error.InvalidCharacter;
            }
        }
        if (index == 3 and saw_any_digits) {
            out_ptr[index] = x;
            return result;
        }
        return error.Incomplete;
    }

    pub fn getPort(self: Ip4Address) u16 {
        return mem.bigToNative(u16, self.sa.port);
    }

    pub fn setPort(self: *Ip4Address, port: u16) void {
        self.sa.port = mem.nativeToBig(u16, port);
    }
};

pub const Ip6Address = extern struct {
    sa: posix.sockaddr.in6,

    pub const ParseError = error{
        Overflow,
        InvalidEnd,
        InvalidCharacter,
        Incomplete,
        InvalidIpv4Mapping,
    };

    pub fn init(addr: [16]u8, port: u16, flowinfo: u32, scope_id: u32) Ip6Address {
        return .{ .sa = .{
            .scope_id = scope_id,
            .port = mem.nativeToBig(u16, port),
            .flowinfo = flowinfo,
            .addr = addr,
        } };
    }

    pub fn parse(buf: []const u8, port: u16) ParseError!Ip6Address {
        // Minimal: libxev never calls parseIp6 in production paths; fail loudly.
        _ = buf;
        _ = port;
        return error.Incomplete;
    }

    pub fn getPort(self: Ip6Address) u16 {
        return mem.bigToNative(u16, self.sa.port);
    }

    pub fn setPort(self: *Ip6Address, port: u16) void {
        self.sa.port = mem.nativeToBig(u16, port);
    }
};
