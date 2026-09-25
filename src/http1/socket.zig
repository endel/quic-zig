//! An accepted TCP connection on the server's libxev loop.
//!
//! Wraps `xev.TCP` with what every connection needs: one re-armed read,
//! ordered writes with a double buffer (the in-flight slice must not move
//! while the kernel reads it), read pausing for backpressure, and a close
//! that waits for in-flight operations before releasing the fd.
//!
//! `Owner` receives events through these methods:
//!   - `onSocketData(owner, bytes)`: bytes are only valid during the call,
//!     and the owner may modify them in place.
//!   - `onSocketEof(owner)`: the peer finished sending, or the connection
//!     failed. The owner usually aborts.
//!   - `onSocketWritable(owner)`: output drained below `low_water`.
//!   - `onSocketClosed(owner)`: the fd is closed and no callback will follow;
//!     the owner may free itself. Always called from a deferred callback,
//!     never from inside `write` or `abort`.
//!
//! A trimmed port of routez's `net/socket.zig`: no connect, sendfile, relay
//! or corking.

const std = @import("std");
const builtin = @import("builtin");
const xev = @import("../xev_backend.zig").xev;
const timers = @import("timers.zig");

/// With epoll every socket on a thread reads into one buffer, so an idle
/// connection doesn't hold one: epoll reads only just before running that
/// read's callback. Other backends can read ahead and queue the callback
/// (kqueue does), so there each socket keeps its own. Either way,
/// `onSocketData` bytes are gone once the call returns.
const shared_read_buf = xev.backend == .epoll;
/// Shared, it can be large: a 64 KiB message arrives in one read rather than
/// four (uWS reads up to 512 KiB). Per socket, it is what an idle connection
/// costs, so it stays small.
pub const read_buffer_size = if (shared_read_buf) 256 * 1024 else 16 * 1024;
threadlocal var thread_read_buf: [read_buffer_size]u8 = undefined;
/// A library can't ignore SIGPIPE for its host process: MSG_NOSIGNAL on
/// Linux, SO_NOSIGPIPE on Darwin.
const send_flags: c_int = if (builtin.os.tag == .linux) std.posix.MSG.NOSIGNAL else 0;
/// Owners stop producing output above this.
pub const high_water = 256 * 1024;
pub const low_water = 64 * 1024;

pub fn Socket(comptime Owner: type) type {
    return struct {
        const Self = @This();

        tcp: xev.TCP,
        loop: *xev.Loop,
        timers: *timers.Timers,
        alloc: std.mem.Allocator,
        owner: *Owner,

        read_c: xev.Completion = .{},
        write_c: xev.Completion = .{},
        closed_cb: timers.Deferred = .{ .callback = onDeferredClose },

        reading: bool = false,
        read_paused: bool = false,
        writing: bool = false,

        /// Slice being written by the kernel; never appended to while `writing`.
        active: std.ArrayList(u8) = .empty,
        active_off: usize = 0,
        pending: std.ArrayList(u8) = .empty,

        state: State = .open,
        fd_closed: bool = false,
        /// Allocated apart from the owner: inline, it would push the owner's
        /// fields onto a second page that every connection then touches.
        own_read_buf: if (shared_read_buf) void else ?*[read_buffer_size]u8 = if (shared_read_buf) {} else null,

        pub const State = enum {
            open,
            /// Write what is queued, then half-close and wait for the peer's FIN.
            flushing,
            /// Write side shut; reading and discarding until EOF.
            lingering,
            closing,
            closed,
        };

        pub fn init(self: *Self, owner: *Owner, loop: *xev.Loop, t: *timers.Timers, alloc: std.mem.Allocator, tcp: xev.TCP) !void {
            self.* = .{ .tcp = tcp, .loop = loop, .timers = t, .alloc = alloc, .owner = owner };
            if (!shared_read_buf) self.own_read_buf = try alloc.create([read_buffer_size]u8);
            setNoSigpipe(tcp.fd);
            // A response is often a head write then a body write; with Nagle
            // the second waits on the client's delayed ACK (~40 ms on Linux).
            setNoDelay(tcp.fd);
        }

        pub fn fd(self: *const Self) std.posix.socket_t {
            return self.tcp.fd;
        }

        pub fn isOpen(self: *const Self) bool {
            return self.state == .open;
        }

        pub fn startReading(self: *Self) void {
            if (self.reading or self.read_paused) return;
            if (self.state == .closing or self.state == .closed) return;
            self.reading = true;
            self.tcp.read(self.loop, &self.read_c, .{ .slice = self.readBuf() }, Self, self, onRead);
        }

        fn readBuf(self: *Self) *[read_buffer_size]u8 {
            return if (shared_read_buf) &thread_read_buf else self.own_read_buf.?;
        }

        pub fn pauseRead(self: *Self) void {
            self.read_paused = true;
        }

        pub fn resumeRead(self: *Self) void {
            if (!self.read_paused) return;
            self.read_paused = false;
            self.startReading();
        }

        fn onRead(ud: ?*Self, _: *xev.Loop, _: *xev.Completion, _: xev.TCP, _: xev.ReadBuffer, r: xev.ReadError!usize) xev.CallbackAction {
            const self = ud.?;
            const n = r catch {
                self.reading = false;
                switch (self.state) {
                    .open, .flushing => Owner.onSocketEof(self.owner),
                    .lingering => self.abort(),
                    .closing, .closed => {},
                }
                self.maybeFinishClose();
                return .disarm;
            };
            switch (self.state) {
                .open, .flushing => Owner.onSocketData(self.owner, self.readBuf()[0..n]),
                .lingering, .closing, .closed => {},
            }
            if (self.state == .closing or self.state == .closed) {
                self.reading = false;
                self.maybeFinishClose();
                return .disarm;
            }
            if (self.read_paused and self.state != .lingering) {
                self.reading = false;
                return .disarm;
            }
            return .rearm;
        }

        /// Queue bytes for sending. Dropped silently once the socket is
        /// closing; a failure closes it, reported through `onSocketClosed`.
        pub fn write(self: *Self, data_in: []const u8) void {
            if (self.state != .open) return;
            if (data_in.len == 0) return;
            var data = data_in;
            // Nothing queued: try the kernel directly. A write completion
            // costs an epoll registration round trip (and on epoll a dup of
            // the fd), which most writes to a healthy socket don't need.
            if (!self.writing and self.buffered() == 0) {
                const rc = std.c.send(self.tcp.fd, data.ptr, data.len, send_flags);
                if (rc > 0) {
                    const n: usize = @intCast(rc);
                    if (n == data.len) return;
                    data = data[n..];
                }
                // An error (not EAGAIN) resurfaces on the queued write below.
            }
            self.pending.appendSlice(self.alloc, data) catch {
                self.abort();
                return;
            };
            self.kickWrite();
        }

        /// `write` for several pieces: one `sendmsg` when the kernel takes
        /// them all, where writing them one by one costs a syscall each.
        pub fn writeVec(self: *Self, parts: []const []const u8) void {
            if (self.state != .open) return;
            var sent: usize = 0;
            if (!self.writing and self.buffered() == 0) {
                var iov: [4]std.posix.iovec_const = undefined;
                std.debug.assert(parts.len <= iov.len);
                for (parts, 0..) |part, i| iov[i] = .{ .base = part.ptr, .len = part.len };
                const msg: std.c.msghdr_const = .{
                    .name = null,
                    .namelen = 0,
                    .iov = &iov,
                    .iovlen = @intCast(parts.len),
                    .control = null,
                    .controllen = 0,
                    .flags = 0,
                };
                const rc = std.c.sendmsg(self.tcp.fd, &msg, @intCast(send_flags));
                // An error (not EAGAIN) resurfaces on the queued write below.
                if (rc > 0) sent = @intCast(rc);
            }
            var queued = false;
            for (parts) |part| {
                if (sent >= part.len) {
                    sent -= part.len;
                    continue;
                }
                self.pending.appendSlice(self.alloc, part[sent..]) catch {
                    self.abort();
                    return;
                };
                sent = 0;
                queued = true;
            }
            if (queued) self.kickWrite();
        }

        /// Bytes queued and not yet accepted by the kernel.
        pub fn buffered(self: *const Self) usize {
            return (self.active.items.len - self.active_off) + self.pending.items.len;
        }

        fn kickWrite(self: *Self) void {
            if (self.writing) return;
            if (self.state == .closing or self.state == .closed or self.state == .lingering) return;
            if (self.active_off >= self.active.items.len) {
                self.active.clearRetainingCapacity();
                self.active_off = 0;
                if (self.pending.items.len == 0) {
                    if (self.state == .flushing) self.finishFlush();
                    return;
                }
                std.mem.swap(std.ArrayList(u8), &self.active, &self.pending);
            }
            self.writing = true;
            self.tcp.write(self.loop, &self.write_c, .{ .slice = self.active.items[self.active_off..] }, Self, self, onWrite);
        }

        fn onWrite(ud: ?*Self, _: *xev.Loop, _: *xev.Completion, _: xev.TCP, _: xev.WriteBuffer, r: xev.WriteError!usize) xev.CallbackAction {
            const self = ud.?;
            self.writing = false;
            if (self.state == .closing or self.state == .closed) {
                self.maybeFinishClose();
                return .disarm;
            }
            const n = r catch {
                self.dropOutput();
                if (self.state == .open) Owner.onSocketEof(self.owner) else self.abort();
                self.maybeFinishClose();
                return .disarm;
            };
            self.active_off += n;
            if (self.active_off >= self.active.items.len) {
                self.active.clearRetainingCapacity();
                self.active_off = 0;
            }
            self.kickWrite();
            if (self.state == .open and self.buffered() < low_water) Owner.onSocketWritable(self.owner);
            return .disarm;
        }

        /// Send what is queued, then close gracefully.
        pub fn closeAfterFlush(self: *Self) void {
            if (self.state != .open) return;
            self.state = .flushing;
            if (!self.writing) self.kickWrite();
        }

        fn finishFlush(self: *Self) void {
            // Half-close so the peer sees everything we sent before any RST
            // that closing with unread input would trigger.
            _ = std.c.shutdown(self.tcp.fd, std.posix.SHUT.WR);
            self.state = .lingering;
            self.read_paused = false;
            self.startReading();
        }

        /// Close now, discarding queued output. Idempotent.
        pub fn abort(self: *Self) void {
            switch (self.state) {
                .closing, .closed => return,
                else => {},
            }
            self.state = .closing;
            self.dropOutput();
            // Wakes any in-flight read or write so it completes promptly.
            _ = std.c.shutdown(self.tcp.fd, std.posix.SHUT.RDWR);
            self.maybeFinishClose();
        }

        fn dropOutput(self: *Self) void {
            if (!self.writing) {
                self.active.clearAndFree(self.alloc);
                self.active_off = 0;
            }
            self.pending.clearAndFree(self.alloc);
        }

        fn maybeFinishClose(self: *Self) void {
            if (self.state != .closing) return;
            if (self.reading or self.writing) return;
            self.state = .closed;
            // The fd is closed from the deferred callback, not here: this
            // may run inside a completion's callback, and libxev's epoll
            // backend deregisters that fd after the callback returns.
            self.active.clearAndFree(self.alloc);
            self.pending.clearAndFree(self.alloc);
            self.timers.defer_(&self.closed_cb);
        }

        fn onDeferredClose(d: *timers.Deferred) void {
            const self: *Self = @fieldParentPtr("closed_cb", d);
            self.closeFd();
            self.freeReadBuf();
            Owner.onSocketClosed(self.owner);
        }

        fn freeReadBuf(self: *Self) void {
            if (shared_read_buf) return;
            if (self.own_read_buf) |b| self.alloc.destroy(b);
            self.own_read_buf = null;
        }

        /// Close the fd now: for a server tearing down on a loop that will
        /// not run again, where no completion is left to wait for.
        pub fn closeFd(self: *Self) void {
            if (self.fd_closed) return;
            self.fd_closed = true;
            _ = std.c.close(self.tcp.fd);
        }

        /// Free the buffers without touching the fd; see `closeFd`.
        pub fn freeBuffers(self: *Self) void {
            self.active.clearAndFree(self.alloc);
            self.pending.clearAndFree(self.alloc);
            self.freeReadBuf();
        }
    };
}

/// Accept one queued connection without waiting; null when none is queued.
pub fn acceptNow(listen_fd: std.posix.socket_t) ?std.posix.socket_t {
    if (comptime builtin.os.tag == .linux) {
        const fd = std.c.accept4(listen_fd, null, null, std.posix.SOCK.NONBLOCK | std.posix.SOCK.CLOEXEC);
        return if (fd < 0) null else fd;
    }
    const fd = std.c.accept(listen_fd, null, null);
    if (fd < 0) return null;
    setNonBlocking(fd);
    _ = std.c.fcntl(fd, std.c.F.SETFD, @as(c_int, std.c.FD_CLOEXEC));
    return fd;
}

pub fn setNonBlocking(fd: std.posix.socket_t) void {
    const nonblock: u32 = @bitCast(std.c.O{ .NONBLOCK = true });
    const flags = std.c.fcntl(fd, std.c.F.GETFL, @as(c_int, 0));
    _ = std.c.fcntl(fd, std.c.F.SETFL, flags | @as(c_int, @bitCast(nonblock)));
}

pub fn setNoDelay(fd: std.posix.socket_t) void {
    const one: c_int = 1;
    _ = std.c.setsockopt(fd, std.posix.IPPROTO.TCP, std.posix.TCP.NODELAY, std.mem.asBytes(&one), @sizeOf(c_int));
}

fn setNoSigpipe(fd: std.posix.socket_t) void {
    if (comptime builtin.os.tag.isDarwin()) {
        const one: c_int = 1;
        _ = std.c.setsockopt(fd, std.posix.SOL.SOCKET, std.c.SO.NOSIGPIPE, std.mem.asBytes(&one), @sizeOf(c_int));
    }
}
