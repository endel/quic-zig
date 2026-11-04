//! One HTTP request and its response, the same over HTTP/1.1 and HTTP/3:
//! what a handler with `onHttpHead` is offered, on the HTTP/1.1 listener and
//! for the ordinary requests of an `.h3` or `.webtransport` server.
//!
//! The head comes first (`onHttpHead`), the body in pieces as it arrives
//! (`onHttpBody`), then its end (`onHttpEnd`). The handler answers whenever
//! it is ready: in one go (`respond`), or a head, then pieces (`write`),
//! then `finish`; `onHttpWritable` says when queued output has drained. An
//! answer started before the body ended leaves the rest unread: HTTP/1.1
//! closes the connection after it, HTTP/3 stops the stream.
//!
//! Valid from `onHttpHead` until `finish` or `abort` returns, or until
//! `onHttpGone` says the peer left first; no callback for it follows
//! either. Use it on the loop's thread only.

const std = @import("std");
const posix = std.posix;
const Mailbox = @import("../mailbox.zig").Mailbox;

pub const Header = @import("../h3/qpack.zig").Header;

pub const Exchange = struct {
    /// The request head, during `onHttpHead` only.
    method: []const u8 = "",
    target: []const u8 = "",
    headers: []const Header = &.{},
    /// Null when the body's length is not known up front (chunked, or an
    /// HTTP/3 request without content-length).
    content_length: ?u64 = null,
    /// The handler's own, kept with the exchange.
    user_data: ?*anyopaque = null,
    /// A HEAD: the answer's body is left out.
    head_only: bool = false,
    /// `pass` was called in `onHttpHead`: the transport serves it.
    passed: bool = false,
    /// Its loop's: work done on another thread posts its answer back here.
    mailbox: ?*Mailbox = null,
    answer: Answer = .none,
    impl: *anyopaque,
    vtable: *const VTable,

    pub const Answer = enum {
        none,
        /// Its head is out, and it has no body: HEAD, 1xx, 204, 304.
        bodiless,
        body,
        /// Finished, aborted or gone.
        done,
    };

    pub const WriteError = error{
        /// Finished, aborted or gone.
        Closed,
    };

    pub const Framing = union(enum) {
        /// The status has no body.
        none,
        length: u64,
        /// HTTP/1.1 sends it chunked.
        unknown,
    };

    /// What a transport does; the rules around it are the `Exchange`'s.
    pub const VTable = struct {
        peer: *const fn (*anyopaque) *const posix.sockaddr.storage,
        /// The status line and `headers`, less those `transportsOwn`.
        head: *const fn (*anyopaque, status: u16, headers: []const Header, framing: Framing) WriteError!void,
        body: *const fn (*anyopaque, data: []const u8) WriteError!void,
        /// The answer is whole; nothing more comes for the exchange.
        end: *const fn (*anyopaque) void,
        reset: *const fn (*anyopaque) void,
        buffered: *const fn (*anyopaque) usize,
        /// Holds output back until uncorked, so an answer leaves in one send.
        cork: *const fn (*anyopaque, on: bool) void,
    };

    /// An exchange no request has: what a transport keeps between them.
    pub const idle: Exchange = .{ .answer = .done, .impl = undefined, .vtable = undefined };

    pub fn peerAddress(self: *const Exchange) *const posix.sockaddr.storage {
        return self.vtable.peer(self.impl);
    }

    /// The whole answer, in one send where the transport can: head,
    /// `body` (left out for HEAD), finish.
    pub fn respond(self: *Exchange, status: u16, headers: []const Header, body: []const u8) void {
        self.vtable.cork(self.impl, true);
        self.sendHead(status, headers, body.len) catch return;
        self.write(body) catch return;
        self.vtable.cork(self.impl, false);
        self.finish();
    }

    /// The status line and `headers`. Content-Length comes from
    /// `content_length`; without one, HTTP/1.1 sends the body chunked.
    /// Connection and framing headers are the transport's own.
    pub fn sendHead(self: *Exchange, status: u16, headers: []const Header, content_length: ?u64) WriteError!void {
        if (self.answer != .none) return error.Closed;
        const no_body = status < 200 or status == 204 or status == 304;
        const framing: Framing = if (no_body) .none else if (content_length) |n| .{ .length = n } else .unknown;
        self.answer = if (no_body or self.head_only) .bodiless else .body;
        self.vtable.head(self.impl, status, headers, framing) catch {
            self.abort();
            return error.Closed;
        };
    }

    /// Queues all of `data` (nothing for HEAD). Past the transport's low
    /// water, `onHttpWritable` follows once it drains: a producer waits for it.
    pub fn write(self: *Exchange, data: []const u8) WriteError!void {
        switch (self.answer) {
            .none, .done => return error.Closed,
            .bodiless => return,
            .body => if (data.len == 0) return,
        }
        self.vtable.body(self.impl, data) catch {
            self.abort();
            return error.Closed;
        };
    }

    /// Without a head sent, the answer is a 204.
    pub fn finish(self: *Exchange) void {
        switch (self.answer) {
            .done => return,
            .none => self.sendHead(204, &.{}, null) catch return,
            .bodiless, .body => {},
        }
        self.answer = .done;
        self.vtable.end(self.impl);
    }

    /// Ends it without a proper answer: the connection (HTTP/1.1) or the
    /// stream (HTTP/3) is reset, so the peer can tell.
    pub fn abort(self: *Exchange) void {
        if (self.answer == .done) return;
        self.answer = .done;
        self.vtable.reset(self.impl);
    }

    /// Bytes of the answer queued and not yet sent.
    pub fn bufferedAmount(self: *const Exchange) usize {
        return self.vtable.buffered(self.impl);
    }

    /// Inside `onHttpHead` only: serve the request as if never offered. On
    /// HTTP/1.1 that is the static files, the raw handler or a 404; on
    /// HTTP/3, a 404.
    pub fn pass(self: *Exchange) void {
        if (self.method.len != 0 and self.answer == .none) self.passed = true;
    }
};

/// Headers a transport writes itself, or that HTTP/3 forbids.
pub fn transportsOwn(name: []const u8) bool {
    for ([_][]const u8{ "connection", "content-length", "keep-alive", "proxy-connection", "transfer-encoding", "upgrade" }) |n| {
        if (std.ascii.eqlIgnoreCase(name, n)) return true;
    }
    return false;
}
