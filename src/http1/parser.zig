//! HTTP/1.1 request heads (RFC 9112).
//!
//! Heads are parsed only once complete (`\r\n\r\n` seen), which keeps the
//! parser a pure function over a buffer; the caller bounds the buffer by
//! `Limits.max_head`. Parsed slices point into that buffer.
//!
//! Framing is strict where ambiguity enables request smuggling: requests with
//! both Content-Length and Transfer-Encoding, conflicting Content-Lengths,
//! transfer codings other than a final `chunked`, obs-fold, and whitespace
//! before the colon are all rejected.
//!
//! Ported from routez's `http1/parser.zig` (request half).

const std = @import("std");

pub const Header = struct {
    name: []const u8,
    value: []const u8,
};

pub const Version = enum {
    http10,
    http11,

    pub fn text(self: Version) []const u8 {
        return switch (self) {
            .http10 => "HTTP/1.0",
            .http11 => "HTTP/1.1",
        };
    }
};

pub const Limits = struct {
    max_head: usize = 16 * 1024,
    max_headers: usize = 100,
};

pub const Error = error{
    BadRequest,
    HeadTooLarge,
    TooManyHeaders,
    VersionNotSupported,
    /// A transfer coding we don't implement.
    NotImplemented,
};

pub const RequestHead = struct {
    method: []const u8,
    target: []const u8,
    version: Version,
    headers: []Header,
    content_length: ?u64 = null,
    chunked: bool = false,
    keep_alive: bool,
    host: ?[]const u8 = null,
    expect_continue: bool = false,
    /// The `Upgrade` value, when `Connection` also lists `upgrade`.
    upgrade: ?[]const u8 = null,

    pub fn hasBody(self: *const RequestHead) bool {
        return self.chunked or (self.content_length orelse 0) > 0;
    }

    pub fn get(self: *const RequestHead, name: []const u8) ?[]const u8 {
        return getHeader(self.headers, name);
    }
};

pub const Parsed = struct { head: RequestHead, len: usize };

/// The first header named `name`, compared case-insensitively.
pub fn getHeader(headers: []const Header, name: []const u8) ?[]const u8 {
    for (headers) |h| {
        if (std.ascii.eqlIgnoreCase(h.name, name)) return h.value;
    }
    return null;
}

/// Whether any comma-separated element of any `name` header equals `token`,
/// case-insensitively. `Connection: keep-alive, Upgrade` has `upgrade`.
pub fn headerHasToken(headers: []const Header, name: []const u8, token: []const u8) bool {
    for (headers) |h| {
        if (!std.ascii.eqlIgnoreCase(h.name, name)) continue;
        var it = std.mem.tokenizeAny(u8, h.value, ", \t");
        while (it.next()) |tok| {
            if (std.ascii.eqlIgnoreCase(tok, token)) return true;
        }
    }
    return false;
}

pub fn isTokenChar(c: u8) bool {
    return switch (c) {
        'a'...'z', 'A'...'Z', '0'...'9' => true,
        '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~' => true,
        else => false,
    };
}

pub fn isToken(s: []const u8) bool {
    if (s.len == 0) return false;
    for (s) |c| if (!isTokenChar(c)) return false;
    return true;
}

/// field-value characters: VCHAR, SP, HTAB, obs-text. Rejects CR, LF, NUL.
pub fn isFieldValue(s: []const u8) bool {
    for (s) |c| {
        if (c == '\t' or c == ' ') continue;
        if (c < 0x21 or c == 0x7f) return false;
    }
    return true;
}

/// Index just past the blank line ending the head, or null if not there yet.
/// `from` lets the caller resume scanning after bytes it already searched.
pub fn findHeadEnd(buf: []const u8, from: usize) ?usize {
    const start = if (from >= 3) from - 3 else 0;
    const idx = std.mem.indexOfPos(u8, buf, start, "\r\n\r\n") orelse return null;
    return idx + 4;
}

const Lines = struct {
    buf: []const u8,
    pos: usize = 0,

    fn next(self: *Lines) ?[]const u8 {
        const end = std.mem.indexOfPos(u8, self.buf, self.pos, "\r\n") orelse return null;
        const line = self.buf[self.pos..end];
        self.pos = end + 2;
        return line;
    }
};

fn parseVersion(s: []const u8) Error!Version {
    if (std.mem.eql(u8, s, "HTTP/1.1")) return .http11;
    if (std.mem.eql(u8, s, "HTTP/1.0")) return .http10;
    if (s.len == 8 and std.mem.startsWith(u8, s, "HTTP/") and std.ascii.isDigit(s[5]) and s[6] == '.' and std.ascii.isDigit(s[7])) {
        return error.VersionNotSupported;
    }
    return error.BadRequest;
}

/// Split header lines into `out`. Returns the filled prefix.
fn parseHeaderLines(lines: *Lines, out: []Header) Error![]Header {
    var n: usize = 0;
    while (lines.next()) |line| {
        if (line.len == 0) return out[0..n];
        // obs-fold
        if (line[0] == ' ' or line[0] == '\t') return error.BadRequest;
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse return error.BadRequest;
        const name = line[0..colon];
        if (!isToken(name)) return error.BadRequest;
        const value = std.mem.trim(u8, line[colon + 1 ..], " \t");
        if (!isFieldValue(value)) return error.BadRequest;
        if (n == out.len) return error.TooManyHeaders;
        out[n] = .{ .name = name, .value = value };
        n += 1;
    }
    return error.BadRequest;
}

const Framing = struct {
    content_length: ?u64 = null,
    chunked: bool = false,
    has_te: bool = false,
    other_coding: bool = false,
    close: bool = false,
    keep_alive_token: bool = false,
    upgrade_token: bool = false,
};

fn scanFraming(headers: []const Header) Error!Framing {
    var f: Framing = .{};
    for (headers) |h| {
        if (std.ascii.eqlIgnoreCase(h.name, "content-length")) {
            // A list of identical values is allowed (RFC 9110 §8.6); anything else is not.
            var it = std.mem.splitScalar(u8, h.value, ',');
            while (it.next()) |raw| {
                const v = std.mem.trim(u8, raw, " \t");
                if (v.len == 0 or v.len > 19) return error.BadRequest;
                for (v) |c| if (!std.ascii.isDigit(c)) return error.BadRequest;
                const n = std.fmt.parseInt(u64, v, 10) catch return error.BadRequest;
                if (f.content_length) |prev| {
                    if (prev != n) return error.BadRequest;
                }
                f.content_length = n;
            }
        } else if (std.ascii.eqlIgnoreCase(h.name, "transfer-encoding")) {
            f.has_te = true;
            var it = std.mem.splitScalar(u8, h.value, ',');
            while (it.next()) |raw| {
                const v = std.mem.trim(u8, raw, " \t");
                if (v.len == 0) continue;
                // chunked must be last and appear once
                if (f.chunked) return error.BadRequest;
                if (std.ascii.eqlIgnoreCase(v, "chunked")) {
                    f.chunked = true;
                } else {
                    f.other_coding = true;
                }
            }
        } else if (std.ascii.eqlIgnoreCase(h.name, "connection")) {
            var it = std.mem.tokenizeAny(u8, h.value, ", \t");
            while (it.next()) |tok| {
                if (std.ascii.eqlIgnoreCase(tok, "close")) f.close = true;
                if (std.ascii.eqlIgnoreCase(tok, "keep-alive")) f.keep_alive_token = true;
                if (std.ascii.eqlIgnoreCase(tok, "upgrade")) f.upgrade_token = true;
            }
        }
    }
    return f;
}

/// Parses the request head at the start of `buf`, or returns null while it
/// is incomplete. `Parsed.len` is how many bytes of `buf` the head took.
pub fn parseRequest(buf: []const u8, headers_out: []Header, limits: Limits) Error!?Parsed {
    // RFC 9112 §2.2: ignore empty lines before the request line.
    var skip: usize = 0;
    while (skip + 1 < buf.len and buf[skip] == '\r' and buf[skip + 1] == '\n' and skip < 8) skip += 2;
    const body = buf[skip..];

    const end = findHeadEnd(body, 0) orelse {
        if (buf.len > limits.max_head) return error.HeadTooLarge;
        return null;
    };
    if (end > limits.max_head) return error.HeadTooLarge;

    var lines: Lines = .{ .buf = body[0..end] };
    const request_line = lines.next() orelse return error.BadRequest;
    var parts = std.mem.splitScalar(u8, request_line, ' ');
    const method = parts.next() orelse return error.BadRequest;
    const target = parts.next() orelse return error.BadRequest;
    const version_text = parts.next() orelse return error.BadRequest;
    if (parts.next() != null) return error.BadRequest;
    if (!isToken(method)) return error.BadRequest;
    if (target.len == 0) return error.BadRequest;
    for (target) |c| if (c <= 0x20 or c == 0x7f) return error.BadRequest;
    const version = try parseVersion(version_text);

    const max = @min(headers_out.len, limits.max_headers);
    const headers = try parseHeaderLines(&lines, headers_out[0..max]);
    const f = try scanFraming(headers);

    var head: RequestHead = .{
        .method = method,
        .target = target,
        .version = version,
        .headers = headers,
        .keep_alive = switch (version) {
            .http11 => !f.close,
            .http10 => f.keep_alive_token and !f.close,
        },
    };

    if (f.has_te) {
        if (version == .http10) return error.BadRequest;
        if (f.content_length != null) return error.BadRequest;
        if (f.other_coding or !f.chunked) return error.NotImplemented;
        head.chunked = true;
    } else {
        head.content_length = f.content_length;
    }

    var host_count: usize = 0;
    for (headers) |h| {
        if (std.ascii.eqlIgnoreCase(h.name, "host")) {
            host_count += 1;
            head.host = h.value;
        } else if (std.ascii.eqlIgnoreCase(h.name, "expect")) {
            if (std.ascii.eqlIgnoreCase(h.value, "100-continue")) head.expect_continue = true;
        } else if (std.ascii.eqlIgnoreCase(h.name, "upgrade")) {
            if (f.upgrade_token) head.upgrade = h.value;
        }
    }
    if (host_count > 1) return error.BadRequest;
    if (version == .http11 and host_count == 0) return error.BadRequest;

    return .{ .head = head, .len = skip + end };
}

/// The reason phrase for the statuses this server sends.
pub fn reason(status: u16) []const u8 {
    return switch (status) {
        101 => "Switching Protocols",
        200 => "OK",
        204 => "No Content",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        408 => "Request Timeout",
        409 => "Conflict",
        410 => "Gone",
        413 => "Content Too Large",
        414 => "URI Too Long",
        426 => "Upgrade Required",
        429 => "Too Many Requests",
        431 => "Request Header Fields Too Large",
        500 => "Internal Server Error",
        501 => "Not Implemented",
        503 => "Service Unavailable",
        505 => "HTTP Version Not Supported",
        else => "Unknown",
    };
}

const testing = std.testing;

test "parse simple request" {
    var hb: [16]Header = undefined;
    const raw = "GET /index.html?x=1 HTTP/1.1\r\nHost: example.com\r\nAccept: */*\r\n\r\nextra";
    const p = (try parseRequest(raw, &hb, .{})).?;
    try testing.expectEqualStrings("GET", p.head.method);
    try testing.expectEqualStrings("/index.html?x=1", p.head.target);
    try testing.expectEqualStrings("example.com", p.head.host.?);
    try testing.expect(p.head.keep_alive);
    try testing.expectEqual(raw.len - "extra".len, p.len);
}

test "incomplete head returns null" {
    var hb: [16]Header = undefined;
    try testing.expectEqual(@as(?Parsed, null), try parseRequest("GET / HTTP/1.1\r\nHost: a\r\n", &hb, .{}));
}

test "smuggling defenses" {
    var hb: [16]Header = undefined;
    const cases = [_][]const u8{
        "POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n",
        "POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\n",
        "POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked, gzip\r\n\r\n",
        "GET / HTTP/1.1\r\nHost : a\r\n\r\n",
        "GET / HTTP/1.1\r\nHost: a\r\n folded\r\n\r\n",
        "GET / HTTP/1.1\r\n\r\n",
        "GET / HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n",
        "GET /a b HTTP/1.1\r\nHost: a\r\n\r\n",
        "POST / HTTP/1.1\r\nHost: a\r\nContent-Length: -1\r\n\r\n",
        "POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 1\n2\r\n\r\n",
    };
    for (cases) |c| {
        if (parseRequest(c, &hb, .{})) |_| {
            std.debug.print("accepted: {s}\n", .{c});
            return error.TestUnexpectedResult;
        } else |_| {}
    }
    try testing.expectError(error.NotImplemented, parseRequest("POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: gzip\r\n\r\n", &hb, .{}));
    try testing.expectError(error.VersionNotSupported, parseRequest("GET / HTTP/2.0\r\nHost: a\r\n\r\n", &hb, .{}));
}

test "head size limit" {
    var hb: [16]Header = undefined;
    const big = "GET / HTTP/1.1\r\nHost: a\r\nX: " ++ "a" ** 100;
    try testing.expectError(error.HeadTooLarge, parseRequest(big, &hb, .{ .max_head = 64 }));
}

test "too many headers" {
    var hb: [2]Header = undefined;
    try testing.expectError(error.TooManyHeaders, parseRequest("GET / HTTP/1.1\r\nHost: a\r\nA: 1\r\nB: 2\r\n\r\n", &hb, .{}));
}

test "http/1.0 keep-alive" {
    var hb: [16]Header = undefined;
    const a = (try parseRequest("GET / HTTP/1.0\r\n\r\n", &hb, .{})).?;
    try testing.expect(!a.head.keep_alive);
    const b = (try parseRequest("GET / HTTP/1.0\r\nConnection: keep-alive\r\n\r\n", &hb, .{})).?;
    try testing.expect(b.head.keep_alive);
}

test "upgrade detection" {
    var hb: [16]Header = undefined;
    const p = (try parseRequest("GET /ws HTTP/1.1\r\nHost: a\r\nConnection: keep-alive, Upgrade\r\nUpgrade: websocket\r\n\r\n", &hb, .{})).?;
    try testing.expectEqualStrings("websocket", p.head.upgrade.?);
    try testing.expect(headerHasToken(p.head.headers, "connection", "upgrade"));
    // Upgrade without the Connection token is not an upgrade.
    const q = (try parseRequest("GET /ws HTTP/1.1\r\nHost: a\r\nUpgrade: websocket\r\n\r\n", &hb, .{})).?;
    try testing.expect(q.head.upgrade == null);
}
