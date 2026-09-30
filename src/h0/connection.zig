// HTTP/0.9 over QUIC (hq-interop)
//
// Minimal protocol for QUIC interop testing. No framing, no headers.
// Server: read "GET /path\r\n" from bidi stream, write file contents, close.
// Client: write "GET /path\r\n" to bidi stream, read response, save to file.

const std = @import("std");
const sys = @import("../sys.zig");
const io = @import("../io_compat.zig");
const fs = std.fs;
const mem = std.mem;
const Allocator = std.mem.Allocator;

const quic_connection = @import("../quic/connection.zig");
const stream_mod = @import("../quic/stream.zig");

pub const ALPN = [_][]const u8{ "hq-interop", "hq-32", "hq-31", "hq-30", "hq-29" };

/// Maximum request line length (GET /path\r\n).
const MAX_REQUEST_LINE = 4096;

/// Maximum file size to serve (10MB).
const MAX_FILE_SIZE = 10 * 1024 * 1024;

/// Event returned by poll().
pub const H0Event = union(enum) {
    /// A complete request was received on a bidi stream (server-side).
    request: struct {
        stream_id: u64,
        path: []const u8, // e.g. "/largefile"
    },
    /// Response data received on a stream (client-side).
    data: struct {
        stream_id: u64,
        data: []const u8,
    },
    /// Stream finished (FIN received).
    finished: u64,
};

/// Joins `root_dir` and a request path into `out`: null for a path with a
/// `..` segment or a NUL, or one that does not fit. Leading slashes are
/// dropped and an empty path names `index.html`. Symlinks under the root
/// are still followed.
pub fn resolvePath(out: []u8, root_dir: []const u8, request_path: []const u8) ?[]const u8 {
    var rel = mem.trimStart(u8, request_path, "/");
    if (rel.len == 0) rel = "index.html";
    if (mem.indexOfScalar(u8, rel, 0) != null) return null;
    var parts = mem.splitScalar(u8, rel, '/');
    while (parts.next()) |part| {
        if (mem.eql(u8, part, "..")) return null;
    }
    const sep: []const u8 = if (root_dir.len > 0 and root_dir[root_dir.len - 1] != '/') "/" else "";
    return std.fmt.bufPrint(out, "{s}{s}{s}", .{ root_dir, sep, rel }) catch null;
}

/// HTTP/0.9 connection layer over QUIC.
pub const H0Connection = struct {
    allocator: Allocator,
    quic_conn: *quic_connection.Connection,
    is_server: bool,

    // Per-stream request buffers (accumulate partial "GET /path\r\n")
    stream_bufs: std.AutoHashMap(u64, std.ArrayList(u8)),
    finished_streams: std.AutoHashMap(u64, void),

    // Scratch buffer for path extraction
    path_buf: [MAX_REQUEST_LINE]u8 = undefined,
    path_len: usize = 0,

    pub fn init(allocator: Allocator, quic_conn: *quic_connection.Connection, is_server: bool) H0Connection {
        return .{
            .allocator = allocator,
            .quic_conn = quic_conn,
            .is_server = is_server,
            .stream_bufs = std.AutoHashMap(u64, std.ArrayList(u8)).init(allocator),
            .finished_streams = std.AutoHashMap(u64, void).init(allocator),
        };
    }

    pub fn deinit(self: *H0Connection) void {
        var it = self.stream_bufs.iterator();
        while (it.next()) |entry| {
            entry.value_ptr.deinit(self.allocator);
        }
        self.stream_bufs.deinit();
        self.finished_streams.deinit();
    }

    /// Open a bidi stream and send an HTTP/0.9 GET request.
    /// Returns the stream ID.
    pub fn sendRequest(self: *H0Connection, path: []const u8) !u64 {
        const stream = try self.quic_conn.openStream();
        const stream_id = stream.stream_id;

        // Write "GET /path\r\n"
        var req_buf: [MAX_REQUEST_LINE]u8 = undefined;
        var pos: usize = 0;
        @memcpy(req_buf[pos..][0..4], "GET ");
        pos += 4;
        if (path.len > MAX_REQUEST_LINE - 6) return error.PathTooLong;
        @memcpy(req_buf[pos..][0..path.len], path);
        pos += path.len;
        req_buf[pos] = '\r';
        pos += 1;
        req_buf[pos] = '\n';
        pos += 1;

        try stream.send.writeData(req_buf[0..pos]);
        stream.send.close();

        return stream_id;
    }

    /// Send response data on a stream (server-side).
    pub fn sendResponse(self: *H0Connection, stream_id: u64, data: []const u8) !void {
        const streams_map = &self.quic_conn.streams;
        const stream = streams_map.getStream(stream_id) orelse return error.StreamNotFound;
        // Mark as incremental so the priority scheduler packs multiple
        // streams into a single packet (critical for multiplexing tests).
        stream.send.incremental = true;
        try stream.send.writeData(data);
        stream.send.close();
    }

    /// Serve a file from the given root directory on the specified stream.
    pub fn serveFile(self: *H0Connection, stream_id: u64, root_dir: []const u8, path: []const u8) !void {
        var full_path_buf: [std.fs.max_path_bytes]u8 = undefined;
        const file_data = if (resolvePath(&full_path_buf, root_dir, path)) |full_path|
            sys.readFileAlloc(self.allocator, full_path, MAX_FILE_SIZE) catch |err| {
                std.log.err("H0: failed to read file '{s}': {any}", .{ full_path, err });
                return self.answerNothing(stream_id);
            }
        else
            return self.answerNothing(stream_id);
        defer self.allocator.free(file_data);

        std.log.info("H0: serving {d} bytes on stream {d}", .{ file_data.len, stream_id });
        try self.sendResponse(stream_id, file_data);
    }

    /// Close the stream with an empty response.
    fn answerNothing(self: *H0Connection, stream_id: u64) void {
        const stream = self.quic_conn.streams.getStream(stream_id) orelse return;
        stream.send.close();
    }

    /// Stop reading a stream whose request we will not serve.
    fn refuse(self: *H0Connection, stream_id: u64) void {
        self.finished_streams.put(stream_id, {}) catch {};
        self.dropRequestBuf(stream_id);
        self.answerNothing(stream_id);
    }

    fn dropRequestBuf(self: *H0Connection, stream_id: u64) void {
        if (self.stream_bufs.fetchRemove(stream_id)) |kv| {
            var buf = kv.value;
            buf.deinit(self.allocator);
        }
    }

    /// Poll for HTTP/0.9 events.
    pub fn poll(self: *H0Connection) !?H0Event {
        const streams_map = &self.quic_conn.streams;

        // Check bidi streams for data
        var it = streams_map.streams.iterator();
        while (it.next()) |kv| {
            const stream = kv.value_ptr.*;
            const stream_id = stream.stream_id;

            // Skip already-finished streams
            if (self.finished_streams.get(stream_id) != null) continue;

            // Try to read available data
            const data = stream.recv.read() orelse {
                // No data available - check if stream is finished
                if (stream.recv.finished) {
                    self.finished_streams.put(stream_id, {}) catch {};
                    return H0Event{ .finished = stream_id };
                }
                continue;
            };

            if (self.is_server) {
                // Server: accumulate request data and look for \r\n
                defer self.allocator.free(data);
                const buf_entry = try self.stream_bufs.getOrPut(stream_id);
                if (!buf_entry.found_existing) {
                    buf_entry.value_ptr.* = .{ .items = &.{}, .capacity = 0 };
                }
                try buf_entry.value_ptr.appendSlice(self.allocator, data);

                // Check for complete request line
                const buf_data = buf_entry.value_ptr.items;
                const idx = mem.indexOf(u8, buf_data, "\r\n") orelse {
                    if (buf_data.len > MAX_REQUEST_LINE) self.refuse(stream_id);
                    continue;
                };
                // Parse "GET /path"
                const line = buf_data[0..idx];
                if (!mem.startsWith(u8, line, "GET ") or line.len - 4 > self.path_buf.len) {
                    self.refuse(stream_id);
                    continue;
                }
                const path = line[4..];
                @memcpy(self.path_buf[0..path.len], path);
                self.path_len = path.len;
                // Mark as finished so subsequent polls skip this stream
                self.finished_streams.put(stream_id, {}) catch {};
                self.dropRequestBuf(stream_id);
                return H0Event{ .request = .{
                    .stream_id = stream_id,
                    .path = self.path_buf[0..self.path_len],
                } };
            } else {
                // Client: return raw data
                return H0Event{ .data = .{
                    .stream_id = stream_id,
                    .data = data,
                } };
            }
        }

        return null;
    }
};

const testing = std.testing;

/// A connection with one bidi stream open and `request` received on it.
fn testStream(conn: *quic_connection.Connection, request: []const u8) !*stream_mod.Stream {
    try quic_connection.connectInto(conn, testing.allocator, "example.com", .{}, null, null);
    conn.streams.setMaxStreams(10, 10);
    const s = try conn.openStream();
    try s.recv.handleStreamFrame(0, request, false);
    return s;
}

test "a request line past MAX_REQUEST_LINE is refused, not copied" {
    const conn = try testing.allocator.create(quic_connection.Connection);
    defer testing.allocator.destroy(conn);
    var line: [MAX_REQUEST_LINE + 1000]u8 = undefined;
    @memcpy(line[0..4], "GET ");
    @memset(line[4 .. line.len - 2], 'a');
    @memcpy(line[line.len - 2 ..], "\r\n");
    _ = try testStream(conn, &line);
    defer conn.deinit();

    var h0 = H0Connection.init(testing.allocator, conn, true);
    defer h0.deinit();
    while (try h0.poll()) |ev| try testing.expect(ev != .request);
}

test "a request line with no end in sight is not buffered past MAX_REQUEST_LINE" {
    const conn = try testing.allocator.create(quic_connection.Connection);
    defer testing.allocator.destroy(conn);
    const s = try testStream(conn, "GET /");
    defer conn.deinit();

    var h0 = H0Connection.init(testing.allocator, conn, true);
    defer h0.deinit();
    var chunk: [1000]u8 = @splat('a');
    var offset: u64 = 5;
    for (0..10) |_| {
        try s.recv.handleStreamFrame(offset, &chunk, false);
        offset += chunk.len;
        while (try h0.poll()) |ev| try testing.expect(ev != .request);
        if (h0.stream_bufs.get(s.stream_id)) |buf| try testing.expect(buf.items.len <= MAX_REQUEST_LINE);
    }
}

test "serveFile answers nothing for a path outside the root or too long to build" {
    const conn = try testing.allocator.create(quic_connection.Connection);
    defer testing.allocator.destroy(conn);
    const s = try testStream(conn, "");
    defer conn.deinit();

    var h0 = H0Connection.init(testing.allocator, conn, true);
    defer h0.deinit();
    var long: [5000]u8 = @splat('a');
    long[0] = '/';
    for ([_][]const u8{ "/../etc/hosts", "/a/../../etc/hosts", "..", &long }) |path| {
        h0.serveFile(s.stream_id, "/tmp", path) catch {};
        try testing.expectEqual(@as(u64, 0), s.send.write_offset);
    }
}

test "resolvePath joins paths under the root and refuses the rest" {
    var buf: [64]u8 = undefined;
    try testing.expectEqualStrings("/www/index.html", resolvePath(&buf, "/www", "/").?);
    try testing.expectEqualStrings("/www/a/b.txt", resolvePath(&buf, "/www/", "//a/b.txt").?);
    try testing.expectEqualStrings("/www/a..b", resolvePath(&buf, "/www", "/a..b").?);
    try testing.expectEqual(null, resolvePath(&buf, "/www", "/a/../../etc/passwd"));
    try testing.expectEqual(null, resolvePath(&buf, "/www", "/.."));
    try testing.expectEqual(null, resolvePath(&buf, "/www", "/a\x00b"));
    try testing.expectEqual(null, resolvePath(&buf, "/www", "/" ++ "a" ** 64));
}
