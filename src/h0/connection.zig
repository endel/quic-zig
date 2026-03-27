// HTTP/0.9 over QUIC (hq-interop)
//
// Minimal protocol for QUIC interop testing. No framing, no headers.
// Server: read "GET /path\r\n" from bidi stream, write file contents, close.
// Client: write "GET /path\r\n" to bidi stream, read response, save to file.

const std = @import("std");
const io = std.io;
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
const REQUEST_REJECTED_ERROR: u64 = 1;

fn copyDefaultPath(out_buf: []u8) ![]const u8 {
    const default_path = "index.html";
    if (out_buf.len < default_path.len) return error.PathTooLong;
    @memcpy(out_buf[0..default_path.len], default_path);
    return out_buf[0..default_path.len];
}

/// Convert an untrusted request path into a normalized relative filesystem path.
/// Rejects path traversal, backslash separators, NUL bytes, and oversized paths.
pub fn sanitizeRelativePath(path: []const u8, out_buf: []u8) ![]const u8 {
    var trimmed = path;
    if (mem.indexOfAny(u8, trimmed, "?#")) |idx| {
        trimmed = trimmed[0..idx];
    }

    while (trimmed.len > 0 and trimmed[0] == '/') {
        trimmed = trimmed[1..];
    }

    if (trimmed.len == 0) {
        return copyDefaultPath(out_buf);
    }

    var out_len: usize = 0;
    var segments = mem.splitScalar(u8, trimmed, '/');
    while (segments.next()) |segment| {
        if (segment.len == 0 or mem.eql(u8, segment, ".")) continue;
        if (mem.eql(u8, segment, "..")) return error.PathTraversal;
        if (mem.indexOfScalar(u8, segment, 0) != null) return error.InvalidPath;
        if (mem.indexOfScalar(u8, segment, '\\') != null) return error.InvalidPath;

        const separator_len: usize = if (out_len == 0) 0 else 1;
        if (out_len + separator_len + segment.len > out_buf.len) return error.PathTooLong;
        if (separator_len == 1) {
            out_buf[out_len] = '/';
            out_len += 1;
        }
        @memcpy(out_buf[out_len..][0..segment.len], segment);
        out_len += segment.len;
    }

    if (out_len == 0) {
        return copyDefaultPath(out_buf);
    }

    return out_buf[0..out_len];
}

pub fn buildSafeFilePath(root_dir: []const u8, request_path: []const u8, clean_path_buf: []u8, full_path_buf: []u8) ![]const u8 {
    const clean_path = try sanitizeRelativePath(request_path, clean_path_buf);

    if (root_dir.len == 0) {
        return std.fmt.bufPrint(full_path_buf, "{s}", .{clean_path}) catch error.PathTooLong;
    }
    if (root_dir[root_dir.len - 1] == '/') {
        return std.fmt.bufPrint(full_path_buf, "{s}{s}", .{ root_dir, clean_path }) catch error.PathTooLong;
    }
    return std.fmt.bufPrint(full_path_buf, "{s}/{s}", .{ root_dir, clean_path }) catch error.PathTooLong;
}

fn copyRequestPath(line: []const u8, out_buf: []u8) !?[]const u8 {
    if (!mem.startsWith(u8, line, "GET ")) return null;

    const path = line[4..];
    if (path.len > out_buf.len) return error.PathTooLong;

    @memcpy(out_buf[0..path.len], path);
    return out_buf[0..path.len];
}

fn rejectRequestStream(stream: *stream_mod.Stream) void {
    stream.send.reset(REQUEST_REJECTED_ERROR);
    stream.recv.stopSending(REQUEST_REJECTED_ERROR);
}

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
        var clean_path_buf: [MAX_REQUEST_LINE]u8 = undefined;
        var full_path_buf: [4096]u8 = undefined;
        const full_path = buildSafeFilePath(root_dir, path, &clean_path_buf, &full_path_buf) catch |err| {
            std.log.warn("H0: rejected request path '{s}': {any}", .{ path, err });
            const streams_map = &self.quic_conn.streams;
            const stream = streams_map.getStream(stream_id) orelse return;
            rejectRequestStream(stream);
            return;
        };

        // Read file
        const file_data = std.fs.cwd().readFileAlloc(self.allocator, full_path, MAX_FILE_SIZE) catch |err| {
            std.log.err("H0: failed to read file '{s}': {any}", .{ full_path, err });
            // Close stream with empty response on file not found
            const streams_map = &self.quic_conn.streams;
            const stream = streams_map.getStream(stream_id) orelse return;
            stream.send.close();
            return;
        };
        defer self.allocator.free(file_data);

        std.log.info("H0: serving {d} bytes on stream {d}", .{ file_data.len, stream_id });
        try self.sendResponse(stream_id, file_data);
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
                    if (self.stream_bufs.getPtr(stream_id)) |buf| {
                        buf.deinit(self.allocator);
                        _ = self.stream_bufs.remove(stream_id);
                    }
                    self.finished_streams.put(stream_id, {}) catch {};
                    return H0Event{ .finished = stream_id };
                }
                continue;
            };

            if (self.is_server) {
                // Server: accumulate request data and look for \r\n
                const buf_entry = try self.stream_bufs.getOrPut(stream_id);
                if (!buf_entry.found_existing) {
                    buf_entry.value_ptr.* = .{ .items = &.{}, .capacity = 0 };
                }
                if (buf_entry.value_ptr.items.len +| data.len > MAX_REQUEST_LINE) {
                    std.log.warn("H0: rejecting oversized request line on stream {d}", .{stream_id});
                    buf_entry.value_ptr.deinit(self.allocator);
                    _ = self.stream_bufs.remove(stream_id);
                    self.finished_streams.put(stream_id, {}) catch {};
                    rejectRequestStream(stream);
                    continue;
                }
                try buf_entry.value_ptr.appendSlice(self.allocator, data);

                // Check for complete request line
                const buf_data = buf_entry.value_ptr.items;
                if (mem.indexOf(u8, buf_data, "\r\n")) |idx| {
                    // Parse "GET /path"
                    const line = buf_data[0..idx];
                    if (try copyRequestPath(line, &self.path_buf)) |path| {
                        self.path_len = path.len;
                        buf_entry.value_ptr.deinit(self.allocator);
                        _ = self.stream_bufs.remove(stream_id);
                        // Mark as finished so subsequent polls skip this stream
                        self.finished_streams.put(stream_id, {}) catch {};
                        return H0Event{ .request = .{
                            .stream_id = stream_id,
                            .path = self.path_buf[0..self.path_len],
                        } };
                    }
                }
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

test "sanitizeRelativePath normalizes safe request paths" {
    var buf: [MAX_REQUEST_LINE]u8 = undefined;

    try std.testing.expectEqualStrings("index.html", try sanitizeRelativePath("/", &buf));
    try std.testing.expectEqualStrings("nested/file.txt", try sanitizeRelativePath("//nested/./file.txt?download=1#frag", &buf));
    try std.testing.expectEqualStrings("foo/bar", try sanitizeRelativePath("/foo//bar/", &buf));
}

test "sanitizeRelativePath rejects traversal and invalid separators" {
    var buf: [MAX_REQUEST_LINE]u8 = undefined;

    try std.testing.expectError(error.PathTraversal, sanitizeRelativePath("/../etc/passwd", &buf));
    try std.testing.expectError(error.PathTraversal, sanitizeRelativePath("/safe/../../etc/passwd", &buf));
    try std.testing.expectError(error.InvalidPath, sanitizeRelativePath("/foo\\bar", &buf));
}

test "buildSafeFilePath bounds the final path" {
    var clean_path_buf: [MAX_REQUEST_LINE]u8 = undefined;
    var full_path_buf: [32]u8 = undefined;
    var long_request: [MAX_REQUEST_LINE]u8 = undefined;

    @memset(&long_request, 'a');

    try std.testing.expectError(
        error.PathTooLong,
        buildSafeFilePath("/www", long_request[0..], &clean_path_buf, &full_path_buf),
    );
}

test "copyRequestPath extracts GET paths" {
    var buf: [16]u8 = undefined;

    const path = (try copyRequestPath("GET /file.txt", &buf)).?;
    try std.testing.expectEqualStrings("/file.txt", path);
    try std.testing.expect((try copyRequestPath("POST /file.txt", &buf)) == null);
}

test "copyRequestPath rejects oversized paths before memcpy" {
    var buf: [4]u8 = undefined;

    try std.testing.expectError(error.PathTooLong, copyRequestPath("GET /abcd", &buf));
}

test "rejectRequestStream cancels both directions" {
    var stream = stream_mod.Stream.init(std.testing.allocator, 0);
    defer stream.deinit();

    rejectRequestStream(&stream);

    try std.testing.expectEqual(@as(?u64, REQUEST_REJECTED_ERROR), stream.send.reset_err);
    try std.testing.expectEqual(@as(?u64, REQUEST_REJECTED_ERROR), stream.recv.stop_sending_err);
}
