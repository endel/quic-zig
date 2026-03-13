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
        // Sanitize path: strip leading "/"
        var clean_path = path;
        while (clean_path.len > 0 and clean_path[0] == '/') {
            clean_path = clean_path[1..];
        }
        if (clean_path.len == 0) clean_path = "index.html";

        // Build full filesystem path
        var full_path_buf: [4096]u8 = undefined;
        var full_path_pos: usize = 0;
        @memcpy(full_path_buf[full_path_pos..][0..root_dir.len], root_dir);
        full_path_pos += root_dir.len;
        if (root_dir.len > 0 and root_dir[root_dir.len - 1] != '/') {
            full_path_buf[full_path_pos] = '/';
            full_path_pos += 1;
        }
        @memcpy(full_path_buf[full_path_pos..][0..clean_path.len], clean_path);
        full_path_pos += clean_path.len;
        full_path_buf[full_path_pos] = 0;

        const full_path = full_path_buf[0..full_path_pos];

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
                try buf_entry.value_ptr.appendSlice(self.allocator, data);

                // Check for complete request line
                const buf_data = buf_entry.value_ptr.items;
                if (mem.indexOf(u8, buf_data, "\r\n")) |idx| {
                    // Parse "GET /path"
                    const line = buf_data[0..idx];
                    if (mem.startsWith(u8, line, "GET ")) {
                        const path = line[4..];
                        @memcpy(self.path_buf[0..path.len], path);
                        self.path_len = path.len;
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
