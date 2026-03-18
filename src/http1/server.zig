// HTTP/1.1 static file server over TCP+TLS.
//
// Runs on a dedicated thread alongside the QUIC event loop, sharing the same
// TLS certificate. Serves files from a configurable directory and advertises
// HTTP/3 via Alt-Svc header.

const std = @import("std");
const posix = std.posix;
const net = std.net;
const fs = std.fs;
const log = std.log.scoped(.http1);
const tls = @import("tls.zig");
const tls13 = @import("../quic/tls13.zig");

pub const Http1Config = struct {
    /// Directory to serve static files from.
    static_dir: []const u8,
    /// TCP port. Defaults to the same as the QUIC port when null.
    port: ?u16 = null,
    /// Automatically include `Alt-Svc: h3=":port"` in responses to advertise HTTP/3.
    alt_svc: bool = true,
};

pub const Http1Server = struct {
    listener: net.Server,
    static_dir: []const u8,
    alt_svc_value: [64]u8 = undefined,
    alt_svc_len: u8 = 0,
    tls_config: tls.TlsServerConfig,
    thread: ?std.Thread = null,
    running: bool = false,

    pub fn init(
        address: []const u8,
        config: Http1Config,
        quic_port: u16,
        tls_config: tls.TlsServerConfig,
    ) !Http1Server {
        const port = config.port orelse quic_port;
        const addr = try net.Address.parseIp4(address, port);

        const listener = try addr.listen(.{
            .reuse_address = true,
        });

        var server = Http1Server{
            .listener = listener,
            .static_dir = config.static_dir,
            .tls_config = tls_config,
        };

        // Pre-format Alt-Svc header value
        if (config.alt_svc) {
            const len = std.fmt.bufPrint(&server.alt_svc_value, "h3=\":{d}\"; ma=86400", .{quic_port}) catch "";
            server.alt_svc_len = @intCast(len.len);
        }

        return server;
    }

    pub fn start(self: *Http1Server) !void {
        self.running = true;
        self.thread = try std.Thread.spawn(.{}, acceptLoop, .{self});
    }

    pub fn stop(self: *Http1Server) void {
        self.running = false;
        // Close the listener to unblock accept()
        self.listener.deinit();
    }

    pub fn deinit(self: *Http1Server) void {
        self.stop();
        if (self.thread) |t| {
            t.join();
            self.thread = null;
        }
    }

    fn acceptLoop(self: *Http1Server) void {
        while (self.running) {
            const conn = self.listener.accept() catch {
                if (!self.running) break;
                continue;
            };
            self.handleConnection(conn.stream);
        }
    }

    fn handleConnection(self: *Http1Server, stream: net.Stream) void {
        defer stream.close();

        // TLS handshake
        var tls_stream = tls.TlsStream.handshake(stream.handle, self.tls_config) catch |err| {
            log.debug("TLS handshake failed: {any}", .{err});
            return;
        };

        // Read HTTP request over TLS
        var buf: [4096]u8 = undefined;
        const n = tls_stream.read(&buf) catch return;
        if (n == 0) return;

        const request = buf[0..n];

        // Parse request line: "GET /path HTTP/1.1\r\n..."
        const method_end = std.mem.indexOfScalar(u8, request, ' ') orelse return;
        const method = request[0..method_end];

        // Only support GET and HEAD
        if (!std.mem.eql(u8, method, "GET") and !std.mem.eql(u8, method, "HEAD")) {
            self.sendError(&tls_stream, "405 Method Not Allowed", "Method not allowed");
            return;
        }

        const path_start = method_end + 1;
        const path_end = std.mem.indexOfScalarPos(u8, request, path_start, ' ') orelse return;
        const raw_path = request[path_start..path_end];

        // Decode URI path (skip query string)
        const query_start = std.mem.indexOfScalar(u8, raw_path, '?');
        const path = raw_path[0..(query_start orelse raw_path.len)];

        // Security: reject paths with ".." to prevent directory traversal
        if (std.mem.indexOf(u8, path, "..") != null) {
            self.sendError(&tls_stream, "403 Forbidden", "Forbidden");
            return;
        }

        // Strip leading slash
        const relative = if (path.len > 0 and path[0] == '/') path[1..] else path;

        // If path is empty or ends with /, try index.html
        const file_path = if (relative.len == 0 or relative[relative.len - 1] == '/')
            "index.html"
        else
            relative;

        // Open and serve the file
        const dir = fs.cwd().openDir(self.static_dir, .{}) catch {
            self.sendError(&tls_stream, "500 Internal Server Error", "Cannot open static directory");
            return;
        };
        const file = dir.openFile(file_path, .{}) catch {
            // Try with /index.html appended (for directory paths)
            if (relative.len > 0 and relative[relative.len - 1] != '/') {
                var index_buf: [512]u8 = undefined;
                const index_path = std.fmt.bufPrint(&index_buf, "{s}/index.html", .{relative}) catch {
                    self.sendError(&tls_stream, "404 Not Found", "Not found");
                    return;
                };
                const index_file = dir.openFile(index_path, .{}) catch {
                    self.sendError(&tls_stream, "404 Not Found", "Not found");
                    return;
                };
                self.serveFile(&tls_stream, index_file, index_path, std.mem.eql(u8, method, "HEAD"));
                return;
            }
            self.sendError(&tls_stream, "404 Not Found", "Not found");
            return;
        };
        self.serveFile(&tls_stream, file, file_path, std.mem.eql(u8, method, "HEAD"));
    }

    fn serveFile(self: *Http1Server, tls_stream: *tls.TlsStream, file: fs.File, path: []const u8, head_only: bool) void {
        defer file.close();

        const stat = file.stat() catch {
            self.sendError(tls_stream, "500 Internal Server Error", "Cannot stat file");
            return;
        };
        const file_size = stat.size;
        const content_type = mimeType(path);

        // Write response header
        var hdr_buf: [1024]u8 = undefined;
        var hdr_len: usize = 0;

        hdr_len += (std.fmt.bufPrint(hdr_buf[hdr_len..], "HTTP/1.1 200 OK\r\n", .{}) catch return).len;
        hdr_len += (std.fmt.bufPrint(hdr_buf[hdr_len..], "Content-Type: {s}\r\n", .{content_type}) catch return).len;
        hdr_len += (std.fmt.bufPrint(hdr_buf[hdr_len..], "Content-Length: {d}\r\n", .{file_size}) catch return).len;
        hdr_len += (std.fmt.bufPrint(hdr_buf[hdr_len..], "Connection: close\r\n", .{}) catch return).len;
        hdr_len += (std.fmt.bufPrint(hdr_buf[hdr_len..], "Access-Control-Allow-Origin: *\r\n", .{}) catch return).len;

        if (self.alt_svc_len > 0) {
            hdr_len += (std.fmt.bufPrint(hdr_buf[hdr_len..], "Alt-Svc: {s}\r\n", .{self.alt_svc_value[0..self.alt_svc_len]}) catch return).len;
        }

        hdr_len += (std.fmt.bufPrint(hdr_buf[hdr_len..], "\r\n", .{}) catch return).len;

        tls_stream.write(hdr_buf[0..hdr_len]) catch return;

        if (head_only) return;

        // Send file body in chunks
        var body_buf: [8192]u8 = undefined;
        var remaining = file_size;
        while (remaining > 0) {
            const to_read = @min(remaining, body_buf.len);
            const bytes_read = file.read(body_buf[0..to_read]) catch return;
            if (bytes_read == 0) break;
            tls_stream.write(body_buf[0..bytes_read]) catch return;
            remaining -= bytes_read;
        }
    }

    fn sendError(self: *Http1Server, tls_stream: *tls.TlsStream, status: []const u8, body: []const u8) void {
        var buf: [512]u8 = undefined;
        var len: usize = 0;

        len += (std.fmt.bufPrint(buf[len..], "HTTP/1.1 {s}\r\n", .{status}) catch return).len;
        len += (std.fmt.bufPrint(buf[len..], "Content-Type: text/plain\r\n", .{}) catch return).len;
        len += (std.fmt.bufPrint(buf[len..], "Content-Length: {d}\r\n", .{body.len}) catch return).len;
        len += (std.fmt.bufPrint(buf[len..], "Connection: close\r\n", .{}) catch return).len;

        if (self.alt_svc_len > 0) {
            len += (std.fmt.bufPrint(buf[len..], "Alt-Svc: {s}\r\n", .{self.alt_svc_value[0..self.alt_svc_len]}) catch return).len;
        }

        len += (std.fmt.bufPrint(buf[len..], "\r\n", .{}) catch return).len;
        len += (std.fmt.bufPrint(buf[len..], "{s}", .{body}) catch return).len;

        tls_stream.write(buf[0..len]) catch return;
    }

    fn mimeType(path: []const u8) []const u8 {
        const ext = std.fs.path.extension(path);
        if (std.mem.eql(u8, ext, ".html") or std.mem.eql(u8, ext, ".htm")) return "text/html; charset=utf-8";
        if (std.mem.eql(u8, ext, ".css")) return "text/css; charset=utf-8";
        if (std.mem.eql(u8, ext, ".js") or std.mem.eql(u8, ext, ".mjs")) return "application/javascript; charset=utf-8";
        if (std.mem.eql(u8, ext, ".json")) return "application/json; charset=utf-8";
        if (std.mem.eql(u8, ext, ".png")) return "image/png";
        if (std.mem.eql(u8, ext, ".jpg") or std.mem.eql(u8, ext, ".jpeg")) return "image/jpeg";
        if (std.mem.eql(u8, ext, ".gif")) return "image/gif";
        if (std.mem.eql(u8, ext, ".svg")) return "image/svg+xml";
        if (std.mem.eql(u8, ext, ".ico")) return "image/x-icon";
        if (std.mem.eql(u8, ext, ".woff2")) return "font/woff2";
        if (std.mem.eql(u8, ext, ".woff")) return "font/woff";
        if (std.mem.eql(u8, ext, ".wasm")) return "application/wasm";
        if (std.mem.eql(u8, ext, ".txt")) return "text/plain; charset=utf-8";
        if (std.mem.eql(u8, ext, ".xml")) return "application/xml";
        return "application/octet-stream";
    }
};

test "mime type lookup" {
    const expect = std.testing.expectEqualStrings;
    try expect("text/html; charset=utf-8", Http1Server.mimeType("index.html"));
    try expect("application/javascript; charset=utf-8", Http1Server.mimeType("app.js"));
    try expect("text/css; charset=utf-8", Http1Server.mimeType("style.css"));
    try expect("image/png", Http1Server.mimeType("logo.png"));
    try expect("application/octet-stream", Http1Server.mimeType("data.bin"));
}
