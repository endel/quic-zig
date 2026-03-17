// WebTransport Interop Runner - Client Endpoint
//
// Reads environment variables set by the interop runner:
//   TESTCASE          - handshake, transfer, transfer-unidirectional-receive,
//                       transfer-bidirectional-receive, transfer-datagram-receive
//   SSLKEYLOGFILE     - optional path to write TLS key log
//   QLOGDIR           - optional path to write qlog files
//   PROTOCOLS         - space-separated sub-protocols for negotiation
//   REQUESTS          - space-separated URLs (passed as CLI args)
//
// Certs at /certs/cert.pem and /certs/priv.key.
// Client files at /www/. Downloads saved to /downloads/.
// Connects to server4:443.

const std = @import("std");
const posix = std.posix;
const net = std.net;
const mem = std.mem;

const lib = @import("quic");
const connection = lib.connection;
const quic_crypto = lib.crypto;
const tls13 = lib.tls13;
const ecn_socket = lib.ecn_socket;
const h3 = lib.h3;
const qpack = lib.qpack;
const webtransport = lib.webtransport;

const MAX_DATAGRAM_SIZE: usize = 1500;
const MAX_FILE_SIZE: usize = 4 * 1024 * 1024;
const TIMEOUT_NS: i128 = 120 * std.time.ns_per_s;

const TestCase = enum {
    handshake,
    transfer,
    transfer_unidirectional_receive,
    transfer_bidirectional_receive,
    transfer_datagram_receive,
    unsupported,
};

fn parseTestCase(name: []const u8) TestCase {
    if (mem.eql(u8, name, "handshake")) return .handshake;
    if (mem.eql(u8, name, "transfer")) return .transfer;
    if (mem.eql(u8, name, "transfer-unidirectional-receive")) return .transfer_unidirectional_receive;
    if (mem.eql(u8, name, "transfer-bidirectional-receive")) return .transfer_bidirectional_receive;
    if (mem.eql(u8, name, "transfer-datagram-receive")) return .transfer_datagram_receive;
    return .unsupported;
}

const ParsedUrl = struct {
    host: []const u8,
    port: u16,
    path: []const u8,
};

fn parseUrl(url: []const u8) ?ParsedUrl {
    var rest = url;
    if (mem.startsWith(u8, rest, "https://")) {
        rest = rest[8..];
    } else if (mem.startsWith(u8, rest, "http://")) {
        rest = rest[7..];
    }
    const path_start = mem.indexOf(u8, rest, "/") orelse rest.len;
    const host_port = rest[0..path_start];
    const path = if (path_start < rest.len) rest[path_start..] else "/";
    if (mem.indexOf(u8, host_port, ":")) |colon| {
        const port = std.fmt.parseInt(u16, host_port[colon + 1 ..], 10) catch 443;
        return .{ .host = host_port[0..colon], .port = port, .path = path };
    }
    return .{ .host = host_port, .port = 443, .path = path };
}

/// Group requests by endpoint (first path component).
/// Returns a list of (endpoint_path, [filenames]) tuples.
const EndpointGroup = struct {
    endpoint: []const u8, // e.g. "/webtransport1"
    files: std.ArrayList([]const u8), // e.g. ["file1.txt", "file2.txt"]
};

fn groupByEndpoint(alloc: std.mem.Allocator, urls: []const ParsedUrl) !std.ArrayList(EndpointGroup) {
    var groups: std.ArrayList(EndpointGroup) = .{ .items = &.{}, .capacity = 0 };
    for (urls) |url| {
        // path = "/endpoint/file.txt" or "/endpoint/" or "/endpoint"
        var path = url.path;
        // strip leading slash
        if (path.len > 0 and path[0] == '/') path = path[1..];
        // split into endpoint and filename
        const slash_pos = mem.indexOf(u8, path, "/");
        const endpoint_name = if (slash_pos) |sp| path[0..sp] else path;
        const filename = if (slash_pos) |sp| (if (sp + 1 < path.len) path[sp + 1 ..] else "") else "";

        // Build endpoint path as "/endpoint_name"
        var ep_buf: [256]u8 = undefined;
        ep_buf[0] = '/';
        @memcpy(ep_buf[1..][0..endpoint_name.len], endpoint_name);
        const ep_path = try alloc.dupe(u8, ep_buf[0 .. 1 + endpoint_name.len]);

        // Find existing group or create new one
        var found = false;
        for (groups.items) |*g| {
            if (mem.eql(u8, g.endpoint, ep_path)) {
                if (filename.len > 0) {
                    try g.files.append(alloc, filename);
                }
                found = true;
                break;
            }
        }
        if (!found) {
            var g = EndpointGroup{
                .endpoint = ep_path,
                .files = .{ .items = &.{}, .capacity = 0 },
            };
            if (filename.len > 0) {
                try g.files.append(alloc, filename);
            }
            try groups.append(alloc, g);
        }
    }
    return groups;
}

/// Per-session state for tracking pending operations.
const SessionState = struct {
    session_id: u64,
    endpoint: []const u8,
    files: []const []const u8,
    session_ready: bool = false,
    requests_sent: bool = false,
    // For transfer (responder) mode: track incoming GETs and pending responses
    bidi_bufs: std.AutoHashMap(u64, std.ArrayList(u8)),
    uni_bufs: std.AutoHashMap(u64, std.ArrayList(u8)),
    // Receive mode: track files by stream id
    pending_gets: std.AutoHashMap(u64, []const u8),
    // Deferred datagram replies (for pacing — avoid burst-sending all at once)
    pending_dgram_replies: std.ArrayList([]const u8),
    files_completed: usize = 0,
    files_expected: usize = 0,

    fn init(alloc: std.mem.Allocator, session_id: u64, endpoint: []const u8, files: []const []const u8) SessionState {
        return .{
            .session_id = session_id,
            .endpoint = endpoint,
            .files = files,
            .bidi_bufs = std.AutoHashMap(u64, std.ArrayList(u8)).init(alloc),
            .uni_bufs = std.AutoHashMap(u64, std.ArrayList(u8)).init(alloc),
            .pending_gets = std.AutoHashMap(u64, []const u8).init(alloc),
            .pending_dgram_replies = .{ .items = &.{}, .capacity = 0 },
        };
    }

    fn deinit(self: *SessionState, alloc: std.mem.Allocator) void {
        {
            var it = self.bidi_bufs.iterator();
            while (it.next()) |entry| entry.value_ptr.deinit(alloc);
            self.bidi_bufs.deinit();
        }
        {
            var it = self.uni_bufs.iterator();
            while (it.next()) |entry| entry.value_ptr.deinit(alloc);
            self.uni_bufs.deinit();
        }
        self.pending_gets.deinit();
    }
};

pub fn main() !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    // Read environment variables
    const testcase_str = posix.getenv("TESTCASE") orelse "handshake";
    const testcase = parseTestCase(testcase_str);
    const sslkeylogfile_path = posix.getenv("SSLKEYLOGFILE");
    const qlog_dir = posix.getenv("QLOGDIR");
    const protocols_str = posix.getenv("PROTOCOLS") orelse "";

    std.log.info("interop wt client: testcase={s}", .{testcase_str});

    if (testcase == .unsupported) {
        std.log.err("unsupported test case: {s}", .{testcase_str});
        std.process.exit(127);
    }

    // Parse client protocols
    var client_protocols: std.ArrayList([]const u8) = .{ .items = &.{}, .capacity = 0 };
    {
        var it = mem.splitScalar(u8, protocols_str, ' ');
        while (it.next()) |p| {
            if (p.len > 0) try client_protocols.append(alloc, p);
        }
    }

    // Parse request URLs from CLI args
    const args = try std.process.argsAlloc(alloc);
    var urls: std.ArrayList(ParsedUrl) = .{ .items = &.{}, .capacity = 0 };
    for (args[1..]) |arg| {
        if (parseUrl(arg)) |url| {
            try urls.append(alloc, url);
        }
    }

    if (urls.items.len == 0) {
        std.log.err("no URLs provided", .{});
        std.process.exit(1);
    }

    // Group URLs by endpoint
    const groups = try groupByEndpoint(alloc, urls.items);
    std.log.info("parsed {d} endpoint group(s) from {d} URL(s)", .{ groups.items.len, urls.items.len });

    // Open SSLKEYLOGFILE if requested
    const keylog_file: ?std.fs.File = if (sslkeylogfile_path) |path|
        std.fs.cwd().createFile(path, .{}) catch null
    else
        null;
    defer if (keylog_file) |f| f.close();

    // Resolve server address
    const host = urls.items[0].host;
    const port = urls.items[0].port;
    const server_addr = blk: {
        break :blk net.Address.resolveIp(host, port) catch {
            const list = net.getAddressList(alloc, host, port) catch |err| {
                std.log.err("failed to resolve {s}:{d}: {any}", .{ host, port, err });
                return err;
            };
            defer list.deinit();
            if (list.addrs.len == 0) {
                std.log.err("no addresses for {s}:{d}", .{ host, port });
                return error.UnknownHostName;
            }
            break :blk list.addrs[0];
        };
    };

    // Create dual-stack UDP socket
    const sockfd = try posix.socket(posix.AF.INET6, posix.SOCK.DGRAM | posix.SOCK.NONBLOCK, 0);
    defer posix.close(sockfd);
    const IPV6_V6ONLY: u32 = if (@import("builtin").os.tag == .linux) 26 else 27;
    const zero: c_int = 0;
    posix.setsockopt(sockfd, posix.IPPROTO.IPV6, IPV6_V6ONLY, mem.asBytes(&zero)) catch {};
    const local_addr = try net.Address.parseIp6("::", 0);
    try posix.bind(sockfd, &local_addr.any, local_addr.getOsSockLen());
    ecn_socket.enableEcnRecv(sockfd) catch {};

    // Build TLS config (h3 ALPN for WebTransport)
    const alpn = try alloc.alloc([]const u8, 1);
    alpn[0] = "h3";

    const tls_config: tls13.TlsConfig = .{
        .cert_chain_der = &.{},
        .private_key_bytes = &.{},
        .alpn = alpn,
        .server_name = host,
        .skip_cert_verify = true,
        .keylog_file = keylog_file,
    };

    var conn = try connection.connect(alloc, host, .{
        .qlog_dir = qlog_dir,
        .max_datagram_frame_size = 1452,
        .initial_max_stream_data_uni = 4_194_304,
        .initial_max_stream_data_bidi_local = 4_194_304,
        .initial_max_stream_data_bidi_remote = 4_194_304,
    }, tls_config, null);
    defer conn.deinit();

    var remote_addr = connection.sockaddrToStorage(&server_addr.any);
    ecn_socket.mapV4ToV6(&remote_addr);
    var addr_size: posix.socklen_t = connection.sockaddrLen(&remote_addr);
    var out: [MAX_DATAGRAM_SIZE]u8 = undefined;

    // ---- Handshake phase ----
    var handshake_complete = false;
    const handshake_start = std.time.nanoTimestamp();
    while (!handshake_complete and (std.time.nanoTimestamp() - handshake_start) < TIMEOUT_NS) {
        conn.onTimeout() catch {};
        {
            var sc: usize = 0;
            while (sc < 10) : (sc += 1) {
                const bw = conn.send(&out) catch break;
                if (bw == 0) break;
                ecn_socket.setEcnMark(sockfd, conn.getEcnMark()) catch {};
                _ = posix.sendto(sockfd, out[0..bw], 0, @ptrCast(&remote_addr), addr_size) catch {};
            }
        }
        var received_any = false;
        while (true) {
            var bytes: [8192]u8 = undefined;
            const recv_result = ecn_socket.recvmsgEcn(sockfd, &bytes) catch break;
            received_any = true;
            remote_addr = recv_result.from_addr;
            addr_size = recv_result.addr_len;
            conn.handleDatagram(bytes[0..recv_result.bytes_read], .{
                .to = connection.sockaddrToStorage(&local_addr.any),
                .from = remote_addr,
                .ecn = recv_result.ecn,
                .datagram_size = recv_result.bytes_read,
            });
            if (conn.state == .connected) handshake_complete = true;
        }
        if (received_any) {
            var fc: usize = 0;
            while (fc < 10) : (fc += 1) {
                const fb = conn.send(&out) catch break;
                if (fb == 0) break;
                ecn_socket.setEcnMark(sockfd, conn.getEcnMark()) catch {};
                _ = posix.sendto(sockfd, out[0..fb], 0, @ptrCast(&remote_addr), addr_size) catch {};
            }
        }
        if (!received_any) std.Thread.sleep(1 * std.time.ns_per_ms);
    }

    if (!handshake_complete) {
        std.log.err("handshake failed", .{});
        std.process.exit(1);
    }
    std.log.info("QUIC handshake complete", .{});

    // Flush post-handshake
    {
        var fc: usize = 0;
        while (fc < 10) : (fc += 1) {
            const bw = conn.send(&out) catch break;
            if (bw == 0) break;
            ecn_socket.setEcnMark(sockfd, conn.getEcnMark()) catch {};
            _ = posix.sendto(sockfd, out[0..bw], 0, @ptrCast(&remote_addr), addr_size) catch {};
        }
    }

    // Sync remote_addr from active path
    remote_addr = conn.peerAddress().*;
    ecn_socket.mapV4ToV6(&remote_addr);
    addr_size = connection.sockaddrLen(&remote_addr);

    // ---- Initialize H3 + WT ----
    var h3c = h3.H3Connection.init(alloc, &conn, false);
    defer h3c.deinit();
    h3c.local_settings.enable_connect_protocol = true;
    h3c.local_settings.h3_datagram = true;
    h3c.local_settings.enable_webtransport = true;
    h3c.local_settings.webtransport_max_sessions = 1;
    try h3c.initConnection();

    var wt = webtransport.WebTransportConnection.init(alloc, &h3c, &conn, false);
    defer wt.deinit();

    // Flush H3 control streams
    burstSend(&conn, sockfd, &out, &remote_addr, addr_size);

    // Wait for server's SETTINGS before opening sessions (need to know if WT is enabled)
    {
        const settings_start = std.time.nanoTimestamp();
        while (!h3c.peer_settings_received and (std.time.nanoTimestamp() - settings_start) < 10 * std.time.ns_per_s) {
            drainRecv(&conn, sockfd, local_addr, &remote_addr, &addr_size);
            conn.onTimeout() catch {};
            _ = wt.poll() catch {};
            burstSend(&conn, sockfd, &out, &remote_addr, addr_size);
            std.Thread.sleep(1 * std.time.ns_per_ms);
        }
        if (!h3c.peer_settings_received) {
            std.log.warn("did not receive server SETTINGS, proceeding anyway", .{});
        }
    }

    // ---- Open WT sessions per endpoint group ----
    var session_states: std.ArrayList(SessionState) = .{ .items = &.{}, .capacity = 0 };
    defer {
        for (session_states.items) |*s| s.deinit(alloc);
        session_states.deinit(alloc);
    }

    for (groups.items) |*group| {
        // Build protocol header if we have protocols to negotiate
        var proto_header_buf: [1024]u8 = undefined;
        var proto_header_len: usize = 0;

        if (client_protocols.items.len > 0) {
            // Send as HTTP Structured Fields list of quoted strings (RFC 8941)
            var fbs = std.io.fixedBufferStream(&proto_header_buf);
            for (client_protocols.items, 0..) |p, idx| {
                if (idx > 0) fbs.writer().writeAll(", ") catch {};
                fbs.writer().writeByte('"') catch {};
                fbs.writer().writeAll(p) catch {};
                fbs.writer().writeByte('"') catch {};
            }
            proto_header_len = fbs.pos;
        }

        const session_id = blk: {
            if (proto_header_len > 0) {
                const extra = [_]qpack.Header{
                    .{ .name = "wt-available-protocols", .value = proto_header_buf[0..proto_header_len] },
                };
                break :blk wt.connectWithHeaders("server4:443", group.endpoint, &extra) catch |err| {
                    std.log.err("failed to connect WT session to {s}: {any}", .{ group.endpoint, err });
                    continue;
                };
            } else {
                break :blk wt.connect("server4:443", group.endpoint) catch |err| {
                    std.log.err("failed to connect WT session to {s}: {any}", .{ group.endpoint, err });
                    continue;
                };
            }
        };

        var ss = SessionState.init(alloc, session_id, group.endpoint, group.files.items);
        ss.files_expected = group.files.items.len;
        try session_states.append(alloc, ss);
        std.log.info("opened WT session {d} to {s} ({d} files)", .{ session_id, group.endpoint, group.files.items.len });
    }

    burstSend(&conn, sockfd, &out, &remote_addr, addr_size);

    // ---- Main event loop ----
    const start_time = std.time.nanoTimestamp();
    var done = false;
    // transfer mode (responder) runs until killed; receive modes have a timeout
    const has_timeout = (testcase != .transfer);

    while (!done and (!has_timeout or (std.time.nanoTimestamp() - start_time) < TIMEOUT_NS)) {
        if (conn.isClosed() or conn.isDraining()) {
            std.log.warn("connection terminated", .{});
            break;
        }

        // Receive packets
        var packets_received: usize = 0;
        {
            var rb: usize = 0;
            while (rb < 100) : (rb += 1) {
                var bytes: [MAX_DATAGRAM_SIZE]u8 = undefined;
                const recv_result = ecn_socket.recvmsgEcn(sockfd, &bytes) catch break;
                packets_received += 1;
                conn.handleDatagram(bytes[0..recv_result.bytes_read], .{
                    .to = connection.sockaddrToStorage(&local_addr.any),
                    .from = recv_result.from_addr,
                    .ecn = recv_result.ecn,
                    .datagram_size = recv_result.bytes_read,
                });
            }
        }

        conn.onTimeout() catch {};

        // Poll WT events and handle per-session logic
        for (session_states.items) |*ss| {
            done = pollWtEvents(alloc, &wt, ss, testcase) or done;
        }

        // Drip-feed deferred datagram replies: queue a few per iteration to avoid
        // bursting 200 datagrams into the CC window at once.
        for (session_states.items) |*ss| {
            sendPendingDgramReplies(alloc, &wt, ss, &conn);
        }

        // Burst send
        burstSend(&conn, sockfd, &out, &remote_addr, addr_size);

        if (packets_received == 0) std.Thread.sleep(200 * std.time.ns_per_us);
    }

    if (done) {
        // Final flush
        burstSend(&conn, sockfd, &out, &remote_addr, addr_size);
        std.Thread.sleep(100 * std.time.ns_per_ms);
        burstSend(&conn, sockfd, &out, &remote_addr, addr_size);
        std.log.info("interop wt client: test complete", .{});
        std.process.exit(0);
    }

    std.log.err("interop wt client: timeout", .{});
    std.process.exit(1);
}

/// Poll WT events and handle test-case-specific logic.
/// Returns true when the test is done.
fn pollWtEvents(
    alloc: std.mem.Allocator,
    wt: *webtransport.WebTransportConnection,
    state: *SessionState,
    testcase: TestCase,
) bool {
    // Session ready: initiate requests for receive-mode tests
    if (state.session_ready and !state.requests_sent) {
        state.requests_sent = true;
        switch (testcase) {
            .handshake => {
                // Already handled in session_ready event
            },
            .transfer_unidirectional_receive => {
                for (state.files) |filename| {
                    const stream_id = wt.openUniStream(state.session_id) catch |err| {
                        std.log.err("failed to open uni stream: {any}", .{err});
                        continue;
                    };
                    var get_buf: [1024]u8 = undefined;
                    const get_msg = std.fmt.bufPrint(&get_buf, "GET {s}", .{filename}) catch continue;
                    wt.sendStreamData(stream_id, get_msg) catch |err| {
                        std.log.err("failed to send GET: {any}", .{err});
                        continue;
                    };
                    wt.closeStream(stream_id);
                    std.log.info("sent GET {s} on uni stream {d}", .{ filename, stream_id });
                }
            },
            .transfer_bidirectional_receive => {
                for (state.files) |filename| {
                    const stream_id = wt.openBidiStream(state.session_id) catch |err| {
                        std.log.err("failed to open bidi stream: {any}", .{err});
                        continue;
                    };
                    var get_buf: [1024]u8 = undefined;
                    const get_msg = std.fmt.bufPrint(&get_buf, "GET {s}", .{filename}) catch continue;
                    wt.sendStreamData(stream_id, get_msg) catch |err| {
                        std.log.err("failed to send GET: {any}", .{err});
                        continue;
                    };
                    wt.closeStream(stream_id);
                    // Track this bidi stream for reading response
                    state.bidi_bufs.put(stream_id, std.ArrayList(u8){ .items = &.{}, .capacity = 0 }) catch {};
                    state.pending_gets.put(stream_id, filename) catch {};
                    std.log.info("sent GET {s} on bidi stream {d}", .{ filename, stream_id });
                }
            },
            .transfer_datagram_receive => {
                for (state.files) |filename| {
                    var get_buf: [1024]u8 = undefined;
                    const get_msg = std.fmt.bufPrint(&get_buf, "GET {s}", .{filename}) catch continue;
                    wt.sendDatagram(state.session_id, get_msg) catch |err| {
                        std.log.err("failed to send GET datagram: {any}", .{err});
                        continue;
                    };
                    std.log.info("sent GET {s} via datagram", .{filename});
                }
            },
            .transfer => {
                // Responder mode: wait for server to send GETs
            },
            .unsupported => {},
        }
    }

    while (true) {
        const event = wt.poll() catch break;
        if (event == null) break;

        switch (event.?) {
            .session_ready => |sr| {
                std.log.info("WT session {d} ready", .{sr.session_id});
                if (sr.session_id == state.session_id) {
                    state.session_ready = true;

                    // For handshake test: extract negotiated protocol from response headers
                    if (testcase == .handshake) {
                        var negotiated: []const u8 = "";
                        for (sr.headers) |hdr| {
                            if (mem.eql(u8, hdr.name, "wt-protocol") or mem.eql(u8, hdr.name, "sec-webtransport-protocol")) {
                                // Strip quotes from HTTP Structured Fields format
                                negotiated = mem.trim(u8, hdr.value, "\"");
                                break;
                            }
                        }
                        saveFile("/downloads", "negotiated_protocol.txt", negotiated) catch |err| {
                            std.log.err("failed to save negotiated_protocol.txt: {any}", .{err});
                        };
                        std.log.info("handshake: negotiated protocol = '{s}'", .{negotiated});
                        return true;
                    }
                }
            },

            .session_rejected => |sr| {
                std.log.err("WT session {d} rejected: {s}", .{ sr.session_id, sr.status });
            },

            .bidi_stream => |bs| {
                std.log.info("WT bidi stream: session={d} stream={d}", .{ bs.session_id, bs.stream_id });
                state.bidi_bufs.put(bs.stream_id, std.ArrayList(u8){ .items = &.{}, .capacity = 0 }) catch {};
            },

            .uni_stream => |us| {
                std.log.info("WT uni stream: session={d} stream={d}", .{ us.session_id, us.stream_id });
                state.uni_bufs.put(us.stream_id, std.ArrayList(u8){ .items = &.{}, .capacity = 0 }) catch {};
            },

            .stream_data => |sd| {
                if (state.bidi_bufs.getPtr(sd.stream_id)) |buf| {
                    buf.appendSlice(alloc, sd.data) catch {};
                } else if (state.uni_bufs.getPtr(sd.stream_id)) |buf| {
                    buf.appendSlice(alloc, sd.data) catch {};
                }
                if (sd.data.len > 0) alloc.free(sd.data);
            },

            .datagram => |dg| {
                handleDatagram(alloc, wt, state, testcase, dg.session_id, dg.data);
                if (dg.data.len > 0) alloc.free(dg.data);
            },

            .connect_request => {},
            .session_closed => |sc| {
                std.log.info("WT session {d} closed (code={d})", .{ sc.session_id, sc.error_code });
            },
            .session_draining => |sd| {
                std.log.info("WT session {d} draining", .{sd.session_id});
            },
        }
    }

    // Check for completed streams
    checkFinishedStreams(alloc, wt, state, testcase);

    // Check completion for receive-mode tests
    if (state.files_expected > 0 and state.files_completed >= state.files_expected) {
        std.log.info("all {d} files received", .{state.files_expected});
        return true;
    }

    return false;
}

/// Check for streams that have received FIN and process accumulated data.
fn checkFinishedStreams(
    alloc: std.mem.Allocator,
    wt: *webtransport.WebTransportConnection,
    state: *SessionState,
    testcase: TestCase,
) void {
    // Check bidi streams
    var bidi_finished: [64]u64 = undefined;
    var bidi_finished_count: usize = 0;
    {
        var it = state.bidi_bufs.iterator();
        while (it.next()) |entry| {
            const stream_id = entry.key_ptr.*;
            if (wt.quic.streams.getStream(stream_id)) |stream| {
                if (stream.recv.read()) |data| {
                    defer alloc.free(data);
                    entry.value_ptr.appendSlice(alloc, data) catch {};
                }
                if (stream.recv.finished) {
                    if (bidi_finished_count < 64) {
                        bidi_finished[bidi_finished_count] = stream_id;
                        bidi_finished_count += 1;
                    }
                }
            }
        }
    }
    for (bidi_finished[0..bidi_finished_count]) |stream_id| {
        if (state.bidi_bufs.get(stream_id)) |buf| {
            handleBidiStreamComplete(alloc, wt, state, testcase, stream_id, buf.items);
            if (state.bidi_bufs.getPtr(stream_id)) |buf_ptr| {
                buf_ptr.deinit(alloc);
                _ = state.bidi_bufs.remove(stream_id);
            }
        }
    }

    // Check uni streams
    var uni_finished: [64]u64 = undefined;
    var uni_finished_count: usize = 0;
    {
        var it = state.uni_bufs.iterator();
        while (it.next()) |entry| {
            const stream_id = entry.key_ptr.*;
            if (wt.quic.streams.recv_streams.get(stream_id)) |recv_stream| {
                if (recv_stream.read()) |data| {
                    defer alloc.free(data);
                    entry.value_ptr.appendSlice(alloc, data) catch {};
                }
                if (recv_stream.finished) {
                    if (uni_finished_count < 64) {
                        uni_finished[uni_finished_count] = stream_id;
                        uni_finished_count += 1;
                    }
                }
            }
        }
    }
    for (uni_finished[0..uni_finished_count]) |stream_id| {
        if (state.uni_bufs.get(stream_id)) |buf| {
            handleUniStreamComplete(alloc, wt, state, testcase, stream_id, buf.items);
            if (state.uni_bufs.getPtr(stream_id)) |buf_ptr| {
                buf_ptr.deinit(alloc);
                _ = state.uni_bufs.remove(stream_id);
            }
        }
    }
}

/// Handle a completed bidi stream.
fn handleBidiStreamComplete(
    alloc: std.mem.Allocator,
    wt: *webtransport.WebTransportConnection,
    state: *SessionState,
    testcase: TestCase,
    stream_id: u64,
    data: []const u8,
) void {
    switch (testcase) {
        .transfer_bidirectional_receive => {
            // Server sent file contents back on same bidi stream
            if (state.pending_gets.get(stream_id)) |filename| {
                // Build save path: endpoint/filename (strip leading /)
                var ep = state.endpoint;
                if (ep.len > 0 and ep[0] == '/') ep = ep[1..];
                var path_buf: [1024]u8 = undefined;
                const save_path = std.fmt.bufPrint(&path_buf, "{s}/{s}", .{ ep, filename }) catch return;
                saveFile("/downloads", save_path, data) catch |err| {
                    std.log.err("failed to save {s}: {any}", .{ save_path, err });
                };
                state.files_completed += 1;
                std.log.info("bidi-recv: saved {s} ({d}/{d})", .{ save_path, state.files_completed, state.files_expected });
            }
        },
        .transfer => {
            // Responder: server sent "GET filename" on bidi stream, we respond with file contents
            if (mem.startsWith(u8, data, "GET ")) {
                const filename = mem.trim(u8, data[4..], " \r\n");
                std.log.info("transfer bidi: GET {s} on stream {d}", .{ filename, stream_id });
                // Build www path: endpoint/filename
                var ep = state.endpoint;
                if (ep.len > 0 and ep[0] == '/') ep = ep[1..];
                const file_data = readFileFromWww(alloc, "/www", ep, filename) catch |err| {
                    std.log.err("transfer bidi: file not found: {s}: {any}", .{ filename, err });
                    return;
                };
                defer alloc.free(file_data);
                wt.sendStreamData(stream_id, file_data) catch |err| {
                    std.log.err("transfer bidi: send error: {any}", .{err});
                };
                wt.closeStream(stream_id);
            }
        },
        else => {},
    }
}

/// Handle a completed uni stream.
fn handleUniStreamComplete(
    alloc: std.mem.Allocator,
    wt: *webtransport.WebTransportConnection,
    state: *SessionState,
    testcase: TestCase,
    stream_id: u64,
    data: []const u8,
) void {
    _ = stream_id;
    switch (testcase) {
        .transfer_unidirectional_receive => {
            // Server sent "PUSH filename\n" + file contents on a new uni stream
            if (mem.startsWith(u8, data, "PUSH ")) {
                const newline_pos = mem.indexOf(u8, data, "\n") orelse return;
                const filename = mem.trim(u8, data[5..newline_pos], " \r");
                const file_data = data[newline_pos + 1 ..];
                // Build save path: endpoint/filename
                var ep = state.endpoint;
                if (ep.len > 0 and ep[0] == '/') ep = ep[1..];
                var path_buf: [1024]u8 = undefined;
                const save_path = std.fmt.bufPrint(&path_buf, "{s}/{s}", .{ ep, filename }) catch return;
                saveFile("/downloads", save_path, file_data) catch |err| {
                    std.log.err("failed to save {s}: {any}", .{ save_path, err });
                    return;
                };
                state.files_completed += 1;
                std.log.info("uni-recv: saved {s} ({d}/{d})", .{ save_path, state.files_completed, state.files_expected });
            }
        },
        .transfer => {
            // Responder: server sent "GET filename" on uni stream, we open NEW uni stream with PUSH
            if (mem.startsWith(u8, data, "GET ")) {
                const filename = mem.trim(u8, data[4..], " \r\n");
                std.log.info("transfer uni: GET {s}", .{filename});
                var ep = state.endpoint;
                if (ep.len > 0 and ep[0] == '/') ep = ep[1..];
                const file_data = readFileFromWww(alloc, "/www", ep, filename) catch |err| {
                    std.log.err("transfer uni: file not found: {s}: {any}", .{ filename, err });
                    return;
                };
                defer alloc.free(file_data);

                const new_stream_id = wt.openUniStream(state.session_id) catch |err| {
                    std.log.err("transfer uni: open stream error: {any}", .{err});
                    return;
                };
                var push_buf: [1024]u8 = undefined;
                const push_header = std.fmt.bufPrint(&push_buf, "PUSH {s}\n", .{filename}) catch return;
                wt.sendStreamData(new_stream_id, push_header) catch |err| {
                    std.log.err("transfer uni: send push header error: {any}", .{err});
                    return;
                };
                wt.sendStreamData(new_stream_id, file_data) catch |err| {
                    std.log.err("transfer uni: send file data error: {any}", .{err});
                    return;
                };
                wt.closeStream(new_stream_id);
                std.log.info("transfer uni: sent PUSH {s} ({d} bytes)", .{ filename, file_data.len });
            }
        },
        else => {},
    }
}

/// Handle a received datagram.
fn handleDatagram(
    alloc: std.mem.Allocator,
    _: *webtransport.WebTransportConnection,
    state: *SessionState,
    testcase: TestCase,
    _: u64,
    data: []const u8,
) void {
    switch (testcase) {
        .transfer_datagram_receive => {
            // Server sent "PUSH filename\n" + file contents as datagram
            if (mem.startsWith(u8, data, "PUSH ")) {
                const newline_pos = mem.indexOf(u8, data, "\n") orelse return;
                const filename = mem.trim(u8, data[5..newline_pos], " \r");
                const file_data = data[newline_pos + 1 ..];
                var ep = state.endpoint;
                if (ep.len > 0 and ep[0] == '/') ep = ep[1..];
                var path_buf: [1024]u8 = undefined;
                const save_path = std.fmt.bufPrint(&path_buf, "{s}/{s}", .{ ep, filename }) catch return;
                saveFile("/downloads", save_path, file_data) catch |err| {
                    std.log.err("failed to save {s}: {any}", .{ save_path, err });
                    return;
                };
                state.files_completed += 1;
                std.log.info("dgram-recv: saved {s} ({d}/{d})", .{ save_path, state.files_completed, state.files_expected });
            }
        },
        .transfer => {
            // Responder: server sent "GET filename" datagram — defer reply to avoid burst
            if (mem.startsWith(u8, data, "GET ")) {
                const filename = mem.trim(u8, data[4..], " \r\n");
                std.log.info("transfer dgram: queued GET {s}", .{filename});
                const duped = alloc.dupe(u8, filename) catch return;
                state.pending_dgram_replies.append(alloc, duped) catch return;
            }
        },
        else => {},
    }
}

// ---- Utility functions ----

/// Send up to N pending datagram replies per call, to avoid bursting.
fn sendPendingDgramReplies(
    alloc: std.mem.Allocator,
    wt: *webtransport.WebTransportConnection,
    state: *SessionState,
    conn: *connection.Connection,
) void {
    // Drip-feed datagram replies to avoid bursting all at once.
    // Limit batch size and check QUIC queue depth to let the CC window
    // breathe between iterations.
    const max_batch: usize = 8;
    var sent: usize = 0;
    while (state.pending_dgram_replies.items.len > 0 and sent < max_batch) {
        // Don't queue more than a few datagrams at a time
        if (conn.isDatagramSendQueueFull()) break;

        const filename = state.pending_dgram_replies.orderedRemove(0);
        var ep = state.endpoint;
        if (ep.len > 0 and ep[0] == '/') ep = ep[1..];
        const file_data = readFileFromWww(alloc, "/www", ep, filename) catch |err| {
            std.log.err("transfer dgram: file not found: {s}: {any}", .{ filename, err });
            continue;
        };
        defer alloc.free(file_data);

        // Leave room for WT quarter_stream_id varint prefix (up to 8 bytes)
        var dgram_buf: [1192]u8 = undefined;
        var pos: usize = 0;
        const push_header = std.fmt.bufPrint(dgram_buf[pos..], "PUSH {s}\n", .{filename}) catch continue;
        pos += push_header.len;
        const copy_len = @min(file_data.len, dgram_buf.len - pos);
        @memcpy(dgram_buf[pos..][0..copy_len], file_data[0..copy_len]);
        pos += copy_len;

        wt.sendDatagram(state.session_id, dgram_buf[0..pos]) catch |err| {
            std.log.err("transfer dgram: send error: {any}", .{err});
            continue;
        };
        std.log.info("sent PUSH {s} ({d} bytes)", .{ filename, pos });
        sent += 1;
    }
}

fn readFileFromWww(alloc: std.mem.Allocator, www_dir: []const u8, endpoint: []const u8, filename: []const u8) ![]u8 {
    var path_buf: [4096]u8 = undefined;
    var pos: usize = 0;
    @memcpy(path_buf[pos..][0..www_dir.len], www_dir);
    pos += www_dir.len;
    if (www_dir.len > 0 and www_dir[www_dir.len - 1] != '/') {
        path_buf[pos] = '/';
        pos += 1;
    }
    if (endpoint.len > 0) {
        @memcpy(path_buf[pos..][0..endpoint.len], endpoint);
        pos += endpoint.len;
        path_buf[pos] = '/';
        pos += 1;
    }
    @memcpy(path_buf[pos..][0..filename.len], filename);
    pos += filename.len;

    return std.fs.cwd().readFileAlloc(alloc, path_buf[0..pos], MAX_FILE_SIZE);
}

fn saveFile(dir: []const u8, filename: []const u8, data: []const u8) !void {
    var path_buf: [4096]u8 = undefined;
    var pos: usize = 0;
    @memcpy(path_buf[pos..][0..dir.len], dir);
    pos += dir.len;
    if (dir.len > 0 and dir[dir.len - 1] != '/') {
        path_buf[pos] = '/';
        pos += 1;
    }
    @memcpy(path_buf[pos..][0..filename.len], filename);
    pos += filename.len;

    const path = path_buf[0..pos];

    // Create parent directory if needed
    if (mem.lastIndexOf(u8, path, "/")) |last_slash| {
        std.fs.cwd().makePath(path[0..last_slash]) catch {};
    }

    const file = try std.fs.cwd().createFile(path, .{});
    defer file.close();
    try file.writeAll(data);
    std.log.info("saved {s} ({d} bytes)", .{ path, data.len });
}

fn burstSend(conn: *connection.Connection, sockfd: posix.fd_t, out: *[MAX_DATAGRAM_SIZE]u8, remote_addr: *posix.sockaddr.storage, addr_size: posix.socklen_t) void {
    var sc: usize = 0;
    while (sc < 100) : (sc += 1) {
        const bw = conn.send(out) catch break;
        if (bw == 0) break;
        ecn_socket.setEcnMark(sockfd, conn.getEcnMark()) catch {};
        _ = posix.sendto(sockfd, out[0..bw], 0, @ptrCast(remote_addr), addr_size) catch {};
    }
}

fn drainRecv(
    conn: *connection.Connection,
    sockfd: posix.fd_t,
    local_addr: net.Address,
    remote_addr: *posix.sockaddr.storage,
    addr_size: *posix.socklen_t,
) void {
    while (true) {
        var bytes: [8192]u8 = undefined;
        const recv_result = ecn_socket.recvmsgEcn(sockfd, &bytes) catch break;
        remote_addr.* = recv_result.from_addr;
        addr_size.* = recv_result.addr_len;
        conn.handleDatagram(bytes[0..recv_result.bytes_read], .{
            .to = connection.sockaddrToStorage(&local_addr.any),
            .from = recv_result.from_addr,
            .ecn = recv_result.ecn,
            .datagram_size = recv_result.bytes_read,
        });
    }
}
