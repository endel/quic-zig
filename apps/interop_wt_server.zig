// WebTransport Interop Runner - Server Endpoint
//
// Reads environment variables set by the interop runner:
//   TESTCASE          - handshake, transfer, transfer-unidirectional-send,
//                       transfer-bidirectional-send, transfer-datagram-send
//   SSLKEYLOGFILE     - optional path to write TLS key log
//   QLOGDIR           - optional path to write qlog files
//   PROTOCOLS         - space-separated sub-protocols for negotiation
//   REQUESTS          - space-separated file paths (for *-send tests)
//
// Certs at /certs/cert.pem and /certs/priv.key.
// Server files at /www/. Downloads saved to /downloads/.
// Listens on 0.0.0.0:443.

const std = @import("std");
const posix = std.posix;
const mem = std.mem;

const lib = @import("quic");
const connection = lib.connection;
const connection_manager = lib.connection_manager;
const quic_crypto = lib.crypto;
const tls13 = lib.tls13;
const ecn_socket = lib.ecn_socket;
const h3 = lib.h3;
const qpack = lib.qpack;
const webtransport = lib.webtransport;

const MAX_DATAGRAM_SIZE: usize = 1500;
const MAX_FILE_SIZE: usize = 4 * 1024 * 1024; // 4MB
const TIMEOUT_NS: i128 = 120 * std.time.ns_per_s;

const TestCase = enum {
    handshake,
    transfer,
    transfer_unidirectional_send,
    transfer_bidirectional_send,
    transfer_datagram_send,
    unsupported,
};

fn parseTestCase(name: []const u8) TestCase {
    if (mem.eql(u8, name, "handshake")) return .handshake;
    if (mem.eql(u8, name, "transfer")) return .transfer;
    if (mem.eql(u8, name, "transfer-unidirectional-send")) return .transfer_unidirectional_send;
    if (mem.eql(u8, name, "transfer-bidirectional-send")) return .transfer_bidirectional_send;
    if (mem.eql(u8, name, "transfer-datagram-send")) return .transfer_datagram_send;
    return .unsupported;
}

/// Per-connection state for tracking WT session and pending operations.
const ConnState = struct {
    wt_conn: ?webtransport.WebTransportConnection = null,
    session_id: ?u64 = null,
    session_ready: bool = false,
    send_requests_initiated: bool = false,
    // Session endpoint path (e.g. "/endpoint_slug" -> "endpoint_slug")
    session_path_buf: [256]u8 = undefined,
    session_path_len: usize = 0,

    // For transfer test: accumulated data per stream
    bidi_bufs: std.AutoHashMap(u64, std.ArrayList(u8)),
    uni_bufs: std.AutoHashMap(u64, std.ArrayList(u8)),
    // Track stream -> filename for incoming PUSH responses
    pending_gets: std.AutoHashMap(u64, []const u8),
    // Deferred datagram replies (for pacing — avoid burst-sending all at once)
    pending_dgram_replies: std.ArrayList([]const u8),
    // Track completed files count
    files_completed: usize = 0,
    files_expected: usize = 0,

    fn init(alloc: std.mem.Allocator) ConnState {
        return .{
            .bidi_bufs = std.AutoHashMap(u64, std.ArrayList(u8)).init(alloc),
            .uni_bufs = std.AutoHashMap(u64, std.ArrayList(u8)).init(alloc),
            .pending_gets = std.AutoHashMap(u64, []const u8).init(alloc),
            .pending_dgram_replies = .{ .items = &.{}, .capacity = 0 },
        };
    }

    fn sessionPath(self: *const ConnState) []const u8 {
        return self.session_path_buf[0..self.session_path_len];
    }

    fn setSessionPath(self: *ConnState, path: []const u8) void {
        // Strip leading slash
        var clean = path;
        while (clean.len > 0 and clean[0] == '/') clean = clean[1..];
        const len = @min(clean.len, self.session_path_buf.len);
        @memcpy(self.session_path_buf[0..len], clean[0..len]);
        self.session_path_len = len;
    }

    fn deinit(self: *ConnState, alloc: std.mem.Allocator) void {
        if (self.wt_conn) |*wt| wt.deinit();
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
    const requests_str = posix.getenv("REQUESTS") orelse "";

    std.log.info("interop wt server: testcase={s}", .{testcase_str});

    if (testcase == .unsupported) {
        std.log.err("unsupported test case: {s}", .{testcase_str});
        std.process.exit(127);
    }

    // Parse server protocols
    var server_protocols: std.ArrayList([]const u8) = .{ .items = &.{}, .capacity = 0 };
    {
        var it = mem.splitScalar(u8, protocols_str, ' ');
        while (it.next()) |p| {
            if (p.len > 0) try server_protocols.append(alloc, p);
        }
    }

    // Parse request file paths (for *-send tests)
    var request_paths: std.ArrayList([]const u8) = .{ .items = &.{}, .capacity = 0 };
    {
        var it = mem.splitScalar(u8, requests_str, ' ');
        while (it.next()) |p| {
            if (p.len > 0) try request_paths.append(alloc, p);
        }
    }

    // Open SSLKEYLOGFILE if requested
    const keylog_file: ?std.fs.File = if (sslkeylogfile_path) |path|
        std.fs.cwd().createFile(path, .{}) catch null
    else
        null;
    defer if (keylog_file) |f| f.close();

    // Load certificates
    const cert_pem = loadFile(alloc, "/certs/cert.pem") catch |err| {
        std.log.err("failed to load /certs/cert.pem: {any}", .{err});
        return err;
    };
    const key_pem = loadFile(alloc, "/certs/priv.key") catch |err| {
        std.log.err("failed to load /certs/priv.key: {any}", .{err});
        return err;
    };

    const cert_chain = try tls13.parsePemCertChain(alloc, cert_pem);
    std.log.info("loaded {d} certificate(s)", .{cert_chain.len});

    var key_der_buf: [4096]u8 = undefined;
    const key_der = try tls13.parsePemPrivateKey(key_pem, &key_der_buf);
    const ec_private_key = try tls13.extractEcPrivateKey(key_der);

    // ALPN: h3 for WebTransport
    const alpn = try alloc.alloc([]const u8, 1);
    alpn[0] = "h3";

    var ticket_key: [16]u8 = undefined;
    std.crypto.random.bytes(&ticket_key);

    var retry_token_key: [16]u8 = undefined;
    std.crypto.random.bytes(&retry_token_key);

    var static_reset_key: [16]u8 = undefined;
    std.crypto.random.bytes(&static_reset_key);

    const tls_config: tls13.TlsConfig = .{
        .cert_chain_der = cert_chain,
        .private_key_bytes = ec_private_key,
        .alpn = alpn,
        .ticket_key = ticket_key,
        .keylog_file = keylog_file,
    };

    // Create UDP socket (dual-stack)
    const sockfd, const local_addr = blk: {
        const addr6 = try std.net.Address.parseIp6("::", 443);
        const fd6 = posix.socket(posix.AF.INET6, posix.SOCK.DGRAM | posix.SOCK.NONBLOCK, 0) catch {
            const addr4 = try std.net.Address.parseIp4("0.0.0.0", 443);
            const fd4 = try posix.socket(posix.AF.INET, posix.SOCK.DGRAM | posix.SOCK.NONBLOCK, 0);
            posix.bind(fd4, &addr4.any, addr4.getOsSockLen()) catch {
                posix.close(fd4);
                return error.BindFailed;
            };
            break :blk .{ fd4, addr4 };
        };
        const IPV6_V6ONLY: u32 = if (@import("builtin").os.tag == .linux) 26 else 27;
        const zero: c_int = 0;
        posix.setsockopt(fd6, posix.IPPROTO.IPV6, IPV6_V6ONLY, mem.asBytes(&zero)) catch {};
        posix.bind(fd6, &addr6.any, addr6.getOsSockLen()) catch {
            posix.close(fd6);
            const addr4 = try std.net.Address.parseIp4("0.0.0.0", 443);
            const fd4 = try posix.socket(posix.AF.INET, posix.SOCK.DGRAM | posix.SOCK.NONBLOCK, 0);
            posix.bind(fd4, &addr4.any, addr4.getOsSockLen()) catch {
                posix.close(fd4);
                return error.BindFailed;
            };
            break :blk .{ fd4, addr4 };
        };
        break :blk .{ fd6, addr6 };
    };
    defer posix.close(sockfd);
    ecn_socket.enableEcnRecv(sockfd) catch {};
    std.log.info("interop wt server listening on [::]:{d}", .{@as(u16, 443)});

    // ConnectionManager for accepting connections
    var conn_mgr = connection_manager.ConnectionManager.init(
        alloc,
        tls_config,
        .{
            .token_key = retry_token_key,
            .qlog_dir = qlog_dir,
            .max_datagram_frame_size = 1452,
            .initial_max_stream_data_uni = 4_194_304,
            .initial_max_stream_data_bidi_local = 4_194_304,
            .initial_max_stream_data_bidi_remote = 4_194_304,
        },
        retry_token_key,
        static_reset_key,
    );
    defer conn_mgr.deinit();

    // Per-connection state map (keyed by conn pointer)
    var conn_states = std.AutoHashMap(usize, *ConnState).init(alloc);
    defer conn_states.deinit();

    var remote_addr: posix.sockaddr.storage = mem.zeroes(posix.sockaddr.storage);
    var addr_size: posix.socklen_t = @sizeOf(posix.sockaddr);
    var out: [MAX_DATAGRAM_SIZE]u8 = undefined;

    const start_time = std.time.nanoTimestamp();
    var done = false;

    // transfer test runs until killed by the runner; other tests have a timeout
    const has_timeout = (testcase != .transfer);

    while (!done and (!has_timeout or (std.time.nanoTimestamp() - start_time) < TIMEOUT_NS)) {
        // Read loop: process all available UDP packets
        var packets_received: usize = 0;
        read_loop: while (true) {
            var bytes: [MAX_DATAGRAM_SIZE]u8 = undefined;
            addr_size = @sizeOf(posix.sockaddr);

            const recv_result = ecn_socket.recvmsgEcn(sockfd, &bytes) catch |err| {
                if (err == error.WouldBlock) break :read_loop;
                std.log.err("recvmsg error: {any}", .{err});
                break :read_loop;
            };
            packets_received += 1;
            remote_addr = recv_result.from_addr;
            addr_size = recv_result.addr_len;

            switch (conn_mgr.recvDatagram(bytes[0..recv_result.bytes_read], remote_addr, connection.sockaddrToStorage(&local_addr.any), recv_result.ecn, &out)) {
                .processed => |entry| {
                    const bytes_written = entry.conn.send(&out) catch continue;
                    if (bytes_written > 0) {
                        ecn_socket.setEcnMark(sockfd, entry.conn.getEcnMark()) catch {};
                        const send_addr = entry.conn.peerAddress();
                        _ = posix.sendto(sockfd, out[0..bytes_written], 0, @ptrCast(send_addr), connection.sockaddrLen(send_addr)) catch {};
                    }
                },
                .send_response => |data| {
                    _ = posix.sendto(sockfd, data, 0, @ptrCast(&remote_addr), addr_size) catch {};
                },
                .dropped => {},
            }
        }

        // Per-connection processing
        var i: usize = 0;
        while (i < conn_mgr.entries.items.len) {
            const entry = conn_mgr.entries.items[i];
            const conn = entry.conn;
            const conn_key = @intFromPtr(conn);

            // Initialize H3 + WT when connection is established
            if (conn.isEstablished() and !entry.h3_initialized) {
                entry.h3_conn = h3.H3Connection.init(alloc, conn, true);
                entry.h3_conn.?.local_settings.enable_connect_protocol = true;
                entry.h3_conn.?.local_settings.h3_datagram = true;
                entry.h3_conn.?.local_settings.enable_webtransport = true;
                entry.h3_conn.?.local_settings.webtransport_max_sessions = 1;
                entry.h3_conn.?.initConnection() catch |err| {
                    std.log.err("H3 init error: {any}", .{err});
                    i += 1;
                    continue;
                };

                // Create per-connection state
                const state = alloc.create(ConnState) catch {
                    i += 1;
                    continue;
                };
                state.* = ConnState.init(alloc);
                state.wt_conn = webtransport.WebTransportConnection.init(alloc, &entry.h3_conn.?, conn, true);
                conn_states.put(conn_key, state) catch {};

                entry.h3_initialized = true;
                std.log.info("connection established (total: {d})", .{conn_mgr.connectionCount()});
            }

            // Poll WT events
            if (conn_states.get(conn_key)) |state| {
                if (state.wt_conn != null) {
                    done = pollWtEvents(alloc, &state.wt_conn.?, state, testcase, server_protocols.items, request_paths.items);
                }
            }

            // Timeouts + close check
            if (!conn_mgr.tickEntry(entry)) {
                if (conn_states.get(conn_key)) |state| {
                    state.deinit(alloc);
                    alloc.destroy(state);
                    _ = conn_states.remove(conn_key);
                }
                continue;
            }

            // Drip-feed deferred datagram replies
            if (conn_states.get(conn_key)) |state| {
                sendPendingDgramReplies(alloc, state, conn);
            }

            // Burst send
            {
                var sc: usize = 0;
                while (sc < 100) : (sc += 1) {
                    const bytes_written = conn.send(&out) catch break;
                    if (bytes_written == 0) break;
                    ecn_socket.setEcnMark(sockfd, conn.getEcnMark()) catch {};
                    const send_addr = conn.peerAddress();
                    _ = posix.sendto(sockfd, out[0..bytes_written], 0, @ptrCast(send_addr), connection.sockaddrLen(send_addr)) catch {};
                }
            }

            i += 1;
        }

        if (packets_received == 0) std.Thread.sleep(200 * std.time.ns_per_us);
    }

    if (done) {
        // Flush remaining data before exiting
        for (conn_mgr.entries.items) |entry| {
            const conn = entry.conn;
            var flush_count: usize = 0;
            while (flush_count < 50) : (flush_count += 1) {
                const bytes_written = conn.send(&out) catch break;
                if (bytes_written == 0) break;
                ecn_socket.setEcnMark(sockfd, conn.getEcnMark()) catch {};
                const send_addr = conn.peerAddress();
                _ = posix.sendto(sockfd, out[0..bytes_written], 0, @ptrCast(send_addr), connection.sockaddrLen(send_addr)) catch {};
            }
        }
        // Brief drain to let final packets be sent
        std.Thread.sleep(100 * std.time.ns_per_ms);
        for (conn_mgr.entries.items) |entry| {
            const conn = entry.conn;
            var flush_count: usize = 0;
            while (flush_count < 50) : (flush_count += 1) {
                const bytes_written = conn.send(&out) catch break;
                if (bytes_written == 0) break;
                ecn_socket.setEcnMark(sockfd, conn.getEcnMark()) catch {};
                const send_addr = conn.peerAddress();
                _ = posix.sendto(sockfd, out[0..bytes_written], 0, @ptrCast(send_addr), connection.sockaddrLen(send_addr)) catch {};
            }
        }

        std.log.info("interop wt server: test complete, exiting", .{});
        std.process.exit(0);
    }

    std.log.err("interop wt server: timeout", .{});
    std.process.exit(1);
}

/// Poll WT events and handle test-case-specific logic.
/// Returns true when the test is done and the server should exit.
fn pollWtEvents(
    alloc: std.mem.Allocator,
    wt: *webtransport.WebTransportConnection,
    state: *ConnState,
    testcase: TestCase,
    server_protocols: []const []const u8,
    request_paths: []const []const u8,
) bool {
    // For *-send tests: initiate requests after session is ready
    if (state.session_ready and !state.send_requests_initiated) {
        switch (testcase) {
            .transfer_unidirectional_send => {
                state.send_requests_initiated = true;
                state.files_expected = request_paths.len;
                for (request_paths) |path| {
                    const filename = extractFilename(path);
                    const stream_id = wt.openUniStream(state.session_id.?) catch |err| {
                        std.log.err("failed to open uni stream: {any}", .{err});
                        continue;
                    };
                    var get_buf: [1024]u8 = undefined;
                    const get_msg = std.fmt.bufPrint(&get_buf, "GET {s}", .{filename}) catch continue;
                    wt.sendStreamData(stream_id, get_msg) catch |err| {
                        std.log.err("failed to send GET on uni stream: {any}", .{err});
                        continue;
                    };
                    wt.closeStream(stream_id);
                    state.pending_gets.put(stream_id, filename) catch {};
                    std.log.info("sent GET {s} on uni stream {d}", .{ filename, stream_id });
                }
            },
            .transfer_bidirectional_send => {
                state.send_requests_initiated = true;
                state.files_expected = request_paths.len;
                for (request_paths) |path| {
                    const filename = extractFilename(path);
                    const stream_id = wt.openBidiStream(state.session_id.?) catch |err| {
                        std.log.err("failed to open bidi stream: {any}", .{err});
                        continue;
                    };
                    var get_buf: [1024]u8 = undefined;
                    const get_msg = std.fmt.bufPrint(&get_buf, "GET {s}", .{filename}) catch continue;
                    wt.sendStreamData(stream_id, get_msg) catch |err| {
                        std.log.err("failed to send GET on bidi stream: {any}", .{err});
                        continue;
                    };
                    wt.closeStream(stream_id);
                    // Track this bidi stream for reading response
                    state.bidi_bufs.put(stream_id, std.ArrayList(u8){ .items = &.{}, .capacity = 0 }) catch {};
                    state.pending_gets.put(stream_id, filename) catch {};
                    std.log.info("sent GET {s} on bidi stream {d}", .{ filename, stream_id });
                }
            },
            .transfer_datagram_send => {
                state.send_requests_initiated = true;
                state.files_expected = request_paths.len;
                for (request_paths) |path| {
                    const filename = extractFilename(path);
                    var get_buf: [1024]u8 = undefined;
                    const get_msg = std.fmt.bufPrint(&get_buf, "GET {s}", .{filename}) catch continue;
                    wt.sendDatagram(state.session_id.?, get_msg) catch |err| {
                        std.log.err("failed to send GET datagram: {any}", .{err});
                        continue;
                    };
                    std.log.info("sent GET {s} via datagram", .{filename});
                }
            },
            else => {},
        }
    }

    while (true) {
        const event = wt.poll() catch break;
        if (event == null) break;

        switch (event.?) {
            .connect_request => |req| {
                std.log.info("WT connect request: session_id={d}, path={s}", .{ req.session_id, req.path });

                // Sub-protocol negotiation: find first client protocol matching server protocols
                var negotiated: ?[]const u8 = null;
                for (req.headers) |hdr| {
                    if (mem.eql(u8, hdr.name, "sec-webtransport-protocol")) {
                        // Client may send comma-separated or multiple headers
                        var proto_it = mem.splitScalar(u8, hdr.value, ',');
                        while (proto_it.next()) |client_proto_raw| {
                            const client_proto = mem.trim(u8, client_proto_raw, " ");
                            for (server_protocols) |sp| {
                                if (mem.eql(u8, client_proto, sp)) {
                                    negotiated = sp;
                                    break;
                                }
                            }
                            if (negotiated != null) break;
                        }
                        if (negotiated != null) break;
                    }
                }

                // Accept with sub-protocol header if negotiated
                if (negotiated) |proto| {
                    const extra = [_]qpack.Header{
                        .{ .name = "sec-webtransport-protocol", .value = proto },
                    };
                    wt.acceptSessionWithHeaders(req.session_id, &extra) catch |err| {
                        std.log.err("WT accept error: {any}", .{err});
                        continue;
                    };
                    std.log.info("WT session accepted with protocol: {s}", .{proto});

                    // For handshake test: write negotiated protocol and exit
                    if (testcase == .handshake) {
                        saveFile("/downloads", "negotiated_protocol.txt", proto) catch |err| {
                            std.log.err("failed to save negotiated_protocol.txt: {any}", .{err});
                        };
                        state.session_id = req.session_id;
                        state.session_ready = true;
                        return true;
                    }
                } else {
                    wt.acceptSession(req.session_id) catch |err| {
                        std.log.err("WT accept error: {any}", .{err});
                        continue;
                    };
                    std.log.info("WT session accepted (no sub-protocol)", .{});

                    // For handshake test with no protocol match: still write empty and succeed
                    if (testcase == .handshake) {
                        state.session_id = req.session_id;
                        state.session_ready = true;
                        return true;
                    }
                }

                state.session_id = req.session_id;
                state.session_ready = true;
                state.setSessionPath(req.path);
            },

            .bidi_stream => |bs| {
                std.log.info("WT bidi stream: session_id={d}, stream_id={d}", .{ bs.session_id, bs.stream_id });
                // Register for data tracking
                state.bidi_bufs.put(bs.stream_id, std.ArrayList(u8){ .items = &.{}, .capacity = 0 }) catch {};
            },

            .uni_stream => |us| {
                std.log.info("WT uni stream: session_id={d}, stream_id={d}", .{ us.session_id, us.stream_id });
                state.uni_bufs.put(us.stream_id, std.ArrayList(u8){ .items = &.{}, .capacity = 0 }) catch {};
            },

            .stream_data => |sd| {
                // Accumulate data for the stream
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

            .session_ready => |sr| {
                std.log.info("WT session {d} ready", .{sr.session_id});
            },

            .session_closed => |sc| {
                std.log.info("WT session {d} closed (code={d})", .{ sc.session_id, sc.error_code });
            },

            .session_rejected => |sr| {
                std.log.info("WT session {d} rejected: {s}", .{ sr.session_id, sr.status });
            },

            .session_draining => |sd| {
                std.log.info("WT session {d} draining", .{sd.session_id});
            },
        }
    }

    // Check for completed bidi/uni streams (FIN received) and process them
    checkFinishedStreams(alloc, wt, state, testcase);

    // Check if *-send tests are done (all expected files received)
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
    state: *ConnState,
    testcase: TestCase,
) void {
    // Check bidi streams
    var bidi_finished: [64]u64 = undefined;
    var bidi_finished_count: usize = 0;
    {
        var it = state.bidi_bufs.iterator();
        while (it.next()) |entry| {
            const stream_id = entry.key_ptr.*;
            // Read any remaining data
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
            // Remove to prevent re-processing
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
            // Remove to prevent re-processing
            if (state.uni_bufs.getPtr(stream_id)) |buf_ptr| {
                buf_ptr.deinit(alloc);
                _ = state.uni_bufs.remove(stream_id);
            }
        }
    }
}

/// Handle a completed bidi stream (client closed write side).
fn handleBidiStreamComplete(
    alloc: std.mem.Allocator,
    wt: *webtransport.WebTransportConnection,
    state: *ConnState,
    testcase: TestCase,
    stream_id: u64,
    data: []const u8,
) void {
    switch (testcase) {
        .transfer => {
            // Client sent "GET filename" on bidi stream. Server sends file contents back on same stream.
            if (mem.startsWith(u8, data, "GET ")) {
                const filename = mem.trim(u8, data[4..], " \r\n");
                std.log.info("transfer bidi: GET {s} on stream {d}", .{ filename, stream_id });
                const file_data = readFileFromWww(alloc, "/www", state.sessionPath(), filename) catch |err| {
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
        .transfer_bidirectional_send => {
            // Server initiated bidi GET; client sent file contents back on same stream.
            if (state.pending_gets.get(stream_id)) |filename| {
                var save_buf: [1024]u8 = undefined;
                const save_path = std.fmt.bufPrint(&save_buf, "{s}/{s}", .{ state.sessionPath(), filename }) catch filename;
                saveFile("/downloads", save_path, data) catch |err| {
                    std.log.err("failed to save {s}: {any}", .{ save_path, err });
                };
                state.files_completed += 1;
                std.log.info("bidi-send: saved {s} ({d}/{d})", .{ save_path, state.files_completed, state.files_expected });
            }
        },
        else => {},
    }
}

/// Handle a completed uni stream (client closed it).
fn handleUniStreamComplete(
    alloc: std.mem.Allocator,
    wt: *webtransport.WebTransportConnection,
    state: *ConnState,
    testcase: TestCase,
    stream_id: u64,
    data: []const u8,
) void {
    _ = stream_id;
    switch (testcase) {
        .transfer => {
            // Client sent "GET filename" on uni stream. Server opens NEW uni stream and sends "PUSH filename\n" + contents.
            if (mem.startsWith(u8, data, "GET ")) {
                const filename = mem.trim(u8, data[4..], " \r\n");
                std.log.info("transfer uni: GET {s}", .{filename});
                const file_data = readFileFromWww(alloc, "/www", state.sessionPath(), filename) catch |err| {
                    std.log.err("transfer uni: file not found: {s}: {any}", .{ filename, err });
                    return;
                };
                defer alloc.free(file_data);

                const new_stream_id = wt.openUniStream(state.session_id.?) catch |err| {
                    std.log.err("transfer uni: failed to open uni stream: {any}", .{err});
                    return;
                };

                // Send "PUSH filename\n" + file contents
                var push_header_buf: [1024]u8 = undefined;
                const push_header = std.fmt.bufPrint(&push_header_buf, "PUSH {s}\n", .{filename}) catch return;
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
        .transfer_unidirectional_send => {
            // Client sent "PUSH filename\n" + file contents on a new uni stream
            if (mem.startsWith(u8, data, "PUSH ")) {
                const newline_pos = mem.indexOf(u8, data, "\n") orelse return;
                const filename = mem.trim(u8, data[5..newline_pos], " \r");
                const file_data = data[newline_pos + 1 ..];
                var save_buf: [1024]u8 = undefined;
                const save_path = std.fmt.bufPrint(&save_buf, "{s}/{s}", .{ state.sessionPath(), filename }) catch filename;
                saveFile("/downloads", save_path, file_data) catch |err| {
                    std.log.err("failed to save {s}: {any}", .{ save_path, err });
                    return;
                };
                state.files_completed += 1;
                std.log.info("uni-send: saved {s} ({d}/{d})", .{ save_path, state.files_completed, state.files_expected });
            }
        },
        else => {},
    }
}

/// Handle a received datagram.
fn handleDatagram(
    alloc: std.mem.Allocator,
    _: *webtransport.WebTransportConnection,
    state: *ConnState,
    testcase: TestCase,
    _: u64,
    data: []const u8,
) void {
    switch (testcase) {
        .transfer => {
            // Client sent "GET filename" as datagram — defer reply to avoid burst
            if (mem.startsWith(u8, data, "GET ")) {
                const filename = mem.trim(u8, data[4..], " \r\n");
                std.log.info("transfer dgram: queued GET {s}", .{filename});
                const duped = alloc.dupe(u8, filename) catch return;
                state.pending_dgram_replies.append(alloc, duped) catch return;
            }
        },
        .transfer_datagram_send => {
            // Client sent "PUSH filename\n" + file contents as datagram
            if (mem.startsWith(u8, data, "PUSH ")) {
                const newline_pos = mem.indexOf(u8, data, "\n") orelse return;
                const filename = mem.trim(u8, data[5..newline_pos], " \r");
                const file_data = data[newline_pos + 1 ..];
                var save_buf: [1024]u8 = undefined;
                const save_path = std.fmt.bufPrint(&save_buf, "{s}/{s}", .{ state.sessionPath(), filename }) catch filename;
                saveFile("/downloads", save_path, file_data) catch |err| {
                    std.log.err("failed to save {s}: {any}", .{ save_path, err });
                    return;
                };
                state.files_completed += 1;
                std.log.info("dgram-send: saved {s} ({d}/{d})", .{ save_path, state.files_completed, state.files_expected });
            }
        },
        else => {},
    }
}

/// Send up to N pending datagram replies per call, to avoid bursting.
fn sendPendingDgramReplies(
    alloc: std.mem.Allocator,
    state: *ConnState,
    conn: *connection.Connection,
) void {
    var wt = &(state.wt_conn orelse return);
    const session_id = state.session_id orelse return;

    const max_batch: usize = 8;
    var sent: usize = 0;
    while (state.pending_dgram_replies.items.len > 0 and sent < max_batch) {
        if (conn.isDatagramSendQueueFull()) break;

        const filename = state.pending_dgram_replies.orderedRemove(0);
        const file_data = readFileFromWww(alloc, "/www", state.sessionPath(), filename) catch |err| {
            std.log.err("transfer dgram: file not found: {s}: {any}", .{ filename, err });
            continue;
        };
        defer alloc.free(file_data);

        var dgram_buf: [1192]u8 = undefined;
        var pos: usize = 0;
        const push_header = std.fmt.bufPrint(dgram_buf[pos..], "PUSH {s}\n", .{filename}) catch continue;
        pos += push_header.len;
        const copy_len = @min(file_data.len, dgram_buf.len - pos);
        @memcpy(dgram_buf[pos..][0..copy_len], file_data[0..copy_len]);
        pos += copy_len;

        wt.sendDatagram(session_id, dgram_buf[0..pos]) catch |err| {
            std.log.err("transfer dgram: send error: {any}", .{err});
            continue;
        };
        std.log.info("sent PUSH {s} ({d} bytes)", .{ filename, pos });
        sent += 1;
    }
}

// ---- Utility functions ----

fn readFileFromWww(alloc: std.mem.Allocator, www_dir: []const u8, endpoint: []const u8, filename: []const u8) ![]u8 {
    var clean_name = filename;
    while (clean_name.len > 0 and clean_name[0] == '/') {
        clean_name = clean_name[1..];
    }
    if (clean_name.len == 0) clean_name = "index.html";

    var full_path_buf: [4096]u8 = undefined;
    var pos: usize = 0;
    @memcpy(full_path_buf[pos..][0..www_dir.len], www_dir);
    pos += www_dir.len;
    if (www_dir.len > 0 and www_dir[www_dir.len - 1] != '/') {
        full_path_buf[pos] = '/';
        pos += 1;
    }
    if (endpoint.len > 0) {
        @memcpy(full_path_buf[pos..][0..endpoint.len], endpoint);
        pos += endpoint.len;
        full_path_buf[pos] = '/';
        pos += 1;
    }
    @memcpy(full_path_buf[pos..][0..clean_name.len], clean_name);
    pos += clean_name.len;

    return std.fs.cwd().readFileAlloc(alloc, full_path_buf[0..pos], MAX_FILE_SIZE);
}

fn saveFile(dir: []const u8, filename: []const u8, data: []const u8) !void {
    // Ensure parent directories exist
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
        const parent = path[0..last_slash];
        std.fs.cwd().makePath(parent) catch {};
    }

    const file = try std.fs.cwd().createFile(path, .{});
    defer file.close();
    try file.writeAll(data);
    std.log.info("saved {s} ({d} bytes)", .{ path, data.len });
}

fn loadFile(alloc: std.mem.Allocator, path: []const u8) ![]u8 {
    return std.fs.cwd().readFileAlloc(alloc, path, 65536);
}

/// Extract the filename from a request path like "endpoint1/file1.txt".
/// Returns just "file1.txt" (the part after the first path component).
fn extractFilename(path: []const u8) []const u8 {
    var result = path;
    while (result.len > 0 and result[0] == '/') {
        result = result[1..];
    }
    // Skip the endpoint component (first path segment)
    if (mem.indexOf(u8, result, "/")) |slash| {
        return result[slash + 1 ..];
    }
    return result;
}

/// Extract the endpoint from a request path like "endpoint1/file1.txt".
/// Returns "endpoint1".
fn extractEndpoint(path: []const u8) []const u8 {
    var result = path;
    while (result.len > 0 and result[0] == '/') {
        result = result[1..];
    }
    if (mem.indexOf(u8, result, "/")) |slash| {
        return result[0..slash];
    }
    return result;
}
