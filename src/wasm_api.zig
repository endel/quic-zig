// WASM entry point for quic-zig.
//
// Exposes a C-style API for JavaScript to drive QUIC client/server
// instances without real sockets — the JS host routes packets between
// WASM instances.

const std = @import("std");
const quic = @import("quic_core");
const platform = quic.platform;
const Connection = quic.connection.Connection;
const H3Connection = quic.h3.H3Connection;
const WebTransportConnection = quic.webtransport.WebTransportConnection;

// ── WASM imports (provided by JS) ─────────────────────────────────────

extern "env" fn console_log(ptr: [*]const u8, len: usize) void;
extern "env" fn random_fill(ptr: [*]u8, len: usize) void;

// ── std_options: route logging + crypto random to JS ──────────────────

pub const std_options: std.Options = .{
    .logFn = wasmLogFn,
    .cryptoRandomSeed = wasmCryptoRandomSeed,
};

fn wasmLogFn(
    comptime level: std.log.Level,
    comptime scope: @Type(.enum_literal),
    comptime format: []const u8,
    args: anytype,
) void {
    _ = level;
    _ = scope;
    var buf: [4096]u8 = undefined;
    const msg = std.fmt.bufPrint(&buf, format, args) catch return;
    console_log(msg.ptr, msg.len);
}

fn wasmCryptoRandomSeed(buffer: []u8) void {
    random_fill(buffer.ptr, buffer.len);
}

// ── Certificates (runtime-settable from JS, with embedded fallback) ──

const embedded_cert_der = @embedFile("wasm_certs/cert.der");
const embedded_key_der = @embedFile("wasm_certs/key.der");

fn extractRawKeyFromDer(der: []const u8) [32]u8 {
    var raw: [32]u8 = undefined;
    if (der.len >= 39 and der[5] == 0x04 and der[6] == 0x20) {
        @memcpy(&raw, der[7..39]);
    } else {
        @memset(&raw, 0);
    }
    return raw;
}

const embedded_raw_key: [32]u8 = extractRawKeyFromDer(embedded_key_der);

// Runtime cert/key storage (heap-allocated by qz_set_cert / qz_set_key)
var runtime_cert: ?[]u8 = null;
var runtime_raw_key: ?[32]u8 = null;

// Stable backing for the cert_chain_der slice-of-slices
var runtime_cert_slice: [1][]const u8 = undefined;

// ── Allocator: use WASM page allocator (supports free + memory growth) ──

const allocator = std.heap.wasm_allocator;

// ── Instance state ────────────────────────────────────────────────────

const EventEntry = struct {
    data: [1024]u8 = undefined,
    len: u16 = 0,
};

const MAX_EVENTS = 32;

/// Buffered data from WT poll events (stream_data / datagram).
/// The WT session's poll() consumes data from the FrameSorter, so we must
/// stash it here for the JS side to retrieve via qz_wt_read_stream / qz_wt_read_datagram.
const PendingData = struct {
    stream_id: u64 = 0, // stream_id for stream data, session_id for datagrams
    buf: [4096]u8 = undefined,
    len: u32 = 0,
    occupied: bool = false,
};

const MAX_PENDING = 16;

const Instance = struct {
    conn: *Connection, // heap-allocated (Connection is ~50KB with TLS buffers)
    h3: ?H3Connection = null,
    wt: ?WebTransportConnection = null,
    is_server: bool,
    initialized: bool = false,

    tls_config: quic.tls13.TlsConfig,
    conn_config: quic.connection.ConnectionConfig,

    events: [MAX_EVENTS]EventEntry = .{EventEntry{}} ** MAX_EVENTS,
    event_head: u16 = 0,
    event_tail: u16 = 0,
    event_count: u16 = 0,

    pending_stream: [MAX_PENDING]PendingData = .{PendingData{}} ** MAX_PENDING,
    pending_dgram: [MAX_PENDING]PendingData = .{PendingData{}} ** MAX_PENDING,

    fn pushEvent(self: *Instance, data: []const u8) void {
        if (self.event_count >= MAX_EVENTS) return;
        const idx = self.event_tail;
        const copy_len = @min(data.len, 1024);
        @memcpy(self.events[idx].data[0..copy_len], data[0..copy_len]);
        self.events[idx].len = @intCast(copy_len);
        self.event_tail = (self.event_tail + 1) % MAX_EVENTS;
        self.event_count += 1;
    }

    fn popEvent(self: *Instance, out: []u8) u32 {
        if (self.event_count == 0) return 0;
        const idx = self.event_head;
        const len = self.events[idx].len;
        if (out.len < len) return 0;
        @memcpy(out[0..len], self.events[idx].data[0..len]);
        self.event_head = (self.event_head + 1) % MAX_EVENTS;
        self.event_count -= 1;
        return len;
    }

    fn stashPending(slots: []PendingData, id: u64, data: []const u8) void {
        for (slots) |*slot| {
            if (!slot.occupied) {
                const copy_len: u32 = @intCast(@min(data.len, slot.buf.len));
                @memcpy(slot.buf[0..copy_len], data[0..copy_len]);
                slot.stream_id = id;
                slot.len = copy_len;
                slot.occupied = true;
                return;
            }
        }
        // All slots full — data is dropped (event still fires with correct length)
    }

    fn takePending(slots: []PendingData, id: u64, out: []u8) i32 {
        for (slots) |*slot| {
            if (slot.occupied and slot.stream_id == id) {
                const copy_len = @min(slot.len, @as(u32, @intCast(out.len)));
                @memcpy(out[0..copy_len], slot.buf[0..copy_len]);
                slot.occupied = false;
                return @intCast(copy_len);
            }
        }
        return 0;
    }
};

var instance: ?*Instance = null;

// ── Event type bytes ──────────────────────────────────────────────────
// See wasm/README.md for payload formats.

const EVT_ESTABLISHED: u8 = 0x01; // QUIC connected (no payload)
const EVT_CLOSED: u8 = 0x02; // Connection closed (no payload)
const EVT_STREAM_DATA: u8 = 0x03; // H3 stream data: [stream_id:u64 BE][len:u64 BE]
const EVT_DATAGRAM: u8 = 0x04; // Raw QUIC datagram (reserved)
const EVT_WT_SESSION: u8 = 0x05; // WT CONNECT request: [session_id:u64 BE]
const EVT_WT_BIDI_STREAM: u8 = 0x06; // New WT bidi stream: [session_id:u64 BE][stream_id:u64 BE]
const EVT_WT_STREAM_DATA: u8 = 0x07; // WT stream data: [stream_id:u64 BE][len:u64 BE]
const EVT_WT_STREAM_FIN: u8 = 0x08; // WT stream finished: [stream_id:u64 BE]
const EVT_WT_DATAGRAM: u8 = 0x09; // WT datagram: [session_id:u64 BE][len:u64 BE]
const EVT_WT_SESSION_CLOSED: u8 = 0x0A; // WT session closed: [session_id:u64 BE][error_code:u32 BE]

// ── Config helpers ────────────────────────────────────────────────────

const embedded_cert_slices = [_][]const u8{embedded_cert_der};
const alpn_slices = [_][]const u8{"h3"};

fn makeTlsConfig(is_server: bool) quic.tls13.TlsConfig {
    // Use runtime cert/key if provided, otherwise fall back to embedded
    const cert_chain: []const []const u8 = if (runtime_cert) |cert| blk: {
        runtime_cert_slice = [1][]const u8{cert};
        break :blk &runtime_cert_slice;
    } else &embedded_cert_slices;

    const key_bytes: []const u8 = if (runtime_raw_key) |*key|
        key
    else
        &embedded_raw_key;

    return .{
        .cert_chain_der = cert_chain,
        .private_key_bytes = key_bytes,
        .alpn = &alpn_slices,
        .server_name = if (!is_server) "localhost" else null,
        .skip_cert_verify = true,
    };
}

fn makeConnConfig() quic.connection.ConnectionConfig {
    return .{
        .max_idle_timeout = 30_000,
        .initial_max_data = 1_048_576,
        .initial_max_stream_data_bidi_local = 524_288,
        .initial_max_stream_data_bidi_remote = 524_288,
        .initial_max_stream_data_uni = 524_288,
        .initial_max_streams_bidi = 100,
        .initial_max_streams_uni = 100,
        .max_datagram_frame_size = 65536,
    };
}

// ── Exported API ──────────────────────────────────────────────────────

/// Set certificate DER bytes from JS. Call before qz_init_server/qz_init_client.
export fn qz_set_cert(ptr: [*]const u8, len: u32) i32 {
    if (runtime_cert) |old| allocator.free(old);
    const cert = allocator.alloc(u8, len) catch return -1;
    @memcpy(cert, ptr[0..len]);
    runtime_cert = cert;
    return 0;
}

/// Set private key DER bytes from JS. Call before qz_init_server/qz_init_client.
/// Accepts a DER-encoded EC private key and extracts the raw 32-byte P-256 scalar.
export fn qz_set_key(ptr: [*]const u8, len: u32) i32 {
    const der = ptr[0..len];
    runtime_raw_key = extractRawKeyFromDer(der);
    return 0;
}

export fn qz_init_server() i32 {
    return initInstance(true) catch return -1;
}

export fn qz_init_client() i32 {
    return initInstance(false) catch return -1;
}

fn initInstance(is_server: bool) !i32 {
    const tls_config = makeTlsConfig(is_server);
    const conn_config = makeConnConfig();

    // Heap-allocate Connection to avoid ~50KB stack overflow
    const conn = try allocator.create(Connection);

    const inst = try allocator.create(Instance);
    inst.* = Instance{
        .conn = conn,
        .is_server = is_server,
        .tls_config = tls_config,
        .conn_config = conn_config,
    };

    if (!is_server) {
        conn.* = try quic.connection.connect(
            allocator,
            "localhost",
            conn_config,
            tls_config,
            null,
        );
        inst.initialized = true;
    }

    instance = inst;
    return 0;
}

export fn qz_deinit() void {
    if (instance) |inst| {
        if (inst.initialized) {
            inst.conn.deinit();
        }
        allocator.destroy(inst.conn);
        allocator.destroy(inst);
        instance = null;
    }
}

export fn qz_recv_packet(data_ptr: [*]const u8, data_len: u32) i32 {
    const inst = instance orelse return -1;
    if (data_len == 0 or data_len > 65535) return -1;

    // Heap-allocate recv buffer to avoid stack pressure
    const buf = allocator.alloc(u8, data_len) catch return -1;
    defer allocator.free(buf);
    @memcpy(buf, data_ptr[0..data_len]);

    const local = std.mem.zeroes(platform.sockaddr_storage);
    const remote = std.mem.zeroes(platform.sockaddr_storage);

    // Lazy server init: accept connection on first Initial packet
    if (inst.is_server and !inst.initialized) {
        var fbs = std.io.fixedBufferStream(buf);
        const header = quic.packet.Header.parse(&fbs, 8) catch return -1;

        inst.conn.* = Connection.accept(
            allocator,
            header,
            local,
            remote,
            true,
            inst.conn_config,
            inst.tls_config,
            null,
            null,
        ) catch return -1;
        inst.initialized = true;
    }

    const recv_info = quic.connection.RecvInfo{
        .to = local,
        .from = remote,
        .ecn = 0,
        .datagram_size = data_len,
    };
    inst.conn.handleDatagram(buf, recv_info);

    // Check for state transitions
    if (inst.conn.state == .connected and inst.h3 == null) {
        inst.h3 = H3Connection.init(allocator, inst.conn, inst.is_server);
        // Set WebTransport settings BEFORE initConnection sends the SETTINGS frame
        inst.h3.?.local_settings.enable_connect_protocol = true;
        inst.h3.?.local_settings.enable_webtransport = true;
        inst.h3.?.local_settings.h3_datagram = true;
        inst.h3.?.initConnection() catch {};
        inst.wt = WebTransportConnection.init(allocator, &inst.h3.?, inst.conn, inst.is_server);
        var evt = [_]u8{EVT_ESTABLISHED};
        inst.pushEvent(&evt);
    }

    return 0;
}

export fn qz_send_packets(out_ptr: [*]u8, out_len: u32) u32 {
    const inst = instance orelse return 0;
    if (!inst.initialized) return 0;

    var total: u32 = 0;
    var remaining = out_ptr[0..out_len];

    while (remaining.len >= 4) {
        var pkt_buf: [1500]u8 = undefined;
        const n = inst.conn.send(&pkt_buf) catch break;
        if (n == 0) break;

        if (remaining.len < 4 + n) break;

        std.mem.writeInt(u32, remaining[0..4], @intCast(n), .big);
        @memcpy(remaining[4..][0..n], pkt_buf[0..n]);
        remaining = remaining[4 + n ..];
        total += @intCast(4 + n);
    }

    return total;
}

export fn qz_on_timeout() void {
    const inst = instance orelse return;
    if (!inst.initialized) return;
    inst.conn.onTimeout() catch {};
}

export fn qz_next_timeout_ns() i64 {
    const inst = instance orelse return -1;
    if (!inst.initialized) return -1;
    return inst.conn.nextTimeoutNs() orelse -1;
}

export fn qz_is_established() bool {
    const inst = instance orelse return false;
    if (!inst.initialized) return false;
    return inst.conn.state == .connected;
}

export fn qz_is_closed() bool {
    const inst = instance orelse return false;
    if (!inst.initialized) return false;
    return inst.conn.isClosed();
}

export fn qz_poll_event(buf_ptr: [*]u8, buf_len: u32) u32 {
    const inst = instance orelse return 0;

    // Poll through WebTransportConnection (wraps H3 → QUIC)
    if (inst.wt) |*wt| {
        while (inst.event_count < MAX_EVENTS) {
            const event = wt.poll() catch break;
            const ev = event orelse break;
            switch (ev) {
                .connect_request => |cr| {
                    var evt: [9]u8 = undefined;
                    evt[0] = EVT_WT_SESSION;
                    std.mem.writeInt(u64, evt[1..9], cr.session_id, .big);
                    inst.pushEvent(&evt);
                },
                .bidi_stream => |bs| {
                    var evt: [17]u8 = undefined;
                    evt[0] = EVT_WT_BIDI_STREAM;
                    std.mem.writeInt(u64, evt[1..9], bs.session_id, .big);
                    std.mem.writeInt(u64, evt[9..17], bs.stream_id, .big);
                    inst.pushEvent(&evt);
                },
                .stream_data => |sd| {
                    if (sd.data.len > 0) {
                        var evt: [17]u8 = undefined;
                        evt[0] = EVT_WT_STREAM_DATA;
                        std.mem.writeInt(u64, evt[1..9], sd.stream_id, .big);
                        std.mem.writeInt(u64, evt[9..17], @intCast(sd.data.len), .big);
                        inst.pushEvent(&evt);
                        Instance.stashPending(&inst.pending_stream, sd.stream_id, sd.data);
                    }
                    if (sd.fin) {
                        var fin_evt: [9]u8 = undefined;
                        fin_evt[0] = EVT_WT_STREAM_FIN;
                        std.mem.writeInt(u64, fin_evt[1..9], sd.stream_id, .big);
                        inst.pushEvent(&fin_evt);
                    }
                },
                .datagram => |dg| {
                    var evt: [17]u8 = undefined;
                    evt[0] = EVT_WT_DATAGRAM;
                    std.mem.writeInt(u64, evt[1..9], dg.session_id, .big);
                    std.mem.writeInt(u64, evt[9..17], @intCast(dg.data.len), .big);
                    inst.pushEvent(&evt);
                    Instance.stashPending(&inst.pending_dgram, dg.session_id, dg.data);
                },
                .session_closed => |sc| {
                    var evt: [13]u8 = undefined;
                    evt[0] = EVT_WT_SESSION_CLOSED;
                    std.mem.writeInt(u64, evt[1..9], sc.session_id, .big);
                    std.mem.writeInt(u32, evt[9..13], sc.error_code, .big);
                    inst.pushEvent(&evt);
                },
                else => {},
            }
        }
    }

    return inst.popEvent(buf_ptr[0..buf_len]);
}

export fn qz_stream_send(stream_id: u64, data_ptr: [*]const u8, data_len: u32) i32 {
    const inst = instance orelse return -1;
    const stream = inst.conn.streams.getStream(stream_id) orelse return -1;
    stream.send.writeData(data_ptr[0..data_len]) catch return -1;
    return 0;
}

export fn qz_stream_close(stream_id: u64) void {
    const inst = instance orelse return;
    const stream = inst.conn.streams.getStream(stream_id) orelse return;
    stream.send.close();
}

export fn qz_stream_read(stream_id: u64, out_ptr: [*]u8, out_len: u32) i32 {
    const inst = instance orelse return -1;
    const stream = inst.conn.streams.getStream(stream_id) orelse return -1;
    const data = stream.recv.read() orelse return 0;
    const copy_len = @min(data.len, out_len);
    @memcpy(out_ptr[0..copy_len], data[0..copy_len]);
    return @intCast(copy_len);
}

export fn qz_datagram_send(data_ptr: [*]const u8, data_len: u32) i32 {
    const inst = instance orelse return -1;
    inst.conn.sendDatagram(data_ptr[0..data_len]) catch return -1;
    return 0;
}

export fn qz_datagram_recv(out_ptr: [*]u8, out_len: u32) i32 {
    const inst = instance orelse return -1;
    const len = inst.conn.recvDatagram(out_ptr[0..out_len]) orelse return 0;
    return @intCast(len);
}

// ── WebTransport API ─────────────────────────────────────────────────

/// Accept a WT session (server-side). Call after receiving EVT_WT_SESSION.
/// Sends an HTTP/3 200 response on the CONNECT stream.
export fn qz_wt_accept_session(session_id: u64) i32 {
    const inst = instance orelse return -1;
    var wt = &(inst.wt orelse return -1);
    wt.acceptSession(session_id) catch return -1;
    return 0;
}

/// Read data from a WT stream. Call after receiving EVT_WT_STREAM_DATA.
/// Returns bytes read, 0 if nothing available, -1 on error.
export fn qz_wt_read_stream(stream_id: u64, out_ptr: [*]u8, out_len: u32) i32 {
    const inst = instance orelse return -1;
    return Instance.takePending(&inst.pending_stream, stream_id, out_ptr[0..out_len]);
}

/// Write data to a WT stream. Returns 0 on success, -1 on error.
export fn qz_wt_send_stream(stream_id: u64, data_ptr: [*]const u8, data_len: u32) i32 {
    const inst = instance orelse return -1;
    var wt = &(inst.wt orelse return -1);
    wt.sendStreamData(stream_id, data_ptr[0..data_len]) catch return -1;
    return 0;
}

/// Close (FIN) a WT stream.
export fn qz_wt_close_stream(stream_id: u64) void {
    const inst = instance orelse return;
    var wt = &(inst.wt orelse return);
    wt.closeStream(stream_id);
}

/// Read a received WT datagram. Call after receiving EVT_WT_DATAGRAM.
/// Returns bytes read, 0 if nothing available, -1 on error.
export fn qz_wt_read_datagram(session_id: u64, out_ptr: [*]u8, out_len: u32) i32 {
    const inst = instance orelse return -1;
    return Instance.takePending(&inst.pending_dgram, session_id, out_ptr[0..out_len]);
}

/// Send a WT datagram on a session. Returns 0 on success, -1 on error.
export fn qz_wt_send_datagram(session_id: u64, data_ptr: [*]const u8, data_len: u32) i32 {
    const inst = instance orelse return -1;
    var wt = &(inst.wt orelse return -1);
    wt.sendDatagram(session_id, data_ptr[0..data_len]) catch return -1;
    return 0;
}

/// Close a WT session with an error code and optional reason.
export fn qz_wt_close_session(session_id: u64, error_code: u32, reason_ptr: [*]const u8, reason_len: u32) i32 {
    const inst = instance orelse return -1;
    var wt = &(inst.wt orelse return -1);
    wt.closeSessionWithError(session_id, error_code, reason_ptr[0..reason_len]) catch return -1;
    return 0;
}

export fn qz_alloc(len: u32) u32 {
    if (len == 0) return 0;
    const slice = allocator.alloc(u8, len) catch return 0;
    return @intFromPtr(slice.ptr);
}

export fn qz_free(ptr_int: u32, len: u32) void {
    if (ptr_int == 0 or len == 0) return;
    const ptr: [*]u8 = @ptrFromInt(ptr_int);
    allocator.free(ptr[0..len]);
}
