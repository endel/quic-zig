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

// ── Embedded certificates ─────────────────────────────────────────────

const cert_der = @embedFile("wasm_certs/cert.der");
const key_der = @embedFile("wasm_certs/key.der");

fn extractRawKey() [32]u8 {
    var raw: [32]u8 = undefined;
    if (key_der.len >= 39 and key_der[5] == 0x04 and key_der[6] == 0x20) {
        @memcpy(&raw, key_der[7..39]);
    } else {
        @memset(&raw, 0);
    }
    return raw;
}

const raw_private_key: [32]u8 = extractRawKey();

// ── Allocator: use WASM page allocator (supports free + memory growth) ──

const allocator = std.heap.wasm_allocator;

// ── Instance state ────────────────────────────────────────────────────

const EventEntry = struct {
    data: [1024]u8 = undefined,
    len: u16 = 0,
};

const MAX_EVENTS = 32;

const Instance = struct {
    conn: *Connection, // heap-allocated (Connection is ~50KB with TLS buffers)
    h3: ?H3Connection = null,
    is_server: bool,
    initialized: bool = false,

    tls_config: quic.tls13.TlsConfig,
    conn_config: quic.connection.ConnectionConfig,

    events: [MAX_EVENTS]EventEntry = .{EventEntry{}} ** MAX_EVENTS,
    event_head: u16 = 0,
    event_tail: u16 = 0,
    event_count: u16 = 0,

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
};

var instance: ?*Instance = null;

// ── Event type bytes ──────────────────────────────────────────────────

const EVT_ESTABLISHED: u8 = 0x01;
const EVT_CLOSED: u8 = 0x02;
const EVT_STREAM_DATA: u8 = 0x03;
const EVT_DATAGRAM: u8 = 0x04;
const EVT_WT_SESSION: u8 = 0x05;

// ── Config helpers ────────────────────────────────────────────────────

const cert_slices = [_][]const u8{cert_der};
const alpn_slices = [_][]const u8{"h3"};

fn makeTlsConfig(is_server: bool) quic.tls13.TlsConfig {
    return .{
        .cert_chain_der = &cert_slices,
        .private_key_bytes = &raw_private_key,
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

    if (inst.h3) |*h3| {
        while (true) {
            const event = h3.poll() catch break;
            const ev = event orelse break;
            switch (ev) {
                .headers => |hdr| {
                    var evt: [9]u8 = undefined;
                    evt[0] = EVT_WT_SESSION;
                    std.mem.writeInt(u64, evt[1..9], hdr.stream_id, .big);
                    inst.pushEvent(&evt);
                },
                .data => |d| {
                    var evt: [17]u8 = undefined;
                    evt[0] = EVT_STREAM_DATA;
                    std.mem.writeInt(u64, evt[1..9], d.stream_id, .big);
                    std.mem.writeInt(u64, evt[9..17], @intCast(d.len), .big);
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

export fn qz_datagram_send(data_ptr: [*]const u8, data_len: u32) i32 {
    const inst = instance orelse return -1;
    inst.conn.sendDatagram(data_ptr[0..data_len]) catch return -1;
    return 0;
}

export fn qz_alloc(len: u32) ?[*]u8 {
    const slice = allocator.alloc(u8, len) catch return null;
    return slice.ptr;
}

export fn qz_free(ptr: [*]u8, len: u32) void {
    allocator.free(ptr[0..len]);
}
