const std = @import("std");
const Allocator = std.mem.Allocator;
const quic = @import("quic");
const event_loop = quic.event_loop;
const ConnEntry = quic.connection_manager.ConnEntry;

// ---------------------------------------------------------------------------
// Event types — matches the binary protocol consumed by JS
// ---------------------------------------------------------------------------

const EventType = enum(u8) {
    none = 0,
    connect_request = 1,
    session_ready = 2,
    session_closed = 3,
    session_draining = 4,
    bidi_stream = 5,
    uni_stream = 6,
    stream_data = 7,
    datagram = 8,
    client_disconnected = 9,
};

const HEADER_SIZE: usize = 24;

// ---------------------------------------------------------------------------
// QueuedEvent — internal representation of a pending event
// ---------------------------------------------------------------------------

const QueuedEvent = struct {
    event_type: EventType,
    flags: u8 = 0,
    client_id: u64 = 0,
    id1: u64 = 0, // session_id or stream_id depending on event type
    // Extended fields (event-type specific):
    error_code: u32 = 0, // SESSION_CLOSED
    extra_id: u64 = 0, // stream_id for BIDI/UNI, session_id for STREAM_DATA
    data: ?[]u8 = null, // owned copy — freed when event is consumed

    fn deinit(self: *QueuedEvent, allocator: Allocator) void {
        if (self.data) |d| allocator.free(d);
    }

    fn extendedSize(self: *const QueuedEvent) usize {
        return switch (self.event_type) {
            .session_closed => 4,
            .bidi_stream, .uni_stream, .stream_data => 8,
            else => 0,
        };
    }

    fn totalSize(self: *const QueuedEvent) usize {
        return HEADER_SIZE + self.extendedSize() + (if (self.data) |d| d.len else 0);
    }

    /// Serialize into caller-provided buffer. Returns bytes written.
    fn serialize(self: *const QueuedEvent, buf: [*]u8, buf_len: u32) u32 {
        const total = self.totalSize();
        if (total > buf_len) return 0;

        const data_len: u32 = if (self.data) |d| @intCast(d.len) else 0;
        const out = buf[0..buf_len];

        // Fixed header (24 bytes, little-endian)
        out[0] = @intFromEnum(self.event_type);
        out[1] = self.flags;
        std.mem.writeInt(u16, out[2..4], 0, .little); // reserved
        std.mem.writeInt(u32, out[4..8], data_len, .little);
        std.mem.writeInt(u64, out[8..16], self.client_id, .little);
        std.mem.writeInt(u64, out[16..24], self.id1, .little);

        // Extended fields
        var offset: usize = HEADER_SIZE;
        switch (self.event_type) {
            .session_closed => {
                std.mem.writeInt(u32, out[offset..][0..4], self.error_code, .little);
                offset += 4;
            },
            .bidi_stream, .uni_stream, .stream_data => {
                std.mem.writeInt(u64, out[offset..][0..8], self.extra_id, .little);
                offset += 8;
            },
            else => {},
        }

        // Variable-length data
        if (self.data) |d| {
            @memcpy(out[offset .. offset + d.len], d);
        }

        return @intCast(total);
    }
};

// ---------------------------------------------------------------------------
// CApiHandler — implements the quic-zig Handler interface
// ---------------------------------------------------------------------------

pub const CApiHandler = struct {
    pub const protocol: event_loop.Protocol = .webtransport;

    allocator: Allocator,
    next_client_id: u64 = 1,
    entry_to_client: std.AutoHashMapUnmanaged(*ConnEntry, u64) = .empty,
    client_to_entry: std.AutoHashMapUnmanaged(u64, *ConnEntry) = .empty,
    event_queue: std.ArrayListUnmanaged(QueuedEvent) = .empty,

    pub fn deinit(self: *CApiHandler) void {
        for (self.event_queue.items) |*ev| ev.deinit(self.allocator);
        self.event_queue.deinit(self.allocator);
        self.entry_to_client.deinit(self.allocator);
        self.client_to_entry.deinit(self.allocator);
    }

    fn getOrAssignClientId(self: *CApiHandler, entry: *ConnEntry) u64 {
        if (self.entry_to_client.get(entry)) |id| return id;
        const id = self.next_client_id;
        self.next_client_id += 1;
        self.entry_to_client.put(self.allocator, entry, id) catch return 0;
        self.client_to_entry.put(self.allocator, id, entry) catch return 0;
        return id;
    }

    /// Scan for closed connections and emit CLIENT_DISCONNECTED events.
    pub fn checkDisconnected(self: *CApiHandler) void {
        var to_remove_buf: [256]u64 = undefined;
        var to_remove_count: usize = 0;

        var it = self.client_to_entry.iterator();
        while (it.next()) |kv| {
            if (kv.value_ptr.*.conn.isClosed()) {
                self.event_queue.append(self.allocator, .{
                    .event_type = .client_disconnected,
                    .client_id = kv.key_ptr.*,
                }) catch {};
                if (to_remove_count < to_remove_buf.len) {
                    to_remove_buf[to_remove_count] = kv.key_ptr.*;
                    to_remove_count += 1;
                }
            }
        }

        for (to_remove_buf[0..to_remove_count]) |id| {
            if (self.client_to_entry.fetchRemove(id)) |kv| {
                _ = self.entry_to_client.remove(kv.value);
            }
        }
    }

    // -----------------------------------------------------------------------
    // Handler callbacks — copy data and push to event_queue
    // -----------------------------------------------------------------------

    pub fn onConnectRequest(self: *CApiHandler, session: *event_loop.Session, session_id: u64, path: []const u8) void {
        const client_id = self.getOrAssignClientId(session.entry);
        const path_copy = self.allocator.dupe(u8, path) catch return;
        self.event_queue.append(self.allocator, .{
            .event_type = .connect_request,
            .client_id = client_id,
            .id1 = session_id,
            .data = path_copy,
        }) catch {
            self.allocator.free(path_copy);
        };
    }

    pub fn onSessionReady(self: *CApiHandler, session: *event_loop.Session, session_id: u64) void {
        const client_id = self.getOrAssignClientId(session.entry);
        self.event_queue.append(self.allocator, .{
            .event_type = .session_ready,
            .client_id = client_id,
            .id1 = session_id,
        }) catch {};
    }

    pub fn onStreamData(self: *CApiHandler, session: *event_loop.Session, stream_id: u64, data: []const u8, fin: bool) void {
        const client_id = self.getOrAssignClientId(session.entry);

        // Look up session_id from the WebTransport connection's stream maps
        const session_id: u64 = blk: {
            if (session.entry.wt_conn) |*wtc| {
                if (wtc.wt_bidi_streams.get(stream_id)) |sid| break :blk sid;
                if (wtc.wt_uni_streams.get(stream_id)) |sid| break :blk sid;
            }
            break :blk 0;
        };

        const data_copy = self.allocator.dupe(u8, data) catch return;
        self.event_queue.append(self.allocator, .{
            .event_type = .stream_data,
            .flags = if (fin) 1 else 0,
            .client_id = client_id,
            .id1 = stream_id,
            .extra_id = session_id,
            .data = data_copy,
        }) catch {
            self.allocator.free(data_copy);
        };
    }

    pub fn onDatagram(self: *CApiHandler, session: *event_loop.Session, session_id: u64, data: []const u8) void {
        const client_id = self.getOrAssignClientId(session.entry);
        // Datagram data is freed by event_loop after this callback — copy only
        const data_copy = self.allocator.dupe(u8, data) catch return;
        self.event_queue.append(self.allocator, .{
            .event_type = .datagram,
            .client_id = client_id,
            .id1 = session_id,
            .data = data_copy,
        }) catch {
            self.allocator.free(data_copy);
        };
    }

    pub fn onSessionClosed(self: *CApiHandler, session: *event_loop.Session, session_id: u64, error_code: u32, reason: []const u8) void {
        const client_id = self.getOrAssignClientId(session.entry);
        const reason_copy: ?[]u8 = if (reason.len > 0) (self.allocator.dupe(u8, reason) catch null) else null;
        self.event_queue.append(self.allocator, .{
            .event_type = .session_closed,
            .client_id = client_id,
            .id1 = session_id,
            .error_code = error_code,
            .data = reason_copy,
        }) catch {
            if (reason_copy) |r| self.allocator.free(r);
        };
    }

    pub fn onSessionDraining(self: *CApiHandler, session: *event_loop.Session, session_id: u64) void {
        const client_id = self.getOrAssignClientId(session.entry);
        self.event_queue.append(self.allocator, .{
            .event_type = .session_draining,
            .client_id = client_id,
            .id1 = session_id,
        }) catch {};
    }

    pub fn onBidiStream(self: *CApiHandler, session: *event_loop.Session, session_id: u64, stream_id: u64) void {
        const client_id = self.getOrAssignClientId(session.entry);
        self.event_queue.append(self.allocator, .{
            .event_type = .bidi_stream,
            .client_id = client_id,
            .id1 = session_id,
            .extra_id = stream_id,
        }) catch {};
    }

    pub fn onUniStream(self: *CApiHandler, session: *event_loop.Session, session_id: u64, stream_id: u64) void {
        const client_id = self.getOrAssignClientId(session.entry);
        self.event_queue.append(self.allocator, .{
            .event_type = .uni_stream,
            .client_id = client_id,
            .id1 = session_id,
            .extra_id = stream_id,
        }) catch {};
    }
};

// ---------------------------------------------------------------------------
// WtServer — top-level struct holding server + handler
// ---------------------------------------------------------------------------

const WtServer = struct {
    server: event_loop.Server(CApiHandler),
    handler: CApiHandler,
    allocator: Allocator,
};

// Error codes returned by C API functions
const ERR_OK: i32 = 0;
const ERR_INVALID_CLIENT: i32 = -1;
const ERR_INVALID_SESSION: i32 = -2;
const ERR_STREAM: i32 = -3;
const ERR_QUEUE_FULL: i32 = -4;
const ERR_TOO_LARGE: i32 = -5;
const STREAM_ERROR: u64 = std.math.maxInt(u64);

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn getWtServer(handle: *anyopaque) *WtServer {
    return @ptrCast(@alignCast(handle));
}

fn getEntry(ws: *WtServer, client_id: u64) ?*ConnEntry {
    return ws.handler.client_to_entry.get(client_id);
}

// ---------------------------------------------------------------------------
// Exported C functions — Server lifecycle
// ---------------------------------------------------------------------------

export fn qz_server_create(
    addr: [*:0]const u8,
    port: u16,
    cert: [*:0]const u8,
    key: [*:0]const u8,
) ?*anyopaque {
    const allocator = std.heap.c_allocator;

    const ws = allocator.create(WtServer) catch return null;

    ws.handler = .{ .allocator = allocator };
    ws.allocator = allocator;
    ws.server = event_loop.Server(CApiHandler).init(allocator, &ws.handler, .{
        .address = std.mem.span(addr),
        .port = port,
        .cert_path = std.mem.span(cert),
        .key_path = std.mem.span(key),
    }) catch {
        ws.handler.deinit();
        allocator.destroy(ws);
        return null;
    };

    return ws;
}

export fn qz_server_tick(handle: *anyopaque) i32 {
    const ws = getWtServer(handle);
    ws.server.tick() catch return -1;
    ws.handler.checkDisconnected();
    return 0;
}

export fn qz_server_poll(handle: *anyopaque, buf: [*]u8, buf_len: u32) u32 {
    const ws = getWtServer(handle);
    if (ws.handler.event_queue.items.len == 0) return 0;

    // Check size before removing so events aren't lost if buffer is too small
    const total = ws.handler.event_queue.items[0].totalSize();
    if (total > buf_len) return 0;

    var ev = ws.handler.event_queue.orderedRemove(0);
    defer ev.deinit(ws.allocator);
    return ev.serialize(buf, buf_len);
}

export fn qz_server_flush(handle: *anyopaque) void {
    const ws = getWtServer(handle);
    ws.server.flush();
}

export fn qz_server_stop(handle: *anyopaque) void {
    const ws = getWtServer(handle);
    ws.server.stop();
}

export fn qz_server_destroy(handle: *anyopaque) void {
    const ws = getWtServer(handle);
    ws.server.deinit();
    ws.handler.deinit();
    ws.allocator.destroy(ws);
}

export fn qz_server_connection_count(handle: *anyopaque) u32 {
    const ws = getWtServer(handle);
    return @intCast(ws.handler.client_to_entry.count());
}

// ---------------------------------------------------------------------------
// Exported C functions — Session management
// ---------------------------------------------------------------------------

export fn qz_session_accept(handle: *anyopaque, client_id: u64, session_id: u64) i32 {
    const ws = getWtServer(handle);
    const entry = getEntry(ws, client_id) orelse return ERR_INVALID_CLIENT;
    var session = event_loop.Session{ .entry = entry };
    session.acceptSession(session_id) catch return ERR_INVALID_SESSION;
    return ERR_OK;
}

export fn qz_session_close(handle: *anyopaque, client_id: u64, session_id: u64) void {
    const ws = getWtServer(handle);
    const entry = getEntry(ws, client_id) orelse return;
    var session = event_loop.Session{ .entry = entry };
    session.closeSession(session_id);
}

export fn qz_session_close_error(
    handle: *anyopaque,
    client_id: u64,
    session_id: u64,
    err_code: u32,
    reason: [*]const u8,
    reason_len: u32,
) i32 {
    const ws = getWtServer(handle);
    const entry = getEntry(ws, client_id) orelse return ERR_INVALID_CLIENT;
    var session = event_loop.Session{ .entry = entry };
    session.closeSessionWithError(session_id, err_code, reason[0..reason_len]) catch return ERR_INVALID_SESSION;
    return ERR_OK;
}

// ---------------------------------------------------------------------------
// Exported C functions — Streams
// ---------------------------------------------------------------------------

export fn qz_stream_open_bidi(handle: *anyopaque, client_id: u64, session_id: u64) u64 {
    const ws = getWtServer(handle);
    const entry = getEntry(ws, client_id) orelse return STREAM_ERROR;
    var session = event_loop.Session{ .entry = entry };
    return session.openBidiStream(session_id) catch return STREAM_ERROR;
}

export fn qz_stream_open_uni(handle: *anyopaque, client_id: u64, session_id: u64) u64 {
    const ws = getWtServer(handle);
    const entry = getEntry(ws, client_id) orelse return STREAM_ERROR;
    var session = event_loop.Session{ .entry = entry };
    return session.openUniStream(session_id) catch return STREAM_ERROR;
}

export fn qz_stream_send(
    handle: *anyopaque,
    client_id: u64,
    stream_id: u64,
    data: [*]const u8,
    len: u32,
) i32 {
    const ws = getWtServer(handle);
    const entry = getEntry(ws, client_id) orelse return ERR_INVALID_CLIENT;
    var session = event_loop.Session{ .entry = entry };
    session.sendStreamData(stream_id, data[0..len]) catch return ERR_STREAM;
    return ERR_OK;
}

export fn qz_stream_close(handle: *anyopaque, client_id: u64, stream_id: u64) void {
    const ws = getWtServer(handle);
    const entry = getEntry(ws, client_id) orelse return;
    var session = event_loop.Session{ .entry = entry };
    session.closeStream(stream_id);
}

export fn qz_stream_reset(handle: *anyopaque, client_id: u64, stream_id: u64, err: u32) void {
    const ws = getWtServer(handle);
    const entry = getEntry(ws, client_id) orelse return;
    var session = event_loop.Session{ .entry = entry };
    session.resetStream(stream_id, err);
}

// ---------------------------------------------------------------------------
// Exported C functions — Datagrams
// ---------------------------------------------------------------------------

export fn qz_datagram_send(
    handle: *anyopaque,
    client_id: u64,
    session_id: u64,
    data: [*]const u8,
    len: u32,
) i32 {
    const ws = getWtServer(handle);
    const entry = getEntry(ws, client_id) orelse return ERR_INVALID_CLIENT;
    var session = event_loop.Session{ .entry = entry };
    if (session.isDatagramSendQueueFull()) return ERR_QUEUE_FULL;
    if (session.maxDatagramPayloadSize(session_id)) |max| {
        if (len > max) return ERR_TOO_LARGE;
    }
    session.sendDatagram(session_id, data[0..len]) catch return ERR_STREAM;
    return ERR_OK;
}

export fn qz_datagram_max_size(handle: *anyopaque, client_id: u64, session_id: u64) u32 {
    const ws = getWtServer(handle);
    const entry = getEntry(ws, client_id) orelse return 0;
    const session = event_loop.Session{ .entry = entry };
    return @intCast(session.maxDatagramPayloadSize(session_id) orelse 0);
}
