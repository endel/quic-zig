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
    /// Bytes of `data` already delivered, in parts.
    sent: usize = 0,

    fn deinit(self: *QueuedEvent, allocator: Allocator) void {
        if (self.data) |d| allocator.free(d);
    }

    fn payload(self: *const QueuedEvent) []const u8 {
        const d = self.data orelse return &.{};
        return d[self.sent..];
    }

    fn headerSize(self: *const QueuedEvent) usize {
        return HEADER_SIZE + self.extendedSize();
    }

    fn extendedSize(self: *const QueuedEvent) usize {
        return switch (self.event_type) {
            .session_closed => 4,
            .bidi_stream, .uni_stream, .stream_data => 8,
            else => 0,
        };
    }

    fn totalSize(self: *const QueuedEvent) usize {
        return self.headerSize() + self.payload().len;
    }

    /// Serialize with the first `n` bytes of the payload into `out`, which
    /// must hold them. Returns bytes written.
    fn serialize(self: *const QueuedEvent, out: []u8, n: usize) u32 {
        const data = self.payload()[0..n];
        // FIN goes with the last part.
        const flags = if (self.event_type == .stream_data and n < self.payload().len) self.flags & ~@as(u8, 1) else self.flags;

        // Fixed header (24 bytes, little-endian)
        out[0] = @backingInt(self.event_type);
        out[1] = flags;
        std.mem.writeInt(u16, out[2..4], 0, .little); // reserved
        std.mem.writeInt(u32, out[4..8], @intCast(n), .little);
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

        @memcpy(out[offset..][0..n], data);
        return @intCast(offset + n);
    }
};

// ---------------------------------------------------------------------------
// CApiHandler — implements the quic-zig Handler interface
// ---------------------------------------------------------------------------

/// Payload bytes queued for one client past which its streams are paused, so
/// flow control holds the peer back, and its datagrams are dropped.
const max_client_backlog = 1 << 20;
/// A client's paused streams resume once the host has drained it to this.
const resume_client_backlog = max_client_backlog / 2;

const Backlog = struct {
    bytes: usize = 0,
    paused: std.ArrayListUnmanaged(u64) = .empty,
};

pub const CApiHandler = struct {
    pub const protocol: event_loop.Protocol = .webtransport;

    allocator: Allocator,
    next_client_id: u64 = 1,
    entry_to_client: std.AutoHashMapUnmanaged(*ConnEntry, u64) = .empty,
    client_to_entry: std.AutoHashMapUnmanaged(u64, *ConnEntry) = .empty,
    event_queue: std.Deque(QueuedEvent) = .empty,
    backlogs: std.AutoHashMapUnmanaged(u64, Backlog) = .empty,

    pub fn deinit(self: *CApiHandler) void {
        var it = self.event_queue.iterator();
        while (it.nextPtr()) |ev| ev.deinit(self.allocator);
        self.event_queue.deinit(self.allocator);
        var bit = self.backlogs.valueIterator();
        while (bit.next()) |b| b.paused.deinit(self.allocator);
        self.backlogs.deinit(self.allocator);
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

    /// Queues `ev`, owning its data whether or not it fits.
    fn push(self: *CApiHandler, ev: QueuedEvent) void {
        var owned = ev;
        const b = self.backlogs.getOrPut(self.allocator, ev.client_id) catch return owned.deinit(self.allocator);
        if (!b.found_existing) b.value_ptr.* = .{};
        self.event_queue.pushBack(self.allocator, ev) catch return owned.deinit(self.allocator);
        b.value_ptr.bytes += if (ev.data) |d| d.len else 0;
    }

    fn backlogOf(self: *const CApiHandler, client_id: u64) usize {
        return if (self.backlogs.get(client_id)) |b| b.bytes else 0;
    }

    fn pause(self: *CApiHandler, session: *event_loop.Session, client_id: u64, stream_id: u64) void {
        const b = self.backlogs.getPtr(client_id) orelse return;
        if (std.mem.indexOfScalar(u64, b.paused.items, stream_id) != null) return;
        b.paused.append(self.allocator, stream_id) catch return;
        session.pauseStream(stream_id) catch {
            _ = b.paused.pop();
        };
    }

    /// The host took `n` bytes of `client_id`'s backlog.
    fn release(self: *CApiHandler, client_id: u64, n: usize) void {
        const b = self.backlogs.getPtr(client_id) orelse return;
        b.bytes -|= n;
        if (b.bytes > resume_client_backlog or b.paused.items.len == 0) return;
        if (self.client_to_entry.get(client_id)) |entry| {
            var session: event_loop.Session = .{ .entry = entry };
            for (b.paused.items) |id| session.resumeStream(id);
        }
        b.paused.clearRetainingCapacity();
    }

    /// Forgets a client's backlog. Events still queued for it are delivered
    /// uncounted.
    fn dropBacklog(self: *CApiHandler, client_id: u64, entry: ?*ConnEntry) void {
        var kv = self.backlogs.fetchRemove(client_id) orelse return;
        defer kv.value.paused.deinit(self.allocator);
        // Its other sessions go on under a new client id.
        const e = entry orelse return;
        var session: event_loop.Session = .{ .entry = e };
        for (kv.value.paused.items) |id| session.resumeStream(id);
    }

    /// Writes the next event into `buf`. Returns its size, or 0 when there
    /// is none, or `buf` can't hold its header and a byte of stream data.
    ///
    /// An event never waits for a bigger buffer, which the host may never
    /// bring: stream data comes in parts, a close reason is cut short, and
    /// a datagram or CONNECT path that doesn't fit is dropped.
    fn poll(self: *CApiHandler, buf: []u8) u32 {
        while (self.event_queue.frontPtr()) |ev| {
            const head = ev.headerSize();
            if (head > buf.len) return 0;
            const room = buf.len - head;
            const len = ev.payload().len;
            if (len <= room) return self.take(buf, len, true);
            switch (ev.event_type) {
                .stream_data => return if (room > 0) self.take(buf, room, false) else 0,
                .session_closed => return self.take(buf, room, true),
                .connect_request => {
                    // Cut short, it would name another resource.
                    if (self.client_to_entry.get(ev.client_id)) |entry| {
                        var session: event_loop.Session = .{ .entry = entry };
                        session.resetRequest(ev.id1, @backingInt(quic.h3.H3Error.request_rejected));
                    }
                    self.discard();
                },
                else => self.discard(),
            }
        }
        return 0;
    }

    /// Writes the head event with `n` bytes of its payload. Pops it once
    /// the payload is out, or when `last` drops the rest.
    fn take(self: *CApiHandler, buf: []u8, n: usize, last: bool) u32 {
        const ev = self.event_queue.frontPtr().?;
        const written = ev.serialize(buf, n);
        if (!last and n < ev.payload().len) {
            ev.sent += n;
            self.release(ev.client_id, n);
            return written;
        }
        self.discard();
        return written;
    }

    fn discard(self: *CApiHandler) void {
        var ev = self.event_queue.popFront().?;
        defer ev.deinit(self.allocator);
        self.release(ev.client_id, ev.payload().len);
    }

    /// Scan for closed connections and emit CLIENT_DISCONNECTED events.
    pub fn checkDisconnected(self: *CApiHandler) void {
        var to_remove_buf: [256]u64 = undefined;
        var to_remove_count: usize = 0;

        var it = self.client_to_entry.iterator();
        while (it.next()) |kv| {
            if (kv.value_ptr.*.conn.isClosed()) {
                self.push(.{
                    .event_type = .client_disconnected,
                    .client_id = kv.key_ptr.*,
                });
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
            self.dropBacklog(id, null);
        }
    }

    // -----------------------------------------------------------------------
    // Handler callbacks — copy data and push to event_queue
    // -----------------------------------------------------------------------

    pub fn onConnectRequest(self: *CApiHandler, session: *event_loop.Session, session_id: u64, path: []const u8) void {
        const client_id = self.getOrAssignClientId(session.entry);
        const path_copy = self.allocator.dupe(u8, path) catch return;
        self.push(.{
            .event_type = .connect_request,
            .client_id = client_id,
            .id1 = session_id,
            .data = path_copy,
        });
    }

    pub fn onSessionReady(self: *CApiHandler, session: *event_loop.Session, session_id: u64) void {
        const client_id = self.getOrAssignClientId(session.entry);
        self.push(.{
            .event_type = .session_ready,
            .client_id = client_id,
            .id1 = session_id,
        });
    }

    pub fn onStreamData(self: *CApiHandler, session: *event_loop.Session, stream_id: u64, data: []const u8, fin: bool) void {
        const client_id = self.getOrAssignClientId(session.entry);

        // Look up session_id from the WebTransport connection's stream maps
        const session_id: u64 = blk: {
            if (session.entry.wt_conn) |wtc| {
                if (wtc.wt_bidi_streams.get(stream_id)) |sid| break :blk sid;
                if (wtc.wt_uni_streams.get(stream_id)) |sid| break :blk sid;
            }
            break :blk 0;
        };

        const data_copy = self.allocator.dupe(u8, data) catch return;
        self.push(.{
            .event_type = .stream_data,
            .flags = if (fin) 1 else 0,
            .client_id = client_id,
            .id1 = stream_id,
            .extra_id = session_id,
            .data = data_copy,
        });
        // Copied, the data's credit goes back to the peer: past the cap, only
        // pausing holds it back.
        if (!fin and self.backlogOf(client_id) > max_client_backlog) self.pause(session, client_id, stream_id);
    }

    pub fn onDatagram(self: *CApiHandler, session: *event_loop.Session, session_id: u64, data: []const u8) void {
        const client_id = self.getOrAssignClientId(session.entry);
        if (self.backlogOf(client_id) > max_client_backlog) return;
        // Datagram data is freed by event_loop after this callback — copy only
        const data_copy = self.allocator.dupe(u8, data) catch return;
        self.push(.{
            .event_type = .datagram,
            .client_id = client_id,
            .id1 = session_id,
            .data = data_copy,
        });
    }

    pub fn onSessionClosed(self: *CApiHandler, session: *event_loop.Session, session_id: u64, error_code: u32, reason: []const u8) void {
        const client_id = self.getOrAssignClientId(session.entry);
        const reason_copy: ?[]u8 = if (reason.len > 0) (self.allocator.dupe(u8, reason) catch null) else null;
        self.push(.{
            .event_type = .session_closed,
            .client_id = client_id,
            .id1 = session_id,
            .error_code = error_code,
            .data = reason_copy,
        });

        // Remove from lookup maps BEFORE the event loop frees the entry.
        // Without this, checkDisconnected() dereferences freed memory.
        _ = self.entry_to_client.remove(session.entry);
        _ = self.client_to_entry.remove(client_id);
        self.dropBacklog(client_id, session.entry);
    }

    pub fn onSessionDraining(self: *CApiHandler, session: *event_loop.Session, session_id: u64) void {
        const client_id = self.getOrAssignClientId(session.entry);
        self.push(.{
            .event_type = .session_draining,
            .client_id = client_id,
            .id1 = session_id,
        });
    }

    pub fn onBidiStream(self: *CApiHandler, session: *event_loop.Session, session_id: u64, stream_id: u64) void {
        const client_id = self.getOrAssignClientId(session.entry);
        self.push(.{
            .event_type = .bidi_stream,
            .client_id = client_id,
            .id1 = session_id,
            .extra_id = stream_id,
        });
        // Its data and FIN could come in one event, too late to pause.
        if (self.backlogOf(client_id) > max_client_backlog) self.pause(session, client_id, stream_id);
    }

    pub fn onUniStream(self: *CApiHandler, session: *event_loop.Session, session_id: u64, stream_id: u64) void {
        const client_id = self.getOrAssignClientId(session.entry);
        self.push(.{
            .event_type = .uni_stream,
            .client_id = client_id,
            .id1 = session_id,
            .extra_id = stream_id,
        });
        // Its data and FIN could come in one event, too late to pause.
        if (self.backlogOf(client_id) > max_client_backlog) self.pause(session, client_id, stream_id);
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
/// A NULL handle, or NULL where a non-zero length says bytes are.
const ERR_INVALID_ARG: i32 = -6;
const STREAM_ERROR: u64 = std.math.maxInt(u64);

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// Every pointer from C is optional: C can pass NULL, and Zig would take a
// non-optional one as a promise that it hasn't.
fn getWtServer(handle: ?*anyopaque) ?*WtServer {
    return @ptrCast(@alignCast(handle orelse return null));
}

fn getEntry(ws: *WtServer, client_id: u64) ?*ConnEntry {
    return ws.handler.client_to_entry.get(client_id);
}

/// Null when NULL stands for a non-zero length.
fn cBytes(ptr: ?[*]const u8, len: u32) ?[]const u8 {
    if (len == 0) return &.{};
    return (ptr orelse return null)[0..len];
}

// ---------------------------------------------------------------------------
// Exported C functions — Server lifecycle
// ---------------------------------------------------------------------------

export fn qz_server_create(
    addr: ?[*:0]const u8,
    port: u16,
    cert: ?[*:0]const u8,
    key: ?[*:0]const u8,
) ?*anyopaque {
    const allocator = std.heap.c_allocator;
    const address = std.mem.span(addr orelse return null);
    const cert_path = std.mem.span(cert orelse return null);
    const key_path = std.mem.span(key orelse return null);

    const ws = allocator.create(WtServer) catch return null;

    ws.handler = .{ .allocator = allocator };
    ws.allocator = allocator;
    ws.server = event_loop.Server(CApiHandler).init(allocator, &ws.handler, .{
        .address = address,
        .port = port,
        .cert_path = cert_path,
        .key_path = key_path,
    }) catch {
        ws.handler.deinit();
        allocator.destroy(ws);
        return null;
    };

    return ws;
}

export fn qz_server_tick(handle: ?*anyopaque) i32 {
    const ws = getWtServer(handle) orelse return -1;
    ws.server.tick() catch return -1;
    // Explicitly drain socket and process connections on every tick.
    // In no_wait mode, kqueue/epoll edge-triggered events can be missed
    // between ticks, so we must poll directly to ensure packets are read.
    ws.server.pollDirect();
    ws.handler.checkDisconnected();
    return 0;
}

export fn qz_server_poll(handle: ?*anyopaque, buf: ?[*]u8, buf_len: u32) u32 {
    const ws = getWtServer(handle) orelse return 0;
    return ws.handler.poll((buf orelse return 0)[0..buf_len]);
}

export fn qz_server_flush(handle: ?*anyopaque) void {
    const ws = getWtServer(handle) orelse return;
    ws.server.flush();
}

export fn qz_server_stop(handle: ?*anyopaque) void {
    const ws = getWtServer(handle) orelse return;
    ws.server.stop();
}

export fn qz_server_destroy(handle: ?*anyopaque) void {
    const ws = getWtServer(handle) orelse return;
    ws.server.deinit();
    ws.handler.deinit();
    ws.allocator.destroy(ws);
}

export fn qz_server_connection_count(handle: ?*anyopaque) u32 {
    const ws = getWtServer(handle) orelse return 0;
    return @intCast(ws.handler.client_to_entry.count());
}

export fn qz_is_client_connected(handle: ?*anyopaque, client_id: u64) i32 {
    const ws = getWtServer(handle) orelse return 0;
    const entry = ws.handler.client_to_entry.get(client_id) orelse return 0;
    return if (entry.conn.isClosed()) 0 else 1;
}

// ---------------------------------------------------------------------------
// Exported C functions — Session management
// ---------------------------------------------------------------------------

export fn qz_session_accept(handle: ?*anyopaque, client_id: u64, session_id: u64) i32 {
    const ws = getWtServer(handle) orelse return ERR_INVALID_ARG;
    const entry = getEntry(ws, client_id) orelse return ERR_INVALID_CLIENT;
    var session = event_loop.Session{ .entry = entry };
    session.acceptSession(session_id) catch return ERR_INVALID_SESSION;
    return ERR_OK;
}

export fn qz_session_close(handle: ?*anyopaque, client_id: u64, session_id: u64) void {
    const ws = getWtServer(handle) orelse return;
    const entry = getEntry(ws, client_id) orelse return;
    var session = event_loop.Session{ .entry = entry };
    session.closeSession(session_id);
}

export fn qz_session_close_error(
    handle: ?*anyopaque,
    client_id: u64,
    session_id: u64,
    err_code: u32,
    reason: ?[*]const u8,
    reason_len: u32,
) i32 {
    const ws = getWtServer(handle) orelse return ERR_INVALID_ARG;
    const bytes = cBytes(reason, reason_len) orelse return ERR_INVALID_ARG;
    const entry = getEntry(ws, client_id) orelse return ERR_INVALID_CLIENT;
    var session = event_loop.Session{ .entry = entry };
    session.closeSessionWithError(session_id, err_code, bytes) catch return ERR_INVALID_SESSION;
    return ERR_OK;
}

// ---------------------------------------------------------------------------
// Exported C functions — Streams
// ---------------------------------------------------------------------------

export fn qz_stream_open_bidi(handle: ?*anyopaque, client_id: u64, session_id: u64) u64 {
    const ws = getWtServer(handle) orelse return STREAM_ERROR;
    const entry = getEntry(ws, client_id) orelse return STREAM_ERROR;
    var session = event_loop.Session{ .entry = entry };
    return session.openBidiStream(session_id, null) catch return STREAM_ERROR;
}

export fn qz_stream_open_uni(handle: ?*anyopaque, client_id: u64, session_id: u64) u64 {
    const ws = getWtServer(handle) orelse return STREAM_ERROR;
    const entry = getEntry(ws, client_id) orelse return STREAM_ERROR;
    var session = event_loop.Session{ .entry = entry };
    return session.openUniStream(session_id, null) catch return STREAM_ERROR;
}

export fn qz_stream_send(
    handle: ?*anyopaque,
    client_id: u64,
    stream_id: u64,
    data: ?[*]const u8,
    len: u32,
) i32 {
    const ws = getWtServer(handle) orelse return ERR_INVALID_ARG;
    const bytes = cBytes(data, len) orelse return ERR_INVALID_ARG;
    const entry = getEntry(ws, client_id) orelse return ERR_INVALID_CLIENT;
    var session = event_loop.Session{ .entry = entry };
    session.sendStreamData(stream_id, bytes) catch return ERR_STREAM;
    return ERR_OK;
}

export fn qz_stream_close(handle: ?*anyopaque, client_id: u64, stream_id: u64) void {
    const ws = getWtServer(handle) orelse return;
    const entry = getEntry(ws, client_id) orelse return;
    var session = event_loop.Session{ .entry = entry };
    session.closeStream(stream_id);
}

export fn qz_stream_reset(handle: ?*anyopaque, client_id: u64, stream_id: u64, err: u32) void {
    const ws = getWtServer(handle) orelse return;
    const entry = getEntry(ws, client_id) orelse return;
    var session = event_loop.Session{ .entry = entry };
    session.resetStream(stream_id, err);
}

// ---------------------------------------------------------------------------
// Exported C functions — Datagrams
// ---------------------------------------------------------------------------

export fn qz_datagram_send(
    handle: ?*anyopaque,
    client_id: u64,
    session_id: u64,
    data: ?[*]const u8,
    len: u32,
) i32 {
    const ws = getWtServer(handle) orelse return ERR_INVALID_ARG;
    const bytes = cBytes(data, len) orelse return ERR_INVALID_ARG;
    const entry = getEntry(ws, client_id) orelse return ERR_INVALID_CLIENT;
    var session = event_loop.Session{ .entry = entry };
    if (session.isDatagramSendQueueFull()) return ERR_QUEUE_FULL;
    if (session.maxDatagramPayloadSize(session_id)) |max| {
        if (len > max) return ERR_TOO_LARGE;
    }
    session.sendDatagram(session_id, bytes) catch return ERR_STREAM;
    return ERR_OK;
}

export fn qz_datagram_max_size(handle: ?*anyopaque, client_id: u64, session_id: u64) u32 {
    const ws = getWtServer(handle) orelse return 0;
    const entry = getEntry(ws, client_id) orelse return 0;
    const session = event_loop.Session{ .entry = entry };
    return @intCast(session.maxDatagramPayloadSize(session_id) orelse 0);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

/// A connection with just enough WebTransport state to pause its streams.
const TestPeer = struct {
    h3: quic.h3.H3Connection = undefined,
    wt: quic.webtransport.WebTransportConnection = undefined,
    entry: ConnEntry = undefined,

    fn init(self: *TestPeer) void {
        self.wt = .init(testing.allocator, &self.h3, undefined, true);
        self.entry = .{ .conn = undefined, .wt_conn = &self.wt };
    }

    fn deinit(self: *TestPeer) void {
        self.wt.deinit();
    }

    fn session(self: *TestPeer) event_loop.Session {
        return .{ .entry = &self.entry };
    }
};

/// A server whose handler the tests drive directly; only polling touches it.
fn testServer(ws: *WtServer) void {
    ws.handler = .{ .allocator = testing.allocator };
    ws.allocator = testing.allocator;
}

fn queuedBytes(h: *const CApiHandler) usize {
    var n: usize = 0;
    var it = h.event_queue.iterator();
    while (it.next()) |ev| n += if (ev.data) |d| d.len else 0;
    return n;
}

test "c_api: a peer the host isn't keeping up with is held back, not queued" {
    // Stream data was copied and its credit returned at once, so a peer
    // grew the queue for as long as the host didn't poll.
    var ws: WtServer = undefined;
    testServer(&ws);
    const h = &ws.handler;
    defer h.deinit();
    var p: TestPeer = .{};
    p.init();
    defer p.deinit();
    var s = p.session();

    const chunk: [16 * 1024]u8 = @splat('d');
    for (0..256) |_| {
        if (p.wt.isStreamPaused(4)) break;
        h.onStreamData(&s, 4, &chunk, false);
        h.onDatagram(&s, 0, &chunk);
    }
    try testing.expect(p.wt.isStreamPaused(4));
    try testing.expect(queuedBytes(h) <= max_client_backlog + 2 * chunk.len);
    // A stream that would bring all of its data and FIN at once is held
    // back before any of it is taken.
    h.onBidiStream(&s, 0, 8);
    try testing.expect(p.wt.isStreamPaused(8));

    // Drained by the host, the stream goes again.
    var buf: [64 * 1024]u8 = undefined;
    while (queuedBytes(h) > resume_client_backlog) try testing.expect(qz_server_poll(&ws, &buf, buf.len) > 0);
    try testing.expect(!p.wt.isStreamPaused(4));
    try testing.expect(!p.wt.isStreamPaused(8));
}

test "c_api: an event too big for the host's buffer doesn't stall the queue" {
    // It stayed at the head, and poll's 0 reads as "no events", for good.
    var ws: WtServer = undefined;
    testServer(&ws);
    const h = &ws.handler;
    defer h.deinit();
    var p: TestPeer = .{};
    p.init();
    defer p.deinit();
    var s = p.session();

    const big: [10 * 1024]u8 = @splat('b');
    h.onConnectRequest(&s, 0, &big);
    h.onDatagram(&s, 0, &big);
    h.onStreamData(&s, 4, &big, true);
    h.onSessionClosed(&s, 0, 7, big[0..1024]);

    var buf: [4096]u8 = undefined;
    var got: usize = 0;
    var fin = false;
    while (true) {
        const n = qz_server_poll(&ws, &buf, buf.len);
        try testing.expect(n > 0);
        const len = std.mem.readInt(u32, buf[4..8], .little);
        switch (@as(EventType, @fromBackingInt(@intCast(buf[0])))) {
            .stream_data => {
                try testing.expect(!fin);
                try testing.expectEqual(n, HEADER_SIZE + 8 + len);
                got += len;
                fin = buf[1] & 1 != 0;
            },
            .session_closed => break,
            // A path can't be cut short, nor a datagram: both are dropped.
            else => return error.TestUnexpectedResult,
        }
    }
    try testing.expectEqual(big.len, got);
    try testing.expect(fin);
    try testing.expectEqual(@as(usize, 0), h.event_queue.len);
}

test "c_api: NULL from C is refused, not dereferenced" {
    try testing.expectEqual(@as(?*anyopaque, null), qz_server_create(null, 4433, null, null));
    try testing.expectEqual(@as(i32, -1), qz_server_tick(null));
    try testing.expectEqual(@as(u32, 0), qz_server_poll(null, null, 64));
    qz_server_flush(null);
    qz_server_stop(null);
    qz_server_destroy(null);
    try testing.expectEqual(@as(u32, 0), qz_server_connection_count(null));
    try testing.expectEqual(@as(i32, 0), qz_is_client_connected(null, 1));
    try testing.expectEqual(ERR_INVALID_ARG, qz_session_accept(null, 1, 0));
    qz_session_close(null, 1, 0);
    try testing.expectEqual(STREAM_ERROR, qz_stream_open_bidi(null, 1, 0));
    try testing.expectEqual(STREAM_ERROR, qz_stream_open_uni(null, 1, 0));
    qz_stream_close(null, 1, 0);
    qz_stream_reset(null, 1, 0, 0);
    try testing.expectEqual(@as(u32, 0), qz_datagram_max_size(null, 1, 0));

    // A live handle, with NULL where bytes should be.
    var ws: WtServer = undefined;
    testServer(&ws);
    defer ws.handler.deinit();
    var p: TestPeer = .{};
    p.init();
    defer p.deinit();
    var s = p.session();
    ws.handler.onSessionReady(&s, 0);
    try testing.expectEqual(@as(u32, 0), qz_server_poll(&ws, null, 64));
    try testing.expectEqual(ERR_INVALID_ARG, qz_stream_send(&ws, 1, 0, null, 5));
    try testing.expectEqual(ERR_INVALID_ARG, qz_datagram_send(&ws, 1, 0, null, 5));
    try testing.expectEqual(ERR_INVALID_ARG, qz_session_close_error(&ws, 1, 0, 0, null, 5));
}
