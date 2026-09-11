// MoQ Transport session state machine, draft-17.
//
// §3.3: each side opens its own unidirectional control stream and puts a
// SETUP on it; every request then gets its own bidirectional stream, whose
// first message identifies the request and whose responses come back on the
// same stream. There are no request IDs on the wire — the stream *is* the
// identifier.
//
// Generic over the transport so raw QUIC and WebTransport share one
// implementation. The transport must provide:
//
//     openUni() !u64
//     openBidi() !u64
//     write(stream_id: u64, data: []const u8) !void
//     finish(stream_id: u64) void          // FIN the send side
//     reset(stream_id: u64, code: u64) void // RESET_STREAM
//
// Buffering: a control message can arrive split across reads, and a peer
// may coalesce several into one. Bytes are accumulated per stream and every
// complete envelope is drained before returning.

const std = @import("std");
const testing = std.testing;

const io = @import("../io_compat.zig");
const wire = @import("wire.zig");
const msg = @import("message.zig");
const codes = @import("message_codes.zig");
const track = @import("track.zig");
const version = @import("version.zig");

pub const MAX_STREAMS: usize = 32;
pub const STREAM_BUF_SIZE: usize = 16 * 1024;

const NO_STREAM: u64 = std.math.maxInt(u64);

pub const Error = error{
    TooManyStreams,
    NotConnected,
} || msg.Error;

/// §3.3.3 stream reset codes. draft-18 generalises these to every request
/// stream; draft-17 already uses CANCELLED for a withdrawn request.
pub const ResetCode = struct {
    pub const INTERNAL_ERROR: u64 = 0x0;
    pub const CANCELLED: u64 = 0x1;
};

pub const StreamKind = enum {
    /// Our outbound control stream (SETUP out).
    control_out,
    /// The peer's control stream (SETUP in).
    control_in,
    /// A bidirectional request stream we opened.
    request,
    /// A data stream — subgroup header, then objects.
    data,
};

/// What the peer did, surfaced to the caller one event at a time.
pub const Event = union(enum) {
    peer_setup: struct { stream_id: u64, options: msg.SetupOptions },
    request_ok: struct { stream_id: u64 },
    request_error: struct { stream_id: u64, err: msg.RequestError },
    subscribe_ok: struct { stream_id: u64, ok: msg.SubscribeOk },
    publish: struct { stream_id: u64, publish: msg.Publish },
    namespace: struct { stream_id: u64, namespace: msg.Namespace },
    namespace_done: struct { stream_id: u64 },
    goaway: struct { stream_id: u64, goaway: msg.Goaway },
    publish_done: struct { stream_id: u64, done: msg.PublishDone },
    /// A message we decode but have no specific event for, and anything on
    /// a data stream. Carries the raw envelope so the caller can decide.
    other: struct { stream_id: u64, type: u64, payload: []const u8 },
    /// Peer closed the stream.
    stream_finished: struct { stream_id: u64 },
};

const StreamState = struct {
    id: u64 = NO_STREAM,
    kind: StreamKind = .data,
    buf: [STREAM_BUF_SIZE]u8 = undefined,
    len: usize = 0,

    fn append(self: *StreamState, bytes: []const u8) void {
        const n = @min(bytes.len, self.buf.len - self.len);
        @memcpy(self.buf[self.len..][0..n], bytes[0..n]);
        self.len += n;
    }

    fn consume(self: *StreamState, n: usize) void {
        std.mem.copyForwards(u8, self.buf[0 .. self.len - n], self.buf[n..self.len]);
        self.len -= n;
    }
};

pub fn Session(comptime Transport: type) type {
    return struct {
        const Self = @This();

        transport: Transport,
        draft: version.Draft = version.DEFAULT,
        implementation: []const u8 = "quic-zig/moq",

        control_out: ?u64 = null,
        control_in: ?u64 = null,
        setup_sent: bool = false,
        setup_received: bool = false,

        streams: [MAX_STREAMS]StreamState = [_]StreamState{.{}} ** MAX_STREAMS,

        // Namespace tuples decoded out of incoming messages alias this, so
        // it lives as long as the session rather than as long as a call.
        ns_buf: msg.NamespaceBuf = undefined,
        kv_buf: [16]wire.KvEntry = undefined,

        pub fn init(transport: Transport) Self {
            return .{ .transport = transport };
        }

        // --- streams -------------------------------------------------

        fn slot(self: *Self, id: u64) ?*StreamState {
            for (&self.streams) |*s| if (s.id == id) return s;
            return null;
        }

        fn claim(self: *Self, id: u64, kind: StreamKind) ?*StreamState {
            if (self.slot(id)) |s| return s;
            for (&self.streams) |*s| if (s.id == NO_STREAM) {
                s.* = .{ .id = id, .kind = kind };
                return s;
            };
            return null;
        }

        fn release(self: *Self, id: u64) void {
            if (self.slot(id)) |s| s.* = .{};
        }

        pub fn kindOf(self: *Self, id: u64) ?StreamKind {
            if (self.slot(id)) |s| return s.kind;
            return null;
        }

        // --- sending -------------------------------------------------

        /// Opens our control stream and puts SETUP on it. §3.3 lets both
        /// sides do this immediately; neither waits for the other.
        pub fn sendSetup(self: *Self) !void {
            const sid = try self.transport.openUni();
            _ = self.claim(sid, .control_out) orelse return Error.TooManyStreams;
            self.control_out = sid;

            var buf: [512]u8 = undefined;
            var fbs = io.fixedBufferStream(&buf);
            try msg.writeSetup(&fbs, .{ .implementation = self.implementation });
            try self.transport.write(sid, buf[0..fbs.seek]);
            self.setup_sent = true;
        }

        /// Opens a request stream and writes `payload` (a complete encoded
        /// control message) as its first message. Returns the stream id,
        /// which is how the caller correlates the response.
        pub fn sendRequest(self: *Self, payload: []const u8) !u64 {
            const sid = try self.transport.openBidi();
            _ = self.claim(sid, .request) orelse return Error.TooManyStreams;
            try self.transport.write(sid, payload);
            return sid;
        }

        /// Withdraws a request by resetting its stream. draft-18 makes this
        /// the way a namespace is un-published; draft-17 already allows it.
        pub fn cancelRequest(self: *Self, stream_id: u64, code: u64) void {
            self.transport.reset(stream_id, code);
            self.release(stream_id);
        }

        pub fn finishStream(self: *Self, stream_id: u64) void {
            self.transport.finish(stream_id);
        }

        // --- receiving -----------------------------------------------

        /// Feeds one read into the session. `out` receives the events it
        /// produced; the return value says how many. Events borrow from
        /// the stream's buffer and from `self`, so consume them before the
        /// next call.
        pub fn onStreamData(
            self: *Self,
            stream_id: u64,
            data: []const u8,
            fin: bool,
            out: []Event,
        ) !usize {
            var n: usize = 0;

            if (data.len > 0) {
                const s = self.claim(stream_id, .data) orelse return Error.TooManyStreams;
                s.append(data);

                while (n < out.len) {
                    const parsed = msg.parseEnvelope(s.buf[0..s.len]) catch break;
                    const ev = self.classify(stream_id, s, parsed.env) catch {
                        s.consume(parsed.consumed);
                        continue;
                    };
                    s.consume(parsed.consumed);
                    if (ev) |e| {
                        out[n] = e;
                        n += 1;
                    }
                }
            }

            if (fin) {
                if (n < out.len) {
                    out[n] = .{ .stream_finished = .{ .stream_id = stream_id } };
                    n += 1;
                }
                self.release(stream_id);
            }
            return n;
        }

        fn classify(self: *Self, stream_id: u64, s: *StreamState, env: msg.Envelope) !?Event {
            // A SETUP arriving on a stream we have not classified marks it
            // as the peer's control stream.
            if (env.type == codes.MSG_SETUP) {
                s.kind = .control_in;
                self.control_in = stream_id;
                self.setup_received = true;
                return .{ .peer_setup = .{
                    .stream_id = stream_id,
                    .options = try msg.decodeSetupPayload(env.payload),
                } };
            }

            if (s.kind == .data) s.kind = .request;

            return switch (env.type) {
                codes.MSG_REQUEST_OK => Event{ .request_ok = .{ .stream_id = stream_id } },
                codes.MSG_REQUEST_ERROR => Event{ .request_error = .{
                    .stream_id = stream_id,
                    .err = try msg.decodeRequestError(env.payload),
                } },
                codes.MSG_SUBSCRIBE_OK => Event{ .subscribe_ok = .{
                    .stream_id = stream_id,
                    .ok = try msg.decodeSubscribeOk(env.payload),
                } },
                codes.MSG_PUBLISH => Event{ .publish = .{
                    .stream_id = stream_id,
                    .publish = try msg.decodePublish(env.payload, &self.ns_buf),
                } },
                codes.MSG_NAMESPACE => Event{ .namespace = .{
                    .stream_id = stream_id,
                    .namespace = try msg.decodeNamespace(env.payload, &self.ns_buf),
                } },
                codes.MSG_NAMESPACE_DONE => Event{ .namespace_done = .{ .stream_id = stream_id } },
                codes.MSG_GOAWAY => Event{ .goaway = .{
                    .stream_id = stream_id,
                    .goaway = try msg.decodeGoaway(env.payload),
                } },
                codes.MSG_PUBLISH_DONE => Event{ .publish_done = .{
                    .stream_id = stream_id,
                    .done = try msg.decodePublishDone(env.payload),
                } },
                else => Event{ .other = .{
                    .stream_id = stream_id,
                    .type = env.type,
                    .payload = env.payload,
                } },
            };
        }

        pub fn isEstablished(self: *const Self) bool {
            return self.setup_sent and self.setup_received;
        }
    };
}

// --- tests ---------------------------------------------------------------

/// Records what a session wrote, and hands back stream ids the way a real
/// transport would.
const FakeTransport = struct {
    next_uni: u64 = 2,
    next_bidi: u64 = 0,
    written: [8192]u8 = undefined,
    written_len: usize = 0,
    last_reset: ?struct { id: u64, code: u64 } = null,
    finished: [16]u64 = undefined,
    finished_len: usize = 0,

    fn openUni(self: *FakeTransport) !u64 {
        defer self.next_uni += 4;
        return self.next_uni;
    }
    fn openBidi(self: *FakeTransport) !u64 {
        defer self.next_bidi += 4;
        return self.next_bidi;
    }
    fn write(self: *FakeTransport, _: u64, data: []const u8) !void {
        @memcpy(self.written[self.written_len..][0..data.len], data);
        self.written_len += data.len;
    }
    fn finish(self: *FakeTransport, id: u64) void {
        self.finished[self.finished_len] = id;
        self.finished_len += 1;
    }
    fn reset(self: *FakeTransport, id: u64, code: u64) void {
        self.last_reset = .{ .id = id, .code = code };
    }
};

const TestSession = Session(*FakeTransport);

test "SETUP goes out on a uni control stream" {
    var t = FakeTransport{};
    var s = TestSession.init(&t);
    try s.sendSetup();

    try testing.expect(s.setup_sent);
    try testing.expectEqual(@as(?u64, 2), s.control_out);
    try testing.expectEqual(StreamKind.control_out, s.kindOf(2).?);

    const parsed = try msg.parseEnvelope(t.written[0..t.written_len]);
    try testing.expectEqual(codes.MSG_SETUP, parsed.env.type);
    const opts = try msg.decodeSetupPayload(parsed.env.payload);
    try testing.expectEqualStrings("quic-zig/moq", opts.implementation.?);
}

test "peer SETUP completes the handshake" {
    var t = FakeTransport{};
    var s = TestSession.init(&t);
    try s.sendSetup();
    try testing.expect(!s.isEstablished());

    var buf: [256]u8 = undefined;
    var fbs = io.fixedBufferStream(&buf);
    try msg.writeSetup(&fbs, .{ .implementation = "peer/1" });

    var events: [4]Event = undefined;
    const n = try s.onStreamData(3, buf[0..fbs.seek], false, &events);
    try testing.expectEqual(@as(usize, 1), n);
    try testing.expectEqualStrings("peer/1", events[0].peer_setup.options.implementation.?);
    try testing.expect(s.isEstablished());
    try testing.expectEqual(@as(?u64, 3), s.control_in);
    try testing.expectEqual(StreamKind.control_in, s.kindOf(3).?);
}

test "a message split across reads is reassembled" {
    var t = FakeTransport{};
    var s = TestSession.init(&t);

    var buf: [256]u8 = undefined;
    var fbs = io.fixedBufferStream(&buf);
    try msg.writeRequestError(&fbs, .{ .error_code = codes.ERR_UNAUTHORIZED, .reason = "nope" });
    const encoded = buf[0..fbs.seek];

    var events: [4]Event = undefined;
    // Nothing complete yet.
    try testing.expectEqual(@as(usize, 0), try s.onStreamData(0, encoded[0 .. encoded.len - 3], false, &events));
    const n = try s.onStreamData(0, encoded[encoded.len - 3 ..], false, &events);
    try testing.expectEqual(@as(usize, 1), n);
    try testing.expectEqual(codes.ERR_UNAUTHORIZED, events[0].request_error.err.error_code);
    try testing.expectEqualStrings("nope", events[0].request_error.err.reason);
}

test "coalesced messages all come out of one read" {
    var t = FakeTransport{};
    var s = TestSession.init(&t);

    var buf: [512]u8 = undefined;
    var fbs = io.fixedBufferStream(&buf);
    try msg.writeRequestOk(&fbs, .{});
    try msg.writeSubscribeOk(&fbs, .{ .track_alias = 7 });
    try msg.writeGoaway(&fbs, .{ .new_uri = "https://elsewhere/moq" });

    var events: [8]Event = undefined;
    const n = try s.onStreamData(0, buf[0..fbs.seek], false, &events);
    try testing.expectEqual(@as(usize, 3), n);
    try testing.expectEqual(@as(u64, 0), events[0].request_ok.stream_id);
    try testing.expectEqual(@as(u64, 7), events[1].subscribe_ok.ok.track_alias);
    try testing.expectEqualStrings("https://elsewhere/moq", events[2].goaway.goaway.new_uri);
}

test "a request opens a bidi stream and FIN releases it" {
    var t = FakeTransport{};
    var s = TestSession.init(&t);

    var buf: [256]u8 = undefined;
    var fbs = io.fixedBufferStream(&buf);
    const ns = [_][]const u8{ "moq-test", "interop" };
    try msg.writePublishNamespace(&fbs, .{ .track_namespace = &ns });

    const sid = try s.sendRequest(buf[0..fbs.seek]);
    try testing.expectEqual(@as(u64, 0), sid);
    try testing.expectEqual(StreamKind.request, s.kindOf(sid).?);

    var events: [4]Event = undefined;
    const n = try s.onStreamData(sid, &.{}, true, &events);
    try testing.expectEqual(@as(usize, 1), n);
    try testing.expectEqual(sid, events[0].stream_finished.stream_id);
    try testing.expectEqual(@as(?StreamKind, null), s.kindOf(sid));
}

test "cancelling a request resets its stream" {
    var t = FakeTransport{};
    var s = TestSession.init(&t);
    const sid = try s.sendRequest(&.{});
    s.cancelRequest(sid, ResetCode.CANCELLED);
    try testing.expectEqual(sid, t.last_reset.?.id);
    try testing.expectEqual(ResetCode.CANCELLED, t.last_reset.?.code);
    try testing.expectEqual(@as(?StreamKind, null), s.kindOf(sid));
}

test "an undecodable message is skipped, not fatal" {
    var t = FakeTransport{};
    var s = TestSession.init(&t);

    // A REQUEST_ERROR whose body is too short to decode, then a good one.
    var buf: [256]u8 = undefined;
    var fbs = io.fixedBufferStream(&buf);
    try msg.writeEnvelope(&fbs, codes.MSG_REQUEST_ERROR, &.{});
    try msg.writeRequestOk(&fbs, .{});

    var events: [4]Event = undefined;
    const n = try s.onStreamData(0, buf[0..fbs.seek], false, &events);
    try testing.expectEqual(@as(usize, 1), n);
    try testing.expectEqual(@as(u64, 0), events[0].request_ok.stream_id);
}

test "namespaces decoded from an event outlive the call" {
    var t = FakeTransport{};
    var s = TestSession.init(&t);

    var buf: [256]u8 = undefined;
    var fbs = io.fixedBufferStream(&buf);
    const ns = [_][]const u8{ "moq-test", "interop" };
    try msg.writeNamespace(&fbs, .{ .track_namespace_suffix = &ns });

    var events: [4]Event = undefined;
    _ = try s.onStreamData(0, buf[0..fbs.seek], false, &events);
    const got = events[0].namespace.namespace.track_namespace_suffix;
    try testing.expectEqual(@as(usize, 2), got.len);
    try testing.expectEqualStrings("moq-test", got[0]);
    try testing.expectEqualStrings("interop", got[1]);
}

test "stream table refuses to overflow" {
    var t = FakeTransport{};
    var s = TestSession.init(&t);
    for (0..MAX_STREAMS) |i| _ = s.claim(@intCast(i), .data).?;
    var events: [2]Event = undefined;
    try testing.expectError(Error.TooManyStreams, s.onStreamData(999, "x", false, &events));
}
