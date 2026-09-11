// Control-message codec for MoQ Transport draft-17.
//
// Framing (§9): every control message on the uni control stream is
//   Type (moq-varint) | Length (u16 big-endian) | Payload (Length bytes)
//
// This module implements the envelope plus payload codecs for all 18
// draft-17 control message types. NAMESPACE_DONE has an empty payload and
// so needs no decoder.

const std = @import("std");
const io = @import("../io_compat.zig");
const testing = std.testing;

const wire = @import("wire.zig");
const codes = @import("message_codes.zig");
const track = @import("track.zig");

pub const MAX_PAYLOAD_LEN: usize = std.math.maxInt(u16);

// Backing store for a decoded Track Namespace tuple. Decoders that return a
// namespace take one of these by pointer so the slice-of-slices outlives the
// call — the parts alias the payload, the array must not be a callee local.
pub const NamespaceBuf = [wire.MAX_TUPLE_PARTS][]const u8;

pub const Error = error{
    UnknownMessageType,
    ReservedLegacyMessage,
    PayloadTooLarge,
    MalformedMessage,
} || wire.Error;

// Envelope I/O -------------------------------------------------------------

pub const Envelope = struct {
    type: u64,
    payload: []const u8,
};

pub fn writeEnvelope(writer: anytype, msg_type: u64, payload: []const u8) !void {
    if (payload.len > MAX_PAYLOAD_LEN) return Error.PayloadTooLarge;
    try wire.writeVarInt(writer, msg_type);
    var len_be: [2]u8 = undefined;
    std.mem.writeInt(u16, &len_be, @as(u16, @intCast(payload.len)), .big);
    try writer.writeAll(&len_be);
    try writer.writeAll(payload);
}

// Parses one envelope from the front of `data`. Returns the envelope
// plus total bytes consumed. Caller should slice `data` forward.
pub fn parseEnvelope(data: []const u8) !struct { env: Envelope, consumed: usize } {
    var fbs = io.fixedBufferStream(data);
    const t = try wire.readVarInt(&fbs);
    if (codes.isReservedLegacyMessageType(t)) return Error.ReservedLegacyMessage;
    if (fbs.seek + 2 > data.len) return Error.BufferTooShort;
    const len = std.mem.readInt(u16, data[fbs.seek..][0..2], .big);
    const payload_start = fbs.seek + 2;
    const payload_end = payload_start + len;
    if (payload_end > data.len) return Error.BufferTooShort;
    return .{
        .env = .{ .type = t, .payload = data[payload_start..payload_end] },
        .consumed = payload_end,
    };
}

// SETUP (0x2F00, §9.4) -----------------------------------------------------

pub const SetupOptions = struct {
    path: ?[]const u8 = null,
    authority: ?[]const u8 = null,
    implementation: ?[]const u8 = null,
    max_auth_token_cache_size: ?u64 = null,
    // AUTHORIZATION_TOKEN (0x03) is decoded at wire level but not
    // surfaced here in the first pass; see auth.zig (TBD).
};

pub fn encodeSetupPayload(writer: anytype, opts: SetupOptions) !void {
    // Build a KV list sorted by key.
    var kvs: [8]wire.KvEntry = undefined;
    var n: usize = 0;
    if (opts.path) |p| {
        kvs[n] = .{ .key = codes.OPT_PATH, .value = .{ .bytes = p } };
        n += 1;
    }
    if (opts.max_auth_token_cache_size) |v| {
        kvs[n] = .{ .key = codes.OPT_MAX_AUTH_TOKEN_CACHE_SIZE, .value = .{ .varint = v } };
        n += 1;
    }
    if (opts.authority) |a| {
        kvs[n] = .{ .key = codes.OPT_AUTHORITY, .value = .{ .bytes = a } };
        n += 1;
    }
    if (opts.implementation) |i| {
        kvs[n] = .{ .key = codes.OPT_MOQT_IMPLEMENTATION, .value = .{ .bytes = i } };
        n += 1;
    }
    try wire.encodeKvList(writer, kvs[0..n]);
}

pub fn decodeSetupPayload(payload: []const u8) !SetupOptions {
    var opts = SetupOptions{};
    var it = wire.KvIterator.init(payload);
    while (try it.next()) |e| {
        switch (e.key) {
            codes.OPT_PATH => opts.path = e.value.bytes,
            codes.OPT_AUTHORIZATION_TOKEN => {}, // ignored in first pass
            codes.OPT_MAX_AUTH_TOKEN_CACHE_SIZE => opts.max_auth_token_cache_size = e.value.varint,
            codes.OPT_AUTHORITY => opts.authority = e.value.bytes,
            codes.OPT_MOQT_IMPLEMENTATION => opts.implementation = e.value.bytes,
            else => {}, // unknown keys: ignore per draft
        }
    }
    return opts;
}

pub fn writeSetup(writer: anytype, opts: SetupOptions) !void {
    var scratch: [MAX_PAYLOAD_LEN]u8 = undefined;
    var fbs = io.fixedBufferStream(&scratch);
    try encodeSetupPayload(&fbs, opts);
    try writeEnvelope(writer, codes.MSG_SETUP, scratch[0..fbs.seek]);
}

// GOAWAY (0x10, §9.5) ------------------------------------------------------

pub const Goaway = struct { new_uri: []const u8 };

pub fn writeGoaway(writer: anytype, g: Goaway) !void {
    var scratch: [MAX_PAYLOAD_LEN]u8 = undefined;
    var fbs = io.fixedBufferStream(&scratch);
    try wire.writeVarBytes(&fbs, g.new_uri);
    try writeEnvelope(writer, codes.MSG_GOAWAY, scratch[0..fbs.seek]);
}

pub fn decodeGoaway(payload: []const u8) !Goaway {
    var fbs = io.fixedBufferStream(payload);
    return .{ .new_uri = try wire.readVarBytesZc(&fbs) };
}

// REQUEST_OK / REQUEST_ERROR (§9.6, §9.7) ----------------------------------
//
// These travel on the per-request bidi stream. In draft-17 they carry
// no request_id on the wire (the stream is the identifier).

pub const RequestOk = struct {
    // An empty trailing KV list of status parameters.
    parameters: []const wire.KvEntry = &.{},
};

pub fn writeRequestOk(writer: anytype, r: RequestOk) !void {
    // Draft-17: no request_id — the request stream is the identifier.
    var scratch: [MAX_PAYLOAD_LEN]u8 = undefined;
    var fbs = io.fixedBufferStream(&scratch);
    try wire.writeVarInt(&fbs, r.parameters.len);
    try wire.encodeKvList(&fbs, r.parameters);
    try writeEnvelope(writer, codes.MSG_REQUEST_OK, scratch[0..fbs.seek]);
}

pub fn decodeRequestOk(payload: []const u8, out: []wire.KvEntry) !RequestOk {
    var fbs = io.fixedBufferStream(payload);
    const count = wire.readVarInt(&fbs) catch return .{};
    if (count > out.len) return Error.MalformedMessage;
    var it = wire.KvIterator.init(payload[fbs.seek..]);
    var n: usize = 0;
    while (n < @as(usize, @intCast(count))) : (n += 1) {
        out[n] = (try it.next()) orelse return Error.MalformedMessage;
    }
    return .{ .parameters = out[0..n] };
}

pub const RequestError = struct {
    error_code: u64,
    reason: []const u8,
};

pub fn writeRequestError(writer: anytype, e: RequestError) !void {
    var scratch: [MAX_PAYLOAD_LEN]u8 = undefined;
    var fbs = io.fixedBufferStream(&scratch);
    try wire.writeVarInt(&fbs, e.error_code);
    try wire.writeVarBytes(&fbs, e.reason);
    try writeEnvelope(writer, codes.MSG_REQUEST_ERROR, scratch[0..fbs.seek]);
}

pub fn decodeRequestError(payload: []const u8) !RequestError {
    var fbs = io.fixedBufferStream(payload);
    const code = try wire.readVarInt(&fbs);
    const reason = try wire.readVarBytesZc(&fbs);
    return .{ .error_code = code, .reason = reason };
}

// SUBSCRIBE (0x03, §9.8) — sent on a bidi request stream.
//
// Draft-17 wire format:
//   request_id (varint)
//   required_request_id_delta (varint, 0)
//   track_namespace (tuple)
//   track_name (varbytes)
//   parameters: delta-encoded KV list (no count prefix):
//     0x10 = forward (varint, 1=true)
//     0x20 = subscriber_priority (varint)
//     0x21 = filter_type (length-prefixed varint)
//     0x22 = group_order (varint)

pub const PARAM_FORWARD: u64 = 0x10;
pub const PARAM_SUBSCRIBER_PRIORITY: u64 = 0x20;
pub const PARAM_FILTER_TYPE: u64 = 0x21;
pub const PARAM_GROUP_ORDER: u64 = 0x22;

pub const Subscribe = struct {
    request_id: track.RequestId = 0,
    track_namespace: []const []const u8,
    track_name: []const u8,
    subscriber_priority: track.Priority = 128,
    group_order: track.GroupOrder = .ascending,
    filter_type: track.FilterType = .latest_object,
    forward: bool = true,
};

pub fn writeSubscribe(writer: anytype, s: Subscribe) !void {
    var scratch: [MAX_PAYLOAD_LEN]u8 = undefined;
    var fbs = io.fixedBufferStream(&scratch);
    const w = &fbs;
    try wire.writeVarInt(w, s.request_id);
    try wire.writeVarInt(w, 0); // required_request_id_delta
    try wire.writeTuple(w, s.track_namespace);
    try wire.writeVarBytes(w, s.track_name);

    // Message parameters: count-prefixed, delta-encoded keys, type-specific values.
    // moq-rs draft-17: bool/u8 as raw byte, FilterType as length-prefixed varint,
    // GroupOrder as raw byte (u8 param).
    try wire.writeVarInt(w, 4); // param count
    try wire.writeVarInt(w, PARAM_FORWARD); // delta from 0 = 0x10
    try w.writeByte(if (s.forward) 1 else 0); // bool → raw byte
    try wire.writeVarInt(w, PARAM_SUBSCRIBER_PRIORITY - PARAM_FORWARD); // delta = 0x10
    try w.writeByte(s.subscriber_priority); // u8 → raw byte
    // FilterType: length-prefixed bytes containing the varint value
    try wire.writeVarInt(w, PARAM_FILTER_TYPE - PARAM_SUBSCRIBER_PRIORITY); // delta = 1
    var ft_buf: [8]u8 = undefined;
    var ft_fbs = io.fixedBufferStream(&ft_buf);
    try wire.writeVarInt(&ft_fbs, @intFromEnum(s.filter_type));
    try wire.writeVarInt(w, ft_fbs.seek); // length prefix
    try w.writeAll(ft_buf[0..ft_fbs.seek]); // varint bytes
    // GroupOrder: raw byte (u8 Param encoding)
    try wire.writeVarInt(w, PARAM_GROUP_ORDER - PARAM_FILTER_TYPE); // delta = 1
    try w.writeByte(@intFromEnum(s.group_order)); // u8 → raw byte

    try writeEnvelope(writer, codes.MSG_SUBSCRIBE, scratch[0..fbs.seek]);
}

// `ns_buf` receives the namespace parts; it must outlive the returned
// Subscribe, whose `track_namespace` aliases it. The parts themselves alias
// `payload`.
pub fn decodeSubscribe(payload: []const u8, ns_buf: *NamespaceBuf) !Subscribe {
    var fbs = io.fixedBufferStream(payload);
    const reader = &fbs;

    const request_id = try wire.readVarInt(reader);
    _ = try wire.readVarInt(reader); // required_request_id_delta

    const ns = wire.readTuple(&fbs, ns_buf) catch return Error.MalformedMessage;
    const name = try wire.readVarBytesZc(&fbs);

    // Parse count-prefixed parameters (delta-encoded keys, type-specific values).
    var sub = Subscribe{
        .request_id = request_id,
        .track_namespace = ns,
        .track_name = name,
    };

    const param_count = wire.readVarInt(reader) catch return sub;
    var prev_key: u64 = 0;
    for (0..@as(usize, @intCast(param_count))) |i| {
        const delta = wire.readVarInt(reader) catch break;
        const key = if (i == 0) delta else prev_key + delta;
        prev_key = key;
        switch (key) {
            PARAM_FORWARD => sub.forward = (reader.takeByte() catch break) != 0,
            PARAM_SUBSCRIBER_PRIORITY => sub.subscriber_priority = reader.takeByte() catch break,
            PARAM_FILTER_TYPE => {
                // Length-prefixed bytes containing varint FilterType.
                const ft_len = wire.readVarInt(reader) catch break;
                if (ft_len == 0) break;
                // Read the inner varint from the prefixed bytes.
                const ft_val = wire.readVarInt(reader) catch break;
                sub.filter_type = track.FilterType.fromInt(ft_val) orelse .latest_object;
            },
            PARAM_GROUP_ORDER => {
                // u8 Param encoding = raw byte.
                const raw = reader.takeByte() catch break;
                sub.group_order = track.GroupOrder.fromInt(raw) orelse return Error.MalformedMessage;
            },
            else => break,
        }
    }

    return sub;
}

// SUBSCRIBE_OK (0x04, §9.9)
// Draft-17: no request_id on wire; track_alias + KV parameters.

pub const SubscribeOk = struct {
    track_alias: track.TrackAlias,
    group_order: ?track.GroupOrder = null,
};

pub fn writeSubscribeOk(writer: anytype, s: SubscribeOk) !void {
    var scratch: [MAX_PAYLOAD_LEN]u8 = undefined;
    var fbs = io.fixedBufferStream(&scratch);
    const w = &fbs;
    try wire.writeVarInt(w, s.track_alias);
    // Message parameters: count-prefixed, delta keys, type-specific values.
    if (s.group_order) |go| {
        try wire.writeVarInt(w, 1); // param count
        try wire.writeVarInt(w, PARAM_GROUP_ORDER); // delta from 0
        try w.writeByte(@intFromEnum(go)); // GroupOrder: raw byte (u8 Param)
    } else {
        try wire.writeVarInt(w, 0); // empty params
    }
    try writeEnvelope(writer, codes.MSG_SUBSCRIBE_OK, scratch[0..fbs.seek]);
}

pub fn decodeSubscribeOk(payload: []const u8) !SubscribeOk {
    var fbs = io.fixedBufferStream(payload);
    const reader = &fbs;
    const alias = try wire.readVarInt(reader);
    var result = SubscribeOk{ .track_alias = alias };

    // Message parameters, same shape the writer emits: count, then
    // delta-encoded keys with type-specific values.
    const param_count = wire.readVarInt(reader) catch return result;
    var prev_key: u64 = 0;
    for (0..@as(usize, @intCast(param_count))) |i| {
        const delta = wire.readVarInt(reader) catch break;
        const key = if (i == 0) delta else prev_key + delta;
        prev_key = key;
        switch (key) {
            PARAM_GROUP_ORDER => {
                const raw = reader.takeByte() catch break;
                result.group_order = track.GroupOrder.fromInt(raw) orelse return Error.MalformedMessage;
            },
            else => break, // unknown key: value shape unknown, stop parsing
        }
    }
    return result;
}

// REQUEST_UPDATE (0x02, §9.10) — update an existing subscribe

pub const RequestUpdate = struct {
    subscriber_priority: track.Priority,
    group_order: track.GroupOrder,
    end: ?track.Location = null,
};

pub fn writeRequestUpdate(writer: anytype, u: RequestUpdate) !void {
    var scratch: [MAX_PAYLOAD_LEN]u8 = undefined;
    var fbs = io.fixedBufferStream(&scratch);
    const w = &fbs;
    try w.writeByte(u.subscriber_priority);
    try w.writeByte(@intFromEnum(u.group_order));
    if (u.end) |loc| {
        try wire.writeVarInt(w, loc.group);
        try wire.writeVarInt(w, loc.object);
    }
    try writeEnvelope(writer, codes.MSG_REQUEST_UPDATE, scratch[0..fbs.seek]);
}

pub fn decodeRequestUpdate(payload: []const u8) !RequestUpdate {
    var fbs = io.fixedBufferStream(payload);
    const reader = &fbs;
    const pri = reader.takeByte() catch return wire.Error.BufferTooShort;
    const order = reader.takeByte() catch return wire.Error.BufferTooShort;
    var u = RequestUpdate{
        .subscriber_priority = pri,
        .group_order = track.GroupOrder.fromInt(order) orelse return Error.MalformedMessage,
    };
    // The end Location is optional: present only when bytes remain.
    if (fbs.seek < payload.len) {
        const g = try wire.readVarInt(reader);
        const o = try wire.readVarInt(reader);
        u.end = .{ .group = g, .object = o };
    }
    return u;
}

// PUBLISH (0x1D, §9.11) — sent on bidi request stream to announce intent

pub const Publish = struct {
    track_namespace: []const []const u8,
    track_name: []const u8,
    track_alias: track.TrackAlias,
    publisher_priority: track.Priority,
};

pub fn writePublish(writer: anytype, p: Publish) !void {
    var scratch: [MAX_PAYLOAD_LEN]u8 = undefined;
    var fbs = io.fixedBufferStream(&scratch);
    const w = &fbs;
    try wire.writeTuple(w, p.track_namespace);
    try wire.writeVarBytes(w, p.track_name);
    try wire.writeVarInt(w, p.track_alias);
    try w.writeByte(p.publisher_priority);
    try writeEnvelope(writer, codes.MSG_PUBLISH, scratch[0..fbs.seek]);
}

// See decodeSubscribe for the `ns_buf` lifetime contract.
pub fn decodePublish(payload: []const u8, ns_buf: *NamespaceBuf) !Publish {
    var fbs = io.fixedBufferStream(payload);
    const reader = &fbs;
    const ns = wire.readTuple(&fbs, ns_buf) catch return Error.MalformedMessage;
    const name = try wire.readVarBytesZc(&fbs);
    const alias = try wire.readVarInt(reader);
    const pri = reader.takeByte() catch return wire.Error.BufferTooShort;
    return .{
        .track_namespace = ns,
        .track_name = name,
        .track_alias = alias,
        .publisher_priority = pri,
    };
}

// PUBLISH_OK (0x1E, §9.12)

pub const PublishOk = struct {
    content_exists: bool = true,
    largest: ?track.Location = null,
};

pub fn writePublishOk(writer: anytype, p: PublishOk) !void {
    var scratch: [MAX_PAYLOAD_LEN]u8 = undefined;
    var fbs = io.fixedBufferStream(&scratch);
    const w = &fbs;
    try w.writeByte(if (p.content_exists) 1 else 0);
    if (p.content_exists) {
        const loc = p.largest orelse track.Location{ .group = 0, .object = 0 };
        try wire.writeVarInt(w, loc.group);
        try wire.writeVarInt(w, loc.object);
    }
    try wire.writeVarInt(w, 0); // parameter count
    try writeEnvelope(writer, codes.MSG_PUBLISH_OK, scratch[0..fbs.seek]);
}

pub fn decodePublishOk(payload: []const u8) !PublishOk {
    var fbs = io.fixedBufferStream(payload);
    const reader = &fbs;
    const exists = (reader.takeByte() catch return wire.Error.BufferTooShort) != 0;
    if (!exists) return .{ .content_exists = false };
    const group = try wire.readVarInt(reader);
    const object = try wire.readVarInt(reader);
    return .{ .content_exists = true, .largest = .{ .group = group, .object = object } };
}

// PUBLISH_DONE (0x0B, §9.13)

pub const PublishDone = struct {
    final_group: ?track.GroupId = null,
    final_object: ?track.ObjectId = null,
    status_code: u64 = 0,
    reason: []const u8 = "",
};

pub fn writePublishDone(writer: anytype, p: PublishDone) !void {
    var scratch: [MAX_PAYLOAD_LEN]u8 = undefined;
    var fbs = io.fixedBufferStream(&scratch);
    const w = &fbs;
    try wire.writeVarInt(w, p.status_code);
    try wire.writeVarBytes(w, p.reason);
    if (p.final_group) |g| {
        try wire.writeVarInt(w, g);
        if (p.final_object) |o| try wire.writeVarInt(w, o);
    }
    try writeEnvelope(writer, codes.MSG_PUBLISH_DONE, scratch[0..fbs.seek]);
}

pub fn decodePublishDone(payload: []const u8) !PublishDone {
    var fbs = io.fixedBufferStream(payload);
    const reader = &fbs;
    var d = PublishDone{
        .status_code = try wire.readVarInt(reader),
        .reason = try wire.readVarBytesZc(&fbs),
    };
    if (fbs.seek < payload.len) d.final_group = try wire.readVarInt(reader);
    if (fbs.seek < payload.len) d.final_object = try wire.readVarInt(reader);
    return d;
}

// PUBLISH_NAMESPACE (0x06, §9.17)

pub const PublishNamespace = struct {
    track_namespace_prefix: []const []const u8,
};

pub fn writePublishNamespace(writer: anytype, p: PublishNamespace) !void {
    var scratch: [MAX_PAYLOAD_LEN]u8 = undefined;
    var fbs = io.fixedBufferStream(&scratch);
    try wire.writeTuple(&fbs, p.track_namespace_prefix);
    try writeEnvelope(writer, codes.MSG_PUBLISH_NAMESPACE, scratch[0..fbs.seek]);
}

pub fn decodePublishNamespace(payload: []const u8, ns_buf: *NamespaceBuf) !PublishNamespace {
    var fbs = io.fixedBufferStream(payload);
    const ns = wire.readTuple(&fbs, ns_buf) catch return Error.MalformedMessage;
    return .{ .track_namespace_prefix = ns };
}

// SUBSCRIBE_NAMESPACE (0x11, §9.20)

pub const SubscribeNamespace = struct {
    track_namespace_prefix: []const []const u8,
};

pub fn writeSubscribeNamespace(writer: anytype, s: SubscribeNamespace) !void {
    var scratch: [MAX_PAYLOAD_LEN]u8 = undefined;
    var fbs = io.fixedBufferStream(&scratch);
    try wire.writeTuple(&fbs, s.track_namespace_prefix);
    try writeEnvelope(writer, codes.MSG_SUBSCRIBE_NAMESPACE, scratch[0..fbs.seek]);
}

pub fn decodeSubscribeNamespace(payload: []const u8, ns_buf: *NamespaceBuf) !SubscribeNamespace {
    var fbs = io.fixedBufferStream(payload);
    const ns = wire.readTuple(&fbs, ns_buf) catch return Error.MalformedMessage;
    return .{ .track_namespace_prefix = ns };
}

// NAMESPACE (0x08, §9.18)

pub const Namespace = struct {
    track_namespace: []const []const u8,
};

pub fn writeNamespace(writer: anytype, n: Namespace) !void {
    var scratch: [MAX_PAYLOAD_LEN]u8 = undefined;
    var fbs = io.fixedBufferStream(&scratch);
    try wire.writeTuple(&fbs, n.track_namespace);
    try writeEnvelope(writer, codes.MSG_NAMESPACE, scratch[0..fbs.seek]);
}

pub fn decodeNamespace(payload: []const u8, ns_buf: *NamespaceBuf) !Namespace {
    var fbs = io.fixedBufferStream(payload);
    const ns = wire.readTuple(&fbs, ns_buf) catch return Error.MalformedMessage;
    return .{ .track_namespace = ns };
}

// NAMESPACE_DONE (0x0E, §9.19)

pub fn writeNamespaceDone(writer: anytype) !void {
    try writeEnvelope(writer, codes.MSG_NAMESPACE_DONE, &.{});
}

// FETCH (0x16, §9.14)

pub const Fetch = struct {
    track_namespace: []const []const u8,
    track_name: []const u8,
    subscriber_priority: track.Priority,
    group_order: track.GroupOrder,
    start: track.Location,
    end: track.Location,
};

pub fn writeFetch(writer: anytype, f: Fetch) !void {
    var scratch: [MAX_PAYLOAD_LEN]u8 = undefined;
    var fbs = io.fixedBufferStream(&scratch);
    const w = &fbs;
    try wire.writeTuple(w, f.track_namespace);
    try wire.writeVarBytes(w, f.track_name);
    try w.writeByte(f.subscriber_priority);
    try w.writeByte(@intFromEnum(f.group_order));
    try wire.writeVarInt(w, f.start.group);
    try wire.writeVarInt(w, f.start.object);
    try wire.writeVarInt(w, f.end.group);
    try wire.writeVarInt(w, f.end.object);
    try writeEnvelope(writer, codes.MSG_FETCH, scratch[0..fbs.seek]);
}

pub fn decodeFetch(payload: []const u8, ns_buf: *NamespaceBuf) !Fetch {
    var fbs = io.fixedBufferStream(payload);
    const reader = &fbs;
    const ns = wire.readTuple(&fbs, ns_buf) catch return Error.MalformedMessage;
    const name = try wire.readVarBytesZc(&fbs);
    const pri = reader.takeByte() catch return wire.Error.BufferTooShort;
    const order = reader.takeByte() catch return wire.Error.BufferTooShort;
    return .{
        .track_namespace = ns,
        .track_name = name,
        .subscriber_priority = pri,
        .group_order = track.GroupOrder.fromInt(order) orelse return Error.MalformedMessage,
        .start = .{ .group = try wire.readVarInt(reader), .object = try wire.readVarInt(reader) },
        .end = .{ .group = try wire.readVarInt(reader), .object = try wire.readVarInt(reader) },
    };
}

// FETCH_OK (0x18, §9.15)

pub const FetchOk = struct {
    track_alias: track.TrackAlias,
};

pub fn writeFetchOk(writer: anytype, f: FetchOk) !void {
    var scratch: [MAX_PAYLOAD_LEN]u8 = undefined;
    var fbs = io.fixedBufferStream(&scratch);
    try wire.writeVarInt(&fbs, f.track_alias);
    try writeEnvelope(writer, codes.MSG_FETCH_OK, scratch[0..fbs.seek]);
}

pub fn decodeFetchOk(payload: []const u8) !FetchOk {
    var fbs = io.fixedBufferStream(payload);
    return .{ .track_alias = try wire.readVarInt(&fbs) };
}

// TRACK_STATUS (0x0D, §9.16)

pub const TrackStatus = struct {
    track_namespace: []const []const u8,
    track_name: []const u8,
    status_code: u64,
    largest: ?track.Location = null,
};

pub fn writeTrackStatus(writer: anytype, t: TrackStatus) !void {
    var scratch: [MAX_PAYLOAD_LEN]u8 = undefined;
    var fbs = io.fixedBufferStream(&scratch);
    const w = &fbs;
    try wire.writeTuple(w, t.track_namespace);
    try wire.writeVarBytes(w, t.track_name);
    try wire.writeVarInt(w, t.status_code);
    if (t.largest) |loc| {
        try wire.writeVarInt(w, loc.group);
        try wire.writeVarInt(w, loc.object);
    }
    try writeEnvelope(writer, codes.MSG_TRACK_STATUS, scratch[0..fbs.seek]);
}

pub fn decodeTrackStatus(payload: []const u8, ns_buf: *NamespaceBuf) !TrackStatus {
    var fbs = io.fixedBufferStream(payload);
    const reader = &fbs;
    const ns = wire.readTuple(&fbs, ns_buf) catch return Error.MalformedMessage;
    const name = try wire.readVarBytesZc(&fbs);
    var t = TrackStatus{
        .track_namespace = ns,
        .track_name = name,
        .status_code = try wire.readVarInt(reader),
    };
    if (fbs.seek < payload.len) {
        const g = try wire.readVarInt(reader);
        const o = try wire.readVarInt(reader);
        t.largest = .{ .group = g, .object = o };
    }
    return t;
}

// PUBLISH_BLOCKED (0x0F, §9.21)

pub const PublishBlocked = struct {
    track_alias: track.TrackAlias,
};

pub fn writePublishBlocked(writer: anytype, p: PublishBlocked) !void {
    var scratch: [MAX_PAYLOAD_LEN]u8 = undefined;
    var fbs = io.fixedBufferStream(&scratch);
    try wire.writeVarInt(&fbs, p.track_alias);
    try writeEnvelope(writer, codes.MSG_PUBLISH_BLOCKED, scratch[0..fbs.seek]);
}

pub fn decodePublishBlocked(payload: []const u8) !PublishBlocked {
    var fbs = io.fixedBufferStream(payload);
    return .{ .track_alias = try wire.readVarInt(&fbs) };
}

// Tests

test "envelope round-trip" {
    var buf: [64]u8 = undefined;
    var fbs = io.fixedBufferStream(&buf);
    try writeEnvelope(&fbs, codes.MSG_GOAWAY, "hello");
    const parsed = try parseEnvelope(buf[0..fbs.seek]);
    try testing.expectEqual(codes.MSG_GOAWAY, parsed.env.type);
    try testing.expectEqualStrings("hello", parsed.env.payload);
    try testing.expectEqual(fbs.seek, parsed.consumed);
}

test "envelope rejects legacy setup codes" {
    // Code 0x20 is a legacy CLIENT_SETUP from pre-v17.
    var buf = [_]u8{ 0x20, 0x00, 0x00 };
    try testing.expectError(Error.ReservedLegacyMessage, parseEnvelope(&buf));
}

test "SETUP round-trip with path + implementation" {
    var buf: [128]u8 = undefined;
    var fbs = io.fixedBufferStream(&buf);
    try writeSetup(&fbs, .{
        .path = "/moq",
        .implementation = "quic-zig/moq/0",
        .max_auth_token_cache_size = 256,
    });
    const p = try parseEnvelope(buf[0..fbs.seek]);
    try testing.expectEqual(codes.MSG_SETUP, p.env.type);
    const opts = try decodeSetupPayload(p.env.payload);
    try testing.expectEqualStrings("/moq", opts.path.?);
    try testing.expectEqualStrings("quic-zig/moq/0", opts.implementation.?);
    try testing.expectEqual(@as(?u64, 256), opts.max_auth_token_cache_size);
    try testing.expectEqual(@as(?[]const u8, null), opts.authority);
}

test "GOAWAY round-trip" {
    var buf: [64]u8 = undefined;
    var fbs = io.fixedBufferStream(&buf);
    try writeGoaway(&fbs, .{ .new_uri = "https://other.example/moq" });
    const p = try parseEnvelope(buf[0..fbs.seek]);
    try testing.expectEqual(codes.MSG_GOAWAY, p.env.type);
    const g = try decodeGoaway(p.env.payload);
    try testing.expectEqualStrings("https://other.example/moq", g.new_uri);
}

test "REQUEST_ERROR round-trip" {
    var buf: [64]u8 = undefined;
    var fbs = io.fixedBufferStream(&buf);
    try writeRequestError(&fbs, .{
        .error_code = codes.ERR_UNAUTHORIZED,
        .reason = "no token",
    });
    const p = try parseEnvelope(buf[0..fbs.seek]);
    const e = try decodeRequestError(p.env.payload);
    try testing.expectEqual(codes.ERR_UNAUTHORIZED, e.error_code);
    try testing.expectEqualStrings("no token", e.reason);
}

test "SUBSCRIBE round-trip" {
    var buf: [256]u8 = undefined;
    var fbs = io.fixedBufferStream(&buf);
    const ns = [_][]const u8{ "moq", "demo" };
    try writeSubscribe(&fbs, .{
        .track_namespace = &ns,
        .track_name = "video",
        .subscriber_priority = 128,
        .group_order = .ascending,
        .filter_type = .latest_object,
    });
    const p = try parseEnvelope(buf[0..fbs.seek]);
    try testing.expectEqual(codes.MSG_SUBSCRIBE, p.env.type);
    var ns_buf: NamespaceBuf = undefined;
    const s = try decodeSubscribe(p.env.payload, &ns_buf);
    try testing.expectEqual(@as(usize, 2), s.track_namespace.len);
    try testing.expectEqualStrings("video", s.track_name);
    try testing.expectEqual(@as(u8, 128), s.subscriber_priority);
    try testing.expectEqual(track.FilterType.latest_object, s.filter_type);
    try testing.expectEqual(track.GroupOrder.ascending, s.group_order);
    try testing.expect(s.forward);
}

test "SUBSCRIBE_OK round-trip" {
    var buf: [64]u8 = undefined;
    var fbs = io.fixedBufferStream(&buf);
    try writeSubscribeOk(&fbs, .{
        .track_alias = 42,
        .group_order = .descending,
    });
    const p = try parseEnvelope(buf[0..fbs.seek]);
    try testing.expectEqual(codes.MSG_SUBSCRIBE_OK, p.env.type);
    const s = try decodeSubscribeOk(p.env.payload);
    try testing.expectEqual(@as(u64, 42), s.track_alias);
}

test "PUBLISH round-trip" {
    var buf: [256]u8 = undefined;
    var fbs = io.fixedBufferStream(&buf);
    const ns = [_][]const u8{ "moq", "demo" };
    try writePublish(&fbs, .{
        .track_namespace = &ns,
        .track_name = "video",
        .track_alias = 7,
        .publisher_priority = 200,
    });
    const p = try parseEnvelope(buf[0..fbs.seek]);
    try testing.expectEqual(codes.MSG_PUBLISH, p.env.type);
    var ns_buf: NamespaceBuf = undefined;
    const pub_ = try decodePublish(p.env.payload, &ns_buf);
    try testing.expectEqual(@as(usize, 2), pub_.track_namespace.len);
    try testing.expectEqualStrings("video", pub_.track_name);
    try testing.expectEqual(@as(u64, 7), pub_.track_alias);
    try testing.expectEqual(@as(u8, 200), pub_.publisher_priority);
}

test "REQUEST_OK round-trip with parameters" {
    var buf: [64]u8 = undefined;
    var fbs = io.fixedBufferStream(&buf);
    const params = [_]wire.KvEntry{
        .{ .key = 0x02, .value = .{ .varint = 9 } },
        .{ .key = 0x07, .value = .{ .bytes = "impl" } },
    };
    try writeRequestOk(&fbs, .{ .parameters = &params });
    const p = try parseEnvelope(buf[0..fbs.seek]);
    try testing.expectEqual(codes.MSG_REQUEST_OK, p.env.type);
    var out: [4]wire.KvEntry = undefined;
    const r = try decodeRequestOk(p.env.payload, &out);
    try testing.expectEqual(@as(usize, 2), r.parameters.len);
    try testing.expectEqual(@as(u64, 9), r.parameters[0].value.varint);
    try testing.expectEqualStrings("impl", r.parameters[1].value.bytes);
}

test "REQUEST_OK round-trip with no parameters" {
    var buf: [16]u8 = undefined;
    var fbs = io.fixedBufferStream(&buf);
    try writeRequestOk(&fbs, .{});
    const p = try parseEnvelope(buf[0..fbs.seek]);
    var out: [4]wire.KvEntry = undefined;
    const r = try decodeRequestOk(p.env.payload, &out);
    try testing.expectEqual(@as(usize, 0), r.parameters.len);
}

test "SUBSCRIBE_OK carries group_order both ways" {
    var buf: [64]u8 = undefined;
    var fbs = io.fixedBufferStream(&buf);
    try writeSubscribeOk(&fbs, .{ .track_alias = 42, .group_order = .descending });
    const p = try parseEnvelope(buf[0..fbs.seek]);
    const s = try decodeSubscribeOk(p.env.payload);
    try testing.expectEqual(@as(u64, 42), s.track_alias);
    try testing.expectEqual(track.GroupOrder.descending, s.group_order.?);

    // And the absent case stays absent rather than decoding garbage.
    var buf2: [64]u8 = undefined;
    var fbs2 = io.fixedBufferStream(&buf2);
    try writeSubscribeOk(&fbs2, .{ .track_alias = 1 });
    const p2 = try parseEnvelope(buf2[0..fbs2.seek]);
    const s2 = try decodeSubscribeOk(p2.env.payload);
    try testing.expectEqual(@as(?track.GroupOrder, null), s2.group_order);
}

test "PUBLISH_OK round-trip" {
    var buf: [64]u8 = undefined;
    var fbs = io.fixedBufferStream(&buf);
    try writePublishOk(&fbs, .{ .content_exists = true, .largest = .{ .group = 11, .object = 3 } });
    const p = try parseEnvelope(buf[0..fbs.seek]);
    const ok = try decodePublishOk(p.env.payload);
    try testing.expect(ok.content_exists);
    try testing.expectEqual(@as(u64, 11), ok.largest.?.group);
    try testing.expectEqual(@as(u64, 3), ok.largest.?.object);

    var buf2: [64]u8 = undefined;
    var fbs2 = io.fixedBufferStream(&buf2);
    try writePublishOk(&fbs2, .{ .content_exists = false });
    const p2 = try parseEnvelope(buf2[0..fbs2.seek]);
    const ok2 = try decodePublishOk(p2.env.payload);
    try testing.expect(!ok2.content_exists);
    try testing.expectEqual(@as(?track.Location, null), ok2.largest);
}

test "REQUEST_UPDATE round-trip with and without end" {
    var buf: [64]u8 = undefined;
    var fbs = io.fixedBufferStream(&buf);
    try writeRequestUpdate(&fbs, .{
        .subscriber_priority = 7,
        .group_order = .descending,
        .end = .{ .group = 5, .object = 6 },
    });
    const p = try parseEnvelope(buf[0..fbs.seek]);
    const u = try decodeRequestUpdate(p.env.payload);
    try testing.expectEqual(@as(u8, 7), u.subscriber_priority);
    try testing.expectEqual(track.GroupOrder.descending, u.group_order);
    try testing.expectEqual(@as(u64, 5), u.end.?.group);

    var buf2: [64]u8 = undefined;
    var fbs2 = io.fixedBufferStream(&buf2);
    try writeRequestUpdate(&fbs2, .{ .subscriber_priority = 1, .group_order = .ascending });
    const p2 = try parseEnvelope(buf2[0..fbs2.seek]);
    const u_no_end = try decodeRequestUpdate(p2.env.payload);
    try testing.expectEqual(@as(?track.Location, null), u_no_end.end);
}

test "PUBLISH_DONE round-trip" {
    var buf: [128]u8 = undefined;
    var fbs = io.fixedBufferStream(&buf);
    try writePublishDone(&fbs, .{
        .status_code = 4,
        .reason = "publisher gone",
        .final_group = 12,
        .final_object = 30,
    });
    const p = try parseEnvelope(buf[0..fbs.seek]);
    const d = try decodePublishDone(p.env.payload);
    try testing.expectEqual(@as(u64, 4), d.status_code);
    try testing.expectEqualStrings("publisher gone", d.reason);
    try testing.expectEqual(@as(?u64, 12), d.final_group);
    try testing.expectEqual(@as(?u64, 30), d.final_object);
}

test "namespace messages round-trip" {
    const ns = [_][]const u8{ "moq", "demo" };
    var ns_buf: NamespaceBuf = undefined;

    var buf: [128]u8 = undefined;
    var fbs = io.fixedBufferStream(&buf);
    try writePublishNamespace(&fbs, .{ .track_namespace_prefix = &ns });
    const p = try parseEnvelope(buf[0..fbs.seek]);
    const pn = try decodePublishNamespace(p.env.payload, &ns_buf);
    try testing.expectEqual(@as(usize, 2), pn.track_namespace_prefix.len);
    try testing.expectEqualStrings("demo", pn.track_namespace_prefix[1]);

    var buf2: [128]u8 = undefined;
    var fbs2 = io.fixedBufferStream(&buf2);
    try writeSubscribeNamespace(&fbs2, .{ .track_namespace_prefix = &ns });
    const p2 = try parseEnvelope(buf2[0..fbs2.seek]);
    const sn = try decodeSubscribeNamespace(p2.env.payload, &ns_buf);
    try testing.expectEqualStrings("moq", sn.track_namespace_prefix[0]);

    var buf3: [128]u8 = undefined;
    var fbs3 = io.fixedBufferStream(&buf3);
    try writeNamespace(&fbs3, .{ .track_namespace = &ns });
    const p3 = try parseEnvelope(buf3[0..fbs3.seek]);
    const n = try decodeNamespace(p3.env.payload, &ns_buf);
    try testing.expectEqual(@as(usize, 2), n.track_namespace.len);
}

test "FETCH and FETCH_OK round-trip" {
    const ns = [_][]const u8{"moq"};
    var ns_buf: NamespaceBuf = undefined;

    var buf: [128]u8 = undefined;
    var fbs = io.fixedBufferStream(&buf);
    try writeFetch(&fbs, .{
        .track_namespace = &ns,
        .track_name = "video",
        .subscriber_priority = 3,
        .group_order = .ascending,
        .start = .{ .group = 1, .object = 2 },
        .end = .{ .group = 9, .object = 0 },
    });
    const p = try parseEnvelope(buf[0..fbs.seek]);
    const f = try decodeFetch(p.env.payload, &ns_buf);
    try testing.expectEqualStrings("video", f.track_name);
    try testing.expectEqual(@as(u8, 3), f.subscriber_priority);
    try testing.expectEqual(@as(u64, 1), f.start.group);
    try testing.expectEqual(@as(u64, 9), f.end.group);

    var buf2: [32]u8 = undefined;
    var fbs2 = io.fixedBufferStream(&buf2);
    try writeFetchOk(&fbs2, .{ .track_alias = 77 });
    const p2 = try parseEnvelope(buf2[0..fbs2.seek]);
    try testing.expectEqual(@as(u64, 77), (try decodeFetchOk(p2.env.payload)).track_alias);
}

test "TRACK_STATUS and PUBLISH_BLOCKED round-trip" {
    const ns = [_][]const u8{"moq"};
    var ns_buf: NamespaceBuf = undefined;

    var buf: [128]u8 = undefined;
    var fbs = io.fixedBufferStream(&buf);
    try writeTrackStatus(&fbs, .{
        .track_namespace = &ns,
        .track_name = "audio",
        .status_code = 0,
        .largest = .{ .group = 4, .object = 8 },
    });
    const p = try parseEnvelope(buf[0..fbs.seek]);
    const t = try decodeTrackStatus(p.env.payload, &ns_buf);
    try testing.expectEqualStrings("audio", t.track_name);
    try testing.expectEqual(@as(u64, 4), t.largest.?.group);

    var buf2: [32]u8 = undefined;
    var fbs2 = io.fixedBufferStream(&buf2);
    try writePublishBlocked(&fbs2, .{ .track_alias = 5 });
    const p2 = try parseEnvelope(buf2[0..fbs2.seek]);
    try testing.expectEqual(@as(u64, 5), (try decodePublishBlocked(p2.env.payload)).track_alias);
}

test "decoded namespace outlives the decode call" {
    // Regression: decodeSubscribe used to return a slice into its own frame.
    const ns = [_][]const u8{ "alpha", "beta", "gamma" };
    var buf: [256]u8 = undefined;
    var fbs = io.fixedBufferStream(&buf);
    try writeSubscribe(&fbs, .{ .track_namespace = &ns, .track_name = "t" });
    const p = try parseEnvelope(buf[0..fbs.seek]);

    var ns_buf: NamespaceBuf = undefined;
    const sub = try decodeSubscribe(p.env.payload, &ns_buf);

    // Churn the stack that a callee-local array would have occupied.
    var scratch: [wire.MAX_TUPLE_PARTS][]const u8 = undefined;
    for (&scratch) |*e| e.* = "xxxxx";
    std.mem.doNotOptimizeAway(&scratch);

    try testing.expectEqual(@as(usize, 3), sub.track_namespace.len);
    try testing.expectEqualStrings("alpha", sub.track_namespace[0]);
    try testing.expectEqualStrings("gamma", sub.track_namespace[2]);
}
