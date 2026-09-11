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
const version = @import("version.zig");

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

pub const Goaway = struct {
    new_uri: []const u8 = "",
    /// Milliseconds the sender will wait before closing the session.
    timeout_ms: u64 = 0,
};

pub fn writeGoaway(writer: anytype, g: Goaway) !void {
    var scratch: [MAX_PAYLOAD_LEN]u8 = undefined;
    var fbs = io.fixedBufferStream(&scratch);
    try wire.writeVarBytes(&fbs, g.new_uri);
    try wire.writeVarInt(&fbs, g.timeout_ms);
    try writeEnvelope(writer, codes.MSG_GOAWAY, scratch[0..fbs.seek]);
}

pub fn decodeGoaway(payload: []const u8) !Goaway {
    var fbs = io.fixedBufferStream(payload);
    const uri = try wire.readVarBytesZc(&fbs);
    return .{ .new_uri = uri, .timeout_ms = try wire.readVarInt(&fbs) };
}

// Message Parameters (§9.3) ------------------------------------------------
//
//   Message Parameter { Type Delta (vi64), Value (..) }
//
// The value encoding is fixed by each parameter type, not by the parity of
// the key — that convention belongs to SETUP options (§1.4.3) and does not
// apply here. Parameters MUST be in ascending Type order, and an unknown
// type is a PROTOCOL_VIOLATION rather than something to skip, because the
// receiver cannot know how long its value is.

pub const ParamType = struct {
    pub const DELIVERY_TIMEOUT: u64 = 0x02;
    pub const AUTHORIZATION_TOKEN: u64 = 0x03;
    pub const RENDEZVOUS_TIMEOUT: u64 = 0x04;
    pub const EXPIRES: u64 = 0x08;
    pub const LARGEST_OBJECT: u64 = 0x09;
    pub const FORWARD: u64 = 0x10;
    pub const SUBSCRIBER_PRIORITY: u64 = 0x20;
    pub const SUBSCRIPTION_FILTER: u64 = 0x21;
    pub const GROUP_ORDER: u64 = 0x22;
    pub const NEW_GROUP_REQUEST: u64 = 0x32;
};

pub const ParamShape = enum { varint, uint8, location, length_prefixed };

pub fn paramShape(t: u64) ?ParamShape {
    return switch (t) {
        ParamType.DELIVERY_TIMEOUT,
        ParamType.RENDEZVOUS_TIMEOUT,
        ParamType.EXPIRES,
        ParamType.NEW_GROUP_REQUEST,
        => .varint,
        ParamType.FORWARD,
        ParamType.SUBSCRIBER_PRIORITY,
        ParamType.GROUP_ORDER,
        => .uint8,
        ParamType.LARGEST_OBJECT => .location,
        ParamType.AUTHORIZATION_TOKEN, ParamType.SUBSCRIPTION_FILTER => .length_prefixed,
        else => null,
    };
}

pub const ParamValue = union(enum) {
    varint: u64,
    uint8: u8,
    location: track.Location,
    bytes: []const u8,
};

pub const Param = struct {
    type: u64,
    value: ParamValue,
};

pub const MAX_PARAMS: usize = 16;

pub fn writeParams(writer: anytype, params: []const Param) !void {
    try wire.writeVarInt(writer, params.len);
    var prev: u64 = 0;
    for (params, 0..) |p, i| {
        if (i > 0 and p.type <= prev) return Error.MalformedMessage; // ascending order
        try wire.writeVarInt(writer, if (i == 0) p.type else p.type - prev);
        prev = p.type;
        switch (p.value) {
            .varint => |v| try wire.writeVarInt(writer, v),
            .uint8 => |v| try writer.writeByte(v),
            .location => |l| {
                try wire.writeVarInt(writer, l.group);
                try wire.writeVarInt(writer, l.object);
            },
            .bytes => |b| try wire.writeVarBytes(writer, b),
        }
    }
}

/// Reads a parameter list from the front of `fbs`, filling `out`.
pub fn readParams(fbs: *io.FixedBufferStream([]const u8), out: []Param) ![]Param {
    const count = try wire.readVarInt(fbs);
    if (count > out.len) return Error.MalformedMessage;
    var prev: u64 = 0;
    for (0..@as(usize, @intCast(count))) |i| {
        const delta = try wire.readVarInt(fbs);
        const t = if (i == 0) delta else std.math.add(u64, prev, delta) catch return Error.MalformedMessage;
        prev = t;
        const shape = paramShape(t) orelse return Error.MalformedMessage;
        out[i] = .{
            .type = t,
            .value = switch (shape) {
                .varint => .{ .varint = try wire.readVarInt(fbs) },
                .uint8 => .{ .uint8 = fbs.takeByte() catch return wire.Error.BufferTooShort },
                .location => .{ .location = .{
                    .group = try wire.readVarInt(fbs),
                    .object = try wire.readVarInt(fbs),
                } },
                .length_prefixed => .{ .bytes = try wire.readVarBytesZc(fbs) },
            },
        };
    }
    return out[0..@as(usize, @intCast(count))];
}

fn findParam(params: []const Param, t: u64) ?ParamValue {
    for (params) |p| if (p.type == t) return p.value;
    return null;
}

// Subscription Filter (§5.1.2) — the SUBSCRIPTION_FILTER parameter's value.

pub const Filter = struct {
    type: track.FilterType = .latest_object,
    /// Present for AbsoluteStart and AbsoluteRange.
    start: ?track.Location = null,
    /// Present for AbsoluteRange.
    end_group_delta: ?u64 = null,

    fn encode(self: Filter, buf: []u8) ![]const u8 {
        var fbs = io.fixedBufferStream(buf);
        try wire.writeVarInt(&fbs, @intFromEnum(self.type));
        if (self.start) |l| {
            try wire.writeVarInt(&fbs, l.group);
            try wire.writeVarInt(&fbs, l.object);
        }
        if (self.end_group_delta) |d| try wire.writeVarInt(&fbs, d);
        return buf[0..fbs.seek];
    }

    fn decode(bytes: []const u8) !Filter {
        var fbs = io.fixedBufferStream(bytes);
        const raw = try wire.readVarInt(&fbs);
        var f = Filter{ .type = track.FilterType.fromInt(raw) orelse return Error.MalformedMessage };
        switch (f.type) {
            .next_group_start, .latest_object => {},
            .absolute_start, .absolute_range => {
                f.start = .{
                    .group = try wire.readVarInt(&fbs),
                    .object = try wire.readVarInt(&fbs),
                };
                if (f.type == .absolute_range) f.end_group_delta = try wire.readVarInt(&fbs);
            },
        }
        return f;
    }
};

// REQUEST_OK / REQUEST_ERROR (§9.6, §9.7) ----------------------------------
//
// These travel on the per-request bidi stream; draft-17 carries no request
// id on the wire, because the stream is the identifier.

pub const RequestOk = struct {
    params: []const Param = &.{},
};

pub fn writeRequestOk(writer: anytype, r: RequestOk) !void {
    var scratch: [MAX_PAYLOAD_LEN]u8 = undefined;
    var fbs = io.fixedBufferStream(&scratch);
    try writeParams(&fbs, r.params);
    try writeEnvelope(writer, codes.MSG_REQUEST_OK, scratch[0..fbs.seek]);
}

pub fn decodeRequestOk(payload: []const u8, out: []Param) !RequestOk {
    var fbs = io.fixedBufferStream(payload);
    return .{ .params = try readParams(&fbs, out) };
}

pub const RequestError = struct {
    error_code: u64,
    /// Milliseconds before the requester should retry; 0 means "don't".
    retry_interval_ms: u64 = 0,
    reason: []const u8 = "",
};

pub fn writeRequestError(writer: anytype, e: RequestError) !void {
    var scratch: [MAX_PAYLOAD_LEN]u8 = undefined;
    var fbs = io.fixedBufferStream(&scratch);
    try wire.writeVarInt(&fbs, e.error_code);
    try wire.writeVarInt(&fbs, e.retry_interval_ms);
    try wire.writeVarBytes(&fbs, e.reason);
    try writeEnvelope(writer, codes.MSG_REQUEST_ERROR, scratch[0..fbs.seek]);
}

pub fn decodeRequestError(payload: []const u8) !RequestError {
    var fbs = io.fixedBufferStream(payload);
    return .{
        .error_code = try wire.readVarInt(&fbs),
        .retry_interval_ms = try wire.readVarInt(&fbs),
        .reason = try wire.readVarBytesZc(&fbs),
    };
}

// SUBSCRIBE (0x03, §9.8) ---------------------------------------------------

pub const Subscribe = struct {
    request_id: track.RequestId = 0,
    required_request_id_delta: u64 = 0,
    track_namespace: []const []const u8,
    track_name: []const u8,
    forward: ?bool = true,
    subscriber_priority: ?track.Priority = 128,
    filter: ?Filter = .{},
    group_order: ?track.GroupOrder = .ascending,
    /// §9.3.4, draft-17: how long the relay should hold a subscription
    /// waiting for a publisher to appear.
    rendezvous_timeout_ms: ?u64 = null,

    fn buildParams(self: Subscribe, out: []Param, filter_buf: []u8) ![]Param {
        var n: usize = 0;
        // Ascending Type order is required by §9.3.
        if (self.rendezvous_timeout_ms) |v| {
            out[n] = .{ .type = ParamType.RENDEZVOUS_TIMEOUT, .value = .{ .varint = v } };
            n += 1;
        }
        if (self.forward) |v| {
            out[n] = .{ .type = ParamType.FORWARD, .value = .{ .uint8 = @intFromBool(v) } };
            n += 1;
        }
        if (self.subscriber_priority) |v| {
            out[n] = .{ .type = ParamType.SUBSCRIBER_PRIORITY, .value = .{ .uint8 = v } };
            n += 1;
        }
        if (self.filter) |f| {
            out[n] = .{ .type = ParamType.SUBSCRIPTION_FILTER, .value = .{ .bytes = try f.encode(filter_buf) } };
            n += 1;
        }
        if (self.group_order) |v| {
            out[n] = .{ .type = ParamType.GROUP_ORDER, .value = .{ .uint8 = @intFromEnum(v) } };
            n += 1;
        }
        return out[0..n];
    }

    fn applyParams(self: *Subscribe, params: []const Param) !void {
        self.forward = null;
        self.subscriber_priority = null;
        self.filter = null;
        self.group_order = null;
        for (params) |p| switch (p.type) {
            ParamType.RENDEZVOUS_TIMEOUT => self.rendezvous_timeout_ms = p.value.varint,
            ParamType.FORWARD => self.forward = p.value.uint8 != 0,
            ParamType.SUBSCRIBER_PRIORITY => self.subscriber_priority = p.value.uint8,
            ParamType.SUBSCRIPTION_FILTER => self.filter = try Filter.decode(p.value.bytes),
            ParamType.GROUP_ORDER => self.group_order = track.GroupOrder.fromInt(p.value.uint8) orelse
                return Error.MalformedMessage,
            else => {},
        };
    }
};

fn writeSubscribeLike(writer: anytype, msg_type: u64, s: Subscribe, draft: version.Draft) !void {
    var scratch: [MAX_PAYLOAD_LEN]u8 = undefined;
    var fbs = io.fixedBufferStream(&scratch);
    const w = &fbs;
    try wire.writeVarInt(w, s.request_id);
    if (version.Rules.of(draft).required_request_id_delta) {
        try wire.writeVarInt(w, s.required_request_id_delta);
    }
    try wire.writeTuple(w, s.track_namespace);
    try wire.writeVarBytes(w, s.track_name);

    var params: [MAX_PARAMS]Param = undefined;
    var filter_buf: [32]u8 = undefined;
    try writeParams(w, try s.buildParams(&params, &filter_buf));

    try writeEnvelope(writer, msg_type, scratch[0..fbs.seek]);
}

pub fn writeSubscribe(writer: anytype, s: Subscribe, draft: version.Draft) !void {
    return writeSubscribeLike(writer, codes.MSG_SUBSCRIBE, s, draft);
}

fn decodeSubscribeLike(payload: []const u8, ns_buf: *NamespaceBuf, draft: version.Draft) !Subscribe {
    var fbs = io.fixedBufferStream(payload);
    var s = Subscribe{
        .request_id = try wire.readVarInt(&fbs),
        .required_request_id_delta = if (version.Rules.of(draft).required_request_id_delta)
            try wire.readVarInt(&fbs)
        else
            0,
        .track_namespace = wire.readTuple(&fbs, ns_buf) catch return Error.MalformedMessage,
        .track_name = try wire.readVarBytesZc(&fbs),
    };
    var params: [MAX_PARAMS]Param = undefined;
    try s.applyParams(try readParams(&fbs, &params));
    return s;
}

/// See the NamespaceBuf contract: `ns_buf` must outlive the result.
pub fn decodeSubscribe(payload: []const u8, ns_buf: *NamespaceBuf, draft: version.Draft) !Subscribe {
    return decodeSubscribeLike(payload, ns_buf, draft);
}

// SUBSCRIBE_OK (0x04, §9.9) ------------------------------------------------
//
// Track Properties fill whatever the message Length leaves after the
// parameters. We emit none and ignore any we are sent — §2.5 properties
// describe the track, and nothing here acts on them yet.

pub const SubscribeOk = struct {
    track_alias: track.TrackAlias,
    expires_ms: ?u64 = null,
    largest: ?track.Location = null,

    fn buildParams(self: SubscribeOk, out: []Param) []Param {
        var n: usize = 0;
        if (self.expires_ms) |v| {
            out[n] = .{ .type = ParamType.EXPIRES, .value = .{ .varint = v } };
            n += 1;
        }
        if (self.largest) |l| {
            out[n] = .{ .type = ParamType.LARGEST_OBJECT, .value = .{ .location = l } };
            n += 1;
        }
        return out[0..n];
    }
};

pub fn writeSubscribeOk(writer: anytype, s: SubscribeOk) !void {
    var scratch: [MAX_PAYLOAD_LEN]u8 = undefined;
    var fbs = io.fixedBufferStream(&scratch);
    try wire.writeVarInt(&fbs, s.track_alias);
    var params: [MAX_PARAMS]Param = undefined;
    try writeParams(&fbs, s.buildParams(&params));
    try writeEnvelope(writer, codes.MSG_SUBSCRIBE_OK, scratch[0..fbs.seek]);
}

pub fn decodeSubscribeOk(payload: []const u8) !SubscribeOk {
    var fbs = io.fixedBufferStream(payload);
    var s = SubscribeOk{ .track_alias = try wire.readVarInt(&fbs) };
    var params: [MAX_PARAMS]Param = undefined;
    const parsed = try readParams(&fbs, &params);
    if (findParam(parsed, ParamType.EXPIRES)) |v| s.expires_ms = v.varint;
    if (findParam(parsed, ParamType.LARGEST_OBJECT)) |v| s.largest = v.location;
    return s;
}

// REQUEST_UPDATE (0x02, §9.10) ---------------------------------------------

pub const RequestUpdate = struct {
    request_id: track.RequestId = 0,
    required_request_id_delta: u64 = 0,
    subscriber_priority: ?track.Priority = null,
    forward: ?bool = null,
    filter: ?Filter = null,
};

pub fn writeRequestUpdate(writer: anytype, u: RequestUpdate, draft: version.Draft) !void {
    var scratch: [MAX_PAYLOAD_LEN]u8 = undefined;
    var fbs = io.fixedBufferStream(&scratch);
    const w = &fbs;
    try wire.writeVarInt(w, u.request_id);
    if (version.Rules.of(draft).required_request_id_delta) {
        try wire.writeVarInt(w, u.required_request_id_delta);
    }

    var params: [MAX_PARAMS]Param = undefined;
    var filter_buf: [32]u8 = undefined;
    var n: usize = 0;
    if (u.forward) |v| {
        params[n] = .{ .type = ParamType.FORWARD, .value = .{ .uint8 = @intFromBool(v) } };
        n += 1;
    }
    if (u.subscriber_priority) |v| {
        params[n] = .{ .type = ParamType.SUBSCRIBER_PRIORITY, .value = .{ .uint8 = v } };
        n += 1;
    }
    if (u.filter) |f| {
        params[n] = .{ .type = ParamType.SUBSCRIPTION_FILTER, .value = .{ .bytes = try f.encode(&filter_buf) } };
        n += 1;
    }
    try writeParams(w, params[0..n]);
    try writeEnvelope(writer, codes.MSG_REQUEST_UPDATE, scratch[0..fbs.seek]);
}

pub fn decodeRequestUpdate(payload: []const u8, draft: version.Draft) !RequestUpdate {
    var fbs = io.fixedBufferStream(payload);
    var u = RequestUpdate{
        .request_id = try wire.readVarInt(&fbs),
        .required_request_id_delta = if (version.Rules.of(draft).required_request_id_delta)
            try wire.readVarInt(&fbs)
        else
            0,
    };
    var params: [MAX_PARAMS]Param = undefined;
    const parsed = try readParams(&fbs, &params);
    if (findParam(parsed, ParamType.FORWARD)) |v| u.forward = v.uint8 != 0;
    if (findParam(parsed, ParamType.SUBSCRIBER_PRIORITY)) |v| u.subscriber_priority = v.uint8;
    if (findParam(parsed, ParamType.SUBSCRIPTION_FILTER)) |v| u.filter = try Filter.decode(v.bytes);
    return u;
}

// PUBLISH (0x1D, §9.11) ----------------------------------------------------

pub const Publish = struct {
    request_id: track.RequestId = 0,
    required_request_id_delta: u64 = 0,
    track_namespace: []const []const u8,
    track_name: []const u8,
    track_alias: track.TrackAlias,
    forward: ?bool = null,
    largest: ?track.Location = null,
};

pub fn writePublish(writer: anytype, p: Publish, draft: version.Draft) !void {
    var scratch: [MAX_PAYLOAD_LEN]u8 = undefined;
    var fbs = io.fixedBufferStream(&scratch);
    const w = &fbs;
    try wire.writeVarInt(w, p.request_id);
    if (version.Rules.of(draft).required_request_id_delta) {
        try wire.writeVarInt(w, p.required_request_id_delta);
    }
    try wire.writeTuple(w, p.track_namespace);
    try wire.writeVarBytes(w, p.track_name);
    try wire.writeVarInt(w, p.track_alias);

    var params: [MAX_PARAMS]Param = undefined;
    var n: usize = 0;
    if (p.largest) |l| {
        params[n] = .{ .type = ParamType.LARGEST_OBJECT, .value = .{ .location = l } };
        n += 1;
    }
    if (p.forward) |v| {
        params[n] = .{ .type = ParamType.FORWARD, .value = .{ .uint8 = @intFromBool(v) } };
        n += 1;
    }
    try writeParams(w, params[0..n]);
    try writeEnvelope(writer, codes.MSG_PUBLISH, scratch[0..fbs.seek]);
}

/// See the NamespaceBuf contract: `ns_buf` must outlive the result.
pub fn decodePublish(payload: []const u8, ns_buf: *NamespaceBuf, draft: version.Draft) !Publish {
    var fbs = io.fixedBufferStream(payload);
    var p = Publish{
        .request_id = try wire.readVarInt(&fbs),
        .required_request_id_delta = if (version.Rules.of(draft).required_request_id_delta)
            try wire.readVarInt(&fbs)
        else
            0,
        .track_namespace = wire.readTuple(&fbs, ns_buf) catch return Error.MalformedMessage,
        .track_name = try wire.readVarBytesZc(&fbs),
        .track_alias = try wire.readVarInt(&fbs),
    };
    var params: [MAX_PARAMS]Param = undefined;
    const parsed = try readParams(&fbs, &params);
    if (findParam(parsed, ParamType.LARGEST_OBJECT)) |v| p.largest = v.location;
    if (findParam(parsed, ParamType.FORWARD)) |v| p.forward = v.uint8 != 0;
    return p;
}

// PUBLISH_OK (0x1E, §9.12) -------------------------------------------------

pub const PublishOk = struct {
    forward: ?bool = null,
    subscriber_priority: ?track.Priority = null,
    filter: ?Filter = null,
};

/// draft-18 removed the PUBLISH_OK code point (#1611) — the response to a
/// PUBLISH is a REQUEST_OK, with the same body. Table 5 still lists a 0x1E
/// row, which is a spec bug.
pub fn writePublishOk(writer: anytype, p: PublishOk, draft: version.Draft) !void {
    var scratch: [MAX_PAYLOAD_LEN]u8 = undefined;
    var fbs = io.fixedBufferStream(&scratch);
    var params: [MAX_PARAMS]Param = undefined;
    var filter_buf: [32]u8 = undefined;
    var n: usize = 0;
    if (p.forward) |v| {
        params[n] = .{ .type = ParamType.FORWARD, .value = .{ .uint8 = @intFromBool(v) } };
        n += 1;
    }
    if (p.subscriber_priority) |v| {
        params[n] = .{ .type = ParamType.SUBSCRIBER_PRIORITY, .value = .{ .uint8 = v } };
        n += 1;
    }
    if (p.filter) |f| {
        params[n] = .{ .type = ParamType.SUBSCRIPTION_FILTER, .value = .{ .bytes = try f.encode(&filter_buf) } };
        n += 1;
    }
    try writeParams(&fbs, params[0..n]);
    const msg_type = if (version.Rules.of(draft).publish_ok_is_own_message)
        codes.MSG_PUBLISH_OK
    else
        codes.MSG_REQUEST_OK;
    try writeEnvelope(writer, msg_type, scratch[0..fbs.seek]);
}

pub fn decodePublishOk(payload: []const u8) !PublishOk {
    var fbs = io.fixedBufferStream(payload);
    var params: [MAX_PARAMS]Param = undefined;
    const parsed = try readParams(&fbs, &params);
    var p = PublishOk{};
    if (findParam(parsed, ParamType.FORWARD)) |v| p.forward = v.uint8 != 0;
    if (findParam(parsed, ParamType.SUBSCRIBER_PRIORITY)) |v| p.subscriber_priority = v.uint8;
    if (findParam(parsed, ParamType.SUBSCRIPTION_FILTER)) |v| p.filter = try Filter.decode(v.bytes);
    return p;
}

// PUBLISH_DONE (0x0B, §9.13) -----------------------------------------------

pub const PublishDone = struct {
    status_code: u64 = 0,
    /// Number of data streams the publisher opened for this subscription,
    /// so the subscriber knows when it has seen them all.
    stream_count: u64 = 0,
    reason: []const u8 = "",
};

pub fn writePublishDone(writer: anytype, p: PublishDone) !void {
    var scratch: [MAX_PAYLOAD_LEN]u8 = undefined;
    var fbs = io.fixedBufferStream(&scratch);
    try wire.writeVarInt(&fbs, p.status_code);
    try wire.writeVarInt(&fbs, p.stream_count);
    try wire.writeVarBytes(&fbs, p.reason);
    try writeEnvelope(writer, codes.MSG_PUBLISH_DONE, scratch[0..fbs.seek]);
}

pub fn decodePublishDone(payload: []const u8) !PublishDone {
    var fbs = io.fixedBufferStream(payload);
    return .{
        .status_code = try wire.readVarInt(&fbs),
        .stream_count = try wire.readVarInt(&fbs),
        .reason = try wire.readVarBytesZc(&fbs),
    };
}

// FETCH (0x16, §9.14) ------------------------------------------------------

pub const FetchType = enum(u64) {
    standalone = 0x1,
    relative_joining = 0x2,
    absolute_joining = 0x3,

    pub fn fromInt(v: u64) ?FetchType {
        return switch (v) {
            0x1 => .standalone,
            0x2 => .relative_joining,
            0x3 => .absolute_joining,
            else => null,
        };
    }
};

pub const Fetch = struct {
    pub const Standalone = struct {
        track_namespace: []const []const u8,
        track_name: []const u8,
        start: track.Location,
        end: track.Location,
    };
    /// Both joining forms carry the same two fields; the tag says whether
    /// Joining Start is relative to the subscription or absolute.
    pub const Joining = struct { joining_request_id: u64, joining_start: u64 };

    pub const Body = union(FetchType) {
        standalone: Standalone,
        relative_joining: Joining,
        absolute_joining: Joining,
    };

    request_id: track.RequestId = 0,
    required_request_id_delta: u64 = 0,
    body: Body,
    subscriber_priority: ?track.Priority = null,
    group_order: ?track.GroupOrder = null,
};

pub fn writeFetch(writer: anytype, f: Fetch, draft: version.Draft) !void {
    var scratch: [MAX_PAYLOAD_LEN]u8 = undefined;
    var fbs = io.fixedBufferStream(&scratch);
    const w = &fbs;
    try wire.writeVarInt(w, f.request_id);
    if (version.Rules.of(draft).required_request_id_delta) {
        try wire.writeVarInt(w, f.required_request_id_delta);
    }
    try wire.writeVarInt(w, @intFromEnum(std.meta.activeTag(f.body)));
    switch (f.body) {
        .standalone => |s| {
            try wire.writeTuple(w, s.track_namespace);
            try wire.writeVarBytes(w, s.track_name);
            try wire.writeVarInt(w, s.start.group);
            try wire.writeVarInt(w, s.start.object);
            try wire.writeVarInt(w, s.end.group);
            try wire.writeVarInt(w, s.end.object);
        },
        .relative_joining, .absolute_joining => |j| {
            try wire.writeVarInt(w, j.joining_request_id);
            try wire.writeVarInt(w, j.joining_start);
        },
    }

    var params: [MAX_PARAMS]Param = undefined;
    var n: usize = 0;
    if (f.subscriber_priority) |v| {
        params[n] = .{ .type = ParamType.SUBSCRIBER_PRIORITY, .value = .{ .uint8 = v } };
        n += 1;
    }
    if (f.group_order) |v| {
        params[n] = .{ .type = ParamType.GROUP_ORDER, .value = .{ .uint8 = @intFromEnum(v) } };
        n += 1;
    }
    try writeParams(w, params[0..n]);
    try writeEnvelope(writer, codes.MSG_FETCH, scratch[0..fbs.seek]);
}

/// See the NamespaceBuf contract: `ns_buf` must outlive the result.
pub fn decodeFetch(payload: []const u8, ns_buf: *NamespaceBuf, draft: version.Draft) !Fetch {
    var fbs = io.fixedBufferStream(payload);
    const request_id = try wire.readVarInt(&fbs);
    const delta = if (version.Rules.of(draft).required_request_id_delta)
        try wire.readVarInt(&fbs)
    else
        0;
    const kind = FetchType.fromInt(try wire.readVarInt(&fbs)) orelse return Error.MalformedMessage;

    var f: Fetch = switch (kind) {
        .standalone => .{
            .request_id = request_id,
            .required_request_id_delta = delta,
            .body = .{ .standalone = .{
                .track_namespace = wire.readTuple(&fbs, ns_buf) catch return Error.MalformedMessage,
                .track_name = try wire.readVarBytesZc(&fbs),
                .start = .{ .group = try wire.readVarInt(&fbs), .object = try wire.readVarInt(&fbs) },
                .end = .{ .group = try wire.readVarInt(&fbs), .object = try wire.readVarInt(&fbs) },
            } },
        },
        .relative_joining => .{
            .request_id = request_id,
            .required_request_id_delta = delta,
            .body = .{ .relative_joining = .{
                .joining_request_id = try wire.readVarInt(&fbs),
                .joining_start = try wire.readVarInt(&fbs),
            } },
        },
        .absolute_joining => .{
            .request_id = request_id,
            .required_request_id_delta = delta,
            .body = .{ .absolute_joining = .{
                .joining_request_id = try wire.readVarInt(&fbs),
                .joining_start = try wire.readVarInt(&fbs),
            } },
        },
    };

    var params: [MAX_PARAMS]Param = undefined;
    const parsed = try readParams(&fbs, &params);
    if (findParam(parsed, ParamType.SUBSCRIBER_PRIORITY)) |v| f.subscriber_priority = v.uint8;
    if (findParam(parsed, ParamType.GROUP_ORDER)) |v| {
        f.group_order = track.GroupOrder.fromInt(v.uint8) orelse return Error.MalformedMessage;
    }
    return f;
}

// FETCH_OK (0x18, §9.15) ---------------------------------------------------

pub const FetchOk = struct {
    end_of_track: bool = false,
    end: track.Location = .{ .group = 0, .object = 0 },
    expires_ms: ?u64 = null,
};

pub fn writeFetchOk(writer: anytype, f: FetchOk) !void {
    var scratch: [MAX_PAYLOAD_LEN]u8 = undefined;
    var fbs = io.fixedBufferStream(&scratch);
    const w = &fbs;
    try w.writeByte(@intFromBool(f.end_of_track));
    try wire.writeVarInt(w, f.end.group);
    try wire.writeVarInt(w, f.end.object);

    var params: [MAX_PARAMS]Param = undefined;
    var n: usize = 0;
    if (f.expires_ms) |v| {
        params[n] = .{ .type = ParamType.EXPIRES, .value = .{ .varint = v } };
        n += 1;
    }
    try writeParams(w, params[0..n]);
    try writeEnvelope(writer, codes.MSG_FETCH_OK, scratch[0..fbs.seek]);
}

pub fn decodeFetchOk(payload: []const u8) !FetchOk {
    var fbs = io.fixedBufferStream(payload);
    var f = FetchOk{
        .end_of_track = (fbs.takeByte() catch return wire.Error.BufferTooShort) != 0,
        .end = .{ .group = try wire.readVarInt(&fbs), .object = try wire.readVarInt(&fbs) },
    };
    var params: [MAX_PARAMS]Param = undefined;
    const parsed = try readParams(&fbs, &params);
    if (findParam(parsed, ParamType.EXPIRES)) |v| f.expires_ms = v.varint;
    return f;
}

// TRACK_STATUS (0x0D, §9.16) -----------------------------------------------
//
// "The TRACK_STATUS message format is identical to the SUBSCRIBE message,
// but subscriber parameters related to Track delivery are not included."

pub const TrackStatus = Subscribe;

pub fn writeTrackStatus(writer: anytype, t: TrackStatus, draft: version.Draft) !void {
    return writeSubscribeLike(writer, codes.MSG_TRACK_STATUS, t, draft);
}

/// See the NamespaceBuf contract: `ns_buf` must outlive the result.
pub fn decodeTrackStatus(payload: []const u8, ns_buf: *NamespaceBuf, draft: version.Draft) !TrackStatus {
    return decodeSubscribeLike(payload, ns_buf, draft);
}

// PUBLISH_NAMESPACE (0x06, §9.17) ------------------------------------------

pub const PublishNamespace = struct {
    request_id: track.RequestId = 0,
    required_request_id_delta: u64 = 0,
    track_namespace: []const []const u8,
};

pub fn writePublishNamespace(writer: anytype, p: PublishNamespace, draft: version.Draft) !void {
    var scratch: [MAX_PAYLOAD_LEN]u8 = undefined;
    var fbs = io.fixedBufferStream(&scratch);
    const w = &fbs;
    try wire.writeVarInt(w, p.request_id);
    if (version.Rules.of(draft).required_request_id_delta) {
        try wire.writeVarInt(w, p.required_request_id_delta);
    }
    try wire.writeTuple(w, p.track_namespace);
    try writeParams(w, &.{});
    try writeEnvelope(writer, codes.MSG_PUBLISH_NAMESPACE, scratch[0..fbs.seek]);
}

/// See the NamespaceBuf contract: `ns_buf` must outlive the result.
pub fn decodePublishNamespace(payload: []const u8, ns_buf: *NamespaceBuf, draft: version.Draft) !PublishNamespace {
    var fbs = io.fixedBufferStream(payload);
    const p = PublishNamespace{
        .request_id = try wire.readVarInt(&fbs),
        .required_request_id_delta = if (version.Rules.of(draft).required_request_id_delta)
            try wire.readVarInt(&fbs)
        else
            0,
        .track_namespace = wire.readTuple(&fbs, ns_buf) catch return Error.MalformedMessage,
    };
    var params: [MAX_PARAMS]Param = undefined;
    _ = try readParams(&fbs, &params);
    return p;
}

// SUBSCRIBE_NAMESPACE (0x11, §9.20) ----------------------------------------

pub const SubscribeOptions = enum(u64) {
    publish = 0x00,
    namespace = 0x01,
    both = 0x02,

    pub fn fromInt(v: u64) ?SubscribeOptions {
        return switch (v) {
            0x00 => .publish,
            0x01 => .namespace,
            0x02 => .both,
            else => null,
        };
    }
};

pub const SubscribeNamespace = struct {
    request_id: track.RequestId = 0,
    required_request_id_delta: u64 = 0,
    track_namespace_prefix: []const []const u8,
    options: SubscribeOptions = .both,
    forward: ?bool = null,
};

fn writeSubscribeNamespaceLike(writer: anytype, msg_type: u64, s: SubscribeNamespace, draft: version.Draft) !void {
    const rules = version.Rules.of(draft);
    var scratch: [MAX_PAYLOAD_LEN]u8 = undefined;
    var fbs = io.fixedBufferStream(&scratch);
    const w = &fbs;
    try wire.writeVarInt(w, s.request_id);
    if (rules.required_request_id_delta) try wire.writeVarInt(w, s.required_request_id_delta);
    try wire.writeTuple(w, s.track_namespace_prefix);
    if (rules.subscribe_namespace_options) try wire.writeVarInt(w, @intFromEnum(s.options));

    var params: [MAX_PARAMS]Param = undefined;
    var n: usize = 0;
    if (s.forward) |v| {
        params[n] = .{ .type = ParamType.FORWARD, .value = .{ .uint8 = @intFromBool(v) } };
        n += 1;
    }
    try writeParams(w, params[0..n]);
    try writeEnvelope(writer, msg_type, scratch[0..fbs.seek]);
}

pub fn writeSubscribeNamespace(writer: anytype, s: SubscribeNamespace, draft: version.Draft) !void {
    return writeSubscribeNamespaceLike(writer, version.Rules.of(draft).subscribe_namespace_code, s, draft);
}

/// draft-18 §10.19 only. SUBSCRIBE_NAMESPACE yields NAMESPACE/NAMESPACE_DONE
/// there; this is the half that yields PUBLISH.
pub fn writeSubscribeTracks(writer: anytype, s: SubscribeNamespace, draft: version.Draft) !void {
    if (version.Rules.of(draft).subscribe_namespace_options) return Error.UnknownMessageType;
    return writeSubscribeNamespaceLike(writer, codes.MSG_SUBSCRIBE_TRACKS, s, draft);
}

/// See the NamespaceBuf contract: `ns_buf` must outlive the result.
pub fn decodeSubscribeNamespace(payload: []const u8, ns_buf: *NamespaceBuf, draft: version.Draft) !SubscribeNamespace {
    const rules = version.Rules.of(draft);
    var fbs = io.fixedBufferStream(payload);
    var s = SubscribeNamespace{
        .request_id = try wire.readVarInt(&fbs),
        .required_request_id_delta = if (rules.required_request_id_delta)
            try wire.readVarInt(&fbs)
        else
            0,
        .track_namespace_prefix = wire.readTuple(&fbs, ns_buf) catch return Error.MalformedMessage,
        .options = if (rules.subscribe_namespace_options)
            SubscribeOptions.fromInt(try wire.readVarInt(&fbs)) orelse return Error.MalformedMessage
        else
            // draft-18 split the choice into two message types, so the
            // caller knows which it read rather than the message saying.
            .namespace,
    };
    var params: [MAX_PARAMS]Param = undefined;
    const parsed = try readParams(&fbs, &params);
    if (findParam(parsed, ParamType.FORWARD)) |v| s.forward = v.uint8 != 0;
    return s;
}

// NAMESPACE (0x08, §9.18) and NAMESPACE_DONE (0x0E, §9.19) -----------------
//
// Both carry only the suffix: what remains of the namespace after the
// SUBSCRIBE_NAMESPACE prefix they answer.

pub const Namespace = struct {
    track_namespace_suffix: []const []const u8,
};

pub fn writeNamespace(writer: anytype, n: Namespace) !void {
    var scratch: [MAX_PAYLOAD_LEN]u8 = undefined;
    var fbs = io.fixedBufferStream(&scratch);
    try wire.writeTuple(&fbs, n.track_namespace_suffix);
    try writeEnvelope(writer, codes.MSG_NAMESPACE, scratch[0..fbs.seek]);
}

/// See the NamespaceBuf contract: `ns_buf` must outlive the result.
pub fn decodeNamespace(payload: []const u8, ns_buf: *NamespaceBuf) !Namespace {
    var fbs = io.fixedBufferStream(payload);
    return .{ .track_namespace_suffix = wire.readTuple(&fbs, ns_buf) catch return Error.MalformedMessage };
}

pub fn writeNamespaceDone(writer: anytype, n: Namespace) !void {
    var scratch: [MAX_PAYLOAD_LEN]u8 = undefined;
    var fbs = io.fixedBufferStream(&scratch);
    try wire.writeTuple(&fbs, n.track_namespace_suffix);
    try writeEnvelope(writer, codes.MSG_NAMESPACE_DONE, scratch[0..fbs.seek]);
}

/// See the NamespaceBuf contract: `ns_buf` must outlive the result.
pub fn decodeNamespaceDone(payload: []const u8, ns_buf: *NamespaceBuf) !Namespace {
    return decodeNamespace(payload, ns_buf);
}

// PUBLISH_BLOCKED (0x0F, §9.21) --------------------------------------------

pub const PublishBlocked = struct {
    track_namespace_suffix: []const []const u8,
    track_name: []const u8,
};

pub fn writePublishBlocked(writer: anytype, p: PublishBlocked) !void {
    var scratch: [MAX_PAYLOAD_LEN]u8 = undefined;
    var fbs = io.fixedBufferStream(&scratch);
    try wire.writeTuple(&fbs, p.track_namespace_suffix);
    try wire.writeVarBytes(&fbs, p.track_name);
    try writeEnvelope(writer, codes.MSG_PUBLISH_BLOCKED, scratch[0..fbs.seek]);
}

/// See the NamespaceBuf contract: `ns_buf` must outlive the result.
pub fn decodePublishBlocked(payload: []const u8, ns_buf: *NamespaceBuf) !PublishBlocked {
    var fbs = io.fixedBufferStream(payload);
    return .{
        .track_namespace_suffix = wire.readTuple(&fbs, ns_buf) catch return Error.MalformedMessage,
        .track_name = try wire.readVarBytesZc(&fbs),
    };
}

// Tests
//
// Round-tripping our own encoder proves only self-consistency — that is how
// the shapes below drifted from the draft in the first place. The byte-level
// assertions pin the wire format against draft-17 §9 directly.

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

test "GOAWAY carries the timeout §9.5 requires" {
    var buf: [64]u8 = undefined;
    var fbs = io.fixedBufferStream(&buf);
    try writeGoaway(&fbs, .{ .new_uri = "https://other.example/moq", .timeout_ms = 5000 });
    const p = try parseEnvelope(buf[0..fbs.seek]);
    const g = try decodeGoaway(p.env.payload);
    try testing.expectEqualStrings("https://other.example/moq", g.new_uri);
    try testing.expectEqual(@as(u64, 5000), g.timeout_ms);
}

test "REQUEST_ERROR carries the retry interval §9.7 requires" {
    var buf: [64]u8 = undefined;
    var fbs = io.fixedBufferStream(&buf);
    try writeRequestError(&fbs, .{
        .error_code = codes.ERR_UNAUTHORIZED,
        .retry_interval_ms = 250,
        .reason = "no token",
    });
    const p = try parseEnvelope(buf[0..fbs.seek]);
    const e = try decodeRequestError(p.env.payload);
    try testing.expectEqual(codes.ERR_UNAUTHORIZED, e.error_code);
    try testing.expectEqual(@as(u64, 250), e.retry_interval_ms);
    try testing.expectEqualStrings("no token", e.reason);
}

test "message parameters are count-prefixed and delta-ordered" {
    var buf: [64]u8 = undefined;
    var fbs = io.fixedBufferStream(&buf);
    const params = [_]Param{
        .{ .type = ParamType.FORWARD, .value = .{ .uint8 = 1 } },
        .{ .type = ParamType.SUBSCRIBER_PRIORITY, .value = .{ .uint8 = 200 } },
        .{ .type = ParamType.GROUP_ORDER, .value = .{ .uint8 = 2 } },
    };
    try writeParams(&fbs, &params);

    // count=3 | delta 0x10, 1 | delta 0x10, 200 | delta 0x02, 2
    try testing.expectEqualSlices(u8, &.{ 0x03, 0x10, 0x01, 0x10, 0xc8, 0x02, 0x02 }, buf[0..fbs.seek]);

    var rfbs = io.fixedBufferStream(@as([]const u8, buf[0..fbs.seek]));
    var out: [MAX_PARAMS]Param = undefined;
    const back = try readParams(&rfbs, &out);
    try testing.expectEqual(@as(usize, 3), back.len);
    try testing.expectEqual(ParamType.GROUP_ORDER, back[2].type);
    try testing.expectEqual(@as(u8, 2), back[2].value.uint8);
}

test "writeParams refuses descending types" {
    var buf: [64]u8 = undefined;
    var fbs = io.fixedBufferStream(&buf);
    const params = [_]Param{
        .{ .type = ParamType.GROUP_ORDER, .value = .{ .uint8 = 1 } },
        .{ .type = ParamType.FORWARD, .value = .{ .uint8 = 1 } },
    };
    try testing.expectError(Error.MalformedMessage, writeParams(&fbs, &params));
}

test "readParams rejects an unknown type" {
    // A receiver cannot know an unknown parameter's length, so §9.3 makes
    // this a protocol violation rather than something to skip.
    const bytes = [_]u8{ 0x01, 0x7e, 0x00 };
    var fbs = io.fixedBufferStream(@as([]const u8, &bytes));
    var out: [MAX_PARAMS]Param = undefined;
    try testing.expectError(Error.MalformedMessage, readParams(&fbs, &out));
}

test "SUBSCRIBE has the request id and delta §9.8 requires" {
    var buf: [256]u8 = undefined;
    var fbs = io.fixedBufferStream(&buf);
    const ns = [_][]const u8{ "moq", "demo" };
    try writeSubscribe(&fbs, .{
        .request_id = 3,
        .track_namespace = &ns,
        .track_name = "video",
        .subscriber_priority = 128,
        .group_order = .ascending,
        .filter = .{ .type = .latest_object },
    }, .draft_17);
    const p = try parseEnvelope(buf[0..fbs.seek]);
    try testing.expectEqual(codes.MSG_SUBSCRIBE, p.env.type);

    // request_id=3, delta=0, then the namespace tuple.
    try testing.expectEqual(@as(u8, 3), p.env.payload[0]);
    try testing.expectEqual(@as(u8, 0), p.env.payload[1]);
    try testing.expectEqual(@as(u8, 2), p.env.payload[2]); // tuple count

    var ns_buf: NamespaceBuf = undefined;
    const s = try decodeSubscribe(p.env.payload, &ns_buf, .draft_17);
    try testing.expectEqual(@as(u64, 3), s.request_id);
    try testing.expectEqual(@as(usize, 2), s.track_namespace.len);
    try testing.expectEqualStrings("video", s.track_name);
    try testing.expectEqual(@as(u8, 128), s.subscriber_priority.?);
    try testing.expectEqual(track.FilterType.latest_object, s.filter.?.type);
    try testing.expectEqual(track.GroupOrder.ascending, s.group_order.?);
    try testing.expect(s.forward.?);
}

test "SUBSCRIBE carries an absolute-range filter" {
    var buf: [256]u8 = undefined;
    var fbs = io.fixedBufferStream(&buf);
    const ns = [_][]const u8{"moq"};
    try writeSubscribe(&fbs, .{
        .track_namespace = &ns,
        .track_name = "v",
        .filter = .{
            .type = .absolute_range,
            .start = .{ .group = 4, .object = 2 },
            .end_group_delta = 9,
        },
    }, .draft_17);
    const p = try parseEnvelope(buf[0..fbs.seek]);
    var ns_buf: NamespaceBuf = undefined;
    const s = try decodeSubscribe(p.env.payload, &ns_buf, .draft_17);
    const f = s.filter.?;
    try testing.expectEqual(track.FilterType.absolute_range, f.type);
    try testing.expectEqual(@as(u64, 4), f.start.?.group);
    try testing.expectEqual(@as(u64, 2), f.start.?.object);
    try testing.expectEqual(@as(u64, 9), f.end_group_delta.?);
}

test "SUBSCRIBE carries RENDEZVOUS_TIMEOUT" {
    var buf: [256]u8 = undefined;
    var fbs = io.fixedBufferStream(&buf);
    const ns = [_][]const u8{"moq"};
    try writeSubscribe(&fbs, .{
        .track_namespace = &ns,
        .track_name = "v",
        .rendezvous_timeout_ms = 500,
    }, .draft_17);
    const p = try parseEnvelope(buf[0..fbs.seek]);
    var ns_buf: NamespaceBuf = undefined;
    const s = try decodeSubscribe(p.env.payload, &ns_buf, .draft_17);
    try testing.expectEqual(@as(u64, 500), s.rendezvous_timeout_ms.?);
}

test "SUBSCRIBE_OK round-trip with expiry and largest object" {
    var buf: [64]u8 = undefined;
    var fbs = io.fixedBufferStream(&buf);
    try writeSubscribeOk(&fbs, .{
        .track_alias = 42,
        .expires_ms = 1000,
        .largest = .{ .group = 7, .object = 3 },
    });
    const p = try parseEnvelope(buf[0..fbs.seek]);
    try testing.expectEqual(codes.MSG_SUBSCRIBE_OK, p.env.type);
    const s = try decodeSubscribeOk(p.env.payload);
    try testing.expectEqual(@as(u64, 42), s.track_alias);
    try testing.expectEqual(@as(u64, 1000), s.expires_ms.?);
    try testing.expectEqual(@as(u64, 7), s.largest.?.group);

    var buf2: [64]u8 = undefined;
    var fbs2 = io.fixedBufferStream(&buf2);
    try writeSubscribeOk(&fbs2, .{ .track_alias = 1 });
    const p2 = try parseEnvelope(buf2[0..fbs2.seek]);
    const s2 = try decodeSubscribeOk(p2.env.payload);
    try testing.expectEqual(@as(?u64, null), s2.expires_ms);
    try testing.expectEqual(@as(?track.Location, null), s2.largest);
}

test "REQUEST_OK round-trip with parameters" {
    var buf: [64]u8 = undefined;
    var fbs = io.fixedBufferStream(&buf);
    const params = [_]Param{
        .{ .type = ParamType.EXPIRES, .value = .{ .varint = 9 } },
        .{ .type = ParamType.LARGEST_OBJECT, .value = .{ .location = .{ .group = 2, .object = 5 } } },
    };
    try writeRequestOk(&fbs, .{ .params = &params });
    const p = try parseEnvelope(buf[0..fbs.seek]);
    try testing.expectEqual(codes.MSG_REQUEST_OK, p.env.type);
    var out: [MAX_PARAMS]Param = undefined;
    const r = try decodeRequestOk(p.env.payload, &out);
    try testing.expectEqual(@as(usize, 2), r.params.len);
    try testing.expectEqual(@as(u64, 9), r.params[0].value.varint);
    try testing.expectEqual(@as(u64, 5), r.params[1].value.location.object);
}

test "REQUEST_UPDATE round-trip" {
    var buf: [128]u8 = undefined;
    var fbs = io.fixedBufferStream(&buf);
    try writeRequestUpdate(&fbs, .{
        .request_id = 4,
        .subscriber_priority = 7,
        .forward = false,
        .filter = .{ .type = .next_group_start },
    }, .draft_17);
    const p = try parseEnvelope(buf[0..fbs.seek]);
    const u = try decodeRequestUpdate(p.env.payload, .draft_17);
    try testing.expectEqual(@as(u64, 4), u.request_id);
    try testing.expectEqual(@as(u8, 7), u.subscriber_priority.?);
    try testing.expect(!u.forward.?);
    try testing.expectEqual(track.FilterType.next_group_start, u.filter.?.type);
}

test "PUBLISH round-trip" {
    var buf: [256]u8 = undefined;
    var fbs = io.fixedBufferStream(&buf);
    const ns = [_][]const u8{ "moq", "demo" };
    try writePublish(&fbs, .{
        .request_id = 1,
        .track_namespace = &ns,
        .track_name = "video",
        .track_alias = 7,
        .forward = true,
        .largest = .{ .group = 3, .object = 1 },
    }, .draft_17);
    const p = try parseEnvelope(buf[0..fbs.seek]);
    try testing.expectEqual(codes.MSG_PUBLISH, p.env.type);
    var ns_buf: NamespaceBuf = undefined;
    const pub_ = try decodePublish(p.env.payload, &ns_buf, .draft_17);
    try testing.expectEqual(@as(u64, 1), pub_.request_id);
    try testing.expectEqual(@as(usize, 2), pub_.track_namespace.len);
    try testing.expectEqualStrings("video", pub_.track_name);
    try testing.expectEqual(@as(u64, 7), pub_.track_alias);
    try testing.expect(pub_.forward.?);
    try testing.expectEqual(@as(u64, 3), pub_.largest.?.group);
}

test "PUBLISH_OK is parameters only" {
    var buf: [64]u8 = undefined;
    var fbs = io.fixedBufferStream(&buf);
    try writePublishOk(&fbs, .{ .forward = true, .subscriber_priority = 9 }, .draft_17);
    const p = try parseEnvelope(buf[0..fbs.seek]);
    const ok = try decodePublishOk(p.env.payload);
    try testing.expect(ok.forward.?);
    try testing.expectEqual(@as(u8, 9), ok.subscriber_priority.?);

    var buf2: [64]u8 = undefined;
    var fbs2 = io.fixedBufferStream(&buf2);
    try writePublishOk(&fbs2, .{}, .draft_17);
    const p2 = try parseEnvelope(buf2[0..fbs2.seek]);
    try testing.expectEqualSlices(u8, &.{0x00}, p2.env.payload); // just count=0
}

test "PUBLISH_DONE carries the stream count" {
    var buf: [128]u8 = undefined;
    var fbs = io.fixedBufferStream(&buf);
    try writePublishDone(&fbs, .{ .status_code = 4, .stream_count = 12, .reason = "publisher gone" });
    const p = try parseEnvelope(buf[0..fbs.seek]);
    const d = try decodePublishDone(p.env.payload);
    try testing.expectEqual(@as(u64, 4), d.status_code);
    try testing.expectEqual(@as(u64, 12), d.stream_count);
    try testing.expectEqualStrings("publisher gone", d.reason);
}

test "standalone FETCH round-trip" {
    var buf: [256]u8 = undefined;
    var fbs = io.fixedBufferStream(&buf);
    const ns = [_][]const u8{"moq"};
    try writeFetch(&fbs, .{
        .request_id = 2,
        .body = .{ .standalone = .{
            .track_namespace = &ns,
            .track_name = "video",
            .start = .{ .group = 1, .object = 2 },
            .end = .{ .group = 9, .object = 0 },
        } },
        .subscriber_priority = 3,
        .group_order = .ascending,
    }, .draft_17);
    const p = try parseEnvelope(buf[0..fbs.seek]);
    var ns_buf: NamespaceBuf = undefined;
    const f = try decodeFetch(p.env.payload, &ns_buf, .draft_17);
    try testing.expectEqual(@as(u64, 2), f.request_id);
    try testing.expectEqualStrings("video", f.body.standalone.track_name);
    try testing.expectEqual(@as(u64, 1), f.body.standalone.start.group);
    try testing.expectEqual(@as(u64, 9), f.body.standalone.end.group);
    try testing.expectEqual(@as(u8, 3), f.subscriber_priority.?);
    try testing.expectEqual(track.GroupOrder.ascending, f.group_order.?);
}

test "joining FETCH round-trip" {
    var buf: [128]u8 = undefined;
    var fbs = io.fixedBufferStream(&buf);
    try writeFetch(&fbs, .{
        .request_id = 5,
        .body = .{ .relative_joining = .{ .joining_request_id = 3, .joining_start = 2 } },
    }, .draft_17);
    const p = try parseEnvelope(buf[0..fbs.seek]);
    var ns_buf: NamespaceBuf = undefined;
    const f = try decodeFetch(p.env.payload, &ns_buf, .draft_17);
    try testing.expectEqual(FetchType.relative_joining, std.meta.activeTag(f.body));
    try testing.expectEqual(@as(u64, 3), f.body.relative_joining.joining_request_id);
    try testing.expectEqual(@as(u64, 2), f.body.relative_joining.joining_start);
}

test "FETCH_OK round-trip" {
    var buf: [64]u8 = undefined;
    var fbs = io.fixedBufferStream(&buf);
    try writeFetchOk(&fbs, .{
        .end_of_track = true,
        .end = .{ .group = 12, .object = 4 },
        .expires_ms = 30,
    });
    const p = try parseEnvelope(buf[0..fbs.seek]);
    const f = try decodeFetchOk(p.env.payload);
    try testing.expect(f.end_of_track);
    try testing.expectEqual(@as(u64, 12), f.end.group);
    try testing.expectEqual(@as(u64, 30), f.expires_ms.?);
}

test "TRACK_STATUS has the SUBSCRIBE shape under its own type" {
    var buf: [256]u8 = undefined;
    var fbs = io.fixedBufferStream(&buf);
    const ns = [_][]const u8{"moq"};
    try writeTrackStatus(&fbs, .{ .request_id = 8, .track_namespace = &ns, .track_name = "audio" }, .draft_17);
    const p = try parseEnvelope(buf[0..fbs.seek]);
    try testing.expectEqual(codes.MSG_TRACK_STATUS, p.env.type);
    var ns_buf: NamespaceBuf = undefined;
    const t = try decodeTrackStatus(p.env.payload, &ns_buf, .draft_17);
    try testing.expectEqual(@as(u64, 8), t.request_id);
    try testing.expectEqualStrings("audio", t.track_name);
}

test "PUBLISH_NAMESPACE has the request id, delta and parameter count" {
    var buf: [128]u8 = undefined;
    var fbs = io.fixedBufferStream(&buf);
    const ns = [_][]const u8{ "moq-test", "interop" };
    try writePublishNamespace(&fbs, .{ .request_id = 0, .track_namespace = &ns }, .draft_17);
    const p = try parseEnvelope(buf[0..fbs.seek]);

    // request_id=0, delta=0, tuple count=2, "moq-test", "interop", params=0.
    const body = p.env.payload;
    try testing.expectEqual(@as(u8, 0), body[0]);
    try testing.expectEqual(@as(u8, 0), body[1]);
    try testing.expectEqual(@as(u8, 2), body[2]);
    try testing.expectEqual(@as(u8, 0), body[body.len - 1]);

    var ns_buf: NamespaceBuf = undefined;
    const pn = try decodePublishNamespace(body, &ns_buf, .draft_17);
    try testing.expectEqual(@as(usize, 2), pn.track_namespace.len);
    try testing.expectEqualStrings("interop", pn.track_namespace[1]);
}

test "SUBSCRIBE_NAMESPACE carries its subscribe options" {
    var buf: [128]u8 = undefined;
    var fbs = io.fixedBufferStream(&buf);
    const ns = [_][]const u8{"moq"};
    try writeSubscribeNamespace(&fbs, .{
        .request_id = 1,
        .track_namespace_prefix = &ns,
        .options = .namespace,
        .forward = true,
    }, .draft_17);
    const p = try parseEnvelope(buf[0..fbs.seek]);
    var ns_buf: NamespaceBuf = undefined;
    const s = try decodeSubscribeNamespace(p.env.payload, &ns_buf, .draft_17);
    try testing.expectEqual(@as(u64, 1), s.request_id);
    try testing.expectEqual(SubscribeOptions.namespace, s.options);
    try testing.expect(s.forward.?);
    try testing.expectEqualStrings("moq", s.track_namespace_prefix[0]);
}

test "NAMESPACE and NAMESPACE_DONE both carry the suffix" {
    const ns = [_][]const u8{"live"};
    var ns_buf: NamespaceBuf = undefined;

    var buf: [128]u8 = undefined;
    var fbs = io.fixedBufferStream(&buf);
    try writeNamespace(&fbs, .{ .track_namespace_suffix = &ns });
    const p = try parseEnvelope(buf[0..fbs.seek]);
    try testing.expectEqual(codes.MSG_NAMESPACE, p.env.type);
    try testing.expectEqualStrings("live", (try decodeNamespace(p.env.payload, &ns_buf)).track_namespace_suffix[0]);

    var buf2: [128]u8 = undefined;
    var fbs2 = io.fixedBufferStream(&buf2);
    try writeNamespaceDone(&fbs2, .{ .track_namespace_suffix = &ns });
    const p2 = try parseEnvelope(buf2[0..fbs2.seek]);
    try testing.expectEqual(codes.MSG_NAMESPACE_DONE, p2.env.type);
    try testing.expectEqualStrings("live", (try decodeNamespaceDone(p2.env.payload, &ns_buf)).track_namespace_suffix[0]);
}

test "PUBLISH_BLOCKED names the track it could not publish" {
    var buf: [128]u8 = undefined;
    var fbs = io.fixedBufferStream(&buf);
    const ns = [_][]const u8{"room"};
    try writePublishBlocked(&fbs, .{ .track_namespace_suffix = &ns, .track_name = "video" });
    const p = try parseEnvelope(buf[0..fbs.seek]);
    var ns_buf: NamespaceBuf = undefined;
    const b = try decodePublishBlocked(p.env.payload, &ns_buf);
    try testing.expectEqualStrings("room", b.track_namespace_suffix[0]);
    try testing.expectEqualStrings("video", b.track_name);
}

test "decoded namespace outlives the decode call" {
    // Regression: decodeSubscribe used to return a slice into its own frame.
    const ns = [_][]const u8{ "alpha", "beta", "gamma" };
    var buf: [256]u8 = undefined;
    var fbs = io.fixedBufferStream(&buf);
    try writeSubscribe(&fbs, .{ .track_namespace = &ns, .track_name = "t" }, .draft_17);
    const p = try parseEnvelope(buf[0..fbs.seek]);

    var ns_buf: NamespaceBuf = undefined;
    const sub = try decodeSubscribe(p.env.payload, &ns_buf, .draft_17);

    var scratch: [wire.MAX_TUPLE_PARTS][]const u8 = undefined;
    for (&scratch) |*e| e.* = "xxxxx";
    std.mem.doNotOptimizeAway(&scratch);

    try testing.expectEqual(@as(usize, 3), sub.track_namespace.len);
    try testing.expectEqualStrings("alpha", sub.track_namespace[0]);
    try testing.expectEqualStrings("gamma", sub.track_namespace[2]);
}

// --- draft-18 ---------------------------------------------------------
//
// The delta is small but load-bearing: a draft-17 reader on a draft-18
// message reads every field one varint late.

test "draft-18 drops Required Request ID Delta from SUBSCRIBE" {
    const ns = [_][]const u8{"moq"};
    var b17: [256]u8 = undefined;
    var f17 = io.fixedBufferStream(&b17);
    try writeSubscribe(&f17, .{ .request_id = 5, .track_namespace = &ns, .track_name = "v" }, .draft_17);

    var b18: [256]u8 = undefined;
    var f18 = io.fixedBufferStream(&b18);
    try writeSubscribe(&f18, .{ .request_id = 5, .track_namespace = &ns, .track_name = "v" }, .draft_18);

    // One varint shorter, and the tuple starts where the delta was.
    try testing.expectEqual(f17.seek - 1, f18.seek);
    const p18 = try parseEnvelope(b18[0..f18.seek]);
    try testing.expectEqual(@as(u8, 5), p18.env.payload[0]);
    try testing.expectEqual(@as(u8, 1), p18.env.payload[1]); // tuple count

    var ns_buf: NamespaceBuf = undefined;
    const s18 = try decodeSubscribe(p18.env.payload, &ns_buf, .draft_18);
    try testing.expectEqual(@as(u64, 5), s18.request_id);
    try testing.expectEqualStrings("v", s18.track_name);
    try testing.expectEqualStrings("moq", s18.track_namespace[0]);
}

test "reading a draft-18 message as draft-17 does not quietly succeed" {
    const ns = [_][]const u8{ "moq", "demo" };
    var buf: [256]u8 = undefined;
    var fbs = io.fixedBufferStream(&buf);
    try writeSubscribe(&fbs, .{ .request_id = 1, .track_namespace = &ns, .track_name = "video" }, .draft_18);
    const p = try parseEnvelope(buf[0..fbs.seek]);

    var ns_buf: NamespaceBuf = undefined;
    const wrong = decodeSubscribe(p.env.payload, &ns_buf, .draft_17);
    // Whatever it does, it must not produce the right answer by accident.
    if (wrong) |s| {
        try testing.expect(!std.mem.eql(u8, s.track_name, "video"));
    } else |_| {}
}

test "draft-18 moves SUBSCRIBE_NAMESPACE and splits off SUBSCRIBE_TRACKS" {
    const ns = [_][]const u8{"moq"};
    var buf: [256]u8 = undefined;

    var f17 = io.fixedBufferStream(&buf);
    try writeSubscribeNamespace(&f17, .{ .track_namespace_prefix = &ns }, .draft_17);
    try testing.expectEqual(codes.MSG_SUBSCRIBE_NAMESPACE, (try parseEnvelope(buf[0..f17.seek])).env.type);

    var b18: [256]u8 = undefined;
    var f18 = io.fixedBufferStream(&b18);
    try writeSubscribeNamespace(&f18, .{ .track_namespace_prefix = &ns }, .draft_18);
    const p18 = try parseEnvelope(b18[0..f18.seek]);
    try testing.expectEqual(codes.MSG_SUBSCRIBE_NAMESPACE_18, p18.env.type);

    var bt: [256]u8 = undefined;
    var ft = io.fixedBufferStream(&bt);
    try writeSubscribeTracks(&ft, .{ .track_namespace_prefix = &ns }, .draft_18);
    try testing.expectEqual(codes.MSG_SUBSCRIBE_TRACKS, (try parseEnvelope(bt[0..ft.seek])).env.type);

    // draft-17 has one message for both, so there is nothing to write.
    var bx: [256]u8 = undefined;
    var fx = io.fixedBufferStream(&bx);
    try testing.expectError(
        Error.UnknownMessageType,
        writeSubscribeTracks(&fx, .{ .track_namespace_prefix = &ns }, .draft_17),
    );

    var ns_buf: NamespaceBuf = undefined;
    const back = try decodeSubscribeNamespace(p18.env.payload, &ns_buf, .draft_18);
    try testing.expectEqualStrings("moq", back.track_namespace_prefix[0]);
}

test "draft-18 answers PUBLISH with REQUEST_OK" {
    var b17: [64]u8 = undefined;
    var f17 = io.fixedBufferStream(&b17);
    try writePublishOk(&f17, .{}, .draft_17);
    try testing.expectEqual(codes.MSG_PUBLISH_OK, (try parseEnvelope(b17[0..f17.seek])).env.type);

    var b18: [64]u8 = undefined;
    var f18 = io.fixedBufferStream(&b18);
    try writePublishOk(&f18, .{}, .draft_18);
    try testing.expectEqual(codes.MSG_REQUEST_OK, (try parseEnvelope(b18[0..f18.seek])).env.type);
}

test "draft-18 request messages round-trip" {
    const ns = [_][]const u8{ "moq", "demo" };
    var ns_buf: NamespaceBuf = undefined;
    var buf: [512]u8 = undefined;

    var f = io.fixedBufferStream(&buf);
    try writePublishNamespace(&f, .{ .request_id = 2, .track_namespace = &ns }, .draft_18);
    const pn = try decodePublishNamespace((try parseEnvelope(buf[0..f.seek])).env.payload, &ns_buf, .draft_18);
    try testing.expectEqual(@as(u64, 2), pn.request_id);
    try testing.expectEqual(@as(usize, 2), pn.track_namespace.len);

    f = io.fixedBufferStream(&buf);
    try writePublish(&f, .{
        .request_id = 3,
        .track_namespace = &ns,
        .track_name = "video",
        .track_alias = 4,
    }, .draft_18);
    const pb = try decodePublish((try parseEnvelope(buf[0..f.seek])).env.payload, &ns_buf, .draft_18);
    try testing.expectEqual(@as(u64, 3), pb.request_id);
    try testing.expectEqual(@as(u64, 4), pb.track_alias);

    f = io.fixedBufferStream(&buf);
    try writeFetch(&f, .{
        .request_id = 6,
        .body = .{ .relative_joining = .{ .joining_request_id = 1, .joining_start = 2 } },
    }, .draft_18);
    const fe = try decodeFetch((try parseEnvelope(buf[0..f.seek])).env.payload, &ns_buf, .draft_18);
    try testing.expectEqual(@as(u64, 6), fe.request_id);
    try testing.expectEqual(@as(u64, 1), fe.body.relative_joining.joining_request_id);

    f = io.fixedBufferStream(&buf);
    try writeRequestUpdate(&f, .{ .request_id = 7, .subscriber_priority = 9 }, .draft_18);
    const ru = try decodeRequestUpdate((try parseEnvelope(buf[0..f.seek])).env.payload, .draft_18);
    try testing.expectEqual(@as(u64, 7), ru.request_id);
    try testing.expectEqual(@as(u8, 9), ru.subscriber_priority.?);
}
