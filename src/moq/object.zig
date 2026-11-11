// Object-delivery framing for MoQ Transport draft-17.
//
// Three carriers:
//   - Subgroup streams (§10.4.2) — unidirectional QUIC stream; one
//     subgroup per stream with a shared header, then a sequence of
//     object records.
//   - Fetch streams (§10.4.4) — unidirectional QUIC stream carrying
//     ordered object records in response to a FETCH request.
//   - Object datagrams (§10.3.1) — single object in a QUIC DATAGRAM.
//
// This module encodes/decodes headers only; payload bytes are opaque.

const std = @import("std");
const io = @import("../io_compat.zig");
const testing = std.testing;

const wire = @import("wire.zig");
const codes = @import("message_codes.zig");
const track = @import("track.zig");
const version = @import("version.zig");

pub const Error = error{
    InvalidStreamType,
    InvalidDatagramType,
    ReservedSubgroupMode,
    InvalidObjectHeader,
} || wire.Error;

// ---------------- Subgroup streams ----------------

pub const SubgroupHeader = struct {
    track_alias: track.TrackAlias,
    group: track.GroupId,
    // null → implicit from flags (either 0 or equal to first object id).
    subgroup: ?track.SubgroupId,
    // null → DEFAULT_PRIORITY bit set; subscriber inherits from control.
    publisher_priority: ?track.Priority,
    end_of_group: bool,
    // Whether each Object carries a Properties (KV list) field.
    per_object_properties: bool,
    // §2.2: set when this stream starts at the first Object ever published in
    // the subgroup. An original publisher opening a new subgroup MUST set it,
    // and so MUST a relay forwarding such a subgroup on. draft-18 only.
    first_object: bool = false,
};

fn subgroupIdMode(h: SubgroupHeader, first_object: ?track.ObjectId) codes.SubgroupIdMode {
    const sg = h.subgroup orelse return .first_object; // safe fallback
    if (sg == 0) return .zero;
    if (first_object) |fo| if (fo == sg) return .first_object;
    return .explicit;
}

pub fn writeSubgroupHeader(writer: anytype, h: SubgroupHeader, draft: version.Draft) !void {
    var flags: u64 = codes.SUBGROUP_BIT_SELECTOR;
    if (h.per_object_properties) flags |= codes.SUBGROUP_BIT_PROPERTIES;
    if (h.end_of_group) flags |= codes.SUBGROUP_BIT_END_OF_GROUP;
    if (h.publisher_priority == null) flags |= codes.SUBGROUP_BIT_DEFAULT_PRIORITY;
    if (h.first_object and version.Rules.of(draft).subgroup_first_object_bit) {
        flags |= codes.SUBGROUP_BIT_FIRST_OBJECT;
    }

    // Encode subgroup id mode. Without knowledge of the first object
    // we can't use .first_object; pick .zero when sg is 0, else .explicit.
    const mode: codes.SubgroupIdMode = if (h.subgroup) |sg|
        (if (sg == 0) .zero else .explicit)
    else
        .first_object;
    flags |= (@as(u64, @backingInt(mode)) << 1);

    try wire.writeVarInt(writer, flags);
    try wire.writeVarInt(writer, h.track_alias);
    try wire.writeVarInt(writer, h.group);
    if (mode == .explicit) try wire.writeVarInt(writer, h.subgroup.?);
    if (h.publisher_priority) |p| try writer.writeByte(p);
}

pub const ParsedSubgroupHeader = struct {
    header: SubgroupHeader,
    id_mode: codes.SubgroupIdMode,
};

pub fn readSubgroupHeader(fbs: *io.FixedBufferStream([]const u8), draft: version.Draft) !ParsedSubgroupHeader {
    const reader = fbs;
    const flags = try wire.readVarInt(reader);
    if (!codes.isSubgroupStreamType(flags, version.Rules.of(draft).subgroup_first_object_bit)) {
        return Error.InvalidStreamType;
    }

    const mode_bits: u2 = @truncate((flags & codes.SUBGROUP_MASK_ID_MODE) >> 1);
    const id_mode: codes.SubgroupIdMode = @fromBackingInt(@intCast(mode_bits));
    if (id_mode == .reserved) return Error.ReservedSubgroupMode;

    const alias = try wire.readVarInt(reader);
    const group = try wire.readVarInt(reader);

    var subgroup: ?track.SubgroupId = null;
    switch (id_mode) {
        .zero => subgroup = 0,
        .first_object => subgroup = null,
        .explicit => subgroup = try wire.readVarInt(reader),
        .reserved => unreachable,
    }

    const pri: ?track.Priority = if ((flags & codes.SUBGROUP_BIT_DEFAULT_PRIORITY) != 0)
        null
    else
        reader.takeByte() catch return wire.Error.BufferTooShort;

    return .{
        .header = .{
            .track_alias = alias,
            .group = group,
            .subgroup = subgroup,
            .publisher_priority = pri,
            .end_of_group = (flags & codes.SUBGROUP_BIT_END_OF_GROUP) != 0,
            .per_object_properties = (flags & codes.SUBGROUP_BIT_PROPERTIES) != 0,
            .first_object = (flags & codes.SUBGROUP_BIT_FIRST_OBJECT) != 0,
        },
        .id_mode = id_mode,
    };
}

/// One object on a subgroup stream (§11.4.2, draft-17 §10.4.2 alike).
/// Properties are kept as the raw KV bytes; nothing here interprets them.
pub const SubgroupObject = struct {
    id: track.ObjectId,
    properties: []const u8 = &.{},
    /// Only on the wire when the payload is empty; 0 is Normal.
    status: u64 = 0,
    payload: []const u8 = &.{},
};

/// `prev` is the previous object's ID on this stream, null for the first:
/// the wire carries `id - prev - 1`, so a run of consecutive IDs is all 0s.
pub fn writeSubgroupObject(writer: anytype, o: SubgroupObject, prev: ?track.ObjectId, with_properties: bool) !void {
    const delta = if (prev) |p| blk: {
        if (o.id <= p) return Error.InvalidObjectHeader;
        break :blk o.id - p - 1;
    } else o.id;
    try wire.writeVarInt(writer, delta);
    if (with_properties) {
        try wire.writeVarInt(writer, o.properties.len);
        try writer.writeAll(o.properties);
    }
    try wire.writeVarInt(writer, o.payload.len);
    if (o.payload.len == 0) try wire.writeVarInt(writer, o.status);
    try writer.writeAll(o.payload);
}

pub const ReadObject = struct { object: SubgroupObject, consumed: usize };

/// Reads the object at the front of `data`, or null while it is still
/// arriving. `with_properties` is the header's PROPERTIES bit.
pub fn readSubgroupObject(data: []const u8, prev: ?track.ObjectId, with_properties: bool) !?ReadObject {
    var fbs = io.fixedBufferStream(data);
    const delta = wire.readVarInt(&fbs) catch |e| return partial(e);
    const id = if (prev) |p| std.math.add(u64, p, delta +| 1) catch return Error.InvalidObjectHeader else delta;
    var properties: []const u8 = &.{};
    if (with_properties) {
        const len = wire.readVarInt(&fbs) catch |e| return partial(e);
        if (len > data.len - fbs.seek) return null;
        properties = data[fbs.seek..][0..@intCast(len)];
        fbs.seek += @intCast(len);
    }
    const payload_len = wire.readVarInt(&fbs) catch |e| return partial(e);
    var status: u64 = 0;
    if (payload_len == 0) status = wire.readVarInt(&fbs) catch |e| return partial(e);
    if (payload_len > data.len - fbs.seek) return null;
    const payload = data[fbs.seek..][0..@intCast(payload_len)];
    return .{
        .object = .{ .id = id, .properties = properties, .status = status, .payload = payload },
        .consumed = fbs.seek + payload.len,
    };
}

fn partial(e: anyerror) !?ReadObject {
    return if (e == wire.Error.BufferTooShort) null else e;
}

// ---------------- Datagram objects ----------------

pub const DatagramObject = struct {
    track_alias: track.TrackAlias,
    group: track.GroupId,
    // null when ZERO_OBJECT_ID set (object id is 0).
    object: ?track.ObjectId,
    publisher_priority: ?track.Priority,
    end_of_group: bool,
    // Either payload bytes OR a status value (mutually exclusive on the wire).
    body: union(enum) {
        payload: []const u8,
        status: track.ObjectStatus,
    },
};

pub fn writeDatagramObject(writer: anytype, obj: DatagramObject) !void {
    var flags: u64 = 0;
    if (obj.end_of_group) flags |= codes.DGRAM_BIT_END_OF_GROUP;
    if (obj.object == null) flags |= codes.DGRAM_BIT_ZERO_OBJECT_ID;
    if (obj.publisher_priority == null) flags |= codes.DGRAM_BIT_DEFAULT_PRIORITY;
    switch (obj.body) {
        .status => flags |= codes.DGRAM_BIT_STATUS,
        .payload => {},
    }
    if (!codes.isDatagramObjectType(flags)) return Error.InvalidDatagramType;

    try wire.writeVarInt(writer, flags);
    try wire.writeVarInt(writer, obj.track_alias);
    try wire.writeVarInt(writer, obj.group);
    if (obj.object) |oid| try wire.writeVarInt(writer, oid);
    if (obj.publisher_priority) |p| try writer.writeByte(p);
    switch (obj.body) {
        .status => |s| try wire.writeVarInt(writer, @backingInt(s)),
        .payload => |p| try writer.writeAll(p),
    }
}

pub fn readDatagramObject(data: []const u8) !DatagramObject {
    var fbs = io.fixedBufferStream(data);
    const reader = &fbs;
    const flags = try wire.readVarInt(reader);
    if (!codes.isDatagramObjectType(flags)) return Error.InvalidDatagramType;

    const alias = try wire.readVarInt(reader);
    const group = try wire.readVarInt(reader);
    const object: ?track.ObjectId = if ((flags & codes.DGRAM_BIT_ZERO_OBJECT_ID) != 0)
        null
    else
        try wire.readVarInt(reader);
    const pri: ?track.Priority = if ((flags & codes.DGRAM_BIT_DEFAULT_PRIORITY) != 0)
        null
    else
        reader.takeByte() catch return wire.Error.BufferTooShort;

    const body: @FieldType(DatagramObject, "body") = if ((flags & codes.DGRAM_BIT_STATUS) != 0) blk: {
        const raw = try wire.readVarInt(reader);
        const s = track.ObjectStatus.fromInt(raw) orelse return Error.InvalidObjectHeader;
        break :blk .{ .status = s };
    } else .{
        .payload = data[fbs.seek..],
    };

    return .{
        .track_alias = alias,
        .group = group,
        .object = object,
        .publisher_priority = pri,
        .end_of_group = (flags & codes.DGRAM_BIT_END_OF_GROUP) != 0,
        .body = body,
    };
}

// ---------------- Fetch stream ----------------

pub fn writeFetchStreamHeader(writer: anytype, request_id: track.RequestId) !void {
    try wire.writeVarInt(writer, codes.STREAM_FETCH);
    try wire.writeVarInt(writer, request_id);
}

pub fn readFetchStreamHeader(fbs: *io.FixedBufferStream([]const u8)) !track.RequestId {
    const reader = fbs;
    const t = try wire.readVarInt(reader);
    if (t != codes.STREAM_FETCH) return Error.InvalidStreamType;
    return try wire.readVarInt(reader);
}

/// One object on a FETCH stream (§11.4.1).
pub const FetchObject = struct {
    group: track.GroupId,
    /// Null for an object that was sent as a datagram.
    subgroup: ?u64 = 0,
    id: track.ObjectId,
    publisher_priority: track.Priority = 128,
    /// The raw KV bytes; null leaves the field off the wire.
    properties: ?[]const u8 = null,
    payload: []const u8 = &.{},
};

/// What an End of Range says about the Locations it closes (Table 8).
pub const FetchRangeKind = enum(u64) {
    does_not_exist = 0x8C,
    unknown = 0x10C,
    timed_out = 0x20C,
};

pub const FetchItem = union(enum) {
    object: FetchObject,
    /// Every Location after the prior item, up to and including this one.
    end_of_range: struct { kind: FetchRangeKind, at: track.Location },
};

const FETCH_SUBGROUP_MASK: u64 = 0x03;
const FETCH_OBJECT_ID: u64 = 0x04;
const FETCH_GROUP_ID: u64 = 0x08;
const FETCH_PRIORITY: u64 = 0x10;
const FETCH_PROPERTIES: u64 = 0x20;
const FETCH_DATAGRAM: u64 = 0x40;

/// The prior item on one FETCH stream, which the next is encoded against.
pub const FetchCursor = struct {
    deltas: bool,
    descending: bool = false,
    at: ?track.Location = null,
    /// From the last actual object: an End of Range carries neither.
    subgroup: ?u64 = null,
    priority: ?track.Priority = null,

    pub fn init(draft: version.Draft, descending: bool) FetchCursor {
        return .{ .deltas = version.Rules.of(draft).fetch_id_deltas, .descending = descending };
    }

    const Ids = struct { flags: u64, group: ?u64 = null, object: ?u64 = null };

    fn encodeIds(self: *const FetchCursor, at: track.Location) !Ids {
        const all: Ids = .{ .flags = FETCH_GROUP_ID | FETCH_OBJECT_ID, .group = at.group, .object = at.object };
        const p = self.at orelse return all;
        if (!self.deltas) {
            if (at.group != p.group) return all;
            if (at.object <= p.object) return Error.InvalidObjectHeader;
            if (at.object == p.object + 1) return .{ .flags = 0 };
            return .{ .flags = FETCH_OBJECT_ID, .object = at.object };
        }
        if (at.group != p.group) {
            const step = if (self.descending) std.math.sub(u64, p.group, at.group) else std.math.sub(u64, at.group, p.group);
            const s = step catch return Error.InvalidObjectHeader;
            return .{ .flags = FETCH_GROUP_ID | FETCH_OBJECT_ID, .group = s - 1, .object = at.object };
        }
        if (at.object <= p.object) return Error.InvalidObjectHeader;
        if (at.object == p.object + 1) return .{ .flags = 0 };
        return .{ .flags = FETCH_OBJECT_ID, .object = at.object - p.object };
    }

    fn decodeIds(self: *const FetchCursor, group: ?u64, object: ?u64) !track.Location {
        const p = self.at orelse {
            // §11.4.1.1: the first item carries both, as absolute values.
            return .{ .group = group orelse return Error.InvalidObjectHeader, .object = object orelse return Error.InvalidObjectHeader };
        };
        const overflow = Error.InvalidObjectHeader;
        if (!self.deltas) return .{
            .group = group orelse p.group,
            .object = object orelse (std.math.add(u64, p.object, 1) catch return overflow),
        };
        if (group) |d| {
            const step = std.math.add(u64, d, 1) catch return overflow;
            const g = if (self.descending) std.math.sub(u64, p.group, step) else std.math.add(u64, p.group, step);
            return .{
                .group = g catch return overflow,
                .object = object orelse (std.math.add(u64, p.object, 1) catch return overflow),
            };
        }
        return .{
            .group = p.group,
            .object = std.math.add(u64, p.object, object orelse 1) catch return overflow,
        };
    }
};

pub fn writeFetchItem(writer: anytype, item: FetchItem, c: *FetchCursor) !void {
    try writeFetchItemHead(writer, item, c);
    switch (item) {
        .object => |o| try writer.writeAll(o.payload),
        .end_of_range => {},
    }
}

/// All of the item but an object's payload bytes, which the caller sends
/// next: a relay can hand them on from its cache without a copy.
pub fn writeFetchItemHead(writer: anytype, item: FetchItem, c: *FetchCursor) !void {
    switch (item) {
        .end_of_range => |r| {
            // Its Group ID Delta always moves on a group, so a range can't
            // end inside the prior object's.
            if (c.deltas) if (c.at) |p| if (r.at.group == p.group) return Error.InvalidObjectHeader;
            const ids = try c.encodeIds(r.at);
            try wire.writeVarInt(writer, @backingInt(r.kind));
            // Both fields are on the wire: the kind's value has both bits.
            try wire.writeVarInt(writer, ids.group orelse 0);
            try wire.writeVarInt(writer, ids.object orelse r.at.object);
            c.at = r.at;
        },
        .object => |o| {
            const at: track.Location = .{ .group = o.group, .object = o.id };
            const ids = try c.encodeIds(at);
            var flags = ids.flags;
            var subgroup_field: ?u64 = null;
            if (o.subgroup) |sg| {
                if (sg == 0) {} else if (c.subgroup != null and c.subgroup.? == sg) {
                    flags |= 0x01;
                } else if (c.subgroup != null and c.subgroup.? +% 1 == sg) {
                    flags |= 0x02;
                } else {
                    flags |= 0x03;
                    subgroup_field = sg;
                }
            } else flags |= FETCH_DATAGRAM;
            const new_priority = c.priority == null or c.priority.? != o.publisher_priority;
            if (new_priority) flags |= FETCH_PRIORITY;
            if (o.properties != null) flags |= FETCH_PROPERTIES;

            try wire.writeVarInt(writer, flags);
            if (ids.group) |g| try wire.writeVarInt(writer, g);
            if (subgroup_field) |sg| try wire.writeVarInt(writer, sg);
            if (ids.object) |v| try wire.writeVarInt(writer, v);
            if (new_priority) try writer.writeByte(o.publisher_priority);
            if (o.properties) |p| {
                try wire.writeVarInt(writer, p.len);
                try writer.writeAll(p);
            }
            try wire.writeVarInt(writer, o.payload.len);
            c.at = at;
            c.subgroup = o.subgroup;
            c.priority = o.publisher_priority;
        },
    }
}

pub const ReadFetchItem = struct { item: FetchItem, consumed: usize };

/// Reads the item at the front of `data`, or null while it is still
/// arriving; `c` moves on only past a whole item.
pub fn readFetchItem(data: []const u8, c: *FetchCursor) !?ReadFetchItem {
    var fbs = io.fixedBufferStream(data);
    const flags = wire.readVarInt(&fbs) catch |e| return partialFetch(e);
    if (flags >= 128) {
        const kind: FetchRangeKind = switch (flags) {
            0x8C => .does_not_exist,
            0x10C => .unknown,
            0x20C => .timed_out,
            else => return Error.InvalidObjectHeader,
        };
        const g = wire.readVarInt(&fbs) catch |e| return partialFetch(e);
        const o = wire.readVarInt(&fbs) catch |e| return partialFetch(e);
        const at = try c.decodeIds(g, o);
        c.at = at;
        return .{ .item = .{ .end_of_range = .{ .kind = kind, .at = at } }, .consumed = fbs.seek };
    }
    const group: ?u64 = if (flags & FETCH_GROUP_ID != 0) wire.readVarInt(&fbs) catch |e| return partialFetch(e) else null;
    var subgroup: ?u64 = null;
    if (flags & FETCH_DATAGRAM == 0) switch (flags & FETCH_SUBGROUP_MASK) {
        0 => subgroup = 0,
        1 => subgroup = c.subgroup orelse return Error.InvalidObjectHeader,
        2 => subgroup = std.math.add(u64, c.subgroup orelse return Error.InvalidObjectHeader, 1) catch return Error.InvalidObjectHeader,
        else => subgroup = wire.readVarInt(&fbs) catch |e| return partialFetch(e),
    };
    const object: ?u64 = if (flags & FETCH_OBJECT_ID != 0) wire.readVarInt(&fbs) catch |e| return partialFetch(e) else null;
    const priority: track.Priority = if (flags & FETCH_PRIORITY != 0)
        fbs.takeByte() catch return null
    else
        c.priority orelse return Error.InvalidObjectHeader;
    var properties: ?[]const u8 = null;
    if (flags & FETCH_PROPERTIES != 0) {
        const len = wire.readVarInt(&fbs) catch |e| return partialFetch(e);
        if (len > data.len - fbs.seek) return null;
        properties = data[fbs.seek..][0..@intCast(len)];
        fbs.seek += @intCast(len);
    }
    const payload_len = wire.readVarInt(&fbs) catch |e| return partialFetch(e);
    if (payload_len > data.len - fbs.seek) return null;
    const payload = data[fbs.seek..][0..@intCast(payload_len)];

    const at = try c.decodeIds(group, object);
    c.at = at;
    c.subgroup = subgroup;
    c.priority = priority;
    return .{
        .item = .{ .object = .{
            .group = at.group,
            .subgroup = subgroup,
            .id = at.object,
            .publisher_priority = priority,
            .properties = properties,
            .payload = payload,
        } },
        .consumed = fbs.seek + payload.len,
    };
}

fn partialFetch(e: anyerror) !?ReadFetchItem {
    return if (e == wire.Error.BufferTooShort) null else e;
}

// Tests

test "subgroup header round-trip — explicit subgroup with priority" {
    var buf: [32]u8 = undefined;
    var fbs = io.fixedBufferStream(&buf);
    const h = SubgroupHeader{
        .track_alias = 42,
        .group = 7,
        .subgroup = 3,
        .publisher_priority = 128,
        .end_of_group = false,
        .per_object_properties = true,
    };
    try writeSubgroupHeader(&fbs, h, .draft_17);
    const written = fbs.seek;

    var rb = io.fixedBufferStream(@as([]const u8, buf[0..written]));
    const parsed = try readSubgroupHeader(&rb, .draft_17);
    try testing.expectEqual(@as(u64, 42), parsed.header.track_alias);
    try testing.expectEqual(@as(u64, 7), parsed.header.group);
    try testing.expectEqual(@as(?u64, 3), parsed.header.subgroup);
    try testing.expectEqual(@as(?u8, 128), parsed.header.publisher_priority);
    try testing.expect(parsed.header.per_object_properties);
    try testing.expect(!parsed.header.end_of_group);
    try testing.expectEqual(codes.SubgroupIdMode.explicit, parsed.id_mode);
}

test "subgroup header round-trip — zero subgroup, default priority, end-of-group" {
    var buf: [16]u8 = undefined;
    var fbs = io.fixedBufferStream(&buf);
    const h = SubgroupHeader{
        .track_alias = 1,
        .group = 0,
        .subgroup = 0,
        .publisher_priority = null,
        .end_of_group = true,
        .per_object_properties = false,
    };
    try writeSubgroupHeader(&fbs, h, .draft_17);
    var rb = io.fixedBufferStream(@as([]const u8, buf[0..fbs.seek]));
    const parsed = try readSubgroupHeader(&rb, .draft_17);
    try testing.expectEqual(codes.SubgroupIdMode.zero, parsed.id_mode);
    try testing.expect(parsed.header.end_of_group);
    try testing.expectEqual(@as(?u8, null), parsed.header.publisher_priority);
}

test "FIRST_OBJECT is a draft-18 bit, and a draft-17 reader would not know it" {
    const h = SubgroupHeader{
        .track_alias = 1,
        .group = 0,
        .subgroup = 0,
        .publisher_priority = 128,
        .end_of_group = false,
        .per_object_properties = false,
        .first_object = true,
    };

    var b18: [16]u8 = undefined;
    var f18 = io.fixedBufferStream(&b18);
    try writeSubgroupHeader(&f18, h, .draft_18);
    try testing.expectEqual(
        codes.SUBGROUP_BIT_SELECTOR | codes.SUBGROUP_BIT_FIRST_OBJECT,
        b18[0],
    );
    var r18 = io.fixedBufferStream(@as([]const u8, b18[0..f18.seek]));
    try testing.expect((try readSubgroupHeader(&r18, .draft_18)).header.first_object);

    // draft-17 has no such bit: setting it would make the type invalid there.
    var b17: [16]u8 = undefined;
    var f17 = io.fixedBufferStream(&b17);
    try writeSubgroupHeader(&f17, h, .draft_17);
    try testing.expectEqual(@as(u8, codes.SUBGROUP_BIT_SELECTOR), b17[0]);
    var r17 = io.fixedBufferStream(@as([]const u8, b18[0..f18.seek]));
    try testing.expectError(Error.InvalidStreamType, readSubgroupHeader(&r17, .draft_17));
}

test "subgroup header rejects reserved id-mode" {
    // Raw type byte with reserved mode bits (0b11 at bits 1-2) and selector set.
    const raw = [_]u8{ codes.SUBGROUP_BIT_SELECTOR | codes.SUBGROUP_MASK_ID_MODE, 0x01, 0x00 };
    var rb = io.fixedBufferStream(@as([]const u8, &raw));
    try testing.expectError(Error.InvalidStreamType, readSubgroupHeader(&rb, .draft_17));
}

test "datagram object round-trip with payload" {
    var buf: [64]u8 = undefined;
    var fbs = io.fixedBufferStream(&buf);
    const obj = DatagramObject{
        .track_alias = 5,
        .group = 2,
        .object = 7,
        .publisher_priority = 200,
        .end_of_group = false,
        .body = .{ .payload = "frame-data" },
    };
    try writeDatagramObject(&fbs, obj);
    const got = try readDatagramObject(buf[0..fbs.seek]);
    try testing.expectEqual(@as(u64, 5), got.track_alias);
    try testing.expectEqual(@as(u64, 2), got.group);
    try testing.expectEqual(@as(?u64, 7), got.object);
    try testing.expectEqual(@as(?u8, 200), got.publisher_priority);
    try testing.expectEqualStrings("frame-data", got.body.payload);
}

test "datagram object with status and zero object id" {
    var buf: [16]u8 = undefined;
    var fbs = io.fixedBufferStream(&buf);
    const obj = DatagramObject{
        .track_alias = 1,
        .group = 10,
        .object = null, // ZERO_OBJECT_ID
        .publisher_priority = null, // DEFAULT_PRIORITY
        .end_of_group = false,
        .body = .{ .status = .does_not_exist },
    };
    try writeDatagramObject(&fbs, obj);
    const got = try readDatagramObject(buf[0..fbs.seek]);
    try testing.expectEqual(@as(?u64, null), got.object);
    try testing.expectEqual(@as(?u8, null), got.publisher_priority);
    try testing.expectEqual(track.ObjectStatus.does_not_exist, got.body.status);
}

test "datagram rejects status+end_of_group combination" {
    // Construct a flags value with both STATUS (0x20) and END_OF_GROUP (0x02) set.
    const raw = [_]u8{ 0x22, 0x01, 0x00, 0x00 };
    try testing.expectError(Error.InvalidDatagramType, readDatagramObject(&raw));
}

test "fetch stream header round-trip" {
    var buf: [16]u8 = undefined;
    var fbs = io.fixedBufferStream(&buf);
    try writeFetchStreamHeader(&fbs, 0xabcd);
    var rb = io.fixedBufferStream(@as([]const u8, buf[0..fbs.seek]));
    const rid = try readFetchStreamHeader(&rb);
    try testing.expectEqual(@as(u64, 0xabcd), rid);
}

test "draft-18 accepts the FIRST_OBJECT bit that draft-17 rejects" {
    // §11.4.2 added bit 0x40. A draft-17 reader must refuse the type code
    // outright rather than ignore the bit, because the rest of the header
    // would then be read at the wrong offset.
    var buf: [32]u8 = undefined;
    var fbs = io.fixedBufferStream(&buf);
    try wire.writeVarInt(&fbs, codes.SUBGROUP_BIT_SELECTOR | codes.SUBGROUP_BIT_FIRST_OBJECT);
    try wire.writeVarInt(&fbs, 7); // track alias
    try wire.writeVarInt(&fbs, 3); // group
    try fbs.writeByte(128); // publisher priority
    const encoded = buf[0..fbs.seek];

    var r17 = io.fixedBufferStream(@as([]const u8, encoded));
    try testing.expectError(Error.InvalidStreamType, readSubgroupHeader(&r17, .draft_17));

    var r18 = io.fixedBufferStream(@as([]const u8, encoded));
    const parsed = try readSubgroupHeader(&r18, .draft_18);
    try testing.expectEqual(@as(u64, 7), parsed.header.track_alias);
    try testing.expectEqual(@as(u64, 3), parsed.header.group);
}

test "subgroup objects carry the ID as a delta from the one before" {
    // §11.4.2: "a Subgroup of sequential Object IDs starting at 0 will have
    // 0 for all Object ID Delta values".
    var buf: [64]u8 = undefined;
    var fbs = io.fixedBufferStream(&buf);
    try writeSubgroupObject(&fbs, .{ .id = 0, .payload = "ab" }, null, false);
    try writeSubgroupObject(&fbs, .{ .id = 1, .payload = "c" }, 0, false);
    try writeSubgroupObject(&fbs, .{ .id = 5, .status = 3 }, 1, false);
    try testing.expectEqualSlices(u8, &.{
        0x00, 0x02, 'a', 'b', // delta 0 → id 0
        0x00, 0x01, 'c', // delta 0 → id 1
        0x03, 0x00, 0x03, // delta 3 → id 5, empty, END_OF_GROUP status
    }, buf[0..fbs.seek]);

    var data: []const u8 = buf[0..fbs.seek];
    var prev: ?track.ObjectId = null;
    const want = [_]struct { id: u64, payload: []const u8, status: u64 }{
        .{ .id = 0, .payload = "ab", .status = 0 },
        .{ .id = 1, .payload = "c", .status = 0 },
        .{ .id = 5, .payload = "", .status = 3 },
    };
    for (want) |w| {
        const r = (try readSubgroupObject(data, prev, false)).?;
        try testing.expectEqual(w.id, r.object.id);
        try testing.expectEqualStrings(w.payload, r.object.payload);
        try testing.expectEqual(w.status, r.object.status);
        prev = r.object.id;
        data = data[r.consumed..];
    }
    try testing.expectEqual(@as(usize, 0), data.len);
}

test "a subgroup object that has not all arrived reads as null" {
    var buf: [32]u8 = undefined;
    var fbs = io.fixedBufferStream(&buf);
    try writeSubgroupObject(&fbs, .{ .id = 0, .properties = &.{ 0x02, 0x07 }, .payload = "xyz" }, null, true);
    const whole = buf[0..fbs.seek];
    try testing.expectEqualSlices(u8, &.{ 0x00, 0x02, 0x02, 0x07, 0x03, 'x', 'y', 'z' }, whole);
    for (0..whole.len) |n| try testing.expectEqual(@as(?ReadObject, null), try readSubgroupObject(whole[0..n], null, true));
    const r = (try readSubgroupObject(whole, null, true)).?;
    try testing.expectEqualSlices(u8, &.{ 0x02, 0x07 }, r.object.properties);
    try testing.expectEqualStrings("xyz", r.object.payload);
}

fn fetchRoundTrip(draft: version.Draft, descending: bool, items: []const FetchItem) !void {
    var buf: [512]u8 = undefined;
    var fbs = io.fixedBufferStream(&buf);
    var wc = FetchCursor.init(draft, descending);
    for (items) |it| try writeFetchItem(&fbs, it, &wc);

    var rc = FetchCursor.init(draft, descending);
    var data: []const u8 = buf[0..fbs.seek];
    for (items) |want| {
        const r = (try readFetchItem(data, &rc)) orelse return error.TestUnexpectedResult;
        switch (want) {
            .end_of_range => |w| {
                try testing.expectEqual(w.kind, r.item.end_of_range.kind);
                try testing.expectEqual(w.at, r.item.end_of_range.at);
            },
            .object => |w| {
                const o = r.item.object;
                try testing.expectEqual(w.group, o.group);
                try testing.expectEqual(w.subgroup, o.subgroup);
                try testing.expectEqual(w.id, o.id);
                try testing.expectEqual(w.publisher_priority, o.publisher_priority);
                try testing.expectEqual(w.properties == null, o.properties == null);
                try testing.expectEqualSlices(u8, w.payload, o.payload);
            },
        }
        data = data[r.consumed..];
    }
    try testing.expectEqual(@as(usize, 0), data.len);
}

test "fetch objects round-trip in every draft's encoding" {
    const items = [_]FetchItem{
        .{ .end_of_range = .{ .kind = .unknown, .at = .{ .group = 2, .object = 9 } } },
        .{ .object = .{ .group = 3, .subgroup = 0, .id = 0, .payload = "a" } },
        .{ .object = .{ .group = 3, .subgroup = 0, .id = 1, .payload = "b" } },
        .{ .object = .{ .group = 3, .subgroup = 0, .id = 4, .publisher_priority = 7, .payload = "" } },
        .{ .object = .{ .group = 3, .subgroup = 1, .id = 5, .properties = "\x02\x01", .payload = "c" } },
        .{ .object = .{ .group = 5, .subgroup = 9, .id = 0, .payload = "d" } },
        .{ .object = .{ .group = 6, .subgroup = null, .id = 2, .payload = "e" } },
    };
    for ([_]version.Draft{ .draft_17, .draft_18, .draft_22 }) |d| try fetchRoundTrip(d, false, &items);
}

test "draft-18 fetch objects carry IDs as deltas" {
    var buf: [64]u8 = undefined;
    var fbs = io.fixedBufferStream(&buf);
    var c = FetchCursor.init(.draft_18, false);
    try writeFetchItem(&fbs, .{ .object = .{ .group = 4, .id = 2, .payload = "" } }, &c);
    try writeFetchItem(&fbs, .{ .object = .{ .group = 4, .id = 3, .payload = "" } }, &c);
    try writeFetchItem(&fbs, .{ .object = .{ .group = 7, .id = 1, .payload = "" } }, &c);
    try testing.expectEqualSlices(u8, &.{
        0x1C, 4, 2, 128, 0, // first: both IDs whole, priority
        0x00, 0, // same group, next ID: no fields at all
        0x0C, 2, 1, 0, // group 4 + 2 + 1, object 1 whole
    }, buf[0..fbs.seek]);
}

test "descending fetch groups step down" {
    const items = [_]FetchItem{
        .{ .object = .{ .group = 9, .id = 0, .payload = "x" } },
        .{ .object = .{ .group = 9, .id = 1, .payload = "y" } },
        .{ .object = .{ .group = 4, .id = 0, .payload = "z" } },
    };
    try fetchRoundTrip(.draft_18, true, &items);
    try fetchRoundTrip(.draft_22, true, &items);
}

test "a fetch item referencing a prior object it doesn't have is refused" {
    var c = FetchCursor.init(.draft_18, false);
    // 0x01: the prior object's subgroup, on the first object.
    try testing.expectError(Error.InvalidObjectHeader, readFetchItem(&.{ 0x1D, 0, 0, 128, 0 }, &c));
    // No Group ID on the first object.
    try testing.expectError(Error.InvalidObjectHeader, readFetchItem(&.{ 0x14, 0, 128, 0 }, &c));
    // An End of Range value that isn't one.
    try testing.expectError(Error.InvalidObjectHeader, readFetchItem(&.{ 0x40, 0x8D, 0, 0 }, &c));
    // Half an object.
    try testing.expectEqual(@as(?ReadFetchItem, null), try readFetchItem(&.{ 0x1C, 4, 2, 128, 3, 'a' }, &c));
    try testing.expectEqual(@as(?track.Location, null), c.at);
}
