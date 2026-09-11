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
    flags |= (@as(u64, @intFromEnum(mode)) << 1);

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
    const id_mode: codes.SubgroupIdMode = @enumFromInt(mode_bits);
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
        .status => |s| try wire.writeVarInt(writer, @intFromEnum(s)),
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
