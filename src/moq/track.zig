// Shared value types for MoQ Transport draft-17.

const std = @import("std");

// A Track Namespace is up to 32 byte-strings; the wire form is a tuple
// (count + per-part length-prefixed bytes). See wire.writeTuple.
pub const TrackNamespace = []const []const u8;

pub const TrackName = []const u8;

pub const FullTrackName = struct {
    namespace: TrackNamespace,
    name: TrackName,

    pub fn eql(a: FullTrackName, b: FullTrackName) bool {
        if (!std.mem.eql(u8, a.name, b.name)) return false;
        if (a.namespace.len != b.namespace.len) return false;
        for (a.namespace, b.namespace) |pa, pb| {
            if (!std.mem.eql(u8, pa, pb)) return false;
        }
        return true;
    }
};

pub const TrackAlias = u64;
pub const RequestId = u64;
pub const GroupId = u64;
pub const SubgroupId = u64;
pub const ObjectId = u64;
pub const Priority = u8;

// §9.8 "Group Order" parameter value.
// §10.2.8: the GROUP_ORDER parameter is Ascending or Descending only —
// "use the publisher's preference" is said by omitting it, not by a value.
pub const GroupOrder = enum(u8) {
    ascending = 0x01,
    descending = 0x02,

    pub fn fromInt(v: u8) ?GroupOrder {
        return switch (v) {
            0x01 => .ascending,
            0x02 => .descending,
            else => null,
        };
    }
};

// §9.8 "Filter Type" parameter value.
pub const FilterType = enum(u64) {
    next_group_start = 0x01,
    latest_object = 0x02,
    absolute_start = 0x03,
    absolute_range = 0x04,

    pub fn fromInt(v: u64) ?FilterType {
        return switch (v) {
            0x01 => .next_group_start,
            0x02 => .latest_object,
            0x03 => .absolute_start,
            0x04 => .absolute_range,
            else => null,
        };
    }
};

// §10.5 Object Status values.
pub const ObjectStatus = enum(u64) {
    normal = 0x00,
    does_not_exist = 0x01,
    end_of_group = 0x03,
    end_of_track = 0x04,

    pub fn fromInt(v: u64) ?ObjectStatus {
        return switch (v) {
            0x00 => .normal,
            0x01 => .does_not_exist,
            0x03 => .end_of_group,
            0x04 => .end_of_track,
            else => null,
        };
    }
};

// Position within a track used by SUBSCRIBE/FETCH range parameters
// (group_id, object_id).
pub const Location = struct {
    group: GroupId,
    object: ObjectId,

    pub fn order(a: Location, b: Location) std.math.Order {
        if (a.group != b.group) return std.math.order(a.group, b.group);
        return std.math.order(a.object, b.object);
    }
};
