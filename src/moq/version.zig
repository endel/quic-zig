// Media-over-QUIC Transport — IETF draft version identifiers.
//
// Since draft-15 the version is chosen by ALPN alone: on native QUIC the
// ALPN token itself, and over WebTransport the same token carried in the
// WT-Available-Protocols / WT-Protocol CONNECT headers (§3.1). There is no
// version list in SETUP. The wire codes below are only used by peers that
// still negotiate through the pre-draft-15 `moq-00` ALPN.

const std = @import("std");
const testing = std.testing;

pub const Draft = enum(u8) {
    draft_17 = 17,
    draft_18 = 18,

    pub fn number(self: Draft) u8 {
        return @intFromEnum(self);
    }

    pub fn alpn(self: Draft) []const u8 {
        return switch (self) {
            .draft_17 => "moqt-17",
            .draft_18 => "moqt-18",
        };
    }

    // The code a pre-draft-15 peer would negotiate with. Not on the wire
    // for the drafts we speak; kept because peers log and compare it.
    pub fn wireCode(self: Draft) u64 {
        return 0xff00_0000 | @as(u64, @intFromEnum(self));
    }

    pub fn fromAlpn(token: []const u8) ?Draft {
        inline for (comptime std.enums.values(Draft)) |d| {
            if (std.mem.eql(u8, token, d.alpn())) return d;
        }
        return null;
    }
};

// Newest first, so a peer that speaks several picks the newest we share.
//
// Only offer what is implemented. Over raw QUIC the QUIC ALPN carries one
// token and a mismatch fails the handshake, but over WebTransport this
// list goes in WT-Available-Protocols, where the connection still succeeds
// and only the MoQ on top of it goes quiet.
pub const PREFERRED: []const Draft = &.{ .draft_18, .draft_17 };

/// Where the two drafts differ on the wire, in one place.
///
/// draft-18 (§10) removed `Required Request ID Delta` from every request
/// message, moved SUBSCRIBE_NAMESPACE, stopped sending PUBLISH_OK as its
/// own type, and added a FIRST_OBJECT bit to the subgroup header.
pub const Rules = struct {
    /// draft-17 only: a varint after the Request ID in every request.
    required_request_id_delta: bool,
    subscribe_namespace_code: u64,
    /// draft-18 answers PUBLISH with REQUEST_OK instead.
    publish_ok_is_own_message: bool,
    /// draft-17 only: SUBSCRIBE_NAMESPACE carries a Subscribe Options varint.
    subscribe_namespace_options: bool,
    /// draft-18 only: SUBGROUP_HEADER bit 0x40.
    subgroup_first_object_bit: bool,

    pub fn of(draft: Draft) Rules {
        return switch (draft) {
            .draft_17 => .{
                .required_request_id_delta = true,
                .subscribe_namespace_code = 0x11,
                .publish_ok_is_own_message = true,
                .subscribe_namespace_options = true,
                .subgroup_first_object_bit = false,
            },
            .draft_18 => .{
                .required_request_id_delta = false,
                .subscribe_namespace_code = 0x50,
                .publish_ok_is_own_message = false,
                .subscribe_namespace_options = false,
                .subgroup_first_object_bit = true,
            },
        };
    }
};

// The draft this stack implements by default. draft-18 moved
// SUBSCRIBE_NAMESPACE, dropped Required Request ID from every request
// message and relaxed the varint, so it is not yet the default.
pub const DEFAULT: Draft = .draft_18;

// Fills `out` with the ALPN tokens for `drafts`, in the given order.
pub fn alpnOffer(drafts: []const Draft, out: [][]const u8) [][]const u8 {
    const n = @min(drafts.len, out.len);
    for (drafts[0..n], out[0..n]) |d, *slot| slot.* = d.alpn();
    return out[0..n];
}

// Back-compat aliases for call sites that predate the version table.
pub const DRAFT_NUMBER: u32 = @intFromEnum(DEFAULT);
pub const WIRE_VERSION: u64 = 0xff00_0011;
pub const ALPN: []const u8 = "moqt-17";

test "the rules table says where the drafts differ" {
    const r17 = Rules.of(.draft_17);
    const r18 = Rules.of(.draft_18);
    try testing.expect(r17.required_request_id_delta);
    try testing.expect(!r18.required_request_id_delta);
    try testing.expectEqual(@as(u64, 0x11), r17.subscribe_namespace_code);
    try testing.expectEqual(@as(u64, 0x50), r18.subscribe_namespace_code);
    try testing.expect(r17.publish_ok_is_own_message);
    try testing.expect(!r18.publish_ok_is_own_message);
    try testing.expect(!r17.subgroup_first_object_bit);
    try testing.expect(r18.subgroup_first_object_bit);
}

test "alpn round-trips through the draft table" {
    try testing.expectEqualStrings("moqt-17", Draft.draft_17.alpn());
    try testing.expectEqualStrings("moqt-18", Draft.draft_18.alpn());
    try testing.expectEqual(Draft.draft_18, Draft.fromAlpn("moqt-18").?);
    try testing.expectEqual(@as(?Draft, null), Draft.fromAlpn("moqt-99"));
    try testing.expectEqual(@as(?Draft, null), Draft.fromAlpn("h3"));
}

test "wire codes match the draft numbers" {
    try testing.expectEqual(WIRE_VERSION, Draft.draft_17.wireCode());
    try testing.expectEqual(@as(u64, 0xff00_0012), Draft.draft_18.wireCode());
}

test "alpn offer is newest-first and clamps to the buffer" {
    var buf: [4][]const u8 = undefined;
    const offer = alpnOffer(PREFERRED, &buf);
    try testing.expectEqual(@as(usize, 2), offer.len);
    try testing.expectEqualStrings("moqt-18", offer[0]);
    try testing.expectEqualStrings("moqt-17", offer[1]);

    var small: [1][]const u8 = undefined;
    try testing.expectEqual(@as(usize, 1), alpnOffer(PREFERRED, &small).len);
}
