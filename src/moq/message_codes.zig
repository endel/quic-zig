// Numeric constants for MoQ Transport draft-17.
// Single source of truth — ranges/tables cross-referenced in
// SPEC/DRAFT_IETF_MOQ_TRANSPORT.md.

// Control message types (draft-17 §9 Table 4).
pub const MSG_SETUP: u64 = 0x2F00;
pub const MSG_GOAWAY: u64 = 0x10;
pub const MSG_REQUEST_OK: u64 = 0x07;
pub const MSG_REQUEST_ERROR: u64 = 0x05;
pub const MSG_SUBSCRIBE: u64 = 0x03;
pub const MSG_SUBSCRIBE_OK: u64 = 0x04;
pub const MSG_REQUEST_UPDATE: u64 = 0x02;
pub const MSG_PUBLISH: u64 = 0x1D;
pub const MSG_PUBLISH_OK: u64 = 0x1E;
pub const MSG_PUBLISH_DONE: u64 = 0x0B;
pub const MSG_FETCH: u64 = 0x16;
pub const MSG_FETCH_OK: u64 = 0x18;
pub const MSG_TRACK_STATUS: u64 = 0x0D;
pub const MSG_PUBLISH_NAMESPACE: u64 = 0x06;
pub const MSG_NAMESPACE: u64 = 0x08;
pub const MSG_NAMESPACE_DONE: u64 = 0x0E;
/// draft-17 only. draft-18 moved it to 0x50 and split off SUBSCRIBE_TRACKS,
/// so a writer takes the code from `version.Rules.of(draft)
/// .subscribe_namespace_code` rather than from this constant. A reader that
/// serves both drafts accepts either, and the negotiated draft decides how
/// the body is laid out.
pub const MSG_SUBSCRIBE_NAMESPACE: u64 = 0x11;
pub const MSG_SUBSCRIBE_NAMESPACE_18: u64 = 0x50;
/// draft-18 (§10.19): SUBSCRIBE_NAMESPACE yields NAMESPACE/NAMESPACE_DONE,
/// and this yields PUBLISH. In draft-17 one message did both.
pub const MSG_SUBSCRIBE_TRACKS: u64 = 0x51;
pub const MSG_PUBLISH_BLOCKED: u64 = 0x0F;

pub fn isReservedLegacyMessageType(t: u64) bool {
    return switch (t) {
        0x01, 0x20, 0x21, 0x40, 0x41 => true,
        else => false,
    };
}

// SETUP options (§9.4.1). Option keys obey the even/odd encoding rule
// of §1.4.3: even key → varint value, odd key → length-prefixed bytes.
pub const OPT_PATH: u64 = 0x01;
pub const OPT_AUTHORIZATION_TOKEN: u64 = 0x03;
pub const OPT_MAX_AUTH_TOKEN_CACHE_SIZE: u64 = 0x04;
pub const OPT_AUTHORITY: u64 = 0x05;
pub const OPT_MOQT_IMPLEMENTATION: u64 = 0x07;

// Data-stream type code for a FETCH stream (§10.4.4).
pub const STREAM_FETCH: u64 = 0x05;

// Subgroup stream type bit-field (§10.4.2). Bit 4 (0x10) is the
// selector; valid codes are 0x10..0x15, 0x18..0x1D, 0x30..0x35, 0x38..0x3D.
pub const SUBGROUP_BIT_PROPERTIES: u64 = 0x01;
pub const SUBGROUP_MASK_ID_MODE: u64 = 0x06;
pub const SUBGROUP_BIT_END_OF_GROUP: u64 = 0x08;
pub const SUBGROUP_BIT_SELECTOR: u64 = 0x10;
pub const SUBGROUP_BIT_DEFAULT_PRIORITY: u64 = 0x20;
/// draft-18 (§11.4.2): the first object on this stream is the first the
/// original publisher put in the subgroup. Unknown to draft-17, which
/// rejects the whole type code as out of range.
pub const SUBGROUP_BIT_FIRST_OBJECT: u64 = 0x40;

pub const SubgroupIdMode = enum(u2) {
    zero = 0b00, // Subgroup ID is 0; absent from header.
    first_object = 0b01, // Subgroup ID equals first Object ID; absent.
    explicit = 0b10, // Subgroup ID carried explicitly in header.
    reserved = 0b11, // Receipt is a PROTOCOL_VIOLATION.
};

/// `first_object` widens the accepted range to draft-18's `0b0XX1XXXX`.
pub fn isSubgroupStreamType(t: u64, first_object: bool) bool {
    // Must have selector bit set.
    if ((t & SUBGROUP_BIT_SELECTOR) == 0) return false;
    // Reserved-id-mode must not be present.
    const mode: u2 = @truncate((t & SUBGROUP_MASK_ID_MODE) >> 1);
    if (mode == @intFromEnum(SubgroupIdMode.reserved)) return false;
    const known: u64 = if (first_object) 0x7F else 0x3F;
    return (t & ~known) == 0;
}

// Datagram object type bit-field (§10.3.1). Valid codes 0x00..0x0F, 0x20..0x2F.
pub const DGRAM_BIT_PROPERTIES: u64 = 0x01;
pub const DGRAM_BIT_END_OF_GROUP: u64 = 0x02;
pub const DGRAM_BIT_ZERO_OBJECT_ID: u64 = 0x04;
pub const DGRAM_BIT_DEFAULT_PRIORITY: u64 = 0x08;
pub const DGRAM_BIT_STATUS: u64 = 0x20;

pub fn isDatagramObjectType(t: u64) bool {
    // Bit 4 (0x10) must be clear (it would select a subgroup stream).
    if ((t & 0x10) != 0) return false;
    // STATUS + END_OF_GROUP combined is disallowed.
    if ((t & (DGRAM_BIT_STATUS | DGRAM_BIT_END_OF_GROUP)) ==
        (DGRAM_BIT_STATUS | DGRAM_BIT_END_OF_GROUP)) return false;
    // High bits above those we know must be zero.
    return (t & ~@as(u64, 0x2F)) == 0;
}

// Session error codes (§3.5) — carried on CONNECTION_CLOSE / the
// WebTransport session close. These are a separate number space from the
// request error codes below; the two must not be mixed.
pub const SESSION_NO_ERROR: u64 = 0x0;
pub const SESSION_INTERNAL_ERROR: u64 = 0x1;
pub const SESSION_UNAUTHORIZED: u64 = 0x2;
pub const SESSION_PROTOCOL_VIOLATION: u64 = 0x3;
pub const SESSION_INVALID_REQUEST_ID: u64 = 0x4;
pub const SESSION_DUPLICATE_TRACK_ALIAS: u64 = 0x5;
pub const SESSION_KEY_VALUE_FORMATTING_ERROR: u64 = 0x6;
pub const SESSION_INVALID_REQUIRED_REQUEST_ID: u64 = 0x7;
pub const SESSION_INVALID_PATH: u64 = 0x8;
pub const SESSION_MALFORMED_PATH: u64 = 0x9;
pub const SESSION_GOAWAY_TIMEOUT: u64 = 0x10;
pub const SESSION_CONTROL_MESSAGE_TIMEOUT: u64 = 0x11;
pub const SESSION_DATA_STREAM_TIMEOUT: u64 = 0x12;
pub const SESSION_AUTH_TOKEN_CACHE_OVERFLOW: u64 = 0x13;
pub const SESSION_DUPLICATE_AUTH_TOKEN_ALIAS: u64 = 0x14;
pub const SESSION_VERSION_NEGOTIATION_FAILED: u64 = 0x15;
pub const SESSION_MALFORMED_AUTH_TOKEN: u64 = 0x16;
pub const SESSION_UNKNOWN_AUTH_TOKEN_ALIAS: u64 = 0x17;
pub const SESSION_EXPIRED_AUTH_TOKEN: u64 = 0x18;
pub const SESSION_INVALID_AUTHORITY: u64 = 0x19;
pub const SESSION_MALFORMED_AUTHORITY: u64 = 0x1A;

// Request error codes (§9.7) — carried in REQUEST_ERROR.
pub const ERR_INTERNAL_ERROR: u64 = 0x0;
pub const ERR_UNAUTHORIZED: u64 = 0x1;
pub const ERR_TIMEOUT: u64 = 0x2;
pub const ERR_NOT_SUPPORTED: u64 = 0x3;
pub const ERR_MALFORMED_AUTH_TOKEN: u64 = 0x4;
pub const ERR_EXPIRED_AUTH_TOKEN: u64 = 0x5;
pub const ERR_GOING_AWAY: u64 = 0x6;
pub const ERR_EXCESSIVE_LOAD: u64 = 0x9;
pub const ERR_DOES_NOT_EXIST: u64 = 0x10;
pub const ERR_INVALID_RANGE: u64 = 0x11;
pub const ERR_MALFORMED_TRACK: u64 = 0x12;
pub const ERR_DUPLICATE_SUBSCRIPTION: u64 = 0x19;
pub const ERR_UNINTERESTED: u64 = 0x20;
pub const ERR_PREFIX_OVERLAP: u64 = 0x30;
pub const ERR_NAMESPACE_TOO_LARGE: u64 = 0x31;
pub const ERR_INVALID_JOINING_REQUEST_ID: u64 = 0x32;

// PUBLISH_DONE status codes (§9.13).
pub const DONE_INTERNAL_ERROR: u64 = 0x0;
pub const DONE_UNAUTHORIZED: u64 = 0x1;
pub const DONE_TRACK_ENDED: u64 = 0x2;
pub const DONE_SUBSCRIPTION_ENDED: u64 = 0x3;
pub const DONE_GOING_AWAY: u64 = 0x4;
pub const DONE_EXPIRED: u64 = 0x5;
