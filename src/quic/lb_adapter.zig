// Generic "load balancer adapter" hook used by the QUIC core to absorb
// LB-specific framing on incoming datagrams.
//
// The core (ConnectionManager) knows nothing about any particular LB wire
// format. If an adapter is installed, it gets the chance to inspect each
// datagram before QUIC parsing: it can declare the datagram is plain QUIC
// ("passthrough"), unwrap it and provide injected context for new
// connections ("injected"), or reject it as malformed ("drop").
//
// Concrete implementations live outside the core. Today:
//   - `src/quic/lb_envelope.zig` — proprietary netcode framing with HMAC.
//
// Future: an adapter for HAProxy's PROXY protocol v2, a Fastly-style
// wrapper, or a deployment-specific sidecar format can all be added
// without touching the ConnectionManager.

const std = @import("std");

pub const MAX_CID_LEN: usize = 20;

/// What the adapter extracted from an LB-wrapped datagram. The core uses
/// these fields to populate transport params on newly accepted
/// connections: `original_destination_connection_id` comes from `odcid`
/// and `retry_source_connection_id` from `retry_scid` (RFC 9000 §7.3).
pub const InjectedContext = struct {
    odcid_buf: [MAX_CID_LEN]u8 = .{0} ** MAX_CID_LEN,
    odcid_len: u8 = 0,
    retry_scid_buf: [MAX_CID_LEN]u8 = .{0} ** MAX_CID_LEN,
    retry_scid_len: u8 = 0,
    was_retried: bool = false,
    /// Byte offset in the original datagram at which the inner QUIC
    /// payload begins. The core will feed only `bytes[payload_offset..]`
    /// to its parser.
    payload_offset: usize = 0,

    pub fn odcid(self: *const InjectedContext) []const u8 {
        return self.odcid_buf[0..self.odcid_len];
    }
    pub fn retryScid(self: *const InjectedContext) []const u8 {
        return self.retry_scid_buf[0..self.retry_scid_len];
    }
};

pub const UnwrapResult = union(enum) {
    /// Adapter does not recognize this datagram. Treat as plain QUIC.
    passthrough,
    /// Adapter recognized and decoded the framing.
    injected: InjectedContext,
    /// Adapter recognized the framing but the datagram is malformed or
    /// fails authentication — the core should drop without processing.
    drop,
};

/// Type-erased vtable for an LB adapter. Construct via an implementation's
/// `lbAdapter()` helper; the returned value is cheap to copy.
pub const LbAdapter = struct {
    ctx: *anyopaque,
    unwrap_fn: *const fn (ctx: *anyopaque, buf: []const u8) UnwrapResult,

    pub fn unwrap(self: LbAdapter, buf: []const u8) UnwrapResult {
        return self.unwrap_fn(self.ctx, buf);
    }
};
