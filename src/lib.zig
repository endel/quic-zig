// Public API re-exports for the quic-zig library.
pub const sys = @import("sys.zig");
pub const sockaddr = @import("sockaddr.zig");
pub const io_compat = @import("io_compat.zig");
pub const packet = @import("quic/packet.zig");
pub const frame = @import("quic/frame.zig");
pub const connection = @import("quic/connection.zig");
pub const connection_manager = @import("quic/connection_manager.zig");
pub const crypto = @import("quic/crypto.zig");
pub const tls13 = @import("quic/tls13.zig");
pub const ca_bundle = @import("quic/ca_bundle.zig");
pub const ecn_socket = @import("quic/ecn_socket.zig");
pub const transport_params = @import("quic/transport_params.zig");
pub const stateless_reset = @import("quic/stateless_reset.zig");
pub const h3 = @import("h3/connection.zig");
pub const h0 = @import("h0/connection.zig");
pub const http1 = @import("http1/server.zig");
pub const qpack = @import("h3/qpack.zig");
pub const webtransport = @import("webtransport/session.zig");
pub const webtransport_flow_control = @import("webtransport/flow_control.zig");
pub const webtransport_protocol = @import("webtransport/protocol.zig");
pub const quic_lb = @import("quic/quic_lb.zig");
pub const event_loop = @import("event_loop.zig");
pub const moq = struct {
    pub const wire = @import("moq/wire.zig");
    pub const message = @import("moq/message.zig");
    pub const message_codes = @import("moq/message_codes.zig");
    pub const object = @import("moq/object.zig");
    pub const track = @import("moq/track.zig");
    pub const version = @import("moq/version.zig");
    pub const url = @import("moq/url.zig");
    pub const session = @import("moq/session.zig");

    /// moq-lite (draft-lcurley-moq-lite-05) — a separate wire format from
    /// the IETF draft above, sharing only the transport underneath.
    pub const lite = struct {
        pub const wire = @import("moq/lite/wire.zig");
        pub const message = @import("moq/lite/message.zig");
        pub const version = @import("moq/lite/version.zig");
        pub const session = @import("moq/lite/session.zig");
    };
};
