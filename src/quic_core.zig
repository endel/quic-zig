// WASM-safe subset of the quic-zig library.
//
// Exports the core QUIC, TLS 1.3, H3, and WebTransport modules
// WITHOUT event_loop, ecn_socket, http1, or quic_lb — which
// depend on OS sockets / kqueue / epoll.

pub const connection = @import("quic/connection.zig");
pub const connection_manager = @import("quic/connection_manager.zig");
pub const crypto = @import("quic/crypto.zig");
pub const tls13 = @import("quic/tls13.zig");
pub const transport_params = @import("quic/transport_params.zig");
pub const stateless_reset = @import("quic/stateless_reset.zig");
pub const packet = @import("quic/packet.zig");
pub const h3 = @import("h3/connection.zig");
pub const qpack = @import("h3/qpack.zig");
pub const webtransport = @import("webtransport/session.zig");
pub const platform = @import("quic/platform.zig");
