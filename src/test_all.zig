// Test entry point: imports all library modules to discover their tests.
test {
    _ = @import("quic/connection.zig");
    _ = @import("quic/packet.zig");
    _ = @import("quic/protocol.zig");
    _ = @import("quic/frame.zig");
    _ = @import("quic/ranges.zig");
    _ = @import("quic/rtt.zig");
    _ = @import("quic/ack_handler.zig");
    _ = @import("quic/congestion.zig");
    _ = @import("quic/flow_control.zig");
    _ = @import("quic/transport_params.zig");
    _ = @import("quic/stream.zig");
    _ = @import("quic/crypto_stream.zig");
    _ = @import("quic/packet_packer.zig");
    _ = @import("quic/tls13.zig");
    _ = @import("quic/mtu.zig");
    _ = @import("quic/stateless_reset.zig");
    _ = @import("quic/connection_manager.zig");
    _ = @import("quic/ecn.zig");
    _ = @import("quic/ecn_socket.zig");
    _ = @import("quic/quic_lb.zig");
    _ = @import("h3/frame.zig");
    _ = @import("h3/qpack.zig");
    _ = @import("h3/huffman.zig");
    _ = @import("h3/connection.zig");
    _ = @import("webtransport/session.zig");
    _ = @import("h3/capsule.zig");
}
