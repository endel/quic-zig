const std = @import("std");

// loss detection
pub const K_PACKET_THRESHOLD = 3;
pub const K_GRANULARITY = 0.001; // seconds
pub const K_TIME_THRESHOLD = 9 / 8;
pub const K_MICRO_SECOND = 0.000001;
pub const K_SECOND = 1.0;

// congestion control
pub const K_MAX_DATAGRAM_SIZE = 1280;
pub const K_INITIAL_WINDOW = 10 * K_MAX_DATAGRAM_SIZE;
pub const K_MINIMUM_WINDOW = 2 * K_MAX_DATAGRAM_SIZE;
pub const K_LOSS_REDUCTION_FACTOR = 0.5;

pub const QuicPacketSpace = struct {
    ack_at: f32 = undefined,
    ack_queue: std.TailQueue(f32) = undefined,
    discarded: bool = false,
    expected_packet_number: u32 = 0,
    largest_received_packet: i32 = -1,
    largest_received_time: f32 = undefined,

    // sent packets and loss
    ack_eliciting_in_flight: u32 = 0,
    largest_acked_packet: u32 = 0,
    loss_time: f32 = undefined,

    // TODO: sent pakcet?
    // sent_packets: std.AutoHashMap(u32, u32), // Dict[int, QuicSentPacket] = {}

    pub fn init() QuicPacketSpace {
        return .{};
    }
};
