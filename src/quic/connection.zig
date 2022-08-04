pub const Connection = struct {
    version: u32,
    dcid: u32,
    scid: u32,

    // stats
    recv_count: u32 = 0,
    sent_count: u32 = 0,
    retrans_count: u32 = 0,
    sent_bytes: u32 = 0,
    recv_bytes: u32 = 0,

    pkt_num_spaces: u32,
    handshake: tls,

    pub fn init() Connection {
        return .{};
    }
};
