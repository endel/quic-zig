pub const Connection = struct {
    pub fn init() Connection {
        return .{};
    }
};

// self.__frame_handlers = {
//     0x00: (self._handle_padding_frame, EPOCHS("IH01")),
//     0x01: (self._handle_ping_frame, EPOCHS("IH01")),
//     0x02: (self._handle_ack_frame, EPOCHS("IH1")),
//     0x03: (self._handle_ack_frame, EPOCHS("IH1")),
//     0x04: (self._handle_reset_stream_frame, EPOCHS("01")),
//     0x05: (self._handle_stop_sending_frame, EPOCHS("01")),
//     0x06: (self._handle_crypto_frame, EPOCHS("IH1")),
//     0x07: (self._handle_new_token_frame, EPOCHS("1")),
//     0x08: (self._handle_stream_frame, EPOCHS("01")),
//     0x09: (self._handle_stream_frame, EPOCHS("01")),
//     0x0A: (self._handle_stream_frame, EPOCHS("01")),
//     0x0B: (self._handle_stream_frame, EPOCHS("01")),
//     0x0C: (self._handle_stream_frame, EPOCHS("01")),
//     0x0D: (self._handle_stream_frame, EPOCHS("01")),
//     0x0E: (self._handle_stream_frame, EPOCHS("01")),
//     0x0F: (self._handle_stream_frame, EPOCHS("01")),
//     0x10: (self._handle_max_data_frame, EPOCHS("01")),
//     0x11: (self._handle_max_stream_data_frame, EPOCHS("01")),
//     0x12: (self._handle_max_streams_bidi_frame, EPOCHS("01")),
//     0x13: (self._handle_max_streams_uni_frame, EPOCHS("01")),
//     0x14: (self._handle_data_blocked_frame, EPOCHS("01")),
//     0x15: (self._handle_stream_data_blocked_frame, EPOCHS("01")),
//     0x16: (self._handle_streams_blocked_frame, EPOCHS("01")),
//     0x17: (self._handle_streams_blocked_frame, EPOCHS("01")),
//     0x18: (self._handle_new_connection_id_frame, EPOCHS("01")),
//     0x19: (self._handle_retire_connection_id_frame, EPOCHS("01")),
//     0x1A: (self._handle_path_challenge_frame, EPOCHS("01")),
//     0x1B: (self._handle_path_response_frame, EPOCHS("01")),
//     0x1C: (self._handle_connection_close_frame, EPOCHS("IH01")),
//     0x1D: (self._handle_connection_close_frame, EPOCHS("01")),
//     0x1E: (self._handle_handshake_done_frame, EPOCHS("1")),
//     0x30: (self._handle_datagram_frame, EPOCHS("01")),
//     0x31: (self._handle_datagram_frame, EPOCHS("01")),
// }
//
