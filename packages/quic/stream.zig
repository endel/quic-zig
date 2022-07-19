pub const QuicStream = struct {
    is_blocked: bool,
    max_stream_data_local: u32,
    max_stream_data_local_sent: u32,
    max_stream_data_remote: u32,
    // receiver = QuicStreamReceiver(stream_id=stream_id, readable=readable)
    // sender = QuicStreamSender(stream_id=stream_id, writable=writable)
    stream_id: u32,

    pub fn isFinished(_: QuicStream) bool {
        // TODO: need receiver and sender
        return false;
        // return self.receiver.is_finished and self.sender.is_finished;
    }
};
