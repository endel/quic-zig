const Configuration = @import("configuration.zig");
const recovery = @import("recovery.zig");

const structs = @import("structs.zig");
const QuicConnectionId = structs.QuicConnectionId;

const Connection = @This();

is_client: bool = undefined,
configuration: Configuration = undefined,

ack_delay: f32 = undefined,
close_at: f32 = undefined,

host_cids: std.Array(QuicConnectionId) = undefined,

// self._close_event: Optional[events.ConnectionTerminated] = None
// self._connect_called = False
// self._cryptos: Dict[tls.Epoch, CryptoPair] = {}
// self._crypto_buffers: Dict[tls.Epoch, Buffer] = {}
// self._crypto_retransmitted = False
// self._crypto_streams: Dict[tls.Epoch, QuicStream] = {}
// self._events: Deque[events.QuicEvent] = deque()
// self._handshake_complete = False
// self._handshake_confirmed = False
self._host_cids = [
    QuicConnectionId(
        cid=os.urandom(configuration.connection_id_length),
        sequence_number=0,
        stateless_reset_token=os.urandom(16) if not self._is_client else None,
        was_sent=True,
    )
]
self.host_cid = self._host_cids[0].cid
self._host_cid_seq = 1
self._local_ack_delay_exponent = 3
self._local_active_connection_id_limit = 8
self._local_initial_source_connection_id = self._host_cids[0].cid
self._local_max_data = Limit(
    frame_type=QuicFrameType.MAX_DATA,
    name="max_data",
    value=configuration.max_data,
)
self._local_max_stream_data_bidi_local = configuration.max_stream_data
self._local_max_stream_data_bidi_remote = configuration.max_stream_data
self._local_max_stream_data_uni = configuration.max_stream_data
self._local_max_streams_bidi = Limit(
    frame_type=QuicFrameType.MAX_STREAMS_BIDI,
    name="max_streams_bidi",
    value=128,
)
self._local_max_streams_uni = Limit(
    frame_type=QuicFrameType.MAX_STREAMS_UNI, name="max_streams_uni", value=128
)
self._loss_at: Optional[float] = None
self._network_paths: List[QuicNetworkPath] = []
self._pacing_at: Optional[float] = None
self._packet_number = 0
self._parameters_received = False
self._peer_cid = QuicConnectionId(
    cid=os.urandom(configuration.connection_id_length), sequence_number=None
)
self._peer_cid_available: List[QuicConnectionId] = []
self._peer_cid_sequence_numbers: Set[int] = set([0])
self._peer_token = b""
self._quic_logger: Optional[QuicLoggerTrace] = None
self._remote_ack_delay_exponent = 3
self._remote_active_connection_id_limit = 2
self._remote_initial_source_connection_id: Optional[bytes] = None
self._remote_max_idle_timeout = 0.0  # seconds
self._remote_max_data = 0
self._remote_max_data_used = 0
self._remote_max_datagram_frame_size: Optional[int] = None
self._remote_max_stream_data_bidi_local = 0
self._remote_max_stream_data_bidi_remote = 0
self._remote_max_stream_data_uni = 0
self._remote_max_streams_bidi = 0
self._remote_max_streams_uni = 0
self._retry_count = 0
self._retry_source_connection_id = retry_source_connection_id
self._spaces: Dict[tls.Epoch, QuicPacketSpace] = {}
self._spin_bit = False
self._spin_highest_pn = 0
self._state = QuicConnectionState.FIRSTFLIGHT
self._streams: Dict[int, QuicStream] = {}
self._streams_blocked_bidi: List[QuicStream] = []
self._streams_blocked_uni: List[QuicStream] = []
self._streams_finished: Set[int] = set()
self._version: Optional[int] = None
self._version_negotiation_count = 0

pub fn init() Connection {
    // if configuration.is_client:
    //     assert (
    //         original_destination_connection_id is None
    //     ), "Cannot set original_destination_connection_id for a client"
    //     assert (
    //         retry_source_connection_id is None
    //     ), "Cannot set retry_source_connection_id for a client"
    // else:
    //     assert (
    //         configuration.certificate is not None
    //     ), "SSL certificate is required for a server"
    //     assert (
    //         configuration.private_key is not None
    //     ), "SSL private key is required for a server"
    //     assert (
    //         original_destination_connection_id is not None
    //     ), "original_destination_connection_id is required for a server"
    //

    return .{

    };
}



        if self._is_client:
            self._original_destination_connection_id = self._peer_cid.cid
        else:
            self._original_destination_connection_id = (
                original_destination_connection_id
            )

        # logging
        self._logger = QuicConnectionAdapter(
            logger, {"id": dump_cid(self._original_destination_connection_id)}
        )
        if configuration.quic_logger:
            self._quic_logger = configuration.quic_logger.start_trace(
                is_client=configuration.is_client,
                odcid=self._original_destination_connection_id,
            )

        # loss recovery
        self._loss = QuicPacketRecovery(
            initial_rtt=configuration.initial_rtt,
            peer_completed_address_validation=not self._is_client,
            quic_logger=self._quic_logger,
            send_probe=self._send_probe,
            logger=self._logger,
        )

        # things to send
        self._close_pending = False
        self._datagrams_pending: Deque[bytes] = deque()
        self._handshake_done_pending = False
        self._ping_pending: List[int] = []
        self._probe_pending = False
        self._retire_connection_ids: List[int] = []
        self._streams_blocked_pending = False

        # callbacks
        self._session_ticket_fetcher = session_ticket_fetcher
        self._session_ticket_handler = session_ticket_handler



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
