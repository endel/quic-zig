const std = @import("std");
const string = []const u8;

pub const QuicConnectionId = struct {
    cid: []u8,
    sequence_number: u32,
    stateless_reset_token: []u8 = .{},
    was_sent: bool = false,
};

pub const QuicConnectionState = enum(u8) {
    FIRSTFLIGHT = 0,
    CONNECTED = 1,
    CLOSING = 2,
    DRAINING = 3,
    TERMINATED = 4,
};

pub const QuicNetworkPath = struct {
    addr: std.net.Address,
    bytes_received: u32,
    bytes_sent: u32,
    is_validated: bool,
    local_challenge: []u8,
    remote_challenge: []u8,

    // TODO: i don't like "canXX()" bool method names.
    pub fn canSend(self: QuicNetworkPath, size: u32) bool {
        // TODO: this math looks suspicious!
        return self.is_validated || (self.bytes_sent + size) <= 3 * self.bytes_received;
    }
};

///
/// A QUIC Configuration
///
pub const QuicConfiguration = struct {
    /// A list of supported ALPN protocols.
    // TODO: dynamic allocation for protocols here.
    alpn_protocols: [11]string = undefined,

    // The length in bytes of local connection IDs.
    connection_id_length: u8 = 8,

    // The idle timeout in seconds.
    // The connection is terminated if nothing is received for the given duration.
    idle_timeout: u8 = 60,

    // Whether this is the client side of the QUIC connection.
    is_client: bool = false,

    // Connection-wide flow control limit.
    max_data: u32 = 1048576,

    // Per-stream flow control limit.
    max_stream_data: u32 = 1048576,

    // The server name to send during the TLS handshake the Server Name Indication.
    // .. note:: This is only used by clients.
    server_name: []u8 = undefined,

    // // The TLS session ticket which should be used for session resumption.
    // session_ticket: Optional[SessionTicket] = None

    // cadata: Optional[bytes] = None
    // cafile: Optional[str] = None
    // capath: Optional[str] = None
    // certificate: Any = None
    // certificate_chain: List[Any] = field(default_factory=list)
    // cipher_suites: Optional[List[CipherSuite]] = None

    initial_rtt: f32 = 0.1,
    max_datagram_frame_size: u32 = undefined,

    // private_key: Any = None
    // quantum_readiness_test: bool = False
    // supported_versions: List[u8] = field(
    //     default_factory=lambda: [
    //         QuicProtocolVersion.VERSION_1,
    //         QuicProtocolVersion.DRAFT_32,
    //         QuicProtocolVersion.DRAFT_31,
    //         QuicProtocolVersion.DRAFT_30,
    //         QuicProtocolVersion.DRAFT_29,
    //     ]
    // )
    //
    verify_mode: u8 = undefined,

    // pub fn readCertChain(self: QuicConfiguration, certfile: string, keyfile: ?string, password: ?string) !void {
    pub fn readCertChain(self: QuicConfiguration, alloc: std.mem.Allocator, opts: struct { certfile: string, keyfile: ?string, password: ?string = undefined }) !void {
        _ = self;
        _ = opts;

        _ = alloc;
        // const kcert = try cert.pem.fromFile(alloc, opts.certfile);
        // std.log.info("public: {any}", .{kcert});
        //
        // if (opts.keyfile) |file| {
        //     const kprivate = try cert.pem.fromFile(alloc, file);
        //     std.log.info("private: {any}", .{kprivate});
        // }

        // -------------------------------------------------------------------

        // TODO: add ability to parse PRIVATE KEY embedded in the CERTIFICATE file.
        // TODO: support certificates with multiple lines (can only parse from a single line)

        // var it = std.mem.split(u8, opts.certfile, "-----BEGIN PRIVATE KEY-----\n");
        // while (it.next()) |chunk| {
        //     std.log.info("token: {s}", .{chunk});
        // }

        // std.log.info("CHUNKS: {s}, {any}", .{ chunks.delimiter_bytes, chunks });

        // Load a private key and the corresponding certificate.

        // with open(certfile, "rb") as fp:
        //     boundary = b"-----BEGIN PRIVATE KEY-----\n"
        //     chunks = split(b"\n" + boundary, fp.read())
        //     certificates = load_pem_x509_certificates(chunks[0])
        //     if len(chunks) == 2:
        //         private_key = boundary + chunks[1]
        //         self.private_key = load_pem_private_key(private_key)
        // self.certificate = certificates[0]
        // self.certificate_chain = certificates[1:]
        //
        // if keyfile is not None:
        //     with open(keyfile, "rb") as fp:
        //         self.private_key = load_pem_private_key(
        //             fp.read(),
        //             password=password.encode("utf8")
        //             if isinstance(password, str)
        //             else password,
        //         )

    }
};
