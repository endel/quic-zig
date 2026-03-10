const std = @import("std");
const net = std.net;
const posix = std.posix;
const crypto = std.crypto;

const protocol = @import("protocol.zig");
const packet = @import("packet.zig");
const tls = @import("tls.zig");
const tls13 = @import("tls13.zig");
const frame_mod = @import("frame.zig");
const Frame = frame_mod.Frame;
const FrameType = frame_mod.FrameType;
const ack_handler = @import("ack_handler.zig");
const congestion = @import("congestion.zig");
const flow_control = @import("flow_control.zig");
const rtt = @import("rtt.zig");
const stream_mod = @import("stream.zig");
const crypto_stream = @import("crypto_stream.zig");
const transport_params = @import("transport_params.zig");
const packet_packer = @import("packet_packer.zig");
const quic_crypto = @import("crypto.zig");
const mtu_mod = @import("mtu.zig");
const stateless_reset = @import("stateless_reset.zig");
const ecn = @import("ecn.zig");

pub const State = enum(u8) {
    first_flight = 0,
    handshake = 1,
    connected = 2,
    closing = 3,
    draining = 4,
    terminated = 5,
};

pub const PathValidationState = enum {
    idle,
    pending,
    validated,
    failed,
};

pub const PathValidator = struct {
    challenge_data: [8]u8 = .{0} ** 8,
    state: PathValidationState = .idle,
    challenge_sent_time: i64 = 0,
    retries: u8 = 0,

    const MAX_RETRIES: u8 = 3;

    pub fn startChallenge(self: *PathValidator) [8]u8 {
        crypto.random.bytes(&self.challenge_data);
        self.state = .pending;
        self.challenge_sent_time = @intCast(std.time.nanoTimestamp());
        self.retries = 0;
        return self.challenge_data;
    }

    pub fn handleResponse(self: *PathValidator, data: [8]u8) bool {
        if (self.state != .pending) return false;
        if (std.mem.eql(u8, &data, &self.challenge_data)) {
            self.state = .validated;
            return true;
        }
        return false;
    }

    pub fn checkTimeout(self: *PathValidator, now: i64, pto_ns: i64) void {
        if (self.state != .pending) return;
        if (self.retries >= MAX_RETRIES) {
            const elapsed = now - self.challenge_sent_time;
            if (elapsed > pto_ns) {
                self.state = .failed;
            }
        }
    }

    pub fn needsRetry(self: *const PathValidator, now: i64, pto_ns: i64) bool {
        if (self.state != .pending) return false;
        if (self.retries >= MAX_RETRIES) return false;
        const elapsed = now - self.challenge_sent_time;
        return elapsed > pto_ns;
    }

    pub fn retry(self: *PathValidator) void {
        self.retries += 1;
        self.challenge_sent_time = @intCast(std.time.nanoTimestamp());
    }
};

pub const NetworkPath = struct {
    local_addr: posix.sockaddr,
    peer_addr: posix.sockaddr,
    is_initial: bool,

    /// Bytes received on this path (for amplification limit).
    bytes_received: u64 = 0,

    /// Bytes sent on this path.
    bytes_sent: u64 = 0,

    /// Whether the path has been validated (e.g., by Retry or handshake completion).
    is_validated: bool = false,

    /// Path validation state machine.
    validator: PathValidator = .{},

    pub fn init(
        local_addr: posix.sockaddr,
        peer_addr: posix.sockaddr,
        is_initial: bool,
    ) NetworkPath {
        return .{
            .local_addr = local_addr,
            .peer_addr = peer_addr,
            .is_initial = is_initial,
        };
    }

    /// Check if we can send `size` bytes without exceeding the amplification limit.
    /// Before address validation, servers can only send 3x what they've received.
    pub fn canSend(self: *const NetworkPath, size: u64) bool {
        return self.is_validated or (self.bytes_sent + size) <= 3 * self.bytes_received;
    }
};

pub const ConnectionIdEntry = struct {
    cid_buf: [20]u8 = .{0} ** 20,
    cid_len: u8 = 0,
    seq_num: u64 = 0,
    stateless_reset_token: [16]u8 = .{0} ** 16,
    in_use: bool = false,
    occupied: bool = false,

    pub fn getCid(self: *const ConnectionIdEntry) []const u8 {
        return self.cid_buf[0..self.cid_len];
    }
};

pub const ConnectionIdPool = struct {
    const MAX_POOL_SIZE: usize = 8;

    entries: [MAX_POOL_SIZE]ConnectionIdEntry = .{ConnectionIdEntry{}} ** MAX_POOL_SIZE,

    pub fn addPeerCid(self: *ConnectionIdPool, seq_num: u64, cid: []const u8, reset_token: [16]u8) void {
        // Find a free slot
        for (&self.entries) |*entry| {
            if (!entry.occupied) {
                entry.occupied = true;
                entry.in_use = false;
                entry.seq_num = seq_num;
                entry.cid_len = @intCast(cid.len);
                @memcpy(entry.cid_buf[0..cid.len], cid);
                entry.stateless_reset_token = reset_token;
                return;
            }
        }
        // Pool full — drop silently
    }

    pub fn consumeUnused(self: *ConnectionIdPool) ?*ConnectionIdEntry {
        for (&self.entries) |*entry| {
            if (entry.occupied and !entry.in_use) {
                entry.in_use = true;
                return entry;
            }
        }
        return null;
    }

    pub fn retirePriorTo(self: *ConnectionIdPool, seq: u64) void {
        for (&self.entries) |*entry| {
            if (entry.occupied and entry.seq_num < seq) {
                entry.* = ConnectionIdEntry{};
            }
        }
    }

    pub fn removeBySeq(self: *ConnectionIdPool, seq: u64) void {
        for (&self.entries) |*entry| {
            if (entry.occupied and entry.seq_num == seq) {
                entry.* = ConnectionIdEntry{};
                return;
            }
        }
    }

    pub fn count(self: *const ConnectionIdPool) usize {
        var n: usize = 0;
        for (&self.entries) |*entry| {
            if (entry.occupied) n += 1;
        }
        return n;
    }
};

/// Tracks a locally-issued connection ID (RFC 9000 §5.1).
pub const LocalCidEntry = struct {
    cid_buf: [20]u8 = .{0} ** 20,
    cid_len: u8 = 0,
    seq_num: u64 = 0,
    stateless_reset_token: [16]u8 = .{0} ** 16,
    occupied: bool = false,
    retired: bool = false,

    pub fn getCid(self: *const LocalCidEntry) []const u8 {
        return self.cid_buf[0..self.cid_len];
    }
};

/// Pool of locally-issued connection IDs (RFC 9000 §5.1).
/// Seq 0 = initial SCID. New CIDs issued via issueNewCid().
pub const LocalCidPool = struct {
    const MAX_POOL_SIZE: usize = 8;

    entries: [MAX_POOL_SIZE]LocalCidEntry = .{LocalCidEntry{}} ** MAX_POOL_SIZE,
    next_seq_num: u64 = 1,
    retire_prior_to: u64 = 0,

    /// Register the initial SCID as sequence number 0.
    /// If static_key is provided, compute a deterministic reset token; otherwise random.
    pub fn registerInitialCid(self: *LocalCidPool, cid: []const u8, static_key: ?[16]u8) void {
        self.entries[0] = LocalCidEntry{
            .occupied = true,
            .retired = false,
            .seq_num = 0,
            .cid_len = @intCast(cid.len),
        };
        @memcpy(self.entries[0].cid_buf[0..cid.len], cid);
        if (static_key) |key| {
            self.entries[0].stateless_reset_token = stateless_reset.computeToken(key, cid);
        } else {
            crypto.random.bytes(&self.entries[0].stateless_reset_token);
        }
    }

    /// Issue a new CID with the given length. Returns the entry or null if pool full.
    /// If static_key is provided, compute a deterministic reset token; otherwise random.
    pub fn issueNewCid(self: *LocalCidPool, cid_len: u8, static_key: ?[16]u8) ?*const LocalCidEntry {
        // Find a free slot
        for (&self.entries) |*entry| {
            if (!entry.occupied) {
                entry.occupied = true;
                entry.retired = false;
                entry.seq_num = self.next_seq_num;
                entry.cid_len = cid_len;
                generateConnectionId(entry.cid_buf[0..cid_len]);
                if (static_key) |key| {
                    entry.stateless_reset_token = stateless_reset.computeToken(key, entry.cid_buf[0..cid_len]);
                } else {
                    crypto.random.bytes(&entry.stateless_reset_token);
                }
                self.next_seq_num += 1;
                return entry;
            }
        }
        return null;
    }

    /// Mark an entry as retired by sequence number.
    pub fn retireBySeq(self: *LocalCidPool, seq: u64) void {
        for (&self.entries) |*entry| {
            if (entry.occupied and entry.seq_num == seq) {
                entry.occupied = false;
                entry.retired = true;
                return;
            }
        }
    }

    /// Count active (occupied, non-retired) entries.
    pub fn activeCount(self: *const LocalCidPool) usize {
        var n: usize = 0;
        for (&self.entries) |*entry| {
            if (entry.occupied and !entry.retired) n += 1;
        }
        return n;
    }
};

/// Fixed-capacity queue for QUIC DATAGRAM frames (RFC 9221).
/// Stores up to 16 datagrams, each up to MAX_DATAGRAM_SIZE bytes.
pub const DatagramQueue = struct {
    pub const MAX_ITEMS: usize = 16;
    pub const MAX_DATAGRAM_SIZE: usize = 1200;

    bufs: [MAX_ITEMS][MAX_DATAGRAM_SIZE]u8 = undefined,
    lens: [MAX_ITEMS]usize = .{0} ** MAX_ITEMS,
    head: usize = 0,
    tail: usize = 0,
    count: usize = 0,

    pub fn push(self: *DatagramQueue, data: []const u8) bool {
        if (self.count >= MAX_ITEMS or data.len > MAX_DATAGRAM_SIZE) return false;
        @memcpy(self.bufs[self.tail][0..data.len], data);
        self.lens[self.tail] = data.len;
        self.tail = (self.tail + 1) % MAX_ITEMS;
        self.count += 1;
        return true;
    }

    pub fn pop(self: *DatagramQueue, out: []u8) ?usize {
        if (self.count == 0) return null;
        const len = self.lens[self.head];
        if (out.len < len) return null;
        @memcpy(out[0..len], self.bufs[self.head][0..len]);
        self.head = (self.head + 1) % MAX_ITEMS;
        self.count -= 1;
        return len;
    }

    pub fn isEmpty(self: *const DatagramQueue) bool {
        return self.count == 0;
    }
};

pub const ConnectionError = struct {
    is_app: bool,
    code: u64,
    reason: []const u8,
};

// ECN codepoint values from IP TOS field (2 low bits)
pub const ECN_NOT_ECT: u2 = 0b00;
pub const ECN_ECT1: u2 = 0b01;
pub const ECN_ECT0: u2 = 0b10;
pub const ECN_CE: u2 = 0b11;

pub const RecvInfo = struct {
    to: posix.sockaddr,
    from: posix.sockaddr,
    // ECN codepoint from IP header (0=Not-ECT, 1=ECT(1), 2=ECT(0), 3=CE)
    ecn: u2 = ECN_NOT_ECT,
};

/// Configuration for a QUIC connection.
pub const ConnectionConfig = struct {
    max_idle_timeout: u64 = 30_000, // ms
    initial_max_data: u64 = 16_777_216, // 16MB
    initial_max_stream_data_bidi_local: u64 = 6_291_456, // 6MB
    initial_max_stream_data_bidi_remote: u64 = 6_291_456, // 6MB
    initial_max_stream_data_uni: u64 = 1_048_576, // 1MB
    initial_max_streams_bidi: u64 = 100,
    initial_max_streams_uni: u64 = 100,
    max_datagram_frame_size: ?u64 = null,
    preferred_address: ?transport_params.PreferredAddress = null,
    // Key for NEW_TOKEN generation (server) — should match the Retry token key
    token_key: ?[16]u8 = null,
    // Enable Compatible Version Negotiation to QUIC v2 (RFC 9368/9369)
    enable_v2: bool = false,
    // Disable Path MTU Discovery (PMTUD)
    disable_pmtud: bool = false,
};

/// A QUIC connection.
///
/// This is the central state machine that manages the QUIC protocol.
/// Following quic-go's architecture, the connection runs an event-driven
/// loop that processes received packets, handles timers, and sends data.
pub const Connection = struct {
    version: u32 = undefined,
    is_server: bool,
    state: State = .first_flight,
    allocator: std.mem.Allocator,

    // Connection IDs
    dcid: [packet.CONNECTION_ID_MAX_SIZE]u8 = .{0} ** packet.CONNECTION_ID_MAX_SIZE,
    dcid_len: u8 = 0,
    scid: [packet.CONNECTION_ID_MAX_SIZE]u8 = .{0} ** packet.CONNECTION_ID_MAX_SIZE,
    scid_len: u8 = 0,

    // TLS 1.3 handshake (null if not configured with TlsConfig)
    tls13_hs: ?tls13.Tls13Handshake = null,

    // Network paths (active + candidate for migration)
    paths: [2]NetworkPath = .{ undefined, undefined },
    active_path_idx: u8 = 0,
    path_initialized: bool = false,

    // Packet number spaces and crypto
    pkt_num_spaces: [3]packet.PacketNumSpace = .{
        packet.PacketNumSpace{},
        packet.PacketNumSpace{},
        packet.PacketNumSpace{},
    },

    // New subsystems
    pkt_handler: ack_handler.PacketHandler = undefined,
    cc: congestion.NewReno = congestion.NewReno.init(),
    pacer: congestion.Pacer = congestion.Pacer.init(),
    conn_flow_ctrl: flow_control.ConnectionFlowController = undefined,
    streams: stream_mod.StreamsMap = undefined,
    crypto_streams: crypto_stream.CryptoStreamManager = undefined,
    packer: packet_packer.PacketPacker = undefined,

    // Transport parameters
    local_params: transport_params.TransportParams = .{},
    peer_params: ?transport_params.TransportParams = null,

    // Pending control frames queue
    pending_frames: frame_mod.PendingFrameQueue = .{},

    // Pool of peer-issued connection IDs for migration
    peer_cid_pool: ConnectionIdPool = .{},

    // Pool of locally-issued connection IDs (RFC 9000 §5.1)
    local_cid_pool: LocalCidPool = .{},

    // Static key for deterministic stateless reset tokens (RFC 9000 §10.3)
    static_reset_key: [16]u8 = .{0} ** 16,

    // Key update manager for 1-RTT key rotation (RFC 9001 Section 6)
    key_update: ?quic_crypto.KeyUpdateManager = null,

    // Whether PMTUD is disabled
    disable_pmtud: bool = false,

    // Path MTU Discovery (DPLPMTUD, RFC 8899)
    mtu_discoverer: mtu_mod.MtuDiscoverer = .{},

    // QUIC DATAGRAM support (RFC 9221)
    datagram_recv_queue: DatagramQueue = .{},
    datagram_send_queue: DatagramQueue = .{},
    datagrams_enabled: bool = false,

    // 0-RTT (early data) keys
    early_data_open: ?quic_crypto.Open = null, // Server: decrypt 0-RTT packets
    early_data_seal: ?quic_crypto.Seal = null, // Client: encrypt 0-RTT packets

    // Session ticket received from server (readable by application)
    session_ticket: ?tls13.SessionTicket = null,

    // NEW_TOKEN received from server (client stores for reuse in future connections)
    new_token_buf: [packet.TOKEN_MAX_LEN]u8 = .{0} ** packet.TOKEN_MAX_LEN,
    new_token_len: u8 = 0,

    // Token key for NEW_TOKEN generation (server, shared with retry_token_key)
    token_key: [16]u8 = .{0} ** 16,

    // ECN validation: peer-reported ECN counts from ACK_ECN frames (RFC 9000 §13.4.2.1)
    // Track per-space to detect increases; only Application space matters in practice
    peer_ecn_ect0: [3]u64 = .{ 0, 0, 0 },
    peer_ecn_ect1: [3]u64 = .{ 0, 0, 0 },
    peer_ecn_ce: [3]u64 = .{ 0, 0, 0 },

    // ECN validation state machine (RFC 9000 §13.4.2.1)
    ecn_validator: ecn.EcnValidator = .{},

    // Connection state
    got_peer_conn_id: bool = false,
    peer_max_cid_seq: u64 = 0,
    active_cid_seq: u64 = 0,
    local_err: ?ConnectionError = null,
    handshake_confirmed: bool = false,
    spin_bit: bool = false, // Spin bit for passive RTT measurement (RFC 9000 §17.4)
    largest_pn_received: ?u64 = null, // Tracks largest 1-RTT PN for spin bit toggling
    enable_v2: bool = false, // Compatible Version Negotiation (RFC 9368/9369)
    // DCID used for initial key derivation (needed for v2 re-derivation)
    initial_dcid_buf: [packet.CONNECTION_ID_MAX_SIZE]u8 = .{0} ** packet.CONNECTION_ID_MAX_SIZE,
    initial_dcid_len: u8 = 0,

    // Connection close state (RFC 9000 Section 10)
    closing_start_time: i64 = 0,
    close_pkt_buf: [256]u8 = undefined,
    close_pkt_len: u16 = 0,
    needs_close_retransmit: bool = false,

    // Retry state (client-side)
    odcid_buf: [packet.CONNECTION_ID_MAX_SIZE]u8 = .{0} ** packet.CONNECTION_ID_MAX_SIZE,
    odcid_len: u8 = 0,
    retry_received: bool = false,
    retry_token_buf: [256]u8 = .{0} ** 256,
    retry_token_len: u16 = 0,

    // Timing
    last_packet_received_time: i64 = 0,
    creation_time: i64 = 0,
    idle_timeout_ns: i64 = 30_000_000_000, // 30s default

    pub fn accept(
        allocator: std.mem.Allocator,
        header: packet.Header,
        local: posix.sockaddr,
        remote: posix.sockaddr,
        comptime is_server: bool,
        config: ConnectionConfig,
        tls_config: ?tls13.TlsConfig,
        odcid: ?[]const u8,
        retry_scid: ?[]const u8,
    ) !Connection {
        var initial_path = NetworkPath.init(local, remote, true);
        // If Retry was used, the path is already validated
        if (odcid != null) {
            initial_path.is_validated = true;
        }
        const now: i64 = @intCast(std.time.nanoTimestamp());

        var conn = Connection{
            .allocator = allocator,
            .version = header.version,
            .is_server = is_server,
            .paths = .{ initial_path, undefined },
            .path_initialized = true,
            .creation_time = now,
            .last_packet_received_time = now,

            // Initialize new subsystems
            .pkt_handler = ack_handler.PacketHandler.init(allocator),
            .conn_flow_ctrl = flow_control.ConnectionFlowController.init(
                config.initial_max_data,
                6 * 1024 * 1024, // 6MB max
            ),
            .streams = stream_mod.StreamsMap.init(allocator, is_server),
            .crypto_streams = crypto_stream.CryptoStreamManager.init(allocator),
        };

        // Set connection IDs:
        // Server: dcid = client's SCID (for sending TO client), scid = our generated CID
        // Client: dcid = header.dcid, scid = header.scid
        if (is_server) {
            conn.dcid_len = @intCast(header.scid.len);
            @memcpy(conn.dcid[0..header.scid.len], header.scid);
            conn.scid_len = 8;
            generateConnectionId(conn.scid[0..8]);
            conn.got_peer_conn_id = true;
        } else {
            conn.dcid_len = @intCast(header.dcid.len);
            @memcpy(conn.dcid[0..header.dcid.len], header.dcid);
            conn.scid_len = @intCast(header.scid.len);
            @memcpy(conn.scid[0..header.scid.len], header.scid);
        }

        // Generate static reset key for deterministic tokens
        crypto.random.bytes(&conn.static_reset_key);

        // Register initial SCID in local CID pool with deterministic token
        conn.local_cid_pool.registerInitialCid(conn.scid[0..conn.scid_len], conn.static_reset_key);

        // For Retry: use the original DCID (before Retry) for the transport param
        const tp_odcid = odcid orelse (if (is_server) header.dcid else null);

        // Server SHOULD include stateless_reset_token for the initial SCID (RFC 9000 §18.2)
        const reset_token: ?[16]u8 = if (is_server) conn.local_cid_pool.entries[0].stateless_reset_token else null;

        // Build transport params AFTER CIDs are stored in conn (to avoid dangling slices)
        var local_params: transport_params.TransportParams = .{
            .original_destination_connection_id = tp_odcid,
            .initial_source_connection_id = conn.scid[0..conn.scid_len],
            .retry_source_connection_id = retry_scid,
            .stateless_reset_token = reset_token,
            .max_idle_timeout = config.max_idle_timeout,
            .initial_max_data = config.initial_max_data,
            .initial_max_stream_data_bidi_local = config.initial_max_stream_data_bidi_local,
            .initial_max_stream_data_bidi_remote = config.initial_max_stream_data_bidi_remote,
            .initial_max_stream_data_uni = config.initial_max_stream_data_uni,
            .initial_max_streams_bidi = config.initial_max_streams_bidi,
            .initial_max_streams_uni = config.initial_max_streams_uni,
            .max_datagram_frame_size = config.max_datagram_frame_size,
            // Server's preferred address (RFC 9000 §9.6) — only for servers, must not coexist with disable_active_migration
            .preferred_address = if (is_server and config.preferred_address != null) config.preferred_address else null,
        };

        // RFC 9368: Include version_information transport parameter when v2 is enabled
        if (config.enable_v2) {
            local_params.version_info_chosen = header.version; // v1 for client, may be updated by server
            local_params.version_info_available = .{ protocol.QUIC_V2, protocol.QUIC_V1, 0, 0, 0, 0, 0, 0 };
            local_params.version_info_available_count = 2;
        }

        conn.local_params = local_params;
        conn.enable_v2 = config.enable_v2;
        conn.disable_pmtud = config.disable_pmtud;

        // Initialize TLS 1.3 handshake if config provided
        if (tls_config) |tc| {
            var tc_versioned = tc;
            tc_versioned.quic_version = conn.version;
            conn.tls13_hs = if (is_server)
                tls13.Tls13Handshake.initServer(tc_versioned, local_params)
            else
                tls13.Tls13Handshake.initClient(tc_versioned, local_params);
        }

        // Store the DCID used for initial key derivation (needed for v2 re-derivation)
        conn.initial_dcid_len = @intCast(header.dcid.len);
        @memcpy(conn.initial_dcid_buf[0..header.dcid.len], header.dcid);

        // Set up initial crypto keys (always use header.dcid for key derivation)
        try conn.pkt_num_spaces[@intFromEnum(packet.Epoch.initial)].setupInitial(
            header.dcid,
            header.version,
            is_server,
        );

        // Initialize the packet packer
        conn.packer = packet_packer.PacketPacker.init(
            allocator,
            is_server,
            conn.scid[0..conn.scid_len],
            conn.dcid[0..conn.dcid_len],
            header.version,
        );

        // Set token key for NEW_TOKEN generation (server)
        if (config.token_key) |tk| {
            conn.token_key = tk;
        }

        // Configure stream limits
        conn.streams.setMaxIncomingStreams(
            config.initial_max_streams_bidi,
            config.initial_max_streams_uni,
        );

        // Set initial send window from connection flow control
        conn.conn_flow_ctrl.base.send_window = config.initial_max_data;

        if (config.max_idle_timeout > 0) {
            conn.idle_timeout_ns = @as(i64, @intCast(config.max_idle_timeout)) * 1_000_000;
        }

        return conn;
    }

    pub fn deinit(self: *Connection) void {
        self.pkt_handler.deinit();
        self.streams.deinit();
        self.crypto_streams.deinit();
    }

    /// Handle a Retry packet (client only).
    /// Verifies the integrity tag, saves ODCID, re-derives Initial keys with new DCID,
    /// and resets crypto stream so the same ClientHello is re-sent.
    pub fn handleRetryPacket(self: *Connection, header: *const packet.Header, raw_packet: []const u8) !void {
        // Only accept one Retry, only before handshake progresses
        if (self.retry_received or self.state != .first_flight) {
            std.log.warn("ignoring Retry: retry_received={}, state={}", .{ self.retry_received, @intFromEnum(self.state) });
            return;
        }

        // Verify integrity tag using the ODCID (which is the initial DCID we sent to)
        const odcid = self.odcid_buf[0..self.odcid_len];
        const valid = packet.verifyRetryIntegrity(raw_packet, odcid, self.version) catch {
            std.log.err("Retry integrity check error", .{});
            return;
        };
        if (!valid) {
            std.log.warn("Retry integrity tag verification failed", .{});
            return;
        }

        // Update DCID to the Retry packet's SCID
        self.dcid_len = @intCast(header.scid.len);
        @memcpy(self.dcid[0..header.scid.len], header.scid);
        self.packer.updateDcid(header.scid);

        // Store the Retry token for inclusion in the next Initial packet
        if (header.token) |token| {
            if (token.len <= self.retry_token_buf.len) {
                @memcpy(self.retry_token_buf[0..token.len], token);
                self.retry_token_len = @intCast(token.len);
                // Point the packer's initial_token to our owned buffer
                self.packer.initial_token = self.retry_token_buf[0..self.retry_token_len];
            } else {
                std.log.err("Retry token too large ({d} bytes, max {d})", .{ token.len, self.retry_token_buf.len });
            }
        } else {
            std.log.warn("Retry packet has no token", .{});
        }

        // Re-derive Initial keys with the new DCID (Retry SCID)
        try self.pkt_num_spaces[0].setupInitial(
            self.dcid[0..self.dcid_len],
            self.version,
            false, // client
        );

        // Reset packet number so the next Initial starts from 0
        self.pkt_num_spaces[0].next_packet_number = 0;

        // Reset the crypto stream send offset to re-send the same ClientHello
        self.crypto_streams.getStream(0).resetSendOffset();

        self.retry_received = true;
        self.got_peer_conn_id = false; // will pick up server's SCID from ServerHello

        std.log.info("Retry handled: new DCID={any}, token_len={d}", .{
            self.dcid[0..self.dcid_len],
            self.retry_token_len,
        });
    }

    /// Process a received packet.
    pub fn recv(self: *Connection, header: *packet.Header, fbs: anytype, info: RecvInfo) !void {
        // Guard: don't process packets in terminal states (RFC 9000 §10)
        if (self.state == .terminated) return;
        if (self.state == .draining) {
            self.last_packet_received_time = @intCast(std.time.nanoTimestamp());
            return;
        }
        if (self.state == .closing) {
            self.needs_close_retransmit = true;
            self.last_packet_received_time = @intCast(std.time.nanoTimestamp());
            return;
        }

        // Intercept Retry packets before normal processing (client only)
        if (header.packet_type == .retry) {
            if (!self.is_server) {
                try self.handleRetryPacket(header, fbs.buffer[header.packet_start..fbs.buffer.len]);
            }
            return;
        }

        const epoch = try packet.Epoch.fromPacketType(header.packet_type);
        std.log.debug("recv: packet_type={s}, epoch={s}", .{ @tagName(header.packet_type), @tagName(epoch) });

        // RFC 9368: Client-side Compatible Version Negotiation detection
        // If we receive an Initial/Handshake from the server with a different version
        // than what we sent, and we advertised that version, switch to it.
        if (!self.is_server and self.enable_v2 and header.version != 0 and header.version != self.version) {
            if (protocol.isSupportedVersion(header.version)) {
                std.log.info("recv: compatible version negotiation detected, switching to 0x{x:0>8}", .{header.version});
                try self.switchVersion(header.version);
            }
        }

        // 0-RTT packets use the application PN space but with early data keys
        if (epoch == packet.Epoch.zero_rtt) {
            if (self.early_data_open == null) {
                std.log.info("recv: dropping 0-RTT packet (no early data keys)", .{});
                return;
            }

            // 0-RTT uses pkt_num_spaces[2] (application) for PN tracking
            var space = self.pkt_num_spaces[2];
            var early_open = self.early_data_open.?;
            // Temporarily install early keys in the space for decryption
            const saved_open = space.crypto_open;
            space.crypto_open = early_open;
            const payload = packet.decrypt(header, fbs, space) catch |err| {
                std.log.err("can't decrypt 0-RTT packet. {any}", .{err});
                space.crypto_open = saved_open;
                return error.InvalidPacket;
            };
            space.crypto_open = saved_open;
            _ = &early_open;

            if (payload.len == 0) return error.InvalidPacket;

            const now: i64 = @intCast(std.time.nanoTimestamp());
            self.last_packet_received_time = now;
            self.paths[self.active_path_idx].bytes_received += @intCast(fbs.buffer.len);

            // Process 0-RTT frames (STREAM, DATAGRAM etc. - no CRYPTO or HANDSHAKE_DONE)
            var remaining = payload;
            var ack_eliciting = false;
            while (remaining.len > 0) {
                if (remaining[0] == 0x00) { remaining = remaining[1..]; continue; }
                const frame = Frame.parse(remaining) catch break;
                // Enforce frame-in-correct-space (RFC 9000 §12.5)
                if (!frame.isAllowedIn(.zero_rtt)) {
                    std.log.warn("frame {s} not allowed in 0-RTT packet, closing", .{@tagName(frame)});
                    return error.ProtocolViolation;
                }
                if (frame.isAckEliciting()) ack_eliciting = true;
                try self.processFrame(frame, .application, now);
                const consumed = self.frameSize(frame, remaining);
                if (consumed == 0) break;
                remaining = remaining[consumed..];
            }
            try self.pkt_handler.onPacketReceived(.application, header.packet_number, ack_eliciting, now, info.ecn);
            if (header.packet_number + 1 > self.pkt_num_spaces[2].next_packet_number) {
                self.pkt_num_spaces[2].next_packet_number = header.packet_number + 1;
            }
            if (self.state == .first_flight) self.state = .handshake;
            try self.advanceHandshake();
            return;
        }

        const enc_level = epochToEncLevel(epoch);
        const space_idx = @intFromEnum(enc_level);
        var space = self.pkt_num_spaces[space_idx];
        const has_keys = space.crypto_open != null and space.crypto_seal != null;
        std.log.debug("recv: using space {d} ({s}), has_keys={}", .{ space_idx, @tagName(enc_level), has_keys });

        if (!has_keys) {
            std.log.info("recv: dropping packet for {s} (keys not available)", .{@tagName(enc_level)});
            return;
        }

        // For 1-RTT packets with key update manager, use the appropriate key generation
        var payload: []u8 = undefined;
        if (epoch == .application and self.key_update != null) {
            // Decrypt using KeyUpdateManager: first do header unprotection with the
            // (unchanging) HP key, then select the right AEAD key based on key phase
            payload = packet.decryptWithKeyUpdate(header, fbs, &space, &self.key_update.?) catch {
                // Undecryptable 1-RTT packets are silently dropped (RFC 9001 §6.3).
                std.log.warn("silently dropping 1-RTT packet (key update decrypt failed) pn_space_next={d}", .{space.next_packet_number});
                return;
            };
        } else {
            payload = packet.decrypt(header, fbs, space) catch {
                // Silently drop undecryptable packets
                std.log.warn("silently dropping packet enc_level={s}", .{@tagName(enc_level)});
                return;
            };
        }

        if (payload.len == 0) {
            return error.InvalidPacket;
        }

        const now: i64 = @intCast(std.time.nanoTimestamp());
        self.last_packet_received_time = now;

        // Handle key phase change for 1-RTT packets (RFC 9001 Section 6)
        if (epoch == .application) {
            if (self.key_update) |*ku| {
                if (header.key_phase != ku.key_phase and ku.first_acked_with_current) {
                    // Peer initiated a key update (RFC 9001 §6.1)
                    // Only roll if we've confirmed the peer has our current keys
                    // (first_acked_with_current=true). Otherwise the mismatch is
                    // just an in-flight packet from before our own key update.
                    const pto_ns = self.pkt_handler.rtt_stats.pto();
                    ku.rollKeys(now, pto_ns);
                    self.packer.key_phase = ku.key_phase;
                    std.log.info("key update: peer-initiated, new key_phase={}", .{ku.key_phase});
                }
                ku.maybeDropPrevKeys(now);
            }
        }

        // Spin bit handling (RFC 9000 §17.4) for 1-RTT packets only
        if (epoch == .application) {
            const is_new_largest = self.largest_pn_received == null or header.packet_number > self.largest_pn_received.?;
            if (is_new_largest) {
                self.largest_pn_received = header.packet_number;
                if (self.is_server) {
                    // Server: reflect the spin bit from the client
                    self.spin_bit = header.spin_bit;
                } else {
                    // Client: invert the spin bit on each new largest PN
                    self.spin_bit = !header.spin_bit;
                }
                self.packer.spin_bit = self.spin_bit;
            }
        }

        // Update network path stats
        self.paths[self.active_path_idx].bytes_received += @intCast(fbs.buffer.len);

        // Check for duplicate
        if (self.pkt_handler.recv[@intFromEnum(enc_level)].isDuplicate(header.packet_number)) {
            return; // Duplicate, ignore
        }

        // Determine path - set peer connection ID on first packet
        if (!self.got_peer_conn_id and header.scid.len > 0) {
            std.log.info("recv: updating DCID to peer SCID={any}", .{header.scid});
            self.dcid_len = @intCast(header.scid.len);
            @memcpy(self.dcid[0..header.scid.len], header.scid);
            // Update packer with new DCID
            self.packer.updateDcid(header.scid);
            self.got_peer_conn_id = true;
        }

        // Process all frames from the decrypted payload
        var ack_eliciting = false;
        var has_non_probing = false;
        var remaining = payload;

        while (remaining.len > 0) {
            // Skip padding
            if (remaining[0] == 0x00) {
                remaining = remaining[1..];
                continue;
            }

            const frame = Frame.parse(remaining) catch |err| {
                std.log.err("Failed to parse frame: {}", .{err});
                break;
            };

            std.log.debug("recv: parsed frame type={s}", .{@tagName(frame)});

            // Enforce frame-in-correct-space (RFC 9000 §12.5)
            if (!frame.isAllowedIn(header.packet_type)) {
                std.log.warn("frame {s} not allowed in {s} packet, closing", .{ @tagName(frame), @tagName(header.packet_type) });
                return error.ProtocolViolation;
            }

            if (frame.isAckEliciting()) {
                ack_eliciting = true;
            }
            if (!frame.isProbing()) {
                has_non_probing = true;
            }

            try self.processFrame(frame, epoch, now);

            // Advance past this frame. For frames that contain data slices,
            // figure out where they end in the buffer.
            const consumed = self.frameSize(frame, remaining);
            if (consumed == 0) break; // safety: avoid infinite loop
            remaining = remaining[consumed..];
        }

        // Record receipt for ACK generation
        try self.pkt_handler.onPacketReceived(enc_level, header.packet_number, ack_eliciting, now, info.ecn);

        // Update expected packet number for correct decoding of subsequent packets
        // (critical for coalesced packets where multiple packets share a datagram)
        if (header.packet_number + 1 > self.pkt_num_spaces[space_idx].next_packet_number) {
            self.pkt_num_spaces[space_idx].next_packet_number = header.packet_number + 1;
        }

        // Initialize path on first received packet (client-side: connect() doesn't know server addr)
        if (!self.path_initialized) {
            self.paths[self.active_path_idx] = NetworkPath.init(info.to, info.from, true);
            self.path_initialized = true;
        }

        // Detect connection migration (RFC 9000 Section 9)
        // Only for 1-RTT packets after handshake is confirmed, with non-probing frames
        if (epoch == .application and self.handshake_confirmed and has_non_probing) {
            const active_path = &self.paths[self.active_path_idx];
            if (!sockaddrEql(&info.from, &active_path.peer_addr)) {
                std.log.info("connection migration detected from new peer address", .{});
                self.handleMigration(info.from, info.to, now);
            }
        }

        // Update connection state
        if (self.state == .first_flight and epoch == .initial) {
            self.state = .handshake;
        }

        // After processing crypto frames, try advancing the handshake
        try self.advanceHandshake();
    }

    /// Queue CRYPTO frame retransmission by resetting the crypto stream's send offset.
    /// This causes the packer to re-send all crypto data at the given level (RFC 9002 §6.2).
    fn queueCryptoRetransmission(self: *Connection, level: ack_handler.EncLevel) void {
        const crypto_idx: u8 = switch (level) {
            .initial => 0,
            .handshake => 2,
            .application => 3,
        };
        const cs = self.crypto_streams.getStream(crypto_idx);
        if (cs.write_offset > 0) {
            cs.resetSendOffset();
        }
    }

    /// Queue retransmission for stream frames that were in a lost packet.
    fn queueStreamRetransmissions(self: *Connection, pkt: *const ack_handler.SentPacket) void {
        for (pkt.getStreamFrames()) |sf| {
            // Look up the stream and queue the retransmission
            if (stream_mod.isBidi(sf.stream_id)) {
                if (self.streams.getStream(sf.stream_id)) |s| {
                    if (s.send.reset_err == null) {
                        s.send.queueRetransmit(sf.offset, sf.length, sf.fin);
                    }
                }
            } else {
                // Unidirectional send stream
                if (self.streams.send_streams.get(sf.stream_id)) |s| {
                    if (s.reset_err == null) {
                        s.queueRetransmit(sf.offset, sf.length, sf.fin);
                    }
                }
            }
        }
    }

    /// Process a single frame.
    pub fn processFrame(self: *Connection, frame: Frame, epoch: packet.Epoch, now: i64) !void {
        switch (frame) {
            .padding => {},
            .ping => {},

            .ack => |ack| {
                const enc_level = epochToEncLevel(epoch);
                const peer_tp = self.peer_params orelse transport_params.TransportParams{};
                const result = try self.pkt_handler.onAckReceived(
                    enc_level,
                    ack.largest_ack,
                    ack.ack_delay,
                    @intCast(peer_tp.ack_delay_exponent),
                    ack.ack_ranges[0..ack.ack_range_count],
                    ack.first_ack_range,
                    now,
                );

                // Notify congestion controller, track key update ACKs, and PMTUD
                var has_non_probe_loss = false;
                var earliest_lost_sent_time: ?i64 = null;
                for (result.acked.constSlice()) |pkt| {
                    // Check if this is an MTU probe ACK
                    if (self.mtu_discoverer.onProbeAcked(pkt.pn, now)) {
                        // Probe succeeded — update packet size and congestion controller
                        const new_mtu = self.mtu_discoverer.current_mtu;
                        self.packer.max_packet_size = new_mtu;
                        self.cc.setMaxDatagramSize(new_mtu);
                        self.pacer.max_datagram_size = new_mtu;
                        std.log.info("PMTUD: probe ACK'd, MTU raised to {d}", .{new_mtu});
                    }

                    self.cc.onPacketAcked(pkt.size, pkt.time_sent);

                    // Track whether a packet sent with current keys has been ACKed
                    if (enc_level == .application) {
                        if (self.key_update) |*ku| {
                            if (ku.first_sent_with_current) |first_pn| {
                                if (pkt.pn >= first_pn) {
                                    ku.first_acked_with_current = true;
                                }
                            }
                        }
                    }
                }

                for (result.lost.constSlice()) |pkt| {
                    // Check if this is an MTU probe loss — don't trigger CC
                    if (self.mtu_discoverer.onProbeLost(pkt.pn, now)) {
                        std.log.info("PMTUD: probe lost pn={d}", .{pkt.pn});
                    } else {
                        has_non_probe_loss = true;
                        if (earliest_lost_sent_time == null or pkt.time_sent < earliest_lost_sent_time.?) {
                            earliest_lost_sent_time = pkt.time_sent;
                        }
                    }

                    // Queue stream data retransmission for lost packets
                    self.queueStreamRetransmissions(&pkt);

                    // Queue CRYPTO frame retransmission for lost packets (RFC 9002 §6.2)
                    if (pkt.has_crypto_data) {
                        self.queueCryptoRetransmission(pkt.enc_level);
                    }
                }

                if (has_non_probe_loss) {
                    if (result.persistent_congestion) {
                        self.cc.onPersistentCongestion();
                        std.log.info("persistent congestion detected, window reduced to minimum", .{});
                    } else if (earliest_lost_sent_time) |lost_time| {
                        self.cc.onCongestionEvent(lost_time, now);
                    }
                }

                // Update pacer
                self.pacer.setBandwidth(self.cc.sendWindow(), &self.pkt_handler.rtt_stats);
            },

            .ack_ecn => |ack| {
                const enc_level = epochToEncLevel(epoch);
                const space_idx = @intFromEnum(enc_level);
                const peer_tp = self.peer_params orelse transport_params.TransportParams{};
                const result = try self.pkt_handler.onAckReceived(
                    enc_level,
                    ack.largest_ack,
                    ack.ack_delay,
                    @intCast(peer_tp.ack_delay_exponent),
                    ack.ack_ranges[0..ack.ack_range_count],
                    ack.first_ack_range,
                    now,
                );

                // Notify congestion controller, track key update ACKs, and PMTUD
                var has_non_probe_loss = false;
                var earliest_lost_sent_time_ecn: ?i64 = null;
                for (result.acked.constSlice()) |pkt| {
                    if (self.mtu_discoverer.onProbeAcked(pkt.pn, now)) {
                        const new_mtu = self.mtu_discoverer.current_mtu;
                        self.packer.max_packet_size = new_mtu;
                        self.cc.setMaxDatagramSize(new_mtu);
                        self.pacer.max_datagram_size = new_mtu;
                        std.log.info("PMTUD: probe ACK'd, MTU raised to {d}", .{new_mtu});
                    }
                    self.cc.onPacketAcked(pkt.size, pkt.time_sent);

                    if (enc_level == .application) {
                        if (self.key_update) |*ku| {
                            if (ku.first_sent_with_current) |first_pn| {
                                if (pkt.pn >= first_pn) {
                                    ku.first_acked_with_current = true;
                                }
                            }
                        }
                    }
                }

                for (result.lost.constSlice()) |pkt| {
                    if (self.mtu_discoverer.onProbeLost(pkt.pn, now)) {
                        std.log.info("PMTUD: probe lost pn={d}", .{pkt.pn});
                    } else {
                        has_non_probe_loss = true;
                        if (earliest_lost_sent_time_ecn == null or pkt.time_sent < earliest_lost_sent_time_ecn.?) {
                            earliest_lost_sent_time_ecn = pkt.time_sent;
                        }
                    }

                    // Queue stream data retransmission for lost packets
                    self.queueStreamRetransmissions(&pkt);

                    // Queue CRYPTO frame retransmission for lost packets (RFC 9002 §6.2)
                    if (pkt.has_crypto_data) {
                        self.queueCryptoRetransmission(pkt.enc_level);
                    }
                }

                if (has_non_probe_loss) {
                    if (result.persistent_congestion) {
                        self.cc.onPersistentCongestion();
                        std.log.info("persistent congestion detected, window reduced to minimum", .{});
                    } else if (earliest_lost_sent_time_ecn) |lost_time| {
                        self.cc.onCongestionEvent(lost_time, now);
                    }
                }

                // ECN validation (RFC 9000 §13.4.2.1):
                // Count how many newly-acked packets were ECN-marked
                var newly_acked_ect0: u64 = 0;
                for (result.acked.constSlice()) |pkt| {
                    if (pkt.ecn_marked) newly_acked_ect0 += 1;
                }

                // Validate ECN counts from peer
                const ecn_valid = self.ecn_validator.validate(
                    ack.ecn_ect0,
                    ack.ecn_ect1,
                    ack.ecn_ce,
                    self.peer_ecn_ect0[space_idx],
                    self.peer_ecn_ect1[space_idx],
                    self.peer_ecn_ce[space_idx],
                    newly_acked_ect0,
                );

                // If valid and CE count increased, treat as congestion event
                if (ecn_valid and ack.ecn_ce > self.peer_ecn_ce[space_idx]) {
                    std.log.info("ECN: CE count increased {d} -> {d}, congestion signal", .{ self.peer_ecn_ce[space_idx], ack.ecn_ce });
                    self.cc.onCongestionEvent(now, now);
                }
                self.peer_ecn_ect0[space_idx] = ack.ecn_ect0;
                self.peer_ecn_ect1[space_idx] = ack.ecn_ect1;
                self.peer_ecn_ce[space_idx] = ack.ecn_ce;

                // Update pacer
                self.pacer.setBandwidth(self.cc.sendWindow(), &self.pkt_handler.rtt_stats);
            },

            .reset_stream => |rs| {
                if (self.streams.getStream(rs.stream_id)) |s| {
                    s.recv.handleResetStream(rs.error_code, rs.final_size);
                    // If send side is also done, stream is fully closed
                    if (s.send.fin_sent or s.send.reset_err != null) {
                        self.streams.closeStream(rs.stream_id);
                    }
                }
            },

            .stop_sending => |ss| {
                if (self.streams.getStream(ss.stream_id)) |s| {
                    s.send.reset(ss.error_code);
                }
            },

            .crypto => |crypto_frame| {
                const level: u8 = @intFromEnum(epoch);
                try self.crypto_streams.handleCryptoFrame(level, crypto_frame.offset, crypto_frame.data);
                // Handshake advancement happens after all frames are processed
            },

            .new_token => |token| {
                // Client stores the token for reuse in future connections (RFC 9000 §8.1.3)
                if (!self.is_server and token.len <= self.new_token_buf.len) {
                    @memcpy(self.new_token_buf[0..token.len], token);
                    self.new_token_len = @intCast(token.len);
                    std.log.info("stored NEW_TOKEN from server ({d} bytes)", .{token.len});
                }
            },

            .stream => |s| {
                if (stream_mod.isBidi(s.stream_id)) {
                    // Bidirectional stream
                    const strm = self.streams.getOrCreateStream(s.stream_id) catch |err| {
                        std.log.err("Failed to get/create stream {}: {}", .{ s.stream_id, err });
                        return;
                    };
                    try strm.recv.handleStreamFrame(s.offset, s.data, s.fin);

                    // Check if stream is fully closed (both directions done)
                    if (s.fin and (strm.send.fin_sent or strm.send.reset_err != null)) {
                        self.streams.closeStream(s.stream_id);
                    }
                } else {
                    // Unidirectional stream — route to recv_streams
                    const recv_strm = self.streams.getOrCreateRecvStream(s.stream_id) catch |err| {
                        std.log.err("Failed to get/create recv stream {}: {}", .{ s.stream_id, err });
                        return;
                    };
                    try recv_strm.handleStreamFrame(s.offset, s.data, s.fin);

                    // For incoming uni streams, FIN means the stream is done
                    if (s.fin) {
                        self.streams.closeStream(s.stream_id);
                    }
                }

                // Update flow control
                try self.conn_flow_ctrl.base.addBytesReceived(s.offset + s.data.len);
                self.conn_flow_ctrl.addBytesRead(s.data.len);
            },

            .max_data => |max| {
                self.conn_flow_ctrl.updateSendWindow(max);
            },

            .max_stream_data => |msd| {
                if (self.streams.getStream(msd.stream_id)) |s| {
                    s.send.updateSendWindow(msd.max);
                }
            },

            .max_streams_bidi => |max| {
                self.streams.setMaxStreams(max, self.streams.max_uni_streams);
            },

            .max_streams_uni => |max| {
                self.streams.setMaxStreams(self.streams.max_bidi_streams, max);
            },

            .data_blocked => {},
            .stream_data_blocked => {},
            .streams_blocked_bidi => {
                // Peer is blocked — respond with our current MAX_STREAMS limit
                if (self.streams.max_incoming_bidi_streams > 0) {
                    self.pending_frames.push(.{ .max_streams_bidi = self.streams.max_incoming_bidi_streams });
                }
            },
            .streams_blocked_uni => {
                // Peer is blocked — respond with our current MAX_STREAMS limit
                if (self.streams.max_incoming_uni_streams > 0) {
                    self.pending_frames.push(.{ .max_streams_uni = self.streams.max_incoming_uni_streams });
                }
            },

            .new_connection_id => |ncid| {
                if (ncid.seq_num > self.peer_max_cid_seq) {
                    self.peer_max_cid_seq = ncid.seq_num;
                }

                // Retire old CIDs as requested by peer
                if (ncid.retire_prior_to > self.active_cid_seq) {
                    var seq = self.active_cid_seq;
                    while (seq < ncid.retire_prior_to) : (seq += 1) {
                        self.pending_frames.push(.{ .retire_connection_id = seq });
                    }
                    self.active_cid_seq = ncid.retire_prior_to;
                    self.peer_cid_pool.retirePriorTo(ncid.retire_prior_to);
                }

                // Store CID in pool for future migration use
                self.peer_cid_pool.addPeerCid(ncid.seq_num, ncid.conn_id, ncid.stateless_reset_token);
                std.log.info("stored peer CID in pool from NEW_CONNECTION_ID seq={d}, pool_size={d}", .{ ncid.seq_num, self.peer_cid_pool.count() });

                // Update DCID if this is a new active CID
                if (ncid.seq_num >= self.active_cid_seq) {
                    self.packer.updateDcid(ncid.conn_id);
                    std.log.info("updated DCID from NEW_CONNECTION_ID seq={d}", .{ncid.seq_num});
                }
            },

            .retire_connection_id => |rcid| {
                std.log.info("peer retired connection ID seq={d}", .{rcid.seq_num});
                self.local_cid_pool.retireBySeq(rcid.seq_num);

                // Issue a replacement CID to stay at the peer's limit
                const peer_limit = if (self.peer_params) |pp| pp.active_connection_id_limit else 2;
                if (self.local_cid_pool.activeCount() < peer_limit) {
                    if (self.local_cid_pool.issueNewCid(self.scid_len, self.static_reset_key)) |entry| {
                        self.pending_frames.push(.{ .new_connection_id = .{
                            .seq_num = entry.seq_num,
                            .retire_prior_to = self.local_cid_pool.retire_prior_to,
                            .cid_buf = entry.cid_buf,
                            .cid_len = entry.cid_len,
                            .stateless_reset_token = entry.stateless_reset_token,
                        } });
                        std.log.info("issued replacement NEW_CONNECTION_ID seq={d}", .{entry.seq_num});
                    }
                }
            },

            .path_challenge => |data| {
                self.pending_frames.push(.{ .path_response = data });
            },

            .path_response => |data| {
                for (&self.paths) |*path| {
                    if (path.validator.handleResponse(data)) {
                        path.is_validated = true;
                        std.log.info("path validated via PATH_RESPONSE", .{});
                        break;
                    }
                }
            },

            .connection_close => |cc| {
                std.log.err("CONNECTION_CLOSE: error_code=0x{x}, frame_type=0x{x}, reason_len={d}, reason={s}", .{
                    cc.error_code,
                    cc.frame_type,
                    cc.reason.len,
                    if (cc.reason.len > 0) cc.reason else "none",
                });
                self.state = .draining;
                self.closing_start_time = now;
                self.local_err = .{
                    .is_app = false,
                    .code = cc.error_code,
                    .reason = cc.reason,
                };
            },

            .application_close => |ac| {
                self.state = .draining;
                self.closing_start_time = now;
                self.local_err = .{
                    .is_app = true,
                    .code = ac.error_code,
                    .reason = ac.reason,
                };
            },

            .handshake_done => {
                self.handshake_confirmed = true;
                self.state = .connected;
                self.ecn_validator.start();

                // Drop Initial and Handshake packet number spaces
                self.pkt_handler.dropSpace(.initial);
                self.pkt_handler.dropSpace(.handshake);
            },

            .datagram => |d| {
                if (self.datagrams_enabled) {
                    _ = self.datagram_recv_queue.push(d.data);
                }
            },

            .datagram_with_length => |d| {
                if (self.datagrams_enabled) {
                    _ = self.datagram_recv_queue.push(d.data);
                }
            },
        }
    }

    /// Calculate how many bytes a parsed frame occupies in the raw buffer.
    fn frameSize(self: *const Connection, frame: Frame, buf: []const u8) usize {
        _ = self;
        _ = frame;
        // Create a temporary stream to measure how far parsing advances
        var fbs = std.io.fixedBufferStream(@constCast(buf));
        const reader = fbs.reader();
        const frame_type = packet.readVarInt(reader) catch return 1;

        switch (frame_type) {
            0x00 => {
                // Padding - already skipped in caller, just 1 byte
                return 1;
            },
            0x01 => return fbs.pos, // ping: just the type byte
            0x02, 0x03 => {
                // ACK/ACK_ECN
                _ = packet.readVarInt(reader) catch return fbs.pos; // largest_ack
                _ = packet.readVarInt(reader) catch return fbs.pos; // ack_delay
                const range_count = packet.readVarInt(reader) catch return fbs.pos;
                _ = packet.readVarInt(reader) catch return fbs.pos; // first_ack_range
                var i: u64 = 0;
                while (i < range_count) : (i += 1) {
                    _ = packet.readVarInt(reader) catch return fbs.pos;
                    _ = packet.readVarInt(reader) catch return fbs.pos;
                }
                if (frame_type == 0x03) {
                    _ = packet.readVarInt(reader) catch return fbs.pos; // ect0
                    _ = packet.readVarInt(reader) catch return fbs.pos; // ect1
                    _ = packet.readVarInt(reader) catch return fbs.pos; // ce
                }
                return fbs.pos;
            },
            0x04 => {
                // reset_stream
                _ = packet.readVarInt(reader) catch return fbs.pos;
                _ = packet.readVarInt(reader) catch return fbs.pos;
                _ = packet.readVarInt(reader) catch return fbs.pos;
                return fbs.pos;
            },
            0x05 => {
                // stop_sending
                _ = packet.readVarInt(reader) catch return fbs.pos;
                _ = packet.readVarInt(reader) catch return fbs.pos;
                return fbs.pos;
            },
            0x06 => {
                // crypto
                _ = packet.readVarInt(reader) catch return fbs.pos; // offset
                const length = packet.readVarInt(reader) catch return fbs.pos;
                return fbs.pos + @as(usize, @intCast(length));
            },
            0x07 => {
                // new_token
                const len = packet.readVarInt(reader) catch return fbs.pos;
                return fbs.pos + @as(usize, @intCast(len));
            },
            0x08...0x0f => {
                // stream
                const type_byte: u8 = @intCast(frame_type);
                _ = packet.readVarInt(reader) catch return fbs.pos; // stream_id
                if ((type_byte & 0x04) != 0) {
                    _ = packet.readVarInt(reader) catch return fbs.pos; // offset
                }
                if ((type_byte & 0x02) != 0) {
                    const data_len = packet.readVarInt(reader) catch return fbs.pos;
                    return fbs.pos + @as(usize, @intCast(data_len));
                } else {
                    // No length field - rest of packet is data
                    return buf.len;
                }
            },
            0x10 => {
                _ = packet.readVarInt(reader) catch return fbs.pos;
                return fbs.pos;
            },
            0x11 => {
                _ = packet.readVarInt(reader) catch return fbs.pos;
                _ = packet.readVarInt(reader) catch return fbs.pos;
                return fbs.pos;
            },
            0x12, 0x13, 0x14 => {
                _ = packet.readVarInt(reader) catch return fbs.pos;
                return fbs.pos;
            },
            0x15 => {
                _ = packet.readVarInt(reader) catch return fbs.pos;
                _ = packet.readVarInt(reader) catch return fbs.pos;
                return fbs.pos;
            },
            0x16, 0x17 => {
                _ = packet.readVarInt(reader) catch return fbs.pos;
                return fbs.pos;
            },
            0x18 => {
                // new_connection_id
                _ = packet.readVarInt(reader) catch return fbs.pos;
                _ = packet.readVarInt(reader) catch return fbs.pos;
                const cid_len = reader.readByte() catch return fbs.pos;
                fbs.seekBy(cid_len) catch return fbs.pos;
                fbs.seekBy(16) catch return fbs.pos; // stateless reset token
                return fbs.pos;
            },
            0x19 => {
                _ = packet.readVarInt(reader) catch return fbs.pos;
                return fbs.pos;
            },
            0x1a, 0x1b => {
                fbs.seekBy(8) catch return fbs.pos;
                return fbs.pos;
            },
            0x1c => {
                // connection_close
                _ = packet.readVarInt(reader) catch return fbs.pos;
                _ = packet.readVarInt(reader) catch return fbs.pos;
                const len = packet.readVarInt(reader) catch return fbs.pos;
                return fbs.pos + @as(usize, @intCast(len));
            },
            0x1d => {
                // application_close
                _ = packet.readVarInt(reader) catch return fbs.pos;
                const len = packet.readVarInt(reader) catch return fbs.pos;
                return fbs.pos + @as(usize, @intCast(len));
            },
            0x1e => return fbs.pos, // handshake_done
            0x30 => return buf.len, // datagram without length - rest of packet
            0x31 => {
                // datagram with length
                const len = packet.readVarInt(reader) catch return fbs.pos;
                return fbs.pos + @as(usize, @intCast(len));
            },
            else => return buf.len, // unknown - consume rest
        }
    }

    /// Advance the TLS 1.3 handshake by reading contiguous crypto data.
    fn advanceHandshake(self: *Connection) !void {
        // Allow post-handshake messages (NST) even after handshake_confirmed
        var hs = &(self.tls13_hs orelse return);

        // If handshake is confirmed, only feed application-level crypto data for NST
        if (self.handshake_confirmed) {
            const cs = self.crypto_streams.getStream(3); // application level
            var got_data = false;
            while (cs.read()) |data| {
                defer self.allocator.free(data);
                hs.provideData(data);
                got_data = true;
            }
            if (got_data) {
                var nst_iters: usize = 0;
                while (nst_iters < 10) : (nst_iters += 1) {
                    const action = hs.step() catch break;
                    switch (action) {
                        .complete => {
                            if (hs.received_ticket) |ticket| {
                                self.session_ticket = ticket;
                                std.log.info("stored session ticket from server (lifetime={d}s)", .{ticket.lifetime});
                            }
                            break;
                        },
                        ._continue => continue,
                        else => break,
                    }
                }
            }
            return;
        }

        std.log.info("advanceHandshake: state={}, iterations starting", .{@intFromEnum(hs.state)});

        // Feed crypto stream data to the handshake
        inline for ([_]u8{ 0, 2, 3 }) |level| {
            const cs = self.crypto_streams.getStream(level);
            var crypto_data_count: usize = 0;
            while (cs.read()) |data| {
                defer self.allocator.free(data);
                crypto_data_count += 1;
                std.log.info("advanceHandshake: feeding crypto level={} data len={}", .{ level, data.len });
                hs.provideData(data);
            }
            if (crypto_data_count > 0) {
                std.log.info("advanceHandshake: fed {d} crypto frames from level {}", .{ crypto_data_count, level });
            }
        }

        // Drive the state machine until it needs more data or completes
        var iterations: usize = 0;
        while (iterations < 50) {
            iterations += 1;
            const action = hs.step() catch |err| {
                std.log.err("TLS 1.3 handshake error: {}", .{err});
                return;
            };
            std.log.info("advanceHandshake: step {d} produced action={s}", .{ iterations, @tagName(action) });

            switch (action) {
                .send_data => |sd| {
                    // Write the TLS handshake data to the appropriate crypto stream
                    const cs_level: u8 = @intFromEnum(sd.level);
                    const cs = self.crypto_streams.getStream(cs_level);
                    std.log.info("advanceHandshake: writing {d} bytes to level {}", .{ sd.data.len, cs_level });
                    try cs.writeData(sd.data);
                },
                .install_keys => |ik| {
                    switch (ik.level) {
                        .early_data => {
                            if (self.is_server) {
                                self.early_data_open = ik.open;
                                std.log.info("installed 0-RTT decrypt keys (server)", .{});
                            } else {
                                self.early_data_seal = ik.seal;
                                // Pre-set stream limits for 0-RTT (RFC 9000 §7.4.1: use remembered
                                // transport params). Since we don't persist transport params across
                                // connections yet, use reasonable defaults so the app can open streams.
                                self.streams.setMaxStreams(100, 100);
                                std.log.info("installed 0-RTT encrypt keys (client), set default stream limits", .{});
                            }
                        },
                        .handshake => {
                            self.installHandshakeKeys(ik.open, ik.seal);
                            // RFC 9368: After TLS negotiation, check if version switched
                            if (self.is_server and self.enable_v2) {
                                if (hs.config.quic_version != self.version) {
                                    try self.switchVersion(hs.config.quic_version);
                                }
                            }
                        },
                        .application => self.installAppKeys(ik.open, ik.seal),
                        else => {},
                    }
                },
                .wait_for_data => break,
                .complete => {
                    self.state = .connected;
                    self.handshake_confirmed = true;
                    self.ecn_validator.start();
                    self.paths[self.active_path_idx].is_validated = true;
                    self.pkt_handler.dropSpace(.initial);
                    self.pkt_handler.dropSpace(.handshake);

                    // Clear early data keys (0-RTT period is over)
                    self.early_data_open = null;
                    self.early_data_seal = null;

                    // Clear Initial encryption keys so we stop sending padded Initial packets
                    self.pkt_num_spaces[0].crypto_open = null;
                    self.pkt_num_spaces[0].crypto_seal = null;

                    if (self.is_server) {
                        // Server clears Handshake keys (Finished already sent)
                        self.pkt_num_spaces[1].crypto_open = null;
                        self.pkt_num_spaces[1].crypto_seal = null;

                        // Server must send HANDSHAKE_DONE to the client (RFC 9001 Section 4.1.2)
                        self.packer.send_handshake_done = true;
                    }
                    // Client: Handshake keys cleared in client.zig after sending Finished

                    // Store received session ticket if any
                    if (hs.received_ticket) |ticket| {
                        self.session_ticket = ticket;
                        std.log.info("stored session ticket (lifetime={d}s)", .{ticket.lifetime});
                    }

                    // Initialize KeyUpdateManager from TLS traffic secrets (RFC 9001 Section 6)
                    if (hs.key_schedule.computed_app) {
                        const recv_secret = if (self.is_server)
                            hs.key_schedule.client_app_traffic_secret
                        else
                            hs.key_schedule.server_app_traffic_secret;
                        const send_secret = if (self.is_server)
                            hs.key_schedule.server_app_traffic_secret
                        else
                            hs.key_schedule.client_app_traffic_secret;

                        // Get HP keys from current app-level Open/Seal (they never change)
                        const app_open = self.pkt_num_spaces[2].crypto_open.?;
                        const app_seal = self.pkt_num_spaces[2].crypto_seal.?;

                        self.key_update = quic_crypto.KeyUpdateManager.initFull(
                            recv_secret,
                            send_secret,
                            app_open.hp_key,
                            app_seal.hp_key,
                            hs.negotiated_cipher_suite,
                            self.version,
                        );
                        std.log.info("KeyUpdateManager initialized for 1-RTT key rotation", .{});
                    }

                    // Store peer transport parameters and apply stream limits
                    if (hs.peer_transport_params) |peer_tp| {
                        self.peer_params = peer_tp;

                        // Client-side: validate ODCID and retry_scid transport params (RFC 9000 §7.3)
                        if (!self.is_server) {
                            // original_destination_connection_id must match the DCID we initially sent
                            if (peer_tp.original_destination_connection_id) |peer_odcid| {
                                if (!std.mem.eql(u8, peer_odcid, self.odcid_buf[0..self.odcid_len])) {
                                    std.log.err("transport param validation failed: ODCID mismatch", .{});
                                    return error.TransportParameterError;
                                }
                            } else {
                                std.log.err("transport param validation failed: server must send ODCID", .{});
                                return error.TransportParameterError;
                            }

                            // If Retry was used, retry_source_connection_id must be present
                            // If not, it must be absent
                            if (self.retry_received) {
                                if (peer_tp.retry_source_connection_id == null) {
                                    std.log.err("transport param validation failed: retry_scid missing after Retry", .{});
                                    return error.TransportParameterError;
                                }
                            } else {
                                if (peer_tp.retry_source_connection_id != null) {
                                    std.log.err("transport param validation failed: retry_scid present without Retry", .{});
                                    return error.TransportParameterError;
                                }
                            }
                        }

                        self.streams.setMaxStreams(
                            peer_tp.initial_max_streams_bidi,
                            peer_tp.initial_max_streams_uni,
                        );
                        self.streams.setPeerInitialMaxStreamData(
                            peer_tp.initial_max_stream_data_bidi_local,
                            peer_tp.initial_max_stream_data_bidi_remote,
                            peer_tp.initial_max_stream_data_uni,
                        );
                        self.conn_flow_ctrl.base.send_window = peer_tp.initial_max_data;

                        // Enable DATAGRAM support if both sides advertise max_datagram_frame_size
                        if (peer_tp.max_datagram_frame_size != null and self.local_params.max_datagram_frame_size != null) {
                            self.datagrams_enabled = true;
                            std.log.info("DATAGRAM support enabled (peer max_dgram={d}, local max_dgram={d})", .{
                                peer_tp.max_datagram_frame_size.?,
                                self.local_params.max_datagram_frame_size.?,
                            });
                        }

                        // Negotiate idle timeout: use min of local and peer when both non-zero (RFC 9000 §10.1)
                        if (peer_tp.max_idle_timeout > 0 and self.local_params.max_idle_timeout > 0) {
                            const effective_ms = @min(peer_tp.max_idle_timeout, self.local_params.max_idle_timeout);
                            self.idle_timeout_ns = @as(i64, @intCast(effective_ms)) * 1_000_000;
                        } else if (peer_tp.max_idle_timeout > 0) {
                            self.idle_timeout_ns = @as(i64, @intCast(peer_tp.max_idle_timeout)) * 1_000_000;
                        }
                        // else: keep local timeout (already set)

                        // Store peer's stateless reset token for initial CID (RFC 9000 §10.3.1)
                        // Server sends this in transport params; client stores it for detection
                        if (peer_tp.stateless_reset_token) |token| {
                            self.peer_cid_pool.addPeerCid(0, self.dcid[0..self.dcid_len], token);
                            std.log.info("stored peer stateless reset token from transport params", .{});
                        }

                        std.log.info("applied peer transport params: max_bidi={d}, max_uni={d}, max_data={d}", .{
                            peer_tp.initial_max_streams_bidi,
                            peer_tp.initial_max_streams_uni,
                            peer_tp.initial_max_data,
                        });

                        // Client: migrate to server's preferred address (RFC 9000 §9.6)
                        if (!self.is_server) {
                            if (peer_tp.preferred_address) |pref| {
                                if (!peer_tp.disable_active_migration) {
                                    // Store preferred CID + reset token in peer CID pool
                                    self.peer_cid_pool.addPeerCid(1, pref.getCid(), pref.stateless_reset_token);

                                    // Build sockaddr from preferred IPv4 (prefer v4 for now)
                                    const pref_addr = if (pref.hasIpv4()) pref.toSockaddrV4() else pref.toSockaddrV6();

                                    // Set up candidate path
                                    const candidate_idx: u8 = 1 - self.active_path_idx;
                                    self.paths[candidate_idx] = NetworkPath.init(
                                        self.paths[self.active_path_idx].local_addr,
                                        pref_addr,
                                        false,
                                    );

                                    // Switch active path
                                    self.active_path_idx = candidate_idx;

                                    // Update packer DCID to preferred CID
                                    if (self.peer_cid_pool.consumeUnused()) |entry| {
                                        self.packer.updateDcid(entry.getCid());
                                        std.log.info("preferred_address: using CID seq={d}", .{entry.seq_num});
                                    }

                                    // Start PATH_CHALLENGE
                                    const challenge = self.paths[candidate_idx].validator.startChallenge();
                                    self.pending_frames.push(.{ .path_challenge = challenge });

                                    // Reset CC/RTT/MTU/ECN for new IP
                                    self.cc = congestion.NewReno.init();
                                    self.pacer = congestion.Pacer.init();
                                    self.pkt_handler.rtt_stats = rtt.RttStats{};
                                    self.mtu_discoverer.reset();
                                    self.packer.max_packet_size = mtu_mod.BASE_PLPMTU;
                                    self.ecn_validator.reset();

                                    std.log.info("preferred_address: migrating to {s} port {d}", .{
                                        if (pref.hasIpv4()) "IPv4" else "IPv6",
                                        if (pref.hasIpv4()) pref.ipv4_port else pref.ipv6_port,
                                    });
                                }
                            }
                        }
                    }

                    // Issue NEW_CONNECTION_ID frames up to peer's active_connection_id_limit (RFC 9000 §5.1)
                    {
                        const peer_limit = if (self.peer_params) |pp| pp.active_connection_id_limit else 2;
                        while (self.local_cid_pool.activeCount() < peer_limit) {
                            if (self.local_cid_pool.issueNewCid(self.scid_len, self.static_reset_key)) |entry| {
                                self.pending_frames.push(.{ .new_connection_id = .{
                                    .seq_num = entry.seq_num,
                                    .retire_prior_to = self.local_cid_pool.retire_prior_to,
                                    .cid_buf = entry.cid_buf,
                                    .cid_len = entry.cid_len,
                                    .stateless_reset_token = entry.stateless_reset_token,
                                } });
                                std.log.info("issued NEW_CONNECTION_ID seq={d}, cid_len={d}", .{ entry.seq_num, entry.cid_len });
                            } else break; // pool full
                        }
                    }

                    // Server: issue NEW_TOKEN for client address validation (RFC 9000 §8.1.3)
                    if (self.is_server) {
                        var nt_buf: [packet.TOKEN_MAX_LEN]u8 = undefined;
                        const nt_len = packet.generateNewToken(
                            &nt_buf,
                            self.paths[self.active_path_idx].peer_addr,
                            self.token_key,
                        ) catch 0;
                        if (nt_len > 0) {
                            var pcf: frame_mod.PendingControlFrame = .{ .new_token = .{} };
                            @memcpy(pcf.new_token.token_buf[0..nt_len], nt_buf[0..nt_len]);
                            pcf.new_token.token_len = @intCast(nt_len);
                            self.pending_frames.push(pcf);
                            std.log.info("issued NEW_TOKEN ({d} bytes)", .{nt_len});
                        }
                    }

                    // Start PMTUD now that the handshake is complete
                    if (!self.disable_pmtud) self.mtu_discoverer.start();

                    break;
                },
                ._continue => continue,
            }
        }
    }

    /// Install handshake-level encryption keys.
    /// Called when the TLS handshake produces Handshake-level secrets.
    /// Switch the connection to a new QUIC version (Compatible Version Negotiation, RFC 9368).
    /// Re-derives Initial keys asymmetrically:
    /// - Server: keeps v1 open keys (to decrypt client retransmissions), switches seal to v2
    /// - Client: switches open keys to v2 (to decrypt server's v2 response), keeps v1 seal
    /// Handshake/Application keys are already correct (TLS derives them with the new version's labels).
    pub fn switchVersion(self: *Connection, new_version: u32) !void {
        const old_version = self.version;
        self.version = new_version;

        // Re-derive Initial keys with the new version's salt
        const dcid = self.initial_dcid_buf[0..self.initial_dcid_len];
        const space = &self.pkt_num_spaces[@intFromEnum(packet.Epoch.initial)];
        if (self.is_server) {
            // Server: only switch seal keys to v2 (keep v1 open for client retransmissions)
            const saved_open = space.crypto_open;
            const keys = try quic_crypto.deriveInitialKeyMaterial(dcid, new_version, true);
            space.crypto_open = saved_open; // restore v1 open
            space.crypto_seal = keys[1]; // v2 seal
        } else {
            // Client: only switch open keys to v2 (keep v1 seal, though we won't send more Initials)
            const saved_seal = space.crypto_seal;
            const keys = try quic_crypto.deriveInitialKeyMaterial(dcid, new_version, false);
            space.crypto_open = keys[0]; // v2 open
            space.crypto_seal = saved_seal; // restore v1 seal
        }

        // Update packet packer version
        self.packer.version = new_version;

        // Update TLS config version so handshake/app key derivation uses v2 HKDF labels
        if (self.tls13_hs) |*hs| {
            hs.config.quic_version = new_version;
        }

        std.log.info("switchVersion: 0x{x:0>8} -> 0x{x:0>8}", .{ old_version, new_version });
    }

    pub fn installHandshakeKeys(self: *Connection, open: quic_crypto.Open, seal: quic_crypto.Seal) void {
        // Packet number space index 1 = Handshake
        self.pkt_num_spaces[1].crypto_open = open;
        self.pkt_num_spaces[1].crypto_seal = seal;
        std.log.info("installHandshakeKeys: keys installed for space 1", .{});
    }

    /// Install 1-RTT (Application) encryption keys.
    /// Called when the TLS handshake produces application-level secrets.
    pub fn installAppKeys(self: *Connection, open: quic_crypto.Open, seal: quic_crypto.Seal) void {
        // Packet number space index 2 = Application (1-RTT)
        self.pkt_num_spaces[2].crypto_open = open;
        self.pkt_num_spaces[2].crypto_seal = seal;
        std.log.info("installAppKeys: keys installed for space 2", .{});
    }

    /// Check if connection-level flow control needs a MAX_DATA or MAX_STREAMS update.
    fn queueFlowControlUpdates(self: *Connection) void {
        if (self.conn_flow_ctrl.getWindowUpdate(&self.pkt_handler.rtt_stats)) |new_max| {
            self.pending_frames.push(.{ .max_data = new_max });
        }

        // Check if MAX_STREAMS updates are needed (sliding window)
        const ms_update = self.streams.getMaxStreamsUpdates();
        if (ms_update.bidi) |new_max| {
            self.pending_frames.push(.{ .max_streams_bidi = new_max });
        }
        if (ms_update.uni) |new_max| {
            self.pending_frames.push(.{ .max_streams_uni = new_max });
        }

        // DATA_BLOCKED: signal peer when connection-level flow control blocks sending (RFC 9000 §4.1)
        if (self.conn_flow_ctrl.base.shouldSendBlocked()) |limit| {
            self.pending_frames.push(.{ .data_blocked = limit });
        }

        // STREAM_DATA_BLOCKED: signal peer when stream-level flow control blocks sending
        var stream_it = self.streams.streams.valueIterator();
        while (stream_it.next()) |s_ptr| {
            const s: *stream_mod.Stream = s_ptr.*;
            if (s.send.shouldSendBlocked()) |limit| {
                self.pending_frames.push(.{ .stream_data_blocked = .{
                    .stream_id = s.stream_id,
                    .limit = limit,
                } });
            }
        }
    }

    /// Build and send outgoing packets.
    pub fn send(self: *Connection, out_buf: []u8) !usize {
        // Draining/terminated: do not send anything
        if (self.state == .draining or self.state == .terminated) return 0;

        const now: i64 = @intCast(std.time.nanoTimestamp());

        // Closing: retransmit saved close packet on each incoming packet (RFC 9000 §10.2.1)
        if (self.state == .closing) {
            if (self.close_pkt_len > 0) {
                // Already built the close packet
                if (self.needs_close_retransmit) {
                    // Retransmit saved close packet
                    self.needs_close_retransmit = false;
                    const len = self.close_pkt_len;
                    @memcpy(out_buf[0..len], self.close_pkt_buf[0..len]);
                    return len;
                }
                // Not triggered by incoming packet — just waiting for timeout
                return 0;
            }

            // First time: build close packet at best available encryption level
            const app_seal: ?quic_crypto.Seal = if (self.key_update) |*ku|
                ku.current_seal
            else
                self.pkt_num_spaces[2].crypto_seal;
            const handshake_seal = self.pkt_num_spaces[1].crypto_seal;
            const initial_seal = self.pkt_num_spaces[0].crypto_seal;

            // Try 1-RTT, then Handshake, then Initial
            const seal = app_seal orelse handshake_seal orelse initial_seal;
            if (seal != null) {
                const bytes_written = try self.packer.packCoalesced(
                    out_buf,
                    &self.pkt_handler,
                    &self.crypto_streams,
                    &self.streams,
                    &self.pending_frames,
                    if (app_seal == null and handshake_seal == null) initial_seal else null,
                    null,
                    if (app_seal == null) handshake_seal else null,
                    app_seal,
                    now,
                    null,
                    false, // not ack_only — sending CONNECTION_CLOSE
                );
                if (bytes_written > 0) {
                    // Save close packet for retransmission
                    const save_len: u16 = @intCast(@min(bytes_written, self.close_pkt_buf.len));
                    @memcpy(self.close_pkt_buf[0..save_len], out_buf[0..save_len]);
                    self.close_pkt_len = save_len;
                }
                return bytes_written;
            }
            return 0;
        }

        // Check if pacer allows sending
        const pacer_delay = self.pacer.timeUntilSend(now);
        if (pacer_delay > 0) {
            return 0;
        }

        // Check congestion window
        if (self.pkt_handler.bytes_in_flight >= self.cc.sendWindow()) {
            // Congestion limited - only send ACKs
            std.log.info("send: congestion-limited bif={d} cwnd={d}", .{ self.pkt_handler.bytes_in_flight, self.cc.sendWindow() });
            return try self.sendAckOnly(out_buf, now);
        }

        // Queue flow control updates before packing
        self.queueFlowControlUpdates();

        // Check if we should proactively initiate a key update (RFC 9001 Section 6)
        if (self.key_update) |*ku| {
            if (ku.shouldInitiateUpdate() and ku.canUpdate()) {
                const pto_ns = self.pkt_handler.rtt_stats.pto();
                ku.rollKeys(now, pto_ns);
                self.packer.key_phase = ku.key_phase;
                std.log.info("key update: self-initiated at {d} packets, new key_phase={}", .{
                    quic_crypto.CONFIDENTIALITY_LIMIT,
                    ku.key_phase,
                });
            }
        }

        // Anti-amplification: servers must not send more than 3x bytes received
        // before address validation (RFC 9000 Section 8.1)
        if (self.is_server) {
            const active_path = &self.paths[self.active_path_idx];
            if (!active_path.canSend(1200)) {
                return 0;
            }
        }

        // Build coalesced packet with available encryption levels
        // Packet number space indices: 0=Initial, 1=Handshake, 2=Application
        const initial_seal = self.pkt_num_spaces[0].crypto_seal;
        const handshake_seal = self.pkt_num_spaces[1].crypto_seal;
        // Use KeyUpdateManager seal for 1-RTT if available
        const app_seal: ?quic_crypto.Seal = if (self.key_update) |*ku|
            ku.current_seal
        else
            self.pkt_num_spaces[2].crypto_seal;

        // 0-RTT seal (client only, before handshake completes)
        const early_seal = if (!self.handshake_confirmed) self.early_data_seal else null;

        const dq: ?*DatagramQueue = if (self.datagrams_enabled and !self.datagram_send_queue.isEmpty())
            &self.datagram_send_queue
        else
            null;

        self.packer.conn_flow_ctrl = &self.conn_flow_ctrl;
        const bytes_written = try self.packer.packCoalesced(
            out_buf,
            &self.pkt_handler,
            &self.crypto_streams,
            &self.streams,
            &self.pending_frames,
            initial_seal,
            early_seal,
            handshake_seal,
            app_seal,
            now,
            dq,
            false, // ack_only
        );

        if (bytes_written > 0) {
            self.paths[self.active_path_idx].bytes_sent += bytes_written;
            self.pacer.onPacketSent(bytes_written, now);

            // Client: auto-clear Handshake keys once Finished has been packed and sent
            // (RFC 9001 §4.9.2: discard Handshake keys when handshake is confirmed)
            if (!self.is_server and self.handshake_confirmed and self.pkt_num_spaces[1].crypto_seal != null) {
                if (!self.crypto_streams.getStream(1).hasData()) {
                    self.dropHandshakeKeys();
                }
            }

            // Track packets sent with current keys for key update
            if (self.key_update) |*ku| {
                if (app_seal != null) {
                    const app_idx = @intFromEnum(ack_handler.EncLevel.application);
                    const pn = self.pkt_handler.next_pn[app_idx];
                    if (pn > 0) ku.onPacketSent(pn - 1);
                }
            }

            // Track ECN marking for sent packets
            if (self.ecn_validator.shouldMark() and app_seal != null) {
                self.ecn_validator.onPacketSent();
            }
        }

        // PMTUD: send a probe if it's time (separate datagram from regular data)
        if (app_seal != null and bytes_written == 0) {
            const srtt = self.pkt_handler.rtt_stats.smoothedRttOrDefault();
            if (self.mtu_discoverer.shouldProbe(now, srtt)) {
                const probe_size: usize = self.mtu_discoverer.nextProbeSize();
                if (out_buf.len >= probe_size) {
                    const result = try self.packer.packMtuProbe(
                        out_buf,
                        probe_size,
                        &self.pkt_handler,
                        app_seal.?,
                        now,
                    );
                    if (result.bytes_written > 0) {
                        self.mtu_discoverer.onProbeSent(result.pn, @intCast(probe_size), now);
                        self.paths[self.active_path_idx].bytes_sent += result.bytes_written;
                        std.log.info("PMTUD: sent probe size={d} pn={d}", .{ probe_size, result.pn });
                        return result.bytes_written;
                    }
                }
            }
        }

        // Check PMTUD raise timer
        self.mtu_discoverer.checkRaiseTimer(now);

        return bytes_written;
    }

    /// Send ACK-only packets (when congestion limited).
    /// ACKs are NOT congestion-controlled per RFC 9000 §13.2.
    fn sendAckOnly(self: *Connection, out_buf: []u8, now: i64) !usize {
        // Piggyback flow control updates (MAX_DATA, MAX_STREAMS)
        self.queueFlowControlUpdates();

        // Anti-amplification: servers must not send more than 3x bytes received
        if (self.is_server) {
            const active_path = &self.paths[self.active_path_idx];
            if (!active_path.canSend(1200)) {
                return 0;
            }
        }

        // Gather seals at all encryption levels
        const initial_seal = self.pkt_num_spaces[0].crypto_seal;
        const handshake_seal = self.pkt_num_spaces[1].crypto_seal;
        const app_seal: ?quic_crypto.Seal = if (self.key_update) |*ku|
            ku.current_seal
        else
            self.pkt_num_spaces[2].crypto_seal;

        const bytes_written = try self.packer.packCoalesced(
            out_buf,
            &self.pkt_handler,
            &self.crypto_streams,
            &self.streams,
            &self.pending_frames,
            initial_seal,
            null, // no 0-RTT for ACK-only
            handshake_seal,
            app_seal,
            now,
            null, // no datagrams
            true, // ack_only
        );

        if (bytes_written > 0) {
            self.paths[self.active_path_idx].bytes_sent += bytes_written;
            // Don't update pacer — ACKs are not paced
        }

        return bytes_written;
    }

    /// Handle connection migration (RFC 9000 Section 9).
    /// Called when a 1-RTT packet with non-probing frames arrives from a different address.
    fn handleMigration(self: *Connection, new_peer_addr: posix.sockaddr, local_addr: posix.sockaddr, now: i64) void {
        // Check if peer disabled active migration
        if (self.peer_params) |pp| {
            if (pp.disable_active_migration) {
                std.log.info("migration: peer disabled active migration, ignoring", .{});
                return;
            }
        }

        // Set up candidate path at the alternate index
        const candidate_idx: u8 = 1 - self.active_path_idx;
        self.paths[candidate_idx] = NetworkPath.init(local_addr, new_peer_addr, false);

        // Try to consume a fresh CID for the new path
        if (self.peer_cid_pool.consumeUnused()) |entry| {
            self.packer.updateDcid(entry.getCid());
            std.log.info("migration: switched to new peer CID seq={d}", .{entry.seq_num});
        }

        // Switch active path
        self.active_path_idx = candidate_idx;

        // Start path validation via PATH_CHALLENGE
        const challenge = self.paths[candidate_idx].validator.startChallenge();
        self.pending_frames.push(.{ .path_challenge = challenge });

        // Reset CC/RTT/MTU/ECN if IP address changed (not just port — NAT rebinding preserves CC)
        const old_path = &self.paths[1 - candidate_idx];
        if (!sockaddrSameIp(&new_peer_addr, &old_path.peer_addr)) {
            self.cc = congestion.NewReno.init();
            self.pacer = congestion.Pacer.init();
            self.pkt_handler.rtt_stats = rtt.RttStats{};
            self.mtu_discoverer.reset();
            self.packer.max_packet_size = mtu_mod.BASE_PLPMTU;
            self.ecn_validator.reset();
            std.log.info("migration: IP changed, reset CC, RTT, MTU and ECN", .{});
        } else {
            std.log.info("migration: port-only change (NAT rebinding), preserving CC", .{});
        }

        _ = now;
    }

    /// Check for timeouts and maintenance tasks.
    pub fn onTimeout(self: *Connection) !void {
        if (self.state == .terminated) return;

        const now: i64 = @intCast(std.time.nanoTimestamp());

        // Closing/draining: wait 3×PTO then terminate (RFC 9000 §10.2)
        if (self.state == .closing or self.state == .draining) {
            if (self.closing_start_time > 0) {
                const pto_ns = self.pkt_handler.rtt_stats.pto();
                const drain_timeout = 3 * pto_ns;
                if (now - self.closing_start_time > drain_timeout) {
                    self.state = .terminated;
                    std.log.info("connection terminated after draining period", .{});
                }
            }
            return;
        }

        // Check idle timeout
        if (now - self.last_packet_received_time > self.idle_timeout_ns) {
            self.state = .terminated;
            return;
        }

        // Check PTO — prefer retransmitting data over PING (RFC 9002 §6.2.4)
        if (self.pkt_handler.getPtoTimeout()) |pto_time| {
            if (now >= pto_time) {
                self.pkt_handler.pto_count += 1;

                // Check if there's retransmittable data in the PTO space
                var has_data = false;
                if (self.pkt_handler.getPtoSpace()) |pto_level| {
                    switch (pto_level) {
                        .initial, .handshake => {
                            // Re-queue crypto data for retransmission on PTO (RFC 9002 §6.2.4)
                            self.queueCryptoRetransmission(pto_level);
                            const crypto_idx: u8 = if (pto_level == .initial) 0 else 2;
                            if (self.crypto_streams.getStream(crypto_idx).hasData()) {
                                has_data = true;
                            }
                        },
                        .application => {
                            // Check application-level crypto stream (e.g. NewSessionTicket)
                            if (self.crypto_streams.getStream(3).hasData()) {
                                has_data = true;
                            }
                            // Check if any stream has data to send
                            var stream_it = self.streams.streams.valueIterator();
                            while (stream_it.next()) |s_ptr| {
                                if (s_ptr.*.send.hasData()) {
                                    has_data = true;
                                    break;
                                }
                            }
                        },
                    }
                }

                // Only send PING as last resort when no data available
                if (!has_data) {
                    self.pending_frames.push(.{ .ping = {} });
                }
                // If has_data is true, the packer will naturally pick up the
                // stream/crypto data and produce an ack-eliciting probe packet
            }
        }

        // Check path validation timeouts
        const pto_ns = self.pkt_handler.rtt_stats.pto();
        for (&self.paths) |*path| {
            if (path.validator.needsRetry(now, pto_ns)) {
                path.validator.retry();
                self.pending_frames.push(.{ .path_challenge = path.validator.challenge_data });
            }
            path.validator.checkTimeout(now, pto_ns);
        }
    }

    /// Close the connection gracefully with an application error.
    pub fn close(self: *Connection, error_code: u64, reason: []const u8) void {
        if (self.state == .closing or self.state == .draining or self.state == .terminated) return;
        self.state = .closing;
        self.closing_start_time = @intCast(std.time.nanoTimestamp());
        self.local_err = .{
            .is_app = true,
            .code = error_code,
            .reason = reason,
        };
        self.pending_frames.push(.{ .connection_close = .{
            .error_code = error_code,
            .frame_type = 0,
            .is_app = true,
        } });
    }

    /// Close the connection with a transport error (RFC 9000 §10.2).
    pub fn closeWithTransportError(self: *Connection, error_code: u64, frame_type: u64, reason: []const u8) void {
        if (self.state == .closing or self.state == .draining or self.state == .terminated) return;
        self.state = .closing;
        self.closing_start_time = @intCast(std.time.nanoTimestamp());
        self.local_err = .{
            .is_app = false,
            .code = error_code,
            .reason = reason,
        };
        self.pending_frames.push(.{ .connection_close = .{
            .error_code = error_code,
            .frame_type = frame_type,
            .is_app = false,
        } });
    }

    /// Open a new bidirectional stream.
    pub fn openStream(self: *Connection) !*stream_mod.Stream {
        return self.streams.openBidiStream();
    }

    /// Open a new unidirectional stream.
    pub fn openUniStream(self: *Connection) !*stream_mod.SendStream {
        return self.streams.openUniStream();
    }

    /// Send a QUIC DATAGRAM frame (RFC 9221).
    /// Returns error if datagrams are not enabled or the queue is full.
    pub fn sendDatagram(self: *Connection, data: []const u8) !void {
        if (!self.datagrams_enabled) return error.DatagramsNotEnabled;
        if (!self.datagram_send_queue.push(data)) return error.DatagramQueueFull;
    }

    /// Receive a QUIC DATAGRAM frame (RFC 9221).
    /// Returns the number of bytes written to buf, or null if no datagram available.
    pub fn recvDatagram(self: *Connection, buf: []u8) ?usize {
        return self.datagram_recv_queue.pop(buf);
    }

    pub fn isClosed(self: *const Connection) bool {
        return self.state == .terminated;
    }

    pub fn isDraining(self: *const Connection) bool {
        return self.state == .draining;
    }

    pub fn isEstablished(self: *const Connection) bool {
        return self.state == .connected;
    }

    /// Drop Initial and Handshake encryption keys (RFC 9001 §4.9).
    /// Called automatically for server in advanceHandshake, and for client
    /// after the Handshake Finished has been sent. Applications should not
    /// need to call this directly.
    pub fn dropHandshakeKeys(self: *Connection) void {
        self.pkt_num_spaces[0].crypto_open = null;
        self.pkt_num_spaces[0].crypto_seal = null;
        self.pkt_num_spaces[1].crypto_open = null;
        self.pkt_num_spaces[1].crypto_seal = null;
    }

    /// Initiate a key update (RFC 9001 §6).
    /// The next 1-RTT packet will use the new key phase.
    /// Returns true if the key update was initiated, false if not possible
    /// (e.g., no key update manager, or update already in progress).
    pub fn initiateKeyUpdate(self: *Connection) bool {
        if (self.key_update) |*ku| {
            if (ku.canUpdate()) {
                const now = @as(i64, @intCast(std.time.nanoTimestamp()));
                const pto_ns = self.pkt_handler.rtt_stats.pto();
                ku.rollKeys(now, pto_ns);
                self.packer.key_phase = ku.key_phase;
                return true;
            }
        }
        return false;
    }

    /// Return the ECN codepoint to mark on outgoing packets.
    /// Returns ECT(0) if ECN validation allows it, else Not-ECT.
    pub fn getEcnMark(self: *const Connection) u2 {
        return if (self.ecn_validator.shouldMark()) ECN_ECT0 else ECN_NOT_ECT;
    }

    // Get the NEW_TOKEN received from the server (for reuse in future connections).
    // Returns null if no token was received.
    pub fn getNewToken(self: *const Connection) ?[]const u8 {
        if (self.new_token_len == 0) return null;
        return self.new_token_buf[0..self.new_token_len];
    }

    // Check if a received packet is a stateless reset (RFC 9000 §10.3).
    // Collects all known peer reset tokens and checks the packet's last 16 bytes.
    pub fn matchesStatelessReset(self: *const Connection, data: []const u8) bool {
        var tokens: [ConnectionIdPool.MAX_POOL_SIZE][stateless_reset.TOKEN_LEN]u8 = undefined;
        var count: usize = 0;
        for (&self.peer_cid_pool.entries) |*entry| {
            if (entry.occupied) {
                tokens[count] = entry.stateless_reset_token;
                count += 1;
            }
        }
        if (count == 0) return false;
        return stateless_reset.isStatelessReset(data, tokens[0..count]);
    }

    fn setInitialDCID(self: *Connection, cid: []const u8) void {
        self.dcid_len = @intCast(cid.len);
        @memcpy(self.dcid[0..cid.len], cid);
        // Update packer
        self.packer.dcid = self.dcid[0..self.dcid_len];
    }

    fn epochToEncLevel(epoch: packet.Epoch) ack_handler.EncLevel {
        return switch (epoch) {
            .initial => .initial,
            .zero_rtt, .handshake => .handshake,
            .application => .application,
        };
    }
};

/// Compare two sockaddrs for equality (IPv4: port + address).
/// Uses byte-level reads to avoid alignment issues with posix.sockaddr (align=1).
pub fn sockaddrEql(a: *const posix.sockaddr, b: *const posix.sockaddr) bool {
    if (a.family != b.family) return false;
    if (a.family == posix.AF.INET6) {
        const a_bytes: *const [@sizeOf(posix.sockaddr.in6)]u8 = @ptrCast(a);
        const b_bytes: *const [@sizeOf(posix.sockaddr.in6)]u8 = @ptrCast(b);
        const a6 = std.mem.bytesToValue(posix.sockaddr.in6, a_bytes);
        const b6 = std.mem.bytesToValue(posix.sockaddr.in6, b_bytes);
        return a6.port == b6.port and std.mem.eql(u8, &a6.addr, &b6.addr) and a6.scope_id == b6.scope_id;
    }
    const a_bytes: *const [@sizeOf(posix.sockaddr.in)]u8 = @ptrCast(a);
    const b_bytes: *const [@sizeOf(posix.sockaddr.in)]u8 = @ptrCast(b);
    const a_in = std.mem.bytesToValue(posix.sockaddr.in, a_bytes);
    const b_in = std.mem.bytesToValue(posix.sockaddr.in, b_bytes);
    return a_in.port == b_in.port and a_in.addr == b_in.addr;
}

/// Compare two sockaddrs for same IP address (ignoring port).
/// Uses byte-level reads to avoid alignment issues with posix.sockaddr (align=1).
pub fn sockaddrSameIp(a: *const posix.sockaddr, b: *const posix.sockaddr) bool {
    if (a.family != b.family) return false;
    if (a.family == posix.AF.INET6) {
        const a_bytes: *const [@sizeOf(posix.sockaddr.in6)]u8 = @ptrCast(a);
        const b_bytes: *const [@sizeOf(posix.sockaddr.in6)]u8 = @ptrCast(b);
        const a6 = std.mem.bytesToValue(posix.sockaddr.in6, a_bytes);
        const b6 = std.mem.bytesToValue(posix.sockaddr.in6, b_bytes);
        return std.mem.eql(u8, &a6.addr, &b6.addr);
    }
    const a_bytes: *const [@sizeOf(posix.sockaddr.in)]u8 = @ptrCast(a);
    const b_bytes: *const [@sizeOf(posix.sockaddr.in)]u8 = @ptrCast(b);
    const a_in = std.mem.bytesToValue(posix.sockaddr.in, a_bytes);
    const b_in = std.mem.bytesToValue(posix.sockaddr.in, b_bytes);
    return a_in.addr == b_in.addr;
}

/// Generates a new random connection ID of the given size into the provided buffer.
pub fn generateConnectionId(buf: []u8) void {
    crypto.random.bytes(buf);
}

/// Create a client-side connection and generate the initial packet.
/// The returned Connection is ready to produce an Initial packet
/// containing a ClientHello.
///
/// If `tls_config` is provided, a real TLS 1.3 ClientHello is generated.
/// Otherwise, transport parameters are queued as a placeholder.
pub fn connect(
    allocator: std.mem.Allocator,
    server_name: []const u8,
    config: ConnectionConfig,
    tls_config: ?tls13.TlsConfig,
    initial_token: ?[]const u8,
) !Connection {
    const now: i64 = @intCast(std.time.nanoTimestamp());
    var scid: [8]u8 = undefined;
    var dcid: [8]u8 = undefined;
    generateConnectionId(&scid);
    generateConnectionId(&dcid);

    var local_params: transport_params.TransportParams = .{
        .max_idle_timeout = config.max_idle_timeout,
        .initial_max_data = config.initial_max_data,
        .initial_max_stream_data_bidi_local = config.initial_max_stream_data_bidi_local,
        .initial_max_stream_data_bidi_remote = config.initial_max_stream_data_bidi_remote,
        .initial_max_stream_data_uni = config.initial_max_stream_data_uni,
        .initial_max_streams_bidi = config.initial_max_streams_bidi,
        .initial_max_streams_uni = config.initial_max_streams_uni,
        .max_datagram_frame_size = config.max_datagram_frame_size,
        .initial_source_connection_id = &scid,
    };

    // RFC 9368: Include version_information when v2 is enabled
    if (config.enable_v2) {
        local_params.version_info_chosen = protocol.QUIC_V1; // Client starts with v1
        local_params.version_info_available = .{ protocol.QUIC_V2, protocol.QUIC_V1, 0, 0, 0, 0, 0, 0 };
        local_params.version_info_available_count = 2;
    }

    var conn = Connection{
        .allocator = allocator,
        .version = protocol.SUPPORTED_VERSIONS[0],
        .is_server = false,
        .state = .first_flight,
        .creation_time = now,
        .last_packet_received_time = now,

        .pkt_handler = ack_handler.PacketHandler.init(allocator),
        .conn_flow_ctrl = flow_control.ConnectionFlowController.init(
            config.initial_max_data,
            6 * 1024 * 1024,
        ),
        .streams = stream_mod.StreamsMap.init(allocator, false),
        .crypto_streams = crypto_stream.CryptoStreamManager.init(allocator),

        .local_params = local_params,
    };

    // Set connection IDs
    conn.scid_len = 8;
    @memcpy(conn.scid[0..8], &scid);
    conn.dcid_len = 8;
    @memcpy(conn.dcid[0..8], &dcid);

    // Save the initial DCID as the Original Destination CID (needed for Retry handling)
    conn.odcid_len = 8;
    @memcpy(conn.odcid_buf[0..8], &dcid);

    // Store DCID for v2 re-derivation and enable_v2 flag
    conn.initial_dcid_len = 8;
    @memcpy(conn.initial_dcid_buf[0..8], &dcid);
    conn.enable_v2 = config.enable_v2;
    conn.disable_pmtud = config.disable_pmtud;

    // Generate static reset key and register initial SCID with deterministic token
    crypto.random.bytes(&conn.static_reset_key);
    conn.local_cid_pool.registerInitialCid(conn.scid[0..conn.scid_len], conn.static_reset_key);

    std.log.info("connection.connect: dcid={any}, scid={any}", .{ dcid, scid });

    // Derive Initial encryption keys from the DCID we chose
    try conn.pkt_num_spaces[@intFromEnum(packet.Epoch.initial)].setupInitial(
        &dcid,
        conn.version,
        false, // client-side
    );

    // Initialize packet packer
    conn.packer = packet_packer.PacketPacker.init(
        allocator,
        false,
        conn.scid[0..conn.scid_len],
        conn.dcid[0..conn.dcid_len],
        conn.version,
    );

    // If a token from NEW_TOKEN was provided, include it in the Initial packet
    if (initial_token) |token| {
        const len = @min(token.len, conn.retry_token_buf.len);
        @memcpy(conn.retry_token_buf[0..len], token[0..len]);
        conn.retry_token_len = @intCast(len);
        conn.packer.initial_token = conn.retry_token_buf[0..len];
        std.log.info("using NEW_TOKEN from previous connection ({d} bytes)", .{len});
    }

    // Configure stream limits
    conn.streams.setMaxIncomingStreams(
        config.initial_max_streams_bidi,
        config.initial_max_streams_uni,
    );

    conn.conn_flow_ctrl.base.send_window = config.initial_max_data;

    if (config.max_idle_timeout > 0) {
        conn.idle_timeout_ns = @as(i64, @intCast(config.max_idle_timeout)) * 1_000_000;
    }

    // Initialize TLS 1.3 handshake and generate ClientHello
    if (tls_config) |tc| {
        var tc_with_sni = tc;
        tc_with_sni.server_name = server_name;
        tc_with_sni.quic_version = conn.version;
        conn.tls13_hs = tls13.Tls13Handshake.initClient(tc_with_sni, local_params);

        // Step the handshake to generate the ClientHello
        try conn.advanceHandshake();
    } else {
        // Legacy: queue transport parameters as placeholder crypto data
        var tp_buf: [256]u8 = undefined;
        var tp_fbs = std.io.fixedBufferStream(&tp_buf);
        try conn.local_params.encode(tp_fbs.writer());
        const tp_data = tp_fbs.getWritten();
        const cs = conn.crypto_streams.getStream(0); // Initial level
        try cs.writeData(tp_data);
    }

    return conn;
}

test "connect: create client connection" {
    var conn = try connect(std.testing.allocator, "example.com", .{}, null, null);
    defer conn.deinit();

    try std.testing.expect(!conn.is_server);
    try std.testing.expectEqual(conn.state, .first_flight);
    try std.testing.expectEqual(conn.version, protocol.SUPPORTED_VERSIONS[0]);
    try std.testing.expectEqual(@as(u8, 8), conn.scid_len);
    try std.testing.expectEqual(@as(u8, 8), conn.dcid_len);

    // Should have crypto data queued (transport parameters)
    const cs = conn.crypto_streams.getStream(0);
    try std.testing.expect(cs.hasData());

    // Should have Initial encryption keys
    const seal = conn.pkt_num_spaces[@intFromEnum(packet.Epoch.initial)].crypto_seal;
    try std.testing.expect(seal != null);
}

test "Connection: init and basic state" {
    const dcid_val = "dest1234" ++ ([_]u8{0} ** 12);
    const scid_val = "src12345" ++ ([_]u8{0} ** 12);

    var conn = Connection{
        .allocator = std.testing.allocator,
        .is_server = true,
        .dcid = dcid_val.*,
        .dcid_len = 8,
        .scid = scid_val.*,
        .scid_len = 8,
        .version = protocol.SUPPORTED_VERSIONS[0],
        .pkt_handler = ack_handler.PacketHandler.init(std.testing.allocator),
        .conn_flow_ctrl = flow_control.ConnectionFlowController.init(1048576, 6 * 1024 * 1024),
        .streams = stream_mod.StreamsMap.init(std.testing.allocator, true),
        .crypto_streams = crypto_stream.CryptoStreamManager.init(std.testing.allocator),
        .packer = packet_packer.PacketPacker.init(
            std.testing.allocator,
            true,
            dcid_val[0..8],
            scid_val[0..8],
            protocol.SUPPORTED_VERSIONS[0],
        ),
    };
    defer conn.deinit();

    try std.testing.expectEqual(conn.dcid[0..8].*, dcid_val[0..8].*);
    try std.testing.expectEqual(conn.state, .first_flight);
    try std.testing.expect(!conn.isClosed());
    try std.testing.expect(!conn.isDraining());
}

// ConnectionIdPool tests
test "ConnectionIdPool: add and consume" {
    var pool = ConnectionIdPool{};
    const cid1 = [_]u8{ 0x01, 0x02, 0x03, 0x04 };
    const token1 = [_]u8{0xAA} ** 16;
    pool.addPeerCid(1, &cid1, token1);

    try std.testing.expectEqual(@as(usize, 1), pool.count());

    const entry = pool.consumeUnused();
    try std.testing.expect(entry != null);
    try std.testing.expectEqualSlices(u8, &cid1, entry.?.getCid());
    try std.testing.expect(entry.?.in_use);

    // No more unused entries
    try std.testing.expect(pool.consumeUnused() == null);
}

test "ConnectionIdPool: retire prior to" {
    var pool = ConnectionIdPool{};
    const token = [_]u8{0} ** 16;
    pool.addPeerCid(0, &[_]u8{ 0x01, 0x02 }, token);
    pool.addPeerCid(1, &[_]u8{ 0x03, 0x04 }, token);
    pool.addPeerCid(2, &[_]u8{ 0x05, 0x06 }, token);

    try std.testing.expectEqual(@as(usize, 3), pool.count());
    pool.retirePriorTo(2);
    try std.testing.expectEqual(@as(usize, 1), pool.count());

    const entry = pool.consumeUnused();
    try std.testing.expect(entry != null);
    try std.testing.expectEqual(@as(u64, 2), entry.?.seq_num);
}

test "ConnectionIdPool: remove by seq" {
    var pool = ConnectionIdPool{};
    const token = [_]u8{0} ** 16;
    pool.addPeerCid(5, &[_]u8{ 0x01, 0x02, 0x03 }, token);
    pool.addPeerCid(6, &[_]u8{ 0x04, 0x05, 0x06 }, token);

    try std.testing.expectEqual(@as(usize, 2), pool.count());
    pool.removeBySeq(5);
    try std.testing.expectEqual(@as(usize, 1), pool.count());
}

test "ConnectionIdPool: pool full" {
    var pool = ConnectionIdPool{};
    const token = [_]u8{0} ** 16;
    var i: u64 = 0;
    while (i < ConnectionIdPool.MAX_POOL_SIZE + 2) : (i += 1) {
        pool.addPeerCid(i, &[_]u8{@intCast(i)}, token);
    }
    // Should cap at MAX_POOL_SIZE
    try std.testing.expectEqual(ConnectionIdPool.MAX_POOL_SIZE, pool.count());
}

// PathValidator tests
test "PathValidator: challenge and response" {
    var validator = PathValidator{};
    const challenge = validator.startChallenge();

    try std.testing.expectEqual(PathValidationState.pending, validator.state);
    try std.testing.expect(validator.handleResponse(challenge));
    try std.testing.expectEqual(PathValidationState.validated, validator.state);
}

test "PathValidator: wrong response" {
    var validator = PathValidator{};
    _ = validator.startChallenge();

    const wrong_data = [_]u8{0xFF} ** 8;
    try std.testing.expect(!validator.handleResponse(wrong_data));
    try std.testing.expectEqual(PathValidationState.pending, validator.state);
}

test "PathValidator: needs retry" {
    var validator = PathValidator{};
    _ = validator.startChallenge();
    // Simulate time passing by setting challenge_sent_time far in the past
    validator.challenge_sent_time = 0;

    const now: i64 = 1_000_000_000; // 1s
    const pto: i64 = 100_000_000; // 100ms
    try std.testing.expect(validator.needsRetry(now, pto));

    validator.retry();
    try std.testing.expectEqual(@as(u8, 1), validator.retries);
}

// LocalCidPool tests
test "LocalCidPool: register and issue" {
    var pool = LocalCidPool{};
    const initial_cid = [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 };
    pool.registerInitialCid(&initial_cid, null);

    // Seq 0 should be registered
    try std.testing.expectEqual(@as(usize, 1), pool.activeCount());
    try std.testing.expectEqual(@as(u64, 1), pool.next_seq_num);

    // Issue a new CID
    const entry1 = pool.issueNewCid(8, null).?;
    try std.testing.expectEqual(@as(u64, 1), entry1.seq_num);
    try std.testing.expectEqual(@as(u8, 8), entry1.cid_len);
    try std.testing.expectEqual(@as(usize, 2), pool.activeCount());

    // Issue another
    const entry2 = pool.issueNewCid(8, null).?;
    try std.testing.expectEqual(@as(u64, 2), entry2.seq_num);
    try std.testing.expectEqual(@as(usize, 3), pool.activeCount());
}

test "LocalCidPool: retire and replace" {
    var pool = LocalCidPool{};
    pool.registerInitialCid(&[_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 }, null);

    // Issue 2 more CIDs (seq 1, 2)
    _ = pool.issueNewCid(8, null);
    _ = pool.issueNewCid(8, null);
    try std.testing.expectEqual(@as(usize, 3), pool.activeCount());

    // Retire seq 0
    pool.retireBySeq(0);
    try std.testing.expectEqual(@as(usize, 2), pool.activeCount());

    // Can issue a replacement into the freed slot
    const replacement = pool.issueNewCid(8, null).?;
    try std.testing.expectEqual(@as(u64, 3), replacement.seq_num);
    try std.testing.expectEqual(@as(usize, 3), pool.activeCount());
}

test "LocalCidPool: pool full" {
    var pool = LocalCidPool{};
    pool.registerInitialCid(&[_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 }, null);

    // Fill remaining 7 slots
    var i: usize = 0;
    while (i < LocalCidPool.MAX_POOL_SIZE - 1) : (i += 1) {
        try std.testing.expect(pool.issueNewCid(8, null) != null);
    }
    try std.testing.expectEqual(@as(usize, LocalCidPool.MAX_POOL_SIZE), pool.activeCount());

    // Pool full — should return null
    try std.testing.expect(pool.issueNewCid(8, null) == null);
}
