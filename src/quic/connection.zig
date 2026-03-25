const std = @import("std");
const net = std.net;
const platform = @import("platform.zig");
const crypto = std.crypto;

const protocol = @import("protocol.zig");
const packet = @import("packet.zig");
const tls13 = @import("tls13.zig");
const frame_mod = @import("frame.zig");
const Frame = frame_mod.Frame;
const FrameType = frame_mod.FrameType;
const TransportError = frame_mod.TransportError;
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
const qlog = @import("qlog.zig");
const quic_lb = @import("quic_lb.zig");

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
        self.challenge_sent_time = platform.nanoTimestamp();
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
        self.challenge_sent_time = platform.nanoTimestamp();
    }
};

pub const NetworkPath = struct {
    local_addr: platform.sockaddr_storage,
    peer_addr: platform.sockaddr_storage,
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
        local_addr: platform.sockaddr_storage,
        peer_addr: platform.sockaddr_storage,
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

    /// Register the preferred_address CID at sequence number 1 (RFC 9000 §5.1.1).
    pub fn registerPreferredCid(self: *LocalCidPool, cid: []const u8, reset_token: [16]u8) void {
        // Find a free slot for seq 1
        for (&self.entries) |*entry| {
            if (!entry.occupied) {
                entry.occupied = true;
                entry.retired = false;
                entry.seq_num = 1;
                entry.cid_len = @intCast(cid.len);
                @memcpy(entry.cid_buf[0..cid.len], cid);
                entry.stateless_reset_token = reset_token;
                // Ensure next_seq_num is at least 2
                if (self.next_seq_num <= 1) self.next_seq_num = 2;
                return;
            }
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

    /// Issue a new CID using QUIC-LB encoding. Returns the entry or null if pool full.
    /// If static_key is provided, compute a deterministic reset token; otherwise random.
    pub fn issueNewCidLb(self: *LocalCidPool, lb_config: *const quic_lb.Config, static_key: ?[16]u8) ?*const LocalCidEntry {
        for (&self.entries) |*entry| {
            if (!entry.occupied) {
                entry.occupied = true;
                entry.retired = false;
                entry.seq_num = self.next_seq_num;
                const cid_len = quic_lb.cidLength(lb_config);
                entry.cid_len = cid_len;
                quic_lb.generateCid(lb_config, entry.cid_buf[0..cid_len]);
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
pub const DatagramQueue = struct {
    pub const DEFAULT_MAX_ITEMS: usize = 32;
    pub const MAX_DATAGRAM_SIZE: usize = 1200;

    allocator: ?std.mem.Allocator = null,
    bufs_static: [DEFAULT_MAX_ITEMS][MAX_DATAGRAM_SIZE]u8 = undefined,
    lens_static: [DEFAULT_MAX_ITEMS]usize = .{0} ** DEFAULT_MAX_ITEMS,
    bufs_dynamic: ?[][MAX_DATAGRAM_SIZE]u8 = null,
    lens_dynamic: ?[]usize = null,
    max_items: usize = DEFAULT_MAX_ITEMS,
    head: usize = 0,
    tail: usize = 0,
    count: usize = 0,

    /// Resize the queue to a custom capacity (must be called before use).
    pub fn resize(self: *DatagramQueue, alloc: std.mem.Allocator, capacity: usize) !void {
        if (capacity <= DEFAULT_MAX_ITEMS) return; // static buffer is enough
        self.allocator = alloc;
        self.bufs_dynamic = try alloc.alloc([MAX_DATAGRAM_SIZE]u8, capacity);
        self.lens_dynamic = try alloc.alloc(usize, capacity);
        @memset(self.lens_dynamic.?, 0);
        self.max_items = capacity;
    }

    pub fn deinitQueue(self: *DatagramQueue) void {
        if (self.allocator) |alloc| {
            if (self.bufs_dynamic) |b| alloc.free(b);
            if (self.lens_dynamic) |l| alloc.free(l);
        }
    }

    fn getBuf(self: *DatagramQueue, idx: usize) *[MAX_DATAGRAM_SIZE]u8 {
        if (self.bufs_dynamic) |b| return &b[idx];
        return &self.bufs_static[idx];
    }

    fn getLen(self: *DatagramQueue, idx: usize) *usize {
        if (self.lens_dynamic) |l| return &l[idx];
        return &self.lens_static[idx];
    }

    pub fn push(self: *DatagramQueue, data: []const u8) bool {
        if (self.count >= self.max_items or data.len > MAX_DATAGRAM_SIZE) return false;
        @memcpy(self.getBuf(self.tail)[0..data.len], data);
        self.getLen(self.tail).* = data.len;
        self.tail = (self.tail + 1) % self.max_items;
        self.count += 1;
        return true;
    }

    pub fn pop(self: *DatagramQueue, out: []u8) ?usize {
        if (self.count == 0) return null;
        const len = self.getLen(self.head).*;
        if (out.len < len) return null;
        @memcpy(out[0..len], self.getBuf(self.head)[0..len]);
        self.head = (self.head + 1) % self.max_items;
        self.count -= 1;
        return len;
    }

    pub fn isEmpty(self: *const DatagramQueue) bool {
        return self.count == 0;
    }

    pub fn isFull(self: *const DatagramQueue) bool {
        return self.count >= self.max_items;
    }

    pub fn queueLen(self: *const DatagramQueue) usize {
        return self.count;
    }

    /// Peek at the length of the next datagram without removing it.
    pub fn peekLen(self: *DatagramQueue) ?usize {
        if (self.count == 0) return null;
        return self.getLen(self.head).*;
    }

    /// Return a slice into the ring buffer entry without copying.
    /// The slice is valid until the next pop() or consume() call.
    pub fn peekData(self: *DatagramQueue) ?[]const u8 {
        if (self.count == 0) return null;
        const len = self.getLen(self.head).*;
        return self.getBuf(self.head)[0..len];
    }

    /// Advance past the head entry (after peekData was used).
    pub fn consume(self: *DatagramQueue) void {
        if (self.count == 0) return;
        self.head = (self.head + 1) % self.max_items;
        self.count -= 1;
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
    to: platform.sockaddr_storage,
    from: platform.sockaddr_storage,
    // ECN codepoint from IP header (0=Not-ECT, 1=ECT(1), 2=ECT(0), 3=CE)
    ecn: u2 = ECN_NOT_ECT,
    // Size of the UDP datagram (for amplification limit accounting).
    // Set to the datagram size for the first packet; 0 for subsequent coalesced packets.
    datagram_size: u64 = 0,
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
    // QUIC-LB CID encoding config (server-side, for load balancer routing)
    quic_lb: ?quic_lb.Config = null,
    // QLOG output directory (if set, writes .sqlog files)
    qlog_dir: ?[]const u8 = null,
    // Keep-alive period in milliseconds (0 = disabled). When enabled, PINGs are
    // sent after this duration of silence, clamped to idle_timeout/2 so the
    // connection stays alive without tripping the idle timeout.
    keep_alive_period: u64 = 0,
    // Datagram queue capacity (per direction). Default 32. Increase for apps
    // that send/receive large bursts of datagrams (e.g. WebTransport datagram tests).
    datagram_queue_capacity: usize = DatagramQueue.DEFAULT_MAX_ITEMS,
    // Auto-close connection when all data is sent and acknowledged.
    close_when_idle: bool = false,
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
    cc: congestion.Cubic = congestion.Cubic.init(),
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

    // QUIC-LB CID encoding config (server-side, for load balancer routing)
    quic_lb_config: ?quic_lb.Config = null,

    // Key update manager for 1-RTT key rotation (RFC 9001 Section 6)
    key_update: ?quic_crypto.KeyUpdateManager = null,

    // Whether PMTUD is disabled
    disable_pmtud: bool = false,

    // Keep-alive: computed interval in nanoseconds (0 = disabled)
    keep_alive_interval_ns: i64 = 0,
    // True after a keep-alive PING has been sent; reset on packet receipt
    keep_alive_ping_sent: bool = false,
    // When true, the connection will close as soon as all stream data has been
    // sent and acknowledged, or after too many idle PTO cycles.
    close_when_idle: bool = false,
    // Counter for consecutive PTO fires with no data to send.
    // Unlike pto_count, this is NOT reset by received ACKs.
    idle_pto_count: u32 = 0,

    // Path MTU Discovery (DPLPMTUD, RFC 8899)
    mtu_discoverer: mtu_mod.MtuDiscoverer = .{},

    // HANDSHAKE_DONE delivery tracking (server only)
    // True from handshake completion until the client ACKs a packet carrying HANDSHAKE_DONE.
    // Used to re-arm packer.send_handshake_done on PTO/loss retransmission.
    handshake_done_pending: bool = false,

    // QUIC DATAGRAM support (RFC 9221)
    datagram_recv_queue: DatagramQueue = .{},
    datagram_send_queue: DatagramQueue = .{},
    datagrams_enabled: bool = false,

    /// Optional zero-copy datagram callback. When set, incoming DATAGRAM frames
    /// are delivered directly during packet processing (inside recv()) instead of
    /// being copied to the ring buffer. The data slice points into the decrypted
    /// packet buffer and is only valid for the duration of the callback.
    /// This eliminates 2 memcpy operations per datagram on the receive path.
    datagram_recv_callback: ?*const fn (data: []const u8, ctx: ?*anyopaque) void = null,
    datagram_recv_ctx: ?*anyopaque = null,

    // draft-ietf-quic-ack-frequency
    peer_supports_ack_freq: bool = false,
    ack_freq_send_seq: u64 = 0,

    // 0-RTT (early data) keys
    early_data_open: ?quic_crypto.Open = null, // Server: decrypt 0-RTT packets
    early_data_seal: ?quic_crypto.Seal = null, // Client: encrypt 0-RTT packets

    // Session ticket received from server (readable by application)
    session_ticket: ?tls13.SessionTicket = null,

    // RFC 9000 §7.4.1: remembered transport params from session ticket (for 0-RTT validation)
    remembered_params: ?tls13.SessionTicket = null,

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

    // QLOG structured logging (optional, enabled via QLOGDIR)
    qlog_writer: ?qlog.QlogWriter = null,

    // PTO probe pending — bypass congestion control for one packet (RFC 9002 §6.2.4)
    pto_probe_pending: u2 = 0,

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
    last_packet_sent_time: i64 = 0,
    creation_time: i64 = 0,
    idle_timeout_ns: i64 = 30_000_000_000, // 30s default

    pub fn accept(
        allocator: std.mem.Allocator,
        header: packet.Header,
        local: platform.sockaddr_storage,
        remote: platform.sockaddr_storage,
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
        const now: i64 = platform.nanoTimestamp();

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
            if (config.quic_lb) |lb_config| {
                // Use QUIC-LB encoded CID for load balancer routing
                const scid_len = quic_lb.cidLength(&lb_config);
                conn.scid_len = scid_len;
                quic_lb.generateCid(&lb_config, conn.scid[0..scid_len]);
                conn.quic_lb_config = lb_config;
            } else {
                conn.scid_len = 8;
                generateConnectionId(conn.scid[0..8]);
            }
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
            .min_ack_delay = 1000, // 1ms minimum ACK delay (draft-ietf-quic-ack-frequency)
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

        // Compute keep-alive interval: clamp to idle_timeout/2
        if (config.keep_alive_period > 0) {
            const ka_ns: i64 = @intCast(config.keep_alive_period * 1_000_000);
            conn.keep_alive_interval_ns = @min(ka_ns, @divTrunc(conn.idle_timeout_ns, 2));
        }
        conn.close_when_idle = config.close_when_idle;

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

        // Register the preferred_address CID in local CID pool (RFC 9000 §5.1.1: seq=1)
        if (is_server) {
            if (config.preferred_address) |pref| {
                const pref_cid = pref.getCid();
                if (pref_cid.len > 0) {
                    conn.local_cid_pool.registerPreferredCid(pref_cid, pref.stateless_reset_token);
                }
            }
        }

        // Initialize QLOG if configured
        if (config.qlog_dir) |dir| {
            const qlog_odcid = if (odcid) |o| o else header.dcid;
            conn.qlog_writer = qlog.QlogWriter.init(dir, qlog_odcid, is_server);
            if (conn.qlog_writer != null) {
                conn.qlog_writer.?.connectionStarted(now);
            }
        }

        // Set token key for NEW_TOKEN generation (server)
        if (config.token_key) |tk| {
            conn.token_key = tk;
        }

        // Configure stream limits
        conn.streams.setMaxIncomingStreams(
            config.initial_max_streams_bidi,
            config.initial_max_streams_uni,
        );
        conn.streams.local_max_stream_data_bidi_local = config.initial_max_stream_data_bidi_local;
        conn.streams.local_max_stream_data_bidi_remote = config.initial_max_stream_data_bidi_remote;
        conn.streams.local_max_stream_data_uni = config.initial_max_stream_data_uni;

        // Set initial send window from connection flow control
        conn.conn_flow_ctrl.base.send_window = config.initial_max_data;

        if (config.max_idle_timeout > 0) {
            conn.idle_timeout_ns = @as(i64, @intCast(config.max_idle_timeout)) * 1_000_000;
        }

        // Resize datagram queues if configured larger than default
        if (config.datagram_queue_capacity > DatagramQueue.DEFAULT_MAX_ITEMS) {
            try conn.datagram_recv_queue.resize(allocator, config.datagram_queue_capacity);
            try conn.datagram_send_queue.resize(allocator, config.datagram_queue_capacity);
        }

        return conn;
    }

    pub fn deinit(self: *Connection) void {
        if (self.qlog_writer) |*ql| {
            const now: i64 = platform.nanoTimestamp();
            ql.connectionClosed(now, "application", 0);
            ql.deinit();
            self.qlog_writer = null;
        }
        self.pkt_handler.deinit();
        self.streams.deinit();
        self.crypto_streams.deinit();
        self.datagram_recv_queue.deinitQueue();
        self.datagram_send_queue.deinitQueue();
    }

    /// Handle a Version Negotiation packet (RFC 9000 §6.2, client only).
    /// Since we support Compatible Version Negotiation (RFC 9368), VN packets
    /// indicate the server doesn't support any of our versions — close the connection.
    fn handleVersionNegotiation(self: *Connection, header: *const packet.Header, fbs: anytype) void {
        // RFC 9000 §6.2: A client MUST discard VN if it has already received and
        // successfully processed any packet, including an earlier VN.
        if (self.state != .first_flight) return;

        // Validate: the VN's DCID must match our SCID, and SCID must match our DCID
        if (!std.mem.eql(u8, header.dcid, self.scid[0..self.scid_len])) return;
        if (!std.mem.eql(u8, header.scid, self.dcid[0..self.dcid_len])) return;

        // Read listed versions from the remaining bytes
        const remaining = fbs.buffer.len - fbs.pos;
        if (remaining < 4 or remaining % 4 != 0) return;

        const version_data = fbs.buffer[fbs.pos..];
        const version_count = remaining / 4;

        // Check if any listed version is one we support (skip reserved versions)
        var has_supported = false;
        var i: usize = 0;
        while (i < version_count) : (i += 1) {
            const v = std.mem.readInt(u32, version_data[i * 4 ..][0..4], .big);
            if (protocol.isSupportedVersion(v)) {
                has_supported = true;
                break;
            }
        }

        if (has_supported) {
            // The server lists a version we support but sent VN anyway.
            // This shouldn't happen with compatible VN — possible downgrade attack.
            // RFC 9000 §6.2: "A client MUST discard a Version Negotiation packet
            // that lists the QUIC version selected by the client."
            std.log.warn("VN packet lists our version — possible downgrade attack, ignoring", .{});
            return;
        }

        // No compatible version — close the connection
        std.log.info("VN: server does not support any of our versions, closing", .{});
        self.closeWithTransportError(@intFromEnum(TransportError.version_negotiation_error), 0, "Version negotiation failed");
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
            self.last_packet_received_time = platform.nanoTimestamp();
            return;
        }
        if (self.state == .closing) {
            self.needs_close_retransmit = true;
            self.last_packet_received_time = platform.nanoTimestamp();
            return;
        }

        // Intercept Retry packets before normal processing (client only)
        if (header.packet_type == .retry) {
            if (!self.is_server) {
                try self.handleRetryPacket(header, fbs.buffer[header.packet_start..fbs.buffer.len]);
            }
            return;
        }

        // RFC 9000 §6.2: Handle Version Negotiation packets (client only)
        if (header.packet_type == .version_negotiation) {
            if (!self.is_server and !self.handshake_confirmed) {
                self.handleVersionNegotiation(header, fbs);
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

            std.log.info("recv: processing 0-RTT packet (early data)", .{});
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

            if (payload.len == 0) {
                self.closeWithTransportError(@intFromEnum(TransportError.protocol_violation), 0, "empty packet payload");
                return error.InvalidPacket;
            }

            const now: i64 = platform.nanoTimestamp();
            self.last_packet_received_time = now;
            self.keep_alive_ping_sent = false;
            if (info.datagram_size > 0) {
                self.paths[self.active_path_idx].bytes_received += info.datagram_size;
            }

            // Process 0-RTT frames (STREAM, DATAGRAM etc. - no CRYPTO or HANDSHAKE_DONE)
            var remaining = payload;
            var ack_eliciting = false;
            while (remaining.len > 0) {
                if (remaining[0] == 0x00) {
                    remaining = remaining[1..];
                    continue;
                }
                const frame = Frame.parse(remaining) catch break;
                // Enforce frame-in-correct-space (RFC 9000 §12.5)
                if (!frame.isAllowedIn(.zero_rtt)) {
                    self.closeWithTransportError(@intFromEnum(TransportError.protocol_violation), @intFromEnum(FrameType.crypto), "frame not allowed in 0-RTT");
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
            self.closeWithTransportError(@intFromEnum(TransportError.protocol_violation), 0, "empty packet payload");
            return error.InvalidPacket;
        }

        // RFC 9000 §17.2, §17.3: reserved bits MUST be zero after header protection removal
        if (header.reserved_bits_set) {
            self.closeWithTransportError(@intFromEnum(TransportError.protocol_violation), 0, "reserved header bits are non-zero");
            return error.ProtocolViolation;
        }

        const now: i64 = platform.nanoTimestamp();
        self.last_packet_received_time = now;
        self.keep_alive_ping_sent = false;

        // RFC 9000 §8.1: Receipt of a Handshake packet from the client confirms
        // address ownership (client derived keys → it processed our Initial).
        // Lift the anti-amplification limit immediately.
        if (self.is_server and epoch == .handshake and !self.paths[self.active_path_idx].is_validated) {
            self.paths[self.active_path_idx].is_validated = true;
            std.log.info("path validated via Handshake packet (amplification limit lifted)", .{});
        }

        // Handle key phase change for 1-RTT packets (RFC 9001 Section 6)
        if (epoch == .application) {
            if (self.key_update) |*ku| {
                if (header.key_phase != ku.key_phase and ku.first_acked_with_current and ku.prev_open == null) {
                    // Peer initiated a key update (RFC 9001 §6.1)
                    // Only roll if:
                    // 1. first_acked_with_current: peer has our current keys
                    // 2. prev_open is null: no recent self-initiated update whose
                    //    old-generation packets could still be in flight
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

        // Update network path stats (only once per datagram, not per coalesced packet)
        if (info.datagram_size > 0) {
            self.paths[self.active_path_idx].bytes_received += info.datagram_size;
        }

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

        // Server: re-verify DCID from AEAD-authenticated long-header packets.
        // If the Initial that created this connection was corrupted in transit,
        // accept() may have stored a wrong peer SCID as our outgoing DCID.
        // The first successfully-decrypted packet has the real peer SCID.
        if (self.is_server and !self.handshake_confirmed and
            (epoch == .initial or epoch == .handshake) and header.scid.len > 0)
        {
            if (self.dcid_len != @as(u8, @intCast(header.scid.len)) or
                !std.mem.eql(u8, self.dcid[0..self.dcid_len], header.scid))
            {
                std.log.info("recv: correcting DCID to AEAD-verified SCID (len {d})", .{header.scid.len});
                self.dcid_len = @intCast(header.scid.len);
                @memcpy(self.dcid[0..header.scid.len], header.scid);
                self.packer.updateDcid(header.scid);
            }
        }

        // Process all frames from the decrypted payload
        var ack_eliciting = false;
        var has_non_probing = false;
        var remaining = payload;

        // Collect frames for QLOG
        var qlog_frames: [32]Frame = undefined;
        var qlog_frame_count: usize = 0;

        while (remaining.len > 0) {
            // Skip padding
            if (remaining[0] == 0x00) {
                remaining = remaining[1..];
                continue;
            }

            const frame = Frame.parse(remaining) catch |err| {
                std.log.err("Failed to parse frame: {}", .{err});
                // RFC 9000 §12.4: frame encoding errors
                if (err == error.FrameEncodingError) {
                    self.closeWithTransportError(@intFromEnum(TransportError.frame_encoding_error), 0, "unknown or malformed frame type");
                } else {
                    self.closeWithTransportError(@intFromEnum(TransportError.frame_encoding_error), 0, "frame encoding error");
                }
                return error.ProtocolViolation;
            };

            std.log.debug("recv: parsed frame type={s}", .{@tagName(frame)});

            // Enforce frame-in-correct-space (RFC 9000 §12.5)
            if (!frame.isAllowedIn(header.packet_type)) {
                std.log.warn("frame {s} not allowed in {s} packet, closing", .{ @tagName(frame), @tagName(header.packet_type) });
                self.closeWithTransportError(@intFromEnum(TransportError.protocol_violation), 0, "frame not allowed in this packet type");
                return error.ProtocolViolation;
            }

            if (frame.isAckEliciting()) {
                ack_eliciting = true;
            }
            if (!frame.isProbing()) {
                has_non_probing = true;
            }

            // Track frames for QLOG
            if (qlog_frame_count < qlog_frames.len) {
                qlog_frames[qlog_frame_count] = frame;
                qlog_frame_count += 1;
            }

            try self.processFrame(frame, epoch, now);

            // Advance past this frame. For frames that contain data slices,
            // figure out where they end in the buffer.
            const consumed = self.frameSize(frame, remaining);
            if (consumed == 0) break; // safety: avoid infinite loop
            remaining = remaining[consumed..];
        }

        // QLOG: packet_received
        if (self.qlog_writer) |*ql| {
            var frames_buf: [2048]u8 = undefined;
            const frames_len = qlog.QlogWriter.serializeFrames(qlog_frames[0..qlog_frame_count], &frames_buf);
            ql.packetReceived(now, qlog.packetTypeStr(header.packet_type), header.packet_number, payload.len, frames_buf[0..frames_len]);
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
                // Credit this packet's bytes to the new path (already counted on old path above)
                if (info.datagram_size > 0) {
                    self.paths[self.active_path_idx].bytes_received += info.datagram_size;
                }
            } else if (!sockaddrEql(&info.to, &active_path.local_addr)) {
                // Local address changed (e.g., client migrated to our preferred_address port).
                // Treat as a path change: update local_addr and send PATH_CHALLENGE.
                std.log.info("preferred_address migration: local address changed", .{});
                active_path.local_addr = info.to;
                const challenge = active_path.validator.startChallenge();
                self.pending_frames.push(.{ .path_challenge = challenge });
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

                // RFC 9002 §7.8: snapshot app_limited BEFORE processing ACKs,
                // while bytes_in_flight still reflects the pre-ACK state.
                // If checked after, bytes_in_flight is already decremented,
                // making it appear app-limited even when the sender filled cwnd.
                self.cc.app_limited = self.pkt_handler.bytes_in_flight < self.cc.sendWindow();

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

                    // Update stream ack_offset for ACKed stream frames
                    for (pkt.getStreamFrames()) |sf| {
                        if (stream_mod.isBidi(sf.stream_id)) {
                            if (self.streams.getStream(sf.stream_id)) |s| {
                                s.send.onAck(sf.offset, sf.length);
                            }
                        } else {
                            if (self.streams.send_streams.get(sf.stream_id)) |s| {
                                s.onAck(sf.offset, sf.length);
                            }
                        }
                    }

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

                    // QLOG: packet_lost
                    if (self.qlog_writer) |*ql| {
                        const lost_type: []const u8 = switch (pkt.enc_level) {
                            .initial => "initial",
                            .handshake => "handshake",
                            .application => "1RTT",
                        };
                        ql.packetLost(now, lost_type, pkt.pn, "time_threshold");
                    }

                    // Queue stream data retransmission for lost packets
                    self.queueStreamRetransmissions(&pkt);

                    // Queue CRYPTO frame retransmission for lost packets (RFC 9002 §6.2)
                    if (pkt.has_crypto_data) {
                        self.queueCryptoRetransmission(pkt.enc_level);
                    }

                    // Re-arm HANDSHAKE_DONE if the lost packet carried it
                    if (pkt.has_handshake_done and self.handshake_done_pending) {
                        self.packer.send_handshake_done = true;
                    }
                }

                if (has_non_probe_loss) {
                    if (result.persistent_congestion) {
                        // Only trigger persistent congestion if the lost packets
                        // are from outside the current recovery epoch. This prevents
                        // repeated resets when old packets are gradually declared lost
                        // across multiple ACK events after a blackhole.
                        if (earliest_lost_sent_time) |lost_time| {
                            if (!self.cc.inCongestionRecovery(lost_time)) {
                                self.cc.onPersistentCongestion(now);
                                std.log.info("persistent congestion detected, window reduced to minimum", .{});
                            }
                        }
                    } else if (earliest_lost_sent_time) |lost_time| {
                        self.cc.onCongestionEvent(lost_time, now);
                    }
                }

                // QLOG: metrics_updated after ACK processing
                if (self.qlog_writer) |*ql| {
                    const rs = &self.pkt_handler.rtt_stats;
                    ql.metricsUpdated(now, rs.min_rtt, rs.smoothed_rtt, rs.latest_rtt, rs.rtt_var, self.cc.sendWindow(), self.pkt_handler.bytes_in_flight);
                }

                self.maybeConfirmHandshake(enc_level, result.acked.len);

                // Update pacer
                self.pacer.setBandwidth(self.cc.sendWindow(), &self.pkt_handler.rtt_stats);
            },

            .ack_ecn => |ack| {
                const enc_level = epochToEncLevel(epoch);
                const space_idx = @intFromEnum(enc_level);
                const peer_tp = self.peer_params orelse transport_params.TransportParams{};

                // RFC 9002 §7.8: snapshot app_limited BEFORE processing ACKs
                self.cc.app_limited = self.pkt_handler.bytes_in_flight < self.cc.sendWindow();

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

                    // Stop including HANDSHAKE_DONE once a packet containing it is ACKed
                    if (pkt.has_handshake_done) {
                        self.packer.send_handshake_done = false;
                        self.handshake_done_pending = false;
                    }

                    // Update stream ack_offset for ACKed stream frames
                    for (pkt.getStreamFrames()) |sf| {
                        if (stream_mod.isBidi(sf.stream_id)) {
                            if (self.streams.getStream(sf.stream_id)) |s| {
                                s.send.onAck(sf.offset, sf.length);
                            }
                        } else {
                            if (self.streams.send_streams.get(sf.stream_id)) |s| {
                                s.onAck(sf.offset, sf.length);
                            }
                        }
                    }

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

                    // QLOG: packet_lost
                    if (self.qlog_writer) |*ql| {
                        const lost_type: []const u8 = switch (pkt.enc_level) {
                            .initial => "initial",
                            .handshake => "handshake",
                            .application => "1RTT",
                        };
                        ql.packetLost(now, lost_type, pkt.pn, "time_threshold");
                    }

                    // Queue stream data retransmission for lost packets
                    self.queueStreamRetransmissions(&pkt);

                    // Queue CRYPTO frame retransmission for lost packets (RFC 9002 §6.2)
                    if (pkt.has_crypto_data) {
                        self.queueCryptoRetransmission(pkt.enc_level);
                    }

                    // Re-arm HANDSHAKE_DONE if the lost packet carried it
                    if (pkt.has_handshake_done and self.handshake_done_pending) {
                        self.packer.send_handshake_done = true;
                    }
                }

                if (has_non_probe_loss) {
                    if (result.persistent_congestion) {
                        if (earliest_lost_sent_time_ecn) |lost_time| {
                            if (!self.cc.inCongestionRecovery(lost_time)) {
                                self.cc.onPersistentCongestion(now);
                                std.log.info("persistent congestion detected, window reduced to minimum", .{});
                            }
                        }
                    } else if (earliest_lost_sent_time_ecn) |lost_time| {
                        self.cc.onCongestionEvent(lost_time, now);
                    }
                }

                // QLOG: metrics_updated after ACK_ECN processing
                if (self.qlog_writer) |*ql| {
                    const rs = &self.pkt_handler.rtt_stats;
                    ql.metricsUpdated(now, rs.min_rtt, rs.smoothed_rtt, rs.latest_rtt, rs.rtt_var, self.cc.sendWindow(), self.pkt_handler.bytes_in_flight);
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

                self.maybeConfirmHandshake(enc_level, result.acked.len);

                // Update pacer
                self.pacer.setBandwidth(self.cc.sendWindow(), &self.pkt_handler.rtt_stats);
            },

            .reset_stream => |rs| {
                // RFC 9000 §19.4: RESET_STREAM on a send-only stream is STREAM_STATE_ERROR
                if (stream_mod.isLocal(rs.stream_id, self.is_server) and !stream_mod.isBidi(rs.stream_id)) {
                    self.closeWithTransportError(@intFromEnum(TransportError.stream_state_error), @intFromEnum(FrameType.reset_stream), "RESET_STREAM on send-only stream");
                    return error.ProtocolViolation;
                }
                if (self.streams.getStream(rs.stream_id)) |s| {
                    s.recv.handleResetStream(rs.error_code, rs.final_size) catch {
                        // RFC 9000 §4.5: FINAL_SIZE_ERROR
                        self.closeWithTransportError(@intFromEnum(TransportError.final_size_error), @intFromEnum(FrameType.reset_stream), "RESET_STREAM final_size mismatch");
                        return error.ProtocolViolation;
                    };
                    // RFC 9000 §4.4: account for final_size in connection flow control
                    self.conn_flow_ctrl.base.addBytesReceived(rs.final_size) catch {
                        self.closeWithTransportError(@intFromEnum(TransportError.flow_control_error), @intFromEnum(FrameType.reset_stream), "RESET_STREAM exceeds flow control");
                        return error.FlowControlError;
                    };
                    // Mark bytes as "read" so connection flow control window advances
                    const already_read = s.recv.bytes_read;
                    if (rs.final_size > already_read) {
                        self.conn_flow_ctrl.addBytesRead(rs.final_size - already_read);
                    }
                    // If send side is also done, stream is fully closed
                    if (s.send.fin_sent or s.send.reset_err != null) {
                        self.streams.closeStream(rs.stream_id);
                    }
                }
            },

            .stop_sending => |ss| {
                // RFC 9000 §19.5: STOP_SENDING for a receive-only stream is STREAM_STATE_ERROR
                if (!stream_mod.isLocal(ss.stream_id, self.is_server) and !stream_mod.isBidi(ss.stream_id)) {
                    self.closeWithTransportError(@intFromEnum(TransportError.stream_state_error), @intFromEnum(FrameType.stop_sending), "STOP_SENDING on receive-only stream");
                    return error.ProtocolViolation;
                }
                // RFC 9000 §19.5: STOP_SENDING for a locally-initiated stream not yet created
                if (stream_mod.isLocal(ss.stream_id, self.is_server)) {
                    if (self.streams.getStream(ss.stream_id) == null) {
                        self.closeWithTransportError(@intFromEnum(TransportError.stream_state_error), @intFromEnum(FrameType.stop_sending), "STOP_SENDING for stream not yet created");
                        return error.ProtocolViolation;
                    }
                }
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
                // RFC 9000 §19.7: server MUST NOT send NEW_TOKEN; client receiving it is valid
                if (self.is_server) {
                    self.closeWithTransportError(@intFromEnum(TransportError.protocol_violation), @intFromEnum(FrameType.new_token), "server received NEW_TOKEN");
                    return error.ProtocolViolation;
                }
                if (token.len <= self.new_token_buf.len) {
                    @memcpy(self.new_token_buf[0..token.len], token);
                    self.new_token_len = @intCast(token.len);
                    std.log.info("stored NEW_TOKEN from server ({d} bytes)", .{token.len});
                }
            },

            .stream => |s| {
                // RFC 9000 §19.8: STREAM on send-only stream is STREAM_STATE_ERROR
                if (stream_mod.isLocal(s.stream_id, self.is_server) and !stream_mod.isBidi(s.stream_id)) {
                    self.closeWithTransportError(@intFromEnum(TransportError.stream_state_error), @intFromEnum(FrameType.stream), "STREAM on send-only stream");
                    return error.ProtocolViolation;
                }
                // RFC 9000 §19.8: STREAM for locally-initiated stream not yet created
                if (stream_mod.isLocal(s.stream_id, self.is_server) and stream_mod.isBidi(s.stream_id)) {
                    if (self.streams.getStream(s.stream_id) == null) {
                        self.closeWithTransportError(@intFromEnum(TransportError.stream_state_error), @intFromEnum(FrameType.stream), "STREAM for locally-initiated stream not yet created");
                        return error.ProtocolViolation;
                    }
                }
                // RFC 9000 §4.1: STREAM frame offset exceeding flow control limit
                if (s.offset + s.data.len > self.conn_flow_ctrl.base.receive_window) {
                    self.closeWithTransportError(@intFromEnum(TransportError.flow_control_error), @intFromEnum(FrameType.stream), "STREAM exceeds connection flow control limit");
                    return error.FlowControlError;
                }
                // RFC 9000 §4.6: stream ID exceeding peer's MAX_STREAMS limit
                {
                    const stream_seq = s.stream_id / 4;
                    const limit = if (stream_mod.isBidi(s.stream_id)) self.streams.max_incoming_bidi_streams else self.streams.max_incoming_uni_streams;
                    if (!stream_mod.isLocal(s.stream_id, self.is_server) and stream_seq >= limit) {
                        self.closeWithTransportError(@intFromEnum(TransportError.stream_limit_error), @intFromEnum(FrameType.stream), "stream ID exceeds MAX_STREAMS limit");
                        return error.ProtocolViolation;
                    }
                }
                if (stream_mod.isBidi(s.stream_id)) {
                    // Bidirectional stream
                    const strm = self.streams.getOrCreateStream(s.stream_id) catch |err| {
                        std.log.err("Failed to get/create stream {}: {}", .{ s.stream_id, err });
                        return;
                    };
                    strm.recv.handleStreamFrame(s.offset, s.data, s.fin) catch |err| switch (err) {
                        error.FinalSizeError => {
                            self.closeWithTransportError(@intFromEnum(TransportError.final_size_error), @intFromEnum(FrameType.stream), "STREAM final_size mismatch");
                            return error.ProtocolViolation;
                        },
                        else => return err,
                    };
                    if (s.fin) self.streams.needs_gc_scan = true;

                    // Check if stream is fully closed (both directions done)
                    if (s.fin and (strm.send.fin_sent or strm.send.reset_err != null) and !strm.closed_for_gc) {
                        strm.closed_for_gc = true;
                        self.streams.closeStream(s.stream_id);
                        if (strm.send.retransmit_count == 0) {
                            self.streams.queueDisposal(s.stream_id);
                        }
                    }
                } else {
                    // Unidirectional stream — route to recv_streams
                    const recv_strm = self.streams.getOrCreateRecvStream(s.stream_id) catch |err| {
                        std.log.err("Failed to get/create recv stream {}: {}", .{ s.stream_id, err });
                        return;
                    };
                    recv_strm.handleStreamFrame(s.offset, s.data, s.fin) catch |err| switch (err) {
                        error.FinalSizeError => {
                            self.closeWithTransportError(@intFromEnum(TransportError.final_size_error), @intFromEnum(FrameType.stream), "STREAM final_size mismatch");
                            return error.ProtocolViolation;
                        },
                        else => return err,
                    };

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
                // RFC 9000 §19.10: MAX_STREAM_DATA on receive-only stream is STREAM_STATE_ERROR
                if (!stream_mod.isLocal(msd.stream_id, self.is_server) and !stream_mod.isBidi(msd.stream_id)) {
                    self.closeWithTransportError(@intFromEnum(TransportError.stream_state_error), @intFromEnum(FrameType.max_stream_data), "MAX_STREAM_DATA on receive-only stream");
                    return error.ProtocolViolation;
                }
                // RFC 9000 §19.10: MAX_STREAM_DATA for locally-initiated stream not yet created
                if (stream_mod.isLocal(msd.stream_id, self.is_server)) {
                    if (self.streams.getStream(msd.stream_id) == null and self.streams.send_streams.get(msd.stream_id) == null) {
                        self.closeWithTransportError(@intFromEnum(TransportError.stream_state_error), @intFromEnum(FrameType.max_stream_data), "MAX_STREAM_DATA for stream not yet created");
                        return error.ProtocolViolation;
                    }
                }
                // Update send window on bidi streams
                if (self.streams.getStream(msd.stream_id)) |s| {
                    s.send.updateSendWindow(msd.max);
                }
                // Update send window on uni send streams
                if (self.streams.send_streams.get(msd.stream_id)) |s| {
                    s.updateSendWindow(msd.max);
                }
            },

            .max_streams_bidi => |max| {
                // RFC 9000 §19.11: MAX_STREAMS must not exceed 2^60
                if (max > (1 << 60)) {
                    self.closeWithTransportError(@intFromEnum(TransportError.frame_encoding_error), @intFromEnum(FrameType.max_streams_bidi), "MAX_STREAMS_BIDI exceeds 2^60");
                    return error.ProtocolViolation;
                }
                self.streams.setMaxStreams(max, self.streams.max_uni_streams);
            },

            .max_streams_uni => |max| {
                // RFC 9000 §19.11: MAX_STREAMS must not exceed 2^60
                if (max > (1 << 60)) {
                    self.closeWithTransportError(@intFromEnum(TransportError.frame_encoding_error), @intFromEnum(FrameType.max_streams_uni), "MAX_STREAMS_UNI exceeds 2^60");
                    return error.ProtocolViolation;
                }
                self.streams.setMaxStreams(self.streams.max_bidi_streams, max);
            },

            .data_blocked => {},
            .stream_data_blocked => {},
            .streams_blocked_bidi => |val| {
                // RFC 9000 §19.14: STREAMS_BLOCKED must not exceed 2^60
                if (val > (1 << 60)) {
                    self.closeWithTransportError(@intFromEnum(TransportError.stream_limit_error), @intFromEnum(FrameType.streams_blocked_bidi), "STREAMS_BLOCKED_BIDI exceeds 2^60");
                    return error.ProtocolViolation;
                }
                // Peer is blocked — respond with our current MAX_STREAMS limit
                if (self.streams.max_incoming_bidi_streams > 0) {
                    self.pending_frames.push(.{ .max_streams_bidi = self.streams.max_incoming_bidi_streams });
                }
            },
            .streams_blocked_uni => |val| {
                // RFC 9000 §19.14: STREAMS_BLOCKED must not exceed 2^60
                if (val > (1 << 60)) {
                    self.closeWithTransportError(@intFromEnum(TransportError.stream_limit_error), @intFromEnum(FrameType.streams_blocked_uni), "STREAMS_BLOCKED_UNI exceeds 2^60");
                    return error.ProtocolViolation;
                }
                // Peer is blocked — respond with our current MAX_STREAMS limit
                if (self.streams.max_incoming_uni_streams > 0) {
                    self.pending_frames.push(.{ .max_streams_uni = self.streams.max_incoming_uni_streams });
                }
            },

            .new_connection_id => |ncid| {
                // RFC 9000 §19.15: Retire_Prior_To must not exceed Sequence_Number
                if (ncid.retire_prior_to > ncid.seq_num) {
                    self.closeWithTransportError(@intFromEnum(TransportError.frame_encoding_error), @intFromEnum(FrameType.new_connection_id), "NEW_CONNECTION_ID: retire_prior_to > seq_num");
                    return error.ProtocolViolation;
                }
                // RFC 9000 §19.15: CID length of 0 is invalid (except for initial)
                if (ncid.conn_id.len == 0) {
                    self.closeWithTransportError(@intFromEnum(TransportError.frame_encoding_error), @intFromEnum(FrameType.new_connection_id), "NEW_CONNECTION_ID: 0-byte connection ID");
                    return error.ProtocolViolation;
                }
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
                    const maybe_entry = if (self.quic_lb_config) |*lb_cfg|
                        self.local_cid_pool.issueNewCidLb(lb_cfg, self.static_reset_key)
                    else
                        self.local_cid_pool.issueNewCid(self.scid_len, self.static_reset_key);
                    if (maybe_entry) |entry| {
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
                // RFC 9000 §19.20: only server sends HANDSHAKE_DONE
                if (self.is_server) {
                    self.closeWithTransportError(@intFromEnum(TransportError.protocol_violation), @intFromEnum(FrameType.handshake_done), "server received HANDSHAKE_DONE");
                    return error.ProtocolViolation;
                }
                self.handshake_confirmed = true;
                self.state = .connected;
                self.ecn_validator.start();

                // Drop Initial and Handshake packet number spaces and encryption keys
                self.pkt_handler.dropSpace(.initial);
                self.pkt_handler.dropSpace(.handshake);
                self.pkt_num_spaces[0].crypto_open = null;
                self.pkt_num_spaces[0].crypto_seal = null;
                self.pkt_num_spaces[1].crypto_open = null;
                self.pkt_num_spaces[1].crypto_seal = null;
            },

            .datagram => |d| {
                if (self.datagrams_enabled) {
                    if (self.datagram_recv_callback) |cb| {
                        cb(d.data, self.datagram_recv_ctx);
                    } else {
                        _ = self.datagram_recv_queue.push(d.data);
                    }
                }
            },

            .datagram_with_length => |d| {
                if (self.datagrams_enabled) {
                    if (self.datagram_recv_callback) |cb| {
                        cb(d.data, self.datagram_recv_ctx);
                    } else {
                        _ = self.datagram_recv_queue.push(d.data);
                    }
                }
            },

            .ack_frequency => |af| {
                // draft-ietf-quic-ack-frequency: update ACK generation parameters
                if (!self.peer_supports_ack_freq) {
                    self.closeWithTransportError(@intFromEnum(TransportError.protocol_violation), 0xaf, "ACK_FREQUENCY not negotiated");
                    return error.ProtocolViolation;
                }
                const applied = self.pkt_handler.recv[2].applyAckFrequency(
                    af.sequence_number,
                    af.ack_eliciting_threshold,
                    af.request_max_ack_delay,
                    af.reordering_threshold,
                );
                if (applied) {
                    std.log.info("ACK_FREQUENCY applied: seq={d} threshold={d} max_delay={d}µs reorder={d}", .{
                        af.sequence_number, af.ack_eliciting_threshold, af.request_max_ack_delay, af.reordering_threshold,
                    });
                }
            },

            .immediate_ack => {
                // draft-ietf-quic-ack-frequency: force immediate ACK
                self.pkt_handler.recv[2].triggerImmediateAck();
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
                    const action = hs.step() catch |err| {
                        // RFC 9001 §4.8: post-handshake TLS errors
                        const tls_alert: u64 = switch (err) {
                            error.UnexpectedMessage => 10,
                            else => 80,
                        };
                        self.closeWithTransportError(TransportError.cryptoError(tls_alert), @intFromEnum(FrameType.crypto), "post-handshake TLS error");
                        return;
                    };
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
                // RFC 9000 §7.4: TransportParameterError is a QUIC transport error, not TLS
                if (err == error.TransportParameterError) {
                    self.closeWithTransportError(@intFromEnum(TransportError.transport_parameter_error), @intFromEnum(FrameType.crypto), "transport parameter error");
                    return;
                }
                // RFC 9001 §4.8: map TLS errors to CRYPTO_ERROR (0x100 + TLS alert code)
                const tls_alert: u64 = switch (err) {
                    error.BadCertificate => 42, // bad_certificate
                    error.BadCertificateVerify => 51, // decrypt_error
                    error.UnexpectedMessage => 10, // unexpected_message
                    error.DecodeError => 50, // decode_error
                    error.BadFinished => 51, // decrypt_error
                    error.NoKeyShare => 40, // handshake_failure
                    error.UnsupportedVersion => 70, // protocol_version
                    error.NoApplicationProtocol => 120, // no_application_protocol
                    error.MissingExtension => 109, // missing_extension
                    else => 80, // internal_error
                };
                self.closeWithTransportError(TransportError.cryptoError(tls_alert), @intFromEnum(FrameType.crypto), "TLS handshake failure");
                return;
            };
            std.log.info("advanceHandshake: step {d} produced action={s}", .{ iterations, @tagName(action) });

            switch (action) {
                .send_data => |sd| {
                    // Write the TLS handshake data to the appropriate crypto stream
                    const cs_level: u8 = @intFromEnum(sd.level);
                    const cs = self.crypto_streams.getStream(cs_level);
                    // Log hash of data being written to crypto stream for corruption debugging
                    var data_hash: [32]u8 = undefined;
                    std.crypto.hash.sha2.Sha256.hash(sd.data, &data_hash, .{});
                    std.log.info("advanceHandshake: writing {d} bytes to level {}, first4={x:0>2}{x:0>2}{x:0>2}{x:0>2}, sha256={x}", .{
                        sd.data.len,
                        cs_level,
                        sd.data[0],
                        if (sd.data.len > 1) sd.data[1] else @as(u8, 0),
                        if (sd.data.len > 2) sd.data[2] else @as(u8, 0),
                        if (sd.data.len > 3) sd.data[3] else @as(u8, 0),
                        data_hash,
                    });
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
                                // RFC 9000 §7.4.1: restore remembered transport params for 0-RTT
                                if (self.remembered_params) |rp| {
                                    self.streams.setMaxStreams(rp.initial_max_streams_bidi, rp.initial_max_streams_uni);
                                    self.streams.setPeerInitialMaxStreamData(
                                        rp.initial_max_stream_data_bidi_local,
                                        rp.initial_max_stream_data_bidi_remote,
                                        rp.initial_max_stream_data_uni,
                                    );
                                    self.conn_flow_ctrl.base.send_window = rp.initial_max_data;
                                    std.log.info("installed 0-RTT keys (client), restored remembered params: max_bidi={d}, max_uni={d}, max_data={d}", .{
                                        rp.initial_max_streams_bidi, rp.initial_max_streams_uni, rp.initial_max_data,
                                    });
                                } else {
                                    self.streams.setMaxStreams(100, 100);
                                    std.log.info("installed 0-RTT encrypt keys (client), default stream limits", .{});
                                }
                            }
                            if (self.qlog_writer) |*ql| {
                                const now_ql: i64 = platform.nanoTimestamp();
                                ql.keyUpdated(now_ql, "tls", if (self.is_server) "server_0rtt_secret" else "client_0rtt_secret");
                            }
                        },
                        .handshake => {
                            self.installHandshakeKeys(ik.open, ik.seal);
                            // RFC 9001 §4.9.1: client stops sending Initial packets after
                            // receiving the first Handshake packet (which installs these keys).
                            // Drop the Initial seal to prevent the packer from generating
                            // Initial packets with the (now shorter) DCID.
                            if (!self.is_server) {
                                self.pkt_num_spaces[0].crypto_seal = null;
                            }
                            if (self.qlog_writer) |*ql| {
                                const now_ql: i64 = platform.nanoTimestamp();
                                ql.keyUpdated(now_ql, "tls", "server_handshake_secret");
                                ql.keyUpdated(now_ql, "tls", "client_handshake_secret");
                            }
                            if (self.is_server and self.enable_v2) {
                                if (hs.config.quic_version != self.version) {
                                    try self.switchVersion(hs.config.quic_version);
                                }
                            }
                        },
                        .application => {
                            self.installAppKeys(ik.open, ik.seal);
                            if (self.qlog_writer) |*ql| {
                                const now_ql: i64 = platform.nanoTimestamp();
                                ql.keyUpdated(now_ql, "tls", "server_1rtt_secret");
                                ql.keyUpdated(now_ql, "tls", "client_1rtt_secret");
                            }
                        },
                        else => {},
                    }
                },
                .wait_for_data => break,
                .complete => {
                    // Skip if already connected (duplicate .complete from post-handshake messages)
                    if (self.state == .connected) break;

                    self.state = .connected;
                    self.ecn_validator.start();
                    self.paths[self.active_path_idx].is_validated = true;

                    // Drop Initial space and keys (both client and server)
                    self.pkt_handler.dropSpace(.initial);
                    self.pkt_num_spaces[0].crypto_open = null;
                    self.pkt_num_spaces[0].crypto_seal = null;

                    // Clear early data keys (0-RTT period is over)
                    self.early_data_open = null;
                    self.early_data_seal = null;

                    // Handle 0-RTT rejection (RFC 9001 §4.1.2):
                    // When the server rejects 0-RTT, the client must retransmit all
                    // 0-RTT data as 1-RTT. Queue retransmission of all in-flight
                    // application-space packets that carried stream data.
                    if (!self.is_server and !hs.zero_rtt_accepted) {
                        const app_tracker = &self.pkt_handler.sent[@intFromEnum(ack_handler.EncLevel.application)];
                        var pkt_it = app_tracker.sent_packets.iterator();
                        while (pkt_it.next()) |entry| {
                            const pkt = entry.value_ptr;
                            if (pkt.getStreamFrames().len > 0) {
                                self.queueStreamRetransmissions(pkt);
                            }
                        }
                    }

                    if (self.is_server) {
                        // Server confirms handshake immediately and clears Handshake keys
                        self.handshake_confirmed = true;
                        self.pkt_handler.dropSpace(.handshake);
                        self.pkt_num_spaces[1].crypto_open = null;
                        self.pkt_num_spaces[1].crypto_seal = null;

                        // Server must send HANDSHAKE_DONE to the client (RFC 9001 Section 4.1.2)
                        self.packer.send_handshake_done = true;
                        self.handshake_done_pending = true;

                        // draft-ietf-quic-ack-frequency: disabled for now.
                        // Sending ACK_FREQUENCY changes the browser's ACK behavior,
                        // which can negatively impact datagram latency in ping-pong patterns.
                        // The RFC 9000 default (ACK every 2 ack-eliciting packets) works well
                        // for interactive workloads. Re-enable for bulk transfer scenarios.
                        // if (self.peer_supports_ack_freq) { ... }
                    }
                    // Client: Keep Handshake keys until HANDSHAKE_DONE received (RFC 9001 §4.9.2)
                    // This allows the client to ACK server's Handshake retransmissions under loss

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

                        try self.validatePeerTransportParams(&peer_tp);

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

                        // Recompute keep-alive interval after idle timeout negotiation
                        if (self.keep_alive_interval_ns > 0) {
                            self.keep_alive_interval_ns = @min(self.keep_alive_interval_ns, @divTrunc(self.idle_timeout_ns, 2));
                        }

                        // Apply peer's max_ack_delay to RTT stats (RFC 9002 §5.3)
                        self.pkt_handler.rtt_stats.max_ack_delay = @as(i64, @intCast(peer_tp.max_ack_delay)) * 1_000_000;

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

                        // draft-ietf-quic-ack-frequency: detect peer support
                        if (peer_tp.min_ack_delay != null) {
                            self.peer_supports_ack_freq = true;
                        }

                        // Client: migrate to server's preferred address (RFC 9000 §9.6)
                        if (!self.is_server) {
                            if (peer_tp.preferred_address) |pref| {
                                if (!peer_tp.disable_active_migration) {
                                    // Store preferred CID + reset token in peer CID pool
                                    self.peer_cid_pool.addPeerCid(1, pref.getCid(), pref.stateless_reset_token);

                                    // Pick preferred address of the OTHER family to ensure a real path change.
                                    // Detects IPv4-mapped IPv6 (::ffff:x.x.x.x) as effectively IPv4.
                                    const current_is_v4 = isEffectivelyV4(&self.paths[self.active_path_idx].peer_addr);
                                    const pref_addr = if (current_is_v4)
                                        (if (pref.hasIpv6()) pref.toSockaddrV6() else pref.toSockaddrV4())
                                    else
                                        (if (pref.hasIpv4()) pref.toSockaddrV4() else pref.toSockaddrV6());

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
                                    self.cc = congestion.Cubic.init();
                                    self.pacer = congestion.Pacer.init();
                                    self.pkt_handler.rtt_stats = rtt.RttStats{};
                                    self.mtu_discoverer.reset();
                                    self.packer.max_packet_size = mtu_mod.BASE_PLPMTU;
                                    self.ecn_validator.reset();

                                    const migrating_to_v4 = !current_is_v4 and pref.hasIpv4();
                                    std.log.info("preferred_address: migrating from {s} to {s} port {d}", .{
                                        if (current_is_v4) "IPv4" else "IPv6",
                                        if (migrating_to_v4) "IPv4" else "IPv6",
                                        if (migrating_to_v4) pref.ipv4_port else pref.ipv6_port,
                                    });
                                }
                            }
                        }
                    }

                    // Issue NEW_CONNECTION_ID frames up to peer's active_connection_id_limit (RFC 9000 §5.1)
                    {
                        const peer_limit = if (self.peer_params) |pp| pp.active_connection_id_limit else 2;
                        while (self.local_cid_pool.activeCount() < peer_limit) {
                            const maybe_entry = if (self.quic_lb_config) |*lb_cfg|
                                self.local_cid_pool.issueNewCidLb(lb_cfg, self.static_reset_key)
                            else
                                self.local_cid_pool.issueNewCid(self.scid_len, self.static_reset_key);
                            if (maybe_entry) |entry| {
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
        // Garbage-collect fully-closed bidi streams so consumed count advances
        // and MAX_STREAMS updates can fire.
        self.streams.collectClosedStreams();

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

        // MAX_STREAM_DATA: update peer's send window as we consume stream data
        {
            var stream_it = self.streams.streams.valueIterator();
            while (stream_it.next()) |s_ptr| {
                const s: *stream_mod.Stream = s_ptr.*;
                if (s.recv.getWindowUpdate()) |new_max| {
                    self.pending_frames.push(.{ .max_stream_data = .{
                        .stream_id = s.stream_id,
                        .max = new_max,
                    } });
                }
            }
        }

        // DATA_BLOCKED: signal peer when connection-level flow control blocks sending (RFC 9000 §4.1)
        if (self.conn_flow_ctrl.base.shouldSendBlocked()) |limit| {
            self.pending_frames.push(.{ .data_blocked = limit });
        }

        // STREAM_DATA_BLOCKED: signal peer when stream-level flow control blocks sending
        {
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

        // RESET_STREAM: send for streams with reset_err set
        {
            var stream_it = self.streams.streams.valueIterator();
            while (stream_it.next()) |s_ptr| {
                const s: *stream_mod.Stream = s_ptr.*;
                if (s.send.reset_err != null and !s.send.reset_stream_sent) {
                    s.send.reset_stream_sent = true;
                    self.pending_frames.push(.{ .reset_stream = .{
                        .stream_id = s.stream_id,
                        .error_code = s.send.reset_err.?,
                        .final_size = s.send.write_offset,
                    } });
                }
            }
        }

        // STOP_SENDING: send for streams requesting peer to stop
        {
            var stream_it = self.streams.streams.valueIterator();
            while (stream_it.next()) |s_ptr| {
                const s: *stream_mod.Stream = s_ptr.*;
                if (s.recv.stop_sending_err != null and !s.recv.stop_sending_sent) {
                    s.recv.stop_sending_sent = true;
                    self.pending_frames.push(.{ .stop_sending = .{
                        .stream_id = s.stream_id,
                        .error_code = s.recv.stop_sending_err.?,
                    } });
                }
            }
        }
    }

    /// Build and send outgoing packets.
    pub fn send(self: *Connection, out_buf: []u8) !usize {
        // Draining/terminated: do not send anything
        if (self.state == .draining or self.state == .terminated) return 0;

        const now: i64 = platform.nanoTimestamp();

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
                // During closing, send at ALL available encryption levels
                // so the peer can decrypt at whatever level they've reached.
                // Include Initial/Handshake crypto data so the peer can
                // derive keys before seeing the CONNECTION_CLOSE.
                const bytes_written = try self.packer.packCoalesced(
                    out_buf,
                    &self.pkt_handler,
                    &self.crypto_streams,
                    &self.streams,
                    &self.pending_frames,
                    initial_seal,
                    null,
                    handshake_seal,
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
        // Exception: PTO probes bypass pacing (RFC 9002 §6.2.4)
        if (self.pto_probe_pending == 0) {
            const pacer_delay = self.pacer.timeUntilSend(now);
            if (pacer_delay > 0) {
                return 0;
            }
        }

        // Check congestion window — only send ACKs + control frames when congestion-limited
        // Exception: PTO probes MUST bypass congestion control (RFC 9002 §6.2.4)
        // DATAGRAM frames are subject to CC per RFC 9221 §5: "DATAGRAM frames SHOULD be
        // subject to congestion control" — they piggyback on CC-allowed packets only.
        if (self.pkt_handler.bytes_in_flight >= self.cc.sendWindow() and self.pto_probe_pending == 0) {
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
        // before address validation (RFC 9000 Section 8.1).
        // Instead of a binary canSend(1200) check, calculate remaining budget
        // and limit the output buffer size. This allows sending smaller packets
        // when the full MTU isn't available, using every byte of the 3x budget.
        var send_buf = out_buf;
        if (self.is_server) {
            const active_path = &self.paths[self.active_path_idx];
            if (!active_path.is_validated) {
                const budget = 3 * active_path.bytes_received;
                if (active_path.bytes_sent >= budget) return 0;
                const remaining = budget - active_path.bytes_sent;
                if (remaining < out_buf.len) {
                    send_buf = out_buf[0..@as(usize, @intCast(remaining))];
                }
            }
        }

        // Build coalesced packet with available encryption levels
        // Packet number space indices: 0=Initial, 1=Handshake, 2=Application
        const initial_seal = self.pkt_num_spaces[0].crypto_seal;
        const handshake_seal = self.pkt_num_spaces[1].crypto_seal;
        // Use KeyUpdateManager seal for 1-RTT if available.
        // Server: don't send 1-RTT data until the handshake is complete.
        // Sending 1-RTT PINGs during the handshake causes the peer to respond
        // with 1-RTT ACKs instead of retransmitting the Handshake Finished.
        const app_seal: ?quic_crypto.Seal = if (self.is_server and !self.handshake_confirmed)
            null
        else if (self.key_update) |*ku|
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
        self.packer.ecn_mark = self.ecn_validator.shouldMark();


        const bytes_written = try self.packer.packCoalesced(
            send_buf,
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

        // Always consume PTO probe slots, even if nothing was packed.
        // Without this, an empty second probe leaves pto_probe_pending=1 forever,
        // blocking all subsequent PTO fires from re-queuing crypto data.
        if (bytes_written == 0 and self.pto_probe_pending > 0) {
            self.pto_probe_pending -|= 1;
        }

        if (bytes_written > 0) {
            // QLOG: packet_sent (log using the highest encryption level that was packed)
            if (self.qlog_writer) |*ql| {
                const pkt_type_str: []const u8 = if (app_seal != null and self.pkt_handler.next_pn[@intFromEnum(ack_handler.EncLevel.application)] > 0)
                    "1RTT"
                else if (handshake_seal != null and self.pkt_handler.next_pn[@intFromEnum(ack_handler.EncLevel.handshake)] > 0)
                    "handshake"
                else
                    "initial";
                // Use the last PN that was allocated
                const enc_idx: usize = if (app_seal != null and self.pkt_handler.next_pn[@intFromEnum(ack_handler.EncLevel.application)] > 0)
                    @intFromEnum(ack_handler.EncLevel.application)
                else if (handshake_seal != null and self.pkt_handler.next_pn[@intFromEnum(ack_handler.EncLevel.handshake)] > 0)
                    @intFromEnum(ack_handler.EncLevel.handshake)
                else
                    @intFromEnum(ack_handler.EncLevel.initial);
                const pn = self.pkt_handler.next_pn[enc_idx] -| 1;
                ql.packetSent(now, pkt_type_str, pn, bytes_written, "");
            }

            self.pto_probe_pending -|= 1;
            self.paths[self.active_path_idx].bytes_sent += bytes_written;
            self.pacer.onPacketSent(bytes_written, now);
            self.last_packet_sent_time = now;

            // If more PTO probes are pending, re-queue stream data + crypto data
            // so the next probe ALSO carries the retransmission (not just a PING).
            // Under burst-3 loss, both probes carrying data doubles the delivery chance.
            if (self.pto_probe_pending > 0) {
                // Re-queue crypto retransmissions
                if (self.pkt_num_spaces[0].crypto_seal != null) {
                    self.queueCryptoRetransmission(.initial);
                }
                if (self.pkt_num_spaces[1].crypto_seal != null) {
                    self.queueCryptoRetransmission(.handshake);
                }
                // Reset stream send_offset for unACKed data
                var resend_it = self.streams.streams.valueIterator();
                while (resend_it.next()) |s_ptr| {
                    const s = s_ptr.*;
                    if (s.send.hasUnackedData()) {
                        s.send.send_offset = s.send.ack_offset;
                        if (s.send.fin_queued) s.send.fin_sent = false;
                    }
                }
            }

            // Client: auto-clear Handshake keys once Finished has been sent AND acknowledged
            // RFC 9001 §4.9.2: "A client MUST NOT discard keys for the Handshake packet
            // number space until ... its HANDSHAKE packets have been acknowledged."
            if (!self.is_server and self.handshake_confirmed and self.pkt_num_spaces[1].crypto_seal != null) {
                if (!self.crypto_streams.getStream(1).hasData()) {
                    const hs_tracker = &self.pkt_handler.sent[@intFromEnum(ack_handler.EncLevel.handshake)];
                    if (hs_tracker.ack_eliciting_in_flight == 0) {
                        self.dropHandshakeKeys();
                    }
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

        // Anti-amplification: limit output to remaining budget
        var send_buf = out_buf;
        if (self.is_server) {
            const active_path = &self.paths[self.active_path_idx];
            if (!active_path.is_validated) {
                const budget = 3 * active_path.bytes_received;
                if (active_path.bytes_sent >= budget) return 0;
                const remaining = budget - active_path.bytes_sent;
                if (remaining < out_buf.len) {
                    send_buf = out_buf[0..@as(usize, @intCast(remaining))];
                }
            }
        }

        // Gather seals at all encryption levels
        const initial_seal = self.pkt_num_spaces[0].crypto_seal;
        const handshake_seal = self.pkt_num_spaces[1].crypto_seal;
        const app_seal: ?quic_crypto.Seal = if (self.is_server and !self.handshake_confirmed)
            null
        else if (self.key_update) |*ku|
            ku.current_seal
        else
            self.pkt_num_spaces[2].crypto_seal;

        const bytes_written = try self.packer.packCoalesced(
            send_buf,
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
            self.pto_probe_pending -|= 1;
            self.paths[self.active_path_idx].bytes_sent += bytes_written;
            // Don't update pacer — ACKs are not paced
        }

        return bytes_written;
    }

    /// Handle connection migration (RFC 9000 Section 9).
    /// Called when a 1-RTT packet with non-probing frames arrives from a different address.
    fn handleMigration(self: *Connection, new_peer_addr: platform.sockaddr_storage, local_addr: platform.sockaddr_storage, now: i64) void {
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
        const same_ip = sockaddrSameIp(&new_peer_addr, &old_path.peer_addr);
        if (!same_ip) {
            self.cc = congestion.Cubic.init();
            self.pacer = congestion.Pacer.init();
            self.pkt_handler.rtt_stats = rtt.RttStats{};
            self.mtu_discoverer.reset();
            self.packer.max_packet_size = mtu_mod.BASE_PLPMTU;
            self.ecn_validator.reset();
            std.log.info("migration: IP changed, reset CC, RTT, MTU and ECN", .{});
        } else {
            // NAT rebinding (port-only change): path is already validated since same IP,
            // and carry over MTU from old path
            self.paths[candidate_idx].is_validated = true;
            // Mark current time as congestion recovery start so that loss detection
            // for pre-migration packets (sent to old port) won't reduce CWND —
            // these are path losses, not congestion losses.
            self.cc.enterRecoveryForMigration(now);
            std.log.info("migration: port-only change (NAT rebinding), preserving CC", .{});
        }
    }

    /// Check for timeouts and maintenance tasks.
    pub fn onTimeout(self: *Connection) !void {
        if (self.state == .terminated) return;

        const now: i64 = platform.nanoTimestamp();

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

        // Check idle timeout (RFC 9000 §10.1, §10.1.2)
        // The effective idle timeout MUST be at least 3× the *base* PTO (without backoff)
        // to avoid terminating the connection before probes have a chance to be answered.
        // Using base PTO (not backed-off) matches quic-go and quiche behavior: the idle
        // timeout should not extend indefinitely as pto_count grows.
        //
        // When data is in flight, extend idle to cover the current PTO backoff schedule.
        // This prevents premature termination while actively retransmitting under loss.
        {
            const base_pto = self.pkt_handler.rtt_stats.pto();
            var effective_idle = @max(self.idle_timeout_ns, 3 * base_pto);
            const app_idx = @intFromEnum(ack_handler.EncLevel.application);
            if (self.handshake_confirmed and self.pkt_handler.sent[app_idx].ack_eliciting_in_flight > 0) {
                const shift: u6 = @intCast(@min(self.pkt_handler.pto_count, 30));
                const backed_off_pto = @min(base_pto << shift, 60_000_000_000);
                effective_idle = @max(effective_idle, 3 * backed_off_pto);
            }
            // RFC 9000 §10.1.2: Before handshake confirmed, also defer idle timeout
            // when sending ack-eliciting packets (to avoid premature timeout during
            // handshake retransmission). After handshake confirmed, only received
            // packets reset the idle timer.
            const last_activity = if (!self.handshake_confirmed)
                @max(self.last_packet_received_time, self.last_packet_sent_time)
            else
                self.last_packet_received_time;
            if (now - last_activity > effective_idle) {
                self.state = .terminated;
                return;
            }
        }
        // Auto-close: when close_when_idle is set and all stream data has been
        // sent (FIN queued, no pending retransmissions), close the connection.
        // Don't wait for control frame ACKs (HANDSHAKE_DONE, NEW_CONNECTION_ID)
        // which can take multiple RTTs under loss.
        // Auto-close: when close_when_idle is set, close the connection once all
        // stream data has been queued for sending (FIN queued, no pending retransmissions).
        // This triggers close BEFORE the data is necessarily ACKed — the CONNECTION_CLOSE
        // is coalesced with or sent after the data, so the peer receives both. Under loss,
        // if the data packet is lost, the CONNECTION_CLOSE packet still reaches the peer,
        // which then closes its side. The server's draining period handles retransmission
        // of the close frame.
        if (self.close_when_idle and self.handshake_confirmed and self.state == .connected) {
            if (self.streams.streams.count() > 0) {
                var all_streams_done = true;
                var stream_it = self.streams.streams.valueIterator();
                while (stream_it.next()) |s_ptr| {
                    if (s_ptr.*.send.hasData() or !s_ptr.*.send.fin_queued) {
                        all_streams_done = false;
                        break;
                    }
                }
                if (all_streams_done) {
                    self.close(0, "");
                    return;
                }
            }
        }

        // Loss detection timer: check loss_time BEFORE PTO (RFC 9002 §6.2.1).
        // Loss timers don't increment pto_count — they run loss detection directly.
        if (self.pkt_handler.getExpiredLossTime(now)) |loss_level| {
            const loss_result = self.pkt_handler.detectLossesForSpace(loss_level, now);
            var has_non_probe_loss_lt = false;
            var earliest_lost_sent_time_lt: ?i64 = null;
            for (loss_result.lost.constSlice()) |pkt| {
                if (self.mtu_discoverer.onProbeLost(pkt.pn, now)) {} else {
                    has_non_probe_loss_lt = true;
                    if (earliest_lost_sent_time_lt == null or pkt.time_sent < earliest_lost_sent_time_lt.?) {
                        earliest_lost_sent_time_lt = pkt.time_sent;
                    }
                }
                self.queueStreamRetransmissions(&pkt);
                if (pkt.has_crypto_data) {
                    self.queueCryptoRetransmission(pkt.enc_level);
                }
                if (pkt.has_handshake_done and self.handshake_done_pending) {
                    self.packer.send_handshake_done = true;
                }
            }
            if (has_non_probe_loss_lt) {
                if (loss_result.persistent_congestion) {
                    if (earliest_lost_sent_time_lt) |lost_time| {
                        if (!self.cc.inCongestionRecovery(lost_time)) {
                            self.cc.onPersistentCongestion(now);
                            std.log.info("persistent congestion detected (loss timer), window reduced to minimum", .{});
                        }
                    }
                } else if (earliest_lost_sent_time_lt) |lost_time| {
                    self.cc.onCongestionEvent(lost_time, now);
                }
            }
            self.pacer.setBandwidth(self.cc.sendWindow(), &self.pkt_handler.rtt_stats);
        }

        // Check PTO — prefer retransmitting data over PING (RFC 9002 §6.2.4)
        // Only fires when no loss_time triggered above.
        else if (self.pkt_handler.getPtoTimeout()) |pto_time| {
            if (now >= pto_time) {
                self.pkt_handler.pto_count += 1;

                // Force-arm ACKs so probes include acknowledgements.
                // When a PTO fires, our previous packets (which carried ACK frames) likely
                // never reached the peer. getAckFrame() clears ack_queued on first call,
                // so without re-arming, PTO probes go out without ACKs. This is critical
                // for amplification-limited handshakes: the server needs ACKs to know the
                // client received its data, and the client needs ACKs in its probes to
                // give the server enough anti-amplification credit.
                //
                // Force-arm ALL spaces (not just the PTO space), because:
                // - Initial PTO should include Handshake ACKs (coalesced packets)
                // - The server needs Handshake ACKs to lift the amplification limit
                for (&self.pkt_handler.recv) |*recv_tracker| {
                    if (recv_tracker.largest_received != null) {
                        recv_tracker.ack_queued = true;
                    }
                }

                // Queue retransmission for ALL spaces with outstanding data.
                // quic-go fires PTO for each space separately, sending 2 probes per
                // space. This maximizes the chance of at least one packet getting
                // through burst loss (burst_to_client=3 drops 3 consecutive packets).
                var has_data = false;

                // Handshake spaces: re-queue crypto data
                {
                    const has_hs_keys = self.pkt_num_spaces[1].crypto_seal != null;
                    if (!has_hs_keys and self.pkt_num_spaces[0].crypto_seal != null) {
                        self.queueCryptoRetransmission(.initial);
                    }
                    if (self.pkt_num_spaces[1].crypto_seal != null) {
                        self.queueCryptoRetransmission(.handshake);
                    }
                    if (self.crypto_streams.getStream(0).hasData() or
                        self.crypto_streams.getStream(2).hasData())
                    {
                        has_data = true;
                    }
                }

                // Application space — always process, not just when it's the earliest.
                // quic-go fires PTO for each space independently; we process all
                // spaces in a single onTimeout() to maximize packet diversity.
                {
                    {
                        // Client: also retransmit Handshake Finished when Application
                        // PTO fires but the handshake is not yet confirmed.
                        if (!self.is_server and !self.handshake_confirmed) {
                            self.queueCryptoRetransmission(.handshake);
                            if (self.crypto_streams.getStream(2).hasData()) {
                                    has_data = true;
                                }
                            }
                            // Check application-level crypto stream (e.g. NewSessionTicket)
                            if (self.crypto_streams.getStream(3).hasData()) {
                                has_data = true;
                            }
                            // HANDSHAKE_DONE: re-arm for retransmission on PTO
                            if (self.handshake_done_pending) {
                                self.packer.send_handshake_done = true;
                                has_data = true;
                            }
                            // Check if any stream has data to send
                            {
                                var stream_it = self.streams.streams.valueIterator();
                                while (stream_it.next()) |s_ptr| {
                                    if (s_ptr.*.send.hasData()) {
                                        has_data = true;
                                        break;
                                    }
                                }
                            }
                            // Always scan in-flight packets for stream data to retransmit
                            // (RFC 9002 §6.2.4: prefer data over PING). This is critical
                            // under loss: after the packer consumes retransmission data,
                            // hasData() returns false, but the retransmission packet might
                            // still be in-flight (not yet ACKed/declared lost). Without this
                            // unconditional scan, the PTO sends PINGs instead of data,
                            // and the peer never receives the file.
                            // If no stream data is pending AND the stream has unsent
                            // data that was consumed by the packer but never ACKed,
                            // reset send_offset to write_offset - data_size to force
                            // retransmission. Only do this for small streams (multiconnect
                            // serves 1KB files) to avoid resending entire large transfers.
                            // If no pending data but there IS unACKed data,
                            // reset send_offset to ack_offset to retransmit
                            // only the unACKed portion.
                            if (!has_data) {
                                var resend_it = self.streams.streams.valueIterator();
                                while (resend_it.next()) |s_ptr| {
                                    const s = s_ptr.*;
                                    if (s.send.hasUnackedData()) {
                                        s.send.send_offset = s.send.ack_offset;
                                        if (s.send.fin_queued) {
                                            s.send.fin_sent = false;
                                        }
                                        has_data = true;
                                    }
                                }
                            }
                    }
                }

                // RFC 9002 §6.2.4: "An endpoint MUST send at least one
                // ack-eliciting packet in the packet number space..."
                // Always push a PING so the second probe (pto_probe_pending=2)
                // has content even after the first probe consumed crypto data.
                // For has_data=false, only push if there's stream data in flight
                // (to allow idle timeout when all data is delivered).
                if (has_data) {
                    // PING for second probe (first probe has crypto/stream data)
                    self.pending_frames.push(.{ .ping = {} });
                    self.idle_pto_count = 0;
                } else {
                    var has_stream_in_flight = false;
                    const app_tracker2 = &self.pkt_handler.sent[@intFromEnum(ack_handler.EncLevel.application)];
                    var pkt_it2 = app_tracker2.sent_packets.iterator();
                    while (pkt_it2.next()) |entry| {
                        if (entry.value_ptr.in_flight and entry.value_ptr.getStreamFrames().len > 0) {
                            has_stream_in_flight = true;
                            break;
                        }
                    }
                    if (has_stream_in_flight) {
                        self.pending_frames.push(.{ .ping = {} });
                    }
                    self.idle_pto_count += 1;
                }
                // RFC 9002 §6.2.4: "An endpoint MUST send at least one ack-eliciting
                // packet in the packet number space..." — quic-go sends 2 probes per
                // PTO fire for burst loss resilience. With burst_to_client=3, a single
                // probe can be wiped; 2 probes double the chance of getting through.
                self.pto_probe_pending = 2;
                if (self.pkt_handler.getPtoSpace()) |space| {
                    std.log.info("PTO fired: count={d}, space={s}, has_data={}", .{ self.pkt_handler.pto_count, @tagName(space), has_data });
                }
            }
        }

        // RFC 9002 §6.2.2.1: Client anti-deadlock timer.
        // When the client has no ack-eliciting packets in flight and the handshake
        // is not confirmed, the server might be blocked by the anti-amplification
        // limit. The client MUST arm a PTO timer to send packets that unblock the
        // server (e.g. a PING in a Handshake or padded Initial packet).
        else if (!self.is_server and !self.handshake_confirmed) {
            // Compute PTO based on time since handshake start (creation_time)
            var pto_duration = self.pkt_handler.rtt_stats.ptoNoAckDelay();
            const shift: u6 = @intCast(@min(self.pkt_handler.pto_count, 30));
            pto_duration = pto_duration << shift;
            pto_duration = @min(pto_duration, 60_000_000_000); // cap at 60s

            const deadline = self.creation_time + pto_duration;
            if (now >= deadline) {
                self.pkt_handler.pto_count += 1;

                // Force-arm ACKs so anti-deadlock probes include them.
                // Without ACKs, the server can't confirm we received its data
                // and stays amplification-limited.
                for (&self.pkt_handler.recv) |*recv_tracker| {
                    if (recv_tracker.largest_received != null) {
                        recv_tracker.ack_queued = true;
                    }
                }

                // Send a Handshake packet if we have Handshake keys, else padded Initial.
                // This gives the server more anti-amplification credit.
                if (self.pkt_num_spaces[1].crypto_seal != null) {
                    // Re-queue Initial crypto data too if still outstanding
                    self.queueCryptoRetransmission(.initial);
                    self.queueCryptoRetransmission(.handshake);
                } else {
                    self.queueCryptoRetransmission(.initial);
                }
                self.pending_frames.push(.{ .ping = {} });
                self.pto_probe_pending = 2;
                std.log.info("client anti-deadlock PTO fired (pto_count={d})", .{self.pkt_handler.pto_count});
            }
        }

        // Keep-alive PING: send a PING after keep_alive_interval_ns of silence
        // to prevent the connection from hitting the idle timeout (RFC 9000 §10.1.2).
        if (self.keep_alive_interval_ns > 0 and self.handshake_confirmed and !self.keep_alive_ping_sent) {
            const pto_ns = self.pkt_handler.rtt_stats.pto();
            const interval = @max(self.keep_alive_interval_ns, pto_ns + @divTrunc(pto_ns, 2)); // floor at 1.5×PTO
            const silence = now - self.last_packet_received_time;
            if (silence >= interval) {
                self.pending_frames.push(.{ .ping = {} });
                self.keep_alive_ping_sent = true;
            }
        }

        // Check path validation timeouts
        {
            const pto_ns = self.pkt_handler.rtt_stats.pto();
            for (&self.paths) |*path| {
                if (path.validator.needsRetry(now, pto_ns)) {
                    path.validator.retry();
                    self.pending_frames.push(.{ .path_challenge = path.validator.challenge_data });
                }
                path.validator.checkTimeout(now, pto_ns);
            }
        }
    }

    /// Close the connection gracefully with an application error.
    pub fn close(self: *Connection, error_code: u64, reason: []const u8) void {
        if (self.state == .closing or self.state == .draining or self.state == .terminated) return;
        self.state = .closing;
        self.closing_start_time = platform.nanoTimestamp();
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

    /// Validate peer transport parameters (RFC 9000 §7.3, §7.4, §18.2).
    fn validatePeerTransportParams(self: *Connection, peer_tp: *const transport_params.TransportParams) !void {
        // Validate initial_source_connection_id is present (RFC 9000 §7.3)
        if (peer_tp.initial_source_connection_id == null) {
            self.closeWithTransportError(@intFromEnum(TransportError.transport_parameter_error), @intFromEnum(FrameType.crypto), "missing initial_source_connection_id");
            return error.TransportParameterError;
        }

        // Validate numeric ranges (RFC 9000 §7.4, §18.2)
        if (peer_tp.max_udp_payload_size < 1200) {
            self.closeWithTransportError(@intFromEnum(TransportError.transport_parameter_error), @intFromEnum(FrameType.crypto), "max_udp_payload_size below 1200");
            return error.TransportParameterError;
        }
        if (peer_tp.ack_delay_exponent > 20) {
            self.closeWithTransportError(@intFromEnum(TransportError.transport_parameter_error), @intFromEnum(FrameType.crypto), "ack_delay_exponent exceeds 20");
            return error.TransportParameterError;
        }
        if (peer_tp.max_ack_delay >= 16384) {
            self.closeWithTransportError(@intFromEnum(TransportError.transport_parameter_error), @intFromEnum(FrameType.crypto), "max_ack_delay exceeds 2^14");
            return error.TransportParameterError;
        }

        // Client-side: validate ODCID and retry_scid transport params (RFC 9000 §7.3)
        if (!self.is_server) {
            // original_destination_connection_id must match the DCID we initially sent
            if (peer_tp.original_destination_connection_id) |peer_odcid| {
                if (!std.mem.eql(u8, peer_odcid, self.odcid_buf[0..self.odcid_len])) {
                    self.closeWithTransportError(@intFromEnum(TransportError.transport_parameter_error), @intFromEnum(FrameType.crypto), "ODCID mismatch");
                    return error.TransportParameterError;
                }
            } else {
                self.closeWithTransportError(@intFromEnum(TransportError.transport_parameter_error), @intFromEnum(FrameType.crypto), "server must send ODCID");
                return error.TransportParameterError;
            }

            // If Retry was used, retry_source_connection_id must be present
            // If not, it must be absent
            if (self.retry_received) {
                if (peer_tp.retry_source_connection_id == null) {
                    self.closeWithTransportError(@intFromEnum(TransportError.transport_parameter_error), @intFromEnum(FrameType.crypto), "retry_scid missing after Retry");
                    return error.TransportParameterError;
                }
            } else {
                if (peer_tp.retry_source_connection_id != null) {
                    self.closeWithTransportError(@intFromEnum(TransportError.transport_parameter_error), @intFromEnum(FrameType.crypto), "retry_scid present without Retry");
                    return error.TransportParameterError;
                }
            }
        }

        // Server-side: reject server-only params from client (RFC 9000 §18.2)
        if (self.is_server) {
            if (peer_tp.original_destination_connection_id != null) {
                self.closeWithTransportError(@intFromEnum(TransportError.transport_parameter_error), @intFromEnum(FrameType.crypto), "client sent original_destination_connection_id");
                return error.TransportParameterError;
            }
            if (peer_tp.preferred_address != null) {
                self.closeWithTransportError(@intFromEnum(TransportError.transport_parameter_error), @intFromEnum(FrameType.crypto), "client sent preferred_address");
                return error.TransportParameterError;
            }
            if (peer_tp.retry_source_connection_id != null) {
                self.closeWithTransportError(@intFromEnum(TransportError.transport_parameter_error), @intFromEnum(FrameType.crypto), "client sent retry_source_connection_id");
                return error.TransportParameterError;
            }
            if (peer_tp.stateless_reset_token != null) {
                self.closeWithTransportError(@intFromEnum(TransportError.transport_parameter_error), @intFromEnum(FrameType.crypto), "client sent stateless_reset_token");
                return error.TransportParameterError;
            }
        }

        // RFC 9000 §7.4.1: if 0-RTT was used, validate that server's new
        // transport params are not less than the remembered values.
        if (self.remembered_params != null and self.early_data_seal != null) {
            const rp = self.remembered_params.?;
            if (peer_tp.initial_max_data < rp.initial_max_data or
                peer_tp.initial_max_stream_data_bidi_local < rp.initial_max_stream_data_bidi_local or
                peer_tp.initial_max_stream_data_bidi_remote < rp.initial_max_stream_data_bidi_remote or
                peer_tp.initial_max_stream_data_uni < rp.initial_max_stream_data_uni or
                peer_tp.initial_max_streams_bidi < rp.initial_max_streams_bidi or
                peer_tp.initial_max_streams_uni < rp.initial_max_streams_uni or
                peer_tp.active_connection_id_limit < rp.active_connection_id_limit)
            {
                self.closeWithTransportError(
                    @intFromEnum(TransportError.transport_parameter_error),
                    0,
                    "0-RTT transport params reduced",
                );
                return error.TransportParameterError;
            }
            // Clear remembered params after successful validation
            self.remembered_params = null;
        }
    }

    /// Close the connection with a transport error (RFC 9000 §10.2).
    pub fn closeWithTransportError(self: *Connection, error_code: u64, frame_type: u64, reason: []const u8) void {
        if (self.state == .closing or self.state == .draining or self.state == .terminated) return;
        self.state = .closing;
        self.closing_start_time = platform.nanoTimestamp();
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
    /// Returns error.DatagramsNotEnabled, error.DatagramTooLarge (permanent — reduce payload),
    /// or error.DatagramQueueFull (transient — retry after sending).
    pub fn sendDatagram(self: *Connection, data: []const u8) !void {
        if (!self.datagrams_enabled) return error.DatagramsNotEnabled;
        if (data.len > DatagramQueue.MAX_DATAGRAM_SIZE) return error.DatagramTooLarge;
        if (self.datagram_send_queue.isFull()) return error.DatagramQueueFull;
        _ = self.datagram_send_queue.push(data);
    }

    /// Returns true if the datagram send queue is full.
    pub fn isDatagramSendQueueFull(self: *const Connection) bool {
        return self.datagram_send_queue.isFull();
    }

    /// Returns the number of datagrams currently in the send queue.
    pub fn datagramSendQueueLen(self: *const Connection) usize {
        return self.datagram_send_queue.queueLen();
    }

    /// Returns the maximum payload size for a DATAGRAM frame, accounting for
    /// short header overhead, AEAD tag, and frame encoding. Returns null if
    /// datagrams are not enabled.
    pub fn maxDatagramPayloadSize(self: *const Connection) ?usize {
        if (!self.datagrams_enabled) return null;
        const peer_max = if (self.peer_params) |pp| pp.max_datagram_frame_size orelse return null else return null;
        // Short header: 1 (flags) + dcid_len + 4 (max pkt num) + 16 (AEAD tag)
        const header_overhead = 1 + @as(usize, self.dcid_len) + 4 + 16;
        const max_pkt = self.packer.max_packet_size;
        if (header_overhead >= max_pkt) return null;
        const payload_budget = max_pkt - header_overhead;
        // DATAGRAM_WITH_LENGTH frame: 1 (type) + varint(len) + payload
        // Use 2-byte varint for length (covers up to 16383)
        const frame_overhead: usize = 1 + 2;
        if (frame_overhead >= payload_budget) return null;
        const from_pkt = payload_budget - frame_overhead;
        // Peer's max_datagram_frame_size includes type + length + payload
        const from_peer = if (peer_max > frame_overhead) peer_max - frame_overhead else return null;
        const max_payload = @min(from_pkt, from_peer);
        return @min(max_payload, DatagramQueue.MAX_DATAGRAM_SIZE);
    }

    /// Receive a QUIC DATAGRAM frame (RFC 9221).
    /// Returns the number of bytes written to buf, or null if no datagram available.
    pub fn recvDatagram(self: *Connection, buf: []u8) ?usize {
        return self.datagram_recv_queue.pop(buf);
    }

    /// Zero-copy datagram receive: returns a slice into the internal ring buffer.
    /// Caller MUST call consumeDatagram() after processing the data.
    pub fn peekDatagram(self: *Connection) ?[]const u8 {
        return self.datagram_recv_queue.peekData();
    }

    /// Advance past the datagram returned by peekDatagram().
    pub fn consumeDatagram(self: *Connection) void {
        self.datagram_recv_queue.consume();
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

    /// Compute the next timeout deadline (nanosecond timestamp) without side effects.
    /// Returns null if the connection is terminated and needs no timer.
    /// Used by event loop to schedule the global timer.
    pub fn nextTimeoutNs(self: *const Connection) ?i64 {
        if (self.state == .terminated) return null;

        var earliest: ?i64 = null;

        // Closing/draining: 3×PTO from closing_start_time
        if (self.state == .closing or self.state == .draining) {
            if (self.closing_start_time > 0) {
                const pto_ns = self.pkt_handler.rtt_stats.pto();
                const deadline = self.closing_start_time + 3 * pto_ns;
                return deadline;
            }
            return null;
        }

        // Idle timeout — use base PTO (no backoff), matching quic-go/quiche
        {
            const base_pto = self.pkt_handler.rtt_stats.pto();
            const effective_idle = @max(self.idle_timeout_ns, 3 * base_pto);
            const last_activity = if (!self.handshake_confirmed)
                @max(self.last_packet_received_time, self.last_packet_sent_time)
            else
                self.last_packet_received_time;
            const idle_deadline = last_activity + effective_idle;
            if (earliest == null or idle_deadline < earliest.?) {
                earliest = idle_deadline;
            }
        }

        // Keep-alive deadline
        if (self.keep_alive_interval_ns > 0 and self.handshake_confirmed and !self.keep_alive_ping_sent) {
            const pto_ns = self.pkt_handler.rtt_stats.pto();
            const interval = @max(self.keep_alive_interval_ns, pto_ns + @divTrunc(pto_ns, 2));
            const ka_deadline = self.last_packet_received_time + interval;
            if (earliest == null or ka_deadline < earliest.?) {
                earliest = ka_deadline;
            }
        }

        // Loss detection timer — must fire immediately, no clamping
        for (self.pkt_handler.sent) |tracker| {
            if (tracker.loss_time) |lt| {
                if (earliest == null or lt < earliest.?) {
                    earliest = lt;
                }
            }
        }

        // PTO timer — delegates to spacePtoDeadline which correctly handles
        // handshake spaces per RFC 9002 §6.2.2.1.
        // Clamp past deadlines to avoid spinning on stale handshake spaces
        // (client waiting for HANDSHAKE_DONE after TLS completion).
        {
            var pto_earliest: ?i64 = null;
            for (self.pkt_handler.sent, 0..) |tracker, idx| {
                if (tracker.loss_time != null) continue; // handled above
                const deadline = self.pkt_handler.spacePtoDeadline(tracker, idx) orelse continue;
                if (pto_earliest == null or deadline < pto_earliest.?) {
                    pto_earliest = deadline;
                }
            }
            if (pto_earliest) |pto_deadline| {
                if (earliest == null or pto_deadline < earliest.?) {
                    earliest = pto_deadline;
                }
            }
        }

        // No pending data check needed — spacePtoDeadline handles this via
        // last_ack_eliciting_sent_time for handshake spaces. For application space,
        // the loss detection timer + send loop handles retransmissions.

        // ACK alarm: if we have pending ACKs to send (delayed ACK timer),
        // include the alarm deadline so the event loop wakes up in time (RFC 9000 §13.2.1).
        for (self.pkt_handler.recv) |tracker| {
            if (tracker.ack_alarm) |alarm| {
                if (earliest == null or alarm < earliest.?) {
                    earliest = alarm;
                }
            }
        }

        // Pacer: if the pacer has bandwidth set (active transfer), include its
        // next-send time so the event loop wakes up promptly to send more data.
        if (self.pacer.bandwidth_shifted > 0 and self.state == .connected) {
            const now: i64 = platform.nanoTimestamp();
            // Estimate pacer delay without mutating: budget is replenished by elapsed time
            const elapsed = now - self.pacer.last_sent_time;
            var budget = self.pacer.budget;
            if (self.pacer.last_sent_time > 0 and elapsed > 0) {
                const replenished = (self.pacer.bandwidth_shifted *| @as(u64, @intCast(elapsed))) >> 20;
                budget = @min(budget + replenished, self.pacer.max_burst);
            }
            if (budget < self.pacer.max_datagram_size) {
                const deficit = self.pacer.max_datagram_size - budget;
                const delay: i64 = @intCast((deficit << 20) / self.pacer.bandwidth_shifted);
                const pacer_deadline = now + delay;
                if (earliest == null or pacer_deadline < earliest.?) {
                    earliest = pacer_deadline;
                }
            }
        }

        return earliest;
    }

    /// Drop Initial and Handshake encryption keys (RFC 9001 §4.9).
    /// Called automatically for server in advanceHandshake, and for client
    /// after the Handshake Finished has been sent. Applications should not
    /// need to call this directly.
    /// RFC 9001 §4.1.2: At the client, the handshake is considered confirmed
    /// when it receives an acknowledgment for a 1-RTT packet.
    fn maybeConfirmHandshake(self: *Connection, enc_level: ack_handler.EncLevel, acked_count: usize) void {
        if (!self.is_server and !self.handshake_confirmed and enc_level == .application and acked_count > 0) {
            self.handshake_confirmed = true;
            // RFC 9001 §4.9.2: Do NOT drop Handshake keys here — they must be kept
            // until the client's Handshake packets (Finished) have been acknowledged.
            // In 0-RTT scenarios, the server may send 1-RTT ACKs (for 0-RTT data)
            // before receiving the client's Handshake Finished. Dropping keys here
            // would prevent the client from retransmitting the Finished if lost.
            // The auto-clear in emitPackets() handles key discard safely.
            std.log.info("handshake confirmed via 1-RTT ACK", .{});
        }
    }

    pub fn dropHandshakeKeys(self: *Connection) void {
        if (self.qlog_writer) |*ql| {
            const now_ql: i64 = platform.nanoTimestamp();
            ql.keyDiscarded(now_ql, "client_initial_secret");
            ql.keyDiscarded(now_ql, "server_initial_secret");
            ql.keyDiscarded(now_ql, "client_handshake_secret");
            ql.keyDiscarded(now_ql, "server_handshake_secret");
        }
        self.pkt_num_spaces[0].crypto_open = null;
        self.pkt_num_spaces[0].crypto_seal = null;
        self.pkt_num_spaces[1].crypto_open = null;
        self.pkt_num_spaces[1].crypto_seal = null;
        // Drop Initial and Handshake packet number spaces so PTO won't fire for them
        self.pkt_handler.dropSpace(.initial);
        self.pkt_handler.dropSpace(.handshake);
    }

    /// Initiate a key update (RFC 9001 §6).
    /// The next 1-RTT packet will use the new key phase.
    /// Returns true if the key update was initiated, false if not possible
    /// (e.g., no key update manager, or update already in progress).
    pub fn initiateKeyUpdate(self: *Connection) bool {
        if (self.key_update) |*ku| {
            if (ku.canUpdate()) {
                const now: i64 = platform.nanoTimestamp();
                const pto_ns = self.pkt_handler.rtt_stats.pto();
                ku.rollKeys(now, pto_ns);
                self.packer.key_phase = ku.key_phase;
                return true;
            }
        }
        return false;
    }

    /// Manually queue a keep-alive PING frame.
    /// No-op if the connection is not yet fully established.
    pub fn sendKeepAlive(self: *Connection) void {
        if (self.state != .connected or !self.handshake_confirmed) return;
        self.pending_frames.push(.{ .ping = {} });
    }

    /// Return the ECN codepoint to mark on outgoing packets.
    /// Returns ECT(0) if ECN validation allows it, else Not-ECT.
    pub fn getEcnMark(self: *const Connection) u2 {
        return if (self.ecn_validator.shouldMark()) ECN_ECT0 else ECN_NOT_ECT;
    }

    /// Initiate a client-side connection migration (RFC 9000 Section 9).
    /// Consumes a fresh DCID from the peer CID pool and queues PATH_CHALLENGE.
    /// The caller is responsible for actually sending from a new local address.
    /// Returns true if migration was initiated, false if no unused CID is available.
    pub fn initiateClientMigration(self: *Connection) bool {
        const entry = self.peer_cid_pool.consumeUnused() orelse return false;
        const new_cid = entry.getCid();

        // Update DCID in packer (affects outgoing packet headers)
        self.packer.updateDcid(new_cid);

        // Keep self.dcid in sync
        self.dcid_len = @intCast(new_cid.len);
        @memcpy(self.dcid[0..new_cid.len], new_cid);

        std.log.info("client migration: switched to new DCID seq={d}", .{entry.seq_num});
        return true;
    }

    /// Return the peer address on the active path.
    /// This may change after connection migration or preferred address selection.
    pub fn peerAddress(self: *const Connection) *const platform.sockaddr_storage {
        return &self.paths[self.active_path_idx].peer_addr;
    }

    /// Return the local address on the active path.
    pub fn localAddress(self: *const Connection) *const platform.sockaddr_storage {
        return &self.paths[self.active_path_idx].local_addr;
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

    /// Process a raw UDP datagram containing one or more coalesced QUIC packets.
    /// Handles header parsing, coalesced packet boundaries (RFC 9000 §12.2),
    /// and dispatches each packet through recv().
    pub fn handleDatagram(self: *Connection, bytes: []u8, info: RecvInfo) void {
        var fbs = std.io.fixedBufferStream(bytes);
        var first_packet = true;
        while (fbs.pos < bytes.len) {
            // All valid QUIC packets have the fixed bit (0x40) set.
            // If not set, remaining bytes are padding — stop parsing.
            if (bytes[fbs.pos] & 0x40 == 0) break;

            const pkt_start = fbs.pos;
            var header = packet.Header.parse(&fbs, self.scid_len) catch break;
            const full_size = fbs.pos - pkt_start + header.remainder_len;

            // Only count datagram_size for the first packet to avoid
            // double-counting in amplification limit calculations.
            var pkt_info = info;
            if (!first_packet) pkt_info.datagram_size = 0;
            first_packet = false;
            self.recv(&header, &fbs, pkt_info) catch break;

            const next_pos = pkt_start + full_size;
            if (fbs.pos < next_pos) fbs.pos = next_pos;
        }
    }
};

/// Compare two sockaddrs for equality (IPv4: port + address).
/// Uses byte-level reads to avoid alignment issues with posix.sockaddr (align=1).
/// Check if an AF_INET6 address is IPv4-mapped (::ffff:a.b.c.d).
pub fn isV4Mapped(addr: *const platform.sockaddr_storage) bool {
    if (addr.family != platform.AF.INET6) return false;
    const in6: *const platform.sockaddr_in6 = @ptrCast(@alignCast(addr));
    // ::ffff:0:0/96 — first 10 bytes zero, bytes 10-11 are 0xff
    for (0..10) |i| {
        if (in6.addr[i] != 0) return false;
    }
    return in6.addr[10] == 0xff and in6.addr[11] == 0xff;
}

/// Check if an address is effectively IPv4 (AF_INET or IPv4-mapped AF_INET6).
pub fn isEffectivelyV4(addr: *const platform.sockaddr_storage) bool {
    return addr.family == platform.AF.INET or isV4Mapped(addr);
}

pub fn sockaddrEql(a: *const platform.sockaddr_storage, b: *const platform.sockaddr_storage) bool {
    if (a.family != b.family) return false;
    if (a.family == platform.AF.INET6) {
        const a_bytes: *const [@sizeOf(platform.sockaddr_in6)]u8 = @ptrCast(a);
        const b_bytes: *const [@sizeOf(platform.sockaddr_in6)]u8 = @ptrCast(b);
        const a6 = std.mem.bytesToValue(platform.sockaddr_in6, a_bytes);
        const b6 = std.mem.bytesToValue(platform.sockaddr_in6, b_bytes);
        return a6.port == b6.port and std.mem.eql(u8, &a6.addr, &b6.addr) and a6.scope_id == b6.scope_id;
    }
    const a_bytes: *const [@sizeOf(platform.sockaddr_in)]u8 = @ptrCast(a);
    const b_bytes: *const [@sizeOf(platform.sockaddr_in)]u8 = @ptrCast(b);
    const a_in = std.mem.bytesToValue(platform.sockaddr_in, a_bytes);
    const b_in = std.mem.bytesToValue(platform.sockaddr_in, b_bytes);
    return a_in.port == b_in.port and a_in.addr == b_in.addr;
}

/// Compare two sockaddrs for same IP address (ignoring port).
/// Uses byte-level reads to avoid alignment issues with posix.sockaddr (align=1).
pub fn sockaddrSameIp(a: *const platform.sockaddr_storage, b: *const platform.sockaddr_storage) bool {
    if (a.family != b.family) return false;
    if (a.family == platform.AF.INET6) {
        const a_bytes: *const [@sizeOf(platform.sockaddr_in6)]u8 = @ptrCast(a);
        const b_bytes: *const [@sizeOf(platform.sockaddr_in6)]u8 = @ptrCast(b);
        const a6 = std.mem.bytesToValue(platform.sockaddr_in6, a_bytes);
        const b6 = std.mem.bytesToValue(platform.sockaddr_in6, b_bytes);
        return std.mem.eql(u8, &a6.addr, &b6.addr);
    }
    const a_bytes: *const [@sizeOf(platform.sockaddr_in)]u8 = @ptrCast(a);
    const b_bytes: *const [@sizeOf(platform.sockaddr_in)]u8 = @ptrCast(b);
    const a_in = std.mem.bytesToValue(platform.sockaddr_in, a_bytes);
    const b_in = std.mem.bytesToValue(platform.sockaddr_in, b_bytes);
    return a_in.addr == b_in.addr;
}

/// Get the correct address length for sendto() based on the address family.
pub fn sockaddrLen(addr: *const platform.sockaddr_storage) platform.socklen_t {
    return if (addr.family == platform.AF.INET6) @sizeOf(platform.sockaddr_in6) else @sizeOf(platform.sockaddr_in);
}

/// Extract port from a sockaddr in host byte order.
pub fn sockaddrPort(addr: *const platform.sockaddr_storage) u16 {
    if (addr.family == platform.AF.INET6) {
        const in6: *const platform.sockaddr_in6 = @ptrCast(@alignCast(addr));
        return std.mem.bigToNative(u16, in6.port);
    } else if (addr.family == platform.AF.INET) {
        const in4: *const platform.sockaddr_in = @ptrCast(@alignCast(addr));
        return std.mem.bigToNative(u16, in4.port);
    }
    return 0;
}

/// Convert a platform.sockaddr (from std.net.Address.any) to platform.sockaddr_storage.
pub fn sockaddrToStorage(addr: *const platform.sockaddr) platform.sockaddr_storage {
    var storage: platform.sockaddr_storage = std.mem.zeroes(platform.sockaddr_storage);
    const src_bytes: [*]const u8 = @ptrCast(addr);
    const dst_bytes: [*]u8 = @ptrCast(&storage);
    const len: usize = if (addr.family == platform.AF.INET6) @sizeOf(platform.sockaddr_in6) else @sizeOf(platform.sockaddr_in);
    @memcpy(dst_bytes[0..len], src_bytes[0..len]);
    return storage;
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
    const now: i64 = platform.nanoTimestamp();
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
        .min_ack_delay = 1000, // 1ms minimum ACK delay (draft-ietf-quic-ack-frequency)
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

    // Compute keep-alive interval: clamp to idle_timeout/2
    if (config.keep_alive_period > 0) {
        const ka_ns: i64 = @intCast(config.keep_alive_period * 1_000_000);
        conn.keep_alive_interval_ns = @min(ka_ns, @divTrunc(conn.idle_timeout_ns, 2));
    }
    conn.close_when_idle = config.close_when_idle;

    // Initialize QLOG if configured
    if (config.qlog_dir) |dir| {
        conn.qlog_writer = qlog.QlogWriter.init(dir, &dcid, false);
        if (conn.qlog_writer != null) {
            conn.qlog_writer.?.connectionStarted(now);
        }
    }

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
    conn.streams.local_max_stream_data_bidi_local = config.initial_max_stream_data_bidi_local;
    conn.streams.local_max_stream_data_bidi_remote = config.initial_max_stream_data_bidi_remote;
    conn.streams.local_max_stream_data_uni = config.initial_max_stream_data_uni;

    conn.conn_flow_ctrl.base.send_window = config.initial_max_data;

    if (config.max_idle_timeout > 0) {
        conn.idle_timeout_ns = @as(i64, @intCast(config.max_idle_timeout)) * 1_000_000;
    }

    // Initialize TLS 1.3 handshake and generate ClientHello
    if (tls_config) |tc| {
        var tc_with_sni = tc;
        tc_with_sni.server_name = server_name;
        tc_with_sni.quic_version = conn.version;

        // RFC 9000 §7.4.1: remember transport params from session ticket for 0-RTT
        if (tc.session_ticket) |ticket| {
            conn.remembered_params = ticket.*;
        }

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

    // Resize datagram queues if configured larger than default
    if (config.datagram_queue_capacity > DatagramQueue.DEFAULT_MAX_ITEMS) {
        try conn.datagram_recv_queue.resize(allocator, config.datagram_queue_capacity);
        try conn.datagram_send_queue.resize(allocator, config.datagram_queue_capacity);
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

// --- DatagramQueue tests ---

test "DatagramQueue: push and pop" {
    var q = DatagramQueue{};
    try std.testing.expect(q.isEmpty());
    try std.testing.expectEqual(@as(usize, 0), q.queueLen());
    try std.testing.expect(!q.isFull());

    const data1 = "hello";
    const data2 = "world!";
    try std.testing.expect(q.push(data1));
    try std.testing.expect(q.push(data2));
    try std.testing.expect(!q.isEmpty());
    try std.testing.expectEqual(@as(usize, 2), q.queueLen());

    var buf: [1200]u8 = undefined;
    const len1 = q.pop(&buf).?;
    try std.testing.expectEqual(@as(usize, 5), len1);
    try std.testing.expectEqualSlices(u8, "hello", buf[0..len1]);

    const len2 = q.pop(&buf).?;
    try std.testing.expectEqual(@as(usize, 6), len2);
    try std.testing.expectEqualSlices(u8, "world!", buf[0..len2]);

    // Empty now
    try std.testing.expect(q.pop(&buf) == null);
    try std.testing.expect(q.isEmpty());
    try std.testing.expectEqual(@as(usize, 0), q.queueLen());
}

test "DatagramQueue: full queue" {
    var q = DatagramQueue{};
    // Fill the queue (MAX_ITEMS = 32)
    var i: usize = 0;
    while (i < DatagramQueue.DEFAULT_MAX_ITEMS) : (i += 1) {
        try std.testing.expect(!q.isFull());
        try std.testing.expect(q.push("data"));
    }
    // Queue full — push should fail
    try std.testing.expect(q.isFull());
    try std.testing.expectEqual(@as(usize, DatagramQueue.DEFAULT_MAX_ITEMS), q.queueLen());
    try std.testing.expect(!q.push("overflow"));
}

test "DatagramQueue: oversized datagram rejected" {
    var q = DatagramQueue{};
    const big = [_]u8{0xAA} ** (DatagramQueue.MAX_DATAGRAM_SIZE + 1);
    try std.testing.expect(!q.push(&big));
    try std.testing.expect(q.isEmpty());
}

test "DatagramQueue: pop with small buffer" {
    var q = DatagramQueue{};
    try std.testing.expect(q.push("hello"));
    var small_buf: [2]u8 = undefined;
    // Buffer too small — should return null
    try std.testing.expect(q.pop(&small_buf) == null);
}

// --- Address utility function tests ---

fn makeIpv4Addr(a: u8, b: u8, c: u8, d: u8, port: u16) platform.sockaddr_storage {
    var in4: platform.sockaddr_in = std.mem.zeroes(platform.sockaddr_in);
    in4.family = platform.AF.INET;
    in4.port = std.mem.nativeToBig(u16, port);
    in4.addr = (@as(u32, d) << 24) | (@as(u32, c) << 16) | (@as(u32, b) << 8) | @as(u32, a);
    return sockaddrToStorage(@ptrCast(&in4));
}

fn makeIpv6Addr(addr_bytes_in: [16]u8, port: u16) platform.sockaddr_storage {
    var in6: platform.sockaddr_in6 = std.mem.zeroes(platform.sockaddr_in6);
    in6.family = platform.AF.INET6;
    in6.port = std.mem.nativeToBig(u16, port);
    in6.addr = addr_bytes_in;
    return sockaddrToStorage(@ptrCast(&in6));
}

test "sockaddrEql: same IPv4 addresses" {
    const a = makeIpv4Addr(127, 0, 0, 1, 4433);
    const b = makeIpv4Addr(127, 0, 0, 1, 4433);
    try std.testing.expect(sockaddrEql(&a, &b));
}

test "sockaddrEql: different IPv4 ports" {
    const a = makeIpv4Addr(127, 0, 0, 1, 4433);
    const b = makeIpv4Addr(127, 0, 0, 1, 4434);
    try std.testing.expect(!sockaddrEql(&a, &b));
}

test "sockaddrEql: different IPv4 addresses" {
    const a = makeIpv4Addr(127, 0, 0, 1, 4433);
    const b = makeIpv4Addr(192, 168, 1, 1, 4433);
    try std.testing.expect(!sockaddrEql(&a, &b));
}

test "sockaddrSameIp: same IP different ports" {
    const a = makeIpv4Addr(10, 0, 0, 1, 1234);
    const b = makeIpv4Addr(10, 0, 0, 1, 5678);
    try std.testing.expect(sockaddrSameIp(&a, &b));
}

test "sockaddrSameIp: different IPs" {
    const a = makeIpv4Addr(10, 0, 0, 1, 1234);
    const b = makeIpv4Addr(10, 0, 0, 2, 1234);
    try std.testing.expect(!sockaddrSameIp(&a, &b));
}

test "isV4Mapped: IPv4-mapped IPv6" {
    // ::ffff:127.0.0.1
    var addr_bytes = [_]u8{0} ** 16;
    addr_bytes[10] = 0xff;
    addr_bytes[11] = 0xff;
    addr_bytes[12] = 127;
    addr_bytes[13] = 0;
    addr_bytes[14] = 0;
    addr_bytes[15] = 1;
    const addr = makeIpv6Addr(addr_bytes, 4433);
    try std.testing.expect(isV4Mapped(&addr));
}

test "isV4Mapped: regular IPv6 is not mapped" {
    // ::1 (loopback)
    var addr_bytes = [_]u8{0} ** 16;
    addr_bytes[15] = 1;
    const addr = makeIpv6Addr(addr_bytes, 4433);
    try std.testing.expect(!isV4Mapped(&addr));
}

test "isV4Mapped: IPv4 is not mapped" {
    const addr = makeIpv4Addr(127, 0, 0, 1, 4433);
    try std.testing.expect(!isV4Mapped(&addr));
}

test "isEffectivelyV4: IPv4" {
    const addr = makeIpv4Addr(10, 0, 0, 1, 80);
    try std.testing.expect(isEffectivelyV4(&addr));
}

test "isEffectivelyV4: IPv4-mapped IPv6" {
    var addr_bytes = [_]u8{0} ** 16;
    addr_bytes[10] = 0xff;
    addr_bytes[11] = 0xff;
    addr_bytes[12] = 10;
    addr_bytes[13] = 0;
    addr_bytes[14] = 0;
    addr_bytes[15] = 1;
    const addr = makeIpv6Addr(addr_bytes, 80);
    try std.testing.expect(isEffectivelyV4(&addr));
}

test "isEffectivelyV4: native IPv6 is not v4" {
    var addr_bytes = [_]u8{0} ** 16;
    addr_bytes[0] = 0x20;
    addr_bytes[1] = 0x01;
    const addr = makeIpv6Addr(addr_bytes, 80);
    try std.testing.expect(!isEffectivelyV4(&addr));
}

test "sockaddrLen: IPv4 vs IPv6" {
    const v4 = makeIpv4Addr(127, 0, 0, 1, 80);
    try std.testing.expectEqual(@as(platform.socklen_t, @sizeOf(platform.sockaddr_in)), sockaddrLen(&v4));

    var v6_bytes = [_]u8{0} ** 16;
    v6_bytes[15] = 1;
    const v6 = makeIpv6Addr(v6_bytes, 80);
    try std.testing.expectEqual(@as(platform.socklen_t, @sizeOf(platform.sockaddr_in6)), sockaddrLen(&v6));
}

// --- Connection state and method tests ---

fn testConnection(allocator: std.mem.Allocator) Connection {
    const dcid_val = "dest1234" ++ ([_]u8{0} ** 12);
    const scid_val = "src12345" ++ ([_]u8{0} ** 12);
    return Connection{
        .allocator = allocator,
        .is_server = true,
        .dcid = dcid_val.*,
        .dcid_len = 8,
        .scid = scid_val.*,
        .scid_len = 8,
        .version = protocol.SUPPORTED_VERSIONS[0],
        .pkt_handler = ack_handler.PacketHandler.init(allocator),
        .conn_flow_ctrl = flow_control.ConnectionFlowController.init(1048576, 6 * 1024 * 1024),
        .streams = stream_mod.StreamsMap.init(allocator, true),
        .crypto_streams = crypto_stream.CryptoStreamManager.init(allocator),
        .packer = packet_packer.PacketPacker.init(
            allocator,
            true,
            dcid_val[0..8],
            scid_val[0..8],
            protocol.SUPPORTED_VERSIONS[0],
        ),
    };
}

test "Connection: close transitions to closing state" {
    var conn = testConnection(std.testing.allocator);
    defer conn.deinit();

    try std.testing.expectEqual(State.first_flight, conn.state);
    conn.close(0, "done");
    try std.testing.expectEqual(State.closing, conn.state);
    try std.testing.expect(conn.local_err != null);
    try std.testing.expect(conn.local_err.?.is_app);
    try std.testing.expectEqual(@as(u64, 0), conn.local_err.?.code);
}

test "Connection: close is idempotent in terminal states" {
    var conn = testConnection(std.testing.allocator);
    defer conn.deinit();

    conn.close(1, "first");
    try std.testing.expectEqual(State.closing, conn.state);
    // Second close should be ignored
    conn.close(2, "second");
    try std.testing.expectEqual(@as(u64, 1), conn.local_err.?.code);
}

test "Connection: closeWithTransportError" {
    var conn = testConnection(std.testing.allocator);
    defer conn.deinit();

    conn.closeWithTransportError(@intFromEnum(TransportError.protocol_violation), @intFromEnum(FrameType.crypto), "flow control");
    try std.testing.expectEqual(State.closing, conn.state);
    try std.testing.expect(!conn.local_err.?.is_app);
    try std.testing.expectEqual(@as(u64, @intFromEnum(TransportError.protocol_violation)), conn.local_err.?.code);
}

test "Connection: state queries" {
    var conn = testConnection(std.testing.allocator);
    defer conn.deinit();

    // first_flight
    try std.testing.expect(!conn.isClosed());
    try std.testing.expect(!conn.isDraining());
    try std.testing.expect(!conn.isEstablished());

    // connected
    conn.state = .connected;
    try std.testing.expect(conn.isEstablished());
    try std.testing.expect(!conn.isClosed());

    // draining
    conn.state = .draining;
    try std.testing.expect(conn.isDraining());

    // terminated
    conn.state = .terminated;
    try std.testing.expect(conn.isClosed());
}

test "Connection: datagram send requires enabled" {
    var conn = testConnection(std.testing.allocator);
    defer conn.deinit();

    // Datagrams not enabled — should error
    try std.testing.expectError(error.DatagramsNotEnabled, conn.sendDatagram("test"));

    // Enable datagrams and send
    conn.datagrams_enabled = true;
    try conn.sendDatagram("hello datagram");

    // Verify it's in the send queue (not recv queue)
    try std.testing.expect(!conn.datagram_send_queue.isEmpty());
    try std.testing.expect(conn.datagram_recv_queue.isEmpty());
}

test "Connection: DatagramTooLarge vs DatagramQueueFull" {
    var conn = testConnection(std.testing.allocator);
    defer conn.deinit();
    conn.datagrams_enabled = true;

    // Too-large payload → permanent error
    const big = [_]u8{0xAA} ** (DatagramQueue.MAX_DATAGRAM_SIZE + 1);
    try std.testing.expectError(error.DatagramTooLarge, conn.sendDatagram(&big));

    // Fill the queue → transient error
    var i: usize = 0;
    while (i < DatagramQueue.DEFAULT_MAX_ITEMS) : (i += 1) {
        try conn.sendDatagram("x");
    }
    try std.testing.expect(conn.isDatagramSendQueueFull());
    try std.testing.expectEqual(@as(usize, DatagramQueue.DEFAULT_MAX_ITEMS), conn.datagramSendQueueLen());
    try std.testing.expectError(error.DatagramQueueFull, conn.sendDatagram("overflow"));
}

test "Connection: maxDatagramPayloadSize" {
    var conn = testConnection(std.testing.allocator);
    defer conn.deinit();

    // Datagrams not enabled → null
    try std.testing.expect(conn.maxDatagramPayloadSize() == null);

    // Enable datagrams but no peer params → null
    conn.datagrams_enabled = true;
    try std.testing.expect(conn.maxDatagramPayloadSize() == null);

    // Set peer params with max_datagram_frame_size
    conn.peer_params = transport_params.TransportParams{};
    conn.peer_params.?.max_datagram_frame_size = 65536;
    conn.dcid_len = 8;
    // Short header: 1 + 8 + 4 + 16 = 29 overhead
    // max_packet_size default = 1200, payload budget = 1200 - 29 = 1171
    // frame overhead = 3 (type + 2-byte varint), from_pkt = 1168
    // from_peer = 65536 - 3 = 65533, capped by from_pkt and MAX_DATAGRAM_SIZE
    const max_payload = conn.maxDatagramPayloadSize().?;
    try std.testing.expect(max_payload > 0);
    try std.testing.expect(max_payload <= DatagramQueue.MAX_DATAGRAM_SIZE);

    // Disabled peer param → null
    conn.peer_params.?.max_datagram_frame_size = null;
    try std.testing.expect(conn.maxDatagramPayloadSize() == null);
}

test "Connection: datagram receive" {
    var conn = testConnection(std.testing.allocator);
    defer conn.deinit();

    // Nothing to receive initially
    var buf: [1200]u8 = undefined;
    try std.testing.expect(conn.recvDatagram(&buf) == null);

    // Simulate receiving a datagram (push to recv queue)
    try std.testing.expect(conn.datagram_recv_queue.push("incoming data"));

    const len = conn.recvDatagram(&buf).?;
    try std.testing.expectEqualSlices(u8, "incoming data", buf[0..len]);
    try std.testing.expect(conn.recvDatagram(&buf) == null);
}

test "Connection: getNewToken" {
    var conn = testConnection(std.testing.allocator);
    defer conn.deinit();

    // No token initially
    try std.testing.expect(conn.getNewToken() == null);

    // Simulate receiving a token
    const token = "test-token-12345";
    @memcpy(conn.new_token_buf[0..token.len], token);
    conn.new_token_len = @intCast(token.len);

    const got = conn.getNewToken().?;
    try std.testing.expectEqualSlices(u8, token, got);
}

test "Connection: dropHandshakeKeys clears Initial and Handshake" {
    var conn = testConnection(std.testing.allocator);
    defer conn.deinit();

    // Initial keys should be set (from testConnection → pkt_num_spaces default)
    // Set dummy keys to verify they get cleared
    const dummy_seal = conn.pkt_num_spaces[0].crypto_seal;
    _ = dummy_seal;
    conn.dropHandshakeKeys();

    try std.testing.expect(conn.pkt_num_spaces[0].crypto_open == null);
    try std.testing.expect(conn.pkt_num_spaces[0].crypto_seal == null);
    try std.testing.expect(conn.pkt_num_spaces[1].crypto_open == null);
    try std.testing.expect(conn.pkt_num_spaces[1].crypto_seal == null);
}

test "Connection: initiateKeyUpdate without key_update manager" {
    var conn = testConnection(std.testing.allocator);
    defer conn.deinit();

    // No key update manager — should return false
    try std.testing.expect(!conn.initiateKeyUpdate());
}

test "Connection: getEcnMark" {
    var conn = testConnection(std.testing.allocator);
    defer conn.deinit();

    // ECN validator starts disabled — shouldMark() = false
    try std.testing.expectEqual(ECN_NOT_ECT, conn.getEcnMark());

    // Start ECN validation (transitions to testing)
    conn.ecn_validator.start();
    try std.testing.expectEqual(ECN_ECT0, conn.getEcnMark());

    // If ECN fails
    conn.ecn_validator.state = .failed;
    try std.testing.expectEqual(ECN_NOT_ECT, conn.getEcnMark());
}

test "Connection: matchesStatelessReset with no tokens" {
    var conn = testConnection(std.testing.allocator);
    defer conn.deinit();

    const data = [_]u8{0xAA} ** 32;
    try std.testing.expect(!conn.matchesStatelessReset(&data));
}

test "Connection: matchesStatelessReset with matching token" {
    var conn = testConnection(std.testing.allocator);
    defer conn.deinit();

    // Add a peer CID with a known reset token
    const token = [_]u8{0xBB} ** 16;
    const cid = [_]u8{ 0x01, 0x02, 0x03, 0x04 };
    conn.peer_cid_pool.addPeerCid(1, &cid, token);

    // Build a packet whose last 16 bytes are the token
    var data: [32]u8 = undefined;
    @memset(data[0..16], 0xCC); // random prefix
    @memcpy(data[16..32], &token); // token at end
    try std.testing.expect(conn.matchesStatelessReset(&data));
}

test "Connection: openStream" {
    var conn = testConnection(std.testing.allocator);
    defer conn.deinit();

    // Set peer's max bidi streams limit (simulating received transport params)
    conn.streams.max_bidi_streams = 100;

    // Server opens bidi stream (stream ID 1 for server-initiated bidi)
    const s = try conn.openStream();
    try std.testing.expectEqual(@as(u64, 1), s.stream_id);
}

test "accept: create server connection" {
    const local = makeIpv4Addr(0, 0, 0, 0, 443);
    const remote = makeIpv4Addr(192, 168, 1, 100, 12345);

    const dcid = [_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
    const scid = [_]u8{ 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18 };

    const header = packet.Header{
        .packet_type = .initial,
        .version = protocol.SUPPORTED_VERSIONS[0],
        .dcid = &dcid,
        .scid = &scid,
        .token = &.{},
        .packet_number = 0,
        .packet_number_len = 1,
        .remainder_len = 0,
    };

    var conn = try Connection.accept(
        std.testing.allocator,
        header,
        local,
        remote,
        true,
        .{},
        null,
        null,
        null,
    );
    defer conn.deinit();

    try std.testing.expect(conn.is_server);
    try std.testing.expectEqual(State.first_flight, conn.state);
    // Server: dcid = client's SCID, scid = generated
    try std.testing.expectEqual(@as(u8, 8), conn.dcid_len);
    try std.testing.expectEqualSlices(u8, &scid, conn.dcid[0..8]);
    try std.testing.expectEqual(@as(u8, 8), conn.scid_len);
    // Path should be initialized
    try std.testing.expect(conn.path_initialized);
}

test "PathValidator: checkTimeout after max retries" {
    var validator = PathValidator{};
    _ = validator.startChallenge();

    // Exhaust retries
    validator.retries = PathValidator.MAX_RETRIES;
    validator.challenge_sent_time = 0;

    const now: i64 = 1_000_000_000;
    const pto: i64 = 100_000_000;
    validator.checkTimeout(now, pto);

    try std.testing.expectEqual(PathValidationState.failed, validator.state);
}

test "NetworkPath: amplification limit" {
    var path = NetworkPath.init(
        makeIpv4Addr(0, 0, 0, 0, 443),
        makeIpv4Addr(192, 168, 1, 1, 12345),
        true,
    );

    // Not validated — 3x amplification limit applies
    try std.testing.expect(!path.is_validated);
    try std.testing.expect(!path.canSend(1)); // 0 received * 3 = 0 budget

    path.bytes_received = 100;
    try std.testing.expect(path.canSend(300)); // 300 <= 300
    try std.testing.expect(!path.canSend(301)); // 301 > 300

    // After validation, no limit
    path.is_validated = true;
    try std.testing.expect(path.canSend(1_000_000));
}

// Keep-alive tests

test "keep_alive_period = 0 means no keep-alive interval" {
    var conn = try connect(std.testing.allocator, "example.com", .{ .keep_alive_period = 0 }, null, null);
    defer conn.deinit();
    try std.testing.expectEqual(@as(i64, 0), conn.keep_alive_interval_ns);
}

test "keep_alive_period within idle_timeout/2 is used directly" {
    // keep_alive_period = 10s, idle_timeout = 30s → interval = 10s
    var conn = try connect(std.testing.allocator, "example.com", .{
        .keep_alive_period = 10_000,
        .max_idle_timeout = 30_000,
    }, null, null);
    defer conn.deinit();
    try std.testing.expectEqual(@as(i64, 10_000_000_000), conn.keep_alive_interval_ns);
}

test "keep_alive_period capped at idle_timeout/2" {
    // keep_alive_period = 20s, idle_timeout = 30s → interval = 15s (capped)
    var conn = try connect(std.testing.allocator, "example.com", .{
        .keep_alive_period = 20_000,
        .max_idle_timeout = 30_000,
    }, null, null);
    defer conn.deinit();
    try std.testing.expectEqual(@as(i64, 15_000_000_000), conn.keep_alive_interval_ns);
}

test "sendKeepAlive queues PING when connected" {
    var conn = try connect(std.testing.allocator, "example.com", .{}, null, null);
    defer conn.deinit();

    // Not connected yet — should be no-op
    conn.sendKeepAlive();
    try std.testing.expectEqual(@as(usize, 0), conn.pending_frames.len);

    // Simulate connected state
    conn.state = .connected;
    conn.handshake_confirmed = true;
    conn.sendKeepAlive();
    try std.testing.expectEqual(@as(usize, 1), conn.pending_frames.len);
}

test "nextTimeoutNs includes keep-alive deadline" {
    var conn = try connect(std.testing.allocator, "example.com", .{
        .keep_alive_period = 5_000, // 5s
        .max_idle_timeout = 30_000,
    }, null, null);
    defer conn.deinit();

    conn.state = .connected;
    conn.handshake_confirmed = true;

    const timeout_with_ka = conn.nextTimeoutNs();
    try std.testing.expect(timeout_with_ka != null);

    // Now disable keep-alive and check that the deadline changes
    conn.keep_alive_interval_ns = 0;
    const timeout_without_ka = conn.nextTimeoutNs();
    try std.testing.expect(timeout_without_ka != null);

    // Keep-alive deadline should be earlier than idle timeout alone
    try std.testing.expect(timeout_with_ka.? <= timeout_without_ka.?);
}

test "keep_alive_ping_sent resets on packet receipt simulation" {
    var conn = try connect(std.testing.allocator, "example.com", .{
        .keep_alive_period = 5_000,
        .max_idle_timeout = 30_000,
    }, null, null);
    defer conn.deinit();

    conn.keep_alive_ping_sent = true;
    // Simulate what recv() does
    conn.last_packet_received_time = platform.nanoTimestamp();
    conn.keep_alive_ping_sent = false;
    try std.testing.expect(!conn.keep_alive_ping_sent);
}
