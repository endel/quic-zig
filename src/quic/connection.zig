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

pub const ConnectionError = struct {
    is_app: bool,
    code: u64,
    reason: []const u8,
};

pub const RecvInfo = struct {
    to: posix.sockaddr,
    from: posix.sockaddr,
};

/// Configuration for a QUIC connection.
pub const ConnectionConfig = struct {
    max_idle_timeout: u64 = 30_000, // ms
    initial_max_data: u64 = 1_048_576, // 1MB
    initial_max_stream_data_bidi_local: u64 = 65536,
    initial_max_stream_data_bidi_remote: u64 = 65536,
    initial_max_stream_data_uni: u64 = 65536,
    initial_max_streams_bidi: u64 = 100,
    initial_max_streams_uni: u64 = 100,
    max_datagram_frame_size: ?u64 = null,
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

    // Key update manager for 1-RTT key rotation (RFC 9001 Section 6)
    key_update: ?quic_crypto.KeyUpdateManager = null,

    // Connection state
    got_peer_conn_id: bool = false,
    peer_max_cid_seq: u64 = 0,
    active_cid_seq: u64 = 0,
    local_err: ?ConnectionError = null,
    handshake_confirmed: bool = false,

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
    ) !Connection {
        const initial_path = NetworkPath.init(local, remote, true);
        const now: i64 = @intCast(std.time.nanoTimestamp());

        var conn = Connection{
            .allocator = allocator,
            .version = header.version,
            .is_server = is_server,
            .paths = .{ initial_path, undefined },
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

        // Build transport params AFTER CIDs are stored in conn (to avoid dangling slices)
        const local_params: transport_params.TransportParams = .{
            .original_destination_connection_id = if (is_server) header.dcid else null,
            .initial_source_connection_id = conn.scid[0..conn.scid_len],
            .max_idle_timeout = config.max_idle_timeout,
            .initial_max_data = config.initial_max_data,
            .initial_max_stream_data_bidi_local = config.initial_max_stream_data_bidi_local,
            .initial_max_stream_data_bidi_remote = config.initial_max_stream_data_bidi_remote,
            .initial_max_stream_data_uni = config.initial_max_stream_data_uni,
            .initial_max_streams_bidi = config.initial_max_streams_bidi,
            .initial_max_streams_uni = config.initial_max_streams_uni,
            .max_datagram_frame_size = config.max_datagram_frame_size,
        };
        conn.local_params = local_params;

        // Initialize TLS 1.3 handshake if config provided
        if (tls_config) |tc| {
            conn.tls13_hs = if (is_server)
                tls13.Tls13Handshake.initServer(tc, local_params)
            else
                tls13.Tls13Handshake.initClient(tc, local_params);
        }

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

    /// Process a received packet.
    pub fn recv(self: *Connection, header: *packet.Header, fbs: anytype, info: RecvInfo) !void {
        _ = info;

        const epoch = try packet.Epoch.fromPacketType(header.packet_type);
        std.log.info("recv: packet_type={s}, epoch={s}", .{ @tagName(header.packet_type), @tagName(epoch) });

        if (epoch == packet.Epoch.zero_rtt) {
            std.log.info("TODO: implement zero rtt", .{});
            return error.NotImplemented;
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
            payload = packet.decryptWithKeyUpdate(header, fbs, &space, &self.key_update.?) catch |err| {
                std.log.err("can't decrypt 1-RTT packet with key update. {any}", .{err});
                return error.InvalidPacket;
            };
        } else {
            payload = packet.decrypt(header, fbs, space) catch |err| {
                std.log.err("can't decrypt packet. {any}", .{err});
                return error.InvalidPacket;
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
                if (header.key_phase != ku.key_phase) {
                    // Peer initiated a key update
                    const pto_ns = self.pkt_handler.rtt_stats.pto();
                    ku.rollKeys(now, pto_ns);
                    self.packer.key_phase = ku.key_phase;
                    std.log.info("key update: peer-initiated, new key_phase={}", .{ku.key_phase});
                }
                ku.maybeDropPrevKeys(now);
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

            std.log.info("recv: parsed frame type={s}", .{@tagName(frame)});

            if (frame.isAckEliciting()) {
                ack_eliciting = true;
            }

            try self.processFrame(frame, epoch, now);

            // Advance past this frame. For frames that contain data slices,
            // figure out where they end in the buffer.
            const consumed = self.frameSize(frame, remaining);
            if (consumed == 0) break; // safety: avoid infinite loop
            remaining = remaining[consumed..];
        }

        // Record receipt for ACK generation
        try self.pkt_handler.onPacketReceived(enc_level, header.packet_number, ack_eliciting, now);

        // Update expected packet number for correct decoding of subsequent packets
        // (critical for coalesced packets where multiple packets share a datagram)
        if (header.packet_number + 1 > self.pkt_num_spaces[space_idx].next_packet_number) {
            self.pkt_num_spaces[space_idx].next_packet_number = header.packet_number + 1;
        }

        // Update connection state
        if (self.state == .first_flight and epoch == .initial) {
            self.state = .handshake;
        }

        // After processing crypto frames, try advancing the handshake
        try self.advanceHandshake();
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

                // Notify congestion controller and track key update ACKs
                for (result.acked.constSlice()) |pkt| {
                    self.cc.onPacketAcked(pkt.size, pkt.pn);

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

                if (result.lost.len > 0) {
                    if (self.pkt_handler.sent[@intFromEnum(enc_level)].largest_sent) |ls| {
                        self.cc.onCongestionEvent(ls);
                    }
                }

                // Update pacer
                self.pacer.setBandwidth(self.cc.sendWindow(), &self.pkt_handler.rtt_stats);
            },

            .ack_ecn => |ack| {
                // Process same as ACK but with ECN
                _ = ack;
            },

            .reset_stream => |rs| {
                if (self.streams.getStream(rs.stream_id)) |s| {
                    s.recv.handleResetStream(rs.error_code, rs.final_size);
                }
            },

            .stop_sending => |ss| {
                if (self.streams.getStream(ss.stream_id)) |s| {
                    s.send.reset(ss.error_code);
                }
            },

            .crypto => |crypto_frame| {
                const level: u8 = @intFromEnum(epoch);
                std.log.info("processFrame: CRYPTO frame level={} offset={d} data_len={d}", .{ level, crypto_frame.offset, crypto_frame.data.len });
                try self.crypto_streams.handleCryptoFrame(level, crypto_frame.offset, crypto_frame.data);
                // Handshake advancement happens after all frames are processed
            },

            .new_token => {},

            .stream => |s| {
                // Get or create the stream
                const strm = self.streams.getOrCreateStream(s.stream_id) catch |err| {
                    std.log.err("Failed to get/create stream {}: {}", .{ s.stream_id, err });
                    return;
                };

                // Deliver data to the receive stream
                try strm.recv.handleStreamFrame(s.offset, s.data, s.fin);

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
            .streams_blocked_bidi => {},
            .streams_blocked_uni => {},

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
                self.local_err = .{
                    .is_app = false,
                    .code = cc.error_code,
                    .reason = cc.reason,
                };
            },

            .application_close => |ac| {
                self.state = .draining;
                self.local_err = .{
                    .is_app = true,
                    .code = ac.error_code,
                    .reason = ac.reason,
                };
            },

            .handshake_done => {
                self.handshake_confirmed = true;
                self.state = .connected;

                // Drop Initial and Handshake packet number spaces
                self.pkt_handler.dropSpace(.initial);
                self.pkt_handler.dropSpace(.handshake);
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
            else => return buf.len, // unknown - consume rest
        }
    }

    /// Advance the TLS 1.3 handshake by reading contiguous crypto data.
    fn advanceHandshake(self: *Connection) !void {
        if (self.handshake_confirmed) return;
        var hs = &(self.tls13_hs orelse return);

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
                        .handshake => self.installHandshakeKeys(ik.open, ik.seal),
                        .application => self.installAppKeys(ik.open, ik.seal),
                        else => {},
                    }
                },
                .wait_for_data => break,
                .complete => {
                    self.state = .connected;
                    self.handshake_confirmed = true;
                    self.paths[self.active_path_idx].is_validated = true;
                    self.pkt_handler.dropSpace(.initial);
                    self.pkt_handler.dropSpace(.handshake);

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

                        self.key_update = quic_crypto.KeyUpdateManager.init(
                            recv_secret,
                            send_secret,
                            app_open.hp_key,
                            app_seal.hp_key,
                        );
                        std.log.info("KeyUpdateManager initialized for 1-RTT key rotation", .{});
                    }

                    // Store peer transport parameters and apply stream limits
                    if (hs.peer_transport_params) |peer_tp| {
                        self.peer_params = peer_tp;
                        self.streams.setMaxStreams(
                            peer_tp.initial_max_streams_bidi,
                            peer_tp.initial_max_streams_uni,
                        );
                        self.conn_flow_ctrl.base.send_window = peer_tp.initial_max_data;
                        std.log.info("applied peer transport params: max_bidi={d}, max_uni={d}, max_data={d}", .{
                            peer_tp.initial_max_streams_bidi,
                            peer_tp.initial_max_streams_uni,
                            peer_tp.initial_max_data,
                        });
                    }
                    break;
                },
                ._continue => continue,
            }
        }
    }

    /// Install handshake-level encryption keys.
    /// Called when the TLS handshake produces Handshake-level secrets.
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

    /// Check if connection-level flow control needs a MAX_DATA update.
    fn queueFlowControlUpdates(self: *Connection) void {
        if (self.conn_flow_ctrl.getWindowUpdate(&self.pkt_handler.rtt_stats)) |new_max| {
            self.pending_frames.push(.{ .max_data = new_max });
        }
    }

    /// Build and send outgoing packets.
    pub fn send(self: *Connection, out_buf: []u8) !usize {
        // Draining: do not send anything
        if (self.state == .draining) return 0;

        const now: i64 = @intCast(std.time.nanoTimestamp());

        // Closing: send one packet with CONNECTION_CLOSE, then transition to draining
        if (self.state == .closing) {
            const app_seal: ?quic_crypto.Seal = if (self.key_update) |*ku|
                ku.current_seal
            else
                self.pkt_num_spaces[2].crypto_seal;
            if (app_seal != null) {
                const bytes_written = try self.packer.packCoalesced(
                    out_buf,
                    &self.pkt_handler,
                    &self.crypto_streams,
                    &self.streams,
                    &self.pending_frames,
                    null,
                    null,
                    app_seal,
                    now,
                );
                self.state = .draining;
                return bytes_written;
            }
            self.state = .draining;
            return 0;
        }

        // Check if pacer allows sending
        const pacer_delay = self.pacer.timeUntilSend(now);
        if (pacer_delay > 0) return 0;

        // Check congestion window
        if (self.pkt_handler.bytes_in_flight >= self.cc.sendWindow()) {
            // Congestion limited - only send ACKs
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

        // Build coalesced packet with available encryption levels
        // Packet number space indices: 0=Initial, 1=Handshake, 2=Application
        const initial_seal = self.pkt_num_spaces[0].crypto_seal;
        const handshake_seal = self.pkt_num_spaces[1].crypto_seal;
        // Use KeyUpdateManager seal for 1-RTT if available
        const app_seal: ?quic_crypto.Seal = if (self.key_update) |*ku|
            ku.current_seal
        else
            self.pkt_num_spaces[2].crypto_seal;

        const has_initial = initial_seal != null;
        const has_handshake = handshake_seal != null;
        const has_app = app_seal != null;
        std.log.debug("send: packing coalesced packet, has_initial={} has_handshake={} has_app={}", .{ has_initial, has_handshake, has_app });

        const bytes_written = try self.packer.packCoalesced(
            out_buf,
            &self.pkt_handler,
            &self.crypto_streams,
            &self.streams,
            &self.pending_frames,
            initial_seal,
            handshake_seal,
            app_seal,
            now,
        );

        if (bytes_written > 0) {
            self.paths[self.active_path_idx].bytes_sent += bytes_written;
            self.pacer.onPacketSent(bytes_written, now);

            // Track packets sent with current keys for key update
            if (self.key_update) |*ku| {
                if (app_seal != null) {
                    const app_idx = @intFromEnum(ack_handler.EncLevel.application);
                    const pn = self.pkt_handler.next_pn[app_idx];
                    if (pn > 0) ku.onPacketSent(pn - 1);
                }
            }
        }

        return bytes_written;
    }

    /// Send ACK-only packets (when congestion limited).
    fn sendAckOnly(self: *Connection, out_buf: []u8, now: i64) !usize {
        _ = self;
        _ = out_buf;
        _ = now;
        // TODO: pack ACK-only packets
        return 0;
    }

    /// Check for timeouts and maintenance tasks.
    pub fn onTimeout(self: *Connection) !void {
        const now: i64 = @intCast(std.time.nanoTimestamp());

        // Check idle timeout
        if (now - self.last_packet_received_time > self.idle_timeout_ns) {
            self.state = .terminated;
            return;
        }

        // Check PTO
        if (self.pkt_handler.getPtoTimeout()) |pto_time| {
            if (now >= pto_time) {
                self.pkt_handler.pto_count += 1;
                self.pending_frames.push(.{ .ping = {} });
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

    /// Close the connection gracefully.
    pub fn close(self: *Connection, error_code: u64, reason: []const u8) void {
        self.state = .closing;
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

    /// Open a new bidirectional stream.
    pub fn openStream(self: *Connection) !*stream_mod.Stream {
        return self.streams.openBidiStream();
    }

    /// Open a new unidirectional stream.
    pub fn openUniStream(self: *Connection) !*stream_mod.SendStream {
        return self.streams.openUniStream();
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
) !Connection {
    const now: i64 = @intCast(std.time.nanoTimestamp());
    var scid: [8]u8 = undefined;
    var dcid: [8]u8 = undefined;
    generateConnectionId(&scid);
    generateConnectionId(&dcid);

    const local_params: transport_params.TransportParams = .{
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
    var conn = try connect(std.testing.allocator, "example.com", .{}, null);
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
