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

    // Network paths
    paths: [1]NetworkPath = .{undefined},

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

    // Connection state
    got_peer_conn_id: bool = false,
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

        const local_params: transport_params.TransportParams = .{
            .original_destination_connection_id = if (is_server) header.dcid else null,
            .initial_source_connection_id = header.scid,
            .max_idle_timeout = config.max_idle_timeout,
            .initial_max_data = config.initial_max_data,
            .initial_max_stream_data_bidi_local = config.initial_max_stream_data_bidi_local,
            .initial_max_stream_data_bidi_remote = config.initial_max_stream_data_bidi_remote,
            .initial_max_stream_data_uni = config.initial_max_stream_data_uni,
            .initial_max_streams_bidi = config.initial_max_streams_bidi,
            .initial_max_streams_uni = config.initial_max_streams_uni,
            .max_datagram_frame_size = config.max_datagram_frame_size,
        };

        var conn = Connection{
            .allocator = allocator,
            .version = header.version,
            .is_server = is_server,
            .paths = .{initial_path},
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

            .local_params = local_params,
        };

        // Initialize TLS 1.3 handshake if config provided
        if (tls_config) |tc| {
            conn.tls13_hs = if (is_server)
                tls13.Tls13Handshake.initServer(tc, local_params)
            else
                tls13.Tls13Handshake.initClient(tc, local_params);
        }

        // Copy connection IDs
        conn.dcid_len = @intCast(header.dcid.len);
        @memcpy(conn.dcid[0..header.dcid.len], header.dcid);
        conn.scid_len = @intCast(header.scid.len);
        @memcpy(conn.scid[0..header.scid.len], header.scid);

        // Set up initial crypto keys
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
        if (epoch == packet.Epoch.zero_rtt) {
            std.log.info("TODO: implement zero rtt", .{});
            return error.NotImplemented;
        }

        const space = self.pkt_num_spaces[@intFromEnum(epochToEncLevel(epoch))];
        const payload = packet.decrypt(header, fbs, space) catch |err| {
            std.log.err("can't decrypt packet. {any}", .{err});
            return error.InvalidPacket;
        };

        if (payload.len == 0) {
            return error.InvalidPacket;
        }

        const now: i64 = @intCast(std.time.nanoTimestamp());
        self.last_packet_received_time = now;

        // Update network path stats
        self.paths[0].bytes_received += @intCast(fbs.buffer.len);

        // Check for duplicate
        const enc_level = epochToEncLevel(epoch);
        if (self.pkt_handler.recv[@intFromEnum(enc_level)].isDuplicate(header.packet_number)) {
            return; // Duplicate, ignore
        }

        // Determine path - set peer connection ID on first packet
        if (self.is_server and !self.got_peer_conn_id) {
            self.setInitialDCID(header.scid);
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
                    ack.ranges,
                    ack.first_ack_range,
                    now,
                );

                // Notify congestion controller
                for (result.acked.constSlice()) |pkt| {
                    self.cc.onPacketAcked(pkt.size, pkt.pn);
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
            },

            .max_data => |max| {
                self.conn_flow_ctrl.updateSendWindow(max);
            },

            .max_stream_data => |msd| {
                if (self.streams.getStream(msd.stream_id)) |s| {
                    // Update stream-level send window
                    _ = s; // TODO: integrate with stream flow controller
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
                _ = ncid;
                // TODO: manage connection ID rotation
            },

            .retire_connection_id => |rcid| {
                _ = rcid;
                // TODO: retire old connection IDs
            },

            .path_challenge => |data| {
                // Queue PATH_RESPONSE with the same data
                _ = data;
                // TODO: queue path response frame
            },

            .path_response => {},

            .connection_close => |cc| {
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
        var hs = &(self.tls13_hs orelse return);

        // Feed crypto stream data to the handshake
        inline for ([_]u8{ 0, 2, 3 }) |level| {
            const cs = self.crypto_streams.getStream(level);
            while (cs.read()) |data| {
                defer self.allocator.free(data);
                hs.provideData(data);
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

            switch (action) {
                .send_data => |sd| {
                    // Write the TLS handshake data to the appropriate crypto stream
                    const cs_level: u8 = @intFromEnum(sd.level);
                    const cs = self.crypto_streams.getStream(cs_level);
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
                    self.paths[0].is_validated = true;
                    self.pkt_handler.dropSpace(.initial);
                    self.pkt_handler.dropSpace(.handshake);

                    // Store peer transport parameters if available
                    if (hs.peer_transport_params) |peer_tp| {
                        self.peer_params = peer_tp;
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
    }

    /// Install 1-RTT (Application) encryption keys.
    /// Called when the TLS handshake produces application-level secrets.
    pub fn installAppKeys(self: *Connection, open: quic_crypto.Open, seal: quic_crypto.Seal) void {
        // Packet number space index 2 = Application (1-RTT)
        self.pkt_num_spaces[2].crypto_open = open;
        self.pkt_num_spaces[2].crypto_seal = seal;
    }

    /// Build and send outgoing packets.
    pub fn send(self: *Connection, out_buf: []u8) !usize {
        const now: i64 = @intCast(std.time.nanoTimestamp());

        // Check if pacer allows sending
        const pacer_delay = self.pacer.timeUntilSend(now);
        if (pacer_delay > 0) return 0;

        // Check congestion window
        if (self.pkt_handler.bytes_in_flight >= self.cc.sendWindow()) {
            // Congestion limited - only send ACKs
            return try self.sendAckOnly(out_buf, now);
        }

        // Build coalesced packet with available encryption levels
        // Packet number space indices: 0=Initial, 1=Handshake, 2=Application
        const initial_seal = self.pkt_num_spaces[0].crypto_seal;
        const handshake_seal = self.pkt_num_spaces[1].crypto_seal;
        const app_seal = self.pkt_num_spaces[2].crypto_seal;

        const bytes_written = try self.packer.packCoalesced(
            out_buf,
            &self.pkt_handler,
            &self.crypto_streams,
            &self.streams,
            initial_seal,
            handshake_seal,
            app_seal,
            now,
        );

        if (bytes_written > 0) {
            self.paths[0].bytes_sent += bytes_written;
            self.pacer.onPacketSent(bytes_written, now);
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
                // TODO: send PTO probe packets
            }
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
