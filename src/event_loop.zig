const std = @import("std");
const posix = std.posix;
const builtin = @import("builtin");
const log = std.log.scoped(.event_loop);
const sys = @import("sys.zig");
const net = @import("sockaddr.zig");
const io_compat = @import("io_compat.zig");

const xev_backend = @import("xev_backend.zig");
const xev = xev_backend.xev;
const halted_poll_action = xev_backend.halted_poll_action;
const forgetPollResult = xev_backend.forgetPollResult;
const cancelCompletion = xev_backend.cancelCompletion;

/// The libxev backend this build selected. A caller sharing one loop across
/// several clients has to create it from here: on Linux this is `Epoll`, not
/// what a bare `@import("xev")` gives you, and the two are different types.
pub const Xev = xev;

const connection = @import("quic/connection.zig");
const connection_manager = @import("quic/connection_manager.zig");
pub const ConnEntry = connection_manager.ConnEntry;
const stream_mod = @import("quic/stream.zig");
const tls13 = @import("quic/tls13.zig");
const ecn_socket = @import("quic/ecn_socket.zig");
const h3 = @import("h3/connection.zig");
const h0 = @import("h0/connection.zig");
const http1 = @import("http1/server.zig");
const qpack = @import("h3/qpack.zig");
const h3_frame = @import("h3/frame.zig");
const wt = @import("webtransport/session.zig");
const wt_fc = @import("webtransport/flow_control.zig");
const transport_params = @import("quic/transport_params.zig");
const packet = @import("quic/packet.zig");
const quic_lb = @import("quic/quic_lb.zig");
const Certificate = std.crypto.Certificate;
const ca_bundle = @import("quic/ca_bundle.zig");

pub const Protocol = enum { quic, h3, h0, webtransport };

/// HTTP/3 error codes, for `Session.resetRequest` and `onRequestCancelled`.
pub const H3Error = h3.H3Error;

pub const Http1Config = http1.Config;
pub const Http1WebSocketConfig = http1.WebSocketConfig;

/// A WebSocket upgrade request, handed to `onWsUpgrade`; see `http1.WsRequest`.
pub const WsRequest = http1.WsRequest;
/// An open WebSocket; see `http1.WsConn`.
pub const WsConn = http1.WsConn;
pub const WsAcceptOptions = http1.WsAcceptOptions;
pub const WsSendError = http1.WsSendError;
pub const WsMessageKind = http1.WsMessageKind;
pub const WsCloseCode = http1.WsCloseCode;

/// The largest datagram we can receive whole. It has to be whatever we tell
/// peers they may send — a longer one is truncated by recvmsg and then fails
/// AEAD authentication, which reads as a decryption bug rather than a short
/// read. Safari fills the 16 KB loopback MTU and found that the hard way.
const MAX_RECV_DATAGRAM: usize = (transport_params.TransportParams{}).max_udp_payload_size;

pub const Config = struct {
    address: []const u8 = "127.0.0.1",
    port: u16 = 4433,
    cert_path: []const u8 = "interop/certs/server.crt",
    key_path: []const u8 = "interop/certs/server.key",
    max_datagram_frame_size: u64 = 65536,
    webtransport_max_sessions: u64 = 4,
    /// draft-ietf-webtrans-http3-13 §5.3-§5.6 session flow control: the window
    /// each session grants its peer, handed over as a WT_MAX_STREAMS /
    /// WT_MAX_DATA capsule when the session opens and raised as the peer
    /// spends it.
    ///
    /// A zero grants nothing, which stops a draft-13 peer opening any stream at
    /// all. Peers that never sent the draft-13 WT_MAX_SESSIONS get no capsules
    /// and no limits either way; see `webtransport.flowControlEnabled`.
    wt_credits: wt_fc.Credits = wt_fc.Credits.default,

    /// Also announce those windows in SETTINGS, as §5.5 allows, so a peer may
    /// open a stream in the same flight as its CONNECT rather than waiting for
    /// the capsule.
    ///
    /// Off, because it costs a live browser: Safari 26.4 rejects the session
    /// outright — every scenario, `connect-echo` included — when
    /// SETTINGS_WT_INITIAL_MAX_DATA / _STREAMS_BIDI / _UNI (0x2b61, 0x2b65,
    /// 0x2b64) are present, and goes back to passing when they are not.
    /// Measured both ways; `WT_SETTINGS_CREDITS=1` on `wpt-server` reproduces it.
    /// Nothing is lost meanwhile: the per-session capsule carries the same
    /// credit to every peer that implements §5.6.
    wt_advertise_credits: bool = false,

    /// Also advertise the pre-draft-13 WebTransport settings
    /// (ENABLE_WEBTRANSPORT, WT_ENABLED, the old WT_MAX_SESSIONS codepoint).
    /// Chrome and Firefox read those; Safari 26.4 reads only the draft-13 ones,
    /// which are always sent.
    wt_legacy_settings: bool = true,

    /// Answer every new client with Retry (RFC 9000 8.1.2): it must echo
    /// the token from its own address before the server keeps any state.
    /// Costs every client a round trip; see `retry_threshold`.
    require_retry: bool = false,

    /// Retry new clients only once this many connections are live, so a
    /// loaded server gives state only to clients that proved their address
    /// and an idle one costs nothing extra. Below it, clients still echoing
    /// a Retry are served as such. `Server.setRequireRetry` covers load
    /// signals of the embedder's own.
    ///
    /// Servers behind one port (`reuse_port`) should share `retry_token_key`,
    /// or a token is only good at the server that issued it.
    retry_threshold: ?usize = null,

    // Advanced: provide pre-built TLS and connection configs directly.
    // When tls_config is set, cert_path/key_path are ignored.
    tls_config: ?tls13.TlsConfig = null,
    conn_config: ?connection.ConnectionConfig = null,
    retry_token_key: ?[16]u8 = null,
    static_reset_key: ?[16]u8 = null,

    // Use IPv6 dual-stack socket (supports both IPv4 and IPv6)
    ipv6: bool = false,

    /// A bound, non-blocking UDP socket to serve on instead of opening one.
    /// The server owns it once `init` succeeds; on failure it is left open
    /// for the caller. `address`, `port`, `ipv6`, `reuse_port` and the
    /// buffer sizes are not applied to it. Lets a replacement server take
    /// over a socket it could not bind itself: after dropping privileges,
    /// say, or while an SO_REUSEPORT group is held by another user.
    socket: ?posix.socket_t = null,

    // Optional second port for preferred_address (connectionmigration).
    // When set, a second socket is created on this port so that clients
    // migrating to the server's preferred address can reach us.
    preferred_port: ?u16 = null,

    /// An HTTP/1.1 listener on TCP beside QUIC on UDP, on the same port by
    /// default (TCP and UDP are separate namespaces) and the same loop:
    /// static files from `static_dir`, WebSockets through the handler's
    /// `onWsUpgrade` / `onWsMessage` / `onWsClose`, TLS with the QUIC
    /// certificates, and Alt-Svc advertising HTTP/3. Required when the
    /// handler declares `onWsUpgrade`.
    http1: ?Http1Config = null,

    /// ALPN protocols offered in the handshake when the server loads its
    /// certificate from `cert_path`/`key_path`. Null means `{"h3"}`. The
    /// strings are borrowed and must outlive the server. Ignored when
    /// `tls_config` is set: its own `alpn` applies.
    alpn: ?[]const []const u8 = null,

    /// Live connections past which new ones are refused with
    /// CONNECTION_REFUSED.
    max_connections: usize = connection_manager.ConnectionManager.DEFAULT_MAX_CONNECTIONS,

    /// Server-wide cap, per second, on each kind of reply sent without
    /// connection state: Version Negotiation, stateless reset and
    /// CONNECTION_REFUSED, budgeted separately. Each is triggerable with a
    /// spoofed source address. Zero sends none.
    stateless_reply_rate: u32 = 200,

    /// SO_REUSEPORT on the UDP socket(s), so several servers — one per worker
    /// thread, each on its own loop — can bind the same port and let the
    /// kernel spread peers across them.
    ///
    /// The kernel balances by 4-tuple (Linux) and knows nothing of QUIC, so a
    /// peer that migrates can land on a worker that does not have its
    /// connection; it gets a stateless reset unless `quic_lb` and
    /// `foreign_datagram` steer it back to the owner.
    reuse_port: bool = false,

    /// QUIC-LB CID encoding (draft-ietf-quic-load-balancers): every CID this
    /// server issues — the handshake SCID and each NEW_CONNECTION_ID —
    /// carries `server_id`. Applied on top of `conn_config` when both are set.
    /// Servers that steer to each other share everything but `server_id`.
    quic_lb: ?quic_lb.Config = null,

    /// Called for a Handshake or 1-RTT datagram whose DCID is not ours but
    /// decodes, under `quic_lb`, to another server id: a peer of a sibling
    /// server that migrated onto this socket. Without it such a datagram
    /// gets a stateless reset. Requires `quic_lb`.
    ///
    /// Runs on this server's loop thread, during its receive pass. The hook
    /// copies the bytes (they are only valid for the call), moves them to the
    /// owner's thread — a queue plus an `xev.Async`, say — and there calls
    /// the owner's `injectDatagram`. Initials are never reported: whichever
    /// server receives one accepts the connection.
    foreign_datagram: ?ForeignDatagramHook = null,

    /// SO_RCVBUF / SO_SNDBUF for the UDP socket(s). Null keeps the OS default,
    /// which is small for a busy server (~200 KB on Linux); several MB avoids
    /// drops under bursts. The kernel may clamp it (`net.core.rmem_max`).
    recv_buffer_size: ?u32 = null,
    send_buffer_size: ?u32 = null,

    /// An event loop to join rather than create, so the server can share one
    /// thread with other I/O — TCP listeners, upstream connections, clients.
    /// The caller owns the loop and runs it; `run()` is only for a server
    /// that owns its loop, and `stop()` never stops a loop it joined.
    ///
    /// The loop outlives the server, so the server's completions have to be
    /// off it before `deinit()`: call `stop()`, then keep running the loop
    /// until `isStopped()`.
    loop: ?*xev.Loop = null,
};

/// A datagram a server received for a connection another server owns; see
/// `Config.foreign_datagram`.
pub const ForeignDatagram = struct {
    /// The whole UDP payload, valid only for the duration of the hook.
    bytes: []const u8,
    peer: posix.sockaddr.storage,
    /// The receiving socket's address. Under SO_REUSEPORT it is the owner's
    /// too, so hand it to `injectDatagram` unchanged.
    local: posix.sockaddr.storage,
    ecn: u2,
    /// The QUIC-LB server id the DCID decodes to, `quic_lb.server_id_len`
    /// bytes. Nothing checks that such a server exists: the hook drops
    /// what it cannot route.
    server_id: []const u8,
};

pub const ForeignDatagramHook = struct {
    ctx: ?*anyopaque = null,
    func: *const fn (ctx: ?*anyopaque, datagram: *const ForeignDatagram) void,
};

/// Session wraps a ConnEntry and provides convenience methods for sending data.
///
/// The entry pointer is stable from the first callback that hands it out
/// until `onConnectionClosed`, so a handler may keep it — or a copy of the
/// Session — across loop iterations and write from other callbacks on the same
/// loop. After `onConnectionClosed` the entry is freed.
///
/// Writes made from outside a Server callback (a TCP read callback on a shared
/// loop, say) are sent on the next loop iteration without any further call;
/// `Server.flush()` sends them immediately. Sessions are not thread-safe: use
/// them only from the thread running the server's loop.
pub const Session = struct {
    entry: *ConnEntry,

    /// This connection's id: unique within the server, never reused.
    pub fn id(self: *const Session) u64 {
        return self.entry.id;
    }

    /// The client's verified certificate (DER leaf), when the certificate
    /// entry SNI selected has `client_auth` and the client sent one.
    pub fn peerCertificate(self: *const Session) ?[]const u8 {
        return self.entry.conn.peerCertificate();
    }

    /// The client-auth policy this connection's handshake ran under.
    pub fn clientAuth(self: *const Session) ?*const tls13.ClientAuth {
        return self.entry.conn.clientAuth();
    }

    // --- H3 methods (also for ordinary requests on a WebTransport server) ---

    /// A whole response: headers, `body` as one DATA frame, FIN.
    pub fn sendResponse(self: *Session, stream_id: u64, headers: []const qpack.Header, body: []const u8) !void {
        const h3c = self.entry.h3_conn orelse return error.NoH3Connection;
        defer self.entry.wake();
        try h3c.sendResponse(stream_id, headers, body);
    }

    /// Response headers without ending the stream: a 1xx, or the final
    /// response's headers ahead of a streamed body. Fails with
    /// `error.ResponseHeadersAlreadySent` after the final headers; trailers
    /// go through `finishResponse`.
    pub fn sendResponseHeaders(self: *Session, stream_id: u64, headers: []const qpack.Header) !void {
        const h3c = self.entry.h3_conn orelse return error.NoH3Connection;
        defer self.entry.wake();
        try h3c.sendResponseHeaders(stream_id, headers);
    }

    /// One DATA frame of response body. Empty data writes nothing. Buffered
    /// in full regardless of flow control; pace with `notifyWritable`.
    /// Fails with `error.ResponseHeadersNotSent` before the final headers.
    pub fn sendResponseData(self: *Session, stream_id: u64, data: []const u8) !void {
        const h3c = self.entry.h3_conn orelse return error.NoH3Connection;
        defer self.entry.wake();
        try h3c.sendResponseData(stream_id, data);
    }

    /// End the response with optional trailers, then FIN. Fails with
    /// `error.ResponseHeadersNotSent` before the final headers.
    pub fn finishResponse(self: *Session, stream_id: u64, trailers: ?[]const qpack.Header) !void {
        const h3c = self.entry.h3_conn orelse return error.NoH3Connection;
        defer self.entry.wake();
        try h3c.finishResponse(stream_id, trailers);
    }

    /// Abort a request stream in both directions (RESET_STREAM +
    /// STOP_SENDING) with an HTTP/3 error code, e.g.
    /// `@intFromEnum(H3Error.internal_error)` or `.request_cancelled`.
    pub fn resetRequest(self: *Session, stream_id: u64, error_code: u64) void {
        const h3c = self.entry.h3_conn orelse return;
        h3c.cancelRequest(stream_id, error_code);
        self.entry.wake();
    }

    /// Stop delivering `stream_id`'s request body: no more `onData` or
    /// `onRequestEnd` for it until `resumeRequestBody`. Unlike buffering in
    /// the handler, this pushes back on the client — the body stays unread
    /// in QUIC and MAX_STREAM_DATA is only extended as it is read, so at
    /// most one stream window (`ConnectionConfig.initial_max_stream_data_*`)
    /// is held per paused request. For a proxy whose upstream is slower
    /// than its client. Safe to call from inside `onData`.
    pub fn pauseRequestBody(self: *Session, stream_id: u64) !void {
        const h3c = self.entry.h3_conn orelse return error.NoH3Connection;
        try h3c.pauseBody(stream_id);
    }

    /// Resume a body paused with `pauseRequestBody`. What arrived meanwhile
    /// is delivered on a later loop pass, then `onRequestEnd` if the client
    /// has finished; no packet needs to arrive for that.
    pub fn resumeRequestBody(self: *Session, stream_id: u64) void {
        const h3c = self.entry.h3_conn orelse return;
        h3c.resumeBody(stream_id);
        self.entry.repoll();
    }

    /// Bytes written to the stream and not yet sent — held back by flow or
    /// congestion control. Null for a stream we cannot send on.
    pub fn streamBufferedBytes(self: *const Session, stream_id: u64) ?u64 {
        return self.entry.conn.streamBufferedBytes(stream_id);
    }

    // --- WebTransport methods ---

    /// Stop `onStreamData` for a WebTransport stream until `resumeStream`,
    /// so a relay can hold a fast sender to the pace of a slow receiver. The
    /// data stays unread in QUIC and the peer is held back by the stream's
    /// flow-control window. Resets are still reported through
    /// `onStreamReset`.
    pub fn pauseStream(self: *Session, stream_id: u64) !void {
        const wtc = self.entry.wt_conn orelse return error.NoWebTransportConnection;
        try wtc.pauseStream(stream_id);
    }

    /// Resume a stream paused with `pauseStream`. What arrived meanwhile,
    /// FIN included, is delivered on a later loop pass without waiting for
    /// a packet. Callable from outside a server callback.
    pub fn resumeStream(self: *Session, stream_id: u64) void {
        const wtc = self.entry.wt_conn orelse return;
        wtc.resumeStream(stream_id);
        self.entry.repoll();
    }

    pub fn sendStreamData(self: *Session, stream_id: u64, data: []const u8) !void {
        defer self.entry.wake();
        if (self.entry.wt_conn) |wtc| {
            try wtc.sendStreamData(stream_id, data);
        }
    }

    /// `session_id` names the WebTransport session; on raw QUIC there is
    /// none and it is ignored.
    pub fn sendDatagram(self: *Session, session_id: u64, data: []const u8) !void {
        defer self.entry.wake();
        if (self.entry.wt_conn) |wtc| {
            return wtc.sendDatagram(session_id, data);
        }
        return self.entry.conn.sendDatagram(data);
    }

    pub fn acceptSession(self: *Session, session_id: u64) !void {
        defer self.entry.wake();
        if (self.entry.wt_conn) |wtc| {
            try wtc.acceptSession(session_id);
        }
    }

    pub fn closeStream(self: *Session, stream_id: u64) void {
        defer self.entry.wake();
        if (self.entry.wt_conn) |wtc| {
            wtc.closeStream(stream_id);
        }
    }

    pub fn openBidiStream(self: *Session, session_id: u64, send_order: ?i64) !u64 {
        if (self.entry.wt_conn) |wtc| {
            return try wtc.openBidiStream(session_id, send_order);
        }
        return error.NoWtConnection;
    }

    pub fn openUniStream(self: *Session, session_id: u64, send_order: ?i64) !u64 {
        if (self.entry.wt_conn) |wtc| {
            return try wtc.openUniStream(session_id, send_order);
        }
        return error.NoWtConnection;
    }

    pub fn setSendOrder(self: *Session, stream_id: u64, send_order: ?i64) void {
        defer self.entry.wake();
        if (self.entry.wt_conn) |wtc| {
            wtc.setSendOrder(stream_id, send_order);
        }
    }

    pub fn closeSession(self: *Session, session_id: u64) void {
        defer self.entry.wake();
        if (self.entry.wt_conn) |wtc| {
            wtc.closeSession(session_id);
        }
    }

    pub fn closeSessionWithError(self: *Session, session_id: u64, error_code: u32, reason: []const u8) !void {
        defer self.entry.wake();
        if (self.entry.wt_conn) |wtc| {
            try wtc.closeSessionWithError(session_id, error_code, reason);
        }
    }

    /// Signal graceful shutdown without closing: the peer stops opening new
    /// streams but finishes what is in flight. This is what resolves a
    /// browser's `WebTransport.draining`.
    pub fn drainSession(self: *Session, session_id: u64) !void {
        defer self.entry.wake();
        if (self.entry.wt_conn) |wtc| {
            try wtc.drainSession(session_id);
        }
    }

    pub fn resetStream(self: *Session, stream_id: u64, error_code: u32) void {
        defer self.entry.wake();
        if (self.entry.wt_conn) |wtc| {
            wtc.resetStream(stream_id, error_code);
        }
    }

    pub fn stopSending(self: *Session, stream_id: u64, error_code: u32) void {
        defer self.entry.wake();
        if (self.entry.wt_conn) |wtc| {
            wtc.stopSending(stream_id, error_code);
        }
    }

    pub fn acceptSessionWithHeaders(self: *Session, session_id: u64, extra_headers: []const qpack.Header) !void {
        defer self.entry.wake();
        if (self.entry.wt_conn) |wtc| {
            try wtc.acceptSessionWithHeaders(session_id, extra_headers);
        }
    }

    /// What the peer advertised in its HTTP/3 SETTINGS, once they have
    /// arrived. Worth logging when a peer's WebTransport behaviour is in
    /// question: which draft's codepoints it speaks is in here.
    pub fn peerSettings(self: *const Session) ?h3_frame.Settings {
        const h3c = self.entry.h3_conn orelse return null;
        if (!h3c.peer_settings_received) return null;
        return h3c.peer_settings;
    }

    pub fn getStats(self: *const Session) connection.Connection.Stats {
        return self.entry.conn.getStats();
    }

    pub fn getSendStreamStats(self: *const Session, stream_id: u64) ?wt.SendStreamStats {
        if (self.entry.wt_conn) |wtc| return wtc.getSendStreamStats(stream_id);
        return null;
    }

    pub fn getRecvStreamStats(self: *const Session, stream_id: u64) ?wt.RecvStreamStats {
        if (self.entry.wt_conn) |wtc| return wtc.getRecvStreamStats(stream_id);
        return null;
    }

    pub fn closeConnection(self: *Session) void {
        defer self.entry.wake();
        self.entry.conn.close(0, "");
    }

    pub fn setIncomingDatagramMaxAge(self: *Session, max_age_ms: ?u64) void {
        self.entry.conn.setIncomingDatagramMaxAge(max_age_ms);
    }

    pub fn setOutgoingDatagramMaxAge(self: *Session, max_age_ms: ?u64) void {
        self.entry.conn.setOutgoingDatagramMaxAge(max_age_ms);
    }

    pub fn setIncomingDatagramHighWaterMark(self: *Session, count: usize) void {
        self.entry.conn.setIncomingDatagramHighWaterMark(count);
    }

    pub fn setOutgoingDatagramHighWaterMark(self: *Session, count: usize) void {
        self.entry.conn.setOutgoingDatagramHighWaterMark(count);
    }

    pub fn isDatagramSendQueueFull(self: *const Session) bool {
        if (self.entry.wt_conn) |wtc| {
            return wtc.isDatagramSendQueueFull();
        }
        return true;
    }

    /// Bytes `session_id` can still write before the peer's credit is spent;
    /// see `WebTransportConnection.sendCapacity`. On raw QUIC, the connection's.
    pub fn sendCapacity(self: *const Session, session_id: u64) u64 {
        if (self.entry.wt_conn) |wtc| return wtc.sendCapacity(session_id);
        return self.entry.conn.sendCapacity();
    }

    pub fn streamSendCapacity(self: *const Session, stream_id: u64) ?u64 {
        if (self.entry.wt_conn) |wtc| return wtc.streamSendCapacity(stream_id);
        return self.entry.conn.streamSendCapacity(stream_id);
    }

    /// One `onWritable` once `min_bytes` fit.
    ///
    /// On a WebTransport stream or session, see
    /// `WebTransportConnection.notifyWritable`. On an HTTP/3 request stream
    /// (`.h3`, or an ordinary request on a WebTransport server) `stream_id` is
    /// required, `session_id` is ignored, and `onWritable` receives the
    /// stream id as both; see `H3Connection.notifyWritable` — it also waits
    /// for the stream's unsent backlog to fall below `min_bytes`.
    pub fn notifyWritable(self: *Session, session_id: u64, stream_id: ?u64, min_bytes: u64) !void {
        defer self.entry.repoll(); // an already-met wait fires on a poll pass
        if (stream_id) |sid| {
            if (self.isH3RequestStream(sid)) {
                return self.entry.h3_conn.?.notifyWritable(sid, min_bytes);
            }
        }
        const wtc = self.entry.wt_conn orelse return error.NoWtConnection;
        try wtc.notifyWritable(session_id, stream_id, min_bytes);
    }

    fn isH3RequestStream(self: *const Session, stream_id: u64) bool {
        const h3c = self.entry.h3_conn orelse return false;
        const wtc = self.entry.wt_conn orelse return true;
        if (!stream_mod.isBidi(stream_id)) return false;
        if (h3c.excluded_streams.contains(stream_id)) return false;
        return wtc.getSession(stream_id) == null;
    }

    pub fn maxDatagramPayloadSize(self: *const Session, session_id: u64) ?usize {
        if (self.entry.wt_conn) |wtc| {
            return wtc.maxDatagramPayloadSize(session_id);
        }
        return null;
    }

    // --- Raw QUIC methods ---

    pub fn writeStream(self: *Session, stream_id: u64, data: []const u8) !void {
        defer self.entry.wake();
        if (self.entry.conn.streams.getStream(stream_id)) |stream| {
            return stream.send.writeData(data);
        }
        if (self.entry.conn.streams.send_streams.get(stream_id)) |ss| {
            return ss.writeData(data);
        }
        return error.StreamNotFound;
    }

    pub fn closeQuicStream(self: *Session, stream_id: u64) void {
        defer self.entry.wake();
        if (self.entry.conn.streams.getStream(stream_id)) |stream| {
            stream.send.close();
        } else if (self.entry.conn.streams.send_streams.get(stream_id)) |ss| {
            ss.close();
        }
    }

    pub fn readStream(self: *Session, stream_id: u64) ?[]const u8 {
        const stream = self.entry.conn.streams.getStream(stream_id) orelse return null;
        return stream.recv.read();
    }

    pub fn openStream(self: *Session) !u64 {
        const stream = try self.entry.conn.openStream();
        return stream.stream_id;
    }

    pub fn openQuicUniStream(self: *Session) !u64 {
        const ss = try self.entry.conn.openUniStream();
        return ss.stream_id;
    }

    pub fn resetQuicStream(self: *Session, stream_id: u64, error_code: u64) void {
        defer self.entry.wake();
        if (self.entry.conn.streams.getStream(stream_id)) |stream| {
            stream.send.reset(error_code);
        } else if (self.entry.conn.streams.send_streams.get(stream_id)) |ss| {
            ss.reset(error_code);
        }
    }

    /// A QUIC DATAGRAM with no WebTransport session prefix.
    pub fn sendQuicDatagram(self: *Session, data: []const u8) !void {
        defer self.entry.wake();
        try self.entry.conn.sendDatagram(data);
    }

    /// True for a connection a `raw_quic` WebTransport server is serving as
    /// plain QUIC, because it negotiated something other than h3.
    pub fn isRawQuic(self: *const Session) bool {
        return self.entry.raw_quic;
    }

    pub fn alpn(self: *const Session) []const u8 {
        return self.entry.conn.negotiatedAlpn();
    }

    // --- H0 methods ---

    pub fn serveFile(self: *Session, stream_id: u64, root_dir: []const u8, path: []const u8) !void {
        defer self.entry.wake();
        if (self.entry.h0_conn) |h0c| {
            try h0c.serveFile(stream_id, root_dir, path);
        }
    }

    pub fn sendH0Response(self: *Session, stream_id: u64, data: []const u8) !void {
        defer self.entry.wake();
        if (self.entry.h0_conn) |h0c| {
            try h0c.sendResponse(stream_id, data);
        }
    }

    // --- Connection-level methods ---

    pub fn sendKeepAlive(self: *Session) void {
        defer self.entry.wake();
        self.entry.conn.sendKeepAlive();
    }
};

pub fn Server(comptime Handler: type) type {
    // A WebTransport handler may also take native-QUIC protocols on the same
    // port (MoQT's `moqt-NN` beside `h3`): each connection's ALPN picks.
    const serves_raw_quic = Handler.protocol == .webtransport and
        @hasDecl(Handler, "raw_quic") and Handler.raw_quic;
    comptime {
        if (!@hasDecl(Handler, "protocol")) {
            @compileError("Handler must declare 'pub const protocol: event_loop.Protocol'");
        }

        const known = [_][]const u8{
            "onConnectRequest",   "onSessionReady",     "onStreamData",
            "onDatagram",         "onSessionClosed",    "onSessionDraining",
            "onBidiStream",       "onUniStream",        "onStreamReset",
            "onStopSending",      "onPollComplete",     "onRequest",
            "onData",             "onH0Request",        "onH0Data",
            "onH0Finished",       "onWritable",         "onRequestEnd",
            "onRequestCancelled", "onConnectionClosed", "onQuicConnected",
            "onWsUpgrade",        "onWsMessage",        "onWsClose",
        };

        for (@typeInfo(Handler).@"struct".decls) |decl| {
            if (decl.name.len >= 2 and decl.name[0] == 'o' and decl.name[1] == 'n') {
                var found = false;
                for (known) |k| {
                    if (std.mem.eql(u8, decl.name, k)) {
                        found = true;
                        break;
                    }
                }
                if (!found) {
                    @compileError("Handler has unrecognized callback '" ++ decl.name ++
                        "'. Known callbacks: onRequest, onData, onRequestEnd, " ++
                        "onRequestCancelled, onConnectRequest, " ++
                        "onSessionReady, onStreamData, onDatagram, onSessionClosed, " ++
                        "onSessionDraining, onBidiStream, onUniStream, onStreamReset, " ++
                        "onStopSending, onWritable, onPollComplete, onConnectionClosed, " ++
                        "onQuicConnected, onH0Request, onH0Data, onH0Finished, " ++
                        "onWsUpgrade, onWsMessage, onWsClose");
                }
            }
        }

        if (@hasDecl(Handler, "onQuicConnected") and !serves_raw_quic) {
            @compileError("onQuicConnected needs protocol = .webtransport and raw_quic = true");
        }

        if (@hasDecl(Handler, "onStreamData")) {
            const params = @typeInfo(@TypeOf(Handler.onStreamData)).@"fn".params;
            if (params.len != 4 and params.len != 5) {
                @compileError("onStreamData must have 4 params (self, session, stream_id, data) " ++
                    "or 5 params (self, session, stream_id, data, fin)");
            }
        }

        if ((@hasDecl(Handler, "onWsMessage") or @hasDecl(Handler, "onWsClose")) and !@hasDecl(Handler, "onWsUpgrade")) {
            @compileError("onWsMessage and onWsClose need onWsUpgrade, which accepts the WebSockets they serve");
        }
        if (@hasDecl(Handler, "onWsUpgrade") and @typeInfo(@TypeOf(Handler.onWsUpgrade)).@"fn".params.len != 3) {
            @compileError("onWsUpgrade must have 3 params (self, req: *WsRequest, path)");
        }
        if (@hasDecl(Handler, "onWsMessage")) {
            const n = @typeInfo(@TypeOf(Handler.onWsMessage)).@"fn".params.len;
            if (n != 3 and n != 4) {
                @compileError("onWsMessage must have 3 params (self, ws: *WsConn, data) " ++
                    "or 4 params (self, ws, data, kind: WsMessageKind)");
            }
        }
        if (@hasDecl(Handler, "onWsClose") and @typeInfo(@TypeOf(Handler.onWsClose)).@"fn".params.len != 4) {
            @compileError("onWsClose must have 4 params (self, ws: *WsConn, code: u16, reason)");
        }
    }

    return struct {
        const Self = @This();

        allocator: std.mem.Allocator,
        handler: *Handler,
        conn_mgr: connection_manager.ConnectionManager,

        // libxev. `own_loop` is unused when the caller supplied one; the
        // active loop comes from eventLoop(), as init() returns by value.
        own_loop: xev.Loop,
        shared_loop: ?*xev.Loop,
        file: xev.File,
        timer: xev.Timer,
        poll_completion: xev.Completion,
        timer_completion: xev.Completion,
        timer_cancel_completion: xev.Completion,
        timer_armed: bool,
        started: bool,
        stopping: bool,
        /// `drain()` was called; see there.
        draining: bool,

        /// Zero-delay timer that services connections written to from outside
        /// our callbacks; see `ConnEntry.wake`.
        wake_completion: xev.Completion,
        wake_armed: bool,
        /// Set while one of our callbacks runs: its own send pass covers
        /// whatever the handler queues, so no wakeup is needed.
        in_callback: bool,
        /// A handler wrote during a callback after the send pass began, maybe
        /// to a connection whose turn had passed — another's
        /// onConnectionClosed writing to it, say. Wakes us once it is over.
        written_in_pass: bool,
        /// Stream ids snapshotted per raw-QUIC poll: a handler may open or
        /// close streams from onStreamData, which would invalidate an
        /// iterator over the stream maps.
        quic_poll_ids: std.ArrayList(u64),
        /// A stopped server on a shared loop: every completion is cancelled or
        /// on its way off the loop, and nothing may re-arm.
        halted: bool,
        cancel_completions: [4]xev.Completion,

        // I/O (our own, for ECN support)
        sockfd: posix.socket_t,
        local_addr: posix.sockaddr.storage,
        batch: ecn_socket.SendBatch,
        recv_buf: [MAX_RECV_DATAGRAM]u8,
        out_buf: [1500]u8,
        /// How long datagrams waited in the kernel before the loop read them.
        /// Only filled when the socket was stamped (a qlog run); reported and
        /// cleared once a second.
        rx_wait: RxWait = .{},

        /// Shared by every H3Connection on this loop — one 16 KB buffer for
        /// the whole server rather than one per connection. Safe because a
        /// loop decodes one header block at a time and never holds the
        /// resulting slices past the poll that produced them.
        qpack_scratch: [qpack.SCRATCH_SIZE]u8,

        /// Optional second socket for preferred_address (connectionmigration).
        /// When the server advertises a preferred_address on a different port,
        /// clients migrate there. This socket receives and responds on that port.
        /// The TLS material read off disk in init(), when we loaded it rather
        /// than the caller supplying an in-memory config. Freed in deinit().
        owned_tls: ?OwnedTlsMaterial,

        preferred: ?PreferredSocket,

        /// Optional HTTP/1.1 listener on the same loop; see `Config.http1`.
        http1_server: ?http1.Server,

        foreign_hook: ?ForeignDatagramHook,

        /// WebTransport SETTINGS advertised to every peer, from Config.
        wt_settings: struct {
            max_sessions: u64,
            legacy: bool,
            advertise_credits: bool,
            credits: wt_fc.Credits,
        },

        const PreferredSocket = struct {
            sockfd: posix.socket_t,
            local_addr: posix.sockaddr.storage,
            port: u16,
            file: xev.File,
            poll_completion: xev.Completion,
            batch: ecn_socket.SendBatch,
        };

        pub fn init(alloc: std.mem.Allocator, handler: *Handler, config: Config) !Self {
            if (@hasDecl(Handler, "onWsUpgrade") and config.http1 == null) return error.WebSocketNeedsHttp1;

            // Determine TLS config: use advanced or build from cert/key paths
            var owned_tls: ?OwnedTlsMaterial = null;
            const tls_config: tls13.TlsConfig = if (config.tls_config) |tc| tc else blk: {
                // Read cert files
                const server_cert_pem = try sys.readFileAlloc(alloc, config.cert_path, 8192);
                const server_key_pem = try sys.readFileAlloc(alloc, config.key_path, 8192);

                // Parse PEM -> DER (supports certificate chains, e.g. Let's Encrypt fullchain.pem)
                const cert_chain = try tls13.parsePemCertChain(alloc, server_cert_pem);

                var key_der_buf: [4096]u8 = undefined;
                const key_der = try tls13.parsePemPrivateKey(server_key_pem, &key_der_buf);
                const key = try tls13.extractPrivateKey(key_der);
                const private_key = try alloc.dupe(u8, key.bytes);

                const default_alpn = [_][]const u8{"h3"};
                const alpn = try alloc.dupe([]const u8, config.alpn orelse &default_alpn);

                var ticket_key: [16]u8 = undefined;
                sys.randomBytes(&ticket_key);

                owned_tls = .{
                    .cert_pem = server_cert_pem,
                    .key_pem = server_key_pem,
                    .cert_chain = cert_chain,
                    .private_key = private_key,
                    .alpn = alpn,
                };

                break :blk .{
                    .cert_chain_der = cert_chain,
                    .private_key_bytes = private_key,
                    .private_key_algorithm = key.algorithm,
                    .alpn = alpn,
                    .ticket_key = ticket_key,
                };
            };
            errdefer if (owned_tls) |*o| o.deinit(alloc);

            var retry_token_key: [16]u8 = if (config.retry_token_key) |k| k else undefined;
            if (config.retry_token_key == null) sys.randomBytes(&retry_token_key);

            var static_reset_key: [16]u8 = if (config.static_reset_key) |k| k else undefined;
            if (config.static_reset_key == null) sys.randomBytes(&static_reset_key);

            // Connection config
            var conn_config: connection.ConnectionConfig = if (config.conn_config) |cc| cc else blk: {
                var cc: connection.ConnectionConfig = .{ .token_key = retry_token_key };
                if (Handler.protocol == .webtransport or Handler.protocol == .quic) {
                    cc.max_datagram_frame_size = config.max_datagram_frame_size;
                }
                break :blk cc;
            };
            if (config.quic_lb) |lb| conn_config.quic_lb = lb;
            if (config.foreign_datagram != null and conn_config.quic_lb == null) return error.ForeignDatagramNeedsQuicLb;

            const sockfd, const local_addr = if (config.socket) |fd| .{ fd, try boundAddress(fd) } else try openUdpSocket(config, config.port);
            errdefer if (config.socket == null) sys.close(sockfd);

            // A qlog run is a diagnostic run: stamp arrivals too, so the time a
            // datagram spent queued can be told apart from the time spent
            // answering it. Costs a cmsg per recvmsg, so it is not on otherwise.
            if (conn_config.qlog_dir != null) ecn_socket.enableRxTimestamps(sockfd);

            // Optional second socket for preferred_address (connectionmigration)
            const preferred: ?PreferredSocket = if (config.preferred_port) |pp| blk: {
                const pfd, const paddr = try openUdpSocket(config, pp);
                break :blk .{
                    .sockfd = pfd,
                    .local_addr = connection.sockaddrToStorage(&paddr.any),
                    .port = pp,
                    .file = xev.File.initFd(pfd),
                    .poll_completion = .{},
                    .batch = ecn_socket.SendBatch.init(pfd),
                };
            } else null;
            errdefer if (preferred) |p| sys.close(p.sockfd);

            var conn_mgr = connection_manager.ConnectionManager.init(
                alloc,
                tls_config,
                conn_config,
                retry_token_key,
                static_reset_key,
            );
            conn_mgr.require_retry = config.require_retry;
            conn_mgr.retry_threshold = config.retry_threshold;
            conn_mgr.max_connections = config.max_connections;
            conn_mgr.reply_limits = .init(config.stateless_reply_rate);
            conn_mgr.steer_foreign = config.foreign_datagram != null;

            // Init libxev
            const loop = if (config.loop == null) try xev.Loop.init(.{}) else undefined;
            const file_handle = xev.File.initFd(sockfd);
            const timer_handle = try xev.Timer.init();

            const http1_server: ?http1.Server = if (config.http1) |h1cfg|
                try http1.Server.init(alloc, h1cfg, .{
                    .address = config.address,
                    .ipv6 = config.ipv6,
                    .quic_port = config.port,
                    .reuse_port = config.reuse_port,
                    .certs = .{
                        .entries = tls_config.certs,
                        .single = .{
                            .cert_chain_der = tls_config.cert_chain_der,
                            .private_key_bytes = tls_config.private_key_bytes,
                            .private_key_algorithm = tls_config.private_key_algorithm,
                        },
                        .client_auth = tls_config.client_auth,
                    },
                })
            else
                null;

            return .{
                .allocator = alloc,
                .handler = handler,
                .conn_mgr = conn_mgr,
                .own_loop = loop,
                .shared_loop = config.loop,
                .file = file_handle,
                .timer = timer_handle,
                .poll_completion = .{},
                .timer_completion = .{},
                .timer_cancel_completion = .{},
                .timer_armed = false,
                .started = false,
                .stopping = false,
                .draining = false,
                .wake_completion = .{},
                .wake_armed = false,
                .in_callback = false,
                .written_in_pass = false,
                .quic_poll_ids = .empty,
                .halted = false,
                .cancel_completions = .{ .{}, .{}, .{}, .{} },
                .sockfd = sockfd,
                .local_addr = connection.sockaddrToStorage(&local_addr.any),
                .batch = ecn_socket.SendBatch.init(sockfd),
                .recv_buf = undefined,
                .qpack_scratch = undefined,
                .out_buf = undefined,
                .owned_tls = owned_tls,
                .preferred = preferred,
                .http1_server = http1_server,
                .foreign_hook = config.foreign_datagram,
                .wt_settings = .{
                    .max_sessions = config.webtransport_max_sessions,
                    .legacy = config.wt_legacy_settings,
                    .advertise_credits = config.wt_advertise_credits,
                    .credits = config.wt_credits,
                },
            };
        }

        pub fn deinit(self: *Self) void {
            // On a shared loop our completions must be off it first; see
            // Config.loop.
            if (self.shared_loop != null) std.debug.assert(self.isStopped());
            if (self.http1_server) |*h1| h1.deinit();

            // Whatever is still live goes now; the handler hears about each
            // one first, as it would had the connection closed on its own.
            self.halted = true;
            if (@hasDecl(Handler, "onConnectionClosed")) {
                for (self.conn_mgr.entries.items) |entry| {
                    var session = Session{ .entry = entry };
                    self.handler.onConnectionClosed(&session);
                }
            }

            self.timer.deinit();
            if (self.shared_loop == null) self.own_loop.deinit();
            sys.close(self.sockfd);
            if (self.preferred) |p| sys.close(p.sockfd);
            self.conn_mgr.deinit();
            self.quic_poll_ids.deinit(self.allocator);
            // Last: live connections hold slices into this material.
            if (self.owned_tls) |*o| o.deinit(self.allocator);
        }

        /// The loop this server runs on, ours or the caller's.
        pub fn eventLoop(self: *Self) *xev.Loop {
            return self.shared_loop orelse &self.own_loop;
        }

        /// Register watchers and start the event loop. Call once before tick().
        pub fn start(self: *Self) void {
            const loop = self.eventLoop();
            // Register socket readability watch
            self.file.poll(loop, &self.poll_completion, .read, Self, self, onReadable);
            // Register preferred socket if present
            if (self.preferred) |*p| {
                p.file.poll(loop, &p.poll_completion, .read, Self, self, onReadable);
            }
            if (self.http1_server) |*h1| {
                // WebSocket ids share the QUIC connection counter.
                h1.start(loop, http1.handlersFor(Handler, self.handler), &self.conn_mgr.next_entry_id) catch |err| {
                    log.err("Failed to start HTTP/1.1 listener: {any}", .{err});
                };
            }
            // Arm initial timer (1ms to kick things off)
            self.timer.run(loop, &self.timer_completion, 1, Self, self, onTimer);
            self.timer_armed = true;
            self.started = true;
        }

        /// Blocking run: registers watchers and runs the event loop until
        /// `stop()` completes. Only for a server that owns its loop; on a
        /// shared one, run the loop yourself.
        pub fn run(self: *Self) !void {
            std.debug.assert(self.shared_loop == null);
            self.start();
            try self.own_loop.run(.until_done);
        }

        /// Non-blocking tick: process all pending events and return immediately.
        /// Call start() once before the first tick(). On a shared loop this
        /// drives everything else on it too.
        pub fn tick(self: *Self) !void {
            if (!self.started) self.start();
            try self.eventLoop().run(.no_wait);
        }

        /// True from the moment `stop()` is called, on either kind of loop.
        /// A caller's own completion on the server's loop — a room tick,
        /// say — should stop re-arming then: a shared loop can't run dry
        /// while it does.
        pub fn isStopping(self: *const Self) bool {
            return self.stopping;
        }

        /// On a shared loop: true once `stop()` has finished and none of the
        /// server's completions remain on the loop, so `deinit()` is safe.
        pub fn isStopped(self: *Self) bool {
            if (!self.started) return true;
            if (!self.halted) return false;
            const pending = [_]*const xev.Completion{
                &self.poll_completion,
                &self.timer_completion,
                &self.timer_cancel_completion,
                &self.wake_completion,
            };
            for (pending) |c| if (c.state() != .dead) return false;
            if (self.preferred) |*p| if (p.poll_completion.state() != .dead) return false;
            for (&self.cancel_completions) |*c| if (c.state() != .dead) return false;
            if (self.http1_server) |*h1| if (!h1.isStopped()) return false;
            return true;
        }

        /// Explicitly drain the socket, process connections, and handle timeouts.
        /// Use this from C API tick loops to avoid missing events between
        /// non-blocking event loop polls (edge-triggered race in kqueue/epoll).
        pub fn pollDirect(self: *Self) void {
            self.in_callback = true;
            defer self.endCallback();
            _ = self.recvAllPackets();
            self.processConnections();
            self.tickAndSend();
            self.conn_mgr.freeDeadEntries();
        }

        /// Build and send whatever is queued, now. Writes made through a
        /// Session outside our callbacks already schedule a send for the next
        /// loop iteration; call this to skip that wait, or when the loop is
        /// not being run (a C API caller between ticks).
        pub fn flush(self: *Self) void {
            for (self.conn_mgr.entries.items) |entry| {
                const conn = entry.conn;
                if (conn.isClosed()) continue;
                const batch = self.batchForConn(conn);
                var send_count: usize = 0;
                while (send_count < 1000) : (send_count += 1) {
                    const bytes_written = conn.send(batch.reserve()) catch break;
                    if (bytes_written == 0) break;
                    const send_addr = conn.peerAddress();
                    batch.commit(
                        bytes_written,
                        @ptrCast(send_addr),
                        connection.sockaddrLen(send_addr),
                        conn.getEcnMark(),
                    );
                }
            }
            self.batch.flush();
            if (self.preferred) |*p| p.batch.flush();
            self.rescheduleTimer();
        }

        /// Turn `Config.require_retry` on or off, for an embedder with its own
        /// idea of load — CPU, memory, handshakes per second. Loop thread only.
        pub fn setRequireRetry(self: *Self, on: bool) void {
            self.conn_mgr.require_retry = on;
        }

        /// Begin a graceful HTTP/3 shutdown (RFC 9114 5.2): what a server
        /// under a process manager does on SIGTERM before it stops.
        ///
        /// Every HTTP/3 connection gets a GOAWAY and every WebTransport
        /// session a DRAIN_WEBTRANSPORT_SESSION. New connections are refused
        /// with CONNECTION_REFUSED. Requests already in flight carry on: the
        /// first GOAWAY names no limit, and a PTO later a second one names
        /// the last request served, after which new requests are rejected
        /// with H3_REQUEST_REJECTED. Each connection closes with H3_NO_ERROR
        /// once its requests have finished and the peer has acked every
        /// response byte. WebTransport sessions end when the handler or the
        /// peer closes them. Raw-QUIC and HTTP/0.9 connections have no
        /// graceful signal and are closed at once.
        ///
        /// Poll `isDrained()`, typically against a deadline, then call
        /// `stop()`: it closes whatever is still open, so it is also the
        /// fallback when the deadline passes first.
        pub fn drain(self: *Self) void {
            if (self.draining or self.stopping) return;
            self.draining = true;
            self.conn_mgr.refuse_new = true;
            if (self.http1_server) |*h1| h1.drain();
            const now: i64 = sys.nanoTimestamp();
            for (self.conn_mgr.entries.items) |entry| beginDrain(entry, now);
            self.flush();
        }

        /// True once `drain()` has left no connection with work in flight:
        /// each has closed or is closing. `stop()` then finishes promptly.
        pub fn isDrained(self: *Self) bool {
            if (!self.draining) return false;
            if (self.http1_server) |*h1| if (!h1.isDrained()) return false;
            for (self.conn_mgr.entries.items) |entry| {
                if (entry.conn.state != .closing and entry.conn.state != .draining and
                    entry.conn.state != .terminated) return false;
            }
            return true;
        }

        fn beginDrain(entry: *ConnEntry, now: i64) void {
            const conn = entry.conn;
            if (conn.state == .closing or conn.state == .draining or conn.isClosed()) return;
            switch (Handler.protocol) {
                .h3, .webtransport => if (entry.raw_quic) {
                    conn.close(0, "server shutdown");
                    return;
                },
                .quic, .h0 => {
                    conn.close(0, "server shutdown");
                    return;
                },
            }
            // Still handshaking: initProtocol sends GOAWAY(0) once it can.
            const h3c = entry.h3_conn orelse return;
            h3c.initiateShutdown() catch {
                conn.close(@intFromEnum(h3.H3Error.no_error), "server shutdown");
                return;
            };
            entry.drain_final_goaway_at = now + conn.pkt_handler.rtt_stats.pto();
            if (entry.wt_conn) |wtc| {
                for (&wtc.sessions) |*sess| {
                    if (sess.occupied and sess.state == .active) wtc.drainSession(sess.session_id) catch {};
                }
            }
        }

        /// One drain step for a connection: the final GOAWAY once its time
        /// comes, then CONNECTION_CLOSE once nothing is left in flight.
        fn advanceDrain(entry: *ConnEntry, now: i64) void {
            const conn = entry.conn;
            if (conn.state == .closing or conn.state == .draining or conn.isClosed()) {
                entry.drain_final_goaway_at = null; // a past deadline would spin the timer
                return;
            }
            const h3c = entry.h3_conn orelse return;
            if (h3c.shutdown_state == .going_away_initial) {
                if (now < (entry.drain_final_goaway_at orelse now)) return;
                entry.drain_final_goaway_at = null;
                h3c.completeShutdown() catch {
                    conn.close(@intFromEnum(h3.H3Error.no_error), "server shutdown");
                    return;
                };
            }
            const done = h3c.shutdown_state == .drain_complete or
                (h3c.shutdown_state == .going_away_final and h3c.isDrainComplete());
            if (!done) return;
            // Closing drops whatever the peer has not acked yet, and the
            // close path sends no RESET_STREAM for a request still to reject.
            var it = conn.streams.streams.valueIterator();
            while (it.next()) |s| {
                const send = &s.*.send;
                if (send.hasUnackedData()) return;
                if (send.reset_err != null and !send.reset_stream_sent) return;
            }
            conn.close(@intFromEnum(h3.H3Error.no_error), "");
        }

        /// Initiate graceful shutdown. All active connections receive
        /// CONNECTION_CLOSE, pending data is flushed, then the event loop exits.
        pub fn stop(self: *Self) void {
            self.stopping = true;
            if (self.http1_server) |*h1| h1.stop();
            self.conn_mgr.refuse_new = true; // or arrivals keep stop() from finishing
            for (self.conn_mgr.entries.items) |entry| {
                const conn = entry.conn;
                if (!conn.isClosed() and conn.state != .closing and conn.state != .draining) {
                    conn.close(0, "server shutdown");
                }
            }
            // close() only queues the frame. Waiting for the loop to send it
            // is fine when the caller goes on to run(), and silently wrong
            // when it exits instead — the peer then holds the connection
            // until its idle timeout rather than learning we are gone.
            self.flush();
            if (self.started and self.allConnectionsClosed()) self.finishStop(null);
        }

        /// The last step of `stop()`, once every connection has closed. Our
        /// own loop just stops; a shared one keeps running, so everything we
        /// have on it is cancelled instead.
        ///
        /// `running` is the socket watch whose callback we are in, if any: it
        /// leaves by returning `.disarm` instead, as cancelling it from inside
        /// its own callback does not take.
        fn finishStop(self: *Self, running: ?*xev.Completion) void {
            if (self.shared_loop == null) {
                self.own_loop.stop();
                return;
            }
            if (self.halted) return;
            self.halted = true;
            const loop = self.eventLoop();
            if (running != &self.poll_completion) {
                cancelCompletion(loop, &self.poll_completion, &self.cancel_completions[0]);
            }
            if (self.preferred) |*p| if (running != &p.poll_completion) {
                cancelCompletion(loop, &p.poll_completion, &self.cancel_completions[1]);
            };
            cancelCompletion(loop, &self.timer_completion, &self.cancel_completions[2]);
            cancelCompletion(loop, &self.wake_completion, &self.cancel_completions[3]);
        }

        // A zero-delay pass for writes made outside our callbacks.
        fn scheduleWake(self: *Self) void {
            if (self.in_callback) {
                self.written_in_pass = true;
                return;
            }
            self.armWake();
        }

        fn endCallback(self: *Self) void {
            self.in_callback = false;
            if (self.written_in_pass) {
                self.written_in_pass = false;
                self.armWake();
            }
        }

        fn armWake(self: *Self) void {
            if (self.halted or self.wake_armed or !self.started) return;
            self.timer.run(self.eventLoop(), &self.wake_completion, 0, Self, self, onWake);
            self.wake_armed = true;
        }

        fn wakeFromEntry(ctx: *anyopaque) void {
            const self: *Self = @ptrCast(@alignCast(ctx));
            self.scheduleWake();
        }

        // Unlike a write, nothing in the current pass would pick this up.
        fn repollFromEntry(ctx: *anyopaque) void {
            const self: *Self = @ptrCast(@alignCast(ctx));
            self.armWake();
        }

        fn onWake(
            self_opt: ?*Self,
            _: *xev.Loop,
            _: *xev.Completion,
            r: xev.Timer.RunError!void,
        ) xev.CallbackAction {
            const self = self_opt orelse return .disarm;
            self.wake_armed = false;
            _ = r catch return .disarm;
            if (self.halted) return .disarm;
            self.service();
            return .disarm;
        }

        /// One pass over everything: read, dispatch, send, reap. Shared by
        /// the timer and wakeup callbacks.
        fn service(self: *Self) void {
            self.in_callback = true;
            _ = self.recvAllPackets();
            self.processConnections();
            self.tickAndSend();
            self.conn_mgr.freeDeadEntries();
            self.endCallback();

            if (self.stopping and self.allConnectionsClosed()) {
                self.finishStop(null);
                return;
            }
            self.rescheduleTimer();
        }

        // ---- Internal callbacks ----

        fn onReadable(
            self_opt: ?*Self,
            _: *xev.Loop,
            c: *xev.Completion,
            _: xev.File,
            r: xev.PollError!xev.PollEvent,
        ) xev.CallbackAction {
            forgetPollResult(c);
            _ = r catch return .rearm;
            const self = self_opt orelse return .disarm;
            if (self.halted) return halted_poll_action;
            self.in_callback = true;

            // Process loop: receive → dispatch events → send responses.
            // Loop to catch packets that arrive during processing (critical for
            // edge-triggered I/O where we'd otherwise miss them until the next
            // timer fires, causing ~30ms latency spikes).
            var iterations: usize = 0;
            while (iterations < 4) : (iterations += 1) {
                const received = self.recvAllPackets();
                self.processConnections();
                self.tickAndSend();
                // Free entries that were invalidated during tickAndSend.
                // Deferred so that stale Session pointers from processConnections
                // (which may still be on the stack) safely see wt_conn == null
                // instead of accessing freed memory.
                self.conn_mgr.freeDeadEntries();

                // If no new packets arrived during this cycle, we're done.
                // On the first iteration we always process (triggered by poll event).
                if (iterations > 0 and !received) break;
            }
            self.endCallback();

            if (self.stopping and self.allConnectionsClosed()) {
                self.finishStop(c);
                return .disarm;
            }

            // Reschedule timer
            self.rescheduleTimer();

            return .rearm;
        }

        fn onTimer(
            self_opt: ?*Self,
            _: *xev.Loop,
            _: *xev.Completion,
            r: xev.Timer.RunError!void,
        ) xev.CallbackAction {
            _ = r catch return .disarm;
            const self = self_opt orelse return .disarm;
            self.timer_armed = false;
            if (self.halted) return .disarm;

            // Drains the socket too: an edge-triggered poll may not re-fire
            // for data that arrived while we were processing.
            self.service();

            return .disarm; // one-shot; rescheduled via rescheduleTimer
        }

        fn recvAllPackets(self: *Self) bool {
            var received = self.drainSocket(self.sockfd, self.local_addr, &self.batch);
            if (self.preferred) |*p| {
                if (self.drainSocket(p.sockfd, p.local_addr, &p.batch)) received = true;
            }
            return received;
        }

        fn drainSocket(self: *Self, sockfd: posix.socket_t, local_addr: posix.sockaddr.storage, recv_batch: *ecn_socket.SendBatch) bool {
            var received = false;
            while (true) {
                const recv_result = ecn_socket.recvmsgEcn(sockfd, &self.recv_buf) catch |err| {
                    if (err == error.WouldBlock) break;
                    break;
                };
                received = true;
                if (recv_result.kernel_ns != 0) {
                    // SO_TIMESTAMPNS stamps the wall clock, so the comparison
                    // has to be made on it rather than on the monotonic one.
                    const now_ns: i64 = sys.realtimeNs();
                    self.rx_wait.record(now_ns - recv_result.kernel_ns);
                    self.rx_wait.maybeReport(now_ns);
                }
                if (recv_result.truncated) {
                    std.log.warn("datagram truncated at {d} bytes — raise MAX_RECV_DATAGRAM", .{recv_result.bytes_read});
                }

                switch (self.conn_mgr.recvDatagram(
                    self.recv_buf[0..recv_result.bytes_read],
                    recv_result.from_addr,
                    local_addr,
                    recv_result.ecn,
                    &self.out_buf,
                )) {
                    .processed => {},
                    .send_response => |data| {
                        recv_batch.add(data, @ptrCast(&recv_result.from_addr), recv_result.addr_len, 0);
                    },
                    .dropped => {},
                    .foreign => |server_id| if (self.foreign_hook) |hook| {
                        const dg: ForeignDatagram = .{
                            .bytes = self.recv_buf[0..recv_result.bytes_read],
                            .peer = recv_result.from_addr,
                            .local = local_addr,
                            .ecn = recv_result.ecn,
                            .server_id = server_id,
                        };
                        hook.func(hook.ctx, &dg);
                    },
                }
            }

            return received;
        }

        /// Process a datagram another server received for one of our
        /// connections (see `Config.foreign_datagram`) as if it had arrived
        /// on our own socket: the connection sees `peer` as its source, and
        /// replies go out on our socket — the one whose address is `local`
        /// if it is our preferred-address socket, else the main one.
        ///
        /// Must be called on this server's loop thread, and not from inside
        /// one of its callbacks. `bytes` is decrypted in place.
        ///
        /// A datagram we do not recognise either is answered with a stateless
        /// reset, never handed on again.
        pub fn injectDatagram(
            self: *Self,
            bytes: []u8,
            peer: posix.sockaddr.storage,
            local: posix.sockaddr.storage,
            ecn: u2,
        ) void {
            if (!self.started or self.halted) return;
            var batch = &self.batch;
            var on = self.local_addr;
            if (self.preferred) |*p| {
                if (connection.sockaddrPort(&local) == p.port) {
                    batch = &p.batch;
                    on = p.local_addr;
                }
            }
            self.in_callback = true;
            switch (self.conn_mgr.recvHandedOver(bytes, peer, on, ecn, &self.out_buf)) {
                .send_response => |data| batch.add(data, @ptrCast(&peer), connection.sockaddrLen(&peer), 0),
                .processed, .dropped, .foreign => {},
            }
            self.in_callback = false;
            // One pass covers every datagram handed over this loop tick.
            self.armWake();
        }

        /// Pick the correct SendBatch for a connection based on its local port.
        /// After preferred_address migration, the connection's local_addr will
        /// have the preferred port, so we send from the preferred socket.
        fn batchForConn(self: *Self, conn: *connection.Connection) *ecn_socket.SendBatch {
            if (self.preferred) |*p| {
                const local = conn.localAddress();
                const port = connection.sockaddrPort(local);
                if (port == p.port) return &p.batch;
            }
            return &self.batch;
        }

        fn processConnections(self: *Self) void {
            for (self.conn_mgr.entries.items) |entry| {
                const conn = entry.conn;

                // Initialize protocol layer once handshake completes
                if (conn.isEstablished() and !entry.h3_initialized) {
                    self.initProtocol(entry);
                }

                // Poll events and dispatch to handler
                switch (Handler.protocol) {
                    .webtransport => if (entry.raw_quic) self.pollQuicEvents(entry) else self.pollWtEvents(entry),
                    .h3 => self.pollH3Events(entry),
                    .h0 => self.pollH0Events(entry),
                    .quic => self.pollQuicEvents(entry),
                }

                // Remove streams that were queued for disposal during this cycle.
                // WT layer reads the queue first (to clean its own maps), then
                // QUIC layer drains it (actually removing stream objects).
                if (entry.wt_conn) |wtc| {
                    wtc.drainDisposalQueue(); // chains to its H3 layer
                } else if (entry.h3_conn) |h3c| {
                    h3c.drainDisposalQueue();
                }
                for (conn.streams.disposal_queue[0..conn.streams.disposal_count]) |id| {
                    _ = entry.finished_streams.remove(id);
                }
                conn.streams.drainDisposalQueue();

                if (self.draining) advanceDrain(entry, sys.nanoTimestamp());
            }
        }

        /// Zero-copy datagram callback: fires during QUIC packet processing,
        /// before the data is copied to any ring buffer. `data` is a slice into
        /// the decrypted packet and is only valid for the duration of this call.
        fn datagramRecvCallback(data: []const u8, ctx: ?*anyopaque) void {
            const entry: *ConnEntry = @ptrCast(@alignCast(ctx orelse return));
            const wtc = entry.wt_conn orelse return;

            // Parse WT quarter_stream_id prefix inline
            var reader: std.Io.Reader = .fixed(data);
            const quarter_id = packet.readVarInt(&reader) catch return;
            const session_id = quarter_id * 4;

            if (wtc.getSession(session_id) == null) return;
            const payload = data[reader.seek..];

            // Deliver directly to handler — bypasses ring buffer + poll chain entirely.
            const handler_ptr: *Handler = @ptrCast(@alignCast(entry.datagram_handler_ctx orelse return));
            var session = Session{ .entry = entry };
            handler_ptr.onDatagram(&session, session_id, payload);
        }

        fn initProtocol(self: *Self, entry: *ConnEntry) void {
            if (serves_raw_quic and !std.mem.eql(u8, entry.conn.negotiatedAlpn(), "h3")) {
                entry.raw_quic = true;
            } else switch (Handler.protocol) {
                .webtransport => {
                    const h3c = self.allocator.create(h3.H3Connection) catch return;
                    h3c.* = h3.H3Connection.init(self.allocator, entry.conn, true);
                    h3c.qpack_scratch = &self.qpack_scratch;
                    h3c.local_settings = .{
                        .enable_connect_protocol = true,
                        .h3_datagram = true,
                        .enable_webtransport = self.wt_settings.legacy,
                        .webtransport_max_sessions = if (self.wt_settings.legacy) self.wt_settings.max_sessions else null,
                        .wt_max_sessions_v13 = self.wt_settings.max_sessions,
                        .wt_initial_max_data = announced(self.wt_settings.advertise_credits, self.wt_settings.credits.max_data),
                        .wt_initial_max_streams_bidi = announced(self.wt_settings.advertise_credits, self.wt_settings.credits.max_streams_bidi),
                        .wt_initial_max_streams_uni = announced(self.wt_settings.advertise_credits, self.wt_settings.credits.max_streams_uni),
                    };
                    entry.h3_conn = h3c;
                    h3c.initConnection() catch return;

                    const wtc = self.allocator.create(wt.WebTransportConnection) catch return;
                    wtc.* = wt.WebTransportConnection.init(self.allocator, h3c, entry.conn, true);
                    wtc.grants = self.wt_settings.credits;
                    entry.wt_conn = wtc;

                    // Install zero-copy datagram callback on the QUIC connection.
                    // Datagrams will be delivered directly during packet processing,
                    // bypassing the recv ring buffer entirely.
                    if (@hasDecl(Handler, "onDatagram")) {
                        entry.conn.datagram_recv_callback = datagramRecvCallback;
                        entry.conn.datagram_recv_ctx = @ptrCast(entry);
                        entry.datagram_handler_ctx = @ptrCast(self.handler);
                    }
                },
                .h3 => {
                    const h3c = self.allocator.create(h3.H3Connection) catch return;
                    h3c.* = h3.H3Connection.init(self.allocator, entry.conn, true);
                    h3c.qpack_scratch = &self.qpack_scratch;
                    entry.h3_conn = h3c;
                    h3c.initConnection() catch return;
                },
                .h0 => {
                    const h0c = self.allocator.create(h0.H0Connection) catch return;
                    h0c.* = h0.H0Connection.init(self.allocator, entry.conn, true);
                    entry.h0_conn = h0c;
                },
                .quic => {},
            }

            entry.wake_fn = wakeFromEntry;
            entry.repoll_fn = repollFromEntry;
            entry.wake_ctx = self;
            entry.h3_initialized = true;

            if (serves_raw_quic and entry.raw_quic and @hasDecl(Handler, "onQuicConnected")) {
                var session = Session{ .entry = entry };
                self.handler.onQuicConnected(&session);
            }

            // Finished its handshake after drain() began: it may send nothing.
            if (self.draining) {
                if (entry.h3_conn) |h3c| {
                    h3c.sendGoaway(0) catch entry.conn.close(@intFromEnum(h3.H3Error.no_error), "server shutdown");
                } else {
                    entry.conn.close(0, "server shutdown");
                }
            }
        }

        fn pollWtEvents(self: *Self, entry: *ConnEntry) void {
            if (entry.wt_conn == null) return;
            const wtc = entry.wt_conn.?;
            var session = Session{ .entry = entry };

            // Allow handler to run deferred work each poll cycle
            if (@hasDecl(Handler, "onPollComplete")) {
                self.handler.onPollComplete(&session);
            }

            // Fast-path: drain datagrams directly without going through the
            // full wt.poll() chain. This avoids O(event_types) overhead per
            // datagram by calling pollDatagrams() directly.
            if (@hasDecl(Handler, "onDatagram")) {
                while (wtc.pollDatagrams()) |dg_event| {
                    switch (dg_event) {
                        .datagram => |dg| self.handler.onDatagram(&session, dg.session_id, dg.data),
                        else => unreachable,
                    }
                }
            }

            while (true) {
                const event = wtc.poll() catch break;
                if (event == null) break;

                switch (event.?) {
                    .connect_request => |req| {
                        self.dispatchConnectRequest(&session, req.session_id, req.path, req.headers);
                    },
                    .session_ready => |sr| {
                        self.dispatchSessionReady(&session, sr.session_id, sr.headers);
                    },
                    .stream_data => |sd| {
                        self.dispatchStreamData(&session, sd.stream_id, sd.data, sd.fin);
                        if (sd.data.len > 0) self.allocator.free(sd.data);
                    },
                    .datagram => |dg| {
                        if (@hasDecl(Handler, "onDatagram")) {
                            self.handler.onDatagram(&session, dg.session_id, dg.data);
                        }
                    },
                    .session_closed => |cls| {
                        if (@hasDecl(Handler, "onSessionClosed")) {
                            self.handler.onSessionClosed(&session, cls.session_id, cls.error_code, cls.reason);
                        }
                    },
                    .session_draining => |sd| {
                        if (@hasDecl(Handler, "onSessionDraining")) {
                            self.handler.onSessionDraining(&session, sd.session_id);
                        }
                    },
                    .bidi_stream => |bs| {
                        if (@hasDecl(Handler, "onBidiStream")) {
                            self.handler.onBidiStream(&session, bs.session_id, bs.stream_id);
                        }
                    },
                    .uni_stream => |us| {
                        if (@hasDecl(Handler, "onUniStream")) {
                            self.handler.onUniStream(&session, us.session_id, us.stream_id);
                        }
                    },
                    .stream_reset => |rst| {
                        if (@hasDecl(Handler, "onStreamReset")) {
                            self.handler.onStreamReset(&session, rst.session_id, rst.stream_id, rst.error_code);
                        }
                    },
                    .stream_stop_sending => |ss| {
                        if (@hasDecl(Handler, "onStopSending")) {
                            self.handler.onStopSending(&session, ss.session_id, ss.stream_id, ss.error_code);
                        }
                    },
                    .writable => |w| {
                        if (@hasDecl(Handler, "onWritable")) {
                            self.handler.onWritable(&session, w.session_id, w.stream_id);
                        }
                    },
                    .session_rejected => {},
                    .request => |req| self.dispatchRequest(&session, req.stream_id, req.headers),
                    .request_data => |d| {
                        if (@hasDecl(Handler, "onData")) self.handler.onData(&session, d.stream_id, d.data);
                    },
                    .request_end => |sid| self.dispatchRequestEnd(&session, sid),
                    .request_cancelled => |rc| self.dispatchRequestCancelled(&session, rc.stream_id, rc.error_code),
                }
            }
        }

        fn dispatchRequest(self: *Self, session: *Session, stream_id: u64, headers: []const qpack.Header) void {
            if (@hasDecl(Handler, "onRequest")) {
                self.handler.onRequest(session, stream_id, headers);
            } else {
                // Nobody will answer it, so say so instead of leaving it open.
                session.resetRequest(stream_id, @intFromEnum(h3.H3Error.request_rejected));
            }
        }

        fn dispatchRequestEnd(self: *Self, session: *Session, stream_id: u64) void {
            if (@hasDecl(Handler, "onRequestEnd")) self.handler.onRequestEnd(session, stream_id);
        }

        fn dispatchRequestCancelled(self: *Self, session: *Session, stream_id: u64, error_code: u64) void {
            if (@hasDecl(Handler, "onRequestCancelled")) self.handler.onRequestCancelled(session, stream_id, error_code);
        }

        fn dispatchStreamData(self: *Self, session: *Session, stream_id: u64, data: []const u8, fin: bool) void {
            if (!@hasDecl(Handler, "onStreamData")) return;

            if (comptime @typeInfo(@TypeOf(Handler.onStreamData)).@"fn".params.len == 5) {
                self.handler.onStreamData(session, stream_id, data, fin);
            } else if (data.len > 0) {
                self.handler.onStreamData(session, stream_id, data);
            }
        }

        // The 5-arity form also receives the CONNECT request headers, which
        // is where WebTransport carries the application-protocol offer.
        fn dispatchConnectRequest(self: *Self, session: *Session, session_id: u64, path: []const u8, headers: []const qpack.Header) void {
            if (!@hasDecl(Handler, "onConnectRequest")) return;

            if (comptime @typeInfo(@TypeOf(Handler.onConnectRequest)).@"fn".params.len == 5) {
                self.handler.onConnectRequest(session, session_id, path, headers);
            } else {
                self.handler.onConnectRequest(session, session_id, path);
            }
        }

        fn dispatchSessionReady(self: *Self, session: *Session, session_id: u64, headers: []const qpack.Header) void {
            if (!@hasDecl(Handler, "onSessionReady")) return;

            if (comptime @typeInfo(@TypeOf(Handler.onSessionReady)).@"fn".params.len == 4) {
                self.handler.onSessionReady(session, session_id, headers);
            } else {
                self.handler.onSessionReady(session, session_id);
            }
        }

        fn pollH3Events(self: *Self, entry: *ConnEntry) void {
            if (entry.h3_conn == null) return;
            const h3c = entry.h3_conn.?;
            var session = Session{ .entry = entry };

            while (true) {
                const event = h3c.poll() catch break;
                if (event == null) break;

                switch (event.?) {
                    .headers => |hdr| self.dispatchRequest(&session, hdr.stream_id, hdr.headers),
                    // We never offer Extended CONNECT, so this is a peer's own idea.
                    .connect_request => |req| self.dispatchRequest(&session, req.stream_id, req.headers),
                    .data => |d| {
                        if (@hasDecl(Handler, "onData")) {
                            var body_buf: [8192]u8 = undefined;
                            while (true) {
                                const n = h3c.recvBody(&body_buf);
                                if (n == 0) break;
                                self.handler.onData(&session, d.stream_id, body_buf[0..n]);
                            }
                        } else {
                            // Drain body even if handler doesn't consume it
                            var sink: [4096]u8 = undefined;
                            while (h3c.recvBody(&sink) > 0) {}
                        }
                    },
                    .finished => |sid| self.dispatchRequestEnd(&session, sid),
                    .request_cancelled => |rc| self.dispatchRequestCancelled(&session, rc.stream_id, rc.error_code),
                    .writable => |sid| {
                        if (@hasDecl(Handler, "onWritable")) self.handler.onWritable(&session, sid, sid);
                    },
                    .settings, .goaway, .shutdown_complete => {},
                }
            }
        }

        fn pollH0Events(self: *Self, entry: *ConnEntry) void {
            const h0c = entry.h0_conn orelse return;
            var session = Session{ .entry = entry };

            while (true) {
                const event = h0c.poll() catch break;
                if (event == null) break;

                switch (event.?) {
                    .request => |req| {
                        if (@hasDecl(Handler, "onH0Request")) {
                            self.handler.onH0Request(&session, req.stream_id, req.path);
                        }
                    },
                    .data => |d| {
                        if (@hasDecl(Handler, "onH0Data")) {
                            self.handler.onH0Data(&session, d.stream_id, d.data);
                        }
                    },
                    .finished => |stream_id| {
                        if (@hasDecl(Handler, "onH0Finished")) {
                            self.handler.onH0Finished(&session, stream_id);
                        }
                    },
                }
            }
        }

        fn pollQuicEvents(self: *Self, entry: *ConnEntry) void {
            const conn = entry.conn;
            var session = Session{ .entry = entry };

            if (@hasDecl(Handler, "onPollComplete")) {
                self.handler.onPollComplete(&session);
            }

            // Raw QUIC has no session id to report, so 0 stands in.
            // WebTransport installs a zero-copy callback instead and does
            // not reach here.
            if (@hasDecl(Handler, "onDatagram")) {
                while (conn.peekDatagram()) |dg| {
                    self.handler.onDatagram(&session, 0, dg);
                    conn.consumeDatagram();
                }
            }

            // Poll bidirectional streams. Everything readable goes now: a
            // pass happens only on I/O, and data left behind stays unread —
            // withholding flow-control credit — until the peer sends again.
            const ids = &self.quic_poll_ids;
            ids.clearRetainingCapacity();
            ids.ensureTotalCapacity(self.allocator, conn.streams.streams.count() + conn.streams.recv_streams.count()) catch return;
            var key_it = conn.streams.streams.keyIterator();
            while (key_it.next()) |k| ids.appendAssumeCapacity(k.*);
            var recv_key_it = conn.streams.recv_streams.keyIterator();
            while (recv_key_it.next()) |k| ids.appendAssumeCapacity(k.*);

            // Looked up again each time: the handler may have closed it.
            for (ids.items) |stream_id| {
                while (conn.streams.getRecvStream(stream_id)) |rs| {
                    const data = rs.read() orelse break;
                    const fin = rs.finished;
                    if (fin) entry.finished_streams.put(self.allocator, stream_id, {}) catch {};
                    self.dispatchStreamData(&session, stream_id, data, fin);
                    self.allocator.free(data);
                }
                const rs = conn.streams.getRecvStream(stream_id) orelse continue;
                if (rs.finished and !entry.finished_streams.contains(stream_id)) {
                    entry.finished_streams.put(self.allocator, stream_id, {}) catch {};
                    self.dispatchStreamData(&session, stream_id, &[_]u8{}, true);
                }
                // Raw QUIC has no session: 0 stands in, as for datagrams.
                if (rs.reset_err) |code| if (!entry.finished_streams.contains(stream_id)) {
                    entry.finished_streams.put(self.allocator, stream_id, {}) catch {};
                    if (@hasDecl(Handler, "onStreamReset")) self.handler.onStreamReset(&session, 0, stream_id, @truncate(code));
                };
                // A peer's uni stream has no send side left to wait on.
                if ((rs.finished or rs.reset_err != null) and !stream_mod.isBidi(stream_id)) conn.streams.releaseRecvStream(stream_id);
            }
        }

        fn tickAndSend(self: *Self) void {
            // What was written before this point goes out below.
            self.written_in_pass = false;
            // One clock read for the pass: a deadline check does not need a
            // fresher now than this, and reading it per connection showed up.
            const pass_now_ns: i64 = sys.nanoTimestamp();
            var i: usize = 0;
            while (i < self.conn_mgr.entries.items.len) {
                const entry = self.conn_mgr.entries.items[i];

                // Call onTimeout() in a loop to fire ALL expired PTO deadlines.
                // quic-go fires PTO for each space independently; without this loop,
                // we only fire the earliest space per tick, requiring separate timer
                // events for each space. Under burst loss, coalescing all PTO fires
                // sends more diverse packets in one burst.
                // Only when a deadline has actually passed, or the connection is
                // waiting to close once its streams drain: `close_when_idle` has
                // no deadline of its own and relies on being looked at each pass.
                // Otherwise onTimeout does nothing, and reaching it costs a call
                // and a clock read for every connection on every pass.
                const due = if (entry.conn.nextTimeoutNs()) |first| first <= pass_now_ns else false;
                if (due or entry.conn.close_when_idle) {
                    var timeout_iter: usize = 0;
                    while (timeout_iter < 8) : (timeout_iter += 1) {
                        entry.conn.onTimeout() catch {};
                        if (entry.conn.isClosed()) break;
                        // Check if there are more expired timeouts
                        const next = entry.conn.nextTimeoutNs();
                        if (next == null) break;
                        const now_ns: i64 = sys.nanoTimestamp();
                        if (next.? > now_ns) break;
                    }
                }
                if (entry.conn.isClosed()) {
                    // Fire onSessionClosed BEFORE removeConnection invalidates
                    // the entry, so the handler can mark clients as disconnected.
                    // Without this, PTO-killed connections never get a session_closed
                    // event because the entry is removed from the list before the
                    // WT layer can generate one.
                    var session = Session{ .entry = entry };
                    if (@hasDecl(Handler, "onSessionClosed")) {
                        self.handler.onSessionClosed(&session, 0, 0, "");
                    }
                    if (@hasDecl(Handler, "onConnectionClosed")) {
                        self.handler.onConnectionClosed(&session);
                    }
                    self.conn_mgr.removeConnection(entry);
                    continue;
                }

                const conn = entry.conn;
                const batch = self.batchForConn(conn);
                const max_burst_packets = 1000;
                var send_count: usize = 0;
                while (send_count < max_burst_packets) : (send_count += 1) {
                    const bytes_written = conn.send(batch.reserve()) catch break;
                    if (bytes_written == 0) break;
                    const send_addr = conn.peerAddress();
                    batch.commit(
                        bytes_written,
                        @ptrCast(send_addr),
                        connection.sockaddrLen(send_addr),
                        conn.getEcnMark(),
                    );
                }

                i += 1;
            }

            self.batch.flush();
            if (self.preferred) |*p| p.batch.flush();
        }

        fn rescheduleTimer(self: *Self) void {
            // Before start() the timer is not ours to arm: start() arms it.
            if (self.halted or !self.started) return;
            const next_ms = self.computeNextTimeoutMs() orelse return;

            if (!self.timer_armed and self.timer_cancel_completion.state() != .dead) {
                // The timer fired with a reset's cancel still queued against
                // it. Re-adding it now would let that cancel kill the new timer
                // and leave it linked in libxev's submission queue, where the
                // next add corrupts the queue. Retry once the cancel is through.
                self.armWake();
                return;
            }
            if (self.timer_armed) {
                self.timer.reset(
                    self.eventLoop(),
                    &self.timer_completion,
                    &self.timer_cancel_completion,
                    next_ms,
                    Self,
                    self,
                    onTimer,
                );
            } else {
                self.timer.run(
                    self.eventLoop(),
                    &self.timer_completion,
                    next_ms,
                    Self,
                    self,
                    onTimer,
                );
            }
            self.timer_armed = true;
        }

        fn allConnectionsClosed(self: *Self) bool {
            for (self.conn_mgr.entries.items) |entry| {
                if (!entry.conn.isClosed()) return false;
            }
            return true;
        }

        fn computeNextTimeoutMs(self: *Self) ?u64 {
            const now: i64 = sys.nanoTimestamp();
            var earliest: ?i64 = null;

            for (self.conn_mgr.entries.items) |entry| {
                if (entry.conn.nextTimeoutNs()) |deadline| {
                    if (earliest == null or deadline < earliest.?) {
                        earliest = deadline;
                    }
                }
                if (entry.drain_final_goaway_at) |deadline| {
                    if (earliest == null or deadline < earliest.?) earliest = deadline;
                }
            }

            // A handler with its own deadlines — a publisher on a tick, a
            // relay holding a subscription open — cannot rely on QUIC having
            // a timer pending, so let it name a cadence to be woken on.
            const floor: ?u64 = if (@hasDecl(Handler, "poll_interval_ms")) Handler.poll_interval_ms else null;

            const deadline = earliest orelse return floor;
            const delta_ns = deadline - now;
            if (delta_ns <= 0) return 1; // overdue — fire on next tick
            const ms: u64 = @intCast(@divFloor(delta_ns, 1_000_000));
            return if (floor) |f| @min(ms, f) else ms;
        }
    };
}

/// The address `fd` is bound to.
fn boundAddress(fd: posix.socket_t) !net.Address {
    var addr: net.Address = undefined;
    var len: posix.socklen_t = @sizeOf(net.Address);
    try sys.getsockname(fd, &addr.any, &len);
    return addr;
}

/// A bound, non-blocking UDP socket for the server, with Config's socket
/// options applied.
fn openUdpSocket(config: Config, port: u16) !struct { posix.socket_t, net.Address } {
    const addr = if (config.ipv6)
        try net.Address.parseIp6("::", port)
    else
        try net.Address.parseIp4(config.address, port);
    const family: u32 = if (config.ipv6) posix.AF.INET6 else posix.AF.INET;
    const fd = try sys.socket(family, posix.SOCK.DGRAM | posix.SOCK.NONBLOCK, 0);
    errdefer sys.close(fd);

    if (config.ipv6) {
        // Dual-stack: also accept IPv4 peers.
        const IPV6_V6ONLY: u32 = if (builtin.os.tag == .linux) 26 else 27;
        posix.setsockopt(fd, posix.IPPROTO.IPV6, IPV6_V6ONLY, std.mem.asBytes(&@as(c_int, 0))) catch {};
    }
    posix.setsockopt(fd, posix.SOL.SOCKET, posix.SO.REUSEADDR, std.mem.asBytes(&@as(c_int, 1))) catch {};
    // Asked for explicitly, so a failure is the caller's to see.
    if (config.reuse_port) {
        try posix.setsockopt(fd, posix.SOL.SOCKET, posix.SO.REUSEPORT, std.mem.asBytes(&@as(c_int, 1)));
    }
    if (config.recv_buffer_size) |n| {
        try posix.setsockopt(fd, posix.SOL.SOCKET, posix.SO.RCVBUF, std.mem.asBytes(&@as(c_int, @intCast(@min(n, std.math.maxInt(c_int))))));
    }
    if (config.send_buffer_size) |n| {
        try posix.setsockopt(fd, posix.SOL.SOCKET, posix.SO.SNDBUF, std.mem.asBytes(&@as(c_int, @intCast(@min(n, std.math.maxInt(c_int))))));
    }

    try sys.bind(fd, &addr.any, addr.getOsSockLen());
    ecn_socket.enableEcnRecv(fd) catch {};
    return .{ fd, addr };
}

/// Receive-queue delay, summarised rather than kept per datagram: the question
/// it answers is whether a request waited to be read at all, not which one did.
const RxWait = struct {
    count: u64 = 0,
    sum_ns: u64 = 0,
    max_ns: u64 = 0,
    over_1ms: u64 = 0,
    report_at: i64 = 0,

    fn record(self: *RxWait, wait_ns: i64) void {
        if (wait_ns < 0) return; // clocks disagree; nothing to learn from it
        const w: u64 = @intCast(wait_ns);
        self.count += 1;
        self.sum_ns += w;
        if (w > self.max_ns) self.max_ns = w;
        if (w > std.time.ns_per_ms) self.over_1ms += 1;
    }

    fn maybeReport(self: *RxWait, now: i64) void {
        if (self.count == 0) return;
        if (self.report_at == 0) {
            self.report_at = now + std.time.ns_per_s;
            return;
        }
        if (now < self.report_at) return;
        // Straight to stderr: this is a diagnostic run's output, and a
        // dependency's std.log does not reach the host's log writer.
        std.debug.print("rx wait: n={d} mean={d}us max={d}us over_1ms={d}\n", .{
            self.count,
            self.sum_ns / self.count / std.time.ns_per_us,
            self.max_ns / std.time.ns_per_us,
            self.over_1ms,
        });
        self.* = .{ .report_at = now + std.time.ns_per_s };
    }
};

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

/// draft-13 §5.5: a credit is announced in SETTINGS only when we chose to.
/// Absent means the peer starts at zero and waits for the per-session capsule.
fn announced(advertise: bool, credit: u64) ?u64 {
    return if (advertise) credit else null;
}

pub const ClientConfig = struct {
    // Target server
    address: []const u8 = "127.0.0.1",
    port: u16 = 4433,
    server_name: []const u8 = "localhost",

    // WebTransport session path (auto-CONNECT on handshake complete)
    path: []const u8 = "/.well-known/webtransport",

    // Extra headers on the extended CONNECT — this is where
    // WT-Available-Protocols goes. The slices must outlive the client.
    connect_headers: []const qpack.Header = &.{},

    // TLS ALPN override (when null, derived from handler protocol: "h3" for h3/webtransport)
    alpn: ?[]const u8 = null,

    // TLS verification
    /// Where the trust anchors come from. `.none` leaves the chain unrooted:
    /// the hostname, each link's signature, CA:TRUE/keyCertSign and the
    /// validity dates are still checked, but nothing says the chain ends
    /// anywhere you trust. `.system` reads the platform's store, `.file` a
    /// PEM bundle of your own — a private CA, an interop peer's.
    ///
    /// `.pinned_hashes` is the browsers' `serverCertificateHashes`: SHA-256
    /// fingerprints of leaf certificates to accept outright. The fingerprint
    /// replaces the chain, the hostname and the validity dates, so it reaches
    /// a self-signed server the trust store knows nothing about — the same
    /// bargain that lets a browser talk to our test server.
    ///
    /// Anything but `.none` also turns `skip_cert_verify` off.
    ///
    /// Each client loads its own copy — about 13 ms for the 163 certificates
    /// in the macOS store. For many short-lived clients in one process, build
    /// one `ca_bundle.loadSystem()` yourself and hand it to every connection
    /// through `tls_config`.
    ca: union(enum) {
        none,
        system,
        file: []const u8,
        pinned_hashes: []const [32]u8,
    } = .none,
    skip_cert_verify: bool = false,

    // QUIC transport
    max_datagram_frame_size: u64 = 65536,

    /// draft-13 §5.6 session flow control. See the identically named `Config`
    /// fields.
    wt_credits: wt_fc.Credits = wt_fc.Credits.default,
    wt_advertise_credits: bool = false,

    // Advanced overrides
    tls_config: ?tls13.TlsConfig = null,
    conn_config: ?connection.ConnectionConfig = null,

    // IPv6
    ipv6: bool = false,

    /// An event loop to join rather than create. Several clients sharing one
    /// loop is how you drive more than one connection at a time without
    /// spinning `tick()` over each of them in turn: the caller owns the loop,
    /// calls `start()` on each client, and then runs it. A client that joined
    /// a loop never stops it, so one shutting down leaves the others running.
    ///
    /// The loop outlives the client, so the client's completions have to be
    /// off it before `deinit()`: `stop()`, then `tick()` until
    /// `conn.isClosed()`. Deinitialising every client before the loop and not
    /// running it again does just as well.
    loop: ?*xev.Loop = null,
};

/// ClientSession wraps a single client-side connection and provides the same
/// convenience methods as the server-side Session.
/// TLS material a Server allocated for itself in init(), so deinit() can give
/// it back. Absent when the caller supplied an in-memory `tls_config`.
const OwnedTlsMaterial = struct {
    cert_pem: []u8,
    key_pem: []u8,
    cert_chain: [][]const u8,
    private_key: []u8,
    alpn: [][]const u8,

    fn deinit(self: *OwnedTlsMaterial, alloc: std.mem.Allocator) void {
        alloc.free(self.cert_pem);
        alloc.free(self.key_pem);
        for (self.cert_chain) |der| alloc.free(der); // each DER is its own alloc
        alloc.free(self.cert_chain);
        alloc.free(self.private_key);
        alloc.free(self.alpn);
    }
};

pub const ClientSession = struct {
    conn: *connection.Connection,
    h3_conn: ?*h3.H3Connection = null,
    wt_conn: ?*wt.WebTransportConnection = null,

    /// The owning Client's `stopping` flag. A client has exactly one
    /// connection, so closing it from a handler is a request to shut down —
    /// the run loop only leaves once this is set and the connection has
    /// finished draining.
    stopping: ?*bool = null,

    /// The owning Client's wakeup, so a write made outside its callbacks is
    /// sent on the next loop iteration.
    wake_fn: ?*const fn (ctx: *anyopaque) void = null,
    wake_ctx: ?*anyopaque = null,
    /// Asks for another poll pass even from inside a callback, for data
    /// already received that became deliverable. Takes `wake_ctx`.
    repoll_fn: ?*const fn (ctx: *anyopaque) void = null,

    fn wake(self: *ClientSession) void {
        if (self.wake_fn) |f| f(self.wake_ctx orelse return);
    }

    fn repoll(self: *ClientSession) void {
        if (self.repoll_fn) |f| f(self.wake_ctx orelse return);
    }

    // --- H3 methods ---

    pub fn sendRequest(self: *ClientSession, headers: []const qpack.Header, body: ?[]const u8) !u64 {
        defer self.wake();
        if (self.h3_conn) |h3c| {
            return try h3c.sendRequest(headers, body);
        }
        return error.NoH3Connection;
    }

    pub fn sendResponse(self: *ClientSession, stream_id: u64, headers: []const qpack.Header, body: []const u8) !void {
        defer self.wake();
        if (self.h3_conn) |h3c| {
            try h3c.sendResponse(stream_id, headers, body);
        } else return error.NoH3Connection;
    }

    pub fn recvBody(self: *ClientSession, buf: []u8) usize {
        if (self.h3_conn) |h3c| {
            return h3c.recvBody(buf);
        }
        return 0;
    }

    // --- Raw QUIC methods ---

    pub fn openStream(self: *ClientSession) !u64 {
        const stream = try self.conn.openStream();
        return stream.stream_id;
    }

    pub fn openQuicUniStream(self: *ClientSession) !u64 {
        const send_stream = try self.conn.openUniStream();
        return send_stream.stream_id;
    }

    pub fn writeStream(self: *ClientSession, stream_id: u64, data: []const u8) !void {
        defer self.wake();
        if (self.conn.streams.getStream(stream_id)) |stream| {
            return stream.send.writeData(data);
        }
        if (self.conn.streams.send_streams.get(stream_id)) |ss| {
            return ss.writeData(data);
        }
        return error.StreamNotFound;
    }

    pub fn closeQuicStream(self: *ClientSession, stream_id: u64) void {
        defer self.wake();
        if (self.conn.streams.getStream(stream_id)) |stream| {
            stream.send.close();
        } else if (self.conn.streams.send_streams.get(stream_id)) |ss| {
            ss.close();
        }
    }

    pub fn readStream(self: *ClientSession, stream_id: u64) ?[]const u8 {
        if (self.conn.streams.getStream(stream_id)) |stream| {
            return stream.recv.read();
        }
        if (self.conn.streams.recv_streams.get(stream_id)) |rs| {
            return rs.read();
        }
        return null;
    }

    // --- WebTransport methods ---

    /// `Session.pauseStream`, for a client: stop `onStreamData` for a
    /// WebTransport stream and let flow control hold the server back.
    pub fn pauseStream(self: *ClientSession, stream_id: u64) !void {
        const wtc = self.wt_conn orelse return error.NoWebTransportConnection;
        try wtc.pauseStream(stream_id);
    }

    /// `Session.resumeStream`, for a client.
    pub fn resumeStream(self: *ClientSession, stream_id: u64) void {
        const wtc = self.wt_conn orelse return;
        wtc.resumeStream(stream_id);
        self.repoll();
    }

    pub fn sendStreamData(self: *ClientSession, stream_id: u64, data: []const u8) !void {
        defer self.wake();
        if (self.wt_conn) |wtc| {
            try wtc.sendStreamData(stream_id, data);
        } else return error.NoWtConnection;
    }

    /// `session_id` names the WebTransport session; on raw QUIC there is
    /// none and it is ignored.
    pub fn sendDatagram(self: *ClientSession, session_id: u64, data: []const u8) !void {
        defer self.wake();
        if (self.wt_conn) |wtc| {
            return wtc.sendDatagram(session_id, data);
        }
        return self.conn.sendDatagram(data);
    }

    pub fn closeStream(self: *ClientSession, stream_id: u64) void {
        defer self.wake();
        if (self.wt_conn) |wtc| {
            wtc.closeStream(stream_id);
        }
    }

    pub fn openBidiStream(self: *ClientSession, session_id: u64, send_order: ?i64) !u64 {
        if (self.wt_conn) |wtc| {
            return try wtc.openBidiStream(session_id, send_order);
        }
        return error.NoWtConnection;
    }

    pub fn openUniStream(self: *ClientSession, session_id: u64, send_order: ?i64) !u64 {
        if (self.wt_conn) |wtc| {
            return try wtc.openUniStream(session_id, send_order);
        }
        return error.NoWtConnection;
    }

    pub fn setSendOrder(self: *ClientSession, stream_id: u64, send_order: ?i64) void {
        if (self.wt_conn) |wtc| {
            wtc.setSendOrder(stream_id, send_order);
        }
    }

    pub fn closeSession(self: *ClientSession, session_id: u64) void {
        defer self.wake();
        if (self.wt_conn) |wtc| {
            wtc.closeSession(session_id);
        }
    }

    pub fn closeSessionWithError(self: *ClientSession, session_id: u64, error_code: u32, reason: []const u8) !void {
        defer self.wake();
        if (self.wt_conn) |wtc| {
            try wtc.closeSessionWithError(session_id, error_code, reason);
        }
    }

    pub fn resetStream(self: *ClientSession, stream_id: u64, error_code: u32) void {
        defer self.wake();
        if (self.wt_conn) |wtc| {
            wtc.resetStream(stream_id, error_code);
        }
    }

    pub fn stopSending(self: *ClientSession, stream_id: u64, error_code: u32) void {
        defer self.wake();
        if (self.wt_conn) |wtc| {
            wtc.stopSending(stream_id, error_code);
        }
    }

    pub fn drainSession(self: *ClientSession, session_id: u64) !void {
        defer self.wake();
        if (self.wt_conn) |wtc| {
            try wtc.drainSession(session_id);
        }
    }

    pub fn closeConnection(self: *ClientSession) void {
        defer self.wake();
        self.conn.close(0, "");
        if (self.stopping) |flag| flag.* = true;
    }

    pub fn getStats(self: *const ClientSession) connection.Connection.Stats {
        return self.conn.getStats();
    }

    pub fn getSendStreamStats(self: *const ClientSession, stream_id: u64) ?wt.SendStreamStats {
        if (self.wt_conn) |wtc| return wtc.getSendStreamStats(stream_id);
        return null;
    }

    pub fn getRecvStreamStats(self: *const ClientSession, stream_id: u64) ?wt.RecvStreamStats {
        if (self.wt_conn) |wtc| return wtc.getRecvStreamStats(stream_id);
        return null;
    }

    /// Bytes `session_id` can still write before the peer's credit is spent;
    /// see `WebTransportConnection.sendCapacity`. On raw QUIC, the connection's.
    pub fn sendCapacity(self: *const ClientSession, session_id: u64) u64 {
        if (self.wt_conn) |wtc| return wtc.sendCapacity(session_id);
        return self.conn.sendCapacity();
    }

    pub fn streamSendCapacity(self: *const ClientSession, stream_id: u64) ?u64 {
        if (self.wt_conn) |wtc| return wtc.streamSendCapacity(stream_id);
        return self.conn.streamSendCapacity(stream_id);
    }

    /// One `onWritable` once `min_bytes` fit; see
    /// `WebTransportConnection.notifyWritable`.
    pub fn notifyWritable(self: *ClientSession, session_id: u64, stream_id: ?u64, min_bytes: u64) !void {
        const wtc = self.wt_conn orelse return error.NoWtConnection;
        try wtc.notifyWritable(session_id, stream_id, min_bytes);
    }

    pub fn isDatagramSendQueueFull(self: *const ClientSession) bool {
        if (self.wt_conn) |wtc| {
            return wtc.isDatagramSendQueueFull();
        }
        return true;
    }

    pub fn maxDatagramPayloadSize(self: *const ClientSession, session_id: u64) ?usize {
        if (self.wt_conn) |wtc| {
            return wtc.maxDatagramPayloadSize(session_id);
        }
        return null;
    }

    pub fn setIncomingDatagramMaxAge(self: *ClientSession, max_age_ms: ?u64) void {
        self.conn.setIncomingDatagramMaxAge(max_age_ms);
    }

    pub fn setOutgoingDatagramMaxAge(self: *ClientSession, max_age_ms: ?u64) void {
        self.conn.setOutgoingDatagramMaxAge(max_age_ms);
    }

    pub fn setIncomingDatagramHighWaterMark(self: *ClientSession, count: usize) void {
        self.conn.setIncomingDatagramHighWaterMark(count);
    }

    pub fn setOutgoingDatagramHighWaterMark(self: *ClientSession, count: usize) void {
        self.conn.setOutgoingDatagramHighWaterMark(count);
    }

    pub fn sendKeepAlive(self: *ClientSession) void {
        defer self.wake();
        self.conn.sendKeepAlive();
    }
};

pub fn Client(comptime Handler: type) type {
    comptime {
        if (!@hasDecl(Handler, "protocol")) {
            @compileError("Handler must declare 'pub const protocol: event_loop.Protocol'");
        }

        const known = [_][]const u8{
            // Common
            "onConnected",       "onPollComplete",
            // H3
            "onHeaders",         "onData",
            "onFinished",        "onSettings",
            "onGoaway",          "onRequestCancelled",
            // Raw QUIC
            "onStreamData",
            // WebTransport
                 "onSessionReady",
            "onSessionRejected", "onDatagram",
            "onSessionClosed",   "onSessionDraining",
            "onBidiStream",      "onUniStream",
            "onStreamReset",     "onStopSending",
            "onWritable",
        };

        for (@typeInfo(Handler).@"struct".decls) |decl| {
            if (decl.name.len >= 2 and decl.name[0] == 'o' and decl.name[1] == 'n') {
                var found = false;
                for (known) |k| {
                    if (std.mem.eql(u8, decl.name, k)) {
                        found = true;
                        break;
                    }
                }
                if (!found) {
                    @compileError("Handler has unrecognized callback '" ++ decl.name ++
                        "'. Known client callbacks: onConnected, onPollComplete, " ++
                        "onHeaders, onData, onFinished, onSettings, onGoaway, onRequestCancelled, " ++
                        "onStreamData, " ++
                        "onSessionReady, onSessionRejected, onDatagram, onSessionClosed, " ++
                        "onSessionDraining, onBidiStream, onUniStream, onStreamReset, " ++
                        "onStopSending, onWritable");
                }
            }
        }

        if (@hasDecl(Handler, "onStreamData")) {
            const params = @typeInfo(@TypeOf(Handler.onStreamData)).@"fn".params;
            if (params.len != 4 and params.len != 5) {
                @compileError("onStreamData must have 4 params (self, session, stream_id, data) " ++
                    "or 5 params (self, session, stream_id, data, fin)");
            }
        }
    }

    return struct {
        const Self = @This();

        allocator: std.mem.Allocator,
        handler: *Handler,

        // libxev. `own_loop` is unused when the caller supplied one, and the
        // active loop comes from eventLoop() rather than a stored pointer:
        // init() returns by value, so a pointer into self would dangle.
        own_loop: xev.Loop,
        shared_loop: ?*xev.Loop,
        file: xev.File,
        timer: xev.Timer,
        poll_completion: xev.Completion,
        timer_completion: xev.Completion,
        timer_cancel_completion: xev.Completion,
        timer_armed: bool,
        started: bool,
        stopping: bool,

        /// Zero-delay pass for writes made outside our callbacks; the same
        /// scheme as the server's.
        wake_completion: xev.Completion,
        wake_armed: bool,
        in_callback: bool,
        /// Stopped on a shared loop: our completions are cancelled or leaving,
        /// and nothing may re-arm.
        halted: bool,
        cancel_completions: [3]xev.Completion,

        // I/O
        sockfd: posix.socket_t,
        local_addr: posix.sockaddr.storage,
        batch: ecn_socket.SendBatch,
        recv_buf: [MAX_RECV_DATAGRAM]u8,

        /// Shared by every H3Connection on this loop — one 16 KB buffer for
        /// the whole server rather than one per connection. Safe because a
        /// loop decodes one header block at a time and never holds the
        /// resulting slices past the poll that produced them.
        qpack_scratch: [qpack.SCRATCH_SIZE]u8,

        // Single QUIC connection
        conn: *connection.Connection,
        remote_addr: posix.sockaddr.storage,

        // Protocol layers (initialized after handshake). Pointers, so a raw-QUIC
        // client does not carry ~27 KB of H3/WT state it never touches — Client
        // is returned by value from init().
        h3_conn: ?*h3.H3Connection,
        wt_conn: ?*wt.WebTransportConnection,
        protocol_initialized: bool,
        session_id: ?u64,

        // For raw QUIC: track streams whose fin has been delivered via onStreamData(..., fin)
        finished_streams: std.AutoHashMap(u64, void),
        /// See the server's `quic_poll_ids`.
        quic_poll_ids: std.ArrayList(u64),

        // Config retained for protocol init
        server_name: []const u8,
        path: []const u8,
        connect_headers: []const qpack.Header,

        /// draft-13 §5.6 session windows, mirrored from ClientConfig.
        wt_credits: wt_fc.Credits,
        wt_advertise_credits: bool,

        /// The default ALPN list, when we built it rather than the caller.
        owned_alpn: ?[][]const u8,

        /// The trust anchors, when `ClientConfig.ca` asked us to load them.
        owned_ca: ?*Certificate.Bundle,

        pub fn init(alloc: std.mem.Allocator, handler: *Handler, config: ClientConfig) !Self {
            // Build TLS config
            var owned_alpn: ?[][]const u8 = null;
            var owned_ca: ?*Certificate.Bundle = null;
            const tls_config: tls13.TlsConfig = if (config.tls_config) |tc| tc else blk: {
                const alpn = try alloc.alloc([]const u8, 1);
                owned_alpn = alpn;
                alpn[0] = if (config.alpn) |a| a else switch (Handler.protocol) {
                    .h3, .webtransport => "h3",
                    .quic, .h0 => "h3", // default; override via config.alpn for custom protocols
                };

                // On the heap: init() returns by value, so a bundle stored
                // in the client would move out from under this pointer.
                switch (config.ca) {
                    .none, .pinned_hashes => {},
                    .system, .file => {
                        const b = try alloc.create(Certificate.Bundle);
                        errdefer alloc.destroy(b);
                        b.* = switch (config.ca) {
                            .system => try ca_bundle.loadSystem(alloc),
                            .file => |path| try ca_bundle.loadFile(alloc, path),
                            else => unreachable,
                        };
                        owned_ca = b;
                    },
                }

                const pins: ?[]const [32]u8 = switch (config.ca) {
                    .pinned_hashes => |h| h,
                    else => null,
                };

                break :blk .{
                    .cert_chain_der = &.{},
                    .private_key_bytes = &.{},
                    .alpn = alpn,
                    .server_name = config.server_name,
                    // Pinning needs CertificateVerify, so it forces verification
                    // on just as a trust store does.
                    .skip_cert_verify = if (owned_ca != null or pins != null) false else config.skip_cert_verify,
                    .cert_hashes = pins,
                    .ca_bundle = owned_ca,
                };
            };

            // Connection config
            const conn_config: connection.ConnectionConfig = if (config.conn_config) |cc| cc else cc_blk: {
                var cc: connection.ConnectionConfig = .{};
                if (Handler.protocol == .webtransport or Handler.protocol == .quic) {
                    cc.max_datagram_frame_size = config.max_datagram_frame_size;
                }
                break :cc_blk cc;
            };

            // Heap-allocate for pointer stability, then build in place: the
            // by-value connect() would stage all ~137 KB on the stack first.
            errdefer if (owned_alpn) |a| alloc.free(a);
            errdefer if (owned_ca) |b| {
                b.deinit(alloc);
                alloc.destroy(b);
            };

            const conn_ptr = try alloc.create(connection.Connection);
            errdefer alloc.destroy(conn_ptr);
            try connection.connectInto(
                conn_ptr,
                alloc,
                config.server_name,
                conn_config,
                tls_config,
                null,
            );
            errdefer conn_ptr.deinit();

            // Resolve remote address
            const remote_addr = if (config.ipv6) blk: {
                const addr6 = try net.Address.parseIp6(config.address, config.port);
                break :blk connection.sockaddrToStorage(&addr6.any);
            } else blk: {
                const addr4 = try net.Address.parseIp4(config.address, config.port);
                break :blk connection.sockaddrToStorage(&addr4.any);
            };

            // Create non-blocking UDP socket, bind to ephemeral port
            const sockfd, const local_addr = if (config.ipv6) blk: {
                const addr6 = try net.Address.parseIp6("::", 0);
                const fd = try sys.socket(posix.AF.INET6, posix.SOCK.DGRAM | posix.SOCK.NONBLOCK, 0);
                errdefer sys.close(fd);
                const IPV6_V6ONLY: u32 = if (@import("builtin").os.tag == .linux) 26 else 27;
                const zero_val: c_int = 0;
                posix.setsockopt(fd, posix.IPPROTO.IPV6, IPV6_V6ONLY, std.mem.asBytes(&zero_val)) catch {};
                try sys.bind(fd, &addr6.any, addr6.getOsSockLen());
                break :blk .{ fd, addr6 };
            } else blk: {
                const addr4 = try net.Address.parseIp4("0.0.0.0", 0);
                const fd = try sys.socket(posix.AF.INET, posix.SOCK.DGRAM | posix.SOCK.NONBLOCK, 0);
                errdefer sys.close(fd);
                try sys.bind(fd, &addr4.any, addr4.getOsSockLen());
                break :blk .{ fd, addr4 };
            };
            errdefer sys.close(sockfd);
            ecn_socket.enableEcnRecv(sockfd) catch {};

            // Init libxev
            const loop = if (config.loop == null) try xev.Loop.init(.{}) else undefined;
            const file_handle = xev.File.initFd(sockfd);
            const timer_handle = try xev.Timer.init();

            return .{
                .allocator = alloc,
                .handler = handler,
                .own_loop = loop,
                .shared_loop = config.loop,
                .file = file_handle,
                .timer = timer_handle,
                .poll_completion = .{},
                .timer_completion = .{},
                .timer_cancel_completion = .{},
                .timer_armed = false,
                .started = false,
                .stopping = false,
                .wake_completion = .{},
                .wake_armed = false,
                .in_callback = false,
                .halted = false,
                .cancel_completions = .{ .{}, .{}, .{} },
                .sockfd = sockfd,
                .local_addr = connection.sockaddrToStorage(&local_addr.any),
                .batch = ecn_socket.SendBatch.init(sockfd),
                .recv_buf = undefined,
                .qpack_scratch = undefined,
                .conn = conn_ptr,
                .remote_addr = remote_addr,
                .h3_conn = null,
                .wt_conn = null,
                .protocol_initialized = false,
                .session_id = null,
                .finished_streams = std.AutoHashMap(u64, void).init(alloc),
                .quic_poll_ids = .empty,
                .server_name = config.server_name,
                .path = config.path,
                .connect_headers = config.connect_headers,
                .wt_credits = config.wt_credits,
                .wt_advertise_credits = config.wt_advertise_credits,
                .owned_alpn = owned_alpn,
                .owned_ca = owned_ca,
            };
        }

        pub fn deinit(self: *Self) void {
            // See ClientConfig.loop: stop, then run the loop until isStopped().
            if (self.shared_loop != null) std.debug.assert(self.isStopped());
            connection_manager.destroyProtocols(self.allocator, self.wt_conn, self.h3_conn, null);
            self.wt_conn = null;
            self.h3_conn = null;
            if (self.owned_alpn) |a| self.allocator.free(a);
            if (self.owned_ca) |b| {
                b.deinit(self.allocator);
                self.allocator.destroy(b);
            }
            self.finished_streams.deinit();
            self.quic_poll_ids.deinit(self.allocator);
            self.timer.deinit();
            if (self.shared_loop == null) self.own_loop.deinit();
            sys.close(self.sockfd);
            self.conn.deinit();
            self.allocator.destroy(self.conn);
        }

        /// The loop this client runs on, ours or the caller's.
        pub fn eventLoop(self: *Self) *xev.Loop {
            return self.shared_loop orelse &self.own_loop;
        }

        pub fn start(self: *Self) void {
            const loop = self.eventLoop();
            self.file.poll(loop, &self.poll_completion, .read, Self, self, onReadable);
            self.timer.run(loop, &self.timer_completion, 1, Self, self, onTimer);
            self.timer_armed = true;
            self.started = true;
        }

        /// Runs until this client's connection closes. Only for a client that
        /// owns its loop: on a shared one this would drive the other clients
        /// too and return when the last of them finished.
        pub fn run(self: *Self) !void {
            std.debug.assert(self.shared_loop == null);
            self.start();
            try self.own_loop.run(.until_done);
        }

        pub fn tick(self: *Self) !void {
            if (!self.started) self.start();
            try self.eventLoop().run(.no_wait);
        }

        /// A ClientSession for use outside callbacks — writes through it are
        /// sent on the next loop iteration, or at once with `flush()`.
        pub fn clientSession(self: *Self) ClientSession {
            return self.makeSession();
        }

        /// On a shared loop: true once `stop()` has finished and none of this
        /// client's completions remain on the loop, so `deinit()` is safe
        /// while the loop keeps running for everything else.
        pub fn isStopped(self: *Self) bool {
            if (!self.started) return true;
            if (!self.halted) return false;
            const pending = [_]*const xev.Completion{
                &self.poll_completion,
                &self.timer_completion,
                &self.timer_cancel_completion,
                &self.wake_completion,
            };
            for (pending) |c| if (c.state() != .dead) return false;
            for (&self.cancel_completions) |*c| if (c.state() != .dead) return false;
            return true;
        }

        /// The last step of stopping, once the connection has closed. A shared
        /// loop belongs to the caller and keeps running, so instead of stopping
        /// it we take everything of ours off it. `running` is the socket
        /// watch whose callback we are in, which leaves by `.disarm` instead.
        fn finishStop(self: *Self, running: ?*xev.Completion) void {
            if (self.shared_loop == null) {
                self.own_loop.stop();
                return;
            }
            if (self.halted) return;
            self.halted = true;
            const loop = self.eventLoop();
            if (running != &self.poll_completion) {
                cancelCompletion(loop, &self.poll_completion, &self.cancel_completions[0]);
            }
            cancelCompletion(loop, &self.timer_completion, &self.cancel_completions[1]);
            cancelCompletion(loop, &self.wake_completion, &self.cancel_completions[2]);
        }

        fn scheduleWake(self: *Self) void {
            if (self.in_callback) return;
            self.armWake();
        }

        fn armWake(self: *Self) void {
            if (self.halted or self.wake_armed or !self.started) return;
            self.timer.run(self.eventLoop(), &self.wake_completion, 0, Self, self, onWake);
            self.wake_armed = true;
        }

        fn wakeFromSession(ctx: *anyopaque) void {
            const self: *Self = @ptrCast(@alignCast(ctx));
            self.scheduleWake();
        }

        // Unlike a write, nothing in the current pass would pick this up.
        fn repollFromSession(ctx: *anyopaque) void {
            const self: *Self = @ptrCast(@alignCast(ctx));
            self.armWake();
        }

        fn onWake(
            self_opt: ?*Self,
            _: *xev.Loop,
            _: *xev.Completion,
            r: xev.Timer.RunError!void,
        ) xev.CallbackAction {
            const self = self_opt orelse return .disarm;
            self.wake_armed = false;
            _ = r catch return .disarm;
            if (self.halted) return .disarm;
            self.service();
            return .disarm;
        }

        /// One pass: read, dispatch, send. Shared by the timer and wakeup.
        fn service(self: *Self) void {
            self.in_callback = true;
            _ = self.recvAllPackets();
            self.processConnection();
            self.tickAndSend();
            self.in_callback = false;

            if (self.stopping and self.conn.isClosed()) {
                self.finishStop(null);
                return;
            }
            self.rescheduleTimer();
        }

        pub fn flush(self: *Self) void {
            const conn = self.conn;
            if (conn.isClosed()) return;
            const send_addr: *const posix.sockaddr.storage = if (conn.isEstablished())
                conn.peerAddress()
            else
                &self.remote_addr;
            var send_count: usize = 0;
            while (send_count < 1000) : (send_count += 1) {
                const bytes_written = conn.send(self.batch.reserve()) catch break;
                if (bytes_written == 0) break;
                self.batch.commit(
                    bytes_written,
                    @ptrCast(send_addr),
                    connection.sockaddrLen(send_addr),
                    conn.getEcnMark(),
                );
            }
            self.batch.flush();
            self.rescheduleTimer();
        }

        /// Closes the connection and puts the CONNECTION_CLOSE on the wire.
        /// See the note on the server's stop() for why it flushes here.
        ///
        /// On a shared loop, keep running the loop until `isStopped()` before
        /// `deinit()`: the closing period still needs the loop.
        pub fn stop(self: *Self) void {
            self.stopping = true;
            const conn = self.conn;
            if (!conn.isClosed() and conn.state != .closing and conn.state != .draining) {
                conn.close(0, "client shutdown");
            }
            self.flush();
            if (self.shared_loop != null and self.started and conn.isClosed()) self.finishStop(null);
        }

        // ---- Internal callbacks ----

        fn onReadable(
            self_opt: ?*Self,
            _: *xev.Loop,
            c: *xev.Completion,
            _: xev.File,
            r: xev.PollError!xev.PollEvent,
        ) xev.CallbackAction {
            forgetPollResult(c);
            _ = r catch return .rearm;
            const self = self_opt orelse return .disarm;
            if (self.halted) return halted_poll_action;
            self.in_callback = true;

            // Process loop: catch packets arriving during processing
            var iterations: usize = 0;
            while (iterations < 4) : (iterations += 1) {
                const received = self.recvAllPackets();
                self.processConnection();
                self.tickAndSend();

                if (iterations > 0 and !received) break;
            }
            self.in_callback = false;

            if (self.stopping and self.conn.isClosed()) {
                self.finishStop(c);
                return .disarm;
            }

            self.rescheduleTimer();
            return .rearm;
        }

        fn onTimer(
            self_opt: ?*Self,
            _: *xev.Loop,
            _: *xev.Completion,
            r: xev.Timer.RunError!void,
        ) xev.CallbackAction {
            _ = r catch return .disarm;
            const self = self_opt orelse return .disarm;
            self.timer_armed = false;
            if (self.halted) return .disarm;
            self.service();
            return .disarm;
        }

        fn recvAllPackets(self: *Self) bool {
            var received = false;
            while (true) {
                const recv_result = ecn_socket.recvmsgEcn(self.sockfd, &self.recv_buf) catch |err| {
                    if (err == error.WouldBlock) break;
                    break;
                };
                received = true;
                if (recv_result.truncated) {
                    std.log.warn("datagram truncated at {d} bytes — raise MAX_RECV_DATAGRAM", .{recv_result.bytes_read});
                }

                // Update remote addr (may change due to preferred address migration)
                self.remote_addr = recv_result.from_addr;

                self.conn.handleDatagram(self.recv_buf[0..recv_result.bytes_read], .{
                    .to = self.local_addr,
                    .from = recv_result.from_addr,
                    .ecn = recv_result.ecn,
                    .datagram_size = recv_result.bytes_read,
                });

                // Don't send here — tickAndSend will coalesce ACKs with
                // stream data into a single QUIC packet, reducing round-trips.
            }
            // No flush — tickAndSend handles it
            return received;
        }

        fn processConnection(self: *Self) void {
            const conn = self.conn;

            // Initialize protocol layer once handshake completes
            if (conn.isEstablished() and !self.protocol_initialized) {
                self.initProtocol();

                if (@hasDecl(Handler, "onConnected")) {
                    var session = self.makeSession();
                    self.handler.onConnected(&session);
                }
            }

            // Poll events and dispatch to handler
            switch (Handler.protocol) {
                .webtransport => self.pollWtEvents(),
                .h3 => self.pollH3Events(),
                .quic => self.pollQuicEvents(),
                .h0 => {},
            }

            // Drain disposal queues
            if (self.wt_conn) |wtc| {
                wtc.drainDisposalQueue(); // chains to its H3 layer
            } else if (self.h3_conn) |h3c| {
                h3c.drainDisposalQueue();
            }
            for (conn.streams.disposal_queue[0..conn.streams.disposal_count]) |id| {
                _ = self.finished_streams.remove(id);
            }
            conn.streams.drainDisposalQueue();
        }

        fn initProtocol(self: *Self) void {
            switch (Handler.protocol) {
                .webtransport => {
                    const h3c = self.allocator.create(h3.H3Connection) catch return;
                    h3c.* = h3.H3Connection.init(self.allocator, self.conn, false);
                    h3c.qpack_scratch = &self.qpack_scratch;
                    h3c.local_settings = .{
                        .enable_connect_protocol = true,
                        .h3_datagram = true,
                        .enable_webtransport = true,
                        // §5.1 reads a WT_MAX_SESSIONS above one as "this
                        // endpoint supports several sessions, and therefore
                        // flow control". A client receives no sessions, but the
                        // setting is the mutual signal and the number is the
                        // truth: that many session slots exist.
                        .webtransport_max_sessions = wt.MAX_SESSIONS,
                        .wt_max_sessions_v13 = wt.MAX_SESSIONS,
                        .wt_initial_max_data = announced(self.wt_advertise_credits, self.wt_credits.max_data),
                        .wt_initial_max_streams_bidi = announced(self.wt_advertise_credits, self.wt_credits.max_streams_bidi),
                        .wt_initial_max_streams_uni = announced(self.wt_advertise_credits, self.wt_credits.max_streams_uni),
                    };
                    self.h3_conn = h3c;
                    h3c.initConnection() catch return;

                    const wtc = self.allocator.create(wt.WebTransportConnection) catch return;
                    wtc.* = wt.WebTransportConnection.init(self.allocator, h3c, self.conn, false);
                    wtc.grants = self.wt_credits;
                    self.wt_conn = wtc;

                    // Send Extended CONNECT to establish WebTransport session
                    const session_id = wtc.connectWithHeaders(
                        self.server_name,
                        self.path,
                        self.connect_headers,
                    ) catch return;
                    self.session_id = session_id;
                },
                .h3 => {
                    const h3c = self.allocator.create(h3.H3Connection) catch return;
                    h3c.* = h3.H3Connection.init(self.allocator, self.conn, false);
                    h3c.qpack_scratch = &self.qpack_scratch;
                    self.h3_conn = h3c;
                    h3c.initConnection() catch return;
                },
                .quic, .h0 => {},
            }
            self.protocol_initialized = true;
        }

        fn pollWtEvents(self: *Self) void {
            if (self.wt_conn == null) return;
            const wtc = self.wt_conn.?;
            var session = self.makeSession();

            if (@hasDecl(Handler, "onPollComplete")) {
                self.handler.onPollComplete(&session);
            }

            while (true) {
                const event = wtc.poll() catch break;
                if (event == null) break;

                switch (event.?) {
                    .session_ready => |sr| {
                        self.dispatchSessionReady(&session, sr.session_id, sr.headers);
                    },
                    .session_rejected => |rej| {
                        if (@hasDecl(Handler, "onSessionRejected")) {
                            self.handler.onSessionRejected(&session, rej.session_id, rej.status);
                        }
                    },
                    .stream_data => |sd| {
                        self.dispatchStreamData(&session, sd.stream_id, sd.data, sd.fin);
                        if (sd.data.len > 0) self.allocator.free(sd.data);
                    },
                    .datagram => |dg| {
                        if (@hasDecl(Handler, "onDatagram")) {
                            self.handler.onDatagram(&session, dg.session_id, dg.data);
                        }
                    },
                    .session_closed => |cls| {
                        if (@hasDecl(Handler, "onSessionClosed")) {
                            self.handler.onSessionClosed(&session, cls.session_id, cls.error_code, cls.reason);
                        }
                    },
                    .session_draining => |drain| {
                        if (@hasDecl(Handler, "onSessionDraining")) {
                            self.handler.onSessionDraining(&session, drain.session_id);
                        }
                    },
                    .bidi_stream => |bs| {
                        if (@hasDecl(Handler, "onBidiStream")) {
                            self.handler.onBidiStream(&session, bs.session_id, bs.stream_id);
                        }
                    },
                    .uni_stream => |us| {
                        if (@hasDecl(Handler, "onUniStream")) {
                            self.handler.onUniStream(&session, us.session_id, us.stream_id);
                        }
                    },
                    .stream_reset => |rst| {
                        if (@hasDecl(Handler, "onStreamReset")) {
                            self.handler.onStreamReset(&session, rst.session_id, rst.stream_id, rst.error_code);
                        }
                    },
                    .stream_stop_sending => |ss| {
                        if (@hasDecl(Handler, "onStopSending")) {
                            self.handler.onStopSending(&session, ss.session_id, ss.stream_id, ss.error_code);
                        }
                    },
                    .writable => |w| {
                        if (@hasDecl(Handler, "onWritable")) {
                            self.handler.onWritable(&session, w.session_id, w.stream_id);
                        }
                    },
                    // Server-side only.
                    .connect_request, .request, .request_data, .request_end, .request_cancelled => {},
                }
            }
        }

        // The 4-arity form also receives the CONNECT response headers, which
        // is where WebTransport names the negotiated application protocol.
        fn dispatchSessionReady(self: *Self, session: *ClientSession, session_id: u64, headers: []const qpack.Header) void {
            if (!@hasDecl(Handler, "onSessionReady")) return;

            if (comptime @typeInfo(@TypeOf(Handler.onSessionReady)).@"fn".params.len == 4) {
                self.handler.onSessionReady(session, session_id, headers);
            } else {
                self.handler.onSessionReady(session, session_id);
            }
        }

        fn dispatchStreamData(self: *Self, session: *ClientSession, stream_id: u64, data: []const u8, fin: bool) void {
            if (!@hasDecl(Handler, "onStreamData")) return;

            if (comptime @typeInfo(@TypeOf(Handler.onStreamData)).@"fn".params.len == 5) {
                self.handler.onStreamData(session, stream_id, data, fin);
            } else if (data.len > 0) {
                self.handler.onStreamData(session, stream_id, data);
            }
        }

        fn pollH3Events(self: *Self) void {
            if (self.h3_conn == null) return;
            const h3c = self.h3_conn.?;
            var session = self.makeSession();

            if (@hasDecl(Handler, "onPollComplete")) {
                self.handler.onPollComplete(&session);
            }

            while (true) {
                const event = h3c.poll() catch break;
                if (event == null) break;

                switch (event.?) {
                    .headers => |hdr| {
                        if (@hasDecl(Handler, "onHeaders")) {
                            self.handler.onHeaders(&session, hdr.stream_id, hdr.headers);
                        }
                    },
                    .data => |d| {
                        if (@hasDecl(Handler, "onData")) {
                            self.handler.onData(&session, d.stream_id, d.len);
                        } else {
                            // Drain body even if handler doesn't consume it
                            var sink: [4096]u8 = undefined;
                            while (h3c.recvBody(&sink) > 0) {}
                        }
                    },
                    .finished => |stream_id| {
                        if (@hasDecl(Handler, "onFinished")) {
                            self.handler.onFinished(&session, stream_id);
                        }
                    },
                    .settings => |settings| {
                        if (@hasDecl(Handler, "onSettings")) {
                            self.handler.onSettings(&session, settings);
                        }
                    },
                    .goaway => |id| {
                        if (@hasDecl(Handler, "onGoaway")) {
                            self.handler.onGoaway(&session, id);
                        }
                    },
                    .writable => |sid| {
                        if (@hasDecl(Handler, "onWritable")) self.handler.onWritable(&session, sid, sid);
                    },
                    // The server reset our request: H3_REQUEST_REJECTED says
                    // it was never processed and may be retried elsewhere.
                    .request_cancelled => |rc| {
                        if (@hasDecl(Handler, "onRequestCancelled")) {
                            self.handler.onRequestCancelled(&session, rc.stream_id, rc.error_code);
                        }
                    },
                    .connect_request, .shutdown_complete => {},
                }
            }
        }

        fn pollQuicEvents(self: *Self) void {
            const conn = self.conn;
            var session = self.makeSession();

            if (@hasDecl(Handler, "onPollComplete")) {
                self.handler.onPollComplete(&session);
            }

            // Raw QUIC has no session id to report, so 0 stands in.
            if (@hasDecl(Handler, "onDatagram")) {
                while (conn.peekDatagram()) |dg| {
                    self.handler.onDatagram(&session, 0, dg);
                    conn.consumeDatagram();
                }
            }

            // Snapshot ids: see `quic_poll_ids`.
            const ids = &self.quic_poll_ids;
            ids.clearRetainingCapacity();
            ids.ensureTotalCapacity(self.allocator, conn.streams.streams.count() + conn.streams.recv_streams.count()) catch return;
            var key_it = conn.streams.streams.keyIterator();
            while (key_it.next()) |k| ids.appendAssumeCapacity(k.*);
            var recv_key_it = conn.streams.recv_streams.keyIterator();
            while (recv_key_it.next()) |k| ids.appendAssumeCapacity(k.*);

            for (ids.items) |stream_id| {
                while (conn.streams.getRecvStream(stream_id)) |rs| {
                    const data = rs.read() orelse break;
                    const fin = rs.finished;
                    if (fin) self.finished_streams.put(stream_id, {}) catch {};
                    self.dispatchStreamData(&session, stream_id, data, fin);
                    self.allocator.free(data);
                }
                const rs = conn.streams.getRecvStream(stream_id) orelse continue;
                if (rs.finished and !self.finished_streams.contains(stream_id)) {
                    self.finished_streams.put(stream_id, {}) catch {};
                    self.dispatchStreamData(&session, stream_id, &[_]u8{}, true);
                }
                if (rs.finished and !stream_mod.isBidi(stream_id)) conn.streams.releaseRecvStream(stream_id);
            }
        }

        fn tickAndSend(self: *Self) void {
            const conn = self.conn;
            // Loop to fire ALL expired PTO deadlines in one tick
            {
                var timeout_iter: usize = 0;
                while (timeout_iter < 8) : (timeout_iter += 1) {
                    conn.onTimeout() catch |err| {
                        std.log.warn("client onTimeout error: {}", .{err});
                        break;
                    };
                    if (conn.isClosed()) break;
                    const next = conn.nextTimeoutNs();
                    if (next == null) break;
                    const now_ns: i64 = sys.nanoTimestamp();
                    if (next.? > now_ns) break;
                }
            }

            if (conn.isClosed()) {
                // A shared loop is left to our callers' finishStop.
                if (self.stopping and self.shared_loop == null) self.own_loop.stop();
                return;
            }

            // Use remote_addr for pre-handshake, peer address after connection established
            const send_addr: *const posix.sockaddr.storage = if (conn.isEstablished())
                conn.peerAddress()
            else
                &self.remote_addr;

            const max_burst_packets = 1000;
            var send_count: usize = 0;
            while (send_count < max_burst_packets) : (send_count += 1) {
                const bytes_written = conn.send(self.batch.reserve()) catch break;
                if (bytes_written == 0) break;
                self.batch.commit(
                    bytes_written,
                    @ptrCast(send_addr),
                    connection.sockaddrLen(send_addr),
                    conn.getEcnMark(),
                );
            }
            self.batch.flush();
        }

        fn rescheduleTimer(self: *Self) void {
            // Before start() the timer is not ours to arm: start() arms it.
            if (self.halted or !self.started) return;
            const next_ms = self.computeNextTimeoutMs() orelse return;

            // See the server's rescheduleTimer: never re-add the timer while a
            // reset's cancel is still queued against it.
            if (!self.timer_armed and self.timer_cancel_completion.state() != .dead) {
                self.armWake();
                return;
            }

            const loop = self.eventLoop();
            if (self.timer_armed) {
                self.timer.reset(
                    loop,
                    &self.timer_completion,
                    &self.timer_cancel_completion,
                    next_ms,
                    Self,
                    self,
                    onTimer,
                );
            } else {
                self.timer.run(
                    loop,
                    &self.timer_completion,
                    next_ms,
                    Self,
                    self,
                    onTimer,
                );
            }
            self.timer_armed = true;
        }

        fn computeNextTimeoutMs(self: *Self) ?u64 {
            const floor: ?u64 = if (@hasDecl(Handler, "poll_interval_ms")) Handler.poll_interval_ms else null;
            const deadline = self.conn.nextTimeoutNs() orelse return floor;
            const now: i64 = sys.nanoTimestamp();
            const delta_ns = deadline - now;
            if (delta_ns <= 0) return 1;
            const ms: u64 = @intCast(@divFloor(delta_ns, 1_000_000));
            const clamped = if (floor) |f| @min(ms, f) else ms;
            return if (clamped == 0) 1 else clamped;
        }

        fn makeSession(self: *Self) ClientSession {
            return .{
                .conn = self.conn,
                .h3_conn = self.h3_conn,
                .wt_conn = self.wt_conn,
                .stopping = &self.stopping,
                .wake_fn = wakeFromSession,
                .repoll_fn = repollFromSession,
                .wake_ctx = self,
            };
        }
    };
}

// ─── Tests ───────────────────────────────────────────────────────────

const testing = std.testing;
const crypto = std.crypto;
const EcdsaP256Sha256 = crypto.sign.ecdsa.EcdsaP256Sha256;

fn makeTestTlsConfig() tls13.TlsConfig {
    const server_key_pair = EcdsaP256Sha256.KeyPair.generate(std.testing.io);
    const S = struct {
        var secret_key_bytes: [32]u8 = undefined;
        var pub_key_bytes: [65]u8 = undefined;
        var cert_chain: [1][]const u8 = undefined;
        var alpn: [1][]const u8 = undefined;
        var ticket_key: [16]u8 = undefined;
    };
    S.secret_key_bytes = server_key_pair.secret_key.toBytes();
    S.pub_key_bytes = server_key_pair.public_key.toUncompressedSec1();
    S.cert_chain = .{&S.pub_key_bytes};
    S.alpn = .{"h3"};
    sys.randomBytes(&S.ticket_key);
    return .{
        .cert_chain_der = &S.cert_chain,
        .private_key_bytes = &S.secret_key_bytes,
        .alpn = &S.alpn,
        .ticket_key = S.ticket_key,
    };
}

// Handler with compile-time validation
const TestWtHandler = struct {
    pub const protocol: Protocol = .webtransport;
    session_ready_count: u32 = 0,
    stream_data_count: u32 = 0,
    connect_request_count: u32 = 0,

    pub fn onConnectRequest(self: *TestWtHandler, session: *Session, session_id: u64, _: []const u8) void {
        self.connect_request_count += 1;
        session.acceptSession(session_id) catch {};
    }
    pub fn onSessionReady(self: *TestWtHandler, _: *Session, _: u64) void {
        self.session_ready_count += 1;
    }
    pub fn onStreamData(self: *TestWtHandler, session: *Session, stream_id: u64, data: []const u8, fin: bool) void {
        self.stream_data_count += 1;
        // Echo back
        if (data.len > 0) {
            session.sendStreamData(stream_id, data) catch {};
        }
        if (fin) {
            session.closeStream(stream_id);
        }
    }
    pub fn onDatagram(_: *TestWtHandler, _: *Session, _: u64, _: []const u8) void {}
    pub fn onSessionClosed(_: *TestWtHandler, _: *Session, _: u64, _: u32, _: []const u8) void {}
};

const TestH3Handler = struct {
    pub const protocol: Protocol = .h3;
    request_count: u32 = 0,

    pub fn onRequest(self: *TestH3Handler, session: *Session, stream_id: u64, _: []const qpack.Header) void {
        self.request_count += 1;
        const resp = [_]qpack.Header{.{ .name = ":status", .value = "200" }};
        session.sendResponse(stream_id, &resp, "OK") catch {};
    }
};

// Compile-time handler validation: unrecognized callback should fail
// (can't test compile errors in Zig tests, but we verify valid handlers compile)
test "Server: handler validation compiles for valid handlers" {
    // These should compile without error
    _ = Server(TestWtHandler);
    _ = Server(TestH3Handler);
}

test "Server: handlers may take the CONNECT headers" {
    // The extra parameter is how a WebTransport handler sees
    // WT-Available-Protocols; both arities have to keep compiling.
    const WithHeaders = struct {
        pub const protocol: Protocol = .webtransport;
        pub fn onConnectRequest(_: *@This(), _: *Session, _: u64, _: []const u8, _: []const qpack.Header) void {}
        pub fn onSessionReady(_: *@This(), _: *Session, _: u64, _: []const qpack.Header) void {}
        pub fn onStreamData(_: *@This(), _: *Session, _: u64, _: []const u8, _: bool) void {}
    };
    _ = Server(WithHeaders);
}

test "Client: handlers may take the CONNECT response headers" {
    const WithHeaders = struct {
        pub const protocol: Protocol = .webtransport;
        pub fn onSessionReady(_: *@This(), _: *ClientSession, _: u64, _: []const qpack.Header) void {}
        pub fn onStreamData(_: *@This(), _: *ClientSession, _: u64, _: []const u8, _: bool) void {}
    };
    _ = Client(WithHeaders);
}

test "Client: handler validation compiles for valid handlers" {
    // WebTransport client handler
    const TestWtClientHandler = struct {
        pub const protocol: Protocol = .webtransport;
        pub fn onSessionReady(_: *@This(), _: *ClientSession, _: u64) void {}
        pub fn onStreamData(_: *@This(), _: *ClientSession, _: u64, _: []const u8, _: bool) void {}
        pub fn onDatagram(_: *@This(), _: *ClientSession, _: u64, _: []const u8) void {}
    };
    _ = Client(TestWtClientHandler);

    // H3 client handler
    const TestH3ClientHandler = struct {
        pub const protocol: Protocol = .h3;
        pub fn onConnected(_: *@This(), _: *ClientSession) void {}
        pub fn onHeaders(_: *@This(), _: *ClientSession, _: u64, _: []const qpack.Header) void {}
        pub fn onData(_: *@This(), _: *ClientSession, _: u64, _: usize) void {}
        pub fn onFinished(_: *@This(), _: *ClientSession, _: u64) void {}
        pub fn onSettings(_: *@This(), _: *ClientSession, _: h3.H3Connection.Settings) void {}
        pub fn onGoaway(_: *@This(), _: *ClientSession, _: u64) void {}
    };
    _ = Client(TestH3ClientHandler);

    // Raw QUIC client handler
    const TestQuicClientHandler = struct {
        pub const protocol: Protocol = .quic;
        pub fn onConnected(_: *@This(), _: *ClientSession) void {}
        pub fn onStreamData(_: *@This(), _: *ClientSession, _: u64, _: []const u8, _: bool) void {}
    };
    _ = Client(TestQuicClientHandler);
}

test "Server: init and deinit with in-memory TLS config" {
    const tls_config = makeTestTlsConfig();
    var handler = TestH3Handler{};
    var server = try Server(TestH3Handler).init(testing.allocator, &handler, .{
        .port = 0, // ephemeral port
        .tls_config = tls_config,
    });
    defer server.deinit();

    // Server should be in initial state
    try testing.expect(!server.started);
    try testing.expect(!server.stopping);
}

test "Client: init and deinit with in-memory TLS config" {
    var handler = struct {
        pub const protocol: Protocol = .webtransport;
        pub fn onSessionReady(_: *@This(), _: *ClientSession, _: u64) void {}
    }{};

    var client = try Client(@TypeOf(handler)).init(testing.allocator, &handler, .{
        .port = 19876,
        .skip_cert_verify = true,
    });
    defer client.deinit();

    try testing.expect(!client.started);
    try testing.expect(!client.stopping);
    try testing.expect(!client.protocol_initialized);
    try testing.expect(client.session_id == null);
}

test "Server: start, tick, stop lifecycle" {
    const tls_config = makeTestTlsConfig();
    var handler = TestH3Handler{};
    var server = try Server(TestH3Handler).init(testing.allocator, &handler, .{
        .port = 0,
        .tls_config = tls_config,
    });
    defer server.deinit();

    // tick() should auto-start
    try server.tick();
    try testing.expect(server.started);

    // stop() should set stopping flag
    server.stop();
    try testing.expect(server.stopping);

    // tick after stop with no connections should be fine
    try server.tick();
}

test "Client H3: init and deinit" {
    var handler = struct {
        pub const protocol: Protocol = .h3;
        pub fn onHeaders(_: *@This(), _: *ClientSession, _: u64, _: []const qpack.Header) void {}
    }{};

    var client = try Client(@TypeOf(handler)).init(testing.allocator, &handler, .{
        .port = 19877,
        .skip_cert_verify = true,
    });
    defer client.deinit();

    try testing.expect(!client.started);
    try testing.expect(!client.protocol_initialized);
    try testing.expect(client.h3_conn == null);
}

test "Client QUIC: init and deinit" {
    var handler = struct {
        pub const protocol: Protocol = .quic;
        pub fn onStreamData(_: *@This(), _: *ClientSession, _: u64, _: []const u8, _: bool) void {}
    }{};

    var client = try Client(@TypeOf(handler)).init(testing.allocator, &handler, .{
        .port = 19878,
        .skip_cert_verify = true,
    });
    defer client.deinit();

    try testing.expect(!client.started);
    try testing.expect(!client.protocol_initialized);
    try testing.expect(client.h3_conn == null);
}

test "Client H3: start, tick, stop lifecycle" {
    var handler = struct {
        pub const protocol: Protocol = .h3;
        pub fn onHeaders(_: *@This(), _: *ClientSession, _: u64, _: []const qpack.Header) void {}
    }{};

    var client = try Client(@TypeOf(handler)).init(testing.allocator, &handler, .{
        .port = 19879,
        .skip_cert_verify = true,
    });
    defer client.deinit();

    try client.tick();
    try testing.expect(client.started);

    client.stop();
    try testing.expect(client.stopping);
}

test "Client QUIC: start, tick, stop lifecycle" {
    var handler = struct {
        pub const protocol: Protocol = .quic;
        pub fn onStreamData(_: *@This(), _: *ClientSession, _: u64, _: []const u8, _: bool) void {}
    }{};

    var client = try Client(@TypeOf(handler)).init(testing.allocator, &handler, .{
        .port = 19880,
        .skip_cert_verify = true,
    });
    defer client.deinit();

    try client.tick();
    try testing.expect(client.started);

    client.stop();
    try testing.expect(client.stopping);
}

test "stop() leaves nothing queued for the peer" {
    // The CONNECTION_CLOSE has to be on the wire when stop() returns. If it
    // is merely queued, a caller that exits instead of running the loop
    // leaves the peer holding the connection until its idle timeout, and
    // the symptom shows up on some unrelated connection much later.
    var handler = struct {
        pub const protocol: Protocol = .quic;
        pub fn onStreamData(_: *@This(), _: *ClientSession, _: u64, _: []const u8, _: bool) void {}
    }{};

    var client = try Client(@TypeOf(handler)).init(testing.allocator, &handler, .{
        .port = 19881,
        .skip_cert_verify = true,
    });
    defer client.deinit();

    try client.tick();
    client.stop();

    try testing.expect(client.conn.state == .closing or client.conn.isClosed());

    // Nothing left to send means the close was drained, not just queued.
    var buf: [2048]u8 = undefined;
    try testing.expectEqual(@as(usize, 0), client.conn.send(&buf) catch 0);
}

test "stop() turns away a client that arrives while it finishes" {
    var loop = try xev.Loop.init(.{});
    defer loop.deinit();
    var sh = HelloServer{};
    var server = try Server(HelloServer).init(testing.allocator, &sh, .{
        .port = 29436,
        .tls_config = makeTestTlsConfig(),
        .loop = &loop,
    });
    server.start();
    var ha = CheckingClient{};
    var a = try Client(CheckingClient).init(testing.allocator, &ha, .{ .port = 29436, .skip_cert_verify = true, .loop = &loop });
    a.start();
    try runUntil(&loop, &ha, CheckingClient.done, 10_000);

    // a's connection is still closing when b arrives. Served, b would hold
    // stop() open for as long as it stayed.
    server.stop();
    var hb = CheckingClient{};
    var b = try Client(CheckingClient).init(testing.allocator, &hb, .{ .port = 29436, .skip_cert_verify = true, .loop = &loop });
    b.start();
    const server_stopped = runUntil(&loop, &server, Server(HelloServer).isStopped, 5000);

    a.stop();
    b.stop();
    const All = struct {
        s: *Server(HelloServer),
        a: *Client(CheckingClient),
        b: *Client(CheckingClient),
        fn stopped(self: *const @This()) bool {
            return self.s.isStopped() and self.a.isStopped() and self.b.isStopped();
        }
    };
    try runUntil(&loop, &All{ .s = &server, .a = &a, .b = &b }, All.stopped, 5000);
    a.deinit();
    b.deinit();
    server.deinit();
    try server_stopped;
    try testing.expectEqual(@as(usize, 0), hb.received);
}

test "Client: closeConnection from a handler arms the run loop's exit" {
    var handler = struct {
        pub const protocol: Protocol = .quic;
        pub fn onStreamData(_: *@This(), _: *ClientSession, _: u64, _: []const u8, _: bool) void {}
    }{};

    var client = try Client(@TypeOf(handler)).init(testing.allocator, &handler, .{
        .port = 19881,
        .skip_cert_verify = true,
    });
    defer client.deinit();

    try client.tick();
    try testing.expect(!client.stopping);

    // run() only leaves once `stopping` is set, so a handler that closes the
    // connection without it leaves the client spinning after the exchange.
    var session = client.makeSession();
    session.closeConnection();
    try testing.expect(client.stopping);
}

test "two clients share one loop" {
    // Driving two connections used to mean two loops and a caller spinning
    // tick() over both. On a shared loop one run() drives them, and one
    // stopping must not take the other down with it.
    const H = struct {
        pub const protocol: Protocol = .quic;
        pub fn onStreamData(_: *@This(), _: *ClientSession, _: u64, _: []const u8, _: bool) void {}
    };
    var handler = H{};

    var loop = try xev.Loop.init(.{});
    defer loop.deinit();

    var a = try Client(H).init(testing.allocator, &handler, .{
        .port = 19882,
        .skip_cert_verify = true,
        .loop = &loop,
    });
    defer a.deinit();

    var b = try Client(H).init(testing.allocator, &handler, .{
        .port = 19883,
        .skip_cert_verify = true,
        .loop = &loop,
    });
    defer b.deinit();

    try testing.expectEqual(a.eventLoop(), b.eventLoop());

    a.start();
    b.start();
    try loop.run(.no_wait);

    a.stop();
    try testing.expect(a.conn.state == .closing or a.conn.isClosed());

    // b still has work on a loop a did not stop.
    try loop.run(.no_wait);
    try testing.expect(!b.conn.isClosed());

    // The teardown order the config documents: drain each client off the
    // loop before the loop goes away.
    b.stop();
    const Both = struct {
        a: *Client(H),
        b: *Client(H),
        fn done(x: *const @This()) bool {
            return x.a.isStopped() and x.b.isStopped();
        }
    };
    try runUntil(&loop, &Both{ .a = &a, .b = &b }, Both.done, 10_000);
}

// ─── End-to-end: Server and Client on one caller-owned loop ──────────

/// Runs `loop` until `done(ctx)` holds, failing after `timeout_ms`. Never
/// blocks in the loop: a stopped client leaves its socket watch behind, and
/// that alone would keep a blocking run waiting forever.
fn runUntil(loop: *xev.Loop, ctx: anytype, comptime done: fn (@TypeOf(ctx)) bool, timeout_ms: i64) !void {
    const deadline = sys.nanoTimestamp() + timeout_ms * std.time.ns_per_ms;
    while (!done(ctx)) {
        if (sys.nanoTimestamp() > deadline) return error.Timeout;
        try loop.run(.no_wait);
        sys.sleepNs(50 * std.time.ns_per_us);
    }
}

/// A server and a client joined to one loop the test owns.
fn E2e(comptime ServerHandler: type, comptime ClientHandler: type) type {
    return struct {
        const Self = @This();

        loop: xev.Loop,
        server: Server(ServerHandler),
        client: Client(ClientHandler),

        /// In place: both sides keep pointers into `self` once started.
        fn init(self: *Self, port: u16, sh: *ServerHandler, ch: *ClientHandler) !void {
            return self.initWith(port, sh, ch, null, null);
        }

        fn initWith(
            self: *Self,
            port: u16,
            sh: *ServerHandler,
            ch: *ClientHandler,
            server_conn: ?connection.ConnectionConfig,
            client_conn: ?connection.ConnectionConfig,
        ) !void {
            self.loop = try xev.Loop.init(.{});
            errdefer self.loop.deinit();
            self.server = try Server(ServerHandler).init(testing.allocator, sh, .{
                .port = port,
                .tls_config = makeTestTlsConfig(),
                .conn_config = server_conn,
                .loop = &self.loop,
            });
            errdefer self.server.deinit();
            self.client = try Client(ClientHandler).init(testing.allocator, ch, .{
                .port = port,
                .skip_cert_verify = true,
                .conn_config = client_conn,
                .loop = &self.loop,
            });
            self.server.start();
            self.client.start();
        }

        /// The teardown a shared loop needs: close both ends, then run the
        /// loop until neither has anything left on it.
        fn deinit(self: *Self) void {
            self.client.stop();
            self.server.stop();
            runUntil(&self.loop, self, bothStopped, 5000) catch @panic("did not stop");
            // Stopping them must not have stopped the caller's loop.
            std.debug.assert(!self.loop.stopped());
            self.client.deinit();
            self.server.deinit();
            self.loop.deinit();
        }

        fn bothStopped(self: *Self) bool {
            return self.server.isStopped() and self.client.isStopped();
        }
    };
}

const E2E_CHUNK: usize = 16 * 1024;
const E2E_BODY: usize = 1024 * 1024;

fn e2eBodyByte(offset: usize) u8 {
    return @truncate(offset *% 31 +% (offset >> 12));
}

const get_request = [_]qpack.Header{
    .{ .name = ":method", .value = "GET" },
    .{ .name = ":scheme", .value = "https" },
    .{ .name = ":authority", .value = "localhost" },
    .{ .name = ":path", .value = "/" },
};

/// Answers with headers at once, then streams the body from a timer on the
/// shared loop — outside any server callback — paced by `onWritable`.
const StreamingServer = struct {
    pub const protocol: Protocol = .h3;

    loop: *xev.Loop,
    pump_timer: xev.Timer = .{},
    pump_c: xev.Completion = .{},
    pump_armed: bool = false,
    session: ?Session = null,
    stream_id: u64 = 0,
    sent: usize = 0,
    finished: bool = false,
    writable_count: u32 = 0,
    wrong_writable: u32 = 0,
    closed_count: u32 = 0,
    closed_id_matched: bool = false,

    pub fn onRequest(self: *@This(), session: *Session, stream_id: u64, _: []const qpack.Header) void {
        session.sendResponseHeaders(stream_id, &.{.{ .name = ":status", .value = "200" }}) catch unreachable;
        self.session = session.*;
        self.stream_id = stream_id;
        self.armPump();
    }

    pub fn onWritable(self: *@This(), _: *Session, session_id: u64, stream_id: ?u64) void {
        if (session_id != self.stream_id or stream_id != self.stream_id) self.wrong_writable += 1;
        self.writable_count += 1;
        self.armPump();
    }

    pub fn onConnectionClosed(self: *@This(), session: *Session) void {
        self.closed_count += 1;
        if (self.session) |s| self.closed_id_matched = s.id() == session.id();
        self.session = null; // the entry is freed after this returns
    }

    fn hasRequest(self: *@This()) bool {
        return self.session != null and self.sent > 0;
    }

    fn armPump(self: *@This()) void {
        if (self.pump_armed) return;
        self.pump_armed = true;
        self.pump_timer.run(self.loop, &self.pump_c, 0, @This(), self, onPump);
    }

    fn onPump(self_opt: ?*@This(), _: *xev.Loop, _: *xev.Completion, r: xev.Timer.RunError!void) xev.CallbackAction {
        const self = self_opt.?;
        self.pump_armed = false;
        _ = r catch return .disarm;
        self.pump();
        return .disarm;
    }

    fn pump(self: *@This()) void {
        const s = &(self.session orelse return);
        const want = E2E_CHUNK + 16; // chunk plus its DATA frame header
        var chunk: [E2E_CHUNK]u8 = undefined;
        while (self.sent < E2E_BODY) {
            const cap = s.streamSendCapacity(self.stream_id) orelse return;
            const buffered = s.streamBufferedBytes(self.stream_id) orelse return;
            if (cap < want or buffered >= want) {
                s.notifyWritable(0, self.stream_id, want) catch unreachable;
                return;
            }
            const n = @min(E2E_CHUNK, E2E_BODY - self.sent);
            for (chunk[0..n], self.sent..) |*b, off| b.* = e2eBodyByte(off);
            s.sendResponseData(self.stream_id, chunk[0..n]) catch unreachable;
            self.sent += n;
        }
        s.finishResponse(self.stream_id, null) catch unreachable;
        self.finished = true;
    }
};

/// Sends one request on connect and checks what comes back.
const CheckingClient = struct {
    pub const protocol: Protocol = .h3;

    request: []const qpack.Header = &get_request,
    request_body: ?[]const u8 = null,
    /// Checked against e2eBodyByte when set, else collected into `body`.
    patterned: bool = false,
    /// Cancel the request as soon as the response headers arrive.
    cancel_on_headers: bool = false,

    stream_id: ?u64 = null,
    status: [3]u8 = .{ 0, 0, 0 },
    received: usize = 0,
    mismatches: usize = 0,
    body: [64]u8 = undefined,
    finished: bool = false,

    pub fn onConnected(self: *@This(), session: *ClientSession) void {
        self.stream_id = session.sendRequest(self.request, self.request_body) catch null;
    }

    pub fn onHeaders(self: *@This(), session: *ClientSession, stream_id: u64, headers: []const qpack.Header) void {
        for (headers) |h| {
            if (std.mem.eql(u8, h.name, ":status") and h.value.len == 3) @memcpy(&self.status, h.value);
        }
        if (self.cancel_on_headers) {
            session.h3_conn.?.cancelRequest(stream_id, @intFromEnum(H3Error.request_cancelled));
        }
    }

    pub fn onData(self: *@This(), session: *ClientSession, _: u64, _: usize) void {
        var buf: [4096]u8 = undefined;
        while (true) {
            const n = session.recvBody(&buf);
            if (n == 0) break;
            for (buf[0..n], self.received..) |b, off| {
                if (self.patterned) {
                    if (b != e2eBodyByte(off)) self.mismatches += 1;
                } else if (off < self.body.len) {
                    self.body[off] = b;
                }
            }
            self.received += n;
        }
    }

    pub fn onFinished(self: *@This(), _: *ClientSession, _: u64) void {
        self.finished = true;
    }

    fn done(self: *@This()) bool {
        return self.finished;
    }
};

test "e2e: a server on a shared loop streams 1 MiB under backpressure" {
    var client_handler = CheckingClient{ .patterned = true };
    var server_handler = StreamingServer{ .loop = undefined };
    var e2e: E2e(StreamingServer, CheckingClient) = undefined;
    try e2e.init(29411, &server_handler, &client_handler);
    server_handler.loop = &e2e.loop;

    defer e2e.deinit();

    try runUntil(&e2e.loop, &client_handler, CheckingClient.done, 20_000);

    try testing.expectEqualStrings("200", &client_handler.status);
    try testing.expectEqual(E2E_BODY, client_handler.received);
    try testing.expectEqual(@as(usize, 0), client_handler.mismatches);
    try testing.expect(server_handler.finished);
    // It had to wait: the body is far bigger than one flight.
    try testing.expect(server_handler.writable_count > 0);
    try testing.expectEqual(@as(u32, 0), server_handler.wrong_writable);
}

test "e2e: onConnectionClosed fires once, before the entry goes" {
    var client_handler = CheckingClient{};
    var server_handler = StreamingServer{ .loop = undefined };
    var e2e: E2e(StreamingServer, CheckingClient) = undefined;
    try e2e.init(29416, &server_handler, &client_handler);
    server_handler.loop = &e2e.loop;
    {
        errdefer e2e.deinit();
        try runUntil(&e2e.loop, &server_handler, StreamingServer.hasRequest, 10_000);
        try testing.expect(server_handler.session.?.id() != 0);
    }
    // Torn down mid-response: the close still reaches the handler, once.
    e2e.deinit();
    try testing.expectEqual(@as(u32, 1), server_handler.closed_count);
    try testing.expect(server_handler.closed_id_matched);
}

/// Echoes how much request body arrived, once the request is complete.
const UploadServer = struct {
    pub const protocol: Protocol = .h3;

    body_bytes: usize = 0,
    body_ok: bool = true,
    ended: u32 = 0,
    reply: [32]u8 = undefined,

    pub fn onRequest(_: *@This(), _: *Session, _: u64, _: []const qpack.Header) void {}

    pub fn onData(self: *@This(), _: *Session, _: u64, data: []const u8) void {
        for (data, self.body_bytes..) |b, off| {
            if (b != e2eBodyByte(off)) self.body_ok = false;
        }
        self.body_bytes += data.len;
    }

    pub fn onRequestEnd(self: *@This(), session: *Session, stream_id: u64) void {
        self.ended += 1;
        const text = std.fmt.bufPrint(&self.reply, "{d}", .{self.body_bytes}) catch unreachable;
        session.sendResponse(stream_id, &.{.{ .name = ":status", .value = "200" }}, text) catch unreachable;
    }
};

test "e2e: onRequestEnd follows the whole POST body" {
    const body = try testing.allocator.alloc(u8, 100_000);
    defer testing.allocator.free(body);
    for (body, 0..) |*b, i| b.* = e2eBodyByte(i);

    var client_handler = CheckingClient{
        .request = &.{
            .{ .name = ":method", .value = "POST" },
            .{ .name = ":scheme", .value = "https" },
            .{ .name = ":authority", .value = "localhost" },
            .{ .name = ":path", .value = "/upload" },
        },
        .request_body = body,
    };
    var server_handler = UploadServer{};
    var e2e: E2e(UploadServer, CheckingClient) = undefined;
    try e2e.init(29412, &server_handler, &client_handler);
    defer e2e.deinit();

    try runUntil(&e2e.loop, &client_handler, CheckingClient.done, 10_000);
    try testing.expectEqual(@as(u32, 1), server_handler.ended);
    try testing.expect(server_handler.body_ok);
    try testing.expectEqualStrings("100000", client_handler.body[0..client_handler.received]);
}

/// Sends headers and then nothing, leaving the client to give up.
const StallingServer = struct {
    pub const protocol: Protocol = .h3;

    cancelled_stream: ?u64 = null,
    cancel_code: u64 = 0,

    pub fn onRequest(_: *@This(), session: *Session, stream_id: u64, _: []const qpack.Header) void {
        session.sendResponseHeaders(stream_id, &.{.{ .name = ":status", .value = "200" }}) catch unreachable;
    }

    pub fn onRequestCancelled(self: *@This(), _: *Session, stream_id: u64, error_code: u64) void {
        self.cancelled_stream = stream_id;
        self.cancel_code = error_code;
    }

    fn done(self: *@This()) bool {
        return self.cancelled_stream != null;
    }
};

test "e2e: a client abandoning a response reaches onRequestCancelled" {
    var client_handler = CheckingClient{ .cancel_on_headers = true };
    var server_handler = StallingServer{};
    var e2e: E2e(StallingServer, CheckingClient) = undefined;
    try e2e.init(29413, &server_handler, &client_handler);
    defer e2e.deinit();

    try runUntil(&e2e.loop, &server_handler, StallingServer.done, 10_000);
    try testing.expectEqual(client_handler.stream_id, server_handler.cancelled_stream);
    try testing.expectEqual(@as(u64, @intFromEnum(H3Error.request_cancelled)), server_handler.cancel_code);
}

/// A WebTransport listener that also serves plain requests.
const MixedServer = struct {
    pub const protocol: Protocol = .webtransport;

    requests: u32 = 0,
    connects: u32 = 0,

    pub fn onConnectRequest(self: *@This(), session: *Session, session_id: u64, _: []const u8) void {
        self.connects += 1;
        session.acceptSession(session_id) catch {};
    }

    pub fn onRequest(self: *@This(), session: *Session, stream_id: u64, headers: []const qpack.Header) void {
        self.requests += 1;
        for (headers) |h| {
            if (std.mem.eql(u8, h.name, ":method") and !std.mem.eql(u8, h.value, "GET")) return;
        }
        session.sendResponseHeaders(stream_id, &.{.{ .name = ":status", .value = "200" }}) catch unreachable;
    }

    pub fn onRequestEnd(_: *@This(), session: *Session, stream_id: u64) void {
        session.sendResponseData(stream_id, "hello ") catch unreachable;
        session.sendResponseData(stream_id, "world") catch unreachable;
        session.finishResponse(stream_id, null) catch unreachable;
    }
};

test "e2e: a WebTransport listener serves a plain GET" {
    var client_handler = CheckingClient{};
    var server_handler = MixedServer{};
    var e2e: E2e(MixedServer, CheckingClient) = undefined;
    try e2e.init(29414, &server_handler, &client_handler);
    defer e2e.deinit();

    try runUntil(&e2e.loop, &client_handler, CheckingClient.done, 10_000);
    try testing.expectEqual(@as(u32, 1), server_handler.requests);
    try testing.expectEqual(@as(u32, 0), server_handler.connects);
    try testing.expectEqualStrings("200", &client_handler.status);
    try testing.expectEqualStrings("hello world", client_handler.body[0..client_handler.received]);
}

test "e2e: an RSA certificate, picked by SNI next to an EC one" {
    const test_certs = @import("tls/test_certs.zig");
    var ec_certs: test_certs.TestCerts = undefined;
    try ec_certs.load();
    var rsa_cert: test_certs.RsaCert = undefined;
    try rsa_cert.load(false);
    const entries = [_]tls13.CertEntry{
        ec_certs.entries[0],
        .{ .server_names = &.{"rsa.test"}, .cert = rsa_cert.cert },
    };
    // The pin stands in for the chain; CertificateVerify is still checked.
    var pin: [32]u8 = undefined;
    crypto.hash.sha2.Sha256.hash(rsa_cert.chain[0], &pin, .{});
    const pins = [_][32]u8{pin};

    var loop = try xev.Loop.init(.{});
    defer loop.deinit();
    const S = Server(MixedServer);
    const C = Client(CheckingClient);
    var sh = MixedServer{};
    var server = try S.init(testing.allocator, &sh, .{
        .port = 29437,
        .tls_config = .{ .cert_chain_der = &.{}, .private_key_bytes = &.{}, .certs = &entries, .alpn = &.{"h3"} },
        .loop = &loop,
    });
    server.start();
    var ch = CheckingClient{};
    var client = try C.init(testing.allocator, &ch, .{
        .port = 29437,
        .server_name = "rsa.test",
        .ca = .{ .pinned_hashes = &pins },
        .loop = &loop,
    });
    client.start();
    try runUntil(&loop, &ch, finishedOne, 10_000);
    try testing.expectEqualStrings("200", &ch.status);
    try testing.expectEqualStrings("hello world", ch.body[0..ch.received]);

    client.stop();
    server.stop();
    const Both = struct {
        s: *S,
        c: *C,
        fn done(x: *const @This()) bool {
            return x.s.isStopped() and x.c.isStopped();
        }
    };
    try runUntil(&loop, &Both{ .s = &server, .c = &client }, Both.done, 5000);
    client.deinit();
    server.deinit();
}

test "Server: socket options, ALPN and connection cap come from Config" {
    const alpn = [_][]const u8{ "h3", "hq-interop" };
    var handler = TestH3Handler{};
    const S = Server(TestH3Handler);

    // Two sockets on one port is exactly what SO_REUSEPORT allows.
    var a = try S.init(testing.allocator, &handler, .{
        .port = 29415,
        .reuse_port = true,
        // Under Linux's default rmem_max, which clamps anything larger.
        .recv_buffer_size = 150_000,
        .send_buffer_size = 150_000,
        .max_connections = 1000,
        .alpn = &alpn,
    });
    defer a.deinit();
    var b = try S.init(testing.allocator, &handler, .{ .port = 29415, .reuse_port = true });
    defer b.deinit();

    try testing.expectEqual(@as(usize, 1000), a.conn_mgr.max_connections);
    try testing.expectEqual(@as(usize, 2), a.owned_tls.?.alpn.len);
    try testing.expectEqualStrings("hq-interop", a.owned_tls.?.alpn[1]);
    try testing.expectEqualStrings("h3", b.owned_tls.?.alpn[0]);

    // Linux reports double what was asked; b shows the OS default.
    const rcvbuf = try getRcvBuf(a.sockfd);
    try testing.expect(rcvbuf >= 150_000);
    try testing.expect(rcvbuf != try getRcvBuf(b.sockfd));
}

test "Server: serves on a socket it is given" {
    var handler = TestH3Handler{};
    const S = Server(TestH3Handler);
    var a = try S.init(testing.allocator, &handler, .{ .port = 29416 });
    // A dup of a's socket, as a replacement server after a restart would get.
    const fd = std.c.fcntl(a.sockfd, posix.F.DUPFD_CLOEXEC, @as(c_int, 0));
    try testing.expect(fd >= 0);
    a.deinit();
    var b = try S.init(testing.allocator, &handler, .{ .socket = fd, .port = 1 });
    defer b.deinit();
    try testing.expectEqual(fd, b.sockfd);
    const local: *const posix.sockaddr.in = @ptrCast(@alignCast(&b.local_addr));
    try testing.expectEqual(@as(u16, 29416), std.mem.bigToNative(u16, local.port));
}

fn getRcvBuf(fd: posix.socket_t) !c_int {
    var v: c_int = 0;
    var len: posix.socklen_t = @sizeOf(c_int);
    try testing.expectEqual(@as(c_int, 0), std.c.getsockopt(fd, posix.SOL.SOCKET, posix.SO.RCVBUF, @ptrCast(&v), &len));
    return v;
}

/// Answers every GET with a short body.
const HelloServer = struct {
    pub const protocol: Protocol = .h3;

    pub fn onRequest(_: *@This(), session: *Session, stream_id: u64, _: []const qpack.Header) void {
        session.sendResponse(stream_id, &.{.{ .name = ":status", .value = "200" }}, "hello") catch unreachable;
    }
};

fn allFinished(clients: []CheckingClient) bool {
    for (clients) |*c| if (!c.finished) return false;
    return true;
}

test "e2e: one client on a shared loop stops and goes while the others carry on" {
    const C = Client(CheckingClient);
    var loop = try xev.Loop.init(.{});
    defer loop.deinit();

    var server_handler = HelloServer{};
    var server = try Server(HelloServer).init(testing.allocator, &server_handler, .{
        .port = 29417,
        .tls_config = makeTestTlsConfig(),
        .loop = &loop,
    });
    defer server.deinit();
    server.start();

    var handlers = [_]CheckingClient{ .{}, .{}, .{} };
    var clients: [3]C = undefined;
    for (&clients, &handlers, 0..) |*c, *h, i| {
        c.* = try C.init(testing.allocator, h, .{ .port = 29417, .skip_cert_verify = true, .loop = &loop });
        errdefer for (clients[0..i]) |*prev| prev.deinit();
        c.start();
    }
    var live: []C = &clients;
    defer for (live) |*c| c.deinit();

    const all: []CheckingClient = &handlers;
    try runUntil(&loop, all, allFinished, 10_000);

    // The first client leaves; the loop keeps running for everyone else.
    clients[0].stop();
    try runUntil(&loop, &clients[0], C.isStopped, 5000);
    clients[0].deinit();
    live = clients[1..];
    try testing.expect(!loop.stopped());

    // A second request from each survivor, written outside any callback:
    // the client's own wakeup has to get it onto the wire.
    for (live, handlers[1..]) |*c, *h| {
        h.finished = false;
        h.received = 0;
        var cs = c.clientSession();
        h.stream_id = try cs.sendRequest(&get_request, null);
    }
    try runUntil(&loop, all[1..], allFinished, 10_000);
    for (handlers[1..]) |*h| try testing.expectEqualStrings("hello", h.body[0..h.received]);

    for (live) |*c| c.stop();
    server.stop();
    const Everything = struct {
        server: *Server(HelloServer),
        clients: []C,
        fn stopped(self: *const @This()) bool {
            if (!self.server.isStopped()) return false;
            for (self.clients) |*c| if (!c.isStopped()) return false;
            return true;
        }
    };
    try runUntil(&loop, &Everything{ .server = &server, .clients = live }, Everything.stopped, 5000);
}

const DRIP_CHUNK: usize = 1000;
const DRIP_CHUNKS: usize = 40;
const DRIP_INTERVAL_MS: u64 = 20;

/// Serves the first request slowly — one chunk per timer tick, from outside
/// any server callback — so a drain begins with it still in flight.
const DrippingServer = struct {
    pub const protocol: Protocol = .h3;

    loop: *xev.Loop,
    timer: xev.Timer = .{},
    timer_c: xev.Completion = .{},
    session: ?Session = null,
    stream_id: u64 = 0,
    sent: usize = 0,
    requests: u32 = 0,

    pub fn onRequest(self: *@This(), session: *Session, stream_id: u64, _: []const qpack.Header) void {
        self.requests += 1;
        if (self.session != null) return;
        session.sendResponseHeaders(stream_id, &.{.{ .name = ":status", .value = "200" }}) catch unreachable;
        self.session = session.*;
        self.stream_id = stream_id;
        self.timer.run(self.loop, &self.timer_c, DRIP_INTERVAL_MS, @This(), self, onTick);
    }

    pub fn onConnectionClosed(self: *@This(), _: *Session) void {
        self.session = null;
    }

    fn onTick(self_opt: ?*@This(), loop: *xev.Loop, c: *xev.Completion, r: xev.Timer.RunError!void) xev.CallbackAction {
        const self = self_opt.?;
        _ = r catch return .disarm;
        const s = &(self.session orelse return .disarm);
        var chunk: [DRIP_CHUNK]u8 = undefined;
        for (&chunk, self.sent..) |*b, off| b.* = e2eBodyByte(off);
        s.sendResponseData(self.stream_id, &chunk) catch return .disarm;
        self.sent += chunk.len;
        if (self.sent == DRIP_CHUNK * DRIP_CHUNKS) {
            s.finishResponse(self.stream_id, null) catch {};
            return .disarm;
        }
        self.timer.run(loop, c, DRIP_INTERVAL_MS, @This(), self, onTick);
        return .disarm;
    }

    fn inFlight(self: *@This()) bool {
        return self.sent > 0;
    }
};

/// Reads the dripped response and, on the final GOAWAY, tries a second
/// request twice: once as a client that honours GOAWAY, once as one that
/// does not.
const DrainedClient = struct {
    pub const protocol: Protocol = .h3;

    stream_id: ?u64 = null,
    received: usize = 0,
    mismatches: usize = 0,
    finished: bool = false,
    goaway_id: ?u64 = null,
    refused_locally: bool = false,
    late_stream: ?u64 = null,
    late_reset_code: ?u64 = null,

    pub fn onConnected(self: *@This(), session: *ClientSession) void {
        self.stream_id = session.sendRequest(&get_request, null) catch null;
    }

    pub fn onHeaders(_: *@This(), _: *ClientSession, _: u64, _: []const qpack.Header) void {}

    pub fn onData(self: *@This(), session: *ClientSession, _: u64, _: usize) void {
        var buf: [4096]u8 = undefined;
        while (true) {
            const n = session.recvBody(&buf);
            if (n == 0) break;
            for (buf[0..n], self.received..) |b, off| {
                if (b != e2eBodyByte(off)) self.mismatches += 1;
            }
            self.received += n;
        }
    }

    pub fn onFinished(self: *@This(), _: *ClientSession, stream_id: u64) void {
        if (stream_id == self.stream_id) self.finished = true;
    }

    pub fn onGoaway(self: *@This(), session: *ClientSession, id: u64) void {
        if (id > 1 << 40) return; // the first GOAWAY names no limit
        self.goaway_id = id;
        if (session.sendRequest(&get_request, null)) |_| {} else |_| self.refused_locally = true;
        session.h3_conn.?.peer_goaway_id = null;
        self.late_stream = session.sendRequest(&get_request, null) catch null;
    }

    pub fn onRequestCancelled(self: *@This(), _: *ClientSession, stream_id: u64, error_code: u64) void {
        if (stream_id == self.late_stream) self.late_reset_code = error_code;
    }
};

const DrainE2e = E2e(DrippingServer, DrainedClient);

fn drainSettled(e2e: *DrainE2e) bool {
    return e2e.client.handler.finished and e2e.client.handler.late_reset_code != null and e2e.server.isDrained();
}

test "e2e: drain() lets an in-flight response finish and turns new requests away" {
    var client_handler = DrainedClient{};
    var server_handler = DrippingServer{ .loop = undefined };
    var e2e: DrainE2e = undefined;
    try e2e.init(29420, &server_handler, &client_handler);
    server_handler.loop = &e2e.loop;
    defer e2e.deinit();

    try runUntil(&e2e.loop, &server_handler, DrippingServer.inFlight, 10_000);
    e2e.server.drain();
    try testing.expect(!e2e.server.isDrained());

    try runUntil(&e2e.loop, &e2e, drainSettled, 10_000);
    // The response survived the drain, whole.
    try testing.expectEqual(DRIP_CHUNK * DRIP_CHUNKS, client_handler.received);
    try testing.expectEqual(@as(usize, 0), client_handler.mismatches);
    // The final GOAWAY names the first request not served: the next one.
    try testing.expectEqual(@as(?u64, 4), client_handler.goaway_id);
    try testing.expect(client_handler.refused_locally);
    try testing.expectEqual(@as(?u64, @intFromEnum(H3Error.request_rejected)), client_handler.late_reset_code);
    try testing.expectEqual(@as(u32, 1), server_handler.requests);
}

const PAUSE_WINDOW: u64 = 256 * 1024;
const PAUSE_BODY: usize = 4 * 1024 * 1024;

/// Pauses every request body on arrival; the test resumes it.
const PausingServer = struct {
    pub const protocol: Protocol = .h3;

    session: ?Session = null,
    stream_id: u64 = 0,
    body_bytes: usize = 0,
    body_ok: bool = true,
    ended: u32 = 0,
    bytes_at_end: usize = 0,
    reply: [32]u8 = undefined,

    pub fn onRequest(self: *@This(), session: *Session, stream_id: u64, _: []const qpack.Header) void {
        session.pauseRequestBody(stream_id) catch unreachable;
        self.session = session.*;
        self.stream_id = stream_id;
    }

    pub fn onData(self: *@This(), _: *Session, _: u64, data: []const u8) void {
        for (data, self.body_bytes..) |b, off| {
            if (b != e2eBodyByte(off)) self.body_ok = false;
        }
        self.body_bytes += data.len;
    }

    pub fn onRequestEnd(self: *@This(), session: *Session, stream_id: u64) void {
        self.ended += 1;
        self.bytes_at_end = self.body_bytes;
        const text = std.fmt.bufPrint(&self.reply, "{d}", .{self.body_bytes}) catch unreachable;
        session.sendResponse(stream_id, &.{.{ .name = ":status", .value = "200" }}, text) catch unreachable;
    }

    pub fn onConnectionClosed(self: *@This(), _: *Session) void {
        self.session = null;
    }

    fn hasRequest(self: *@This()) bool {
        return self.session != null;
    }

    /// Request bytes held server-side: unread in QUIC plus buffered in H3.
    fn buffered(self: *@This()) usize {
        const s = self.session orelse return 0;
        var total: usize = 0;
        if (s.entry.conn.streams.getStream(self.stream_id)) |st| {
            for (st.recv.sorter.chunks.items) |c| total += c.data.len;
        }
        if (s.entry.h3_conn) |h| {
            if (h.stream_bufs.get(self.stream_id)) |b| total += b.items.len;
        }
        return total;
    }
};

const PauseWatch = struct {
    server: *PausingServer,
    until: i64,
    max_buffered: usize = 0,

    fn sample(self: *@This()) bool {
        self.max_buffered = @max(self.max_buffered, self.server.buffered());
        return sys.nanoTimestamp() > self.until;
    }
};

test "e2e: a paused request body is held back by flow control, then delivered whole" {
    const body = try testing.allocator.alloc(u8, PAUSE_BODY);
    defer testing.allocator.free(body);
    for (body, 0..) |*b, i| b.* = e2eBodyByte(i);

    var client_handler = CheckingClient{
        .request = &.{
            .{ .name = ":method", .value = "POST" },
            .{ .name = ":scheme", .value = "https" },
            .{ .name = ":authority", .value = "localhost" },
            .{ .name = ":path", .value = "/upload" },
        },
        .request_body = body,
    };
    var server_handler = PausingServer{};
    var e2e: E2e(PausingServer, CheckingClient) = undefined;
    try e2e.initWith(29421, &server_handler, &client_handler, .{
        .initial_max_stream_data_bidi_remote = PAUSE_WINDOW,
    }, null);
    defer e2e.deinit();

    try runUntil(&e2e.loop, &server_handler, PausingServer.hasRequest, 10_000);
    // Long enough for an unpaused upload of this size to finish many times.
    var watch = PauseWatch{ .server = &server_handler, .until = sys.nanoTimestamp() + 500 * std.time.ns_per_ms };
    try runUntil(&e2e.loop, &watch, PauseWatch.sample, 5_000);

    try testing.expectEqual(@as(usize, 0), server_handler.body_bytes);
    try testing.expect(watch.max_buffered > 0);
    try testing.expect(watch.max_buffered <= PAUSE_WINDOW + 4096);
    const st = server_handler.session.?.entry.conn.streams.getStream(server_handler.stream_id).?;
    try testing.expect(st.recv.sorter.highestReceived() <= PAUSE_WINDOW);

    // Resumed from outside any server callback, as a proxy would once its
    // upstream drains.
    server_handler.session.?.resumeRequestBody(server_handler.stream_id);
    try runUntil(&e2e.loop, &client_handler, CheckingClient.done, 20_000);

    try testing.expectEqual(@as(u32, 1), server_handler.ended);
    try testing.expectEqual(PAUSE_BODY, server_handler.bytes_at_end);
    try testing.expect(server_handler.body_ok);
    try testing.expectEqualStrings("4194304", client_handler.body[0..client_handler.received]);
}

const UNI_BODY: usize = 3 * 1024 * 1024;

/// Counts what arrives on the peer's uni streams.
const UniSink = struct {
    pub const protocol: Protocol = .quic;

    bytes: usize = 0,
    ok: bool = true,
    fin: bool = false,

    pub fn onStreamData(self: *@This(), _: *Session, stream_id: u64, data: []const u8, fin: bool) void {
        if (stream_mod.isBidi(stream_id)) return;
        for (data, self.bytes..) |b, off| {
            if (b != e2eBodyByte(off)) self.ok = false;
        }
        self.bytes += data.len;
        if (fin) self.fin = true;
    }

    fn done(self: *@This()) bool {
        return self.fin;
    }
};

/// Sends `UNI_BODY` bytes on one uni stream as soon as it connects.
const UniSender = struct {
    pub const protocol: Protocol = .quic;

    body: []const u8,

    pub fn onConnected(self: *@This(), session: *ClientSession) void {
        const id = session.openQuicUniStream() catch unreachable;
        session.writeStream(id, self.body) catch unreachable;
        session.closeQuicStream(id);
    }

    pub fn onStreamData(_: *@This(), _: *ClientSession, _: u64, _: []const u8, _: bool) void {}
};

test "e2e: a peer uni stream carries well past its 1 MiB initial window" {
    const body = try testing.allocator.alloc(u8, UNI_BODY);
    defer testing.allocator.free(body);
    for (body, 0..) |*b, i| b.* = e2eBodyByte(i);

    var client_handler = UniSender{ .body = body };
    var server_handler = UniSink{};
    var e2e: E2e(UniSink, UniSender) = undefined;
    try e2e.init(29422, &server_handler, &client_handler);
    defer e2e.deinit();

    try runUntil(&e2e.loop, &server_handler, UniSink.done, 20_000);
    try testing.expectEqual(UNI_BODY, server_handler.bytes);
    try testing.expect(server_handler.ok);
}

/// Holds the first request's response open, then finishes it from another
/// connection's onConnectionClosed.
const CrossWriter = struct {
    pub const protocol: Protocol = .h3;

    held: ?Session = null,
    held_stream: u64 = 0,

    pub fn onRequest(self: *@This(), session: *Session, stream_id: u64, _: []const qpack.Header) void {
        if (self.held == null) {
            session.sendResponseHeaders(stream_id, &.{.{ .name = ":status", .value = "200" }}) catch unreachable;
            self.held = session.*;
            self.held_stream = stream_id;
        } else {
            session.sendResponse(stream_id, &.{.{ .name = ":status", .value = "200" }}, "hello") catch unreachable;
        }
    }

    pub fn onConnectionClosed(self: *@This(), session: *Session) void {
        const h = &(self.held orelse return);
        if (h.entry == session.entry) {
            self.held = null;
            return;
        }
        h.sendResponseData(self.held_stream, "bye") catch unreachable;
        h.finishResponse(self.held_stream, null) catch unreachable;
    }
};

fn statusSeen(c: *CheckingClient) bool {
    return c.status[0] != 0;
}

fn finishedOne(c: *CheckingClient) bool {
    return c.finished;
}

test "e2e: a write from one connection's onConnectionClosed to another goes out at once" {
    var loop = try xev.Loop.init(.{});
    defer loop.deinit();
    const S = Server(CrossWriter);
    const C = Client(CheckingClient);
    var sh = CrossWriter{};
    var server = try S.init(testing.allocator, &sh, .{ .port = 29423, .tls_config = makeTestTlsConfig(), .loop = &loop });
    server.start();

    var ha = CheckingClient{};
    var a = try C.init(testing.allocator, &ha, .{ .port = 29423, .skip_cert_verify = true, .loop = &loop });
    a.start();
    try runUntil(&loop, &ha, statusSeen, 5000);

    var hb = CheckingClient{};
    var b = try C.init(testing.allocator, &hb, .{ .port = 29423, .skip_cert_verify = true, .loop = &loop });
    b.start();
    try runUntil(&loop, &hb, finishedOne, 5000);
    b.stop();
    try runUntil(&loop, &b, C.isStopped, 5000);
    b.deinit();

    const OneLeft = struct {
        fn done(x: *S) bool {
            return x.conn_mgr.entries.items.len == 1;
        }
    };
    try runUntil(&loop, &server, OneLeft.done, 5000);
    // Without a wakeup this waits for A's next packet: the idle timeout.
    try runUntil(&loop, &ha, finishedOne, 150);
    try testing.expectEqualStrings("bye", ha.body[0..ha.received]);

    a.stop();
    server.stop();
    const Both = struct {
        s: *S,
        c: *C,
        fn done(x: *const @This()) bool {
            return x.s.isStopped() and x.c.isStopped();
        }
    };
    try runUntil(&loop, &Both{ .s = &server, .c = &a }, Both.done, 5000);
    a.deinit();
    server.deinit();
}

const FANOUT_STREAMS: u32 = 12;

/// Opens streams of its own from onStreamData, growing the stream map the
/// raw-QUIC poll is walking.
const FanoutServer = struct {
    pub const protocol: Protocol = .quic;

    fins: u32 = 0,
    opened: u32 = 0,

    pub fn onStreamData(self: *@This(), session: *Session, _: u64, _: []const u8, fin: bool) void {
        for (0..4) |_| {
            const id = session.openStream() catch break;
            session.closeQuicStream(id);
            self.opened += 1;
        }
        if (fin) self.fins += 1;
    }

    fn done(self: *@This()) bool {
        return self.fins == FANOUT_STREAMS;
    }
};

/// Sends a byte and a FIN on each of `FANOUT_STREAMS` bidi streams.
const FanoutClient = struct {
    pub const protocol: Protocol = .quic;

    pub fn onConnected(_: *@This(), session: *ClientSession) void {
        for (0..FANOUT_STREAMS) |_| {
            const id = session.openStream() catch unreachable;
            session.writeStream(id, "x") catch unreachable;
            session.closeQuicStream(id);
        }
    }

    pub fn onStreamData(_: *@This(), _: *ClientSession, _: u64, _: []const u8, _: bool) void {}
};

test "e2e: a raw-QUIC handler may open streams from onStreamData" {
    var client_handler = FanoutClient{};
    var server_handler = FanoutServer{};
    var e2e: E2e(FanoutServer, FanoutClient) = undefined;
    try e2e.init(29424, &server_handler, &client_handler);
    defer e2e.deinit();

    try runUntil(&e2e.loop, &server_handler, FanoutServer.done, 10_000);
    try testing.expect(server_handler.opened > 0);
}

/// Writes `PAUSE_BODY` patterned bytes and a FIN on one WebTransport
/// stream, as fast as the peer's credit allows. Works for either side.
const WtPump = struct {
    session_id: u64 = 0,
    stream_id: ?u64 = null,
    sent: usize = 0,
    closed: bool = false,

    /// False until the peer's stream credit allows it; retry later.
    fn open(self: *WtPump, s: anytype, session_id: u64) bool {
        self.session_id = session_id;
        self.stream_id = s.openBidiStream(session_id, null) catch return false;
        self.pump(s);
        return true;
    }

    fn pump(self: *WtPump, s: anytype) void {
        const sid = self.stream_id orelse return;
        var chunk: [E2E_CHUNK]u8 = undefined;
        while (self.sent < PAUSE_BODY) {
            const n = @min(E2E_CHUNK, PAUSE_BODY - self.sent);
            const cap = s.streamSendCapacity(sid) orelse return;
            if (cap < n) {
                s.notifyWritable(self.session_id, sid, n) catch unreachable;
                return;
            }
            for (chunk[0..n], self.sent..) |*b, off| b.* = e2eBodyByte(off);
            s.sendStreamData(sid, chunk[0..n]) catch unreachable;
            self.sent += n;
        }
        if (!self.closed) {
            self.closed = true;
            s.closeStream(sid);
        }
    }
};

/// Receiving end of a `WtPump` stream: pauses it on arrival and checks
/// what comes through once resumed.
const WtSink = struct {
    stream_id: ?u64 = null,
    bytes: usize = 0,
    ok: bool = true,
    fin: bool = false,

    fn opened(self: *WtSink, s: anytype, stream_id: u64) void {
        s.pauseStream(stream_id) catch unreachable;
        self.stream_id = stream_id;
    }

    fn data(self: *WtSink, stream_id: u64, bytes: []const u8, fin: bool) void {
        if (self.stream_id != stream_id) return;
        for (bytes, self.bytes..) |b, off| {
            if (b != e2eBodyByte(off)) self.ok = false;
        }
        self.bytes += bytes.len;
        if (fin) self.fin = true;
    }

    fn done(self: *WtSink) bool {
        return self.fin;
    }
};

const WtUploadClient = struct {
    pub const protocol: Protocol = .webtransport;
    up: WtPump = .{},

    pub fn onSessionReady(self: *@This(), session: *ClientSession, session_id: u64) void {
        if (!self.up.open(session, session_id)) unreachable;
    }
    pub fn onWritable(self: *@This(), session: *ClientSession, _: u64, _: ?u64) void {
        self.up.pump(session);
    }
    pub fn onStreamData(_: *@This(), _: *ClientSession, _: u64, _: []const u8, _: bool) void {}
};

const WtPausingServer = struct {
    pub const protocol: Protocol = .webtransport;
    sink: WtSink = .{},
    session: ?Session = null,

    pub fn onConnectRequest(_: *@This(), session: *Session, session_id: u64, _: []const u8) void {
        session.acceptSession(session_id) catch unreachable;
    }
    pub fn onBidiStream(self: *@This(), session: *Session, _: u64, stream_id: u64) void {
        self.sink.opened(session, stream_id);
        self.session = session.*;
    }
    pub fn onStreamData(self: *@This(), _: *Session, stream_id: u64, data: []const u8, fin: bool) void {
        self.sink.data(stream_id, data, fin);
    }
    pub fn onConnectionClosed(self: *@This(), _: *Session) void {
        self.session = null;
    }
};

const WtDownloadServer = struct {
    pub const protocol: Protocol = .webtransport;
    up: WtPump = .{},
    accepted: ?u64 = null,

    pub fn onConnectRequest(self: *@This(), session: *Session, session_id: u64, _: []const u8) void {
        session.acceptSession(session_id) catch unreachable;
        self.accepted = session_id;
    }
    pub fn onPollComplete(self: *@This(), session: *Session) void {
        const id = self.accepted orelse return;
        if (self.up.open(session, id)) self.accepted = null;
    }
    pub fn onWritable(self: *@This(), session: *Session, _: u64, _: ?u64) void {
        self.up.pump(session);
    }
    pub fn onStreamData(_: *@This(), _: *Session, _: u64, _: []const u8, _: bool) void {}
};

const WtPausingClient = struct {
    pub const protocol: Protocol = .webtransport;
    sink: WtSink = .{},

    pub fn onSessionReady(_: *@This(), _: *ClientSession, _: u64) void {}
    pub fn onBidiStream(self: *@This(), session: *ClientSession, _: u64, stream_id: u64) void {
        self.sink.opened(session, stream_id);
    }
    pub fn onStreamData(self: *@This(), _: *ClientSession, stream_id: u64, data: []const u8, fin: bool) void {
        self.sink.data(stream_id, data, fin);
    }
};

/// Runs the loop for `ms` while nothing may arrive on a paused stream.
fn holdPaused(loop: *xev.Loop, sink: *WtSink, conn: *connection.Connection, ms: i64) !void {
    const Watch = struct {
        sink: *WtSink,
        until: i64,
        fn over(self: *@This()) bool {
            return self.sink.bytes > 0 or sys.nanoTimestamp() > self.until;
        }
    };
    var w = Watch{ .sink = sink, .until = sys.nanoTimestamp() + ms * std.time.ns_per_ms };
    try runUntil(loop, &w, Watch.over, ms + 5_000);
    try testing.expectEqual(@as(usize, 0), sink.bytes);
    // One window, plus the first read that identified the stream as
    // WebTransport — taken before the handler could pause it.
    const st = conn.streams.getStream(sink.stream_id.?).?;
    try testing.expect(st.recv.sorter.highestReceived() > 0);
    try testing.expect(st.recv.sorter.highestReceived() <= 2 * PAUSE_WINDOW);
}

test "e2e: a paused WebTransport stream holds its sender back, then delivers whole" {
    var client_handler = WtUploadClient{};
    var server_handler = WtPausingServer{};
    var e2e: E2e(WtPausingServer, WtUploadClient) = undefined;
    try e2e.initWith(29433, &server_handler, &client_handler, .{
        .initial_max_stream_data_bidi_remote = PAUSE_WINDOW,
    }, null);
    defer e2e.deinit();

    const Opened = struct {
        fn f(h: *WtPausingServer) bool {
            return h.sink.stream_id != null;
        }
    };
    try runUntil(&e2e.loop, &server_handler, Opened.f, 10_000);
    try holdPaused(&e2e.loop, &server_handler.sink, server_handler.session.?.entry.conn, 500);
    try testing.expect(client_handler.up.sent < PAUSE_BODY);

    // From outside any callback, as a relay would once its other side drains.
    server_handler.session.?.resumeStream(server_handler.sink.stream_id.?);
    try runUntil(&e2e.loop, &server_handler.sink, WtSink.done, 20_000);
    try testing.expectEqual(PAUSE_BODY, server_handler.sink.bytes);
    try testing.expect(server_handler.sink.ok);
}

test "e2e: a WebTransport client pauses a server stream the same way" {
    var client_handler = WtPausingClient{};
    var server_handler = WtDownloadServer{};
    var e2e: E2e(WtDownloadServer, WtPausingClient) = undefined;
    try e2e.initWith(29434, &server_handler, &client_handler, null, .{
        .initial_max_stream_data_bidi_remote = PAUSE_WINDOW,
        .max_datagram_frame_size = 65536, // WebTransport needs DATAGRAM
    });
    defer e2e.deinit();

    const Opened = struct {
        fn f(h: *WtPausingClient) bool {
            return h.sink.stream_id != null;
        }
    };
    try runUntil(&e2e.loop, &client_handler, Opened.f, 10_000);
    try holdPaused(&e2e.loop, &client_handler.sink, e2e.client.conn, 500);
    try testing.expect(server_handler.up.sent < PAUSE_BODY);

    var cs = e2e.client.clientSession();
    cs.resumeStream(client_handler.sink.stream_id.?);
    try runUntil(&e2e.loop, &client_handler.sink, WtSink.done, 20_000);
    try testing.expectEqual(PAUSE_BODY, client_handler.sink.bytes);
    try testing.expect(client_handler.sink.ok);
}

test "e2e: a server past retry_threshold makes a client retry, then serves it" {
    var loop = try xev.Loop.init(.{});
    defer loop.deinit();
    var server_handler = HelloServer{};
    var server = try Server(HelloServer).init(testing.allocator, &server_handler, .{
        .port = 29435,
        .tls_config = makeTestTlsConfig(),
        .retry_threshold = 0,
        .loop = &loop,
    });
    defer server.deinit();
    server.start();

    var client_handler = CheckingClient{};
    var client = try Client(CheckingClient).init(testing.allocator, &client_handler, .{
        .port = 29435,
        .skip_cert_verify = true,
        .loop = &loop,
    });
    defer client.deinit();
    client.start();

    try runUntil(&loop, &client_handler, CheckingClient.done, 10_000);
    try testing.expect(client.conn.retry_received);
    try testing.expectEqualStrings("hello", client_handler.body[0..client_handler.received]);

    client.stop();
    server.stop();
    const Both = struct {
        s: *Server(HelloServer),
        c: *Client(CheckingClient),
        fn stopped(self: *const @This()) bool {
            return self.s.isStopped() and self.c.isStopped();
        }
    };
    try runUntil(&loop, &Both{ .s = &server, .c = &client }, Both.stopped, 5000);
}

/// Server ids 1 and 2 under one QUIC-LB config, as a proxy's workers would
/// share it.
fn steerLbConfig(server_id: u8) quic_lb.Config {
    var cfg: quic_lb.Config = .{ .config_id = 1, .server_id_len = 1, .nonce_len = 7, .key = [_]u8{0x5a} ** 16 };
    cfg.server_id[0] = server_id;
    return cfg;
}

/// A tiny spin lock: std 0.16 keeps its mutex behind `Io`.
const SpinLock = struct {
    held: std.atomic.Value(bool) = .init(false),

    fn lock(self: *SpinLock) void {
        while (self.held.cmpxchgWeak(false, true, .acquire, .monotonic) != null) std.atomic.spinLoopHint();
    }

    fn unlock(self: *SpinLock) void {
        self.held.store(false, .release);
    }
};

/// One worker of a proxy: a server on its own thread and loop, plus the inbox
/// its siblings hand datagrams to, drained on its own thread by an Async.
const SteerWorker = struct {
    const Handed = struct {
        buf: [1500]u8,
        len: usize,
        peer: posix.sockaddr.storage,
        local: posix.sockaddr.storage,
        ecn: u2,
    };

    server: Server(HelloServer),
    wakeup: xev.Async,
    wakeup_c: xev.Completion = .{},
    thread: std.Thread = undefined,

    lock: SpinLock = .{},
    inbox: [32]Handed = undefined,
    head: usize = 0,
    count: usize = 0,
    quit: std.atomic.Value(bool) = .init(false),

    /// Owner thread only; read after join.
    injected: usize = 0,

    fn run(self: *SteerWorker) void {
        self.server.start();
        self.wakeup.wait(self.server.eventLoop(), &self.wakeup_c, SteerWorker, self, onWakeup);
        self.server.eventLoop().run(.until_done) catch {};
    }

    fn onWakeup(self_opt: ?*SteerWorker, _: *xev.Loop, _: *xev.Completion, r: xev.Async.WaitError!void) xev.CallbackAction {
        const self = self_opt.?;
        _ = r catch return .rearm;
        var item: Handed = undefined;
        while (true) {
            self.lock.lock();
            if (self.count == 0) {
                self.lock.unlock();
                break;
            }
            item = self.inbox[self.head];
            self.head = (self.head + 1) % self.inbox.len;
            self.count -= 1;
            self.lock.unlock();
            self.server.injectDatagram(item.buf[0..item.len], item.peer, item.local, item.ecn);
            self.injected += 1;
        }
        if (self.quit.load(.acquire)) {
            self.server.stop();
            return .disarm;
        }
        return .rearm;
    }

    /// Any thread.
    fn hand(self: *SteerWorker, dg: *const ForeignDatagram) void {
        if (dg.bytes.len > 1500) return;
        self.lock.lock();
        if (self.count < self.inbox.len) {
            const slot = &self.inbox[(self.head + self.count) % self.inbox.len];
            @memcpy(slot.buf[0..dg.bytes.len], dg.bytes);
            slot.len = dg.bytes.len;
            slot.peer = dg.peer;
            slot.local = dg.local;
            slot.ecn = dg.ecn;
            self.count += 1;
        }
        self.lock.unlock();
        self.wakeup.notify() catch {};
    }
};

const SteerRouter = struct {
    workers: [2]*SteerWorker,
    forwarded: std.atomic.Value(usize) = .init(0),

    fn onForeign(ctx: ?*anyopaque, dg: *const ForeignDatagram) void {
        const self: *SteerRouter = @ptrCast(@alignCast(ctx.?));
        const id = dg.server_id[0];
        if (id < 1 or id > self.workers.len) return;
        _ = self.forwarded.fetchAdd(1, .monotonic);
        self.workers[id - 1].hand(dg);
    }
};

/// Stands in for a NAT between client and servers: relays through one
/// upstream socket to `first`, then — once `rebound` is set — through a
/// fresh one to `second`, so the client's packets change both source
/// address and receiving server.
const RebindingRelay = struct {
    front: posix.socket_t,
    up: [2]posix.socket_t,
    targets: [2]net.Address,
    rebound: std.atomic.Value(bool) = .init(false),
    quit: std.atomic.Value(bool) = .init(false),
    client: posix.sockaddr.storage = undefined,
    client_len: posix.socklen_t = 0,

    fn udp(port: u16) !posix.socket_t {
        const fd = try sys.socket(posix.AF.INET, posix.SOCK.DGRAM | posix.SOCK.NONBLOCK, 0);
        errdefer sys.close(fd);
        const addr = try net.Address.parseIp4("127.0.0.1", port);
        try sys.bind(fd, &addr.any, addr.getOsSockLen());
        return fd;
    }

    fn run(self: *RebindingRelay) void {
        var buf: [2048]u8 = undefined;
        while (!self.quit.load(.acquire)) {
            var idle = true;
            var from: posix.sockaddr.storage = undefined;
            var from_len: posix.socklen_t = @sizeOf(posix.sockaddr.storage);
            if (sys.recvfrom(self.front, &buf, 0, @ptrCast(&from), &from_len)) |n| {
                idle = false;
                self.client = from;
                self.client_len = from_len;
                const i: usize = @intFromBool(self.rebound.load(.acquire));
                const to = self.targets[i];
                _ = sys.sendto(self.up[i], buf[0..n], 0, &to.any, to.getOsSockLen()) catch {};
            } else |_| {}
            for (self.up) |fd| {
                if (sys.recvfrom(fd, &buf, 0, null, null)) |n| {
                    idle = false;
                    if (self.client_len != 0) {
                        _ = sys.sendto(self.front, buf[0..n], 0, @ptrCast(&self.client), self.client_len) catch {};
                    }
                } else |_| {}
            }
            if (idle) sys.sleepNs(50 * std.time.ns_per_us);
        }
    }
};

test "e2e: a migrated peer landing on the wrong worker is steered to its owner" {
    const relay_port: u16 = 29430;
    const ports = [2]u16{ 29431, 29432 };

    var handler = HelloServer{};
    var router: SteerRouter = .{ .workers = undefined };
    for (&router.workers, ports, 1..) |*w, port, id| {
        w.* = try testing.allocator.create(SteerWorker);
        w.*.* = .{
            .server = try Server(HelloServer).init(testing.allocator, &handler, .{
                .port = port,
                .reuse_port = true,
                .tls_config = makeTestTlsConfig(),
                .quic_lb = steerLbConfig(@intCast(id)),
                .foreign_datagram = .{ .ctx = &router, .func = SteerRouter.onForeign },
            }),
            .wakeup = try xev.Async.init(),
        };
    }
    defer for (router.workers) |w| {
        w.wakeup.deinit();
        w.server.deinit();
        testing.allocator.destroy(w);
    };

    var relay: RebindingRelay = .{
        .front = try RebindingRelay.udp(relay_port),
        .up = .{ try RebindingRelay.udp(0), try RebindingRelay.udp(0) },
        .targets = .{ try net.Address.parseIp4("127.0.0.1", ports[0]), try net.Address.parseIp4("127.0.0.1", ports[1]) },
    };
    defer for ([_]posix.socket_t{ relay.front, relay.up[0], relay.up[1] }) |fd| sys.close(fd);

    for (router.workers) |w| w.thread = try std.Thread.spawn(.{}, SteerWorker.run, .{w});
    const relay_thread = try std.Thread.spawn(.{}, RebindingRelay.run, .{&relay});

    var loop = try xev.Loop.init(.{});
    defer loop.deinit();
    var client_handler = CheckingClient{};
    var client = try Client(CheckingClient).init(testing.allocator, &client_handler, .{
        .port = relay_port,
        .skip_cert_verify = true,
        .loop = &loop,
    });
    client.start();

    const first = runUntil(&loop, &client_handler, CheckingClient.done, 10_000);

    // Rebind: from here on only worker 2 hears the client.
    relay.rebound.store(true, .release);
    const second: anyerror!void = if (first) |_| blk: {
        client_handler.finished = false;
        client_handler.received = 0;
        var cs = client.clientSession();
        client_handler.stream_id = try cs.sendRequest(&get_request, null);
        break :blk runUntil(&loop, &client_handler, CheckingClient.done, 10_000);
    } else |err| err;

    client.stop();
    runUntil(&loop, &client, Client(CheckingClient).isStopped, 5000) catch {};
    client.deinit();
    for (router.workers) |w| {
        w.quit.store(true, .release);
        w.wakeup.notify() catch {};
    }
    for (router.workers) |w| w.thread.join();
    relay.quit.store(true, .release);
    relay_thread.join();

    try first;
    try second;
    try testing.expectEqualStrings("hello", client_handler.body[0..client_handler.received]);
    // Worker 1 accepted the connection; worker 2 only ever passed packets on.
    try testing.expect(router.forwarded.load(.monotonic) > 0);
    try testing.expectEqual(router.forwarded.load(.monotonic), router.workers[0].injected);
    try testing.expectEqual(@as(usize, 0), router.workers[1].injected);
    try testing.expectEqual(@as(usize, 0), router.workers[1].server.conn_mgr.connectionCount());
}
