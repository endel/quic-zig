const std = @import("std");
const tls = std.crypto.tls;
const packet = @import("packet.zig");

const RANDOM_SIZE = 32;
const MAX_SESSION_ID_LENGTH = 32;

pub const TLSError = error{
    HandshakeError,
};

pub const HandshakeState = enum(u8) {
    // shared states
    start = 0,
    tls13,
    process_change_cipher_spec,
    done,

    // server states
    read_client_hello,
    read_client_hello_after_ech,
    select_certificate,
    select_parameters,
    send_server_hello,
    send_server_certificate,
    send_server_key_exchange,
    send_server_hello_done,
    read_client_certificate,
    verify_client_certificate,
    read_client_key_exchange,
    read_client_certificate_verify,
    read_change_cipher_spec,
    read_next_proto,
    read_channel_id,
    read_client_finished,
    send_server_finished,
    finish_server_handshake,

    // client states
    enter_early_data,
    early_reverify_server_certificate,
    read_hello_verify_request,
    read_server_hello,
    read_server_certificate,
    read_certificate_status,
    verify_server_certificate,
    reverify_server_certificate,
    read_server_key_exchange,
    read_certificate_request,
    read_server_hello_done,
    send_client_certificate,
    send_client_key_exchange,
    send_client_certificate_verify,
    send_client_finished,
    finish_flight,
    read_session_ticket,
    read_server_finished,
    finish_client_handshake,
};

// TLS Message Type
pub const MessageType = enum(u8) {
    hello_request = 0,
    client_hello = 1,
    server_hello = 2,
    new_session_ticket = 4,
    end_of_early_data = 5,
    encrypted_extensions = 8,
    certificate = 11,
    server_key_exchange = 12,
    certificate_request = 13,
    server_hello_done = 14,
    certificate_verify = 15,
    client_key_exchange = 16,
    finished = 20,
    certificate_status = 22,
    supplemental_data = 23,
    key_update = 24,
    compressed_certificate = 25,
    next_proto = 67,
    channel_id = 203,
    message_hash = 254,
    _,
};

// const Message = struct {
// };

pub const Handshake = struct {
    buffer: [8000]u8 = .{0} ** 8000,
    encryption_level: u8 = 0,
    state: HandshakeState = .start, // .start_accept

    pub fn provideData(self: *Handshake, data: []u8, encryption_level: u8) void {
        // FIXME: append here instead of replacing into position 0
        std.mem.copy(u8, self.buffer[0..data.len], data);
        self.encryption_level = encryption_level;
    }

    pub fn perform(self: *Handshake, is_server: bool) !void {
        if (is_server) {
            try self.doServerHandshake();
        } else {
            try self.doClientHandshake();
        }
    }

    fn doServerHandshake(self: *Handshake) !void {
        // try decoder.ensure(self.buffer.len);
        var decoder: tls.Decoder = .{
            .buf = &self.buffer,
            .our_end = self.buffer.len,
        };

        while (self.state != .done) {
            std.log.info("doServerHandshake ... state: {any}", .{self.state});
            //
            switch (self.state) {
                .start => {
                    // TODO: trigger "handshake start" callback
                    self.state = .read_client_hello;
                },

                .read_client_hello => {
                    // get message type and length
                    const message_type = @intToEnum(MessageType, decoder.decode(u8));
                    if (message_type != .client_hello) {
                        std.log.err("ClientHello: invalid message type", .{});
                        return error.HandshakeError;
                    }

                    const message_len = decoder.decode(u24);

                    // FIXME: use tls.Decoder.sub()??
                    var msg_decoder = tls.Decoder.fromTheirSlice(self.buffer[decoder.idx..(decoder.idx + message_len)]);
                    msg_decoder.our_end = message_len;
                    // advance main decoder, we're gonna use only the
                    // msg_decoder within this block
                    decoder.skip(message_len);

                    // parse client hello
                    var legacy_version = msg_decoder.decode(u16);
                    var random = msg_decoder.slice(RANDOM_SIZE);
                    var session_id_len = msg_decoder.decode(u8);
                    var session_id = msg_decoder.slice(session_id_len);
                    if (session_id.len > MAX_SESSION_ID_LENGTH) {
                        std.log.err("ClientHello: session_id must not exceed {} length", .{MAX_SESSION_ID_LENGTH});
                        return error.HandshakeError;
                    }

                    var cipher_suites = msg_decoder.slice(msg_decoder.decode(u16));
                    if (cipher_suites.len < 2) {
                        std.log.err("ClientHello: cipher_suites must be length 2 or higher.", .{});
                        return error.HandshakeError;
                    }

                    var compression_methods = msg_decoder.slice(msg_decoder.decode(u8));
                    if (compression_methods.len < 1) {
                        std.log.err("ClientHello: compression_methods must be length 1 or higher.", .{});
                        return error.HandshakeError;
                    }

                    var extensions: ?[]u8 = null;
                    if (msg_decoder.idx + 3 < msg_decoder.our_end) {
                        //
                        // parse extensions
                        //
                        // there may not be more than one extension of the same
                        // type in a ClientHello or ServerHello.
                        //
                        // => http://tools.ietf.org/html/rfc5246#section-7.4.1.4
                        //
                        extensions = msg_decoder.slice(msg_decoder.decode(u16));
                    }

                    var client_hello: ClientHello = .{
                        .buf = msg_decoder.buf,
                        .legacy_version = legacy_version,
                        .random = random,
                        .session_id = session_id,
                        .cipher_suites = cipher_suites,
                        .compression_methods = compression_methods,
                        .extensions = extensions,
                    };

                    std.log.info("ClientHello => {any}", .{client_hello});

                    // TODO: decrypt ECH
                    // TODO: validate ECH
                    // TODO: extract SNI

                    self.state = .read_client_hello_after_ech;
                },

                .read_client_hello_after_ech => {
                    return (error{NotImplemented}).NotImplemented;
                },

                .select_certificate => {},
                .tls13 => {},
                .select_parameters => {},
                .send_server_hello => {},
                .send_server_certificate => {},
                .send_server_key_exchange => {},
                .send_server_hello_done => {},

                .read_client_certificate => {},
                .verify_client_certificate => {},
                .read_client_key_exchange => {},
                .read_client_certificate_verify => {},
                .read_change_cipher_spec => {},
                .process_change_cipher_spec => {},

                .read_next_proto => {},
                .read_channel_id => {},
                .read_client_finished => {},
                .send_server_finished => {},
                .finish_server_handshake => {},
                .done => {},
                else => return error.HandshakeError,
            }
        }
    }

    fn doClientHandshake(self: *Handshake) !void {
        _ = self;
        std.log.info("TODO: doClientHandshake ...", .{});
    }
};

// enum ssl_client_hs_state_t {
//   state_start_connect = 0,
//   state_enter_early_data,
//   state_early_reverify_server_certificate,
//   state_read_hello_verify_request,
//   state_read_server_hello,
//   state_tls13,
//   state_read_server_certificate,
//   state_read_certificate_status,
//   state_verify_server_certificate,
//   state_reverify_server_certificate,
//   state_read_server_key_exchange,
//   state_read_certificate_request,
//   state_read_server_hello_done,
//   state_send_client_certificate,
//   state_send_client_key_exchange,
//   state_send_client_certificate_verify,
//   state_send_client_finished,
//   state_finish_flight,
//   state_read_session_ticket,
//   state_process_change_cipher_spec,
//   state_read_server_finished,
//   state_finish_client_handshake,
//   state_done,
// };

pub const ClientHello = struct {
    buf: []u8,
    legacy_version: u16,
    random: []u8,
    session_id: []u8,
    cipher_suites: []u8,
    compression_methods: []u8,
    extensions: ?[]u8,
};

pub const ExtensionType = enum(u16) {
    server_name = 0, // RFC 6066
    max_fragment_length = 1, // RFC 6066
    status_request = 5, // RFC 6066
    supported_groups = 10, // RFC 8422, 7919
    signature_algorithms = 13, // RFC 8446
    use_srtp = 14, // RFC 5764
    heartbeat = 15, // RFC 6520
    application_layer_protocol_negotiation = 16, // RFC 7301
    signed_certificate_timestamp = 18, // RFC 6962
    client_certificate_type = 19, // RFC 7250
    server_certificate_type = 20, // RFC 7250
    padding = 21, // RFC 7685
    pre_shared_key = 41, // RFC 8446
    early_data = 42, // RFC 8446
    supported_versions = 43, // RFC 8446
    cookie = 44, // RFC 8446
    psk_key_exchange_modes = 45, // RFC 8446
    certificate_authorities = 47, // RFC 8446
    oid_filters = 48, // RFC 8446
    post_handshake_auth = 49, // RFC 8446
    signature_algorithms_cert = 50, // RFC 8446
    key_share = 51, // RFC 8446
    _,
};
