const std = @import("std");
const io = std.io;
const tls = std.crypto.tls;
const packet = @import("packet.zig");
const util = @import("util.zig");

const RANDOM_SIZE = 32;
const MAX_SESSION_ID_LENGTH = 32;

pub const TLSError = error{
    HandshakeError,
    DecodeError,
    NotImplemented,
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
    hostname: []u8 = undefined,

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
                    try decryptECH(&client_hello);
                    // TODO: validate ECH

                    try self.extractSNI(&client_hello);

                    self.state = .read_client_hello_after_ech;
                },

                .read_client_hello_after_ech => {
                    return error.NotImplemented;
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

    fn decryptECH(client_hello: *ClientHello) !void {
        var encrypted_client_hello = try client_hello.getExtension(.encrypted_client_hello);
        if (encrypted_client_hello != null) {
            std.log.err("encrypted_client_hello extension FOUND. ECH decryption not implemented.", .{});
            return error.NotImplemented;
        }
    }

    fn extractSNI(self: *Handshake, client_hello: *ClientHello) !void {
        //
        // SNI = ServerNameIndication extension
        //

        var server_name_ext = try client_hello.getExtension(.server_name);
        if (server_name_ext == null) {
            // no SNI extension to parse
            return;
        }

        // TODO: optimize here

        var ext = util.StreamReader.from(server_name_ext.?);
        var server_name_list = util.StreamReader.from(ext.getSlicePrefixedLength(u16));
        var name_type = server_name_list.get(u8);
        var host_name_len = server_name_list.get(u16);
        var host_name = server_name_list.getSlice(host_name_len);

        if (name_type != 0 or
            host_name.len == 0 or
            host_name.len > 255 or // max hostname length
            host_name.len != host_name_len // memchr 0
        ) {
            return error.DecodeError;
        }

        self.hostname = host_name;
        // hs->should_ack_sni = true;
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

    pub fn getExtension(self: *ClientHello, find_extension_type: ExtensionType) !?[]u8 {
        if (self.extensions != null) {
            var reader = util.StreamReader.from(self.extensions.?);

            while (!reader.eof()) {
                var extension_type = reader.get(ExtensionType);
                std.log.info("extension type => {any}", .{extension_type});

                var value_len = reader.get(u16);
                std.log.info("extension value length => {any}", .{value_len});

                var value = reader.getSlice(value_len);
                std.log.info("extension value => {any}", .{value});

                if (extension_type == find_extension_type) {
                    return value;
                }
            }
        }
        return null;
    }
};

pub const ExtensionType = enum(u16) {
    server_name = 0, // RFC 6066
    max_fragment_length = 1, // RFC 6066
    status_request = 5, // RFC 6066
    supported_groups = 10, // RFC 8422, 7919
    ec_point_formats = 11, // RFC 4492
    signature_algorithms = 13, // RFC 8446
    use_srtp = 14, // RFC 5764
    heartbeat = 15, // RFC 6520
    application_layer_protocol_negotiation = 16, // RFC 7301
    signed_certificate_timestamp = 18, // RFC 6962
    client_certificate_type = 19, // RFC 7250
    server_certificate_type = 20, // RFC 7250
    padding = 21, // RFC 7685
    extended_master_secret = 23, // RFC 7627
    cert_compression = 27, // RFC 8879
    session_ticket = 35, // RFC 4507
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
    quic_transport_parameters = 57, // RFC 9000

    //
    renegotiate = 0xff01, // RFC 5746
    next_proto_neg = 13172, // (This is not an IANA defined extension number)
    delegated_credential = 0x22, // draft-ietf-tls-subcerts.
    application_settings = 17513, // (draft-vvv-tls-alps. This is not an IANA defined extension number.)
    encrypted_client_hello = 0xfe0d, // (draft-ietf-tls-esni-13. This is not an IANA defined extension number.)
    ech_outer_extensions = 0xfd00, // (draft-ietf-tls-esni-13. This is not an IANA defined extension number.)
    channel_id = 30032, // (This is not an IANA defined extension number)
    //

    _,
};
