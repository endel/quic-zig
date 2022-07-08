//! Contains the data and logic to perform
//! a TLS 1.3 handshake
//! This does however not contain the logic to generate
//! and verify any of the handshake keys required to sign and
//! verify the messages.

const std = @import("std");
const tls = @import("tls.zig");
const ciphers = @import("ciphers.zig");
const mem = std.mem;
const crypto = std.crypto;
const Sha256 = crypto.hash.sha2.Sha256;
const HmacSha256 = crypto.auth.hmac.sha2.HmacSha256;
const ecdsa = @import("crypto/ecdsa.zig");

/// Represents the possible handshake types
pub const HandshakeType = enum(u8) {
    client_hello = 1,
    server_hello = 2,
    new_session_ticket = 4,
    end_of_early_data = 5,
    encrypted_extensions = 8,
    certificate = 11,
    certificate_request = 13,
    certificate_verify = 15,
    finished = 20,
    key_update = 24,
    message_hash = 254,

    pub fn int(self: HandshakeType) u8 {
        return @enumToInt(self);
    }
};

/// Handshake-specific header record type
pub const HandshakeHeader = struct {
    handshake_type: HandshakeType,
    length: u24,

    /// Converts the header into bytes
    pub fn toBytes(self: HandshakeHeader) [4]u8 {
        var buf: [4]u8 = undefined;
        buf[0] = self.handshake_type.int();
        mem.writeIntBig(16, buf[1..4], self.length);
        return buf;
    }

    /// Constructs a HandshakeHeader from an array of bytes
    pub fn fromBytes(bytes: [4]u8) HandshakeHeader {
        return .{
            .handshake_type = @intToEnum(HandshakeType, bytes[0]),
            .length = mem.readIntBig(u24, bytes[1..4]),
        };
    }
};

pub const ReadError = error{
    /// Reached end of stream, perhaps the client disconnected.
    EndOfStream,
};

/// Builds an error type representing both a `HandshakeReader`'s `Error`
/// and a `HandshakeWriter`'s `Error` depending on a given `reader` and `writer`.
pub fn ReadWriteError(comptime ReaderType: type, comptime WriterType: type) type {
    const ReaderError = HandshakeReader(ReaderType).Error;
    const WriterError = HandshakeWriter(WriterType).Error;
    return ReaderError || WriterError;
}

/// Initializes a new reader that decodes and performs a handshake
pub fn handshakeReader(reader: anytype, hasher: *Sha256) HandshakeReader(@TypeOf(reader)) {
    return HandshakeReader(@TypeOf(reader)).init(reader, hasher);
}

/// Generic handshake reader that will perform a handshake and decode all
/// handshake types
pub fn HandshakeReader(comptime ReaderType: type) type {
    return struct {
        const Self = @This();
        /// HashReader that will read from the stream
        /// and then hash its contents.
        reader: HashReader(ReaderType),

        pub const Error = ReadError || ReaderType.Error;

        const ClientHelloResult = struct {
            legacy_version: u16,
            session_id: [32]u8,
            random: [32]u8,
            cipher_suites: []const tls.CipherSuite,
            /// Represents the extensions as raw bytes
            /// Utilize ExtensionIterator to iterate over.
            extensions: []u8,
        };

        const Result = union(enum) {
            client_hello: ClientHelloResult,
        };

        /// Initializes a new instance of `HandshakeReader` of a given reader that must be of
        /// `ReaderType`.
        pub fn init(reader: ReaderType, hasher: *Sha256) Self {
            return .{ .reader = HashReader(ReaderType).init(reader, hasher) };
        }

        /// Starts reading from the reader and will try to perform a handshake.
        pub fn decode(self: *Self) Error!Result {
            var reader = self.reader.reader();
            const handshake_type = try reader.readByte();
            const remaining_length = try reader.readIntBig(u24);

            switch (@intToEnum(HandshakeType, handshake_type)) {
                .client_hello => return Result{ .client_hello = try self.decodeClientHello(remaining_length) },
                else => @panic("TODO"),
            }
        }

        /// Decodes a 'client hello' message received from the client.
        /// This means the Record header and handshake header have already been read
        /// and the first data to read will be the protocol version.
        pub fn decodeClientHello(self: *Self, message_length: usize) Error!ClientHelloResult {
            var result: ClientHelloResult = undefined;

            // maximum length of an entire record (record header + message)
            var buf: [1 << 14]u8 = undefined;
            try self.reader.reader().readNoEof(buf[0..message_length]);
            const content = buf[0..message_length];
            result.legacy_version = mem.readIntBig(u16, content[0..2]);
            // current index into `contents`
            var index: usize = 2;

            std.mem.copy(u8, &result.random, content[index..][0..32]);
            index += 32; // random

            // TLS version 1.3 ignores session_id
            // but we will return it to echo it in the server hello.
            const session_len = content[index];
            index += 1;
            result.session_id = [_]u8{0} ** 32;
            if (session_len != 0) {
                std.mem.copy(u8, &result.session_id, content[index..][0..session_len]);
                index += session_len;
            }

            const cipher_suites_len = mem.readIntBig(u16, content[index..][0..2]);
            index += 2;

            const cipher_suites = blk: {
                const cipher_bytes = content[index..][0..cipher_suites_len];
                index += cipher_suites_len;
                break :blk tls.bytesToTypedSlice(tls.CipherSuite, cipher_bytes);
            };
            result.cipher_suites = cipher_suites;

            // TLS version 1.3 ignores compression as well
            const compression_methods_len = content[index];
            index += compression_methods_len + 1;

            const extensions_length = mem.readIntBig(u16, content[index..][0..2]);
            index += 2;
            result.extensions = content[index..][0..extensions_length];
            index += extensions_length;

            std.debug.assert(index == message_length);

            return result;
        }
    };
}

/// Initializes a new `HandshakeWriter`, deducing the type of a given
/// instance of a `writer`. The handshake writer will construct all
/// required messages for a succesful handshake.
pub fn handshakeWriter(writer: anytype, hasher: *Sha256) HandshakeWriter(@TypeOf(writer)) {
    return HandshakeWriter(@TypeOf(writer)).init(writer, hasher);
}

/// Creates a new HandshakeWriter using a given writer type.
/// The handshakewriter builds all messages required to construct a succesful handshake.
pub fn HandshakeWriter(comptime WriterType: type) type {
    return struct {
        const Self = @This();

        writer: WriterType,
        hasher: *Sha256,

        const Error = WriterType.Error;

        /// Initializes a new `HandshakeWriter` by wrapping the given `writer` into
        /// a `HashWriter` and setting up the hasher.
        pub fn init(writer: WriterType, hasher: *Sha256) Self {
            return .{ .writer = writer, .hasher = hasher };
        }

        /// Constructs and sends a 'Server Hello' message to the client.
        /// This must be called, after a succesful 'Client Hello' message was received.
        pub fn serverHello(
            self: *Self,
            /// Determines if the server hello is a regular server hello,
            /// or a Hello Retry Request. As the messages share the same format,
            /// they're combined for simplicity, but the random that is generated
            /// will be different.
            kind: enum { server_hello, retry_request },
            // Legacy session_id to emit.
            // In TLS 1.3 we can simply echo client's session id.
            session_id: [32]u8,
            // The cipher_suite we support as a server and that was provided
            // by the client.
            cipher_suite: tls.CipherSuite,
            /// The `KeyShare` that was generated, based
            /// on the client's Key Share.
            key_share: tls.KeyShare,
            /// Randomly generated bytes.
            /// Bytes will be overwritten if `kind` is `retry_request`.
            random: [32]u8,
        ) Error!void {
            var builder = RecordBuilder.init();
            builder.startMessage(.server_hello);
            const writer = builder.writer();

            // Means TLS 1.2, this is legacy and actual version is sent through extensions
            writer.writeIntBig(u16, 0x303) catch unreachable;

            const server_random = switch (kind) {
                .server_hello => random,
                .retry_request => blk: {
                    // When sending a hello retry request, the random must always be the
                    // SHA-256 of "HelloRetryRequest"
                    var buf: [32]u8 = undefined;
                    Sha256.hash("HelloRetryRequest", &buf, .{});
                    break :blk buf;
                },
            };

            writer.writeAll(&server_random) catch unreachable;

            // session_id is legacy and no longer used. In TLS 1.3 we
            // can just 'echo' client's session id.
            writer.writeByte(0x20) catch unreachable; // length of session id (32);
            writer.writeAll(&session_id) catch unreachable;

            // cipher suite
            writer.writeIntBig(u16, cipher_suite.int()) catch unreachable;

            // Compression methods, which is no longer allowed for TLS 1.3 so assign "null"
            writer.writeByte(0x00) catch unreachable;

            // write the extension length key_share's length + 6 for supported versions
            writer.writeIntBig(u16, key_share.byteLen() + 6) catch unreachable;

            // Extension -- Key Share
            // TODO: When sending a retry, we should only send the named_group we want.
            try key_share.writeTo(writer);

            // Extension -- Supported versions
            const supported_versions = &[_]u8{
                // Extension type
                0x0,  0x2b,
                // byte length remaining (2)
                0x0,  0x02,
                // actual version (TLS 1.3)
                0x03, 0x04,
            };
            writer.writeAll(supported_versions) catch unreachable;

            builder.endMessage(self.hasher);
            try builder.writeRecord(.handshake, self.writer);
        }

        /// Sends the remaining messages required to finish the handshake.
        /// Wraps all messages and encrypts them, using the provided Cipher.
        pub fn handshakeFinish(
            self: *Self,
            comptime Cipher: type,
            key_storage: *ciphers.KeyStorage,
            certificate: []const u8,
            secret: [32]u8,
            sequence: u64,
        ) !void {
            var builder = RecordBuilder.init();
            const builder_writer = builder.writer();
            // encrypted extensions
            builder.startMessage(.encrypted_extensions);
            builder_writer.writeAll(&.{ 0x00, 0x00 }) catch unreachable;
            builder.endMessage(self.hasher);

            // Certificate
            builder.startMessage(.certificate);
            builder_writer.writeByte(0x00) catch unreachable; // request context
            // Full length of all certificates
            // For now, only support a single one
            // 5 extra bytes as we write the length of the first
            // certificate once more, and the certificate extensions.
            builder_writer.writeIntBig(u24, @intCast(u24, certificate.len + 5)) catch unreachable;
            builder_writer.writeIntBig(u24, @intCast(u24, certificate.len)) catch unreachable;
            builder_writer.writeAll(certificate) catch unreachable;
            builder_writer.writeAll(&.{ 0x00, 0x00 }) catch unreachable; // no extensions
            builder.endMessage(self.hasher);

            // Certificate verify
            builder.startMessage(.certificate_verify);
            builder_writer.writeIntBig(u16, Cipher.suite.int()) catch unreachable;
            builder_writer.writeIntBig(u16, 64) catch unreachable; // signature length

            // the message we will sign, containing
            // 0x20 (x64), 34 bytes for "TLS 1.3, server CertificateVerify",
            // and 32 bytes for the hash of the handshake
            var sig_msg = [_]u8{0} ** (64 + 34 + 32);
            sig_msg[0..64].* = [_]u8{0x20} ** 64;
            std.mem.copy(u8, sig_msg[64..], "TLS 1.3, server CertificateVerify");
            {
                var hash_copy = self.hasher;
                hash_copy.final(sig_msg[64 + 34 ..][0..32]);
            }
            // TODO: Get public key from certificate so we can
            // sign our message and input the bytes

            builder.endMessage(self.hasher);

            // handshake finished type
            builder.startMessage(.finished);
            const verify_data: [32]u8 = blk: {
                const finished_key = tls.hkdfExpandLabel(secret, "finished", "", 32);
                // copy hasher
                const finished_hash: [32]u8 = hsh: {
                    var temp_hasher = self.hasher.*;
                    var buf: [32]u8 = undefined;
                    // add the data between server hello and cert verify
                    // Will not include the `finished` message.
                    temp_hasher.final(&buf);
                    break :hsh buf;
                };

                var out: [32]u8 = undefined;
                HmacSha256.create(&out, &finished_key, &finished_hash);
                break :blk out;
            };
            builder_writer.writeAll(&verify_data) catch unreachable;
            builder.endMessage(self.hasher);

            try builder.writeRecordEncrypted(
                .handshake,
                self.writer,
                Cipher,
                key_storage,
                sequence,
            );
        }
    };
}

/// Constructs a new record to be sent to the client
/// for the handshake process. Contains an internal
/// buffer so we can calculate the total length required
/// to parse the entire content.
const RecordBuilder = struct {
    buffer: [1 << 14]u8,
    index: u14,
    state: union(enum) {
        start: u14,
        end: void,
    },

    /// No errors can occur when writing to the internal
    /// buffer as it's safety checked during release-safe and debug modes.
    ///
    /// Any panics are caused by a developer of the library, not by user-code.
    const Error = error{};

    const CipherData = struct {
        cipher: type,
        key_storage: *ciphers.KeyStorage,
        sequence: u64,
    };

    pub fn init() RecordBuilder {
        return .{ .buffer = undefined, .index = 0, .state = .end };
    }

    /// Initializes a new Handshake message of type `HandshakeType`.
    /// It sets an inner state and saves the location where the result length
    /// will be written to.
    pub fn startMessage(self: *RecordBuilder, rec: HandshakeType) void {
        std.debug.assert(self.state == .end);
        self.buffer[self.index] = rec.int();
        self.state = .{ .start = self.index + 1 };
        self.index += 4; // 3 bytes for the length we will write later
    }

    /// Ends the current Handshake message (NOT the total record), updates the state
    /// and writes the written length to the handshake record.
    pub fn endMessage(self: *RecordBuilder, hasher: *Sha256) void {
        std.debug.assert(self.state == .start);
        defer self.state = .end;
        const idx = self.state.start;
        const len = self.index - idx - 3; // 3 bytes for writing the index
        std.mem.writeIntBig(u24, self.buffer[idx..][0..3], len);
        hasher.update(self.buffer[idx - 1 ..][0..len]);
    }

    /// Writes to the internal buffer, asserting a handshake record was set.
    /// Updates the internal index on each write and returns the length that
    /// was written to the internal buffer.
    fn write(self: *RecordBuilder, bytes: []const u8) Error!usize {
        std.debug.assert(bytes.len != 0); // empty slice given.
        std.debug.assert(self.state == .start); // it's illegal to write random data without creating a message type first.
        mem.copy(u8, self.buffer[self.index..], bytes);
        self.index += @intCast(u14, bytes.len);
        return bytes.len;
    }

    /// Initializes a `std.io.Writer` that allows writing data to a handshake record
    /// without requiring any allocations.
    ///
    /// It is illegal to write to this without calling `startRecord` first.
    pub fn writer(self: *RecordBuilder) std.io.Writer(*RecordBuilder, Error, write) {
        return .{ .context = self };
    }

    /// Writes a new Record to a given writer using a given `tag` of `tls.Record.RecordType`.
    /// Writes the total length written to this buffer as part of the Record.
    ///
    /// Asserts a started handshake record was ended before calling this.
    ///
    /// This does not reset the internal buffer. For that, use `reset()`.
    pub fn writeRecord(self: RecordBuilder, tag: tls.Record.RecordType, any_writer: anytype) @TypeOf(any_writer).Error!void {
        std.debug.assert(self.state == .end);

        const data_len = @intCast(u16, self.length());
        var record = tls.Record.init(tag, data_len);
        try record.writeTo(any_writer);
        try any_writer.writeAll(self.toSlice());
    }

    /// Writes a new Record to a given writer using a given `tag` of `tls.Record.RecordType`.
    /// Writes the total length written to this buffer as part of the Record.
    ///
    /// Asserts a started handshake record was ended before calling this.
    ///
    /// This does not reset the internal buffer. For that, use `reset()`.
    pub fn writeRecordEncrypted(
        self: *RecordBuilder,
        tag: tls.Record.RecordType,
        any_writer: anytype,
        comptime Cipher: type,
        key_storage: *ciphers.KeyStorage,
        sequence: u64,
    ) @TypeOf(any_writer).Error!void {
        std.debug.assert(self.state == .end);

        // Write the actual tag
        self.buffer[self.index] = tag.int();
        self.index += 1;

        const data_len = @intCast(u16, self.length());
        var record = tls.Record.init(.application_data, data_len + 16); // include auth tag

        var auth_tag: [16]u8 = undefined;
        var buf: [1 << 14]u8 = undefined;
        Cipher.encrypt(
            key_storage,
            buf[0..data_len],
            self.toSlice(),
            &record.toBytes(),
            sequence,
            &auth_tag,
        );

        try record.writeTo(any_writer);
        try any_writer.writeAll(buf[0..data_len]);
        try any_writer.writeAll(&auth_tag);
    }

    /// Resets the internal buffer's index to 0 so we can build a new record.
    ///
    /// Asserts no handshake record is being written currently.
    pub fn reset(self: *RecordBuilder) void {
        std.debug.assert(self.state == .end); // resetting during a record write is not allowed.
        self.index = 0;
    }

    /// Returns a slice of the current internal buffer.
    ///
    /// When we are still writing to a handshake message, this will return a
    /// slice until the start of that record as it assumes the slice is needed
    /// unside the record.
    pub fn toSlice(self: RecordBuilder) []const u8 {
        return switch (self.state) {
            .start => |idx| self.buffer[0..idx],
            .end => self.buffer[0..self.index],
        };
    }

    /// Returns the length of the currently written data
    pub fn length(self: RecordBuilder) usize {
        return self.index;
    }
};

/// Constructs a reader that hashes each read's content
/// NOTE: It reads raw data, not hashed data.
fn HashReader(comptime ReaderType: type) type {
    return struct {
        const Self = @This();
        hash: *Sha256,
        any_reader: ReaderType,

        const Error = ReaderType.Error;

        pub fn init(any_reader: ReaderType, hash: *Sha256) Self {
            return .{ .any_reader = any_reader, .hash = hash };
        }

        pub fn read(self: *Self, buf: []u8) Error!usize {
            const len = try self.any_reader.read(buf);
            if (len != 0) {
                self.hash.update(buf[0..len]);
            }
            return len;
        }

        pub fn reader(self: *Self) std.io.Reader(*Self, Error, read) {
            return .{ .context = self };
        }
    };
}

test "Client Hello" {
    // Client hello bytes taken from:
    // https://tls13.ulfheim.net/

    // zig fmt: off
    var data = [_]u8{
        // Handshake header
        0x01, 0x00, 0x00, 0xc6,
        // client version
        0x03, 0x03,
        // random
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
        // Session id
        0x20, 0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6,
        0xe7, 0xe8, 0xe9, 0xea, 0xeb, 0xec, 0xed, 0xee,
        0xef, 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6,
        0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe,
        0xff,
        // Cipher suites
        0x00, 0x06, 0x13, 0x01,
        0x13, 0x02, 0x13, 0x03,
        // Compression methods
        0x01, 0x00,
        // Extension length
        0x00, 0x77,
        // Extension - Server name
        0x00, 0x00, 0x00, 0x18, 0x00, 0x16, 0x00, 0x00,
        0x13, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65,
        0x2e, 0x75, 0x6c, 0x66, 0x68, 0x65, 0x69, 0x6d,
        0x2e, 0x6e, 0x65, 0x74,
        // Extension - Support groups
        0x00, 0x0a, 0x00, 0x08, 0x00, 0x06, 0x00, 0x1d,
        0x00, 0x17, 0x00, 0x18,
        // Extension - Signature Algorithms
        0x00, 0x0d, 0x00, 0x14, 0x00, 0x12, 0x04, 0x03,
        0x08, 0x04, 0x04, 0x01, 0x05, 0x03, 0x08, 0x05,
        0x05, 0x01, 0x08, 0x06, 0x06, 0x01, 0x02, 0x01,
        // Extensions - Key Share
        0x00, 0x33, 0x00, 0x26, 0x00, 0x24, 0x00, 0x1d,
        0x00, 0x20, 0x35, 0x80, 0x72, 0xd6, 0x36, 0x58,
        0x80, 0xd1, 0xae, 0xea, 0x32, 0x9a, 0xdf, 0x91,
        0x21, 0x38, 0x38, 0x51, 0xed, 0x21, 0xa2, 0x8e,
        0x3b, 0x75, 0xe9, 0x65, 0xd0, 0xd2, 0xcd, 0x16,
        0x62, 0x54,
        // Extension - PSK Key Exchange modes
        0x00, 0x2d, 0x00, 0x02, 0x01, 0x01,
        // Extension - Supported versions
        0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04,
    };
    // zig fmt: on

    var fb_reader = std.io.fixedBufferStream(&data).reader();
    var hasher = Sha256.init(.{});
    var hs_reader = handshakeReader(fb_reader, &hasher);
    const result = try hs_reader.decode();
    const client_hello = result.client_hello;

    try std.testing.expectEqual(@as(u16, 0x0303), client_hello.legacy_version);

    // check random
    try std.testing.expectEqualSlices(u8, &.{
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    }, &client_hello.random);

    // check session id
    try std.testing.expectEqualSlices(u8, &.{
        0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6,
        0xe7, 0xe8, 0xe9, 0xea, 0xeb, 0xec, 0xed,
        0xee, 0xef, 0xf0, 0xf1, 0xf2, 0xf3, 0xf4,
        0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb,
        0xfc, 0xfd, 0xfe, 0xff,
    }, &client_hello.session_id);

    var cipher_bytes = [_]u8{ 0x13, 0x01, 0x13, 0x02, 0x13, 0x03 };
    const ciphers_slice = tls.bytesToTypedSlice(tls.CipherSuite, &cipher_bytes);
    try std.testing.expectEqualSlices(tls.CipherSuite, ciphers_slice, client_hello.cipher_suites);
}

test "Server Hello" {
    var buf: [2048]u8 = undefined;
    var fb = std.io.fixedBufferStream(&buf);
    const writer = fb.writer();
    var hasher = Sha256.init(.{});
    var hs_writer = handshakeWriter(writer, &hasher);
    const session_id: [32]u8 = .{
        0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7, 0xe8, 0xe9, 0xea, 0xeb, 0xec, 0xed, 0xee, 0xef,
        0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff,
    };

    const random: [32]u8 = .{
        0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f,
        0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
    };

    const key_share = tls.KeyShare{
        .key_exchange = .{
            0x9f, 0xd7, 0xad, 0x6d, 0xcf, 0xf4, 0x29, 0x8d, 0xd3, 0xf9, 0x6d, 0x5b, 0x1b, 0x2a, 0xf9, 0x10,
            0xa0, 0x53, 0x5b, 0x14, 0x88, 0xd7, 0xf8, 0xfa, 0xbb, 0x34, 0x9a, 0x98, 0x28, 0x80, 0xb6, 0x15,
        },
        .named_group = .x25519,
    };

    try hs_writer.serverHello(
        .server_hello,
        session_id,
        .tls_aes_128_gcm_sha256,
        key_share,
        random,
    );

    // zig fmt: off
    const expected = &[_]u8{
        // record header
        0x16, 0x03, 0x03, 0x00, 0x7a,
        // handshake header
        0x02, 0x00, 0x00, 0x76,
        // server version
        0x03, 0x03,
    }
        // server random
        ++ random ++
        // session id length (32 bytes)
        &[_]u8{0x20} ++
        // session id
        session_id ++ &[_]u8{
        //cipher suite
        0x13, 0x1,
        // compression method
        0x00,
        // extension length
        0x00, 0x2e,
        // extension key_share
        0x00, 0x33, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20, 0x9f, 0xd7, 0xad, 0x6d, 0xcf, 0xf4, 0x29, 0x8d, 0xd3, 0xf9, 0x6d, 0x5b,
        0x1b, 0x2a, 0xf9, 0x10, 0xa0, 0x53, 0x5b, 0x14, 0x88, 0xd7, 0xf8, 0xfa, 0xbb, 0x34, 0x9a, 0x98, 0x28, 0x80, 0xb6, 0x15,
        // supported versions
        0x00, 0x2b, 0x00, 0x02, 0x03, 0x04
    };
    // zig fmt: on

    try std.testing.expectEqualSlices(u8, expected, fb.getWritten());
}

test "RecordBuilder" {
    const finished_bytes = [_]u8{
        0xea, 0x6e, 0xe1, 0x76, 0xdc, 0xcc, 0x4a, 0xf1, 0x85, 0x9e, 0x9e, 0x4e, 0x93, 0xf7, 0x97, 0xea,
        0xc9, 0xa7, 0x8c, 0xe4, 0x39, 0x30, 0x1e, 0x35, 0x27, 0x5a, 0xd4, 0x3f, 0x3c, 0xdd, 0xbd, 0xe3,
    };
    var buf: [1 << 14]u8 = undefined;
    var stream = std.io.fixedBufferStream(&buf);
    const writer = stream.writer();
    var builder = RecordBuilder.init();
    var hasher = Sha256.init(.{});
    builder.startMessage(.finished);
    builder.writer().writeAll(&finished_bytes) catch unreachable;
    builder.endMessage(&hasher);
    try builder.writeRecord(.application_data, writer);

    // zig fmt: off
    try std.testing.expectEqualSlices(u8, &([_]u8{
        // application data
        0x17,
        // Tls version
        0x03, 0x03,
        // length
        0x00, 0x24,
        // finished handshake header type
        0x14,
        // handshake header length
        0x00, 0x00, 0x20,
        // actual finished bytes
    } ++ finished_bytes),
    stream.getWritten());
    // zig fmt: on
}
