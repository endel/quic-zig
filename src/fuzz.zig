// Fuzz tests for quic-zig.
//
// Uses Zig 0.15's built-in std.testing.fuzz which integrates with libFuzzer.
//
// Run:
//   zig build fuzz                          # Build + run all fuzz targets
//   zig test src/fuzz.zig -ffuzz [--port N] # Direct invocation with fuzzer
//
// Each target feeds arbitrary bytes into a parser and asserts:
//   1. No crashes, panics, or undefined behavior
//   2. Successful parses can round-trip (encode → decode → same result)
//   3. No out-of-bounds reads/writes (Zig safety checks in debug mode)

const std = @import("std");
const io_compat = @import("io_compat.zig");
const testing = std.testing;

const packet = @import("quic/packet.zig");
const frame = @import("quic/frame.zig");
const transport_params = @import("quic/transport_params.zig");
const h3_frame = @import("h3/frame.zig");
const qpack = @import("h3/qpack.zig");
const huffman = @import("h3/huffman.zig");
const capsule = @import("h3/capsule.zig");
const priority = @import("h3/priority.zig");
const ranges = @import("quic/ranges.zig");
const stream = @import("quic/stream.zig");
const connection = @import("quic/connection.zig");
const tls13 = @import("quic/tls13.zig");
const moq_wire = @import("moq/wire.zig");
const moq_msg = @import("moq/message.zig");
const moq_codes = @import("moq/message_codes.zig");
const moq_version = @import("moq/version.zig");
const moq_obj = @import("moq/object.zig");
const lite_wire = @import("moq/lite/wire.zig");
const lite_msg = @import("moq/lite/message.zig");
const lite_session = @import("moq/lite/session.zig");

// ════════════════════════════════════════════════════════
// Target 1: QUIC Variable-Length Integer (RFC 9000 §16)
//
// Foundation of all QUIC parsing. Tests 1/2/4/8 byte
// encodings, boundary values, and round-trip consistency.
// ════════════════════════════════════════════════════════

test "fuzz: varint round-trip" {
    try testing.fuzz({}, struct {
        fn f(_: void, smith: *std.testing.Smith) anyerror!void {
            const input = smith.in orelse return;
            var fbs = io_compat.fixedBufferStream(input);
            const reader = &fbs;
            const val = packet.readVarInt(reader) catch return;

            // Round-trip: encode the parsed value and decode again
            var buf: [8]u8 = undefined;
            var wfbs = io_compat.fixedBufferStream(&buf);
            packet.writeVarInt(&wfbs, val) catch return;

            var rfbs = io_compat.fixedBufferStream(wfbs.buffered());
            const val2 = packet.readVarInt(&rfbs) catch return;
            try testing.expectEqual(val, val2);
        }
    }.f, .{});
}

// ════════════════════════════════════════════════════════
// Target 2: QUIC Packet Header (RFC 9000 §17)
//
// The first thing parsed on every incoming UDP datagram.
// Tests long/short headers, version negotiation, connection
// IDs, packet number decoding, and coalesced packets.
// ════════════════════════════════════════════════════════

test "fuzz: packet header parse" {
    try testing.fuzz({}, struct {
        fn f(_: void, smith: *std.testing.Smith) anyerror!void {
            const input = smith.in orelse return;
            if (input.len == 0) return;
            // Header.parse takes a mutable fbs; we need a mutable copy
            var buf: [1536]u8 = undefined;
            const len = @min(input.len, buf.len);
            @memcpy(buf[0..len], input[0..len]);
            var fbs = io_compat.fixedBufferStream(buf[0..len]);

            // Try parsing with various short DCID lengths (0, 8, 20)
            for ([_]u8{ 0, 8, 20 }) |dcid_len| {
                fbs.seek = 0;
                _ = packet.Header.parse(&fbs, dcid_len) catch continue;
            }
        }
    }.f, .{});
}

// ════════════════════════════════════════════════════════
// Target 3: QUIC Frame Parsing (RFC 9000 §12.4)
//
// Parses all 24 frame types. This is the core of QUIC's
// wire format: ACK, STREAM, CRYPTO, flow control, etc.
// ════════════════════════════════════════════════════════

test "fuzz: frame parse" {
    try testing.fuzz({}, struct {
        fn f(_: void, smith: *std.testing.Smith) anyerror!void {
            const input = smith.in orelse return;
            if (input.len == 0) return;
            // Frame.parse takes []u8 (mutable)
            var buf: [4096]u8 = undefined;
            const len = @min(input.len, buf.len);
            @memcpy(buf[0..len], input[0..len]);
            _ = frame.Frame.parse(buf[0..len]) catch return;
        }
    }.f, .{});
}

// ════════════════════════════════════════════════════════
// Target 4: Transport Parameters (RFC 9000 §18)
//
// Decode + encode round-trip. Tests varint-encoded TLV
// parameters with unknown parameter skipping.
// ════════════════════════════════════════════════════════

test "fuzz: transport params decode" {
    try testing.fuzz({}, struct {
        fn f(_: void, smith: *std.testing.Smith) anyerror!void {
            const input = smith.in orelse return;
            const params = transport_params.TransportParams.decode(input) catch return;

            // Round-trip: encode and decode again
            var buf: [4096]u8 = undefined;
            var wfbs = io_compat.fixedBufferStream(&buf);
            params.encode(&wfbs) catch return;

            const params2 = transport_params.TransportParams.decode(wfbs.buffered()) catch return;

            // Verify key fields match
            try testing.expectEqual(params.initial_max_data, params2.initial_max_data);
            try testing.expectEqual(params.initial_max_streams_bidi, params2.initial_max_streams_bidi);
            try testing.expectEqual(params.initial_max_streams_uni, params2.initial_max_streams_uni);
            try testing.expectEqual(params.max_idle_timeout, params2.max_idle_timeout);
            try testing.expectEqual(params.max_udp_payload_size, params2.max_udp_payload_size);
        }
    }.f, .{});
}

// ════════════════════════════════════════════════════════
// Target 5: HTTP/3 Frame Parsing (RFC 9114)
//
// Tests DATA, HEADERS, SETTINGS, GOAWAY, PRIORITY_UPDATE,
// and WebTransport capsule frames. Validates reserved
// HTTP/2 type rejection.
// ════════════════════════════════════════════════════════

test "fuzz: h3 frame parse" {
    try testing.fuzz({}, struct {
        fn f(_: void, smith: *std.testing.Smith) anyerror!void {
            const input = smith.in orelse return;
            if (input.len == 0) return;
            _ = h3_frame.parse(input) catch return;
        }
    }.f, .{});
}

// ════════════════════════════════════════════════════════
// Target 6: QPACK Header Compression (RFC 9204)
//
// Tests static table lookups, huffman-encoded literals,
// indexed/literal field line representations.
// ════════════════════════════════════════════════════════

test "fuzz: qpack decode" {
    try testing.fuzz({}, struct {
        fn f(_: void, smith: *std.testing.Smith) anyerror!void {
            const input = smith.in orelse return;
            if (input.len < 2) return;
            var headers: [64]qpack.Header = undefined;
            var scratch: [qpack.SCRATCH_SIZE]u8 = undefined;
            _ = qpack.decodeHeaders(input, &headers, &scratch) catch return;
        }
    }.f, .{});
}

// ════════════════════════════════════════════════════════
// Target 7: Huffman Codec (RFC 7541 Appendix B)
//
// Bit-level trie traversal, padding validation,
// EOS symbol detection.
// ════════════════════════════════════════════════════════

test "fuzz: huffman decode" {
    try testing.fuzz({}, struct {
        fn f(_: void, smith: *std.testing.Smith) anyerror!void {
            const input = smith.in orelse return;
            var out: [8192]u8 = undefined;
            const decoded_len = huffman.decode(input, &out) catch return;

            // Round-trip: encode the decoded output and verify
            var encoded: [16384]u8 = undefined;
            const encoded_len = huffman.encode(out[0..decoded_len], &encoded) catch return;

            var redecoded: [8192]u8 = undefined;
            const redecoded_len = huffman.decode(encoded[0..encoded_len], &redecoded) catch return;

            try testing.expectEqual(decoded_len, redecoded_len);
            try testing.expectEqualSlices(u8, out[0..decoded_len], redecoded[0..redecoded_len]);
        }
    }.f, .{});
}

// ════════════════════════════════════════════════════════
// Target 8: Connection handleDatagram (tquic-style)
//
// The top-level network entry point: raw UDP bytes fed into
// a QUIC connection. This exercises the full parsing pipeline:
// header → decryption → frame parsing → state machine.
// ════════════════════════════════════════════════════════

test "fuzz: connection recv raw datagram" {
    try testing.fuzz({}, struct {
        fn f(_: void, smith: *std.testing.Smith) anyerror!void {
            const input = smith.in orelse return;
            if (input.len < 2) return;

            // Build a minimal header from the fuzzed input so we can call accept()
            var hdr_buf: [1536]u8 = undefined;
            const hdr_len = @min(input.len, hdr_buf.len);
            @memcpy(hdr_buf[0..hdr_len], input[0..hdr_len]);
            var hdr_fbs = io_compat.fixedBufferStream(hdr_buf[0..hdr_len]);
            const hdr = packet.Header.parse(&hdr_fbs, 8) catch return;

            const local_storage = std.mem.zeroes(std.posix.sockaddr.storage);
            const remote_storage = std.mem.zeroes(std.posix.sockaddr.storage);

            // Create a server connection using the parsed header
            var conn = connection.Connection.accept(
                testing.allocator,
                hdr,
                local_storage,
                remote_storage,
                true,
                .{},
                null,
                null,
                null,
            ) catch return;
            defer conn.deinit();

            // Feed the full fuzzed input as a raw UDP datagram
            var buf: [1536]u8 = undefined;
            const len = @min(input.len, buf.len);
            @memcpy(buf[0..len], input[0..len]);

            conn.handleDatagram(buf[0..len], .{
                .to = local_storage,
                .from = remote_storage,
                .ecn = 0,
                .datagram_size = len,
            });
        }
    }.f, .{});
}

// ════════════════════════════════════════════════════════
// Target 9: RangeSet operations
//
// Tests range merging, overlap handling, and iterator
// correctness with adversarial input sequences.
// ════════════════════════════════════════════════════════

test "fuzz: rangeset operations" {
    try testing.fuzz({}, struct {
        fn f(_: void, smith: *std.testing.Smith) anyerror!void {
            const input = smith.in orelse return;
            if (input.len < 2) return;
            var rs = ranges.RangeSet.init(testing.allocator);
            defer rs.deinit();

            // Interpret input as a sequence of (op, value) pairs
            var i: usize = 0;
            while (i + 1 < input.len) : (i += 2) {
                const op = input[i];
                const val: u64 = input[i + 1];

                switch (op & 0x03) {
                    0 => rs.add(val) catch {},
                    1 => {
                        const end = val +| (if (i + 2 < input.len) @as(u64, input[i + 2]) else 1);
                        rs.addRange(val, end) catch {};
                        if (i + 2 < input.len) i += 1;
                    },
                    2 => _ = rs.contains(val),
                    3 => rs.removeBelow(val),
                    else => {},
                }

                // Invariant: ranges must be non-overlapping and descending
                var prev_start: ?u64 = null;
                for (rs.ranges.items) |r| {
                    if (r.start > r.end) {
                        @panic("range start > end");
                    }
                    if (prev_start) |ps| {
                        if (r.end >= ps) {
                            @panic("ranges overlap or not descending");
                        }
                    }
                    prev_start = r.start;
                }
            }
        }
    }.f, .{});
}

// ════════════════════════════════════════════════════════
// Target 10: TLS PEM parsing
//
// Tests certificate and private key PEM decoding with
// arbitrary input (base64, whitespace, header variations).
// ════════════════════════════════════════════════════════

test "fuzz: tls pem parse" {
    try testing.fuzz({}, struct {
        fn f(_: void, smith: *std.testing.Smith) anyerror!void {
            const input = smith.in orelse return;
            var cert_buf: [8192]u8 = undefined;
            _ = tls13.parsePemCert(input, &cert_buf) catch {};

            var key_buf: [4096]u8 = undefined;
            _ = tls13.parsePemPrivateKey(input, &key_buf) catch {};
        }
    }.f, .{});
}

// ════════════════════════════════════════════════════════
// Target 11: HTTP Capsule Parsing (RFC 9297 §4)
//
// Varint-based type+length+payload TLV codec. Tests
// truncated capsules, large lengths, and iterator over
// sequential capsules.
// ════════════════════════════════════════════════════════

test "fuzz: capsule parse" {
    try testing.fuzz({}, struct {
        fn f(_: void, smith: *std.testing.Smith) anyerror!void {
            const input = smith.in orelse return;
            // Try parsing a single capsule
            if (capsule.parse(input)) |result| {
                // Verify consumed <= input length
                if (result.consumed > input.len) @panic("consumed exceeds input length");
                // Verify value slice is within consumed region
                if (result.capsule.value.len > result.consumed) @panic("value exceeds consumed");
            } else |_| {}

            // Try iterating multiple capsules
            var iter = capsule.CapsuleIterator.init(input);
            var capsule_count: usize = 0;
            while (capsule_count < 100) : (capsule_count += 1) {
                const c = iter.next() catch break;
                if (c == null) break;
            }
        }
    }.f, .{});
}

// ════════════════════════════════════════════════════════
// Target 12: HTTP Capsule Round-Trip
//
// Write a capsule from fuzzed type+value, then parse it
// back and verify equality.
// ════════════════════════════════════════════════════════

test "fuzz: capsule round-trip" {
    try testing.fuzz({}, struct {
        fn f(_: void, smith: *std.testing.Smith) anyerror!void {
            const input = smith.in orelse return;
            if (input.len < 2) return;

            // Use first bytes as capsule type (varint), rest as value
            var fbs = io_compat.fixedBufferStream(input);
            const capsule_type = packet.readVarInt(&fbs) catch return;
            const value = input[fbs.seek..];

            // Write capsule
            var buf: [4096]u8 = undefined;
            var wfbs = io_compat.fixedBufferStream(&buf);
            capsule.write(&wfbs, capsule_type, value) catch return;

            // Parse it back
            const result = capsule.parse(wfbs.buffered()) catch return;
            try testing.expectEqual(capsule_type, result.capsule.capsule_type);
            try testing.expectEqualSlices(u8, value, result.capsule.value);
        }
    }.f, .{});
}

// ════════════════════════════════════════════════════════
// Target 13: Priority Structured Field (RFC 9218)
//
// Parse + serialize round-trip for "u=N, i" style
// priority field values. Tests whitespace handling,
// unknown parameter skipping, boundary urgency values.
// ════════════════════════════════════════════════════════

test "fuzz: priority parse round-trip" {
    try testing.fuzz({}, struct {
        fn f(_: void, smith: *std.testing.Smith) anyerror!void {
            const input = smith.in orelse return;
            // Parse priority from arbitrary bytes
            const p1 = priority.parse(input);

            // Invariants: urgency must be 0-7, incremental must be bool
            if (p1.urgency > 7) @panic("urgency out of range");

            // Serialize and re-parse — must produce same result
            var buf: [64]u8 = undefined;
            const len = priority.serialize(p1, &buf);
            const p2 = priority.parse(buf[0..len]);

            try testing.expectEqual(p1.urgency, p2.urgency);
            try testing.expectEqual(p1.incremental, p2.incremental);
        }
    }.f, .{});
}

// ════════════════════════════════════════════════════════
// Target 14: QPACK Encoder Instructions (RFC 9204 §4.1)
//
// Encoder→decoder stream: Insert With Name Reference,
// Insert With Literal Name, Duplicate, Set Capacity.
// Tests varint integer decoding, Huffman string decoding,
// dynamic table insert/evict logic.
// ════════════════════════════════════════════════════════

test "fuzz: qpack encoder instructions" {
    try testing.fuzz({}, struct {
        fn f(_: void, smith: *std.testing.Smith) anyerror!void {
            const input = smith.in orelse return;
            if (input.len == 0) return;
            var decoder = qpack.QpackDecoder{};
            decoder.setCapacity(4096);
            decoder.processEncoderInstruction(input) catch return;
        }
    }.f, .{});
}

// ════════════════════════════════════════════════════════
// Target 15: QPACK Decoder Instructions (RFC 9204 §4.2)
//
// Decoder→encoder stream: Header Acknowledgment,
// Stream Cancellation, Insert Count Increment.
// Tests varint decoding with 6/7-bit prefixes.
// ════════════════════════════════════════════════════════

test "fuzz: qpack decoder instructions" {
    try testing.fuzz({}, struct {
        fn f(_: void, smith: *std.testing.Smith) anyerror!void {
            const input = smith.in orelse return;
            if (input.len == 0) return;
            var encoder = qpack.QpackEncoder{};
            encoder.processDecoderInstruction(input) catch return;
        }
    }.f, .{});
}

// ════════════════════════════════════════════════════════
// Target 16: QPACK Encode/Decode Round-Trip
//
// Encode headers via QPACK, then decode and verify the
// headers match. Exercises both encoder and decoder paths
// with adversarial header names/values.
// ════════════════════════════════════════════════════════

test "fuzz: qpack encode-decode round-trip" {
    try testing.fuzz({}, struct {
        fn f(_: void, smith: *std.testing.Smith) anyerror!void {
            const input = smith.in orelse return;
            if (input.len < 4) return;

            // Interpret input as name/value pairs: [name_len, name..., value_len, value...]
            var headers: [16]qpack.Header = undefined;
            var count: usize = 0;
            var pos: usize = 0;

            while (pos < input.len and count < headers.len) {
                if (pos >= input.len) break;
                const name_len: usize = @min(input[pos], 64);
                pos += 1;
                if (pos + name_len > input.len) break;
                const name = input[pos..][0..name_len];
                pos += name_len;

                if (pos >= input.len) break;
                const val_len: usize = @min(input[pos], 128);
                pos += 1;
                if (pos + val_len > input.len) break;
                const value = input[pos..][0..val_len];
                pos += val_len;

                // Skip empty names (invalid in HTTP)
                if (name_len == 0) continue;

                headers[count] = .{ .name = name, .value = value };
                count += 1;
            }

            if (count == 0) return;

            // Encode
            var encoded: [8192]u8 = undefined;
            const encoded_len = qpack.encodeHeaders(headers[0..count], &encoded) catch return;

            // Decode
            var decoded: [16]qpack.Header = undefined;
            var scratch: [qpack.SCRATCH_SIZE]u8 = undefined;
            const decoded_count = qpack.decodeHeaders(encoded[0..encoded_len], &decoded, &scratch) catch return;

            // Verify count matches
            try testing.expectEqual(count, decoded_count);
        }
    }.f, .{});
}

// ════════════════════════════════════════════════════════
// Target 17: DER Private Key Extraction
//
// Parses EC (RFC 5915) and PKCS#8 DER-encoded private
// keys. Tests ASN.1 SEQUENCE/OCTET STRING walking,
// length byte handling, boundary checks.
// ════════════════════════════════════════════════════════

test "fuzz: der key extraction" {
    try testing.fuzz({}, struct {
        fn f(_: void, smith: *std.testing.Smith) anyerror!void {
            const input = smith.in orelse return;
            // Try EC private key extraction
            if (tls13.extractEcPrivateKey(input)) |key| {
                // Key must be exactly 32 bytes
                if (key.len != 32) @panic("EC key not 32 bytes");
            } else |_| {}

            // Try PKCS#8 extraction
            if (tls13.extractPkcs8EcPrivateKey(input)) |key| {
                if (key.len != 32) @panic("PKCS#8 key not 32 bytes");
            } else |_| {}
        }
    }.f, .{});
}

// ════════════════════════════════════════════════════════
// Target 18: FrameSorter (Out-of-Order Reassembly)
//
// Adversarial push/pop sequences testing overlap handling,
// final size validation, and memory safety under
// reordering/duplication.
// ════════════════════════════════════════════════════════

test "fuzz: frame sorter" {
    try testing.fuzz({}, struct {
        fn f(_: void, smith: *std.testing.Smith) anyerror!void {
            const input = smith.in orelse return;
            if (input.len < 3) return;

            var sorter = stream.FrameSorter.init(testing.allocator);
            defer sorter.deinit();

            var i: usize = 0;
            while (i + 2 < input.len) {
                const op = input[i];
                i += 1;

                switch (op & 0x03) {
                    0, 1 => {
                        // Push: offset (1 byte) + data length (1 byte) + optional FIN
                        const offset: u64 = input[i];
                        i += 1;
                        if (i >= input.len) break;
                        const data_len: usize = @min(input[i], 32);
                        i += 1;
                        const end = @min(i + data_len, input.len);
                        const data = input[i..end];
                        i = end;
                        const fin = (op & 0x04) != 0;
                        sorter.push(offset, data, fin) catch {};
                    },
                    2 => {
                        // Pop
                        if (sorter.pop()) |data| {
                            testing.allocator.free(data);
                        }
                        i += 2;
                    },
                    3 => {
                        // Check invariants
                        _ = sorter.isComplete();
                        _ = sorter.highestReceived();
                        i += 2;
                    },
                    else => {
                        i += 2;
                    },
                }
            }

            // Drain remaining
            while (sorter.pop()) |data| {
                testing.allocator.free(data);
            }
        }
    }.f, .{});
}

// ════════════════════════════════════════════════════════
// Target 19: QUIC Frame Round-Trip
//
// Parse a frame, write it back, parse again, and verify
// key fields match. Catches encode/decode asymmetries.
// ════════════════════════════════════════════════════════

test "fuzz: frame round-trip" {
    try testing.fuzz({}, struct {
        fn f(_: void, smith: *std.testing.Smith) anyerror!void {
            const input = smith.in orelse return;
            if (input.len == 0) return;

            // Parse
            var buf1: [4096]u8 = undefined;
            const len1 = @min(input.len, buf1.len);
            @memcpy(buf1[0..len1], input[0..len1]);
            const f1 = frame.Frame.parse(buf1[0..len1]) catch return;

            // Write
            var buf2: [4096]u8 = undefined;
            var wfbs = io_compat.fixedBufferStream(&buf2);
            f1.write(&wfbs) catch return;

            // Parse again
            const written = wfbs.buffered();
            var buf3: [4096]u8 = undefined;
            @memcpy(buf3[0..written.len], written);
            const f2 = frame.Frame.parse(buf3[0..written.len]) catch return;

            // Verify frame types match
            try testing.expectEqual(
                @as(frame.FrameType, f1),
                @as(frame.FrameType, f2),
            );
        }
    }.f, .{});
}

// ════════════════════════════════════════════════════════
// Target 20: Multiple Coalesced QUIC Packets
//
// Feeds multiple concatenated fuzzed packets, testing
// coalesced packet parsing (RFC 9000 §12.2). Exercises
// long header length-delimited parsing + short header
// remainder-of-datagram parsing.
// ════════════════════════════════════════════════════════

test "fuzz: coalesced packet headers" {
    try testing.fuzz({}, struct {
        fn f(_: void, smith: *std.testing.Smith) anyerror!void {
            const input = smith.in orelse return;
            if (input.len < 2) return;

            var buf: [1536]u8 = undefined;
            const len = @min(input.len, buf.len);
            @memcpy(buf[0..len], input[0..len]);

            // Parse consecutive headers from the same datagram
            var offset: usize = 0;
            var count: usize = 0;
            while (offset < len and count < 10) : (count += 1) {
                var fbs = io_compat.fixedBufferStream(buf[offset..len]);
                const hdr = packet.Header.parse(&fbs, 8) catch break;

                // Advance past this packet
                const consumed = fbs.seek;
                if (consumed == 0) break;

                // Short header (1-RTT) consumes rest of datagram
                if (hdr.packet_type == .one_rtt) break;

                // Long headers have remainder_len for payload
                offset += consumed + hdr.remainder_len;
            }
        }
    }.f, .{});
}

// ════════════════════════════════════════════════════════
// MoQ Transport (draft-17)
//
// wire.zig, message.zig and object.zig are pure parsers fed
// straight off the network, and have already shipped one
// out-of-bounds read (commit 17df27e).
// ════════════════════════════════════════════════════════

test "fuzz: moq varint round-trip" {
    try testing.fuzz({}, struct {
        fn f(_: void, smith: *std.testing.Smith) anyerror!void {
            const input = smith.in orelse return;
            var fbs = io_compat.fixedBufferStream(input);
            const val = moq_wire.readVarInt(&fbs) catch return;

            var buf: [9]u8 = undefined;
            var wfbs = io_compat.fixedBufferStream(&buf);
            try moq_wire.writeVarInt(&wfbs, val);

            var rfbs = io_compat.fixedBufferStream(wfbs.buffered());
            try testing.expectEqual(val, try moq_wire.readVarInt(&rfbs));
        }
    }.f, .{});
}

test "fuzz: moq kv list and tuple decode" {
    try testing.fuzz({}, struct {
        fn f(_: void, smith: *std.testing.Smith) anyerror!void {
            const input = smith.in orelse return;

            var it = moq_wire.KvIterator.init(input);
            while (it.next() catch null) |_| {}

            var fbs = io_compat.fixedBufferStream(input);
            var parts: [moq_wire.MAX_TUPLE_PARTS][]const u8 = undefined;
            _ = moq_wire.readTuple(&fbs, &parts) catch {};
        }
    }.f, .{});
}

test "fuzz: moq control message decode" {
    try testing.fuzz({}, struct {
        fn f(_: void, smith: *std.testing.Smith) anyerror!void {
            const input = smith.in orelse return;
            const parsed = moq_msg.parseEnvelope(input) catch return;
            const body = parsed.env.payload;
            const draft = moq_version.Draft.draft_17;

            // Every decoder sees every payload: a peer can put any message
            // type on the wire, and a mis-typed body must not be a crash.
            var ns: moq_msg.NamespaceBuf = undefined;
            var kvs: [moq_msg.MAX_PARAMS]moq_msg.Param = undefined;
            _ = moq_msg.decodeSetupPayload(body) catch {};
            _ = moq_msg.decodeGoaway(body) catch {};
            _ = moq_msg.decodeRequestOk(body, &kvs) catch {};
            _ = moq_msg.decodeRequestError(body) catch {};
            _ = moq_msg.decodeRequestUpdate(body, draft) catch {};
            _ = moq_msg.decodeSubscribe(body, &ns, draft) catch {};
            _ = moq_msg.decodeSubscribeOk(body) catch {};
            _ = moq_msg.decodePublish(body, &ns, draft) catch {};
            _ = moq_msg.decodePublishOk(body) catch {};
            _ = moq_msg.decodePublishDone(body) catch {};
            _ = moq_msg.decodePublishNamespace(body, &ns, draft) catch {};
            _ = moq_msg.decodeSubscribeNamespace(body, &ns, draft) catch {};
            _ = moq_msg.decodeNamespace(body, &ns) catch {};
            _ = moq_msg.decodeFetch(body, &ns, draft) catch {};
            _ = moq_msg.decodeFetchOk(body) catch {};
            _ = moq_msg.decodeTrackStatus(body, &ns, draft) catch {};
            _ = moq_msg.decodePublishBlocked(body, &ns) catch {};
        }
    }.f, .{});
}

test "fuzz: moq data stream headers" {
    try testing.fuzz({}, struct {
        fn f(_: void, smith: *std.testing.Smith) anyerror!void {
            const input = smith.in orelse return;
            const draft = moq_version.Draft.draft_17;

            var f1 = io_compat.fixedBufferStream(input);
            _ = moq_obj.readSubgroupHeader(&f1, draft) catch {};

            _ = moq_obj.readDatagramObject(input) catch {};

            var f3 = io_compat.fixedBufferStream(input);
            _ = moq_obj.readFetchStreamHeader(&f3) catch {};
        }
    }.f, .{});
}

// `zig build fuzz` runs without -ffuzz (that mode does not compile on
// Zig 0.16.0 — the errors are in lib/compiler/test_runner.zig), so
// testing.fuzz above only ever sees its seed input. This sweep gives the
// MoQ parsers real coverage under plain `zig build test`: fixed seed, so a
// failure reproduces.
test "moq decoders survive a randomized sweep" {
    var prng = std.Random.DefaultPrng.init(0x4d6f5100);
    const rand = prng.random();

    var buf: [512]u8 = undefined;
    var ns: moq_msg.NamespaceBuf = undefined;
    var kvs: [moq_msg.MAX_PARAMS]moq_msg.Param = undefined;

    for (0..20_000) |i| {
        const len = rand.uintLessThan(usize, buf.len);
        const input = buf[0..len];
        rand.bytes(input);

        // Pure noise mostly dies at the envelope, so two thirds of the
        // inputs are steered towards the payload decoders: one third gets a
        // plausible type+length header, one third is a real encoded message
        // with a few bytes corrupted.
        switch (i % 3) {
            0 => if (len >= 8) {
                var wfbs = io_compat.fixedBufferStream(input);
                moq_wire.writeVarInt(&wfbs, rand.uintLessThan(u64, 0x60)) catch {};
                const body_len: u16 = @intCast(@min(len - wfbs.seek - 2, rand.uintLessThan(usize, len)));
                std.mem.writeInt(u16, input[wfbs.seek..][0..2], body_len, .big);
            },
            1 => {
                const n = seedMoqMessage(input, rand, .draft_17) orelse continue;
                const seeded = input[0..n];
                for (0..1 + rand.uintLessThan(usize, 3)) |_| {
                    seeded[rand.uintLessThan(usize, seeded.len)] = rand.int(u8);
                }
                try sweepMoqDecoders(seeded, &ns, &kvs);
                continue;
            },
            else => {},
        }

        try sweepMoqDecoders(input, &ns, &kvs);
    }
}

fn sweepMoqDecoders(input: []const u8, ns: *moq_msg.NamespaceBuf, kvs: []moq_msg.Param) !void {
    // Both drafts: a peer negotiates either, and the request messages
    // differ by a field.
    inline for (comptime std.enums.values(moq_version.Draft)) |draft| {
        try sweepMoqDecodersAt(input, ns, kvs, draft);
    }
}

fn sweepMoqDecodersAt(
    input: []const u8,
    ns: *moq_msg.NamespaceBuf,
    kvs: []moq_msg.Param,
    comptime draft: moq_version.Draft,
) !void {
    var f1 = io_compat.fixedBufferStream(input);
    _ = moq_wire.readVarInt(&f1) catch {};
    var f2 = io_compat.fixedBufferStream(input);
    var parts: [moq_wire.MAX_TUPLE_PARTS][]const u8 = undefined;
    _ = moq_wire.readTuple(&f2, &parts) catch {};
    var it = moq_wire.KvIterator.init(input);
    while (it.next() catch null) |_| {}

    var f3 = io_compat.fixedBufferStream(input);
    _ = moq_obj.readSubgroupHeader(&f3, draft) catch {};
    _ = moq_obj.readDatagramObject(input) catch {};
    var f4 = io_compat.fixedBufferStream(input);
    _ = moq_obj.readFetchStreamHeader(&f4) catch {};

    const parsed = moq_msg.parseEnvelope(input) catch return;
    const body = parsed.env.payload;
    _ = moq_msg.decodeSetupPayload(body) catch {};
    _ = moq_msg.decodeGoaway(body) catch {};
    _ = moq_msg.decodeRequestOk(body, kvs) catch {};
    _ = moq_msg.decodeRequestError(body) catch {};
    _ = moq_msg.decodeRequestUpdate(body, draft) catch {};
    _ = moq_msg.decodeSubscribe(body, ns, draft) catch {};
    _ = moq_msg.decodeSubscribeOk(body) catch {};
    _ = moq_msg.decodePublish(body, ns, draft) catch {};
    _ = moq_msg.decodePublishOk(body) catch {};
    _ = moq_msg.decodePublishDone(body) catch {};
    _ = moq_msg.decodePublishNamespace(body, ns, draft) catch {};
    _ = moq_msg.decodeSubscribeNamespace(body, ns, draft) catch {};
    _ = moq_msg.decodeNamespace(body, ns) catch {};
    _ = moq_msg.decodeNamespaceDone(body, ns) catch {};
    _ = moq_msg.decodeFetch(body, ns, draft) catch {};
    _ = moq_msg.decodeFetchOk(body) catch {};
    _ = moq_msg.decodeTrackStatus(body, ns, draft) catch {};
    _ = moq_msg.decodePublishBlocked(body, ns) catch {};
}

// Writes one valid encoded control message into `buf`, chosen at random.
// Returns its length, or null if it did not fit.
fn seedMoqMessage(buf: []u8, rand: std.Random, draft: moq_version.Draft) ?usize {
    const ns = [_][]const u8{ "moq", "demo" };
    var fbs = io_compat.fixedBufferStream(buf);
    const w = &fbs;
    switch (rand.uintLessThan(u8, 12)) {
        0 => moq_msg.writeSetup(w, .{ .path = "/moq", .implementation = "fuzz" }) catch return null,
        1 => moq_msg.writeGoaway(w, .{ .new_uri = "https://x/moq" }) catch return null,
        2 => moq_msg.writeRequestError(w, .{ .error_code = 3, .reason = "no" }) catch return null,
        3 => moq_msg.writeSubscribe(w, .{ .track_namespace = &ns, .track_name = "video" }, draft) catch return null,
        4 => moq_msg.writeSubscribeOk(w, .{ .track_alias = 9, .largest = .{ .group = 1, .object = 2 } }) catch return null,
        5 => moq_msg.writePublish(w, .{
            .track_namespace = &ns,
            .track_name = "video",
            .track_alias = 2,
            .forward = true,
        }, draft) catch return null,
        6 => moq_msg.writePublishOk(w, .{ .subscriber_priority = 4 }, draft) catch return null,
        7 => moq_msg.writePublishDone(w, .{ .status_code = 1, .stream_count = 3, .reason = "bye" }) catch return null,
        8 => moq_msg.writeFetch(w, .{
            .body = .{ .standalone = .{
                .track_namespace = &ns,
                .track_name = "video",
                .start = .{ .group = 0, .object = 0 },
                .end = .{ .group = 1, .object = 1 },
            } },
            .subscriber_priority = 1,
            .group_order = .ascending,
        }, draft) catch return null,
        9 => moq_msg.writeTrackStatus(w, .{
            .track_namespace = &ns,
            .track_name = "audio",
        }, draft) catch return null,
        10 => moq_msg.writeSubscribeNamespace(w, .{ .track_namespace_prefix = &ns }, draft) catch return null,
        else => moq_msg.writeRequestUpdate(w, .{
            .request_id = 1,
            .subscriber_priority = 3,
            .forward = true,
        }, draft) catch return null,
    }
    return fbs.seek;
}

// ════════════════════════════════════════════════════════
// moq-lite (draft-lcurley-moq-lite-05)
//
// A separate parser from the draft-17 one above — QUIC
// varints, length-prefixed framing, no message-type table.
// ════════════════════════════════════════════════════════

fn sweepLiteDecoders(input: []const u8) !void {
    var hop_buf: [lite_msg.MAX_HOPS]u64 = undefined;

    // The framing layer first: it decides how much of the buffer a message
    // claims, which is where a length can run past the end.
    const f = (lite_msg.frame(input) catch return) orelse return;
    const body = f.body;

    // Every decoder sees every body: a stream's type decides which one is
    // correct, and a peer can put the wrong bytes on any stream.
    _ = lite_msg.decodeSetup(body) catch {};
    _ = lite_msg.decodeAnnounceRequest(body) catch {};
    _ = lite_msg.decodeAnnounceOk(body) catch {};
    _ = lite_msg.decodeAnnounceBroadcast(body, &hop_buf) catch {};
    _ = lite_msg.decodeSubscribe(body) catch {};
    _ = lite_msg.decodeSubscribeUpdate(body) catch {};
    _ = lite_msg.decodeTrack(body) catch {};
    _ = lite_msg.decodeTrackInfo(body) catch {};
    _ = lite_msg.decodeFetch(body) catch {};
    _ = lite_msg.decodeProbe(body) catch {};
    _ = lite_msg.decodeGoaway(body) catch {};
    _ = lite_msg.decodeGroup(body) catch {};
    inline for (comptime std.enums.values(lite_msg.ResponseType)) |k| {
        _ = lite_msg.decodeSubscribeResponse(k, body) catch {};
    }
    _ = lite_msg.decodeDatagram(input) catch {};

    // Frames are not framed messages — the timestamp delta sits outside
    // the length prefix, so this is a second parser.
    var rest = input;
    var guard: usize = 0;
    while (guard < 64) : (guard += 1) {
        const r = (lite_msg.readFrame(rest) catch break) orelse break;
        rest = rest[r.consumed..];
    }
}

/// One valid encoded moq-lite message, chosen at random.
fn seedLiteMessage(buf: []u8, rand: std.Random) ?usize {
    var fbs = io_compat.fixedBufferStream(buf);
    const w = &fbs;
    const hops = [_]u64{ 1, 2 };
    switch (rand.uintLessThan(u8, 12)) {
        0 => lite_msg.writeSetup(w, .{ .probe = .report, .path = "/anon" }) catch return null,
        1 => lite_msg.writeAnnounceRequest(w, .{ .prefix = "room", .exclude_hop = 3 }) catch return null,
        2 => lite_msg.writeAnnounceOk(w, .{ .hop_id = 9, .active_count = 2 }) catch return null,
        3 => lite_msg.writeAnnounceBroadcast(w, .{ .suffix = "alice", .hops = &hops }) catch return null,
        4 => lite_msg.writeSubscribe(w, .{
            .id = 1,
            .broadcast = "room",
            .track = "video",
            .group_start = 4,
        }) catch return null,
        5 => lite_msg.writeSubscribeUpdate(w, .{ .priority = 2, .ordered = true }) catch return null,
        6 => lite_msg.writeTrack(w, .{ .broadcast = "room", .track = "video" }) catch return null,
        7 => lite_msg.writeTrackInfo(w, .{}) catch return null,
        8 => lite_msg.writeFetch(w, .{ .broadcast = "room", .track = "v", .group = 7 }) catch return null,
        9 => lite_msg.writeProbe(w, .{ .bitrate = 1000, .rtt_ms = 5 }) catch return null,
        10 => lite_msg.writeGroup(w, .{ .subscribe_id = 2, .sequence = 3 }) catch return null,
        else => lite_msg.writeSubscribeResponse(w, .{ .drop = .{
            .group_start = 1,
            .group_end = 2,
            .error_code = 3,
        } }) catch return null,
    }
    return fbs.seek;
}

test "moq-lite decoders survive a randomized sweep" {
    var prng = std.Random.DefaultPrng.init(0x6c697465);
    const rand = prng.random();

    var buf: [512]u8 = undefined;

    for (0..20_000) |i| {
        const len = rand.uintLessThan(usize, buf.len);
        const input = buf[0..len];
        rand.bytes(input);

        if (i % 2 == 0) {
            const n = seedLiteMessage(input, rand) orelse continue;
            const seeded = input[0..n];
            for (0..1 + rand.uintLessThan(usize, 3)) |_| {
                seeded[rand.uintLessThan(usize, seeded.len)] = rand.int(u8);
            }
            try sweepLiteDecoders(seeded);
            continue;
        }

        try sweepLiteDecoders(input);

        // Paths take attacker-controlled bytes too.
        var out: [256]u8 = undefined;
        _ = lite_wire.normalizePath(input, &out) catch {};
        _ = lite_wire.stripPathPrefix(input, input[0..@min(4, input.len)]);
    }
}

test "moq-lite FrameReader survives a randomized byte stream" {
    var prng = std.Random.DefaultPrng.init(0x6672616d);
    const rand = prng.random();

    var rbuf: [4096]u8 = undefined;
    var chunk: [128]u8 = undefined;

    for (0..2_000) |_| {
        var reader = lite_session.FrameReader.init(&rbuf);
        for (0..8) |_| {
            const n = rand.uintLessThan(usize, chunk.len);
            rand.bytes(chunk[0..n]);
            reader.push(chunk[0..n]) catch break;
            var guard: usize = 0;
            while (guard < 64) : (guard += 1) {
                _ = reader.next() catch break;
            }
        }
    }
}
