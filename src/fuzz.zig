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
const testing = std.testing;

const packet = @import("quic/packet.zig");
const frame = @import("quic/frame.zig");
const transport_params = @import("quic/transport_params.zig");
const h3_frame = @import("h3/frame.zig");
const qpack = @import("h3/qpack.zig");
const huffman = @import("h3/huffman.zig");
const ranges = @import("quic/ranges.zig");
const connection = @import("quic/connection.zig");
const tls13 = @import("quic/tls13.zig");

// ════════════════════════════════════════════════════════
// Target 1: QUIC Variable-Length Integer (RFC 9000 §16)
//
// Foundation of all QUIC parsing. Tests 1/2/4/8 byte
// encodings, boundary values, and round-trip consistency.
// ════════════════════════════════════════════════════════

test "fuzz: varint round-trip" {
    try testing.fuzz({}, struct {
        fn f(_: void, input: []const u8) anyerror!void {
            var fbs = std.io.fixedBufferStream(input);
            const reader = fbs.reader();
            const val = packet.readVarInt(reader) catch return;

            // Round-trip: encode the parsed value and decode again
            var buf: [8]u8 = undefined;
            var wfbs = std.io.fixedBufferStream(&buf);
            packet.writeVarInt(wfbs.writer(), val) catch return;

            var rfbs = std.io.fixedBufferStream(wfbs.getWritten());
            const val2 = packet.readVarInt(rfbs.reader()) catch return;
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
        fn f(_: void, input: []const u8) anyerror!void {
            if (input.len == 0) return;
            // Header.parse takes a mutable fbs; we need a mutable copy
            var buf: [1536]u8 = undefined;
            const len = @min(input.len, buf.len);
            @memcpy(buf[0..len], input[0..len]);
            var fbs = std.io.fixedBufferStream(buf[0..len]);

            // Try parsing with various short DCID lengths (0, 8, 20)
            for ([_]u8{ 0, 8, 20 }) |dcid_len| {
                fbs.pos = 0;
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
        fn f(_: void, input: []const u8) anyerror!void {
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
        fn f(_: void, input: []const u8) anyerror!void {
            const params = transport_params.TransportParams.decode(input) catch return;

            // Round-trip: encode and decode again
            var buf: [4096]u8 = undefined;
            var wfbs = std.io.fixedBufferStream(&buf);
            params.encode(wfbs.writer()) catch return;

            const params2 = transport_params.TransportParams.decode(wfbs.getWritten()) catch return;

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
        fn f(_: void, input: []const u8) anyerror!void {
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
        fn f(_: void, input: []const u8) anyerror!void {
            if (input.len < 2) return;
            var headers: [64]qpack.Header = undefined;
            _ = qpack.decodeHeaders(input, &headers) catch return;
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
        fn f(_: void, input: []const u8) anyerror!void {
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
        fn f(_: void, input: []const u8) anyerror!void {
            if (input.len < 2) return;

            // Build a minimal header from the fuzzed input so we can call accept()
            var hdr_buf: [1536]u8 = undefined;
            const hdr_len = @min(input.len, hdr_buf.len);
            @memcpy(hdr_buf[0..hdr_len], input[0..hdr_len]);
            var hdr_fbs = std.io.fixedBufferStream(hdr_buf[0..hdr_len]);
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
        fn f(_: void, input: []const u8) anyerror!void {
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
        fn f(_: void, input: []const u8) anyerror!void {
            var cert_buf: [8192]u8 = undefined;
            _ = tls13.parsePemCert(input, &cert_buf) catch {};

            var key_buf: [4096]u8 = undefined;
            _ = tls13.parsePemPrivateKey(input, &key_buf) catch {};
        }
    }.f, .{});
}
