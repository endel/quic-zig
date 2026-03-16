// Generate seed corpus files for fuzz testing.
// Run: zig run tools/gen_fuzz_corpus.zig

const std = @import("std");

fn writeCorpus(dir: std.fs.Dir, name: []const u8, data: []const u8) void {
    dir.writeFile(.{ .sub_path = name, .data = data }) catch {};
}

pub fn main() !void {
    var dir = try std.fs.cwd().openDir("fuzz/corpus", .{});
    defer dir.close();

    // VarInt encodings: 1-byte, 2-byte, 4-byte, 8-byte
    writeCorpus(dir, "varint_1byte", &.{0x25}); // 37
    writeCorpus(dir, "varint_2byte", &.{ 0x7b, 0xbd }); // 15293
    writeCorpus(dir, "varint_4byte", &.{ 0x9d, 0x7f, 0x3e, 0x7d }); // 494878333
    writeCorpus(dir, "varint_8byte", &.{ 0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c }); // big
    writeCorpus(dir, "varint_zero", &.{0x00});
    writeCorpus(dir, "varint_max_1byte", &.{0x3f}); // 63

    // QUIC Long Header (Initial packet)
    writeCorpus(dir, "long_header_initial", &.{
        0xc0,       // Long header, Initial type
        0x00, 0x00, 0x00, 0x01, // Version 1
        0x08, // DCID len = 8
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, // DCID
        0x00, // SCID len = 0
        0x00, // Token length = 0
        0x04, // Payload length = 4
        0x00, // Packet number
        0x06, // CRYPTO frame type
        0x00, // offset = 0
        0x00, // length = 0
    });

    // QUIC Short Header (1-RTT)
    writeCorpus(dir, "short_header_1rtt", &.{
        0x40,       // Short header, fixed bit set
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, // DCID (8 bytes)
        0x00, // Packet number
        0x01, // PING frame
    });

    // Frame seeds - one per type
    writeCorpus(dir, "frame_padding", &.{0x00}); // PADDING
    writeCorpus(dir, "frame_ping", &.{0x01}); // PING
    writeCorpus(dir, "frame_ack", &.{ 0x02, 0x05, 0x00, 0x00, 0x00 }); // ACK
    writeCorpus(dir, "frame_reset_stream", &.{ 0x04, 0x01, 0x00, 0x10 }); // RESET_STREAM
    writeCorpus(dir, "frame_stop_sending", &.{ 0x05, 0x01, 0x00 }); // STOP_SENDING
    writeCorpus(dir, "frame_crypto", &.{ 0x06, 0x00, 0x04, 'h', 'e', 'l', 'l' }); // CRYPTO
    writeCorpus(dir, "frame_new_token", &.{ 0x07, 0x04, 't', 'o', 'k', 'n' }); // NEW_TOKEN
    writeCorpus(dir, "frame_stream", &.{ 0x08, 0x00, 'h', 'i' }); // STREAM (minimal)
    writeCorpus(dir, "frame_stream_fin", &.{ 0x09, 0x00, 'h', 'i' }); // STREAM+FIN
    writeCorpus(dir, "frame_max_data", &.{ 0x10, 0x40, 0x00 }); // MAX_DATA
    writeCorpus(dir, "frame_max_stream_data", &.{ 0x11, 0x00, 0x40, 0x00 }); // MAX_STREAM_DATA
    writeCorpus(dir, "frame_max_streams_bidi", &.{ 0x12, 0x10 }); // MAX_STREAMS bidi
    writeCorpus(dir, "frame_connection_close", &.{ 0x1c, 0x00, 0x00, 0x00 }); // CONNECTION_CLOSE
    writeCorpus(dir, "frame_handshake_done", &.{0x1e}); // HANDSHAKE_DONE
    writeCorpus(dir, "frame_datagram", &.{ 0x31, 0x04, 'd', 'a', 't', 'a' }); // DATAGRAM_WITH_LENGTH
    writeCorpus(dir, "frame_path_challenge", &.{ 0x1a, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 }); // PATH_CHALLENGE
    writeCorpus(dir, "frame_new_cid", &.{
        0x18, // NEW_CONNECTION_ID
        0x01, // sequence = 1
        0x00, // retire prior to = 0
        0x08, // CID length = 8
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, // CID
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, // Stateless reset token
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    });

    // Transport parameters
    writeCorpus(dir, "tp_minimal", &.{
        0x04, 0x04, 0x80, 0x00, 0xff, 0xff, // initial_max_data = 65535
        0x08, 0x02, 0x40, 0x64, // initial_max_streams_bidi = 100
    });
    writeCorpus(dir, "tp_with_cid", &.{
        0x00, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, // original_dcid
        0x04, 0x04, 0x80, 0x00, 0xff, 0xff, // initial_max_data
    });

    // HTTP/3 frames
    writeCorpus(dir, "h3_data", &.{ 0x00, 0x05, 'h', 'e', 'l', 'l', 'o' }); // DATA
    writeCorpus(dir, "h3_headers", &.{ 0x01, 0x03, 0xc0, 0xc1, 0xd1 }); // HEADERS
    writeCorpus(dir, "h3_settings", &.{
        0x04, 0x08, // SETTINGS, length 8
        0x06, 0x40, 0x64, // MAX_FIELD_SECTION_SIZE = 100
        0x08, 0x01, // ENABLE_CONNECT_PROTOCOL = 1
        0x33, 0x01, // H3_DATAGRAM = 1
    });
    writeCorpus(dir, "h3_goaway", &.{ 0x07, 0x01, 0x00 }); // GOAWAY

    // QPACK
    writeCorpus(dir, "qpack_indexed", &.{ 0x00, 0x00, 0xc0 | 17 }); // :method = GET (static idx 17)
    writeCorpus(dir, "qpack_literal", &.{
        0x00, 0x00, // Required insert count = 0, delta base = 0
        0x27, 0x03, 'f', 'o', 'o', 0x03, 'b', 'a', 'r', // literal name+value
    });

    // Huffman
    writeCorpus(dir, "huffman_www", &.{ 0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff }); // "www.example.com"
    writeCorpus(dir, "huffman_empty", &.{});

    // PEM
    writeCorpus(dir, "pem_cert_header", "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n");
    writeCorpus(dir, "pem_key_header", "-----BEGIN EC PRIVATE KEY-----\nMHQ=\n-----END EC PRIVATE KEY-----\n");

    std.debug.print("Generated seed corpus in fuzz/corpus/\n", .{});
}
