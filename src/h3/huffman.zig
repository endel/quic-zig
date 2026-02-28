const std = @import("std");
const testing = std.testing;

pub const DecodeError = error{
    InvalidHuffmanEncoding,
    OutputBufferTooSmall,
    EosSymbolDecoded,
    InvalidPadding,
};

// RFC 7541 Appendix B - HPACK Huffman Code Table
// Each entry: { .code = bit pattern (MSB-aligned in u32), .bit_len = number of bits, .symbol = decoded byte }
const HuffmanEntry = struct {
    symbol: u16, // 0-255 for chars, 256 for EOS
    code: u32,
    bit_len: u8,
};

// All 257 entries from RFC 7541 Appendix B
const huffman_table = [257]HuffmanEntry{
    .{ .symbol = 0, .code = 0x1ff8, .bit_len = 13 },
    .{ .symbol = 1, .code = 0x7fffd8, .bit_len = 23 },
    .{ .symbol = 2, .code = 0xfffffe2, .bit_len = 28 },
    .{ .symbol = 3, .code = 0xfffffe3, .bit_len = 28 },
    .{ .symbol = 4, .code = 0xfffffe4, .bit_len = 28 },
    .{ .symbol = 5, .code = 0xfffffe5, .bit_len = 28 },
    .{ .symbol = 6, .code = 0xfffffe6, .bit_len = 28 },
    .{ .symbol = 7, .code = 0xfffffe7, .bit_len = 28 },
    .{ .symbol = 8, .code = 0xfffffe8, .bit_len = 28 },
    .{ .symbol = 9, .code = 0xffffea, .bit_len = 24 },
    .{ .symbol = 10, .code = 0x3ffffffc, .bit_len = 30 },
    .{ .symbol = 11, .code = 0xfffffe9, .bit_len = 28 },
    .{ .symbol = 12, .code = 0xfffffea, .bit_len = 28 },
    .{ .symbol = 13, .code = 0x3ffffffd, .bit_len = 30 },
    .{ .symbol = 14, .code = 0xfffffeb, .bit_len = 28 },
    .{ .symbol = 15, .code = 0xfffffec, .bit_len = 28 },
    .{ .symbol = 16, .code = 0xfffffed, .bit_len = 28 },
    .{ .symbol = 17, .code = 0xfffffee, .bit_len = 28 },
    .{ .symbol = 18, .code = 0xfffffef, .bit_len = 28 },
    .{ .symbol = 19, .code = 0xffffff0, .bit_len = 28 },
    .{ .symbol = 20, .code = 0xffffff1, .bit_len = 28 },
    .{ .symbol = 21, .code = 0xffffff2, .bit_len = 28 },
    .{ .symbol = 22, .code = 0xffffff3, .bit_len = 28 },
    .{ .symbol = 23, .code = 0xffffff4, .bit_len = 28 },
    .{ .symbol = 24, .code = 0xffffff5, .bit_len = 28 },
    .{ .symbol = 25, .code = 0xffffff6, .bit_len = 28 },
    .{ .symbol = 26, .code = 0xffffff7, .bit_len = 28 },
    .{ .symbol = 27, .code = 0xffffff8, .bit_len = 28 },
    .{ .symbol = 28, .code = 0xffffff9, .bit_len = 28 },
    .{ .symbol = 29, .code = 0xffffffa, .bit_len = 28 },
    .{ .symbol = 30, .code = 0xffffffb, .bit_len = 28 },
    .{ .symbol = 31, .code = 0xffffffc, .bit_len = 28 },
    .{ .symbol = 32, .code = 0x14, .bit_len = 6 },
    .{ .symbol = 33, .code = 0x3f8, .bit_len = 10 },
    .{ .symbol = 34, .code = 0x3f9, .bit_len = 10 },
    .{ .symbol = 35, .code = 0xffa, .bit_len = 12 },
    .{ .symbol = 36, .code = 0x1ff9, .bit_len = 13 },
    .{ .symbol = 37, .code = 0x15, .bit_len = 6 },
    .{ .symbol = 38, .code = 0xf8, .bit_len = 8 },
    .{ .symbol = 39, .code = 0x7fa, .bit_len = 11 },
    .{ .symbol = 40, .code = 0x3fa, .bit_len = 10 },
    .{ .symbol = 41, .code = 0x3fb, .bit_len = 10 },
    .{ .symbol = 42, .code = 0xf9, .bit_len = 8 },
    .{ .symbol = 43, .code = 0x7fb, .bit_len = 11 },
    .{ .symbol = 44, .code = 0xfa, .bit_len = 8 },
    .{ .symbol = 45, .code = 0x16, .bit_len = 6 },
    .{ .symbol = 46, .code = 0x17, .bit_len = 6 },
    .{ .symbol = 47, .code = 0x18, .bit_len = 6 },
    .{ .symbol = 48, .code = 0x0, .bit_len = 5 },
    .{ .symbol = 49, .code = 0x1, .bit_len = 5 },
    .{ .symbol = 50, .code = 0x2, .bit_len = 5 },
    .{ .symbol = 51, .code = 0x19, .bit_len = 6 },
    .{ .symbol = 52, .code = 0x1a, .bit_len = 6 },
    .{ .symbol = 53, .code = 0x1b, .bit_len = 6 },
    .{ .symbol = 54, .code = 0x1c, .bit_len = 6 },
    .{ .symbol = 55, .code = 0x1d, .bit_len = 6 },
    .{ .symbol = 56, .code = 0x1e, .bit_len = 6 },
    .{ .symbol = 57, .code = 0x1f, .bit_len = 6 },
    .{ .symbol = 58, .code = 0x5c, .bit_len = 7 },
    .{ .symbol = 59, .code = 0xfb, .bit_len = 8 },
    .{ .symbol = 60, .code = 0x7ffc, .bit_len = 15 },
    .{ .symbol = 61, .code = 0x20, .bit_len = 6 },
    .{ .symbol = 62, .code = 0xffb, .bit_len = 12 },
    .{ .symbol = 63, .code = 0x3fc, .bit_len = 10 },
    .{ .symbol = 64, .code = 0x1ffa, .bit_len = 13 },
    .{ .symbol = 65, .code = 0x21, .bit_len = 6 },
    .{ .symbol = 66, .code = 0x5d, .bit_len = 7 },
    .{ .symbol = 67, .code = 0x5e, .bit_len = 7 },
    .{ .symbol = 68, .code = 0x5f, .bit_len = 7 },
    .{ .symbol = 69, .code = 0x60, .bit_len = 7 },
    .{ .symbol = 70, .code = 0x61, .bit_len = 7 },
    .{ .symbol = 71, .code = 0x62, .bit_len = 7 },
    .{ .symbol = 72, .code = 0x63, .bit_len = 7 },
    .{ .symbol = 73, .code = 0x64, .bit_len = 7 },
    .{ .symbol = 74, .code = 0x65, .bit_len = 7 },
    .{ .symbol = 75, .code = 0x66, .bit_len = 7 },
    .{ .symbol = 76, .code = 0x67, .bit_len = 7 },
    .{ .symbol = 77, .code = 0x68, .bit_len = 7 },
    .{ .symbol = 78, .code = 0x69, .bit_len = 7 },
    .{ .symbol = 79, .code = 0x6a, .bit_len = 7 },
    .{ .symbol = 80, .code = 0x6b, .bit_len = 7 },
    .{ .symbol = 81, .code = 0x6c, .bit_len = 7 },
    .{ .symbol = 82, .code = 0x6d, .bit_len = 7 },
    .{ .symbol = 83, .code = 0x6e, .bit_len = 7 },
    .{ .symbol = 84, .code = 0x6f, .bit_len = 7 },
    .{ .symbol = 85, .code = 0x70, .bit_len = 7 },
    .{ .symbol = 86, .code = 0x71, .bit_len = 7 },
    .{ .symbol = 87, .code = 0x72, .bit_len = 7 },
    .{ .symbol = 88, .code = 0xfc, .bit_len = 8 },
    .{ .symbol = 89, .code = 0x73, .bit_len = 7 },
    .{ .symbol = 90, .code = 0xfd, .bit_len = 8 },
    .{ .symbol = 91, .code = 0x1ffb, .bit_len = 13 },
    .{ .symbol = 92, .code = 0x7fff0, .bit_len = 19 },
    .{ .symbol = 93, .code = 0x1ffc, .bit_len = 13 },
    .{ .symbol = 94, .code = 0x3ffc, .bit_len = 14 },
    .{ .symbol = 95, .code = 0x22, .bit_len = 6 },
    .{ .symbol = 96, .code = 0x7ffd, .bit_len = 15 },
    .{ .symbol = 97, .code = 0x3, .bit_len = 5 },
    .{ .symbol = 98, .code = 0x23, .bit_len = 6 },
    .{ .symbol = 99, .code = 0x4, .bit_len = 5 },
    .{ .symbol = 100, .code = 0x24, .bit_len = 6 },
    .{ .symbol = 101, .code = 0x5, .bit_len = 5 },
    .{ .symbol = 102, .code = 0x25, .bit_len = 6 },
    .{ .symbol = 103, .code = 0x26, .bit_len = 6 },
    .{ .symbol = 104, .code = 0x27, .bit_len = 6 },
    .{ .symbol = 105, .code = 0x6, .bit_len = 5 },
    .{ .symbol = 106, .code = 0x74, .bit_len = 7 },
    .{ .symbol = 107, .code = 0x75, .bit_len = 7 },
    .{ .symbol = 108, .code = 0x28, .bit_len = 6 },
    .{ .symbol = 109, .code = 0x29, .bit_len = 6 },
    .{ .symbol = 110, .code = 0x2a, .bit_len = 6 },
    .{ .symbol = 111, .code = 0x7, .bit_len = 5 },
    .{ .symbol = 112, .code = 0x2b, .bit_len = 6 },
    .{ .symbol = 113, .code = 0x76, .bit_len = 7 },
    .{ .symbol = 114, .code = 0x2c, .bit_len = 6 },
    .{ .symbol = 115, .code = 0x8, .bit_len = 5 },
    .{ .symbol = 116, .code = 0x9, .bit_len = 5 },
    .{ .symbol = 117, .code = 0x2d, .bit_len = 6 },
    .{ .symbol = 118, .code = 0x77, .bit_len = 7 },
    .{ .symbol = 119, .code = 0x78, .bit_len = 7 },
    .{ .symbol = 120, .code = 0x79, .bit_len = 7 },
    .{ .symbol = 121, .code = 0x7a, .bit_len = 7 },
    .{ .symbol = 122, .code = 0x7b, .bit_len = 7 },
    .{ .symbol = 123, .code = 0x7ffe, .bit_len = 15 },
    .{ .symbol = 124, .code = 0x7fc, .bit_len = 11 },
    .{ .symbol = 125, .code = 0x3ffd, .bit_len = 14 },
    .{ .symbol = 126, .code = 0x1ffd, .bit_len = 13 },
    .{ .symbol = 127, .code = 0xffffffd, .bit_len = 28 },
    .{ .symbol = 128, .code = 0xfffe0, .bit_len = 20 },
    .{ .symbol = 129, .code = 0xfffe1, .bit_len = 20 },
    .{ .symbol = 130, .code = 0xfffe2, .bit_len = 20 },
    .{ .symbol = 131, .code = 0xfffe3, .bit_len = 20 },
    .{ .symbol = 132, .code = 0xfffe4, .bit_len = 20 },
    .{ .symbol = 133, .code = 0xfffe5, .bit_len = 20 },
    .{ .symbol = 134, .code = 0xfffe6, .bit_len = 20 },
    .{ .symbol = 135, .code = 0xfffe7, .bit_len = 20 },
    .{ .symbol = 136, .code = 0xfffe8, .bit_len = 20 },
    .{ .symbol = 137, .code = 0xfffe9, .bit_len = 20 },
    .{ .symbol = 138, .code = 0xfffea, .bit_len = 20 },
    .{ .symbol = 139, .code = 0xfffeb, .bit_len = 20 },
    .{ .symbol = 140, .code = 0xfffec, .bit_len = 20 },
    .{ .symbol = 141, .code = 0xfffed, .bit_len = 20 },
    .{ .symbol = 142, .code = 0xfffee, .bit_len = 20 },
    .{ .symbol = 143, .code = 0xfffef, .bit_len = 20 },
    .{ .symbol = 144, .code = 0xffff0, .bit_len = 20 },
    .{ .symbol = 145, .code = 0xffff1, .bit_len = 20 },
    .{ .symbol = 146, .code = 0xffff2, .bit_len = 20 },
    .{ .symbol = 147, .code = 0xffff3, .bit_len = 20 },
    .{ .symbol = 148, .code = 0xffff4, .bit_len = 20 },
    .{ .symbol = 149, .code = 0xffff5, .bit_len = 20 },
    .{ .symbol = 150, .code = 0xffff6, .bit_len = 20 },
    .{ .symbol = 151, .code = 0xffff7, .bit_len = 20 },
    .{ .symbol = 152, .code = 0xffff8, .bit_len = 20 },
    .{ .symbol = 153, .code = 0xffff9, .bit_len = 20 },
    .{ .symbol = 154, .code = 0xffffa, .bit_len = 20 },
    .{ .symbol = 155, .code = 0xffffb, .bit_len = 20 },
    .{ .symbol = 156, .code = 0xffffc, .bit_len = 20 },
    .{ .symbol = 157, .code = 0xffffd, .bit_len = 20 },
    .{ .symbol = 158, .code = 0xffffe, .bit_len = 20 },
    .{ .symbol = 159, .code = 0xfffff, .bit_len = 20 },
    .{ .symbol = 160, .code = 0x100000, .bit_len = 21 },
    .{ .symbol = 161, .code = 0x100001, .bit_len = 21 },
    .{ .symbol = 162, .code = 0x100002, .bit_len = 21 },
    .{ .symbol = 163, .code = 0x100003, .bit_len = 21 },
    .{ .symbol = 164, .code = 0x100004, .bit_len = 21 },
    .{ .symbol = 165, .code = 0x100005, .bit_len = 21 },
    .{ .symbol = 166, .code = 0x100006, .bit_len = 21 },
    .{ .symbol = 167, .code = 0x100007, .bit_len = 21 },
    .{ .symbol = 168, .code = 0x100008, .bit_len = 21 },
    .{ .symbol = 169, .code = 0x100009, .bit_len = 21 },
    .{ .symbol = 170, .code = 0x10000a, .bit_len = 21 },
    .{ .symbol = 171, .code = 0x10000b, .bit_len = 21 },
    .{ .symbol = 172, .code = 0x10000c, .bit_len = 21 },
    .{ .symbol = 173, .code = 0x10000d, .bit_len = 21 },
    .{ .symbol = 174, .code = 0x10000e, .bit_len = 21 },
    .{ .symbol = 175, .code = 0x10000f, .bit_len = 21 },
    .{ .symbol = 176, .code = 0x100010, .bit_len = 21 },
    .{ .symbol = 177, .code = 0x100011, .bit_len = 21 },
    .{ .symbol = 178, .code = 0x100012, .bit_len = 21 },
    .{ .symbol = 179, .code = 0x100013, .bit_len = 21 },
    .{ .symbol = 180, .code = 0x100014, .bit_len = 21 },
    .{ .symbol = 181, .code = 0x100015, .bit_len = 21 },
    .{ .symbol = 182, .code = 0x100016, .bit_len = 21 },
    .{ .symbol = 183, .code = 0x100017, .bit_len = 21 },
    .{ .symbol = 184, .code = 0x100018, .bit_len = 21 },
    .{ .symbol = 185, .code = 0x100019, .bit_len = 21 },
    .{ .symbol = 186, .code = 0x10001a, .bit_len = 21 },
    .{ .symbol = 187, .code = 0x10001b, .bit_len = 21 },
    .{ .symbol = 188, .code = 0x10001c, .bit_len = 21 },
    .{ .symbol = 189, .code = 0x10001d, .bit_len = 21 },
    .{ .symbol = 190, .code = 0x10001e, .bit_len = 21 },
    .{ .symbol = 191, .code = 0x10001f, .bit_len = 21 },
    .{ .symbol = 192, .code = 0x100020, .bit_len = 21 },
    .{ .symbol = 193, .code = 0x100021, .bit_len = 21 },
    .{ .symbol = 194, .code = 0x100022, .bit_len = 21 },
    .{ .symbol = 195, .code = 0x100023, .bit_len = 21 },
    .{ .symbol = 196, .code = 0x100024, .bit_len = 21 },
    .{ .symbol = 197, .code = 0x100025, .bit_len = 21 },
    .{ .symbol = 198, .code = 0x100026, .bit_len = 21 },
    .{ .symbol = 199, .code = 0x100027, .bit_len = 21 },
    .{ .symbol = 200, .code = 0x100028, .bit_len = 21 },
    .{ .symbol = 201, .code = 0x100029, .bit_len = 21 },
    .{ .symbol = 202, .code = 0x10002a, .bit_len = 21 },
    .{ .symbol = 203, .code = 0x10002b, .bit_len = 21 },
    .{ .symbol = 204, .code = 0x10002c, .bit_len = 21 },
    .{ .symbol = 205, .code = 0x10002d, .bit_len = 21 },
    .{ .symbol = 206, .code = 0x10002e, .bit_len = 21 },
    .{ .symbol = 207, .code = 0x10002f, .bit_len = 21 },
    .{ .symbol = 208, .code = 0x100030, .bit_len = 21 },
    .{ .symbol = 209, .code = 0x100031, .bit_len = 21 },
    .{ .symbol = 210, .code = 0x100032, .bit_len = 21 },
    .{ .symbol = 211, .code = 0x100033, .bit_len = 21 },
    .{ .symbol = 212, .code = 0x100034, .bit_len = 21 },
    .{ .symbol = 213, .code = 0x100035, .bit_len = 21 },
    .{ .symbol = 214, .code = 0x100036, .bit_len = 21 },
    .{ .symbol = 215, .code = 0x100037, .bit_len = 21 },
    .{ .symbol = 216, .code = 0x100038, .bit_len = 21 },
    .{ .symbol = 217, .code = 0x100039, .bit_len = 21 },
    .{ .symbol = 218, .code = 0x10003a, .bit_len = 21 },
    .{ .symbol = 219, .code = 0x10003b, .bit_len = 21 },
    .{ .symbol = 220, .code = 0x10003c, .bit_len = 21 },
    .{ .symbol = 221, .code = 0x10003d, .bit_len = 21 },
    .{ .symbol = 222, .code = 0x10003e, .bit_len = 21 },
    .{ .symbol = 223, .code = 0x10003f, .bit_len = 21 },
    .{ .symbol = 224, .code = 0x100040, .bit_len = 21 },
    .{ .symbol = 225, .code = 0x100041, .bit_len = 21 },
    .{ .symbol = 226, .code = 0x100042, .bit_len = 21 },
    .{ .symbol = 227, .code = 0x100043, .bit_len = 21 },
    .{ .symbol = 228, .code = 0x100044, .bit_len = 21 },
    .{ .symbol = 229, .code = 0x100045, .bit_len = 21 },
    .{ .symbol = 230, .code = 0x100046, .bit_len = 21 },
    .{ .symbol = 231, .code = 0x100047, .bit_len = 21 },
    .{ .symbol = 232, .code = 0x100048, .bit_len = 21 },
    .{ .symbol = 233, .code = 0x100049, .bit_len = 21 },
    .{ .symbol = 234, .code = 0x10004a, .bit_len = 21 },
    .{ .symbol = 235, .code = 0x10004b, .bit_len = 21 },
    .{ .symbol = 236, .code = 0x10004c, .bit_len = 21 },
    .{ .symbol = 237, .code = 0x10004d, .bit_len = 21 },
    .{ .symbol = 238, .code = 0x10004e, .bit_len = 21 },
    .{ .symbol = 239, .code = 0x10004f, .bit_len = 21 },
    .{ .symbol = 240, .code = 0x100050, .bit_len = 21 },
    .{ .symbol = 241, .code = 0x100051, .bit_len = 21 },
    .{ .symbol = 242, .code = 0x100052, .bit_len = 21 },
    .{ .symbol = 243, .code = 0x100053, .bit_len = 21 },
    .{ .symbol = 244, .code = 0x100054, .bit_len = 21 },
    .{ .symbol = 245, .code = 0x100055, .bit_len = 21 },
    .{ .symbol = 246, .code = 0x100056, .bit_len = 21 },
    .{ .symbol = 247, .code = 0x100057, .bit_len = 21 },
    .{ .symbol = 248, .code = 0x100058, .bit_len = 21 },
    .{ .symbol = 249, .code = 0x100059, .bit_len = 21 },
    .{ .symbol = 250, .code = 0x10005a, .bit_len = 21 },
    .{ .symbol = 251, .code = 0x10005b, .bit_len = 21 },
    .{ .symbol = 252, .code = 0x10005c, .bit_len = 21 },
    .{ .symbol = 253, .code = 0x10005d, .bit_len = 21 },
    .{ .symbol = 254, .code = 0x10005e, .bit_len = 21 },
    .{ .symbol = 255, .code = 0x10005f, .bit_len = 21 },
    .{ .symbol = 256, .code = 0x3ffffffe, .bit_len = 30 }, // EOS
};

// Maximum number of trie nodes. Huffman codes range from 5 to 30 bits.
// The trie can have at most sum of all unique prefix paths, which is bounded.
// 1024 nodes is more than enough for the HPACK table.
const MAX_TRIE_NODES = 1024;

// Sentinel value for unallocated trie children.
const UNALLOCATED: u16 = 0xFFFF;

const TrieNode = struct {
    children: [2]u16, // index into trie array, UNALLOCATED if not set
    is_leaf: [2]bool,
    symbol: [2]u16,
};

const DecodeTrie = struct {
    nodes: [MAX_TRIE_NODES]TrieNode,
    count: u16,
};

fn buildDecodeTrie() DecodeTrie {
    @setEvalBranchQuota(100000);
    var trie: DecodeTrie = undefined;
    trie.count = 1;

    // Initialize all nodes
    for (&trie.nodes) |*node| {
        node.* = .{
            .children = .{ UNALLOCATED, UNALLOCATED },
            .is_leaf = .{ false, false },
            .symbol = .{ 0, 0 },
        };
    }

    for (huffman_table) |entry| {
        var node_idx: u16 = 0; // start at root

        // Walk the code from MSB to LSB
        var i: u8 = 0;
        while (i < entry.bit_len) : (i += 1) {
            const bit_pos = entry.bit_len - 1 - i;
            const bit: u1 = @intCast((entry.code >> @intCast(bit_pos)) & 1);

            if (i == entry.bit_len - 1) {
                // Last bit - this is a leaf
                trie.nodes[node_idx].is_leaf[bit] = true;
                trie.nodes[node_idx].symbol[bit] = entry.symbol;
            } else {
                // Intermediate bit - traverse or create child
                if (trie.nodes[node_idx].children[bit] == UNALLOCATED) {
                    // Allocate new node
                    const new_idx = trie.count;
                    trie.count += 1;
                    trie.nodes[node_idx].children[bit] = new_idx;
                }
                node_idx = trie.nodes[node_idx].children[bit];
            }
        }
    }

    return trie;
}

const decode_trie = buildDecodeTrie();

// EOS symbol value
const EOS_SYMBOL: u16 = 256;

/// Decode a Huffman-encoded byte slice according to RFC 7541 Appendix B.
/// Returns the number of decoded bytes written to out_buf.
/// Errors:
///   - InvalidHuffmanEncoding: bits do not form valid Huffman codes
///   - OutputBufferTooSmall: out_buf is not large enough
///   - EosSymbolDecoded: the EOS symbol appeared in the encoded data (RFC 7541 violation)
///   - InvalidPadding: trailing padding bits are not all 1s or exceed 7 bits
pub fn decode(encoded: []const u8, out_buf: []u8) DecodeError!usize {
    var out_pos: usize = 0;
    var node_idx: u16 = 0; // current position in trie (0 = root)
    var bits_in_current_code: u8 = 0; // how many bits consumed since last symbol

    for (encoded) |byte| {
        // Process each bit from MSB to LSB
        var bit_idx: u4 = 8;
        while (bit_idx > 0) {
            bit_idx -= 1;
            const bit: u1 = @intCast((byte >> @as(u3, @intCast(bit_idx))) & 1);
            bits_in_current_code += 1;

            if (decode_trie.nodes[node_idx].is_leaf[bit]) {
                const sym = decode_trie.nodes[node_idx].symbol[bit];
                if (sym == EOS_SYMBOL) {
                    return DecodeError.EosSymbolDecoded;
                }
                if (out_pos >= out_buf.len) {
                    return DecodeError.OutputBufferTooSmall;
                }
                out_buf[out_pos] = @intCast(sym);
                out_pos += 1;
                // Reset to root for next symbol
                node_idx = 0;
                bits_in_current_code = 0;
            } else {
                // Traverse to child
                const child = decode_trie.nodes[node_idx].children[bit];
                if (child == UNALLOCATED) {
                    return DecodeError.InvalidHuffmanEncoding;
                }
                node_idx = child;
            }
        }
    }

    // After processing all bytes, we should be back at the root, or the remaining bits
    // should be valid padding (all 1s, at most 7 bits). Per RFC 7541 Section 5.2:
    // "padding consisting of the most significant bits of the code for the EOS symbol"
    // The EOS code is 0x3ffffffe (30 bits, all 1s except the last bit), so padding is all 1s.
    if (node_idx != 0) {
        // We have leftover bits. Check that:
        // 1. There are at most 7 padding bits
        // 2. The padding bits are all 1s (i.e., we only traversed '1' branches from root)
        if (bits_in_current_code > 7) {
            return DecodeError.InvalidPadding;
        }
        // Verify all accumulated bits since last symbol were 1s.
        // We can check this by verifying we only went down '1' branches from root.
        // The simplest check: walk the same path from root using all 1s and see if we
        // reach the same node.
        var check_idx: u16 = 0;
        var i: u8 = 0;
        while (i < bits_in_current_code) : (i += 1) {
            if (decode_trie.nodes[check_idx].is_leaf[1]) {
                // If we hit a leaf on a '1' path before consuming all padding bits,
                // the padding is invalid (it would decode a symbol).
                return DecodeError.InvalidPadding;
            }
            const child = decode_trie.nodes[check_idx].children[1];
            if (child == UNALLOCATED) {
                return DecodeError.InvalidPadding;
            }
            check_idx = child;
        }
        if (check_idx != node_idx) {
            // The leftover bits are not all 1s
            return DecodeError.InvalidPadding;
        }
    }

    return out_pos;
}

/// Encode a byte slice using HPACK Huffman coding (RFC 7541 Appendix B).
/// Returns the number of encoded bytes written to out_buf.
pub fn encode(input: []const u8, out_buf: []u8) DecodeError!usize {
    var out_pos: usize = 0;
    var current_byte: u8 = 0;
    var bits_left: u4 = 8; // bits remaining in current_byte

    for (input) |ch| {
        const entry = huffman_table[ch];
        var code = entry.code;
        var code_len = entry.bit_len;

        while (code_len > 0) {
            if (out_pos >= out_buf.len and bits_left == 8) {
                return DecodeError.OutputBufferTooSmall;
            }

            if (code_len >= bits_left) {
                // Fill the rest of current_byte
                const shift_amount = code_len - bits_left;
                current_byte |= @intCast((code >> @intCast(shift_amount)) & ((@as(u32, 1) << bits_left) - 1));
                code_len -= bits_left;
                // Mask off the bits we just used
                if (code_len < 32) {
                    code &= (@as(u32, 1) << @intCast(code_len)) -% 1;
                }
                if (out_pos >= out_buf.len) {
                    return DecodeError.OutputBufferTooSmall;
                }
                out_buf[out_pos] = current_byte;
                out_pos += 1;
                current_byte = 0;
                bits_left = 8;
            } else {
                // code_len < bits_left: shift code into the upper bits of remaining space
                const shift_amount = bits_left - @as(u4, @intCast(code_len));
                current_byte |= @as(u8, @intCast(code)) << @intCast(shift_amount);
                bits_left -= @as(u4, @intCast(code_len));
                code_len = 0;
            }
        }
    }

    // Pad with 1s to byte boundary (EOS prefix padding per RFC 7541 Section 5.2)
    if (bits_left < 8) {
        current_byte |= (@as(u8, 1) << @as(u3, @intCast(bits_left))) - 1;
        if (out_pos >= out_buf.len) {
            return DecodeError.OutputBufferTooSmall;
        }
        out_buf[out_pos] = current_byte;
        out_pos += 1;
    }

    return out_pos;
}

/// Return the encoded length in bytes for the given input (without actually encoding).
pub fn encodedLength(input: []const u8) usize {
    var total_bits: usize = 0;
    for (input) |ch| {
        total_bits += huffman_table[ch].bit_len;
    }
    // Round up to byte boundary
    return (total_bits + 7) / 8;
}

// ============================================================================
// Tests
// ============================================================================

// Verify the trie was built successfully at comptime
test "huffman trie built at comptime" {
    // The trie should have more than 1 node
    try testing.expect(decode_trie.count > 1);
    // Root should not be a leaf for both children
    // (5-bit codes start with various prefixes)
    try testing.expect(decode_trie.count < MAX_TRIE_NODES);
}

// Test decoding "www.example.com" - known test vector from RFC 7541 Section C.4.1
// The Huffman encoding of "www.example.com" is:
// f1e3 c2e5 f23a 6ba0 ab90 f4ff
test "decode www.example.com" {
    const encoded = [_]u8{ 0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff };
    var out: [256]u8 = undefined;
    const n = try decode(&encoded, &out);
    try testing.expectEqualStrings("www.example.com", out[0..n]);
}

// Test decoding "no-cache" - from RFC 7541 Section C.4.2
// Huffman encoding: a8eb 1064 9cbf
test "decode no-cache" {
    const encoded = [_]u8{ 0xa8, 0xeb, 0x10, 0x64, 0x9c, 0xbf };
    var out: [256]u8 = undefined;
    const n = try decode(&encoded, &out);
    try testing.expectEqualStrings("no-cache", out[0..n]);
}

// Test decoding "custom-key" from RFC 7541 Section C.4.3
// Huffman encoding: 25a8 49e9 5ba9 7d7f
test "decode custom-key" {
    const encoded = [_]u8{ 0x25, 0xa8, 0x49, 0xe9, 0x5b, 0xa9, 0x7d, 0x7f };
    var out: [256]u8 = undefined;
    const n = try decode(&encoded, &out);
    try testing.expectEqualStrings("custom-key", out[0..n]);
}

// Test decoding "custom-value" from RFC 7541 Section C.4.3
// Huffman encoding: 25a8 49e9 5bb8 e8b4 bf
test "decode custom-value" {
    const encoded = [_]u8{ 0x25, 0xa8, 0x49, 0xe9, 0x5b, 0xb8, 0xe8, 0xb4, 0xbf };
    var out: [256]u8 = undefined;
    const n = try decode(&encoded, &out);
    try testing.expectEqualStrings("custom-value", out[0..n]);
}

// Test encoding then decoding roundtrip
test "encode-decode roundtrip" {
    const test_strings = [_][]const u8{
        "www.example.com",
        "no-cache",
        "custom-key",
        "custom-value",
        "/",
        "GET",
        "https",
        ":status",
        "200",
        "hello, world!",
        "0123456789",
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
        "abcdefghijklmnopqrstuvwxyz",
    };

    for (test_strings) |input| {
        var enc_buf: [512]u8 = undefined;
        const enc_len = try encode(input, &enc_buf);

        var dec_buf: [512]u8 = undefined;
        const dec_len = try decode(enc_buf[0..enc_len], &dec_buf);

        try testing.expectEqualStrings(input, dec_buf[0..dec_len]);
    }
}

// Test that encodedLength matches actual encode output
test "encodedLength matches encode" {
    const test_strings = [_][]const u8{
        "www.example.com",
        "no-cache",
        "GET",
        "/index.html",
    };

    for (test_strings) |input| {
        var enc_buf: [512]u8 = undefined;
        const enc_len = try encode(input, &enc_buf);
        try testing.expectEqual(encodedLength(input), enc_len);
    }
}

// Test empty input
test "decode empty input" {
    const encoded = [_]u8{};
    var out: [256]u8 = undefined;
    const n = try decode(&encoded, &out);
    try testing.expectEqual(@as(usize, 0), n);
}

// Test output buffer too small
test "decode output buffer too small" {
    // "www.example.com" is 15 bytes decoded
    const encoded = [_]u8{ 0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff };
    var out: [5]u8 = undefined;
    const result = decode(&encoded, &out);
    try testing.expectError(DecodeError.OutputBufferTooSmall, result);
}

// Test that single ASCII characters encode/decode correctly
test "single character roundtrip" {
    var enc_buf: [8]u8 = undefined;
    var dec_buf: [4]u8 = undefined;

    // Test a few representative characters
    const chars = [_]u8{ '0', 'a', 'A', ' ', '/', ':', '-', '.' };
    for (chars) |ch| {
        const input = [_]u8{ch};
        const enc_len = try encode(&input, &enc_buf);
        const dec_len = try decode(enc_buf[0..enc_len], &dec_buf);
        try testing.expectEqual(@as(usize, 1), dec_len);
        try testing.expectEqual(ch, dec_buf[0]);
    }
}

// Verify the www.example.com encoding matches the RFC test vector
test "encode www.example.com matches RFC" {
    var enc_buf: [256]u8 = undefined;
    const enc_len = try encode("www.example.com", &enc_buf);
    const expected = [_]u8{ 0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff };
    try testing.expectEqual(expected.len, enc_len);
    try testing.expectEqualSlices(u8, &expected, enc_buf[0..enc_len]);
}
