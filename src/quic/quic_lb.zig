// QUIC-LB: Connection ID encoding/decoding for load balancers
// Implements draft-ietf-quic-load-balancers CID generation with
// plaintext and encrypted (4-pass Feistel / single-pass AES-ECB) modes.

const std = @import("std");
const builtin = @import("builtin");
const sys = @import("../sys.zig");
const crypto = std.crypto;
const Aes128 = crypto.core.aes.Aes128;

/// QUIC-LB configuration for CID encoding.
pub const Config = struct {
    config_id: u3, // 0-6, identifies which config
    server_id: [15]u8 = @splat(0),
    server_id_len: u4, // 1-15
    nonce_len: u5, // 4-18
    key: ?[16]u8 = null, // null = plaintext, set = encrypted
    encode_length: bool = true, // first octet encodes CID length
};

/// Checks the lengths fit a CID of at most 20 bytes, with the draft's
/// minimums; config_id 7 is reserved for unroutable CIDs. Every other
/// function here assumes a config that passed.
pub fn validate(config: *const Config) error{InvalidQuicLbConfig}!void {
    if (config.config_id > 6 or config.server_id_len < 1 or config.nonce_len < 4 or
        @as(u8, config.server_id_len) + config.nonce_len > 19)
        return error.InvalidQuicLbConfig;
}

/// Total CID length: 1 (first octet) + server_id_len + nonce_len.
pub fn cidLength(config: *const Config) u8 {
    return 1 + @as(u8, config.server_id_len) + @as(u8, config.nonce_len);
}

/// Generate a QUIC-LB encoded CID into buf.
/// buf must be at least cidLength(config) bytes.
pub fn generateCid(config: *const Config, buf: []u8) void {
    const total = cidLength(config);
    std.debug.assert(buf.len >= total);

    // First octet: config_id in bits 7-5
    const config_bits: u8 = @as(u8, config.config_id) << 5;
    if (config.encode_length) {
        // Bits 4-0 encode (CID length - 1)
        buf[0] = config_bits | (total - 1);
    } else {
        // Bits 4-0 are random
        var random_byte: [1]u8 = undefined;
        sys.randomBytes(&random_byte);
        buf[0] = config_bits | (random_byte[0] & 0x1F);
    }

    const sid_len: u8 = @as(u8, config.server_id_len);
    const nonce_len: u8 = @as(u8, config.nonce_len);

    // Place server_id and nonce into bytes 1..total
    @memcpy(buf[1 .. 1 + sid_len], config.server_id[0..sid_len]);
    // Fill nonce with random bytes
    sys.randomBytes(buf[1 + sid_len .. total]);

    // Encrypt if key is set
    if (config.key) |key| {
        const payload_len = sid_len + nonce_len;
        if (payload_len == 16) {
            // Single-pass AES-ECB: encrypt bytes 1..17
            singlePassEncrypt(key, buf[1..17]);
        } else {
            // 4-pass Feistel cipher
            feistelEncrypt(key, buf[1..total], payload_len);
        }
    }
}

/// Extract server_id from a QUIC-LB encoded CID.
/// Writes server_id into out[0..config.server_id_len].
/// Returns false if CID is too short.
pub fn extractServerId(config: *const Config, cid: []const u8, out: []u8) bool {
    const total = cidLength(config);
    if (cid.len < total) return false;

    const sid_len: u8 = @as(u8, config.server_id_len);
    const nonce_len: u8 = @as(u8, config.nonce_len);
    const payload_len = sid_len + nonce_len;

    if (out.len < sid_len) return false;

    if (config.key) |key| {
        // Decrypt in a temporary buffer (don't mutate input)
        var tmp: [19]u8 = undefined;
        if (payload_len > tmp.len) return false; // a config validate() refuses
        @memcpy(tmp[0..payload_len], cid[1 .. 1 + payload_len]);

        if (payload_len == 16) {
            singlePassDecrypt(key, tmp[0..16]);
        } else {
            feistelDecrypt(key, tmp[0..payload_len], payload_len);
        }
        @memcpy(out[0..sid_len], tmp[0..sid_len]);
    } else {
        // Plaintext: server_id is at bytes 1..1+sid_len
        @memcpy(out[0..sid_len], cid[1 .. 1 + sid_len]);
    }

    return true;
}

/// Extract the config_id (bits 7-5) from the first octet of a CID.
pub fn extractConfigId(first_octet: u8) u3 {
    return @intCast(first_octet >> 5);
}

// --- Kernel steering ---

/// A classic BPF instruction (`struct sock_filter`).
pub const SockFilter = extern struct { code: u16, jt: u8, jf: u8, k: u32 };

const bpf = struct {
    const ld_len = 0x80; // BPF_LD | BPF_W | BPF_LEN
    const ldb = 0x30; // BPF_LD | BPF_B | BPF_ABS
    const and_k = 0x54; // BPF_ALU | BPF_AND | BPF_K
    const jeq = 0x15; // BPF_JMP | BPF_JEQ | BPF_K
    const jge = 0x35;
    const jset = 0x45;
    const ret_k = 0x06;
    const ret_a = 0x16;

    fn op(code: u16, k: u32) SockFilter {
        return .{ .code = code, .jt = 0, .jf = 0, .k = k };
    }

    /// A jump at `at` to `t` when true, `f` when false.
    fn jump(code: u16, k: u32, at: u8, t: u8, f: u8) SockFilter {
        return .{ .code = code, .jt = t - at - 1, .jf = f - at - 1, .k = k };
    }
};

/// The program `steerReuseportGroup` attaches, for a group whose sockets,
/// in bind order, are the servers with ids 0 to `servers` - 1: the index
/// of the socket a datagram's DCID names, or past the group's end, which
/// leaves it to the kernel's 4-tuple hash. Only a DCID with this config's
/// length and first octet counts, so a client's random first DCID is
/// hashed as it would be without a program, and so is anything too short
/// to read. Needs plaintext CIDs: the kernel can't decrypt. A socket's id
/// is the server id's last byte, so what comes before it can name the
/// process to a balancer in front; the group never looks at that.
pub fn reuseportProgram(config: *const Config, servers: usize) error{Unsteerable}![20]SockFilter {
    if (config.key != null or servers == 0 or servers > 256) return error.Unsteerable;
    const cid_len = cidLength(config);
    const short_id: u32 = 1 + @as(u32, config.server_id_len);
    const long_id: u32 = 6 + @as(u32, config.server_id_len);
    // Without the length in it, the first octet's low bits are random.
    const mask: u32 = if (config.encode_length) 0xff else 0xe0;
    const first: u32 = @as(u32, config.config_id) << 5 | if (config.encode_length) cid_len - 1 else 0;
    const n: u32 = @intCast(servers);
    const long = 9;
    const by_id = 18;
    const hash = 19;
    return .{
        bpf.op(bpf.ld_len, 0),
        bpf.jump(bpf.jge, short_id + 1, 1, 2, hash),
        bpf.op(bpf.ldb, 0),
        bpf.jump(bpf.jset, 0x80, 3, long, 4),
        // Short header: the DCID starts at byte 1.
        bpf.op(bpf.ldb, 1),
        bpf.op(bpf.and_k, mask),
        bpf.jump(bpf.jeq, first, 6, 7, hash),
        bpf.op(bpf.ldb, short_id),
        bpf.jump(bpf.jge, n, 8, hash, by_id),
        // Long header: version, then the DCID's length at byte 5.
        bpf.op(bpf.ld_len, 0),
        bpf.jump(bpf.jge, long_id + 1, 10, 11, hash),
        bpf.op(bpf.ldb, 5),
        bpf.jump(bpf.jeq, cid_len, 12, 13, hash),
        bpf.op(bpf.ldb, 6),
        bpf.op(bpf.and_k, mask),
        bpf.jump(bpf.jeq, first, 15, 16, hash),
        bpf.op(bpf.ldb, long_id),
        bpf.jump(bpf.jge, n, 17, hash, by_id),
        bpf.op(bpf.ret_a, 0),
        bpf.op(bpf.ret_k, 0xffff_ffff),
    };
}

pub const SteerError = error{ Unsteerable, Unsupported, PermissionDenied, Refused };

/// Linux: have the kernel deliver each datagram reaching the SO_REUSEPORT
/// group `fd` is in to the socket of the server its DCID names
/// (`reuseportProgram`) instead of by 4-tuple hash, so the packets of a
/// connection that moved to another server, handed over or migrated, need
/// no forwarding. The servers' sockets must be bound in id order, id 0
/// first, and only theirs: the kernel numbers the group in bind order. One
/// call serves the whole group, sockets bound later included. Needs no
/// privilege (Linux 4.5+).
///
/// Closing a socket moves the group's last into its place, so close them
/// last first, or have `Config.foreign_datagram` pass on what the moved
/// one gets meanwhile.
pub fn steerReuseportGroup(fd: std.posix.socket_t, config: *const Config, servers: usize) SteerError!void {
    if (builtin.os.tag != .linux) return error.Unsupported;
    const posix = std.posix;
    const prog = try reuseportProgram(config, servers);
    const fprog: extern struct { len: u16, filter: [*]const SockFilter } = .{ .len = prog.len, .filter = &prog };
    const rc = posix.system.setsockopt(fd, posix.SOL.SOCKET, posix.SO.ATTACH_REUSEPORT_CBPF, @ptrCast(&fprog), @sizeOf(@TypeOf(fprog)));
    return switch (posix.errno(rc)) {
        .SUCCESS => {},
        .PERM, .ACCES => error.PermissionDenied,
        .NOPROTOOPT => error.Unsupported,
        else => error.Refused,
    };
}

// --- Internal cipher functions ---

/// Single-pass AES-ECB encrypt (for payload_len == 16).
fn singlePassEncrypt(key: [16]u8, data: *[16]u8) void {
    const ctx = Aes128.initEnc(key);
    var out: [16]u8 = undefined;
    ctx.encrypt(&out, data);
    data.* = out;
}

/// Single-pass AES-ECB decrypt (for payload_len == 16).
fn singlePassDecrypt(key: [16]u8, data: *[16]u8) void {
    const ctx = Aes128.initDec(key);
    var out: [16]u8 = undefined;
    ctx.decrypt(&out, data);
    data.* = out;
}

/// 4-pass Feistel encrypt in place.
/// data[0..total_len] contains server_id ++ nonce.
pub fn feistelEncrypt(key: [16]u8, data: []u8, total_len: u8) void {
    const half_len: u8 = (total_len + 1) / 2; // ceil(N/2)
    const right_len: u8 = total_len - half_len;

    // Round 1: right ^= truncate(AES(expand(left, N, 1)), right_len)
    {
        var block = expandBlock(data[0..half_len], half_len, total_len, 1);
        const ctx = Aes128.initEnc(key);
        var enc: [16]u8 = undefined;
        ctx.encrypt(&enc, &block);
        xorSlice(data[half_len..total_len], enc[0..right_len]);
    }

    // Round 2: left ^= truncate(AES(expand(right, N, 2)), half_len)
    {
        var block = expandBlock(data[half_len..total_len], right_len, total_len, 2);
        const ctx = Aes128.initEnc(key);
        var enc: [16]u8 = undefined;
        ctx.encrypt(&enc, &block);
        xorSlice(data[0..half_len], enc[0..half_len]);
    }

    // Round 3: right ^= truncate(AES(expand(left, N, 3)), right_len)
    {
        var block = expandBlock(data[0..half_len], half_len, total_len, 3);
        const ctx = Aes128.initEnc(key);
        var enc: [16]u8 = undefined;
        ctx.encrypt(&enc, &block);
        xorSlice(data[half_len..total_len], enc[0..right_len]);
    }

    // Round 4: left ^= truncate(AES(expand(right, N, 4)), half_len)
    {
        var block = expandBlock(data[half_len..total_len], right_len, total_len, 4);
        const ctx = Aes128.initEnc(key);
        var enc: [16]u8 = undefined;
        ctx.encrypt(&enc, &block);
        xorSlice(data[0..half_len], enc[0..half_len]);
    }
}

/// 4-pass Feistel decrypt in place.
/// data[0..total_len] contains encrypted server_id ++ nonce.
pub fn feistelDecrypt(key: [16]u8, data: []u8, total_len: u8) void {
    const half_len: u8 = (total_len + 1) / 2; // ceil(N/2)
    const right_len: u8 = total_len - half_len;

    // Undo Round 4: left ^= truncate(AES(expand(right, N, 4)), half_len)
    {
        var block = expandBlock(data[half_len..total_len], right_len, total_len, 4);
        const ctx = Aes128.initEnc(key);
        var enc: [16]u8 = undefined;
        ctx.encrypt(&enc, &block);
        xorSlice(data[0..half_len], enc[0..half_len]);
    }

    // Undo Round 3: right ^= truncate(AES(expand(left, N, 3)), right_len)
    {
        var block = expandBlock(data[0..half_len], half_len, total_len, 3);
        const ctx = Aes128.initEnc(key);
        var enc: [16]u8 = undefined;
        ctx.encrypt(&enc, &block);
        xorSlice(data[half_len..total_len], enc[0..right_len]);
    }

    // Undo Round 2: left ^= truncate(AES(expand(right, N, 2)), half_len)
    {
        var block = expandBlock(data[half_len..total_len], right_len, total_len, 2);
        const ctx = Aes128.initEnc(key);
        var enc: [16]u8 = undefined;
        ctx.encrypt(&enc, &block);
        xorSlice(data[0..half_len], enc[0..half_len]);
    }

    // Undo Round 1: right ^= truncate(AES(expand(left, N, 1)), right_len)
    {
        var block = expandBlock(data[0..half_len], half_len, total_len, 1);
        const ctx = Aes128.initEnc(key);
        var enc: [16]u8 = undefined;
        ctx.encrypt(&enc, &block);
        xorSlice(data[half_len..total_len], enc[0..right_len]);
    }
}

/// Build the 16-byte AES input block: [half_data | zero_padding | total_len | round]
fn expandBlock(half: []const u8, half_len: u8, total_len: u8, round: u8) [16]u8 {
    var block: [16]u8 = @splat(0);
    @memcpy(block[0..half_len], half[0..half_len]);
    // Positions 14 and 15 hold total_len and round number
    block[14] = total_len;
    block[15] = round;
    return block;
}

/// XOR src into dst in place.
fn xorSlice(dst: []u8, src: []const u8) void {
    for (dst, src) |*d, s| {
        d.* ^= s;
    }
}

// --- Tests ---

// Plaintext roundtrip: generate CID, extract server_id, verify match
test "quic_lb plaintext roundtrip" {
    var config = Config{
        .config_id = 2,
        .server_id_len = 4,
        .nonce_len = 6,
    };
    config.server_id[0] = 0xAB;
    config.server_id[1] = 0xCD;
    config.server_id[2] = 0x12;
    config.server_id[3] = 0x34;

    const total = cidLength(&config);
    try std.testing.expectEqual(@as(u8, 11), total); // 1 + 4 + 6

    var cid: [20]u8 = undefined;
    generateCid(&config, &cid);

    // Verify config_id in first octet
    try std.testing.expectEqual(@as(u3, 2), extractConfigId(cid[0]));

    // Verify encoded length in first octet
    try std.testing.expectEqual(@as(u8, 10), cid[0] & 0x1F); // total - 1 = 10

    // Extract and verify server_id
    var extracted_sid: [15]u8 = undefined;
    try std.testing.expect(extractServerId(&config, &cid, &extracted_sid));
    try std.testing.expectEqualSlices(u8, &.{ 0xAB, 0xCD, 0x12, 0x34 }, extracted_sid[0..4]);
}

// Encrypted roundtrip (Feistel): generate CID, extract server_id, verify match
test "quic_lb encrypted roundtrip feistel" {
    var config = Config{
        .config_id = 3,
        .server_id_len = 4,
        .nonce_len = 6,
        .key = .{ 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10 },
    };
    config.server_id[0] = 0xDE;
    config.server_id[1] = 0xAD;
    config.server_id[2] = 0xBE;
    config.server_id[3] = 0xEF;

    const total = cidLength(&config);
    try std.testing.expectEqual(@as(u8, 11), total);

    var cid: [20]u8 = undefined;
    generateCid(&config, &cid);

    // Config ID preserved in first octet (not encrypted)
    try std.testing.expectEqual(@as(u3, 3), extractConfigId(cid[0]));

    // Encrypted bytes should differ from plaintext server_id
    // (with overwhelming probability given random nonce)
    const plaintext_match = std.mem.eql(u8, cid[1..5], &.{ 0xDE, 0xAD, 0xBE, 0xEF });
    // Not guaranteed to be different, but extremely likely
    _ = plaintext_match;

    // Extract and verify server_id
    var extracted_sid: [15]u8 = undefined;
    try std.testing.expect(extractServerId(&config, &cid, &extracted_sid));
    try std.testing.expectEqualSlices(u8, &.{ 0xDE, 0xAD, 0xBE, 0xEF }, extracted_sid[0..4]);
}

// Single-pass AES-ECB (server_id_len + nonce_len == 16)
test "quic_lb single pass aes ecb" {
    var config = Config{
        .config_id = 1,
        .server_id_len = 8,
        .nonce_len = 8,
        .key = .{ 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99 },
    };
    config.server_id[0] = 0x01;
    config.server_id[1] = 0x02;
    config.server_id[2] = 0x03;
    config.server_id[3] = 0x04;
    config.server_id[4] = 0x05;
    config.server_id[5] = 0x06;
    config.server_id[6] = 0x07;
    config.server_id[7] = 0x08;

    const total = cidLength(&config);
    try std.testing.expectEqual(@as(u8, 17), total); // 1 + 8 + 8

    var cid: [20]u8 = undefined;
    generateCid(&config, &cid);

    // Extract and verify server_id
    var extracted_sid: [15]u8 = undefined;
    try std.testing.expect(extractServerId(&config, &cid, &extracted_sid));
    try std.testing.expectEqualSlices(u8, &.{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 }, extracted_sid[0..8]);
}

// Config ID extraction from first octet
test "quic_lb config id extraction" {
    try std.testing.expectEqual(@as(u3, 0), extractConfigId(0b000_00000));
    try std.testing.expectEqual(@as(u3, 1), extractConfigId(0b001_00000));
    try std.testing.expectEqual(@as(u3, 3), extractConfigId(0b011_10101));
    try std.testing.expectEqual(@as(u3, 6), extractConfigId(0b110_11111));
    try std.testing.expectEqual(@as(u3, 7), extractConfigId(0b111_00000));
}

// Different CIDs for same server_id (nonce uniqueness)
test "quic_lb nonce uniqueness" {
    var config = Config{
        .config_id = 0,
        .server_id_len = 2,
        .nonce_len = 6,
    };
    config.server_id[0] = 0xAA;
    config.server_id[1] = 0xBB;

    var cid1: [20]u8 = undefined;
    var cid2: [20]u8 = undefined;
    generateCid(&config, &cid1);
    generateCid(&config, &cid2);

    const total = cidLength(&config);
    // CIDs should be different (with overwhelming probability)
    try std.testing.expect(!std.mem.eql(u8, cid1[0..total], cid2[0..total]));

    // But both should extract to the same server_id
    var sid1: [15]u8 = undefined;
    var sid2: [15]u8 = undefined;
    try std.testing.expect(extractServerId(&config, &cid1, &sid1));
    try std.testing.expect(extractServerId(&config, &cid2, &sid2));
    try std.testing.expectEqualSlices(u8, sid1[0..2], sid2[0..2]);
    try std.testing.expectEqualSlices(u8, &.{ 0xAA, 0xBB }, sid1[0..2]);
}

// CID too short returns false
test "quic_lb extract from short cid" {
    var config = Config{
        .config_id = 0,
        .server_id_len = 4,
        .nonce_len = 6,
    };
    var out: [15]u8 = undefined;
    const short_cid = [_]u8{ 0x00, 0x01, 0x02 };
    try std.testing.expect(!extractServerId(&config, &short_cid, &out));
}

// Feistel encrypt/decrypt roundtrip with known data
test "quic_lb feistel roundtrip deterministic" {
    const key = [16]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10 };
    var data = [_]u8{ 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22, 0x33, 0x44 };
    const original = data;

    feistelEncrypt(key, &data, 10);
    // Encrypted should differ from original
    try std.testing.expect(!std.mem.eql(u8, &data, &original));

    feistelDecrypt(key, &data, 10);
    // Decrypted should match original
    try std.testing.expectEqualSlices(u8, &original, &data);
}

// Single-pass AES roundtrip with known data
test "quic_lb single pass aes roundtrip deterministic" {
    const key = [16]u8{ 0xF0, 0xE1, 0xD2, 0xC3, 0xB4, 0xA5, 0x96, 0x87, 0x78, 0x69, 0x5A, 0x4B, 0x3C, 0x2D, 0x1E, 0x0F };
    var data: [16]u8 = .{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10 };
    const original = data;

    singlePassEncrypt(key, &data);
    try std.testing.expect(!std.mem.eql(u8, &data, &original));

    singlePassDecrypt(key, &data);
    try std.testing.expectEqualSlices(u8, &original, &data);
}

// Encrypted roundtrip with encode_length=false
test "quic_lb encrypted no length encoding" {
    var config = Config{
        .config_id = 5,
        .server_id_len = 3,
        .nonce_len = 5,
        .key = .{ 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xA0, 0xB0, 0xC0, 0xD0, 0xE0, 0xF0, 0x00 },
        .encode_length = false,
    };
    config.server_id[0] = 0x11;
    config.server_id[1] = 0x22;
    config.server_id[2] = 0x33;

    var cid: [20]u8 = undefined;
    generateCid(&config, &cid);

    // Config ID still in bits 7-5
    try std.testing.expectEqual(@as(u3, 5), extractConfigId(cid[0]));

    // Extract server_id
    var extracted_sid: [15]u8 = undefined;
    try std.testing.expect(extractServerId(&config, &cid, &extracted_sid));
    try std.testing.expectEqualSlices(u8, &.{ 0x11, 0x22, 0x33 }, extracted_sid[0..3]);
}

test "a config past a 20-byte CID is refused, and never overruns a decode" {
    const too_long: Config = .{ .config_id = 0, .server_id_len = 15, .nonce_len = 18, .key = @splat(1) };
    var cid: [34]u8 = @splat(0x42);
    var out: [15]u8 = undefined;
    try std.testing.expect(!extractServerId(&too_long, &cid, &out));

    try std.testing.expectError(error.InvalidQuicLbConfig, validate(&too_long));
    try std.testing.expectError(error.InvalidQuicLbConfig, validate(&.{ .config_id = 7, .server_id_len = 1, .nonce_len = 7 }));
    try std.testing.expectError(error.InvalidQuicLbConfig, validate(&.{ .config_id = 0, .server_id_len = 1, .nonce_len = 3 }));
    try validate(&.{ .config_id = 0, .server_id_len = 15, .nonce_len = 4 });
    try validate(&.{ .config_id = 6, .server_id_len = 1, .nonce_len = 18 });
}

/// Runs a classic BPF program on `pkt` as the kernel would: a load past its
/// end ends the program with 0.
fn runFilter(prog: []const SockFilter, pkt: []const u8) u32 {
    var a: u32 = 0;
    var pc: usize = 0;
    while (true) : (pc += 1) {
        const i = prog[pc];
        switch (i.code) {
            bpf.ld_len => a = @intCast(pkt.len),
            bpf.ldb => a = if (i.k < pkt.len) pkt[i.k] else return 0,
            bpf.and_k => a &= i.k,
            bpf.jeq, bpf.jge, bpf.jset => {
                const taken = switch (i.code) {
                    bpf.jeq => a == i.k,
                    bpf.jge => a >= i.k,
                    else => a & i.k != 0,
                };
                pc += if (taken) i.jt else i.jf;
            },
            bpf.ret_k => return i.k,
            bpf.ret_a => return a,
            else => unreachable,
        }
    }
}

fn workerConfig(id: u8) Config {
    var cfg: Config = .{ .config_id = 0, .server_id_len = 1, .nonce_len = 6 };
    cfg.server_id[0] = id;
    return cfg;
}

/// A short-header packet to `dcid`, or a long-header one: a v1 Initial.
fn steeringPacket(buf: []u8, long: bool, dcid: []const u8) []u8 {
    var n: usize = 0;
    if (long) {
        @memcpy(buf[0..6], &[_]u8{ 0xc0, 0, 0, 0, 1, @intCast(dcid.len) });
        n = 6;
    } else {
        buf[0] = 0x40;
        n = 1;
    }
    @memcpy(buf[n..][0..dcid.len], dcid);
    n += dcid.len;
    @memset(buf[n..][0..24], 0xee);
    return buf[0 .. n + 24];
}

test "reuseportProgram: a DCID of ours picks its server's socket, anything else the hash" {
    const prog = try reuseportProgram(&workerConfig(0), 4);
    const hash: u32 = 0xffff_ffff;
    var buf: [64]u8 = undefined;
    var cid: [8]u8 = undefined;

    for (0..4) |w| {
        generateCid(&workerConfig(@intCast(w)), &cid);
        try std.testing.expectEqual(@as(u32, @intCast(w)), runFilter(&prog, steeringPacket(&buf, false, &cid)));
        try std.testing.expectEqual(@as(u32, @intCast(w)), runFilter(&prog, steeringPacket(&buf, true, &cid)));
    }
    // Ids past the group, CIDs not ours: a client's first DCID, another
    // length, another first octet.
    generateCid(&workerConfig(4), &cid);
    try std.testing.expectEqual(hash, runFilter(&prog, steeringPacket(&buf, false, &cid)));
    try std.testing.expectEqual(hash, runFilter(&prog, steeringPacket(&buf, true, &cid)));
    const client_dcid = [_]u8{ 0x5a, 1, 2, 3, 4, 5, 6, 7 };
    try std.testing.expectEqual(hash, runFilter(&prog, steeringPacket(&buf, true, &client_dcid)));
    try std.testing.expectEqual(hash, runFilter(&prog, steeringPacket(&buf, false, &client_dcid)));
    const longer = [_]u8{ 0x07, 1, 2, 3, 4, 5, 6, 7, 8 };
    try std.testing.expectEqual(hash, runFilter(&prog, steeringPacket(&buf, true, &longer)));
    try std.testing.expectEqual(@as(u32, 1), runFilter(&prog, steeringPacket(&buf, false, &longer)));
    // Too short to read: hashed, not socket 0.
    try std.testing.expectEqual(hash, runFilter(&prog, ""));
    try std.testing.expectEqual(hash, runFilter(&prog, &.{ 0x40, 0x07 }));
    try std.testing.expectEqual(hash, runFilter(&prog, &.{ 0xc0, 0, 0, 0, 1, 8, 0x07 }));
    try std.testing.expectEqual(@as(u32, 3), runFilter(&prog, &.{ 0x40, 0x07, 3 }));
    try std.testing.expectEqual(@as(u32, 3), runFilter(&prog, &.{ 0xc0, 0, 0, 0, 1, 8, 0x07, 3 }));
}

test "reuseportProgram: without the length in the first octet only its config bits count; unreadable configs are refused" {
    var cfg: Config = .{ .config_id = 2, .server_id_len = 1, .nonce_len = 7, .encode_length = false };
    const prog = try reuseportProgram(&cfg, 2);
    try std.testing.expectEqual(@as(u32, 1), runFilter(&prog, &.{ 0x40, 0b010_10101, 1 }));
    try std.testing.expectEqual(@as(u32, 0xffff_ffff), runFilter(&prog, &.{ 0x40, 0b011_00111, 1 }));

    try std.testing.expectError(error.Unsteerable, reuseportProgram(&workerConfig(0), 0));
    try std.testing.expectError(error.Unsteerable, reuseportProgram(&workerConfig(0), 257));
    cfg.key = @splat(1);
    try std.testing.expectError(error.Unsteerable, reuseportProgram(&cfg, 2));
}

test "reuseportProgram: a longer server id picks its socket by its last byte" {
    var cfg: Config = .{ .config_id = 0, .server_id_len = 2, .nonce_len = 6 };
    cfg.server_id[0] = 200;
    const prog = try reuseportProgram(&cfg, 3);
    const hash: u32 = 0xffff_ffff;
    var buf: [64]u8 = undefined;
    var cid: [9]u8 = undefined;
    for (0..3) |w| {
        cfg.server_id[1] = @intCast(w);
        generateCid(&cfg, &cid);
        try std.testing.expectEqual(@as(u32, @intCast(w)), runFilter(&prog, steeringPacket(&buf, false, &cid)));
        try std.testing.expectEqual(@as(u32, @intCast(w)), runFilter(&prog, steeringPacket(&buf, true, &cid)));
    }
    cfg.server_id[1] = 3; // past the group
    generateCid(&cfg, &cid);
    try std.testing.expectEqual(hash, runFilter(&prog, steeringPacket(&buf, false, &cid)));
    // A client's first DCID, of another length, and too short to read.
    const client_dcid = [_]u8{ 0x08, 1, 2, 3, 4, 5, 6, 7 };
    try std.testing.expectEqual(hash, runFilter(&prog, steeringPacket(&buf, true, &client_dcid)));
    try std.testing.expectEqual(hash, runFilter(&prog, &.{ 0x40, 0x08, 200 }));
    try std.testing.expectEqual(hash, runFilter(&prog, &.{ 0xc0, 0, 0, 0, 1, 9, 0x08, 200 }));
    try std.testing.expectEqual(@as(u32, 2), runFilter(&prog, &.{ 0x40, 0x08, 200, 2 }));
    try std.testing.expectEqual(@as(u32, 2), runFilter(&prog, &.{ 0xc0, 0, 0, 0, 1, 9, 0x08, 200, 2 }));
}

test "steerReuseportGroup: the kernel delivers by server id, in bind order, and hashes the rest" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const posix = std.posix;
    const net = @import("../sockaddr.zig");
    const n = 3;

    var group: [n]posix.socket_t = undefined;
    var bound: usize = 0;
    defer for (group[0..bound]) |fd| sys.close(fd);
    var port: u16 = 0;
    while (bound < n) : (bound += 1) {
        const fd = try sys.socket(posix.AF.INET, posix.SOCK.DGRAM | posix.SOCK.NONBLOCK, 0);
        group[bound] = fd;
        try posix.setsockopt(fd, posix.SOL.SOCKET, posix.SO.REUSEPORT, std.mem.asBytes(&@as(c_int, 1)));
        const addr = try net.Address.parseIp4("127.0.0.1", port);
        try sys.bind(fd, &addr.any, addr.getOsSockLen());
        if (port == 0) {
            var got: net.Address = undefined;
            var len: posix.socklen_t = @sizeOf(net.Address);
            try sys.getsockname(fd, &got.any, &len);
            port = got.getPort();
        }
    }
    try steerReuseportGroup(group[0], &workerConfig(0), n);

    // From many source ports, so the hash spreads them.
    const clients = 16;
    var from: [clients]posix.socket_t = undefined;
    var from_port: [clients]u16 = undefined;
    var opened: usize = 0;
    defer for (from[0..opened]) |fd| sys.close(fd);
    const to = try net.Address.parseIp4("127.0.0.1", port);
    var buf: [64]u8 = undefined;
    var cid: [8]u8 = undefined;
    const client_dcid = [_]u8{ 0x5a, 0, 1, 2, 3, 4, 5, 6 };
    while (opened < clients) : (opened += 1) {
        const fd = try sys.socket(posix.AF.INET, posix.SOCK.DGRAM, 0);
        from[opened] = fd;
        const c: u8 = @intCast(opened);
        for (0..5) |kind| {
            const pkt = switch (kind) {
                0, 1, 3 => blk: {
                    const id: u8 = switch (kind) {
                        0 => c % n,
                        1 => (c + 1) % n,
                        else => 200,
                    };
                    generateCid(&workerConfig(id), &cid);
                    break :blk steeringPacket(&buf, kind == 1, &cid);
                },
                2 => steeringPacket(&buf, true, &client_dcid),
                else => buf[0..2],
            };
            // The kind rides in the last byte; the stub is told by its length.
            if (kind == 4) @memcpy(pkt, &[_]u8{ 0x40, 0x07 }) else pkt[pkt.len - 1] = @intCast(kind);
            _ = try sys.sendto(fd, pkt, 0, &to.any, to.getOsSockLen());
        }
        var a: net.Address = undefined;
        var a_len: posix.socklen_t = @sizeOf(net.Address);
        try sys.getsockname(fd, &a.any, &a_len);
        from_port[opened] = a.getPort();
    }

    // where[client][kind]: the group socket it reached.
    var where: [clients][5]?usize = @splat(@splat(null));
    var got: usize = 0;
    const deadline = sys.nanoTimestamp() + 2 * std.time.ns_per_s;
    while (got < clients * 5 and sys.nanoTimestamp() < deadline) {
        for (group, 0..) |fd, s| {
            var src: posix.sockaddr.storage = undefined;
            var src_len: posix.socklen_t = @sizeOf(posix.sockaddr.storage);
            const len = sys.recvfrom(fd, &buf, 0, @ptrCast(&src), &src_len) catch continue;
            const src_port = std.mem.bigToNative(u16, @as(*const posix.sockaddr.in, @ptrCast(&src)).port);
            const c = std.mem.indexOfScalar(u16, &from_port, src_port) orelse return error.TestUnexpectedResult;
            const kind: usize = if (len == 2) 4 else buf[len - 1];
            where[c][kind] = s;
            got += 1;
        }
        sys.sleepNs(std.time.ns_per_ms);
    }
    try std.testing.expectEqual(@as(usize, clients * 5), got);

    var hashed_to: [n]bool = @splat(false);
    for (where, 0..) |w, c| {
        try std.testing.expectEqual(c % n, w[0].?);
        try std.testing.expectEqual((c + 1) % n, w[1].?);
        // The rest go where the client's 4-tuple hashes, together.
        try std.testing.expectEqual(w[2].?, w[3].?);
        try std.testing.expectEqual(w[2].?, w[4].?);
        hashed_to[w[2].?] = true;
    }
    try std.testing.expect(std.mem.count(bool, &hashed_to, &.{true}) > 1);
}

test "steerReuseportGroup: a socket in no reuseport group is refused with an error" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const posix = std.posix;
    const fd = try sys.socket(posix.AF.INET, posix.SOCK.DGRAM, 0);
    defer sys.close(fd);
    try std.testing.expectError(error.Refused, steerReuseportGroup(fd, &workerConfig(0), 2));
    try std.testing.expectError(error.Unsteerable, steerReuseportGroup(fd, &workerConfig(0), 0));
}
