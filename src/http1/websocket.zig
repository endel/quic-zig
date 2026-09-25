//! The WebSocket protocol (RFC 6455), server side, sans-IO.
//!
//! - Handshake: `isUpgrade`, `checkUpgrade` and `acceptKey` turn an HTTP/1.1
//!   upgrade request into the values a 101 response needs.
//! - `Decoder` takes the bytes a client sent and yields whole messages and
//!   control frames: it unmasks, reassembles fragments, bounds message size,
//!   checks text is UTF-8 and close frames are well formed.
//! - `writeFrameHeader` / `closePayload` build server frames, which are never
//!   masked.
//!
//! Extensions (permessage-deflate) are not negotiated, so every RSV bit a
//! client sets is a protocol error.

const std = @import("std");
const parser = @import("parser.zig");

/// RFC 6455 §1.3: appended to Sec-WebSocket-Key before hashing.
pub const accept_guid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

pub const Opcode = enum(u4) {
    continuation = 0x0,
    text = 0x1,
    binary = 0x2,
    close = 0x8,
    ping = 0x9,
    pong = 0xa,
    _,

    pub fn isControl(op: Opcode) bool {
        return @intFromEnum(op) & 0x8 != 0;
    }
};

pub const MessageKind = enum { binary, text };

/// Status codes (RFC 6455 §7.4.1). 1005 and 1006 are never sent: they stand
/// for "no code in the Close frame" and "no Close frame at all".
pub const CloseCode = struct {
    pub const normal: u16 = 1000;
    pub const going_away: u16 = 1001;
    pub const protocol_error: u16 = 1002;
    pub const unsupported_data: u16 = 1003;
    pub const no_status: u16 = 1005;
    pub const abnormal: u16 = 1006;
    pub const invalid_payload: u16 = 1007;
    pub const policy_violation: u16 = 1008;
    pub const message_too_big: u16 = 1009;
    pub const internal_error: u16 = 1011;
};

/// Whether a peer may put `code` in a Close frame: the RFC 6455 codes that
/// are not reserved for local use, the IANA-registered 1012-1014, and the
/// ranges for libraries (3000-3999) and applications (4000-4999).
pub fn isValidCloseCode(code: u16) bool {
    return switch (code) {
        1000...1003, 1007...1014, 3000...4999 => true,
        else => false,
    };
}

// ─── Handshake ───────────────────────────────────────────────────────

pub const UpgradeError = error{
    /// Malformed upgrade: answer 400.
    BadRequest,
    /// Sec-WebSocket-Version isn't 13: answer 426 with
    /// `Sec-WebSocket-Version: 13`.
    UnsupportedVersion,
};

/// Whether the request asks to switch to WebSocket: `Connection` lists
/// `upgrade` (the parser only sets `upgrade` then) and `Upgrade` lists
/// `websocket`.
pub fn isUpgrade(head: *const parser.RequestHead) bool {
    const value = head.upgrade orelse return false;
    var it = std.mem.tokenizeAny(u8, value, ", \t");
    while (it.next()) |tok| {
        if (std.ascii.eqlIgnoreCase(tok, "websocket")) return true;
    }
    return false;
}

/// Checks an upgrade request against RFC 6455 §4.2.1 and returns its
/// Sec-WebSocket-Key.
pub fn checkUpgrade(head: *const parser.RequestHead) UpgradeError![]const u8 {
    if (!std.mem.eql(u8, head.method, "GET")) return error.BadRequest;
    if (head.version != .http11) return error.BadRequest;
    if (head.hasBody()) return error.BadRequest;
    const version = head.get("sec-websocket-version") orelse return error.UnsupportedVersion;
    if (!std.mem.eql(u8, version, "13")) return error.UnsupportedVersion;
    const key = head.get("sec-websocket-key") orelse return error.BadRequest;
    // A base64-encoded 16-byte nonce: 24 characters ending in "==".
    const decoder = std.base64.standard.Decoder;
    const n = decoder.calcSizeForSlice(key) catch return error.BadRequest;
    if (n != 16) return error.BadRequest;
    var nonce: [16]u8 = undefined;
    decoder.decode(&nonce, key) catch return error.BadRequest;
    return key;
}

/// Sec-WebSocket-Accept for a key: base64(SHA-1(key ++ GUID)).
pub fn acceptKey(key: []const u8) [28]u8 {
    var sha1 = std.crypto.hash.Sha1.init(.{});
    sha1.update(key);
    sha1.update(accept_guid);
    var digest: [std.crypto.hash.Sha1.digest_length]u8 = undefined;
    sha1.final(&digest);
    var out: [28]u8 = undefined;
    _ = std.base64.standard.Encoder.encode(&out, &digest);
    return out;
}

/// Whether the client listed `protocol` in Sec-WebSocket-Protocol.
pub fn protocolOffered(head: *const parser.RequestHead, protocol: []const u8) bool {
    for (head.headers) |h| {
        if (!std.ascii.eqlIgnoreCase(h.name, "sec-websocket-protocol")) continue;
        var it = std.mem.tokenizeAny(u8, h.value, ", \t");
        while (it.next()) |tok| {
            if (std.mem.eql(u8, tok, protocol)) return true;
        }
    }
    return false;
}

// ─── Frames ──────────────────────────────────────────────────────────

pub const Error = error{
    /// Close with 1002.
    ProtocolError,
    /// Close with 1007: text or a close reason that isn't UTF-8.
    InvalidPayload,
    /// Close with 1009.
    MessageTooBig,
    OutOfMemory,
};

/// The close code that answers a decoding error.
pub fn closeCodeFor(err: Error) u16 {
    return switch (err) {
        error.ProtocolError => CloseCode.protocol_error,
        error.InvalidPayload => CloseCode.invalid_payload,
        error.MessageTooBig => CloseCode.message_too_big,
        error.OutOfMemory => CloseCode.internal_error,
    };
}

pub const Frame = struct {
    fin: bool,
    opcode: Opcode,
    /// Unmasked in place.
    payload: []u8,
};

pub const ParsedFrame = struct { frame: Frame, len: usize };

/// A client frame's header, masking key included.
pub const Header = struct {
    fin: bool,
    opcode: Opcode,
    key: [4]u8,
    /// Where the payload starts: the header's length.
    payload_start: usize,
    payload_len: usize,
};

/// Parses the client frame at the start of `buf`, unmasking its payload in
/// place, or returns null until all of it has arrived. A data frame whose
/// payload is longer than `max_payload` fails as soon as its header is in,
/// so an oversized frame is never buffered.
pub fn parseFrame(buf: []u8, max_payload: usize) Error!?ParsedFrame {
    const h = try parseHeader(buf, max_payload) orelse return null;
    if (buf.len - h.payload_start < h.payload_len) return null;
    const payload = buf[h.payload_start..][0..h.payload_len];
    unmask(payload, h.key);
    return .{ .frame = .{ .fin = h.fin, .opcode = h.opcode, .payload = payload }, .len = h.payload_start + h.payload_len };
}

/// The header of the client frame at the start of `buf`, checked as
/// `parseFrame` describes; null until all of it has arrived.
pub fn parseHeader(buf: []const u8, max_payload: usize) Error!?Header {
    if (buf.len < 2) return null;
    const b0 = buf[0];
    const b1 = buf[1];
    if (b0 & 0x70 != 0) return error.ProtocolError; // RSV1-3 without an extension
    const opcode: Opcode = @enumFromInt(@as(u4, @truncate(b0)));
    switch (opcode) {
        .continuation, .text, .binary, .close, .ping, .pong => {},
        _ => return error.ProtocolError,
    }
    const fin = b0 & 0x80 != 0;
    // §5.1: a server closes on an unmasked client frame.
    if (b1 & 0x80 == 0) return error.ProtocolError;

    var pos: usize = 2;
    const len7: u7 = @truncate(b1);
    const len: u64 = switch (len7) {
        126 => blk: {
            if (buf.len < 4) return null;
            pos = 4;
            break :blk std.mem.readInt(u16, buf[2..4], .big);
        },
        127 => blk: {
            if (buf.len < 10) return null;
            pos = 10;
            const n = std.mem.readInt(u64, buf[2..10], .big);
            if (n >> 63 != 0) return error.ProtocolError;
            break :blk n;
        },
        else => len7,
    };
    if (opcode.isControl()) {
        // §5.5: control frames are never fragmented and carry at most 125 bytes.
        if (!fin or len > 125) return error.ProtocolError;
    } else if (len > max_payload) {
        return error.MessageTooBig;
    }

    if (buf.len < pos + 4) return null;
    return .{
        .fin = fin,
        .opcode = opcode,
        .key = buf[pos..][0..4].*,
        .payload_start = pos + 4,
        .payload_len = @intCast(len),
    };
}

/// XORs `data` with the repeating 4-byte `key`, a vector at a time.
pub fn unmask(data: []u8, key: [4]u8) void {
    const lanes = 16;
    const V = @Vector(lanes, u8);
    const pattern: V = @bitCast(key ** (lanes / 4));
    var i: usize = 0;
    while (i + lanes <= data.len) : (i += lanes) {
        const chunk: V = data[i..][0..lanes].*;
        data[i..][0..lanes].* = chunk ^ pattern;
    }
    // `i` is a multiple of 4 here, so the key restarts at index 0.
    for (data[i..], 0..) |*b, j| b.* ^= key[j & 3];
}

/// Writes the header of an unmasked server frame; returns its bytes.
pub fn writeFrameHeader(buf: *[10]u8, opcode: Opcode, fin: bool, len: usize) []const u8 {
    buf[0] = @as(u8, if (fin) 0x80 else 0) | @as(u8, @intFromEnum(opcode));
    if (len < 126) {
        buf[1] = @intCast(len);
        return buf[0..2];
    }
    if (len <= 0xffff) {
        buf[1] = 126;
        std.mem.writeInt(u16, buf[2..4], @intCast(len), .big);
        return buf[0..4];
    }
    buf[1] = 127;
    std.mem.writeInt(u64, buf[2..10], len, .big);
    return buf[0..10];
}

/// A Close frame's payload: the code, then as much of `reason` as fits in
/// the 125 bytes a control frame allows, cut at a UTF-8 boundary.
pub fn closePayload(buf: *[125]u8, code: u16, reason: []const u8) []const u8 {
    std.mem.writeInt(u16, buf[0..2], code, .big);
    var n = @min(reason.len, buf.len - 2);
    while (n < reason.len and n > 0 and reason[n] & 0xc0 == 0x80) n -= 1;
    @memcpy(buf[2..][0..n], reason[0..n]);
    return buf[0 .. 2 + n];
}

// ─── Messages ────────────────────────────────────────────────────────

pub const Event = union(enum) {
    /// A whole message. Valid until the next `decode`.
    message: struct { kind: MessageKind, data: []const u8 },
    ping: []const u8,
    pong: []const u8,
    /// `code` is null when the frame carried none (report it as 1005).
    close: struct { code: ?u16, reason: []const u8 },
};

pub const Step = struct {
    /// Bytes of the input the step used. Zero with no event: need more input.
    consumed: usize,
    event: ?Event,
};

/// Turns client frames into messages. Holds the fragments of a message
/// in progress; control frames may arrive between them (§5.4).
///
/// Text is checked as it arrives (§8.1 "fail fast"): across fragments, and
/// within a frame whose payload is still coming in, so a byte no valid text
/// can continue with fails at once rather than when the message ends.
pub const Decoder = struct {
    max_message_size: usize,
    /// Kind of the fragmented message in progress, if one is.
    fragment_kind: ?MessageKind = null,
    fragments: std.ArrayList(u8) = .empty,
    /// The text message in progress, checked so far.
    utf8: Utf8Stream = .{},
    /// Payload bytes of the incomplete frame at the head of the input that
    /// have already been checked.
    partial: usize = 0,
    /// `fragments` holds a message that was handed out; cleared next time.
    delivered: bool = false,

    pub fn init(max_message_size: usize) Decoder {
        return .{ .max_message_size = max_message_size };
    }

    pub fn deinit(self: *Decoder, gpa: std.mem.Allocator) void {
        self.fragments.deinit(gpa);
    }

    /// Decodes the next frame at the start of `buf` (unmasking it in place).
    /// A single-frame message is returned as a slice of `buf`.
    pub fn decode(self: *Decoder, gpa: std.mem.Allocator, buf: []u8) Error!Step {
        if (self.delivered) {
            self.delivered = false;
            // A one-off large message shouldn't pin its buffer.
            if (self.fragments.capacity > 64 * 1024) {
                self.fragments.clearAndFree(gpa);
            } else {
                self.fragments.clearRetainingCapacity();
            }
        }
        const room = self.max_message_size - self.fragments.items.len;
        const h = try parseHeader(buf, room) orelse return .{ .consumed = 0, .event = null };
        const avail = buf[h.payload_start..];
        if (avail.len < h.payload_len) {
            try self.checkArriving(h, avail);
            return .{ .consumed = 0, .event = null };
        }
        const payload = avail[0..h.payload_len];
        unmask(payload, h.key);
        const checked = self.partial;
        self.partial = 0;
        const f: Frame = .{ .fin = h.fin, .opcode = h.opcode, .payload = payload };
        return .{ .consumed = h.payload_start + h.payload_len, .event = try self.onFrame(gpa, f, checked) };
    }

    /// Whether the frame belongs to a text message, after the ordering
    /// checks `onFrame` would make.
    fn carriesText(self: *const Decoder, op: Opcode) Error!bool {
        return switch (op) {
            .text => if (self.fragment_kind != null) error.ProtocolError else true,
            .continuation => (self.fragment_kind orelse return error.ProtocolError) == .text,
            else => false,
        };
    }

    /// Checks the part of a text frame that has arrived. The frame is
    /// unmasked in place only once it is whole, so this unmasks a copy.
    fn checkArriving(self: *Decoder, h: Header, avail: []const u8) Error!void {
        if (!try self.carriesText(h.opcode)) return;
        if (h.opcode == .text and self.partial == 0) self.utf8 = .{};
        var tmp: [256]u8 = undefined;
        var off = self.partial;
        while (off < avail.len) {
            const n = @min(tmp.len, avail.len - off);
            for (tmp[0..n], avail[off..][0..n], off..) |*d, b, j| d.* = b ^ h.key[j & 3];
            if (!self.utf8.feed(tmp[0..n])) return error.InvalidPayload;
            off += n;
        }
        self.partial = avail.len;
    }

    /// `checked`: leading payload bytes `checkArriving` already went through.
    fn onFrame(self: *Decoder, gpa: std.mem.Allocator, f: Frame, checked: usize) Error!?Event {
        switch (f.opcode) {
            .ping => return .{ .ping = f.payload },
            .pong => return .{ .pong = f.payload },
            .close => return try parseClose(f.payload),
            .text, .binary => {
                if (self.fragment_kind != null) return error.ProtocolError;
                const kind: MessageKind = if (f.opcode == .text) .text else .binary;
                if (kind == .text) {
                    if (checked == 0) self.utf8 = .{};
                    try self.checkText(f.payload[checked..], f.fin);
                }
                if (f.fin) return .{ .message = .{ .kind = kind, .data = f.payload } };
                self.fragment_kind = kind;
                try self.fragments.appendSlice(gpa, f.payload);
                return null;
            },
            .continuation => {
                const kind = self.fragment_kind orelse return error.ProtocolError;
                if (kind == .text) try self.checkText(f.payload[checked..], f.fin);
                try self.fragments.appendSlice(gpa, f.payload);
                if (!f.fin) return null;
                self.fragment_kind = null;
                self.delivered = true;
                return .{ .message = .{ .kind = kind, .data = self.fragments.items } };
            },
            _ => unreachable, // parseHeader rejects reserved opcodes
        }
    }

    fn checkText(self: *Decoder, bytes: []const u8, last: bool) Error!void {
        if (!self.utf8.feed(bytes)) return error.InvalidPayload;
        if (last and !self.utf8.complete()) return error.InvalidPayload;
    }
};

/// UTF-8 checked a piece at a time. It fails at the first byte no valid text
/// could continue with, even when that byte ends a piece: `ED A0` fails
/// before the third byte arrives, since no code point starts that way
/// (Unicode Table 3-7; `ED A0` would be a surrogate).
pub const Utf8Stream = struct {
    /// Continuation bytes still owed by the code point in progress.
    need: u2 = 0,
    /// Range the next continuation byte must fall in: narrower right after
    /// E0, ED, F0 and F4.
    lo: u8 = 0x80,
    hi: u8 = 0xbf,

    /// False once the text can't be valid, whatever follows.
    pub fn feed(self: *Utf8Stream, bytes: []const u8) bool {
        var i: usize = 0;
        // Finish a code point the last piece left open.
        while (self.need > 0) : (i += 1) {
            if (i == bytes.len) return true;
            if (!self.step(bytes[i])) return false;
        }
        // Whole code points go to std's vectorized check; only a trailing,
        // cut-off one is stepped through here.
        const rest = bytes[i..];
        const end = completeUtf8Prefix(rest);
        if (!std.unicode.utf8ValidateSlice(rest[0..end])) return false;
        for (rest[end..]) |b| {
            if (!self.step(b)) return false;
        }
        return true;
    }

    /// At a code point boundary: the text so far is whole.
    pub fn complete(self: *const Utf8Stream) bool {
        return self.need == 0;
    }

    fn step(self: *Utf8Stream, b: u8) bool {
        if (self.need > 0) {
            if (b < self.lo or b > self.hi) return false;
            self.need -= 1;
            self.lo = 0x80;
            self.hi = 0xbf;
            return true;
        }
        switch (b) {
            0x00...0x7f => {},
            0xc2...0xdf => self.need = 1,
            0xe0 => self.start(2, 0xa0, 0xbf),
            0xe1...0xec, 0xee...0xef => self.need = 2,
            0xed => self.start(2, 0x80, 0x9f),
            0xf0 => self.start(3, 0x90, 0xbf),
            0xf1...0xf3 => self.need = 3,
            0xf4 => self.start(3, 0x80, 0x8f),
            else => return false,
        }
        return true;
    }

    fn start(self: *Utf8Stream, need: u2, lo: u8, hi: u8) void {
        self.need = need;
        self.lo = lo;
        self.hi = hi;
    }
};

/// The end of the last whole UTF-8 sequence in `buf`: `buf.len`, or the
/// start of a trailing sequence the buffer only has part of.
fn completeUtf8Prefix(buf: []const u8) usize {
    var i = buf.len;
    var back: usize = 0;
    while (i > 0 and back < 4) {
        i -= 1;
        back += 1;
        const c = buf[i];
        if (c & 0xc0 == 0x80) continue; // continuation byte
        const need: usize = if (c < 0x80) 1 else if (c & 0xe0 == 0xc0) 2 else if (c & 0xf0 == 0xe0) 3 else if (c & 0xf8 == 0xf0) 4 else 1;
        return if (back < need) i else buf.len;
    }
    return buf.len;
}

fn parseClose(payload: []const u8) Error!Event {
    if (payload.len == 0) return .{ .close = .{ .code = null, .reason = "" } };
    if (payload.len == 1) return error.ProtocolError;
    const code = std.mem.readInt(u16, payload[0..2], .big);
    if (!isValidCloseCode(code)) return error.ProtocolError;
    const reason = payload[2..];
    if (!std.unicode.utf8ValidateSlice(reason)) return error.InvalidPayload;
    return .{ .close = .{ .code = code, .reason = reason } };
}

// ─── Tests ───────────────────────────────────────────────────────────

const testing = std.testing;

/// A masked client frame, as a browser would send it.
fn clientFrame(buf: []u8, opcode: Opcode, fin: bool, payload: []const u8) []u8 {
    var hdr: [10]u8 = undefined;
    const h = writeFrameHeader(&hdr, opcode, fin, payload.len);
    @memcpy(buf[0..h.len], h);
    buf[1] |= 0x80;
    const key = [4]u8{ 0x37, 0xfa, 0x21, 0x3d };
    @memcpy(buf[h.len..][0..4], &key);
    const body = buf[h.len + 4 ..][0..payload.len];
    @memcpy(body, payload);
    unmask(body, key);
    return buf[0 .. h.len + 4 + payload.len];
}

test "accept key: RFC 6455 section 1.3 example" {
    try testing.expectEqualStrings("s3pPLMBiTxaQ9kYGzzhZRbK+xOo=", &acceptKey("dGhlIHNhbXBsZSBub25jZQ=="));
}

test "upgrade checks" {
    var hb: [16]parser.Header = undefined;
    const ok = "GET /chat?x=1 HTTP/1.1\r\nHost: a\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" ++
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n" ++
        "Sec-WebSocket-Protocol: chat, superchat\r\n\r\n";
    const p = (try parser.parseRequest(ok, &hb, .{})).?;
    try testing.expect(isUpgrade(&p.head));
    try testing.expectEqualStrings("dGhlIHNhbXBsZSBub25jZQ==", try checkUpgrade(&p.head));
    try testing.expect(protocolOffered(&p.head, "superchat"));
    try testing.expect(!protocolOffered(&p.head, "super"));

    const v12 = "GET / HTTP/1.1\r\nHost: a\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" ++
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 12\r\n\r\n";
    const q = (try parser.parseRequest(v12, &hb, .{})).?;
    try testing.expectError(error.UnsupportedVersion, checkUpgrade(&q.head));

    const short_key = "GET / HTTP/1.1\r\nHost: a\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" ++
        "Sec-WebSocket-Key: c2hvcnQ=\r\nSec-WebSocket-Version: 13\r\n\r\n";
    const r = (try parser.parseRequest(short_key, &hb, .{})).?;
    try testing.expectError(error.BadRequest, checkUpgrade(&r.head));

    const post = "POST / HTTP/1.1\r\nHost: a\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" ++
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n";
    const s = (try parser.parseRequest(post, &hb, .{})).?;
    try testing.expectError(error.BadRequest, checkUpgrade(&s.head));

    const h2c = "GET / HTTP/1.1\r\nHost: a\r\nUpgrade: h2c\r\nConnection: Upgrade\r\n\r\n";
    const t = (try parser.parseRequest(h2c, &hb, .{})).?;
    try testing.expect(!isUpgrade(&t.head));
}

test "frame header: every length form" {
    var hdr: [10]u8 = undefined;
    try testing.expectEqualSlices(u8, &.{ 0x82, 125 }, writeFrameHeader(&hdr, .binary, true, 125));
    try testing.expectEqualSlices(u8, &.{ 0x81, 126, 0, 126 }, writeFrameHeader(&hdr, .text, true, 126));
    try testing.expectEqualSlices(u8, &.{ 0x02, 126, 0xff, 0xff }, writeFrameHeader(&hdr, .binary, false, 0xffff));
    try testing.expectEqualSlices(u8, &.{ 0x82, 127, 0, 0, 0, 0, 0, 1, 0, 0 }, writeFrameHeader(&hdr, .binary, true, 0x10000));

    var buf: [0x10000 + 16]u8 = undefined;
    var payload: [0x10000]u8 = undefined;
    for (&payload, 0..) |*b, i| b.* = @truncate(i *% 7);
    for ([_]usize{ 0, 1, 125, 126, 0xffff, 0x10000 }) |n| {
        const f = clientFrame(&buf, .binary, true, payload[0..n]);
        const p = (try parseFrame(f, 1 << 20)).?;
        try testing.expectEqual(f.len, p.len);
        try testing.expectEqualSlices(u8, payload[0..n], p.frame.payload);
        // Every strict prefix is incomplete.
        try testing.expectEqual(@as(?ParsedFrame, null), try parseFrame(f[0 .. f.len - 1], 1 << 20));
    }
}

test "unmask matches the byte-wise definition" {
    var data: [67]u8 = undefined;
    var expect: [67]u8 = undefined;
    const key = [4]u8{ 1, 2, 0x80, 0xff };
    for (&data, &expect, 0..) |*d, *e, i| {
        d.* = @truncate(i * 31);
        e.* = d.* ^ key[i % 4];
    }
    unmask(&data, key);
    try testing.expectEqualSlices(u8, &expect, &data);
}

test "frame errors" {
    var buf: [256]u8 = undefined;
    // Unmasked client frame.
    try testing.expectError(error.ProtocolError, parseFrame(@constCast(&[_]u8{ 0x82, 0x00 }), 100));
    // RSV1 without an extension.
    try testing.expectError(error.ProtocolError, parseFrame(@constCast(&[_]u8{ 0xc2, 0x80, 0, 0, 0, 0 }), 100));
    // Reserved opcodes.
    try testing.expectError(error.ProtocolError, parseFrame(@constCast(&[_]u8{ 0x83, 0x80, 0, 0, 0, 0 }), 100));
    try testing.expectError(error.ProtocolError, parseFrame(@constCast(&[_]u8{ 0x8b, 0x80, 0, 0, 0, 0 }), 100));
    // Fragmented ping.
    try testing.expectError(error.ProtocolError, parseFrame(clientFrame(&buf, .ping, false, "x"), 100));
    // Control frame over 125 bytes.
    try testing.expectError(error.ProtocolError, parseFrame(clientFrame(&buf, .ping, true, &([_]u8{0} ** 126)), 1000));
    // 64-bit length with the top bit set.
    var huge = [_]u8{ 0x82, 0xff, 0x80, 0, 0, 0, 0, 0, 0, 0 };
    try testing.expectError(error.ProtocolError, parseFrame(&huge, 100));
    // Oversized: fails on the header, before the payload arrives.
    try testing.expectError(error.MessageTooBig, parseFrame(@constCast(&[_]u8{ 0x82, 0xfe, 0x01, 0x00 }), 255));
}

fn decodeAll(d: *Decoder, input: []u8, events: *std.ArrayList(Event), copies: *std.ArrayList([]u8)) Error!void {
    var pos: usize = 0;
    while (pos < input.len) {
        const step = try d.decode(testing.allocator, input[pos..]);
        if (step.consumed == 0) break;
        pos += step.consumed;
        if (step.event) |ev| {
            var e = ev;
            // Messages are only valid until the next decode.
            if (e == .message) {
                const copy = try testing.allocator.dupe(u8, e.message.data);
                try copies.append(testing.allocator, copy);
                e.message.data = copy;
            }
            try events.append(testing.allocator, e);
        }
    }
}

test "fragmented message with an interleaved ping" {
    var d = Decoder.init(1024);
    defer d.deinit(testing.allocator);
    var buf: [256]u8 = undefined;
    var n: usize = 0;
    n += clientFrame(buf[n..], .text, false, "Hel").len;
    n += clientFrame(buf[n..], .ping, true, "p").len;
    n += clientFrame(buf[n..], .continuation, false, "lo, ").len;
    n += clientFrame(buf[n..], .continuation, true, "wörld").len;
    n += clientFrame(buf[n..], .binary, true, &.{ 1, 2, 3 }).len;

    var events: std.ArrayList(Event) = .empty;
    defer events.deinit(testing.allocator);
    var copies: std.ArrayList([]u8) = .empty;
    defer {
        for (copies.items) |c| testing.allocator.free(c);
        copies.deinit(testing.allocator);
    }
    try decodeAll(&d, buf[0..n], &events, &copies);
    try testing.expectEqual(@as(usize, 3), events.items.len);
    try testing.expectEqualStrings("p", events.items[0].ping);
    try testing.expectEqual(MessageKind.text, events.items[1].message.kind);
    try testing.expectEqualStrings("Hello, wörld", events.items[1].message.data);
    try testing.expectEqual(MessageKind.binary, events.items[2].message.kind);
    try testing.expectEqualSlices(u8, &.{ 1, 2, 3 }, events.items[2].message.data);
}

test "message ordering errors" {
    var buf: [64]u8 = undefined;
    {
        var d = Decoder.init(1024);
        defer d.deinit(testing.allocator);
        try testing.expectError(error.ProtocolError, d.decode(testing.allocator, clientFrame(&buf, .continuation, true, "x")));
    }
    {
        var d = Decoder.init(1024);
        defer d.deinit(testing.allocator);
        _ = try d.decode(testing.allocator, clientFrame(&buf, .binary, false, "x"));
        try testing.expectError(error.ProtocolError, d.decode(testing.allocator, clientFrame(&buf, .text, true, "y")));
    }
}

test "message size bound spans fragments" {
    var buf: [64]u8 = undefined;
    var d = Decoder.init(8);
    defer d.deinit(testing.allocator);
    _ = try d.decode(testing.allocator, clientFrame(&buf, .binary, false, "12345"));
    try testing.expectError(error.MessageTooBig, d.decode(testing.allocator, clientFrame(&buf, .continuation, true, "6789")));
}

test "invalid UTF-8 fails fast across fragments" {
    var buf: [64]u8 = undefined;
    var d = Decoder.init(1024);
    defer d.deinit(testing.allocator);
    // "κ" split across fragments is fine...
    _ = try d.decode(testing.allocator, clientFrame(&buf, .text, false, "\xce"));
    _ = try d.decode(testing.allocator, clientFrame(&buf, .continuation, false, "\xba"));
    // ...a lone continuation byte is not, even before the message ends.
    try testing.expectError(error.InvalidPayload, d.decode(testing.allocator, clientFrame(&buf, .continuation, false, "\x80")));

    var e = Decoder.init(1024);
    defer e.deinit(testing.allocator);
    // A surrogate half (U+D800) in one frame.
    try testing.expectError(error.InvalidPayload, e.decode(testing.allocator, clientFrame(&buf, .text, true, "\xed\xa0\x80")));
}

test "Utf8Stream: any split of valid text passes, a dead-end prefix fails at once" {
    const text = "aκόσμε€𝄞z\xed\x9f\xbf\xf4\x8f\xbf\xbf";
    for (0..text.len + 1) |cut| {
        for (cut..text.len + 1) |cut2| {
            var u: Utf8Stream = .{};
            try testing.expect(u.feed(text[0..cut]));
            try testing.expect(u.feed(text[cut..cut2]));
            try testing.expect(u.feed(text[cut2..]));
            try testing.expect(u.complete());
        }
    }
    // Each fails on its last byte, before the code point could be finished.
    const dead_ends = [_][]const u8{ "\xed\xa0", "\xf4\x90", "\xe0\x80", "\xf0\x80", "\xc0", "\xc1", "\xf5", "\xff", "ab\x80" };
    for (dead_ends) |bad| {
        var u: Utf8Stream = .{};
        try testing.expect(u.feed(bad[0 .. bad.len - 1]));
        try testing.expect(!u.feed(bad[bad.len - 1 ..]));
    }
    var open: Utf8Stream = .{};
    try testing.expect(open.feed("\xed\x9f")); // still a possible U+D7xx
    try testing.expect(!open.complete());
}

test "invalid UTF-8 fails fast inside a frame that is still arriving" {
    // Autobahn 6.4.3/6.4.4: one text frame whose payload goes bad at "\xed\xa0".
    const payload = "κόσμε\xed\xa0\x80edited";
    const bad_at = std.mem.indexOf(u8, payload, "\xed\xa0").? + 1;
    var buf: [64]u8 = undefined;
    const frame = clientFrame(&buf, .text, true, payload);
    const hdr_len = frame.len - payload.len;

    var d = Decoder.init(1024);
    defer d.deinit(testing.allocator);
    // Everything before the bad byte could still be text: wait for more.
    for (hdr_len..hdr_len + bad_at + 1) |n| {
        const step = try d.decode(testing.allocator, frame[0..n]);
        try testing.expectEqual(@as(usize, 0), step.consumed);
    }
    // The byte that can't continue a code point fails with the frame unfinished.
    try testing.expectError(error.InvalidPayload, d.decode(testing.allocator, frame[0 .. hdr_len + bad_at + 1]));
}

test "a text frame checked as it arrives is delivered whole and unchanged" {
    const payload = "Hello, κόσμε — 𝄞 ok";
    var buf: [64]u8 = undefined;
    var d = Decoder.init(1024);
    defer d.deinit(testing.allocator);
    // A fragmented message, each frame arriving a byte at a time.
    var n: usize = 0;
    n += clientFrame(buf[n..], .text, false, payload[0..9]).len;
    const second = n;
    n += clientFrame(buf[n..], .continuation, true, payload[9..]).len;

    var pos: usize = 0;
    var end: usize = 1;
    var got: ?[]const u8 = null;
    while (pos < n) : (end += 1) {
        const step = try d.decode(testing.allocator, buf[pos..@min(end, n)]);
        pos += step.consumed;
        if (step.event) |ev| got = ev.message.data;
    }
    try testing.expect(pos == n and second < n);
    try testing.expectEqualStrings(payload, got.?);
}

test "close frames" {
    var buf: [256]u8 = undefined;
    var d = Decoder.init(1024);
    defer d.deinit(testing.allocator);

    const empty = try d.decode(testing.allocator, clientFrame(&buf, .close, true, ""));
    try testing.expectEqual(@as(?u16, null), empty.event.?.close.code);

    var p: [125]u8 = undefined;
    const ok = try d.decode(testing.allocator, clientFrame(&buf, .close, true, closePayload(&p, 1000, "bye")));
    try testing.expectEqual(@as(?u16, 1000), ok.event.?.close.code);
    try testing.expectEqualStrings("bye", ok.event.?.close.reason);

    try testing.expectError(error.ProtocolError, d.decode(testing.allocator, clientFrame(&buf, .close, true, "\x03")));
    for ([_]u16{ 0, 999, 1004, 1005, 1006, 1015, 1016, 2999, 5000 }) |code| {
        try testing.expectError(error.ProtocolError, d.decode(testing.allocator, clientFrame(&buf, .close, true, closePayload(&p, code, ""))));
    }
    for ([_]u16{ 1001, 1003, 1007, 1011, 3000, 4999 }) |code| {
        _ = try d.decode(testing.allocator, clientFrame(&buf, .close, true, closePayload(&p, code, "")));
    }
    try testing.expectError(error.InvalidPayload, d.decode(testing.allocator, clientFrame(&buf, .close, true, "\x03\xe8\xff")));
}

test "close payload cuts the reason at a code point" {
    var p: [125]u8 = undefined;
    const reason = "a" ** 122 ++ "é"; // 124 bytes; "é" straddles the 123-byte limit
    const out = closePayload(&p, 1000, reason);
    try testing.expectEqual(@as(usize, 2 + 122), out.len);
    try testing.expect(std.unicode.utf8ValidateSlice(out[2..]));
}
