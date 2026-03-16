// QLOG structured logging for QUIC (draft-ietf-quic-qlog-main-schema)
//
// Outputs JSON-SEQ (.sqlog) format: one JSON object per line.
// Events follow draft-ietf-quic-qlog-quic-events naming conventions.

const std = @import("std");
const frame_mod = @import("frame.zig");
const Frame = frame_mod.Frame;
const packet = @import("packet.zig");

pub const QlogWriter = struct {
    file: std.fs.File,
    start_time: i64, // nanoTimestamp at connection creation

    const Self = @This();

    pub fn init(dir_path: []const u8, odcid: []const u8, is_server: bool) ?Self {
        // Ensure directory exists
        std.fs.makeDirAbsolute(dir_path) catch |err| switch (err) {
            error.PathAlreadyExists => {},
            else => return null,
        };

        // Build filename: {odcid_hex}_{role}.sqlog
        var name_buf: [128]u8 = undefined;
        var name_pos: usize = 0;

        for (odcid) |b| {
            const h = hexByte(b);
            name_buf[name_pos] = h[0];
            name_buf[name_pos + 1] = h[1];
            name_pos += 2;
        }

        const suffix = if (is_server) "_server.sqlog" else "_client.sqlog";
        @memcpy(name_buf[name_pos..][0..suffix.len], suffix);
        name_pos += suffix.len;

        // Open file inside directory
        var dir = std.fs.openDirAbsolute(dir_path, .{}) catch return null;
        defer dir.close();

        const file = dir.createFile(name_buf[0..name_pos], .{}) catch return null;
        const now: i64 = @intCast(std.time.nanoTimestamp());

        var self = Self{
            .file = file,
            .start_time = now,
        };

        // Write header
        self.writeHeader(odcid, is_server);
        return self;
    }

    pub fn deinit(self: *Self) void {
        self.file.close();
    }

    fn writeHeader(self: *Self, odcid: []const u8, is_server: bool) void {
        var buf: [1024]u8 = undefined;
        var pos: usize = 0;

        const prefix = "{\"qlog_version\":\"0.4\",\"qlog_format\":\"JSON-SEQ\"," ++
            "\"serialization_format\":\"application/qlog+json-seq\"," ++
            "\"trace\":{\"vantage_point\":{\"type\":\"";
        @memcpy(buf[pos..][0..prefix.len], prefix);
        pos += prefix.len;

        const role = if (is_server) "server" else "client";
        @memcpy(buf[pos..][0..role.len], role);
        pos += role.len;

        const mid = "\"},\"common_fields\":{\"group_id\":\"";
        @memcpy(buf[pos..][0..mid.len], mid);
        pos += mid.len;

        for (odcid) |b| {
            const h = hexByte(b);
            buf[pos] = h[0];
            buf[pos + 1] = h[1];
            pos += 2;
        }

        const tail = "\"}}}\n";
        @memcpy(buf[pos..][0..tail.len], tail);
        pos += tail.len;

        _ = self.file.write(buf[0..pos]) catch {};
    }

    // ── Time helper ──────────────────────────────────────────────────────

    fn relativeTimeMs(self: *const Self, now: i64) f64 {
        const delta_ns = now - self.start_time;
        return @as(f64, @floatFromInt(delta_ns)) / 1_000_000.0;
    }

    // ── Event writers ────────────────────────────────────────────────────

    pub fn connectionStarted(self: *Self, now: i64) void {
        var buf: [256]u8 = undefined;
        const time_ms = self.relativeTimeMs(now);
        const len = std.fmt.bufPrint(&buf, "{{\"time\":{d:.3},\"name\":\"transport:connection_started\",\"data\":{{}}}}\n", .{time_ms}) catch return;
        _ = self.file.write(len) catch {};
    }

    pub fn connectionClosed(self: *Self, now: i64, trigger: []const u8, error_code: u64) void {
        var buf: [512]u8 = undefined;
        const time_ms = self.relativeTimeMs(now);
        const len = std.fmt.bufPrint(&buf, "{{\"time\":{d:.3},\"name\":\"transport:connection_closed\",\"data\":{{\"trigger\":\"{s}\",\"connection_code\":{d}}}}}\n", .{ time_ms, trigger, error_code }) catch return;
        _ = self.file.write(len) catch {};
    }

    pub fn parametersSet(self: *Self, now: i64, owner: []const u8, params_json: []const u8) void {
        var buf: [1024]u8 = undefined;
        const time_ms = self.relativeTimeMs(now);
        const len = std.fmt.bufPrint(&buf, "{{\"time\":{d:.3},\"name\":\"transport:parameters_set\",\"data\":{{\"owner\":\"{s}\",{s}}}}}\n", .{ time_ms, owner, params_json }) catch return;
        _ = self.file.write(len) catch {};
    }

    pub fn packetSent(self: *Self, now: i64, pkt_type: []const u8, pn: u64, length: usize, frames_json: []const u8) void {
        var buf: [4096]u8 = undefined;
        const time_ms = self.relativeTimeMs(now);
        const len = std.fmt.bufPrint(&buf, "{{\"time\":{d:.3},\"name\":\"transport:packet_sent\",\"data\":{{\"header\":{{\"packet_type\":\"{s}\",\"packet_number\":{d}}},\"raw\":{{\"length\":{d}}},\"frames\":[{s}]}}}}\n", .{ time_ms, pkt_type, pn, length, frames_json }) catch return;
        _ = self.file.write(len) catch {};
    }

    pub fn packetReceived(self: *Self, now: i64, pkt_type: []const u8, pn: u64, length: usize, frames_json: []const u8) void {
        var buf: [4096]u8 = undefined;
        const time_ms = self.relativeTimeMs(now);
        const len = std.fmt.bufPrint(&buf, "{{\"time\":{d:.3},\"name\":\"transport:packet_received\",\"data\":{{\"header\":{{\"packet_type\":\"{s}\",\"packet_number\":{d}}},\"raw\":{{\"length\":{d}}},\"frames\":[{s}]}}}}\n", .{ time_ms, pkt_type, pn, length, frames_json }) catch return;
        _ = self.file.write(len) catch {};
    }

    pub fn packetDropped(self: *Self, now: i64, pkt_type: []const u8, trigger: []const u8) void {
        var buf: [512]u8 = undefined;
        const time_ms = self.relativeTimeMs(now);
        const len = std.fmt.bufPrint(&buf, "{{\"time\":{d:.3},\"name\":\"transport:packet_dropped\",\"data\":{{\"header\":{{\"packet_type\":\"{s}\"}},\"trigger\":\"{s}\"}}}}\n", .{ time_ms, pkt_type, trigger }) catch return;
        _ = self.file.write(len) catch {};
    }

    pub fn metricsUpdated(self: *Self, now: i64, min_rtt_ns: i64, smoothed_rtt_ns: i64, latest_rtt_ns: i64, rttvar_ns: i64, cwnd: u64, bytes_in_flight: u64) void {
        var buf: [512]u8 = undefined;
        const time_ms = self.relativeTimeMs(now);
        const min_rtt = @as(f64, @floatFromInt(min_rtt_ns)) / 1_000_000.0;
        const srtt = @as(f64, @floatFromInt(smoothed_rtt_ns)) / 1_000_000.0;
        const latest = @as(f64, @floatFromInt(latest_rtt_ns)) / 1_000_000.0;
        const rttvar = @as(f64, @floatFromInt(rttvar_ns)) / 1_000_000.0;
        const len = std.fmt.bufPrint(&buf, "{{\"time\":{d:.3},\"name\":\"recovery:metrics_updated\",\"data\":{{\"min_rtt\":{d:.3},\"smoothed_rtt\":{d:.3},\"latest_rtt\":{d:.3},\"rtt_variance\":{d:.3},\"congestion_window\":{d},\"bytes_in_flight\":{d}}}}}\n", .{ time_ms, min_rtt, srtt, latest, rttvar, cwnd, bytes_in_flight }) catch return;
        _ = self.file.write(len) catch {};
    }

    pub fn congestionStateUpdated(self: *Self, now: i64, new_state: []const u8) void {
        var buf: [256]u8 = undefined;
        const time_ms = self.relativeTimeMs(now);
        const len = std.fmt.bufPrint(&buf, "{{\"time\":{d:.3},\"name\":\"recovery:congestion_state_updated\",\"data\":{{\"new\":\"{s}\"}}}}\n", .{ time_ms, new_state }) catch return;
        _ = self.file.write(len) catch {};
    }

    pub fn packetLost(self: *Self, now: i64, pkt_type: []const u8, pn: u64, trigger: []const u8) void {
        var buf: [256]u8 = undefined;
        const time_ms = self.relativeTimeMs(now);
        const len = std.fmt.bufPrint(&buf, "{{\"time\":{d:.3},\"name\":\"recovery:packet_lost\",\"data\":{{\"header\":{{\"packet_type\":\"{s}\",\"packet_number\":{d}}},\"trigger\":\"{s}\"}}}}\n", .{ time_ms, pkt_type, pn, trigger }) catch return;
        _ = self.file.write(len) catch {};
    }

    pub fn keyUpdated(self: *Self, now: i64, trigger: []const u8, key_type: []const u8) void {
        var buf: [256]u8 = undefined;
        const time_ms = self.relativeTimeMs(now);
        const len = std.fmt.bufPrint(&buf, "{{\"time\":{d:.3},\"name\":\"security:key_updated\",\"data\":{{\"trigger\":\"{s}\",\"key_type\":\"{s}\"}}}}\n", .{ time_ms, trigger, key_type }) catch return;
        _ = self.file.write(len) catch {};
    }

    pub fn keyDiscarded(self: *Self, now: i64, key_type: []const u8) void {
        var buf: [256]u8 = undefined;
        const time_ms = self.relativeTimeMs(now);
        const len = std.fmt.bufPrint(&buf, "{{\"time\":{d:.3},\"name\":\"security:key_discarded\",\"data\":{{\"key_type\":\"{s}\"}}}}\n", .{ time_ms, key_type }) catch return;
        _ = self.file.write(len) catch {};
    }

    // ── Frame serialization helpers ──────────────────────────────────────

    pub fn serializeFrames(frames: []const Frame, out: []u8) usize {
        var pos: usize = 0;
        var first = true;

        for (frames) |f| {
            if (!first and pos < out.len) {
                out[pos] = ',';
                pos += 1;
            }
            const written = serializeFrame(f, out[pos..]);
            if (written == 0) continue;
            pos += written;
            first = false;
        }
        return pos;
    }

    pub fn serializeFrame(f: Frame, out: []u8) usize {
        const result: []u8 = switch (f) {
            .padding => |len| std.fmt.bufPrint(out, "{{\"frame_type\":\"padding\",\"length\":{d}}}", .{len}) catch return 0,
            .ping => std.fmt.bufPrint(out, "{{\"frame_type\":\"ping\"}}", .{}) catch return 0,
            .ack => |ack| blk: {
                var tmp: [512]u8 = undefined;
                const ranges_len = serializeAckRanges(ack.largest_ack, ack.first_ack_range, ack.ack_ranges[0..ack.ack_range_count], &tmp);
                break :blk std.fmt.bufPrint(out, "{{\"frame_type\":\"ack\",\"ack_delay\":{d},\"acked_ranges\":[{s}]}}", .{ ack.ack_delay, tmp[0..ranges_len] }) catch return 0;
            },
            .ack_ecn => |ack| blk: {
                var tmp: [512]u8 = undefined;
                const ranges_len = serializeAckRanges(ack.largest_ack, ack.first_ack_range, ack.ack_ranges[0..ack.ack_range_count], &tmp);
                break :blk std.fmt.bufPrint(out, "{{\"frame_type\":\"ack\",\"ack_delay\":{d},\"acked_ranges\":[{s}],\"ect0\":{d},\"ect1\":{d},\"ce\":{d}}}", .{ ack.ack_delay, tmp[0..ranges_len], ack.ecn_ect0, ack.ecn_ect1, ack.ecn_ce }) catch return 0;
            },
            .crypto => |c| std.fmt.bufPrint(out, "{{\"frame_type\":\"crypto\",\"offset\":{d},\"length\":{d}}}", .{ c.offset, c.data.len }) catch return 0,
            .stream => |s| std.fmt.bufPrint(out, "{{\"frame_type\":\"stream\",\"stream_id\":{d},\"offset\":{d},\"length\":{d},\"fin\":{}}}", .{ s.stream_id, s.offset, s.length, s.fin }) catch return 0,
            .max_data => |v| std.fmt.bufPrint(out, "{{\"frame_type\":\"max_data\",\"maximum\":{d}}}", .{v}) catch return 0,
            .max_stream_data => |v| std.fmt.bufPrint(out, "{{\"frame_type\":\"max_stream_data\",\"stream_id\":{d},\"maximum\":{d}}}", .{ v.stream_id, v.max }) catch return 0,
            .max_streams_bidi => |v| std.fmt.bufPrint(out, "{{\"frame_type\":\"max_streams\",\"stream_type\":\"bidirectional\",\"maximum\":{d}}}", .{v}) catch return 0,
            .max_streams_uni => |v| std.fmt.bufPrint(out, "{{\"frame_type\":\"max_streams\",\"stream_type\":\"unidirectional\",\"maximum\":{d}}}", .{v}) catch return 0,
            .reset_stream => |r| std.fmt.bufPrint(out, "{{\"frame_type\":\"reset_stream\",\"stream_id\":{d},\"error_code\":{d},\"final_size\":{d}}}", .{ r.stream_id, r.error_code, r.final_size }) catch return 0,
            .stop_sending => |s| std.fmt.bufPrint(out, "{{\"frame_type\":\"stop_sending\",\"stream_id\":{d},\"error_code\":{d}}}", .{ s.stream_id, s.error_code }) catch return 0,
            .new_connection_id => |n| std.fmt.bufPrint(out, "{{\"frame_type\":\"new_connection_id\",\"sequence_number\":{d},\"retire_prior_to\":{d}}}", .{ n.seq_num, n.retire_prior_to }) catch return 0,
            .retire_connection_id => |r| std.fmt.bufPrint(out, "{{\"frame_type\":\"retire_connection_id\",\"sequence_number\":{d}}}", .{r.seq_num}) catch return 0,
            .path_challenge => std.fmt.bufPrint(out, "{{\"frame_type\":\"path_challenge\"}}", .{}) catch return 0,
            .path_response => std.fmt.bufPrint(out, "{{\"frame_type\":\"path_response\"}}", .{}) catch return 0,
            .connection_close => |c| std.fmt.bufPrint(out, "{{\"frame_type\":\"connection_close\",\"error_space\":\"transport\",\"error_code\":{d},\"raw_error_code\":{d}}}", .{ c.error_code, c.error_code }) catch return 0,
            .application_close => |c| std.fmt.bufPrint(out, "{{\"frame_type\":\"connection_close\",\"error_space\":\"application\",\"error_code\":{d}}}", .{c.error_code}) catch return 0,
            .handshake_done => std.fmt.bufPrint(out, "{{\"frame_type\":\"handshake_done\"}}", .{}) catch return 0,
            .new_token => std.fmt.bufPrint(out, "{{\"frame_type\":\"new_token\"}}", .{}) catch return 0,
            .data_blocked => |v| std.fmt.bufPrint(out, "{{\"frame_type\":\"data_blocked\",\"limit\":{d}}}", .{v}) catch return 0,
            .stream_data_blocked => |v| std.fmt.bufPrint(out, "{{\"frame_type\":\"stream_data_blocked\",\"stream_id\":{d},\"limit\":{d}}}", .{ v.stream_id, v.limit }) catch return 0,
            .streams_blocked_bidi => |v| std.fmt.bufPrint(out, "{{\"frame_type\":\"streams_blocked\",\"stream_type\":\"bidirectional\",\"limit\":{d}}}", .{v}) catch return 0,
            .streams_blocked_uni => |v| std.fmt.bufPrint(out, "{{\"frame_type\":\"streams_blocked\",\"stream_type\":\"unidirectional\",\"limit\":{d}}}", .{v}) catch return 0,
            .immediate_ack => std.fmt.bufPrint(out, "{{\"frame_type\":\"immediate_ack\"}}", .{}) catch return 0,
            .datagram => |d| std.fmt.bufPrint(out, "{{\"frame_type\":\"datagram\",\"length\":{d}}}", .{d.data.len}) catch return 0,
            .datagram_with_length => |d| std.fmt.bufPrint(out, "{{\"frame_type\":\"datagram\",\"length\":{d}}}", .{d.data.len}) catch return 0,
            .ack_frequency => |af| std.fmt.bufPrint(out, "{{\"frame_type\":\"ack_frequency\",\"sequence\":{d},\"threshold\":{d},\"max_delay\":{d},\"reorder\":{d}}}", .{ af.sequence_number, af.ack_eliciting_threshold, af.request_max_ack_delay, af.reordering_threshold }) catch return 0,
        };
        return result.len;
    }

    fn serializeAckRanges(largest_ack: u64, first_range: u64, ranges: []const frame_mod.AckRange, out: []u8) usize {
        var pos: usize = 0;
        const lo = largest_ack - first_range;
        if (lo == largest_ack) {
            const r = std.fmt.bufPrint(out[pos..], "[{d}]", .{largest_ack}) catch return pos;
            pos += r.len;
        } else {
            const r = std.fmt.bufPrint(out[pos..], "[{d},{d}]", .{ lo, largest_ack }) catch return pos;
            pos += r.len;
        }
        for (ranges) |rng| {
            if (pos >= out.len - 20) break;
            out[pos] = ',';
            pos += 1;
            if (rng.start == rng.end) {
                const r = std.fmt.bufPrint(out[pos..], "[{d}]", .{rng.start}) catch return pos;
                pos += r.len;
            } else {
                const r = std.fmt.bufPrint(out[pos..], "[{d},{d}]", .{ rng.start, rng.end }) catch return pos;
                pos += r.len;
            }
        }
        return pos;
    }
};

fn hexByte(b: u8) [2]u8 {
    const hex = "0123456789abcdef";
    return .{ hex[b >> 4], hex[b & 0x0f] };
}

pub fn packetTypeStr(pkt_type: packet.PacketType) []const u8 {
    return switch (pkt_type) {
        .initial => "initial",
        .zero_rtt => "0RTT",
        .handshake => "handshake",
        .one_rtt => "1RTT",
        .retry => "retry",
        .version_negotiation => "version_negotiation",
        _ => "unknown",
    };
}

// ── Tests ────────────────────────────────────────────────────────────────

test "QlogWriter.serializeFrame - ping" {
    var buf: [256]u8 = undefined;
    const len = QlogWriter.serializeFrame(.{ .ping = {} }, &buf);
    try std.testing.expectEqualStrings("{\"frame_type\":\"ping\"}", buf[0..len]);
}

test "QlogWriter.serializeFrame - stream" {
    var buf: [256]u8 = undefined;
    const len = QlogWriter.serializeFrame(.{ .stream = .{
        .stream_id = 4,
        .offset = 100,
        .length = 200,
        .fin = true,
        .data = &.{},
    } }, &buf);
    try std.testing.expectEqualStrings("{\"frame_type\":\"stream\",\"stream_id\":4,\"offset\":100,\"length\":200,\"fin\":true}", buf[0..len]);
}

test "QlogWriter.serializeFrame - ack" {
    var buf: [512]u8 = undefined;
    const len = QlogWriter.serializeFrame(.{ .ack = .{
        .largest_ack = 10,
        .ack_delay = 25,
        .first_ack_range = 3,
        .ack_range_count = 0,
    } }, &buf);
    try std.testing.expectEqualStrings("{\"frame_type\":\"ack\",\"ack_delay\":25,\"acked_ranges\":[[7,10]]}", buf[0..len]);
}

test "QlogWriter.serializeFrame - handshake_done" {
    var buf: [256]u8 = undefined;
    const len = QlogWriter.serializeFrame(.{ .handshake_done = {} }, &buf);
    try std.testing.expectEqualStrings("{\"frame_type\":\"handshake_done\"}", buf[0..len]);
}

test "QlogWriter.serializeFrame - connection_close" {
    var buf: [256]u8 = undefined;
    const len = QlogWriter.serializeFrame(.{ .connection_close = .{
        .error_code = 0,
        .frame_type = 0,
        .reason = &.{},
    } }, &buf);
    try std.testing.expectEqualStrings("{\"frame_type\":\"connection_close\",\"error_space\":\"transport\",\"error_code\":0,\"raw_error_code\":0}", buf[0..len]);
}

test "QlogWriter.serializeFrame - max_data" {
    var buf: [256]u8 = undefined;
    const len = QlogWriter.serializeFrame(.{ .max_data = 1048576 }, &buf);
    try std.testing.expectEqualStrings("{\"frame_type\":\"max_data\",\"maximum\":1048576}", buf[0..len]);
}

test "packetTypeStr" {
    try std.testing.expectEqualStrings("initial", packetTypeStr(.initial));
    try std.testing.expectEqualStrings("1RTT", packetTypeStr(.one_rtt));
    try std.testing.expectEqualStrings("0RTT", packetTypeStr(.zero_rtt));
    try std.testing.expectEqualStrings("handshake", packetTypeStr(.handshake));
}
