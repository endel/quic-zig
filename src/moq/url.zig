// Relay locators.
//
// Through draft-17 the scheme *is* the transport selector: `https://` names
// a WebTransport endpoint, `moqt://` a native-QUIC one. draft-18 §3.1 makes
// `moqt://` canonical for both and picks the transport from the ALPN offer,
// deriving the https URI internally for the WebTransport CONNECT
// (§3.1.3: "moqt://example.com/path becomes https://example.com/path").
//
// The moq-interop-runner still hands out both forms — it "continues to
// accept https:// as a legacy WebTransport locator" — so a client has to
// take either.

const std = @import("std");
const testing = std.testing;

pub const Error = error{
    MissingScheme,
    UnsupportedScheme,
    MissingHost,
    InvalidPort,
};

pub const Transport = enum {
    /// Native QUIC, version chosen by the QUIC ALPN.
    quic,
    /// WebTransport over HTTP/3, version chosen by WT-Available-Protocols.
    webtransport,
};

pub const Scheme = enum { https, moqt };

pub const Locator = struct {
    scheme: Scheme,
    host: []const u8,
    port: u16,
    /// Always begins with '/', and carries the query string when present —
    /// it is the `:path` of the CONNECT, and the relay's origin prefix.
    path: []const u8,

    /// What an https:// locator means, and what a moqt:// locator defaults
    /// to when the peer does not select a native-QUIC ALPN.
    pub fn defaultTransport(self: Locator) Transport {
        return switch (self.scheme) {
            .https => .webtransport,
            .moqt => .quic,
        };
    }

    /// True when this locator may be reached over WebTransport. An https
    /// locator only ever is; a moqt one may be, via the derived https URI.
    pub fn allowsWebTransport(self: Locator) bool {
        _ = self;
        return true;
    }

    /// Renders the https form used for the WebTransport CONNECT. For an
    /// https locator this is the input; for a moqt one it is §3.1.3's
    /// scheme substitution. The default port is elided, as in a URL.
    pub fn httpsUri(self: Locator, buf: []u8) ![]const u8 {
        if (self.port == DEFAULT_PORT) {
            return std.fmt.bufPrint(buf, "https://{s}{s}", .{ self.host, self.path });
        }
        return std.fmt.bufPrint(buf, "https://{s}:{d}{s}", .{ self.host, self.port, self.path });
    }

    /// The `:authority` for the CONNECT: host, plus port when non-default.
    pub fn authority(self: Locator, buf: []u8) ![]const u8 {
        if (self.port == DEFAULT_PORT) return std.fmt.bufPrint(buf, "{s}", .{self.host});
        return std.fmt.bufPrint(buf, "{s}:{d}", .{ self.host, self.port });
    }
};

pub const DEFAULT_PORT: u16 = 443;

pub fn parse(url: []const u8) Error!Locator {
    const sep = std.mem.indexOf(u8, url, "://") orelse return Error.MissingScheme;
    const scheme_str = url[0..sep];
    const scheme: Scheme = if (std.ascii.eqlIgnoreCase(scheme_str, "https"))
        .https
    else if (std.ascii.eqlIgnoreCase(scheme_str, "moqt"))
        .moqt
    else
        return Error.UnsupportedScheme;

    const rest = url[sep + 3 ..];

    // The path starts at the first '/', '?' or '#'. A fragment is a
    // draft-18 addition that identifies a resource, not a location, so it
    // is not part of what we dial; drop it.
    var authority_end = rest.len;
    var path_start = rest.len;
    for (rest, 0..) |c, i| {
        if (c == '/' or c == '?') {
            authority_end = i;
            path_start = i;
            break;
        }
        if (c == '#') {
            authority_end = i;
            path_start = rest.len;
            break;
        }
    }
    var path = rest[path_start..];
    if (std.mem.indexOfScalar(u8, path, '#')) |hash| path = path[0..hash];
    if (path.len == 0 or path[0] == '?') {
        // "moqt://host" and "moqt://host?x" both mean the root path.
        path = if (path.len == 0) "/" else path; // a bare query keeps its '?'
    }

    const authority_str = rest[0..authority_end];
    if (authority_str.len == 0) return Error.MissingHost;

    // Only split on a colon outside brackets, so an IPv6 literal survives.
    var host = authority_str;
    var port: u16 = DEFAULT_PORT;
    if (authority_str[0] == '[') {
        const close = std.mem.indexOfScalar(u8, authority_str, ']') orelse return Error.MissingHost;
        host = authority_str[0 .. close + 1];
        const after = authority_str[close + 1 ..];
        if (after.len > 0) {
            if (after[0] != ':') return Error.InvalidPort;
            port = std.fmt.parseInt(u16, after[1..], 10) catch return Error.InvalidPort;
        }
    } else if (std.mem.lastIndexOfScalar(u8, authority_str, ':')) |colon| {
        host = authority_str[0..colon];
        port = std.fmt.parseInt(u16, authority_str[colon + 1 ..], 10) catch return Error.InvalidPort;
    }
    if (host.len == 0) return Error.MissingHost;

    return .{ .scheme = scheme, .host = host, .port = port, .path = path };
}

/// Strips the brackets from an IPv6 literal so the result can be handed to
/// a socket address parser.
pub fn bareHost(host: []const u8) []const u8 {
    if (host.len >= 2 and host[0] == '[' and host[host.len - 1] == ']') return host[1 .. host.len - 1];
    return host;
}

test "https locator selects WebTransport" {
    const l = try parse("https://relay.example.com:4443/anon");
    try testing.expectEqual(Scheme.https, l.scheme);
    try testing.expectEqualStrings("relay.example.com", l.host);
    try testing.expectEqual(@as(u16, 4443), l.port);
    try testing.expectEqualStrings("/anon", l.path);
    try testing.expectEqual(Transport.webtransport, l.defaultTransport());
}

test "moqt locator selects native QUIC" {
    const l = try parse("moqt://cdn.moq.dev:443/anon");
    try testing.expectEqual(Scheme.moqt, l.scheme);
    try testing.expectEqualStrings("cdn.moq.dev", l.host);
    try testing.expectEqual(@as(u16, 443), l.port);
    try testing.expectEqual(Transport.quic, l.defaultTransport());
}

test "default port and root path" {
    const l = try parse("https://cdn.moq.dev");
    try testing.expectEqual(DEFAULT_PORT, l.port);
    try testing.expectEqualStrings("/", l.path);
    try testing.expectEqualStrings("cdn.moq.dev", l.host);
}

test "query string stays with the path" {
    const l = try parse("https://relay.example/demo?jwt=abc.def");
    try testing.expectEqualStrings("/demo?jwt=abc.def", l.path);

    const bare = try parse("https://relay.example?jwt=x");
    try testing.expectEqualStrings("?jwt=x", bare.path);
}

test "fragment is not part of the locator" {
    const l = try parse("moqt://example.com/app#track:video");
    try testing.expectEqualStrings("/app", l.path);
    try testing.expectEqualStrings("example.com", l.host);

    const no_path = try parse("moqt://example.com#x");
    try testing.expectEqualStrings("/", no_path.path);
    try testing.expectEqualStrings("example.com", no_path.host);
}

test "moqt derives the https URI for a WebTransport CONNECT" {
    var buf: [128]u8 = undefined;
    const l = try parse("moqt://example.com/path");
    try testing.expectEqualStrings("https://example.com/path", try l.httpsUri(&buf));

    const ported = try parse("moqt://example.com:4443/path");
    try testing.expectEqualStrings("https://example.com:4443/path", try ported.httpsUri(&buf));
}

test "authority elides the default port" {
    var buf: [128]u8 = undefined;
    try testing.expectEqualStrings("example.com", try (try parse("https://example.com/x")).authority(&buf));
    try testing.expectEqualStrings("example.com:4443", try (try parse("https://example.com:4443/x")).authority(&buf));
}

test "ipv6 literals keep their brackets until the socket layer" {
    const l = try parse("moqt://[2001:db8::1]:4443/anon");
    try testing.expectEqualStrings("[2001:db8::1]", l.host);
    try testing.expectEqual(@as(u16, 4443), l.port);
    try testing.expectEqualStrings("2001:db8::1", bareHost(l.host));

    const no_port = try parse("moqt://[2001:db8::1]/anon");
    try testing.expectEqual(DEFAULT_PORT, no_port.port);
    try testing.expectEqualStrings("[2001:db8::1]", no_port.host);
}

test "rejects what it cannot dial" {
    try testing.expectError(Error.MissingScheme, parse("relay.example.com"));
    try testing.expectError(Error.UnsupportedScheme, parse("http://relay.example.com"));
    try testing.expectError(Error.UnsupportedScheme, parse("wss://relay.example.com"));
    try testing.expectError(Error.MissingHost, parse("https:///anon"));
    try testing.expectError(Error.InvalidPort, parse("https://relay.example.com:notaport/"));
    try testing.expectError(Error.InvalidPort, parse("https://relay.example.com:99999/"));
}

test "scheme comparison is case-insensitive" {
    try testing.expectEqual(Scheme.https, (try parse("HTTPS://example.com")).scheme);
    try testing.expectEqual(Scheme.moqt, (try parse("MoQT://example.com")).scheme);
}
