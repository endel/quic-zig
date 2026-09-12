![quic-zig](./quic-zig.svg)

A QUIC / H3 / WebTransport implementation in pure Zig.

> **Current state:** Not production-ready. Public APIs may still change as the project gets battle-tested.

---

Check out my [GitHub Sponsors](https://github.com/sponsors/endel) for motivation
and goals of this project!

## Features

- **QUIC v1 & v2** (RFC 9000 / RFC 9369) — handshake, streams, flow control, connection migration, PMTUD, ECN
- **TLS 1.3** (RFC 8446 / RFC 9001) — ECDSA P-256 + RSA PSS, X25519, AES-128-GCM + ChaCha20, session resumption, 0-RTT
- **Loss Detection & Congestion Control** (RFC 9002) — CUBIC, PTO, token bucket pacer
- **HTTP/3** (RFC 9114) — QPACK static table, request/response, priority scheduling (RFC 9218)
- **WebTransport** (draft-ietf-webtrans-http3) — bidi/uni streams, datagrams, Extended CONNECT, browser support
- **Media over QUIC** (draft-ietf-moq-transport-17) — wire layer, pub/sub, multi-subscriber relay with alias remapping, live browser video demo (WebCodecs VP8)
- **HTTP/1.1+TLS** — static file server on TCP, same cert as QUIC, Alt-Svc for HTTP/3 upgrade

## The Story

This project started in February 2022 with a simple UDP listener and a
question: _"Is it possible to write an entire WebTransport implementation in Zig?"_

What followed was months of painful, incremental progress. Parsing QUIC Initial
headers byte by byte. Getting stuck on packet number decryption. Falling down
the TLS 1.3 rabbit hole. Evaluating every crypto library under the sun
-- BoringSSL, BearSSL, picotls, s2n -- watching pure-Zig TLS efforts like
[feilich](https://github.com/Luukdegram/feilich) emerge and eventually TLS
land in Zig's standard library. Reading [quiche](https://github.com/cloudflare/quiche) source
code for the tenth time, mesmerized by how clean it was, wondering if my own
attempt would ever get there.

By August 2022, the reality had fully set in: _"The more I read implementations
and portions of the specs, the more I see this is a multi-year endeavour that
may never end. I'm struggling to implement the very basics."_ The project was
shelved. QUIC is not one spec -- it's a stack of RFCs (9000, 9001, 9002, 9114,
9204, 9297) each building on the last, each with enough edge cases to fill a
career. For a solo developer, it was humanly impossible.

Fast-forward to 2026. Claude Code changed the equation. Not by writing perfect
code -- but by making it possible to move fast enough across the full stack that
the project could actually reach the point where it gets battle-tested. The
entire codebase was rebuilt from scratch: TLS 1.3 handshake, QUIC transport,
loss detection, congestion control, HTTP/3, QPACK, and WebTransport -- all in
pure Zig, no C dependencies.

The code passes most interop tests against [quic-go](https://github.com/quic-go/quic-go)
and [quiche](https://github.com/cloudflare/quiche), and integrates with the
official [QUIC Interop Runner](https://github.com/quic-interop/quic-interop-runner).

Is AI-assisted code "slop"? Only until it's battle-tested. That's the challenge
-- and I'm hoping we can get there.


## Using as a Library

Add to your `build.zig.zon`:

```bash
zig fetch --save git+https://github.com/endel/quic-zig
```

Then in your `build.zig`:

```zig
const quic_dep = b.dependency("quic", .{ .target = target, .optimize = optimize });

const exe = b.addExecutable(.{
    .name = "my-app",
    .root_module = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{.{ .name = "quic", .module = quic_dep.module("quic") }},
    }),
});
```

### High-level API (event loop server)

```zig
const quic = @import("quic");
const event_loop = quic.event_loop;

const MyHandler = struct {
    pub const protocol: event_loop.Protocol = .webtransport;

    pub fn onConnectRequest(_: *MyHandler, session: *event_loop.Session, session_id: u64, _: []const u8) void {
        session.acceptSession(session_id) catch return;
    }

    pub fn onStreamData(_: *MyHandler, session: *event_loop.Session, stream_id: u64, data: []const u8, fin: bool) void {
        if (data.len > 0) {
            session.sendStreamData(stream_id, data) catch {}; // echo
        }
        if (fin) session.closeStream(stream_id);
    }

    pub fn onDatagram(_: *MyHandler, session: *event_loop.Session, session_id: u64, data: []const u8) void {
        session.sendDatagram(session_id, data) catch {}; // echo
    }

    pub fn onSessionReady(_: *MyHandler, _: *event_loop.Session, _: u64) void {}
    pub fn onSessionClosed(_: *MyHandler, _: *event_loop.Session, _: u64, _: u32, _: []const u8) void {}
};

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const alloc = gpa.allocator();

    var handler = MyHandler{};
    var server = try event_loop.Server(MyHandler).init(alloc, &handler, .{
        .port = 4433,
        .cert_path = "cert.pem",
        .key_path = "key.pem",
    });
    defer server.deinit();
    try server.run();
}
```

### Serving static files over HTTPS (HTTP/1.1+TLS)

The server can optionally serve static files over HTTP/1.1+TLS on the same port
alongside QUIC. TCP and UDP are separate namespaces, so the same port works for
both. The same TLS certificate is shared. An `Alt-Svc` header is automatically
included to advertise HTTP/3 to browsers.

```zig
var server = try event_loop.Server(MyHandler).init(alloc, &handler, .{
    .port = 4433,
    .cert_path = "cert.pem",
    .key_path = "key.pem",
    .http1 = .{ .static_dir = "public" },
});
```

This is particularly useful for browser WebTransport — the browser loads the
HTML/JS page over HTTPS, then upgrades to WebTransport over QUIC:

| Transport | Port | Protocol |
|-----------|------|----------|
| UDP | 4433 | QUIC / H3 / WebTransport (TLS 1.3) |
| TCP | 4433 | HTTP/1.1 static files (TLS 1.3) |

`Http1Config` options:

| Field | Default | Description |
|---|---|---|
| `static_dir` | *(required)* | Directory to serve files from |
| `port` | same as QUIC | TCP port override |
| `alt_svc` | `true` | Send `Alt-Svc: h3=":port"` header |

### Graceful shutdown

The server exposes `stop()` for graceful shutdown — it sends CONNECTION_CLOSE to
all active connections, waits for the drain period (3×PTO), then exits. Signal
handling is the application's responsibility:

```zig
const std = @import("std");
const posix = std.posix;
const quic = @import("quic");

var server_instance: ?*MyServer = null;

fn handleSignal(_: c_int) callconv(.c) void {
    if (server_instance) |s| s.stop();
}

pub fn main() !void {
    // ...
    var server = try quic.event_loop.Server(MyHandler).init(alloc, &handler, .{ .port = 4433 });
    defer server.deinit();
    server_instance = &server;

    // Install signal handlers
    const act = posix.Sigaction{
        .handler = .{ .handler = handleSignal },
        .mask = std.mem.zeroes(posix.sigset_t),
        .flags = 0,
    };
    posix.sigaction(posix.SIG.TERM, &act, null);
    posix.sigaction(posix.SIG.INT, &act, null);

    try server.run(); // blocks until stop() is called and all connections drain
}
```

### High-level API (event loop client)

The client mirrors the server pattern — define a handler struct, and `Client(Handler)` manages the QUIC handshake, H3/WebTransport setup, and Extended CONNECT automatically:

```zig
const quic = @import("quic");
const event_loop = quic.event_loop;

const MyHandler = struct {
    pub const protocol: event_loop.Protocol = .webtransport;

    pub fn onSessionReady(_: *MyHandler, session: *event_loop.ClientSession, session_id: u64) void {
        const stream_id = session.openBidiStream(session_id, null) catch return; // null = no sendOrder
        session.sendStreamData(stream_id, "Hello!") catch {};
        session.closeStream(stream_id);

        session.sendDatagram(session_id, "Hello via datagram!") catch {};
    }

    pub fn onStreamData(_: *MyHandler, session: *event_loop.ClientSession, stream_id: u64, data: []const u8, _: bool) void {
        if (data.len == 0) return;
        std.debug.print("Response on stream {d}: {s}\n", .{ stream_id, data });
        session.closeConnection();
    }

    pub fn onDatagram(_: *MyHandler, session: *event_loop.ClientSession, session_id: u64, data: []const u8) void {
        std.debug.print("Datagram: {s}\n", .{data});
        _ = session_id;
    }
};

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const alloc = gpa.allocator();

    var handler = MyHandler{};
    var client = try event_loop.Client(MyHandler).init(alloc, &handler, .{
        .address = "127.0.0.1",
        .port = 4433,
        .server_name = "localhost",
        .ca = .{ .file = "ca.crt" },
    });
    defer client.deinit();
    try client.run();
}
```

`ClientConfig` options:

| Field | Default | Description |
|---|---|---|
| `address` | `"127.0.0.1"` | Server IP address |
| `port` | `4433` | Server port |
| `server_name` | `"localhost"` | TLS SNI / CONNECT authority |
| `path` | `"/.well-known/webtransport"` | WebTransport CONNECT path |
| `ca` | `.none` | Trust anchors: `.none`, `.system`, `.file` (a PEM bundle), or `.pinned_hashes` (SHA-256 leaf fingerprints, the `serverCertificateHashes` equivalent). Anything but `.none` turns `skip_cert_verify` off |
| `skip_cert_verify` | `false` | Skip certificate verification (testing only) |
| `max_datagram_frame_size` | `65536` | QUIC datagram frame size limit |
| `wt_credits` | QUIC's own limits | draft-13 §5.6 session credit granted to the peer, per session: `.max_streams_bidi`, `.max_streams_uni`, `.max_data` |
| `wt_advertise_credits` | `false` | Also announce those credits in SETTINGS (§5.5). Off: Safari 26.4 refuses the session when it sees them |
| `ipv6` | `false` | Use IPv6 dual-stack socket |
| `tls_config` | `null` | Override TLS config directly |
| `conn_config` | `null` | Override QUIC connection config |

Handler callbacks (all optional):

| Callback | Description |
|---|---|
| `onConnected(session)` | QUIC handshake complete |
| `onSessionReady(session, session_id)` | WebTransport session established |
| `onSessionRejected(session, session_id, status)` | Server rejected CONNECT |
| `onStreamData(session, stream_id, data[, fin])` | Data received on a stream |
| `onDatagram(session, session_id, data)` | Datagram received |
| `onBidiStream(session, session_id, stream_id)` | Incoming bidi stream opened |
| `onUniStream(session, session_id, stream_id)` | Incoming uni stream opened |
| `onStreamReset(session, session_id, stream_id, error_code)` | Peer reset a stream — the `WebTransportError.streamErrorCode` equivalent |
| `onStopSending(session, session_id, stream_id, error_code)` | Peer asked us to stop sending on a stream |
| `onSessionClosed(session, session_id, error_code, reason)` | Session closed |
| `onSessionDraining(session, session_id)` | Session draining |
| `onPollComplete(session)` | Called each poll cycle |

### Low-level API (direct connection control)

```zig
const quic = @import("quic");

// Client
var conn = try quic.connection.connect(allocator, "example.com", .{}, tls_config, null);
defer conn.deinit();

// Send/receive loop
var out: [1500]u8 = undefined;
const n = conn.send(&out) catch 0;
// sendto(sockfd, out[0..n], ...)
// recvfrom(...) -> buf
conn.handleDatagram(buf[0..len], recv_info);
```

## Building

Requires **Zig 0.16.0**.

```bash
zig build
```

Produces binaries in `zig-out/bin/`:

| Binary | Description |
|--------|-------------|
| `server` | HTTP/3 echo server (127.0.0.1:4434) |
| `client` | HTTP/3 client |
| `wt-server` | WebTransport echo server |
| `wt-client` | WebTransport client |
| `wt-browser-server` | WebTransport server for browser clients (0.0.0.0:4433) |
| `moq-server` | MoQ Transport publisher over raw QUIC (ALPN `moqt-18`/`moqt-17`) |
| `moq-client` | MoQ Transport client over raw QUIC — subscribe or `--mode publish` |
| `moq-relay` | MoQ Transport relay over raw QUIC (pub/sub fanout, synthetic origin) |
| `moq-browser-server` | MoQ Transport relay over WebTransport for browser clients |
| `moq-test-client` | MoQ interop-runner test client (TAP 14) |
| `moq-lite` | moq-lite client: `publish`, `subscribe`, `announce`, `serve` |
| `moq-lite-relay` | moq-lite relay over WebTransport |
| `interop-server` | QUIC Interop Runner server endpoint |
| `interop-client` | QUIC Interop Runner client endpoint |
| `interop-wt-server` | QUIC Interop Runner WebTransport server |

## Running Tests

```bash
zig build test
```

## Interop Testing

### Local

Bidirectional interop is verified against [quic-go](https://github.com/quic-go/quic-go) and [quiche](https://github.com/cloudflare/quiche) across QUIC, HTTP/3, and WebTransport. Browser WebTransport (Chrome) is also tested.

An automated test script covers all combinations:

```bash
./interop/run_local_tests.sh
```

Or run individual tests manually:

```bash
# Build Go interop programs
cd interop/quic-go
go build -o h3server_bin ./h3server && go build -o h3client_bin ./h3client
go build -o wt_server_bin ./wt_server && go build -o wt_client_bin ./wt_client

# H3: Zig server ↔ Go client
zig-out/bin/server &
./interop/quic-go/h3client_bin --addr localhost:4434

# WebTransport: Zig server ↔ Go client
zig-out/bin/wt-server &
./interop/quic-go/wt_client_bin --addr localhost:4434

# Browser WebTransport (requires ECDSA cert)
cd interop/browser && ./generate-cert.sh
zig build run-wt-browser-server
# Open interop/browser/index.html in Chrome
```

### QUIC Interop Runner

This project integrates with the official [QUIC Interop Runner](https://github.com/quic-interop/quic-interop-runner), the framework used by all major QUIC implementations for cross-implementation testing.

**Prerequisites:**

- Docker (with `docker compose` v2)
- Python 3
- [Wireshark](https://www.wireshark.org/) >= 4.5.0 (`tshark` must be in PATH)

**Setup:**

```bash
# Initialize the interop runner submodule
git submodule update --init interop/quic-interop-runner

# Install Python dependencies
pip3 install -r interop/quic-interop-runner/requirements.txt
```

**Run tests:**

```bash
# Handshake test (quic-zig ↔ quic-zig)
./interop/runner/run.sh handshake

# Multiple tests
./interop/runner/run.sh handshake,transfer,retry

# Test against another implementation (e.g. quic-go)
./interop/runner/run.sh handshake quic-go
```

The script builds a Docker image (`quic-zig-interop:latest`), injects it into the runner's implementation list, and executes the tests.

**Manual Docker build:**

```bash
docker build --platform linux/amd64 \
  -t quic-zig-interop:latest \
  -f interop/runner/Dockerfile .
```

## Media over QUIC

Two dialects, because the standards track and the deployed ecosystem have not
converged yet. They share the transport underneath and nothing above it — most
of all, moq-lite uses the QUIC varint where draft-17 uses a leading-ones one.

| | Module | Spec |
|---|---|---|
| IETF MoQ Transport draft-17 and draft-18 | `src/moq/`, `quic.moq` | [DRAFT_IETF_MOQ_TRANSPORT.md](./SPEC/DRAFT_IETF_MOQ_TRANSPORT.md) |
| moq-lite draft-05 | `src/moq/lite/`, `quic.moq.lite` | [DRAFT_LCURLEY_MOQ_LITE_05.md](./SPEC/DRAFT_LCURLEY_MOQ_LITE_05.md) |

Interop with the [MoQ interop runner](https://github.com/englishm/moq-interop-runner):
[SPEC/moq-interop.md](./SPEC/moq-interop.md), results in
[SPEC/moq-interop-results.md](./SPEC/moq-interop-results.md).

### moq-lite

```bash
zig build run-moq-lite-relay -- --port 4450
zig build run-moq-lite -- publish   --url https://127.0.0.1:4450/ \
    --broadcast clock --track seconds --tls-disable-verify
zig build run-moq-lite -- subscribe --url https://127.0.0.1:4450/ \
    --broadcast clock --track seconds --tls-disable-verify
```

Against the reference implementation (`cargo install moq-relay moq-clock`), in
both directions and across a relay that speaks lite-05 to us and lite-04 to
them. `interop/browser/moq_lite.html` is a standalone JS subscriber;
`tools/moq_lite_browser_test.mjs` drives it through Chrome.

### MoQ interop test client

```bash
zig build run-moq-test-client -- --relay moqt://127.0.0.1:4455/ --tls-disable-verify
tools/moq_interop.sh          # matrix -> SPEC/moq-interop-results.md
```

### Live browser video demo

Two Chrome/Brave tabs — one publishing from webcam, the other (or many others) subscribing:

```bash
cd interop/browser && ./generate-cert.sh   # once, short-lived ECDSA cert
zig build run-moq-browser-server           # Zig WT relay on :4433
# Open https://127.0.0.1:4433/moq_video.html in two tabs.
# Paste the cert SHA-256 hash from the server's startup banner.
# Tab A: "Start Publishing (camera)"   Tab B: "Start Subscribing"
```

Flow: browser camera → `VideoEncoder` (VP8 @ 1 Mbps) → MoQ objects over
WebTransport uni streams → Zig relay parses the subgroup header, remaps
`track_alias`, fans out to each subscriber's WT session → browser `VideoDecoder`
→ `<canvas>`. No external MoQ library anywhere in the stack. Tested with 6
simultaneous subscribers on one publisher.

### Raw-QUIC MoQ (non-browser, ALPN `moqt-17`)

```bash
zig build run-moq-relay                                                          # :4443
zig build run-moq-client -- --addr 127.0.0.1:4443 --ns live --track camera --mode publish
zig build run-moq-client -- --addr 127.0.0.1:4443 --ns live --track camera       # subscribe
```

### Library API

```zig
const quic = @import("quic");
const wire = quic.moq.wire;         // draft-17 leading-ones varint, KV codec, tuples
const msg = quic.moq.message;       // all 18 control messages, encode and decode
const obj = quic.moq.object;        // subgroup/datagram/fetch stream headers
const track = quic.moq.track;       // TrackNamespace, FilterType, GroupOrder, …
const session = quic.moq.session;   // SETUP + request-stream state machine
const url = quic.moq.url;           // moqt:// and https:// relay locators

const lite = quic.moq.lite;         // moq-lite: QUIC varints, its own messages
```

Apps that don't reference `quic.moq` don't link any MoQ code — Zig's lazy
semantic analysis strips unused subtrees at compile time.

## License

MIT License
