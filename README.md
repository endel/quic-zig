# quic-zig

A _work-in-progress_ QUIC implementation, written in Zig.

> This is experimental. Do not use in production.

---

Check out my [GitHub Sponsors](https://github.com/sponsors/endel) for motivation
and goals of this project!

## Features

- **QUIC v1** (RFC 9000) — handshake, streams, flow control, connection migration, PMTUD
- **TLS 1.3** (RFC 8446 / RFC 9001) — ECDSA P-256 + RSA PSS, X25519, session resumption, 0-RTT
- **Loss Detection & Congestion Control** (RFC 9002) — NewReno, PTO, token bucket pacer
- **HTTP/3** (RFC 9114) — QPACK static table, request/response, SETTINGS
- **WebTransport** (draft-ietf-webtrans-http3) — bidi/uni streams, datagrams, Extended CONNECT

## Building

Requires **Zig 0.15.2**.

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
| `interop-server` | QUIC Interop Runner server endpoint |
| `interop-client` | QUIC Interop Runner client endpoint |

## Running Tests

```bash
zig build test
```

## Interop Testing

### Local (Zig ↔ Go)

Bidirectional interop with [quic-go](https://github.com/quic-go/quic-go) and [quiche](https://github.com/cloudflare/quiche) is verified. See `interop/quic-go/` and `interop/quiche/` for test programs.

```bash
# Build Go interop programs
cd interop/quic-go && go build -o server_bin ./server && go build -o client_bin ./client

# Zig server ↔ Go client
zig-out/bin/server &
./interop/quic-go/client_bin --addr localhost:4434

# Go server ↔ Zig client
./interop/quic-go/server_bin --addr localhost:4434 &
zig-out/bin/client
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

**Supported test cases:**

| Test Case | `TESTCASE` | Description |
|-----------|-----------|-------------|
| Handshake | `handshake` | Basic connection + small file download |
| Transfer | `transfer` | Stream multiplexing, flow control |
| Retry | `retry` | Server-side Retry token validation |
| Resumption | `resumption` | Session resumption (no 0-RTT) |
| 0-RTT | `zerortt` | 0-RTT resumption |
| Key Update | `keyupdate` | Key update during transfer |
| HTTP/3 | `http3` | File transfer over HTTP/3 |
| Multi-connect | `multiconnect` | Multiple sequential connections |

**Manual Docker build:**

```bash
docker build --platform linux/amd64 \
  -t quic-zig-interop:latest \
  -f interop/runner/Dockerfile .
```

## License

MIT License
