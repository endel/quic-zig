# quic-zig

A _work-in-progress_ QUIC implementation, written in Zig.

> This is experimental. Do not use in production.

---

Check out my [GitHub Sponsors](https://github.com/sponsors/endel) for motivation
and goals of this project!

## The Story

This project started in February 2022 with a simple UDP listener and a
question: _"Should I re-write/port an entire HTTP/3 implementation in Zig?"_

What followed was months of painful, incremental progress. Parsing QUIC Initial
headers byte by byte. Getting stuck on packet number decryption. Falling down
the TLS 1.3 rabbit hole. Evaluating every crypto library under the sun
-- BoringSSL, BearSSL, picotls, s2n -- before finding
[feilich](https://github.com/Luukdegram/feilich), a pure-Zig TLS 1.3
implementation. Reading [quiche](https://github.com/cloudflare/quiche) source
code for the tenth time, mesmerized by how clean it was, wondering if my own
attempt would ever get there.

By August 2022, the reality had fully set in: _"The more I read implementations
and portions of the specs, the more I see this is a multi-year endeavour that
may never end. I'm struggling to implement the very basics."_ The project was
shelved. QUIC is not one spec -- it's a stack of RFCs (9000, 9001, 9002, 9114,
9204, 9297) each building on the last, each with enough edge cases to fill a
career. For a solo developer, it was humanly impossible.

Fast-forward to 2025. [Claude Code](https://docs.anthropic.com/en/docs/claude-code)
changed the equation. Not by writing perfect code -- but by making it possible
to move fast enough across the full stack that the project could actually reach
the point where it gets battle-tested. The entire codebase was rebuilt from
scratch: TLS 1.3 handshake, QUIC transport, loss detection, congestion control,
HTTP/3, QPACK, and WebTransport -- all in pure Zig, no C dependencies.

The code passes interop tests against [quic-go](https://github.com/quic-go/quic-go)
and [quiche](https://github.com/cloudflare/quiche). It integrates with the
official [QUIC Interop Runner](https://github.com/quic-interop/quic-interop-runner).
It handles handshakes, stream multiplexing, retry, session resumption, 0-RTT,
key updates, and HTTP/3 file transfers.

Is AI-assisted code "slop"? Only until it's battle-tested. That's the challenge
-- and we're getting there.

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
