# QUIC Interop Runner Integration

Reference: https://github.com/quic-interop/quic-interop-runner

## Architecture

The interop runner orchestrates 3 Docker containers via docker-compose:
- **`sim`** — ns-3 network simulator (delay, loss, corruption, blackholes)
- **`server`** on `193.167.100.100:443` (rightnet `193.167.100.0/24`)
- **`client`** on `193.167.0.100` (leftnet `193.167.0.0/24`)

All containers use `martenseemann/quic-network-simulator-endpoint:latest` as base image (Ubuntu 24.04). The base image provides `/setup.sh` (routing), `/wait-for-it.sh` (sim readiness), and network tools.

## Environment Variables

| Variable | Description |
|----------|-------------|
| `ROLE` | `"client"` or `"server"` |
| `TESTCASE` | Test case name (e.g., `handshake`, `transfer`, `retry`, `http3`) |
| `REQUESTS` | Space-separated URLs for client to download |
| `SSLKEYLOGFILE` | Path to write TLS secrets (NSS Key Log format) |
| `QLOGDIR` | Directory for qlog output |
| `CLIENT_PARAMS` | Extra client parameters |
| `SERVER_PARAMS` | Extra server parameters |

## Volume Mounts

| Path | Purpose |
|------|---------|
| `/www` | Files for server to serve (read-only) |
| `/downloads` | Client saves downloaded files here |
| `/certs` | `cert.pem` (chain) + `priv.key` |
| `/logs` | Log output directory |

## Protocol: HTTP/0.9 (`hq-interop`)

Most test cases use HTTP/0.9 over QUIC (NOT HTTP/3). ALPN: `hq-interop`.

**Client**: Open stream → send `GET /filename\r\n` → close write → read response → save to `/downloads/filename`

**Server**: Accept connection → accept stream → read `GET /path\r\n` → serve file from `/www/path` → close stream

## Exit Codes

- `0` — success
- `1` — failure
- `127` — test case not supported (required for graceful degradation)

## Test Cases

| # | Test | `TESTCASE` value | What it tests | Status |
|---|------|------------------|---------------|--------|
| 1 | Handshake | `handshake` | Basic 1KB transfer | Ready |
| 2 | Transfer | `transfer` | 2+3+5 MB concurrent streams | Ready |
| 3 | Long RTT | `longrtt` (server/client see `handshake`) | 750ms delay handshake | Ready |
| 4 | ChaCha20 | `chacha20` | ChaCha20-Poly1305 only | **Missing cipher** |
| 5 | Multiplexing | `multiplexing` (endpoints see `transfer`) | 2000×32B, stream limit ≤1000 | Ready |
| 6 | Retry | `retry` | Retry packet + token | Ready |
| 7 | Resumption | `resumption` | 2 connections, no cert in 2nd | Ready |
| 8 | 0-RTT | `zerortt` | 0-RTT data in 2nd connection | Ready |
| 9 | HTTP/3 | `http3` | H3 ALPN + transfer | Ready |
| 10 | Amplification Limit | `amplificationlimit` (endpoints see `transfer`) | 3x server limit, 9-cert chain | Ready |
| 11 | Blackhole | `blackhole` (endpoints see `transfer`) | 5s on/2s off, PTO recovery | Ready |
| 12 | Key Update | `keyupdate` (server sees `transfer`) | Key phase bit flip | Ready |
| 13 | Handshake Loss | `handshakeloss` (endpoints see `multiconnect`) | 30% loss, 50 handshakes | Ready |
| 14 | Transfer Loss | `transferloss` (endpoints see `transfer`) | 2% loss | Ready |
| 15 | Handshake Corruption | `handshakecorruption` (endpoints see `multiconnect`) | 30% corruption | Ready |
| 16 | Transfer Corruption | `transfercorruption` (endpoints see `transfer`) | 2% corruption | Ready |
| 17 | ECN | `ecn` (endpoints see `handshake`) | ECT marking + ACK-ECN | Ready |
| 18 | Port Rebind | `rebind-port` (endpoints see `transfer`) | PATH_CHALLENGE on new port | Ready |
| 19 | Addr Rebind | `rebind-addr` (endpoints see `transfer`) | Path validation on new IP | Ready |
| 20 | IPv6 | `ipv6` (endpoints see `transfer`) | IPv6 only | **Missing IPv6 sockets** |
| 21 | Conn Migration | `connectionmigration` | Server preferred address | Partial |
| 22 | V2 | `v2` | QUIC v2 negotiation | **Missing v2** |

## Implementation Gaps

### Must Have (blocks interop runner participation)

1. **HTTP/0.9 protocol** — `GET /path\r\n` request/response over QUIC streams, ALPN `hq-interop`
2. **SSLKEYLOGFILE** — Export TLS traffic secrets in NSS Key Log format from tls13.zig
3. **Interop server binary** — Configurable addr/port/certs, `$TESTCASE` dispatch, serves `/www`
4. **Interop client binary** — Parses `$REQUESTS` URLs, downloads to `/downloads/`, handles test modes
5. **`run_endpoint.sh`** — Entry point dispatching on `$ROLE`, exit 127 for unsupported
6. **`Dockerfile`** — Multi-stage: Zig build → network-simulator-endpoint base

### Nice to Have

7. **qlog** — QLOG event logging to `$QLOGDIR`
8. **ChaCha20-Poly1305** — For `chacha20` test case
9. **QUIC v2** — For `v2` test case
10. **IPv6 sockets** — For `ipv6` test case

## SSLKEYLOGFILE Format

NSS Key Log format, one line per secret:
```
CLIENT_HANDSHAKE_TRAFFIC_SECRET <client_random_hex> <secret_hex>
SERVER_HANDSHAKE_TRAFFIC_SECRET <client_random_hex> <secret_hex>
CLIENT_TRAFFIC_SECRET_0 <client_random_hex> <secret_hex>
SERVER_TRAFFIC_SECRET_0 <client_random_hex> <secret_hex>
```

The `client_random` is the 32-byte random from the ClientHello message.

## Docker Setup

### Dockerfile (multi-stage)

```dockerfile
FROM martenseemann/quic-network-simulator-endpoint:latest AS builder
RUN apt-get update && apt-get install -y xz-utils
# Install Zig 0.15.2
ADD https://ziglang.org/builds/zig-linux-x86_64-0.15.2.tar.xz /tmp/
RUN tar -xf /tmp/zig-linux-x86_64-0.15.2.tar.xz -C /opt && \
    ln -s /opt/zig-linux-x86_64-0.15.2/zig /usr/local/bin/zig
COPY . /src
WORKDIR /src
RUN zig build -Doptimize=ReleaseSafe

FROM martenseemann/quic-network-simulator-endpoint:latest
COPY --from=builder /src/zig-out/bin/interop-server /usr/local/bin/
COPY --from=builder /src/zig-out/bin/interop-client /usr/local/bin/
COPY interop/runner/run_endpoint.sh /
RUN chmod +x /run_endpoint.sh
ENTRYPOINT ["/run_endpoint.sh"]
```

### run_endpoint.sh

```bash
#!/bin/bash
set -e
/setup.sh

if [ "$ROLE" == "client" ]; then
    /wait-for-it.sh sim:57832 -s -t 30
    interop-client $CLIENT_PARAMS $REQUESTS
elif [ "$ROLE" == "server" ]; then
    interop-server $SERVER_PARAMS
else
    echo "unknown role: $ROLE"
    exit 127
fi
```

## Registration

Add to `implementations_quic.json`:
```json
{
  "quic-zig": {
    "image": "ghcr.io/user/quic-zig-interop:latest",
    "url": "https://github.com/user/quic-zig",
    "role": "both"
  }
}
```

Image must be `linux/amd64`. Publish via GitHub Actions + `docker buildx`.
