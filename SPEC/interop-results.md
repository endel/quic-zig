# Interop Test Results

Date: 2026-04-15 (supersedes 2026-03-24 baseline below)
Zig version: 0.15.2, quic-go interop image `martenseemann/quic-go-interop:latest`, neqo interop image `ghcr.io/mozilla/neqo-qns:latest`, webtransport-go interop image `martenseemann/webtransport-go-interop:latest`
Build: Docker interop image from `interop/runner/Dockerfile`, `zig build -Doptimize=ReleaseSafe`

## 2026-04-15: UDP send-path optimizations (`sendmmsg` + pacer hardening)

Inspired by Cloudflare's "Accelerating UDP packet transmission for QUIC" post,
narrowed to the techniques that fit a real-time WebTransport workload (small
datagrams, latency-sensitive). Larger throughput-oriented optimizations (UDP
GSO, SO_TXTIME kernel pacing) were prototyped, validated, and reverted —
see "Cloudflare optimizations: what we kept and why" in `SPEC/STATUS.md` if
revisiting in the future.

### Send-path toggles
| Feature | Default | Env var | Notes |
|---------|---------|---------|-------|
| `sendmmsg` batching | on (Linux) | `QUIC_ZIG_NO_SENDMMSG=1` disables | one syscall per ECN-mark run |
| User-space pacer | on | `QUIC_ZIG_NO_PACING=1` disables | bisection escape hatch |
| Pacer clock | always `CLOCK_MONOTONIC` | n/a | NTP-skew resilience |

### Matrix (sequential run, `handshake,transfer,chacha20,multiplexing,longrtt,http3,keyupdate`)

|                           | quic-go (server/client) | neqo (server/client) |
|---------------------------|-------------------------|----------------------|
| quic-zig server ← peer client | **7/7 PASS**        | **7/7 PASS**         |
| quic-zig client → peer server | **7/7 PASS**        | **6-7/7 PASS**       |

Zero regressions against the 2026-03-24 baseline recorded below. The
zig-client → neqo-server flake on `keyupdate`/`chacha20` predates this work.

## 2026-03-24 baseline (pre-optimization)

## Functional Interop Matrix

### QUIC / HTTP/3 (`quic-go`)

#### Zig server ← quic-go client (9/14 pass)

| Test | Result | Notes |
|------|--------|-------|
| handshake | PASS | |
| transfer | PASS | |
| retry | PASS | |
| http3 | PASS | |
| longrtt | PASS | |
| multiplexing | PASS | |
| keyupdate | PASS | |
| amplificationlimit | PASS | |
| transferloss | PASS | |
| blackhole | FAIL | Quick failure — PTO recovery stalls |
| handshakeloss | FAIL | 30% loss, handshake timeout |
| handshakecorruption | FAIL | Corruption, handshake timeout |
| transfercorruption | FAIL | Corruption during transfer, timeout |
| connectionmigration | FAIL | Go client didn't migrate to preferred address |

#### quic-go server ← Zig client (12/15 pass)

| Test | Result | Notes |
|------|--------|-------|
| handshake | PASS | |
| transfer | PASS | |
| retry | PASS | |
| http3 | PASS | |
| longrtt | PASS | |
| multiplexing | PASS | |
| blackhole | PASS | |
| keyupdate | PASS | |
| handshakeloss | PASS | |
| transferloss | PASS | |
| handshakecorruption | PASS | |
| transfercorruption | PASS | |
| ecn | UNSUPPORTED | Go server does not support ECN test case |
| amplificationlimit | FAIL | Timeout during amplification-limited transfer |
| connectionmigration | UNSUPPORTED | Go server does not support connectionmigration test case |

### WebTransport (`webtransport-go`)

#### Zig server ← webtransport-go client (5/7 pass)

| Test | Result |
|------|--------|
| handshake | PASS |
| transfer-unidirectional-receive | PASS |
| transfer-unidirectional-send | PASS |
| transfer-bidirectional-receive | FAIL |
| transfer-bidirectional-send | PASS |
| transfer-datagram-receive | PASS |
| transfer-datagram-send | FAIL |

#### webtransport-go server ← Zig client (5/7 pass)

| Test | Result |
|------|--------|
| handshake | PASS |
| transfer-unidirectional-receive | PASS |
| transfer-unidirectional-send | PASS |
| transfer-bidirectional-receive | PASS |
| transfer-bidirectional-send | FAIL |
| transfer-datagram-receive | FAIL |
| transfer-datagram-send | PASS |

### Legend
- `H` handshake, `DC` transfer, `S` retry, `3` HTTP/3, `LR` longrtt, `M` multiplexing
- `B` blackhole, `U` keyupdate, `E` ecn, `A` amplificationlimit
- `L1` handshakeloss, `L2` transferloss, `C1` handshakecorruption, `C2` transfercorruption, `CM` connectionmigration
- `UR` unidi-receive, `US` unidi-send, `BR` bidi-receive, `BS` bidi-send, `DR` datagram-receive, `DS` datagram-send

**Latest findings (2026-03-24):**
- **CRYPTO_ERROR 0x133 resolved** — the earlier "ECDSA verification failure" was caused by Docker container race conditions (stale sim container), not a real TLS bug. With clean Docker state, all handshakes succeed in both directions.
- Zig-as-server now passes 9/14 QUIC tests (up from 0). Remaining failures are loss/corruption recovery and connection migration.
- Zig-as-client passes 12/15 QUIC tests (up from 4). Only `amplificationlimit` fails.
- WebTransport passes 5/7 in both directions. The bidi/datagram failures are directionally swapped.
- Linux interop containers use `epoll` backend (not `io_uring` due to kernel version).

**Remaining work:**
- Loss/corruption recovery: blackhole, handshakeloss, handshakecorruption, transfercorruption (Zig server PTO recovery under adverse conditions)
- Connection migration: preferred address migration not triggering path change in Go client
- Amplification limit: Zig client timeout during amplification-limited handshake
- WebTransport bidi-send/receive and datagram-send/receive directional failures

## Latency Benchmarks

### Go WT Client -> Server (localhost, 2000 iterations)

| Metric | Go server | Zig server | Ratio |
|--------|-----------|------------|-------|
| Bidi median | 96µs | 101µs | 1.05x |
| Bidi p95 | 181µs | 240µs | 1.33x |
| Bidi p99 | 307µs | 357µs | 1.16x |
| Bidi max | 1.214ms | 674µs | **0.56x** |
| DG median | 62µs | 79µs | 1.27x |
| DG p95 | 96µs | 123µs | 1.28x |
| DG p99 | 111µs | 198µs | 1.78x |
| DG max | 285µs | 595µs | 2.09x |

### Chrome WebTransport (puppeteer, `page.evaluate`, 1000 iterations)

| Metric | Go server | Zig server | Ratio |
|--------|-----------|------------|-------|
| Bidi median | 0.20ms | 0.20ms | 1.0x |
| Bidi p99 | 0.40ms | 0.60ms | 1.5x |
| DG median | 0.10ms | 0.20ms | 2.0x |
| DG p99 | 0.20ms | 0.30ms | 1.5x |
| Spikes >5ms | 0 | 0 | -- |

### Chrome WebTransport (latency.html with DOM updates, 1000 iterations)

| Metric | Go server | Zig server | Ratio |
|--------|-----------|------------|-------|
| Bidi median | 0.40ms | 0.40ms | 1.0x |
| Bidi p95 | 1.30ms | 1.30ms | 1.0x |
| Bidi p99 | 2.20ms | 2.10ms | 0.95x |
| DG median | 0.60ms | 0.60ms | 1.0x |
| DG p95 | 2.00ms | 2.00ms | 1.0x |
| Spikes >5ms | 8 | 8 | 1.0x |

## Optimizations Applied

1. **ReleaseFast build** — Debug mode added ~400µs/packet from safety checks and unoptimized codegen.
2. **Log level `.err`** — `std.log.info` (67 calls in connection.zig) was flushing to stderr on every packet in ReleaseFast (default level is `.info`).
3. **Targeted stream disposal** — Closed streams accumulated in HashMaps, causing O(n) scans in `pollWtStreamData`, `identifyWtBidiStreams`, `getScheduledStreams`. Fixed with a disposal queue: `queueDisposal()` at close time, `drainDisposalQueue()` once per cycle. O(k) where k = streams just closed.
4. **FIN-aware echo handler** — `onStreamData` was called twice per bidi stream (data + empty FIN). The handler echoed both, sending "Echo: ping" + "Echo: " (double response). This doubled packets, created congestion backpressure, and caused cascading 5-26ms spikes in Chrome. Fixed by using the `onStreamData(session, stream_id, data, fin)` signature and only echoing non-empty data while using `fin` to decide when to close.
