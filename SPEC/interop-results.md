# Interop Test Results

Date: 2026-03-18
Zig version: 0.15.2, quic-go v0.59.0, webtransport-go v0.10.0
Build: `-Doptimize=ReleaseFast`, `std_options.log_level = .err` (echo server)

## Functional Interop Matrix

### QUIC (Raw Streams)

| Server | Client | Result | Notes |
|--------|--------|--------|-------|
| Zig | Go (raw QUIC) | FAIL | ALPN mismatch: Zig server speaks H3, Go client uses hq-interop |
| Go | Zig | PASS | |
| Zig | Zig | PASS | |

### HTTP/3

| Server | Client | Result | Notes |
|--------|--------|--------|-------|
| Zig | Go (h3client) | PASS | GET / -> 200 OK |
| Go (h3server) | Zig | PASS | GET / -> 200 OK |

### WebTransport

| Server | Client | Result | Notes |
|--------|--------|--------|-------|
| Zig | Go (wt_client) | PASS | Bidi echo + datagram echo |
| Go | Zig (wt-client) | FAIL | Zig client rejects self-signed cert (BadCertificate) |
| Zig | Zig (wt-client) | FAIL | Same cert validation issue |
| Zig | Chrome | PASS | Bidi echo + datagram echo via cert pinning |

**Known issues:**
- Zig WT/QUIC client requires trusted certificate chain; no `--skip-verify` flag yet.
- Raw QUIC (non-H3) interop with Go client requires hq-interop ALPN support.

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
4. **FIN-aware echo handler** — `onStreamData` was called twice per bidi stream (data + empty FIN). The handler echoed both, sending "Echo: ping" + "Echo: " (double response). This doubled packets, created congestion backpressure, and caused cascading 5-26ms spikes in Chrome. Fixed by using the 4-arg `onStreamData(session, stream_id, data, fin)` signature and only echoing non-empty data.
