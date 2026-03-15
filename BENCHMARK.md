# Benchmarks

HTTP/3 request/response throughput on localhost (macOS M-series, single-threaded servers).

## Quick Start

```sh
# Build release
zig build -Doptimize=ReleaseFast

# Start server
zig-out/bin/server --port 4434

# Run bench (another terminal)
zig-out/bin/bench --port 4434 -c 50 -n 100
```

## Bench Options

```
zig-out/bin/bench [options]
  --port PORT        Server port (default: 4434)
  -c, --connections  Number of sequential connections (default: 1)
  -n, --requests     Requests per connection (default: 100)
  -z, --zerortt      Enable 0-RTT session resumption
```

## Server Options

```
zig-out/bin/server [options]
  --port PORT        Listen port (default: 4434)
  -w, --workers N    Worker threads (default: 0 = single-threaded)
```

## Results (macOS M-series, localhost, 50 conn × 100 req)

### Server Comparison (Zig bench client)

| Server               | Req/s      | Handshake | p50    | p99    |
|----------------------|------------|-----------|--------|--------|
| quic-go (Go)         | **13,278** | 876µs     | 264µs  | 733µs  |
| **quic-zig** (Zig)   | **11,009** | 1,030µs   | 404µs  | 586µs  |
| quiche+mio (Rust)    | 1,114      | 1,143µs   | 329µs  | 1,992µs|

### Client Comparison (quic-zig server)

| Client     | Req/s      | p50    | p99     |
|------------|------------|--------|---------|
| Zig bench  | **11,009** | 404µs  | 586µs   |
| Go bench   | 6,085      | 136µs  | 1,722µs |

### 0-RTT Handshake Speedup

| Mode  | Handshake | Req/s      |
|-------|-----------|------------|
| 1-RTT | 932µs     | 11,258     |
| 0-RTT | 410µs     | **12,409** |

### Debug vs Release

| Build   | Req/s      | Handshake | p50     |
|---------|------------|-----------|---------|
| Debug   | 3,561      | 5,441µs   | 1,411µs |
| Release | **11,678** | 891µs     | 383µs   |

## Reproducing Comparisons

### quic-go server

```sh
cd interop/quic-go
go build -o h3server_bin ./h3server
./h3server_bin --addr localhost:4435 \
  --cert ../certs/server.crt --key ../certs/server.key
```

### quiche server (Rust + mio)

```sh
cd interop/quiche
cargo build --release --bin h3server
./target/release/h3server --addr 127.0.0.1:4436 \
  --cert ../certs/server.crt --key ../certs/server.key
```

### Go bench client

```sh
cd interop/quic-go
go build -o bench_bin ./bench
./bench_bin -port 4434 -c 50 -n 100
```

## Notes

- All servers use the same TLS certificates (`interop/certs/`)
- quiche's standalone server processes connections serially; in Cloudflare's production stack it uses connection-per-worker sharding
- The Go client shows lower p50 latency but lower throughput due to `net/http` overhead
- Multi-worker mode (`--workers N`) uses a recv thread + N worker threads with CID-based dispatch
