# QUIC Interop Testing with quiche

Rust-based QUIC client and server using [cloudflare/quiche](https://github.com/cloudflare/quiche) for testing against the Zig QUIC implementation.

## Setup

```bash
cd interop/quiche

# Copy certificates from quic-go (or generate new ones)
cp -r ../quic-go/certs .

# Build the project
cargo build --release
```

## Usage

### quiche server (for Zig client to connect to)

```bash
cargo run --bin server                           # listens on 127.0.0.1:4434
cargo run --bin server -- --addr 127.0.0.1:4433 # custom port
```

### quiche client (for connecting to Zig server)

```bash
cargo run --bin client                           # connects to 127.0.0.1:4433
cargo run --bin client -- --addr 127.0.0.1:4434 # connect to quiche server
cargo run --bin client -- --msg "test data"      # custom message
```

### quiche-to-quiche echo test

```bash
# Terminal 1: start the quiche server
cargo run --bin server

# Terminal 2: connect with quiche client
cargo run --bin client -- --addr 127.0.0.1:4434
```

### Zig-to-quiche / quiche-to-Zig

```bash
# Test Zig server with quiche client
# Terminal 1: start Zig server on :4433
# Terminal 2:
cargo run --bin client -- --addr 127.0.0.1:4433

# Test Zig client with quiche server
# Terminal 1:
cargo run --bin server -- --addr 127.0.0.1:4433
# Terminal 2: start Zig client connecting to :4433
```

## Certificates

The `certs/` directory should contain ECDSA P-256 certificates compatible with the Zig TLS 1.3 implementation:

- `ca.crt` / `ca.key` — self-signed CA
- `server.crt` / `server.key` — server cert (SAN: localhost, 127.0.0.1)

Generate new certificates using the script from quic-go:

```bash
../quic-go/generate-certs.sh
```

## Flags

Both client and server support these flags:

| Flag | Default | Description |
|------|---------|-------------|
| `--addr` | `127.0.0.1:4433` (client) / `127.0.0.1:4434` (server) | Address |
| `--alpn` | `h3` | ALPN protocol |
| `--cert` | `certs/server.crt` | TLS certificate (server only) |
| `--key` | `certs/server.key` | TLS private key (server only) |
| `--msg` | `hello from quiche client` | Message to send (client only) |
