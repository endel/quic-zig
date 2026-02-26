# QUIC Interop Testing

Go-based QUIC client and server using [quic-go](https://github.com/quic-go/quic-go) for testing against the Zig QUIC implementation.

## Setup

```bash
cd interop

# Generate ECDSA P-256 certificates
./generate-certs.sh

# Download Go dependencies
go mod tidy
```

## Usage

### Go server (for Zig client to connect to)

```bash
go run ./server                        # listens on localhost:4434
go run ./server --addr localhost:4433   # custom port
```

### Go client (for connecting to Zig server)

```bash
go run ./client                        # connects to localhost:4433
go run ./client --addr localhost:4434   # connect to Go server
go run ./client --msg "test data"      # custom message
```

### Go-to-Go echo test

```bash
# Terminal 1: start the Go server
go run ./server

# Terminal 2: connect with Go client
go run ./client --addr localhost:4434
```

### Zig-to-Go / Go-to-Zig

```bash
# Test Zig server with Go client
# Terminal 1: start Zig server on :4433
# Terminal 2:
go run ./client --addr localhost:4433

# Test Zig client with Go server
# Terminal 1:
go run ./server --addr localhost:4433
# Terminal 2: start Zig client connecting to :4433
```

## Certificates

The `generate-certs.sh` script creates ECDSA P-256 certificates in `certs/`:

- `ca.crt` / `ca.key` — self-signed CA
- `server.crt` / `server.key` — server cert (SAN: localhost, 127.0.0.1)

These are compatible with the Zig TLS 1.3 implementation which only supports ECDSA P-256.

## Flags

Both client and server support these flags:

| Flag | Default | Description |
|------|---------|-------------|
| `--addr` | `:4433` (client) / `:4434` (server) | Address |
| `--alpn` | `h3` | ALPN protocol |
| `--cert` | `certs/server.crt` | TLS certificate (server only) |
| `--key` | `certs/server.key` | TLS private key (server only) |
| `--msg` | `hello from quic-go client` | Message to send (client only) |
