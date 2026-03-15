# QUIC-LB: Load Balancing

Implementation of [draft-ietf-quic-load-balancers](https://datatracker.ietf.org/doc/html/draft-ietf-quic-load-balancers) for routing QUIC packets across multiple backend servers.

## How it works

```
Client ──── UDP ────► QUIC-LB (port 443) ──── UDP ────► Server A (server_id=0001)
                      extracts server_id       ├─────► Server B (server_id=0002)
                      from encrypted CID       └─────► Server C (server_id=0003)
```

1. Each backend server encodes its **server_id** into every Connection ID it generates
2. The load balancer decrypts the CID to extract the server_id and routes to the correct backend
3. Connection migration works automatically — the CID always identifies the server

## Quick Start

### 1. Create a config file

```
# quic-lb.conf
listen 0.0.0.0:443
config_id 0
server_id_len 2
nonce_len 6
key 0123456789abcdef0123456789abcdef
server 0001 10.0.0.1:4433
server 0002 10.0.0.2:4433
```

### 2. Start backend servers

Each server needs `--server-id` and `--lb-key` matching the config:

```sh
# Server A
zig-out/bin/server --port 4433 --server-id 0001 --lb-key 0123456789abcdef0123456789abcdef

# Server B
zig-out/bin/server --port 4433 --server-id 0002 --lb-key 0123456789abcdef0123456789abcdef
```

### 3. Start the load balancer

```sh
zig-out/bin/quic-lb quic-lb.conf
```

### 4. Connect through the LB

```sh
zig-out/bin/client --port 443
```

## Config File Format

```
listen <ip:port>          # LB listen address
config_id <0-6>           # Config rotation ID (3 bits)
server_id_len <1-15>      # Server ID length in bytes
nonce_len <4-18>          # Nonce length in bytes
key <32 hex chars>        # AES-128 encryption key (omit for plaintext mode)
server <id_hex> <ip:port> # Backend mapping (repeat for each server)
```

- `server_id_len + nonce_len` must be ≤ 19
- The `key` enables encrypted mode (4-pass Feistel cipher or single-pass AES-ECB)
- Without `key`, server IDs are visible in plaintext (use only in trusted networks)

## Server Flags

Both `server` and `wt-browser-server` accept:

```
--server-id <hex>    Server ID (must match LB config, e.g. "0001")
--lb-key <hex>       AES-128 key (32 hex chars, must match LB config)
```

## Encryption Modes

| Mode | When | Security |
|---|---|---|
| **Plaintext** | No `key` in config | Server ID visible to observers |
| **4-pass Feistel** | `key` set, `server_id_len + nonce_len ≠ 16` | Encrypted with AES-ECB rounds |
| **Single-pass AES** | `key` set, `server_id_len + nonce_len = 16` | Direct AES-ECB block cipher |

## Programmatic Usage

```zig
const quic_lb = @import("quic").quic_lb;

// Configure QUIC-LB CID encoding
var lb_config = quic_lb.Config{
    .config_id = 0,
    .server_id_len = 2,
    .nonce_len = 6,
    .key = my_aes_key, // or null for plaintext
};
lb_config.server_id[0] = 0x00;
lb_config.server_id[1] = 0x01;

// Pass to connection config
const conn_config = connection.ConnectionConfig{
    .quic_lb = lb_config,
};
```

## Limitations

- Initial packets from new clients have random DCIDs (not QUIC-LB encoded) — the LB uses round-robin for these
- Retry tokens are disabled when QUIC-LB is active (Retry changes the DCID)
- The LB tracks client↔backend mappings for return traffic (not fully stateless)
- Single-socket LB — adequate for moderate traffic; production deployments may want kernel-level routing

## CID Format

```
┌──────────────┬────────────────────────────────────┐
│  First Octet │         Encrypted Payload          │
│ [config][len]│     [server_id]     [nonce]        │
│  3 bits 5bits│   server_id_len    nonce_len       │
└──────────────┴────────────────────────────────────┘
```

- Bits 7-5 of the first octet: config rotation ID (0-6)
- Bits 4-0: CID length self-encoding (or random if disabled)
- Remaining bytes: server_id + nonce, optionally encrypted
