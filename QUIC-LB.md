# QUIC-LB: Load Balancing

Two coexisting modes:

- **Draft-20 mode** — compatible with [draft-ietf-quic-load-balancers](https://datatracker.ietf.org/doc/html/draft-ietf-quic-load-balancers) CID encoding (plaintext, 4-pass Feistel, single-pass AES-ECB).
- **Netcode mode** — proprietary 17-byte CID + retry offload + LB↔backend envelope framing, designed for game-server fabrics where the CID is opaque to clients and both sides of the LB boundary are ours. See [Netcode mode](#netcode-mode) below.

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

## Netcode mode

When the CID is opaque to clients (which RFC 9000 mandates) and you control both the LB and the backends, there's no reason to fight the draft's variable-length + Feistel design. Netcode mode chooses a simpler fixed layout and, on top of it, offers **retry offload** — the LB, not the backend, mints and validates Retry tokens — and an **LB↔backend envelope** that delivers the original DCID to the backend so it can populate `original_destination_connection_id` per RFC 9000 §7.3.

### Netcode CID format

```
byte 0: {config_id:3 | length:5}   (length = 16 → encoded as 0b?????_10000)
bytes 1..17: AES-128-ECB(
    server_id:4 || reserved:4 || nonce:8
)
```

Fixed 17-byte CID, single-pass AES-128-ECB, one block, no Feistel. `server_id` is 4 bytes you interpret as you like (e.g. `{region:1, host:2, shard:1}` or a flat u32). The first octet preserves the draft's length self-encoding so a stateless LB parses any short-header packet without per-connection state.

### Retry Service

Enable with `require_retry true` + `retry_key`. The LB:

1. Receives an Initial, picks a backend (CID-routed if already netcode-encoded; round-robin otherwise).
2. Mints a new **Retry SCID** via `generateNetcodeCid` that encodes the chosen backend's `server_id` — so post-Retry packets route back to the same backend.
3. AEAD-seals a self-contained token: `key_id(1) || nonce(12) || AES-128-GCM({timestamp, backend_id, addr_data, odcid, retry_scid}, AAD=key_id) || tag(16)`.
4. Sends an RFC 9000 Retry packet. Backends never see Retry; they continue to think they issued it.

Token replay: the token's AEAD AAD authenticates the key_id, plaintext authenticates the client address and timestamp. We intentionally **do not reject repeat token presentations** — RFC 9000 allows clients to retransmit the retried Initial with the same token, so strict nonce-based replay rejection would break recovery after packet loss. Cross-address replay is prevented by the in-token address binding; temporal bound is the token lifetime (default 10s).

### LB↔backend envelope

Enable with `envelope_hmac_key` (32 bytes hex). Wire layout:

```
magic(4) = 'NCNR'
version(1)
flags(1)       // bit0 was_retried | bit1 has_hmac
odcid_len(1) | odcid
retry_scid_len(1) | retry_scid
hmac(16)       // HMAC-SHA256 truncated to 16 bytes (if has_hmac)
quic_payload
```

HMAC covers everything except the tag itself. Backends strip the envelope in `ConnectionManager.recvDatagram` and inject ODCID + retry_scid into the new connection's transport params.

### Config example

```
listen 127.0.0.1:14500
cid_format netcode
config_id 0
netcode_key 00112233445566778899aabbccddeeff
require_retry true
retry_key ffeeddccbbaa99887766554433221100
envelope_hmac_key 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
server 00000001 127.0.0.1:14501
server 00000002 127.0.0.1:14502
```

Backends launch with matching envelope settings:

```sh
zig-out/bin/server --port 14501 --lb-envelope --envelope-hmac <64-hex>
zig-out/bin/server --port 14502 --lb-envelope --envelope-hmac <64-hex>
```

### Interop tested

- Zig H3 client → LB (netcode + retry + envelope) → backend → H3 200 ✅
- quic-go H3 client → LB → backend → H3 200 ✅

Reproduce with `tools/test_lb_retry.sh`.

### Trust model

- The envelope is proprietary LB↔backend framing. Clients never see it.
- Without `envelope_hmac_key`, the envelope has no authentication — backends MUST bind to a private interface (e.g. loopback, VPC) so only the LB can reach them.
- With `envelope_hmac_key`, HMAC-SHA256 authenticates every enveloped datagram end-to-end. Safe across untrusted networks.

### Limitations

- Mixed backend fleets: if some backends are quic-zig and others are third-party (quiche, nginx, etc.), envelope mode can't be global. The third-party backends will lose retry-offload (they never receive the ODCID).
- Key rotation: `RetryService` supports current+previous keys. Token carries `key_id` (0 = current, 1 = previous) so you can roll keys without dropping in-flight handshakes.
- Matchmaker mint-CID: the structured `server_id` is designed for a matchmaker to pre-mint CIDs before handing clients the LB address. API: `quic_lb.generateNetcodeCid(config, server_id, out)`. Client-side support (providing the first DCID explicitly) is not yet wired into the Zig client CLI.
