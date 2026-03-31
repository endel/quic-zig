# quic-zig WASM API

Full QUIC + TLS 1.3 state machine compiled to WebAssembly. No network I/O — the host (JavaScript) is responsible for feeding packets in and sending packets out.

## Build

```sh
zig build wasm
# Output: wasm/quic.wasm
```

## Instantiation

```js
const wasmBytes = await fetch('quic.wasm').then(r => r.arrayBuffer());
const { instance } = await WebAssembly.instantiate(wasmBytes, {
  env: {
    get_time_ns: () => BigInt(Math.round(performance.now() * 1_000_000)),
    console_log: (ptr, len) => {
      const msg = new TextDecoder().decode(
        new Uint8Array(instance.exports.memory.buffer, ptr, len)
      );
      console.log('[quic]', msg);
    },
    random_fill: (ptr, len) => {
      crypto.getRandomValues(
        new Uint8Array(instance.exports.memory.buffer, ptr, len)
      );
    },
  },
});
const wasm = instance.exports;
```

### Required imports (`env`)

| Import         | Signature                        | Description                          |
|----------------|----------------------------------|--------------------------------------|
| `get_time_ns`  | `() → i64 (BigInt)`             | Monotonic clock in nanoseconds       |
| `console_log`  | `(ptr: u32, len: u32) → void`   | Log a UTF-8 string from WASM memory |
| `random_fill`  | `(ptr: u32, len: u32) → void`   | Fill buffer with cryptographic random bytes |

## API Reference

### Memory management

| Export                          | Description |
|---------------------------------|-------------|
| `qz_alloc(len: u32) → ptr`     | Allocate `len` bytes in WASM memory. Returns pointer, or 0 on failure. |
| `qz_free(ptr, len: u32)`       | Free a buffer previously returned by `qz_alloc`. |

All data exchange between JS and WASM goes through `qz_alloc`/`qz_free`. The pattern is always:

```js
const ptr = wasm.qz_alloc(data.byteLength);
new Uint8Array(wasm.memory.buffer, ptr, data.byteLength).set(data);
// ... call WASM function with ptr ...
wasm.qz_free(ptr, data.byteLength);
```

> **Warning:** Any WASM call that allocates (including `qz_alloc`, `qz_recv_packet`, `qz_poll_event`) may trigger `memory.grow`, which **detaches** the underlying `ArrayBuffer`. Always re-create `Uint8Array` views after calling into WASM.

### Certificates

The WASM module embeds a default certificate. To provide your own (required for browser WebTransport, which needs ≤14-day validity):

| Export                                   | Description |
|------------------------------------------|-------------|
| `qz_set_cert(ptr, len: u32) → i32`      | Set DER-encoded X.509 certificate. Returns 0 on success. |
| `qz_set_key(ptr, len: u32) → i32`       | Set DER-encoded EC private key (P-256). Returns 0 on success. |

**Call both before `qz_init_server` / `qz_init_client`.** If not called, the embedded cert/key is used.

```js
// Example: load cert and key from fetch or generated in JS
const certDer = new Uint8Array(/* DER bytes */);
const keyDer  = new Uint8Array(/* DER bytes */);

const certPtr = wasm.qz_alloc(certDer.byteLength);
new Uint8Array(wasm.memory.buffer, certPtr, certDer.byteLength).set(certDer);
wasm.qz_set_cert(certPtr, certDer.byteLength);
wasm.qz_free(certPtr, certDer.byteLength);

const keyPtr = wasm.qz_alloc(keyDer.byteLength);
new Uint8Array(wasm.memory.buffer, keyPtr, keyDer.byteLength).set(keyDer);
wasm.qz_set_key(keyPtr, keyDer.byteLength);
wasm.qz_free(keyPtr, keyDer.byteLength);
```

Generate a browser-compatible cert (ECDSA P-256, ≤14 days):
```sh
openssl ecparam -name prime256v1 -genkey -noout -out key.pem
openssl req -new -x509 -key key.pem -out cert.pem -days 13 -subj '/CN=127.0.0.1'
openssl x509 -in cert.pem -outform der -out cert.der
openssl ec -in key.pem -outform der -out key.der 2>/dev/null
# SHA-256 digest for serverCertificateHashes:
openssl x509 -in cert.pem -outform der | openssl dgst -sha256 -binary | xxd -p
```

### Lifecycle

| Export                              | Description |
|-------------------------------------|-------------|
| `qz_init_server() → i32`           | Initialize as QUIC server. Returns 0 on success. |
| `qz_init_client() → i32`           | Initialize as QUIC client (sends Initial immediately). Returns 0 on success. |
| `qz_deinit()`                      | Tear down the instance and free all memory. |
| `qz_is_established() → bool`       | True after TLS handshake completes. |
| `qz_is_closed() → bool`            | True after connection is fully closed. |

### Packet I/O

These are the core functions for driving the QUIC state machine. The host is responsible for transporting packets between peers (via UDP socket, loopback between two WASM instances, etc.).

#### Receiving packets (network → WASM)

```
qz_recv_packet(ptr, len: u32) → i32
```

Feed a raw QUIC packet into the state machine. Returns 0 on success.

```js
function feedPacket(wasm, packet /* Uint8Array */) {
  const ptr = wasm.qz_alloc(packet.byteLength);
  new Uint8Array(wasm.memory.buffer, ptr, packet.byteLength).set(packet);
  wasm.qz_recv_packet(ptr, packet.byteLength);
  wasm.qz_free(ptr, packet.byteLength);
}
```

#### Sending packets (WASM → network)

```
qz_send_packets(out_ptr, out_len: u32) → u32
```

Drains outgoing packets into a buffer. Returns total bytes written. Packets are length-prefixed:

```
[4-byte BE length][packet bytes][4-byte BE length][packet bytes]...
```

```js
function drainPackets(wasm) {
  const bufLen = 65536;
  const ptr = wasm.qz_alloc(bufLen);
  const total = wasm.qz_send_packets(ptr, bufLen);

  // Copy out immediately (memory.grow may detach buffer)
  const raw = new Uint8Array(new Uint8Array(wasm.memory.buffer, ptr, total));
  wasm.qz_free(ptr, bufLen);

  const packets = [];
  let offset = 0;
  while (offset + 4 <= total) {
    const len = (raw[offset]<<24) | (raw[offset+1]<<16) | (raw[offset+2]<<8) | raw[offset+3];
    offset += 4;
    packets.push(raw.slice(offset, offset + len));
    offset += len;
  }
  return packets; // Array of Uint8Array
}
```

### Timers

| Export                              | Description |
|-------------------------------------|-------------|
| `qz_on_timeout()`                  | Notify the state machine that a timer has fired. Call this periodically and/or when `qz_next_timeout_ns` expires. |
| `qz_next_timeout_ns() → i64`      | Returns the next timeout deadline in nanoseconds, or -1 if none. |

Typical timer loop:

```js
setInterval(() => {
  wasm.qz_on_timeout();
  for (const pkt of drainPackets(wasm)) {
    sendToNetwork(pkt);
  }
}, 50);
```

### Events

```
qz_poll_event(buf_ptr, buf_len: u32) → u32
```

Pops the next event from the queue. Returns bytes written (0 = no more events). Call in a loop until it returns 0.

Event format — first byte is the type, followed by type-specific payload:

| Byte | Type               | Payload                                  |
|------|--------------------|------------------------------------------|
| 0x01 | `ESTABLISHED`      | *(none)* — QUIC+TLS handshake complete   |
| 0x02 | `CLOSED`           | *(none)* — connection closed             |
| 0x03 | `STREAM_DATA`      | `stream_id: u64 BE` + `length: u64 BE`  |
| 0x04 | `DATAGRAM`         | *(reserved)*                             |
| 0x05 | `WT_SESSION`       | `session_id: u64 BE` — CONNECT request, call `qz_wt_accept_session` |
| 0x06 | `WT_BIDI_STREAM`   | `session_id: u64 BE` + `stream_id: u64 BE` |
| 0x07 | `WT_STREAM_DATA`   | `stream_id: u64 BE` + `length: u64 BE`  |
| 0x08 | `WT_STREAM_FIN`    | `stream_id: u64 BE` — remote closed stream |
| 0x09 | `WT_DATAGRAM`      | `session_id: u64 BE` + `length: u64 BE` |
| 0x0A | `WT_SESSION_CLOSED`| `session_id: u64 BE` + `error_code: u32 BE` |

### Raw QUIC stream I/O

| Export                                              | Returns | Description |
|-----------------------------------------------------|---------|-------------|
| `qz_stream_read(stream_id: u64, out_ptr, out_len)` | `i32`   | Read available data from a receive stream. Returns bytes read, 0 if nothing available, -1 on error. |
| `qz_stream_send(stream_id: u64, data_ptr, len)`    | `i32`   | Write data to a send stream. Returns 0 on success. |
| `qz_stream_close(stream_id: u64)`                  | `void`  | Close (FIN) a send stream. |

### Raw QUIC datagram I/O

| Export                                       | Returns | Description |
|----------------------------------------------|---------|-------------|
| `qz_datagram_send(data_ptr, len: u32)`       | `i32`   | Send an unreliable datagram. Returns 0 on success. |
| `qz_datagram_recv(out_ptr, out_len: u32)`    | `i32`   | Receive next queued datagram. Returns bytes read, 0 if empty, -1 on error. |

### WebTransport API

| Export                                                            | Returns | Description |
|-------------------------------------------------------------------|---------|-------------|
| `qz_wt_accept_session(session_id: u64)`                          | `i32`   | Accept a WT session (sends HTTP/3 200 response). Call after `EVT_WT_SESSION`. |
| `qz_wt_read_stream(stream_id: u64, out_ptr, out_len)`            | `i32`   | Read data from a WT stream. Returns bytes read, 0 if empty, -1 on error. |
| `qz_wt_send_stream(stream_id: u64, data_ptr, len)`               | `i32`   | Write data to a WT stream. Returns 0 on success. |
| `qz_wt_close_stream(stream_id: u64)`                             | `void`  | Close (FIN) a WT stream. |
| `qz_wt_send_datagram(session_id: u64, data_ptr, len)`            | `i32`   | Send a WT datagram. Returns 0 on success. |
| `qz_wt_close_session(session_id: u64, error_code, reason_ptr, reason_len)` | `i32` | Close a WT session with error code and reason. |

## WebTransport echo server example

See [`webtransport-example.js`](webtransport-example.js) for a fully commented example showing:
- Where raw UDP packets enter the WASM state machine
- Where decoded application data is available to read
- Where to write response data back into the state machine
- Where encrypted response packets come out to send back

Summary of the data flow:
```
UDP packet in → feedPacket() → qz_recv_packet()
                                    │
                             qz_poll_event()
                                    │
              ┌─────────────────────┼──────────────────────┐
              │                     │                      │
       EVT_WT_SESSION        EVT_WT_STREAM_DATA      EVT_WT_DATAGRAM
              │                     │                      │
   qz_wt_accept_session()  qz_wt_read_stream()    qz_datagram_recv()
                             ← decoded data here    ← decoded data here
                                    │                      │
                            qz_wt_send_stream()    qz_wt_send_datagram()
                             → write response here  → write response here
                                    │                      │
                              qz_send_packets()
                                    │
                             encrypted QUIC packets → send to network
```
