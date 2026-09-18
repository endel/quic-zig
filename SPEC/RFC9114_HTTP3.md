# RFC 9114 — HTTP/3

## Status: ✅ Complete

See also the section-level status matrix in [STATUS.md](STATUS.md#rfc-9114--http3).

## Implementation

| Area | File |
|------|------|
| Frame codec | `src/h3/frame.zig` |
| Connection state machine | `src/h3/connection.zig` |
| QPACK (see [RFC9204_QPACK.md](RFC9204_QPACK.md)) | `src/h3/qpack.zig`, `src/h3/huffman.zig` |
| RFC 9218 priority (see below) | `src/h3/priority.zig` |
| Capsule protocol (see [RFC9297_S4.md](RFC9297_S4.md)) | `src/h3/capsule.zig` |

## Test coverage

127 unit + integration tests across the H3 layer:

| File | Tests |
|------|------:|
| `frame.zig` | 15 |
| `connection.zig` | 57 |
| `qpack.zig` | 19 |
| `priority.zig` | 15 |
| `huffman.zig` | 11 |
| `capsule.zig` | 10 |

Bidirectional interop validated against quic-go (h3server/h3client) and the
in-tree Zig H3 client/server. See STATUS.md notes and CLAUDE.md H3 interop
section.

## §2 Protocol Overview

Each HTTP request/response exchange uses one client-initiated bidi QUIC
stream. Unidirectional streams carry control (0x00), push (0x01, unused),
and QPACK encoder (0x02) / decoder (0x03) data.

## §3.1 Discovering an HTTP/3 Endpoint — ❌ N/A

Alt-Svc is an application-level concern outside the transport/framing layer.

## §3.2 Connection Establishment — ✅ Done

- ALPN: `"h3"` (plus legacy draft labels `"h3-32".."h3-29"` for compatibility)
  listed in `connection.zig:13` as `pub const ALPN`.
- Handshake is handled by the QUIC layer (RFC 9001); H3 `initConnection()`
  runs after the handshake completes.

## §3.3 Connection Reuse — ❌ Not implemented

Each H3Connection wraps exactly one QUIC connection. We do not maintain a
client-side pool of connections for origin reuse across requests. This is an
HTTP-client concern rather than an H3 protocol concern and is deferred.

## §4.1 HTTP Message Framing — ✅ Done

- Requests: `sendRequest(headers, body)` opens a bidi stream, encodes
  HEADERS via QPACK, optionally writes a DATA frame, then FINs.
- Responses: `sendResponse(stream_id, headers, body)` writes HEADERS +
  optional DATA + FIN on the request stream. Streamed form:
  `sendResponseHeaders` (repeatable, for 1xx), `sendResponseData` (one DATA
  frame per call; empty is a no-op), `finishResponse(stream_id, trailers)`.
  Header blocks of any size are encoded (heap buffer past 4 KiB).
- `notifyWritable(stream_id, n)` yields one `writable` event once `n` more
  bytes fit the peer's credit and fewer than `n` sit unsent.
- Incoming: `poll()` returns `headers` / `data` / `finished` /
  `request_cancelled` events. Body bytes are read via `recvBody(buf)`;
  `poll()` does not advance past a stream with a pending body.
- Incoming frames are never buffered whole. `poll()` pulls a request
  stream's QUIC data one chunk at a time, only when its buffer can make no
  further progress; a DATA frame is surfaced as `data` events piece by piece
  as it arrives (`len` is what is buffered now), and unknown or unsupported
  frames are discarded as they arrive. A HEADERS frame longer than
  `MAX_HEADERS_FRAME` (64 KiB) is `H3_EXCESSIVE_LOAD`; a stream that ends
  mid-frame is `H3_FRAME_ERROR`. Bytes H3 holds are marked
  `ReceiveStream.retained`, so MAX_STREAM_DATA and MAX_DATA credit only what
  the application has taken.

### §4.1.1 Request Cancellation — ✅ Done

- `cancelRequest(stream_id, error_code)`: emits `RESET_STREAM` +
  `STOP_SENDING` with the given H3 error code.
- `rejectRequest(stream_id)`: shortcut that uses `H3_REQUEST_REJECTED`.
- Peer-initiated cancellation is surfaced as a `request_cancelled` event
  (stream_id + peer error code) after any complete buffered frames are
  delivered (a partial one is dropped) —
  RESET_STREAM on the request, or (server) STOP_SENDING on the response,
  including after the request is complete. Reported once per stream.

## §4.2 HTTP Fields — ✅ Done (via QPACK)

See [RFC9204_QPACK.md](RFC9204_QPACK.md).

## §4.3 HTTP Control Data — ✅ Done

Pseudo-header validation lives in `validateRequestHeaders` and
`validateResponseHeaders` (connection.zig:799). Violations close the
connection with `H3_MESSAGE_ERROR`. Rules enforced:

- Pseudo-headers must appear before regular fields.
- Requests: exactly one `:method`. Non-CONNECT requests require
  `:scheme`, `:path` (non-empty), and — for http/https — `:authority` or
  `Host`.
- Plain CONNECT: only `:method` + `:authority` required.
- Extended CONNECT (RFC 9220, `:protocol` present): requires
  `:method=CONNECT`, `:protocol`, `:scheme`, `:path`, `:authority`.
- `:status` is rejected in requests.
- Responses: exactly one `:status`, no other pseudo-headers.
- Header names must be lowercase (rejects any ASCII `A`-`Z`).
- `te` header: only value `"trailers"` is permitted.
- Unknown pseudo-headers are rejected.

## §4.4 The CONNECT Method — ✅ Done

Plain CONNECT is accepted (authority-only request). Extended CONNECT
(RFC 9220) is used by the WebTransport layer — `connect_request` events
carry `protocol`, `authority`, `path`, and the full header list.
`sendConnectResponse()` / `sendConnectResponseWithHeaders()` write the
response headers but leave the stream open.

## §4.5 HTTP Upgrade — ❌ N/A

Not applicable to HTTP/3.

## §4.6 Server Push — ❌ N/A (deprecated)

Server Push is intentionally not implemented. Chrome removed client
support; most deployed stacks consider this feature dead. RFC 9218
extensible priorities replace its remaining use cases.

`CANCEL_PUSH` (0x03), `PUSH_PROMISE` (0x05), `MAX_PUSH_ID` (0x0d), and
push uni streams (type 0x01) are parseable but no send/dispatch logic
exists. Push uni streams are identified and silently ignored.

## §5.1 Idle Connections — ✅ Done

Driven by the QUIC idle timeout (see RFC 9000 §10.1).

## §5.2 Connection Shutdown — ✅ Done

Two-phase GOAWAY per the spec:

- `initiateShutdown()`: sends GOAWAY with the max client-bidi ID
  (servers) or max push ID (clients) — phase 1.
- `completeShutdown()`: sends GOAWAY with `highest_processed_stream_id + 4`
  (next client-initiated bidi after the last we processed) — phase 2.
- `sendGoaway(id)`: single-step alternative with validation (rejects
  increasing IDs or non-client-bidi IDs on the server).
- `isDrainComplete()`: returns true once all tracked request streams
  below the local GOAWAY ID have completed; `poll()` emits
  `shutdown_complete` when that happens.
- Incoming GOAWAY: rejected if its ID *increases* (`H3_ID_ERROR`) or if
  it arrives before SETTINGS (`H3_MISSING_SETTINGS`). Otherwise recorded
  as `peer_goaway_id`; `sendRequest()` returns `H3RequestRejected` when
  the next bidi ID would reach or exceed the peer's GOAWAY ID.
- Once the final GOAWAY is out (`going_away_final` or `drain_complete`),
  bidi streams ≥ our GOAWAY ID are reset with `H3_REQUEST_REJECTED` inside
  the bidi poll loop. A client learns of that reset through a
  `request_cancelled` event even when no response byte arrived; the
  client event loop hands it to an optional `onRequestCancelled`.

### Server-wide drain (`event_loop.Server.drain()`)

What a server does on SIGTERM. `drain()`:

1. Sets `ConnectionManager.refuse_new`, so every new connection is answered
   with CONNECTION_REFUSED in an Initial.
2. Sends phase-1 GOAWAY on every H3 connection and DRAIN_WEBTRANSPORT_SESSION
   on every active WebTransport session. Raw-QUIC and HTTP/0.9 connections,
   which have no graceful signal, are closed at once. A connection still
   handshaking gets GOAWAY(0) as soon as H3 is set up.
3. One PTO later per connection (`ConnEntry.drain_final_goaway_at`, on the
   server's timer), sends phase 2: `completeShutdown()`.
4. Closes each connection with H3_NO_ERROR once `isDrainComplete()` holds,
   no request stream has unacked data, and every rejection's RESET_STREAM
   has been queued — closing sooner would drop the tail of a response.

`isDrained()` is true once every connection is closing or closed; the caller
waits on it against its own deadline and then calls `stop()`, which is also
the fallback when the deadline passes first. WebTransport sessions keep their
connection open until the handler or the peer closes them.

## Request-body backpressure

`H3Connection.pauseBody(stream_id)` / `resumeBody`, surfaced as
`Session.pauseRequestBody` / `resumeRequestBody`. While paused, `poll()` skips
the stream's data and FIN (a peer reset is still reported), so its bytes stay
unread in QUIC and MAX_STREAM_DATA stops advancing: the client is held to one
stream window rather than the server buffering the body. Pausing mid-frame is
allowed: what `recvBody` has not returned stays buffered and is surfaced
first after the resume, and other streams are not blocked behind it. `resumeRequestBody` asks the event loop for
another pass (`ConnEntry.repoll`), since no packet may arrive to trigger one.

## §5.3 Immediate Closure — ✅ Done

`closeWithError(H3Error, reason)` sends `CONNECTION_CLOSE` with an
application error code. Error-code tests verify all 17 RFC 9114 §8.1
codes + QPACK §6 codes match the spec values (connection.zig:1451).

## §6.1 Bidirectional Streams — ✅ Done

Client-initiated bidi streams carry requests. Server poll loop iterates
`quic_conn.streams.streams` and attempts to parse H3 frames from each.

## §6.2 Unidirectional Streams — ✅ Done

Identified by their type varint prefix (`UniStreamType` in frame.zig:121):

| Type | Purpose |
|-----:|---------|
| 0x00 | Control |
| 0x01 | Push (unused, quietly ignored) |
| 0x02 | QPACK encoder |
| 0x03 | QPACK decoder |

Other/unknown uni stream types surface `error.UnknownStreamType` to the
caller (the WebTransport layer handles its own 0x54 prefix before H3
sees the stream).

### §6.2.1 Control Streams — ✅ Done

- Local control stream opened in `initConnection()` with type byte then
  an immediate SETTINGS frame.
- Peer control stream identified by `identifyPeerUniStreams()` on the
  first read; remaining bytes after the type byte are buffered for
  SETTINGS parsing.
- Critical stream closure (reset or FIN) on any of control / QPACK
  encoder / QPACK decoder triggers `H3_CLOSED_CRITICAL_STREAM` in
  `checkCriticalStreams()` (runs first in `poll()`).
- First frame on the peer control stream must be SETTINGS; anything
  else yields `H3_MISSING_SETTINGS`. Duplicate SETTINGS yields
  `H3_FRAME_UNEXPECTED`.
- Control-stream frames are bounded: SETTINGS and PRIORITY_UPDATE past
  `MAX_CONTROL_FRAME` (16 KiB) are `H3_EXCESSIVE_LOAD`, GOAWAY /
  CANCEL_PUSH / MAX_PUSH_ID longer than one varint are `H3_FRAME_ERROR`, and
  unknown frames are discarded as they arrive.

### §6.2.2 Push Streams — ❌ N/A

Deferred with Server Push.

## §7.1 Frame Layout — ✅ Done

`h3/frame.zig:parse()` reads `varint type | varint length | payload`.
Short buffers return `error.BufferTooShort`. The connection reads the
header alone first (`parseHeader`) and decides from the type and declared
length whether to stream, cap or skip the payload, so only bounded frames
are ever accumulated whole.

## §7.2 Frame Definitions

| Frame | Type | Status |
|-------|-----:|--------|
| DATA | 0x00 | ✅ parse + serialize |
| HEADERS | 0x01 | ✅ parse + serialize |
| CANCEL_PUSH | 0x03 | ❌ N/A (push deprecated; parsed defensively) |
| SETTINGS | 0x04 | ✅ parse + serialize |
| PUSH_PROMISE | 0x05 | ❌ N/A |
| GOAWAY | 0x07 | ✅ parse + serialize |
| MAX_PUSH_ID | 0x0d | ❌ N/A (parsed defensively) |
| PRIORITY_UPDATE (request) | 0xF0700 | ✅ RFC 9218 |
| CLOSE_WEBTRANSPORT_SESSION | 0x2843 | ✅ WT draft |
| DRAIN_WEBTRANSPORT_SESSION | 0x78ae | ✅ WT draft |
| GREASE / unknown | — | ✅ returned as `.unknown`, skipped |

`PRIORITY_UPDATE for Push Streams` (0xF0701) is not implemented because
Server Push is not implemented.

### §7.2.4 SETTINGS — ✅ Done

- Must be the first frame on each control stream; enforced by
  `peer_settings_received` gate.
- Duplicate SETTINGS → `H3_FRAME_UNEXPECTED`.
- Reserved HTTP/2 settings IDs (0x00, 0x02, 0x03, 0x04, 0x05) →
  `H3_SETTINGS_ERROR` (frame.zig:49).
- Supported identifiers:
  - `QPACK_MAX_TABLE_CAPACITY` (0x01) — advertised 4096 by default.
    The peer's value is unused: our QPACK encoder is static-only.
  - `MAX_FIELD_SECTION_SIZE` (0x06) — optional.
  - `QPACK_BLOCKED_STREAMS` (0x07) — advertised as 0 (no blocked
    streams supported; see caveats).
  - `SETTINGS_ENABLE_CONNECT_PROTOCOL` (0x08, RFC 9220).
  - `SETTINGS_H3_DATAGRAM` (0x33, RFC 9297).
  - `SETTINGS_ENABLE_WEBTRANSPORT` (0x2b603742, draft-06) and
    `SETTINGS_WT_ENABLED` (0x2c7cf000, current WT draft). Both are
    sent for compatibility.
  - `SETTINGS_WT_MAX_SESSIONS` (0xc671706a).
  - Unknown settings are silently ignored.
- Malformed SETTINGS payload (incomplete varint) → `H3_FRAME_ERROR`.

### §7.2.8 Reserved Frame Types — ✅ Done

HTTP/2 frame types `0x02, 0x06, 0x08, 0x09` on any H3 stream trigger
`H3_FRAME_UNEXPECTED`. Unknown types (GREASE `0x1f*N+0x21`, etc.) are
returned from `parse()` as a distinct `.unknown` variant that higher
layers ignore while still advancing the buffer cursor — verified by the
GREASE test in frame.zig. On request and control streams they are skipped
incrementally from the header, whatever length they declare.

## §8 Error Handling — ✅ Done

All RFC 9114 §8.1 error codes defined in `H3Error` (connection.zig:16)
with the RFC-specified numeric values. Codes are emitted at the right
points:

| Error | Trigger |
|-------|---------|
| `H3_CLOSED_CRITICAL_STREAM` | Peer closes/resets control or QPACK stream |
| `H3_FRAME_UNEXPECTED` | Wrong frame on wrong stream (DATA/HEADERS on control; SETTINGS/GOAWAY/PRIORITY_UPDATE on bidi; HTTP/2 frame type; DATA before HEADERS; duplicate SETTINGS) |
| `H3_FRAME_ERROR` | Malformed SETTINGS/GOAWAY/generic varint |
| `H3_SETTINGS_ERROR` | Reserved HTTP/2 settings ID |
| `H3_MISSING_SETTINGS` | First frame on control stream is not SETTINGS |
| `H3_ID_ERROR` | GOAWAY ID increases, or server sends non-bidi GOAWAY ID |
| `H3_MESSAGE_ERROR` | Malformed pseudo-headers |
| `H3_REQUEST_REJECTED` | Stream above local GOAWAY during shutdown |
| `QPACK_DECOMPRESSION_FAILED` | QPACK decoder error on request stream |
| `QPACK_ENCODER_STREAM_ERROR` | Peer violates encoder stream rules |
| `QPACK_DECODER_STREAM_ERROR` | Peer sends Insert Count Increment of 0 |

## §9 Extensions — ✅ Done

- **DATAGRAM (RFC 9297)** — capsule protocol codec in `h3/capsule.zig`;
  see [RFC9297_S4.md](RFC9297_S4.md).
- **WebTransport** — CONNECT + session management in `src/webtransport/`.
  CLOSE/DRAIN frames and session capsules handled at H3 + WT layers.
- **RFC 9218 Priority** — full integration:
  - `priority.zig` parses/serializes field values (`u=N, i`).
  - Incoming `priority` HTTP header on a request updates
    `stream.send.urgency` / `incremental`.
  - `PRIORITY_UPDATE` frame on the control stream applies to the
    target stream.
  - `sendPriorityUpdate(stream_id, prio)` emits the frame from a
    client and updates local scheduling state.

## §10 Security Considerations — ✅ N/A

Informational.

## Caveats / Known limitations

- **Connection reuse (§3.3)**: not implemented — one origin, one
  QUIC connection. Deferred; not a wire-protocol gap.
- **Server Push (§4.6, §6.2.2, §7.2.3, §7.2.5, §7.2.7)**: intentionally
  deprecated. `MAX_PUSH_ID` is parsed defensively but never acted upon.
- **`qpack_blocked_streams`** is advertised as 0. The decoder handles
  dynamic-table references eagerly when referenced entries are already
  present; header blocks that reference not-yet-inserted entries would
  need blocked-stream bookkeeping which is not implemented. This is
  only visible if a peer actually emits out-of-order header blocks.
- **Decoded header count per frame capped at `MAX_HEADERS = 128`**,
  and decoded names + values at `qpack.SCRATCH_SIZE` (16 KiB). Over-large
  header lists close the connection with QPACK_DECOMPRESSION_FAILED.
- **Request trailers** arrive as a second `headers` event on the stream;
  the event loop hands them to `onRequest` again.
- **`huffman_scratch`**: qpack.zig uses a 16 KiB file-scope scratch
  buffer for decoded field values. Not safe across concurrent decoder
  instances on the same thread.
- **QPACK Huffman encoding**: decoder supports Huffman; encoder always
  emits plain (H=0) strings. Interop works because Huffman is optional
  on the wire.
