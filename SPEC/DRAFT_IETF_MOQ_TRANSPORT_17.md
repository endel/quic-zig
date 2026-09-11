# Media-over-QUIC Transport — draft-ietf-moq-transport-17

Status: **working end-to-end**. Wire layer complete. Raw-QUIC + WebTransport relays operational. Live browser video demo verified with multiple simultaneous subscribers.

Reference: `draft-ietf-moq-transport-17` (expires 2026-09). Cross-checked against `moq-rs` (kixelated/moq-rs) `main`, which implements draft-14/15/16/17 concurrently.

## Apps shipped

| Binary | Purpose |
| --- | --- |
| `moq-server` | Raw-QUIC MoQ publisher (synthetic clock track) |
| `moq-client` | Raw-QUIC MoQ subscriber + `--mode publish` |
| `moq-relay` | Raw-QUIC MoQ relay with pub/sub fanout and synthetic origin |
| `moq-browser-server` | WebTransport MoQ relay for browsers, shared TLS cert with HTTP/1.1 static file server |
| `moq-test-client` | moq-interop-runner test client; TAP 14 output. See [moq-interop.md](moq-interop.md) |

Browser pages (served by `moq-browser-server`):
- `interop/browser/moq.html` — clock-tick subscribe demo
- `interop/browser/moq_video.html` — live webcam capture → VP8 encode → MoQ publish → relay fanout → MoQ subscribe → VP8 decode → canvas render

## Wire facts pinned for implementation

## Wire facts pinned for implementation

### Identifiers

| Item | Value | Source |
| --- | --- | --- |
| ALPN (raw QUIC) | `"moqt-17"` (7 ASCII bytes) | §3.1 |
| ALPN (final RFC) | `"moqt"` — NOT used during draft | §3.1 |
| Version code (internal) | `0xff00_0011` | moq-rs `ietf/version.rs:71` |
| Wire version negotiation | ALPN-only — **no `SUPPORTED_VERSIONS` param** in SETUP | §9.4, changelog |
| WT path | configurable (implementation default `/moq`) | §3.2 |

### MoQ varint (§1.4.1) — NOT the QUIC varint

MoQ uses a distinct "leading-ones" varint encoding. **Cannot reuse `quic/packet.zig` varint helpers.** The first byte's number of leading 1-bits determines total length: 1, 2, 3, 4, 5, 6, 8, or 9 bytes. A dedicated `src/moq/wire.zig` implements this.

### Control streams (§3.3)

- **Pair of unidirectional streams**, one opened by each peer. (Breaking change from pre-v17 bidi.)
- First message on each uni control stream is `SETUP` (type `0x2F00`), whose type varint doubles as the stream identifier.
- Both peers call `open_uni()` unconditionally after connect/accept.

### Request streams (§3.3)

Peer-initiated **bidirectional** streams carry a single request + response. First frame's message type identifies the request:
`TRACK_STATUS | SUBSCRIBE | PUBLISH | FETCH | PUBLISH_NAMESPACE | SUBSCRIBE_NAMESPACE`.
The `REQUEST_OK` / `REQUEST_ERROR` response travels back on the same bidi stream — **they carry no `request_id` field** on the wire; the stream itself is the identifier.

### Control-message framing (§9)

```
Type (moq-varint) | Length (u16, big-endian) | Payload (Length bytes)
```

Length is a **fixed 16-bit unsigned**, not a varint. Same framing applies to SETUP.

### Control message type codes (draft-17 §9 Table 4)

| Name | Code | Section |
| --- | --- | --- |
| SETUP | `0x2F00` | 9.4 |
| GOAWAY | `0x10` | 9.5 |
| REQUEST_OK | `0x07` | 9.6 |
| REQUEST_ERROR | `0x05` | 9.7 |
| SUBSCRIBE | `0x03` | 9.8 |
| SUBSCRIBE_OK | `0x04` | 9.9 |
| REQUEST_UPDATE | `0x02` | 9.10 |
| PUBLISH | `0x1D` | 9.11 |
| PUBLISH_OK | `0x1E` | 9.12 |
| PUBLISH_DONE | `0x0B` | 9.13 |
| FETCH | `0x16` | 9.14 |
| FETCH_OK | `0x18` | 9.15 |
| TRACK_STATUS | `0x0D` | 9.16 |
| PUBLISH_NAMESPACE | `0x06` | 9.17 |
| NAMESPACE | `0x08` | 9.18 |
| NAMESPACE_DONE | `0x0E` | 9.19 |
| SUBSCRIBE_NAMESPACE | `0x11` | 9.20 |
| PUBLISH_BLOCKED | `0x0F` | 9.21 |

**Reserved / legacy codes (MUST NOT emit; receipt → terminate):** `0x01`, `0x20`, `0x21`, `0x40`, `0x41` (legacy SETUP variants for draft ≤16 / ≤10).

**Removed messages (folded into REQUEST_OK/ERROR or signaled via stream close):** SUBSCRIBE_ERROR, SUBSCRIBE_DONE, FETCH_ERROR, FETCH_CANCEL, PUBLISH_ERROR, UNSUBSCRIBE, MAX_REQUEST_ID, REQUESTS_BLOCKED, TRACK_STATUS_REQUEST, and all the PUBLISH_NAMESPACE_*/SUBSCRIBE_NAMESPACE_* variants.

### SETUP Options (§9.4.1)

No count prefix; options fill the `u16 Length`. Delta-encoded key-value pairs (§1.4.3): even key → value is a single varint; odd key → value is varint-length-prefixed bytes. Keys MUST appear in ascending order.

| Option | Code | Shape |
| --- | --- | --- |
| PATH | `0x01` | length-prefixed bytes |
| AUTHORIZATION_TOKEN | `0x03` | length-prefixed token struct |
| MAX_AUTH_TOKEN_CACHE_SIZE | `0x04` | varint |
| AUTHORITY | `0x05` | length-prefixed bytes (URI authority) |
| MOQT_IMPLEMENTATION | `0x07` | length-prefixed UTF-8 |

`MAX_REQUEST_ID` (was `0x02` in v14–16) **removed** in v17.

### Data streams

#### Subgroup streams (§10.4.2)

Valid stream-type varints: `0x10..0x15`, `0x18..0x1D`, `0x30..0x35`, `0x38..0x3D`. Bit-4 always 1 (selector). Bits:

| Mask | Bit | Name | Meaning |
| --- | --- | --- | --- |
| `0x01` | 0 | PROPERTIES | Per-object Properties field present |
| `0x06` | 1-2 | SUBGROUP_ID_MODE | `00`=id is 0 (absent); `01`=absent, equals first object id; `10`=explicit in header; `11`=reserved (PROTOCOL_VIOLATION) |
| `0x08` | 3 | END_OF_GROUP | FIN signals largest object id in group |
| `0x10` | 4 | (selector) | Always 1 |
| `0x20` | 5 | DEFAULT_PRIORITY | Publisher Priority absent; inherit from control |

Header layout:

```
Type (moq-varint)
Track Alias (moq-varint)
Group ID (moq-varint)
[Subgroup ID (moq-varint)]      // only if SUBGROUP_ID_MODE == 0b10
[Publisher Priority (u8)]       // only if DEFAULT_PRIORITY == 0
```

No `final_object_id` field — end of group inferred from `END_OF_GROUP` bit + FIN.

Invalid subgroup stream-type codes (PROTOCOL_VIOLATION): `0x16, 0x17, 0x1E, 0x1F, 0x36, 0x37, 0x3E, 0x3F`.

#### Fetch stream (§10.4.4)

```
Type (moq-varint) = 0x05
Request ID (moq-varint)
```

Followed by per-object records with their own `Serialization Flags (varint)` + optional fields.

#### Datagram objects (§10.3.1)

Valid type range: `0x00..0x0F`, `0x20..0x2F`. Bit 4 is always 0 (datagram selector).

| Mask | Name |
| --- | --- |
| `0x01` | PROPERTIES |
| `0x02` | END_OF_GROUP |
| `0x04` | ZERO_OBJECT_ID (Object ID field absent) |
| `0x08` | DEFAULT_PRIORITY |
| `0x20` | STATUS (object-status present, no payload) |

Layout:

```
Type (moq-varint)
Track Alias (moq-varint)
Group ID (moq-varint)
[Object ID (moq-varint)]       // absent if ZERO_OBJECT_ID
[Publisher Priority (u8)]      // absent if DEFAULT_PRIORITY
[Properties (..)]              // if PROPERTIES
[Object Status (moq-varint)]   // if STATUS (no payload)
[Object Payload (..)]          // if !STATUS (remainder of datagram)
```

Invalid datagram types: `0x22, 0x23, 0x26, 0x27, 0x2A, 0x2B, 0x2E, 0x2F` (STATUS + END_OF_GROUP together).

### Required QUIC features

- RFC 9221 DATAGRAM extension MUST be negotiated. Already supported by this stack.

### moq-rs interop reality

- `main` implements draft-14/15/16/17 simultaneously, keyed by ALPN.
- Supports both raw QUIC and WebTransport.
- Shares struct names across drafts; IDs `0x05`/`0x07`/`0x08` are overloaded per draft — for draft-17 we treat them as REQUEST_ERROR / REQUEST_OK / NAMESPACE respectively.

## Implementation state

| Component | State |
| --- | --- |
| Wire primitives (`src/moq/wire.zig`, `message_codes.zig`) | done; leading-ones varint, KV list, tuples |
| Control messages (`src/moq/message.zig`) | all 18 types encode **and** decode, matched to the §9 figures |
| Message parameters (§9.3) | one codec with the type→shape table; unknown types are a protocol violation, as the draft requires |
| Object framing (`src/moq/object.zig`) | subgroup headers (all id-modes and priority variants), datagram objects, fetch stream headers |
| Session (`src/moq/session.zig`) | SETUP + request-stream state machine, generic over the transport; reassembles split messages and drains coalesced ones |
| Publisher / Subscriber | `moq-client` subscribes or `--mode publish`; `moq-server` publishes |
| Relay (`moq-relay`) | pub/sub fanout with alias remapping, namespace registry, rendezvous timeouts, PUBLISH_DONE on publisher loss |
| Browser (WebTransport) | `moq-browser-server` + `interop/browser/moq.html`, with WT application-protocol negotiation |
| Interop test client | `moq-test-client`, 7 cases, TAP 14, containerised |
| Datagram objects | done — `moq-client --mode publish --datagrams`, relayed with alias remapping |
| FETCH | codec done; no runtime request/response flow |
| AUTHORIZATION_TOKEN | decoded at the KV level and discarded; no policy engine |
| draft-18 | not implemented; see below |

## Verified interop

`tools/moq_interop.sh` regenerates [moq-interop-results.md](moq-interop-results.md).

The one case moq-relay does not pass is `rendezvous-timeout`: it answers
`REQUEST_ERROR` with code `404`, which is not a code in the draft-17 §9.7
table at all. Older builds held the subscription open and never answered.

| Scenario | Result |
| --- | --- |
| `moq-test-client` → our relay (raw QUIC) | 7/7 |
| `moq-test-client` → moq-relay v0.14.16 (raw QUIC) | 6/7 |
| `moq-test-client` → moq-relay v0.14.16 (WebTransport) | 6/7 |
| `moq-test-client` → `cdn.moq.dev` | blocked at TLS: no HelloRetryRequest |
| Zig pub → Zig relay → Zig sub (raw QUIC) | ✅ |
| Datagram objects, pub → relay → sub (raw QUIC) | ✅ |
| Browser ↔ Zig WT relay (clock, live video) | ✅ |

## What draft-18 would take

The runner's `current_target` is draft-18, and draft-17 pairs with only
four of its eighteen registered relays. The delta is bounded but real —
it touches every request message, so it is wire work rather than an ALPN
bump:

- **`Required Request ID Delta` is removed from every request message**
  (#1615): SUBSCRIBE, REQUEST_UPDATE, PUBLISH, FETCH, PUBLISH_NAMESPACE,
  SUBSCRIBE_NAMESPACE.
- `SUBSCRIBE_NAMESPACE` moves **0x11 → 0x50** and loses `Subscribe
  Options`; the new **`SUBSCRIBE_TRACKS` (0x51)** takes over yielding
  PUBLISH while 0x50 yields only NAMESPACE/NAMESPACE_DONE.
- **`PUBLISH_OK` (0x1E) is no longer sent** — respond to PUBLISH with
  `REQUEST_OK` (0x07). Table 5 still lists a 0x1E row pointing at §10.5;
  that is a spec bug, PR #1611 is explicit that the code point changed.
- `REQUEST_OK` gains trailing Track Properties; `REQUEST_ERROR` gains an
  optional `Redirect` and the `REDIRECT` / `UNSUPPORTED_EXTENSION` codes.
- **`PUBLISH_DONE` status codes swap**: `TOO_FAR_BEHIND` 0x6 → 0x5,
  `EXPIRED` 0x5 → 0x6.
- The varint **stays leading-ones**, but the **7-byte form becomes valid**
  and non-minimal encodings are explicitly allowed — `wire.zig` currently
  returns `Error.InvalidVarInt` for exactly those, so a draft-17 decoder
  rejects valid draft-18 input.
- `SUBGROUP_HEADER` gains a **FIRST_OBJECT bit (0x40)**; the type pattern
  widens to `0b0XX1XXXX`. Datagram headers are unchanged.
- FETCH per-object fields become delta-encoded Group/Object IDs.
- Message parameter `0x02 DELIVERY_TIMEOUT` → `OBJECT_DELIVERY_TIMEOUT`;
  new `0x06 SUBGROUP_DELIVERY_TIMEOUT`, `0x0A FILL_TIMEOUT`,
  `0x34 TRACK_NAMESPACE_PREFIX`.
- Unified `moqt://` URI for both transports (`src/moq/url.zig` already
  takes it), GOAWAY on request streams, generalized reset codes (§3.3.3),
  mandatory-to-understand track properties.
- Sections renumber: control messages §9 → §10, data streams §10 → §11.

draft-19 and draft-20 also exist, and -19 reverted some of the above
(Request ID removed from GOAWAY again, `PUBLISH_BLOCKED` renamed
`PUBLISH_SKIPPED`). `src/moq/version.zig` is a table so a second draft can
be added beside draft-17 rather than replacing it.

## Video demo architecture

The browser-to-browser live video demo (`moq_video.html` + `moq-browser-server`) uses:

- **Capture**: `getUserMedia({ video: 640x360@30fps })` + `MediaStreamTrackProcessor`
- **Encode**: WebCodecs `VideoEncoder` with VP8 @ 1 Mbps, `latencyMode: 'realtime'`, keyframe every 30 frames (≈1 s)
- **MoQ framing**: one subgroup stream per group (keyframe cycle). Publisher writes subgroup header once per stream, then appends `object_id (varint) + payload_len (varint) + [keyframe_flag (1b) + timestamp (varint μs) + VP8 bytes]` per frame. Each new keyframe → close prior stream, open new one. Result: ~1 stream/sec per subscriber instead of 30/sec.
- **Relay fanout**: parses the subgroup header once on the publisher's stream, opens a matching output stream on each subscriber's WT session with `track_alias` remapped, then forwards raw publisher bytes chunk-by-chunk (incremental, no buffering for FIN)
- **Decode**: subscriber parses objects incrementally as bytes arrive (no wait-for-FIN), feeds `EncodedVideoChunk` into `VideoDecoder`, draws `VideoFrame` on canvas

The one-stream-per-group design is what allowed scaling past ~1000 frames per subscriber without hitting the QUIC peer's uni stream limit (`MAX_STREAMS_UNI`).

## Caveats and deferred work

- No AUTHORIZATION_TOKEN policy engine — wire-level decode only.
- VP8 video is in the demo app only; MoQ core treats object payloads as opaque bytes (as the spec intends: the media codec is not part of MoQ).
- moq-lite is implemented separately — see [DRAFT_LCURLEY_MOQ_LITE_05.md](DRAFT_LCURLEY_MOQ_LITE_05.md). It is a different wire format, not a profile of this one.
- FETCH request/response flow is codec-only. Namespace discovery is wired up in the raw-QUIC relay.
- The earlier note that moq-rs interop was blocked by their auth config is stale: `demo/relay/localhost.toml` sets `auth.public = ""`, and with it the interop client reaches 5/7 against them.
