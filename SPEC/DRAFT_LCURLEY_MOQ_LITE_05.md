# moq-lite — draft-lcurley-moq-lite-05

Spec: <https://www.ietf.org/archive/id/draft-lcurley-moq-lite-05.txt>
(30 June 2026, Informational). Reference implementations: `rs/moq-net`
and `js/net` in <https://github.com/moq-dev/moq>.

moq-lite is **not** a profile of IETF moq-transport — it is a separate wire
format that happens to solve the same problem. Most importantly it uses the
**QUIC varint**, where draft-17 uses a leading-ones varint, so the two
codecs cannot share primitives. `src/moq/lite/` and `src/moq/` are separate
namespaces for that reason.

It is what the deployed ecosystem speaks: `moq-relay`, `cdn.moq.dev`, the
`@moq/net` browser client, and the GStreamer/OBS bindings.

## Apps shipped

| Binary | Purpose |
| --- | --- |
| `moq-lite` | `publish` / `subscribe` / `announce` over either transport |

## Wire facts pinned for implementation

### Versions and ALPN (§3.1)

From lite-03 on, the version *is* the ALPN string; there is no version code
on the wire and no negotiation inside SETUP.

| Version | ALPN | Legacy code |
| --- | --- | --- |
| lite-05 | `moq-lite-05` | `0xff0dad05` |
| lite-04 | `moq-lite-04` | `0xff0dad04` |
| lite-03 | `moq-lite-03` | `0xff0dad03` |

`moql` is the ALPN lite-01 and lite-02 shared, negotiating the version in
SETUP with draft-14 framing. We do not implement those; the codes above are
only reachable through it.

Over WebTransport the QUIC ALPN stays `h3` and the same token travels in
the `WT-Available-Protocols` / `WT-Protocol` CONNECT headers — the browser
API spells this `new WebTransport(url, { protocols: [...] })`.

### Primitives (§4)

| Notation | Encoding |
| --- | --- |
| `(i)` | QUIC varint (RFC 9000 §16) — **not** the draft-17 varint |
| `(8)` | one raw byte; priority, ordered and announce status are all this |
| `(s)` | varint length + UTF-8 bytes |
| `(b)` | varint length + bytes |
| zigzag `(i)` | `(n << 1) ^ (n >> 63)`, decode `(u >> 1) ^ -(u & 1)` |
| optional group | `0` = default, otherwise absolute sequence + 1 |

Every control message is `varint Message Length || body`, and the decoder
must consume exactly Length. `MAX_MESSAGE_SIZE` is 64 MiB.

A broadcast path is `/`-separated; leading and trailing slashes are
trimmed, runs collapse, and there are at most 32 parts. Prefix matching is
path-aware: `foo` does not prefix `foobar`.

### Streams

There is **no global message-type table**. A message is identified by its
stream's type plus its position in the stream.

Bidirectional (§5.1) — subscriber-created except Goaway:

| ID | Stream |
| --- | --- |
| `0x1` | Announce |
| `0x2` | Subscribe |
| `0x3` | Fetch |
| `0x4` | Probe |
| `0x5` | Goaway |
| `0x6` | Track |

Unidirectional (§6.3):

| ID | Stream | Creator |
| --- | --- | --- |
| `0x0` | Group | Publisher |
| `0x1` | Setup | Either |

### Session setup (§6.3.1)

No blocking handshake. Each endpoint opens a Setup Stream, writes one SETUP
message, and FINs it — then starts opening control streams without waiting
for the peer's.

```
SETUP { Message Length (i), Parameter Count (i), (Type (i), Value (b)) ... }
```

| Type | Name | Value |
| --- | --- | --- |
| `0x1` | PROBE | varint level: 0 none, 1 report, 2 increase |
| `0x2` | PATH | UTF-8 path; client-only, and MUST NOT be sent over WebTransport |

Unknown parameters MUST be ignored — they are length-prefixed, so unlike a
moq-transport message parameter they can be skipped.

### Messages

```
ANNOUNCE_REQUEST   { prefix (s), exclude_hop (i) }
ANNOUNCE_OK        { hop_id (i), active_count (i) }
ANNOUNCE_BROADCAST { status (i) 0=ended 1=active, suffix (s), hop_count (i), hop_id (i)... }

SUBSCRIBE          { id (i), broadcast (s), track (s), priority (8),
                     ordered (8), max_latency (i), group_start (i), group_end (i) }
SUBSCRIBE_UPDATE   { priority (8), ordered (8), max_latency (i),
                     group_start (i), group_end (i) }

TRACK              { broadcast (s), track (s) }
TRACK_INFO         { priority (8), ordered (8), max_latency (i), timescale (i) }

SUBSCRIBE_OK       { Type (i) = 0x0, Length (i), group (i) }
SUBSCRIBE_END      { Type (i) = 0x1, Length (i), group (i) }
SUBSCRIBE_DROP     { Type (i) = 0x2, Length (i), group_start (i), group_end (i), error (i) }

FETCH              { broadcast (s), track (s), priority (8), group (i) }
PROBE              { bitrate (i), rtt (i) }
GOAWAY             { uri (s) }

GROUP              { subscribe_id (i), sequence (i) }
FRAME              { timestamp_delta (zigzag i), Length (i), payload (b) }
DATAGRAM body      { subscribe_id (i), sequence (i), timestamp (i), payload }
```

Notes that cost time if missed:

- **`FRAME`'s timestamp delta is outside the length prefix.** It is not a
  framed message and does not go through the same reader.
- **`SUBSCRIBE_END`'s group is exclusive** — no group at or after it will be
  produced. The -05 text says inclusive; the reference implementation and
  the -06 changelog say that was a mistake. Follow the code.
- **Response type IDs shifted in lite-05**: DROP moved `0x1` → `0x2`, and
  `0x1` is now END.
- `timescale` MUST be non-zero. Typical values: 1000, 48000, 90000, 1000000.
- Subscription rejection is a **stream reset**, not a message; there is no
  SUBSCRIBE_ERROR. An unknown stream type resets that stream and never the
  session.
- A datagram has no length prefix — the datagram boundary delimits it.

**Golden vector.** A default `TRACK_INFO` on lite-05 encodes to
`06 00 00 53 88 43 e8` (len 6, priority 0, ordered 0, max_latency 5000 ms,
timescale 1000). `rs/moq-net` asserts the same bytes; our encoder is tested
against it.

## Differences from IETF moq-transport (Appendix B)

Streams instead of request IDs; pull only, with no unsolicited publishing;
HTTP-shaped FETCH; a non-blocking SETUP on its own unidirectional stream;
UTF-8 names instead of byte-array tuples; subscriptions default to the
latest *group*, not the latest object; no subgroups; no ID gaps; no object
properties; no paused subscriptions.

Gone entirely: `MAX_SUBSCRIBE_ID`, `REQUESTS_BLOCKED`, `SUBSCRIBE_ERROR`,
`UNSUBSCRIBE`, `PUBLISH*`, `FETCH_OK`/`_ERROR`/`_CANCEL`, `FETCH_HEADER`,
`TRACK_STATUS*`, `PUBLISH_NAMESPACE*`, `OBJECT_DATAGRAM`. Renamed:
`SUBSCRIBE_NAMESPACE` → `ANNOUNCE_REQUEST`, `SUBGROUP_HEADER` → `GROUP`.

## Implementation state

| Component | State |
| --- | --- |
| Wire primitives (`src/moq/lite/wire.zig`) | done — QUIC varint, zigzag, paths, optional groups |
| Messages (`src/moq/lite/message.zig`) | done — every message above, pinned to the golden vector |
| Versions (`src/moq/lite/version.zig`) | done — lite-03/04/05 ALPN offer |
| Session (`src/moq/lite/session.zig`) | done — stream dispatch, setup, announce/subscribe/track/probe/goaway, group framing |
| `moq-lite` client | `publish`, `subscribe`, `announce` over QUIC and WebTransport |
| Relay | not started — `apps/moq_relay.zig` is the IETF draft, not this |
| Datagram delivery | codec done; no runtime path |
| Fetch | codec and stream dispatch done; no runtime path |
| lite-03 / lite-04 compatibility | not implemented — the ALPN is offered, the differences are not handled |

## Verified interop

| Scenario | Result |
| --- | --- |
| WT protocol negotiation vs `moq-relay` | ✅ `moq-lite-05` selected |
| SETUP exchange vs `moq-relay` | ✅ both directions |
| ANNOUNCE_REQUEST → ANNOUNCE_OK vs `moq-relay` | ✅ real hop id returned |
| Our announcement echoed back through the relay | ✅ |

## Caveats

- Only lite-05 is implemented, and the ALPN offer says so. lite-04 differs
  in at least: no Setup Stream, no Track Stream, no ANNOUNCE_OK, and a
  different SUBSCRIBE_OK body. `version.ALL` names the older ones for
  peers that log them.
- Group payloads are surfaced as raw bytes rather than parsed frames, so a
  relay can forward them untouched. `FrameReader` parses them for a
  subscriber; its buffer bounds the largest frame it can reassemble.
- `Publisher Max Latency` and the expiration rules in §6.2 are decoded but
  not acted on.
