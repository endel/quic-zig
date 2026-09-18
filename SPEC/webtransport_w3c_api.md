# The W3C WebTransport API, measured against our Zig client

[WebTransport](https://www.w3.org/TR/webtransport/) became Baseline in March 2026
when Safari 26.4 shipped it. That gives us a settled API to hold the Zig client
to, and three real browsers that can act as a second, independent client of the
same Zig server — which is what `SPEC/webtransport_conformance.md` does.

This document is the gap analysis: what browsers actually expose, what our
client has, and which of the differences are worth closing.

Browser support is from [MDN's compat data][bcd], checked September 2026.

[bcd]: https://github.com/mdn/browser-compat-data/blob/main/api/WebTransport.json

## What every browser exposes

Chrome 143+, Firefox 155+ and Safari 26.4+ all have these, so a client that
wants parity needs them.

| W3C member | quic-zig equivalent |
|---|---|
| `new WebTransport(url, options)`, `ready` | `event_loop.Client(Handler)` + `onSessionReady` |
| `closed`, `close(WebTransportCloseInfo)` | `onSessionClosed`, `closeSessionWithError(id, code, reason)` |
| `createBidirectionalStream()` | `ClientSession.openBidiStream(session_id, send_order)` |
| `createUnidirectionalStream()` | `ClientSession.openUniStream(session_id, send_order)` |
| `incomingBidirectionalStreams` | `onBidiStream` |
| `incomingUnidirectionalStreams` | `onUniStream` |
| `datagrams.readable` | `onDatagram` |
| `datagrams.maxDatagramSize` | `maxDatagramPayloadSize(session_id)` |
| `datagrams.incomingMaxAge` / `outgoingMaxAge` | `setIncomingDatagramMaxAge` / `setOutgoingDatagramMaxAge` |
| `WebTransportSendStream.abort(code)` → RESET_STREAM | `resetStream(stream_id, code)` |
| `readable.cancel()` → STOP_SENDING | `stopSending(stream_id, code)` |
| `ReadableStream` backpressure (not reading) | `pauseStream(stream_id)` / `resumeStream(stream_id)` |
| `options.protocols` / `protocol` | `WT-Available-Protocols` / `WT-Protocol` (`src/webtransport/protocol.zig`) |
| **`WebTransportError.streamErrorCode` on an inbound abort** | **added — see below** |
| **`options.serverCertificateHashes`** | **added — see below** |
| **`WritableStream` backpressure: `writer.desiredSize`, `writer.ready`** | **added — see below** |

Three of those were missing and are now implemented.

### Writers could not tell they were ahead of the peer

A browser's `writer.write()` never refuses: it queues, `desiredSize` goes
negative, and `ready` stays pending until there is room. `sendStreamData`
queued the same way but offered neither of the other two, so a Zig server
writing to a peer that stopped granting MAX_DATA grew its send buffers without
limit. Safari is that peer (WebKit bug 319818).

`streamSendCapacity(stream_id)` is `desiredSize`, measured against the peer's
credit rather than a local high-water mark. `notifyWritable(session_id,
stream_id, n)` with the `onWritable` callback is `ready`. Both also work per
session, with no stream: a browser has no use for that, but a server that opens
a stream per message — a MoQ relay, the firehose handler — has no stream to wait
on until it opens one. The mechanics are in
[RFC9000_3.md](RFC9000_3.md#send-credit-and-backpressure).

### Inbound resets were invisible

`ReceiveStream.handleResetStream` recorded the code at `src/quic/stream.zig:303`,
but `read()` then returned null and `finished` never flipped — so
`pollWtStreamData` emitted nothing at all. An application never learned the
stream had died, let alone with what code. `h3ToAppErrorCode`
(`src/webtransport/session.zig:33`) had been unit-tested since it was written
and had zero production callers.

`WtEvent` now carries `stream_reset` and `stream_stop_sending`, surfaced as the
`onStreamReset` / `onStopSending` handler callbacks on both `Server` and
`Client`. Inbound STOP_SENDING needed a new `SendStream.peer_stop_sending`
field: the QUIC layer funnelled it into `reset_err`, which is also where our own
`resetStream` writes, so the two were indistinguishable.

### `serverCertificateHashes` had no analogue

`ClientConfig.ca` offered `.none`, `.system` and `.file`, none of which reach a
self-signed 13-day certificate the way a browser does. It now has
`.pinned_hashes: []const [32]u8`, backed by `TlsConfig.cert_hashes`
(`src/quic/tls13.zig`): the SHA-256 of the leaf stands in for the chain, the
hostname and the dates, exactly the bargain the browsers strike.
CertificateVerify still runs — without it a pin would prove only that someone
had copied a public certificate.

This is what lets `wpt-client` pin the same certificate file the browsers pin,
rather than reaching the test server by a separate trust path.

## Supported by two engines

Firefox and Safari have these; Chrome does not.

| W3C member | quic-zig | verdict |
|---|---|---|
| `draining` | `onSessionDraining`; server-side `Session.drainSession` **added** | done |
| `sendOrder` | `openBidiStream(…, send_order)`, `setSendOrder` | already had it |
| `createSendGroup()` / `sendGroup` | — | **skip**: grouping is a local scheduling hint with no wire form, and nothing downstream of us asks for one |
| `congestionControl` | — | **skip**: a hint, and we already choose our own controller |
| `reliability` | — | **skip**: we are always QUIC, so the answer is a constant |
| `allowPooling`, `requireUnreliable` | — | **skip**: browser-sandbox concerns with no native analogue |

`drainSession` existed on `ClientSession` and on the raw
`WebTransportConnection` but not on the server-side `Session`, so a Zig server
could not exercise a browser's `draining` promise at all. That asymmetry is
fixed, and the `server-drain` scenario now covers it.

## Supported by one engine

| W3C member | engine | quic-zig | verdict |
|---|---|---|---|
| `getStats()` | Safari only (Firefox throws) | `getStats`, `getSendStreamStats`, `getRecvStreamStats` | we are ahead |
| `responseHeaders` | Safari preview | the 4-arity `onSessionReady` receives them | we are ahead |
| `exportKeyingMaterial()` | Firefox only | — | **skip** until a second engine wants it |
| `anticipatedConcurrentIncoming*` | Safari only | — | **skip**: a pre-allocation hint |
| `supportsReliableOnly` | Safari only | — | not applicable to a native client |

## The protocol-level gap: draft-13 §5, since closed

`src/h3/frame.zig` had known every draft-13 SETTINGS identifier for a while and
parsed all of them, but two things were wrong:

- `wt_max_sessions_v13` (0x14e9cd29) was **never serialized**, despite a comment
  claiming it was emitted alongside the pre-draft-13 codepoint. Safari 26.4
  reads only the new one. It is now emitted, as its own `Settings` field so the
  two drafts can be served independently (`Config.wt_legacy_settings` turns the
  older identifiers off).
- The session flow-control capsules — `WT_MAX_STREAMS`, `WT_MAX_DATA` and their
  `*_BLOCKED` partners — did not exist. They do now, and they are what lets
  Safari open a client-initiated stream at all. The reasoning that shapes them
  is in [DRAFT_IETF_WEBTRANS_HTTP3_13.md](DRAFT_IETF_WEBTRANS_HTTP3_13.md);
  the short version is that the credit travels as a capsule per session rather
  than as the §5.5 SETTINGS, which Safari answers by refusing the session.

What remains open: `RESET_STREAM_AT` reliable reset (`TODO.md` I5), the other
draft-13 dependency.

## Two bugs underneath this that browsers could not have shown us

**A WebTransport connection never read its peer's SETTINGS.** The WT poll looks
at peer-initiated uni streams before H3 does, hunting for its own stream type,
and `read()` transfers ownership — so the first read of the peer's control
stream, SETTINGS and all, was consumed and dropped. Nothing looked broken:
`peerMaxSessions()` quietly answered 1, the QPACK dynamic table stayed off, and
WebTransport does not otherwise need anything the peer says. It is fatal to
session flow control, though, which is entirely a conversation about what the
peer advertised. `H3Connection.adoptUniStream` now takes the bytes from whoever
read them first.

**Datagrams larger than 8 KB were dropped as decryption failures.** The receive
buffer was 8 KB; a peer may fill the path MTU, and on loopback that is 16 KB.
Safari sends 3-16 KB datagrams there, so a 64 KB stream write arrived with holes
that were never retransmitted — the packets were truncated by `recvmsg`, so they
failed AEAD authentication and read as `ChaCha20-Poly1305 decryption failed`
rather than as a short read. That is what `bidi-echo-64kb` and `uni-echo-64kb`
had been failing on under Safari, and it is unrelated to WebTransport.

## A framing bug this analysis turned up

Worth recording, because it was worth four red cells in every browser and was
misdiagnosed for months as a flush-ordering problem.

RFC 9297 §3.2: the capsule stream is the HTTP message content, and in HTTP/3
content travels in DATA frames. We *parsed* capsules both bare and DATA-wrapped
— with a comment noting that Chrome wraps — but *wrote* them bare. A bare
capsule reaches the peer as an unknown H3 frame type, which RFC 9114 §9 tells it
to ignore; the session then ended on the FIN alone and the close code was lost.
Chrome and Safari timed out, Firefox reported `closeCode: 0`.

`writeCapsule` now wraps outgoing CLOSE and DRAIN capsules. Chrome went from
9/13 to 13/13 and Firefox from 9/13 to 12/13 on the old suite. The regression
guard is `expectCapsulePayload` in `src/webtransport/session.zig`, which asserts
the wrapper is present rather than merely that a capsule can be parsed.

`SPEC/webtransport_browser_tests.md` recorded the old diagnosis — that the
session was finalized before the packet was transmitted, and that quic-go had
the same flaw. That was wrong.
