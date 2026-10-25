# WebTransport over HTTP/3 — draft-ietf-webtrans-http3-13

What of the draft we implement, and the three decisions inside §5 that a
reader would otherwise have to reconstruct from the code.

Session-level flow control (§5.3–§5.6) is implemented and is what a browser
needs before it will open a client-initiated stream: Safari 26.4 opens none
without it. Conformance numbers across three browsers live in
[webtransport_conformance.md](webtransport_conformance.md); the W3C API gap
analysis in [webtransport_w3c_api.md](webtransport_w3c_api.md); the per-section
table in [STATUS.md](STATUS.md).

## Codepoints

| Item | Value | Where |
| --- | --- | --- |
| `SETTINGS_WT_MAX_SESSIONS` | 0x14e9cd29 | §9.2 |
| ... pre-draft-13 spelling | 0xc671706a | still sent; Chrome and Firefox read it |
| `SETTINGS_WT_INITIAL_MAX_DATA` | 0x2b61 | §9.2 — **not sent by default**, see below |
| `SETTINGS_WT_INITIAL_MAX_STREAMS_UNI` | 0x2b64 | §9.2 |
| `SETTINGS_WT_INITIAL_MAX_STREAMS_BIDI` | 0x2b65 | §9.2 |
| `WT_CLOSE_SESSION` | 0x2843 | §6 |
| `WT_DRAIN_SESSION` | 0x78ae | §5.1 |
| `WT_MAX_DATA` | 0x190B4D3D | §5.6.4 |
| `WT_MAX_STREAMS` bidi / uni | 0x190B4D3F / 0x190B4D40 | §5.6.2 |
| `WT_DATA_BLOCKED` | 0x190B4D41 | §5.6.5 |
| `WT_STREAMS_BLOCKED` bidi / uni | 0x190B4D43 / 0x190B4D44 | §5.6.3 |

Codec: `src/h3/frame.zig`, asserted against the draft's figures as bytes rather
than round-tripped. Accounting: `src/webtransport/flow_control.zig`, which is
pure arithmetic. Capsule I/O: `src/webtransport/session.zig`, which owns the
one function that puts a capsule on the wire.

## Three decisions inside §5

### We do not advertise the initial credits in SETTINGS

§5.5 says initial limits *may* travel in SETTINGS. We send the capsule instead,
because **Safari 26.4 refuses the session outright when it sees those three
identifiers** — every scenario fails, `connect-echo` included, and the CONNECT
never arrives. Measured both ways; `WT_CREDITS=0` / `WT_SETTINGS_CREDITS=1` on
`wpt-server` reproduce each side of it.

Nothing is given up. §9.2 describes exactly this arrangement for the default
case: with no initial credit advertised, "the endpoint needs to send
WT_MAX_STREAMS capsules on each individual WebTransport session before its peer
is allowed to create any streams within that session" — so every session gets
its window as a capsule the moment it opens. The only cost is that a peer
cannot open a stream in the same flight as its CONNECT.
`Config.wt_advertise_credits` turns the announcement back on for a peer that
wants it.

### Silence from a peer is not a limit of zero

§9.2 makes an absent credit a limit of zero, which would be correct and useless:
a peer that never sent the setting is far more often one that does not implement
§5.6 at all than one that means to block us, and reading it strictly would stop
us opening a single stream to Chrome. So a stated limit binds — an explicit zero
included — and silence does not. `StreamLimit.max_send` is `?u64` for that
reason.

The gate above it is §5.1's: the limits bind at all only when **both** endpoints
advertise `WT_MAX_SESSIONS` above one, on the draft-13 codepoint. Chrome,
Firefox and quic-go send the pre-draft-13 spelling, so nothing in this family
applies to them and none of it can regress them.

Granting is deliberately wider than that gate: we send credit to any peer that
sent the draft-13 `WT_MAX_SESSIONS` at all, whatever its value. §5.1 can be read
as gating on the *server's* value alone, and a peer reading it that way waits
forever for a credit we would otherwise never send. A capsule the peer must
ignore costs a dozen bytes; the deadlock costs every client-initiated stream.
Safari 26.4 sends `WT_MAX_SESSIONS = 1`, which is exactly the case that matters.

### An overrun raises the window, not the connection

The draft names no error for a peer that exceeds `WT_MAX_DATA` or
`WT_MAX_STREAMS` — unlike QUIC, which makes it a FLOW_CONTROL_ERROR. We are
lenient on the receive side: the accounting still runs, the window still slides,
and a peer that outruns its credit is not disconnected over a rule the draft
does not state. Our own send side obeys the peer's limit and says so with
`WT_STREAMS_BLOCKED` / `WT_DATA_BLOCKED`.

## Sizing

The default window is 100 streams each way and 16 MB of session data, mirroring
the QUIC connection defaults so the session limit is never the tighter of the
two by accident: both slide by half a window, but the session's slides on
streams *opened* where QUIC's waits for them to close. A session limit that
binds before QUIC's would be a new way for an application to stall.

`WT_STREAMS_BLOCKED` from the peer naming a limit below the one we granted
re-sends the grant rather than waiting for the window to slide — the grant was
lost or crossed in flight.

## Not implemented

| Item | Note |
| --- | --- |
| `RESET_STREAM_AT` reliable reset (§4.3) | The draft makes it a MUST for resetting a WT data stream, so both ends agree the header arrived. `TODO.md` I5. Without it, §5.3's note stands: the two ends cannot agree on which streams are open — which is why our stream limit counts opens rather than closures, and does not need to. |
| `WT_MAX_STREAM_DATA` / `WT_STREAM_DATA_BLOCKED` | §5.4 prohibits them — receipt should be a session error. We ignore them instead. |
| Flow control across an intermediary (§5.6.1) | We are not an intermediary. |
| 0-RTT limit retention (§3.2) | No 0-RTT on the WebTransport path. |

## Session termination (§6)

Followed as draft-16 §6 words it, which adds the UTF-8 rules and the optional
STOP_SENDING to draft-13's text. Any end of the CONNECT stream ends the
session: the application gets one `session_closed`, and the session's streams
are reset and stopped with `WT_SESSION_GONE`.

| Peer sends on the CONNECT stream | `session_closed` | We answer with |
| --- | --- | --- |
| `WT_CLOSE_SESSION` (then FIN) | its code and reason | FIN |
| FIN alone | code 0, reason `""` | FIN |
| RESET_STREAM or STOP_SENDING | `abrupt`, code 0 | RESET_STREAM and, while it may still send, STOP_SENDING, both `H3_REQUEST_CANCELLED` |
| a FIN cutting a capsule short; a close whose reason is past 1024 bytes or not UTF-8; a known capsule that does not parse | `abrupt`, code 0 | both, `H3_MESSAGE_ERROR` (RFC 9297 §3.3, RFC 9114 §4.1.2) |
| bytes after a `WT_CLOSE_SESSION` | the close's code | both, `H3_MESSAGE_ERROR` |
| a capsule type we do not know | nothing: dropped (RFC 9297 §3.2) | — |

Capsules are acted on before the stream's end, so a close that shares a packet
with the FIN or with a STOP_SENDING (webtransport-go sends all three) keeps its
code. A STOP_SENDING that overtakes the capsule in an earlier packet does not:
the session is gone by the time the code arrives, as in Chrome and Firefox.

Once we have sent our own close, the session waits for the peer to end its
side, however it does, and then reports our code. Nothing malformed from the
peer is answered with a reset in that state: the reset could overtake our
capsule. A client whose CONNECT the server finishes or resets without a 200
gets `session_rejected` with an empty status; our own server does that to a
CONNECT past its session slots.

**What we send.** A close is the capsule and a FIN, nothing more: no
STOP_SENDING before the peer's FIN, which Chrome and Firefox turn into an
abrupt close that loses the code (Chrome counts a close clean only once both
FINs have crossed). The library never follows a close with CONNECTION_CLOSE; an
application that wants the connection gone too should wait for
`session_closed`, which arrives with the peer's FIN. A reason longer than 1024
bytes is cut at a UTF-8 character boundary.

**Not enforced.** §6 also forbids new streams and datagrams on a terminated
session. `openBidiStream`, `openUniStream` and `sendDatagram` do not check;
the peer refuses them, and the application has had its `session_closed`.
Bytes the peer sends after its close in a *later* packet go unread rather
than answered with H3_MESSAGE_ERROR: the session slot is released by then.

## Caveats worth knowing

**Streams wait for their session (§4.5).** A stream naming a session that is
still connecting, or whose CONNECT has not been read yet, is kept from the
application with its data unread, and surfaced once the session is accepted.
At most 16 wait at once; past that a stream is reset with
`WT_BUFFERED_STREAM_REJECTED`. One naming a session that is gone, or a request
stream that never was one, is reset with `WT_SESSION_GONE`. Datagrams for a
session not yet active are dropped rather than buffered.

**A server refuses a session with a status, never a capsule (§3.3).**
`rejectSession(id, status)` answers the CONNECT with a 3xx–5xx and its FIN;
the connection's other sessions are untouched. A close capsule there would
come before any response HEADERS, which RFC 9114 §4.1 makes
H3_FRAME_UNEXPECTED: the peer would close the whole connection. So
`closeSession` on a session not yet accepted refuses it with 403. A CONNECT
past the session slots is reset with H3_REQUEST_REJECTED before the
application sees it.

**A capsule may not straddle a DATA frame.** RFC 9297 §3.2 puts the capsule
stream in the HTTP message content, so in HTTP/3 capsules travel inside DATA
frames; we unwrap a DATA frame by dropping its header and reading the capsules
that follow. That is correct as long as each DATA frame holds whole capsules,
which is what every peer we have met writes. A capsule split across two DATA
frames would mis-parse.

**A capsule longer than 4 KB is skipped, not buffered.** The peer chooses
Length, and buffering whatever it names would let it name 2^62. The largest
capsule we parse is `WT_CLOSE_SESSION`, whose reason §6 caps at 1024 bytes; one
announcing more is malformed and ends the session before any of it is read.

**Session flow control is invisible on a Chrome connection.** Nothing in this
family is emitted or enforced unless the peer speaks draft-13, so the Chrome and
quic-go columns of the conformance matrix say nothing about whether it works.
The tests that do are in `src/webtransport/flow_control.zig`,
`src/webtransport/session.zig` ("WT flow control: …"), and `WT_CREDITS=<n>` on
`wpt-server`, which is how you watch a real peer hit the limit and ask for more.
