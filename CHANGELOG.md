# Changelog

Notable changes to quic-zig. Versions follow [semantic versioning](https://semver.org);
`Unreleased` collects what has landed on `main` since the last tag.

## Unreleased

### Fixed

- A MoQ subscription through the relay never ended. Our relay ignored the
  publisher's PUBLISH_DONE, so a subscriber sat waiting for objects that were
  never coming — for moq-rs's test client, until its ten-second deadline. Each
  subscriber is now told the publication has finished, with the number of data
  streams the relay opened for it, and a publisher that disconnects without a
  PUBLISH_DONE has one sent on its behalf.
- The relay's WebTransport side answered no namespace discovery at all:
  SUBSCRIBE_NAMESPACE was dropped, so a subscriber that waits to be told a
  namespace exists before subscribing — moq-dev-rs's client does — never got
  past it. The raw-QUIC side did answer, but parsed draft-18 with draft-17's
  field list and sent the whole namespace where only the part after the
  subscribed prefix belongs.
- Every subgroup stream the relay forwarded said it did not start at the
  subgroup's first object, whether or not it did; draft-18 §2.2 requires the
  FIRST_OBJECT bit in exactly that case.
- A parameter value the draft makes session-fatal — an undefined subscription
  filter type, an unknown parameter type, a GROUP_ORDER or FORWARD outside its
  range — is answered with the PROTOCOL_VIOLATION session close it asks for
  rather than a REQUEST_ERROR. A peer sending one used to get an error that
  read as "that track is malformed", which let a subscribe test pass on a
  message we had never parsed.
- Certificate validity was checked against the monotonic clock, whose zero is
  the last boot, so every real certificate looked not-yet-valid and no chain
  could verify — which is why `skip_cert_verify` was the only way to connect
  anywhere. Session tickets carried the same timestamp, making a ticket
  issued by one host meaningless to another, and one older than 49 days
  aborted the process instead of wrapping.
- A server asking for a client certificate ended the handshake. Cloudflare's
  edge does, so `cdn.moq.dev` — and presumably any relay behind Cloudflare —
  could not be reached at all, over either transport. The request is now
  answered the way RFC 8446 says to when there is nothing to offer: with an
  empty certificate. `cdn.moq.dev` now runs a full session over either
  transport, verified against the system trust store.
- A peer could abort the process before the handshake completed. A QUIC packet
  whose Length field was below its packet number length read gigabytes past
  the datagram, and one below the 16-byte AEAD tag tripped an assertion; an
  Initial carrying a token of ~500 bytes or more overflowed the buffer the
  associated data is built in; and a QPACK integer with a long enough
  continuation run overflowed its accumulator, which any HTTP/3 peer can send.
- A peer's QPACK encoder stream could corrupt our dynamic table. `Duplicate`
  and `Insert With Name Reference` both name an entry the table already holds,
  and inserting the copy can evict the original first — so the insert read
  from the bytes it was overwriting. The visible effect is one header's value
  filed under another header's name, which for a proxy means attributing a
  request field it was never sent.
- QPACK header encoding wrote past the end of its output buffer when the
  headers did not fit. The size check only covered the first byte of each one.
- Rejecting a peer's packet no longer logs at error level. An unsupported QUIC
  version, a failed decryption and an undecryptable packet are ordinary events
  a peer chooses, so a junk-packet flood was also a log flood.

### Added

- `ClientConfig.ca` loads trust anchors — `.system` for the platform store,
  `.file` for a PEM bundle of your own — and turns certificate verification
  on when set. The `ca_cert_path` it replaces had done nothing but log a
  warning since the Zig 0.16 migration, so a client could not verify a server
  against anything. `moq-lite` and `moq-test-client` now use the trust store
  unless `--tls-disable-verify` is passed.
- `ClientConfig.loop` joins an event loop instead of creating one, so several
  clients share it and one `run()` drives them all. A client needing two
  connections at once no longer means two loops and a caller spinning `tick()`
  over both.
- Randomized sweeps over the QUIC packet, frame, transport-parameter, HTTP/3
  frame, QPACK, Huffman and capsule parsers, and over a connection fed a
  stream of datagrams. They are what found the above; `zig build fuzz` runs
  them. Zig 0.16's `-ffuzz` does not compile, so until it does this is the
  only thing feeding those parsers bytes they did not expect.

## 0.3.0

Media over QUIC, in both dialects the ecosystem uses, and an interop client
for the runner that tests them. Closes
[#21](https://github.com/endel/quic-zig/issues/21).

### Added

- **MoQ Transport draft-18**, alongside draft-17 and chosen by ALPN per
  peer, so a relay serves each client at the draft it asked for. draft-18
  is what the MoQ interop runner targets.
- **moq-lite** (draft-lcurley-moq-lite-05), the dialect `moq-relay`,
  `cdn.moq.dev` and the `@moq/net` browser client actually speak. Wire and
  message codecs, a session layer, and a `moq-lite` binary that publishes,
  subscribes, discovers broadcasts, or serves as an origin. Verified in both
  directions against `moq-relay` v0.14.16 and `moq-clock`, and from a browser.
- **`moq-test-client`**, the interop client for
  [moq-interop-runner](https://github.com/englishm/moq-interop-runner): seven
  control-plane test cases over either transport, TAP 14 output, packaged as a
  container. `tools/moq_interop.sh` runs it against a relay list. Registering
  with the runner is prepared but not submitted — see `SPEC/moq-interop.md`.
  [#21](https://github.com/endel/quic-zig/issues/21)
- **WebTransport application-protocol negotiation** (`WT-Available-Protocols` /
  `WT-Protocol`). Both moq-lite and moq-transport from draft-15 on choose their
  wire version this way over WebTransport, so nothing browser-facing could
  negotiate one before.
- MoQ relays hold a `SUBSCRIBE` open when the subscriber asks them to, and
  answer `DOES_NOT_EXIST` when it does not.
- An event-loop handler can declare `poll_interval_ms` to be woken on a
  cadence rather than only when the peer sends something.
- A `.quic` handler receives QUIC datagrams, and MoQ objects can be
  published over them (`moq-client --mode publish --datagrams`).
- `Connection.negotiatedAlpn()` reports the protocol in force.
- The WebTransport MoQ relay negotiates its draft per session and enforces
  the same namespace rules as the raw-QUIC one.

### Fixed

- A TLS server that advertised several ALPN protocols echoed
  `config.alpn[0]` to every client rather than the one that matched, so
  the client and server could disagree about what they were speaking.
- An event-loop client queued its `CONNECTION_CLOSE` and never flushed it,
  so the connection ended with the process and the peer held the session
  until its own idle timeout — half a minute of a server's capacity per
  short-lived client.
- The browser MoQ demos encoded `PUBLISH` without its request id, delta or
  parameter count, and subscribed with no `RENDEZVOUS_TIMEOUT`.
- **MoQ draft-17 control messages did not match the draft.** Most were
  encode-only, so their round-trip tests agreed with a shape no peer spoke.
  PUBLISH_NAMESPACE, SUBSCRIBE_NAMESPACE, PUBLISH, REQUEST_UPDATE and FETCH
  were missing their Request ID and Required Request ID Delta; GOAWAY its
  Timeout, REQUEST_ERROR its Retry Interval, PUBLISH_DONE its Stream Count;
  FETCH had no Fetch Type and so no joining form; FETCH_OK, PUBLISH_OK and
  PUBLISH_BLOCKED had invented bodies; NAMESPACE_DONE carried nothing. The
  error codes were a pre-draft-17 list that mixed the session and request
  number spaces.
- A MoQ peer could abort the process with one byte: a `GroupOrder` outside
  `0x00`-`0x02` reached `@enumFromInt` in four decoders.
- `decodeSubscribe` and `decodePublish` returned a track namespace that
  pointed into their own stack frame.
- The MoQ relay tracked stream roles in a 256-entry array indexed by stream
  id, so a long-lived connection stopped being able to tell a control stream
  from a subgroup header. It also read a connection pointer the event loop
  had already freed.
- `interop/runner/matrix.sh` removed every container on the machine between
  test cases, not just its own.

- Unidirectional receive streams were never freed. A connection kept a receive
  buffer and its reassembly state for every uni stream it had ever accepted, so
  anything that puts messages on uni streams — MoQ objects, WebTransport uni
  streams — grew for the life of the connection. They are released once the
  application has been handed the stream's FIN.
- `RESET_STREAM` on a peer-initiated unidirectional stream was ignored
  completely. The sender counts the whole final size against connection flow
  control when it sends, so a reset stream permanently consumed that much of the
  connection window; enough of them stall the connection. A retransmitted FIN on
  a uni stream also counted twice against the stream limit.
- A `STREAMS_BLOCKED` frame was answered with the limit the peer had just said
  it was stuck at, which unblocks nothing. The peer is now granted the credit
  its closed streams have earned, and the current limit is resent only when the
  peer's view of it is behind ours.
- A send stream held every byte it had ever sent until it closed, so a long
  transfer held the whole transfer in memory. Acknowledged data is released as
  it goes.
- `closeConnection()` on a client session closed the connection but left the
  run loop spinning forever, so a client that finished its work never exited.
- A connection no longer holds on to the streams it has finished with. They were
  marked closed but never removed, so a long-lived connection serving many
  short-lived streams — a relay, a WebTransport session pulling byte ranges —
  grew for its whole lifetime, and every PTO walked every stream it had ever
  opened. Underneath, a stream that sent a FIN counted as unacknowledged forever,
  because the FIN is not a byte and the check compared byte offsets; it is now
  tracked from the flag on the acknowledged frame. HTTP/3's own per-stream
  bookkeeping is pruned alongside. Reported in
  [#29](https://github.com/endel/quic-zig/pull/29) — thanks @MKS2508!

  8000 sequential HTTP/3 requests on one connection: 6364 live streams at the
  end, now 6; peak server memory 18.3 MB above idle, now 2.8 MB; 3183 → 3623
  requests/s.
- Every server in `apps/` allocated from an arena, where freeing does nothing, so
  a server's memory grew for as long as the process ran no matter what the
  library released. They now use an allocator that reuses it. Clients keep the
  arena; they exit.
- PTO could push data past the peer's `MAX_STREAM_DATA`. It queued everything
  from the last acknowledged byte to the last byte the *application* had written,
  including bytes never sent, and the retransmit path is the one send path with
  no window check of its own. quic-go closed our transfer with FLOW_CONTROL_ERROR
  under the blackhole test.
- The Application-space PTO ran before the handshake was confirmed, concluded
  that 0-RTT data the peer had not yet had a chance to acknowledge was lost, and
  re-sent every early request at 1-RTT — spending the round trip 0-RTT exists to
  save. RFC 9002 §6.2.1 gives that space no timer until confirmation.
- A server that accepted a resumption ticket sent the `early_data` extension in
  EncryptedExtensions whether or not the client had offered early data.
  BoringSSL calls that an unexpected extension, so every quiche client resuming
  against us was closed with alert 110.
- Stream credit was only extended once a quarter of the initial limit had been
  consumed, so a peer whose remaining work was smaller than that batch waited
  forever for credit it would never be offered — quiche's client stalled at 1988
  of 1999 requests. The remainder is now granted once the peer has opened
  everything it was allowed.
- A `CRYPTO`, `NEW_TOKEN` or `CONNECTION_CLOSE` frame whose declared length ran
  past the end of the datagram read out of bounds — an 8-byte datagram claiming
  16383 bytes of crypto data panicked. `NEW_CONNECTION_ID` never checked its
  declared connection ID length at all. All four are reachable from the network
  before the handshake completes. Transport parameters, `STREAM`, `DATAGRAM`,
  QPACK strings and the MoQ wire layer had the same shape and are fixed too.
- QPACK decoding shared one process-wide buffer and handed out `Header` slices
  into it, so two connections decoding on different threads corrupted each
  other's headers.
- Closing a server connection leaked its HTTP/3 and WebTransport state — nine
  hash maps per connection — because nothing ever deinitialised them.
- A peer's advertised QPACK table capacity is no longer trusted: it is clamped to
  what we can hold, and the clamped value is what we announce back.

### Changed

- Per-connection memory. A connection speaking raw QUIC used to carry HTTP/3 and
  WebTransport state it never touched; those layers are now allocated only when a
  protocol needs them, and the connection table entry goes from 181,640 bytes to
  256. The HTTP/3 layer itself goes from 175,776 to 21,160 bytes, almost all of it
  QPACK: every dynamic table entry reserved a 128-byte name and a 512-byte value,
  twice per connection, so a table advertising 4 KB of capacity reserved 82 KB to
  hold it. Entries now share one capacity-sized arena.
- Entries larger than 128/512 bytes are now indexable in the QPACK dynamic
  table, which they were not before.
- `Connection` and the TLS 1.3 handshake are no longer returned by value, so
  constructing one no longer costs 185 KB and 52 KB of the caller's stack.
- The interop image's binaries are cross-compiled on the host rather than built
  inside the linux/amd64 image. On an Apple-silicon host that stage ran the
  x86_64 Zig compiler under emulation and produced a server whose ECDSA
  CertificateVerify no peer would accept. Building the image is now 7 seconds
  rather than 25-30 minutes.

Measured on an interleaved A/B over loopback against the pre-merge tree: on the
workload the reclamation is about — 8000 sequential HTTP/3 requests on one
connection — 3192 → 3652 requests/s. Single-stream bulk download is unchanged;
48 order-balanced runs a side put the two within 1% of each other, which is well
inside this benchmark's ±5% per-run spread.

### Added

- `tools/interop_local.sh` runs eleven interop cases — handshake, transfer,
  http3, chacha20, keyupdate, multiconnect, retry, v2, resumption, zerortt, ecn —
  against our own client and server, with no Docker.
- `tools/bench_local.sh` reports single-stream download throughput and
  handshake/request rate over loopback.
- `interop/runner/matrix.sh` runs the quic-interop-runner matrix against a peer
  in both directions, one case at a time, recording each verdict so an
  interrupted run resumes where it stopped.
- `interop/run_local_tests.sh` covers quic-zig against quiche directly, in both
  directions and over HTTP/3; previously quiche was only ever run against
  quic-go. Every client now runs under a watchdog, so a client that does not exit
  no longer stalls the rest of the suite.

## 0.2.0

Baseline for this changelog. See `SPEC/STATUS.md` for the state of each RFC.
