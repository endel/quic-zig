# Changelog

Notable changes to quic-zig. Versions follow [semantic versioning](https://semver.org);
`Unreleased` collects what has landed on `main` since the last tag.

## Unreleased

### Fixed

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
