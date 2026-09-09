# Changelog

Notable changes to quic-zig. Versions follow [semantic versioning](https://semver.org);
`Unreleased` collects what has landed on `main` since the last tag.

## Unreleased

### Fixed

- A connection no longer holds the send buffers of streams it has finished with.
  Streams were marked closed but never removed, so a long-lived connection
  serving many short-lived streams — a relay, a WebTransport session pulling byte
  ranges — grew for its whole lifetime. They are now reclaimed as soon as the
  peer acknowledges the last byte. Based on
  [#29](https://github.com/endel/quic-zig/pull/29). Thanks @MKS2508!
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

- Per-connection memory drops from 181 KB to 27 KB. A full 256-connection table
  goes from 44 MB to 6 MB. Most of it was QPACK: every dynamic table entry
  reserved a 128-byte name and a 512-byte value, twice per connection, whether or
  not the peer used the table. Entries now share one capacity-sized arena, and
  HTTP/3 and WebTransport state is allocated only for connections that speak
  those protocols.
- Entries larger than 128/512 bytes are now indexable in the QPACK dynamic
  table, which they were not before.
- `Connection` and the TLS 1.3 handshake are no longer returned by value, so
  constructing one no longer costs 185 KB and 52 KB of the caller's stack.

### Added

- `tools/interop_local.sh` runs eleven interop cases — handshake, transfer,
  http3, chacha20, keyupdate, multiconnect, retry, v2, resumption, zerortt, ecn —
  against our own client and server, with no Docker.
- `tools/bench_local.sh` reports single-stream download throughput and
  handshake/request rate over loopback.
- `interop/run_local_tests.sh` covers quic-zig against quiche directly, in both
  directions and over HTTP/3; previously quiche was only ever run against
  quic-go. Every client now runs under a watchdog, so a client that does not exit
  no longer stalls the rest of the suite.

## 0.2.0

Baseline for this changelog. See `SPEC/STATUS.md` for the state of each RFC.
