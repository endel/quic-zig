# quic-zig — improvement backlog

Tiers 1-4 derive from the full gap review against quic-go HEAD `89690bf`
(2026-06-08, post-v0.60.0). Detailed findings with file:line citations on both
sides live in
[`SPEC/REVIEW_quic_go_comparison_2026-06.md`](SPEC/REVIEW_quic_go_comparison_2026-06.md).
Tier 5 is separate: core problems hit while building MoQ on top of this stack.

Status legend: `[ ]` todo · `[~]` in progress · `[x]` done · `(S/M/L)` effort.

---

## Performance (in progress — measuring gains vs quic-go)

Benchmark harness: `apps/bench_throughput.zig` (bulk single-stream H3 download).
Results tracked in [`bench/throughput-results.md`](bench/throughput-results.md).

- [ ] **P1. UDP socket buffer sizing (S)** — set SO_RCVBUF/SO_SNDBUF ~7 MB at socket
  creation (`event_loop.zig` + bench/interop apps). quic-go: `sys_conn_buffers.go:14-68`.
- [ ] **P2. App-limited check stalls cwnd growth (S)** — `connection.zig:1510,1640` +
  `congestion.zig:102,251`. Treat as cwnd-limited only when `available ≤ 3×MDS` (+ slow-start
  half-window rule), not `in_flight < cwnd`. quic-go: `cubic_sender.go:267-275`.
- [ ] **P3. Pacer burst fixed at 12 KB (S)** — `congestion.zig:442-448`. Recompute as
  `max(bandwidth×2ms, 10×MDS)` on bandwidth/MTU change; floor pacing delay at 1 ms.
- [ ] **P4. Flow-control updates late + auto-tune eager (S)** — fire MAX_DATA/MAX_STREAM_DATA
  at 25% consumed not 75% (`flow_control.zig:100`, `stream.zig:316`); gate window doubling on
  `elapsed < 4×fraction×srtt` (`flow_control.zig:115-138`); add 1.5× conn/stream coupling.
- [ ] **P5. Datagram frames packed after stream data (S)** — pack DATAGRAM right after ACK
  (`packet_packer.zig:444-546`). quic-go: `packet_packer.go:653-668`.
- [ ] **P6. PING after N non-ack-eliciting packets (S)** — counter-based, every ~20th ACK-only
  packet; don't store non-in-flight packets / purge below largest_acked (`ack_handler.zig:187`).
- [ ] **P7. DF bit + send-errno handling (M)** — IP_DONTFRAG/IP_PMTUDISC_PROBE, gate PMTUD on
  it, map EMSGSIZE→probe-lost; stop discarding `sendmsg` results (`ecn_socket.zig:268,297`).
- [ ] **P8. MTU probes starve under load (M)** — don't gate probe on `bytes_written==0`
  (`connection.zig:3149`); bisect on tracked lost sizes; clamp to peer max_udp_payload_size.
- [ ] **P9. PTO retransmits whole window (M)** — per-packet crypto ranges; probe = oldest
  unacked packet's frames only (`connection.zig:3488-3503,1463-1473`).
- [ ] **P10. Hybrid slow start (M)** — HyStart delay-increase exit (`hybrid_slow_start.go`).
- [ ] **P11. Linux GSO + recvmmsg (L)** + skip plaintext tmp→out copy (S,
  `packet_packer.zig:257-261`) + per-packet ECN cmsg (S, `ecn_socket.zig:88-95`).
- [ ] **P12. Smaller wins (S each)** — RTT sample from Retry/NEW_TOKEN; immediate ACK for
  Initial/Handshake + ECN-CE; ack_delay only post-confirm; don't arm app PTO pre-confirm; strip
  length on last STREAM frame; optional 32-pkt initial cwnd; idle-timer restart on send.

## Tier 1 — Correctness & security

- [ ] **C1. ACK for unsent PN accepted; no PN skipping (S+M)** — `ack_handler.zig:210`. Validate
  `largest_ack ≤ largest_sent` → PROTOCOL_VIOLATION; add skipping PN generator.
- [ ] **C2. Per-stream receive flow control not enforced (S)** — `connection.zig:1868` only
  checks conn window; `StreamFlowController` is dead code.
- [ ] **C3. CRYPTO stream has no 16 KiB offset cap (S)** — pre-auth DoS (`crypto_stream.zig:48`).
- [x] **C4. Send buffers never reclaim acked bytes (L)** — `buf_base` + amortised
  compaction in `SendStream`; see [SPEC/RFC9000_3.md](SPEC/RFC9000_3.md).
- [ ] **C5. Incoming uni streams never get MAX_STREAM_DATA (S)** — `connection.zig:2838` loops
  bidi map only; H3/WT/MoQ uni streams stall after 1 MB.
- [ ] **C6. Stateless reset dead both directions (S/M)** — share manager key into `accept()`;
  call `matchesStatelessReset` from recv path (`connection.zig:808,4104`).
- [ ] **C7. Lost control frames never retransmitted (M)** — RFC §13.3; record popped control
  frames in `SentPacket`, re-push on loss (`packet_packer.zig:419`).
- [ ] **C8. Coalesced datagrams can exceed 1200 B pre-validation (S/M)** — thread datagram
  budget through `packCoalesced` + pad-to-1200 fixup (`packet_packer.zig:120-234`).
- [ ] **C9. AEAD/key-update limits not enforced (M)** — failed-decrypt counter →
  AEAD_LIMIT_REACHED; raise KEY_UPDATE_ERROR (`crypto.zig`, `connection.zig:1277`).
- [ ] **C10. Stale tokens deadlock handshake (M)** — fall back to Retry on invalid token; split
  retry vs NEW_TOKEN lifetimes; carry RTT (`connection_manager.zig:355`).
- [ ] **C11. Server ingress validation (S)** — drop Initials <1200 B / DCID <8 B; require
  ≥1200 B + rate-limit before VN (`connection_manager.zig:307,317`).
- [ ] **C12. ECN CE cuts cwnd every ACK; validation holes (S+M)** — once-per-round dedupe;
  detect bleaching/mangling, stop marking in unknown (`connection.zig:1774`, `ecn.zig`).
- [ ] **C13. Path migration gaps (M/L)** — PATH_RESPONSE on probed path; highest-PN switch rule;
  pad challenge/response to 1200 (`connection.zig:2094,3235`).
- [ ] **C14. DATAGRAM size contract violated (M)** — advertise 65536 but drop >1200
  (`connection.zig:330,391,3751`).

## Tier 3 — Robustness / DoS

- [ ] **R1. Received-packet RangeSet unbounded (S)** — cap at 64 (`ack_handler.zig:356`).
- [ ] **R2. FrameSorter no gap cap (S)** — cap at 1000 (`stream.zig:79`).
- [ ] **R3. PendingFrameQueue overflow silently drops (S)** — `frame.zig:929`.
- [ ] **R4. CONNECTION_CLOSE retransmit 1:1 → amplification (S)** — popcount backoff
  (`connection.zig:1171,2910`).
- [ ] **R5. Stateless reset inline, no rate limit (S)** — >42 B trigger + token bucket
  (`connection_manager.zig:318`).
- [ ] **R6. Malformed ACK ranges accepted via saturation (S)** — FRAME_ENCODING_ERROR
  (`frame.zig:236`).
- [ ] **R7. CID lifecycle gaps (M)** — retire-on-switch, CONNECTION_ID_LIMIT_ERROR, in-use
  guard, RETIRE validation, delayed routing removal, rotation (`connection.zig:162,2063`).
- [ ] **R8. At-capacity Initials silently dropped (S/M)** — send CONNECTION_REFUSED; Retry-under-
  load callback (`connection_manager.zig:98,168`).
- [ ] **R9. No max cwnd cap (S)** — 10000 pkts (`congestion.zig`).
- [ ] **R10. Persistent-congestion check loose vs §7.6.2 (S)** — `ack_handler.zig:313`.
- [ ] **R11. Control-frame order not randomized (S, low)** — `packet_packer.zig:333`.

## Tier 4 — Interop features & observability

- [ ] **I1. Server-level 0-RTT queue + undecryptable-queue expiry (M)** —
  `connection_manager.zig:317`. (Relevant to `debug/zerortt-quic-go-interop`.)
- [ ] **I2. HelloRetryRequest unsupported (M)** — `tls13.zig`. Still missing,
  but no longer known to block anything. The `cdn.moq.dev` failure attributed
  to it here was a misdiagnosis: instrumenting the `UnexpectedMessage` showed
  handshake type 13, a **CertificateRequest**, arriving where the server's own
  Certificate was expected. X25519 had been accepted and there was no HRR in
  sight. Handling it (RFC 8446 4.3.2/4.4.2 — accept the request, answer with an
  empty Certificate) makes `cdn.moq.dev` work over both raw QUIC and
  WebTransport: full moq-lite session, 8 broadcasts listed.

  An HRR would fail as `DecodeError`, not `UnexpectedMessage` — its key_share
  carries a bare selected_group, which our 4-byte minimum rejects. That is the
  fingerprint to look for next time.

- [x] **I2b. Certificate validity was checked against the monotonic clock
  (S)** — `sys.nanoTimestamp()` is `CLOCK_MONOTONIC`, whose zero is the last
  boot, and `tls13.zig` compared X.509 notBefore/notAfter against it. Every
  real certificate read as `CertificateNotYetValid`, so a chain could never
  verify and everything ran with `skip_cert_verify`. Session tickets embedded
  the same clock, so a ticket issued by one host and presented to another
  computed a meaningless age — and one older than ~49 days aborted the
  process on a `u32` overflow rather than wrapping as RFC 8446 4.2.11 says.
  Fixed with `sys.realtimeSeconds()`. `cdn.moq.dev` now verifies.

  Still open is the trust anchor: `ca_cert_path` is ignored pending the 0.16
  `Io` threading (`event_loop.zig`), so the chain is checked link by link and
  against the hostname, but never rooted. That is I3.
- [x] **I3. Client cert verification defaults off (S)** — `ClientConfig.ca`
  now takes `.none`, `.system` (the platform trust store) or
  `.file` (a PEM bundle), and anything but `.none` turns `skip_cert_verify`
  off. `src/quic/ca_bundle.zig` holds the `Io` that 0.16 requires for the
  load, so it stays out of the library's signatures. The `ca_cert_path` field
  it replaces had done nothing but log a warning since the 0.16 migration.
  `moq-lite` and `moq-test-client` default to the trust store unless
  `--tls-disable-verify` is passed. Verified against `cdn.moq.dev` (system
  store) and our own interop CA (file).
- [ ] **I4. Cipher/curve breadth (S/M/L)** — AES-256-GCM-SHA384, P-384, X25519MLKEM768.
- [ ] **I5. RESET_STREAM_AT reliable reset (M/L)** — needed by WebTransport draft-13.
- [ ] **I6. Proactive key-update cadence (S)** — rotate every ~100k pkts (`crypto.zig:788`).
- [ ] **I7. STREAMS_BLOCKED never emitted (S)** — `stream.zig:899-923`.
- [ ] **I8. IP_PKTINFO missing (M)** — wildcard-bound multihomed source-addr bug
  (`ecn_socket.zig`).
- [ ] **I9. qlog: emit RFC 7464 0x1E separator (S) + missing events (M)** — `qlog.zig:66`.
- [ ] **I10. Stats: latest_rtt/bytes_lost + server counters (S)** — `connection.zig:4009`.
- [ ] **I11. Misc (S)** — always advertise v2 in version_information; embed PSK ticket nonce
  (`tls13.zig:1845`).

## Tier 5 — Found while building MoQ (2026-09)

Core issues, not MoQ ones. Each was hit in practice rather than read off a
spec, so the consequence is recorded alongside the fix.

- [x] **F1. `Client.stop()` queues CONNECTION_CLOSE but never sends it (S)** —
  `event_loop.zig:1710`. `stop()` calls `conn.close()`, which only queues the
  frame; it reaches the wire on the next flush. An app driving the loop with
  `run()` is fine, because the armed timer fires and drains before the loop
  exits. An app driving it with `tick()` and then exiting is not: `tick()` is
  `loop.run(.no_wait)` and returns without firing a timer that is not yet due,
  so the close never leaves and the peer holds the session for its whole idle
  timeout — 30 s of a server's per-client capacity for a client that ran for
  two. It surfaces far from the cause: a relay's client table fills and some
  *later*, unrelated connection fails with "no SETUP from peer". Either make
  Fixed: both `Server.stop()` and `Client.stop()` flush. The server's doc
  comment had claimed it did for as long as it had not. Regression test
  `stop() leaves nothing queued for the peer`, which fails without it.

- [x] **F2. 23 of 26 fuzz targets never see a random byte (M)** — `fuzz.zig`.
  `-ffuzz` does not compile on Zig 0.16.0: 27 errors inside the toolchain's
  own `lib/compiler/test_runner.zig` (`*builtin.StackTrace` vs
  `*debug.StackTrace`), so `std.testing.fuzz` runs each body once on its seed
  and the whole file was a smoke test. The three MoQ parsers had a fixed-seed
  sweep instead — random bytes, plus real encoded messages with a few bytes
  flipped — and it found a one-byte remote abort within seconds of being
  written (`@enumFromInt` on an attacker-controlled `GroupOrder`).

  Fixed: the same shape now covers the QUIC packet headers, frames, transport
  parameters, HTTP/3 frames, QPACK, Huffman and capsules, plus a connection
  fed a stream of datagrams — `handleDatagram` being the whole pipeline. Five
  bugs a peer can reach fell out, four of them aborts and three of those
  pre-handshake: a QPACK integer whose continuation run overflows its
  accumulator, a packet Length below the packet number length (reads gigabytes
  past the datagram), one below the 16-byte AEAD tag, an Initial token past
  the 512-byte buffer the associated data is built in, and a QPACK `Duplicate`
  reading the arena it was writing to. `SWEEP_ITERATIONS` is what
  `zig build fuzz` can afford; raise it locally when touching a parser, the
  seeds are fixed so a longer run is a superset.

  Worth knowing if you extend these: a sweep is only as good as its reach.
  The transport-parameter and QPACK sweeps looked fine and were decoding
  nothing — 53 and 244 successes per 50k — because a seeded message was handed
  over with the rest of the random buffer trailing it, and neither format is
  self-delimiting. Count what gets past the first length check before trusting
  a sweep.

  Still open underneath: `-ffuzz` itself, which would replace all of this
  with coverage-guided input. Recheck on the next Zig release.

- [x] **F3. `Client` is one connection per loop (M)** — `event_loop.zig:1432`.
  Any client needing two concurrent connections — the MoQ interop runner's
  two-connection cases, a relay dialling upstream, a migration test — had to
  instantiate two `Client`s and alternate `tick()` on them, which works but
  means two sockets, two libxev loops and hand-rolled scheduling.

  Fixed the loop half: `ClientConfig.loop` joins an existing loop instead of
  making one, so several clients share it and one `run()` drives them all. A
  client that joined a loop never stops it. `event_loop.Xev` exports the
  backend the build selected, because on Linux a bare `@import("xev")` is a
  different type. See `two clients share one loop`.

  Left as is: one socket per connection. Separate 4-tuples are the right
  shape for a client — independent congestion control, and migration tests
  need them — so `ConnectionManager`'s demultiplexing has nothing to do here.
  The measured case for going further is weak: rewiring `moq_test_client` onto
  a shared loop was tried and reverted, because it came out identical on both
  the healthy path (1.13 s vs 1.18 s) and against an unreachable relay
  (6.5 s user vs 6.4 s) — the CPU there is handshake retransmission, not the
  spin.

- [x] **F4. TLS server echoed `config.alpn[0]` regardless of the match (S)** —
  a server advertising more than one protocol told every client its own first
  choice, so the two could disagree about what they were speaking. Fixed with
  `Tls13Handshake.negotiatedAlpn()` and `Connection.negotiatedAlpn()`; it had
  gone unnoticed because nothing advertised more than one ALPN until MoQ
  needed to serve two drafts at once.

## Where we already lead quic-go (keep)

Persistent congestion (§7.6) · RFC 9218 priority scheduling · PMTUD raise timer (§8899) ·
datagram age expiry · per-space PTO counts + 3 s handshake cap · zero-alloc stack send buffers.
