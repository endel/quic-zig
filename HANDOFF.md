# quic-zig — handover

State at `1a0473e`, 30 commits ahead of `origin/main` (`b6f9eb6`), unpushed.
540/540 unit tests, 431/431 fuzz smoke, 11/11 `tools/interop_local.sh`,
9/9 `interop/run_local_tests.sh`, 64/88 on the docker matrix (12 fail,
12 the peer does not implement). Full matrix in
[`SPEC/interop-results.md`](SPEC/interop-results.md); what changed and why in
[`CHANGELOG.md`](CHANGELOG.md).

## Running things

    zig build test                 # repo needs Zig 0.16; zvm's default may be 0.15.2
    zig build                      # apps/ into zig-out/bin
    zig build fuzz

    tools/interop_local.sh         # 11 cases, quic-zig against itself, no docker
    tools/interop_local.sh retry v2
    interop/run_local_tests.sh     # 9 cases against quic-go and quiche binaries
    tools/bench_local.sh           # single-stream throughput + handshake rate

    interop/runner/matrix.sh                    # full docker matrix, both peers
    interop/runner/matrix.sh quic-go handshake,transfer
    interop/runner/report.py                    # renders the SPEC table

`matrix.sh` appends a verdict per case to `interop/runner/matrix-results.txt`
and skips what is already there, so an interrupted run resumes. To re-run only
the failures: `grep -v FAIL matrix-results.txt > tmp && mv tmp matrix-results.txt`
and run it again. It needs `PYTHON=/opt/homebrew/bin/python3.12` (3.10+) and a
`quic-zig-interop:latest` image.

**The image rebuild is the bottleneck** — see task 6.

## What landed

Merged `memory-and-bounds`; reworked and merged [#29](https://github.com/endel/quic-zig/pull/29).
The headline is that no bidi stream was ever reclaimable: `hasUnackedData()`
compared byte offsets against a FIN, which is not a byte, so any stream that had
sent one counted as unacknowledged forever. Every PTO also walked every stream
the connection had ever opened. Six further bugs came out of running the matrix
— they are listed in the changelog; four of them flipped an interop case green.

Measured against the pre-merge tree: 8000 sequential H3 requests on one
connection went 3192 → 3652 req/s with peak RSS growth 18.3 → 2.8 MB and live
streams at the end 6364 → 6. Single-stream bulk throughput is unchanged (48
order-balanced runs a side land within 1%, inside a ±5% per-run spread — an
earlier two-run reading claiming −2% did not hold up).

Not done, deliberately: **nothing is pushed, and PR #29 has no comment on it.**

## Open, roughly in the order I would take them

### 1. Uni receive streams are never reclaimed
`StreamsMap.recv_streams` is only inserted into (`stream.zig:1045`) and removed
in `drainDisposalQueue` and `deinit`; every `disposeIfSettled` call site works on
a bidi `*Stream`, so nothing ever queues a uni ID. Same shape as the bug just
fixed for bidi, still open. Credit accounting is fine — `closeStream` does run on
uni FIN (`connection.zig:1957`) — it is the `ReceiveStream` and its `FrameSorter`
that are retained for the connection's life. Matters most for MoQ, which puts
objects on uni streams.

The predicate has to differ: there is no send side to wait on, so the signal is
`recv.finished` (the application has read past the FIN), not an ACK.

### 2. `wt-client` never exits
Completes the exchange, drains, logs "connection terminated after draining
period", then sits in the event loop forever. Predates all of this work; it is
why `interop/run_local_tests.sh` now runs every client under a 20 s watchdog.
Worked around, never diagnosed. User-visible for anyone using the client API.

### 3. STREAMS_BLOCKED is answered with a limit that unblocks nothing
`connection.zig:2046` replies with `max_incoming_bidi_streams` — the limit the
peer is already sitting at. Granting the accumulated `consumed` credit instead
would make the handler work, and would let the eager per-send MAX_STREAMS flush
added in `getMaxStreamsUpdates` go back to batching. That flush currently emits
one frame per closed stream at saturation instead of one per 25; harmless
(~0.4 ms over a 2.2 s run) but it exists only because the blocked path is dead.

### 4. Send buffers never reclaim acked bytes (TODO C4)
`SendStream.write_buffer` holds an entire transfer for its duration, so one
multi-GB stream holds multi-GB. With streams now reclaimed this is the last
unbounded-memory path. `buf_base` + compaction.

### 5. Handshake retransmission is slow under loss
50 handshakes at 30% loss run ~2.7 s each; quiche's client finishes 11 and hits
its own timeout, which is what `quic-zig<-quiche handshakeloss` and
`handshakecorruption` fail on. The connection it is on when time runs out is
healthy. quic-go's client passes the same case, so we are simply slower off the
mark than quiche waits for. Pre-existing — the pre-merge image fails identically.

### 6. The interop image has no build cache
`interop/runner/Dockerfile` does `COPY . .` before `zig build`, so any source
change invalidates everything after it and you pay the full `-j1` ReleaseSafe
compile: 25–30 minutes, four times in one session. A BuildKit cache mount on the
Zig cache directories would make it incremental. Do this before the next round of
interop fixes. Note `-j1` is deliberate — a parallel build peaks around 12 GB and
the machine OOM'd during this session even at `-j1` with other work alongside.

### 7. `chacha20` — fails against both peers, unexplained
The one open failure I could not close. Ruled out, with evidence in
`SPEC/interop-results.md`: cipher negotiation (pcap shows only `0x1303` offered
and selected), the key schedule (both endpoints' keylogs are byte-identical), and
our packet protection — a from-scratch RFC 9001 §5.4.4 implementation decrypts
305 of 307 of our Handshake packets from the capture, and the plaintext parses
cleanly.

quiche removes our header protection (it logs the right packet numbers) and then
drops the packet; quic-go reports `payload_decrypt_error` and records the dropped
header as `dcil: 0, scil: 0` where the wire carries 20 and 8. That last detail is
the only lead — it would put the packet-number offset nine bytes early. Next step
is a peer build with header parsing traced, not more changes to our crypto.

### 8. `quic-zig<-quiche multiplexing` — stalls at 1986/1999
Not stream credit: quiche logged MAX_STREAMS up to 2777 against the 1999 needed,
and never sent STREAMS_BLOCKED. Pre-existing. Unexplained.

### 9. `MEMORY.md` is over its size limit
312 lines against a 200-line cap, so only part of it loads each session. The Zig
0.15.2 API notes and the test counts are stale. Worth pruning to the index it is
meant to be.

## Review findings left on the table

From a `/simplify` pass, all sound, all bigger than that pass warranted:
`createH3`/`createWt` constructor helpers (seven hand-rolled copies across the
event loop and apps); `qpack_scratch` as a `poll()` parameter rather than a
shared-or-owned field with a lazy fallback; a `dispose_observer` on `StreamsMap`
so the "protocol layer drains before QUIC" ordering cannot be got wrong at five
call sites; `initCommonInto` for `initClientInto`/`initServerInto`, which share
~30 identical lines and already drifted once; deriving `DynamicTable.size` from
`used`/`count` instead of maintaining both.

Also: the uni half of `getMaxStreamsUpdates` has no early flush, because there is
no `highest_peer_uni_stream_id` to write the condition against.

## Environment notes

- Peer images: `martenseemann/quic-go-interop:latest`,
  `cloudflare/quiche-qns:latest`, `martenseemann/quic-network-simulator`.
  Pull with `--platform linux/amd64` on Apple silicon.
- `interop/quic-interop-runner` carries local modifications (implementations,
  docker-compose, testcase.py). `matrix.sh` registers `quic-zig` idempotently.
- `tools/interop_local.sh` excludes `connectionmigration`: the manual server
  advertises a preferred address on its own port and listens on one socket, so
  the client migrates to an address nothing is reading. `interop-server`, used by
  the docker image, uses a second socket and does exercise it.

## The ESP32 branch

`esp32-s3` is abandoned. If it is revisited, the thing worth knowing is that
Zig's C backend produced three separate silent miscompiles on Xtensa (u128 struct
alignment vs. ZIG_TARGET_MAX_INT_ALIGNMENT, uintptr_t vs uint32_t in helper
signatures, and an Ed25519 keypair corruption reproduced in
`qz_diag_ed25519_minimal`). Everything else there was ordinary porting.
