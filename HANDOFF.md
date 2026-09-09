# quic-zig — handover

State at `8192e79`, unpushed. 572/572 unit tests, 448/448 fuzz smoke,
11/11 `tools/interop_local.sh`, 9/9 `interop/run_local_tests.sh`.
Docker matrix: see [`SPEC/interop-results.md`](SPEC/interop-results.md).
What changed and why: [`CHANGELOG.md`](CHANGELOG.md).

## Running things

    zig build test                 # repo needs Zig 0.16; zvm's default may be 0.15.2
    zig build                      # apps/ into zig-out/bin
    zig build interop              # only the four binaries the interop image ships
    zig build fuzz

    tools/interop_local.sh         # 11 cases, quic-zig against itself, no docker
    interop/run_local_tests.sh     # 9 cases against quic-go and quiche binaries
    tools/bench_local.sh           # single-stream throughput + handshake rate

    interop/runner/build_image.sh  # cross-compile + package, ~7 s
    interop/runner/matrix.sh       # full docker matrix, both peers
    interop/runner/report.py       # renders the SPEC table

`matrix.sh` appends a verdict per case to `interop/runner/matrix-results.txt`
and skips what is already there, so an interrupted run resumes. To re-run only
the failures: `grep -v FAIL matrix-results.txt > tmp && mv tmp matrix-results.txt`.
It needs `PYTHON=/opt/homebrew/bin/python3.12` (3.10+) and a
`quic-zig-interop:latest` image.

## Read this before trusting a matrix result

**Never build the interop image with a plain `docker build`.** The old
Dockerfile compiled inside the `linux/amd64` builder stage, which on an
Apple-silicon host runs the x86_64 Zig compiler under emulation — and the
ReleaseSafe binaries it produced were wrong. The server's ECDSA
CertificateVerify failed to verify in every peer (`tls: invalid signature by
the server certificate`), so every case failed at the handshake and it looked
exactly like a protocol regression. `interop/runner/build_image.sh`
cross-compiles on the host instead; it is also 7 seconds rather than 25-30
minutes, which is why interop fixes no longer have to be batched.

Isolating that took a while, so here is the ten-second version for next time.
Generate runner certs, then point a peer client at the image's binary directly:

    cd interop/quic-interop-runner && ./certs.sh /tmp/rc 1
    docker run --rm --platform linux/amd64 -d --name s -p 15730:443/udp \
      -v /tmp/rc:/certs:ro -v /tmp/www:/www:ro \
      -e CERTS=/certs -e WWW=/www -e TESTCASE=http3 -e PORT=443 \
      --entrypoint /usr/local/bin/interop-server quic-zig-interop:latest
    (cd interop/quic-go && ./h3client_bin --addr 127.0.0.1:15730)

The matrix takes hours; that takes ten seconds and separates "our protocol is
broken" from "our toolchain is broken". The same trick — swap in a binary built
a different way with `-v` and `--entrypoint` — is what narrowed it: macOS
Debug and ReleaseSafe both fine, container Debug fine, container ReleaseSafe
broken, host-cross-compiled ReleaseSafe fine.

**Anything measured on this machine before that fix is suspect**, including the
"12 pre-existing failures, no regressions" line in the previous handover.

## What landed

Eight of the nine items on the previous list. Details in the changelog; the
parts worth knowing:

- Unidirectional receive streams are reclaimed now. The predicate could not be
  `recv.finished`: that flips inside `read()`, which the protocol layer calls
  itself, so at that instant WebTransport has the bytes but has not delivered
  the FIN event and H3 has not yet noticed a peer closing a critical stream.
  The consumer calls `StreamsMap.releaseRecvStream()` when it is genuinely
  done. H3's control and QPACK streams are never released, which is the right
  answer by construction rather than by special case. See
  [`SPEC/RFC9000_3.md`](SPEC/RFC9000_3.md).
- Two RESET_STREAM bugs came out of that. On a peer-initiated uni stream the
  frame was ignored completely, so the final size never reached connection flow
  control and the window stayed short by that much permanently. And a peer
  whose STREAM frames were all lost announces the stream with the reset itself
  (RFC 9000 §3.2) — we dropped the frame instead of opening the stream.
- Send buffers release acknowledged data. Note the second condition in
  `compactAcked`: discarding on a flat size threshold alone is quadratic
  against an application that writes ahead, and cost two thirds of bulk
  throughput (20.0 → 7.2 MB/s) before the amortised rule went in.
- `event_loop.zig` was never in `test_all.zig`. Its eleven tests stopped
  compiling during the 0.16 migration and nothing noticed for months. They pass
  now and immediately found six leaks.
- RFC 9001 Appendix A.5 runs as a unit test. It passes byte-exact, so the open
  `chacha20` interop failure is **not** our ChaCha20 crypto or header
  protection. Worth keeping in mind that A.2 (AES) was the only vector tested
  before, and the RFC 7541 Huffman table bug got in exactly this way.

## Open, roughly in the order I would take them

### 1. `chacha20` — fails against both peers, unexplained
Ruled out with evidence: cipher negotiation, the key schedule, our packet
protection (a from-scratch RFC 9001 implementation decrypts 305 of 307 of our
Handshake packets from a capture), and now the A.5 known-answer vector. The
peer removes our header protection correctly — quiche logs the right packet
number — and then fails the AEAD.

The one lead left: quic-go records the dropped packet's header as
`dcil: 0, scil: 0` where the wire carries 20 and 8. That is what you would see
if it parsed at the wrong offset in a coalesced datagram, which would point at
our long-header Length field rather than at crypto — and the chacha20 case
changes the ClientHello size, so a size-dependent coalescing bug would show up
here and nowhere else. Worth writing a parser that walks one of our datagrams
by its Length fields, the way a peer does, before touching crypto again.

### 2. `quic-zig<-quiche multiplexing` — stalls at 1986/1999
Not stream credit: quiche logged MAX_STREAMS up to 2777 against the 1999 needed
and never sent STREAMS_BLOCKED. Unexplained. `getScheduledStreams` schedules
only one non-incremental stream per call at the minimum urgency (which is
RFC 9218 behaviour), picked in hash-iteration order — worth ruling out before
looking further.

### 3. Handshake retransmission under loss
`quic-zig<-quiche handshakeloss` and `handshakecorruption`: quiche's client
finishes 11 of 50 handshakes and hits its own overall timeout. A local harness
now exists to poke at this without docker — a UDP relay that drops a fraction
of datagrams in both directions. Under it our server averaged 1.50 s per
handshake at 30 % loss against quiche's client, where quiche's *own* server
averaged 4.43 s, so the local model does not reproduce whatever the simulator
does. The scripts are in the session scratchpad, not committed; they were
30 lines of Python and bash.

### 4. Review findings left on the table
From an earlier `/simplify` pass, all sound: `createH3`/`createWt` constructor
helpers (seven hand-rolled copies across the event loop and apps);
`qpack_scratch` as a `poll()` parameter rather than a shared-or-owned field;
a `dispose_observer` on `StreamsMap` so the "protocol layer drains before QUIC"
ordering cannot be got wrong at five call sites; `initCommonInto` for
`initClientInto`/`initServerInto`, which share ~30 identical lines and have
already drifted once; deriving `DynamicTable.size` from `used`/`count`.

### 5. Smaller things
- The plain-QUIC uni loop in `event_loop.zig` reads `rs.finished` right after
  `rs.read()` returned data, where it is always false; the following branch
  delivers the FIN. Harmless, but the first branch reads as if it does something.
- `Server.init` reads the cert with an 8192-byte cap. A longer chain fails to
  load rather than truncating, but the limit is arbitrary.

## Environment notes

- Peer images: `martenseemann/quic-go-interop:latest`,
  `cloudflare/quiche-qns:latest`, `martenseemann/quic-network-simulator`.
  Pull with `--platform linux/amd64` on Apple silicon.
- `interop/quic-interop-runner` carries local modifications (implementations,
  docker-compose, testcase.py). `matrix.sh` registers `quic-zig` idempotently.
- `tools/interop_local.sh` excludes `connectionmigration`: the manual server
  advertises a preferred address on its own port and listens on one socket, so
  the client migrates to an address nothing is reading. `interop-server`, used
  by the docker image, uses a second socket and does exercise it.

## The ESP32 branch

`esp32-s3` is abandoned. If it is revisited, the thing worth knowing is that
Zig's C backend produced three separate silent miscompiles on Xtensa (u128
struct alignment vs. ZIG_TARGET_MAX_INT_ALIGNMENT, uintptr_t vs uint32_t in
helper signatures, and an Ed25519 keypair corruption reproduced in
`qz_diag_ed25519_minimal`). Everything else there was ordinary porting.
