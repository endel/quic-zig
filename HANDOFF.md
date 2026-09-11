# quic-zig — handover

Branch `moq-interop-and-lite`, unpushed. This session was MoQ: an interop
test client for <https://github.com/englishm/moq-interop-runner>, a
substantial correction to the draft-17 control messages, and a moq-lite
implementation.

    zig build test      # green
    zig build fuzz      # green
    tools/interop_local.sh      # 11/11
    interop/run_local_tests.sh  # 9/9
    interop/runner/matrix.sh    # 64/88, identical to the previous run
    tools/moq_local.sh          # 9/9, MoQ end-to-end against our own binaries
    tools/moq_interop.sh        # MoQ, both drafts: 7/7 ours, 6/7 moq-relay
    node tools/moq_lite_browser_test.mjs          # moq-lite in Chrome
    RELAY=1 node tools/moq_lite_browser_test.mjs  # ... through our relay

The docker matrix landed one case away from the baseline on the first
pass — `quiche<-quic-zig handshakecorruption` — and passed on a re-run, so
64/88 with the same verdicts case for case. That case is flaky under this
peer, which the corruption notes below already say.

What changed and why: [`CHANGELOG.md`](CHANGELOG.md). MoQ specifics:
[`SPEC/moq-interop.md`](SPEC/moq-interop.md),
[`SPEC/DRAFT_IETF_MOQ_TRANSPORT.md`](SPEC/DRAFT_IETF_MOQ_TRANSPORT.md),
[`SPEC/DRAFT_LCURLEY_MOQ_LITE_05.md`](SPEC/DRAFT_LCURLEY_MOQ_LITE_05.md).

## Running things

    zig build test                 # repo needs Zig 0.16; zvm's default may be 0.15.2
    zig build                      # apps/ into zig-out/bin
    zig build interop              # only the four binaries the QUIC interop image ships
    zig build moq-interop          # only the MoQ interop client
    zig build fuzz

    tools/interop_local.sh         # 11 cases, quic-zig against itself, no docker
    interop/run_local_tests.sh     # 9 cases against quic-go and quiche binaries
    tools/moq_local.sh             # MoQ end-to-end, our binaries only, no docker
    tools/moq_interop.sh           # MoQ interop matrix -> SPEC/moq-interop-results.md
    tools/wt_protocol_test.mjs     # WebTransport protocol negotiation, via Chrome
    tools/bench_local.sh           # single-stream throughput + handshake rate

    interop/runner/build_image.sh      # QUIC interop image, cross-compile + package
    interop/moq-runner/build_image.sh  # MoQ interop client image
    interop/runner/matrix.sh           # full docker matrix, both peers
    interop/runner/report.py           # renders the SPEC table

`matrix.sh` appends a verdict per case to `interop/runner/matrix-results.txt`
and skips what is already there, so an interrupted run resumes. To re-run only
the failures: `grep -v FAIL matrix-results.txt > tmp && mv tmp matrix-results.txt`.
It needs `PYTHON=/opt/homebrew/bin/python3.12` (3.10+) and a
`quic-zig-interop:latest` image.

Peers for MoQ work: `cargo install moq-relay` gives a native lite-05 and
draft-17 relay (`moq-relay <config.toml>`, config shape in
`interop/moq-rs/demo/relay/localhost.toml` with `auth.public = ""`). The
`moqdev/moq-relay` Docker image is the same thing, but `matrix.sh` used to
`docker rm -f` every container on the machine and took it out twice; that
is now scoped to the runner's own three.

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

### draft-18, alongside draft-17

The runner targets draft-18 and draft-17 pairs with only four of its
eighteen relays, so both are implemented. Where they differ is one table,
`version.Rules` in `src/moq/version.zig`, rather than a condition per call
site; the draft travels with each message because a relay serves peers at
different ones, read off the ALPN each negotiated.

That meant fixing something underneath: a server matching a client's ALPN
never recorded *which* entry matched and echoed `config.alpn[0]`
regardless, so advertising two protocols told every client the first one.
`Connection.negotiatedAlpn()` is the accessor.

What of draft-18 is deliberately skipped is written down in
`SPEC/DRAFT_IETF_MOQ_TRANSPORT.md` — chiefly the relaxed varint, which
would need the draft threaded through every length and tuple read for one
byte on values almost nothing emits.

### The interop test client

`apps/moq_test_client.zig` drives the runner's seven control-plane cases
over either transport and reports TAP 14. `interop/moq-runner/` packages it
the way the runner expects — `RELAY_URL`/`TESTCASE`/`TLS_DISABLE_VERIFY`/
`VERBOSE`, uid 1000, `/mlog` — and it passes 7/7 against our own relay from
inside the container. `tools/moq_interop.sh` runs a relay list and writes
[`SPEC/moq-interop-results.md`](SPEC/moq-interop-results.md).

Registering it is not done and is your call: it means publishing an image
to GHCR and a PR against someone else's repo. The entry is written out in
`SPEC/moq-interop.md`.

### draft-17 control messages were wrong, and the client is how we found out

Most of them were encode-only. Their round-trip tests agreed with a shape
nobody else spoke, so they passed while being wrong. moq-rs rejected our
PUBLISH_NAMESPACE with "bounds exceeded"; that turned out to be the
smallest of it.

Against the draft's §9 figures: PUBLISH_NAMESPACE, SUBSCRIBE_NAMESPACE,
PUBLISH, REQUEST_UPDATE and FETCH were all missing Request ID and Required
Request ID Delta; GOAWAY was missing Timeout, REQUEST_ERROR its Retry
Interval, PUBLISH_DONE its Stream Count; FETCH had no Fetch Type and so no
joining form; FETCH_OK, PUBLISH_OK and PUBLISH_BLOCKED had invented bodies;
NAMESPACE_DONE carried nothing at all. The error code table was a
pre-draft-17 list, and mixed the session and request number spaces.

Message parameters now go through one codec with the §9.3 type table, so a
parameter's value shape comes from its type rather than from each call site.
The interop client went from 1/7 to 5/7 against moq-rs; the two it does not
pass are theirs — they hold a SUBSCRIBE for an unknown namespace open
instead of answering.

**If you take one thing from this: a round-trip test against your own
encoder proves self-consistency and nothing else.** The new tests assert
bytes against the draft figures where the shape is load-bearing.

### Our relay had the mirror-image bug

It answered SUBSCRIBE_OK to any namespace at all, because it created a
track on demand. §9.3.4 says a subscriber that sent no RENDEZVOUS_TIMEOUT —
the default is 0 — wants DOES_NOT_EXIST straight away, and one that sent a
non-zero timeout wants the subscription held until it expires and then
TIMEOUT. Both work now, and PUBLISH_NAMESPACE registers the prefix that
makes a later SUBSCRIBE legitimate. 7/7.

Two things fell out of making that work:

- The relay read each client's connection pointer on every poll to notice
  disconnects, but the loop frees the connection immediately after firing
  `onSessionClosed`, which the relay did not implement. Nothing crashed
  while clients only ever left voluntarily; a REQUEST_ERROR makes them
  leave promptly. Teardown moved into the callback.
- The loop armed no timer when QUIC had no deadline pending, so a handler
  with its own deadline was not woken until the peer sent something. A
  handler can now declare `poll_interval_ms`. This is also the cause of the
  sparse clock tick that was noted as a MoQ caveat.

### WebTransport application-protocol negotiation

`WT-Available-Protocols` / `WT-Protocol` on the extended CONNECT
(draft-ietf-webtrans-http3-13 §3.3). Both moq-lite and moq-transport ≥
draft-15 choose their wire version this way over WebTransport, so nothing
browser-facing worked without it. The headers were already on the
`WtEvent`; the event loop dropped them before the handler.

Checked against Chrome 146 rather than only against ourselves
(`tools/wt_protocol_test.mjs`): our own client agreeing with our own server
would have proved only that both share one reading of the grammar.

### moq-lite

`src/moq/lite/` — wire, messages, versions, session — plus `apps/moq_lite.zig`
with `publish`, `subscribe`, `announce` and `serve`. It is a different wire
format from the IETF draft, not a profile of it; most of all it uses the
QUIC varint where draft-17 uses a leading-ones one, so the two share no
primitives.

Verified against `moq-relay` v0.14.16: `moq-lite-05` negotiated on the
CONNECT, SETUP both ways, announce plane round-tripping, and the data plane
end to end — our publisher, their relay, our subscriber, ten frames with
the timestamps they were sent with.

`moq-lite-relay` is a relay: it learns what each session carries by being
a subscriber to it, routes a subscription upstream to the broadcast's
origin, and forwards the origin's group streams with the subscribe id
rewritten. Verified with a Zig publisher and the browser client as the
subscriber, so three implementations sit in the path.

Only lite-05 is implemented and the ALPN offer says so; lite-04 has no
Setup or Track stream, no ANNOUNCE_OK and a different SUBSCRIBE_OK body.
That is also why `moq-clock` cannot use our relay — it offers up to
lite-04 — and the cheapest way to widen that is lite-04 support rather
than anything structural.

### Datagrams

A `.quic` handler could not receive a QUIC datagram at all — the zero-copy
callback was installed only on the WebTransport path and `pollQuicEvents`
never drained the queue; `sendDatagram` was WebTransport-only for the same
reason. With that wired, MoQ datagram objects (§10.3.1) work end to end:
`moq-client --mode publish --datagrams`, relayed to each subscriber with
the alias rewritten as for subgroup streams.

### Smaller, but worth knowing

- **Offer only the version you implement.** The WebTransport CONNECT
  advertised `moqt-18` next to `moqt-17`; the current moq-relay speaks up
  to draft-21, picks 18, and then every message is the wrong shape. The
  connection succeeds and only the MoQ on top of it goes quiet, which
  looks like anything but a version mismatch. Raw QUIC was fine because
  its ALPN carried one token. moq-lite had the same bug.
- `decodeSubscribe`/`decodePublish` returned a slice-of-slices into their
  own stack frame. Every relay SUBSCRIBE took that path.
- A peer's GroupOrder byte outside 0x00-0x02 reached `@enumFromInt` in four
  decoders — one byte, remote abort. Found by the randomized decoder sweep
  added to `src/fuzz.zig`; `-ffuzz` does not compile on Zig 0.16.0 (the
  errors are in `lib/compiler/test_runner.zig`), so the existing
  `testing.fuzz` targets only ever see their seed.
- `moq_relay.zig` indexed stream roles into a 256-entry array, so a
  long-lived connection stopped being able to tell a control stream from a
  subgroup header.
- `interop/browser/certs/server.crt` had expired, which fails every browser
  WebTransport test identically and looks like a protocol regression. Run
  `interop/browser/generate-cert.sh`; Chrome caps these at 14 days.

## Open, roughly in the order I would take them

### MoQ, from this session

**a. Register with the interop runner.** Needs your go-ahead: a GHCR image
and a PR against `englishm/moq-interop-runner`. Everything else is done and
the entry is written out in `SPEC/moq-interop.md`.

**b. The draft-18 corners that were skipped.** The relaxed varint,
`REQUEST_ERROR`'s `Redirect`, `REQUEST_OK`'s Track Properties,
delta-encoded FETCH object ids, the renamed timeout parameters. None are
exercised by the runner's cases, and each is listed in
`SPEC/DRAFT_IETF_MOQ_TRANSPORT.md`. draft-19 and -20 are another row in
`version.Rules` each.

**c. moq-lite over raw QUIC, and lite-04.** The relay and origin are
WebTransport-only; `moq-lite` the client does both. Supporting lite-04
would let `moq-clock` and the rest of the moq-dev tooling use our relay,
which is the widest external validation available for it.

**d. `cdn.moq.dev` is unreachable — no HelloRetryRequest.** Both transports
fail identically at TLS with `error.UnexpectedMessage`, before any MoQ.
Cloudflare's edge asks for HRR and `src/quic/tls13.zig` has no notion of
it. This blocks every public MoQ relay, and probably more than MoQ.

**e. A relay image for the runner.** `apps/moq_relay.zig` is raw-QUIC only
and the runner's compose defaults to `https://relay:4443`. The relay's 7/7
is over QUIC; the WebTransport relay (`moq_browser_server.zig`) has had
none of the conformance work.

### Carried over


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

### 3. Handshake retransmission under loss vs quiche
`quic-zig<-quiche handshakeloss` and `handshakecorruption`: quiche's client
finishes 11 of 50 handshakes and hits its own overall timeout. Note the PTO
probe fix above did not move these, and the quic-go equivalents all pass in
both directions. A local harness
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

- **This machine OOMs during a matrix run.** The harness kills the background
  task, but `matrix.sh` resumes from `matrix-results.txt`, so just run it
  again; a small wrapper loop that re-invokes it until the file has 88 lines
  gets through unattended. Dropping the Docker builder stage also freed 16.5 GB
  of now-dead BuildKit cache, which is worth pruning if it comes back.
- A `tshark` crash in the runner shows up as `ERROR` rather than `FAIL`. It is
  a harness casualty, not a result — delete the line and re-run that case.
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
