# MoQ Interop Runner Integration

Reference: <https://github.com/englishm/moq-interop-runner>

Not to be confused with `SPEC/interop.md`, which covers the QUIC interop
runner. The two share no conventions: this one has no network simulator, no
pcap capture, and none of `ROLE` / `REQUESTS` / `SSLKEYLOGFILE` / `QLOGDIR`.

## Architecture

Bash + jq + Docker Compose. The matrix is **test-client × relay**: a client
container drives every connection a test needs, including both legs of the
two-connection cases, and reports the verdicts. A nightly cron publishes to
<https://englishm.github.io/moq-interop-runner/>.

An implementation participates as a client, as a relay, or both. A relay
can be a Docker image or just a public URL.

## Test client contract

| Env | Meaning |
|---|---|
| `RELAY_URL` | Relay locator; the scheme selects the transport |
| `TESTCASE` | One test name, or unset/empty for all |
| `TLS_DISABLE_VERIFY` | `1` to skip certificate verification |
| `VERBOSE` | `1` for diagnostics on stderr |

CLI: `--relay URL`, `--test NAME`, `--list`, `--verbose`,
`--tls-disable-verify`, `--draft 17|18`. Flags win over env.

The runner has no way to ask for a draft — a pair negotiates whatever it
negotiates — so `--draft` is ours, for running the matrix at each.

Output is **TAP version 14 on stdout** and nothing else:

```
TAP version 14
# moq-test-client v0.1.0
# Relay: moqt://127.0.0.1:4455/
# Draft: draft-17
1..7
ok 1 - setup-only
  ---
  duration_ms: 16
  implementation_version: "quic-zig/0.1.0"
  sessions:
    client:
      moqt_version: "moqt-17"
      transport: "quic"
  ...
not ok 4 - subscribe-error
  ---
  message: "received SUBSCRIBE_OK instead of REQUEST_ERROR"
  ...
```

`--list` prints one test name per line — not TAP. Exit codes: `0` all
passed, `1` one or more failed, `127` unsupported. A test that is not
implemented is `ok N - name # SKIP reason`, which counts separately from
both passes and failures.

## Test cases

All seven are control-plane; there is no data-plane case yet. Namespace
`moq-test/interop`, track `test-track`, both fixed by the spec.

| Test | What it does | Passes when |
|---|---|---|
| `setup-only` | SETUP both ways, then close | peer SETUP arrives, clean close |
| `announce-only` | PUBLISH_NAMESPACE | REQUEST_OK |
| `publish-namespace-done` | as above, then cancel the request stream with `CANCELLED` (0x1) | REQUEST_OK, clean cancel |
| `subscribe-error` | SUBSCRIBE `nonexistent/namespace` | REQUEST_ERROR |
| `rendezvous-timeout` | SUBSCRIBE `nonexistent/rendezvous` with `RENDEZVOUS_TIMEOUT` 500 ms | REQUEST_ERROR with code `TIMEOUT` |
| `announce-subscribe` | publisher announces, then a second connection subscribes | SUBSCRIBE_OK |
| `subscribe-before-announce` | subscriber first, publisher 500 ms later | SUBSCRIBE_OK **or** REQUEST_ERROR |

Timeouts 2 s, except `announce-subscribe` (3 s) and
`subscribe-before-announce` (3.5 s).

The runner's own spec cites `RENDEZVOUS_TIMEOUT` as draft-18 §10.2.6, which
reads as though draft-17 cannot run that case. It can: the parameter is
§9.3.4 in draft-17, type `0x04`, and "if RENDEZVOUS_TIMEOUT is absent, the
default is 0", which is what makes `subscribe-error` expect an immediate
`DOES_NOT_EXIST` rather than an open subscription.

`moq-relay` answers that case with `REQUEST_ERROR` code `404`, which is not
in either draft's error table. It is the one case it does not pass.

## Relay contract

`MOQT_ROLE=relay`, `MOQT_PORT=4443`, certs at `/certs/cert.pem` and
`/certs/priv.key`, logs under `/mlog`, `EXPOSE 4443/udp`, running as uid
1000. The compose file defaults `RELAY_URL=https://relay:4443`, so a relay
entry has to speak WebTransport.

We do not ship a relay image yet — `apps/moq_relay.zig` is raw-QUIC only.

## URL schemes

`https://` is WebTransport and `moqt://` is native QUIC. draft-18 §3.1
makes `moqt://` canonical for both, with the transport chosen by the ALPN
offer and the https URI derived for the CONNECT; the runner still accepts
`https://` as a legacy WebTransport locator. `src/moq/url.zig` takes both.

## Running it here

```sh
zig build

# One relay, one case, verbose.
zig-out/bin/moq-test-client --relay moqt://127.0.0.1:4455/ \
    --test setup-only --verbose --tls-disable-verify

# The local matrix at both drafts, written to SPEC/moq-interop-results.md.
tools/moq_interop.sh
DRAFTS=18 tools/moq_interop.sh         # just one
PUBLIC=1 tools/moq_interop.sh          # also cdn.moq.dev

# The container the runner would pull.
interop/moq-runner/build_image.sh
docker run --rm -e RELAY_URL=moqt://host.docker.internal:4455/ \
    -e TLS_DISABLE_VERIFY=1 quic-zig-moq-client:latest
```

Peers to test against:

| Peer | How |
|---|---|
| our relay | `zig build run-moq-relay -- --port 4455` |
| moq-rs (draft-17) | `cargo install moq-relay`, then `moq-relay <config.toml>` |
| `cdn.moq.dev` | public; currently unreachable — see below |

## Registering with the runner

Not done, and it needs a decision that is not ours to make: it means
publishing an image to GHCR and opening a PR against
`englishm/moq-interop-runner`. The entry would be:

```json
"quic-zig": {
  "name": "quic-zig",
  "organization": "Endel Dreyer",
  "repository": "https://github.com/endel/quic-zig",
  "draft_versions": ["draft-17", "draft-18"],
  "roles": {
    "client": { "docker": { "image": "ghcr.io/<owner>/quic-zig-moq-client:latest" } }
  }
}
```

Both drafts are implemented, so `draft_versions` would be
`["draft-17", "draft-18"]`. draft-18 is the runner's `current_target` and
pairs with most of its eighteen relays; draft-17 with four.

## Known blockers

- **`cdn.moq.dev` does not complete a TLS handshake.** Both transports fail
  identically with `error.UnexpectedMessage`, before any MoQ is exchanged.
  Our TLS 1.3 implements no HelloRetryRequest, which Cloudflare's edge asks
  for. This is a QUIC-layer gap, not a MoQ one.
