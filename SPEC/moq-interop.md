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
| `TLS_DISABLE_VERIFY` | `1` to skip certificate verification (the image defaults to `1`: every relay in the matrix is self-signed) |
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

Two cases `moq-relay` does not pass, both its side:

- `rendezvous-timeout`: it answers `REQUEST_ERROR` with code `404`, which
  is in neither draft's error table.
- `announce-subscribe`: it passes against a freshly started relay and fails
  once the earlier cases have run, so it is holding state from publishers
  that have since withdrawn or disconnected. Our relay passes it either
  way. The runner drives all seven against one relay in sequence, so this
  is the shape a real run would see.

Both are what the matrix is for, and the harness records them rather than
working around them.

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

# Our own binaries end to end: both drafts, streams, datagrams, moq-lite.
tools/moq_local.sh

# One relay, one case, verbose.
zig-out/bin/moq-test-client --relay moqt://127.0.0.1:4455/ \
    --test setup-only --verbose --tls-disable-verify

# The local matrix at both drafts, written to SPEC/moq-interop-results.md.
tools/moq_interop.sh
DRAFTS=18 tools/moq_interop.sh         # just one
PUBLIC=1 tools/moq_interop.sh          # also cdn.moq.dev

# The containers the runner would pull.
interop/moq-runner/build_image.sh        # client and relay images
docker run --rm -e RELAY_URL=moqt://host.docker.internal:4455/ \
    -e TLS_DISABLE_VERIFY=1 quic-zig-moq-client:latest

# Both sides containerised, the way compose runs them.
docker network create moqnet
docker run -d --rm --name relay --network moqnet \
    -v "$PWD/certs:/certs:ro" quic-zig-moq-relay:latest
docker run --rm --network moqnet \
    -e RELAY_URL=https://relay:4443/moq -e TLS_DISABLE_VERIFY=1 \
    quic-zig-moq-client:latest
```

Peers to test against:

| Peer | How |
|---|---|
| our relay | `zig build run-moq-relay -- --port 4455` |
| moq-rs (draft-17) | `cargo install moq-relay`, then `moq-relay <config.toml>` |
| `cdn.moq.dev` | public; reachable, certificate verifies |

## Registering with the runner

Both images publish to GHCR on every push to `main`
([`.github/workflows/docker.yml`](../.github/workflows/docker.yml)), as
`ghcr.io/endel/quic-zig-moq-client` and `…-moq-relay`. The entry to send is
[`interop/moq-runner/implementations-entry.json`](../interop/moq-runner/implementations-entry.json);
validate it against their `implementations.schema.json` first. Opening the PR
is what remains, and that is not ours to do.

Both packages came out public on first publish, inheriting the repository's
visibility — `docker manifest inspect` and `docker pull` both succeed with no
credentials. Worth re-checking if that ever changes: the runner cannot pull a
private image.

The images pass 7/7 against each other over a compose-style network, with
certificates generated exactly the way the runner's `generate-certs.sh` does.

Against the registry's eight public relays, through the runner's own harness:
three pass 7/7 both transports (moq-rs-draft-18, moqt-nr, moxygen), the rest
miss only `rendezvous-timeout`, and `moqt://cdn.moq.dev` does not speak IETF
draft-18 at all. Full table and the conformance question that accounts for
every remaining failure: [`moq-interop-results.md`](moq-interop-results.md).

**The relay needs an ECDSA P-256 key.** Our TLS signs with ECDSA P-256 or
Ed25519 and has no RSA signing path, so an RSA `priv.key` fails at startup
with `error: DecodeError` and nothing pairs. Both the SEC1 and PKCS#8
encodings are read. The runner generates P-256 — deliberately, so browsers
can pin the certificate by hash — so this costs nothing there; it is a trap
only when mounting certificates of your own.

Both drafts are implemented, so `draft_versions` would be
`["draft-17", "draft-18"]`. draft-18 is the runner's `current_target` and
pairs with most of its eighteen relays; draft-17 with four.

## Known blockers

- **(Cleared) `cdn.moq.dev` is reachable.** A full moq-lite session runs over
  both transports, with Cloudflare's certificate verified against the system
  trust store — hostname, every link's signature, CA:TRUE/keyCertSign,
  validity dates, and a trusted root.

  It used to fail outright, with `error.UnexpectedMessage` on both transports,
  and that was recorded here as a missing HelloRetryRequest. Two unrelated
  bugs, neither of them HRR:

  1. The message was a **CertificateRequest** (handshake type 13). Cloudflare's
     edge asks for a client certificate, and refusing to answer ended the
     handshake.
  2. Certificate validity was compared against `CLOCK_MONOTONIC`, so every
     real certificate read as not-yet-valid and no chain could ever verify.
  3. There was no trust store to root a chain in: `ca_cert_path` had done
     nothing but log a warning since the Zig 0.16 migration.

  We still implement no HelloRetryRequest — it would fail as `DecodeError`.
