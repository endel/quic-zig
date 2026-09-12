# WebTransport conformance: one suite, two kinds of client

A single scenario list, run by the Zig client and by real browsers against the
same Zig server. The point is that our own client is held to the bar a browser
sets, and that a scenario cannot exist on one side only.

For which W3C features browsers expose and which of them the Zig client
implements, see [webtransport_w3c_api.md](webtransport_w3c_api.md).

## Running it

```bash
./tools/wt_conformance.sh                  # Zig client + Chrome
./tools/wt_conformance.sh --firefox        # ... and Firefox
./tools/wt_conformance.sh --safari         # ... and Safari
./tools/wt_conformance.sh --safari-preview # ... and Safari Technology Preview
./tools/wt_conformance.sh --zig-only       # no browser; this is what CI runs
```

The script regenerates the certificate if it is within a day of expiring,
builds, starts one `wpt-server`, and runs each client against it. Set
`RESULTS_DIR` to keep the logs somewhere you choose.

Prerequisites: Node 18+ with `npm install` done. Firefox needs
`npx puppeteer browsers install firefox` and `brew install nss` (for
`certutil`). Safari needs *Allow Remote Automation* in Safari → Settings →
Developer.

Safari Technology Preview is worth running whenever a Safari gap is in
question: it is the same engine some versions ahead, so a gap it has closed is
one to wait for rather than work around. It ships its own driver and its own
copy of the automation setting, so enable *Allow Remote Automation* in
**Technology Preview's** Settings → Developer as well — the runner uses
`Safari Technology Preview.app/Contents/MacOS/safaridriver` on port 9516 and
reports the driver's own message when the setting is off.

Preview deliberately starts with **no** `expect_fail` entries of its own: it
runs the same scenarios as `safari`, but looks up `expect_fail["safari-preview"]`
rather than inheriting the release browser's notes. A gap Preview has fixed
therefore shows up as `XPASS`, which is the signal worth having.

To run the scenarios by hand in a browser, serve the repo
(`node tools/coop_httpd.mjs . 8000`) and open
`http://127.0.0.1:8000/interop/browser/wpt-tests.html`.

## How the two sides stay in step

```
interop/conformance/scenarios.json     the list: id, handler path, what it exercises,
          │                             who runs it, and any expected failures
          ├──────────────┬──────────────────────────────┐
          ▼              ▼                              ▼
   bodies.mjs      apps/wpt_client.zig          apps/wpt_server.zig
   (browser)       (Zig, one fn per id)         routes by CONNECT path
          │              │                              ▲
          └──────────────┴──────────────────────────────┘
                    both connect here
```

Each runner checks at startup that its set of implemented ids **equals** the
manifest's, and refuses to run otherwise. Adding a scenario to one side and
forgetting the other is then a startup error rather than a quietly smaller
suite — which is exactly how the two previous copies of the browser list drifted
apart.

`expect_fail` records a known failure against a runner, with the reason. Such a
scenario reports `XFAIL` and does not fail the run; one that *starts passing*
reports `XPASS` and **does** fail it, so a stale note gets noticed instead of
outliving the bug it describes.

The handler paths mirror the Python handlers in
[web-platform-tests/wpt/webtransport/handlers][wpt], so the lineage stays
legible; `apps/wpt_server.zig` implements them in Zig.

[wpt]: https://github.com/web-platform-tests/wpt/tree/master/webtransport/handlers

## Results

September 2026. Chrome 146, Firefox 148, Safari 26.4, Safari Technology
Preview 27.0. Four Safari runs and three Preview runs, because a single Safari
run is weak evidence either way — see *Flakiness*.
✓ pass · ✗ fail · ~ expected failure (reason recorded in the manifest).

| Scenario | Zig | Chrome | Firefox | Safari&nbsp;26.4 | STP&nbsp;27.0 |
|---|:--:|:--:|:--:|:--:|:--:|
| connect-echo | ✓ | ✓ | ✓ | ✓ | ✓ |
| client-close-code | ✓ | ✓ | ✓ | ✓ | ✓ |
| server-close-code0 | ✓ | ✓ | ✓ | ✓ | ✓ |
| server-close-code42 | ✓ | ✓ | ✓ | ✓ | ✓ |
| server-close-code3999 | ✓ | ✓ | ✓ | ✓ | ✓ |
| server-connection-close | ✓ | ✓ | ✓ | ✓* | ✓* |
| bidi-echo-small | ✓ | ✓ | ✓ | ✓ | ✓ |
| bidi-echo-3-streams | ✓ | ✓ | ✓ | ✓ | ✓ |
| bidi-echo-64kb | ✓ | ✓ | ✓ | ✓ | ✓ |
| uni-echo | ✓ | ✓ | ✓ | ✓ | ✓ |
| uni-echo-64kb | ✓ | ✓ | ✓ | ✓ | ✓ |
| uni-multiple-streams | ✓ | ✓ | ~ | ✓ | ✓ |
| datagram-echo | ✓ | ✓ | ✓ | ✓ | ✓ |
| datagram-maxsize | ✓ | ✓ | ✓ | ✓ | ✓ |
| datagram-length-echo | ✓ | ✓ | ✓ | ~ | ✓ |
| server-abort-stream | ✓ | ✓ | ✓ | ✓ | ✓ |
| client-abort-stream | ✓ | ✓ | ✓ | ✓ | ✓ |
| server-stop-sending | ✓ | ✓ | ✓ | ✓* | ✓* |
| server-drain | ✓ | n/a | ✓ | ✓ | ~ |
| wt-protocol-negotiation | ✓ | ✓ | ~ | ✓ | ✓ |
| **Total** | **20/20** | **19/19** | **18/18 + 2~** | **18-19/19 + 1~** | **17-19/19 + 1~** |

\* Passed in some runs and failed in others against an unchanged server — see
*Flakiness* below. `server-stop-sending` is a coin flip under both Safari
builds; the others moved once each.

`server-drain` is not run under Chrome: `WebTransport.draining` lands in Firefox
155 and Safari 26.4 and does not exist in Chrome at all.

### What changed for Safari

Safari went from 8-10 passing with ten expected failures to this. Nine of those
ten expectations are gone, and what closed them was two things:

- **draft-13 session flow control.** Safari 26.4 advertises `WT_MAX_SESSIONS`
  on the draft-13 codepoint and opens no client-initiated stream until it has
  been granted credit for one. It never sent a `WT_STREAMS_BLOCKED` to say so,
  which is what made this look like a framing problem for months. The capsule
  family is now implemented — see
  [DRAFT_IETF_WEBTRANS_HTTP3_13.md](DRAFT_IETF_WEBTRANS_HTTP3_13.md), which
  also explains why the matching SETTINGS are *not* advertised: Safari refuses
  the session outright when it sees them.
- **A receive buffer smaller than the path MTU.** The two 64 KB scenarios
  failed for a reason of their own: Safari fills the loopback MTU with 3-16 KB
  datagrams, the receive buffer was 8 KB, and a truncated datagram fails AEAD
  authentication. It read as `ChaCha20-Poly1305 decryption failed` on exactly
  the packets carrying the start of the stream, which then never arrived.

Neither was visible through Chrome or Firefox: both send the pre-draft-13
settings, so none of the flow-control family applies to them, and neither
exceeds 8 KB per datagram.

### What Technology Preview changes

STP 27.0 differs from release 26.4 in three places, and only one of them is an
improvement:

- **`datagram-length-echo` is fixed.** 26.4 reports `maxDatagramSize` as the
  QUIC `max_datagram_frame_size` (65535) and then refuses to send one that
  large. Preview reports 1024, matching Chrome, and the scenario passes.
- **`server-drain` regressed.** Preview never resolves `WebTransport.draining`
  on a `WT_DRAIN_SESSION` capsule — every run of four — where release 26.4
  resolves it against the same server in every run. This is the one stable
  Preview gap, and the only one still marked `expect_fail`.
- **`server-connection-close` half-regressed.** Preview rejects
  `new WebTransport()` with a `WebTransportError` before the session is
  established, where 26.4 establishes it and reports the abrupt close — but
  only in three runs of five. Not marked, for the same reason as
  `server-stop-sending` below.

Both regressions are worth reporting to WebKit alongside the
`server-stop-sending` behaviour below.

### What the expected failures mean

**Safari, `datagram-length-echo`.** Safari 26.4 reports `maxDatagramSize` as the
QUIC `max_datagram_frame_size` (65535) rather than anything derived from the
path MTU, then refuses to send a datagram that large. Chrome reports 1024 and
the Zig client 1199. Preview has fixed it.

**Preview, `server-drain`.** Described above; the one stable Preview gap.

**Firefox, `uni-multiple-streams`.** Firefox 148 surfaces only 2 of the 5 server
uni streams. Chrome and the Zig client receive all five from the same server,
and Firefox granted `max_uni=100`, so this is not stream credit. Firefox 155 may
fix it; re-run when it is the installed version.

**Firefox, `wt-protocol-negotiation`.** `WebTransport.protocol` lands in Firefox
155; 148 leaves it `undefined`.

### Flakiness worth knowing about

**`server-stop-sending` under Safari is a coin flip** — three passes and three
failures over six runs on 26.4, one pass in three on Preview. When it fails, the
server's STOP_SENDING did arrive and Safari stopped sending within a few
kilobytes of it; what never happens is the `writable` promise settling, so the
scenario waits out its eight seconds. Safari also reports `streamErrorCode` as
`undefined` on the runs where it does reject. Neither half is ours: the code
reaches the peer, and the peer decides what to do with it. It is deliberately
*not* marked `expect_fail`, because a note that is right half the time turns
into an `XPASS` failure the other half.

**Safari's results move between runs** more generally. `server-connection-close`
failed in one run of four on 26.4 and passed in the rest, and on Preview it goes
the other way three runs in five. Treat a single Safari run as weak evidence, and
prefer the Zig and Chrome columns when deciding whether something we changed is
at fault.

**`server-stop-sending` is a race in the scenario, not only in Safari.** Firefox
failed it once in three with `writes kept succeeding after STOP_SENDING`: the
body writes 800 KB expecting the server's STOP_SENDING to land mid-loop, and
over loopback the loop sometimes wins. Chrome and Firefox each also show an
occasional one-off timeout (`client-close-code`, `client-abort-stream` have both
done it once) that does not reproduce. The suite does not retry, so a lone red
cell in an otherwise green column is worth re-running before investigating.

`safaridriver` itself wedges from time to time — it stops answering, or reports
"already paired with another WebDriver session" for every remaining scenario,
which is a harness casualty rather than a result. Every WebDriver call is
bounded and returns null rather than throwing, so a stuck scenario costs one
result instead of aborting the rest of the run; if the driver exits outright the
runner says so and stops.

## Adding a scenario

1. Add an entry to `interop/conformance/scenarios.json` — `id`, `handler`,
   `title`, `exercises`, and the `runners` that have the API for it.
2. Add the body to `interop/conformance/bodies.mjs` under the same id.
3. Add an enum member and a case to `apps/wpt_client.zig` (`Scenario`,
   `handlerFor`, `onSessionReady`, and `evaluate` if the verdict depends on what
   arrives).
4. If it needs new server behaviour, extend `apps/wpt_server.zig`: the `Handler`
   enum, `parseHandler`, and the startup routing table.

Skipping step 2 or 3 makes that runner refuse to start, which is the point.

### Two traps worth knowing

**Resetting a stream races its own delivery.** RESET_STREAM lets the peer
discard everything it has buffered, so a stream reset before the peer has
acknowledged the header may never be surfaced to the application at all — it
simply never hears about the stream. Chrome does exactly this. Both the
`abort-stream-from-server` handler and the Zig `client-abort-stream` scenario
wait for an acknowledgement (`getSendStreamStats(id).bytes_acknowledged > 0`)
before resetting.

**Session ids restart at 0 on every connection.** They are not a name. The
runners leave the previous scenario's connection draining while the next one
starts, so two live connections both have a session 0 — `apps/wpt_server.zig`
keys its per-session state by `(connection, id)`. Keying by id alone had one
connection's poll consuming the other's deferred action, which looked exactly
like a client bug.
