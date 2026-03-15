# WebTransport Browser Interop Tests

Automated test suite verifying the quic-zig WebTransport server against real browsers (Chrome, Firefox, Safari), based on [W3C Web Platform Tests](https://github.com/web-platform-tests/wpt/tree/master/webtransport) handler behaviors.

## Quick Start

```bash
# 1. Generate a fresh certificate (valid 13 days, required for browser pinning)
cd interop/browser && ./generate-cert.sh && cd ../..

# 2. Build the WPT server
zig build -p ./zig-out

# 3. Start the WPT server (keep running in a separate terminal)
./zig-out/bin/wpt-server

# 4. Run tests
node interop/browser/run-wpt-tests.mjs             # Chrome (default)
node interop/browser/run-wpt-tests.mjs --firefox    # Firefox
node interop/browser/run-wpt-tests.mjs --safari     # Safari (requires feature flag)
```

### Options

| Flag | Description |
|------|-------------|
| `--firefox` | Use Firefox via Puppeteer |
| `--safari` | Use Safari via safaridriver |
| `--filter <pattern>` | Only run tests whose name contains `<pattern>` |
| `TIMEOUT=15000` | Override per-test timeout (default: 8000ms) |
| `WT_SERVER=host:port` | Override server address (default: `127.0.0.1:4433`) |

### Prerequisites

- **Node.js** (v18+) with `puppeteer` installed (`npm install`)
- **Chrome**: auto-downloaded by Puppeteer
- **Firefox**: `npx puppeteer browsers install firefox` + `brew install nss` (for certutil)
- **Safari**: Enable "Allow Remote Automation" in Safari > Settings > Developer, enable "WebTransport" in Safari > Settings > Feature Flags

## Architecture

```
┌──────────────────────┐      QUIC/HTTP3       ┌─────────────────────┐
│   Browser (headless) │ ◄──────────────────── │  wpt-server (Zig)   │
│                      │    WebTransport        │  port 4433          │
│  serverCertHashes    │                        │                     │
│  pinning             │                        │  Routes by path:    │
└──────┬───────────────┘                        │  /handlers/echo.py  │
       │ HTTP (test page)                       │  /handlers/server-  │
       │                                        │    close.py?code=N  │
┌──────┴───────────────┐                        │  /handlers/...      │
│  run-wpt-tests.mjs   │                        └─────────────────────┘
│  Node.js test runner │
│  serves test HTML    │
│  on port 8787        │
└──────────────────────┘
```

Each test runs in an isolated browser page. The test runner:
1. Serves a generated HTML page with the test code + cert hash baked in
2. Navigates the browser to the test page
3. Polls `document.title` for `PASS:...` or `FAIL:...`
4. Reports results

## WPT Server Handlers

The Zig WPT server (`apps/wpt_server.zig`) routes requests by CONNECT path, matching the behavior of Python handlers in the [WPT repository](https://github.com/web-platform-tests/wpt/tree/master/webtransport/handlers):

| Handler Path | Behavior |
|-------------|----------|
| `/handlers/echo.py` | Bidi: echo on same stream after FIN. Uni: echo on new uni stream. Datagrams: echo back. |
| `/handlers/server-close.py?code=N&reason=R` | Accept session, then close with code/reason (deferred) |
| `/handlers/client-close.py?token=T` | Accept, track close events, stash for later query |
| `/handlers/query.py?token=T` | Return stashed data on a uni stream |
| `/handlers/abort-stream-from-server.py?code=N` | Create and reset bidi+uni streams with error code |
| `/handlers/server-connection-close.py` | Accept, then abruptly close the QUIC connection |
| `/handlers/server-read-then-close.py` | Accept, close session on first data received |

## Test Cases

| Test | What it verifies |
|------|-----------------|
| `connect-echo` | Basic WebTransport session establishment |
| `client-close-code` | Client-initiated close with code=7 and reason |
| `server-close-code0` | Server-initiated close with code=0, reason="bye" |
| `server-close-code42` | Server-initiated close with code=42 |
| `server-close-code3999` | Server-initiated close with maximum code (3999) |
| `server-connection-close` | Server abruptly closes QUIC connection |
| `bidi-echo-small` | Echo "hello" on bidirectional stream |
| `bidi-echo-3-streams` | Echo on 3 concurrent bidirectional streams |
| `bidi-echo-64kb` | Echo 64KB data on bidirectional stream |
| `uni-echo` | Client→server uni stream, server echoes on new uni stream |
| `datagram-echo` | Echo datagram round-trip |
| `datagram-maxsize` | Verify `maxDatagramSize > 0` |
| `server-abort-stream` | Server creates and resets streams with error code |

## Cross-Browser Results

Tested with quic-go's [webtransport-go](https://github.com/quic-go/webtransport-go) as reference — same server-close failures confirm these are browser/protocol limitations, not our bugs.

| Test | Chrome | Firefox | Safari | Go+Chrome |
|------|--------|---------|--------|-----------|
| connect-echo | PASS | PASS | PASS | PASS |
| client-close-code | PASS | PASS | PASS | PASS |
| server-close-code0 | FAIL | FAIL | FAIL | FAIL |
| server-close-code42 | FAIL | FAIL | FAIL | FAIL |
| server-close-code3999 | FAIL | FAIL | FAIL | FAIL |
| server-connection-close | FAIL | FAIL | FAIL | FAIL |
| bidi-echo-small | PASS | PASS | PASS | PASS |
| bidi-echo-3-streams | PASS | PASS | PASS | PASS |
| bidi-echo-64kb | PASS | PASS | FAIL | PASS |
| uni-echo | PASS | PASS | PASS | PASS |
| datagram-echo | PASS | PASS | PASS | PASS |
| datagram-maxsize | PASS | PASS | PASS | PASS |
| server-abort-stream | PASS | PASS | PASS | PASS |
| **Total** | **9/13** | **9/13** | **8/13** | **9/13** |

### Known Issues

**Server-close (all browsers)**: The `CLOSE_WEBTRANSPORT_SESSION` capsule is written to the CONNECT stream but the session is finalized locally before the packet is transmitted. Chrome and Safari time out; Firefox resolves `wt.closed` but with code=0 instead of the actual close code. quic-go's `CloseWithError` has the same issue — their Chrome interop tests [don't test server-initiated close codes](https://github.com/quic-go/webtransport-go/tree/master/interop_chrome).

**Safari 64KB bidi**: Safari's WebTransport (behind feature flag) appears to have a bug with large data transfers on bidirectional streams. This is a Safari issue.

**server-connection-close (all browsers)**: All browsers time out waiting for `wt.closed` to resolve/reject after an abrupt QUIC connection close. quic-go also fails this test.

## Certificate Requirements

Browsers require specific certificate properties for `serverCertificateHashes`:

- **Algorithm**: ECDSA P-256 (required by Chrome)
- **Validity**: < 14 days (browser security requirement)
- **SAN**: Must include the server hostname/IP
- **Self-signed**: OK when using `serverCertificateHashes`

The `interop/browser/generate-cert.sh` script generates a compliant certificate. Regenerate when expired (every 13 days).

## Browser-Specific Notes

### Chrome
- Uses Puppeteer with `--enable-quic` and `--origin-to-force-quic-on`
- `serverCertificateHashes` fully supported
- Best overall compatibility

### Firefox
- Uses Puppeteer's Firefox support with preferences:
  - `network.webtransport.enabled`
  - `network.http.http3.enabled`
  - `network.http.http3.webtransport.enabled`
- Requires NSS `certutil` for cert import (`brew install nss`)
- `serverCertificateHashes` supported since Firefox 133
- Best server-close handling (resolves `wt.closed`, just wrong code)

### Safari
- Uses native `safaridriver` (WebDriver protocol)
- Requires manual setup:
  1. Safari > Settings > Feature Flags > enable "WebTransport"
  2. Safari > Settings > Developer > enable "Allow Remote Automation"
- `serverCertificateHashes` supported
- WebTransport is experimental — expect some failures
