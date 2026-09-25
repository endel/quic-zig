# RFC 6455 — The WebSocket Protocol (server)

## Status: ✅ Server side complete, without extensions

WebSockets over HTTP/1.1, on the same port and event loop as QUIC. A handler
serves WebTransport sessions and WebSockets side by side: all its callbacks
run on the loop's thread, so one set of room state needs no locks. The
motivating user is netcode, which falls back to WebSocket for browsers and
networks where WebTransport isn't available.

Autobahn testsuite (fuzzingclient, 25 Sep 2026), `ws://` and `wss://`,
macOS (kqueue) and Linux (epoll): 301 cases, **298 OK, 3 INFORMATIONAL, 0
NON-STRICT, 0 FAILED**. The informational ones (7.1.6, 7.13.1, 7.13.2) are
not scored. Cases 12 and 13 (permessage-deflate) are excluded, since the
extension isn't implemented. `tools/autobahn.sh` reruns it, and CI runs it
on every push.

For comparison, the report µWebSockets links for its "perfect score" has the
same 3 INFORMATIONAL, 11 NON-STRICT (3.2, 3.3, 4.1.3, 4.1.4, 4.2.3, 4.2.4,
5.15, 6.4.1–6.4.4), and passes 12 and 13 with compression on.

## Files

| File | What |
|---|---|
| `src/http1/websocket.zig` | Sans-IO codec: handshake checks, `acceptKey`, frame parser, `Decoder` (reassembly, control frames, UTF-8, close codes), frame header encoder |
| `src/http1/parser.zig` | HTTP/1.1 request heads, ported from routez, keeping its request-smuggling checks |
| `src/http1/conn.zig` | One TCP connection: TLS or plain, request heads, static files, the upgrade, the open WebSocket (`WsConn`, `WsRequest`) |
| `src/http1/server.zig` | The listener: accept on the loop, connection list, `drain` / `stop`, `handlersFor` |
| `src/http1/socket.zig`, `timers.zig` | Non-blocking TCP on libxev and coarse deadlines, trimmed ports of routez's |
| `src/http1/e2e_test.zig` | End-to-end tests against `event_loop.Server`, plain and TLS, WebTransport next to WebSocket |
| `apps/ws_echo_server.zig` | WebSocket and WebTransport echo from one handler; the Autobahn target |

## API

Enable the listener with `Config.http1`, then give the handler:

```zig
pub fn onWsUpgrade(self: *H, req: *event_loop.WsRequest, path: []const u8) void
pub fn onWsMessage(self: *H, ws: *event_loop.WsConn, data: []const u8) void
pub fn onWsMessage(self: *H, ws: *event_loop.WsConn, data: []const u8, kind: event_loop.WsMessageKind) void
pub fn onWsClose(self: *H, ws: *event_loop.WsConn, code: u16, reason: []const u8) void
```

- `path` is the request target, query string included.
- `req.accept(.{ .protocol, .headers })` answers 101 and returns the
  `*WsConn`. `req.reject(status)` answers with an HTTP error. A request the
  handler leaves undecided gets 403.
- `WsConn` has `id()`, `send`, `sendText`, `close(code, reason)`,
  `bufferedAmount()` and `peerAddress()`. `id()` comes from the counter
  behind `Session.id()`.
- `onWsClose` fires exactly once for every accepted WebSocket:
  - with the peer's code, or 1005 when its Close carried none;
  - with 1006 when there was no Close frame at all (a TCP reset, a TLS
    failure, a silent peer), or when the peer didn't answer our Close
    within 5 s;
  - with 1001 on `Server.stop()`;
  - with 1002 / 1007 / 1009 when the peer broke the protocol.
- `onWsClose` never fires from inside a `WsConn` method.
- `data` and `req` are valid only during their callback.

`README.md` ("HTTP/1.1 listener: static files and WebSockets") has the
config table.

## Section by section

| § | Section | Status | Notes |
|---|---------|--------|-------|
| 4.2.1 | Reading the client's opening handshake | ✅ | GET, HTTP/1.1, `Upgrade: websocket`, `Connection: upgrade` (as a token), a Sec-WebSocket-Key that decodes to 16 bytes. Anything else gets 400 |
| 4.2.2 | Sending the server's opening handshake | ✅ | `Sec-WebSocket-Accept`, and an optional subprotocol that must be one the client offered. No extension is ever accepted |
| 4.4 | Supporting multiple versions | ✅ | Anything but 13 gets `426` with `Sec-WebSocket-Version: 13` |
| 5.1–5.3 | Framing, client-to-server masking | ✅ | An unmasked client frame gets 1002. 7-, 16- and 64-bit lengths; a 64-bit length with its top bit set gets 1002. Unmasking works 16 bytes at a time |
| 5.4 | Fragmentation | ✅ | Reassembled up to `max_message_size`, which is checked against each frame header, so an oversized frame is refused (1009) before its payload is buffered. Control frames may come between fragments |
| 5.5 | Control frames | ✅ | Ping gets a pong. Close is echoed with the peer's code, then TCP is closed by the server. A control frame over 125 bytes, or fragmented, gets 1002 |
| 5.6 | Data frames | ✅ | Text must be UTF-8 (otherwise 1007). Surrogates are rejected |
| 8.1 | Invalid UTF-8, fail fast | ✅ | Checked as bytes arrive, across fragments and inside a frame still coming in: the first byte no valid text can continue with fails the connection |
| 5.8 | Extensibility | ✅ | An RSV bit or a reserved opcode gets 1002 |
| 7 | Closing the connection | ✅ | Close handshake in both directions. Our `close()` waits 5 s for the peer's Close. A peer that goes quiet is pinged after `ping_interval_ms` and dropped after twice that (1006) |
| 7.4 | Status codes | ✅ | Received codes are checked: 1000–1003, 1007–1014 and 3000–4999 are accepted, anything else gets 1002. `close()` sends 1000 in place of a code the peer may not receive |
| 9 / RFC 7692 | Extensions, permessage-deflate | ❌ | Not implemented. Browsers offer it and carry on without it |
| RFC 8441 / 9220 | WebSockets over HTTP/2 or HTTP/3 | ❌ | Not implemented. Browsers use HTTP/1.1 for `wss://` when a server offers nothing else |

## Caveats

- **Frames are decoded whole, where they arrive.** Input is parsed in the
  socket's read buffer (256 KiB, one per thread on epoll; 16 KiB per socket
  on kqueue) or in TLS's plaintext buffer, and a single-frame message is
  handed out as a slice of it. Only the tail of a frame that hasn't finished
  arriving is copied into the connection's own buffer, which can therefore
  grow to one frame, up to `max_message_size` plus 14 bytes. Text is still
  checked as it arrives: the part of a frame already in is unmasked into a
  scratch buffer and checked (`Utf8Stream`), so bad UTF-8 fails at once,
  and no byte is checked twice.
- **The send buffer is bounded.** `WsConn.send` refuses to queue more than
  `max_send_buffer` bytes (`error.SendBufferFull`) and queues nothing when
  it refuses. What to do with a slow peer is the application's decision.
- **Origin isn't checked.** `onWsUpgrade` can read it with
  `req.header("origin")`. A server that authenticates by cookie must check
  it (RFC 6455 §10.2).
- **Request bodies are refused.** The listener serves GET and HEAD for
  static files. A request with a body gets 400, and other methods get 405.
- **Server only.** There is no WebSocket client.

## Replacing the blocking HTTP/1.1 server

`Config.http1` used to start a thread that served one connection at a time,
over a blocking TLS layer that only took the legacy single ECDSA
certificate. That server is gone. The listener now runs on the server's
loop:

- TLS comes from `tls/server.zig`, so it has the QUIC side's certificates:
  SNI, RSA, Ed25519, and client authentication.
- It has keep-alive and pipelining, and serves `index.html` for directory
  paths.
- It can run in plain text (`tls = false`).
- It binds the UDP socket's address family, so `ipv6 = true` is
  dual-stack. The old server was IPv4 only.
- It joins `reuse_port`.
- `drain()` and `stop()` cover it.

Session tickets use a key of the listener's own, so a QUIC ticket can't
resume a TCP session.

## Running Autobahn

```sh
./tools/autobahn.sh          # ws://
./tools/autobahn.sh --tls    # wss://
```

It needs Docker. It builds `ws-echo-server` (ReleaseSafe), runs the pinned
`crossbario/autobahn-testsuite` image against it, and fails unless all 301
cases ran and each is OK or INFORMATIONAL. `$RESULTS_DIR/reports/index.html`
has the per-case report.

On macOS, Docker Desktop's host proxy sometimes stops forwarding new
connections partway through a run: wstest reports "User timeout caused
connection failure" and exits 0. Node's `ws` server hits the same thing in 3
runs out of 5, so it isn't the server. The script checks the case count and
retries such a run up to three times. On Linux the container shares the
host's network, and the proxy isn't involved.
