# API Polish v1 — Handler Validation & Graceful Shutdown

**Date:** 2026-03-15

## Changes

### 1. Compile-time Handler Validation (`src/event_loop.zig`)

A `comptime` block at the top of `Server(Handler)` checks:

1. **`protocol` required** — `@compileError` if Handler doesn't declare it.
2. **Typo detection** — Any `pub fn on*` that isn't in the known callback set
   triggers a `@compileError` listing all valid callbacks.
3. **`onStreamData` signature** — Must have 4 params (without `fin`) or 5
   params (with `fin`).

Known callback set:
```
onRequest, onData, onConnectRequest, onSessionReady, onStreamData,
onDatagram, onSessionClosed, onSessionDraining, onBidiStream,
onUniStream, onPollComplete, onH0Request, onH0Data, onH0Finished
```

Only methods starting with `on` are checked. User helpers like `formatResponse`
are allowed freely. The known set must be updated when adding new event types
(which already requires changes to `event_loop.zig`).

Example error when `onRequest` is misspelled as `onReqest`:
```
error: Handler has unrecognized callback 'onReqest'. Known callbacks: onRequest, ...
```

### 2. Graceful Shutdown (`src/event_loop.zig`)

New `stop()` method on `Server`:

```zig
server.stop();
// run() returns after all connections drain
```

How it works:
1. `stop()` sets `stopping = true` and calls `close(0, "server shutdown")`
   on every active connection.
2. `onReadable` and `onTimer` check `stopping && allConnectionsClosed()` after
   processing. When true, they call `loop.stop()` and return `.disarm`.
3. The xev loop exits, `run()` returns.

Connections in `.draining` state take up to 3xPTO to terminate (RFC 9000
requirement). For immediate exit, call `deinit()` directly.

## Breaking Changes

None. All changes are additive.

## Testing

- All 431 tests pass.
- All build targets compile.
- Comptime validation verified: `onReqest` typo produces clear error.
