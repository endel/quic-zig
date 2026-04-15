# Clock contract

quic-zig uses two clock sources internally. Most of the codebase reads
`std.time.nanoTimestamp()` (REALTIME); the user-space pacer is the single
exception — it runs on `CLOCK_MONOTONIC` via `clock.monoNanos()`.

This split is intentional. Reading this page once should be enough to avoid
introducing a cross-clock comparison bug on a future change.

## Who uses what

| Subsystem | Clock | Source | Why |
|-----------|-------|--------|-----|
| Loss detection (PTO, RTT) | REALTIME | `std.time.nanoTimestamp()` | Compares timestamps it produced itself; absolute drift is irrelevant. |
| Idle timeout | REALTIME | `std.time.nanoTimestamp()` | Same — only the delta `now − last_activity` matters. |
| Stateless reset / token expiry | REALTIME | `std.time.nanoTimestamp()` | Long-horizon validity windows; wall-clock alignment is fine. |
| qlog timestamps | REALTIME | `std.time.nanoTimestamp()` | Wall-clock is what humans expect when reading traces. |
| Datagram receive timestamps | REALTIME | `std.time.nanoTimestamp()` | Compared only to other REALTIME values within the same connection. |
| **Pacer** (`Pacer.last_sent_time`, `timeUntilSend`, `onPacketSent`) | **MONOTONIC** | `clock.monoNanos()` | Budget replenishment math (`elapsed = now − last_sent_time`) breaks if a wall-clock jump (NTP slew, manual time change, DST) makes elapsed go negative or huge. |

## The single boundary

`Connection.nextTimeoutNs()` is the only function that crosses the boundary.
It folds the pacer's next-send time into a deadline that the event loop
compares against REALTIME-based deadlines (loss timer, idle timer, ack alarm).

The conversion happens inline at `connection.zig:3793`:

```zig
const now_realtime: i64 = @intCast(std.time.nanoTimestamp());
const now_mono: i64 = clock.monoNanos();
const elapsed = now_mono - self.pacer.last_sent_time;     // duration on MONO
// ... compute pacer_delay (a duration, clock-agnostic) ...
const pacer_deadline = now_realtime + delay;              // anchor on REALTIME
```

We compute the *duration* on the monotonic clock (where the pacer's state
lives) and add it to a REALTIME `now` so the resulting deadline is comparable
to the other deadlines the event loop collects. The result is a REALTIME
timestamp, never a MONOTONIC one — that boundary stays inside this function.

## Rules for future changes

1. **Adding a new pacer call site:** pass `now_mono` (or call `clock.monoNanos()` fresh). Never pass a `nanoTimestamp()` value.
2. **Reading `pacer.last_sent_time` from outside the Pacer:** treat it as MONOTONIC. Subtract it from another MONOTONIC value to get a duration. Never compare to a REALTIME timestamp.
3. **Adding a new clock-using subsystem:** default to REALTIME. Switch to MONOTONIC only if the subsystem hands timestamps to the kernel (e.g., a future `SCM_TXTIME` cmsg) or is genuinely sensitive to wall-clock jumps.
4. **Mixing in a single deadline computation:** allowed only when computing a *duration* on one clock and anchoring the deadline on another (the `nextTimeoutNs` pattern above). Document why in a comment.

## Why not migrate everything to MONOTONIC

- Loss detection, PTO, and idle timeout are all *delta-based* — they don't care which clock as long as the timestamps in a single comparison agree. They've worked correctly on REALTIME since day one and changing them adds risk for no gain.
- qlog readers and external tooling expect wall-clock timestamps.
- Token-validity windows are conceptually wall-clock (a 1-day token means 24 wall-clock hours).
- The single subsystem that genuinely needed monotonic semantics (the pacer) is now isolated.

## Why the pacer specifically

- `Pacer.replenish` computes `elapsed = now - last_sent_time` and turns it into bytes of budget. If the wall clock jumps backward by 10 seconds (NTP slew, DST end, manual time change), `elapsed` goes negative and the pacer either refuses to send or floods, depending on signedness handling.
- A forward jump credits the pacer with phantom bandwidth, briefly defeating congestion control.
- `MONOTONIC` immunizes both directions.

## Files

- `src/quic/clock.zig` — defines `monoNanos()` (Linux/macOS via `clock_gettime`, Windows fallback to `nanoTimestamp()`).
- `src/quic/congestion.zig` — `Pacer` doc comment names the contract.
- `src/quic/connection.zig` — three pacer call sites in `send()` use `now_mono`; `nextTimeoutNs` handles the boundary conversion.
