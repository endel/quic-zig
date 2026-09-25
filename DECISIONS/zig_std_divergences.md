# Where we diverge from Zig's std

This page lists every place quic-zig copies, replaces or works around Zig
standard-library code. For each one it gives:

- what std does;
- what we do instead, and why;
- how to reproduce the numbers;
- whether Zig master still behaves the same way.

It exists for two uses. First, check it on every Zig upgrade, so we can delete
what upstream has fixed. Second, it is the material for raising these points
with the Zig project, which a person does, not an AI agent. See "Upstream
contributions" in `CLAUDE.md`.

- **Baseline:** Zig 0.16.0, the version this repo builds against.
- **Master:** each section says what Codeberg `ziglang/zig` master showed on
  24 Sep 2026, or the date it gives.
- **Benchmark hardware:** arm64 figures are native runs on an Apple M-series
  core. x86_64 figures ran under Rosetta in Docker Desktop. They are good for
  comparing one variant with another, not as absolute numbers. Confirm them on
  native x86 before raising anything upstream.

| # | Area | Our code | Kind | Upstream-worthy? |
|---|------|----------|------|------------------|
| 1 | GHASH aggregation threshold | `src/quic/ghash.zig` | vendored copy, one constant changed | yes: tuning |
| 2 | AES-GCM per-key setup | `src/quic/aes_gcm.zig` | API gap: no keyed AEAD context | yes: API |
| 3 | CTR mode tail (master regression) | `src/quic/aes_gcm.zig` (`ctr`) | kept 0.16's loop | yes: perf regression |
| 4 | RSA modular exponentiation | `src/quic/mont.zig` | narrow replacement for `std.crypto.ff` | maybe: design question |
| 5 | ECDSA signing without deriving the public key | `src/quic/tls13.zig` `signCertificateVerify` | relies on an internal detail | yes: API |
| 6 | DER element parsing bounds | `src/quic/tls13.zig` `certificateWellFormed` | guard in front of std | yes: robustness bug |
| 7 | `std.net.Address` | `src/sockaddr.zig` | adapted copy of 0.15.2 code | no: migration choice |
| 8 | Fixed-buffer reader/writer | `src/io_compat.zig` | kept our own stream | maybe: codegen observation |
| 9 | `std.http.Server.WebSocket` | `src/http1/websocket.zig` | replacement: sans-IO codec | maybe: API scope |

Not a std divergence, but related: std picks the AES and GHASH
implementation at **compile time** from the target's CPU features.
`-Dtarget=x86_64-linux-gnu` with no `-Dcpu` gets baseline x86_64, so AES-GCM
runs in software, about 35× slower (35 µs against 1.0 µs per 1200 B packet).
LLVM's `x86_64_v3` level does *not* include `aes` or `pclmul`. Our release
builds therefore pass `-Dcpu=x86_64_v3+aes+pclmul`; see
`.github/workflows/docker.yml`.

---

## 1. GHASH switches to 8-way aggregation too late for packets

**std** (`lib/std/crypto/ghash_polyval.zig`): `blocks()` chooses how many
blocks to fold per reduction from the message length. The thresholds are
`agg_4_threshold = 22`, `agg_8_threshold = 84` and `agg_16_threshold = 328`,
counted in 16-byte blocks. A QUIC packet is at most about 1500 bytes, 94
blocks. A typical full packet is 1200–1452 bytes, 75–91 blocks. So most
packets take the 4-way path.

**Ours:** `src/quic/ghash.zig` is the 0.16.0 file with two lines changed:
the `std` import, and `agg_8_threshold = 16`.

**Why:** GHASH is about two-thirds of AES-GCM's cost on a 1200-byte packet
(CTR 167 ns, GHASH 366 ns on arm64). Folding 8 blocks per reduction from 16
blocks up:

| 1200 B GHASH | threshold 84 (std) | threshold 16 | 16-way from 32 blocks too |
|---|---|---|---|
| arm64 (native) | 366 ns | 222 ns (−39%) | 214 ns |
| x86_64 (Rosetta) | 447 ns | 287 ns (−36%) | 301 ns |

Lowering the 16-way threshold as well bought nothing. Output is
byte-identical: the thresholds only change the order of the arithmetic, and
the differential test (below) checks every aggregation width.

**Open question for upstream:** 84 may be tuned for CPUs where carryless
multiply is slow (the file already uses Karatsuba on 32-bit x86 for that
reason). Native x86 data across a few microarchitectures would settle it.

**Master (24 Sep 2026):** still `agg_8_threshold = 84`. The only changes
since 0.16 are syntax: `.ReleaseSmall` became `.small`, and `@splat`.

## 2. std's AEAD API has no keyed context

**std** (`lib/std/crypto/aes_gcm.zig`): `encrypt` and `decrypt` take the raw
key on every call. Each call does `Aes.initEnc(key)` (key expansion), one
AES block to derive H, and `Ghash.initForBlockCount`, which computes powers
of H with carryless multiplies. For a transport protocol, one key protects
millions of messages, so this work repeats for nothing.

**Ours:** `src/quic/aes_gcm.zig` `Ctx` does that work once, in `init(key)`,
when the key is installed (`Open`/`Seal.prepareCtx()` in `crypto.zig`). The
per-message code is std's `encrypt`/`decrypt` line for line, starting from a
copy of the prepared GHASH state. The copy is about 300 bytes; we hold all
16 powers because that is what `Ghash.init` computes.

**Numbers** (`zig build bench-crypto -Doptimize=ReleaseFast`, 1200 B
packets, arm64). These include item 1:

| | std `Aes128Gcm` | `aes_gcm.Ctx` |
|---|---|---|
| encrypt | 607 ns | 455 ns |
| decrypt | 664 ns | 487 ns |

Caching alone, without item 1, was worth 2–10%. Most of the gain is the
GHASH threshold.

**Cost:** `Open`/`Seal` grew from about 288 to 784 bytes. We now pass them by
pointer through the packer and the receive path, which used to copy them per
packet.

**Upstream-shaped suggestion:** a keyed-context API along the lines of
`Aes128Gcm.init(key) -> Context` with `context.encrypt(...)` /
`context.decrypt(...)`. Other std primitives already split key setup from
use (`Aes128.initEnc`, `Ghash.init`); the AEAD wrappers are where that stops.

## 3. CTR mode on master is slower for short messages

**std 0.16** (`lib/std/crypto/modes.zig` `ctrSlice`):
- Full batches go through `xorWide`.
- Whole leftover blocks go through `xor` one at a time.
- A partial final block is padded.

**Master** (commit `e339566922`, "crypto.mode.ctr: make the counter wrap,
even in parallel updates", 29 May 2026):
- The counter wraps now. That part is a correctness fix we agree with.
- The tail changed: whatever is left after the full batches, even one byte,
  gets a full `encryptWide(parallel_count)` into a keystream buffer.
- That keystream is then XORed into the output one byte at a time.

**Numbers** (same message and key, 0.16 vs master's `ctr`, both compiled
with 0.16):

| | 64 B | 1200 B | 1450 B |
|---|---|---|---|
| arm64, 0.16 | 9 ns | 161 ns | 217 ns |
| arm64, master | 38 ns | 215 ns | 244 ns |
| x86_64 (Rosetta), 0.16 | 13 ns | 209 ns | 290 ns |
| x86_64 (Rosetta), master | 50 ns | 328 ns | 390 ns |

**Ours:** `aes_gcm.zig` carries 0.16's loop, with the batch increment made
wrapping (`+%=`) as master has it. That way moving to 0.17 does not slow
every packet down.

**Upstream-shaped report:** a performance regression for messages under a
few KB. A likely fix keeps the wrapping and restores block-sized tail
handling, or XORs the tail a word or vector at a time.

## 4. RSA modular exponentiation

**std** (`std.crypto.ff`): general-purpose modular arithmetic, with two costs
on this path:
- It uses 63-bit limbs, so a 1024-bit CRT half needs 17 limbs instead of 16.
- Unless `side_channels_mitigations` is `.none`, it builds every 64×64
  product from four 32×32 multiplies, to defend against cores whose
  multiplier timing depends on the data. aarch64 and x86-64 multiply in
  constant time, so that halves the inner loop and buys nothing.

Setting the mitigation to `.none` globally is not an alternative. It also
turns `ff`'s window-table lookup into a secret-indexed load, which leaks the
exponent through the cache.

**Ours:** `src/quic/mont.zig` handles only the two CRT exponentiations in RSA
signing:
- 64-bit limbs and one `u128` product per limb pair;
- a 4-bit window read with a conditional-move scan;
- inner loops specialised for 16, 24 and 32 limbs.

Everything else stays on `ff` (`src/quic/rsa.zig`), and every signature is
checked against the public key before it is returned.

**Numbers:** a 1024-bit modexp takes 1.55 ms through `ff` and 0.45 ms
through `mont` (3.5×). Run `zig build bench-crypto` and compare the two
modexp rows. A test checks `mont` against `ff` on random inputs.

**Upstream-shaped question:** could the multiply mitigation and the
table-lookup mitigation be controlled separately? Could `ff` use full 64-bit
limbs where the CPU multiplies in constant time? This is a design
conversation more than a bug.

**Master:** not re-checked for this page. Check before raising it.

## 5. ECDSA signing makes you derive the public key

**std** (`lib/std/crypto/ecdsa.zig`): signing goes through
`KeyPair.sign`/`KeyPair.signer`. `Signer.init(secret_key, noise)` is
private. From a secret key alone, the documented route is
`KeyPair.fromSecretKey`, which multiplies the base point to recover a public
key that signing never reads. That costs as much as the signature itself:
359 µs against 198 µs for signing alone (P-256, when measured on 20 Sep
2026).

**Ours:** `signCertificateVerify` in `src/quic/tls13.zig` builds
`KeyPair{ .secret_key = sk, .public_key = undefined }` and calls `sign`.
This depends on an **internal detail**: `KeyPair.signer` passing only
`secret_key` to `Signer.init`. If std ever reads `public_key` while signing,
we would produce bad signatures. The loopback handshake tests would catch
that: the client always verifies CertificateVerify.

**Master (24 Sep 2026):** unchanged. `signer` still calls
`Signer.init(key_pair.secret_key, noise)`, and `Signer.init` is still
private.

**Upstream-shaped suggestion:** a public way to sign from a `SecretKey`,
either by making `Signer.init` public or through a `SecretKey.sign`.

## 6. DER element parsing trusts its lengths

**std** (`lib/std/crypto/Certificate.zig`, `der.Element.parse`): it reads
the tag and length bytes without checking them against `bytes.len`. It
returns a slice whose `end` can lie past the buffer, and callers index with
it. A truncated certificate, or one whose lengths lie, indexes out of bounds:
a panic in safe builds, and undefined behaviour in ReleaseFast.

**Ours:** `certificateWellFormed` (`src/quic/tls13.zig`) walks the whole
certificate with bounds-checked TLV reads. It runs on every certificate a
peer sends, before `Certificate.parse`. `src/fuzz.zig` exercises the pair.

**Master (24 Sep 2026):** `der.Element.parse` is unchanged from 0.16.

**Upstream-shaped report:** bounds-check `der.Element.parse` and return a
parse error. Raise it as a robustness issue with a minimal input. Don't put
exploit details in a public report.

## 7. `std.net.Address` was removed in 0.16

**std 0.16** moved networking under `std.Io.net`. Its address type is a plain
struct, and its layout does not match the `sockaddr` the `sendmsg`,
`recvmsg` and `bind` syscalls take.

**Ours:** `src/sockaddr.zig` adapts 0.15.2's `std/net.zig` `Address`: an
`extern union` over `sockaddr` / `.in` / `.in6`, with ports in network byte
order, so it can be `@ptrCast` straight into syscalls.

This was a migration choice, not a bug in std. Revisit it if the event
loop ever moves onto `std.Io` networking.

## 8. Fixed-buffer streams stay ours

**std 0.16** replaced `std.io.fixedBufferStream` with `std.Io.Reader.fixed`
and `std.Io.Writer.fixed`, which are separate types.

**Ours:** `src/io_compat.zig` keeps one stream that both reads and writes the
same buffer, with 0.16's method names. On codec microbenchmarks
(`zig build run-bench-codec`):

- `readVarInt` alone was faster on `std.Io.Reader.fixed`.
- `Frame.parse`, the same loop inlined into a larger function, was 54% slower
  on it.

Details are in `bench/bench-summary.md`, which is local and untracked.

A related observation from 24 Sep 2026: a hand-rolled varint decode (one
bounds check and a big-endian load) halved `readVarInt` in isolation, but
made `Frame.parse` 45% slower, so it was reverted. When judging a codec
change, measure `Frame.parse`, not the primitive.

This is an optimizer observation, not a std bug. It would need a minimal
reproduction before it is worth mentioning upstream.

## 9. `std.http.Server.WebSocket` isn't used

**std 0.16** has a server-side WebSocket in `std/http/Server.zig`:
`Request.respondWebSocket` writes the 101, and `WebSocket` reads and writes
frames over a blocking `std.Io.Reader` / `Writer`. Its
`readSmallMessage`:

- rejects any fragmented message (`!fin` returns `MessageOversize`), and
  rejects a continuation frame outright;
- returns a Close frame as `error.ConnectionClose`, and skips pongs;
- needs the whole frame to fit in the reader's buffer;
- doesn't check RSV bits, UTF-8 in text frames, or close codes.

**Ours:** `src/http1/websocket.zig` is a sans-IO codec that the HTTP/1.1
listener drives from its libxev read callbacks. It adds fragmentation
with control frames in between, a bound on message size, fail-fast UTF-8
checking across fragments, close-code validation, and a vector unmask. The
Autobahn testsuite passes it with no failures (`SPEC/RFC6455_WEBSOCKET.md`).
The handshake uses std's `Sha1` and `base64`, like std's own.

std's version is sized for the blocking `std.http.Server`, so this is a
question of scope, not a bug. The Autobahn gaps above are specific enough
to raise if std ever wants its WebSocket to be conformant.

**Master** (Codeberg `5b9147ed59`, 25 Sep 2026): the same design. Only the
unmask loop changed (`[4]u8` chunks instead of an `align(1) u32` slice).

---

## Verifying the copies still match std

- `aes_gcm.zig` has a differential test against std's `Aes128Gcm`: 400 random
  keys, nonces, messages and AAD lengths. The lengths cross every GHASH
  aggregation width, and both tampered tags and tampered ciphertext are
  checked. It passed in Debug and ReleaseFast on arm64, and on x86_64 with
  and without AES-NI.
- To see how `ghash.zig` has drifted from std:

  ```sh
  diff <(sed -n '/^const std/,$p' src/quic/ghash.zig) \
       <(sed '/^const htest/,$d' "$(zig env | sed -n 's/.*\.std_dir = "\(.*\)".*/\1/p')/crypto/ghash_polyval.zig")
  ```

  It should show only the `std` import and `agg_8_threshold`.

## On a Zig upgrade

1. Re-diff `ghash_polyval.zig`, `aes_gcm.zig` and `modes.zig` against
   `src/quic/ghash.zig` and `aes_gcm.zig`. Delete a copy once upstream has the
   same behaviour and `bench-crypto` shows no regression.
2. Check whether `Signer.init` became public, or `der.Element.parse` gained
   bounds checks. If so, drop the workaround.
3. Rerun `zig build bench-crypto -Doptimize=ReleaseFast` and
   `zig build run-bench-codec -Doptimize=ReleaseFast`, and update the numbers
   here.
