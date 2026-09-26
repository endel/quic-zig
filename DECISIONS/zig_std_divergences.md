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
  24 Sep 2026.
- **Benchmark hardware:** arm64 figures are native runs on an Apple M-series
  core. x86_64 figures ran under Rosetta in Docker Desktop. They are good for
  comparing one variant with another, not as absolute numbers. Confirm them on
  native x86 before raising anything upstream.

| # | Area | Our code | Kind | Upstream-worthy? |
|---|------|----------|------|------------------|
| 1 | GHASH aggregation threshold | `src/quic/ghash.zig` | vendored copy, one constant changed | yes: tuning |
| 2 | AES-GCM per-key setup | `src/quic/aes_gcm.zig` | API gap: no keyed AEAD context | yes: API |
| 3 | AES-CTR with hardware AES | `src/quic/aes_gcm.zig` (`ctrFast`) | own CTR loop and arm64 rounds | yes: perf |
| 4 | RSA modular exponentiation | `src/quic/mont.zig` | narrow replacement for `std.crypto.ff` | maybe: design question |
| 5 | ECDSA signing without deriving the public key | `src/quic/tls13.zig` `signCertificateVerify` | relies on an internal detail | yes: API |
| 6 | DER element parsing bounds | `src/quic/tls13.zig` `certificateWellFormed` | guard in front of std | yes: robustness bug |
| 7 | `std.net.Address` | `src/sockaddr.zig` | adapted copy of 0.15.2 code | no: migration choice |
| 8 | Fixed-buffer reader/writer | `src/io_compat.zig` | kept our own stream | maybe: codegen observation |
| 9 | GHASH on arm64 | `src/quic/aes_gcm.zig` (`ghashBlocks`) | GHASH in vector registers | yes: codegen |
| 10 | Master compiles AES-GCM slower | `src/quic/aes_gcm.zig` (`xorBlock`) | explicit unaligned vector loads | yes: codegen regression |

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

On arm64, packets no longer go through this file: see item 9. It still
serves x86_64, and arm64 builds in ReleaseSmall.

## 2. std's AEAD API has no keyed context

**std** (`lib/std/crypto/aes_gcm.zig`): `encrypt` and `decrypt` take the raw
key on every call. Each call does `Aes.initEnc(key)` (key expansion), one
AES block to derive H, and `Ghash.initForBlockCount`, which computes powers
of H with carryless multiplies. For a transport protocol, one key protects
millions of messages, so this work repeats for nothing.

**Ours:** `src/quic/aes_gcm.zig` `Ctx` does that work once, in `init(key)`,
when the key is installed (`Open`/`Seal.prepareCtx()` in `crypto.zig`). The
per-message code follows std's `encrypt`/`decrypt`, over its own CTR (item
3) and, on arm64, its own GHASH (item 9), which reads the prepared powers of
H in place. Elsewhere each message starts from a copy of the prepared GHASH
state, about 300 bytes. We hold all 16 powers because that is what
`Ghash.init` computes.

**Numbers** (`zig build bench-crypto -Doptimize=ReleaseFast`, 1200 B
packets, native arm64, called out of line as packets do). These include
items 3 and 9:

| | std `Aes128Gcm` | `aes_gcm.Ctx` |
|---|---|---|
| encrypt | 624–664 ns | 237 ns |
| decrypt | 694–749 ns | 239–249 ns |

Caching alone was worth 2–10%. Most of the gain is items 3 and 9. The
figures this section first gave (455 and 487 ns) came from calls inlined into
the timing loop, which kept the round keys in registers across iterations.
Out of line, that version measured 486–528 ns natively, and in routez's
Linux build it was slower than std.

**Cost:** `Open`/`Seal` grew from about 288 to 784 bytes. We now pass them by
pointer through the packer and the receive path, which used to copy them per
packet.

**Upstream-shaped suggestion:** a keyed-context API along the lines of
`Aes128Gcm.init(key) -> Context` with `context.encrypt(...)` /
`context.decrypt(...)`. Other std primitives already split key setup from
use (`Aes128.initEnc`, `Ghash.init`); the AEAD wrappers are where that stops.

## 3. AES-CTR: our own loop, and arm64 rounds with the key in `aese`

**std 0.16** (`lib/std/crypto/modes.zig` `ctrSlice`, over
`lib/std/crypto/aes/armcrypto.zig`):
- Full batches of `optimal_parallel_blocks` (6 on arm64) go through
  `xorWide`, whole leftover blocks through `xor` one at a time, and a partial
  final block is padded.
- Each arm64 round is one asm block: `mov`, `aese` with a **zero** key,
  `aesmc`, then an `eor` of the round key outside the asm. That is four
  instructions where two do: `aese` XORs its key operand in first, and
  `aese` + `aesmc` on one register is a pair the core fuses.
- The asm operands use the `x` constraint, which on arm64 means v0-v15. Six
  blocks plus 11 round keys don't fit, so keys are moved or reloaded
  between rounds.
- Whether `xorWide` is inlined decides whether the keys stay in registers
  across the loop. With 0.16's loop copied into `aes_gcm.zig`, routez's Linux
  build compiled it out of line (two callers), and h3-static lost 27% (see
  routez's `TODO/h3-per-request-latency.md`, 25 Sep 2026).

**Master** (0.17.0-dev.2294, 24 Sep 2026): the same round form and the same
tail loop as 0.16; the batch counter now wraps (`+%=`). An earlier version of
this note described a master commit (`e339566922`) that batched the tail;
master at dev.2294 does not do that.

**Ours** (`aes_gcm.zig` `ctrFast`, when `crypto.core.aes.has_hardware_support`):
- 8 blocks per step with the round keys copied to a local, so they stay in
  registers and stores to the output can't alias them.
- The tail as one batch of exactly the blocks left, with the tag mask
  E(K, J0) as one more lane, so a short packet costs one AES latency.
- On arm64, each round is `aese v, rk` + `aesmc v, v` in one asm block with
  `w` operands (all 32 registers). On x86_64, the rounds are std's `aesenc`
  blocks, which already take the key.
- The GCM counter is a 32-bit big-endian increment of the last word, as the
  spec has it.

**Numbers** (`zig build bench-crypto -Doptimize=ReleaseFast`, 1200 B,
native arm64, AES-GCM called out of line as packets do; GHASH unchanged):

| | seal | open |
|---|---|---|
| std `Aes128Gcm` | 593–664 ns | 659–749 ns |
| `Ctx` with 0.16's CTR loop | 486–513 ns | 510–528 ns |
| `Ctx` with `ctrFast` | 403–433 ns | 409–472 ns |

**Upstream-shaped report:** armcrypto's `Block.encrypt` could put the round
key in `aese` and use the `w` constraint. Every AES user on arm64 would
gain, not only CTR. The master tail regression is separate: keep the
wrapping and restore block-sized tail handling.

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

## 9. GHASH on arm64 runs in general-purpose registers

**std** (`lib/std/crypto/ghash_polyval.zig`, and our copy in
`src/quic/ghash.zig`): the state and every intermediate are `u128`. On arm64
LLVM keeps `u128` in pairs of general-purpose registers. Each carryless
multiply is an asm block on vectors, so every one of them moves its operands
into vector registers and its result back out. Byte reversal runs as `rev`
on general registers. In `update` in a ReleaseFast arm64 build, 205 of 826
instructions move data between the two register files, against 122
`pmull`s, and some values spill to the stack.

**Ours** (`aes_gcm.zig` `ghashBlocks`, arm64 with the `aes` feature, not
ReleaseSmall): the same schoolbook product and the same reduction as std,
on `@Vector(2, u64)`. Blocks are byte-reversed with a vector shuffle.
Batches of 8 blocks, the tail as one batch, and the length block rides in
the message's last batch, so each of AD and message costs one reduction. It
reads the powers of H that `Ghash.init` already computed, so `Ctx` layout
doesn't change.

**Numbers** (`bench-crypto`, as in item 2, with item 3 in both columns):

| | seal | open |
|---|---|---|
| `ghash.zig` | 403–433 ns | 409–472 ns |
| `ghashBlocks` | 237 ns | 239–249 ns |

**Upstream-shaped report:** a codegen observation more than a bug. On
arm64, `ghash_polyval.zig` would do better with its state and accumulators
as vectors. x86_64 likely has the same shape, with `u128` in general
registers around `pclmulqdq`, but that has not been measured.

---

## 10. Zig master compiles AES-GCM slower on arm64

Measured 26 Sep 2026 with 0.17.0-dev.2294+71403f299 (LLVM 22.1.8) against
0.16.0 (LLVM 21.1), same M1 Pro, 1200 B seal out of line:

| | 0.16.0 | master |
|---|---|---|
| std `Aes128Gcm` | 569 ns | 723 ns (+27%) |
| `aes_gcm.Ctx` before `a34c55a` | 219 ns | 336 ns (+53%) |
| `aes_gcm.Ctx` | 216 ns | 217 ns |

The cause in our code: `@as(V, @bitCast(src.*))` on a `*const [16]u8`
compiled to sixteen `ldrb` and a chain of shifts and `orr`s instead of one
`ldr q`, doubling CTR. An `align(1)` vector pointer is one load on both
compilers (`xorBlock`). std's slowdown is probably the same pattern in
`Block.fromBytes`/`xorBytes`; not confirmed. Master also names this CPU
`apple_a14` where 0.16 says `apple_m1`, which made no difference here.

**Upstream-shaped report:** a codegen regression on aarch64: a bitcast of an
unaligned `[16]u8` load to a 128-bit vector is lowered byte by byte.

## Verifying the copies still match std

- `aes_gcm.zig` is checked three ways, all run by `zig build test`:
  - Wycheproof's 67 AES-128-GCM vectors with 96-bit IVs (40 valid, 27
    modified tags), from `aes_gcm_vectors.zig`.
  - Against std's `Aes128Gcm` on 600 random keys, nonces and lengths
    (messages to 2 KB, AD to 600 B), and on every message length from 0
    to 320 B against AD lengths either side of each batch boundary. Each
    case is sealed in place and not, opened, and refused with one flipped
    bit in the tag, the message or the AD.
  - A `zig build fuzz` target doing the same on arbitrary input.

  They pass in Debug, ReleaseSafe, ReleaseFast and ReleaseSmall on arm64, on
  arm64 with `-mcpu baseline` (software AES) and as generic arm64 Linux, and
  on x86_64 with and without AES-NI (built with `-target x86_64-linux-musl
  --test-no-exec`, run under Docker's amd64 emulation). A one-off
  differential run of 250 million random cases against std (arm64 native
  and Linux, x86_64 AES-NI and software; 26 Sep 2026) found no difference
  and no accepted forgery.
- To see how `ghash.zig` has drifted from std:

  ```sh
  diff <(sed -n '/^const std/,$p' src/quic/ghash.zig) \
       <(sed '/^const htest/,$d' "$(zig env | sed -n 's/.*\.std_dir = "\(.*\)".*/\1/p')/crypto/ghash_polyval.zig")
  ```

  It should show only the `std` import and `agg_8_threshold`.

## On a Zig upgrade

1. Re-diff `ghash_polyval.zig` and `aes_gcm.zig` against `src/quic/ghash.zig`
   and `aes_gcm.zig`, and check whether armcrypto's rounds take the key in
   `aese`. Delete our code once upstream has the same behaviour and
   `bench-crypto` shows no regression.
2. Check whether `Signer.init` became public, or `der.Element.parse` gained
   bounds checks. If so, drop the workaround.
3. Rerun `zig build bench-crypto -Doptimize=ReleaseFast` and
   `zig build run-bench-codec -Doptimize=ReleaseFast`, and update the numbers
   here.
