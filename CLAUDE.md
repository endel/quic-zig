# Claude Code Configuration for quic-zig

## Objective
- Final objective is the implementation of core QUIC Spec: https://www.rfc-editor.org/rfc/rfc9000.txt
- Use ./interop/ client and server implementations as reference when testing specific features.
- Pass as many interoperability tests as possible (https://github.com/quic-interop/quic-interop-runner)

## Iteration over QUIC specifications
- Keep code and architecture clean, covered with tests, optimized and maintainable
- Document the state of each implementation, with their caveats of the spec under ./SPEC/[RFC_NUMBER]_[SECTION].md
- ./Keep the SPEC/STATUS.md up-to-date.
- When required to re-visit the implementation of documented pieces of
  implementation, update it under ./SPEC/[RFC_NUMBER]_[SECTION].md

## Secondary Objectives
- QUIC Loss Detection and Congestion Control (https://www.rfc-editor.org/rfc/rfc9002.txt)
- HTTP/3 (https://www.rfc-editor.org/rfc/rfc9114.txt)
- QPACK: Field Compression for HTTP/3 (https://www.rfc-editor.org/rfc/rfc9204.txt)
- HTTP Datagrams and the Capsule Protocol (https://www.rfc-editor.org/rfc/rfc9297.txt)
- Final step: The WebTransport Protocol Framework (https://www.ietf.org/archive/id/draft-ietf-webtrans-overview-11.txt)


## Checking the Zig stdlib

This repo targets Zig 0.16 (`minimum_zig_version` in `build.zig.zon`). Never
answer a stdlib question from memory or from a 0.15-era habit — 0.16 moved most
of `std.posix`, `std.fs` and `std.time` onto the `Io` interface, so a stale
answer still looks plausible instead of failing.

Use the pinned wrapper, which resolves `std` from the version this repo builds
against:

```bash
./tools/zigdoc std.Io.net.Socket
./tools/zigdoc std.crypto.tls
```

Install once with `gh release download --repo rockorager/zigdoc` (or
`zig build install --prefix $HOME/.local` from source) so `zigdoc` is on PATH.
The wrapper exists because zigdoc resolves `std` from the first `zig` on PATH:
if that is not 0.16 it answers from the wrong stdlib rather than erroring.

`src/sys.zig` is the library's syscall seam and documents which 0.16 homes each
helper corresponds to.

## libxev

libxev comes from our fork, [endel/libxev](https://github.com/endel/libxev),
pinned in `build.zig.zon` to a `quic-zig-YYYY-MM-DD` tag of its `quic-zig`
branch. The fork exists to carry fixes while upstream reviews them; the goal is
to pin upstream mitchellh/libxev again. Its `FORK.md` has the full rules and
tooling (clone: `~/Projects/libxev`, remotes `origin` = upstream, `endel` =
fork). The ones that matter from here:

- **Every change to libxev is an upstream PR.** Its own branch, cut from
  upstream `main`, opened as a PR on mitchellh/libxev. Nothing is carried that
  is not proposed upstream. Never patch the library inside this repo.
- **libxev's own tests must pass**: `fork/check.sh <branch>` runs what upstream
  CI runs (tests on macOS and Linux, examples and benchmarks, every CI target),
  on the change's branch alone before the PR opens, and on `quic-zig` before the
  pin moves. A fix comes with a test that fails without it.
- **The `quic-zig` branch is generated, never edited.** Add the branch to
  `fork/patches`, then `fork/rebuild.sh` and `fork/check.sh quic-zig-next`,
  then promote, tag, push, and repin here with `zig fetch` for the hash.
- **Nothing a pin names is deleted.** GitHub serves the pinned tarball by
  commit; retire a fork branch or tag only once no pushed quic-zig references
  it.
- **When a PR merges upstream**, drop it from `fork/patches`, rebuild, check,
  repin. When the list is empty, pin upstream.

Changing the pin changes routez too, which gets libxev only through here: run
its e2e suite (`tests/e2e/run.sh`, macOS and Linux) before pushing a new pin.
