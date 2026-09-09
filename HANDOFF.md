# quic-zig — open items after the memory/bounds pass

Branch `memory-and-bounds`, off master `344c0e4`. 528/528 unit tests,
11/11 local interop (`tools/interop_local.sh`), 3/3 of the Zig-involved
cases in `interop/run_local_tests.sh`.

## Running things

    ZIG=~/.zvm/0.16.0/zig          # repo needs 0.16; zvm default is 0.15.2
    $ZIG build test
    $ZIG build                     # builds apps/ into zig-out/bin
    tools/interop_local.sh         # the 11 passing interop cases, no docker

`tools/interop_local.sh [case...]` boots interop-server-manual and
interop-client-manual against each other and compares the downloaded bytes.
Cases that pass: handshake transfer http3 chacha20 keyupdate multiconnect
retry v2 resumption zerortt ecn.

## Open

### 1. `size`/`used` in DynamicTable are still mutually derivable
`src/h3/qpack.zig`. `size == used - descs[tail].off + 32*count`. Left alone
deliberately: deriving it means a `tailIndex()` plus a descriptor load at
every read (the `setCapacity` and `insert` eviction loops), and it trades a
flat invariant for one that has to reason about `count == 0`. The `head`
field, which was exactly `insert_count % MAX_ENTRIES`, is gone.

### 2. `wt-client` never exits
`zig-out/bin/wt-client` completes the WebTransport exchange, drains, logs
"connection terminated after draining period" — and then sits in the event
loop forever. `interop/run_local_tests.sh` has no client timeout, so it
blocks there and the three cases after it never run. Reproduces identically
on `a461a81`, so it predates this branch.

### 3. `connectionmigration` interop fails
`panic: reached unreachable code` in the client. Verified identical on clean
master, so it is not from this work — but it is real and unfixed.

## The ESP32 branch

`esp32-s3` is abandoned. If it is ever revisited, the thing worth knowing is
that Zig's C backend produced three separate silent miscompiles on Xtensa
(u128 struct alignment vs. ZIG_TARGET_MAX_INT_ALIGNMENT, uintptr_t vs
uint32_t in helper signatures, and an Ed25519 keypair corruption reproduced
in `qz_diag_ed25519_minimal`). Everything else there was ordinary porting.
