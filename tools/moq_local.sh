#!/usr/bin/env bash
# MoQ end-to-end checks against our own binaries. No docker, no peers.
#
#   tools/moq_local.sh
#
# Covers what the unit tests cannot: that the pieces talk to each other
# over a real connection. Peer interop is tools/moq_interop.sh.
set -uo pipefail
# Backgrounded peers are killed on purpose; without this the shell prints
# a "Terminated" line for each, which buries the results.
set +m

cd "$(dirname "$0")/.."

TMP=$(mktemp -d)
PIDS=()
kill_quietly() {
  for p in "$@"; do kill "$p" 2>/dev/null; done
  wait "$@" 2>/dev/null
}
cleanup() {
  kill_quietly "${PIDS[@]:-}"
  rm -rf "$TMP"
}
trap cleanup EXIT

PASS=0
FAIL=0
report() { # name, ok?, detail
  if [ "$2" = 1 ]; then
    printf '  PASS  %s\n' "$1"; PASS=$((PASS + 1))
  else
    printf '  FAIL  %s%s\n' "$1" "${3:+ — $3}"; FAIL=$((FAIL + 1))
  fi
}

for bin in moq-relay moq-client moq-test-client moq-lite moq-lite-relay; do
  [ -x "zig-out/bin/$bin" ] || { echo "build first: zig build" >&2; exit 1; }
done

# Ports unlikely to collide with the interop runner's.
IETF_PORT=4461
LITE_RELAY_PORT=4462
LITE_ORIGIN_PORT=4463
CERT=interop/browser/certs/server.crt
KEY=interop/browser/certs/server.key

start() { # logfile, cmd...
  local log=$1; shift
  "$@" > "$log" 2>&1 &
  PIDS+=($!)
  sleep 1.5
}

echo "=== IETF MoQ Transport ==="
start "$TMP/ietf-relay.log" zig-out/bin/moq-relay --port "$IETF_PORT"

for draft in 17 18; do
  zig-out/bin/moq-test-client --relay "moqt://127.0.0.1:$IETF_PORT/" \
      --draft "$draft" --tls-disable-verify > "$TMP/tap-$draft.txt" 2>&1
  ok=$(grep -cE '^ok ' "$TMP/tap-$draft.txt")
  [ "$ok" = 7 ] && report "interop client, draft-$draft (7/7)" 1 \
                || report "interop client, draft-$draft" 0 "$ok/7"
done

# Objects on subgroup streams, and the same over datagrams.
for draft in 17 18; do
  for mode in streams datagrams; do
    ns="d$draft-$mode"
    flag=""; [ "$mode" = datagrams ] && flag="--datagrams"
    zig-out/bin/moq-client --addr "127.0.0.1:$IETF_PORT" --ns "$ns" --track cam \
        --mode publish --draft "$draft" $flag > "$TMP/pub.log" 2>&1 &
    pub=$!; PIDS+=($pub)
    sleep 1
    zig-out/bin/moq-client --addr "127.0.0.1:$IETF_PORT" --ns "$ns" --track cam \
        --draft "$draft" > "$TMP/sub-$ns.log" 2>&1 &
    sub=$!; PIDS+=($sub)
    sleep 4
    kill_quietly $pub $sub
    pat='Object track'; [ "$mode" = datagrams ] && pat='Datagram track'
    n=$(grep -cE "$pat" "$TMP/sub-$ns.log")
    [ "$n" -ge 2 ] && report "$mode, draft-$draft ($n received)" 1 \
                   || report "$mode, draft-$draft" 0 "$n received"
  done
done

echo
echo "=== moq-lite ==="
start "$TMP/lite-origin.log" zig-out/bin/moq-lite serve \
    --port "$LITE_ORIGIN_PORT" --broadcast clock --track seconds \
    --cert "$CERT" --key "$KEY"
start "$TMP/lite-relay.log" zig-out/bin/moq-lite-relay \
    --port "$LITE_RELAY_PORT" --cert "$CERT" --key "$KEY"

zig-out/bin/moq-lite subscribe --url "https://127.0.0.1:$LITE_ORIGIN_PORT/" \
    --broadcast clock --track seconds --tls-disable-verify --seconds 4 \
    > "$TMP/lite-origin-sub.log" 2>&1
n=$(grep -cE '^  ts=' "$TMP/lite-origin-sub.log")
[ "$n" -ge 4 ] && report "origin -> subscriber ($n frames)" 1 \
               || report "origin -> subscriber" 0 "$n frames"

zig-out/bin/moq-lite publish --url "https://127.0.0.1:$LITE_RELAY_PORT/" \
    --broadcast clock --track seconds --tls-disable-verify --seconds 10 \
    > "$TMP/lite-pub.log" 2>&1 &
PIDS+=($!)
sleep 1.5
zig-out/bin/moq-lite subscribe --url "https://127.0.0.1:$LITE_RELAY_PORT/" \
    --broadcast clock --track seconds --tls-disable-verify --seconds 5 \
    > "$TMP/lite-relay-sub.log" 2>&1
n=$(grep -cE '^  ts=' "$TMP/lite-relay-sub.log")
[ "$n" -ge 3 ] && report "publisher -> relay -> subscriber ($n frames)" 1 \
               || report "publisher -> relay -> subscriber" 0 "$n frames"

# A subscription for something nobody publishes is a stream reset, not a
# message, so the subscriber simply gets nothing.
zig-out/bin/moq-lite subscribe --url "https://127.0.0.1:$LITE_RELAY_PORT/" \
    --broadcast nothing --track here --tls-disable-verify --seconds 3 \
    > "$TMP/lite-missing.log" 2>&1
n=$(grep -cE '^  ts=' "$TMP/lite-missing.log")
[ "$n" = 0 ] && report "unknown broadcast is refused" 1 \
             || report "unknown broadcast is refused" 0 "$n frames arrived"

echo
echo "  $PASS passed, $FAIL failed"
[ "$FAIL" = 0 ]
