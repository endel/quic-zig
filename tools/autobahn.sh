#!/usr/bin/env bash
# Run the Autobahn|Testsuite fuzzing client against ws-echo-server: the
# WebSocket (RFC 6455) conformance suite. Needs Docker.
#
#   ./tools/autobahn.sh          # ws://
#   ./tools/autobahn.sh --tls    # wss://, through the TLS 1.3 listener
#
# Passes only when every case is OK or INFORMATIONAL: a FAILED, NON-STRICT or
# UNIMPLEMENTED case fails the run. Cases 12 and 13 test permessage-deflate,
# which isn't implemented, and are excluded. The HTML report is left in
# $RESULTS_DIR (relative to the repo root; a temporary directory by default).
set -uo pipefail

cd "$(dirname "$0")/.."
OUT="${RESULTS_DIR:-$(mktemp -d)}"
# docker -v takes an absolute path; a relative one names a volume.
mkdir -p "$OUT" && OUT=$(cd "$OUT" && pwd)
# Pinned: the suite is barely maintained, and a moving tag would move the bar.
IMAGE=crossbario/autobahn-testsuite@sha256:519915fb568b04c9383f70a1c405ae3ff44ab9e35835b085239c258b6fac3074
# Every case of the pinned suite outside 12 and 13. wstest exits 0 when it
# gives up on a connection, so a short count is how an aborted run shows.
EXPECTED_CASES=301

TLS=0
for arg in "$@"; do
  case "$arg" in
    --tls) TLS=1 ;;
    *) echo "unknown flag: $arg" >&2; exit 2 ;;
  esac
done
# A port per mode: a run right after the other mode's can't meet its leftovers.
PORT="${AUTOBAHN_PORT:-$((9001 + TLS))}"

# ReleaseSafe: fast enough for the 16 MiB cases, and still panics on UB.
zig build ws-echo-server -Doptimize=ReleaseSafe -p "$OUT/zig-out" || exit 1

server_args=(--port "$PORT" --address 0.0.0.0 --cert interop/certs/server.crt --key interop/certs/server.key)
scheme=wss
agent=quic-zig-tls
if [ "$TLS" = 0 ]; then
  server_args+=(--plain)
  scheme=ws
  agent=quic-zig
fi
"$OUT/zig-out/bin/ws-echo-server" "${server_args[@]}" >"$OUT/server.log" 2>&1 &
SERVER_PID=$!
trap 'kill $SERVER_PID 2>/dev/null' EXIT
sleep 1
kill -0 $SERVER_PID 2>/dev/null || { echo "server failed to start:"; cat "$OUT/server.log"; exit 1; }

# Linux shares the host's network; Docker Desktop reaches the host by name.
if [ "$(uname)" = Linux ]; then
  net=(--network host)
  host=127.0.0.1
else
  net=(--add-host=host.docker.internal:host-gateway)
  host=host.docker.internal
fi

mkdir -p "$OUT/reports"
cat >"$OUT/fuzzingclient.json" <<JSON
{
  "outdir": "/reports",
  "servers": [{ "agent": "$agent", "url": "$scheme://$host:$PORT" }],
  "cases": ["*"],
  "exclude-cases": ["12.*", "13.*"],
  "exclude-agent-cases": {}
}
JSON

echo "Autobahn fuzzingclient → $scheme://$host:$PORT (reports in $OUT/reports)"
# Docker Desktop's host proxy sometimes stops forwarding new connections
# mid-run ("User timeout caused connection failure"); Node's `ws` server
# aborts the same way, 3 runs in 5. Only such an unfinished run is retried.
for attempt in 1 2 3; do
  docker run --rm "${net[@]}" -v "$OUT":/config -v "$OUT/reports":/reports "$IMAGE" \
    wstest -m fuzzingclient -s /config/fuzzingclient.json >"$OUT/wstest.log" 2>&1 \
    || { echo "wstest failed:"; tail -20 "$OUT/wstest.log"; exit 1; }
  kill -0 $SERVER_PID 2>/dev/null || { echo "server died during the run:"; tail -20 "$OUT/server.log"; exit 1; }
  ran=$(grep -c "Running test case" "$OUT/wstest.log")
  [ "$ran" -ge "$EXPECTED_CASES" ] && break
  echo "attempt $attempt stopped after $ran cases: $(grep -o 'failed (.*' "$OUT/wstest.log" | head -1)"
  [ "$attempt" = 3 ] && { echo "the suite never finished"; exit 1; }
done

python3 - "$OUT/reports/index.json" "$agent" "$EXPECTED_CASES" <<'PY'
import collections, json, sys
cases = json.load(open(sys.argv[1]))[sys.argv[2]]
if len(cases) != int(sys.argv[3]):
    sys.exit(f"expected {sys.argv[3]} cases, the report has {len(cases)}")
ok = {"OK", "INFORMATIONAL"}
count = collections.Counter(v["behavior"] for v in cases.values())
print(f"{len(cases)} cases: " + ", ".join(f"{n} {b}" for b, n in sorted(count.items())))
key = lambda k: [int(p) for p in k.split(".")]
bad = [(k, v) for k, v in sorted(cases.items(), key=lambda kv: key(kv[0]))
       if v["behavior"] not in ok or v["behaviorClose"] not in ok]
for k, v in bad:
    print(f"  {k}: {v['behavior']} (close: {v['behaviorClose']})")
sys.exit(1 if bad or not cases else 0)
PY
