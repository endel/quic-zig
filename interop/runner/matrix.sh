#!/usr/bin/env bash
# Full quic-interop-runner matrix for quic-zig against one or more peers, both
# directions, one test case at a time.
#
#   interop/runner/matrix.sh                          # default peers and tests
#   interop/runner/matrix.sh quic-go handshake,transfer
#
# Assumes the quic-zig image is built (interop/runner/run.sh builds it).
# Appends one line per (server, client, test) to $OUT, and skips what is already
# recorded there, so an interrupted run resumes instead of starting over.
set -u

cd "$(dirname "$0")/../.."
ROOT=$(pwd)
RUNNER="$ROOT/interop/quic-interop-runner"
PYTHON=${PYTHON:-/opt/homebrew/bin/python3.12}
OUT=${OUT:-$ROOT/interop/runner/matrix-results.txt}
LOGS="$ROOT/interop/runner/matrix-logs"

PEERS=${1:-"quic-go quiche"}
TESTS=${2:-"handshake,transfer,http3,retry,resumption,zerortt,multiplexing,longrtt,keyupdate,chacha20,v2,ipv6,amplificationlimit,blackhole,ecn,handshakeloss,transferloss,handshakecorruption,transfercorruption,rebind-port,rebind-addr,connectionmigration"}

command -v "$PYTHON" >/dev/null || { echo "need python >= 3.10 at \$PYTHON"; exit 1; }
mkdir -p "$LOGS"

cat > "$LOGS/verdict.py" <<'PY'
import json, sys
try:
    d = json.load(open(sys.argv[1]))
    r = [x["result"] for row in d["results"] for x in row]
    print({"succeeded": "PASS", "failed": "FAIL",
           "unsupported": "UNSUPPORTED"}.get(r[0], "UNKNOWN") if r else "UNKNOWN")
except Exception:
    print("ERROR")
PY

# Register quic-zig with the runner (idempotent).
"$PYTHON" - "$RUNNER/implementations_quic.json" <<'PY'
import json, sys
path = sys.argv[1]
impls = json.load(open(path))
impls["quic-zig"] = {"image": "quic-zig-interop:latest",
                     "url": "https://github.com/endel/quic-zig", "role": "both"}
json.dump(impls, open(path, "w"), indent=2)
open(path, "a").write("\n")
PY

touch "$OUT"
IFS=',' read -ra TEST_ARRAY <<< "$TESTS"

run_one() {
    server=$1; client=$2; test=$3
    key="$server<-$client $test"
    if grep -qF "$key " "$OUT"; then
        echo "  skip  $key ($(grep -F "$key " "$OUT" | tail -1 | awk '{print $NF}'))"
        return
    fi
    # Clear the previous case's containers. Scoped by name to the three
    # the runner creates — `docker ps -aq` would take out whatever else the
    # machine happens to be running, which is a nasty surprise when a peer
    # relay is up in another terminal.
    docker rm -f sim server client >/dev/null 2>&1
    docker network prune -f >/dev/null 2>&1
    log="$LOGS/${server}-${client}-${test}.txt"
    json="$LOGS/${server}-${client}-${test}.json"
    ( cd "$RUNNER" && "$PYTHON" run.py -s "$server" -c "$client" -t "$test" -j "$json" ) >"$log" 2>&1
    verdict=$("$PYTHON" "$LOGS/verdict.py" "$json")
    echo "$key $verdict" >> "$OUT"
    echo "  $verdict  $key"
    [ "$verdict" = PASS ] && rm -f "$log" "$json"
    return 0
}

for peer in $PEERS; do
    echo "=== quic-zig server <- $peer client ==="
    for t in "${TEST_ARRAY[@]}"; do run_one quic-zig "$peer" "$t"; done
    echo "=== $peer server <- quic-zig client ==="
    for t in "${TEST_ARRAY[@]}"; do run_one "$peer" quic-zig "$t"; done
done

echo
echo "=== summary ($OUT) ==="
awk '{print $NF}' "$OUT" | sort | uniq -c
