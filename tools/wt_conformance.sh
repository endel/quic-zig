#!/usr/bin/env bash
# Run the shared WebTransport conformance suite: one server, both clients.
#
#   ./tools/wt_conformance.sh                 # Zig client + Chrome
#   ./tools/wt_conformance.sh --firefox       # ... and Firefox
#   ./tools/wt_conformance.sh --safari        # ... and Safari
#   ./tools/wt_conformance.sh --safari-preview # ... and Safari Technology Preview
#   ./tools/wt_conformance.sh --zig-only      # no browser needed (this is CI's leg)
#
# Scenarios live in interop/conformance/scenarios.json. Both runners refuse to
# start unless they implement exactly that list.
set -uo pipefail

cd "$(dirname "$0")/.."
PORT="${WT_PORT:-4433}"
CERT=interop/browser/certs/server.crt
OUT="${RESULTS_DIR:-$(mktemp -d)}"

BROWSERS=(chrome)
ZIG_ONLY=0
for arg in "$@"; do
  case "$arg" in
    --firefox) BROWSERS+=(firefox) ;;
    --safari)  BROWSERS+=(safari) ;;
    --safari-preview) BROWSERS+=(safari-preview) ;;
    --zig-only) ZIG_ONLY=1 ;;
    *) echo "unknown flag: $arg" >&2; exit 2 ;;
  esac
done

# Browsers pin this certificate by hash and refuse one older than 14 days; the
# Zig client pins the same file, so both sides fail together on a stale one.
if ! openssl x509 -in "$CERT" -noout -checkend 86400 >/dev/null 2>&1; then
  echo "Certificate missing or expiring within a day — regenerating"
  interop/browser/generate-cert.sh >/dev/null
fi

zig build -p ./zig-out || exit 1

./zig-out/bin/wpt-server --port "$PORT" \
  --cert "$CERT" --key interop/browser/certs/server.key >"$OUT/server.log" 2>&1 &
SERVER_PID=$!
trap 'kill $SERVER_PID 2>/dev/null' EXIT
sleep 2
kill -0 $SERVER_PID 2>/dev/null || { echo "server failed to start:"; cat "$OUT/server.log"; exit 1; }

status=0

echo
echo "=== zig ==="
./zig-out/bin/wpt-client --port "$PORT" --cert "$CERT" | tee "$OUT/zig.txt" || status=1

if [ "$ZIG_ONLY" = 0 ]; then
  for b in "${BROWSERS[@]}"; do
    echo
    echo "=== $b ==="
    flag=""
    [ "$b" = firefox ] && flag=--firefox
    [ "$b" = safari ] && flag=--safari
    [ "$b" = safari-preview ] && flag=--safari-preview
    RESULTS_JSON="$OUT/$b.json" WT_SERVER="127.0.0.1:$PORT" \
      node interop/browser/run-wpt-tests.mjs $flag | tee "$OUT/$b.txt" || status=1
  done
fi

echo
echo "Logs and per-runner results in $OUT"
exit $status
