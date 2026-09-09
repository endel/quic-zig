#!/usr/bin/env bash
# Runs the quic-interop test cases against our own server, without docker:
# interop-server-manual and interop-client-manual are just two binaries.
#
#   tools/interop_local.sh              # every case known to pass
#   tools/interop_local.sh retry v2     # only these
#
# connectionmigration is excluded: interop-server-manual advertises a preferred
# address on its own port and listens on one socket, so the client migrates to
# an address nothing is reading and both ends PTO. interop-server (the docker
# image) uses a second socket on a different port and does exercise it.
set -u

cd "$(dirname "$0")/.."

ZIG=${ZIG:-$HOME/.zvm/0.16.0/zig}
SERVER=zig-out/bin/interop-server-manual
CLIENT=zig-out/bin/interop-client-manual

CASES=(handshake transfer http3 chacha20 keyupdate multiconnect retry v2 resumption zerortt ecn)
[ $# -gt 0 ] && CASES=("$@")

[ -x "$SERVER" ] && [ -x "$CLIENT" ] || { echo "building..."; "$ZIG" build || exit 1; }

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"; [ -n "${SRV_PID:-}" ] && kill -9 "$SRV_PID" 2>/dev/null' EXIT

# The server wants cert.pem + priv.key side by side; the repo's interop cert
# already carries a 127.0.0.1 SAN and a SEC1 (RFC 5915) EC key, which is what
# extractEcPrivateKey parses.
mkdir -p "$WORK/certs" "$WORK/www"
cp interop/certs/server.crt "$WORK/certs/cert.pem"
cp interop/certs/server.key "$WORK/certs/priv.key"

# Two sizes: one that fits a single packet, one that needs flow control.
echo "hello from quic-zig" > "$WORK/www/small.txt"
dd if=/dev/urandom of="$WORK/www/big.bin" bs=1024 count=1024 2>/dev/null

PORT=14433
PASS=0; FAIL=0; FAILED=()

for tc in "${CASES[@]}"; do
    PORT=$((PORT + 1))
    DL="$WORK/dl-$tc"; mkdir -p "$DL"

    CERTS="$WORK/certs" PORT=$PORT WWW="$WORK/www" TESTCASE="$tc" \
        "$SERVER" >"$WORK/server-$tc.log" 2>&1 &
    SRV_PID=$!
    sleep 0.4

    if ! kill -0 $SRV_PID 2>/dev/null; then
        echo "  FAIL  $tc (server did not start)"; tail -5 "$WORK/server-$tc.log"
        FAIL=$((FAIL+1)); FAILED+=("$tc"); SRV_PID=; continue
    fi

    # No `timeout` on macOS — run the client under our own watchdog.
    TESTCASE="$tc" DOWNLOADS="$DL" "$CLIENT" \
        "https://127.0.0.1:$PORT/small.txt" "https://127.0.0.1:$PORT/big.bin" \
        >"$WORK/client-$tc.log" 2>&1 &
    CLI_PID=$!
    ( sleep 30; kill -9 $CLI_PID 2>/dev/null ) & WD_PID=$!
    wait $CLI_PID; rc=$?
    kill $WD_PID 2>/dev/null; wait $WD_PID 2>/dev/null

    kill -9 $SRV_PID 2>/dev/null; wait $SRV_PID 2>/dev/null; SRV_PID=

    # Trust the bytes, not the exit code: both files must round-trip intact.
    if [ $rc -eq 0 ] \
       && cmp -s "$DL/small.txt" "$WORK/www/small.txt" \
       && cmp -s "$DL/big.bin"   "$WORK/www/big.bin"; then
        echo "  PASS  $tc"; PASS=$((PASS+1))
    else
        echo "  FAIL  $tc (exit $rc)"
        tail -5 "$WORK/client-$tc.log" | sed 's/^/        /'
        FAIL=$((FAIL+1)); FAILED+=("$tc")
    fi
done

echo
echo "  $PASS/$((PASS+FAIL)) passed"
[ $FAIL -eq 0 ] || { echo "  failed: ${FAILED[*]}"; exit 1; }
