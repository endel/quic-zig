#!/usr/bin/env bash
# Time repeated handshakes through a lossy UDP relay. No docker, no simulator —
# for poking at Initial/Handshake retransmission timing directly.
#
#   tools/handshake_loss.sh                    # zig server, quiche client, 30% loss
#   SERVER=quiche LOSS=20 RUNS=20 tools/handshake_loss.sh
#
# SERVER=quiche runs quiche against itself as a control; without one it is easy
# to read the peer client's own idle timeout as our slowness.
set -u
cd "$(dirname "$0")/.."

LOSS=${LOSS:-30}
RUNS=${RUNS:-10}
SERVER=${SERVER:-zig}
SRV_PORT=${SRV_PORT:-15901}
PROXY_PORT=${PROXY_PORT:-15900}
QUICHE=interop/quiche/target/release

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"; kill -9 ${SRV:-} ${PROXY:-} 2>/dev/null' EXIT

if [ "$SERVER" = zig ]; then
    ./zig-out/bin/quic-server --port "$SRV_PORT" >"$WORK/server.log" 2>&1 &
else
    "$QUICHE/server" --addr "127.0.0.1:$SRV_PORT" \
        --cert interop/certs/server.crt --key interop/certs/server.key --alpn h3 \
        >"$WORK/server.log" 2>&1 &
fi
SRV=$!
python3 tools/lossy_proxy.py "$PROXY_PORT" "$SRV_PORT" "$LOSS" 11 >"$WORK/proxy.log" 2>&1 &
PROXY=$!
sleep 1
kill -0 $SRV 2>/dev/null || { echo "server did not start:"; tail -5 "$WORK/server.log"; exit 1; }

ok=0; fail=0; total=0
for i in $(seq 1 "$RUNS"); do
    start=$(python3 -c 'import time;print(time.time())')
    rc=0
    "$QUICHE/client" --addr "127.0.0.1:$PROXY_PORT" --alpn h3 >>"$WORK/client.log" 2>&1 || rc=$?
    end=$(python3 -c 'import time;print(time.time())')
    total=$(python3 -c "print(f'{$total+$end-$start:.2f}')")
    [ "$rc" -eq 0 ] && ok=$((ok+1)) || fail=$((fail+1))
    printf '  run %2d: %ss rc=%s\n' "$i" "$(python3 -c "print(f'{($end-$start):.2f}')")" "$rc"
done
echo "server=$SERVER loss=${LOSS}% runs=$RUNS ok=$ok fail=$fail avg=$(python3 -c "print(f'{$total/$RUNS:.2f}')")s"
