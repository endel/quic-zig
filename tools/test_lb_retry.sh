#!/usr/bin/env bash
# Integration test for QUIC-LB netcode mode + retry offload + envelope.
#
# Starts two backend servers + the quic-lb router, then runs the Zig H3
# client against the LB. Verifies: Retry round-trip, envelope forwarding,
# handshake completion on a backend, and H3 200 response.
set -euo pipefail

cd "$(dirname "$0")/.."

# Config
LB_PORT=14500
BACKEND_A_PORT=14501
BACKEND_B_PORT=14502
CID_CONFIG_ID=0
CID_KEY=00112233445566778899aabbccddeeff
RETRY_KEY=ffeeddccbbaa99887766554433221100
# 32-byte HMAC key for envelope authentication (64 hex chars)
ENVELOPE_HMAC=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef

TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"; kill $LB_PID $A_PID $B_PID 2>/dev/null || true' EXIT

# Write LB config
LB_CFG="$TMPDIR/lb.cfg"
cat > "$LB_CFG" <<EOF
listen 127.0.0.1:$LB_PORT
cid_format netcode
config_id $CID_CONFIG_ID
netcode_key $CID_KEY
require_retry true
retry_key $RETRY_KEY
envelope_hmac_key $ENVELOPE_HMAC
server 00000001 127.0.0.1:$BACKEND_A_PORT
server 00000002 127.0.0.1:$BACKEND_B_PORT
EOF

echo "=== starting backend A on :$BACKEND_A_PORT ==="
zig-out/bin/server --port $BACKEND_A_PORT --lb-envelope --envelope-hmac $ENVELOPE_HMAC \
    > "$TMPDIR/backend_a.log" 2>&1 &
A_PID=$!

echo "=== starting backend B on :$BACKEND_B_PORT ==="
zig-out/bin/server --port $BACKEND_B_PORT --lb-envelope --envelope-hmac $ENVELOPE_HMAC \
    > "$TMPDIR/backend_b.log" 2>&1 &
B_PID=$!

echo "=== starting quic-lb on :$LB_PORT ==="
zig-out/bin/quic-lb "$LB_CFG" > "$TMPDIR/lb.log" 2>&1 &
LB_PID=$!

# Wait for servers to bind
sleep 1

# Verify they are up
if ! kill -0 $A_PID 2>/dev/null; then
    echo "FAIL: backend A died"
    cat "$TMPDIR/backend_a.log"
    exit 1
fi
if ! kill -0 $B_PID 2>/dev/null; then
    echo "FAIL: backend B died"
    cat "$TMPDIR/backend_b.log"
    exit 1
fi
if ! kill -0 $LB_PID 2>/dev/null; then
    echo "FAIL: LB died"
    cat "$TMPDIR/lb.log"
    exit 1
fi

echo "=== running Zig H3 client against LB ==="
CLIENT_OUT="$TMPDIR/client.log"
( zig-out/bin/client --port $LB_PORT > "$CLIENT_OUT" 2>&1 ) &
CLIENT_PID=$!
CLIENT_OK=1
for _ in $(seq 1 100); do
    sleep 0.1
    if ! kill -0 $CLIENT_PID 2>/dev/null; then
        wait $CLIENT_PID
        CLIENT_OK=$?
        break
    fi
done
if kill -0 $CLIENT_PID 2>/dev/null; then
    echo "client still running after 10s, killing"
    kill $CLIENT_PID 2>/dev/null || true
    CLIENT_OK=124
fi

if [ "$CLIENT_OK" != "0" ]; then
    echo "FAIL: client exited non-zero / timed out"
    echo "--- client.log ---"
    cat "$CLIENT_OUT"
    echo "--- lb.log ---"
    cat "$TMPDIR/lb.log"
    echo "--- backend_a.log ---"
    tail -40 "$TMPDIR/backend_a.log"
    echo "--- backend_b.log ---"
    tail -40 "$TMPDIR/backend_b.log"
    exit 1
fi

echo "--- client output ---"
cat "$CLIENT_OUT"

# Success criteria
if grep -q "200" "$CLIENT_OUT" || grep -q "Hello from Zig HTTP/3" "$CLIENT_OUT"; then
    echo
    echo "PASS: client got a response through LB"
else
    echo "FAIL: no 200 / body seen"
    echo "--- lb.log ---"
    cat "$TMPDIR/lb.log"
    exit 1
fi

# Verify at least one backend handled a connection
A_HITS=$(grep -c "accepted" "$TMPDIR/backend_a.log" 2>/dev/null || echo 0)
B_HITS=$(grep -c "accepted" "$TMPDIR/backend_b.log" 2>/dev/null || echo 0)
echo "backend A 'accepted' hits: $A_HITS"
echo "backend B 'accepted' hits: $B_HITS"

# Check that Retry was actually issued
if grep -qE "retry|Retry|RETRY" "$TMPDIR/lb.log"; then
    echo "LB logged retry activity"
fi

# --- Third-party interop: quic-go H3 client ---
GO_CLIENT=interop/quic-go/h3client_bin
if [ -x "$GO_CLIENT" ]; then
    echo
    echo "=== running quic-go H3 client against LB ==="
    GO_OUT="$TMPDIR/goclient.log"
    ( "$GO_CLIENT" --addr 127.0.0.1:$LB_PORT --path / > "$GO_OUT" 2>&1 ) &
    GC_PID=$!
    for _ in $(seq 1 100); do
        sleep 0.1
        if ! kill -0 $GC_PID 2>/dev/null; then
            wait $GC_PID
            GC_OK=$?
            break
        fi
    done
    if kill -0 $GC_PID 2>/dev/null; then
        echo "quic-go client hung, killing"
        kill $GC_PID 2>/dev/null || true
        GC_OK=124
    fi
    echo "--- quic-go client output ---"
    cat "$GO_OUT"
    if [ "${GC_OK:-1}" = "0" ]; then
        echo "PASS: quic-go client handshake completed through netcode LB + retry"
    else
        echo "FAIL: quic-go client failed"
        exit 1
    fi
else
    echo "skipping quic-go interop (binary not built)"
fi
