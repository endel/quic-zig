#!/bin/bash
# Local interop test suite — tests event-loop-based Zig servers against Go/quiche
set -e

cd "$(dirname "$0")/.."

PASS=0
FAIL=0
RESULTS=""

# Use different ports to avoid bind conflicts between tests
NEXT_PORT=14400

# Kill any leftover processes from a previous run
lsof -i UDP:14400-14420 2>/dev/null | grep -v COMMAND | awk '{print $2}' | sort -u | xargs kill -9 2>/dev/null || true
sleep 0.5

ZIG_SERVER=./zig-out/bin/server
ZIG_WT_SERVER=./zig-out/bin/wt-server
ZIG_CLIENT=./zig-out/bin/client
ZIG_WT_CLIENT=./zig-out/bin/wt-client

GO_H3_CLIENT=./interop/quic-go/h3client_bin
GO_H3_SERVER=./interop/quic-go/h3server_bin
GO_WT_CLIENT=./interop/quic-go/wt_client_bin
GO_WT_SERVER=./interop/quic-go/wt_server_bin
GO_CLIENT=./interop/quic-go/client_bin
GO_SERVER=./interop/quic-go/server_bin

QUICHE_CLIENT=./interop/quiche/target/release/client
QUICHE_SERVER=./interop/quiche/target/release/server

CERT=interop/certs/server.crt
KEY=interop/certs/server.key

SERVER_PID=""

cleanup() {
    if [ -n "$SERVER_PID" ]; then
        kill -9 $SERVER_PID 2>/dev/null || true
        wait $SERVER_PID 2>/dev/null || true
        SERVER_PID=""
    fi
}
trap cleanup EXIT

run_test() {
    local name="$1"
    local server_cmd="$2"
    local client_cmd="$3"
    local expect_pattern="$4"
    local sleep_time="${5:-1.5}"

    local PORT=$NEXT_PORT
    NEXT_PORT=$((NEXT_PORT + 1))

    # Substitute __PORT__ in commands
    server_cmd="${server_cmd//__PORT__/$PORT}"
    client_cmd="${client_cmd//__PORT__/$PORT}"

    echo ""
    echo "=== TEST: $name (port $PORT) ==="

    # Start server
    eval "$server_cmd" >/tmp/interop_server.log 2>&1 &
    SERVER_PID=$!
    sleep "$sleep_time"

    # Check server is alive
    if ! kill -0 $SERVER_PID 2>/dev/null; then
        echo "  FAIL: server failed to start"
        cat /tmp/interop_server.log | head -10
        FAIL=$((FAIL + 1))
        RESULTS="$RESULTS\n  FAIL  $name (server crash)"
        SERVER_PID=""
        return
    fi

    # Run client
    local output
    output=$(eval "$client_cmd" 2>&1) || true

    # Stop server
    kill -9 $SERVER_PID 2>/dev/null || true
    wait $SERVER_PID 2>/dev/null || true
    SERVER_PID=""

    # Check result
    if echo "$output" | grep -qi "$expect_pattern"; then
        echo "  PASS"
        PASS=$((PASS + 1))
        RESULTS="$RESULTS\n  PASS  $name"
    else
        echo "  FAIL: expected pattern '$expect_pattern' not found"
        echo "  Client output (last 10 lines):"
        echo "$output" | tail -10
        echo "  Server log (last 10 lines):"
        cat /tmp/interop_server.log | tail -10
        FAIL=$((FAIL + 1))
        RESULTS="$RESULTS\n  FAIL  $name"
    fi
}

echo "============================================"
echo "  quic-zig local interop tests (event-loop)"
echo "============================================"

# --- H3 tests (event-loop servers) ---

run_test "Go H3 client → Zig H3 server (event-loop)" \
    "$ZIG_SERVER --port __PORT__" \
    "$GO_H3_CLIENT --addr localhost:__PORT__" \
    "Hello from Zig HTTP/3 server"

run_test "Zig H3 client → Go H3 server" \
    "$GO_H3_SERVER --addr localhost:__PORT__ --cert $CERT --key $KEY" \
    "$ZIG_CLIENT --port __PORT__" \
    ":status: 200"

# --- WebTransport tests (event-loop servers) ---

run_test "Go WT client → Zig WT server (event-loop)" \
    "$ZIG_WT_SERVER --port __PORT__" \
    "$GO_WT_CLIENT --addr localhost:__PORT__" \
    "completed successfully"

run_test "Zig WT client → Go WT server" \
    "$GO_WT_SERVER --addr localhost:__PORT__ --cert $CERT --key $KEY" \
    "$ZIG_WT_CLIENT --port __PORT__" \
    "Echo:"

# --- Raw QUIC echo tests (Go hq-interop) ---

run_test "Go QUIC client → Go QUIC server (baseline)" \
    "$GO_SERVER --addr localhost:__PORT__ --cert $CERT --key $KEY" \
    "$GO_CLIENT --addr localhost:__PORT__" \
    "received"

# --- quiche (Rust) raw QUIC echo tests ---

run_test "quiche client → Go QUIC server" \
    "$GO_SERVER --addr localhost:__PORT__ --cert $CERT --key $KEY --alpn hq-interop" \
    "$QUICHE_CLIENT --addr 127.0.0.1:__PORT__ --alpn hq-interop" \
    "received"

# NOTE: Go client → quiche server has a known version negotiation issue
# (quiche reports UnknownVersion). Skipped.
# run_test "Go QUIC client → quiche server" \
#     "$QUICHE_SERVER --addr 127.0.0.1:__PORT__ --cert $CERT --key $KEY --alpn hq-interop" \
#     "$GO_CLIENT --addr localhost:__PORT__ --alpn hq-interop" \
#     "received"

# --- Summary ---

echo ""
echo "============================================"
echo "  RESULTS"
echo "============================================"
echo -e "$RESULTS"
echo ""
echo "  Total: $((PASS + FAIL))  Pass: $PASS  Fail: $FAIL"
echo "============================================"

if [ $FAIL -gt 0 ]; then
    exit 1
fi
