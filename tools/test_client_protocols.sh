#!/bin/bash
# Integration tests for event_loop.Client protocol support
# Tests H3 and raw QUIC clients against Zig and Go servers.
set -e

PASS=0
FAIL=0
BASE_PORT=14450

cleanup() {
    # Kill any lingering test servers
    kill $SERVER_PID 2>/dev/null || true
    wait $SERVER_PID 2>/dev/null || true
}
trap cleanup EXIT

run_test() {
    local name="$1"
    local server_cmd="$2"
    local client_cmd="$3"
    local expected="$4"
    local port=$((BASE_PORT++))

    # Substitute PORT placeholder
    server_cmd="${server_cmd//PORT/$port}"
    client_cmd="${client_cmd//PORT/$port}"

    echo -n "  $name ... "

    # Start server
    eval "$server_cmd" &
    SERVER_PID=$!
    sleep 1

    # Run client with timeout
    output=$(perl -e "alarm 5; exec @ARGV" $client_cmd 2>&1) || true

    # Kill server
    kill $SERVER_PID 2>/dev/null || true
    wait $SERVER_PID 2>/dev/null || true

    if echo "$output" | grep -q "$expected"; then
        echo "PASS"
        PASS=$((PASS + 1))
    else
        echo "FAIL (expected '$expected')"
        echo "    Output: $(echo "$output" | grep -E 'Response|Error|error' | head -3)"
        FAIL=$((FAIL + 1))
    fi
}

echo "Building..."
zig build 2>&1

echo ""
echo "=== H3 Client Tests ==="

run_test "Zig H3 client -> Zig H3 server" \
    "zig-out/bin/server --port PORT" \
    "zig-out/bin/h3-client --port PORT" \
    "Hello from Zig HTTP/3 server"

run_test "Zig H3 client -> Go H3 server" \
    "interop/quic-go/h3server_bin --addr localhost:PORT" \
    "zig-out/bin/h3-client --port PORT --insecure" \
    "Hello from Go HTTP/3 server"

run_test "Go H3 client -> Zig H3 server" \
    "zig-out/bin/server --port PORT" \
    "interop/quic-go/h3client_bin --addr localhost:PORT" \
    "Hello from Zig HTTP/3 server"

echo ""
echo "=== Raw QUIC Client Tests ==="

run_test "Zig QUIC client -> Zig QUIC server" \
    "zig-out/bin/quic-server --port PORT" \
    "zig-out/bin/quic-client --port PORT" \
    "Response on stream 0: Hello from Zig QUIC client"

run_test "Zig QUIC client -> Go QUIC server" \
    "interop/quic-go/server_bin --addr localhost:PORT" \
    "zig-out/bin/quic-client --port PORT --insecure" \
    "Response on stream 0: Hello from Zig QUIC client"

run_test "Go QUIC client -> Zig QUIC server" \
    "zig-out/bin/quic-server --port PORT" \
    "interop/quic-go/client_bin --addr localhost:PORT --msg 'hello from go'" \
    "OK"

echo ""
echo "=== Results: $PASS passed, $FAIL failed ==="
[ $FAIL -eq 0 ] && exit 0 || exit 1
