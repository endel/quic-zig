#!/bin/bash
# WebTransport Benchmark Runner
#
# Builds optimized binaries, starts echo server, runs benchmarks, reports results.
# Methodology matches webtransport-bun for direct comparison.
#
# Usage:
#   ./tools/bench_wt.sh                    # Run all benchmarks
#   MODE=handshake ./tools/bench_wt.sh     # Run only handshake benchmark
#   ROUNDS=100 ./tools/bench_wt.sh         # 100 rounds instead of 50
#   JSON=1 ./tools/bench_wt.sh             # Include JSON output
#
# Environment variables:
#   PORT      - Server port (default: 4434)
#   MODE      - handshake|stream|datagram|all (default: all)
#   ROUNDS    - Number of rounds for handshake/stream (default: 50)
#   DURATION  - Datagram test duration in seconds (default: 10)
#   JSON      - Set to 1 for JSON output lines

set -e

PORT=${PORT:-4434}
MODE=${MODE:-all}
ROUNDS=${ROUNDS:-50}
DURATION=${DURATION:-10}

EXTRA_ARGS=""
if [ "${JSON}" = "1" ]; then
    EXTRA_ARGS="--json"
fi

cd "$(dirname "$0")/.."

echo "Building (ReleaseFast)..."
zig build -Doptimize=ReleaseFast 2>&1 | tail -1 || true

echo "Starting benchmark echo server on port $PORT..."
./zig-out/bin/bench-wt-server --port "$PORT" >/dev/null 2>&1 &
SERVER_PID=$!

cleanup() {
    if kill -0 "$SERVER_PID" 2>/dev/null; then
        kill "$SERVER_PID" 2>/dev/null || true
        wait "$SERVER_PID" 2>/dev/null || true
    fi
}
trap cleanup EXIT

# Wait for server to be ready
sleep 2

echo "Running benchmarks..."
echo ""
./zig-out/bin/bench-wt \
    --port "$PORT" \
    --mode "$MODE" \
    --rounds "$ROUNDS" \
    --duration "$DURATION" \
    $EXTRA_ARGS

echo ""
echo "Comparison reference (webtransport-bun thresholds):"
echo "  Handshake p95:       <500ms  (CI gate)"
echo "  Handshake p99:       <300ms  (target)"
echo "  Stream throughput:   >0.5 MB/s (regression gate)"
echo "  Datagram enqueue:    <10ms p99 (target)"
echo "  Stream open:         <20ms p99 (target)"
