#!/bin/bash
# Run the WebTransport Interop Runner with quic-zig
#
# Usage:
#   ./interop/runner/run_wt.sh                            # handshake test, self-interop
#   ./interop/runner/run_wt.sh handshake,transfer         # specific tests
#   ./interop/runner/run_wt.sh handshake webtransport-go  # test against webtransport-go
#
# Prerequisites:
#   - Docker (with docker compose v2)
#   - Python >= 3.10 + pip install -r interop/quic-interop-runner/requirements.txt
#   - wireshark (tshark) >= 4.5.0

set -e

# Find Python >= 3.10
PYTHON=""
for py in python3.13 python3.12 python3.11 python3.10 python3; do
    if command -v "$py" &>/dev/null; then
        ver=$("$py" -c "import sys; print(sys.version_info >= (3,10))" 2>/dev/null)
        if [ "$ver" = "True" ]; then
            PYTHON="$py"
            break
        fi
    fi
done
if [ -z "$PYTHON" ]; then
    echo "Error: Python >= 3.10 required. Install with: brew install python@3.12"
    exit 1
fi
echo "Using $PYTHON ($($PYTHON --version))"

# Prefer Homebrew OpenSSL over macOS LibreSSL
if [ -d "/opt/homebrew/opt/openssl@3/bin" ]; then
    export PATH="/opt/homebrew/opt/openssl@3/bin:$PATH"
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
RUNNER_DIR="$ROOT_DIR/interop/quic-interop-runner"

TESTS="${1:-handshake}"
PEER="${2:-quic-zig}"
IMAGE_TAG="quic-zig-interop:latest"

echo "=== Building quic-zig interop Docker image ==="
docker build --network=host -t "$IMAGE_TAG" -f "$SCRIPT_DIR/Dockerfile" "$ROOT_DIR"

echo ""
echo "=== Injecting quic-zig into implementations_webtransport.json ==="

$PYTHON -c "
import json
path = '$RUNNER_DIR/implementations_webtransport.json'
with open(path) as f:
    impls = json.load(f)
impls['quic-zig'] = {
    'image': '$IMAGE_TAG',
    'url': 'https://github.com/endel/quic-zig',
    'role': 'both'
}
with open(path, 'w') as f:
    json.dump(impls, f, indent=2)
    f.write('\n')
print('  Added quic-zig to', path)
"

cd "$RUNNER_DIR"

echo ""
echo "=== Running WebTransport interop tests: $TESTS ==="

if [ "$PEER" = "quic-zig" ]; then
    echo "    quic-zig <-> quic-zig"
    $PYTHON run.py --protocol webtransport -s quic-zig -c quic-zig -t "$TESTS" -d
else
    # Pull peer image
    echo "    Pulling $PEER image..."
    $PYTHON pull.py -i "$PEER" 2>/dev/null || true

    echo "    quic-zig server <-> $PEER client"
    $PYTHON run.py --protocol webtransport -s quic-zig -c "$PEER" -t "$TESTS" -d || true

    echo ""
    echo "    $PEER server <-> quic-zig client"
    $PYTHON run.py --protocol webtransport -s "$PEER" -c quic-zig -t "$TESTS" -d || true
fi

echo ""
echo "=== Done ==="
