#!/usr/bin/env bash
# Build the quic-zig MoQ interop client image.
#
#   interop/moq-runner/build_image.sh [client-tag] [relay-tag]
#
# See interop/runner/build_image.sh for why the binary is cross-compiled on
# the host instead of inside the image.
set -euo pipefail

cd "$(dirname "$0")/../.."
CLIENT_TAG=${1:-quic-zig-moq-client:latest}
RELAY_TAG=${2:-quic-zig-moq-relay:latest}
STAGE=$(mktemp -d)
trap 'rm -rf "$STAGE"' EXIT

echo "=== Cross-compiling for x86_64-linux ==="
zig build moq-interop -Doptimize=ReleaseSafe -Dtarget=x86_64-linux-gnu -j1 --prefix "$STAGE"

cp interop/moq-runner/entrypoint-client.sh "$STAGE/entrypoint-client.sh"
cp interop/moq-runner/entrypoint-relay.sh "$STAGE/entrypoint-relay.sh"

echo "=== Packaging $CLIENT_TAG ==="
cp interop/moq-runner/Dockerfile "$STAGE/Dockerfile"
docker build --platform linux/amd64 -t "$CLIENT_TAG" "$STAGE"

echo "=== Packaging $RELAY_TAG ==="
cp interop/moq-runner/Dockerfile.relay "$STAGE/Dockerfile"
docker build --platform linux/amd64 -t "$RELAY_TAG" "$STAGE"

echo "=== Built $CLIENT_TAG and $RELAY_TAG ==="
