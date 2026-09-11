#!/usr/bin/env bash
# Build the quic-zig MoQ interop client image.
#
#   interop/moq-runner/build_image.sh [tag]
#
# See interop/runner/build_image.sh for why the binary is cross-compiled on
# the host instead of inside the image.
set -euo pipefail

cd "$(dirname "$0")/../.."
TAG=${1:-quic-zig-moq-client:latest}
STAGE=$(mktemp -d)
trap 'rm -rf "$STAGE"' EXIT

echo "=== Cross-compiling moq-test-client for x86_64-linux ==="
zig build moq-interop -Doptimize=ReleaseSafe -Dtarget=x86_64-linux-gnu -j1 --prefix "$STAGE"

echo "=== Packaging $TAG ==="
cp interop/moq-runner/entrypoint-client.sh "$STAGE/entrypoint-client.sh"
cp interop/moq-runner/Dockerfile "$STAGE/Dockerfile"
docker build --platform linux/amd64 -t "$TAG" "$STAGE"
echo "=== Built $TAG ==="
