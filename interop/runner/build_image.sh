#!/usr/bin/env bash
# Build the quic-zig interop image.
#
#   interop/runner/build_image.sh [tag]
#
# The binaries are cross-compiled here on the host rather than inside the
# image. Two reasons, and the first is not an optimisation:
#
#  1. On an Apple-silicon host the linux/amd64 builder stage ran the x86_64 Zig
#     compiler under emulation, and the ReleaseSafe binaries it produced were
#     wrong: the server's ECDSA CertificateVerify failed to verify in every Go
#     and Rust client ("tls: invalid signature by the server certificate"), so
#     every test case failed at the handshake. The same source cross-compiled
#     from the host with the same flags is correct.
#  2. It is minutes faster — no emulated compile, and the image is a COPY.
set -euo pipefail

cd "$(dirname "$0")/../.."
TAG=${1:-quic-zig-interop:latest}
STAGE=$(mktemp -d)
trap 'rm -rf "$STAGE"' EXIT

echo "=== Cross-compiling interop binaries for x86_64-linux ==="
zig build interop -Doptimize=ReleaseSafe -Dtarget=x86_64-linux-gnu -Dcpu=x86_64_v3+aes+pclmul -j1 --prefix "$STAGE"

echo "=== Packaging $TAG ==="
cp interop/runner/run_endpoint.sh "$STAGE/run_endpoint.sh"
cp interop/runner/Dockerfile "$STAGE/Dockerfile"
docker build --platform linux/amd64 -t "$TAG" "$STAGE"
echo "=== Built $TAG ==="
