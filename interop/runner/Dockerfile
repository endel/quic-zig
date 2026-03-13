# syntax=docker/dockerfile:1
# Stage 1: Build quic-zig binaries
FROM ubuntu:24.04 AS builder

RUN apt-get update && apt-get install -y curl xz-utils && rm -rf /var/lib/apt/lists/*

# Download and install Zig 0.15.2 (architecture-aware)
ARG TARGETARCH
RUN ZIG_ARCH=$(case "$TARGETARCH" in arm64) echo "aarch64";; *) echo "x86_64";; esac) && \
    curl -L https://ziglang.org/download/0.15.2/zig-${ZIG_ARCH}-linux-0.15.2.tar.xz | tar -xJ -C /opt && \
    ln -s /opt/zig-${ZIG_ARCH}-linux-0.15.2/zig /usr/local/bin/zig

WORKDIR /src
COPY . .

# Build interop binaries via zig build (needed for libxev dependency)
# Use --network=host so BuildKit can resolve DNS for dependency fetching
RUN --network=host zig build -Doptimize=ReleaseSafe

# Stage 2: Runtime image based on quic-network-simulator endpoint
FROM martenseemann/quic-network-simulator-endpoint:latest

# Copy built binaries
COPY --from=builder /src/zig-out/bin/interop-server /usr/local/bin/interop-server
COPY --from=builder /src/zig-out/bin/interop-client /usr/local/bin/interop-client

# Copy entrypoint script
COPY interop/runner/run_endpoint.sh /run_endpoint.sh
RUN chmod +x /run_endpoint.sh

ENTRYPOINT ["/run_endpoint.sh"]
