# syntax=docker/dockerfile:1
# Stage 1: Build quic-zig binaries
FROM ubuntu:24.04 AS builder

RUN apt-get update && apt-get install -y curl xz-utils && rm -rf /var/lib/apt/lists/*

# Download and install Zig 0.16.0 (architecture-aware)
ARG TARGETARCH
RUN ZIG_ARCH=$(case "$TARGETARCH" in arm64) echo "aarch64";; *) echo "x86_64";; esac) && \
    curl -L https://ziglang.org/download/0.16.0/zig-${ZIG_ARCH}-linux-0.16.0.tar.xz | tar -xJ -C /opt && \
    ln -s /opt/zig-${ZIG_ARCH}-linux-0.16.0/zig /usr/local/bin/zig

WORKDIR /src

# Manifest before sources, so editing a .zig file does not re-fetch the world.
COPY build.zig build.zig.zon ./

# Pre-fetch libxev dependency (curl works with Docker DNS; zig fetch sometimes doesn't)
RUN --mount=type=cache,target=/root/.cache/zig,sharing=locked \
    curl -L -o /tmp/libxev.tar.gz https://github.com/mitchellh/libxev/archive/a82a04eabb46.tar.gz && \
    zig fetch --global-cache-dir /root/.cache/zig /tmp/libxev.tar.gz && \
    rm /tmp/libxev.tar.gz

COPY src ./src
COPY apps ./apps

# Build interop binaries. The `interop` step builds only the four this image
# ships; the default step builds all 24 apps and most of that is waste here.
# `-j1` keeps peak RAM usage low (builds roll through exe targets sequentially)
# so this works in tight CI/Docker VMs — a full parallel build peaks near 12 GB.
#
# Both Zig caches are BuildKit cache mounts, so a source change recompiles only
# what it touched instead of paying the full ~25 min ReleaseSafe build. They
# outlive the image, so `docker build --no-cache` still reuses them; add
# `docker builder prune` to force a cold compile.
RUN --mount=type=cache,target=/root/.cache/zig,sharing=locked \
    --mount=type=cache,target=/src/.zig-cache,sharing=locked \
    zig build interop -Doptimize=ReleaseSafe --global-cache-dir /root/.cache/zig -j1

# Stage 2: Runtime image based on quic-network-simulator endpoint
FROM martenseemann/quic-network-simulator-endpoint:latest

# Copy built binaries
COPY --from=builder /src/zig-out/bin/interop-server /usr/local/bin/interop-server
COPY --from=builder /src/zig-out/bin/interop-client /usr/local/bin/interop-client
COPY --from=builder /src/zig-out/bin/interop-wt-server /usr/local/bin/interop-wt-server
COPY --from=builder /src/zig-out/bin/interop-wt-client /usr/local/bin/interop-wt-client

# Copy entrypoint script
COPY interop/runner/run_endpoint.sh /run_endpoint.sh
RUN chmod +x /run_endpoint.sh

ENTRYPOINT ["/run_endpoint.sh"]
