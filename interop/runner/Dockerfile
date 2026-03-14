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

# Pre-fetch libxev dependency (curl works with Docker DNS; zig fetch sometimes doesn't)
RUN mkdir -p /root/.cache/zig && \
    curl -L -o /tmp/libxev.tar.gz https://github.com/mitchellh/libxev/archive/d398cba9bf711fa4dd21c48bf73d25e4d8986408.tar.gz && \
    zig fetch --global-cache-dir /root/.cache/zig /tmp/libxev.tar.gz && \
    rm /tmp/libxev.tar.gz

# Build interop binaries
RUN zig build -Doptimize=ReleaseSafe --global-cache-dir /root/.cache/zig

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
