# Stage 1: Build quic-zig binaries
FROM ubuntu:24.04 AS builder

RUN apt-get update && apt-get install -y curl xz-utils && rm -rf /var/lib/apt/lists/*

# Download and install Zig 0.15.2
RUN curl -L https://ziglang.org/download/0.15.2/zig-x86_64-linux-0.15.2.tar.xz | tar -xJ -C /opt && \
    ln -s /opt/zig-x86_64-linux-0.15.2/zig /usr/local/bin/zig

WORKDIR /src
COPY . .

# Build interop binaries directly (bypasses build.zig to avoid Zig 0.15.2 shuffle bug)
RUN mkdir -p zig-out/bin && \
    zig build-exe src/interop_server.zig -OReleaseSafe -lc && \
    mv interop_server zig-out/bin/interop-server && \
    zig build-exe src/interop_client.zig -OReleaseSafe -lc && \
    mv interop_client zig-out/bin/interop-client

# Stage 2: Runtime image based on quic-network-simulator endpoint
FROM martenseemann/quic-network-simulator-endpoint:latest

# Copy built binaries
COPY --from=builder /src/zig-out/bin/interop-server /usr/local/bin/interop-server
COPY --from=builder /src/zig-out/bin/interop-client /usr/local/bin/interop-client

# Copy entrypoint script
COPY interop/runner/run_endpoint.sh /run_endpoint.sh
RUN chmod +x /run_endpoint.sh

ENTRYPOINT ["/run_endpoint.sh"]
