# syntax=docker/dockerfile:1
# Packages the binary interop/moq-runner/build_image.sh has already
# cross-compiled — do not `docker build` this directory directly.
#
# Cross-compiling on the host rather than in a builder stage is the same
# call interop/runner/Dockerfile documents: an emulated x86_64 Zig on an
# Apple-silicon host produced binaries whose ECDSA signatures no peer would
# accept.
FROM debian:bookworm-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/*

COPY bin/moq-test-client /app/moq-test-client
COPY entrypoint-client.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh /app/moq-test-client && mkdir -p /mlog

# The runner's compose file runs the client as uid 1000.
RUN useradd -r -u 1000 -g nogroup moq
USER moq

ENV RELAY_URL=https://relay:4443
# The harness sets this explicitly on both paths — 1 for its compose relay,
# whose certificate no trust store has heard of, and false for a remote. The
# default only reaches a manual run, where skipping verification silently is
# the wrong way round.
ENV TLS_DISABLE_VERIFY=0

ENTRYPOINT ["/app/entrypoint.sh"]
