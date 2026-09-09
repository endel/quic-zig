# syntax=docker/dockerfile:1
# Packages binaries that interop/runner/build_image.sh has already
# cross-compiled — do not `docker build` this directory directly.
#
# The binaries are built on the host because an emulated x86_64 Zig compiler
# produced a server whose ECDSA CertificateVerify no peer would accept. See
# build_image.sh for the detail.
FROM martenseemann/quic-network-simulator-endpoint:latest

COPY bin/interop-server /usr/local/bin/interop-server
COPY bin/interop-client /usr/local/bin/interop-client
COPY bin/interop-wt-server /usr/local/bin/interop-wt-server
COPY bin/interop-wt-client /usr/local/bin/interop-wt-client

COPY run_endpoint.sh /run_endpoint.sh
RUN chmod +x /run_endpoint.sh

ENTRYPOINT ["/run_endpoint.sh"]
