# Claude Code Configuration for quic-zig

## Objective
- Final objective is the implementation of core QUIC Spec: https://www.rfc-editor.org/rfc/rfc9000.txt
- Use ./interop/ client and server implementations as reference when testing specific features.
- Pass as many interoperability tests as possible (https://github.com/quic-interop/quic-interop-runner)

## Iteration over QUIC specifications
- Keep code and architecture clean, covered with tests, optimized and maintainable
- Document the state of each implementation, with their caveats of the spec under ./SPEC/[RFC_NUMBER]_[SECTION].md
- ./Keep the SPEC/STATUS.md up-to-date.
- When required to re-visit the implementation of documented pieces of
  implementation, update it under ./SPEC/[RFC_NUMBER]_[SECTION].md

## Secondary Objectives
- QUIC Loss Detection and Congestion Control (https://www.rfc-editor.org/rfc/rfc9002.txt)
- HTTP/3 (https://www.rfc-editor.org/rfc/rfc9114.txt)
- QPACK: Field Compression for HTTP/3 (https://www.rfc-editor.org/rfc/rfc9204.txt)
- HTTP Datagrams and the Capsule Protocol (https://www.rfc-editor.org/rfc/rfc9297.txt)
- Final step: The WebTransport Protocol Framework (https://www.ietf.org/archive/id/draft-ietf-webtrans-overview-11.txt)

