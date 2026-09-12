# WebTransport browser tests — superseded

This document described a 13-scenario browser-only suite and recorded Chrome
9/13, Firefox 9/13, Safari 8/13, with a "Known Issues" section attributing four
of the failures to the session being finalized before the CLOSE capsule was
transmitted.

**That diagnosis was wrong.** Outgoing capsules were written bare instead of
inside an H3 DATA frame, so peers discarded them as an unknown H3 frame type and
the session ended on the FIN alone with no close code. Fixing the framing turned
all four green.

The suite has been replaced by one scenario list that the Zig client and the
browsers both run against the same server:

- **[webtransport_conformance.md](webtransport_conformance.md)** — how to run it,
  the current matrix, and what each expected failure means.
- **[webtransport_w3c_api.md](webtransport_w3c_api.md)** — which W3C API members
  browsers actually expose, and which of them the Zig client implements.
- **[DRAFT_IETF_WEBTRANS_HTTP3_13.md](DRAFT_IETF_WEBTRANS_HTTP3_13.md)** — what
  of draft-13 is implemented, including the session flow control Safari needs
  before it will open a stream.

`./tools/wt_conformance.sh` runs the whole thing.
