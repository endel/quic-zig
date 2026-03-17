# Priorities

## 1. Spec Gaps (Core RFCs)

### RFC 9000 — Partial items
- §7.4.1 — 0-RTT transport parameter remember/restore (needed for real 0-RTT)
- §6.2 — Version Negotiation retry (client doesn't retry with different version)
- §9.3.3 — Off-path packet forwarding countermeasures
- §10.1.2 — Idle timeout deferring edge cases
- §14.2.1/14.3.3/14.4.1 — ICMP handling + PMTU probes with SCID (platform-limited)

### RFC 9001 — Partial items
- §4.4 — Certificate revocation checking (CRL/OCSP)
- §4.9.2 — Post-handshake authentication

### RFC 9114 — Remaining
- §4.6 — Server Push (PUSH_PROMISE, CANCEL_PUSH, MAX_PUSH_ID) — large, deprecated in practice
- §3.3 — Connection Reuse

## 2. Performance

### Worth Fixing (high ROI, low risk)
- **Padding byte-by-byte loop** (`packet_packer.zig:551-567`) — Initial packets write 1000+ padding bytes one at a time via `writeByte(0x00)`. Replace with `@memset`. Trivial fix.
- **Active stream tracking** (`packet_packer.zig:471-500`) — Every outgoing packet iterates ALL uni send streams to find ones with data. Add a counter/flag to skip when no streams have pending data (the common case).
- **Stream scheduling double-pass** (`stream.zig:802-856`) — Two full iterations over all streams per packet for priority scheduling. Cache min-urgency and reduce to single pass.

### Worth Considering (good ROI, needs design)
- **Shrink SentPacket struct** (`ack_handler.zig`) — Currently ~1250 bytes due to embedded `[48]StreamFrameInfo` array. Moving stream frame info to a separate slab and storing only a pointer/index would reduce it to ~50 bytes, dramatically improving HashMap cache locality. Ring buffer replacement was evaluated and rejected: 960KB fixed memory per connection (vs ~30KB typical HashMap) with marginal iteration gains.
- **FrameSorter per-chunk allocations** (`stream.zig:41-146`) — Every out-of-order STREAM frame triggers `allocator.dupe()` + HashMap put. On lossy networks this is hot. A ring buffer or slab would help but changes buffer semantics (fixed max size).

## 3. Future Extensions (Nice to Have)
- **ACK Frequency** (draft-ietf-quic-ack-frequency) — sender-controlled ACK timing via ACK_FREQUENCY + IMMEDIATE_ACK frames, `min_ack_delay` transport param. Reduces CPU overhead and reverse-path congestion on asymmetric links.
- **Multipath QUIC** (draft-ietf-quic-multipath) — simultaneous use of multiple network paths
