# QUIC Load Balancing — Implementation Status

This repository ships two load-balancing modes. Neither is an RFC; the draft
series `draft-ietf-quic-load-balancers` expired without publication.

## Draft-20 compatible mode

Target: [draft-ietf-quic-load-balancers-20](https://datatracker.ietf.org/doc/html/draft-ietf-quic-load-balancers-20).

| Section | Feature | Status | Notes |
|---|---|---|---|
| 3 | Routable CID format | ✅ Done | First-octet `{config_id:3, length:5}` encoding |
| 4.1 | Plaintext CIDs | ✅ Done | `key == null` config |
| 4.2 | Encrypted CIDs (block-aligned) | ✅ Done | Single-pass AES-128-ECB when payload == 16 bytes |
| 4.3 | Encrypted CIDs (non-block-aligned) | ✅ Done | 4-pass Feistel, matching draft §4.3 |
| 5 | Fallback routing | ⚠️ Partial | Round-robin for client-random DCIDs; no deterministic fallback |
| 6 | Config rotation | ⚠️ Partial | `config_id` field honored, but only one config loaded at a time |
| 7 | Retry Service | ❌ Not in draft-20 mode | Covered in netcode mode only |

## Netcode mode (proprietary)

Netcode mode is not tied to any draft. It's a smaller fixed-layout format with
additional LB-side features (retry offload, envelope framing) that only make
sense when both sides of the LB boundary are under one operator.

| Feature | Status | Source |
|---|---|---|
| Fixed 17-byte CID, AES-128-ECB single-block | ✅ | `src/quic/quic_lb.zig` — `NetcodeConfig`, `generateNetcodeCid`, `decodeNetcodeCid`, `extractNetcodeServerId` |
| First-octet length self-encoding invariant | ✅ | Preserved from draft — LB can parse any short-header |
| Structured 4-byte server_id | ✅ | Caller interprets; useful for matchmaker mint-CID |
| Retry service (LB-side token mint/validate) | ✅ | `RetryService`, `mintToken`, `consumeToken` |
| AES-128-GCM token format with key_id + timestamp + address binding | ✅ | `key_id(1) \|\| nonce(12) \|\| AEAD(plaintext, AAD=key_id) \|\| tag(16)` |
| Current + previous key rotation | ✅ | `RetryService.init(alloc, current, previous, ...)` |
| LB↔backend envelope framing | ✅ | `src/quic/lb_envelope.zig` |
| HMAC-SHA256 envelope authentication | ✅ | Optional, 32-byte key |
| ODCID injection into backend transport params | ✅ | `ConnectionManager.recvDatagram` strips envelope, passes to `acceptConnection` |
| Matchmaker-mintable CID | ✅ | `generateNetcodeCid` exposed through `quic.quic_lb` public API |
| Client-side custom initial DCID | ❌ | Not wired into Zig client CLI yet |

## Replay model

The Retry Service *intentionally permits* multiple consumes of the same
token within its validity window. RFC 9000 §17.2.5.1 requires clients to
retransmit the retried Initial with the same token, so strict nonce-based
replay rejection would break loss recovery. The security boundary is:

- In-token address binding rejects tokens used from a different client IP.
- Token timestamp + `max_age_ns` (default 10s) bounds reuse temporally.
- AEAD tag rejects any tampering.

If per-session stricter replay is needed, layer session tracking above the
token — don't tighten the token itself.

## Interop validated (as of 2026-04-14)

| Client | Mode | Outcome |
|---|---|---|
| Zig H3 client | netcode + retry + envelope HMAC | ✅ H3 200 |
| quic-go H3 client | netcode + retry + envelope HMAC | ✅ H3 200 |
| quiche H3 client | — | Not tested (bundled quiche client is plain-QUIC, not H3) |

Reproducer: `tools/test_lb_retry.sh`.

## Known gaps / deferred

1. **Config rotation**: the LB config file parses only one `config_id` at a time. Operating a fleet through a key roll requires running old + new configs in parallel on separate LBs.
2. **Deterministic fallback routing** (draft §5): client-random DCIDs in first Initial packets fall back to round-robin. For full determinism, implement DCID-hash fallback.
3. **Third-party backends**: `--lb-envelope` is a quic-zig feature. Backends running quiche/nginx/msquic cannot participate in retry offload because they won't understand the envelope; they can still be routed to normally.
4. **Client-side mint-CID plumbing**: `quic_lb.generateNetcodeCid` is exposed, but the Zig client CLI doesn't yet accept an `--initial-dcid` flag. Required to complete the matchmaker handoff pattern.

## References

- [draft-ietf-quic-load-balancers-20](https://datatracker.ietf.org/doc/html/draft-ietf-quic-load-balancers-20) — base CID format, expired.
- RFC 9000 §7.3 (retry_source_connection_id, original_destination_connection_id)
- RFC 9000 §8.1.2 (Retry token address validation)
- RFC 9001 §5.8 (Retry integrity tag)
