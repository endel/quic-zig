# quic-zig vs quic-go — full-codebase gap review (2026-06-09)

Compared against quic-go HEAD `89690bf` (2026-06-08, post-v0.60.0), cloned at the time of
review. Six subsystem-by-subsystem comparisons (loss recovery/CC, packing/framing/MTU,
connection core/paths/CIDs, streams/flow control, TLS/packet protection, I/O/server/qlog),
each verifying "we lack X" claims against our source before reporting. The highest-impact
claims were independently re-verified in `src/quic/` afterwards.

**Overall verdict:** the protocol core is in strong shape — long parity lists below, and a few
areas where we exceed quic-go. The gaps cluster in (a) loss-path completeness (control-frame
retransmission, ACK validation), (b) flow-control enforcement, (c) resource bounds (DoS), and
(d) the UDP socket layer.

---

## Tier 1 — Correctness & security

1. **ACKs for unsent packet numbers are accepted; no packet-number skipping.**
   quic-go closes with PROTOCOL_VIOLATION when `largestAcked > largestSent`
   (`sent_packet_handler.go:381-387`) and skips a random PN periodically, erroring if a skipped
   PN is ACKed (`packet_number_generator.go:36-84`); it also skips a PN on each 1-RTT PTO to
   elicit an immediate ACK. We accept any `largest_ack` (`ack_handler.zig:210-212`) and use
   strictly sequential PNs (`ack_handler.zig:547-552`). A malicious peer can poison
   `largest_acked` → the packet-threshold rule (`ack_handler.zig:287-301`) declares the whole
   window lost (retransmit storm) or inflate cwnd via optimistic ACKs (RFC 9000 §21.4).
   Fix: validate `largest_ack <= largest_sent` (S); add skipping generator + skipped-PN check (M).
   *(Found independently by two reviewers.)*

2. **Per-stream receive flow control is not enforced.** The STREAM handler checks only the
   connection window (`connection.zig:1868`); `ReceiveStream`/`FrameSorter` never check the
   stream's `receive_window`, and `StreamFlowController` in `flow_control.zig` is dead code
   (zero instantiations). RFC 9000 §4.1 requires FLOW_CONTROL_ERROR; one stream can consume
   the entire 16 MB connection window. Fix: compare `s.offset + s.data.len` against the
   stream's window in the STREAM handler. Effort S.

3. **CRYPTO stream has no offset cap — pre-auth memory DoS.** quic-go rejects crypto offsets
   beyond 16 KiB with CRYPTO_BUFFER_EXCEEDED (`crypto_stream.go:36-41`). Our
   `handleCryptoFrame` pushes into FrameSorter unbounded (`crypto_stream.zig:48-51`). Effort S.

4. **Send buffers never reclaim acknowledged bytes.** `SendStream.write_buffer` is a contiguous
   ArrayList indexed by absolute offset; `onAck` advances `ack_offset`
   (`stream.zig:441-467`) but nothing ever trims the buffer — a multi-GB transfer holds
   multi-GB in RAM. quic-go retains only unsent data + lost frames (`send_stream.go:379,666`).
   Fix: `buf_base` offset + compaction (or ring/segmented buffer); rebase index math.
   Effort L — but the most consequential memory issue for HTTP/3/WT/MoQ workloads.

5. **Incoming unidirectional streams never receive MAX_STREAM_DATA.**
   `queueFlowControlUpdates` iterates only the bidi map (`connection.zig:2838-2849`); the
   `recv_streams` map (incoming uni: H3 control/QPACK, WT uni, MoQ subscribes) only gets credit
   reactively on STREAM_DATA_BLOCKED. Those streams stall permanently after the initial 1 MB.
   Fix: second loop over `recv_streams` calling `getWindowUpdate()`. Effort S.

6. **Stateless reset is effectively dead in both directions.** Each `Connection.accept()`
   generates a random `static_reset_key` (`connection.zig:808`) for advertised tokens, while
   `ConnectionManager` emits resets with its own key (`connection_manager.zig:108,325`) — so
   resets we emit never match tokens we advertised. And `matchesStatelessReset`
   (`connection.zig:4104`) has no callers outside tests, so we never *detect* a peer's reset
   (hang until idle timeout). quic-go shares one resetter per Transport (`transport.go:417,648-665`)
   and checks tokens on undecryptable short-header packets (`connection.go:1198-1209`).
   Fix: inject the manager's key into `accept()`; call `matchesStatelessReset` from the recv
   path when short-header decryption fails (len ≥ 21). Effort S/M.

7. **Lost control frames are never retransmitted (RFC 9000 §13.3 violation).** `SentPacket`
   records only stream ranges + crypto/handshake_done/datagram flags (`ack_handler.zig:54-89`);
   control frames are popped one-shot from `PendingFrameQueue` (`packet_packer.zig:419-436`).
   Lost RESET_STREAM, STOP_SENDING, NEW/RETIRE_CONNECTION_ID, NEW_TOKEN, MAX_STREAMS,
   ACK_FREQUENCY are gone forever → peer hangs on half-closed streams, CID-pool starvation,
   MAX_STREAMS deadlock. quic-go re-queues lost frames via per-frame `OnLost` handlers
   (`retransmission_queue.go:139-158`). Fix: record popped control frames (value types) in
   `SentPacket`, re-push on loss/PTO. Effort M.

8. **Coalesced datagrams can exceed 1200 bytes before address validation.** Each
   `packSinglePacket` is capped at `max_packet_size` but the *sum* in `packCoalesced` is only
   bounded by the 1500-byte out buffer (`packet_packer.zig:120-234`; verified). Client 0-RTT
   first flight: Initial padded to 1200 + appended 0-RTT ≈ 1480 B; server Initial+Handshake can
   reach ~1370 B. Violates RFC 9000 §14 → handshake blackholes on 1280–1400-MTU paths (PTO
   retransmits are equally oversized). Related edge case: Initial padding is pre-decided, so an
   empty Handshake companion can leave an ack-eliciting Initial datagram < 1200 (§14.1 discard).
   Fix: thread a datagram budget `min(out_buf.len, max_packet_size)` through `packCoalesced`;
   post-coalesce pad-to-1200 fixup. Effort S/M (one refactor fixes both).

9. **AEAD limits and key-update violations are not enforced (RFC 9001 §6).**
   (a) No failed-decryption counter → never closes with AEAD_LIMIT_REACHED (quic-go:
   `updatable_aead.go:182-194`; limits 2^52 AES / 2^36 ChaCha). The error code exists in
   `packet.zig:156` but is never raised. (b) `key_update_error` (0x0e) never raised: a peer
   updating keys before our update is acked is tolerated silently
   (`crypto.zig:750-761`, `connection.zig:1277`) instead of closing (quic-go
   `updatable_aead.go:230-300`). Fix: counters in `KeyUpdateManager` + the two §6 checks. Effort M.

10. **Invalid/stale address tokens deadlock the handshake.** Any token failing both
    `validateRetryToken` and `validateNewToken` causes the Initial to be *dropped*
    (`connection_manager.zig:355-371`) — a client re-presenting a stale NEW_TOKEN retransmits
    forever. quic-go treats an invalid non-retry token as "no token" (proceed/Retry) and answers
    an invalid retry token with INVALID_TOKEN (`server.go:720-753`). Both our token types share
    one 60 s lifetime (`packet.zig:787`; quic-go: ~10 s retry vs 24 h NEW_TOKEN) and don't carry
    RTT for seeding (`token_generator.go:73-83`). Effort M.

11. **Server ingress validation gaps (amplification/spoofing).**
    (a) Initials are accepted without checking datagram ≥ 1200 B or client DCID ≥ 8 B
    (`connection_manager.zig:317-376`; quic-go `server.go:499-513,680-694`) — spec MUST §14.1,
    lets tiny spoofed packets create connection state.
    (b) Version Negotiation is sent for arbitrarily small unknown-version packets with no rate
    limit (`connection_manager.zig:307-312`; quic-go requires ≥ 1200 B + bounded queue,
    `server.go:455-466`) — reflection vector. Both fixes are S.

12. **ECN: CE response cuts cwnd repeatedly; validation has holes.** We call
    `cc.onCongestionEvent(now, now)` on every CE-count increase (`connection.zig:1774-1777`), so
    consecutive CE-bearing ACKs cut 0.7× each — violating RFC 9002 §7.1 once-per-RTT (quic-go
    keys recovery on `largestSentAtLastCutback`, `cubic_sender.go:199-224`). Validation: ACKs
    *without* ECN counts never reach the validator (bleaching never detected →
    we keep marking forever), no lost-testing-packet/mangling checks, and we keep marking in
    `unknown` state (`ecn.zig:46-51`; quic-go `internal/ackhandler/ecn.go:122-318`). Also only
    process ECN counts when largest_acked increases. Effort S (CE dedupe) + M (validation).

13. **Path migration gaps.** PATH_RESPONSE is queued into `pending_frames` and goes out on the
    *active* path (`connection.zig:2094-2096`) — make-before-break probing (quic-go's
    `Path.Probe` API, browsers) can never validate. Path switch ignores the highest-PN rule
    (RFC 9000 §9.3; `handleMigration` at `connection.zig:3235-3259` — spoofed/duplicated old
    packets can yank the connection; we already track `largest_pn_received`). PATH_CHALLENGE /
    PATH_RESPONSE datagrams are not expanded to 1200 B (§8.2.1-8.2.2 MUST; padding only applies
    to long headers, `packet_packer.zig:578`). quic-go: per-address path entries each with own
    CID, probes sent to the probed address, switch only when
    `validated && rcvdNonProbing && pn == largestRcvdAppData` (`path_manager.go:66-148`).
    Effort M/L.

14. **DATAGRAM size contract violated.** We advertise `max_datagram_frame_size = 65536`
    (`event_loop.zig:36,1135`) but the queue's fixed slots cap payloads at 1200: larger incoming
    datagrams are *silently dropped* (`connection.zig:330,391`) and `sendDatagram` rejects
    > 1200 (`connection.zig:3751`). quic-go advertises 16383, enforces on receive with
    PROTOCOL_VIOLATION, sizes sends from MTU (`connection.go:2142-2147,3033-3040`; v0.60.0 fixed
    post-PMTUD sizing, #5650). Fix: advertise what we accept, or size buffers from negotiation +
    MTU. Effort M.

## Tier 2 — Performance

1. **No UDP socket buffer sizing.** quic-go bumps SO_RCVBUF/SO_SNDBUF to 7 MB with
   force-fallback + once-only warning (`sys_conn_buffers.go:14-68`). We set neither
   (`event_loop.zig:382-416`): default kernel buffers (~200 KB Linux / ~786 KB darwin) overflow
   at QUIC bandwidth in a single-threaded loop; drops read as congestion loss. Cheapest big win. S.

2. **App-limited check permanently stalls cwnd growth.** We snapshot
   `app_limited = bytes_in_flight < cwnd` (`connection.zig:1510,1640`) and skip growth when set
   (`congestion.zig:102,251`). Once cwnd stops being an exact packet multiple (any odd-size
   ack-eliciting packet), `in_flight < cwnd` holds at every ACK → cwnd never grows. quic-go
   treats "available ≤ 3×MDS" as cwnd-limited, plus a slow-start half-window rule
   (`cubic_sender.go:267-275`). S.

3. **Pacer burst fixed at 12 KB.** Computed once (`congestion.zig:442-448`), never rescaled by
   bandwidth or PMTUD. With ~1 ms timer granularity that's a ~96 Mbit/s ceiling. quic-go:
   `max(bandwidth × 2 ms, 10 pkts)` + 1 ms min pacing delay (`pacer.go:64-69,105`). S.

4. **PTO retransmits the whole unacked window (and full crypto stream).** On app PTO every
   stream re-queues `ack_offset..write_offset` (`connection.zig:3488-3503`), and crypto
   retransmission rewinds to offset 0 including acked data (`connection.zig:1463-1473`).
   quic-go probes with only the *first outstanding packet's* frames
   (`sent_packet_handler.go:1041-1054`) and splits lost CRYPTO frames. One spurious PTO on a
   high-BDP path re-sends ~a full cwnd. Fix: per-packet crypto ranges (like `StreamFrameInfo`),
   probe = oldest unacked packet's frames. M.

5. **DF bit never set → PMTUD results are invalid; send errors ignored.** Without
   IP_DONTFRAG / IP_PMTUDISC_PROBE (quic-go `sys_conn_df_{darwin,linux}.go`), oversized probes
   may be *fragmented* and still arrive — converging on an MTU the path can't carry unfragmented
   (blackhole later). All `sendmsg` results are discarded (`ecn_socket.zig:268,297`), so
   EMSGSIZE can't inform the search and real failures (ENOBUFS, EPERM) are invisible. M.

6. **MTU probes starve during continuous transfer.** Probes only fire when the regular packer
   wrote nothing (`connection.zig:3149-3170` `bytes_written == 0` guard) — a busy sender stays
   at 1200 forever, exactly when bigger MTU matters. Probe-loss convergence is ≥15 RTTs per
   halving (re-probe same size ×3, 5×SRTT apart, `mtu.zig:122-142`); search max isn't clamped to
   peer `max_udp_payload_size`. quic-go interleaves probes with normal sends and bisects on
   tracked lost sizes (`mtu_discoverer.go:90-177`). M.

7. **Datagram frames packed after stream data.** Bulk stream transfer squeezes out
   latency-sensitive WT/MoQ datagrams until they expire (`packet_packer.zig:444-546`); quic-go
   packs the DATAGRAM right after the ACK, before stream data (`packet_packer.go:653-668`). S.

8. **Flow-control window updates too late, auto-tune too eager.** Updates fire at ~75% consumed
   (`flow_control.zig:100`, `stream.zig:316`) vs quic-go's 25% (`base_flow_controller.go:73-77`)
   — high-BDP senders stall on credit. Auto-tuning computes `srtt` then ignores it, doubling on
   nearly every update (`flow_control.zig:115-138`) vs quic-go's growth only when consumption
   outpaces `4×fraction×rtt` (`base_flow_controller.go:104-110`); add the 1.5× conn/stream
   coupling (`connection_flow_controller.go:82-97`) once windows actually float. S.

9. **No PING after consecutive non-ack-eliciting packets → unbounded sent-packet state.** A
   download-only peer never ACKs us, so app-space `sent_packets` grows forever and ACK-of-ACK
   pruning never fires (`packet_packer.zig:548-551` deliberately sends none;
   `ack_handler.zig:187-196`). quic-go PINGs every 20th ACK-only packet
   (`packet_packer.go:608-623`) — counter-based, no ping-pong loop. Also: don't store
   non-in-flight packets, or purge below `largest_acked`. S.

10. **No hybrid slow start.** Slow start exits only on loss → overshoot + deep cut on
    large-buffer paths. quic-go: HyStart delay-increase exit (`hybrid_slow_start.go:52-87`). M.

11. **Linux I/O batching.** No GSO (`UDP_SEGMENT`, one 20 KB buffer per sendmsg burst —
    quic-go's dominant send-path win, with EIO fallback, `sys_conn_helper_linux.go:64-119`) and
    no recvmmsg (batch 8, `sys_conn_oob.go:36-179`). Our per-packet syscall path is the bulk
    throughput ceiling on Linux. L (GSO) / M (recvmmsg). Also S: skip the plaintext `tmp` →
    `out_buf` copy in `packSinglePacket` (`packet_packer.zig:257-261,599-615`) by serializing +
    sealing in place, and attach ECN as per-packet cmsg instead of socket-wide setsockopt
    (`ecn_socket.zig:88-95` — marks can leak across conns sharing the server socket).

12. **Smaller wins:** RTT sample from Retry (`sent_packet_handler.go:1093-1104`) and from
    NEW_TOKEN tokens; immediate ACKs for Initial/Handshake spaces + on ECN-CE
    (`received_packet_tracker.go:14-49,200-204`; we add up to 25 ms per handshake flight,
    `ack_handler.zig:340-393`); ack_delay only after handshake confirmed + require ack-eliciting
    newly-acked for RTT samples (`ack_handler.zig:241-244`); don't arm app-space PTO before
    handshake confirmed (`ack_handler.zig:647-678`); strip the length field from the last STREAM
    frame (`framer.go:147-152`); optional 32-packet initial cwnd (quic-go default,
    `cubic_sender.go:20`); restart idle timer on first ack-eliciting send after idle
    (`connection.go:906-912`).

## Tier 3 — Robustness / DoS hardening

1. **Received-packet RangeSet unbounded** — peer sending every other PN ⇒ one range per 2
   packets, O(n) scans + unbounded memory (`ack_handler.zig:356-358`). quic-go caps at 64 ranges
   (`received_packet_history.go:39-44`). S.
2. **FrameSorter has no gap cap** — adversarial 1-byte alternating chunks ⇒ unbounded map
   entries (`stream.zig:79-174`); quic-go caps at 1000 gaps (`frame_sorter.go:172-174`). S.
3. **PendingFrameQueue overflow silently drops control frames** (cap 128,
   `frame.zig:929-933`) — a dropped PATH_RESPONSE/RESET_STREAM is protocol loss (amplified by
   T1.7). quic-go grows to 16 K then closes the connection (`framer.go:67-87`). S.
4. **CONNECTION_CLOSE retransmitted 1:1 with incoming packets** while closing
   (`connection.zig:1171-1175,2910-2919`) — amplification; quic-go uses popcount backoff
   (1st, 2nd, 4th, 8th… packet, `closed_conn.go:31-40`). S.
5. **Stateless resets computed inline, ≥22 B trigger, no rate limit**
   (`connection_manager.zig:318-330`) — per-packet HMAC under garbage flood; quic-go: > 42 B
   trigger + 4-deep drop-when-busy queue (`transport.go:628-646`). S.
6. **Malformed ACK ranges accepted via saturating arithmetic** (`frame.zig:236-248`) instead of
   FRAME_ENCODING_ERROR (`wire/ack_frame.go:60-100`). S.
7. **CID lifecycle gaps:** old DCID not retired on switch; pool overflow silently dropped
   instead of CONNECTION_ID_LIMIT_ERROR (`connection.zig:162,2063-2067`); migration's
   `consumeUnused()` can return the CID already in use (§9.5 linkability);
   RETIRE_CONNECTION_ID not validated (seq > issued / retire-the-one-you-sent-on ⇒
   PROTOCOL_VIOLATION, §19.16) and routing-map removal is immediate instead of 3×PTO-delayed
   (`connection_manager.zig:220-226`); no periodic CID rotation
   (quic-go: `conn_id_manager.go:64-236`, `conn_id_generator.go:99-171`). M.
8. **At capacity, Initials are silently dropped** (`connection_manager.zig:98,168-170`) — send
   CONNECTION_REFUSED instead (quic-go `server.go:894-898,1016-1071`); replace the
   `require_retry` bool with a `fn(addr) bool` callback so Retry engages only under load
   (`transport.go:110-119`). S/M.
9. **No max cwnd cap** (quic-go: 10 000 packets, `cubic_sender.go:135-137`) — the amplifier for
   T1.1. S.
10. **Persistent congestion check looser than §7.6.2** (no "no ACK between" / prior-RTT-sample
    conditions, `ack_handler.zig:313-320`) — note quic-go doesn't implement persistent
    congestion at all. S.
11. **Control-frame order never randomized** (ossification; quic-go shuffles,
    `packet_packer.go:965-968`). S, low priority.

## Tier 4 — Interop features & observability

1. **Server-level 0-RTT queue:** 0-RTT packets arriving *before* the Initial (unknown DCID) are
   dropped at routing (`connection_manager.zig:317-331`); quic-go buffers per-DCID
   (≤32×31 pkts, 100 ms expiry) and replays after accept (`server.go:555-657`). Our
   connection-level undecryptable queue (commits 39c8d0b/7229743) is at parity; add an expiry
   timer to it. Directly relevant to the `debug/zerortt-quic-go-interop` branch. M.
2. **HelloRetryRequest unsupported** (`tls13.zig` has no HRR sentinel/cookie path) — fails
   against servers that mandate HRR (cookie DoS-defense or group steering). M.
3. **Client cert verification defaults off** — `skip_cert_verify = true` (`tls13.zig:509`)
   although full chain/hostname verification is already implemented
   (`tls13.zig:1109-1158`). Flip the default when `server_name`+`ca_bundle` present. S.
4. **Cipher/key-exchange breadth:** add TLS_AES_256_GCM_SHA384 (needs SHA-384
   transcript/schedule; S/M), P-384 (Zig std has it; S), X25519MLKEM768 post-quantum (L — no
   Zig std primitive yet). We already have ChaCha20-Poly1305 + P-256 (verified).
5. **RESET_STREAM_AT (reliable reset draft)** — quic-go ships it behind a transport param
   (`reset_stream_frame.go`, `send_stream.go:443-535`). Needed by WebTransport draft-13 work
   (Safari gap). M/L.
6. **Proactive key-update cadence:** we'd only rotate at the 2^23 hard limit
   (`crypto.zig:788-790`), i.e. never in practice; quic-go rotates every 100 k packets
   (sent or received) and once after the first 100 (`params.go:156-157`) — also exercises the
   interop `keyupdate` test. S.
7. **STREAMS_BLOCKED never emitted** when `openBidiStream`/`openUniStream` hit the limit
   (`stream.zig:899-923`). S.
8. **IP_PKTINFO missing:** wildcard-bound (`::`) multihomed servers may reply from the wrong
   source IP → "random" handshake failures; quic-go echoes dst addr/ifindex per packet
   (`sys_conn_oob.go:86-242`), since v0.60.0 also on path probes. M.
9. **qlog:** header claims JSON-SEQ but we never emit the RFC 7464 `0x1E` record separator
   (`qlog.zig:66-107`) — strict tooling rejects our files (one-line fix). Missing events:
   `packet_buffered`, `mtu_updated`, `spurious_loss`, `ecn_state_updated`,
   `version_information`, `alpn_information`, `parameters_restored`, `loss_timer_updated`, and
   any transport-level (ConnectionManager) events. Writes are synchronous in the packet path. S/M.
10. **Stats:** add `latest_rtt`/`bytes_lost` to `Connection.Stats` (`connection.zig:4009-4022`)
    and server-wide counters (drops by reason, VN/Retry/reset sent, conns accepted/refused,
    handshake duration) mirroring quic-go's dashboard set. S. Spurious-loss tracking
    (last-64 lost ring, `lost_packet_tracker.go`) is the prerequisite for adaptive reordering
    thresholds. S/M.
11. **Misc:** always advertise v2 in `version_information` (today VN lists v2 but the TP needs
    `enable_v2`, `connection.zig:839-843` vs `packet.zig:618-620` — authentication mismatch for
    v2-first clients). Embed the PSK ticket nonce instead of brute-forcing 0..256 on resumption
    (`tls13.zig:1845-1867`). S each.

## Where we're ahead of quic-go

- **Persistent congestion (RFC 9002 §7.6)** — quic-go doesn't implement it at all.
- **RFC 9218 priority scheduling** (urgency + incremental + WT send_order tiers) — quic-go has a
  plain FIFO ring.
- **PMTUD raise timer** (10-min re-probe per RFC 8899) — quic-go lacks it.
- **Datagram age expiry** in the send queue.
- **Per-space PTO counts + 3 s handshake-space cap** (RFC 8961-friendly).
- **Zero-alloc stack send buffers** (vs sync.Pool) — keep, just remove the extra copy.
- Full parity verified on: PTO/loss-threshold formulas, anti-amplification (byte-exact 3×),
  Retry integrity v1+v2, initial secrets v1+v2, key-update schedule ("quic ku", 3×PTO drop),
  ChaCha20 header protection, 0-RTT/PSK resumption + param re-validation, coalescing structure,
  ACK_FREQUENCY/IMMEDIATE_ACK draft, transport-param GREASE + validation, VN reception
  + downgrade guard, idle-timeout negotiation, keep-alive policy, single-deadline timer model,
  CID demux/routing, frame-sorter overlap correctness, final-size validation, darwin ECN cmsg
  quirks, datagram drop-don't-retransmit.

## quic-go releases since v0.59.0

- **v0.59.1** (May 2026): HTTP/3 trailer-validation backport only.
- **v0.60.0** (June 2026): FIPS 140-3 enablement (stdlib HKDF/AES-GCM, guarded ChaCha20);
  path probes carry OOB/pktinfo (#5544); fixed max-datagram-size estimation after MTU discovery
  (#5650); stream contexts canceled on conn close; Extended CONNECT `:protocol` validation;
  large fuzzing migration. **Nothing protocol-new we're missing at the release level** — all
  gaps above are long-standing behaviors.

## Suggested attack order

1. **Quick wins, ~all S, big payoff:** socket buffers (T2.1) · `largest_ack` validation (T1.1a)
   · per-stream FC enforcement (T1.2) · CRYPTO cap (T1.3) · uni-stream MAX_STREAM_DATA (T1.5) ·
   app-limited slack (T2.2) · pacer burst (T2.3) · ECN once-per-round (T1.12a) · Initial/VN size
   checks (T1.11) · range/gap caps (T3.1-2) · FC update at 25% (T2.8) · qlog RS byte (T4.9).
2. **Medium refactors:** control-frame retransmission (T1.7) · packing budget + padding fixup
   (T1.8) · stateless reset unification (T1.6) · token fallback + lifetimes (T1.10) · AEAD/key-
   update enforcement (T1.9) · DF bit + send-errno (T2.5) · MTU probe scheduling (T2.6) · PTO
   probe scope (T2.4) · CID lifecycle (T3.7) · datagram size contract (T1.14).
3. **Larger projects:** send-buffer reclamation (T1.4) · path-manager rework for probing (T1.13)
   · GSO/recvmmsg (T2.11) · HRR (T4.2) · RESET_STREAM_AT (T4.5) · ML-KEM (T4.4).
