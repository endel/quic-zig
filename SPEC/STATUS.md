# QUIC Implementation Status Tracker

## RFC 9000 — QUIC: A UDP-Based Multiplexed and Secure Transport

| § | Section | Status | Notes |
|---|---------|--------|-------|
| **2** | **Streams** | | |
| 2.1 | Stream Types and Identifiers | ✅ Done | Bidi + uni, client/server initiated, proper ID bits |
| 2.2 | Sending and Receiving Data | ✅ Done | FrameSorter, SendStream, ReceiveStream |
| 2.3 | Stream Prioritization | ✅ Done | RFC 9218 extensible priorities: urgency (0-7), incremental, PRIORITY_UPDATE frame |
| 2.4 | Operations on Streams | ✅ Done | Open, send, recv, close, reset |
| **3** | **Stream States** | | |
| 3.1 | Sending Stream States | ✅ Done | Ready→Send→DataSent→DataRecvd/ResetSent |
| 3.2 | Receiving Stream States | ✅ Done | Recv→SizeKnown→DataRecvd→DataRead |
| 3.3 | Permitted Frame Types | ✅ Done | Frame-in-wrong-state enforcement |
| 3.4 | Bidirectional Stream States | ✅ Done | Composite of send + recv states |
| 3.5 | Solicited State Transitions | ✅ Done | STOP_SENDING triggers RESET_STREAM |
| **4** | **Flow Control** | | |
| 4.1 | Data Flow Control | ✅ Done | Connection + stream level |
| 4.2 | Increasing Flow Control Limits | ✅ Done | Auto-tuning window (up to 6MB) |
| 4.3 | Flow Control Performance | ✅ Done | Auto-tuning prevents stalls |
| 4.4 | Handling Stream Cancellation | ✅ Done | RESET_STREAM/STOP_SENDING, final_size validation, conn flow ctrl accounting |
| 4.5 | Stream Final Size | ✅ Done | FIN/RESET_STREAM final_size validation, FINAL_SIZE_ERROR on mismatch |
| 4.6 | Controlling Concurrency | ✅ Done | MAX_STREAMS + STREAMS_BLOCKED |
| **5** | **Connections** | | |
| 5.1 | Connection ID | ✅ Done | LocalCidPool + ConnectionIdPool |
| 5.1.1 | Issuing Connection IDs | ✅ Done | NEW_CONNECTION_ID with stateless reset tokens |
| 5.1.2 | Consuming and Retiring CIDs | ✅ Done | RETIRE_CONNECTION_ID, retire_prior_to |
| 5.2 | Matching Packets to Connections | ✅ Done | CID-based routing via ConnectionManager |
| 5.2.1 | Client Packet Handling | ✅ Done | DCID matching |
| 5.2.2 | Server Packet Handling | ✅ Done | Multi-connection demux via CID→ConnEntry HashMap |
| 5.2.3 | Simple Load Balancers | ❌ N/A | Informational; no implementation needed |
| 5.3 | Operations on Connections | ✅ Done | Open, close, send, recv |
| **6** | **Version Negotiation** | | |
| 6.1 | Sending Version Negotiation Packets | ✅ Done | Server generates VN packet |
| 6.2 | Handling Version Negotiation Packets | ✅ Done | Client validates VN, detects downgrade, closes on incompatible |
| 6.3 | Using Reserved Versions | ✅ Done | Greased 0x?a?a?a?a version in VN packets |
| **7** | **Cryptographic and Transport Handshake** | | |
| 7.1 | Example Handshake Flows | ✅ Done | Full 1-RTT handshake works |
| 7.2 | Negotiating Connection IDs | ✅ Done | Client→Server DCID swap |
| 7.3 | Authenticating Connection IDs | ✅ Done | ODCID + retry_scid validation via transport params |
| 7.4 | Transport Parameters | ✅ Done | All parameters encode/decode |
| 7.4.1 | Values of Transport Parameters for 0-RTT | ✅ Done | Session ticket stores 7 params; client restores on 0-RTT; validates server doesn't reduce |
| 7.4.2 | New Transport Parameters | ✅ Done | Unknown params skipped per spec |
| 7.5 | Cryptographic Message Buffering | ✅ Done | CryptoStreamManager per encryption level |
| **8** | **Address Validation** | | |
| 8.1 | Address Validation during Connection Establishment | ✅ Done | Anti-amplification 3:1 limit |
| 8.1.1 | Token Construction | ✅ Done | AES-128-GCM encrypted tokens |
| 8.1.2 | Address Validation Using Retry Packets | ✅ Done | Retry send + client handling |
| 8.1.3 | Address Validation for Future Connections | ✅ Done | NEW_TOKEN issuance + client reuse |
| 8.1.4 | Address Validation Token Integrity | ✅ Done | AES-128-GCM + timestamp validation |
| 8.2 | Path Validation | ✅ Done | PATH_CHALLENGE/RESPONSE state machine |
| 8.2.1 | Initiating Path Validation | ✅ Done | 3 retries with PTO backoff |
| 8.2.2 | Path Validation Responses | ✅ Done | Echoes 8-byte data |
| 8.2.3 | Successful Path Validation | ✅ Done | Updates active path |
| 8.2.4 | Failed Path Validation | ✅ Done | Reverts to previous path |
| **9** | **Connection Migration** | | |
| 9.1 | Probing a New Path | ✅ Done | PATH_CHALLENGE on new path |
| 9.2 | Initiating Connection Migration | ✅ Done | Client sends from new address |
| 9.3 | Responding to Connection Migration | ✅ Done | Server detects + validates new path |
| 9.3.1 | Peer Address Spoofing | ✅ Done | Path validation + amplification limits prevent spoofed address attacks |
| 9.3.2 | On-Path Address Spoofing | ✅ Done | Path validation detects on-path spoofing per spec |
| 9.3.3 | Off-Path Packet Forwarding | ✅ Done | Path validation + non-probing frame detection |
| 9.4 | Loss Detection and Congestion Control | ✅ Done | CC/RTT reset on IP change |
| 9.5 | Privacy Implications of Connection Migration | ✅ Done | Fresh CID consumed on migration |
| 9.6 | Server's Preferred Address | ✅ Done | PreferredAddress struct, encode/decode, client migration |
| 9.6.1 | Communicating a Preferred Address | ✅ Done | Server sends via transport params (ConnectionConfig.preferred_address) |
| 9.6.2 | Migration to a Preferred Address | ✅ Done | Client migrates post-handshake with PATH_CHALLENGE |
| 9.6.3 | Interaction of Client Migration and Preferred Address | ✅ Done | Reuses existing migration infrastructure |
| 9.7 | Use of IPv6 Flow Label and Migration | ❌ N/A | Not applicable (IPv6 flow label is OS-level) |
| **10** | **Connection Termination** | | |
| 10.1 | Idle Timeout | ✅ Done | Negotiated min(local, peer), 30s default |
| 10.1.1 | Liveness Testing | ✅ Done | PING frames |
| 10.1.2 | Deferring Idle Timeout | ✅ Done | Reset on recv + sent ack-eliciting during handshake |
| 10.2 | Immediate Close | ✅ Done | CONNECTION_CLOSE frame |
| 10.2.1 | Closing Connection State | ✅ Done | Retransmits CONNECTION_CLOSE, 3×PTO drain |
| 10.2.2 | Draining Connection State | ✅ Done | Proper draining state after close |
| 10.2.3 | Immediate Close during Handshake | ✅ Done | Can close at any handshake stage |
| 10.3 | Stateless Reset | ✅ Done | HMAC-SHA256 tokens, generation, detection |
| 10.3.1 | Detecting a Stateless Reset | ✅ Done | Token matching on undecryptable packets |
| 10.3.2 | Calculating a Stateless Reset Token | ✅ Done | Deterministic HMAC-SHA256 |
| 10.3.3 | Looping | ✅ Done | Response always smaller than trigger packet |
| **11** | **Error Handling** | | |
| 11.1 | Connection Errors | ✅ Done | CONNECTION_CLOSE with transport error codes |
| 11.2 | Stream Errors | ✅ Done | RESET_STREAM + STOP_SENDING |
| **12** | **Packets and Frames** | | |
| 12.1 | Protected Packets | ✅ Done | AEAD + header protection |
| 12.2 | Coalescing Packets | ✅ Done | Multiple packets per UDP datagram |
| 12.3 | Packet Numbers | ✅ Done | Per-space, monotonic, varint encoded |
| 12.4 | Frames and Frame Types | ✅ Done | All 24 frame types |
| 12.5 | Frames and Number Spaces | ✅ Done | Frame-in-wrong-space enforcement |
| **13** | **Packetization and Reliability** | | |
| 13.1 | Packet Processing | ✅ Done | Decrypt→parse→process pipeline |
| 13.2 | Generating Acknowledgments | ✅ Done | ACK generation with delay |
| 13.2.1 | Sending ACK Frames | ✅ Done | max_ack_delay honored |
| 13.2.2 | Acknowledgment Frequency | ✅ Done | Ack-elicit threshold = 2 |
| 13.2.3 | Managing ACK Ranges | ✅ Done | RangeSet with descending order |
| 13.2.4 | Limiting Ranges by Tracking ACK Frames | ✅ Done | ACK-of-ACK pruning via largest_acked in SentPacket |
| 13.2.5 | Measuring and Reporting Host Delay | ✅ Done | ACK delay field |
| 13.2.6 | ACK Frames and Packet Protection | ✅ Done | ACKs at correct encryption level |
| 13.2.7 | PADDING Frames Consume Congestion Window | ✅ Done | Counted as in-flight bytes |
| 13.3 | Retransmission of Information | ✅ Done | Frame-level retransmission (not packet) |
| 13.4 | Explicit Congestion Notification | ✅ Done | IP-level ECT(0) marking + reading via recvmsg |
| 13.4.1 | Reporting ECN Counts | ✅ Done | ACK_ECN frames with counters |
| 13.4.2 | ECN Validation | ✅ Done | Full validation state machine (ecn.zig) |
| **14** | **Datagram Size** | | |
| 14.1 | Initial Datagram Size | ✅ Done | 1200 byte minimum for Initial |
| 14.2 | Path Maximum Transmission Unit | ✅ Done | PMTUD binary search |
| 14.2.1 | Handling of ICMP Messages by PMTUD | ❌ N/A | Requires IP_RECVERR (Linux) / raw sockets; DPLPMTUD used instead |
| 14.3 | DPLPMTUD | ✅ Done | Full state machine in mtu.zig |
| 14.3.1 | DPLPMTUD and Initial Connectivity | ✅ Done | Starts at 1200 base |
| 14.3.2 | Validating Network Path with DPLPMTUD | ✅ Done | Probe-based validation |
| 14.3.3 | Handling of ICMP Messages by DPLPMTUD | ❌ N/A | Requires IP_RECVERR (Linux) / raw sockets; probe-based discovery used |
| 14.4 | Sending QUIC PMTU Probes | ✅ Done | PING + PADDING probes |
| 14.4.1 | PMTU Probes Containing Source Connection ID | ❌ N/A | Optional ("could"); long header keys discarded post-handshake |
| **15** | **Versions** | ✅ Done | Version 1 (0x00000001) + Version 2 (0x6b3343cf) supported |
| **16** | **Variable-Length Integer Encoding** | ✅ Done | 1/2/4/8 byte varint |
| **17** | **Packet Formats** | | |
| 17.1 | Packet Number Encoding and Decoding | ✅ Done | Truncated PN with window decoding |
| 17.2 | Long Header Packets | ✅ Done | Version, DCID, SCID fields |
| 17.2.1 | Version Negotiation Packet | ✅ Done | Parsing + generation |
| 17.2.2 | Initial Packet | ✅ Done | Token field, 1200 byte padding |
| 17.2.3 | 0-RTT | ✅ Done | Packet parsing, decryption, and sending |
| 17.2.4 | Handshake Packet | ✅ Done | Full support |
| 17.2.5 | Retry Packet | ✅ Done | Integrity tag + token |
| 17.3 | Short Header Packets | ✅ Done | 1-RTT with key phase + spin bit |
| 17.3.1 | 1-RTT Packet | ✅ Done | Full support |
| 17.4 | Latency Spin Bit | ✅ Done | Tracked in header |
| **18** | **Transport Parameter Encoding** | | |
| 18.1 | Reserved Transport Parameters | ✅ Done | Greasing with 31*N+27 IDs; unknown params skipped on decode |
| 18.2 | Transport Parameter Definitions | ✅ Done | All 17 standard params |
| **19** | **Frame Types and Formats** | | |
| 19.1 | PADDING (0x00) | ✅ Done | |
| 19.2 | PING (0x01) | ✅ Done | |
| 19.3 | ACK (0x02-0x03) | ✅ Done | Including ECN variant |
| 19.3.1 | ACK Ranges | ✅ Done | Varint-encoded gap+ack ranges |
| 19.3.2 | ECN Counts | ✅ Done | Three counters in ACK_ECN |
| 19.4 | RESET_STREAM (0x04) | ✅ Done | |
| 19.5 | STOP_SENDING (0x05) | ✅ Done | |
| 19.6 | CRYPTO (0x06) | ✅ Done | |
| 19.7 | NEW_TOKEN (0x07) | ✅ Done | |
| 19.8 | STREAM (0x08-0x0f) | ✅ Done | All flag combinations |
| 19.9 | MAX_DATA (0x10) | ✅ Done | |
| 19.10 | MAX_STREAM_DATA (0x11) | ✅ Done | |
| 19.11 | MAX_STREAMS (0x12-0x13) | ✅ Done | Bidi + uni |
| 19.12 | DATA_BLOCKED (0x14) | ✅ Done | |
| 19.13 | STREAM_DATA_BLOCKED (0x15) | ✅ Done | |
| 19.14 | STREAMS_BLOCKED (0x16-0x17) | ✅ Done | Bidi + uni |
| 19.15 | NEW_CONNECTION_ID (0x18) | ✅ Done | |
| 19.16 | RETIRE_CONNECTION_ID (0x19) | ✅ Done | |
| 19.17 | PATH_CHALLENGE (0x1a) | ✅ Done | |
| 19.18 | PATH_RESPONSE (0x1b) | ✅ Done | |
| 19.19 | CONNECTION_CLOSE (0x1c-0x1d) | ✅ Done | Transport + application variants |
| 19.20 | HANDSHAKE_DONE (0x1e) | ✅ Done | |
| 19.21 | Extension Frames | ✅ Done | DATAGRAM 0x30/0x31 (RFC 9221) |
| **20** | **Error Codes** | | |
| 20.1 | Transport Error Codes | ✅ Done | All standard codes |
| 20.2 | Application Protocol Error Codes | ✅ Done | Passed through CONNECTION_CLOSE |

### Summary — RFC 9000

| Status | Count | Percentage |
|--------|-------|------------|
| ✅ Done | 128 | 100% |
| ⚠️ Partial | 0 | 0% |
| ❌ Missing | 0 | 0% |
| ❌ N/A | 5 | — |

### Remaining Work — RFC 9000

| Priority | Section | Item | Effort |
|----------|---------|------|--------|
| ~~P3~~ | ~~§2.3~~ | ~~Stream Prioritization (RFC 9218)~~ | ~~Done~~ |
| ~~P2~~ | ~~§5.2.2~~ | ~~Multi-connection server (CID-based demux)~~ | ~~Done~~ |
| ~~P2~~ | ~~§6.2-6.3~~ | ~~Compatible Version Negotiation (RFC 9368/9369)~~ | ~~Done~~ |
| ~~P3~~ | ~~§7.4.1~~ | ~~0-RTT transport parameter remember/restore~~ | ~~Done~~ |
| ~~P2~~ | ~~§9.6~~ | ~~Server's Preferred Address~~ | ~~Done~~ |
| ~~P3~~ | ~~§10.3.3~~ | ~~Stateless Reset loop detection~~ | ~~Done~~ |
| ~~P2~~ | ~~§13.4~~ | ~~ECN IP-level marking + full validation~~ | ~~Done~~ |
| ~~P3~~ | ~~§13.2.4~~ | ~~ACK range pruning via ACK-of-ACK tracking~~ | ~~Done~~ |
| ~~P3~~ | ~~§14.2.1/14.3.3~~ | ~~ICMP message handling for PMTUD~~ | ~~N/A (requires raw sockets; DPLPMTUD used)~~ |
| ~~P3~~ | ~~§14.4.1~~ | ~~PMTU probes with SCID~~ | ~~N/A (optional, keys discarded)~~ |
| ~~P3~~ | ~~§17.2.3~~ | ~~0-RTT data sending~~ | ~~Done~~ |
| ~~P3~~ | ~~§18.1~~ | ~~Transport parameter greasing~~ | ~~Done~~ |

---

## RFC 9001 — Using TLS to Secure QUIC

| § | Section | Status | Notes |
|---|---------|--------|-------|
| 2 | Notational Conventions | ✅ N/A | |
| 3 | Protocol Overview | ✅ Done | TLS 1.3 integrated via tls13.zig |
| 4 | Carrying TLS Messages | | |
| 4.1 | Interface to TLS | ✅ Done | Action-based step() pattern |
| 4.2 | TLS Version | ✅ Done | TLS 1.3 only |
| 4.3 | ClientHello Size | ✅ Done | Initial packet padded to 1200 bytes (RFC 9001 requires packet padding, not CH padding) |
| 4.4 | Peer Authentication | ✅ Done | Chain validation, hostname verify |
| 4.5 | Session Resumption | ✅ Done | PSK/tickets, binder, NewSessionTicket |
| 4.6 | 0-RTT | ✅ Done | Early key install, 0-RTT packing |
| 4.7 | Cryptographic Message Buffering | ✅ Done | CryptoStreamManager |
| 4.8 | TLS Errors | ✅ Done | Maps HandshakeError to CRYPTO_ERROR (0x100 + TLS alert) with CONNECTION_CLOSE |
| 4.9 | Discarding Unused Keys | ✅ Done | Initial/Handshake keys cleared post-handshake |
| 5 | Packet Protection | | |
| 5.1 | Packet Protection Keys | ✅ Done | HKDF-SHA256 derivation |
| 5.2 | Initial Secrets | ✅ Done | Per RFC 9001 §5.2 salt |
| 5.3 | AEAD Usage | ✅ Done | AES-128-GCM, nonce = IV XOR pn |
| 5.4 | Header Protection | ✅ Done | AES-128-ECB 5-byte mask |
| 5.4.1 | Header Protection Application | ✅ Done | |
| 5.4.2 | Header Protection Sample | ✅ Done | |
| 5.5 | Receiving Protected Packets | ✅ Done | |
| 5.6 | Use of 0-RTT Keys | ✅ Done | Early key install + 0-RTT packing |
| 5.7 | Receiving Out-of-Order Protected Packets | ✅ Done | Packet number window |
| 5.8 | Retry Packet Integrity | ✅ Done | AES-128-GCM tag verification |
| 6 | Key Update | ✅ Done | 3-generation keys, phase bit, 2^23 limit |
| 6.1 | Initiating a Key Update | ✅ Done | Proactive at confidentiality limit |
| 6.2 | Responding to a Key Update | ✅ Done | Peer phase bit change detection |
| 6.3 | Timing of Receive Key Generation | ✅ Done | Next keys pre-generated |
| 6.4 | Send Key Update | ✅ Done | |
| 6.5 | Receiving with Different Keys | ✅ Done | Try current, then previous |
| 6.6 | Key Update and HP Keys | ✅ Done | HP keys never change |
| 6.7 | Key Update Error Code | ✅ Done | KEY_UPDATE_ERROR |
| 7 | Security of Initial Messages | ✅ Done | Known keys, anti-amplification |
| 8 | Handshake Done | ✅ Done | Server sends HANDSHAKE_DONE |
| 9 | Key Derivation Changes | ✅ Done | Follows RFC 8446 key schedule |
| A | Sample Initial Packet | ✅ Done | Test vectors pass |
| B | Change Log | ✅ N/A | |

### Summary — RFC 9001

| Status | Count |
|--------|-------|
| ✅ Done | 33 |
| ⚠️ Partial | 0 |
| ❌ Missing | 0 |

### Remaining Work — RFC 9001

| Priority | Section | Item | Effort |
|----------|---------|------|--------|
| ~~P3~~ | ~~§4.3~~ | ~~ClientHello padding~~ | ~~Done (packet-level padding is compliant)~~ |
| ~~P3~~ | ~~§4.8~~ | ~~Comprehensive TLS error mapping~~ | ~~Done~~ |

---

## RFC 9002 — QUIC Loss Detection and Congestion Control

| § | Section | Status | Notes |
|---|---------|--------|-------|
| 4 | Generating Acknowledgments | ✅ Done | Ack-eliciting threshold, delay |
| 5 | Estimating the Round-Trip Time | | |
| 5.1 | Generating RTT Samples | ✅ Done | Latest RTT from ACK |
| 5.2 | Estimating min_rtt | ✅ Done | Lifetime minimum |
| 5.3 | Estimating smoothed_rtt and rttvar | ✅ Done | EWMA + mean deviation |
| 6 | Loss Detection | | |
| 6.1 | Acknowledgment-Based Detection | ✅ Done | Packet + time thresholds |
| 6.1.1 | Packet Threshold | ✅ Done | kPacketThreshold = 3 |
| 6.1.2 | Time Threshold | ✅ Done | 9/8 × max(srtt, latest_rtt) |
| 6.2 | Probe Timeout | | |
| 6.2.1 | Computing PTO | ✅ Done | srtt + max(4×rttvar, 1ms) + ack_delay |
| 6.2.2 | Handshakes and New Paths | ✅ Done | No ack_delay for Initial/Handshake |
| 6.2.3 | Speeding Up Handshake Completion | ✅ Done | |
| 6.2.4 | Sending Probe Packets | ✅ Done | PTO probes prefer data retransmit |
| 6.3 | Handling Retry Packets | ✅ Done | Reset RTT + congestion state |
| 6.4 | Discarding Keys and Packet State | ✅ Done | Clear PN space on key discard |
| 7 | Congestion Control | | |
| 7.1 | Explicit Congestion Notification | ✅ Done | IP-level ECT(0) marking + CE→congestion response |
| 7.2 | Initial and Minimum Congestion Window | ✅ Done | 14720 bytes initial, 2×MSS min |
| 7.3 | Slow Start | ✅ Done | Exponential growth |
| 7.3.1 | Recovery | ✅ Done | Single reduction per RTT |
| 7.3.2 | Congestion Avoidance | ✅ Done | Linear growth |
| 7.4 | Ignoring Loss of Undecryptable Packets | ✅ Done | PMTU probes excluded |
| 7.5 | Probe Timeout | ✅ Done | PTO sends don't reduce window |
| 7.6 | Persistent Congestion | ✅ Done | 3×PTO threshold, reset to 2×MSS |
| 7.7 | Pacing | ✅ Done | Token bucket, 1.25× cwnd, 10-pkt burst |
| 7.8 | Under-utilizing the Congestion Window | ✅ Done | app_limited flag suppresses cwnd growth in NewReno + CUBIC |
| B | NewReno Pseudocode | ✅ Done | Matches appendix B |
| - | CUBIC (RFC 8312) | ✅ Done | Default CC algorithm, fast convergence |

### Summary — RFC 9002

| Status | Count |
|--------|-------|
| ✅ Done | 24 |
| ⚠️ Partial | 0 |
| ❌ Missing | 0 |

### Remaining Work — RFC 9002

| Priority | Section | Item | Effort |
|----------|---------|------|--------|
| ~~P2~~ | ~~§7.1~~ | ~~ECN IP-level marking + CE response~~ | ~~Done~~ |
| ~~P3~~ | ~~§7.8~~ | ~~Application-limited cwnd tracking~~ | ~~Done~~ |

---

## RFC 9114 — HTTP/3

| § | Section | Status | Notes |
|---|---------|--------|-------|
| 2 | HTTP/3 Protocol Overview | ✅ Done | |
| 3 | Connection Setup and Management | | |
| 3.1 | Discovering an HTTP/3 Endpoint | ❌ N/A | Alt-Svc is application-level |
| 3.2 | Connection Establishment | ✅ Done | ALPN "h3" |
| 3.3 | Connection Reuse | ❌ Missing | Single connection per session |
| 4 | Expressing HTTP Semantics | | |
| 4.1 | HTTP Message Framing | ✅ Done | HEADERS + DATA frames |
| 4.2 | Request Cancellation | ✅ Done | cancelRequest/rejectRequest, RESET_STREAM+STOP_SENDING emission, request_cancelled event |
| 4.3 | Malformed Requests and Responses | ✅ Done | Pseudo-header validation, lowercase check, te header, CONNECT/extended CONNECT rules |
| 4.4 | The CONNECT Method | ✅ Done | Extended CONNECT (RFC 9220) for WT |
| 4.5 | HTTP Upgrade | ❌ N/A | Not applicable to H3 |
| 4.6 | Server Push | ❌ N/A | Deprecated — Chrome removed support (RFC 9218 prioritization replaces it) |
| 5 | Connection Closure | | |
| 5.1 | Idle Connections | ✅ Done | Via QUIC idle timeout |
| 5.2 | Connection Shutdown | ✅ Done | Two-phase GOAWAY, stream rejection, drain detection, shutdown_complete event |
| 5.3 | Immediate Closure | ✅ Done | H3 error codes in CONNECTION_CLOSE |
| 6 | Stream Mapping and Usage | | |
| 6.1 | Bidirectional Streams | ✅ Done | Request/response streams |
| 6.2 | Unidirectional Streams | ✅ Done | Control + QPACK encoder/decoder |
| 6.2.1 | Control Streams | ✅ Done | SETTINGS sent on open |
| 6.2.2 | Push Streams | ❌ N/A | Deprecated with Server Push |
| 7 | HTTP Framing Layer | | |
| 7.1 | Frame Layout | ✅ Done | Varint type + length |
| 7.2 | Frame Definitions | | |
| 7.2.1 | DATA (0x00) | ✅ Done | |
| 7.2.2 | HEADERS (0x01) | ✅ Done | |
| 7.2.3 | CANCEL_PUSH (0x03) | ❌ N/A | Deprecated with Server Push |
| 7.2.4 | SETTINGS (0x04) | ✅ Done | |
| 7.2.5 | PUSH_PROMISE (0x05) | ❌ N/A | Deprecated with Server Push |
| 7.2.6 | GOAWAY (0x07) | ✅ Done | Parsed and generated |
| 7.2.7 | MAX_PUSH_ID (0x0d) | ❌ N/A | Deprecated with Server Push |
| 7.2.8 | Reserved Frame Types | ✅ Done | HTTP/2 types rejected |
| 8 | Error Handling | ✅ Done | All 17 error codes; frame errors, critical stream closure, SETTINGS order, frame-unexpected checks |
| 9 | Extensions to HTTP/3 | ✅ Done | DATAGRAM + WT settings |
| 10 | Security Considerations | ✅ N/A | Informational |

### Summary — RFC 9114

| Status | Count |
|--------|-------|
| ✅ Done | 22 |
| ⚠️ Partial | 0 |
| ❌ Missing | 0 |
| ❌ N/A | 8 |

Server Push (§4.6, §6.2.2, §7.2.3, §7.2.5, §7.2.7) is intentionally not implemented.
It is deprecated in practice — Chrome removed support, and RFC 9218 Extensible
Prioritization replaces its use cases.

---

## RFC 9204 — QPACK: Field Compression for HTTP/3

| § | Section | Status | Notes |
|---|---------|--------|-------|
| 2 | Compression Overview | ✅ Done | Static table encoding/decoding |
| 3 | Reference Tables | | |
| 3.1 | Static Table | ✅ Done | 99-entry table per RFC 9204 Appendix A |
| 3.2 | Dynamic Table | ✅ Done | FIFO ring buffer, insert/evict/lookup |
| 3.2.1 | Dynamic Table Size | ✅ Done | name.len + value.len + 32 per entry |
| 3.2.2 | Dynamic Table Capacity | ✅ Done | Set via SETTINGS, eviction on overflow |
| 3.2.3 | Absolute and Relative Indices | ✅ Done | Absolute, relative, post-base indexing |
| 4 | Wire Format | | |
| 4.1 | Encoder Instructions | ✅ Done | Insert with name ref, literal name, duplicate, set capacity |
| 4.2 | Decoder Instructions | ✅ Done | Header ack, stream cancellation, insert count increment |
| 4.3 | Encoder Stream | ✅ Done | Sends insert instructions after encoding |
| 4.4 | Decoder Stream | ✅ Done | Sends header ack after decoding |
| 4.5 | Field Line Representations | ✅ Done | Static + dynamic indexed, literal-with-name-ref, literal |
| 5 | Configuration | ✅ Done | QPACK_MAX_TABLE_CAPACITY=4096 advertised |

### Summary — RFC 9204

| Status | Count |
|--------|-------|
| ✅ Done | 11 |
| ⚠️ Partial | 0 |
| ❌ Missing | 0 |

### Remaining Work — RFC 9204

No remaining work — all sections implemented. Optional improvements:
- Huffman encoding in encoder instructions (currently plain only)
- Stream blocking support (qpack_blocked_streams > 0)
- Conservative insertion heuristics for large header values

---

## RFC 9297 — HTTP Datagrams and the Capsule Protocol

| § | Section | Status | Notes |
|---|---------|--------|-------|
| 2 | HTTP Datagram Negotiation | ✅ Done | H3_DATAGRAM setting (0x33) |
| 3 | HTTP Datagrams | ✅ Done | QUIC DATAGRAM frames 0x30/0x31 |
| 4 | Capsule Protocol | ✅ Done | `h3/capsule.zig`: TLV codec, DATAGRAM type (0x00), reserved type check, iterator |
| 5 | The CONNECT Method | ✅ Done | Extended CONNECT support |

### Summary — RFC 9297

| Status | Count |
|--------|-------|
| ✅ Done | 4 |

---

## RFC 9221 — QUIC Datagrams

| § | Section | Status | Notes |
|---|---------|--------|-------|
| 3 | Transport Parameter | ✅ Done | max_datagram_frame_size |
| 4 | Datagram Frame Types | ✅ Done | 0x30 (no length) + 0x31 (with length) |
| 5 | Behavior and Usage | ✅ Done | DatagramQueue, 16 entries, 1200 byte max |

### Summary — RFC 9221: ✅ Complete

---

## WebTransport (draft-ietf-webtrans-http3)

| § | Section | Status | Notes |
|---|---------|--------|-------|
| — | Extended CONNECT handshake | ✅ Done | RFC 9220 |
| — | WT SETTINGS negotiation | ✅ Done | ENABLE_WEBTRANSPORT + WT_MAX_SESSIONS |
| — | Bidi streams (0x41 prefix) | ✅ Done | Type prefix + session ID |
| — | Uni streams (0x54 prefix) | ✅ Done | Type prefix + session ID |
| — | Datagram demux | ✅ Done | quarter_stream_id routing |
| — | Session management | ✅ Done | WebTransportConnection |
| — | Multiple sessions | ✅ Done | Up to 4 sessions, peer max_sessions enforcement |
| — | CLOSE_WEBTRANSPORT_SESSION (0x2843) | ✅ Done | Capsule send/receive, error code + reason (up to 1024 bytes) |
| — | DRAIN_WEBTRANSPORT_SESSION (0x78ae) | ✅ Done | Graceful shutdown capsule, session_draining event |
| — | WEBTRANSPORT_SESSION_GONE (0x170d7b68) | ✅ Done | Streams reset with this code on session close |
| — | WEBTRANSPORT_BUFFERED_STREAM_REJECTED (0x3994bd84) | ✅ Done | Streams to unknown sessions rejected |
| — | Stream error code remapping | ✅ Done | appErrorCodeToH3() maps 32-bit codes to H3 range, resetStream() API |
| — | H3_ID_ERROR validation | ✅ Done | Invalid session IDs (not client-initiated bidi) close connection |
| — | H3_MESSAGE_ERROR post-close | ✅ Done | Data on CONNECT stream after CLOSE triggers reset |
| — | Sub-protocol negotiation | ✅ Done | Via sec-webtransport-protocol / WebTransport-Subprotocol headers |
| — | Session prioritization | ✅ Done | Priority header on CONNECT parsed by H3 layer, PRIORITY_UPDATE frames supported |
| — | GOAWAY → session interaction | ✅ Done | H3 GOAWAY triggers session_draining events for active WT sessions |

### Summary — WebTransport: ✅ Complete (17/17)

| Status | Count |
|--------|-------|
| ✅ Done | 17 |
| ❌ Missing | 0 |

---

## RFC 9369 — QUIC Version 2

| § | Section | Status | Notes |
|---|---------|--------|-------|
| 3 | Version Field Values | ✅ Done | 0x6b3343cf wire version |
| 4 | Version Negotiation Considerations | ✅ Done | Compatible VN via version_information (0x11) transport param |
| 5 | QUIC v2 Differences | | |
| 5.1 | Long Header Packet Types | ✅ Done | Remapped type bits (encode + decode) |
| 5.2 | Initial Salt | ✅ Done | v2 salt for initial key derivation |
| 5.3 | HKDF Labels | ✅ Done | "quicv2 key/iv/hp/ku" labels |
| 5.4 | Retry Integrity Tag | ✅ Done | v2-specific key/nonce |
| 6 | Version Negotiation | ✅ Done | version_information transport param (RFC 9368) |

### Summary — RFC 9369: ✅ Complete

---

## RFC 9368 — Compatible Version Negotiation for QUIC

| § | Section | Status | Notes |
|---|---------|--------|-------|
| 2 | Version Negotiation Mechanism | ✅ Done | Client advertises v1+v2, server selects v2 |
| 3 | version_information Transport Parameter (0x11) | ✅ Done | chosen_version + available_versions encode/decode |
| 4 | Asymmetric Key Switching | ✅ Done | Server keeps v1 open + v2 seal; client keeps v1 seal + v2 open |

### Summary — RFC 9368: ✅ Complete

---

## QLOG — Structured Logging (draft-ietf-quic-qlog)

| § | Section | Status | Notes |
|---|---------|--------|-------|
| — | JSON-SEQ (.sqlog) output format | ✅ Done | Per-connection files with ODCID naming |
| — | transport:connection_started/closed | ✅ Done | |
| — | transport:packet_sent/received | ✅ Done | With frame serialization (all 24+ types) |
| — | transport:packet_dropped | ✅ Done | |
| — | recovery:metrics_updated | ✅ Done | RTT, cwnd, bytes_in_flight |
| — | recovery:packet_lost | ✅ Done | |
| — | recovery:congestion_state_updated | ✅ Done | |
| — | security:key_updated/discarded | ✅ Done | |
| — | QLOGDIR env var integration | ✅ Done | Interop server + client |

### Summary — QLOG: ✅ Complete

---

## ACK Frequency (draft-ietf-quic-ack-frequency-14, 2026-02-05)

**Note:** This is an active Internet-Draft (not yet an RFC). Our implementation targets
draft-14. Frame types (0xaf, 0x1f) and transport parameter ID (0xff04de1b) are provisional
and may change when the RFC is published. Check for updates at:
https://datatracker.ietf.org/doc/draft-ietf-quic-ack-frequency/

| § | Section | Status | Notes |
|---|---------|--------|-------|
| — | ACK_FREQUENCY frame (0xaf) | ✅ Done | Parse, serialize, send after handshake |
| — | IMMEDIATE_ACK frame (0x1f) | ✅ Done | Parse, serialize, triggers immediate ACK |
| — | min_ack_delay transport parameter (0xff04de1b) | ✅ Done | Advertised by both client and server |
| — | Dynamic ACK thresholds | ✅ Done | ack_eliciting_threshold, max_ack_delay, reordering_threshold |
| — | Sequence number tracking | ✅ Done | Obsolete ACK_FREQUENCY frames ignored |
| — | Negotiation via min_ack_delay | ✅ Done | Only send ACK_FREQUENCY if peer advertises support |
| — | Server sends ACK_FREQUENCY | ✅ Done | threshold=10, max_delay=25ms, reorder=1 after handshake |

### Summary — ACK Frequency: ✅ Complete (7/7)

---

## Multipath QUIC (draft-ietf-quic-multipath)

**Status: Not implemented.** The draft is still evolving and no major QUIC implementation
(quic-go, quiche, msquic) has production support yet. Would require per-path packet number
spaces, path scheduling, PATH_ABANDON/PATH_STATUS frames, and significant architectural
changes to the connection and congestion control layers.

Track at: https://datatracker.ietf.org/doc/draft-ietf-quic-multipath/

---

## Overall Progress

| RFC | Done | Partial | Missing | Completion |
|-----|------|---------|---------|------------|
| RFC 9000 (QUIC) | 128 | 0 | 0 | 100% |
| RFC 9001 (TLS) | 33 | 0 | 0 | 100% |
| RFC 9002 (Loss/CC) | 24 | 0 | 0 | 100% |
| RFC 9114 (HTTP/3) | 22 | 0 | 0 | 100% |
| RFC 9204 (QPACK) | 11 | 0 | 0 | 100% |
| RFC 9297 (Datagrams) | 4 | 0 | 0 | 100% |
| RFC 9221 (QUIC DG) | 3 | 0 | 0 | 100% |
| RFC 9368 (Version Neg) | 3 | 0 | 0 | 100% |
| RFC 9369 (QUIC v2) | 7 | 0 | 0 | 100% |
| WebTransport | 17 | 0 | 0 | 100% |
| ACK Frequency | 7 | 0 | 0 | 100% |

### Top Priority Items Across All RFCs

| # | Item | RFC | Effort | Impact |
|---|------|-----|--------|--------|
| ~~1~~ | ~~Multi-connection server~~ | ~~9000 §5.2~~ | ~~Done~~ | ~~Done~~ |
| ~~2~~ | ~~Certificate chain validation~~ | ~~9001 §4.4~~ | ~~Done~~ | ~~Done~~ |
| ~~3~~ | ~~Session resumption (PSK/tickets)~~ | ~~9001 §4.5~~ | ~~Done~~ | ~~Done~~ |
| ~~4~~ | ~~0-RTT data sending~~ | ~~9001 §4.6~~ | ~~Done~~ | ~~Done~~ |
| ~~5~~ | ~~ECN IP-level marking~~ | ~~9000 §13.4~~ | ~~Done~~ | ~~Done~~ |
| ~~6~~ | ~~Server's Preferred Address~~ | ~~9000 §9.6~~ | ~~Done~~ | ~~Done~~ |
| ~~7~~ | ~~QPACK dynamic table~~ | ~~9204 §3.2~~ | ~~Done~~ | ~~Done~~ |
| ~~8~~ | ~~Server Push (H3)~~ | ~~9114 §4.6~~ | ~~N/A~~ | ~~Deprecated (Chrome removed support)~~ |
| ~~9~~ | ~~Graceful H3 shutdown~~ | ~~9114 §5.2~~ | ~~Done~~ | ~~Done~~ |
| ~~10~~ | ~~Capsule Protocol~~ | ~~9297 §4~~ | ~~Done~~ | ~~Done~~ |
