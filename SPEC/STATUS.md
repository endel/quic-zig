# QUIC Implementation Status Tracker

## RFC 9000 — QUIC: A UDP-Based Multiplexed and Secure Transport

| § | Section | Status | Notes |
|---|---------|--------|-------|
| **2** | **Streams** | | |
| 2.1 | Stream Types and Identifiers | ✅ Done | Bidi + uni, client/server initiated, proper ID bits |
| 2.2 | Sending and Receiving Data | ✅ Done | FrameSorter, SendStream, ReceiveStream |
| 2.3 | Stream Prioritization | ❌ Missing | No priority mechanism (RFC 9218 extensible priorities) |
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
| 4.4 | Handling Stream Cancellation | ⚠️ Partial | RESET_STREAM parsed; final size accounting may be incomplete |
| 4.5 | Stream Final Size | ✅ Done | FIN handling in FrameSorter |
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
| 6.2 | Handling Version Negotiation Packets | ⚠️ Partial | Parsed but client doesn't retry with different version |
| 6.3 | Using Reserved Versions | ❌ Missing | No greasing with reserved versions |
| **7** | **Cryptographic and Transport Handshake** | | |
| 7.1 | Example Handshake Flows | ✅ Done | Full 1-RTT handshake works |
| 7.2 | Negotiating Connection IDs | ✅ Done | Client→Server DCID swap |
| 7.3 | Authenticating Connection IDs | ✅ Done | ODCID + retry_scid validation via transport params |
| 7.4 | Transport Parameters | ✅ Done | All parameters encode/decode |
| 7.4.1 | Values of Transport Parameters for 0-RTT | ⚠️ Partial | 0-RTT packet parsing works; param remember/restore not impl |
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
| 9.3.1 | Peer Address Spoofing | ⚠️ Partial | Path validation prevents, but no explicit anti-spoofing beyond that |
| 9.3.2 | On-Path Address Spoofing | ⚠️ Partial | No explicit countermeasures beyond path validation |
| 9.3.3 | Off-Path Packet Forwarding | ⚠️ Partial | No explicit countermeasures |
| 9.4 | Loss Detection and Congestion Control | ✅ Done | CC/RTT reset on IP change |
| 9.5 | Privacy Implications of Connection Migration | ✅ Done | Fresh CID consumed on migration |
| 9.6 | Server's Preferred Address | ❌ Missing | Transport param parsed but not acted upon |
| 9.6.1 | Communicating a Preferred Address | ❌ Missing | Not sent by server |
| 9.6.2 | Migration to a Preferred Address | ❌ Missing | Client doesn't migrate to preferred addr |
| 9.6.3 | Interaction of Client Migration and Preferred Address | ❌ Missing | — |
| 9.7 | Use of IPv6 Flow Label and Migration | ❌ N/A | Not applicable (IPv6 flow label is OS-level) |
| **10** | **Connection Termination** | | |
| 10.1 | Idle Timeout | ✅ Done | Negotiated min(local, peer), 30s default |
| 10.1.1 | Liveness Testing | ✅ Done | PING frames |
| 10.1.2 | Deferring Idle Timeout | ⚠️ Partial | Reset on ack-eliciting recv; may not cover all cases |
| 10.2 | Immediate Close | ✅ Done | CONNECTION_CLOSE frame |
| 10.2.1 | Closing Connection State | ✅ Done | Retransmits CONNECTION_CLOSE, 3×PTO drain |
| 10.2.2 | Draining Connection State | ✅ Done | Proper draining state after close |
| 10.2.3 | Immediate Close during Handshake | ✅ Done | Can close at any handshake stage |
| 10.3 | Stateless Reset | ✅ Done | HMAC-SHA256 tokens, generation, detection |
| 10.3.1 | Detecting a Stateless Reset | ✅ Done | Token matching on undecryptable packets |
| 10.3.2 | Calculating a Stateless Reset Token | ✅ Done | Deterministic HMAC-SHA256 |
| 10.3.3 | Looping | ⚠️ Partial | No explicit loop detection mechanism |
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
| 13.2.4 | Limiting Ranges by Tracking ACK Frames | ⚠️ Partial | Basic range limiting; no explicit tracking of peer ACK-of-ACK |
| 13.2.5 | Measuring and Reporting Host Delay | ✅ Done | ACK delay field |
| 13.2.6 | ACK Frames and Packet Protection | ✅ Done | ACKs at correct encryption level |
| 13.2.7 | PADDING Frames Consume Congestion Window | ✅ Done | Counted as in-flight bytes |
| 13.3 | Retransmission of Information | ✅ Done | Frame-level retransmission (not packet) |
| 13.4 | Explicit Congestion Notification | ⚠️ Partial | Protocol-level counters; no IP-level marking/reading |
| 13.4.1 | Reporting ECN Counts | ✅ Done | ACK_ECN frames with counters |
| 13.4.2 | ECN Validation | ⚠️ Partial | No full validation state machine per §13.4.2.1 |
| **14** | **Datagram Size** | | |
| 14.1 | Initial Datagram Size | ✅ Done | 1200 byte minimum for Initial |
| 14.2 | Path Maximum Transmission Unit | ✅ Done | PMTUD binary search |
| 14.2.1 | Handling of ICMP Messages by PMTUD | ❌ Missing | No ICMP handling (requires raw sockets) |
| 14.3 | DPLPMTUD | ✅ Done | Full state machine in mtu.zig |
| 14.3.1 | DPLPMTUD and Initial Connectivity | ✅ Done | Starts at 1200 base |
| 14.3.2 | Validating Network Path with DPLPMTUD | ✅ Done | Probe-based validation |
| 14.3.3 | Handling of ICMP Messages by DPLPMTUD | ❌ Missing | No ICMP processing |
| 14.4 | Sending QUIC PMTU Probes | ✅ Done | PING + PADDING probes |
| 14.4.1 | PMTU Probes Containing Source Connection ID | ❌ Missing | Probes don't include SCID |
| **15** | **Versions** | ✅ Done | Version 1 (0x00000001) supported |
| **16** | **Variable-Length Integer Encoding** | ✅ Done | 1/2/4/8 byte varint |
| **17** | **Packet Formats** | | |
| 17.1 | Packet Number Encoding and Decoding | ✅ Done | Truncated PN with window decoding |
| 17.2 | Long Header Packets | ✅ Done | Version, DCID, SCID fields |
| 17.2.1 | Version Negotiation Packet | ✅ Done | Parsing + generation |
| 17.2.2 | Initial Packet | ✅ Done | Token field, 1200 byte padding |
| 17.2.3 | 0-RTT | ⚠️ Partial | Packet parsing/decryption works; sending 0-RTT data not implemented |
| 17.2.4 | Handshake Packet | ✅ Done | Full support |
| 17.2.5 | Retry Packet | ✅ Done | Integrity tag + token |
| 17.3 | Short Header Packets | ✅ Done | 1-RTT with key phase + spin bit |
| 17.3.1 | 1-RTT Packet | ✅ Done | Full support |
| 17.4 | Latency Spin Bit | ✅ Done | Tracked in header |
| **18** | **Transport Parameter Encoding** | | |
| 18.1 | Reserved Transport Parameters | ⚠️ Partial | Unknown params skipped; no greasing sent |
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
| ✅ Done | 87 | ~84% |
| ⚠️ Partial | 12 | ~12% |
| ❌ Missing | 7 | ~4% |
| ❌ N/A | 2 | — |

### Remaining Work — RFC 9000

| Priority | Section | Item | Effort |
|----------|---------|------|--------|
| P3 | §2.3 | Stream Prioritization (RFC 9218) | Medium |
| ~~P2~~ | ~~§5.2.2~~ | ~~Multi-connection server (CID-based demux)~~ | ~~Done~~ |
| P3 | §6.2-6.3 | Version Negotiation client retry + greasing | Small |
| P3 | §7.4.1 | 0-RTT transport parameter remember/restore | Medium |
| P2 | §9.6 | Server's Preferred Address | Medium |
| P3 | §10.3.3 | Stateless Reset loop detection | Small |
| P2 | §13.4 | ECN IP-level marking + full validation | Medium |
| P3 | §13.2.4 | ACK range pruning via ACK-of-ACK tracking | Small |
| P3 | §14.2.1/14.3.3 | ICMP message handling for PMTUD | Small (platform-limited) |
| P3 | §14.4.1 | PMTU probes with SCID | Small |
| P3 | §17.2.3 | 0-RTT data sending | Medium |
| P3 | §18.1 | Transport parameter greasing | Small |

---

## RFC 9001 — Using TLS to Secure QUIC

| § | Section | Status | Notes |
|---|---------|--------|-------|
| 2 | Notational Conventions | ✅ N/A | |
| 3 | Protocol Overview | ✅ Done | TLS 1.3 integrated via tls13.zig |
| 4 | Carrying TLS Messages | | |
| 4.1 | Interface to TLS | ✅ Done | Action-based step() pattern |
| 4.2 | TLS Version | ✅ Done | TLS 1.3 only |
| 4.3 | ClientHello Size | ⚠️ Partial | Padded Initial to 1200; no explicit ClientHello padding |
| 4.4 | Peer Authentication | ⚠️ Partial | No cert chain validation (accepts self-signed) |
| 4.5 | Session Resumption | ❌ Missing | No PSK/session ticket support |
| 4.6 | 0-RTT | ⚠️ Partial | Parsing/decryption only; no sending |
| 4.7 | Cryptographic Message Buffering | ✅ Done | CryptoStreamManager |
| 4.8 | TLS Errors | ⚠️ Partial | Basic error propagation |
| 4.9 | Discarding Unused Keys | ✅ Done | Initial/Handshake keys cleared post-handshake |
| 5 | Packet Protection | | |
| 5.1 | Packet Protection Keys | ✅ Done | HKDF-SHA256 derivation |
| 5.2 | Initial Secrets | ✅ Done | Per RFC 9001 §5.2 salt |
| 5.3 | AEAD Usage | ✅ Done | AES-128-GCM, nonce = IV XOR pn |
| 5.4 | Header Protection | ✅ Done | AES-128-ECB 5-byte mask |
| 5.4.1 | Header Protection Application | ✅ Done | |
| 5.4.2 | Header Protection Sample | ✅ Done | |
| 5.5 | Receiving Protected Packets | ✅ Done | |
| 5.6 | Use of 0-RTT Keys | ⚠️ Partial | Decryption works; sending not impl |
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
| ✅ Done | 28 |
| ⚠️ Partial | 5 |
| ❌ Missing | 1 |

### Remaining Work — RFC 9001

| Priority | Section | Item | Effort |
|----------|---------|------|--------|
| P2 | §4.4 | Certificate chain validation | Medium |
| P2 | §4.5 | Session resumption (PSK/tickets) | Large |
| P2 | §4.6/5.6 | 0-RTT data sending | Medium |
| P3 | §4.8 | Comprehensive TLS error mapping | Small |

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
| 7.1 | Explicit Congestion Notification | ⚠️ Partial | Protocol-level only |
| 7.2 | Initial and Minimum Congestion Window | ✅ Done | 14720 bytes initial, 2×MSS min |
| 7.3 | Slow Start | ✅ Done | Exponential growth |
| 7.3.1 | Recovery | ✅ Done | Single reduction per RTT |
| 7.3.2 | Congestion Avoidance | ✅ Done | Linear growth |
| 7.4 | Ignoring Loss of Undecryptable Packets | ✅ Done | PMTU probes excluded |
| 7.5 | Probe Timeout | ✅ Done | PTO sends don't reduce window |
| 7.6 | Persistent Congestion | ✅ Done | 3×PTO threshold, reset to 2×MSS |
| 7.7 | Pacing | ✅ Done | Token bucket, 1.25× cwnd, 10-pkt burst |
| 7.8 | Under-utilizing the Congestion Window | ⚠️ Partial | App-limited not fully tracked |
| B | NewReno Pseudocode | ✅ Done | Matches appendix B |

### Summary — RFC 9002

| Status | Count |
|--------|-------|
| ✅ Done | 22 |
| ⚠️ Partial | 2 |
| ❌ Missing | 0 |

### Remaining Work — RFC 9002

| Priority | Section | Item | Effort |
|----------|---------|------|--------|
| P2 | §7.1 | ECN IP-level marking + CE response | Medium |
| P3 | §7.8 | Application-limited cwnd tracking | Small |

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
| 4.2 | Request Cancellation | ⚠️ Partial | RESET_STREAM exists; no H3 cancel logic |
| 4.3 | Malformed Requests and Responses | ⚠️ Partial | Basic validation only |
| 4.4 | The CONNECT Method | ✅ Done | Extended CONNECT (RFC 9220) for WT |
| 4.5 | HTTP Upgrade | ❌ N/A | Not applicable to H3 |
| 4.6 | Server Push | ❌ Missing | PUSH_PROMISE not implemented |
| 5 | Connection Closure | | |
| 5.1 | Idle Connections | ✅ Done | Via QUIC idle timeout |
| 5.2 | Connection Shutdown | ⚠️ Partial | GOAWAY frame parsed but graceful shutdown not fully impl |
| 5.3 | Immediate Closure | ✅ Done | H3 error codes in CONNECTION_CLOSE |
| 6 | Stream Mapping and Usage | | |
| 6.1 | Bidirectional Streams | ✅ Done | Request/response streams |
| 6.2 | Unidirectional Streams | ✅ Done | Control + QPACK encoder/decoder |
| 6.2.1 | Control Streams | ✅ Done | SETTINGS sent on open |
| 6.2.2 | Push Streams | ❌ Missing | Not implemented |
| 7 | HTTP Framing Layer | | |
| 7.1 | Frame Layout | ✅ Done | Varint type + length |
| 7.2 | Frame Definitions | | |
| 7.2.1 | DATA (0x00) | ✅ Done | |
| 7.2.2 | HEADERS (0x01) | ✅ Done | |
| 7.2.3 | CANCEL_PUSH (0x03) | ❌ Missing | |
| 7.2.4 | SETTINGS (0x04) | ✅ Done | |
| 7.2.5 | PUSH_PROMISE (0x05) | ❌ Missing | |
| 7.2.6 | GOAWAY (0x07) | ✅ Done | Parsed and generated |
| 7.2.7 | MAX_PUSH_ID (0x0d) | ❌ Missing | |
| 7.2.8 | Reserved Frame Types | ✅ Done | HTTP/2 types rejected |
| 8 | Error Handling | ⚠️ Partial | Basic error codes; not all error conditions checked |
| 9 | Extensions to HTTP/3 | ✅ Done | DATAGRAM + WT settings |
| 10 | Security Considerations | ✅ N/A | Informational |

### Summary — RFC 9114

| Status | Count |
|--------|-------|
| ✅ Done | 18 |
| ⚠️ Partial | 4 |
| ❌ Missing | 5 |
| ❌ N/A | 3 |

### Remaining Work — RFC 9114

| Priority | Section | Item | Effort |
|----------|---------|------|--------|
| P3 | §4.6 | Server Push (PUSH_PROMISE, CANCEL_PUSH, MAX_PUSH_ID) | Large |
| P3 | §5.2 | Graceful shutdown (GOAWAY stream ID tracking) | Medium |
| P3 | §4.2-4.3 | Request cancellation + malformed request handling | Small |
| P3 | §8 | Comprehensive H3 error handling | Small |

---

## RFC 9204 — QPACK: Field Compression for HTTP/3

| § | Section | Status | Notes |
|---|---------|--------|-------|
| 2 | Compression Overview | ✅ Done | Static table encoding/decoding |
| 3 | Reference Tables | | |
| 3.1 | Static Table | ✅ Done | 99-entry table per RFC 9204 Appendix A |
| 3.2 | Dynamic Table | ❌ Missing | Static-only; dynamic refs gracefully skipped |
| 3.2.1 | Dynamic Table Size | ❌ Missing | |
| 3.2.2 | Dynamic Table Capacity | ❌ Missing | |
| 3.2.3 | Absolute and Relative Indices | ❌ Missing | |
| 4 | Wire Format | | |
| 4.1 | Encoder Instructions | ❌ Missing | |
| 4.2 | Decoder Instructions | ❌ Missing | |
| 4.3 | Encoder Stream | ⚠️ Partial | Stream opened but no instructions sent |
| 4.4 | Decoder Stream | ⚠️ Partial | Stream opened but no instructions sent |
| 4.5 | Field Line Representations | ✅ Done | Indexed, literal-with-name-ref, literal |
| 5 | Configuration | ⚠️ Partial | QPACK_MAX_TABLE_CAPACITY=0 (static only) |

### Summary — RFC 9204

| Status | Count |
|--------|-------|
| ✅ Done | 3 |
| ⚠️ Partial | 3 |
| ❌ Missing | 5 |

### Remaining Work — RFC 9204

| Priority | Section | Item | Effort |
|----------|---------|------|--------|
| P3 | §3.2 | Dynamic table (insertion, eviction, capacity mgmt) | Large |
| P3 | §4.1-4.2 | Encoder/decoder instructions | Medium |

---

## RFC 9297 — HTTP Datagrams and the Capsule Protocol

| § | Section | Status | Notes |
|---|---------|--------|-------|
| 2 | HTTP Datagram Negotiation | ✅ Done | H3_DATAGRAM setting (0x33) |
| 3 | HTTP Datagrams | ✅ Done | QUIC DATAGRAM frames 0x30/0x31 |
| 4 | Capsule Protocol | ❌ Missing | CAPSULE frames not implemented |
| 5 | The CONNECT Method | ✅ Done | Extended CONNECT support |

### Summary — RFC 9297

| Status | Count |
|--------|-------|
| ✅ Done | 3 |
| ❌ Missing | 1 |

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
| — | Multiple sessions | ⚠️ Partial | Single session per connection |
| — | Session close/drain | ⚠️ Partial | Basic close; no CLOSE_WEBTRANSPORT_SESSION |

### Summary — WebTransport: ✅ Functional (interop verified with quic-go)

---

## Overall Progress

| RFC | Done | Partial | Missing | Completion |
|-----|------|---------|---------|------------|
| RFC 9000 (QUIC) | 87 | 12 | 7 | ~93% |
| RFC 9001 (TLS) | 28 | 5 | 1 | ~91% |
| RFC 9002 (Loss/CC) | 22 | 2 | 0 | ~92% |
| RFC 9114 (HTTP/3) | 18 | 4 | 5 | ~74% |
| RFC 9204 (QPACK) | 3 | 3 | 5 | ~41% |
| RFC 9297 (Datagrams) | 3 | 0 | 1 | ~88% |
| RFC 9221 (QUIC DG) | 3 | 0 | 0 | 100% |
| WebTransport | 6 | 2 | 0 | ~88% |

### Top Priority Items Across All RFCs

| # | Item | RFC | Effort | Impact |
|---|------|-----|--------|--------|
| ~~1~~ | ~~Multi-connection server~~ | ~~9000 §5.2~~ | ~~Done~~ | ~~Done~~ |
| 2 | Certificate chain validation | 9001 §4.4 | Medium | Security |
| 3 | Session resumption (PSK/tickets) | 9001 §4.5 | Large | Performance (0-RTT) |
| 4 | 0-RTT data sending | 9001 §4.6 | Medium | Performance |
| 5 | ECN IP-level marking | 9000 §13.4 | Medium | Congestion signal quality |
| 6 | Server's Preferred Address | 9000 §9.6 | Medium | Migration feature |
| 7 | QPACK dynamic table | 9204 §3.2 | Large | H3 compression efficiency |
| 8 | Server Push (H3) | 9114 §4.6 | Large | H3 feature completeness |
| 9 | Graceful H3 shutdown | 9114 §5.2 | Medium | Connection lifecycle |
| 10 | Capsule Protocol | 9297 §4 | Medium | WT/proxy completeness |
