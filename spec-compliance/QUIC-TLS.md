https://datatracker.ietf.org/doc/html/rfc9001

1.  Introduction

2.  Notational Conventions
  2.1.  TLS Overview

3.  Protocol Overview

4.  Carrying TLS Messages
  4.1.  Interface to TLS
    4.1.1.  Handshake Complete
    4.1.2.  Handshake Confirmed
    4.1.3.  Sending and Receiving Handshake Messages
    4.1.4.  Encryption Level Changes
    4.1.5.  TLS Interface Summary
  4.2.  TLS Version
  4.3.  ClientHello Size
  4.4.  Peer Authentication
  4.5.  Session Resumption
  4.6.  0-RTT
    4.6.1.  Enabling 0-RTT
    4.6.2.  Accepting and Rejecting 0-RTT
    4.6.3.  Validating 0-RTT Configuration
  4.7.  HelloRetryRequest
  4.8.  TLS Errors
  4.9.  Discarding Unused Keys
    4.9.1.  Discarding Initial Keys
    4.9.2.  Discarding Handshake Keys
    4.9.3.  Discarding 0-RTT Keys

5.  Packet Protection
  5.1.  Packet Protection Keys
  5.2.  Initial Secrets
  5.3.  AEAD Usage
  5.4.  Header Protection
    5.4.1.  Header Protection Application
    5.4.2.  Header Protection Sample
    5.4.3.  AES-Based Header Protection
    5.4.4.  ChaCha20-Based Header Protection
  5.5.  Receiving Protected Packets
  5.6.  Use of 0-RTT Keys
  5.7.  Receiving Out-of-Order Protected Packets
  5.8.  Retry Packet Integrity

6.  Key Update
  6.1.  Initiating a Key Update
  6.2.  Responding to a Key Update
  6.3.  Timing of Receive Key Generation
  6.4.  Sending with Updated Keys
  6.5.  Receiving with Different Keys
  6.6.  Limits on AEAD Usage
  6.7.  Key Update Error Code

7.  Security of Initial Messages

8.  QUIC-Specific Adjustments to the TLS Handshake
  8.1.  Protocol Negotiation
  8.2.  QUIC Transport Parameters Extension
  8.3.  Removing the EndOfEarlyData Message
  8.4.  Prohibit TLS Middlebox Compatibility Mode

9.  Security Considerations
  9.1.  Session Linkability
  9.2.  Replay Attacks with 0-RTT
  9.3.  Packet Reflection Attack Mitigation
  9.4.  Header Protection Analysis
  9.5.  Header Protection Timing Side Channels
  9.6.  Key Diversity
  9.7.  Randomness

10. IANA Considerations

11. References
  11.1.  Normative References
  11.2.  Informative References
Appendix A.  Sample Packet Protection
  A.1.  Keys
  A.2.  Client Initial
  A.3.  Server Initial
  A.4.  Retry
  A.5.  ChaCha20-Poly1305 Short Header Packet
Appendix B.  AEAD Algorithm Analysis
  B.1.  Analysis of AEAD_AES_128_GCM and AEAD_AES_256_GCM Usage
        Limits
    B.1.1.  Confidentiality Limit
    B.1.2.  Integrity Limit
  B.2.  Analysis of AEAD_AES_128_CCM Usage Limits

