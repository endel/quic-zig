https://datatracker.ietf.org/doc/html/rfc9000

1.  Overview
  1.1.  Document Structure
  1.2.  Terms and Definitions
  1.3.  Notational Conventions

2.  Streams
  2.1.  Stream Types and Identifiers
  2.2.  Sending and Receiving Data
  2.3.  Stream Prioritization
  2.4.  Operations on Streams

3.  Stream States
  3.1.  Sending Stream States
  3.2.  Receiving Stream States
  3.3.  Permitted Frame Types
  3.4.  Bidirectional Stream States
  3.5.  Solicited State Transitions

4.  Flow Control
  4.1.  Data Flow Control
  4.2.  Increasing Flow Control Limits
  4.3.  Flow Control Performance
  4.4.  Handling Stream Cancellation
  4.5.  Stream Final Size
  4.6.  Controlling Concurrency

5.  Connections
  5.1.  Connection ID
    5.1.1.  Issuing Connection IDs
    5.1.2.  Consuming and Retiring Connection IDs
  5.2.  Matching Packets to Connections
    5.2.1.  Client Packet Handling
    5.2.2.  Server Packet Handling
    5.2.3.  Considerations for Simple Load Balancers
  5.3.  Operations on Connections

6.  Version Negotiation
  6.1.  Sending Version Negotiation Packets
  6.2.  Handling Version Negotiation Packets
  6.3.  Using Reserved Versions

7.  Cryptographic and Transport Handshake
  7.1.  Example Handshake Flows
  7.2.  Negotiating Connection IDs
  7.3.  Authenticating Connection IDs
  7.4.  Transport Parameters
    7.4.1.  Values of Transport Parameters for 0-RTT
    7.4.2.  New Transport Parameters
  7.5.  Cryptographic Message Buffering

8.  Address Validation
  8.1.  Address Validation during Connection Establishment
    8.1.1.  Token Construction
    8.1.2.  Address Validation Using Retry Packets
    8.1.3.  Address Validation for Future Connections
    8.1.4.  Address Validation Token Integrity
  8.2.  Path Validation
    8.2.1.  Initiating Path Validation
    8.2.2.  Path Validation Responses
    8.2.3.  Successful Path Validation
    8.2.4.  Failed Path Validation

9.  Connection Migration
  9.1.  Probing a New Path
  9.2.  Initiating Connection Migration
  9.3.  Responding to Connection Migration
    9.3.1.  Peer Address Spoofing
    9.3.2.  On-Path Address Spoofing
    9.3.3.  Off-Path Packet Forwarding
  9.4.  Loss Detection and Congestion Control
  9.5.  Privacy Implications of Connection Migration
  9.6.  Server's Preferred Address
    9.6.1.  Communicating a Preferred Address
    9.6.2.  Migration to a Preferred Address
    9.6.3.  Interaction of Client Migration and Preferred Address
  9.7.  Use of IPv6 Flow Label and Migration

10. Connection Termination
  10.1.  Idle Timeout
    10.1.1.  Liveness Testing
    10.1.2.  Deferring Idle Timeout
  10.2.  Immediate Close
    10.2.1.  Closing Connection State
    10.2.2.  Draining Connection State
    10.2.3.  Immediate Close during the Handshake
  10.3.  Stateless Reset
    10.3.1.  Detecting a Stateless Reset
    10.3.2.  Calculating a Stateless Reset Token
    10.3.3.  Looping

11. Error Handling
  11.1.  Connection Errors
  11.2.  Stream Errors

12. Packets and Frames
  12.1.  Protected Packets
  12.2.  Coalescing Packets
  12.3.  Packet Numbers
  12.4.  Frames and Frame Types
  12.5.  Frames and Number Spaces

13. Packetization and Reliability
  13.1.  Packet Processing
  13.2.  Generating Acknowledgments
    13.2.1.  Sending ACK Frames
    13.2.2.  Acknowledgment Frequency
    13.2.3.  Managing ACK Ranges
    13.2.4.  Limiting Ranges by Tracking ACK Frames
    13.2.5.  Measuring and Reporting Host Delay
    13.2.6.  ACK Frames and Packet Protection
    13.2.7.  PADDING Frames Consume Congestion Window
  13.3.  Retransmission of Information
  13.4.  Explicit Congestion Notification
    13.4.1.  Reporting ECN Counts
    13.4.2.  ECN Validation

14. Datagram Size
  14.1.  Initial Datagram Size
  14.2.  Path Maximum Transmission Unit
    14.2.1.  Handling of ICMP Messages by PMTUD
  14.3.  Datagram Packetization Layer PMTU Discovery
    14.3.1.  DPLPMTUD and Initial Connectivity
    14.3.2.  Validating the Network Path with DPLPMTUD
    14.3.3.  Handling of ICMP Messages by DPLPMTUD
  14.4.  Sending QUIC PMTU Probes
    14.4.1.  PMTU Probes Containing Source Connection ID

15. Versions

16. Variable-Length Integer Encoding

17. Packet Formats
  17.1.  Packet Number Encoding and Decoding
  17.2.  Long Header Packets
    17.2.1.  Version Negotiation Packet
    17.2.2.  Initial Packet
    17.2.3.  0-RTT
    17.2.4.  Handshake Packet
    17.2.5.  Retry Packet
  17.3.  Short Header Packets
    17.3.1.  1-RTT Packet
  17.4.  Latency Spin Bit

18. Transport Parameter Encoding
  18.1.  Reserved Transport Parameters
  18.2.  Transport Parameter Definitions

19. Frame Types and Formats
  19.1.  PADDING Frames
  19.2.  PING Frames
  19.3.  ACK Frames
    19.3.1.  ACK Ranges
    19.3.2.  ECN Counts
  19.4.  RESET_STREAM Frames
  19.5.  STOP_SENDING Frames
  19.6.  CRYPTO Frames
  19.7.  NEW_TOKEN Frames
  19.8.  STREAM Frames
  19.9.  MAX_DATA Frames
  19.10. MAX_STREAM_DATA Frames
  19.11. MAX_STREAMS Frames
  19.12. DATA_BLOCKED Frames
  19.13. STREAM_DATA_BLOCKED Frames
  19.14. STREAMS_BLOCKED Frames
  19.15. NEW_CONNECTION_ID Frames
  19.16. RETIRE_CONNECTION_ID Frames
  19.17. PATH_CHALLENGE Frames
  19.18. PATH_RESPONSE Frames
  19.19. CONNECTION_CLOSE Frames
  19.20. HANDSHAKE_DONE Frames
  19.21. Extension Frames

20. Error Codes
  20.1.  Transport Error Codes
  20.2.  Application Protocol Error Codes

21. Security Considerations
  21.1.  Overview of Security Properties
    21.1.1.  Handshake
    21.1.2.  Protected Packets
    21.1.3.  Connection Migration
  21.2.  Handshake Denial of Service
  21.3.  Amplification Attack
  21.4.  Optimistic ACK Attack
  21.5.  Request Forgery Attacks
    21.5.1.  Control Options for Endpoints
    21.5.2.  Request Forgery with Client Initial Packets
    21.5.3.  Request Forgery with Preferred Addresses
    21.5.4.  Request Forgery with Spoofed Migration
    21.5.5.  Request Forgery with Version Negotiation
    21.5.6.  Generic Request Forgery Countermeasures
  21.6.  Slowloris Attacks
  21.7.  Stream Fragmentation and Reassembly Attacks
  21.8.  Stream Commitment Attack
  21.9.  Peer Denial of Service
  21.10. Explicit Congestion Notification Attacks
  21.11. Stateless Reset Oracle
  21.12. Version Downgrade
  21.13. Targeted Attacks by Routing
  21.14. Traffic Analysis

22. IANA Considerations
  22.1.  Registration Policies for QUIC Registries
    22.1.1.  Provisional Registrations
    22.1.2.  Selecting Codepoints
    22.1.3.  Reclaiming Provisional Codepoints
    22.1.4.  Permanent Registrations
  22.2.  QUIC Versions Registry
  22.3.  QUIC Transport Parameters Registry
  22.4.  QUIC Frame Types Registry
  22.5.  QUIC Transport Error Codes Registry

23. References
  23.1.  Normative References
  23.2.  Informative References

Appendix A.  Pseudocode
  A.1.  Sample Variable-Length Integer Decoding
  A.2.  Sample Packet Number Encoding Algorithm
  A.3.  Sample Packet Number Decoding Algorithm
  A.4.  Sample ECN Validation Algorithm