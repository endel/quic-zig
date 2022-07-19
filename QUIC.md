# QUIC

## Handshake

QUIC integrates the TLS handshake [TLS13](https://datatracker.ietf.org/doc/html/rfc9000#ref-TLS13), although using a customized framing for protecting packets.

The integration of TLS and QUIC is described in more detail in [QUIC-TLS](https://datatracker.ietf.org/doc/html/rfc9000#ref-QUIC-TLS).

## Packets / Encryption

QUIC authenticates the entirety of each packet and encrypts as much of each packet as is practical.

QUIC packets are carried in UDP datagrams [UDP](https://datatracker.ietf.org/doc/html/rfc768) to better facilitate deployment in existing systems and networks.

## Streams

Application protocols exchange information over a QUIC connection via streams, which are ordered sequences of bytes.

**Two types of streams:**

- bidirectional streams (allow both endpoints to send data)
- unidirectional streams (allow a single endpoint to send data)

A credit-based scheme is used to limit stream creation and to bound the amount of data that can be sent.

## Congestion Control

QUIC provides the necessary feedback to implement reliable delivery and congestion control.

An algorithm for detecting and recovering from loss of data is described in Section 6 of [QUIC-RECOVERY](https://datatracker.ietf.org/doc/html/rfc9000#ref-QUIC-RECOVERY).

QUIC depends on congestion control to avoid network congestion.  An exemplary congestion control algorithm is described in Section 7 of [QUIC-RECOVERY](https://datatracker.ietf.org/doc/html/rfc9000#ref-QUIC-RECOVERY).

## Connection migration

QUIC connections are not strictly bound to a single network path.

Connection migration uses connection identifiers to allow connections to
transfer to a new network path.

Only clients are able to migrate in this version of QUIC.

This design also allows connections to continue after changes in network
topology or address mappings, such as might be caused by NAT rebinding.

## Connection termination

Once established, multiple options are provided for connection termination.

- Applications can manage a graceful shutdown
- Endpoints can negotiate a timeout period
- Errors can cause immediate connection teardown
- A stateless mechanism provides for termination of connections after one endpoint has lost state.

