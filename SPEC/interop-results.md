# Interop Test Results

Date: 2026-09-18  ·  quic-zig `4988228`, Zig 0.16.0, `zig build -Doptimize=ReleaseSafe`
Peers: `martenseemann/quic-go-interop:latest`, `cloudflare/quiche-qns:latest`
Harness: `interop/runner/matrix.sh` (quic-interop-runner + quic-network-simulator)

## QUIC / HTTP/3 matrix

Read `A<-B` as "A is the server, B is the client".

| Test | quic-go<-quic-zig | quic-zig<-quic-go | quic-zig<-quiche | quiche<-quic-zig |
|---|---|---|---|---|
| handshake | ✅ | ✅ | ✅ | ✅ |
| transfer | ✅ | ✅ | ✅ | ✅ |
| http3 | ✅ | ✅ | ✅ | ✅ |
| retry | ✅ | ✅ | ✅ | ✅ |
| resumption | ✅ | ✅ | ✅ | ✅ |
| zerortt | ✅ | ✅ | ✅ | ✅ |
| multiplexing | ✅ | ✅ | ❌ | ✅ |
| longrtt | ✅ | ✅ | ✅ | ✅ |
| keyupdate | ✅ | ✅ | — | ✅ |
| chacha20 | ✅ | ✅ | — | ✅ |
| v2 | — | — | — | — |
| ipv6 | ✅ | ✅ | ✅ | ✅ |
| ecn | — | — | — | — |
| amplificationlimit | ✅ | ✅ | ❌ | ✅ |
| rebind-port | ✅ | ✅ | ❌ | ❌ |
| rebind-addr | ✅ | ✅ | ❌ | ❌ |
| connectionmigration | — | ❌ | ❌ | — |
| blackhole | ✅ | ✅ | ✅ | ✅ |
| handshakeloss | ✅ | ✅ | ❌ | ✅ |
| transferloss | ✅ | ✅ | ✅ | ✅ |
| handshakecorruption | ✅ | ✅ | ❌ | ✅ |
| transfercorruption | ✅ | ✅ | ✅ | ✅ |

Totals:
- `quic-go<-quic-zig` — 19 pass, 0 fail, 3 unsupported, of 22
- `quic-zig<-quic-go` — 19 pass, 1 fail, 2 unsupported, of 22
- `quic-zig<-quiche` — 11 pass, 7 fail, 4 unsupported, of 22
- `quiche<-quic-zig` — 17 pass, 2 fail, 3 unsupported, of 22

Legend: ✅ pass · ❌ fail · — the peer does not implement the case.

## Changes since the previous matrix (`4ca8f01`)

    chacha20            quic-go<-quic-zig   ❌ → ✅
    chacha20            quic-zig<-quic-go   ❌ → ✅
    chacha20            quiche<-quic-zig    ❌ → ✅
    amplificationlimit  quic-zig<-quiche    ✅ → ❌

Neither move comes from this branch. The `e09f4c5` (main) tree, built as its own
image and run in the same session, gives the same verdict on each of these
cells: chacha20 passes in all three directions, and amplificationlimit against
quiche's client fails 3 runs of 3, exactly as this branch does.

chacha20 was the open item in the previous run. It already passes at
`e09f4c5`, and no separate fix is recorded for it.

### amplificationlimit against quiche — a newer quiche client, not us
The `cloudflare/quiche-qns:latest` pulled for this run was built on 2026-09-17.
Our server stays within the limit: it sends a 10 704-byte first flight after
receiving 3 600 bytes, against a limit of 10 800. The check still fails, because it only stops
counting when the client sends a datagram that *starts* with a Handshake packet.
This quiche client never sends one. Its Finished goes out coalesced behind an
Initial ACK, and after that it sends only 1-RTT. The runner therefore reads
the whole trace as an unfinished handshake. The `e09f4c5` server produces the same
pcap and the same verdict.

## A caution about this table

The binaries under test must be cross-compiled by
`interop/runner/build_image.sh`, not built inside the image. Building them in
the `linux/amd64` builder stage on an Apple-silicon host runs the x86_64 Zig
compiler under emulation, and its ReleaseSafe output has a broken ECDSA signing
path: every peer rejects the server's CertificateVerify and every case in the
matrix fails at the handshake. It reads exactly like a protocol regression.

Ten seconds separates the two, where the matrix takes hours — run the image's
own binary against a peer client directly:

    cd interop/quic-interop-runner && ./certs.sh /tmp/rc 1
    docker run --rm --platform linux/amd64 -d --name s -p 15730:443/udp \
      -v /tmp/rc:/certs:ro -v /tmp/www:/www:ro \
      -e CERTS=/certs -e WWW=/www -e TESTCASE=http3 -e PORT=443 \
      --entrypoint /usr/local/bin/interop-server quic-zig-interop:latest
    (cd interop/quic-go && ./h3client_bin --addr 127.0.0.1:15730)

If that handshake fails, the toolchain is the suspect, not the protocol.

## What the remaining failures are

### connectionmigration and rebind-addr / rebind-port — environmental
The runner's `connectionmigration` needs the *client* to migrate. quic-go's
client does not, so "Server saw only a single path in use" is what the check
reports regardless of what we do; quiche declares the case unsupported outright.

The rebind cases fail the same way in three of the four pairings: the simulator
starts rewriting the client's source address within ~200 ms of our client's
first packet, so the rebind lands during the handshake, and the peer keeps
addressing its replies to the pre-rebind address for many seconds. In the
rebind-addr pairing that does pass, quic-go's client's very first packet already
carries the post-rebind address. Our client answers PATH_CHALLENGE correctly and
quiche logs "Connection migrated"; the transfer simply never resumes because
nothing reaches us at the address the peer is using.

### multiplexing against quiche — open
quiche's client completes 1986 of 1999 requests and times out. Granting the last
partial MAX_STREAMS batch (which was a real bug, and is fixed) did not move the
number, so the stall is something else. Not reproduced against quic-go, whose
client passes the same case.

### handshakeloss / handshakecorruption against quiche — slow, not broken
The 50 sequential handshakes under 30 % loss do complete, but at roughly 2.7 s
each: quiche's client finishes 11 of them and then hits its own overall timeout.
The connection it is on when time runs out is healthy — it has exchanged
Finished and is sending 1-RTT. quic-go's client passes the same case, so this
reads as our Initial/Handshake retransmission being slower off the mark than
quiche is willing to wait for, rather than a stall.
