# netcode.io

HTTP/3 implementation written in Zig.

## Main specifications

**Specifications**

- QUIC: https://w3c.github.io/webtransport/
- HTTP/3: https://datatracker.ietf.org/doc/html/draft-ietf-quic-http
- WebTransport: https://w3c.github.io/webtransport/

---

# QUIC

**RFC:** https://datatracker.ietf.org/doc/html/rfc9000
**About:** https://datatracker.ietf.org/wg/quic/about/
**Working Group:** https://quicwg.org/

**Implementations**

- https://github.com/aws/s2n-quic
- https://github.com/private-octopus/picoquic
- https://en.wikipedia.org/wiki/HTTP/3#Libraries
- https://github.com/facebookincubator/mvfst
- https://github.com/microsoft/msquic
- https://github.com/lucas-clemente/quic-go
- https://github.com/Vect0rZ/Quic.NET

**More**

- (Empirical study on QUIC implementations) https://qlog.edm.uhasselt.be/epiq/
- https://www.chromium.org/quic/playing-with-quic/

## QUIC "Extensions"

### QPACK:

- https://github.com/litespeedtech/ls-qpack

### Load Balancing

- ...

### qlog

- https://github.com/quicwg/qlog

---

## Interesting ZIG code for reference:

- statsd-zig: https://github.com/remeh/statsd-zig/blob/master/src/main.zig
- zig-network: https://github.com/MasterQ32/zig-network/blob/master/network.zig

---

## License

© 2022 Endel Dreyer. Apache License 2.0.
