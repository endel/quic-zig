# netcode.io

HTTP/3 implementation written in Zig.

Objectives: https://github.com/private-octopus/picoquic/pull/1372/files

## WebTransport links

Browser's `web-platform-tests`: https://wpt.fyi/webtransport

## Main specifications

**Specifications**

- [ ] QUIC: https://w3c.github.io/webtransport/
  - [ ] TLS 1.3: https://tools.ietf.org/html/draft-ietf-tls-tls13-14
  - [ ] TLS + QUIC: https://datatracker.ietf.org/doc/html/rfc9001
    - [ ] Openssl 1.1.1p (Example PR) https://github.com/quictls/openssl/pull/87
    - [ ] Openssl 3.0.5+quic (Example PR) https://github.com/quictls/openssl/pull/88
- [ ] HTTP/3: https://datatracker.ietf.org/doc/html/draft-ietf-quic-http
- [ ] WebTransport: https://w3c.github.io/webtransport/

**Congestion Control Algorithms**

- New Reno: https://tools.ietf.org/html/rfc6582
- BBR: https://www.ietf.org/proceedings/97/slides/slides-97-iccrg-bbr-congestion-control-02.pdf
- SCReAM: https://github.com/EricssonResearch/scream
- (More: https://en.wikipedia.org/wiki/TCP_congestion_control)

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

### Unreliable Datagram Extension

- https://datatracker.ietf.org/doc/html/rfc9221

### QPACK:

QPACK is the header compression used in QUIC. It has a "simple" implementation,
that compresses 50% of the header, and a "complex" implementation that
compresses more.

- https://github.com/litespeedtech/ls-qpack

### Load Balancing (Not fully established yet)

- Draft: [QUIC-LB: Generating Routable QUIC Connection IDs](https://datatracker.ietf.org/doc/html/rfc9000)
- "Process demultiplexing"? (https://github.com/quicwg/load-balancers/pull/178/files)
- "Twelve-pass encryption"? (https://github.com/quicwg/load-balancers/pull/175)

### qlog

- https://github.com/quicwg/qlog

---

## License

© 2022 Endel Dreyer. Apache License 2.0.
