# Netcode Journal and Progress Report

## October 2022
- 18.10: Ok 🤦 I was getting the `first` from the (pn+sample) rather than the
  first byte of the packet itself.
- 16.10: Still trying to decrypt packet number. The `first` byte seems to
  diverge on my implementation than Quiche's. The `mask`, and `sample` are ok,
  though. (Maybe the quic-varint is advancing a byte that it shouldn't? need to
  research & experiment)
- 10.10: First heard of the [Warp draft](https://datatracker.ietf.org/doc/draft-lcurley-warp/) This draft is brought by a Twitch engineer: Luke Curley / @kixelated very active on WebTransport draft as well.
  Warp is a segmented live media transport protocol. Warp maps live media to
  QUIC streams based on the underlying media encoding.  Media is prioritized to
  reduce latency when encountering congestion.
- 09.10: Realized the part where I've been stuck ([parsing packer
  number](https://www.rfc-editor.org/rfc/rfc9000.html#name-packet-number-encoding-and-))
  is not fully implemented even by shiguredo's implementation.
- 01.10 ~ 08.10: Been reading and understanding shiguredo's take on their QUIC
  implementation.

## August 2022

- 29.09: `SSLKEYLOGFILE` support is important for debugging from external software https://firefox-source-docs.mozilla.org/security/nss/legacy/key_log_format/index.html
  - > "Key logs can be written by NSS so that external programs can decrypt TLS connections. Wireshark 1.6.0 and above can use these log files to decrypt packets. You can tell Wireshark where to find the key file via Edit→Preferences→Protocols→TLS→(Pre)-Master-Secret log filename."
- 29.09: A japanese company (shiguredo) seems to be implementing TLS1.3 on Zig!
  https://github.com/shiguredo/tls13-zig/, oops and they also are implementing
  QUIC! Apache 2.0-licensed ongoing development for server and client here:
  https://github.com/shiguredo/quic-server-zig |
  https://github.com/shiguredo/quic-client-zig
- 26.09: Opened/had a glance at RFC3394 for the first time today
  https://www.rfc-editor.org/rfc/rfc3394. Apparently Feilich already implements
  it and hopefully I won't need to "port" cryptogams over.
- 26.09: _(💭 inner-thoughts)_ How can it be so hard to get 5 encrypted bytes? The `new_mask()`
  method goes through assembler just to get 5 encrypted bytes out of a sample.
- 23.09: Diving into the `aead.new_mask()` method call habbit hole from quiche,
  I found out that boringssl has many different ASM implementations based on the
  host chipset, which are compiled using PERL. They were implemented originally
  by [@appro](https://www.openssl.org/~appro/cryptogams/), he also released the
  low-level cryptographic primitives on a more permissive license under the name
  of CRYPTOGAMS.

- 17.09: Found this nice TLS+QUIC step-by-step illustrations that explains every
  byte. Very interesting! https://tls13.xargs.org/ | https://quic.xargs.org/

- 13.09: Taking quiche + ring/aead as inspiration for decryption/removing header
  protection. (Noticed that some Rust ring and tokyo maintainers are very young
  {@briansmith}, which I found it very curious)

- 12.09: I'm always mesmerized by the quality of quiche's source-code. Been
  looking how they decrypt header, and their code overall looks so clean &
  simple. I need to borrow some of that.

- 06.09: Trying to decrypt header.

- 30.08: Having some progress understanding how TLS initial packets are
  encrypted. Made a PR trying to support zig's stage2 compiler for feilich
  (https://github.com/Luukdegram/feilich/pull/1)

- 26.08: Found this gist from  [Martin
  Thomson](https://datatracker.ietf.org/person/martin.thomson@gmail.com) (one of
  the authors of QUIC, and other 38 RFCs) on protecting/encrypting quic
  packets
  https://gist.github.com/martinthomson/1f000d3e389b0bf1308e1043e141fbb9.

- 25.08: Reading more aioquic sources. Continued adapting its TLS context stuff
  to zig.

- 24.08: Been feeling stuck reading TLS handshake and the TLS context required
  for setting up connections. Considering embedding quictls/openssl instead of
  trying to adapt feilich to support QUIC stuff. Final thought: embedding
  external TLS is going to make cross-platform compilation potentially more
  complicated.

- 04.08: _(💭 inner-thoughts)_ The more I read implementations and portions of
  the specs, the more I see this is a multi-year endeavour that may never end.
  I'm struggling to implement the very basics.

- 01.08: Got stuck understanding quiche's `quiche::accept()` method. Watched
  Robin Marx's video on QUIC where he mentions that to understand QUIC one must
  read and understand 4 different RFC documents. So, now I started reading RFC
  9001 (Using TLS to Secure QUIC).

## July 2022

- Finally touching TLS/Handshake stuff, need to understand how QUIC handshake
  works.
- Parsing QUIC "Initial" header in Zig. Progress! (tiny, but progress!)
- Realized using aioquic as a reference may not be ideal, since it lacks
  low-level system calls that are required on Zig. As I'm a noob with systems
  programming, I need to see low-level references to better understand stuff.
  Thus, started using picoquic (C++, very good & readable code!) _and_ quiche
  (Rust, more elegant than picoquic, also very readable!). I'm not copying or
  porting any code over, just using them as references.
- Been trying to use feilich's server and the web browser as a client. Could see
  the TLS server receiving some messages, but the handshake doesn't succeed. I'm
  clearly missing some steps, as I'm not really sure what the browser is doing
  in the request. Also, I'm not even sure the CA/certs I'm using are correct.
- Instead of using web browser as a client, I've decided to run a Python-based
  http/3 implementation, which I can modify and better understand what's going
  on ([aioquic](https://github.com/aiortc/aioquic/))
- Been reading the sources of `aioquic` (really well-written and easy to
  understand!), and figured out that feilich's TLS server (`StreamServer`) only
  listens to TCP, whereas QUIC communicates through `socket.SOCK_DGRAM`  (Zig's
  `StreamServer` used to be called
  [`TcpServer`](https://github.com/ziglang/zig/commit/f4d8dc278b312fc3eccf33a37cfe89c7c012d6fd))


## June 2022

**17/06/2022:**
- Started reading WebTransport's W3C Meeting Notes from https://www.w3.org/wiki/WebTransport/Meetings#WebTransport_Bi-weekly_Virtual_Meeting_.2339_late_-_May_24th.2C_2022
- Discovered that [Justin Uberti](https://github.com/juberti) is the author of the first WebRTC specs, same person who worked in Google Due, and Stadia. (https://drive.google.com/file/d/1U_arWk-uOqdb8uCWvceUQdX5atf_6Xi2/view)
- Found an initial Zig implementation for TLS 1.3 (https://github.com/Luukdegram/feilich), which may not be 100% finished. The author [Luuk de Gram](https://github.com/Luukdegram) is also member of the Zig Core Team.

**16/06/2022:**
- TLS 1.3 is going to be a major requirement.
- The BearSSL project (which currently only supports TLS 1.2) has documented their status to support TLS 1.3 in their [documentation](https://bearssl.org/tls13.html).

**15/06/2022:**
- Found a proper MsQuic C# implementation https://github.com/StirlingLabs/MsQuic.Net, but it doesn't currently work on Mac arm64 (https://github.com/StirlingLabs/MsQuic.Net/issues/3).

(💭 _"Should I re-write/port an entire HTTP/3 implementation in ZIG?"_)

**14/06/2022:**

- Found a C# implementation of WebTransport in the wild, which uses msquic bindings. https://github.com/wegylexy/webtransport

## March 2022

**06/03/2022**:
- I need to understand how to import and use [quictls/openssl](https://github.com/quictls/openssl/tree/OpenSSL_1_1_1m+quic) from Zig.

- Found [ziget](https://github.com/marler8997/ziget) - a project that consumes a few TLS implementations in order request network assets. TLS implementations include `openssl`, `iguana` and `schannel`.

- If I can get `ziget` to compile, I can adapt it to use `quictls/openssl` instead of `openssl`.

---

**05/03/2022**:
Checking out alternative TLS implementations that could be used, such as:

- [quictls/openssl](https://github.com/quictls/openssl/tree/OpenSSL_1_1_1m+quic) - probably the most correct implementationn to use. It is a joined effort between Akamai and Microsoft to bring QUIC features to many OpenSSL versions.
- [picotls](https://github.com/h2o/picotls) supports 3 different "crypto engines" - ["fusion"](https://github.com/h2o/picotls/pull/310) being the most interesting for this due to QUIC support
- [s2n-tls](https://github.com/aws/s2n-tls)
- [BoringSSL](https://boringssl.googlesource.com/boringssl/) Designed for Google's needs - they don't recommend 3rd parties to depend on it, as per quote: `"We don't recommend that third parties depend upon it."`
- [BearSSL](https://github.com/MasterQ32/zig-bearssl), made by [@MasterQ32](https://github.com/MasterQ32), has Zig integration, but doesn't have TLS 1.3, thus can't be used for QUIC.

---

## February 2022

**Tech**

- Made a simple UDP listener in Zig
- Started hands-on with Zig and learning its basics

**Brand/product**

- Netcode 1st Logo
- Purchased [netcode.io](http://netcode.io/) for $179 (auction, with 3 other bidders)
