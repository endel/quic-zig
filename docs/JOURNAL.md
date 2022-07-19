# Netcode Journal and Progress Report

## July 2022

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
