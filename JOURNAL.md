# Netcode Journal and Progress Report

## March 2022

**06/03**: I need to understand how to import and use [quictls/openssl](https://github.com/quictls/openssl/tree/OpenSSL_1_1_1m+quic) from Zig.

Found [ziget](https://github.com/marler8997/ziget) - a project that consumes a few TLS implementations in order request network assets. TLS implementations include `openssl`, `iguana` and `schannel`.

If I can get `ziget` to compile, I can adapt it to use `quictls/openssl` instead of `openssl`.

---

**05/03**: Checking out alternative TLS implementations that could be used, such as:

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
