# RFC 5280 - X.509 Certificate Chain Validation

## Implementation Status: Partial

### What's Implemented

#### Chain Validation (via `std.crypto.Certificate`)
- **Signature verification**: Each certificate's signature is verified against its issuer's public key
- **Issuer/subject name matching**: Verified automatically by `Parsed.verify()`
- **Time validity**: Not-before/not-after checked against `sys.realtimeSeconds()`.
  Until Sept 2026 this read `sys.nanoTimestamp()`, which is `CLOCK_MONOTONIC`
  — its zero is the last boot, so every real certificate came back
  `CertificateNotYetValid` and nothing here could ever succeed. See
  [`../TODO.md`](../TODO.md) I2b.
- **Hostname verification**: Leaf cert checked against SNI via `verifyHostName()` (supports wildcards, SAN)
- **Trust anchor verification**: Last cert in chain verified against `Certificate.Bundle` (CA trust store)

#### Extension Validation (custom implementation in `tls13.zig`)
- **Basic Constraints (§4.2.1.9)**: Issuer certs must have `CA:TRUE` when basicConstraints is present
- **Path Length Constraint**: `pathLenConstraint` enforced on intermediate CA certs
- **Key Usage (§4.2.1.3)**: If keyUsage extension is present on an issuer cert, `keyCertSign` bit must be set

#### System Root CAs
- `src/quic/ca_bundle.zig`: `loadSystem()` for the OS store, `loadFile()` for a
  PEM bundle of your own. Zig 0.16 moved certificate loading behind `Io`, and
  this module is where that `Io` is built and torn down so it stays out of the
  library's signatures (the same call `src/sys.zig` documents).
- Supports macOS (Keychain), Linux (`/etc/ssl/certs/`), FreeBSD, OpenBSD, etc.
- Event-loop clients ask for it with `ClientConfig.ca` = `.system` or
  `.{ .file = path }`; either turns `skip_cert_verify` off. Each client loads
  its own copy — about 13 ms for the 163 certificates in the macOS store — so
  a process making many short-lived clients should build one bundle and pass
  it through `tls_config`.

### Configuration

```zig
const tls_config = TlsConfig{
    .cert_chain_der = cert_chain,
    .private_key_bytes = key_bytes,
    .alpn = &.{"h3"},
    .skip_cert_verify = false,    // Enable validation
    .ca_bundle = &ca_bundle,      // Trust anchor bundle
};
```

### What's NOT Implemented

- **Certificate Revocation Lists (CRL)** — RFC 5280 §5
- **OCSP stapling** — RFC 6960
- **Extended Key Usage** — `id-kp-serverAuth` not checked on a server's leaf (recommended but not required by TLS 1.3); `id-kp-clientAuth` is checked on a client's
- **Name Constraints** — RFC 5280 §4.2.1.10
- **Policy Constraints** — RFC 5280 §4.2.1.11
- **Mandatory ca_bundle enforcement** — When `skip_cert_verify=false` and no `ca_bundle` is provided, the chain's self-signed root is accepted without trust anchor verification

#### Client certificates
- A server asks for one when the certificate SNI selected has
  `CertEntry.client_auth` (or, without `certs`, `TlsConfig.client_auth`):
  a `CertificateRequest` (RFC 8446 §4.3.2) with an empty context, our
  `signature_algorithms`, and `certificate_authorities` when
  `ClientAuth.authorities` is set (`tls13.certificateAuthorities` builds it
  from the bundle, or nothing past 8 KiB). Same for QUIC and `tls_server`.
- The client's chain goes through `tls13.verifyPeerChain` — the same links,
  dates and issuer constraints as a server chain, anchored in
  `ClientAuth.ca_bundle` — and the leaf must allow client authentication:
  `digitalSignature` in keyUsage and `clientAuth` (or anyExtendedKeyUsage) in
  extendedKeyUsage, each when present. No name is checked; the application
  reads the leaf from `peerCertificate()` and decides what it proves.
- `ClientAuth.mode = .required` fails a client that sends no certificate
  with `certificate_required`; `.optional` lets it in with no identity. A
  certificate that does not verify fails either way (`bad_certificate`,
  `unknown_ca`, `certificate_expired`), and a bad `CertificateVerify` with
  `decrypt_error`.
- Session tickets are neither issued nor accepted under a client-auth
  policy: a ticket carries no client identity, so resuming would skip the
  certificate. Every connection proves it afresh (and so never gets 0-RTT).
- A client answers a `CertificateRequest` with `client_certificate` when its
  key can sign with a scheme the server offers, and with an empty
  `Certificate` otherwise. Refusing to answer used to end the handshake,
  which is what made every Cloudflare edge — `cdn.moq.dev` among them —
  unreachable.
- Post-handshake authentication (RFC 8446 §4.6.2) is not supported; RFC 9001
  §4.4 forbids it over QUIC anyway.

#### Malformed certificates
`std.crypto.Certificate.der.Element.parse` checks no length against its
buffer, so a truncated or lying certificate indexes out of bounds inside
`Certificate.parse`. Every certificate a peer sends first passes
`tls13.certificateWellFormed`: the X.509 skeleton std walks, each element
within its parent, extension values well-formed DER, an RSA key's
`SEQUENCE { INTEGER, INTEGER }`. A fuzz target and a random-corruption test
feed what it accepts to std's parser and our extension readers.

### Caveats

- `skip_cert_verify` defaults to `true` for backward compatibility
- V1 certificates (no extensions) are accepted as CAs when no basicConstraints is present — this matches common practice but is less strict than RFC 5280's recommendation
- The interop client always uses `skip_cert_verify=true` since interop test
  peers use various self-signed certs. The MoQ interop image's
  `TLS_DISABLE_VERIFY` defaults to `1` for the same reason.

### TLS over TCP client (`quic.tls_client`)

Same checks, from the same helpers (`tls13.issuerConstraintsOk`,
`tls13.verifyCertificateVerifySignature`), with these differences:

- Verification is all or nothing: `Config.ca_bundle` set means chain, host
  name and CertificateVerify are all checked; null means none are. There is
  no "chain without trust anchor" middle ground.
- The chain is accepted at the first certificate a bundle CA signed, so extra
  certificates a server appends (a cross-signed root, say) do not matter.
- An IP literal in `server_name` is matched against iPAddress SANs
  (`std.crypto.Certificate.verifyHostName` only knows DNS names) and is not
  sent as SNI.
- Failures are told apart: `UnknownCa`, `CertificateExpired`,
  `CertificateHostMismatch`, `BadCertificate`, each with its alert.
- CertificateVerify also accepts ECDSA P-384, which the QUIC client does not offer.

### Verified against

`cdn.moq.dev` (Cloudflare, ECDSA chain) over both raw QUIC and WebTransport
with `ClientConfig.ca = .system`, and our own `interop/certs/ca.crt` with
`.file`. Sept 2026.
