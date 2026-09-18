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
- **Extended Key Usage** — `id-kp-serverAuth` not checked on leaf (recommended but not required by TLS 1.3)
- **Name Constraints** — RFC 5280 §4.2.1.10
- **Policy Constraints** — RFC 5280 §4.2.1.11
- **Mandatory ca_bundle enforcement** — When `skip_cert_verify=false` and no `ca_bundle` is provided, the chain's self-signed root is accepted without trust anchor verification

#### Client certificates
- A server's `CertificateRequest` (RFC 8446 §4.3.2) is answered with an empty
  `Certificate` and no `CertificateVerify` (§4.4.2). We never offer one.
  Refusing to answer used to end the handshake, which is what made every
  Cloudflare edge — `cdn.moq.dev` among them — unreachable.
- We never send a `CertificateRequest` of our own.

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
