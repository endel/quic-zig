# RFC 5280 - X.509 Certificate Chain Validation

## Implementation Status: Partial

### What's Implemented

#### Chain Validation (via `std.crypto.Certificate`)
- **Signature verification**: Each certificate's signature is verified against its issuer's public key
- **Issuer/subject name matching**: Verified automatically by `Parsed.verify()`
- **Time validity**: Not-before/not-after checked against current time
- **Hostname verification**: Leaf cert checked against SNI via `verifyHostName()` (supports wildcards, SAN)
- **Trust anchor verification**: Last cert in chain verified against `Certificate.Bundle` (CA trust store)

#### Extension Validation (custom implementation in `tls13.zig`)
- **Basic Constraints (§4.2.1.9)**: Issuer certs must have `CA:TRUE` when basicConstraints is present
- **Path Length Constraint**: `pathLenConstraint` enforced on intermediate CA certs
- **Key Usage (§4.2.1.3)**: If keyUsage extension is present on an issuer cert, `keyCertSign` bit must be set

#### System Root CAs
- `loadSystemCaBundle()` helper wraps `Certificate.Bundle.rescan()` for OS-native roots
- Supports macOS (Keychain), Linux (`/etc/ssl/certs/`), Windows (CertStore), FreeBSD, OpenBSD, etc.

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

### Caveats

- `skip_cert_verify` defaults to `false`; callers must opt out explicitly for test-only/self-signed scenarios
- V1 certificates (no extensions) are accepted as CAs when no basicConstraints is present — this matches common practice but is less strict than RFC 5280's recommendation
- The interop client always uses `skip_cert_verify=true` since interop test peers use various self-signed certs
