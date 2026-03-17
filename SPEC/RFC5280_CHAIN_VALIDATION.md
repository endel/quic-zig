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
- `event_loop.ClientConfig` now auto-loads the system root store when `skip_cert_verify=false` and no `ca_cert_path` is provided

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
### Caveats

- `tls13.TlsConfig.skip_cert_verify` defaults to `true` for backward compatibility, while `event_loop.ClientConfig.skip_cert_verify` defaults to `false`
- Trust-anchor verification still requires `tls13.TlsConfig.ca_bundle` to be non-null when callers construct `tls13.TlsConfig` directly; `event_loop.ClientConfig` now auto-populates the system root store for the verified-client default path
- V1 certificates (no extensions) are accepted as CAs when no basicConstraints is present — this matches common practice but is less strict than RFC 5280's recommendation
- The interop client always uses `skip_cert_verify=true` since interop test peers use various self-signed certs
