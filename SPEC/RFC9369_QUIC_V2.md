# RFC 9369 — QUIC Version 2

## Overview

QUIC v2 (RFC 9369) defines a second version of QUIC that is intentionally wire-incompatible with v1 in specific ways to exercise version negotiation and prevent ossification. The key differences from v1 are:

- **Version number**: `0x6b3343cf` instead of `0x00000001`
- **Initial salt**: Different 20-byte salt for initial key derivation
- **Long header packet type bits**: Remapped (v2: 0b00=Retry, 0b01=Initial, 0b10=0-RTT, 0b11=Handshake vs v1: 0b00=Initial, 0b01=0-RTT, 0b10=Handshake, 0b11=Retry)
- **HKDF labels**: `"quicv2 key"`, `"quicv2 iv"`, `"quicv2 hp"`, `"quicv2 ku"` instead of `"quic key"`, etc.
- **Retry integrity**: Different AES-128-GCM key and nonce

## Implementation

### Version Constants (`src/quic/protocol.zig`)
- `QUIC_V2 = 0x6b3343cf`
- `isV2()` — checks if version is v2
- `isSupportedVersion()` — returns true for v1 or v2
- `quicLabel()` — returns v1 or v2 HKDF label based on version
- `initialSalt()` — returns version-specific 20-byte salt

### Crypto (`src/quic/crypto.zig`)
- All key derivation functions accept a `version` parameter
- `hkdfExpandLabelRuntime()` used for version-dependent labels (runtime strings)
- `deriveInitialKeyMaterial()` uses version-specific salt
- `KeyUpdateManager` derives next-generation secrets with version-aware "ku" label
- `deriveRetryIntegrityKey()` returns v2-specific key/nonce when version is v2

### Packet Encoding/Decoding (`src/quic/packet.zig`, `src/quic/packet_packer.zig`)
- `longHeaderPacketType()` — decodes 2-bit type field with version-aware mapping
- `encodeLongHeaderTypeBits()` — encodes packet type to 2-bit field for given version
- `PacketPacker` uses `encodeLongHeaderTypeBits()` for correct wire encoding

### Transport Parameters (`src/quic/transport_params.zig`)
- `version_information` transport parameter (ID `0x11`)
- Fields: `version_info_chosen` (chosen version), `version_info_available` (list of supported versions)
- `hasAvailableVersion()` helper to check if a version is in the available list

## Compatible Version Negotiation (RFC 9368)

Version negotiation is triggered via the `version_information` transport parameter:

1. **Client** sends v1 Initial with `version_information` containing `chosen_version=v1` and `available_versions=[v2, v1]`
2. **Server** parses client's transport params, sees v2 in available versions, selects v2
3. **Server** updates TLS config to v2, sends v2 Initial + Handshake
4. **Client** detects server response has different version, calls `switchVersion()`

### Asymmetric Key Switching

During version switch, keys must be handled carefully:

- **Server**: Keeps v1 Initial open keys (client may retransmit v1 Initials), switches seal to v2
- **Client**: Keeps v1 Initial seal keys (unused but safe), switches open to v2
- **TLS config** version is updated so Handshake and Application key derivation uses v2 HKDF labels

### Connection.switchVersion()

```
switchVersion(new_version):
  1. Update self.version
  2. Re-derive Initial keys with new salt (asymmetric: keep old decrypt, new encrypt)
  3. Update PacketPacker.version (for correct type bit encoding)
  4. Update TLS config.quic_version (for correct HKDF labels in handshake/app keys)
```

## Testing

Self-interop test: `TESTCASE=v2` with interop server + client confirms:
- Client sends v1 Initial with version_information
- Server detects v2 support, switches to v2
- Client detects v2 from server's Initial, switches version
- Handshake completes with v2 keys
- File transfer succeeds over v2 connection

## Caveats

- No greasing with reserved versions (not sending random versions in version_information)
- version_information only advertises v1 and v2 (no extensibility for future versions yet)
- Downgrade prevention (RFC 9368 §3) not explicitly validated (both sides prefer v2 when available)
