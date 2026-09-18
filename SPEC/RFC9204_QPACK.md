# RFC 9204 — QPACK: Field Compression for HTTP/3

## Status: ✅ Complete (static-only encoder)

The decoder supports the full dynamic table. The encoder is deliberately
static-only: it emits static-table references and literals, never inserts,
and every header block it writes has Required Insert Count 0. RFC 9204
allows this (an encoder need not use the dynamic table), and every peer
can decode it.

See the section-level status matrix in [STATUS.md](STATUS.md#rfc-9204--qpack-field-compression-for-http3).

## Implementation

| Area | File |
|------|------|
| Static table + field-line codec | `src/h3/qpack.zig` |
| Dynamic table (FIFO ring) | `src/h3/qpack.zig` (`DynamicTable`) |
| Static-only encoder | `src/h3/qpack.zig` (`QpackEncoder`, `encodeHeaders`) |
| Decoder state machine | `src/h3/qpack.zig` (`QpackDecoder`) |
| Huffman (RFC 7541 Appendix B) | `src/h3/huffman.zig` |
| Encoder/decoder stream wiring | `src/h3/connection.zig` |

## Test coverage

- `qpack.zig`: static table round-trips, dynamic table
  insertion/eviction/relative-indexing/post-base, RIC encode/decode,
  Set-Capacity handling, hand-built encoder instructions and dynamic
  header blocks, malformed and overflowing lengths/indexes, and the
  static-only encoder against a peer decoder that holds a table.
- `huffman.zig`: 11 tests — encode/decode round-trips, padding rules,
  invalid-encoding rejection, EOS-symbol rejection.
- Plus the H3 integration tests in `connection.zig` exercise the
  encoder/decoder streams end-to-end.

## §2 Compression Overview — ✅ Done

Static table references + optional dynamic table. Each encoded header
block has a two-part prefix (Required Insert Count + Delta Base) followed
by zero or more field-line representations.

## §3 Reference Tables

### §3.1 Static Table — ✅ Done

All 99 entries from Appendix A are present in `static_table`
(qpack.zig:18). `findStaticMatch(name, value)` returns the best index
(full match preferred, else name-only match).

### §3.2 Dynamic Table — ✅ Done

Decoder side only. Names and values live in one arena sized to the
capacity we advertise, indexed by a ring of descriptors — no heap
allocation per entry, and no per-entry limit beyond the capacity.
Insertion errors propagate as QPACK encoder stream errors.

### §3.2.1 Dynamic Table Size — ✅ Done

`computeEntrySize(name, value)` returns `name.len + value.len + 32` per
the spec formula. Eviction happens on insert when `size + entry > cap`.

### §3.2.2 Dynamic Table Capacity — ✅ Done

- The decoder's local max is set via `setCapacity(cap)` (the advertised
  value, default 4096).
- The peer's `SETTINGS_QPACK_MAX_TABLE_CAPACITY` is ignored: the encoder
  never sends `Set Dynamic Table Capacity`, so our table in the peer's
  decoder stays at capacity 0.
- Decoder enforces `cap ≤ local_max`; values exceeding the advertised
  maximum produce `error.CapacityExceeded` → `QPACK_ENCODER_STREAM_ERROR`.

### §3.2.3 Absolute, Relative, Post-Base Indices — ✅ Done

- `get(abs_idx)` — absolute lookup; returns `null` once evicted.
- `getRelative(base, rel_idx)` — `abs = base - rel_idx - 1`.
- `getPostBase(base, post_idx)` — `abs = base + post_idx`.

## §4 Wire Format

### §4.1 Encoder Instructions — ✅ Done (decode only)

All four are parsed by `QpackDecoder.processEncoderInstruction()`; the
static-only encoder emits none of them.

| Instruction | Pattern |
|-------------|---------|
| Set Dynamic Table Capacity | `001xxxxx` |
| Insert with Name Reference | `1Txxxxxx` |
| Insert with Literal Name | `01Hxxxxx` |
| Duplicate | `000xxxxx` |

Insert with Name Reference (T=0) and Duplicate carry relative indexes:
`insert_count - 1 - index`, so 0 is the newest entry.

Instructions are read as a stream, not per read: one cut off at the end of
a QUIC read is held in `QpackDecoder.pending` and applied once the rest
arrives (`QpackEncoder.pending` does the same for decoder instructions).
The held tail is bounded by the table capacity plus two integers; a string
declared longer than the table fails with `EntryTooLarge` as soon as its
length is read. A Huffman string whose encoding is longer than the table
is rejected even if it would decode to fit.

### §4.2 Decoder Instructions — ✅ Done

| Instruction | Pattern | Implementation |
|-------------|---------|----------------|
| Header Acknowledgment | `1xxxxxxx` | Emitted by `emitHeaderAck(stream_id)` after a decode with dynamic refs; received, it is `QPACK_DECODER_STREAM_ERROR` (§4.4.1 — we never send a block that needs one) |
| Stream Cancellation | `01xxxxxx` | Parsed; no per-stream state to reclaim |
| Insert Count Increment | `00xxxxxx` | Received, any value is `QPACK_DECODER_STREAM_ERROR` (§4.4.3 — we never insert) |

### §4.3 Encoder Stream — ✅ Done

Opened by `H3Connection.initConnection()` with type 0x02 and never
written past the type byte.

### §4.4 Decoder Stream — ✅ Done

Opened with type 0x03. The decoder emits Header Ack on any decode that
resolved a dynamic reference; `flushDecoderInstructions()` is called from
the request poll loop.

### §4.5 Field Line Representations — ✅ Done

| Rep | Pattern | Encoder | Decoder |
|-----|---------|---------|---------|
| Indexed Field Line (static) | `11NNNNNN` | ✅ | ✅ |
| Indexed Field Line (dynamic) | `10NNNNNN` | — | ✅ |
| Indexed with Post-Base | `0001NNNN` | — | ✅ |
| Literal with Name Reference | `01NTNNNN` | ✅ T=1 only | ✅ both |
| Literal with Post-Base Name Reference | `0000NNNN` | — | ✅ |
| Literal with Literal Name | `001NHNNN` | ✅ (H=0) | ✅ (H=0 or H=1) |

Decoder also handles Huffman-encoded names/values on the literal-name
path via `huffman.decode()`.

### §4.5.1 Required Insert Count — ✅ Done

`encodeRequiredInsertCount(ric, max_entries)` and
`decodeRequiredInsertCount(encoded, max_entries, total_insert_count)`
implement the wrapping algorithm. Invalid encodings (RIC > 2·MaxEntries,
result ≤ 0, max_entries == 0 with non-zero encoded) return
`error.InvalidRIC`.

### §4.5.5 Decompression Failure — ✅ Done

Any error from `QpackDecoder.decode()` (bad index, truncated string,
corrupt Huffman, buffer too small, too many headers, …) yields
`H3_QPACK_DECOMPRESSION_FAILED` via `closeWithError()` in the H3 bidi
poll loop (connection.zig:976).

## §5 Configuration — ✅ Done

- `SETTINGS_QPACK_MAX_TABLE_CAPACITY = 4096` advertised in local SETTINGS.
- `SETTINGS_QPACK_BLOCKED_STREAMS = 0` advertised — see caveats.
- The peer's advertised capacity and blocked-streams limit are not used:
  the encoder is static-only.

## §6 Error Codes — ✅ Done

| Code | Value | Trigger |
|------|------:|---------|
| `QPACK_DECOMPRESSION_FAILED` | 0x0200 | Any decode error on a request HEADERS block |
| `QPACK_ENCODER_STREAM_ERROR` | 0x0201 | Peer's encoder violates stream rules (e.g. capacity overrun) |
| `QPACK_DECODER_STREAM_ERROR` | 0x0202 | Peer sends Insert Count Increment of 0 |

## Caveats / Known limitations

- **Huffman encoding** is not emitted by the encoder (`encodeString` sets
  H=0). The decoder fully supports both Huffman- and plain-encoded
  strings, so this is a size/bandwidth trade-off rather than a
  correctness issue. Adding Huffman encoding would be a pure encoder
  change via `huffman.encodedLength`/`huffman.encode` already present.
- **Huffman table history (Apr 2026)**: the RFC 7541 Appendix B table in
  `huffman.zig` was originally incorrect for symbols 22–31, 127, and the
  entire 128–256 range (including EOS). Zig↔Zig interop worked because
  the table was self-consistent; cross-impl interop silently corrupted
  any Huffman-encoded header value containing bytes ≥128 or a handful
  of control chars. Discovered during RFC 9114 adversarial testing,
  fixed by transcribing Appendix B directly. A per-byte round-trip test
  (`encode+decode every byte 0..255 round-trips`) and a quic-go cross-impl
  regression check both pass.
- **Static-only encoder.** A dynamic-table encoder has to fix Base
  before any insert in the block, keep entries an unacknowledged block
  references from being evicted, and stay within the peer's
  `SETTINGS_QPACK_BLOCKED_STREAMS` and Insert Count acknowledgements. The
  one we had did none of that, so peers that keep a table (Firefox,
  quic-go, ngtcp2) decoded the wrong headers. Until a correct one is
  written, header blocks cost more bytes but are always decodable.
- **`qpack_blocked_streams = 0`** — we do not support out-of-order
  header blocks that reference dynamic entries not yet received on the
  encoder stream. If a peer emits a block with
  `Required Insert Count` ahead of our current insert count, decoding
  fails rather than waiting.
- **No Stream Cancellation bookkeeping** — the static-only encoder has
  no per-stream state, so incoming Stream Cancellation instructions are
  consumed and ignored.
- **`huffman_scratch`** is a 16 KiB file-scope buffer shared across
  decode calls. Decoded slices are valid only until the next
  `decodeHeaders` / `QpackDecoder.decode` call on the same thread —
  callers must consume or copy immediately.
