//! Capacity profile for the fixed-size buffers inside `Connection` and the
//! QPACK dynamic tables.
//!
//! Collected here because these numbers are not local decisions: `Connection`
//! is built by value in several places, so its size is paid on the stack of
//! whatever constructs one, and `ConnEntry` embeds an `H3Connection`, so the
//! QPACK numbers multiply by the connection count.

/// Datagrams each direction can queue without allocating.
/// `DatagramQueue.resize` allocates beyond this when an app asks for more.
pub const datagram_static_items: usize = 32;

/// Packets buffered while their keys are missing (RFC 9001 4.1.4 permits
/// dropping when full).
pub const undecryptable_buf_len: usize = 32 * 1024;
pub const undecryptable_max_pkts: usize = 32;

/// Control frames queued for the next packet.
pub const pending_frames: usize = 128;

/// Distinct out-of-order runs a single `FrameSorter` will hold before the
/// connection is torn down. RFC 9000 21.7 asks that reassembly tracking be
/// bounded: a peer that withholds every other byte otherwise pins one chunk
/// per hole, paying both the memory and the per-push search cost. Peers cap
/// comparably — quic-go 1000, quinn 1024, ngtcp2 4000.
pub const max_reassembly_chunks: usize = 1000;

/// How far past the consumed offset a CRYPTO stream will buffer, per
/// encryption level. CRYPTO frames are not flow controlled (RFC 9000 7.5), so
/// this is the only ceiling on pre-handshake reassembly memory; past it the
/// peer gets CRYPTO_BUFFER_EXCEEDED. Matches `tls_handshake_in`, which is all
/// of one peer flight we can stage anyway.
pub const max_crypto_stream_offset: u64 = tls_handshake_in;

/// Largest QPACK dynamic table capacity we will honour, in bytes, and the
/// size of the per-table arena backing it. RFC 9204 3.2.1 bounds the table's
/// total content by the negotiated capacity, so this is the whole storage
/// cost. A peer advertising more is clamped, not trusted.
pub const qpack_table_capacity: usize = 4096;

/// TLS 1.3 handshake staging, heap-allocated per connection alongside
/// `Connection` (`tls13_hs`) and the largest single allocation unit left.
/// The out buffer holds one outgoing flight, dominated by the Certificate
/// message, so it scales with the local cert chain — 32 KB covers the
/// 9-cert amplificationlimit interop case. The in buffer reassembles one
/// peer flight.
pub const tls_handshake_out: usize = 32 * 1024;
pub const tls_handshake_in: usize = 16 * 1024;
