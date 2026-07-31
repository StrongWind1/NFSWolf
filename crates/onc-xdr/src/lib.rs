//! XDR (External Data Representation) codec -- [RFC 4506].
//!
//! Every ONC RPC protocol encodes its arguments and results with XDR. The
//! rules that matter for reading the protocol crates built on this one:
//!
//! * Integers are big-endian and always occupy a multiple of 4 bytes.  A
//!   `u8`, a `bool`, and a `u32` all take 4 bytes on the wire.
//! * Variable-length data (opaque byte strings, arrays) is length-prefixed by
//!   a 4-byte count and then zero-padded up to the next 4-byte boundary.
//! * Fixed-length opaque data carries no length prefix -- NFSv2's 32-byte file
//!   handle is 32 raw bytes, whereas NFSv3's is a prefixed byte string.
//! * Discriminated unions lead with a 4-byte discriminant.
//!
//! [`Pack`] and [`Unpack`] are the two traits every wire type implements.
//! Most types get them from `#[derive(XdrCodec)]`, re-exported here; types
//! whose encoding does not follow the mechanical field-by-field rule implement
//! them by hand.
//!
//! # Decoding untrusted input
//!
//! Every length and count on the wire is chosen by the peer. [`util`] provides
//! the hardened readers the protocol crates use instead of sizing an
//! allocation from a declared length directly -- see [`PREALLOC_CAP`].
//!
//! [RFC 4506]: https://www.rfc-editor.org/rfc/rfc4506

// The XdrCodec derive macro expands to `::onc_xdr::` paths so that it works
// for downstream crates.  This alias lets those same paths resolve when the
// macro is used inside this crate.
#[expect(unused_extern_crates, reason = "required for derive macro path resolution")]
extern crate self as onc_xdr;

mod error;
mod list;
mod opaque;
mod primitives;
mod traits;
pub mod util;
mod void;

pub use onc_xdr_derive::XdrCodec;

pub use self::error::Error;
pub use self::list::{BoundedList, List};
pub use self::opaque::Opaque;
pub use self::traits::{Pack, Unpack};
pub use self::util::{PREALLOC_CAP, pack_string, read_bytes, skip_pad, string_packed_size, unpack_string, vec_with_capacity, write_pad};
pub use self::void::Void;

/// Result of an XDR encode or decode operation.
pub type Result<T> = std::result::Result<T, Error>;
