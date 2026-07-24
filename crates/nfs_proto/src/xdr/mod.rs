//! XDR (External Data Representation) codec -- [RFC 4506].
//!
//! Every ONC RPC protocol NFSWolf speaks encodes its arguments and results
//! with XDR.  The rules that matter for reading the rest of this crate:
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
//! Most types get them from `#[derive(XdrCodec)]`; types whose encoding does
//! not follow the mechanical field-by-field rule implement them by hand.
//!
//! [RFC 4506]: https://www.rfc-editor.org/rfc/rfc4506

pub(crate) mod error;
pub(crate) mod list;
pub(crate) mod opaque;
pub(crate) mod primitives;
pub(crate) mod traits;
pub mod util;
pub(crate) mod void;

pub use nfs_xdr::XdrCodec;

pub use self::util::{PREALLOC_CAP, pack_string, read_bytes, skip_pad, string_packed_size, unpack_string, vec_with_capacity, write_pad};

pub use self::error::Error;
pub use self::list::{BoundedList, List};
pub use self::opaque::Opaque;
pub use self::traits::{Pack, Unpack};
pub use self::void::Void;

/// Result of an XDR encode or decode operation.
pub type Result<T> = std::result::Result<T, Error>;
