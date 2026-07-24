//! NFS version 3 -- [RFC 1813].
//!
//! The 22 procedures of NFSv3 (program 100003, version 3), plus the client
//! that issues them.  Compared with NFSv2 this version adds 64-bit file sizes
//! and offsets, variable-length file handles, and the `ACCESS` procedure.
//!
//! Two protocol properties NFSWolf depends on:
//!
//! * **File handles are bearer tokens.**  A handle obtained under one
//!   credential stays valid under any other (RFC 1813 sec. 2.6), so handles
//!   can be reused across UID switches instead of re-resolving paths.
//! * **`ACCESS` is advisory.**  The server answers what it believes the
//!   caller may do, but is not required to be right and may still refuse the
//!   real operation (RFC 1813 sec. 3.3.4).  Always confirm by attempting it.
//!
//! [RFC 1813]: https://www.rfc-editor.org/rfc/rfc1813

mod client;
mod types;

pub use client::Nfs3Client;
pub use types::*;
