//! NFSv3 and MOUNT v3 wire types -- verbatim transcriptions of [RFC 1813].
//!
//! Identifiers keep the RFC's own spelling (`fattr3`, `nfsstat3`,
//! `NFS3ERR_STALE`) so a definition here can be checked against the spec
//! without a translation step. The `api` module wraps these in types that read
//! naturally from Rust.
//!
//! [RFC 1813]: https://www.rfc-editor.org/rfc/rfc1813

pub mod mount;
mod types;

pub use types::*;
