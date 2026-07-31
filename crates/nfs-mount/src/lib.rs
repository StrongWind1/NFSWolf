//! MOUNT protocol -- versions 1 and 3 (RFC 1094 Appendix A / RFC 1813 Appendix I).
//!
//! The MOUNT sideband service turns a directory path into the root file handle
//! that every NFS operation starts from. It also negotiates authentication
//! flavors (v3 only) and exposes the export list.
//!
//! This crate owns the wire types, the client, and the error type for both
//! protocol versions. It depends only on `nfswolf-xdr` and `nfswolf-rpc`;
//! the NFS version crates (`nfswolf-nfs2`, `nfswolf-nfs3`) depend on it,
//! not the reverse.

mod client;
mod error;
pub mod wire;

pub use client::{MountClient, MountVersion, MountedHandle};
pub use error::MountError;
