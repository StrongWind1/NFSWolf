//! NFSv3 and MOUNT v3 wire types -- verbatim transcriptions of [RFC 1813].
//!
//! Identifiers keep the RFC's own spelling (`fattr3`, `nfsstat3`,
//! `NFS3ERR_STALE`) so a definition here can be checked against the spec
//! without a translation step. The `api` module wraps these in types that read
//! naturally from Rust.
//!
//! [RFC 1813]: https://www.rfc-editor.org/rfc/rfc1813

/// Re-export mount wire types from `nfswolf-mount` for backward compatibility.
///
/// Callers that used `nfs_v3::wire::mount::*` can keep that path; new
/// code should use `nfs_mount::wire::*` directly.
pub mod mount {
    pub use nfs_mount::wire::{FHSIZE3, FhStatus, MNTNAMLEN, MNTPATHLEN, MOUNT_V3, MOUNT_V3_PROC as MOUNT_PROGRAM, PROGRAM, dirpath, export_node, exports, fhandle3, mountbody, mountlist, mountres3, mountres3_ok, mountstat3, name};

    /// Backward-compatible alias for the MOUNT v3 version constant.
    pub const VERSION: u32 = MOUNT_V3;
}

mod types;

pub use types::*;
