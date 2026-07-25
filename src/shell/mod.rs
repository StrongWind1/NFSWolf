//! Interactive NFS shell -- readline-based REPL for browsing NFS exports.
//!
//! The shell is generic over `ShellOps`, so NFSv2 and NFSv3 share the same
//! command dispatch, tab completion, and help text. Version-specific behavior
//! lives in `v2::V2Ops` and `v3::V3Ops`.

pub(crate) mod ops;
pub(crate) mod v2;
pub(crate) mod v3;

// Re-export the old shell for now -- will be replaced by the generic shell
// once the refactor is complete.
#[path = "../shell_old.rs"]
mod shell_old;
pub(crate) use shell_old::*;
