//! NFSv4 COMPOUND client.
//!
//! The wire types live in `nfs_proto::nfs4`; this module holds the client that
//! drives them.
//!
//! Even when a server primarily serves NFSv3, the v4 endpoint is often active
//! on the same port (2049) and answers questions v3 cannot:
//!
//! - SECINFO reports the authentication flavors a directory actually accepts,
//!   per-directory rather than per-export.
//! - The pseudo-filesystem exposes export boundaries via fsid changes.
//! - READDIR still works when the v3 endpoint is filtered.
//!
//! Only the read-only subset is implemented. The stateful half of the protocol
//! -- OPEN, CLOSE, LOCK, delegations, and the v4.1 session machinery -- is out
//! of scope; see `nfs_proto::nfs4` for the operations that are covered.

/// NFSv4 wire types live in the protocol crate; re-exported under the name
/// call sites already use.
pub(crate) use nfs_proto::nfs4 as types;

pub(crate) mod compound;
