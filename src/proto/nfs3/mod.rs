//! NFSv3 client  --  pooled wrapper over `nfs_proto::Nfs3Client`
//! (all 22 procedures per RFC 1813).
//!
//! `nfs_proto` provides the wire protocol. This module adds:
//! - AUTH_SYS stamp injection (via proto::auth)
//! - Connection checkout from pool (via proto::pool)
//! - Circuit breaker integration (via proto::circuit)
//! - Auto-UID resolution (via proto::auto_uid)
//! - Error mapping: nfs_proto::nfs3::nfsstat3 -> our domain errors

pub(crate) mod client;
pub(crate) mod errors;
pub(crate) mod types;
