//! NFSv3 client  --  thin wrapper over nfs3_client (all 22 procedures per RFC 1813).
//!
//! nfs3_client provides the wire protocol. This module adds:
//! - AUTH_SYS stamp injection (via proto::auth)
//! - Connection checkout from pool (via proto::pool)
//! - Circuit breaker integration (via proto::circuit)
//! - Auto-UID resolution (via proto::auto_uid)
//! - Error mapping: nfs3_types::nfs3::nfsstat3 -> our domain errors

pub mod client;
pub mod errors;
pub mod types;
