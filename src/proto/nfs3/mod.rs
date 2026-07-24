//! NFSv3 client  --  pooled wrapper over `nfswolf_nfs3::Nfs3Client`
//! (all 22 procedures per RFC 1813).
//!
//! `nfswolf-nfs3` provides the wire protocol and the domain types. This module
//! adds the policy the library deliberately has none of:
//! - AUTH_SYS stamp injection (via `proto::auth`)
//! - Connection checkout from the pool (via `proto::pool`)
//! - Circuit breaker integration (via `proto::circuit`)
//! - Per-call deadlines

/// Domain types live in the protocol crate; re-exported under the name call
/// sites already use.
pub(crate) use nfswolf_nfs3::api as types;

/// Protocol status codes live in the protocol crate.
pub(crate) mod errors {
    pub(crate) use nfswolf_nfs3::Nfs3Error;
}

pub(crate) mod client;
