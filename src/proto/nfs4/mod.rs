//! NFSv4 for nfswolf: both direct (probe) and pooled (shell) clients.
//!
//! The wire types live in `nfs_v4`; this module provides:
//!
//! - `Nfs4DirectClient` (in `compound.rs`): pool-free, single-connection client
//!   for scanner/analyzer probes. Manages its own TCP socket, proxy tunnelling,
//!   and stealth pacing.
//!
//! - `Nfs4Client` (type alias below): the library client bound to
//!   `PooledTransport`, giving the v4 shell circuit breaking, connection reuse,
//!   stealth pacing, and zero-round-trip credential swaps -- the same policy the
//!   v2 and v3 shells use.
//!
//! NFSv4.0 has no session state (v4.1 adds sessions via RFC 8881), so each
//! COMPOUND is independent and pooling is safe. The stateful half of the
//! protocol (OPEN, CLOSE, LOCK, delegations) is out of scope.
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
//! of scope; see `nfs_v4` for the operations that are covered.

/// NFSv4 wire types live in the protocol crate; re-exported under the name
/// call sites already use.
pub(crate) use nfs_v4::wire as types;

pub(crate) mod compound;

// ---------------------------------------------------------------------------
// Pooled NFSv4 client  --  mirrors proto::nfs2 and proto::nfs3
// ---------------------------------------------------------------------------

/// An NFSv4 client issuing calls through nfswolf's pooled transport.
///
/// Unlike `Nfs4DirectClient` (single raw TCP socket, used by the scanner and
/// analyzer), this type gets circuit breaking, connection reuse, stealth
/// pacing, and zero-round-trip credential swaps -- the same policy surface as
/// `proto::nfs3::Nfs3Client`.
pub(crate) type Nfs4Client = nfs_v4::Nfs4Client<crate::proto::transport::PooledTransport>;

/// Hostname presented when no AUTH_SYS credential is configured.
///
/// Advisory on Linux knfsd, which logs it without using it for access control.
pub(crate) const DEFAULT_MACHINENAME: &str = "nfswolf";

/// Accessors the binary needs on a pooled NFSv4 client.
///
/// `Nfs4Client` lives in the protocol crate and knows nothing about pools, so
/// these forward to the transport underneath. An extension trait rather than
/// wrapper methods keeps the call sites reading the same as the v2/v3 paths.
pub(crate) trait PooledNfs4 {
    /// Server this client talks to.
    #[expect(dead_code, reason = "API parity with PooledNfs3; needed when v4 circuit breaker consumers land")]
    fn host(&self) -> std::net::SocketAddr;
    /// Identity calls are issued under.
    fn uid(&self) -> u32;
    /// Primary group calls are issued under.
    fn gid(&self) -> u32;
    /// Hostname presented in the AUTH_SYS credential.
    fn machinename(&self) -> &str;
    /// Same connection settings, different identity.
    ///
    /// `uid` and `gid` also select the pool key, so the returned client draws
    /// from a connection set carrying that identity. Zero round trips: the new
    /// transport just targets a different pool key, so credential changes in the
    /// v4 shell no longer require a TCP reconnect.
    fn with_credential(&self, credential: crate::proto::auth::Credential, uid: u32, gid: u32) -> Self;
}

impl PooledNfs4 for Nfs4Client {
    fn host(&self) -> std::net::SocketAddr {
        self.transport().addr()
    }

    fn uid(&self) -> u32 {
        self.transport().uid()
    }

    fn gid(&self) -> u32 {
        self.transport().gid()
    }

    fn machinename(&self) -> &str {
        match self.transport().credential() {
            crate::proto::auth::Credential::Sys(a) => &a.machinename,
            // Same rationale as PooledNfs3: avoid a blank machinename on the wire.
            crate::proto::auth::Credential::None => DEFAULT_MACHINENAME,
        }
    }

    fn with_credential(&self, credential: crate::proto::auth::Credential, uid: u32, gid: u32) -> Self {
        Self::new(self.transport().with_credential(credential, uid, gid))
    }
}
