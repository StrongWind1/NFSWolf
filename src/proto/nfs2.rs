//! NFSv2 for nfswolf: the library client, bound to the pooled transport.
//!
//! Mirror of `proto::nfs3` for NFSv2. `nfswolf-nfs2` owns the protocol;
//! `PooledTransport` owns the policy. This module is the seam between them.

/// An NFSv2 client issuing calls through nfswolf's pooled transport.
pub(crate) type Nfs2Client = nfswolf_nfs2::Nfs2Client<crate::proto::transport::PooledTransport>;

/// Hostname presented when no AUTH_SYS credential is configured.
///
/// Advisory on Linux knfsd, which logs it without using it for access control.
pub(crate) const DEFAULT_MACHINENAME: &str = "nfswolf";

/// Accessors the binary needs on a pooled NFSv2 client.
///
/// `Nfs2Client` lives in the protocol crate and knows nothing about pools, so
/// these forward to the transport underneath. An extension trait rather than
/// wrapper methods keeps the call sites reading the same as before the split.
pub(crate) trait PooledNfs2 {
    /// Server this client talks to.
    #[expect(dead_code, reason = "API parity with PooledNfs3; needed when v2 circuit breaker consumers land")]
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
    /// from a connection set carrying that identity.
    fn with_credential(&self, credential: crate::proto::auth::Credential, uid: u32, gid: u32) -> Self;
}

impl PooledNfs2 for Nfs2Client {
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
