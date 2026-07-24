//! NFSv3 for nfswolf: the library client, bound to the pooled transport.
//!
//! `nfswolf-nfs3` owns the protocol; `PooledTransport` owns the policy. This
//! module is only the seam between them, which is why it is a type alias rather
//! than a wrapper: the 22 procedure methods that used to live here each
//! repeated the same six lines of pool checkout, breaker check, and timeout
//! plumbing. That plumbing now exists once, in `proto::transport`.

/// Domain types live in the protocol crate; re-exported under the name call
/// sites already use.
pub(crate) use nfswolf_nfs3::api as types;

/// Protocol status codes live in the protocol crate.
pub(crate) mod errors {
    pub(crate) use nfswolf_nfs3::Nfs3Error;
}

/// An NFSv3 client issuing calls through nfswolf's pooled transport.
pub(crate) type Nfs3Client = nfswolf_nfs3::Nfs3Client<crate::proto::transport::PooledTransport>;

/// Accessors the binary needs on a pooled NFSv3 client.
///
/// `Nfs3Client` lives in the protocol crate and knows nothing about pools, so
/// these forward to the transport underneath. An extension trait rather than
/// wrapper methods keeps the call sites reading the same as before the split.
pub(crate) trait PooledNfs3 {
    /// Server this client talks to.
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

impl PooledNfs3 for Nfs3Client {
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
            crate::proto::auth::Credential::None => "",
        }
    }

    fn with_credential(&self, credential: crate::proto::auth::Credential, uid: u32, gid: u32) -> Self {
        Self::new(self.transport().with_credential(credential, uid, gid))
    }
}
