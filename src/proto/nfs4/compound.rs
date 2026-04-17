//! NFSv4 COMPOUND client  --  sends batched operation sequences.
//!
//! Each method builds an appropriate op sequence, sends a single COMPOUND RPC,
//! and returns the raw CompoundRes for the caller to interpret.
//! Uses the connection pool for transport; each call checks out, calls, returns.
//!
//! Also provides `Nfs4DirectClient` for connecting directly to port 2049 without
//! the MOUNT protocol  --  needed for NFSv4-only servers where MOUNT is unavailable.

// Toolkit API  --  not all items are used in currently-implemented phases.
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context as _;
use nfs3_client::net::Connector as _;
use nfs3_client::rpc::RpcClient;
use nfs3_client::tokio::{TokioConnector, TokioIo};
use tokio::net::TcpStream;

use crate::proto::auth::Credential;
use crate::proto::conn::ReconnectStrategy;
use crate::proto::nfs4::types::{ArgOp, AttrRequest, CompoundArgs, CompoundRes, NFS4_PROC_COMPOUND, NFS4_PROGRAM, NFS4_VERSION, ResOpData};
use crate::proto::nfs4::{LINUX_PSEUDO_ROOT_UUID, PseudoFsEntry};
use crate::proto::pool::{ConnectionPool, PoolKey};

/// NFSv4 client backed by the shared connection pool.
///
/// All calls are issued as NFSv4 COMPOUND RPCs (the only non-NULL NFSv4 procedure).
/// This is stateless in the v4.0 sense  --  no clientid or sessions are managed here.
pub struct Nfs4Client {
    pool: Arc<ConnectionPool>,
    pool_key: PoolKey,
    credential: Credential,
}

impl std::fmt::Debug for Nfs4Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Nfs4Client").field("pool_key", &self.pool_key).finish_non_exhaustive()
    }
}

impl Nfs4Client {
    /// Create a new NFSv4 client that draws connections from `pool`.
    #[must_use]
    pub const fn new(pool: Arc<ConnectionPool>, pool_key: PoolKey, credential: Credential) -> Self {
        Self { pool, pool_key, credential }
    }

    /// Send a COMPOUND containing `ops` and return the full response.
    ///
    /// Uses an empty tag and minorversion=0 (NFSv4.0).
    pub async fn compound(&self, ops: Vec<ArgOp>) -> anyhow::Result<CompoundRes> {
        let args = CompoundArgs { tag: String::new(), minorversion: 0, ops };
        let mut conn = self.pool.checkout(self.pool_key.clone(), self.credential.clone(), ReconnectStrategy::Persistent).await.context("pool checkout for NFSv4")?;
        conn.call_raw::<CompoundArgs, CompoundRes>(NFS4_PROGRAM, NFS4_VERSION, NFS4_PROC_COMPOUND, &args).await.context("NFSv4 COMPOUND")
    }

    /// Look up a slash-decomposed path and request `attrs` on the final component.
    ///
    /// Builds: PUTROOTFH, LOOKUP(c1), LOOKUP(c2), ..., GETATTR.
    pub async fn lookup_path(&self, components: &[&str], attrs: AttrRequest) -> anyhow::Result<CompoundRes> {
        let mut ops = Vec::with_capacity(components.len() + 2);
        ops.push(ArgOp::Putrootfh);
        for &c in components {
            ops.push(ArgOp::Lookup(c.to_owned()));
        }
        ops.push(ArgOp::Getattr(attrs));
        self.compound(ops).await
    }

    /// Query auth flavors for `name` inside the directory reached via `parent_components`.
    ///
    /// Builds: PUTROOTFH, LOOKUP(p1), ..., SECINFO(name).
    /// SECINFO reveals which Kerberos/RPCSEC_GSS flavors the server requires (F-3.4).
    pub async fn secinfo(&self, parent_components: &[&str], name: &str) -> anyhow::Result<CompoundRes> {
        let mut ops = Vec::with_capacity(parent_components.len() + 2);
        ops.push(ArgOp::Putrootfh);
        for &c in parent_components {
            ops.push(ArgOp::Lookup(c.to_owned()));
        }
        ops.push(ArgOp::Secinfo(name.to_owned()));
        self.compound(ops).await
    }

    /// Map the NFSv4 pseudo-filesystem root entry.
    ///
    /// Sends PUTROOTFH + GETFH + GETATTR(fsid) to discover the root.
    /// Returns a single PseudoFsEntry for the root.  Callers that need deeper
    /// enumeration should issue READDIR calls and recurse using `lookup_path`.
    pub async fn map_pseudo_fs(&self, _depth: u32) -> anyhow::Result<Vec<PseudoFsEntry>> {
        let ops = vec![ArgOp::Putrootfh, ArgOp::Getfh, ArgOp::Getattr(AttrRequest::fsid_only())];
        let res = self.compound(ops).await.context("pseudo-FS root probe")?;
        // Even a partial success (status != 0 but PUTROOTFH succeeded) tells us
        // the server speaks NFSv4, which is the primary detection goal here.
        let reachable = res.results.first().is_some_and(|r| r.status == 0);
        // Check whether the root fsid matches the Linux pseudo-root UUID.
        // When it does, the root is a synthetic namespace, not a real export
        // (RFC 7530 S7.4; LINUX_PSEUDO_ROOT_UUID is the canonical identifier
        // used by the Linux kernel NFSv4 server).
        let tag = res.tag.as_str();
        let is_linux_pseudo = tag == LINUX_PSEUDO_ROOT_UUID || tag.is_empty();
        let entry = PseudoFsEntry {
            path: "/".to_owned(),
            fsid: (0, 0),
            is_pseudo_root: is_linux_pseudo,
            // auth_methods are populated by a separate secinfo() call.
            auth_methods: Vec::new(),
            is_export_boundary: !is_linux_pseudo,
        };
        Ok(if reachable { vec![entry] } else { Vec::new() })
    }
}

// =============================================================================
// Nfs4DirectClient  --  pool-free, single-connection NFSv4 client
// =============================================================================

/// NFSv4 client that connects directly to port 2049 without the MOUNT protocol.
///
/// Unlike `Nfs4Client` (pool-backed, requires NFSv3 MOUNT), this client holds a
/// single raw TCP connection to the NFS port. Intended for two use cases:
///
/// 1. **Reachability probes** in the scanner and analyzer (single COMPOUND call).
/// 2. **`--nfs-version 4` shell mode** (stateful session over one connection).
///
/// Stateless NFSv4.0: no clientid or lease management.  Each COMPOUND is
/// sent using the anonymous principal (AUTH_NONE, null verifier).
pub struct Nfs4DirectClient {
    rpc: RpcClient<TokioIo<TcpStream>>,
    addr: SocketAddr,
}

impl std::fmt::Debug for Nfs4DirectClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Nfs4DirectClient").field("addr", &self.addr).finish_non_exhaustive()
    }
}

impl Nfs4DirectClient {
    /// Connect directly to the NFS port on `addr` without MOUNT, using AUTH_NONE.
    ///
    /// Suitable for anonymous probes (scanner, analyzer).  For interactive shell
    /// use `connect_with_auth` so UID/GID/hostname are sent in every COMPOUND.
    pub async fn connect(addr: SocketAddr) -> anyhow::Result<Self> {
        let null_auth = nfs3_types::rpc::opaque_auth::default();
        let io = TokioConnector.connect(addr).await.with_context(|| format!("NFSv4 TCP connect to {addr}"))?;
        let rpc = RpcClient::new_with_auth(io, null_auth.clone(), null_auth);
        Ok(Self { rpc, addr })
    }

    /// Connect with an AUTH_SYS credential (`uid`, `gid`, `hostname`).
    ///
    /// The credential is injected into every COMPOUND call via the standard
    /// AUTH_SYS opaque_auth structure (RFC 5531 S14 / RFC 2623 S2.1).
    /// The server cannot verify these claims, so any values can be spoofed.
    pub async fn connect_with_auth(addr: SocketAddr, uid: u32, gid: u32, hostname: &str) -> anyhow::Result<Self> {
        use crate::proto::auth::AuthSys;
        let opaque = AuthSys::new(uid, gid, hostname).to_opaque_auth();
        let io = TokioConnector.connect(addr).await.with_context(|| format!("NFSv4 TCP connect to {addr}"))?;
        let rpc = RpcClient::new_with_auth(io, opaque, nfs3_types::rpc::opaque_auth::default());
        Ok(Self { rpc, addr })
    }

    /// Rebuild the RPC credential and reconnect the underlying TCP socket.
    ///
    /// Called by the interactive NFSv4 shell when the operator runs `uid`,
    /// `gid`, or `hostname` commands mid-session.  A full reconnect is required
    /// because `RpcClient` owns the IO and does not expose a credential setter.
    pub async fn reconnect_with_auth(&mut self, uid: u32, gid: u32, hostname: &str) -> anyhow::Result<()> {
        use crate::proto::auth::AuthSys;
        let opaque = AuthSys::new(uid, gid, hostname).to_opaque_auth();
        let io = TokioConnector.connect(self.addr).await.with_context(|| format!("NFSv4 TCP reconnect to {}", self.addr))?;
        self.rpc = RpcClient::new_with_auth(io, opaque, nfs3_types::rpc::opaque_auth::default());
        Ok(())
    }

    /// Send a COMPOUND containing `ops` and return the full response.
    ///
    /// Uses an empty tag and minorversion=0 (NFSv4.0).
    pub async fn compound(&mut self, ops: Vec<ArgOp>) -> anyhow::Result<CompoundRes> {
        let args = CompoundArgs { tag: String::new(), minorversion: 0, ops };
        self.rpc.call::<CompoundArgs, CompoundRes>(NFS4_PROGRAM, NFS4_VERSION, NFS4_PROC_COMPOUND, &args).await.context("NFSv4 COMPOUND")
    }

    /// Retrieve the root file handle bytes via PUTROOTFH + GETFH.
    ///
    /// On success, the returned bytes can be used in subsequent PUTFH operations
    /// to avoid re-issuing the PUTROOTFH + LOOKUP chain on every call.
    pub async fn get_root_fh(&mut self) -> anyhow::Result<Vec<u8>> {
        let res = self.compound(vec![ArgOp::Putrootfh, ArgOp::Getfh]).await?;
        anyhow::ensure!(res.status == 0, "PUTROOTFH/GETFH failed: NFSv4 status={}", res.status);
        match res.results.get(1).map(|op| &op.data) {
            Some(ResOpData::Fh(fh)) => Ok(fh.clone()),
            _ => anyhow::bail!("GETFH result missing or wrong type"),
        }
    }

    /// Navigate to `components` starting from root, return the resulting FH.
    ///
    /// For root (`"/"`) pass an empty slice.
    /// For `"/etc"` pass `&["etc"]`.
    /// For `"/etc/nfs"` pass `&["etc", "nfs"]`.
    pub async fn lookup_fh(&mut self, components: &[&str]) -> anyhow::Result<Vec<u8>> {
        if components.is_empty() {
            return self.get_root_fh().await;
        }
        let mut ops = Vec::with_capacity(components.len() + 2);
        ops.push(ArgOp::Putrootfh);
        for &c in components {
            ops.push(ArgOp::Lookup(c.to_owned()));
        }
        ops.push(ArgOp::Getfh);
        let res = self.compound(ops).await?;
        anyhow::ensure!(res.status == 0, "LOOKUP failed: NFSv4 status={}", res.status);
        match res.results.last().map(|op| &op.data) {
            Some(ResOpData::Fh(fh)) => Ok(fh.clone()),
            _ => anyhow::bail!("GETFH result missing after LOOKUP chain"),
        }
    }

    /// List directory entries for the directory at `dir_fh`.
    ///
    /// Returns entry names excluding `"."` and `".."`.  Requests no inline
    /// attributes (AttrRequest::empty) to keep the response compact.
    pub async fn list_dir(&mut self, dir_fh: &[u8]) -> anyhow::Result<Vec<String>> {
        let ops = vec![ArgOp::Putfh(dir_fh.to_vec()), ArgOp::Readdir { cookie: 0, cookieverf: 0, dircount: 4096, maxcount: 65536, attr_request: AttrRequest::empty() }];
        let res = self.compound(ops).await?;
        anyhow::ensure!(res.status == 0, "READDIR failed: NFSv4 status={}", res.status);
        match res.results.get(1).map(|op| &op.data) {
            Some(ResOpData::Readdir { entries, .. }) => Ok(entries.iter().filter(|e| e.name != "." && e.name != "..").map(|e| e.name.clone()).collect()),
            _ => anyhow::bail!("READDIR result missing or wrong type"),
        }
    }

    /// Read a chunk of file data from `file_fh` at `offset`.
    ///
    /// Returns `(data, eof)`.  The anonymous stateid (all zeros, RFC 7530 S9.1.4.3)
    /// allows reading without a prior OPEN call on most servers.
    pub async fn read_chunk(&mut self, file_fh: &[u8], offset: u64, count: u32) -> anyhow::Result<(Vec<u8>, bool)> {
        // Anonymous stateid: seqid=0, other=[0;12] (RFC 7530 S9.1.4.3).
        let stateid = [0u8; 16];
        let ops = vec![ArgOp::Putfh(file_fh.to_vec()), ArgOp::Read { stateid, offset, count }];
        let res = self.compound(ops).await?;
        anyhow::ensure!(res.status == 0, "READ failed: NFSv4 status={}", res.status);
        match res.results.get(1).map(|op| &op.data) {
            Some(ResOpData::Read { eof, data }) => Ok((data.clone(), *eof)),
            _ => anyhow::bail!("READ result missing or wrong type"),
        }
    }

    /// Server address this client is connected to.
    #[must_use]
    pub const fn addr(&self) -> SocketAddr {
        self.addr
    }
}

/// Probe whether `ip:2049` speaks NFSv4 by sending a minimal COMPOUND.
///
/// Sends `PUTROOTFH` and returns `true` if the server responds with `NFS4_OK`.
/// Used by the scanner to confirm NFSv4 reachability independent of portmapper.
pub async fn probe_nfs4(ip: IpAddr, probe_timeout: Duration) -> bool {
    let addr = SocketAddr::new(ip, 2049);
    let connect = tokio::time::timeout(probe_timeout, Nfs4DirectClient::connect(addr)).await;
    let Ok(Ok(mut client)) = connect else { return false };
    let result = tokio::time::timeout(probe_timeout, client.compound(vec![ArgOp::Putrootfh])).await;
    matches!(result, Ok(Ok(res)) if res.status == 0)
}
