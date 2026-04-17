//! NFSv3 client  --  wraps ConnectionPool + CircuitBreaker for all 22 procedures.
//!
//! Each method checks the circuit breaker, checks out a pooled connection,
//! applies the stealth delay, executes the NFS call, then records the result
//! in the circuit breaker. Transient errors poison the connection and increment
//! the circuit breaker; permission errors (expected during UID spraying) do not.

// Toolkit API  --  not all items are used in currently-implemented phases.
use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Context as _;
use nfs3_types::nfs3::{
    ACCESS3args, ACCESS3res, COMMIT3args, COMMIT3res, CREATE3args, CREATE3res, FSINFO3args, FSINFO3res, FSSTAT3args, FSSTAT3res, GETATTR3args, GETATTR3res, LINK3args, LINK3res, LOOKUP3args, LOOKUP3res, MKDIR3args, MKDIR3res, MKNOD3args, MKNOD3res, PATHCONF3args, PATHCONF3res, READ3args, READ3res,
    READDIR3args, READDIR3res, READDIRPLUS3args, READDIRPLUS3res, READLINK3args, READLINK3res, REMOVE3args, REMOVE3res, RENAME3args, RENAME3res, RMDIR3args, RMDIR3res, SETATTR3args, SETATTR3res, SYMLINK3args, SYMLINK3res, WRITE3args, WRITE3res,
};

use crate::proto::auth::Credential;
use crate::proto::circuit::CircuitBreaker;
use crate::proto::conn::ReconnectStrategy;
use crate::proto::nfs3::errors::Nfs3Error;
use crate::proto::pool::{ConnectionPool, PoolKey, PooledConnection};
use crate::util::stealth::StealthConfig;

/// NFSv3 client  --  pool-backed, circuit-breaker-protected.
///
/// Delegate to the underlying `NfsConnection` for each of the 22 NFSv3
/// procedures. Handles credential injection, connection reuse, and
/// transient error tracking.
pub struct Nfs3Client {
    pool: Arc<ConnectionPool>,
    pool_key: PoolKey,
    circuit: Arc<CircuitBreaker>,
    stealth: StealthConfig,
    credential: Credential,
    reconnect: ReconnectStrategy,
    /// When set, connections bypass MOUNT and connect directly to this NFS port.
    ///
    /// Used with `--handle` when portmapper/MOUNT is filtered but the NFS port is open.
    direct_nfs_port: Option<u16>,
}

impl std::fmt::Debug for Nfs3Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Nfs3Client").field("pool_key", &self.pool_key).finish_non_exhaustive()
    }
}

impl Nfs3Client {
    /// Create a new client backed by the given pool and circuit breaker.
    #[must_use]
    pub const fn new(pool: Arc<ConnectionPool>, pool_key: PoolKey, circuit: Arc<CircuitBreaker>, stealth: StealthConfig, credential: Credential, reconnect: ReconnectStrategy) -> Self {
        Self { pool, pool_key, circuit, stealth, credential, reconnect, direct_nfs_port: None }
    }

    /// Create a client that connects directly to `nfs_port`, bypassing portmapper and MOUNT.
    ///
    /// Used with `--handle` when the portmapper or MOUNT daemon is not reachable but the
    /// NFS port is directly accessible (e.g., port 111 filtered, port 2049 open).
    #[must_use]
    pub const fn new_direct(pool: Arc<ConnectionPool>, pool_key: PoolKey, circuit: Arc<CircuitBreaker>, stealth: StealthConfig, credential: Credential, reconnect: ReconnectStrategy, nfs_port: u16) -> Self {
        Self { pool, pool_key, circuit, stealth, credential, reconnect, direct_nfs_port: Some(nfs_port) }
    }

    /// Get the server address this client connects to (for circuit breaker).
    #[must_use]
    pub const fn host(&self) -> SocketAddr {
        self.pool_key.host
    }

    /// UID embedded in this client's AUTH_SYS credential.
    #[must_use]
    pub const fn uid(&self) -> u32 {
        self.pool_key.uid
    }

    /// GID embedded in this client's AUTH_SYS credential.
    #[must_use]
    pub const fn gid(&self) -> u32 {
        self.pool_key.gid
    }

    /// Clone this client with a different credential (new pool key for the new uid/gid).
    #[must_use]
    pub fn with_credential(&self, cred: Credential, uid: u32, gid: u32) -> Self {
        let mut key = self.pool_key.clone();
        key.uid = uid;
        key.gid = gid;
        Self { pool: Arc::clone(&self.pool), pool_key: key, circuit: Arc::clone(&self.circuit), stealth: self.stealth.clone(), credential: cred, reconnect: self.reconnect, direct_nfs_port: self.direct_nfs_port }
    }

    /// Issue `NFSPROC3_NULL`  --  no-op, used to check connectivity.
    pub async fn null(&self) -> anyhow::Result<()> {
        let addr = self.pool_key.host;
        self.circuit.check_or_wait(addr)?;
        let mut conn = self.checkout().await?;
        self.stealth.wait().await;
        let res = conn.inner_mut().null().await;
        update_circuit(&self.circuit, &mut conn, &res.as_ref().map(|()| &()), addr);
        res.map_err(|e| anyhow::anyhow!("{e}").context("NFSPROC3_NULL"))
    }

    /// Issue `NFSPROC3_GETATTR`  --  get file attributes.
    pub async fn getattr(&self, args: &GETATTR3args) -> anyhow::Result<GETATTR3res> {
        let addr = self.pool_key.host;
        self.circuit.check_or_wait(addr)?;
        let mut conn = self.checkout().await?;
        self.stealth.wait().await;
        let res = conn.inner_mut().getattr(args).await;
        update_circuit(&self.circuit, &mut conn, &res.as_ref().map(|_| &()), addr);
        res.map_err(|e| anyhow::anyhow!("{e}").context("NFSPROC3_GETATTR"))
    }

    /// Issue `NFSPROC3_SETATTR`  --  set file attributes.
    pub async fn setattr(&self, args: &SETATTR3args) -> anyhow::Result<SETATTR3res> {
        let addr = self.pool_key.host;
        self.circuit.check_or_wait(addr)?;
        let mut conn = self.checkout().await?;
        self.stealth.wait().await;
        let res = conn.inner_mut().setattr(args).await;
        update_circuit(&self.circuit, &mut conn, &res.as_ref().map(|_| &()), addr);
        res.map_err(|e| anyhow::anyhow!("{e}").context("NFSPROC3_SETATTR"))
    }

    /// Issue `NFSPROC3_LOOKUP`  --  look up a name in a directory.
    pub async fn lookup(&self, args: &LOOKUP3args<'_>) -> anyhow::Result<LOOKUP3res> {
        let addr = self.pool_key.host;
        self.circuit.check_or_wait(addr)?;
        let mut conn = self.checkout().await?;
        self.stealth.wait().await;
        let res = conn.inner_mut().lookup(args).await;
        update_circuit(&self.circuit, &mut conn, &res.as_ref().map(|_| &()), addr);
        res.map_err(|e| anyhow::anyhow!("{e}").context("NFSPROC3_LOOKUP"))
    }

    /// Issue `NFSPROC3_ACCESS`  --  advisory permission check.
    ///
    /// Note: ACCESS results are advisory only (RFC 1813 S3.3.4).
    /// Always confirm by attempting the actual operation.
    pub async fn access(&self, args: &ACCESS3args) -> anyhow::Result<ACCESS3res> {
        let addr = self.pool_key.host;
        self.circuit.check_or_wait(addr)?;
        let mut conn = self.checkout().await?;
        self.stealth.wait().await;
        let res = conn.inner_mut().access(args).await;
        update_circuit(&self.circuit, &mut conn, &res.as_ref().map(|_| &()), addr);
        res.map_err(|e| anyhow::anyhow!("{e}").context("NFSPROC3_ACCESS"))
    }

    /// Issue `NFSPROC3_READLINK`  --  read a symbolic link target.
    pub async fn readlink(&self, args: &READLINK3args) -> anyhow::Result<READLINK3res<'static>> {
        let addr = self.pool_key.host;
        self.circuit.check_or_wait(addr)?;
        let mut conn = self.checkout().await?;
        self.stealth.wait().await;
        let res = conn.inner_mut().readlink(args).await;
        update_circuit(&self.circuit, &mut conn, &res.as_ref().map(|_| &()), addr);
        res.map_err(|e| anyhow::anyhow!("{e}").context("NFSPROC3_READLINK"))
    }

    /// Issue `NFSPROC3_READ`  --  read file data.
    pub async fn read(&self, args: &READ3args) -> anyhow::Result<READ3res<'static>> {
        let addr = self.pool_key.host;
        self.circuit.check_or_wait(addr)?;
        let mut conn = self.checkout().await?;
        self.stealth.wait().await;
        let res = conn.inner_mut().read(args).await;
        update_circuit(&self.circuit, &mut conn, &res.as_ref().map(|_| &()), addr);
        res.map_err(|e| anyhow::anyhow!("{e}").context("NFSPROC3_READ"))
    }

    /// Issue `NFSPROC3_WRITE`  --  write file data.
    pub async fn write(&self, args: &WRITE3args<'_>) -> anyhow::Result<WRITE3res> {
        let addr = self.pool_key.host;
        self.circuit.check_or_wait(addr)?;
        let mut conn = self.checkout().await?;
        self.stealth.wait().await;
        let res = conn.inner_mut().write(args).await;
        update_circuit(&self.circuit, &mut conn, &res.as_ref().map(|_| &()), addr);
        res.map_err(|e| anyhow::anyhow!("{e}").context("NFSPROC3_WRITE"))
    }

    /// Issue `NFSPROC3_CREATE`  --  create a file.
    pub async fn create(&self, args: &CREATE3args<'_>) -> anyhow::Result<CREATE3res> {
        let addr = self.pool_key.host;
        self.circuit.check_or_wait(addr)?;
        let mut conn = self.checkout().await?;
        self.stealth.wait().await;
        let res = conn.inner_mut().create(args).await;
        update_circuit(&self.circuit, &mut conn, &res.as_ref().map(|_| &()), addr);
        res.map_err(|e| anyhow::anyhow!("{e}").context("NFSPROC3_CREATE"))
    }

    /// Issue `NFSPROC3_MKDIR`  --  create a directory.
    pub async fn mkdir(&self, args: &MKDIR3args<'_>) -> anyhow::Result<MKDIR3res> {
        let addr = self.pool_key.host;
        self.circuit.check_or_wait(addr)?;
        let mut conn = self.checkout().await?;
        self.stealth.wait().await;
        let res = conn.inner_mut().mkdir(args).await;
        update_circuit(&self.circuit, &mut conn, &res.as_ref().map(|_| &()), addr);
        res.map_err(|e| anyhow::anyhow!("{e}").context("NFSPROC3_MKDIR"))
    }

    /// Issue `NFSPROC3_SYMLINK`  --  create a symbolic link.
    pub async fn symlink(&self, args: &SYMLINK3args<'_>) -> anyhow::Result<SYMLINK3res> {
        let addr = self.pool_key.host;
        self.circuit.check_or_wait(addr)?;
        let mut conn = self.checkout().await?;
        self.stealth.wait().await;
        let res = conn.inner_mut().symlink(args).await;
        update_circuit(&self.circuit, &mut conn, &res.as_ref().map(|_| &()), addr);
        res.map_err(|e| anyhow::anyhow!("{e}").context("NFSPROC3_SYMLINK"))
    }

    /// Issue `NFSPROC3_MKNOD`  --  create a special file.
    pub async fn mknod(&self, args: &MKNOD3args<'_>) -> anyhow::Result<MKNOD3res> {
        let addr = self.pool_key.host;
        self.circuit.check_or_wait(addr)?;
        let mut conn = self.checkout().await?;
        self.stealth.wait().await;
        let res = conn.inner_mut().mknod(args).await;
        update_circuit(&self.circuit, &mut conn, &res.as_ref().map(|_| &()), addr);
        res.map_err(|e| anyhow::anyhow!("{e}").context("NFSPROC3_MKNOD"))
    }

    /// Issue `NFSPROC3_REMOVE`  --  remove a file.
    pub async fn remove(&self, args: &REMOVE3args<'_>) -> anyhow::Result<REMOVE3res> {
        let addr = self.pool_key.host;
        self.circuit.check_or_wait(addr)?;
        let mut conn = self.checkout().await?;
        self.stealth.wait().await;
        let res = conn.inner_mut().remove(args).await;
        update_circuit(&self.circuit, &mut conn, &res.as_ref().map(|_| &()), addr);
        res.map_err(|e| anyhow::anyhow!("{e}").context("NFSPROC3_REMOVE"))
    }

    /// Issue `NFSPROC3_RMDIR`  --  remove a directory.
    pub async fn rmdir(&self, args: &RMDIR3args<'_>) -> anyhow::Result<RMDIR3res> {
        let addr = self.pool_key.host;
        self.circuit.check_or_wait(addr)?;
        let mut conn = self.checkout().await?;
        self.stealth.wait().await;
        let res = conn.inner_mut().rmdir(args).await;
        update_circuit(&self.circuit, &mut conn, &res.as_ref().map(|_| &()), addr);
        res.map_err(|e| anyhow::anyhow!("{e}").context("NFSPROC3_RMDIR"))
    }

    /// Issue `NFSPROC3_RENAME`  --  rename a file.
    pub async fn rename(&self, args: &RENAME3args<'_, '_>) -> anyhow::Result<RENAME3res> {
        let addr = self.pool_key.host;
        self.circuit.check_or_wait(addr)?;
        let mut conn = self.checkout().await?;
        self.stealth.wait().await;
        let res = conn.inner_mut().rename(args).await;
        update_circuit(&self.circuit, &mut conn, &res.as_ref().map(|_| &()), addr);
        res.map_err(|e| anyhow::anyhow!("{e}").context("NFSPROC3_RENAME"))
    }

    /// Issue `NFSPROC3_LINK`  --  create a hard link.
    pub async fn link(&self, args: &LINK3args<'_>) -> anyhow::Result<LINK3res> {
        let addr = self.pool_key.host;
        self.circuit.check_or_wait(addr)?;
        let mut conn = self.checkout().await?;
        self.stealth.wait().await;
        let res = conn.inner_mut().link(args).await;
        update_circuit(&self.circuit, &mut conn, &res.as_ref().map(|_| &()), addr);
        res.map_err(|e| anyhow::anyhow!("{e}").context("NFSPROC3_LINK"))
    }

    /// Issue `NFSPROC3_READDIR`  --  read directory entries.
    pub async fn readdir(&self, args: &READDIR3args) -> anyhow::Result<READDIR3res<'static>> {
        let addr = self.pool_key.host;
        self.circuit.check_or_wait(addr)?;
        let mut conn = self.checkout().await?;
        self.stealth.wait().await;
        let res = conn.inner_mut().readdir(args).await;
        update_circuit(&self.circuit, &mut conn, &res.as_ref().map(|_| &()), addr);
        res.map_err(|e| anyhow::anyhow!("{e}").context("NFSPROC3_READDIR"))
    }

    /// Issue `NFSPROC3_READDIRPLUS`  --  read directory entries with attributes.
    pub async fn readdirplus(&self, args: &READDIRPLUS3args) -> anyhow::Result<READDIRPLUS3res<'static>> {
        let addr = self.pool_key.host;
        self.circuit.check_or_wait(addr)?;
        let mut conn = self.checkout().await?;
        self.stealth.wait().await;
        let res = conn.inner_mut().readdirplus(args).await;
        update_circuit(&self.circuit, &mut conn, &res.as_ref().map(|_| &()), addr);
        res.map_err(|e| anyhow::anyhow!("{e}").context("NFSPROC3_READDIRPLUS"))
    }

    /// Issue `NFSPROC3_FSSTAT`  --  get filesystem statistics.
    pub async fn fsstat(&self, args: &FSSTAT3args) -> anyhow::Result<FSSTAT3res> {
        let addr = self.pool_key.host;
        self.circuit.check_or_wait(addr)?;
        let mut conn = self.checkout().await?;
        self.stealth.wait().await;
        let res = conn.inner_mut().fsstat(args).await;
        update_circuit(&self.circuit, &mut conn, &res.as_ref().map(|_| &()), addr);
        res.map_err(|e| anyhow::anyhow!("{e}").context("NFSPROC3_FSSTAT"))
    }

    /// Issue `NFSPROC3_FSINFO`  --  get filesystem capabilities.
    pub async fn fsinfo(&self, args: &FSINFO3args) -> anyhow::Result<FSINFO3res> {
        let addr = self.pool_key.host;
        self.circuit.check_or_wait(addr)?;
        let mut conn = self.checkout().await?;
        self.stealth.wait().await;
        let res = conn.inner_mut().fsinfo(args).await;
        update_circuit(&self.circuit, &mut conn, &res.as_ref().map(|_| &()), addr);
        res.map_err(|e| anyhow::anyhow!("{e}").context("NFSPROC3_FSINFO"))
    }

    /// Issue `NFSPROC3_PATHCONF`  --  get filesystem path configuration.
    pub async fn pathconf(&self, args: &PATHCONF3args) -> anyhow::Result<PATHCONF3res> {
        let addr = self.pool_key.host;
        self.circuit.check_or_wait(addr)?;
        let mut conn = self.checkout().await?;
        self.stealth.wait().await;
        let res = conn.inner_mut().pathconf(args).await;
        update_circuit(&self.circuit, &mut conn, &res.as_ref().map(|_| &()), addr);
        res.map_err(|e| anyhow::anyhow!("{e}").context("NFSPROC3_PATHCONF"))
    }

    /// Issue `NFSPROC3_COMMIT`  --  force unstable writes to stable storage.
    pub async fn commit(&self, args: &COMMIT3args) -> anyhow::Result<COMMIT3res> {
        let addr = self.pool_key.host;
        self.circuit.check_or_wait(addr)?;
        let mut conn = self.checkout().await?;
        self.stealth.wait().await;
        let res = conn.inner_mut().commit(args).await;
        update_circuit(&self.circuit, &mut conn, &res.as_ref().map(|_| &()), addr);
        res.map_err(|e| anyhow::anyhow!("{e}").context("NFSPROC3_COMMIT"))
    }

    /// Check out a single connection for exclusive use (e.g., UID spraying).
    ///
    /// Unlike the per-method checkout, this returns the `PooledConnection` directly
    /// so callers can issue many RPC calls on the same TCP session with different
    /// credentials without creating a new connection per call.
    pub async fn checkout_one(&self) -> anyhow::Result<PooledConnection> {
        self.checkout().await
    }

    /// Checkout a connection from the pool.
    ///
    /// When `direct_nfs_port` is set, bypasses MOUNT and connects to the NFS port directly.
    async fn checkout(&self) -> anyhow::Result<PooledConnection> {
        if let Some(nfs_port) = self.direct_nfs_port {
            self.pool.checkout_direct(self.pool_key.clone(), nfs_port, self.credential.clone(), self.reconnect).await.context("pool checkout (direct)")
        } else {
            self.pool.checkout(self.pool_key.clone(), self.credential.clone(), self.reconnect).await.context("pool checkout")
        }
    }
}

/// Update the circuit breaker and poison the connection on transient failure.
///
/// Permission errors (expected during UID spraying) do not trip the circuit.
/// IO and protocol errors do, since they indicate the server is degraded.
fn update_circuit<T>(circuit: &CircuitBreaker, conn: &mut PooledConnection, res: &Result<T, &nfs3_client::error::Error>, addr: SocketAddr) {
    match res {
        Ok(_) => circuit.record_success(addr),
        Err(e) => {
            let nfs_err = extract_nfs_error(e);
            let is_perm = nfs_err.is_some_and(Nfs3Error::is_permission_denied);
            let is_transient = nfs_err.is_some_and(Nfs3Error::is_transient) || nfs_err.is_none();
            if is_transient && !is_perm {
                conn.poison();
                circuit.record_failure(addr);
            }
        },
    }
}

/// Extract the `Nfs3Error` if the error is an NFS status code, None otherwise.
const fn extract_nfs_error(e: &nfs3_client::error::Error) -> Option<Nfs3Error> {
    if let nfs3_client::error::Error::NfsError(stat) = e { Nfs3Error::from_nfsstat3(*stat) } else { None }
}
