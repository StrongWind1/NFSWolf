//! NFSv3 client  --  wraps ConnectionPool + CircuitBreaker for all 22 procedures.
//!
//! Each method checks the circuit breaker, checks out a pooled connection,
//! applies the stealth delay, executes the NFS call, then records the result
//! in the circuit breaker. Transport-fatal errors (IO, fragmented reply)
//! poison the connection and trip the breaker; reusable protocol-level RPC
//! errors and NFS-status errors (which arrive as `Ok`) leave it untouched.

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

// Each procedure holds a `PooledConnection` across the stealth wait and the RPC
// round-trip. That connection now owns the pool's admission semaphore permit, so
// the type is "significant drop"; holding it for the full checkout -> RPC ->
// record-result lifetime is intentional (it bounds concurrent connections), and
// `update_circuit` consumes it to release the permit the instant the result is
// recorded. `significant_drop_tightening` cannot see the move-into-function and
// auto-suggests a use-after-move, so it is allowed for this impl block.
#[allow(clippy::significant_drop_tightening, reason = "PooledConnection's admission permit is held intentionally for the whole RPC; update_circuit consumes conn to drop it promptly")]
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

    /// The AUTH_SYS machinename (spoofed client hostname) in this client's
    /// credential. Escalated clones reuse this so the operator's `--hostname`
    /// / `hostname` spoof (F-1.4) survives the auto-UID ladder instead of
    /// being reset to a default. Falls back to "nfswolf" for `Credential::None`.
    #[must_use]
    pub fn machinename(&self) -> &str {
        match &self.credential {
            Credential::Sys(auth) => &auth.machinename,
            Credential::None => "nfswolf",
        }
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
        update_circuit(&self.circuit, conn, &res.as_ref().map(|()| &()), addr);
        res.map_err(|e| anyhow::anyhow!("{e}").context("NFSPROC3_NULL"))
    }

    /// Issue `NFSPROC3_GETATTR`  --  get file attributes.
    pub async fn getattr(&self, args: &GETATTR3args) -> anyhow::Result<GETATTR3res> {
        let addr = self.pool_key.host;
        self.circuit.check_or_wait(addr)?;
        let mut conn = self.checkout().await?;
        self.stealth.wait().await;
        let res = conn.inner_mut().getattr(args).await;
        update_circuit(&self.circuit, conn, &res.as_ref().map(|_| &()), addr);
        res.map_err(|e| anyhow::anyhow!("{e}").context("NFSPROC3_GETATTR"))
    }

    /// Issue `NFSPROC3_SETATTR`  --  set file attributes.
    pub async fn setattr(&self, args: &SETATTR3args) -> anyhow::Result<SETATTR3res> {
        let addr = self.pool_key.host;
        self.circuit.check_or_wait(addr)?;
        let mut conn = self.checkout().await?;
        self.stealth.wait().await;
        let res = conn.inner_mut().setattr(args).await;
        update_circuit(&self.circuit, conn, &res.as_ref().map(|_| &()), addr);
        res.map_err(|e| anyhow::anyhow!("{e}").context("NFSPROC3_SETATTR"))
    }

    /// Issue `NFSPROC3_LOOKUP`  --  look up a name in a directory.
    pub async fn lookup(&self, args: &LOOKUP3args<'_>) -> anyhow::Result<LOOKUP3res> {
        let addr = self.pool_key.host;
        self.circuit.check_or_wait(addr)?;
        let mut conn = self.checkout().await?;
        self.stealth.wait().await;
        let res = conn.inner_mut().lookup(args).await;
        update_circuit(&self.circuit, conn, &res.as_ref().map(|_| &()), addr);
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
        update_circuit(&self.circuit, conn, &res.as_ref().map(|_| &()), addr);
        res.map_err(|e| anyhow::anyhow!("{e}").context("NFSPROC3_ACCESS"))
    }

    /// Issue `NFSPROC3_READLINK`  --  read a symbolic link target.
    pub async fn readlink(&self, args: &READLINK3args) -> anyhow::Result<READLINK3res<'static>> {
        let addr = self.pool_key.host;
        self.circuit.check_or_wait(addr)?;
        let mut conn = self.checkout().await?;
        self.stealth.wait().await;
        let res = conn.inner_mut().readlink(args).await;
        update_circuit(&self.circuit, conn, &res.as_ref().map(|_| &()), addr);
        res.map_err(|e| anyhow::anyhow!("{e}").context("NFSPROC3_READLINK"))
    }

    /// Issue `NFSPROC3_READ`  --  read file data.
    pub async fn read(&self, args: &READ3args) -> anyhow::Result<READ3res<'static>> {
        let addr = self.pool_key.host;
        self.circuit.check_or_wait(addr)?;
        let mut conn = self.checkout().await?;
        self.stealth.wait().await;
        let res = conn.inner_mut().read(args).await;
        update_circuit(&self.circuit, conn, &res.as_ref().map(|_| &()), addr);
        res.map_err(|e| anyhow::anyhow!("{e}").context("NFSPROC3_READ"))
    }

    /// Issue `NFSPROC3_WRITE`  --  write file data.
    pub async fn write(&self, args: &WRITE3args<'_>) -> anyhow::Result<WRITE3res> {
        let addr = self.pool_key.host;
        self.circuit.check_or_wait(addr)?;
        let mut conn = self.checkout().await?;
        self.stealth.wait().await;
        let res = conn.inner_mut().write(args).await;
        update_circuit(&self.circuit, conn, &res.as_ref().map(|_| &()), addr);
        res.map_err(|e| anyhow::anyhow!("{e}").context("NFSPROC3_WRITE"))
    }

    /// Issue `NFSPROC3_CREATE`  --  create a file.
    pub async fn create(&self, args: &CREATE3args<'_>) -> anyhow::Result<CREATE3res> {
        let addr = self.pool_key.host;
        self.circuit.check_or_wait(addr)?;
        let mut conn = self.checkout().await?;
        self.stealth.wait().await;
        let res = conn.inner_mut().create(args).await;
        update_circuit(&self.circuit, conn, &res.as_ref().map(|_| &()), addr);
        res.map_err(|e| anyhow::anyhow!("{e}").context("NFSPROC3_CREATE"))
    }

    /// Issue `NFSPROC3_MKDIR`  --  create a directory.
    pub async fn mkdir(&self, args: &MKDIR3args<'_>) -> anyhow::Result<MKDIR3res> {
        let addr = self.pool_key.host;
        self.circuit.check_or_wait(addr)?;
        let mut conn = self.checkout().await?;
        self.stealth.wait().await;
        let res = conn.inner_mut().mkdir(args).await;
        update_circuit(&self.circuit, conn, &res.as_ref().map(|_| &()), addr);
        res.map_err(|e| anyhow::anyhow!("{e}").context("NFSPROC3_MKDIR"))
    }

    /// Issue `NFSPROC3_SYMLINK`  --  create a symbolic link.
    pub async fn symlink(&self, args: &SYMLINK3args<'_>) -> anyhow::Result<SYMLINK3res> {
        let addr = self.pool_key.host;
        self.circuit.check_or_wait(addr)?;
        let mut conn = self.checkout().await?;
        self.stealth.wait().await;
        let res = conn.inner_mut().symlink(args).await;
        update_circuit(&self.circuit, conn, &res.as_ref().map(|_| &()), addr);
        res.map_err(|e| anyhow::anyhow!("{e}").context("NFSPROC3_SYMLINK"))
    }

    /// Issue `NFSPROC3_MKNOD`  --  create a special file.
    pub async fn mknod(&self, args: &MKNOD3args<'_>) -> anyhow::Result<MKNOD3res> {
        let addr = self.pool_key.host;
        self.circuit.check_or_wait(addr)?;
        let mut conn = self.checkout().await?;
        self.stealth.wait().await;
        let res = conn.inner_mut().mknod(args).await;
        update_circuit(&self.circuit, conn, &res.as_ref().map(|_| &()), addr);
        res.map_err(|e| anyhow::anyhow!("{e}").context("NFSPROC3_MKNOD"))
    }

    /// Issue `NFSPROC3_REMOVE`  --  remove a file.
    pub async fn remove(&self, args: &REMOVE3args<'_>) -> anyhow::Result<REMOVE3res> {
        let addr = self.pool_key.host;
        self.circuit.check_or_wait(addr)?;
        let mut conn = self.checkout().await?;
        self.stealth.wait().await;
        let res = conn.inner_mut().remove(args).await;
        update_circuit(&self.circuit, conn, &res.as_ref().map(|_| &()), addr);
        res.map_err(|e| anyhow::anyhow!("{e}").context("NFSPROC3_REMOVE"))
    }

    /// Issue `NFSPROC3_RMDIR`  --  remove a directory.
    pub async fn rmdir(&self, args: &RMDIR3args<'_>) -> anyhow::Result<RMDIR3res> {
        let addr = self.pool_key.host;
        self.circuit.check_or_wait(addr)?;
        let mut conn = self.checkout().await?;
        self.stealth.wait().await;
        let res = conn.inner_mut().rmdir(args).await;
        update_circuit(&self.circuit, conn, &res.as_ref().map(|_| &()), addr);
        res.map_err(|e| anyhow::anyhow!("{e}").context("NFSPROC3_RMDIR"))
    }

    /// Issue `NFSPROC3_RENAME`  --  rename a file.
    pub async fn rename(&self, args: &RENAME3args<'_, '_>) -> anyhow::Result<RENAME3res> {
        let addr = self.pool_key.host;
        self.circuit.check_or_wait(addr)?;
        let mut conn = self.checkout().await?;
        self.stealth.wait().await;
        let res = conn.inner_mut().rename(args).await;
        update_circuit(&self.circuit, conn, &res.as_ref().map(|_| &()), addr);
        res.map_err(|e| anyhow::anyhow!("{e}").context("NFSPROC3_RENAME"))
    }

    /// Issue `NFSPROC3_LINK`  --  create a hard link.
    pub async fn link(&self, args: &LINK3args<'_>) -> anyhow::Result<LINK3res> {
        let addr = self.pool_key.host;
        self.circuit.check_or_wait(addr)?;
        let mut conn = self.checkout().await?;
        self.stealth.wait().await;
        let res = conn.inner_mut().link(args).await;
        update_circuit(&self.circuit, conn, &res.as_ref().map(|_| &()), addr);
        res.map_err(|e| anyhow::anyhow!("{e}").context("NFSPROC3_LINK"))
    }

    /// Issue `NFSPROC3_READDIR`  --  read directory entries.
    pub async fn readdir(&self, args: &READDIR3args) -> anyhow::Result<READDIR3res<'static>> {
        let addr = self.pool_key.host;
        self.circuit.check_or_wait(addr)?;
        let mut conn = self.checkout().await?;
        self.stealth.wait().await;
        let res = conn.inner_mut().readdir(args).await;
        update_circuit(&self.circuit, conn, &res.as_ref().map(|_| &()), addr);
        res.map_err(|e| anyhow::anyhow!("{e}").context("NFSPROC3_READDIR"))
    }

    /// Issue `NFSPROC3_READDIRPLUS`  --  read directory entries with attributes.
    pub async fn readdirplus(&self, args: &READDIRPLUS3args) -> anyhow::Result<READDIRPLUS3res<'static>> {
        let addr = self.pool_key.host;
        self.circuit.check_or_wait(addr)?;
        let mut conn = self.checkout().await?;
        self.stealth.wait().await;
        let res = conn.inner_mut().readdirplus(args).await;
        update_circuit(&self.circuit, conn, &res.as_ref().map(|_| &()), addr);
        res.map_err(|e| anyhow::anyhow!("{e}").context("NFSPROC3_READDIRPLUS"))
    }

    /// Issue `NFSPROC3_FSSTAT`  --  get filesystem statistics.
    pub async fn fsstat(&self, args: &FSSTAT3args) -> anyhow::Result<FSSTAT3res> {
        let addr = self.pool_key.host;
        self.circuit.check_or_wait(addr)?;
        let mut conn = self.checkout().await?;
        self.stealth.wait().await;
        let res = conn.inner_mut().fsstat(args).await;
        update_circuit(&self.circuit, conn, &res.as_ref().map(|_| &()), addr);
        res.map_err(|e| anyhow::anyhow!("{e}").context("NFSPROC3_FSSTAT"))
    }

    /// Issue `NFSPROC3_FSINFO`  --  get filesystem capabilities.
    pub async fn fsinfo(&self, args: &FSINFO3args) -> anyhow::Result<FSINFO3res> {
        let addr = self.pool_key.host;
        self.circuit.check_or_wait(addr)?;
        let mut conn = self.checkout().await?;
        self.stealth.wait().await;
        let res = conn.inner_mut().fsinfo(args).await;
        update_circuit(&self.circuit, conn, &res.as_ref().map(|_| &()), addr);
        res.map_err(|e| anyhow::anyhow!("{e}").context("NFSPROC3_FSINFO"))
    }

    /// Issue `NFSPROC3_PATHCONF`  --  get filesystem path configuration.
    pub async fn pathconf(&self, args: &PATHCONF3args) -> anyhow::Result<PATHCONF3res> {
        let addr = self.pool_key.host;
        self.circuit.check_or_wait(addr)?;
        let mut conn = self.checkout().await?;
        self.stealth.wait().await;
        let res = conn.inner_mut().pathconf(args).await;
        update_circuit(&self.circuit, conn, &res.as_ref().map(|_| &()), addr);
        res.map_err(|e| anyhow::anyhow!("{e}").context("NFSPROC3_PATHCONF"))
    }

    /// Issue `NFSPROC3_COMMIT`  --  force unstable writes to stable storage.
    pub async fn commit(&self, args: &COMMIT3args) -> anyhow::Result<COMMIT3res> {
        let addr = self.pool_key.host;
        self.circuit.check_or_wait(addr)?;
        let mut conn = self.checkout().await?;
        self.stealth.wait().await;
        let res = conn.inner_mut().commit(args).await;
        update_circuit(&self.circuit, conn, &res.as_ref().map(|_| &()), addr);
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

/// Update the circuit breaker and poison the connection on transport failure.
///
/// Uses upstream `is_connection_reusable()` to decide whether the TCP session
/// is still in a clean state. Only genuinely transient transport failures
/// (non-reusable: `Io` and `FragmentedReply`) poison the connection AND trip
/// the breaker, per critical design rule 3. Reusable protocol-level RPC errors
/// (auth rejection, program/proc mismatch, garbage args, XDR) leave the
/// transport intact and do NOT count as breaker failures -- they are
/// permission-class / protocol denials, not outages. NFS-status errors
/// (`NFS3ERR_ACCES`, etc.) arrive inside the `Ok` payload as `Nfs3Result::Err`,
/// so they reach this function as `Ok` and never trip the breaker.
///
/// Takes `conn` by value so the connection (and its pool-admission permit) is
/// returned to the pool the moment the result is recorded, rather than lingering
/// until the end of the caller's method.
fn update_circuit<T>(circuit: &CircuitBreaker, mut conn: PooledConnection, res: &Result<T, &nfs3_client::RpcError>, addr: SocketAddr) {
    match res {
        Ok(_) => circuit.record_success(addr),
        // Transport is dead (Io) or left mid-fragment (FragmentedReply): the
        // connection is unusable and this is a transient outage -- poison and
        // count it against the breaker.
        Err(e) if !e.is_connection_reusable() => {
            conn.poison();
            circuit.record_failure(addr);
        },
        // Reusable RPC error (auth/program/proc/XDR): transport stays at a clean
        // message boundary and the failure is not transient, so leave the
        // breaker state unchanged and keep the connection.
        Err(_) => {},
    }
}
