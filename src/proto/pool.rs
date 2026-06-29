//! Connection pool  --  per-(host, export, uid, gid) pooling with health eviction.
//!
//! Keys connections by (host, export, uid, gid) so each unique credential/export
//! pair has its own idle queue. Stale connections receive a GETATTR health check
//! before reuse. A poisoned connection is discarded instead of re-queued.
//! Admission is gated by a `tokio::sync::Semaphore` with `max_total` permits, so
//! the outstanding count can never exceed `max_total` and a returned connection
//! reliably wakes the next waiter (the permit is released on drop).

// Toolkit API  --  not all items are used in currently-implemented phases.
use std::collections::VecDeque;
use std::net::SocketAddr;
use std::ops::{Deref, DerefMut};
use std::sync::Arc;
use std::time::Duration;

use dashmap::DashMap;
use tokio::sync::{Mutex, OwnedSemaphorePermit, Semaphore};

use crate::proto::auth::Credential;
use crate::proto::conn::{NfsConnection, ReconnectStrategy};

/// Key identifying a unique (host, export, uid, gid) connection group.
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct PoolKey {
    /// Remote server address.
    pub host: SocketAddr,
    /// NFS export path.
    pub export: String,
    /// AUTH_SYS UID for this pool slot.
    pub uid: u32,
    /// AUTH_SYS GID for this pool slot.
    pub gid: u32,
}

/// Pool statistics snapshot.
#[derive(Debug, Clone)]
pub struct PoolStats {
    /// Total connections idle across all keys.
    pub idle: usize,
    /// Total connections currently checked out.
    pub outstanding: usize,
}

/// Connection pool inner data  --  shared by clones.
struct PoolInner {
    /// Per-key idle queues. The inner `Mutex<VecDeque>` is wrapped in `Arc` so a
    /// checkout can clone the queue handle out of the DashMap and drop the
    /// DashMap shard guard BEFORE awaiting the async mutex (see `try_pop`).
    pools: DashMap<PoolKey, Arc<Mutex<VecDeque<NfsConnection>>>>,
    max_per_key: usize,
    max_total: usize,
    /// Global admission gate  --  one permit per outstanding checkout. Acquiring a
    /// permit before handing out a connection enforces `max_total` atomically (it
    /// can never overshoot) and reliably wakes the next waiter when a
    /// `PooledConnection` is dropped, since the permit is released on drop.
    admission: Arc<Semaphore>,
    stale_threshold: Duration,
    /// Optional SOCKS5 proxy for all new connections created by this pool.
    proxy: Option<String>,
}

/// Per-(host, export, uid, gid) connection pool with health eviction.
///
/// Connections are returned in LIFO order to maximise cache warmth on the server.
/// Thread-safe via `Arc<PoolInner>` and per-key `Mutex<VecDeque>`.
#[derive(Clone, Debug)]
pub struct ConnectionPool {
    inner: Arc<PoolInner>,
}

impl std::fmt::Debug for PoolInner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PoolInner").field("max_per_key", &self.max_per_key).field("max_total", &self.max_total).field("outstanding", &self.max_total.saturating_sub(self.admission.available_permits())).finish_non_exhaustive()
    }
}

impl ConnectionPool {
    /// Create a new pool with the given limits.
    #[must_use]
    pub fn new(max_per_key: usize, max_total: usize, stale_threshold: Duration) -> Self {
        Self { inner: Arc::new(PoolInner { pools: DashMap::new(), max_per_key, max_total, admission: Arc::new(Semaphore::new(max_total)), stale_threshold, proxy: None }) }
    }

    /// Create with sensible defaults for interactive scanning.
    #[must_use]
    pub fn default_config() -> Self {
        Self::new(4, 256, Duration::from_secs(5))
    }

    /// Create with default limits and a SOCKS5 proxy for all connections.
    ///
    /// `proxy` should be `"host:port"` or `"socks5://host:port"`.
    #[must_use]
    pub fn with_proxy(proxy: String) -> Self {
        Self { inner: Arc::new(PoolInner { pools: DashMap::new(), max_per_key: 4, max_total: 256, admission: Arc::new(Semaphore::new(256)), stale_threshold: Duration::from_secs(5), proxy: Some(proxy) }) }
    }

    /// Check out a connection for `key`, creating one if necessary.
    ///
    /// Blocks until a slot is available when `max_total` is reached.
    pub async fn checkout(&self, key: PoolKey, credential: Credential, reconnect: ReconnectStrategy) -> anyhow::Result<PooledConnection> {
        // Reserve a global slot atomically before touching the pool. The permit
        // bounds outstanding connections to `max_total` (it can never overshoot)
        // and is released on `PooledConnection` drop, which wakes the next waiter.
        let permit = Arc::clone(&self.inner.admission).acquire_owned().await.map_err(|e| anyhow::anyhow!("connection pool closed: {e}"))?;

        if let Some(mut conn) = self.try_pop(&key).await {
            // Re-stamp the reused connection with the REQUESTED credential before
            // returning it: see `restamp_credential` for why uid/gid keying alone
            // is not enough (aux-gids + machinename are not part of PoolKey).
            restamp_credential(&mut conn, credential);
            return Ok(PooledConnection { conn: Some(conn), pool: self.clone(), key, _permit: permit });
        }

        // No idle connection  --  create a new one (via proxy if configured). A
        // fresh connection is stamped with `credential` at construction, so it
        // needs no re-stamp here.
        let conn = NfsConnection::connect(key.host, &key.export, credential, reconnect, self.inner.proxy.as_deref()).await?;
        Ok(PooledConnection { conn: Some(conn), pool: self.clone(), key, _permit: permit })
    }

    /// Return a connection to the idle queue (LIFO).
    ///
    /// Poisoned connections are discarded rather than re-queued.
    pub fn checkin(&self, key: PoolKey, conn: NfsConnection) {
        // The admission permit is released by `PooledConnection`'s drop, which runs
        // after this call (explicit Drop body first, then fields), so the slot is
        // freed and the next waiter woken only once the connection is back in the
        // idle queue. No manual counter/notify is needed here.
        if conn.health.poisoned {
            return; // discard
        }

        // Clone the queue handle out and drop the DashMap entry guard before
        // touching the inner mutex, so the shard write lock is never held across
        // the (non-blocking) try_lock either.
        let queue = {
            let entry = self.inner.pools.entry(key).or_insert_with(|| Arc::new(Mutex::new(VecDeque::new())));
            Arc::clone(&entry)
        };
        // Try to lock without blocking  --  if the mutex is contended, just drop.
        if let Ok(mut q) = queue.try_lock()
            && q.len() < self.inner.max_per_key
        {
            q.push_back(conn); // LIFO: push_back + pop_back
        }
    }

    /// Check out a direct (no-MOUNT) connection for `key`, creating one if necessary.
    ///
    /// `nfs_port` is the NFS port to connect to without portmapper or MOUNT.
    /// Used when `--handle` is given and portmapper is filtered but the NFS port is open.
    pub async fn checkout_direct(&self, key: PoolKey, nfs_port: u16, credential: Credential, reconnect: ReconnectStrategy) -> anyhow::Result<PooledConnection> {
        let permit = Arc::clone(&self.inner.admission).acquire_owned().await.map_err(|e| anyhow::anyhow!("connection pool closed: {e}"))?;

        if let Some(mut conn) = self.try_pop(&key).await {
            // Same re-stamp as checkout(): honour the requested aux-gids/hostname
            // on a reused connection (PoolKey keys only on uid/gid).
            restamp_credential(&mut conn, credential);
            return Ok(PooledConnection { conn: Some(conn), pool: self.clone(), key, _permit: permit });
        }

        let conn = NfsConnection::connect_direct(key.host, nfs_port, credential, reconnect, self.inner.proxy.as_deref()).await?;
        Ok(PooledConnection { conn: Some(conn), pool: self.clone(), key, _permit: permit })
    }

    /// Drain all idle connections for a key (used after a host goes down).
    pub async fn drain(&self, key: &PoolKey) {
        // Clone the queue handle out before awaiting, dropping the DashMap read
        // guard first (same guard-across-await hazard as `try_pop`).
        let queue = self.inner.pools.get(key).map(|q| Arc::clone(&q));
        if let Some(queue) = queue {
            queue.lock().await.clear();
        }
    }

    /// Snapshot current pool statistics.
    #[must_use]
    pub fn stats(&self) -> PoolStats {
        // Outstanding = permits handed out = max_total minus those still available.
        let outstanding = self.inner.max_total.saturating_sub(self.inner.admission.available_permits());
        let idle = self.inner.pools.iter().filter_map(|e| e.value().try_lock().ok().map(|q| q.len())).sum();
        PoolStats { idle, outstanding }
    }

    /// Pop one idle connection, running a health check if it is stale.
    async fn try_pop(&self, key: &PoolKey) -> Option<NfsConnection> {
        // Clone the per-key queue handle out of the DashMap and drop the DashMap
        // read guard BEFORE awaiting the async mutex. A DashMap `Ref` is a shard
        // RwLock read guard; holding it across `.lock().await` is the documented
        // tokio "lock held across await" footgun -- a concurrent `checkin` taking
        // the same shard's write lock (via `entry`) can stall a worker thread, and
        // under same-key checkout/checkin contention the runtime can wedge.
        // `clippy::await_holding_lock` does not see DashMap guards, so this must be
        // enforced structurally. The `get` Ref is confined to the block below, so
        // it is dropped before `queue.lock().await`.
        let queue = {
            let entry = self.inner.pools.get(key)?;
            Arc::clone(&entry)
        };

        let mut conn = {
            let mut q = queue.lock().await;
            q.pop_back()?
        };

        if conn.is_stale(self.inner.stale_threshold) && !conn.health_check().await {
            // Connection is dead  --  discard and signal caller to create a new one.
            return None;
        }
        Some(conn)
    }
}

/// Re-stamp `conn` with `credential` so the AUTH_SYS identity actually used on
/// the wire matches the caller's request, not whatever the pooled connection was
/// last stamped with.
///
/// `PoolKey` keys only on (host, export, uid, gid); the auxiliary-GID list and
/// the machinename (RFC 1057 S9.2) are not part of the key. Without this, a
/// connection created for uid=0/gid=0 with `gids=[100]` (or a specific hostname)
/// could be reused for a later uid=0/gid=0 request carrying different aux-gids /
/// hostname, silently running under the wrong supplementary groups. This mirrors
/// the per-call credential swap `NfsConnection::access_as` already performs.
fn restamp_credential(conn: &mut NfsConnection, credential: Credential) {
    let opaque = match &credential {
        Credential::None => nfs3_types::rpc::opaque_auth::default(),
        Credential::Sys(auth) => auth.to_opaque_auth(),
    };
    conn.inner_mut().nfs3_client.set_credential(opaque);
    conn.update_credential(credential);
}

/// RAII wrapper  --  returns the connection to the pool on drop.
pub struct PooledConnection {
    conn: Option<NfsConnection>,
    pool: ConnectionPool,
    key: PoolKey,
    /// Global admission permit  --  released when this guard drops (after the
    /// `Drop` body runs `checkin`), freeing the `max_total` slot and waking the
    /// next waiter. Held purely for its drop side effect.
    _permit: OwnedSemaphorePermit,
}

impl std::fmt::Debug for PooledConnection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PooledConnection").field("key", &self.key).finish_non_exhaustive()
    }
}

impl Drop for PooledConnection {
    fn drop(&mut self) {
        if let Some(conn) = self.conn.take() {
            self.pool.checkin(self.key.clone(), conn);
        }
    }
}

impl Deref for PooledConnection {
    type Target = NfsConnection;

    fn deref(&self) -> &Self::Target {
        // conn is always Some while this guard is alive; None only after Drop takes it.
        self.conn.as_ref().unwrap_or_else(|| unreachable!("connection must be present while guard is alive"))
    }
}

impl DerefMut for PooledConnection {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.conn.as_mut().unwrap_or_else(|| unreachable!("connection must be present while guard is alive"))
    }
}
