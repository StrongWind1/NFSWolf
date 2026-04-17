//! Connection pool  --  per-(host, export, uid, gid) pooling with health eviction.
//!
//! Keys connections by (host, export, uid, gid) so each unique credential/export
//! pair has its own idle queue. Stale connections receive a GETATTR health check
//! before reuse. A poisoned connection is discarded instead of re-queued.
//! When the total outstanding count reaches `max_total`, callers wait on a
//! `tokio::sync::Notify` until a connection is returned.

// Toolkit API  --  not all items are used in currently-implemented phases.
use std::collections::VecDeque;
use std::net::SocketAddr;
use std::ops::{Deref, DerefMut};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use dashmap::DashMap;
use tokio::sync::{Mutex, Notify};

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
    pools: DashMap<PoolKey, Mutex<VecDeque<NfsConnection>>>,
    max_per_key: usize,
    max_total: usize,
    outstanding: AtomicUsize,
    stale_threshold: Duration,
    backpressure: Notify,
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
        f.debug_struct("PoolInner").field("max_per_key", &self.max_per_key).field("max_total", &self.max_total).field("outstanding", &self.outstanding.load(Ordering::Relaxed)).finish_non_exhaustive()
    }
}

impl ConnectionPool {
    /// Create a new pool with the given limits.
    #[must_use]
    pub fn new(max_per_key: usize, max_total: usize, stale_threshold: Duration) -> Self {
        Self { inner: Arc::new(PoolInner { pools: DashMap::new(), max_per_key, max_total, outstanding: AtomicUsize::new(0), stale_threshold, backpressure: Notify::new(), proxy: None }) }
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
        Self { inner: Arc::new(PoolInner { pools: DashMap::new(), max_per_key: 4, max_total: 256, outstanding: AtomicUsize::new(0), stale_threshold: Duration::from_secs(5), backpressure: Notify::new(), proxy: Some(proxy) }) }
    }

    /// Check out a connection for `key`, creating one if necessary.
    ///
    /// Blocks until a slot is available when `max_total` is reached.
    pub async fn checkout(&self, key: PoolKey, credential: Credential, reconnect: ReconnectStrategy) -> anyhow::Result<PooledConnection> {
        loop {
            // Wait if at global limit.
            if self.inner.outstanding.load(Ordering::Relaxed) >= self.inner.max_total {
                self.inner.backpressure.notified().await;
                continue;
            }

            if let Some(conn) = self.try_pop(&key).await {
                self.inner.outstanding.fetch_add(1, Ordering::Relaxed);
                return Ok(PooledConnection { conn: Some(conn), pool: self.clone(), key });
            }

            // No idle connection  --  create a new one (via proxy if configured).
            let conn = NfsConnection::connect(key.host, &key.export, credential, reconnect, self.inner.proxy.as_deref()).await?;
            self.inner.outstanding.fetch_add(1, Ordering::Relaxed);
            return Ok(PooledConnection { conn: Some(conn), pool: self.clone(), key });
        }
    }

    /// Return a connection to the idle queue (LIFO).
    ///
    /// Poisoned connections are discarded rather than re-queued.
    pub fn checkin(&self, key: PoolKey, conn: NfsConnection) {
        self.inner.outstanding.fetch_sub(1, Ordering::Relaxed);
        self.inner.backpressure.notify_one();

        if conn.health.poisoned {
            return; // discard
        }

        let queue = self.inner.pools.entry(key).or_insert_with(|| Mutex::new(VecDeque::new()));
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
        loop {
            if self.inner.outstanding.load(Ordering::Relaxed) >= self.inner.max_total {
                self.inner.backpressure.notified().await;
                continue;
            }

            if let Some(conn) = self.try_pop(&key).await {
                self.inner.outstanding.fetch_add(1, Ordering::Relaxed);
                return Ok(PooledConnection { conn: Some(conn), pool: self.clone(), key });
            }

            let conn = NfsConnection::connect_direct(key.host, nfs_port, credential, reconnect, self.inner.proxy.as_deref()).await?;
            self.inner.outstanding.fetch_add(1, Ordering::Relaxed);
            return Ok(PooledConnection { conn: Some(conn), pool: self.clone(), key });
        }
    }

    /// Drain all idle connections for a key (used after a host goes down).
    pub async fn drain(&self, key: &PoolKey) {
        if let Some(queue) = self.inner.pools.get(key) {
            queue.lock().await.clear();
        }
    }

    /// Snapshot current pool statistics.
    #[must_use]
    pub fn stats(&self) -> PoolStats {
        let outstanding = self.inner.outstanding.load(Ordering::Relaxed);
        let idle = self.inner.pools.iter().filter_map(|e| e.value().try_lock().ok().map(|q| q.len())).sum();
        PoolStats { idle, outstanding }
    }

    /// Pop one idle connection, running a health check if it is stale.
    async fn try_pop(&self, key: &PoolKey) -> Option<NfsConnection> {
        // Scope the DashMap ref and Mutex guard so both are dropped before the
        // health_check await  --  holding them across an await would block other tasks.
        let mut conn = {
            let entry = self.inner.pools.get(key)?;
            let mut queue = entry.lock().await;
            let conn = queue.pop_back()?;
            drop(queue);
            drop(entry);
            conn
        };

        if conn.is_stale(self.inner.stale_threshold) && !conn.health_check().await {
            // Connection is dead  --  discard and signal caller to create a new one.
            return None;
        }
        Some(conn)
    }
}

/// RAII wrapper  --  returns the connection to the pool on drop.
pub struct PooledConnection {
    conn: Option<NfsConnection>,
    pool: ConnectionPool,
    key: PoolKey,
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
