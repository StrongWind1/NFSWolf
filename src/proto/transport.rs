//! The pooled [`RpcTransport`] -- where all of nfswolf's connection policy lives.
//!
//! The protocol crates deliberately carry none: they describe wire formats and
//! nothing else. Everything that decides *how* a call reaches the server --
//! reusing connections, pacing them, giving up on a dead host, bounding a stall
//! -- is here, written once and shared by every NFS version rather than
//! reimplemented per client.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use onc_rpc_client::RpcError;
use onc_rpc_client::RpcTransport;
use onc_rpc_client::rpc::opaque_auth;
use onc_xdr::{Pack, Unpack};

use crate::proto::auth::Credential;
use crate::proto::circuit::CircuitBreaker;
use crate::proto::conn::ReconnectStrategy;
use crate::proto::pool::{ConnectionPool, PoolKey, PooledConnection};
use crate::util::stealth::StealthConfig;

/// Ceiling on how long a single RPC may take before the connection is written
/// off.
///
/// Without it a server that accepts the TCP connection and then stops
/// responding holds a pooled connection and its admission permit forever. The
/// pool starves while the circuit breaker, which is only consulted *before* a
/// call, stays blind to the fact that nothing is coming back. Bounding the wait
/// converts a stall into a transient failure the breaker can act on.
const RPC_TIMEOUT: Duration = Duration::from_secs(30);

/// An [`RpcTransport`] that draws connections from the shared pool and applies
/// nfswolf's resilience policy to every call.
#[derive(Clone)]
pub(crate) struct PooledTransport {
    pool: Arc<ConnectionPool>,
    pool_key: PoolKey,
    circuit: Arc<CircuitBreaker>,
    stealth: StealthConfig,
    credential: Credential,
    reconnect: ReconnectStrategy,
    /// When set, connections bypass MOUNT and go straight to this NFS port.
    direct_nfs_port: Option<u16>,
}

impl std::fmt::Debug for PooledTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PooledTransport").field("pool_key", &self.pool_key).finish_non_exhaustive()
    }
}

impl PooledTransport {
    /// Build a transport that mounts its export through MOUNT.
    pub(crate) const fn new(pool: Arc<ConnectionPool>, pool_key: PoolKey, circuit: Arc<CircuitBreaker>, stealth: StealthConfig, credential: Credential, reconnect: ReconnectStrategy) -> Self {
        Self { pool, pool_key, circuit, stealth, credential, reconnect, direct_nfs_port: None }
    }

    /// Build a transport that bypasses MOUNT and talks to `nfs_port` directly.
    pub(crate) const fn new_direct(pool: Arc<ConnectionPool>, pool_key: PoolKey, circuit: Arc<CircuitBreaker>, stealth: StealthConfig, credential: Credential, reconnect: ReconnectStrategy, nfs_port: u16) -> Self {
        Self { pool, pool_key, circuit, stealth, credential, reconnect, direct_nfs_port: Some(nfs_port) }
    }

    /// The server this transport talks to.
    pub(crate) const fn addr(&self) -> SocketAddr {
        self.pool_key.host
    }

    /// The identity calls are issued under.
    pub(crate) const fn uid(&self) -> u32 {
        self.pool_key.uid
    }

    /// The primary group calls are issued under.
    pub(crate) const fn gid(&self) -> u32 {
        self.pool_key.gid
    }

    /// The credential calls are issued under.
    pub(crate) const fn credential(&self) -> &Credential {
        &self.credential
    }

    /// Derive a transport identical to this one but under a different identity.
    ///
    /// `uid` and `gid` are part of the pool key, so the derived transport draws
    /// from a different connection set. That is deliberate: a pooled connection
    /// carries a credential, and handing one back to a caller expecting a
    /// different identity would silently issue calls as the wrong user.
    pub(crate) fn with_credential(&self, credential: Credential, uid: u32, gid: u32) -> Self {
        let mut next = self.clone();
        next.pool_key.uid = uid;
        next.pool_key.gid = gid;
        next.credential = credential;
        next
    }

    /// Check out one connection, honouring the breaker and the stealth delay.
    pub(crate) async fn checkout(&self) -> anyhow::Result<PooledConnection> {
        let addr = self.pool_key.host;
        self.circuit.check_or_wait(addr)?;
        self.stealth.wait().await;
        match self.pool.checkout_for(self.pool_key.clone(), self.credential.clone(), self.reconnect, self.direct_nfs_port).await {
            Ok(conn) => Ok(conn),
            Err(e) => {
                // A connection that could not be established is usually the
                // outage the breaker exists to notice -- without this a dead
                // host is retried at full rate forever.
                //
                // But checkout also performs the MOUNT exchange, and a MOUNT
                // denial is an authorization decision, not an outage. Counting
                // it would violate the same rule the RPC path is careful about:
                // probe an export we are not on the host list for, and ten
                // denials open a breaker keyed on the address alone, which then
                // refuses every *other* export on that host -- including the
                // ones we can reach. That is the tool giving up exactly when it
                // started learning something.
                if !is_authorization_denial(&e) {
                    self.circuit.record_failure(addr);
                }
                Err(e)
            },
        }
    }

    /// Record an RPC outcome, release the connection, and surface the result.
    ///
    /// Takes `conn` by value so the pool admission permit is freed the moment
    /// the outcome is known, rather than lingering to the end of the caller.
    fn finish<T>(&self, mut conn: PooledConnection, timed: Result<Result<T, RpcError>, tokio::time::error::Elapsed>) -> Result<T, RpcError> {
        let addr = self.pool_key.host;
        match timed {
            Ok(res) => {
                Self::update_circuit(&self.circuit, &mut conn, res.as_ref(), addr);
                drop(conn);
                res
            },
            Err(_elapsed) => {
                // The reply may be half-read, so the stream is desynchronised
                // regardless of what the server does next.
                //
                // Poisoning also covers a second case: a timeout cancels the
                // future mid-flight, so a `call_as` that was running under a
                // borrowed identity never reaches its restore. Discarding the
                // connection is what stops that identity leaking to whoever
                // checks it out next.
                conn.poison();
                self.circuit.record_failure(addr);
                drop(conn);
                Err(RpcError::Io(std::io::Error::new(std::io::ErrorKind::TimedOut, format!("RPC timed out after {RPC_TIMEOUT:?}"))))
            },
        }
    }

    /// Classify an RPC outcome for the breaker and the connection.
    ///
    /// The two judgements here are the reason this logic lives in one place.
    ///
    /// **Which errors poison the connection.** `is_connection_reusable()`
    /// answers that: the non-reusable set is `{Io, FragmentedReply}`. Either
    /// leaves the socket unusable -- dead, or stopped mid-fragment -- so it must
    /// be discarded rather than requeued.
    ///
    /// **Which errors trip the breaker.** Only `Io`. `FragmentedReply` is a
    /// deterministic RFC 1831 record-marking condition that a large `READ` or
    /// `READDIRPLUS` reply can provoke from a perfectly healthy server. Counting
    /// it would let one oversized reply wedge every subsequent small `GETATTR`
    /// to that host. Reusable protocol errors -- auth rejection, program or
    /// procedure mismatch, garbage args, XDR faults -- leave the transport
    /// intact and are denials rather than outages.
    ///
    /// NFS status errors such as `NFS3ERR_ACCES` never reach here as errors at
    /// all: they arrive inside a successful RPC reply, so they land in the `Ok`
    /// arm. That is deliberate. A permission denial during a UID sweep is the
    /// expected result, and letting it trip the breaker would make the tool
    /// stop probing precisely when it started finding things.
    fn update_circuit<T>(circuit: &CircuitBreaker, conn: &mut PooledConnection, res: Result<&T, &RpcError>, addr: SocketAddr) {
        match res {
            Ok(_) => circuit.record_success(addr),
            Err(e) => {
                if !e.is_connection_reusable() {
                    conn.poison();
                }
                if matches!(e, RpcError::Io(_)) {
                    circuit.record_failure(addr);
                }
            },
        }
    }
}

/// Whether a checkout failure was the server refusing us rather than failing.
///
/// MOUNT answers a denial with a status code, so the exchange completed and the
/// host is demonstrably alive. Only a genuine transport fault should feed the
/// breaker.
fn is_authorization_denial(err: &anyhow::Error) -> bool {
    err.chain().any(|cause| cause.downcast_ref::<nfs_mount::MountError<RpcError>>().is_some_and(nfs_mount::MountError::is_denial))
}

/// Flatten a checkout failure into the transport's error type.
///
/// `anyhow::Error`'s `Display` prints only the outermost context, so the
/// alternate form is used to keep the whole chain. That chain is the diagnosis:
/// a checkout failure is usually `MNT3ERR_ACCES` three levels down, which is
/// what tells an operator to retry from a privileged port rather than that the
/// host is unreachable.
fn checkout_error(e: &anyhow::Error) -> RpcError {
    RpcError::Io(std::io::Error::other(format!("{e:#}")))
}

impl RpcTransport for PooledTransport {
    type Error = RpcError;

    #[expect(clippy::similar_names, reason = "prog and proc are the RFC 5531 call_body field names")]
    async fn call<C, R>(&self, prog: u32, vers: u32, proc: u32, args: &C) -> Result<R, RpcError>
    where
        C: Pack + Send + Sync,
        R: Unpack,
    {
        let mut conn = self.checkout().await.map_err(|e| checkout_error(&e))?;
        let timed = tokio::time::timeout(RPC_TIMEOUT, conn.call::<C, R>(prog, vers, proc, args)).await;
        self.finish(conn, timed)
    }

    #[expect(clippy::similar_names, reason = "prog and proc are the RFC 5531 call_body field names")]
    async fn call_as<C, R>(&self, cred: opaque_auth<'static>, prog: u32, vers: u32, proc: u32, args: &C) -> Result<R, RpcError>
    where
        C: Pack + Send + Sync,
        R: Unpack,
    {
        let mut conn = self.checkout().await.map_err(|e| checkout_error(&e))?;
        let timed = tokio::time::timeout(RPC_TIMEOUT, conn.call_as::<C, R>(cred, prog, vers, proc, args)).await;
        self.finish(conn, timed)
    }
}
