//! NfsConnection  --  wraps nfs3_client::Nfs3Connection with nfswolf management.
//!
//! Adds AUTH_SYS stamp injection, reconnection strategy, and health tracking.
//! Each connection wraps a single nfs3_client TCP connection to one (host, export).
//! A second TCP connection to the NFS port is kept for raw RPC calls (NFSv2, NLM, NSM).
//! When a SOCKS5 proxy is configured, both connections are tunneled through it.

// Toolkit API  --  not all items are used in currently-implemented phases.
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use anyhow::Context as _;
use nfs3_client::net::Connector;
use nfs3_client::rpc::RpcClient;
use nfs3_client::tokio::{TokioConnector, TokioIo};
use nfs3_client::{Nfs3Connection, Nfs3ConnectionBuilder};
use nfs3_types::nfs3::{GETATTR3args, Nfs3Result, nfs_fh3, nfsstat3};
use nfs3_types::xdr_codec::{Pack, Unpack};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::proto::auth::{AuthSys, Credential};

/// Concrete IO type used for all NFS connections.
pub type NfsIo = TokioIo<TcpStream>;

/// Reconnection strategy  --  matches HP-UX quirk where the server closes after each exchange.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReconnectStrategy {
    /// Keep the TCP connection open across multiple RPC calls (standard).
    Persistent,
    /// Reconnect after every RPC call (HP-UX drops connection after one exchange).
    ResetPerCall,
}

/// Health state of a pooled connection.
#[derive(Debug)]
pub struct ConnectionHealth {
    /// When this connection was established.
    pub created_at: Instant,
    /// When this connection last completed a successful call.
    pub last_used: Instant,
    /// Total number of RPC calls made on this connection.
    pub request_count: u64,
    /// True if the connection encountered a fatal error and must not be reused.
    pub poisoned: bool,
}

impl ConnectionHealth {
    fn new() -> Self {
        let now = Instant::now();
        Self { created_at: now, last_used: now, request_count: 0, poisoned: false }
    }
}

/// Wraps nfs3_client::Nfs3Connection with nfswolf-specific management.
///
/// Holds two TCP connections: one for NFSv3 procedures (via nfs3_client) and
/// one for raw RPC calls (NFSv2, NLM, NSM via `RpcClient::call`).
pub struct NfsConnection {
    /// NFSv3 connection including mount and NFS clients.
    inner: Nfs3Connection<NfsIo>,
    /// Separate raw RPC connection to the NFS port for NFSv2/NLM/NSM calls.
    raw_rpc: RpcClient<NfsIo>,
    /// Remote server address (host + portmapper port).
    pub addr: SocketAddr,
    /// NFS export path this connection is mounted on.
    pub export: String,
    /// Current AUTH_SYS credential injected into calls.
    pub credential: Credential,
    /// Reconnection behaviour.
    reconnect: ReconnectStrategy,
    /// Connection health for pool management.
    pub health: ConnectionHealth,
    /// True when this connection was established without MOUNT (raw handle mode).
    ///
    /// In this case the inner mountres3_ok is a dummy with an empty handle, so
    /// health checks must use NFSPROC3_NULL rather than GETATTR on the root fh.
    is_direct: bool,
}

impl std::fmt::Debug for NfsConnection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NfsConnection").field("addr", &self.addr).field("export", &self.export).field("request_count", &self.health.request_count).field("poisoned", &self.health.poisoned).finish_non_exhaustive()
    }
}

impl NfsConnection {
    /// Establish a new connection to `addr` and mount `export`.
    ///
    /// Uses a privileged local port (300-1023) as required by most NFS servers.
    /// When `proxy` is `Some("host:port")` or `Some("socks5://host:port")`, all
    /// TCP connections are tunneled through the SOCKS5 proxy.
    pub async fn connect(addr: SocketAddr, export: &str, credential: Credential, reconnect: ReconnectStrategy, proxy: Option<&str>) -> anyhow::Result<Self> {
        let opaque = match &credential {
            Credential::None => nfs3_types::rpc::opaque_auth::default(),
            Credential::Sys(auth) => auth.to_opaque_auth(),
        };

        let host = addr.ip().to_string();

        // Build the NFS+MOUNT connection via TCP (direct or proxied).
        let conn = if let Some(p) = proxy {
            let proxy_addr = parse_proxy_addr(p)?;
            Nfs3ConnectionBuilder::new(Socks5Connector { proxy_addr }, host.as_str(), export).credential(opaque.clone()).mount().await.with_context(|| format!("mount {export} on {addr} via proxy {p}"))?
        } else {
            Nfs3ConnectionBuilder::new(TokioConnector, host.as_str(), export).credential(opaque.clone()).mount().await.with_context(|| format!("mount {export} on {addr}"))?
        };

        // Build a second TCP connection to the NFS port for raw RPC calls.
        let nfs_port = conn.nfs3_port;
        let nfs_addr = SocketAddr::new(addr.ip(), nfs_port);
        let raw_io: TokioIo<TcpStream> = if let Some(p) = proxy {
            let proxy_addr = parse_proxy_addr(p)?;
            let stream = socks5_connect(proxy_addr, nfs_addr).await.with_context(|| format!("raw RPC proxy connect to {nfs_addr}"))?;
            TokioIo::new(stream)
        } else {
            TokioConnector.connect(nfs_addr).await.with_context(|| format!("raw RPC connect to {nfs_addr}"))?
        };
        let raw_rpc = RpcClient::new_with_auth(raw_io, opaque, nfs3_types::rpc::opaque_auth::default());

        Ok(Self { inner: conn, raw_rpc, addr, export: export.to_owned(), credential, reconnect, health: ConnectionHealth::new(), is_direct: false })
    }

    /// Execute a raw RPC call on the NFS port connection.
    ///
    /// Used for NFSv2 (program 100003, version 2), NLM (100021), NSM (100024).
    /// The caller is responsible for correct `program`, `version`, and `proc` values.
    pub async fn call_raw<C, R>(&mut self, program: u32, version: u32, proc: u32, args: &C) -> anyhow::Result<R>
    where
        C: Pack + Send + Sync,
        R: Unpack,
    {
        self.health.request_count = self.health.request_count.saturating_add(1);
        self.health.last_used = Instant::now();
        let result = self.raw_rpc.call::<C, R>(program, version, proc, args).await;
        match result {
            Ok(r) => Ok(r),
            Err(e) => {
                self.health.poisoned = true;
                Err(anyhow::Error::new(e).context("raw RPC call failed"))
            },
        }
    }

    /// Establish a direct NFS connection without going through MOUNT.
    ///
    /// Connects to `nfs_port` on `addr` directly, bypassing portmapper and the MOUNT
    /// protocol. Used when `--handle` is given and portmapper is filtered but the NFS
    /// port is directly reachable.
    ///
    /// The inner mountres3_ok contains a dummy empty handle; health checks use
    /// NFSPROC3_NULL instead of GETATTR since no valid root handle exists.
    pub async fn connect_direct(addr: SocketAddr, nfs_port: u16, credential: Credential, reconnect: ReconnectStrategy, proxy: Option<&str>) -> anyhow::Result<Self> {
        use nfs3_client::{MountClient, Nfs3Client as RawNfs3};
        use nfs3_types::mount::{dirpath, fhandle3, mountres3_ok};
        use nfs3_types::xdr_codec::Opaque;

        let opaque = match &credential {
            Credential::None => nfs3_types::rpc::opaque_auth::default(),
            Credential::Sys(auth) => auth.to_opaque_auth(),
        };

        let nfs_addr = SocketAddr::new(addr.ip(), nfs_port);

        // Helper to connect to nfs_addr, optionally via SOCKS5.
        let tcp_connect = |target: SocketAddr| async move {
            if let Some(p) = proxy {
                let proxy_addr = parse_proxy_addr(p)?;
                let stream = socks5_connect(proxy_addr, target).await?;
                anyhow::Ok(TokioIo::new(stream))
            } else {
                Ok(TokioConnector.connect(target).await?)
            }
        };

        // Primary NFS connection -- use privileged source port when not proxied.
        let nfs_io: TokioIo<TcpStream> = if proxy.is_some() { tcp_connect(nfs_addr).await.with_context(|| format!("direct NFS connect (proxy) to {nfs_addr}"))? } else { connect_privileged_nfs(nfs_addr).await.with_context(|| format!("direct NFS connect to {nfs_addr}"))? };
        let nfs3_client = RawNfs3::new_with_auth(nfs_io, opaque.clone(), nfs3_types::rpc::opaque_auth::default());

        // Dummy mount client on the NFS port -- satisfies the Nfs3Connection type but
        // is never called. Using NFS port here avoids an extra connection to mount port.
        let dummy_io = tcp_connect(nfs_addr).await.with_context(|| format!("dummy mount connect to {nfs_addr}"))?;
        let mount_client = MountClient::new(dummy_io);

        // Fake mountres3_ok with an empty handle -- not used for file operations.
        // AUTH_SYS (flavor 1) is assumed; the raw handle bypasses any root fh usage.
        let mount_resok = mountres3_ok { fhandle: fhandle3(Opaque::owned(vec![])), auth_flavors: vec![1] };

        let inner = Nfs3Connection { host: addr.ip().to_string(), mount_port: nfs_port, mount_path: dirpath(Opaque::owned(b"/__direct__".to_vec())), mount_client, mount_resok, nfs3_port: nfs_port, nfs3_client };

        // Raw RPC connection for NFSv2/NLM/NSM calls.
        let raw_io = tcp_connect(nfs_addr).await.with_context(|| format!("raw RPC direct connect to {nfs_addr}"))?;
        let raw_rpc = RpcClient::new_with_auth(raw_io, opaque, nfs3_types::rpc::opaque_auth::default());

        Ok(Self { inner, raw_rpc, addr, export: format!("__direct__{nfs_port}"), credential, reconnect, health: ConnectionHealth::new(), is_direct: true })
    }

    /// Send GETATTR on the root handle; returns true if the server responds NFS3_OK.
    ///
    /// Used by the connection pool to verify a connection is still usable before reuse.
    /// Direct connections (established without MOUNT) use NFSPROC3_NULL instead since
    /// they have no valid root handle in mountres3_ok.
    pub async fn health_check(&mut self) -> bool {
        if self.is_direct {
            // No valid root handle available -- use NULL as a lightweight liveness probe.
            return self.inner.null().await.is_ok();
        }
        let root_fh = nfs_fh3 { data: self.inner.root_nfs_fh3().data.clone() };
        let args = GETATTR3args { object: root_fh };
        // Server is alive if GETATTR returns OK or a permission error (expected during spraying).
        self.inner.getattr(&args).await.is_ok_and(|res| match res {
            Nfs3Result::Ok(_) => true,
            Nfs3Result::Err((stat, _)) => matches!(stat, nfsstat3::NFS3ERR_ACCES | nfsstat3::NFS3ERR_PERM),
        })
    }

    /// Mark this connection as permanently failed.
    ///
    /// A poisoned connection is discarded on return to the pool rather than re-queued.
    pub const fn poison(&mut self) {
        self.health.poisoned = true;
    }

    /// Returns true if `last_used` is older than `threshold`.
    ///
    /// Stale connections are health-checked before reuse.
    #[must_use]
    pub fn is_stale(&self, threshold: Duration) -> bool {
        self.health.last_used.elapsed() > threshold
    }

    /// Swap in a different credential (new pool key -> new stamp).
    ///
    /// This does not reconnect; the credential is only used for the next call if
    /// the underlying `Nfs3Client` is rebuilt. Primarily used to note which uid
    /// the connection was last used with.
    pub fn update_credential(&mut self, new_cred: Credential) {
        self.credential = new_cred;
    }

    /// Get a mutable reference to the inner NFSv3 connection.
    ///
    /// The caller borrows this exclusively, so no concurrent calls are possible.
    pub fn inner_mut(&mut self) -> &mut Nfs3Connection<NfsIo> {
        self.health.request_count = self.health.request_count.saturating_add(1);
        self.health.last_used = Instant::now();
        &mut self.inner
    }

    /// Send NFSPROC3_ACCESS with a fresh AUTH_SYS credential on the existing TCP connection.
    ///
    /// Swaps the credential inline before the call and restores the connection's
    /// registered credential afterwards (both on success and on error), so a
    /// subsequent pool user does not inherit the sprayed identity. This lets UID/GID
    /// spraying reuse a single mount session instead of opening a new TCP connection
    /// per (uid, gid) pair.
    pub async fn access_as(&mut self, args: &nfs3_types::nfs3::ACCESS3args, uid: u32, gid: u32, gids: &[u32], hostname: &str) -> anyhow::Result<nfs3_types::nfs3::ACCESS3res> {
        use crate::proto::auth::AuthSys;

        let stamp_cred = AuthSys::with_groups(uid, gid, gids, hostname).to_opaque_auth();
        self.health.request_count = self.health.request_count.saturating_add(1);
        self.health.last_used = Instant::now();
        // Swap credential on the inner nfs3_client for this one call.  This
        // reuses the existing TCP session instead of opening a new connection.
        self.inner.nfs3_client.set_credential(stamp_cred);
        let result = self.inner.access(args).await.map_err(|e| anyhow::anyhow!("{e}"));
        // Always restore the registered credential so the next pool user
        // receives a connection stamped with the pool key's identity.
        let orig = match &self.credential {
            Credential::None => nfs3_types::rpc::opaque_auth::default(),
            Credential::Sys(auth) => auth.to_opaque_auth(),
        };
        self.inner.nfs3_client.set_credential(orig);
        result
    }

    /// Reconnect strategy in effect for this connection.
    #[must_use]
    pub const fn reconnect_strategy(&self) -> ReconnectStrategy {
        self.reconnect
    }
}

// =============================================================================
// SOCKS5 proxy support
// =============================================================================

/// Establish a TCP connection to `target` via a SOCKS5 proxy at `proxy_addr`.
///
/// Implements the minimal SOCKS5 CONNECT handshake (RFC 1928):
/// 1. Greeting: [VER=5, NMETHODS=1, METHOD=NO_AUTH(0)]
/// 2. Method selection: server replies [VER=5, METHOD=0]
/// 3. CONNECT request: [VER, CMD=CONNECT, RSV, ATYP=IPv4, addr(4), port(2)]
/// 4. Reply: [VER, REP=0(success), RSV, ATYP, BNDADDR, BNDPORT]
///
/// IPv6 targets are not supported (NFS servers are typically IPv4).
async fn socks5_connect(proxy_addr: SocketAddr, target: SocketAddr) -> std::io::Result<TcpStream> {
    let mut stream = TcpStream::connect(proxy_addr).await?;

    // Step 1: greeting  --  offer NO_AUTH (method 0x00).
    stream.write_all(&[0x05, 0x01, 0x00]).await?;

    // Step 2: method selection response.
    let mut method_resp = [0u8; 2];
    stream.read_exact(&mut method_resp).await?;
    if method_resp[0] != 0x05 || method_resp[1] != 0x00 {
        return Err(std::io::Error::other(format!("SOCKS5 auth rejected (method byte=0x{:02x})", method_resp[1])));
    }

    // Step 3: CONNECT request  --  IPv4 only (ATYP=0x01).
    let ip = match target.ip() {
        IpAddr::V4(v4) => v4.octets(),
        IpAddr::V6(_) => return Err(std::io::Error::other("SOCKS5 proxy: IPv6 target not supported")),
    };
    let port = target.port().to_be_bytes();
    stream.write_all(&[0x05, 0x01, 0x00, 0x01, ip[0], ip[1], ip[2], ip[3], port[0], port[1]]).await?;

    // Step 4: CONNECT reply  --  10 bytes for IPv4 bind address.
    let mut reply = [0u8; 10];
    stream.read_exact(&mut reply).await?;
    if reply[1] != 0x00 {
        return Err(std::io::Error::other(format!("SOCKS5 CONNECT failed (REP=0x{:02x})", reply[1])));
    }

    Ok(stream)
}

/// Parse a proxy string of the form `host:port` or `socks5://host:port`.
fn parse_proxy_addr(proxy: &str) -> anyhow::Result<SocketAddr> {
    let stripped = proxy.strip_prefix("socks5://").unwrap_or(proxy);
    stripped.parse::<SocketAddr>().with_context(|| format!("invalid proxy address '{proxy}' (expected host:port or socks5://host:port)"))
}

/// nfs3-rs `Connector` implementation that tunnels through a SOCKS5 proxy.
///
/// Implements the same connection interface as `TokioConnector` so it can be
/// passed to `Nfs3ConnectionBuilder`.  `connect_with_port` ignores the source
/// port request because the proxy controls the outbound port.
struct Socks5Connector {
    proxy_addr: SocketAddr,
}

impl Connector for Socks5Connector {
    type Connection = TokioIo<TcpStream>;

    async fn connect(&self, addr: SocketAddr) -> std::io::Result<Self::Connection> {
        let stream = socks5_connect(self.proxy_addr, addr).await?;
        Ok(TokioIo::new(stream))
    }

    async fn connect_with_port(&self, addr: SocketAddr, _local_port: u16) -> std::io::Result<Self::Connection> {
        // Source port control is not possible via SOCKS5; fall back to plain connect.
        tracing::debug!(%addr, "SOCKS5 proxy: ignoring privileged port request");
        self.connect(addr).await
    }
}

/// Connect to `addr` from a privileged source port (300-1023), falling back to ephemeral.
///
/// Most NFS servers require the client to bind from a port < 1024 (the `secure` export
/// option). This mirrors the mount-side logic in `proto::mount`.
///
/// `PermissionDenied` on the first attempt is treated as "cannot bind privileged ports at
/// all" (non-root, no CAP_NET_BIND_SERVICE) and falls back immediately rather than
/// firing 700+ SYNs against the target. `AddrInUse` and other transient errors advance
/// to the next port so a busy local machine does not lose the entire range.
async fn connect_privileged_nfs(addr: SocketAddr) -> std::io::Result<NfsIo> {
    for port in 300_u16..1024 {
        match TokioConnector.connect_with_port(addr, port).await {
            Ok(io) => return Ok(io),
            Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => {},
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                tracing::debug!(%addr, "no privilege to bind <1024, falling back to ephemeral");
                break;
            },
            Err(e) => {
                tracing::debug!(%addr, %e, "privileged port connect failed, trying next port");
            },
        }
    }
    tracing::warn!(%addr, "privileged NFS port binding failed, falling back to ephemeral port");
    TokioConnector.connect(addr).await
}

/// Construct a default `AuthSys` credential for anonymous access.
#[must_use]
pub fn nobody_cred() -> Credential {
    Credential::Sys(AuthSys::new(65534, 65534, "nfswolf"))
}
