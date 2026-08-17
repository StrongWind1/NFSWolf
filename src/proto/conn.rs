//! NfsConnection  --  one pooled RPC session to an NFS server.
//!
//! One TCP session per (host, export, identity), carrying every NFS version's
//! calls. Adds AUTH_SYS stamp injection and health tracking on top of the
//! protocol crates, which have neither.
//!
//! When a SOCKS5 proxy is configured the session is tunnelled through it.

// Toolkit API  --  not all items are used in currently-implemented phases.
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use anyhow::Context as _;
use nfs_v3::wire::{GETATTR3args, Nfs3Result, nfs_fh3, nfsstat3};
use onc_rpc_client::rpc::RpcClient;
use onc_rpc_client::transport::net::Connector;
use onc_rpc_client::transport::tokio::{TokioConnector, TokioIo};
use onc_xdr::{Pack, Unpack, Void};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::proto::auth::Credential;

/// NFS RPC program number and NFSv3 version, from the protocol crate rather
/// than restated here (RFC 1813 sec. 3).
use nfs_v3::{PROGRAM as NFS_PROGRAM, VERSION as NFS_VERSION_3};

/// `NFSPROC3_GETATTR` -- procedure 1 (RFC 1813 sec. 3.3.1).
const NFSPROC3_GETATTR: u32 = 1;

/// `NFSPROC3_NULL` -- procedure 0 (RFC 1813 sec. 3.3.0).
///
/// Used for health checks because it touches no filesystem state and needs no
/// file handle, so it works whether or not the connection went through MOUNT.
const NFSPROC3_NULL: u32 = 0;

/// Conventional NFS port (IANA `nfsd`), used when the portmapper is
/// unreachable -- a filtered portmapper is common and not a reason to give up.
const NFS_DEFAULT_PORT: u16 = 2049;

/// Concrete IO type used for all NFS connections.
pub(crate) type NfsIo = TokioIo<TcpStream>;

/// Reconnection strategy for a pooled connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReconnectStrategy {
    /// Keep the TCP connection open across multiple RPC calls (standard).
    Persistent,
}

/// Health state of a pooled connection.
#[derive(Debug)]
pub(crate) struct ConnectionHealth {
    /// When this connection was established (tracked for pool age-out).
    pub _created_at: Instant,
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
        Self { _created_at: now, last_used: now, request_count: 0, poisoned: false }
    }
}

/// One pooled connection to an NFS server.
///
/// A single TCP session carrying RPC calls, plus whatever the MOUNT exchange
/// established about the export. Earlier revisions held two sockets -- one for
/// NFSv3 through a protocol-specific client and a second for raw RPC -- because
/// the client type baked its credential in at construction. Now that the
/// transport owns the credential, one socket serves every NFS version.
pub(crate) struct NfsConnection {
    /// The RPC session. Every call on this connection goes through it.
    rpc: RpcClient<NfsIo>,
    /// Export root handle from MOUNT, absent when the connection bypassed MOUNT.
    pub root: Option<Vec<u8>>,
    /// Auth flavors the server advertised for this export (stored for future ACL checks).
    pub _auth_flavors: Vec<u32>,
    /// Remote server address.
    pub addr: SocketAddr,
    /// Export path this connection was established for.
    pub export: String,
    /// Credential calls are issued under by default.
    pub credential: Credential,
    /// Reconnection behaviour (stored for pool management decisions).
    _reconnect: ReconnectStrategy,
    /// Health state for pool management.
    pub health: ConnectionHealth,
}

impl std::fmt::Debug for NfsConnection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NfsConnection").field("addr", &self.addr).field("export", &self.export).field("request_count", &self.health.request_count).field("poisoned", &self.health.poisoned).finish_non_exhaustive()
    }
}

impl NfsConnection {
    /// Establish a connection to `addr` and mount `export`.
    ///
    /// Resolves the NFS port through the portmapper, performs the MOUNT
    /// exchange to obtain the export's root handle and advertised auth flavors,
    /// then opens the RPC session subsequent calls ride on.
    ///
    /// Binds a privileged local port where possible: many servers enforce the
    /// `secure` export option and refuse calls from ports above 1023. A proxy
    /// controls its own outbound port, so that step is skipped when tunnelling.
    pub(crate) async fn connect(addr: SocketAddr, export: &str, credential: Credential, reconnect: ReconnectStrategy, proxy: Option<&str>) -> anyhow::Result<Self> {
        let mut mount = crate::proto::mount::NfsMountClient::default().with_credential(credential.clone());
        let mut portmap = crate::proto::portmap::PortmapClient::default_port();
        if let Some(p) = proxy {
            mount = mount.with_proxy(p.to_owned());
            portmap = portmap.with_proxy(p.to_owned());
        }
        let mounted = mount.mount(addr, export).await.with_context(|| format!("mount {export} on {addr}"))?;
        // A filtered portmapper is common and not a reason to give up, but
        // falling back silently means a server running nfsd off 2049 produces a
        // bare connect error with the real cause discarded. Say so.
        let nfs_port = match portmap.query_port(addr, NFS_PROGRAM, NFS_VERSION_3).await {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!(%addr, err = %e, port = NFS_DEFAULT_PORT, "portmapper did not answer for NFSv3; assuming the conventional port");
                NFS_DEFAULT_PORT
            },
        };
        let nfs_addr = SocketAddr::new(addr.ip(), nfs_port);

        let io = Self::open(nfs_addr, proxy).await.with_context(|| format!("NFS connect to {nfs_addr}"))?;
        let rpc = RpcClient::new_with_auth(io, credential.to_opaque_auth(), onc_rpc_client::rpc::opaque_auth::default());

        Ok(Self { rpc, root: Some(mounted.handle.as_bytes().to_vec()), _auth_flavors: mounted.auth_flavors, addr, export: export.to_owned(), credential, _reconnect: reconnect, health: ConnectionHealth::new() })
    }

    /// Establish a connection straight to the NFS port, bypassing MOUNT.
    ///
    /// Used with `--handle`, where the caller already holds a file handle and
    /// the portmapper or mountd may be filtered. No root handle is recorded
    /// because none was obtained, so health checks use `NULL` rather than a
    /// `GETATTR` against a handle that does not exist.
    pub(crate) async fn connect_direct(addr: SocketAddr, nfs_port: u16, credential: Credential, reconnect: ReconnectStrategy, proxy: Option<&str>) -> anyhow::Result<Self> {
        let nfs_addr = SocketAddr::new(addr.ip(), nfs_port);
        let io = Self::open(nfs_addr, proxy).await.with_context(|| format!("direct NFS connect to {nfs_addr}"))?;
        let rpc = RpcClient::new_with_auth(io, credential.to_opaque_auth(), onc_rpc_client::rpc::opaque_auth::default());

        // Nothing was advertised; assume AUTH_SYS, which is what a raw handle is
        // being used with in the first place.
        Ok(Self { rpc, root: None, _auth_flavors: vec![1], addr, export: format!("__direct__{nfs_port}"), credential, _reconnect: reconnect, health: ConnectionHealth::new() })
    }

    /// Open a TCP session to `target`, through the proxy when one is configured.
    async fn open(target: SocketAddr, proxy: Option<&str>) -> anyhow::Result<NfsIo> {
        if let Some(p) = proxy {
            let proxy_addr = parse_proxy_addr(p)?;
            let stream = socks5_connect(proxy_addr, target).await?;
            Ok(TokioIo::new(stream))
        } else {
            Ok(connect_privileged_nfs(target).await?)
        }
    }

    /// Issue one RPC call on this connection.
    ///
    /// Re-encodes the credential per call so each carries a fresh AUTH_SYS
    /// stamp (RFC 1057 sec. 9.2); a repeated stamp lets a server answer from its
    /// duplicate-request cache, which silently corrupts a UID sweep.
    pub(crate) async fn call<C, R>(&mut self, program: u32, version: u32, proc: u32, args: &C) -> Result<R, onc_rpc_client::RpcError>
    where
        C: Pack + Send + Sync,
        R: Unpack,
    {
        self.health.request_count = self.health.request_count.saturating_add(1);
        self.health.last_used = Instant::now();
        self.rpc.credential = self.credential.to_opaque_auth();
        self.rpc.call::<C, R>(program, version, proc, args).await
    }

    /// Issue one call under `cred`, restoring this connection's own credential
    /// afterwards so the next pool user is not left carrying a borrowed identity.
    pub(crate) async fn call_as<C, R>(&mut self, cred: onc_rpc_client::rpc::opaque_auth<'static>, program: u32, version: u32, proc: u32, args: &C) -> Result<R, onc_rpc_client::RpcError>
    where
        C: Pack + Send + Sync,
        R: Unpack,
    {
        self.health.request_count = self.health.request_count.saturating_add(1);
        self.health.last_used = Instant::now();
        self.rpc.credential = cred;
        let result = self.rpc.call::<C, R>(program, version, proc, args).await;
        self.rpc.credential = self.credential.to_opaque_auth();
        result
    }

    /// Probe whether this connection is still usable.
    ///
    /// Where a root handle is available, `GETATTR` against it is used rather
    /// than `NULL`. `NULL` is answered before any export check, so it stays
    /// healthy across an `exportfs` reload that has invalidated the mount --
    /// the connection would be handed back and the next real call would fail
    /// with `NFS3ERR_STALE`, which arrives inside a successful RPC and so never
    /// reaches the pool's health logic. `GETATTR` catches that here instead.
    ///
    /// A permission denial still means alive: the server processed the call.
    ///
    /// Connections that bypassed MOUNT have no root handle, so they fall back
    /// to `NULL`.
    pub(crate) async fn health_check(&mut self) -> bool {
        let Some(root) = self.root.clone() else {
            return self.call::<Void, Void>(NFS_PROGRAM, NFS_VERSION_3, NFSPROC3_NULL, &Void).await.is_ok();
        };
        let args = GETATTR3args { object: nfs_fh3 { data: onc_xdr::Opaque::owned(root) } };
        match self.call::<_, nfs_v3::wire::GETATTR3res>(NFS_PROGRAM, NFS_VERSION_3, NFSPROC3_GETATTR, &args).await {
            Ok(Nfs3Result::Ok(_)) => true,
            Ok(Nfs3Result::Err((status, _))) => matches!(status, nfsstat3::NFS3ERR_ACCES | nfsstat3::NFS3ERR_PERM),
            Ok(_) | Err(_) => false,
        }
    }

    /// Mark this connection unusable so the pool discards rather than requeues it.
    pub(crate) const fn poison(&mut self) {
        self.health.poisoned = true;
    }

    /// Whether this connection has been idle longer than `threshold`.
    pub(crate) fn is_stale(&self, threshold: Duration) -> bool {
        self.health.last_used.elapsed() > threshold
    }

    /// Replace the credential used for subsequent calls.
    pub(crate) fn update_credential(&mut self, credential: Credential) {
        self.credential = credential;
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
/// 4. Reply: [VER, REP=0(success), RSV, ATYP, BND.ADDR(var), BND.PORT(2)]
///
/// The reply's bound address is variable-length keyed on its ATYP byte
/// (IPv4/IPv6/domain, RFC 1928 S5), so it is parsed rather than assumed IPv4.
/// IPv6 targets are not supported (NFS servers are typically IPv4).
pub(crate) async fn socks5_connect(proxy_addr: SocketAddr, target: SocketAddr) -> std::io::Result<TcpStream> {
    let mut stream = TcpStream::connect(proxy_addr).await?;

    // Step 1: greeting  --  offer NO_AUTH (method 0x00).
    stream.write_all(&[0x05, 0x01, 0x00]).await?;

    // Step 2: method selection response.
    let mut method_resp = [0u8; 2];
    _ = stream.read_exact(&mut method_resp).await?;
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

    // Step 4: CONNECT reply  --  [VER, REP, RSV, ATYP, BND.ADDR(var), BND.PORT(2)]
    // (RFC 1928 S6). The bound-address length depends on ATYP, so read the fixed
    // 4-byte head first, then consume exactly the address+port the type implies.
    let mut head = [0u8; 4];
    _ = stream.read_exact(&mut head).await?;
    if head[1] != 0x00 {
        return Err(std::io::Error::other(format!("SOCKS5 CONNECT failed (REP=0x{:02x})", head[1])));
    }
    // RFC 1928 S5: ATYP 0x01=IPv4 (4), 0x04=IPv6 (16), 0x03=domain (1+len); all
    // followed by a 2-byte port. read_exact returns an error (not a panic) on a
    // short or hostile reply.
    let bnd_len = match head[3] {
        0x01 => 4 + 2,
        0x04 => 16 + 2,
        0x03 => {
            let mut len = [0u8; 1];
            _ = stream.read_exact(&mut len).await?;
            usize::from(len[0]) + 2
        },
        atyp => return Err(std::io::Error::other(format!("SOCKS5 CONNECT reply has unsupported ATYP=0x{atyp:02x}"))),
    };
    let mut bnd = vec![0u8; bnd_len];
    _ = stream.read_exact(&mut bnd).await?;

    Ok(stream)
}

/// Parse a proxy string of the form `host:port` or `socks5://host:port`.
pub(crate) fn parse_proxy_addr(proxy: &str) -> anyhow::Result<SocketAddr> {
    let stripped = proxy.strip_prefix("socks5://").unwrap_or(proxy);
    stripped.parse::<SocketAddr>().with_context(|| format!("invalid proxy address '{proxy}' (expected host:port or socks5://host:port)"))
}

/// Connect to `addr` from a privileged source port (300-1023), falling back to ephemeral.
///
/// Most NFS servers require the client to bind from a port < 1024 (the `secure` export
/// option). This mirrors the mount-side logic in `proto::mount`.
///
/// `PermissionDenied` on the first attempt is treated as "cannot bind privileged ports at
/// all" (non-root, no CAP_NET_BIND_SERVICE) and falls back immediately rather than
/// firing 700+ SYNs against the target. `AddrInUse` is a local source-port conflict and
/// advances to the next port so a busy local machine does not lose the entire range.
/// Any other error is a destination-side condition (`ConnectionRefused`/`TimedOut`/
/// unreachable) that is identical for every source port, so the loop breaks and falls
/// through to the single ephemeral attempt instead of retrying all ~724 ports against an
/// unreachable host.
async fn connect_privileged_nfs(addr: SocketAddr) -> std::io::Result<NfsIo> {
    // Retry up to 3 times with a brief sleep between sweeps. Under heavy
    // use all 724 privileged ports (300-1023) can land in TIME_WAIT; a
    // short pause lets the kernel recycle them (tcp_tw_reuse / fin_timeout).
    for attempt in 0..3u8 {
        if attempt > 0 {
            tracing::debug!(%addr, attempt, "privileged ports exhausted, waiting for TIME_WAIT recycle");
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
        for port in 300_u16..1024 {
            match TokioConnector.connect_with_port(addr, port).await {
                Ok(io) => return Ok(io),
                Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => {},
                Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                    tracing::debug!(%addr, "no privilege to bind <1024, falling back to ephemeral");
                    return TokioConnector.connect(addr).await;
                },
                Err(e) => {
                    // Destination-side failure (refused / timed out / unreachable):
                    // same outcome awaits every other source port, stop immediately.
                    tracing::debug!(%addr, %e, "destination connect failed, not retrying other source ports");
                    return TokioConnector.connect(addr).await;
                },
            }
        }
    }
    tracing::warn!(%addr, "privileged NFS port binding failed after retries, falling back to ephemeral port");
    TokioConnector.connect(addr).await
}
