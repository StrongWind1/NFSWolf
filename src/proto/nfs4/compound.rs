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
use crate::proto::nfs4::PseudoFsEntry;
use crate::proto::nfs4::types::{ArgOp, AttrRequest, CompoundArgs, CompoundRes, NFS4_PROC_COMPOUND, NFS4_PROGRAM, NFS4_VERSION, ResOpData};
use crate::proto::pool::{ConnectionPool, PoolKey};
use crate::util::stealth::StealthConfig;

/// NFSv4 client backed by the shared connection pool.
///
/// All calls are issued as NFSv4 COMPOUND RPCs (the only non-NULL NFSv4 procedure).
/// This is stateless in the v4.0 sense  --  no clientid or sessions are managed here.
pub struct Nfs4Client {
    pool: Arc<ConnectionPool>,
    pool_key: PoolKey,
    credential: Credential,
    /// Timing profile applied before every COMPOUND (Critical Design Rule 10).
    stealth: StealthConfig,
}

impl std::fmt::Debug for Nfs4Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Nfs4Client").field("pool_key", &self.pool_key).finish_non_exhaustive()
    }
}

impl Nfs4Client {
    /// Create a new NFSv4 client that draws connections from `pool`.
    ///
    /// Stealth defaults to off; chain `with_stealth` to honor `--delay`/`--jitter`.
    #[must_use]
    pub const fn new(pool: Arc<ConnectionPool>, pool_key: PoolKey, credential: Credential) -> Self {
        Self { pool, pool_key, credential, stealth: StealthConfig::none() }
    }

    /// Attach a stealth profile so each COMPOUND honors the configured pacing.
    ///
    /// Additive builder: `new` keeps its signature so existing call sites are
    /// unaffected; callers with a configured `StealthConfig` chain this.
    #[must_use]
    pub const fn with_stealth(mut self, stealth: StealthConfig) -> Self {
        self.stealth = stealth;
        self
    }

    /// Send a COMPOUND containing `ops` and return the full response.
    ///
    /// Uses an empty tag and minorversion=0 (NFSv4.0).
    pub async fn compound(&self, ops: Vec<ArgOp>) -> anyhow::Result<CompoundRes> {
        // Pace v4 traffic like the v2/v3 clients (Critical Design Rule 10).
        self.stealth.wait().await;
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
        // Identify the pseudo-root from the decoded root fsid, not the echoed
        // request tag (which is always our own empty tag, so the old check was
        // unconditionally true). Linux knfsd presents the NFSv4 pseudo-root (the
        // `fsid=0` root export, exports(5)) with an all-zero fsid4; a real export
        // at the root reports a non-zero, device-derived fsid (RFC 7530 S7.3
        // pseudo-file system; S5.8.1.9 fsid). We claim pseudo-root only on
        // positive evidence (decoded fsid == 0/0); an undecodable fsid yields no
        // pseudo-root claim rather than a false positive.
        let fsid = res.results.iter().find_map(|op| if let ResOpData::Getattr { fsid } = &op.data { *fsid } else { None });
        let is_pseudo_root = fsid == Some((0, 0));
        let entry = PseudoFsEntry {
            path: "/".to_owned(),
            fsid: fsid.unwrap_or((0, 0)),
            is_pseudo_root,
            // auth_methods are populated by a separate secinfo() call.
            auth_methods: Vec::new(),
            // A non-pseudo root whose fsid we decoded is itself an export
            // boundary; with no decoded fsid we assert no boundary.
            is_export_boundary: fsid.is_some() && !is_pseudo_root,
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
    proxy: Option<String>,
    /// Timing profile applied before every COMPOUND (Critical Design Rule 10).
    stealth: StealthConfig,
    /// Auxiliary GIDs (RFC 5531 S14) carried in the AUTH_SYS credential, kept so
    /// a mid-session `uid`/`gid`/`hostname` reconnect preserves the operator's
    /// `--aux-gids` (the shadow-GID trick) instead of dropping them.
    aux_gids: Vec<u32>,
}

/// Build the AUTH_SYS GID list: primary `gid` first, then `aux_gids` (deduped).
///
/// Mirrors `cli::probe::build_gid_list`; duplicated here to keep the proto layer
/// free of a dependency on the CLI layer.
fn merge_gids(gid: u32, aux_gids: &[u32]) -> Vec<u32> {
    let mut gids = vec![gid];
    for &g in aux_gids {
        if !gids.contains(&g) {
            gids.push(g);
        }
    }
    gids
}

impl std::fmt::Debug for Nfs4DirectClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Nfs4DirectClient").field("addr", &self.addr).finish_non_exhaustive()
    }
}

impl Nfs4DirectClient {
    /// Open a TCP connection, tunnelling through a SOCKS5 proxy when configured.
    async fn connect_tcp(addr: SocketAddr, proxy: Option<&str>) -> anyhow::Result<TokioIo<TcpStream>> {
        if let Some(p) = proxy {
            let proxy_addr = crate::proto::conn::parse_proxy_addr(p)?;
            let stream = crate::proto::conn::socks5_connect(proxy_addr, addr).await.with_context(|| format!("SOCKS5 connect to {addr} via {p}"))?;
            Ok(TokioIo::new(stream))
        } else {
            TokioConnector.connect(addr).await.with_context(|| format!("NFSv4 TCP connect to {addr}"))
        }
    }

    /// Connect directly to the NFS port on `addr` without MOUNT, using AUTH_NONE.
    ///
    /// Suitable for anonymous probes (scanner, analyzer).  For interactive shell
    /// use `connect_with_auth` so UID/GID/hostname are sent in every COMPOUND.
    pub async fn connect(addr: SocketAddr) -> anyhow::Result<Self> {
        Self::connect_proxy(addr, None).await
    }

    /// Connect via an optional SOCKS5 proxy, using AUTH_NONE.
    pub async fn connect_proxy(addr: SocketAddr, proxy: Option<&str>) -> anyhow::Result<Self> {
        let null_auth = nfs3_types::rpc::opaque_auth::default();
        let io = Self::connect_tcp(addr, proxy).await?;
        let rpc = RpcClient::new_with_auth(io, null_auth.clone(), null_auth);
        Ok(Self { rpc, addr, proxy: proxy.map(String::from), stealth: StealthConfig::none(), aux_gids: Vec::new() })
    }

    /// Connect with an AUTH_SYS credential (`uid`, `gid`, `hostname`).
    ///
    /// The credential is injected into every COMPOUND call via the standard
    /// AUTH_SYS opaque_auth structure (RFC 5531 S14 / RFC 2623 S2.1).
    /// The server cannot verify these claims, so any values can be spoofed.
    pub async fn connect_with_auth(addr: SocketAddr, uid: u32, gid: u32, hostname: &str) -> anyhow::Result<Self> {
        Self::connect_with_auth_proxy(addr, uid, gid, hostname, None).await
    }

    /// Connect with AUTH_SYS via an optional SOCKS5 proxy.
    pub async fn connect_with_auth_proxy(addr: SocketAddr, uid: u32, gid: u32, hostname: &str, proxy: Option<&str>) -> anyhow::Result<Self> {
        use crate::proto::auth::AuthSys;
        let opaque = AuthSys::new(uid, gid, hostname).to_opaque_auth();
        let io = Self::connect_tcp(addr, proxy).await?;
        let rpc = RpcClient::new_with_auth(io, opaque, nfs3_types::rpc::opaque_auth::default());
        Ok(Self { rpc, addr, proxy: proxy.map(String::from), stealth: StealthConfig::none(), aux_gids: Vec::new() })
    }

    /// Connect with AUTH_SYS carrying auxiliary GIDs, via an optional SOCKS5 proxy.
    ///
    /// Like `connect_with_auth_proxy` but sends up to 16 supplementary GIDs
    /// (RFC 5531 S14), so the v4 shell can use the shadow-GID trick the same way
    /// the v3 shell does (e.g. `--aux-gids 42` to read /etc/shadow without
    /// no_root_squash). `aux_gids` are the auxiliary groups only; the primary
    /// `gid` is prepended automatically and the set is retained for reconnects.
    pub async fn connect_with_groups_proxy(addr: SocketAddr, uid: u32, gid: u32, aux_gids: &[u32], hostname: &str, proxy: Option<&str>) -> anyhow::Result<Self> {
        use crate::proto::auth::AuthSys;
        let gids = merge_gids(gid, aux_gids);
        let opaque = AuthSys::with_groups(uid, gid, &gids, hostname).to_opaque_auth();
        let io = Self::connect_tcp(addr, proxy).await?;
        let rpc = RpcClient::new_with_auth(io, opaque, nfs3_types::rpc::opaque_auth::default());
        Ok(Self { rpc, addr, proxy: proxy.map(String::from), stealth: StealthConfig::none(), aux_gids: aux_gids.to_vec() })
    }

    /// Attach a stealth profile so each COMPOUND honors the configured pacing.
    ///
    /// Additive builder: the `connect*` constructors keep their signatures (used
    /// by the scanner, analyzer, and v4 shell) and default to no stealth;
    /// callers with a configured `StealthConfig` chain this after connecting.
    #[must_use]
    pub const fn with_stealth(mut self, stealth: StealthConfig) -> Self {
        self.stealth = stealth;
        self
    }

    /// Rebuild the RPC credential and reconnect the underlying TCP socket.
    ///
    /// Called by the interactive NFSv4 shell when the operator runs `uid`,
    /// `gid`, or `hostname` commands mid-session.  A full reconnect is required
    /// because `RpcClient` owns the IO and does not expose a credential setter.
    /// The retained `aux_gids` are re-applied (with the possibly-changed primary
    /// `gid`) so the shadow-GID trick survives a mid-session identity change.
    pub async fn reconnect_with_auth(&mut self, uid: u32, gid: u32, hostname: &str) -> anyhow::Result<()> {
        use crate::proto::auth::AuthSys;
        let gids = merge_gids(gid, &self.aux_gids);
        let opaque = AuthSys::with_groups(uid, gid, &gids, hostname).to_opaque_auth();
        let io = Self::connect_tcp(self.addr, self.proxy.as_deref()).await?;
        self.rpc = RpcClient::new_with_auth(io, opaque, nfs3_types::rpc::opaque_auth::default());
        Ok(())
    }

    /// Send a COMPOUND containing `ops` and return the full response.
    ///
    /// Uses an empty tag and minorversion=0 (NFSv4.0).
    pub async fn compound(&mut self, ops: Vec<ArgOp>) -> anyhow::Result<CompoundRes> {
        // Pace v4 traffic like the v2/v3 clients (Critical Design Rule 10).
        self.stealth.wait().await;
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
    /// attributes (`AttrRequest::empty`) to keep the response compact.
    ///
    /// NFSv4 READDIR is paginated (RFC 7530 S16.24): a directory larger than
    /// `maxcount` is returned across multiple calls, each ending with `eof=false`,
    /// and the client must resume from the last entry's cookie. This loops until
    /// `eof`, accumulating entries; a single READDIR would silently truncate large
    /// directories (the v4 `ls` feeds export/file enumeration). The loop is bounded
    /// by `MAX_READDIR_ENTRIES` so a hostile server (CLAUDE.md threat model) that
    /// never sets `eof` cannot spin or exhaust memory -- the same defence the v3
    /// shell's `try_readdirplus` paging uses.
    ///
    /// Known limitation: RFC 7530 S16.24 also requires echoing the server's
    /// `cookieverf` on each continuation, but the READDIR decoder currently
    /// discards the verifier (`ResOpData::Readdir` carries no cookieverf), so this
    /// resumes with `cookieverf=0`. Servers that strictly validate the verifier
    /// (returning NFS4ERR_NOT_SAME / NFS4ERR_BAD_COOKIE) will error on continuation
    /// rather than truncate; fully correct pagination requires surfacing the
    /// cookieverf from the decoder in `proto::nfs4::types` (cross-module change).
    pub async fn list_dir(&mut self, dir_fh: &[u8]) -> anyhow::Result<Vec<String>> {
        // Hard cap against a server that never signals eof (untrusted-server
        // hardening; mirrors the v3 shell readdir cap).
        const MAX_READDIR_ENTRIES: usize = 1_000_000;
        let mut names = Vec::new();
        // Bound on RAW entries seen (not the filtered `names`): a hostile server
        // can return non-empty pages whose entries are all "." / ".." with a
        // cycling cookie, which would never grow `names` and never break.
        let mut raw_seen: usize = 0;
        let mut cookie: u64 = 0;
        loop {
            // cookieverf=0: the first call requires it, and the decoder does not yet
            // surface the server's verifier for continuation (see method note).
            let ops = vec![ArgOp::Putfh(dir_fh.to_vec()), ArgOp::Readdir { cookie, cookieverf: 0, dircount: 4096, maxcount: 65536, attr_request: AttrRequest::empty() }];
            let res = self.compound(ops).await?;
            anyhow::ensure!(res.status == 0, "READDIR failed: NFSv4 status={}", res.status);
            let (entries, eof) = match res.results.get(1).map(|op| &op.data) {
                Some(ResOpData::Readdir { entries, eof }) => (entries, *eof),
                _ => anyhow::bail!("READDIR result missing or wrong type"),
            };
            // An empty page means no forward progress is possible (no cookie to
            // resume from); stop rather than re-issue the same request forever.
            let Some(last_cookie) = entries.last().map(|e| e.cookie) else { break };
            raw_seen = raw_seen.saturating_add(entries.len());
            for e in entries {
                if e.name != "." && e.name != ".." {
                    names.push(e.name.clone());
                }
            }
            if eof {
                break;
            }
            if raw_seen >= MAX_READDIR_ENTRIES {
                tracing::warn!(count = raw_seen, "NFSv4 READDIR hit entry cap; directory listing truncated");
                break;
            }
            // Resume from the last entry's cookie. If it did not advance, stop to
            // avoid an infinite loop on a misbehaving server.
            if last_cookie == cookie {
                break;
            }
            cookie = last_cookie;
        }
        Ok(names)
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
/// When `proxy` is `Some`, the TCP connection is tunnelled through SOCKS5.
pub async fn probe_nfs4(ip: IpAddr, probe_timeout: Duration, proxy: Option<&str>) -> bool {
    let addr = SocketAddr::new(ip, 2049);
    let connect = tokio::time::timeout(probe_timeout, Nfs4DirectClient::connect_proxy(addr, proxy)).await;
    let Ok(Ok(mut client)) = connect else { return false };
    let result = tokio::time::timeout(probe_timeout, client.compound(vec![ArgOp::Putrootfh])).await;
    matches!(result, Ok(Ok(res)) if res.status == 0)
}
