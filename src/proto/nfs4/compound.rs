//! NFSv4 COMPOUND client  --  sends batched operation sequences.
//!
//! Each method builds an op sequence, sends a single COMPOUND RPC, and returns
//! the raw `CompoundRes` for the caller to interpret.
//!
//! `Nfs4DirectClient` holds one raw TCP connection to port 2049 and speaks no
//! MOUNT protocol, because NFSv4 has none -- the export tree is reached from
//! PUTROOTFH instead.

use std::net::SocketAddr;

use anyhow::Context as _;
use onc_rpc_client::rpc::RpcClient;
use onc_rpc_client::transport::net::Connector as _;
use onc_rpc_client::transport::tokio::{TokioConnector, TokioIo};
use tokio::net::TcpStream;

use crate::proto::nfs4::types::{ArgOp, AttrRequest, CompoundArgs, CompoundBuilder, CompoundRes, NFS4_PROC_COMPOUND, NFS4_PROGRAM, NFS4_VERSION, ResOpData, Stateid4};
use crate::util::stealth::StealthConfig;

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
pub(crate) struct Nfs4DirectClient {
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

    /// Connect via an optional SOCKS5 proxy, using AUTH_NONE.
    pub(crate) async fn connect_proxy(addr: SocketAddr, proxy: Option<&str>) -> anyhow::Result<Self> {
        let null_auth = onc_rpc_client::rpc::opaque_auth::default();
        let io = Self::connect_tcp(addr, proxy).await?;
        let rpc = RpcClient::new_with_auth(io, null_auth.clone(), null_auth);
        Ok(Self { rpc, addr, proxy: proxy.map(String::from), stealth: StealthConfig::none(), aux_gids: Vec::new() })
    }

    /// Connect with AUTH_SYS via an optional SOCKS5 proxy.
    pub(crate) async fn connect_with_auth_proxy(addr: SocketAddr, uid: u32, gid: u32, hostname: &str, proxy: Option<&str>) -> anyhow::Result<Self> {
        use crate::proto::auth::AuthSys;
        let opaque = AuthSys::new(uid, gid, hostname).to_opaque_auth(crate::proto::auth::next_stamp());
        let io = Self::connect_tcp(addr, proxy).await?;
        let rpc = RpcClient::new_with_auth(io, opaque, onc_rpc_client::rpc::opaque_auth::default());
        Ok(Self { rpc, addr, proxy: proxy.map(String::from), stealth: StealthConfig::none(), aux_gids: Vec::new() })
    }

    /// Connect with AUTH_SYS carrying auxiliary GIDs, via an optional SOCKS5 proxy.
    ///
    /// Like `connect_with_auth_proxy` but sends up to 16 supplementary GIDs
    /// (RFC 5531 S14), so the v4 shell can use the shadow-GID trick the same way
    /// the v3 shell does (e.g. `--aux-gids 42` to read /etc/shadow without
    /// no_root_squash). `aux_gids` are the auxiliary groups only; the primary
    /// `gid` is prepended automatically and the set is retained for reconnects.
    #[expect(dead_code, reason = "v4 shell with aux-GID support not yet wired up")]
    pub(crate) async fn connect_with_groups_proxy(addr: SocketAddr, uid: u32, gid: u32, aux_gids: &[u32], hostname: &str, proxy: Option<&str>) -> anyhow::Result<Self> {
        use crate::proto::auth::AuthSys;
        let gids = aux_gids.to_vec();
        let opaque = AuthSys::with_groups(uid, gid, &gids, hostname).to_opaque_auth(crate::proto::auth::next_stamp());
        let io = Self::connect_tcp(addr, proxy).await?;
        let rpc = RpcClient::new_with_auth(io, opaque, onc_rpc_client::rpc::opaque_auth::default());
        Ok(Self { rpc, addr, proxy: proxy.map(String::from), stealth: StealthConfig::none(), aux_gids: aux_gids.to_vec() })
    }

    /// Attach a stealth profile so each COMPOUND honors the configured pacing.
    ///
    /// Additive builder: the `connect*` constructors keep their signatures (used
    /// by the scanner, analyzer, and v4 shell) and default to no stealth;
    /// callers with a configured `StealthConfig` chain this after connecting.
    #[must_use]
    pub(crate) const fn with_stealth(mut self, stealth: StealthConfig) -> Self {
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
    #[expect(dead_code, reason = "v4 shell identity-change path not yet wired up")]
    pub(crate) async fn reconnect_with_auth(&mut self, uid: u32, gid: u32, hostname: &str) -> anyhow::Result<()> {
        use crate::proto::auth::AuthSys;
        let opaque = AuthSys::with_groups(uid, gid, &self.aux_gids, hostname).to_opaque_auth(crate::proto::auth::next_stamp());
        let io = Self::connect_tcp(self.addr, self.proxy.as_deref()).await?;
        self.rpc = RpcClient::new_with_auth(io, opaque, onc_rpc_client::rpc::opaque_auth::default());
        Ok(())
    }

    /// Send a COMPOUND containing `ops` and return the full response.
    ///
    /// Uses an empty tag and minorversion=0 (NFSv4.0).
    pub(crate) async fn compound(&mut self, ops: Vec<ArgOp>) -> anyhow::Result<CompoundRes> {
        // Pace v4 traffic like the v2/v3 clients (Critical Design Rule 10).
        self.stealth.wait().await;
        let args = CompoundArgs { tag: String::new(), minorversion: 0, ops };
        self.rpc.call::<CompoundArgs, CompoundRes>(NFS4_PROGRAM, NFS4_VERSION, NFS4_PROC_COMPOUND, &args).await.context("NFSv4 COMPOUND")
    }

    /// Send a COMPOUND with minorversion=1 (NFSv4.1).
    ///
    /// EXCHANGE_ID (op 42, RFC 5661 S18.35) and other v4.1 operations require
    /// minorversion=1 in the COMPOUND tag; v4.0-only servers reject them with
    /// NFS4ERR_MINOR_VERS_MISMATCH or NFS4ERR_OP_ILLEGAL.
    pub(crate) async fn compound_v41(&mut self, ops: Vec<ArgOp>) -> anyhow::Result<CompoundRes> {
        self.stealth.wait().await;
        let args = CompoundArgs { tag: String::new(), minorversion: 1, ops };
        self.rpc.call::<CompoundArgs, CompoundRes>(NFS4_PROGRAM, NFS4_VERSION, NFS4_PROC_COMPOUND, &args).await.context("NFSv4.1 COMPOUND")
    }

    /// Retrieve the root file handle bytes via PUTROOTFH + GETFH.
    ///
    /// On success, the returned bytes can be used in subsequent PUTFH operations
    /// to avoid re-issuing the PUTROOTFH + LOOKUP chain on every call.
    pub(crate) async fn get_root_fh(&mut self) -> anyhow::Result<Vec<u8>> {
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
    pub(crate) async fn lookup_fh(&mut self, components: &[&str]) -> anyhow::Result<Vec<u8>> {
        if components.is_empty() {
            return self.get_root_fh().await;
        }
        let mut b = CompoundBuilder::new().putrootfh();
        for &c in components {
            b = b.lookup(c);
        }
        let res = self.compound(b.getfh().build()).await?;
        anyhow::ensure!(res.status == 0, "LOOKUP failed: NFSv4 status={}", res.status);
        match res.results.last().map(|op| &op.data) {
            Some(ResOpData::Fh(fh)) => Ok(fh.clone()),
            _ => anyhow::bail!("GETFH result missing after LOOKUP chain"),
        }
    }

    /// Navigate to `components` starting from an arbitrary file handle.
    ///
    /// Like `lookup_fh` but uses PUTFH instead of PUTROOTFH, enabling
    /// relative path resolution from the current working directory.
    #[expect(dead_code, reason = "used by escape --all v4 seed acquisition when Nfs4DirectClient is chosen over PooledTransport")]
    pub(crate) async fn lookup_from_fh(&mut self, start_fh: &[u8], components: &[&str]) -> anyhow::Result<Vec<u8>> {
        if components.is_empty() {
            return Ok(start_fh.to_vec());
        }
        let mut b = CompoundBuilder::new().putfh(start_fh.to_vec());
        for &c in components {
            b = b.lookup(c);
        }
        let res = self.compound(b.getfh().build()).await?;
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
    pub(crate) async fn list_dir(&mut self, dir_fh: &[u8]) -> anyhow::Result<Vec<String>> {
        // Hard cap against a server that never signals eof (untrusted-server
        // hardening; mirrors the v3 shell readdir cap).
        const MAX_READDIR_ENTRIES: usize = 1_000_000;
        let mut names = Vec::new();
        // Bound on RAW entries seen (not the filtered `names`): a hostile server
        // can return non-empty pages whose entries are all "." / ".." with a
        // cycling cookie, which would never grow `names` and never break.
        let mut raw_seen: usize = 0;
        let mut cookie: u64 = 0;
        // RFC 7530 S16.24: first call sends cookieverf=0; subsequent calls echo
        // the server's verifier so it can detect directory mutations between pages.
        let mut cookieverf: u64 = 0;
        loop {
            let ops = vec![ArgOp::Putfh(dir_fh.to_vec()), ArgOp::Readdir { cookie, cookieverf, dircount: 4096, maxcount: 65536, attr_request: AttrRequest::empty() }];
            let res = self.compound(ops).await?;
            anyhow::ensure!(res.status == 0, "READDIR failed: NFSv4 status={}", res.status);
            let (server_verf, entries, eof) = match res.results.get(1).map(|op| &op.data) {
                Some(ResOpData::Readdir { cookieverf, entries, eof }) => (*cookieverf, entries, *eof),
                _ => anyhow::bail!("READDIR result missing or wrong type"),
            };
            // Echo the server's verifier on the next continuation call.
            cookieverf = u64::from_be_bytes(server_verf);
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
    #[expect(dead_code, reason = "v4 shell READ path not yet wired up")]
    pub(crate) async fn read_chunk(&mut self, file_fh: &[u8], offset: u64, count: u32) -> anyhow::Result<(Vec<u8>, bool)> {
        let ops = vec![ArgOp::Putfh(file_fh.to_vec()), ArgOp::Read { stateid: Stateid4::ANONYMOUS.to_bytes(), offset, count }];
        let res = self.compound(ops).await?;
        anyhow::ensure!(res.status == 0, "READ failed: NFSv4 status={}", res.status);
        match res.results.get(1).map(|op| &op.data) {
            Some(ResOpData::Read { eof, data }) => Ok((data.clone(), *eof)),
            _ => anyhow::bail!("READ result missing or wrong type"),
        }
    }
}
