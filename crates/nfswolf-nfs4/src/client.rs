//! NFSv4 COMPOUND client -- generic over [`RpcTransport`].
//!
//! One client works over a direct socket or a pooled, rate-limited, circuit-broken
//! transport -- the generic parameter decides the policy, while this module owns
//! the protocol.
//!
//! Only the stateless, read-only subset of NFSv4.0 is implemented. The stateful
//! half -- OPEN, CLOSE, LOCK, delegations, and v4.1 sessions -- is out of scope.
//! NFSv4.0 has no session state, so each COMPOUND is independent and pooling is
//! safe.

use nfswolf_rpc::RpcTransport;

use crate::wire::{ArgOp, AttrRequest, CompoundArgs, CompoundRes, NFS4_PROC_COMPOUND, NFS4_PROGRAM, NFS4_VERSION, Nfs4Status, ResOpData};

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// An NFSv4 operation failed.
///
/// Mirrors `Nfs2Error<E>` / `Nfs3Error`: the `Rpc` variant carries the
/// transport-level failure while `Status` and `MissingResult` capture
/// protocol-level failures that a successful RPC revealed.
#[derive(Debug)]
pub enum Nfs4Error<E> {
    /// The RPC call did not reach a protocol answer.
    Rpc(E),
    /// The COMPOUND returned a non-zero top-level status.
    ///
    /// Expected during credential probing -- must not trip the circuit breaker.
    Status(Nfs4Status),
    /// A required result op was missing or had an unexpected type.
    ///
    /// The server answered NFS4_OK but the expected result data (file handle,
    /// directory entries, read data) was absent from the response. This is a
    /// server bug or a wire-level mismatch, not a permissions issue.
    MissingResult,
}

impl<E: std::fmt::Display> std::fmt::Display for Nfs4Error<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Rpc(e) => e.fmt(f),
            Self::Status(s) => write!(f, "NFSv4 error: {s}"),
            Self::MissingResult => f.write_str("NFSv4: expected result op missing from COMPOUND response"),
        }
    }
}

impl<E: std::error::Error + 'static> std::error::Error for Nfs4Error<E> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Rpc(e) => Some(e),
            Self::Status(s) => Some(s),
            Self::MissingResult => None,
        }
    }
}

impl<E> From<E> for Nfs4Error<E> {
    fn from(e: E) -> Self {
        Self::Rpc(e)
    }
}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

/// Client for the NFSv4 service (program 100003, version 4).
///
/// Generic over the transport, so the same client works over a single socket
/// with no policy at all ([`DirectTransport`](nfswolf_rpc::DirectTransport)) or
/// over a pooled, circuit-broken, paced transport.
///
/// NFSv4 has no MOUNT protocol -- the pseudo-filesystem is reached from
/// PUTROOTFH. The client connects directly to the NFS port (default 2049).
///
/// All methods take `&self` (not `&mut self`) because `RpcTransport::call` is
/// `&self`, enabling `Arc`-sharing across tasks without a mutex.
#[derive(Debug)]
pub struct Nfs4Client<T> {
    transport: T,
}

impl<T: RpcTransport> Nfs4Client<T> {
    /// Wrap a transport.
    pub const fn new(transport: T) -> Self {
        Self { transport }
    }

    /// Borrow the underlying transport.
    pub const fn transport(&self) -> &T {
        &self.transport
    }

    /// Consume the client and return the transport.
    pub fn into_transport(self) -> T {
        self.transport
    }

    /// Send a COMPOUND containing `ops` and return the full response.
    ///
    /// Uses an empty tag and minorversion=0 (NFSv4.0). Returns the raw
    /// `CompoundRes` for the caller to interpret -- no status checking.
    pub async fn compound(&self, ops: Vec<ArgOp>) -> Result<CompoundRes, T::Error> {
        let args = CompoundArgs { tag: String::new(), minorversion: 0, ops };
        self.transport.call::<CompoundArgs, CompoundRes>(NFS4_PROGRAM, NFS4_VERSION, NFS4_PROC_COMPOUND, &args).await.inspect_err(|e| {
            tracing::debug!(error = %e, "NFSv4 COMPOUND failed");
        })
    }

    /// Retrieve the root file handle bytes via PUTROOTFH + GETFH.
    ///
    /// On success the returned bytes can be used in subsequent PUTFH operations
    /// to avoid re-issuing the PUTROOTFH chain on every call.
    pub async fn get_root_fh(&self) -> Result<Vec<u8>, Nfs4Error<T::Error>> {
        let res = self.compound(vec![ArgOp::Putrootfh, ArgOp::Getfh]).await?;
        check_status(res.status)?;
        match res.results.get(1).map(|op| &op.data) {
            Some(ResOpData::Fh(fh)) => Ok(fh.clone()),
            _ => Err(Nfs4Error::MissingResult),
        }
    }

    /// Navigate to `components` starting from root, return the resulting FH.
    ///
    /// For root (`"/"`) pass an empty slice.
    /// For `"/etc"` pass `&["etc"]`.
    /// For `"/etc/nfs"` pass `&["etc", "nfs"]`.
    pub async fn lookup_fh(&self, components: &[&str]) -> Result<Vec<u8>, Nfs4Error<T::Error>> {
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
        check_status(res.status)?;
        match res.results.last().map(|op| &op.data) {
            Some(ResOpData::Fh(fh)) => Ok(fh.clone()),
            _ => Err(Nfs4Error::MissingResult),
        }
    }

    /// Navigate to `components` starting from an arbitrary file handle.
    ///
    /// Like `lookup_fh` but uses PUTFH instead of PUTROOTFH, enabling
    /// relative path resolution from a known directory.
    pub async fn lookup_from_fh(&self, start_fh: &[u8], components: &[&str]) -> Result<Vec<u8>, Nfs4Error<T::Error>> {
        if components.is_empty() {
            return Ok(start_fh.to_vec());
        }
        let mut ops = Vec::with_capacity(components.len() + 2);
        ops.push(ArgOp::Putfh(start_fh.to_vec()));
        for &c in components {
            ops.push(ArgOp::Lookup(c.to_owned()));
        }
        ops.push(ArgOp::Getfh);
        let res = self.compound(ops).await?;
        check_status(res.status)?;
        match res.results.last().map(|op| &op.data) {
            Some(ResOpData::Fh(fh)) => Ok(fh.clone()),
            _ => Err(Nfs4Error::MissingResult),
        }
    }

    /// List directory entries for the directory at `dir_fh`.
    ///
    /// Returns entry names excluding `"."` and `".."`. Requests no inline
    /// attributes (`AttrRequest::empty`) to keep the response compact.
    ///
    /// NFSv4 READDIR is paginated (RFC 7530 S16.24): a directory larger than
    /// `maxcount` is returned across multiple calls, each ending with `eof=false`,
    /// and the client must resume from the last entry's cookie. This loops until
    /// `eof`, accumulating entries. The loop is bounded by `MAX_READDIR_ENTRIES`
    /// so a hostile server (untrusted-server hardening) that never sets `eof`
    /// cannot spin or exhaust memory.
    pub async fn list_dir(&self, dir_fh: &[u8]) -> Result<Vec<String>, Nfs4Error<T::Error>> {
        // Hard cap against a server that never signals eof.
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
            check_status(res.status)?;
            let (server_verf, entries, eof) = match res.results.get(1).map(|op| &op.data) {
                Some(ResOpData::Readdir { cookieverf, entries, eof }) => (*cookieverf, entries, *eof),
                _ => return Err(Nfs4Error::MissingResult),
            };
            // Echo the server's verifier on the next continuation call.
            cookieverf = u64::from_be_bytes(server_verf);
            // An empty page means no forward progress is possible (no cookie to
            // resume from); stop rather than re-issue the same request forever.
            let Some(last_cookie) = entries.last().map(|e| e.cookie) else {
                break;
            };
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
    /// Returns `(data, eof)`. The anonymous stateid (all zeros, RFC 7530 S9.1.4.3)
    /// allows reading without a prior OPEN call on most servers.
    pub async fn read_chunk(&self, file_fh: &[u8], offset: u64, count: u32) -> Result<(Vec<u8>, bool), Nfs4Error<T::Error>> {
        // Anonymous stateid: seqid=0, other=[0;12] (RFC 7530 S9.1.4.3).
        let stateid = [0u8; 16];
        let ops = vec![ArgOp::Putfh(file_fh.to_vec()), ArgOp::Read { stateid, offset, count }];
        let res = self.compound(ops).await?;
        check_status(res.status)?;
        match res.results.get(1).map(|op| &op.data) {
            Some(ResOpData::Read { eof, data }) => Ok((data.clone(), *eof)),
            _ => Err(Nfs4Error::MissingResult),
        }
    }
}

/// Translate a non-zero COMPOUND status into a typed error.
fn check_status<E>(status: u32) -> Result<(), Nfs4Error<E>> {
    if status == 0 { Ok(()) } else { Err(Nfs4Error::Status(Nfs4Status::from_u32(status))) }
}
