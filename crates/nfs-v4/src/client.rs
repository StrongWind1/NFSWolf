//! NFSv4 COMPOUND client -- generic over [`RpcTransport`].
//!
//! One client works over a direct socket or a pooled, rate-limited, circuit-broken
//! transport -- the generic parameter decides the policy, while this module owns
//! the protocol.
//!
//! Both stateless operations (LOOKUP, GETATTR, READDIR, anonymous READ) and
//! stateful operations (SETCLIENTID, OPEN, CLOSE, stateid-bearing READ/WRITE,
//! RENEW) are implemented. The stateful path uses [`Nfs4Session`] for client
//! identity and [`OpenState`] for per-file open state tracking.

use onc_rpc_client::RpcTransport;

use crate::session::Nfs4Session;
use crate::state::{LockRange, LockState, OpenState};
use crate::wire::{ArgOp, AttrRequest, ChangeInfo4, CompoundArgs, CompoundRes, CreateType4, Fattr4, LockOwner4, LockType4, Locker4, NFS4_PROC_COMPOUND, NFS4_PROGRAM, NFS4_VERSION, Nfs4DirEntry, Nfs4FileInfo, Nfs4Status, OpenClaim4, OpenDelegationType4, OpenFlag4, ResOpData, SecInfoEntry, Stateid4};

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// An NFSv4 operation failed.
///
/// Mirrors `Nfs2Error<E>` / `Nfs3Error`: the `Rpc` variant carries the
/// transport-level failure while `Status` and `MissingResult` capture
/// protocol-level failures that a successful RPC revealed.
#[derive(Debug)]
#[non_exhaustive]
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
// Error classification -- mirrors Nfs3Error's predicates
// ---------------------------------------------------------------------------

impl<E> Nfs4Error<E> {
    /// True for transient errors that should trip the circuit breaker.
    pub fn is_transient(&self) -> bool {
        matches!(self, Self::Status(s) if s.is_transient())
    }

    /// True for permission denials (expected during credential probing).
    pub fn is_permission_denied(&self) -> bool {
        matches!(self, Self::Status(s) if s.is_permission_denied())
    }

    /// True for "not found" errors.
    pub fn is_not_found(&self) -> bool {
        matches!(self, Self::Status(s) if s.is_not_found())
    }

    /// True for stale file handle errors.
    pub fn is_stale(&self) -> bool {
        matches!(self, Self::Status(s) if s.is_stale())
    }

    /// Extract the NFS status code if this is a protocol-level error.
    pub fn nfs_status(&self) -> Option<Nfs4Status> {
        match self {
            Self::Status(s) => Some(*s),
            _ => None,
        }
    }

    // --- Crash recovery classification ---

    /// True when the server is in grace period.
    pub fn is_grace(&self) -> bool {
        matches!(self, Self::Status(s) if s.is_grace())
    }

    /// True when the client ID needs re-establishment.
    pub fn is_stale_clientid(&self) -> bool {
        matches!(self, Self::Status(s) if s.is_stale_clientid())
    }

    /// True when all state has expired and needs full recovery.
    pub fn is_expired(&self) -> bool {
        matches!(self, Self::Status(s) if s.is_expired())
    }
}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

/// Client for the NFSv4 service (program 100003, version 4).
///
/// Generic over the transport, so the same client works over a single socket
/// with no policy at all ([`DirectTransport`](onc_rpc_client::DirectTransport)) or
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

    // --- High-level API: path resolution + attributes ---

    /// Look up a single path component and return (file_handle, file_info).
    ///
    /// Issues PUTFH + LOOKUP + GETFH + GETATTR in one COMPOUND, avoiding
    /// the two-round-trip cost of a separate lookup_from_fh + getattr.
    pub async fn lookup(&self, dir_fh: &[u8], name: &str) -> Result<(Vec<u8>, Nfs4FileInfo), Nfs4Error<T::Error>> {
        let ops = vec![ArgOp::Putfh(dir_fh.to_vec()), ArgOp::Lookup(name.to_owned()), ArgOp::Getfh, ArgOp::Getattr(AttrRequest::shell_attrs())];
        let res = self.compound(ops).await?;
        check_status(res.status)?;
        let fh = match res.results.get(2).map(|op| &op.data) {
            Some(ResOpData::Fh(fh)) => fh.clone(),
            _ => return Err(Nfs4Error::MissingResult),
        };
        let info = match res.results.get(3).map(|op| &op.data) {
            Some(ResOpData::Getattr(attrs)) => Nfs4FileInfo::from(attrs.clone()),
            _ => Nfs4FileInfo::default(),
        };
        Ok((fh, info))
    }

    /// Get attributes for a file handle.
    ///
    /// Issues PUTFH + GETATTR and returns decoded attributes.
    pub async fn getattr(&self, fh: &[u8]) -> Result<Nfs4FileInfo, Nfs4Error<T::Error>> {
        let ops = vec![ArgOp::Putfh(fh.to_vec()), ArgOp::Getattr(AttrRequest::shell_attrs())];
        let res = self.compound(ops).await?;
        check_status(res.status)?;
        match res.results.get(1).map(|op| &op.data) {
            Some(ResOpData::Getattr(attrs)) => Ok(Nfs4FileInfo::from(attrs.clone())),
            _ => Err(Nfs4Error::MissingResult),
        }
    }

    /// Read symbolic link target (RFC 7530 S16.25).
    ///
    /// Issues PUTFH + READLINK and returns the link target string.
    pub async fn readlink(&self, fh: &[u8]) -> Result<String, Nfs4Error<T::Error>> {
        let ops = vec![ArgOp::Putfh(fh.to_vec()), ArgOp::Readlink];
        let res = self.compound(ops).await?;
        check_status(res.status)?;
        match res.results.get(1).map(|op| &op.data) {
            Some(ResOpData::Readlink(target)) => Ok(target.clone()),
            _ => Err(Nfs4Error::MissingResult),
        }
    }

    /// Check access rights on a file handle (RFC 7530 S16.1).
    ///
    /// Returns `(supported, access)` bitmasks. `supported` indicates which
    /// bits the server can reliably check; `access` indicates which of the
    /// requested rights the caller actually has.
    pub async fn access(&self, fh: &[u8], mask: u32) -> Result<(u32, u32), Nfs4Error<T::Error>> {
        let ops = vec![ArgOp::Putfh(fh.to_vec()), ArgOp::Access { access: mask }];
        let res = self.compound(ops).await?;
        check_status(res.status)?;
        match res.results.get(1).map(|op| &op.data) {
            Some(ResOpData::Access { supported, access }) => Ok((*supported, *access)),
            _ => Err(Nfs4Error::MissingResult),
        }
    }

    // --- High-level API: directory listing with attributes ---

    /// List directory entries with inline attributes.
    ///
    /// The NFSv4 equivalent of NFSv3 READDIRPLUS. Requests inline attrs
    /// per entry via `shell_attrs_with_fh()`. Paginates internally until
    /// EOF or the entry cap is hit.
    ///
    /// Note: file handles are requested via the FATTR4_FILEHANDLE bit, but
    /// the current attribute decoder skips them, so `Nfs4DirEntry.fh` will
    /// be `None`. A future decoder enhancement will populate them.
    pub async fn readdir_plus(&self, dir_fh: &[u8]) -> Result<Vec<Nfs4DirEntry>, Nfs4Error<T::Error>> {
        const MAX_READDIR_ENTRIES: usize = 1_000_000;
        let mut entries = Vec::new();
        let mut raw_seen: usize = 0;
        let mut cookie: u64 = 0;
        let mut cookieverf: u64 = 0;
        loop {
            let ops = vec![ArgOp::Putfh(dir_fh.to_vec()), ArgOp::Readdir { cookie, cookieverf, dircount: 8192, maxcount: 65536, attr_request: AttrRequest::shell_attrs_with_fh() }];
            let res = self.compound(ops).await?;
            check_status(res.status)?;
            let (server_verf, dir_entries, eof) = match res.results.get(1).map(|op| &op.data) {
                Some(ResOpData::Readdir { cookieverf, entries, eof }) => (*cookieverf, entries, *eof),
                _ => return Err(Nfs4Error::MissingResult),
            };
            cookieverf = u64::from_be_bytes(server_verf);
            let Some(last_cookie) = dir_entries.last().map(|e| e.cookie) else {
                break;
            };
            raw_seen = raw_seen.saturating_add(dir_entries.len());
            for e in dir_entries {
                if e.name != "." && e.name != ".." {
                    let info = e.attrs.as_ref().map(|a| Nfs4FileInfo::from(a.clone()));
                    entries.push(Nfs4DirEntry { name: e.name.clone(), cookie: e.cookie, fh: None, info });
                }
            }
            if eof {
                break;
            }
            if raw_seen >= MAX_READDIR_ENTRIES {
                tracing::warn!(count = raw_seen, "NFSv4 readdir_plus hit entry cap");
                break;
            }
            if last_cookie == cookie {
                break;
            }
            cookie = last_cookie;
        }
        Ok(entries)
    }

    // --- High-level API: directory and file mutation ---

    /// Create a directory (RFC 7530 S16.4).
    ///
    /// Returns `(new_dir_fh, change_info)`. Uses empty initial attributes;
    /// the server applies its default mode.
    pub async fn mkdir(&self, dir_fh: &[u8], name: &str) -> Result<(Vec<u8>, ChangeInfo4), Nfs4Error<T::Error>> {
        let ops = vec![ArgOp::Putfh(dir_fh.to_vec()), ArgOp::Create { objtype: CreateType4::Dir, objname: name.to_owned(), createattrs: Fattr4::default() }, ArgOp::Getfh];
        let res = self.compound(ops).await?;
        check_status(res.status)?;
        let cinfo = match res.results.get(1).map(|op| &op.data) {
            Some(ResOpData::Create { cinfo, .. }) => *cinfo,
            _ => return Err(Nfs4Error::MissingResult),
        };
        let fh = match res.results.get(2).map(|op| &op.data) {
            Some(ResOpData::Fh(fh)) => fh.clone(),
            _ => return Err(Nfs4Error::MissingResult),
        };
        Ok((fh, cinfo))
    }

    /// Remove a filesystem object by name (RFC 7530 S16.26).
    ///
    /// Returns the directory's change info (before/after the removal).
    pub async fn remove(&self, dir_fh: &[u8], name: &str) -> Result<ChangeInfo4, Nfs4Error<T::Error>> {
        let ops = vec![ArgOp::Putfh(dir_fh.to_vec()), ArgOp::Remove { target: name.to_owned() }];
        let res = self.compound(ops).await?;
        check_status(res.status)?;
        match res.results.get(1).map(|op| &op.data) {
            Some(ResOpData::ChangeInfo(ci)) => Ok(*ci),
            _ => Err(Nfs4Error::MissingResult),
        }
    }

    /// Rename a filesystem object (RFC 7530 S16.27).
    ///
    /// Uses PUTFH(src) + SAVEFH + PUTFH(dst) + RENAME to reference both
    /// directories in a single COMPOUND. Returns `(source_change, target_change)`.
    pub async fn rename(&self, src_dir_fh: &[u8], oldname: &str, dst_dir_fh: &[u8], newname: &str) -> Result<(ChangeInfo4, ChangeInfo4), Nfs4Error<T::Error>> {
        let ops = vec![ArgOp::Putfh(src_dir_fh.to_vec()), ArgOp::Savefh, ArgOp::Putfh(dst_dir_fh.to_vec()), ArgOp::Rename { oldname: oldname.to_owned(), newname: newname.to_owned() }];
        let res = self.compound(ops).await?;
        check_status(res.status)?;
        match res.results.get(3).map(|op| &op.data) {
            Some(ResOpData::RenameInfo { source, target }) => Ok((*source, *target)),
            _ => Err(Nfs4Error::MissingResult),
        }
    }

    /// Create a hard link (RFC 7530 S16.9).
    ///
    /// Saved FH is the source object, current FH is the target directory.
    /// Returns the target directory's change info.
    pub async fn link(&self, src_fh: &[u8], dir_fh: &[u8], newname: &str) -> Result<ChangeInfo4, Nfs4Error<T::Error>> {
        let ops = vec![ArgOp::Putfh(src_fh.to_vec()), ArgOp::Savefh, ArgOp::Putfh(dir_fh.to_vec()), ArgOp::Link { newname: newname.to_owned() }];
        let res = self.compound(ops).await?;
        check_status(res.status)?;
        match res.results.get(3).map(|op| &op.data) {
            Some(ResOpData::ChangeInfo(ci)) => Ok(*ci),
            _ => Err(Nfs4Error::MissingResult),
        }
    }

    /// Create a symbolic link (RFC 7530 S16.4).
    ///
    /// Returns `(new_fh, change_info)`. Uses empty initial attributes.
    pub async fn symlink(&self, dir_fh: &[u8], name: &str, target: &str) -> Result<(Vec<u8>, ChangeInfo4), Nfs4Error<T::Error>> {
        let ops = vec![ArgOp::Putfh(dir_fh.to_vec()), ArgOp::Create { objtype: CreateType4::Lnk(target.to_owned()), objname: name.to_owned(), createattrs: Fattr4::default() }, ArgOp::Getfh];
        let res = self.compound(ops).await?;
        check_status(res.status)?;
        let cinfo = match res.results.get(1).map(|op| &op.data) {
            Some(ResOpData::Create { cinfo, .. }) => *cinfo,
            _ => return Err(Nfs4Error::MissingResult),
        };
        let fh = match res.results.get(2).map(|op| &op.data) {
            Some(ResOpData::Fh(fh)) => fh.clone(),
            _ => return Err(Nfs4Error::MissingResult),
        };
        Ok((fh, cinfo))
    }

    /// Set attributes on a file (RFC 7530 S16.32).
    ///
    /// Returns the bitmap of attributes the server actually set.
    pub async fn setattr(&self, fh: &[u8], stateid: Stateid4, attrs: Fattr4) -> Result<Vec<u32>, Nfs4Error<T::Error>> {
        let ops = vec![ArgOp::Putfh(fh.to_vec()), ArgOp::Setattr { stateid, obj_attributes: attrs }];
        let res = self.compound(ops).await?;
        check_status(res.status)?;
        match res.results.get(1).map(|op| &op.data) {
            Some(ResOpData::Bitmap(words)) => Ok(words.clone()),
            _ => Err(Nfs4Error::MissingResult),
        }
    }

    /// Commit cached data to stable storage (RFC 7530 S16.3).
    ///
    /// Returns the 8-byte write verifier for detecting server reboots.
    pub async fn commit(&self, fh: &[u8], offset: u64, count: u32) -> Result<[u8; 8], Nfs4Error<T::Error>> {
        let ops = vec![ArgOp::Putfh(fh.to_vec()), ArgOp::Commit { offset, count }];
        let res = self.compound(ops).await?;
        check_status(res.status)?;
        match res.results.get(1).map(|op| &op.data) {
            Some(ResOpData::CommitVerf(verf)) => Ok(*verf),
            _ => Err(Nfs4Error::MissingResult),
        }
    }

    /// Query supported auth flavors for a named child (RFC 7530 S16.31).
    ///
    /// Returns the list of security mechanisms the server accepts for the
    /// named object. Each entry carries the auth flavor and, for RPCSEC_GSS,
    /// the mechanism OID and service level.
    pub async fn secinfo(&self, dir_fh: &[u8], name: &str) -> Result<Vec<SecInfoEntry>, Nfs4Error<T::Error>> {
        let ops = vec![ArgOp::Putfh(dir_fh.to_vec()), ArgOp::Secinfo(name.to_owned())];
        let res = self.compound(ops).await?;
        check_status(res.status)?;
        match res.results.get(1).map(|op| &op.data) {
            Some(ResOpData::SecFlavors(entries)) => Ok(entries.clone()),
            _ => Err(Nfs4Error::MissingResult),
        }
    }

    // --- Stateful API: session establishment ---

    /// Establish an NFSv4.0 client identity (RFC 7530 S16.33 + S16.34).
    ///
    /// Issues SETCLIENTID + SETCLIENTID_CONFIRM in two COMPOUNDs. Returns a
    /// confirmed session ready for OPEN/LOCK operations. The verifier is
    /// hardcoded to "nfswolf\0" so the server can detect client reboots.
    pub async fn establish(&self, client_name: &str, callback_addr: &str) -> Result<Nfs4Session, Nfs4Error<T::Error>> {
        // Step 1: SETCLIENTID -- negotiate a clientid.
        let ops = vec![ArgOp::Setclientid {
            client_verifier: [0x6E, 0x66, 0x73, 0x77, 0x6F, 0x6C, 0x66, 0x00], // "nfswolf\0"
            client_id: client_name.as_bytes().to_vec(),
            cb_program: 0x4000_0000,
            cb_netid: "tcp".to_owned(),
            cb_addr: callback_addr.to_owned(),
            callback_ident: 1,
        }];
        let res = self.compound(ops).await?;
        check_status(res.status)?;

        let (clientid, confirm_verifier) = match res.results.first().map(|op| &op.data) {
            Some(ResOpData::Setclientid { clientid, confirm_verifier }) => (*clientid, *confirm_verifier),
            _ => return Err(Nfs4Error::MissingResult),
        };

        let mut session = Nfs4Session::new(clientid, confirm_verifier, b"nfswolf");

        // Step 2: SETCLIENTID_CONFIRM -- lock in the clientid.
        let ops = vec![ArgOp::SetclientidConfirm { clientid, verifier: confirm_verifier }];
        let res = self.compound(ops).await?;
        check_status(res.status)?;

        session.mark_confirmed();
        Ok(session)
    }

    /// Re-establish a session after NFS4ERR_STALE_CLIENTID.
    ///
    /// Issues a new SETCLIENTID + SETCLIENTID_CONFIRM sequence. The old
    /// session is consumed and a new one is returned. All prior open/lock
    /// state is invalidated by the server -- the consumer must re-open files.
    pub async fn re_establish(&self, client_name: &str, callback_addr: &str) -> Result<Nfs4Session, Nfs4Error<T::Error>> {
        // The server treats this as a fresh client.
        self.establish(client_name, callback_addr).await
    }

    /// Attempt to reclaim an open file after server reboot (grace period).
    ///
    /// Issues OPEN with CLAIM_PREVIOUS during the server's grace period.
    /// Only succeeds if the server is in grace and the open state is reclaimable.
    pub async fn reclaim_open(&self, session: &Nfs4Session, fh: &[u8], delegation_type: OpenDelegationType4) -> Result<OpenState, Nfs4Error<T::Error>> {
        let seqid = session.next_seqid();
        let ops = vec![ArgOp::Putfh(fh.to_vec()), ArgOp::Open { seqid, share_access: 1, share_deny: 0, owner: session.open_owner().clone(), openhow: OpenFlag4::NoCreate, claim: OpenClaim4::Previous(delegation_type) }];
        let res = self.compound(ops).await?;
        check_status(res.status)?;
        let (stateid, delegation) = match res.results.get(1).map(|op| &op.data) {
            Some(ResOpData::Open { stateid, delegation, .. }) => (*stateid, delegation.clone()),
            _ => return Err(Nfs4Error::MissingResult),
        };
        Ok(OpenState { stateid, fh: fh.to_vec(), share_access: 1, share_deny: 0, delegation, confirmed: true })
    }

    /// Renew the lease for a session (RFC 7530 S16.28).
    ///
    /// Must be called before the lease expires (typically every lease_time/2
    /// seconds) or all open/lock state is lost.
    pub async fn renew(&self, session: &Nfs4Session) -> Result<(), Nfs4Error<T::Error>> {
        let ops = vec![ArgOp::Renew { clientid: session.clientid() }];
        let res = self.compound(ops).await?;
        check_status(res.status)?;
        Ok(())
    }

    // --- Stateful API: file open/close lifecycle ---

    /// Open a file for reading (RFC 7530 S16.16).
    ///
    /// Issues PUTFH + OPEN(SHARE_ACCESS_READ) + GETFH + GETATTR in one COMPOUND.
    /// Handles OPEN_CONFIRM automatically on first use per open-owner.
    pub async fn open_read(&self, session: &Nfs4Session, dir_fh: &[u8], name: &str) -> Result<(OpenState, Nfs4FileInfo), Nfs4Error<T::Error>> {
        self.open_file(session, dir_fh, name, 1, 0).await // OPEN4_SHARE_ACCESS_READ=1, DENY_NONE=0
    }

    /// Open a file for writing.
    pub async fn open_write(&self, session: &Nfs4Session, dir_fh: &[u8], name: &str) -> Result<(OpenState, Nfs4FileInfo), Nfs4Error<T::Error>> {
        self.open_file(session, dir_fh, name, 2, 0).await // OPEN4_SHARE_ACCESS_WRITE=2, DENY_NONE=0
    }

    /// Open a file for read+write.
    pub async fn open_rw(&self, session: &Nfs4Session, dir_fh: &[u8], name: &str) -> Result<(OpenState, Nfs4FileInfo), Nfs4Error<T::Error>> {
        self.open_file(session, dir_fh, name, 3, 0).await // OPEN4_SHARE_ACCESS_BOTH=3, DENY_NONE=0
    }

    /// Open a file with the given share access/deny modes.
    ///
    /// Automatically issues OPEN_CONFIRM when the server's rflags request it
    /// (OPEN4_RESULT_CONFIRM, bit 1 of rflags per RFC 7530 S16.16.4).
    async fn open_file(&self, session: &Nfs4Session, dir_fh: &[u8], name: &str, share_access: u32, share_deny: u32) -> Result<(OpenState, Nfs4FileInfo), Nfs4Error<T::Error>> {
        let seqid = session.next_seqid();
        let ops = vec![ArgOp::Putfh(dir_fh.to_vec()), ArgOp::Open { seqid, share_access, share_deny, owner: session.open_owner().clone(), openhow: OpenFlag4::NoCreate, claim: OpenClaim4::Null(name.to_owned()) }, ArgOp::Getfh, ArgOp::Getattr(AttrRequest::shell_attrs())];
        let res = self.compound(ops).await?;
        check_status(res.status)?;

        // Extract OPEN result (index 1: after PUTFH).
        let (stateid, rflags, delegation) = match res.results.get(1).map(|op| &op.data) {
            Some(ResOpData::Open { stateid, rflags, delegation, .. }) => (*stateid, *rflags, delegation.clone()),
            _ => return Err(Nfs4Error::MissingResult),
        };

        // Extract file handle (index 2: GETFH).
        let fh = match res.results.get(2).map(|op| &op.data) {
            Some(ResOpData::Fh(fh)) => fh.clone(),
            _ => return Err(Nfs4Error::MissingResult),
        };

        // Extract attributes (index 3: GETATTR). Fall back to default on mismatch.
        let info = match res.results.get(3).map(|op| &op.data) {
            Some(ResOpData::Getattr(attrs)) => Nfs4FileInfo::from(attrs.clone()),
            _ => Nfs4FileInfo::default(),
        };

        let mut open_state = OpenState { stateid, fh, share_access, share_deny, delegation, confirmed: false };

        // OPEN_CONFIRM if the server set OPEN4_RESULT_CONFIRM (bit 1).
        if rflags & 0x0002 != 0 {
            let confirm_seqid = session.next_seqid();
            let confirm_ops = vec![ArgOp::Putfh(open_state.fh.clone()), ArgOp::OpenConfirm { stateid: open_state.stateid.to_bytes(), seqid: confirm_seqid }];
            let cres = self.compound(confirm_ops).await?;
            check_status(cres.status)?;
            // OPEN_CONFIRM returns an updated stateid.
            if let Some(ResOpData::Stateid(new_stateid)) = cres.results.get(1).map(|op| &op.data) {
                open_state.stateid = *new_stateid;
            }
        }
        open_state.confirmed = true;

        Ok((open_state, info))
    }

    /// Close an opened file (RFC 7530 S16.2).
    ///
    /// Releases the open stateid on the server. The open state should not be
    /// used after this call.
    pub async fn close_file(&self, session: &Nfs4Session, open_state: &OpenState) -> Result<(), Nfs4Error<T::Error>> {
        let seqid = session.next_seqid();
        let ops = vec![ArgOp::Putfh(open_state.fh.clone()), ArgOp::Close { seqid, stateid: open_state.stateid.to_bytes() }];
        let res = self.compound(ops).await?;
        check_status(res.status)?;
        Ok(())
    }

    // --- Stateful API: stateid-aware read/write ---

    /// Read file data using an open stateid (RFC 7530 S16.23).
    ///
    /// Unlike `read_chunk` which uses the anonymous stateid, this uses the
    /// stateid from a prior OPEN to read data with proper share-reservation
    /// semantics. Returns `(data, eof)`.
    pub async fn read_via_open(&self, open_state: &OpenState, offset: u64, count: u32) -> Result<(Vec<u8>, bool), Nfs4Error<T::Error>> {
        let ops = vec![ArgOp::Putfh(open_state.fh.clone()), ArgOp::Read { stateid: open_state.stateid.to_bytes(), offset, count }];
        let res = self.compound(ops).await?;
        check_status(res.status)?;
        match res.results.get(1).map(|op| &op.data) {
            Some(ResOpData::Read { eof, data }) => Ok((data.clone(), *eof)),
            _ => Err(Nfs4Error::MissingResult),
        }
    }

    /// Write file data using an open stateid (RFC 7530 S16.36).
    ///
    /// Returns `(count, committed, writeverf)`. The `stable` parameter controls
    /// the write stability: 0 = UNSTABLE4, 1 = DATA_SYNC4, 2 = FILE_SYNC4.
    pub async fn write_via_open(&self, open_state: &OpenState, offset: u64, stable: u32, data: &[u8]) -> Result<(u32, u32, [u8; 8]), Nfs4Error<T::Error>> {
        let ops = vec![ArgOp::Putfh(open_state.fh.clone()), ArgOp::Write { stateid: open_state.stateid.to_bytes(), offset, stable, data: data.to_vec() }];
        let res = self.compound(ops).await?;
        check_status(res.status)?;
        match res.results.get(1).map(|op| &op.data) {
            Some(ResOpData::WriteRes { count, committed, writeverf }) => Ok((*count, *committed, *writeverf)),
            _ => Err(Nfs4Error::MissingResult),
        }
    }

    // --- Stateful API: convenience wrappers ---

    /// Read an entire file via OPEN + READ loop + CLOSE.
    ///
    /// Opens the file for reading, reads until EOF in 64 KiB chunks, then
    /// closes. Returns `(file_data, file_info)`. Close errors are silently
    /// ignored (the data was already read successfully).
    pub async fn read_file(&self, session: &Nfs4Session, dir_fh: &[u8], name: &str) -> Result<(Vec<u8>, Nfs4FileInfo), Nfs4Error<T::Error>> {
        let (open_state, info) = self.open_read(session, dir_fh, name).await?;
        let mut data = Vec::new();
        let mut offset = 0u64;
        loop {
            let (chunk, eof) = self.read_via_open(&open_state, offset, 65536).await?;
            offset += chunk.len() as u64;
            data.extend_from_slice(&chunk);
            if eof || chunk.is_empty() {
                break;
            }
        }
        // Best-effort close -- data is already captured.
        drop(self.close_file(session, &open_state).await);
        Ok((data, info))
    }

    /// Write data to a file via OPEN + WRITE loop + COMMIT + CLOSE.
    ///
    /// Opens the file for writing, writes in 64 KiB chunks (UNSTABLE for all
    /// but the last chunk which uses FILE_SYNC), issues COMMIT if unstable
    /// writes were used, fetches final attributes, then closes. Returns the
    /// final file info.
    pub async fn write_file(&self, session: &Nfs4Session, dir_fh: &[u8], name: &str, data: &[u8]) -> Result<Nfs4FileInfo, Nfs4Error<T::Error>> {
        let (open_state, _) = self.open_write(session, dir_fh, name).await?;
        let mut offset = 0usize;
        let chunk_size = 65536usize;
        while offset < data.len() {
            let end = std::cmp::min(offset + chunk_size, data.len());
            let chunk = data.get(offset..end).unwrap_or_default();
            // FILE_SYNC4 = 2 for the last chunk, UNSTABLE4 = 0 otherwise.
            let stable = if end == data.len() { 2 } else { 0 };
            let _write_res = self.write_via_open(&open_state, offset as u64, stable, chunk).await?;
            offset = end;
        }
        // COMMIT if any UNSTABLE writes were issued (multi-chunk case).
        if data.len() > chunk_size {
            drop(self.commit(open_state.fh(), 0, 0).await);
        }
        // Fetch final attributes; fall back to default on error.
        let info = self.getattr(open_state.fh()).await.unwrap_or_default();
        drop(self.close_file(session, &open_state).await);
        Ok(info)
    }

    // --- Stateful API: byte-range locking (RFC 7530 S16.10-S16.12) ---

    /// Acquire a byte-range lock on an opened file (RFC 7530 S16.10).
    ///
    /// Issues PUTFH + LOCK in one COMPOUND. The lock is associated with a new
    /// lock-owner derived from the open stateid. Returns a `LockState` tracking
    /// the lock stateid and range for subsequent unlock/extend operations.
    pub async fn lock(&self, session: &Nfs4Session, open_state: &OpenState, locktype: LockType4, offset: u64, length: u64) -> Result<LockState, Nfs4Error<T::Error>> {
        let lock_seqid = session.next_seqid();
        let lock_owner = LockOwner4 { clientid: session.clientid(), owner: b"nfswolf-lock".to_vec() };
        let ops = vec![ArgOp::Putfh(open_state.fh.clone()), ArgOp::Lock { locktype, reclaim: false, offset, length, locker: Locker4::NewLockOwner { open_seqid: session.next_seqid(), open_stateid: open_state.stateid, lock_seqid, lock_owner: lock_owner.clone() } }];
        let res = self.compound(ops).await?;
        check_status(res.status)?;
        let lock_stateid = match res.results.get(1).map(|op| &op.data) {
            Some(ResOpData::Stateid(sid)) => *sid,
            _ => return Err(Nfs4Error::MissingResult),
        };
        Ok(LockState { lock_stateid, lock_owner, ranges: vec![LockRange { offset, length, locktype }] })
    }

    /// Release a byte-range lock (RFC 7530 S16.12).
    ///
    /// Issues PUTFH + LOCKU in one COMPOUND. Returns the updated lock stateid
    /// from the server (the caller should update their `LockState` accordingly).
    pub async fn unlock(&self, session: &Nfs4Session, fh: &[u8], lock_state: &LockState, locktype: LockType4, offset: u64, length: u64) -> Result<Stateid4, Nfs4Error<T::Error>> {
        let seqid = session.next_seqid();
        let ops = vec![ArgOp::Putfh(fh.to_vec()), ArgOp::Locku { locktype, seqid, lock_stateid: lock_state.lock_stateid, offset, length }];
        let res = self.compound(ops).await?;
        check_status(res.status)?;
        match res.results.get(1).map(|op| &op.data) {
            Some(ResOpData::Stateid(sid)) => Ok(*sid),
            _ => Err(Nfs4Error::MissingResult),
        }
    }

    /// Test for a byte-range lock without acquiring it (RFC 7530 S16.11).
    ///
    /// Issues PUTFH + LOCKT. Returns `Ok(())` if no conflicting lock exists,
    /// or `Err(Nfs4Error::Status(Denied))` if a conflicting lock is held.
    pub async fn test_lock(&self, fh: &[u8], session: &Nfs4Session, locktype: LockType4, offset: u64, length: u64) -> Result<(), Nfs4Error<T::Error>> {
        let owner = LockOwner4 { clientid: session.clientid(), owner: b"nfswolf-lock".to_vec() };
        let ops = vec![ArgOp::Putfh(fh.to_vec()), ArgOp::Lockt { locktype, offset, length, owner }];
        let res = self.compound(ops).await?;
        check_status(res.status)?;
        Ok(())
    }

    /// Release all state associated with a lock owner (RFC 7530 S16.37).
    ///
    /// Should be called after all locks for the owner have been released via
    /// LOCKU. The server frees bookkeeping state for the lock-owner identity.
    pub async fn release_lockowner(&self, lock_owner: LockOwner4) -> Result<(), Nfs4Error<T::Error>> {
        let ops = vec![ArgOp::ReleaseLockowner { lock_owner }];
        let res = self.compound(ops).await?;
        check_status(res.status)?;
        Ok(())
    }

    /// Return a delegation to the server (RFC 7530 S16.6).
    ///
    /// Issues PUTFH + DELEGRETURN. Should be called when the client no longer
    /// needs the delegation (e.g., after closing the file or on server recall).
    pub async fn delegreturn(&self, fh: &[u8], stateid: Stateid4) -> Result<(), Nfs4Error<T::Error>> {
        let ops = vec![ArgOp::Putfh(fh.to_vec()), ArgOp::Delegreturn { stateid: stateid.to_bytes() }];
        let res = self.compound(ops).await?;
        check_status(res.status)?;
        Ok(())
    }
}

/// Translate a non-zero COMPOUND status into a typed error.
fn check_status<E>(status: u32) -> Result<(), Nfs4Error<E>> {
    if status == 0 { Ok(()) } else { Err(Nfs4Error::Status(Nfs4Status::from_u32(status))) }
}

#[cfg(test)]
mod tests {
    #![expect(clippy::pedantic, reason = "unit test -- lints are suppressed per project policy")]
    use super::*;

    // Use io::Error as the concrete transport error for classification tests.
    type TestError = Nfs4Error<std::io::Error>;

    #[test]
    fn is_transient_positive() {
        assert!(TestError::Status(Nfs4Status::Io).is_transient());
        assert!(TestError::Status(Nfs4Status::Delay).is_transient());
        assert!(TestError::Status(Nfs4Status::Resource).is_transient());
        assert!(TestError::Status(Nfs4Status::ServerFault).is_transient());
    }

    #[test]
    fn is_transient_negative() {
        assert!(!TestError::Status(Nfs4Status::Acces).is_transient());
        assert!(!TestError::Status(Nfs4Status::Stale).is_transient());
        assert!(!TestError::Status(Nfs4Status::NoEnt).is_transient());
        assert!(!TestError::MissingResult.is_transient());
    }

    #[test]
    fn is_permission_denied_positive() {
        assert!(TestError::Status(Nfs4Status::Acces).is_permission_denied());
        assert!(TestError::Status(Nfs4Status::Perm).is_permission_denied());
    }

    #[test]
    fn is_permission_denied_negative() {
        assert!(!TestError::Status(Nfs4Status::Io).is_permission_denied());
        assert!(!TestError::Status(Nfs4Status::NoEnt).is_permission_denied());
        assert!(!TestError::MissingResult.is_permission_denied());
    }

    #[test]
    fn is_not_found_positive() {
        assert!(TestError::Status(Nfs4Status::NoEnt).is_not_found());
    }

    #[test]
    fn is_not_found_negative() {
        assert!(!TestError::Status(Nfs4Status::Acces).is_not_found());
        assert!(!TestError::MissingResult.is_not_found());
    }

    #[test]
    fn is_stale_positive() {
        assert!(TestError::Status(Nfs4Status::Stale).is_stale());
    }

    #[test]
    fn is_stale_negative() {
        assert!(!TestError::Status(Nfs4Status::BadHandle).is_stale());
        assert!(!TestError::MissingResult.is_stale());
    }

    #[test]
    fn nfs_status_returns_some_for_status() {
        let err = TestError::Status(Nfs4Status::Io);
        assert_eq!(err.nfs_status(), Some(Nfs4Status::Io));
    }

    #[test]
    fn nfs_status_returns_none_for_missing_result() {
        assert_eq!(TestError::MissingResult.nfs_status(), None);
    }

    #[test]
    fn nfs_status_returns_none_for_rpc_error() {
        let err = TestError::Rpc(std::io::Error::new(std::io::ErrorKind::BrokenPipe, "gone"));
        assert_eq!(err.nfs_status(), None);
    }

    // --- Crash recovery classification ---

    #[test]
    fn is_grace_positive() {
        assert!(TestError::Status(Nfs4Status::Grace).is_grace());
    }

    #[test]
    fn is_grace_negative() {
        assert!(!TestError::Status(Nfs4Status::NoGrace).is_grace());
        assert!(!TestError::Status(Nfs4Status::Expired).is_grace());
        assert!(!TestError::MissingResult.is_grace());
    }

    #[test]
    fn is_stale_clientid_positive() {
        assert!(TestError::Status(Nfs4Status::StaleClientid).is_stale_clientid());
    }

    #[test]
    fn is_stale_clientid_negative() {
        assert!(!TestError::Status(Nfs4Status::StaleStateid).is_stale_clientid());
        assert!(!TestError::Status(Nfs4Status::Expired).is_stale_clientid());
        assert!(!TestError::MissingResult.is_stale_clientid());
    }

    #[test]
    fn is_expired_positive() {
        assert!(TestError::Status(Nfs4Status::Expired).is_expired());
    }

    #[test]
    fn is_expired_negative() {
        assert!(!TestError::Status(Nfs4Status::StaleClientid).is_expired());
        assert!(!TestError::Status(Nfs4Status::Grace).is_expired());
        assert!(!TestError::MissingResult.is_expired());
    }
}
