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

use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use onc_rpc_client::RpcTransport;

use crate::session::Nfs4Session;
use crate::state::{LockRange, LockState, OpenState};
use crate::wire::{
    ArgOp, AttrRequest, ChangeInfo4, CompoundArgs, CompoundRes, CreateType4, DirEntry4, Fattr4, LockOwner4, LockType4, Locker4, NFS4_PROC_COMPOUND, NFS4_PROGRAM, NFS4_VERSION, Nfs4DirEntry, Nfs4FileInfo, Nfs4Status, OpenClaim4, OpenDelegationType4, OpenFlag4, ResOpData, SecInfoEntry, Stateid4,
};

/// Largest file [`Nfs4Client::read_file`] will assemble in memory.
pub const READ_FILE_MAX_BYTES: usize = 256 * 1024 * 1024;

/// Bytes per READ or WRITE in the whole-file helpers.
const IO_CHUNK: u32 = 65_536;

/// Most READDIR entries a listing will collect before giving up on `eof`.
const MAX_READDIR_ENTRIES: usize = 1_000_000;

/// `OPEN4_RESULT_CONFIRM` in OPEN's `rflags` (RFC 7530 sec. 16.16.4).
const OPEN4_RESULT_CONFIRM: u32 = 0x0002;

/// `FILE_SYNC4` (RFC 7530 sec. 16.36.4): data and metadata are on stable
/// storage before the WRITE reply.
const FILE_SYNC4: u32 = 2;

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
    /// The data exceeds a size limit this client imposes.
    ///
    /// Raised by the client, not the server: the server was still answering.
    TooLarge {
        /// The limit, in bytes.
        limit: usize,
    },
    /// A WRITE succeeded but accepted no bytes, so the transfer cannot make
    /// progress.
    WriteStalled {
        /// File offset of the write that accepted nothing.
        offset: u64,
    },
}

impl<E: std::fmt::Display> std::fmt::Display for Nfs4Error<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Rpc(e) => e.fmt(f),
            Self::Status(s) => write!(f, "NFSv4 error: {s}"),
            Self::MissingResult => f.write_str("NFSv4: expected result op missing from COMPOUND response"),
            Self::TooLarge { limit } => write!(f, "NFSv4: data exceeds the client's {limit}-byte limit"),
            Self::WriteStalled { offset } => write!(f, "NFSv4: WRITE at offset {offset} accepted no bytes"),
        }
    }
}

impl<E: std::error::Error + 'static> std::error::Error for Nfs4Error<E> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Rpc(e) => Some(e),
            Self::Status(s) => Some(s),
            Self::MissingResult | Self::TooLarge { .. } | Self::WriteStalled { .. } => None,
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
    /// Pages through the whole directory (RFC 7530 S16.24), stopping at
    /// `eof`, an empty page, a cookie that does not advance, or one million
    /// raw entries -- the server is untrusted, so `eof` cannot be the only
    /// exit.
    pub async fn list_dir(&self, dir_fh: &[u8]) -> Result<Vec<String>, Nfs4Error<T::Error>> {
        let mut names = Vec::new();
        self.readdir_pages(dir_fh, 4096, &AttrRequest::empty(), |e| names.push(e.name.clone())).await?;
        Ok(names)
    }

    /// Run READDIR to the end of the directory, handing each entry other than
    /// `"."` and `".."` to `each`.
    ///
    /// NFSv4 READDIR is paginated (RFC 7530 S16.24): a directory larger than
    /// `maxcount` is returned across multiple calls, each ending with
    /// `eof=false`, and the client must resume from the last entry's cookie,
    /// echoing the server's cookie verifier so it can detect a directory that
    /// changed between pages.
    ///
    /// The server is untrusted, so `eof` is not the only exit: the loop also
    /// stops on an empty page, on a cookie that does not advance, and after
    /// [`MAX_READDIR_ENTRIES`] raw entries. It counts raw entries rather than
    /// the ones handed on, because a hostile server can send pages of nothing
    /// but `"."` and `".."` with a cycling cookie.
    async fn readdir_pages(&self, dir_fh: &[u8], dircount: u32, attr_request: &AttrRequest, mut each: impl FnMut(&DirEntry4) + Send) -> Result<(), Nfs4Error<T::Error>> {
        let mut raw_seen: usize = 0;
        let mut cookie: u64 = 0;
        // RFC 7530 S16.24: the first call sends cookieverf=0.
        let mut cookieverf: u64 = 0;
        loop {
            let ops = vec![ArgOp::Putfh(dir_fh.to_vec()), ArgOp::Readdir { cookie, cookieverf, dircount, maxcount: 65536, attr_request: attr_request.clone() }];
            let res = self.compound(ops).await?;
            check_status(res.status)?;
            let (server_verf, entries, eof) = match res.results.get(1).map(|op| &op.data) {
                Some(ResOpData::Readdir { cookieverf, entries, eof }) => (*cookieverf, entries, *eof),
                _ => return Err(Nfs4Error::MissingResult),
            };
            cookieverf = u64::from_be_bytes(server_verf);
            // An empty page leaves no cookie to resume from.
            let Some(last_cookie) = entries.last().map(|e| e.cookie) else {
                break;
            };
            raw_seen = raw_seen.saturating_add(entries.len());
            entries.iter().filter(|e| e.name != "." && e.name != "..").for_each(&mut each);
            if eof {
                break;
            }
            if raw_seen >= MAX_READDIR_ENTRIES {
                tracing::warn!(count = raw_seen, "NFSv4 READDIR hit entry cap; directory listing truncated");
                break;
            }
            if last_cookie == cookie {
                break;
            }
            cookie = last_cookie;
        }
        Ok(())
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
            Some(ResOpData::Getattr(attrs)) => Nfs4FileInfo::from(*attrs.clone()),
            _ => return Err(Nfs4Error::MissingResult),
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
            Some(ResOpData::Getattr(attrs)) => Ok(Nfs4FileInfo::from(*attrs.clone())),
            _ => Err(Nfs4Error::MissingResult),
        }
    }

    /// The server's largest READ and WRITE for the filesystem holding `fh`,
    /// in bytes (`maxread` and `maxwrite`, RFC 7530 S5.8.2.16-17).
    ///
    /// Either is `None` when the server does not report it.
    pub async fn transfer_limits(&self, fh: &[u8]) -> Result<(Option<u64>, Option<u64>), Nfs4Error<T::Error>> {
        let ops = vec![ArgOp::Putfh(fh.to_vec()), ArgOp::Getattr(AttrRequest::transfer_limits())];
        let res = self.compound(ops).await?;
        check_status(res.status)?;
        match res.results.get(1).map(|op| &op.data) {
            Some(ResOpData::Getattr(attrs)) => Ok((attrs.maxread, attrs.maxwrite)),
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

    /// List directory entries with inline attributes and file handles.
    ///
    /// The NFSv4 equivalent of NFSv3 READDIRPLUS. Each entry asks for the
    /// shell attributes plus `FATTR4_FILEHANDLE`, so [`Nfs4DirEntry::fh`] is
    /// filled whenever the server returns the handle and no per-entry LOOKUP
    /// is needed. Pages to the end of the directory with the same bounds as
    /// [`list_dir`](Self::list_dir).
    pub async fn readdir_plus(&self, dir_fh: &[u8]) -> Result<Vec<Nfs4DirEntry>, Nfs4Error<T::Error>> {
        let mut entries = Vec::new();
        self.readdir_pages(dir_fh, 8192, &AttrRequest::shell_attrs_with_fh(), |e| {
            let fh = e.attrs.as_ref().and_then(|a| a.filehandle.clone());
            let info = e.attrs.as_ref().map(|a| Nfs4FileInfo::from(a.clone()));
            entries.push(Nfs4DirEntry { name: e.name.clone(), cookie: e.cookie, fh, info });
        })
        .await?;
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
    /// confirmed session ready for OPEN/LOCK operations.
    ///
    /// Every call sends a new verifier, so each session is a new incarnation
    /// of `client_name`: once it is confirmed the server discards whatever
    /// open and lock state an earlier session under that name left behind
    /// (RFC 7530 S16.33.5). That is what lets a caller recover from a
    /// sequence-id mismatch by establishing again. A constant verifier would
    /// do the opposite -- the server would treat the new session as the old
    /// incarnation and keep its stale state.
    pub async fn establish(&self, client_name: &str, callback_addr: &str) -> Result<Nfs4Session, Nfs4Error<T::Error>> {
        // Step 1: SETCLIENTID -- negotiate a clientid.
        let ops = vec![ArgOp::Setclientid { client_verifier: fresh_verifier(), client_id: client_name.as_bytes().to_vec(), cb_program: 0x4000_0000, cb_netid: "tcp".to_owned(), cb_addr: callback_addr.to_owned(), callback_ident: 1 }];
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
        let seqid = session.current_seqid();
        let ops = vec![ArgOp::Putfh(fh.to_vec()), ArgOp::Open { seqid, share_access: 1, share_deny: 0, owner: session.open_owner().clone(), openhow: OpenFlag4::NoCreate, claim: OpenClaim4::Previous(delegation_type) }];
        let res = self.compound(ops).await?;
        session.record_outcome(&res, 1);
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
        let seqid = session.current_seqid();
        let ops = vec![ArgOp::Putfh(dir_fh.to_vec()), ArgOp::Open { seqid, share_access, share_deny, owner: session.open_owner().clone(), openhow: OpenFlag4::NoCreate, claim: OpenClaim4::Null(name.to_owned()) }, ArgOp::Getfh, ArgOp::Getattr(AttrRequest::shell_attrs())];
        let res = self.compound(ops).await?;
        // Index 1 is OPEN. If PUTFH failed it never ran and the seqid is unspent.
        session.record_outcome(&res, 1);
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

        // Extract attributes (index 3: GETATTR).
        let info = match res.results.get(3).map(|op| &op.data) {
            Some(ResOpData::Getattr(attrs)) => Nfs4FileInfo::from(*attrs.clone()),
            _ => return Err(Nfs4Error::MissingResult),
        };

        let mut open_state = OpenState { stateid, fh, share_access, share_deny, delegation, confirmed: false };

        if rflags & OPEN4_RESULT_CONFIRM != 0 {
            let confirm_seqid = session.current_seqid();
            let confirm_ops = vec![ArgOp::Putfh(open_state.fh.clone()), ArgOp::OpenConfirm { stateid: open_state.stateid.to_bytes(), seqid: confirm_seqid }];
            let cres = self.compound(confirm_ops).await?;
            session.record_outcome(&cres, 1);
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
        let seqid = session.current_seqid();
        let ops = vec![ArgOp::Putfh(open_state.fh.clone()), ArgOp::Close { seqid, stateid: open_state.stateid.to_bytes() }];
        let res = self.compound(ops).await?;
        session.record_outcome(&res, 1);
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
    /// closes. Returns `(file_data, file_info)`. CLOSE is sent whether or not
    /// the reads succeed, so a failed transfer does not leave the open behind
    /// until the lease expires; a CLOSE error after a successful read is
    /// ignored, since the data is already in hand.
    ///
    /// Files larger than [`READ_FILE_MAX_BYTES`] fail with
    /// [`Nfs4Error::TooLarge`]: the server controls both the data and the
    /// end-of-file flag, so neither can be the only bound on the allocation.
    pub async fn read_file(&self, session: &Nfs4Session, dir_fh: &[u8], name: &str) -> Result<(Vec<u8>, Nfs4FileInfo), Nfs4Error<T::Error>> {
        let (open_state, info) = self.open_read(session, dir_fh, name).await?;
        let data = self.read_open_file(&open_state).await;
        drop(self.close_file(session, &open_state).await);
        Ok((data?, info))
    }

    /// The READ loop behind [`read_file`](Self::read_file).
    async fn read_open_file(&self, open_state: &OpenState) -> Result<Vec<u8>, Nfs4Error<T::Error>> {
        let mut data = Vec::new();
        let mut offset = 0u64;
        loop {
            let (chunk, eof) = self.read_via_open(open_state, offset, IO_CHUNK).await?;
            if data.len().saturating_add(chunk.len()) > READ_FILE_MAX_BYTES {
                return Err(Nfs4Error::TooLarge { limit: READ_FILE_MAX_BYTES });
            }
            offset += chunk.len() as u64;
            data.extend_from_slice(&chunk);
            if eof || chunk.is_empty() {
                return Ok(data);
            }
        }
    }

    /// Write data to a file via OPEN + WRITE loop + CLOSE.
    ///
    /// Opens the file for writing and writes in 64 KiB chunks, each
    /// `FILE_SYNC4`: the data is on stable storage when each reply arrives, so
    /// there is no COMMIT to fail and no write verifier to watch for a server
    /// restart. A short write is legal, so the offset advances by the count
    /// the server accepted and the rest is resent; a write that accepts
    /// nothing fails with [`Nfs4Error::WriteStalled`].
    ///
    /// Returns the file's attributes after the write. CLOSE is sent whether
    /// or not the writes succeed; a CLOSE error after a successful write is
    /// ignored, since the data is already durable.
    pub async fn write_file(&self, session: &Nfs4Session, dir_fh: &[u8], name: &str, data: &[u8]) -> Result<Nfs4FileInfo, Nfs4Error<T::Error>> {
        let (open_state, _) = self.open_write(session, dir_fh, name).await?;
        let info = match self.write_open_file(&open_state, data).await {
            Ok(()) => self.getattr(open_state.fh()).await,
            Err(e) => Err(e),
        };
        drop(self.close_file(session, &open_state).await);
        info
    }

    /// The WRITE loop behind [`write_file`](Self::write_file).
    async fn write_open_file(&self, open_state: &OpenState, data: &[u8]) -> Result<(), Nfs4Error<T::Error>> {
        let mut offset = 0usize;
        while let Some(rest) = data.get(offset..).filter(|rest| !rest.is_empty()) {
            let chunk = rest.get(..rest.len().min(IO_CHUNK as usize)).unwrap_or(rest);
            let (count, _committed, _verf) = self.write_via_open(open_state, offset as u64, FILE_SYNC4, chunk).await?;
            let accepted = (count as usize).min(chunk.len());
            if accepted == 0 {
                return Err(Nfs4Error::WriteStalled { offset: offset as u64 });
            }
            offset += accepted;
        }
        Ok(())
    }

    // --- Stateful API: byte-range locking (RFC 7530 S16.10-S16.12) ---

    /// Acquire a byte-range lock on an opened file (RFC 7530 S16.10).
    ///
    /// Issues PUTFH + LOCK in one COMPOUND, creating a new lock-owner tied to
    /// the open stateid. That LOCK carries two sequence ids (RFC 7530
    /// sec. 9.1.7): `open_seqid` continues the open-owner's sequence and is
    /// recorded against `session`, while `lock_seqid` starts the new
    /// lock-owner's own sequence. The returned [`LockState`] carries that
    /// sequence for [`unlock`](Self::unlock).
    ///
    /// Each call uses a lock-owner name not used before in this process, so
    /// its sequence always starts fresh.
    pub async fn lock(&self, session: &Nfs4Session, open_state: &OpenState, locktype: LockType4, offset: u64, length: u64) -> Result<LockState, Nfs4Error<T::Error>> {
        static LOCK_OWNERS: AtomicU64 = AtomicU64::new(0);
        let owner = format!("nfswolf-lock-{}", LOCK_OWNERS.fetch_add(1, Ordering::Relaxed));
        let lock_owner = LockOwner4 { clientid: session.clientid(), owner: owner.into_bytes() };
        let locker = Locker4::NewLockOwner { open_seqid: session.current_seqid(), open_stateid: open_state.stateid, lock_seqid: LockState::INITIAL_SEQID, lock_owner: lock_owner.clone() };
        let ops = vec![ArgOp::Putfh(open_state.fh.clone()), ArgOp::Lock { locktype, reclaim: false, offset, length, locker }];
        let res = self.compound(ops).await?;
        session.record_outcome(&res, 1);
        check_status(res.status)?;
        let lock_stateid = match res.results.get(1).map(|op| &op.data) {
            Some(ResOpData::Stateid(sid)) => *sid,
            _ => return Err(Nfs4Error::MissingResult),
        };
        // The LOCK spent INITIAL_SEQID on the new lock-owner's sequence.
        Ok(LockState { lock_stateid, lock_owner, seqid: LockState::INITIAL_SEQID.wrapping_add(1), ranges: vec![LockRange { offset, length, locktype }] })
    }

    /// Release a byte-range lock (RFC 7530 S16.12).
    ///
    /// Issues PUTFH + LOCKU with the lock-owner's seqid from `lock_state`,
    /// then records the outcome there: the sequence advances per RFC 7530
    /// sec. 9.1.7, and on success the new lock stateid replaces the old one
    /// and the released range is dropped from `ranges`. Returns the new lock
    /// stateid.
    pub async fn unlock(&self, fh: &[u8], lock_state: &mut LockState, locktype: LockType4, offset: u64, length: u64) -> Result<Stateid4, Nfs4Error<T::Error>> {
        let ops = vec![ArgOp::Putfh(fh.to_vec()), ArgOp::Locku { locktype, seqid: lock_state.seqid, lock_stateid: lock_state.lock_stateid, offset, length }];
        let res = self.compound(ops).await?;
        lock_state.record_outcome(&res, 1);
        check_status(res.status)?;
        let sid = match res.results.get(1).map(|op| &op.data) {
            Some(ResOpData::Stateid(sid)) => *sid,
            _ => return Err(Nfs4Error::MissingResult),
        };
        lock_state.lock_stateid = sid;
        lock_state.ranges.retain(|r| (r.offset, r.length) != (offset, length));
        Ok(sid)
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

/// A SETCLIENTID verifier that no earlier call in this process has used.
///
/// RFC 7530 S16.33 asks for a verifier that changes when the client restarts.
/// A base taken from the clock and process ID at first use separates
/// processes; the counter separates calls within one.
fn fresh_verifier() -> [u8; 8] {
    static BASE: OnceLock<u64> = OnceLock::new();
    static CALLS: AtomicU64 = AtomicU64::new(0);
    let base = *BASE.get_or_init(|| {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
        now.as_secs().rotate_left(32) ^ u64::from(now.subsec_nanos()) ^ u64::from(std::process::id()).rotate_left(16)
    });
    base.wrapping_add(CALLS.fetch_add(1, Ordering::Relaxed)).to_be_bytes()
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

    // --- Sequence ids against canned replies ---

    /// A transport that answers each call with the next canned COMPOUND reply.
    struct Canned(std::sync::Mutex<std::collections::VecDeque<Vec<u8>>>);

    impl Canned {
        fn client(replies: Vec<Vec<u8>>) -> Nfs4Client<Self> {
            Nfs4Client::new(Self(std::sync::Mutex::new(replies.into())))
        }
    }

    impl RpcTransport for Canned {
        type Error = std::io::Error;

        async fn call<C, R>(&self, _prog: u32, _vers: u32, _proc: u32, _args: &C) -> Result<R, std::io::Error>
        where
            C: onc_xdr::Pack + Send + Sync,
            R: onc_xdr::Unpack,
        {
            let bytes = self.0.lock().unwrap().pop_front().expect("a canned reply per call");
            R::unpack(&mut std::io::Cursor::new(bytes)).map(|(r, _)| r).map_err(std::io::Error::other)
        }

        async fn call_as<C, R>(&self, _cred: onc_rpc_client::rpc::opaque_auth<'static>, prog: u32, vers: u32, proc: u32, args: &C) -> Result<R, std::io::Error>
        where
            C: onc_xdr::Pack + Send + Sync,
            R: onc_xdr::Unpack,
        {
            self.call(prog, vers, proc, args).await
        }
    }

    /// Encode a COMPOUND reply: each op is (opcode, status, result body).
    fn compound_reply(ops: &[(u32, u32, &[u8])]) -> Vec<u8> {
        let status = ops.last().map_or(0, |&(_, st, _)| st);
        let mut wire = Vec::new();
        wire.extend_from_slice(&status.to_be_bytes());
        wire.extend_from_slice(&0u32.to_be_bytes()); // empty tag
        wire.extend_from_slice(&u32::try_from(ops.len()).unwrap().to_be_bytes());
        for &(op, st, body) in ops {
            wire.extend_from_slice(&op.to_be_bytes());
            wire.extend_from_slice(&st.to_be_bytes());
            wire.extend_from_slice(body);
        }
        wire
    }

    const PUTFH: u32 = 22;
    const OPEN: u32 = 18;
    const LOCK: u32 = 12;
    const LOCKU: u32 = 14;

    fn stateid(seqid: u32) -> Vec<u8> {
        let mut sid = seqid.to_be_bytes().to_vec();
        sid.extend_from_slice(&[0xAB; 12]);
        sid
    }

    fn open_state() -> OpenState {
        OpenState { stateid: Stateid4 { seqid: 1, other: [0xCD; 12] }, fh: vec![1, 2, 3, 4], share_access: 3, share_deny: 0, delegation: crate::wire::OpenDelegation4::None, confirmed: true }
    }

    /// The finding's case: PUTFH of a stale directory stops the COMPOUND, OPEN
    /// never runs, and the client must not consume a seqid for it.
    #[tokio::test]
    async fn open_with_stale_directory_does_not_advance_seqid() {
        let session = Nfs4Session::new(7, [0; 8], b"test");
        let client = Canned::client(vec![compound_reply(&[(PUTFH, 70, &[])])]);
        let err = client.open_read(&session, &[9], "f").await.expect_err("stale directory");
        assert!(err.is_stale());
        assert_eq!(session.current_seqid(), 1);
    }

    /// An OPEN that ran and was refused does advance the sequence.
    #[tokio::test]
    async fn refused_open_advances_seqid() {
        let session = Nfs4Session::new(7, [0; 8], b"test");
        let client = Canned::client(vec![compound_reply(&[(PUTFH, 0, &[]), (OPEN, 13, &[])])]);
        let err = client.open_read(&session, &[9], "f").await.expect_err("access denied");
        assert!(err.is_permission_denied());
        assert_eq!(session.current_seqid(), 2);
    }

    /// LOCK spends one open-owner seqid and starts the lock-owner's own
    /// sequence; LOCKU continues the lock-owner's sequence, not the
    /// open-owner's.
    #[tokio::test]
    async fn lock_and_unlock_keep_separate_sequences() {
        let session = Nfs4Session::new(7, [0; 8], b"test");
        let lock_sid = stateid(1);
        let unlock_sid = stateid(2);
        let client = Canned::client(vec![compound_reply(&[(PUTFH, 0, &[]), (LOCK, 0, &lock_sid)]), compound_reply(&[(PUTFH, 0, &[]), (LOCKU, 10026, &[])]), compound_reply(&[(PUTFH, 0, &[]), (LOCKU, 0, &unlock_sid)])]);

        let mut lock = client.lock(&session, &open_state(), LockType4::WriteLt, 0, 10).await.expect("lock");
        assert_eq!(session.current_seqid(), 2, "LOCK continues the open-owner sequence exactly once");
        assert_eq!(lock.seqid, LockState::INITIAL_SEQID + 1, "the new lock-owner's first seqid is spent");

        let err = client.unlock(&[1, 2, 3, 4], &mut lock, LockType4::WriteLt, 0, 10).await.expect_err("bad seqid");
        assert_eq!(err.nfs_status(), Some(Nfs4Status::BadSeqid));
        assert_eq!(lock.seqid, LockState::INITIAL_SEQID + 1, "NFS4ERR_BAD_SEQID leaves the sequence where it was");

        let sid = client.unlock(&[1, 2, 3, 4], &mut lock, LockType4::WriteLt, 0, 10).await.expect("unlock");
        assert_eq!(sid.seqid, 2);
        assert_eq!(lock.lock_stateid.seqid, 2);
        assert_eq!(lock.seqid, LockState::INITIAL_SEQID + 2);
        assert!(lock.ranges.is_empty());
        assert_eq!(session.current_seqid(), 2, "LOCKU does not touch the open-owner sequence");
    }

    const GETFH: u32 = 10;
    const GETATTR: u32 = 9;
    const WRITE: u32 = 38;
    const CLOSE: u32 = 4;

    /// PUTFH + OPEN + GETFH + GETATTR, as `open_write` sends, with no
    /// OPEN_CONFIRM requested.
    fn open_reply() -> Vec<u8> {
        let mut open = stateid(1);
        open.extend_from_slice(&[0; 20]); // change_info4
        open.extend_from_slice(&0u32.to_be_bytes()); // rflags
        open.extend_from_slice(&0u32.to_be_bytes()); // empty attrset
        open.extend_from_slice(&0u32.to_be_bytes()); // OPEN_DELEGATE_NONE
        let mut fh = 4u32.to_be_bytes().to_vec();
        fh.extend_from_slice(&[1, 2, 3, 4]);
        let empty_attrs = [0u8; 8]; // bitmap count 0, attrvals length 0
        compound_reply(&[(PUTFH, 0, &[]), (OPEN, 0, &open), (GETFH, 0, &fh), (GETATTR, 0, &empty_attrs)])
    }

    fn write_reply(count: u32) -> Vec<u8> {
        let mut body = count.to_be_bytes().to_vec();
        body.extend_from_slice(&FILE_SYNC4.to_be_bytes());
        body.extend_from_slice(&[0; 8]);
        compound_reply(&[(PUTFH, 0, &[]), (WRITE, 0, &body)])
    }

    fn close_reply() -> Vec<u8> {
        compound_reply(&[(PUTFH, 0, &[]), (CLOSE, 0, &stateid(2))])
    }

    /// A short write is legal: the rest is resent from where the server
    /// stopped, and the transfer only ends when every byte was accepted.
    #[tokio::test]
    async fn write_file_resends_after_a_short_write() {
        let session = Nfs4Session::new(7, [0; 8], b"test");
        let getattr = compound_reply(&[(PUTFH, 0, &[]), (GETATTR, 0, &[0u8; 8])]);
        let client = Canned::client(vec![open_reply(), write_reply(4), write_reply(6), getattr, close_reply()]);
        let _info = client.write_file(&session, &[9], "f", &[7; 10]).await.expect("write");
        assert!(client.transport().0.lock().unwrap().is_empty(), "every canned reply, CLOSE included, must be used");
        assert_eq!(session.current_seqid(), 3, "OPEN and CLOSE each spend one seqid");
    }

    /// A WRITE that accepts nothing fails the transfer, and the file is still
    /// closed rather than left open until the lease expires.
    #[tokio::test]
    async fn write_file_stops_on_zero_progress_and_still_closes() {
        let session = Nfs4Session::new(7, [0; 8], b"test");
        let client = Canned::client(vec![open_reply(), write_reply(0), close_reply()]);
        let err = client.write_file(&session, &[9], "f", &[7; 10]).await.expect_err("stalled write");
        assert!(matches!(err, Nfs4Error::WriteStalled { offset: 0 }), "got {err:?}");
        assert!(client.transport().0.lock().unwrap().is_empty(), "CLOSE must be sent after a failed write");
    }

    #[test]
    fn verifiers_differ_between_calls() {
        assert_ne!(fresh_verifier(), fresh_verifier(), "each session must be a new incarnation");
    }

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
