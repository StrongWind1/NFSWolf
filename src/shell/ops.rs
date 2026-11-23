//! Version-neutral types and the `ShellOps` trait.
//!
//! Every shell command is written against `ShellOps` rather than a specific
//! NFS version. `V3Ops` and `V2Ops` implement the trait, so the shell gets
//! both versions for free.

// ---------------------------------------------------------------------------
// Shared constants
// ---------------------------------------------------------------------------

/// Read/write chunk size used by `get`, `put`, and the `read_file` helpers.
pub(crate) const CHUNK_SIZE: u32 = 65_536; // 64 KiB

/// Maximum bytes read by `read_file` / `download_file` before bailing.
pub(crate) const READ_ALL_MAX: u64 = 256 * 1024 * 1024; // 256 MiB

/// Largest READ or WRITE payload `get` and `put` will issue, whatever the
/// server advertises.
///
/// Linux knfsd advertises 1 MiB. Bounding it keeps a server that claims a
/// huge transfer size from making each in-flight request a large allocation,
/// and stays well under the RPC client's 8 MiB reply limit.
pub(crate) const MAX_IO_SIZE: u32 = 1024 * 1024;

/// Smallest transfer size taken from a server; a smaller advertised value is
/// treated as a misreport and replaced by [`CHUNK_SIZE`].
pub(crate) const MIN_IO_SIZE: u32 = 4096;

/// Transfer sizes for one file, in bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct IoSizes {
    pub read: u32,
    pub write: u32,
}

impl IoSizes {
    /// What `get` and `put` use when the server does not say.
    pub(crate) const DEFAULT: Self = Self { read: CHUNK_SIZE, write: CHUNK_SIZE };

    /// Sizes from server-advertised values, each clamped to
    /// [`MIN_IO_SIZE`]..=[`MAX_IO_SIZE`] or replaced by the default when
    /// missing or implausibly small.
    pub(crate) fn from_server(read: Option<u64>, write: Option<u64>) -> Self {
        let pick = |v: Option<u64>| v.filter(|&n| n >= u64::from(MIN_IO_SIZE)).map_or(CHUNK_SIZE, |n| u32::try_from(n.min(u64::from(MAX_IO_SIZE))).unwrap_or(MAX_IO_SIZE));
        Self { read: pick(read), write: pick(write) }
    }
}

/// Result of [`ShellOps::read_at`].
#[derive(Debug, Clone, Default)]
pub(crate) struct ReadReply {
    pub data: Vec<u8>,
    /// The server says no data follows this reply.
    pub eof: bool,
}

/// Result of [`ShellOps::write_unstable`].
#[derive(Debug, Clone, Copy)]
pub(crate) struct WriteReply {
    /// Bytes the server accepted.
    pub count: u32,
    /// Whether the data is already on stable storage.
    pub stable: bool,
    /// The write verifier, for comparing against a later COMMIT. `None` when
    /// the write was stable and there is nothing to check.
    pub verifier: Option<[u8; 8]>,
}

// ---------------------------------------------------------------------------
// Version-neutral types
// ---------------------------------------------------------------------------

/// File type, covering the union of NFSv2 `FType` and NFSv3 `FileType`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ShellFileType {
    Regular,
    Directory,
    Block,
    Character,
    Symlink,
    Socket,
    Fifo,
    Unknown,
}

impl ShellFileType {
    pub(crate) fn letter(self) -> char {
        match self {
            Self::Regular => '-',
            Self::Directory => 'd',
            Self::Block => 'b',
            Self::Character => 'c',
            Self::Symlink => 'l',
            Self::Socket => 's',
            Self::Fifo => 'p',
            Self::Unknown => '?',
        }
    }
}

/// Version-neutral file attributes.
#[derive(Debug, Clone)]
pub(crate) struct ShellFileInfo {
    pub file_type: ShellFileType,
    pub mode: u32,
    pub nlink: u32,
    pub uid: u32,
    pub gid: u32,
    pub size: u64,
    pub fileid: u64,
    pub atime_secs: u64,
    #[cfg_attr(not(feature = "fuse"), expect(dead_code, reason = "read by the FUSE adapter"))]
    pub atime_nsecs: u32,
    pub mtime_secs: u64,
    #[cfg_attr(not(feature = "fuse"), expect(dead_code, reason = "read by the FUSE adapter"))]
    pub mtime_nsecs: u32,
    pub ctime_secs: u64,
    #[cfg_attr(not(feature = "fuse"), expect(dead_code, reason = "read by the FUSE adapter"))]
    pub ctime_nsecs: u32,
    pub used: u64,
    pub rdev: (u32, u32),
    pub fsid: u64,
}

/// Typed NFS error for FUSE errno mapping.
///
/// Embedded in `anyhow::Error` chains by ShellOps implementations so the FUSE
/// adapter can downcast to a specific errno instead of defaulting to EIO.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ShellError {
    Perm,
    NoEnt,
    Io,
    Nxio,
    Acces,
    Exist,
    Xdev,
    NotDir,
    IsDir,
    Inval,
    FBig,
    NoSpc,
    Rofs,
    NameTooLong,
    NotEmpty,
    Dquot,
    Stale,
    NotSupp,
    BadHandle,
    ServerFault,
}

impl std::fmt::Display for ShellError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Perm => "EPERM",
            Self::NoEnt => "ENOENT",
            Self::Io => "EIO",
            Self::Nxio => "ENXIO",
            Self::Acces => "EACCES",
            Self::Exist => "EEXIST",
            Self::Xdev => "EXDEV",
            Self::NotDir => "ENOTDIR",
            Self::IsDir => "EISDIR",
            Self::Inval => "EINVAL",
            Self::FBig => "EFBIG",
            Self::NoSpc => "ENOSPC",
            Self::Rofs => "EROFS",
            Self::NameTooLong => "ENAMETOOLONG",
            Self::NotEmpty => "ENOTEMPTY",
            Self::Dquot => "EDQUOT",
            Self::Stale => "ESTALE",
            Self::NotSupp => "ENOTSUP",
            Self::BadHandle => "EBADF",
            Self::ServerFault => "EIO (server fault)",
        })
    }
}

impl std::error::Error for ShellError {}

impl From<nfs_v3::Nfs3Error> for ShellError {
    fn from(e: nfs_v3::Nfs3Error) -> Self {
        use nfs_v3::Nfs3Error as E;
        match e {
            E::Perm => Self::Perm,
            E::NoEnt => Self::NoEnt,
            E::Nxio | E::Nodev => Self::Nxio,
            E::Acces => Self::Acces,
            E::Exist => Self::Exist,
            E::Xdev => Self::Xdev,
            E::NotDir => Self::NotDir,
            E::IsDir => Self::IsDir,
            E::Inval => Self::Inval,
            E::Fbig => Self::FBig,
            E::Nospc => Self::NoSpc,
            E::Rofs => Self::Rofs,
            E::NameTooLong => Self::NameTooLong,
            E::NotEmpty => Self::NotEmpty,
            E::Dquot => Self::Dquot,
            E::Stale => Self::Stale,
            E::BadHandle => Self::BadHandle,
            E::NotSupp => Self::NotSupp,
            E::ServerFault => Self::ServerFault,
            _ => Self::Io,
        }
    }
}

impl From<nfs_v4::wire::Nfs4Status> for ShellError {
    fn from(s: nfs_v4::wire::Nfs4Status) -> Self {
        use nfs_v4::wire::Nfs4Status as S;
        match s {
            S::Perm => Self::Perm,
            S::NoEnt => Self::NoEnt,
            S::Nxio => Self::Nxio,
            S::Acces => Self::Acces,
            S::Exist => Self::Exist,
            S::NotDir => Self::NotDir,
            S::IsDir => Self::IsDir,
            S::Inval => Self::Inval,
            S::Fbig => Self::FBig,
            S::NoSpc => Self::NoSpc,
            S::Rofs => Self::Rofs,
            S::NameTooLong => Self::NameTooLong,
            S::NotEmpty => Self::NotEmpty,
            S::Stale => Self::Stale,
            S::BadHandle => Self::BadHandle,
            S::NotSupp => Self::NotSupp,
            S::Dquot => Self::Dquot,
            _ => Self::Io,
        }
    }
}

impl From<nfs_v2::wire::Nfs2Stat> for ShellError {
    fn from(s: nfs_v2::wire::Nfs2Stat) -> Self {
        use nfs_v2::wire::Nfs2Stat as S;
        match s {
            S::Perm => Self::Perm,
            S::NoEnt => Self::NoEnt,
            S::Nxio | S::NoDev => Self::Nxio,
            S::Acces => Self::Acces,
            S::Exist => Self::Exist,
            S::NotDir => Self::NotDir,
            S::IsDir => Self::IsDir,
            S::Fbig => Self::FBig,
            S::NoSpc => Self::NoSpc,
            S::Rofs => Self::Rofs,
            S::NameTooLong => Self::NameTooLong,
            S::NotEmpty => Self::NotEmpty,
            S::Dquot => Self::Dquot,
            S::Stale => Self::Stale,
            _ => Self::Io,
        }
    }
}

#[cfg(feature = "fuse")]
impl ShellError {
    pub(crate) fn to_errno(self) -> libc::c_int {
        match self {
            Self::Perm => libc::EPERM,
            Self::NoEnt => libc::ENOENT,
            Self::Io | Self::ServerFault => libc::EIO,
            Self::Nxio => libc::ENXIO,
            Self::Acces => libc::EACCES,
            Self::Exist => libc::EEXIST,
            Self::Xdev => libc::EXDEV,
            Self::NotDir => libc::ENOTDIR,
            Self::IsDir => libc::EISDIR,
            Self::Inval => libc::EINVAL,
            Self::FBig => libc::EFBIG,
            Self::NoSpc => libc::ENOSPC,
            Self::Rofs => libc::EROFS,
            Self::NameTooLong => libc::ENAMETOOLONG,
            Self::NotEmpty => libc::ENOTEMPTY,
            Self::Dquot => libc::EDQUOT,
            Self::Stale => libc::ESTALE,
            Self::NotSupp => libc::ENOTSUP,
            Self::BadHandle => libc::EBADF,
        }
    }
}

/// Extract errno from an anyhow error chain containing a `ShellError`.
#[cfg(feature = "fuse")]
pub(crate) fn shell_err_to_errno(e: &anyhow::Error) -> libc::c_int {
    for cause in e.chain() {
        if let Some(se) = cause.downcast_ref::<ShellError>() {
            return se.to_errno();
        }
    }
    libc::EIO
}

/// Atomic setattr request. Each field is `None` = don't change.
#[derive(Debug, Clone, Default)]
pub(crate) struct ShellSetAttr {
    pub mode: Option<u32>,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    pub size: Option<u64>,
    pub atime: Option<ShellTimeSpec>,
    pub mtime: Option<ShellTimeSpec>,
}

/// Timestamp value for `ShellSetAttr`.
#[derive(Debug, Clone, Copy)]
#[cfg_attr(not(feature = "fuse"), expect(dead_code, reason = "read by the FUSE adapter"))]
pub(crate) enum ShellTimeSpec {
    Now,
    At(u64, u32),
}

/// Filesystem statistics for `df` / FUSE `statfs`.
#[derive(Debug, Clone)]
#[cfg_attr(not(feature = "fuse"), expect(dead_code, reason = "read by the FUSE adapter"))]
pub(crate) struct ShellFsStat {
    pub total_bytes: u64,
    pub free_bytes: u64,
    pub avail_bytes: u64,
    pub total_files: u64,
    pub free_files: u64,
    pub block_size: u32,
}

impl ShellFileInfo {
    pub(crate) fn mode_string(&self) -> String {
        let mut s = String::with_capacity(10);
        s.push(self.file_type.letter());
        s.push_str(&format_rwx(self.mode));
        s
    }

    pub(crate) fn type_name(&self) -> &'static str {
        match self.file_type {
            ShellFileType::Regular => "REG",
            ShellFileType::Directory => "DIR",
            ShellFileType::Block => "BLK",
            ShellFileType::Character => "CHR",
            ShellFileType::Symlink => "LNK",
            ShellFileType::Socket => "SOCK",
            ShellFileType::Fifo => "FIFO",
            ShellFileType::Unknown => "???",
        }
    }
}

/// Format a Unix permission mode word as `rwxrwxrwx` (9 chars, no type prefix).
///
/// Shared implementation used by both `ShellFileInfo::mode_string()` (which
/// prepends the type letter) and the `ls` column formatter in the shell.
pub(crate) fn format_rwx(mode: u32) -> String {
    let bits = [(0o400, 'r'), (0o200, 'w'), (0o100, 'x'), (0o040, 'r'), (0o020, 'w'), (0o010, 'x'), (0o004, 'r'), (0o002, 'w'), (0o001, 'x')];
    bits.iter().map(|(mask, ch)| if mode & mask != 0 { *ch } else { '-' }).collect()
}

/// One directory entry returned by `ShellOps::list_dir`.
#[derive(Debug, Clone)]
pub(crate) struct ShellEntry {
    pub name: String,
    pub info: Option<ShellFileInfo>,
    pub handle: Option<ShellHandle>,
}

/// Opaque file handle that works for both v2 (fixed 32) and v3 (variable).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct ShellHandle(pub Vec<u8>);

impl ShellHandle {
    pub(crate) fn to_hex(&self) -> String {
        use std::fmt::Write;
        let mut s = String::with_capacity(self.0.len() * 2);
        for b in &self.0 {
            // Infallible: fmt::Write for String never fails.
            let _ = write!(s, "{b:02x}");
        }
        s
    }

    /// Parse a handle (or any other byte string) given as hex.
    ///
    /// Same syntax everywhere the tool reads hex: see [`nfs_v3::decode_hex`].
    pub(crate) fn from_hex(hex: &str) -> anyhow::Result<Self> {
        nfs_v3::decode_hex(hex).map(Self).map_err(anyhow::Error::from)
    }

    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Device type for `ShellOps::mknod`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ShellDeviceType {
    Char,
    Block,
}

// ---------------------------------------------------------------------------
// Credential escalation cache
// ---------------------------------------------------------------------------

use std::sync::Mutex;

use crate::engine::credential::identity_ladder;
pub(crate) use crate::engine::credential::{Identity, ObservedIdentities};

/// Caches the winning identity for each file handle so the escalation
/// ladder is only walked once per file, and counts the identities seen
/// owning files so the ladder can try them. Shared across V2Ops, V3Ops, V4Ops.
pub(crate) struct CredCache {
    map: Mutex<std::collections::HashMap<Vec<u8>, Identity>>,
    /// Owners and groups seen in listings and lookups (READDIRPLUS, LOOKUP).
    /// Survives an identity switch, and is shared with the clones
    /// `ShellOps::with_credential` makes: who owns the files does not change.
    pub(crate) observed: std::sync::Arc<ObservedIdentities>,
}

impl CredCache {
    pub(crate) fn new() -> Self {
        Self { map: Mutex::new(std::collections::HashMap::new()), observed: std::sync::Arc::default() }
    }

    /// An empty cache that shares this one's observations, for a backend
    /// clone carrying a different identity.
    pub(crate) fn sharing_observations(&self) -> Self {
        Self { map: Mutex::new(std::collections::HashMap::new()), observed: std::sync::Arc::clone(&self.observed) }
    }

    pub(crate) fn flush(&self) {
        self.map.lock().unwrap_or_else(std::sync::PoisonError::into_inner).clear();
    }

    pub(crate) fn get(&self, fh: &[u8]) -> Option<Identity> {
        self.map.lock().unwrap_or_else(std::sync::PoisonError::into_inner).get(fh).cloned()
    }

    pub(crate) fn insert(&self, fh: &[u8], id: Identity) {
        let mut lock = self.map.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        drop(lock.insert(fh.to_vec(), id));
    }
}

/// Record the owner of every listed entry that came with attributes.
pub(crate) fn observe_entries(observed: &ObservedIdentities, entries: &[ShellEntry]) {
    observed.record(entries.iter().filter_map(|e| e.info.as_ref()).map(|i| (i.uid, i.gid)));
}

/// Run an operation with credential escalation: cached -> caller -> ladder.
///
/// `op` is called with an [`Identity`] -- it must build an ephemeral client
/// carrying that identity (UID, primary GID and supplementary groups) and
/// perform the operation. The caller's own identity is tried as given, so
/// `--aux-gids` reaches the server; the ladder rungs after it claim the
/// file's group and the observed groups too (see `engine::credential`). On
/// success the winning identity is cached for later calls on the same handle.
pub(crate) async fn try_with_escalation<T, F, Fut>(caller: &Identity, cache: &CredCache, fh: &ShellHandle, get_owner: impl Future<Output = Option<((u32, u32), u32)>> + Send, is_acces: fn(&anyhow::Error) -> bool, op: F, bail_msg: &str) -> anyhow::Result<T>
where
    F: Fn(Identity) -> Fut,
    Fut: Future<Output = anyhow::Result<T>>,
{
    let mut tried: Vec<Identity> = Vec::with_capacity(2);

    // 1. Try the cached identity.
    if let Some(id) = cache.get(fh.as_bytes()) {
        tried.push(id.clone());
        match op(id).await {
            Ok(v) => return Ok(v),
            Err(e) if !is_acces(&e) => return Err(e),
            Err(_) => {},
        }
    }

    // 2. Try the caller's identity.
    if !tried.contains(caller) {
        tried.push(caller.clone());
        match op(caller.clone()).await {
            Ok(v) => return Ok(v),
            Err(e) if !is_acces(&e) => return Err(e),
            Err(_) => {},
        }
    }

    // 3. Walk the credential ladder.
    let facts = get_owner.await;
    for id in identity_ladder(caller, facts.map(|f| f.0), facts.map(|f| f.1), &cache.observed) {
        if tried.contains(&id) {
            continue;
        }
        match op(id.clone()).await {
            Ok(v) => {
                tracing::debug!(uid = id.uid, gid = id.gid, groups = ?id.groups, "credential escalation succeeded");
                cache.insert(fh.as_bytes(), id);
                return Ok(v);
            },
            Err(e) if !is_acces(&e) => return Err(e),
            Err(_) => {},
        }
    }

    anyhow::bail!("{bail_msg}")
}

// ---------------------------------------------------------------------------
// The trait
// ---------------------------------------------------------------------------

/// Backend operations the shell dispatches through.
///
/// One implementation per NFS version. The shell is generic over this trait
/// so every command is written once.
pub(crate) trait ShellOps: Send + Sync + 'static {
    // -- Navigation --

    fn lookup(&self, dir: &ShellHandle, name: &str) -> impl Future<Output = anyhow::Result<(ShellHandle, ShellFileInfo)>> + Send;

    fn lookup_path(&self, start: &ShellHandle, path: &str) -> impl Future<Output = anyhow::Result<(ShellHandle, ShellFileInfo)>> + Send;

    fn getattr(&self, fh: &ShellHandle) -> impl Future<Output = anyhow::Result<ShellFileInfo>> + Send;

    // -- Directory listing --

    fn list_dir(&self, dir: &ShellHandle) -> impl Future<Output = anyhow::Result<Vec<ShellEntry>>> + Send;

    // -- File I/O --

    /// Read the whole file into memory through the pipelined transfer engine
    /// ([`read_whole`](crate::shell::transfer::read_whole)), capped at
    /// [`READ_ALL_MAX`].
    ///
    /// `size_hint` is the size a lookup or listing reported, or 0 when unknown:
    /// it only sets how far reads run ahead, and the file is read to its end
    /// either way.
    fn read_file(&self, fh: &ShellHandle, size_hint: u64) -> impl Future<Output = anyhow::Result<Vec<u8>>> + Send
    where
        Self: Sized,
    {
        // Boxed: the transfer's state is large, and every command that reads a
        // file would otherwise carry it inline.
        async move { Box::pin(crate::shell::transfer::read_whole(self, fh, size_hint)).await }
    }

    /// READ up to `count` bytes at `offset`, with the server's end-of-file
    /// flag. A short reply mid-file is legal and is not end-of-file.
    fn read_at(&self, fh: &ShellHandle, offset: u64, count: u32) -> impl Future<Output = anyhow::Result<ReadReply>> + Send;

    /// [`read_at`](Self::read_at) without the end-of-file flag.
    #[cfg_attr(not(feature = "fuse"), expect(dead_code, reason = "used by the FUSE adapter"))]
    fn read_chunk(&self, fh: &ShellHandle, offset: u64, count: u32) -> impl Future<Output = anyhow::Result<Vec<u8>>> + Send {
        async move { Ok(self.read_at(fh, offset, count).await?.data) }
    }

    /// WRITE `data` at `offset`, durably: the reply arrives once the data is
    /// on stable storage. Returns the bytes accepted.
    fn write_chunk(&self, fh: &ShellHandle, offset: u64, data: &[u8]) -> impl Future<Output = anyhow::Result<u32>> + Send;

    /// WRITE `data` at `offset` without waiting for stable storage.
    ///
    /// Much faster on a disk-backed server, which otherwise syncs on every
    /// write, but the data is only safe after [`write_verifier`](Self::write_verifier)
    /// (a COMMIT) returns the verifier this write did. The default writes
    /// stably, for versions with no unstable write (NFSv2).
    fn write_unstable(&self, fh: &ShellHandle, offset: u64, data: &[u8]) -> impl Future<Output = anyhow::Result<WriteReply>> + Send {
        async move { Ok(WriteReply { count: self.write_chunk(fh, offset, data).await?, stable: true, verifier: None }) }
    }

    /// The READ and WRITE sizes to use for `fh`, from what the server
    /// advertises. Never fails: a server that will not say gets the default.
    fn io_sizes(&self, _fh: &ShellHandle) -> impl Future<Output = IoSizes> + Send {
        async { IoSizes::DEFAULT }
    }

    // -- Mutations --

    /// Create `name` in `dir`, or truncate it to empty if it already exists:
    /// every caller is about to write the file's whole new contents.
    fn create_file(&self, dir: &ShellHandle, name: &str, mode: u32) -> impl Future<Output = anyhow::Result<ShellHandle>> + Send;

    fn mkdir(&self, dir: &ShellHandle, name: &str, mode: u32) -> impl Future<Output = anyhow::Result<ShellHandle>> + Send;

    fn remove(&self, dir: &ShellHandle, name: &str) -> impl Future<Output = anyhow::Result<()>> + Send;

    fn rmdir(&self, dir: &ShellHandle, name: &str) -> impl Future<Output = anyhow::Result<()>> + Send;

    fn rename(&self, from_dir: &ShellHandle, from: &str, to_dir: &ShellHandle, to: &str) -> impl Future<Output = anyhow::Result<()>> + Send;

    fn symlink(&self, dir: &ShellHandle, name: &str, target: &str) -> impl Future<Output = anyhow::Result<()>> + Send;

    fn hard_link(&self, fh: &ShellHandle, dir: &ShellHandle, name: &str) -> impl Future<Output = anyhow::Result<()>> + Send;

    fn mknod(&self, dir: &ShellHandle, name: &str, dev_type: ShellDeviceType, major: u32, minor: u32, mode: u32) -> impl Future<Output = anyhow::Result<ShellHandle>> + Send;

    fn readlink(&self, fh: &ShellHandle) -> impl Future<Output = anyhow::Result<String>> + Send;

    fn set_mode(&self, fh: &ShellHandle, mode: u32) -> impl Future<Output = anyhow::Result<()>> + Send;

    fn set_owner(&self, fh: &ShellHandle, uid: Option<u32>, gid: Option<u32>) -> impl Future<Output = anyhow::Result<()>> + Send;

    // -- Identity --

    fn uid(&self) -> u32;
    fn gid(&self) -> u32;
    fn machinename(&self) -> &str;

    /// The full AUTH_SYS identity calls go out under: UID, primary GID and the
    /// supplementary groups from `--gid`/`--aux-gids`.
    fn identity(&self) -> Identity;

    /// Owners and groups seen so far on this session, for the ladder.
    fn observed(&self) -> &ObservedIdentities;

    /// Switch the AUTH_SYS identity for subsequent calls.
    ///
    /// Every backend swaps the credential on the pooled transport -- zero
    /// network round trips -- and keeps the operator's supplementary groups.
    /// File handles are bearer tokens (RFC 1094 S2.3.3), so they stay valid
    /// across identity changes.
    fn change_identity(&mut self, uid: u32, gid: u32, hostname: &str) -> anyhow::Result<()>;

    // -- Capabilities --

    fn version_name(&self) -> &'static str;
    fn supports_mknod(&self) -> bool;

    fn supports_identity_change(&self) -> bool;

    /// Tab-completable command list for this NFS version.
    fn commands(&self) -> &'static [&'static str];

    fn make_completer(&self) -> Box<dyn crate::shell::complete::RemoteCompleter>;

    /// V2-only: probe NFSPROC_ROOT (obsolete MOUNT bypass check).
    /// Returns `Ok(None)` on versions that don't support it.
    fn probe_root(&self) -> impl Future<Output = anyhow::Result<Option<ShellHandle>>> + Send {
        async { Ok(None) }
    }

    /// COMMIT the whole file and return the server's write verifier (RFC 1813
    /// S3.3.21: offset 0, count 0 flushes to end of file).
    ///
    /// Doubles as the reboot oracle, and as the check that
    /// [`write_unstable`](Self::write_unstable) data survived. NFSv2 has no
    /// COMMIT and returns `Ok(None)`.
    fn write_verifier(&self, _fh: &ShellHandle) -> impl Future<Output = anyhow::Result<Option<[u8; 8]>>> + Send {
        async { Ok(None) }
    }

    // -- FUSE-required operations --

    /// Advisory permission check (NFSv3 ACCESS / NFSv4 ACCESS).
    ///
    /// Returns the subset of `mask` bits the server grants. NFSv2 has no
    /// ACCESS procedure, so V2Ops returns `Ok(mask)` (all granted).
    #[cfg_attr(not(feature = "fuse"), expect(dead_code, reason = "used by the FUSE adapter"))]
    fn access(&self, _fh: &ShellHandle, mask: u32) -> impl Future<Output = anyhow::Result<u32>> + Send {
        async move { Ok(mask) }
    }

    /// Atomic attribute update (mode, owner, size, timestamps).
    #[cfg_attr(not(feature = "fuse"), expect(dead_code, reason = "used by the FUSE adapter"))]
    fn setattr(&self, fh: &ShellHandle, attrs: ShellSetAttr) -> impl Future<Output = anyhow::Result<ShellFileInfo>> + Send;

    /// Filesystem statistics for `df`.
    #[cfg_attr(not(feature = "fuse"), expect(dead_code, reason = "used by the FUSE adapter"))]
    fn statfs(&self, fh: &ShellHandle) -> impl Future<Output = anyhow::Result<ShellFsStat>> + Send;

    /// Flush uncommitted writes to stable storage. No-op on NFSv2.
    #[cfg_attr(not(feature = "fuse"), expect(dead_code, reason = "used by the FUSE adapter"))]
    fn commit(&self, _fh: &ShellHandle) -> impl Future<Output = anyhow::Result<()>> + Send {
        async { Ok(()) }
    }

    /// Build an ephemeral ops instance carrying a different AUTH_SYS identity.
    ///
    /// The returned instance shares the underlying connection pool but
    /// carries its own credential. Used by the FUSE credential ladder.
    #[cfg_attr(not(feature = "fuse"), expect(dead_code, reason = "used by the FUSE adapter"))]
    fn with_credential(&self, id: &Identity, hostname: &str) -> Self
    where
        Self: Sized;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_rwx_common_modes() {
        assert_eq!(format_rwx(0o777), "rwxrwxrwx");
        assert_eq!(format_rwx(0o000), "---------");
        assert_eq!(format_rwx(0o644), "rw-r--r--");
        assert_eq!(format_rwx(0o755), "rwxr-xr-x");
        assert_eq!(format_rwx(0o700), "rwx------");
        assert_eq!(format_rwx(0o100), "--x------");
    }

    #[test]
    fn shell_handle_hex_round_trip() {
        let handle = ShellHandle(vec![0x00, 0x0a, 0xff, 0x42]);
        let hex = handle.to_hex();
        assert_eq!(hex, "000aff42");
        let parsed = ShellHandle::from_hex(&hex).unwrap();
        assert_eq!(parsed, handle);
    }

    #[test]
    fn shell_handle_from_hex_whitespace() {
        let h = ShellHandle::from_hex("  0a0b  ").unwrap();
        assert_eq!(h.0, vec![0x0a, 0x0b]);
    }

    #[test]
    fn shell_handle_from_hex_odd_length_rejected() {
        assert!(ShellHandle::from_hex("abc").is_err());
    }

    #[test]
    fn shell_handle_from_hex_invalid_chars_rejected() {
        assert!(ShellHandle::from_hex("zzzz").is_err());
    }

    /// A multi-byte character in an even-length input used to panic on a
    /// char-boundary slice and end the session.
    #[test]
    fn shell_handle_from_hex_non_ascii_is_an_error() {
        assert!(ShellHandle::from_hex("a\u{e9}1").is_err());
        assert!(ShellHandle::from_hex("+1+2").is_err());
    }

    #[test]
    fn shell_handle_empty() {
        let h = ShellHandle(vec![]);
        assert_eq!(h.to_hex(), "");
        assert!(h.as_bytes().is_empty());
    }

    /// `--aux-gids` must reach the server on the very first attempt: the
    /// reported failure was uid 0 with group 522 under root_squash, where only
    /// the group grants access.
    #[tokio::test]
    async fn escalation_sends_the_operators_groups() {
        let cache = CredCache::new();
        let caller = Identity::new(0, 0, &[522]);
        let tried = Mutex::new(Vec::new());
        let got = try_with_escalation(
            &caller,
            &cache,
            &ShellHandle(vec![1]),
            async { Some(((1001, 522), 0o640)) },
            |_| true,
            |id| {
                tried.lock().unwrap().push(id.clone());
                async move { if id.groups.contains(&522) { Ok(id.uid) } else { anyhow::bail!("NFS3ERR_ACCES") } }
            },
            "exhausted",
        )
        .await
        .unwrap();
        assert_eq!(got, 0);
        assert_eq!(tried.lock().unwrap().len(), 1, "the caller's own identity, groups included, works first time");
    }

    /// An owner-only file: the ladder must reach the owner's UID, and the
    /// winner is cached for the next call on that handle.
    #[tokio::test]
    async fn escalation_finds_the_owner_and_caches_it() {
        let cache = CredCache::new();
        let fh = ShellHandle(vec![2]);
        let op = async |id: Identity| if id.uid == 1001 { Ok(()) } else { anyhow::bail!("NFS3ERR_ACCES") };
        try_with_escalation(&Identity::new(0, 0, &[]), &cache, &fh, async { Some(((1001, 1001), 0o600)) }, |_| true, op, "exhausted").await.unwrap();
        assert_eq!(cache.get(fh.as_bytes()).map(|id| id.uid), Some(1001));
    }

    #[test]
    fn shell_file_type_letters() {
        assert_eq!(ShellFileType::Regular.letter(), '-');
        assert_eq!(ShellFileType::Directory.letter(), 'd');
        assert_eq!(ShellFileType::Symlink.letter(), 'l');
        assert_eq!(ShellFileType::Block.letter(), 'b');
        assert_eq!(ShellFileType::Character.letter(), 'c');
        assert_eq!(ShellFileType::Socket.letter(), 's');
        assert_eq!(ShellFileType::Fifo.letter(), 'p');
        assert_eq!(ShellFileType::Unknown.letter(), '?');
    }
}
