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
    #[cfg_attr(not(feature = "fuse"), allow(dead_code))]
    pub atime_nsecs: u32,
    pub mtime_secs: u64,
    #[cfg_attr(not(feature = "fuse"), allow(dead_code))]
    pub mtime_nsecs: u32,
    pub ctime_secs: u64,
    #[cfg_attr(not(feature = "fuse"), allow(dead_code))]
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
#[cfg_attr(not(feature = "fuse"), allow(dead_code))]
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
#[cfg_attr(not(feature = "fuse"), allow(dead_code))]
pub(crate) enum ShellTimeSpec {
    Now,
    At(u64, u32),
}

/// Filesystem statistics for `df` / FUSE `statfs`.
#[derive(Debug, Clone)]
#[cfg_attr(not(feature = "fuse"), allow(dead_code))]
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

    pub(crate) fn from_hex(hex: &str) -> anyhow::Result<Self> {
        let hex = hex.trim();
        anyhow::ensure!(hex.len().is_multiple_of(2), "hex string must have even length");
        let bytes: Result<Vec<u8>, _> = (0..hex.len()).step_by(2).map(|i| u8::from_str_radix(&hex[i..i + 2], 16)).collect();
        Ok(Self(bytes.map_err(|e| anyhow::anyhow!("invalid hex: {e}"))?))
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

use crate::engine::credential::credential_ladder_with;

/// Caches the winning (uid, gid) for each file handle so the escalation
/// ladder is only walked once per file. Shared across V2Ops, V3Ops, V4Ops.
pub(crate) struct CredCache {
    map: Mutex<std::collections::HashMap<Vec<u8>, (u32, u32)>>,
}

impl CredCache {
    pub(crate) fn new() -> Self {
        Self { map: Mutex::new(std::collections::HashMap::new()) }
    }

    pub(crate) fn flush(&self) {
        self.map.lock().unwrap_or_else(std::sync::PoisonError::into_inner).clear();
    }

    pub(crate) fn get(&self, fh: &[u8]) -> Option<(u32, u32)> {
        self.map.lock().unwrap_or_else(std::sync::PoisonError::into_inner).get(fh).copied()
    }

    pub(crate) fn insert(&self, fh: &[u8], uid: u32, gid: u32) {
        let mut lock = self.map.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let _ = lock.insert(fh.to_vec(), (uid, gid));
    }
}

/// Run an operation with credential escalation: cached -> base -> ladder.
///
/// `op` is called with `(uid, gid)` -- it must build an ephemeral client with
/// those credentials and perform the operation. On success, the winning
/// credential is cached for future calls on the same file handle.
pub(crate) async fn try_with_escalation<T, F, Fut>(caller: (u32, u32), cache: &CredCache, fh: &ShellHandle, get_owner: impl Future<Output = Option<((u32, u32), u32)>> + Send, is_acces: fn(&anyhow::Error) -> bool, op: F, bail_msg: &str) -> anyhow::Result<T>
where
    F: Fn(u32, u32) -> Fut,
    Fut: Future<Output = anyhow::Result<T>>,
{
    // 1. Try cached credential.
    if let Some((uid, gid)) = cache.get(fh.as_bytes()) {
        match op(uid, gid).await {
            Ok(v) => return Ok(v),
            Err(e) if !is_acces(&e) => return Err(e),
            Err(_) => {},
        }
    }

    // 2. Try base credential.
    match op(caller.0, caller.1).await {
        Ok(v) => return Ok(v),
        Err(e) if !is_acces(&e) => return Err(e),
        Err(_) => {},
    }

    // 3. Walk the credential ladder.
    let facts = get_owner.await;
    for (uid, gid) in credential_ladder_with(caller, facts.map(|f| f.0), facts.map(|f| f.1), &[]) {
        match op(uid, gid).await {
            Ok(v) => {
                tracing::debug!(uid, gid, "credential escalation succeeded");
                cache.insert(fh.as_bytes(), uid, gid);
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

    fn read_file(&self, fh: &ShellHandle) -> impl Future<Output = anyhow::Result<Vec<u8>>> + Send;

    fn read_chunk(&self, fh: &ShellHandle, offset: u64, count: u32) -> impl Future<Output = anyhow::Result<Vec<u8>>> + Send;

    fn write_chunk(&self, fh: &ShellHandle, offset: u64, data: &[u8]) -> impl Future<Output = anyhow::Result<u32>> + Send;

    // -- Mutations --

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

    /// Switch the AUTH_SYS identity for subsequent calls.
    ///
    /// Both V2Ops and V3Ops swap the credential on the pooled transport --
    /// zero network round trips. File handles are bearer tokens (RFC 1094
    /// S2.3.3), so they stay valid across identity changes.
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

    /// Retrieve the server's write verifier (reboot oracle, RFC 1813 S3.3.21).
    ///
    /// Only NFSv3 supports COMMIT; v2 returns `Ok(None)`.
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

    /// Build an ephemeral ops instance with different AUTH_SYS credentials.
    ///
    /// The returned instance shares the underlying connection pool but
    /// carries its own credential. Used by the FUSE credential ladder.
    #[cfg_attr(not(feature = "fuse"), expect(dead_code, reason = "used by the FUSE adapter"))]
    fn with_credential(&self, uid: u32, gid: u32, hostname: &str) -> Self
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

    #[test]
    fn shell_handle_empty() {
        let h = ShellHandle(vec![]);
        assert_eq!(h.to_hex(), "");
        assert!(h.as_bytes().is_empty());
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
