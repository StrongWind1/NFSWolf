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
    pub atime_secs: u32,
    pub mtime_secs: u32,
    pub ctime_secs: u32,
    pub used: u64,
    pub rdev: (u32, u32),
    pub fsid: u64,
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
}
