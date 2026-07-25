//! Version-neutral types and the `ShellOps` trait.
//!
//! Every shell command is written against `ShellOps` rather than a specific
//! NFS version. `V3Ops` and `V2Ops` implement the trait, so the shell gets
//! both versions for free.


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
}

impl ShellFileInfo {
    pub(crate) fn mode_string(&self) -> String {
        let mut s = String::with_capacity(10);
        s.push(self.file_type.letter());
        let rwx = b"xwr";
        for shift in (0..9).rev() {
            let ch = rwx.get(shift % 3).map_or(b'?', |c| *c);
            s.push(if self.mode & (1 << shift) != 0 { ch as char } else { '-' });
        }
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

/// One directory entry returned by `ShellOps::list_dir`.
#[derive(Debug, Clone)]
pub(crate) struct ShellEntry {
    pub name: String,
    pub info: Option<ShellFileInfo>,
}

/// Opaque file handle that works for both v2 (fixed 32) and v3 (variable).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct ShellHandle(pub Vec<u8>);

impl ShellHandle {
    pub(crate) fn to_hex(&self) -> String {
        use std::fmt::Write;
        let mut s = String::with_capacity(self.0.len() * 2);
        for b in &self.0 {
            let _ = write!(s, "{b:02x}");
        }
        s
    }

    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.0
    }
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

    fn readlink(&self, fh: &ShellHandle) -> impl Future<Output = anyhow::Result<String>> + Send;

    fn set_mode(&self, fh: &ShellHandle, mode: u32) -> impl Future<Output = anyhow::Result<()>> + Send;

    fn set_owner(&self, fh: &ShellHandle, uid: Option<u32>, gid: Option<u32>) -> impl Future<Output = anyhow::Result<()>> + Send;

    // -- Identity --

    fn uid(&self) -> u32;
    fn gid(&self) -> u32;
    fn machinename(&self) -> &str;

    /// Switch the AUTH_SYS identity for subsequent calls.
    ///
    /// V3Ops rebuilds the pooled client and flushes the credential cache.
    /// V2Ops returns an error since the DirectTransport credential is fixed
    /// at construction time (reconnection would be needed).
    fn change_identity(&mut self, uid: u32, gid: u32, hostname: &str) -> anyhow::Result<()>;

    // -- Capabilities --

    fn version_name(&self) -> &'static str;
    fn supports_mknod(&self) -> bool;

    /// V2-only: probe NFSPROC_ROOT (obsolete MOUNT bypass check).
    /// Returns `Ok(None)` on versions that don't support it.
    fn probe_root(&self) -> impl Future<Output = anyhow::Result<Option<ShellHandle>>> + Send {
        async { Ok(None) }
    }
}
