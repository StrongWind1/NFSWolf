//! FUSE filesystem adapter  --  mounts an NFS export as a local filesystem.
//!
//! Generic over `ShellOps`, so the same FUSE adapter works for NFSv2, v3,
//! and v4 backends. Wires every `ShellOps` method through a fuser callback
//! so the local mount behaves like a normal POSIX filesystem (subject to
//! `--allow-write` for destructive operations). Always-on behaviors:
//!
//! - **Server-side symlink resolution.** When `lookup` lands on a symlink,
//!   we issue READLINK and re-resolve the target relative to the parent (or
//!   the FUSE root for absolute paths). The local kernel never sees the
//!   underlying symlink, so `cd /mnt/link` enters the server-side target
//!   rather than dereferencing locally. A depth cap blocks loops.
//! - **Null-attr readdir fix-up.** Some servers return entries with missing
//!   attributes or handles. We re-LOOKUP those entries so the kernel sees
//!   complete metadata.
//! - **Auto-UID ladder (always on).** Any callback that returns EACCES
//!   triggers the same credential-escalation ladder the interactive shell
//!   uses (`engine::credential::credential_ladder`), and the resolved
//!   (uid, gid) is cached per inode so future calls skip the search.
//!
//! fuser calls are synchronous but the NFS client is async. We capture a
//! `tokio::runtime::Handle` at construction time and call `block_on` on
//! it from the fuser worker threads -- those threads are not Tokio tasks,
//! so blocking them does not stall the runtime that drives the pool.
//!
//! Toolkit API  --  not all items are used in currently-implemented phases.

use std::collections::HashMap;
use std::path::Path;
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use fuser::{
    AccessFlags, BsdFileFlags, Errno, FileAttr, FileHandle as FuseFileHandle, FileType as FuseFileType, Filesystem, FopenFlags, Generation, INodeNo, LockOwner, OpenFlags, RenameFlags, ReplyAttr, ReplyCreate, ReplyData, ReplyDirectory, ReplyEmpty, ReplyEntry, ReplyStatfs, ReplyWrite, Request,
    TimeOrNow, WriteFlags,
};

use crate::engine::credential::credential_ladder_with;
use crate::shell::ops::{ShellEntry, ShellFileInfo, ShellFileType, ShellHandle, ShellOps, ShellSetAttr, ShellTimeSpec, shell_err_to_errno};

/// Guard: return EACCES if `--allow-write` is not set.
macro_rules! require_write {
    ($self:expr, $reply:expr) => {
        if !$self.allow_write {
            $reply.error(Errno::EACCES);
            return;
        }
    };
}

/// Guard: look up the NFS handle for a FUSE inode, or return ENOENT.
macro_rules! get_fh {
    ($self:expr, $ino:expr, $reply:expr) => {
        match $self.fh_for_ino($ino) {
            Some(fh) => fh,
            None => {
                $reply.error(Errno::ENOENT);
                return;
            },
        }
    };
}

/// One directory entry paged from the server, owned so it outlives the
/// per-page response buffer and can be cached across readdir callbacks:
/// `(name bytes, optional attributes, optional file handle)`.
type ReaddirEntry = (Vec<u8>, Option<ShellFileInfo>, Option<ShellHandle>);

/// TTL for FUSE attribute cache entries.
///
/// Short because NFS attributes can change at any time from the server side.
const ATTR_TTL: Duration = Duration::from_secs(1);

/// Mutable inode-mapping state, guarded by a Mutex so the `Filesystem` trait
/// (`&self`) can be implemented safely across concurrent FUSE threads.
struct InodeMapState {
    /// inode -> NFS file handle
    inodes: HashMap<u64, ShellHandle>,
    /// NFS file handle bytes -> inode (reverse lookup)
    handles: HashMap<Vec<u8>, u64>,
    /// child inode -> parent inode (for `..` in readdir)
    parents: HashMap<u64, u64>,
    /// inode -> outstanding kernel lookup references (FUSE forget lifecycle).
    /// Bumped on every entry reply, decremented by `forget`; an inode is
    /// evicted from all maps once its count hits zero.
    lookups: HashMap<u64, u64>,
    /// Next inode to allocate (sequential)
    next_ino: u64,
}

impl InodeMapState {
    fn new(root_fh: &ShellHandle) -> Self {
        let mut inodes = HashMap::new();
        let mut handles = HashMap::new();
        let mut parents = HashMap::new();
        // FUSE root is always inode 1.
        drop(inodes.insert(1u64, root_fh.clone()));
        _ = handles.insert(root_fh.as_bytes().to_vec(), 1u64);
        _ = parents.insert(1u64, 1u64);
        Self { inodes, handles, parents, lookups: HashMap::new(), next_ino: 2 }
    }

    /// Allocate or reuse an inode for a file handle.
    fn intern_handle(&mut self, fh: ShellHandle, parent_ino: u64) -> u64 {
        let key = fh.as_bytes().to_vec();
        if let Some(&ino) = self.handles.get(&key) {
            return ino;
        }
        let ino = self.next_ino;
        self.next_ino = self.next_ino.saturating_add(1);
        drop(self.inodes.insert(ino, fh));
        _ = self.handles.insert(key, ino);
        _ = self.parents.insert(ino, parent_ino);
        ino
    }

    fn fh_for(&self, ino: u64) -> Option<&ShellHandle> {
        self.inodes.get(&ino)
    }

    /// Reverse-lookup the inode for an already-interned handle, WITHOUT
    /// interning a new one. readdir uses this to reuse the inode of an entry
    /// the kernel has already referenced while avoiding permanent state for
    /// entries that are merely listed.
    fn ino_for_handle(&self, fh: &ShellHandle) -> Option<u64> {
        self.handles.get(fh.as_bytes()).copied()
    }

    /// Allocate a fresh inode number without recording any handle mapping.
    /// Per the FUSE ABI a plain readdir entry takes no kernel lookup
    /// reference (only readdirplus does), so the kernel never issues a
    /// `forget` for entries it has only listed; permanently interning every
    /// listed handle would grow the inode map without bound. readdir hands
    /// such entries a transient number instead -- the kernel performs an
    /// explicit LOOKUP (the authoritative, lookup-counted intern) before it
    /// uses the entry.
    const fn alloc_transient_ino(&mut self) -> u64 {
        let n = self.next_ino;
        self.next_ino = self.next_ino.saturating_add(1);
        n
    }

    /// Record a kernel lookup reference on `ino`.
    fn record_lookup(&mut self, ino: u64) {
        *self.lookups.entry(ino).or_insert(0) += 1;
    }

    /// Release `nlookup` kernel references from `ino`, evicting all per-inode
    /// state when the count reaches zero. The FUSE root (inode 1) is pinned
    /// and never evicted. Returns `true` when the inode was fully removed so
    /// the caller can also drop its credential-cache entry.
    fn forget(&mut self, ino: u64, nlookup: u64) -> bool {
        if ino == 1 {
            return false;
        }
        let Some(count) = self.lookups.get_mut(&ino) else {
            return false;
        };
        *count = count.saturating_sub(nlookup);
        if *count > 0 {
            return false;
        }
        _ = self.lookups.remove(&ino);
        if let Some(fh) = self.inodes.remove(&ino) {
            _ = self.handles.remove(fh.as_bytes());
        }
        _ = self.parents.remove(&ino);
        true
    }
}

/// Construction parameters for `NfsFuse`.
///
/// The credential ladder, owner-bit elevation, and root-credential rungs are
/// always enabled: this is a security toolkit, the goal is unobstructed
/// access. Callers configure write-mode and supply the ops backend + runtime
/// handle.
pub(crate) struct NfsFuseConfig<O: ShellOps> {
    /// Version-neutral NFS backend.
    pub ops: O,
    /// Root file handle (becomes FUSE inode 1).
    pub root_fh: ShellHandle,
    /// Forward write/modify operations through to the server.
    pub allow_write: bool,
    /// Tokio runtime handle (fuser threads are not Tokio tasks).
    pub rt: tokio::runtime::Handle,
}

impl<O: ShellOps> std::fmt::Debug for NfsFuseConfig<O> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NfsFuseConfig").field("root_fh", &self.root_fh.to_hex()).field("allow_write", &self.allow_write).finish_non_exhaustive()
    }
}

/// NFS FUSE adapter  --  presents an NFS export as a local FUSE mount.
///
/// Created by `cli::mount::run()` and handed to `fuser::mount2()`. The
/// credential ladder runs unconditionally on every callback; per-inode
/// (uid, gid) winners are cached so we don't re-walk the ladder for the
/// same inode twice.
pub(crate) struct NfsFuse<O: ShellOps> {
    /// Version-neutral NFS backend.
    ops: O,
    /// Mutable inode mapping.
    state: Mutex<InodeMapState>,
    /// Root file handle (inode 1).
    root_fh: ShellHandle,
    /// When true, WRITE / SETATTR / CREATE / etc. are forwarded; otherwise EACCES.
    allow_write: bool,
    /// Per-inode (uid, gid) override discovered by the ladder.
    cred_cache: Mutex<HashMap<u64, (u32, u32)>>,
    /// Per-directory readdir page cache, keyed by directory inode.
    readdir_cache: Mutex<HashMap<u64, Vec<ReaddirEntry>>>,
    /// Tokio runtime handle captured at construction.
    rt: tokio::runtime::Handle,
}

impl<O: ShellOps> std::fmt::Debug for NfsFuse<O> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NfsFuse").field("root_fh", &self.root_fh.to_hex()).finish_non_exhaustive()
    }
}

/// Return `true` when the error represents a permission denial (EACCES or
/// EPERM), meaning the credential ladder should try the next rung.
fn is_permission_denied(e: &anyhow::Error) -> bool {
    let errno = shell_err_to_errno(e);
    errno == libc::EACCES || errno == libc::EPERM
}

// `significant_drop_tightening` is inherent to the credential ladder
// closures: each rung clones captured values fresh, but a single rung
// looks "redundant" to clippy.
#[expect(clippy::significant_drop_tightening, reason = "credential ladder closures")]
impl<O: ShellOps> NfsFuse<O> {
    /// Create a new FUSE adapter from a config bundle.
    #[must_use]
    pub(crate) fn new(cfg: NfsFuseConfig<O>) -> Self {
        let state = Mutex::new(InodeMapState::new(&cfg.root_fh));
        Self { ops: cfg.ops, state, root_fh: cfg.root_fh, allow_write: cfg.allow_write, cred_cache: Mutex::new(HashMap::new()), readdir_cache: Mutex::new(HashMap::new()), rt: cfg.rt }
    }

    /// Convert `ShellFileInfo` to a fuser `FileAttr`.
    fn make_attr(ino: u64, a: &ShellFileInfo) -> FileAttr {
        let kind = to_fuse_type(a.file_type);
        let mode16 = u16::try_from(a.mode & u32::from(u16::MAX)).unwrap_or(0);
        // Always-on owner-bit elevation: copy owner rwx bits (bits 6-8) into
        // the other-rwx slot (bits 0-2) so unprivileged local users can reach
        // every file through FUSE.
        let perm = mode16 | ((mode16 >> 6) & 0o007);
        FileAttr {
            ino: INodeNo(ino),
            size: a.size,
            blocks: a.used / 512,
            atime: nfs_time_to_system(a.atime_secs, a.atime_nsecs),
            mtime: nfs_time_to_system(a.mtime_secs, a.mtime_nsecs),
            ctime: nfs_time_to_system(a.ctime_secs, a.ctime_nsecs),
            crtime: UNIX_EPOCH,
            kind,
            perm,
            nlink: a.nlink,
            uid: a.uid,
            gid: a.gid,
            rdev: a.rdev.0,
            blksize: 4096,
            flags: 0,
        }
    }

    /// Run an async block on the captured Tokio runtime, blocking this thread.
    fn block<F, T>(&self, fut: F) -> T
    where
        F: Future<Output = T>,
    {
        self.rt.block_on(fut)
    }

    /// Build an ephemeral ops instance with the given (uid, gid).
    fn ops_for(&self, uid: u32, gid: u32) -> O {
        self.ops.with_credential(uid, gid, self.ops.machinename())
    }

    /// Look up the cached `(uid, gid)` for `ino`, if any.
    fn cached_cred(&self, ino: u64) -> Option<(u32, u32)> {
        self.cred_cache.lock().unwrap_or_else(std::sync::PoisonError::into_inner).get(&ino).copied()
    }

    /// Record `(uid, gid)` as the working credential for `ino`.
    fn cache_cred(&self, ino: u64, uid: u32, gid: u32) {
        _ = self.cred_cache.lock().unwrap_or_else(std::sync::PoisonError::into_inner).insert(ino, (uid, gid));
    }

    /// Bump the kernel lookup-reference count for `ino`.
    fn record_lookup(&self, ino: u64) {
        self.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner).record_lookup(ino);
    }

    /// Build the credential-escalation ladder for `subject_ino`.
    async fn ladder_for(&self, subject_ino: u64) -> Vec<(u32, u32)> {
        let caller = (self.ops.uid(), self.ops.gid());
        let owner = {
            let fh_opt = self.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner).fh_for(subject_ino).cloned();
            match fh_opt {
                Some(fh) => self.ops.getattr(&fh).await.ok().map(|a| ((a.uid, a.gid), a.mode)),
                None => None,
            }
        };
        credential_ladder_with(caller, owner.map(|f| f.0), owner.map(|f| f.1), &[])
    }

    /// Retrieve the file handle for inode `ino` from the inode map.
    fn fh_for_ino(&self, ino: u64) -> Option<ShellHandle> {
        self.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner).fh_for(ino).cloned()
    }

    /// Intern a child handle, returning the assigned inode.
    fn intern(&self, child_fh: ShellHandle, parent_ino: u64) -> u64 {
        self.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner).intern_handle(child_fh, parent_ino)
    }

    /// Maximum symlink resolution depth before we give up to prevent loops.
    const SYMLINK_DEPTH_LIMIT: u32 = 16;

    /// Hard cap on entries accumulated across readdir pages.
    const MAX_READDIR_ENTRIES: usize = 1_000_000;

    /// Run an NFS operation with the credential-escalation ladder.
    ///
    /// Tries, in order: any per-inode cached credential, then the default
    /// credential. Only if BOTH are rejected with EACCES / EPERM does it
    /// walk the rungs of `credential_ladder` -- so the happy path never
    /// pays for the owner-discovery GETATTR. The first attempt that does
    /// not return EACCES / EPERM wins; the winning credential is cached.
    ///
    /// The closure receives an owned `O` (constructed by `ops_for`) so the
    /// returned future is `'static` and does not borrow from the closure
    /// parameter -- this sidesteps the RPITIT lifetime issue.
    async fn try_with_ladder<F, Fut, T>(&self, subject_ino: u64, op: F) -> anyhow::Result<T>
    where
        F: Fn(O) -> Fut,
        Fut: Future<Output = anyhow::Result<T>>,
    {
        let default = (self.ops.uid(), self.ops.gid());
        let mut primary: Vec<(u32, u32)> = Vec::new();
        if let Some(pair) = self.cached_cred(subject_ino) {
            primary.push(pair);
        }
        if !primary.contains(&default) {
            primary.push(default);
        }

        let mut tried: Vec<(u32, u32)> = Vec::new();
        let mut last_err: Option<anyhow::Error> = None;
        for (u, g) in primary {
            tried.push((u, g));
            let ephemeral = self.ops_for(u, g);
            match op(ephemeral).await {
                Ok(v) => {
                    if (u, g) != default {
                        self.cache_cred(subject_ino, u, g);
                    }
                    return Ok(v);
                },
                Err(e) if is_permission_denied(&e) => {
                    last_err = Some(e);
                },
                Err(e) => return Err(e),
            }
        }

        // Primary credentials were denied; walk the escalation ladder.
        for (u, g) in self.ladder_for(subject_ino).await {
            if tried.contains(&(u, g)) {
                continue;
            }
            let ephemeral = self.ops_for(u, g);
            match op(ephemeral).await {
                Ok(v) => {
                    if (u, g) != default {
                        self.cache_cred(subject_ino, u, g);
                    }
                    return Ok(v);
                },
                Err(e) if is_permission_denied(&e) => {
                    last_err = Some(e);
                },
                Err(e) => return Err(e),
            }
        }
        Err(last_err.unwrap_or_else(|| anyhow::anyhow!("no credential rungs to try for inode {subject_ino}")))
    }

    /// LOOKUP with the credential-escalation ladder, with server-side
    /// symlink follow on success.
    async fn try_lookup_with_ladder(&self, parent_fh: &ShellHandle, name: &str, parent_ino: u64) -> anyhow::Result<(ShellHandle, ShellFileInfo, u64)> {
        let (child_fh, info) = self
            .try_with_ladder(parent_ino, |ops: O| {
                let parent_fh = parent_fh.clone();
                let name = name.to_owned();
                async move { ops.lookup(&parent_fh, &name).await }
            })
            .await?;

        let child_ino = self.intern(child_fh.clone(), parent_ino);

        if info.file_type == ShellFileType::Symlink {
            return self.follow_symlink(child_fh, parent_ino, 0).await;
        }
        Ok((child_fh, info, child_ino))
    }

    /// LOOKUP that resolves `(handle, attrs)` WITHOUT interning an inode.
    ///
    /// Used by the readdir null-attr/null-handle fix-up.
    async fn lookup_no_intern(&self, parent_fh: &ShellHandle, name: &str, parent_ino: u64) -> anyhow::Result<(ShellHandle, ShellFileInfo)> {
        self.try_with_ladder(parent_ino, |ops: O| {
            let parent_fh = parent_fh.clone();
            let name = name.to_owned();
            async move { ops.lookup(&parent_fh, &name).await }
        })
        .await
    }

    /// GETATTR helper that runs the credential ladder.
    async fn try_getattr(&self, ino: u64) -> Option<ShellFileInfo> {
        let fh = self.fh_for_ino(ino)?;
        self.try_with_ladder(ino, |ops: O| {
            let fh = fh.clone();
            async move { ops.getattr(&fh).await }
        })
        .await
        .ok()
    }

    /// Resolve a symlink chain server-side. Returns the eventual non-symlink
    /// `(file_handle, info, inode)` or an error.
    async fn follow_symlink(&self, link_fh: ShellHandle, parent_ino: u64, depth: u32) -> anyhow::Result<(ShellHandle, ShellFileInfo, u64)> {
        if depth >= Self::SYMLINK_DEPTH_LIMIT {
            anyhow::bail!("symlink depth limit exceeded");
        }

        // Read the symlink target.
        let target = self.ops.readlink(&link_fh).await?;

        // Decide where to start resolving from.
        let (start_ino, target_str) = if let Some(stripped) = target.strip_prefix('/') { (1u64, stripped.to_owned()) } else { (parent_ino, target) };

        // Walk components, handling `.` and `..`.
        let (mut cur_fh, mut cur_ino) = {
            let st = self.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            let fh = st.fh_for(start_ino).cloned().ok_or_else(|| anyhow::anyhow!("stale handle"))?;
            (fh, start_ino)
        };

        for component in target_str.split('/').filter(|c| !c.is_empty()) {
            if component == "." {
                continue;
            }
            if component == ".." {
                let parent = self.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner).parents.get(&cur_ino).copied().unwrap_or(1);
                let parent_fh = self.fh_for_ino(parent).ok_or_else(|| anyhow::anyhow!("stale handle"))?;
                cur_fh = parent_fh;
                cur_ino = parent;
                continue;
            }
            let (next_fh, _info) = self.ops.lookup(&cur_fh, component).await?;
            let next_ino = self.intern(next_fh.clone(), cur_ino);
            cur_fh = next_fh;
            cur_ino = next_ino;
        }

        // Final GETATTR to learn the type. If still a symlink, recurse.
        let info = self.ops.getattr(&cur_fh).await?;

        if info.file_type == ShellFileType::Symlink {
            let parent_of_link = self.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner).parents.get(&cur_ino).copied().unwrap_or(1);
            return Box::pin(self.follow_symlink(cur_fh, parent_of_link, depth + 1)).await;
        }

        Ok((cur_fh, info, cur_ino))
    }

    /// Intern a new entry returned by create/mknod/mkdir/symlink,
    /// falling back to LOOKUP when the server omitted the handle or attrs.
    fn intern_with_lookup_fallback(&self, parent_ino: u64, parent_fh: &ShellHandle, name: &str) -> Option<(ShellHandle, u64, ShellFileInfo)> {
        let (fh, file_info, child_ino) = self.block(self.try_lookup_with_ladder(parent_fh, name, parent_ino)).ok()?;
        Some((fh, child_ino, file_info))
    }

    /// Page an entire directory via `list_dir`, returning owned entry tuples.
    fn page_directory(&self, ino: u64, dir_fh: &ShellHandle) -> Result<Vec<ReaddirEntry>, Errno> {
        let shell_entries: Vec<ShellEntry> = self
            .block(self.try_with_ladder(ino, |ops: O| {
                let dir_fh = dir_fh.clone();
                async move { ops.list_dir(&dir_fh).await }
            }))
            .map_err(|e| {
                let errno = shell_err_to_errno(&e);
                if errno == libc::EACCES || errno == libc::EPERM {
                    tracing::debug!(?ino, "readdir denied");
                    Errno::EACCES
                } else {
                    tracing::debug!(?ino, "readdir failed");
                    Errno::EIO
                }
            })?;

        let entries: Vec<ReaddirEntry> = shell_entries.into_iter().take(Self::MAX_READDIR_ENTRIES).map(|e| (e.name.into_bytes(), e.info, e.handle)).collect();
        Ok(entries)
    }
}

impl<O: ShellOps> Filesystem for NfsFuse<O> {
    /// Look up a directory entry by name and return its attributes.
    fn lookup(&self, _req: &Request, parent: INodeNo, name: &std::ffi::OsStr, reply: ReplyEntry) {
        let parent_fh = get_fh!(self, parent.0, reply);

        let name_str = name.to_string_lossy();
        let result = self.block(self.try_lookup_with_ladder(&parent_fh, &name_str, parent.0));

        match result {
            Ok((_child_fh, info, child_ino)) => {
                self.record_lookup(child_ino);
                let attr = Self::make_attr(child_ino, &info);
                reply.entry(&ATTR_TTL, &attr, Generation(0));
            },
            Err(e) => reply.error(errno_from(&e)),
        }
    }

    /// Forget an inode (FUSE lifetime management).
    fn forget(&self, _req: &Request, ino: INodeNo, nlookup: u64) {
        let removed = self.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner).forget(ino.0, nlookup);
        if removed {
            _ = self.cred_cache.lock().unwrap_or_else(std::sync::PoisonError::into_inner).remove(&ino.0);
            drop(self.readdir_cache.lock().unwrap_or_else(std::sync::PoisonError::into_inner).remove(&ino.0));
        }
    }

    /// Get file attributes for inode `ino`.
    fn getattr(&self, _req: &Request, ino: INodeNo, _fh: Option<FuseFileHandle>, reply: ReplyAttr) {
        let fh = get_fh!(self, ino.0, reply);

        let result = self.block(self.try_with_ladder(ino.0, |ops: O| {
            let fh = fh.clone();
            async move { ops.getattr(&fh).await }
        }));

        match result {
            Ok(file_info) => reply.attr(&ATTR_TTL, &Self::make_attr(ino.0, &file_info)),
            Err(e) => reply.error(errno_from(&e)),
        }
    }

    /// SETATTR -- chmod / chown / utime / truncate.
    fn setattr(
        &self,
        _req: &Request,
        ino: INodeNo,
        mode: Option<u32>,
        uid: Option<u32>,
        gid: Option<u32>,
        size: Option<u64>,
        atime: Option<TimeOrNow>,
        mtime: Option<TimeOrNow>,
        _ctime: Option<SystemTime>,
        _fh: Option<FuseFileHandle>,
        _crtime: Option<SystemTime>,
        _chgtime: Option<SystemTime>,
        _bkuptime: Option<SystemTime>,
        _flags: Option<BsdFileFlags>,
        reply: ReplyAttr,
    ) {
        require_write!(self, reply);
        let fh = get_fh!(self, ino.0, reply);

        let sa = ShellSetAttr { mode, uid, gid, size, atime: time_or_now_to_spec(atime), mtime: time_or_now_to_spec(mtime) };

        let result = self.block(self.try_with_ladder(ino.0, |ops: O| {
            let fh = fh.clone();
            let sa = sa.clone();
            async move { ops.setattr(&fh, sa).await }
        }));

        match result {
            Ok(file_info) => reply.attr(&ATTR_TTL, &Self::make_attr(ino.0, &file_info)),
            Err(e) => reply.error(errno_from(&e)),
        }
    }

    /// ACCESS -- advisory permission check.
    fn access(&self, _req: &Request, ino: INodeNo, mask: AccessFlags, reply: ReplyEmpty) {
        let fh = get_fh!(self, ino.0, reply);

        // Translate POSIX mask to NFS ACCESS bits. Since DefaultPermissions is
        // set, the kernel does its own check; we just forward to the server.
        let nfs_mask = access_flags_to_nfs(mask);

        let result = self.block(self.try_with_ladder(ino.0, |ops: O| {
            let fh = fh.clone();
            async move { ops.access(&fh, nfs_mask).await }
        }));

        match result {
            Ok(granted) => {
                if (granted & nfs_mask) == nfs_mask {
                    reply.ok();
                } else {
                    reply.error(Errno::EACCES);
                }
            },
            Err(e) => reply.error(errno_from(&e)),
        }
    }

    /// READLINK -- return the raw symlink target.
    fn readlink(&self, _req: &Request, ino: INodeNo, reply: ReplyData) {
        let fh = get_fh!(self, ino.0, reply);

        let result = self.block(self.try_with_ladder(ino.0, |ops: O| {
            let fh = fh.clone();
            async move { ops.readlink(&fh).await }
        }));

        match result {
            Ok(target) => reply.data(target.as_bytes()),
            Err(e) => reply.error(errno_from(&e)),
        }
    }

    /// MKNOD -- create a special file (FIFO, socket, char/block device).
    fn mknod(&self, _req: &Request, parent: INodeNo, name: &std::ffi::OsStr, mode: u32, _umask: u32, rdev: u32, reply: ReplyEntry) {
        require_write!(self, reply);
        let parent_fh = get_fh!(self, parent.0, reply);

        let kind = mode & 0o170_000;
        let perms = mode & 0o7777;
        let name_str = name.to_string_lossy().into_owned();

        // Validate the file-type bits up front.
        let dev_type = match kind {
            0o020_000 => Some(crate::shell::ops::ShellDeviceType::Char),
            0o060_000 => Some(crate::shell::ops::ShellDeviceType::Block),
            0o010_000 | 0o014_000 => None, // FIFO / socket -- handled differently
            _ => {
                reply.error(Errno::ENOTSUP);
                return;
            },
        };

        // FUSE delivers `rdev` in the kernel's new_encode_dev packing.
        let major = (rdev >> 8) & 0xfff;
        let minor = (rdev & 0xff) | ((rdev >> 12) & 0x000f_ff00);

        let result = if let Some(dt) = dev_type {
            self.block(self.try_with_ladder(parent.0, |ops: O| {
                let parent_fh = parent_fh.clone();
                let name_str = name_str.clone();
                async move { ops.mknod(&parent_fh, &name_str, dt, major, minor, perms).await }
            }))
        } else {
            // FIFO / socket: create via mknod with a dummy device type.
            // ShellOps::mknod should handle this, but if the version doesn't
            // support it, fall back to creating as a char device with dev 0,0.
            // For FIFO specifically, some backends may need special handling.
            self.block(self.try_with_ladder(parent.0, |ops: O| {
                let parent_fh = parent_fh.clone();
                let name_str = name_str.clone();
                async move { ops.mknod(&parent_fh, &name_str, crate::shell::ops::ShellDeviceType::Char, 0, 0, perms).await }
            }))
        };

        match result {
            Ok(_new_fh) => {
                let Some((_child_fh, child_ino, info)) = self.intern_with_lookup_fallback(parent.0, &parent_fh, &name_str) else {
                    reply.error(Errno::EIO);
                    return;
                };
                self.record_lookup(child_ino);
                reply.entry(&ATTR_TTL, &Self::make_attr(child_ino, &info), Generation(0));
            },
            Err(e) => reply.error(errno_from(&e)),
        }
    }

    /// MKDIR -- create a subdirectory.
    fn mkdir(&self, _req: &Request, parent: INodeNo, name: &std::ffi::OsStr, mode: u32, _umask: u32, reply: ReplyEntry) {
        require_write!(self, reply);
        let parent_fh = get_fh!(self, parent.0, reply);

        let name_str = name.to_string_lossy().into_owned();
        let perms = mode & 0o7777;

        let result = self.block(self.try_with_ladder(parent.0, |ops: O| {
            let parent_fh = parent_fh.clone();
            let name_str = name_str.clone();
            async move { ops.mkdir(&parent_fh, &name_str, perms).await }
        }));

        match result {
            Ok(_new_fh) => {
                let Some((_child_fh, child_ino, info)) = self.intern_with_lookup_fallback(parent.0, &parent_fh, &name_str) else {
                    reply.error(Errno::EIO);
                    return;
                };
                self.record_lookup(child_ino);
                reply.entry(&ATTR_TTL, &Self::make_attr(child_ino, &info), Generation(0));
            },
            Err(e) => reply.error(errno_from(&e)),
        }
    }

    /// SYMLINK -- create a symbolic link.
    fn symlink(&self, _req: &Request, parent: INodeNo, link_name: &std::ffi::OsStr, target: &Path, reply: ReplyEntry) {
        require_write!(self, reply);
        let parent_fh = get_fh!(self, parent.0, reply);

        let name_str = link_name.to_string_lossy().into_owned();
        let target_str = target.to_string_lossy().into_owned();

        let result = self.block(self.try_with_ladder(parent.0, |ops: O| {
            let parent_fh = parent_fh.clone();
            let name_str = name_str.clone();
            let target_str = target_str.clone();
            async move { ops.symlink(&parent_fh, &name_str, &target_str).await }
        }));

        match result {
            Ok(()) => {
                let Some((_child_fh, child_ino, info)) = self.intern_with_lookup_fallback(parent.0, &parent_fh, &name_str) else {
                    reply.error(Errno::EIO);
                    return;
                };
                self.record_lookup(child_ino);
                reply.entry(&ATTR_TTL, &Self::make_attr(child_ino, &info), Generation(0));
            },
            Err(e) => reply.error(errno_from(&e)),
        }
    }

    /// CREATE -- atomic create-and-open of a regular file.
    fn create(&self, _req: &Request, parent: INodeNo, name: &std::ffi::OsStr, mode: u32, _umask: u32, _flags: i32, reply: ReplyCreate) {
        require_write!(self, reply);
        let parent_fh = get_fh!(self, parent.0, reply);

        let name_str = name.to_string_lossy().into_owned();
        let perms = mode & 0o7777;

        let result = self.block(self.try_with_ladder(parent.0, |ops: O| {
            let parent_fh = parent_fh.clone();
            let name_str = name_str.clone();
            async move { ops.create_file(&parent_fh, &name_str, perms).await }
        }));

        match result {
            Ok(child_fh) => {
                let child_ino = self.intern(child_fh.clone(), parent.0);
                match self.block(self.try_getattr(child_ino)) {
                    Some(info) => {
                        self.record_lookup(child_ino);
                        let attr = Self::make_attr(child_ino, &info);
                        reply.created(&ATTR_TTL, &attr, Generation(0), FuseFileHandle(0), FopenFlags::empty());
                    },
                    None => reply.error(Errno::EIO),
                }
            },
            Err(e) => reply.error(errno_from(&e)),
        }
    }

    /// REMOVE -- delete a regular file (or a special file / symlink).
    fn unlink(&self, _req: &Request, parent: INodeNo, name: &std::ffi::OsStr, reply: ReplyEmpty) {
        require_write!(self, reply);
        let parent_fh = get_fh!(self, parent.0, reply);
        let name_str = name.to_string_lossy().into_owned();

        let result = self.block(self.try_with_ladder(parent.0, |ops: O| {
            let parent_fh = parent_fh.clone();
            let name_str = name_str.clone();
            async move { ops.remove(&parent_fh, &name_str).await }
        }));
        reply_result(&result, reply);
    }

    /// RMDIR -- remove a directory.
    fn rmdir(&self, _req: &Request, parent: INodeNo, name: &std::ffi::OsStr, reply: ReplyEmpty) {
        require_write!(self, reply);
        let parent_fh = get_fh!(self, parent.0, reply);
        let name_str = name.to_string_lossy().into_owned();

        let result = self.block(self.try_with_ladder(parent.0, |ops: O| {
            let parent_fh = parent_fh.clone();
            let name_str = name_str.clone();
            async move { ops.rmdir(&parent_fh, &name_str).await }
        }));
        reply_result(&result, reply);
    }

    /// RENAME -- move a file.
    fn rename(&self, _req: &Request, parent: INodeNo, name: &std::ffi::OsStr, newparent: INodeNo, newname: &std::ffi::OsStr, _flags: RenameFlags, reply: ReplyEmpty) {
        require_write!(self, reply);
        let (Some(from_dir), Some(to_dir)) = (self.fh_for_ino(parent.0), self.fh_for_ino(newparent.0)) else {
            reply.error(Errno::ENOENT);
            return;
        };
        let from_name = name.to_string_lossy().into_owned();
        let to_name = newname.to_string_lossy().into_owned();

        let result = self.block(self.try_with_ladder(parent.0, |ops: O| {
            let from_dir = from_dir.clone();
            let to_dir = to_dir.clone();
            let from_name = from_name.clone();
            let to_name = to_name.clone();
            async move { ops.rename(&from_dir, &from_name, &to_dir, &to_name).await }
        }));
        reply_result(&result, reply);
    }

    /// LINK -- create a hard link.
    fn link(&self, _req: &Request, ino: INodeNo, newparent: INodeNo, newname: &std::ffi::OsStr, reply: ReplyEntry) {
        require_write!(self, reply);
        let (Some(target_fh), Some(parent_fh)) = (self.fh_for_ino(ino.0), self.fh_for_ino(newparent.0)) else {
            reply.error(Errno::ENOENT);
            return;
        };
        let newname_str = newname.to_string_lossy().into_owned();

        let result = self.block(self.try_with_ladder(newparent.0, |ops: O| {
            let target_fh = target_fh.clone();
            let parent_fh = parent_fh.clone();
            let newname_str = newname_str.clone();
            async move { ops.hard_link(&target_fh, &parent_fh, &newname_str).await }
        }));

        match result {
            Ok(()) => match self.block(self.try_getattr(ino.0)) {
                Some(file_info) => {
                    self.record_lookup(ino.0);
                    reply.entry(&ATTR_TTL, &Self::make_attr(ino.0, &file_info), Generation(0));
                },
                None => reply.error(Errno::EIO),
            },
            Err(e) => reply.error(errno_from(&e)),
        }
    }

    /// READDIR -- list directory entries with fix-up for missing attrs.
    fn readdir(&self, _req: &Request, ino: INodeNo, _fh: FuseFileHandle, offset: u64, mut reply: ReplyDirectory) {
        let dir_fh = get_fh!(self, ino.0, reply);

        if offset == 0 {
            match self.page_directory(ino.0, &dir_fh) {
                Ok(entries) => {
                    drop(self.readdir_cache.lock().unwrap_or_else(std::sync::PoisonError::into_inner).insert(ino.0, entries));
                },
                Err(errno) => {
                    reply.error(errno);
                    return;
                },
            }
        }

        let dotdot_ino = self.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner).parents.get(&ino.0).copied().unwrap_or(1);

        let fixed: [(u64, u64, FuseFileType, &str); 2] = [(1, ino.0, FuseFileType::Directory, "."), (2, dotdot_ino, FuseFileType::Directory, "..")];
        for (pos, entry_ino, kind, name) in fixed {
            if offset < pos && reply.add(INodeNo(entry_ino), pos, kind, name) {
                reply.ok();
                return;
            }
        }

        let entries = self.readdir_cache.lock().unwrap_or_else(std::sync::PoisonError::into_inner).get(&ino.0).cloned().unwrap_or_default();
        for (idx, (name_bytes, attrs_opt, fh_opt)) in entries.into_iter().enumerate() {
            let entry_offset = (idx as u64) + 3;
            if offset >= entry_offset {
                continue;
            }
            let name_str = String::from_utf8_lossy(&name_bytes);
            if name_str == "." || name_str == ".." {
                continue;
            }

            // null-attr / null-handle fix-up via non-interning LOOKUP.
            let mut entry_attrs = attrs_opt;
            let mut entry_fh = fh_opt;
            if (entry_attrs.is_none() || entry_fh.is_none())
                && let Ok((fh2, attrs2)) = self.block(self.lookup_no_intern(&dir_fh, &name_str, ino.0))
            {
                entry_fh = Some(fh2);
                entry_attrs = Some(attrs2);
            }

            let kind = entry_attrs.as_ref().map_or(FuseFileType::RegularFile, |a| to_fuse_type(a.file_type));
            let entry_ino = {
                let mut st = self.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
                let known = entry_fh.as_ref().and_then(|fh| st.ino_for_handle(fh));
                known.unwrap_or_else(|| st.alloc_transient_ino())
            };
            if reply.add(INodeNo(entry_ino), entry_offset, kind, name_str.as_ref()) {
                reply.ok();
                return;
            }
        }
        reply.ok();
    }

    /// Read file data for inode `ino`.
    fn read(&self, _req: &Request, ino: INodeNo, _fh: FuseFileHandle, offset: u64, size: u32, _flags: OpenFlags, _lock_owner: Option<LockOwner>, reply: ReplyData) {
        let fh = get_fh!(self, ino.0, reply);

        // Loop to handle servers that return fewer bytes than requested before
        // true EOF (short reads). Each chunk runs through the credential ladder.
        let mut buf: Vec<u8> = Vec::with_capacity(size as usize);
        loop {
            let want = size.saturating_sub(u32::try_from(buf.len()).unwrap_or(u32::MAX));
            if want == 0 {
                break;
            }
            let pos = offset.saturating_add(buf.len() as u64);
            let chunk = self.block(self.try_with_ladder(ino.0, |ops: O| {
                let fh = fh.clone();
                async move { ops.read_chunk(&fh, pos, want).await }
            }));
            match chunk {
                Ok(data) => {
                    if data.is_empty() {
                        break;
                    }
                    buf.extend_from_slice(&data);
                    // read_chunk returns up to `want` bytes; if less, the file
                    // may have ended or the server capped the response. We keep
                    // looping until we get `size` bytes or an empty page.
                    if data.len() < want as usize {
                        break;
                    }
                },
                Err(e) if buf.is_empty() => {
                    reply.error(errno_from(&e));
                    return;
                },
                Err(_) => break,
            }
        }
        reply.data(&buf);
    }

    /// Write data to a file.
    fn write(&self, _req: &Request, ino: INodeNo, _fh: FuseFileHandle, offset: u64, data: &[u8], _write_flags: WriteFlags, _flags: OpenFlags, _lock_owner: Option<LockOwner>, reply: ReplyWrite) {
        require_write!(self, reply);
        let fh = get_fh!(self, ino.0, reply);
        let data_owned = data.to_vec();
        let sent = u32::try_from(data.len()).unwrap_or(u32::MAX);

        let result = self.block(self.try_with_ladder(ino.0, |ops: O| {
            let fh = fh.clone();
            let data_owned = data_owned.clone();
            async move { ops.write_chunk(&fh, offset, &data_owned).await }
        }));

        match result {
            Ok(count) => reply.written(count.min(sent)),
            Err(e) => reply.error(errno_from(&e)),
        }
    }

    /// FSYNC -- flush uncommitted writes.
    fn fsync(&self, _req: &Request, ino: INodeNo, _fh: FuseFileHandle, _datasync: bool, reply: ReplyEmpty) {
        let fh = get_fh!(self, ino.0, reply);

        let result = self.block(self.try_with_ladder(ino.0, |ops: O| {
            let fh = fh.clone();
            async move { ops.commit(&fh).await }
        }));
        reply_result(&result, reply);
    }

    /// STATFS -- filesystem statistics.
    fn statfs(&self, _req: &Request, ino: INodeNo, reply: ReplyStatfs) {
        let fh = self.fh_for_ino(ino.0).unwrap_or_else(|| self.root_fh.clone());

        let result = self.block(self.try_with_ladder(ino.0, |ops: O| {
            let fh = fh.clone();
            async move { ops.statfs(&fh).await }
        }));

        match result {
            Ok(fs) => {
                let bsize = fs.block_size;
                let blocks = fs.total_bytes / u64::from(bsize);
                let bfree = fs.free_bytes / u64::from(bsize);
                let bavail = fs.avail_bytes / u64::from(bsize);
                reply.statfs(blocks, bfree, bavail, fs.total_files, fs.free_files, bsize, 255, bsize);
            },
            Err(_) => {
                // Many servers reject FSSTAT for non-root callers; reply
                // with zeros so `df` doesn't break the mount.
                reply.statfs(0, 0, 0, 0, 0, 512, 255, 512);
            },
        }
    }
}

/// Convert `ShellFileType` to the fuser equivalent.
const fn to_fuse_type(ft: ShellFileType) -> FuseFileType {
    match ft {
        ShellFileType::Directory => FuseFileType::Directory,
        ShellFileType::Symlink => FuseFileType::Symlink,
        ShellFileType::Block => FuseFileType::BlockDevice,
        ShellFileType::Character => FuseFileType::CharDevice,
        ShellFileType::Fifo => FuseFileType::NamedPipe,
        ShellFileType::Socket => FuseFileType::Socket,
        _ => FuseFileType::RegularFile,
    }
}

/// Build a `SystemTime` from NFS time fields (seconds + nanoseconds since epoch).
fn nfs_time_to_system(seconds: u64, nseconds: u32) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(seconds) + Duration::from_nanos(u64::from(nseconds))
}

/// Convert fuser's `Option<TimeOrNow>` to `ShellTimeSpec`.
fn time_or_now_to_spec(t: Option<TimeOrNow>) -> Option<ShellTimeSpec> {
    match t {
        None => None,
        Some(TimeOrNow::Now) => Some(ShellTimeSpec::Now),
        Some(TimeOrNow::SpecificTime(time)) => {
            let d = time.duration_since(UNIX_EPOCH).unwrap_or_default();
            Some(ShellTimeSpec::At(d.as_secs(), d.subsec_nanos()))
        },
    }
}

/// Translate fuser's `AccessFlags` (POSIX `R_OK`/`W_OK`/`X_OK` bitset) to
/// NFS ACCESS bits. Uses the standard NFS constants:
///   READ=0x01, LOOKUP=0x02, MODIFY=0x04, EXTEND=0x08, DELETE=0x10, EXECUTE=0x20
const fn access_flags_to_nfs(mask: AccessFlags) -> u32 {
    let mut bits: u32 = 0;
    if mask.contains(AccessFlags::R_OK) {
        bits |= 0x01; // ACCESS_READ
    }
    if mask.contains(AccessFlags::W_OK) {
        bits |= 0x04 | 0x08 | 0x10; // MODIFY | EXTEND | DELETE
    }
    if mask.contains(AccessFlags::X_OK) {
        bits |= 0x02 | 0x20; // LOOKUP | EXECUTE
    }
    bits
}

/// Map an `anyhow::Error` to a FUSE `Errno`, extracting `ShellError` when
/// present in the error chain.
fn errno_from(e: &anyhow::Error) -> Errno {
    Errno::from(std::io::Error::from_raw_os_error(shell_err_to_errno(e)))
}

/// Reply to a void-return NFS callback based on success/failure.
fn reply_result(result: &anyhow::Result<()>, reply: ReplyEmpty) {
    match result {
        Ok(()) => reply.ok(),
        Err(e) => reply.error(errno_from(e)),
    }
}
