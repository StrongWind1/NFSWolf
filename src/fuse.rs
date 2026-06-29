//! FUSE filesystem adapter  --  mounts an NFS export as a local filesystem.
//!
//! Wires every `Nfs3Client` procedure through a fuser callback so the local
//! mount behaves like a normal POSIX filesystem (subject to `--allow-write`
//! for destructive operations). Always-on behaviors:
//!
//! - **Server-side symlink resolution.** When `lookup` lands on a symlink,
//!   we issue NFSv3 READLINK and re-resolve the target relative to the
//!   parent (or the FUSE root for absolute paths). The local kernel never
//!   sees the underlying symlink, so `cd /mnt/link` enters the server-side
//!   target rather than dereferencing locally. A depth cap blocks loops.
//! - **Null-attr READDIRPLUS fix-up.** Some servers (notably NetApp on
//!   nested exports) return entries with `name_attributes = None` /
//!   `name_handle = None`. We re-LOOKUP those entries so the kernel sees
//!   complete metadata.
//! - **Auto-UID ladder (always on).** Any callback that returns
//!   NFS3ERR_ACCES triggers the same credential-escalation ladder the
//!   interactive shell uses (`engine::credential::escalation_list`),
//!   and the resolved (uid, gid) is cached per inode so future calls
//!   skip the search.
//!
//! fuser calls are synchronous but the NFS client is async. We capture a
//! `tokio::runtime::Handle` at construction time and call `block_on` on
//! it from the fuser worker threads -- those threads are not Tokio tasks,
//! so blocking them does not stall the runtime that drives the pool.
//!
//! Toolkit API  --  not all items are used in currently-implemented phases.

use std::collections::HashMap;
use std::future::Future;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use fuser::{
    AccessFlags, BsdFileFlags, Errno, FileAttr, FileHandle as FuseFileHandle, FileType as FuseFileType, Filesystem, FopenFlags, Generation, INodeNo, LockOwner, OpenFlags, RenameFlags, ReplyAttr, ReplyCreate, ReplyData, ReplyDirectory, ReplyEmpty, ReplyEntry, ReplyStatfs, ReplyWrite, Request,
    TimeOrNow, WriteFlags,
};
use nfs3_types::nfs3::{
    ACCESS3args, COMMIT3args, CREATE3args, FSSTAT3args, GETATTR3args, LINK3args, LOOKUP3args, MKDIR3args, MKNOD3args, Nfs3Option, Nfs3Result, READ3args, READDIRPLUS3args, READLINK3args, REMOVE3args, RENAME3args, RMDIR3args, SETATTR3args, SYMLINK3args, WRITE3args, cookieverf3, createhow3,
    devicedata3, diropargs3, filename3, mknoddata3, nfspath3, nfsstat3, nfstime3, sattr3, set_atime, set_mtime, specdata3, stable_how, symlinkdata3,
};
use nfs3_types::xdr_codec::Opaque;

use crate::engine::credential::escalation_list;
use crate::proto::auth::{AuthSys, Credential};
use crate::proto::nfs3::client::Nfs3Client;
use crate::proto::nfs3::types::{FileAttrs, FileHandle, FileType};

/// One directory entry paged from READDIRPLUS, owned so it outlives the
/// per-page response buffer and can be cached across readdir callbacks:
/// `(name bytes, optional attributes, optional file handle)`.
type ReaddirEntry = (Vec<u8>, Option<FileAttrs>, Option<FileHandle>);

/// TTL for FUSE attribute cache entries.
///
/// Short because NFS attributes can change at any time from the server side.
const ATTR_TTL: Duration = Duration::from_secs(1);

/// Mutable inode-mapping state, guarded by a Mutex so the `Filesystem` trait
/// (`&self`) can be implemented safely across concurrent FUSE threads.
struct InodeMapState {
    /// inode -> NFS file handle
    inodes: HashMap<u64, FileHandle>,
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
    fn new(root_fh: &FileHandle) -> Self {
        let mut inodes = HashMap::new();
        let mut handles = HashMap::new();
        let mut parents = HashMap::new();
        // FUSE root is always inode 1.
        inodes.insert(1u64, root_fh.clone());
        handles.insert(root_fh.as_bytes().to_vec(), 1u64);
        parents.insert(1u64, 1u64);
        Self { inodes, handles, parents, lookups: HashMap::new(), next_ino: 2 }
    }

    /// Allocate or reuse an inode for a file handle.
    fn intern_handle(&mut self, fh: FileHandle, parent_ino: u64) -> u64 {
        let key = fh.as_bytes().to_vec();
        if let Some(&ino) = self.handles.get(&key) {
            return ino;
        }
        let ino = self.next_ino;
        self.next_ino = self.next_ino.saturating_add(1);
        self.inodes.insert(ino, fh);
        self.handles.insert(key, ino);
        self.parents.insert(ino, parent_ino);
        ino
    }

    fn fh_for(&self, ino: u64) -> Option<&FileHandle> {
        self.inodes.get(&ino)
    }

    /// Reverse-lookup the inode for an already-interned handle, WITHOUT
    /// interning a new one. readdir uses this to reuse the inode of an entry
    /// the kernel has already referenced while avoiding permanent state for
    /// entries that are merely listed.
    fn ino_for_handle(&self, fh: &FileHandle) -> Option<u64> {
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
    ///
    /// FUSE bumps an inode's lookup count by one for every entry reply
    /// (`lookup` / `create` / `mknod` / `mkdir` / `symlink` / `link`) and
    /// releases that many on the matching `forget`. Tracking the count lets
    /// us reclaim the inode/handle/parent maps once the kernel is done.
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
        self.lookups.remove(&ino);
        if let Some(fh) = self.inodes.remove(&ino) {
            self.handles.remove(fh.as_bytes());
        }
        self.parents.remove(&ino);
        true
    }
}

/// Construction parameters for `NfsFuse`.
///
/// The credential ladder, owner-bit elevation, and root-credential rungs are
/// always enabled: this is a security toolkit, the goal is unobstructed
/// access. Callers configure write-mode and supply the default credential
/// + runtime handle.
#[derive(Debug)]
pub struct NfsFuseConfig {
    /// Pool-backed NFS client (the default-credential client).
    pub nfs3: Arc<Nfs3Client>,
    /// Root file handle (becomes FUSE inode 1).
    pub root_fh: FileHandle,
    /// Forward write/modify operations through to the server.
    pub allow_write: bool,
    /// Default credential (the one rejected before ladder kicks in).
    pub default_cred: Credential,
    /// Tokio runtime handle (fuser threads are not Tokio tasks).
    pub rt: tokio::runtime::Handle,
}

/// NFS FUSE adapter  --  presents an NFS export as a local FUSE mount.
///
/// Created by `cli::mount::run()` and handed to `fuser::mount2()`. The
/// credential ladder runs unconditionally on every callback; per-inode
/// (uid, gid) winners are cached so we don't re-walk the ladder for the
/// same inode twice.
pub struct NfsFuse {
    /// Default-credential pool-backed NFS client.
    nfs3: Arc<Nfs3Client>,
    /// Mutable inode mapping.
    state: Mutex<InodeMapState>,
    /// Root file handle (inode 1).
    root_fh: FileHandle,
    /// When true, WRITE / SETATTR / CREATE / etc. are forwarded; otherwise EACCES.
    allow_write: bool,
    /// Default credential (used until a per-inode override is cached).
    default_cred: Credential,
    /// Per-inode (uid, gid) override discovered by the ladder.
    cred_cache: Mutex<HashMap<u64, (u32, u32)>>,
    /// Per-directory readdir page cache, keyed by directory inode.
    ///
    /// Populated by the `offset == 0` `readdir` callback (the whole directory
    /// is paged from the server exactly once) and served on every subsequent
    /// `offset > 0` callback, so a single listing pages the server only once
    /// instead of re-enumerating from cookie 0 on each kernel callback.
    /// Evicted in `forget` when the kernel releases the directory inode.
    readdir_cache: Mutex<HashMap<u64, Vec<ReaddirEntry>>>,
    /// Tokio runtime handle captured at construction.
    ///
    /// fuser invokes `Filesystem` callbacks on its own worker threads, which
    /// have no Tokio runtime context. Storing an explicit handle lets us
    /// dispatch async NFS calls onto the parent runtime via `block_on`,
    /// avoiding the `Handle::current()` panic on fuser-0.
    rt: tokio::runtime::Handle,
}

impl std::fmt::Debug for NfsFuse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NfsFuse").field("root_fh", &self.root_fh.to_hex()).finish_non_exhaustive()
    }
}

// Inode-state and credential-cache locks are protected by `Mutex`. A poisoned
// lock can only happen if a thread previously panicked while holding it; the
// expect calls below propagate the original panic, which is the correct
// behavior here. `significant_drop_tightening` and `redundant_clone` are
// inherent to the `Fn(Nfs3Client) -> Fut` ladder closures: each rung clones
// captured values fresh, but a single rung looks "redundant" to clippy.
#[allow(clippy::expect_used, clippy::significant_drop_tightening, clippy::redundant_clone, reason = "Mutex poison propagates and Fn-closure clones look redundant per-iteration")]
impl NfsFuse {
    /// Create a new FUSE adapter from a config bundle.
    ///
    /// `cfg.rt` must be a handle to the Tokio runtime that owns `cfg.nfs3`'s
    /// connection pool; it is used to drive async NFS calls from fuser's
    /// worker threads.
    #[must_use]
    pub fn new(cfg: NfsFuseConfig) -> Self {
        let state = Mutex::new(InodeMapState::new(&cfg.root_fh));
        Self { nfs3: cfg.nfs3, state, root_fh: cfg.root_fh, allow_write: cfg.allow_write, default_cred: cfg.default_cred, cred_cache: Mutex::new(HashMap::new()), readdir_cache: Mutex::new(HashMap::new()), rt: cfg.rt }
    }

    /// Convert our `FileAttrs` to a fuser `FileAttr`.
    fn make_attr(&self, ino: u64, a: &FileAttrs) -> FileAttr {
        let kind = to_fuse_type(a.file_type);
        let mode16 = u16::try_from(a.mode & u32::from(u16::MAX)).unwrap_or(0);
        // Always-on owner-bit elevation: copy owner rwx bits (bits 6-8) into
        // the other-rwx slot (bits 0-2) so unprivileged local users can reach
        // every file through FUSE. Server-side permissions are unchanged
        // -- this is purely a kernel-facing widening.
        let perm = mode16 | ((mode16 >> 6) & 0o007);
        FileAttr {
            ino: INodeNo(ino),
            size: a.size,
            blocks: a.used / 512,
            atime: nfs_time_to_system(a.atime.seconds, a.atime.nseconds),
            mtime: nfs_time_to_system(a.mtime.seconds, a.mtime.nseconds),
            ctime: nfs_time_to_system(a.ctime.seconds, a.ctime.nseconds),
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
    ///
    /// fuser calls are synchronous and arrive on fuser-owned worker threads
    /// (`fuser-0`, ...) which have no Tokio runtime context, so we cannot
    /// rely on `Handle::current()`. Instead we dispatch onto the runtime
    /// captured at `NfsFuse::new`. Safe because fuser worker threads are
    /// not Tokio tasks -- blocking one does not stall the scheduler.
    fn block<F, T>(&self, fut: F) -> T
    where
        F: Future<Output = T>,
    {
        self.rt.block_on(fut)
    }

    /// Build an NFS client with the given (uid, gid), reusing the default
    /// hostname from `default_cred`. Used to retry calls during the ladder.
    fn client_for(&self, uid: u32, gid: u32) -> Nfs3Client {
        let hostname = match &self.default_cred {
            Credential::Sys(a) => a.machinename.clone(),
            Credential::None => String::from("nfswolf"),
        };
        let cred = Credential::Sys(AuthSys::with_groups(uid, gid, &[gid], &hostname));
        self.nfs3.with_credential(cred, uid, gid)
    }

    /// Look up the cached `(uid, gid)` for `ino`, if any.
    fn cached_cred(&self, ino: u64) -> Option<(u32, u32)> {
        self.cred_cache.lock().expect("cred cache lock").get(&ino).copied()
    }

    /// Record `(uid, gid)` as the working credential for `ino`.
    fn cache_cred(&self, ino: u64, uid: u32, gid: u32) {
        self.cred_cache.lock().expect("cred cache lock").insert(ino, (uid, gid));
    }

    /// Bump the kernel lookup-reference count for `ino` (FUSE forget
    /// lifecycle). Called whenever we hand an inode to the kernel via an
    /// entry reply so a later `forget` can release it.
    fn record_lookup(&self, ino: u64) {
        self.state.lock().expect("inode map lock").record_lookup(ino);
    }

    /// Build the credential-escalation ladder for `subject_ino`.
    ///
    /// Mirrors the shell's behavior in `engine::credential::escalation_list`:
    /// owner first (when known via GETATTR), then root, then well-known
    /// service UIDs. Root rungs are always included -- this is a security
    /// toolkit, the goal is unobstructed access.
    async fn ladder_for(&self, subject_ino: u64) -> Vec<(u32, u32)> {
        let caller = (self.nfs3.uid(), self.nfs3.gid());
        let owner = {
            let fh_opt = self.state.lock().expect("inode map lock").fh_for(subject_ino).cloned();
            match fh_opt {
                Some(fh) => {
                    let args = GETATTR3args { object: fh.to_nfs_fh3() };
                    match self.nfs3.getattr(&args).await {
                        Ok(Nfs3Result::Ok(ok)) => Some((ok.obj_attributes.uid, ok.obj_attributes.gid)),
                        _ => None,
                    }
                },
                None => None,
            }
        };
        escalation_list(caller, owner)
    }

    /// Retrieve the file handle for inode `ino` from the inode map.
    fn fh_for_ino(&self, ino: u64) -> Option<FileHandle> {
        self.state.lock().expect("inode map lock").fh_for(ino).cloned()
    }

    /// Intern a child handle, returning the assigned inode.
    fn intern(&self, child_fh: FileHandle, parent_ino: u64) -> u64 {
        self.state.lock().expect("inode map lock").intern_handle(child_fh, parent_ino)
    }

    /// Maximum symlink resolution depth before we give up to prevent loops.
    const SYMLINK_DEPTH_LIMIT: u32 = 16;

    /// Hard cap on entries accumulated across READDIRPLUS pages.
    ///
    /// READDIRPLUS is looped until the server signals `eof` (RFC 1813 sec.
    /// 3.3.17); this cap bounds memory and CPU if a hostile or buggy server
    /// never sets eof (or keeps advancing the cookie forever). It is far
    /// above any realistic directory size.
    const MAX_READDIR_ENTRIES: usize = 1_000_000;

    /// Resolve a symlink chain server-side, starting from `link_fh` whose
    /// parent is inode `parent_ino`. Returns the eventual non-symlink
    /// `(file_handle, attrs)` or an error if the depth limit is hit, the
    /// chain leaves the export, or any RPC fails.
    ///
    /// Absolute targets (those starting with `/`) are resolved relative to
    /// the FUSE root (the export root); relative targets are resolved
    /// relative to the symlink's containing directory. If the target
    /// happens to also be a symlink we recurse until we hit a regular file
    /// or directory.
    async fn follow_symlink(&self, link_fh: FileHandle, parent_ino: u64, depth: u32) -> Result<(FileHandle, FileAttrs, u64), nfsstat3> {
        if depth >= Self::SYMLINK_DEPTH_LIMIT {
            return Err(nfsstat3::NFS3ERR_NAMETOOLONG);
        }

        // Read the symlink target.
        let args = READLINK3args { symlink: link_fh.to_nfs_fh3() };
        let target_bytes: Vec<u8> = match self.nfs3.readlink(&args).await {
            Ok(Nfs3Result::Ok(ok)) => ok.data.0.as_ref().to_vec(),
            Ok(Nfs3Result::Err((stat, _))) => return Err(stat),
            Err(_) => return Err(nfsstat3::NFS3ERR_IO),
        };

        // Decide where to start resolving from.
        let (start_ino, target_str) = if target_bytes.first() == Some(&b'/') {
            // Absolute target -- start at FUSE root (which corresponds to the
            // export root or whatever handle the user provided).
            (1u64, String::from_utf8_lossy(target_bytes.get(1..).unwrap_or(&[])).into_owned())
        } else {
            (parent_ino, String::from_utf8_lossy(&target_bytes).into_owned())
        };

        // Walk components, handling `.` and `..` along the way.
        let (mut cur_fh, mut cur_ino) = {
            let st = self.state.lock().expect("inode map lock");
            let fh = st.fh_for(start_ino).cloned().ok_or(nfsstat3::NFS3ERR_STALE)?;
            (fh, start_ino)
        };

        for component in target_str.split('/').filter(|c| !c.is_empty()) {
            if component == "." {
                continue;
            }
            if component == ".." {
                let parent = self.state.lock().expect("inode map lock").parents.get(&cur_ino).copied().unwrap_or(1);
                let parent_fh = self.fh_for_ino(parent).ok_or(nfsstat3::NFS3ERR_STALE)?;
                cur_fh = parent_fh;
                cur_ino = parent;
                continue;
            }
            let lookup = LOOKUP3args { what: diropargs3 { dir: cur_fh.to_nfs_fh3(), name: filename3(Opaque::owned(component.as_bytes().to_vec())) } };
            match self.nfs3.lookup(&lookup).await {
                Ok(Nfs3Result::Ok(ok)) => {
                    let next_fh = FileHandle::from_nfs_fh3(&ok.object);
                    let next_ino = self.intern(next_fh.clone(), cur_ino);
                    cur_fh = next_fh;
                    cur_ino = next_ino;
                },
                Ok(Nfs3Result::Err((stat, _))) => return Err(stat),
                Err(_) => return Err(nfsstat3::NFS3ERR_IO),
            }
        }

        // Final GETATTR to learn the type. If still a symlink, recurse.
        let attrs = match self.nfs3.getattr(&GETATTR3args { object: cur_fh.to_nfs_fh3() }).await {
            Ok(Nfs3Result::Ok(ok)) => FileAttrs::from_fattr3(&ok.obj_attributes),
            Ok(Nfs3Result::Err((stat, _))) => return Err(stat),
            Err(_) => return Err(nfsstat3::NFS3ERR_IO),
        };

        if attrs.file_type == FileType::Symlink {
            let parent_of_link = self.state.lock().expect("inode map lock").parents.get(&cur_ino).copied().unwrap_or(1);
            return Box::pin(self.follow_symlink(cur_fh, parent_of_link, depth + 1)).await;
        }

        Ok((cur_fh, attrs, cur_ino))
    }

    /// Run an NFS3 operation with the credential-escalation ladder.
    ///
    /// Tries, in order: any per-inode cached credential, then the default
    /// credential. Only if BOTH are rejected with `NFS3ERR_ACCES` /
    /// `NFS3ERR_PERM` does it walk the rungs of `escalation_list(caller,
    /// owner)` -- so the happy path never pays for the owner-discovery
    /// GETATTR inside `ladder_for`. The first attempt that does not return
    /// `NFS3ERR_ACCES` / `NFS3ERR_PERM` wins; the winning credential is
    /// cached for `subject_ino` so subsequent calls skip the search.
    ///
    /// `op` is invoked with a fresh `Nfs3Client` that carries the credential
    /// for the rung being tried; the closure builds the args and calls the
    /// matching NFS3 procedure.
    async fn try_with_ladder<F, Fut, T, U>(&self, subject_ino: u64, op: F) -> anyhow::Result<Nfs3Result<T, U>>
    where
        F: Fn(Nfs3Client) -> Fut,
        Fut: Future<Output = anyhow::Result<Nfs3Result<T, U>>>,
    {
        // Primary credentials: any per-inode cached winner, then the default.
        // We only fall back to the escalation ladder -- which costs an
        // owner-discovery GETATTR in `ladder_for` -- after BOTH of these are
        // rejected with NFS3ERR_ACCES / NFS3ERR_PERM. This keeps the common
        // path a single RPC instead of speculatively probing the file owner
        // on every callback.
        let default = (self.nfs3.uid(), self.nfs3.gid());
        let mut primary: Vec<(u32, u32)> = Vec::new();
        if let Some(pair) = self.cached_cred(subject_ino) {
            primary.push(pair);
        }
        if !primary.contains(&default) {
            primary.push(default);
        }

        let mut tried: Vec<(u32, u32)> = Vec::new();
        let mut last: Option<anyhow::Result<Nfs3Result<T, U>>> = None;
        for (u, g) in primary {
            tried.push((u, g));
            let c = self.client_for(u, g);
            let r = op(c).await;
            match r {
                Ok(Nfs3Result::Err((nfsstat3::NFS3ERR_ACCES | nfsstat3::NFS3ERR_PERM, _))) => {
                    last = Some(r);
                },
                Ok(_) => {
                    if (u, g) != default {
                        self.cache_cred(subject_ino, u, g);
                    }
                    return r;
                },
                Err(_) => return r,
            }
        }

        // Primary credentials were denied; now walk the escalation ladder
        // (this is where the owner-discovery GETATTR is paid for).
        for (u, g) in self.ladder_for(subject_ino).await {
            if tried.contains(&(u, g)) {
                continue;
            }
            let c = self.client_for(u, g);
            let r = op(c).await;
            match r {
                Ok(Nfs3Result::Err((nfsstat3::NFS3ERR_ACCES | nfsstat3::NFS3ERR_PERM, _))) => {
                    last = Some(r);
                },
                Ok(_) => {
                    if (u, g) != default {
                        self.cache_cred(subject_ino, u, g);
                    }
                    return r;
                },
                Err(_) => return r,
            }
        }
        last.unwrap_or_else(|| Err(anyhow::anyhow!("no credential rungs to try for inode {subject_ino}")))
    }

    /// LOOKUP with the credential-escalation ladder, with server-side
    /// symlink follow on success.
    ///
    /// Allocates an inode for the resolved object, fills in attrs (via a
    /// follow-up GETATTR if the LOOKUP didn't return them), and chases
    /// symlink chains with `follow_symlink`.
    async fn try_lookup_with_ladder(&self, parent_fh: &FileHandle, name_bytes: &[u8], parent_ino: u64) -> Result<(FileHandle, FileAttrs, u64), nfsstat3> {
        let result = self
            .try_with_ladder(parent_ino, |c| {
                let parent_fh = parent_fh.clone();
                let name_bytes = name_bytes.to_vec();
                async move {
                    let args = LOOKUP3args { what: diropargs3 { dir: parent_fh.to_nfs_fh3(), name: filename3(Opaque::owned(name_bytes)) } };
                    c.lookup(&args).await
                }
            })
            .await
            .map_err(|_| nfsstat3::NFS3ERR_IO)?;

        let (child_fh, attrs_opt) = match result {
            Nfs3Result::Ok(ok) => {
                let fh = FileHandle::from_nfs_fh3(&ok.object);
                let attrs = post_op_attr_to_attrs(ok.obj_attributes);
                (fh, attrs)
            },
            Nfs3Result::Err((stat, _)) => return Err(stat),
        };

        let child_ino = self.intern(child_fh.clone(), parent_ino);

        let attrs = match attrs_opt {
            Some(a) => a,
            None => self.try_getattr(child_ino).await.ok_or(nfsstat3::NFS3ERR_IO)?,
        };

        if attrs.file_type == FileType::Symlink {
            return self.follow_symlink(child_fh, parent_ino, 0).await;
        }
        Ok((child_fh, attrs, child_ino))
    }

    /// LOOKUP that resolves `(handle, attrs)` WITHOUT interning an inode.
    ///
    /// Used by the readdir null-attr/null-handle fix-up: a merely-listed entry
    /// takes no kernel lookup reference, so it must not be permanently interned
    /// (that would leak -- `forget` only reclaims lookup-counted inodes). Unlike
    /// `try_lookup_with_ladder`, this neither interns nor follows symlinks (the
    /// listing shows the link itself); the kernel's later explicit LOOKUP does
    /// the authoritative, lookup-counted intern.
    async fn lookup_no_intern(&self, parent_fh: &FileHandle, name_bytes: &[u8], parent_ino: u64) -> Result<(FileHandle, FileAttrs), nfsstat3> {
        let result = self
            .try_with_ladder(parent_ino, |c| {
                let parent_fh = parent_fh.clone();
                let name_bytes = name_bytes.to_vec();
                async move {
                    let args = LOOKUP3args { what: diropargs3 { dir: parent_fh.to_nfs_fh3(), name: filename3(Opaque::owned(name_bytes)) } };
                    c.lookup(&args).await
                }
            })
            .await
            .map_err(|_| nfsstat3::NFS3ERR_IO)?;

        let (child_fh, attrs_opt) = match result {
            Nfs3Result::Ok(ok) => (FileHandle::from_nfs_fh3(&ok.object), post_op_attr_to_attrs(ok.obj_attributes)),
            Nfs3Result::Err((stat, _)) => return Err(stat),
        };

        let attrs = if let Some(a) = attrs_opt {
            a
        } else {
            // GETATTR the child handle directly (no intern) via the ladder.
            let fh = child_fh.clone();
            let r = self
                .try_with_ladder(parent_ino, move |c| {
                    let fh = fh.clone();
                    async move { c.getattr(&GETATTR3args { object: fh.to_nfs_fh3() }).await }
                })
                .await
                .map_err(|_| nfsstat3::NFS3ERR_IO)?;
            match r {
                Nfs3Result::Ok(ok) => FileAttrs::from_fattr3(&ok.obj_attributes),
                Nfs3Result::Err((stat, _)) => return Err(stat),
            }
        };
        Ok((child_fh, attrs))
    }

    /// GETATTR helper that runs the credential ladder. Returns `None` on
    /// any error so the caller can map to a single ENOENT/EIO reply.
    async fn try_getattr(&self, ino: u64) -> Option<FileAttrs> {
        let fh = self.fh_for_ino(ino)?;
        let result = self
            .try_with_ladder(ino, |c| {
                let fh = fh.clone();
                async move {
                    let args = GETATTR3args { object: fh.to_nfs_fh3() };
                    c.getattr(&args).await
                }
            })
            .await
            .ok()?;
        match result {
            Nfs3Result::Ok(ok) => Some(FileAttrs::from_fattr3(&ok.obj_attributes)),
            Nfs3Result::Err(_) => None,
        }
    }

    /// Intern a new entry returned by CREATE / MKNOD / MKDIR / SYMLINK,
    /// falling back to LOOKUP when the server's response left out either
    /// the post-op file handle or the post-op attributes (RFC 1813 makes
    /// both optional for compactness).
    fn intern_with_lookup_fallback(&self, parent_ino: u64, parent_fh: &FileHandle, name_bytes: &[u8], fh_opt: Option<FileHandle>, attrs_opt: Option<FileAttrs>) -> Option<(FileHandle, u64, FileAttrs)> {
        if let (Some(fh), Some(a)) = (fh_opt, attrs_opt) {
            let ino = self.intern(fh.clone(), parent_ino);
            return Some((fh, ino, a));
        }
        let (fh, a, ino) = self.block(self.try_lookup_with_ladder(parent_fh, name_bytes, parent_ino)).ok()?;
        Some((fh, ino, a))
    }

    /// Page an entire directory via a looped READDIRPLUS, returning owned
    /// entry tuples. NFSv3 READDIRPLUS (RFC 1813 sec. 3.3.17) returns at most
    /// `maxcount` bytes per call and clears `eof` when more entries remain, so
    /// we carry the server cookie + cookieverf forward until eof. Accumulation
    /// is capped at `MAX_READDIR_ENTRIES` to stay safe against a hostile or
    /// buggy server that never sets eof (or never advances the cookie). Each
    /// page still runs through the credential-escalation ladder. Called once
    /// per listing (on the `offset == 0` readdir callback) so the server is
    /// paged a single time rather than re-enumerated on every kernel callback.
    fn page_directory(&self, ino: u64, dir_fh: &FileHandle) -> Result<Vec<ReaddirEntry>, Errno> {
        let mut entries: Vec<ReaddirEntry> = Vec::new();
        let mut cookie: u64 = 0;
        let mut cookieverf: [u8; 8] = [0u8; 8];
        loop {
            let result = self.block(self.try_with_ladder(ino, |c| {
                let dir_fh = dir_fh.clone();
                async move {
                    let args = READDIRPLUS3args { dir: dir_fh.to_nfs_fh3(), cookie, cookieverf: cookieverf3(cookieverf), dircount: 4096, maxcount: 65_536 };
                    c.readdirplus(&args).await
                }
            }));

            match result {
                Ok(Nfs3Result::Ok(ok)) => {
                    cookieverf = ok.cookieverf.0;
                    let eof = ok.reply.eof;
                    let page = ok.reply.entries.into_inner();
                    let last_cookie = page.last().map(|e| e.cookie);
                    for e in page {
                        let name = e.name.as_ref().to_vec();
                        let attrs = match e.name_attributes {
                            Nfs3Option::Some(a) => Some(FileAttrs::from_fattr3(&a)),
                            Nfs3Option::None => None,
                        };
                        let handle = match e.name_handle {
                            Nfs3Option::Some(fh) => Some(FileHandle::from_nfs_fh3(&fh)),
                            Nfs3Option::None => None,
                        };
                        entries.push((name, attrs, handle));
                    }
                    // Stop at eof, on the entry cap, on an empty page, or if the
                    // cookie fails to advance (defensive: a buggy server must
                    // not spin us forever).
                    let at_cap = entries.len() >= Self::MAX_READDIR_ENTRIES;
                    match last_cookie {
                        Some(c) if !eof && !at_cap && c != cookie => cookie = c,
                        _ => break,
                    }
                },
                Ok(Nfs3Result::Err((nfsstat3::NFS3ERR_ACCES | nfsstat3::NFS3ERR_PERM, _))) => {
                    tracing::debug!(?ino, "READDIRPLUS denied: NFS3ERR_ACCES");
                    return Err(Errno::EACCES);
                },
                Ok(Nfs3Result::Err((stat, _))) => {
                    tracing::debug!(?ino, ?stat, "READDIRPLUS failed");
                    return Err(Errno::EIO);
                },
                Err(e) => {
                    tracing::debug!(?ino, error = %e, "READDIRPLUS RPC error");
                    return Err(Errno::EIO);
                },
            }
        }
        Ok(entries)
    }
}

// The Mutex protecting the inode state can only be poisoned if a thread panics
// while holding it, which propagates the panic anyway -- expect() is correct here.
#[allow(clippy::expect_used, reason = "Mutex poison propagates existing panics")]
impl Filesystem for NfsFuse {
    /// Look up a directory entry by name and return its attributes.
    ///
    /// Server-side symlink follow is always on: if the LOOKUP result is a
    /// symlink we READLINK and walk to the target before replying, so the
    /// kernel never sees the underlying symlink.
    fn lookup(&self, _req: &Request, parent: INodeNo, name: &std::ffi::OsStr, reply: ReplyEntry) {
        let Some(parent_fh) = self.fh_for_ino(parent.0) else {
            reply.error(Errno::ENOENT);
            return;
        };

        let name_bytes = name.as_encoded_bytes().to_vec();
        let result = self.block(self.try_lookup_with_ladder(&parent_fh, &name_bytes, parent.0));

        match result {
            Ok((child_fh, attrs, child_ino)) => {
                self.record_lookup(child_ino);
                let attr = self.make_attr(child_ino, &attrs);
                reply.entry(&ATTR_TTL, &attr, Generation(0));
                let _ = child_fh; // file handle already interned
            },
            Err(nfsstat3::NFS3ERR_NOENT) => reply.error(Errno::ENOENT),
            Err(nfsstat3::NFS3ERR_ACCES | nfsstat3::NFS3ERR_PERM) => reply.error(Errno::EACCES),
            Err(stat) => {
                tracing::debug!(?parent, ?stat, "LOOKUP failed");
                reply.error(Errno::EIO);
            },
        }
    }

    /// Forget an inode (FUSE lifetime management).
    ///
    /// The kernel drops `nlookup` of the references it acquired via earlier
    /// entry replies; once they reach zero we evict the inode from every map
    /// (inode / handle / parent + the per-inode credential cache) so a
    /// long-lived mount that walks large trees does not grow these maps
    /// without bound. fuser's default `batch_forget` dispatches to this per
    /// node, so multi-forget batches are covered too.
    fn forget(&self, _req: &Request, ino: INodeNo, nlookup: u64) {
        let removed = self.state.lock().expect("inode map lock").forget(ino.0, nlookup);
        if removed {
            self.cred_cache.lock().expect("cred cache lock").remove(&ino.0);
            self.readdir_cache.lock().expect("readdir cache lock").remove(&ino.0);
        }
    }

    /// Get file attributes for inode `ino`.
    fn getattr(&self, _req: &Request, ino: INodeNo, _fh: Option<FuseFileHandle>, reply: ReplyAttr) {
        let Some(fh) = self.fh_for_ino(ino.0) else {
            reply.error(Errno::ENOENT);
            return;
        };

        let result = self.block(self.try_with_ladder(ino.0, |c| {
            let fh = fh.clone();
            async move {
                let args = GETATTR3args { object: fh.to_nfs_fh3() };
                c.getattr(&args).await
            }
        }));

        match result {
            Ok(Nfs3Result::Ok(ok)) => {
                let a = FileAttrs::from_fattr3(&ok.obj_attributes);
                let attr = self.make_attr(ino.0, &a);
                reply.attr(&ATTR_TTL, &attr);
            },
            Ok(Nfs3Result::Err((nfsstat3::NFS3ERR_ACCES | nfsstat3::NFS3ERR_PERM, _))) => reply.error(Errno::EACCES),
            Ok(Nfs3Result::Err(_)) | Err(_) => reply.error(Errno::EIO),
        }
    }

    /// SETATTR -- chmod / chown / utime / truncate.
    ///
    /// fuser packs all `setattr` requests into one callback regardless of
    /// which fields the caller wanted to change; the unset ones come in as
    /// `None` and we map those to `set_*::DONT_CHANGE` so the server-side
    /// state is left alone.
    #[allow(clippy::too_many_arguments, reason = "fuser callback signature")]
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
        if !self.allow_write {
            reply.error(Errno::EACCES);
            return;
        }
        let Some(fh) = self.fh_for_ino(ino.0) else {
            reply.error(Errno::ENOENT);
            return;
        };

        let new_attrs = sattr3 {
            mode: mode.map_or(Nfs3Option::None, Nfs3Option::Some),
            uid: uid.map_or(Nfs3Option::None, Nfs3Option::Some),
            gid: gid.map_or(Nfs3Option::None, Nfs3Option::Some),
            size: size.map_or(Nfs3Option::None, Nfs3Option::Some),
            atime: time_or_now_to_set_atime(atime),
            mtime: time_or_now_to_set_mtime(mtime),
        };

        let result = self.block(self.try_with_ladder(ino.0, |c| {
            let fh = fh.clone();
            let new_attrs = new_attrs.clone();
            async move {
                let args = SETATTR3args { object: fh.to_nfs_fh3(), new_attributes: new_attrs, guard: Nfs3Option::None };
                c.setattr(&args).await
            }
        }));

        match result {
            Ok(Nfs3Result::Ok(ok)) => match ok.obj_wcc.after {
                Nfs3Option::Some(a) => {
                    let attrs = FileAttrs::from_fattr3(&a);
                    reply.attr(&ATTR_TTL, &self.make_attr(ino.0, &attrs));
                },
                Nfs3Option::None => {
                    // SETATTR succeeded but server didn't return post-op attrs;
                    // re-issue GETATTR to keep the kernel in sync.
                    if let Some(attrs) = self.block(self.try_getattr(ino.0)) {
                        reply.attr(&ATTR_TTL, &self.make_attr(ino.0, &attrs));
                    } else {
                        reply.error(Errno::EIO);
                    }
                },
            },
            Ok(Nfs3Result::Err((nfsstat3::NFS3ERR_ACCES | nfsstat3::NFS3ERR_PERM, _))) => reply.error(Errno::EACCES),
            Ok(Nfs3Result::Err((nfsstat3::NFS3ERR_NOTSUPP, _))) => reply.error(Errno::ENOTSUP),
            Ok(Nfs3Result::Err(_)) | Err(_) => reply.error(Errno::EIO),
        }
    }

    /// ACCESS -- advisory permission check (RFC 1813 S3.3.4).
    ///
    /// We translate the FUSE access mask into the NFSv3 ACCESS bits and
    /// honour what the server says; the spec is explicit that ACCESS is
    /// advisory only, but the kernel's mask check usually wants this.
    fn access(&self, _req: &Request, ino: INodeNo, mask: AccessFlags, reply: ReplyEmpty) {
        let Some(fh) = self.fh_for_ino(ino.0) else {
            reply.error(Errno::ENOENT);
            return;
        };

        let nfs_mask = access_flags_to_nfs(mask);

        let result = self.block(self.try_with_ladder(ino.0, |c| {
            let fh = fh.clone();
            async move {
                let args = ACCESS3args { object: fh.to_nfs_fh3(), access: nfs_mask };
                c.access(&args).await
            }
        }));

        match result {
            Ok(Nfs3Result::Ok(ok)) => {
                if (ok.access & nfs_mask) == nfs_mask {
                    reply.ok();
                } else {
                    reply.error(Errno::EACCES);
                }
            },
            Ok(Nfs3Result::Err((nfsstat3::NFS3ERR_ACCES | nfsstat3::NFS3ERR_PERM, _))) => reply.error(Errno::EACCES),
            Ok(Nfs3Result::Err(_)) | Err(_) => reply.error(Errno::EIO),
        }
    }

    /// READLINK -- return the raw target bytes the kernel asked for.
    ///
    /// `lookup` already follows symlinks server-side so the kernel rarely
    /// sees a NF3LNK on this FUSE mount, but we still implement readlink
    /// for completeness and for the case where someone holds a handle to
    /// a symlink directly.
    fn readlink(&self, _req: &Request, ino: INodeNo, reply: ReplyData) {
        let Some(fh) = self.fh_for_ino(ino.0) else {
            reply.error(Errno::ENOENT);
            return;
        };

        let result = self.block(self.try_with_ladder(ino.0, |c| {
            let fh = fh.clone();
            async move {
                let args = READLINK3args { symlink: fh.to_nfs_fh3() };
                c.readlink(&args).await
            }
        }));

        match result {
            Ok(Nfs3Result::Ok(ok)) => reply.data(ok.data.0.as_ref()),
            Ok(Nfs3Result::Err((nfsstat3::NFS3ERR_ACCES | nfsstat3::NFS3ERR_PERM, _))) => reply.error(Errno::EACCES),
            Ok(Nfs3Result::Err(_)) | Err(_) => reply.error(Errno::EIO),
        }
    }

    /// MKNOD -- create a special file (FIFO, socket, char/block device).
    ///
    /// Regular files come through `create()` instead.
    fn mknod(&self, _req: &Request, parent: INodeNo, name: &std::ffi::OsStr, mode: u32, _umask: u32, rdev: u32, reply: ReplyEntry) {
        if !self.allow_write {
            reply.error(Errno::EACCES);
            return;
        }
        let Some(parent_fh) = self.fh_for_ino(parent.0) else {
            reply.error(Errno::ENOENT);
            return;
        };

        let kind = mode & 0o170_000;
        let perms = mode & 0o7777;
        let name_bytes = name.as_encoded_bytes().to_vec();

        // Validate the file-type bits up front; mknoddata3 itself isn't
        // Clone, so we rebuild it inside the closure on each ladder rung.
        match kind {
            0o010_000 | 0o014_000 | 0o020_000 | 0o060_000 => {},
            _ => {
                // 0o100_000 (regular file) goes through `create` in modern
                // kernels; anything else (e.g. door files) is unsupported.
                reply.error(Errno::ENOTSUP);
                return;
            },
        }

        let result = self.block(self.try_with_ladder(parent.0, |c| {
            let parent_fh = parent_fh.clone();
            let name_bytes = name_bytes.clone();
            let attrs = sattr3_for_perms(perms);
            // FUSE delivers `rdev` in the kernel's new_encode_dev packing:
            // minor low 8 bits, major in bits 8-19, minor high bits in bits
            // 20-31. Both major and minor can exceed 8 bits, so decode the full
            // values (the previous `& 0xff` masks truncated them) and place
            // major in specdata1, minor in specdata2 -- RFC 1813 sec. 2.5: for
            // NF3CHR / NF3BLK specdata1 and specdata2 are the major and minor
            // device numbers respectively.
            let major = (rdev >> 8) & 0xfff;
            let minor = (rdev & 0xff) | ((rdev >> 12) & 0x000f_ff00);
            let spec = specdata3 { specdata1: major, specdata2: minor };
            let what = match kind {
                0o010_000 => mknoddata3::NF3FIFO(attrs),
                0o014_000 => mknoddata3::NF3SOCK(attrs),
                0o020_000 => mknoddata3::NF3CHR(devicedata3 { dev_attributes: attrs, spec }),
                _ => mknoddata3::NF3BLK(devicedata3 { dev_attributes: attrs, spec }),
            };
            async move {
                let args = MKNOD3args { where_: diropargs3 { dir: parent_fh.to_nfs_fh3(), name: filename3(Opaque::owned(name_bytes)) }, what };
                c.mknod(&args).await
            }
        }));

        match result {
            Ok(Nfs3Result::Ok(ok)) => {
                let fh_opt = post_op_fh3_to_handle(ok.obj);
                let attrs_opt = post_op_attr_to_attrs(ok.obj_attributes);
                let Some((_child_fh, child_ino, attrs)) = self.intern_with_lookup_fallback(parent.0, &parent_fh, &name_bytes, fh_opt, attrs_opt) else {
                    reply.error(Errno::EIO);
                    return;
                };
                self.record_lookup(child_ino);
                reply.entry(&ATTR_TTL, &self.make_attr(child_ino, &attrs), Generation(0));
            },
            Ok(Nfs3Result::Err((nfsstat3::NFS3ERR_ACCES | nfsstat3::NFS3ERR_PERM, _))) => reply.error(Errno::EACCES),
            Ok(Nfs3Result::Err((nfsstat3::NFS3ERR_EXIST, _))) => reply.error(Errno::EEXIST),
            Ok(Nfs3Result::Err(_)) | Err(_) => reply.error(Errno::EIO),
        }
    }

    /// MKDIR -- create a subdirectory.
    fn mkdir(&self, _req: &Request, parent: INodeNo, name: &std::ffi::OsStr, mode: u32, _umask: u32, reply: ReplyEntry) {
        if !self.allow_write {
            reply.error(Errno::EACCES);
            return;
        }
        let Some(parent_fh) = self.fh_for_ino(parent.0) else {
            reply.error(Errno::ENOENT);
            return;
        };

        let name_bytes = name.as_encoded_bytes().to_vec();
        let attrs = sattr3_for_perms(mode & 0o7777);

        let result = self.block(self.try_with_ladder(parent.0, |c| {
            let parent_fh = parent_fh.clone();
            let name_bytes = name_bytes.clone();
            let attrs = attrs.clone();
            async move {
                let args = MKDIR3args { where_: diropargs3 { dir: parent_fh.to_nfs_fh3(), name: filename3(Opaque::owned(name_bytes)) }, attributes: attrs };
                c.mkdir(&args).await
            }
        }));

        match result {
            Ok(Nfs3Result::Ok(ok)) => {
                let fh_opt = post_op_fh3_to_handle(ok.obj);
                let attrs_opt = post_op_attr_to_attrs(ok.obj_attributes);
                let Some((_child_fh, child_ino, attrs)) = self.intern_with_lookup_fallback(parent.0, &parent_fh, &name_bytes, fh_opt, attrs_opt) else {
                    reply.error(Errno::EIO);
                    return;
                };
                self.record_lookup(child_ino);
                reply.entry(&ATTR_TTL, &self.make_attr(child_ino, &attrs), Generation(0));
            },
            Ok(Nfs3Result::Err((nfsstat3::NFS3ERR_ACCES | nfsstat3::NFS3ERR_PERM, _))) => reply.error(Errno::EACCES),
            Ok(Nfs3Result::Err((nfsstat3::NFS3ERR_EXIST, _))) => reply.error(Errno::EEXIST),
            Ok(Nfs3Result::Err(_)) | Err(_) => reply.error(Errno::EIO),
        }
    }

    /// SYMLINK -- create a symbolic link.
    fn symlink(&self, _req: &Request, parent: INodeNo, link_name: &std::ffi::OsStr, target: &Path, reply: ReplyEntry) {
        if !self.allow_write {
            reply.error(Errno::EACCES);
            return;
        }
        let Some(parent_fh) = self.fh_for_ino(parent.0) else {
            reply.error(Errno::ENOENT);
            return;
        };

        let name_bytes = link_name.as_encoded_bytes().to_vec();
        let target_bytes: Vec<u8> = target.as_os_str().as_encoded_bytes().to_vec();

        let result = self.block(self.try_with_ladder(parent.0, |c| {
            let parent_fh = parent_fh.clone();
            let name_bytes = name_bytes.clone();
            let target_bytes = target_bytes.clone();
            async move {
                let args = SYMLINK3args { where_: diropargs3 { dir: parent_fh.to_nfs_fh3(), name: filename3(Opaque::owned(name_bytes)) }, symlink: symlinkdata3 { symlink_attributes: sattr3_for_perms(0o777), symlink_data: nfspath3(Opaque::owned(target_bytes)) } };
                c.symlink(&args).await
            }
        }));

        match result {
            Ok(Nfs3Result::Ok(ok)) => {
                let fh_opt = post_op_fh3_to_handle(ok.obj);
                let attrs_opt = post_op_attr_to_attrs(ok.obj_attributes);
                let Some((_child_fh, child_ino, attrs)) = self.intern_with_lookup_fallback(parent.0, &parent_fh, &name_bytes, fh_opt, attrs_opt) else {
                    reply.error(Errno::EIO);
                    return;
                };
                self.record_lookup(child_ino);
                reply.entry(&ATTR_TTL, &self.make_attr(child_ino, &attrs), Generation(0));
            },
            Ok(Nfs3Result::Err((nfsstat3::NFS3ERR_ACCES | nfsstat3::NFS3ERR_PERM, _))) => reply.error(Errno::EACCES),
            Ok(Nfs3Result::Err((nfsstat3::NFS3ERR_EXIST, _))) => reply.error(Errno::EEXIST),
            Ok(Nfs3Result::Err(_)) | Err(_) => reply.error(Errno::EIO),
        }
    }

    /// CREATE -- atomic create-and-open of a regular file.
    fn create(&self, _req: &Request, parent: INodeNo, name: &std::ffi::OsStr, mode: u32, _umask: u32, _flags: i32, reply: ReplyCreate) {
        if !self.allow_write {
            reply.error(Errno::EACCES);
            return;
        }
        let Some(parent_fh) = self.fh_for_ino(parent.0) else {
            reply.error(Errno::ENOENT);
            return;
        };

        let name_bytes = name.as_encoded_bytes().to_vec();
        let attrs = sattr3_for_perms(mode & 0o7777);

        let result = self.block(self.try_with_ladder(parent.0, |c| {
            let parent_fh = parent_fh.clone();
            let name_bytes = name_bytes.clone();
            let attrs = attrs.clone();
            async move {
                let args = CREATE3args { where_: diropargs3 { dir: parent_fh.to_nfs_fh3(), name: filename3(Opaque::owned(name_bytes)) }, how: createhow3::UNCHECKED(attrs) };
                c.create(&args).await
            }
        }));

        match result {
            Ok(Nfs3Result::Ok(ok)) => {
                let fh_opt = match ok.obj {
                    Nfs3Option::Some(fh) => Some(FileHandle::from_nfs_fh3(&fh)),
                    Nfs3Option::None => None,
                };
                let attrs_opt = match ok.obj_attributes {
                    Nfs3Option::Some(a) => Some(FileAttrs::from_fattr3(&a)),
                    Nfs3Option::None => None,
                };

                let Some((child_fh, child_ino, attrs)) = self.intern_with_lookup_fallback(parent.0, &parent_fh, &name_bytes, fh_opt, attrs_opt) else {
                    reply.error(Errno::EIO);
                    return;
                };

                self.record_lookup(child_ino);
                let attr = self.make_attr(child_ino, &attrs);
                reply.created(&ATTR_TTL, &attr, Generation(0), FuseFileHandle(0), FopenFlags::empty());
                let _ = child_fh;
            },
            Ok(Nfs3Result::Err((nfsstat3::NFS3ERR_ACCES | nfsstat3::NFS3ERR_PERM, _))) => reply.error(Errno::EACCES),
            Ok(Nfs3Result::Err((nfsstat3::NFS3ERR_EXIST, _))) => reply.error(Errno::EEXIST),
            Ok(Nfs3Result::Err(_)) | Err(_) => reply.error(Errno::EIO),
        }
    }

    /// REMOVE -- delete a regular file (or a special file / symlink).
    fn unlink(&self, _req: &Request, parent: INodeNo, name: &std::ffi::OsStr, reply: ReplyEmpty) {
        if !self.allow_write {
            reply.error(Errno::EACCES);
            return;
        }
        let Some(parent_fh) = self.fh_for_ino(parent.0) else {
            reply.error(Errno::ENOENT);
            return;
        };
        let name_bytes = name.as_encoded_bytes().to_vec();

        let result = self.block(self.try_with_ladder(parent.0, |c| {
            let parent_fh = parent_fh.clone();
            let name_bytes = name_bytes.clone();
            async move {
                let args = REMOVE3args { object: diropargs3 { dir: parent_fh.to_nfs_fh3(), name: filename3(Opaque::owned(name_bytes)) } };
                c.remove(&args).await
            }
        }));
        reply_empty(&result, reply);
    }

    /// RMDIR -- remove a directory.
    fn rmdir(&self, _req: &Request, parent: INodeNo, name: &std::ffi::OsStr, reply: ReplyEmpty) {
        if !self.allow_write {
            reply.error(Errno::EACCES);
            return;
        }
        let Some(parent_fh) = self.fh_for_ino(parent.0) else {
            reply.error(Errno::ENOENT);
            return;
        };
        let name_bytes = name.as_encoded_bytes().to_vec();

        let result = self.block(self.try_with_ladder(parent.0, |c| {
            let parent_fh = parent_fh.clone();
            let name_bytes = name_bytes.clone();
            async move {
                let args = RMDIR3args { object: diropargs3 { dir: parent_fh.to_nfs_fh3(), name: filename3(Opaque::owned(name_bytes)) } };
                c.rmdir(&args).await
            }
        }));
        reply_empty(&result, reply);
    }

    /// RENAME -- move a file from `(parent, name)` to `(newparent, newname)`.
    fn rename(&self, _req: &Request, parent: INodeNo, name: &std::ffi::OsStr, newparent: INodeNo, newname: &std::ffi::OsStr, _flags: RenameFlags, reply: ReplyEmpty) {
        if !self.allow_write {
            reply.error(Errno::EACCES);
            return;
        }
        let (Some(from_dir), Some(to_dir)) = (self.fh_for_ino(parent.0), self.fh_for_ino(newparent.0)) else {
            reply.error(Errno::ENOENT);
            return;
        };
        let from_name = name.as_encoded_bytes().to_vec();
        let to_name = newname.as_encoded_bytes().to_vec();

        let result = self.block(self.try_with_ladder(parent.0, |c| {
            let from_dir = from_dir.clone();
            let to_dir = to_dir.clone();
            let from_name = from_name.clone();
            let to_name = to_name.clone();
            async move {
                let args = RENAME3args { from: diropargs3 { dir: from_dir.to_nfs_fh3(), name: filename3(Opaque::owned(from_name)) }, to: diropargs3 { dir: to_dir.to_nfs_fh3(), name: filename3(Opaque::owned(to_name)) } };
                c.rename(&args).await
            }
        }));
        reply_empty(&result, reply);
    }

    /// LINK -- create a hard link.
    fn link(&self, _req: &Request, ino: INodeNo, newparent: INodeNo, newname: &std::ffi::OsStr, reply: ReplyEntry) {
        if !self.allow_write {
            reply.error(Errno::EACCES);
            return;
        }
        let (Some(target_fh), Some(parent_fh)) = (self.fh_for_ino(ino.0), self.fh_for_ino(newparent.0)) else {
            reply.error(Errno::ENOENT);
            return;
        };
        let new_name = newname.as_encoded_bytes().to_vec();

        let result = self.block(self.try_with_ladder(newparent.0, |c| {
            let target_fh = target_fh.clone();
            let parent_fh = parent_fh.clone();
            let new_name = new_name.clone();
            async move {
                let args = LINK3args { file: target_fh.to_nfs_fh3(), link: diropargs3 { dir: parent_fh.to_nfs_fh3(), name: filename3(Opaque::owned(new_name)) } };
                c.link(&args).await
            }
        }));

        // LINK does not return a new handle (it's the same inode), so we
        // re-use the existing one and fetch fresh attrs.
        match result {
            Ok(Nfs3Result::Ok(_)) => {
                if let Some(attrs) = self.block(self.try_getattr(ino.0)) {
                    self.record_lookup(ino.0);
                    reply.entry(&ATTR_TTL, &self.make_attr(ino.0, &attrs), Generation(0));
                } else {
                    reply.error(Errno::EIO);
                }
            },
            Ok(Nfs3Result::Err((nfsstat3::NFS3ERR_ACCES | nfsstat3::NFS3ERR_PERM, _))) => reply.error(Errno::EACCES),
            Ok(Nfs3Result::Err((nfsstat3::NFS3ERR_EXIST, _))) => reply.error(Errno::EEXIST),
            Ok(Nfs3Result::Err(_)) | Err(_) => reply.error(Errno::EIO),
        }
    }

    /// READDIRPLUS -- list directory entries with attributes / handles.
    ///
    /// Always fills in any `name_attributes = None` / `name_handle = None`
    /// entries via individual LOOKUP calls (the NetApp / nested-export
    /// fix-up). This makes `ls -l` correct on servers that omit inline
    /// attrs by default.
    fn readdir(&self, _req: &Request, ino: INodeNo, _fh: FuseFileHandle, offset: u64, mut reply: ReplyDirectory) {
        let Some(dir_fh) = self.fh_for_ino(ino.0) else {
            reply.error(Errno::ENOENT);
            return;
        };

        // Offset-aware paging. The kernel resumes a large listing by re-calling
        // readdir with an advancing `offset` each time the reply buffer fills;
        // paging the whole directory from cookie 0 on every callback would turn
        // one `ls` into O(callbacks x server-pages) READDIRPLUS RPCs. Instead we
        // page the server exactly once -- on the `offset == 0` callback -- cache
        // the fully-paged owned entry vector keyed by directory inode, and serve
        // every later (`offset > 0`) callback from that cache. The cache entry
        // is dropped in `forget` when the kernel releases the directory inode.
        if offset == 0 {
            match self.page_directory(ino.0, &dir_fh) {
                Ok(entries) => {
                    self.readdir_cache.lock().expect("readdir cache lock").insert(ino.0, entries);
                },
                Err(errno) => {
                    reply.error(errno);
                    return;
                },
            }
        }

        let dotdot_ino = self.state.lock().expect("inode map lock").parents.get(&ino.0).copied().unwrap_or(1);

        // FUSE readdir cookies are exclusive: when the kernel calls back with
        // `offset = N`, it expects entries with cookie > N (the entry AT
        // offset N has already been consumed). Using `<=` here re-emits
        // "." / ".." every time the kernel resumes at offset 2, which is an
        // infinite loop on any non-empty directory.
        let fixed: [(u64, u64, FuseFileType, &str); 2] = [(1, ino.0, FuseFileType::Directory, "."), (2, dotdot_ino, FuseFileType::Directory, "..")];
        for (pos, entry_ino, kind, name) in fixed {
            if offset < pos && reply.add(INodeNo(entry_ino), pos, kind, name) {
                reply.ok();
                return;
            }
        }

        // Serve entries from the per-inode cache populated on the offset == 0
        // callback (cloned out so the lock is not held across the per-entry
        // fix-up LOOKUPs below).
        let entries = self.readdir_cache.lock().expect("readdir cache lock").get(&ino.0).cloned().unwrap_or_default();
        for (idx, (name_bytes, attrs_opt, fh_opt)) in entries.into_iter().enumerate() {
            let entry_offset = (idx as u64) + 3;
            if offset >= entry_offset {
                continue;
            }
            let name_str = String::from_utf8_lossy(&name_bytes);
            if name_str == "." || name_str == ".." {
                continue;
            }

            // null-attr / null-handle fix-up: re-LOOKUP if missing. Use the
            // non-interning variant so a merely-listed entry is not permanently
            // pinned in the inode map (#35) -- the kernel's explicit LOOKUP later
            // does the authoritative, lookup-counted intern.
            let mut entry_attrs = attrs_opt;
            let mut entry_fh = fh_opt;
            if (entry_attrs.is_none() || entry_fh.is_none())
                && let Ok((fh2, attrs2)) = self.block(self.lookup_no_intern(&dir_fh, &name_bytes, ino.0))
            {
                entry_fh = Some(fh2);
                entry_attrs = Some(attrs2);
            }

            let kind = entry_attrs.as_ref().map_or(FuseFileType::RegularFile, |a| to_fuse_type(a.file_type));
            // Resolve an inode number WITHOUT pinning brand-new entries. Per
            // the FUSE ABI a plain readdir entry takes no kernel lookup
            // reference (only readdirplus does), so the kernel never sends a
            // `forget` for entries it has merely listed -- permanently
            // interning every listed handle would grow the inode map without
            // bound (contradicting the `forget` reclamation bound). Reuse an
            // inode only when its handle is already known (interned by a real
            // lookup/create and reclaimed by the lookup/forget lifecycle);
            // otherwise hand the kernel a transient number we do not store. The
            // kernel issues an explicit LOOKUP -- the authoritative,
            // lookup-counted intern -- before it uses the entry.
            let entry_ino = {
                let mut st = self.state.lock().expect("inode map lock");
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
        let Some(fh) = self.fh_for_ino(ino.0) else {
            reply.error(Errno::ENOENT);
            return;
        };

        // NFSv3 READ may return fewer bytes than requested before true EOF
        // (RFC 1813 sec. 3.3.6: a server caps a single READ at rtmax/rtpref).
        // A non-direct-io FUSE mount zero-fills the unread remainder, so a single
        // READ silently corrupts data from any server whose rtmax is below the
        // kernel's request size. Loop until we have `size` bytes, the server
        // signals eof, or returns an empty page. Each chunk still runs through
        // the credential-escalation ladder (the winning cred is cached after the
        // first chunk, so continuations stay single-RPC).
        let mut buf: Vec<u8> = Vec::with_capacity(size as usize);
        loop {
            let want = size.saturating_sub(u32::try_from(buf.len()).unwrap_or(u32::MAX));
            if want == 0 {
                break;
            }
            let pos = offset.saturating_add(buf.len() as u64);
            let chunk = self.block(self.try_with_ladder(ino.0, |c| {
                let fh = fh.clone();
                async move {
                    let args = READ3args { file: fh.to_nfs_fh3(), offset: pos, count: want };
                    c.read(&args).await
                }
            }));
            match chunk {
                Ok(Nfs3Result::Ok(ok)) => {
                    let data = ok.data.as_ref();
                    if data.is_empty() {
                        break;
                    }
                    buf.extend_from_slice(data);
                    if ok.eof {
                        break;
                    }
                },
                // A denial or error before any bytes were read is fatal; after a
                // partial read, return what we have (the next read() resumes).
                Ok(Nfs3Result::Err((nfsstat3::NFS3ERR_ACCES | nfsstat3::NFS3ERR_PERM, _))) if buf.is_empty() => {
                    reply.error(Errno::EACCES);
                    return;
                },
                Ok(Nfs3Result::Err(_)) | Err(_) if buf.is_empty() => {
                    reply.error(Errno::EIO);
                    return;
                },
                _ => break,
            }
        }
        reply.data(&buf);
    }

    /// Write data to a file  --  only when `allow_write` is set.
    ///
    /// Per RFC 1813 S3.3.7 we always request `FILE_SYNC` for data integrity.
    fn write(&self, _req: &Request, ino: INodeNo, _fh: FuseFileHandle, offset: u64, data: &[u8], _write_flags: WriteFlags, _flags: OpenFlags, _lock_owner: Option<LockOwner>, reply: ReplyWrite) {
        if !self.allow_write {
            reply.error(Errno::EACCES);
            return;
        }
        let Some(fh) = self.fh_for_ino(ino.0) else {
            reply.error(Errno::ENOENT);
            return;
        };
        let data_owned = data.to_vec();

        let result = self.block(self.try_with_ladder(ino.0, |c| {
            let fh = fh.clone();
            let data_owned = data_owned.clone();
            async move {
                let count = u32::try_from(data_owned.len()).unwrap_or(u32::MAX);
                let args = WRITE3args { file: fh.to_nfs_fh3(), offset, count, stable: stable_how::FILE_SYNC, data: Opaque::borrowed(&data_owned) };
                c.write(&args).await
            }
        }));

        match result {
            Ok(Nfs3Result::Ok(ok)) => {
                // Clamp the server-reported write count to the bytes we
                // actually sent. NFSv3 WRITE (RFC 1813 sec. 3.3.7) returns the
                // committed count, but an untrusted server reporting a count
                // larger than the request would otherwise mis-report progress
                // to the kernel.
                let sent = u32::try_from(data.len()).unwrap_or(u32::MAX);
                reply.written(ok.count.min(sent));
            },
            Ok(Nfs3Result::Err((nfsstat3::NFS3ERR_ACCES | nfsstat3::NFS3ERR_PERM, _))) => reply.error(Errno::EACCES),
            Ok(Nfs3Result::Err(_)) | Err(_) => reply.error(Errno::EIO),
        }
    }

    /// FSYNC -- forward NFSv3 COMMIT for the open file.
    ///
    /// We always commit the entire file (offset=0, count=0 means "from
    /// here to end-of-file" per RFC 1813 S3.3.21).
    fn fsync(&self, _req: &Request, ino: INodeNo, _fh: FuseFileHandle, _datasync: bool, reply: ReplyEmpty) {
        let Some(fh) = self.fh_for_ino(ino.0) else {
            reply.error(Errno::ENOENT);
            return;
        };

        let result = self.block(self.try_with_ladder(ino.0, |c| {
            let fh = fh.clone();
            async move {
                let args = COMMIT3args { file: fh.to_nfs_fh3(), offset: 0, count: 0 };
                c.commit(&args).await
            }
        }));
        reply_empty(&result, reply);
    }

    /// STATFS -- forward NFSv3 FSSTAT.
    fn statfs(&self, _req: &Request, ino: INodeNo, reply: ReplyStatfs) {
        let fh = self.fh_for_ino(ino.0).unwrap_or_else(|| self.root_fh.clone());

        let result = self.block(self.try_with_ladder(ino.0, |c| {
            let fh = fh.clone();
            async move {
                let args = FSSTAT3args { fsroot: fh.to_nfs_fh3() };
                c.fsstat(&args).await
            }
        }));

        match result {
            Ok(Nfs3Result::Ok(ok)) => {
                // NFSv3 reports byte counts; statfs takes block counts, so
                // we pick a 512-byte block size and divide.
                let bsize: u32 = 512;
                let blocks = ok.tbytes / u64::from(bsize);
                let bfree = ok.fbytes / u64::from(bsize);
                let bavail = ok.abytes / u64::from(bsize);
                reply.statfs(blocks, bfree, bavail, ok.tfiles, ok.ffiles, bsize, 255, bsize);
            },
            Ok(Nfs3Result::Err(_)) | Err(_) => {
                // Many servers reject FSSTAT for non-root callers; reply
                // with zeros so `df` doesn't break the mount.
                reply.statfs(0, 0, 0, 0, 0, 512, 255, 512);
            },
        }
    }
}

/// Convert our `FileType` to the fuser equivalent.
const fn to_fuse_type(ft: FileType) -> FuseFileType {
    match ft {
        FileType::Directory => FuseFileType::Directory,
        FileType::Symlink => FuseFileType::Symlink,
        FileType::Block => FuseFileType::BlockDevice,
        FileType::Character => FuseFileType::CharDevice,
        FileType::Fifo => FuseFileType::NamedPipe,
        FileType::Socket => FuseFileType::Socket,
        FileType::Regular => FuseFileType::RegularFile,
    }
}

/// Build a `SystemTime` from NFS time fields (seconds + nanoseconds since epoch).
fn nfs_time_to_system(seconds: u32, nseconds: u32) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(u64::from(seconds)) + Duration::from_nanos(u64::from(nseconds))
}

/// Convert fuser's `Option<TimeOrNow>` to NFSv3 `set_atime`.
///
/// `None` -> DONT_CHANGE; `Some(Now)` -> SET_TO_SERVER_TIME;
/// `Some(SpecificTime(t))` -> SET_TO_CLIENT_TIME with `t` packed as
/// `nfstime3` (RFC 1813 §3.3.2).
fn time_or_now_to_set_atime(t: Option<TimeOrNow>) -> set_atime {
    match t {
        None => set_atime::DONT_CHANGE,
        Some(TimeOrNow::Now) => set_atime::SET_TO_SERVER_TIME,
        Some(TimeOrNow::SpecificTime(time)) => set_atime::SET_TO_CLIENT_TIME(nfstime3::try_from(time).unwrap_or_default()),
    }
}

/// Convert fuser's `Option<TimeOrNow>` to NFSv3 `set_mtime`. Mirror of
/// `time_or_now_to_set_atime`.
fn time_or_now_to_set_mtime(t: Option<TimeOrNow>) -> set_mtime {
    match t {
        None => set_mtime::DONT_CHANGE,
        Some(TimeOrNow::Now) => set_mtime::SET_TO_SERVER_TIME,
        Some(TimeOrNow::SpecificTime(time)) => set_mtime::SET_TO_CLIENT_TIME(nfstime3::try_from(time).unwrap_or_default()),
    }
}

/// Translate fuser's `AccessFlags` (POSIX `R_OK`/`W_OK`/`X_OK` bitset) to
/// the NFSv3 ACCESS bit mask (RFC 1813 §3.3.4).
///
/// `R_OK` maps to `ACCESS3_READ`; `W_OK` is the union of MODIFY / EXTEND /
/// DELETE because the kernel sees a single "may write here" check whereas
/// NFSv3 splits write operations apart; `X_OK` requests EXECUTE on regular
/// files but LOOKUP semantics for directories, so we set both.
const fn access_flags_to_nfs(mask: AccessFlags) -> u32 {
    use crate::proto::nfs3::types::access;
    let mut bits: u32 = 0;
    if mask.contains(AccessFlags::R_OK) {
        bits |= access::READ;
    }
    if mask.contains(AccessFlags::W_OK) {
        bits |= access::MODIFY | access::EXTEND | access::DELETE;
    }
    if mask.contains(AccessFlags::X_OK) {
        bits |= access::EXECUTE | access::LOOKUP;
    }
    bits
}

/// Build a `sattr3` that only sets the mode field (used by mknod / mkdir /
/// symlink where the kernel asks for a specific mode but no other
/// attributes).
const fn sattr3_for_perms(perms: u32) -> sattr3 {
    sattr3 { mode: Nfs3Option::Some(perms), uid: Nfs3Option::None, gid: Nfs3Option::None, size: Nfs3Option::None, atime: set_atime::DONT_CHANGE, mtime: set_mtime::DONT_CHANGE }
}

/// Convert the optional post-op file handle returned by CREATE / MKNOD /
/// MKDIR / SYMLINK responses (RFC 1813 §3.3.8 etc.) to our `FileHandle`.
fn post_op_fh3_to_handle(opt: Nfs3Option<nfs3_types::nfs3::nfs_fh3>) -> Option<FileHandle> {
    match opt {
        Nfs3Option::Some(fh) => Some(FileHandle::from_nfs_fh3(&fh)),
        Nfs3Option::None => None,
    }
}

/// Convert an optional post-op attribute reply into our `FileAttrs`.
#[allow(clippy::missing_const_for_fn, reason = "FileAttrs::from_fattr3 is not const")]
fn post_op_attr_to_attrs(opt: nfs3_types::nfs3::post_op_attr) -> Option<FileAttrs> {
    match opt {
        Nfs3Option::Some(a) => Some(FileAttrs::from_fattr3(&a)),
        Nfs3Option::None => None,
    }
}

/// Reply to a no-data NFS3 callback (REMOVE / RMDIR / RENAME / COMMIT)
/// based on the server's status code.
fn reply_empty<T, U>(result: &anyhow::Result<Nfs3Result<T, U>>, reply: ReplyEmpty) {
    match result {
        Ok(Nfs3Result::Ok(_)) => reply.ok(),
        Ok(Nfs3Result::Err((nfsstat3::NFS3ERR_ACCES | nfsstat3::NFS3ERR_PERM, _))) => reply.error(Errno::EACCES),
        Ok(Nfs3Result::Err((nfsstat3::NFS3ERR_NOENT, _))) => reply.error(Errno::ENOENT),
        Ok(Nfs3Result::Err((nfsstat3::NFS3ERR_NOTEMPTY, _))) => reply.error(Errno::ENOTEMPTY),
        Ok(Nfs3Result::Err((nfsstat3::NFS3ERR_EXIST, _))) => reply.error(Errno::EEXIST),
        Ok(Nfs3Result::Err((nfsstat3::NFS3ERR_NOTSUPP, _))) => reply.error(Errno::ENOTSUP),
        Ok(Nfs3Result::Err((nfsstat3::NFS3ERR_XDEV, _))) => reply.error(Errno::EXDEV),
        Ok(Nfs3Result::Err((nfsstat3::NFS3ERR_NOSPC, _))) => reply.error(Errno::ENOSPC),
        Ok(Nfs3Result::Err((nfsstat3::NFS3ERR_DQUOT, _))) => reply.error(Errno::EDQUOT),
        Ok(Nfs3Result::Err((nfsstat3::NFS3ERR_ROFS, _))) => reply.error(Errno::EROFS),
        Ok(Nfs3Result::Err(_)) | Err(_) => reply.error(Errno::EIO),
    }
}
