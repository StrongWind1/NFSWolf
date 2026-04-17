//! FUSE filesystem adapter  --  mounts an NFS export as a local filesystem.
//!
//! Implements the minimum `fuser::Filesystem` surface needed for read-only
//! browsing: `lookup`, `getattr`, `readdir`, and `read`. Write operations
//! are stubbed with `ENOSYS` unless `allow_write` is set, in which case
//! `write` is routed to the NFSv3 WRITE procedure.
//!
//! fuser calls are synchronous but the NFS client is async. We use
//! `tokio::runtime::Handle::current().block_on(...)` to bridge the gap  --
//! the FUSE kernel thread is distinct from the Tokio scheduler, so blocking

//! Toolkit API  --  not all items are used in currently-implemented phases.
//! here does not stall the async runtime.

use std::collections::HashMap;
use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use fuser::{Errno, FileAttr, FileHandle as FuseFileHandle, FileType as FuseFileType, Filesystem, Generation, INodeNo, LockOwner, OpenFlags, ReplyAttr, ReplyData, ReplyDirectory, ReplyEntry, ReplyWrite, Request, WriteFlags};
use nfs3_types::nfs3::{GETATTR3args, LOOKUP3args, READ3args, READDIRPLUS3args, cookieverf3, diropargs3, filename3};
use nfs3_types::xdr_codec::Opaque;

use crate::proto::nfs3::client::Nfs3Client;
use crate::proto::nfs3::types::{FileAttrs, FileHandle, FileType};

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
        Self { inodes, handles, parents, next_ino: 2 }
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
}

/// NFS FUSE adapter  --  presents an NFS export as a local FUSE mount.
///
/// Created by `cli::mount::run()` and handed to `fuser::mount2()`.
pub struct NfsFuse {
    /// Pool-backed NFS client.
    nfs3: Arc<Nfs3Client>,
    /// Mutable inode mapping.
    state: Mutex<InodeMapState>,
    /// Root file handle (inode 1).
    root_fh: FileHandle,
    /// When true, WRITE calls are forwarded; otherwise EACCES.
    allow_write: bool,
    /// When true, fake permissions so all files appear world-readable.
    elevate_perms: bool,
}

impl std::fmt::Debug for NfsFuse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NfsFuse").field("root_fh", &self.root_fh.to_hex()).finish_non_exhaustive()
    }
}

impl NfsFuse {
    /// Create a new FUSE adapter rooted at `root_fh`.
    #[must_use]
    pub fn new(nfs3: Arc<Nfs3Client>, root_fh: FileHandle, allow_write: bool, elevate_perms: bool) -> Self {
        let state = Mutex::new(InodeMapState::new(&root_fh));
        Self { nfs3, state, root_fh, allow_write, elevate_perms }
    }

    /// Convert our `FileAttrs` to a fuser `FileAttr`.
    fn make_attr(&self, ino: u64, a: &FileAttrs) -> FileAttr {
        let kind = to_fuse_type(a.file_type);
        let mode16 = u16::try_from(a.mode & u32::from(u16::MAX)).unwrap_or(0);
        let perm = if self.elevate_perms { mode16 | ((mode16 >> 3) & 0o007) } else { mode16 };
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

    /// Run an async block on the current Tokio runtime, blocking this thread.
    ///
    /// fuser calls are synchronous; we bridge to async NFS calls via
    /// `Handle::current().block_on()`. Safe because the FUSE session thread
    /// is not a Tokio task -- blocking it does not starve the scheduler.
    fn block<F, T>(fut: F) -> T
    where
        F: Future<Output = T>,
    {
        tokio::runtime::Handle::current().block_on(fut)
    }
}

// The Mutex protecting the inode state can only be poisoned if a thread panics
// while holding it, which propagates the panic anyway -- expect() is correct here.
#[allow(clippy::expect_used, reason = "Mutex poison propagates existing panics")]
impl Filesystem for NfsFuse {
    /// Look up a directory entry by name and return its attributes.
    fn lookup(&self, _req: &Request, parent: INodeNo, name: &std::ffi::OsStr, reply: ReplyEntry) {
        let parent_fh = {
            let st = self.state.lock().expect("inode map lock");
            st.fh_for(parent.0).cloned()
        };
        let Some(parent_fh) = parent_fh else {
            reply.error(Errno::ENOENT);
            return;
        };

        let name_bytes = name.as_encoded_bytes().to_vec();
        let nfs3 = Arc::clone(&self.nfs3);
        let parent_nfs_fh = parent_fh.to_nfs_fh3();

        let result = Self::block(async move {
            let args = LOOKUP3args { what: diropargs3 { dir: parent_nfs_fh, name: filename3(Opaque::owned(name_bytes)) } };
            nfs3.lookup(&args).await
        });

        match result {
            Ok(nfs3_types::nfs3::Nfs3Result::Ok(ok)) => {
                let child_fh = FileHandle::from_nfs_fh3(&ok.object);
                let attrs = match ok.obj_attributes {
                    nfs3_types::nfs3::Nfs3Option::Some(a) => FileAttrs::from_fattr3(&a),
                    nfs3_types::nfs3::Nfs3Option::None => {
                        let nfs3b = Arc::clone(&self.nfs3);
                        let fh_clone = child_fh.clone();
                        if let Ok(nfs3_types::nfs3::Nfs3Result::Ok(ga)) = Self::block(async move {
                            let args = GETATTR3args { object: fh_clone.to_nfs_fh3() };
                            nfs3b.getattr(&args).await
                        }) {
                            FileAttrs::from_fattr3(&ga.obj_attributes)
                        } else {
                            reply.error(Errno::EIO);
                            return;
                        }
                    },
                };
                let ino = self.state.lock().expect("inode map lock").intern_handle(child_fh, parent.0);
                let attr = self.make_attr(ino, &attrs);
                reply.entry(&ATTR_TTL, &attr, Generation(0));
            },
            Ok(nfs3_types::nfs3::Nfs3Result::Err((nfs3_types::nfs3::nfsstat3::NFS3ERR_NOENT, _))) => reply.error(Errno::ENOENT),
            Ok(nfs3_types::nfs3::Nfs3Result::Err((nfs3_types::nfs3::nfsstat3::NFS3ERR_ACCES, _))) => reply.error(Errno::EACCES),
            Ok(nfs3_types::nfs3::Nfs3Result::Err(_)) | Err(_) => reply.error(Errno::EIO),
        }
    }

    /// Get file attributes for inode `ino`.
    fn getattr(&self, _req: &Request, ino: INodeNo, _fh: Option<FuseFileHandle>, reply: ReplyAttr) {
        let fh = {
            let st = self.state.lock().expect("inode map lock");
            st.fh_for(ino.0).cloned()
        };
        let Some(fh) = fh else {
            reply.error(Errno::ENOENT);
            return;
        };

        let nfs3 = Arc::clone(&self.nfs3);
        let result = Self::block(async move {
            let args = GETATTR3args { object: fh.to_nfs_fh3() };
            nfs3.getattr(&args).await
        });

        match result {
            Ok(nfs3_types::nfs3::Nfs3Result::Ok(ok)) => {
                let a = FileAttrs::from_fattr3(&ok.obj_attributes);
                let attr = self.make_attr(ino.0, &a);
                reply.attr(&ATTR_TTL, &attr);
            },
            Ok(nfs3_types::nfs3::Nfs3Result::Err(_)) | Err(_) => reply.error(Errno::EIO),
        }
    }

    /// Read directory entries for inode `ino`.
    ///
    /// Uses READDIRPLUS so we can cache file handles alongside names.
    fn readdir(&self, _req: &Request, ino: INodeNo, _fh: FuseFileHandle, offset: u64, mut reply: ReplyDirectory) {
        let dir_fh = {
            let st = self.state.lock().expect("inode map lock");
            st.fh_for(ino.0).cloned()
        };
        let Some(dir_fh) = dir_fh else {
            reply.error(Errno::ENOENT);
            return;
        };

        let nfs3 = Arc::clone(&self.nfs3);
        let result = Self::block(async move {
            let args = READDIRPLUS3args { dir: dir_fh.to_nfs_fh3(), cookie: 0, cookieverf: cookieverf3::default(), dircount: 4096, maxcount: 65_536 };
            nfs3.readdirplus(&args).await
        });

        match result {
            Ok(nfs3_types::nfs3::Nfs3Result::Ok(ok)) => {
                let entries: Vec<_> = ok.reply.entries.into_inner();
                let dotdot_ino = self.state.lock().expect("inode map lock").parents.get(&ino.0).copied().unwrap_or(1);

                // Synthetic `.` and `..` at positions 0 and 1.
                let fixed: [(u64, u64, FuseFileType, &str); 2] = [(1, ino.0, FuseFileType::Directory, "."), (2, dotdot_ino, FuseFileType::Directory, "..")];
                for (pos, entry_ino, kind, name) in fixed {
                    if offset <= pos && reply.add(INodeNo(entry_ino), pos, kind, name) {
                        reply.ok();
                        return;
                    }
                }

                for (idx, e) in entries.iter().enumerate() {
                    let entry_offset = (idx as u64) + 3;
                    if offset >= entry_offset {
                        continue;
                    }
                    let name = String::from_utf8_lossy(e.name.as_ref());
                    if name == "." || name == ".." {
                        continue;
                    }
                    let kind = match &e.name_attributes {
                        nfs3_types::nfs3::Nfs3Option::Some(a) => to_fuse_type(FileType::from_ftype3(a.type_)),
                        nfs3_types::nfs3::Nfs3Option::None => FuseFileType::RegularFile,
                    };
                    let entry_fh = match &e.name_handle {
                        nfs3_types::nfs3::Nfs3Option::Some(fh) => Some(FileHandle::from_nfs_fh3(fh)),
                        nfs3_types::nfs3::Nfs3Option::None => None,
                    };
                    let entry_ino = if let Some(fh) = entry_fh {
                        self.state.lock().expect("inode map lock").intern_handle(fh, ino.0)
                    } else {
                        let mut st = self.state.lock().expect("inode map lock");
                        let n = st.next_ino;
                        st.next_ino = st.next_ino.saturating_add(1);
                        n
                    };
                    if reply.add(INodeNo(entry_ino), entry_offset, kind, name.as_ref()) {
                        reply.ok();
                        return;
                    }
                }
                reply.ok();
            },
            Ok(nfs3_types::nfs3::Nfs3Result::Err(_)) | Err(_) => reply.error(Errno::EIO),
        }
    }

    /// Read file data for inode `ino`.
    fn read(&self, _req: &Request, ino: INodeNo, _fh: FuseFileHandle, offset: u64, size: u32, _flags: OpenFlags, _lock_owner: Option<LockOwner>, reply: ReplyData) {
        let fh = {
            let st = self.state.lock().expect("inode map lock");
            st.fh_for(ino.0).cloned()
        };
        let Some(fh) = fh else {
            reply.error(Errno::ENOENT);
            return;
        };

        let nfs3 = Arc::clone(&self.nfs3);
        let result = Self::block(async move {
            let args = READ3args { file: fh.to_nfs_fh3(), offset, count: size };
            nfs3.read(&args).await
        });

        match result {
            Ok(nfs3_types::nfs3::Nfs3Result::Ok(ok)) => reply.data(ok.data.as_ref()),
            Ok(nfs3_types::nfs3::Nfs3Result::Err((nfs3_types::nfs3::nfsstat3::NFS3ERR_ACCES, _))) => reply.error(Errno::EACCES),
            Ok(nfs3_types::nfs3::Nfs3Result::Err(_)) | Err(_) => reply.error(Errno::EIO),
        }
    }

    /// Write data to a file  --  only when `allow_write` is set.
    ///
    /// Returns `ENOSYS` when read-only so the kernel stops retrying writes.
    /// Per RFC 1813 S3.3.7 we always request `FILE_SYNC` for data integrity.
    fn write(&self, _req: &Request, ino: INodeNo, _fh: FuseFileHandle, offset: u64, data: &[u8], _write_flags: WriteFlags, _flags: OpenFlags, _lock_owner: Option<LockOwner>, reply: ReplyWrite) {
        if !self.allow_write {
            reply.error(Errno::ENOSYS);
            return;
        }

        let fh = {
            let st = self.state.lock().expect("inode map lock");
            st.fh_for(ino.0).cloned()
        };
        let Some(fh) = fh else {
            reply.error(Errno::ENOENT);
            return;
        };

        let nfs3 = Arc::clone(&self.nfs3);
        let fh_nfs = fh.to_nfs_fh3();
        let data_owned = data.to_vec();

        let result = tokio::runtime::Handle::current().block_on(async move {
            use nfs3_types::nfs3::{WRITE3args, stable_how};
            use nfs3_types::xdr_codec::Opaque;
            let count = u32::try_from(data_owned.len()).unwrap_or(u32::MAX);
            let args = WRITE3args { file: fh_nfs, offset, count, stable: stable_how::FILE_SYNC, data: Opaque::borrowed(&data_owned) };
            nfs3.write(&args).await
        });

        match result {
            Ok(nfs3_types::nfs3::Nfs3Result::Ok(ok)) => reply.written(ok.count),
            Ok(nfs3_types::nfs3::Nfs3Result::Err((nfs3_types::nfs3::nfsstat3::NFS3ERR_ACCES, _))) => reply.error(Errno::EACCES),
            Ok(nfs3_types::nfs3::Nfs3Result::Err(_)) | Err(_) => reply.error(Errno::EIO),
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
