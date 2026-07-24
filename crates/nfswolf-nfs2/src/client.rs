//! NFSv2 client -- [RFC 1094].
//!
//! All 18 procedures. The version is long obsolete but still enabled on plenty
//! of servers, and it is the weakest of the three by a wide margin: no security
//! negotiation at all (RFC 2623 sec. 2.7), no `ACCESS` procedure for the server
//! to advise with, and some servers apply `root_squash` on their v3 path but
//! not their v2 one.
//!
//! Generic over the transport, like every client in this workspace, so it
//! carries no connection policy of its own.

use nfswolf_rpc::RpcTransport;
use nfswolf_xdr::{Pack, Unpack, Void};

use crate::wire::{AttrStatRes, DirOpArgs, DirOpRes, NFS_PROGRAM, NFS_VERSION, Nfs2FileAttr, Nfs2FileHandle, Nfs2SetAttr, NfsStat, ReadArgs, ReadRes, ReaddirArgs, ReaddirEntry, StatFsRes, WriteArgs, createargs, linkargs, proc, readdirres, readlinkres, renameargs, sattrargs, symlinkargs};

/// Client for the `NFSv2` service (program 100003, version 2).
#[derive(Debug)]
pub struct Nfs2Client<T> {
    transport: T,
}

impl<T: RpcTransport> Nfs2Client<T> {
    /// Wrap a transport.
    pub const fn new(transport: T) -> Self {
        Self { transport }
    }

    /// Borrow the underlying transport.
    pub const fn transport(&self) -> &T {
        &self.transport
    }

    /// NFSPROC_NULL (proc 0)  --  no-op connectivity check.
    pub async fn null(&self) -> Result<(), Nfs2Error<T::Error>> {
        self.raw_call::<Void, Void>(proc::NFSPROC_NULL, &Void).await.map(|_| ())
    }

    /// NFSPROC_GETATTR (proc 1)  --  get file attributes.
    /// Response is `attrstat` (RFC 1094 S2.3.9): status + fattr, no file handle.
    pub async fn getattr(&self, fh: &Nfs2FileHandle) -> Result<Nfs2FileAttr, Nfs2Error<T::Error>> {
        let res: AttrStatRes = self.raw_call(proc::NFSPROC_GETATTR, fh).await?;
        check_status(res.status)?;
        Ok(res.attrs)
    }

    /// NFSPROC_SETATTR (proc 2)  --  set file attributes.
    /// Response is `attrstat` (RFC 1094 S2.3.9): status + fattr, no file handle.
    pub async fn setattr(&self, fh: &Nfs2FileHandle, attrs: &Nfs2SetAttr) -> Result<Nfs2FileAttr, Nfs2Error<T::Error>> {
        // Wire format: fhandle || sattr
        let combined = sattrargs { fh: *fh, attrs: *attrs };
        let res: AttrStatRes = self.raw_call(proc::NFSPROC_SETATTR, &combined).await?;
        check_status(res.status)?;
        Ok(res.attrs)
    }

    /// `NFSPROC_ROOT` (proc 3) -- obsolete, retained for completeness.
    ///
    /// RFC 1094 sec. 2.2.3 marks it obsolete: the root handle comes from the
    /// MOUNT protocol instead. Servers answer `NFSERR_STALE` or drop it. It
    /// exists here so the crate covers all 18 procedure numbers and so a caller
    /// probing a server's behaviour can send it deliberately.
    pub async fn root(&self) -> Result<(), Nfs2Error<T::Error>> {
        self.raw_call::<Void, Void>(proc::NFSPROC_ROOT, &Void).await.map(|_| ())
    }

    /// `NFSPROC_WRITECACHE` (proc 7) -- reserved and unused.
    ///
    /// RFC 1094 sec. 2.2.7 defines the number and no semantics; no server
    /// implements it. Present for the same reason as [`root`](Self::root).
    pub async fn writecache(&self) -> Result<(), Nfs2Error<T::Error>> {
        self.raw_call::<Void, Void>(proc::NFSPROC_WRITECACHE, &Void).await.map(|_| ())
    }

    /// NFSPROC_LOOKUP (proc 4)  --  look up filename in directory.
    pub async fn lookup(&self, dir: &Nfs2FileHandle, name: &str) -> Result<(Nfs2FileHandle, Nfs2FileAttr), Nfs2Error<T::Error>> {
        let args = DirOpArgs { dir: *dir, name: name.to_owned() };
        let res: DirOpRes = self.raw_call(proc::NFSPROC_LOOKUP, &args).await?;
        check_status(res.status)?;
        Ok((res.handle, res.attrs))
    }

    /// NFSPROC_READLINK (proc 5)  --  read symbolic link target.
    pub async fn readlink(&self, fh: &Nfs2FileHandle) -> Result<String, Nfs2Error<T::Error>> {
        let res: readlinkres = self.raw_call(proc::NFSPROC_READLINK, fh).await?;
        check_status(res.status)?;
        Ok(res.data)
    }

    /// NFSPROC_READ (proc 6)  --  read data from file.
    pub async fn read(&self, fh: &Nfs2FileHandle, offset: u32, count: u32) -> Result<(Nfs2FileAttr, Vec<u8>), Nfs2Error<T::Error>> {
        let args = ReadArgs { file: *fh, offset, count, totalcount: 0 };
        let res: ReadRes = self.raw_call(proc::NFSPROC_READ, &args).await?;
        check_status(res.status)?;
        Ok((res.attrs, res.data))
    }

    /// NFSPROC_WRITE (proc 8)  --  write data to file.
    /// Response is `attrstat` (RFC 1094 S2.3.9): status + fattr, no file handle.
    pub async fn write(&self, fh: &Nfs2FileHandle, offset: u32, data: Vec<u8>) -> Result<Nfs2FileAttr, Nfs2Error<T::Error>> {
        let args = WriteArgs { file: *fh, beginoffset: 0, offset, totalcount: 0, data };
        let res: AttrStatRes = self.raw_call(proc::NFSPROC_WRITE, &args).await?;
        check_status(res.status)?;
        Ok(res.attrs)
    }

    /// NFSPROC_CREATE (proc 9)  --  create a file.
    pub async fn create(&self, dir: &Nfs2FileHandle, name: &str, attrs: &Nfs2SetAttr) -> Result<(Nfs2FileHandle, Nfs2FileAttr), Nfs2Error<T::Error>> {
        let combined = createargs { args: DirOpArgs { dir: *dir, name: name.to_owned() }, attrs: *attrs };
        let res: DirOpRes = self.raw_call(proc::NFSPROC_CREATE, &combined).await?;
        check_status(res.status)?;
        Ok((res.handle, res.attrs))
    }

    /// NFSPROC_REMOVE (proc 10)  --  remove a file.
    pub async fn remove(&self, dir: &Nfs2FileHandle, name: &str) -> Result<(), Nfs2Error<T::Error>> {
        let args = DirOpArgs { dir: *dir, name: name.to_owned() };
        let status: NfsStat = self.raw_call(proc::NFSPROC_REMOVE, &args).await?;
        check_status(status)
    }

    /// NFSPROC_RENAME (proc 11)  --  rename a file.
    pub async fn rename(&self, from_dir: &Nfs2FileHandle, from: &str, to_dir: &Nfs2FileHandle, to: &str) -> Result<(), Nfs2Error<T::Error>> {
        let args = renameargs { from: DirOpArgs { dir: *from_dir, name: from.to_owned() }, to: DirOpArgs { dir: *to_dir, name: to.to_owned() } };
        let status: NfsStat = self.raw_call(proc::NFSPROC_RENAME, &args).await?;
        check_status(status)
    }

    /// NFSPROC_LINK (proc 12)  --  create a hard link.
    pub async fn link(&self, fh: &Nfs2FileHandle, dir: &Nfs2FileHandle, name: &str) -> Result<(), Nfs2Error<T::Error>> {
        let args = linkargs { fh: *fh, to: DirOpArgs { dir: *dir, name: name.to_owned() } };
        let status: NfsStat = self.raw_call(proc::NFSPROC_LINK, &args).await?;
        check_status(status)
    }

    /// NFSPROC_SYMLINK (proc 13)  --  create a symbolic link.
    pub async fn symlink(&self, dir: &Nfs2FileHandle, name: &str, target: &str, attrs: &Nfs2SetAttr) -> Result<(), Nfs2Error<T::Error>> {
        let args = symlinkargs { from: DirOpArgs { dir: *dir, name: name.to_owned() }, target: target.to_owned(), attrs: *attrs };
        let status: NfsStat = self.raw_call(proc::NFSPROC_SYMLINK, &args).await?;
        check_status(status)
    }

    /// NFSPROC_MKDIR (proc 14)  --  create a directory.
    pub async fn mkdir(&self, dir: &Nfs2FileHandle, name: &str, attrs: &Nfs2SetAttr) -> Result<(Nfs2FileHandle, Nfs2FileAttr), Nfs2Error<T::Error>> {
        let combined = createargs { args: DirOpArgs { dir: *dir, name: name.to_owned() }, attrs: *attrs };
        let res: DirOpRes = self.raw_call(proc::NFSPROC_MKDIR, &combined).await?;
        check_status(res.status)?;
        Ok((res.handle, res.attrs))
    }

    /// NFSPROC_RMDIR (proc 15)  --  remove a directory.
    pub async fn rmdir(&self, dir: &Nfs2FileHandle, name: &str) -> Result<(), Nfs2Error<T::Error>> {
        let args = DirOpArgs { dir: *dir, name: name.to_owned() };
        let status: NfsStat = self.raw_call(proc::NFSPROC_RMDIR, &args).await?;
        check_status(status)
    }

    /// NFSPROC_READDIR (proc 16)  --  list directory entries.
    pub async fn readdir(&self, dir: &Nfs2FileHandle, cookie: u32, count: u32) -> Result<Vec<ReaddirEntry>, Nfs2Error<T::Error>> {
        let args = ReaddirArgs { dir: *dir, cookie, count };
        let res: readdirres = self.raw_call(proc::NFSPROC_READDIR, &args).await?;
        check_status(res.status)?;
        Ok(res.entries)
    }

    /// NFSPROC_STATFS (proc 17)  --  get filesystem statistics.
    pub async fn statfs(&self, fh: &Nfs2FileHandle) -> Result<StatFsRes, Nfs2Error<T::Error>> {
        let res: StatFsRes = self.raw_call(proc::NFSPROC_STATFS, fh).await?;
        check_status(res.status)?;
        Ok(res)
    }

    /// Walk a slash-separated path from `root` using repeated LOOKUP calls.
    pub async fn lookup_path(&self, root: &Nfs2FileHandle, path: &str) -> Result<(Nfs2FileHandle, Nfs2FileAttr), Nfs2Error<T::Error>> {
        let mut fh = *root;
        let mut attrs = self.getattr(&fh).await?;
        for component in path.split('/').filter(|c| !c.is_empty()) {
            let (next_fh, next_attrs) = self.lookup(&fh, component).await?;
            fh = next_fh;
            attrs = next_attrs;
        }
        Ok((fh, attrs))
    }

    /// Read an entire file in chunks bounded by the NFSv2 MAXDATA limit.
    ///
    /// RFC 1094 fixes MAXDATA = 8192 as the maximum data in a READ reply, so a
    /// full-size reply is only 8 KB and must NOT be mistaken for end-of-file.
    /// READ returns the file's current attributes (RFC 1094 S2.2.6 readres), so
    /// the loop runs until `offset` reaches the reported size or the server
    /// returns an empty chunk -- a short read mid-file is legal and is not
    /// treated as EOF.
    pub async fn read_file(&self, fh: &Nfs2FileHandle) -> Result<Vec<u8>, Nfs2Error<T::Error>> {
        const CHUNK: u32 = 8_192; // NFSv2 MAXDATA (RFC 1094 S2.2.6)
        // The server is untrusted: it controls both `attrs.size` and whether each
        // chunk is non-empty, so neither can be the sole loop bound. Cap the total
        // so a hostile server reporting a near-4 GiB size cannot drive an
        // unbounded allocation (mirrors the v3 `read_all` READ_ALL_MAX_BYTES guard
        // in src/shell.rs).
        const MAX_BYTES: usize = 256 * 1024 * 1024; // 256 MiB hard cap
        let mut data = Vec::new();
        let mut offset: u32 = 0;
        loop {
            let (attrs, chunk) = self.read(fh, offset, CHUNK).await?;
            if chunk.is_empty() {
                break; // server signalled no more data
            }
            let chunk_len = u32::try_from(chunk.len()).unwrap_or(CHUNK);
            data.extend_from_slice(&chunk);
            if data.len() > MAX_BYTES {
                return Err(Nfs2Error::Status(NfsStat::Io));
            }
            offset = offset.saturating_add(chunk_len);
            if offset >= attrs.size {
                break; // reached the file size the server reported
            }
        }
        Ok(data)
    }

    /// Issue one NFSv2 procedure call against program 100003, version 2.
    async fn raw_call<C, R>(&self, proc: u32, args: &C) -> Result<R, Nfs2Error<T::Error>>
    where
        C: Pack + Send + Sync,
        R: Unpack,
    {
        self.transport.call::<C, R>(NFS_PROGRAM, NFS_VERSION, proc, args).await.map_err(Nfs2Error::Rpc)
    }
}

/// An NFSv2 operation failed.
#[derive(Debug)]
pub enum Nfs2Error<E> {
    /// The RPC call did not reach a protocol answer.
    Rpc(E),
    /// The server answered with a non-OK status.
    ///
    /// This is a decision by the server, not a failure to reach it, and during
    /// identity probing it is the expected result rather than an error.
    Status(NfsStat),
}

impl<E: std::fmt::Display> std::fmt::Display for Nfs2Error<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Rpc(e) => e.fmt(f),
            Self::Status(s) => write!(f, "NFSv2 error: {s:?}"),
        }
    }
}

impl<E: std::error::Error + 'static> std::error::Error for Nfs2Error<E> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Rpc(e) => Some(e),
            Self::Status(_) => None,
        }
    }
}

impl<E> Nfs2Error<E> {
    /// The protocol status, when the server returned one.
    #[must_use]
    pub const fn status(&self) -> Option<NfsStat> {
        match self {
            Self::Status(s) => Some(*s),
            Self::Rpc(_) => None,
        }
    }
}

/// Map a non-OK status onto an error.
const fn check_status<E>(status: NfsStat) -> Result<(), Nfs2Error<E>> {
    if matches!(status, NfsStat::Ok) { Ok(()) } else { Err(Nfs2Error::Status(status)) }
}
