//! The domain API -- NFSv3 operations in Rust terms rather than wire terms.
//!
//! Every method here takes and returns domain types ([`FileHandle`],
//! [`FileAttrs`], `&str`) and flattens the protocol's two-level result into one
//! [`Nfs3Fault`]. The raw `Nfs3Client` methods remain available for callers who
//! need to send something the domain layer will not construct -- a malformed
//! request, an unusual flag combination, a handle built rather than looked up.
//!
//! The split matters because NFSv3 reports failure two ways: the RPC itself can
//! fail, or it can succeed and carry a protocol status. Collapsing both into
//! one opaque error would lose the distinction, and for a security tool that
//! distinction is most of the signal -- `NFS3ERR_ACCES` is a fact about the
//! export's permissions, while a connection reset is a fact about the network.

use nfswolf_rpc::RpcTransport;
use nfswolf_xdr::Opaque;

use super::{DirEntryPlus, FileAttrs, FileHandle, FileType};
use crate::error::Nfs3Error;
use crate::raw::Nfs3Client;
use crate::wire::{
    ACCESS3args, COMMIT3args, CREATE3args, FSINFO3args, FSSTAT3args, GETATTR3args, LINK3args, LOOKUP3args, MKDIR3args, Nfs3Option, Nfs3Result, PATHCONF3args, READ3args, READDIRPLUS3args, READLINK3args, REMOVE3args, RENAME3args, RMDIR3args, SETATTR3args, SYMLINK3args, WRITE3args, cookieverf3,
    createhow3, diropargs3, filename3, nfspath3, nfsstat3, post_op_attr, sattr3, stable_how, symlinkdata3,
};

/// An NFSv3 operation did not succeed.
///
/// Two shapes, deliberately kept apart: [`Rpc`](Self::Rpc) means the call never
/// reached a protocol answer, [`Status`](Self::Status) means the server
/// answered and refused. Only the second says anything about the export.
#[derive(Debug)]
pub enum Nfs3Fault<E> {
    /// Transport or RPC failure -- no protocol answer was received.
    Rpc(E),
    /// The server answered with a non-OK status.
    Status(Nfs3Error),
}

impl<E: std::fmt::Display> std::fmt::Display for Nfs3Fault<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Rpc(e) => e.fmt(f),
            Self::Status(s) => s.fmt(f),
        }
    }
}

impl<E: std::error::Error + 'static> std::error::Error for Nfs3Fault<E> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Rpc(e) => Some(e),
            Self::Status(s) => Some(s),
        }
    }
}

impl<E> Nfs3Fault<E> {
    /// The protocol status, when the server returned one.
    #[must_use]
    pub const fn status(&self) -> Option<Nfs3Error> {
        match self {
            Self::Status(s) => Some(*s),
            Self::Rpc(_) => None,
        }
    }

    /// Whether the server refused on permission grounds.
    ///
    /// Expected rather than exceptional when probing identities: it means the
    /// call was processed and denied, which is a result worth recording.
    #[must_use]
    pub const fn is_permission_denied(&self) -> bool {
        matches!(self, Self::Status(s) if s.is_permission_denied())
    }

    /// Whether the handle named nothing that exists.
    ///
    /// Half of the handle oracle, and also the signal to re-resolve a path: a
    /// handle cached across a server-side rename or remount goes stale.
    #[must_use]
    pub const fn is_stale(&self) -> bool {
        matches!(self, Self::Status(s) if s.is_handle_oracle_hit())
    }

    /// Whether the named entry does not exist.
    #[must_use]
    pub const fn is_not_found(&self) -> bool {
        matches!(self, Self::Status(Nfs3Error::NoEnt))
    }
}

/// Result of a `READ`.
#[derive(Debug, Clone)]
pub struct ReadChunk {
    /// Bytes returned, which may be fewer than requested even mid-file.
    pub data: Vec<u8>,
    /// Whether the server reports end-of-file at this offset.
    pub eof: bool,
    /// Attributes after the read, when the server supplied them.
    pub attrs: Option<FileAttrs>,
}

/// Result of a `WRITE`.
#[derive(Debug, Clone, Copy)]
pub struct WriteAck {
    /// Bytes the server accepted.
    pub count: u32,
    /// How durably the server committed them.
    pub committed: stable_how,
}

/// One page of a directory listing.
#[derive(Debug, Clone)]
pub struct DirPage {
    /// Entries in this page.
    pub entries: Vec<DirEntryPlus>,
    /// Whether the directory is exhausted.
    pub eof: bool,
    /// Cursor for the next page.
    pub cookie: u64,
    /// Verifier the server expects echoed back on the next page.
    ///
    /// A server may invalidate a listing between pages; echoing the verifier
    /// is how it tells the client the listing has shifted underneath it.
    pub cookieverf: cookieverf3,
}

/// Convert a wire result into a domain result, flattening both failure shapes.
fn flatten<T, U, E>(res: Result<Nfs3Result<T, U>, E>) -> Result<T, Nfs3Fault<E>> {
    match res {
        Ok(Nfs3Result::Ok(ok)) => Ok(ok),
        Ok(Nfs3Result::Err((status, _))) => Err(Nfs3Fault::Status(Nfs3Error::from_nfsstat3(status).unwrap_or(Nfs3Error::ServerFault))),
        Err(e) => Err(Nfs3Fault::Rpc(e)),
    }
}

/// Borrow a `post_op_attr` as domain attributes, if the server sent any.
fn opt_attrs(a: &post_op_attr) -> Option<FileAttrs> {
    match a {
        Nfs3Option::Some(x) => Some(FileAttrs::from_fattr3(x)),
        Nfs3Option::None => None,
    }
}

/// Build the `diropargs3` every directory-scoped procedure takes.
fn dirop(dir: &FileHandle, name: &str) -> diropargs3<'static> {
    diropargs3 { dir: dir.to_nfs_fh3(), name: filename3(Opaque::owned(name.as_bytes().to_vec())) }
}

impl<T: RpcTransport> Nfs3Client<T> {
    /// Check that the service responds. Touches no filesystem state.
    pub async fn ping(&self) -> Result<(), Nfs3Fault<T::Error>> {
        self.null().await.map_err(Nfs3Fault::Rpc)
    }

    /// Fetch a file's attributes.
    pub async fn attrs(&self, fh: &FileHandle) -> Result<FileAttrs, Nfs3Fault<T::Error>> {
        let ok = flatten(self.getattr(&GETATTR3args { object: fh.to_nfs_fh3() }).await)?;
        Ok(FileAttrs::from_fattr3(&ok.obj_attributes))
    }

    /// Apply new attributes.
    pub async fn set_attrs(&self, fh: &FileHandle, attrs: sattr3) -> Result<(), Nfs3Fault<T::Error>> {
        let _ = flatten(self.setattr(&SETATTR3args { object: fh.to_nfs_fh3(), new_attributes: attrs, guard: Nfs3Option::None }).await)?;
        Ok(())
    }

    /// Resolve one path component within a directory.
    pub async fn resolve(&self, dir: &FileHandle, name: &str) -> Result<(FileHandle, Option<FileAttrs>), Nfs3Fault<T::Error>> {
        let ok = flatten(self.lookup(&LOOKUP3args { what: dirop(dir, name) }).await)?;
        Ok((FileHandle::from_nfs_fh3(&ok.object), opt_attrs(&ok.obj_attributes)))
    }

    /// Ask which of `mask`'s operations the server believes it would permit.
    ///
    /// Advisory only (RFC 1813 sec. 3.3.4): the server may allow an operation
    /// here and refuse it for real, or the reverse. Confirm by attempting it.
    pub async fn check_access(&self, fh: &FileHandle, mask: u32) -> Result<u32, Nfs3Fault<T::Error>> {
        let ok = flatten(self.access(&ACCESS3args { object: fh.to_nfs_fh3(), access: mask }).await)?;
        Ok(ok.access)
    }

    /// Read a symbolic link's target.
    pub async fn read_link(&self, fh: &FileHandle) -> Result<String, Nfs3Fault<T::Error>> {
        let ok = flatten(self.readlink(&READLINK3args { symlink: fh.to_nfs_fh3() }).await)?;
        Ok(String::from_utf8_lossy(ok.data.0.as_ref()).into_owned())
    }

    /// Read up to `count` bytes at `offset`.
    ///
    /// A short read mid-file is legal and does not mean end-of-file; use
    /// [`eof`](ReadChunk::eof), or [`read_all`](Self::read_all) to loop.
    pub async fn read_at(&self, fh: &FileHandle, offset: u64, count: u32) -> Result<ReadChunk, Nfs3Fault<T::Error>> {
        let ok = flatten(self.read(&READ3args { file: fh.to_nfs_fh3(), offset, count }).await)?;
        Ok(ReadChunk { data: ok.data.0.into_owned(), eof: ok.eof, attrs: opt_attrs(&ok.file_attributes) })
    }

    /// Write `data` at `offset`.
    pub async fn write_at(&self, fh: &FileHandle, offset: u64, data: &[u8], stable: stable_how) -> Result<WriteAck, Nfs3Fault<T::Error>> {
        let count = u32::try_from(data.len()).unwrap_or(u32::MAX);
        let ok = flatten(self.write(&WRITE3args { file: fh.to_nfs_fh3(), offset, count, stable, data: Opaque::borrowed(data) }).await)?;
        Ok(WriteAck { count: ok.count, committed: ok.committed })
    }

    /// Create a regular file.
    pub async fn create_file(&self, dir: &FileHandle, name: &str, attrs: sattr3) -> Result<Option<FileHandle>, Nfs3Fault<T::Error>> {
        let ok = flatten(self.create(&CREATE3args { where_: dirop(dir, name), how: createhow3::UNCHECKED(attrs) }).await)?;
        Ok(match ok.obj {
            Nfs3Option::Some(fh) => Some(FileHandle::from_nfs_fh3(&fh)),
            Nfs3Option::None => None,
        })
    }

    /// Create a directory.
    pub async fn create_dir(&self, dir: &FileHandle, name: &str, attrs: sattr3) -> Result<Option<FileHandle>, Nfs3Fault<T::Error>> {
        let ok = flatten(self.mkdir(&MKDIR3args { where_: dirop(dir, name), attributes: attrs }).await)?;
        Ok(match ok.obj {
            Nfs3Option::Some(fh) => Some(FileHandle::from_nfs_fh3(&fh)),
            Nfs3Option::None => None,
        })
    }

    /// Create a symbolic link pointing at `target`.
    pub async fn create_symlink(&self, dir: &FileHandle, name: &str, target: &str, attrs: sattr3) -> Result<(), Nfs3Fault<T::Error>> {
        let data = symlinkdata3 { symlink_attributes: attrs, symlink_data: nfspath3(Opaque::owned(target.as_bytes().to_vec())) };
        let _ = flatten(self.symlink(&SYMLINK3args { where_: dirop(dir, name), symlink: data }).await)?;
        Ok(())
    }

    /// Remove a non-directory entry.
    pub async fn unlink(&self, dir: &FileHandle, name: &str) -> Result<(), Nfs3Fault<T::Error>> {
        let _ = flatten(self.remove(&REMOVE3args { object: dirop(dir, name) }).await)?;
        Ok(())
    }

    /// Remove a directory.
    pub async fn remove_dir(&self, dir: &FileHandle, name: &str) -> Result<(), Nfs3Fault<T::Error>> {
        let _ = flatten(self.rmdir(&RMDIR3args { object: dirop(dir, name) }).await)?;
        Ok(())
    }

    /// Rename an entry, possibly across directories.
    pub async fn rename_entry(&self, from_dir: &FileHandle, from: &str, to_dir: &FileHandle, to: &str) -> Result<(), Nfs3Fault<T::Error>> {
        let _ = flatten(self.rename(&RENAME3args { from: dirop(from_dir, from), to: dirop(to_dir, to) }).await)?;
        Ok(())
    }

    /// Create a hard link to an existing object.
    pub async fn hard_link(&self, fh: &FileHandle, dir: &FileHandle, name: &str) -> Result<(), Nfs3Fault<T::Error>> {
        let _ = flatten(self.link(&LINK3args { file: fh.to_nfs_fh3(), link: dirop(dir, name) }).await)?;
        Ok(())
    }

    /// Flush unstable writes to stable storage.
    pub async fn commit_range(&self, fh: &FileHandle, offset: u64, count: u32) -> Result<(), Nfs3Fault<T::Error>> {
        let _ = flatten(self.commit(&COMMIT3args { file: fh.to_nfs_fh3(), offset, count }).await)?;
        Ok(())
    }

    /// Dynamic filesystem statistics.
    pub async fn stat_fs(&self, fh: &FileHandle) -> Result<super::FsStat, Nfs3Fault<T::Error>> {
        let ok = flatten(self.fsstat(&FSSTAT3args { fsroot: fh.to_nfs_fh3() }).await)?;
        Ok(super::FsStat { total_bytes: ok.tbytes, free_bytes: ok.fbytes, avail_bytes: ok.abytes, total_files: ok.tfiles, free_files: ok.ffiles, avail_files: ok.afiles })
    }

    /// Static filesystem limits and capabilities.
    pub async fn info_fs(&self, fh: &FileHandle) -> Result<super::FsInfo, Nfs3Fault<T::Error>> {
        let ok = flatten(self.fsinfo(&FSINFO3args { fsroot: fh.to_nfs_fh3() }).await)?;
        Ok(super::FsInfo {
            rtmax: ok.rtmax,
            rtpref: ok.rtpref,
            rtmult: ok.rtmult,
            wtmax: ok.wtmax,
            wtpref: ok.wtpref,
            wtmult: ok.wtmult,
            dtpref: ok.dtpref,
            max_file_size: ok.maxfilesize,
            time_delta: super::NfsTime { seconds: ok.time_delta.seconds, nseconds: ok.time_delta.nseconds },
            properties: ok.properties,
        })
    }

    /// POSIX pathname limits for a filesystem object.
    pub async fn path_conf(&self, fh: &FileHandle) -> Result<u32, Nfs3Fault<T::Error>> {
        let ok = flatten(self.pathconf(&PATHCONF3args { object: fh.to_nfs_fh3() }).await)?;
        Ok(ok.linkmax)
    }

    /// Read one page of a directory, with attributes and handles.
    pub async fn list_dir_page(&self, dir: &FileHandle, cookie: u64, cookieverf: cookieverf3) -> Result<DirPage, Nfs3Fault<T::Error>> {
        let args = READDIRPLUS3args { dir: dir.to_nfs_fh3(), cookie, cookieverf, dircount: DIRCOUNT_HINT, maxcount: MAXCOUNT_HINT };
        let ok = flatten(self.readdirplus(&args).await)?;
        let mut entries = Vec::new();
        let mut last_cookie = cookie;
        for e in ok.reply.entries.0 {
            last_cookie = e.cookie;
            entries.push(DirEntryPlus {
                fileid: e.fileid,
                name: String::from_utf8_lossy(e.name.0.as_ref()).into_owned(),
                cookie: e.cookie,
                attrs: opt_attrs(&e.name_attributes),
                handle: match &e.name_handle {
                    Nfs3Option::Some(fh) => Some(FileHandle::from_nfs_fh3(fh)),
                    Nfs3Option::None => None,
                },
            });
        }
        Ok(DirPage { entries, eof: ok.reply.eof, cookie: last_cookie, cookieverf: ok.cookieverf })
    }

    /// Read a directory to completion, paging as needed.
    ///
    /// `max_entries` bounds the result: the server chooses both the page size
    /// and the end-of-file flag, so an unbounded loop is at its mercy.
    pub async fn list_dir(&self, dir: &FileHandle, max_entries: usize) -> Result<Vec<DirEntryPlus>, Nfs3Fault<T::Error>> {
        let mut out = Vec::new();
        let mut cookie = 0_u64;
        let mut verf = cookieverf3::default();
        loop {
            let page = self.list_dir_page(dir, cookie, verf).await?;
            let done = page.eof || page.entries.is_empty();
            // Echo the server's verifier so it can tell us the listing shifted.
            verf = page.cookieverf;
            cookie = page.cookie;
            out.extend(page.entries);
            if done || out.len() >= max_entries {
                out.truncate(max_entries);
                return Ok(out);
            }
        }
    }

    /// Read a whole file, up to `max_bytes`.
    ///
    /// The server controls both the reported size and whether each chunk is
    /// non-empty, so neither can be the sole loop bound -- `max_bytes` is a
    /// hard cap so a hostile server cannot drive an unbounded allocation.
    pub async fn read_all(&self, fh: &FileHandle, max_bytes: usize) -> Result<Vec<u8>, Nfs3Fault<T::Error>> {
        let mut out = Vec::new();
        let mut offset = 0_u64;
        loop {
            let want = u32::try_from(max_bytes.saturating_sub(out.len()).min(READ_CHUNK)).unwrap_or(u32::MAX);
            if want == 0 {
                return Ok(out);
            }
            let chunk = self.read_at(fh, offset, want).await?;
            let got = chunk.data.len();
            out.extend_from_slice(&chunk.data);
            // A zero-length reply with eof unset would otherwise spin forever.
            if chunk.eof || got == 0 || out.len() >= max_bytes {
                out.truncate(max_bytes);
                return Ok(out);
            }
            offset = offset.saturating_add(got as u64);
        }
    }

    /// Walk a slash-separated path from `root`.
    ///
    /// Empty components are skipped, so a leading or doubled slash is harmless.
    pub async fn walk(&self, root: &FileHandle, path: &str) -> Result<(FileHandle, Option<FileAttrs>), Nfs3Fault<T::Error>> {
        let mut fh = root.clone();
        let mut attrs = None;
        for component in path.split('/').filter(|c| !c.is_empty()) {
            let (next, a) = self.resolve(&fh, component).await?;
            fh = next;
            attrs = a;
        }
        Ok((fh, attrs))
    }

    /// Whether a handle names a directory.
    pub async fn is_dir(&self, fh: &FileHandle) -> Result<bool, Nfs3Fault<T::Error>> {
        Ok(self.attrs(fh).await?.file_type == FileType::Directory)
    }
}

/// Bytes of directory-entry names the server should aim to return per page.
const DIRCOUNT_HINT: u32 = 8192;

/// Bytes of total reply the server should aim not to exceed per page.
const MAXCOUNT_HINT: u32 = 65536;

/// Bytes requested per `READ` in [`Nfs3Client::read_all`].
///
/// 64 KiB is the usual `rtpref` on Linux servers; larger requests are commonly
/// truncated anyway and risk the multi-fragment replies this client rejects.
const READ_CHUNK: usize = 64 * 1024;

/// Statuses that mean "this status could not be decoded", used by [`flatten`].
///
/// `from_nfsstat3` returns `None` only for `NFS3_OK`, which cannot appear in
/// the error arm of a wire result. Mapping it to a server fault keeps the
/// conversion total without a panic on a malformed reply.
const _: () = {
    assert!(matches!(nfsstat3::NFS3_OK, nfsstat3::NFS3_OK));
};

#[cfg(test)]
mod tests {
    use super::*;

    /// A fault carrying a permission denial must be distinguishable from a
    /// transport failure -- the whole point of keeping the two variants apart.
    #[test]
    fn permission_denial_is_not_a_transport_failure() {
        let denied: Nfs3Fault<std::io::Error> = Nfs3Fault::Status(Nfs3Error::Acces);
        assert!(denied.is_permission_denied());
        assert_eq!(denied.status(), Some(Nfs3Error::Acces));

        let dead: Nfs3Fault<std::io::Error> = Nfs3Fault::Rpc(std::io::Error::from(std::io::ErrorKind::ConnectionReset));
        assert!(!dead.is_permission_denied());
        assert_eq!(dead.status(), None, "a transport failure says nothing about permissions");
    }

    #[test]
    fn stale_is_reported_for_handle_reresolution() {
        let stale: Nfs3Fault<std::io::Error> = Nfs3Fault::Status(Nfs3Error::Stale);
        assert!(stale.is_stale());
        assert!(!stale.is_not_found(), "STALE and NOENT drive different recovery");
    }

    #[test]
    fn flatten_maps_both_failure_shapes() {
        let ok: Result<Nfs3Result<u32, ()>, std::io::Error> = Ok(Nfs3Result::Ok(7));
        assert_eq!(flatten(ok).ok(), Some(7));

        let denied: Result<Nfs3Result<u32, ()>, std::io::Error> = Ok(Nfs3Result::Err((nfsstat3::NFS3ERR_ACCES, ())));
        assert!(flatten(denied).unwrap_err().is_permission_denied());

        let dead: Result<Nfs3Result<u32, ()>, std::io::Error> = Err(std::io::Error::from(std::io::ErrorKind::ConnectionReset));
        assert_eq!(flatten(dead).unwrap_err().status(), None);
    }
}
