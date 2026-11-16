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

use std::io::Read;

use onc_rpc_client::RpcTransport;
use onc_xdr::{Pack, Unpack, Void};

use crate::wire::{AttrStatRes, DirOpArgs, DirOpRes, NFS_PROGRAM, NFS_VERSION, Nfs2FileAttr, Nfs2FileHandle, Nfs2SetAttr, Nfs2Stat, ReadArgs, ReadRes, ReaddirArgs, ReaddirEntry, StatFsRes, WriteArgs, createargs, linkargs, proc, readdirres, readlinkres, renameargs, sattrargs, symlinkargs};

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

    /// Consume the client and return the transport.
    pub fn into_transport(self) -> T {
        self.transport
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

    /// `NFSPROC_ROOT` (proc 3) -- obsolete probe.
    ///
    /// RFC 1094 sec. 2.2.3 specifies void -> void, and a compliant server
    /// answers with an empty body or an NFS error status. A non-compliant
    /// server (e.g. VxWorks) that returns a handle instead hands out a root
    /// handle without MOUNT.
    ///
    /// One call is sent and its body is classified by length, because an RPC
    /// reply decoder must consume the whole body: decoding as void rejects a
    /// handle, and decoding as a handle rejects an empty body. An empty body
    /// or a 4-byte status means no handle; 32 bytes is a bare handle; 36 bytes
    /// is a status followed by a handle, which counts only if the status is
    /// zero. An all-zero handle counts as none.
    ///
    /// Returns `Ok(Some(handle))` if the server returns a non-zero handle,
    /// `Ok(None)` if it returns void or an error status, and `Err` if the call
    /// fails or the body has a shape none of those explain.
    pub async fn root(&self) -> Result<Option<Nfs2FileHandle>, Nfs2Error<T::Error>> {
        let RootReply(fh) = self.raw_call(proc::NFSPROC_ROOT, &Void).await?;
        Ok(fh)
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
        let status: Nfs2Stat = self.raw_call(proc::NFSPROC_REMOVE, &args).await?;
        check_status(status)
    }

    /// NFSPROC_RENAME (proc 11)  --  rename a file.
    pub async fn rename(&self, from_dir: &Nfs2FileHandle, from: &str, to_dir: &Nfs2FileHandle, to: &str) -> Result<(), Nfs2Error<T::Error>> {
        let args = renameargs { from: DirOpArgs { dir: *from_dir, name: from.to_owned() }, to: DirOpArgs { dir: *to_dir, name: to.to_owned() } };
        let status: Nfs2Stat = self.raw_call(proc::NFSPROC_RENAME, &args).await?;
        check_status(status)
    }

    /// NFSPROC_LINK (proc 12)  --  create a hard link.
    pub async fn link(&self, fh: &Nfs2FileHandle, dir: &Nfs2FileHandle, name: &str) -> Result<(), Nfs2Error<T::Error>> {
        let args = linkargs { fh: *fh, to: DirOpArgs { dir: *dir, name: name.to_owned() } };
        let status: Nfs2Stat = self.raw_call(proc::NFSPROC_LINK, &args).await?;
        check_status(status)
    }

    /// NFSPROC_SYMLINK (proc 13)  --  create a symbolic link.
    pub async fn symlink(&self, dir: &Nfs2FileHandle, name: &str, target: &str, attrs: &Nfs2SetAttr) -> Result<(), Nfs2Error<T::Error>> {
        let args = symlinkargs { from: DirOpArgs { dir: *dir, name: name.to_owned() }, target: target.to_owned(), attrs: *attrs };
        let status: Nfs2Stat = self.raw_call(proc::NFSPROC_SYMLINK, &args).await?;
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
        let status: Nfs2Stat = self.raw_call(proc::NFSPROC_RMDIR, &args).await?;
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
    ///
    /// Files larger than [`READ_FILE_MAX_BYTES`] fail with
    /// [`Nfs2Error::TooLarge`].
    pub async fn read_file(&self, fh: &Nfs2FileHandle) -> Result<Vec<u8>, Nfs2Error<T::Error>> {
        const CHUNK: u32 = 8_192; // NFSv2 MAXDATA (RFC 1094 S2.2.6)
        // The server is untrusted: it controls both `attrs.size` and whether each
        // chunk is non-empty, so neither can be the sole loop bound. Cap the total
        // so a hostile server reporting a near-4 GiB size cannot drive an
        // unbounded allocation.
        const MAX_BYTES: usize = READ_FILE_MAX_BYTES;
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
                return Err(Nfs2Error::TooLarge { limit: MAX_BYTES });
            }
            offset = offset.saturating_add(chunk_len);
            if offset >= attrs.size {
                break; // reached the file size the server reported
            }
        }
        Ok(data)
    }

    /// Issue one NFSv2 procedure call against program 100003, version 2.
    ///
    /// Failures are traced with the procedure number before propagating so
    /// that transport errors carry enough context to diagnose without a
    /// packet capture.
    async fn raw_call<C, R>(&self, proc: u32, args: &C) -> Result<R, Nfs2Error<T::Error>>
    where
        C: Pack + Send + Sync,
        R: Unpack,
    {
        self.transport
            .call::<C, R>(NFS_PROGRAM, NFS_VERSION, proc, args)
            .await
            .inspect_err(|e| {
                tracing::debug!(procedure = proc, error = %e, "NFSv2 call failed");
            })
            .map_err(Nfs2Error::Rpc)
    }
}

/// Largest file [`Nfs2Client::read_file`] will assemble in memory.
pub const READ_FILE_MAX_BYTES: usize = 256 * 1024 * 1024;

/// The body of an `NFSPROC_ROOT` reply, classified by its length.
///
/// RFC 1094 defines the reply as void, but the procedure is obsolete and
/// servers disagree about what to send, so every shape seen in practice is
/// accepted:
///
/// | Bytes | Read as |
/// |-------|---------|
/// | 0 | void, as the RFC specifies -- no handle |
/// | 4 | an NFS status -- no handle |
/// | 32 | a bare `fhandle` (RFC 1094 sec. 2.3.3) |
/// | 36 | a status followed by an `fhandle`, like `diropres` |
///
/// An all-zero handle, or a handle behind a non-zero status, counts as none.
/// Any other length is a decode error.
#[derive(Debug)]
struct RootReply(Option<Nfs2FileHandle>);

impl Unpack for RootReply {
    fn unpack(input: &mut impl Read) -> onc_xdr::Result<(Self, usize)> {
        const STATUS: usize = 4;
        const LONGEST: usize = STATUS + crate::wire::FHSIZE;
        let mut body = Vec::with_capacity(LONGEST);
        // One byte past the longest shape, so an oversized body is detected
        // here rather than left for the caller's leftover-bytes check.
        let _ = input.take(LONGEST as u64 + 1).read_to_end(&mut body).map_err(onc_xdr::Error::Io)?;
        let handle = |bytes: &[u8]| Some(Nfs2FileHandle::from_bytes(bytes)).filter(|fh| fh.0 != [0u8; crate::wire::FHSIZE]);
        let fh = match body.len() {
            0 | STATUS => None,
            crate::wire::FHSIZE => handle(&body),
            LONGEST => match body.split_at(STATUS) {
                ([0, 0, 0, 0], fh) => handle(fh),
                _ => None,
            },
            other => return Err(onc_xdr::Error::InvalidLength(other)),
        };
        Ok((Self(fh), body.len()))
    }
}

/// An NFSv2 operation failed.
#[derive(Debug)]
#[non_exhaustive]
pub enum Nfs2Error<E> {
    /// The RPC call did not reach a protocol answer.
    Rpc(E),
    /// The server answered with a non-OK status.
    ///
    /// This is a decision by the server, not a failure to reach it, and during
    /// identity probing it is the expected result rather than an error.
    Status(Nfs2Stat),
    /// The data exceeds a size limit this client imposes.
    ///
    /// Raised by the client, not the server: the server was still answering.
    TooLarge {
        /// The limit, in bytes.
        limit: usize,
    },
}

impl<E: std::fmt::Display> std::fmt::Display for Nfs2Error<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Rpc(e) => e.fmt(f),
            Self::Status(s) => write!(f, "NFSv2 error: {s}"),
            Self::TooLarge { limit } => write!(f, "NFSv2: data exceeds the client's {limit}-byte limit"),
        }
    }
}

impl<E: std::error::Error + 'static> std::error::Error for Nfs2Error<E> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Rpc(e) => Some(e),
            Self::Status(_) | Self::TooLarge { .. } => None,
        }
    }
}

impl<E> Nfs2Error<E> {
    /// The protocol status, when the server returned one.
    #[must_use]
    pub const fn status(&self) -> Option<Nfs2Stat> {
        match self {
            Self::Status(s) => Some(*s),
            Self::Rpc(_) | Self::TooLarge { .. } => None,
        }
    }

    /// Whether the server denied access (NFSERR_ACCES or NFSERR_PERM).
    ///
    /// Expected during identity probing -- these must never trip a circuit
    /// breaker.
    #[must_use]
    pub const fn is_permission_denied(&self) -> bool {
        matches!(self, Self::Status(Nfs2Stat::Acces | Nfs2Stat::Perm))
    }

    /// Whether the server returned NFSERR_STALE (70).
    ///
    /// NFSv2 has no BADHANDLE counterpart, so there is no oracle split, but
    /// STALE still means the handle format was accepted and only the inode
    /// is wrong.
    #[must_use]
    pub const fn is_stale(&self) -> bool {
        matches!(self, Self::Status(Nfs2Stat::Stale))
    }

    /// Whether the server returned NFSERR_NOENT (2).
    #[must_use]
    pub const fn is_not_found(&self) -> bool {
        matches!(self, Self::Status(Nfs2Stat::NoEnt))
    }
}

/// Map a non-OK status onto an error.
const fn check_status<E>(status: Nfs2Stat) -> Result<(), Nfs2Error<E>> {
    if matches!(status, Nfs2Stat::Ok) { Ok(()) } else { Err(Nfs2Error::Status(status)) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use onc_rpc_client::transport::io::{AsyncRead, AsyncWrite};
    use onc_rpc_client::{DirectTransport, RpcError};

    /// A stream that answers the one call written to it with `body` as the
    /// accepted, successful result.
    struct OneReply {
        body: Vec<u8>,
        reply: std::io::Cursor<Vec<u8>>,
    }

    impl OneReply {
        fn client(body: &[u8]) -> Nfs2Client<DirectTransport<Self>> {
            Nfs2Client::new(DirectTransport::new(Self { body: body.to_vec(), reply: std::io::Cursor::new(Vec::new()) }))
        }
    }

    impl AsyncWrite for OneReply {
        async fn async_write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            // Bytes 4..8 are the XID, after the record-marking header.
            let xid = buf.get(4..8).expect("request carries an XID");
            let mut msg = Vec::new();
            msg.extend_from_slice(xid);
            for word in [1u32, 0, 0, 0, 0] {
                // REPLY, MSG_ACCEPTED, verifier AUTH_NULL with empty body, SUCCESS
                msg.extend_from_slice(&word.to_be_bytes());
            }
            msg.extend_from_slice(&self.body);
            let header = u32::try_from(msg.len()).expect("small reply") | 0x8000_0000;
            let mut reply = header.to_be_bytes().to_vec();
            reply.extend_from_slice(&msg);
            self.reply = std::io::Cursor::new(reply);
            Ok(buf.len())
        }
    }

    impl AsyncRead for OneReply {
        async fn async_read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            Read::read(&mut self.reply, buf)
        }
    }

    const HANDLE: [u8; 32] = [0x01, 0x00, 0x04, 0x00, 0x29, 0x00, 0x12, 0x00, 0xE6, 0x8D, 0x6A, 0x0C, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

    #[tokio::test]
    async fn root_void_reply_has_no_handle() {
        assert!(OneReply::client(&[]).root().await.expect("void reply").is_none());
    }

    #[tokio::test]
    async fn root_bare_handle_is_returned() {
        let fh = OneReply::client(&HANDLE).root().await.expect("handle reply");
        assert_eq!(fh.map(|h| h.0), Some(HANDLE));
    }

    #[tokio::test]
    async fn root_status_and_handle_is_returned() {
        let mut body = vec![0, 0, 0, 0];
        body.extend_from_slice(&HANDLE);
        let fh = OneReply::client(&body).root().await.expect("diropres-shaped reply");
        assert_eq!(fh.map(|h| h.0), Some(HANDLE));
    }

    #[tokio::test]
    async fn root_error_status_has_no_handle() {
        assert!(OneReply::client(&13u32.to_be_bytes()).root().await.expect("status reply").is_none());
        let mut body = 13u32.to_be_bytes().to_vec();
        body.extend_from_slice(&HANDLE);
        assert!(OneReply::client(&body).root().await.expect("status + handle").is_none());
    }

    #[tokio::test]
    async fn root_zero_handle_counts_as_none() {
        assert!(OneReply::client(&[0u8; 32]).root().await.expect("zero handle").is_none());
    }

    #[tokio::test]
    async fn root_unexplained_length_is_an_error() {
        let err = OneReply::client(&[0u8; 40]).root().await.expect_err("40 bytes matches no known shape");
        assert!(matches!(err, Nfs2Error::Rpc(RpcError::Xdr(_))), "got {err:?}");
    }
}
