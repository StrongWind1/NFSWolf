//! NFSv2 client  --  calls via nfs3-rs's generic RpcClient.
//!
//! Uses `NfsConnection::call_raw(NFS_PROGRAM, 2, proc, args)` for all operations.
//! Implements the 18 NFSv2 procedures (RFC 1094).
//! Preferred over v3 when available  --  bypasses auth negotiation entirely.
//! Fixed 32-byte handles, 32-bit file sizes, no ACCESS procedure.

// Toolkit API  --  not all items are used in currently-implemented phases.
// XDR padding uses slice [..pad] where pad is always 0-3 (enforced by modulo 4).
use std::sync::Arc;

use anyhow::Context as _;
use nfs3_types::xdr_codec::Void;

use crate::proto::auth::Credential;
use crate::proto::circuit::CircuitBreaker;
use crate::proto::conn::ReconnectStrategy;
use crate::proto::nfs2::types::{AttrStatRes, DirOpArgs, DirOpRes, NFS_PROGRAM, NFS_VERSION, Nfs2FileAttr, Nfs2FileHandle, Nfs2SetAttr, NfsStat, ReadArgs, ReadRes, ReaddirArgs, ReaddirEntry, StatFsRes, WriteArgs, proc};
use crate::proto::pool::{ConnectionPool, PoolKey};
use crate::util::stealth::StealthConfig;

/// NFSv2 client  --  uses the connection pool for raw RPC calls.
///
/// Since NFSv2 has no auth negotiation (RFC 2623 S2.7), it is the preferred
/// downgrade path when the server supports both v2 and v3.
pub struct Nfs2Client {
    pool: Arc<ConnectionPool>,
    pool_key: PoolKey,
    circuit: Arc<CircuitBreaker>,
    stealth: StealthConfig,
    credential: Credential,
}

impl std::fmt::Debug for Nfs2Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Nfs2Client").field("pool_key", &self.pool_key).finish_non_exhaustive()
    }
}

impl Nfs2Client {
    /// Create a new NFSv2 client using the given connection pool.
    #[must_use]
    pub const fn new(pool: Arc<ConnectionPool>, pool_key: PoolKey, circuit: Arc<CircuitBreaker>, stealth: StealthConfig, credential: Credential) -> Self {
        Self { pool, pool_key, circuit, stealth, credential }
    }

    /// NFSPROC_NULL (proc 0)  --  no-op connectivity check.
    pub async fn null(&self) -> anyhow::Result<()> {
        self.raw_call::<Void, Void>(proc::NFSPROC_NULL, &Void).await.map(|_| ())
    }

    /// NFSPROC_GETATTR (proc 1)  --  get file attributes.
    /// Response is `attrstat` (RFC 1094 S2.3.9): status + fattr, no file handle.
    pub async fn getattr(&self, fh: &Nfs2FileHandle) -> anyhow::Result<Nfs2FileAttr> {
        let res: AttrStatRes = self.raw_call(proc::NFSPROC_GETATTR, fh).await?;
        check_status(res.status)?;
        Ok(res.attrs)
    }

    /// NFSPROC_SETATTR (proc 2)  --  set file attributes.
    /// Response is `attrstat` (RFC 1094 S2.3.9): status + fattr, no file handle.
    pub async fn setattr(&self, fh: &Nfs2FileHandle, attrs: &Nfs2SetAttr) -> anyhow::Result<Nfs2FileAttr> {
        // Wire format: fhandle || sattr
        let combined = FhAndSattr { fh: fh.clone(), attrs: attrs.clone() };
        let res: AttrStatRes = self.raw_call(proc::NFSPROC_SETATTR, &combined).await?;
        check_status(res.status)?;
        Ok(res.attrs)
    }

    /// NFSPROC_LOOKUP (proc 4)  --  look up filename in directory.
    pub async fn lookup(&self, dir: &Nfs2FileHandle, name: &str) -> anyhow::Result<(Nfs2FileHandle, Nfs2FileAttr)> {
        let args = DirOpArgs { dir: dir.clone(), name: name.to_owned() };
        let res: DirOpRes = self.raw_call(proc::NFSPROC_LOOKUP, &args).await?;
        check_status(res.status)?;
        Ok((res.handle, res.attrs))
    }

    /// NFSPROC_READLINK (proc 5)  --  read symbolic link target.
    pub async fn readlink(&self, fh: &Nfs2FileHandle) -> anyhow::Result<String> {
        let res: ReadlinkRes = self.raw_call(proc::NFSPROC_READLINK, fh).await?;
        check_status(res.status)?;
        Ok(res.data)
    }

    /// NFSPROC_READ (proc 6)  --  read data from file.
    pub async fn read(&self, fh: &Nfs2FileHandle, offset: u32, count: u32) -> anyhow::Result<(Nfs2FileAttr, Vec<u8>)> {
        let args = ReadArgs { file: fh.clone(), offset, count, totalcount: 0 };
        let res: ReadRes = self.raw_call(proc::NFSPROC_READ, &args).await?;
        check_status(res.status)?;
        Ok((res.attrs, res.data))
    }

    /// NFSPROC_WRITE (proc 8)  --  write data to file.
    /// Response is `attrstat` (RFC 1094 S2.3.9): status + fattr, no file handle.
    pub async fn write(&self, fh: &Nfs2FileHandle, offset: u32, data: Vec<u8>) -> anyhow::Result<Nfs2FileAttr> {
        let args = WriteArgs { file: fh.clone(), beginoffset: 0, offset, totalcount: 0, data };
        let res: AttrStatRes = self.raw_call(proc::NFSPROC_WRITE, &args).await?;
        check_status(res.status)?;
        Ok(res.attrs)
    }

    /// NFSPROC_CREATE (proc 9)  --  create a file.
    pub async fn create(&self, dir: &Nfs2FileHandle, name: &str, attrs: &Nfs2SetAttr) -> anyhow::Result<(Nfs2FileHandle, Nfs2FileAttr)> {
        let combined = DirOpAndSattr { args: DirOpArgs { dir: dir.clone(), name: name.to_owned() }, attrs: attrs.clone() };
        let res: DirOpRes = self.raw_call(proc::NFSPROC_CREATE, &combined).await?;
        check_status(res.status)?;
        Ok((res.handle, res.attrs))
    }

    /// NFSPROC_REMOVE (proc 10)  --  remove a file.
    pub async fn remove(&self, dir: &Nfs2FileHandle, name: &str) -> anyhow::Result<()> {
        let args = DirOpArgs { dir: dir.clone(), name: name.to_owned() };
        let status: NfsStat = self.raw_call(proc::NFSPROC_REMOVE, &args).await?;
        check_status(status)
    }

    /// NFSPROC_RENAME (proc 11)  --  rename a file.
    pub async fn rename(&self, from_dir: &Nfs2FileHandle, from: &str, to_dir: &Nfs2FileHandle, to: &str) -> anyhow::Result<()> {
        let args = TwoDirOpArgs { from: DirOpArgs { dir: from_dir.clone(), name: from.to_owned() }, to: DirOpArgs { dir: to_dir.clone(), name: to.to_owned() } };
        let status: NfsStat = self.raw_call(proc::NFSPROC_RENAME, &args).await?;
        check_status(status)
    }

    /// NFSPROC_LINK (proc 12)  --  create a hard link.
    pub async fn link(&self, fh: &Nfs2FileHandle, dir: &Nfs2FileHandle, name: &str) -> anyhow::Result<()> {
        let args = LinkArgs { fh: fh.clone(), to: DirOpArgs { dir: dir.clone(), name: name.to_owned() } };
        let status: NfsStat = self.raw_call(proc::NFSPROC_LINK, &args).await?;
        check_status(status)
    }

    /// NFSPROC_SYMLINK (proc 13)  --  create a symbolic link.
    pub async fn symlink(&self, dir: &Nfs2FileHandle, name: &str, target: &str, attrs: &Nfs2SetAttr) -> anyhow::Result<()> {
        let args = SymlinkArgs { from: DirOpArgs { dir: dir.clone(), name: name.to_owned() }, target: target.to_owned(), attrs: attrs.clone() };
        let status: NfsStat = self.raw_call(proc::NFSPROC_SYMLINK, &args).await?;
        check_status(status)
    }

    /// NFSPROC_MKDIR (proc 14)  --  create a directory.
    pub async fn mkdir(&self, dir: &Nfs2FileHandle, name: &str, attrs: &Nfs2SetAttr) -> anyhow::Result<(Nfs2FileHandle, Nfs2FileAttr)> {
        let combined = DirOpAndSattr { args: DirOpArgs { dir: dir.clone(), name: name.to_owned() }, attrs: attrs.clone() };
        let res: DirOpRes = self.raw_call(proc::NFSPROC_MKDIR, &combined).await?;
        check_status(res.status)?;
        Ok((res.handle, res.attrs))
    }

    /// NFSPROC_RMDIR (proc 15)  --  remove a directory.
    pub async fn rmdir(&self, dir: &Nfs2FileHandle, name: &str) -> anyhow::Result<()> {
        let args = DirOpArgs { dir: dir.clone(), name: name.to_owned() };
        let status: NfsStat = self.raw_call(proc::NFSPROC_RMDIR, &args).await?;
        check_status(status)
    }

    /// NFSPROC_READDIR (proc 16)  --  list directory entries.
    pub async fn readdir(&self, dir: &Nfs2FileHandle, cookie: u32, count: u32) -> anyhow::Result<Vec<ReaddirEntry>> {
        let args = ReaddirArgs { dir: dir.clone(), cookie, count };
        let res: ReaddirRes = self.raw_call(proc::NFSPROC_READDIR, &args).await?;
        check_status(res.status)?;
        Ok(res.entries)
    }

    /// NFSPROC_STATFS (proc 17)  --  get filesystem statistics.
    pub async fn statfs(&self, fh: &Nfs2FileHandle) -> anyhow::Result<StatFsRes> {
        let res: StatFsRes = self.raw_call(proc::NFSPROC_STATFS, fh).await?;
        check_status(res.status)?;
        Ok(res)
    }

    /// Walk a slash-separated path from `root` using repeated LOOKUP calls.
    pub async fn lookup_path(&self, root: &Nfs2FileHandle, path: &str) -> anyhow::Result<(Nfs2FileHandle, Nfs2FileAttr)> {
        let mut fh = root.clone();
        let mut attrs = self.getattr(&fh).await?;
        for component in path.split('/').filter(|c| !c.is_empty()) {
            let (next_fh, next_attrs) = self.lookup(&fh, component).await.with_context(|| format!("lookup {component}"))?;
            fh = next_fh;
            attrs = next_attrs;
        }
        Ok((fh, attrs))
    }

    /// Read an entire file in chunks up to the 2 GB v2 limit.
    pub async fn read_file(&self, fh: &Nfs2FileHandle) -> anyhow::Result<Vec<u8>> {
        const CHUNK: u32 = 65_536;
        let mut data = Vec::new();
        let mut offset: u32 = 0;
        loop {
            let (_, chunk) = self.read(fh, offset, CHUNK).await?;
            if chunk.is_empty() {
                break;
            }
            let chunk_len = u32::try_from(chunk.len()).unwrap_or(CHUNK);
            data.extend_from_slice(&chunk);
            offset = offset.saturating_add(chunk_len);
            if (chunk_len as usize) < CHUNK as usize {
                break; // short read = EOF
            }
        }
        Ok(data)
    }

    /// Issue a raw RPC call via the pool's connection.
    async fn raw_call<C, R>(&self, proc: u32, args: &C) -> anyhow::Result<R>
    where
        C: Pack + Send + Sync,
        R: Unpack,
    {
        let addr = self.pool_key.host;
        self.circuit.check_or_wait(addr)?;
        let mut conn = self.pool.checkout(self.pool_key.clone(), self.credential.clone(), ReconnectStrategy::Persistent).await.context("pool checkout")?;
        self.stealth.wait().await;
        conn.call_raw::<C, R>(NFS_PROGRAM, NFS_VERSION, proc, args).await.with_context(|| format!("NFSv2 proc {proc}"))
    }
}

// --- Wire helpers for compound argument types ---

use nfs3_types::xdr_codec::{Pack, Unpack};
use std::io::{Read, Write};

/// Wire-encodes fhandle followed by sattr (for SETATTR).
struct FhAndSattr {
    fh: Nfs2FileHandle,
    attrs: Nfs2SetAttr,
}

impl Pack for FhAndSattr {
    fn packed_size(&self) -> usize {
        self.fh.packed_size() + self.attrs.packed_size()
    }
    fn pack(&self, out: &mut impl Write) -> nfs3_types::xdr_codec::Result<usize> {
        Ok(self.fh.pack(out)? + self.attrs.pack(out)?)
    }
}

/// Wire-encodes diropargs followed by sattr (for CREATE/MKDIR).
struct DirOpAndSattr {
    args: DirOpArgs,
    attrs: Nfs2SetAttr,
}

impl Pack for DirOpAndSattr {
    fn packed_size(&self) -> usize {
        self.args.packed_size() + self.attrs.packed_size()
    }
    fn pack(&self, out: &mut impl Write) -> nfs3_types::xdr_codec::Result<usize> {
        Ok(self.args.pack(out)? + self.attrs.pack(out)?)
    }
}

/// Wire-encodes two diropargs (for RENAME).
struct TwoDirOpArgs {
    from: DirOpArgs,
    to: DirOpArgs,
}

impl Pack for TwoDirOpArgs {
    fn packed_size(&self) -> usize {
        self.from.packed_size() + self.to.packed_size()
    }
    fn pack(&self, out: &mut impl Write) -> nfs3_types::xdr_codec::Result<usize> {
        Ok(self.from.pack(out)? + self.to.pack(out)?)
    }
}

/// Wire-encodes fhandle followed by diropargs (for LINK).
struct LinkArgs {
    fh: Nfs2FileHandle,
    to: DirOpArgs,
}

impl Pack for LinkArgs {
    fn packed_size(&self) -> usize {
        self.fh.packed_size() + self.to.packed_size()
    }
    fn pack(&self, out: &mut impl Write) -> nfs3_types::xdr_codec::Result<usize> {
        Ok(self.fh.pack(out)? + self.to.pack(out)?)
    }
}

/// Wire-encodes diropargs + target string + sattr (for SYMLINK).
struct SymlinkArgs {
    from: DirOpArgs,
    target: String,
    attrs: Nfs2SetAttr,
}

impl Pack for SymlinkArgs {
    fn packed_size(&self) -> usize {
        self.from.packed_size() + string_packed_size(&self.target) + self.attrs.packed_size()
    }
    fn pack(&self, out: &mut impl Write) -> nfs3_types::xdr_codec::Result<usize> {
        Ok(self.from.pack(out)? + pack_string(&self.target, out)? + self.attrs.pack(out)?)
    }
}

/// READLINK result: status + path string.
struct ReadlinkRes {
    status: NfsStat,
    data: String,
}

impl Unpack for ReadlinkRes {
    /// RFC 1094  --  readlinkres is an XDR union: on error status, only the
    /// status discriminant is present (no path string follows).
    fn unpack(input: &mut impl Read) -> nfs3_types::xdr_codec::Result<(Self, usize)> {
        let (status, n0) = NfsStat::unpack(input)?;
        if status != NfsStat::Ok {
            return Ok((Self { status, data: String::new() }, n0));
        }
        let (data, n1) = unpack_string(input)?;
        Ok((Self { status, data }, n0 + n1))
    }
}

/// READDIR result: status + entry list + eof flag.
struct ReaddirRes {
    status: NfsStat,
    entries: Vec<ReaddirEntry>,
}

impl Unpack for ReaddirRes {
    /// RFC 1094  --  readdirres is an XDR union: on error status, only the
    /// status discriminant is present (no entry list or EOF flag follows).
    fn unpack(input: &mut impl Read) -> nfs3_types::xdr_codec::Result<(Self, usize)> {
        let (status, mut n) = NfsStat::unpack(input)?;
        if status != NfsStat::Ok {
            return Ok((Self { status, entries: Vec::new() }, n));
        }
        let mut entries = Vec::new();
        loop {
            let (has_entry, dn) = u32::unpack(input)?;
            n += dn;
            if has_entry == 0 {
                break;
            }
            let (entry, en) = ReaddirEntry::unpack(input)?;
            n += en;
            entries.push(entry);
        }
        // EOF flag
        let (_, dn) = u32::unpack(input)?;
        n += dn;
        Ok((Self { status, entries }, n))
    }
}

// String helpers (duplicated from types.rs to avoid pub exports)

/// Write 1, 2, or 3 zero-padding bytes to reach a 4-byte XDR boundary.
fn write_xdr_pad(out: &mut impl Write, pad: usize) -> nfs3_types::xdr_codec::Result<()> {
    match pad {
        1 => out.write_all(&[0u8]).map_err(nfs3_types::xdr_codec::Error::Io),
        2 => out.write_all(&[0u8; 2]).map_err(nfs3_types::xdr_codec::Error::Io),
        3 => out.write_all(&[0u8; 3]).map_err(nfs3_types::xdr_codec::Error::Io),
        _ => Ok(()),
    }
}

/// Read and discard 1, 2, or 3 XDR padding bytes.
fn skip_xdr_pad(input: &mut impl Read, pad: usize) -> nfs3_types::xdr_codec::Result<()> {
    match pad {
        1 => {
            let mut b = [0u8; 1];
            input.read_exact(&mut b).map_err(nfs3_types::xdr_codec::Error::Io)
        },
        2 => {
            let mut b = [0u8; 2];
            input.read_exact(&mut b).map_err(nfs3_types::xdr_codec::Error::Io)
        },
        3 => {
            let mut b = [0u8; 3];
            input.read_exact(&mut b).map_err(nfs3_types::xdr_codec::Error::Io)
        },
        _ => Ok(()),
    }
}

fn pack_string(s: &str, out: &mut impl Write) -> nfs3_types::xdr_codec::Result<usize> {
    let bytes = s.as_bytes();
    let len = u32::try_from(bytes.len()).map_err(|_| nfs3_types::xdr_codec::Error::ObjectTooLarge(bytes.len()))?;
    let mut n = len.pack(out)?;
    out.write_all(bytes).map_err(nfs3_types::xdr_codec::Error::Io)?;
    n += bytes.len();
    let pad = (4 - (bytes.len() % 4)) % 4;
    write_xdr_pad(out, pad)?;
    n += pad;
    Ok(n)
}

fn unpack_string(input: &mut impl Read) -> nfs3_types::xdr_codec::Result<(String, usize)> {
    let (len, mut n) = u32::unpack(input)?;
    let len = len as usize;
    let mut buf = vec![0u8; len];
    input.read_exact(&mut buf).map_err(nfs3_types::xdr_codec::Error::Io)?;
    n += len;
    let pad = (4 - (len % 4)) % 4;
    skip_xdr_pad(input, pad)?;
    n += pad;
    Ok((String::from_utf8_lossy(&buf).into_owned(), n))
}

const fn string_packed_size(s: &str) -> usize {
    let len = s.len();
    4 + len + (4 - (len % 4)) % 4
}

/// Map a non-OK NfsStat to an error.
fn check_status(status: NfsStat) -> anyhow::Result<()> {
    if status == NfsStat::Ok { Ok(()) } else { Err(anyhow::anyhow!("NFSv2 error: {status:?}")) }
}
