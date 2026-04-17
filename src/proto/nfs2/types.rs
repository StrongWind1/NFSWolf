//! NFSv2 XDR types  --  RFC 1094.
//!
//! Simpler than NFSv3: fixed 32-byte handles, 32-bit file sizes,
//! no READDIRPLUS, synchronous writes only.
//! All types implement nfs3_types::xdr_codec::{Pack, Unpack} for wire encoding.
//! XDR encoding rules (RFC 1094 S2.1):
//! - File handles: fixed 32 bytes, no length prefix
//! - Strings: 4-byte length + data + zero-padding to 4-byte boundary
//! - All integers: big-endian u32

// XDR type fields are wire-format values; individual docs would repeat names.
// Toolkit API  --  not all items are used in currently-implemented phases.
// XDR Pack/Unpack implementations use fixed-size slice access; all accesses are
// guarded by the protocol's fixed field sizes (e.g., exact 32-byte file handle).
use std::io::{Read, Write};

use nfs3_types::xdr_codec::{Pack, Unpack};

/// NFSv2 fixed-size file handle (32 bytes, RFC 1094 S2.3.3).
/// Unlike v3's variable-length opaque, v2 handles are always exactly 32 bytes.
pub const FHSIZE: usize = 32;

/// NFSv2 program and version constants.
pub const NFS_PROGRAM: u32 = 100_003;
/// NFSv2 program version number.
pub const NFS_VERSION: u32 = 2;

/// NFSv2 procedure numbers (RFC 1094 S2.2).
pub mod proc {
    /// Null procedure  --  no-op.
    pub const NFSPROC_NULL: u32 = 0;
    /// Get file attributes.
    pub const NFSPROC_GETATTR: u32 = 1;
    /// Set file attributes.
    pub const NFSPROC_SETATTR: u32 = 2;
    /// Obsolete (ignored).
    pub const NFSPROC_ROOT: u32 = 3;
    /// Lookup filename in directory.
    pub const NFSPROC_LOOKUP: u32 = 4;
    /// Read symbolic link.
    pub const NFSPROC_READLINK: u32 = 5;
    /// Read from file.
    pub const NFSPROC_READ: u32 = 6;
    /// Unused.
    pub const NFSPROC_WRITECACHE: u32 = 7;
    /// Write to file.
    pub const NFSPROC_WRITE: u32 = 8;
    /// Create file.
    pub const NFSPROC_CREATE: u32 = 9;
    /// Remove file.
    pub const NFSPROC_REMOVE: u32 = 10;
    /// Rename file.
    pub const NFSPROC_RENAME: u32 = 11;
    /// Create hard link.
    pub const NFSPROC_LINK: u32 = 12;
    /// Create symbolic link.
    pub const NFSPROC_SYMLINK: u32 = 13;
    /// Create directory.
    pub const NFSPROC_MKDIR: u32 = 14;
    /// Remove directory.
    pub const NFSPROC_RMDIR: u32 = 15;
    /// Read directory entries.
    pub const NFSPROC_READDIR: u32 = 16;
    /// Get filesystem statistics.
    pub const NFSPROC_STATFS: u32 = 17;
}

/// NFSv2 status codes (RFC 1094 S2.3.1).
/// Subset of v3  --  notably missing NFS3ERR_BADHANDLE (the handle oracle
/// only works on v3+, but v2 doesn't need it since handles are fixed-format).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum NfsStat {
    /// No error.
    Ok = 0,
    /// Not owner.
    Perm = 1,
    /// No such file or directory.
    NoEnt = 2,
    /// I/O error.
    Io = 5,
    /// No such device.
    Nxio = 6,
    /// Permission denied.
    Acces = 13,
    /// File exists.
    Exist = 17,
    /// No such device.
    NoDev = 19,
    /// Not a directory.
    NotDir = 20,
    /// Is a directory.
    IsDir = 21,
    /// File too large.
    Fbig = 27,
    /// No space left on device.
    NoSpc = 28,
    /// Read-only filesystem.
    Rofs = 30,
    /// File name too long.
    NameTooLong = 63,
    /// Directory not empty.
    NotEmpty = 66,
    /// Disk quota exceeded.
    Dquot = 69,
    /// Stale file handle.
    Stale = 70,
}

impl NfsStat {
    /// Decode a u32 status code from the wire.
    #[must_use]
    pub const fn from_u32(v: u32) -> Self {
        match v {
            0 => Self::Ok,
            1 => Self::Perm,
            2 => Self::NoEnt,
            6 => Self::Nxio,
            13 => Self::Acces,
            17 => Self::Exist,
            19 => Self::NoDev,
            20 => Self::NotDir,
            21 => Self::IsDir,
            27 => Self::Fbig,
            28 => Self::NoSpc,
            30 => Self::Rofs,
            63 => Self::NameTooLong,
            66 => Self::NotEmpty,
            69 => Self::Dquot,
            70 => Self::Stale,
            // 5 = NFS_ERR_IO; all unknown status codes also map to IO.
            _ => Self::Io,
        }
    }
}

impl Pack for NfsStat {
    fn packed_size(&self) -> usize {
        4
    }
    fn pack(&self, out: &mut impl Write) -> nfs3_types::xdr_codec::Result<usize> {
        (*self as u32).pack(out)
    }
}

impl Unpack for NfsStat {
    fn unpack(input: &mut impl Read) -> nfs3_types::xdr_codec::Result<(Self, usize)> {
        let (v, n) = u32::unpack(input)?;
        Ok((Self::from_u32(v), n))
    }
}

/// NFSv2 file type (RFC 1094 S2.3.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum FType {
    /// Non-file (used for error cases).
    NonFile = 0,
    /// Regular file.
    Regular = 1,
    /// Directory.
    Directory = 2,
    /// Block device.
    Block = 3,
    /// Character device.
    Character = 4,
    /// Symbolic link.
    Symlink = 5,
}

impl FType {
    /// Decode from wire u32.
    #[must_use]
    pub const fn from_u32(v: u32) -> Self {
        match v {
            1 => Self::Regular,
            2 => Self::Directory,
            3 => Self::Block,
            4 => Self::Character,
            5 => Self::Symlink,
            _ => Self::NonFile,
        }
    }
}

impl Pack for FType {
    fn packed_size(&self) -> usize {
        4
    }
    fn pack(&self, out: &mut impl Write) -> nfs3_types::xdr_codec::Result<usize> {
        (*self as u32).pack(out)
    }
}

impl Unpack for FType {
    fn unpack(input: &mut impl Read) -> nfs3_types::xdr_codec::Result<(Self, usize)> {
        let (v, n) = u32::unpack(input)?;
        Ok((Self::from_u32(v), n))
    }
}

// --- XDR helper for NFS strings (4-byte len + data + padding) ---

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
    let s = String::from_utf8_lossy(&buf).into_owned();
    Ok((s, n))
}

const fn string_packed_size(s: &str) -> usize {
    let len = s.len();
    4 + len + (4 - (len % 4)) % 4
}

// --- Fixed 32-byte file handle ---

/// NFSv2 fixed-size file handle (32 bytes, no length prefix).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Nfs2FileHandle(pub [u8; FHSIZE]);

impl Nfs2FileHandle {
    /// Create a handle from a byte slice, truncating or padding with zeros.
    #[must_use]
    pub fn from_bytes(b: &[u8]) -> Self {
        let mut arr = [0u8; FHSIZE];
        let n = b.len().min(FHSIZE);
        if let (Some(dst), Some(src)) = (arr.get_mut(..n), b.get(..n)) {
            dst.copy_from_slice(src);
        }
        Self(arr)
    }
}

impl Pack for Nfs2FileHandle {
    fn packed_size(&self) -> usize {
        FHSIZE
    }
    fn pack(&self, out: &mut impl Write) -> nfs3_types::xdr_codec::Result<usize> {
        out.write_all(&self.0).map_err(nfs3_types::xdr_codec::Error::Io)?;
        Ok(FHSIZE)
    }
}

impl Unpack for Nfs2FileHandle {
    fn unpack(input: &mut impl Read) -> nfs3_types::xdr_codec::Result<(Self, usize)> {
        let mut buf = [0u8; FHSIZE];
        input.read_exact(&mut buf).map_err(nfs3_types::xdr_codec::Error::Io)?;
        Ok((Self(buf), FHSIZE))
    }
}

// --- Timeval ---

/// UNIX timeval (seconds + microseconds) used in NFSv2 timestamps (RFC 1094 S2.3.5).
#[derive(Debug, Clone, Copy)]
pub struct Timeval {
    /// Seconds since epoch.
    pub seconds: u32,
    /// Microseconds within the second.
    pub useconds: u32,
}

impl Pack for Timeval {
    fn packed_size(&self) -> usize {
        8
    }
    fn pack(&self, out: &mut impl Write) -> nfs3_types::xdr_codec::Result<usize> {
        Ok(self.seconds.pack(out)? + self.useconds.pack(out)?)
    }
}

impl Unpack for Timeval {
    fn unpack(input: &mut impl Read) -> nfs3_types::xdr_codec::Result<(Self, usize)> {
        let (seconds, n1) = u32::unpack(input)?;
        let (useconds, n2) = u32::unpack(input)?;
        Ok((Self { seconds, useconds }, n1 + n2))
    }
}

// --- File attributes ---

/// NFSv2 file attributes (RFC 1094 S2.3.5).
/// 32-bit sizes (vs v3's 64-bit), timeval timestamps.
#[derive(Debug, Clone)]
pub struct Nfs2FileAttr {
    /// File type.
    pub ftype: FType,
    /// File mode (permission bits).
    pub mode: u32,
    /// Number of hard links.
    pub nlink: u32,
    /// Owner user ID.
    pub uid: u32,
    /// Owner group ID.
    pub gid: u32,
    /// File size in bytes (32-bit: 2 GB max).
    pub size: u32,
    /// Block size for I/O.
    pub blocksize: u32,
    /// Device ID (for device files).
    pub rdev: u32,
    /// Number of 512-byte blocks allocated.
    pub blocks: u32,
    /// Filesystem ID.
    pub fsid: u32,
    /// File inode number.
    pub fileid: u32,
    /// Last access time.
    pub atime: Timeval,
    /// Last modification time.
    pub mtime: Timeval,
    /// Last status-change time.
    pub ctime: Timeval,
}

impl Nfs2FileAttr {
    /// Zero-valued attributes for error response branches where no attrs are on the wire.
    const fn zeroed() -> Self {
        Self { ftype: FType::NonFile, mode: 0, nlink: 0, uid: 0, gid: 0, size: 0, blocksize: 0, rdev: 0, blocks: 0, fsid: 0, fileid: 0, atime: Timeval { seconds: 0, useconds: 0 }, mtime: Timeval { seconds: 0, useconds: 0 }, ctime: Timeval { seconds: 0, useconds: 0 } }
    }
}

impl Pack for Nfs2FileAttr {
    fn packed_size(&self) -> usize {
        4 * 11 + 8 * 3
    } // 11 u32 fields + 3 timevals
    fn pack(&self, out: &mut impl Write) -> nfs3_types::xdr_codec::Result<usize> {
        let mut n = 0;
        n += self.ftype.pack(out)?;
        n += self.mode.pack(out)?;
        n += self.nlink.pack(out)?;
        n += self.uid.pack(out)?;
        n += self.gid.pack(out)?;
        n += self.size.pack(out)?;
        n += self.blocksize.pack(out)?;
        n += self.rdev.pack(out)?;
        n += self.blocks.pack(out)?;
        n += self.fsid.pack(out)?;
        n += self.fileid.pack(out)?;
        n += self.atime.pack(out)?;
        n += self.mtime.pack(out)?;
        n += self.ctime.pack(out)?;
        Ok(n)
    }
}

impl Unpack for Nfs2FileAttr {
    fn unpack(input: &mut impl Read) -> nfs3_types::xdr_codec::Result<(Self, usize)> {
        let (ftype, n0) = FType::unpack(input)?;
        let (mode, n1) = u32::unpack(input)?;
        let (nlink, n2) = u32::unpack(input)?;
        let (uid, n3) = u32::unpack(input)?;
        let (gid, n4) = u32::unpack(input)?;
        let (size, n5) = u32::unpack(input)?;
        let (blocksize, n6) = u32::unpack(input)?;
        let (rdev, n7) = u32::unpack(input)?;
        let (blocks, n8) = u32::unpack(input)?;
        let (fsid, n9) = u32::unpack(input)?;
        let (fileid, n10) = u32::unpack(input)?;
        let (atime, n11) = Timeval::unpack(input)?;
        let (mtime, n12) = Timeval::unpack(input)?;
        let (ctime, n13) = Timeval::unpack(input)?;
        let total = n0 + n1 + n2 + n3 + n4 + n5 + n6 + n7 + n8 + n9 + n10 + n11 + n12 + n13;
        Ok((Self { ftype, mode, nlink, uid, gid, size, blocksize, rdev, blocks, fsid, fileid, atime, mtime, ctime }, total))
    }
}

// --- Settable attributes (SETATTR) ---

/// Sentinel value meaning "don't change this field" (RFC 1094 S2.3.6).
pub const SATTR_UNCHANGED: u32 = 0xFFFF_FFFF;

/// Settable attributes for SETATTR  --  fields set to `SATTR_UNCHANGED` are not modified.
#[derive(Debug, Clone)]
pub struct Nfs2SetAttr {
    /// New file mode, or `SATTR_UNCHANGED`.
    pub mode: u32,
    /// New owner UID, or `SATTR_UNCHANGED`.
    pub uid: u32,
    /// New owner GID, or `SATTR_UNCHANGED`.
    pub gid: u32,
    /// New file size, or `SATTR_UNCHANGED` (truncate/extend).
    pub size: u32,
    /// New access time.
    pub atime: Timeval,
    /// New modification time.
    pub mtime: Timeval,
}

impl Pack for Nfs2SetAttr {
    fn packed_size(&self) -> usize {
        4 * 4 + 8 * 2
    }
    fn pack(&self, out: &mut impl Write) -> nfs3_types::xdr_codec::Result<usize> {
        let mut n = 0;
        n += self.mode.pack(out)?;
        n += self.uid.pack(out)?;
        n += self.gid.pack(out)?;
        n += self.size.pack(out)?;
        n += self.atime.pack(out)?;
        n += self.mtime.pack(out)?;
        Ok(n)
    }
}

impl Unpack for Nfs2SetAttr {
    fn unpack(input: &mut impl Read) -> nfs3_types::xdr_codec::Result<(Self, usize)> {
        let (mode, n0) = u32::unpack(input)?;
        let (uid, n1) = u32::unpack(input)?;
        let (gid, n2) = u32::unpack(input)?;
        let (size, n3) = u32::unpack(input)?;
        let (atime, n4) = Timeval::unpack(input)?;
        let (mtime, n5) = Timeval::unpack(input)?;
        Ok((Self { mode, uid, gid, size, atime, mtime }, n0 + n1 + n2 + n3 + n4 + n5))
    }
}

// --- Directory operation types ---

/// Arguments for LOOKUP and CREATE (fhandle + filename).
#[derive(Debug, Clone)]
pub struct DirOpArgs {
    /// Parent directory handle.
    pub dir: Nfs2FileHandle,
    /// Filename within the directory.
    pub name: String,
}

impl Pack for DirOpArgs {
    fn packed_size(&self) -> usize {
        FHSIZE + string_packed_size(&self.name)
    }
    fn pack(&self, out: &mut impl Write) -> nfs3_types::xdr_codec::Result<usize> {
        Ok(self.dir.pack(out)? + pack_string(&self.name, out)?)
    }
}

impl Unpack for DirOpArgs {
    fn unpack(input: &mut impl Read) -> nfs3_types::xdr_codec::Result<(Self, usize)> {
        let (dir, n0) = Nfs2FileHandle::unpack(input)?;
        let (name, n1) = unpack_string(input)?;
        Ok((Self { dir, name }, n0 + n1))
    }
}

/// Result of LOOKUP or CREATE.
#[derive(Debug, Clone)]
pub struct DirOpRes {
    /// Status code.
    pub status: NfsStat,
    /// New file handle (valid only if `status == Ok`).
    pub handle: Nfs2FileHandle,
    /// Attributes of the file (valid only if `status == Ok`).
    pub attrs: Nfs2FileAttr,
}

impl Pack for DirOpRes {
    fn packed_size(&self) -> usize {
        4 + FHSIZE + self.attrs.packed_size()
    }
    fn pack(&self, out: &mut impl Write) -> nfs3_types::xdr_codec::Result<usize> {
        Ok(self.status.pack(out)? + self.handle.pack(out)? + self.attrs.pack(out)?)
    }
}

impl Unpack for DirOpRes {
    /// RFC 1094  --  diropres is an XDR union: on error status, only the status
    /// discriminant is present (no handle or attrs follow).
    fn unpack(input: &mut impl Read) -> nfs3_types::xdr_codec::Result<(Self, usize)> {
        let (status, n0) = NfsStat::unpack(input)?;
        if status != NfsStat::Ok {
            return Ok((Self { status, handle: Nfs2FileHandle([0u8; FHSIZE]), attrs: Nfs2FileAttr::zeroed() }, n0));
        }
        let (handle, n1) = Nfs2FileHandle::unpack(input)?;
        let (attrs, n2) = Nfs2FileAttr::unpack(input)?;
        Ok((Self { status, handle, attrs }, n0 + n1 + n2))
    }
}

// --- Attribute status result (GETATTR, SETATTR, WRITE responses) ---

/// Result of GETATTR, SETATTR, and WRITE  --  `attrstat` per RFC 1094 S2.3.9.
/// XDR union: on success, contains status + fattr. On error, only status.
/// Unlike `DirOpRes`, this does NOT include a file handle.
#[derive(Debug, Clone)]
pub struct AttrStatRes {
    /// Status code.
    pub status: NfsStat,
    /// File attributes (valid only if `status == Ok`).
    pub attrs: Nfs2FileAttr,
}

impl Unpack for AttrStatRes {
    /// RFC 1094  --  attrstat is an XDR union: on error status, only the status
    /// discriminant is present (no attrs follow).
    fn unpack(input: &mut impl Read) -> nfs3_types::xdr_codec::Result<(Self, usize)> {
        let (status, n0) = NfsStat::unpack(input)?;
        if status != NfsStat::Ok {
            return Ok((Self { status, attrs: Nfs2FileAttr::zeroed() }, n0));
        }
        let (attrs, n1) = Nfs2FileAttr::unpack(input)?;
        Ok((Self { status, attrs }, n0 + n1))
    }
}

// --- Read ---

/// Arguments for the READ procedure.
#[derive(Debug, Clone)]
pub struct ReadArgs {
    /// File handle.
    pub file: Nfs2FileHandle,
    /// Byte offset within the file.
    pub offset: u32,
    /// Number of bytes to read.
    pub count: u32,
    /// Unused (set to 0 per RFC 1094).
    pub totalcount: u32,
}

impl Pack for ReadArgs {
    fn packed_size(&self) -> usize {
        FHSIZE + 12
    }
    fn pack(&self, out: &mut impl Write) -> nfs3_types::xdr_codec::Result<usize> {
        Ok(self.file.pack(out)? + self.offset.pack(out)? + self.count.pack(out)? + self.totalcount.pack(out)?)
    }
}

impl Unpack for ReadArgs {
    fn unpack(input: &mut impl Read) -> nfs3_types::xdr_codec::Result<(Self, usize)> {
        let (file, n0) = Nfs2FileHandle::unpack(input)?;
        let (offset, n1) = u32::unpack(input)?;
        let (count, n2) = u32::unpack(input)?;
        let (totalcount, n3) = u32::unpack(input)?;
        Ok((Self { file, offset, count, totalcount }, n0 + n1 + n2 + n3))
    }
}

/// Result of a READ call.
#[derive(Debug, Clone)]
pub struct ReadRes {
    /// Status code.
    pub status: NfsStat,
    /// Current file attributes.
    pub attrs: Nfs2FileAttr,
    /// Data read from the file.
    pub data: Vec<u8>,
}

impl Unpack for ReadRes {
    /// RFC 1094  --  readres is an XDR union: on error status, only the status
    /// discriminant is present (no attrs or data follow).
    fn unpack(input: &mut impl Read) -> nfs3_types::xdr_codec::Result<(Self, usize)> {
        let (status, n0) = NfsStat::unpack(input)?;
        if status != NfsStat::Ok {
            return Ok((Self { status, attrs: Nfs2FileAttr::zeroed(), data: Vec::new() }, n0));
        }
        let (attrs, n1) = Nfs2FileAttr::unpack(input)?;
        // Data is XDR opaque: 4-byte length then raw bytes with padding
        let (data_len, n2) = u32::unpack(input)?;
        let data_len = data_len as usize;
        let mut data = vec![0u8; data_len];
        input.read_exact(&mut data).map_err(nfs3_types::xdr_codec::Error::Io)?;
        let pad = (4 - (data_len % 4)) % 4;
        skip_xdr_pad(input, pad)?;
        Ok((Self { status, attrs, data }, n0 + n1 + n2 + data_len + pad))
    }
}

// --- Write ---

/// Arguments for the WRITE procedure.
#[derive(Debug, Clone)]
pub struct WriteArgs {
    /// File handle.
    pub file: Nfs2FileHandle,
    /// Unused (set to 0 per RFC 1094).
    pub beginoffset: u32,
    /// Byte offset for the write.
    pub offset: u32,
    /// Unused (set to 0 per RFC 1094).
    pub totalcount: u32,
    /// Data to write.
    pub data: Vec<u8>,
}

impl Pack for WriteArgs {
    fn packed_size(&self) -> usize {
        FHSIZE + 12 + 4 + self.data.len() + (4 - (self.data.len() % 4)) % 4
    }
    fn pack(&self, out: &mut impl Write) -> nfs3_types::xdr_codec::Result<usize> {
        let mut n = self.file.pack(out)?;
        n += self.beginoffset.pack(out)?;
        n += self.offset.pack(out)?;
        n += self.totalcount.pack(out)?;
        // Write data as XDR opaque
        let data_len = u32::try_from(self.data.len()).map_err(|_| nfs3_types::xdr_codec::Error::ObjectTooLarge(self.data.len()))?;
        n += data_len.pack(out)?;
        out.write_all(&self.data).map_err(nfs3_types::xdr_codec::Error::Io)?;
        n += self.data.len();
        let pad = (4 - (self.data.len() % 4)) % 4;
        write_xdr_pad(out, pad)?;
        n += pad;
        Ok(n)
    }
}

// --- READDIR ---

/// Arguments for the READDIR procedure.
#[derive(Debug, Clone)]
pub struct ReaddirArgs {
    /// Directory file handle.
    pub dir: Nfs2FileHandle,
    /// Opaque cookie from previous READDIR (0 for first call).
    pub cookie: u32,
    /// Preferred response size in bytes.
    pub count: u32,
}

impl Pack for ReaddirArgs {
    fn packed_size(&self) -> usize {
        FHSIZE + 8
    }
    fn pack(&self, out: &mut impl Write) -> nfs3_types::xdr_codec::Result<usize> {
        Ok(self.dir.pack(out)? + self.cookie.pack(out)? + self.count.pack(out)?)
    }
}

// --- Tests ---

#[cfg(test)]
mod tests {
    #![allow(
        clippy::all,
        clippy::pedantic,
        clippy::nursery,
        clippy::cargo,
        clippy::expect_used,
        clippy::unwrap_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::cast_possible_truncation,
        clippy::cast_possible_wrap,
        clippy::cast_precision_loss,
        clippy::cast_sign_loss,
        reason = "unit test  --  lints are suppressed per project policy"
    )]
    use super::*;
    use std::io::Cursor;

    #[test]
    fn nfsstat_from_u32_maps_all_known_codes() {
        assert_eq!(NfsStat::from_u32(0), NfsStat::Ok);
        assert_eq!(NfsStat::from_u32(1), NfsStat::Perm);
        assert_eq!(NfsStat::from_u32(2), NfsStat::NoEnt);
        assert_eq!(NfsStat::from_u32(5), NfsStat::Io);
        assert_eq!(NfsStat::from_u32(6), NfsStat::Nxio);
        assert_eq!(NfsStat::from_u32(13), NfsStat::Acces);
        assert_eq!(NfsStat::from_u32(17), NfsStat::Exist);
        assert_eq!(NfsStat::from_u32(19), NfsStat::NoDev);
        assert_eq!(NfsStat::from_u32(20), NfsStat::NotDir);
        assert_eq!(NfsStat::from_u32(21), NfsStat::IsDir);
        assert_eq!(NfsStat::from_u32(27), NfsStat::Fbig);
        assert_eq!(NfsStat::from_u32(28), NfsStat::NoSpc);
        assert_eq!(NfsStat::from_u32(30), NfsStat::Rofs);
        assert_eq!(NfsStat::from_u32(63), NfsStat::NameTooLong);
        assert_eq!(NfsStat::from_u32(66), NfsStat::NotEmpty);
        assert_eq!(NfsStat::from_u32(69), NfsStat::Dquot);
        assert_eq!(NfsStat::from_u32(70), NfsStat::Stale);
    }

    #[test]
    fn nfsstat_from_u32_unknown_maps_to_io() {
        assert_eq!(NfsStat::from_u32(9999), NfsStat::Io);
        assert_eq!(NfsStat::from_u32(42), NfsStat::Io);
    }

    #[test]
    fn nfs2_file_handle_from_bytes_truncates_to_32() {
        let big = vec![0xAB; 64];
        let fh = Nfs2FileHandle::from_bytes(&big);
        assert_eq!(fh.0.len(), 32);
        assert!(fh.0.iter().all(|&b| b == 0xAB));
    }

    #[test]
    fn nfs2_file_handle_from_bytes_pads_short_input() {
        let short = vec![0xFF; 4];
        let fh = Nfs2FileHandle::from_bytes(&short);
        assert_eq!(fh.0[0], 0xFF);
        assert_eq!(fh.0[3], 0xFF);
        assert_eq!(fh.0[4], 0x00);
        assert_eq!(fh.0[31], 0x00);
    }

    #[test]
    fn nfs2_file_handle_pack_unpack_round_trip() {
        let fh = Nfs2FileHandle::from_bytes(&[1, 2, 3, 4, 5]);
        let mut buf = Vec::new();
        fh.pack(&mut buf).unwrap();
        assert_eq!(buf.len(), 32);
        let (decoded, n) = Nfs2FileHandle::unpack(&mut Cursor::new(&buf)).unwrap();
        assert_eq!(n, 32);
        assert_eq!(decoded, fh);
    }

    #[test]
    fn diropres_unpack_ok_branch_decodes_handle_and_attrs() {
        // Build a DirOpRes with status=Ok, then a 32-byte handle, then 68 bytes of attrs.
        let mut wire: Vec<u8> = Vec::new();
        NfsStat::Ok.pack(&mut wire).unwrap();
        let fh = Nfs2FileHandle::from_bytes(&[0x42; 32]);
        fh.pack(&mut wire).unwrap();
        // Minimal attrs: ftype=Regular(1), then 10 u32 zeros, then 3 timevals of zeros
        FType::Regular.pack(&mut wire).unwrap();
        for _ in 0..10 {
            0u32.pack(&mut wire).unwrap();
        }
        for _ in 0..6 {
            0u32.pack(&mut wire).unwrap();
        }
        let (res, _) = DirOpRes::unpack(&mut Cursor::new(&wire)).unwrap();
        assert_eq!(res.status, NfsStat::Ok);
        assert_eq!(res.handle, fh);
        assert_eq!(res.attrs.ftype, FType::Regular);
    }

    #[test]
    fn diropres_unpack_error_branch_returns_zeroed() {
        let mut wire: Vec<u8> = Vec::new();
        NfsStat::Acces.pack(&mut wire).unwrap();
        // No handle or attrs follow the error status.
        let (res, n) = DirOpRes::unpack(&mut Cursor::new(&wire)).unwrap();
        assert_eq!(res.status, NfsStat::Acces);
        assert_eq!(res.handle, Nfs2FileHandle([0u8; FHSIZE]));
        assert_eq!(res.attrs.ftype, FType::NonFile);
        assert_eq!(n, 4);
    }

    #[test]
    fn attrstatres_unpack_ok_branch() {
        let mut wire: Vec<u8> = Vec::new();
        NfsStat::Ok.pack(&mut wire).unwrap();
        let attr =
            Nfs2FileAttr { ftype: FType::Directory, mode: 0o755, nlink: 2, uid: 0, gid: 0, size: 4096, blocksize: 4096, rdev: 0, blocks: 8, fsid: 1, fileid: 2, atime: Timeval { seconds: 100, useconds: 0 }, mtime: Timeval { seconds: 200, useconds: 0 }, ctime: Timeval { seconds: 300, useconds: 0 } };
        attr.pack(&mut wire).unwrap();
        let (res, _) = AttrStatRes::unpack(&mut Cursor::new(&wire)).unwrap();
        assert_eq!(res.status, NfsStat::Ok);
        assert_eq!(res.attrs.ftype, FType::Directory);
        assert_eq!(res.attrs.mode, 0o755);
    }

    #[test]
    fn readres_unpack_error_branch() {
        let mut wire: Vec<u8> = Vec::new();
        NfsStat::Perm.pack(&mut wire).unwrap();
        let (res, n) = ReadRes::unpack(&mut Cursor::new(&wire)).unwrap();
        assert_eq!(res.status, NfsStat::Perm);
        assert!(res.data.is_empty());
        assert_eq!(n, 4);
    }

    #[test]
    fn statfsres_unpack_error_branch() {
        let mut wire: Vec<u8> = Vec::new();
        NfsStat::Stale.pack(&mut wire).unwrap();
        let (res, n) = StatFsRes::unpack(&mut Cursor::new(&wire)).unwrap();
        assert_eq!(res.status, NfsStat::Stale);
        assert_eq!(res.tsize, 0);
        assert_eq!(n, 4);
    }

    #[test]
    fn ftype_from_u32_covers_all_variants() {
        assert_eq!(FType::from_u32(0), FType::NonFile);
        assert_eq!(FType::from_u32(1), FType::Regular);
        assert_eq!(FType::from_u32(2), FType::Directory);
        assert_eq!(FType::from_u32(3), FType::Block);
        assert_eq!(FType::from_u32(4), FType::Character);
        assert_eq!(FType::from_u32(5), FType::Symlink);
        assert_eq!(FType::from_u32(99), FType::NonFile);
    }

    // --- XDR pack size tests ---

    #[test]
    fn nfs2_file_handle_pack_produces_exactly_32_bytes() {
        let fh = Nfs2FileHandle::from_bytes(&[0xAB; 10]);
        let mut buf = Vec::new();
        let n = fh.pack(&mut buf).unwrap();
        assert_eq!(n, 32);
        assert_eq!(buf.len(), 32);
    }

    #[test]
    fn nfs2_file_handle_unpack_reads_exactly_32_bytes() {
        let wire = vec![0x42u8; 64]; // more than 32 bytes available
        let (_, n) = Nfs2FileHandle::unpack(&mut Cursor::new(&wire)).unwrap();
        assert_eq!(n, 32, "unpack must consume exactly 32 bytes");
    }

    #[test]
    fn timeval_pack_is_8_bytes() {
        let tv = Timeval { seconds: 1000, useconds: 500 };
        let mut buf = Vec::new();
        let n = tv.pack(&mut buf).unwrap();
        assert_eq!(n, 8);
        assert_eq!(buf.len(), 8);
    }

    #[test]
    fn nfs2_file_attr_pack_is_68_bytes() {
        let attr =
            Nfs2FileAttr { ftype: FType::Regular, mode: 0o644, nlink: 1, uid: 1000, gid: 1000, size: 4096, blocksize: 4096, rdev: 0, blocks: 8, fsid: 1, fileid: 42, atime: Timeval { seconds: 0, useconds: 0 }, mtime: Timeval { seconds: 0, useconds: 0 }, ctime: Timeval { seconds: 0, useconds: 0 } };
        let mut buf = Vec::new();
        let n = attr.pack(&mut buf).unwrap();
        // 11 u32 fields (44 bytes) + 3 timevals (24 bytes) = 68 bytes
        assert_eq!(n, 68);
        assert_eq!(buf.len(), 68);
    }

    #[test]
    fn nfs2_setattr_pack_is_32_bytes() {
        let sa = Nfs2SetAttr { mode: SATTR_UNCHANGED, uid: SATTR_UNCHANGED, gid: SATTR_UNCHANGED, size: SATTR_UNCHANGED, atime: Timeval { seconds: 0, useconds: 0 }, mtime: Timeval { seconds: 0, useconds: 0 } };
        let mut buf = Vec::new();
        let n = sa.pack(&mut buf).unwrap();
        // 4 u32 fields (16 bytes) + 2 timevals (16 bytes) = 32 bytes
        assert_eq!(n, 32);
        assert_eq!(buf.len(), 32);
    }

    #[test]
    fn diropargs_pack_includes_handle_and_string() {
        let args = DirOpArgs { dir: Nfs2FileHandle::from_bytes(&[0; 32]), name: "test".to_owned() };
        let mut buf = Vec::new();
        let n = args.pack(&mut buf).unwrap();
        // 32 (handle) + 4 (string len) + 4 (data "test") = 40 bytes
        assert_eq!(n, 40);
    }

    #[test]
    fn write_args_pack_includes_data_with_xdr_padding() {
        let args = WriteArgs {
            file: Nfs2FileHandle::from_bytes(&[0; 32]),
            beginoffset: 0,
            offset: 0,
            totalcount: 0,
            data: vec![0xAB; 5], // 5 bytes + 3 padding = 8
        };
        let mut buf = Vec::new();
        let n = args.pack(&mut buf).unwrap();
        // 32 (handle) + 12 (3 u32) + 4 (data len) + 5 (data) + 3 (pad) = 56
        assert_eq!(n, 56);
    }

    #[test]
    fn read_args_pack_is_fhsize_plus_12() {
        let args = ReadArgs { file: Nfs2FileHandle::from_bytes(&[0; 32]), offset: 0, count: 1024, totalcount: 0 };
        let mut buf = Vec::new();
        let n = args.pack(&mut buf).unwrap();
        assert_eq!(n, FHSIZE + 12);
    }
}

/// Single READDIR entry.
#[derive(Debug, Clone)]
pub struct ReaddirEntry {
    /// Inode number.
    pub fileid: u32,
    /// File name.
    pub name: String,
    /// Cookie for resuming enumeration after this entry.
    pub cookie: u32,
}

impl Unpack for ReaddirEntry {
    fn unpack(input: &mut impl Read) -> nfs3_types::xdr_codec::Result<(Self, usize)> {
        let (fileid, n0) = u32::unpack(input)?;
        let (name, n1) = unpack_string(input)?;
        let (cookie, n2) = u32::unpack(input)?;
        Ok((Self { fileid, name, cookie }, n0 + n1 + n2))
    }
}

// --- STATFS ---

/// Result of STATFS.
#[derive(Debug, Clone)]
pub struct StatFsRes {
    /// Status code.
    pub status: NfsStat,
    /// Optimal transfer size in bytes.
    pub tsize: u32,
    /// Block size in bytes.
    pub bsize: u32,
    /// Total data blocks in filesystem.
    pub blocks: u32,
    /// Free blocks in filesystem.
    pub bfree: u32,
    /// Free blocks available to non-superuser.
    pub bavail: u32,
}

impl Unpack for StatFsRes {
    /// RFC 1094  --  statfsres is an XDR union: on error status, only the status
    /// discriminant is present (no filesystem info follows).
    fn unpack(input: &mut impl Read) -> nfs3_types::xdr_codec::Result<(Self, usize)> {
        let (status, n0) = NfsStat::unpack(input)?;
        if status != NfsStat::Ok {
            return Ok((Self { status, tsize: 0, bsize: 0, blocks: 0, bfree: 0, bavail: 0 }, n0));
        }
        let (tsize, n1) = u32::unpack(input)?;
        let (bsize, n2) = u32::unpack(input)?;
        let (blocks, n3) = u32::unpack(input)?;
        let (bfree, n4) = u32::unpack(input)?;
        let (bavail, n5) = u32::unpack(input)?;
        Ok((Self { status, tsize, bsize, blocks, bfree, bavail }, n0 + n1 + n2 + n3 + n4 + n5))
    }
}
