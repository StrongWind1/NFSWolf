//! NFSv2 XDR types  --  RFC 1094.
//!
//! Simpler than NFSv3: fixed 32-byte handles, 32-bit file sizes,
//! no READDIRPLUS, synchronous writes only.
//! All types implement onc_xdr::{Pack, Unpack} for wire encoding.
//! XDR encoding rules (RFC 1094 S2.1):
//! - File handles: fixed 32 bytes, no length prefix
//! - Strings: 4-byte length + data + zero-padding to 4-byte boundary
//! - All integers: big-endian u32

#![expect(non_camel_case_types, reason = "identifiers are transcribed verbatim from RFC 1094's XDR definitions; renaming them to Rust conventions would break the correspondence a reader needs when checking this module against the spec")]
#![expect(missing_docs, reason = "these are mechanical transcriptions of the RFC's XDR type table -- per-field prose would restate the field name and nothing more. The module doc cites the defining RFC section, which is the real documentation")]
#![expect(
    missing_copy_implementations,
    reason = "Copy is derived on the wire types whose callers benefit from it; demanding it exhaustively cascades through every containing struct without improving the API, and whether a value is copied or moved is a Rust-side choice the wire format has no opinion on"
)]

// XDR type fields are wire-format values; individual docs would repeat names.
// Toolkit API  --  not all items are used in currently-implemented phases.
// XDR Pack/Unpack implementations use fixed-size slice access; all accesses are
// guarded by the protocol's fixed field sizes (e.g., exact 32-byte file handle).
use std::io::{Read, Write};

use onc_xdr::{Pack, Unpack};

/// NFSv2 fixed-size file handle (32 bytes, RFC 1094 S2.3.3).
/// Unlike v3's variable-length opaque, v2 handles are always exactly 32 bytes.
pub const FHSIZE: usize = 32;

/// NFSv2 program and version constants.
pub const NFS_PROGRAM: u32 = 100_003;
/// NFSv2 program version number.
pub const NFS_VERSION: u32 = 2;
/// Maximum data transfer size for READ/WRITE (RFC 1094 sec 3.5).
pub const MAXDATA: usize = 8192;
/// Maximum pathname length (RFC 1094 sec 3.5).
pub const MAXPATHLEN: usize = 1024;
/// Maximum filename component length (RFC 1094 sec 3.5).
pub const MAXNAMLEN: usize = 255;
/// Cookie size in bytes for READDIR (RFC 1094 sec 3.5).
pub const COOKIESIZE: usize = 4;

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
#[non_exhaustive]
pub enum Nfs2Stat {
    /// No error.
    Ok,
    /// Not owner.
    Perm,
    /// No such file or directory.
    NoEnt,
    /// I/O error.
    Io,
    /// No such device.
    Nxio,
    /// Permission denied.
    Acces,
    /// File exists.
    Exist,
    /// No such device.
    NoDev,
    /// Not a directory.
    NotDir,
    /// Is a directory.
    IsDir,
    /// File too large.
    Fbig,
    /// No space left on device.
    NoSpc,
    /// Read-only filesystem.
    Rofs,
    /// File name too long.
    NameTooLong,
    /// Directory not empty.
    NotEmpty,
    /// Disk quota exceeded.
    Dquot,
    /// Stale file handle.
    Stale,
    /// Write cache flushed (RFC 1094 S2.3.1, server-only advisory).
    WFlush,
    /// Unrecognized status code from the wire.
    Unknown(u32),
}

impl Nfs2Stat {
    /// Decode a u32 status code from the wire.
    #[must_use]
    pub const fn from_u32(v: u32) -> Self {
        match v {
            0 => Self::Ok,
            1 => Self::Perm,
            2 => Self::NoEnt,
            5 => Self::Io,
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
            99 => Self::WFlush,
            _ => Self::Unknown(v),
        }
    }

    /// Encode to the wire u32 value.
    const fn to_u32(self) -> u32 {
        match self {
            Self::Ok => 0,
            Self::Perm => 1,
            Self::NoEnt => 2,
            Self::Io => 5,
            Self::Nxio => 6,
            Self::Acces => 13,
            Self::Exist => 17,
            Self::NoDev => 19,
            Self::NotDir => 20,
            Self::IsDir => 21,
            Self::Fbig => 27,
            Self::NoSpc => 28,
            Self::Rofs => 30,
            Self::NameTooLong => 63,
            Self::NotEmpty => 66,
            Self::Dquot => 69,
            Self::Stale => 70,
            Self::WFlush => 99,
            Self::Unknown(v) => v,
        }
    }
}

impl Pack for Nfs2Stat {
    fn packed_size(&self) -> usize {
        4
    }
    fn pack(&self, out: &mut impl Write) -> onc_xdr::Result<usize> {
        self.to_u32().pack(out)
    }
}

impl Unpack for Nfs2Stat {
    fn unpack(input: &mut impl Read) -> onc_xdr::Result<(Self, usize)> {
        let (v, n) = u32::unpack(input)?;
        Ok((Self::from_u32(v), n))
    }
}

impl std::fmt::Display for Nfs2Stat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ok => f.write_str("NFS_OK"),
            Self::Perm => f.write_str("NFSERR_PERM"),
            Self::NoEnt => f.write_str("NFSERR_NOENT"),
            Self::Io => f.write_str("NFSERR_IO"),
            Self::Nxio => f.write_str("NFSERR_NXIO"),
            Self::Acces => f.write_str("NFSERR_ACCES"),
            Self::Exist => f.write_str("NFSERR_EXIST"),
            Self::NoDev => f.write_str("NFSERR_NODEV"),
            Self::NotDir => f.write_str("NFSERR_NOTDIR"),
            Self::IsDir => f.write_str("NFSERR_ISDIR"),
            Self::Fbig => f.write_str("NFSERR_FBIG"),
            Self::NoSpc => f.write_str("NFSERR_NOSPC"),
            Self::Rofs => f.write_str("NFSERR_ROFS"),
            Self::NameTooLong => f.write_str("NFSERR_NAMETOOLONG"),
            Self::NotEmpty => f.write_str("NFSERR_NOTEMPTY"),
            Self::Dquot => f.write_str("NFSERR_DQUOT"),
            Self::Stale => f.write_str("NFSERR_STALE"),
            Self::WFlush => f.write_str("NFSERR_WFLUSH"),
            Self::Unknown(code) => write!(f, "NFSERR_UNKNOWN({code})"),
        }
    }
}

/// NFSv2 file type.
///
/// RFC 1094 S2.3.3 defines values 0-5. The Linux kernel header (nfs2.h)
/// extends these with NF2SOCK (6), NF2BAD (7), and NF2FIFO (8), which a
/// real Linux knfsd v2 server returns for socket and FIFO inodes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
#[repr(u32)]
pub enum FType {
    /// Non-file (used for error cases). NFNON = 0.
    NonFile = 0,
    /// Regular file. NFREG = 1.
    Regular = 1,
    /// Directory. NFDIR = 2.
    Directory = 2,
    /// Block device. NFBLK = 3.
    Block = 3,
    /// Character device. NFCHR = 4.
    Character = 4,
    /// Symbolic link. NFLNK = 5.
    Symlink = 5,
    /// Unix domain socket. NF2SOCK = 6 (Linux extension, not in RFC 1094).
    Socket = 6,
    /// Bad file type. NF2BAD = 7 (Linux extension).
    Bad = 7,
    /// Named pipe (FIFO). NF2FIFO = 8 (Linux extension).
    Fifo = 8,
    /// Unrecognised file type from the wire.
    Unknown(u32),
}

impl FType {
    /// Decode from wire u32, preserving unknown values.
    #[must_use]
    pub const fn from_u32(v: u32) -> Self {
        match v {
            0 => Self::NonFile,
            1 => Self::Regular,
            2 => Self::Directory,
            3 => Self::Block,
            4 => Self::Character,
            5 => Self::Symlink,
            6 => Self::Socket,
            7 => Self::Bad,
            8 => Self::Fifo,
            _ => Self::Unknown(v),
        }
    }

    const fn to_u32(self) -> u32 {
        match self {
            Self::NonFile => 0,
            Self::Regular => 1,
            Self::Directory => 2,
            Self::Block => 3,
            Self::Character => 4,
            Self::Symlink => 5,
            Self::Socket => 6,
            Self::Bad => 7,
            Self::Fifo => 8,
            Self::Unknown(v) => v,
        }
    }
}

impl Pack for FType {
    fn packed_size(&self) -> usize {
        4
    }
    fn pack(&self, out: &mut impl Write) -> onc_xdr::Result<usize> {
        self.to_u32().pack(out)
    }
}

impl Unpack for FType {
    fn unpack(input: &mut impl Read) -> onc_xdr::Result<(Self, usize)> {
        let (v, n) = u32::unpack(input)?;
        Ok((Self::from_u32(v), n))
    }
}

// --- Fixed 32-byte file handle ---

/// NFSv2 fixed-size file handle (32 bytes, no length prefix).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
    fn pack(&self, out: &mut impl Write) -> onc_xdr::Result<usize> {
        out.write_all(&self.0).map_err(onc_xdr::Error::Io)?;
        Ok(FHSIZE)
    }
}

impl Unpack for Nfs2FileHandle {
    fn unpack(input: &mut impl Read) -> onc_xdr::Result<(Self, usize)> {
        let mut buf = [0u8; FHSIZE];
        input.read_exact(&mut buf).map_err(onc_xdr::Error::Io)?;
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
    fn pack(&self, out: &mut impl Write) -> onc_xdr::Result<usize> {
        Ok(self.seconds.pack(out)? + self.useconds.pack(out)?)
    }
}

impl Unpack for Timeval {
    fn unpack(input: &mut impl Read) -> onc_xdr::Result<(Self, usize)> {
        let (seconds, n1) = u32::unpack(input)?;
        let (useconds, n2) = u32::unpack(input)?;
        Ok((Self { seconds, useconds }, n1 + n2))
    }
}

// --- File attributes ---

/// NFSv2 file attributes (RFC 1094 S2.3.5).
/// 32-bit sizes (vs v3's 64-bit), timeval timestamps.
#[derive(Debug, Clone, Copy)]
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
    fn pack(&self, out: &mut impl Write) -> onc_xdr::Result<usize> {
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
    fn unpack(input: &mut impl Read) -> onc_xdr::Result<(Self, usize)> {
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
#[derive(Debug, Clone, Copy)]
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
    fn pack(&self, out: &mut impl Write) -> onc_xdr::Result<usize> {
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
    fn unpack(input: &mut impl Read) -> onc_xdr::Result<(Self, usize)> {
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
        FHSIZE + onc_xdr::string_packed_size(&self.name)
    }
    fn pack(&self, out: &mut impl Write) -> onc_xdr::Result<usize> {
        Ok(self.dir.pack(out)? + onc_xdr::pack_string(&self.name, out)?)
    }
}

impl Unpack for DirOpArgs {
    fn unpack(input: &mut impl Read) -> onc_xdr::Result<(Self, usize)> {
        let (dir, n0) = Nfs2FileHandle::unpack(input)?;
        let (name, n1) = onc_xdr::unpack_string(input)?;
        Ok((Self { dir, name }, n0 + n1))
    }
}

/// Result of LOOKUP or CREATE.
#[derive(Debug, Clone)]
pub struct DirOpRes {
    /// Status code.
    pub status: Nfs2Stat,
    /// New file handle (valid only if `status == Ok`).
    pub handle: Nfs2FileHandle,
    /// Attributes of the file (valid only if `status == Ok`).
    pub attrs: Nfs2FileAttr,
}

impl Pack for DirOpRes {
    fn packed_size(&self) -> usize {
        if self.status == Nfs2Stat::Ok { 4 + FHSIZE + self.attrs.packed_size() } else { 4 }
    }
    fn pack(&self, out: &mut impl Write) -> onc_xdr::Result<usize> {
        let n = self.status.pack(out)?;
        if self.status != Nfs2Stat::Ok {
            return Ok(n);
        }
        Ok(n + self.handle.pack(out)? + self.attrs.pack(out)?)
    }
}

impl Unpack for DirOpRes {
    /// RFC 1094  --  diropres is an XDR union: on error status, only the status
    /// discriminant is present (no handle or attrs follow).
    fn unpack(input: &mut impl Read) -> onc_xdr::Result<(Self, usize)> {
        let (status, n0) = Nfs2Stat::unpack(input)?;
        if status != Nfs2Stat::Ok {
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
    pub status: Nfs2Stat,
    /// File attributes (valid only if `status == Ok`).
    pub attrs: Nfs2FileAttr,
}

impl Unpack for AttrStatRes {
    /// RFC 1094  --  attrstat is an XDR union: on error status, only the status
    /// discriminant is present (no attrs follow).
    fn unpack(input: &mut impl Read) -> onc_xdr::Result<(Self, usize)> {
        let (status, n0) = Nfs2Stat::unpack(input)?;
        if status != Nfs2Stat::Ok {
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
    fn pack(&self, out: &mut impl Write) -> onc_xdr::Result<usize> {
        Ok(self.file.pack(out)? + self.offset.pack(out)? + self.count.pack(out)? + self.totalcount.pack(out)?)
    }
}

impl Unpack for ReadArgs {
    fn unpack(input: &mut impl Read) -> onc_xdr::Result<(Self, usize)> {
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
    pub status: Nfs2Stat,
    /// Current file attributes.
    pub attrs: Nfs2FileAttr,
    /// Data read from the file.
    pub data: Vec<u8>,
}

impl Unpack for ReadRes {
    /// RFC 1094  --  readres is an XDR union: on error status, only the status
    /// discriminant is present (no attrs or data follow).
    fn unpack(input: &mut impl Read) -> onc_xdr::Result<(Self, usize)> {
        let (status, n0) = Nfs2Stat::unpack(input)?;
        if status != Nfs2Stat::Ok {
            return Ok((Self { status, attrs: Nfs2FileAttr::zeroed(), data: Vec::new() }, n0));
        }
        let (attrs, n1) = Nfs2FileAttr::unpack(input)?;
        // Data is XDR opaque: 4-byte length then raw bytes with padding
        let (data_len, n2) = u32::unpack(input)?;
        let data_len = data_len as usize;
        // Do not pre-size from the untrusted length; read bounded by real bytes.
        let data = onc_xdr::read_bytes(input, data_len)?;
        let pad = (4 - (data_len % 4)) % 4;
        onc_xdr::skip_pad(input, pad)?;
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
    fn pack(&self, out: &mut impl Write) -> onc_xdr::Result<usize> {
        let mut n = self.file.pack(out)?;
        n += self.beginoffset.pack(out)?;
        n += self.offset.pack(out)?;
        n += self.totalcount.pack(out)?;
        // Write data as XDR opaque
        let data_len = u32::try_from(self.data.len()).map_err(|_| onc_xdr::Error::ObjectTooLarge(self.data.len()))?;
        n += data_len.pack(out)?;
        out.write_all(&self.data).map_err(onc_xdr::Error::Io)?;
        n += self.data.len();
        let pad = (4 - (self.data.len() % 4)) % 4;
        onc_xdr::write_pad(out, pad)?;
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
    fn pack(&self, out: &mut impl Write) -> onc_xdr::Result<usize> {
        Ok(self.dir.pack(out)? + self.cookie.pack(out)? + self.count.pack(out)?)
    }
}

// --- Tests ---

#[cfg(test)]
mod tests {
    #![expect(clippy::pedantic, clippy::cast_possible_truncation, reason = "unit test  --  lints are suppressed per project policy")]
    use super::*;
    use std::io::Cursor;

    #[test]
    fn nfsstat_from_u32_maps_all_known_codes() {
        assert_eq!(Nfs2Stat::from_u32(0), Nfs2Stat::Ok);
        assert_eq!(Nfs2Stat::from_u32(1), Nfs2Stat::Perm);
        assert_eq!(Nfs2Stat::from_u32(2), Nfs2Stat::NoEnt);
        assert_eq!(Nfs2Stat::from_u32(5), Nfs2Stat::Io);
        assert_eq!(Nfs2Stat::from_u32(6), Nfs2Stat::Nxio);
        assert_eq!(Nfs2Stat::from_u32(13), Nfs2Stat::Acces);
        assert_eq!(Nfs2Stat::from_u32(17), Nfs2Stat::Exist);
        assert_eq!(Nfs2Stat::from_u32(19), Nfs2Stat::NoDev);
        assert_eq!(Nfs2Stat::from_u32(20), Nfs2Stat::NotDir);
        assert_eq!(Nfs2Stat::from_u32(21), Nfs2Stat::IsDir);
        assert_eq!(Nfs2Stat::from_u32(27), Nfs2Stat::Fbig);
        assert_eq!(Nfs2Stat::from_u32(28), Nfs2Stat::NoSpc);
        assert_eq!(Nfs2Stat::from_u32(30), Nfs2Stat::Rofs);
        assert_eq!(Nfs2Stat::from_u32(63), Nfs2Stat::NameTooLong);
        assert_eq!(Nfs2Stat::from_u32(66), Nfs2Stat::NotEmpty);
        assert_eq!(Nfs2Stat::from_u32(69), Nfs2Stat::Dquot);
        assert_eq!(Nfs2Stat::from_u32(70), Nfs2Stat::Stale);
    }

    #[test]
    fn nfsstat_from_u32_unknown_preserves_raw_value() {
        assert_eq!(Nfs2Stat::from_u32(9999), Nfs2Stat::Unknown(9999));
        assert_eq!(Nfs2Stat::from_u32(42), Nfs2Stat::Unknown(42));
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
        _ = fh.pack(&mut buf).unwrap();
        assert_eq!(buf.len(), 32);
        let (decoded, n) = Nfs2FileHandle::unpack(&mut Cursor::new(&buf)).unwrap();
        assert_eq!(n, 32);
        assert_eq!(decoded, fh);
    }

    #[test]
    fn diropres_unpack_ok_branch_decodes_handle_and_attrs() {
        // Build a DirOpRes with status=Ok, then a 32-byte handle, then 68 bytes of attrs.
        let mut wire: Vec<u8> = Vec::new();
        _ = Nfs2Stat::Ok.pack(&mut wire).unwrap();
        let fh = Nfs2FileHandle::from_bytes(&[0x42; 32]);
        _ = fh.pack(&mut wire).unwrap();
        // Minimal attrs: ftype=Regular(1), then 10 u32 zeros, then 3 timevals of zeros
        _ = FType::Regular.pack(&mut wire).unwrap();
        for _ in 0..10 {
            _ = 0u32.pack(&mut wire).unwrap();
        }
        for _ in 0..6 {
            _ = 0u32.pack(&mut wire).unwrap();
        }
        let (res, _) = DirOpRes::unpack(&mut Cursor::new(&wire)).unwrap();
        assert_eq!(res.status, Nfs2Stat::Ok);
        assert_eq!(res.handle, fh);
        assert_eq!(res.attrs.ftype, FType::Regular);
    }

    #[test]
    fn diropres_unpack_error_branch_returns_zeroed() {
        let mut wire: Vec<u8> = Vec::new();
        _ = Nfs2Stat::Acces.pack(&mut wire).unwrap();
        // No handle or attrs follow the error status.
        let (res, n) = DirOpRes::unpack(&mut Cursor::new(&wire)).unwrap();
        assert_eq!(res.status, Nfs2Stat::Acces);
        assert_eq!(res.handle, Nfs2FileHandle([0u8; FHSIZE]));
        assert_eq!(res.attrs.ftype, FType::NonFile);
        assert_eq!(n, 4);
    }

    #[test]
    fn attrstatres_unpack_ok_branch() {
        let mut wire: Vec<u8> = Vec::new();
        _ = Nfs2Stat::Ok.pack(&mut wire).unwrap();
        let attr =
            Nfs2FileAttr { ftype: FType::Directory, mode: 0o755, nlink: 2, uid: 0, gid: 0, size: 4096, blocksize: 4096, rdev: 0, blocks: 8, fsid: 1, fileid: 2, atime: Timeval { seconds: 100, useconds: 0 }, mtime: Timeval { seconds: 200, useconds: 0 }, ctime: Timeval { seconds: 300, useconds: 0 } };
        _ = attr.pack(&mut wire).unwrap();
        let (res, _) = AttrStatRes::unpack(&mut Cursor::new(&wire)).unwrap();
        assert_eq!(res.status, Nfs2Stat::Ok);
        assert_eq!(res.attrs.ftype, FType::Directory);
        assert_eq!(res.attrs.mode, 0o755);
    }

    #[test]
    fn readres_unpack_error_branch() {
        let mut wire: Vec<u8> = Vec::new();
        _ = Nfs2Stat::Perm.pack(&mut wire).unwrap();
        let (res, n) = ReadRes::unpack(&mut Cursor::new(&wire)).unwrap();
        assert_eq!(res.status, Nfs2Stat::Perm);
        assert!(res.data.is_empty());
        assert_eq!(n, 4);
    }

    #[test]
    fn statfsres_unpack_error_branch() {
        let mut wire: Vec<u8> = Vec::new();
        _ = Nfs2Stat::Stale.pack(&mut wire).unwrap();
        let (res, n) = StatFsRes::unpack(&mut Cursor::new(&wire)).unwrap();
        assert_eq!(res.status, Nfs2Stat::Stale);
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
        assert_eq!(FType::from_u32(99), FType::Unknown(99));
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

    // --- RFC 1094 S2.3.1: Nfs2Stat WFlush ---

    #[test]
    fn nfsstat_wflush_99_maps_correctly() {
        // RFC 1094 S2.3.1: NFSERR_WFLUSH = 99, server-only advisory status.
        assert_eq!(Nfs2Stat::from_u32(99), Nfs2Stat::WFlush);
        assert_eq!(Nfs2Stat::WFlush.to_u32(), 99);
    }

    #[test]
    fn nfsstat_round_trips_all_known_values() {
        // RFC 1094 S2.3.1: pack -> unpack cycle for every defined status code.
        let all: [(u32, Nfs2Stat); 18] = [
            (0, Nfs2Stat::Ok),
            (1, Nfs2Stat::Perm),
            (2, Nfs2Stat::NoEnt),
            (5, Nfs2Stat::Io),
            (6, Nfs2Stat::Nxio),
            (13, Nfs2Stat::Acces),
            (17, Nfs2Stat::Exist),
            (19, Nfs2Stat::NoDev),
            (20, Nfs2Stat::NotDir),
            (21, Nfs2Stat::IsDir),
            (27, Nfs2Stat::Fbig),
            (28, Nfs2Stat::NoSpc),
            (30, Nfs2Stat::Rofs),
            (63, Nfs2Stat::NameTooLong),
            (66, Nfs2Stat::NotEmpty),
            (69, Nfs2Stat::Dquot),
            (70, Nfs2Stat::Stale),
            (99, Nfs2Stat::WFlush),
        ];
        for (wire_val, expected) in &all {
            let mut buf = Vec::new();
            _ = expected.pack(&mut buf).unwrap();
            assert_eq!(buf.len(), 4);
            // Wire encoding is big-endian u32.
            let encoded = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
            assert_eq!(encoded, *wire_val, "wire encoding mismatch for {expected:?}");
            let (decoded, n) = Nfs2Stat::unpack(&mut Cursor::new(&buf)).unwrap();
            assert_eq!(n, 4);
            assert_eq!(decoded, *expected, "round-trip failed for wire value {wire_val}");
        }
    }

    #[test]
    fn nfsstat_unknown_preserves_raw_code() {
        // Unrecognized wire values are preserved as Unknown(raw).
        for bogus in [3, 4, 7, 8, 10, 42, 100, 255, 0xDEAD, u32::MAX] {
            assert_eq!(Nfs2Stat::from_u32(bogus), Nfs2Stat::Unknown(bogus), "unknown status {bogus} must become Unknown");
        }
    }

    // --- RFC 1094 S2.3.3: FType round-trip ---

    #[test]
    fn ftype_all_9_variants_round_trip() {
        // RFC 1094 S2.3.3 values 0-5; Linux kernel extensions 6 (socket),
        // 7 (bad), 8 (FIFO) from nfs2.h.
        let all: [(u32, FType); 9] = [(0, FType::NonFile), (1, FType::Regular), (2, FType::Directory), (3, FType::Block), (4, FType::Character), (5, FType::Symlink), (6, FType::Socket), (7, FType::Bad), (8, FType::Fifo)];
        for (wire_val, expected) in &all {
            let mut buf = Vec::new();
            _ = expected.pack(&mut buf).unwrap();
            assert_eq!(buf.len(), 4);
            let encoded = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
            assert_eq!(encoded, *wire_val, "wire encoding mismatch for {expected:?}");
            let (decoded, n) = FType::unpack(&mut Cursor::new(&buf)).unwrap();
            assert_eq!(n, 4);
            assert_eq!(decoded, *expected, "round-trip failed for wire value {wire_val}");
        }
    }

    // --- RFC 1094 S2.3.3: file handle is fixed 32 bytes, no length prefix ---

    #[test]
    fn nfs2_file_handle_wire_has_no_length_prefix() {
        // RFC 1094 S2.3.3: "The file handle is 32 bytes" -- fixed opaque,
        // no XDR length prefix. First byte on wire must be handle data.
        let fh = Nfs2FileHandle::from_bytes(&[0xDE, 0xAD, 0xBE, 0xEF]);
        let mut buf = Vec::new();
        _ = fh.pack(&mut buf).unwrap();
        assert_eq!(buf.len(), FHSIZE, "must be exactly 32 bytes, not 36");
        // First 4 bytes are handle data, NOT a length field.
        assert_eq!(buf[0], 0xDE);
        assert_eq!(buf[1], 0xAD);
        assert_eq!(buf[2], 0xBE);
        assert_eq!(buf[3], 0xEF);
    }

    // --- RFC 1094 S2.3.4: Timeval round-trip ---

    #[test]
    fn timeval_round_trip_preserves_values() {
        // RFC 1094 S2.3.4: timeval = seconds(u32) + useconds(u32).
        let tv = Timeval { seconds: 1_700_000_000, useconds: 123_456 };
        let mut buf = Vec::new();
        _ = tv.pack(&mut buf).unwrap();
        assert_eq!(buf.len(), 8);
        let (decoded, n) = Timeval::unpack(&mut Cursor::new(&buf)).unwrap();
        assert_eq!(n, 8);
        assert_eq!(decoded.seconds, 1_700_000_000);
        assert_eq!(decoded.useconds, 123_456);
    }

    // --- RFC 1094 S2.3.6: SATTR_UNCHANGED sentinel ---

    #[test]
    fn sattr_unchanged_sentinel_is_minus_one() {
        // RFC 1094 S2.3.6: fields set to -1 (0xFFFFFFFF as u32) mean "don't change".
        assert_eq!(SATTR_UNCHANGED, 0xFFFF_FFFF);
        assert_eq!(SATTR_UNCHANGED, u32::MAX);
        // Verify the sentinel survives a pack/unpack cycle through Nfs2SetAttr.
        let sa = Nfs2SetAttr { mode: SATTR_UNCHANGED, uid: SATTR_UNCHANGED, gid: SATTR_UNCHANGED, size: SATTR_UNCHANGED, atime: Timeval { seconds: SATTR_UNCHANGED, useconds: SATTR_UNCHANGED }, mtime: Timeval { seconds: SATTR_UNCHANGED, useconds: SATTR_UNCHANGED } };
        let mut buf = Vec::new();
        _ = sa.pack(&mut buf).unwrap();
        let (decoded, _) = Nfs2SetAttr::unpack(&mut Cursor::new(&buf)).unwrap();
        assert_eq!(decoded.mode, SATTR_UNCHANGED);
        assert_eq!(decoded.uid, SATTR_UNCHANGED);
        assert_eq!(decoded.gid, SATTR_UNCHANGED);
        assert_eq!(decoded.size, SATTR_UNCHANGED);
    }

    // --- XDR union encoding: DirOpRes ---

    #[test]
    fn diropres_pack_error_writes_only_4_bytes() {
        // RFC 1094 diropres union: error arm has only the status discriminant.
        let res = DirOpRes { status: Nfs2Stat::Acces, handle: Nfs2FileHandle([0u8; FHSIZE]), attrs: Nfs2FileAttr::zeroed() };
        let mut buf = Vec::new();
        let n = res.pack(&mut buf).unwrap();
        assert_eq!(n, 4);
        assert_eq!(buf.len(), 4);
    }

    #[test]
    fn diropres_pack_ok_writes_104_bytes() {
        // RFC 1094 diropres union: success arm = status(4) + fhandle(32) + fattr(68) = 104.
        let res = DirOpRes {
            status: Nfs2Stat::Ok,
            handle: Nfs2FileHandle::from_bytes(&[0x42; 32]),
            attrs: Nfs2FileAttr {
                ftype: FType::Regular,
                mode: 0o644,
                nlink: 1,
                uid: 1000,
                gid: 1000,
                size: 4096,
                blocksize: 4096,
                rdev: 0,
                blocks: 8,
                fsid: 1,
                fileid: 42,
                atime: Timeval { seconds: 0, useconds: 0 },
                mtime: Timeval { seconds: 0, useconds: 0 },
                ctime: Timeval { seconds: 0, useconds: 0 },
            },
        };
        let mut buf = Vec::new();
        let n = res.pack(&mut buf).unwrap();
        assert_eq!(n, 104, "status(4) + fhandle(32) + fattr(68) = 104");
        assert_eq!(buf.len(), 104);
    }

    // --- XDR union encoding: AttrStatRes ---

    #[test]
    fn attrstatres_unpack_error_reads_only_4_bytes() {
        // RFC 1094 attrstat union: error arm has only the status discriminant.
        let mut wire: Vec<u8> = Vec::new();
        _ = Nfs2Stat::NoEnt.pack(&mut wire).unwrap();
        // Append trailing garbage to prove only 4 bytes are consumed.
        wire.extend_from_slice(&[0xFF; 100]);
        let (res, n) = AttrStatRes::unpack(&mut Cursor::new(&wire)).unwrap();
        assert_eq!(n, 4);
        assert_eq!(res.status, Nfs2Stat::NoEnt);
        assert_eq!(res.attrs.ftype, FType::NonFile);
    }

    // --- RFC 1094 S2.2.6: ReadArgs wire size ---

    #[test]
    fn read_args_pack_is_44_bytes() {
        // fhandle(32) + offset(4) + count(4) + totalcount(4) = 44 bytes.
        let args = ReadArgs { file: Nfs2FileHandle::from_bytes(&[0; 32]), offset: 0x1000, count: 8192, totalcount: 0 };
        let mut buf = Vec::new();
        let n = args.pack(&mut buf).unwrap();
        assert_eq!(n, 44, "fhandle(32) + offset(4) + count(4) + totalcount(4) = 44");
        assert_eq!(buf.len(), 44);
    }

    // --- RFC 1094 S2.2: procedure number table ---

    #[test]
    fn procedure_numbers_match_rfc1094() {
        // RFC 1094 S2.2: the 18 NFS procedures are numbered 0 through 17.
        use proc::*;
        let all = [
            (NFSPROC_NULL, 0),
            (NFSPROC_GETATTR, 1),
            (NFSPROC_SETATTR, 2),
            (NFSPROC_ROOT, 3),
            (NFSPROC_LOOKUP, 4),
            (NFSPROC_READLINK, 5),
            (NFSPROC_READ, 6),
            (NFSPROC_WRITECACHE, 7),
            (NFSPROC_WRITE, 8),
            (NFSPROC_CREATE, 9),
            (NFSPROC_REMOVE, 10),
            (NFSPROC_RENAME, 11),
            (NFSPROC_LINK, 12),
            (NFSPROC_SYMLINK, 13),
            (NFSPROC_MKDIR, 14),
            (NFSPROC_RMDIR, 15),
            (NFSPROC_READDIR, 16),
            (NFSPROC_STATFS, 17),
        ];
        for (i, &(actual, expected)) in all.iter().enumerate() {
            assert_eq!(actual, expected, "procedure {i} has wrong number");
        }
        // Verify the sequence is contiguous 0..=17.
        for (i, &(proc_num, _)) in all.iter().enumerate() {
            assert_eq!(proc_num, i as u32, "procedure sequence broken at index {i}");
        }
    }

    // =========================================================================
    // Golden vector tests -- NFSv2 (RFC 1094)
    // =========================================================================

    /// Golden vector: Nfs2FileAttr for a regular file (RFC 1094 S2.3.5).
    ///
    /// Regular file, mode 0644, uid/gid 1000, size 4096, inode 42.
    /// 68 bytes: 11 u32 fields (44) + 3 timevals (24).
    #[test]
    fn golden_nfs2_fattr_regular_file() {
        #[rustfmt::skip]
        const GOLDEN: [u8; 68] = [
            0x00, 0x00, 0x00, 0x01, // ftype = Regular (1)
            0x00, 0x00, 0x01, 0xA4, // mode = 0o644 = 420
            0x00, 0x00, 0x00, 0x01, // nlink = 1
            0x00, 0x00, 0x03, 0xE8, // uid = 1000
            0x00, 0x00, 0x03, 0xE8, // gid = 1000
            0x00, 0x00, 0x10, 0x00, // size = 4096
            0x00, 0x00, 0x10, 0x00, // blocksize = 4096
            0x00, 0x00, 0x00, 0x00, // rdev = 0
            0x00, 0x00, 0x00, 0x08, // blocks = 8
            0x00, 0x00, 0x00, 0x01, // fsid = 1
            0x00, 0x00, 0x00, 0x2A, // fileid = 42
            0x00, 0x00, 0x00, 0x64, // atime.seconds = 100
            0x00, 0x00, 0x00, 0x00, // atime.useconds = 0
            0x00, 0x00, 0x00, 0xC8, // mtime.seconds = 200
            0x00, 0x00, 0x00, 0x00, // mtime.useconds = 0
            0x00, 0x00, 0x01, 0x2C, // ctime.seconds = 300
            0x00, 0x00, 0x00, 0x00, // ctime.useconds = 0
        ];

        // Unpack and verify every field.
        let (attr, consumed) = Nfs2FileAttr::unpack(&mut Cursor::new(&GOLDEN[..])).unwrap();
        assert_eq!(consumed, 68);
        assert_eq!(attr.ftype, FType::Regular);
        assert_eq!(attr.mode, 0o644);
        assert_eq!(attr.nlink, 1);
        assert_eq!(attr.uid, 1000);
        assert_eq!(attr.gid, 1000);
        assert_eq!(attr.size, 4096);
        assert_eq!(attr.blocksize, 4096);
        assert_eq!(attr.rdev, 0);
        assert_eq!(attr.blocks, 8);
        assert_eq!(attr.fsid, 1);
        assert_eq!(attr.fileid, 42);
        assert_eq!(attr.atime.seconds, 100);
        assert_eq!(attr.atime.useconds, 0);
        assert_eq!(attr.mtime.seconds, 200);
        assert_eq!(attr.mtime.useconds, 0);
        assert_eq!(attr.ctime.seconds, 300);
        assert_eq!(attr.ctime.useconds, 0);

        // Re-pack and verify exact byte equality.
        let mut repacked = Vec::new();
        _ = attr.pack(&mut repacked).unwrap();
        assert_eq!(repacked, GOLDEN);
    }

    /// Golden vector: DirOpRes error branch (RFC 1094 diropres union).
    ///
    /// NFSERR_ACCES = 13. Error arm carries only the 4-byte status discriminant.
    #[test]
    fn golden_nfs2_diropres_error() {
        const GOLDEN: [u8; 4] = [0x00, 0x00, 0x00, 0x0D]; // NFSERR_ACCES = 13

        let (res, consumed) = DirOpRes::unpack(&mut Cursor::new(&GOLDEN[..])).unwrap();
        assert_eq!(consumed, 4);
        assert_eq!(res.status, Nfs2Stat::Acces);
        assert_eq!(res.handle, Nfs2FileHandle([0u8; FHSIZE]));

        // Re-pack the error branch.
        let mut repacked = Vec::new();
        _ = res.pack(&mut repacked).unwrap();
        assert_eq!(repacked, GOLDEN);
    }

    /// Golden vector: Nfs2FileHandle (RFC 1094 S2.3.3).
    ///
    /// Fixed 32 bytes, no length prefix. First 4 bytes are handle data, not a
    /// length field -- this catches a codec that incorrectly adds a prefix.
    #[test]
    fn golden_nfs2_file_handle() {
        // A 32-byte handle with a recognizable pattern.
        let mut golden = [0u8; 32];
        golden[0] = 0x01;
        golden[1] = 0x00;
        golden[2] = 0x07;
        golden[3] = 0x00;
        // Bytes 4..31 stay 0x00, byte 31 = 0xFF.
        golden[31] = 0xFF;

        let (fh, consumed) = Nfs2FileHandle::unpack(&mut Cursor::new(&golden[..])).unwrap();
        assert_eq!(consumed, 32);
        assert_eq!(fh.0[0], 0x01);
        assert_eq!(fh.0[2], 0x07);
        assert_eq!(fh.0[31], 0xFF);

        let mut repacked = Vec::new();
        _ = fh.pack(&mut repacked).unwrap();
        assert_eq!(repacked.as_slice(), &golden[..]);
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
    fn unpack(input: &mut impl Read) -> onc_xdr::Result<(Self, usize)> {
        let (fileid, n0) = u32::unpack(input)?;
        let (name, n1) = onc_xdr::unpack_string(input)?;
        let (cookie, n2) = u32::unpack(input)?;
        Ok((Self { fileid, name, cookie }, n0 + n1 + n2))
    }
}

// --- STATFS ---

/// Result of STATFS.
#[derive(Debug, Clone, Copy)]
pub struct StatFsRes {
    /// Status code.
    pub status: Nfs2Stat,
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
    fn unpack(input: &mut impl Read) -> onc_xdr::Result<(Self, usize)> {
        let (status, n0) = Nfs2Stat::unpack(input)?;
        if status != Nfs2Stat::Ok {
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

// --- Compound argument and result types (RFC 1094) ---
//
// Several NFSv2 procedures take two or three concatenated structures with no
// enclosing tag, so each combination needs its own type. They live here with
// the rest of the wire format rather than beside the client that happens to
// use them.

/// Wire-encodes fhandle followed by sattr (for SETATTR).
#[derive(Debug)]
pub struct sattrargs {
    pub fh: Nfs2FileHandle,
    pub attrs: Nfs2SetAttr,
}

impl Pack for sattrargs {
    fn packed_size(&self) -> usize {
        self.fh.packed_size() + self.attrs.packed_size()
    }
    fn pack(&self, out: &mut impl Write) -> onc_xdr::Result<usize> {
        Ok(self.fh.pack(out)? + self.attrs.pack(out)?)
    }
}

/// Wire-encodes diropargs followed by sattr (for CREATE/MKDIR).
#[derive(Debug)]
pub struct createargs {
    pub args: DirOpArgs,
    pub attrs: Nfs2SetAttr,
}

impl Pack for createargs {
    fn packed_size(&self) -> usize {
        self.args.packed_size() + self.attrs.packed_size()
    }
    fn pack(&self, out: &mut impl Write) -> onc_xdr::Result<usize> {
        Ok(self.args.pack(out)? + self.attrs.pack(out)?)
    }
}

/// Wire-encodes two diropargs (for RENAME).
#[derive(Debug)]
pub struct renameargs {
    pub from: DirOpArgs,
    pub to: DirOpArgs,
}

impl Pack for renameargs {
    fn packed_size(&self) -> usize {
        self.from.packed_size() + self.to.packed_size()
    }
    fn pack(&self, out: &mut impl Write) -> onc_xdr::Result<usize> {
        Ok(self.from.pack(out)? + self.to.pack(out)?)
    }
}

/// Wire-encodes fhandle followed by diropargs (for LINK).
#[derive(Debug)]
pub struct linkargs {
    pub fh: Nfs2FileHandle,
    pub to: DirOpArgs,
}

impl Pack for linkargs {
    fn packed_size(&self) -> usize {
        self.fh.packed_size() + self.to.packed_size()
    }
    fn pack(&self, out: &mut impl Write) -> onc_xdr::Result<usize> {
        Ok(self.fh.pack(out)? + self.to.pack(out)?)
    }
}

/// Wire-encodes diropargs + target string + sattr (for SYMLINK).
#[derive(Debug)]
pub struct symlinkargs {
    pub from: DirOpArgs,
    pub target: String,
    pub attrs: Nfs2SetAttr,
}

impl Pack for symlinkargs {
    fn packed_size(&self) -> usize {
        self.from.packed_size() + onc_xdr::string_packed_size(&self.target) + self.attrs.packed_size()
    }
    fn pack(&self, out: &mut impl Write) -> onc_xdr::Result<usize> {
        Ok(self.from.pack(out)? + onc_xdr::pack_string(&self.target, out)? + self.attrs.pack(out)?)
    }
}

/// READLINK result: status + path string.
#[derive(Debug)]
pub struct readlinkres {
    pub status: Nfs2Stat,
    pub data: String,
}

impl Unpack for readlinkres {
    /// RFC 1094  --  readlinkres is an XDR union: on error status, only the
    /// status discriminant is present (no path string follows).
    fn unpack(input: &mut impl Read) -> onc_xdr::Result<(Self, usize)> {
        let (status, n0) = Nfs2Stat::unpack(input)?;
        if status != Nfs2Stat::Ok {
            return Ok((Self { status, data: String::new() }, n0));
        }
        let (data, n1) = onc_xdr::unpack_string(input)?;
        Ok((Self { status, data }, n0 + n1))
    }
}

/// READDIR result: status + entry list + eof flag (RFC 1094 sec 2.2.17).
#[derive(Debug)]
pub struct readdirres {
    pub status: Nfs2Stat,
    pub entries: Vec<ReaddirEntry>,
    /// Whether the server has returned all remaining entries.
    pub eof: bool,
}

impl Unpack for readdirres {
    /// RFC 1094  --  readdirres is an XDR union: on error status, only the
    /// status discriminant is present (no entry list or EOF flag follows).
    fn unpack(input: &mut impl Read) -> onc_xdr::Result<(Self, usize)> {
        let (status, mut n) = Nfs2Stat::unpack(input)?;
        if status != Nfs2Stat::Ok {
            return Ok((Self { status, entries: Vec::new(), eof: true }, n));
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
        // EOF flag (RFC 1094 sec 2.2.17)
        let (eof, dn) = bool::unpack(input)?;
        n += dn;
        Ok((Self { status, entries, eof }, n))
    }
}
