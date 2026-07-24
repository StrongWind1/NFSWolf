//! Domain types  --  ergonomic wrappers over the raw NFSv3 wire format.
//!
//! The `wire` module provides the raw XDR types (nfs_fh3, fattr3, nfsstat3).
//! This module provides nfswolf-friendly wrappers with hex encoding,
//! display formatting, and domain methods.

// Struct fields and enum variants are wire-protocol values; individual
// field docs would be redundant with the module-level RFC citations.
// Toolkit API  --  not all items are used in currently-implemented phases.
use crate::wire::{fattr3, ftype3, nfs_fh3};
use nfswolf_xdr::Opaque;

/// Error returned when a hex string is not valid (odd length or non-hex chars).
///
/// Replaces `hex::FromHexError` -- the hex crate was the only dependency that
/// used this type.  Both encode and decode are trivially implementable with
/// stdlib, so the crate is not needed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HexError;

impl std::fmt::Display for HexError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("invalid hex string (odd length or non-hex character)")
    }
}

impl std::error::Error for HexError {}

/// Opaque file handle  --  identifies a file/directory on the server.
/// An opaque NFSv3 file handle -- at most 64 bytes (RFC 1813 sec. 2.3.1).
///
/// The bytes are meaningful only to the server, but they are also a bearer
/// token: a handle works under any credential, so possession alone grants
/// whatever access the object allows (RFC 1813 sec. 2.6).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FileHandle(pub Vec<u8>);

impl FileHandle {
    /// Build a handle from raw bytes.
    #[must_use]
    pub fn from_bytes(data: &[u8]) -> Self {
        Self(data.to_vec())
    }

    /// Borrow the raw bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Render as lowercase hex, the form the CLI accepts and prints.
    #[must_use]
    pub fn to_hex(&self) -> String {
        // Two lowercase hex chars per byte -- no crate needed for this.
        self.0.iter().fold(String::with_capacity(self.0.len() * 2), |mut s, b| {
            use std::fmt::Write as _;
            let _ = write!(s, "{b:02x}");
            s
        })
    }

    /// Decode a lowercase or uppercase hex string (optional 0x prefix) into a handle.
    pub fn from_hex(s: &str) -> Result<Self, HexError> {
        let s = s.strip_prefix("0x").unwrap_or(s);
        if !s.len().is_multiple_of(2) {
            return Err(HexError);
        }
        let bytes = (0..s.len()).step_by(2).map(|i| u8::from_str_radix(s.get(i..i + 2).ok_or(HexError)?, 16).map_err(|_| HexError)).collect::<Result<Vec<u8>, HexError>>()?;
        Ok(Self(bytes))
    }

    /// Length in bytes.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the handle carries no bytes.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Convert to the wire type.
    #[must_use]
    pub fn to_nfs_fh3(&self) -> nfs_fh3 {
        nfs_fh3 { data: Opaque::owned(self.0.clone()) }
    }

    /// Convert from the wire type.
    #[must_use]
    pub fn from_nfs_fh3(fh: &nfs_fh3) -> Self {
        Self(fh.data.as_ref().to_vec())
    }
}

/// File type (ftype3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum FileType {
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
    /// Unix domain socket.
    Socket = 6,
    /// Named pipe.
    Fifo = 7,
}

impl FileType {
    /// Convert from the wire `ftype3`.
    #[must_use]
    pub const fn from_ftype3(ft: ftype3) -> Self {
        match ft {
            ftype3::NF3REG => Self::Regular,
            ftype3::NF3DIR => Self::Directory,
            ftype3::NF3BLK => Self::Block,
            ftype3::NF3CHR => Self::Character,
            ftype3::NF3LNK => Self::Symlink,
            ftype3::NF3SOCK => Self::Socket,
            ftype3::NF3FIFO => Self::Fifo,
        }
    }
}

/// A file's attributes, as reported by the server.
#[derive(Debug, Clone, Copy)]
pub struct FileAttrs {
    /// What kind of filesystem object this is.
    pub file_type: FileType,
    /// POSIX permission bits.
    pub mode: u32,
    /// Number of hard links.
    pub nlink: u32,
    /// Owning UID, as the server sees it.
    pub uid: u32,
    /// Owning GID, as the server sees it.
    pub gid: u32,
    /// Size in bytes.
    pub size: u64,
    /// Bytes of storage actually consumed, which is smaller than `size` for a
    /// sparse file.
    pub used: u64,
    /// Device major and minor numbers, meaningful only for device nodes.
    pub rdev: (u32, u32),
    /// Filesystem identifier.
    ///
    /// A change in this value between a directory and its parent marks an
    /// export or mount boundary.
    pub fsid: u64,
    /// Inode number within the filesystem.
    pub fileid: u64,
    /// Last access time.
    pub atime: NfsTime,
    /// Last modification time.
    pub mtime: NfsTime,
    /// Last inode change time.
    pub ctime: NfsTime,
}

impl FileAttrs {
    /// Convert from the wire `fattr3`.
    #[must_use]
    pub const fn from_fattr3(a: &fattr3) -> Self {
        Self {
            file_type: FileType::from_ftype3(a.type_),
            mode: a.mode,
            nlink: a.nlink,
            uid: a.uid,
            gid: a.gid,
            size: a.size,
            used: a.used,
            rdev: (a.rdev.specdata1, a.rdev.specdata2),
            fsid: a.fsid,
            fileid: a.fileid,
            atime: NfsTime { seconds: a.atime.seconds, nseconds: a.atime.nseconds },
            mtime: NfsTime { seconds: a.mtime.seconds, nseconds: a.mtime.nseconds },
            ctime: NfsTime { seconds: a.ctime.seconds, nseconds: a.ctime.nseconds },
        }
    }
}

/// NFS timestamp (seconds + nanoseconds since epoch).
#[derive(Debug, Clone, Copy)]
pub struct NfsTime {
    /// Whole seconds since the Unix epoch.
    pub seconds: u32,
    /// Nanoseconds within the second.
    pub nseconds: u32,
}

/// Directory entry from READDIRPLUS.
#[derive(Debug, Clone)]
pub struct DirEntryPlus {
    /// Server-assigned inode number.
    pub fileid: u64,
    /// Entry name within the directory.
    pub name: String,
    /// Opaque position marker; pass it back to resume paging here.
    pub cookie: u64,
    /// Attributes, when the server chose to return them.
    ///
    /// Optional by design (RFC 1813 sec. 3.3.17): a server may answer
    /// `READDIRPLUS` without attributes, and some return them as null for
    /// entries crossing a mount boundary.
    pub attrs: Option<FileAttrs>,
    /// File handle, when the server chose to return one.
    pub handle: Option<FileHandle>,
}

/// Directory entry from READDIR.
#[derive(Debug, Clone)]
pub struct DirEntry {
    /// Server-assigned inode number.
    pub fileid: u64,
    /// Entry name within the directory.
    pub name: String,
    /// Opaque position marker; pass it back to resume paging here.
    pub cookie: u64,
}

/// Dynamic filesystem statistics, from `FSSTAT`.
#[derive(Debug, Clone, Copy)]
pub struct FsStat {
    /// Total size of the filesystem in bytes.
    pub total_bytes: u64,
    /// Free bytes, counting space only the superuser may use.
    pub free_bytes: u64,
    /// Free bytes available to this caller.
    pub avail_bytes: u64,
    /// Total file slots.
    pub total_files: u64,
    /// Free file slots.
    pub free_files: u64,
    /// File slots available to this caller.
    pub avail_files: u64,
}

/// Static filesystem limits and capabilities, from `FSINFO`.
#[derive(Debug, Clone, Copy)]
pub struct FsInfo {
    /// Largest READ the server will accept.
    pub rtmax: u32,
    /// READ size the server prefers.
    pub rtpref: u32,
    /// Suggested READ size granularity.
    pub rtmult: u32,
    /// Largest WRITE the server will accept.
    pub wtmax: u32,
    /// WRITE size the server prefers.
    pub wtpref: u32,
    /// Suggested WRITE size granularity.
    pub wtmult: u32,
    /// READDIR reply size the server prefers.
    pub dtpref: u32,
    /// Largest file the filesystem can represent.
    pub max_file_size: u64,
    /// Finest timestamp granularity the server records.
    pub time_delta: NfsTime,
    /// Capability bits (`FSF3_*`): link and symlink support, homogeneity,
    /// and whether times can be set.
    pub properties: u32,
}

/// Access check bits (for ACCESS procedure  --  RFC 1813 S3.3.4).
///
/// These are the six access types the client can request in one call.
/// ACCESS results are advisory only  --  always confirm with the actual
/// operation (READ, WRITE, etc.) per RFC 1813 S3.3.4.
pub mod access {
    /// Read file data or list directory entries.
    pub const READ: u32 = 0x0001;
    /// Look up a name in a directory.
    pub const LOOKUP: u32 = 0x0002;
    /// Write data or modify file attributes.
    pub const MODIFY: u32 = 0x0004;
    /// Append data to a file or add entries to a directory.
    pub const EXTEND: u32 = 0x0008;
    /// Delete a file or directory entry.
    pub const DELETE: u32 = 0x0010;
    /// Execute a file.
    pub const EXECUTE: u32 = 0x0020;
    /// All six bits OR'd  --  request the full access mask in one call.
    pub const ALL: u32 = READ | LOOKUP | MODIFY | EXTEND | DELETE | EXECUTE;

    /// The write-capability bits: modify data/attrs, extend/create, or delete.
    /// A handle granting any of these is writable. ACCESS is advisory only
    /// (RFC 1813 S3.3.4)  --  confirm with an actual CREATE/WRITE.
    pub const WRITE_BITS: u32 = MODIFY | EXTEND | DELETE;

    /// Whether an ACCESS result mask grants any write capability.
    #[must_use]
    pub const fn grants_write(mask: u32) -> bool {
        mask & WRITE_BITS != 0
    }
}

/// Write stability levels.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum WriteStable {
    /// Server may buffer; a later `COMMIT` is required to make data durable.
    Unstable = 0,
    /// File data is on stable storage; metadata may not be.
    DataSync = 1,
    /// Both data and metadata are on stable storage before the reply.
    FileSync = 2,
}

/// Create mode for CREATE operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum CreateMode {
    /// Create, truncating any existing file without complaint.
    Unchecked = 0,
    /// Fail with `NFS3ERR_EXIST` if the name already exists.
    Guarded = 1,
    /// Create-once semantics using a client verifier, so a retransmitted
    /// request is not mistaken for a second creation.
    Exclusive = 2,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filehandle_round_trips_bytes() {
        let raw = [0x01u8, 0x00, 0x00, 0x01, 0xAB, 0xCD, 0xEF, 0x00];
        let fh = FileHandle::from_bytes(&raw);
        assert_eq!(fh.as_bytes(), &raw);
    }

    #[test]
    fn filehandle_hex_round_trip() {
        let raw = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let fh = FileHandle::from_bytes(&raw);
        let hex = fh.to_hex();
        let fh2 = FileHandle::from_hex(&hex).expect("hex decode must succeed");
        assert_eq!(fh, fh2);
    }

    #[test]
    fn filehandle_len_and_is_empty() {
        let empty = FileHandle::from_bytes(&[]);
        assert!(empty.is_empty());
        assert_eq!(empty.len(), 0);

        let fh = FileHandle::from_bytes(&[1, 2, 3, 4]);
        assert!(!fh.is_empty());
        assert_eq!(fh.len(), 4);
    }

    #[test]
    fn access_constants_are_distinct_single_bits() {
        // Each ACCESS bit must be a distinct power of two (RFC 1813 S3.3.4).
        let bits = [access::READ, access::LOOKUP, access::MODIFY, access::EXTEND, access::DELETE, access::EXECUTE];
        for (i, &a) in bits.iter().enumerate() {
            assert_eq!(a.count_ones(), 1, "bit {i} must be a single power of two");
            for (j, &b) in bits.iter().enumerate() {
                if i != j {
                    assert_eq!(a & b, 0, "access bits {i} and {j} must not overlap");
                }
            }
        }
    }
}
