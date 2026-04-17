//! NFSv3 type wrappers  --  re-exports and conversions from nfs3_types.
//!
//! nfs3_types provides the raw XDR types (nfs_fh3, fattr3, nfsstat3, etc.).
//! This module provides nfswolf-friendly wrappers with hex encoding,
//! display formatting, and domain methods.

// Struct fields and enum variants are wire-protocol values; individual
// field docs would be redundant with the module-level RFC citations.
// Toolkit API  --  not all items are used in currently-implemented phases.
use nfs3_types::nfs3::{fattr3, ftype3, nfs_fh3};
use nfs3_types::xdr_codec::Opaque;

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
/// Max 64 bytes for NFSv3 (RFC 1813 S2.3.1). Wraps nfs3_types::nfs3::nfs_fh3.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FileHandle(pub Vec<u8>);

impl FileHandle {
    pub fn from_bytes(data: &[u8]) -> Self {
        Self(data.to_vec())
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

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

    pub const fn len(&self) -> usize {
        self.0.len()
    }

    pub const fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Convert to nfs3-rs wire type.
    pub fn to_nfs_fh3(&self) -> nfs_fh3 {
        nfs_fh3 { data: Opaque::owned(self.0.clone()) }
    }

    /// Convert from nfs3-rs wire type.
    pub fn from_nfs_fh3(fh: &nfs_fh3) -> Self {
        Self(fh.data.as_ref().to_vec())
    }
}

/// File type (ftype3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum FileType {
    Regular = 1,
    Directory = 2,
    Block = 3,
    Character = 4,
    Symlink = 5,
    Socket = 6,
    Fifo = 7,
}

impl FileType {
    /// Convert from nfs3-rs ftype3.
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

/// File attributes (fattr3). Wraps nfs3_types::nfs3::fattr3.
#[derive(Debug, Clone)]
pub struct FileAttrs {
    pub file_type: FileType,
    pub mode: u32,
    pub nlink: u32,
    pub uid: u32,
    pub gid: u32,
    pub size: u64,
    pub used: u64,
    pub rdev: (u32, u32),
    pub fsid: u64,
    pub fileid: u64,
    pub atime: NfsTime,
    pub mtime: NfsTime,
    pub ctime: NfsTime,
}

impl FileAttrs {
    /// Convert from nfs3-rs fattr3.
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
    pub seconds: u32,
    pub nseconds: u32,
}

/// Directory entry from READDIRPLUS.
#[derive(Debug, Clone)]
pub struct DirEntryPlus {
    pub fileid: u64,
    pub name: String,
    pub cookie: u64,
    pub attrs: Option<FileAttrs>,
    pub handle: Option<FileHandle>,
}

/// Directory entry from READDIR.
#[derive(Debug, Clone)]
pub struct DirEntry {
    pub fileid: u64,
    pub name: String,
    pub cookie: u64,
}

/// Filesystem statistics (from FSSTAT).
#[derive(Debug, Clone)]
pub struct FsStat {
    pub total_bytes: u64,
    pub free_bytes: u64,
    pub avail_bytes: u64,
    pub total_files: u64,
    pub free_files: u64,
    pub avail_files: u64,
}

/// Filesystem info (from FSINFO).
#[derive(Debug, Clone)]
pub struct FsInfo {
    pub rtmax: u32,
    pub rtpref: u32,
    pub rtmult: u32,
    pub wtmax: u32,
    pub wtpref: u32,
    pub wtmult: u32,
    pub dtpref: u32,
    pub max_file_size: u64,
    pub time_delta: NfsTime,
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
}

/// Write stability levels.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum WriteStable {
    Unstable = 0,
    DataSync = 1,
    FileSync = 2,
}

/// Create mode for CREATE operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum CreateMode {
    Unchecked = 0,
    Guarded = 1,
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
