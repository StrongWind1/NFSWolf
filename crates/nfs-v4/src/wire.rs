//! NFSv4 XDR types  --  RFC 7530.
//!
//! All 37 NFSv4.0 operations (ops 3-39) plus ILLEGAL (op 10044) are
//! fully representable in `ArgOp` (request) and `ResOpData` (response).
//! Every operation has a typed `ArgOp` variant and a typed response
//! decoder -- the COMPOUND round-trip is lossless for all NFSv4.0 ops.
//! All types implement onc_xdr::{Pack, Unpack}.

// XDR type fields are wire-format values; individual docs would repeat names.
// Toolkit API  --  not all items are used in currently-implemented phases.
// NFSv4 XDR Pack/Unpack slices are at fixed offsets matching the RFC 7530 wire format.
use std::io::{Read, Write};

use onc_xdr::{Opaque, Pack, Unpack};

/// NFSv4 RPC program number (shared with NFSv2/v3  --  version distinguishes).
pub const NFS4_PROGRAM: u32 = 100_003;

/// NFSv4.0 version number for the COMPOUND procedure.
pub const NFS4_VERSION: u32 = 4;

/// COMPOUND is the sole non-NULL procedure in NFSv4 (RFC 7530 S15.2).
/// All operations are batched inside a single COMPOUND call.
pub const NFS4_PROC_COMPOUND: u32 = 1;

// --- NFSv4 operation codes (RFC 7530 S16) ---
// NFSv4.0 defines operations 3-39 in section 16 (not 18, which is RFC 5661/NFSv4.1).
// ILLEGAL is defined in S16.35 as 10044.

/// ACCESS  --  check access rights (op 3, RFC 7530 S16.1).
const OP_ACCESS: u32 = 3;
/// CLOSE  --  close file (op 4, RFC 7530 S16.2).
const OP_CLOSE: u32 = 4;
/// COMMIT  --  commit cached data (op 5, RFC 7530 S16.3).
const OP_COMMIT: u32 = 5;
/// CREATE  --  create a non-regular file object (op 6, RFC 7530 S16.4).
const OP_CREATE: u32 = 6;
/// DELEGPURGE  --  purge delegations awaiting recovery (op 7, RFC 7530 S16.5).
const OP_DELEGPURGE: u32 = 7;
/// DELEGRETURN  --  return delegation (op 8, RFC 7530 S16.6).
const OP_DELEGRETURN: u32 = 8;
/// GETATTR  --  retrieve file attributes (op 9, RFC 7530 S16.7).
const OP_GETATTR: u32 = 9;
/// GETFH  --  retrieve the current file handle (op 10, RFC 7530 S16.8).
const OP_GETFH: u32 = 10;
/// LINK  --  create link to a file (op 11, RFC 7530 S16.9).
const OP_LINK: u32 = 11;
/// LOCK  --  create lock (op 12, RFC 7530 S16.10).
const OP_LOCK: u32 = 12;
/// LOCKT  --  test for lock (op 13, RFC 7530 S16.11).
const OP_LOCKT: u32 = 13;
/// LOCKU  --  unlock file (op 14, RFC 7530 S16.12).
const OP_LOCKU: u32 = 14;
/// LOOKUP  --  look up a component in the current FH (op 15, RFC 7530 S16.13).
const OP_LOOKUP: u32 = 15;
/// LOOKUPP  --  look up parent directory (op 16, RFC 7530 S16.14).
const OP_LOOKUPP: u32 = 16;
/// NVERIFY  --  verify difference in attributes (op 17, RFC 7530 S16.15).
const OP_NVERIFY: u32 = 17;
/// OPEN  --  open a regular file (op 18, RFC 7530 S16.16).
const OP_OPEN: u32 = 18;
/// OPENATTR  --  open named attribute directory (op 19, RFC 7530 S16.17).
const OP_OPENATTR: u32 = 19;
/// OPEN_CONFIRM  --  confirm open (op 20, RFC 7530 S16.18).
const OP_OPEN_CONFIRM: u32 = 20;
/// OPEN_DOWNGRADE  --  reduce open file access (op 21, RFC 7530 S16.19).
const OP_OPEN_DOWNGRADE: u32 = 21;
/// PUTFH  --  make an existing FH current (op 22, RFC 7530 S16.20).
const OP_PUTFH: u32 = 22;
/// PUTPUBFH  --  make the server's public (WebNFS) FH current (op 23, RFC 7530 S16.21).
const OP_PUTPUBFH: u32 = 23;
/// PUTROOTFH  --  make the server's root FH current (op 24, RFC 7530 S16.22).
const OP_PUTROOTFH: u32 = 24;
/// READ  --  read file data (op 25, RFC 7530 S16.23).
const OP_READ: u32 = 25;
/// READDIR  --  read directory entries with inline attributes (op 26, RFC 7530 S16.24).
const OP_READDIR: u32 = 26;
/// READLINK  --  read symbolic link (op 27, RFC 7530 S16.25).
const OP_READLINK: u32 = 27;
/// REMOVE  --  remove filesystem object (op 28, RFC 7530 S16.26).
const OP_REMOVE: u32 = 28;
/// RENAME  --  rename filesystem object (op 29, RFC 7530 S16.27).
const OP_RENAME: u32 = 29;
/// RENEW  --  renew a lease (op 30, RFC 7530 S16.28).
const OP_RENEW: u32 = 30;
/// RESTOREFH  --  restore saved file handle (op 31, RFC 7530 S16.29).
const OP_RESTOREFH: u32 = 31;
/// SAVEFH  --  save current file handle (op 32, RFC 7530 S16.30).
const OP_SAVEFH: u32 = 32;
/// SECINFO  --  query auth flavors for a name (op 33, RFC 7530 S16.31).
const OP_SECINFO: u32 = 33;
/// SETATTR  --  set attributes (op 34, RFC 7530 S16.32).
const OP_SETATTR: u32 = 34;
/// SETCLIENTID  --  negotiate client ID (op 35, RFC 7530 S16.33).
const OP_SETCLIENTID: u32 = 35;
/// SETCLIENTID_CONFIRM  --  confirm client ID (op 36, RFC 7530 S16.34).
const OP_SETCLIENTID_CONFIRM: u32 = 36;
/// VERIFY  --  verify same attributes (op 37, RFC 7530 S16.35).
const OP_VERIFY: u32 = 37;
/// WRITE  --  write to file (op 38, RFC 7530 S16.36).
const OP_WRITE: u32 = 38;
/// RELEASE_LOCKOWNER  --  release lock-owner state (op 39, RFC 7530 S16.37).
const OP_RELEASE_LOCKOWNER: u32 = 39;
/// ILLEGAL  --  illegal operation (op 10044, RFC 7530 S16.38).
const OP_ILLEGAL: u32 = 10044;

// --- NFSv4.1 operation codes (RFC 5661 S18) ---

/// EXCHANGE_ID  --  establish client identity (op 42, RFC 5661 S18.35).
const OP_EXCHANGE_ID: u32 = 42;
/// GETDEVICEINFO  --  retrieve pNFS device info (op 47, RFC 5661 S18.40).
const OP_GETDEVICEINFO: u32 = 47;
/// GETDEVICELIST  --  enumerate pNFS devices (op 48, RFC 5661 S18.41).
const OP_GETDEVICELIST: u32 = 48;
/// SECINFO_NO_NAME  --  get security info for current FH (op 52, RFC 5661 S18.45).
const OP_SECINFO_NO_NAME: u32 = 52;

// --- NFSv4 wire-format size constants ---

/// Maximum NFSv4 file handle size in bytes (RFC 7530 S4).
pub const NFS4_FHSIZE: usize = 128;
/// Verifier size in bytes (RFC 7530 S2.2.3).
pub const NFS4_VERIFIER_SIZE: usize = 8;
/// Stateid "other" field size in bytes (RFC 7530 S2.2.11).
pub const NFS4_OTHER_SIZE: usize = 12;
/// Maximum opaque data size in bytes (RFC 7530 S2.2).
pub const NFS4_OPAQUE_LIMIT: usize = 1024;

// --- XDR helpers ---

/// Pack XDR opaque<> (variable-length): 4-byte length + bytes + padding.
fn pack_opaque(data: &[u8], out: &mut impl Write) -> onc_xdr::Result<usize> {
    let len = u32::try_from(data.len()).map_err(|_| onc_xdr::Error::ObjectTooLarge(data.len()))?;
    let mut n = len.pack(out)?;
    out.write_all(data).map_err(onc_xdr::Error::Io)?;
    n += data.len();
    let pad = (4 - (data.len() % 4)) % 4;
    onc_xdr::write_pad(out, pad)?;
    n += pad;
    Ok(n)
}

const fn opaque_packed_size(data: &[u8]) -> usize {
    let len = data.len();
    4 + len + (4 - (len % 4)) % 4
}

// --- NFSv4 typed enums ---

/// Write stability level (RFC 7530 S16.36).
///
/// Controls how the server commits data to stable storage before replying.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum StableHow4 {
    /// Server may cache the data without flushing (RFC 7530 S16.36).  Wire value 0.
    Unstable,
    /// Data is on stable storage, metadata may be cached (RFC 7530 S16.36).  Wire value 1.
    DataSync,
    /// Data and metadata are both on stable storage (RFC 7530 S16.36).  Wire value 2.
    FileSync,
    /// Unrecognized stability level from the wire.
    Unknown(u32),
}

impl StableHow4 {
    /// Decode a u32 from the wire into a known variant or `Unknown`.
    #[must_use]
    pub const fn from_u32(v: u32) -> Self {
        match v {
            0 => Self::Unstable,
            1 => Self::DataSync,
            2 => Self::FileSync,
            other => Self::Unknown(other),
        }
    }

    /// Convert back to the raw u32 wire value.
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        match self {
            Self::Unstable => 0,
            Self::DataSync => 1,
            Self::FileSync => 2,
            Self::Unknown(v) => v,
        }
    }
}

impl Pack for StableHow4 {
    fn packed_size(&self) -> usize {
        4
    }

    fn pack(&self, out: &mut impl Write) -> onc_xdr::Result<usize> {
        self.as_u32().pack(out)
    }
}

impl Unpack for StableHow4 {
    fn unpack(input: &mut impl Read) -> onc_xdr::Result<(Self, usize)> {
        let (v, n) = u32::unpack(input)?;
        Ok((Self::from_u32(v), n))
    }
}

/// NFSv4 open delegation result (RFC 7530 S16.16).
///
/// Decoded from the `open_delegation4` union in the OPEN response.
/// Carries the delegation stateid, recall flag, and the ACE controlling
/// delegated access.
#[derive(Debug, Clone)]
pub enum OpenDelegation4 {
    /// No delegation granted (OPEN_DELEGATE_NONE, wire value 0).
    None,
    /// Read delegation (OPEN_DELEGATE_READ, wire value 1, RFC 7530 S16.16.5).
    Read {
        /// Stateid for this delegation.
        stateid: Stateid4,
        /// True if the server may recall this delegation.
        recall: bool,
        /// ACE describing permitted access under the delegation.
        ace: NfsAce4,
    },
    /// Write delegation (OPEN_DELEGATE_WRITE, wire value 2, RFC 7530 S16.16.5).
    Write {
        /// Stateid for this delegation.
        stateid: Stateid4,
        /// True if the server may recall this delegation.
        recall: bool,
        /// Server-imposed space limit for the delegated file.
        space_limit: SpaceLimit4,
        /// ACE describing permitted access under the delegation.
        ace: NfsAce4,
    },
}

/// Server-imposed space limit for write delegations (RFC 7530 S16.16.5).
///
/// Decoded from the `nfs_space_limit4` union in write delegation results.
#[derive(Debug, Clone, Copy)]
pub enum SpaceLimit4 {
    /// Absolute size limit in bytes (NFS_LIMIT_SIZE, wire value 1).
    Size(u64),
    /// Block-based limit (NFS_LIMIT_BLOCKS, wire value 2).
    Blocks {
        /// Number of blocks allowed.
        num_blocks: u64,
        /// Bytes per block.
        bytes_per_block: u32,
    },
}

/// Open delegation type (RFC 7530 S16.16).
///
/// Indicates whether and what kind of delegation the server granted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum OpenDelegationType4 {
    /// No delegation granted (RFC 7530 S16.16).  Wire value 0.
    None,
    /// Read delegation granted (RFC 7530 S16.16).  Wire value 1.
    Read,
    /// Write delegation granted (RFC 7530 S16.16).  Wire value 2.
    Write,
    /// Unrecognized delegation type from the wire.
    Unknown(u32),
}

impl OpenDelegationType4 {
    /// Decode a u32 from the wire into a known variant or `Unknown`.
    #[must_use]
    pub const fn from_u32(v: u32) -> Self {
        match v {
            0 => Self::None,
            1 => Self::Read,
            2 => Self::Write,
            other => Self::Unknown(other),
        }
    }

    /// Convert back to the raw u32 wire value.
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        match self {
            Self::None => 0,
            Self::Read => 1,
            Self::Write => 2,
            Self::Unknown(v) => v,
        }
    }
}

impl Pack for OpenDelegationType4 {
    fn packed_size(&self) -> usize {
        4
    }

    fn pack(&self, out: &mut impl Write) -> onc_xdr::Result<usize> {
        self.as_u32().pack(out)
    }
}

impl Unpack for OpenDelegationType4 {
    fn unpack(input: &mut impl Read) -> onc_xdr::Result<(Self, usize)> {
        let (v, n) = u32::unpack(input)?;
        Ok((Self::from_u32(v), n))
    }
}

/// File creation mode for OPEN/CREATE (RFC 7530 S16.4).
///
/// Controls whether the server creates a new file or fails if one exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CreateMode4 {
    /// Create with no existence check (RFC 7530 S16.4).  Wire value 0.
    Unchecked,
    /// Fail if the file already exists (RFC 7530 S16.4).  Wire value 1.
    Guarded,
    /// Create exclusively using a verifier (RFC 7530 S16.4).  Wire value 2.
    Exclusive,
    /// Unrecognized creation mode from the wire.
    Unknown(u32),
}

impl CreateMode4 {
    /// Decode a u32 from the wire into a known variant or `Unknown`.
    #[must_use]
    pub const fn from_u32(v: u32) -> Self {
        match v {
            0 => Self::Unchecked,
            1 => Self::Guarded,
            2 => Self::Exclusive,
            other => Self::Unknown(other),
        }
    }

    /// Convert back to the raw u32 wire value.
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        match self {
            Self::Unchecked => 0,
            Self::Guarded => 1,
            Self::Exclusive => 2,
            Self::Unknown(v) => v,
        }
    }
}

impl Pack for CreateMode4 {
    fn packed_size(&self) -> usize {
        4
    }

    fn pack(&self, out: &mut impl Write) -> onc_xdr::Result<usize> {
        self.as_u32().pack(out)
    }
}

impl Unpack for CreateMode4 {
    fn unpack(input: &mut impl Read) -> onc_xdr::Result<(Self, usize)> {
        let (v, n) = u32::unpack(input)?;
        Ok((Self::from_u32(v), n))
    }
}

/// OPEN type: whether to create the file (RFC 7530 S16.16).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum OpenType4 {
    /// Open existing file, do not create (RFC 7530 S16.16).  Wire value 0.
    NoCreate,
    /// Create the file if it does not exist (RFC 7530 S16.16).  Wire value 1.
    Create,
    /// Unrecognized open type from the wire.
    Unknown(u32),
}

impl OpenType4 {
    /// Decode a u32 from the wire into a known variant or `Unknown`.
    #[must_use]
    pub const fn from_u32(v: u32) -> Self {
        match v {
            0 => Self::NoCreate,
            1 => Self::Create,
            other => Self::Unknown(other),
        }
    }

    /// Convert back to the raw u32 wire value.
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        match self {
            Self::NoCreate => 0,
            Self::Create => 1,
            Self::Unknown(v) => v,
        }
    }
}

impl Pack for OpenType4 {
    fn packed_size(&self) -> usize {
        4
    }

    fn pack(&self, out: &mut impl Write) -> onc_xdr::Result<usize> {
        self.as_u32().pack(out)
    }
}

impl Unpack for OpenType4 {
    fn unpack(input: &mut impl Read) -> onc_xdr::Result<(Self, usize)> {
        let (v, n) = u32::unpack(input)?;
        Ok((Self::from_u32(v), n))
    }
}

/// OPEN claim type (RFC 7530 S16.16).
///
/// Determines how the client identifies the file to open.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum OpenClaimType4 {
    /// Open by name in the current directory (RFC 7530 S16.16).  Wire value 0.
    Null,
    /// Reclaim a previous open after server reboot (RFC 7530 S16.16).  Wire value 1.
    Previous,
    /// Open using a current delegation (RFC 7530 S16.16).  Wire value 2.
    DelegateCur,
    /// Open using a previous delegation (RFC 7530 S16.16).  Wire value 3.
    DelegatePrev,
    /// Unrecognized claim type from the wire.
    Unknown(u32),
}

impl OpenClaimType4 {
    /// Decode a u32 from the wire into a known variant or `Unknown`.
    #[must_use]
    pub const fn from_u32(v: u32) -> Self {
        match v {
            0 => Self::Null,
            1 => Self::Previous,
            2 => Self::DelegateCur,
            3 => Self::DelegatePrev,
            other => Self::Unknown(other),
        }
    }

    /// Convert back to the raw u32 wire value.
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        match self {
            Self::Null => 0,
            Self::Previous => 1,
            Self::DelegateCur => 2,
            Self::DelegatePrev => 3,
            Self::Unknown(v) => v,
        }
    }
}

impl Pack for OpenClaimType4 {
    fn packed_size(&self) -> usize {
        4
    }

    fn pack(&self, out: &mut impl Write) -> onc_xdr::Result<usize> {
        self.as_u32().pack(out)
    }
}

impl Unpack for OpenClaimType4 {
    fn unpack(input: &mut impl Read) -> onc_xdr::Result<(Self, usize)> {
        let (v, n) = u32::unpack(input)?;
        Ok((Self::from_u32(v), n))
    }
}

/// Byte-range lock type (RFC 7530 S16.10).
///
/// Note: wire values start at 1, not 0.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum LockType4 {
    /// Shared (read) lock (RFC 7530 S16.10).  Wire value 1.
    ReadLt,
    /// Exclusive (write) lock (RFC 7530 S16.10).  Wire value 2.
    WriteLt,
    /// Blocking shared lock request (RFC 7530 S16.10).  Wire value 3.
    ReadwLt,
    /// Blocking exclusive lock request (RFC 7530 S16.10).  Wire value 4.
    WritewLt,
    /// Unrecognized lock type from the wire.
    Unknown(u32),
}

impl LockType4 {
    /// Decode a u32 from the wire into a known variant or `Unknown`.
    #[must_use]
    pub const fn from_u32(v: u32) -> Self {
        match v {
            1 => Self::ReadLt,
            2 => Self::WriteLt,
            3 => Self::ReadwLt,
            4 => Self::WritewLt,
            other => Self::Unknown(other),
        }
    }

    /// Convert back to the raw u32 wire value.
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        match self {
            Self::ReadLt => 1,
            Self::WriteLt => 2,
            Self::ReadwLt => 3,
            Self::WritewLt => 4,
            Self::Unknown(v) => v,
        }
    }
}

impl Pack for LockType4 {
    fn packed_size(&self) -> usize {
        4
    }

    fn pack(&self, out: &mut impl Write) -> onc_xdr::Result<usize> {
        self.as_u32().pack(out)
    }
}

impl Unpack for LockType4 {
    fn unpack(input: &mut impl Read) -> onc_xdr::Result<(Self, usize)> {
        let (v, n) = u32::unpack(input)?;
        Ok((Self::from_u32(v), n))
    }
}

// --- Phase 2 compound types ---

/// NFSv4 stateid (RFC 7530 S2.2.11).
///
/// A stateid identifies a set of locks held by a particular client on a file.
/// The seqid field is incremented on each state-changing operation; the other
/// field is an opaque server-generated 12-byte identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Stateid4 {
    /// Monotonically increasing sequence number for this state.
    pub seqid: u32,
    /// Server-generated opaque identifier (RFC 7530 S2.2.11).
    pub other: [u8; NFS4_OTHER_SIZE],
}

impl Stateid4 {
    /// Anonymous stateid: seqid=0, other=all-zeros (RFC 7530 S9.1.4.3).
    ///
    /// Used for READ/WRITE without a prior OPEN when the server permits it
    /// (e.g., AUTH_SYS with no mandatory locking).
    pub const ANONYMOUS: Self = Self { seqid: 0, other: [0; NFS4_OTHER_SIZE] };

    /// Read-bypass stateid: seqid=0xFFFFFFFF, other=all-0xFF (RFC 7530 S9.1.4.3).
    ///
    /// Bypasses any share reservations or locks for READ operations. Useful
    /// for security probes that need to read data regardless of open state.
    pub const READ_BYPASS: Self = Self { seqid: 0xFFFF_FFFF, other: [0xFF; NFS4_OTHER_SIZE] };

    /// Convert to raw 16-byte representation (4-byte seqid BE + 12-byte other).
    #[must_use]
    pub fn to_bytes(self) -> [u8; 16] {
        let mut out = [0u8; 16];
        out[..4].copy_from_slice(&self.seqid.to_be_bytes());
        out[4..].copy_from_slice(&self.other);
        out
    }

    /// Parse from raw 16-byte representation (4-byte seqid BE + 12-byte other).
    #[must_use]
    pub fn from_bytes(bytes: [u8; 16]) -> Self {
        let seqid = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        let mut other = [0u8; NFS4_OTHER_SIZE];
        other.copy_from_slice(&bytes[4..]);
        Self { seqid, other }
    }
}

impl Pack for Stateid4 {
    fn packed_size(&self) -> usize {
        16
    }

    fn pack(&self, out: &mut impl Write) -> onc_xdr::Result<usize> {
        out.write_all(&self.seqid.to_be_bytes()).map_err(onc_xdr::Error::Io)?;
        out.write_all(&self.other).map_err(onc_xdr::Error::Io)?;
        Ok(16)
    }
}

impl Unpack for Stateid4 {
    fn unpack(input: &mut impl Read) -> onc_xdr::Result<(Self, usize)> {
        let mut buf = [0u8; 16];
        input.read_exact(&mut buf).map_err(onc_xdr::Error::Io)?;
        Ok((Self::from_bytes(buf), 16))
    }
}

impl From<[u8; 16]> for Stateid4 {
    fn from(bytes: [u8; 16]) -> Self {
        Self::from_bytes(bytes)
    }
}

impl From<Stateid4> for [u8; 16] {
    fn from(s: Stateid4) -> Self {
        s.to_bytes()
    }
}

/// Change information returned by directory-mutating ops (RFC 7530 S2.2.4).
///
/// Contains the change attribute before and after the operation, plus a flag
/// indicating whether the before/after values were obtained atomically.
/// Response-only type -- never sent by the client.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChangeInfo4 {
    /// True if `before` and `after` were captured atomically (RFC 7530 S2.2.4).
    pub atomic: bool,
    /// Change attribute value before the operation.
    pub before: u64,
    /// Change attribute value after the operation.
    pub after: u64,
}

impl Unpack for ChangeInfo4 {
    fn unpack(input: &mut impl Read) -> onc_xdr::Result<(Self, usize)> {
        let (raw, mut n) = u32::unpack(input)?;
        let atomic = raw != 0;
        let (before, bn) = u64::unpack(input)?;
        n += bn;
        let (after, an) = u64::unpack(input)?;
        n += an;
        Ok((Self { atomic, before, after }, n))
    }
}

/// File type enum (RFC 7530 S5.8.1.2).
///
/// Encodes the `nfs_ftype4` value from GETATTR results. Named-attribute
/// types (8, 9) are NFSv4-specific; everything else mirrors Unix types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum NfsFtype4 {
    /// Regular file (RFC 7530 S5.8.1.2).  Wire value 1.
    Reg,
    /// Directory (RFC 7530 S5.8.1.2).  Wire value 2.
    Dir,
    /// Block device (RFC 7530 S5.8.1.2).  Wire value 3.
    Blk,
    /// Character device (RFC 7530 S5.8.1.2).  Wire value 4.
    Chr,
    /// Symbolic link (RFC 7530 S5.8.1.2).  Wire value 5.
    Lnk,
    /// Socket (RFC 7530 S5.8.1.2).  Wire value 6.
    Sock,
    /// Named pipe / FIFO (RFC 7530 S5.8.1.2).  Wire value 7.
    Fifo,
    /// Named-attribute directory (RFC 7530 S5.8.1.2).  Wire value 8.
    AttrDir,
    /// Named attribute (RFC 7530 S5.8.1.2).  Wire value 9.
    NamedAttr,
    /// Unrecognized file type from the wire.
    Unknown(u32),
}

impl NfsFtype4 {
    /// Decode a u32 from the wire into a known variant or `Unknown`.
    #[must_use]
    pub const fn from_u32(v: u32) -> Self {
        match v {
            1 => Self::Reg,
            2 => Self::Dir,
            3 => Self::Blk,
            4 => Self::Chr,
            5 => Self::Lnk,
            6 => Self::Sock,
            7 => Self::Fifo,
            8 => Self::AttrDir,
            9 => Self::NamedAttr,
            other => Self::Unknown(other),
        }
    }

    /// Convert back to the raw u32 wire value.
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        match self {
            Self::Reg => 1,
            Self::Dir => 2,
            Self::Blk => 3,
            Self::Chr => 4,
            Self::Lnk => 5,
            Self::Sock => 6,
            Self::Fifo => 7,
            Self::AttrDir => 8,
            Self::NamedAttr => 9,
            Self::Unknown(v) => v,
        }
    }
}

impl Pack for NfsFtype4 {
    fn packed_size(&self) -> usize {
        4
    }

    fn pack(&self, out: &mut impl Write) -> onc_xdr::Result<usize> {
        self.as_u32().pack(out)
    }
}

impl Unpack for NfsFtype4 {
    fn unpack(input: &mut impl Read) -> onc_xdr::Result<(Self, usize)> {
        let (v, n) = u32::unpack(input)?;
        Ok((Self::from_u32(v), n))
    }
}

impl core::fmt::Display for NfsFtype4 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Reg => f.write_str("NF4REG"),
            Self::Dir => f.write_str("NF4DIR"),
            Self::Blk => f.write_str("NF4BLK"),
            Self::Chr => f.write_str("NF4CHR"),
            Self::Lnk => f.write_str("NF4LNK"),
            Self::Sock => f.write_str("NF4SOCK"),
            Self::Fifo => f.write_str("NF4FIFO"),
            Self::AttrDir => f.write_str("NF4ATTRDIR"),
            Self::NamedAttr => f.write_str("NF4NAMEDATTR"),
            Self::Unknown(v) => write!(f, "NF4UNKNOWN({v})"),
        }
    }
}

/// Open-owner identifier (RFC 7530 S2.2.13).
///
/// Binds a client ID and an opaque owner value to an open-state sequence.
/// The owner field is typically a per-process or per-thread identifier
/// chosen by the client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenOwner4 {
    /// Client ID from SETCLIENTID (RFC 7530 S16.33).
    pub clientid: u64,
    /// Opaque owner value (per-process/thread identity).
    pub owner: Vec<u8>,
}

impl Pack for OpenOwner4 {
    fn packed_size(&self) -> usize {
        8 + opaque_packed_size(&self.owner)
    }

    fn pack(&self, out: &mut impl Write) -> onc_xdr::Result<usize> {
        let mut n = self.clientid.pack(out)?;
        n += pack_opaque(&self.owner, out)?;
        Ok(n)
    }
}

impl Unpack for OpenOwner4 {
    fn unpack(input: &mut impl Read) -> onc_xdr::Result<(Self, usize)> {
        let (clientid, mut n) = u64::unpack(input)?;
        let (owner_opaque, on) = Opaque::unpack(input)?;
        n += on;
        Ok((Self { clientid, owner: owner_opaque.into_owned() }, n))
    }
}

/// Lock-owner identifier (RFC 7530 S2.2.14).
///
/// Same wire format as `OpenOwner4` but semantically distinct: identifies
/// the entity holding byte-range locks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LockOwner4 {
    /// Client ID from SETCLIENTID (RFC 7530 S16.33).
    pub clientid: u64,
    /// Opaque owner value.
    pub owner: Vec<u8>,
}

impl Pack for LockOwner4 {
    fn packed_size(&self) -> usize {
        8 + opaque_packed_size(&self.owner)
    }

    fn pack(&self, out: &mut impl Write) -> onc_xdr::Result<usize> {
        let mut n = self.clientid.pack(out)?;
        n += pack_opaque(&self.owner, out)?;
        Ok(n)
    }
}

impl Unpack for LockOwner4 {
    fn unpack(input: &mut impl Read) -> onc_xdr::Result<(Self, usize)> {
        let (clientid, mut n) = u64::unpack(input)?;
        let (owner_opaque, on) = Opaque::unpack(input)?;
        n += on;
        Ok((Self { clientid, owner: owner_opaque.into_owned() }, n))
    }
}

/// NFSv4 ACE entry (RFC 7530 S5.11.1).
///
/// Represents one Access Control Entry in an NFSv4 ACL attribute.
/// The `who` field is a UTF-8 name string (user\@domain or group\@domain).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NfsAce4 {
    /// ACE type: ALLOW (0), DENY (1), AUDIT (2), ALARM (3) per RFC 7530 S5.11.1.
    pub ace_type: u32,
    /// ACE flags (inheritance, identifier group, etc.) per RFC 7530 S5.11.2.
    pub flag: u32,
    /// Bitmask of operations this ACE applies to (RFC 7530 S5.11.3).
    pub access_mask: u32,
    /// Principal name in "user\@domain" or "group\@domain" form (RFC 7530 S5.11.4).
    pub who: String,
}

impl Pack for NfsAce4 {
    fn packed_size(&self) -> usize {
        4 + 4 + 4 + onc_xdr::string_packed_size(&self.who)
    }

    fn pack(&self, out: &mut impl Write) -> onc_xdr::Result<usize> {
        let mut n = self.ace_type.pack(out)?;
        n += self.flag.pack(out)?;
        n += self.access_mask.pack(out)?;
        n += onc_xdr::pack_string(&self.who, out)?;
        Ok(n)
    }
}

impl Unpack for NfsAce4 {
    fn unpack(input: &mut impl Read) -> onc_xdr::Result<(Self, usize)> {
        let (ace_type, mut n) = u32::unpack(input)?;
        let (flag, fn_) = u32::unpack(input)?;
        n += fn_;
        let (access_mask, an) = u32::unpack(input)?;
        n += an;
        let (who, wn) = onc_xdr::unpack_string(input)?;
        n += wn;
        Ok((Self { ace_type, flag, access_mask, who }, n))
    }
}

// --- Phase 2b compound types ---

/// Discriminated union for the CREATE operation's object type (RFC 7530 S16.4).
///
/// Encodes the `ftype4` discriminant followed by variant-specific data.
/// Only non-regular file types are representable; regular files are created
/// via OPEN, not CREATE.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum CreateType4 {
    /// Directory (ftype4 = NF4DIR = 2).
    Dir,
    /// Block device with major/minor numbers (ftype4 = NF4BLK = 3).
    Blk {
        /// Major device number.
        specdata1: u32,
        /// Minor device number.
        specdata2: u32,
    },
    /// Character device with major/minor numbers (ftype4 = NF4CHR = 4).
    Chr {
        /// Major device number.
        specdata1: u32,
        /// Minor device number.
        specdata2: u32,
    },
    /// Symbolic link with target path (ftype4 = NF4LNK = 5).
    Lnk(String),
    /// Socket (ftype4 = NF4SOCK = 6).
    Sock,
    /// FIFO / named pipe (ftype4 = NF4FIFO = 7).
    Fifo,
}

impl Pack for CreateType4 {
    fn packed_size(&self) -> usize {
        4 + match self {
            Self::Dir | Self::Sock | Self::Fifo => 0,
            Self::Blk { .. } | Self::Chr { .. } => 8,
            Self::Lnk(target) => onc_xdr::string_packed_size(target),
        }
    }

    fn pack(&self, out: &mut impl Write) -> onc_xdr::Result<usize> {
        let (disc, extra): (u32, usize) = match self {
            Self::Dir => (2, 0),
            Self::Blk { specdata1, specdata2 } => {
                let n = 3u32.pack(out)?;
                let n2 = specdata1.pack(out)?;
                let n3 = specdata2.pack(out)?;
                return Ok(n + n2 + n3);
            },
            Self::Chr { specdata1, specdata2 } => {
                let n = 4u32.pack(out)?;
                let n2 = specdata1.pack(out)?;
                let n3 = specdata2.pack(out)?;
                return Ok(n + n2 + n3);
            },
            Self::Lnk(target) => {
                let n = 5u32.pack(out)?;
                let n2 = onc_xdr::pack_string(target, out)?;
                return Ok(n + n2);
            },
            Self::Sock => (6, 0),
            Self::Fifo => (7, 0),
        };
        let n = disc.pack(out)?;
        Ok(n + extra)
    }
}

/// Locker argument for the LOCK operation (RFC 7530 S16.10).
///
/// Discriminated by `new_lock_owner`: TRUE (1) for a first-time lock
/// request that carries the open stateid and a new lock-owner identity,
/// FALSE (0) for subsequent requests on an existing lock stateid.
#[derive(Debug, Clone)]
pub enum Locker4 {
    /// First lock request: references the open stateid and provides a new lock-owner.
    NewLockOwner {
        /// Sequence number for the open stateid.
        open_seqid: u32,
        /// Open stateid from which the lock derives.
        open_stateid: Stateid4,
        /// Initial sequence number for the new lock-owner.
        lock_seqid: u32,
        /// Identity of the lock-owner being created.
        lock_owner: LockOwner4,
    },
    /// Subsequent lock request on an already-established lock stateid.
    ExistLockOwner {
        /// Existing lock stateid to extend.
        lock_stateid: Stateid4,
        /// Next sequence number for this lock-owner.
        lock_seqid: u32,
    },
}

impl Pack for Locker4 {
    fn packed_size(&self) -> usize {
        4 + match self {
            Self::NewLockOwner { open_stateid, lock_owner, .. } => 4 + open_stateid.packed_size() + 4 + lock_owner.packed_size(),
            Self::ExistLockOwner { lock_stateid, .. } => lock_stateid.packed_size() + 4,
        }
    }

    fn pack(&self, out: &mut impl Write) -> onc_xdr::Result<usize> {
        match self {
            Self::NewLockOwner { open_seqid, open_stateid, lock_seqid, lock_owner } => {
                let mut n = 1u32.pack(out)?; // TRUE
                n += open_seqid.pack(out)?;
                n += open_stateid.pack(out)?;
                n += lock_seqid.pack(out)?;
                n += lock_owner.pack(out)?;
                Ok(n)
            },
            Self::ExistLockOwner { lock_stateid, lock_seqid } => {
                let mut n = 0u32.pack(out)?; // FALSE
                n += lock_stateid.pack(out)?;
                n += lock_seqid.pack(out)?;
                Ok(n)
            },
        }
    }
}

/// Claim argument for the OPEN operation (RFC 7530 S16.16).
///
/// Determines how the client identifies the file to open:
/// - `Null`: open by name in the current directory (claim_type 0).
/// - `Previous`: reclaim a delegation after server reboot (claim_type 1).
/// - `DelegateCur`: open using a current delegation (claim_type 2).
/// - `DelegatePrev`: open using a previous delegation filename (claim_type 3).
#[derive(Debug, Clone)]
pub enum OpenClaim4 {
    /// Open by name in the current directory (CLAIM_NULL, wire value 0).
    Null(String),
    /// Reclaim after reboot with the given delegation type (CLAIM_PREVIOUS, wire value 1).
    Previous(OpenDelegationType4),
    /// Open using a current delegation stateid (CLAIM_DELEGATE_CUR, wire value 2).
    DelegateCur {
        /// Delegation stateid being used.
        delegate_stateid: Stateid4,
        /// Filename to open.
        file: String,
    },
    /// Open using a previous delegation filename (CLAIM_DELEGATE_PREV, wire value 3).
    DelegatePrev(String),
}

impl Pack for OpenClaim4 {
    fn packed_size(&self) -> usize {
        4 + match self {
            Self::Previous(_) => 4,
            Self::DelegateCur { delegate_stateid, file } => delegate_stateid.packed_size() + onc_xdr::string_packed_size(file),
            Self::Null(file) | Self::DelegatePrev(file) => onc_xdr::string_packed_size(file),
        }
    }

    fn pack(&self, out: &mut impl Write) -> onc_xdr::Result<usize> {
        match self {
            Self::Null(file) => {
                let mut n = 0u32.pack(out)?;
                n += onc_xdr::pack_string(file, out)?;
                Ok(n)
            },
            Self::Previous(deleg_type) => {
                let mut n = 1u32.pack(out)?;
                n += deleg_type.pack(out)?;
                Ok(n)
            },
            Self::DelegateCur { delegate_stateid, file } => {
                let mut n = 2u32.pack(out)?;
                n += delegate_stateid.pack(out)?;
                n += onc_xdr::pack_string(file, out)?;
                Ok(n)
            },
            Self::DelegatePrev(file) => {
                let mut n = 3u32.pack(out)?;
                n += onc_xdr::pack_string(file, out)?;
                Ok(n)
            },
        }
    }
}

/// Open-how argument for the OPEN operation (RFC 7530 S16.16).
///
/// Controls whether the server should create the file:
/// - `NoCreate`: the file must already exist.
/// - `Create`: create the file with the given mode and attributes.
#[derive(Debug, Clone)]
pub enum OpenFlag4 {
    /// Open existing file, do not create (opentype4 = OPEN4_NOCREATE = 0).
    NoCreate,
    /// Create the file if absent (opentype4 = OPEN4_CREATE = 1).
    Create {
        /// Creation mode controlling exclusivity (RFC 7530 S16.4).
        mode: CreateMode4,
        /// Pre-encoded attribute or verifier data.
        ///
        /// - For `Exclusive` mode: the 8-byte create verifier.
        /// - For `Unchecked`/`Guarded`: pre-encoded fattr4 bytes.
        attrs: Vec<u8>,
    },
}

impl Pack for OpenFlag4 {
    fn packed_size(&self) -> usize {
        4 + match self {
            Self::NoCreate => 0,
            Self::Create { mode, attrs } => mode.packed_size() + attrs.len(),
        }
    }

    fn pack(&self, out: &mut impl Write) -> onc_xdr::Result<usize> {
        match self {
            Self::NoCreate => 0u32.pack(out),
            Self::Create { mode, attrs } => {
                let mut n = 1u32.pack(out)?;
                n += mode.pack(out)?;
                out.write_all(attrs).map_err(onc_xdr::Error::Io)?;
                n += attrs.len();
                Ok(n)
            },
        }
    }
}

/// Wire-level fattr4 container (RFC 7530 S2.2.6).
///
/// Carries a bitmap indicating which attributes are present, and the XDR-encoded
/// values of those attributes packed end-to-end in `attrvals`. Decoding the
/// individual values requires walking the bitmap and unpacking in attribute-number
/// order -- that is Phase 4 work; this type handles the wire framing only.
#[derive(Debug, Clone, Default)]
pub struct Fattr4 {
    /// Bitmap indicating which attributes are present in `attrvals`.
    pub bitmap: AttrRequest,
    /// XDR-encoded attribute values, packed end-to-end in bitmap order.
    pub attrvals: Vec<u8>,
}

impl Pack for Fattr4 {
    fn packed_size(&self) -> usize {
        self.bitmap.packed_size() + opaque_packed_size(&self.attrvals)
    }

    fn pack(&self, out: &mut impl Write) -> onc_xdr::Result<usize> {
        let mut n = self.bitmap.pack(out)?;
        n += pack_opaque(&self.attrvals, out)?;
        Ok(n)
    }
}

impl Unpack for Fattr4 {
    fn unpack(input: &mut impl Read) -> onc_xdr::Result<(Self, usize)> {
        let (bitmap, mut n) = AttrRequest::unpack(input)?;
        let (opaque, on) = Opaque::unpack(input)?;
        n += on;
        Ok((Self { bitmap, attrvals: opaque.into_owned() }, n))
    }
}

// --- AttrRequest ---

/// Bitmap of requested NFSv4 attributes (RFC 7530 S5.6).
///
/// Attributes are addressed by bit position across a variable-length word array.
/// Word 0 covers mandatory attributes 0-31, word 1 covers recommended 32-63.
#[derive(Debug, Clone)]
pub struct AttrRequest {
    /// Attribute bitmap words (XDR array of uint32_t).
    pub words: Vec<u32>,
}

impl Default for AttrRequest {
    fn default() -> Self {
        Self::empty()
    }
}

impl AttrRequest {
    /// Request no attributes  --  used when we only want the file handle.
    #[must_use]
    pub fn empty() -> Self {
        Self { words: vec![0, 0] }
    }

    /// Request just fsid (bit 8 in word 0, RFC 7530 S5.8.1.9).
    #[must_use]
    pub fn fsid_only() -> Self {
        // FATTR4_FSID = 8 -> word 0, bit 8
        Self { words: vec![1 << 8, 0] }
    }

    /// Request the SEC_LABEL attribute (attribute 80, RFC 7862 S12.2.4).
    ///
    /// Produces a bitmap with only bit 80 set (word 2, bit 16). The response
    /// contains a `SecLabel4` value when the server supports labeled NFS.
    #[must_use]
    pub fn sec_label() -> Self {
        // Attribute 80 sits in word 2 (80 / 32 = 2), bit 16 (80 % 32 = 16).
        Self { words: vec![0, 0, 1 << 16] }
    }

    /// Request the standard set of file attributes for shell display.
    ///
    /// Includes type, change, size, fsid, fileid (word 0) and mode,
    /// numlinks, owner, owner_group, time_access, time_metadata,
    /// time_modify (word 1).  This matches what `ls -la` needs.
    #[must_use]
    pub fn shell_attrs() -> Self {
        // Word 0: type(1) | change(3) | size(4) | fsid(8) | fileid(20)
        let w0: u32 = (1 << 1) | (1 << 3) | (1 << 4) | (1 << 8) | (1 << 20);
        // Word 1: mode(bit 1, attr 33) | numlinks(bit 3, attr 35) |
        //   owner(bit 4, attr 36) | owner_group(bit 5, attr 37) |
        //   time_access(bit 15, attr 47) | time_metadata(bit 19, attr 51) |
        //   time_modify(bit 20, attr 52)
        let w1: u32 = (1 << 1) | (1 << 3) | (1 << 4) | (1 << 5) | (1 << 15) | (1 << 19) | (1 << 20);
        Self { words: vec![w0, w1] }
    }

    /// Request shell attrs plus filehandle for READDIR (avoids per-entry LOOKUP).
    ///
    /// Adds FATTR4_FILEHANDLE (word 0 bit 19) so READDIR entries carry their
    /// file handles inline, eliminating the need for a separate LOOKUP per entry.
    #[must_use]
    #[expect(clippy::indexing_slicing, reason = "shell_attrs() always returns exactly 2 words")]
    pub fn shell_attrs_with_fh() -> Self {
        let mut ar = Self::shell_attrs();
        // FATTR4_FILEHANDLE (attr 19, word 0 bit 19)
        ar.words[0] |= 1 << 19;
        ar
    }
}

impl Pack for AttrRequest {
    fn packed_size(&self) -> usize {
        // XDR array: 4-byte count + 4 bytes per word
        4 + self.words.len() * 4
    }

    fn pack(&self, out: &mut impl Write) -> onc_xdr::Result<usize> {
        let count = u32::try_from(self.words.len()).map_err(|_| onc_xdr::Error::ObjectTooLarge(self.words.len()))?;
        let mut n = count.pack(out)?;
        for &w in &self.words {
            n += w.pack(out)?;
        }
        Ok(n)
    }
}

impl Unpack for AttrRequest {
    fn unpack(input: &mut impl Read) -> onc_xdr::Result<(Self, usize)> {
        let (count, mut n) = u32::unpack(input)?;
        // Clamp the speculative reservation: `count` is attacker-controlled.
        let mut words = onc_xdr::vec_with_capacity(count as usize);
        for _ in 0..count {
            let (w, wn) = u32::unpack(input)?;
            words.push(w);
            n += wn;
        }
        Ok((Self { words }, n))
    }
}

// --- ArgOp ---

/// A single NFSv4 operation inside a COMPOUND request.
///
/// All 37 NFSv4.0 operations (ops 3-39) plus ILLEGAL (op 10044) are
/// representable. The hot-path operations are fully typed; the stateful
/// ops (OPEN, LOCK, CREATE, etc.) carry pre-encoded XDR payloads so
/// every valid op code can be constructed and serialised without
/// building out the full union nesting.
///
/// Wire format is: 4-byte op code + op-specific data.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum ArgOp {
    // --- Fully typed operations (hot path) ---
    /// Check access rights (op 3, RFC 7530 S16.1).
    Access {
        /// Bitmask of requested access checks (ACCESS4_READ, etc.).
        access: u32,
    },
    /// Return attributes for the current FH (op 9, RFC 7530 S16.7).
    Getattr(AttrRequest),
    /// Return the current file handle as opaque bytes (op 10, RFC 7530 S16.8).
    Getfh,
    /// Look up a single path component in the current directory (op 15, RFC 7530 S16.13).
    Lookup(String),
    /// Look up parent directory -- no arguments (op 16, RFC 7530 S16.14).
    Lookupp,
    /// Set the current FH to a known handle (op 22, RFC 7530 S16.20).
    Putfh(Vec<u8>),
    /// Set the current FH to the server's public (WebNFS) handle (op 23, RFC 7530 S16.21).
    Putpubfh,
    /// Set the current FH to the server's pseudo-root (op 24, RFC 7530 S16.22).
    Putrootfh,
    /// Read file data starting at `offset` (op 25, RFC 7530 S16.23).
    ///
    /// The anonymous stateid (all zeros) allows non-locked reads without OPEN.
    /// Per RFC 7530 S9.1.4.3, seqid=0 and other=\[0;12\] identify the anonymous stateid.
    Read {
        /// 16-byte stateid: 4-byte seqid + 12-byte other (RFC 7530 S9.1.4.3).
        stateid: [u8; 16],
        /// Byte offset from the start of the file.
        offset: u64,
        /// Maximum bytes to return.
        count: u32,
    },
    /// Read directory entries with inline attribute bitmaps (op 26, RFC 7530 S16.24).
    Readdir {
        /// Opaque resume cookie (0 for first call).
        cookie: u64,
        /// Verifier for cookie validity.
        cookieverf: u64,
        /// Maximum bytes of entry names per response.
        dircount: u32,
        /// Maximum bytes of full entries per response.
        maxcount: u32,
        /// Attributes to inline per entry.
        attr_request: AttrRequest,
    },
    /// Read symbolic link target -- no arguments (op 27, RFC 7530 S16.25).
    Readlink,
    /// Remove a filesystem object by name (op 28, RFC 7530 S16.26).
    Remove {
        /// Name of the entry to remove from the current directory.
        target: String,
    },
    /// Rename a filesystem object (op 29, RFC 7530 S16.27).
    ///
    /// Saved FH is source directory, current FH is target directory.
    Rename {
        /// Old name in the saved-FH directory.
        oldname: String,
        /// New name in the current-FH directory.
        newname: String,
    },
    /// Restore saved file handle as current (op 31, RFC 7530 S16.29).
    Restorefh,
    /// Save current file handle (op 32, RFC 7530 S16.30).
    Savefh,
    /// Query supported auth flavors for a named child (op 33, RFC 7530 S16.31).
    Secinfo(String),

    // --- Typed operations with simple arg structs ---
    /// Close an opened file (op 4, RFC 7530 S16.2).
    Close {
        /// Sequence ID for the open-owner.
        seqid: u32,
        /// 16-byte open stateid (4-byte seqid + 12-byte other).
        stateid: [u8; 16],
    },
    /// Commit cached data to stable storage (op 5, RFC 7530 S16.3).
    Commit {
        /// Byte offset to start flushing from.
        offset: u64,
        /// Number of bytes to flush (0 = flush to EOF).
        count: u32,
    },
    /// Purge delegations awaiting recovery (op 7, RFC 7530 S16.5).
    Delegpurge {
        /// Client ID whose delegations to purge.
        clientid: u64,
    },
    /// Return a delegation (op 8, RFC 7530 S16.6).
    Delegreturn {
        /// 16-byte delegation stateid.
        stateid: [u8; 16],
    },
    /// Create a hard link (op 11, RFC 7530 S16.9).
    ///
    /// Saved FH is the source object, current FH is the target directory.
    Link {
        /// Name for the new link in the current directory.
        newname: String,
    },
    /// Open named attribute directory (op 19, RFC 7530 S16.17).
    Openattr {
        /// Whether to create the named-attribute directory if absent.
        createdir: bool,
    },
    /// Confirm an OPEN (op 20, RFC 7530 S16.18).
    OpenConfirm {
        /// 16-byte open stateid returned from the OPEN.
        stateid: [u8; 16],
        /// Sequence ID (must be OPEN seqid + 1).
        seqid: u32,
    },
    /// Reduce open file access/deny modes (op 21, RFC 7530 S16.19).
    OpenDowngrade {
        /// 16-byte open stateid.
        stateid: [u8; 16],
        /// Sequence ID.
        seqid: u32,
        /// Reduced share access mode.
        share_access: u32,
        /// Reduced share deny mode.
        share_deny: u32,
    },
    /// Renew a lease (op 30, RFC 7530 S16.28).
    Renew {
        /// Client ID whose lease to renew.
        clientid: u64,
    },
    /// Confirm a client ID after SETCLIENTID (op 36, RFC 7530 S16.34).
    SetclientidConfirm {
        /// Client ID from the SETCLIENTID response.
        clientid: u64,
        /// 8-byte confirm verifier from the SETCLIENTID response.
        verifier: [u8; 8],
    },
    /// Write data to a file (op 38, RFC 7530 S16.36).
    Write {
        /// 16-byte stateid (RFC 7530 S9.1.4.3).
        stateid: [u8; 16],
        /// Byte offset to start writing at.
        offset: u64,
        /// Stability level: 0 = UNSTABLE4, 1 = DATA_SYNC4, 2 = FILE_SYNC4.
        stable: u32,
        /// File data to write.
        data: Vec<u8>,
    },

    // --- Typed operations (stateful / complex XDR unions) ---
    /// Create a non-regular file object (op 6, RFC 7530 S16.4).
    Create {
        /// Object type to create (directory, symlink, device, etc.).
        objtype: CreateType4,
        /// Name of the new object in the current directory.
        objname: String,
        /// Initial attributes for the new object.
        createattrs: Fattr4,
    },
    /// Create a byte-range lock (op 12, RFC 7530 S16.10).
    Lock {
        /// Type of lock: read, write, blocking read, blocking write.
        locktype: LockType4,
        /// True if reclaiming a lock after server reboot.
        reclaim: bool,
        /// Starting byte offset of the lock range.
        offset: u64,
        /// Length of the lock range (0 = to EOF).
        length: u64,
        /// Lock owner identity (new or existing).
        locker: Locker4,
    },
    /// Test for a byte-range lock (op 13, RFC 7530 S16.11).
    Lockt {
        /// Type of lock to test for.
        locktype: LockType4,
        /// Starting byte offset.
        offset: u64,
        /// Length (0 = to EOF).
        length: u64,
        /// Lock owner whose lock to test.
        owner: LockOwner4,
    },
    /// Unlock a byte-range lock (op 14, RFC 7530 S16.12).
    Locku {
        /// Type of lock to release.
        locktype: LockType4,
        /// Sequence ID for the lock-owner state.
        seqid: u32,
        /// Current lock stateid.
        lock_stateid: Stateid4,
        /// Starting byte offset.
        offset: u64,
        /// Length (0 = to EOF).
        length: u64,
    },
    /// Verify difference in attributes (op 17, RFC 7530 S16.15).
    Nverify {
        /// Attributes to compare against server state.
        obj_attributes: Fattr4,
    },
    /// Open a regular file (op 18, RFC 7530 S16.16).
    Open {
        /// Sequence ID for the open-owner.
        seqid: u32,
        /// Share access mode (RFC 7530 S16.16.3).
        share_access: u32,
        /// Share deny mode (RFC 7530 S16.16.3).
        share_deny: u32,
        /// Open-owner identity.
        owner: OpenOwner4,
        /// Whether and how to create the file.
        openhow: OpenFlag4,
        /// Claim type identifying the file to open.
        claim: OpenClaim4,
    },
    /// Set attributes (op 34, RFC 7530 S16.32).
    Setattr {
        /// Stateid for the open/lock state.
        stateid: Stateid4,
        /// Attributes to set.
        obj_attributes: Fattr4,
    },
    /// Negotiate a client ID (op 35, RFC 7530 S16.33).
    Setclientid {
        /// 8-byte client verifier for detecting reboots.
        client_verifier: [u8; 8],
        /// Opaque client identity.
        client_id: Vec<u8>,
        /// Callback program number.
        cb_program: u32,
        /// Callback network ID (e.g., "tcp").
        cb_netid: String,
        /// Callback universal address (e.g., "h1.h2.h3.h4.p1.p2").
        cb_addr: String,
        /// Callback ident for demuxing.
        callback_ident: u32,
    },
    /// Verify same attributes (op 37, RFC 7530 S16.35).
    Verify {
        /// Attributes to compare against server state.
        obj_attributes: Fattr4,
    },
    /// Release lock-owner state (op 39, RFC 7530 S16.37).
    ReleaseLockowner {
        /// Lock owner whose state to release.
        lock_owner: LockOwner4,
    },
    // --- NFSv4.1 operations (RFC 5661 S18) ---
    /// Establish client identity (op 42, RFC 5661 S18.35).
    ///
    /// Payload: pre-encoded `EXCHANGE_ID4args` body.
    /// Replaces SETCLIENTID in NFSv4.1. The response reveals the server's
    /// implementation id (vendor, version string) and capability flags.
    ExchangeId(Vec<u8>),
    /// Retrieve pNFS device info (op 47, RFC 5661 S18.40).
    ///
    /// Payload: pre-encoded `GETDEVICEINFO4args` body (deviceid + layout_type + maxcount).
    /// Returns data-server addresses, including RDMA endpoints when the file layout
    /// uses the NFSv4.1/files layout type.
    Getdeviceinfo(Vec<u8>),
    /// Enumerate pNFS device IDs (op 48, RFC 5661 S18.41).
    ///
    /// Payload: pre-encoded `GETDEVICELIST4args` body (layout_type + maxdevices + cookie).
    /// Lists all device IDs known to the server for a given layout type.
    Getdevicelist(Vec<u8>),
    /// Get security info for the current FH's export (op 52, RFC 5661 S18.45).
    ///
    /// Unlike SECINFO (which takes a child name), SECINFO_NO_NAME queries the
    /// security policies on the current file handle itself. The argument is a
    /// single u32 style: 0 = SECINFO_STYLE4_CURRENT_FH, 1 = SECINFO_STYLE4_PARENT.
    SecinfoNoName {
        /// 0 = current FH, 1 = parent directory.
        style: u32,
    },

    /// Illegal operation sentinel (op 10044, RFC 7530 S16.38).
    ///
    /// Servers return NFS4ERR_OP_ILLEGAL for this. No arguments.
    Illegal,
}

impl Pack for ArgOp {
    fn packed_size(&self) -> usize {
        match self {
            // No-argument ops: just the 4-byte opcode.
            Self::Putpubfh | Self::Putrootfh | Self::Getfh | Self::Lookupp | Self::Readlink | Self::Restorefh | Self::Savefh | Self::Illegal => 4,

            Self::Putfh(fh) => 4 + opaque_packed_size(fh),
            Self::Lookup(name) | Self::Secinfo(name) | Self::Remove { target: name } | Self::Link { newname: name } => 4 + onc_xdr::string_packed_size(name),
            Self::Getattr(attrs) => 4 + attrs.packed_size(),
            Self::Readdir { attr_request, .. } => 4 + 8 + 8 + 4 + 4 + attr_request.packed_size(),
            // 4 (opcode) + 16 (stateid) + 8 (offset) + 4 (count) = 32
            Self::Read { .. } | Self::OpenDowngrade { .. } => 4 + 16 + 8 + 4,
            // 4 (opcode) + 4 (uint32)
            Self::Access { .. } | Self::Openattr { .. } | Self::SecinfoNoName { .. } => 4 + 4,
            // 4 (opcode) + 4 (seqid) + 16 (stateid) = 24
            Self::Close { .. } | Self::OpenConfirm { .. } => 4 + 4 + 16,
            Self::Commit { .. } => 4 + 8 + 4,
            Self::Delegpurge { .. } | Self::Renew { .. } => 4 + 8,
            // 4 (opcode) + 16 (stateid) = 4 + 8 + 8 = 20
            Self::Delegreturn { .. } | Self::SetclientidConfirm { .. } => 4 + 16,
            Self::Write { data, .. } => 4 + 16 + 8 + 4 + opaque_packed_size(data),
            Self::Rename { oldname, newname } => 4 + onc_xdr::string_packed_size(oldname) + onc_xdr::string_packed_size(newname),

            // Typed stateful ops.
            Self::Create { objtype, objname, createattrs } => 4 + objtype.packed_size() + onc_xdr::string_packed_size(objname) + createattrs.packed_size(),
            Self::Lock { locktype, locker, .. } => 4 + locktype.packed_size() + 4 + 8 + 8 + locker.packed_size(),
            Self::Lockt { locktype, owner, .. } => 4 + locktype.packed_size() + 8 + 8 + owner.packed_size(),
            Self::Locku { locktype, lock_stateid, .. } => 4 + locktype.packed_size() + 4 + lock_stateid.packed_size() + 8 + 8,
            Self::Nverify { obj_attributes } | Self::Verify { obj_attributes } => 4 + obj_attributes.packed_size(),
            Self::Open { owner, openhow, claim, .. } => 4 + 4 + 4 + 4 + owner.packed_size() + openhow.packed_size() + claim.packed_size(),
            Self::Setattr { stateid, obj_attributes } => 4 + stateid.packed_size() + obj_attributes.packed_size(),
            Self::Setclientid { client_id, cb_netid, cb_addr, .. } => 4 + 8 + opaque_packed_size(client_id) + 4 + onc_xdr::string_packed_size(cb_netid) + onc_xdr::string_packed_size(cb_addr) + 4,
            Self::ReleaseLockowner { lock_owner } => 4 + lock_owner.packed_size(),

            // v4.1 opaque-payload ops.
            Self::ExchangeId(payload) | Self::Getdeviceinfo(payload) | Self::Getdevicelist(payload) => 4 + payload.len(),
        }
    }

    fn pack(&self, out: &mut impl Write) -> onc_xdr::Result<usize> {
        match self {
            Self::Putpubfh => OP_PUTPUBFH.pack(out),
            Self::Putrootfh => OP_PUTROOTFH.pack(out),
            Self::Getfh => OP_GETFH.pack(out),
            Self::Lookupp => OP_LOOKUPP.pack(out),
            Self::Readlink => OP_READLINK.pack(out),
            Self::Restorefh => OP_RESTOREFH.pack(out),
            Self::Savefh => OP_SAVEFH.pack(out),
            Self::Illegal => OP_ILLEGAL.pack(out),

            Self::Access { access } => {
                let mut n = OP_ACCESS.pack(out)?;
                n += access.pack(out)?;
                Ok(n)
            },
            Self::Putfh(fh) => {
                let mut n = OP_PUTFH.pack(out)?;
                n += pack_opaque(fh, out)?;
                Ok(n)
            },
            Self::Lookup(name) => {
                let mut n = OP_LOOKUP.pack(out)?;
                n += onc_xdr::pack_string(name, out)?;
                Ok(n)
            },
            Self::Getattr(attrs) => {
                let mut n = OP_GETATTR.pack(out)?;
                n += attrs.pack(out)?;
                Ok(n)
            },
            Self::Secinfo(name) => {
                let mut n = OP_SECINFO.pack(out)?;
                n += onc_xdr::pack_string(name, out)?;
                Ok(n)
            },
            Self::Readdir { cookie, cookieverf, dircount, maxcount, attr_request } => {
                let mut n = OP_READDIR.pack(out)?;
                n += cookie.pack(out)?;
                n += cookieverf.pack(out)?;
                n += dircount.pack(out)?;
                n += maxcount.pack(out)?;
                n += attr_request.pack(out)?;
                Ok(n)
            },
            Self::Read { stateid, offset, count } => {
                let mut n = OP_READ.pack(out)?;
                out.write_all(stateid).map_err(onc_xdr::Error::Io)?;
                n += 16;
                n += offset.pack(out)?;
                n += count.pack(out)?;
                Ok(n)
            },
            Self::Close { seqid, stateid } => {
                let mut n = OP_CLOSE.pack(out)?;
                n += seqid.pack(out)?;
                out.write_all(stateid).map_err(onc_xdr::Error::Io)?;
                n += 16;
                Ok(n)
            },
            Self::Commit { offset, count } => {
                let mut n = OP_COMMIT.pack(out)?;
                n += offset.pack(out)?;
                n += count.pack(out)?;
                Ok(n)
            },
            Self::Delegpurge { clientid } => {
                let mut n = OP_DELEGPURGE.pack(out)?;
                n += clientid.pack(out)?;
                Ok(n)
            },
            Self::Delegreturn { stateid } => {
                let mut n = OP_DELEGRETURN.pack(out)?;
                out.write_all(stateid).map_err(onc_xdr::Error::Io)?;
                n += 16;
                Ok(n)
            },
            Self::Link { newname } => {
                let mut n = OP_LINK.pack(out)?;
                n += onc_xdr::pack_string(newname, out)?;
                Ok(n)
            },
            Self::Openattr { createdir } => {
                let mut n = OP_OPENATTR.pack(out)?;
                let v: u32 = u32::from(*createdir);
                n += v.pack(out)?;
                Ok(n)
            },
            Self::OpenConfirm { stateid, seqid } => {
                let mut n = OP_OPEN_CONFIRM.pack(out)?;
                out.write_all(stateid).map_err(onc_xdr::Error::Io)?;
                n += 16;
                n += seqid.pack(out)?;
                Ok(n)
            },
            Self::OpenDowngrade { stateid, seqid, share_access, share_deny } => {
                let mut n = OP_OPEN_DOWNGRADE.pack(out)?;
                out.write_all(stateid).map_err(onc_xdr::Error::Io)?;
                n += 16;
                n += seqid.pack(out)?;
                n += share_access.pack(out)?;
                n += share_deny.pack(out)?;
                Ok(n)
            },
            Self::Remove { target } => {
                let mut n = OP_REMOVE.pack(out)?;
                n += onc_xdr::pack_string(target, out)?;
                Ok(n)
            },
            Self::Rename { oldname, newname } => {
                let mut n = OP_RENAME.pack(out)?;
                n += onc_xdr::pack_string(oldname, out)?;
                n += onc_xdr::pack_string(newname, out)?;
                Ok(n)
            },
            Self::Renew { clientid } => {
                let mut n = OP_RENEW.pack(out)?;
                n += clientid.pack(out)?;
                Ok(n)
            },
            Self::SetclientidConfirm { clientid, verifier } => {
                let mut n = OP_SETCLIENTID_CONFIRM.pack(out)?;
                n += clientid.pack(out)?;
                out.write_all(verifier).map_err(onc_xdr::Error::Io)?;
                n += 8;
                Ok(n)
            },
            Self::Write { stateid, offset, stable, data } => {
                let mut n = OP_WRITE.pack(out)?;
                out.write_all(stateid).map_err(onc_xdr::Error::Io)?;
                n += 16;
                n += offset.pack(out)?;
                n += stable.pack(out)?;
                n += pack_opaque(data, out)?;
                Ok(n)
            },

            // Typed stateful ops.
            Self::Create { objtype, objname, createattrs } => {
                let mut n = OP_CREATE.pack(out)?;
                n += objtype.pack(out)?;
                n += onc_xdr::pack_string(objname, out)?;
                n += createattrs.pack(out)?;
                Ok(n)
            },
            Self::Lock { locktype, reclaim, offset, length, locker } => {
                let mut n = OP_LOCK.pack(out)?;
                n += locktype.pack(out)?;
                n += u32::from(*reclaim).pack(out)?;
                n += offset.pack(out)?;
                n += length.pack(out)?;
                n += locker.pack(out)?;
                Ok(n)
            },
            Self::Lockt { locktype, offset, length, owner } => {
                let mut n = OP_LOCKT.pack(out)?;
                n += locktype.pack(out)?;
                n += offset.pack(out)?;
                n += length.pack(out)?;
                n += owner.pack(out)?;
                Ok(n)
            },
            Self::Locku { locktype, seqid, lock_stateid, offset, length } => {
                let mut n = OP_LOCKU.pack(out)?;
                n += locktype.pack(out)?;
                n += seqid.pack(out)?;
                n += lock_stateid.pack(out)?;
                n += offset.pack(out)?;
                n += length.pack(out)?;
                Ok(n)
            },
            Self::Nverify { obj_attributes } => {
                let mut n = OP_NVERIFY.pack(out)?;
                n += obj_attributes.pack(out)?;
                Ok(n)
            },
            Self::Open { seqid, share_access, share_deny, owner, openhow, claim } => {
                let mut n = OP_OPEN.pack(out)?;
                n += seqid.pack(out)?;
                n += share_access.pack(out)?;
                n += share_deny.pack(out)?;
                n += owner.pack(out)?;
                n += openhow.pack(out)?;
                n += claim.pack(out)?;
                Ok(n)
            },
            Self::Setattr { stateid, obj_attributes } => {
                let mut n = OP_SETATTR.pack(out)?;
                n += stateid.pack(out)?;
                n += obj_attributes.pack(out)?;
                Ok(n)
            },
            Self::Setclientid { client_verifier, client_id, cb_program, cb_netid, cb_addr, callback_ident } => {
                let mut n = OP_SETCLIENTID.pack(out)?;
                out.write_all(client_verifier).map_err(onc_xdr::Error::Io)?;
                n += 8;
                n += pack_opaque(client_id, out)?;
                n += cb_program.pack(out)?;
                n += onc_xdr::pack_string(cb_netid, out)?;
                n += onc_xdr::pack_string(cb_addr, out)?;
                n += callback_ident.pack(out)?;
                Ok(n)
            },
            Self::Verify { obj_attributes } => {
                let mut n = OP_VERIFY.pack(out)?;
                n += obj_attributes.pack(out)?;
                Ok(n)
            },
            Self::ReleaseLockowner { lock_owner } => {
                let mut n = OP_RELEASE_LOCKOWNER.pack(out)?;
                n += lock_owner.pack(out)?;
                Ok(n)
            },

            // v4.1 opaque-payload ops.
            Self::ExchangeId(payload) => pack_opcode_payload(OP_EXCHANGE_ID, payload, out),
            Self::Getdeviceinfo(payload) => pack_opcode_payload(OP_GETDEVICEINFO, payload, out),
            Self::Getdevicelist(payload) => pack_opcode_payload(OP_GETDEVICELIST, payload, out),
            Self::SecinfoNoName { style } => {
                let mut n = OP_SECINFO_NO_NAME.pack(out)?;
                n += style.pack(out)?;
                Ok(n)
            },
        }
    }
}

/// Pack an opcode followed by a raw pre-encoded payload.
fn pack_opcode_payload(opcode: u32, payload: &[u8], out: &mut impl Write) -> onc_xdr::Result<usize> {
    let mut n = opcode.pack(out)?;
    out.write_all(payload).map_err(onc_xdr::Error::Io)?;
    n += payload.len();
    Ok(n)
}

// --- CompoundArgs ---

/// NFSv4 COMPOUND request (RFC 7530 S15.2.3).
///
/// The entire NFSv4 RPC API is expressed as sequences of operations batched
/// inside a single COMPOUND call. The server processes them in order, stopping
/// at the first error.
#[derive(Debug, Clone)]
pub struct CompoundArgs {
    /// Arbitrary tag for correlating requests with responses (usually empty).
    pub tag: String,
    /// Protocol minor version: 0 for NFSv4.0, 1 for NFSv4.1.
    pub minorversion: u32,
    /// Ordered list of operations to perform.
    pub ops: Vec<ArgOp>,
}

impl Pack for CompoundArgs {
    fn packed_size(&self) -> usize {
        onc_xdr::string_packed_size(&self.tag) + 4 + 4 + self.ops.iter().map(Pack::packed_size).sum::<usize>()
    }

    fn pack(&self, out: &mut impl Write) -> onc_xdr::Result<usize> {
        let mut n = onc_xdr::pack_string(&self.tag, out)?;
        n += self.minorversion.pack(out)?;
        let count = u32::try_from(self.ops.len()).map_err(|_| onc_xdr::Error::ObjectTooLarge(self.ops.len()))?;
        n += count.pack(out)?;
        for op in &self.ops {
            n += op.pack(out)?;
        }
        Ok(n)
    }
}

// --- CompoundBuilder ---

/// Chainable builder for NFSv4 COMPOUND operation sequences.
///
/// Construct via [`CompoundBuilder::new`], chain operations with the builder
/// methods, and finish with [`build`](CompoundBuilder::build) to get a
/// `Vec<ArgOp>` ready for [`CompoundArgs`] or a client's `compound()` method.
///
/// The builder carries no state beyond the op list -- it is a convenience
/// layer over manual `Vec<ArgOp>` construction.
#[derive(Debug, Clone, Default)]
pub struct CompoundBuilder {
    ops: Vec<ArgOp>,
}

impl CompoundBuilder {
    /// Start a new builder with an empty operation sequence.
    #[must_use]
    pub fn new() -> Self {
        Self { ops: Vec::new() }
    }

    /// Consume the builder and return the operation list.
    #[must_use]
    pub fn build(self) -> Vec<ArgOp> {
        self.ops
    }

    /// Append a raw `ArgOp` to the sequence.
    #[must_use]
    pub fn op(mut self, op: ArgOp) -> Self {
        self.ops.push(op);
        self
    }

    /// PUTROOTFH -- set the current FH to the server's pseudo-root (op 24).
    #[must_use]
    pub fn putrootfh(self) -> Self {
        self.op(ArgOp::Putrootfh)
    }

    /// PUTPUBFH -- set the current FH to the server's public (WebNFS) handle (op 23).
    #[must_use]
    pub fn putpubfh(self) -> Self {
        self.op(ArgOp::Putpubfh)
    }

    /// PUTFH -- set the current FH to a known handle (op 22).
    #[must_use]
    pub fn putfh(self, fh: Vec<u8>) -> Self {
        self.op(ArgOp::Putfh(fh))
    }

    /// LOOKUP -- look up a single path component (op 15).
    #[must_use]
    pub fn lookup(self, name: &str) -> Self {
        self.op(ArgOp::Lookup(name.to_owned()))
    }

    /// GETFH -- return the current file handle (op 10).
    #[must_use]
    pub fn getfh(self) -> Self {
        self.op(ArgOp::Getfh)
    }

    /// GETATTR -- return attributes for the current FH (op 9).
    #[must_use]
    pub fn getattr(self, attrs: AttrRequest) -> Self {
        self.op(ArgOp::Getattr(attrs))
    }

    /// SECINFO -- query auth flavors for a named child (op 33).
    #[must_use]
    pub fn secinfo(self, name: &str) -> Self {
        self.op(ArgOp::Secinfo(name.to_owned()))
    }

    /// SETCLIENTID -- negotiate a client ID with callback address (op 35, RFC 7530 S16.33).
    ///
    /// Constructs a typed `ArgOp::Setclientid`:
    /// - `nfs_client_id4`: 8-byte verifier (deterministic) + client name as opaque id
    /// - `cb_client4`: callback program 0x40000000 + clientaddr4(netid="tcp", addr=callback_addr)
    /// - `callback_ident`: 1
    ///
    /// `callback_addr` is the attacker-controlled universal address the server
    /// will dial back to for delegation recalls (RFC 7530 S16.33.3). Format is
    /// "h1.h2.h3.h4.p1.p2" for IPv4.
    #[must_use]
    pub fn setclientid(self, client_name: &str, callback_addr: &str) -> Self {
        self.op(ArgOp::Setclientid {
            // Deterministic verifier for reproducible probes ("nfswolf\0").
            client_verifier: [0x6E, 0x66, 0x73, 0x77, 0x6F, 0x6C, 0x66, 0x00],
            client_id: client_name.as_bytes().to_vec(),
            // Conventional callback program number (RFC 7530 S16.33.5).
            cb_program: 0x4000_0000,
            cb_netid: "tcp".to_owned(),
            cb_addr: callback_addr.to_owned(),
            callback_ident: 1,
        })
    }

    /// SECINFO_NO_NAME -- query auth flavors for the current FH (op 52, RFC 5661 S18.45).
    ///
    /// `style`: 0 = SECINFO_STYLE4_CURRENT_FH, 1 = SECINFO_STYLE4_PARENT.
    /// Unlike SECINFO (which takes a child name), this queries the security
    /// policies on the current file handle itself.
    #[must_use]
    pub fn secinfo_no_name(self, style: u32) -> Self {
        self.op(ArgOp::SecinfoNoName { style })
    }

    /// EXCHANGE_ID -- establish client identity (op 42, RFC 5661 S18.35).
    ///
    /// Constructs the pre-encoded EXCHANGE_ID4args payload. The response reveals
    /// the server's implementation id (vendor string, version) and capability flags
    /// (pNFS support, migration, referrals).
    #[must_use]
    pub fn exchange_id(self, client_name: &str) -> Self {
        let payload = encode_exchange_id(client_name);
        self.op(ArgOp::ExchangeId(payload))
    }

    /// GETDEVICEINFO -- retrieve pNFS device info (op 47, RFC 5661 S18.40).
    ///
    /// `device_id` is the 16-byte device ID, `layout_type` is the layout type
    /// (1 = LAYOUT4_NFSV4_1_FILES). Returns data-server addresses including
    /// any RDMA endpoints.
    #[must_use]
    pub fn getdeviceinfo(self, device_id: &[u8; 16], layout_type: u32) -> Self {
        let payload = encode_getdeviceinfo(device_id, layout_type);
        self.op(ArgOp::Getdeviceinfo(payload))
    }

    /// GETDEVICELIST -- enumerate pNFS device IDs (op 48, RFC 5661 S18.41).
    ///
    /// `layout_type` is the layout type (1 = LAYOUT4_NFSV4_1_FILES).
    /// Returns a list of device IDs that can be passed to GETDEVICEINFO.
    #[must_use]
    pub fn getdevicelist(self, layout_type: u32) -> Self {
        let payload = encode_getdevicelist(layout_type);
        self.op(ArgOp::Getdevicelist(payload))
    }

    /// OPEN with OPEN4_SHARE_ACCESS_READ -- open a file for reading (op 18, RFC 7530 S16.16).
    ///
    /// Constructs a typed `ArgOp::Open` for a read-only open:
    /// - `seqid`: 1 (first open in the sequence)
    /// - `share_access`: OPEN4_SHARE_ACCESS_READ (1)
    /// - `share_deny`: OPEN4_SHARE_DENY_NONE (0)
    /// - `open_owner4`: clientid=0, owner="nfswolf"
    /// - `openhow4`: OPEN4_NOCREATE (0)
    /// - `open_claim4`: CLAIM_NULL (0) + filename
    ///
    /// Requires SETCLIENTID + SETCLIENTID_CONFIRM first, or the server rejects
    /// with NFS4ERR_STALE_CLIENTID. For the "honest write test" use case, the
    /// write probe can try OPEN with OPEN4_SHARE_ACCESS_WRITE instead.
    #[must_use]
    pub fn open_read(self, name: &str) -> Self {
        self.op(ArgOp::Open {
            seqid: 1,
            share_access: 1, // OPEN4_SHARE_ACCESS_READ (RFC 7530 S16.16.3)
            share_deny: 0,   // OPEN4_SHARE_DENY_NONE (RFC 7530 S16.16.3)
            owner: OpenOwner4 { clientid: 0, owner: b"nfswolf".to_vec() },
            openhow: OpenFlag4::NoCreate,
            claim: OpenClaim4::Null(name.to_owned()),
        })
    }

    // --- Phase 5: builder methods for all remaining typed ArgOp variants ---

    /// ACCESS -- check access rights (op 3, RFC 7530 S16.1).
    #[must_use]
    pub fn access(self, access: u32) -> Self {
        self.op(ArgOp::Access { access })
    }

    /// CLOSE -- close an opened file (op 4, RFC 7530 S16.2).
    #[must_use]
    pub fn close(self, seqid: u32, stateid: Stateid4) -> Self {
        self.op(ArgOp::Close { seqid, stateid: stateid.to_bytes() })
    }

    /// COMMIT -- commit cached data to stable storage (op 5, RFC 7530 S16.3).
    #[must_use]
    pub fn commit(self, offset: u64, count: u32) -> Self {
        self.op(ArgOp::Commit { offset, count })
    }

    /// CREATE -- create a non-regular file object (op 6, RFC 7530 S16.4).
    #[must_use]
    pub fn create(self, objtype: CreateType4, objname: &str, createattrs: Fattr4) -> Self {
        self.op(ArgOp::Create { objtype, objname: objname.to_owned(), createattrs })
    }

    /// DELEGPURGE -- purge delegations awaiting recovery (op 7, RFC 7530 S16.5).
    #[must_use]
    pub fn delegpurge(self, clientid: u64) -> Self {
        self.op(ArgOp::Delegpurge { clientid })
    }

    /// DELEGRETURN -- return a delegation (op 8, RFC 7530 S16.6).
    #[must_use]
    pub fn delegreturn(self, stateid: Stateid4) -> Self {
        self.op(ArgOp::Delegreturn { stateid: stateid.to_bytes() })
    }

    /// LINK -- create a hard link (op 11, RFC 7530 S16.9).
    ///
    /// Saved FH is the source object, current FH is the target directory.
    #[must_use]
    pub fn link(self, newname: &str) -> Self {
        self.op(ArgOp::Link { newname: newname.to_owned() })
    }

    /// LOCK -- create a byte-range lock (op 12, RFC 7530 S16.10).
    #[must_use]
    pub fn lock(self, locktype: LockType4, reclaim: bool, offset: u64, length: u64, locker: Locker4) -> Self {
        self.op(ArgOp::Lock { locktype, reclaim, offset, length, locker })
    }

    /// LOCKT -- test for a byte-range lock (op 13, RFC 7530 S16.11).
    #[must_use]
    pub fn lockt(self, locktype: LockType4, offset: u64, length: u64, owner: LockOwner4) -> Self {
        self.op(ArgOp::Lockt { locktype, offset, length, owner })
    }

    /// LOCKU -- unlock a byte-range lock (op 14, RFC 7530 S16.12).
    #[must_use]
    pub fn locku(self, locktype: LockType4, seqid: u32, lock_stateid: Stateid4, offset: u64, length: u64) -> Self {
        self.op(ArgOp::Locku { locktype, seqid, lock_stateid, offset, length })
    }

    /// LOOKUPP -- look up parent directory (op 16, RFC 7530 S16.14).
    #[must_use]
    pub fn lookupp(self) -> Self {
        self.op(ArgOp::Lookupp)
    }

    /// NVERIFY -- verify difference in attributes (op 17, RFC 7530 S16.15).
    #[must_use]
    pub fn nverify(self, obj_attributes: Fattr4) -> Self {
        self.op(ArgOp::Nverify { obj_attributes })
    }

    /// OPEN -- open a regular file (op 18, RFC 7530 S16.16).
    #[must_use]
    pub fn open(self, seqid: u32, share_access: u32, share_deny: u32, owner: OpenOwner4, openhow: OpenFlag4, claim: OpenClaim4) -> Self {
        self.op(ArgOp::Open { seqid, share_access, share_deny, owner, openhow, claim })
    }

    /// OPENATTR -- open named attribute directory (op 19, RFC 7530 S16.17).
    #[must_use]
    pub fn openattr(self, createdir: bool) -> Self {
        self.op(ArgOp::Openattr { createdir })
    }

    /// OPEN_CONFIRM -- confirm an OPEN (op 20, RFC 7530 S16.18).
    #[must_use]
    pub fn open_confirm(self, stateid: Stateid4, seqid: u32) -> Self {
        self.op(ArgOp::OpenConfirm { stateid: stateid.to_bytes(), seqid })
    }

    /// OPEN_DOWNGRADE -- reduce open file access/deny modes (op 21, RFC 7530 S16.19).
    #[must_use]
    pub fn open_downgrade(self, stateid: Stateid4, seqid: u32, share_access: u32, share_deny: u32) -> Self {
        self.op(ArgOp::OpenDowngrade { stateid: stateid.to_bytes(), seqid, share_access, share_deny })
    }

    /// READ -- read file data (op 25, RFC 7530 S16.23).
    #[must_use]
    pub fn read(self, stateid: Stateid4, offset: u64, count: u32) -> Self {
        self.op(ArgOp::Read { stateid: stateid.to_bytes(), offset, count })
    }

    /// READDIR -- read directory entries with inline attributes (op 26, RFC 7530 S16.24).
    #[must_use]
    pub fn readdir(self, cookie: u64, cookieverf: u64, dircount: u32, maxcount: u32, attr_request: AttrRequest) -> Self {
        self.op(ArgOp::Readdir { cookie, cookieverf, dircount, maxcount, attr_request })
    }

    /// READLINK -- read symbolic link target (op 27, RFC 7530 S16.25).
    #[must_use]
    pub fn readlink(self) -> Self {
        self.op(ArgOp::Readlink)
    }

    /// REMOVE -- remove a filesystem object by name (op 28, RFC 7530 S16.26).
    #[must_use]
    pub fn remove(self, target: &str) -> Self {
        self.op(ArgOp::Remove { target: target.to_owned() })
    }

    /// RENAME -- rename a filesystem object (op 29, RFC 7530 S16.27).
    ///
    /// Saved FH is source directory, current FH is target directory.
    #[must_use]
    pub fn rename(self, oldname: &str, newname: &str) -> Self {
        self.op(ArgOp::Rename { oldname: oldname.to_owned(), newname: newname.to_owned() })
    }

    /// RENEW -- renew a lease (op 30, RFC 7530 S16.28).
    #[must_use]
    pub fn renew(self, clientid: u64) -> Self {
        self.op(ArgOp::Renew { clientid })
    }

    /// RESTOREFH -- restore saved file handle as current (op 31, RFC 7530 S16.29).
    #[must_use]
    pub fn restorefh(self) -> Self {
        self.op(ArgOp::Restorefh)
    }

    /// SAVEFH -- save current file handle (op 32, RFC 7530 S16.30).
    #[must_use]
    pub fn savefh(self) -> Self {
        self.op(ArgOp::Savefh)
    }

    /// SETATTR -- set file attributes (op 34, RFC 7530 S16.32).
    #[must_use]
    pub fn setattr(self, stateid: Stateid4, obj_attributes: Fattr4) -> Self {
        self.op(ArgOp::Setattr { stateid, obj_attributes })
    }

    /// SETCLIENTID_CONFIRM -- confirm a client ID (op 36, RFC 7530 S16.34).
    #[must_use]
    pub fn setclientid_confirm(self, clientid: u64, verifier: [u8; 8]) -> Self {
        self.op(ArgOp::SetclientidConfirm { clientid, verifier })
    }

    /// VERIFY -- verify same attributes (op 37, RFC 7530 S16.35).
    #[must_use]
    pub fn verify(self, obj_attributes: Fattr4) -> Self {
        self.op(ArgOp::Verify { obj_attributes })
    }

    /// WRITE -- write data to a file (op 38, RFC 7530 S16.36).
    #[must_use]
    pub fn write(self, stateid: Stateid4, offset: u64, stable: StableHow4, data: Vec<u8>) -> Self {
        self.op(ArgOp::Write { stateid: stateid.to_bytes(), offset, stable: stable.as_u32(), data })
    }

    /// RELEASE_LOCKOWNER -- release lock-owner state (op 39, RFC 7530 S16.37).
    #[must_use]
    pub fn release_lockowner(self, lock_owner: LockOwner4) -> Self {
        self.op(ArgOp::ReleaseLockowner { lock_owner })
    }

    /// ILLEGAL -- illegal operation sentinel (op 10044, RFC 7530 S16.38).
    #[must_use]
    pub fn illegal(self) -> Self {
        self.op(ArgOp::Illegal)
    }
}

/// Pre-encode EXCHANGE_ID4args body (RFC 5661 S18.35).
///
/// Wire layout:
///   eia_clientowner: co_verifier(8 bytes) + co_ownerid(opaque<NFS4_OPAQUE_LIMIT>)
///   eia_flags: u32 (0 = no special capabilities requested)
///   eia_state_protect: state_protect_how4(u32=0 SP4_NONE)
///   eia_client_impl_id: nfs_impl_id4<1> (optional, 0-element array = absent)
fn encode_exchange_id(client_name: &str) -> Vec<u8> {
    let mut buf = Vec::with_capacity(64);

    // co_verifier: 8 bytes (deterministic for reproducible probes).
    buf.extend_from_slice(&[0x6E, 0x66, 0x73, 0x77, 0x6F, 0x6C, 0x66, 0x00]);

    // co_ownerid: opaque<> with client name.
    drop(pack_opaque(client_name.as_bytes(), &mut buf));

    // eia_flags: 0 (no EXCHGID4_FLAG bits set -- pure recon, no pNFS/migration claims).
    buf.extend_from_slice(&0u32.to_be_bytes());

    // eia_state_protect: SP4_NONE (0) -- no state protection negotiation.
    buf.extend_from_slice(&0u32.to_be_bytes());

    // eia_client_impl_id: 0-element optional array (absent).
    buf.extend_from_slice(&0u32.to_be_bytes());

    buf
}

/// Pre-encode GETDEVICEINFO4args body (RFC 5661 S18.40).
///
/// Wire layout:
///   gdia_device_id: deviceid4 (16 bytes, fixed)
///   gdia_layout_type: layouttype4 (u32)
///   gdia_maxcount: u32 (max response size, 0 = server default)
///   gdia_notify_types: bitmap4 (0-word bitmap = no notifications)
fn encode_getdeviceinfo(device_id: &[u8; 16], layout_type: u32) -> Vec<u8> {
    let mut buf = Vec::with_capacity(32);

    // deviceid4: 16 bytes fixed.
    buf.extend_from_slice(device_id);

    // layout_type.
    buf.extend_from_slice(&layout_type.to_be_bytes());

    // maxcount: 65536 (generous but bounded).
    buf.extend_from_slice(&65536u32.to_be_bytes());

    // notify_types bitmap: 0 words (no notifications requested).
    buf.extend_from_slice(&0u32.to_be_bytes());

    buf
}

/// Pre-encode GETDEVICELIST4args body (RFC 5661 S18.41).
///
/// Wire layout:
///   gdla_layout_type: layouttype4 (u32)
///   gdla_maxdevices: u32 (max devices to return)
///   gdla_cookie: u64 (0 for first call)
///   gdla_cookieverf: verifier4 (8 bytes, all-zeros for first call)
fn encode_getdevicelist(layout_type: u32) -> Vec<u8> {
    let mut buf = Vec::with_capacity(24);

    // layout_type.
    buf.extend_from_slice(&layout_type.to_be_bytes());

    // maxdevices: 256 (reasonable bound for recon).
    buf.extend_from_slice(&256u32.to_be_bytes());

    // cookie: 0 (first call).
    buf.extend_from_slice(&0u64.to_be_bytes());

    // cookieverf: all-zeros (first call).
    buf.extend_from_slice(&[0u8; 8]);

    buf
}

// --- CompoundRes ---

/// Decoded NFSv4 file attributes (RFC 7530 S5).
///
/// Produced by `decode_fattr4()` from raw bitmap + attrvals bytes.
/// Only the attributes nfswolf cares about are decoded; the rest are
/// skipped when their wire sizes are known, or decoding stops early
/// when an unknown-size attribute precedes one we need.
#[derive(Debug, Clone, Default)]
pub struct Fattr4Decoded {
    /// File type (attr 1, word 0 bit 1, RFC 7530 S5.8.1.2).
    pub ftype: Option<NfsFtype4>,
    /// Change attribute (attr 3, word 0 bit 3, RFC 7530 S5.8.1.4).
    pub change: Option<u64>,
    /// File size in bytes (attr 4, word 0 bit 4, RFC 7530 S5.8.1.5).
    pub size: Option<u64>,
    /// Filesystem ID (attr 8, word 0 bit 8, RFC 7530 S5.8.1.9).
    pub fsid: Option<(u64, u64)>,
    /// Lease time in seconds (attr 10, word 0 bit 10, RFC 7530 S5.8.1.11).
    pub lease_time: Option<u32>,
    /// File ID / inode number (attr 20, word 0 bit 20, RFC 7530 S5.8.1.21).
    pub fileid: Option<u64>,
    /// POSIX mode bits (attr 33, word 1 bit 1, RFC 7530 S5.8.2.8).
    pub mode: Option<u32>,
    /// Hard link count (attr 35, word 1 bit 3, RFC 7530 S5.8.2.10).
    pub numlinks: Option<u32>,
    /// Owner name (attr 36, word 1 bit 4, RFC 7530 S5.8.2.11).
    pub owner: Option<String>,
    /// Owner group name (attr 37, word 1 bit 5, RFC 7530 S5.8.2.12).
    pub owner_group: Option<String>,
    /// Last access time (attr 47, word 1 bit 15, RFC 7530 S5.8.2.22).
    pub time_access: Option<(i64, u32)>,
    /// Metadata change time (attr 52, word 1 bit 20, RFC 7530 S5.8.2.27).
    pub time_metadata: Option<(i64, u32)>,
    /// Last modify time (attr 53, word 1 bit 21, RFC 7530 S5.8.2.28).
    pub time_modify: Option<(i64, u32)>,
    /// MAC security label (attr 80, word 2 bit 16, RFC 7862 S12.2.4).
    pub sec_label: Option<SecLabel4>,
}

impl Fattr4Decoded {
    /// True when no attributes were decoded.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.ftype.is_none()
            && self.change.is_none()
            && self.size.is_none()
            && self.fsid.is_none()
            && self.lease_time.is_none()
            && self.fileid.is_none()
            && self.mode.is_none()
            && self.numlinks.is_none()
            && self.owner.is_none()
            && self.owner_group.is_none()
            && self.time_access.is_none()
            && self.time_metadata.is_none()
            && self.time_modify.is_none()
            && self.sec_label.is_none()
    }
}

/// Decode fattr4 attribute values from raw bytes given a bitmap.
///
/// Walks the bitmap in order (word 0 bit 0 through word N bit 31).
/// For each set bit, if it maps to a known attribute we decode it and
/// advance the cursor.  If it maps to an attribute whose wire size we
/// know but don't care about (e.g. filehandle, rdattr_error), we skip
/// past it.  If we hit an unknown-size attribute before we've decoded
/// everything, we stop -- remaining fields stay `None`.
///
/// This handles the common case (server returns exactly what we asked for
/// via `AttrRequest::shell_attrs()`) and degrades gracefully otherwise.
#[expect(clippy::indexing_slicing, clippy::match_same_arms, reason = "bounds checked before macro indexing; same-arm returns are intentional for readability")]
fn decode_fattr4(bitmap_words: &[u32], attrvals: &[u8]) -> Fattr4Decoded {
    let mut out = Fattr4Decoded::default();
    let mut off: usize = 0;

    // Helper: read a u32 from attrvals at `off`, advancing.
    macro_rules! read_u32 {
        () => {{
            if off + 4 > attrvals.len() {
                return out;
            }
            let v = u32::from_be_bytes([attrvals[off], attrvals[off + 1], attrvals[off + 2], attrvals[off + 3]]);
            off += 4;
            v
        }};
    }
    macro_rules! read_u64 {
        () => {{
            if off + 8 > attrvals.len() {
                return out;
            }
            let v = u64::from_be_bytes([attrvals[off], attrvals[off + 1], attrvals[off + 2], attrvals[off + 3], attrvals[off + 4], attrvals[off + 5], attrvals[off + 6], attrvals[off + 7]]);
            off += 8;
            v
        }};
    }
    macro_rules! read_i64 {
        () => {{
            if off + 8 > attrvals.len() {
                return out;
            }
            let v = i64::from_be_bytes([attrvals[off], attrvals[off + 1], attrvals[off + 2], attrvals[off + 3], attrvals[off + 4], attrvals[off + 5], attrvals[off + 6], attrvals[off + 7]]);
            off += 8;
            v
        }};
    }

    // Read an XDR string (u32 len + utf8 data + padding) from attrvals.
    macro_rules! read_string {
        () => {{
            let slen = read_u32!() as usize;
            if off + slen > attrvals.len() {
                return out;
            }
            let s = String::from_utf8_lossy(&attrvals[off..off + slen]).into_owned();
            off += slen;
            let pad = (4 - (slen % 4)) % 4;
            off += pad;
            s
        }};
    }

    // Read an XDR opaque (u32 len + data + padding) from attrvals, return raw bytes.
    macro_rules! read_opaque {
        () => {{
            let olen = read_u32!() as usize;
            if off + olen > attrvals.len() {
                return out;
            }
            let data = attrvals[off..off + olen].to_vec();
            off += olen;
            let pad = (4 - (olen % 4)) % 4;
            off += pad;
            data
        }};
    }

    // nfstime4: i64 seconds + u32 nseconds (RFC 7530 S2.2.7).
    macro_rules! read_nfstime4 {
        () => {{
            let secs = read_i64!();
            let nsecs = read_u32!();
            (secs, nsecs)
        }};
    }

    // Known attribute table.  Each entry: (word_index, bit, decode_action).
    // We walk through all bitmap words/bits in order and match against this.
    //
    // Word 0 known bits with their XDR sizes:
    //   0 (supported_attrs): bitmap -- unknown variable size, STOP
    //   1 (type): u32
    //   2 (fh_expire_type): u32 -- skip 4
    //   3 (change): u64
    //   4 (size): u64
    //   5 (link_support): bool(u32) -- skip 4
    //   6 (symlink_support): bool(u32) -- skip 4
    //   7 (named_attr): bool(u32) -- skip 4
    //   8 (fsid): u64+u64
    //   9 (unique_handles): bool(u32) -- skip 4
    //  10 (lease_time): u32
    //  11 (rdattr_error): u32 -- skip 4
    //  12 (acl): variable -- STOP
    //  13 (aclsupport): u32 -- skip 4
    //  14 (archive): bool(u32) -- skip 4
    //  15 (cansettime): bool(u32) -- skip 4
    //  16 (case_insensitive): bool(u32) -- skip 4
    //  17 (case_preserving): bool(u32) -- skip 4
    //  18 (chown_restricted): bool(u32) -- skip 4
    //  19 (filehandle): opaque<> -- variable, skip it
    //  20 (fileid): u64
    //  21 (files_avail): u64 -- skip 8
    //  22 (files_free): u64 -- skip 8
    //  23 (files_total): u64 -- skip 8
    //  24 (fs_locations): variable -- STOP
    //  25 (hidden): bool(u32) -- skip 4
    //  26 (homogeneous): bool(u32) -- skip 4
    //  27 (maxfilesize): u64 -- skip 8
    //  28 (maxlink): u32 -- skip 4
    //  29 (maxname): u32 -- skip 4
    //  30 (maxread): u64 -- skip 8
    //  31 (maxwrite): u64 -- skip 8

    // Walk word 0 bits.
    let w0 = bitmap_words.first().copied().unwrap_or(0);
    for bit in 0..32u32 {
        if w0 & (1 << bit) == 0 {
            continue;
        }
        match bit {
            0 => {
                // supported_attrs: bitmap (variable length array of u32) -- can't skip
                return out;
            },
            1 => out.ftype = Some(NfsFtype4::from_u32(read_u32!())),
            2 => {
                // fh_expire_type: u32
                off += 4;
                if off > attrvals.len() {
                    return out;
                }
            },
            3 => out.change = Some(read_u64!()),
            4 => out.size = Some(read_u64!()),
            5..=7 => {
                // bool(u32): link_support, symlink_support, named_attr
                off += 4;
                if off > attrvals.len() {
                    return out;
                }
            },
            8 => {
                let major = read_u64!();
                let minor = read_u64!();
                out.fsid = Some((major, minor));
            },
            9 => {
                // unique_handles: bool(u32)
                off += 4;
                if off > attrvals.len() {
                    return out;
                }
            },
            10 => out.lease_time = Some(read_u32!()),
            11 => {
                // rdattr_error: u32
                off += 4;
                if off > attrvals.len() {
                    return out;
                }
            },
            12 => {
                // acl: variable length -- can't skip
                return out;
            },
            13..=18 => {
                // u32 each: aclsupport(13), archive(14), cansettime(15),
                //   case_insensitive(16), case_preserving(17), chown_restricted(18)
                off += 4;
                if off > attrvals.len() {
                    return out;
                }
            },
            19 => {
                // filehandle: opaque<> -- variable length, skip past it.
                // We only need the offset advancement; the data is discarded.
                let _fh = read_opaque!();
            },
            20 => out.fileid = Some(read_u64!()),
            21..=23 => {
                // files_avail(21), files_free(22), files_total(23): u64 each
                off += 8;
                if off > attrvals.len() {
                    return out;
                }
            },
            24 => {
                // fs_locations: variable length -- can't skip
                return out;
            },
            25 | 26 => {
                // hidden(25), homogeneous(26): bool(u32)
                off += 4;
                if off > attrvals.len() {
                    return out;
                }
            },
            27 => {
                // maxfilesize: u64
                off += 8;
                if off > attrvals.len() {
                    return out;
                }
            },
            28 | 29 => {
                // maxlink(28), maxname(29): u32
                off += 4;
                if off > attrvals.len() {
                    return out;
                }
            },
            30 | 31 => {
                // maxread(30), maxwrite(31): u64
                off += 8;
                if off > attrvals.len() {
                    return out;
                }
            },
            _ => unreachable!(),
        }
    }

    // Word 1 known bits:
    //   0 (mimetype, attr 32): string -- variable
    //   1 (mode, attr 33): u32
    //   2 (no_trunc, attr 34): bool(u32)
    //   3 (numlinks, attr 35): u32
    //   4 (owner, attr 36): string
    //   5 (owner_group, attr 37): string
    //   6 (quota_avail_hard, attr 38): u64
    //   7 (quota_avail_soft, attr 39): u64
    //   8 (quota_used, attr 40): u64
    //   9 (rawdev, attr 41): specdata4 = u32+u32 = 8 bytes
    //  10 (space_avail, attr 42): u64
    //  11 (space_free, attr 43): u64
    //  12 (space_total, attr 44): u64
    //  13 (space_used, attr 45): u64
    //  14 (system, attr 46): bool(u32)
    //  15 (time_access, attr 47): nfstime4 = i64+u32 = 12 bytes
    //  16 (rdattr_error, attr 48): u32 -- wait, that's not right.
    //      Actually: attr 48 = time_backup, attr 49 = time_create.
    //      Let me re-check the RFC 7530 attribute numbering.
    //
    // Per RFC 7530 Table 4 (S5.4):
    //   32 = mimetype         (string)
    //   33 = mode             (u32)
    //   34 = no_trunc         (bool/u32)
    //   35 = numlinks         (u32)
    //   36 = owner            (string)
    //   37 = owner_group      (string)
    //   38 = quota_avail_hard (u64)
    //   39 = quota_avail_soft (u64)
    //   40 = quota_used       (u64)
    //   41 = rawdev           (specdata4 = 2*u32 = 8 bytes)
    //   42 = space_avail      (u64)
    //   43 = space_free       (u64)
    //   44 = space_total      (u64)
    //   45 = space_used       (u64)
    //   46 = system           (bool/u32)
    //   47 = time_access      (nfstime4 = 12 bytes)
    //   48 = time_backup      (nfstime4 = 12 bytes)
    //   49 = time_create      (nfstime4 = 12 bytes)
    //   50 = time_delta       (nfstime4 = 12 bytes)
    //   51 = time_metadata    (nfstime4 = 12 bytes)  -- NOT 52!
    //   52 = time_modify      (nfstime4 = 12 bytes)  -- NOT 53!
    //   53 = mounted_on_fileid (u64)
    //
    // Wait -- the task description says time_metadata=52, time_modify=53. Let me
    // double-check RFC 7530.  From RFC 7530 Table 4:
    //   51 = time_metadata (word 1 bit 19)
    //   52 = time_modify   (word 1 bit 20)
    //   53 = mounted_on_fileid (word 1 bit 21)
    //
    // Actually, let me recount: 32 + bit_position = attr_number. So:
    //   word 1, bit 0  -> attr 32 (mimetype)
    //   word 1, bit 1  -> attr 33 (mode)
    //   ...
    //   word 1, bit 15 -> attr 47 (time_access)
    //   word 1, bit 16 -> attr 48 (time_backup)
    //   word 1, bit 17 -> attr 49 (time_create)
    //   word 1, bit 18 -> attr 50 (time_delta)
    //   word 1, bit 19 -> attr 51 (time_metadata)
    //   word 1, bit 20 -> attr 52 (time_modify)
    //   word 1, bit 21 -> attr 53 (mounted_on_fileid)
    //
    // The task said:
    //   Bit 15 (time_access, attr 47) -- correct
    //   Bit 16 (rdattr_error, attr 48) -- WRONG, rdattr_error is attr 11 (word 0 bit 11)
    //   Bit 20 (time_metadata, attr 52) -- wrong, that's time_modify
    //   Bit 21 (time_modify, attr 53) -- wrong, that's mounted_on_fileid
    //
    // I'll use the correct RFC 7530 numbering.
    let w1 = bitmap_words.get(1).copied().unwrap_or(0);
    for bit in 0..32u32 {
        if w1 & (1 << bit) == 0 {
            continue;
        }
        match bit {
            0 => {
                // mimetype (attr 32): string -- variable length, skip
                let _mime = read_string!();
            },
            1 => out.mode = Some(read_u32!()),
            2 => {
                // no_trunc (attr 34): bool(u32)
                off += 4;
                if off > attrvals.len() {
                    return out;
                }
            },
            3 => out.numlinks = Some(read_u32!()),
            4 => out.owner = Some(read_string!()),
            5 => out.owner_group = Some(read_string!()),
            6..=8 => {
                // quota_avail_hard(38), quota_avail_soft(39), quota_used(40): u64
                off += 8;
                if off > attrvals.len() {
                    return out;
                }
            },
            9 => {
                // rawdev (attr 41): specdata4 = u32+u32
                off += 8;
                if off > attrvals.len() {
                    return out;
                }
            },
            10..=13 => {
                // space_avail(42), space_free(43), space_total(44), space_used(45): u64
                off += 8;
                if off > attrvals.len() {
                    return out;
                }
            },
            14 => {
                // system (attr 46): bool(u32)
                off += 4;
                if off > attrvals.len() {
                    return out;
                }
            },
            15 => out.time_access = Some(read_nfstime4!()),
            16..=18 => {
                // time_backup(48), time_create(49), time_delta(50): nfstime4 = 12 bytes
                off += 12;
                if off > attrvals.len() {
                    return out;
                }
            },
            19 => out.time_metadata = Some(read_nfstime4!()),
            20 => out.time_modify = Some(read_nfstime4!()),
            21 => {
                // mounted_on_fileid (attr 53): u64
                off += 8;
                if off > attrvals.len() {
                    return out;
                }
            },
            _ => {
                // Unknown word-1 attribute -- can't determine size, stop.
                return out;
            },
        }
    }

    // Word 2 -- only attribute 80 (sec_label) at bit 16.
    let w2 = bitmap_words.get(2).copied().unwrap_or(0);
    for bit in 0..32u32 {
        if w2 & (1 << bit) == 0 {
            continue;
        }
        match bit {
            16 => {
                // sec_label (attr 80): lfs(u32) + pi(u32) + opaque<>
                let lfs = read_u32!();
                let pi = read_u32!();
                let label = read_opaque!();
                out.sec_label = Some(SecLabel4 { lfs, pi, label });
            },
            _ => {
                // Unknown word-2 attribute -- can't determine size, stop.
                return out;
            },
        }
    }

    out
}

/// A single directory entry returned by NFSv4 READDIR (RFC 7530 S16.24).
#[derive(Debug, Clone)]
pub struct DirEntry4 {
    /// Resume cookie for pagination (opaque to the client).
    pub cookie: u64,
    /// Entry name.
    pub name: String,
    /// Decoded inline attributes (populated when the READDIR request
    /// included an `AttrRequest` and the server returned per-entry attrs).
    pub attrs: Option<Fattr4Decoded>,
}

// --- NFSv4.1 types (RFC 8881) ---

/// Server implementation identity (RFC 8881 S18.35).
///
/// Returned inside the EXCHANGE_ID response. The domain and name fields
/// reveal the NFS server vendor and product version -- high-value recon
/// data for fingerprinting the server stack.
#[derive(Debug, Clone)]
pub struct NfsImplId4 {
    /// DNS domain of the implementor (e.g., "kernel.org").
    pub domain: String,
    /// Implementation name / version string (e.g., "Linux NFS 6.1").
    pub name: String,
    /// Build date as `(seconds_since_epoch, nanoseconds)`.
    pub date: (u64, u32),
}

// --- NFSv4.2 types (RFC 7862) ---

/// FATTR4_SEC_LABEL attribute number (attribute 80, RFC 7862 S12.2.4).
///
/// Bit 80 in the attribute bitmap = word 2, bit 16.
pub const FATTR4_SEC_LABEL: u32 = 80;

/// MAC security label (RFC 7862 S12.2.4, attribute 80).
///
/// Carries the SELinux/Smack/AppArmor label assigned to a file.
/// The `label` field contains the raw context string bytes
/// (e.g., `b"system_u:object_r:nfs_t:s0"` for SELinux).
#[derive(Debug, Clone)]
pub struct SecLabel4 {
    /// Label Format Specifier -- identifies the MAC model.
    pub lfs: u32,
    /// Policy Identifier -- further qualifies the LFS.
    pub pi: u32,
    /// Raw label bytes (opaque to the wire layer; interpretation is model-specific).
    pub label: Vec<u8>,
}

/// One entry from a SECINFO / SECINFO_NO_NAME response (RFC 7530 S16.31).
///
/// Simple flavors (AUTH_NONE, AUTH_SYS, AUTH_DH) carry only the flavor number.
/// RPCSEC_GSS (flavor 6) additionally carries the GSS mechanism OID, QOP hint,
/// and service level (1=none/auth-only, 2=integrity, 3=privacy).
#[derive(Debug, Clone)]
pub struct SecInfoEntry {
    /// Auth flavor number (RFC 5531 S8.2).
    pub flavor: u32,
    /// GSS mechanism OID bytes (DER-encoded), when flavor == 6.
    pub gss_oid: Option<Vec<u8>>,
    /// Quality-of-protection hint, when flavor == 6 (usually 0 = default).
    pub gss_qop: Option<u32>,
    /// GSS service level, when flavor == 6. RFC 2203 S5.2.2:
    /// 1 = rpc_gss_svc_none (auth only, no per-message protection),
    /// 2 = rpc_gss_svc_integrity (MIC on every message),
    /// 3 = rpc_gss_svc_privacy (encrypted payload).
    pub gss_service: Option<u32>,
}

impl SecInfoEntry {
    /// The raw flavor number (convenience for callers that just need the u32).
    #[must_use]
    pub const fn flavor(&self) -> u32 {
        self.flavor
    }
}

/// Decoded payload from a successful NFSv4 operation result.
///
/// Most operations produce no inline data beyond the status code.
/// GETFH, READDIR, READ, SECINFO, ACCESS, READLINK, COMMIT, and WRITE
/// carry operation-specific results that are decoded. Other ops' results
/// are represented as `None`.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub enum ResOpData {
    /// File handle bytes from GETFH (RFC 7530 S16.8).
    Fh(Vec<u8>),
    /// Decoded file attributes from GETATTR (RFC 7530 S16.7).
    ///
    /// Contains all decoded attributes from the response bitmap.
    /// Access individual fields (fsid, mode, owner, etc.) through
    /// the `Fattr4Decoded` struct.
    Getattr(Fattr4Decoded),
    /// Directory entries from READDIR (RFC 7530 S16.24), plus EOF flag.
    Readdir {
        /// Server's cookie verifier (RFC 7530 S16.24).
        ///
        /// Must be echoed back verbatim on the next READDIR continuation call
        /// so the server can detect directory mutations between pages.
        /// First call sends all-zeros; subsequent calls echo this value.
        cookieverf: [u8; 8],
        /// Entries decoded from the READDIR linked list.
        entries: Vec<DirEntry4>,
        /// True if this is the last page of directory entries.
        eof: bool,
    },
    /// File data from READ (RFC 7530 S16.23), plus EOF flag.
    Read {
        /// True if this read reached the end of the file.
        eof: bool,
        /// File data bytes.
        data: Vec<u8>,
    },
    /// Security info entries from SECINFO / SECINFO_NO_NAME (RFC 7530 S16.31).
    ///
    /// Each entry carries the auth flavor and, for RPCSEC_GSS (flavor 6), the
    /// mechanism OID, QOP, and service level from the `rpcsec_gss_info` struct.
    SecFlavors(Vec<SecInfoEntry>),
    /// ACCESS result: supported + access bitmasks (RFC 7530 S16.1).
    Access {
        /// Access rights the server can reliably verify.
        supported: u32,
        /// Access rights available to the requesting user.
        access: u32,
    },
    /// Symbolic link target from READLINK (RFC 7530 S16.25).
    Readlink(String),
    /// Write verifier from COMMIT (RFC 7530 S16.3).
    CommitVerf([u8; 8]),
    /// WRITE result: bytes written, stability, verifier (RFC 7530 S16.36).
    WriteRes {
        /// Number of bytes actually written.
        count: u32,
        /// Stability level committed: 0 = UNSTABLE4, 1 = DATA_SYNC4, 2 = FILE_SYNC4.
        committed: u32,
        /// 8-byte write verifier for detecting server reboots.
        writeverf: [u8; 8],
    },
    // --- NFSv4.1 result variants (RFC 8881) ---
    /// EXCHANGE_ID result: server identity and capabilities (op 42, RFC 8881 S18.35).
    ///
    /// Contains the server's client ID assignment, capability flags, and
    /// implementation identity (vendor, version, build date).
    ExchangeId {
        /// Server-assigned client ID.
        clientid: u64,
        /// Sequence ID for the client ID slot.
        sequenceid: u32,
        /// Server capability flags (EXCHGID4_FLAG_* bits, RFC 8881 S18.35.3).
        flags: u32,
        /// Server owner major ID (identifies the server instance).
        server_owner: Vec<u8>,
        /// Server scope (identifies the server's administrative domain).
        server_scope: Vec<u8>,
        /// Server implementation identity (0 or 1 element; vendor, product, build date).
        impl_id: Vec<NfsImplId4>,
    },
    /// GETDEVICEINFO result: pNFS device address (op 47, RFC 8881 S18.40).
    ///
    /// The `device_addr` bytes carry the layout-type-specific address structure
    /// (e.g., `nfsv4_1_file_layout_ds_addr4` for `LAYOUT4_NFSV4_1_FILES`).
    GetDeviceInfo {
        /// Layout type this address applies to.
        layout_type: u32,
        /// Opaque device address body (layout-type-specific encoding).
        device_addr: Vec<u8>,
        /// Notification bitmap word 0 (which change notifications the server supports).
        notification: u32,
    },
    /// GETDEVICELIST result: enumerated pNFS device IDs (op 48, RFC 8881 S18.41).
    ///
    /// Lists device IDs that can be passed to GETDEVICEINFO. Paginated via
    /// cookie/cookieverf like READDIR.
    GetDeviceList {
        /// Resume cookie for the next page.
        cookie: u64,
        /// Cookie verifier -- echo back for pagination integrity.
        cookieverf: [u8; 8],
        /// Device IDs (each 16 bytes, fixed size per RFC 8881).
        deviceid_list: Vec<[u8; 16]>,
        /// True if this is the last page of device IDs.
        eof: bool,
    },

    /// Change info from directory-mutating ops: REMOVE, LINK (RFC 7530 S16.26/S16.9).
    ChangeInfo(ChangeInfo4),
    /// Rename result: source and target change info (RFC 7530 S16.27).
    RenameInfo {
        /// Change info for the source directory.
        source: ChangeInfo4,
        /// Change info for the target directory.
        target: ChangeInfo4,
    },
    /// Stateid from CLOSE, OPEN_CONFIRM, OPEN_DOWNGRADE, LOCK, LOCKU (RFC 7530 S16.2/S16.10/S16.12).
    Stateid(Stateid4),
    /// Bitmap from SETATTR result (RFC 7530 S16.32).
    Bitmap(Vec<u32>),
    /// SETCLIENTID result: clientid + confirm verifier (RFC 7530 S16.33).
    Setclientid {
        /// Server-assigned client ID.
        clientid: u64,
        /// Verifier to pass to SETCLIENTID_CONFIRM.
        confirm_verifier: [u8; 8],
    },
    /// CREATE result: change info + attributes set bitmap (RFC 7530 S16.4).
    Create {
        /// Change info for the directory where the object was created.
        cinfo: ChangeInfo4,
        /// Bitmap of attributes the server actually set.
        attrset: Vec<u32>,
    },
    /// OPEN result: full stateful open response (RFC 7530 S16.16).
    Open {
        /// Stateid for the opened file.
        stateid: Stateid4,
        /// Change info for the directory (if CLAIM_NULL/CLAIM_DELEGATE_CUR).
        cinfo: ChangeInfo4,
        /// Result flags (OPEN4_RESULT_* bits, RFC 7530 S16.16.4).
        rflags: u32,
        /// Bitmap of attributes the server set (from createattrs).
        attrset: Vec<u32>,
        /// Delegation granted by the server.
        delegation: OpenDelegation4,
    },

    /// No result data  --  PUTPUBFH, PUTROOTFH, PUTFH, LOOKUP, LOOKUPP,
    /// DELEGPURGE, DELEGRETURN, OPENATTR, RENEW, RESTOREFH, SAVEFH,
    /// SETCLIENTID_CONFIRM, LOCKT, RELEASE_LOCKOWNER, ILLEGAL, NVERIFY,
    /// VERIFY, and other ops with no result payload beyond status.
    #[default]
    None,
}

/// Single operation result inside a COMPOUND response.
///
/// Carries the op code, NFS4 status, and (for data-carrying ops) decoded result data.
#[derive(Debug, Clone)]
pub struct ResOp {
    /// Operation code that produced this result.
    pub op_code: u32,
    /// NFS4 status (0 = NFS4_OK, non-zero = error).
    pub status: u32,
    /// Decoded operation-specific result data.
    pub data: ResOpData,
}

/// NFSv4 COMPOUND response (RFC 7530 S15.2.3).
#[derive(Debug, Clone)]
pub struct CompoundRes {
    /// Top-level status  --  status of the first failing op, or NFS4_OK.
    pub status: u32,
    /// Echo of the request tag.
    pub tag: String,
    /// Per-operation results.
    pub results: Vec<ResOp>,
}

impl Unpack for CompoundRes {
    fn unpack(input: &mut impl Read) -> onc_xdr::Result<(Self, usize)> {
        let (status, n0) = u32::unpack(input)?;
        let (tag, n1) = onc_xdr::unpack_string(input)?;
        let (count, n2) = u32::unpack(input)?;
        let mut n = n0 + n1 + n2;
        // Clamp the speculative reservation: `count` is attacker-controlled.
        let mut results = onc_xdr::vec_with_capacity(count as usize);
        for _ in 0..count {
            let (op_code, on) = u32::unpack(input)?;
            let (op_status, sn) = u32::unpack(input)?;
            n += on + sn;
            // If the op failed, the server stops here  --  no more results follow.
            if op_status != 0 {
                results.push(ResOp { op_code, status: op_status, data: ResOpData::None });
                break;
            }
            // Decode op-specific result data.  Unknown or complex ops that can't
            // be decoded safely stop further parsing  --  results so far are valid.
            if let Ok((data, dn)) = decode_op_result_data(op_code, input) {
                n += dn;
                results.push(ResOp { op_code, status: op_status, data });
            } else {
                results.push(ResOp { op_code, status: op_status, data: ResOpData::None });
                break;
            }
        }
        Ok((Self { status, tag, results }, n))
    }
}

/// Decode op-specific result data from a successful COMPOUND response op.
///
/// Returns `(ResOpData, bytes_consumed)`.  Returns `Err` for any op whose
/// wire format cannot be safely decoded  --  the caller's loop should stop
/// at that point; all results collected before the error are valid.
///
/// All 37 NFSv4.0 ops (3-39) plus ILLEGAL (10044) are fully decoded.
/// NFSv4.1 ops (EXCHANGE_ID, GETDEVICEINFO, GETDEVICELIST, SECINFO_NO_NAME)
/// are also handled.
fn decode_op_result_data(op_code: u32, input: &mut impl Read) -> onc_xdr::Result<(ResOpData, usize)> {
    match op_code {
        // --- No result data beyond status ---
        // LOCKT: on NFS4_OK the response is VOID (no lock conflict = 0 bytes).
        OP_PUTPUBFH | OP_PUTROOTFH | OP_PUTFH | OP_LOOKUP | OP_LOOKUPP | OP_RESTOREFH | OP_SAVEFH | OP_DELEGPURGE | OP_DELEGRETURN | OP_OPENATTR | OP_RENEW | OP_NVERIFY | OP_VERIFY | OP_RELEASE_LOCKOWNER | OP_ILLEGAL | OP_LOCKT | OP_SETCLIENTID_CONFIRM => Ok((ResOpData::None, 0)),

        // ACCESS result: supported(u32) + access(u32) (RFC 7530 S16.1).
        OP_ACCESS => {
            let (supported, mut n) = u32::unpack(input)?;
            let (access, an) = u32::unpack(input)?;
            n += an;
            Ok((ResOpData::Access { supported, access }, n))
        },

        // GETFH result: opaque<> file handle (4-byte length + data + padding).
        OP_GETFH => {
            let (len, mut n) = u32::unpack(input)?;
            let len = len as usize;
            let fh = onc_xdr::read_bytes(input, len)?;
            n += len;
            let pad = (4 - (len % 4)) % 4;
            onc_xdr::skip_pad(input, pad)?;
            n += pad;
            Ok((ResOpData::Fh(fh), n))
        },

        // GETATTR result: bitmap (u32 count + N words) + opaque<> attrvals.
        // The bitmap tells which attributes are present; attrvals carries their
        // XDR-encoded values packed in bitmap order. `decode_fattr4()` walks the
        // bitmap and decodes all attributes nfswolf understands.
        OP_GETATTR => {
            let (bitmap_count, mut n) = u32::unpack(input)?;
            let mut bitmap_words = Vec::with_capacity(bitmap_count as usize);
            for _ in 0..bitmap_count {
                let (w, wn) = u32::unpack(input)?;
                bitmap_words.push(w);
                n += wn;
            }
            let (attrval_len, ln) = u32::unpack(input)?;
            n += ln;
            let attrval_len = attrval_len as usize;
            let attrvals = onc_xdr::read_bytes(input, attrval_len)?;
            n += attrval_len;
            let pad = (4 - (attrval_len % 4)) % 4;
            onc_xdr::skip_pad(input, pad)?;
            n += pad;

            let decoded = decode_fattr4(&bitmap_words, &attrvals);
            Ok((ResOpData::Getattr(decoded), n))
        },

        // SECINFO / SECINFO_NO_NAME result: variable-length array of secinfo4.
        // Same wire format for both (RFC 5661 S18.45.3).
        OP_SECINFO | OP_SECINFO_NO_NAME => {
            let (arr_count, mut n) = u32::unpack(input)?;
            let mut entries = onc_xdr::vec_with_capacity(arr_count as usize);
            for _ in 0..arr_count {
                let (flavor, fn_) = u32::unpack(input)?;
                n += fn_;
                if flavor == 6 {
                    // RPCSEC_GSS: sec_oid4 opaque<> + qop u32 + service u32
                    let (oid, on) = Opaque::unpack(input)?;
                    n += on;
                    let (qop, qn) = u32::unpack(input)?;
                    n += qn;
                    let (service, sn) = u32::unpack(input)?;
                    n += sn;
                    entries.push(SecInfoEntry { flavor, gss_oid: Some(oid.into_owned()), gss_qop: Some(qop), gss_service: Some(service) });
                } else {
                    entries.push(SecInfoEntry { flavor, gss_oid: None, gss_qop: None, gss_service: None });
                }
            }
            Ok((ResOpData::SecFlavors(entries), n))
        },

        // READ result: bool eof (u32) + opaque<> file data.
        OP_READ => {
            let (eof_raw, mut n) = u32::unpack(input)?;
            let (data_len, dn) = u32::unpack(input)?;
            n += dn;
            let data_len = data_len as usize;
            let data = onc_xdr::read_bytes(input, data_len)?;
            n += data_len;
            let pad = (4 - (data_len % 4)) % 4;
            onc_xdr::skip_pad(input, pad)?;
            n += pad;
            Ok((ResOpData::Read { eof: eof_raw != 0, data }, n))
        },

        // READDIR result: verifier[8] + linked-list entries + eof.
        // Each entry carries inline fattr4: bitmap + attrvals opaque.
        OP_READDIR => {
            let mut verifier = [0u8; 8];
            input.read_exact(&mut verifier).map_err(onc_xdr::Error::Io)?;
            let mut n = 8;
            let mut entries = Vec::new();
            loop {
                let (value_follows, vn) = u32::unpack(input)?;
                n += vn;
                if value_follows == 0 {
                    break;
                }
                let (cookie, cn) = u64::unpack(input)?;
                n += cn;
                let (name, nn) = onc_xdr::unpack_string(input)?;
                n += nn;
                // Read per-entry fattr4: bitmap words + attrvals opaque.
                let (bitmap_count, bn) = u32::unpack(input)?;
                n += bn;
                let mut entry_bitmap = Vec::with_capacity(bitmap_count as usize);
                for _ in 0..bitmap_count {
                    let (w, wn) = u32::unpack(input)?;
                    entry_bitmap.push(w);
                    n += wn;
                }
                let (attrval_len, aln) = u32::unpack(input)?;
                n += aln;
                let attrval_len = attrval_len as usize;
                let entry_attrvals = onc_xdr::read_bytes(input, attrval_len)?;
                n += attrval_len;
                let pad = (4 - (attrval_len % 4)) % 4;
                onc_xdr::skip_pad(input, pad)?;
                n += pad;

                // Decode attributes if the server sent any.
                let attrs = if entry_bitmap.iter().any(|&w| w != 0) && !entry_attrvals.is_empty() {
                    let decoded = decode_fattr4(&entry_bitmap, &entry_attrvals);
                    if decoded.is_empty() { None } else { Some(decoded) }
                } else {
                    None
                };

                entries.push(DirEntry4 { cookie, name, attrs });
            }
            let (eof_raw, en) = u32::unpack(input)?;
            n += en;
            Ok((ResOpData::Readdir { cookieverf: verifier, entries, eof: eof_raw != 0 }, n))
        },

        // READLINK result: linktext4 (= opaque string, RFC 7530 S16.25).
        OP_READLINK => {
            let (link, n) = onc_xdr::unpack_string(input)?;
            Ok((ResOpData::Readlink(link), n))
        },

        // COMMIT result: verifier4 writeverf (8 bytes, RFC 7530 S16.3).
        OP_COMMIT => {
            let mut verf = [0u8; 8];
            input.read_exact(&mut verf).map_err(onc_xdr::Error::Io)?;
            Ok((ResOpData::CommitVerf(verf), 8))
        },

        // WRITE result: count(u32) + committed(u32) + writeverf(8 bytes).
        OP_WRITE => {
            let (count, mut n) = u32::unpack(input)?;
            let (committed, cn) = u32::unpack(input)?;
            n += cn;
            let mut writeverf = [0u8; 8];
            input.read_exact(&mut writeverf).map_err(onc_xdr::Error::Io)?;
            n += 8;
            Ok((ResOpData::WriteRes { count, committed, writeverf }, n))
        },

        // REMOVE / LINK result: change_info4 (RFC 7530 S16.26 / S16.9).
        OP_REMOVE | OP_LINK => {
            let (cinfo, n) = ChangeInfo4::unpack(input)?;
            Ok((ResOpData::ChangeInfo(cinfo), n))
        },

        // RENAME result: source_cinfo + target_cinfo (two change_info4, RFC 7530 S16.27).
        OP_RENAME => {
            let (source, mut n) = ChangeInfo4::unpack(input)?;
            let (target, tn) = ChangeInfo4::unpack(input)?;
            n += tn;
            Ok((ResOpData::RenameInfo { source, target }, n))
        },

        // SETATTR result: bitmap4 attrsset (RFC 7530 S16.32).
        OP_SETATTR => {
            let (bitmap_count, mut n) = u32::unpack(input)?;
            let mut words = onc_xdr::vec_with_capacity(bitmap_count as usize);
            for _ in 0..bitmap_count {
                let (w, wn) = u32::unpack(input)?;
                n += wn;
                words.push(w);
            }
            Ok((ResOpData::Bitmap(words), n))
        },

        // CLOSE / OPEN_CONFIRM / OPEN_DOWNGRADE / LOCKU / LOCK result: stateid4 (16 bytes).
        OP_CLOSE | OP_OPEN_CONFIRM | OP_OPEN_DOWNGRADE | OP_LOCKU | OP_LOCK => {
            let (sid, n) = Stateid4::unpack(input)?;
            Ok((ResOpData::Stateid(sid), n))
        },

        // EXCHANGE_ID result (RFC 8881 S18.35.3).
        //
        // Decodes the server's identity, capability flags, and impl_id.
        // Only SP4_NONE state protection is decodable -- SP4_MACH_CRED and
        // SP4_SSV have complex nested structures that stop parsing.
        OP_EXCHANGE_ID => {
            let (clientid, mut n) = u64::unpack(input)?;
            let (sequenceid, sn) = u32::unpack(input)?;
            n += sn;
            let (flags, fn_) = u32::unpack(input)?;
            n += fn_;
            // state_protect4_r: union on state_protect_how4.
            // SP4_NONE (0) carries no additional data; anything else is
            // too complex to skip without the full ops-pair / SSV types.
            let (protect_how, pn) = u32::unpack(input)?;
            n += pn;
            if protect_how != 0 {
                return Err(onc_xdr::Error::InvalidEnumValue(protect_how));
            }
            // server_owner4: so_minor_id(u64) + so_major_id(opaque<>).
            // Minor ID is typically 0 on Linux knfsd; only the major ID
            // (server identity string) matters for recon.
            let (_, mn) = u64::unpack(input)?;
            n += mn;
            let (major_len, mln) = u32::unpack(input)?;
            n += mln;
            let major_len_usize = major_len as usize;
            let server_owner = onc_xdr::read_bytes(input, major_len_usize)?;
            n += major_len_usize;
            let pad = (4 - (major_len_usize % 4)) % 4;
            onc_xdr::skip_pad(input, pad)?;
            n += pad;
            // server_scope: opaque<>.
            let (scope_len, scn) = u32::unpack(input)?;
            n += scn;
            let scope_len_usize = scope_len as usize;
            let server_scope = onc_xdr::read_bytes(input, scope_len_usize)?;
            n += scope_len_usize;
            let scope_pad = (4 - (scope_len_usize % 4)) % 4;
            onc_xdr::skip_pad(input, scope_pad)?;
            n += scope_pad;
            // server_impl_id: array<nfs_impl_id4> (0 or 1 element per RFC).
            let (impl_count, icn) = u32::unpack(input)?;
            n += icn;
            let mut impl_id = onc_xdr::vec_with_capacity(impl_count as usize);
            for _ in 0..impl_count {
                let (domain, dn) = onc_xdr::unpack_string(input)?;
                n += dn;
                let (name, nn) = onc_xdr::unpack_string(input)?;
                n += nn;
                // nfstime4: seconds(int64/hyper) + nseconds(uint32).
                // Read as u64 -- the sign bit is irrelevant for recon timestamps.
                let (seconds, tsn) = u64::unpack(input)?;
                n += tsn;
                let (nseconds, nsn) = u32::unpack(input)?;
                n += nsn;
                impl_id.push(NfsImplId4 { domain, name, date: (seconds, nseconds) });
            }
            Ok((ResOpData::ExchangeId { clientid, sequenceid, flags, server_owner, server_scope, impl_id }, n))
        },

        // GETDEVICEINFO result (RFC 8881 S18.40.3).
        OP_GETDEVICEINFO => {
            // device_addr4: da_layout_type(u32) + da_addr_body(opaque<>).
            let (layout_type, mut n) = u32::unpack(input)?;
            let (addr_len, aln) = u32::unpack(input)?;
            n += aln;
            let addr_len_usize = addr_len as usize;
            let device_addr = onc_xdr::read_bytes(input, addr_len_usize)?;
            n += addr_len_usize;
            let pad = (4 - (addr_len_usize % 4)) % 4;
            onc_xdr::skip_pad(input, pad)?;
            n += pad;
            // notification: bitmap4 (array of u32 words).
            let (notify_count, ncn) = u32::unpack(input)?;
            n += ncn;
            let mut notification = 0u32;
            for i in 0..notify_count {
                let (w, wn) = u32::unpack(input)?;
                n += wn;
                // Only word 0 is stored; higher words are read and discarded.
                if i == 0 {
                    notification = w;
                }
            }
            Ok((ResOpData::GetDeviceInfo { layout_type, device_addr, notification }, n))
        },

        // GETDEVICELIST result (RFC 8881 S18.41.3).
        OP_GETDEVICELIST => {
            let (cookie, mut n) = u64::unpack(input)?;
            let mut cookieverf = [0u8; 8];
            input.read_exact(&mut cookieverf).map_err(onc_xdr::Error::Io)?;
            n += 8;
            // deviceid_list: array of deviceid4 (each 16 bytes, fixed).
            let (dev_count, dcn) = u32::unpack(input)?;
            n += dcn;
            let mut deviceid_list = onc_xdr::vec_with_capacity(dev_count as usize);
            for _ in 0..dev_count {
                let mut devid = [0u8; 16];
                input.read_exact(&mut devid).map_err(onc_xdr::Error::Io)?;
                n += 16;
                deviceid_list.push(devid);
            }
            let (eof_raw, en) = u32::unpack(input)?;
            n += en;
            Ok((ResOpData::GetDeviceList { cookie, cookieverf, deviceid_list, eof: eof_raw != 0 }, n))
        },

        // SETCLIENTID result: clientid4 (u64) + verifier4 (8 bytes) (RFC 7530 S16.33).
        OP_SETCLIENTID => {
            let (clientid, mut n) = u64::unpack(input)?;
            let mut confirm_verifier = [0u8; 8];
            input.read_exact(&mut confirm_verifier).map_err(onc_xdr::Error::Io)?;
            n += 8;
            Ok((ResOpData::Setclientid { clientid, confirm_verifier }, n))
        },

        // CREATE result: change_info4 + bitmap4 attrset (RFC 7530 S16.4).
        OP_CREATE => {
            let (cinfo, mut n) = ChangeInfo4::unpack(input)?;
            let (bitmap_count, bcn) = u32::unpack(input)?;
            n += bcn;
            let mut attrset = onc_xdr::vec_with_capacity(bitmap_count as usize);
            for _ in 0..bitmap_count {
                let (w, wn) = u32::unpack(input)?;
                n += wn;
                attrset.push(w);
            }
            Ok((ResOpData::Create { cinfo, attrset }, n))
        },

        // OPEN result: stateid4 + change_info4 + rflags + bitmap4 + open_delegation4
        // (RFC 7530 S16.16).
        OP_OPEN => {
            let (stateid, mut n) = Stateid4::unpack(input)?;
            let (cinfo, cn) = ChangeInfo4::unpack(input)?;
            n += cn;
            let (rflags, rn) = u32::unpack(input)?;
            n += rn;
            // bitmap4 attrset.
            let (bitmap_count, bcn) = u32::unpack(input)?;
            n += bcn;
            let mut attrset = onc_xdr::vec_with_capacity(bitmap_count as usize);
            for _ in 0..bitmap_count {
                let (w, wn) = u32::unpack(input)?;
                n += wn;
                attrset.push(w);
            }
            // open_delegation4: discriminated union.
            let (deleg_type, dtn) = u32::unpack(input)?;
            n += dtn;
            let delegation = match deleg_type {
                0 => OpenDelegation4::None,
                1 => {
                    // OPEN_DELEGATE_READ: stateid4 + bool recall + nfsace4.
                    let (del_sid, sn) = Stateid4::unpack(input)?;
                    n += sn;
                    let (recall_raw, rn2) = u32::unpack(input)?;
                    n += rn2;
                    let (ace, an) = NfsAce4::unpack(input)?;
                    n += an;
                    OpenDelegation4::Read { stateid: del_sid, recall: recall_raw != 0, ace }
                },
                2 => {
                    // OPEN_DELEGATE_WRITE: stateid4 + bool recall + space_limit4 + nfsace4.
                    let (del_sid, sn) = Stateid4::unpack(input)?;
                    n += sn;
                    let (recall_raw, rn2) = u32::unpack(input)?;
                    n += rn2;
                    // nfs_space_limit4: union on limit_by.
                    let (limit_by, lbn) = u32::unpack(input)?;
                    n += lbn;
                    let space_limit = match limit_by {
                        1 => {
                            // NFS_LIMIT_SIZE: u64 filesize.
                            let (size, szn) = u64::unpack(input)?;
                            n += szn;
                            SpaceLimit4::Size(size)
                        },
                        2 => {
                            // NFS_LIMIT_BLOCKS: u64 num_blocks + u32 bytes_per_block.
                            let (num_blocks, nbn) = u64::unpack(input)?;
                            n += nbn;
                            let (bytes_per_block, bpn) = u32::unpack(input)?;
                            n += bpn;
                            SpaceLimit4::Blocks { num_blocks, bytes_per_block }
                        },
                        _ => return Err(onc_xdr::Error::InvalidEnumValue(limit_by)),
                    };
                    let (ace, an) = NfsAce4::unpack(input)?;
                    n += an;
                    OpenDelegation4::Write { stateid: del_sid, recall: recall_raw != 0, space_limit, ace }
                },
                _ => return Err(onc_xdr::Error::InvalidEnumValue(deleg_type)),
            };
            Ok((ResOpData::Open { stateid, cinfo, rflags, attrset, delegation }, n))
        },

        // Ops with complex/variable result unions that cannot be skipped
        // without a full decoder, plus anything unknown -- stop parsing here.
        // Results so far are valid.
        _ => Err(onc_xdr::Error::InvalidEnumValue(op_code)),
    }
}

// --- NFSv4 status codes ---

/// NFSv4 status codes (RFC 7530 S13.1).
///
/// Common values nfswolf tests for are named variants; anything else is
/// captured as `Unknown(u32)` so callers can still inspect the raw code
/// rather than silently mapping every unrecognized value to `BadXdr`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Nfs4Status {
    /// No error (NFS4_OK = 0).
    Ok,
    /// Not owner (NFS4ERR_PERM = 1, RFC 7530 S13.1.6).
    Perm,
    /// No such file or directory (NFS4ERR_NOENT = 2, RFC 7530 S13.1.6).
    NoEnt,
    /// I/O error (NFS4ERR_IO = 5, RFC 7530 S13.1.6).
    Io,
    /// No such device or address (NFS4ERR_NXIO = 6, RFC 7530 S13.1.6).
    Nxio,
    /// Permission denied (NFS4ERR_ACCESS = 13, RFC 7530 S13.1.6).
    Acces,
    /// File exists (NFS4ERR_EXIST = 17, RFC 7530 S13.1.6).
    Exist,
    /// Not a directory (NFS4ERR_NOTDIR = 20, RFC 7530 S13.1.6).
    NotDir,
    /// Is a directory (NFS4ERR_ISDIR = 21, RFC 7530 S13.1.6).
    IsDir,
    /// Invalid argument (NFS4ERR_INVAL = 22, RFC 7530 S13.1.6).
    Inval,
    /// File too large (NFS4ERR_FBIG = 27, RFC 7530 S13.1.6).
    Fbig,
    /// No space on device (NFS4ERR_NOSPC = 28, RFC 7530 S13.1.6).
    NoSpc,
    /// Read-only filesystem (NFS4ERR_ROFS = 30, RFC 7530 S13.1.6).
    Rofs,
    /// Name too long (NFS4ERR_NAMETOOLONG = 63, RFC 7530 S13.1.6).
    NameTooLong,
    /// Directory not empty (NFS4ERR_NOTEMPTY = 66, RFC 7530 S13.1.6).
    NotEmpty,
    /// Stale file handle (NFS4ERR_STALE = 70, RFC 7530 S13.1.6).
    Stale,
    /// Illegal file handle (NFS4ERR_BADHANDLE = 10001, RFC 7530 S13.1.6).
    BadHandle,
    /// Bad cookie for READDIR (NFS4ERR_BAD_COOKIE = 10003, RFC 7530 S13.1.6).
    BadCookie,
    /// Operation not supported by server (NFS4ERR_NOTSUPP = 10004, RFC 7530 S13.1.6).
    NotSupp,
    /// Lock request denied (NFS4ERR_DENIED = 10010, RFC 7530 S13.1.6).
    Denied,
    /// Lock lease expired (NFS4ERR_EXPIRED = 10011, RFC 7530 S13.1.6).
    Expired,
    /// File is locked (NFS4ERR_LOCKED = 10012, RFC 7530 S13.1.6).
    Locked,
    /// Wrong security flavor for this export (NFS4ERR_WRONGSEC = 10016, RFC 7530 S13.1.6).
    WrongSec,
    /// Filesystem has been moved (NFS4ERR_MOVED = 10019, RFC 7530 S13.1.6).
    Moved,
    /// Malformed XDR in request (NFS4ERR_BADXDR = 10036, RFC 7530 S13.1.6).
    BadXdr,
    /// Cross-device link (NFS4ERR_XDEV = 18, RFC 7530 S13.1.6).
    Xdev,
    /// Too many hard links (NFS4ERR_MLINK = 31, RFC 7530 S13.1.6).
    Mlink,
    /// Disk quota exceeded (NFS4ERR_DQUOT = 69, RFC 7530 S13.1.6).
    Dquot,
    /// Buffer too small for result (NFS4ERR_TOOSMALL = 10005, RFC 7530 S13.1.6).
    TooSmall,
    /// Internal server error (NFS4ERR_SERVERFAULT = 10006, RFC 7530 S13.1.6).
    ServerFault,
    /// Object type mismatch (NFS4ERR_BADTYPE = 10007, RFC 7530 S13.1.6).
    BadType,
    /// Operation delayed, retry later (NFS4ERR_DELAY = 10008, RFC 7530 S13.1.6).
    Delay,
    /// Attributes are the same (NFS4ERR_SAME = 10009, RFC 7530 S13.1.6).
    Same,
    /// Server in grace period (NFS4ERR_GRACE = 10013, RFC 7530 S13.1.6).
    Grace,
    /// File handle has expired (NFS4ERR_FHEXPIRED = 10014, RFC 7530 S13.1.6).
    FhExpired,
    /// Share reservation conflict (NFS4ERR_SHARE_DENIED = 10015, RFC 7530 S13.1.6).
    ShareDenied,
    /// Client ID already in use (NFS4ERR_CLID_INUSE = 10017, RFC 7530 S13.1.6).
    ClidInuse,
    /// Server resource exhaustion (NFS4ERR_RESOURCE = 10018, RFC 7530 S13.1.6).
    Resource,
    /// No current file handle set (NFS4ERR_NOFILEHANDLE = 10020, RFC 7530 S13.1.6).
    NoFilehandle,
    /// Minor version not supported (NFS4ERR_MINOR_VERS_MISMATCH = 10021, RFC 7530 S13.1.6).
    MinorVersMismatch,
    /// Client ID is stale (NFS4ERR_STALE_CLIENTID = 10022, RFC 7530 S13.1.6).
    StaleClientid,
    /// Stateid is stale (NFS4ERR_STALE_STATEID = 10023, RFC 7530 S13.1.6).
    StaleStateid,
    /// Stateid has old seqid (NFS4ERR_OLD_STATEID = 10024, RFC 7530 S13.1.6).
    OldStateid,
    /// Stateid is invalid (NFS4ERR_BAD_STATEID = 10025, RFC 7530 S13.1.6).
    BadStateid,
    /// Sequence ID is invalid (NFS4ERR_BAD_SEQID = 10026, RFC 7530 S13.1.6).
    BadSeqid,
    /// VERIFY found attributes differ (NFS4ERR_NOT_SAME = 10027, RFC 7530 S13.1.6).
    NotSame,
    /// Lock range not supported (NFS4ERR_LOCK_RANGE = 10028, RFC 7530 S13.1.6).
    LockRange,
    /// Should have followed a symlink (NFS4ERR_SYMLINK = 10029, RFC 7530 S13.1.6).
    Symlink,
    /// RESTOREFH with no saved handle (NFS4ERR_RESTOREFH = 10030, RFC 7530 S13.1.6).
    RestoreFh,
    /// Lease has moved to another server (NFS4ERR_LEASE_MOVED = 10031, RFC 7530 S13.1.6).
    LeaseMoved,
    /// Attribute not supported (NFS4ERR_ATTRNOTSUPP = 10032, RFC 7530 S13.1.6).
    AttrNotSupp,
    /// Reclaim outside grace period (NFS4ERR_NO_GRACE = 10033, RFC 7530 S13.1.6).
    NoGrace,
    /// Reclaim of bad state (NFS4ERR_RECLAIM_BAD = 10034, RFC 7530 S13.1.6).
    ReclaimBad,
    /// Reclaim conflict with another client (NFS4ERR_RECLAIM_CONFLICT = 10035, RFC 7530 S13.1.6).
    ReclaimConflict,
    /// Locks are still held (NFS4ERR_LOCKS_HELD = 10037, RFC 7530 S13.1.6).
    LocksHeld,
    /// Conflicting open mode (NFS4ERR_OPENMODE = 10038, RFC 7530 S13.1.6).
    Openmode,
    /// Owner translation failed (NFS4ERR_BADOWNER = 10039, RFC 7530 S13.1.6).
    BadOwner,
    /// Invalid character in name (NFS4ERR_BADCHAR = 10040, RFC 7530 S13.1.6).
    BadChar,
    /// Invalid name (NFS4ERR_BADNAME = 10041, RFC 7530 S13.1.6).
    BadName,
    /// Lock range not representable (NFS4ERR_BAD_RANGE = 10042, RFC 7530 S13.1.6).
    BadRange,
    /// Locking not supported (NFS4ERR_LOCK_NOTSUPP = 10043, RFC 7530 S13.1.6).
    LockNotSupp,
    /// Illegal operation code (NFS4ERR_OP_ILLEGAL = 10044, RFC 7530 S13.1.6).
    OpIllegal,
    /// Deadlock detected (NFS4ERR_DEADLOCK = 10045, RFC 7530 S13.1.6).
    Deadlock,
    /// File is open, operation not allowed (NFS4ERR_FILE_OPEN = 10046, RFC 7530 S13.1.6).
    FileOpen,
    /// State revoked by admin (NFS4ERR_ADMIN_REVOKED = 10047, RFC 7530 S13.1.6).
    AdminRevoked,
    /// Callback path down (NFS4ERR_CB_PATH_DOWN = 10048, RFC 7530 S13.1.6).
    CbPathDown,
    /// Any status code not explicitly listed above.
    Unknown(u32),
}

impl Nfs4Status {
    /// Decode a u32 from the wire into a known variant or `Unknown`.
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
            18 => Self::Xdev,
            20 => Self::NotDir,
            21 => Self::IsDir,
            22 => Self::Inval,
            27 => Self::Fbig,
            28 => Self::NoSpc,
            30 => Self::Rofs,
            31 => Self::Mlink,
            63 => Self::NameTooLong,
            66 => Self::NotEmpty,
            69 => Self::Dquot,
            70 => Self::Stale,
            10001 => Self::BadHandle,
            10003 => Self::BadCookie,
            10004 => Self::NotSupp,
            10005 => Self::TooSmall,
            10006 => Self::ServerFault,
            10007 => Self::BadType,
            10008 => Self::Delay,
            10009 => Self::Same,
            10010 => Self::Denied,
            10011 => Self::Expired,
            10012 => Self::Locked,
            10013 => Self::Grace,
            10014 => Self::FhExpired,
            10015 => Self::ShareDenied,
            10016 => Self::WrongSec,
            10017 => Self::ClidInuse,
            10018 => Self::Resource,
            10019 => Self::Moved,
            10020 => Self::NoFilehandle,
            10021 => Self::MinorVersMismatch,
            10022 => Self::StaleClientid,
            10023 => Self::StaleStateid,
            10024 => Self::OldStateid,
            10025 => Self::BadStateid,
            10026 => Self::BadSeqid,
            10027 => Self::NotSame,
            10028 => Self::LockRange,
            10029 => Self::Symlink,
            10030 => Self::RestoreFh,
            10031 => Self::LeaseMoved,
            10032 => Self::AttrNotSupp,
            10033 => Self::NoGrace,
            10034 => Self::ReclaimBad,
            10035 => Self::ReclaimConflict,
            10036 => Self::BadXdr,
            10037 => Self::LocksHeld,
            10038 => Self::Openmode,
            10039 => Self::BadOwner,
            10040 => Self::BadChar,
            10041 => Self::BadName,
            10042 => Self::BadRange,
            10043 => Self::LockNotSupp,
            10044 => Self::OpIllegal,
            10045 => Self::Deadlock,
            10046 => Self::FileOpen,
            10047 => Self::AdminRevoked,
            10048 => Self::CbPathDown,
            other => Self::Unknown(other),
        }
    }

    /// Convert back to the raw u32 wire value.
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        match self {
            Self::Ok => 0,
            Self::Perm => 1,
            Self::NoEnt => 2,
            Self::Io => 5,
            Self::Nxio => 6,
            Self::Acces => 13,
            Self::Exist => 17,
            Self::Xdev => 18,
            Self::NotDir => 20,
            Self::IsDir => 21,
            Self::Inval => 22,
            Self::Fbig => 27,
            Self::NoSpc => 28,
            Self::Rofs => 30,
            Self::Mlink => 31,
            Self::NameTooLong => 63,
            Self::NotEmpty => 66,
            Self::Dquot => 69,
            Self::Stale => 70,
            Self::BadHandle => 10001,
            Self::BadCookie => 10003,
            Self::NotSupp => 10004,
            Self::TooSmall => 10005,
            Self::ServerFault => 10006,
            Self::BadType => 10007,
            Self::Delay => 10008,
            Self::Same => 10009,
            Self::Denied => 10010,
            Self::Expired => 10011,
            Self::Locked => 10012,
            Self::Grace => 10013,
            Self::FhExpired => 10014,
            Self::ShareDenied => 10015,
            Self::WrongSec => 10016,
            Self::ClidInuse => 10017,
            Self::Resource => 10018,
            Self::Moved => 10019,
            Self::NoFilehandle => 10020,
            Self::MinorVersMismatch => 10021,
            Self::StaleClientid => 10022,
            Self::StaleStateid => 10023,
            Self::OldStateid => 10024,
            Self::BadStateid => 10025,
            Self::BadSeqid => 10026,
            Self::NotSame => 10027,
            Self::LockRange => 10028,
            Self::Symlink => 10029,
            Self::RestoreFh => 10030,
            Self::LeaseMoved => 10031,
            Self::AttrNotSupp => 10032,
            Self::NoGrace => 10033,
            Self::ReclaimBad => 10034,
            Self::ReclaimConflict => 10035,
            Self::BadXdr => 10036,
            Self::LocksHeld => 10037,
            Self::Openmode => 10038,
            Self::BadOwner => 10039,
            Self::BadChar => 10040,
            Self::BadName => 10041,
            Self::BadRange => 10042,
            Self::LockNotSupp => 10043,
            Self::OpIllegal => 10044,
            Self::Deadlock => 10045,
            Self::FileOpen => 10046,
            Self::AdminRevoked => 10047,
            Self::CbPathDown => 10048,
            Self::Unknown(v) => v,
        }
    }

    /// True when the server returned success (NFS4_OK = 0, RFC 7530 S13.1).
    #[must_use]
    pub const fn is_ok(self) -> bool {
        matches!(self, Self::Ok)
    }

    /// True for permission errors (NFS4ERR_PERM, NFS4ERR_ACCESS).
    ///
    /// Expected during credential probing -- must never trip the circuit breaker.
    #[must_use]
    pub const fn is_permission_denied(self) -> bool {
        matches!(self, Self::Perm | Self::Acces)
    }

    /// True when the file handle was well-formed but names nothing that exists.
    ///
    /// NFS4ERR_STALE (70, RFC 7530 S13.1.6) is the positive half of the
    /// handle oracle: the server parsed the handle layout and looked it up,
    /// so only the inode/generation is wrong.
    #[must_use]
    pub const fn is_stale(self) -> bool {
        matches!(self, Self::Stale)
    }

    /// True for "no such file or directory" (NFS4ERR_NOENT = 2, RFC 7530 S13.1.6).
    #[must_use]
    pub const fn is_not_found(self) -> bool {
        matches!(self, Self::NoEnt)
    }

    /// True for transient errors that should trip the circuit breaker.
    ///
    /// Permission denials are NOT transient -- they're expected during UID spraying.
    #[must_use]
    pub const fn is_transient(self) -> bool {
        matches!(self, Self::Io | Self::Delay | Self::Resource | Self::ServerFault)
    }

    /// True for stateid-related errors that indicate stale or revoked state.
    ///
    /// Callers should discard the affected stateid and re-open / re-lock.
    #[must_use]
    pub const fn is_stateid_error(self) -> bool {
        matches!(self, Self::StaleStateid | Self::OldStateid | Self::BadStateid | Self::Expired | Self::AdminRevoked)
    }

    /// True for lease-level errors requiring client ID re-establishment.
    #[must_use]
    pub const fn is_lease_error(self) -> bool {
        matches!(self, Self::StaleClientid | Self::Expired | Self::LeaseMoved)
    }

    /// True for grace-period errors during server recovery.
    #[must_use]
    pub const fn is_grace_error(self) -> bool {
        matches!(self, Self::Grace | Self::NoGrace | Self::ReclaimBad | Self::ReclaimConflict)
    }

    /// True for locking and share-reservation errors.
    #[must_use]
    pub const fn is_lock_error(self) -> bool {
        matches!(self, Self::Denied | Self::Locked | Self::ShareDenied | Self::BadSeqid | Self::LockRange | Self::LocksHeld | Self::Openmode | Self::BadRange | Self::LockNotSupp | Self::Deadlock)
    }

    // --- Single-variant predicates for crash recovery scenarios ---

    /// True when the server is in grace period and only allows reclaim operations.
    #[must_use]
    pub const fn is_grace(self) -> bool {
        matches!(self, Self::Grace)
    }

    /// True when the client ID is stale (server rebooted or client expired).
    #[must_use]
    pub const fn is_stale_clientid(self) -> bool {
        matches!(self, Self::StaleClientid)
    }

    /// True when all state for this client has expired.
    #[must_use]
    pub const fn is_expired(self) -> bool {
        matches!(self, Self::Expired)
    }
}

impl core::fmt::Display for Nfs4Status {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Ok => f.write_str("NFS4_OK"),
            Self::Perm => f.write_str("NFS4ERR_PERM"),
            Self::NoEnt => f.write_str("NFS4ERR_NOENT"),
            Self::Io => f.write_str("NFS4ERR_IO"),
            Self::Nxio => f.write_str("NFS4ERR_NXIO"),
            Self::Acces => f.write_str("NFS4ERR_ACCESS"),
            Self::Exist => f.write_str("NFS4ERR_EXIST"),
            Self::Xdev => f.write_str("NFS4ERR_XDEV"),
            Self::NotDir => f.write_str("NFS4ERR_NOTDIR"),
            Self::IsDir => f.write_str("NFS4ERR_ISDIR"),
            Self::Inval => f.write_str("NFS4ERR_INVAL"),
            Self::Fbig => f.write_str("NFS4ERR_FBIG"),
            Self::NoSpc => f.write_str("NFS4ERR_NOSPC"),
            Self::Rofs => f.write_str("NFS4ERR_ROFS"),
            Self::Mlink => f.write_str("NFS4ERR_MLINK"),
            Self::NameTooLong => f.write_str("NFS4ERR_NAMETOOLONG"),
            Self::NotEmpty => f.write_str("NFS4ERR_NOTEMPTY"),
            Self::Dquot => f.write_str("NFS4ERR_DQUOT"),
            Self::Stale => f.write_str("NFS4ERR_STALE"),
            Self::BadHandle => f.write_str("NFS4ERR_BADHANDLE"),
            Self::BadCookie => f.write_str("NFS4ERR_BAD_COOKIE"),
            Self::NotSupp => f.write_str("NFS4ERR_NOTSUPP"),
            Self::TooSmall => f.write_str("NFS4ERR_TOOSMALL"),
            Self::ServerFault => f.write_str("NFS4ERR_SERVERFAULT"),
            Self::BadType => f.write_str("NFS4ERR_BADTYPE"),
            Self::Delay => f.write_str("NFS4ERR_DELAY"),
            Self::Same => f.write_str("NFS4ERR_SAME"),
            Self::Denied => f.write_str("NFS4ERR_DENIED"),
            Self::Expired => f.write_str("NFS4ERR_EXPIRED"),
            Self::Locked => f.write_str("NFS4ERR_LOCKED"),
            Self::Grace => f.write_str("NFS4ERR_GRACE"),
            Self::FhExpired => f.write_str("NFS4ERR_FHEXPIRED"),
            Self::ShareDenied => f.write_str("NFS4ERR_SHARE_DENIED"),
            Self::WrongSec => f.write_str("NFS4ERR_WRONGSEC"),
            Self::ClidInuse => f.write_str("NFS4ERR_CLID_INUSE"),
            Self::Resource => f.write_str("NFS4ERR_RESOURCE"),
            Self::Moved => f.write_str("NFS4ERR_MOVED"),
            Self::NoFilehandle => f.write_str("NFS4ERR_NOFILEHANDLE"),
            Self::MinorVersMismatch => f.write_str("NFS4ERR_MINOR_VERS_MISMATCH"),
            Self::StaleClientid => f.write_str("NFS4ERR_STALE_CLIENTID"),
            Self::StaleStateid => f.write_str("NFS4ERR_STALE_STATEID"),
            Self::OldStateid => f.write_str("NFS4ERR_OLD_STATEID"),
            Self::BadStateid => f.write_str("NFS4ERR_BAD_STATEID"),
            Self::BadSeqid => f.write_str("NFS4ERR_BAD_SEQID"),
            Self::NotSame => f.write_str("NFS4ERR_NOT_SAME"),
            Self::LockRange => f.write_str("NFS4ERR_LOCK_RANGE"),
            Self::Symlink => f.write_str("NFS4ERR_SYMLINK"),
            Self::RestoreFh => f.write_str("NFS4ERR_RESTOREFH"),
            Self::LeaseMoved => f.write_str("NFS4ERR_LEASE_MOVED"),
            Self::AttrNotSupp => f.write_str("NFS4ERR_ATTRNOTSUPP"),
            Self::NoGrace => f.write_str("NFS4ERR_NO_GRACE"),
            Self::ReclaimBad => f.write_str("NFS4ERR_RECLAIM_BAD"),
            Self::ReclaimConflict => f.write_str("NFS4ERR_RECLAIM_CONFLICT"),
            Self::BadXdr => f.write_str("NFS4ERR_BADXDR"),
            Self::LocksHeld => f.write_str("NFS4ERR_LOCKS_HELD"),
            Self::Openmode => f.write_str("NFS4ERR_OPENMODE"),
            Self::BadOwner => f.write_str("NFS4ERR_BADOWNER"),
            Self::BadChar => f.write_str("NFS4ERR_BADCHAR"),
            Self::BadName => f.write_str("NFS4ERR_BADNAME"),
            Self::BadRange => f.write_str("NFS4ERR_BAD_RANGE"),
            Self::LockNotSupp => f.write_str("NFS4ERR_LOCK_NOTSUPP"),
            Self::OpIllegal => f.write_str("NFS4ERR_OP_ILLEGAL"),
            Self::Deadlock => f.write_str("NFS4ERR_DEADLOCK"),
            Self::FileOpen => f.write_str("NFS4ERR_FILE_OPEN"),
            Self::AdminRevoked => f.write_str("NFS4ERR_ADMIN_REVOKED"),
            Self::CbPathDown => f.write_str("NFS4ERR_CB_PATH_DOWN"),
            Self::Unknown(n) => write!(f, "NFS4ERR_UNKNOWN({n})"),
        }
    }
}

impl std::error::Error for Nfs4Status {}

// ---------------------------------------------------------------------------
// Domain types -- stable public API consumed by the shell and analyzer
// ---------------------------------------------------------------------------

/// File type for shell display (RFC 7530 S5.8.1.2).
///
/// Maps from the wire `NfsFtype4` enum but is independent of the wire
/// representation so consumers don't couple to encoding details.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Nfs4FileType {
    /// Regular file.
    Regular,
    /// Directory.
    Directory,
    /// Symbolic link.
    Symlink,
    /// Block device.
    BlockDev,
    /// Character device.
    CharDev,
    /// Socket.
    Socket,
    /// Named pipe / FIFO.
    Fifo,
    /// Named attribute.
    NamedAttr,
    /// Named-attribute directory.
    AttrDir,
    /// Unrecognized wire value.
    Unknown,
}

impl From<NfsFtype4> for Nfs4FileType {
    fn from(ft: NfsFtype4) -> Self {
        match ft {
            NfsFtype4::Reg => Self::Regular,
            NfsFtype4::Dir => Self::Directory,
            NfsFtype4::Lnk => Self::Symlink,
            NfsFtype4::Blk => Self::BlockDev,
            NfsFtype4::Chr => Self::CharDev,
            NfsFtype4::Sock => Self::Socket,
            NfsFtype4::Fifo => Self::Fifo,
            NfsFtype4::NamedAttr => Self::NamedAttr,
            NfsFtype4::AttrDir => Self::AttrDir,
            NfsFtype4::Unknown(_) => Self::Unknown,
        }
    }
}

/// Decoded file attributes for shell display.
///
/// Constructed from `Fattr4Decoded` but drops wire-only fields (lease_time,
/// sec_label) that the shell never needs. This is the version-neutral API
/// surface the shell's `ShellOps` trait maps into.
#[derive(Debug, Clone, Default)]
pub struct Nfs4FileInfo {
    /// File type (regular, directory, symlink, etc.).
    pub ftype: Option<Nfs4FileType>,
    /// File size in bytes.
    pub size: Option<u64>,
    /// POSIX permission mode bits.
    pub mode: Option<u32>,
    /// Owner name (UTF-8 user@domain or numeric string).
    pub owner: Option<String>,
    /// Owner group name (UTF-8 group@domain or numeric string).
    pub owner_group: Option<String>,
    /// Hard link count.
    pub numlinks: Option<u32>,
    /// File ID / inode number.
    pub fileid: Option<u64>,
    /// Filesystem ID as (major, minor).
    pub fsid: Option<(u64, u64)>,
    /// Change attribute (opaque server-managed version counter).
    pub change: Option<u64>,
    /// Last access time as (seconds, nanoseconds).
    pub time_access: Option<(i64, u32)>,
    /// Last modification time as (seconds, nanoseconds).
    pub time_modify: Option<(i64, u32)>,
    /// Metadata change time as (seconds, nanoseconds).
    pub time_metadata: Option<(i64, u32)>,
}

impl From<Fattr4Decoded> for Nfs4FileInfo {
    fn from(d: Fattr4Decoded) -> Self {
        Self { ftype: d.ftype.map(Nfs4FileType::from), size: d.size, mode: d.mode, owner: d.owner, owner_group: d.owner_group, numlinks: d.numlinks, fileid: d.fileid, fsid: d.fsid, change: d.change, time_access: d.time_access, time_modify: d.time_modify, time_metadata: d.time_metadata }
    }
}

/// Directory entry with optional attributes and file handle.
///
/// Built from the raw `DirEntry4` after READDIR + GETATTR + GETFH, carrying
/// only what the shell and analyzer need for display and traversal.
#[derive(Debug, Clone)]
pub struct Nfs4DirEntry {
    /// Entry name (component, not a full path).
    pub name: String,
    /// READDIR cookie for resumption.
    pub cookie: u64,
    /// File handle, present when GETFH was included in the READDIR attrs.
    pub fh: Option<Vec<u8>>,
    /// Decoded attributes, present when GETATTR was included.
    pub info: Option<Nfs4FileInfo>,
}

#[cfg(test)]
mod tests {
    #![expect(clippy::pedantic, unused_results, reason = "unit test  --  lints are suppressed per project policy")]
    use super::*;

    #[test]
    #[expect(clippy::cognitive_complexity, reason = "flat list of assert_eq! checking all known status codes")]
    fn nfs4_status_from_u32_maps_known_codes() {
        assert_eq!(Nfs4Status::from_u32(0), Nfs4Status::Ok);
        assert_eq!(Nfs4Status::from_u32(1), Nfs4Status::Perm);
        assert_eq!(Nfs4Status::from_u32(2), Nfs4Status::NoEnt);
        assert_eq!(Nfs4Status::from_u32(5), Nfs4Status::Io);
        assert_eq!(Nfs4Status::from_u32(6), Nfs4Status::Nxio);
        assert_eq!(Nfs4Status::from_u32(13), Nfs4Status::Acces);
        assert_eq!(Nfs4Status::from_u32(17), Nfs4Status::Exist);
        assert_eq!(Nfs4Status::from_u32(18), Nfs4Status::Xdev);
        assert_eq!(Nfs4Status::from_u32(20), Nfs4Status::NotDir);
        assert_eq!(Nfs4Status::from_u32(21), Nfs4Status::IsDir);
        assert_eq!(Nfs4Status::from_u32(22), Nfs4Status::Inval);
        assert_eq!(Nfs4Status::from_u32(27), Nfs4Status::Fbig);
        assert_eq!(Nfs4Status::from_u32(28), Nfs4Status::NoSpc);
        assert_eq!(Nfs4Status::from_u32(30), Nfs4Status::Rofs);
        assert_eq!(Nfs4Status::from_u32(31), Nfs4Status::Mlink);
        assert_eq!(Nfs4Status::from_u32(63), Nfs4Status::NameTooLong);
        assert_eq!(Nfs4Status::from_u32(66), Nfs4Status::NotEmpty);
        assert_eq!(Nfs4Status::from_u32(69), Nfs4Status::Dquot);
        assert_eq!(Nfs4Status::from_u32(70), Nfs4Status::Stale);
        assert_eq!(Nfs4Status::from_u32(10001), Nfs4Status::BadHandle);
        assert_eq!(Nfs4Status::from_u32(10003), Nfs4Status::BadCookie);
        assert_eq!(Nfs4Status::from_u32(10004), Nfs4Status::NotSupp);
        assert_eq!(Nfs4Status::from_u32(10005), Nfs4Status::TooSmall);
        assert_eq!(Nfs4Status::from_u32(10006), Nfs4Status::ServerFault);
        assert_eq!(Nfs4Status::from_u32(10007), Nfs4Status::BadType);
        assert_eq!(Nfs4Status::from_u32(10008), Nfs4Status::Delay);
        assert_eq!(Nfs4Status::from_u32(10009), Nfs4Status::Same);
        assert_eq!(Nfs4Status::from_u32(10010), Nfs4Status::Denied);
        assert_eq!(Nfs4Status::from_u32(10011), Nfs4Status::Expired);
        assert_eq!(Nfs4Status::from_u32(10012), Nfs4Status::Locked);
        assert_eq!(Nfs4Status::from_u32(10013), Nfs4Status::Grace);
        assert_eq!(Nfs4Status::from_u32(10014), Nfs4Status::FhExpired);
        assert_eq!(Nfs4Status::from_u32(10015), Nfs4Status::ShareDenied);
        assert_eq!(Nfs4Status::from_u32(10016), Nfs4Status::WrongSec);
        assert_eq!(Nfs4Status::from_u32(10017), Nfs4Status::ClidInuse);
        assert_eq!(Nfs4Status::from_u32(10018), Nfs4Status::Resource);
        assert_eq!(Nfs4Status::from_u32(10019), Nfs4Status::Moved);
        assert_eq!(Nfs4Status::from_u32(10020), Nfs4Status::NoFilehandle);
        assert_eq!(Nfs4Status::from_u32(10021), Nfs4Status::MinorVersMismatch);
        assert_eq!(Nfs4Status::from_u32(10022), Nfs4Status::StaleClientid);
        assert_eq!(Nfs4Status::from_u32(10023), Nfs4Status::StaleStateid);
        assert_eq!(Nfs4Status::from_u32(10024), Nfs4Status::OldStateid);
        assert_eq!(Nfs4Status::from_u32(10025), Nfs4Status::BadStateid);
        assert_eq!(Nfs4Status::from_u32(10026), Nfs4Status::BadSeqid);
        assert_eq!(Nfs4Status::from_u32(10027), Nfs4Status::NotSame);
        assert_eq!(Nfs4Status::from_u32(10028), Nfs4Status::LockRange);
        assert_eq!(Nfs4Status::from_u32(10029), Nfs4Status::Symlink);
        assert_eq!(Nfs4Status::from_u32(10030), Nfs4Status::RestoreFh);
        assert_eq!(Nfs4Status::from_u32(10031), Nfs4Status::LeaseMoved);
        assert_eq!(Nfs4Status::from_u32(10032), Nfs4Status::AttrNotSupp);
        assert_eq!(Nfs4Status::from_u32(10033), Nfs4Status::NoGrace);
        assert_eq!(Nfs4Status::from_u32(10034), Nfs4Status::ReclaimBad);
        assert_eq!(Nfs4Status::from_u32(10035), Nfs4Status::ReclaimConflict);
        assert_eq!(Nfs4Status::from_u32(10036), Nfs4Status::BadXdr);
        assert_eq!(Nfs4Status::from_u32(10037), Nfs4Status::LocksHeld);
        assert_eq!(Nfs4Status::from_u32(10038), Nfs4Status::Openmode);
        assert_eq!(Nfs4Status::from_u32(10039), Nfs4Status::BadOwner);
        assert_eq!(Nfs4Status::from_u32(10040), Nfs4Status::BadChar);
        assert_eq!(Nfs4Status::from_u32(10041), Nfs4Status::BadName);
        assert_eq!(Nfs4Status::from_u32(10042), Nfs4Status::BadRange);
        assert_eq!(Nfs4Status::from_u32(10043), Nfs4Status::LockNotSupp);
        assert_eq!(Nfs4Status::from_u32(10044), Nfs4Status::OpIllegal);
        assert_eq!(Nfs4Status::from_u32(10045), Nfs4Status::Deadlock);
        assert_eq!(Nfs4Status::from_u32(10046), Nfs4Status::FileOpen);
        assert_eq!(Nfs4Status::from_u32(10047), Nfs4Status::AdminRevoked);
        assert_eq!(Nfs4Status::from_u32(10048), Nfs4Status::CbPathDown);
    }

    #[test]
    fn nfs4_status_unknown_preserves_value() {
        let status = Nfs4Status::from_u32(999);
        assert_eq!(status, Nfs4Status::Unknown(999));
        assert_eq!(status.as_u32(), 999);
    }

    #[test]
    fn attr_request_empty_has_two_zero_words() {
        let ar = AttrRequest::empty();
        assert_eq!(ar.words.len(), 2);
        assert_eq!(ar.words[0], 0);
        assert_eq!(ar.words[1], 0);
    }

    #[test]
    fn attr_request_fsid_only_has_bit_8_set() {
        let ar = AttrRequest::fsid_only();
        assert_eq!(ar.words[0], 1 << 8);
        assert_eq!(ar.words[1], 0);
    }

    #[test]
    fn argop_putpubfh_packed_size_is_4() {
        assert_eq!(ArgOp::Putpubfh.packed_size(), 4);
    }

    #[test]
    fn argop_putpubfh_encodes_opcode_23() {
        let mut buf = Vec::new();
        let n = ArgOp::Putpubfh.pack(&mut buf).unwrap();
        assert_eq!(n, 4);
        let opcode = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
        assert_eq!(opcode, 23, "PUTPUBFH op code must be 23 per RFC 7530 S16.21");
    }

    #[test]
    fn argop_putrootfh_packed_size_is_4() {
        assert_eq!(ArgOp::Putrootfh.packed_size(), 4);
    }

    #[test]
    fn argop_getfh_packed_size_is_4() {
        assert_eq!(ArgOp::Getfh.packed_size(), 4);
    }

    #[test]
    fn argop_lookup_packed_size_includes_string() {
        let op = ArgOp::Lookup("test".to_owned());
        // 4 (opcode) + 4 (string len) + 4 (data "test" = 4 bytes, no padding needed)
        assert_eq!(op.packed_size(), 4 + 4 + 4);
    }

    #[test]
    fn compound_args_pack_produces_expected_size() {
        let args = CompoundArgs { tag: String::new(), minorversion: 0, ops: vec![ArgOp::Putrootfh, ArgOp::Getfh] };
        // tag: 4 (empty XDR string = len 0, padded to 4) + minorversion: 4 + op_count: 4
        // + putrootfh: 4 + getfh: 4 = 20
        let expected = 4 + 4 + 4 + 4 + 4;
        assert_eq!(args.packed_size(), expected);
        let mut buf = Vec::new();
        let n = args.pack(&mut buf).unwrap();
        assert_eq!(n, expected);
        assert_eq!(buf.len(), expected);
    }

    #[test]
    fn compound_args_tag_is_encoded_as_xdr_string() {
        let args = CompoundArgs { tag: "nfswolf".to_owned(), minorversion: 0, ops: vec![] };
        let mut buf = Vec::new();
        _ = args.pack(&mut buf).unwrap();
        // First 4 bytes: string length
        let tag_len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
        assert_eq!(tag_len, 7, "tag 'nfswolf' must be encoded as 7-byte XDR string");
        // Verify the tag bytes follow (with padding to 4-byte boundary)
        let tag_bytes = &buf[4..11];
        assert_eq!(tag_bytes, b"nfswolf");
    }

    #[test]
    fn argop_secinfo_includes_name_string() {
        let op = ArgOp::Secinfo("etc".to_owned());
        // 4 (opcode) + 4 (string len) + 4 (data "etc" = 3 bytes + 1 pad)
        assert_eq!(op.packed_size(), 4 + 4 + 4);
        let mut buf = Vec::new();
        let n = op.pack(&mut buf).unwrap();
        assert_eq!(n, 12);
    }

    #[test]
    fn argop_readdir_includes_cookie_verifier_counts_bitmap() {
        let op = ArgOp::Readdir { cookie: 0, cookieverf: 0, dircount: 4096, maxcount: 65536, attr_request: AttrRequest::empty() };
        // 4 (opcode) + 8 (cookie) + 8 (verifier) + 4 (dircount) + 4 (maxcount) + bitmap(4+8)
        let expected = 4 + 8 + 8 + 4 + 4 + (4 + 2 * 4);
        assert_eq!(op.packed_size(), expected);
    }

    #[test]
    fn argop_read_packed_size_is_32() {
        let op = ArgOp::Read { stateid: [0u8; 16], offset: 0, count: 65536 };
        // 4 (opcode) + 16 (stateid) + 8 (offset) + 4 (count)
        assert_eq!(op.packed_size(), 32);
        let mut buf = Vec::new();
        let n = op.pack(&mut buf).unwrap();
        assert_eq!(n, 32);
        assert_eq!(buf.len(), 32);
    }

    #[test]
    fn argop_read_encodes_opcode_25() {
        let op = ArgOp::Read { stateid: [0u8; 16], offset: 0, count: 1024 };
        let mut buf = Vec::new();
        _ = op.pack(&mut buf).unwrap();
        let opcode = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
        assert_eq!(opcode, 25, "READ op code must be 25 per RFC 7530 S16.23");
    }

    #[test]
    fn argop_putfh_includes_opaque_file_handle() {
        let fh = vec![0xAB; 8]; // 8-byte handle
        let op = ArgOp::Putfh(fh);
        // 4 (opcode) + 4 (opaque length) + 8 (data, no padding needed)
        assert_eq!(op.packed_size(), 4 + 4 + 8);
    }

    #[test]
    fn compound_args_minorversion_is_encoded() {
        let args = CompoundArgs { tag: String::new(), minorversion: 1, ops: vec![] };
        let mut buf = Vec::new();
        _ = args.pack(&mut buf).unwrap();
        // After the tag (4 bytes for empty string), the next 4 bytes are minorversion
        let mv = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
        assert_eq!(mv, 1, "minorversion=1 must be encoded at offset 4");
    }

    // --- Status code round-trip tests (RFC 7530 S13) ---

    #[test]
    fn nfs4_status_all_named_variants_round_trip() {
        // Every named variant must survive from_u32 -> as_u32 -> from_u32 intact.
        let cases: &[(u32, Nfs4Status)] = &[
            (0, Nfs4Status::Ok),
            (1, Nfs4Status::Perm),
            (2, Nfs4Status::NoEnt),
            (5, Nfs4Status::Io),
            (6, Nfs4Status::Nxio),
            (13, Nfs4Status::Acces),
            (17, Nfs4Status::Exist),
            (18, Nfs4Status::Xdev),
            (20, Nfs4Status::NotDir),
            (21, Nfs4Status::IsDir),
            (22, Nfs4Status::Inval),
            (27, Nfs4Status::Fbig),
            (28, Nfs4Status::NoSpc),
            (30, Nfs4Status::Rofs),
            (31, Nfs4Status::Mlink),
            (63, Nfs4Status::NameTooLong),
            (66, Nfs4Status::NotEmpty),
            (69, Nfs4Status::Dquot),
            (70, Nfs4Status::Stale),
            (10001, Nfs4Status::BadHandle),
            (10003, Nfs4Status::BadCookie),
            (10004, Nfs4Status::NotSupp),
            (10005, Nfs4Status::TooSmall),
            (10006, Nfs4Status::ServerFault),
            (10007, Nfs4Status::BadType),
            (10008, Nfs4Status::Delay),
            (10009, Nfs4Status::Same),
            (10010, Nfs4Status::Denied),
            (10011, Nfs4Status::Expired),
            (10012, Nfs4Status::Locked),
            (10013, Nfs4Status::Grace),
            (10014, Nfs4Status::FhExpired),
            (10015, Nfs4Status::ShareDenied),
            (10016, Nfs4Status::WrongSec),
            (10017, Nfs4Status::ClidInuse),
            (10018, Nfs4Status::Resource),
            (10019, Nfs4Status::Moved),
            (10020, Nfs4Status::NoFilehandle),
            (10021, Nfs4Status::MinorVersMismatch),
            (10022, Nfs4Status::StaleClientid),
            (10023, Nfs4Status::StaleStateid),
            (10024, Nfs4Status::OldStateid),
            (10025, Nfs4Status::BadStateid),
            (10026, Nfs4Status::BadSeqid),
            (10027, Nfs4Status::NotSame),
            (10028, Nfs4Status::LockRange),
            (10029, Nfs4Status::Symlink),
            (10030, Nfs4Status::RestoreFh),
            (10031, Nfs4Status::LeaseMoved),
            (10032, Nfs4Status::AttrNotSupp),
            (10033, Nfs4Status::NoGrace),
            (10034, Nfs4Status::ReclaimBad),
            (10035, Nfs4Status::ReclaimConflict),
            (10036, Nfs4Status::BadXdr),
            (10037, Nfs4Status::LocksHeld),
            (10038, Nfs4Status::Openmode),
            (10039, Nfs4Status::BadOwner),
            (10040, Nfs4Status::BadChar),
            (10041, Nfs4Status::BadName),
            (10042, Nfs4Status::BadRange),
            (10043, Nfs4Status::LockNotSupp),
            (10044, Nfs4Status::OpIllegal),
            (10045, Nfs4Status::Deadlock),
            (10046, Nfs4Status::FileOpen),
            (10047, Nfs4Status::AdminRevoked),
            (10048, Nfs4Status::CbPathDown),
        ];
        for &(raw, expected) in cases {
            let decoded = Nfs4Status::from_u32(raw);
            assert_eq!(decoded, expected, "from_u32({raw}) should yield {expected:?}");
            assert_eq!(decoded.as_u32(), raw, "{expected:?}.as_u32() should yield {raw}");
            // Full round-trip: raw -> variant -> raw -> variant
            assert_eq!(Nfs4Status::from_u32(decoded.as_u32()), expected, "round-trip failed for {raw}");
        }
    }

    #[test]
    fn nfs4_status_unknown_preserves_arbitrary_value() {
        let status = Nfs4Status::from_u32(12345);
        assert_eq!(status, Nfs4Status::Unknown(12345));
        assert_eq!(status.as_u32(), 12345);
    }

    #[test]
    fn nfs4_status_unknown_round_trips_through_as_u32() {
        // The raw value must survive Unknown -> as_u32 -> from_u32 intact.
        let raw = 12345u32;
        let status = Nfs4Status::from_u32(raw);
        assert_eq!(status.as_u32(), raw);
        assert_eq!(Nfs4Status::from_u32(status.as_u32()), Nfs4Status::Unknown(raw));
    }

    // --- Operation code constants (RFC 7530 S16) ---

    #[test]
    #[expect(clippy::cognitive_complexity, reason = "flat list of assert_eq! checking all 38 opcodes, no real branching")]
    fn operation_codes_match_rfc7530() {
        // All 37 NFSv4.0 ops (3-39) + ILLEGAL (10044) per RFC 7530 S16.
        assert_eq!(OP_ACCESS, 3, "ACCESS must be 3 (RFC 7530 S16.1)");
        assert_eq!(OP_CLOSE, 4, "CLOSE must be 4 (RFC 7530 S16.2)");
        assert_eq!(OP_COMMIT, 5, "COMMIT must be 5 (RFC 7530 S16.3)");
        assert_eq!(OP_CREATE, 6, "CREATE must be 6 (RFC 7530 S16.4)");
        assert_eq!(OP_DELEGPURGE, 7, "DELEGPURGE must be 7 (RFC 7530 S16.5)");
        assert_eq!(OP_DELEGRETURN, 8, "DELEGRETURN must be 8 (RFC 7530 S16.6)");
        assert_eq!(OP_GETATTR, 9, "GETATTR must be 9 (RFC 7530 S16.7)");
        assert_eq!(OP_GETFH, 10, "GETFH must be 10 (RFC 7530 S16.8)");
        assert_eq!(OP_LINK, 11, "LINK must be 11 (RFC 7530 S16.9)");
        assert_eq!(OP_LOCK, 12, "LOCK must be 12 (RFC 7530 S16.10)");
        assert_eq!(OP_LOCKT, 13, "LOCKT must be 13 (RFC 7530 S16.11)");
        assert_eq!(OP_LOCKU, 14, "LOCKU must be 14 (RFC 7530 S16.12)");
        assert_eq!(OP_LOOKUP, 15, "LOOKUP must be 15 (RFC 7530 S16.13)");
        assert_eq!(OP_LOOKUPP, 16, "LOOKUPP must be 16 (RFC 7530 S16.14)");
        assert_eq!(OP_NVERIFY, 17, "NVERIFY must be 17 (RFC 7530 S16.15)");
        assert_eq!(OP_OPEN, 18, "OPEN must be 18 (RFC 7530 S16.16)");
        assert_eq!(OP_OPENATTR, 19, "OPENATTR must be 19 (RFC 7530 S16.17)");
        assert_eq!(OP_OPEN_CONFIRM, 20, "OPEN_CONFIRM must be 20 (RFC 7530 S16.18)");
        assert_eq!(OP_OPEN_DOWNGRADE, 21, "OPEN_DOWNGRADE must be 21 (RFC 7530 S16.19)");
        assert_eq!(OP_PUTFH, 22, "PUTFH must be 22 (RFC 7530 S16.20)");
        assert_eq!(OP_PUTPUBFH, 23, "PUTPUBFH must be 23 (RFC 7530 S16.21)");
        assert_eq!(OP_PUTROOTFH, 24, "PUTROOTFH must be 24 (RFC 7530 S16.22)");
        assert_eq!(OP_READ, 25, "READ must be 25 (RFC 7530 S16.23)");
        assert_eq!(OP_READDIR, 26, "READDIR must be 26 (RFC 7530 S16.24)");
        assert_eq!(OP_READLINK, 27, "READLINK must be 27 (RFC 7530 S16.25)");
        assert_eq!(OP_REMOVE, 28, "REMOVE must be 28 (RFC 7530 S16.26)");
        assert_eq!(OP_RENAME, 29, "RENAME must be 29 (RFC 7530 S16.27)");
        assert_eq!(OP_RENEW, 30, "RENEW must be 30 (RFC 7530 S16.28)");
        assert_eq!(OP_RESTOREFH, 31, "RESTOREFH must be 31 (RFC 7530 S16.29)");
        assert_eq!(OP_SAVEFH, 32, "SAVEFH must be 32 (RFC 7530 S16.30)");
        assert_eq!(OP_SECINFO, 33, "SECINFO must be 33 (RFC 7530 S16.31)");
        assert_eq!(OP_SETATTR, 34, "SETATTR must be 34 (RFC 7530 S16.32)");
        assert_eq!(OP_SETCLIENTID, 35, "SETCLIENTID must be 35 (RFC 7530 S16.33)");
        assert_eq!(OP_SETCLIENTID_CONFIRM, 36, "SETCLIENTID_CONFIRM must be 36 (RFC 7530 S16.34)");
        assert_eq!(OP_VERIFY, 37, "VERIFY must be 37 (RFC 7530 S16.35)");
        assert_eq!(OP_WRITE, 38, "WRITE must be 38 (RFC 7530 S16.36)");
        assert_eq!(OP_RELEASE_LOCKOWNER, 39, "RELEASE_LOCKOWNER must be 39 (RFC 7530 S16.37)");
        assert_eq!(OP_ILLEGAL, 10044, "ILLEGAL must be 10044 (RFC 7530 S16.38)");
    }

    // --- Program/version constants ---

    #[test]
    fn program_version_constants_match_rfc7530() {
        assert_eq!(NFS4_PROGRAM, 100_003, "NFS program number is 100003 for all NFS versions");
        assert_eq!(NFS4_VERSION, 4, "NFSv4.0 version number is 4");
        assert_eq!(NFS4_PROC_COMPOUND, 1, "COMPOUND is procedure 1 (the only non-NULL procedure)");
    }

    // --- COMPOUND encoding (RFC 7530 S15.2) ---

    #[test]
    fn compound_args_empty_ops_packs_correctly() {
        // Empty COMPOUND: tag(XDR string) + minorversion(u32) + argarray_len(u32=0)
        let args = CompoundArgs { tag: String::new(), minorversion: 0, ops: vec![] };
        let mut buf = Vec::new();
        let n = args.pack(&mut buf).unwrap();
        // Empty tag = 4 bytes (len=0), minorversion = 4 bytes, op count = 4 bytes
        assert_eq!(n, 12);
        assert_eq!(buf.len(), 12);
        // Tag length = 0
        assert_eq!(u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]), 0);
        // Minorversion = 0
        assert_eq!(u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]), 0);
        // Op count = 0
        assert_eq!(u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]]), 0);
    }

    #[test]
    fn compound_args_one_putrootfh_packs_correctly() {
        // Single-op COMPOUND with PUTROOTFH.
        let args = CompoundArgs { tag: String::new(), minorversion: 0, ops: vec![ArgOp::Putrootfh] };
        let mut buf = Vec::new();
        let n = args.pack(&mut buf).unwrap();
        // tag(4) + minorversion(4) + count(4) + putrootfh_opcode(4) = 16
        assert_eq!(n, 16);
        // Op count = 1
        assert_eq!(u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]]), 1);
        // Op code = 24 (PUTROOTFH)
        assert_eq!(u32::from_be_bytes([buf[12], buf[13], buf[14], buf[15]]), 24);
    }

    #[test]
    fn compound_args_tag_xdr_string_with_padding() {
        // Tag "abc" is 3 bytes, needs 1 byte padding to reach 4-byte XDR boundary.
        let args = CompoundArgs { tag: "abc".to_owned(), minorversion: 0, ops: vec![] };
        let mut buf = Vec::new();
        let n = args.pack(&mut buf).unwrap();
        // tag: 4 (len) + 4 (3 bytes + 1 pad) = 8; minorversion: 4; count: 4 = 16
        assert_eq!(n, 16);
        // Tag length = 3
        assert_eq!(u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]), 3);
        // Tag data
        assert_eq!(&buf[4..7], b"abc");
        // Padding byte must be zero
        assert_eq!(buf[7], 0);
    }

    #[test]
    fn compound_args_minorversion_zero_for_nfsv40() {
        let args = CompoundArgs { tag: String::new(), minorversion: 0, ops: vec![] };
        let mut buf = Vec::new();
        _ = args.pack(&mut buf).unwrap();
        let mv = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
        assert_eq!(mv, 0, "NFSv4.0 uses minorversion=0");
    }

    // --- ArgOp encoding (individual operations) ---

    #[test]
    fn argop_putrootfh_encodes_opcode_24() {
        let mut buf = Vec::new();
        let n = ArgOp::Putrootfh.pack(&mut buf).unwrap();
        assert_eq!(n, 4);
        let opcode = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
        assert_eq!(opcode, 24, "PUTROOTFH op code must be 24 per RFC 7530 S16.22");
    }

    #[test]
    fn argop_getfh_encodes_opcode_10() {
        let mut buf = Vec::new();
        let n = ArgOp::Getfh.pack(&mut buf).unwrap();
        assert_eq!(n, 4);
        let opcode = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
        assert_eq!(opcode, 10, "GETFH op code must be 10 per RFC 7530 S16.8");
    }

    #[test]
    fn argop_lookup_encodes_opcode_and_name() {
        let op = ArgOp::Lookup("etc".to_owned());
        let mut buf = Vec::new();
        let n = op.pack(&mut buf).unwrap();
        // 4 (opcode) + 4 (string len) + 4 (3 bytes "etc" + 1 pad)
        assert_eq!(n, 12);
        let opcode = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
        assert_eq!(opcode, 15, "LOOKUP op code must be 15 per RFC 7530 S16.13");
        let name_len = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
        assert_eq!(name_len, 3);
        assert_eq!(&buf[8..11], b"etc");
    }

    #[test]
    fn argop_putfh_encodes_opcode_and_handle() {
        let fh = vec![0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE];
        let op = ArgOp::Putfh(fh.clone());
        let mut buf = Vec::new();
        let n = op.pack(&mut buf).unwrap();
        // 4 (opcode) + 4 (opaque len) + 8 (6 bytes + 2 pad)
        assert_eq!(n, 16);
        let opcode = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
        assert_eq!(opcode, 22, "PUTFH op code must be 22 per RFC 7530 S16.20");
        let fh_len = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
        assert_eq!(fh_len, 6);
        assert_eq!(&buf[8..14], &fh[..]);
    }

    #[test]
    fn argop_putfh_packed_size_accounts_for_padding() {
        // 5-byte handle: 4 (opcode) + 4 (len) + 8 (5 bytes + 3 pad)
        let op = ArgOp::Putfh(vec![0x11; 5]);
        assert_eq!(op.packed_size(), 16);

        // 4-byte handle: 4 (opcode) + 4 (len) + 4 (no padding)
        let op = ArgOp::Putfh(vec![0x22; 4]);
        assert_eq!(op.packed_size(), 12);
    }

    #[test]
    fn argop_read_encodes_stateid_offset_count() {
        let stateid = [0u8; 16]; // anonymous stateid
        let op = ArgOp::Read { stateid, offset: 0x0000_1000, count: 8192 };
        let mut buf = Vec::new();
        let n = op.pack(&mut buf).unwrap();
        assert_eq!(n, 32);
        // opcode at [0..4]
        let opcode = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
        assert_eq!(opcode, 25);
        // stateid at [4..20] -- all zeros for anonymous
        assert_eq!(&buf[4..20], &[0u8; 16]);
        // offset at [20..28]
        let offset = u64::from_be_bytes([buf[20], buf[21], buf[22], buf[23], buf[24], buf[25], buf[26], buf[27]]);
        assert_eq!(offset, 0x1000);
        // count at [28..32]
        let count = u32::from_be_bytes([buf[28], buf[29], buf[30], buf[31]]);
        assert_eq!(count, 8192);
    }

    #[test]
    fn argop_secinfo_encodes_opcode_and_name() {
        let op = ArgOp::Secinfo("home".to_owned());
        let mut buf = Vec::new();
        let n = op.pack(&mut buf).unwrap();
        // 4 (opcode) + 4 (string len) + 4 (4 bytes "home", no padding)
        assert_eq!(n, 12);
        let opcode = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
        assert_eq!(opcode, 33, "SECINFO op code must be 33 per RFC 7530 S16.31");
        let name_len = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
        assert_eq!(name_len, 4);
        assert_eq!(&buf[8..12], b"home");
    }

    #[test]
    fn argop_readdir_encodes_all_fields() {
        let attr_req = AttrRequest::empty();
        let op = ArgOp::Readdir { cookie: 42, cookieverf: 0xDEAD, dircount: 4096, maxcount: 65536, attr_request: attr_req };
        let mut buf = Vec::new();
        let n = op.pack(&mut buf).unwrap();
        // 4 (opcode) + 8 (cookie) + 8 (cookieverf) + 4 (dircount) + 4 (maxcount) + 12 (bitmap: 4 len + 2*4 words)
        let expected = 4 + 8 + 8 + 4 + 4 + 12;
        assert_eq!(n, expected);
        // opcode = 26 (READDIR)
        let opcode = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
        assert_eq!(opcode, 26, "READDIR op code must be 26 per RFC 7530 S16.24");
        // cookie at [4..12]
        let cookie = u64::from_be_bytes(buf[4..12].try_into().unwrap());
        assert_eq!(cookie, 42);
        // cookieverf at [12..20]
        let verf = u64::from_be_bytes(buf[12..20].try_into().unwrap());
        assert_eq!(verf, 0xDEAD);
        // dircount at [20..24]
        let dircount = u32::from_be_bytes(buf[20..24].try_into().unwrap());
        assert_eq!(dircount, 4096);
        // maxcount at [24..28]
        let maxcount = u32::from_be_bytes(buf[24..28].try_into().unwrap());
        assert_eq!(maxcount, 65536);
    }

    #[test]
    fn argop_getattr_encodes_opcode_and_bitmap() {
        let op = ArgOp::Getattr(AttrRequest::fsid_only());
        let mut buf = Vec::new();
        let n = op.pack(&mut buf).unwrap();
        // 4 (opcode=9) + 4 (bitmap word count=2) + 4 (word 0: bit 8) + 4 (word 1: 0)
        assert_eq!(n, 16);
        let opcode = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
        assert_eq!(opcode, 9, "GETATTR op code must be 9 per RFC 7530 S16.7");
        // Bitmap count = 2
        let bm_count = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
        assert_eq!(bm_count, 2);
        // Word 0 = 1<<8 = 256 (FATTR4_FSID)
        let w0 = u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]]);
        assert_eq!(w0, 256);
    }

    // --- AttrRequest (RFC 7530 S5.6) ---

    #[test]
    fn attr_request_empty_packed_size() {
        let ar = AttrRequest::empty();
        // 4 (word count) + 4*2 (two zero words) = 12
        assert_eq!(ar.packed_size(), 12);
    }

    #[test]
    fn attr_request_fsid_only_packed_size() {
        let ar = AttrRequest::fsid_only();
        assert_eq!(ar.packed_size(), 12);
    }

    #[test]
    fn attr_request_empty_packs_as_two_zero_words() {
        let ar = AttrRequest::empty();
        let mut buf = Vec::new();
        let n = ar.pack(&mut buf).unwrap();
        assert_eq!(n, 12);
        // Word count = 2
        assert_eq!(u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]), 2);
        // Word 0 = 0
        assert_eq!(u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]), 0);
        // Word 1 = 0
        assert_eq!(u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]]), 0);
    }

    #[test]
    fn attr_request_fsid_only_sets_bit_8_in_word_0() {
        let ar = AttrRequest::fsid_only();
        let mut buf = Vec::new();
        _ = ar.pack(&mut buf).unwrap();
        let w0 = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
        assert_eq!(w0, 1 << 8, "FATTR4_FSID is attribute 8 -> bit 8 in word 0");
        let w1 = u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]]);
        assert_eq!(w1, 0, "word 1 should be zero for fsid-only request");
    }

    #[test]
    fn attr_request_round_trips_through_pack_unpack() {
        let ar = AttrRequest::fsid_only();
        let mut buf = Vec::new();
        let packed = ar.pack(&mut buf).unwrap();
        let (decoded, consumed) = AttrRequest::unpack(&mut &buf[..]).unwrap();
        assert_eq!(consumed, packed);
        assert_eq!(decoded.words, ar.words);
    }

    // --- Anonymous stateid (RFC 7530 S9.1.4.3) ---

    #[test]
    fn anonymous_stateid_is_all_zeros() {
        // RFC 7530 S9.1.4.3: anonymous stateid has seqid=0 and other=all-zeros.
        // Total 16 bytes: 4 (seqid) + 12 (other).
        let stateid = [0u8; 16];
        let op = ArgOp::Read { stateid, offset: 0, count: 1024 };
        let mut buf = Vec::new();
        _ = op.pack(&mut buf).unwrap();
        // Stateid bytes at [4..20] must all be zero.
        assert_eq!(&buf[4..20], &[0u8; 16], "anonymous stateid must be 16 zero bytes");
    }

    // --- CompoundRes unpacking ---

    #[test]
    fn compound_res_unpacks_empty_response() {
        // Wire: status(0) + tag("", len=0) + result_count(0)
        let mut wire = Vec::new();
        0u32.pack(&mut wire).unwrap(); // status = NFS4_OK
        onc_xdr::pack_string("", &mut wire).unwrap(); // empty tag
        0u32.pack(&mut wire).unwrap(); // zero results
        let (res, _) = CompoundRes::unpack(&mut &wire[..]).unwrap();
        assert_eq!(res.status, 0);
        assert_eq!(res.tag, "");
        assert!(res.results.is_empty());
    }

    #[test]
    fn compound_res_unpacks_putrootfh_ok() {
        let mut wire = Vec::new();
        0u32.pack(&mut wire).unwrap(); // status = NFS4_OK
        onc_xdr::pack_string("", &mut wire).unwrap(); // tag
        1u32.pack(&mut wire).unwrap(); // 1 result
        OP_PUTROOTFH.pack(&mut wire).unwrap(); // op code
        0u32.pack(&mut wire).unwrap(); // op status = OK
        // PUTROOTFH has no result data beyond status.
        let (res, _) = CompoundRes::unpack(&mut &wire[..]).unwrap();
        assert_eq!(res.results.len(), 1);
        assert_eq!(res.results[0].op_code, OP_PUTROOTFH);
        assert_eq!(res.results[0].status, 0);
        assert!(matches!(res.results[0].data, ResOpData::None));
    }

    #[test]
    fn compound_res_unpacks_getfh_with_handle() {
        let mut wire = Vec::new();
        0u32.pack(&mut wire).unwrap();
        onc_xdr::pack_string("", &mut wire).unwrap();
        1u32.pack(&mut wire).unwrap(); // 1 result
        OP_GETFH.pack(&mut wire).unwrap();
        0u32.pack(&mut wire).unwrap(); // status OK
        // GETFH result: opaque file handle
        let fh = [0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45];
        pack_opaque(&fh, &mut wire).unwrap();
        let (res, _) = CompoundRes::unpack(&mut &wire[..]).unwrap();
        assert_eq!(res.results.len(), 1);
        match &res.results[0].data {
            ResOpData::Fh(h) => assert_eq!(h.as_slice(), &fh),
            other => panic!("expected ResOpData::Fh, got {other:?}"),
        }
    }

    #[test]
    fn compound_res_unpacks_read_with_data_and_eof() {
        let mut wire = Vec::new();
        0u32.pack(&mut wire).unwrap();
        onc_xdr::pack_string("", &mut wire).unwrap();
        1u32.pack(&mut wire).unwrap();
        OP_READ.pack(&mut wire).unwrap();
        0u32.pack(&mut wire).unwrap(); // status OK
        // READ result: eof(bool=1) + opaque data
        1u32.pack(&mut wire).unwrap(); // eof = true
        let data = b"hello world";
        pack_opaque(data, &mut wire).unwrap();
        let (res, _) = CompoundRes::unpack(&mut &wire[..]).unwrap();
        match &res.results[0].data {
            ResOpData::Read { eof, data: d } => {
                assert!(*eof);
                assert_eq!(d.as_slice(), b"hello world");
            },
            other => panic!("expected ResOpData::Read, got {other:?}"),
        }
    }

    #[test]
    fn compound_res_stops_at_failed_op() {
        // When an op fails, the server stops and returns no further results.
        let mut wire = Vec::new();
        2u32.pack(&mut wire).unwrap(); // overall status = NFS4ERR_NOENT
        onc_xdr::pack_string("", &mut wire).unwrap();
        2u32.pack(&mut wire).unwrap(); // 2 results in array
        // First op: PUTROOTFH OK
        OP_PUTROOTFH.pack(&mut wire).unwrap();
        0u32.pack(&mut wire).unwrap();
        // Second op: LOOKUP fails with NOENT
        OP_LOOKUP.pack(&mut wire).unwrap();
        2u32.pack(&mut wire).unwrap(); // status = NOENT
        let (res, _) = CompoundRes::unpack(&mut &wire[..]).unwrap();
        assert_eq!(res.status, 2);
        assert_eq!(res.results.len(), 2);
        assert_eq!(res.results[0].status, 0);
        assert_eq!(res.results[1].status, 2);
        assert_eq!(res.results[1].op_code, OP_LOOKUP);
    }

    #[test]
    fn compound_res_unpacks_secinfo_flavors() {
        let mut wire = Vec::new();
        0u32.pack(&mut wire).unwrap();
        onc_xdr::pack_string("", &mut wire).unwrap();
        1u32.pack(&mut wire).unwrap();
        OP_SECINFO.pack(&mut wire).unwrap();
        0u32.pack(&mut wire).unwrap(); // status OK
        // SECINFO result: array of 2 flavors (AUTH_SYS=1, AUTH_NONE=0)
        2u32.pack(&mut wire).unwrap(); // array count
        1u32.pack(&mut wire).unwrap(); // AUTH_SYS
        0u32.pack(&mut wire).unwrap(); // AUTH_NONE
        let (res, _) = CompoundRes::unpack(&mut &wire[..]).unwrap();
        match &res.results[0].data {
            ResOpData::SecFlavors(entries) => {
                assert_eq!(entries.len(), 2);
                assert_eq!(entries[0].flavor, 1);
                assert!(entries[0].gss_oid.is_none());
                assert_eq!(entries[1].flavor, 0);
                assert!(entries[1].gss_oid.is_none());
            },
            other => panic!("expected ResOpData::SecFlavors, got {other:?}"),
        }
    }

    #[test]
    fn compound_res_unpacks_readdir_entries() {
        let mut wire = Vec::new();
        0u32.pack(&mut wire).unwrap();
        onc_xdr::pack_string("", &mut wire).unwrap();
        1u32.pack(&mut wire).unwrap();
        OP_READDIR.pack(&mut wire).unwrap();
        0u32.pack(&mut wire).unwrap(); // status OK
        // READDIR result: cookieverf(8) + entries(linked list) + eof
        wire.extend_from_slice(&[0u8; 8]); // cookieverf
        // Entry 1: value_follows=1, cookie=1, name=".", empty fattr4
        1u32.pack(&mut wire).unwrap(); // value_follows
        1u64.pack(&mut wire).unwrap(); // cookie
        onc_xdr::pack_string(".", &mut wire).unwrap(); // name
        // fattr4: bitmap_count=0, attrvals opaque len=0
        0u32.pack(&mut wire).unwrap(); // bitmap count
        0u32.pack(&mut wire).unwrap(); // attrvals len
        // Entry 2: value_follows=1, cookie=2, name=".."
        1u32.pack(&mut wire).unwrap();
        2u64.pack(&mut wire).unwrap();
        onc_xdr::pack_string("..", &mut wire).unwrap();
        0u32.pack(&mut wire).unwrap();
        0u32.pack(&mut wire).unwrap();
        // End of list
        0u32.pack(&mut wire).unwrap(); // value_follows=0
        1u32.pack(&mut wire).unwrap(); // eof=true
        let (res, _) = CompoundRes::unpack(&mut &wire[..]).unwrap();
        match &res.results[0].data {
            ResOpData::Readdir { cookieverf, entries, eof } => {
                assert_eq!(*cookieverf, [0u8; 8]);
                assert_eq!(entries.len(), 2);
                assert_eq!(entries[0].name, ".");
                assert_eq!(entries[0].cookie, 1);
                assert_eq!(entries[1].name, "..");
                assert_eq!(entries[1].cookie, 2);
                assert!(*eof);
            },
            other => panic!("expected ResOpData::Readdir, got {other:?}"),
        }
    }

    #[test]
    fn compound_res_unpacks_getattr_fsid() {
        let mut wire = Vec::new();
        0u32.pack(&mut wire).unwrap();
        onc_xdr::pack_string("", &mut wire).unwrap();
        1u32.pack(&mut wire).unwrap();
        OP_GETATTR.pack(&mut wire).unwrap();
        0u32.pack(&mut wire).unwrap(); // status OK
        // GETATTR result: bitmap(word_count=2, w0=1<<8, w1=0) + attrvals(fsid4: major + minor)
        2u32.pack(&mut wire).unwrap(); // bitmap count
        (1u32 << 8).pack(&mut wire).unwrap(); // word 0: FATTR4_FSID bit
        0u32.pack(&mut wire).unwrap(); // word 1
        // attrvals opaque: fsid4 = (major=100, minor=200), total 16 bytes
        16u32.pack(&mut wire).unwrap(); // attrvals length
        100u64.pack(&mut wire).unwrap(); // major
        200u64.pack(&mut wire).unwrap(); // minor
        let (res, _) = CompoundRes::unpack(&mut &wire[..]).unwrap();
        match &res.results[0].data {
            ResOpData::Getattr(attrs) => {
                assert_eq!(attrs.fsid, Some((100, 200)));
                assert!(attrs.sec_label.is_none());
            },
            other => panic!("expected ResOpData::Getattr, got {other:?}"),
        }
    }

    // --- packed_size consistency ---

    #[test]
    fn packed_size_matches_actual_pack_for_all_ops() {
        // Every ArgOp variant's packed_size() must exactly match the bytes pack() writes.
        let ops: Vec<ArgOp> = vec![
            // No-argument ops
            ArgOp::Putpubfh,
            ArgOp::Putrootfh,
            ArgOp::Getfh,
            ArgOp::Lookupp,
            ArgOp::Readlink,
            ArgOp::Restorefh,
            ArgOp::Savefh,
            ArgOp::Illegal,
            // Opaque FH
            ArgOp::Putfh(vec![0x01, 0x02, 0x03]),
            ArgOp::Putfh(vec![0x01, 0x02, 0x03, 0x04]),
            // String-argument ops
            ArgOp::Lookup("passwd".to_owned()),
            ArgOp::Lookup("a".to_owned()),
            ArgOp::Secinfo("exports".to_owned()),
            ArgOp::Remove { target: "old".to_owned() },
            ArgOp::Link { newname: "newlink".to_owned() },
            ArgOp::Rename { oldname: "src".to_owned(), newname: "dst".to_owned() },
            // Bitmap
            ArgOp::Getattr(AttrRequest::empty()),
            ArgOp::Getattr(AttrRequest::fsid_only()),
            // Read / Readdir
            ArgOp::Read { stateid: [0u8; 16], offset: 0, count: 1024 },
            ArgOp::Read { stateid: [0xFF; 16], offset: u64::MAX, count: u32::MAX },
            ArgOp::Readdir { cookie: 0, cookieverf: 0, dircount: 4096, maxcount: 65536, attr_request: AttrRequest::empty() },
            // Typed struct ops
            ArgOp::Access { access: 0x3F },
            ArgOp::Close { seqid: 1, stateid: [0xAA; 16] },
            ArgOp::Commit { offset: 0, count: 0 },
            ArgOp::Delegpurge { clientid: 42 },
            ArgOp::Delegreturn { stateid: [0xBB; 16] },
            ArgOp::Openattr { createdir: true },
            ArgOp::Openattr { createdir: false },
            ArgOp::OpenConfirm { stateid: [0xCC; 16], seqid: 2 },
            ArgOp::OpenDowngrade { stateid: [0xDD; 16], seqid: 3, share_access: 1, share_deny: 0 },
            ArgOp::Renew { clientid: 99 },
            ArgOp::SetclientidConfirm { clientid: 100, verifier: [0xEE; 8] },
            ArgOp::Write { stateid: [0u8; 16], offset: 4096, stable: 2, data: vec![0x41; 5] },
            ArgOp::Write { stateid: [0u8; 16], offset: 0, stable: 0, data: vec![] },
            // Typed stateful ops
            ArgOp::Create { objtype: CreateType4::Dir, objname: "newdir".to_owned(), createattrs: Fattr4::default() },
            ArgOp::Create { objtype: CreateType4::Lnk("/target".to_owned()), objname: "link".to_owned(), createattrs: Fattr4::default() },
            ArgOp::Lock { locktype: LockType4::WriteLt, reclaim: false, offset: 0, length: 100, locker: Locker4::ExistLockOwner { lock_stateid: Stateid4::ANONYMOUS, lock_seqid: 1 } },
            ArgOp::Lockt { locktype: LockType4::ReadLt, offset: 0, length: 0, owner: LockOwner4 { clientid: 1, owner: vec![0x01] } },
            ArgOp::Locku { locktype: LockType4::WriteLt, seqid: 2, lock_stateid: Stateid4::ANONYMOUS, offset: 0, length: 0 },
            ArgOp::Nverify { obj_attributes: Fattr4::default() },
            ArgOp::Open { seqid: 1, share_access: 1, share_deny: 0, owner: OpenOwner4 { clientid: 0, owner: b"test".to_vec() }, openhow: OpenFlag4::NoCreate, claim: OpenClaim4::Null("file".to_owned()) },
            ArgOp::Setattr { stateid: Stateid4::ANONYMOUS, obj_attributes: Fattr4::default() },
            ArgOp::Setclientid { client_verifier: [0x6E, 0x66, 0x73, 0x77, 0x6F, 0x6C, 0x66, 0x00], client_id: b"test".to_vec(), cb_program: 0x4000_0000, cb_netid: "tcp".to_owned(), cb_addr: "0.0.0.0.0.0".to_owned(), callback_ident: 1 },
            ArgOp::Verify { obj_attributes: Fattr4::default() },
            ArgOp::ReleaseLockowner { lock_owner: LockOwner4 { clientid: 42, owner: vec![0xAA] } },
        ];
        let ops = {
            let mut v = ops;
            v.extend([ArgOp::ExchangeId(vec![0u8; 32]), ArgOp::Getdeviceinfo(vec![0u8; 28]), ArgOp::Getdevicelist(vec![0u8; 24]), ArgOp::SecinfoNoName { style: 0 }, ArgOp::SecinfoNoName { style: 1 }]);
            v
        };
        for op in &ops {
            let predicted = op.packed_size();
            let mut buf = Vec::new();
            let actual = op.pack(&mut buf).unwrap();
            assert_eq!(predicted, actual, "packed_size mismatch for {op:?}: predicted {predicted}, actual {actual}");
            assert_eq!(buf.len(), actual, "buffer length mismatch for {op:?}");
        }
    }

    #[test]
    fn compound_args_packed_size_matches_actual_pack() {
        let compounds = vec![
            CompoundArgs { tag: String::new(), minorversion: 0, ops: vec![] },
            CompoundArgs { tag: "nfswolf".to_owned(), minorversion: 0, ops: vec![ArgOp::Putrootfh, ArgOp::Getfh] },
            CompoundArgs { tag: "x".to_owned(), minorversion: 0, ops: vec![ArgOp::Putrootfh, ArgOp::Lookup("etc".to_owned()), ArgOp::Getfh] },
        ];
        for args in &compounds {
            let predicted = args.packed_size();
            let mut buf = Vec::new();
            let actual = args.pack(&mut buf).unwrap();
            assert_eq!(predicted, actual, "packed_size mismatch for compound with tag {:?}", args.tag);
        }
    }

    // --- Multi-op COMPOUND wire layout ---

    #[test]
    fn compound_args_multi_op_wire_layout() {
        // PUTROOTFH + LOOKUP("etc") + GETFH  --  verify the full wire sequence.
        let args = CompoundArgs { tag: String::new(), minorversion: 0, ops: vec![ArgOp::Putrootfh, ArgOp::Lookup("etc".to_owned()), ArgOp::Getfh] };
        let mut buf = Vec::new();
        let n = args.pack(&mut buf).unwrap();
        // tag(4) + minorversion(4) + count(4) + putrootfh(4) + lookup(4+4+4=12) + getfh(4) = 32
        assert_eq!(n, 32);
        let mut off = 0;
        // tag length = 0
        assert_eq!(u32::from_be_bytes(buf[off..off + 4].try_into().unwrap()), 0);
        off += 4;
        // minorversion = 0
        assert_eq!(u32::from_be_bytes(buf[off..off + 4].try_into().unwrap()), 0);
        off += 4;
        // op count = 3
        assert_eq!(u32::from_be_bytes(buf[off..off + 4].try_into().unwrap()), 3);
        off += 4;
        // PUTROOTFH opcode = 24
        assert_eq!(u32::from_be_bytes(buf[off..off + 4].try_into().unwrap()), 24);
        off += 4;
        // LOOKUP opcode = 15
        assert_eq!(u32::from_be_bytes(buf[off..off + 4].try_into().unwrap()), 15);
        off += 4;
        // LOOKUP name length = 3
        assert_eq!(u32::from_be_bytes(buf[off..off + 4].try_into().unwrap()), 3);
        off += 4;
        // "etc" + 1 pad byte
        assert_eq!(&buf[off..off + 3], b"etc");
        off += 4; // 3 bytes + 1 pad
        // GETFH opcode = 10
        assert_eq!(u32::from_be_bytes(buf[off..off + 4].try_into().unwrap()), 10);
    }

    #[test]
    fn compound_res_unpacks_multi_op_response() {
        // Simulate: PUTROOTFH(OK) + LOOKUP(OK) + GETFH(OK, handle=0xBEEF)
        let mut wire = Vec::new();
        0u32.pack(&mut wire).unwrap();
        onc_xdr::pack_string("", &mut wire).unwrap();
        3u32.pack(&mut wire).unwrap(); // 3 results
        // PUTROOTFH OK
        OP_PUTROOTFH.pack(&mut wire).unwrap();
        0u32.pack(&mut wire).unwrap();
        // LOOKUP OK
        OP_LOOKUP.pack(&mut wire).unwrap();
        0u32.pack(&mut wire).unwrap();
        // GETFH OK + handle
        OP_GETFH.pack(&mut wire).unwrap();
        0u32.pack(&mut wire).unwrap();
        pack_opaque(&[0xBE, 0xEF], &mut wire).unwrap();
        let (res, _) = CompoundRes::unpack(&mut &wire[..]).unwrap();
        assert_eq!(res.results.len(), 3);
        assert_eq!(res.results[0].op_code, OP_PUTROOTFH);
        assert_eq!(res.results[1].op_code, OP_LOOKUP);
        match &res.results[2].data {
            ResOpData::Fh(h) => assert_eq!(h.as_slice(), &[0xBE, 0xEF]),
            other => panic!("expected Fh, got {other:?}"),
        }
    }

    #[test]
    fn compound_res_tag_echoed_back() {
        let mut wire = Vec::new();
        0u32.pack(&mut wire).unwrap();
        onc_xdr::pack_string("mytag", &mut wire).unwrap();
        0u32.pack(&mut wire).unwrap(); // zero results
        let (res, _) = CompoundRes::unpack(&mut &wire[..]).unwrap();
        assert_eq!(res.tag, "mytag");
    }

    // =========================================================================
    // Golden vector tests -- NFSv4 (RFC 7530)
    // =========================================================================

    /// Golden vector: CompoundArgs encoding (RFC 7530 S15.2.3).
    ///
    /// PUTROOTFH + LOOKUP("etc") + GETFH, empty tag, minorversion 0.
    /// 32 bytes total.
    #[test]
    fn golden_compound_args_putrootfh_lookup_getfh() {
        #[rustfmt::skip]
        const GOLDEN: [u8; 32] = [
            // tag = "" (empty XDR string: length 0)
            0x00, 0x00, 0x00, 0x00,
            // minorversion = 0
            0x00, 0x00, 0x00, 0x00,
            // op count = 3
            0x00, 0x00, 0x00, 0x03,
            // PUTROOTFH opcode = 24
            0x00, 0x00, 0x00, 0x18,
            // LOOKUP opcode = 15
            0x00, 0x00, 0x00, 0x0F,
            // LOOKUP name length = 3
            0x00, 0x00, 0x00, 0x03,
            // LOOKUP name "etc" + 1 pad byte
            0x65, 0x74, 0x63, 0x00,
            // GETFH opcode = 10
            0x00, 0x00, 0x00, 0x0A,
        ];

        // Pack the struct and verify it matches the golden vector.
        let args = CompoundArgs { tag: String::new(), minorversion: 0, ops: vec![ArgOp::Putrootfh, ArgOp::Lookup("etc".to_owned()), ArgOp::Getfh] };
        let mut packed = Vec::new();
        let n = args.pack(&mut packed).unwrap();
        assert_eq!(n, 32);
        assert_eq!(packed, GOLDEN);
    }

    /// Golden vector: CompoundRes for PUTROOTFH(OK) + GETFH(OK) (RFC 7530).
    ///
    /// status=0, tag="", 2 results. GETFH returns a 4-byte handle [DE AD BE EF].
    #[test]
    fn golden_compound_res_putrootfh_getfh() {
        #[rustfmt::skip]
        const GOLDEN: [u8; 36] = [
            // overall status = NFS4_OK (0)
            0x00, 0x00, 0x00, 0x00,
            // tag = "" (empty)
            0x00, 0x00, 0x00, 0x00,
            // result count = 2
            0x00, 0x00, 0x00, 0x02,
            // result[0]: PUTROOTFH (24), status OK (0)
            0x00, 0x00, 0x00, 0x18,
            0x00, 0x00, 0x00, 0x00,
            // result[1]: GETFH (10), status OK (0)
            0x00, 0x00, 0x00, 0x0A,
            0x00, 0x00, 0x00, 0x00,
            // GETFH result: opaque handle length = 4
            0x00, 0x00, 0x00, 0x04,
            // handle data [DE AD BE EF]
            0xDE, 0xAD, 0xBE, 0xEF,
        ];

        let (res, consumed) = CompoundRes::unpack(&mut &GOLDEN[..]).unwrap();
        assert_eq!(consumed, GOLDEN.len());
        assert_eq!(res.status, 0);
        assert_eq!(res.tag, "");
        assert_eq!(res.results.len(), 2);

        // First result: PUTROOTFH OK
        assert_eq!(res.results[0].op_code, 24);
        assert_eq!(res.results[0].status, 0);
        assert!(matches!(res.results[0].data, ResOpData::None));

        // Second result: GETFH with handle
        assert_eq!(res.results[1].op_code, 10);
        assert_eq!(res.results[1].status, 0);
        match &res.results[1].data {
            ResOpData::Fh(fh) => assert_eq!(fh.as_slice(), &[0xDE, 0xAD, 0xBE, 0xEF]),
            other => panic!("expected ResOpData::Fh, got {other:?}"),
        }
    }

    /// Golden vector: CompoundRes with a failed LOOKUP (RFC 7530 S15.2).
    ///
    /// The server stops at the first failing op: PUTROOTFH(OK) + LOOKUP(NOENT).
    #[test]
    fn golden_compound_res_lookup_failure() {
        #[rustfmt::skip]
        const GOLDEN: [u8; 28] = [
            // overall status = NFS4ERR_NOENT (2)
            0x00, 0x00, 0x00, 0x02,
            // tag = ""
            0x00, 0x00, 0x00, 0x00,
            // result count = 2
            0x00, 0x00, 0x00, 0x02,
            // result[0]: PUTROOTFH (24), status OK (0)
            0x00, 0x00, 0x00, 0x18,
            0x00, 0x00, 0x00, 0x00,
            // result[1]: LOOKUP (15), status NOENT (2)
            0x00, 0x00, 0x00, 0x0F,
            0x00, 0x00, 0x00, 0x02,
        ];

        let (res, consumed) = CompoundRes::unpack(&mut &GOLDEN[..]).unwrap();
        assert_eq!(consumed, GOLDEN.len());
        assert_eq!(res.status, 2);
        assert_eq!(res.results.len(), 2);
        assert_eq!(res.results[0].status, 0);
        assert_eq!(res.results[1].op_code, 15); // LOOKUP
        assert_eq!(res.results[1].status, 2); // NOENT
    }

    // =========================================================================
    // New operation encoding tests (RFC 7530 S16)
    // =========================================================================

    #[test]
    fn argop_access_encodes_opcode_3_and_mask() {
        let op = ArgOp::Access { access: 0x3F };
        let mut buf = Vec::new();
        let n = op.pack(&mut buf).unwrap();
        assert_eq!(n, 8);
        assert_eq!(u32::from_be_bytes(buf[0..4].try_into().unwrap()), 3);
        assert_eq!(u32::from_be_bytes(buf[4..8].try_into().unwrap()), 0x3F);
    }

    #[test]
    fn argop_close_encodes_seqid_and_stateid() {
        let op = ArgOp::Close { seqid: 7, stateid: [0xAA; 16] };
        let mut buf = Vec::new();
        let n = op.pack(&mut buf).unwrap();
        assert_eq!(n, 24);
        assert_eq!(u32::from_be_bytes(buf[0..4].try_into().unwrap()), 4);
        assert_eq!(u32::from_be_bytes(buf[4..8].try_into().unwrap()), 7);
        assert_eq!(&buf[8..24], &[0xAA; 16]);
    }

    #[test]
    fn argop_commit_encodes_offset_and_count() {
        let op = ArgOp::Commit { offset: 4096, count: 8192 };
        let mut buf = Vec::new();
        let n = op.pack(&mut buf).unwrap();
        assert_eq!(n, 16);
        assert_eq!(u32::from_be_bytes(buf[0..4].try_into().unwrap()), 5);
        assert_eq!(u64::from_be_bytes(buf[4..12].try_into().unwrap()), 4096);
        assert_eq!(u32::from_be_bytes(buf[12..16].try_into().unwrap()), 8192);
    }

    #[test]
    fn argop_delegpurge_encodes_clientid() {
        let op = ArgOp::Delegpurge { clientid: 42 };
        let mut buf = Vec::new();
        let n = op.pack(&mut buf).unwrap();
        assert_eq!(n, 12);
        assert_eq!(u32::from_be_bytes(buf[0..4].try_into().unwrap()), 7);
        assert_eq!(u64::from_be_bytes(buf[4..12].try_into().unwrap()), 42);
    }

    #[test]
    fn argop_delegreturn_encodes_stateid() {
        let op = ArgOp::Delegreturn { stateid: [0xBB; 16] };
        let mut buf = Vec::new();
        let n = op.pack(&mut buf).unwrap();
        assert_eq!(n, 20);
        assert_eq!(u32::from_be_bytes(buf[0..4].try_into().unwrap()), 8);
        assert_eq!(&buf[4..20], &[0xBB; 16]);
    }

    #[test]
    fn argop_link_encodes_newname() {
        let op = ArgOp::Link { newname: "link".to_owned() };
        let mut buf = Vec::new();
        let n = op.pack(&mut buf).unwrap();
        // 4 (opcode) + 4 (string len) + 4 ("link" = 4 bytes, no padding)
        assert_eq!(n, 12);
        assert_eq!(u32::from_be_bytes(buf[0..4].try_into().unwrap()), 11);
    }

    #[test]
    fn argop_lookupp_encodes_opcode_16() {
        let mut buf = Vec::new();
        let n = ArgOp::Lookupp.pack(&mut buf).unwrap();
        assert_eq!(n, 4);
        assert_eq!(u32::from_be_bytes(buf[0..4].try_into().unwrap()), 16);
    }

    #[test]
    fn argop_readlink_encodes_opcode_27() {
        let mut buf = Vec::new();
        let n = ArgOp::Readlink.pack(&mut buf).unwrap();
        assert_eq!(n, 4);
        assert_eq!(u32::from_be_bytes(buf[0..4].try_into().unwrap()), 27);
    }

    #[test]
    fn argop_remove_encodes_target_name() {
        let op = ArgOp::Remove { target: "old".to_owned() };
        let mut buf = Vec::new();
        let n = op.pack(&mut buf).unwrap();
        assert_eq!(n, 12);
        assert_eq!(u32::from_be_bytes(buf[0..4].try_into().unwrap()), 28);
    }

    #[test]
    fn argop_rename_encodes_both_names() {
        let op = ArgOp::Rename { oldname: "src".to_owned(), newname: "dst".to_owned() };
        let mut buf = Vec::new();
        let n = op.pack(&mut buf).unwrap();
        // 4 (opcode) + 4+4 (src/3+pad) + 4+4 (dst/3+pad)
        assert_eq!(n, 20);
        assert_eq!(u32::from_be_bytes(buf[0..4].try_into().unwrap()), 29);
    }

    #[test]
    fn argop_renew_encodes_clientid() {
        let op = ArgOp::Renew { clientid: 99 };
        let mut buf = Vec::new();
        let n = op.pack(&mut buf).unwrap();
        assert_eq!(n, 12);
        assert_eq!(u32::from_be_bytes(buf[0..4].try_into().unwrap()), 30);
    }

    #[test]
    fn argop_restorefh_encodes_opcode_31() {
        let mut buf = Vec::new();
        let n = ArgOp::Restorefh.pack(&mut buf).unwrap();
        assert_eq!(n, 4);
        assert_eq!(u32::from_be_bytes(buf[0..4].try_into().unwrap()), 31);
    }

    #[test]
    fn argop_savefh_encodes_opcode_32() {
        let mut buf = Vec::new();
        let n = ArgOp::Savefh.pack(&mut buf).unwrap();
        assert_eq!(n, 4);
        assert_eq!(u32::from_be_bytes(buf[0..4].try_into().unwrap()), 32);
    }

    #[test]
    fn argop_openattr_encodes_createdir_bool() {
        let op = ArgOp::Openattr { createdir: true };
        let mut buf = Vec::new();
        let n = op.pack(&mut buf).unwrap();
        assert_eq!(n, 8);
        assert_eq!(u32::from_be_bytes(buf[0..4].try_into().unwrap()), 19);
        assert_eq!(u32::from_be_bytes(buf[4..8].try_into().unwrap()), 1);
    }

    #[test]
    fn argop_open_confirm_encodes_stateid_seqid() {
        let op = ArgOp::OpenConfirm { stateid: [0xCC; 16], seqid: 2 };
        let mut buf = Vec::new();
        let n = op.pack(&mut buf).unwrap();
        assert_eq!(n, 24);
        assert_eq!(u32::from_be_bytes(buf[0..4].try_into().unwrap()), 20);
        assert_eq!(&buf[4..20], &[0xCC; 16]);
        assert_eq!(u32::from_be_bytes(buf[20..24].try_into().unwrap()), 2);
    }

    #[test]
    fn argop_open_downgrade_encodes_all_fields() {
        let op = ArgOp::OpenDowngrade { stateid: [0xDD; 16], seqid: 3, share_access: 1, share_deny: 0 };
        let mut buf = Vec::new();
        let n = op.pack(&mut buf).unwrap();
        assert_eq!(n, 32);
        assert_eq!(u32::from_be_bytes(buf[0..4].try_into().unwrap()), 21);
    }

    #[test]
    fn argop_setclientid_confirm_encodes_clientid_verifier() {
        let op = ArgOp::SetclientidConfirm { clientid: 100, verifier: [0xEE; 8] };
        let mut buf = Vec::new();
        let n = op.pack(&mut buf).unwrap();
        assert_eq!(n, 20);
        assert_eq!(u32::from_be_bytes(buf[0..4].try_into().unwrap()), 36);
        assert_eq!(u64::from_be_bytes(buf[4..12].try_into().unwrap()), 100);
        assert_eq!(&buf[12..20], &[0xEE; 8]);
    }

    #[test]
    fn argop_write_encodes_stateid_offset_stable_data() {
        let data = vec![0x41, 0x42, 0x43]; // 3 bytes -> needs 1 pad
        let op = ArgOp::Write { stateid: [0u8; 16], offset: 256, stable: 2, data };
        let mut buf = Vec::new();
        let n = op.pack(&mut buf).unwrap();
        // 4 (opcode) + 16 (stateid) + 8 (offset) + 4 (stable) + 4 (data len) + 4 (3 bytes + 1 pad)
        assert_eq!(n, 40);
        assert_eq!(u32::from_be_bytes(buf[0..4].try_into().unwrap()), 38);
    }

    #[test]
    fn argop_illegal_encodes_opcode_10044() {
        let mut buf = Vec::new();
        let n = ArgOp::Illegal.pack(&mut buf).unwrap();
        assert_eq!(n, 4);
        assert_eq!(u32::from_be_bytes(buf[0..4].try_into().unwrap()), 10044);
    }

    #[test]
    fn argop_create_encodes_opcode_and_typed_fields() {
        let op = ArgOp::Create { objtype: CreateType4::Dir, objname: "newdir".to_owned(), createattrs: Fattr4::default() };
        let mut buf = Vec::new();
        let n = op.pack(&mut buf).unwrap();
        assert_eq!(n, op.packed_size());
        // Opcode = 6 (CREATE, RFC 7530 S16.4).
        assert_eq!(u32::from_be_bytes(buf[0..4].try_into().unwrap()), 6);
        // CreateType4::Dir discriminant = 2 (NF4DIR).
        assert_eq!(u32::from_be_bytes(buf[4..8].try_into().unwrap()), 2);
    }

    // --- Response decoding for new ops ---

    #[test]
    fn compound_res_unpacks_access_result() {
        let mut wire = Vec::new();
        0u32.pack(&mut wire).unwrap();
        onc_xdr::pack_string("", &mut wire).unwrap();
        1u32.pack(&mut wire).unwrap();
        OP_ACCESS.pack(&mut wire).unwrap();
        0u32.pack(&mut wire).unwrap(); // status OK
        0x3Fu32.pack(&mut wire).unwrap(); // supported
        0x21u32.pack(&mut wire).unwrap(); // access
        let (res, _) = CompoundRes::unpack(&mut &wire[..]).unwrap();
        match &res.results[0].data {
            ResOpData::Access { supported, access } => {
                assert_eq!(*supported, 0x3F);
                assert_eq!(*access, 0x21);
            },
            other => panic!("expected ResOpData::Access, got {other:?}"),
        }
    }

    #[test]
    fn compound_res_unpacks_readlink_result() {
        let mut wire = Vec::new();
        0u32.pack(&mut wire).unwrap();
        onc_xdr::pack_string("", &mut wire).unwrap();
        1u32.pack(&mut wire).unwrap();
        OP_READLINK.pack(&mut wire).unwrap();
        0u32.pack(&mut wire).unwrap(); // status OK
        onc_xdr::pack_string("/target/path", &mut wire).unwrap();
        let (res, _) = CompoundRes::unpack(&mut &wire[..]).unwrap();
        match &res.results[0].data {
            ResOpData::Readlink(link) => assert_eq!(link, "/target/path"),
            other => panic!("expected ResOpData::Readlink, got {other:?}"),
        }
    }

    #[test]
    fn compound_res_unpacks_commit_verifier() {
        let mut wire = Vec::new();
        0u32.pack(&mut wire).unwrap();
        onc_xdr::pack_string("", &mut wire).unwrap();
        1u32.pack(&mut wire).unwrap();
        OP_COMMIT.pack(&mut wire).unwrap();
        0u32.pack(&mut wire).unwrap(); // status OK
        wire.extend_from_slice(&[0xAA; 8]); // writeverf
        let (res, _) = CompoundRes::unpack(&mut &wire[..]).unwrap();
        match &res.results[0].data {
            ResOpData::CommitVerf(verf) => assert_eq!(verf, &[0xAA; 8]),
            other => panic!("expected ResOpData::CommitVerf, got {other:?}"),
        }
    }

    #[test]
    fn compound_res_unpacks_write_result() {
        let mut wire = Vec::new();
        0u32.pack(&mut wire).unwrap();
        onc_xdr::pack_string("", &mut wire).unwrap();
        1u32.pack(&mut wire).unwrap();
        OP_WRITE.pack(&mut wire).unwrap();
        0u32.pack(&mut wire).unwrap(); // status OK
        100u32.pack(&mut wire).unwrap(); // count
        2u32.pack(&mut wire).unwrap(); // committed = FILE_SYNC4
        wire.extend_from_slice(&[0xBB; 8]); // writeverf
        let (res, _) = CompoundRes::unpack(&mut &wire[..]).unwrap();
        match &res.results[0].data {
            ResOpData::WriteRes { count, committed, writeverf } => {
                assert_eq!(*count, 100);
                assert_eq!(*committed, 2);
                assert_eq!(writeverf, &[0xBB; 8]);
            },
            other => panic!("expected ResOpData::WriteRes, got {other:?}"),
        }
    }

    #[test]
    fn compound_res_unpacks_lookupp_ok() {
        let mut wire = Vec::new();
        0u32.pack(&mut wire).unwrap();
        onc_xdr::pack_string("", &mut wire).unwrap();
        1u32.pack(&mut wire).unwrap();
        OP_LOOKUPP.pack(&mut wire).unwrap();
        0u32.pack(&mut wire).unwrap(); // status OK
        let (res, _) = CompoundRes::unpack(&mut &wire[..]).unwrap();
        assert_eq!(res.results[0].op_code, OP_LOOKUPP);
        assert!(matches!(res.results[0].data, ResOpData::None));
    }

    #[test]
    fn compound_res_unpacks_remove_with_change_info() {
        let mut wire = Vec::new();
        0u32.pack(&mut wire).unwrap();
        onc_xdr::pack_string("", &mut wire).unwrap();
        1u32.pack(&mut wire).unwrap();
        OP_REMOVE.pack(&mut wire).unwrap();
        0u32.pack(&mut wire).unwrap(); // status OK
        // change_info4: atomic=true, before=1, after=2
        1u32.pack(&mut wire).unwrap();
        1u64.pack(&mut wire).unwrap();
        2u64.pack(&mut wire).unwrap();
        let (res, _) = CompoundRes::unpack(&mut &wire[..]).unwrap();
        assert_eq!(res.results[0].op_code, OP_REMOVE);
        match &res.results[0].data {
            ResOpData::ChangeInfo(ci) => {
                assert!(ci.atomic);
                assert_eq!(ci.before, 1);
                assert_eq!(ci.after, 2);
            },
            other => panic!("expected ResOpData::ChangeInfo, got {other:?}"),
        }
    }

    #[test]
    fn compound_res_unpacks_rename_with_two_change_infos() {
        let mut wire = Vec::new();
        0u32.pack(&mut wire).unwrap();
        onc_xdr::pack_string("", &mut wire).unwrap();
        1u32.pack(&mut wire).unwrap();
        OP_RENAME.pack(&mut wire).unwrap();
        0u32.pack(&mut wire).unwrap(); // status OK
        // source change_info4
        0u32.pack(&mut wire).unwrap();
        10u64.pack(&mut wire).unwrap();
        11u64.pack(&mut wire).unwrap();
        // target change_info4
        1u32.pack(&mut wire).unwrap();
        20u64.pack(&mut wire).unwrap();
        21u64.pack(&mut wire).unwrap();
        let (res, _) = CompoundRes::unpack(&mut &wire[..]).unwrap();
        assert_eq!(res.results[0].op_code, OP_RENAME);
        match &res.results[0].data {
            ResOpData::RenameInfo { source, target } => {
                assert!(!source.atomic);
                assert_eq!(source.before, 10);
                assert_eq!(source.after, 11);
                assert!(target.atomic);
                assert_eq!(target.before, 20);
                assert_eq!(target.after, 21);
            },
            other => panic!("expected ResOpData::RenameInfo, got {other:?}"),
        }
    }

    #[test]
    fn compound_res_unpacks_close_stateid() {
        let mut wire = Vec::new();
        0u32.pack(&mut wire).unwrap();
        onc_xdr::pack_string("", &mut wire).unwrap();
        1u32.pack(&mut wire).unwrap();
        OP_CLOSE.pack(&mut wire).unwrap();
        0u32.pack(&mut wire).unwrap(); // status OK
        wire.extend_from_slice(&[0xFF; 16]); // stateid4
        let (res, _) = CompoundRes::unpack(&mut &wire[..]).unwrap();
        assert_eq!(res.results[0].op_code, OP_CLOSE);
        match &res.results[0].data {
            ResOpData::Stateid(sid) => {
                assert_eq!(sid.seqid, 0xFFFF_FFFF);
                assert_eq!(sid.other, [0xFF; NFS4_OTHER_SIZE]);
            },
            other => panic!("expected ResOpData::Stateid, got {other:?}"),
        }
    }

    #[test]
    fn compound_res_unpacks_setattr_bitmap() {
        let mut wire = Vec::new();
        0u32.pack(&mut wire).unwrap();
        onc_xdr::pack_string("", &mut wire).unwrap();
        1u32.pack(&mut wire).unwrap();
        OP_SETATTR.pack(&mut wire).unwrap();
        0u32.pack(&mut wire).unwrap(); // status OK
        // attrsset bitmap: 2 words
        2u32.pack(&mut wire).unwrap();
        (1u32 << 8).pack(&mut wire).unwrap();
        0u32.pack(&mut wire).unwrap();
        let (res, _) = CompoundRes::unpack(&mut &wire[..]).unwrap();
        assert_eq!(res.results[0].op_code, OP_SETATTR);
        match &res.results[0].data {
            ResOpData::Bitmap(words) => {
                assert_eq!(words.len(), 2);
                assert_eq!(words[0], 1 << 8);
                assert_eq!(words[1], 0);
            },
            other => panic!("expected ResOpData::Bitmap, got {other:?}"),
        }
    }

    // --- Wire constant value tests ---

    #[test]
    fn wire_constants_match_rfc7530() {
        assert_eq!(NFS4_FHSIZE, 128, "RFC 7530 S4: max file handle size is 128 bytes");
        assert_eq!(NFS4_VERIFIER_SIZE, 8, "RFC 7530 S2.2.3: verifier is 8 bytes");
        assert_eq!(NFS4_OTHER_SIZE, 12, "RFC 7530 S2.2.11: stateid other field is 12 bytes");
        assert_eq!(NFS4_OPAQUE_LIMIT, 1024, "RFC 7530 S2.2: opaque limit is 1024 bytes");
    }

    // --- New Nfs4Status variant round-trip tests ---

    #[test]
    fn nfs4_status_new_variants_round_trip() {
        let cases: &[(u32, Nfs4Status)] = &[
            (18, Nfs4Status::Xdev),
            (31, Nfs4Status::Mlink),
            (69, Nfs4Status::Dquot),
            (10005, Nfs4Status::TooSmall),
            (10006, Nfs4Status::ServerFault),
            (10007, Nfs4Status::BadType),
            (10008, Nfs4Status::Delay),
            (10009, Nfs4Status::Same),
            (10013, Nfs4Status::Grace),
            (10014, Nfs4Status::FhExpired),
            (10015, Nfs4Status::ShareDenied),
            (10017, Nfs4Status::ClidInuse),
            (10018, Nfs4Status::Resource),
            (10020, Nfs4Status::NoFilehandle),
            (10021, Nfs4Status::MinorVersMismatch),
            (10022, Nfs4Status::StaleClientid),
            (10023, Nfs4Status::StaleStateid),
            (10024, Nfs4Status::OldStateid),
            (10025, Nfs4Status::BadStateid),
            (10026, Nfs4Status::BadSeqid),
            (10027, Nfs4Status::NotSame),
            (10028, Nfs4Status::LockRange),
            (10029, Nfs4Status::Symlink),
            (10030, Nfs4Status::RestoreFh),
            (10031, Nfs4Status::LeaseMoved),
            (10032, Nfs4Status::AttrNotSupp),
            (10033, Nfs4Status::NoGrace),
            (10034, Nfs4Status::ReclaimBad),
            (10035, Nfs4Status::ReclaimConflict),
            (10037, Nfs4Status::LocksHeld),
            (10038, Nfs4Status::Openmode),
            (10039, Nfs4Status::BadOwner),
            (10040, Nfs4Status::BadChar),
            (10041, Nfs4Status::BadName),
            (10042, Nfs4Status::BadRange),
            (10043, Nfs4Status::LockNotSupp),
            (10044, Nfs4Status::OpIllegal),
            (10045, Nfs4Status::Deadlock),
            (10046, Nfs4Status::FileOpen),
            (10047, Nfs4Status::AdminRevoked),
            (10048, Nfs4Status::CbPathDown),
        ];
        for &(raw, expected) in cases {
            let decoded = Nfs4Status::from_u32(raw);
            assert_eq!(decoded, expected, "from_u32({raw}) should yield {expected:?}");
            assert_eq!(decoded.as_u32(), raw, "{expected:?}.as_u32() should yield {raw}");
            assert_eq!(Nfs4Status::from_u32(decoded.as_u32()), expected, "round-trip failed for {raw}");
        }
    }

    // --- Classification method tests ---

    #[test]
    fn nfs4_status_is_transient_positive() {
        assert!(Nfs4Status::Io.is_transient());
        assert!(Nfs4Status::Delay.is_transient());
        assert!(Nfs4Status::Resource.is_transient());
        assert!(Nfs4Status::ServerFault.is_transient());
    }

    #[test]
    fn nfs4_status_is_transient_negative() {
        assert!(!Nfs4Status::Perm.is_transient());
        assert!(!Nfs4Status::Acces.is_transient());
        assert!(!Nfs4Status::Stale.is_transient());
        assert!(!Nfs4Status::BadHandle.is_transient());
        assert!(!Nfs4Status::NoEnt.is_transient());
        assert!(!Nfs4Status::Ok.is_transient());
    }

    #[test]
    fn nfs4_status_is_stateid_error_positive() {
        assert!(Nfs4Status::StaleStateid.is_stateid_error());
        assert!(Nfs4Status::OldStateid.is_stateid_error());
        assert!(Nfs4Status::BadStateid.is_stateid_error());
        assert!(Nfs4Status::Expired.is_stateid_error());
        assert!(Nfs4Status::AdminRevoked.is_stateid_error());
    }

    #[test]
    fn nfs4_status_is_stateid_error_negative() {
        assert!(!Nfs4Status::Stale.is_stateid_error());
        assert!(!Nfs4Status::BadHandle.is_stateid_error());
        assert!(!Nfs4Status::Io.is_stateid_error());
        assert!(!Nfs4Status::Ok.is_stateid_error());
    }

    #[test]
    fn nfs4_status_is_lease_error_positive() {
        assert!(Nfs4Status::StaleClientid.is_lease_error());
        assert!(Nfs4Status::Expired.is_lease_error());
        assert!(Nfs4Status::LeaseMoved.is_lease_error());
    }

    #[test]
    fn nfs4_status_is_lease_error_negative() {
        assert!(!Nfs4Status::StaleStateid.is_lease_error());
        assert!(!Nfs4Status::Io.is_lease_error());
        assert!(!Nfs4Status::Ok.is_lease_error());
    }

    #[test]
    fn nfs4_status_is_grace_error_positive() {
        assert!(Nfs4Status::Grace.is_grace_error());
        assert!(Nfs4Status::NoGrace.is_grace_error());
        assert!(Nfs4Status::ReclaimBad.is_grace_error());
        assert!(Nfs4Status::ReclaimConflict.is_grace_error());
    }

    #[test]
    fn nfs4_status_is_grace_error_negative() {
        assert!(!Nfs4Status::Delay.is_grace_error());
        assert!(!Nfs4Status::Expired.is_grace_error());
        assert!(!Nfs4Status::Ok.is_grace_error());
    }

    #[test]
    fn nfs4_status_is_lock_error_positive() {
        assert!(Nfs4Status::Denied.is_lock_error());
        assert!(Nfs4Status::Locked.is_lock_error());
        assert!(Nfs4Status::ShareDenied.is_lock_error());
        assert!(Nfs4Status::BadSeqid.is_lock_error());
        assert!(Nfs4Status::LockRange.is_lock_error());
        assert!(Nfs4Status::LocksHeld.is_lock_error());
        assert!(Nfs4Status::Openmode.is_lock_error());
        assert!(Nfs4Status::BadRange.is_lock_error());
        assert!(Nfs4Status::LockNotSupp.is_lock_error());
        assert!(Nfs4Status::Deadlock.is_lock_error());
    }

    #[test]
    fn nfs4_status_is_lock_error_negative() {
        assert!(!Nfs4Status::Perm.is_lock_error());
        assert!(!Nfs4Status::Acces.is_lock_error());
        assert!(!Nfs4Status::Stale.is_lock_error());
        assert!(!Nfs4Status::Ok.is_lock_error());
    }

    // --- Single-variant recovery classification tests ---

    #[test]
    fn nfs4_status_is_grace_positive() {
        assert!(Nfs4Status::Grace.is_grace());
    }

    #[test]
    fn nfs4_status_is_grace_negative() {
        assert!(!Nfs4Status::NoGrace.is_grace());
        assert!(!Nfs4Status::Expired.is_grace());
        assert!(!Nfs4Status::Ok.is_grace());
    }

    #[test]
    fn nfs4_status_is_stale_clientid_positive() {
        assert!(Nfs4Status::StaleClientid.is_stale_clientid());
    }

    #[test]
    fn nfs4_status_is_stale_clientid_negative() {
        assert!(!Nfs4Status::StaleStateid.is_stale_clientid());
        assert!(!Nfs4Status::Expired.is_stale_clientid());
        assert!(!Nfs4Status::Ok.is_stale_clientid());
    }

    #[test]
    fn nfs4_status_is_expired_positive() {
        assert!(Nfs4Status::Expired.is_expired());
    }

    #[test]
    fn nfs4_status_is_expired_negative() {
        assert!(!Nfs4Status::StaleClientid.is_expired());
        assert!(!Nfs4Status::Grace.is_expired());
        assert!(!Nfs4Status::Ok.is_expired());
    }

    // --- Typed enum Pack/Unpack round-trip tests ---

    #[test]
    fn stable_how4_round_trips() {
        for (val, expected) in [(0, StableHow4::Unstable), (1, StableHow4::DataSync), (2, StableHow4::FileSync)] {
            let variant = StableHow4::from_u32(val);
            assert_eq!(variant, expected);
            assert_eq!(variant.as_u32(), val);
            // Pack/Unpack round-trip.
            let mut buf = Vec::new();
            variant.pack(&mut buf).unwrap();
            let (decoded, n) = StableHow4::unpack(&mut &buf[..]).unwrap();
            assert_eq!(n, 4);
            assert_eq!(decoded, expected);
        }
    }

    #[test]
    fn stable_how4_unknown_catch_all() {
        let variant = StableHow4::from_u32(99);
        assert_eq!(variant, StableHow4::Unknown(99));
        assert_eq!(variant.as_u32(), 99);
        let mut buf = Vec::new();
        variant.pack(&mut buf).unwrap();
        let (decoded, _) = StableHow4::unpack(&mut &buf[..]).unwrap();
        assert_eq!(decoded, StableHow4::Unknown(99));
    }

    #[test]
    fn open_delegation_type4_round_trips() {
        for (val, expected) in [(0, OpenDelegationType4::None), (1, OpenDelegationType4::Read), (2, OpenDelegationType4::Write)] {
            let variant = OpenDelegationType4::from_u32(val);
            assert_eq!(variant, expected);
            assert_eq!(variant.as_u32(), val);
            let mut buf = Vec::new();
            variant.pack(&mut buf).unwrap();
            let (decoded, n) = OpenDelegationType4::unpack(&mut &buf[..]).unwrap();
            assert_eq!(n, 4);
            assert_eq!(decoded, expected);
        }
    }

    #[test]
    fn open_delegation_type4_unknown_catch_all() {
        let variant = OpenDelegationType4::from_u32(77);
        assert_eq!(variant, OpenDelegationType4::Unknown(77));
        assert_eq!(variant.as_u32(), 77);
    }

    #[test]
    fn create_mode4_round_trips() {
        for (val, expected) in [(0, CreateMode4::Unchecked), (1, CreateMode4::Guarded), (2, CreateMode4::Exclusive)] {
            let variant = CreateMode4::from_u32(val);
            assert_eq!(variant, expected);
            assert_eq!(variant.as_u32(), val);
            let mut buf = Vec::new();
            variant.pack(&mut buf).unwrap();
            let (decoded, n) = CreateMode4::unpack(&mut &buf[..]).unwrap();
            assert_eq!(n, 4);
            assert_eq!(decoded, expected);
        }
    }

    #[test]
    fn create_mode4_unknown_catch_all() {
        let variant = CreateMode4::from_u32(55);
        assert_eq!(variant, CreateMode4::Unknown(55));
        assert_eq!(variant.as_u32(), 55);
    }

    #[test]
    fn open_type4_round_trips() {
        for (val, expected) in [(0, OpenType4::NoCreate), (1, OpenType4::Create)] {
            let variant = OpenType4::from_u32(val);
            assert_eq!(variant, expected);
            assert_eq!(variant.as_u32(), val);
            let mut buf = Vec::new();
            variant.pack(&mut buf).unwrap();
            let (decoded, n) = OpenType4::unpack(&mut &buf[..]).unwrap();
            assert_eq!(n, 4);
            assert_eq!(decoded, expected);
        }
    }

    #[test]
    fn open_type4_unknown_catch_all() {
        let variant = OpenType4::from_u32(42);
        assert_eq!(variant, OpenType4::Unknown(42));
        assert_eq!(variant.as_u32(), 42);
    }

    #[test]
    fn open_claim_type4_round_trips() {
        for (val, expected) in [(0, OpenClaimType4::Null), (1, OpenClaimType4::Previous), (2, OpenClaimType4::DelegateCur), (3, OpenClaimType4::DelegatePrev)] {
            let variant = OpenClaimType4::from_u32(val);
            assert_eq!(variant, expected);
            assert_eq!(variant.as_u32(), val);
            let mut buf = Vec::new();
            variant.pack(&mut buf).unwrap();
            let (decoded, n) = OpenClaimType4::unpack(&mut &buf[..]).unwrap();
            assert_eq!(n, 4);
            assert_eq!(decoded, expected);
        }
    }

    #[test]
    fn open_claim_type4_unknown_catch_all() {
        let variant = OpenClaimType4::from_u32(200);
        assert_eq!(variant, OpenClaimType4::Unknown(200));
        assert_eq!(variant.as_u32(), 200);
    }

    #[test]
    fn lock_type4_round_trips() {
        for (val, expected) in [(1, LockType4::ReadLt), (2, LockType4::WriteLt), (3, LockType4::ReadwLt), (4, LockType4::WritewLt)] {
            let variant = LockType4::from_u32(val);
            assert_eq!(variant, expected);
            assert_eq!(variant.as_u32(), val);
            let mut buf = Vec::new();
            variant.pack(&mut buf).unwrap();
            let (decoded, n) = LockType4::unpack(&mut &buf[..]).unwrap();
            assert_eq!(n, 4);
            assert_eq!(decoded, expected);
        }
    }

    #[test]
    fn lock_type4_unknown_catch_all() {
        // 0 is not a valid LockType4 value per RFC 7530 -- should fall to Unknown.
        let variant = LockType4::from_u32(0);
        assert_eq!(variant, LockType4::Unknown(0));
        assert_eq!(variant.as_u32(), 0);
        let variant = LockType4::from_u32(99);
        assert_eq!(variant, LockType4::Unknown(99));
        assert_eq!(variant.as_u32(), 99);
    }

    #[test]
    fn compound_res_unpacks_no_data_ops() {
        // RESTOREFH, SAVEFH, DELEGPURGE, DELEGRETURN, OPENATTR, RENEW,
        // NVERIFY, VERIFY, RELEASE_LOCKOWNER, ILLEGAL all have no result data.
        let no_data_ops = [OP_RESTOREFH, OP_SAVEFH, OP_DELEGPURGE, OP_DELEGRETURN, OP_OPENATTR, OP_RENEW, OP_NVERIFY, OP_VERIFY, OP_RELEASE_LOCKOWNER, OP_ILLEGAL];
        for &op in &no_data_ops {
            let mut wire = Vec::new();
            0u32.pack(&mut wire).unwrap();
            onc_xdr::pack_string("", &mut wire).unwrap();
            1u32.pack(&mut wire).unwrap();
            op.pack(&mut wire).unwrap();
            0u32.pack(&mut wire).unwrap(); // status OK
            let (res, _) = CompoundRes::unpack(&mut &wire[..]).unwrap();
            assert_eq!(res.results.len(), 1, "op {op}: expected 1 result");
            assert_eq!(res.results[0].op_code, op);
            assert!(matches!(res.results[0].data, ResOpData::None), "op {op}: expected ResOpData::None");
        }
    }

    // --- Phase 2 type tests ---

    #[test]
    fn stateid4_anonymous_constant() {
        assert_eq!(Stateid4::ANONYMOUS.seqid, 0);
        assert_eq!(Stateid4::ANONYMOUS.other, [0u8; NFS4_OTHER_SIZE]);
    }

    #[test]
    fn stateid4_read_bypass_constant() {
        assert_eq!(Stateid4::READ_BYPASS.seqid, 0xFFFF_FFFF);
        assert_eq!(Stateid4::READ_BYPASS.other, [0xFF; NFS4_OTHER_SIZE]);
    }

    #[test]
    fn stateid4_to_bytes_from_bytes_round_trip() {
        let sid = Stateid4 { seqid: 0x1234_5678, other: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12] };
        let bytes = sid.to_bytes();
        let restored = Stateid4::from_bytes(bytes);
        assert_eq!(restored, sid);
    }

    #[test]
    fn stateid4_pack_unpack_round_trip() {
        let sid = Stateid4 { seqid: 42, other: [0xAA; NFS4_OTHER_SIZE] };
        let mut buf = Vec::new();
        let n = sid.pack(&mut buf).unwrap();
        assert_eq!(n, 16);
        assert_eq!(buf.len(), 16);
        let (decoded, consumed) = Stateid4::unpack(&mut &buf[..]).unwrap();
        assert_eq!(consumed, 16);
        assert_eq!(decoded, sid);
    }

    #[test]
    fn stateid4_from_array_conversion() {
        let bytes = [0u8; 16];
        let sid: Stateid4 = bytes.into();
        assert_eq!(sid, Stateid4::ANONYMOUS);
        let back: [u8; 16] = sid.into();
        assert_eq!(back, bytes);
    }

    #[test]
    fn stateid4_packed_size_is_16() {
        assert_eq!(Stateid4::ANONYMOUS.packed_size(), 16);
        assert_eq!(Stateid4::READ_BYPASS.packed_size(), 16);
    }

    #[test]
    fn change_info4_unpack_from_bytes() {
        let mut wire = Vec::new();
        // atomic = true (non-zero u32)
        1u32.pack(&mut wire).unwrap();
        // before = 100
        100u64.pack(&mut wire).unwrap();
        // after = 200
        200u64.pack(&mut wire).unwrap();
        let (ci, n) = ChangeInfo4::unpack(&mut &wire[..]).unwrap();
        assert_eq!(n, 20);
        assert!(ci.atomic);
        assert_eq!(ci.before, 100);
        assert_eq!(ci.after, 200);
    }

    #[test]
    fn change_info4_unpack_atomic_false() {
        let mut wire = Vec::new();
        0u32.pack(&mut wire).unwrap(); // atomic = false
        50u64.pack(&mut wire).unwrap();
        51u64.pack(&mut wire).unwrap();
        let (ci, _) = ChangeInfo4::unpack(&mut &wire[..]).unwrap();
        assert!(!ci.atomic);
        assert_eq!(ci.before, 50);
        assert_eq!(ci.after, 51);
    }

    #[test]
    fn nfs_ftype4_from_u32_all_values() {
        assert_eq!(NfsFtype4::from_u32(1), NfsFtype4::Reg);
        assert_eq!(NfsFtype4::from_u32(2), NfsFtype4::Dir);
        assert_eq!(NfsFtype4::from_u32(3), NfsFtype4::Blk);
        assert_eq!(NfsFtype4::from_u32(4), NfsFtype4::Chr);
        assert_eq!(NfsFtype4::from_u32(5), NfsFtype4::Lnk);
        assert_eq!(NfsFtype4::from_u32(6), NfsFtype4::Sock);
        assert_eq!(NfsFtype4::from_u32(7), NfsFtype4::Fifo);
        assert_eq!(NfsFtype4::from_u32(8), NfsFtype4::AttrDir);
        assert_eq!(NfsFtype4::from_u32(9), NfsFtype4::NamedAttr);
    }

    #[test]
    fn nfs_ftype4_unknown_catch_all() {
        let ft = NfsFtype4::from_u32(0);
        assert_eq!(ft, NfsFtype4::Unknown(0));
        assert_eq!(ft.as_u32(), 0);
        let ft = NfsFtype4::from_u32(99);
        assert_eq!(ft, NfsFtype4::Unknown(99));
        assert_eq!(ft.as_u32(), 99);
    }

    #[test]
    fn nfs_ftype4_pack_unpack_round_trip() {
        for val in 1..=9 {
            let ft = NfsFtype4::from_u32(val);
            let mut buf = Vec::new();
            let n = ft.pack(&mut buf).unwrap();
            assert_eq!(n, 4);
            let (decoded, consumed) = NfsFtype4::unpack(&mut &buf[..]).unwrap();
            assert_eq!(consumed, 4);
            assert_eq!(decoded, ft);
            assert_eq!(decoded.as_u32(), val);
        }
    }

    #[test]
    fn nfs_ftype4_display() {
        assert_eq!(format!("{}", NfsFtype4::Reg), "NF4REG");
        assert_eq!(format!("{}", NfsFtype4::Dir), "NF4DIR");
        assert_eq!(format!("{}", NfsFtype4::Unknown(42)), "NF4UNKNOWN(42)");
    }

    #[test]
    fn open_owner4_pack_unpack_round_trip() {
        let oo = OpenOwner4 { clientid: 0xDEAD_BEEF_CAFE_1234, owner: vec![0x01, 0x02, 0x03] };
        let mut buf = Vec::new();
        let n = oo.pack(&mut buf).unwrap();
        assert_eq!(n, oo.packed_size());
        let (decoded, consumed) = OpenOwner4::unpack(&mut &buf[..]).unwrap();
        assert_eq!(consumed, n);
        assert_eq!(decoded.clientid, oo.clientid);
        assert_eq!(decoded.owner, oo.owner);
    }

    #[test]
    fn open_owner4_empty_owner() {
        let oo = OpenOwner4 { clientid: 1, owner: vec![] };
        let mut buf = Vec::new();
        let n = oo.pack(&mut buf).unwrap();
        // 8 (clientid) + 4 (opaque len=0) = 12
        assert_eq!(n, 12);
        let (decoded, _) = OpenOwner4::unpack(&mut &buf[..]).unwrap();
        assert_eq!(decoded.owner, Vec::<u8>::new());
    }

    #[test]
    fn lock_owner4_pack_unpack_round_trip() {
        let lo = LockOwner4 { clientid: 42, owner: vec![0xAA, 0xBB, 0xCC, 0xDD, 0xEE] };
        let mut buf = Vec::new();
        let n = lo.pack(&mut buf).unwrap();
        assert_eq!(n, lo.packed_size());
        let (decoded, consumed) = LockOwner4::unpack(&mut &buf[..]).unwrap();
        assert_eq!(consumed, n);
        assert_eq!(decoded.clientid, lo.clientid);
        assert_eq!(decoded.owner, lo.owner);
    }

    #[test]
    fn nfs_ace4_pack_unpack_round_trip() {
        let ace = NfsAce4 { ace_type: 0, flag: 0x0040, access_mask: 0x001F_01FF, who: "user@domain".to_owned() };
        let mut buf = Vec::new();
        let n = ace.pack(&mut buf).unwrap();
        assert_eq!(n, ace.packed_size());
        let (decoded, consumed) = NfsAce4::unpack(&mut &buf[..]).unwrap();
        assert_eq!(consumed, n);
        assert_eq!(decoded.ace_type, ace.ace_type);
        assert_eq!(decoded.flag, ace.flag);
        assert_eq!(decoded.access_mask, ace.access_mask);
        assert_eq!(decoded.who, ace.who);
    }

    #[test]
    fn nfs_ace4_short_who_with_padding() {
        // "a" is 1 byte -> 3 bytes XDR padding.
        let ace = NfsAce4 { ace_type: 1, flag: 0, access_mask: 0, who: "a".to_owned() };
        let mut buf = Vec::new();
        let n = ace.pack(&mut buf).unwrap();
        // 4 (type) + 4 (flag) + 4 (mask) + 4 (string len) + 4 (1 byte + 3 pad) = 20
        assert_eq!(n, 20);
        let (decoded, consumed) = NfsAce4::unpack(&mut &buf[..]).unwrap();
        assert_eq!(consumed, 20);
        assert_eq!(decoded.who, "a");
    }

    // --- Phase 2b tests ---

    #[test]
    fn create_type4_pack_dir() {
        let ct = CreateType4::Dir;
        let mut buf = Vec::new();
        let n = ct.pack(&mut buf).unwrap();
        assert_eq!(n, 4);
        let (disc, _) = u32::unpack(&mut &buf[..]).unwrap();
        assert_eq!(disc, 2); // NF4DIR
    }

    #[test]
    fn create_type4_pack_sock() {
        let ct = CreateType4::Sock;
        let mut buf = Vec::new();
        let n = ct.pack(&mut buf).unwrap();
        assert_eq!(n, 4);
        let (disc, _) = u32::unpack(&mut &buf[..]).unwrap();
        assert_eq!(disc, 6); // NF4SOCK
    }

    #[test]
    fn create_type4_pack_fifo() {
        let ct = CreateType4::Fifo;
        let mut buf = Vec::new();
        let n = ct.pack(&mut buf).unwrap();
        assert_eq!(n, 4);
        let (disc, _) = u32::unpack(&mut &buf[..]).unwrap();
        assert_eq!(disc, 7); // NF4FIFO
    }

    #[test]
    fn create_type4_pack_lnk() {
        let ct = CreateType4::Lnk("/target".to_owned());
        let mut buf = Vec::new();
        let n = ct.pack(&mut buf).unwrap();
        // 4 (disc) + 4 (string len) + 8 ("/target" = 7 bytes + 1 pad)
        assert_eq!(n, 16);
        assert_eq!(n, ct.packed_size());
        let (disc, _) = u32::unpack(&mut &buf[..]).unwrap();
        assert_eq!(disc, 5); // NF4LNK
    }

    #[test]
    fn create_type4_pack_blk() {
        let ct = CreateType4::Blk { specdata1: 8, specdata2: 0 };
        let mut buf = Vec::new();
        let n = ct.pack(&mut buf).unwrap();
        assert_eq!(n, 12); // 4 (disc) + 4 + 4
        assert_eq!(n, ct.packed_size());
        let (disc, _) = u32::unpack(&mut &buf[..]).unwrap();
        assert_eq!(disc, 3); // NF4BLK
    }

    #[test]
    fn create_type4_pack_chr() {
        let ct = CreateType4::Chr { specdata1: 1, specdata2: 3 };
        let mut buf = Vec::new();
        let n = ct.pack(&mut buf).unwrap();
        assert_eq!(n, 12);
        assert_eq!(n, ct.packed_size());
        let (disc, _) = u32::unpack(&mut &buf[..]).unwrap();
        assert_eq!(disc, 4); // NF4CHR
    }

    #[test]
    fn locker4_new_lock_owner_pack() {
        let locker = Locker4::NewLockOwner { open_seqid: 1, open_stateid: Stateid4::ANONYMOUS, lock_seqid: 0, lock_owner: LockOwner4 { clientid: 42, owner: vec![0x01] } };
        let mut buf = Vec::new();
        let n = locker.pack(&mut buf).unwrap();
        assert_eq!(n, locker.packed_size());
        // Discriminant should be TRUE (1)
        let (disc, _) = u32::unpack(&mut &buf[..]).unwrap();
        assert_eq!(disc, 1);
    }

    #[test]
    fn locker4_exist_lock_owner_pack() {
        let locker = Locker4::ExistLockOwner { lock_stateid: Stateid4::ANONYMOUS, lock_seqid: 5 };
        let mut buf = Vec::new();
        let n = locker.pack(&mut buf).unwrap();
        assert_eq!(n, locker.packed_size());
        // Discriminant should be FALSE (0)
        let (disc, _) = u32::unpack(&mut &buf[..]).unwrap();
        assert_eq!(disc, 0);
        // 4 (disc) + 16 (stateid) + 4 (seqid) = 24
        assert_eq!(n, 24);
    }

    #[test]
    fn open_claim4_null_pack() {
        let claim = OpenClaim4::Null("testfile".to_owned());
        let mut buf = Vec::new();
        let n = claim.pack(&mut buf).unwrap();
        assert_eq!(n, claim.packed_size());
        let (disc, _) = u32::unpack(&mut &buf[..]).unwrap();
        assert_eq!(disc, 0); // CLAIM_NULL
    }

    #[test]
    fn open_claim4_previous_pack() {
        let claim = OpenClaim4::Previous(OpenDelegationType4::Read);
        let mut buf = Vec::new();
        let n = claim.pack(&mut buf).unwrap();
        assert_eq!(n, 8); // 4 (claim_type) + 4 (deleg_type)
        assert_eq!(n, claim.packed_size());
        let (disc, _) = u32::unpack(&mut &buf[..]).unwrap();
        assert_eq!(disc, 1); // CLAIM_PREVIOUS
    }

    #[test]
    fn open_flag4_no_create_pack() {
        let flag = OpenFlag4::NoCreate;
        let mut buf = Vec::new();
        let n = flag.pack(&mut buf).unwrap();
        assert_eq!(n, 4);
        assert_eq!(n, flag.packed_size());
        let (disc, _) = u32::unpack(&mut &buf[..]).unwrap();
        assert_eq!(disc, 0); // OPEN4_NOCREATE
    }

    #[test]
    fn fattr4_pack_unpack_round_trip_empty() {
        let fa = Fattr4 { bitmap: AttrRequest::empty(), attrvals: vec![] };
        let mut buf = Vec::new();
        let n = fa.pack(&mut buf).unwrap();
        assert_eq!(n, fa.packed_size());
        let (decoded, consumed) = Fattr4::unpack(&mut &buf[..]).unwrap();
        assert_eq!(consumed, n);
        assert_eq!(decoded.attrvals, Vec::<u8>::new());
        assert_eq!(decoded.bitmap.words.len(), 2);
    }

    #[test]
    fn fattr4_pack_with_fsid_bitmap() {
        let fa = Fattr4 { bitmap: AttrRequest::fsid_only(), attrvals: vec![0xDE, 0xAD] };
        let mut buf = Vec::new();
        let n = fa.pack(&mut buf).unwrap();
        assert_eq!(n, fa.packed_size());
        let (decoded, consumed) = Fattr4::unpack(&mut &buf[..]).unwrap();
        assert_eq!(consumed, n);
        assert_eq!(decoded.bitmap.words[0], 1 << 8);
        assert_eq!(decoded.attrvals, vec![0xDE, 0xAD]);
    }

    #[test]
    fn compound_res_multi_op_with_new_ops() {
        // PUTROOTFH + LOOKUPP + ACCESS + READLINK + SAVEFH + GETFH
        let mut wire = Vec::new();
        0u32.pack(&mut wire).unwrap();
        onc_xdr::pack_string("", &mut wire).unwrap();
        6u32.pack(&mut wire).unwrap(); // 6 results
        // PUTROOTFH OK
        OP_PUTROOTFH.pack(&mut wire).unwrap();
        0u32.pack(&mut wire).unwrap();
        // LOOKUPP OK
        OP_LOOKUPP.pack(&mut wire).unwrap();
        0u32.pack(&mut wire).unwrap();
        // ACCESS OK: supported=0x3F, access=0x01
        OP_ACCESS.pack(&mut wire).unwrap();
        0u32.pack(&mut wire).unwrap();
        0x3Fu32.pack(&mut wire).unwrap();
        0x01u32.pack(&mut wire).unwrap();
        // READLINK OK: "/etc"
        OP_READLINK.pack(&mut wire).unwrap();
        0u32.pack(&mut wire).unwrap();
        onc_xdr::pack_string("/etc", &mut wire).unwrap();
        // SAVEFH OK
        OP_SAVEFH.pack(&mut wire).unwrap();
        0u32.pack(&mut wire).unwrap();
        // GETFH OK + handle
        OP_GETFH.pack(&mut wire).unwrap();
        0u32.pack(&mut wire).unwrap();
        pack_opaque(&[0xCA, 0xFE], &mut wire).unwrap();

        let (res, _) = CompoundRes::unpack(&mut &wire[..]).unwrap();
        assert_eq!(res.results.len(), 6);
        assert!(matches!(res.results[0].data, ResOpData::None)); // PUTROOTFH
        assert!(matches!(res.results[1].data, ResOpData::None)); // LOOKUPP
        match &res.results[2].data {
            ResOpData::Access { supported, access } => {
                assert_eq!(*supported, 0x3F);
                assert_eq!(*access, 0x01);
            },
            other => panic!("expected Access, got {other:?}"),
        }
        match &res.results[3].data {
            ResOpData::Readlink(link) => assert_eq!(link, "/etc"),
            other => panic!("expected Readlink, got {other:?}"),
        }
        assert!(matches!(res.results[4].data, ResOpData::None)); // SAVEFH
        match &res.results[5].data {
            ResOpData::Fh(fh) => assert_eq!(fh.as_slice(), &[0xCA, 0xFE]),
            other => panic!("expected Fh, got {other:?}"),
        }
    }

    // =========================================================================
    // Phase 3a: Typed ArgOp variant encoding tests
    // =========================================================================

    #[test]
    fn argop_create_dir_wire_layout() {
        let op = ArgOp::Create { objtype: CreateType4::Dir, objname: "subdir".to_owned(), createattrs: Fattr4::default() };
        let mut buf = Vec::new();
        let n = op.pack(&mut buf).unwrap();
        assert_eq!(n, op.packed_size());
        let mut off = 0;
        // Opcode = 6 (CREATE).
        assert_eq!(u32::from_be_bytes(buf[off..off + 4].try_into().unwrap()), 6);
        off += 4;
        // CreateType4::Dir = 2 (NF4DIR).
        assert_eq!(u32::from_be_bytes(buf[off..off + 4].try_into().unwrap()), 2);
        off += 4;
        // objname "subdir" = XDR string len 6.
        assert_eq!(u32::from_be_bytes(buf[off..off + 4].try_into().unwrap()), 6);
        off += 4;
        assert_eq!(&buf[off..off + 6], b"subdir");
    }

    #[test]
    fn argop_create_symlink_wire_layout() {
        let op = ArgOp::Create { objtype: CreateType4::Lnk("/tmp".to_owned()), objname: "mylink".to_owned(), createattrs: Fattr4::default() };
        let mut buf = Vec::new();
        let n = op.pack(&mut buf).unwrap();
        assert_eq!(n, op.packed_size());
        // Opcode = 6.
        assert_eq!(u32::from_be_bytes(buf[0..4].try_into().unwrap()), 6);
        // CreateType4::Lnk = 5.
        assert_eq!(u32::from_be_bytes(buf[4..8].try_into().unwrap()), 5);
    }

    #[test]
    fn argop_lock_wire_layout() {
        let op = ArgOp::Lock { locktype: LockType4::WriteLt, reclaim: false, offset: 0x100, length: 0x200, locker: Locker4::ExistLockOwner { lock_stateid: Stateid4::ANONYMOUS, lock_seqid: 3 } };
        let mut buf = Vec::new();
        let n = op.pack(&mut buf).unwrap();
        assert_eq!(n, op.packed_size());
        let mut off = 0;
        // Opcode = 12 (LOCK).
        assert_eq!(u32::from_be_bytes(buf[off..off + 4].try_into().unwrap()), 12);
        off += 4;
        // LockType4::WriteLt = 2.
        assert_eq!(u32::from_be_bytes(buf[off..off + 4].try_into().unwrap()), 2);
        off += 4;
        // reclaim = false (0).
        assert_eq!(u32::from_be_bytes(buf[off..off + 4].try_into().unwrap()), 0);
        off += 4;
        // offset.
        assert_eq!(u64::from_be_bytes(buf[off..off + 8].try_into().unwrap()), 0x100);
        off += 8;
        // length.
        assert_eq!(u64::from_be_bytes(buf[off..off + 8].try_into().unwrap()), 0x200);
    }

    #[test]
    fn argop_lockt_wire_layout() {
        let op = ArgOp::Lockt { locktype: LockType4::ReadLt, offset: 0, length: 0, owner: LockOwner4 { clientid: 42, owner: vec![0x01, 0x02] } };
        let mut buf = Vec::new();
        let n = op.pack(&mut buf).unwrap();
        assert_eq!(n, op.packed_size());
        // Opcode = 13 (LOCKT).
        assert_eq!(u32::from_be_bytes(buf[0..4].try_into().unwrap()), 13);
        // LockType4::ReadLt = 1.
        assert_eq!(u32::from_be_bytes(buf[4..8].try_into().unwrap()), 1);
        // offset = 0.
        assert_eq!(u64::from_be_bytes(buf[8..16].try_into().unwrap()), 0);
        // length = 0.
        assert_eq!(u64::from_be_bytes(buf[16..24].try_into().unwrap()), 0);
    }

    #[test]
    fn argop_locku_wire_layout() {
        let sid = Stateid4 { seqid: 7, other: [0xAA; NFS4_OTHER_SIZE] };
        let op = ArgOp::Locku { locktype: LockType4::WriteLt, seqid: 5, lock_stateid: sid, offset: 1024, length: 2048 };
        let mut buf = Vec::new();
        let n = op.pack(&mut buf).unwrap();
        assert_eq!(n, op.packed_size());
        // Opcode = 14 (LOCKU).
        assert_eq!(u32::from_be_bytes(buf[0..4].try_into().unwrap()), 14);
        // LockType4::WriteLt = 2.
        assert_eq!(u32::from_be_bytes(buf[4..8].try_into().unwrap()), 2);
        // seqid = 5.
        assert_eq!(u32::from_be_bytes(buf[8..12].try_into().unwrap()), 5);
        // stateid at [12..28] -- verify seqid part.
        assert_eq!(u32::from_be_bytes(buf[12..16].try_into().unwrap()), 7);
        // offset at [28..36].
        assert_eq!(u64::from_be_bytes(buf[28..36].try_into().unwrap()), 1024);
        // length at [36..44].
        assert_eq!(u64::from_be_bytes(buf[36..44].try_into().unwrap()), 2048);
    }

    #[test]
    fn argop_nverify_wire_layout() {
        let op = ArgOp::Nverify { obj_attributes: Fattr4::default() };
        let mut buf = Vec::new();
        let n = op.pack(&mut buf).unwrap();
        assert_eq!(n, op.packed_size());
        // Opcode = 17 (NVERIFY).
        assert_eq!(u32::from_be_bytes(buf[0..4].try_into().unwrap()), 17);
    }

    #[test]
    fn argop_open_wire_layout() {
        let op = ArgOp::Open { seqid: 1, share_access: 1, share_deny: 0, owner: OpenOwner4 { clientid: 0, owner: b"nfswolf".to_vec() }, openhow: OpenFlag4::NoCreate, claim: OpenClaim4::Null("test.txt".to_owned()) };
        let mut buf = Vec::new();
        let n = op.pack(&mut buf).unwrap();
        assert_eq!(n, op.packed_size());
        let mut off = 0;
        // Opcode = 18 (OPEN).
        assert_eq!(u32::from_be_bytes(buf[off..off + 4].try_into().unwrap()), 18);
        off += 4;
        // seqid = 1.
        assert_eq!(u32::from_be_bytes(buf[off..off + 4].try_into().unwrap()), 1);
        off += 4;
        // share_access = 1 (OPEN4_SHARE_ACCESS_READ).
        assert_eq!(u32::from_be_bytes(buf[off..off + 4].try_into().unwrap()), 1);
        off += 4;
        // share_deny = 0 (OPEN4_SHARE_DENY_NONE).
        assert_eq!(u32::from_be_bytes(buf[off..off + 4].try_into().unwrap()), 0);
        off += 4;
        // open_owner4: clientid = 0.
        assert_eq!(u64::from_be_bytes(buf[off..off + 8].try_into().unwrap()), 0);
        off += 8;
        // open_owner4: owner opaque len = 7 ("nfswolf").
        assert_eq!(u32::from_be_bytes(buf[off..off + 4].try_into().unwrap()), 7);
        off += 4;
        assert_eq!(&buf[off..off + 7], b"nfswolf");
    }

    #[test]
    fn argop_setattr_wire_layout() {
        let op = ArgOp::Setattr { stateid: Stateid4::ANONYMOUS, obj_attributes: Fattr4::default() };
        let mut buf = Vec::new();
        let n = op.pack(&mut buf).unwrap();
        assert_eq!(n, op.packed_size());
        // Opcode = 34 (SETATTR).
        assert_eq!(u32::from_be_bytes(buf[0..4].try_into().unwrap()), 34);
        // Stateid at [4..20] = anonymous (all zeros).
        assert_eq!(&buf[4..20], &[0u8; 16]);
    }

    #[test]
    fn argop_setclientid_wire_layout() {
        let op = ArgOp::Setclientid { client_verifier: [0x6E, 0x66, 0x73, 0x77, 0x6F, 0x6C, 0x66, 0x00], client_id: b"testclient".to_vec(), cb_program: 0x4000_0000, cb_netid: "tcp".to_owned(), cb_addr: "1.2.3.4.0.1".to_owned(), callback_ident: 1 };
        let mut buf = Vec::new();
        let n = op.pack(&mut buf).unwrap();
        assert_eq!(n, op.packed_size());
        let mut off = 0;
        // Opcode = 35 (SETCLIENTID).
        assert_eq!(u32::from_be_bytes(buf[off..off + 4].try_into().unwrap()), 35);
        off += 4;
        // 8-byte verifier = "nfswolf\0".
        assert_eq!(&buf[off..off + 8], &[0x6E, 0x66, 0x73, 0x77, 0x6F, 0x6C, 0x66, 0x00]);
        off += 8;
        // client_id opaque: len = 10.
        assert_eq!(u32::from_be_bytes(buf[off..off + 4].try_into().unwrap()), 10);
        off += 4;
        assert_eq!(&buf[off..off + 10], b"testclient");
        off += 12; // 10 bytes data + 2 bytes padding
        // cb_program = 0x40000000.
        assert_eq!(u32::from_be_bytes(buf[off..off + 4].try_into().unwrap()), 0x4000_0000);
        off += 4;
        // cb_netid "tcp" = XDR string len 3.
        assert_eq!(u32::from_be_bytes(buf[off..off + 4].try_into().unwrap()), 3);
        off += 4;
        assert_eq!(&buf[off..off + 3], b"tcp");
        off += 4; // 3 bytes + 1 pad
        // cb_addr "1.2.3.4.0.1" = XDR string len 11.
        assert_eq!(u32::from_be_bytes(buf[off..off + 4].try_into().unwrap()), 11);
        off += 4;
        assert_eq!(&buf[off..off + 11], b"1.2.3.4.0.1");
        off += 12; // 11 bytes + 1 pad
        // callback_ident = 1.
        assert_eq!(u32::from_be_bytes(buf[off..off + 4].try_into().unwrap()), 1);
    }

    #[test]
    fn argop_verify_wire_layout() {
        let op = ArgOp::Verify { obj_attributes: Fattr4::default() };
        let mut buf = Vec::new();
        let n = op.pack(&mut buf).unwrap();
        assert_eq!(n, op.packed_size());
        // Opcode = 37 (VERIFY).
        assert_eq!(u32::from_be_bytes(buf[0..4].try_into().unwrap()), 37);
    }

    #[test]
    fn argop_release_lockowner_wire_layout() {
        let op = ArgOp::ReleaseLockowner { lock_owner: LockOwner4 { clientid: 99, owner: vec![0xAB, 0xCD] } };
        let mut buf = Vec::new();
        let n = op.pack(&mut buf).unwrap();
        assert_eq!(n, op.packed_size());
        // Opcode = 39 (RELEASE_LOCKOWNER).
        assert_eq!(u32::from_be_bytes(buf[0..4].try_into().unwrap()), 39);
        // LockOwner4: clientid = 99.
        assert_eq!(u64::from_be_bytes(buf[4..12].try_into().unwrap()), 99);
        // Owner opaque len = 2.
        assert_eq!(u32::from_be_bytes(buf[12..16].try_into().unwrap()), 2);
        assert_eq!(&buf[16..18], &[0xAB, 0xCD]);
    }

    #[test]
    fn builder_setclientid_produces_typed_variant() {
        let ops = CompoundBuilder::new().setclientid("probe", "0.0.0.0.0.0").build();
        assert_eq!(ops.len(), 1);
        match &ops[0] {
            ArgOp::Setclientid { client_verifier, client_id, cb_program, cb_netid, cb_addr, callback_ident } => {
                assert_eq!(client_verifier, &[0x6E, 0x66, 0x73, 0x77, 0x6F, 0x6C, 0x66, 0x00]);
                assert_eq!(client_id, b"probe");
                assert_eq!(*cb_program, 0x4000_0000);
                assert_eq!(cb_netid, "tcp");
                assert_eq!(cb_addr, "0.0.0.0.0.0");
                assert_eq!(*callback_ident, 1);
            },
            other => panic!("expected ArgOp::Setclientid, got {other:?}"),
        }
    }

    #[test]
    fn builder_open_read_produces_typed_variant() {
        let ops = CompoundBuilder::new().open_read("test.txt").build();
        assert_eq!(ops.len(), 1);
        match &ops[0] {
            ArgOp::Open { seqid, share_access, share_deny, owner, openhow, claim } => {
                assert_eq!(*seqid, 1);
                assert_eq!(*share_access, 1);
                assert_eq!(*share_deny, 0);
                assert_eq!(owner.clientid, 0);
                assert_eq!(owner.owner, b"nfswolf");
                assert!(matches!(openhow, OpenFlag4::NoCreate));
                match claim {
                    OpenClaim4::Null(name) => assert_eq!(name, "test.txt"),
                    other => panic!("expected OpenClaim4::Null, got {other:?}"),
                }
            },
            other => panic!("expected ArgOp::Open, got {other:?}"),
        }
    }

    #[test]
    fn builder_setclientid_wire_compatible_with_old_encoding() {
        // The typed variant must produce the exact same wire bytes as the old
        // encode_setclientid() helper did.
        let ops = CompoundBuilder::new().setclientid("nfswolf-probe", "10.0.0.1.8.1").build();
        let mut buf = Vec::new();
        ops[0].pack(&mut buf).unwrap();
        // Verify the wire starts with opcode 35.
        assert_eq!(u32::from_be_bytes(buf[0..4].try_into().unwrap()), 35);
        // Verify packed_size matches actual.
        assert_eq!(ops[0].packed_size(), buf.len());
    }

    #[test]
    fn builder_open_read_wire_compatible_with_old_encoding() {
        let ops = CompoundBuilder::new().open_read("shadow").build();
        let mut buf = Vec::new();
        ops[0].pack(&mut buf).unwrap();
        // Verify the wire starts with opcode 18.
        assert_eq!(u32::from_be_bytes(buf[0..4].try_into().unwrap()), 18);
        assert_eq!(ops[0].packed_size(), buf.len());
    }

    // =========================================================================
    // Phase 3b: Response decoder tests
    // =========================================================================

    #[test]
    fn decode_lockt_result_void() {
        // LOCKT on NFS4_OK has no response body (VOID).
        let (data, n) = decode_op_result_data(OP_LOCKT, &mut &[][..]).unwrap();
        assert_eq!(n, 0);
        assert!(matches!(data, ResOpData::None));
    }

    #[test]
    fn decode_setclientid_result() {
        let mut wire = Vec::new();
        0xDEAD_BEEF_CAFE_1234u64.pack(&mut wire).unwrap(); // clientid
        wire.extend_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]); // verifier
        let (data, n) = decode_op_result_data(OP_SETCLIENTID, &mut &wire[..]).unwrap();
        assert_eq!(n, 16);
        match data {
            ResOpData::Setclientid { clientid, confirm_verifier } => {
                assert_eq!(clientid, 0xDEAD_BEEF_CAFE_1234);
                assert_eq!(confirm_verifier, [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]);
            },
            other => panic!("expected Setclientid, got {other:?}"),
        }
    }

    #[test]
    fn decode_lock_result_stateid() {
        let sid = Stateid4 { seqid: 42, other: [0xAA; NFS4_OTHER_SIZE] };
        let mut wire = Vec::new();
        sid.pack(&mut wire).unwrap();
        let (data, n) = decode_op_result_data(OP_LOCK, &mut &wire[..]).unwrap();
        assert_eq!(n, 16);
        match data {
            ResOpData::Stateid(decoded) => assert_eq!(decoded, sid),
            other => panic!("expected Stateid, got {other:?}"),
        }
    }

    #[test]
    fn decode_create_result() {
        let mut wire = Vec::new();
        // change_info4: atomic=true, before=100, after=200
        1u32.pack(&mut wire).unwrap();
        100u64.pack(&mut wire).unwrap();
        200u64.pack(&mut wire).unwrap();
        // bitmap4: 2 words
        2u32.pack(&mut wire).unwrap();
        0x0100u32.pack(&mut wire).unwrap(); // word 0
        0u32.pack(&mut wire).unwrap(); // word 1
        let (data, _) = decode_op_result_data(OP_CREATE, &mut &wire[..]).unwrap();
        match data {
            ResOpData::Create { cinfo, attrset } => {
                assert!(cinfo.atomic);
                assert_eq!(cinfo.before, 100);
                assert_eq!(cinfo.after, 200);
                assert_eq!(attrset, vec![0x0100, 0]);
            },
            other => panic!("expected Create, got {other:?}"),
        }
    }

    #[test]
    fn decode_open_result_delegate_none() {
        let mut wire = Vec::new();
        // stateid4
        let sid = Stateid4 { seqid: 1, other: [0xBB; NFS4_OTHER_SIZE] };
        sid.pack(&mut wire).unwrap();
        // change_info4
        0u32.pack(&mut wire).unwrap(); // atomic=false
        50u64.pack(&mut wire).unwrap();
        51u64.pack(&mut wire).unwrap();
        // rflags
        0x0004u32.pack(&mut wire).unwrap(); // OPEN4_RESULT_CONFIRM
        // bitmap4 attrset: 1 word
        1u32.pack(&mut wire).unwrap();
        0u32.pack(&mut wire).unwrap();
        // delegation: OPEN_DELEGATE_NONE
        0u32.pack(&mut wire).unwrap();
        let (data, _) = decode_op_result_data(OP_OPEN, &mut &wire[..]).unwrap();
        match data {
            ResOpData::Open { stateid, cinfo, rflags, attrset, delegation } => {
                assert_eq!(stateid, sid);
                assert!(!cinfo.atomic);
                assert_eq!(cinfo.before, 50);
                assert_eq!(cinfo.after, 51);
                assert_eq!(rflags, 0x0004);
                assert_eq!(attrset, vec![0]);
                assert!(matches!(delegation, OpenDelegation4::None));
            },
            other => panic!("expected Open, got {other:?}"),
        }
    }

    #[test]
    fn decode_open_result_delegate_read() {
        let mut wire = Vec::new();
        // stateid4
        Stateid4::ANONYMOUS.pack(&mut wire).unwrap();
        // change_info4
        1u32.pack(&mut wire).unwrap();
        10u64.pack(&mut wire).unwrap();
        11u64.pack(&mut wire).unwrap();
        // rflags
        0u32.pack(&mut wire).unwrap();
        // bitmap4 attrset: 0 words
        0u32.pack(&mut wire).unwrap();
        // delegation: OPEN_DELEGATE_READ (1)
        1u32.pack(&mut wire).unwrap();
        // delegation stateid
        let del_sid = Stateid4 { seqid: 77, other: [0xCC; NFS4_OTHER_SIZE] };
        del_sid.pack(&mut wire).unwrap();
        // recall = true
        1u32.pack(&mut wire).unwrap();
        // nfsace4: type=0(ALLOW), flag=0, mask=0x1F01FF, who="EVERYONE@"
        let ace = NfsAce4 { ace_type: 0, flag: 0, access_mask: 0x1F_01FF, who: "EVERYONE@".to_owned() };
        ace.pack(&mut wire).unwrap();
        let (data, _) = decode_op_result_data(OP_OPEN, &mut &wire[..]).unwrap();
        match data {
            ResOpData::Open { delegation, .. } => match delegation {
                OpenDelegation4::Read { stateid, recall, ace: decoded_ace } => {
                    assert_eq!(stateid, del_sid);
                    assert!(recall);
                    assert_eq!(decoded_ace.who, "EVERYONE@");
                    assert_eq!(decoded_ace.access_mask, 0x1F_01FF);
                },
                other => panic!("expected OpenDelegation4::Read, got {other:?}"),
            },
            other => panic!("expected Open, got {other:?}"),
        }
    }

    #[test]
    fn decode_link_result_change_info() {
        let mut wire = Vec::new();
        0u32.pack(&mut wire).unwrap(); // atomic=false
        30u64.pack(&mut wire).unwrap();
        31u64.pack(&mut wire).unwrap();
        let (data, _) = decode_op_result_data(OP_LINK, &mut &wire[..]).unwrap();
        match data {
            ResOpData::ChangeInfo(ci) => {
                assert!(!ci.atomic);
                assert_eq!(ci.before, 30);
                assert_eq!(ci.after, 31);
            },
            other => panic!("expected ChangeInfo, got {other:?}"),
        }
    }

    #[test]
    fn decode_rename_result_two_change_infos() {
        let mut wire = Vec::new();
        // source
        1u32.pack(&mut wire).unwrap();
        100u64.pack(&mut wire).unwrap();
        101u64.pack(&mut wire).unwrap();
        // target
        0u32.pack(&mut wire).unwrap();
        200u64.pack(&mut wire).unwrap();
        201u64.pack(&mut wire).unwrap();
        let (data, _) = decode_op_result_data(OP_RENAME, &mut &wire[..]).unwrap();
        match data {
            ResOpData::RenameInfo { source, target } => {
                assert!(source.atomic);
                assert_eq!(source.before, 100);
                assert_eq!(source.after, 101);
                assert!(!target.atomic);
                assert_eq!(target.before, 200);
                assert_eq!(target.after, 201);
            },
            other => panic!("expected RenameInfo, got {other:?}"),
        }
    }

    #[test]
    fn decode_close_returns_stateid() {
        let sid = Stateid4 { seqid: 5, other: [0xDD; NFS4_OTHER_SIZE] };
        let mut wire = Vec::new();
        sid.pack(&mut wire).unwrap();
        let (data, n) = decode_op_result_data(OP_CLOSE, &mut &wire[..]).unwrap();
        assert_eq!(n, 16);
        match data {
            ResOpData::Stateid(decoded) => assert_eq!(decoded, sid),
            other => panic!("expected Stateid, got {other:?}"),
        }
    }

    #[test]
    fn decode_setattr_returns_bitmap() {
        let mut wire = Vec::new();
        3u32.pack(&mut wire).unwrap(); // 3 bitmap words
        0x0100u32.pack(&mut wire).unwrap();
        0x0200u32.pack(&mut wire).unwrap();
        0u32.pack(&mut wire).unwrap();
        let (data, _) = decode_op_result_data(OP_SETATTR, &mut &wire[..]).unwrap();
        match data {
            ResOpData::Bitmap(words) => {
                assert_eq!(words.len(), 3);
                assert_eq!(words[0], 0x0100);
                assert_eq!(words[1], 0x0200);
                assert_eq!(words[2], 0);
            },
            other => panic!("expected Bitmap, got {other:?}"),
        }
    }

    #[test]
    fn decode_setclientid_confirm_is_void() {
        // SETCLIENTID_CONFIRM on NFS4_OK has no result body.
        let (data, n) = decode_op_result_data(OP_SETCLIENTID_CONFIRM, &mut &[][..]).unwrap();
        assert_eq!(n, 0);
        assert!(matches!(data, ResOpData::None));
    }

    // =========================================================================
    // Phase 4: Generalized GETATTR / READDIR attribute decoder
    // =========================================================================

    #[test]
    fn decode_fattr4_empty_bitmap() {
        let decoded = decode_fattr4(&[], &[]);
        assert!(decoded.is_empty());
        assert!(decoded.ftype.is_none());
        assert!(decoded.fsid.is_none());
        assert!(decoded.sec_label.is_none());
    }

    #[test]
    fn decode_fattr4_type_and_size_only() {
        // Bitmap: word 0 = bit 1 (type) | bit 4 (size).
        let bitmap = [((1u32 << 1) | (1 << 4))];
        let mut attrvals = Vec::new();
        // type = NF4DIR = 2
        2u32.pack(&mut attrvals).unwrap();
        // size = 4096
        4096u64.pack(&mut attrvals).unwrap();

        let decoded = decode_fattr4(&bitmap, &attrvals);
        assert_eq!(decoded.ftype, Some(NfsFtype4::Dir));
        assert_eq!(decoded.size, Some(4096));
        assert!(decoded.change.is_none());
        assert!(decoded.fsid.is_none());
        assert!(decoded.fileid.is_none());
    }

    #[test]
    fn decode_fattr4_fsid_only_backward_compatible() {
        // Same bitmap as AttrRequest::fsid_only(): word 0 bit 8 only.
        let bitmap = [1u32 << 8, 0u32];
        let mut attrvals = Vec::new();
        100u64.pack(&mut attrvals).unwrap(); // major
        200u64.pack(&mut attrvals).unwrap(); // minor

        let decoded = decode_fattr4(&bitmap, &attrvals);
        assert_eq!(decoded.fsid, Some((100, 200)));
        // Everything else should be None.
        assert!(decoded.ftype.is_none());
        assert!(decoded.mode.is_none());
    }

    #[test]
    fn decode_fattr4_full_shell_attrs() {
        // Build attrvals for the full shell_attrs() bitmap.
        let ar = AttrRequest::shell_attrs();
        let bitmap = &ar.words;
        let mut attrvals = Vec::new();

        // Word 0 attributes in bit order: type(1), change(3), size(4), fsid(8), fileid(20).
        2u32.pack(&mut attrvals).unwrap(); // type = NF4DIR
        999u64.pack(&mut attrvals).unwrap(); // change
        8192u64.pack(&mut attrvals).unwrap(); // size
        1u64.pack(&mut attrvals).unwrap(); // fsid major
        0u64.pack(&mut attrvals).unwrap(); // fsid minor
        12345u64.pack(&mut attrvals).unwrap(); // fileid

        // Word 1 attributes in bit order: mode(1), numlinks(3), owner(4),
        //   owner_group(5), time_access(15), time_metadata(19), time_modify(20).
        0o755u32.pack(&mut attrvals).unwrap(); // mode
        2u32.pack(&mut attrvals).unwrap(); // numlinks
        onc_xdr::pack_string("root", &mut attrvals).unwrap(); // owner
        onc_xdr::pack_string("wheel", &mut attrvals).unwrap(); // owner_group
        // time_access: nfstime4 = i64 seconds + u32 nseconds
        1700000000i64.pack(&mut attrvals).unwrap();
        123456u32.pack(&mut attrvals).unwrap();
        // time_metadata
        1700000100i64.pack(&mut attrvals).unwrap();
        654321u32.pack(&mut attrvals).unwrap();
        // time_modify
        1700000200i64.pack(&mut attrvals).unwrap();
        111222u32.pack(&mut attrvals).unwrap();

        let decoded = decode_fattr4(bitmap, &attrvals);
        assert_eq!(decoded.ftype, Some(NfsFtype4::Dir));
        assert_eq!(decoded.change, Some(999));
        assert_eq!(decoded.size, Some(8192));
        assert_eq!(decoded.fsid, Some((1, 0)));
        assert_eq!(decoded.fileid, Some(12345));
        assert_eq!(decoded.mode, Some(0o755));
        assert_eq!(decoded.numlinks, Some(2));
        assert_eq!(decoded.owner.as_deref(), Some("root"));
        assert_eq!(decoded.owner_group.as_deref(), Some("wheel"));
        assert_eq!(decoded.time_access, Some((1_700_000_000, 123_456)));
        assert_eq!(decoded.time_metadata, Some((1_700_000_100, 654_321)));
        assert_eq!(decoded.time_modify, Some((1_700_000_200, 111_222)));
        assert!(decoded.sec_label.is_none());
        assert!(decoded.lease_time.is_none());
    }

    #[test]
    fn decode_fattr4_sec_label_only() {
        // Bitmap: word 2 bit 16 (attr 80), words 0 and 1 are zero.
        let bitmap = [0u32, 0u32, 1u32 << 16];
        let mut attrvals = Vec::new();
        42u32.pack(&mut attrvals).unwrap(); // lfs
        7u32.pack(&mut attrvals).unwrap(); // pi
        let label = b"system_u:object_r:nfs_t:s0";
        pack_opaque(label, &mut attrvals).unwrap();

        let decoded = decode_fattr4(&bitmap, &attrvals);
        assert!(decoded.ftype.is_none());
        let sl = decoded.sec_label.as_ref().unwrap();
        assert_eq!(sl.lfs, 42);
        assert_eq!(sl.pi, 7);
        assert_eq!(sl.label, label);
    }

    #[test]
    fn attr_request_shell_attrs_bits() {
        let ar = AttrRequest::shell_attrs();
        assert_eq!(ar.words.len(), 2);
        // Word 0: bits 1, 3, 4, 8, 20
        let w0 = ar.words[0];
        assert_ne!(w0 & (1 << 1), 0, "type bit");
        assert_ne!(w0 & (1 << 3), 0, "change bit");
        assert_ne!(w0 & (1 << 4), 0, "size bit");
        assert_ne!(w0 & (1 << 8), 0, "fsid bit");
        assert_ne!(w0 & (1 << 20), 0, "fileid bit");
        // Word 1: bits 1, 3, 4, 5, 15, 19, 20
        let w1 = ar.words[1];
        assert_ne!(w1 & (1 << 1), 0, "mode bit");
        assert_ne!(w1 & (1 << 3), 0, "numlinks bit");
        assert_ne!(w1 & (1 << 4), 0, "owner bit");
        assert_ne!(w1 & (1 << 5), 0, "owner_group bit");
        assert_ne!(w1 & (1 << 15), 0, "time_access bit");
        assert_ne!(w1 & (1 << 19), 0, "time_metadata bit");
        assert_ne!(w1 & (1 << 20), 0, "time_modify bit");
    }

    #[test]
    fn attr_request_shell_attrs_with_fh_bits() {
        let ar = AttrRequest::shell_attrs_with_fh();
        let w0 = ar.words[0];
        // Must include filehandle (bit 19) on top of shell_attrs.
        assert_ne!(w0 & (1 << 19), 0, "filehandle bit");
        // All shell_attrs bits should still be present.
        assert_ne!(w0 & (1 << 1), 0, "type bit");
        assert_ne!(w0 & (1 << 8), 0, "fsid bit");
    }

    #[test]
    fn getattr_decode_round_trip_full() {
        // Build a COMPOUND response with GETATTR carrying shell_attrs.
        let ar = AttrRequest::shell_attrs();
        let mut attrvals = Vec::new();
        // type = NF4REG
        1u32.pack(&mut attrvals).unwrap();
        // change
        42u64.pack(&mut attrvals).unwrap();
        // size
        1024u64.pack(&mut attrvals).unwrap();
        // fsid
        10u64.pack(&mut attrvals).unwrap();
        20u64.pack(&mut attrvals).unwrap();
        // fileid
        99u64.pack(&mut attrvals).unwrap();
        // mode
        0o644u32.pack(&mut attrvals).unwrap();
        // numlinks
        1u32.pack(&mut attrvals).unwrap();
        // owner
        onc_xdr::pack_string("nobody", &mut attrvals).unwrap();
        // owner_group
        onc_xdr::pack_string("nogroup", &mut attrvals).unwrap();
        // time_access
        1000i64.pack(&mut attrvals).unwrap();
        0u32.pack(&mut attrvals).unwrap();
        // time_metadata
        2000i64.pack(&mut attrvals).unwrap();
        0u32.pack(&mut attrvals).unwrap();
        // time_modify
        3000i64.pack(&mut attrvals).unwrap();
        0u32.pack(&mut attrvals).unwrap();

        // Build COMPOUND response wire bytes.
        let mut wire = Vec::new();
        0u32.pack(&mut wire).unwrap(); // status OK
        onc_xdr::pack_string("", &mut wire).unwrap(); // tag
        1u32.pack(&mut wire).unwrap(); // 1 op
        OP_GETATTR.pack(&mut wire).unwrap(); // op code
        0u32.pack(&mut wire).unwrap(); // op status OK
        // Bitmap
        (ar.words.len() as u32).pack(&mut wire).unwrap();
        for &w in &ar.words {
            w.pack(&mut wire).unwrap();
        }
        // attrvals opaque
        pack_opaque(&attrvals, &mut wire).unwrap();

        let (res, _) = CompoundRes::unpack(&mut &wire[..]).unwrap();
        assert_eq!(res.results.len(), 1);
        match &res.results[0].data {
            ResOpData::Getattr(attrs) => {
                assert_eq!(attrs.ftype, Some(NfsFtype4::Reg));
                assert_eq!(attrs.change, Some(42));
                assert_eq!(attrs.size, Some(1024));
                assert_eq!(attrs.fsid, Some((10, 20)));
                assert_eq!(attrs.fileid, Some(99));
                assert_eq!(attrs.mode, Some(0o644));
                assert_eq!(attrs.numlinks, Some(1));
                assert_eq!(attrs.owner.as_deref(), Some("nobody"));
                assert_eq!(attrs.owner_group.as_deref(), Some("nogroup"));
                assert_eq!(attrs.time_access, Some((1000, 0)));
                assert_eq!(attrs.time_metadata, Some((2000, 0)));
                assert_eq!(attrs.time_modify, Some((3000, 0)));
            },
            other => panic!("expected ResOpData::Getattr, got {other:?}"),
        }
    }

    #[test]
    fn readdir_decode_with_entry_attrs() {
        // Build a READDIR response where entries carry type+size attributes.
        let entry_bitmap: Vec<u32> = vec![(1u32 << 1) | (1 << 4)]; // type + size
        let mut entry_attrvals = Vec::new();
        1u32.pack(&mut entry_attrvals).unwrap(); // type = NF4REG
        2048u64.pack(&mut entry_attrvals).unwrap(); // size

        let mut wire = Vec::new();
        0u32.pack(&mut wire).unwrap(); // status OK
        onc_xdr::pack_string("", &mut wire).unwrap(); // tag
        1u32.pack(&mut wire).unwrap(); // 1 op
        OP_READDIR.pack(&mut wire).unwrap();
        0u32.pack(&mut wire).unwrap(); // status OK
        wire.extend_from_slice(&[0u8; 8]); // cookieverf
        // Entry: value_follows=1, cookie=5, name="testfile"
        1u32.pack(&mut wire).unwrap(); // value_follows
        5u64.pack(&mut wire).unwrap(); // cookie
        onc_xdr::pack_string("testfile", &mut wire).unwrap();
        // fattr4: bitmap + attrvals opaque
        (entry_bitmap.len() as u32).pack(&mut wire).unwrap();
        for &w in &entry_bitmap {
            w.pack(&mut wire).unwrap();
        }
        pack_opaque(&entry_attrvals, &mut wire).unwrap();
        // End of list + eof
        0u32.pack(&mut wire).unwrap(); // value_follows=0
        1u32.pack(&mut wire).unwrap(); // eof=true

        let (res, _) = CompoundRes::unpack(&mut &wire[..]).unwrap();
        match &res.results[0].data {
            ResOpData::Readdir { entries, eof, .. } => {
                assert_eq!(entries.len(), 1);
                assert_eq!(entries[0].name, "testfile");
                assert_eq!(entries[0].cookie, 5);
                assert!(*eof);
                let attrs = entries[0].attrs.as_ref().expect("entry should have attrs");
                assert_eq!(attrs.ftype, Some(NfsFtype4::Reg));
                assert_eq!(attrs.size, Some(2048));
                assert!(attrs.mode.is_none());
            },
            other => panic!("expected ResOpData::Readdir, got {other:?}"),
        }
    }

    #[test]
    fn readdir_decode_without_attrs() {
        // READDIR entries with empty bitmap should have attrs=None.
        let mut wire = Vec::new();
        0u32.pack(&mut wire).unwrap();
        onc_xdr::pack_string("", &mut wire).unwrap();
        1u32.pack(&mut wire).unwrap();
        OP_READDIR.pack(&mut wire).unwrap();
        0u32.pack(&mut wire).unwrap();
        wire.extend_from_slice(&[0u8; 8]); // cookieverf
        // Entry with empty bitmap
        1u32.pack(&mut wire).unwrap(); // value_follows
        1u64.pack(&mut wire).unwrap(); // cookie
        onc_xdr::pack_string("noattrs", &mut wire).unwrap();
        0u32.pack(&mut wire).unwrap(); // bitmap count = 0
        0u32.pack(&mut wire).unwrap(); // attrvals len = 0
        0u32.pack(&mut wire).unwrap(); // value_follows=0
        1u32.pack(&mut wire).unwrap(); // eof

        let (res, _) = CompoundRes::unpack(&mut &wire[..]).unwrap();
        match &res.results[0].data {
            ResOpData::Readdir { entries, .. } => {
                assert_eq!(entries.len(), 1);
                assert_eq!(entries[0].name, "noattrs");
                assert!(entries[0].attrs.is_none());
            },
            other => panic!("expected ResOpData::Readdir, got {other:?}"),
        }
    }

    #[test]
    fn decode_fattr4_with_filehandle_skip() {
        // Verify that filehandle (opaque<>, word 0 bit 19) is properly
        // skipped and fileid (bit 20) is decoded after it.
        let bitmap = [(1u32 << 19) | (1 << 20)]; // filehandle + fileid
        let mut attrvals = Vec::new();
        // filehandle: opaque<> with 6-byte handle (padded to 8)
        let fh = [0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE];
        pack_opaque(&fh, &mut attrvals).unwrap();
        // fileid
        42u64.pack(&mut attrvals).unwrap();

        let decoded = decode_fattr4(&bitmap, &attrvals);
        assert_eq!(decoded.fileid, Some(42));
        assert!(decoded.ftype.is_none());
    }

    // --- CompoundBuilder Phase 5 tests ---

    #[test]
    fn builder_chain_produces_correct_op_count() {
        let ops = CompoundBuilder::new().putrootfh().lookup("etc").getfh().getattr(AttrRequest::shell_attrs()).build();
        assert_eq!(ops.len(), 4);
        assert!(matches!(ops[0], ArgOp::Putrootfh));
        assert!(matches!(ops[1], ArgOp::Lookup(_)));
        assert!(matches!(ops[2], ArgOp::Getfh));
        assert!(matches!(ops[3], ArgOp::Getattr(_)));
    }

    #[test]
    fn builder_access_creates_correct_argop() {
        let ops = CompoundBuilder::new().access(0x1F).build();
        assert_eq!(ops.len(), 1);
        match &ops[0] {
            ArgOp::Access { access } => assert_eq!(*access, 0x1F),
            other => panic!("expected ArgOp::Access, got {other:?}"),
        }
    }

    #[test]
    fn builder_create_with_dir_type() {
        let ops = CompoundBuilder::new().create(CreateType4::Dir, "subdir", Fattr4::default()).build();
        assert_eq!(ops.len(), 1);
        match &ops[0] {
            ArgOp::Create { objtype, objname, .. } => {
                assert!(matches!(objtype, CreateType4::Dir));
                assert_eq!(objname, "subdir");
            },
            other => panic!("expected ArgOp::Create, got {other:?}"),
        }
    }

    #[test]
    fn builder_lock_with_new_lock_owner() {
        let locker = Locker4::NewLockOwner { open_seqid: 1, open_stateid: Stateid4::ANONYMOUS, lock_seqid: 0, lock_owner: LockOwner4 { clientid: 42, owner: b"test".to_vec() } };
        let ops = CompoundBuilder::new().lock(LockType4::WriteLt, false, 0, 1024, locker).build();
        assert_eq!(ops.len(), 1);
        match &ops[0] {
            ArgOp::Lock { locktype, reclaim, offset, length, .. } => {
                assert_eq!(*locktype, LockType4::WriteLt);
                assert!(!reclaim);
                assert_eq!(*offset, 0);
                assert_eq!(*length, 1024);
            },
            other => panic!("expected ArgOp::Lock, got {other:?}"),
        }
    }

    #[test]
    fn builder_open_with_claim_null() {
        let owner = OpenOwner4 { clientid: 100, owner: b"probe".to_vec() };
        let ops = CompoundBuilder::new().open(1, 1, 0, owner, OpenFlag4::NoCreate, OpenClaim4::Null("file.txt".to_owned())).build();
        assert_eq!(ops.len(), 1);
        match &ops[0] {
            ArgOp::Open { seqid, share_access, share_deny, claim, .. } => {
                assert_eq!(*seqid, 1);
                assert_eq!(*share_access, 1);
                assert_eq!(*share_deny, 0);
                assert!(matches!(claim, OpenClaim4::Null(name) if name == "file.txt"));
            },
            other => panic!("expected ArgOp::Open, got {other:?}"),
        }
    }

    #[test]
    fn builder_write_with_file_sync() {
        let data = vec![0xCA, 0xFE, 0xBA, 0xBE];
        let ops = CompoundBuilder::new().write(Stateid4::ANONYMOUS, 4096, StableHow4::FileSync, data.clone()).build();
        assert_eq!(ops.len(), 1);
        match &ops[0] {
            ArgOp::Write { stateid, offset, stable, data: d } => {
                assert_eq!(stateid, &[0u8; 16]);
                assert_eq!(*offset, 4096);
                assert_eq!(*stable, 2, "FileSync wire value is 2");
                assert_eq!(d, &data);
            },
            other => panic!("expected ArgOp::Write, got {other:?}"),
        }
    }

    #[test]
    fn builder_remove_creates_correct_argop() {
        let ops = CompoundBuilder::new().remove("old_file").build();
        assert_eq!(ops.len(), 1);
        match &ops[0] {
            ArgOp::Remove { target } => assert_eq!(target, "old_file"),
            other => panic!("expected ArgOp::Remove, got {other:?}"),
        }
    }

    #[test]
    fn builder_rename_creates_correct_argop() {
        let ops = CompoundBuilder::new().rename("src.txt", "dst.txt").build();
        assert_eq!(ops.len(), 1);
        match &ops[0] {
            ArgOp::Rename { oldname, newname } => {
                assert_eq!(oldname, "src.txt");
                assert_eq!(newname, "dst.txt");
            },
            other => panic!("expected ArgOp::Rename, got {other:?}"),
        }
    }

    #[test]
    fn builder_close_converts_stateid() {
        let sid = Stateid4 { seqid: 5, other: [1; NFS4_OTHER_SIZE] };
        let ops = CompoundBuilder::new().close(2, sid).build();
        assert_eq!(ops.len(), 1);
        match &ops[0] {
            ArgOp::Close { seqid, stateid } => {
                assert_eq!(*seqid, 2);
                assert_eq!(stateid, &sid.to_bytes());
            },
            other => panic!("expected ArgOp::Close, got {other:?}"),
        }
    }

    #[test]
    fn builder_read_converts_stateid() {
        let ops = CompoundBuilder::new().read(Stateid4::READ_BYPASS, 0, 65536).build();
        assert_eq!(ops.len(), 1);
        match &ops[0] {
            ArgOp::Read { stateid, offset, count } => {
                assert_eq!(stateid, &Stateid4::READ_BYPASS.to_bytes());
                assert_eq!(*offset, 0);
                assert_eq!(*count, 65536);
            },
            other => panic!("expected ArgOp::Read, got {other:?}"),
        }
    }

    #[test]
    fn builder_no_arg_ops() {
        // Verify all no-argument builders produce the right variant.
        let ops = CompoundBuilder::new().lookupp().readlink().restorefh().savefh().illegal().build();
        assert_eq!(ops.len(), 5);
        assert!(matches!(ops[0], ArgOp::Lookupp));
        assert!(matches!(ops[1], ArgOp::Readlink));
        assert!(matches!(ops[2], ArgOp::Restorefh));
        assert!(matches!(ops[3], ArgOp::Savefh));
        assert!(matches!(ops[4], ArgOp::Illegal));
    }

    #[test]
    fn builder_commit_creates_correct_argop() {
        let ops = CompoundBuilder::new().commit(512, 4096).build();
        assert_eq!(ops.len(), 1);
        match &ops[0] {
            ArgOp::Commit { offset, count } => {
                assert_eq!(*offset, 512);
                assert_eq!(*count, 4096);
            },
            other => panic!("expected ArgOp::Commit, got {other:?}"),
        }
    }

    #[test]
    fn builder_delegpurge_creates_correct_argop() {
        let ops = CompoundBuilder::new().delegpurge(999).build();
        assert_eq!(ops.len(), 1);
        match &ops[0] {
            ArgOp::Delegpurge { clientid } => assert_eq!(*clientid, 999),
            other => panic!("expected ArgOp::Delegpurge, got {other:?}"),
        }
    }

    #[test]
    fn builder_delegreturn_converts_stateid() {
        let sid = Stateid4 { seqid: 3, other: [0xAB; NFS4_OTHER_SIZE] };
        let ops = CompoundBuilder::new().delegreturn(sid).build();
        assert_eq!(ops.len(), 1);
        match &ops[0] {
            ArgOp::Delegreturn { stateid } => assert_eq!(stateid, &sid.to_bytes()),
            other => panic!("expected ArgOp::Delegreturn, got {other:?}"),
        }
    }

    #[test]
    fn builder_link_creates_correct_argop() {
        let ops = CompoundBuilder::new().link("hardlink_name").build();
        assert_eq!(ops.len(), 1);
        match &ops[0] {
            ArgOp::Link { newname } => assert_eq!(newname, "hardlink_name"),
            other => panic!("expected ArgOp::Link, got {other:?}"),
        }
    }

    #[test]
    fn builder_lockt_creates_correct_argop() {
        let owner = LockOwner4 { clientid: 7, owner: b"lockt".to_vec() };
        let ops = CompoundBuilder::new().lockt(LockType4::ReadLt, 100, 200, owner).build();
        assert_eq!(ops.len(), 1);
        match &ops[0] {
            ArgOp::Lockt { locktype, offset, length, owner: o } => {
                assert_eq!(*locktype, LockType4::ReadLt);
                assert_eq!(*offset, 100);
                assert_eq!(*length, 200);
                assert_eq!(o.clientid, 7);
            },
            other => panic!("expected ArgOp::Lockt, got {other:?}"),
        }
    }

    #[test]
    fn builder_locku_creates_correct_argop() {
        let sid = Stateid4 { seqid: 1, other: [0x55; NFS4_OTHER_SIZE] };
        let ops = CompoundBuilder::new().locku(LockType4::WriteLt, 2, sid, 0, u64::MAX).build();
        assert_eq!(ops.len(), 1);
        match &ops[0] {
            ArgOp::Locku { locktype, seqid, lock_stateid, offset, length } => {
                assert_eq!(*locktype, LockType4::WriteLt);
                assert_eq!(*seqid, 2);
                assert_eq!(*lock_stateid, sid);
                assert_eq!(*offset, 0);
                assert_eq!(*length, u64::MAX);
            },
            other => panic!("expected ArgOp::Locku, got {other:?}"),
        }
    }

    #[test]
    fn builder_nverify_creates_correct_argop() {
        let attrs = Fattr4 { bitmap: AttrRequest::empty(), attrvals: vec![0x42] };
        let ops = CompoundBuilder::new().nverify(attrs).build();
        assert_eq!(ops.len(), 1);
        assert!(matches!(ops[0], ArgOp::Nverify { .. }));
    }

    #[test]
    fn builder_verify_creates_correct_argop() {
        let attrs = Fattr4 { bitmap: AttrRequest::empty(), attrvals: vec![0x99] };
        let ops = CompoundBuilder::new().verify(attrs).build();
        assert_eq!(ops.len(), 1);
        assert!(matches!(ops[0], ArgOp::Verify { .. }));
    }

    #[test]
    fn builder_openattr_creates_correct_argop() {
        let ops = CompoundBuilder::new().openattr(true).build();
        assert_eq!(ops.len(), 1);
        match &ops[0] {
            ArgOp::Openattr { createdir } => assert!(*createdir),
            other => panic!("expected ArgOp::Openattr, got {other:?}"),
        }
    }

    #[test]
    fn builder_open_confirm_converts_stateid() {
        let sid = Stateid4 { seqid: 10, other: [0xCC; NFS4_OTHER_SIZE] };
        let ops = CompoundBuilder::new().open_confirm(sid, 11).build();
        assert_eq!(ops.len(), 1);
        match &ops[0] {
            ArgOp::OpenConfirm { stateid, seqid } => {
                assert_eq!(stateid, &sid.to_bytes());
                assert_eq!(*seqid, 11);
            },
            other => panic!("expected ArgOp::OpenConfirm, got {other:?}"),
        }
    }

    #[test]
    fn builder_open_downgrade_converts_stateid() {
        let sid = Stateid4 { seqid: 4, other: [0xDD; NFS4_OTHER_SIZE] };
        let ops = CompoundBuilder::new().open_downgrade(sid, 5, 1, 0).build();
        assert_eq!(ops.len(), 1);
        match &ops[0] {
            ArgOp::OpenDowngrade { stateid, seqid, share_access, share_deny } => {
                assert_eq!(stateid, &sid.to_bytes());
                assert_eq!(*seqid, 5);
                assert_eq!(*share_access, 1);
                assert_eq!(*share_deny, 0);
            },
            other => panic!("expected ArgOp::OpenDowngrade, got {other:?}"),
        }
    }

    #[test]
    fn builder_readdir_creates_correct_argop() {
        let ops = CompoundBuilder::new().readdir(0, 0, 4096, 65536, AttrRequest::empty()).build();
        assert_eq!(ops.len(), 1);
        match &ops[0] {
            ArgOp::Readdir { cookie, cookieverf, dircount, maxcount, .. } => {
                assert_eq!(*cookie, 0);
                assert_eq!(*cookieverf, 0);
                assert_eq!(*dircount, 4096);
                assert_eq!(*maxcount, 65536);
            },
            other => panic!("expected ArgOp::Readdir, got {other:?}"),
        }
    }

    #[test]
    fn builder_renew_creates_correct_argop() {
        let ops = CompoundBuilder::new().renew(0xDEAD_BEEF).build();
        assert_eq!(ops.len(), 1);
        match &ops[0] {
            ArgOp::Renew { clientid } => assert_eq!(*clientid, 0xDEAD_BEEF),
            other => panic!("expected ArgOp::Renew, got {other:?}"),
        }
    }

    #[test]
    fn builder_setattr_creates_correct_argop() {
        let sid = Stateid4::ANONYMOUS;
        let attrs = Fattr4::default();
        let ops = CompoundBuilder::new().setattr(sid, attrs).build();
        assert_eq!(ops.len(), 1);
        match &ops[0] {
            ArgOp::Setattr { stateid, .. } => assert_eq!(*stateid, Stateid4::ANONYMOUS),
            other => panic!("expected ArgOp::Setattr, got {other:?}"),
        }
    }

    #[test]
    fn builder_setclientid_confirm_creates_correct_argop() {
        let verf = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
        let ops = CompoundBuilder::new().setclientid_confirm(42, verf).build();
        assert_eq!(ops.len(), 1);
        match &ops[0] {
            ArgOp::SetclientidConfirm { clientid, verifier } => {
                assert_eq!(*clientid, 42);
                assert_eq!(verifier, &verf);
            },
            other => panic!("expected ArgOp::SetclientidConfirm, got {other:?}"),
        }
    }

    #[test]
    fn builder_release_lockowner_creates_correct_argop() {
        let owner = LockOwner4 { clientid: 88, owner: b"cleanup".to_vec() };
        let ops = CompoundBuilder::new().release_lockowner(owner).build();
        assert_eq!(ops.len(), 1);
        match &ops[0] {
            ArgOp::ReleaseLockowner { lock_owner } => {
                assert_eq!(lock_owner.clientid, 88);
                assert_eq!(lock_owner.owner, b"cleanup");
            },
            other => panic!("expected ArgOp::ReleaseLockowner, got {other:?}"),
        }
    }

    // --- Domain type tests ---

    #[test]
    fn nfs4_file_type_from_wire_mappings() {
        assert_eq!(Nfs4FileType::from(NfsFtype4::Reg), Nfs4FileType::Regular);
        assert_eq!(Nfs4FileType::from(NfsFtype4::Dir), Nfs4FileType::Directory);
        assert_eq!(Nfs4FileType::from(NfsFtype4::Lnk), Nfs4FileType::Symlink);
        assert_eq!(Nfs4FileType::from(NfsFtype4::Blk), Nfs4FileType::BlockDev);
        assert_eq!(Nfs4FileType::from(NfsFtype4::Chr), Nfs4FileType::CharDev);
        assert_eq!(Nfs4FileType::from(NfsFtype4::Sock), Nfs4FileType::Socket);
        assert_eq!(Nfs4FileType::from(NfsFtype4::Fifo), Nfs4FileType::Fifo);
        assert_eq!(Nfs4FileType::from(NfsFtype4::NamedAttr), Nfs4FileType::NamedAttr);
        assert_eq!(Nfs4FileType::from(NfsFtype4::AttrDir), Nfs4FileType::AttrDir);
        assert_eq!(Nfs4FileType::from(NfsFtype4::Unknown(42)), Nfs4FileType::Unknown);
        assert_eq!(Nfs4FileType::from(NfsFtype4::Unknown(0)), Nfs4FileType::Unknown);
    }

    #[test]
    fn nfs4_file_info_from_fattr4_decoded_preserves_all_fields() {
        let decoded = Fattr4Decoded {
            ftype: Some(NfsFtype4::Reg),
            size: Some(4096),
            mode: Some(0o644),
            owner: Some("root".to_owned()),
            owner_group: Some("wheel".to_owned()),
            numlinks: Some(3),
            fileid: Some(12345),
            fsid: Some((1, 2)),
            change: Some(99),
            time_access: Some((1000, 500)),
            time_modify: Some((2000, 600)),
            time_metadata: Some((3000, 700)),
            ..Fattr4Decoded::default()
        };
        let info = Nfs4FileInfo::from(decoded);
        assert_eq!(info.ftype, Some(Nfs4FileType::Regular));
        assert_eq!(info.size, Some(4096));
        assert_eq!(info.mode, Some(0o644));
        assert_eq!(info.owner.as_deref(), Some("root"));
        assert_eq!(info.owner_group.as_deref(), Some("wheel"));
        assert_eq!(info.numlinks, Some(3));
        assert_eq!(info.fileid, Some(12345));
        assert_eq!(info.fsid, Some((1, 2)));
        assert_eq!(info.change, Some(99));
        assert_eq!(info.time_access, Some((1000, 500)));
        assert_eq!(info.time_modify, Some((2000, 600)));
        assert_eq!(info.time_metadata, Some((3000, 700)));
    }

    #[test]
    fn nfs4_file_info_from_empty_fattr4_decoded() {
        let info = Nfs4FileInfo::from(Fattr4Decoded::default());
        assert!(info.ftype.is_none());
        assert!(info.size.is_none());
        assert!(info.mode.is_none());
        assert!(info.owner.is_none());
        assert!(info.owner_group.is_none());
        assert!(info.numlinks.is_none());
        assert!(info.fileid.is_none());
        assert!(info.fsid.is_none());
        assert!(info.change.is_none());
        assert!(info.time_access.is_none());
        assert!(info.time_modify.is_none());
        assert!(info.time_metadata.is_none());
    }

    #[test]
    fn nfs4_dir_entry_construction() {
        let entry = Nfs4DirEntry { name: "test.txt".to_owned(), cookie: 42, fh: Some(vec![0xDE, 0xAD]), info: Some(Nfs4FileInfo { ftype: Some(Nfs4FileType::Regular), size: Some(1024), ..Nfs4FileInfo::default() }) };
        assert_eq!(entry.name, "test.txt");
        assert_eq!(entry.cookie, 42);
        assert_eq!(entry.fh.as_deref(), Some(&[0xDE, 0xAD][..]));
        assert_eq!(entry.info.as_ref().unwrap().ftype, Some(Nfs4FileType::Regular));
        assert_eq!(entry.info.as_ref().unwrap().size, Some(1024));
    }

    #[test]
    fn nfs4_dir_entry_without_optional_fields() {
        let entry = Nfs4DirEntry { name: "bare".to_owned(), cookie: 0, fh: None, info: None };
        assert_eq!(entry.name, "bare");
        assert_eq!(entry.cookie, 0);
        assert!(entry.fh.is_none());
        assert!(entry.info.is_none());
    }
}
