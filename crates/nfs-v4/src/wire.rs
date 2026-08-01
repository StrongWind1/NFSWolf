//! NFSv4 XDR types  --  RFC 7530.
//!
//! All 37 NFSv4.0 operations (ops 3-39) plus ILLEGAL (op 10044) are
//! representable in `ArgOp` / `ResOpData`. The hot path (COMPOUND
//! encoding, SECINFO, GETATTR, READDIR, pseudo-FS mapping) is fully
//! typed; the remaining operations carry opaque payloads so every valid
//! op code can be constructed, serialised, and round-tripped.
//! All types implement onc_xdr::{Pack, Unpack}.

// XDR type fields are wire-format values; individual docs would repeat names.
// Toolkit API  --  not all items are used in currently-implemented phases.
// NFSv4 XDR Pack/Unpack slices are at fixed offsets matching the RFC 7530 wire format.
use std::io::{Read, Write};

use onc_xdr::{Pack, Unpack};

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

    // --- Opaque-payload operations (complex XDR unions) ---
    //
    // These carry pre-encoded argument bytes so every op code is representable
    // without fully expanding the nested union types (open_claim4, locker4, etc.).
    // The caller is responsible for encoding the payload correctly per the RFC.
    /// Create a non-regular file object (op 6, RFC 7530 S16.4).
    ///
    /// Payload: pre-encoded `CREATE4args` body (createtype4 + component4 + fattr4).
    Create(Vec<u8>),
    /// Create a byte-range lock (op 12, RFC 7530 S16.10).
    ///
    /// Payload: pre-encoded `LOCK4args` body.
    Lock(Vec<u8>),
    /// Test for a byte-range lock (op 13, RFC 7530 S16.11).
    ///
    /// Payload: pre-encoded `LOCKT4args` body.
    Lockt(Vec<u8>),
    /// Unlock a byte-range lock (op 14, RFC 7530 S16.12).
    ///
    /// Payload: pre-encoded `LOCKU4args` body.
    Locku(Vec<u8>),
    /// Verify difference in attributes (op 17, RFC 7530 S16.15).
    ///
    /// Payload: pre-encoded `fattr4` (bitmap + attrvals).
    Nverify(Vec<u8>),
    /// Open a regular file (op 18, RFC 7530 S16.16).
    ///
    /// Payload: pre-encoded `OPEN4args` body.
    Open(Vec<u8>),
    /// Set attributes (op 34, RFC 7530 S16.32).
    ///
    /// Payload: pre-encoded `SETATTR4args` body (stateid4 + fattr4).
    Setattr(Vec<u8>),
    /// Negotiate a client ID (op 35, RFC 7530 S16.33).
    ///
    /// Payload: pre-encoded `SETCLIENTID4args` body (nfs_client_id4 + cb_client4 + callback_ident).
    Setclientid(Vec<u8>),
    /// Verify same attributes (op 37, RFC 7530 S16.35).
    ///
    /// Payload: pre-encoded `fattr4` (bitmap + attrvals).
    Verify(Vec<u8>),
    /// Release lock-owner state (op 39, RFC 7530 S16.37).
    ///
    /// Payload: pre-encoded `lock_owner4` (clientid + opaque owner).
    ReleaseLockowner(Vec<u8>),
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

            // Opaque-payload ops: opcode + raw bytes (already XDR-encoded by caller).
            Self::Create(payload)
            | Self::Lock(payload)
            | Self::Lockt(payload)
            | Self::Locku(payload)
            | Self::Nverify(payload)
            | Self::Open(payload)
            | Self::Setattr(payload)
            | Self::Setclientid(payload)
            | Self::Verify(payload)
            | Self::ReleaseLockowner(payload)
            | Self::ExchangeId(payload)
            | Self::Getdeviceinfo(payload)
            | Self::Getdevicelist(payload) => 4 + payload.len(),
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

            // Opaque-payload ops: opcode then raw pre-encoded bytes.
            Self::Create(payload) => pack_opcode_payload(OP_CREATE, payload, out),
            Self::Lock(payload) => pack_opcode_payload(OP_LOCK, payload, out),
            Self::Lockt(payload) => pack_opcode_payload(OP_LOCKT, payload, out),
            Self::Locku(payload) => pack_opcode_payload(OP_LOCKU, payload, out),
            Self::Nverify(payload) => pack_opcode_payload(OP_NVERIFY, payload, out),
            Self::Open(payload) => pack_opcode_payload(OP_OPEN, payload, out),
            Self::Setattr(payload) => pack_opcode_payload(OP_SETATTR, payload, out),
            Self::Setclientid(payload) => pack_opcode_payload(OP_SETCLIENTID, payload, out),
            Self::Verify(payload) => pack_opcode_payload(OP_VERIFY, payload, out),
            Self::ReleaseLockowner(payload) => pack_opcode_payload(OP_RELEASE_LOCKOWNER, payload, out),

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
    /// Constructs the pre-encoded SETCLIENTID4args payload:
    /// - `nfs_client_id4`: 8-byte verifier (random) + client name as opaque id
    /// - `cb_client4`: callback program 0x40000000 + clientaddr4(netid="tcp", addr=callback_addr)
    /// - `callback_ident`: 1
    ///
    /// `callback_addr` is the attacker-controlled universal address the server
    /// will dial back to for delegation recalls (RFC 7530 S16.33.3). Format is
    /// "h1.h2.h3.h4.p1.p2" for IPv4.
    #[must_use]
    pub fn setclientid(self, client_name: &str, callback_addr: &str) -> Self {
        let payload = encode_setclientid(client_name, callback_addr);
        self.op(ArgOp::Setclientid(payload))
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
    /// Constructs the pre-encoded OPEN4args payload for a read-only open:
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
        let payload = encode_open_read(name);
        self.op(ArgOp::Open(payload))
    }
}

/// Pre-encode SETCLIENTID4args body (RFC 7530 S16.33).
///
/// Wire layout:
///   nfs_client_id4: verifier(8 bytes) + id(opaque<NFS4_OPAQUE_LIMIT>)
///   cb_client4: cb_program(u32) + cb_location(clientaddr4)
///     clientaddr4: r_netid(string) + r_addr(string)
///   callback_ident: u32
fn encode_setclientid(client_name: &str, callback_addr: &str) -> Vec<u8> {
    let mut buf = Vec::with_capacity(128);

    // verifier: 8 bytes, use a deterministic value for reproducible probes.
    // In production a random verifier prevents stale-clientid collisions, but
    // for recon the determinism aids debugging.
    buf.extend_from_slice(&[0x6E, 0x66, 0x73, 0x77, 0x6F, 0x6C, 0x66, 0x00]); // "nfswolf\0"

    // client id: opaque<> with the supplied client name.
    let name_bytes = client_name.as_bytes();
    drop(pack_opaque(name_bytes, &mut buf));

    // cb_program: 0x40000000 (conventional callback program number, RFC 7530 S16.33.5).
    buf.extend_from_slice(&0x4000_0000u32.to_be_bytes());

    // cb_location (clientaddr4): r_netid="tcp", r_addr=callback_addr.
    drop(onc_xdr::pack_string("tcp", &mut buf));
    drop(onc_xdr::pack_string(callback_addr, &mut buf));

    // callback_ident: 1 (arbitrary non-zero value).
    buf.extend_from_slice(&1u32.to_be_bytes());

    buf
}

/// Pre-encode OPEN4args body for a read-only open (RFC 7530 S16.16).
///
/// Wire layout:
///   seqid: u32
///   share_access: u32 (OPEN4_SHARE_ACCESS_READ = 1)
///   share_deny: u32 (OPEN4_SHARE_DENY_NONE = 0)
///   open_owner4: clientid(u64) + owner(opaque<NFS4_OPAQUE_LIMIT>)
///   openhow4: opentype4(u32=0 OPEN4_NOCREATE)
///   open_claim4: claim(u32=0 CLAIM_NULL) + file(component4=XDR string)
fn encode_open_read(name: &str) -> Vec<u8> {
    let mut buf = Vec::with_capacity(96);

    // seqid = 1 (first open in the sequence).
    buf.extend_from_slice(&1u32.to_be_bytes());
    // share_access = OPEN4_SHARE_ACCESS_READ (1, RFC 7530 S16.16.3).
    buf.extend_from_slice(&1u32.to_be_bytes());
    // share_deny = OPEN4_SHARE_DENY_NONE (0, RFC 7530 S16.16.3).
    buf.extend_from_slice(&0u32.to_be_bytes());

    // open_owner4: clientid(u64=0) + owner(opaque<>="nfswolf").
    // clientid=0 signals "use the current SETCLIENTID binding" on Linux knfsd.
    buf.extend_from_slice(&0u64.to_be_bytes());
    drop(pack_opaque(b"nfswolf", &mut buf));

    // openhow4: opentype4 = OPEN4_NOCREATE (0).
    buf.extend_from_slice(&0u32.to_be_bytes());

    // open_claim4: claim = CLAIM_NULL (0) + file = component4 (XDR string).
    buf.extend_from_slice(&0u32.to_be_bytes());
    drop(onc_xdr::pack_string(name, &mut buf));

    buf
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

/// A single directory entry returned by NFSv4 READDIR (RFC 7530 S16.24).
#[derive(Debug, Clone)]
pub struct DirEntry4 {
    /// Resume cookie for pagination (opaque to the client).
    pub cookie: u64,
    /// Entry name.
    pub name: String,
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
    /// fsid from a GETATTR fsid request (RFC 7530 S16.7; attribute 8, S5.8.1.9).
    ///
    /// `Some((major, minor))` when FATTR4_FSID was present and decodable;
    /// `None` otherwise. Used to tell the NFSv4 pseudo-root apart from a real
    /// export boundary (RFC 7530 S7.3).
    Getattr {
        /// Decoded fsid4 major/minor, when FATTR4_FSID was returned.
        fsid: Option<(u64, u64)>,
    },
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
    /// Auth flavor codes from SECINFO (RFC 7530 S16.31).
    ///
    /// 1 = AUTH_SYS, 6 = RPCSEC_GSS (Kerberos). No flavor 6 means
    /// the export accepts credential spoofing via AUTH_SYS (F-3.4).
    SecFlavors(Vec<u32>),
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

    /// No result data  --  PUTPUBFH, PUTROOTFH, PUTFH, LOOKUP, LOOKUPP, REMOVE,
    /// RENAME, CLOSE, DELEGPURGE, DELEGRETURN, LINK, OPENATTR, OPEN_CONFIRM,
    /// OPEN_DOWNGRADE, RENEW, RESTOREFH, SAVEFH, SETCLIENTID_CONFIRM,
    /// SETATTR, RELEASE_LOCKOWNER, ILLEGAL, and other ops with complex or
    /// undecodable results.
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
/// All 37 NFSv4.0 ops (3-39) plus ILLEGAL (10044) are handled. Ops with
/// complex result unions (OPEN, LOCK, LOCKT, LOCKU, CREATE, SETCLIENTID,
/// etc.) stop parsing because their variable-length nested structures
/// cannot be skipped safely without a full XDR decoder for those types.
fn decode_op_result_data(op_code: u32, input: &mut impl Read) -> onc_xdr::Result<(ResOpData, usize)> {
    match op_code {
        // --- No result data beyond status ---
        OP_PUTPUBFH | OP_PUTROOTFH | OP_PUTFH | OP_LOOKUP | OP_LOOKUPP | OP_RESTOREFH | OP_SAVEFH | OP_DELEGPURGE | OP_DELEGRETURN | OP_OPENATTR | OP_RENEW | OP_NVERIFY | OP_VERIFY | OP_RELEASE_LOCKOWNER | OP_ILLEGAL => Ok((ResOpData::None, 0)),

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
        // We decode only FATTR4_FSID (attribute 8, RFC 7530 S5.8.1.9) when it is
        // the sole word-0 attribute requested, so the 16-byte fsid4 sits at the
        // start of attrvals. Any other attribute combination yields fsid = None.
        OP_GETATTR => {
            let (bitmap_count, mut n) = u32::unpack(input)?;
            let mut bitmap_w0 = 0u32;
            for i in 0..bitmap_count {
                let (w, wn) = u32::unpack(input)?;
                if i == 0 {
                    bitmap_w0 = w;
                }
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
            let fsid_bit: u32 = 1 << 8;
            let lower_bits: u32 = fsid_bit - 1;
            let fsid = if (bitmap_w0 & fsid_bit) != 0 && (bitmap_w0 & lower_bits) == 0 {
                let major = attrvals.get(..8).and_then(|b| b.try_into().ok()).map(u64::from_be_bytes);
                let minor = attrvals.get(8..16).and_then(|b| b.try_into().ok()).map(u64::from_be_bytes);
                major.zip(minor)
            } else {
                None
            };
            Ok((ResOpData::Getattr { fsid }, n))
        },

        // SECINFO / SECINFO_NO_NAME result: variable-length array of secinfo4.
        // Same wire format for both (RFC 5661 S18.45.3).
        OP_SECINFO | OP_SECINFO_NO_NAME => {
            let (arr_count, mut n) = u32::unpack(input)?;
            let mut flavors = onc_xdr::vec_with_capacity(arr_count as usize);
            for _ in 0..arr_count {
                let (flavor, fn_) = u32::unpack(input)?;
                n += fn_;
                flavors.push(flavor);
                if flavor == 6 {
                    // RPCSEC_GSS: oid opaque<> + qop u32 + service u32
                    n += skip_opaque(input)?;
                    let (_, qn) = u32::unpack(input)?;
                    n += qn;
                    let (_, sn) = u32::unpack(input)?;
                    n += sn;
                }
            }
            Ok((ResOpData::SecFlavors(flavors), n))
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
                let (bitmap_count, bn) = u32::unpack(input)?;
                n += bn;
                for _ in 0..bitmap_count {
                    let (_, wn) = u32::unpack(input)?;
                    n += wn;
                }
                n += skip_opaque(input)?;
                entries.push(DirEntry4 { cookie, name });
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

        // REMOVE result: change_info4 (bool atomic + u64 before + u64 after).
        // Decoded as None since we don't surface change_info; must skip the bytes.
        OP_REMOVE | OP_LINK => {
            // change_info4: bool(4) + changeid4(8) + changeid4(8) = 20 bytes
            let (_, mut n) = u32::unpack(input)?; // atomic
            let (_, bn) = u64::unpack(input)?; // before
            n += bn;
            let (_, an) = u64::unpack(input)?; // after
            n += an;
            Ok((ResOpData::None, n))
        },

        // RENAME result: source_cinfo + target_cinfo (two change_info4).
        OP_RENAME => {
            let mut n = 0usize;
            for _ in 0..2 {
                let (_, an) = u32::unpack(input)?; // atomic
                n += an;
                let (_, bn) = u64::unpack(input)?; // before
                n += bn;
                let (_, cn) = u64::unpack(input)?; // after
                n += cn;
            }
            Ok((ResOpData::None, n))
        },

        // SETATTR result: bitmap4 attrsset (RFC 7530 S16.32).
        OP_SETATTR => {
            let (bitmap_count, mut n) = u32::unpack(input)?;
            for _ in 0..bitmap_count {
                let (_, wn) = u32::unpack(input)?;
                n += wn;
            }
            Ok((ResOpData::None, n))
        },

        // CLOSE / OPEN_CONFIRM / OPEN_DOWNGRADE / LOCKU result: stateid4 (16 bytes).
        OP_CLOSE | OP_OPEN_CONFIRM | OP_OPEN_DOWNGRADE | OP_LOCKU => {
            let mut stateid = [0u8; 16];
            input.read_exact(&mut stateid).map_err(onc_xdr::Error::Io)?;
            Ok((ResOpData::None, 16))
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

        // Ops with complex/variable result unions that cannot be skipped
        // without a full decoder, plus anything unknown -- stop parsing here.
        // Results so far are valid.
        _ => Err(onc_xdr::Error::InvalidEnumValue(op_code)),
    }
}

/// Read and discard a single XDR opaque<>: 4-byte length + data + padding.
/// Returns the total bytes consumed.
fn skip_opaque(input: &mut impl Read) -> onc_xdr::Result<usize> {
    let (len, mut n) = u32::unpack(input)?;
    let len = len as usize;
    if len > 0 {
        // Read and discard the data bytes, bounded by real bytes (untrusted len).
        let _discarded = onc_xdr::read_bytes(input, len)?;
        n += len;
        let pad = (4 - (len % 4)) % 4;
        onc_xdr::skip_pad(input, pad)?;
        n += pad;
    }
    Ok(n)
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
            20 => Self::NotDir,
            21 => Self::IsDir,
            22 => Self::Inval,
            27 => Self::Fbig,
            28 => Self::NoSpc,
            30 => Self::Rofs,
            63 => Self::NameTooLong,
            66 => Self::NotEmpty,
            70 => Self::Stale,
            10001 => Self::BadHandle,
            10003 => Self::BadCookie,
            10004 => Self::NotSupp,
            10010 => Self::Denied,
            10011 => Self::Expired,
            10012 => Self::Locked,
            10016 => Self::WrongSec,
            10019 => Self::Moved,
            10036 => Self::BadXdr,
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
            Self::NotDir => 20,
            Self::IsDir => 21,
            Self::Inval => 22,
            Self::Fbig => 27,
            Self::NoSpc => 28,
            Self::Rofs => 30,
            Self::NameTooLong => 63,
            Self::NotEmpty => 66,
            Self::Stale => 70,
            Self::BadHandle => 10001,
            Self::BadCookie => 10003,
            Self::NotSupp => 10004,
            Self::Denied => 10010,
            Self::Expired => 10011,
            Self::Locked => 10012,
            Self::WrongSec => 10016,
            Self::Moved => 10019,
            Self::BadXdr => 10036,
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
        matches!(self, Self::Io)
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
            Self::NotDir => f.write_str("NFS4ERR_NOTDIR"),
            Self::IsDir => f.write_str("NFS4ERR_ISDIR"),
            Self::Inval => f.write_str("NFS4ERR_INVAL"),
            Self::Fbig => f.write_str("NFS4ERR_FBIG"),
            Self::NoSpc => f.write_str("NFS4ERR_NOSPC"),
            Self::Rofs => f.write_str("NFS4ERR_ROFS"),
            Self::NameTooLong => f.write_str("NFS4ERR_NAMETOOLONG"),
            Self::NotEmpty => f.write_str("NFS4ERR_NOTEMPTY"),
            Self::Stale => f.write_str("NFS4ERR_STALE"),
            Self::BadHandle => f.write_str("NFS4ERR_BADHANDLE"),
            Self::BadCookie => f.write_str("NFS4ERR_BAD_COOKIE"),
            Self::NotSupp => f.write_str("NFS4ERR_NOTSUPP"),
            Self::Denied => f.write_str("NFS4ERR_DENIED"),
            Self::Expired => f.write_str("NFS4ERR_EXPIRED"),
            Self::Locked => f.write_str("NFS4ERR_LOCKED"),
            Self::WrongSec => f.write_str("NFS4ERR_WRONGSEC"),
            Self::Moved => f.write_str("NFS4ERR_MOVED"),
            Self::BadXdr => f.write_str("NFS4ERR_BADXDR"),
            Self::Unknown(n) => write!(f, "NFS4ERR_UNKNOWN({n})"),
        }
    }
}

impl std::error::Error for Nfs4Status {}

#[cfg(test)]
mod tests {
    #![expect(clippy::pedantic, unused_results, reason = "unit test  --  lints are suppressed per project policy")]
    use super::*;

    #[test]
    fn nfs4_status_from_u32_maps_known_codes() {
        assert_eq!(Nfs4Status::from_u32(0), Nfs4Status::Ok);
        assert_eq!(Nfs4Status::from_u32(1), Nfs4Status::Perm);
        assert_eq!(Nfs4Status::from_u32(2), Nfs4Status::NoEnt);
        assert_eq!(Nfs4Status::from_u32(5), Nfs4Status::Io);
        assert_eq!(Nfs4Status::from_u32(6), Nfs4Status::Nxio);
        assert_eq!(Nfs4Status::from_u32(13), Nfs4Status::Acces);
        assert_eq!(Nfs4Status::from_u32(17), Nfs4Status::Exist);
        assert_eq!(Nfs4Status::from_u32(20), Nfs4Status::NotDir);
        assert_eq!(Nfs4Status::from_u32(21), Nfs4Status::IsDir);
        assert_eq!(Nfs4Status::from_u32(22), Nfs4Status::Inval);
        assert_eq!(Nfs4Status::from_u32(27), Nfs4Status::Fbig);
        assert_eq!(Nfs4Status::from_u32(28), Nfs4Status::NoSpc);
        assert_eq!(Nfs4Status::from_u32(30), Nfs4Status::Rofs);
        assert_eq!(Nfs4Status::from_u32(63), Nfs4Status::NameTooLong);
        assert_eq!(Nfs4Status::from_u32(66), Nfs4Status::NotEmpty);
        assert_eq!(Nfs4Status::from_u32(70), Nfs4Status::Stale);
        assert_eq!(Nfs4Status::from_u32(10001), Nfs4Status::BadHandle);
        assert_eq!(Nfs4Status::from_u32(10003), Nfs4Status::BadCookie);
        assert_eq!(Nfs4Status::from_u32(10004), Nfs4Status::NotSupp);
        assert_eq!(Nfs4Status::from_u32(10010), Nfs4Status::Denied);
        assert_eq!(Nfs4Status::from_u32(10011), Nfs4Status::Expired);
        assert_eq!(Nfs4Status::from_u32(10012), Nfs4Status::Locked);
        assert_eq!(Nfs4Status::from_u32(10016), Nfs4Status::WrongSec);
        assert_eq!(Nfs4Status::from_u32(10019), Nfs4Status::Moved);
        assert_eq!(Nfs4Status::from_u32(10036), Nfs4Status::BadXdr);
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
            (20, Nfs4Status::NotDir),
            (21, Nfs4Status::IsDir),
            (22, Nfs4Status::Inval),
            (27, Nfs4Status::Fbig),
            (28, Nfs4Status::NoSpc),
            (30, Nfs4Status::Rofs),
            (63, Nfs4Status::NameTooLong),
            (66, Nfs4Status::NotEmpty),
            (70, Nfs4Status::Stale),
            (10001, Nfs4Status::BadHandle),
            (10003, Nfs4Status::BadCookie),
            (10004, Nfs4Status::NotSupp),
            (10010, Nfs4Status::Denied),
            (10011, Nfs4Status::Expired),
            (10012, Nfs4Status::Locked),
            (10016, Nfs4Status::WrongSec),
            (10019, Nfs4Status::Moved),
            (10036, Nfs4Status::BadXdr),
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
            ResOpData::SecFlavors(flavors) => {
                assert_eq!(flavors, &[1, 0]);
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
            ResOpData::Getattr { fsid } => {
                assert_eq!(*fsid, Some((100, 200)));
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
            // Opaque-payload ops (pre-encoded bodies)
            ArgOp::Create(vec![0u8; 20]),
            ArgOp::Lock(vec![0u8; 40]),
            ArgOp::Lockt(vec![0u8; 28]),
            ArgOp::Locku(vec![0u8; 36]),
            ArgOp::Nverify(vec![0u8; 12]),
            ArgOp::Open(vec![0u8; 60]),
            ArgOp::Setattr(vec![0u8; 32]),
            ArgOp::Setclientid(vec![0u8; 48]),
            ArgOp::Verify(vec![0u8; 12]),
            ArgOp::ReleaseLockowner(vec![0u8; 16]),
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
    fn argop_opaque_payload_create_encodes_opcode_then_payload() {
        let payload = vec![0xDE, 0xAD];
        let op = ArgOp::Create(payload.clone());
        let mut buf = Vec::new();
        let n = op.pack(&mut buf).unwrap();
        assert_eq!(n, 6);
        assert_eq!(u32::from_be_bytes(buf[0..4].try_into().unwrap()), 6);
        assert_eq!(&buf[4..6], &payload);
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
        assert!(matches!(res.results[0].data, ResOpData::None));
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
        assert!(matches!(res.results[0].data, ResOpData::None));
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
        assert!(matches!(res.results[0].data, ResOpData::None));
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
        assert!(matches!(res.results[0].data, ResOpData::None));
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
}
