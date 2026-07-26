//! NFSv4 XDR types  --  RFC 7530.
//!
//! Minimal subset needed for nfswolf's security analysis: COMPOUND encoding,
//! SECINFO, GETATTR, READDIR, and pseudo-FS mapping.
//! Only the ~7 operations nfswolf actually uses are implemented.
//! All types implement nfswolf_xdr::{Pack, Unpack}.

#![allow(missing_docs, reason = "these are mechanical transcriptions of the RFC's XDR type table -- per-field prose would restate the field name and nothing more. The module doc cites the defining RFC section, which is the real documentation")]
#![allow(
    missing_copy_implementations,
    reason = "Copy is derived on the wire types whose callers benefit from it; demanding it exhaustively cascades through every containing struct without improving the API, and whether a value is copied or moved is a Rust-side choice the wire format has no opinion on"
)]
#![allow(single_use_lifetimes, reason = "newtype wrappers over borrowed wire data genuinely need the parameter; the lint counts the declaration and the single use and misreads it as removable")]

// XDR type fields are wire-format values; individual docs would repeat names.
// Toolkit API  --  not all items are used in currently-implemented phases.
// NFSv4 XDR Pack/Unpack slices are at fixed offsets matching the RFC 7530 wire format.
use std::io::{Read, Write};

use nfswolf_xdr::{Pack, Unpack};

/// NFSv4 RPC program number (shared with NFSv2/v3  --  version distinguishes).
pub const NFS4_PROGRAM: u32 = 100_003;

/// NFSv4.0 version number for the COMPOUND procedure.
pub const NFS4_VERSION: u32 = 4;

/// COMPOUND is the sole non-NULL procedure in NFSv4 (RFC 7530 S15.2).
/// All operations are batched inside a single COMPOUND call.
pub const NFS4_PROC_COMPOUND: u32 = 1;

// --- NFSv4 operation codes (RFC 7530 S16) ---
// NFSv4.0 defines operations in section 16 (not 18, which is RFC 5661/NFSv4.1).

/// PUTPUBFH  --  make the server's public (WebNFS) FH current (op 23, RFC 7530 S16.21).
const OP_PUTPUBFH: u32 = 23;
/// PUTROOTFH  --  make the server's root FH current (op 24, RFC 7530 S16.22).
const OP_PUTROOTFH: u32 = 24;
/// PUTFH  --  make an existing FH current (op 22, RFC 7530 S16.20).
const OP_PUTFH: u32 = 22;
/// LOOKUP  --  look up a component in the current FH (op 15, RFC 7530 S16.13).
const OP_LOOKUP: u32 = 15;
/// GETATTR  --  retrieve file attributes (op 9, RFC 7530 S16.7).
const OP_GETATTR: u32 = 9;
/// GETFH  --  retrieve the current file handle (op 10, RFC 7530 S16.8).
const OP_GETFH: u32 = 10;
/// SECINFO  --  query auth flavors for a name (op 33, RFC 7530 S16.31).
const OP_SECINFO: u32 = 33;
/// READDIR  --  read directory entries with inline attributes (op 26, RFC 7530 S16.24).
const OP_READDIR: u32 = 26;
/// READ  --  read file data (op 25, RFC 7530 S16.23).
const OP_READ: u32 = 25;

// --- XDR helpers ---

/// Pack XDR opaque<> (variable-length): 4-byte length + bytes + padding.
fn pack_opaque(data: &[u8], out: &mut impl Write) -> nfswolf_xdr::Result<usize> {
    let len = u32::try_from(data.len()).map_err(|_| nfswolf_xdr::Error::ObjectTooLarge(data.len()))?;
    let mut n = len.pack(out)?;
    out.write_all(data).map_err(nfswolf_xdr::Error::Io)?;
    n += data.len();
    let pad = (4 - (data.len() % 4)) % 4;
    nfswolf_xdr::write_pad(out, pad)?;
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
}

impl Pack for AttrRequest {
    fn packed_size(&self) -> usize {
        // XDR array: 4-byte count + 4 bytes per word
        4 + self.words.len() * 4
    }

    fn pack(&self, out: &mut impl Write) -> nfswolf_xdr::Result<usize> {
        let count = u32::try_from(self.words.len()).map_err(|_| nfswolf_xdr::Error::ObjectTooLarge(self.words.len()))?;
        let mut n = count.pack(out)?;
        for &w in &self.words {
            n += w.pack(out)?;
        }
        Ok(n)
    }
}

impl Unpack for AttrRequest {
    fn unpack(input: &mut impl Read) -> nfswolf_xdr::Result<(Self, usize)> {
        let (count, mut n) = u32::unpack(input)?;
        // Clamp the speculative reservation: `count` is attacker-controlled.
        let mut words = nfswolf_xdr::vec_with_capacity(count as usize);
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
/// Only the operations nfswolf uses are represented  --  PUTPUBFH, PUTROOTFH, PUTFH,
/// LOOKUP, GETATTR, GETFH, SECINFO, READDIR, READ.  Wire format is: 4-byte op code + op data.
#[derive(Debug, Clone)]
pub enum ArgOp {
    /// Set the current FH to the server's public (WebNFS) handle (RFC 7530 S16.21).
    Putpubfh,
    /// Set the current FH to the server's pseudo-root (RFC 7530 S16.22).
    Putrootfh,
    /// Set the current FH to a known handle (RFC 7530 S16.20).
    Putfh(Vec<u8>),
    /// Look up a single path component in the current directory (RFC 7530 S16.13).
    Lookup(String),
    /// Return attributes for the current FH (RFC 7530 S16.7).
    Getattr(AttrRequest),
    /// Return the current file handle as opaque bytes (RFC 7530 S16.8).
    Getfh,
    /// Query supported auth flavors for a named child (RFC 7530 S16.31).
    Secinfo(String),
    /// Read directory entries with inline attribute bitmaps (RFC 7530 S16.24).
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
    /// Read file data starting at `offset` (RFC 7530 S16.23).
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
}

impl Pack for ArgOp {
    fn packed_size(&self) -> usize {
        match self {
            Self::Putpubfh | Self::Putrootfh | Self::Getfh => 4, // only the opcode (4 bytes), no arguments
            Self::Putfh(fh) => 4 + opaque_packed_size(fh),
            Self::Lookup(name) | Self::Secinfo(name) => 4 + nfswolf_xdr::string_packed_size(name),
            Self::Getattr(attrs) => 4 + attrs.packed_size(),
            Self::Readdir { attr_request, .. } => 4 + 8 + 8 + 4 + 4 + attr_request.packed_size(),
            // 4 (opcode) + 16 (stateid) + 8 (offset) + 4 (count)
            Self::Read { .. } => 4 + 16 + 8 + 4,
        }
    }

    fn pack(&self, out: &mut impl Write) -> nfswolf_xdr::Result<usize> {
        match self {
            Self::Putpubfh => OP_PUTPUBFH.pack(out),
            Self::Putrootfh => OP_PUTROOTFH.pack(out),
            Self::Putfh(fh) => {
                let mut n = OP_PUTFH.pack(out)?;
                n += pack_opaque(fh, out)?;
                Ok(n)
            },
            Self::Lookup(name) => {
                let mut n = OP_LOOKUP.pack(out)?;
                n += nfswolf_xdr::pack_string(name, out)?;
                Ok(n)
            },
            Self::Getattr(attrs) => {
                let mut n = OP_GETATTR.pack(out)?;
                n += attrs.pack(out)?;
                Ok(n)
            },
            Self::Getfh => OP_GETFH.pack(out),
            Self::Secinfo(name) => {
                let mut n = OP_SECINFO.pack(out)?;
                n += nfswolf_xdr::pack_string(name, out)?;
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
                out.write_all(stateid).map_err(nfswolf_xdr::Error::Io)?;
                n += 16;
                n += offset.pack(out)?;
                n += count.pack(out)?;
                Ok(n)
            },
        }
    }
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
        nfswolf_xdr::string_packed_size(&self.tag) + 4 + 4 + self.ops.iter().map(Pack::packed_size).sum::<usize>()
    }

    fn pack(&self, out: &mut impl Write) -> nfswolf_xdr::Result<usize> {
        let mut n = nfswolf_xdr::pack_string(&self.tag, out)?;
        n += self.minorversion.pack(out)?;
        let count = u32::try_from(self.ops.len()).map_err(|_| nfswolf_xdr::Error::ObjectTooLarge(self.ops.len()))?;
        n += count.pack(out)?;
        for op in &self.ops {
            n += op.pack(out)?;
        }
        Ok(n)
    }
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

/// Decoded payload from a successful NFSv4 operation result.
///
/// Most operations produce no inline data beyond the status code.
/// GETFH, READDIR, READ, and SECINFO carry operation-specific results.
#[derive(Debug, Clone, Default)]
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
    /// No result data  --  PUTPUBFH, PUTROOTFH, PUTFH, LOOKUP, GETATTR, etc.
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
    fn unpack(input: &mut impl Read) -> nfswolf_xdr::Result<(Self, usize)> {
        let (status, n0) = u32::unpack(input)?;
        let (tag, n1) = nfswolf_xdr::unpack_string(input)?;
        let (count, n2) = u32::unpack(input)?;
        let mut n = n0 + n1 + n2;
        // Clamp the speculative reservation: `count` is attacker-controlled.
        let mut results = nfswolf_xdr::vec_with_capacity(count as usize);
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
/// Wire formats per RFC 7530:
/// - PUTPUBFH / PUTROOTFH / PUTFH / LOOKUP: no data (S16.21, S16.22, S16.20, S16.13)
/// - GETFH: opaque<> file handle (S16.8)
/// - GETATTR: bitmap + opaque<> attrvals (S16.7)
/// - SECINFO: u32 array count + per-entry flavor/gss-info (S16.31)
/// - READDIR: verifier + linked-list entries + eof (S16.24)
/// - READ: bool eof + opaque<> data (S16.23)
fn decode_op_result_data(op_code: u32, input: &mut impl Read) -> nfswolf_xdr::Result<(ResOpData, usize)> {
    match op_code {
        // No result data beyond status.
        OP_PUTPUBFH | OP_PUTROOTFH | OP_PUTFH | OP_LOOKUP => Ok((ResOpData::None, 0)),

        // GETFH result: opaque<> file handle (4-byte length + data + padding).
        OP_GETFH => {
            let (len, mut n) = u32::unpack(input)?;
            let len = len as usize;
            // Do not pre-size from the untrusted length; read bounded by real bytes.
            let fh = nfswolf_xdr::read_bytes(input, len)?;
            n += len;
            let pad = (4 - (len % 4)) % 4;
            nfswolf_xdr::skip_pad(input, pad)?;
            n += pad;
            Ok((ResOpData::Fh(fh), n))
        },

        // GETATTR result: bitmap (u32 count + N words) + opaque<> attrvals.
        // We decode only FATTR4_FSID (attribute 8, RFC 7530 S5.8.1.9) when it is
        // the sole word-0 attribute requested, so the 16-byte fsid4 sits at the
        // start of attrvals (the fsid_only request used by map_pseudo_fs). Any
        // other attribute combination is not decoded and yields fsid = None.
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
            // attrvals opaque<>: requested attributes XDR-encoded in bit order.
            let (attrval_len, ln) = u32::unpack(input)?;
            n += ln;
            let attrval_len = attrval_len as usize;
            let attrvals = nfswolf_xdr::read_bytes(input, attrval_len)?;
            n += attrval_len;
            let pad = (4 - (attrval_len % 4)) % 4;
            nfswolf_xdr::skip_pad(input, pad)?;
            n += pad;
            // FATTR4_FSID is bit 8 of word 0; fsid4 = { major u64, minor u64 }.
            // Only safe to read at offset 0 when no lower-numbered word-0
            // attribute (bits 0..7) precedes it in the attrvals stream.
            let fsid_bit: u32 = 1 << 8; // FATTR4_FSID = attribute 8, word 0
            let lower_bits: u32 = fsid_bit - 1; // attributes 0..7 in word 0
            let fsid = if (bitmap_w0 & fsid_bit) != 0 && (bitmap_w0 & lower_bits) == 0 {
                let major = attrvals.get(..8).and_then(|b| b.try_into().ok()).map(u64::from_be_bytes);
                let minor = attrvals.get(8..16).and_then(|b| b.try_into().ok()).map(u64::from_be_bytes);
                major.zip(minor)
            } else {
                None
            };
            Ok((ResOpData::Getattr { fsid }, n))
        },

        // SECINFO result: variable-length array of secinfo4 entries.
        // Each entry: u32 flavor.  If flavor == 6 (RPCSEC_GSS): oid(opaque<>) + qop(u32) + service(u32).
        OP_SECINFO => {
            let (arr_count, mut n) = u32::unpack(input)?;
            // Clamp the speculative reservation: `arr_count` is attacker-controlled.
            let mut flavors = nfswolf_xdr::vec_with_capacity(arr_count as usize);
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
            // Do not pre-size from the untrusted length; read bounded by real bytes.
            let data = nfswolf_xdr::read_bytes(input, data_len)?;
            n += data_len;
            let pad = (4 - (data_len % 4)) % 4;
            nfswolf_xdr::skip_pad(input, pad)?;
            n += pad;
            Ok((ResOpData::Read { eof: eof_raw != 0, data }, n))
        },

        // READDIR result: verifier[8] + linked-list { value_follows, cookie, name, fattr4 } + eof.
        // We request AttrRequest::empty() so fattr4 = empty bitmap + empty attrvals.
        OP_READDIR => {
            // Skip cookieverf (8 bytes).
            let mut verifier = [0u8; 8];
            input.read_exact(&mut verifier).map_err(nfswolf_xdr::Error::Io)?;
            let mut n = 8;
            let mut entries = Vec::new();
            // XDR linked list: value_follows(u32) then entry, repeat.
            loop {
                let (value_follows, vn) = u32::unpack(input)?;
                n += vn;
                if value_follows == 0 {
                    break;
                }
                let (cookie, cn) = u64::unpack(input)?;
                n += cn;
                let (name, nn) = nfswolf_xdr::unpack_string(input)?;
                n += nn;
                // Skip fattr4: bitmap (u32 count + N u32 words) + opaque<> attrvals.
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

        // Unknown or unimplemented op  --  caller should stop parsing here.
        _ => Err(nfswolf_xdr::Error::InvalidEnumValue(op_code)),
    }
}

/// Read and discard a single XDR opaque<>: 4-byte length + data + padding.
/// Returns the total bytes consumed.
fn skip_opaque(input: &mut impl Read) -> nfswolf_xdr::Result<usize> {
    let (len, mut n) = u32::unpack(input)?;
    let len = len as usize;
    if len > 0 {
        // Read and discard the data bytes, bounded by real bytes (untrusted len).
        let _discarded = nfswolf_xdr::read_bytes(input, len)?;
        n += len;
        let pad = (4 - (len % 4)) % 4;
        nfswolf_xdr::skip_pad(input, pad)?;
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
}

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
        unused_results,
        reason = "unit test  --  lints are suppressed per project policy"
    )]
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
    fn operation_codes_match_rfc7530() {
        // RFC 7530 section 16 defines these operation codes.
        assert_eq!(OP_PUTROOTFH, 24, "PUTROOTFH must be 24 (RFC 7530 S16.22)");
        assert_eq!(OP_PUTFH, 22, "PUTFH must be 22 (RFC 7530 S16.20)");
        assert_eq!(OP_PUTPUBFH, 23, "PUTPUBFH must be 23 (RFC 7530 S16.21)");
        assert_eq!(OP_LOOKUP, 15, "LOOKUP must be 15 (RFC 7530 S16.13)");
        assert_eq!(OP_GETATTR, 9, "GETATTR must be 9 (RFC 7530 S16.7)");
        assert_eq!(OP_GETFH, 10, "GETFH must be 10 (RFC 7530 S16.8)");
        assert_eq!(OP_SECINFO, 33, "SECINFO must be 33 (RFC 7530 S16.31)");
        assert_eq!(OP_READDIR, 26, "READDIR must be 26 (RFC 7530 S16.24)");
        assert_eq!(OP_READ, 25, "READ must be 25 (RFC 7530 S16.23)");
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
        nfswolf_xdr::pack_string("", &mut wire).unwrap(); // empty tag
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
        nfswolf_xdr::pack_string("", &mut wire).unwrap(); // tag
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
        nfswolf_xdr::pack_string("", &mut wire).unwrap();
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
        nfswolf_xdr::pack_string("", &mut wire).unwrap();
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
        nfswolf_xdr::pack_string("", &mut wire).unwrap();
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
        nfswolf_xdr::pack_string("", &mut wire).unwrap();
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
        nfswolf_xdr::pack_string("", &mut wire).unwrap();
        1u32.pack(&mut wire).unwrap();
        OP_READDIR.pack(&mut wire).unwrap();
        0u32.pack(&mut wire).unwrap(); // status OK
        // READDIR result: cookieverf(8) + entries(linked list) + eof
        wire.extend_from_slice(&[0u8; 8]); // cookieverf
        // Entry 1: value_follows=1, cookie=1, name=".", empty fattr4
        1u32.pack(&mut wire).unwrap(); // value_follows
        1u64.pack(&mut wire).unwrap(); // cookie
        nfswolf_xdr::pack_string(".", &mut wire).unwrap(); // name
        // fattr4: bitmap_count=0, attrvals opaque len=0
        0u32.pack(&mut wire).unwrap(); // bitmap count
        0u32.pack(&mut wire).unwrap(); // attrvals len
        // Entry 2: value_follows=1, cookie=2, name=".."
        1u32.pack(&mut wire).unwrap();
        2u64.pack(&mut wire).unwrap();
        nfswolf_xdr::pack_string("..", &mut wire).unwrap();
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
        nfswolf_xdr::pack_string("", &mut wire).unwrap();
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
            ArgOp::Putpubfh,
            ArgOp::Putrootfh,
            ArgOp::Getfh,
            ArgOp::Putfh(vec![0x01, 0x02, 0x03]),
            ArgOp::Putfh(vec![0x01, 0x02, 0x03, 0x04]),
            ArgOp::Lookup("passwd".to_owned()),
            ArgOp::Lookup("a".to_owned()),
            ArgOp::Secinfo("exports".to_owned()),
            ArgOp::Getattr(AttrRequest::empty()),
            ArgOp::Getattr(AttrRequest::fsid_only()),
            ArgOp::Read { stateid: [0u8; 16], offset: 0, count: 1024 },
            ArgOp::Read { stateid: [0xFF; 16], offset: u64::MAX, count: u32::MAX },
            ArgOp::Readdir { cookie: 0, cookieverf: 0, dircount: 4096, maxcount: 65536, attr_request: AttrRequest::empty() },
        ];
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
        nfswolf_xdr::pack_string("", &mut wire).unwrap();
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
        nfswolf_xdr::pack_string("mytag", &mut wire).unwrap();
        0u32.pack(&mut wire).unwrap(); // zero results
        let (res, _) = CompoundRes::unpack(&mut &wire[..]).unwrap();
        assert_eq!(res.tag, "mytag");
    }
}
