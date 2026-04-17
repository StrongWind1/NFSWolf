//! NFSv4 XDR types  --  RFC 7530.
//!
//! Minimal subset needed for nfswolf's security analysis: COMPOUND encoding,
//! SECINFO, GETATTR, READDIR, and pseudo-FS mapping.
//! Only the ~7 operations nfswolf actually uses are implemented.
//! All types implement nfs3_types::xdr_codec::{Pack, Unpack}.

// XDR type fields are wire-format values; individual docs would repeat names.
// Toolkit API  --  not all items are used in currently-implemented phases.
// NFSv4 XDR Pack/Unpack slices are at fixed offsets matching the RFC 7530 wire format.
use std::io::{Read, Write};

use nfs3_types::xdr_codec::{Pack, Unpack};

/// NFSv4 RPC program number (shared with NFSv2/v3  --  version distinguishes).
pub const NFS4_PROGRAM: u32 = 100_003;

/// NFSv4.0 version number for the COMPOUND procedure.
pub const NFS4_VERSION: u32 = 4;

/// COMPOUND is the sole non-NULL procedure in NFSv4 (RFC 7530 S17.2).
/// All operations are batched inside a single COMPOUND call.
pub const NFS4_PROC_COMPOUND: u32 = 1;

// --- NFSv4 operation codes (RFC 7530 S13) ---

/// PUTROOTFH  --  make the server's root FH current (op 24, RFC 7530 S18.24).
const OP_PUTROOTFH: u32 = 24;
/// PUTFH  --  make an existing FH current (op 22, RFC 7530 S18.22).
const OP_PUTFH: u32 = 22;
/// LOOKUP  --  look up a component in the current FH (op 15, RFC 7530 S18.15).
const OP_LOOKUP: u32 = 15;
/// GETATTR  --  retrieve file attributes (op 9, RFC 7530 S18.9).
const OP_GETATTR: u32 = 9;
/// GETFH  --  retrieve the current file handle (op 10, RFC 7530 S18.10).
const OP_GETFH: u32 = 10;
/// SECINFO  --  query auth flavors for a name (op 33, RFC 7530 S18.29).
const OP_SECINFO: u32 = 33;
/// READDIR  --  read directory entries with inline attributes (op 26, RFC 7530 S18.23).
const OP_READDIR: u32 = 26;
/// READ  --  read file data (op 25, RFC 7530 S18.22).
const OP_READ: u32 = 25;

// --- XDR helpers ---

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

/// Pack an XDR string: 4-byte length, data bytes, zero-pad to 4-byte boundary.
pub fn pack_xdr_string(s: &str, out: &mut impl Write) -> nfs3_types::xdr_codec::Result<usize> {
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

/// Unpack an XDR string: read 4-byte length, data bytes, skip padding.
pub fn unpack_xdr_string(input: &mut impl Read) -> nfs3_types::xdr_codec::Result<(String, usize)> {
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

/// Compute packed size for an XDR string.
pub const fn xdr_string_size(s: &str) -> usize {
    let len = s.len();
    4 + len + (4 - (len % 4)) % 4
}

/// Pack XDR opaque<> (variable-length): 4-byte length + bytes + padding.
fn pack_opaque(data: &[u8], out: &mut impl Write) -> nfs3_types::xdr_codec::Result<usize> {
    let len = u32::try_from(data.len()).map_err(|_| nfs3_types::xdr_codec::Error::ObjectTooLarge(data.len()))?;
    let mut n = len.pack(out)?;
    out.write_all(data).map_err(nfs3_types::xdr_codec::Error::Io)?;
    n += data.len();
    let pad = (4 - (data.len() % 4)) % 4;
    write_xdr_pad(out, pad)?;
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

    fn pack(&self, out: &mut impl Write) -> nfs3_types::xdr_codec::Result<usize> {
        let count = u32::try_from(self.words.len()).map_err(|_| nfs3_types::xdr_codec::Error::ObjectTooLarge(self.words.len()))?;
        let mut n = count.pack(out)?;
        for &w in &self.words {
            n += w.pack(out)?;
        }
        Ok(n)
    }
}

impl Unpack for AttrRequest {
    fn unpack(input: &mut impl Read) -> nfs3_types::xdr_codec::Result<(Self, usize)> {
        let (count, mut n) = u32::unpack(input)?;
        let mut words = Vec::with_capacity(count as usize);
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
/// Only the operations nfswolf uses are represented  --  PUTROOTFH, PUTFH, LOOKUP,
/// GETATTR, GETFH, SECINFO, READDIR, READ.  Wire format is: 4-byte op code + op data.
#[derive(Debug, Clone)]
pub enum ArgOp {
    /// Set the current FH to the server's pseudo-root (RFC 7530 S18.24).
    Putrootfh,
    /// Set the current FH to a known handle (RFC 7530 S18.22).
    Putfh(Vec<u8>),
    /// Look up a single path component in the current directory (RFC 7530 S18.15).
    Lookup(String),
    /// Return attributes for the current FH (RFC 7530 S18.9).
    Getattr(AttrRequest),
    /// Return the current file handle as opaque bytes (RFC 7530 S18.10).
    Getfh,
    /// Query supported auth flavors for a named child (RFC 7530 S18.29).
    Secinfo(String),
    /// Read directory entries with inline attribute bitmaps (RFC 7530 S18.23).
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
    /// Read file data starting at `offset` (RFC 7530 S18.22).
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
            Self::Putrootfh | Self::Getfh => 4, // only the opcode (4 bytes), no arguments
            Self::Putfh(fh) => 4 + opaque_packed_size(fh),
            Self::Lookup(name) | Self::Secinfo(name) => 4 + xdr_string_size(name),
            Self::Getattr(attrs) => 4 + attrs.packed_size(),
            Self::Readdir { attr_request, .. } => 4 + 8 + 8 + 4 + 4 + attr_request.packed_size(),
            // 4 (opcode) + 16 (stateid) + 8 (offset) + 4 (count)
            Self::Read { .. } => 4 + 16 + 8 + 4,
        }
    }

    fn pack(&self, out: &mut impl Write) -> nfs3_types::xdr_codec::Result<usize> {
        match self {
            Self::Putrootfh => OP_PUTROOTFH.pack(out),
            Self::Putfh(fh) => {
                let mut n = OP_PUTFH.pack(out)?;
                n += pack_opaque(fh, out)?;
                Ok(n)
            },
            Self::Lookup(name) => {
                let mut n = OP_LOOKUP.pack(out)?;
                n += pack_xdr_string(name, out)?;
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
                n += pack_xdr_string(name, out)?;
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
                out.write_all(stateid).map_err(nfs3_types::xdr_codec::Error::Io)?;
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
        xdr_string_size(&self.tag) + 4 + 4 + self.ops.iter().map(Pack::packed_size).sum::<usize>()
    }

    fn pack(&self, out: &mut impl Write) -> nfs3_types::xdr_codec::Result<usize> {
        let mut n = pack_xdr_string(&self.tag, out)?;
        n += self.minorversion.pack(out)?;
        let count = u32::try_from(self.ops.len()).map_err(|_| nfs3_types::xdr_codec::Error::ObjectTooLarge(self.ops.len()))?;
        n += count.pack(out)?;
        for op in &self.ops {
            n += op.pack(out)?;
        }
        Ok(n)
    }
}

// --- CompoundRes ---

/// A single directory entry returned by NFSv4 READDIR (RFC 7530 S18.23).
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
    /// File handle bytes from GETFH (RFC 7530 S18.10).
    Fh(Vec<u8>),
    /// Directory entries from READDIR (RFC 7530 S18.23), plus EOF flag.
    Readdir {
        /// Entries decoded from the READDIR linked list.
        entries: Vec<DirEntry4>,
        /// True if this is the last page of directory entries.
        eof: bool,
    },
    /// File data from READ (RFC 7530 S18.22), plus EOF flag.
    Read {
        /// True if this read reached the end of the file.
        eof: bool,
        /// File data bytes.
        data: Vec<u8>,
    },
    /// Auth flavor codes from SECINFO (RFC 7530 S18.29).
    ///
    /// 1 = AUTH_SYS, 6 = RPCSEC_GSS (Kerberos). No flavor 6 means
    /// the export accepts credential spoofing via AUTH_SYS (F-3.4).
    SecFlavors(Vec<u32>),
    /// No result data  --  PUTROOTFH, PUTFH, LOOKUP, GETATTR, etc.
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
    fn unpack(input: &mut impl Read) -> nfs3_types::xdr_codec::Result<(Self, usize)> {
        let (status, n0) = u32::unpack(input)?;
        let (tag, n1) = unpack_xdr_string(input)?;
        let (count, n2) = u32::unpack(input)?;
        let mut n = n0 + n1 + n2;
        let mut results = Vec::with_capacity(count as usize);
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
/// - PUTROOTFH / PUTFH / LOOKUP: no data (S18.24, S18.22, S18.15)
/// - GETFH: opaque<> file handle (S18.10)
/// - GETATTR: bitmap + opaque<> attrvals (S18.9)
/// - SECINFO: u32 array count + per-entry flavor/gss-info (S18.29)
/// - READDIR: verifier + linked-list entries + eof (S18.23)
/// - READ: bool eof + opaque<> data (S18.22)
fn decode_op_result_data(op_code: u32, input: &mut impl Read) -> nfs3_types::xdr_codec::Result<(ResOpData, usize)> {
    match op_code {
        // No result data beyond status.
        OP_PUTROOTFH | OP_PUTFH | OP_LOOKUP => Ok((ResOpData::None, 0)),

        // GETFH result: opaque<> file handle (4-byte length + data + padding).
        OP_GETFH => {
            let (len, mut n) = u32::unpack(input)?;
            let len = len as usize;
            let mut fh = vec![0u8; len];
            input.read_exact(&mut fh).map_err(nfs3_types::xdr_codec::Error::Io)?;
            n += len;
            let pad = (4 - (len % 4)) % 4;
            skip_xdr_pad(input, pad)?;
            n += pad;
            Ok((ResOpData::Fh(fh), n))
        },

        // GETATTR result: bitmap (u32 count + N words) + opaque<> attrvals.
        // We don't decode fattr4 attribute values  --  skip and return None.
        OP_GETATTR => {
            let (bitmap_count, mut n) = u32::unpack(input)?;
            for _ in 0..bitmap_count {
                let (_, wn) = u32::unpack(input)?;
                n += wn;
            }
            n += skip_opaque(input)?;
            Ok((ResOpData::None, n))
        },

        // SECINFO result: variable-length array of secinfo4 entries.
        // Each entry: u32 flavor.  If flavor == 6 (RPCSEC_GSS): oid(opaque<>) + qop(u32) + service(u32).
        OP_SECINFO => {
            let (arr_count, mut n) = u32::unpack(input)?;
            let mut flavors = Vec::with_capacity(arr_count as usize);
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
            let mut data = vec![0u8; data_len];
            input.read_exact(&mut data).map_err(nfs3_types::xdr_codec::Error::Io)?;
            n += data_len;
            let pad = (4 - (data_len % 4)) % 4;
            skip_xdr_pad(input, pad)?;
            n += pad;
            Ok((ResOpData::Read { eof: eof_raw != 0, data }, n))
        },

        // READDIR result: verifier[8] + linked-list { value_follows, cookie, name, fattr4 } + eof.
        // We request AttrRequest::empty() so fattr4 = empty bitmap + empty attrvals.
        OP_READDIR => {
            // Skip cookieverf (8 bytes).
            let mut verifier = [0u8; 8];
            input.read_exact(&mut verifier).map_err(nfs3_types::xdr_codec::Error::Io)?;
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
                let (name, nn) = unpack_xdr_string(input)?;
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
            Ok((ResOpData::Readdir { entries, eof: eof_raw != 0 }, n))
        },

        // Unknown or unimplemented op  --  caller should stop parsing here.
        _ => Err(nfs3_types::xdr_codec::Error::InvalidEnumValue(op_code)),
    }
}

/// Read and discard a single XDR opaque<>: 4-byte length + data + padding.
/// Returns the total bytes consumed.
fn skip_opaque(input: &mut impl Read) -> nfs3_types::xdr_codec::Result<usize> {
    let (len, mut n) = u32::unpack(input)?;
    let len = len as usize;
    if len > 0 {
        // Read and discard the data bytes.
        let mut buf = vec![0u8; len];
        input.read_exact(&mut buf).map_err(nfs3_types::xdr_codec::Error::Io)?;
        n += len;
        let pad = (4 - (len % 4)) % 4;
        skip_xdr_pad(input, pad)?;
        n += pad;
    }
    Ok(n)
}

// --- NFSv4 status codes ---

/// NFSv4 status codes (RFC 7530 S13).
///
/// Common values nfswolf tests for are named variants; anything else is
/// captured as `Unknown(u32)` so callers can still inspect the raw code
/// rather than silently mapping every unrecognized value to `BadXdr`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Nfs4Status {
    /// No error (NFS4_OK = 0).
    Ok,
    /// Permission denied (NFS4ERR_ACCESS = 13, RFC 7530 S13.1.6).
    Acces,
    /// Stale file handle (NFS4ERR_STALE = 70, RFC 7530 S13.1.6).
    Stale,
    /// Malformed XDR in request (NFS4ERR_BADXDR = 10036, RFC 7530 S13.1.6).
    BadXdr,
    /// Operation not supported by server (NFS4ERR_NOTSUPP = 10004, RFC 7530 S13.1.6).
    NotSupp,
    /// Wrong security flavor for this export (NFS4ERR_WRONGSEC = 10016, RFC 7530 S13.1.6).
    WrongSec,
    /// Any status code not explicitly listed above.
    Unknown(u32),
}

impl Nfs4Status {
    /// Decode a u32 from the wire into a known variant or `Unknown`.
    #[must_use]
    pub const fn from_u32(v: u32) -> Self {
        match v {
            0 => Self::Ok,
            13 => Self::Acces,
            70 => Self::Stale,
            10036 => Self::BadXdr,
            10004 => Self::NotSupp,
            10016 => Self::WrongSec,
            other => Self::Unknown(other),
        }
    }

    /// Convert back to the raw u32 wire value.
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        match self {
            Self::Ok => 0,
            Self::Acces => 13,
            Self::Stale => 70,
            Self::BadXdr => 10036,
            Self::NotSupp => 10004,
            Self::WrongSec => 10016,
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
        reason = "unit test  --  lints are suppressed per project policy"
    )]
    use super::*;

    #[test]
    fn nfs4_status_from_u32_maps_known_codes() {
        assert_eq!(Nfs4Status::from_u32(0), Nfs4Status::Ok);
        assert_eq!(Nfs4Status::from_u32(13), Nfs4Status::Acces);
        assert_eq!(Nfs4Status::from_u32(70), Nfs4Status::Stale);
        assert_eq!(Nfs4Status::from_u32(10016), Nfs4Status::WrongSec);
        assert_eq!(Nfs4Status::from_u32(10004), Nfs4Status::NotSupp);
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
        args.pack(&mut buf).unwrap();
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
        op.pack(&mut buf).unwrap();
        let opcode = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
        assert_eq!(opcode, 25, "READ op code must be 25 per RFC 7530 S18.22");
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
        args.pack(&mut buf).unwrap();
        // After the tag (4 bytes for empty string), the next 4 bytes are minorversion
        let mv = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
        assert_eq!(mv, 1, "minorversion=1 must be encoded at offset 4");
    }
}
