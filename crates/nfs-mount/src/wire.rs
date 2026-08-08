#![expect(non_camel_case_types, reason = "identifiers are transcribed verbatim from the RFC XDR definitions; renaming them to Rust conventions would break the correspondence a reader needs when checking this module against the spec")]
#![expect(missing_docs, reason = "these are mechanical transcriptions of the RFC's XDR type table -- per-field prose would restate the field name and nothing more. The module doc cites the defining RFC section, which is the real documentation")]
#![expect(missing_copy_implementations, reason = "Copy is derived on the wire types whose callers benefit from it; demanding it exhaustively cascades through every containing struct without improving the API")]
#![expect(single_use_lifetimes, reason = "newtype wrappers over borrowed wire data genuinely need the parameter; the lint counts the declaration and the single use and misreads it as removable")]

//! Wire types for the MOUNT protocol, versions 1 and 3.
//!
//! Version 1: RFC 1094 Appendix A.
//! Version 3: RFC 1813 Appendix I.
//!
//! The wire format for EXPORT is identical between v1 and v3 -- only the
//! version number in the RPC header differs. The MNT response diverges:
//! v1 returns a bare `fhstatus` (status + fixed 32-byte handle), while v3
//! returns `mountres3` (status + variable-length handle + auth flavor list).

use std::io::{Read, Write};

use onc_xdr::{List, Opaque, Pack, Unpack, XdrCodec};

// --- Constants ---

/// MOUNT program number (RFC 1094 Appendix A / RFC 1813 Appendix I).
pub const PROGRAM: u32 = 100_005;

/// MOUNT protocol version 1 (RFC 1094 Appendix A).
pub const MOUNT_V1: u32 = 1;

/// MOUNT protocol version 3 (RFC 1813 Appendix I).
pub const MOUNT_V3: u32 = 3;

/// Fixed file-handle size for NFSv2 (RFC 1094 S2.3.3).
pub const FHSIZE2: usize = 32;

/// Maximum file-handle size for MOUNT v3 (RFC 1813 Appendix I).
pub const FHSIZE3: usize = 64;

/// Maximum path length for dirpath (RFC 1813 Appendix I).
pub const MNTPATHLEN: usize = 1024;

/// Maximum hostname length (RFC 1813 Appendix I).
pub const MNTNAMLEN: usize = 255;

// --- Procedure numbers ---

/// MOUNT v1 procedure numbers (RFC 1094 Appendix A).
pub mod v1_proc {
    /// Do nothing -- connectivity check.
    pub const MOUNTPROC_NULL: u32 = 0;
    /// Mount an export and obtain a 32-byte file handle.
    pub const MOUNTPROC_MNT: u32 = 1;
    /// Dump the mount table.
    pub const MOUNTPROC_DUMP: u32 = 2;
    /// Unmount a single export.
    pub const MOUNTPROC_UMNT: u32 = 3;
    /// Unmount all exports for this client.
    pub const MOUNTPROC_UMNTALL: u32 = 4;
    /// List all exports and their access control lists.
    pub const MOUNTPROC_EXPORT: u32 = 5;
}

/// MOUNT v3 procedure numbers (RFC 1813 Appendix I sec. 4).
#[derive(Copy, Clone, Debug, XdrCodec)]
#[non_exhaustive]
#[repr(u32)]
pub enum MOUNT_V3_PROC {
    MOUNTPROC3_NULL = 0,
    MOUNTPROC3_MNT = 1,
    MOUNTPROC3_DUMP = 2,
    MOUNTPROC3_UMNT = 3,
    MOUNTPROC3_UMNTALL = 4,
    MOUNTPROC3_EXPORT = 5,
}

impl TryFrom<u32> for MOUNT_V3_PROC {
    type Error = onc_xdr::Error;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::MOUNTPROC3_NULL),
            1 => Ok(Self::MOUNTPROC3_MNT),
            2 => Ok(Self::MOUNTPROC3_DUMP),
            3 => Ok(Self::MOUNTPROC3_UMNT),
            4 => Ok(Self::MOUNTPROC3_UMNTALL),
            5 => Ok(Self::MOUNTPROC3_EXPORT),
            _ => Err(onc_xdr::Error::InvalidEnumValue(value)),
        }
    }
}

impl std::fmt::Display for MOUNT_V3_PROC {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let value = match self {
            Self::MOUNTPROC3_NULL => "MOUNTPROC3_NULL",
            Self::MOUNTPROC3_MNT => "MOUNTPROC3_MNT",
            Self::MOUNTPROC3_DUMP => "MOUNTPROC3_DUMP",
            Self::MOUNTPROC3_UMNT => "MOUNTPROC3_UMNT",
            Self::MOUNTPROC3_UMNTALL => "MOUNTPROC3_UMNTALL",
            Self::MOUNTPROC3_EXPORT => "MOUNTPROC3_EXPORT",
        };
        write!(f, "{value}")
    }
}

// --- Shared types (identical wire format in v1 and v3) ---

/// Directory path argument for MNT/UMNT (RFC 1094 Appendix A / RFC 1813: `dirpath`).
///
/// XDR string, encoded as a length-prefixed opaque.
#[derive(Debug, XdrCodec)]
pub struct dirpath<'a>(pub Opaque<'a>);

/// Export name in the EXPORT response (RFC 1094 Appendix A / RFC 1813: `name`).
#[derive(Debug, XdrCodec)]
pub struct name<'a>(pub Opaque<'a>);

/// One node of the EXPORT linked list (RFC 1094 Appendix A / RFC 1813: `exports`).
///
/// The wire format is identical between v1 and v3.
#[derive(Debug, XdrCodec)]
pub struct export_node<'a, 'b> {
    /// Exported directory path.
    pub ex_dir: dirpath<'a>,
    /// Hosts allowed to mount this export.
    pub ex_groups: List<name<'b>>,
}

/// EXPORT response: linked list of `export_node`.
pub type exports<'a, 'b> = List<export_node<'a, 'b>>;

// --- MOUNT v3 types ---

/// MOUNT v3 variable-length file handle (RFC 1813 Appendix I).
#[derive(Debug, XdrCodec)]
pub struct fhandle3<'a>(pub Opaque<'a>);

/// MOUNT v3 status codes (RFC 1813 Appendix I sec. 4).
#[derive(Copy, Clone, Debug, XdrCodec)]
#[non_exhaustive]
#[repr(u32)]
pub enum mountstat3 {
    MNT3_OK = 0,
    MNT3ERR_PERM = 1,
    MNT3ERR_NOENT = 2,
    MNT3ERR_IO = 5,
    MNT3ERR_ACCES = 13,
    MNT3ERR_NOTDIR = 20,
    MNT3ERR_INVAL = 22,
    MNT3ERR_NAMETOOLONG = 63,
    MNT3ERR_NOTSUPP = 10004,
    MNT3ERR_SERVERFAULT = 10006,
}

impl std::fmt::Display for mountstat3 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let value = match self {
            Self::MNT3_OK => "MNT3_OK",
            Self::MNT3ERR_PERM => "MNT3ERR_PERM",
            Self::MNT3ERR_NOENT => "MNT3ERR_NOENT",
            Self::MNT3ERR_IO => "MNT3ERR_IO",
            Self::MNT3ERR_ACCES => "MNT3ERR_ACCES",
            Self::MNT3ERR_NOTDIR => "MNT3ERR_NOTDIR",
            Self::MNT3ERR_INVAL => "MNT3ERR_INVAL",
            Self::MNT3ERR_NAMETOOLONG => "MNT3ERR_NAMETOOLONG",
            Self::MNT3ERR_NOTSUPP => "MNT3ERR_NOTSUPP",
            Self::MNT3ERR_SERVERFAULT => "MNT3ERR_SERVERFAULT",
        };
        write!(f, "{value}")
    }
}

/// Successful MOUNT v3 MNT response: handle + auth flavors.
#[derive(Debug, XdrCodec)]
pub struct mountres3_ok<'a> {
    pub fhandle: fhandle3<'a>,
    pub auth_flavors: Vec<u32>,
}

/// MOUNT v3 MNT response union (RFC 1813 Appendix I sec. 4.2).
#[derive(Debug)]
#[non_exhaustive]
pub enum mountres3<'a> {
    /// Successful mount.
    Ok(mountres3_ok<'a>),
    /// Mount refused.
    Err(mountstat3),
}

impl Pack for mountres3<'_> {
    fn packed_size(&self) -> usize {
        match self {
            Self::Ok(ok) => mountstat3::MNT3_OK.packed_size() + ok.packed_size(),
            Self::Err(err) => err.packed_size(),
        }
    }

    fn pack(&self, out: &mut impl Write) -> onc_xdr::Result<usize> {
        let len = match self {
            Self::Ok(ok) => {
                let mut len = mountstat3::MNT3_OK.pack(out)?;
                len += ok.pack(out)?;
                len
            },
            Self::Err(err) => err.pack(out)?,
        };
        Ok(len)
    }
}

impl Unpack for mountres3<'_> {
    fn unpack(input: &mut impl Read) -> onc_xdr::Result<(Self, usize)> {
        let (stat, len) = mountstat3::unpack(input)?;
        let (res, res_len) = match stat {
            mountstat3::MNT3_OK => {
                let (ok, ok_len) = mountres3_ok::unpack(input)?;
                (Self::Ok(ok), ok_len)
            },
            _ => (Self::Err(stat), 0),
        };
        Ok((res, len + res_len))
    }
}

/// MOUNT v3 DUMP entry (RFC 1813 Appendix I sec. 4.3).
#[derive(Debug, XdrCodec)]
pub struct mountbody<'a, 'b> {
    pub ml_hostname: name<'a>,
    pub ml_directory: dirpath<'b>,
}

/// MOUNT v3 DUMP response: linked list of mountbody.
pub type mountlist<'a, 'b> = List<mountbody<'a, 'b>>;

// --- MOUNT v1 types ---

/// MOUNT v1 MNT response (RFC 1094 Appendix A).
///
/// ```text
/// union fhstatus switch (unsigned status) {
///     case 0: fhandle directory;   /* opaque[FHSIZE=32] */
///     default: void;
/// };
/// ```
///
/// Hand-implemented because FHSIZE=32 is a fixed-length opaque (no length
/// prefix), and the status is not a standard NFS3 discriminant.
#[derive(Debug)]
pub struct FhStatus {
    /// Zero on success, a UNIX errno on failure.
    pub status: u32,
    /// The root file handle for the export (only valid when `status == 0`).
    ///
    /// Always exactly 32 bytes (FHSIZE2).
    pub fhandle: [u8; FHSIZE2],
}

impl Unpack for FhStatus {
    fn unpack(input: &mut impl Read) -> onc_xdr::Result<(Self, usize)> {
        let (status, n1) = u32::unpack(input)?;
        let mut fhandle = [0u8; FHSIZE2];
        let n2 = if status == 0 {
            Read::read_exact(input, &mut fhandle).map_err(onc_xdr::Error::Io)?;
            FHSIZE2
        } else {
            0
        };
        Ok((Self { status, fhandle }, n1 + n2))
    }
}

impl Pack for FhStatus {
    fn packed_size(&self) -> usize {
        4 + if self.status == 0 { FHSIZE2 } else { 0 }
    }

    fn pack(&self, out: &mut impl Write) -> onc_xdr::Result<usize> {
        let mut n = self.status.pack(out)?;
        if self.status == 0 {
            out.write_all(&self.fhandle).map_err(onc_xdr::Error::Io)?;
            n += FHSIZE2;
        }
        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    #![expect(clippy::pedantic, reason = "unit tests -- lints are suppressed per project policy")]
    use super::*;
    use std::io::Cursor;

    /// Pack a value into a fresh buffer.
    fn pack_to_vec(val: &impl Pack) -> Vec<u8> {
        let mut buf = Vec::new();
        let _n = val.pack(&mut buf).expect("pack must succeed");
        buf
    }

    // --- Program and version constants ---

    #[test]
    fn mount_program_number() {
        assert_eq!(PROGRAM, 100_005, "MOUNT program number must be 100005");
    }

    #[test]
    fn mount_v1_version() {
        assert_eq!(MOUNT_V1, 1);
    }

    #[test]
    fn mount_v3_version() {
        assert_eq!(MOUNT_V3, 3);
    }

    // --- v1 procedure constants ---

    #[test]
    fn mount_v1_procedure_constants() {
        use v1_proc::*;
        assert_eq!(MOUNTPROC_NULL, 0);
        assert_eq!(MOUNTPROC_MNT, 1);
        assert_eq!(MOUNTPROC_DUMP, 2);
        assert_eq!(MOUNTPROC_UMNT, 3);
        assert_eq!(MOUNTPROC_UMNTALL, 4);
        assert_eq!(MOUNTPROC_EXPORT, 5);
    }

    // --- v3 procedure numbers ---

    #[test]
    fn mount_v3_procedure_numbers() {
        assert_eq!(MOUNT_V3_PROC::MOUNTPROC3_NULL as u32, 0);
        assert_eq!(MOUNT_V3_PROC::MOUNTPROC3_MNT as u32, 1);
        assert_eq!(MOUNT_V3_PROC::MOUNTPROC3_DUMP as u32, 2);
        assert_eq!(MOUNT_V3_PROC::MOUNTPROC3_UMNT as u32, 3);
        assert_eq!(MOUNT_V3_PROC::MOUNTPROC3_UMNTALL as u32, 4);
        assert_eq!(MOUNT_V3_PROC::MOUNTPROC3_EXPORT as u32, 5);
    }

    #[test]
    fn mount_v3_procedure_try_from_u32_covers_all_6() {
        for n in 0..=5 {
            let proc = MOUNT_V3_PROC::try_from(n).unwrap_or_else(|_| panic!("procedure {n} must be valid"));
            assert_eq!(proc as u32, n);
        }
        assert!(MOUNT_V3_PROC::try_from(6).is_err());
    }

    // --- mountstat3: all 10 status codes ---

    #[test]
    fn mountstat3_all_10_values_round_trip() {
        let cases: &[(mountstat3, u32)] = &[
            (mountstat3::MNT3_OK, 0),
            (mountstat3::MNT3ERR_PERM, 1),
            (mountstat3::MNT3ERR_NOENT, 2),
            (mountstat3::MNT3ERR_IO, 5),
            (mountstat3::MNT3ERR_ACCES, 13),
            (mountstat3::MNT3ERR_NOTDIR, 20),
            (mountstat3::MNT3ERR_INVAL, 22),
            (mountstat3::MNT3ERR_NAMETOOLONG, 63),
            (mountstat3::MNT3ERR_NOTSUPP, 10004),
            (mountstat3::MNT3ERR_SERVERFAULT, 10006),
        ];
        for &(variant, expected_disc) in cases {
            let wire = pack_to_vec(&variant);
            assert_eq!(wire, expected_disc.to_be_bytes(), "packed {variant:?} must match RFC discriminant {expected_disc}");
            let (decoded, consumed) = mountstat3::unpack(&mut Cursor::new(&wire)).expect("unpack mountstat3");
            assert_eq!(consumed, 4);
            assert_eq!(decoded as u32, expected_disc, "{variant:?} must survive pack/unpack");
        }
    }

    // --- dirpath round-trip ---

    #[test]
    fn dirpath_round_trip() {
        let path = dirpath(Opaque::owned(b"/export/data".to_vec()));
        let wire = pack_to_vec(&path);
        let (decoded, consumed) = dirpath::unpack(&mut Cursor::new(&wire)).expect("unpack dirpath");
        assert_eq!(consumed, wire.len());
        assert_eq!(decoded.0.as_ref(), b"/export/data");
    }

    #[test]
    fn dirpath_pack_unpack_round_trip() {
        let dp = dirpath(Opaque::borrowed(b"/export"));
        let mut buf = Vec::new();
        _ = dp.pack(&mut buf).unwrap();
        // 4 (length) + 7 ("/export") + 1 (pad to 4-byte boundary) = 12 bytes.
        assert_eq!(buf.len(), 12);
        let (decoded, n) = dirpath::unpack(&mut Cursor::new(&buf)).unwrap();
        assert_eq!(n, 12);
        assert_eq!(decoded.0.as_ref(), b"/export");
    }

    // --- mountres3 Ok: carries handle + auth_flavors ---

    #[test]
    fn mountres3_ok_carries_handle_and_auth_flavors() {
        let handle_data: Vec<u8> = (0..28).collect();
        let ok = mountres3::Ok(mountres3_ok { fhandle: fhandle3(Opaque::owned(handle_data.clone())), auth_flavors: vec![1, 6] });
        let wire = pack_to_vec(&ok);

        let (decoded, consumed) = mountres3::unpack(&mut Cursor::new(&wire)).expect("unpack mountres3 Ok");
        assert_eq!(consumed, wire.len());
        match decoded {
            mountres3::Ok(res) => {
                assert_eq!(res.fhandle.0.as_ref(), handle_data.as_slice(), "handle bytes must survive round-trip");
                assert_eq!(res.auth_flavors, vec![1, 6], "auth flavors must survive round-trip");
            },
            mountres3::Err(stat) => panic!("expected Ok, got Err({stat:?})"),
        }
    }

    // --- mountres3 error: carries only status ---

    #[test]
    fn mountres3_error_carries_only_status() {
        let err = mountres3::Err(mountstat3::MNT3ERR_ACCES);
        let wire = pack_to_vec(&err);
        assert_eq!(wire.len(), 4);

        let (decoded, consumed) = mountres3::unpack(&mut Cursor::new(&wire)).expect("unpack mountres3 Err");
        assert_eq!(consumed, 4);
        match decoded {
            mountres3::Err(stat) => assert_eq!(stat as u32, 13),
            mountres3::Ok(_) => panic!("expected Err, got Ok"),
        }
    }

    // --- FhStatus (MOUNT v1 MNT response) ---

    #[test]
    fn fhstatus_ok_carries_exactly_32_byte_handle() {
        let fhs = FhStatus { status: 0, fhandle: [0x42; FHSIZE2] };
        let mut buf = Vec::new();
        let n = fhs.pack(&mut buf).unwrap();
        assert_eq!(n, 36, "status(4) + fhandle(32) = 36");
        assert_eq!(buf.len(), 36);
        let (decoded, un) = FhStatus::unpack(&mut Cursor::new(&buf)).unwrap();
        assert_eq!(un, 36);
        assert_eq!(decoded.status, 0);
        assert_eq!(decoded.fhandle, [0x42; FHSIZE2]);
    }

    #[test]
    fn fhstatus_error_carries_only_4_bytes() {
        let fhs = FhStatus { status: 13, fhandle: [0u8; FHSIZE2] };
        let mut buf = Vec::new();
        let n = fhs.pack(&mut buf).unwrap();
        assert_eq!(n, 4);
        assert_eq!(buf.len(), 4);
        let (decoded, un) = FhStatus::unpack(&mut Cursor::new(&buf)).unwrap();
        assert_eq!(un, 4);
        assert_eq!(decoded.status, 13);
        assert_eq!(decoded.fhandle, [0u8; FHSIZE2]);
    }

    // --- export_node round-trip ---

    #[test]
    fn export_node_round_trip_with_path_and_groups() {
        let node = export_node { ex_dir: dirpath(Opaque::borrowed(b"/data")), ex_groups: List(vec![name(Opaque::borrowed(b"host1")), name(Opaque::borrowed(b"host2"))]) };
        let mut buf = Vec::new();
        _ = node.pack(&mut buf).unwrap();
        let (decoded, _) = export_node::unpack(&mut Cursor::new(&buf)).unwrap();
        assert_eq!(decoded.ex_dir.0.as_ref(), b"/data");
        assert_eq!(decoded.ex_groups.0.len(), 2);
        assert_eq!(decoded.ex_groups.0[0].0.as_ref(), b"host1");
        assert_eq!(decoded.ex_groups.0[1].0.as_ref(), b"host2");
    }
}
