#![expect(non_camel_case_types, reason = "identifiers are transcribed verbatim from the RFC's XDR definitions; renaming them to Rust conventions would break the correspondence a reader needs when checking this module against the spec")]
#![expect(missing_docs, reason = "these are mechanical transcriptions of the RFC's XDR type table -- per-field prose would restate the field name and nothing more. The module doc cites the defining RFC section, which is the real documentation")]
#![expect(single_use_lifetimes, reason = "newtype wrappers over Opaque<'a> genuinely need the parameter; the lint counts the declaration and the single use and misreads it as removable")]

//! This module contains the definitions of the MOUNT3 protocol as defined in RFC 1813.

use std::io::{Read, Write};

use nfswolf_xdr::{List, Opaque, Pack, Unpack, XdrCodec};

pub const PROGRAM: u32 = 100_005;
pub const VERSION: u32 = 3;
pub const MNTPATHLEN: usize = 1024;
pub const MNTNAMLEN: usize = 255;
pub const FHSIZE3: usize = 64;

#[derive(Debug, XdrCodec)]
pub struct fhandle3<'a>(pub Opaque<'a>);
#[derive(Debug, XdrCodec)]
pub struct dirpath<'a>(pub Opaque<'a>);
#[derive(Debug, XdrCodec)]
pub struct name<'a>(pub Opaque<'a>);

#[derive(Copy, Clone, Debug, XdrCodec)]
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

// #[derive(Debug, XdrCodec)]
// pub enum rpc_auth_flavor {
// AUTH_NULL = 0,
// AUTH_UNIX = 1,
// AUTH_SHORT = 2,
// AUTH_DES = 3,
// AUTH_KRB = 4,
// AUTH_GSS = 6,
// AUTH_MAXFLAVOR = 8,
// AUTH_GSS_KRB5 = 390003,
// AUTH_GSS_KRB5I = 390004,
// AUTH_GSS_KRB5P = 390005,
// AUTH_GSS_LKEY = 390006,
// AUTH_GSS_LKEYI = 390007,
// AUTH_GSS_LKEYP = 390008,
// AUTH_GSS_SPKM = 390009,
// AUTH_GSS_SPKMI = 390010,
// AUTH_GSS_SPKMP = 390011,
// }

#[derive(Debug, XdrCodec)]
pub struct mountres3_ok<'a> {
    pub fhandle: fhandle3<'a>,
    pub auth_flavors: Vec<u32>,
}

#[derive(Debug)]
pub enum mountres3<'a> {
    Ok(mountres3_ok<'a>),
    Err(mountstat3),
}

impl Pack for mountres3<'_> {
    fn packed_size(&self) -> usize {
        match self {
            Self::Ok(ok) => mountstat3::MNT3_OK.packed_size() + ok.packed_size(),
            Self::Err(err) => err.packed_size(),
        }
    }

    fn pack(&self, out: &mut impl Write) -> nfswolf_xdr::Result<usize> {
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
    fn unpack(input: &mut impl Read) -> nfswolf_xdr::Result<(Self, usize)> {
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

#[derive(Debug, XdrCodec)]
pub struct mountbody<'a, 'b> {
    pub ml_hostname: name<'a>,
    pub ml_directory: dirpath<'b>,
}

pub type mountlist<'a, 'b> = List<mountbody<'a, 'b>>;

#[derive(Debug, XdrCodec)]
pub struct export_node<'a, 'b> {
    pub ex_dir: dirpath<'a>,
    pub ex_groups: List<name<'b>>,
}

pub type exports<'a, 'b> = List<export_node<'a, 'b>>;

#[derive(Copy, Clone, Debug, XdrCodec)]
#[repr(u32)]
pub enum MOUNT_PROGRAM {
    MOUNTPROC3_NULL = 0,
    MOUNTPROC3_MNT = 1,
    MOUNTPROC3_DUMP = 2,
    MOUNTPROC3_UMNT = 3,
    MOUNTPROC3_UMNTALL = 4,
    MOUNTPROC3_EXPORT = 5,
}

impl TryFrom<u32> for MOUNT_PROGRAM {
    type Error = nfswolf_xdr::Error;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::MOUNTPROC3_NULL),
            1 => Ok(Self::MOUNTPROC3_MNT),
            2 => Ok(Self::MOUNTPROC3_DUMP),
            3 => Ok(Self::MOUNTPROC3_UMNT),
            4 => Ok(Self::MOUNTPROC3_UMNTALL),
            5 => Ok(Self::MOUNTPROC3_EXPORT),
            _ => Err(nfswolf_xdr::Error::InvalidEnumValue(value)),
        }
    }
}

impl std::fmt::Display for MOUNT_PROGRAM {
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    /// Pack a value into a fresh buffer.
    fn pack_to_vec(val: &impl Pack) -> Vec<u8> {
        let mut buf = Vec::new();
        let _n = val.pack(&mut buf).expect("pack must succeed");
        buf
    }

    // --- mountstat3: all 10 status codes (RFC 1813 appendix I sec 4) ---

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

    // --- MOUNT v3 program and version constants ---

    #[test]
    fn mount_program_number() {
        assert_eq!(PROGRAM, 100_005, "MOUNT program number must be 100005 (RFC 1813)");
    }

    #[test]
    fn mount_version_number() {
        assert_eq!(VERSION, 3, "MOUNT version must be 3 (RFC 1813)");
    }

    // --- MOUNT_PROGRAM procedure numbers (RFC 1813 appendix I sec 4) ---

    #[test]
    fn mount_procedure_numbers() {
        assert_eq!(MOUNT_PROGRAM::MOUNTPROC3_NULL as u32, 0);
        assert_eq!(MOUNT_PROGRAM::MOUNTPROC3_MNT as u32, 1);
        assert_eq!(MOUNT_PROGRAM::MOUNTPROC3_DUMP as u32, 2);
        assert_eq!(MOUNT_PROGRAM::MOUNTPROC3_UMNT as u32, 3);
        assert_eq!(MOUNT_PROGRAM::MOUNTPROC3_UMNTALL as u32, 4);
        assert_eq!(MOUNT_PROGRAM::MOUNTPROC3_EXPORT as u32, 5);
    }

    #[test]
    fn mount_procedure_try_from_u32_covers_all_6() {
        for n in 0..=5 {
            let proc = MOUNT_PROGRAM::try_from(n).unwrap_or_else(|_| panic!("procedure {n} must be valid"));
            assert_eq!(proc as u32, n);
        }
        assert!(MOUNT_PROGRAM::try_from(6).is_err());
    }

    // --- dirpath pack/unpack round-trip ---

    #[test]
    fn dirpath_round_trip() {
        let path = dirpath(Opaque::owned(b"/export/data".to_vec()));
        let wire = pack_to_vec(&path);
        let (decoded, consumed) = dirpath::unpack(&mut Cursor::new(&wire)).expect("unpack dirpath");
        assert_eq!(consumed, wire.len());
        assert_eq!(decoded.0.as_ref(), b"/export/data");
    }

    // --- mountres3 Ok: carries handle + auth_flavors array ---

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
        // Error variant is just the status code, 4 bytes.
        assert_eq!(wire.len(), 4);

        let (decoded, consumed) = mountres3::unpack(&mut Cursor::new(&wire)).expect("unpack mountres3 Err");
        assert_eq!(consumed, 4);
        match decoded {
            mountres3::Err(stat) => assert_eq!(stat as u32, 13),
            mountres3::Ok(_) => panic!("expected Err, got Ok"),
        }
    }
}
