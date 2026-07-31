#![expect(non_camel_case_types, reason = "identifiers are transcribed verbatim from the RFC's XDR definitions; renaming them to Rust conventions would break the correspondence a reader needs when checking this module against the spec")]
#![expect(missing_docs, reason = "these are mechanical transcriptions of the RFC's XDR type table -- per-field prose would restate the field name and nothing more. The module doc cites the defining RFC section, which is the real documentation")]
#![expect(single_use_lifetimes, reason = "newtype wrappers over Opaque<'a> genuinely need the parameter; the lint counts the declaration and the single use and misreads it as removable")]

//! This module contains the definitions of the Port Mapper protocol as defined in RFC 1057.

use nfswolf_xdr::{List, Opaque, XdrCodec};

pub const IPPROTO_TCP: u32 = 6;
pub const IPPROTO_UDP: u32 = 17;
pub const PROGRAM: u32 = 100_000;
pub const VERSION: u32 = 2;
pub const PMAP_PORT: u16 = 111;

#[derive(Copy, Clone, Debug, XdrCodec)]
pub struct mapping {
    pub prog: u32,
    pub vers: u32,
    pub prot: u32,
    pub port: u32,
}

pub type pmaplist = List<mapping>;

#[derive(Clone, Debug, XdrCodec)]
pub struct call_args<'a> {
    pub prog: u32,
    pub vers: u32,
    pub proc: u32,
    pub args: Opaque<'a>,
}

#[derive(Clone, Debug, XdrCodec)]
pub struct call_result<'a> {
    pub port: u32,
    pub res: Opaque<'a>,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, XdrCodec)]
#[repr(u32)]
pub enum PMAP_PROG {
    PMAPPROC_NULL = 0,
    PMAPPROC_SET = 1,
    PMAPPROC_UNSET = 2,
    PMAPPROC_GETPORT = 3,
    PMAPPROC_DUMP = 4,
    PMAPPROC_CALLIT = 5,
}

impl TryFrom<u32> for PMAP_PROG {
    type Error = nfswolf_xdr::Error;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::PMAPPROC_NULL),
            1 => Ok(Self::PMAPPROC_SET),
            2 => Ok(Self::PMAPPROC_UNSET),
            3 => Ok(Self::PMAPPROC_GETPORT),
            4 => Ok(Self::PMAPPROC_DUMP),
            5 => Ok(Self::PMAPPROC_CALLIT),
            _ => Err(nfswolf_xdr::Error::InvalidEnumValue(value)),
        }
    }
}

impl std::fmt::Display for PMAP_PROG {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match self {
            Self::PMAPPROC_NULL => "PMAPPROC_NULL",
            Self::PMAPPROC_SET => "PMAPPROC_SET",
            Self::PMAPPROC_UNSET => "PMAPPROC_UNSET",
            Self::PMAPPROC_GETPORT => "PMAPPROC_GETPORT",
            Self::PMAPPROC_DUMP => "PMAPPROC_DUMP",
            Self::PMAPPROC_CALLIT => "PMAPPROC_CALLIT",
        };
        write!(f, "{name}")
    }
}

#[cfg(test)]
mod tests {
    use super::{IPPROTO_TCP, IPPROTO_UDP, PMAP_PORT, PMAP_PROG, PROGRAM, VERSION, mapping};
    use nfswolf_xdr::{Pack, Unpack};
    use std::io::Cursor;

    // --- Protocol constants (RFC 1057 appendix A) ---

    /// RFC 1057 appendix A: portmapper uses TCP protocol number 6 and
    /// UDP protocol number 17.
    #[test]
    fn ipproto_constants_match_iana_values() {
        assert_eq!(IPPROTO_TCP, 6);
        assert_eq!(IPPROTO_UDP, 17);
    }

    /// RFC 1057 appendix A: portmapper is program 100000, version 2, port 111.
    #[test]
    fn portmapper_program_constants() {
        assert_eq!(PROGRAM, 100_000);
        assert_eq!(VERSION, 2);
        assert_eq!(PMAP_PORT, 111);
    }

    // --- mapping pack/unpack (RFC 1057 appendix A) ---

    #[test]
    fn mapping_pack_unpack_round_trip() {
        let m = mapping { prog: 100_003, vers: 3, prot: IPPROTO_TCP, port: 2049 };
        let mut buf = Vec::new();
        let _ = m.pack(&mut buf).expect("pack");
        // 4 XDR u32 fields = 16 bytes
        assert_eq!(buf.len(), 16);
        let mut cursor = Cursor::new(&buf);
        let (decoded, consumed) = mapping::unpack(&mut cursor).expect("unpack");
        assert_eq!(consumed, 16);
        assert_eq!(decoded.prog, 100_003);
        assert_eq!(decoded.vers, 3);
        assert_eq!(decoded.prot, IPPROTO_TCP);
        assert_eq!(decoded.port, 2049);
    }

    #[test]
    fn mapping_udp_variant() {
        let m = mapping { prog: 100_005, vers: 3, prot: IPPROTO_UDP, port: 0 };
        let mut buf = Vec::new();
        let _ = m.pack(&mut buf).expect("pack");
        let mut cursor = Cursor::new(&buf);
        let (decoded, _) = mapping::unpack(&mut cursor).expect("unpack");
        assert_eq!(decoded.prog, 100_005);
        assert_eq!(decoded.prot, IPPROTO_UDP);
        assert_eq!(decoded.port, 0);
    }

    // --- PMAP_PROG procedure numbers (RFC 1057 appendix A) ---

    /// RFC 1057 appendix A defines portmapper procedures 0-5.
    #[test]
    fn pmap_prog_procedure_numbers() {
        let variants = [(PMAP_PROG::PMAPPROC_NULL, 0_u32), (PMAP_PROG::PMAPPROC_SET, 1), (PMAP_PROG::PMAPPROC_UNSET, 2), (PMAP_PROG::PMAPPROC_GETPORT, 3), (PMAP_PROG::PMAPPROC_DUMP, 4), (PMAP_PROG::PMAPPROC_CALLIT, 5)];
        for (variant, expected) in variants {
            let mut buf = Vec::new();
            let _ = variant.pack(&mut buf).expect("pack");
            assert_eq!(buf, expected.to_be_bytes(), "{variant:?}");
        }
    }

    #[test]
    fn pmap_prog_round_trip() {
        for variant in [PMAP_PROG::PMAPPROC_NULL, PMAP_PROG::PMAPPROC_SET, PMAP_PROG::PMAPPROC_UNSET, PMAP_PROG::PMAPPROC_GETPORT, PMAP_PROG::PMAPPROC_DUMP, PMAP_PROG::PMAPPROC_CALLIT] {
            let mut buf = Vec::new();
            let _ = variant.pack(&mut buf).expect("pack");
            let mut cursor = Cursor::new(&buf);
            let (decoded, consumed) = PMAP_PROG::unpack(&mut cursor).expect("unpack");
            assert_eq!(consumed, 4);
            assert_eq!(decoded, variant);
        }
    }

    #[test]
    fn pmap_prog_try_from_valid() {
        for v in 0..=5_u32 {
            assert!(PMAP_PROG::try_from(v).is_ok(), "procedure {v} should be valid");
        }
    }

    #[test]
    fn pmap_prog_try_from_invalid() {
        for v in [6_u32, 100, u32::MAX] {
            assert!(PMAP_PROG::try_from(v).is_err(), "procedure {v} should be invalid");
        }
    }
}
