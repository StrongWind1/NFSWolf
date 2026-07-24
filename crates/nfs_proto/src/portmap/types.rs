#![allow(non_camel_case_types, clippy::upper_case_acronyms, reason = "identifiers are transcribed verbatim from the RFC's XDR definitions; renaming them to Rust conventions would break the correspondence a reader needs when checking this module against the spec")]
#![allow(missing_docs, reason = "these are mechanical transcriptions of the RFC's XDR type table -- per-field prose would restate the field name and nothing more. The module doc cites the defining RFC section, which is the real documentation")]
#![allow(
    missing_copy_implementations,
    reason = "Copy is derived on the wire types whose callers benefit from it; demanding it exhaustively cascades through every containing struct without improving the API, and whether a value is copied or moved is a Rust-side choice the wire format has no opinion on"
)]
#![allow(single_use_lifetimes, reason = "newtype wrappers over Opaque<'a> genuinely need the parameter; the lint counts the declaration and the single use and misreads it as removable")]
#![allow(clippy::large_enum_variant, reason = "variant sizes are dictated by the wire format, not chosen here")]

//! This module contains the definitions of the Port Mapper protocol as defined in RFC 1057.

use crate::xdr::{List, Opaque, XdrCodec};

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
    type Error = crate::xdr::Error;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::PMAPPROC_NULL),
            1 => Ok(Self::PMAPPROC_SET),
            2 => Ok(Self::PMAPPROC_UNSET),
            3 => Ok(Self::PMAPPROC_GETPORT),
            4 => Ok(Self::PMAPPROC_DUMP),
            5 => Ok(Self::PMAPPROC_CALLIT),
            _ => Err(crate::xdr::Error::InvalidEnumValue(value)),
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
