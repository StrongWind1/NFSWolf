#![allow(non_camel_case_types, clippy::upper_case_acronyms, reason = "identifiers are transcribed verbatim from the RFC's XDR definitions; renaming them to Rust conventions would break the correspondence a reader needs when checking this module against the spec")]
#![allow(missing_docs, reason = "these are mechanical transcriptions of the RFC's XDR type table -- per-field prose would restate the field name and nothing more. The module doc cites the defining RFC section, which is the real documentation")]
#![allow(
    missing_copy_implementations,
    reason = "Copy is derived on the wire types whose callers benefit from it; demanding it exhaustively cascades through every containing struct without improving the API, and whether a value is copied or moved is a Rust-side choice the wire format has no opinion on"
)]
#![allow(single_use_lifetimes, reason = "newtype wrappers over Opaque<'a> genuinely need the parameter; the lint counts the declaration and the single use and misreads it as removable")]
#![allow(clippy::large_enum_variant, reason = "variant sizes are dictated by the wire format, not chosen here")]

//! This module contains the definitions of the RPC protocol as defined in RFC 1057.

use std::io::{Read, Write};

use nfswolf_xdr::XdrCodec;

use nfswolf_xdr::{Opaque, Pack, Unpack};

/// RPC header
///
/// The RPC header is a 32-bit integer that contains the length of the fragment and an EOF flag.
#[derive(Default, Copy, Clone, Debug, Eq, PartialEq, XdrCodec)]
pub struct fragment_header {
    pub header: u32,
}

impl fragment_header {
    pub const EOF_FLAG: u32 = 0x8000_0000;
    pub const MASK: u32 = 0x7FFF_FFFF;

    /// Creates a new `fragment_header` with the given length and EOF flag.
    ///
    /// # Panics
    ///
    /// Panics if the length is greater than 2 GiB.
    #[must_use]
    pub fn new(length: u32, eof: bool) -> Self {
        assert!(length <= Self::MASK);
        let mut header = length;
        if eof {
            header |= Self::EOF_FLAG;
        }
        Self { header }
    }
    #[must_use]
    pub const fn eof(self) -> bool {
        self.header & Self::EOF_FLAG != 0
    }
    #[must_use]
    pub const fn fragment_length(self) -> u32 {
        self.header & Self::MASK
    }
    #[must_use]
    pub const fn into_xdr_buf(self) -> [u8; 4] {
        self.header.to_be_bytes()
    }
}

impl From<[u8; 4]> for fragment_header {
    fn from(bytes: [u8; 4]) -> Self {
        let header = u32::from_be_bytes(bytes);
        Self { header }
    }
}

pub const RPC_VERSION_2: u32 = 2;

#[derive(Copy, Clone, Debug, Eq, PartialEq, XdrCodec)]
#[repr(u32)]
pub enum msg_type {
    CALL = 0,
    REPLY = 1,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, XdrCodec)]
#[repr(u32)]
pub enum reply_stat {
    MSG_ACCEPTED = 0,
    MSG_DENIED = 1,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, XdrCodec)]
#[repr(u32)]
pub enum accept_stat {
    SUCCESS = 0,
    PROG_UNAVAIL = 1,
    PROG_MISMATCH = 2,
    PROC_UNAVAIL = 3,
    GARBAGE_ARGS = 4,
    SYSTEM_ERR = 5,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, XdrCodec)]
#[repr(u32)]
pub enum reject_stat {
    RPC_MISMATCH = 0,
    AUTH_ERROR = 1,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, XdrCodec)]
#[repr(u32)]
pub enum auth_stat {
    AUTH_OK = 0,
    AUTH_BADCRED = 1,
    AUTH_REJECTEDCRED = 2,
    AUTH_BADVERF = 3,
    AUTH_REJECTEDVERF = 4,
    AUTH_TOOWEAK = 5,
    AUTH_INVALIDRESP = 6,
    AUTH_FAILED = 7,
}

impl std::fmt::Display for auth_stat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match self {
            Self::AUTH_OK => "AUTH_OK",
            Self::AUTH_BADCRED => "AUTH_BADCRED",
            Self::AUTH_REJECTEDCRED => "AUTH_REJECTEDCRED",
            Self::AUTH_BADVERF => "AUTH_BADVERF",
            Self::AUTH_REJECTEDVERF => "AUTH_REJECTEDVERF",
            Self::AUTH_TOOWEAK => "AUTH_TOOWEAK",
            Self::AUTH_INVALIDRESP => "AUTH_INVALIDRESP",
            Self::AUTH_FAILED => "AUTH_FAILED",
        };
        write!(f, "{name}")
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, XdrCodec)]
#[repr(u32)]
pub enum auth_flavor {
    AUTH_NULL = 0,
    AUTH_UNIX = 1,
    AUTH_SHORT = 2,
    AUTH_DES = 3,
    // and more to be defined
}

#[derive(Clone, Debug, XdrCodec)]
pub struct opaque_auth<'a> {
    pub flavor: auth_flavor,
    pub body: Opaque<'a>,
}

impl Default for opaque_auth<'static> {
    fn default() -> Self {
        Self { flavor: auth_flavor::AUTH_NULL, body: Opaque::borrowed(&[]) }
    }
}

impl opaque_auth<'static> {
    /// Creates a new `opaque_auth` with the given flavor and body constructed from `auth_unix`.
    ///
    /// # Panics
    ///
    /// Panics if the `auth_unix` cannot be packed.
    #[must_use]
    #[expect(clippy::expect_used, reason = "the sink is a Vec, whose Write impl is infallible, so this cannot fire")]
    pub fn auth_unix(auth: &auth_unix) -> Self {
        let mut out = Vec::with_capacity(auth.packed_size());
        // Byte count is redundant -- out.len() already holds it.
        let _ = auth.pack(&mut out).expect("failed to pack auth_unix");
        Self { flavor: auth_flavor::AUTH_UNIX, body: Opaque::owned(out) }
    }

    #[must_use]
    pub fn borrow(&self) -> opaque_auth<'_> {
        opaque_auth { flavor: self.flavor, body: Opaque::borrowed(self.body.as_ref()) }
    }
}

#[derive(Clone, Debug, XdrCodec)]
pub struct auth_unix {
    pub stamp: u32,
    pub machinename: Opaque<'static>,
    pub uid: u32,
    pub gid: u32,
    pub gids: Vec<u32>,
}

impl Default for auth_unix {
    fn default() -> Self {
        Self { stamp: 0, machinename: Opaque::borrowed(b""), uid: 0, gid: 0, gids: vec![] }
    }
}

#[derive(Debug, XdrCodec)]
pub struct call_body<'a> {
    pub rpcvers: u32,
    pub prog: u32,
    pub vers: u32,
    pub proc: u32,
    pub cred: opaque_auth<'a>,
    pub verf: opaque_auth<'a>,
}

#[derive(Debug, XdrCodec)]
pub struct accepted_reply<'a> {
    pub verf: opaque_auth<'a>,
    pub reply_data: accept_stat_data,
}

/// RPC-level accepted reply body (RFC 5531 sec 13.1).
///
/// SUCCESS carries no data at this layer: the procedure-specific reply
/// payload remains on the stream for the caller (NFS/MOUNT/portmapper)
/// to decode with its own type knowledge. The RPC layer cannot interpret
/// it because it is generic over all programs and versions.
#[derive(Debug, Clone, Copy)]
pub enum accept_stat_data {
    SUCCESS,
    PROG_UNAVAIL,
    PROG_MISMATCH { low: u32, high: u32 },
    PROC_UNAVAIL,
    GARBAGE_ARGS,
    SYSTEM_ERR,
}

impl Pack for accept_stat_data {
    fn packed_size(&self) -> usize {
        4 + match self {
            Self::SUCCESS | Self::PROG_UNAVAIL | Self::PROC_UNAVAIL | Self::GARBAGE_ARGS | Self::SYSTEM_ERR => 0,
            Self::PROG_MISMATCH { .. } => 8,
        }
    }

    fn pack(&self, out: &mut impl Write) -> nfswolf_xdr::Result<usize> {
        let len = match self {
            Self::SUCCESS => accept_stat::SUCCESS.pack(out)?,
            Self::PROG_UNAVAIL => accept_stat::PROG_UNAVAIL.pack(out)?,
            Self::PROG_MISMATCH { low, high } => accept_stat::PROG_MISMATCH.pack(out)? + low.pack(out)? + high.pack(out)?,
            Self::PROC_UNAVAIL => accept_stat::PROC_UNAVAIL.pack(out)?,
            Self::GARBAGE_ARGS => accept_stat::GARBAGE_ARGS.pack(out)?,
            Self::SYSTEM_ERR => accept_stat::SYSTEM_ERR.pack(out)?,
        };
        Ok(len)
    }
}

impl Unpack for accept_stat_data {
    fn unpack(input: &mut impl Read) -> nfswolf_xdr::Result<(Self, usize)> {
        let (accept_stat, len) = accept_stat::unpack(input)?;
        let (body, body_len) = match accept_stat {
            accept_stat::SUCCESS => (Self::SUCCESS, 0),
            accept_stat::PROG_MISMATCH => {
                let (low, low_len) = u32::unpack(input)?;
                let (high, high_len) = u32::unpack(input)?;
                (Self::PROG_MISMATCH { low, high }, low_len + high_len)
            },
            accept_stat::PROG_UNAVAIL => (Self::PROG_UNAVAIL, 0),
            accept_stat::PROC_UNAVAIL => (Self::PROC_UNAVAIL, 0),
            accept_stat::GARBAGE_ARGS => (Self::GARBAGE_ARGS, 0),
            accept_stat::SYSTEM_ERR => (Self::SYSTEM_ERR, 0),
        };
        Ok((body, len + body_len))
    }
}

#[derive(Debug, Clone, Copy)]
pub enum rejected_reply {
    RPC_MISMATCH { low: u32, high: u32 },
    AUTH_ERROR(auth_stat),
}

impl rejected_reply {
    #[must_use]
    pub const fn rpc_mismatch(low: u32, high: u32) -> Self {
        Self::RPC_MISMATCH { low, high }
    }
    #[must_use]
    pub const fn auth_error(auth_stat: auth_stat) -> Self {
        Self::AUTH_ERROR(auth_stat)
    }
}

impl Pack for rejected_reply {
    fn packed_size(&self) -> usize {
        4 + match self {
            Self::RPC_MISMATCH { .. } => 8,
            Self::AUTH_ERROR(_) => 4,
        }
    }

    fn pack(&self, out: &mut impl Write) -> nfswolf_xdr::Result<usize> {
        let len = match self {
            Self::RPC_MISMATCH { low, high } => reject_stat::RPC_MISMATCH.pack(out)? + low.pack(out)? + high.pack(out)?,
            Self::AUTH_ERROR(auth_stat) => reject_stat::AUTH_ERROR.pack(out)? + auth_stat.pack(out)?,
        };
        Ok(len)
    }
}

impl Unpack for rejected_reply {
    fn unpack(input: &mut impl Read) -> nfswolf_xdr::Result<(Self, usize)> {
        let (reject_stat, len) = reject_stat::unpack(input)?;
        let (body, body_len) = match reject_stat {
            reject_stat::RPC_MISMATCH => {
                let (low, low_len) = u32::unpack(input)?;
                let (high, high_len) = u32::unpack(input)?;
                (Self::RPC_MISMATCH { low, high }, low_len + high_len)
            },
            reject_stat::AUTH_ERROR => {
                let (auth_stat, auth_stat_len) = auth_stat::unpack(input)?;
                (Self::AUTH_ERROR(auth_stat), auth_stat_len)
            },
        };
        Ok((body, len + body_len))
    }
}

#[derive(Debug, XdrCodec)]
pub enum reply_body<'a> {
    #[xdr(0)]
    MSG_ACCEPTED(accepted_reply<'a>),
    #[xdr(1)]
    MSG_DENIED(rejected_reply),
}

#[derive(Debug, XdrCodec)]
pub struct rpc_msg<'a, 'b> {
    pub xid: u32,
    pub body: msg_body<'a, 'b>,
}

#[derive(Debug, XdrCodec)]
pub enum msg_body<'a, 'b> {
    #[xdr(0)]
    CALL(call_body<'a>),
    #[xdr(1)]
    REPLY(reply_body<'b>),
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    /// Pack a value, then unpack from the resulting bytes and return both the
    /// encoded buffer and the decoded value.
    fn round_trip<T: Pack + Unpack>(val: &T) -> (Vec<u8>, T) {
        let mut buf = Vec::new();
        let _ = val.pack(&mut buf).expect("pack");
        let mut cursor = Cursor::new(&buf);
        let (decoded, consumed) = T::unpack(&mut cursor).expect("unpack");
        assert_eq!(consumed, buf.len(), "unpack must consume every packed byte");
        (buf, decoded)
    }

    // --- fragment_header (RFC 5531 sec 11) ---

    /// RFC 5531 sec 11: "The highest-order bit of the header is a boolean
    /// that indicates whether the fragment is the last fragment of the
    /// record (bit value 1) or not (bit value 0)."
    #[test]
    fn fragment_header_last_fragment_sets_bit_31() {
        let hdr = fragment_header::new(100, true);
        assert!(hdr.eof());
        assert_eq!(hdr.fragment_length(), 100);
        // Bit 31 must be set in the raw u32.
        assert_ne!(hdr.header & fragment_header::EOF_FLAG, 0);
    }

    #[test]
    fn fragment_header_non_last_fragment_clears_bit_31() {
        let hdr = fragment_header::new(200, false);
        assert!(!hdr.eof());
        assert_eq!(hdr.fragment_length(), 200);
        assert_eq!(hdr.header & fragment_header::EOF_FLAG, 0);
    }

    #[test]
    fn fragment_header_pack_unpack_round_trip() {
        let hdr = fragment_header::new(4096, true);
        let (buf, decoded) = round_trip(&hdr);
        assert_eq!(buf.len(), 4);
        assert_eq!(decoded, hdr);
    }

    #[test]
    fn fragment_header_from_be_bytes() {
        // 0x80001000 = last-fragment + length 4096
        let bytes: [u8; 4] = 0x8000_1000_u32.to_be_bytes();
        let hdr = fragment_header::from(bytes);
        assert!(hdr.eof());
        assert_eq!(hdr.fragment_length(), 0x1000);
    }

    #[test]
    fn fragment_header_into_xdr_buf() {
        let hdr = fragment_header::new(256, true);
        let bytes = hdr.into_xdr_buf();
        assert_eq!(bytes, (0x8000_0100_u32).to_be_bytes());
    }

    // --- msg_type (RFC 5531 sec 8) ---

    /// RFC 5531 sec 8: "enum msg_type { CALL = 0, REPLY = 1 };"
    #[test]
    fn msg_type_call_is_zero() {
        let (buf, _) = round_trip(&msg_type::CALL);
        assert_eq!(buf, 0_u32.to_be_bytes());
    }

    #[test]
    fn msg_type_reply_is_one() {
        let (buf, _) = round_trip(&msg_type::REPLY);
        assert_eq!(buf, 1_u32.to_be_bytes());
    }

    #[test]
    fn msg_type_round_trip() {
        for variant in [msg_type::CALL, msg_type::REPLY] {
            let (_, decoded) = round_trip(&variant);
            assert_eq!(decoded, variant);
        }
    }

    // --- reply_stat (RFC 5531 sec 9) ---

    #[test]
    fn reply_stat_msg_accepted_is_zero() {
        let (buf, _) = round_trip(&reply_stat::MSG_ACCEPTED);
        assert_eq!(buf, 0_u32.to_be_bytes());
    }

    #[test]
    fn reply_stat_msg_denied_is_one() {
        let (buf, _) = round_trip(&reply_stat::MSG_DENIED);
        assert_eq!(buf, 1_u32.to_be_bytes());
    }

    #[test]
    fn reply_stat_round_trip() {
        for variant in [reply_stat::MSG_ACCEPTED, reply_stat::MSG_DENIED] {
            let (_, decoded) = round_trip(&variant);
            assert_eq!(decoded, variant);
        }
    }

    // --- accept_stat (RFC 5531 sec 13.2) ---

    /// RFC 5531 sec 13.2 defines the six accept_stat values as 0-5.
    #[test]
    fn accept_stat_all_six_variants_round_trip() {
        let variants = [(accept_stat::SUCCESS, 0_u32), (accept_stat::PROG_UNAVAIL, 1), (accept_stat::PROG_MISMATCH, 2), (accept_stat::PROC_UNAVAIL, 3), (accept_stat::GARBAGE_ARGS, 4), (accept_stat::SYSTEM_ERR, 5)];
        for (variant, expected_disc) in variants {
            let (buf, decoded) = round_trip(&variant);
            assert_eq!(buf, expected_disc.to_be_bytes(), "{variant:?} discriminant");
            assert_eq!(decoded, variant);
        }
    }

    // --- reject_stat (RFC 5531 sec 13.2) ---

    #[test]
    fn reject_stat_rpc_mismatch_is_zero() {
        let (buf, _) = round_trip(&reject_stat::RPC_MISMATCH);
        assert_eq!(buf, 0_u32.to_be_bytes());
    }

    #[test]
    fn reject_stat_auth_error_is_one() {
        let (buf, _) = round_trip(&reject_stat::AUTH_ERROR);
        assert_eq!(buf, 1_u32.to_be_bytes());
    }

    #[test]
    fn reject_stat_round_trip() {
        for variant in [reject_stat::RPC_MISMATCH, reject_stat::AUTH_ERROR] {
            let (_, decoded) = round_trip(&variant);
            assert_eq!(decoded, variant);
        }
    }

    // --- auth_stat (RFC 5531 sec 8.3) ---

    /// RFC 5531 sec 8.3 defines auth_stat values 0-7.
    #[test]
    fn auth_stat_all_variants_round_trip() {
        let variants = [(auth_stat::AUTH_OK, 0_u32), (auth_stat::AUTH_BADCRED, 1), (auth_stat::AUTH_REJECTEDCRED, 2), (auth_stat::AUTH_BADVERF, 3), (auth_stat::AUTH_REJECTEDVERF, 4), (auth_stat::AUTH_TOOWEAK, 5), (auth_stat::AUTH_INVALIDRESP, 6), (auth_stat::AUTH_FAILED, 7)];
        for (variant, expected_disc) in variants {
            let (buf, decoded) = round_trip(&variant);
            assert_eq!(buf, expected_disc.to_be_bytes(), "{variant:?} discriminant");
            assert_eq!(decoded, variant);
        }
    }

    // --- auth_flavor (RFC 5531 sec 8.2) ---

    /// RFC 5531 sec 8.2: AUTH_NULL=0, AUTH_UNIX/AUTH_SYS=1, AUTH_SHORT=2, AUTH_DES=3.
    #[test]
    fn auth_flavor_all_variants_round_trip() {
        let variants = [(auth_flavor::AUTH_NULL, 0_u32), (auth_flavor::AUTH_UNIX, 1), (auth_flavor::AUTH_SHORT, 2), (auth_flavor::AUTH_DES, 3)];
        for (variant, expected_disc) in variants {
            let (buf, decoded) = round_trip(&variant);
            assert_eq!(buf, expected_disc.to_be_bytes(), "{variant:?} discriminant");
            assert_eq!(decoded, variant);
        }
    }

    // --- opaque_auth (RFC 5531 sec 8.2) ---

    #[test]
    fn opaque_auth_null_round_trip() {
        let auth = opaque_auth::default();
        let (buf, decoded) = round_trip(&auth);
        // flavor(4) + body-length(4) + body(0) = 8 bytes
        assert_eq!(buf.len(), 8);
        assert_eq!(decoded.flavor, auth_flavor::AUTH_NULL);
        assert!(decoded.body.as_ref().is_empty());
    }

    #[test]
    fn opaque_auth_with_body_round_trip() {
        let auth = opaque_auth { flavor: auth_flavor::AUTH_UNIX, body: Opaque::owned(vec![0xDE, 0xAD, 0xBE, 0xEF]) };
        let (_, decoded) = round_trip(&auth);
        assert_eq!(decoded.flavor, auth_flavor::AUTH_UNIX);
        assert_eq!(decoded.body.as_ref(), &[0xDE, 0xAD, 0xBE, 0xEF]);
    }

    // --- call_body (RFC 5531 sec 9) ---

    #[test]
    fn call_body_pack_unpack_with_known_program() {
        let call = call_body {
            rpcvers: RPC_VERSION_2,
            prog: 100_003, // NFS
            vers: 3,
            proc: 1, // GETATTR
            cred: opaque_auth::default(),
            verf: opaque_auth::default(),
        };
        let (_, decoded) = round_trip(&call);
        assert_eq!(decoded.rpcvers, RPC_VERSION_2);
        assert_eq!(decoded.prog, 100_003);
        assert_eq!(decoded.vers, 3);
        assert_eq!(decoded.proc, 1);
    }

    // --- rpc_msg CALL round-trip (RFC 5531 sec 8) ---

    #[test]
    fn rpc_msg_call_round_trip() {
        let msg = rpc_msg {
            xid: 0x42,
            body: msg_body::CALL(call_body {
                rpcvers: RPC_VERSION_2,
                prog: 100_005, // MOUNT
                vers: 3,
                proc: 1, // MNT
                cred: opaque_auth::default(),
                verf: opaque_auth::default(),
            }),
        };
        let mut buf = Vec::new();
        let _ = msg.pack(&mut buf).expect("pack");
        let mut cursor = Cursor::new(&buf);
        let (decoded, consumed) = rpc_msg::unpack(&mut cursor).expect("unpack");
        assert_eq!(consumed, buf.len());
        assert_eq!(decoded.xid, 0x42);
        match decoded.body {
            msg_body::CALL(call) => {
                assert_eq!(call.prog, 100_005);
                assert_eq!(call.vers, 3);
                assert_eq!(call.proc, 1);
            },
            msg_body::REPLY(_) => panic!("expected CALL, got REPLY"),
        }
    }

    // --- rpc_msg REPLY MSG_ACCEPTED SUCCESS round-trip ---

    #[test]
    fn rpc_msg_reply_accepted_success_round_trip() {
        let msg = rpc_msg { xid: 0x99, body: msg_body::REPLY(reply_body::MSG_ACCEPTED(accepted_reply { verf: opaque_auth::default(), reply_data: accept_stat_data::SUCCESS })) };
        let mut buf = Vec::new();
        let _ = msg.pack(&mut buf).expect("pack");
        let mut cursor = Cursor::new(&buf);
        let (decoded, _) = rpc_msg::unpack(&mut cursor).expect("unpack");
        assert_eq!(decoded.xid, 0x99);
        match decoded.body {
            msg_body::REPLY(reply_body::MSG_ACCEPTED(reply)) => {
                assert!(matches!(reply.reply_data, accept_stat_data::SUCCESS));
            },
            _ => panic!("expected MSG_ACCEPTED SUCCESS"),
        }
    }

    // --- accept_stat_data PROG_MISMATCH (RFC 5531 sec 13.2) ---

    /// RFC 5531 sec 13.2: when the server denies with PROG_MISMATCH, it
    /// includes the low and high supported versions.
    #[test]
    fn accept_stat_data_prog_mismatch_carries_version_range() {
        let data = accept_stat_data::PROG_MISMATCH { low: 2, high: 4 };
        let (buf, decoded) = round_trip(&data);
        // discriminant(4) + low(4) + high(4) = 12 bytes
        assert_eq!(buf.len(), 12);
        match decoded {
            accept_stat_data::PROG_MISMATCH { low, high } => {
                assert_eq!(low, 2);
                assert_eq!(high, 4);
            },
            other => panic!("expected PROG_MISMATCH, got {other:?}"),
        }
    }

    #[test]
    fn accept_stat_data_simple_variants_round_trip() {
        for variant in [accept_stat_data::SUCCESS, accept_stat_data::PROG_UNAVAIL, accept_stat_data::PROC_UNAVAIL, accept_stat_data::GARBAGE_ARGS, accept_stat_data::SYSTEM_ERR] {
            let (buf, _) = round_trip(&variant);
            // Simple variants are just the 4-byte discriminant.
            assert_eq!(buf.len(), 4);
        }
    }

    // --- rejected_reply (RFC 5531 sec 13.2) ---

    #[test]
    fn rejected_reply_rpc_mismatch_round_trip() {
        let val = rejected_reply::rpc_mismatch(2, 2);
        let (_, decoded) = round_trip(&val);
        match decoded {
            rejected_reply::RPC_MISMATCH { low, high } => {
                assert_eq!(low, 2);
                assert_eq!(high, 2);
            },
            rejected_reply::AUTH_ERROR(_) => panic!("expected RPC_MISMATCH"),
        }
    }

    #[test]
    fn rejected_reply_auth_error_round_trip() {
        let val = rejected_reply::auth_error(auth_stat::AUTH_TOOWEAK);
        let (_, decoded) = round_trip(&val);
        match decoded {
            rejected_reply::AUTH_ERROR(stat) => assert_eq!(stat, auth_stat::AUTH_TOOWEAK),
            rejected_reply::RPC_MISMATCH { .. } => panic!("expected AUTH_ERROR"),
        }
    }

    // --- reply_body round-trip ---

    #[test]
    fn reply_body_msg_denied_round_trip() {
        let body = reply_body::MSG_DENIED(rejected_reply::auth_error(auth_stat::AUTH_BADCRED));
        let mut buf = Vec::new();
        let _ = body.pack(&mut buf).expect("pack");
        let mut cursor = Cursor::new(&buf);
        let (decoded, consumed) = reply_body::unpack(&mut cursor).expect("unpack");
        assert_eq!(consumed, buf.len());
        match decoded {
            reply_body::MSG_DENIED(rejected_reply::AUTH_ERROR(stat)) => {
                assert_eq!(stat, auth_stat::AUTH_BADCRED);
            },
            _ => panic!("expected MSG_DENIED AUTH_BADCRED"),
        }
    }
}
