//! AUTH_SYS stamp policy.
//!
//! The credential itself is RFC 5531 sec. 14 and lives in `onc_rpc_client::auth`.
//! What belongs here is the part that is nfswolf's choice rather than the
//! spec's: which stamp each encoded credential carries.
//!
//! The stamp is an arbitrary caller-chosen value (RFC 1057 sec. 9.2). It is NOT
//! part of the Linux knfsd duplicate-request cache (DRC) key -- the DRC keys on
//! XID + procedure + source address + version + arg length + checksum of the
//! call body (see `fs/nfsd/nfscache.c`). XID uniqueness, which the RPC crate
//! handles via fastrand, is what actually prevents false DRC hits.
//!
//! The incrementing stamp is harmless to keep but the original justification
//! (DRC avoidance during UID sweeps) was wrong. Two calls with different UIDs
//! already differ in their encoded AUTH_SYS body, so they produce different arg
//! checksums and cannot collide in the DRC regardless of stamp value.

use std::sync::atomic::{AtomicU32, Ordering};

use onc_rpc_client::rpc::opaque_auth;

pub(crate) use onc_rpc_client::auth::{AuthFlavor, AuthSys};

/// Stamp start value, and the floor the counter wraps back to.
///
/// Wrapping to 42 rather than 0 avoids the low values other clients commonly
/// use. Not load-bearing (stamps are not in the DRC key), just tidy.
const STAMP_START: u32 = 42;

/// Global stamp counter, advanced once per credential encode.
static STAMP_COUNTER: AtomicU32 = AtomicU32::new(STAMP_START);

/// A credential to present on an RPC call.
#[derive(Debug, Clone)]
pub(crate) enum Credential {
    /// No authentication.
    None,
    /// AUTH_SYS: client-asserted UID and GID, which the server does not verify.
    Sys(AuthSys),
}

impl Credential {
    /// Encode for the wire, consuming a fresh stamp for AUTH_SYS.
    pub(crate) fn to_opaque_auth(&self) -> opaque_auth<'static> {
        match self {
            Self::None => opaque_auth::default(),
            Self::Sys(auth) => auth.to_opaque_auth(next_stamp()),
        }
    }
}

/// Human-readable name for an RPC auth flavor value.
///
/// Covers AUTH_NONE (0), AUTH_SYS (1), AUTH_SHORT (2), AUTH_DH (3),
/// RPCSEC_GSS (6), AUTH_TLS (7, RFC 9289), and the Linux krb5 pseudo-flavors
/// (390003-390005, RFC 2623 S2.1.1). Unknown values render as `flavor(N)`.
pub(crate) fn flavor_name(flavor: u32) -> String {
    match flavor {
        0 => "AUTH_NONE".to_owned(),
        1 => "AUTH_SYS".to_owned(),
        2 => "AUTH_SHORT".to_owned(),
        3 => "AUTH_DH".to_owned(),
        6 => "RPCSEC_GSS".to_owned(),
        7 => "AUTH_TLS".to_owned(),
        390_003 => "RPCSEC_GSS(krb5)".to_owned(),
        390_004 => "RPCSEC_GSS(krb5i)".to_owned(),
        390_005 => "RPCSEC_GSS(krb5p)".to_owned(),
        _ => format!("flavor({flavor})"),
    }
}

/// Fetch the next stamp, wrapping back to [`STAMP_START`] at `u32::MAX`.
///
/// A compare-and-swap loop keeps the wrap atomic without a mutex; contention is
/// negligible because the only work between load and store is a comparison.
pub(crate) fn next_stamp() -> u32 {
    loop {
        let cur = STAMP_COUNTER.load(Ordering::Relaxed);
        let next = if cur == u32::MAX { STAMP_START } else { cur.wrapping_add(1) };
        if STAMP_COUNTER.compare_exchange_weak(cur, next, Ordering::Relaxed, Ordering::Relaxed).is_ok() {
            return cur;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stamps_are_unique_across_consecutive_encodes() {
        let a = next_stamp();
        let b = next_stamp();
        assert_ne!(a, b, "a repeated stamp lets a server serve a cached reply to a different identity");
    }

    #[test]
    fn stamp_never_returns_below_the_floor() {
        for _ in 0..64 {
            assert!(next_stamp() >= STAMP_START);
        }
    }

    #[test]
    fn credential_none_encodes_as_auth_none() {
        use onc_rpc_client::rpc::auth_flavor;
        assert_eq!(Credential::None.to_opaque_auth().flavor, auth_flavor::AUTH_NULL);
    }

    #[test]
    fn credential_sys_encodes_as_auth_unix() {
        use onc_rpc_client::rpc::auth_flavor;
        let cred = Credential::Sys(AuthSys::new(1000, 1000, "host"));
        assert_eq!(cred.to_opaque_auth().flavor, auth_flavor::AUTH_UNIX);
    }
}
