//! AUTH_SYS credentials -- [RFC 5531] sec. 14.
//!
//! AUTH_SYS (historically AUTH_UNIX) is the flavor essentially every NFS
//! deployment uses, and it authenticates nothing. The credential is a plain
//! struct asserting a UID, GID, and supplementary group list. There is no
//! signature, no shared secret, and no challenge -- the server takes the
//! client's word for who it is, and the only thing standing between an
//! attacker and any file is whether the server bothers to check the source
//! port or the export's host list.
//!
//! This module provides the wire encoding only. Whether to reuse a stamp, how
//! to pick UIDs, and when to swap identities are caller policy.
//!
//! [RFC 5531]: https://www.rfc-editor.org/rfc/rfc5531

use nfswolf_xdr::Opaque;

use crate::rpc::{auth_unix, opaque_auth};

/// Maximum supplementary GIDs an AUTH_SYS credential may carry.
///
/// RFC 5531 sec. 14 caps the list at 16. Servers silently ignore anything
/// beyond that, so the encoder truncates rather than letting a longer list
/// produce a credential the server will read differently than intended.
pub const MAX_AUX_GIDS: usize = 16;

/// Authentication flavor identifiers -- [RFC 5531] sec. 8.2.
///
/// [RFC 5531]: https://www.rfc-editor.org/rfc/rfc5531
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum AuthFlavor {
    /// `AUTH_NONE` -- no credential at all.
    None = 0,
    /// `AUTH_SYS` / `AUTH_UNIX` -- client-asserted UID and GID, unverified.
    Sys = 1,
    /// `AUTH_SHORT` -- an opaque server-issued handle standing in for AUTH_SYS.
    Short = 2,
    /// `AUTH_DH` -- Diffie-Hellman, effectively extinct.
    Dh = 3,
    /// `RPCSEC_GSS` -- the only flavor that actually authenticates (Kerberos).
    Gss = 6,
    /// A flavor number this crate does not recognise, including vendor-specific
    /// GSS pseudo-flavors.
    Unknown = 255,
}

impl AuthFlavor {
    /// Classify a flavor number from the wire.
    ///
    /// Kerberos pseudo-flavors (390003-390005, RFC 2623 sec. 2.1.1) map to
    /// [`AuthFlavor::Gss`], since for any security question the answer that
    /// matters is "this export wants Kerberos".
    #[must_use]
    pub const fn from_u32(v: u32) -> Self {
        match v {
            0 => Self::None,
            1 => Self::Sys,
            2 => Self::Short,
            3 => Self::Dh,
            6 | 390_003..=390_005 => Self::Gss,
            _ => Self::Unknown,
        }
    }

    /// Whether this flavor actually verifies the client's claimed identity.
    ///
    /// True only for `RPCSEC_GSS`. Everything else is an assertion the server
    /// is trusting on faith.
    #[must_use]
    pub const fn is_authenticated(self) -> bool {
        matches!(self, Self::Gss)
    }
}

/// An AUTH_SYS credential.
///
/// Every field is chosen by the client and none is verified, which is the
/// entire basis for UID spraying and identity escalation against an NFS export.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthSys {
    /// Client hostname.
    ///
    /// Advisory: Linux knfsd logs it and does not use it for access control,
    /// so it does not bypass a hostname-restricted export.
    pub machinename: String,
    /// Effective UID the server will use for permission checks.
    pub uid: u32,
    /// Effective GID -- primary group for permission checks.
    pub gid: u32,
    /// Supplementary GIDs, truncated to [`MAX_AUX_GIDS`] when encoded.
    pub gids: Vec<u32>,
}

impl AuthSys {
    /// Create a credential for `uid`/`gid`, with `gid` as the only group.
    #[must_use]
    pub fn new(uid: u32, gid: u32, hostname: &str) -> Self {
        Self { machinename: hostname.to_owned(), uid, gid, gids: vec![gid] }
    }

    /// Create a root credential (uid 0, gid 0).
    ///
    /// Whether the server honours this depends on its squash configuration; an
    /// export with `no_root_squash` will.
    #[must_use]
    pub fn root(hostname: &str) -> Self {
        Self::new(0, 0, hostname)
    }

    /// Create a credential with an explicit supplementary group list.
    ///
    /// The list is truncated to [`MAX_AUX_GIDS`] at encode time.
    #[must_use]
    pub fn with_groups(uid: u32, gid: u32, gids: &[u32], hostname: &str) -> Self {
        let truncated = gids.get(..MAX_AUX_GIDS).unwrap_or(gids);
        Self { machinename: hostname.to_owned(), uid, gid, gids: truncated.to_vec() }
    }

    /// Encode as an [`opaque_auth`] carrying the given stamp.
    ///
    /// The stamp is an arbitrary caller-chosen value (RFC 1057 sec. 9.2). Some
    /// servers key a duplicate-request cache on it, so a caller issuing many
    /// calls under different identities should vary it -- otherwise the server
    /// may answer a later call from a cached earlier reply. This function takes
    /// the stamp rather than generating one so that policy stays with the
    /// caller and encoding stays deterministic for tests.
    #[must_use]
    pub fn to_opaque_auth(&self, stamp: u32) -> opaque_auth<'static> {
        let gids = self.gids.get(..MAX_AUX_GIDS).unwrap_or(&self.gids);
        let auth = auth_unix { stamp, machinename: Opaque::owned(self.machinename.as_bytes().to_vec()), uid: self.uid, gid: self.gid, gids: gids.to_vec() };
        opaque_auth::auth_unix(&auth)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kerberos_pseudo_flavors_classify_as_gss() {
        for v in [6_u32, 390_003, 390_004, 390_005] {
            assert_eq!(AuthFlavor::from_u32(v), AuthFlavor::Gss, "flavor {v}");
            assert!(AuthFlavor::from_u32(v).is_authenticated());
        }
    }

    #[test]
    fn auth_sys_is_not_authenticated() {
        assert!(!AuthFlavor::Sys.is_authenticated());
        assert!(!AuthFlavor::None.is_authenticated());
    }

    #[test]
    fn with_groups_truncates_to_the_rfc_limit() {
        let many: Vec<u32> = (0..40).collect();
        let cred = AuthSys::with_groups(1000, 1000, &many, "host");
        assert_eq!(cred.gids.len(), MAX_AUX_GIDS);
    }

    #[test]
    fn encoding_is_deterministic_for_a_given_stamp() {
        use nfswolf_xdr::Pack as _;
        let cred = AuthSys::new(0, 0, "host");
        let (mut a, mut b) = (Vec::new(), Vec::new());
        let _ = cred.to_opaque_auth(42).pack(&mut a).expect("pack");
        let _ = cred.to_opaque_auth(42).pack(&mut b).expect("pack");
        assert_eq!(a, b);
        let mut c = Vec::new();
        let _ = cred.to_opaque_auth(43).pack(&mut c).expect("pack");
        assert_ne!(a, c, "stamp must reach the wire");
    }
}
