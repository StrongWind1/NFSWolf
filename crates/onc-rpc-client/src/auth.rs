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

use onc_xdr::Opaque;

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
#[non_exhaustive]
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
    /// `AUTH_TLS` -- RFC 9289 STARTTLS probe for RPC-with-TLS.
    Tls = 7,
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
            6 | 390_000 | 390_003..=390_005 => Self::Gss,
            7 => Self::Tls,
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

    /// Create a credential with supplementary groups.
    ///
    /// `gid` is included in the group list whether or not `gids` already
    /// contains it. A server checking group ownership reads the list rather
    /// than the `gid` field, so a credential whose list omits its own primary
    /// group silently loses group access -- and callers passing an empty slice
    /// to mean "just my primary group" would get no groups at all. Two call
    /// sites in this workspace had grown their own prepend to work around
    /// that; the invariant belongs here instead.
    ///
    /// The list is truncated to [`MAX_AUX_GIDS`] (RFC 5531 sec. 14).
    #[must_use]
    pub fn with_groups(uid: u32, gid: u32, gids: &[u32], hostname: &str) -> Self {
        let mut list = Vec::with_capacity(gids.len() + 1);
        list.push(gid);
        list.extend(gids.iter().copied().filter(|g| *g != gid));
        list.truncate(MAX_AUX_GIDS);
        Self { machinename: hostname.to_owned(), uid, gid, gids: list }
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
        let many: Vec<u32> = (100..140).collect();
        let cred = AuthSys::with_groups(1000, 1000, &many, "host");
        assert_eq!(cred.gids.len(), MAX_AUX_GIDS);
    }

    #[test]
    fn root_has_uid_and_gid_zero() {
        let cred = AuthSys::root("host");
        assert_eq!(cred.uid, 0);
        assert_eq!(cred.gid, 0);
    }

    #[test]
    fn new_includes_the_primary_gid_in_the_group_list() {
        // A server checking group ownership reads the gids list, not just gid,
        // so omitting the primary group would silently lose group access.
        let cred = AuthSys::new(1000, 500, "host");
        assert!(cred.gids.contains(&500), "primary gid missing from gids: {:?}", cred.gids);
    }

    #[test]
    fn with_groups_preserves_the_supplied_list() {
        let cred = AuthSys::with_groups(1000, 100, &[100, 42, 27], "host");
        assert_eq!(cred.gids, vec![100, 42, 27], "primary gid first, no duplicate");
    }

    #[test]
    fn with_groups_always_includes_the_primary_gid() {
        // An empty slice must not produce an empty group list: a server
        // resolving group access from the list would deny access the caller
        // legitimately has.
        let cred = AuthSys::with_groups(1000, 500, &[], "host");
        assert_eq!(cred.gids, vec![500]);

        // And it must appear even when the caller supplied other groups.
        let cred = AuthSys::with_groups(1000, 500, &[42], "host");
        assert!(cred.gids.contains(&500), "primary gid missing: {:?}", cred.gids);
    }

    #[test]
    fn encoded_body_is_non_empty_and_carries_the_identity() {
        use onc_xdr::Pack as _;
        let mut buf = Vec::new();
        let _ = AuthSys::new(1000, 1000, "host").to_opaque_auth(42).pack(&mut buf).expect("pack");
        assert!(!buf.is_empty(), "an empty credential body would authenticate as nobody");
        // uid 1000 == 0x3E8 must appear big-endian in the encoded body.
        assert!(buf.windows(4).any(|w| w == 1000_u32.to_be_bytes()), "uid not found in encoded credential");
    }

    #[test]
    fn encoding_is_deterministic_for_a_given_stamp() {
        use onc_xdr::Pack as _;
        let cred = AuthSys::new(0, 0, "host");
        let (mut a, mut b) = (Vec::new(), Vec::new());
        let _ = cred.to_opaque_auth(42).pack(&mut a).expect("pack");
        let _ = cred.to_opaque_auth(42).pack(&mut b).expect("pack");
        assert_eq!(a, b);
        let mut c = Vec::new();
        let _ = cred.to_opaque_auth(43).pack(&mut c).expect("pack");
        assert_ne!(a, c, "stamp must reach the wire");
    }

    // --- AuthFlavor::from_u32 coverage ---

    /// AUTH_NULL=0, AUTH_SYS=1, AUTH_SHORT=2, AUTH_DH=3 per RFC 5531 sec 8.2.
    #[test]
    fn auth_flavor_from_u32_covers_all_base_flavors() {
        assert_eq!(AuthFlavor::from_u32(0), AuthFlavor::None);
        assert_eq!(AuthFlavor::from_u32(1), AuthFlavor::Sys);
        assert_eq!(AuthFlavor::from_u32(2), AuthFlavor::Short);
        assert_eq!(AuthFlavor::from_u32(3), AuthFlavor::Dh);
        assert_eq!(AuthFlavor::from_u32(6), AuthFlavor::Gss);
    }

    /// RFC 2623 sec 2.1.1 defines Kerberos pseudo-flavors 390003-390005
    /// (krb5, krb5i, krb5p). They must all map to Gss.
    #[test]
    fn auth_flavor_kerberos_pseudo_flavors_390003_through_390005() {
        assert_eq!(AuthFlavor::from_u32(390_003), AuthFlavor::Gss);
        assert_eq!(AuthFlavor::from_u32(390_004), AuthFlavor::Gss);
        assert_eq!(AuthFlavor::from_u32(390_005), AuthFlavor::Gss);
    }

    #[test]
    fn auth_flavor_unknown_for_unrecognized_values() {
        for v in [4_u32, 5, 8, 100, 390_002, 390_006, u32::MAX] {
            assert_eq!(AuthFlavor::from_u32(v), AuthFlavor::Unknown, "flavor {v} should be Unknown");
        }
    }

    // --- AuthSys encoding details ---

    /// RFC 1057 sec 9.2: the stamp is the first four bytes of the
    /// auth_unix body ("unsigned int stamp").
    #[test]
    fn auth_sys_stamp_is_first_four_bytes_of_body() {
        use onc_xdr::{Pack as _, Unpack as _};
        let cred = AuthSys::new(0, 0, "test");
        let auth = cred.to_opaque_auth(0xDEAD_BEEF);
        // Pack the opaque_auth to get the full wire encoding.
        let mut buf = Vec::new();
        let _ = auth.pack(&mut buf).expect("pack");
        // The opaque_auth is: flavor(4) + body_len(4) + body(...)
        // The body starts at offset 8. The stamp is the first u32 inside.
        let body_start = 8;
        let mut cursor = std::io::Cursor::new(&buf[body_start..]);
        let (stamp, _) = u32::unpack(&mut cursor).expect("unpack stamp");
        assert_eq!(stamp, 0xDEAD_BEEF);
    }

    /// The machinename field from AuthSys must appear in the encoded body.
    #[test]
    fn auth_sys_machinename_appears_in_encoded_body() {
        use onc_xdr::Pack as _;
        let cred = AuthSys::new(0, 0, "myhost.example.com");
        let auth = cred.to_opaque_auth(1);
        let mut buf = Vec::new();
        let _ = auth.pack(&mut buf).expect("pack");
        // The machinename is XDR-encoded as a length-prefixed opaque.
        // The string bytes must appear somewhere in the body.
        assert!(buf.windows(b"myhost.example.com".len()).any(|w| w == b"myhost.example.com"), "machinename not found in encoded credential");
    }

    /// RFC 5531 sec 14: "The groups array should not exceed 16 in size."
    #[test]
    fn max_aux_gids_matches_rfc_5531_sec_14() {
        assert_eq!(MAX_AUX_GIDS, 16);
    }

    /// Verify that with_groups deduplicates the primary GID rather than
    /// double-counting it (which would waste a slot in the 16-entry limit).
    #[test]
    fn with_groups_deduplicates_primary_gid() {
        let cred = AuthSys::with_groups(1000, 42, &[42, 100, 200], "host");
        // 42 should appear exactly once despite being both the primary GID
        // and first in the supplied list.
        assert_eq!(cred.gids.iter().filter(|&&g| g == 42).count(), 1);
        assert_eq!(cred.gids, vec![42, 100, 200]);
    }

    /// Verify the encoded auth_unix body round-trips through unpack.
    #[test]
    fn auth_sys_to_opaque_auth_body_round_trips() {
        use crate::rpc::auth_unix;
        use onc_xdr::{Pack as _, Unpack as _};

        let cred = AuthSys::with_groups(1000, 500, &[500, 42, 27], "scanner");
        let auth = cred.to_opaque_auth(77);

        // Extract just the body bytes and unpack as auth_unix.
        let mut full_buf = Vec::new();
        let _ = auth.pack(&mut full_buf).expect("pack");
        // opaque_auth: flavor(4) + body_len(4) + body(N)
        let body_len = u32::from_be_bytes(full_buf[4..8].try_into().unwrap()) as usize;
        let body_bytes = &full_buf[8..8 + body_len];

        let mut cursor = std::io::Cursor::new(body_bytes);
        let (decoded, consumed) = auth_unix::unpack(&mut cursor).expect("unpack auth_unix");
        assert_eq!(consumed, body_len);
        assert_eq!(decoded.stamp, 77);
        assert_eq!(decoded.uid, 1000);
        assert_eq!(decoded.gid, 500);
        assert_eq!(decoded.machinename.as_ref(), b"scanner");
        assert_eq!(decoded.gids, vec![500, 42, 27]);
    }
}
