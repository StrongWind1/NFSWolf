//! AUTH_SYS stamp injection  --  wraps nfs3-rs auth_unix.
//!
//! nfs3-rs provides the `auth_unix` struct and `opaque_auth::auth_unix()` encoder.
//! We add a global atomic stamp counter (starting at 42, incremented per encode)
//! to defeat duplicate-request caching during UID spraying (RFC 1057 S9.2).

// Struct fields are AUTH_SYS wire values; individual docs would repeat the name.
// Toolkit API  --  not all items are used in currently-implemented phases.
use std::sync::atomic::{AtomicU32, Ordering};

use nfs3_types::rpc::{auth_unix, opaque_auth};
use nfs3_types::xdr_codec::Opaque;

/// Global stamp counter  --  incremented per AUTH_SYS request.
///
/// Some NFS servers cache responses keyed by (uid, gid, stamp). Using the same
/// stamp across requests with different UIDs can return stale/cached results.
/// Incrementing the stamp on every credential encode avoids this.
/// Technique from nfs_analyze.
static STAMP_COUNTER: AtomicU32 = AtomicU32::new(42);

/// Authentication flavor identifiers (RFC 5531 S8.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum AuthFlavor {
    None = 0,
    Sys = 1, // AUTH_UNIX / AUTH_SYS
    Short = 2,
    Dh = 3,
    Gss = 6,       // RPCSEC_GSS (Kerberos)
    Unknown = 255, // Unrecognized flavor (e.g., vendor-specific GSS sub-mechanisms)
}

/// nfswolf credential  --  wraps nfs3-rs auth_unix with stamp injection.
#[derive(Debug, Clone)]
pub enum Credential {
    /// No authentication.
    None,

    /// AUTH_SYS: client-supplied UID/GID (the core of NFSv3 insecurity).
    Sys(AuthSys),
}

/// AUTH_SYS credential  --  the attackable heart of NFSv3.
///
/// The server trusts these values without verification.
/// Changing uid/gid is all it takes to impersonate any user.
#[derive(Debug, Clone)]
pub struct AuthSys {
    /// Client hostname (spoofable, used for logging only).
    pub machinename: String,
    /// Effective UID  --  the identity the server will use for permission checks.
    pub uid: u32,
    /// Effective GID  --  primary group for permission checks.
    pub gid: u32,
    /// Auxiliary GIDs (max 16)  --  additional group memberships.
    pub gids: Vec<u32>,
}

impl AuthSys {
    /// Create a new AUTH_SYS credential with specified identity.
    pub fn new(uid: u32, gid: u32, hostname: &str) -> Self {
        Self { machinename: hostname.to_owned(), uid, gid, gids: vec![gid] }
    }

    /// Create a root credential (uid=0, gid=0).
    pub fn root(hostname: &str) -> Self {
        Self::new(0, 0, hostname)
    }

    /// Create credential for a specific user, with auxiliary groups.
    ///
    /// Truncates to 16 GIDs  --  the AUTH_SYS maximum (RFC 5531 section 14).
    pub fn with_groups(uid: u32, gid: u32, gids: &[u32], hostname: &str) -> Self {
        let truncated = gids.get(..16).unwrap_or(gids);
        Self { machinename: hostname.to_owned(), uid, gid, gids: truncated.to_vec() }
    }

    /// Convert to nfs3-rs `opaque_auth` with auto-incremented stamp.
    ///
    /// The counter wraps back to 42 (not 0) at `u32::MAX` so the stamp never
    /// collides with values 0-41 which may be used by other clients and their
    /// duplicate-request caches (RFC 1057 section 9.2).
    pub fn to_opaque_auth(&self) -> opaque_auth<'static> {
        let stamp = next_stamp();
        // AUTH_SYS allows at most 16 auxiliary GIDs (RFC 5531 S14).
        let gids = self.gids.get(..16).unwrap_or(&self.gids);
        let auth = auth_unix { stamp, machinename: Opaque::owned(self.machinename.as_bytes().to_vec()), uid: self.uid, gid: self.gid, gids: gids.to_vec() };
        opaque_auth::auth_unix(&auth)
    }
}

/// Stamp start value (also used as the wrap floor).
const STAMP_START: u32 = 42;

/// Fetch the next stamp value, wrapping back to `STAMP_START` at `u32::MAX`.
fn next_stamp() -> u32 {
    // Compare-and-swap loop keeps the wrap atomic without introducing a mutex.
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
    fn authsys_stamps_are_unique_across_calls() {
        // Each to_opaque_auth() call must consume a new stamp from the global counter.
        // Reused stamps cause duplicate-request-cache hits during UID spraying (RFC 1057 S9.2).
        let cred = AuthSys::new(1000, 1000, "testhost");
        let auth1 = cred.to_opaque_auth();
        let auth2 = cred.to_opaque_auth();
        // The opaque_auth blobs must differ (different stamp embedded in XDR body).
        assert_ne!(auth1.body.as_ref(), auth2.body.as_ref(), "consecutive stamps must differ");
    }

    #[test]
    fn authsys_root_has_uid_zero() {
        let cred = AuthSys::root("scanner");
        assert_eq!(cred.uid, 0);
        assert_eq!(cred.gid, 0);
    }

    #[test]
    fn authsys_with_groups_stores_aux_gids() {
        let cred = AuthSys::with_groups(501, 501, &[20, 80, 501], "host");
        assert_eq!(cred.uid, 501);
        assert_eq!(cred.gids, &[20, 80, 501]);
    }

    #[test]
    fn credential_none_variant() {
        let c = Credential::None;
        assert!(matches!(c, Credential::None));
    }

    #[test]
    fn authsys_with_groups_truncates_at_16_gids() {
        let many_gids: Vec<u32> = (0..32).collect();
        let cred = AuthSys::with_groups(1000, 1000, &many_gids, "host");
        assert_eq!(cred.gids.len(), 16, "AUTH_SYS allows at most 16 auxiliary GIDs");
    }

    #[test]
    fn authsys_new_includes_primary_gid_in_gids() {
        let cred = AuthSys::new(1000, 500, "host");
        assert!(cred.gids.contains(&500), "primary gid must appear in gids vec");
    }

    #[test]
    fn stamp_counter_monotonically_increasing() {
        // Call to_opaque_auth 100 times and verify all bodies are distinct.
        let cred = AuthSys::new(0, 0, "test");
        let mut bodies = std::collections::HashSet::new();
        for _ in 0..100 {
            let auth = cred.to_opaque_auth();
            let body = auth.body.as_ref().to_vec();
            bodies.insert(body);
        }
        assert_eq!(bodies.len(), 100, "100 consecutive stamps must all be unique");
    }

    #[test]
    fn auth_flavor_unknown_variant_has_value_255() {
        assert_eq!(AuthFlavor::Unknown as u32, 255);
    }

    #[test]
    fn credential_sys_wraps_authsys() {
        let auth = AuthSys::new(42, 42, "scanner");
        let cred = Credential::Sys(auth);
        let Credential::Sys(ref inner) = cred else {
            unreachable!("just constructed Credential::Sys");
        };
        assert_eq!(inner.uid, 42);
        assert_eq!(inner.gid, 42);
    }

    #[test]
    fn to_opaque_auth_body_is_non_empty() {
        let cred = AuthSys::new(0, 0, "x");
        let auth = cred.to_opaque_auth();
        assert!(!auth.body.as_ref().is_empty(), "opaque_auth body must contain XDR-encoded AUTH_SYS data");
    }
}
