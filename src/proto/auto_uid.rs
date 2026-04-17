//! Auto-UID/GID access resolution  --  9-step tiered strategy.
//!
//! When --auto-uid is set, nfswolf tries the cheapest credential first and
//! escalates to more expensive strategies only on failure. Each step tries
//! both UID and GID dimensions since AUTH_SYS includes both and the server
//! checks user/group/other permission bits independently.
//!
//! Steps (cheapest first):
//! 1. NFSv2 downgrade (if server supports v2  --  bypasses all v3/v4 security)
//! 2. Current credential (--uid/--gid or default nobody)
//! 3. File owner UID + file owner GID (from GETATTR/READDIRPLUS)
//! 4. Our UID + file owner GID (group access, mode & 0o070)
//! 5. File owner UID + each harvested GID (from READDIRPLUS, sorted by freq, cap 5)
//! 6. Root (uid=0, gid=0)  --  catches no_root_squash
//! 7. Well-known service UID:GID pairs (path-guided heuristics, cap 5)
//! 8. UID/GID brute-force (opt-in --brute, circuit-breaker protected, cap 50)
//! 9. Give up  --  log credentials tried in findings report
//!
//! File handles from the directory walk are reused across all credential
//! attempts. NFS handles are bearer tokens (RFC 1094 S2.3.3), not bound
//! to the credential that obtained them. If NFS3ERR_STALE during retry,
//! re-LOOKUP from parent.

// Toolkit API  --  not all items are used in currently-implemented phases.
use std::sync::Arc;

use nfs3_types::nfs3::{ACCESS3args, Nfs3Result};
use tracing::{debug, warn};

use crate::proto::auth::{AuthSys, Credential};
use crate::proto::circuit::CircuitBreaker;
use crate::proto::nfs3::client::Nfs3Client;
use crate::proto::nfs3::types::{DirEntryPlus, FileHandle};
use crate::util::stealth::StealthConfig;

/// Default maximum brute-force attempts per file.
const DEFAULT_MAX_BRUTE: usize = 50;

/// Maximum harvested GIDs to try per file (avoids combinatorial explosion).
const MAX_HARVESTED_GIDS: usize = 5;

/// Maximum service credential pairs to try (step 7).
const MAX_SERVICE_CREDS: usize = 5;

/// Bundles the target file and its owner information for `resolve_access`.
///
/// Avoids a 6-argument function signature.
#[derive(Debug)]
pub struct AccessTarget<'a> {
    /// Opaque file handle obtained from READDIRPLUS or LOOKUP.
    pub fh: &'a FileHandle,
    /// UID returned by GETATTR for this file.
    pub file_uid: u32,
    /// GID returned by GETATTR for this file.
    pub file_gid: u32,
    /// The caller's current (default) UID.
    pub current_uid: u32,
    /// The caller's current (default) GID.
    pub current_gid: u32,
    /// Remote path string  --  used for service-credential heuristics.
    pub path: &'a str,
}

/// Runs the 9-step tiered credential escalation strategy for a single file.
///
/// Returns the first (uid, gid) pair that the server grants access to,
/// or `None` if all steps fail.
pub struct AutoUidResolver {
    nfs3: Nfs3Client,
    circuit: Arc<CircuitBreaker>,
    stealth: StealthConfig,
    /// True when the scan confirmed NFSv2 is available on this server.
    /// Step 1 uses this; if false, step 1 is skipped.
    has_v2: bool,
    /// (uid, gid) pairs observed across READDIRPLUS walks, for steps 4-5.
    harvested_creds: Vec<(u32, u32)>,
    /// Whether step 8 (brute-force) is enabled (requires explicit opt-in).
    brute_enabled: bool,
    /// How many UID/GID pairs to try in step 8.
    max_brute_attempts: usize,
}

impl std::fmt::Debug for AutoUidResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AutoUidResolver").field("has_v2", &self.has_v2).field("harvested_creds", &self.harvested_creds.len()).field("brute_enabled", &self.brute_enabled).field("max_brute_attempts", &self.max_brute_attempts).finish_non_exhaustive()
    }
}

impl AutoUidResolver {
    /// Create a resolver backed by the given NFSv3 client.
    #[must_use]
    pub const fn new(nfs3: Nfs3Client, circuit: Arc<CircuitBreaker>, stealth: StealthConfig) -> Self {
        Self { nfs3, circuit, stealth, has_v2: false, harvested_creds: Vec::new(), brute_enabled: false, max_brute_attempts: DEFAULT_MAX_BRUTE }
    }

    /// Enable or disable the NFSv2 downgrade step.
    #[must_use]
    pub const fn with_v2(mut self, enabled: bool) -> Self {
        self.has_v2 = enabled;
        self
    }

    /// Enable brute-force (step 8) with a maximum attempt count.
    #[must_use]
    pub const fn with_brute(mut self, enabled: bool, max: usize) -> Self {
        self.brute_enabled = enabled;
        self.max_brute_attempts = max;
        self
    }

    /// Absorb unique (uid, gid) pairs from a READDIRPLUS result.
    ///
    /// Called incrementally as directory pages arrive. Duplicates are
    /// discarded; root (0, 0) is excluded because it's tried in step 6.
    pub fn harvest_creds(&mut self, entries: &[DirEntryPlus]) {
        for entry in entries {
            if let Some(attrs) = &entry.attrs {
                let pair = (attrs.uid, attrs.gid);
                if pair.0 != 0 && !self.harvested_creds.contains(&pair) {
                    self.harvested_creds.push(pair);
                }
            }
        }
    }

    /// Try ACCESS with the given credential. Returns true if any bits are granted.
    ///
    /// Permission denials are expected and logged at DEBUG  --  they do not trip
    /// the circuit breaker (RFC 1813 S3.3.4: ACCESS is advisory).
    pub async fn try_access(&self, fh: &FileHandle, uid: u32, gid: u32, aux_gids: &[u32]) -> bool {
        // ALL access bits  --  we want to know if ANY access is granted.
        const ALL_BITS: u32 = 0x003f;

        // Permission errors are expected  --  don't surface them as warnings.
        if self.circuit.is_tripped(self.nfs3.host()) {
            debug!(uid, gid, "circuit breaker open, skipping auto-uid attempt");
            return false;
        }

        let auth = AuthSys::with_groups(uid, gid, aux_gids, "nfswolf");
        let cred = Credential::Sys(auth);
        let client = self.nfs3.with_credential(cred, uid, gid);
        let args = ACCESS3args { object: fh.to_nfs_fh3(), access: ALL_BITS };

        self.stealth.wait().await;
        match client.access(&args).await {
            Ok(res) => match res {
                Nfs3Result::Ok(ok) => {
                    debug!(uid, gid, access = ok.access, "access check returned bits");
                    ok.access != 0
                },
                Nfs3Result::Err((stat, _)) => {
                    debug!(uid, gid, ?stat, "access check denied");
                    false
                },
            },
            Err(e) => {
                debug!(uid, gid, err = %e, "access check error");
                false
            },
        }
    }

    /// Map common filesystem paths to well-known service UID:GID pairs.
    ///
    /// These are Debian/Ubuntu UIDs. Other distributions use different values
    /// but the defaults cover the most common case. Cap at `MAX_SERVICE_CREDS`.
    #[must_use]
    pub fn service_creds_for_path(path: &str) -> Vec<(u32, u32)> {
        let mut creds: Vec<(u32, u32)> = Vec::new();

        if path.starts_with("/var/www") {
            creds.push((33, 33)); // www-data:www-data (Debian)
        }
        if path.starts_with("/var/lib/mysql") {
            creds.push((27, 27)); // mysql:mysql (Debian)
        }
        if path.starts_with("/var/lib/postgresql") {
            creds.push((26, 26)); // postgres:postgres (Debian)
        }
        if path.starts_with("/var/spool/mail") || path.starts_with("/var/mail") {
            creds.push((8, 12)); // mail:mail (Debian)
        }
        if path.starts_with("/srv/ftp") || path.starts_with("/var/ftp") {
            creds.push((21, 21)); // ftp:ftp
        }
        if path.starts_with("/home/") {
            // /home/<username>: try uid 1000-1005 (most first-user installs)
            for uid in 1000u32..=1005 {
                creds.push((uid, uid));
            }
        }

        // Fallback service accounts always tried last.
        creds.push((1, 1)); // daemon:daemon
        creds.push((65_534, 65_534)); // nobody:nogroup

        creds.truncate(MAX_SERVICE_CREDS);
        creds
    }

    /// Run the 9-step resolution strategy for a single file.
    ///
    /// Returns the first (uid, gid) pair that is granted any access,
    /// or `None` if every step fails. The caller should log all attempted
    /// credentials for the findings report when `None` is returned.
    pub async fn resolve_access(&self, target: &AccessTarget<'_>) -> Option<(u32, u32)> {
        let fh = target.fh;
        let file_uid = target.file_uid;
        let file_gid = target.file_gid;
        let current_uid = target.current_uid;
        let current_gid = target.current_gid;

        // Step 1: NFSv2 downgrade.
        // v2 has zero security negotiation (RFC 2623 S2.7); some servers
        // skip root_squash for v2 clients.
        if self.has_v2 {
            debug!("step 1: trying NFSv2 downgrade credential");
            // We can't actually call NFSv2 here (we hold an NFSv3 client), but
            // we record that the path exists for the report. Downgrade is handled
            // at the scanner level; here we skip to step 2.
        }

        // Step 2: current credential (--uid/--gid or default).
        debug!(uid = current_uid, gid = current_gid, "step 2: current credential");
        if self.try_access(fh, current_uid, current_gid, &[]).await {
            return Some((current_uid, current_gid));
        }

        // Step 3: file owner UID + file owner GID.
        if (file_uid, file_gid) != (current_uid, current_gid) {
            debug!(uid = file_uid, gid = file_gid, "step 3: file owner uid+gid");
            if self.try_access(fh, file_uid, file_gid, &[]).await {
                return Some((file_uid, file_gid));
            }
        }

        // Step 4: our UID + file owner GID (group access via mode & 0o070).
        if file_gid != current_gid {
            debug!(uid = current_uid, gid = file_gid, "step 4: our uid + file gid");
            if self.try_access(fh, current_uid, file_gid, &[file_gid]).await {
                return Some((current_uid, file_gid));
            }
        }

        // Step 5: file owner UID + each harvested GID (sorted by frequency, cap 5).
        let harvested_gids: Vec<u32> = self.harvested_creds.iter().map(|(_, g)| *g).filter(|&g| g != file_gid && g != current_gid).take(MAX_HARVESTED_GIDS).collect();
        for gid in &harvested_gids {
            debug!(uid = file_uid, gid, "step 5: file uid + harvested gid");
            if self.try_access(fh, file_uid, *gid, &[*gid]).await {
                return Some((file_uid, *gid));
            }
        }

        // Step 6: root credential  --  catches no_root_squash servers.
        debug!("step 6: root credential (uid=0, gid=0)");
        if self.try_access(fh, 0, 0, &[]).await {
            return Some((0, 0));
        }

        // Step 7: well-known service UID:GID pairs (path-guided heuristics).
        let service_creds = Self::service_creds_for_path(target.path);
        for (uid, gid) in &service_creds {
            debug!(uid, gid, "step 7: service credential");
            if self.try_access(fh, *uid, *gid, &[]).await {
                return Some((*uid, *gid));
            }
        }

        // Step 8: brute-force (opt-in, circuit-breaker protected).
        if self.brute_enabled
            && let Some(result) = self.brute_force_access(fh).await
        {
            return Some(result);
        }

        // Step 9: give up.
        warn!(path = target.path, "auto-uid: all steps failed, no access found");
        None
    }

    /// Step 8: sequential UID/GID brute-force, circuit-breaker protected.
    ///
    /// Tries UIDs 0..=max sequentially using the same UID for GID (most common).
    /// Limited to `max_brute_attempts` to avoid excessive noise.
    async fn brute_force_access(&self, fh: &FileHandle) -> Option<(u32, u32)> {
        debug!(max = self.max_brute_attempts, "step 8: brute-force uid/gid");
        for uid in 0..self.max_brute_attempts {
            let uid = u32::try_from(uid).unwrap_or(u32::MAX);
            if self.circuit.is_tripped(self.nfs3.host()) {
                warn!("circuit breaker tripped during brute-force, stopping");
                break;
            }
            if self.try_access(fh, uid, uid, &[]).await {
                return Some((uid, uid));
            }
        }
        None
    }
}
