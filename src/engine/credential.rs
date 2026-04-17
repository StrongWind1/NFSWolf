//! Identity management for NFS operations.
//!
//! Manages UID/GID switching for automatic impersonation.

// Struct fields are UID/GID configuration values; individual docs would repeat the name.
// Toolkit API  --  not all items are used in currently-implemented phases.
use crate::proto::auth::{AuthSys, Credential};

/// Credential manager  --  handles identity switching for auto-UID mode.
#[derive(Debug)]
pub struct CredentialManager {
    /// Default credential to use when not impersonating
    default: AuthSys,
    /// Whether auto-UID mode is enabled
    auto_uid: bool,
    /// Whether root impersonation is allowed (requires no_root_squash)
    allow_root: bool,
    /// Auxiliary GIDs injected into every AUTH_SYS credential.
    /// AUTH_SYS supports up to 16 auxiliary groups  --  filling
    /// these enables access to files that use secondary group
    /// ownership (e.g., `shadow`, `docker`, `adm`).
    auxiliary_gids: Vec<u32>,
}

impl CredentialManager {
    pub fn new(uid: u32, gid: u32, hostname: &str) -> Self {
        Self { default: AuthSys::new(uid, gid, hostname), auto_uid: false, allow_root: false, auxiliary_gids: Vec::new() }
    }

    #[must_use]
    pub fn with_auxiliary_gids(mut self, gids: Vec<u32>) -> Self {
        self.auxiliary_gids = gids;
        self
    }

    #[must_use]
    pub const fn with_auto_uid(mut self) -> Self {
        self.auto_uid = true;
        self
    }

    #[must_use]
    pub const fn with_allow_root(mut self) -> Self {
        self.allow_root = true;
        self
    }

    /// Get the credential to use for accessing a file with given ownership.
    pub fn credential_for(&self, file_uid: u32, file_gid: u32) -> Credential {
        if !self.auto_uid {
            return Credential::Sys(self.default.clone());
        }

        // Don't impersonate root unless explicitly allowed
        if file_uid == 0 && !self.allow_root {
            // Try using the GID if it's non-zero
            if file_gid != 0 {
                return Credential::Sys(AuthSys::with_groups(self.default.uid, file_gid, &[file_gid], &self.default.machinename));
            }
            return Credential::Sys(self.default.clone());
        }

        // Merge the file's GID with auxiliary GIDs (AUTH_SYS max 16)
        let mut gids = vec![file_gid];
        for &g in &self.auxiliary_gids {
            if gids.len() >= 16 {
                break;
            }
            if !gids.contains(&g) {
                gids.push(g);
            }
        }
        Credential::Sys(AuthSys::with_groups(file_uid, file_gid, &gids, &self.default.machinename))
    }

    /// Get the default credential.
    pub fn default_credential(&self) -> Credential {
        Credential::Sys(self.default.clone())
    }
}

/// Build the credential escalation ladder for a failed NFS operation.
///
/// `caller` is the (uid, gid) that was rejected.
/// `owner` is the file/directory owner from GETATTR, if available.
///
/// Priority:
///   1. (owner_uid, owner_gid)  -- file owner; works on uid-protected files
///   2. (caller_uid, owner_gid) -- caller claiming the file group; works for
///      group-readable files when root is squashed (e.g. chrony gid=989)
///   3. (0, 0)                  -- root, works when export has no_root_squash
///   4. Common service UIDs (nobody, 1000, www-data, mysql, postgres)
///
/// Used by the shell (ls, cd, cat) and attack modules (read, lookup) so
/// every NFS operation gets the same automatic privilege escalation.
pub fn escalation_list(caller: (u32, u32), owner: Option<(u32, u32)>) -> Vec<(u32, u32)> {
    let (caller_uid, caller_gid) = caller;
    let mut list = Vec::with_capacity(14);
    if let Some((owner_uid, owner_gid)) = owner {
        list.push((owner_uid, owner_gid));
        if owner_gid != caller_gid {
            list.push((caller_uid, owner_gid));
        }
    }
    list.push((0, 0));
    list.push((65534, 65534));
    list.push((1000, 1000));
    list.push((33, 33)); // www-data
    list.push((27, 27)); // mysql
    list.push((26, 26)); // postgres
    list.push((1001, 1001));
    list.push((1002, 1002));
    list.dedup();
    list
}
