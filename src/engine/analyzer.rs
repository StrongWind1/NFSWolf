//! Security analysis engine.
//!
//! Performs deep security checks against a single NFS server,
//! detecting all 23 documented vulnerability classes.
//!
//! File access tests are generic  --  the caller specifies which paths
//! to test and which UIDs/GIDs to try. Shadow GID defaults (42, 15)
//! are provided as constants for convenience but not hardcoded into
//! the check logic.

// Struct fields and enum variants are domain result types  --  individual docs
// would repeat the field name. See finding IDs in docs/FINDINGS.md.
// Toolkit API  --  not all items are used in currently-implemented phases.
use serde::{Deserialize, Serialize};

/// Name of the temporary file the squash probes create and remove.
///
/// Dot-prefixed so it is inconspicuous in a listing if cleanup fails.
const PROBE_NAME: &str = ".nfswolf_squash_probe";

/// Well-known anonuid values that indicate misconfiguration.
pub(crate) const ANON_UID_ROOT: u32 = 0;
pub(crate) const ANON_UID_NOBODY: u32 = 65534;

/// Security finding from analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct Finding {
    pub id: String,
    pub title: String,
    pub severity: Severity,
    pub description: String,
    pub evidence: String,
    pub remediation: String,
    pub export: Option<String>,
}

/// Finding severity levels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

/// Complete analysis result for a host.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct AnalysisResult {
    pub host: String,
    pub timestamp: String,
    pub os_guess: Option<String>,
    /// Server implementation fingerprint from null-filename LOOKUP probe.
    ///
    /// RFC 1813 sec. 3.3.3 requires NFS3ERR_ACCES for a zero-length filename,
    /// but Linux knfsd rejects it at the XDR layer with RPC GARBAGE_ARGS.
    /// The divergence is a cheap, unauthenticated implementation discriminator.
    pub impl_fingerprint: Option<String>,
    pub nfs_versions: Vec<String>,
    pub exports: Vec<ExportAnalysis>,
    pub findings: Vec<Finding>,
}

/// Analysis of a single export.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct ExportAnalysis {
    pub path: String,
    pub allowed_hosts: Vec<String>,
    pub auth_methods: Vec<String>,
    pub writable: bool,
    pub no_root_squash: Option<bool>,
    pub escape_possible: bool,
    pub file_handle: String,
    /// Generic file access test results  --  replaces the old
    /// `shadow_readable: bool` with a test for any file/cred combo.
    pub file_access_tests: Vec<FileAccessTest>,
    /// NFSv4/4.1 ACL entries.
    pub nfs4_acls: Vec<Nfs4Ace>,
}

/// Result of testing whether a specific file is readable with specific credentials.
///
/// This is the generic replacement for the old hardcoded "shadow_readable" check.
/// The analyzer runs one test per (path, uid, gid) combination the user requested.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct FileAccessTest {
    /// Path that was tested (e.g., "/etc/shadow", "/etc/passwd")
    pub path: String,
    /// UID used for the test
    pub uid: u32,
    /// GID used for the test
    pub gid: u32,
    /// Whether the file was readable with these credentials
    pub readable: bool,
    /// First bytes of file content (truncated) as evidence, if readable
    pub preview: Option<String>,
    /// Whether escape was required to reach this path
    pub via_escape: bool,
}

/// Metadata harvested from an NFS3ERR_ACCES or NFS3ERR_PERM denial response.
///
/// Linux knfsd populates `post_op_attr` in error responses (fs/nfsd/nfs3xdr.c).
/// RFC 1813 sec. 3.3 "strongly encourages" servers to return as much attribute
/// data as possible on failure, so servers routinely disclose uid, gid, size,
/// mode, and timestamps for files the caller cannot access. This feeds the
/// credential ladder: knowing the file owner lets the attacker craft a targeted
/// AUTH_SYS credential instead of brute-forcing.
struct LeakedMetadata {
    /// Which NFS operation leaked the metadata (e.g. "LOOKUP", "READ").
    operation: &'static str,
    /// Path or component that triggered the denial.
    path: String,
    /// Owner UID from the leaked `post_op_attr`.
    uid: u32,
    /// Owner GID from the leaked `post_op_attr`.
    gid: u32,
    /// File size in bytes from the leaked `post_op_attr`.
    size: u64,
    /// POSIX permission mode bits from the leaked `post_op_attr`.
    mode: u32,
}

/// A single NFSv4 access control entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct Nfs4Ace {
    pub ace_type: String,
    pub flags: u32,
    pub access_mask: u32,
    pub who: String,
}

/// Squash configuration detected via write-and-check probing.
///
/// Creates a test file and inspects the resulting ownership to infer
/// the effective squash settings (anonuid, root_squash, all_squash).
#[derive(Debug, Clone, Serialize)]
pub(crate) struct SquashProbeResult {
    /// UID of a file created with AUTH_SYS uid=99999 (arbitrary non-root).
    /// If the file is owned by 99999: no_all_squash (attacker controls identity).
    /// If owned by 65534 (nobody): all_squash with default anonuid.
    /// If owned by 0: all_squash with anonuid=0 (critical misconfig).
    /// If owned by another UID: all_squash with custom anonuid.
    pub observed_uid: u32,
    pub observed_gid: u32,
    /// Whether UID 0 writes are accepted (no_root_squash).
    pub root_squash_bypassed: bool,
    /// Inferred squash mode.
    pub squash_mode: String,
    /// Whether the `insecure` option appears active (accepts ports >1024).
    pub insecure_port: bool,
}

// --- AnalyzeConfig ---

use std::net::SocketAddr;
use std::sync::Arc;

use nfs_v3::wire::{LOOKUP3args, Nfs3Option, Nfs3Result, PATHCONF3args, READ3args, cookieverf3, diropargs3, filename3, nfsstat3, sattr3};
use onc_xdr::Opaque;

use crate::engine::file_handle::{FileHandleAnalyzer, FsType, OsGuess, SigningStatus, WindowsHandleVersion};
use crate::proto::auth::{AuthSys, Credential};
use crate::proto::circuit::CircuitBreaker;
use crate::proto::conn::{ReconnectStrategy, parse_proxy_addr, socks5_connect};
use crate::proto::mount::{ExportEntry, NfsMountClient};
use crate::proto::nfs3::types::FileHandle;
use crate::proto::nfs3::{Nfs3Client, PooledNfs3 as _};
use crate::proto::pool::{ConnectionPool, PoolKey};
use crate::proto::portmap::PortmapClient;
use crate::proto::transport::PooledTransport;
use crate::util::stealth::StealthConfig;

/// Configuration for a full analysis run against one host.
///
/// Every check the analyzer knows about runs unconditionally; the only
/// per-run knobs are which paths/UIDs/GIDs to use for the file-access
/// probes.
#[derive(Debug)]
pub(crate) struct AnalyzeConfig {
    /// Target hostname or IP address.
    pub host: String,
    /// NFS port (default 2049).
    pub port: u16,
    /// Paths to test for readability (e.g., "/etc/shadow").
    pub test_paths: Vec<String>,
    /// UIDs to use when testing file readability.
    pub test_uids: Vec<u32>,
    /// GIDs to use when testing file readability.
    pub test_gids: Vec<u32>,
}

// --- Analyzer ---

/// Orchestrates all security checks against a single NFS server.
///
/// Holds pool-backed protocol clients and dispatches to per-check helper functions.
/// Each check is a free function to keep `analyze()` under the 80-line limit.
pub(crate) struct Analyzer {
    /// Pool-backed NFSv3 client.
    pub nfs3: Arc<Nfs3Client>,
    /// MOUNT protocol client for export enumeration and handle acquisition.
    pub mount: NfsMountClient,
    /// Portmapper client for service enumeration and amplification checks.
    pub portmap: PortmapClient,
    /// Optional SOCKS5 proxy for NFSv4 probes.
    pub proxy: Option<String>,
    /// Stealth pacing applied to per-export probe RPCs (Critical Design Rule 10).
    pub stealth: StealthConfig,
    /// Shared connection pool for per-export clients (avoids a fresh pool per export).
    pub pool: Arc<ConnectionPool>,
    /// Shared circuit breaker for per-export clients.
    pub circuit: Arc<CircuitBreaker>,
    /// AUTH_SYS machinename from --hostname (F-1.4).
    pub hostname: String,
    /// Auxiliary GIDs from --aux-gids, threaded into per-export credentials.
    pub aux_gids: Vec<u32>,
    /// Optional NFS port override (--nfs-port), passed to handle probes.
    pub nfs_port: Option<u16>,
}

impl std::fmt::Debug for Analyzer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Analyzer").finish_non_exhaustive()
    }
}

impl Analyzer {
    /// Construct an Analyzer from pre-built clients.
    #[must_use]
    #[expect(clippy::missing_const_for_fn, reason = "Arc<T> cannot be used in const context")]
    pub(crate) fn new(nfs3: Arc<Nfs3Client>, mount: NfsMountClient, portmap: PortmapClient, pool: Arc<ConnectionPool>, circuit: Arc<CircuitBreaker>, hostname: String, aux_gids: Vec<u32>) -> Self {
        Self { nfs3, mount, portmap, proxy: None, stealth: StealthConfig::none(), pool, circuit, hostname, aux_gids, nfs_port: None }
    }

    /// Attach a SOCKS5 proxy for NFSv4 SECINFO probes.
    #[must_use]
    pub(crate) fn with_proxy(mut self, proxy: String) -> Self {
        self.proxy = Some(proxy);
        self
    }

    /// Apply the configured stealth delay/jitter to per-export probe RPCs.
    ///
    /// Without this the per-export client is built with `StealthConfig::none()`,
    /// so a `--delay`/`--jitter` run would still emit a full-rate burst of mount,
    /// READDIRPLUS, and write probes (Critical Design Rule 10).
    #[must_use]
    #[expect(clippy::missing_const_for_fn, reason = "moves a Drop-bearing Analyzer (Arc/String fields) through the builder")]
    pub(crate) fn with_stealth(mut self, stealth: StealthConfig) -> Self {
        self.stealth = stealth;
        self
    }

    /// Run all enabled security checks and return a consolidated result.
    ///
    /// Enumerates exports via MOUNT, acquires root handles, and dispatches
    /// per-export and global checks. Returns findings even on partial failure.
    pub(crate) async fn analyze(&self, config: &AnalyzeConfig) -> anyhow::Result<AnalysisResult> {
        let addr: SocketAddr = format!("{}:{}", config.host, config.port).parse()?;
        let timestamp = chrono_now();
        let mut findings: Vec<Finding> = Vec::new();

        // Enumerate portmapper first  --  gives us NFS versions + global services.
        let nfs_versions = self.portmap.detect_nfs_versions(addr).await.unwrap_or_default();
        let version_strings: Vec<String> = nfs_versions.iter().map(|v| format!("NFSv{v}")).collect();

        // Global checks that don't need a mounted export -- always run.
        check_v2_downgrade(&nfs_versions, &mut findings);
        run_nis_check(&self.portmap, addr, &mut findings).await;
        run_amplification_check(&self.portmap, addr, &mut findings).await;
        check_webnfs_public_handle(addr, &nfs_versions, &mut findings, self.proxy.as_deref(), &self.stealth).await;
        check_auth_tls(addr, &mut findings, self.proxy.as_deref(), &self.stealth).await;

        // EXCHANGE_ID fingerprint: most authoritative source of server identity.
        // Runs before per-export checks because it needs no MOUNT and works even
        // when all exports deny access. Overrides the null-filename behavioral
        // probe when the server supports NFSv4.1.
        let exchange_id_fp = probe_exchange_id(addr, self.proxy.as_deref(), &self.stealth).await;

        // NFSv4.1 pNFS topology probe: EXCHANGE_ID + conditional GETDEVICELIST.
        probe_pnfs_topology(addr, &mut findings, self.proxy.as_deref(), &self.stealth).await;

        // Per-export checks. Try MOUNT v3 EXPORT first; fall back to MOUNT v1
        // EXPORT when v3 is unavailable (e.g., mountd -N 3).
        let mut exports = self.mount.list_exports(addr).await.unwrap_or_default();
        if exports.is_empty() {
            exports = self.mount.list_exports_v1(addr).await.unwrap_or_default();
        }
        check_export_acls(&exports, &mut findings);

        let mut export_analyses: Vec<ExportAnalysis> = Vec::new();
        // Start with the EXCHANGE_ID result; fall back to null-filename probe
        // if the server doesn't support v4.1.
        let mut impl_fingerprint: Option<String> = exchange_id_fp;
        for entry in &exports {
            let ea = self.analyze_export(config, addr, entry, &mut findings).await;
            // Run the null-filename fingerprint probe once, on the first
            // export that mounted successfully (non-empty handle), but only
            // when EXCHANGE_ID did not already provide a fingerprint.
            if impl_fingerprint.is_none()
                && !ea.file_handle.is_empty()
                && let Ok(fh) = FileHandle::from_hex(&ea.file_handle)
            {
                let probe_client = self.build_export_client(addr, entry);
                impl_fingerprint = Some(check_null_filename_fingerprint(&probe_client, &fh).await);
            }
            export_analyses.push(ea);
        }

        // F-3.1 (Plaintext Traffic Interception): host-level transport-confidentiality
        // check, backed by the auth flavors collected per export above.
        check_plaintext_transport(&export_analyses, &mut findings);

        // Linux knfsd execute-implies-read: nfsd_permission() unconditionally adds
        // NFSD_MAY_OWNER_OVERRIDE to every file-open check, which falls back to
        // MAY_EXEC when READ is denied on a regular file (C702 sec. 12.3.3). Files
        // with mode 0111 (execute-only) are therefore readable via NFS by anyone
        // with execute permission. Emit once per host when Linux knfsd is detected.
        check_execute_implies_read(impl_fingerprint.as_deref(), &mut findings);

        // OS guess from first valid handle.
        let os_guess = export_analyses.iter().find_map(|ea| if ea.file_handle.is_empty() { None } else { FileHandle::from_hex(&ea.file_handle).ok() });
        let os_string = os_guess.map(|fh| check_os_fingerprint(&fh, &nfs_versions));

        Ok(AnalysisResult { host: config.host.clone(), timestamp, os_guess: os_string, impl_fingerprint, nfs_versions: version_strings, exports: export_analyses, findings })
    }

    /// Build a pool-backed NFSv3 client for the given export.
    ///
    /// Shares pool / circuit / proxy / hostname / aux-gids with the analyzer
    /// so every per-export probe uses the same connection infrastructure.
    fn build_export_client(&self, addr: SocketAddr, entry: &ExportEntry) -> Arc<Nfs3Client> {
        let uid = self.nfs3.uid();
        let gid = self.nfs3.gid();
        let gids = crate::cli::probe::build_gid_list(gid, &self.aux_gids);
        let cred = Credential::Sys(AuthSys::with_groups(uid, gid, &gids, &self.hostname));
        let key = PoolKey { host: addr, export: entry.path.clone(), uid, gid };
        Arc::new(Nfs3Client::new(PooledTransport::new(Arc::clone(&self.pool), key, Arc::clone(&self.circuit), self.stealth.clone(), cred, ReconnectStrategy::Persistent)))
    }

    /// Analyze a single export: mount it, run per-export checks, return the result.
    async fn analyze_export(&self, config: &AnalyzeConfig, addr: SocketAddr, entry: &ExportEntry, findings: &mut Vec<Finding>) -> ExportAnalysis {
        let mut ea = ExportAnalysis { path: entry.path.clone(), allowed_hosts: entry.allowed_hosts.clone(), auth_methods: Vec::new(), writable: false, no_root_squash: None, escape_possible: false, file_handle: String::new(), file_access_tests: Vec::new(), nfs4_acls: Vec::new() };

        // Handle acquisition matrix: try MOUNT v3 and v1, derive all length
        // variants (raw, trimmed, padded to 32/64), test each against NFSv3 + NFSv2
        // GETATTR. This catches F-1.6 (v1 leaks handle when v3 requires krb5) and
        // cross-version handle reuse (v1 handle works with v3 ops).
        let export_nfs3 = self.build_export_client(addr, entry);
        let probe = crate::cli::probe::acquire_and_test_handles(&self.mount, &export_nfs3, addr, &entry.path, &self.stealth, self.nfs_port, self.proxy.as_deref(), &self.hostname).await;

        if probe.v1_bypass {
            findings.push(make_finding(
                &FindingSpec {
                    id: "F-1.6",
                    title: "MOUNT v1 leaks handle when MOUNT v3 denies access (auth bypass)",
                    desc: &format!(
                        "MOUNT v3 for export {} failed but MOUNT v1 succeeded. The v1 handle \
                         is usable with NFSv3 operations because the NFS daemon validates handle \
                         bytes, not the MOUNT version (RFC 2623 S2.6).",
                        entry.path
                    ),
                    evidence: &format!("v3_error={}, v1_handle_variants_tested={}", probe.v3_error.as_deref().unwrap_or("unknown"), probe.tested.len()),
                    remediation: "Disable MOUNT v1 (mountd -N 1) or disable NFSv2 entirely (nfs.conf: vers2=n).",
                    export: Some(&entry.path),
                },
                Severity::Critical,
            ));
        }

        let Some(best) = probe.best_v3() else {
            tracing::warn!(export = %entry.path, "No handle variant accepted by NFSv3 GETATTR (tried {} variants)", probe.tested.len());
            return ea;
        };

        let fh = best.variant.handle.clone();
        tracing::debug!(export = %entry.path, variant = %best.variant.label, "Using handle variant for analysis");
        ea.file_handle = fh.to_hex();
        ea.auth_methods = probe.auth_flavors.iter().map(|&f| crate::proto::auth::flavor_name(f)).collect();

        check_auth_methods(&entry.path, &probe.auth_flavors, findings);
        // NFSv4 probes: SECINFO, per-path SECINFO, SEC_LABEL, xattrs.
        run_nfs4_export_checks(addr, &entry.path, findings, self.proxy.as_deref(), &self.stealth).await;
        check_windows_signing(&fh, &entry.path, findings);
        check_handle_entropy(&fh, &entry.path, findings);

        // PATHCONF: case-insensitive detection (Windows/NTFS fingerprint) and
        // unrestricted chown detection (ownership hijacking).
        check_pathconf(&export_nfs3, &fh, &entry.path, findings).await;

        // FSINFO: time_delta (Solaris fingerprint) and properties bitmask.
        check_fsinfo_properties(&export_nfs3, &fh, &entry.path, findings).await;

        // FSSTAT: disk capacity and inode pressure.
        check_fsstat_capacity(&export_nfs3, &fh, &entry.path, findings).await;

        // Silly-rename detection: .nfs<hex> files indicate open-unlinked files.
        check_silly_renames(&export_nfs3, &fh, &entry.path, findings).await;

        // Write verifier stability (reboot oracle): zero-count COMMIT returns
        // the server's writeverf3 at no I/O cost. Two matching probes confirm
        // the server has been up continuously; a mismatch means a reboot (or
        // volatile-cache discard) occurred between probes.
        check_write_verifier(&export_nfs3, &fh, &entry.path, findings).await;

        // AUTH_NONE metadata leak: check if the server allows unauthenticated
        // GETATTR on the export root handle (RFC 2623 S2.3.2 automounter support).
        check_auth_none_leak(addr, &fh, &entry.path, findings, self.proxy.as_deref(), &self.stealth).await;

        // AUTH_TOOWEAK oracle: probe whether the server enforces stronger auth than
        // AUTH_SYS at the NFS operation level (even though MOUNT accepted AUTH_SYS).
        check_auth_tooweak(&export_nfs3, &fh, &entry.path, findings).await;

        // Export escape check (F-2.x). Capture the confirmed escape handle so the
        // --test-read probes below can walk from the filesystem root.
        let escape_fh = check_escape(&export_nfs3, &fh, &entry.path, findings).await;
        ea.escape_possible = escape_fh.is_some();

        // BTRFS subvolume escape (F-2.4)  --  if handle fingerprints as BTRFS.
        check_btrfs_escape(&export_nfs3, &fh, &entry.path, findings).await;

        // Bind mount escape (F-2.6): not separately detectable. A bind mount
        // export is indistinguishable from a regular subtree export on the NFS
        // wire: same fsid, same handles, same READDIRPLUS/FSSTAT results. The
        // mount namespace is a kernel-side abstraction invisible to NFS clients.
        // F-2.1 already covers the escape vector -- if subtree_check is off and
        // the filesystem-root handle resolves, the attacker reaches the entire
        // filesystem regardless of whether the export is a bind mount. The old
        // heuristic (comparing in-handle fsid bytes against fattr3.fsid) was
        // unsound because those use different encodings. No client-side oracle
        // can distinguish "bind mount of /data/project-a" from "direct export
        // of /data/project-a" without server-side information.

        // nohide/crossmnt detection (F-7.3).
        check_nohide(&export_nfs3, &fh, &entry.path, findings).await;

        // Symlink attack preconditions (F-4.4)  --  any world-writable directory.
        check_symlink_preconditions(&export_nfs3, &fh, &entry.path, findings).await;

        // Squash probes write a small payload, then clean up. Run the non-root
        // (uid=99999) probe first: its observed UID is the discriminator that tells
        // genuine no_root_squash (F-4.1) apart from all_squash+anonuid=0 (F-7.5),
        // both of which land a uid=0 write as root.
        let squash_anon_uid = check_squash_config(&export_nfs3, &fh, &entry.path, findings).await;
        check_no_root_squash(&export_nfs3, &fh, &entry.path, squash_anon_uid, findings).await;

        // `insecure` export option (F-7.2): intentionally NOT emitted. A sound test
        // must issue the port-gated MNT operation from a deliberately UNPRIVILEGED
        // source port (>=1024) and flag only when the server accepts it. The prior
        // check called MNTPROC_EXPORT (which Linux rpc.mountd does not gate on source
        // port) and -- when running as root -- the mount client binds a PRIVILEGED
        // source port anyway, so it tested neither the right operation nor the right
        // port and fired on essentially every reachable server. Forcing an
        // unprivileged source port for a control MNT needs connection plumbing not
        // exposed by NfsMountClient here, so the unsound emission is disabled.

        // Missing nosuid/nodev (F-7.4): intentionally NOT emitted. nosuid/nodev are
        // CLIENT-side mount options enforced by the mounting kernel, not server
        // export flags -- the MNTPROC_EXPORT response carries only the export path
        // and its host group list (see ExportEntry), so the server never exposes
        // whether a client mounts with nosuid/nodev. No collected data backs an
        // F-7.4 detection here, so analyze does not claim one. (FINDINGS.md still
        // attributes F-7.4 to `analyze`; that cross-reference over-claims.)

        // File access tests from --test-read paths (F-1.3: auxiliary group injection).
        // Walk from the confirmed escape (filesystem-root) handle when one was found
        // -- that is the "after export escape" read --test-read documents (shadow is
        // typically only reachable post-escape). Fall back to the export root otherwise.
        let (probe_root, via_escape): (&FileHandle, bool) = match escape_fh.as_ref() {
            Some(root) => (root, true),
            None => (&fh, false),
        };
        let mut all_metadata_leaks: Vec<LeakedMetadata> = Vec::new();
        for path in &config.test_paths {
            // Aggregate every credential that read this path into ONE F-1.3 finding
            // rather than emitting a near-identical finding per GID -- the default
            // gids=[0,42,15] previously produced three duplicates for one readable
            // file. The dedup unit is (export, path).
            let mut readable_creds: Vec<String> = Vec::new();
            let mut first_preview: Option<String> = None;
            for &uid in &config.test_uids {
                for &gid in &config.test_gids {
                    let (test, leaks) = probe_file_access(&export_nfs3, probe_root, path, uid, gid, via_escape).await;
                    if test.readable {
                        readable_creds.push(format!("uid={uid} gid={gid}"));
                        if first_preview.is_none() {
                            first_preview.clone_from(&test.preview);
                        }
                    }
                    ea.file_access_tests.push(test);
                    all_metadata_leaks.extend(leaks);
                }
            }
            if !readable_creds.is_empty() {
                findings.push(make_finding(
                    &FindingSpec {
                        // F-1.3: file readable via crafted UID/GID credential
                        // (most commonly shadow GID injection, RFC 2623 S2.1).
                        id: "F-1.3",
                        title: "Sensitive file readable via UID/GID credential",
                        desc: &format!(
                            "File {path} readable with spoofed AUTH_SYS credentials ({}). \
                             AUTH_SYS credential spoofing (RFC 2623 S2.1) allows any client \
                             to claim any UID/GID.",
                            readable_creds.join(", ")
                        ),
                        evidence: first_preview.as_deref().unwrap_or("(no preview)"),
                        remediation: "Use sec=krb5p to authenticate credentials. \
                                      Set root_squash and restrict shadow GID membership.",
                        export: Some(&entry.path),
                    },
                    Severity::Critical,
                ));
            }
        }

        // F-5.6: Metadata disclosed on access denial (RFC 1813 sec. 3.3).
        // Deduplicate by (operation, path) so repeated credential probes against
        // the same component do not inflate the evidence list.
        if !all_metadata_leaks.is_empty() {
            all_metadata_leaks.sort_by(|a, b| a.path.cmp(&b.path).then_with(|| a.operation.cmp(b.operation)));
            all_metadata_leaks.dedup_by(|a, b| a.path == b.path && a.operation == b.operation);
            let evidence_lines: Vec<String> = all_metadata_leaks.iter().map(|l| format!("{} on {}: uid={}, gid={}, size={}, mode={:#o}", l.operation, l.path, l.uid, l.gid, l.size, l.mode)).collect();
            findings.push(make_finding(
                &FindingSpec {
                    id: "F-5.6",
                    title: "Metadata disclosed on access denial",
                    desc: "The server returned file attributes (uid, gid, size, mode) in \
                           the post_op_attr of NFS3ERR_ACCES/NFS3ERR_PERM denial responses. \
                           RFC 1813 sec. 3.3 encourages returning attribute data on failure; \
                           Linux knfsd always does (fs/nfsd/nfs3xdr.c). This discloses \
                           ownership and size of files the caller cannot read, enabling \
                           targeted credential selection for the UID/GID that owns the file.",
                    evidence: &evidence_lines.join("; "),
                    remediation: "No server-side mitigation exists short of patching nfsd to \
                                  suppress post_op_attr on permission denials. Use sec=krb5p \
                                  to prevent unauthenticated callers from reaching the denial path.",
                    export: Some(&entry.path),
                },
                Severity::Low,
            ));
        }

        ea
    }
}

// --- Per-export checks ---

/// Decide whether a single allowed-host ACL entry effectively exposes the export
/// to the whole network (F-7.1, RFC 2623 S2.6 host-based access control).
///
/// Catches four classes the old exact-string match missed:
///   - glob wildcards (`*`, `?`): `*`, `*.example.com`, `192.168.*` -- the ACL no
///     longer pins a specific host;
///   - the explicit world wildcards `0.0.0.0/0` and `::/0`;
///   - broad CIDRs: an IPv4 prefix shorter than /16 or an IPv6 prefix shorter
///     than /48 covers a large slice of the address space (e.g. `10.0.0.0/8`,
///     `0.0.0.0/1`, `::/1`);
///   - broad address/netmask exports: the `addr/255.0.0.0` form exports(5) also
///     accepts, whose leading-one count falls below the same /16 (IPv4) or /48
///     (IPv6) threshold.
fn is_world_accessible_host(host: &str) -> bool {
    // Glob metacharacters match arbitrary hostnames.
    if host.contains('*') || host.contains('?') {
        return true;
    }
    if let Some((addr, prefix)) = host.split_once('/') {
        // CIDR prefix-length form (e.g. 10.0.0.0/8).
        if let Ok(bits) = prefix.parse::<u8>() {
            if addr.parse::<std::net::Ipv4Addr>().is_ok() {
                return bits < 16;
            }
            if addr.parse::<std::net::Ipv6Addr>().is_ok() {
                return bits < 48;
            }
        }
        // address/netmask form -- exports(5) also accepts e.g. 10.0.0.0/255.0.0.0,
        // which showmount/MNTPROC_EXPORT echoes verbatim into allowed_hosts. Convert
        // the mask to a prefix length by counting leading one-bits and apply the same
        // broad-subnet threshold used for CIDR (F-7.1).
        if addr.parse::<std::net::Ipv4Addr>().is_ok()
            && let Ok(mask) = prefix.parse::<std::net::Ipv4Addr>()
        {
            return u32::from(mask).leading_ones() < 16;
        }
        if addr.parse::<std::net::Ipv6Addr>().is_ok()
            && let Ok(mask) = prefix.parse::<std::net::Ipv6Addr>()
        {
            return u128::from(mask).leading_ones() < 48;
        }
    }
    false
}

/// Check export ACLs for world-accessible exports (wildcard or empty host list).
///
/// An empty allowed_hosts list means the server uses `*` implicitly.
/// Glob wildcards and broad CIDRs also flag as open -- see `is_world_accessible_host`.
fn check_export_acls(exports: &[ExportEntry], findings: &mut Vec<Finding>) {
    for export in exports {
        let is_open = export.allowed_hosts.is_empty() || export.allowed_hosts.iter().any(|h| is_world_accessible_host(h));
        if is_open {
            findings.push(make_finding(
                &FindingSpec {
                    id: "F-7.1",
                    title: "Export accessible to all hosts (world-accessible export)",
                    desc: &format!("Export {} has no host restriction or uses a wildcard ACL.", export.path),
                    evidence: &format!("allowed_hosts={:?}", export.allowed_hosts),
                    remediation: "Restrict the export to specific IP ranges in /etc/exports.",
                    export: Some(&export.path),
                },
                Severity::High,
            ));
        }

        // FreeBSD-style truncated subnet detection (F-7.7 / OsGuess::FreeBsd signal).
        let truncated: Vec<&str> = export
            .allowed_hosts
            .iter()
            .filter(|h| {
                if h.contains('/') || h.contains('*') || h.contains('?') {
                    return false;
                }
                let octets: Vec<&str> = h.split('.').collect();
                (octets.len() == 2 || octets.len() == 3) && octets.iter().all(|o| o.parse::<u8>().is_ok())
            })
            .map(String::as_str)
            .collect();
        if !truncated.is_empty() {
            findings.push(make_finding(
                &FindingSpec {
                    id: "F-7.7",
                    title: "FreeBSD-style truncated subnet in export ACL (OS fingerprint)",
                    desc: &format!(
                        "Export {} uses truncated subnet notation ({}) without a mask. \
                         This format is characteristic of FreeBSD NFS servers.",
                        export.path,
                        truncated.join(", ")
                    ),
                    evidence: &format!("truncated_subnets={truncated:?}, FreeBSD OsGuess signal"),
                    remediation: "Informational -- verify the intended subnet scope matches the implied CIDR.",
                    export: Some(&export.path),
                },
                Severity::Info,
            ));
        }
    }
}

/// Flag execute-implies-read on Linux knfsd.
///
/// Linux knfsd's `nfsd_permission()` unconditionally adds `NFSD_MAY_OWNER_OVERRIDE`
/// to every file-open permission check. When READ is denied on a regular file,
/// the code falls back to checking `MAY_EXEC` -- if execute permission exists, READ
/// is allowed (C702 sec. 12.3.3). This means any file with mode `0111` (or any
/// execute bit set without the corresponding read bit) is readable via NFS by
/// anyone with execute permission. The behavior applies to every NFSv3 READ
/// because NFSD_MAY_OWNER_OVERRIDE is added unconditionally.
///
/// Emitted once per host at Info severity when the null-filename fingerprint
/// identifies the server as Linux knfsd.
fn check_execute_implies_read(impl_fingerprint: Option<&str>, findings: &mut Vec<Finding>) {
    let is_linux_knfsd = impl_fingerprint.is_some_and(|fp| fp.contains("Linux knfsd"));
    if !is_linux_knfsd {
        return;
    }
    findings.push(make_finding(
        &FindingSpec {
            id: "F-1.1",
            title: "Execute-implies-read: execute-only files are readable via NFS on Linux knfsd",
            desc: "Linux knfsd's nfsd_permission() unconditionally adds NFSD_MAY_OWNER_OVERRIDE \
                   to every file-open check. When READ is denied on a regular file, it falls back \
                   to MAY_EXEC -- if execute permission exists, READ succeeds (C702 sec. 12.3.3). \
                   Files with execute-only permissions (e.g., mode 0111) are readable by any NFS \
                   client with execute access. This expands the readable file set beyond what \
                   mode bits indicate, potentially exposing secrets in execute-only scripts or \
                   binaries.",
            evidence: "Server fingerprinted as Linux knfsd (null-filename -> GARBAGE_ARGS). \
                       Execute-implies-read is a compile-time behavior in nfsd_permission(), \
                       not a runtime option.",
            remediation: "Do not rely on removing read permission to protect NFS-exported files. \
                          Use Kerberos (sec=krb5p) or filesystem ACLs to restrict access. \
                          Remove execute permission from files that should not be readable.",
            export: None,
        },
        Severity::Info,
    ));
}

/// Flag plaintext NFS transport when no RPCSEC_GSS privacy is advertised (F-3.1).
///
/// NFS defers confidentiality to the transport and specifies none (RFC 1813 S8).
/// RPCSEC_GSS (flavor 6) is the only auth flavor here that can carry krb5p wire
/// privacy; if no analyzed export advertises it, and absent NFS-over-TLS
/// (RFC 9289, opt-in and not probed), every payload and AUTH_SYS credential
/// crosses the wire in cleartext and is open to passive interception.
///
/// Backed solely by the MOUNT/SECINFO auth flavors already collected, so this is
/// emitted once per host at Info severity rather than asserting TLS is absent.
fn check_plaintext_transport(exports: &[ExportAnalysis], findings: &mut Vec<Finding>) {
    // Emit only when a genuinely plaintext flavor (AUTH_SYS / AUTH_NONE) is
    // advertised AND no export offers RPCSEC_GSS (krb5/krb5i/krb5p). A
    // Kerberos-protected export advertises the GSS pseudo-flavors (now rendered as
    // "RPCSEC_GSS(krb5*)" by the flavor map), so this no longer false-positives on
    // a krb5p-only, encrypted export (F-3.1). If auth enumeration learned nothing,
    // `any_plaintext` is false and we stay silent for lack of transport evidence.
    let any_plaintext = exports.iter().any(|ea| ea.auth_methods.iter().any(|m| m == "AUTH_SYS" || m == "AUTH_NONE"));
    let any_gss = exports.iter().any(|ea| ea.auth_methods.iter().any(|m| m.contains("GSS")));
    if !any_plaintext || any_gss {
        return;
    }
    let flavors: Vec<String> = exports.iter().flat_map(|ea| ea.auth_methods.iter().cloned()).collect();
    findings.push(make_finding(
        &FindingSpec {
            id: "F-3.1",
            title: "NFS traffic is unencrypted  --  no RPCSEC_GSS privacy advertised",
            desc: "No analyzed export advertises RPCSEC_GSS (flavor 6), so krb5p wire \
                   privacy is unavailable. NFS defers confidentiality to the transport \
                   and specifies none (RFC 1813 S8); absent NFS-over-TLS (RFC 9289, \
                   opt-in) all file contents and AUTH_SYS credentials are sent in \
                   cleartext and can be passively intercepted.",
            evidence: &format!("auth_methods={flavors:?}"),
            remediation: "Require sec=krb5p (RPCSEC_GSS privacy) or wrap NFS in TLS \
                          (RFC 9289) / a VPN to protect data in transit.",
            export: None,
        },
        Severity::Info,
    ));
}

/// Flag exports that support only AUTH_SYS (F-1.1) or mixed AUTH_SYS + Kerberos (F-1.7).
///
/// AUTH_SYS is trivially spoofable  --  the server cannot verify UID/GID claims.
/// RFC 2623 S2.1 documents this weakness.
///
/// When BOTH AUTH_SYS and Kerberos are advertised on the same export, an attacker
/// can choose AUTH_SYS and bypass Kerberos entirely  --  there is no negotiation
/// that forces the stronger mechanism (RFC 2203 S5.2.1, RFC 2623 S5).
fn check_auth_methods(export_path: &str, auth_flavors: &[u32], findings: &mut Vec<Finding>) {
    let has_auth_sys = auth_flavors.contains(&1);
    // Kerberos: bare RPCSEC_GSS (6) or krb5 pseudo-flavors (390003-390005, IANA
    // RPC auth-flavor registry). Real krb5 exports typically advertise the
    // pseudo-flavors, not bare 6.
    let has_kerberos = auth_flavors.iter().any(|&f| f == 6 || (390_003..=390_005).contains(&f));
    if has_auth_sys && !has_kerberos {
        findings.push(make_finding(
            &FindingSpec {
                id: "F-1.1",
                title: "Export uses AUTH_SYS only (no Kerberos)",
                desc: "AUTH_SYS authentication is trivially spoofable  --  the server cannot \
                       verify the client's UID/GID claims (RFC 2623 S2.1).",
                evidence: &format!("auth_flavors={auth_flavors:?}"),
                remediation: "Enable sec=krb5p in /etc/exports and configure Kerberos.",
                export: Some(export_path),
            },
            Severity::High,
        ));
    } else if has_auth_sys && has_kerberos {
        // Mixed flavors: Kerberos is deployed but not enforced. An attacker
        // simply sends AUTH_SYS requests (RFC 2203 S5.2.1: no facility to
        // negotiate mechanism). A MITM can also strip krb5 entries from the
        // MOUNT flavor list (RFC 2623 S5) or from SECINFO (RFC 7530 S19).
        findings.push(make_finding(
            &FindingSpec {
                id: "F-1.7",
                title: "Mixed auth flavors allow RPCSEC_GSS downgrade to AUTH_SYS",
                desc: "The export advertises both AUTH_SYS and RPCSEC_GSS (Kerberos). An attacker \
                       can choose AUTH_SYS and bypass Kerberos entirely  --  there is no negotiation \
                       that forces the stronger mechanism (RFC 2203 S5.2.1). A MITM can also strip \
                       the krb5 entries from the MOUNT flavor list to force legitimate clients onto \
                       AUTH_SYS (RFC 2623 S5).",
                evidence: &format!("auth_flavors={auth_flavors:?}"),
                remediation: "Remove AUTH_SYS from exports that require Kerberos authentication: \
                              use sec=krb5 (or krb5i/krb5p) exclusively in /etc/exports.",
                export: Some(export_path),
            },
            Severity::High,
        ));
    }

    // AUTH_DH (flavor 3): obsolete, uses 192-bit DH / 56-bit DES (RFC 5531 S14).
    if auth_flavors.contains(&3) {
        findings.push(make_finding(
            &FindingSpec {
                id: "F-3.7",
                title: "AUTH_DH advertised (cryptographically broken)",
                desc: "The export advertises AUTH_DH (flavor 3), which uses 192-bit Diffie-Hellman \
                       key exchange and 56-bit DES encryption. Both are trivially factorable by \
                       modern standards. RFC 5531 S14: 'AUTH_DH [...] is considered obsolete and \
                       insecure; see [RFC2695].'",
                evidence: &format!("auth_flavors={auth_flavors:?}"),
                remediation: "Remove AUTH_DH from the export's security configuration. Use \
                              sec=krb5p for authenticated and integrity-protected access.",
                export: Some(export_path),
            },
            Severity::Medium,
        ));
    }

    // AUTH_SHORT (flavor 2): opaque server-issued session credential replayable
    // from wire captures without knowing the original UID/GID.
    if auth_flavors.contains(&2) {
        findings.push(make_finding(
            &FindingSpec {
                id: "F-3.9",
                title: "AUTH_SHORT session credentials advertised",
                desc: "The export advertises AUTH_SHORT (flavor 2). After an initial AUTH_SYS \
                       call, the server may return an AUTH_SHORT verifier containing an opaque \
                       shorthand credential. This shorthand is not cryptographically bound to \
                       the original identity (RFC 1057 S9.2, RFC 5531 Appendix A). An attacker \
                       who captures the AUTH_SHORT token from the wire can replay it to \
                       impersonate the original client without knowing their UID/GID.",
                evidence: &format!("auth_flavors={auth_flavors:?}"),
                remediation: "AUTH_SHORT is a legacy optimization. Use sec=krb5p to eliminate \
                              replayable session credentials.",
                export: Some(export_path),
            },
            Severity::Low,
        ));
    }
}

/// Attempt to escape the export by constructing a handle targeting the filesystem root.
///
/// Uses `FileHandleAnalyzer::construct_escape_handle` to build an out-of-export handle,
/// then confirms it by comparing READDIRPLUS results on the escape handle vs the export.
/// Returns the confirmed filesystem-root handle when an escape is found (so the
/// --test-read probes can walk from it), else None. The finding is appended only on
/// confirmation, and BOTH the export-root and candidate READDIRPLUS must succeed -- a
/// failed baseline read is a failed probe, not evidence of a boundary crossing.
/// Test whether the filesystem root is reachable via a crafted handle (F-2.1).
///
/// Tries all known root-inode candidates for the detected filesystem:
///   - XFS: inode 128 (v5 default) and inode 64 (v4 / -i size=256)
///   - ext4: inode 2
///   - BTRFS: subvolume 256
///
/// For each candidate, issues READDIRPLUS and compares the entry count to the
/// export root.  A different count -- with both reads succeeding -- confirms the
/// escape.  Using READDIRPLUS rather than GETATTR catches servers that accept
/// GETATTR on the root but refuse it on the export.
async fn check_escape(nfs3: &Nfs3Client, export_fh: &FileHandle, export_path: &str, findings: &mut Vec<Finding>) -> Option<FileHandle> {
    // A confirmed escape needs a working baseline to compare against. When the
    // export's OWN READDIRPLUS fails (transient timeout/reset, or denied to the
    // configured uid/gid) export_count is None -- that is a failed probe, not a
    // boundary crossing. Bail rather than let any crafted handle that merely lists
    // successfully (Some(N) != None) fabricate a Critical F-2.1.
    let export_count = count_readdirplus(nfs3, export_fh).await?;

    // Build the full candidate list: fs-appropriate root first, then XFS/BTRFS.
    let mut candidates = FileHandleAnalyzer::construct_root_candidates(export_fh);
    // Also try BTRFS subvolumes (first 4 are cheap).
    candidates.extend(FileHandleAnalyzer::construct_btrfs_subvol_handles(export_fh, 4));

    for candidate in candidates {
        // Confirm only when BOTH reads succeed and the crafted handle resolves to
        // content that DIFFERS from the export root (a different entry count means a
        // different directory, i.e. outside the export subtree).
        let Some(root_count) = count_readdirplus(nfs3, &candidate.root_handle).await else { continue };
        if root_count != export_count {
            findings.push(make_finding(
                &FindingSpec {
                    id: "F-2.1",
                    title: "Export escape possible  --  filesystem root accessible via crafted handle",
                    desc: "subtree_check is disabled (Linux default). An attacker can craft a file \
                           handle targeting any inode on the filesystem, bypassing export boundaries.",
                    evidence: &format!("export_entries={export_count}, root_entries={root_count}, inode={}, fs_type={:?}, confidence={:.0}%", candidate.inode_number, candidate.fs_type, candidate.confidence * 100.0),
                    remediation: "Enable subtree_check in /etc/exports (caution  --  impacts rename correctness).",
                    export: Some(export_path),
                },
                Severity::Critical,
            ));
            // Hand back the confirmed escape handle so --test-read can walk the path
            // from the filesystem root (F-1.3 shadow is only reachable post-escape).
            return Some(candidate.root_handle);
        }
    }
    None
}

/// Count READDIRPLUS entries for a file handle; returns None on any error.
async fn count_readdirplus(nfs3: &Nfs3Client, fh: &FileHandle) -> Option<u32> {
    let page = nfs3.list_dir_page(fh, 0, cookieverf3([0u8; 8])).await.ok()?;
    Some(u32::try_from(page.entries.len()).unwrap_or(u32::MAX))
}

/// Check for NFSv2 downgrade risk: v2 registered alongside v3/v4.
///
/// NFSv2 has zero security negotiation (RFC 2623 S2.7). If the server also
/// requires Kerberos for v3, an attacker can explicitly request v2 to bypass it.
/// Check for NFSv2 downgrade risk (F-1.6).
///
/// NFSv2 has zero security negotiation (RFC 2623 S2.7). If the server
/// registers v2 alongside v3/v4, a client can request v2 explicitly to
/// bypass sec=krb5 or other v3+ security requirements.
fn check_v2_downgrade(nfs_versions: &[u32], findings: &mut Vec<Finding>) {
    let has_v2 = nfs_versions.contains(&2);
    let has_v3_or_v4 = nfs_versions.iter().any(|&v| v >= 3);
    if has_v2 && has_v3_or_v4 {
        findings.push(make_finding(
            &FindingSpec {
                id: "F-1.6",
                title: "NFSv2 enabled alongside NFSv3/v4 (downgrade attack risk)",
                desc: "NFSv2 supports only AUTH_SYS and has no security negotiation (RFC 2623 S2.7). \
                       A client can request NFSv2 explicitly to bypass sec=krb5 configured on v3/v4.",
                evidence: &format!("registered_versions={nfs_versions:?}"),
                remediation: "Disable NFSv2 in /etc/nfs.conf: vers2=n",
                export: None,
            },
            Severity::High,
        ));
    }
}

/// Detect NIS (ypserv/ypbind) co-hosted with NFS.
///
/// ypserv (program 100004) registered in portmapper means NIS is running.
/// An attacker who discovers the NIS domain name can dump credential maps
/// without authentication (RFC 1094 S2.3).
async fn run_nis_check(portmap: &PortmapClient, addr: SocketAddr, findings: &mut Vec<Finding>) {
    let Ok(nis) = portmap.detect_nis(addr).await else { return };
    if nis.ypserv_present {
        findings.push(make_finding(
            &FindingSpec {
                id: "F-5.3",
                title: "NIS (ypserv) co-hosted with NFS  --  credential maps may be accessible",
                desc: "ypserv (program 100004) is registered in the portmapper. An attacker who \
                       discovers the NIS domain name can extract passwd.byname, shadow.byname, \
                       and group.byname maps without authentication.",
                evidence: &format!("ypserv_port={:?}, ypbind_present={}", nis.ypserv_port, nis.ypbind_present),
                remediation: "Migrate from NIS to LDAP/Kerberos. If NIS is required, restrict \
                              ypserv to specific IP ranges via /etc/hosts.allow.",
                export: None,
            },
            Severity::High,
        ));
    }
}

/// Measure portmapper UDP amplification factor.
///
/// A DUMP response much larger than the request means the host can be
/// weaponized as a DDoS reflector. Factor >10x is considered significant.
async fn run_amplification_check(portmap: &PortmapClient, addr: SocketAddr, findings: &mut Vec<Finding>) {
    let Ok(amp) = portmap.measure_amplification(addr).await else { return };
    if amp.factor >= 10.0 {
        findings.push(make_finding(
            &FindingSpec {
                id: "F-3.2",
                title: "Portmapper UDP amplification factor >= 10x (DDoS risk)",
                desc: "The portmapper responds to UDP DUMP requests with a response significantly \
                       larger than the request. This can be exploited for UDP reflection DDoS attacks.",
                evidence: &format!("request={}B, response={}B, factor={:.1}x", amp.request_bytes, amp.response_bytes, amp.factor),
                remediation: "Filter UDP port 111 at the firewall. Disable portmapper if not required.",
                export: None,
            },
            Severity::Medium,
        ));
    }
}

/// Probe the WebNFS public file handle (XNFS Appendix E).
///
/// WebNFS defines a well-known handle (all-zero for v2, zero-length for v3)
/// that any client can use without going through MOUNT. If the server answers
/// a GETATTR or LOOKUP on this handle, MOUNT's export ACLs are bypassed
/// entirely -- no privileged port needed, no hostname check, no auth flavor
/// negotiation. Typical on Solaris, some NetApp configurations, and embedded
/// RTOS NFS servers (VxWorks).
async fn check_webnfs_public_handle(addr: SocketAddr, nfs_versions: &[u32], findings: &mut Vec<Finding>, proxy: Option<&str>, stealth: &StealthConfig) {
    use onc_rpc_client::rpc::opaque_auth;
    use onc_rpc_client::transport::direct::DirectTransport;
    use onc_rpc_client::transport::tokio::TokioIo;

    stealth.wait().await;

    let nfs_addr = SocketAddr::new(addr.ip(), 2049);

    // NFSv3 public handle: zero-length (send a GETATTR with an empty fh).
    if nfs_versions.contains(&3)
        && let Some(stream) = tokio::time::timeout(std::time::Duration::from_secs(5), connect_tcp(nfs_addr, proxy)).await.ok().and_then(Result::ok)
    {
        let transport = DirectTransport::new(TokioIo::new(stream));
        let empty_fh = FileHandle::from_bytes(&[]);
        let client = nfs_v3::Nfs3Client::new(transport);
        if let Ok(attrs) = client.attrs(&empty_fh).await {
            // Public handle accepted -- try multi-component LOOKUP to prove
            // the full bypass (XNFS Appendix E: "A LOOKUP request that uses
            // the public filehandle can provide a pathname containing multiple
            // components").
            let mut evidence = format!("NFSv3 public handle (zero-length) returned attrs: uid={}, gid={}, mode={:#o}", attrs.uid, attrs.gid, attrs.mode);
            if let Ok((_, Some(shadow_attrs))) = client.resolve(&empty_fh, "etc/shadow").await {
                evidence = format!("{evidence}; multi-component LOOKUP 'etc/shadow' succeeded: uid={}, gid={}, mode={:#o}, size={}", shadow_attrs.uid, shadow_attrs.gid, shadow_attrs.mode, shadow_attrs.size);
            }
            findings.push(make_finding(
                &FindingSpec {
                    id: "F-2.9",
                    title: "WebNFS public file handle accepted (MOUNT bypass)",
                    desc: "The server responds to requests using the WebNFS public file handle \
                               (zero-length for NFSv3, per XNFS Appendix E). This gives any client \
                               access to the public export without going through the MOUNT protocol, \
                               bypassing export ACLs, hostname restrictions, and privileged-port checks. \
                               A multi-component LOOKUP on the public handle can reach any file in \
                               a single RPC without walking the directory tree.",
                    evidence: &evidence,
                    remediation: "Disable WebNFS on the server. On Solaris: remove the 'public' share option. On NetApp: nfs.webnfs.enable off.",
                    export: None,
                },
                Severity::Critical,
            ));
            return;
        }
    }

    // NFSv2 public handle: all-zero 32 bytes.
    if nfs_versions.contains(&2)
        && let Some(stream2) = tokio::time::timeout(std::time::Duration::from_secs(5), connect_tcp(nfs_addr, proxy)).await.ok().and_then(Result::ok)
    {
        let cred = AuthSys::new(0, 0, "localhost");
        let opaque = cred.to_opaque_auth(crate::proto::auth::next_stamp());
        let transport2 = DirectTransport::with_auth(TokioIo::new(stream2), opaque, opaque_auth::default());
        let client = nfs_v2::Nfs2Client::new(transport2);
        let zero_fh = nfs_v2::wire::Nfs2FileHandle([0u8; 32]);
        if let Ok(attrs) = client.getattr(&zero_fh).await {
            let mut evidence = format!("NFSv2 public handle (all-zero) returned attrs: uid={}, gid={}, mode={:#o}, size={}", attrs.uid, attrs.gid, attrs.mode, attrs.size);
            // Multi-component LOOKUP: try to reach /etc/shadow in one call.
            if let Ok((_, shadow_attrs)) = client.lookup_path(&zero_fh, "etc/shadow").await {
                evidence = format!("{evidence}; multi-component path 'etc/shadow' succeeded: uid={}, gid={}, mode={:#o}, size={}", shadow_attrs.uid, shadow_attrs.gid, shadow_attrs.mode, shadow_attrs.size);
            }
            findings.push(make_finding(
                &FindingSpec {
                    id: "F-2.9",
                    title: "WebNFS public file handle accepted (MOUNT bypass)",
                    desc: "The server responds to requests using the WebNFS public file handle \
                               (all-zero 32 bytes for NFSv2, per XNFS Appendix E). This gives any \
                               client access to the public export without going through the MOUNT \
                               protocol, bypassing export ACLs and hostname restrictions.",
                    evidence: &evidence,
                    remediation: "Disable WebNFS on the server.",
                    export: None,
                },
                Severity::Critical,
            ));
        }
    }
}

/// Check Windows file handle signing status.
///
/// All-zero HMAC bytes mean signing is disabled  --  arbitrary handle forgery is possible.
///
/// Two detection paths: `fingerprint_os` recognises 32-byte v3 handles; the new
/// `detect_windows_handle_version` also catches 28-byte v4.1 handles.
fn check_windows_signing(fh: &FileHandle, export_path: &str, findings: &mut Vec<Finding>) {
    let os = FileHandleAnalyzer::fingerprint_os(fh);
    let is_windows = os == OsGuess::Windows || FileHandleAnalyzer::detect_windows_handle_version(fh) == Some(WindowsHandleVersion::V41);
    if !is_windows {
        return;
    }
    let version_label = match FileHandleAnalyzer::detect_windows_handle_version(fh) {
        Some(WindowsHandleVersion::V3) => "NFSv3 (32-byte)",
        Some(WindowsHandleVersion::V41) => "NFSv4.1 (28-byte)",
        None => "unknown",
    };
    if FileHandleAnalyzer::check_windows_signing(fh) == SigningStatus::Disabled {
        findings.push(make_finding(
            &FindingSpec {
                id: "F-2.3",
                title: "Windows NFS server has handle signing disabled",
                desc: &format!(
                    "The NFS server appears to be Windows ({version_label} handle format). \
                     The HMAC signature bytes in the file handle are all zero, meaning handle \
                     signing is disabled. Any handle value can be forged to access arbitrary files.",
                ),
                evidence: &format!("handle_hex={}, version={version_label}", fh.to_hex()),
                remediation: "Enable NFS handle signing in Windows Server NFS configuration.",
                export: Some(export_path),
            },
            Severity::Critical,
        ));
    }
}

/// Check file handle entropy to assess brute-force resistance.
///
/// Low-entropy handles (< 16 bits) can be brute-forced quickly at NFS speeds.
fn check_handle_entropy(fh: &FileHandle, export_path: &str, findings: &mut Vec<Finding>) {
    let entropy = FileHandleAnalyzer::estimate_entropy(fh);
    if entropy.entropy_bits < 16.0 {
        findings.push(make_finding(
            &FindingSpec {
                id: "F-2.2",
                title: "File handle has low entropy  --  brute-force feasible",
                desc: "The file handle contains fewer than 16 bits of randomness. At 10,000 \
                       attempts/sec (typical NFS), the entire handle space can be enumerated quickly.",
                evidence: &format!("entropy_bits={:.1}, brute_force_seconds={:.0}, random_fields={:?}", entropy.entropy_bits, entropy.brute_force_seconds, entropy.random_fields),
                remediation: "Use a filesystem with higher handle entropy (e.g., XFS UUID-based fsid).",
                export: Some(export_path),
            },
            Severity::Medium,
        ));
    }
}

/// Probe whether a specific file is readable with given uid/gid credentials,
/// harvesting any metadata the server leaks in denial responses.
///
/// Uses raw wire-level LOOKUP and READ instead of the domain API so the
/// `post_op_attr` from failure arms (`LOOKUP3resfail.dir_attributes`,
/// `READ3resfail.file_attributes`) is captured. Linux knfsd populates these
/// even on NFS3ERR_ACCES / NFS3ERR_PERM (fs/nfsd/nfs3xdr.c), disclosing uid,
/// gid, size, and mode for files the caller cannot access (RFC 1813 sec. 3.3).
async fn probe_file_access(nfs3: &Nfs3Client, root_fh: &FileHandle, path: &str, uid: u32, gid: u32, via_escape: bool) -> (FileAccessTest, Vec<LeakedMetadata>) {
    let mut result = FileAccessTest { path: path.to_owned(), uid, gid, readable: false, preview: None, via_escape };
    let mut leaks: Vec<LeakedMetadata> = Vec::new();

    // Create a client with the specified credentials so the server sees
    // the correct uid/gid for permission checks.
    let test_client = nfs3.with_credential(Credential::Sys(AuthSys::with_groups(uid, gid, &[gid], "nfswolf")), uid, gid);

    // Walk path components using raw LOOKUP to capture failure-arm metadata.
    let mut current = root_fh.clone();
    let mut walked = String::new();
    for component in path.split('/').filter(|c| !c.is_empty()) {
        let args = LOOKUP3args { what: diropargs3 { dir: current.to_nfs_fh3(), name: filename3(Opaque::owned(component.as_bytes().to_vec())) } };
        match test_client.lookup(&args).await {
            Ok(Nfs3Result::Ok(ok)) => {
                current = FileHandle::from_nfs_fh3(&ok.object);
                if !walked.is_empty() {
                    walked.push('/');
                }
                walked.push_str(component);
            },
            Ok(Nfs3Result::Err((status, fail))) => {
                // Harvest leaked attrs from the denial's post_op_attr (RFC 1813 sec. 3.3.3).
                if matches!(status, nfsstat3::NFS3ERR_ACCES | nfsstat3::NFS3ERR_PERM)
                    && let Nfs3Option::Some(ref attrs) = fail.dir_attributes
                {
                    let leaked_path = if walked.is_empty() { component.to_owned() } else { format!("{walked}/{component}") };
                    leaks.push(LeakedMetadata { operation: "LOOKUP", path: leaked_path, uid: attrs.uid, gid: attrs.gid, size: attrs.size, mode: attrs.mode });
                }
                return (result, leaks);
            },
            Ok(_) | Err(_) => return (result, leaks),
        }
    }

    // Attempt READ using the raw wire call to capture failure-arm metadata.
    let read_args = READ3args { file: current.to_nfs_fh3(), offset: 0, count: 128 };
    match test_client.read(&read_args).await {
        Ok(Nfs3Result::Ok(ok)) => {
            result.readable = true;
            result.preview = Some(String::from_utf8_lossy(ok.data.0.as_ref()).chars().take(64).collect());
        },
        Ok(Nfs3Result::Err((status, fail))) => {
            if matches!(status, nfsstat3::NFS3ERR_ACCES | nfsstat3::NFS3ERR_PERM)
                && let Nfs3Option::Some(ref attrs) = fail.file_attributes
            {
                leaks.push(LeakedMetadata { operation: "READ", path: path.to_owned(), uid: attrs.uid, gid: attrs.gid, size: attrs.size, mode: attrs.mode });
            }
        },
        Ok(_) | Err(_) => {},
    }

    (result, leaks)
}

/// Format OS and filesystem fingerprint as a human-readable string.
///
/// Combines handle-based fingerprinting with the NFS version matrix as a
/// secondary signal. Windows Server NFS supports v3 + v4.1 but NOT v2 or
/// v4.0. A version pattern of [v3, v4] without v2 is suggestive of Windows,
/// though not conclusive -- portmapper registers program version 4 without
/// distinguishing 4.0 from 4.1 (minor versions are negotiated inside the
/// NFSv4 COMPOUND, not at the portmapper level).
fn check_os_fingerprint(fh: &FileHandle, nfs_versions: &[u32]) -> String {
    let os = FileHandleAnalyzer::fingerprint_os(fh);
    let fs = FileHandleAnalyzer::fingerprint_fs(fh);

    let has_v2 = nfs_versions.contains(&2);
    let has_v3 = nfs_versions.contains(&3);
    let has_v4 = nfs_versions.contains(&4);
    let windows_version_pattern = has_v3 && has_v4 && !has_v2;

    match os {
        OsGuess::Windows if windows_version_pattern => "Windows/Unknown (version pattern: v3+v4, no v2 corroborates)".to_owned(),
        OsGuess::Windows => "Windows/Unknown".to_owned(),
        OsGuess::Unknown if windows_version_pattern && FileHandleAnalyzer::detect_windows_handle_version(fh).is_some() => {
            let ver = match FileHandleAnalyzer::detect_windows_handle_version(fh) {
                Some(WindowsHandleVersion::V3) => "NFSv3",
                Some(WindowsHandleVersion::V41) => "NFSv4.1",
                None => unreachable!(),
            };
            format!("Windows(probable)/{ver} handle (version pattern: v3+v4, no v2; portmapper does not distinguish v4.0 from v4.1)")
        },
        _ => format!("{os:?}/{fs:?}"),
    }
}

// --- Missing check implementations ---

/// Check for BTRFS subvolume handle construction (F-2.4).
///
/// When the export handle fingerprints as BTRFS, additional subvolume
/// handles can be constructed that may resolve to sub-trees outside the export.
async fn check_btrfs_escape(nfs3: &Nfs3Client, export_fh: &FileHandle, export_path: &str, findings: &mut Vec<Finding>) {
    if FileHandleAnalyzer::fingerprint_fs(export_fh) != FsType::Btrfs {
        return;
    }
    // F-2.4 is scoped to reaching OTHER subvolumes (different subvol IDs), i.e.
    // outside the export. A bare GETATTR success proves nothing when the export
    // itself lives on the reconstructed subvolume (subvol 256, the typical export
    // target, is the first candidate). Require a working export baseline and confirm
    // each candidate resolves to content that DIFFERS from the export root -- the
    // same boundary guard check_escape (F-2.1) uses.
    let Some(export_count) = count_readdirplus(nfs3, export_fh).await else { return };
    let candidates = FileHandleAnalyzer::construct_btrfs_subvol_handles(export_fh, 16);
    let mut hits = 0u32;
    let mut tried = 0u32;
    for candidate in &candidates {
        // Skip a candidate that reconstructs the export's own handle -- resolving it
        // cannot demonstrate a boundary crossing.
        if candidate.root_handle == *export_fh {
            continue;
        }
        tried += 1;
        // A different entry count means a different directory (a different subvolume),
        // not the export's own subvolume root.
        if matches!(count_readdirplus(nfs3, &candidate.root_handle).await, Some(c) if c != export_count) {
            hits += 1;
        }
    }
    if hits > 0 {
        findings.push(make_finding(
            &FindingSpec {
                id: "F-2.4",
                title: "BTRFS subvolume handles resolve outside export boundary",
                desc: "The export filesystem is BTRFS. Constructed subvolume handles \
                       resolved to directories whose contents differ from the export \
                       root, indicating sub-trees outside the export are accessible \
                       via crafted handles.",
                evidence: &format!("candidates_tried={tried}, handles_resolved_outside={hits}"),
                remediation: "Use subtree_check or restrict to a single BTRFS subvolume per export.",
                export: Some(export_path),
            },
            Severity::High,
        ));
    }
}

/// Detect nohide/crossmnt sub-mount exposure (F-7.3, opt-in).
///
/// Performs READDIRPLUS on the export root and then FSSTAT on any directory
/// entry whose file handle resolves. A different fsid indicates a sub-mount
/// (nohide/crossmnt is active). Per RFC 1813 S3.3.3, servers should not
/// allow LOOKUP to cross mount points by default.
async fn check_nohide(nfs3: &Nfs3Client, root_fh: &FileHandle, export_path: &str, findings: &mut Vec<Finding>) {
    // The export root's own fsid is the baseline every entry is compared to.
    let root_fsid = nfs3.attrs(root_fh).await.map_or(0, |a| a.fsid);

    let mut submounts: Vec<String> = Vec::new();
    // Page through the full directory listing -- a single page may miss entries
    // on large exports, causing sub-mount detection to silently skip them.
    let mut cookie = 0u64;
    let mut verf = cookieverf3([0u8; 8]);
    loop {
        let Ok(page) = nfs3.list_dir_page(root_fh, cookie, verf).await else { break };
        for entry in &page.entries {
            // A server may omit the handle; without it the entry cannot be probed.
            let Some(ref entry_fh) = entry.handle else { continue };
            let Ok(a) = nfs3.attrs(entry_fh).await else { continue };
            if root_fsid != 0 && a.fsid != root_fsid {
                submounts.push(entry.name.clone());
            }
        }
        if page.eof || page.entries.is_empty() {
            break;
        }
        cookie = page.cookie;
        verf = page.cookieverf;
    }

    if !submounts.is_empty() {
        findings.push(make_finding(
            &FindingSpec {
                id: "F-7.3",
                title: "nohide/crossmnt active  --  sub-mounted filesystems are traversable",
                desc: "Directory entries within the export have different fsids, indicating \
                       nohide or crossmnt is set. RFC 1813 S3.3.3 states servers should not \
                       allow LOOKUP to cross mount points; these options override that.",
                evidence: &format!("sub_mounts={submounts:?}"),
                remediation: "Remove nohide/crossmnt from /etc/exports unless explicitly required.",
                export: Some(export_path),
            },
            Severity::Medium,
        ));
    }
}

/// Detect world-writable directories  --  symlink attack preconditions (F-4.4).
///
/// A world-writable directory in an export (regardless of owner -- the classic
/// /tmp vector is root-owned) is a prerequisite for symlink-based escape attacks.
/// The attacker can replace a directory entry with a symlink pointing to a
/// privileged path.
async fn check_symlink_preconditions(nfs3: &Nfs3Client, root_fh: &FileHandle, export_path: &str, findings: &mut Vec<Finding>) {
    // Page through the full directory listing -- a single page may miss
    // world-writable directories deeper in the listing.
    let mut cookie = 0u64;
    let mut verf = cookieverf3([0u8; 8]);
    loop {
        let Ok(page) = nfs3.list_dir_page(root_fh, cookie, verf).await else { break };
        for entry in &page.entries {
            // A server may answer READDIRPLUS without attributes; nothing to judge.
            let Some(ref attrs) = entry.attrs else { continue };
            // Flag ANY world-writable directory (mode & 0o002) regardless of owner. The
            // canonical symlink-escape target is a root-owned, world-writable, sticky dir
            // (/tmp, /var/tmp): any client can drop a symlink there no matter who owns it,
            // and AUTH_SYS lets the attacker assume any UID anyway. The F-4.4 precondition
            // is simply "writable directory" (docs/FINDINGS.md F-4.4); owner UID is
            // evidence, not a gate.
            let is_dir = attrs.file_type == nfs_v3::FileType::Directory;
            let world_writable = (attrs.mode & 0o002) != 0;
            if is_dir && world_writable {
                let name = entry.name.clone();
                findings.push(make_finding(
                    &FindingSpec {
                        id: "F-4.4",
                        title: "World-writable directory  --  symlink attack possible",
                        desc: "A world-writable directory is present in the export. An attacker \
                               with write access can replace directory entries with symlinks \
                               pointing to privileged paths outside the export.",
                        evidence: &format!("path={export_path}/{name} mode={:04o} uid={}", attrs.mode, attrs.uid),
                        remediation: "Remove world-write permission from directories in NFS exports.",
                        export: Some(export_path),
                    },
                    Severity::High,
                ));
            }
        }
        if page.eof || page.entries.is_empty() {
            break;
        }
        cookie = page.cookie;
        verf = page.cookieverf;
    }
}

/// Probe for no_root_squash by creating a test file as uid=0 (F-4.1, opt-in).
///
/// Creates a temporary file with AUTH_SYS uid=0 credentials. If the resulting
/// file is owned by root (GETATTR uid=0), uid=0 was NOT remapped. Per RFC 1813
/// S4.4 and RFC 2623 S2.5, uid=0 should be squashed by default.
///
/// `squash_anon_uid` is the UID observed by the uid=99999 squash probe (run
/// first). It discriminates genuine no_root_squash from all_squash+anonuid=0:
/// under all_squash+anonuid=0 a non-root write ALSO lands as uid 0, so reporting
/// F-4.1 there would point the operator at the wrong export option (that case is
/// F-7.5). F-4.1 is therefore emitted only when uid=0 lands as root AND the
/// non-root probe did NOT also land as root.
async fn check_no_root_squash(nfs3: &Nfs3Client, dir_fh: &FileHandle, export_path: &str, squash_anon_uid: Option<u32>, findings: &mut Vec<Finding>) {
    let root_client = nfs3.with_credential(Credential::Sys(AuthSys::with_groups(0, 0, &[], "nfswolf")), 0, 0);

    let Ok(created) = root_client.create_file(dir_fh, PROBE_NAME, sattr3::default()).await else { return };

    // GETATTR to check the resulting ownership.
    let file_uid = match created {
        Some(ref fh) => nfs3.attrs(fh).await.ok().map(|a| a.uid),
        None => None,
    };

    // Always attempt cleanup regardless of getattr result.
    drop(root_client.unlink(dir_fh, PROBE_NAME).await);

    // If the uid=99999 probe ALSO landed as uid 0, every client UID is squashed
    // to root (all_squash + anonuid=0) -- that is F-7.5, not no_root_squash, so
    // suppress F-4.1 to avoid the wrong remediation. Only uid 0 specifically
    // being honoured (non-root retaining a non-zero identity, or the non-root
    // probe being denied entirely / unknown) is genuine no_root_squash.
    let all_uids_squashed_to_root = squash_anon_uid == Some(0);
    if file_uid == Some(0) && !all_uids_squashed_to_root {
        findings.push(make_finding(
            &FindingSpec {
                id: "F-4.1",
                title: "no_root_squash detected  --  uid=0 credentials not remapped",
                desc: "A file created with AUTH_SYS uid=0 is owned by root on the server. \
                       root_squash is disabled, granting the NFS client full root access \
                       (RFC 1813 S4.4, RFC 2623 S2.5).",
                evidence: &format!("probe_file owned by uid={}", file_uid.unwrap_or(0)),
                remediation: "Add root_squash to /etc/exports (it is the default; check for no_root_squash).",
                export: Some(export_path),
            },
            Severity::Critical,
        ));
    }
}

/// Probe squash configuration by creating a test file as uid=99999 (F-1.2 / F-7.5).
///
/// Creates a temporary file with a non-root arbitrary UID and inspects the
/// resulting ownership to detect all_squash, anonuid=0 (critical), and other
/// squash misconfiguration (RFC 1813 S4.4, RFC 2623 S2.5). Returns the observed
/// UID (the discriminator `check_no_root_squash` uses to avoid mislabeling
/// all_squash+anonuid=0 as no_root_squash); `None` if the probe could not run.
///
/// Emits two findings:
///   - F-7.5 (Critical) when the forced UID lands as root (all_squash+anonuid=0);
///   - F-1.2 (High) when the server HONOURED the forged non-root UID, i.e. the
///     file is owned by uid=99999 -- root_squash only remaps uid 0, so any client
///     can impersonate the UID owning a file. This is the common positive result
///     the previous code computed but never reported.
async fn check_squash_config(nfs3: &Nfs3Client, dir_fh: &FileHandle, export_path: &str, findings: &mut Vec<Finding>) -> Option<u32> {
    const PROBE_UID: u32 = 99_999;
    let probe_client = nfs3.with_credential(Credential::Sys(AuthSys::with_groups(PROBE_UID, PROBE_UID, &[], "nfswolf")), PROBE_UID, PROBE_UID);

    let Ok(created) = probe_client.create_file(dir_fh, PROBE_NAME, sattr3::default()).await else { return None };

    let observed_uid = match created {
        Some(ref fh) => nfs3.attrs(fh).await.ok().map(|a| a.uid),
        None => None,
    };

    // Cleanup probe file before reporting.
    drop(probe_client.unlink(dir_fh, PROBE_NAME).await);

    let uid = observed_uid?;
    let result = infer_squash_mode(uid, PROBE_UID);

    if result.root_squash_bypassed || uid == ANON_UID_ROOT {
        findings.push(make_finding(
            &FindingSpec {
                id: "F-7.5",
                title: "all_squash with anonuid=0  --  all clients effectively run as root",
                desc: "The export uses all_squash but anonuid=0, meaning every client request \
                       is remapped to root. This is worse than no_root_squash because no UID \
                       manipulation is needed (RFC 1813 S4.4, RFC 2623 S2.5).",
                evidence: &format!("probe_uid={PROBE_UID}, observed_uid={uid}, squash_mode={}", result.squash_mode),
                remediation: "Set anonuid to a non-privileged UID (e.g., 65534 for nobody) \
                              or remove all_squash.",
                export: Some(export_path),
            },
            Severity::Critical,
        ));
    } else if uid == PROBE_UID {
        // The forged non-root UID survived: the server trusted a credential it
        // cannot verify (RFC 2623 S2.1). root_squash only remaps uid 0
        // (RFC 1813 S4.4), so an attacker claiming the UID owning a file reads or
        // writes it with no Kerberos and no privileged port.
        findings.push(make_finding(
            &FindingSpec {
                id: "F-1.2",
                title: "Root squash bypass  --  forged non-root UID honoured by server",
                desc: "A file created with AUTH_SYS uid=99999 is owned by uid=99999 on the \
                       server: the forged non-root credential was trusted. root_squash only \
                       remaps uid 0 (RFC 1813 S4.4, RFC 2623 S2.5), so any client can \
                       impersonate the UID that owns a target file and read or write it.",
                evidence: &format!("probe_uid={PROBE_UID}, observed_uid={uid}, squash_mode={}", result.squash_mode),
                remediation: "Use sec=krb5p to authenticate credentials, or all_squash to \
                              collapse every client UID to an unprivileged anonymous account.",
                export: Some(export_path),
            },
            Severity::High,
        ));
    }

    Some(uid)
}

/// Infer the server's squash mode from the observed UID of a test file.
///
/// Per RFC 1813 S7.7.1 and `exports(5)`, the `anonuid` / `anongid` settings
/// control what ownership a squashed request gets:
/// - `ANON_UID_ROOT` (0): `anonuid=0`  --  critical, squash maps to root
/// - `ANON_UID_NOBODY` (65534): standard `all_squash` with nobody/nogroup
/// - `99999` (the probe UID): `no_all_squash`  --  server honours client uid
/// - Any other UID: custom `anonuid`
///
/// Returns a human-readable squash mode string and whether uid=0 was accepted.
pub(crate) fn infer_squash_mode(observed_uid: u32, probe_uid: u32) -> SquashProbeResult {
    let (squash_mode, root_squash_bypassed) = if observed_uid == probe_uid {
        ("no_all_squash (client UID honoured)".to_owned(), probe_uid == 0)
    } else if observed_uid == ANON_UID_ROOT {
        // anonuid=0: all writes land as root regardless of client request
        ("all_squash, anonuid=0 (critical)".to_owned(), true)
    } else if observed_uid == ANON_UID_NOBODY {
        // Standard all_squash: maps to nobody
        ("all_squash, anonuid=65534 (nobody)".to_owned(), false)
    } else {
        // Custom anonuid: still squashing but to a non-standard UID
        (format!("all_squash, anonuid={observed_uid} (custom)"), false)
    };
    SquashProbeResult {
        observed_uid,
        observed_gid: 65534, // gid unknown without a separate probe
        root_squash_bypassed,
        squash_mode,
        insecure_port: false,
    }
}

/// Probe NFSv4 SECINFO for auth-flavor issues (F-3.4 AUTH_SYS-only, F-1.7 mixed).
///
/// SECINFO (RFC 7530 S18.29) returns the actual required auth methods per directory,
/// independent of the NFSv3 MOUNT auth flavor list.  AUTH_SYS-only NFSv4 means
/// an attacker can spoof arbitrary UID/GID credentials even when accessing via NFSv4
/// Run all per-export NFSv4 checks: SECINFO, per-path SECINFO, SEC_LABEL, xattrs.
///
/// Extracted from `analyze_export` to keep cognitive complexity below the threshold.
async fn run_nfs4_export_checks(addr: SocketAddr, export_path: &str, findings: &mut Vec<Finding>, proxy: Option<&str>, stealth: &StealthConfig) {
    // NFSv4 SECINFO check: verify auth methods from the NFSv4 perspective (F-3.4).
    check_nfs4_secinfo(addr, export_path, findings, proxy, stealth).await;
    // NFSv4 per-path SECINFO: walk subdirectories and compare auth flavors to the root.
    check_nfs4_secinfo_per_path(addr, export_path, findings, proxy, stealth).await;
    // NFSv4 FATTR4_SEC_LABEL: read SELinux labels via GETATTR.
    check_nfs4_sec_label(addr, export_path, findings, proxy, stealth).await;
    // NFSv4 named attributes (xattrs) via OPENATTR + READDIR.
    check_nfs4_xattrs(addr, export_path, findings, proxy, stealth).await;
}

/// Emit findings for auth flavors discovered via SECINFO, SECINFO_NO_NAME, or
/// the NFS4ERR_WRONGSEC oracle (F-3.4, F-1.7, F-3.7, F-3.9).
///
/// `source` is the probe method name for the evidence string (e.g. "SECINFO",
/// "SECINFO_NO_NAME", "WRONGSEC oracle"). `entries` are the `SecInfoEntry`
/// items from the response (or synthetic entries for the WRONGSEC path).
fn emit_secinfo_findings(entries: &[nfs_v4::SecInfoEntry], source: &str, export_path: &str, findings: &mut Vec<Finding>) {
    let raw_flavors: Vec<u32> = entries.iter().map(|e| e.flavor).collect();

    // Build a human-readable summary including GSS service levels.
    let flavor_strs: Vec<String> = entries
        .iter()
        .map(|e| {
            if e.flavor == 6 {
                match e.gss_service {
                    Some(1) => "RPCSEC_GSS(krb5)".to_owned(),
                    Some(2) => "RPCSEC_GSS(krb5i)".to_owned(),
                    Some(3) => "RPCSEC_GSS(krb5p)".to_owned(),
                    _ => "RPCSEC_GSS".to_owned(),
                }
            } else {
                crate::proto::auth::flavor_name(e.flavor)
            }
        })
        .collect();
    let evidence_str = format!("{source} flavors=[{}]", flavor_strs.join(", "));

    // Kerberos: bare RPCSEC_GSS (6) or krb5 pseudo-flavors (390003-390005).
    let has_kerberos = raw_flavors.iter().any(|&f| f == 6 || (390_003..=390_005).contains(&f));
    let has_auth_sys = raw_flavors.contains(&1);

    if has_auth_sys && !has_kerberos {
        findings.push(make_finding(
            &FindingSpec {
                id: "F-3.4",
                title: "NFSv4 export accepts AUTH_SYS with no Kerberos (TLS downgrade not enforced)",
                desc: &format!(
                    "NFSv4 {source} for export {export_path} returns AUTH_SYS (flavor 1) \
                     with no RPCSEC_GSS (flavor 6). An attacker can spoof arbitrary UID/GID \
                     credentials via NFSv4 COMPOUND without Kerberos. \
                     RFC 9289 S1: NFS-over-TLS and RPCSEC_GSS are opt-in and rarely deployed.",
                ),
                evidence: &evidence_str,
                remediation: "Configure `sec=krb5p` in /etc/exports to require Kerberos authentication.",
                export: Some(export_path),
            },
            Severity::High,
        ));
    } else if has_auth_sys && has_kerberos {
        findings.push(make_finding(
            &FindingSpec {
                id: "F-1.7",
                title: "NFSv4 SECINFO: mixed auth flavors allow RPCSEC_GSS downgrade to AUTH_SYS",
                desc: &format!(
                    "NFSv4 {source} for export {export_path} returns both AUTH_SYS and RPCSEC_GSS \
                     (Kerberos). An attacker can choose AUTH_SYS and bypass Kerberos entirely \
                     (RFC 2203 S5.2.1). Without integrity protection on the SECINFO call, a MITM \
                     can also strip the krb5 entries to force clients onto AUTH_SYS (RFC 7530 S19).",
                ),
                evidence: &evidence_str,
                remediation: "Remove AUTH_SYS from exports that require Kerberos authentication: \
                              use sec=krb5 (or krb5i/krb5p) exclusively in /etc/exports.",
                export: Some(export_path),
            },
            Severity::High,
        ));
    }

    // AUTH_DH (flavor 3).
    if raw_flavors.contains(&3) {
        findings.push(make_finding(
            &FindingSpec {
                id: "F-3.7",
                title: "NFSv4 SECINFO: AUTH_DH advertised (cryptographically broken)",
                desc: &format!(
                    "NFSv4 {source} for export {export_path} includes AUTH_DH (flavor 3), which \
                     uses 192-bit Diffie-Hellman / 56-bit DES. RFC 5531 S14: 'AUTH_DH [...] is \
                     considered obsolete and insecure; see [RFC2695].'",
                ),
                evidence: &evidence_str,
                remediation: "Remove AUTH_DH from the export's security configuration. Use \
                              sec=krb5p for authenticated and integrity-protected access.",
                export: Some(export_path),
            },
            Severity::Medium,
        ));
    }

    // AUTH_SHORT (flavor 2).
    if raw_flavors.contains(&2) {
        findings.push(make_finding(
            &FindingSpec {
                id: "F-3.9",
                title: "NFSv4 SECINFO: AUTH_SHORT session credentials advertised",
                desc: &format!(
                    "NFSv4 {source} for export {export_path} includes AUTH_SHORT (flavor 2). \
                     AUTH_SHORT opaque tokens captured from the wire can be replayed to \
                     impersonate the original client without knowing their UID/GID \
                     (RFC 1057 S9.2, RFC 5531 Appendix A).",
                ),
                evidence: &evidence_str,
                remediation: "AUTH_SHORT is a legacy optimization. Use sec=krb5p to eliminate \
                              replayable session credentials.",
                export: Some(export_path),
            },
            Severity::Low,
        ));
    }
}

/// (F-3.4: TLS downgrade not enforced  --  RPCSEC_GSS not required).  Mixed
/// AUTH_SYS + Kerberos means the attacker can choose AUTH_SYS and bypass Kerberos
/// entirely (F-1.7, RFC 2203 S5.2.1).
///
/// Probes auth flavors via three methods in order of preference:
/// 1. SECINFO (op 33, v4.0)  --  returns flavors for a named child
/// 2. SECINFO_NO_NAME (op 52, v4.1)  --  fallback when SECINFO fails
/// 3. NFS4ERR_WRONGSEC oracle  --  last resort when both SECINFO ops fail
///
/// Best-effort: silently returns on timeout or PROG_MISMATCH (NFSv3-only server).
async fn check_nfs4_secinfo(addr: SocketAddr, export_path: &str, findings: &mut Vec<Finding>, proxy: Option<&str>, stealth: &StealthConfig) {
    use crate::proto::nfs4::compound::Nfs4DirectClient;
    use crate::proto::nfs4::types::{CompoundBuilder, ResOpData};

    let nfs4_addr = SocketAddr::new(addr.ip(), 2049);
    let timeout = std::time::Duration::from_secs(5);

    let connect = tokio::time::timeout(timeout, Nfs4DirectClient::connect_proxy(nfs4_addr, proxy)).await;
    let Ok(Ok(client)) = connect else { return };
    let mut client = client.with_stealth(stealth.clone());

    // Parse export path into LOOKUP chain components and SECINFO target.
    // "/srv/nfs" -> parent_components=["srv"], secinfo_name="nfs"
    let components: Vec<&str> = export_path.trim_start_matches('/').split('/').filter(|c| !c.is_empty()).collect();
    if components.is_empty() {
        return; // root export: SECINFO on "/" is not meaningful
    }
    let Some((secinfo_name, parent)) = components.split_last() else { return };

    // --- Attempt 1: SECINFO (op 33, v4.0) ---
    let mut b = CompoundBuilder::new().putrootfh();
    for &c in parent {
        b = b.lookup(c);
    }
    let ops = b.secinfo(secinfo_name).build();

    let result = tokio::time::timeout(timeout, client.compound(ops)).await;
    let Ok(Ok(res)) = result else { return };

    if res.status == 0 {
        let entries = res.results.last().and_then(|op| if let ResOpData::SecFlavors(f) = &op.data { Some(f.as_slice()) } else { None });
        if let Some(entries) = entries {
            emit_secinfo_findings(entries, "SECINFO", export_path, findings);
            return;
        }
    }

    // --- Attempt 2: SECINFO_NO_NAME (op 52, v4.1) ---
    // SECINFO failed (NFS4ERR_NOTSUPP, NFS4ERR_OP_ILLEGAL, NFS4ERR_WRONGSEC, or
    // path error on old v4.0 servers). Try SECINFO_NO_NAME which queries the
    // security policy on the current FH itself (RFC 5661 S18.45).
    // Requires minorversion=1 and a fresh connection (previous may be tainted).
    let connect_v41 = tokio::time::timeout(timeout, Nfs4DirectClient::connect_proxy(nfs4_addr, proxy)).await;
    let Ok(Ok(client_v41)) = connect_v41 else {
        // Connection failed; try WRONGSEC oracle as last resort.
        wrongsec_flavor_oracle(nfs4_addr, export_path, &components, findings, proxy, stealth, timeout).await;
        return;
    };
    let mut client_v41 = client_v41.with_stealth(stealth.clone());

    // style=0 = SECINFO_STYLE4_CURRENT_FH (RFC 5661 S18.45.3).
    let mut b = CompoundBuilder::new().putrootfh();
    for &c in &components {
        b = b.lookup(c);
    }
    let v41_ops = b.secinfo_no_name(0).build();

    let v41_result = tokio::time::timeout(timeout, client_v41.compound_v41(v41_ops)).await;
    if let Ok(Ok(v41_res)) = v41_result
        && v41_res.status == 0
    {
        let entries = v41_res.results.last().and_then(|op| if let ResOpData::SecFlavors(f) = &op.data { Some(f.as_slice()) } else { None });
        if let Some(entries) = entries {
            emit_secinfo_findings(entries, "SECINFO_NO_NAME", export_path, findings);
            return;
        }
    }

    // --- Attempt 3: NFS4ERR_WRONGSEC oracle ---
    // Both SECINFO and SECINFO_NO_NAME failed (e.g. permission denied on parent,
    // v4.0-only server rejecting v4.1 ops). Use the WRONGSEC error as a negative
    // auth flavor oracle: try each flavor and see which ones the server rejects.
    wrongsec_flavor_oracle(nfs4_addr, export_path, &components, findings, proxy, stealth, timeout).await;
}

/// Use NFS4ERR_WRONGSEC (status 10016) as a negative auth flavor oracle.
///
/// When SECINFO and SECINFO_NO_NAME both fail to return flavor lists, we can
/// still infer accepted auth flavors by connecting with each flavor's credential
/// and attempting PUTROOTFH + LOOKUP(export components). The server returns
/// NFS4ERR_WRONGSEC (10016, RFC 7530 S13.1.6) when the flavor is rejected,
/// and success (or any other error) when the flavor is accepted for this export.
async fn wrongsec_flavor_oracle(nfs4_addr: SocketAddr, export_path: &str, components: &[&str], findings: &mut Vec<Finding>, proxy: Option<&str>, stealth: &StealthConfig, timeout: std::time::Duration) {
    use crate::proto::nfs4::compound::Nfs4DirectClient;
    use crate::proto::nfs4::types::CompoundBuilder;

    /// Auth flavors to probe: (flavor_number, uid, gid).
    /// AUTH_NONE (0) uses uid=0/gid=0 but connects with AUTH_NONE.
    /// AUTH_SYS (1) uses uid=0/gid=0 with AUTH_SYS credentials.
    const PROBE_FLAVORS: [(u32, u32, u32); 2] = [
        (0, 0, 0), // AUTH_NONE
        (1, 0, 0), // AUTH_SYS
    ];

    let mut accepted_flavors: Vec<u32> = Vec::new();

    for &(flavor, uid, gid) in &PROBE_FLAVORS {
        // Connect with the appropriate auth credential for each flavor.
        let connect_result = if flavor == 0 {
            // AUTH_NONE: use the default anonymous connection.
            tokio::time::timeout(timeout, Nfs4DirectClient::connect_proxy(nfs4_addr, proxy)).await
        } else {
            // AUTH_SYS: connect with uid/gid credentials.
            tokio::time::timeout(timeout, Nfs4DirectClient::connect_with_auth_proxy(nfs4_addr, uid, gid, "localhost", proxy)).await
        };
        let Ok(Ok(probe_client)) = connect_result else { continue };
        let mut probe_client = probe_client.with_stealth(stealth.clone());

        // Build PUTROOTFH + LOOKUP chain for the export path.
        let mut b = CompoundBuilder::new().putrootfh();
        for &c in components {
            b = b.lookup(c);
        }

        let probe_result = tokio::time::timeout(timeout, probe_client.compound(b.build())).await;
        let Ok(Ok(res)) = probe_result else { continue };

        // NFS4ERR_WRONGSEC (10016) means this flavor is explicitly rejected.
        // Any other status (including success=0, permission errors, etc.) means
        // the server accepted this auth flavor for the export.
        if res.status != 10016 {
            accepted_flavors.push(flavor);
        }
    }

    if accepted_flavors.is_empty() {
        return;
    }

    // Build synthetic SecInfoEntry values from the accepted flavors so the
    // shared finding-emission logic can process them uniformly.
    let entries: Vec<nfs_v4::SecInfoEntry> = accepted_flavors.iter().map(|&f| nfs_v4::SecInfoEntry { flavor: f, gss_oid: None, gss_qop: None, gss_service: None }).collect();

    emit_secinfo_findings(&entries, "WRONGSEC oracle", export_path, findings);
}

// --- NFSv4.1 pNFS topology probe ---

/// Probe NFSv4.1 EXCHANGE_ID for pNFS MDS capability, then attempt GETDEVICELIST.
///
/// EXCHANGE_ID (RFC 5661 S18.35) returns server capability flags. When the server
/// advertises pNFS MDS role, GETDEVICELIST enumerates data-server device IDs, which
/// reveals the pNFS topology (data-server addresses the attacker may also reach).
///
/// Best-effort: silently returns if the server does not support NFSv4.1 or pNFS.
async fn probe_pnfs_topology(addr: SocketAddr, findings: &mut Vec<Finding>, proxy: Option<&str>, stealth: &StealthConfig) {
    use crate::proto::nfs4::compound::Nfs4DirectClient;
    use crate::proto::nfs4::types::{CompoundBuilder, ResOpData};

    /// EXCHGID4_FLAG_USE_PNFS_MDS (RFC 5661 S18.35.3, bit 17 = 0x0002_0000).
    const EXCHGID4_FLAG_USE_PNFS_MDS: u32 = 0x0002_0000;

    let nfs4_addr = SocketAddr::new(addr.ip(), 2049);
    let timeout = std::time::Duration::from_secs(5);

    let connect = tokio::time::timeout(timeout, Nfs4DirectClient::connect_proxy(nfs4_addr, proxy)).await;
    let Ok(Ok(mut client)) = connect else { return };
    client = client.with_stealth(stealth.clone());

    // Step 1: EXCHANGE_ID to check v4.1 support and pNFS MDS flag.
    let eid_ops = CompoundBuilder::new().exchange_id("nfswolf").build();
    let eid_res = tokio::time::timeout(timeout, client.compound_v41(eid_ops)).await;
    let Ok(Ok(eid_res)) = eid_res else { return };
    if eid_res.status != 0 {
        return; // v4.1 not supported or EXCHANGE_ID rejected
    }

    let server_flags = match eid_res.results.first().map(|op| &op.data) {
        Some(ResOpData::ExchangeId { flags, .. }) => *flags,
        _ => return,
    };

    let is_mds = (server_flags & EXCHGID4_FLAG_USE_PNFS_MDS) != 0;
    if !is_mds {
        return; // not a pNFS metadata server
    }

    // Step 2: GETDEVICELIST to enumerate pNFS data-server device IDs.
    // LAYOUT4_NFSV4_1_FILES = 1 (RFC 5661 S13.1).
    let gdl_ops = CompoundBuilder::new().putrootfh().getdevicelist(1).build();
    let gdl_res = tokio::time::timeout(timeout, client.compound_v41(gdl_ops)).await;
    let (device_count, device_ids_hex): (usize, Vec<String>) = match gdl_res {
        Ok(Ok(ref res)) if res.status == 0 => match res.results.get(1).map(|op| &op.data) {
            Some(ResOpData::GetDeviceList { deviceid_list, .. }) => {
                let hex: Vec<String> = deviceid_list
                    .iter()
                    .map(|id| {
                        id.iter().fold(String::with_capacity(32), |mut s, b| {
                            use std::fmt::Write;
                            let _ = write!(s, "{b:02x}");
                            s
                        })
                    })
                    .collect();
                (deviceid_list.len(), hex)
            },
            _ => (0, Vec::new()),
        },
        _ => (0, Vec::new()),
    };

    findings.push(make_finding(
        &FindingSpec {
            id: "F-3.5",
            title: "pNFS metadata server detected  --  data-server topology exposed",
            desc: "The server's EXCHANGE_ID flags indicate pNFS metadata server (MDS) capability \
                   (RFC 5661 S18.35). GETDEVICELIST reveals the topology of pNFS data servers, \
                   which may be on separate networks or lack equivalent access controls.",
            evidence: &format!("server_flags={server_flags:#010x}, pNFS_MDS=true, device_count={device_count}, device_ids={device_ids_hex:?}"),
            remediation: "Ensure pNFS data servers have equivalent network access controls \
                          and authentication requirements as the metadata server.",
            export: None,
        },
        Severity::Info,
    ));
}

// --- NFSv4 per-path SECINFO probing ---

/// Walk subdirectories 1 level deep and compare per-path auth flavors to the export root.
///
/// When the auth flavors differ between the export root and a subdirectory, the
/// export has mixed security zones: some paths may accept weaker auth (e.g., AUTH_SYS)
/// while others require krb5. This inconsistency is a downgrade attack vector
/// (RFC 7530 S19: without integrity protection on SECINFO, a MITM can strip the
/// stronger entries).
///
/// Best-effort: silently returns on any error.
async fn check_nfs4_secinfo_per_path(addr: SocketAddr, export_path: &str, findings: &mut Vec<Finding>, proxy: Option<&str>, stealth: &StealthConfig) {
    use crate::proto::nfs4::compound::Nfs4DirectClient;
    use crate::proto::nfs4::types::{CompoundBuilder, ResOpData};

    let nfs4_addr = SocketAddr::new(addr.ip(), 2049);
    let timeout = std::time::Duration::from_secs(5);

    let connect = tokio::time::timeout(timeout, Nfs4DirectClient::connect_proxy(nfs4_addr, proxy)).await;
    let Ok(Ok(mut client)) = connect else { return };
    client = client.with_stealth(stealth.clone());

    // Step 1: Get SECINFO on the export root to establish the baseline.
    let components: Vec<&str> = export_path.trim_start_matches('/').split('/').filter(|c| !c.is_empty()).collect();
    if components.is_empty() {
        return; // root export: per-path comparison not meaningful
    }
    let Some((&secinfo_name, parent)) = components.split_last() else { return };

    let mut b = CompoundBuilder::new().putrootfh();
    for &c in parent {
        b = b.lookup(c);
    }
    let root_ops = b.secinfo(secinfo_name).build();

    let root_result = tokio::time::timeout(timeout, client.compound(root_ops)).await;
    let Ok(Ok(root_res)) = root_result else { return };
    if root_res.status != 0 {
        return;
    }
    let root_flavors: Vec<u32> = match root_res.results.last().map(|op| &op.data) {
        Some(ResOpData::SecFlavors(entries)) => entries.iter().map(nfs_v4::SecInfoEntry::flavor).collect(),
        _ => return,
    };

    // Step 2: READDIR on the export root to list subdirectories (1 level deep).
    // Reconnect because the SECINFO consumed the current FH state.
    let connect2 = tokio::time::timeout(timeout, Nfs4DirectClient::connect_proxy(nfs4_addr, proxy)).await;
    let Ok(Ok(mut client2)) = connect2 else { return };
    client2 = client2.with_stealth(stealth.clone());

    let Ok(Ok(export_fh)) = tokio::time::timeout(timeout, client2.lookup_fh(&components)).await else { return };
    let Ok(Ok(subdirs)) = tokio::time::timeout(timeout, client2.list_dir(&export_fh)).await else { return };

    // Step 3: SECINFO on each subdirectory, compare to root.
    let mut mismatches: Vec<(String, Vec<u32>)> = Vec::new();
    // Cap the number of subdirectories to probe (avoid hammering large dirs).
    for subdir_name in subdirs.iter().take(20) {
        // SECINFO requires the parent FH as current + the child name.
        let sub_ops = CompoundBuilder::new().putfh(export_fh.clone()).secinfo(subdir_name).build();
        let sub_result = tokio::time::timeout(timeout, client2.compound(sub_ops)).await;
        let Ok(Ok(sub_res)) = sub_result else { continue };
        if sub_res.status != 0 {
            continue;
        }
        let sub_flavors: Vec<u32> = match sub_res.results.last().map(|op| &op.data) {
            Some(ResOpData::SecFlavors(entries)) => entries.iter().map(nfs_v4::SecInfoEntry::flavor).collect(),
            _ => continue,
        };
        // Normalize and compare: sort both so order differences don't trigger.
        let mut root_sorted = root_flavors.clone();
        let mut sub_sorted = sub_flavors.clone();
        root_sorted.sort_unstable();
        sub_sorted.sort_unstable();
        if root_sorted != sub_sorted {
            mismatches.push((subdir_name.clone(), sub_flavors));
        }
    }

    if mismatches.is_empty() {
        return;
    }

    let mismatch_detail: Vec<String> = mismatches.iter().map(|(name, flavors)| format!("{name}={flavors:?}")).collect();
    findings.push(make_finding(
        &FindingSpec {
            id: "F-3.6",
            title: "Mixed security zones  --  per-path auth flavors differ from export root",
            desc: &format!(
                "NFSv4 SECINFO probing reveals that subdirectories of {export_path} accept \
                 different auth flavors than the export root. An attacker may bypass stronger \
                 authentication on the root by directly accessing a subdirectory that accepts \
                 weaker auth (e.g., AUTH_SYS vs krb5). SECINFO responses lack integrity \
                 protection unless the initial connection uses RPCSEC_GSS (RFC 7530 S19).",
            ),
            evidence: &format!("root_flavors={root_flavors:?}, mismatched_subdirs=[{detail}]", detail = mismatch_detail.join(", ")),
            remediation: "Apply uniform sec= settings across the entire export tree. \
                          Use sec=krb5p at the export level rather than per-subdirectory overrides.",
            export: Some(export_path),
        },
        Severity::Medium,
    ));
}

// --- NFSv4 FATTR4_SEC_LABEL probe ---

/// Probe the export root for FATTR4_SEC_LABEL (SELinux labels, RFC 7862 S12.2.4).
///
/// If the server supports labeled NFS, the security label attribute carries the
/// MAC label (e.g., "system_u:object_r:nfs_t:s0") for each file. The presence
/// of labels is security-relevant: it reveals the SELinux policy structure and
/// whether labeled NFS is active.
///
/// Best-effort: silently returns if GETATTR for sec_label is not supported.
async fn check_nfs4_sec_label(addr: SocketAddr, export_path: &str, findings: &mut Vec<Finding>, proxy: Option<&str>, stealth: &StealthConfig) {
    use crate::proto::nfs4::compound::Nfs4DirectClient;
    use crate::proto::nfs4::types::{AttrRequest, CompoundBuilder, ResOpData};

    let nfs4_addr = SocketAddr::new(addr.ip(), 2049);
    let timeout = std::time::Duration::from_secs(5);

    let connect = tokio::time::timeout(timeout, Nfs4DirectClient::connect_proxy(nfs4_addr, proxy)).await;
    let Ok(Ok(mut client)) = connect else { return };
    client = client.with_stealth(stealth.clone());

    // Build LOOKUP chain to reach the export directory, then GETATTR with sec_label.
    let components: Vec<&str> = export_path.trim_start_matches('/').split('/').filter(|c| !c.is_empty()).collect();
    let mut b = CompoundBuilder::new().putrootfh();
    for &c in &components {
        b = b.lookup(c);
    }
    let ops = b.getattr(AttrRequest::sec_label()).build();

    let result = tokio::time::timeout(timeout, client.compound(ops)).await;
    let Ok(Ok(res)) = result else { return };
    if res.status != 0 {
        return;
    }

    // The GETATTR result is the last op in the compound.
    let sec_label = res.results.last().and_then(|op| if let ResOpData::Getattr(attrs) = &op.data { attrs.sec_label.as_ref() } else { None });

    let Some(label) = sec_label else { return };

    let label_text = String::from_utf8_lossy(&label.label);
    findings.push(make_finding(
        &FindingSpec {
            id: "F-4.5",
            title: "SELinux security label exposed via NFSv4 FATTR4_SEC_LABEL",
            desc: &format!(
                "The export root at {export_path} carries a SELinux security label \
                 (FATTR4_SEC_LABEL, RFC 7862 S12.2.4). This reveals the server's \
                 SELinux policy structure and confirms labeled NFS is active.",
            ),
            evidence: &format!("lfs={}, pi={}, label=\"{label_text}\"", label.lfs, label.pi),
            remediation: "Review whether exposing SELinux labels to NFS clients is \
                          intended. Consider restricting FATTR4_SEC_LABEL if label \
                          information leakage is a concern.",
            export: Some(export_path),
        },
        Severity::Info,
    ));
}

// --- NFSv4 named attributes / xattrs probe ---

/// Probe for NFSv4 named attributes via OPENATTR + READDIR on the export root.
///
/// OPENATTR (op 19, RFC 7530 S16.17) opens the named attribute directory
/// associated with a file or directory. Named attributes can carry metadata
/// like POSIX ACLs, SELinux labels, and custom xattrs. Their presence reveals
/// what extended metadata the server stores and exposes.
///
/// Best-effort: silently returns if the server does not support named attributes
/// (NFS4ERR_NOTSUPP) or if no named attributes exist (NFS4ERR_NOENT).
async fn check_nfs4_xattrs(addr: SocketAddr, export_path: &str, findings: &mut Vec<Finding>, proxy: Option<&str>, stealth: &StealthConfig) {
    use crate::proto::nfs4::compound::Nfs4DirectClient;
    use crate::proto::nfs4::types::{AttrRequest, CompoundBuilder, ResOpData};

    let nfs4_addr = SocketAddr::new(addr.ip(), 2049);
    let timeout = std::time::Duration::from_secs(5);

    let connect = tokio::time::timeout(timeout, Nfs4DirectClient::connect_proxy(nfs4_addr, proxy)).await;
    let Ok(Ok(mut client)) = connect else { return };
    client = client.with_stealth(stealth.clone());

    // Navigate to the export directory, then OPENATTR(create=false) + READDIR.
    let components: Vec<&str> = export_path.trim_start_matches('/').split('/').filter(|c| !c.is_empty()).collect();
    let mut b = CompoundBuilder::new().putrootfh();
    for &c in &components {
        b = b.lookup(c);
    }
    // OPENATTR changes the current FH to the named attribute directory.
    // READDIR on the named attribute directory to list xattr names.
    let ops = b.openattr(false).readdir(0, 0, 4096, 65536, AttrRequest::empty()).build();

    let result = tokio::time::timeout(timeout, client.compound(ops)).await;
    let Ok(Ok(res)) = result else { return };
    // If OPENATTR failed (NFS4ERR_NOTSUPP=10004, NFS4ERR_NOENT=2), the compound
    // stops before READDIR. Check the overall status and OPENATTR op status.
    if res.status != 0 {
        return;
    }

    // The READDIR result is the last successful op.
    let xattr_names: Vec<String> = match res.results.last().map(|op| &op.data) {
        Some(ResOpData::Readdir { entries, .. }) => entries.iter().map(|e| e.name.clone()).filter(|n| n != "." && n != "..").collect(),
        _ => return,
    };

    if xattr_names.is_empty() {
        return;
    }

    // Flag security-relevant xattrs: POSIX ACLs, SELinux, capabilities.
    let security_xattrs: Vec<&str> = xattr_names.iter().filter(|n| n.starts_with("system.posix_acl") || n.starts_with("security.") || n.starts_with("trusted.") || *n == "system.nfs4_acl").map(String::as_str).collect();

    let severity = if security_xattrs.is_empty() { Severity::Info } else { Severity::Low };

    findings.push(make_finding(
        &FindingSpec {
            id: "F-5.13",
            title: "NFSv4 named attributes (xattrs) exposed on export root",
            desc: &format!(
                "OPENATTR + READDIR on the export root at {export_path} reveals named \
                 attributes. These may carry sensitive metadata: POSIX ACLs \
                 (system.posix_acl_access), SELinux labels (security.selinux), file \
                 capabilities (security.capability), or application-specific data.",
            ),
            evidence: &format!("xattr_names={xattr_names:?}, security_relevant={security_xattrs:?}"),
            remediation: "Review which named attributes are exposed and whether their contents \
                          leak sensitive metadata. Consider restricting xattr access via export options.",
            export: Some(export_path),
        },
        severity,
    ));
}

// --- AUTH_TOOWEAK oracle (RFC 5531 S8.3) ---

/// Probe whether the server enforces stronger auth than AUTH_SYS at the NFS
/// operation level.
///
/// MOUNT may accept AUTH_SYS (returning a handle and auth_flavors) while the
/// NFS server rejects AUTH_SYS operations with AUTH_TOOWEAK (RFC 5531 S8.3).
/// This catches the case where Kerberos is enforced for NFS operations but not
/// for MOUNT, which is common in mixed environments.
async fn check_auth_tooweak(nfs3: &Nfs3Client, root_fh: &FileHandle, export_path: &str, findings: &mut Vec<Finding>) {
    use onc_rpc_client::RpcError;
    use onc_rpc_client::rpc::auth_stat;

    if let Err(nfs_v3::Nfs3Fault::Rpc(RpcError::Auth(stat))) = nfs3.attrs(root_fh).await
        && stat == auth_stat::AUTH_TOOWEAK
    {
        findings.push(make_finding(
            &FindingSpec {
                id: "F-1.8",
                title: "NFS operations reject AUTH_SYS (Kerberos enforced at NFS layer)",
                desc: "MOUNT accepted AUTH_SYS and returned a valid handle, but the NFS \
                           server rejected a GETATTR with AUTH_TOOWEAK (RFC 5531 S8.3). The \
                           server enforces stronger authentication (Kerberos) at the NFS \
                           operation level even though MOUNT does not. AUTH_SYS attacks \
                           (F-1.1 through F-1.7) will fail against this export.",
                evidence: &format!("GETATTR on {export_path} returned AUTH_TOOWEAK"),
                remediation: "Positive security indicator. Consider also requiring \
                                  Kerberos for MOUNT (sec=krb5 on the export) to prevent \
                                  handle disclosure via AUTH_SYS MNT.",
                export: Some(export_path),
            },
            Severity::Info,
        ));
    }
}

// --- AUTH_NONE metadata leak (RFC 2623 S2.3.2) ---

/// Check whether the server allows unauthenticated GETATTR on the export root.
///
/// Some servers permit AUTH_NONE for GETATTR/FSINFO at mount time to support
/// automounters that lack Kerberos credentials (RFC 2623 S2.3.2). If GETATTR
/// with AUTH_NONE returns file attributes, metadata (uid, gid, mode, size,
/// timestamps) is leaked to any unauthenticated client.
async fn check_auth_none_leak(addr: SocketAddr, root_fh: &FileHandle, export_path: &str, findings: &mut Vec<Finding>, proxy: Option<&str>, stealth: &StealthConfig) {
    use onc_rpc_client::transport::direct::DirectTransport;
    use onc_rpc_client::transport::tokio::TokioIo;

    stealth.wait().await;

    let nfs_addr = SocketAddr::new(addr.ip(), 2049);
    let timeout = std::time::Duration::from_secs(5);

    let Ok(Ok(stream)) = tokio::time::timeout(timeout, connect_tcp(nfs_addr, proxy)).await else { return };

    // DirectTransport defaults to AUTH_NONE.
    let transport = DirectTransport::new(TokioIo::new(stream));
    let client = nfs_v3::Nfs3Client::new(transport);

    if let Ok(attrs) = client.attrs(root_fh).await {
        findings.push(make_finding(
            &FindingSpec {
                id: "F-5.8",
                title: "Export root attributes leaked via AUTH_NONE",
                desc: "The server returned file attributes for the export root handle using \
                       AUTH_NONE (no credentials). RFC 2623 S2.3.2 permits this for automounter \
                       support, but it leaks metadata (uid, gid, mode, size, timestamps) to \
                       any unauthenticated client who possesses a valid file handle.",
                evidence: &format!("AUTH_NONE GETATTR: uid={}, gid={}, mode={:#o}, size={}", attrs.uid, attrs.gid, attrs.mode, attrs.size),
                remediation: "Restrict AUTH_NONE access. Configure sec=krb5 or sec=sys \
                              to require authentication for all NFS operations.",
                export: Some(export_path),
            },
            Severity::Low,
        ));
    }
}

// --- AUTH_TLS STARTTLS probe (RFC 9289 S4.1) ---

/// Probe whether the NFS server supports RPC-with-TLS (RFC 9289).
///
/// Sends a NULL RPC with AUTH_TLS (flavor 7) credential and a verifier
/// containing the ASCII string "STARTTLS". If the server responds with
/// MSG_ACCEPTED and "STARTTLS" in the reply verifier, TLS is available.
/// The probe result is stored on the analyzer for use by `check_plaintext_transport`.
async fn check_auth_tls(addr: SocketAddr, findings: &mut Vec<Finding>, proxy: Option<&str>, stealth: &StealthConfig) {
    use onc_rpc_client::RpcTransport as _;
    use onc_rpc_client::rpc::{auth_flavor, opaque_auth};
    use onc_rpc_client::transport::direct::DirectTransport;
    use onc_rpc_client::transport::tokio::TokioIo;

    stealth.wait().await;

    let nfs_addr = SocketAddr::new(addr.ip(), 2049);
    let timeout = std::time::Duration::from_secs(5);

    let Ok(Ok(stream)) = tokio::time::timeout(timeout, connect_tcp(nfs_addr, proxy)).await else { return };

    // Build a raw RPC CALL message with AUTH_TLS credential + STARTTLS verifier.
    // RFC 9289 S4.1: verifier body is the 8-byte fixed-length opaque "STARTTLS".
    // The opaque_auth XDR encoding adds the length prefix; we supply raw bytes only.
    let cred = opaque_auth { flavor: auth_flavor::AUTH_TLS, body: Opaque::borrowed(&[]) };
    let verf = opaque_auth { flavor: auth_flavor::AUTH_TLS, body: Opaque::borrowed(b"STARTTLS") };
    let transport = DirectTransport::with_auth(TokioIo::new(stream), cred, verf);

    // Send a NULL call to NFS program (100003, v3, proc 0).
    let null_args = onc_xdr::Void;
    let result: Result<onc_xdr::Void, _> = transport.call(100_003, 3, 0, &null_args).await;

    if result.is_ok() {
        // Server accepted the AUTH_TLS NULL  --  TLS negotiation is available.
        findings.push(make_finding(
            &FindingSpec {
                id: "F-3.8",
                title: "RPC-with-TLS supported (RFC 9289)",
                desc: "The server accepted an AUTH_TLS NULL probe, indicating that \
                       RPC-with-TLS is available for transport encryption. Note: TLS \
                       encrypts the wire but AUTH_SYS inside TLS still allows credential \
                       forging (RFC 9289 S6.3). Mutual TLS authentication is RECOMMENDED \
                       but not required.",
                evidence: "AUTH_TLS NULL accepted",
                remediation: "Enable mutual TLS authentication to bind client identity \
                              to the TLS certificate. Use RPCSEC_GSS(krb5p) for full \
                              user-level authentication.",
                export: None,
            },
            Severity::Info,
        ));
    }
    // Non-response or rejection: server does not support AUTH_TLS.
    // The plaintext-transport finding (F-3.1) already handles this case.
}

// --- PATHCONF fingerprint and security checks ---

/// Probe PATHCONF for case-insensitive filesystem and unrestricted chown.
///
/// `case_insensitive = true` is a strong Windows NFS / NetApp NTFS fingerprint.
/// `chown_restricted = false` means any user can change file ownership, enabling
/// ownership hijacking attacks.
async fn check_pathconf(nfs3: &Nfs3Client, root_fh: &FileHandle, export_path: &str, findings: &mut Vec<Finding>) {
    let args = PATHCONF3args { object: root_fh.to_nfs_fh3() };
    let Ok(res) = nfs3.pathconf(&args).await else { return };
    let Nfs3Result::Ok(ok) = res else { return };

    if ok.case_insensitive {
        findings.push(make_finding(
            &FindingSpec {
                id: "F-5.7",
                title: "Case-insensitive filesystem (Windows NFS / NTFS fingerprint)",
                desc: "PATHCONF reports case_insensitive=true. This indicates a Windows NFS \
                       server or NetApp NTFS volume. Case-insensitive lookups enable filename \
                       collision attacks: creating 'SHADOW' alongside '/etc/shadow' or exploiting \
                       case-variant names to bypass path-based access controls (RFC 7530 S12).",
                evidence: &format!("case_insensitive=true, case_preserving={}", ok.case_preserving),
                remediation: "Awareness only. Case-insensitive filesystems cannot be changed \
                              to case-sensitive without reformatting.",
                export: Some(export_path),
            },
            Severity::Low,
        ));
    }

    if !ok.chown_restricted {
        findings.push(make_finding(
            &FindingSpec {
                id: "F-4.6",
                title: "Unrestricted chown (any user can change file ownership)",
                desc: "PATHCONF reports chown_restricted=false. Non-root users can change file \
                       ownership via SETATTR, enabling ownership hijacking: an attacker writes a \
                       file, then chowns it to root to create a SUID binary. Most UNIX systems \
                       restrict chown to root (_POSIX_CHOWN_RESTRICTED), but some NFS servers or \
                       older systems do not enforce this.",
                evidence: "chown_restricted=false",
                remediation: "Enable _POSIX_CHOWN_RESTRICTED on the exported filesystem. \
                              On Linux, this is the default and cannot be disabled per-export.",
                export: Some(export_path),
            },
            Severity::High,
        ));
    }
}

// --- NFSv4.1 EXCHANGE_ID fingerprinting ---

/// Probe the server's NFSv4.1 EXCHANGE_ID to extract the implementation identity.
///
/// EXCHANGE_ID (op 42, RFC 5661 S18.35) is a v4.1 operation that returns the
/// server's vendor string, build date, capability flags, and state protection
/// policy. This is the most authoritative fingerprint available -- it comes
/// directly from the NFS server's self-reported identity rather than behavioral
/// inference.
///
/// Uses a raw `DirectTransport` to port 2049 with AUTH_NONE (same approach as
/// `check_webnfs_public_handle`), building a minorversion=1 COMPOUND since the
/// library `compound()` helpers hardcode minorversion=0.
///
/// Returns `None` when the server does not support NFSv4.1 (NFS4ERR_MINOR_VERS_MISMATCH,
/// NFS4ERR_OP_ILLEGAL, or connection failure).
async fn probe_exchange_id(addr: SocketAddr, proxy: Option<&str>, stealth: &StealthConfig) -> Option<String> {
    use onc_rpc_client::RpcTransport as _;
    use onc_rpc_client::transport::direct::DirectTransport;
    use onc_rpc_client::transport::tokio::TokioIo;

    use crate::proto::nfs4::types::{CompoundArgs, CompoundBuilder, CompoundRes, NFS4_PROC_COMPOUND, NFS4_PROGRAM, NFS4_VERSION, ResOpData};

    stealth.wait().await;

    let nfs4_addr = SocketAddr::new(addr.ip(), 2049);
    let timeout = std::time::Duration::from_secs(5);

    let Ok(Ok(stream)) = tokio::time::timeout(timeout, connect_tcp(nfs4_addr, proxy)).await else { return None };

    let null_auth = onc_rpc_client::rpc::opaque_auth::default();
    let transport = DirectTransport::with_auth(TokioIo::new(stream), null_auth.clone(), null_auth);

    // Build a minorversion=1 COMPOUND with just EXCHANGE_ID.
    let ops = CompoundBuilder::new().exchange_id("nfswolf").build();
    let args = CompoundArgs { tag: String::new(), minorversion: 1, ops };

    let result = tokio::time::timeout(timeout, transport.call::<CompoundArgs, CompoundRes>(NFS4_PROGRAM, NFS4_VERSION, NFS4_PROC_COMPOUND, &args)).await;
    let Ok(Ok(res)) = result else {
        tracing::debug!("EXCHANGE_ID probe failed (server may not support NFSv4.1)");
        return None;
    };

    // Non-zero top-level status means the server rejected the COMPOUND
    // (e.g. NFS4ERR_MINOR_VERS_MISMATCH for v4.0-only servers).
    if res.status != 0 {
        tracing::debug!("EXCHANGE_ID COMPOUND rejected: status={}", res.status);
        return None;
    }

    let op = res.results.first()?;
    let ResOpData::ExchangeId { flags, impl_id, .. } = &op.data else {
        return None;
    };

    // Capability flags (RFC 5661 S18.35.3):
    //   0x1  = EXCHGID4_FLAG_SUPP_MOVED_REFER
    //   0x2  = EXCHGID4_FLAG_SUPP_MOVED_MIGR
    //   0x4  = EXCHGID4_FLAG_BIND_PRINC_STATEID
    //   0x10 = EXCHGID4_FLAG_USE_NON_PNFS
    //   0x20 = EXCHGID4_FLAG_USE_PNFS_MDS
    //   0x40 = EXCHGID4_FLAG_USE_PNFS_DS
    // pNFS role flags (RFC 5661 S12.1): 0x20 = USE_PNFS_MDS, 0x40 = USE_PNFS_DS.
    let is_pnfs_metadata = flags & 0x20 != 0;
    let is_pnfs_data = flags & 0x40 != 0;

    let mut extras = Vec::new();
    if is_pnfs_metadata {
        extras.push("pNFS_MDS");
    }
    if is_pnfs_data {
        extras.push("pNFS_DS");
    }
    let extras_str = if extras.is_empty() { String::new() } else { format!(", {}", extras.join("+")) };

    // Extract the implementation identity (0 or 1 element per the RFC).
    let fingerprint = if let Some(id) = impl_id.first() {
        // Format the build date if it looks like a real epoch timestamp.
        let date_str = if id.date.0 > 0 { format_epoch(id.date.0) } else { String::new() };

        if date_str.is_empty() { format!("{} [{}] (EXCHANGE_ID{extras_str})", id.name, id.domain) } else { format!("{} [{}] (built {}, EXCHANGE_ID{extras_str})", id.name, id.domain, date_str) }
    } else {
        // No impl_id but the EXCHANGE_ID succeeded -- still useful.
        format!("NFSv4.1 (no impl_id, EXCHANGE_ID{extras_str})")
    };

    tracing::info!("EXCHANGE_ID fingerprint: {fingerprint}");
    Some(fingerprint)
}

/// Format a Unix epoch timestamp as YYYY-MM-DD.
fn format_epoch(secs: u64) -> String {
    let (year, month, day, _, _, _) = secs_to_datetime(secs);
    format!("{year:04}-{month:02}-{day:02}")
}

// --- FSINFO properties (F-5.10) ---

/// RFC 1813 S3.3.18 filesystem properties bitmask constants.
const FSF3_LINK: u32 = 0x0001;
const FSF3_SYMLINK: u32 = 0x0002;
#[expect(dead_code, reason = "referenced in evidence formatting only")]
const FSF3_HOMOGENEOUS: u32 = 0x0008;
#[expect(dead_code, reason = "referenced in evidence formatting only")]
const FSF3_CANSETTIME: u32 = 0x0010;

/// Extract FSINFO time_delta and properties bitmask.
///
/// `time_delta` of {0, 1000} (1-microsecond) is a Solaris fingerprint signal
/// (Linux uses nanosecond granularity). Missing `FSF3_LINK`/`FSF3_SYMLINK`
/// reduces the symlink/hardlink attack surface.
async fn check_fsinfo_properties(nfs3: &Nfs3Client, root_fh: &FileHandle, export_path: &str, findings: &mut Vec<Finding>) {
    let Ok(info) = nfs3.info_fs(root_fh).await else { return };

    // Solaris fingerprint: time_delta = {0, 1000} means microsecond granularity.
    if info.time_delta.seconds == 0 && info.time_delta.nseconds == 1000 {
        findings.push(make_finding(
            &FindingSpec {
                id: "F-5.10",
                title: "Solaris NFS server detected (microsecond time_delta)",
                desc: "FSINFO reports time_delta={0, 1000} (1-microsecond granularity). \
                       Linux knfsd uses nanosecond (time_delta={0, 1}). Microsecond granularity \
                       is characteristic of Solaris NFS servers.",
                evidence: &format!("time_delta={{{}, {}}}", info.time_delta.seconds, info.time_delta.nseconds),
                remediation: "Informational -- adjust escape strategy for Solaris NFS handle formats.",
                export: Some(export_path),
            },
            Severity::Info,
        ));
    }

    let no_link = (info.properties & FSF3_LINK) == 0;
    let no_symlink = (info.properties & FSF3_SYMLINK) == 0;
    if no_link || no_symlink {
        let mut missing = Vec::new();
        if no_link {
            missing.push("hard links (FSF3_LINK)");
        }
        if no_symlink {
            missing.push("symbolic links (FSF3_SYMLINK)");
        }
        findings.push(make_finding(
            &FindingSpec {
                id: "F-5.11",
                title: "Filesystem lacks link/symlink support (reduced attack surface)",
                desc: &format!(
                    "FSINFO properties indicate the filesystem does not support: {}. \
                     Symlink (F-4.4) and hardlink attacks are inapplicable on this export.",
                    missing.join(", ")
                ),
                evidence: &format!("properties={:#06x}", info.properties),
                remediation: "Informational -- no action required.",
                export: Some(export_path),
            },
            Severity::Info,
        ));
    }
}

// --- FSSTAT capacity ---

/// Check disk capacity and inode pressure via FSSTAT.
///
/// Low `avail_files` relative to `total_files` signals inode exhaustion
/// DoS potential.
async fn check_fsstat_capacity(nfs3: &Nfs3Client, root_fh: &FileHandle, export_path: &str, findings: &mut Vec<Finding>) {
    let Ok(stat) = nfs3.stat_fs(root_fh).await else { return };
    if stat.total_files == 0 {
        return;
    }
    if stat.avail_files < 1000 {
        let usage_pct = ((stat.total_files - stat.free_files) * 100) / stat.total_files;
        findings.push(make_finding(
            &FindingSpec {
                id: "F-5.12",
                title: "Near inode exhaustion (DoS risk)",
                desc: "FSSTAT reports fewer than 1000 available file slots. An attacker \
                       with write access can exhaust remaining inodes to deny file creation.",
                evidence: &format!("total_files={}, free_files={}, avail_files={}, usage={}%, total_bytes={}, free_bytes={}", stat.total_files, stat.free_files, stat.avail_files, usage_pct, stat.total_bytes, stat.free_bytes),
                remediation: "Expand filesystem capacity or restrict write access.",
                export: Some(export_path),
            },
            Severity::Medium,
        ));
    }
}

// --- Silly-rename detection ---

/// Detect `.nfs*` silly-rename files (open-unlinked indicators).
///
/// Linux NFS clients create `.nfs<inode><hex>` files when an open file is
/// unlinked. Their presence reveals actively-used files -- reconnaissance
/// signal for identifying overwrite targets (C702 Appendix A S A.8).
async fn check_silly_renames(nfs3: &Nfs3Client, root_fh: &FileHandle, export_path: &str, findings: &mut Vec<Finding>) {
    let Ok(entries) = nfs3.list_dir(root_fh, 2000).await else { return };
    let silly: Vec<&str> = entries.iter().map(|e| e.name.as_str()).filter(|n| is_silly_rename(n)).collect();
    if silly.is_empty() {
        return;
    }
    let display: Vec<&str> = silly.iter().copied().take(10).collect();
    let truncated = if silly.len() > 10 { format!(" (+{} more)", silly.len() - 10) } else { String::new() };
    findings.push(make_finding(
        &FindingSpec {
            id: "F-5.9",
            title: "Silly-rename files detected (open-unlinked indicator)",
            desc: "The export root contains .nfs* files created by Linux NFS clients \
                   when an open file is deleted. These indicate actively-used files \
                   that can be overwritten via NFS (ETXTBSY is not enforced over NFS, \
                   C702 Appendix A S A.8).",
            evidence: &format!("count={}, names={display:?}{truncated}", silly.len()),
            remediation: "Informational -- used files can be identified and targeted for content replacement.",
            export: Some(export_path),
        },
        Severity::Info,
    ));
}

fn is_silly_rename(name: &str) -> bool {
    let Some(rest) = name.strip_prefix(".nfs") else { return false };
    !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_hexdigit())
}

// --- Write verifier reboot oracle ---

/// Probe the server's write verifier twice to detect a reboot between probes.
///
/// A zero-count COMMIT (RFC 1813 S3.3.21) is a no-op on the data path but returns
/// the current `writeverf3`.  The server regenerates this opaque 8-byte value on
/// reboot (or when its volatile write cache is discarded). Two consecutive probes
/// that return the same verifier confirm the server has been up continuously;
/// a mismatch means a restart occurred between them.
async fn check_write_verifier(nfs3: &Nfs3Client, root_fh: &FileHandle, export_path: &str, findings: &mut Vec<Finding>) {
    let Ok(verf1) = nfs3.commit_verifier(root_fh).await else { return };
    let Ok(verf2) = nfs3.commit_verifier(root_fh).await else { return };

    let hex = |v: &[u8; 8]| -> String {
        use std::fmt::Write as _;
        v.iter().fold(String::with_capacity(16), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
    };

    if verf1 == verf2 {
        tracing::debug!(verifier = %hex(&verf1), export = export_path, "write verifier stable");
    } else {
        findings.push(make_finding(
            &FindingSpec {
                id: "F-5.8",
                title: "Write verifier changed between probes (server reboot detected)",
                desc: "Two consecutive zero-count COMMIT calls returned different writeverf3 \
                       values. Per RFC 1813 S3.3.21 the server regenerates this verifier on \
                       reboot. A verifier change means the server restarted (or flushed its \
                       volatile write cache) between the two probes. Any data previously \
                       written with UNSTABLE stability that was not re-committed is lost.",
                evidence: &format!("verf1={}, verf2={}", hex(&verf1), hex(&verf2)),
                remediation: "Investigate server stability. Clients with outstanding UNSTABLE \
                              writes must re-send them when the verifier changes.",
                export: Some(export_path),
            },
            Severity::Medium,
        ));
    }
}

// --- Null-filename server fingerprint ---

/// Fingerprint the NFS server implementation by sending a zero-length filename LOOKUP.
///
/// RFC 1813 sec. 3.3.3 says LOOKUP with a null-string filename must return
/// NFS3ERR_ACCES.  Linux knfsd rejects the request at the XDR decode layer
/// before the NFS procedure runs, surfacing as RPC GARBAGE_ARGS instead.
/// This one-call divergence is an unauthenticated, cheap implementation
/// discriminator:
///   - NFS3ERR_ACCES  -> spec-conformant (Solaris, NetApp, FreeBSD)
///   - GARBAGE_ARGS   -> Linux knfsd (XDR-level rejection)
///   - other NFS status / RPC error -> unknown / atypical implementation
async fn check_null_filename_fingerprint(nfs3: &Nfs3Client, root_fh: &FileHandle) -> String {
    use onc_rpc_client::RpcError;

    // Construct LOOKUP with a zero-length filename against the export root.
    let args = LOOKUP3args { what: diropargs3 { dir: root_fh.to_nfs_fh3(), name: filename3(Opaque::borrowed(b"")) } };

    match nfs3.lookup(&args).await {
        Ok(Nfs3Result::Err((nfsstat3::NFS3ERR_ACCES, _))) => {
            // Spec-conformant: server parsed the XDR and returned the mandated
            // status for a null-string filename (RFC 1813 sec. 3.3.3).
            "Spec-conformant (null-filename -> NFS3ERR_ACCES)".to_owned()
        },
        Ok(Nfs3Result::Err((status, _))) => {
            // Server parsed the XDR but returned a different NFS error.
            format!("Unknown (null-filename -> {status:?})")
        },
        Ok(Nfs3Result::Ok(_)) => {
            // Server accepted a zero-length filename LOOKUP -- very unusual.
            "Unknown (null-filename LOOKUP succeeded)".to_owned()
        },
        Ok(_) => "Indeterminate (unexpected result shape)".to_owned(),
        Err(RpcError::GarbageArgs) => {
            // Linux knfsd: the XDR decoder rejects the zero-length filename
            // before the NFS LOOKUP procedure runs.
            "Linux knfsd (null-filename -> GARBAGE_ARGS)".to_owned()
        },
        Err(e) => {
            // Transport or other RPC-level failure -- not diagnostic.
            tracing::debug!("null-filename fingerprint probe failed: {e}");
            format!("Indeterminate ({e})")
        },
    }
}

// --- Finding construction ---

/// Grouped string fields for `make_finding()`  --  keeps arg count under the clippy limit.
struct FindingSpec<'a> {
    id: &'a str,
    title: &'a str,
    desc: &'a str,
    evidence: &'a str,
    remediation: &'a str,
    export: Option<&'a str>,
}

/// Construct a Finding from a `FindingSpec` and severity.
///
/// Centralizes finding construction so all callsites are consistent.
fn make_finding(spec: &FindingSpec<'_>, sev: Severity) -> Finding {
    Finding { id: spec.id.to_owned(), title: spec.title.to_owned(), severity: sev, description: spec.desc.to_owned(), evidence: spec.evidence.to_owned(), remediation: spec.remediation.to_owned(), export: spec.export.map(str::to_owned) }
}

/// Get the current UTC timestamp as an ISO 8601 string.
///
/// Uses `std::time::SystemTime` to avoid adding a chrono dependency.
fn chrono_now() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs());
    // Format as YYYY-MM-DDTHH:MM:SSZ (manual, no chrono dep).
    let (year, month, day, hour, min, sec) = secs_to_datetime(secs);
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{min:02}:{sec:02}Z")
}

/// Decompose Unix epoch seconds into (year, month, day, hour, minute, second).
///
/// Implements the Gregorian calendar algorithm from the C standard library.
/// Only used for timestamp formatting  --  not a general-purpose calendar.
const fn secs_to_datetime(secs: u64) -> (u64, u64, u64, u64, u64, u64) {
    let sec = secs % 60;
    let min = (secs / 60) % 60;
    let hour = (secs / 3600) % 24;
    let days = secs / 86400;
    // Shift epoch from 1970-01-01 to 2000-03-01 for simpler leap-year math.
    let days400 = days + 719_468;
    let era = days400 / 146_097;
    let doe = days400 % 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let month_pos = (5 * doy + 2) / 153;
    let day = doy - (153 * month_pos + 2) / 5 + 1;
    let month = if month_pos < 10 { month_pos + 3 } else { month_pos - 9 };
    let year = if month <= 2 { year + 1 } else { year };
    (year, month, day, hour, min, sec)
}

/// Open a TCP connection to `target`, tunnelling through the SOCKS5 proxy when one is configured.
///
/// Lightweight wrapper so the WebNFS probe does not leak the operator's IP.
async fn connect_tcp(target: SocketAddr, proxy: Option<&str>) -> std::io::Result<tokio::net::TcpStream> {
    if let Some(p) = proxy {
        let proxy_addr = parse_proxy_addr(p).map_err(std::io::Error::other)?;
        socks5_connect(proxy_addr, target).await
    } else {
        tokio::net::TcpStream::connect(target).await
    }
}
