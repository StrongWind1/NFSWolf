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

/// Well-known shadow group GIDs per distro family.
/// Provided as defaults for `--test-read-gids` when no explicit GIDs given.
pub const SHADOW_GID_DEBIAN: u32 = 42;
pub const SHADOW_GID_SUSE: u32 = 15;

/// Well-known anonuid values that indicate misconfiguration.
pub const ANON_UID_ROOT: u32 = 0;
pub const ANON_UID_NOBODY: u32 = 65534;

/// Security finding from analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
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
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

/// Complete analysis result for a host.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisResult {
    pub host: String,
    pub timestamp: String,
    pub os_guess: Option<String>,
    pub nfs_versions: Vec<String>,
    pub exports: Vec<ExportAnalysis>,
    pub findings: Vec<Finding>,
}

/// Analysis of a single export.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportAnalysis {
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
pub struct FileAccessTest {
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

/// A single NFSv4 access control entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Nfs4Ace {
    pub ace_type: String,
    pub flags: u32,
    pub access_mask: u32,
    pub who: String,
}

/// Result of symlink attack precondition check.
#[derive(Debug, Clone, Serialize)]
pub struct SymlinkPrecondition {
    pub writable_path: String,
    pub owner_uid: u32,
    pub owner_gid: u32,
    pub mode: u32,
}

/// Result of escape confirmation via directory comparison.
#[derive(Debug, Clone, Serialize)]
pub struct EscapeConfirmation {
    pub root_entries: u32,
    pub export_entries: u32,
    pub confirmed: bool,
}

/// Squash configuration detected via write-and-check probing.
///
/// Creates a test file and inspects the resulting ownership to infer
/// the effective squash settings (anonuid, root_squash, all_squash).
#[derive(Debug, Clone, Serialize)]
pub struct SquashProbeResult {
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

/// Result of NFSv2 downgrade attack detection.
///
/// If a server supports NFSv2 alongside v3/v4, an attacker can explicitly
/// request v2 to bypass sec=krb5 or other v3+ security features.
/// See docs/issues/21-nfsv2-downgrade-attack.md.
#[derive(Debug, Clone, Serialize)]
pub struct VersionDowngradeResult {
    /// NFS versions the server advertises (e.g., [2, 3, 4]).
    pub supported_versions: Vec<u32>,
    /// Whether v2 is enabled alongside newer versions (the downgrade risk).
    pub v2_downgrade_possible: bool,
    /// Whether v3+ requires krb5 but v2 accepts AUTH_SYS (critical bypass).
    pub krb5_bypass_via_v2: bool,
}

/// Result of portmapper UDP amplification check.
///
/// Measures whether the portmapper responds to DUMP requests over UDP
/// and calculates the amplification factor. A factor >10x indicates
/// the host can be weaponized as a DDoS reflector.
/// See docs/issues/20-portmapper-amplification-ddos.md.
#[derive(Debug, Clone, Serialize)]
pub struct PortmapAmplificationResult {
    /// Whether UDP port 111 responded to a DUMP request.
    pub udp_responsive: bool,
    /// Size of the request packet (typically 68 bytes).
    pub request_bytes: u32,
    /// Size of the response packet.
    pub response_bytes: u32,
    /// Amplification factor (response / request).
    pub amplification_factor: f64,
    /// Number of registered RPC programs in the response.
    pub registered_programs: u32,
}

/// Result of `nohide` export option detection.
///
/// When `nohide` is set, the server exposes filesystems mounted beneath
/// the export point without requiring explicit export entries. This enables
/// traversal to sibling filesystems that may contain more sensitive data.
#[derive(Debug, Clone, Serialize)]
pub struct NohideExportResult {
    /// Export path checked.
    pub export_path: String,
    /// Whether sub-mount traversal was detected (nohide or crossmnt active).
    pub nohide_active: bool,
    /// Paths of sub-mounts discovered via traversal.
    pub discovered_submounts: Vec<String>,
}

/// Result of NIS (YP) service detection alongside NFS.
///
/// NIS is an RPC directory service frequently co-hosted on NFS servers.
/// When ypserv/ypbind are registered in portmapper, an attacker who discovers
/// the NIS domain name can extract password hashes, group memberships,
/// and host tables without authentication.
/// See docs/issues/22-nis-credential-extraction.md.
#[derive(Debug, Clone, Serialize)]
pub struct NisDetectionResult {
    /// Whether ypserv (program 100004) is registered in portmapper.
    pub ypserv_present: bool,
    /// Whether ypbind (program 100007) is registered in portmapper.
    pub ypbind_present: bool,
    /// NIS domain name if discovered.
    pub domain_name: Option<String>,
    /// Available NIS maps (e.g., passwd.byname, group.byname).
    pub available_maps: Vec<String>,
}

/// Result of portmapper bypass detection.
///
/// When port 111 is filtered but NFS ports are open, the firewall config
/// is ineffective  --  NFS can still be accessed by specifying ports directly
/// or tunneling through a local fake portmapper.
/// See docs/issues/23-portmapper-tunnel-bypass.md.
#[derive(Debug, Clone, Serialize)]
pub struct PortmapBypassResult {
    /// Whether port 111 is filtered/closed.
    pub portmapper_filtered: bool,
    /// Whether NFS port 2049 is open despite filtered portmapper.
    pub nfs_reachable: bool,
    /// Whether mountd is reachable on a discovered port.
    pub mountd_reachable: bool,
    /// Mountd port if discovered (via scanning or guessing).
    pub mountd_port: Option<u16>,
}

// --- AnalyzeConfig ---

use std::net::SocketAddr;
use std::sync::Arc;

use nfs3_types::nfs3::{CREATE3args, FSSTAT3args, GETATTR3args, READDIRPLUS3args, REMOVE3args, cookieverf3, createhow3, diropargs3, filename3, sattr3};
use nfs3_types::xdr_codec::Opaque;

use crate::engine::file_handle::{FileHandleAnalyzer, FsType, OsGuess, SigningStatus};
use crate::proto::auth::{AuthSys, Credential};
use crate::proto::circuit::CircuitBreaker;
use crate::proto::conn::ReconnectStrategy;
use crate::proto::mount::{ExportEntry, NfsMountClient};
use crate::proto::nfs3::client::Nfs3Client;
use crate::proto::nfs3::types::FileHandle;
use crate::proto::pool::{ConnectionPool, PoolKey};
use crate::proto::portmap::PortmapClient;
use crate::util::stealth::StealthConfig;

/// Configuration for a full analysis run against one host.
///
/// Every check the analyzer knows about runs unconditionally; the only
/// per-run knobs are which paths/UIDs/GIDs to use for the file-access
/// probes.
#[derive(Debug)]
pub struct AnalyzeConfig {
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
pub struct Analyzer {
    /// Pool-backed NFSv3 client.
    pub nfs3: Arc<Nfs3Client>,
    /// MOUNT protocol client for export enumeration and handle acquisition.
    pub mount: NfsMountClient,
    /// Portmapper client for service enumeration and amplification checks.
    pub portmap: PortmapClient,
}

impl std::fmt::Debug for Analyzer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Analyzer").finish_non_exhaustive()
    }
}

impl Analyzer {
    /// Construct an Analyzer from pre-built clients.
    #[must_use]
    pub const fn new(nfs3: Arc<Nfs3Client>, mount: NfsMountClient, portmap: PortmapClient) -> Self {
        Self { nfs3, mount, portmap }
    }

    /// Run all enabled security checks and return a consolidated result.
    ///
    /// Enumerates exports via MOUNT, acquires root handles, and dispatches
    /// per-export and global checks. Returns findings even on partial failure.
    pub async fn analyze(&self, config: &AnalyzeConfig) -> anyhow::Result<AnalysisResult> {
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
        // NLM service detection (F-6.1): checks portmapper for program 100021.
        run_nlm_check(&self.portmap, addr, &mut findings).await;
        // NSM/statd detection (F-6.1 corollary): confirms whether statd is actively monitoring.
        run_nsm_check(&self.portmap, addr, &config.host, &mut findings).await;

        // Per-export checks.
        let exports = self.mount.list_exports(addr).await.unwrap_or_default();
        check_export_acls(&exports, &mut findings);

        let mut export_analyses: Vec<ExportAnalysis> = Vec::new();
        for entry in &exports {
            let ea = self.analyze_export(config, addr, entry, &mut findings).await;
            export_analyses.push(ea);
        }

        // OS guess from first valid handle.
        let os_guess = export_analyses.iter().find_map(|ea| if ea.file_handle.is_empty() { None } else { FileHandle::from_hex(&ea.file_handle).ok() });
        let os_string = os_guess.map(|fh| check_os_fingerprint(&fh));

        Ok(AnalysisResult { host: config.host.clone(), timestamp, os_guess: os_string, nfs_versions: version_strings, exports: export_analyses, findings })
    }

    /// Analyze a single export: mount it, run per-export checks, return the result.
    async fn analyze_export(&self, config: &AnalyzeConfig, addr: SocketAddr, entry: &ExportEntry, findings: &mut Vec<Finding>) -> ExportAnalysis {
        let mut ea = ExportAnalysis { path: entry.path.clone(), allowed_hosts: entry.allowed_hosts.clone(), auth_methods: Vec::new(), writable: false, no_root_squash: None, escape_possible: false, file_handle: String::new(), file_access_tests: Vec::new(), nfs4_acls: Vec::new() };

        let mount_res = match self.mount.mount(addr, &entry.path).await {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!("Failed to mount {}: {e}", entry.path);
                return ea;
            },
        };

        // Build a per-export NFS client so pool checkout uses the correct MOUNT path.
        // The global self.nfs3 has export="/" which fails on servers with restricted exports.
        let export_nfs3 = {
            let uid = self.nfs3.uid();
            let gid = self.nfs3.gid();
            let pool = Arc::new(ConnectionPool::default_config());
            let circuit = Arc::new(CircuitBreaker::default_config());
            let cred = Credential::Sys(AuthSys::with_groups(uid, gid, &[gid], "nfswolf"));
            let key = PoolKey { host: addr, export: entry.path.clone(), uid, gid };
            Arc::new(Nfs3Client::new(pool, key, circuit, StealthConfig::none(), cred, ReconnectStrategy::Persistent))
        };

        let fh = mount_res.handle;
        ea.file_handle = fh.to_hex();
        ea.auth_methods = mount_res
            .auth_flavors
            .iter()
            .map(|&f| match f {
                0 => "AUTH_NONE".to_owned(),
                1 => "AUTH_SYS".to_owned(),
                2 => "AUTH_SHORT".to_owned(),
                3 => "AUTH_DH".to_owned(),
                6 => "RPCSEC_GSS".to_owned(),
                _ => format!("flavor({f})"),
            })
            .collect();

        check_auth_methods(&entry.path, &mount_res.auth_flavors, findings);
        // NFSv4 SECINFO check: verify auth methods from the NFSv4 perspective (F-3.4).
        // Complements check_auth_methods (which uses MOUNT auth flavors) with a live NFSv4 probe.
        check_nfs4_secinfo(addr, &entry.path, findings).await;
        check_windows_signing(&fh, &entry.path, findings);
        check_handle_entropy(&fh, &entry.path, findings);

        // Export escape check (F-2.x).
        ea.escape_possible = check_escape(&export_nfs3, &fh, &entry.path, findings).await;

        // BTRFS subvolume escape (F-2.4)  --  if handle fingerprints as BTRFS.
        check_btrfs_escape(&export_nfs3, &fh, &entry.path, findings).await;

        // Bind mount escape (F-2.6)  --  if fsid from FSSTAT differs from handle-derived fsid.
        check_bind_mount_escape(&export_nfs3, &fh, &entry.path, findings).await;

        // nohide/crossmnt detection (F-7.3).
        check_nohide(&export_nfs3, &fh, &entry.path, findings).await;

        // Symlink attack preconditions (F-4.4)  --  writable dirs owned by non-root.
        check_symlink_preconditions(&export_nfs3, &fh, &entry.path, findings).await;

        // Squash probes write a small payload, then clean up.
        check_no_root_squash(&export_nfs3, &fh, &entry.path, findings).await;
        check_squash_config(&export_nfs3, &fh, &entry.path, findings).await;
        check_insecure_port(addr, &entry.path, findings).await;

        // File access tests from --test-read paths (F-1.3: auxiliary group injection).
        for path in &config.test_paths {
            for &uid in &config.test_uids {
                for &gid in &config.test_gids {
                    let test = probe_file_access(&export_nfs3, &fh, path, uid, gid).await;
                    if test.readable {
                        findings.push(make_finding(
                            &FindingSpec {
                                // F-1.3: file readable via crafted UID/GID credential
                                // (most commonly shadow GID injection, RFC 2623 S2.1).
                                id: "F-1.3",
                                title: "Sensitive file readable via UID/GID credential",
                                desc: &format!(
                                    "File {path} readable as uid={uid} gid={gid}. \
                                               AUTH_SYS credential spoofing (RFC 2623 S2.1) \
                                               allows any client to claim any UID/GID."
                                ),
                                evidence: test.preview.as_deref().unwrap_or("(no preview)"),
                                remediation: "Use sec=krb5p to authenticate credentials. \
                                              Set root_squash and restrict shadow GID membership.",
                                export: Some(&entry.path),
                            },
                            Severity::Critical,
                        ));
                    }
                    ea.file_access_tests.push(test);
                }
            }
        }

        ea
    }
}

// --- Per-export checks ---

/// Check export ACLs for world-accessible exports (wildcard or empty host list).
///
/// An empty allowed_hosts list means the server uses `*` implicitly.
/// Wildcards like `*` or `0.0.0.0/0` also flag as open.
fn check_export_acls(exports: &[ExportEntry], findings: &mut Vec<Finding>) {
    for export in exports {
        let is_open = export.allowed_hosts.is_empty() || export.allowed_hosts.iter().any(|h| h == "*" || h == "0.0.0.0/0" || h == "::/0");
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
    }
}

/// Flag exports that support only AUTH_SYS (flavor 1) with no Kerberos.
///
/// AUTH_SYS is trivially spoofable  --  the server cannot verify UID/GID claims.
/// RFC 2623 S2.1 documents this weakness.
fn check_auth_methods(export_path: &str, auth_flavors: &[u32], findings: &mut Vec<Finding>) {
    // Flavor 6 = RPCSEC_GSS (Kerberos). If absent, only AUTH_SYS is available.
    let has_kerberos = auth_flavors.contains(&6);
    let has_auth_sys = auth_flavors.contains(&1);
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
    }
}

/// Attempt to escape the export by constructing a handle targeting the filesystem root.
///
/// Uses `FileHandleAnalyzer::construct_escape_handle` to build an out-of-export handle,
/// then confirms it by comparing READDIRPLUS results on the escape handle vs the export.
/// Returns true if escape is confirmed. Finding is appended only on success.
/// Test whether the filesystem root is reachable via a crafted handle (F-2.1).
///
/// Tries all known root-inode candidates for the detected filesystem:
///   - XFS: inode 128 (v5 default) and inode 64 (v4 / -i size=256)
///   - ext4: inode 2
///   - BTRFS: subvolume 256
///
/// For each candidate, issues READDIRPLUS and compares the entry count to the
/// export root.  A different count (or successful listing on the escape handle)
/// confirms the escape.  Using READDIRPLUS rather than GETATTR catches servers
/// that accept GETATTR on the root but refuse it on the export.
async fn check_escape(nfs3: &Nfs3Client, export_fh: &FileHandle, export_path: &str, findings: &mut Vec<Finding>) -> bool {
    let export_count = count_readdirplus(nfs3, export_fh).await;

    // Build the full candidate list: XFS 128+64, then generic escape, then BTRFS.
    let mut candidates = FileHandleAnalyzer::construct_xfs_escape_candidates(export_fh);
    if candidates.is_empty()
        && let Some(r) = FileHandleAnalyzer::construct_escape_handle(export_fh)
    {
        candidates.push(r);
    }
    // Also try BTRFS subvolumes (first 4 are cheap).
    candidates.extend(FileHandleAnalyzer::construct_btrfs_subvol_handles(export_fh, 4));

    for candidate in candidates {
        let root_count = count_readdirplus(nfs3, &candidate.root_handle).await;
        let confirmed = root_count.is_some() && root_count != export_count;
        if confirmed {
            findings.push(make_finding(
                &FindingSpec {
                    id: "F-2.1",
                    title: "Export escape possible  --  filesystem root accessible via crafted handle",
                    desc: "subtree_check is disabled (Linux default). An attacker can craft a file \
                           handle targeting any inode on the filesystem, bypassing export boundaries.",
                    evidence: &format!("export_entries={}, root_entries={}, inode={}, fs_type={:?}, confidence={:.0}%", export_count.unwrap_or(0), root_count.unwrap_or(0), candidate.inode_number, candidate.fs_type, candidate.confidence * 100.0,),
                    remediation: "Enable subtree_check in /etc/exports (caution  --  impacts rename correctness).",
                    export: Some(export_path),
                },
                Severity::Critical,
            ));
            return true;
        }
    }
    false
}

/// Count READDIRPLUS entries for a file handle; returns None on any error.
async fn count_readdirplus(nfs3: &Nfs3Client, fh: &FileHandle) -> Option<u32> {
    let args = READDIRPLUS3args { dir: fh.to_nfs_fh3(), cookie: 0, cookieverf: cookieverf3([0u8; 8]), dircount: 4096, maxcount: 65536 };
    let res = nfs3.readdirplus(&args).await.ok()?;
    if let nfs3_types::nfs3::Nfs3Result::Ok(ok) = res {
        let count = u32::try_from(ok.reply.entries.0.len()).unwrap_or(u32::MAX);
        Some(count)
    } else {
        None
    }
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

/// Check Windows file handle signing status.
///
/// All-zero HMAC bytes mean signing is disabled  --  arbitrary handle forgery is possible.
fn check_windows_signing(fh: &FileHandle, export_path: &str, findings: &mut Vec<Finding>) {
    if FileHandleAnalyzer::fingerprint_os(fh) != OsGuess::Windows {
        return;
    }
    if FileHandleAnalyzer::check_windows_signing(fh) == SigningStatus::Disabled {
        findings.push(make_finding(
            &FindingSpec {
                id: "F-2.3",
                title: "Windows NFS server has handle signing disabled",
                desc: "The NFS server appears to be Windows (handle size and format match). \
                       The HMAC signature bytes in the file handle are all zero, meaning handle \
                       signing is disabled. Any handle value can be forged to access arbitrary files.",
                evidence: &format!("handle_hex={}", fh.to_hex()),
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

/// Probe whether a specific file is readable with given uid/gid credentials.
///
/// Walks the path components via LOOKUP, then attempts READ on the final file.
/// Returns a FileAccessTest recording whether the read succeeded and a preview.
async fn probe_file_access(nfs3: &Nfs3Client, root_fh: &FileHandle, path: &str, uid: u32, gid: u32) -> FileAccessTest {
    let mut result = FileAccessTest { path: path.to_owned(), uid, gid, readable: false, preview: None, via_escape: false };

    // Create a client with the specified credentials so the server sees
    // the correct uid/gid for permission checks.
    let test_client = nfs3.with_credential(Credential::Sys(AuthSys::with_groups(uid, gid, &[gid], "nfswolf")), uid, gid);

    // Walk path components, starting from root_fh.
    let fh = walk_path(&test_client, root_fh, path).await;
    let Some(target_fh) = fh else {
        return result;
    };

    // Attempt READ of up to 128 bytes.
    let read_args = nfs3_types::nfs3::READ3args { file: target_fh.to_nfs_fh3(), offset: 0, count: 128 };
    let Ok(read_res) = test_client.read(&read_args).await else {
        return result;
    };

    if let nfs3_types::nfs3::Nfs3Result::Ok(ok) = read_res {
        result.readable = true;
        let bytes = ok.data.as_ref();
        result.preview = Some(String::from_utf8_lossy(bytes).chars().take(64).collect());
    }

    result
}

/// Walk a slash-separated path using LOOKUP, starting from root_fh.
/// Returns the file handle of the final component, or None on any error.
async fn walk_path(nfs3: &Nfs3Client, root_fh: &FileHandle, path: &str) -> Option<FileHandle> {
    let mut current = root_fh.clone();
    for component in path.split('/').filter(|c| !c.is_empty()) {
        let args = nfs3_types::nfs3::LOOKUP3args { what: diropargs3 { dir: current.to_nfs_fh3(), name: filename3(Opaque::owned(component.as_bytes().to_vec())) } };
        let res = nfs3.lookup(&args).await.ok()?;
        if let nfs3_types::nfs3::Nfs3Result::Ok(ok) = res {
            current = FileHandle::from_nfs_fh3(&ok.object);
        } else {
            return None;
        }
    }
    Some(current)
}

/// Format OS and filesystem fingerprint as a human-readable string.
fn check_os_fingerprint(fh: &FileHandle) -> String {
    let os = FileHandleAnalyzer::fingerprint_os(fh);
    let fs = FileHandleAnalyzer::fingerprint_fs(fh);
    format!("{os:?}/{fs:?}")
}

// --- Missing check implementations ---

/// Check NSM/statd service registration and probe live state (F-6.1 corollary).
///
/// NSM (program 100024) runs alongside NLM to provide crash/reboot notification.
/// When NSM is exposed AND the server reports an active reboot counter, this
/// confirms the host has live NLM-based lock state that can be exploited via
/// lock theft or denial-of-service (F-6.1).
async fn run_nsm_check(portmap: &PortmapClient, addr: SocketAddr, host: &str, findings: &mut Vec<Finding>) {
    use crate::proto::nsm::client::NsmClient;

    let Ok(Some(nsm_port)) = portmap.detect_nsm(addr).await else { return };
    let nsm_addr = SocketAddr::new(addr.ip(), nsm_port);

    // SM_STAT: check whether the server is actively monitoring us.
    // state counter: odd = reboot in progress, even = stable.
    let stat = NsmClient::probe_stat(nsm_addr, host).await;
    let (monitoring_msg, evidence) = match stat {
        Some(res) if res.stat == 1 => ("NSM actively monitoring  --  confirms live NLM lock state", format!("NSM port={nsm_port} stat=monitoring state={}", res.state)),
        Some(res) => ("NSM registered but not monitoring  --  lock state may be stale", format!("NSM port={nsm_port} stat=not-monitoring state={}", res.state)),
        None => ("NSM registered in portmapper but did not respond", format!("NSM port={nsm_port} (unresponsive)")),
    };
    findings.push(make_finding(
        &FindingSpec {
            id: "F-6.1",
            title: "NSM/statd exposed  --  lock state enumerable",
            desc: &format!(
                "NSM (statd, program 100024) is registered at port {nsm_port}. {monitoring_msg}. \
                 An attacker can query SM_STAT to fingerprint lock clients and reboot state, \
                 or issue SM_MON/SM_UNMON to disrupt crash recovery.",
            ),
            evidence: &evidence,
            remediation: "Block portmapper (port 111) and statd port from untrusted hosts. \
                          Upgrade to NFSv4 which does not use NSM/statd.",
            export: None,
        },
        Severity::Low,
    ));
}

/// Check NLM service registration in portmapper (F-6.1).
///
/// NLM (program 100021) exposes advisory lock operations. An attacker can
/// forge the caller_name string (RFC 1813 S6.1.4) to release other clients'
/// locks or exhaust the server's lock table. Detection only  --  no lock probing.
async fn run_nlm_check(portmap: &PortmapClient, addr: SocketAddr, findings: &mut Vec<Finding>) {
    let Ok(Some(port)) = portmap.detect_nlm(addr).await else { return };
    findings.push(make_finding(
        &FindingSpec {
            id: "F-6.1",
            title: "NLM service exposed  --  lock exhaustion and lock theft possible",
            desc: "The NLM daemon (program 100021) is registered in portmapper. \
                   NLM's caller_name is a self-reported string (RFC 1813 S6.1.4), \
                   so any client can forge it to release or steal other clients' locks.",
            evidence: &format!("NLM registered at port {port}"),
            remediation: "Restrict portmapper access to trusted hosts. \
                          Upgrade to NFSv4 which uses stateful lease-based locking.",
            export: None,
        },
        Severity::Medium,
    ));
}

/// Check for BTRFS subvolume handle construction (F-2.4).
///
/// When the export handle fingerprints as BTRFS, additional subvolume
/// handles can be constructed that may resolve to sub-trees outside the export.
async fn check_btrfs_escape(nfs3: &Nfs3Client, export_fh: &FileHandle, export_path: &str, findings: &mut Vec<Finding>) {
    if FileHandleAnalyzer::fingerprint_fs(export_fh) != FsType::Btrfs {
        return;
    }
    let candidates = FileHandleAnalyzer::construct_btrfs_subvol_handles(export_fh, 16);
    let mut hits = 0u32;
    for candidate in &candidates {
        if handle_exists(nfs3, &candidate.root_handle).await {
            hits += 1;
        }
    }
    if hits > 0 {
        findings.push(make_finding(
            &FindingSpec {
                id: "F-2.4",
                title: "BTRFS subvolume handles resolve outside export boundary",
                desc: "The export filesystem is BTRFS. Constructed subvolume handles \
                       resolved successfully, indicating sub-trees outside the export \
                       are accessible via crafted handles.",
                evidence: &format!("candidates_tried={}, handles_resolved={hits}", candidates.len()),
                remediation: "Use subtree_check or restrict to a single BTRFS subvolume per export.",
                export: Some(export_path),
            },
            Severity::High,
        ));
    }
}

/// Check for bind mount export escape (F-2.6).
///
/// If FSSTAT returns an fsid that differs from what the export handle implies,
/// the export is a bind mount over a different filesystem  --  the underlying
/// filesystem root may be reachable via a crafted handle.
async fn check_bind_mount_escape(nfs3: &Nfs3Client, export_fh: &FileHandle, export_path: &str, findings: &mut Vec<Finding>) {
    let args = FSSTAT3args { fsroot: export_fh.to_nfs_fh3() };
    let Ok(res) = nfs3.fsstat(&args).await else { return };
    let nfs3_types::nfs3::Nfs3Result::Ok(ok) = res else { return };

    // Extract fsid from the post-op attributes on the root object.
    // post_op_attr is Nfs3Option<fattr3>  --  use match, not .map().
    let server_fsid = match ok.obj_attributes {
        nfs3_types::nfs3::Nfs3Option::Some(ref a) => a.fsid,
        nfs3_types::nfs3::Nfs3Option::None => 0,
    };
    if server_fsid == 0 {
        return; // server didn't include attributes
    }

    // Compare with the fsid embedded in the file handle (bytes 4..12 on Linux ext4/xfs).
    // If they differ, this export is a bind mount.
    let handle_bytes = export_fh.as_bytes();
    if handle_bytes.len() >= 12 {
        let handle_fsid = handle_bytes.get(4..12).and_then(|s| <[u8; 8]>::try_from(s).ok()).map_or(0, u64::from_le_bytes);
        if handle_fsid != 0 && handle_fsid != server_fsid {
            findings.push(make_finding(
                &FindingSpec {
                    id: "F-2.6",
                    title: "Bind mount detected  --  underlying filesystem may be accessible",
                    desc: "The FSSTAT fsid does not match the fsid in the export file handle. \
                           This indicates the export is a bind mount. The underlying filesystem \
                           root may be reachable by constructing a handle with the real fsid.",
                    evidence: &format!("handle_fsid=0x{handle_fsid:016x}, server_fsid=0x{server_fsid:016x}"),
                    remediation: "Avoid bind-mounting sensitive filesystems into exports. \
                                  Enable subtree_check.",
                    export: Some(export_path),
                },
                Severity::High,
            ));
        }
    }
}

/// Detect nohide/crossmnt sub-mount exposure (F-7.3, opt-in).
///
/// Performs READDIRPLUS on the export root and then FSSTAT on any directory
/// entry whose file handle resolves. A different fsid indicates a sub-mount
/// (nohide/crossmnt is active). Per RFC 1813 S3.3.3, servers should not
/// allow LOOKUP to cross mount points by default.
async fn check_nohide(nfs3: &Nfs3Client, root_fh: &FileHandle, export_path: &str, findings: &mut Vec<Finding>) {
    let rdp_args = READDIRPLUS3args { dir: root_fh.to_nfs_fh3(), cookie: 0, cookieverf: cookieverf3([0u8; 8]), dircount: 4096, maxcount: 65536 };
    let Ok(res) = nfs3.readdirplus(&rdp_args).await else { return };
    let nfs3_types::nfs3::Nfs3Result::Ok(ok) = res else { return };

    // FSSTAT on the export root to get its fsid.
    let root_stat = nfs3.fsstat(&FSSTAT3args { fsroot: root_fh.to_nfs_fh3() }).await.ok();
    let root_fsid = root_stat
        .and_then(|r| {
            if let nfs3_types::nfs3::Nfs3Result::Ok(ok) = r {
                match ok.obj_attributes {
                    nfs3_types::nfs3::Nfs3Option::Some(ref a) => Some(a.fsid),
                    nfs3_types::nfs3::Nfs3Option::None => None,
                }
            } else {
                None
            }
        })
        .unwrap_or(0);

    let mut submounts: Vec<String> = Vec::new();
    for entry in &ok.reply.entries.0 {
        // name_handle is Nfs3Option<nfs_fh3>  --  use match, not Some().
        let entry_fh = match &entry.name_handle {
            nfs3_types::nfs3::Nfs3Option::Some(fh_raw) => FileHandle::from_nfs_fh3(fh_raw),
            nfs3_types::nfs3::Nfs3Option::None => continue,
        };
        let stat_res = nfs3.fsstat(&FSSTAT3args { fsroot: entry_fh.to_nfs_fh3() }).await.ok();
        if let Some(nfs3_types::nfs3::Nfs3Result::Ok(st)) = stat_res {
            let entry_fsid = match st.obj_attributes {
                nfs3_types::nfs3::Nfs3Option::Some(ref a) => a.fsid,
                nfs3_types::nfs3::Nfs3Option::None => continue,
            };
            if root_fsid != 0 && entry_fsid != root_fsid {
                let name = String::from_utf8_lossy(entry.name.0.as_ref()).to_string();
                submounts.push(name);
            }
        }
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

/// Detect writable directories owned by non-root  --  symlink attack preconditions (F-4.4).
///
/// A writable directory in an export owned by a non-root UID is a prerequisite
/// for symlink-based escape attacks. The attacker can replace a directory entry
/// with a symlink pointing to a privileged path.
async fn check_symlink_preconditions(nfs3: &Nfs3Client, root_fh: &FileHandle, export_path: &str, findings: &mut Vec<Finding>) {
    let args = READDIRPLUS3args { dir: root_fh.to_nfs_fh3(), cookie: 0, cookieverf: cookieverf3([0u8; 8]), dircount: 4096, maxcount: 65536 };
    let Ok(res) = nfs3.readdirplus(&args).await else { return };
    let nfs3_types::nfs3::Nfs3Result::Ok(ok) = res else { return };

    for entry in &ok.reply.entries.0 {
        // name_attributes is Nfs3Option<fattr3>  --  use match, not Some().
        let attrs = match &entry.name_attributes {
            nfs3_types::nfs3::Nfs3Option::Some(a) => a,
            nfs3_types::nfs3::Nfs3Option::None => continue,
        };
        // World-writable directory (mode & 0o002 != 0) not owned by root.
        let is_dir = attrs.type_ == nfs3_types::nfs3::ftype3::NF3DIR;
        let world_writable = (attrs.mode & 0o002) != 0;
        let not_root_owned = attrs.uid != 0;
        if is_dir && world_writable && not_root_owned {
            let name = String::from_utf8_lossy(entry.name.0.as_ref()).to_string();
            findings.push(make_finding(
                &FindingSpec {
                    id: "F-4.4",
                    title: "World-writable directory owned by non-root  --  symlink attack possible",
                    desc: "A world-writable directory not owned by root is present in the export. \
                           An attacker with write access can replace directory entries with symlinks \
                           pointing to privileged paths outside the export.",
                    evidence: &format!("path={export_path}/{name} mode={:04o} uid={}", attrs.mode, attrs.uid),
                    remediation: "Remove world-write permission from directories in NFS exports.",
                    export: Some(export_path),
                },
                Severity::High,
            ));
        }
    }
}

/// Probe for no_root_squash by creating a test file as uid=0 (F-4.1, opt-in).
///
/// Creates a temporary file with AUTH_SYS uid=0 credentials. If the resulting
/// file is owned by root (GETATTR uid=0), root_squash is disabled.
/// Per RFC 1813 S4.4 and RFC 2623 S2.5, uid=0 should be remapped by default.
async fn check_no_root_squash(nfs3: &Nfs3Client, dir_fh: &FileHandle, export_path: &str, findings: &mut Vec<Finding>) {
    let probe_name = b".nfswolf_root_probe";
    let root_client = nfs3.with_credential(Credential::Sys(AuthSys::with_groups(0, 0, &[], "nfswolf")), 0, 0);

    let create_args = CREATE3args { where_: diropargs3 { dir: dir_fh.to_nfs_fh3(), name: filename3(Opaque::borrowed(probe_name)) }, how: createhow3::UNCHECKED(sattr3::default()) };
    let Ok(create_res) = root_client.create(&create_args).await else { return };
    let nfs3_types::nfs3::Nfs3Result::Ok(created) = create_res else { return };

    // GETATTR to check the resulting ownership.
    let file_uid = if let nfs3_types::nfs3::Nfs3Option::Some(ref fh) = created.obj {
        let fh = FileHandle::from_nfs_fh3(fh);
        let ga_args = GETATTR3args { object: fh.to_nfs_fh3() };
        nfs3.getattr(&ga_args).await.ok().and_then(|r| if let nfs3_types::nfs3::Nfs3Result::Ok(ok) = r { Some(ok.obj_attributes.uid) } else { None })
    } else {
        None
    };

    // Always attempt cleanup regardless of getattr result.
    let _ = root_client.remove(&REMOVE3args { object: diropargs3 { dir: dir_fh.to_nfs_fh3(), name: filename3(Opaque::borrowed(probe_name)) } }).await;

    if file_uid == Some(0) {
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

/// Probe squash configuration by creating a test file as uid=99999 (F-7.5, opt-in).
///
/// Creates a temporary file with a non-root arbitrary UID and inspects the
/// resulting ownership to detect all_squash, anonuid=0 (critical), and
/// other squash misconfiguration (RFC 1813 S4.4, RFC 2623 S2.5).
async fn check_squash_config(nfs3: &Nfs3Client, dir_fh: &FileHandle, export_path: &str, findings: &mut Vec<Finding>) {
    const PROBE_UID: u32 = 99_999;
    let probe_name = b".nfswolf_squash_probe";
    let probe_client = nfs3.with_credential(Credential::Sys(AuthSys::with_groups(PROBE_UID, PROBE_UID, &[], "nfswolf")), PROBE_UID, PROBE_UID);

    let create_args = CREATE3args { where_: diropargs3 { dir: dir_fh.to_nfs_fh3(), name: filename3(Opaque::borrowed(probe_name)) }, how: createhow3::UNCHECKED(sattr3::default()) };
    let Ok(create_res) = probe_client.create(&create_args).await else { return };
    let nfs3_types::nfs3::Nfs3Result::Ok(created) = create_res else { return };

    let observed_uid = if let nfs3_types::nfs3::Nfs3Option::Some(ref fh) = created.obj {
        let fh = FileHandle::from_nfs_fh3(fh);
        let ga_args = GETATTR3args { object: fh.to_nfs_fh3() };
        nfs3.getattr(&ga_args).await.ok().and_then(|r| if let nfs3_types::nfs3::Nfs3Result::Ok(ok) = r { Some(ok.obj_attributes.uid) } else { None })
    } else {
        None
    };

    // Cleanup probe file before reporting.
    let _ = probe_client.remove(&REMOVE3args { object: diropargs3 { dir: dir_fh.to_nfs_fh3(), name: filename3(Opaque::borrowed(probe_name)) } }).await;

    let Some(uid) = observed_uid else { return };
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
    }
}

/// Detect the `insecure` export option by connecting from an unprivileged port (F-7.2).
///
/// If the server accepts MOUNT from a source port >= 1024, the `insecure` export
/// option is active. Per RFC 2623 S2.1, the traditional minimal protection of
/// requiring privileged source ports is removed.
async fn check_insecure_port(addr: SocketAddr, export_path: &str, findings: &mut Vec<Finding>) {
    // Try listing exports from an unprivileged port. NfsMountClient uses
    // TokioConnector which binds to an OS-assigned ephemeral port (>= 1024).
    // If the server rejects the unprivileged-port connection (drops TCP or
    // returns an RPC error), `secure` is in effect and we return early.
    let mount = NfsMountClient::new();
    let Ok(_exports) = mount.list_exports(addr).await else {
        // Server rejected the unprivileged-port connection  --  secure is active.
        return;
    };

    // The server accepted an RPC call from an unprivileged port  --  `insecure`
    // export option is active.
    findings.push(make_finding(
        &FindingSpec {
            id: "F-7.2",
            title: "`insecure` export option active  --  unprivileged port accepted",
            desc: "The server accepted a MOUNT RPC call from a source port >= 1024. \
                   The `insecure` export option is set, removing the minimal protection \
                   that requires clients to hold root privilege to connect (RFC 2623 S2.1).",
            evidence: "MOUNT EXPORT RPC succeeded from unprivileged port",
            remediation: "Remove the 'insecure' option from /etc/exports. \
                          Use sec=krb5 for real authentication.",
            export: Some(export_path),
        },
        Severity::Medium,
    ));
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
pub fn infer_squash_mode(observed_uid: u32, probe_uid: u32) -> SquashProbeResult {
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

/// Verify a file handle exists on the server via GETATTR.
/// Returns true if the server responds with a success (handle is valid).
async fn handle_exists(nfs3: &Nfs3Client, fh: &FileHandle) -> bool {
    let args = GETATTR3args { object: fh.to_nfs_fh3() };
    nfs3.getattr(&args).await.is_ok_and(|r| matches!(r, nfs3_types::nfs3::Nfs3Result::Ok(_)))
}

/// Probe NFSv4 SECINFO for an export path to detect AUTH_SYS-only access via NFSv4.
///
/// SECINFO (RFC 7530 S18.29) returns the actual required auth methods per directory,
/// independent of the NFSv3 MOUNT auth flavor list.  AUTH_SYS-only NFSv4 means
/// an attacker can spoof arbitrary UID/GID credentials even when accessing via NFSv4
/// (F-3.4: TLS downgrade not enforced  --  RPCSEC_GSS not required).
///
/// Best-effort: silently returns on timeout or PROG_MISMATCH (NFSv3-only server).
async fn check_nfs4_secinfo(addr: SocketAddr, export_path: &str, findings: &mut Vec<Finding>) {
    use crate::proto::nfs4::compound::Nfs4DirectClient;
    use crate::proto::nfs4::types::{ArgOp, ResOpData};

    let nfs4_addr = SocketAddr::new(addr.ip(), 2049);
    let timeout = std::time::Duration::from_secs(5);

    let connect = tokio::time::timeout(timeout, Nfs4DirectClient::connect(nfs4_addr)).await;
    let Ok(Ok(mut client)) = connect else { return };

    // Parse export path into LOOKUP chain components and SECINFO target.
    // "/srv/nfs" -> parent_components=["srv"], secinfo_name="nfs"
    let components: Vec<&str> = export_path.trim_start_matches('/').split('/').filter(|c| !c.is_empty()).collect();
    if components.is_empty() {
        return; // root export: SECINFO on "/" is not meaningful
    }
    let Some((secinfo_name, parent)) = components.split_last() else { return };

    let mut ops: Vec<ArgOp> = Vec::with_capacity(parent.len() + 2);
    ops.push(ArgOp::Putrootfh);
    for &c in parent {
        ops.push(ArgOp::Lookup(c.to_owned()));
    }
    ops.push(ArgOp::Secinfo((*secinfo_name).to_owned()));

    let result = tokio::time::timeout(timeout, client.compound(ops)).await;
    let Ok(Ok(res)) = result else { return };

    if res.status != 0 {
        // Server rejected SECINFO (e.g. PROG_MISMATCH, WRONGSEC, or path not found).
        return;
    }

    let flavors = res.results.last().and_then(|op| if let ResOpData::SecFlavors(f) = &op.data { Some(f.as_slice()) } else { None });
    let Some(flavors) = flavors else { return };

    let has_kerberos = flavors.contains(&6); // 6 = RPCSEC_GSS (RFC 7530 S3.2.1)
    let has_auth_sys = flavors.contains(&1); // 1 = AUTH_SYS (RFC 5531 S14)

    if has_auth_sys && !has_kerberos {
        findings.push(make_finding(
            &FindingSpec {
                id: "F-3.4",
                title: "NFSv4 export accepts AUTH_SYS with no Kerberos (TLS downgrade not enforced)",
                desc: &format!(
                    "NFSv4 SECINFO for export {export_path} returns AUTH_SYS (flavor 1) \
                     with no RPCSEC_GSS (flavor 6). An attacker can spoof arbitrary UID/GID \
                     credentials via NFSv4 COMPOUND without Kerberos. \
                     RFC 9289 S1: NFS-over-TLS and RPCSEC_GSS are opt-in and rarely deployed.",
                ),
                evidence: &format!("SECINFO flavors={flavors:?}"),
                remediation: "Configure `sec=krb5p` in /etc/exports to require Kerberos authentication.",
                export: Some(export_path),
            },
            Severity::High,
        ));
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
    let secs = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    // Format as YYYY-MM-DDTHH:MM:SSZ (manual, no chrono dep).
    let (y, mo, d, h, mi, s) = secs_to_datetime(secs);
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{mi:02}:{s:02}Z")
}

/// Decompose Unix epoch seconds into (year, month, day, hour, minute, second).
///
/// Implements the Gregorian calendar algorithm from the C standard library.
/// Only used for timestamp formatting  --  not a general-purpose calendar.
const fn secs_to_datetime(secs: u64) -> (u64, u64, u64, u64, u64, u64) {
    let s = secs % 60;
    let m = (secs / 60) % 60;
    let h = (secs / 3600) % 24;
    let days = secs / 86400;
    // Shift epoch from 1970-01-01 to 2000-03-01 for simpler leap-year math.
    let days400 = days + 719_468;
    let era = days400 / 146_097;
    let doe = days400 % 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let mo = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if mo <= 2 { y + 1 } else { y };
    (y, mo, d, h, m, s)
}
