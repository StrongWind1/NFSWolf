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

use crate::engine::file_handle::{FileHandleAnalyzer, FsType, OsGuess, SigningStatus};
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
        Self { nfs3, mount, portmap, proxy: None, stealth: StealthConfig::none(), pool, circuit, hostname, aux_gids }
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

        // Per-export checks.
        let exports = self.mount.list_exports(addr).await.unwrap_or_default();
        check_export_acls(&exports, &mut findings);

        let mut export_analyses: Vec<ExportAnalysis> = Vec::new();
        let mut impl_fingerprint: Option<String> = None;
        for entry in &exports {
            let ea = self.analyze_export(config, addr, entry, &mut findings).await;
            // Run the null-filename fingerprint probe once, on the first
            // export that mounted successfully (non-empty handle).
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
        let os_string = os_guess.map(|fh| check_os_fingerprint(&fh));

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

        // Pace the per-export MOUNT burst (Critical Design Rule 10). NfsMountClient
        // does not embed StealthConfig, so honour the delay/jitter here.
        self.stealth.wait().await;
        let mount_res = match self.mount.mount(addr, &entry.path).await {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!("Failed to mount {}: {e}", entry.path);
                return ea;
            },
        };

        // Build a per-export NFS client so pool checkout uses the correct MOUNT path.
        // The global self.nfs3 has export="/" which fails on servers with restricted exports.
        // Shares self.pool / self.circuit (the pool keys on (host, export, uid, gid) so
        // different exports get different connection slots automatically), and inherits
        // the proxy, hostname, and aux-gids the operator supplied.
        // Inherits the configured stealth pacing so every per-export probe RPC
        // (escape, btrfs, nohide, symlink, squash writes, file-access reads)
        // honours --delay/--jitter (Critical Design Rule 10).
        let export_nfs3 = self.build_export_client(addr, entry);

        let fh = mount_res.handle;
        ea.file_handle = fh.to_hex();
        ea.auth_methods = mount_res.auth_flavors.iter().map(|&f| crate::proto::auth::flavor_name(f)).collect();

        check_auth_methods(&entry.path, &mount_res.auth_flavors, findings);
        // NFSv4 SECINFO check: verify auth methods from the NFSv4 perspective (F-3.4).
        // Complements check_auth_methods (which uses MOUNT auth flavors) with a live NFSv4 probe.
        check_nfs4_secinfo(addr, &entry.path, findings, self.proxy.as_deref(), &self.stealth).await;
        check_windows_signing(&fh, &entry.path, findings);
        check_handle_entropy(&fh, &entry.path, findings);

        // PATHCONF: case-insensitive detection (Windows/NTFS fingerprint) and
        // unrestricted chown detection (ownership hijacking).
        check_pathconf(&export_nfs3, &fh, &entry.path, findings).await;

        // AUTH_NONE metadata leak: check if the server allows unauthenticated
        // GETATTR on the export root handle (RFC 2623 S2.3.2 automounter support).
        check_auth_none_leak(addr, &fh, &entry.path, findings, self.proxy.as_deref(), &self.stealth).await;

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
fn check_os_fingerprint(fh: &FileHandle) -> String {
    let os = FileHandleAnalyzer::fingerprint_os(fh);
    let fs = FileHandleAnalyzer::fingerprint_fs(fh);
    format!("{os:?}/{fs:?}")
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
/// (F-3.4: TLS downgrade not enforced  --  RPCSEC_GSS not required).  Mixed
/// AUTH_SYS + Kerberos means the attacker can choose AUTH_SYS and bypass Kerberos
/// entirely (F-1.7, RFC 2203 S5.2.1).
///
/// Best-effort: silently returns on timeout or PROG_MISMATCH (NFSv3-only server).
async fn check_nfs4_secinfo(addr: SocketAddr, export_path: &str, findings: &mut Vec<Finding>, proxy: Option<&str>, stealth: &StealthConfig) {
    use crate::proto::nfs4::compound::Nfs4DirectClient;
    use crate::proto::nfs4::types::{ArgOp, ResOpData};

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

    let entries = res.results.last().and_then(|op| if let ResOpData::SecFlavors(f) = &op.data { Some(f.as_slice()) } else { None });
    let Some(entries) = entries else { return };

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
    let evidence_str = format!("SECINFO flavors=[{}]", flavor_strs.join(", "));

    // Kerberos: bare RPCSEC_GSS (6) or krb5 pseudo-flavors (390003-390005).
    let has_kerberos = raw_flavors.iter().any(|&f| f == 6 || (390_003..=390_005).contains(&f));
    let has_auth_sys = raw_flavors.contains(&1);

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
                    "NFSv4 SECINFO for export {export_path} returns both AUTH_SYS and RPCSEC_GSS \
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

    // AUTH_DH (flavor 3) via NFSv4 SECINFO.
    if raw_flavors.contains(&3) {
        findings.push(make_finding(
            &FindingSpec {
                id: "F-3.7",
                title: "NFSv4 SECINFO: AUTH_DH advertised (cryptographically broken)",
                desc: &format!(
                    "NFSv4 SECINFO for export {export_path} includes AUTH_DH (flavor 3), which \
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

    // AUTH_SHORT (flavor 2) via NFSv4 SECINFO.
    if raw_flavors.contains(&2) {
        findings.push(make_finding(
            &FindingSpec {
                id: "F-3.9",
                title: "NFSv4 SECINFO: AUTH_SHORT session credentials advertised",
                desc: &format!(
                    "NFSv4 SECINFO for export {export_path} includes AUTH_SHORT (flavor 2). \
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
    let starttls_bytes: &[u8] = b"\x00\x00\x00\x07STARTTLS";
    let cred = opaque_auth { flavor: auth_flavor::AUTH_TLS, body: Opaque::borrowed(&[]) };
    let verf = opaque_auth { flavor: auth_flavor::AUTH_TLS, body: Opaque::borrowed(starttls_bytes) };
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
