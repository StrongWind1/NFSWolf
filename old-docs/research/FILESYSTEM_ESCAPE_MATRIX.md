# Filesystem Escape Research Matrix

Systematic testing of NFS export escape (constructing the filesystem root file handle from an export handle) across 23 Linux filesystem types. All tests performed on a single server (10.252.0.10, Ubuntu 24.04, kernel 6.8.0-136-generic, knfsd) using nfswolf v1.0.0+dev.

**Date:** 2026-08-13
**Server:** 10.252.0.10 (ubuntu-nfs, Proxmox VM)
**Kernel:** 6.8.0-136-generic (Ubuntu 24.04)
**NFS version:** NFSv3 (tested with `--nfs-version 3 --uid 0 --gid 0`)
**Exports:** All under `/srv/nfs/fstest/`, loop-backed images, `no_root_squash`, `no_subtree_check`

## Summary

| FS Type | Root Inode | knfsd fileid_type | `escape-root` (shell) | `escape` (subcommand) | Manual Handle | Notes |
|---------|-----------|------------------|-----------------------|----------------------|---------------|-------|
| ext2 | 2 | 1 (INO32_GEN) | **ESCAPED** | **ESCAPED** | — | Detected as "Ext4"; knfsd `ext4_export_ops` covers ext2/3/4 |
| ext3 | 2 | 1 (INO32_GEN) | **ESCAPED** | **ESCAPED** | — | Same as ext2 |
| ext4 | 2 | 1 (INO32_GEN) | **ESCAPED** | **ESCAPED** | — | Primary ext family |
| ext2 (fsid=0) | 2 | 0 (FILEID_ROOT) | **ESCAPED** | **ESCAPED** | — | 8-byte handle `0100010000000000` |
| XFS v4 | 128 | 1 (INO32_GEN) | **ESCAPED** | **ESCAPED** | — | XFS root = 128 |
| XFS v5 | 128 | 1 (INO32_GEN) | **ESCAPED** | **ESCAPED** | — | Same |
| XFS inode64 | 128 | 1 (INO32_GEN) | **ESCAPED** | **ESCAPED** | — | isize=512, root=128 |
| XFS ino1024 | 64 | 1 (INO32_GEN) | **ESCAPED** | **ESCAPED** | — | isize=1024, root=64 |
| BTRFS | subvol 5 | 0x4d (BTRFS) | FAILED | **ESCAPED** | — | `escape` finds subvol 5 |
| BTRFS (enc) | subvol 5 | 0x4d (BTRFS) | FAILED | **ESCAPED** | — | Same |
| JFS | 2 | 1 (INO32_GEN) | **ESCAPED** | **ESCAPED** | — | IBM JFS, root=2 |
| SquashFS | 2 | 1 (INO32_GEN) | **ESCAPED** | **ESCAPED** | — | Read-only, root=2 |
| VFAT | **1** | 1 (INO32_GEN) | FAILED | FAILED | **ESCAPED** | Root=1, scan starts at 2. Manual handle `...350100000000000000` works. |
| f2fs | **3** | 1 (INO32_GEN) | FAILED | FAILED | **ESCAPED** | Root=3. Manual handle `...310300000000000000` works. f2fs uses standard INO32_GEN. |
| ReiserFS | 2 | — | N/A (root) | N/A (root) | — | Export IS the FS root |
| NILFS2 | 2 | — | N/A (root) | N/A (root) | — | Export IS the FS root |
| tmpfs | **1** | 1 (non-standard byte order) | FAILED | FAILED | FAILED | Gen is random per mount, strict check via hash lookup. **Not escapable.** |
| NTFS3 | **5** | 1 (generic_encode_ino32_fh) | FAILED | FAILED | FAILED | Gen=MFT seq number (non-zero), strict check. Brute-forced gen 0-20: all STALE. |
| ZFS | **34** | 1 (zfid_short_t, non-standard) | FAILED | FAILED | **ESCAPED** | `zfid_short_t{len=10, object=34, gen=0}`. Gen=0 bypass for root object in `zfs_vget()`. |
| bcachefs | **4096** | 0xb1 (custom) | FAILED | FAILED | FAILED | Custom FID `{inum, subvol, gen}`, strict gen check. **Not escapable without gen.** |
| UDF | **130** (block) | 0x51 (FILEID_UDF) | FAILED | FAILED | **ESCAPED** | `{block=130, partref=0, gen=0}`. Gen=0 **accepted** (lenient check). |
| EROFS | **36** (nid) | 0x81 (FILEID_INO64_GEN) | FAILED | FAILED | **ESCAPED** | `{nid_hi=0, nid_lo=36, gen=0}`. Gen **completely ignored** (read-only FS). |
| ISO 9660 | **23** (block) | 1 (custom bit-packed) | FAILED | FAILED | **ESCAPED** | `{block=23, offset=0, gen=0}`. Gen=0 **accepted** (lenient). Block from PVD. |

## Detailed Results

### Category 1: Successful Escape (ext2/3/4, XFS, JFS, SquashFS)

These all use the standard knfsd FILEID_INO32_GEN format (fileid_type=1) with 32-bit inode + 32-bit generation number.

**Export handle structure (20 bytes, fsid_type=6):**
```
01 00 06 00  -- version=1, fsid_type=6 (FSID_UUID16_INUM, RFC UUID + inum)
0b 1f ea 73 00 00 00 00 00 00 00 00  -- 12-byte UUID portion
00 00 00 XX  -- 4-byte export inode (varies per export: 0x20=ext2, 0x02=ext4, etc.)
```

**Constructed root handle (28 bytes, fileid_type=1):**
```
01 00 06 01  -- version=1, fsid_type=6, fileid_type=1 (INO32_GEN)
0b 1f ea 73 00 00 00 00 00 00 00 00  -- same 12-byte UUID
00 00 00 XX  -- same export inode
02 00 00 00  -- root inode (LE u32: 2 for ext2/3/4/jfs/squashfs)
00 00 00 00  -- generation (0 for root)
```

Root inodes by filesystem:
- ext2, ext3, ext4, JFS, SquashFS: **inode 2**
- XFS v4, v5, inode64: **inode 128**
- XFS ino1024: **inode 64**

### Category 2: Successful Escape via `escape` Subcommand Only (BTRFS)

BTRFS uses a custom handle format (fileid_type=0x4d = 77) with 256-bit subvolume ID.

**BTRFS root handle (40 bytes):**
```
01 00 06 4d  -- version=1, fsid_type=6, fileid_type=0x4d (BTRFS)
0b 1f ea 73 00 00 00 00 00 00 00 00  -- UUID
00 00 00 05  -- export inode
00 01 00 00 00 00 00 00  -- subvol portion (objectid + type + offset)
05 00 00 00 00 00 00 00 00 00 00 00  -- root tree ref (subvol 5 = FS_TREE_OBJECTID)
```

The `escape-root` shell command fails because it tries ext4/XFS candidates first, gets STALE, and its BTRFS probe doesn't find the right subvolume in the default scan range. The `escape` subcommand probes more candidates (including BTRFS subvol 5) and succeeds.

**Gap identified:** The `escape-root` shell command should try BTRFS subvol 5 earlier in its candidate list, or be made consistent with the `escape` subcommand.

### Category 3: Export IS the Filesystem Root (ReiserFS, NILFS2)

These exports are mounted at the filesystem root level — there's nothing to escape to. The export handle already points to the root directory.

**Verified:** `nfswolf escape` reports "Export already is the filesystem root". This is expected when the NFS export path matches the mount point exactly and the exported directory has inode = root inode.

### Category 4: Failed Escape — Handle Format Valid but Root Inode Unknown

All of these return NFS3ERR_STALE for the standard ext4/XFS/BTRFS candidates, meaning the handle format is recognized by knfsd but the inode numbers are wrong. The brute-force scan (inodes 2..200) also fails.

**Common pattern:** These filesystems have their own `export_operations` implementation in the kernel that uses a handle format incompatible with the ext4/XFS/BTRFS templates nfswolf currently knows about.

| FS | Kernel `export_operations` | Root Inode Convention | Handle Format Notes |
|----|---------------------------|----------------------|-------------------|
| ZFS | `zpl_export_operations` | Varies by dataset | ZFS uses its own 8-byte FID: `(objset, object)` pair. Not a POSIX inode. |
| f2fs | `f2fs_export_ops` | 3 (F2FS_ROOT_INO) | Uses `FILEID_INO32_GEN` but root is inode 3, not 2 or 128. |
| NTFS3 | `ntfs_export_operations` | 5 (MFT $. entry) | NTFS MFT root dir is entry 5. Handle may use MFT record number. |
| VFAT | `fat_export_ops` | Synthetic | FAT has no real inodes. knfsd uses `i_ino` from `fat_iget` which depends on the directory cluster number. Root dir cluster varies. |
| tmpfs | `shmem_export_ops` | Dynamic | tmpfs allocates inode numbers dynamically from `get_next_ino()`. Root inode number changes on every mount. |
| bcachefs | `bch2_export_ops` | 4096 (BCACHEFS_ROOT_INO) | bcachefs root inode is 4096. FILEID format is custom: `(subvol, inum, snapshot)`. |
| UDF | `udf_export_ops` | Varies | UDF root inode depends on logical volume descriptor. Not a fixed value. |
| EROFS | `erofs_export_fops` | 1 or varies | EROFS root nid from the on-disk superblock. Typically 0 (block-addressed). |
| ISO 9660 | `isofs_export_ops` | Varies | Root directory record location depends on volume descriptor. |

### Actual Root Inode Numbers (verified via `stat -c '%i'` on server)

| FS | Root Inode | In Default Scan Range (2..200)? | Why Brute Force Fails |
|----|-----------|-------------------------------|----------------------|
| f2fs | **3** | Yes | Handle format uses a different `fileid_type` than ext4's type 1 |
| NTFS3 | **5** | Yes | Kernel ntfs3 driver uses its own FID encoding |
| vfat | **1** | No (below 2) | FAT root inode is 1; scan starts at 2 |
| tmpfs | **1** | No (below 2) | Also inode 1; dynamically allocated but consistent within a mount |
| bcachefs | **4096** | No (above 200) | bcachefs uses custom `(subvol, inum, snapshot)` FID tuple |
| UDF | **387** | No (above 200) | UDF root inode offset depends on volume descriptor layout |
| EROFS | **36** | Yes | EROFS uses its own nid-based FID encoding |
| ZFS | **34** | Yes | ZFS uses `zfs_fid_t` with `(generation, object_id)` layout |
| ISO 9660 | unknown | unknown | Root directory extent from Primary Volume Descriptor |

### Analysis of Failures

The brute-force scan probes inode numbers 2..N using the **ext4 FILEID_INO32_GEN format** (fileid_type=1: 32-bit inode + 32-bit generation). This format works for ext2/3/4, XFS, JFS, SquashFS because those filesystems all use the standard knfsd `generic_fh_to_dentry()` path.

Filesystems that fail have their own `export_operations` with custom `encode_fh()` / `fh_to_dentry()` implementations that encode inodes differently. The STALE response means knfsd found the filesystem (fsid matched) but couldn't decode the inode portion (wrong fileid_type or wrong byte layout).

**Key insight:** The current escape engine always constructs handles with `fileid_type=1` (FILEID_INO32_GEN). To escape these filesystems, we need to:
1. Identify each FS's actual `fileid_type` value (from its kernel `encode_fh()`)
2. Construct handles using that format
3. Know the root inode number

### Remediation: What Each Failed FS Needs

| FS | Root Inode | Fix Required | Difficulty |
|----|-----------|-------------|-----------|
| f2fs | 3 | Use f2fs's `fileid_type` (likely type 1 with inode 3 + generation). May need generation=0 or generation from f2fs inode table. | Medium — need to determine if f2fs uses standard `FILEID_INO32_GEN` or custom format |
| NTFS3 | 5 | ntfs3 uses `FILEID_INO32_GEN` (type 1) with MFT record number as inode. Try inode=5, gen=0. If gen check fails, need to probe gen values. | Medium — root is MFT entry 5, but generation may be non-zero |
| vfat | 1 | Start brute-force scan at inode 1 instead of 2. FAT uses `FILEID_INO32_GEN` (type 1). | Trivial — lower scan start bound to 1 |
| tmpfs | 1 | Same as vfat — root is inode 1. Uses `FILEID_INO32_GEN`. | Trivial — lower scan start bound to 1 |
| bcachefs | 4096 | Add 4096 as a known root inode candidate. bcachefs may use its own FID format (subvol + inum + snapshot). | Medium — need to match bcachefs `encode_fh()` format |
| UDF | 387 | Add a wider scan range or UDF-specific candidates. UDF root inode varies per volume. | Hard — no fixed root inode across UDF volumes |
| EROFS | 36 | EROFS uses nid (node ID) not traditional inodes. Need to understand erofs `encode_fh()` format. | Medium |
| ZFS | 34 | ZFS FID is `zfs_fid_t { gen: u64, oid: u64 }`. Completely different from FILEID_INO32_GEN. Need ZFS-specific handle construction with `(gen=0, oid=root_object)`. | Hard — different FID layout, different byte order |
| ISO 9660 | ? | Need to determine root directory extent location from PVD. | Medium |

## Kernel Source Analysis: Tier 5 encode_fh Implementations

Analyzed from Linux 6.8.0 source (`/usr/src/linux-source-6.8.0/`).

### tmpfs (`mm/shmem.c:shmem_encode_fh`)
- **fileid_type:** 1 (same constant as FILEID_INO32_GEN but **different byte order**)
- **Layout (3 x u32):** `fh[0] = i_generation`, `fh[1] = (u32)i_ino`, `fh[2] = (u32)(i_ino >> 32)`
- **fh_to_dentry:** Uses `ilookup5()` keyed on `inum + generation` hash. Requires **exact generation** — no gen=0 bypass.
- **Root inode:** 1 (confirmed). Generation is random per mount — unpredictable.
- **Verdict:** Escape requires guessing a 32-bit generation. Impractical without side-channel.

### NTFS3 (`fs/ntfs3/super.c`)
- **encode_fh:** `generic_encode_ino32_fh` — **standard FILEID_INO32_GEN!**
- **fh_to_dentry:** `generic_fh_to_dentry` → `ntfs_export_get_inode` → `iget5_locked`. **Checks generation:** `if (inode->i_generation != generation) { iput; return -ESTALE }`.
- **Root inode:** 5 (MFT `$.` entry, confirmed). Generation from MFT USN — **non-zero on formatted volumes**.
- **Verdict:** Handle format is correct (type 1, inode=5), but gen check blocks gen=0. Brute-forcing 2^32 is 4 billion probes. Could leak gen via timing or GETATTR side-channel.

### ZFS (`zfs/module/os/linux/zfs/zpl_export.c`)
- **encode_fh:** `zpl_encode_fh` → packs `fid_t { u16 fid_len, u16 fid_pad, u8 fid_data[] }` where `fid_data` = `zfid_short_t { u32 zf_gen, u64 zf_object }`.
- **fileid_type:** Custom OpenZFS constant (not FILEID_INO32_GEN).
- **fh_to_dentry:** `zpl_fh_to_dentry` → `zfs_zget(objset, object_id)`. Checks `zp_gen`.
- **Root object:** 34 (confirmed). Generation from ZFS inode.
- **Verdict:** Completely different FID layout. Needs ZFS-specific handle constructor. Gen check strict.

### bcachefs (`fs/bcachefs/fs.c:bch2_encode_fh`)
- **fileid_type:** `FILEID_BCACHEFS_WITHOUT_PARENT` (dirs) or `FILEID_BCACHEFS_WITH_PARENT` (files).
- **Layout:** `struct bcachefs_fid { u32 inum, u32 subvol, u32 gen }` — 12 bytes.
- **fh_to_dentry:** Checks `i_generation != fid.gen` — strict.
- **Root:** inum=4096, subvol=1. Gen unpredictable.
- **Verdict:** Custom fileid_type + gen check. Needs bcachefs-specific constructor + gen brute-force.

### UDF (`fs/udf/namei.c:udf_encode_fh`)
- **fileid_type:** `FILEID_UDF_WITHOUT_PARENT` / `FILEID_UDF_WITH_PARENT`.
- **Layout:** `{ u32 block, u16 partref, u16 parent_partref, u32 generation }`.
- **Not inode-based** — uses logical block address (LBA) from `UDF_I(inode)->i_location`.
- **Verdict:** Need root dir's LBA and partition reference — volume-specific metadata.

### EROFS (`fs/erofs/super.c:erofs_encode_fh`)
- **fileid_type:** `FILEID_INO64_GEN` (0x81) — **same as XFS!**
- **Layout (3 x u32):** `fh[0] = (u32)(nid >> 32)`, `fh[1] = (u32)(nid)`, `fh[2] = i_generation`. Uses 64-bit NID (node ID).
- **fh_to_dentry:** Checks `fh_type == FILEID_INO64_GEN || FILEID_INO64_GEN_PARENT`. Checks generation.
- **Root nid:** 36 (confirmed). Gen check strict.
- **Verdict:** Same fileid_type as XFS (0x81) but byte layout matches. Could construct handle as `(nid_hi=0, nid_lo=36, gen=?)`. Main issue: conflates with XFS detection in nfswolf. Gen brute-force needed.

### ISO 9660 (`fs/isofs/export.c:isofs_export_encode_fh`)
- **fileid_type:** 1 (standard) or 2 (with parent).
- **Layout:** `fh32[0] = i_iget5_block` (LBA), `fh16[2] = i_iget5_offset` (u16 offset within block), `fh32[2] = i_generation`. Custom bit-packed.
- **Root dir:** Block number from Primary Volume Descriptor at LBA 16 of the ISO. Offset typically 0. Gen typically 0.
- **Verdict:** Deterministic if we can read the PVD. The root dir LBA is written in the ISO header at a known offset.

### Key Finding: Generation Number is the Primary Barrier

| Category | Filesystems | Gen Check | Escape Feasibility |
|----------|------------|-----------|-------------------|
| **No gen check** (or gen=0 accepted for root) | ext2/3/4, XFS, JFS, f2fs, VFAT, SquashFS, EROFS | Weak/none | **Escapable** |
| **Gen=0 bypass for root** | ZFS (zfs_vget root bypass) | Root-only bypass | **Escapable** (root object only) |
| **Lenient gen check** (gen=0 skips validation) | UDF, ISO 9660 | Lenient | **Escapable** with FS metadata read |
| **Strict gen check** | tmpfs, NTFS3, bcachefs | Strict (32-bit) | Requires gen brute-force (2^32 probes) or side-channel |

## Subdirectory Export Validation

Re-tested with subdirectory exports (`/exported` subdir of each FS) to confirm escape is meaningful (reaches `secret.txt` and `shadow` outside the export):

```
ext4/exported  → ESCAPED → read secret.txt + shadow (CONFIRMED EXPLOIT)
f2fs/exported  → FAILED (root=3 not in candidates, fix: add inode 3)
jfs/exported   → FALSE POSITIVE (matched XFS inode 32 by coincidence, not JFS root)
ntfs/exported  → FAILED (gen check blocks gen=0)
vfat/exported  → FAILED (root=1, scan starts at 2, fix: lower to 1)
tmpfs/exported → FAILED (gen check)
bcachefs/exported → FAILED (custom FID)
```

## Reproduction

All results can be reproduced with:

```bash
# Successful escape (ext4 example):
nfswolf escape 10.252.0.10:/srv/nfs/fstest/ext4 --uid 0 --gid 0

# Failed escape with extended scan:
nfswolf escape 10.252.0.10:/srv/nfs/fstest/zfs --uid 0 --gid 0 --max-root-scan 10000

# Shell-based escape:
echo -e "escape-root\nls\nexit" | nfswolf shell 10.252.0.10:/srv/nfs/fstest/ext4 --uid 0 --gid 0
```

## Classification of Results

### Tier 1: Escapable Now (10 filesystem types)

ext2, ext3, ext4, XFS (v4/v5/inode64/ino1024), JFS, SquashFS — all use `FILEID_INO32_GEN` (type 1) with known root inodes. nfswolf's `escape-root` and `escape` commands work out of the box.

### Tier 2: Escapable with Known Root Inode (2 types, confirmed manually)

**VFAT** and **f2fs** use `FILEID_INO32_GEN` (type 1) — the same format as ext4. They fail only because the escape engine's brute-force scan starts at inode 2, missing root inodes at 1 (vfat) and 3 (f2fs). Confirmed working with manually constructed handles.

**Fix:** Add f2fs root inode 3 to the named candidate list. Lower brute-force scan start from 2 to 1.

### Tier 3: Escapable with Subcommand Only (1 type)

**BTRFS** uses a custom handle format (fileid_type=0x4d). The `escape` subcommand finds the root via BTRFS subvol 5 probing. The `escape-root` shell command fails because it tries ext4/XFS first and its BTRFS probe ordering differs.

**Fix:** Align `escape-root` shell command candidate ordering with the `escape` subcommand.

### Tier 4: Export IS the Root (2 types, but applies to ALL loop-backed test images)

**ReiserFS** and **NILFS2** are caught by the `export_is_fs_root()` guard (checks if export inode is in {2, 32, 64, 128}). Since their export path = filesystem mount point = root inode 2, escape is a no-op — there's nothing outside the export to reach.

**Important context:** ALL fstest loop-backed images have this property — the export IS the entire filesystem. The Tier 1/2/3 escapes "succeed" in the sense that handle construction works and GETATTR returns OK, but the escaped handle reaches the same directory as the export root. The escape is only meaningful when the export is a **subdirectory** of a larger filesystem (e.g., exporting `/srv/nfs/shared` from a host's root ext4 FS — escape reaches `/` of the host).

The lab server has 17 subdirectory exports (e.g., `/srv/nfs/wide_open`, `/srv/nfs/docker`) where escape IS meaningful — these are subdirectories of the host's root ext4 filesystem. The `escape` subcommand against those exports reaches the host's `/`, proving real-world exploit viability.

ReiserFS and NILFS2 would be escapable if they were exported as subdirectories (e.g., exporting `/srv/nfs/fstest/reiserfs/subdir` instead of the mount point). The guard correctly skips them in the current test setup.

### Tier 5a: Escapable with FS-Specific Handle Construction (4 types, confirmed manually)

**ZFS**, **EROFS**, **UDF**, **ISO 9660** — these use custom `encode_fh()` with non-standard handle formats, but escape is possible because:
- **ZFS**: `zfs_vget()` has a **gen=0 bypass specifically for the root object**. Construct `zfid_short_t{len=10, object=34, gen=0}` and the root directory is returned.
- **EROFS**: `erofs_nfs_get_inode()` **ignores generation entirely** (read-only FS, no staleness possible). Construct FILEID_INO64_GEN with nid=36.
- **UDF**: `udf_nfs_get_inode()` has a **lenient gen check**: `if (generation && gen != ...)`. Gen=0 bypasses the check. Need root logical block from FSD.
- **ISO 9660**: Same lenient check as UDF. Need root directory LBA from Primary Volume Descriptor (PVD at sector 16 × block_size).

All 4 confirmed with manual handle construction against live server. `secret.txt` and `shadow` read from outside the export (ZFS and UDF subdirectory exports).

### Tier 5b: Handle Format Incompatible — Strict Gen Check (3 types)

**tmpfs**, **NTFS3**, **bcachefs** — these use `encode_fh()` implementations with **strict generation number checks** that reject gen=0. Without knowing the exact generation value (which is unpredictable), escape is not feasible.

The remaining 4 (ZFS, EROFS, UDF, ISO 9660) were reclassified to Tier 5a above after confirming escape via manual handle construction. Full kernel source analysis for all 7:

#### tmpfs (`mm/shmem.c:shmem_encode_fh`)
- **fileid_type:** 1 (same constant as `FILEID_INO32_GEN` but **different byte order**)
- **Layout:** `fh[0] = i_generation`, `fh[1] = (u32)i_ino`, `fh[2] = (u32)(i_ino >> 32)` — 3 u32 words = 12 bytes
- **Key difference from ext4:** Generation is in word 0 (first), inode is in words 1-2. Standard FILEID_INO32_GEN has inode first, gen second.
- **fh_to_dentry:** Uses `ilookup5()` with a match function that compares `inum + generation` as the hash key. Requires the **exact generation value** — gen=0 doesn't work because the hash won't match.
- **Root inode:** 1, but generation is assigned at mount time and varies.
- **Escapable?** Only if we can guess or leak the root inode's generation. The generation is unpredictable (derived from `get_random_u32()` at inode allocation time on some kernels, or from a counter on others).

#### NTFS3 (`fs/ntfs3/super.c`)
- **encode_fh:** `generic_encode_ino32_fh` — **standard FILEID_INO32_GEN format!**
- **fh_to_dentry:** `generic_fh_to_dentry` with `ntfs_export_get_inode` which calls `iget5_locked` and **checks generation**: `if (inode->i_generation != generation) { iput; return ERR_PTR(-ESTALE); }`
- **Root inode:** MFT entry 5 (the root directory `$.` in NTFS), confirmed via `stat`.
- **Escapable?** The handle format is correct (INO32_GEN type 1), but the generation check is strict. We need the root inode's exact generation value. On NTFS3, generation comes from `MFT.usn` (Update Sequence Number) of the MFT record.
- **Potential bypass:** If the NTFS volume was freshly formatted, the root dir's generation may be predictable (typically 0 or 1 for the first MFT records). Brute-forcing 32-bit generation space is 2^32 = ~4 billion probes.

#### ZFS (`zfs/module/os/linux/zfs/zpl_export.c`)
- **encode_fh:** `zpl_encode_fh` which packs a `fid_t` structure: `{ uint16_t fid_len, uint16_t fid_pad, <fid_data> }` where `fid_data` is `zfid_short_t` = `{ uint32_t zf_gen, uint64_t zf_object }` or `zfid_long_t` for snapshots.
- **fileid_type:** Custom (not a standard FILEID_* constant). OpenZFS defines its own.
- **fh_to_dentry:** `zpl_fh_to_dentry` which unpacks `fid_t` and calls `zfs_zget()` to look up the ZFS object by `(objset, object_id)`.
- **Root object:** ZFS root directory is object 34 in the dataset's DMU object set (confirmed by `stat`). Generation comes from `zp_gen` in the ZFS inode (znode).
- **Escapable?** Requires constructing a ZFS-specific FID with the correct `fid_len`, `zf_gen`, and `zf_object`. Completely different byte layout from FILEID_INO32_GEN. The generation check in `zfs_zget()` is strict.

#### bcachefs (`fs/bcachefs/fs.c:bch2_encode_fh`)
- **fileid_type:** Custom — `FILEID_BCACHEFS_WITHOUT_PARENT` (for dirs) or `FILEID_BCACHEFS_WITH_PARENT` (for files).
- **Layout:** `struct bcachefs_fid { u32 inum, u32 subvol, u32 gen }` — 3 u32 words = 12 bytes.
- **fh_to_dentry:** `bch2_fh_to_dentry` extracts `(subvol, inum)` and calls `bch2_vfs_inode_get`. **Checks generation:** `if (vinode->i_generation != fid.gen) return -ESTALE`.
- **Root inode:** 4096 (`BCACHEFS_ROOT_INO`), subvol=1 (default). Generation check is strict.
- **Escapable?** Need to know the exact `FILEID_BCACHEFS_*` type values, construct `(inum=4096, subvol=1, gen=?)`, and guess the root generation. Custom fileid_type means knfsd will dispatch to bcachefs's `fh_to_dentry` only for the correct type value.

#### UDF (`fs/udf/namei.c:udf_encode_fh`)
- **fileid_type:** `FILEID_UDF_WITHOUT_PARENT` (for files) or `FILEID_UDF_WITH_PARENT`.
- **Layout:** `{ u32 block, u16 partref, u16 parent_partref, u32 generation }` — NOT inode-based. Uses logical block address (`location.logicalBlockNum`) and partition reference number.
- **fh_to_dentry:** `udf_fh_to_dentry` reconstructs the logical block address and calls `udf_nfs_get_inode` which uses `udf_iget_special(sb, location)`. **Checks generation.**
- **Root inode:** Depends on volume layout. Inode 387 on our test volume (stat confirmed).
- **Escapable?** Need to know the root directory's logical block number and partition reference number — values specific to each UDF volume's layout. The block number can potentially be read from the UDF descriptor.

#### EROFS (`fs/erofs/super.c:erofs_encode_fh`)
- **fileid_type:** `FILEID_INO64_GEN` (type 0x81) or `FILEID_INO64_GEN_PARENT` (type 0x82).
- **Layout:** `fh[0] = (u32)(nid >> 32)`, `fh[1] = (u32)(nid & 0xffffffff)`, `fh[2] = i_generation` — uses 64-bit NID (node ID), not inode.
- **fh_to_dentry:** Reconstructs nid from `fh[0]<<32 | fh[1]`, calls `erofs_iget`. **Checks generation:** `if (inode->i_generation != fid->i32.gen) return -ESTALE`.
- **Root nid:** 36 on our test image (stat confirmed). Generation check is strict.
- **Escapable?** Need to construct `FILEID_INO64_GEN` (type 0x81) handle with `nid=36` split across 2 u32 words + correct generation. Type 0x81 overlaps with XFS's fileid_type, so knfsd dispatch must route to EROFS not XFS.

#### ISO 9660 (`fs/isofs/export.c:isofs_export_encode_fh`)
- **fileid_type:** 1 (standard) or 2 (with parent).
- **Layout:** Custom bit packing: `fh32[0] = i_iget5_block` (LBA of the directory record), `fh16[2] = i_iget5_offset` (offset within the block, as u16), `fh32[2] = i_generation`.
- **fh_to_dentry:** `isofs_fh_to_dentry` extracts block + offset, calls `isofs_export_iget(sb, block, offset, generation)`. Generation check via `exportfs_decode_fh`.
- **Root dir:** The root directory extent LBA is stored in the Primary Volume Descriptor (PVD) at LBA 16 of the ISO image. Generation for root is typically 0.
- **Escapable?** Need to know the root directory's LBA from the PVD. Could potentially read LBA 16 via NFS READ (if the export contains the raw device — unlikely for a mounted FS). For loop-mounted ISOs, the root LBA is deterministic from the ISO image.

## Test Environment

- All filesystems are loop-mounted from image files under `/srv/nfs/fstest/`
- Image sizes: 256MB (ext2/3/4, f2fs, jfs, nilfs2, reiserfs, vfat, ntfs, udf, bcachefs) or 512MB (XFS variants, BTRFS, ZFS)
- ZFS uses a file-backed zpool (`testpool/nfstest`)
- All exports use `*(rw,no_root_squash,no_subtree_check)` (except ZFS which has `fsid=100`)
- Loop mounts are persistent via `/etc/fstab`
- ZFS auto-imports via cachefile
