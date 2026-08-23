# Filesystem escape matrix

Systematic testing of NFS export escape (constructing the filesystem root file handle from an export handle) across 22 Linux filesystem types. All results from live testing on kernel 6.8.0 (Ubuntu 24.04, knfsd) using nfswolf.

!!! info "What is export escape?"
    When an NFS server exports a subdirectory (e.g., `/srv/nfs/shared`), the client receives a file handle scoped to that directory. Export escape constructs a new file handle pointing to the filesystem root (`/`), breaking out of the export boundary. This works because NFS file handles are bearer tokens: any valid handle works regardless of how it was obtained. See [F-2.1](../findings/access-control/F-2.1-export-escape.md) for the full finding.

## Summary table

| Filesystem | Tier | Escapable | Root Inode | Handle Size | fileid_type | Method | Notes |
|------------|------|-----------|-----------|-------------|-------------|--------|-------|
| ext2 | 1 | **Yes** | 2 | 28 B | 1 (INO32_GEN) | `escape` + `escape-root` | Detected as ext4; shared `ext4_export_ops` |
| ext3 | 1 | **Yes** | 2 | 28 B | 1 (INO32_GEN) | `escape` + `escape-root` | Same kernel path as ext2 |
| ext4 | 1 | **Yes** | 2 | 28 B | 1 (INO32_GEN) | `escape` + `escape-root` | Primary ext family |
| XFS v4 | 1 | **Yes** | 128 | 28 B | 1 (INO32_GEN) | `escape` + `escape-root` | Standard XFS |
| XFS v5 | 1 | **Yes** | 128 | 28 B | 1 (INO32_GEN) | `escape` + `escape-root` | Same as v4 |
| XFS inode64 | 1 | **Yes** | 128 | 28 B | 1 (INO32_GEN) | `escape` + `escape-root` | isize=512 |
| XFS ino1024 | 1 | **Yes** | 64 | 28 B | 1 (INO32_GEN) | `escape` + `escape-root` | isize=1024 changes root inode |
| JFS | 1 | **Yes** | 2 | 28 B | 1 (INO32_GEN) | `escape` + `escape-root` | IBM JFS, standard format |
| SquashFS | 1 | **Yes** | 2 | 28 B | 1 (INO32_GEN) | `escape` + `escape-root` | Read-only filesystem |
| NTFS3 | 1 | **Yes** | 5 | 28 B | 1 (INO32_GEN) | `escape` + `escape-root` | gen=5 on freshly formatted volumes |
| BTRFS | 2 | **Yes** | subvol 5 | 40 B | 0x4d (BTRFS) | `escape` only | Custom handle; subvol 5 = FS_TREE |
| BTRFS (enc) | 2 | **Yes** | subvol 5 | 40 B | 0x4d (BTRFS) | `escape` only | Encrypted, same handle format |
| f2fs | 3 | **Yes** | 3 | 28 B | 1 (INO32_GEN) | Manual handle | Root is inode 3, not 2 |
| VFAT | 3 | **Yes** | 1 | 28 B | 1 (INO32_GEN) | Manual handle | Root is inode 1 |
| ZFS | 4 | **Yes** | 34 | Custom | Custom (zfid) | FS-specific construction | gen=0 bypass for root object |
| EROFS | 4 | **Yes** | 36 (nid) | Custom | 0x81 (INO64_GEN) | FS-specific construction | Gen ignored (read-only FS) |
| UDF | 4 | **Yes** | 130 (block) | Custom | 0x51 (FILEID_UDF) | FS-specific construction | gen=0 bypasses validation |
| ISO 9660 | 4 | **Yes** | PVD block | Custom | 1 (bit-packed) | FS-specific construction | gen=0 accepted (lenient) |
| bcachefs | 4 | **Yes** | 4096 | 12 B | 0xb1 (custom) | FS-specific construction | gen=0 accepted empirically on kernel 6.8 |
| ReiserFS | -- | N/A | 2 | -- | -- | Export is FS root | Nothing to escape to |
| NILFS2 | -- | N/A | 2 | -- | -- | Export is FS root | Nothing to escape to |
| tmpfs | 5 | **No** | 1 | 12 B | 1 (non-standard) | -- | Random gen per mount |

## Escapability tiers

### Tier 1: escapable out of the box (11 filesystem types)

ext2, ext3, ext4, XFS (all variants), JFS, SquashFS, NTFS3. These all use the standard knfsd `FILEID_INO32_GEN` format (fileid_type=1) with a 32-bit inode and 32-bit generation number. The generation number for root inodes is 0 for most filesystems; NTFS3 uses gen=5 (the initial MFT Update Sequence Number on freshly formatted volumes). All values are in the static candidate table, so nfswolf constructs a valid root handle deterministically.

Both `nfswolf escape` and the `escape-root` shell command work without any special flags.

**Handle structure (28 bytes):**

```
01 00 06 01  -- version=1, fsid_type=6, fileid_type=1 (INO32_GEN)
XX XX XX XX XX XX XX XX XX XX XX XX  -- 12-byte fsid (UUID portion)
XX XX XX XX  -- 4-byte export inode
02 00 00 00  -- root inode (LE u32: 2 for ext/JFS/SquashFS, 128 for XFS, 5 for NTFS3)
00 00 00 00  -- generation (0 for most; 5 for NTFS3)
```

**Root inodes by filesystem:**

| Filesystem | Root Inode | Generation |
|------------|-----------|------------|
| ext2, ext3, ext4, JFS, SquashFS | 2 | 0 |
| XFS v4, v5, inode64 | 128 | 0 |
| XFS ino1024 | 64 | 0 |
| NTFS3 | 5 | 5 |

### Tier 2: escapable via `escape` subcommand (BTRFS)

BTRFS uses a custom handle format (fileid_type=0x4d) with a 256-bit subvolume identifier. The `escape` subcommand probes BTRFS subvol 5 (`FS_TREE_OBJECTID`) and succeeds. The `escape-root` shell command tries ext4/XFS candidates first, and its BTRFS probe ordering differs, so it fails on BTRFS.

**BTRFS root handle (40 bytes):**

```
01 00 06 4d  -- version=1, fsid_type=6, fileid_type=0x4d (BTRFS)
XX XX XX XX XX XX XX XX XX XX XX XX  -- UUID
XX XX XX XX  -- export inode
00 01 00 00 00 00 00 00  -- subvol portion
05 00 00 00 00 00 00 00 00 00 00 00  -- root tree ref (subvol 5)
```

### Tier 3: escapable with known root inode (f2fs, VFAT)

These filesystems use the standard `FILEID_INO32_GEN` format, identical to ext4, but have root inodes outside the default scan range. Escape confirmed with manually constructed handles.

| Filesystem | Root Inode | Why Default Scan Misses It |
|------------|-----------|---------------------------|
| f2fs | 3 | F2FS_ROOT_INO is 3, not 2 or 128 |
| VFAT | 1 | FAT root is inode 1; scan starts at 2 |

### Tier 4: escapable with FS-specific handle construction (ZFS, EROFS, UDF, ISO 9660, bcachefs)

These filesystems use custom `encode_fh()` implementations with non-standard handle layouts, but escape is possible because their generation checks are weak or absent for the root object.

| Filesystem | Root ID | FID Layout | Gen Check | Why Escape Works |
|------------|---------|-----------|-----------|------------------|
| ZFS | object 34 | `zfid_short_t{len, object, gen}` | Strict, but root bypasses | `zfs_vget()` has explicit gen=0 bypass for root object |
| EROFS | nid 36 | `FILEID_INO64_GEN{nid_hi, nid_lo, gen}` | Ignored entirely | Read-only FS; staleness impossible |
| UDF | block 130 | `FILEID_UDF{block, partref, gen}` | Lenient: `if (gen && gen != ...)` | gen=0 skips the validation check |
| ISO 9660 | PVD block | Custom bit-packed `{block, offset, gen}` | Lenient | Same gen=0 bypass as UDF |
| bcachefs | inum 4096 | `{inum: u64, subvol: u32, gen: u32}` | Strict in source, lenient in practice | gen=0 accepted empirically on kernel 6.8 despite strict check in source |

All five confirmed with manual handle construction and live read of files outside the export boundary.

### Tier 5: not escapable (tmpfs)

tmpfs enforces a strict 32-bit generation check with a random value that rejects gen=0. Without knowing the exact generation value, which is unpredictable, escape requires brute-forcing 2^32 values (~4 billion probes).

| Filesystem | Root Inode | Why Escape Fails |
|------------|-----------|-----------------|
| tmpfs | 1 | Gen assigned from `get_random_u32()` at mount time; `ilookup5()` requires exact hash match |

## Kernel `encode_fh` analysis

The following analysis is based on Linux 6.8.0 kernel source.

### Standard path (Tier 1 filesystems)

ext2/3/4, XFS, JFS, SquashFS, and NTFS3 all use `generic_encode_ino32_fh` or equivalent, producing `FILEID_INO32_GEN` (type 1) handles. The `generic_fh_to_dentry` path does not enforce generation for root inodes on most filesystems (gen=0 is accepted). NTFS3 enforces a strict gen check, but the root directory (MFT entry 5) has a known initial generation of 5 on freshly formatted volumes, so the handle is constructible without brute-force.

### tmpfs (`mm/shmem.c`)

```c
// fileid_type = 1, but DIFFERENT byte order from standard INO32_GEN
fh[0] = i_generation;        // gen is FIRST (standard puts inode first)
fh[1] = (u32)i_ino;
fh[2] = (u32)(i_ino >> 32);
```

Uses `ilookup5()` with `inum + generation` as hash key. Exact generation required. Root inode is 1, but generation is random per mount.

### NTFS3 (`fs/ntfs3/super.c`)

Uses `generic_encode_ino32_fh` (standard format), but `ntfs_export_get_inode` enforces:

```c
if (inode->i_generation != generation) { iput(inode); return ERR_PTR(-ESTALE); }
```

Root is MFT entry 5. Generation comes from MFT USN, which is non-zero on formatted volumes. However, the initial USN on a freshly formatted NTFS3 volume is consistently 5, making the root handle constructible with inode=5 gen=5. nfswolf includes this in its static candidate table.

### ZFS (`zfs/module/os/linux/zfs/zpl_export.c`)

Custom `zpl_encode_fh` packs `fid_t`:

```c
struct zfid_short_t {
    uint16_t zf_len;      // 10
    uint16_t zf_pad;
    uint32_t zf_gen;
    uint64_t zf_object;   // 34 for root
};
```

`zfs_zget()` has a gen=0 bypass specifically for the root object, making escape trivial once you know the layout.

### bcachefs (`fs/bcachefs/fs.c`)

Custom fileid types (`FILEID_BCACHEFS_WITHOUT_PARENT` for dirs):

```c
struct bcachefs_fid { u32 inum; u32 subvol; u32 gen; };  // 12 bytes
// root: inum=4096, subvol=1
```

The kernel source shows a strict check: `if (vinode->i_generation != fid.gen) return -ESTALE`. However, live testing on kernel 6.8.0 confirmed that gen=0 is accepted for the root directory (inum=4096, subvol=1), making escape possible via `construct_bcachefs_root_handle()`.

### UDF (`fs/udf/namei.c`)

Not inode-based. Uses logical block address:

```c
struct { u32 block; u16 partref; u16 parent_partref; u32 generation; };
```

Lenient check (`if (generation && gen != ...)`); gen=0 bypasses validation.

### EROFS (`fs/erofs/super.c`)

Uses `FILEID_INO64_GEN` (0x81), same type constant as XFS:

```c
fh[0] = (u32)(nid >> 32);   // nid_hi
fh[1] = (u32)(nid);         // nid_lo  (root: 36)
fh[2] = i_generation;       // ignored for read-only FS
```

Generation check exists in code but is effectively a no-op since the read-only filesystem never changes inodes.

### ISO 9660 (`fs/isofs/export.c`)

Custom bit-packed encoding:

```c
fh32[0] = i_iget5_block;    // LBA of directory record
fh16[2] = i_iget5_offset;   // offset within block
fh32[2] = i_generation;     // typically 0 for root
```

Root directory LBA comes from the Primary Volume Descriptor at sector 16. gen=0 accepted via lenient check.

## Generation number: the primary barrier

The single factor that determines escapability is how the filesystem validates the generation number in its `fh_to_dentry` implementation.

| Gen Check Behavior | Filesystems | Escape Feasibility |
|-------------------|------------|-------------------|
| No check / gen=0 accepted for root | ext2/3/4, XFS, JFS, f2fs, VFAT, SquashFS | Trivially escapable |
| Gen=0 root bypass (special case) | ZFS | Escapable (root object only) |
| Lenient (`if gen && gen != ...`) | UDF, ISO 9660 | Escapable with gen=0 |
| Gen ignored entirely | EROFS | Escapable (read-only FS) |
| Known gen value (deterministic) | NTFS3 (gen=5) | Escapable with known gen |
| Strict in source, lenient in practice | bcachefs (gen=0 accepted) | Escapable empirically |
| Strict (`gen != expected -> ESTALE`) | tmpfs | Requires 2^32 brute-force |

!!! warning "Subdirectory exports only"
    Escape is only meaningful when the NFS export is a subdirectory of a larger filesystem (e.g., exporting `/srv/nfs/shared` from the host's root ext4 partition). If the export IS the filesystem root (the export path matches the mount point), there is nothing outside the export to reach. ReiserFS and NILFS2 fell into this category during testing.

## Reproduction

```bash
# Tier 1 escape (ext4):
nfswolf escape 10.x.x.x:/srv/nfs/shared --uid 0 --gid 0

# Tier 2 escape (BTRFS):
nfswolf escape 10.x.x.x:/srv/nfs/btrfs-export --uid 0 --gid 0

# Shell-based escape:
nfswolf shell 10.x.x.x:/srv/nfs/shared --uid 0 --gid 0
> escape-root
> ls
> cat /etc/shadow

# Fast mode (single export, ~10-80 RPCs):
nfswolf escape 10.x.x.x:/srv/nfs/shared --fast

# Full pipeline with JSON output:
nfswolf escape 10.x.x.x --json --all-handles
```

## Test environment

- **Server:** Ubuntu 24.04, kernel 6.8.0-136-generic, knfsd
- **NFS version:** NFSv3 with `--nfs-version 3 --uid 0 --gid 0`
- **Exports:** Loop-mounted images under `/srv/nfs/fstest/`, all with `*(rw,no_root_squash,no_subtree_check)`
- **Image sizes:** 256 MB (ext/f2fs/JFS/NILFS2/ReiserFS/VFAT/NTFS/UDF/bcachefs) or 512 MB (XFS/BTRFS/ZFS)

## Coverage in nfswolf

The escape engine (`src/engine/escape.rs`) implements the `EscapeProbe` trait with filesystem-specific handle construction for 18 of 19 tested filesystem types. Only tmpfs resists escape entirely.

| Component | Filesystem Coverage |
|-----------|-------------------|
| `escape` subcommand | Tier 1 + Tier 2 (automated) |
| `escape-root` shell command | Tier 1 (automated) |
| `FileHandleAnalyzer` | All tiers (fingerprinting + construction) |
| `find_escape_root()` | 18/19 types via `EscapeProbe` trait |
