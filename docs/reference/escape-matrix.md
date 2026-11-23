# Filesystem escape matrix

Systematic testing of NFS export escape (constructing the filesystem root file handle from an export handle) across 18 Linux filesystem types in 22 configurations (four XFS variants and two BTRFS variants are listed separately). All results from live testing on kernel 6.8.0 (Ubuntu 24.04, knfsd) using nfswolf.

!!! info "What is export escape?"
    When an NFS server exports a subdirectory (e.g., `/srv/nfs/shared`), the client receives a file handle scoped to that directory. Export escape constructs a new file handle pointing to the filesystem root (`/`), breaking out of the export boundary. This works because NFS file handles are bearer tokens: any valid handle works regardless of how it was obtained. See [F-2.1](../security/access-control/F-2.1-export-escape.md) for the full finding.

## Summary table

Every escapable row is automated: `nfswolf escape`, `nfswolf escape --fast` and the `escape-root` shell command (which runs the same fast pipeline) all build the static candidate table, the BTRFS subvolume handles and the filesystem-specific constructors for each seed handle. Only the brute-force inode sweep is limited to the full `escape` run.

| Filesystem | Tier | Escapable | Root Inode | Handle Size | fileid_type | Method | Notes |
|------------|------|-----------|-----------|-------------|-------------|--------|-------|
| ext2 | 1 | **Yes** | 2 | 28 B | 1 (INO32_GEN) | `escape` + `escape-root` | Detected as ext4; shared `ext4_export_ops` |
| ext3 | 1 | **Yes** | 2 | 28 B | 1 (INO32_GEN) | `escape` + `escape-root` | Same kernel path as ext2 |
| ext4 | 1 | **Yes** | 2 | 28 B | 1 (INO32_GEN) | `escape` + `escape-root` | Primary ext family |
| XFS v4 | 1 | **Yes** | 128, 64 or 32 | 28 B | 1 (INO32_GEN) | `escape` + `escape-root` | Root inode depends on inode size and AG layout; all three are probed |
| XFS v5 | 1 | **Yes** | 128, 64 or 32 | 28 B | 1 (INO32_GEN) | `escape` + `escape-root` | As above |
| XFS inode64 | 1 | **Yes** | 128, 64 or 32 | 28 B | 1 (INO32_GEN) | `escape` + `escape-root` | isize=512 |
| XFS ino1024 | 1 | **Yes** | 128, 64 or 32 | 28 B | 1 (INO32_GEN) | `escape` + `escape-root` | isize=1024; a larger inode size lowers the root inode number |
| JFS | 1 | **Yes** | 2 | 28 B | 1 (INO32_GEN) | `escape` + `escape-root` | IBM JFS, standard format |
| SquashFS | 1 | **Yes** | Set by mksquashfs | 28 B | 1 (INO32_GEN) | `escape` + `escape-root` | Read-only; the static table probes inodes 2 and 7 |
| NTFS3 | 1 | **Yes** | 5 | 28 B | 1 (INO32_GEN) | `escape` + `escape-root` | gen=5 on freshly formatted volumes |
| f2fs | 1 | **Yes** | 3 | 28 B | 1 (INO32_GEN) | `escape` + `escape-root` | `F2FS_ROOT_INO` is 3, not 2 |
| VFAT | 1 | **Yes** | 1 | 28 B | 1 (INO32_GEN) | `escape` + `escape-root` | FAT root is inode 1 (`MSDOS_ROOT_INO`) in the inode-number handle format (the default, and `nfs=stale_rw`) |
| BTRFS | 2 | **Yes** | subvol 5 | 40 B | 0x4d (BTRFS) | `escape` + `escape-root` | Custom handle; subvol 5 = FS_TREE |
| BTRFS (enc) | 2 | **Yes** | subvol 5 | 40 B | 0x4d (BTRFS) | `escape` + `escape-root` | Encrypted, same handle format |
| ZFS | 3 | **Yes** | object 34 | Custom (12 B fid) | 1 (zfid_short_t payload) | `escape` + `escape-root` | gen=0 bypass for root object |
| EROFS | 3 | **Yes** | 36 (nid) | Custom (12 B fid) | 0x81 (INO64_GEN) | `escape` + `escape-root` | Gen ignored (read-only FS) |
| UDF | 3 | **Yes** | 130 (block) | Custom (12 B fid) | 0x51 (FILEID_UDF) | `escape` + `escape-root` | gen=0 bypasses validation; several common root blocks are probed |
| ISO 9660 | 3 | **Yes** | PVD block | Custom (12 B fid) | 1 (bit-packed) | `escape` + `escape-root` | gen=0 accepted (lenient); root LBAs 18-30 are probed |
| bcachefs | 3 | **Yes** | 4096 | Custom (16 B fid) | 0xb1 (custom) | `escape` + `escape-root` | gen=0 accepted empirically on kernel 6.8 |
| ReiserFS | -- | N/A | 2 | -- | -- | Export is FS root | Nothing to escape to; the static table still carries inode 2 gen=1 |
| NILFS2 | -- | N/A | 2 | -- | -- | Export is FS root | Nothing to escape to; a `FILEID_NILFS` (0x61) root constructor exists |
| tmpfs | 4 | **No** | 1 | 12 B | 1 (non-standard) | -- | Random gen per mount |

## Escapability tiers

### Tier 1: static INO32_GEN candidates (9 filesystem types)

ext2, ext3, ext4, XFS (all four variants), JFS, SquashFS, NTFS3, f2fs, VFAT. These all use the standard knfsd `FILEID_INO32_GEN` format (fileid_type=1) with a 32-bit inode and 32-bit generation number. The generation number for root inodes is 0 for most filesystems; NTFS3 uses gen=5 (the initial MFT Update Sequence Number on freshly formatted volumes). nfswolf's static candidate table (`INO32_GEN_CANDIDATES` in `src/engine/file_handle.rs`) holds nine (inode, generation) pairs, tried in this order:

| Inode | Generation | Filesystem |
|-------|-----------|------------|
| 2 | 0 | ext2, ext3, ext4, JFS |
| 3 | 0 | f2fs |
| 1 | 0 | VFAT |
| 128 | 0 | XFS |
| 64 | 0 | XFS |
| 32 | 0 | XFS |
| 5 | 5 | NTFS3 |
| 2 | 1 | ReiserFS |
| 7 | 0 | SquashFS |

When the seed handle carries a generation number of its own, every inode in the table is tried with that generation as well. The probe layer rejects hits that are not directories or that resolve to the export itself, so a table entry that happens to name an ordinary file on another filesystem is harmless.

Both `nfswolf escape` and the `escape-root` shell command work without any special flags.

**Handle structure (28 bytes, fsid_type=6):**

```text
01 00 06 01  -- version=1, auth_type=0, fsid_type=6 (UUID16), fileid_type=1 (INO32_GEN)
XX XX XX XX XX XX XX XX XX XX XX XX XX XX XX XX  -- 16-byte filesystem UUID
02 00 00 00  -- root inode (LE u32: 2 for ext/JFS, 3 for f2fs, 1 for VFAT, 128/64/32 for XFS, 5 for NTFS3)
00 00 00 00  -- generation (0 for most; 5 for NTFS3)
```

The fsid portion is copied from the seed handle, so its length follows the seed's fsid_type (4 to 24 bytes); only the fileid portion is replaced.

**XFS root inode.** An XFS inode number encodes the allocation group, the AG block and the slot within that block, so the root inode (`sb_rootino`, the first inode of the first inode chunk in AG 0) is the AG block of that chunk shifted left by log2(inodes per block). Doubling the inode size halves the inodes per block and halves the root inode number, and the chunk's AG block depends on the mkfs layout. nfswolf does not try to predict which value a given mkfs produced; it probes 128, 64 and 32. XFS also switches to `FILEID_INO64_GEN` (0x81: 64-bit inode, 32-bit generation) when the filesystem's inode numbers do not all fit in 32 bits; the test images were small enough for type 1. The constructor keeps whichever fileid_type the seed handle carries.

**SquashFS root inode.** mksquashfs assigns inode numbers when it builds the image, so the root's number varies by image. The static table covers inodes 2 and 7, and the full `escape` sweep covers the rest of the low range.

**Brute-force sweep (full `escape` only).** After the table, `escape` without `--fast` tries inodes 1-5 with generations 0-5, then inodes 6 to `--max-root-scan` (default 200) with generation 0. `--fast` and `escape-root` skip this sweep.

### Tier 2: BTRFS subvolumes

BTRFS uses a custom handle format (fileid_type=0x4d) that names the subvolume tree. nfswolf builds a handle for the root directory (objectid 256) of subvolume 5 (`FS_TREE_OBJECTID`), then of user subvolumes 256 and up: `--btrfs-subvols` of them (default 16) in a full `escape` run, two in `--fast` and `escape-root`. For a compound-UUID seed (fsid_type=7), each handle is also built in the UUID-only fsid_type=6 form.

**BTRFS root handle (40 bytes, fsid_type=6):**

```text
01 00 06 4d  -- version=1, auth_type=0, fsid_type=6 (UUID16), fileid_type=0x4d (BTRFS)
XX XX XX XX XX XX XX XX XX XX XX XX XX XX XX XX  -- 16-byte filesystem UUID
00 01 00 00 00 00 00 00  -- objectid (LE u64): 256, the subvolume's root directory
05 00 00 00 00 00 00 00  -- root_objectid (LE u64): subvolume 5
00 00 00 00  -- generation
```

### Tier 3: filesystem-specific handle construction (ZFS, EROFS, UDF, ISO 9660, bcachefs)

These filesystems use custom `encode_fh()` implementations with non-standard handle layouts, but escape is possible because their generation checks are weak or absent for the root object. nfswolf has a constructor for each and runs them automatically after the BTRFS handles.

| Filesystem | Root ID | FID Layout | Gen Check | Why Escape Works |
|------------|---------|-----------|-----------|------------------|
| ZFS | object 34 | `zfid_short_t{zf_len: u16, zf_object: [u8; 6], zf_gen: [u8; 4]}` under fileid_type 1 | Strict, but root bypasses | `zfs_vget()` has explicit gen=0 bypass for root object |
| EROFS | nid 36 | `FILEID_INO64_GEN{nid_hi, nid_lo, gen}` | Ignored entirely | Read-only FS; staleness impossible |
| UDF | block 130 | `FILEID_UDF{block, partref, parent_partref, gen}` | Lenient: `if (gen && gen != ...)` | gen=0 skips the validation check; blocks 66, 130, 258, 2, 64, 128, 256 and 512 are probed |
| ISO 9660 | PVD block | Custom bit-packed `{block, offset, gen}` | Lenient | Same gen=0 bypass as UDF; root LBAs 18-30 are probed |
| bcachefs | inum 4096 | `{inum: u64, subvol: u32, gen: u32}` | Strict in source, lenient in practice | gen=0 accepted empirically on kernel 6.8 despite strict check in source |

All five confirmed with live read of files outside the export boundary. The engine also carries a constructor for NILFS2 (`FILEID_NILFS_WITHOUT_PARENT`, inode 2, checkpoint 0), for servers that hand out that format. FAT exports mounted `nfs=nostale_ro` use `FILEID_FAT_WITHOUT_PARENT` (0x71) handles keyed on the directory entry position, which nfswolf does not construct.

### Tier 4: not escapable (tmpfs)

tmpfs enforces a strict 32-bit generation check with a random value that rejects gen=0. Without knowing the exact generation value, which is unpredictable, escape requires brute-forcing 2^32 values (~4 billion probes).

| Filesystem | Root Inode | Why Escape Fails |
|------------|-----------|-----------------|
| tmpfs | 1 | Gen assigned from `get_random_u32()` at mount time; `ilookup5()` requires exact hash match |

## Kernel `encode_fh` analysis

The following analysis is based on Linux 6.8.0 kernel source.

### Standard path (Tier 1 filesystems)

ext2/3/4, XFS, JFS, SquashFS, NTFS3, f2fs and VFAT all use `generic_encode_ino32_fh` or equivalent, producing `FILEID_INO32_GEN` (type 1) handles. The `generic_fh_to_dentry` path does not enforce generation for root inodes on most filesystems (gen=0 is accepted). NTFS3 enforces a strict gen check, but the root directory (MFT entry 5) has a known initial generation of 5 on freshly formatted volumes, so the handle is constructible without brute-force.

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
typedef struct zfid_short {
    uint16_t zf_len;          // 10
    uint8_t  zf_object[6];    // little-endian; 34 for root
    uint8_t  zf_gen[4];       // little-endian
} zfid_short_t;
```

knfsd reports fileid_type 1 for these handles, so nfswolf writes fileid_type 1 followed by the 12-byte `zfid_short_t` with object 34 and generation 0.

`zfs_zget()` has a gen=0 bypass specifically for the root object, making escape trivial once you know the layout.

### bcachefs (`fs/bcachefs/fs.c`)

Custom fileid types (`FILEID_BCACHEFS_WITHOUT_PARENT` for dirs):

```c
struct bcachefs_fid { u64 inum; u32 subvol; u32 gen; } __packed;  // 16 bytes
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

The escape engine (`src/engine/escape.rs`, with the constructors in `src/engine/file_handle.rs`) builds root handle candidates for 17 of the 18 filesystem types tested; only tmpfs resists escape entirely. 15 were confirmed by a live escape. ReiserFS and NILFS2 were exported at their filesystem root in the test setup, so there was nothing to escape to.

| Component | Filesystem Coverage |
|-----------|-------------------|
| `escape` subcommand | Tiers 1-3, plus the brute-force inode sweep (automated) |
| `escape --fast` | Tiers 1-3 for one export, no sweep (automated) |
| `escape-root` shell command | Same as `escape --fast`: it calls the same `run_fast()` pipeline |
| `FileHandleAnalyzer` | All tiers (fingerprinting + construction) |
| `find_escape_root()` | Tiers 1-3 plus the sweep, via the `EscapeProbe` trait |
