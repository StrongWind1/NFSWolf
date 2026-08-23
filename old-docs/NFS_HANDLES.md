# NFS File Handles -- Technical Reference

A complete guide to Linux NFS file handle structure, byte layout, and security implications. Every field and value documented here was verified against the Linux kernel source (`fs/nfsd/nfsfh.h`, `include/linux/exportfs.h`) and live-tested with nfswolf against 7 lab servers.

---

## What a File Handle Is

A file handle is an opaque byte sequence that identifies a file or directory on the NFS server. The client receives handles via MOUNT (v2/v3) or LOOKUP/GETFH (v4), and sends them back in every subsequent operation. The server never validates that the client obtained the handle through normal navigation -- it only checks that the bytes resolve to a valid inode. This is why handles are bearer tokens: whoever holds the bytes has access.

---

## Wire Format

Linux knfsd file handles are a sequence of 32-bit words. The first word is always a 4-byte header:

```
Byte  Field           Description
────  ──────────────  ──────────────────────────────────────────────────
 0    fh_version      Always 0x01 on Linux knfsd
 1    fh_auth_type    Deprecated, always 0x00
 2    fh_fsid_type    How the filesystem/export is identified (see table)
 3    fh_fileid_type  How the file within the filesystem is identified (see table)
 4+   fh_fsid[]       Variable-length filesystem identifier
 4+N  fh_fileid[]     Variable-length file identifier (inode, generation, etc.)
```

All multi-byte values are in **host byte order** (little-endian on x86). This differs from the XDR encoding of RPC messages (big-endian) -- the handle contents are opaque to the RPC layer and passed through without byte-swapping.

### Handle Size Limits

| NFS Version | Max Handle Size | Typical Size |
|---|---|---|
| NFSv2 | 32 bytes (fixed, zero-padded) | 20 bytes of data + 12 bytes padding |
| NFSv3 | 64 bytes (variable-length, XDR length-prefixed) | 20-44 bytes |
| NFSv4 | 128 bytes (variable-length) | 8-44 bytes |

---

## fsid_type (Byte 2) -- Filesystem Identification

The `fsid_type` determines how the server identifies which filesystem the handle belongs to. This is the key field for escape handle construction: the escape handle must preserve the fsid from the seed so the server maps it to the same filesystem.

| Value | Name | Size | Layout | Notes |
|---|---|---|---|---|
| 0 | FSID_DEV | 8 bytes | `dev_major(2) dev_minor(2) ino(4)` | Older format. dev encodes the block device. |
| 1 | FSID_NUM | 4 bytes | `fsidnum(4)` | User-specified `fsid=` value from `/etc/exports`. Pseudo-FS root uses this. |
| 2 | FSID_MAJOR_MINOR | 12 bytes | `major(4) minor(4) ino(4)` | Deprecated. Explicit major/minor split. |
| 3 | FSID_ENCODE_DEV | 8 bytes | `encoded_dev(4) ino(4)` | `new_encode_dev()` format, userspace-compatible. |
| 4 | FSID_UUID4_INUM | 8 bytes | `ino(4) uuid[0..3](4)` | First 4 bytes of filesystem UUID + inode. |
| 5 | FSID_UUID8 | 8 bytes | `uuid[0..7](8)` | First 8 bytes of filesystem UUID. |
| 6 | FSID_UUID16 | 16 bytes | `uuid[0..15](16)` | Full 16-byte filesystem UUID. |
| 7 | FSID_UUID16_INUM | 24 bytes | `export_ino(4) export_gen(4) uuid[0..15](16)` | Full UUID + export directory inode/generation. Called "compound UUID". |

### Security Implications of fsid_type

**fsid_type=7 (compound UUID)** is the most important for escape:
- The `export_ino` and `export_gen` identify WHICH export on this filesystem the handle belongs to
- The server applies that export's `root_squash`/`all_squash`/`ro` settings based on this field
- Different exports on the same filesystem have different `export_ino` values but the same UUID
- An escape handle constructed from one export's seed inherits that export's squash settings

**fsid_type=6 (UUID-only)** lacks the export context:
- No `export_ino` or `export_gen` -- the server cannot determine which export the handle belongs to
- On NFSv4, this handle may resolve to the pseudo-filesystem root instead of the real filesystem
- On NFSv3, the server typically resolves it to the export with the matching UUID

**fsid_type=1 (pseudo-FS)** is synthetic:
- Only 4 bytes (user-specified number)
- Used for the NFSv4 pseudo-root (`fsid=0` in `/etc/exports`)
- Not a real filesystem -- cannot be used for escape

---

## fileid_type (Byte 3) -- File Identification

The `fileid_type` tells the server how to interpret the file-identification bytes that follow the fsid. This is filesystem-specific: ext4 uses one format, BTRFS uses another, XFS uses another.

### Standard Types (from `include/linux/exportfs.h`)

| Value | Name | Fileid Size | Layout | Filesystem |
|---|---|---|---|---|
| 0x00 | FILEID_ROOT | 0 bytes | (none) | Mount/export root. No inode data. |
| 0x01 | FILEID_INO32_GEN | 8 bytes | `inode(4) generation(4)` | ext2/3/4, JFS, f2fs, reiserfs, VFAT, NTFS3, squashfs |
| 0x02 | FILEID_INO32_GEN_PARENT | 16 bytes | `inode(4) gen(4) parent_ino(4) parent_gen(4)` | ext2/3/4 (with parent) |
| 0x4d | FILEID_BTRFS_WITHOUT_PARENT | 24 bytes | `objectid(8) root_objectid(8) generation(4)` | BTRFS |
| 0x4e | FILEID_BTRFS_WITH_PARENT | 40 bytes | `objectid(8) root_objectid(8) gen(4) parent_objectid(8) parent_gen(4)` | BTRFS (with parent) |
| 0x4f | FILEID_BTRFS_WITH_PARENT_ROOT | 48 bytes | Above + `parent_root_objectid(8)` | BTRFS (with parent root) |
| 0x51 | FILEID_UDF_WITHOUT_PARENT | 8 bytes | `block(4) partref(2) unused(2) generation(4)` | UDF |
| 0x52 | FILEID_UDF_WITH_PARENT | 16 bytes | Above + `parent_block(4) parent_gen(4)` | UDF |
| 0x61 | FILEID_NILFS_WITHOUT_PARENT | 20 bytes | `cno(8) ino(8) gen(4)` | NILFS2 |
| 0x62 | FILEID_NILFS_WITH_PARENT | 32 bytes | Above + `parent_gen(4) parent_ino(8)` | NILFS2 |
| 0x71 | FILEID_FAT_WITHOUT_PARENT | 12 bytes | `gen(4) i_pos_hi(1) i_pos_lo(4)` | VFAT/exFAT |
| 0x81 | FILEID_INO64_GEN | 12 bytes | `inode(8) generation(4)` | XFS, EROFS |
| 0x82 | FILEID_INO64_GEN_PARENT | 24 bytes | `inode(8) gen(4) parent_inode(8) parent_gen(4)` | XFS (with parent) |
| 0xb1 | FILEID_BCACHEFS_WITHOUT_PARENT | 16 bytes | `inode(8) subvol(4) gen(4)` | bcachefs |
| 0xb2 | FILEID_BCACHEFS_WITH_PARENT | 28 bytes | Above + `parent fields` | bcachefs |
| 0xff | FILEID_INVALID | -- | -- | Reserved, never used |

### Root Inode Values by Filesystem

When constructing an escape handle, the fileid must target the filesystem root directory. Each filesystem has a specific root inode number:

| Filesystem | Root Inode | Generation | Notes |
|---|---|---|---|
| ext2/3/4 | 2 | 0 | Always inode 2, gen ignored on root |
| XFS v5 | 128 | 0 | `XFS_INO64_GEN`. XFS v4: 64 or 32 |
| BTRFS | 256 (default subvol) or 5 (fs-tree root) | -- | objectid, not inode. root_objectid=subvol_id |
| JFS | 2 | 0 | Same as ext4 |
| f2fs | 3 | 0 | Root inode is 3, not 2 |
| reiserfs | 2 | 1 | Generation is 1, not 0 |
| NTFS3 | 5 | 5 | MFT root record. Gen = MFT sequence number |
| VFAT | 1 | 0 | Root cluster |
| squashfs | 7 | 0 | Offset-based, not a true inode |
| ZFS | 3 | 0 | `zfid_short_t` with `zf_object=3`, gen ignored |
| EROFS | 36 | 0 | Uses `INO64_GEN`, nid=36 is typical root |
| NILFS2 | 2 | 0 | cno=0 (checkpoint 0 = current) |
| bcachefs | 4096 | 0 | inum=4096, subvol=1 |
| UDF | 2-512 | 0 | Block-based, varies by disc layout |
| ISO9660 | 18-30 | 0 | Block-based, varies by disc layout |
| tmpfs | random | random | 32-bit random per mount, not escapable |

---

## Complete Handle Examples

### Example 1: MOUNT v3 handle (fsid_type=7, ext4)

```
Hex: 01 00 07 00 60000200 00000000 1d96c9d9009c49daa193f721ec3fe9b6

Byte  Value       Field
────  ──────────  ──────────────────────────────
 0    01          fh_version = 1
 1    00          fh_auth_type = 0 (unused)
 2    07          fh_fsid_type = 7 (compound UUID)
 3    00          fh_fileid_type = 0 (FILEID_ROOT, export root)
 4-7  60000200    export_ino = 0x00020060 (LE) = inode 131168
 8-11 00000000    export_gen = 0
12-27 1d96c9d9... uuid = filesystem UUID (16 bytes)

Total: 28 bytes. This is the export root handle (fileid_type=0 means
"the root of this mount point"). No inode data in the fileid section.
```

### Example 2: Escape handle constructed from Example 1

```
Hex: 01 00 07 02 60000200 00000000 1d96c9d9009c49daa193f721ec3fe9b6
     02000000 00000000 02000000 00000000

Byte  Value       Field
────  ──────────  ──────────────────────────────
 0    01          fh_version = 1
 1    00          fh_auth_type = 0
 2    07          fh_fsid_type = 7 (compound UUID, same as seed)
 3    02          fh_fileid_type = 2 (INO32_GEN_PARENT, changed from 0)
 4-27 (same)      fsid preserved from seed (same export context)
28-31 02000000    inode = 2 (ext4 root, LE)
32-35 00000000    generation = 0
36-39 02000000    parent_inode = 2 (root is its own parent)
40-43 00000000    parent_generation = 0

Total: 44 bytes. The server resolves inode 2 on the same filesystem
and applies the export's squash/ro settings based on export_ino.
```

### Example 3: MOUNT v1 handle (fsid_type=4, zero-padded to 32 bytes)

```
Hex: 01 00 04 00 60000200 50a69e94 00000000...00000000

Byte  Value       Field
────  ──────────  ──────────────────────────────
 0    01          fh_version = 1
 1    00          fh_auth_type = 0
 2    04          fh_fsid_type = 4 (FSID_UUID4_INUM)
 3    00          fh_fileid_type = 0 (FILEID_ROOT)
 4-7  60000200    ino = inode of export dir
 8-11 50a69e94    uuid[0..3] = first 4 bytes of UUID
12-31 00000000... zero padding to fill NFSv2's fixed 32-byte handle

Total: 32 bytes (NFSv2 fixed size). Only 12 bytes of data, rest is padding.
MOUNT v1 returns this fixed-size format because NFSv2 handles are always 32 bytes.
```

### Example 4: BTRFS handle (fileid_type=0x4d)

```
Hex: 01 00 06 4d 4894757213b8af42 0000000000000000
     00010000 00000000 05000000 00000000 00000000

Byte  Value             Field
────  ────────────────  ──────────────────────────────
 0    01                fh_version = 1
 1    00                fh_auth_type = 0
 2    06                fh_fsid_type = 6 (UUID-only, 16 bytes)
 3    4d                fh_fileid_type = 0x4d (BTRFS_WITHOUT_PARENT)
 4-19 4894757213b8...   uuid (16 bytes)
20-27 0001000000000000  objectid = 256 (LE u64, default subvolume)
28-35 0500000000000000  root_objectid = 5 (LE u64, fs-tree root)
36-39 00000000          generation = 0

Total: 40 bytes. BTRFS uses 64-bit object IDs instead of inodes.
objectid=256 is the default subvolume. root_objectid=5 is the fs-tree.
```

### Example 5: NFSv4 pseudo-root

```
Hex: 01 00 01 00 00000000

Byte  Value       Field
────  ──────────  ──────────────────────────────
 0    01          fh_version = 1
 1    00          fh_auth_type = 0
 2    01          fh_fsid_type = 1 (user-specified fsid number)
 3    00          fh_fileid_type = 0 (FILEID_ROOT)
 4-7  00000000    fsid number = 0

Total: 8 bytes. This is the NFSv4 pseudo-root, a synthetic directory
that connects all exports. It is NOT a real filesystem and cannot be
used for escape. LOOKUP from here navigates the pseudo-FS namespace.
```

---

## NFS Version Differences

### NFSv2

- Handles are **fixed 32 bytes**, zero-padded. No length prefix on the wire.
- MOUNT v1 returns handles in this format.
- Only fsid_type 0, 3, 4 are common (shorter fsid fits in 32 bytes with fileid data).
- fsid_type 7 (compound UUID, 24-byte fsid) leaves only 4 bytes for fileid data, so fileid_type is typically 0 (root) or 1 (INO32_GEN with 8 bytes).

### NFSv3

- Handles are **variable-length up to 64 bytes**, XDR length-prefixed on the wire.
- MOUNT v3 returns handles in this format.
- All fsid_types are supported. fsid_type 7 with fileid_type 2 (INO32_GEN_PARENT) produces 44-byte handles.
- The extra space allows fileid_type 2 (with parent inode), which is useful for `subtree_check`.

### NFSv4

- Handles are **variable-length up to 128 bytes**, XDR opaque on the wire.
- No MOUNT protocol -- handles are obtained via PUTROOTFH + LOOKUP + GETFH.
- The pseudo-root handle (fsid_type=1, 8 bytes) is unique to NFSv4.
- All real filesystem handles use the same byte format as v3.
- **Handles are cross-protocol**: a handle from MOUNT v3 works with NFSv4 COMPOUND (PUTFH), and vice versa, on servers that support both versions.

---

## Escape Construction Rules

1. **Preserve the fsid**: copy all fsid bytes from the seed handle unchanged. This ensures the escape handle maps to the same filesystem.

2. **Change the fileid_type**: replace byte 3 with the appropriate fileid_type for the target filesystem (0x01 for ext4, 0x4d for BTRFS, 0x81 for XFS, etc.).

3. **Set the root inode**: write the filesystem's root inode number and generation=0 into the fileid section.

4. **For compound UUID seeds (fsid_type=7)**: also produce a fsid_type=6 variant by stripping the `export_ino` and `export_gen` (bytes 4-11) and keeping only the UUID (bytes 12-27). This gives a second escape vector, though on NFSv4 it may resolve to the pseudo-root instead.

5. **The seed must come from inside the target filesystem**: a pseudo-FS handle or a handle from a different filesystem will not work because the fsid won't match.

---

## Handle Sources in nfswolf

| Source | How obtained | fsid_type | fileid_type | When available |
|---|---|---|---|---|
| MOUNT v3 | MNTPROC3_MNT | 6 or 7 | 0 (root) | v3 server with mountd |
| MOUNT v1 | MNTPROC1_MNT | 0, 3, or 4 | 0 (root) | v2 server with mountd |
| NFSv4 LOOKUP | PUTROOTFH + LOOKUP chain + GETFH | 6 or 7 | 0 (root) | v4 server |
| NFSv4 child LOOKUP | LOOKUP into export + READDIR + LOOKUP child | varies | 1+ (real inode) | v4 server (escape --all) |
| NFSv4 LOOKUPP | LOOKUPP loop from export | 1 | 0 | v4 server (pseudo-root) |
| WebNFS | PUTPUBFH + LOOKUP | varies | varies | v3/v4 with WebNFS enabled |

---

## Kernel Source References

| File | What it defines |
|---|---|
| `fs/nfsd/nfsfh.h` | `struct knfsd_fh`, `fh_version`/`fh_auth_type`/`fh_fsid_type`/`fh_fileid_type` offsets, fsid_type values 0-7 |
| `include/linux/exportfs.h` | `enum fid_type` (all fileid_type values), `struct fid` union layouts |
| `fs/nfsd/nfsfh.c` | `fh_verify()` -- handle validation, `fh_compose()` -- handle construction |
| `fs/nfsd/export.c` | Export lookup by fsid, `subtree_check` enforcement |
| `fs/exportfs/expfs.c` | `exportfs_decode_fh()` -- dispatches to per-FS `fh_to_dentry()` |
