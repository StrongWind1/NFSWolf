# Decode

The `decode` subcommand is a fully offline NFS file handle decoder. It takes a hex-encoded handle and prints every decoded field, the OS and filesystem fingerprint, and a security assessment. No network access, no NFS server needed. Works with handles from any NFS version (v2/v3/v4) or any source (MOUNT response, escape output, GETFH, pcap capture).

## Usage

```bash
nfswolf decode <HEX_HANDLE>
```

The handle must be at least 4 bytes (8 hex characters) and have even length.

### Examples

```bash
# Decode a handle from a prior escape or scan
nfswolf decode 01000702000002000000000000000000000000006ea718660ea71866

# Decode a short MOUNT v1 handle
nfswolf decode 0100040001000200c7a34f12

# Decode a BTRFS handle
nfswolf decode 0100060600000000abcdef0123456789004d000100000000000000000001000000
```

## Output sections

The decoder prints four sections for every handle.

### Header (bytes 0-3)

The first four bytes of a Linux knfsd handle encode the handle version, authentication type (deprecated, always 0), fsid type, and fileid type:

| Byte | Field | Description |
|------|-------|-------------|
| 0 | `version` | Handle format version. 1 = Linux knfsd. |
| 1 | `auth_type` | Deprecated, always 0. |
| 2 | `fsid_type` | How the filesystem is identified (device, UUID, fsid number). |
| 3 | `fileid_type` | How the file is identified within the filesystem (inode format). |

The fsid_type determines the filesystem identification scheme:

| Type | Name | Size | Fields |
|------|------|------|--------|
| 0 | FSID_DEV | 8 bytes | device major/minor + inode |
| 1 | FSID_NUM | 4 bytes | user-specified fsid number (pseudo-FS) |
| 2 | FSID_MAJOR_MINOR | 12 bytes | explicit major + minor + inode (deprecated) |
| 3 | FSID_ENCODE_DEV | 8 bytes | encoded device + inode |
| 4 | FSID_UUID4_INUM | 8 bytes | 4-byte UUID prefix + inode |
| 5 | FSID_UUID8 | 8 bytes | 8-byte UUID prefix |
| 6 | FSID_UUID16 | 16 bytes | full 16-byte filesystem UUID |
| 7 | FSID_UUID16_INUM | 24 bytes | export inode + generation + 16-byte UUID |

The fileid_type determines the inode encoding:

| Type | Name | Description |
|------|------|-------------|
| 0x00 | FILEID_ROOT | Mount/export root (no inode data) |
| 0x01 | INO32_GEN | 32-bit inode + generation (ext4, JFS, f2fs) |
| 0x02 | INO32_GEN_PARENT | 32-bit inode + gen + parent inode + parent gen |
| 0x4d | BTRFS_WITHOUT_PARENT | objectid + root_objectid + generation |
| 0x4e-0x4f | BTRFS_WITH_PARENT | objectid + root + gen + parent data |
| 0x51-0x52 | UDF | block + partref + generation |
| 0x61-0x62 | NILFS | checkpoint + inode + generation |
| 0x71 | FAT_WITHOUT_PARENT | generation + i_pos |
| 0x81-0x82 | INO64_GEN | 64-bit inode + generation (XFS, EROFS) |
| 0xb1-0xb2 | BCACHEFS | inode + subvolume + generation |

### Filesystem ID (fsid)

The decoded filesystem identifier. Depending on the fsid_type, this includes device numbers, filesystem UUIDs, export inode numbers, or synthetic fsid values. The UUID is particularly useful for correlating handles from different exports that share the same underlying filesystem.

### File ID (fileid)

The decoded inode information. For FILEID_ROOT (type 0x00), this section notes that the handle points to the export/mount root with no embedded inode data. For all other types, it prints the inode number, generation counter, and any parent information. BTRFS handles additionally show the root_objectid (subvolume number) with a human-readable label.

### Fingerprint and assessment

The OS and filesystem fingerprint is derived from the handle structure by `FileHandleAnalyzer`. The security assessment categorizes the handle:

| Tag | Meaning |
|-----|---------|
| `[BEST]` | Full export context with real inode data -- ideal for escape construction |
| `[GOOD]` | Export root or UUID-only with usable inode -- viable escape seed |
| `[BTRFS]` | BTRFS handle reaching the volume root, not the host root |
| `[CAUTION]` | UUID-only with real inode -- may resolve to pseudo-root on NFSv4 |
| `[PSEUDO]` | Pseudo-FS synthetic handle (fsid_num) -- not a real filesystem, cannot escape |
| `[?]` | Unknown handle type |

All non-pseudo handles are noted as cross-protocol: a handle obtained via one NFS version works on v2, v3, and v4 (on servers that support the respective version).

??? example "Example output"

    ```
      Handle: 28 bytes
      01000702000002000000000000000000000000006ea718660ea71866

      Header
        byte 0  version      = 1 (Linux knfsd)
        byte 1  auth_type    = 0 (deprecated, always 0)
        byte 2  fsid_type    = 7 (FSID_UUID16_INUM: export inode + generation + 16-byte UUID)
        byte 3  fileid_type  = 0x02 (INO32_GEN_PARENT: 32-bit inode + gen + parent inode + parent gen)

      Filesystem ID (fsid)
        export_ino   = 2
        export_gen   = 0
        uuid         = 000000000000000000006ea718660ea71866

      File ID (fileid)
        inode        = 2
        generation   = 0
        parent_inode = 0
        parent_gen   = 0

      Fingerprint
        OS:         Linux
        Filesystem: Ext4

      Assessment
        [BEST] This handle has full export context and real inode data.
        Handles are cross-protocol: this handle works on NFSv2, v3, and v4
        (on servers that support the respective version).
    ```

## Use cases

- **Pre-escape analysis** -- decode a handle from `scan` output to determine whether the filesystem type supports escape before running `nfswolf escape`.
- **Handle provenance** -- identify which filesystem and inode a handle references when working with handles from multiple exports.
- **Forensics** -- decode handles captured from network traffic (pcap) or NFS server logs without needing access to the server.
- **BTRFS subvolume mapping** -- decode BTRFS handles to identify which subvolume a handle reaches (objectid 5 = fs-tree root, 256+ = named subvolumes).

## Related pages

- [Escape](escape.md) -- uses handles decoded here as seeds for export escape
- [Brute Handle](brute-handle.md) -- generates candidate handles by sweeping the inode/gen space
- [File Handles](../nfs/file-handles.md) -- background on NFS file handle architecture and security implications
