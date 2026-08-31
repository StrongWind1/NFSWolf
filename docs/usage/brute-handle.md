# Brute-handle

The `brute-handle` subcommand performs file handle brute-force using the NFS STALE/BADHANDLE error oracle. It systematically generates candidate handles by sweeping the inode and generation number space, probing each against the server to discover valid file handles pointing to directories or files outside the export boundary.

!!! info "When to use brute-handle"
    Most of the time, [`escape`](escape.md) is the right tool. It uses fingerprint-driven construction to find root handles in under 100 RPCs. Reach for `brute-handle` when escape found STALE hits (the handle format is correct) but could not locate the root inode, or when you want to enumerate handles for specific inodes beyond the filesystem root.

## Usage

```bash
nfswolf brute-handle <TARGET[:/export]> [OPTIONS]
```

### Examples

```bash
# Basic brute-force against an export (seed derived from MOUNT)
nfswolf brute-handle 10.0.0.1:/srv/nfs

# Explicit seed from a prior escape or MOUNT
nfswolf brute-handle 10.0.0.1 --seed-handle 01000700020002000000...

# Custom inode range targeting high inodes
nfswolf brute-handle 10.0.0.1:/srv/nfs --inode-start 64 --inode-end 512

# Sweep generation numbers (rare, but needed on some filesystems)
nfswolf brute-handle 10.0.0.1:/srv/nfs --inode-start 1 --inode-end 10 --gen-start 0 --gen-end 100

# Increase attempt cap for large sweeps
nfswolf brute-handle 10.0.0.1:/srv/nfs --inode-end 5000 --max-attempts 50000
```

## The STALE/BADHANDLE oracle

NFSv3 distinguishes two error codes for invalid handles (RFC 1813 S2.6), and this distinction is the foundation of the brute-force search:

| Error | Code | Meaning | Implication |
|-------|------|---------|-------------|
| `NFS3ERR_STALE` | 70 | Handle format is correct, but the inode/generation pair does not exist | The handle layout is right -- keep sweeping the inode/gen space |
| `NFS3ERR_BADHANDLE` | 10001 | Handle format is unrecognized by the server | Wrong structure entirely -- varying inode/gen is wasted work |

This is an oracle: a STALE response positively confirms that the handle's fsid, fileid_type, and structural layout are accepted by the server. The search reduces to iterating the inode and generation fields until a valid inode is found.

A handle is accepted as a hit on any of:

- **NFS3_OK with file type = Directory** -- the primary target (filesystem root or other directory)
- **NFS3_OK with file type != Directory** -- valid inode, reported as an additional discovery
- **NFS3ERR_ACCES** -- the handle is valid but `root_squash` blocks the read; still a usable handle

!!! note "NFSv2 limitation"
    NFSv2 has no BADHANDLE error. All rejections return `NFSERR_STALE` (RFC 1094 S2.3.1), so the format-vs-inode distinction is lost. The brute-force still works but cannot confirm handle format correctness. When MOUNT v3 fails, `brute-handle` falls back to NFSv2 automatically.

## How the seed handle works

The seed handle provides the filesystem identifier (fsid) and handle structure that all candidates inherit. Only the inode and generation fields are varied during the sweep; the rest of the handle bytes are preserved from the seed.

There are two ways to obtain a seed:

1. **Automatic (default)** -- pass `host:/export` and the tool mounts the export via MOUNT v3 (falling back to MOUNT v1) to derive the seed handle.
2. **Explicit** -- pass `--seed-handle HEX` with a hex-encoded handle from a prior escape, MOUNT response, or pcap capture. Use this when the export is no longer mountable or when you have a handle from another source.

The tool fingerprints the seed to determine the filesystem type (ext4, XFS, BTRFS, etc.) and selects the appropriate sweep strategy. For BTRFS, it sweeps subvolume IDs instead of raw inodes. For unknown filesystem types, it tries the standard inode sweep first and falls back to BTRFS subvolume sweep if nothing is found.

## Search space

The search space is the cross product of the inode range and generation range:

```
candidates = (inode_end - inode_start + 1) * (gen_end - gen_start + 1)
```

The default ranges (`--inode-start 0 --inode-end 500 --gen-start 0 --gen-end 0`) produce 501 candidates. On most Linux filesystems, the root inode has generation 0, so sweeping generations is rarely necessary. Increase `--gen-end` when targeting filesystems that use non-zero generations for the root (ReiserFS uses generation 1, NTFS3 uses generation 5).

The `--max-attempts` flag (default 10,000) caps the total number of probes regardless of the range size. The sweep stops when the cap is reached, even if the range has not been fully covered.

## Writability hints

For each discovered handle, the tool reports a non-destructive writability hint derived from the NFSv3 ACCESS procedure (RFC 1813 S3.3.4). It probes as uid=0 first, then as the object's owner if uid=0 is squashed. These hints are advisory; the export's `ro`/`rw` flag and the credential used determine actual writability. Confirm by writing via [`shell`](shell.md) or [`mount`](mount.md).

NFSv2 handles get no writability hint because NFSv2 has no ACCESS procedure.

## Flags reference

| Flag | Default | Description |
|------|---------|-------------|
| `--seed-handle HEX` | -- | Explicit seed handle in hex. Overrides the MOUNT-derived seed. |
| `--max-attempts N` | 10000 | Maximum number of handle probes before stopping. |
| `--inode-start INODE` | 0 | Start of the inode range (inclusive). |
| `--inode-end INODE` | 500 | End of the inode range (inclusive). |
| `--gen-start GEN` | 0 | Start of the generation range (inclusive). |
| `--gen-end GEN` | 0 | End of the generation range (inclusive). 0 means only generation 0 is tried. |
| `-e, --export PATH` | -- | Alternative to the `host:/export` positional syntax. |
| `--mask HEXMASK` | -- | Nibble-mask mode: hex handle with `?` for unknown nibbles (see below). |

## Nibble-mask mode

The `--mask` flag enables OS-agnostic file handle brute force. Instead of varying inode/generation numbers within a known Linux filesystem handle layout, mask mode treats the handle as raw hex and enumerates all combinations of nibbles marked with `?`.

```bash
nfswolf brute-handle 10.0.0.5 --mask 0100020000??00000200000000000000
```

Each `?` represents one hex nibble (4 bits, values 0-F). The tool substitutes every possible value for each `?`, probing 16^N combinations total. Up to 16 wild nibbles are supported (64-bit counter).

This mode requires no filesystem-specific knowledge -- it works against any NFS server regardless of operating system (Linux, OpenBSD, FreeBSD, Solaris, NetApp, Windows Server, etc.). Where the standard inode sweep depends on knowing the handle layout for a specific Linux filesystem type, mask mode works with any handle format by brute-forcing the unknown bytes directly.

### When to use mask mode

Use `--mask` when:

- The target runs a non-Linux NFS server (OpenBSD, FreeBSD, Solaris) where nfswolf has no built-in handle layout knowledge
- `nfswolf decode` shows an unrecognized handle format
- You have a partial handle from a packet capture or log and need to recover the missing bytes
- The filesystem type is unknown and the standard inode sweep found nothing

### Workflow

1. Obtain a valid handle from MOUNT, escape, or a packet capture
2. Use `nfswolf decode` to inspect the handle structure and identify which fields vary
3. Replace the unknown nibbles with `?` in the hex string
4. Run the mask sweep

```bash
# Step 1: decode a known handle to understand the structure
nfswolf decode 0000000062e9877c0c00000002000000fc4fad170000000000000000

# Step 2: the decode output shows bytes 8-9 are the inode field (0c00 = inode 12)
# and bytes 10-13 are a random/generation field. Replace them with ?:
nfswolf brute-handle 10.0.0.5 --mask 0000000062e9877c??000000??000000fc4fad170000000000000000

# Step 3: cap the probe count if the search space is large
nfswolf brute-handle 10.0.0.5 --mask 0000000062e9877c??000000????????fc4fad170000000000000000 --max-attempts 100000
```

### Interaction with other flags

When `--mask` is provided, the tool connects directly to the NFS port without mounting. The `--seed-handle`, `--inode-start/end`, and `--gen-start/end` flags are ignored. The `--max-attempts` flag still applies to cap the total number of probes.

## Output

Every valid handle is printed with its filesystem type, inode number, generation, hex-encoded handle, and writability hint. The first root directory handle is the primary result; additional hits (other directories, files, access-denied handles) are listed separately. After the sweep, a summary line reports the total probes and STALE count.

??? example "Example output"

    ```
    [*] Brute-forcing handles on 10.0.0.1 [Ext4, v3] inodes 0..=500 x gen 0..=0 (501 candidates, max 10000)

      Filesystem:  Ext4  (inode 2  root directory, inode 2 gen 0)
      Writability: writable as uid=0 (advisory; rw export, root not squashed)
      Root handle: 01000702000002000000000000000000000000006ea718660ea71866

      Next steps:
        nfswolf shell 10.0.0.1 --handle 01000702000002000000000000000000000000006ea718660ea71866

    [*] Probed 501 candidates, 498 STALE
    ```

## Related pages

- [Escape](escape.md) -- the primary export escape tool (fingerprint-driven, use first)
- [Decode](decode.md) -- analyze a handle's structure before brute-forcing
- [UID Spray](uid-spray.md) -- credential brute-force (identity space, not handle space)
- [F-2.2 File Handle Guessing](../security/access-control/F-2.2-file-handle-guessing.md) -- the finding that documents handle brute-force attacks
