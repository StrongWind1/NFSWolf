# Lateral movement

Lateral movement in NFS takes an attacker from access to a single export to access across the server's entire filesystem -- and potentially to other exports restricted to different clients. The key insight is that NFS export boundaries are an illusion enforced at mount time, not in the data path. Once the attacker holds a file handle, the export boundary disappears.

This stage bridges [initial access](access.md) and [privilege escalation](privesc.md). The attacker starts with a handle to `/srv/nfs/public` and ends with handles to `/etc`, `/home`, and every directory on the filesystem.

---

## Findings in this stage

| Finding | Name | Severity | nfswolf Subcommand | What It Enables |
|---------|------|----------|-------------------|----------------|
| [F-2.1](../access-control/F-2.1-export-escape.md) | Export Escape via Filesystem Root Handle | Critical | `escape`, `shell escape-root` | Construct handle for inode 2 to reach the filesystem root from any subdirectory export |
| [F-2.5](../access-control/F-2.5-stale-handle-persistence.md) | Cross-Export Handle Reuse | Medium | `shell --handle`, `shell mount-handle` | Handles obtained via one export or credential work with any other |
| [F-2.8](../access-control/F-2.8-sibling-export-lateral-access.md) | Sibling Export Lateral Access | Critical | `escape` + `shell` | After escaping to filesystem root, LOOKUP reaches any directory on the filesystem -- including IP-restricted peer exports |
| [F-2.11](../access-control/F-2.11-nfsv4-lookupp-export-escape.md) | NFSv4 LOOKUPP Export Escape | Critical | `shell` (v4), `escape` | LOOKUPP walks up from any subdirectory export to the filesystem root -- no handle construction needed |
| [F-2.12](../access-control/F-2.12-nfsv4-lookupp-cross-export-lateral.md) | NFSv4 Cross-Export via LOOKUPP | High | `shell exports`, `shell` (v4) | LOOKUPP to pseudo-root, then LOOKUP into any sibling export over a single TCP connection |
| [F-2.6](../access-control/F-2.6-bind-mount-escape.md) | Bind Mount Export Escape | High | `escape` | Bind mounts share the same fsid; handle construction reaches the underlying filesystem root |
| [F-2.10](../access-control/F-2.10-sign-fh-root-exemption.md) | SIGN_FH Root Handle Exemption | Medium | `shell --handle` | Root handles bypass SIGN_FH MAC verification -- fileid_type 0x00 is exempt |

---

## Two escape paths

### NFSv3/v2: handle construction

The attacker fingerprints the file handle structure from the MOUNT-returned seed handle, identifies the filesystem type (ext4, XFS, BTRFS, etc.), and constructs a new handle pointing to the filesystem root inode. On ext4 this is inode 2; on BTRFS it is subvolume 5 with objectid 256; on ZFS it uses a different root encoding. The constructed handle is validated with GETATTR, then READDIRPLUS enumerates the real root directory.

```text
Export:     /srv/nfs/data       (seed handle from MOUNT)
Escape:     /                   (constructed handle for inode 2)
Lateral:    /etc/shadow         (LOOKUP from escaped root)
            /home/admin/.ssh/   (LOOKUP from escaped root)
            /srv/nfs/restricted (another export on the same filesystem)
```

nfswolf supports escape construction for 18 of 19 Linux filesystem types. Only tmpfs resists because it uses opaque pointer-based handles with no inode addressing.

### NFSv4: LOOKUPP traversal

NFSv4's LOOKUPP operation walks upward from any subdirectory export to the filesystem root -- a single `cd ..` is sufficient, with no handle construction or fingerprinting required. See [F-2.11](../access-control/F-2.11-nfsv4-lookupp-export-escape.md) for the full technical detail. Cross-export lateral movement via the pseudo-filesystem namespace is covered in [F-2.12](../access-control/F-2.12-nfsv4-lookupp-cross-export-lateral.md).

---

## Cross-export lateral access

Once the attacker escapes to the filesystem root (via F-2.1 or F-2.11), any directory on the same filesystem is reachable through standard LOOKUP operations. This means:

- An export restricted to `10.0.0.0/24` that shares a filesystem with a wildcard export (`*`) is accessible to anyone who can reach the wildcard export.
- The per-export security policy (`root_squash`, `ro`, IP ACLs) is evaluated against the escape handle's source export, not the target directory.
- `crossmnt`/`nohide` exports (F-7.3) further extend reach by exposing sub-mounted filesystems through the parent export's LOOKUP path.

!!! danger "The filesystem boundary is what matters"
    Export ACLs are enforced per-export, but file handles are scoped per-filesystem. Two exports on the same ext4 partition share the same fsid. A handle valid for one is valid for the other. The only reliable boundary is a separate physical filesystem (separate partition, separate LVM volume, separate ZFS dataset).

---

## Filesystem-specific escape behavior

nfswolf supports escape construction for 18 of 19 Linux filesystem types (only tmpfs resists due to opaque pointer-based handles). Escape difficulty ranges from trivial (ext4 inode 2, XFS inode 128) to low (BTRFS compound UUID, ZFS root dataset). See [F-2.1](../access-control/F-2.1-export-escape.md) for the full filesystem root inode table and per-filesystem escape strategy.

The `decode` subcommand (`nfswolf decode <hex>`) performs offline analysis of any file handle, printing its header, fsid, fileid, OS/FS fingerprint, and security assessment without network access. This reveals the filesystem type and escape strategy before any escape attempt.

---

## The `exports` shell command

The `exports` command in the nfswolf shell enumerates reachable sibling exports via LOOKUPP traversal. Starting from the current export, it walks up to the pseudo-root (NFSv4) or filesystem root (NFSv3 after escape), lists all sibling directories, and reports which ones correspond to known exports from the MOUNT EXPORT list. This maps the attacker's reachable scope without manual directory walking.

---

## Relationship to other stages

Lateral movement consumes the filesystem fingerprint and export topology from [reconnaissance](recon.md), uses the initial file handle from [initial access](access.md), and produces the expanded filesystem access that enables [privilege escalation](privesc.md) and [data exfiltration](exfil.md). An attacker who escapes to `/` can read `/etc/shadow` (exfiltration), find SUID binaries (escalation), or plant crontab entries (escalation) -- all through standard NFS LOOKUP and READ operations.

!!! tip "nfswolf workflow"
    `nfswolf escape target:/export` runs the full seven-phase escape pipeline: gather seeds from MOUNT v3/v1/NFSv4 and upward traversal, construct candidates, probe across versions with credential escalation, dedup and filter, detect rootfs, score and annotate, and report. Use `--fast` for single-export quick mode (~10-80 RPCs), `--all` to test every export, and `--json` for machine-readable output. Inside the shell, `escape-root` runs the same algorithm interactively and `cd ..` on NFSv4 uses LOOKUPP directly.
