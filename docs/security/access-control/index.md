# Access control bypass (F-2.x)

NFS file handles are bearer tokens. Possession of a handle is the only authorization required to perform operations on the file or directory it references. The MOUNT protocol is the sole access gate, and the handles it issues have no binding, no MAC, no expiry, and no revocation mechanism.

> "An attacker can circumvent the MOUNT server's access control by either stealing a file handle or guessing a file handle."
> -- RFC 2623 sec. 2.6

The twelve findings in this category exploit the bearer-token property of file handles, weaknesses in handle construction, and the NFS daemon's inability to re-validate MOUNT-level authorization on a per-request basis.

## Finding summary

| ID | Finding | Severity | RFC Basis | Detection |
|----|---------|----------|-----------|-----------|
| [F-2.1](F-2.1-export-escape.md) | Export Escape via Filesystem Root Handle | **Critical** | RFC 1813 sec. 3.3.3, RFC 1094 sec. 2.3.3 | `escape`, `analyze`, `shell escape-root` |
| [F-2.2](F-2.2-file-handle-guessing.md) | File Handle Guessing / Brute Force | High | RFC 1094 sec. 2.3.3, RFC 2623 sec. 2.6 | `analyze` (entropy), `brute-handle` |
| [F-2.3](F-2.3-windows-handle-signing.md) | Windows File Handle Signing Disabled | **Critical** | Implementation-specific | `analyze` (handle signing check) |
| [F-2.4](F-2.4-btrfs-subvolume-escape.md) | BTRFS Subvolume Handle Construction | High | RFC 1094 sec. 2.3.3 | `escape` (subvol probing) |
| [F-2.5](F-2.5-stale-handle-persistence.md) | Stale Handle After Permission Revocation | Medium | RFC 1094 sec. 1.3, Appendix A | `shell --handle`, `mount --handle` |
| [F-2.6](F-2.6-bind-mount-escape.md) | Bind Mount Export Escape | High | RFC 1094 sec. 2.3.3 | `escape` (fsid-based handle) |
| [F-2.7](F-2.7-nfsd-acl-blindness.md) | NFS Daemon Export ACL Blindness | **Critical** | RFC 2623 sec. 2.6, RFC 1094 sec. 2.3.3 | `shell --handle` (port 2049, no MOUNT) |
| [F-2.8](F-2.8-sibling-export-lateral-access.md) | Sibling Export Lateral Access | **Critical** | RFC 1813 sec. 3.3.3, RFC 2623 sec. 2.6 | `escape` + `shell` (cd to peer export) |
| [F-2.9](F-2.9-webnfs-public-handle.md) | WebNFS Public File Handle (MOUNT Bypass) | **Critical** | RFC 2054 sec. 5, RFC 2224 sec. 9 | `analyze` (zero-handle probe) |
| [F-2.10](F-2.10-sign-fh-root-exemption.md) | SIGN_FH Root Handle Exemption | Medium | Implementation-specific (Linux) | `shell --handle` (constructed root) |
| [F-2.11](F-2.11-nfsv4-lookupp-export-escape.md) | NFSv4 LOOKUPP Export Escape | **Critical** | RFC 7530 sec. 16.14, sec. 7.3 | `escape-root` (v4), `cd ..` |
| [F-2.12](F-2.12-nfsv4-lookupp-cross-export-lateral.md) | NFSv4 LOOKUPP Cross-Export Lateral Access | High | RFC 7530 sec. 7.3, sec. 16.14 | `cd ..` + `cd <sibling>`, `exports` cmd |

## Findings

### F-2.1: Export Escape via Filesystem Root Handle

!!! critical
    The primary export breakout technique. Confirmed on ext2/3/4, XFS, BTRFS, ZFS, f2fs, JFS, NILFS2, ReiserFS, VFAT, NTFS3, UDF, bcachefs, SquashFS, EROFS, and ISO9660. Only tmpfs resists.

File handles contain filesystem-specific data, typically fsid, inode number, and generation counter. The NFS RFCs do not require the server to confine access to the exported subtree. When `subtree_check` is disabled (the Linux default), any handle with a valid fsid resolves, regardless of whether its inode falls within the exported directory tree. nfswolf's escape engine fingerprints the handle structure, constructs a handle targeting inode 2 (the filesystem root on most Linux filesystems), and confirms the escape via READDIRPLUS.

### F-2.2: File Handle Guessing / Brute Force

Neither RFC 1094 nor RFC 1813 requires handles to be cryptographically random. The error code distinction between `NFS3ERR_STALE` (correct format, wrong inode/generation) and `NFS3ERR_BADHANDLE` (wrong format entirely) acts as an oracle that confirms when the attacker has guessed the correct structure. nfswolf's `brute-handle` subcommand uses this oracle for targeted inode enumeration after fingerprinting the handle layout.

### F-2.3: Windows File Handle Signing Disabled

!!! critical
    When signing is disabled (default in some Windows NFS configurations), the HMAC field in handles is zeroed, making handles trivially constructible.

Windows NFS server adds a non-standard HMAC to file handles. When signing is disabled, the last 10 bytes (v3) or 16 bytes (v4.1) of the handle are null or constant. nfswolf's `FileHandleAnalyzer` checks the trailing bytes for this pattern and flags the finding.

### F-2.4: BTRFS Subvolume Handle Construction

BTRFS uses `fileid_type` encodings (0x4d-0x4f) that include subvolume IDs. By constructing handles with different subvol IDs (default subvol 5, user subvols 256+), an attacker can access other subvolumes on the same filesystem, escaping the intended export boundary even when the export points to a specific subvolume. nfswolf's escape engine constructs candidate handles with compound UUID escape targeting multiple subvolume IDs.

### F-2.5: Stale Handle After Permission Revocation

NFS is stateless by design. The UMNT operation removes a mount-list entry but does not invalidate the file handle (RFC 1094 Appendix A: "The mount list information is not critical for the correct functioning of either the client or the server"). A client that previously had legitimate access retains working handles indefinitely, even after the export ACL is changed to deny that client. There is no revocation mechanism.

### F-2.6: Bind Mount Export Escape

Bind mounts share the underlying filesystem's fsid. When `subtree_check` is disabled, the NFS server validates only that a handle's fsid matches the export's filesystem. A handle for any inode on that filesystem is accepted, regardless of the bind mount boundary. nfswolf constructs a filesystem root handle from the bind mount's fsid to demonstrate the escape.

### F-2.7: NFS Daemon Export ACL Blindness (Bearer Token Property)

!!! critical
    This is the root cause behind all handle-based bypasses. The NFS daemon on port 2049 never calls back to mountd to verify that the requesting client was authorized to receive the handle.

The kernel checks `(client_auth_domain, fsid)` in the export cache. If any wildcard export exists on the same filesystem, the handle resolves from any IP. MOUNT is the only gate, and it issues permanent bearer tokens. nfswolf's `shell --handle <hex>` path demonstrates this directly: it connects to port 2049 without MOUNT, and the handle works.

### F-2.8: Sibling Export Lateral Access (Cross-Export Handle Reuse)

!!! critical
    After escaping to the filesystem root (F-2.1), standard LOOKUP operations reach any directory on the filesystem -- including IP-restricted peer exports.

When two exports share a physical filesystem and `subtree_check` is disabled, the kernel does not verify that a handle's inode is within the export's directory tree. No handle construction is needed for the lateral movement step; only the initial escape to the filesystem root is required. nfswolf demonstrates this via `escape-root` followed by `cd /path/to/restricted` and `ls`/`cat`.

### F-2.9: WebNFS Public File Handle (MOUNT Bypass)

!!! critical
    The all-zeros public handle grants immediate access to the public export from any IP, completely bypassing MOUNT host ACLs.

WebNFS (RFC 2054/2055/2224) defines a well-known public file handle (all zeros) that bypasses the MOUNT protocol entirely. If WebNFS is enabled (Solaris `public` share, NetApp `nfs.webnfs.enable`), any client can issue LOOKUP with the zero handle and access the public export without host-based ACL checks. nfswolf's analyzer probes for this handle on each target.

### F-2.10: SIGN_FH Root Handle Exemption (FILEID_ROOT MAC Bypass)

Linux knfsd's handle signing (`NFSEXP_SIGN_FH`) appends a SipHash-2-4 MAC to non-root file handles. Root handles (`fileid_type=0`) are explicitly exempt: `nfsd_set_fh_dentry()` skips all MAC verification for FILEID_ROOT and returns the export root dentry directly. An attacker who knows the export's fsid (discoverable via GETATTR or MOUNT) can construct a valid root handle with no MAC. From the root, standard LOOKUP returns legitimately signed child handles.

### F-2.11: NFSv4 LOOKUPP Export Escape

!!! critical
    A single `cd ..` from an NFSv4 subdirectory export reaches the filesystem root. No handle construction or filesystem fingerprinting required.

NFSv4's LOOKUPP operation returns the parent directory of any file handle. When a server exports a subdirectory, LOOKUPP from the export root reaches the filesystem root -- escaping the export boundary. This is the NFSv4 equivalent of F-2.1 but requires zero protocol-level sophistication. The pseudo-root boundary stops upward traversal at the top of the export tree (cannot reach host `/`), but within any individual filesystem the escape is complete. Confirmed on ext4, ZFS, BTRFS, f2fs, and all other filesystem types with subdirectory exports.

### F-2.12: NFSv4 LOOKUPP Cross-Export Lateral Access

The NFSv4 pseudo-filesystem connects all exports under a shared namespace tree. A client with access to any one export can LOOKUPP to the shared parent directory and then LOOKUP into any sibling export. No MOUNT protocol is involved; the entire traversal happens over a single TCP connection, bypassing MOUNT-level IP ACLs entirely. The pseudo-root READDIR also reveals the names of all exports (F-5.5), including IP-restricted ones.

## Attack chain

The typical access-control bypass proceeds through these stages:

1. **Handle acquisition** -- MOUNT MNT returns the export root handle. Alternatively, WebNFS (F-2.9), a stolen handle (F-2.5), or `--handle <hex>` (F-2.7) skips MOUNT entirely.
2. **Fingerprinting** -- `FileHandleAnalyzer` determines OS, filesystem type, and handle structure from the raw bytes. Windows signing status is checked (F-2.3).
3. **Escape** -- `escape` constructs a filesystem root handle (F-2.1), probes BTRFS subvolumes (F-2.4), or uses LOOKUPP on NFSv4 (F-2.11). Bind mount boundaries are crossed via shared fsid (F-2.6).
4. **Lateral movement** -- From the filesystem root, LOOKUP reaches sibling exports (F-2.8) or NFSv4 pseudo-FS peers (F-2.12). The NFS daemon accepts all handles without re-checking MOUNT authorization (F-2.7).
5. **Persistence** -- Handles never expire. Even after export ACL changes, previously obtained handles continue to work (F-2.5).

## Mitigations

| Mitigation | Findings Addressed |
|------------|--------------------|
| `subtree_check` on all exports | F-2.1, F-2.6, F-2.8 (with performance cost) |
| `sign_fh` with `fh_key` | F-2.1, F-2.2 (non-root handles only; root exempt per F-2.10) |
| Export at filesystem mount point, not subdirectory | F-2.1, F-2.11 (eliminates escape surface) |
| Disable WebNFS | F-2.9 |
| Enable Windows handle signing | F-2.3 |
| NFSv4 with `sec=krb5p` exclusively | F-2.7 (limits handle utility to authenticated clients) |
| Separate sensitive data onto distinct filesystems | F-2.8, F-2.12 (prevents lateral movement via shared fsid) |
