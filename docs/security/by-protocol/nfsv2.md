# NFSv2 findings

NFSv2 (RFC 1094) is the oldest version of the NFS protocol still encountered in the wild. Its design predates any concept of security negotiation -- there is no mechanism to advertise or require strong authentication. Fixed 32-byte file handles, no READDIRPLUS, and no FSINFO make it a simpler protocol, but that simplicity translates directly into weaker defenses. Servers that still expose NFSv2 alongside v3 or v4 introduce a downgrade path that bypasses every security improvement made since 1989.

## Applicable findings

| Finding | Name | Severity | NFSv2-Specific Notes |
|---------|------|----------|----------------------|
| [F-1.1](../identity/F-1.1-uid-gid-spoofing.md) | UID/GID Spoofing | Critical | Identical to v3. AUTH_SYS is the only authentication mechanism available in v2; there is no flavor negotiation to even offer an alternative. |
| [F-1.6](../identity/F-1.6-nfsv2-downgrade.md) | NFSv2 Downgrade | High | The defining v2 finding. A server exporting with `sec=krb5` on v3/v4 can be contacted via v2, which has no security flavor negotiation at all (RFC 2623 Section 2.7). MOUNT v1 leaks the file handle without requiring Kerberos credentials. |
| [F-2.1](../access-control/F-2.1-export-escape.md) | Export Escape | Critical | File handles are fixed at 32 bytes in v2 (RFC 1094 Section 2.3.3). The shorter handle format simplifies construction: fewer bytes to get right, fewer possible encodings. The `Nfs2EscapeProbe` implementation handles v2-specific escape. |
| [F-2.2](../access-control/F-2.2-file-handle-guessing.md) | Handle Brute Force | High | Fixed 32-byte handles are significantly easier to brute-force than v3's variable-length (up to 64-byte) handles. The search space is smaller and the format is more predictable on older kernels where v2 was the primary target. |
| [F-3.1](../network/F-3.1-plaintext-wire-protocol.md) | Plaintext Traffic | High | No TLS, no krb5p, no integrity protection. All data and credentials travel in cleartext. RFC 9289 (NFS-over-TLS) does not apply to v2. |
| [F-5.8](../info-disclosure/F-5.8-auth-none-metadata-leak.md) | AUTH_NONE Metadata Leak | Low | GETATTR with AUTH_NONE on a valid file handle leaks uid, gid, mode, size, and timestamps. This works on v2 the same way it works on v3 -- the automounter exemption (RFC 2623 Section 2.3.2) applies to both. |

## Protocol-specific exploitation analysis

### No security flavor negotiation

NFSv2 has no equivalent of the NFSv3 MOUNT auth_flavors list or the NFSv4 SECINFO operation. The protocol simply does not have a mechanism for the server to tell the client "you must use Kerberos." RFC 2623 Section 2.7 states it directly: "NFS Version 2 had no support for security flavor negotiation. It was up to the client to guess, or depend on prior knowledge."

This means that even when an administrator configures `sec=krb5` on an export, a client that explicitly speaks NFSv2 bypasses the requirement entirely. Linux knfsd enforces `sec=krb5` on v2 NFS operations (tested on kernels 2.6.32+), but MOUNT v1 still leaks the root file handle without Kerberos authentication. The handle, once obtained, is a bearer token (F-2.7) usable from any client.

On a mixed-flavor export (`sec=krb5:sys`), the situation is even worse: NFSv2 operations with AUTH_SYS succeed on both the MOUNT and NFS layers because the export explicitly accepts AUTH_SYS as a valid flavor. The krb5 flavor is simply ignored because NFSv2 has no mechanism to prefer it. This was confirmed in live testing against Linux knfsd kernels 2.6.32 through 4.15.

### Fixed 32-byte handles

Every NFSv2 file handle is exactly 32 bytes. On Linux knfsd, the handle layout is the same knfsd format used by v3, but padded or truncated to fit the 32-byte constraint. This has two consequences for attackers:

1. **Reduced search space.** The `brute-handle` subcommand needs to guess fewer bytes. On ext4, a v2 root-inode handle is fully deterministic given the fsid -- no generation number variation.
2. **Simpler fingerprinting.** With a fixed size, entropy analysis is more reliable. The `FileHandleAnalyzer` can identify filesystem type, OS, and handle layout from a single 32-byte sample.

The fixed size also means that v2 handles on filesystems that normally produce shorter knfsd handles (e.g., ext4 with small inodes) will have zero-padding at the end. This padding is predictable and does not add entropy, further reducing the effective search space for brute-force attacks.

### MOUNT v1 handle leak

NFSv2 uses MOUNT v1, which returns a 32-byte `fhstatus` on successful MNT. The critical detail: MOUNT v1 MNT does not return an auth_flavors list. There is no way for the server to signal which authentication flavors the export requires. The client receives the handle and proceeds with whatever credentials it chooses. On a `sec=krb5` export, the handle is leaked through MOUNT v1 even though subsequent v2 NFS operations may be rejected by the kernel's krb5 enforcement.

nfswolf's escape pipeline exploits this explicitly: the `gather_seeds` phase calls MOUNT v1 MNT alongside MOUNT v3 MNT and NFSv4 LOOKUP to collect root handles from every available protocol version. The MOUNT v1 path often succeeds where v3 fails because v3 at least advertises the auth_flavors, making the krb5 requirement visible even though it does not enforce it.

### NFSv2 procedure set limitations

NFSv2 defines 18 procedures (RFC 1094 Section 2.2). Compared to v3's 22 procedures, the notable absences are:

- **No READDIRPLUS.** Directory enumeration returns filenames and fileids only, not file handles or attributes. The attacker must LOOKUP each entry individually to obtain handles. This is slower but not a meaningful barrier.
- **No FSINFO / FSSTAT.** No filesystem metadata queries. The attacker cannot check inode counts, filesystem capabilities, or link support via the NFS protocol itself.
- **No ACCESS.** Permission checking must be done by attempting the actual operation (READ, WRITE, LOOKUP). This is noisier but arguably more accurate than the advisory ACCESS check in v3.
- **No MKNOD.** Device node creation (F-4.3) requires v3. However, SUID binary creation (F-4.2) works fine via v2 CREATE with appropriate mode bits.
- **No COMMIT.** All writes are synchronous. No write verifier for reboot detection (F-5.17).

These limitations make NFSv2 a less efficient attack platform, but they do not remove the core vulnerabilities. UID spoofing, export escape, and handle bearer-token abuse all work the same way.

### V2 in the nfswolf shell

nfswolf supports NFSv2 via `--nfs-version 2` or `--handle HEX` with v2 auto-detection. The `NfsShell<V2Ops>` implementation provides all 54 shell commands over NFSv2. Identity changes work differently in v2 than in v3/v4: because v2 connections carry a single credential bound at connect time, changing UID requires a full TCP reconnect (new socket, new AUTH_SYS credential, re-MOUNT). This is handled transparently by `V2Ops`.

The auto-version detection in `resolve_version` probes v3 first, then v2, then v4. When v2 is the only available version, nfswolf automatically selects it and adapts all shell operations to the v2 procedure set. The credential ladder and escape algorithm work identically; only the wire encoding changes.

### Servers still running NFSv2

NFSv2 appears most commonly on legacy systems -- embedded devices, older Solaris installations, and Linux servers that have never updated their NFS configuration. The `scan` subcommand checks for program 100003 version 2 in the portmapper DUMP output and reports it as a version downgrade risk (F-1.6). Any server advertising v2 alongside v3 or v4 has a downgrade path that an attacker can exploit without modifying the server configuration.

Modern Linux distributions (RHEL 8+, Ubuntu 20.04+) disable NFSv2 by default in the kernel NFS server, but older installations and appliances frequently still expose it. The presence of v2 in the portmapper DUMP output is the signal. Even if v2 operations fail due to kernel enforcement, the MOUNT v1 handle leak alone is worth the probe.

### NFSv2 escape pipeline integration

The escape pipeline in `src/cli/escape.rs` gathers seed handles from MOUNT v1 MNT as one of its five discovery channels. The `Nfs2EscapeProbe` implementation adapts the `find_escape_root()` algorithm for v2's fixed 32-byte handles. When `--fast` mode is used, the pipeline picks the first available protocol version and runs a minimal probe (~10-80 RPCs). In full mode, all three protocol versions are tried in parallel, and any escape found via v2 is deduplicated against v3/v4 results based on the filesystem root inode.

The `escape --all` flag additionally attempts MOUNT v1 against every discovered export, collecting v2 seed handles even when v3 handles are already available. This catches cases where v2 MOUNT succeeds where v3 MOUNT is denied (the krb5 bypass scenario described in F-1.6).

### Findings not applicable to NFSv2

Several findings are specific to v3 or v4 and do not apply to NFSv2:

| Finding | Why It Does Not Apply |
|---------|----------------------|
| F-2.4 (BTRFS Subvolume Escape) | BTRFS subvolume fileid_types use extended handle formats that exceed 32 bytes. The v2 handle is truncated, making subvolume ID manipulation unreliable. |
| F-4.3 (Device Node via MKNOD) | NFSv2 has no MKNOD procedure. Device nodes cannot be created over v2. |
| F-5.2 (READDIRPLUS Harvesting) | NFSv2 has no READDIRPLUS. Directory enumeration returns filenames and fileids only -- no handles, no attributes. Each file requires a separate LOOKUP. |
| F-5.6 (Metadata on Access Denial) | NFSv2 does not return post_op_attr on failure responses. Access-denied errors carry no metadata. |
| F-5.12 (Near Inode Exhaustion) | NFSv2 has no FSSTAT procedure. Inode counts are not available. |
| F-5.17 (Write Verifier Change) | NFSv2 has no COMMIT procedure. No write verifier exists for reboot detection. |
