# Previous Research

NFS security issues have been documented since the protocol's creation in the 1980s, yet the same fundamental weaknesses persist in most deployments today. This page surveys the key research, publications, and community knowledge that inform nfswolf's [findings catalog](../security/index.md).

## Foundational protocol analysis

The earliest security analysis comes from the protocol authors themselves. Sun Microsystems designed NFS for trusted local networks where every machine was administered by the same organization. The AUTH_SYS authentication model, where clients assert their own identity with no cryptographic verification, was an explicit design trade-off documented in RFC 1057 Section 9.3: "There is no verifier, so credentials can easily be faked."

RFC 2623, "NFS Version 2 and Version 3 Security Issues and the NFS Protocol's Use of RPCSEC_GSS and Kerberos V5" (1999), remains the single most important security reference for NFS. It systematically catalogs the protocol's weaknesses:

- **AUTH_SYS is fundamentally insecure** (Section 2.1): "AUTH_SYS is not a security flavor and SHOULD NOT be used in new deployments."
- **File handles are bearer tokens** (Section 2.6): possession grants access with no user binding, no MAC, no expiry.
- **NFSv2 cannot negotiate security** (Section 2.7): a v2 client bypasses any v3/v4 Kerberos requirements because the v2 code path has no flavor negotiation mechanism.
- **Privileged ports are security theater** (Section 2.1): "at best an inconvenience" to attackers.
- **The fixes are opt-in** (Section 5): RPCSEC_GSS exists but is rarely deployed.

These observations directly map to nfswolf findings [F-1.1](../security/identity/F-1.1-uid-gid-spoofing.md) through [F-1.7](../security/identity/F-1.7-rpcsec-gss-flavor-downgrade.md).

## RFC 2623 as the foundational security audit

RFC 2623 was written by Mike Eisler at Sun -- one of the organizations that designed NFS. Published in June 1999, it lays out every fundamental weakness that NFS security tools still exploit today. Section 2 ("Overview of NFS Security") reads like a pentester's notes, not a specification.

The RFC identifies five distinct attack surfaces, each of which nfswolf automates:

1. **Port monitoring is theater** (Section 2.1): The privileged-port requirement assumes the client OS enforces binding restrictions, but "on many operating systems, there are no constraints on what port what user can bind to." Even on systems that do enforce it, physical access to a desktop machine makes root "trivially acquired." The RFC concludes that port monitoring "SHOULD NOT be depended on." nfswolf tests this directly via [F-7.2](../security/config/F-7.2-privileged-port-bypass.md) by probing whether the server accepts connections from unprivileged ports.

2. **MOUNT is a one-time gate** (Section 2.6): Access control is checked only at mount time via the MOUNT protocol. After the client receives a file handle, subsequent NFS requests carry no authorization check against the original MOUNT ACL. The RFC warns that an attacker can "circumvent the MOUNT server's access control to gain access to a file system" by stealing or guessing a handle. This is the theoretical basis for nfswolf's entire escape pipeline and handle construction engine.

3. **AUTH_SYS credentials are unverifiable** (Section 2.2.1): The server receives the client's UID, GID, and supplemental group list on every call and "uses them to check access" -- but has no way to verify they are truthful. This is the foundation of UID spoofing ([F-1.1](../security/identity/F-1.1-uid-gid-spoofing.md)) and auxiliary group injection ([F-1.3](../security/identity/F-1.3-auxiliary-group-injection.md)).

4. **NFSv2 has no security negotiation** (Section 2.7): NFSv2 provides no mechanism for the client and server to agree on a security flavor. The client must "guess, or depend on prior knowledge." This means a v2 client can bypass v3/v4 Kerberos requirements entirely -- the basis of [F-1.6](../security/identity/F-1.6-nfsv2-downgrade.md).

5. **Anonymous mapping is inconsistent** (Section 2.5): Root squashing maps only UID/GID 0 to `nobody`. The RFC acknowledges this but does not address the consequence: every non-root identity is trusted without verification, enabling the shadow-group read trick and setgid escalation techniques discovered 25 years later by HVS Consulting.

Every issue RFC 2623 identified in 1999 is still exploitable on default Linux NFS configs today. The fixes it proposed (RPCSEC_GSS with Kerberos V5) exist but are rarely deployed in practice, exactly as the RFC's authors feared. nfswolf implements automated tests for every issue RFC 2623 cataloged, making it possible to verify in seconds what the RFC described in pages of careful prose.

## Key publications and research

| Year | Author / Source | Contribution |
|------|----------------|--------------|
| 1985 | Sun Microsystems | NFS protocol design (RFC 1094, later RFC 1813) with AUTH_SYS trust model |
| 1989 | Leendert van Doorn | `nfsshell` -- the first interactive NFS security tool, providing raw handle injection, UID spoofing, and source routing |
| 1994 | Cheswick & Bellovin | "Firewalls and Internet Security": early documentation of NFS as an attack vector on trusted networks |
| 1994 | CERT Advisory CA-1994-15 | NFS vulnerabilities advisory covering UID spoofing and export misconfiguration |
| 1999 | Eisler, Schemers, Srivastava | RFC 2623 -- the first systematic NFS security audit, cataloging AUTH_SYS weakness, handle bearer tokens, port monitoring futility, and MOUNT-as-only-gate |
| 2003 | Shepler et al. | RFC 3530 (NFSv4.0) -- introduced COMPOUND ops, SECINFO, eliminated separate MOUNT protocol |
| 2006 | Stony Brook University (FSL) | "NFS File Handle Security" technical report: file handle structure analysis and export escape via inode/generation manipulation |
| 2010 | Shepler, Eisler, Noveck | RFC 5661 (NFSv4.1) -- sessions, pNFS, delegation improvements |
| 2014 | Daniel Miller (NfSpy) | FUSE mount with UID spoofing and stealth mount (immediate UMNT after handle acquisition) -- introduced the "hide mode" concept |
| 2018 | hegusung (RPCScan) | Network-wide RPC scanner with NFS export enumeration and recursive directory listing -- first tool to combine network scanning with NFS file access |
| 2021 | J. Bruce Fields | linux-nfs mailing list thread documenting cross-filesystem escape via symlink replacement of export directory |
| 2022 | RFC 9289 | RPC-with-TLS specification -- STARTTLS-style upgrade for NFS, addressing plaintext wire protocol (F-3.1) |
| 2024 | HVS Consulting | "NFS Security: Identifying and Exploiting Misconfigurations": comprehensive blog post, wiki, and tooling (nfs_analyze, fuse_nfs) with original research on BTRFS/ZFS escape, shadow group read, and setgid privilege escalation |
| 2024 | CVE-2024-46695 | Linux kernel nfsd SELinux label bypass -- server fails to enforce inode security labels on NFS-created files |
| 2024 | dejisec (niffler) | First NFS-specific credential and secret scanner with rule engine, UID cycling, and web dashboard -- designed as a post-access companion to nfswolf |
| 2024 | 44Con London | nfscli presented by Claes M Nyberg and John Cartwright (Signedness.org) at 44Con ([video](https://www.youtube.com/watch?v=NuxCUMIH5M8)), covering NFS export escape techniques, source IP spoofing for ACL bypass, and file handle brute-force. Released nfscli and brutefh. Discovered OpenBSD NFS server READDIRPLUS remote kernel crash. |

## The Stony Brook file handle research

The [NFS File Handle Security Technical Report](https://www.fsl.cs.stonybrook.edu/docs/nfscrack-tr/index.html) from Stony Brook University's File Systems and Storage Lab is the foundational work on export escape attacks. It demonstrated that the internal structure of NFS file handles (which the protocol declares opaque to clients) is predictable enough to construct handles targeting files outside the exported directory.

The key insight: on Linux, file handles encode the filesystem UUID, inode number, and generation number. The root directory of ext4 always uses inode 2 with generation 0; XFS uses inode 64 or 128 depending on configuration. An attacker who obtains any valid handle from an export can replace the fileid portion to target the filesystem root, escaping the export boundary entirely.

The preconditions documented in the report remain accurate today:

1. `subtree_check` must not be enabled (it is disabled by default since 2007).
2. The export must not be the root of a filesystem (otherwise there is nothing to escape to).
3. The filesystem must have predictable inode and generation numbers (ext4, XFS, and BTRFS all qualify -- these are the defaults on Debian, Fedora, and SUSE respectively).
4. The attacker must be able to send manipulated NFS requests from a privileged port (<1024), which requires root or `CAP_NET_BIND_SERVICE`.

All four preconditions are met on a standard Linux distribution with default NFS export configuration. This research directly informs nfswolf's [F-2.1 export escape](../security/access-control/F-2.1-export-escape.md) implementation, which extends the original work to cover 18 of 19 Linux filesystem types (ext2/3/4, XFS, BTRFS, ZFS, f2fs, JFS, NILFS2, ReiserFS, VFAT, NTFS3, UDF, bcachefs, SquashFS, EROFS, ISO9660; only tmpfs resists because it does not implement `export_operations`).

The Stony Brook report focused on ext4 and XFS, which were the dominant Linux filesystems at the time. Their handle format analysis showed that ext4 root is always at inode 2 with generation 0, and XFS root at inode 64 or 128 depending on inode size configuration. Subsequent work by HVS Consulting extended this to BTRFS (where handle semantics differ due to subvolume architecture), and nfswolf further extended it to 15 additional filesystem types by analyzing each filesystem's `encode_fh` and `fh_to_dentry` kernel functions to determine the handle structure and root directory constants.

## HVS Consulting research (2024)

HVS Consulting published a detailed [blog post](https://www.hvs-consulting.de/en/nfs-security-identifying-and-exploiting-misconfigurations/), three open-source tools, and a [wiki](https://github.com/hvs-consulting/nfs-security-tooling/wiki) covering NFS security from protocol theory through exploitation on modern Linux distributions.

Their wiki starts with how NFS works (protocol overview, Linux/Windows/other implementations), moves through the security features that are supposed to protect exports (authentication methods, secure ports, squashing, subtree_check, allowed hosts, RPC-with-TLS), and then documents the attacks that succeed when those features are misconfigured or insufficient.

Key original contributions:

- **BTRFS subvolume escape**: demonstrated that BTRFS exports can be escaped beyond the filesystem root to reach all subvolumes and snapshots, because BTRFS file handles encode a subvolume ID that can be incremented. The special subvolume 5 (FS_TREE) contains all other subvolumes as subdirectories. Their wiki documents the exact 20-byte `FILEID_BTRFS_WITHOUT_PARENT` handle format: 8 bytes for the object ID (always 256 for root directories), 8 bytes for the subvolume ID (starts at 256, incrementing), and 4 bytes for the generation (always 0). This maps to [F-2.4](../security/access-control/F-2.4-btrfs-subvolume-escape.md).
- **ZFS dataset escape**: documented the ZFS file handle structure and the limitations of escape (restricted to the same dataset, generation number requires brute-force). They also noted that TrueNAS Scale automatically enables `subtree_check` when a subdirectory of a dataset is exported, limiting the attack surface on that platform.
- **Shadow group read trick**: showed that on Debian/SUSE systems, `/etc/shadow` is readable by the `shadow` group (GID 42 on Debian, GID 15 on SUSE). Since `root_squash` only maps UID/GID 0, an attacker can read shadow password hashes by setting their GID to the shadow group. The wiki explains the rationale: the `shadow` group exists so that setgid binaries like `chage` can read expiration dates without running as root, but NFS's trust-based authentication turns this local security measure into a remote attack vector. This maps to [F-1.3](../security/identity/F-1.3-auxiliary-group-injection.md).
- **Client-side privilege escalation without `no_root_squash`**: documented a progression of attacks using `setgid` binaries: the `disk` group (GID 6) grants raw block device access via `debugfs`, the `docker` group grants container escape to host root, and the `sudo`/`wheel` group grants `sudo` access. Their wiki also documents the `nodev` defense gap -- many administrators set `nosuid` on client mounts but forget `nodev`, leaving the block-device attack path open.
- **Cross-filesystem escape via symlink replacement**: documented the attack (originally described by J. Bruce Fields on the linux-nfs mailing list) where an attacker with write access to the parent of an exported directory can replace it with a symlink to an arbitrary path. After an NFS service restart, the server follows the symlink, effectively re-exporting any directory the attacker chose. The wiki notes this requires `no_root_squash` or specific parent directory permissions, and that the NFS service restart is the main practical barrier.
- **RPC-with-TLS setup guide**: provided the first practical deployment guide for RFC 9289 on Linux, including TLS and MTLS configuration with `tlshd`. Critically, their wiki documents that RPC-with-TLS operates below the NFS authentication layer -- NFS requests over TLS still typically use AUTH_SYS, so clients can still spoof UIDs unless certificate-to-user mapping is implemented.
- **nfs_analyze and fuse_nfs**: two tools covering analysis and mounting respectively. nfs_analyze automates export escape detection and OS fingerprinting. fuse_nfs provides FUSE mount with automatic UID cycling. See [Related Tools](tools.md). Note: nfscli is a separate project by Claes M Nyberg / Signedness.org (not HVS Consulting) -- see the 44Con entry above.

## Nyberg and Cartwright research (2024)

Claes M Nyberg and John Cartwright (Signedness.org) presented NFS attack research at [44Con London 2024](https://www.youtube.com/watch?v=NuxCUMIH5M8), releasing two tools: [nfscli](https://github.com/claesmnyberg/nfscli) (interactive NFS client) and [brutefh](https://github.com/claesmnyberg/brutefh) (file handle brute forcer). Nyberg's prior security research includes presentations at DEF CON 15 and 16.

Key original contributions:

- **Three-phase export escape**: nfscli implements a layered escape strategy. Phase 1 uses LOOKUP `..` from the export root and READDIRPLUS parent handle leaks (the READDIRPLUS response for `.` and `..` entries often returns the parent directory's file handle even when LOOKUP `..` is blocked by subtree_check). Phase 2 probes covering exports (if the export is `/export/home`, try mounting `/export` or `/`). Phase 3 uses cross-export pivot -- find any escapable export on the same server, escape to the filesystem root from there, and walk down to reach the original target. This three-phase approach is more thorough than a single-method escape attempt.
- **Layer 2 source IP spoofing**: nfscli builds raw Ethernet frames via PF_PACKET sockets with forged IP/UDP headers, a background ARP responder thread, and BPF kernel-filtered reception. This defeats host-based NFS export ACLs when the attacker is on the same L2 segment. The implementation is a complete spoofing stack -- gratuitous ARP on startup, persistent ARP responder for the spoofed IP, and kernel-level BPF filtering so only the expected UDP responses are copied to userspace. This maps to [F-1.4](../security/identity/F-1.4-machine-name-spoofing.md) and [F-3.3](../security/network/F-3.3-ip-spoofing-host-trust.md).
- **Nibble-mask handle brute force**: brutefh takes a hex-encoded file handle and replaces unknown nibbles with `?`, then enumerates all combinations. Counter mode covers up to 64 bits (16 nibbles) exhaustively; random mode probes larger spaces indefinitely; flood mode fires UDP GETATTR probes without waiting for replies. The tool specifically analyzes OpenBSD file handle structure, documenting the 32-bit random field from `fsirand(8)` that requires ~75 hours to cover on gigabit Ethernet. This approach is OS-agnostic -- no filesystem-specific knowledge is needed, making it applicable to OpenBSD, FreeBSD, Solaris, and any other NFS server. nfswolf adopted this approach in `brute-handle --mask`, which implements the same nibble-mask enumeration over TCP with the STALE/BADHANDLE oracle. The two approaches are complementary: nfswolf's structure-aware inode sweep is faster on Linux (skips straight to known root inodes), while `--mask` works against any OS without needing filesystem-specific handle layout knowledge.
- **OpenBSD kernel crash**: during testing, nfscli triggered a remote kernel crash in OpenBSD's NFS server via a READDIRPLUS request on a symlink, reported to bugs@openbsd.org. This demonstrates that NFS server implementations remain fragile -- even modern kernels crash on edge-case inputs from security tools.
- **Browse sub-shell with Unix-style text processing**: nfscli's `browse` mode (authored primarily by John Cartwright) provides a path-based interactive shell with shell piping (`cat /etc/passwd | grep root`), output redirection, grep with `-i`/`-v`/`-n`/`-r`, strings, head/tail, wc, xxd, glob expansion, and write-at-offset for in-place binary patching. This influenced nfswolf's `append` and `grep` shell commands.

## Linux kernel documentation

The Linux kernel's own NFS server (knfsd) documentation is a critical primary source. The export options that administrators configure in `/etc/exports` map directly to kernel-level enforcement (or lack thereof):

- **`no_subtree_check`** (default since nfs-utils 1.1.0, 2007): disables verification that file handles reference files within the export subtree. When disabled (the default), the server accepts any handle pointing to the same filesystem, enabling export escape. See [F-2.1](../security/access-control/F-2.1-export-escape.md).
- **`root_squash`** (default): maps only UID/GID 0 to `nobody` (UID 65534). Every other identity is trusted without verification. See [F-1.2](../security/identity/F-1.2-root-squash-bypass.md).
- **`all_squash`**: maps all UIDs/GIDs to the anonymous user. Can be combined with `anonuid=0` to inadvertently give every client root access, a worse misconfiguration than `no_root_squash`. See [F-7.5](../security/config/F-7.5-squash-misconfiguration.md).
- **`sec=sys`** (default): accepts AUTH_SYS with no cryptographic verification. See [F-1.1](../security/identity/F-1.1-uid-gid-spoofing.md).
- **`insecure`**: allows connections from unprivileged ports (>1024). See [F-7.2](../security/config/F-7.2-privileged-port-bypass.md).
- **`crossmnt` / `nohide`**: automatically exports filesystems mounted beneath the exported tree. Can inadvertently expose sensitive filesystems. See [F-7.3](../security/config/F-7.3-nohide-crossmnt-exposure.md).

!!! warning "Defaults favor usability over security"
    The Linux NFS defaults (`sec=sys`, `root_squash`, `no_subtree_check`) create a configuration where any network-accessible client can claim any non-root identity and access any file on the same filesystem as the export. This is not a bug -- it is the documented default behavior, optimized for ease of deployment in trusted environments.

The nfswolf repository includes a [3200-line kernel breakdown](../reference/kernel.md) mapping every security-relevant knfsd function to its file path, line number, and corresponding finding. Key sections cover the authentication chain (how `svc_authenticate` dispatches to flavor-specific handlers), the file handle architecture (`knfsd_fh` layout, `fh_verify` validation path), the export flag security matrix, and the GSS bypass catalog documenting code paths where Kerberos enforcement can be circumvented.

### Linux kernel NFS source analysis

The kernel breakdown in `ref/linux-kernel/BREAKDOWN.md` represents a layer of analysis that sits between the protocol RFCs and the HVS Consulting application-level research. While the RFCs describe what the protocol is supposed to do and the HVS wiki documents what attackers can achieve, the kernel source analysis explains why specific attacks succeed or fail at the implementation level.

The analysis covers the Linux 7.1.8 NFS server (knfsd) as a layered architecture from RPC dispatch down to per-version procedure handlers. Several findings from this analysis are not documented in any RFC or prior research:

- **The authentication chain** (Section 6.1): traces the complete call path from `svc_authenticate` through `svcauth_unix_accept` to show exactly how AUTH_SYS credentials are extracted from the wire and placed into the request context. The key insight is that the kernel performs no validation beyond parsing -- the UID, GID, and supplemental groups from the RPC header are accepted as-is and used directly for VFS permission checks.
- **File handle verification** (Section 2.5): documents the `fh_verify` function's validation path, showing that handle verification checks the filesystem UUID and confirms the inode exists, but does not verify that the handle was issued to the requesting client or that the export path is an ancestor of the target file. This is the kernel-level explanation for why export escape works.
- **Export flag security matrix** (Section 6.3): maps every `/etc/exports` option to its kernel enforcement point, revealing which flags are checked on every operation versus only at mount time. The matrix confirms that `subtree_check` is the only flag that constrains post-mount handle use, and documents its known unreliability with bind mounts.
- **GSS bypass catalog** (Section 6.4): documents code paths in knfsd where RPCSEC_GSS enforcement can be circumvented. These include NFSv2 operations (which bypass flavor negotiation entirely), the NULL procedure (which most implementations accept over AUTH_NONE regardless of export security settings), and mount-time operations like GETATTR and FSINFO that some servers process without authentication for automounter compatibility, as noted in RFC 2623 Section 2.3.2.

This kernel-level analysis is essential for understanding the gap between what the protocol spec allows and what the Linux implementation actually enforces. In several cases, the kernel is more permissive than the RFCs suggest -- making attacks easier in practice than the protocol description implies.

### The linux-nfs mailing list

The linux-nfs mailing list is a primary source for undocumented NFS server behaviors and edge cases. Notable security-relevant threads include:

- **Cross-filesystem escape via symlink replacement** (2021, J. Bruce Fields): if an attacker can write to the parent of an exported directory (via export escape with `no_root_squash`), they can delete the export directory and replace it with a symlink to any path on the server. After an NFS service restart, the server follows the symlink and exports the target directory. This gives access to arbitrary filesystems beyond the one containing the original export.
- **`subtree_check` unreliability with bind mounts**: live testing confirmed that `subtree_check` does not prevent escape when exports use bind-mounted directories, due to a known kernel limitation in inode-to-dentry resolution across mount namespaces.
- **`sec=krb5` enforcement gaps on NFSv2**: threads documenting that Linux knfsd enforces Kerberos on v2 NFS operations but that MOUNT v1 will still issue file handles without Kerberos authentication, creating a handle-leak path on mixed-security exports. This is an implementation detail not covered by any RFC.
- **`all_squash` + `anonuid=0` interaction**: community reports of administrators using `all_squash` for security but setting `anonuid=0`, inadvertently granting every client root access -- a worse misconfiguration than `no_root_squash` alone because it applies to all clients rather than just those from specific hosts.

## NFSv4 security improvements and their limitations

NFSv4 (RFC 7530, later RFC 5661 for v4.1 and RFC 7862 for v4.2) was designed with security in mind, eliminating several protocol-level weaknesses from v2/v3. The key improvements include:

- **Elimination of the MOUNT protocol**: NFSv4 uses a pseudo-filesystem with COMPOUND operations, removing the MOUNT-as-only-gate vulnerability identified in RFC 2623 Section 2.6. Export access is negotiated inline via LOOKUP and PUTROOTFH operations.
- **SECINFO for security negotiation**: NFSv4 provides an explicit mechanism for clients and servers to negotiate authentication flavors per export, addressing the v2 negotiation gap that RFC 2623 Section 2.7 documented.
- **Mandatory SETCLIENTID**: NFSv4 requires clients to establish a session identity before performing operations, providing a layer of client tracking that v2/v3 lack entirely.
- **ACL support**: NFSv4 introduces a richer ACL model beyond POSIX mode bits, allowing more granular access control.

However, these improvements have limited practical impact on the attack surface for several reasons:

1. **AUTH_SYS remains the default**: Despite NFSv4's security mechanisms, most deployments still use AUTH_SYS authentication. The SECINFO mechanism only reports what flavors are available -- it does not force the use of strong authentication.
2. **File handles are still bearer tokens**: NFSv4 handles have the same bearer-token property as v2/v3 handles. Possession grants access with no user binding. The elimination of MOUNT changes how handles are initially obtained (via LOOKUP instead of MNT) but does not change their fundamental security property.
3. **Export escape still works**: NFSv4 servers still use the same kernel file handle infrastructure as v3. The `knfsd_fh` structure and `fh_verify` validation path are shared across versions, so a constructed handle that works over v3 typically works over v4 as well. nfswolf's escape pipeline probes across all three versions for this reason.
4. **Downgrade attacks**: On servers that expose multiple NFS versions (the common default), an attacker can use v2 or v3 to bypass v4's security negotiation entirely. Live testing confirmed that Linux knfsd enforces `sec=krb5` on v2 NFS operations but MOUNT v1 leaks handles without krb5 auth, creating an entry point. See [F-1.6](../security/identity/F-1.6-nfsv2-downgrade.md).

The net result is that NFSv4's security improvements matter only when RPCSEC_GSS is deployed and older protocol versions are disabled -- a configuration that remains the exception rather than the rule.

## Other authentication research

Beyond AUTH_SYS, several authentication mechanisms have been analyzed for NFS:

**AUTH_DH / AUTH_DES** (Diffie-Hellman): Solaris-era authentication using 192-bit DH key exchange to derive a DES session key. The [Solaris NFS documentation](https://docs.oracle.com/cd/E23824_01/html/821-1671/rpcproto-54618.html) describes the mechanism, and the book ["Managing NFS and NIS"](https://docstore.mik.ua/orelly/networking_2ndEd/nfs/ch12_05.htm) documents its cryptographic weaknesses. Both 192-bit DH and 56-bit DES are considered broken by modern standards. nfswolf implements AUTH_DH session support behind the `auth-dh` feature flag. See [F-3.7](../security/network/F-3.7-auth-dh-obsolete.md).

**RPCSEC_GSS / Kerberos**: RFC 2203 defines the GSS-API security framework for RPC, with Kerberos V5 as the primary mechanism. Three protection levels exist: `krb5` (authentication only), `krb5i` (integrity), `krb5p` (privacy/encryption). The [CITI project at University of Michigan](http://www.citi.umich.edu/projects/nfsv4/gssd/) documents the Linux gssd implementation. Despite being available since NFSv3, RPCSEC_GSS deployment remains rare because it requires a functioning Kerberos infrastructure, a significant operational burden for many organizations.

**RPC-with-TLS** (RFC 9289): the newest approach, defined in 2022, uses STARTTLS-style connection upgrade to provide encryption without requiring Kerberos. Experimental implementations exist for Linux (kernel 6.4+) and FreeBSD. The HVS Consulting wiki provides the most detailed [setup guide](https://github.com/hvs-consulting/nfs-security-tooling/wiki/4_6-RPC-with-TLS) available. A critical subtlety: RPC-with-TLS operates below the NFS authentication layer, so NFS requests over TLS still typically use AUTH_SYS. Clients can still spoof UIDs unless the server implements certificate-to-user mapping (currently only FreeBSD does this via SAN extraction). See [F-3.8](../security/network/F-3.8-rpc-with-tls.md).

## Penetration testing references

NFS enumeration is a standard topic in penetration testing curricula, though most references cover only surface-level reconnaissance:

| Source | Coverage | Depth |
|--------|----------|-------|
| HackTricks NFS page | `showmount -e`, UID spoofing, `no_root_squash` | Shallow -- recipes without protocol-level explanation |
| SANS SEC560 / GPEN | NFS enumeration as part of network pentesting | Moderate -- covers export discovery and basic access |
| OWASP Testing Guide | Peripheral mention in network service testing | Minimal |
| Pentestmonkey "Abusing Hardlinks via NFS" | Hard link attack for accessing files outside export | Focused -- single technique, well documented |
| Juggernaut Security NFS writeup | `no_root_squash` SUID escalation walkthrough | Focused -- single technique with step-by-step |
| HTB / CTF writeups | NFS as initial access vector in lab environments | Variable -- usually `showmount` + mount + SUID |
| HVS Consulting blog + wiki | Full attack chain: escape, shadow read, privesc, TLS | Deep -- protocol-level analysis with original research and tooling |
| Offensive Security (OSCP) | NFS enumeration in lab environments | Moderate -- `showmount`, mount, basic file access |
| Linux man pages (`exports(5)`) | Export option documentation | Reference -- essential for understanding server configuration but no security analysis |

!!! note "Gap in existing references"
    Most penetration testing references stop at "mount the share, find SUID binaries." They do not cover export escape via handle construction, BTRFS subvolume traversal, AUTH_SYS auxiliary group injection, NFSv4 SECINFO enumeration, portmapper amplification measurement, or the distinction between `NFS3ERR_STALE` and `NFS3ERR_BADHANDLE` as an oracle for handle brute-force. The gap is partly explained by the protocol complexity: a penetration tester who can mount an NFS share and find a SUID binary can already demonstrate impact, so there is little incentive to learn the handle-level attacks that require a custom RPC implementation. nfswolf and the HVS tools lower the barrier by automating the protocol-level techniques that were previously accessible only to researchers who could write their own NFS clients.

## Client-side privilege escalation research

The HVS Consulting wiki documents a progression of client-side privilege escalation techniques that go beyond the well-known `no_root_squash` + SUID binary attack:

1. **Classic SUID attack** (`no_root_squash` + missing `nosuid` on client mount): upload a SUID-root binary via NFS, execute it on the client. Well-documented, widely known.
2. **Device node attack** (`no_root_squash` + missing `nodev` on client mount): create a block device file on the NFS share matching the client's disk major/minor numbers, then use `debugfs` to read/write the raw filesystem. More subtle -- many administrators enable `nosuid` but forget `nodev`.
3. **setgid escalation without `no_root_squash`**: upload a `setgid` binary targeting the `disk` group (GID 6 on Debian/Fedora), `shadow` group (GID 42), `docker` group, or `sudo`/`wheel` group (GID 27/10). Since only GID 0 is squashed by `root_squash`, these group escalations bypass squashing entirely. The `disk` group grants raw block device access; the `docker` group grants container escape to host root; the `sudo` group grants `sudo` access if the target user's password is known or `NOPASSWD` is configured.
4. **Hard link attack** (documented by Pentestmonkey): when `nosuid` is set and `no_root_squash` is disabled, create hard links within the export to files elsewhere on the same filesystem, then access them with the appropriate spoofed UID via NFS. Works on any filesystem supporting hard links, even with `subtree_check` enabled.

These techniques map to findings [F-4.1](../security/privesc/F-4.1-no-root-squash.md) through [F-4.4](../security/privesc/F-4.4-symlink-escape.md).

## Implementation-specific security research

Beyond the protocol-level analysis in the RFCs, several implementation-specific security issues have been documented:

**Windows NFS Server**: Microsoft's NFS implementation in Windows Server uses handle signing (HMAC-SHA256) to prevent file handle forgery. This is documented in nfswolf as [F-2.3](../security/access-control/F-2.3-windows-handle-signing.md). The Windows NFS server also runs all services (NFS, MOUNT, portmapper) on a single port (2049), which simplifies firewall configuration but eliminates the portmapper as a reconnaissance surface. The [ms-nfs41-client](https://github.com/kofemann/ms-nfs41-client) project provides reference material for how Windows handles NFSv4.1 sessions and pNFS layouts.

**FreeBSD NFS Server**: FreeBSD's NFS implementation has historically been more security-conscious than Linux's. FreeBSD's RPC-with-TLS implementation includes certificate-to-user mapping via Subject Alternative Names, which prevents UID spoofing even when AUTH_SYS is used over TLS -- a capability the Linux implementation does not have as of kernel 6.12.

**Solaris / illumos**: Oracle Solaris and its open-source derivative illumos provide the AUTH_DH authentication mechanism (192-bit Diffie-Hellman + DES session keys) that is not available on Linux. While cryptographically obsolete, AUTH_DH represents the only non-Kerberos cryptographic authentication available for NFS, making it historically significant. The Solaris NFS documentation and the book "Managing NFS and NIS" (O'Reilly) both document AUTH_DH's cryptographic weaknesses: 192-bit DH and 56-bit DES are far below modern security thresholds. nfswolf implements AUTH_DH session support behind the `auth-dh` feature flag. See [F-3.7](../security/network/F-3.7-auth-dh-obsolete.md).

**ShenanigaNFS**: the [ShenanigaNFS](https://github.com/JordanMilne/ShenanigaNFS) project takes a different approach to NFS security research -- rather than building an offensive client, it provides a framework for building malicious NFS servers. With per-mount filesystem state and a FUSE-like VFS API, researchers can create NFS servers that exhibit arbitrary behavior (time-of-check/time-of-use attacks, inconsistent directory listings, malformed responses) to test client-side vulnerabilities. This complements the client-side attack tools by enabling server-side fuzzing and TOCTOU research against NFS client implementations.

**WebNFS and the public file handle**: RFC 2623 Section 2.6 briefly mentions WebNFS (RFC 2054), which introduced a "public file handle" mechanism allowing clients to skip the MOUNT protocol entirely. WebNFS clients look up files using a well-known handle, bypassing whatever access control the MOUNT server might enforce. While WebNFS never achieved widespread adoption, the concept reinforces the fundamental NFS security problem: the MOUNT protocol is the only authorization gate, and any mechanism that bypasses it (whether WebNFS, handle theft, or handle construction) gives unrestricted access to the exported filesystem. The public file handle is essentially an admission by the protocol designers that the MOUNT-based access model was already considered inadequate by 1998.

**Cloud NFS implementations**: AWS EFS, Azure Files NFS, and GCP Filestore all expose NFS as a managed service, typically NFSv4.1 with AUTH_SYS over VPC-internal networks. These implementations inherit the AUTH_SYS trust model documented in RFC 2623 -- any VM in the same VPC can claim any UID and access any file. Cloud providers rely on VPC security groups and network ACLs rather than NFS-level authentication, which means a compromised VM or container in the same network segment can access all NFS-mounted data. None of the major cloud providers deploy RPCSEC_GSS by default on their managed NFS services.

## The gap between documentation and tooling

Every NFS security weakness on this page has been documented for years, some for decades. Testing for them required manual protocol manipulation or single-purpose scripts until recently.

AUTH_SYS credential spoofing was documented in 1999 (RFC 2623). Export escape via handle construction was demonstrated in 2006 (Stony Brook). BTRFS subvolume traversal and shadow-group reads were documented in 2024 (HVS Consulting). Each publication described a specific technique, but no tool implemented all of them, and no tool connected them into a single workflow. A researcher needed Python, C, Go, and Rust tools to cover the path from recon to exploitation.

nfswolf's [finding catalog](../security/index.md) references the specific RFC section, paper, or kernel code path behind each weakness. It does not discover new vulnerabilities -- it automates tests for what the NFS community has documented over four decades.

Between the Stony Brook report in 2006 and the HVS Consulting research in 2024, nearly two decades passed with no significant new NFS security research. During the same period, cloud providers adopted NFS (AWS EFS, Azure Files, GCP Filestore), containers used NFS for persistent volumes, and NAS appliances shipped NFS as a default. The deployment grew while the tooling did not.

## Protocol RFCs

The complete RFC chain for NFS security analysis:

| RFC | Title | Security Relevance |
|-----|-------|--------------------|
| RFC 1057 | ONC RPC v1 | AUTH_SYS definition, "credentials can easily be faked" (Section 9.3); portmapper protocol (Appendix A) |
| RFC 1094 | NFSv2 | 18 procedures, fixed 32-byte handles, no security negotiation; MOUNT protocol (Appendix A) |
| RFC 1813 | NFSv3 | ACCESS advisory semantics (Section 3.3.4), handle opacity (Section 2.6), READDIRPLUS identity harvesting |
| RFC 1831 | ONC RPC v2 | Updated RPC specification with authentication flavor framework |
| RFC 1833 | Binding Protocols for ONC RPC | rpcbind v3/v4 -- GETTIME for clock skew detection, GETSTAT for per-version call statistics |
| RFC 2203 | RPCSEC_GSS | GSS-API authentication framework for RPC; pseudo-flavor negotiation for mechanism selection |
| RFC 2623 | NFS v2/v3 Security Issues | Canonical security analysis -- AUTH_SYS weakness, handle bearer tokens, privileged port futility, MOUNT-as-only-gate, v2 negotiation absence |
| RFC 4506 | XDR | External Data Representation encoding -- the wire format underlying all NFS communication |
| RFC 5531 | ONC RPC v2 | AUTH_SYS with AUTH_NONE verifier (Appendix A); AUTH_SHORT opaque token replay |
| RFC 5661 | NFSv4.1 | Sessions, pNFS, backchannel delegation -- added state management complexity but not deployed widely enough to displace AUTH_SYS |
| RFC 7530 | NFSv4.0 | COMPOUND batching, SECINFO for auth flavor discovery, pseudo-filesystem, ACLs, mandatory SETCLIENTID |
| RFC 7862 | NFSv4.2 | Server-side copy, ALLOCATE/DEALLOCATE, labeled NFS (SELinux) -- latest version, limited deployment |
| RFC 9289 | RPC-with-TLS | STARTTLS-style encryption, STRIPTLS vulnerability; operates below NFS auth layer so AUTH_SYS UID spoofing persists unless MTLS certificate mapping is implemented |

For the full RFC catalog and local copies, see the [RFC reference page](../reference/rfcs.md).

## Primary source index

For researchers who want to trace nfswolf's findings back to their original sources, the following index maps each research category to its authoritative materials:

| Research Area | Primary Sources | nfswolf Coverage |
|---------------|----------------|-----------------|
| AUTH_SYS weakness | RFC 2623 Section 2.2.1, RFC 5531 Section 14 | F-1.1, F-1.2, F-1.3 |
| Handle bearer token property | RFC 2623 Section 2.6, RFC 1094 Section 2.3.3 | F-2.1 through F-2.12 |
| Export escape construction | Stony Brook FSL technical report, HVS Consulting wiki Section 5.1 | F-2.1, F-2.4, F-2.5 |
| Kernel enforcement gaps | ref/linux-kernel/BREAKDOWN.md Sections 2.5, 6.1, 6.3, 6.4 | F-1.1, F-2.1, F-7.1 through F-7.7 |
| Client-side privilege escalation | HVS Consulting wiki Sections 5.2.1-5.2.3, Pentestmonkey | F-4.1 through F-4.4 |
| Wire protocol exposure | RFC 1813 Section 8, RFC 9289 | F-3.1 through F-3.8 |
| NFSv4 security negotiation | RFC 7530 Section 2.6 (SECINFO) | F-1.7, F-5.7 |

## Further reading

- [NFS Insecurity Model](../security/insecurity.md) -- how these research findings translate to nfswolf's threat model
- [File Handles](file-handles.md) -- deep dive into handle structure and escape mechanics
- [Authentication](authentication.md) -- AUTH_SYS, RPCSEC_GSS, AUTH_DH comparison
- [Related Tools](tools.md) -- the tool landscape that informed nfswolf's design
- [Findings Catalog](../security/index.md) -- the 62 findings with RFC citations and detection methods
