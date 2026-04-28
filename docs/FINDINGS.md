# Security Findings Catalog

All findings that nfswolf detects, grouped by attack category. Each finding traces to a specific RFC section explaining WHY the vulnerability exists at the protocol level.

---

## Category 1: Identity Attacks (AUTH_SYS Trust Model)

The NFS security model trusts client-supplied credentials without verification.

> "There is no verifier, so credentials can easily be faked."
> — RFC 1057 §9.3

### F-1.1: UID/GID Spoofing

| Field | Value |
|-------|-------|
| Severity | Critical |
| RFC Basis | RFC 5531 §14, RFC 1057 §9.2, RFC 1813 §4.4 |
| Precondition | Server accepts AUTH_SYS (default) |
| Detection | Attempt ACCESS/READ with forged credentials |

**Why the RFC allows this**: AUTH_SYS credentials use AUTH_NONE as verifier (RFC 5531 Appendix A). The RPC layer treats credentials as opaque pass-through (RFC 5531 §8.2). The server "gets the client's effective uid, effective gid, and groups on each call and uses them to check access" (RFC 1813 §4.4) with no verification step.

**What nfswolf tests**: UID spray (0-65535), targeted UID based on file ownership, auxiliary GID combinations (up to 16 per RFC 1057 §9.2).

### F-1.2: Root Squash Bypass via Non-Root UID

| Field | Value |
|-------|-------|
| Severity | High |
| RFC Basis | RFC 1813 §4.4, RFC 2623 §2.5 |
| Precondition | root_squash enabled (default) |
| Detection | Create test file as arbitrary non-root UID |

**Why the RFC allows this**: Root squash ONLY maps uid 0 to nobody. "A UNIX server by default maps uid 0 to a distinguished value (UID_NOBODY)" (RFC 1813 §4.4). Any non-zero UID is trusted. An attacker claiming uid=owner of a file gets full access because "the server's permission checking algorithm should allow the owner of a file to access it regardless of the permission setting" (RFC 1813 §4.4).

**What nfswolf tests**: Squash probe (write as uid 0, write as uid 99999, compare resulting ownership).

### F-1.3: Auxiliary Group Injection

| Field | Value |
|-------|-------|
| Severity | High |
| RFC Basis | RFC 1057 §9.2 |
| Precondition | Files protected by group permissions |
| Detection | ACCESS with target file's GID in aux groups |

**Why the RFC allows this**: The `gids<16>` array in AUTH_SYS is client-asserted. A client can include any GID values (e.g., the `shadow` group GID 42) without verification. The server uses these to check group access bits.

**What nfswolf tests**: Test file readability with shadow GIDs (42, 15), then spray GIDs 0-65535.

### F-1.4: Machine Name Spoofing / Log Poisoning

| Field | Value |
|-------|-------|
| Severity | Low |
| RFC Basis | RFC 1057 §9.2, RFC 9289 §A.1 |
| Precondition | Server logs client machine name |
| Detection | Set machinename to arbitrary value |

**Why the RFC allows this**: The `machinename<255>` field is "an unprotected domain name" (RFC 9289 §A.1). It is never verified against DNS or any other source. Attackers can set it to any string (including log injection payloads, impersonation of other hosts, or null bytes).

**What the spoof actually does on Linux knfsd**: the `machinename` field is *logged*, not *authorised against*. Export ACLs on Linux knfsd match on the source IP (resolved to a hostname via reverse DNS), not on the value of `auth_unix.machinename`. Setting `--hostname victim.example.com` therefore does **not** bypass a host-based export ACL on its own; it poisons log entries and gives false attribution. See F-3.3 for the related but distinct IP-based trust issue.

### F-1.5: Credential Replay from Wire

| Field | Value |
|-------|-------|
| Severity | High |
| RFC Basis | RFC 1094 §3.4, RFC 5531 §9 |
| Precondition | Network access to observe NFS traffic |
| Detection | N/A (passive attack) |

**Why the RFC allows this**: AUTH_SYS has no nonce, timestamp, or sequence number. The 32-bit XID is "only used for clients matching reply messages with call messages" (RFC 5531 §9), not for replay prevention. Any captured RPC message can be replayed indefinitely.

### F-1.6: NFSv2 Downgrade (Auth Bypass)

| Field | Value |
|-------|-------|
| Severity | High |
| RFC Basis | RFC 2623 §2.7 |
| Precondition | Server supports NFSv2 alongside v3/v4 |
| Detection | rpcinfo shows program 100003 version 2 |

**Why the RFC allows this**: "NFS Version 2 had no support for security flavor negotiation. It was up to the client to guess, or depend on prior knowledge." (RFC 2623 §2.7). A client explicitly requesting v2 bypasses any v3+ sec=krb5 requirements because the v2 code path has no mechanism to enforce them.

---

## Category 2: Access Control Bypass (File Handle Exploitation)

File handles are bearer tokens — possession is authorization.

> "An attacker can circumvent the MOUNT server's access control by either stealing a file handle or guessing a file handle."
> — RFC 2623 §2.6

### F-2.1: Export Escape via Filesystem Root Handle

| Field | Value |
|-------|-------|
| Severity | Critical |
| RFC Basis | RFC 1813 §3.3.3, RFC 1094 §2.3.3 |
| Precondition | Export is a subdirectory, subtree_check disabled |
| Detection | Construct handle for inode 2 (root), issue READDIRPLUS |

**Why the RFC allows this**: File handles are opaque to the client but contain filesystem-specific data (typically: fsid + inode + generation). The RFC says "The file handle can contain whatever information the server needs" (RFC 1094 §2.3.3) but does NOT require the server to confine access to the exported subtree. "A server will not allow a LOOKUP operation to cross a mountpoint" (RFC 1813 §3.3.3) but says nothing about constructed handles pointing outside the export within the SAME filesystem.

**What nfswolf tests**: Fingerprint handle structure (ext4/xfs/btrfs), construct root inode handle, confirm escape via READDIRPLUS child count comparison.

### F-2.2: File Handle Guessing / Brute Force

| Field | Value |
|-------|-------|
| Severity | High |
| RFC Basis | RFC 1094 §2.3.3, RFC 1813 §2.6, RFC 2623 §2.6 |
| Precondition | Predictable handle structure (sequential inodes) |
| Detection | Entropy analysis of observed handles |

**Why the RFC allows this**: Neither RFC 1094 nor RFC 1813 requires handles to be cryptographically random or unpredictable. The oracle problem (NFS3ERR_BADHANDLE vs NFS3ERR_STALE) confirms when the attacker has guessed the correct format (RFC 1813 §2.6).

**What nfswolf tests**: Handle entropy analysis, inode-based candidate generation, filesystem fingerprinting for known handle layouts.

### F-2.3: Windows File Handle Signing Disabled

| Field | Value |
|-------|-------|
| Severity | Critical |
| RFC Basis | Implementation-specific (no RFC coverage) |
| Precondition | Windows NFS server with signing disabled |
| Detection | Examine last 10 bytes (v3) or 16 bytes (v4.1) of handle for null/constant |

**Why this exists**: Windows NFS server adds HMAC to file handles as a non-standard extension. When signing is disabled (default in some configs), the HMAC field is zeroed, making handles trivially constructible.

### F-2.4: BTRFS Subvolume Handle Construction

| Field | Value |
|-------|-------|
| Severity | High |
| RFC Basis | RFC 1094 §2.3.3 (handles are server-specific) |
| Precondition | BTRFS filesystem, export on subvolume |
| Detection | fileid_type 0x4d-0x4f in handle structure |

**Why this exists**: BTRFS uses fileid_type encodings that include subvolume IDs. By constructing handles with different subvol IDs (256+), an attacker can access other subvolumes on the same filesystem — escaping the intended export boundary.

### F-2.5: Stale Handle After Permission Revocation

| Field | Value |
|-------|-------|
| Severity | Medium |
| RFC Basis | RFC 1094 §1.3, RFC 1094 Appendix A |
| Precondition | Client previously had legitimate access |
| Detection | Use handle after export ACL change |

**Why the RFC allows this**: The stateless design means "The mount list information is not critical for the correct functioning of either the client or the server. It is intended for advisory use only." (RFC 1094 Appendix A). UMNT removes the list entry but does NOT invalidate the file handle.

### F-2.6: Bind Mount Export Escape

| Field | Value |
|-------|-------|
| Severity | High |
| RFC Basis | RFC 1094 §2.3.3 (handles are filesystem-scoped) |
| Precondition | Bind mount used as NFS export, subtree_check disabled |
| Detection | Construct filesystem root handle from bind mount's fsid |

**Why this exists**: Bind mounts are an alternative view of the same underlying filesystem — they share the same filesystem ID. When `subtree_check` is disabled, the NFS server only validates that a handle's fsid matches the export's filesystem. A handle for any inode on that filesystem is accepted, regardless of the bind mount boundary.

---

## Category 3: Network-Level Attacks

### F-3.1: Plaintext Traffic Interception

| Field | Value |
|-------|-------|
| Severity | High |
| RFC Basis | RFC 1813 §8, RFC 1094 §3.4 |
| Precondition | Network access between client and server |
| Detection | Check if TLS/krb5p is in use |

**Why the RFC allows this**: "NFS version 3 defers to the authentication provisions of the supporting RPC protocol, and assumes that data privacy and integrity are provided by underlying transport layers" (RFC 1813 §8). No transport layer protection is specified or required.

### F-3.2: Portmapper UDP Amplification (DDoS)

| Field | Value |
|-------|-------|
| Severity | Medium |
| RFC Basis | RFC 1057 Appendix A |
| Precondition | UDP port 111 reachable |
| Detection | Send 68-byte DUMP, measure response size |

**Why the RFC allows this**: The portmapper has no authentication on any operation (RFC 1057 Appendix A). DUMP returns all registered services (~486-1930 bytes) in response to a small request over UDP, where source addresses are trivially spoofed.

### F-3.3: IP Spoofing Against Host-Based ACLs

| Field | Value |
|-------|-------|
| Severity | High |
| RFC Basis | RFC 2623 §2.6, RFC 7530 §19 |
| Precondition | Export restricted to specific IPs |
| Detection | Check if export uses IP-based restrictions without krb5 |

**Why the RFC allows this**: "NFS has historically used a model where, from an authentication perspective, the client was the entire machine, or at least the source IP address of the machine." (RFC 7530 §19). With UDP transport, IP addresses are trivially spoofable. Even TCP requires only SYN prediction.

**What nfswolf does for this finding**: detection only. `nfswolf analyze` reports whether an export is restricted by IP/hostname and whether Kerberos is in use. Active spoofing is out of scope because it requires privileged network positioning and is not reproducible across lab environments; the `--hostname` flag manipulates `auth_unix.machinename` (F-1.4), which is NOT the same as source-IP spoofing.

### F-3.4: STRIPTLS Downgrade (RFC 9289)

| Field | Value |
|-------|-------|
| Severity | High |
| RFC Basis | RFC 9289 §6.1.1 |
| Precondition | Server supports TLS but client doesn't require it |
| Detection | Check for DANE/TLSA records, probe TLS support |

**Why the RFC allows this**: "The initial AUTH_TLS probe occurs in cleartext. An on-path attacker can alter a cleartext handshake to make it appear as though TLS support is not available." (RFC 9289 §6.1.1).

### F-3.5: Filtered Portmapper Bypass

| Field | Value |
|-------|-------|
| Severity | Medium |
| RFC Basis | RFC 1057 Appendix A (portmapper is convenience, not security) |
| Precondition | Port 111 filtered, NFS ports open |
| Detection | Scan 2049 directly when 111 is filtered |

**Why this works**: The portmapper is a service directory, not a security gate. NFS can be contacted directly on port 2049 without going through portmapper. Mount ports can be guessed or scanned.

---

## Category 4: Privilege Escalation

### F-4.1: no_root_squash Exploitation

| Field | Value |
|-------|-------|
| Severity | Critical |
| RFC Basis | RFC 1813 §4.4, RFC 2623 §2.5 |
| Precondition | no_root_squash enabled on export |
| Detection | Create file as uid=0, check ownership |

**Why the RFC allows this**: "This superuser permission may not be allowed on the server, since anyone who can become superuser on their client could gain access to all remote files." (RFC 1813 §4.4). When no_root_squash is set, uid=0 credentials are not remapped — full root access.

**What nfswolf tests**: Write test file as uid=0, verify it's owned by root on server.

### F-4.2: SUID/SGID Binary Creation

| Field | Value |
|-------|-------|
| Severity | High |
| RFC Basis | RFC 1094 §2.3.5 |
| Precondition | Writable export with no_root_squash (or no nosuid mount) |
| Detection | Create file with mode 04755, verify SUID bit persists |

**Why the RFC allows this**: CREATE accepts an `sattr` structure including mode bits. The mode bits include "0004000 Set user id on execution" (RFC 1094 §2.3.5). An attacker with write access + uid=0 can create setuid-root binaries.

### F-4.3: Device Node Creation via MKNOD

| Field | Value |
|-------|-------|
| Severity | High |
| RFC Basis | RFC 1813 §3.3.11 |
| Precondition | Writable export, no nodev mount on client |
| Detection | Attempt MKNOD with NF3CHR/NF3BLK type |

**Why the RFC allows this**: "Creates a special file of the type, specdata..." (RFC 1813 §3.3.11). MKNOD can create character and block device nodes with arbitrary major/minor numbers — potentially providing raw disk access from the client side.

### F-4.4: Symlink Escape

| Field | Value |
|-------|-------|
| Severity | High |
| RFC Basis | RFC 1094 §2.2.14, RFC 1813 §3.3.5, §3.3.10 |
| Precondition | Writable directory, application follows symlinks |
| Detection | Create symlink pointing outside export, test if apps follow it |

**Why the RFC allows this**: "The data is not necessarily interpreted by the server, just stored in the file." (RFC 1813 §3.3.5). Symlink targets are not validated against export boundaries. "Note that this procedure does not follow symbolic links. The client is responsible for all parsing of filenames." (RFC 1813 §3.3.3). An application on the client that follows server-stored symlinks can be directed outside the intended export.

### F-4.5: SELinux/MAC Label Bypass via NFS

| Field | Value |
|-------|-------|
| Severity | Medium |
| RFC Basis | RFC 7861 §4 (residual limitation) |
| Precondition | SELinux/Smack enforcing, NFS-mounted files |
| Detection | Check if NFS-created files get default labels instead of intended labels |

**Why this exists**: "RPCSEC_GSSv3 is not a complete solution for labeling: it conveys the labels of actors but not the labels of objects." (RFC 7861 §4). Without labeled NFS (extremely rare), NFS-created files get default SELinux contexts, bypassing mandatory access control.

---

## Category 5: Information Disclosure

### F-5.1: Export List Enumeration

| Field | Value |
|-------|-------|
| Severity | Medium |
| RFC Basis | RFC 1094 Appendix A §5.6, RFC 1813 §5.2.5 |
| Precondition | Mountd reachable |
| Detection | Call MNTPROC_EXPORT |

**Why the RFC allows this**: EXPORT "returns a variable number of export list entries" (RFC 1094 Appendix A) without requiring authentication. Full export topology is revealed.

### F-5.2: READDIRPLUS File Handle Harvesting

| Field | Value |
|-------|-------|
| Severity | High |
| RFC Basis | RFC 1813 §3.3.17 |
| Precondition | Any directory handle |
| Detection | Single READDIRPLUS call returns all child handles |

**Why the RFC allows this**: READDIRPLUS returns "name, fileid, attributes (including the fileid), and file handle" for every entry (RFC 1813 §3.3.17). A single call harvests bearer tokens for all files in a directory without per-file access checks.

### F-5.3: NIS Credential Extraction

| Field | Value |
|-------|-------|
| Severity | High |
| RFC Basis | Related RPC service (programs 100004/100007) |
| Precondition | NIS (ypserv) co-hosted with NFS |
| Detection | Check portmapper for program 100004/100007 |

**Why this exists**: NIS is an unauthenticated RPC directory service. When co-hosted with NFS (common on legacy systems), `ypcat passwd.byname` dumps password hashes without authentication. Discovered via the same portmapper scan.

### F-5.4: RPC Service Enumeration

| Field | Value |
|-------|-------|
| Severity | Low |
| RFC Basis | RFC 1057 Appendix A (DUMP procedure) |
| Precondition | Portmapper reachable |
| Detection | PMAPPROC_DUMP returns all registered services |

**Why the RFC allows this**: No authentication on DUMP. Returns program number, version, protocol, and port for all registered services — revealing the full RPC service topology.

### F-5.5: NFSv4 Pseudo-Filesystem Structure Leakage

| Field | Value |
|-------|-------|
| Severity | Low |
| RFC Basis | RFC 7530 §7.8 |
| Precondition | NFSv4 server |
| Detection | Browse from PUTROOTFH |

**Why the RFC allows this**: The pseudo-filesystem "provides a view of exported directories" (RFC 7530 §7.3). The server SHOULD hide existence via ancestor security policies, but this is only SHOULD — the directory structure between exports is often visible.

---

## Category 6: Denial of Service (out of scope)

NLM/NSM lock attacks (F-6.1), NFSv4 grace-period blocking (F-6.2), and
SETCLIENTID state destruction (F-6.3) were initially scoped but are
intentionally not implemented. The lock-DoS module was removed along with
the NLM and NSM clients, and grace-period / SETCLIENTID DoS were never
implemented. Detailed write-ups remain in `docs/findings/F-6.1-*.md`,
`F-6.2-*.md`, and `F-6.3-*.md` for completeness, but no nfswolf
subcommand exercises these findings.

---

## Category 7: Configuration Weaknesses

### F-7.1: Wildcard/Broad Subnet Exports

| Field | Value |
|-------|-------|
| Severity | High |
| RFC Basis | RFC 2623 §2.6 |
| Precondition | Export allows * or large CIDR |
| Detection | Parse MNTPROC_EXPORT response for wildcards |

**Why this matters**: "Host-based access control" is the primary authorization mechanism (RFC 2623 §2.6). Wildcard exports make it accessible to any host on the network.

### F-7.2: `insecure` Export Option (Unprivileged Ports)

| Field | Value |
|-------|-------|
| Severity | Medium |
| RFC Basis | RFC 2623 §2.1 |
| Precondition | Server accepts connections from ports ≥ 1024 |
| Detection | Connect from unprivileged port, attempt mount |

**Why this matters**: While port monitoring is "at best an inconvenience" (RFC 2623 §2.1), removing even this minimal check means any unprivileged process (no root needed) can connect to NFS.

### F-7.3: `nohide`/`crossmnt` Sub-Mount Exposure

| Field | Value |
|-------|-------|
| Severity | Medium |
| RFC Basis | RFC 1813 §3.3.3, §4.2 |
| Precondition | nohide or crossmnt set on export |
| Detection | Traverse past filesystem boundaries |

**Why this matters**: RFC 1813 §3.3.3 states "A server will not allow a LOOKUP operation to cross a mountpoint." The `nohide`/`crossmnt` options override this, exposing sub-mounted filesystems that may contain more sensitive data than the parent export.

### F-7.4: Missing `nosuid`/`nodev` on Client Mount

| Field | Value |
|-------|-------|
| Severity | High |
| RFC Basis | RFC 1094 §2.3.5 (SUID bits in mode) |
| Precondition | Client mounts without nosuid/nodev |
| Detection | Server-side: check export options; client-side: check mount flags |

**Why this matters**: NFS allows creating files with SUID bits (RFC 1094 §2.3.5) and device nodes (RFC 1813 §3.3.11). Without client-side nosuid/nodev, these are executable/usable as privilege escalation vectors.

### F-7.5: all_squash with anonuid=0

| Field | Value |
|-------|-------|
| Severity | Critical |
| RFC Basis | RFC 1813 §4.4, RFC 2623 §2.5 |
| Precondition | all_squash enabled with anonuid=0 |
| Detection | Squash probe (create file, check ownership) |

**Why this matters**: all_squash maps ALL clients to the anonymous UID. If anonuid is set to 0, every client operation runs as root — worse than no_root_squash because no UID even needs to be forged.

### F-7.6: Absence of Audit Logging

| Field | Value |
|-------|-------|
| Severity | Medium |
| RFC Basis | Implementation limitation (knfsd bypasses auditd) |
| Precondition | Linux NFS kernel server |
| Detection | N/A (operational gap, not a remotely testable finding) |

**Why this matters**: The Linux NFS kernel server processes file operations in kernel space, bypassing the auditd framework. No file access logs are generated for NFS operations regardless of audit rules. All NFS attacks operate in a detection blind spot.

---

## Finding ID Cross-Reference

| Finding | Detail Doc | Severity | Detected by |
|---------|-----------|----------|-------------|
| F-1.1 | [UID/GID Spoofing](findings/F-1.1-uid-gid-spoofing.md) | Critical | `uid-spray`, `shell uid/impersonate`, `mount --uid` |
| F-1.2 | [Root Squash Bypass](findings/F-1.2-root-squash-bypass.md) | High | `analyze` (squash probe), `shell uid 0` once `escape` returns a handle |
| F-1.3 | [Auxiliary Group Injection](findings/F-1.3-auxiliary-group-injection.md) | High | `analyze` (shadow GID 42/15), `shell gid`, `mount --aux-gids` |
| F-1.4 | [Machine Name Spoofing](findings/F-1.4-machine-name-spoofing.md) | Low | `--hostname` global flag (every subcommand), `shell hostname` |
| F-1.5 | [Credential Replay](findings/F-1.5-credential-replay.md) | High | Passive only -- precondition detected via F-3.1 |
| F-1.6 | [NFSv2 Downgrade](findings/F-1.6-nfsv2-downgrade.md) | High | `scan` (portmapper version matrix), `analyze` |
| F-2.1 | [Export Escape](findings/F-2.1-export-escape.md) | Critical | `escape`, `analyze`, `shell escape-root` |
| F-2.2 | [File Handle Guessing](findings/F-2.2-file-handle-guessing.md) | High | `analyze` (entropy), `brute-handle` |
| F-2.3 | [Windows Handle Signing](findings/F-2.3-windows-handle-signing.md) | Critical | `analyze` (`FileHandleAnalyzer::check_windows_signing`) |
| F-2.4 | [BTRFS Subvolume Escape](findings/F-2.4-btrfs-subvolume-escape.md) | High | `escape` (subvol 5 + 256+), `shell escape-root` |
| F-2.5 | [Stale Handle Persistence](findings/F-2.5-stale-handle-persistence.md) | Medium | `shell --handle <hex>`, `mount --handle <hex>`, `shell mount-handle` |
| F-2.6 | [Bind Mount Escape](findings/F-2.6-bind-mount-escape.md) | High | `escape` (fsid-based handle), `analyze` |
| F-3.1 | [Plaintext Wire Protocol](findings/F-3.1-plaintext-wire-protocol.md) | High | `analyze` (TLS probe; precondition check) |
| F-3.2 | [Portmapper Amplification](findings/F-3.2-portmapper-amplification.md) | Medium | `scan` (UDP DUMP amplification factor), `analyze` |
| F-3.3 | [IP Spoofing](findings/F-3.3-ip-spoofing-host-trust.md) | High | `analyze` (host-based ACL detection; no active exploit) |
| F-3.4 | [STRIPTLS Downgrade](findings/F-3.4-striptls-downgrade.md) | High | `analyze` (AUTH_TLS probe); NFSv4 SECINFO |
| F-3.5 | [Portmapper Tunnel Bypass](findings/F-3.5-portmapper-tunnel-bypass.md) | Medium | `scan` (direct port 2049 probe when 111 filtered) |
| F-4.1 | [no_root_squash](findings/F-4.1-no-root-squash.md) | Critical | `analyze`, `mount --uid 0 --allow-write`, `shell uid 0` |
| F-4.2 | [SUID/SGID Escalation](findings/F-4.2-suid-sgid-escalation.md) | High | `shell suid-scan`, `mount` + `chmod u+s` via regular tools |
| F-4.3 | [Device Node Creation](findings/F-4.3-device-node-creation.md) | High | `shell mknod` |
| F-4.4 | [Symlink Escape](findings/F-4.4-symlink-escape.md) | High | `analyze` (writable parent detection), `shell ln -s` |
| F-4.5 | [SELinux Label Bypass](findings/F-4.5-selinux-label-bypass.md) | Medium | `analyze` (MAC label check on created file) |
| F-5.1 | [Export List Enumeration](findings/F-5.1-export-list-enumeration.md) | Medium | `scan` (MNTPROC_EXPORT), `analyze` |
| F-5.2 | [READDIRPLUS Harvesting](findings/F-5.2-readdirplus-handle-harvesting.md) | High | `shell ls`, `shell find`, `mount` (transparent via FUSE) |
| F-5.3 | [NIS Credential Extraction](findings/F-5.3-nis-credential-extraction.md) | High | `scan` / `analyze` (portmapper 100004/100007 detect) |
| F-5.4 | [RPC Service Enumeration](findings/F-5.4-rpc-service-enumeration.md) | Low | `scan` (PMAPPROC_DUMP full dump) |
| F-5.5 | [NFSv4 Pseudo-FS Leakage](findings/F-5.5-nfsv4-pseudo-fs-leakage.md) | Low | `scan` (Nfs4Client::map_pseudo_fs) |
| F-6.1 | [NLM Lock Attacks](findings/F-6.1-nlm-lock-attacks.md) | Medium | Out of scope -- lock-DoS module removed |
| F-6.2 | [Grace Period DoS](findings/F-6.2-grace-period-dos.md) | Medium | Out of scope -- never implemented |
| F-6.3 | [SETCLIENTID State Destruction](findings/F-6.3-setclientid-state-destruction.md) | Medium | Out of scope -- never implemented |
| F-7.1 | [Wildcard Exports](findings/F-7.1-wildcard-export-policy.md) | High | `scan` + `analyze` (ACL pattern match on EXPORT output) |
| F-7.2 | [Privileged Port Bypass](findings/F-7.2-privileged-port-bypass.md) | Medium | `analyze` (insecure port probe) |
| F-7.3 | [nohide/crossmnt Exposure](findings/F-7.3-nohide-crossmnt-exposure.md) | Medium | `analyze` (crossmnt LOOKUP traversal), `shell` |
| F-7.4 | [Missing nosuid/nodev](findings/F-7.4-missing-nosuid-nodev.md) | High | `analyze` (server-side export flag check) |
| F-7.5 | [Squash Misconfiguration](findings/F-7.5-squash-misconfiguration.md) | Critical | `analyze` (all_squash + anonuid=0 detection) |
| F-7.6 | [No Audit Logging](findings/F-7.6-no-audit-logging.md) | Medium | Not remotely detectable -- documented for awareness |
