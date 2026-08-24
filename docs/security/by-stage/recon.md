# Reconnaissance

The reconnaissance stage maps the target's NFS infrastructure without touching file data. Every finding here discloses information that feeds later stages: export paths guide initial access, UID oracles narrow credential spraying, filesystem fingerprints select the right escape technique, and server clock skew reveals operational posture.

NFS reconnaissance is uniquely productive because the protocol's sideband services -- portmapper, MOUNT, rquotad, NFS_ACL -- require no authentication. A single unauthenticated TCP connection to port 111 reveals the server's complete RPC topology. From there, each service leaks a different dimension of the target.

---

## Findings in this stage

| Finding | Name | Severity | nfswolf Subcommand | What It Reveals |
|---------|------|----------|-------------------|----------------|
| [F-5.4](../info-disclosure/F-5.4-rpc-service-enumeration.md) | RPC Service Enumeration | Low | `scan` | Full RPC program/version/port map via PMAPPROC_DUMP |
| [F-5.1](../info-disclosure/F-5.1-export-list-enumeration.md) | Export List Enumeration | Medium | `scan`, `analyze` | Every export path and its host-based ACL via MNTPROC_EXPORT |
| [F-5.2](../info-disclosure/F-5.2-readdirplus-handle-harvesting.md) | READDIRPLUS File Handle Harvesting | High | `shell ls`, `shell find` | Handles, UIDs, GIDs, sizes, and timestamps for every file in a directory via a single call |
| F-5.15 | rquotad UID Oracle | Medium | `analyze` | Active UIDs on the server via GETQUOTA, plus filesystem block size |
| F-5.14 | POSIX ACL Enumeration | Medium | `analyze` | Named USER/GROUP ACL entries invisible to mode-bit analysis |
| [F-5.7](../info-disclosure/F-5.7-case-insensitive-fs.md) | PATHCONF Filesystem Fingerprint | Low | `analyze` | Case sensitivity, chown restriction, symlink/link support (PATHCONF) |
| [F-5.8](../info-disclosure/F-5.8-auth-none-metadata-leak.md) | Export Root Attributes Leaked via AUTH_NONE | Low | `analyze` | Export root uid, gid, mode, size, and timestamps leaked to unauthenticated clients |
| [F-5.9](../info-disclosure/F-5.9-read-if-exec-content-disclosure.md) | Execute-Only File Content Disclosure | Low | `analyze` | Files with mode 0111 (execute-only) are readable via the READ_IF_EXEC fallback |
| [F-5.10](../info-disclosure/F-5.10-pnfs-layout-security-downgrade.md) | pNFS Flex-File Layout Security Downgrade | Medium | `analyze` | pNFS flex-file layout downgrades data path from NFSv4.1 to NFSv3 AUTH_SYS |
| [F-5.5](../info-disclosure/F-5.5-nfsv4-pseudo-fs-leakage.md) | NFSv4 Pseudo-Filesystem Structure Leakage | Low | `scan` | Export directory structure visible via PUTROOTFH + READDIR without MOUNT |
| [F-5.3](../info-disclosure/F-5.3-nis-credential-extraction.md) | NIS Domain Detection | High | `scan`, `analyze` | NIS programs (100004/100007) in portmapper indicate credential stores |
| [F-5.6](../info-disclosure/F-5.6-metadata-on-access-denial.md) | Metadata Disclosed on Access Denial | Low | `analyze` | uid, gid, mode, and size leaked in post_op_attr on NFS3ERR_ACCES/PERM responses |
| [F-1.8](../identity/F-1.8-auth-tooweak-kerberos-enforced.md) | AUTH_TOOWEAK Oracle | High | `analyze` | Definitively reveals whether an export requires Kerberos |
| [F-3.9](../network/F-3.9-auth-short-session-credentials.md) | AUTH_SHORT Token Detection | Info | `analyze` | Detects servers issuing opaque session tokens in reply verifiers |
| [F-3.7](../network/F-3.7-auth-dh-obsolete.md) | RDMA / AUTH_DH Detection | Medium | `scan` | RDMA transport availability; AUTH_DH (broken crypto) advertisement |

---

## Recon by protocol layer

NFS reconnaissance spans four protocol layers, each contributing different intelligence:

**Portmapper (port 111).** The entry point. PMAPPROC_DUMP returns every registered RPC program with its version, transport protocol, and listening port. This single call reveals whether the server runs NFS (100003), mountd (100005), rquotad (100011), NFS_ACL (100227), NIS (100004/100007), and any other RPC services. The 1251-entry IANA registry maps program numbers to named services. UDP availability on port 111 also enables amplification measurement (F-3.2): a 68-byte request produces up to 1930 bytes of response.

**MOUNT daemon.** Two procedures provide the bulk of the export intelligence. EXPORT returns every exported path with its access control list (IP addresses, hostnames, netgroups, wildcards). DUMP returns the list of currently mounted clients with their IPs, export paths, and mount timestamps. Together they reveal what is shared, who is allowed, and who is actively connected. Neither procedure requires authentication.

**NFSv4 pseudo-filesystem.** For servers running NFSv4, the pseudo-FS exposes the structure of all exports from a single PUTROOTFH + READDIR sequence. This reveals export names even when the MOUNT daemon is firewalled or absent. The pseudo-root may disclose exports that are IP-restricted at the MOUNT level, because NFSv4 does not use MOUNT for namespace resolution.

**Sideband RPC services.** rquotad (100011) confirms active UIDs through quota queries -- non-zero block/file counts prove a UID has disk activity. NFS_ACL (100227) returns POSIX ACL entries that reveal UIDs and GIDs granted access beyond what mode bits show. PATHCONF reports filesystem properties: case sensitivity (Windows NFS indicator), chown restriction, and link/symlink support.

---

## How information flows forward

Reconnaissance output directly parameterizes every subsequent stage:

- **Export paths** from F-5.1 become MOUNT targets for [initial access](access.md).
- **Active UIDs** from F-5.15 (rquotad) and F-5.14 (POSIX ACLs) feed the credential ladder for [privilege escalation](privesc.md), replacing blind UID spraying with targeted attempts.
- **Filesystem type** from handle structure fingerprinting (`decode` subcommand, `FileHandleAnalyzer`) selects the correct escape constructor for [lateral movement](lateral.md). An ext4 export needs inode 2; BTRFS needs subvolume 5 + objectid 256; ZFS needs a different root encoding entirely.
- **AUTH_TOOWEAK** from F-1.8 tells the attacker which exports are hardened (Kerberos-only) and which are soft targets (AUTH_SYS). No point running the credential ladder against a `sec=krb5`-only export.
- **NIS detection** from F-5.3 opens a parallel attack path: if ypserv is co-hosted, `ypcat passwd.byname` dumps password hashes without authentication -- before NFS is even touched.
- **MOUNT DUMP** from F-5.2 reveals legitimate client IPs, which feed IP-based ACL bypass attempts and source-address selection.

!!! tip "nfswolf workflow"
    Run `nfswolf scan <target>` first to collect the full RPC topology, export list, mount clients, and NFSv4 pseudo-FS structure. Then run `nfswolf analyze <target>` for per-export deep inspection: PATHCONF, FSSTAT, POSIX ACLs, rquotad probing, AUTH_TOOWEAK detection, and handle fingerprinting. The scanner is breadth-first (what services exist); the analyzer is depth-first (what each export reveals).

---

## Why recon is so effective against NFS

NFS reconnaissance produces more actionable intelligence per packet than almost any other protocol. The portmapper's DUMP procedure returns the complete RPC service registry in a single unauthenticated call. MOUNT EXPORT lists every shared directory with its access controls. FSSTAT and FSINFO report filesystem internals that select attack strategies. rquotad confirms which UIDs are real without triggering login failures.

None of these services require authentication. None log the queries in a way that triggers alerts. The portmapper was designed as a public directory service (RFC 1057 Appendix A), MOUNT was designed to be queryable by automounters (RFC 2623 Section 2.3.2), and rquotad was designed for remote quota display. They work exactly as specified -- the problem is that "as specified" means unauthenticated and unrestricted.

---

## Detection and countermeasures

Filtering port 111 (portmapper) reduces the attack surface but does not eliminate reconnaissance. The scanner falls back to direct port 2049 probing (F-3.5) and NFSv4 pseudo-FS enumeration when the portmapper is filtered. Disabling rquotad and NFS_ACL removes two UID oracle channels but does not affect the core export enumeration through MOUNT EXPORT.

The only configuration that blocks all reconnaissance is restricting mountd and nfsd to authenticated access (`sec=krb5` without AUTH_SYS) combined with firewall rules that limit portmapper access to authorized clients. Even then, the portmapper's DUMP response leaks the existence and version of NFS services to any host that can reach port 111 over UDP.

!!! warning "Recon produces no alerts on most deployments"
    Linux knfsd does not log EXPORT, DUMP, or NULL probe calls at any log level. The portmapper logs nothing by default. An attacker can fully enumerate the NFS infrastructure without generating a single log entry. Network-level monitoring (IDS rules matching RPC DUMP patterns) is the only reliable detection path for NFS reconnaissance.

---

## Relationship to other stages

Reconnaissance is the foundation of every subsequent stage. The export list and ACL data from F-5.1 feed directly into [initial access](access.md) target selection. Handle structure fingerprints (from `decode` / `FileHandleAnalyzer`) determine the escape technique for [lateral movement](lateral.md). Active UID data from rquotad (F-5.15) and POSIX ACL entries (F-5.14) populate the credential ladder that drives [privilege escalation](privesc.md). AUTH_TOOWEAK detection (F-1.8) eliminates Kerberos-hardened exports from the attack scope before time is wasted on them.
