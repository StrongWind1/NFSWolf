# Security findings catalog

nfswolf documents **62 NFS security findings** across 7 attack categories. Every finding traces to a specific RFC section (or kernel code path) that explains why the vulnerability exists at the protocol level. Together they cover the full NFS attack surface, from unauthenticated recon through credential forging, export escape, privilege escalation, and lateral movement.

The catalog is the authoritative reference for what nfswolf detects and why each attack works. Findings are numbered `F-{category}.{sequence}` and carry a severity rating, RFC basis, preconditions, and a mapping to the nfswolf subcommand that exercises them.

---

## How to read a finding

Each finding page follows a consistent structure:

| Field | What it tells you |
|-------|-------------------|
| **Severity** | Critical / High / Medium / Low / Info -- based on direct exploitability and impact |
| **RFC Basis** | The specific RFC section (or kernel code path) that creates the vulnerability |
| **Precondition** | What must be true on the target for the finding to apply |
| **Detection** | The protocol operation nfswolf uses to test for the condition |
| **Why the RFC allows this** | The protocol-level rationale -- why this is a design property, not a bug |
| **What nfswolf tests** | The concrete checks and subcommands that exercise the finding |

---

## Protocol root causes

The 62 findings trace back to four fundamental design properties of NFS:

!!! abstract "Client-asserted credentials (AUTH_SYS)"

    The server trusts whatever UID, GID, and auxiliary groups the client claims. There is no verifier, no challenge-response, no proof of identity. This single design choice enables Category 1 (all 8 identity findings) and is a precondition for most of Category 4 (privilege escalation).

    > "There is no verifier, so credentials can easily be faked." -- RFC 1057 sec. 9.3

!!! abstract "Bearer-token file handles"

    File handles are opaque blobs that grant access to whoever presents them. There is no binding to the client that received the handle, no expiry, and no revocation mechanism. Possession is authorization. This drives all 12 findings in Category 2.

    > "An attacker can circumvent the MOUNT server's access control by either stealing a file handle or guessing a file handle." -- RFC 2623 sec. 2.6

!!! abstract "No transport security by default"

    NFS defers encryption and integrity to "underlying transport layers" that are never specified and rarely deployed. All wire traffic is plaintext unless the administrator explicitly configures Kerberos or RPC-with-TLS. This enables Category 3 (network attacks).

    > "NFS version 3 defers to the authentication provisions of the supporting RPC protocol." -- RFC 1813 sec. 8

!!! abstract "Stateless architecture"

    The MOUNT protocol is an advisory directory service, not a security gate. The NFS daemon never calls back to MOUNT to verify that a client was authorized, and unmounting does not invalidate file handles. See the [MOUNT protocol](../nfs/protocols/mount.md) reference for the full architectural analysis.

---

## Categories

| Category | ID Range | Count | Severity Breakdown | Description |
|----------|----------|------:|---------------------|-------------|
| [Identity Attacks](identity/index.md) | F-1.1 -- F-1.8 | 8 | 1 Critical, 6 High, 1 Low | AUTH_SYS trust model exploitation: UID/GID spoofing, root squash bypass, credential replay, version downgrade |
| [Access Control Bypass](access-control/index.md) | F-2.1 -- F-2.12 | 12 | 6 Critical, 4 High, 2 Medium | File handle bearer-token abuse: export escape, handle guessing, cross-export lateral movement, LOOKUPP traversal |
| [Network Attacks](network/index.md) | F-3.1 -- F-3.9 | 9 | 1 Critical, 3 High, 3 Medium, 2 Info | Wire-level attacks: plaintext interception, UDP amplification, STRIPTLS downgrade, AUTH_DH weakness |
| [Privilege Escalation](privesc/index.md) | F-4.1 -- F-4.6 | 6 | 1 Critical, 4 High, 1 Medium | Post-access escalation: no_root_squash, SUID/SGID creation, device nodes, symlink escape, chown abuse |
| [Information Disclosure](info-disclosure/index.md) | F-5.1 -- F-5.17 | 17 | 2 High, 6 Medium, 6 Low, 3 Info | Data leakage: export enumeration, handle harvesting, NIS extraction, metadata on denial, pNFS downgrade |
| [Denial of Service](dos/index.md) | F-6.1 -- F-6.3 | 3 | 3 Medium | Lock and state attacks (out of scope -- documented only) |
| [Configuration Weaknesses](config/index.md) | F-7.1 -- F-7.7 | 7 | 1 Critical, 2 High, 4 Medium | Server misconfigurations: wildcard exports, missing nosuid/nodev, squash errors, TLS coexistence |

---

## Severity distribution

| Severity | Count | Proportion |
|----------|------:|------------|
| :material-alert-circle:{ .critical } **Critical** | 10 | 16% |
| :material-alert:{ .high } **High** | 21 | 34% |
| :material-alert-outline:{ .medium } **Medium** | 19 | 31% |
| :material-information-outline:{ .low } **Low** | 7 | 11% |
| :material-information:{ .info } **Info** | 5 | 8% |

!!! danger "Half of all findings are Critical or High"

    31 of the 62 findings carry Critical or High severity. The NFS protocol's design (client-asserted credentials, bearer-token file handles, no transport security by default) makes most of these inherent to the protocol rather than implementation bugs.

---

## Attack chain

The 62 findings connect into a directed attack flow where each stage feeds the next with handles, credentials, or filesystem access. See the [attack chain](attack-chain.md) page for the full diagram, stage-by-stage walkthrough, defense mapping, and an example attack narrative against a default Linux NFS server.

---

## Cross-reference views

Browse findings grouped by a different axis:

**By Protocol Version**

- [ONC RPC / Portmapper](by-protocol/rpc.md) -- portmapper amplification, service enumeration, AUTH_SYS wire format
- [MOUNT](by-protocol/mount.md) -- export enumeration, handle acquisition, UDP theft
- [NFSv2](by-protocol/nfsv2.md) -- version downgrade, fixed 32-byte handles
- [NFSv3](by-protocol/nfsv3.md) -- READDIRPLUS harvesting, ACCESS advisory, post_op_attr leaks
- [NFSv4](by-protocol/nfsv4.md) -- LOOKUPP escape, pseudo-FS leakage, SECINFO probing, SETCLIENTID state destruction

**By Attack Stage**

- [Recon](by-stage/recon.md) -- pre-authentication information gathering
- [Access](by-stage/access.md) -- initial foothold via credential forging or handle reuse
- [Lateral Movement](by-stage/lateral.md) -- cross-export traversal
- [Privilege Escalation](by-stage/privesc.md) -- post-access root and capability escalation
- [Exfiltration](by-stage/exfil.md) -- sensitive data extraction

---

## Scope and limitations

!!! note "Category 6 (Denial of Service) is documented but not implemented"

    The three DoS findings (F-6.1 NLM lock attacks, F-6.2 grace period blocking, F-6.3 SETCLIENTID state destruction) are cataloged for completeness. The NLM and NSM clients were removed in v0.2.0 and the NFSv4 DoS attacks were never implemented. No nfswolf subcommand exercises these findings.

!!! note "Some findings are detection-only"

    Several findings describe attacks that nfswolf detects but does not actively exploit: F-3.3 (IP spoofing requires network positioning), F-4.5 (SELinux bypass requires labeled NFS), F-7.4 (nosuid/nodev are client-side mount options not visible to the server), F-7.6 (audit logging gaps are not remotely testable). These are flagged by `analyze` as risk indicators.

---

## Complete finding index

Every finding in the catalog, sorted by ID. The **Detected By** column lists the nfswolf subcommand(s) that exercise or detect the finding.

| ID | Name | Severity | Category | Detected By |
|----|------|----------|----------|-------------|
| F-1.1 | [UID/GID Spoofing](identity/F-1.1-uid-gid-spoofing.md) | Critical | Identity | `uid-spray`, `shell uid/impersonate`, `mount --uid` |
| F-1.2 | [Root Squash Bypass](identity/F-1.2-root-squash-bypass.md) | High | Identity | `analyze` (squash probe) |
| F-1.3 | [Auxiliary Group Injection](identity/F-1.3-auxiliary-group-injection.md) | High | Identity | `analyze` (shadow GID), `shell gid`, `mount --aux-gids` |
| F-1.4 | [Machine Name Spoofing](identity/F-1.4-machine-name-spoofing.md) | Low | Identity | `--hostname` global flag |
| F-1.5 | [Credential Replay](identity/F-1.5-credential-replay.md) | High | Identity | Passive -- precondition via F-3.1 |
| F-1.6 | [NFSv2 Downgrade](identity/F-1.6-nfsv2-downgrade.md) | High | Identity | `scan` (version matrix), `analyze` |
| F-1.7 | [RPCSEC_GSS Flavor Downgrade](identity/F-1.7-rpcsec-gss-flavor-downgrade.md) | High | Identity | `analyze` (mixed auth flavor) |
| F-1.8 | [AUTH_TOOWEAK Oracle](identity/F-1.8-auth-tooweak-kerberos-enforced.md) | High | Identity | `analyze` (SECINFO, MOUNT auth-flavors) |
| F-2.1 | [Export Escape via FS Root Handle](access-control/F-2.1-export-escape.md) | Critical | Access Control | `escape`, `analyze`, `shell escape-root` |
| F-2.2 | [File Handle Guessing](access-control/F-2.2-file-handle-guessing.md) | High | Access Control | `analyze` (entropy), `brute-handle` |
| F-2.3 | [Windows Handle Signing Disabled](access-control/F-2.3-windows-handle-signing.md) | Critical | Access Control | `analyze` (signing check) |
| F-2.4 | [BTRFS Subvolume Escape](access-control/F-2.4-btrfs-subvolume-escape.md) | High | Access Control | `escape`, `shell escape-root` |
| F-2.5 | [Stale Handle Persistence](access-control/F-2.5-stale-handle-persistence.md) | Medium | Access Control | `shell --handle`, `mount --handle` |
| F-2.6 | [Bind Mount Escape](access-control/F-2.6-bind-mount-escape.md) | High | Access Control | `escape` (fsid-based handle) |
| F-2.7 | [NFS Daemon ACL Blindness](access-control/F-2.7-nfsd-acl-blindness.md) | Critical | Access Control | `shell --handle` (port 2049, no MOUNT) |
| F-2.8 | [Sibling Export Lateral Access](access-control/F-2.8-sibling-export-lateral-access.md) | Critical | Access Control | `escape` + `shell` (cross-export cd) |
| F-2.9 | [WebNFS Public File Handle](access-control/F-2.9-webnfs-public-handle.md) | Critical | Access Control | `analyze` (zero-handle probe) |
| F-2.10 | [SIGN_FH Root Handle Exemption](access-control/F-2.10-sign-fh-root-exemption.md) | Medium | Access Control | `shell --handle` (constructed root) |
| F-2.11 | [NFSv4 LOOKUPP Export Escape](access-control/F-2.11-nfsv4-lookupp-export-escape.md) | Critical | Access Control | `escape-root` (v4 shell), `cd ..` |
| F-2.12 | [NFSv4 LOOKUPP Cross-Export Lateral](access-control/F-2.12-nfsv4-lookupp-cross-export-lateral.md) | High | Access Control | `cd ..` + `cd <sibling>`, `exports` |
| F-3.1 | [Plaintext Wire Protocol](network/F-3.1-plaintext-wire-protocol.md) | High | Network | `analyze` (no RPCSEC_GSS flag) |
| F-3.2 | [Portmapper UDP Amplification](network/F-3.2-portmapper-amplification.md) | Medium | Network | `scan` (UDP DUMP amplification) |
| F-3.3 | [IP Spoofing Against Host ACLs](network/F-3.3-ip-spoofing-host-trust.md) | High | Network | `analyze` (host-based ACL detection) |
| F-3.4 | [STRIPTLS Downgrade](network/F-3.4-striptls-downgrade.md) | High | Network | `analyze` (AUTH_TLS probe) |
| F-3.5 | [Portmapper Tunnel Bypass](network/F-3.5-portmapper-tunnel-bypass.md) | Medium | Network | `scan` (direct 2049 probe) |
| F-3.6 | [UDP MOUNT Handle Theft](network/F-3.6-udp-mount-handle-theft.md) | Critical | Network | `scan --scan-udp` |
| F-3.7 | [AUTH_DH Advertised](network/F-3.7-auth-dh-obsolete.md) | Medium | Network | `analyze` (flavor 3 detection) |
| F-3.8 | [RPC-with-TLS Supported](network/F-3.8-rpc-with-tls.md) | Info | Network | `analyze` (AUTH_TLS NULL probe) |
| F-3.9 | [AUTH_SHORT Session Credentials](network/F-3.9-auth-short-session-credentials.md) | Info | Network | `analyze` (flavor 2 detection) |
| F-4.1 | [no_root_squash Exploitation](privesc/F-4.1-no-root-squash.md) | Critical | Privilege Escalation | `analyze`, `mount --uid 0 --allow-write` |
| F-4.2 | [SUID/SGID Binary Creation](privesc/F-4.2-suid-sgid-escalation.md) | High | Privilege Escalation | `shell suid-scan`, `mount` + `chmod u+s` |
| F-4.3 | [Device Node Creation](privesc/F-4.3-device-node-creation.md) | High | Privilege Escalation | `shell mknod` |
| F-4.4 | [Symlink Escape](privesc/F-4.4-symlink-escape.md) | High | Privilege Escalation | `analyze`, `shell symlink` |
| F-4.5 | [SELinux/MAC Label Bypass](privesc/F-4.5-selinux-label-bypass.md) | Medium | Privilege Escalation | Not implemented (documented) |
| F-4.6 | [Unrestricted chown](privesc/F-4.6-unrestricted-chown.md) | High | Privilege Escalation | `analyze` (PATHCONF check) |
| F-5.1 | [Export List Enumeration](info-disclosure/F-5.1-export-list-enumeration.md) | Medium | Info Disclosure | `scan`, `analyze` |
| F-5.2 | [READDIRPLUS Handle Harvesting](info-disclosure/F-5.2-readdirplus-handle-harvesting.md) | High | Info Disclosure | `shell ls`, `shell find`, `mount` |
| F-5.3 | [NIS Credential Extraction](info-disclosure/F-5.3-nis-credential-extraction.md) | High | Info Disclosure | `scan`, `analyze` (portmapper) |
| F-5.4 | [RPC Service Enumeration](info-disclosure/F-5.4-rpc-service-enumeration.md) | Low | Info Disclosure | `scan` (DUMP) |
| F-5.5 | [NFSv4 Pseudo-FS Leakage](info-disclosure/F-5.5-nfsv4-pseudo-fs-leakage.md) | Low | Info Disclosure | `scan` (pseudo-root READDIR) |
| F-5.6 | [Metadata on Access Denial](info-disclosure/F-5.6-metadata-on-access-denial.md) | Low | Info Disclosure | `analyze` (post_op_attr harvest) |
| F-5.7 | [Case-Insensitive Filesystem](info-disclosure/F-5.7-case-insensitive-fs.md) | Low | Info Disclosure | `analyze` (PATHCONF) |
| F-5.8 | [AUTH_NONE Metadata Leak](info-disclosure/F-5.8-auth-none-metadata-leak.md) | Low | Info Disclosure | `analyze` (AUTH_NONE GETATTR) |
| F-5.9 | [Execute-Only File Content Disclosure](info-disclosure/F-5.9-read-if-exec-content-disclosure.md) | Low | Info Disclosure | `analyze` (read-if-exec check) |
| F-5.10 | [pNFS Layout Security Downgrade](info-disclosure/F-5.10-pnfs-layout-security-downgrade.md) | Medium | Info Disclosure | Not implemented (documented) |
| F-5.11 | [Filesystem Lacks Link/Symlink Support](info-disclosure/F-5.11-filesystem-lacks-link-symlink.md) | Info | Info Disclosure | `analyze` (FSINFO) |
| F-5.12 | [Near Inode Exhaustion](info-disclosure/F-5.12-near-inode-exhaustion.md) | Medium | Info Disclosure | `analyze` (FSSTAT) |
| F-5.13 | [NFSv4 Named Attributes Exposed](info-disclosure/F-5.13-nfsv4-named-attributes-exposed.md) | Info | Info Disclosure | `analyze` (OPENATTR) |
| F-5.14 | [POSIX ACL Entries Beyond Mode Bits](info-disclosure/F-5.14-posix-acl-entries.md) | Medium | Info Disclosure | `analyze` (NFS_ACL GETACL) |
| F-5.15 | [rquotad UID Activity Disclosure](info-disclosure/F-5.15-rquotad-uid-oracle.md) | Medium | Info Disclosure | `analyze` (RQUOTA GETQUOTA) |
| F-5.16 | [Silly-Rename Files Detected](info-disclosure/F-5.16-silly-rename-detected.md) | Info | Info Disclosure | `analyze` (READDIRPLUS pattern) |
| F-5.17 | [Write Verifier Change (Reboot Detected)](info-disclosure/F-5.17-write-verifier-changed.md) | Medium | Info Disclosure | `analyze` (COMMIT comparison) |
| F-6.1 | [NLM Lock Attacks](dos/F-6.1-nlm-lock-attacks.md) | Medium | Denial of Service | Out of scope |
| F-6.2 | [Grace Period DoS](dos/F-6.2-grace-period-dos.md) | Medium | Denial of Service | Out of scope |
| F-6.3 | [SETCLIENTID State Destruction](dos/F-6.3-setclientid-state-destruction.md) | Medium | Denial of Service | Out of scope |
| F-7.1 | [Wildcard/Broad Subnet Exports](config/F-7.1-wildcard-export-policy.md) | High | Configuration | `scan`, `analyze` |
| F-7.2 | [Privileged Port Bypass](config/F-7.2-privileged-port-bypass.md) | Medium | Configuration | `analyze` (probe removed -- see note) |
| F-7.3 | [nohide/crossmnt Exposure](config/F-7.3-nohide-crossmnt-exposure.md) | Medium | Configuration | `analyze` (crossmnt LOOKUP) |
| F-7.4 | [Missing nosuid/nodev](config/F-7.4-missing-nosuid-nodev.md) | High | Configuration | Not server-observable (client-side) |
| F-7.5 | [all_squash with anonuid=0](config/F-7.5-squash-misconfiguration.md) | Critical | Configuration | `analyze` |
| F-7.6 | [No Audit Logging](config/F-7.6-no-audit-logging.md) | Medium | Configuration | Not remotely detectable (documented) |
| F-7.7 | [xprtsec Permissive Default](config/F-7.7-xprtsec-permissive-default.md) | Medium | Configuration | Not implemented (documented) |
