# NFSv3 findings

NFSv3 (RFC 1813) is the most commonly deployed NFS version and the primary target for nfswolf. The majority of the findings catalog applies to v3 because it is where AUTH_SYS trust, file handle bearer tokens, and plaintext wire protocol all intersect with the richest set of operations. READDIRPLUS harvests handles and metadata in bulk, FSINFO and FSSTAT leak filesystem internals, and the MOUNT protocol provides unauthenticated export enumeration. This page collects every finding relevant to NFSv3, sorted by severity.

## Applicable findings

### Critical

| Finding | Name | Notes |
|---------|------|-------|
| [F-1.1](../identity/F-1.1-uid-gid-spoofing.md) | UID/GID Spoofing | AUTH_SYS credentials are accepted without verification. The credential ladder (uid spray, owner-first, observed-identity ranking) is tuned for v3. |
| [F-2.1](../access-control/F-2.1-export-escape.md) | Export Escape | The primary escape path. Filesystem root handle construction works across 18 of 19 Linux filesystem types. v3's variable-length handles (up to 64 bytes) carry more metadata than v2 but the knfsd layout is well-documented. |
| [F-2.3](../access-control/F-2.3-windows-handle-signing.md) | Windows Handle Signing Disabled | Windows NFS Server adds HMAC to v3 handles. When signing is disabled, the last 10 bytes are zero -- handles become trivially constructible. |
| [F-2.7](../access-control/F-2.7-nfsd-acl-blindness.md) | NFS Daemon ACL Blindness | The NFS daemon on port 2049 never checks whether the presenting client was authorized by MOUNT. Any valid handle works from any IP. `shell --handle <hex>` demonstrates this directly. |
| [F-2.8](../access-control/F-2.8-sibling-export-lateral-access.md) | Sibling Export Lateral Access | After escaping to the filesystem root (F-2.1), LOOKUP reaches any directory on the same filesystem, including IP-restricted peer exports. No handle construction needed for the lateral step. |
| [F-2.9](../access-control/F-2.9-webnfs-public-handle.md) | WebNFS Public Handle | The all-zeros public handle (RFC 2055 Section 5) bypasses MOUNT entirely. Primarily a Solaris/NetApp concern but applies to any v3 server with WebNFS enabled. |
| [F-4.1](../privesc/F-4.1-no-root-squash.md) | no_root_squash | uid=0 credentials get full root access including `CAP_MAC_OVERRIDE` (bypasses SELinux/AppArmor) and `CAP_SYS_RESOURCE` (bypasses disk quotas). |
| [F-7.5](../config/F-7.5-squash-misconfiguration.md) | all_squash with anonuid=0 | Worse than no_root_squash: every client operation runs as root regardless of claimed UID. |

### High

| Finding | Name | Notes |
|---------|------|-------|
| [F-1.2](../identity/F-1.2-root-squash-bypass.md) | Root Squash Bypass | root_squash only maps uid 0. Any non-zero UID is trusted. Claiming the file owner's UID bypasses all permission checks. |
| [F-1.3](../identity/F-1.3-auxiliary-group-injection.md) | Auxiliary Group Injection | The `gids<16>` array is client-asserted. Including `gid=42` (shadow group) grants group-read access to `/etc/shadow` on many systems. |
| [F-1.5](../identity/F-1.5-credential-replay.md) | Credential Replay | AUTH_SYS has no nonce, timestamp, or sequence number. Captured RPC messages can be replayed indefinitely. |
| [F-1.6](../identity/F-1.6-nfsv2-downgrade.md) | NFSv2 Downgrade | Relevant to v3 because the downgrade FROM v3 TO v2 is the attack. A server with both v2 and v3 allows bypassing v3's security flavor requirements. |
| [F-1.7](../identity/F-1.7-rpcsec-gss-flavor-downgrade.md) | RPCSEC_GSS Flavor Downgrade | When an export advertises `sec=krb5:sys`, a client freely chooses AUTH_SYS. The server does not enforce the strongest flavor. |
| [F-1.8](../identity/F-1.8-auth-tooweak-kerberos-enforced.md) | AUTH_TOOWEAK Oracle | MOUNT succeeds with AUTH_SYS even on krb5-only exports (leaking the handle), but subsequent operations fail with AUTH_TOOWEAK -- confirming export existence and krb5 enforcement. |
| [F-2.2](../access-control/F-2.2-file-handle-guessing.md) | Handle Brute Force | The STALE/BADHANDLE oracle (NFS3ERR_STALE vs NFS3ERR_BADHANDLE) confirms when the handle format is correct, enabling targeted brute-force. |
| [F-2.4](../access-control/F-2.4-btrfs-subvolume-escape.md) | BTRFS Subvolume Escape | Constructing handles with different subvolume IDs (256+) accesses other subvolumes on the same BTRFS filesystem. |
| [F-2.6](../access-control/F-2.6-bind-mount-escape.md) | Bind Mount Escape | Bind mounts share the same fsid. With no_subtree_check, any inode handle on the filesystem is accepted regardless of bind mount boundary. |
| [F-3.1](../network/F-3.1-plaintext-wire-protocol.md) | Plaintext Traffic | Default v3 has no wire encryption. All file data and AUTH_SYS credentials are visible to any network observer. |
| [F-3.3](../network/F-3.3-ip-spoofing-host-trust.md) | IP Spoofing | Export ACLs rely on source IP. UDP transport makes spoofing trivial; TCP requires SYN prediction. |
| [F-3.4](../network/F-3.4-striptls-downgrade.md) | STRIPTLS Downgrade | The AUTH_TLS STARTTLS probe is cleartext and can be intercepted by an on-path attacker (RFC 9289 Section 6.1.1). |
| [F-4.2](../privesc/F-4.2-suid-sgid-escalation.md) | SUID/SGID Creation | CREATE with mode 04755 plants a setuid-root binary. Requires writable export + no_root_squash. |
| [F-4.3](../privesc/F-4.3-device-node-creation.md) | Device Node Creation | MKNOD creates character/block devices with arbitrary major/minor numbers. Raw disk access from the NFS client. |
| [F-4.4](../privesc/F-4.4-symlink-escape.md) | Symlink Escape | Symlink targets are not validated against export boundaries. Applications following server-stored symlinks can be directed outside the export. |
| [F-4.6](../privesc/F-4.6-unrestricted-chown.md) | Unrestricted chown | PATHCONF `chown_restricted=false` allows any user to change file ownership via SETATTR. Write a file, chown to root, set SUID. |
| [F-5.2](../info-disclosure/F-5.2-readdirplus-handle-harvesting.md) | READDIRPLUS Harvesting | A single READDIRPLUS call returns file handles, attributes, and names for every entry in a directory. Mass bearer-token harvest. |
| [F-5.3](../info-disclosure/F-5.3-nis-credential-extraction.md) | NIS Credential Extraction | NIS (ypserv) co-hosted with NFS dumps password hashes without authentication. Discovered via portmapper scan. |
| [F-7.1](../config/F-7.1-wildcard-export-policy.md) | Wildcard Exports | Export allows `*` or broad CIDR, making it accessible to any host on the network. |
| [F-7.4](../config/F-7.4-missing-nosuid-nodev.md) | Missing nosuid/nodev | Client-side mount options. Without them, SUID binaries (F-4.2) and device nodes (F-4.3) are exploitable. |

### Medium

| Finding | Name | Notes |
|---------|------|-------|
| [F-2.5](../access-control/F-2.5-stale-handle-persistence.md) | Stale Handle Persistence | UMNT removes the mount list entry but does not invalidate the handle. Handles survive permission revocation. |
| [F-2.10](../access-control/F-2.10-sign-fh-root-exemption.md) | SIGN_FH Root Exemption | Linux knfsd's handle signing skips root handles (fileid_type=0). Root handles can be constructed without the MAC key. |
| [F-3.2](../network/F-3.2-portmapper-amplification.md) | Portmapper Amplification | UDP DUMP returns 486-1930 bytes for a 68-byte request. Spoofed-source DDoS vector. |
| [F-3.5](../network/F-3.5-pnfs-metadata-server-detected.md) | pNFS Metadata Server Detected | NFSv4.1 finding; not applicable to NFSv3-only deployments. Listed for cross-reference completeness. |
| [F-3.7](../network/F-3.7-auth-dh-obsolete.md) | AUTH_DH Advertised | AUTH_DH uses 192-bit DH + 56-bit DES. Trivially breakable by modern standards. |
| [F-4.5](../privesc/F-4.5-selinux-label-bypass.md) | SELinux Label Bypass | NFS-created files get default SELinux contexts. NFS root with `CAP_MAC_OVERRIDE` bypasses all MAC enforcement. |
| [F-5.1](../info-disclosure/F-5.1-export-list-enumeration.md) | Export List Enumeration | MNTPROC_EXPORT reveals full export topology without authentication. |
| [F-5.10](../info-disclosure/F-5.10-solaris-time-delta-fingerprint.md) | Solaris Time Delta Fingerprint | FSINFO time_delta of {0, 1000} nanoseconds identifies Solaris NFS servers, enabling targeted attack selection. |
| F-5.12 | Near Inode Exhaustion | FSSTAT reports available inodes. Below 1000 = DoS risk via inode exhaustion. |
| F-5.14 | POSIX ACL Exposure | NFS_ACL sideband (program 100227) returns named USER/GROUP ACL entries invisible to mode-bit analysis. |
| F-5.15 | rquotad UID Oracle | GETQUOTA reveals per-UID disk activity and filesystem block size without authentication. |
| F-5.17 | Write Verifier Change | Two COMMIT calls with different writeverf3 values prove a server reboot occurred. Lock state was reset, unstable writes may be lost. |
| [F-7.2](../config/F-7.2-privileged-port-bypass.md) | Privileged Port Bypass | `insecure` export option allows unprivileged-port connections. Any process, not just root, can connect. |
| [F-7.3](../config/F-7.3-nohide-crossmnt-exposure.md) | nohide/crossmnt Exposure | Sub-mounted filesystems exposed across LOOKUP boundaries that RFC 1813 Section 3.3.3 says should be blocked. |
| [F-7.6](../config/F-7.6-no-audit-logging.md) | No Audit Logging | knfsd processes file operations in kernel space, bypassing auditd. All NFS attacks run in a detection blind spot. |

### Low / Info

| Finding | Name | Notes |
|---------|------|-------|
| [F-1.4](../identity/F-1.4-machine-name-spoofing.md) | Machine Name Spoofing | `machinename` is logged but not used for access control on Linux knfsd. Log poisoning only. |
| [F-5.4](../info-disclosure/F-5.4-rpc-service-enumeration.md) | RPC Service Enumeration | PMAPPROC_DUMP reveals all registered RPC services. Reconnaissance feed. |
| [F-5.6](../info-disclosure/F-5.6-metadata-on-access-denial.md) | Metadata on Access Denial | post_op_attr in NFS3ERR_ACCES/PERM responses leaks uid, gid, mode, size of files the caller cannot read. |
| [F-5.7](../info-disclosure/F-5.7-case-insensitive-fs.md) | Case-Insensitive FS | PATHCONF `case_insensitive=true` fingerprints Windows NFS / NTFS. Filename collision attacks become possible. |
| [F-5.8](../info-disclosure/F-5.8-auth-none-metadata-leak.md) | AUTH_NONE Metadata Leak | GETATTR with AUTH_NONE on a valid handle leaks attributes. Automounter exemption (RFC 2623 Section 2.3.2). |
| [F-5.9](../info-disclosure/F-5.9-read-if-exec-content-disclosure.md) | Execute-Only Disclosure | `nfsd_permission()` retries READ with MAY_EXEC when MAY_READ fails. Execute-only files become readable. |
| F-5.11 | No Link/Symlink Support | FSINFO properties field lacks FSF3_LINK or FSF3_SYMLINK. Narrows attack surface (F-4.4 inapplicable). |
| F-5.16 | Silly-Rename Detection | `.nfs*` filenames in READDIRPLUS indicate active open-unlinked state and NFS client activity. |
| [F-3.8](../network/F-3.8-rpc-with-tls.md) | RPC-with-TLS Supported | Informational. TLS encrypts the wire but AUTH_SYS inside TLS still allows UID forgery. |
| [F-3.9](../network/F-3.9-auth-short-session-credentials.md) | AUTH_SHORT Session | Informational. Linux knfsd never issues AUTH_SHORT. Relevant only for non-Linux implementations. |
| [F-7.7](../config/F-7.7-freebsd-truncated-subnet.md) | FreeBSD-Style Truncated Subnet | Export ACL entries using 2-3 octet dotted notation (e.g., `10.0.1`) fingerprint a FreeBSD NFS server. |

## Protocol-specific exploitation notes

### READDIRPLUS is the primary harvesting tool

NFSv3's READDIRPLUS (procedure 17) is the single most powerful reconnaissance operation in the protocol. One call returns the file handle, full fattr3 attributes (uid, gid, mode, size, timestamps), and filename for every entry in a directory. This means a single RPC round-trip harvests bearer tokens for every file in a directory without triggering per-file access checks. The `shell ls` and `shell find` commands use READDIRPLUS internally. The credential ladder's `observed_identities()` function parses READDIRPLUS results to rank UIDs and GIDs by frequency for targeted escalation.

### The STALE/BADHANDLE oracle

NFSv3 distinguishes two handle-rejection errors: `NFS3ERR_STALE` (70) means the handle format is correct but the inode or generation is wrong; `NFS3ERR_BADHANDLE` (10001) means the handle format itself is unrecognized. This distinction is an oracle for brute-force attacks (F-2.2): once an attacker gets STALE instead of BADHANDLE, they know the filesystem type and handle layout are correct and only need to enumerate inodes.

### Post-operation attributes leak metadata

RFC 1813 "strongly encourages" servers to return fattr3 in failure responses. Linux knfsd always does. This means access-denied responses (NFS3ERR_ACCES, NFS3ERR_PERM) still reveal the target file's uid, gid, mode, size, and timestamps -- enough to identify high-value targets and feed the credential ladder without ever successfully reading a file.
