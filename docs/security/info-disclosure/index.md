# Information disclosure (F-5.x)

Data leakage findings. NFS and its supporting RPC services expose a remarkable amount of information without authentication: export topology, file metadata, user activity, server configuration, and filesystem internals. Most of this leakage is by design: the RFCs specify unauthenticated access to service directories, export lists, and file attributes.

These findings range from low-severity reconnaissance aids to high-severity harvesting of bearer tokens (file handles) and credential material. Individually, most are informational. Combined, they give an attacker a complete map of the target before any exploitation begins.

## Summary

| Finding | Title | Severity | RFC Basis | Detected by | Write-up |
|---------|-------|----------|-----------|-------------|----------|
| F-5.1 | Export List Enumeration | :material-information:{ .medium } Medium | RFC 1094 Appendix A | `scan`, `analyze` | [Detail](F-5.1-export-list-enumeration.md) |
| F-5.2 | READDIRPLUS File Handle Harvesting | :material-alert:{ .high } High | RFC 1813 sec 3.3.17 | `shell ls`, `mount` | [Detail](F-5.2-readdirplus-handle-harvesting.md) |
| F-5.3 | NIS Credential Extraction | :material-alert:{ .high } High | Programs 100004/100007 | `scan`, `analyze` | [Detail](F-5.3-nis-credential-extraction.md) |
| F-5.4 | RPC Service Enumeration | :material-information-outline:{ .low } Low | RFC 1057 Appendix A | `scan` | [Detail](F-5.4-rpc-service-enumeration.md) |
| F-5.5 | NFSv4 Pseudo-FS Structure Leakage | :material-information-outline:{ .low } Low | RFC 7530 sec 7.8 | `scan` | [Detail](F-5.5-nfsv4-pseudo-fs-leakage.md) |
| F-5.6 | Metadata Disclosed on Access Denial | :material-information-outline:{ .low } Low | RFC 1813 sec 3.3 | `analyze` | [Detail](F-5.6-metadata-on-access-denial.md) |
| F-5.7 | Case-Insensitive Filesystem Detection | :material-information-outline:{ .low } Low | RFC 1813 sec 3.3.20 | `analyze` | [Detail](F-5.7-case-insensitive-fs.md) |
| F-5.8 | Export Root Attributes via AUTH_NONE | :material-information-outline:{ .low } Low | RFC 2623 sec 2.3.2 | `analyze` | [Detail](F-5.8-auth-none-metadata-leak.md) |
| F-5.9 | Execute-Only File Content Disclosure | :material-information-outline:{ .low } Low | Implementation-specific | `analyze` | [Detail](F-5.9-read-if-exec-content-disclosure.md) |
| F-5.10 | Solaris NFS Server Detected (time_delta fingerprint) | :material-information-outline:{ .info } Info | RFC 1813 sec 3.3.20 | `analyze` | [Detail](F-5.10-solaris-time-delta-fingerprint.md) |
| F-5.11 | Filesystem Lacks Link/Symlink Support | :material-information-outline:{ .info } Info | RFC 1813 sec 3.3.20 | `analyze` | [Detail](F-5.11-filesystem-lacks-link-symlink.md) |
| F-5.12 | Near Inode Exhaustion (DoS Risk) | :material-information:{ .medium } Medium | RFC 1813 sec 3.3.18 | `analyze` | [Detail](F-5.12-near-inode-exhaustion.md) |
| F-5.13 | NFSv4 Named Attributes Exposed | :material-information-outline:{ .info } Info | RFC 7530 sec 5.3 | `analyze` | [Detail](F-5.13-nfsv4-named-attributes-exposed.md) |
| F-5.14 | POSIX ACL Entries Expose Access | :material-information:{ .medium } Medium | NFS_ACL program 100227 | `analyze` | [Detail](F-5.14-posix-acl-entries.md) |
| F-5.15 | rquotad Exposes UID Activity | :material-information:{ .medium } Medium | Program 100011 | `analyze` | [Detail](F-5.15-rquotad-uid-oracle.md) |
| F-5.16 | Silly-Rename Files Detected | :material-information-outline:{ .info } Info | Implementation-specific | `analyze` | [Detail](F-5.16-silly-rename-detected.md) |
| F-5.17 | Write Verifier Changed (Reboot Detected) | :material-information:{ .medium } Medium | RFC 1813 sec 3.3.21 | `analyze` | [Detail](F-5.17-write-verifier-changed.md) |

## Reconnaissance findings

These findings provide the attacker's initial map of the target. They require no credentials and no prior access, just network reachability to port 111 or 2049.

### F-5.1: Export List Enumeration

The MOUNT protocol's EXPORT procedure returns every exported path and its ACL without authentication. RFC 1094 Appendix A defines this as an open directory listing. This is the first step in any NFS attack: it tells the attacker what filesystems are available and who is allowed to mount them.

**Detection**: `nfswolf scan` calls MNTPROC_EXPORT on every reachable mountd.

### F-5.4: RPC Service Enumeration

The portmapper DUMP procedure (RFC 1057 Appendix A) returns every registered RPC service: program number, version, protocol, and port. No authentication required. This reveals NFS versions, mountd ports, NLM, NIS, rquotad, and any other RPC service on the host.

**Detection**: `nfswolf scan` issues PMAPPROC_DUMP and decodes program numbers against the IANA registry (1251 entries).

### F-5.5: NFSv4 Pseudo-Filesystem Structure Leakage

The NFSv4 pseudo-filesystem (RFC 7530 sec 7.3) connects all exports under a shared namespace. READDIR from the pseudo-root reveals the names and paths of all exports, including IP-restricted ones that the client is not authorized to access. The RFC says servers SHOULD hide these, but "SHOULD" is not "MUST."

**Detection**: `nfswolf scan` performs PUTROOTFH + READDIR via `Nfs4DirectClient` to enumerate the pseudo-FS tree.

### F-5.15: rquotad Exposes UID Activity via Quota Queries

rquotad (program 100011) returns per-UID disk usage without authentication. GETQUOTA for a specific UID reveals whether that UID has disk activity (non-zero block and file counts), confirming UID existence on the server. The `bsize` field leaks the filesystem block size (ext4=4096, XFS=512, ZFS=1024), narrowing escape strategy.

**Detection**: `nfswolf analyze` resolves rquotad via portmapper GETPORT, then probes UIDs 0, 1000, and 65534.

## Credential and handle harvesting

These findings provide material for active exploitation: bearer tokens, user identities, and authentication weaknesses.

### F-5.2: READDIRPLUS File Handle Harvesting

!!! warning "High: mass bearer token disclosure"
    A single READDIRPLUS call returns the file handle (bearer token) for every entry in a directory. Each handle grants permanent access to that file from any IP address (F-2.7), regardless of subsequent permission changes.

RFC 1813 sec 3.3.17: READDIRPLUS returns "name, fileid, attributes (including the fileid), and file handle" for every directory entry. No per-file access check occurs during listing; directory read permission is sufficient to harvest handles for all children.

### F-5.3: NIS Credential Extraction

!!! warning "High: password hash disclosure"
    When NIS (ypserv, programs 100004/100007) is co-hosted with NFS, `ypcat passwd.byname` dumps password hashes without authentication. Common on legacy Solaris and RHEL systems.

NIS is discovered via the same portmapper scan that finds NFS. Its presence on an NFS server is a strong indicator of a legacy environment with weak security boundaries.

### F-5.14: POSIX ACL Entries Expose Access Beyond Mode Bits

The NFS_ACL sideband protocol (program 100227) returns POSIX ACL entries that grant access to specific UIDs/GIDs invisible to standard mode-bit analysis. Named USER and GROUP ACL entries reveal access paths that `ls -l` does not show, feeding the credential ladder for targeted escalation.

**Detection**: `nfswolf analyze` calls NFSACL_GETACL on the export root.

## Server fingerprinting

These findings narrow the attack surface by revealing server characteristics: filesystem type, OS, kernel behavior, and configuration.

### F-5.6: Metadata Disclosed on Access Denial

RFC 1813 "strongly encourages" servers to return file attributes even on access denial. Linux knfsd always returns `post_op_attr` on NFS3ERR_ACCES and NFS3ERR_PERM, disclosing uid, gid, mode, and size of files the caller cannot read. On NFSv4, `NFS4_ANYONE_MODE` unconditionally includes `READ_ATTRIBUTES` in every ALLOW ACE, so even `mode 0000` files leak their attributes.

### F-5.7: Case-Insensitive Filesystem Detection

PATHCONF `case_insensitive=true` indicates a Windows NFS server or NetApp NTFS volume. Case-insensitive lookups enable filename collision attacks and narrow the target OS to Windows or a CIFS-backed NAS.

### F-5.8: Export Root Attributes Leaked via AUTH_NONE

RFC 2623 sec 2.3.2 permits AUTH_NONE for GETATTR to support automounters. This leaks uid, gid, mode, size, and timestamps of the export root to any unauthenticated client with a valid file handle.

### F-5.9: Execute-Only File Content Disclosure

Linux knfsd's `nfsd_permission()` retries denied READ requests with `MAY_EXEC` when `NFSD_MAY_READ_IF_EXEC` is set. Files with execute permission but no read permission (mode 0111) are readable over NFS. Limited practical impact, as few files use execute-only permissions.

### F-5.11: Filesystem Lacks Link/Symlink Support

FSINFO `properties` field (RFC 1813 sec 3.3.20) reports whether the filesystem supports hard links (`FSF3_LINK`) and symbolic links (`FSF3_SYMLINK`). When absent, symlink escape (F-4.4) and hardlink attacks are inapplicable. Informational; narrows the effective attack surface.

### F-5.16: Silly-Rename Files Detected

Filenames matching `.nfs*` in directory listings indicate NFS silly-rename state, where files were deleted by one client while still open by another. Their presence confirms the export is actively used and the silly-rename files may contain sensitive data that the deleting application expected to be gone.

## Operational intelligence

### F-5.10: Solaris NFS Server Detected (time_delta Fingerprint)

FSINFO `time_delta` of `{0, 1000}` (microsecond granularity) is characteristic of Solaris NFS servers. Linux knfsd uses nanosecond granularity (`{0, 1}`). This passive OS fingerprint adjusts the escape strategy because Solaris NFS file handle formats differ from Linux.

**Detection**: `nfswolf analyze` calls FSINFO on the export root and compares `time_delta` against known OS fingerprints.

### F-5.12: Near Inode Exhaustion (DoS Risk)

FSSTAT (RFC 1813 sec 3.3.18) reports total, free, and available file slots. When fewer than 1000 inodes remain, an attacker with write access can exhaust capacity to deny file creation for all users.

### F-5.13: NFSv4 Named Attributes Exposed on Export Root

OPENATTR + READDIR on the export root enumerates extended attributes. These may carry POSIX ACLs (`system.posix_acl_access`), SELinux labels (`security.selinux`), file capabilities (`security.capability`), or application-specific metadata, revealing the MAC/DAC enforcement posture.

### F-5.17: Write Verifier Changed Between Probes (Server Reboot Detected)

The `writeverf3` value returned by COMMIT (RFC 1813 sec 3.3.21) changes on server reboot. Two COMMIT calls with different verifiers prove the NFS service restarted, which means NLM lock state was reset, unstable writes may have been lost, and an NFSv4 grace period is active. For an attacker, this signals that stale handles may be invalidated and the credential cache needs re-validation.

## Mitigation

| Defense | Findings mitigated | Notes |
|---------|--------------------|-------|
| Firewall port 111 | F-5.1, F-5.4, F-5.15 | Blocks portmapper, mountd, and rquotad enumeration from external networks |
| `sec=krb5` | F-5.2, F-5.6, F-5.8 | Prevents unauthenticated metadata access; handles still leak via READDIRPLUS to authenticated users |
| Remove NIS | F-5.3 | NIS is fundamentally unauthenticated; migrate to LDAP/Kerberos |
| NFSv4-only | F-5.1, F-5.4 | Eliminates MOUNT and portmapper; pseudo-FS leakage (F-5.5) remains |
| `subtree_check` | F-5.2 | Limits handle reuse to the exported subtree (performance cost) |
