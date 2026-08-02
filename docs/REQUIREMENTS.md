# Requirements Document

What nfswolf MUST detect, organized by operational phase. Every requirement traces to a finding in [FINDINGS.md](FINDINGS.md).

---

## R1: Reconnaissance (Passive Discovery)

### R1.1: Port Discovery

| Requirement | Priority | Finding |
|-------------|----------|---------|
| Detect TCP/UDP port 111 (portmapper/rpcbind) | MUST | F-5.4 |
| Detect TCP port 2049 (NFS) | MUST | -- |
| Detect mountd on ephemeral ports (scan 20048, 32768-60999) | MUST | F-3.5 |
| Detect NIS (programs 100004/100007) | SHOULD | F-5.3 |
| Report when port 111 is filtered but 2049 is open | MUST | F-3.5 |

### R1.2: Service Enumeration

| Requirement | Priority | Finding |
|-------------|----------|---------|
| Enumerate all RPC programs via PMAPPROC_DUMP | MUST | F-5.4 |
| Enumerate exports via MNTPROC_EXPORT | MUST | F-5.1 |
| Parse export ACLs (hosts/subnets/wildcards) | MUST | F-7.1 |
| Detect NFS version support (v2, v3, v4.0, v4.1, v4.2) | MUST | F-1.6 |
| Detect auth flavors per export (from MNT response) | MUST | F-1.1 |
| Enumerate connected clients (if available) | SHOULD | -- |
| Detect vendor-specific programs (NetApp 400010) | MUST | -- |
| Report security implications for sideband programs (NLM/NSM/RQUOTA/NFS_ACL/PCNFSD) | MUST | -- |

### R1.3: OS/Filesystem Fingerprinting

| Requirement | Priority | Finding |
|-------------|----------|---------|
| Fingerprint server OS from file handle structure | MUST | F-2.1 |
| Fingerprint filesystem type (ext4/xfs/btrfs/ntfs/zfs) | MUST | F-2.1 |
| Detect BTRFS fileid_type (0x4d-0x4f) for subvolume attacks | MUST | F-2.4 |
| Detect Windows NFS server (handle size/structure) | MUST | F-2.3 |
| Detect case-insensitive filesystem via PATHCONF | MUST | F-5.7 |
| Detect unrestricted chown via PATHCONF | MUST | F-4.6 |
| Analyze file handle entropy (brute-force feasibility) | SHOULD | F-2.2 |

---

## R2: Authentication Testing

### R2.1: UID/GID Spray

| Requirement | Priority | Finding |
|-------------|----------|---------|
| Test ACCESS procedure with arbitrary UID/GID combinations | MUST | F-1.1 |
| Spray UID range 0-65535 (configurable) | MUST | F-1.1 |
| Spray GID range 0-65535 (configurable) | MUST | F-1.3 |
| Test auxiliary GID combinations (up to 16 per call) | MUST | F-1.3 |
| Test well-known shadow GIDs (42, 15) | MUST | F-1.3 |
| Report all ACCESS bits per credential (READ, LOOKUP, MODIFY, EXTEND, DELETE, EXECUTE) | MUST | F-1.1 |
| Support per-credential delay for stealth | SHOULD | -- |

### R2.2: Squash Detection

| Requirement | Priority | Finding |
|-------------|----------|---------|
| Detect no_root_squash (write as uid=0, verify ownership) | MUST | F-4.1 |
| Detect all_squash (write as arbitrary uid, check if mapped to nobody) | MUST | F-7.5 |
| Detect anonuid/anongid values | MUST | F-7.5 |
| Flag anonuid=0 as critical | MUST | F-7.5 |
| Detect root_squash bypass via non-root UIDs | SHOULD | F-1.2 |

### R2.3: Port and Transport Checks

| Requirement | Priority | Finding |
|-------------|----------|---------|
| Test if server accepts connections from ports >= 1024 | ~~MUST~~ removed | F-7.2 |
| Report `insecure` export option detection | ~~MUST~~ removed | F-7.2 |
| Test UDP vs TCP availability | SHOULD | F-3.3 |
| Detect TLS support (AUTH_TLS STARTTLS probe) | MUST | F-3.8 |
| Flag AUTH_DH as cryptographically broken | MUST | F-3.7 |
| Check for DANE/TLSA records | SHOULD | F-3.4 |

---

## R3: Access Control Testing

### R3.1: Export Escape

| Requirement | Priority | Finding |
|-------------|----------|---------|
| Construct filesystem root handle (inode 2, generation 0) | MUST | F-2.1 |
| Confirm escape via READDIRPLUS child count comparison | MUST | F-2.1 |
| Support ext4, xfs, btrfs handle formats | MUST | F-2.1 |
| Construct BTRFS subvolume handles (subvol IDs 256+) | MUST | F-2.4 |
| Report escape as critical when subtree_check disabled | MUST | F-2.1 |

### R3.2: File Handle Analysis

| Requirement | Priority | Finding |
|-------------|----------|---------|
| Detect Windows NFS signing status (HMAC present/absent) | MUST | F-2.3 |
| Calculate handle entropy (randomness of variable fields) | MUST | F-2.2 |
| Estimate brute-force time based on entropy | SHOULD | F-2.2 |
| Generate handle candidates for target filesystem | SHOULD | F-2.2 |
| Detect NFS3ERR_BADHANDLE vs NFS3ERR_STALE (oracle) | MUST | F-2.2 |

### R3.3: File Access Testing

| Requirement | Priority | Finding |
|-------------|----------|---------|
| Test readability of user-specified paths with specified credentials | MUST | F-1.1 |
| Test /etc/shadow readability with shadow group GIDs | SHOULD | F-1.3 |
| Test write access per export | MUST | F-4.1 |
| Report file preview (first bytes) as evidence | MUST | F-1.1 |
| Support escape + credential combination testing | MUST | F-2.1 |

### R3.4: Symlink and Traversal

| Requirement | Priority | Finding |
|-------------|----------|---------|
| Detect writable directories (symlink attack precondition) | MUST | F-4.4 |
| Detect nohide/crossmnt (sub-mount traversal) | MUST | F-7.3 |
| Report symlink targets that point outside export | SHOULD | F-4.4 |

---

## R4: Version and Protocol Checks

### R4.1: Version Matrix

| Requirement | Priority | Finding |
|-------------|----------|---------|
| Detect NFSv2 support | MUST | F-1.6 |
| Flag v2 alongside v3/v4 as downgrade risk | MUST | F-1.6 |
| Flag v2+v3 with v3 requiring krb5 as critical bypass | MUST | F-1.6 |
| Detect NFSv4 SECINFO flavors per path | SHOULD | -- |
| Map NFSv4 pseudo-filesystem structure | SHOULD | F-5.5 |

### R4.2: Security Flavor Assessment

| Requirement | Priority | Finding |
|-------------|----------|---------|
| Report AUTH_SYS-only exports as high risk | MUST | F-1.1 |
| Detect krb5/krb5i/krb5p support | MUST | -- |
| Detect mixed-flavor exports (AUTH_SYS + krb5) | SHOULD | -- |
| Report when SECINFO results differ from MNT auth list | SHOULD | -- |

---

## R5: Exploitation Capabilities

### R5.1: File Operations (Generic)

| Requirement | Priority | Finding |
|-------------|----------|---------|
| Read arbitrary files with specified credentials | MUST | F-1.1 |
| Write arbitrary files with specified credentials | MUST | F-4.1 |
| Upload local files to remote export | MUST | F-4.2 |
| Create files with SUID/SGID bits | MUST | F-4.2 |
| Create symlinks with arbitrary targets | SHOULD | F-4.4 |
| Create device nodes (MKNOD) | SHOULD | F-4.3 |

### R5.2: Credential Control

| Requirement | Priority | Finding |
|-------------|----------|---------|
| Specify arbitrary UID/GID per operation | MUST | F-1.1 |
| Specify auxiliary GIDs (up to 16) | MUST | F-1.3 |
| Specify machine name | MUST | F-1.4 |
| Evidence-driven credential ladder (owner -> caller+owner-group -> root -> observed identities -> service accounts; mode-bit pruning when `mode & 0o007 == 0`) | MUST | F-1.1 |
| UID+GID harvest from READDIRPLUS attributes (deduplicated, ranked by frequency via `observed_identities()`) | MUST | F-1.1 |
| Fixed service-account fallback list (nobody, www-data, mysql, postgres) | SHOULD | F-1.1 |
| UID/GID brute-force as standalone subcommand (`uid-spray`, never automatic) | SHOULD | F-1.3 |
| Incremental AUTH_SYS stamps (defeat response caching) | MUST | F-1.5 |

### R5.3: Handle Control

| Requirement | Priority | Finding |
|-------------|----------|---------|
| Use constructed handle (hex input) | MUST | F-2.1 |
| Escape flag (auto-construct root handle) | MUST | F-2.1 |
| Handle-based mount (bypass MOUNT protocol) | MUST | F-2.5 |

---

## R6: Reporting

### R6.1: Output Formats

| Requirement | Priority |
|-------------|----------|
| Terminal output with severity coloring | MUST |
| JSON output (machine-readable) | MUST |
| TXT output (plain text report) | SHOULD |
| HTML report (executive summary) | SHOULD |
| CSV output (for spreadsheet analysis) | SHOULD |

### R6.2: Finding Content

| Requirement | Priority |
|-------------|----------|
| Each finding has: ID, title, severity, description | MUST |
| Each finding has: evidence (observed data) | MUST |
| Each finding has: remediation guidance | MUST |
| Each finding has: RFC reference | MUST |
| Each finding has: affected export | MUST |
| Findings are deduplicated across exports | SHOULD |
| Aggregate risk score per host | SHOULD |

---

## R7: Operational Requirements

### R7.1: Performance

| Requirement | Priority |
|-------------|----------|
| Port scanning: 10,000 hosts/minute | MUST |
| Full NFS enumeration: 1,000 hosts/minute | SHOULD |
| UID spray: configurable rate with per-credential delay | MUST |
| Concurrent connections: configurable (default 256) | MUST |
| Connection pool per (host, export, uid, gid) with health eviction | MUST |
| Circuit breaker per host (60s window, 80% transient error threshold, exponential cooldown) | MUST |

### R7.2: Stealth

| Requirement | Priority |
|-------------|----------|
| Configurable inter-request delay with jitter | MUST |
| Configurable machine name per connection | MUST |
| No kernel mount (pure userspace RPC) | MUST |
| Optional "hide" mode (immediate unmount after handle acquisition) | SHOULD |

### R7.3: Connectivity

| Requirement | Priority |
|-------------|----------|
| TCP and UDP transport | MUST |
| SOCKS5 proxy support | SHOULD |
| Direct port specification (bypass portmapper) | MUST |
| Privileged port binding (< 1024) when available | MUST |
| Fallback to unprivileged port with warning | MUST |

### R7.4: Safety

| Requirement | Priority |
|-------------|----------|
| Read-only by default (explicit --allow-write) | MUST |
| Squash probes always create a tiny test file then immediately remove it | MUST |
| no_root_squash test always creates a test directory then immediately removes it | MUST |
| Cleanup of test files on squash/write probes is unconditional, even on error paths | MUST |

---

## Non-Requirements (Explicitly Out of Scope)

| Item | Reason |
|------|--------|
| Kerberos ticket acquisition | Use `kinit` externally |
| TLS certificate management | Use system PKI |
| Packet capture / sniffing | Use tcpdump/wireshark |
| Exploit payload generation | Use msfvenom externally |
| Post-exploitation (persistence, lateral movement) | Different tool category |
| NFSv4.1/4.2 session management | v4.1+ is a future phase |
| FUSE mount for end users | Only for testing/demo |

---

## Requirement Traceability

```
FINDINGS.md (41 findings with RFC analysis)
    └── findings/ (detailed write-ups)
        └── REQUIREMENTS.md (what the tool detects)  <- you are here
            └── ARCHITECTURE.md (how it's built)
                └── src/ (implementation)
```

Every requirement traces upward to a finding in FINDINGS.md, which cites the RFC section explaining why the vulnerability exists. If a requirement cannot be traced to a documented vulnerability with RFC backing, it should not be implemented.
