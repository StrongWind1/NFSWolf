# Configuration weaknesses (F-7.x)

Server misconfiguration findings. These are not protocol vulnerabilities; the NFS protocol works as designed. The problem is that the default and common configurations leave security gaps that attackers exploit. Several of these weaknesses are invisible to remote probing (client-side mount options, audit logging) and are documented for defender awareness rather than automated detection.

## Summary

| Finding | Title | Severity | RFC Basis | Detected by | Write-up |
|---------|-------|----------|-----------|-------------|----------|
| F-7.1 | Wildcard/Broad Subnet Exports | :material-alert:{ .high } High | RFC 2623 sec 2.6 | `scan`, `analyze` | [Detail](F-7.1-wildcard-export-policy.md) |
| F-7.2 | `insecure` Export Option | :material-information:{ .medium } Medium | RFC 2623 sec 2.1 | Detection gap | [Detail](F-7.2-privileged-port-bypass.md) |
| F-7.3 | `nohide`/`crossmnt` Sub-Mount Exposure | :material-information:{ .medium } Medium | RFC 1813 sec 3.3.3 | `analyze` | [Detail](F-7.3-nohide-crossmnt-exposure.md) |
| F-7.4 | Missing `nosuid`/`nodev` on Client Mount | :material-alert:{ .high } High | RFC 1094 sec 2.3.5 | Not detectable | [Detail](F-7.4-missing-nosuid-nodev.md) |
| F-7.5 | `all_squash` with `anonuid=0` | :material-alert-circle:{ .critical } Critical | RFC 1813 sec 4.4 | `analyze` | [Detail](F-7.5-squash-misconfiguration.md) |
| F-7.6 | Absence of Audit Logging | :material-information:{ .medium } Medium | Implementation-specific | Not detectable | [Detail](F-7.6-no-audit-logging.md) |
| F-7.7 | FreeBSD-Style Truncated Subnet in Export ACL | :material-information-outline:{ .info } Info | Implementation-specific | `analyze` | [Detail](F-7.7-xprtsec-permissive-default.md) |

## Findings

### F-7.1: Wildcard/Broad Subnet Exports

!!! warning "High -- no access control"
    Exports with `*` or broad subnet ACLs (e.g., `/24` or larger) are accessible to any host on the network. Host-based access control, which is the primary authorization mechanism for NFS (RFC 2623 sec 2.6), is effectively disabled.

The MOUNT protocol's EXPORT response includes the ACL for each export path. nfswolf parses this list and flags exports that use wildcards (`*`), broad CIDR ranges, or no restriction at all. Combined with AUTH_SYS credential forging (F-1.1), a wildcard export gives any network-reachable attacker full access to the exported filesystem.

Common patterns that trigger this finding:

- `/export *(rw,no_root_squash)`: world-writable with root access
- `/data 10.0.0.0/8(rw)`: any host on the /8 has write access
- `/home (rw)`: missing host specifier defaults to world-accessible on some implementations

**Detection**: `nfswolf scan` and `nfswolf analyze` parse the MNTPROC_EXPORT ACL and flag wildcard or broad subnet entries.

---

### F-7.2: `insecure` Export Option (Unprivileged Ports)

By default, Linux knfsd requires NFS clients to connect from a privileged source port (below 1024). The `insecure` export option removes this check, allowing any unprivileged process to connect without root on the attacker's machine.

RFC 2623 sec 2.1 acknowledges that privileged-port checking is "at best an inconvenience" because any root user can bind a low port. The real consequence of `insecure` is lowering the barrier from "attacker needs root somewhere" to "attacker needs any user account."

!!! note "Detection gap"
    The previous `analyze` probe for this finding was removed because it was tautological: MNTPROC_EXPORT itself is not source-port gated, so the probe always reported `insecure` even on secure servers. A sound test requires attempting MNT from an unprivileged source port, which is not yet implemented.

---

### F-7.3: `nohide`/`crossmnt` Sub-Mount Exposure

RFC 1813 sec 3.3.3 states "A server will not allow a LOOKUP operation to cross a mountpoint." The `nohide` and `crossmnt` export options override this boundary, exposing sub-mounted filesystems that may contain more sensitive data than the parent export.

For example, if `/export` is exported with `crossmnt` and `/export/secrets` is a separate filesystem mounted inside it, a client mounting `/export` automatically sees the contents of `/export/secrets` without a separate MOUNT request, bypassing any ACL that might restrict who can mount `/export/secrets` directly.

**Detection**: `nfswolf analyze` performs LOOKUP traversal from the export root to detect crossmnt behavior (the server allows traversal across filesystem boundaries).

---

### F-7.4: Missing `nosuid`/`nodev` on Client Mount

!!! warning "High -- enables F-4.2 and F-4.3"
    Without `nosuid`, SUID binaries planted by an attacker (F-4.2) are executable with elevated privileges. Without `nodev`, device nodes planted by an attacker (F-4.3) provide raw hardware access. These are client-side mount options that the NFS server cannot enforce or verify.

This is a documented gap in nfswolf's detection capability. The `nosuid` and `nodev` flags are client-side mount options that do not appear in MNTPROC_EXPORT output or any server-side query. The server has no mechanism to require clients to mount with these options.

!!! info "Not remotely detectable"
    `nfswolf analyze` cannot detect this finding because the information is not exposed by any NFS protocol operation. Defenders must audit client `/etc/fstab` entries and active mounts directly.

---

### F-7.5: `all_squash` with `anonuid=0`

!!! danger "Critical -- worse than no_root_squash"
    `all_squash` maps every client UID to the anonymous UID. When `anonuid=0`, every client operation runs as root, regardless of what UID the client claims. This is strictly worse than `no_root_squash` because the attacker does not even need to forge UID 0; any credential works.

The administrator's intent with `all_squash` is usually to restrict access by mapping all clients to a low-privilege account. Setting `anonuid=0` inverts this completely. Every file read, write, and attribute change operates with full root authority.

**Detection**: `nfswolf analyze` performs a squash probe: it creates a test file with a non-root UID and checks whether the resulting ownership is root. If `all_squash` is active and `anonuid=0`, the file is owned by root regardless of the client's claimed UID.

---

### F-7.6: Absence of Audit Logging

The Linux NFS kernel server (knfsd) processes file operations in kernel space, bypassing the `auditd` framework entirely. No file access audit records are generated for NFS operations, regardless of audit rules configured on the server. All NFS attacks (credential forging, export escape, file exfiltration) operate in a detection blind spot.

This is a fundamental limitation of knfsd's architecture: the VFS operations occur in the `nfsd` kernel thread context, which does not pass through the audit hooks that `open()`, `read()`, and `write()` system calls traverse.

!!! info "Not remotely detectable"
    This is an operational gap, not a protocol-level finding. nfswolf cannot detect it remotely. Defenders should be aware that standard Linux auditing does not cover NFS file access and should implement compensating controls (network-level monitoring, NFS-specific logging via `rpcdebug`, or sidecar file integrity monitoring).

---

### F-7.7: FreeBSD-Style Truncated Subnet in Export ACL

Export ACL entries with 2-3 octet dotted notation (e.g., `10.0` or `10.0.1`) without an explicit netmask are characteristic of FreeBSD NFS servers. This truncated subnet notation is an OS fingerprint. The intended access scope may not match the implied CIDR, potentially admitting more hosts than intended.

**Detection**: `nfswolf analyze` parses the MOUNT EXPORT ACL entries and flags those matching the truncated subnet pattern.

## Detection coverage

Not all configuration weaknesses are remotely detectable. The following table summarizes what nfswolf can and cannot probe:

| Finding | Remotely detectable? | Why / why not |
|---------|---------------------|---------------|
| F-7.1 | Yes | MNTPROC_EXPORT returns the ACL |
| F-7.2 | Partially | Requires MNT from unprivileged port (not yet implemented) |
| F-7.3 | Yes | LOOKUP traversal crosses filesystem boundaries |
| F-7.4 | No | Client-side mount option, not exposed by any server protocol |
| F-7.5 | Yes | Squash probe (create file, check ownership) |
| F-7.6 | No | Kernel architecture limitation, not a protocol attribute |
| F-7.7 | Yes | MNTPROC_EXPORT ACL pattern matching for truncated subnets |

## Mitigation

| Defense | Findings mitigated | Configuration |
|---------|--------------------|---------------|
| Narrow export ACLs | F-7.1 | Use specific IPs or `/32` entries instead of wildcards |
| Remove `insecure` | F-7.2 | Default is `secure` (privileged ports only) |
| Avoid `crossmnt`/`nohide` | F-7.3 | Export each filesystem separately with its own ACL |
| Client `nosuid,nodev` | F-7.4 | Add to `/etc/fstab` NFS entries; server cannot enforce |
| Never set `anonuid=0` | F-7.5 | Use a dedicated low-privilege UID for anonymous mapping |
| Network-level NFS monitoring | F-7.6 | `rpcdebug -m nfsd -s all`, or network tap with NFS protocol decoder |
| Use explicit CIDR notation in export ACLs | F-7.7 | Replace truncated subnets with full IP/mask (e.g., `10.0.1.0/24` not `10.0.1`) |
| `sec=krb5` on all exports | All | Prevents credential forging, making most configuration weaknesses unexploitable |
