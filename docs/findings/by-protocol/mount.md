# MOUNT protocol findings

The MOUNT protocol (RFC 1094 Appendix A, RFC 1813 Appendix I) is the gatekeeper for NFSv2 and NFSv3. Before a client can access an export, it must call the MOUNT daemon to obtain a root file handle. MOUNT also provides unauthenticated export enumeration and client tracking. Despite being the only access-control gate in the v2/v3 architecture, MOUNT has fundamental weaknesses: it issues permanent bearer tokens with no binding or expiry, its export list is world-readable, and its client tracking is advisory-only. NFSv4 eliminates the MOUNT protocol entirely, but any server exposing v2 or v3 alongside v4 still runs a MOUNT daemon.

## Applicable findings

| Finding | Name | Severity | MOUNT-Specific Detail |
|---------|------|----------|-----------------------|
| [F-2.1](../access-control/F-2.1-export-escape.md) | Export Escape (Seed Handle) | Critical | MOUNT's MNT procedure provides the seed file handle that makes export escape possible. The root handle returned by MNT contains the filesystem ID (fsid) needed to construct handles for other inodes on the same filesystem. Without MOUNT, the attacker needs an alternative handle source (NFSv4 PUTROOTFH, `--handle` flag, or WebNFS). |
| [F-1.6](../identity/F-1.6-nfsv2-downgrade.md) | MOUNT v1 Handle Leak | High | MOUNT v1 (used by NFSv2) returns a 32-byte `fhstatus` without an auth_flavors list. The server has no way to signal that the export requires Kerberos. On a `sec=krb5` export, MOUNT v1 leaks the root handle even though subsequent NFSv2 operations may be rejected by the kernel's krb5 enforcement. The handle, once obtained, is a permanent bearer token (F-2.7). |
| [F-5.1](../info-disclosure/F-5.1-export-list-enumeration.md) | Export List Enumeration | Medium | MNTPROC_EXPORT returns the complete export topology (paths, hostnames, allowed networks) without any authentication. RFC 1094 Appendix A Section 5.6 defines EXPORT as returning "a variable number of export list entries" with no access control. This is the primary reconnaissance step for NFS attacks. |
| [F-3.6](../network/F-3.6-udp-mount-handle-theft.md) | UDP MOUNT Handle Theft | Critical | mountd's UDP listener trusts `recvfrom()` source addresses. An attacker on the same L2 segment spoofs the allowed IP, sends a UDP MNT datagram, and receives the file handle in the reply. The handle is then usable indefinitely over TCP from any IP (F-2.7). nfswolf's scanner reports mountd UDP availability. |
| [F-2.5](../access-control/F-2.5-stale-handle-persistence.md) | UMNT Does Not Invalidate Handles | Medium | UMNT removes the client from the mount list (advisory tracking) but does NOT invalidate the file handle. RFC 1094 Appendix A states "The mount list information is not critical for the correct functioning of either the client or the server. It is intended for advisory use only." An administrator who revokes access via export ACL changes and expects UMNT to invalidate handles is mistaken; the handle remains valid indefinitely. |
| [F-1.8](../identity/F-1.8-auth-tooweak-kerberos-enforced.md) | AUTH_TOOWEAK via MOUNT | High | MOUNT MNT succeeds with AUTH_SYS even on krb5-only exports (RFC 2623 Section 2.3.2 automounter exemption). The handle is returned. Subsequent NFS operations fail with AUTH_TOOWEAK, confirming the export exists and requires Kerberos. The handle leak through MOUNT is the first step; the AUTH_TOOWEAK response is the oracle. |

## Protocol-specific exploitation notes

### MOUNT as the single gate

MOUNT is the only access-control checkpoint in the v2/v3 architecture: it issues permanent, unbound bearer tokens with no expiry or revocation. The NFS daemon never calls back to verify authorization. For a full explanation of this architectural gap and its security consequences, see the [MOUNT Protocol](../../protocols/mount.md) reference.

### EXPORT reveals the full attack surface

MNTPROC_EXPORT returns the complete export topology (paths, allowed hosts/networks) without any authentication. From it, the attacker maps wildcard exports (F-7.1), subdirectory exports vulnerable to escape (F-2.1), and sibling exports on shared filesystems (F-2.8). See [F-5.1](../info-disclosure/F-5.1-export-list-enumeration.md) and the [MOUNT Protocol EXPORT procedure](../../protocols/mount.md#procedure-5-export-list-all-exports) for details.

### MOUNT v1 vs v3 differences

| Feature | MOUNT v1 | MOUNT v3 |
|---------|----------|----------|
| Handle size | Fixed 32 bytes | Variable, up to 64 bytes |
| Auth flavors returned | No | Yes (after MNT) |
| EXPORT | Same wire format | Same wire format |
| DUMP | Same semantics | Same semantics |
| UMNTALL | Available | Available |
| Protocol number | 100005 v1 | 100005 v3 |

nfswolf's escape pipeline gathers seed handles from both MOUNT v3 and MOUNT v1. The v1 MNT path is particularly valuable against krb5-protected exports: v1 returns the handle without checking authentication flavors, while v3 MNT at least advertises the required flavors (though it still returns the handle).

### DUMP for client intelligence

MNTPROC_DUMP returns all active mount entries (client hostname/IP and export path), revealing which machines are NFS clients and what they have mounted, providing reconnaissance for credential theft and lateral movement. nfswolf retrieves DUMP from both v1 and v3 via `dump_clients_v1` and `dump_clients` in `src/proto/mount.rs`. See the [MOUNT Protocol DUMP procedure](../../protocols/mount.md#procedure-2-dump-list-active-mounts) for details.

### UMNTALL as a cleanup signal

UMNTALL removes mount list entries for operational cleanup after scanning, but since the mount list is advisory-only (F-2.5), this is purely cosmetic; handles remain valid.

### The MOUNT-to-NFS handoff gap

The handoff gap, where MOUNT issues a handle and NFS operates on it without back-checking authorization, is the root cause of F-2.7 (bearer tokens), F-2.5 (stale handles), F-2.8 (sibling lateral), and F-3.6 (UDP theft). No fix exists within the protocol; NFSv4 eliminates MOUNT but introduces its own traversal issues (F-2.11, F-2.12). See the [MOUNT Protocol](../../protocols/mount.md) reference for the full architectural analysis.

### MOUNT port discovery

The MOUNT daemon does not run on a well-known port. Its port is registered in the portmapper (program 100005) and must be looked up via PMAPPROC_GETPORT or PMAPPROC_DUMP. When the portmapper is firewalled (F-3.5), the MOUNT port must be guessed or scanned. Common mount ports include 20048 (NFS utils default), 892, and random high ports. nfswolf's `--probe-port` flag supports scanning arbitrary ports for mountd, and `--skip-mountd` bypasses MOUNT entirely when the handle is already known.

### MOUNT NULL probe for version detection

MOUNT NULL (procedure 0) is a zero-cost version probe: it accepts any auth flavor, creates no mount list entry, and confirms whether the server supports v1 (NFSv2) or v3 (NFSv3). nfswolf uses it in the scanner's Phase 1 parallel port probing.

### NFSv4 eliminates MOUNT

NFSv4 does not use the MOUNT protocol. File handles are obtained via PUTROOTFH (pseudo-FS root) or LOOKUP from a known directory. This eliminates F-5.1 (export enumeration via MNTPROC_EXPORT), F-3.6 (UDP handle theft via MNT), and the auth_flavors leak. However, any server that exposes NFSv3 or NFSv2 alongside v4 still runs a MOUNT daemon, and all MOUNT findings apply to that daemon regardless of whether the attacker ultimately operates over v4. The `scan` subcommand reports MOUNT availability even when the target is primarily a v4 server.
