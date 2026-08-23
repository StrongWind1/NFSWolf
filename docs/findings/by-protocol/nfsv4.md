# NFSv4 findings

NFSv4 (RFC 7530) was designed to address many of the security shortcomings of NFSv2 and NFSv3. It eliminates the separate MOUNT and portmapper protocols, introduces SECINFO for per-directory security flavor negotiation, and defines a pseudo-filesystem that replaces the unauthenticated EXPORT list. These are real improvements. But NFSv4 does not fix the fundamental problems: AUTH_SYS is still allowed by default, file handles are still bearer tokens, and the LOOKUPP operation introduces a new escape path that requires zero protocol sophistication.

This page categorizes findings into three groups: those NFSv4 mitigates or eliminates, those that persist unchanged, and those that are new to NFSv4.

## Findings NFSv4 mitigates

These findings are reduced in severity or eliminated when a server is configured as NFSv4-only with proper security flavors.

| Finding | Name | Severity | How NFSv4 Helps |
|---------|------|----------|-----------------|
| [F-1.6](../identity/F-1.6-nfsv2-downgrade.md) | NFSv2 Downgrade | High | Eliminated if v2/v3 are disabled. NFSv4 has SECINFO for flavor negotiation, so the "no way to signal krb5 requirement" problem disappears. Only relevant if the server also exposes v2. |
| [F-3.2](../network/F-3.2-portmapper-amplification.md) | Portmapper Amplification | Medium | NFSv4 does not use the portmapper. It runs on a fixed port (2049). If portmapper is disabled entirely, this finding is eliminated. |
| [F-3.5](../network/F-3.5-portmapper-tunnel-bypass.md) | Filtered Portmapper Bypass | Medium | No portmapper dependency means no portmapper to bypass. NFSv4 connects directly to 2049. |
| [F-5.1](../info-disclosure/F-5.1-export-list-enumeration.md) | Export List Enumeration | Medium | MNTPROC_EXPORT is a MOUNT protocol operation. NFSv4 replaces it with pseudo-FS browsing (F-5.5), which is slightly harder to enumerate but still leaks export names. |
| [F-5.2](../info-disclosure/F-5.2-readdirplus-handle-harvesting.md) | READDIRPLUS Harvesting | High | NFSv4 READDIR can return file handles via GETFH in a COMPOUND, but this requires an explicit attribute request. The implicit handle return of NFSv3 READDIRPLUS does not exist. Practical impact is minimal, since an attacker simply includes GETFH in the COMPOUND. |
| [F-3.6](../network/F-3.6-udp-mount-handle-theft.md) | UDP MOUNT Handle Theft | Critical | NFSv4 does not use the MOUNT protocol at all. No mountd listener means no UDP handle theft. Eliminated if v3 is disabled. |

## Findings that persist in NFSv4

These findings apply to NFSv4 with the same severity as v3. The protocol changes do not address the underlying vulnerability.

| Finding | Name | Severity | Why NFSv4 Does Not Help |
|---------|------|----------|------------------------|
| [F-1.1](../identity/F-1.1-uid-gid-spoofing.md) | UID/GID Spoofing | Critical | AUTH_SYS is still the default authentication mechanism on most NFSv4 deployments. The SECINFO operation can signal that krb5 is required, but only if the administrator configures it. Default configurations accept AUTH_SYS. |
| [F-1.2](../identity/F-1.2-root-squash-bypass.md) | Root Squash Bypass | High | root_squash behavior is identical in v4. UID 0 is mapped to nobody; every other UID is trusted without verification. |
| [F-1.3](../identity/F-1.3-auxiliary-group-injection.md) | Auxiliary Group Injection | High | The AUTH_SYS `gids<16>` array is still client-asserted in v4. Including the shadow group GID grants group-read access. |
| [F-1.4](../identity/F-1.4-machine-name-spoofing.md) | Machine Name Spoofing | Low | The `machinename` field in AUTH_SYS is still unverified. Log poisoning works the same way. |
| [F-1.5](../identity/F-1.5-credential-replay.md) | Credential Replay | High | AUTH_SYS over NFSv4 has no nonce or sequence number. Captured RPCs are replayable. NFSv4.1 sessions with RPCSEC_GSS address this, but v4.0 with AUTH_SYS does not. |
| [F-1.7](../identity/F-1.7-rpcsec-gss-flavor-downgrade.md) | RPCSEC_GSS Flavor Downgrade | High | SECINFO may advertise both AUTH_SYS and krb5. A client freely chooses AUTH_SYS. Identical to the v3 MOUNT auth_flavors problem. |
| [F-1.8](../identity/F-1.8-auth-tooweak-kerberos-enforced.md) | AUTH_TOOWEAK Oracle | High | NFSv4 returns NFS4ERR_WRONGSEC when AUTH_SYS is used against a krb5-only export. This confirms the export exists and requires Kerberos, an information leak that helps the attacker enumerate security policies. |
| [F-2.7](../access-control/F-2.7-nfsd-acl-blindness.md) | NFS Daemon ACL Blindness | Critical | File handles in NFSv4 are still bearer tokens. The kernel checks `(client_auth_domain, fsid)` in the export cache, not whether the client was authorized to receive the specific handle. `shell --handle <hex>` works over NFSv4. |
| [F-3.1](../network/F-3.1-plaintext-wire-protocol.md) | Plaintext Traffic | High | NFSv4 does not mandate encryption. Default deployments run in cleartext on port 2049. krb5p or RPC-with-TLS must be explicitly configured. |
| [F-3.3](../network/F-3.3-ip-spoofing-host-trust.md) | IP Spoofing | High | NFSv4 export ACLs still rely on source IP when AUTH_SYS is in use. |
| [F-4.1](../privesc/F-4.1-no-root-squash.md) | no_root_squash | Critical | Export squash options apply identically to v4. uid=0 gets full root access with `CAP_MAC_OVERRIDE`. |
| [F-4.2](../privesc/F-4.2-suid-sgid-escalation.md) | SUID/SGID Creation | High | NFSv4 SETATTR can set mode bits including SUID. Same attack, different RPC encoding. |
| [F-4.4](../privesc/F-4.4-symlink-escape.md) | Symlink Escape | High | NFSv4 SYMLINK creates symlinks with unvalidated targets. Applications following them can be directed outside the export. |
| [F-7.1](../config/F-7.1-wildcard-export-policy.md) | Wildcard Exports | High | Export ACL wildcards apply to v4 the same as v3. |

## Findings new to NFSv4

These findings are specific to NFSv4 or are new attack surfaces introduced by the protocol.

| Finding | Name | Severity | NFSv4-Specific Detail |
|---------|------|----------|-----------------------|
| [F-2.11](../access-control/F-2.11-nfsv4-lookupp-export-escape.md) | LOOKUPP Export Escape | Critical | LOOKUPP returns the parent directory of any file handle. From a subdirectory export, a single `cd ..` reaches the filesystem root. No handle construction, no filesystem fingerprinting, no brute force. This is the v4 equivalent of F-2.1 but requires zero sophistication. |
| [F-2.12](../access-control/F-2.12-nfsv4-lookupp-cross-export-lateral.md) | LOOKUPP Cross-Export Lateral | High | From any export, LOOKUPP to the pseudo-FS parent and LOOKUP into sibling exports. Bypasses MOUNT-level IP ACLs entirely because NFSv4 does not use MOUNT. The `exports` shell command enumerates reachable siblings. |
| [F-5.5](../info-disclosure/F-5.5-nfsv4-pseudo-fs-leakage.md) | Pseudo-FS Structure Leakage | Low | The pseudo-filesystem connects all exports under a shared namespace. READDIR from PUTROOTFH reveals the names and structure of all exports, including IP-restricted ones. Replaces F-5.1 (MOUNT EXPORT) with a harder-to-firewall equivalent. |
| F-5.13 | Named Attributes Exposed | Low | OPENATTR + READDIR on the export root enumerates xattrs: POSIX ACLs, SELinux labels, file capabilities. Reveals the MAC/DAC enforcement posture. |
| [F-3.7](../network/F-3.7-auth-dh-obsolete.md) | AUTH_DH in SECINFO | Medium | NFSv4 SECINFO can advertise AUTH_DH (flavor 3). The 192-bit DH + 56-bit DES is trivially breakable. |

## Protocol-specific exploitation notes

### LOOKUPP is the simplest escape

LOOKUPP returns the parent directory of any filehandle, making export escape a single `cd ..` with no handle construction or fingerprinting needed. The pseudo-root boundary limits traversal across filesystem boundaries, but within any individual filesystem the escape is complete. See [F-2.11](../access-control/F-2.11-nfsv4-lookupp-export-escape.md) for the full technical detail and confirmed filesystem types.

### SECINFO is reconnaissance, not defense

SECINFO (RFC 7530 Section 16.29) returns the list of security flavors a directory accepts. Administrators intend this to enforce krb5 requirements. Attackers use it as reconnaissance: SECINFO reveals per-directory security policies, identifies which exports require Kerberos (helping prioritize softer targets), and exposes whether AUTH_SYS is accepted alongside krb5 (F-1.7). nfswolf's scanner probes SECINFO on every discovered NFSv4 export.

### No MOUNT protocol means no MOUNT ACLs

NFSv4 does not use the MOUNT protocol. This eliminates one layer of access control (the MOUNT server's host-based ACL) but also eliminates the MOUNT-specific findings (F-5.1 export enumeration via MNTPROC_EXPORT, F-3.6 UDP handle theft). The trade-off is that NFSv4's pseudo-FS discovery (F-5.5) and LOOKUPP lateral movement (F-2.12) replace these attack surfaces with protocol-native equivalents that cannot be mitigated by firewalling a separate mountd port.

### Stateful operations and session infrastructure

NFSv4 introduces stateful operations (OPEN, CLOSE, LOCK) with stateids, client IDs, and lease renewal. While nfswolf's `Nfs4Client` handles all of this transparently (SETCLIENTID lifecycle, open-owner sequencing, lock-owner management), the stateful infrastructure does not add security against AUTH_SYS attacks. Stateids are per-client-session, not per-credential, so an attacker who establishes a session can change AUTH_SYS credentials mid-session and reuse existing stateids.

The COMPOUND operation model (RFC 7530 Section 14) batches multiple operations into a single RPC call. This is more efficient than v3's one-operation-per-RPC model, but it also means a single forged RPC call can perform an entire attack chain: PUTROOTFH + LOOKUP + GETFH + GETATTR + READ in one round trip. The atomicity of COMPOUND does not provide security; it provides efficiency for both legitimate clients and attackers.

### NFSv4 credential escalation in nfswolf

Credential escalation in the NFSv4 shell works via `try_with_escalation()`, the same shared mechanism used by v3. The credential ladder (owner-first, group match, root, observed identities, service accounts) operates identically. The difference is in the transport: v4 changes credentials mid-session by swapping the AUTH_SYS fields in subsequent COMPOUND calls, while v3 uses the pooled transport's credential swap. Both are transparent to the shell user; the `uid`, `gid`, and `impersonate` commands work the same way across all three NFS versions.

### NFSv4-only servers

A server configured as NFSv4-only (no v2/v3, no portmapper, no mountd) has a significantly reduced attack surface. The portmapper, MOUNT, and version-downgrade findings are eliminated entirely. The remaining attack surface is: AUTH_SYS credential forgery (if krb5 is not enforced), LOOKUPP escape (if subdirectory exports exist), pseudo-FS enumeration, and the standard file handle bearer-token property. This is still enough for full filesystem compromise from a single wildcard export with AUTH_SYS, but it removes the easiest reconnaissance paths.
