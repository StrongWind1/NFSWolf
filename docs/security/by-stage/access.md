# Initial access

Initial access is the transition from network presence to file-level interaction with an NFS export. The attacker goes from knowing what exports exist (reconnaissance) to holding a valid file handle and reading directory contents. On a default NFS deployment, this transition requires no credentials, no passwords, and no exploitation of software vulnerabilities. The protocol hands over access by design.

The findings in this stage exploit two structural properties: AUTH_SYS trusts whatever identity the client claims, and file handles are bearer tokens that grant access to anyone who possesses them.

---

## Findings in this stage

| Finding | Name | Severity | nfswolf Subcommand | What It Enables |
|---------|------|----------|-------------------|----------------|
| [F-1.1](../identity/F-1.1-uid-gid-spoofing.md) | UID/GID Spoofing | Critical | `shell`, `uid-spray` | Claim any identity; server applies POSIX checks on forged UID/GID |
| [F-1.3](../identity/F-1.3-auxiliary-group-injection.md) | Auxiliary Group Injection | High | `shell`, `analyze` | Inject target GIDs (e.g., shadow group 42) into AUTH_SYS credentials |
| [F-1.8](../identity/F-1.8-auth-tooweak-kerberos-enforced.md) | AUTH_TOOWEAK Oracle | High | `analyze` | Definitively reveals whether an export requires Kerberos (MOUNT leaks handle, NFS rejects with AUTH_TOOWEAK) |
| [F-2.1](../access-control/F-2.1-export-escape.md) | Export Escape via Root Handle | Critical | `escape`, `shell escape-root` | Construct filesystem root handle to break out of the exported subdirectory |
| [F-2.5](../access-control/F-2.5-stale-handle-persistence.md) | Stale Handle After Permission Revocation | Medium | `shell --handle` | Handles remain valid indefinitely after UMNT or export ACL changes, with no revocation mechanism |
| [F-2.7](../access-control/F-2.7-nfsd-acl-blindness.md) | NFS Daemon ACL Blindness | Critical | `shell --handle` | Port 2049 never verifies the client was authorized to hold its handle |
| [F-2.9](../access-control/F-2.9-webnfs-public-handle.md) | WebNFS Public Handle | Critical | `analyze` | All-zeros handle grants immediate access without MOUNT |
| [F-7.1](../config/F-7.1-wildcard-export-policy.md) | Wildcard/Broad Subnet Exports | High | `scan`, `analyze` | Exports available to `*` or large CIDRs; any host on the network qualifies |
| [F-7.3](../config/F-7.3-nohide-crossmnt-exposure.md) | nohide/crossmnt Sub-Mount Exposure | Medium | `analyze` | `nohide`/`crossmnt` exposes sub-mounted filesystems beyond the parent export |

---

## The access sequence

A typical initial access chain against a default NFS server:

1. **MOUNT the export.** `nfswolf shell target:/export` sends MOUNT MNT, which returns the root file handle. MOUNT checks the client's IP against the export ACL, but wildcard exports (F-7.1) accept any source address. The handle is now a permanent bearer token (F-2.7).

2. **Choose an identity.** The shell defaults to `uid=0, gid=0`, but `root_squash` (the default) maps this to `nobody`. The credential ladder automatically tries the file owner's UID, then observed identities from READDIRPLUS, then common service accounts. Any non-zero UID bypasses root squash entirely (F-1.2).

3. **Read the directory.** READDIRPLUS returns file names, attributes, and handles for every entry in a single call. No per-file access check occurs at the READDIRPLUS level; the server returns handles for files the caller cannot read, trusting per-operation checks later.

4. **Access files.** With the correct UID (often discovered from file ownership in step 3), READ succeeds. If the file is world-readable, any UID works.

!!! warning "MOUNT is not a security gate"
    MOUNT checks the client's IP address against the export ACL exactly once, at mount time. It then issues a permanent bearer token (the file handle) with no binding, no MAC, no expiry, and no revocation. The `--handle` flag in nfswolf demonstrates this: `nfswolf shell target --handle <hex>` connects directly to port 2049, skipping MOUNT entirely. If the handle is valid, the server accepts it from any IP.

---

## Version-specific access paths

The initial access technique varies by NFS protocol version, but the outcome is the same: the attacker obtains a file handle and begins file operations.

**NFSv3 (default).** MOUNT MNT returns the export root handle. The server checks the client's source IP against the export ACL. If the export is wildcard (`*`) or matches the attacker's subnet, MOUNT succeeds. The returned handle is 64 bytes on most Linux servers and contains the fsid and root inode. From here, READDIRPLUS enumerates the export's contents. The handle persists indefinitely. UMNT removes the client from the mount list but does not invalidate the handle (F-2.5).

**NFSv2.** MOUNT v1 MNT returns a fixed 32-byte handle. The v2 protocol lacks READDIRPLUS, so directory enumeration requires individual LOOKUP calls per entry after READDIR provides names. NFSv2 is significant because it predates security flavor negotiation entirely (RFC 2623 Section 2.7): even exports configured with `sec=krb5` may leak their handles through MOUNT v1, because the MOUNT daemon's v1 code path does not enforce the export's security flavor. Live testing confirms this: MOUNT v1 returns the handle, but subsequent v2 NFS operations fail with AUTH_TOOWEAK if Kerberos is enforced. The handle itself, however, is valid and can be used over NFSv3 if v3 accepts AUTH_SYS.

**NFSv4.** No MOUNT protocol. The client sends PUTROOTFH to get the pseudo-root handle, then LOOKUP operations navigate the pseudo-filesystem to the export. The export's security flavor is enforced per-operation via SECINFO. NFSv4 initial access is simpler because there is no separate mount daemon to query; everything happens over a single TCP connection to port 2049.

---

## Bypassing MOUNT entirely

Three paths achieve initial access without going through MOUNT at all:

- **WebNFS (F-2.9).** The all-zeros public file handle (RFC 2055 Section 5) grants immediate access on servers with WebNFS enabled. No MOUNT call, no IP check.
- **Handle theft (F-2.7).** A handle captured from network traffic or obtained from a previous session works from any IP, with any credentials. `nfswolf shell target --handle <hex>` takes a raw hex handle and operates directly on port 2049.
- **NFSv4 (no MOUNT protocol).** NFSv4 does not use the MOUNT protocol at all. The client sends PUTROOTFH to get the pseudo-root, then LOOKUP to navigate to the export. IP-based ACLs at the MOUNT level are irrelevant.

---

## What determines success

Initial access fails only when the export requires `sec=krb5` (or stronger) and does not also list `sec=sys`. The AUTH_TOOWEAK oracle (F-1.8) reveals this condition: MOUNT succeeds and leaks the handle, but subsequent GETATTR returns `AUTH_TOOWEAK`, indicating Kerberos enforcement. Mixed-flavor exports (`sec=krb5:sys`) remain vulnerable because the attacker simply selects AUTH_SYS ([F-1.7](../identity/F-1.7-rpcsec-gss-flavor-downgrade.md)).

Every other common defense (`root_squash`, `ro`, IP-based ACLs, privileged ports) permits initial access. They may limit what the attacker can do after access (writes, root operations), but they do not prevent the attacker from reading the export and obtaining file handles.

---

## Auto-version detection

When `--nfs-version` is not specified, nfswolf probes the server in order: v3, then v2, then v4. The probe sequence uses portmapper GETPORT for v2/v3 (verifying with a NULL call) and direct COMPOUND for v4. This ensures the tool finds the most feature-rich available version while falling back gracefully. Explicit `--nfs-version 2` forces v2 access, which is useful for testing NFSv2 downgrade attacks (F-1.6) against servers that advertise v2 alongside v3/v4.

---

## Relationship to other stages

Initial access produces the file handles and directory listings that feed every subsequent stage. The export root handle enables [lateral movement](lateral.md) via escape construction. File ownership metadata from READDIRPLUS feeds the credential ladder for [privilege escalation](privesc.md). World-readable files discovered during initial directory enumeration may be directly exfiltrated without further escalation ([data exfiltration](exfil.md)).

!!! tip "nfswolf workflow"
    `nfswolf shell target:/export` is the primary initial-access tool. It handles MOUNT, credential selection, and READDIRPLUS automatically. For exports that require handle bypass, use `nfswolf shell target --handle <hex>`. For broad discovery, `nfswolf escape target:/export` tests whether the export can be escaped to the full filesystem in a single command.
