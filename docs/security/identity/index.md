# Identity attacks (F-1.x)

AUTH_SYS is the default authentication flavor for NFS. It passes client-asserted UIDs, GIDs, and a machine name to the server with no cryptographic verification. The server trusts these values at face value.

> "There is no verifier, so credentials can easily be faked."
> -- RFC 1057 sec. 9.3

Every finding in this category exploits the same root cause: the NFS server cannot distinguish a legitimate credential from a forged one when AUTH_SYS is in use. The eight findings below cover the full spectrum from direct UID spoofing to protocol-level downgrade attacks that force AUTH_SYS onto exports configured for stronger authentication.

## Finding summary

| ID | Finding | Severity | RFC Basis | Detection |
|----|---------|----------|-----------|-----------|
| [F-1.1](F-1.1-uid-gid-spoofing.md) | UID/GID Spoofing | **Critical** | RFC 5531 sec. 14, RFC 1057 sec. 9.2 | `uid-spray`, `shell uid/impersonate` |
| [F-1.2](F-1.2-root-squash-bypass.md) | Root Squash Bypass via Non-Root UID | High | RFC 1813 sec. 4.4, RFC 2623 sec. 2.5 | `analyze` (squash probe) |
| [F-1.3](F-1.3-auxiliary-group-injection.md) | Auxiliary Group Injection | High | RFC 1057 sec. 9.2 | `analyze` (shadow GID 42/15), `shell gid` |
| [F-1.4](F-1.4-machine-name-spoofing.md) | Machine Name Spoofing / Log Poisoning | Low | RFC 1057 sec. 9.2, RFC 9289 sec. A.1 | `--hostname` global flag |
| [F-1.5](F-1.5-credential-replay.md) | Credential Replay from Wire | High | RFC 1094 sec. 3.4, RFC 5531 sec. 9 | Passive (precondition: F-3.1) |
| [F-1.6](F-1.6-nfsv2-downgrade.md) | NFSv2 Downgrade (Auth Bypass) | High | RFC 2623 sec. 2.7 | `scan` (portmapper version matrix) |
| [F-1.7](F-1.7-rpcsec-gss-flavor-downgrade.md) | RPCSEC_GSS Flavor Downgrade | High | RFC 2203 sec. 5.2.1, RFC 7530 sec. 19 | `analyze` (mixed auth flavor detection) |
| [F-1.8](F-1.8-auth-tooweak-kerberos-enforced.md) | AUTH_TOOWEAK Oracle | High | RFC 5531 sec. 7.4, RFC 2623 sec. 2.3.2 | `analyze` (SECINFO scanner, MOUNT auth list) |

## Findings

### F-1.1: UID/GID Spoofing

!!! critical
    This is the foundational NFS vulnerability. Every other identity finding builds on it.

AUTH_SYS credentials carry a UID, GID, and up to 16 auxiliary GIDs. The verifier is AUTH_NONE: a zero-length opaque blob. The RPC layer treats credentials as opaque pass-through (RFC 5531 sec. 8.2), and the NFS server applies them directly to permission checks with no verification step (RFC 1813 sec. 4.4).

nfswolf exploits this by spraying UIDs 0-65535, targeting file-owner UIDs observed via GETATTR, and injecting auxiliary GIDs matching group-protected files. A single forged RPC call is sufficient to read any file whose UNIX permissions allow the claimed identity.

### F-1.2: Root Squash Bypass via Non-Root UID

Root squash maps UID 0 to `nobody` on the server. It does not protect against non-root UIDs. An attacker who claims the UID of a file's owner gets full owner-permission access, because the server's permission algorithm "should allow the owner of a file to access it regardless of the permission setting" (RFC 1813 sec. 4.4). nfswolf's credential ladder targets the file owner's UID first, making root squash irrelevant for most files.

### F-1.3: Auxiliary Group Injection

The `gids<16>` array in AUTH_SYS is entirely client-asserted. An attacker can inject any GID, including privileged groups like `shadow` (42) or `admin` (15), to pass group permission checks. nfswolf tests specific high-value GIDs first, then falls back to GID spraying when targeted injection fails.

### F-1.4: Machine Name Spoofing / Log Poisoning

The `machinename<255>` field in AUTH_SYS is "an unprotected domain name" (RFC 9289 sec. A.1). It is logged but not used for authorization on Linux knfsd; export ACLs match on source IP via reverse DNS, not on this field. Spoofing it poisons server logs with false attribution but does not bypass host-based ACLs on its own.

### F-1.5: Credential Replay from Wire

AUTH_SYS has no nonce, timestamp, or sequence number. The 32-bit XID is only for client-side reply matching (RFC 5531 sec. 9), not replay prevention. Any captured RPC message can be replayed indefinitely. This finding is passive: nfswolf detects the precondition (plaintext wire, F-3.1) rather than performing the replay itself.

### F-1.6: NFSv2 Downgrade (Auth Bypass)

!!! warning
    Live-tested: Linux knfsd 2.6.32+ enforces `sec=krb5` on NFSv2 NFS operations, but MOUNT v1 leaks the root handle without krb5 auth. Mixed `sec=krb5:sys` exports are fully accessible via AUTH_SYS on both versions.

NFSv2 has no security flavor negotiation mechanism. "It was up to the client to guess, or depend on prior knowledge" (RFC 2623 sec. 2.7). When a server supports NFSv2 alongside v3/v4, a client can explicitly request v2 to sidestep any v3+ `sec=krb5` requirements, because the v2 code path has no way to enforce them. nfswolf's scanner detects v2 availability via the portmapper version matrix.

### F-1.7: RPCSEC_GSS Flavor Downgrade

When an export advertises multiple security flavors (e.g., `sec=krb5:sys`), the client chooses freely. The server does not enforce the strongest available flavor. An attacker who cannot obtain Kerberos credentials selects AUTH_SYS and proceeds with forged credentials (F-1.1). nfswolf's analyzer flags exports that accept AUTH_SYS alongside any RPCSEC_GSS flavor in the MOUNT EXPORT auth-flavor list or NFSv4 SECINFO response.

### F-1.8: AUTH_TOOWEAK Oracle (Kerberos Enforcement Detection)

When no configured security flavor matches the request, the server returns AUTH_TOOWEAK (RFC 5531 sec. 7.4). This is a definitive oracle: it confirms the export exists and requires stronger authentication. Critically, the MOUNT protocol still succeeds with AUTH_SYS and leaks the root file handle -- only subsequent NFS operations fail. The handle is a permanent bearer token (F-2.7) usable if the attacker later obtains valid Kerberos credentials.

## AUTH_SYS wire format

Understanding the wire format makes the severity concrete. Every RPC call carrying AUTH_SYS sends the following structure in cleartext:

```
struct authsys_parms {
    unsigned int stamp;           /* arbitrary 32-bit value */
    string machinename<255>;      /* client-asserted, unverified */
    unsigned int uid;             /* client-asserted, unverified */
    unsigned int gid;             /* client-asserted, unverified */
    unsigned int gids<16>;        /* client-asserted, unverified */
};
```

The verifier that accompanies this credential is `AUTH_NONE`: literally zero bytes of verification data. The server has no mechanism to confirm that the UID/GID values correspond to a real user on the client machine, or that the client is who it claims to be. This structure is defined in RFC 5531 sec. 14 and unchanged since RFC 1057 (1988).

## Severity distribution

| Severity | Count | Findings |
|----------|-------|----------|
| Critical | 1 | F-1.1 |
| High | 6 | F-1.2, F-1.3, F-1.5, F-1.6, F-1.7, F-1.8 |
| Low | 1 | F-1.4 |

Six of eight findings are rated High or above. The single Critical finding (F-1.1) is the root cause that enables every other identity attack. The six High findings represent different exploitation paths that all terminate in the same outcome: the attacker presents forged AUTH_SYS credentials and the server accepts them.

## Attack chain

The typical identity attack proceeds through these stages:

1. **Reconnaissance** -- `scan` enumerates exports, auth flavors, and NFS versions. If the export accepts AUTH_SYS, proceed directly to step 3. If it requires krb5, check for mixed flavors (F-1.7) or v2 availability (F-1.6).
2. **Downgrade** -- If only krb5 is advertised, attempt NFSv2 downgrade or mixed-flavor exploitation. AUTH_TOOWEAK (F-1.8) confirms kerberos enforcement and leaks the handle for later use.
3. **Credential forging** -- `shell uid <N>` or `uid-spray` forges AUTH_SYS credentials. The credential ladder targets the file owner first (F-1.2), then group injection (F-1.3), then root if no_root_squash is set (see F-4.1), then observed identities from READDIRPLUS.
4. **Persistence** -- File handles obtained with any credential work with any other credential (F-2.7). Once access is established, handles persist across UID switches and server reboots.

## Mitigations

| Mitigation | Findings Addressed |
|------------|--------------------|
| `sec=krb5p` (exclusively, no `sys` fallback) | F-1.1, F-1.2, F-1.3, F-1.5, F-1.7 |
| Disable NFSv2 on the server | F-1.6 |
| Network segmentation / firewall NFS ports | F-1.5 (wire capture), F-1.4 (log poisoning) |
| RPC-with-TLS (RFC 9289) with mutual TLS | F-1.5 (replay), F-1.1 (spoofing with mTLS identity binding) |
| Monitor and alert on `machinename` mismatches | F-1.4 |
