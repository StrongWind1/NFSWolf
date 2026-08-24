# What Changed in NFSv4

NFSv4 is not an incremental update to v3. It is a protocol redesign that collapses the multi-service NFS architecture into a single protocol, adds state, and integrates security negotiation. This page documents the eight major changes and what each means for security.

## 1. No portmapper dependency

NFSv3 required portmapper (port 111) to discover the mountd port, which in turn provided the root file handle. NFSv4 runs exclusively on port 2049 over TCP (RFC 7530 sec. 3.1). No portmapper, no dynamic port discovery.

```
v3: Client → portmapper:111 → mountd:random → nfsd:2049
v4: Client → nfsd:2049
```

**Security impact:** Firewall rules are simpler in both directions. Defenders only need to manage one port. Attackers only need one port open. If port 2049 is filtered, NFSv4 is completely unreachable; there is no UDP fallback and no alternate port discovery mechanism.

nfswolf's scanner detects v4 by sending `COMPOUND([PUTROOTFH])` directly to port 2049 (`probe_nfs4()`). This works even when portmapper (port 111) is completely filtered -- a v4-only server is discoverable without any auxiliary services.

## 2. No MOUNT protocol

NFSv3 used the MOUNT protocol (RFC 1813 Appendix I) as a gatekeeper: the client sent an export path, the server returned a root file handle after checking IP-based ACLs. NFSv4 eliminates MOUNT entirely (RFC 7530 sec. 1.4.3).

The v4 equivalent of `MOUNT MNT /export` is:

```
COMPOUND([PUTROOTFH, LOOKUP("export"), GETFH])
```

PUTROOTFH (op 24) sets the current filehandle to the server's pseudo-root. No authentication check, no export path required. Every v4 server must support this. From the pseudo-root, LOOKUP operations navigate to any export.

| MOUNT feature | NFSv4 equivalent |
|---------------|-----------------|
| MNT (path to handle) | PUTROOTFH + LOOKUP chain |
| EXPORT (list paths) | READDIR on pseudo-root |
| Auth flavor list | SECINFO per path |
| DUMP (connected clients) | No equivalent |
| UMNT (cleanup) | No equivalent |

**Security impact:** The MOUNT protocol's IP-based ACL check was the only gatekeeper for handle acquisition on v3. On v4, the pseudo-root is freely accessible and the server applies access controls at the export boundary during LOOKUP, not during handle acquisition. This makes export enumeration easier but does not bypass per-export security policies on well-configured servers.

## 3. COMPOUND batching

NFSv3 had 22 distinct RPC procedures, each requiring a separate RPC call. NFSv4 has exactly two procedures: NULL and COMPOUND. All file operations are expressed as **operations** batched inside a single COMPOUND call (RFC 7530 sec. 14.1).

```
v3: LOOKUP(dir, "etc") → separate RPC
    LOOKUP(etc_fh, "passwd") → separate RPC
    READ(passwd_fh, 0, 65536) → separate RPC

v4: COMPOUND([PUTROOTFH, LOOKUP("etc"), LOOKUP("passwd"), READ(0, 65536)])
    → one RPC call, three directory traversals + read
```

Operations within a COMPOUND share a **current filehandle** that passes context from one operation to the next. A **saved filehandle** slot provides temporary storage for operations like RENAME that need two handles. See the [COMPOUND Operations](compound.md) page for the full model.

**Security impact:** COMPOUND reduces the number of round trips, which helps both legitimate clients and attackers. A single RPC can traverse a deep directory tree and read a file. The server evaluates operations sequentially and stops at the first failure, so an attacker can probe paths by observing which operation in the chain fails.

## 4. Stateful model

NFSv3 was stateless. Every READ, WRITE, and LOOKUP was independent -- the server maintained no per-client state. File locking was outsourced to the separate NLM protocol (Network Lock Manager).

NFSv4 integrates state into the protocol (RFC 7530 sec. 9):

- **SETCLIENTID + SETCLIENTID_CONFIRM** establish a client identity with the server
- **OPEN** returns a **stateid** -- a 128-bit token authorizing file I/O
- **CLOSE** releases open state
- **LOCK / LOCKT / LOCKU** provide byte-range locking without NLM
- **RENEW** refreshes the client's lease before it expires

The server maintains leases for all client state. If a client fails to renew within the lease period, the server may release all associated state. See the [Stateful Model](stateful.md) page for the full lifecycle.

!!! info "Anonymous stateid"
    For world-readable files, the anonymous stateid (seqid=0, other=all-zeros, per RFC 7530 sec. 9.1.4.3) allows READ without OPEN. nfswolf uses this for initial file reads before establishing a session.

**Security impact:** Stateids are not bound to any particular credential. A stateid obtained with one UID can potentially be used with different credentials, similar to how file handles are bearer tokens. The stateful model also introduces state-based DoS vectors: SETCLIENTID can destroy another client's state (F-6.3), and lock operations can create denial-of-service conditions (F-6.2).

## 5. Pseudo-filesystem

NFSv3 relied on the MOUNT EXPORT procedure to list available exports. Each export was an independent namespace with no structural relationship to other exports. NFSv4 presents all exports within a single virtual namespace called the pseudo-filesystem (RFC 7530 sec. 7.3).

```
Server exports:
  /srv/nfs/public     *(rw)
  /srv/nfs/internal   10.0.0.0/24(rw)

Pseudo-FS tree:
  /              ← pseudo-root (PUTROOTFH)
  └── srv/
      └── nfs/
          ├── public/      ← export junction
          └── internal/    ← export junction
```

The pseudo-root has a unique fsid (on Linux knfsd: `39c6b5c1-3f24-4f4e-977c-7fe6546b8a25`). Export boundaries are detected by fsid changes during LOOKUP traversal. See the [Pseudo-Filesystem](pseudo-fs.md) page for details.

**Security impact:** The pseudo-FS reveals export names and structure to any authenticated client, even if the client lacks access to the exports themselves (F-5.5). LOOKUPP enables upward traversal to the pseudo-root, then LOOKUP descends into sibling exports, enabling cross-export lateral movement without handle forging (F-2.12).

## 6. Mandatory SECINFO

NFSv3 disclosed supported authentication flavors once, at MOUNT time, as part of the MNT response. There was no way to query per-directory security requirements.

NFSv4 adds the SECINFO operation (op 33, RFC 7530 sec. 3.3.1), which returns the security mechanisms required for a specific path. The server can enforce different security policies per export within the namespace.

```
COMPOUND([PUTROOTFH, SECINFO("public")])
→ [AUTH_SYS(1)]  -- spoofable

COMPOUND([PUTROOTFH, LOOKUP("srv"), SECINFO("restricted")])
→ [RPCSEC_GSS(6, krb5p)]  -- Kerberos with privacy
```

When a client attempts to access a path with an unsupported flavor, the server returns `NFS4ERR_WRONGSEC`, directing the client to use SECINFO to discover the required mechanisms. See the [Security Negotiation](security.md) page for the full model.

**Security impact:** SECINFO is a designed-in security audit mechanism. An attacker can probe every directory to find which paths accept AUTH_SYS (spoofable) and which require Kerberos (not spoofable), then focus on the weak paths. This is more efficient than the v3 approach of attempting operations and observing failures.

## 7. UTF-8 strings and named attributes

NFSv3 treated filenames as opaque byte strings with no defined encoding. NFSv4 mandates UTF-8 encoding for all file and directory names (RFC 7530 sec. 12). Servers may enforce normalization and reject invalid UTF-8.

NFSv4 also introduces **named attributes** (RFC 7530 sec. 5.3): opaque byte streams associated with files and directories, accessed via the OPENATTR operation (op 19). Named attributes are stored in a per-file "named attribute directory" that behaves like a hidden subdirectory. NFSv4 ACLs (RFC 7530 sec. 6.2.1) replace the sideband NFS_ACL protocol used on v3.

**Security impact:** UTF-8 enforcement can reject path-traversal attempts using non-UTF-8 byte sequences that v3 servers would pass through. Named attributes provide a new data channel that is not visible through traditional directory listing -- potentially useful for data hiding but also for data exfiltration.

## 8. Delegations

NFSv4 introduces delegations: the server can grant a client exclusive or shared access to a file, allowing the client to cache aggressively and service operations locally without server round trips (RFC 7530 sec. 10.4). When another client requests conflicting access, the server recalls the delegation via a callback channel.

- **OPEN_DELEGATE_READ** -- no other client can write while the delegation is held
- **OPEN_DELEGATE_WRITE** -- no other client can read or write

**Security impact:** Delegations themselves are not a direct attack vector, but the callback mechanism requires the server to connect back to the client. If the callback path is blocked (firewall, NAT), delegations cannot be granted. An attacker could potentially exploit DELEGPURGE (op 7) to interfere with other clients' cached state.

## Summary of changes

| Change | v3 Mechanism | v4 Mechanism | Net Security Effect |
|--------|-------------|-------------|---------------------|
| No portmapper | Port 111 required | Fixed port 2049 | Neutral -- simpler for both sides |
| No MOUNT | MOUNT MNT with IP ACL | PUTROOTFH (no ACL) | Easier recon, same access control at export boundary |
| COMPOUND | 22 separate RPCs | Batched operations | Neutral -- fewer round trips for everyone |
| Stateful | Stateless + NLM | Integrated state + leases | New DoS vectors (F-6.2, F-6.3) |
| Pseudo-FS | MOUNT EXPORT | Virtual namespace tree | Exposes export names to all clients (F-5.5) |
| SECINFO | Flavor list at MOUNT | Per-path negotiation | Better audit capability for both sides |
| UTF-8 / attrs | Opaque bytes, no ACLs | UTF-8, NFSv4 ACLs, named attrs | Minor improvement (rejects some path tricks) |
| Delegations | None | OPEN_DELEGATE_READ/WRITE | Minimal security impact |

## What did not change

Despite all the architectural improvements, three properties remain constant across all NFS versions:

1. **AUTH_SYS is still trust-the-client.** The server believes whatever UID/GID the client asserts. No cryptographic verification. This is the same on v2, v3, and v4.

2. **File handles are still bearer tokens.** A handle obtained by one credential works with any other credential. Handle reuse across UID switches is valid protocol behavior (RFC 7530 sec. 4, RFC 2623 sec. 2.6).

3. **ACCESS is still advisory.** The ACCESS operation (op 3, RFC 7530 sec. 16.1) returns the server's best guess at the client's permissions. The actual access check happens when the operation is attempted. Always confirm by doing the operation.

!!! danger "The bottom line"
    If a server accepts AUTH_SYS on NFSv4, the attacker has the same credential-spoofing surface as v2/v3 but with better recon tools (SECINFO, pseudo-FS, single port) and full write/create/lock capability. If the server enforces Kerberos, NFSv4 is the hardest version to attack -- consider downgrading to v3 or v2 where Kerberos enforcement may be weaker or absent.
