# NFSv4

NFSv4 is a ground-up redesign of the NFS protocol, defined in RFC 7530 (March 2015, obsoleting RFC 3530 and the original RFC 3010). It eliminates the multi-service architecture of v2/v3, replacing portmapper, MOUNT daemon, and NLM lock manager with a single protocol on a single port. Every operation is batched into COMPOUND RPCs, the server tracks client state, and security negotiation is built into the protocol itself.

From a security perspective, the redesign improves some things (mandatory SECINFO, TCP-only transport, stateful locking) while leaving the fundamental AUTH_SYS problem untouched. If a server accepts AUTH_SYS on NFSv4, the same credential-spoofing attacks that work on v2/v3 still work, with easier recon thanks to SECINFO and the pseudo-filesystem.

## Specification history

| Document | Date | Status |
|----------|------|--------|
| RFC 3010 | December 2000 | Original NFSv4 specification (obsoleted) |
| RFC 3530 | April 2003 | Revised NFSv4 specification (obsoleted) |
| RFC 7530 | March 2015 | Current NFSv4.0 specification |
| RFC 7531 | March 2015 | Companion XDR description document |
| RFC 8881 | August 2020 | NFSv4.1 (parallel NFS, sessions) |

!!! note "nfswolf targets NFSv4.0"
    nfswolf implements NFSv4.0 (RFC 7530), not NFSv4.1 or NFSv4.2. The v4.0 protocol is the most widely deployed NFSv4 variant and covers the full attack surface relevant to AUTH_SYS-based attacks. NFSv4.1 (RFC 8881) adds sessions and parallel NFS (pNFS) but does not change the AUTH_SYS attack surface. NFSv4.2 (RFC 7862) adds server-side copy and security labels but is rarely deployed independently of v4.1.

## Design goals

RFC 7530 Section 1.2 outlines four goals that drove the v4 redesign:

1. **Internet operation** -- transit firewalls easily (single port), perform well with high latency (COMPOUND batching), scale to many clients.
2. **Strong security with negotiation** -- RPCSEC_GSS is mandatory to implement, SECINFO enables per-path security discovery.
3. **Cross-platform interoperability** -- ACLs, named attributes, and UTF-8 strings support Windows and UNIX environments equally.
4. **Protocol extensibility** -- minor versioning (v4.1, v4.2) adds features without breaking backward compatibility.

## Architecture comparison: v3 vs v4

The table below covers every significant difference between NFSv3 and NFSv4 from both a protocol and security perspective.

| Dimension | NFSv3 (RFC 1813) | NFSv4 (RFC 7530) |
|-----------|------------------|-------------------|
| **RPC programs** | 3 separate: NFS (100003), MOUNT (100005), NLM (100021) | 1 program: NFS (100003) |
| **Required ports** | 2049 (NFS) + random (mountd) + 111 (portmapper) | 2049 only |
| **Transport** | TCP or UDP | TCP mandatory (RFC 7530 sec. 3.1) |
| **Port discovery** | Portmapper (port 111) resolves mountd port | Not needed; fixed port 2049 |
| **RPC procedures** | 22 distinct procedures (NULL through COMMIT) | 2 procedures: NULL and COMPOUND |
| **Operation model** | One procedure per RPC call | Multiple operations batched in COMPOUND |
| **File handles** | Variable, up to 64 bytes, persistent | Variable, up to 128 bytes, persistent or volatile |
| **Initial handle** | MOUNT MNT converts path to handle | PUTROOTFH returns pseudo-root handle |
| **Export listing** | MOUNT EXPORT enumerates paths | READDIR on pseudo-root |
| **Auth negotiation** | MOUNT response carries flavor list (one-time) | SECINFO per-path (dynamic, in-band) |
| **Kerberos** | Optional (RFC 2623), rarely enforced | Mandatory to implement (RFC 7530 sec. 3.2.1) |
| **File locking** | Separate NLM protocol (RFC 1813) | Integrated LOCK/LOCKT/LOCKU operations |
| **State model** | Stateless; every call independent | Stateful; SETCLIENTID, OPEN, leases |
| **Parent traversal** | LOOKUP(".."), server-dependent behavior | LOOKUPP (op 16), protocol-guaranteed |
| **String encoding** | Opaque byte strings | UTF-8 (RFC 7530 sec. 12) |
| **ACLs** | None in protocol (NFS_ACL sideband) | NFSv4 ACLs built in (RFC 7530 sec. 6.2.1) |
| **Delegations** | None | OPEN_DELEGATE_READ / OPEN_DELEGATE_WRITE |
| **Named attributes** | None | Opaque byte streams keyed by string name |

## What matters for security

**AUTH_SYS is still the weak link.** NFSv4's architectural improvements do not change the fundamental authentication problem. AUTH_SYS credentials are still client-asserted UIDs with no cryptographic verification. If a v4 server accepts AUTH_SYS (and most do), credential spoofing works exactly as it does on v2/v3.

=== "What helps the attacker"

    - **Single port** -- port 2049, TCP, done. No portmapper or mountd to locate. If 2049 is open, everything is reachable.
    - **PUTROOTFH** -- returns the server's root handle without any MOUNT call. No export path needed, no ACL check.
    - **SECINFO** -- in-band security negotiation per directory path. Probe which paths require Kerberos and which accept AUTH_SYS, without being denied.
    - **Pseudo-filesystem** -- one READDIR chain maps every exported path. No separate EXPORT call needed.
    - **LOOKUPP** -- protocol-guaranteed parent traversal enables export escape (F-2.11) and cross-export lateral movement (F-2.12).
    - **Full stateful operations** -- nfswolf implements the complete SETCLIENTID lifecycle, OPEN/CLOSE with stateid tracking, LOCK/LOCKU, and crash recovery. Write attacks, file creation, and lock-based DoS all work natively over v4.

=== "What helps the defender"

    - **TCP required** -- no UDP, so no IP-spoofing via source address forgery.
    - **Kerberos mandatory to implement** -- more v4 deployments enforce Kerberos than v3 deployments, though AUTH_SYS is still accepted on many servers.
    - **Volatile handles** -- servers may change pseudo-FS handles at any time, making handle brute-forcing unreliable on v4.
    - **No STALE/BADHANDLE oracle** -- the clean format/content distinction from v3 that makes handle brute-forcing efficient is less reliable on v4 servers.
    - **No UDP** -- TCP is mandatory for NFSv4 (RFC 7530 sec. 3.1). This eliminates the IP-spoofing attack surface that exists on v2/v3 when UDP is available.

## The NFSv4 attack path

NFSv4 eliminates the three-service chain that v2/v3 required (portmapper + mountd + nfsd). Everything runs behind one port:

```
Client                               Server
  |                                    |
  |-- COMPOUND[ PUTROOTFH, GETFH ] --> |:2049  nfsd v4
  |<-- root file handle -------------- |
  |                                    |
  |-- COMPOUND[ PUTFH(root),       --> |
  |             READDIR ]              |
  |<-- directory entries ------------- |
  |                                    |
  |-- COMPOUND[ SETCLIENTID,       --> |
  |             SETCLIENTID_CONFIRM ]  |
  |<-- clientid + lease -------------- |
  |                                    |
  |-- COMPOUND[ PUTFH(dir),        --> |
  |             OPEN("target"),        |
  |             READ(stateid) ]        |
  |<-- file data --------------------- |
```

One port. One RPC procedure (COMPOUND). Multiple operations batched per call. No portmapper, no MOUNT daemon, no extra ports to discover. If the server accepts AUTH_SYS, the attacker has full read/write/create/lock capability with spoofed credentials.

If port 2049 is blocked, there is no bypass. NFSv4 runs exclusively on port 2049 over TCP. There is no UDP option (RFC 7530 sec. 3.1). The `--nfs-port PORT` flag supports non-standard ports if the server is configured on an alternate port.

## File handles on NFSv4

NFSv4 file handles have the same internal byte structure as v2/v3 on Linux knfsd, but with different acquisition and lifetime semantics:

| Property | NFSv2 | NFSv3 | NFSv4 |
|----------|-------|-------|-------|
| Max size | 32 bytes (fixed) | 64 bytes (variable) | 128 bytes (variable) |
| Acquisition | MOUNT v1 MNT | MOUNT v3 MNT | PUTROOTFH + LOOKUP + GETFH |
| Persistence | Always persistent | Always persistent | Persistent or volatile |
| Cross-protocol reuse | Yes | Yes | Yes (same internal format on knfsd) |
| Bearer token | Yes | Yes | Yes |

!!! info "Cross-protocol handle reuse"
    File handles are cross-protocol on servers that support multiple NFS versions. A handle from MOUNT v3 works with NFSv4 PUTFH, and a handle from NFSv4 GETFH works with NFSv3 procedures. The internal byte layout is identical on Linux knfsd. nfswolf exploits this in the escape engine: seed handles acquired via MOUNT v3 are probed over v4, and vice versa.

## nfswolf NFSv4 support

nfswolf implements the full NFSv4.0 protocol stack in the `nfs-v4` crate (244 tests). The implementation covers:

- All 37 operations (ops 3-39) fully typed with response decoders
- 66 named status codes with classification predicates
- SETCLIENTID lifecycle, OPEN/CLOSE/LOCK state, crash recovery
- Domain types (`Nfs4FileInfo`, `Nfs4DirEntry`, `Nfs4FileType`)
- 47 public client methods in `Nfs4Client`
- `V4Ops` implementing `ShellOps` for the unified 52-command shell
- `Nfs4EscapeProbe` for the escape engine on v4-only servers
- Auto-version detection probing v3, v2, then v4

### Two client variants

| Client | Transport | Use case |
|--------|-----------|----------|
| `Nfs4Client` (pool-backed) | `PooledTransport` with circuit breaker, stealth, credential management | Shell, analyzer, escape engine |
| `Nfs4DirectClient` (direct TCP) | Single TCP connection, no pool | Scanner v4 probe (`probe_nfs4()`) |

### Auto-version detection

When `--nfs-version` is omitted, `resolve_version` probes in order: v3 (portmapper GETPORT + NULL verification), v2 (portmapper GETPORT + NULL verification), v4 (direct COMPOUND to port 2049). The first version that responds successfully is selected. This means v4-only servers (no portmapper, no MOUNT) are detected automatically and the full 52-command shell works without manual configuration.

## In this section

| Page | Contents |
|------|----------|
| [What Changed in NFSv4](changes.md) | The eight major architectural changes from v3 and their security implications |
| [COMPOUND Operations](compound.md) | How operation batching works, the current/saved filehandle model, all 37 operations |
| [Stateful Model](stateful.md) | Client IDs, stateids, leases, OPEN/CLOSE/LOCK, crash recovery |
| [Pseudo-Filesystem](pseudo-fs.md) | The virtual namespace, export browsing, LOOKUPP traversal, fsid boundaries |
| [Security Negotiation](security.md) | SECINFO, AUTH_TOOWEAK, Kerberos enforcement, nfswolf probing |
