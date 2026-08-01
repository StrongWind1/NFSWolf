# NFSv4 Protocol Reference

Technical companion guide for NFSv4.0 (RFC 7530, March 2015). NFSv4 is a fundamentally different protocol from v2/v3 -- single port, no MOUNT, no portmapper, stateful sessions, and in-band security negotiation. This guide covers how nfswolf interacts with v4 and what changes from the attacker's perspective.

---

## v4 vs v2/v3: What Actually Matters for Attacking

**The architecture is completely different, but AUTH_SYS is still the weak link.**

NFSv4 collapses everything into one port and one RPC procedure. No portmapper, no MOUNT daemon, no separate mountd port. Just port 2049, one COMPOUND call, and you're in. This sounds simpler, but the protocol itself is much more complex -- stateful sessions, delegations, locking, and a 39-operation COMPOUND mechanism.

**What helps the attacker:**

- **Single port, no discovery chain** -- Port 2049, TCP, done. No need for portmapper (111) or mountd (random). Firewall rules are simpler for defenders but also for attackers: if 2049 is open, everything is reachable.
- **PUTROOTFH** -- Gives you the server's root file handle without any MOUNT call. No export path needed, no ACL check. You get the pseudo-root and navigate from there.
- **SECINFO** -- In-band security negotiation per directory path. You can probe which paths require Kerberos and which accept AUTH_SYS without being denied -- the protocol is designed for this. On v3, you only learn auth flavors at MOUNT time.
- **Pseudo-filesystem** -- The server exposes a virtual namespace bridging all exports. One PUTROOTFH + READDIR chain maps every exported path without calling MOUNT for each one.

**What hurts the attacker:**

- **No STALE/BADHANDLE oracle** -- NFSv4 uses different error semantics. The clean STALE-vs-BADHANDLE distinction from v3 that makes handle brute-forcing efficient is less reliable on v4 servers. Handle forging is a v2/v3 attack.
- **Stateful operations** -- OPEN, CLOSE, LOCK require a client ID (SETCLIENTID) and lease management. nfswolf's v4 client is stateless -- it uses the anonymous stateid for reads, which limits it to operations that don't require OPEN state. Write attacks need v3.
- **Kerberos is mandatory in the spec** -- RFC 7530 §3.2.1 says RPCSEC_GSS with Kerberos V5 is mandatory to implement. In practice, most servers still accept AUTH_SYS (the spec says MAY for other flavors), but properly hardened v4 deployments are more likely to enforce Kerberos than v3 deployments.
- **TCP required** -- RFC 7530 §3.1 mandates TCP. No UDP support. You can't IP-spoof with TCP like you can with UDP on v2/v3.

**The one thing that matters most:** If the server accepts AUTH_SYS on NFSv4, you have the same credential-spoofing attack surface as v2/v3 but with easier recon (SECINFO, pseudo-FS, single port). If it enforces Kerberos, v4 is the hardest version to attack -- try downgrading to v3 or v2 instead.

---

## Attack Path

### NFSv4 eliminates the three-service chain

v2/v3 required portmapper + mountd + nfsd (three services, three ports). v4 puts everything behind one port:

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
  |-- COMPOUND[ PUTFH(root),       --> |
  |             LOOKUP("etc"),         |
  |             LOOKUP("shadow"),      |
  |             READ(anon_stateid) ]   |
  |<-- file data --------------------- |
```

One port. One RPC procedure (COMPOUND). Multiple operations batched per call. No portmapper, no MOUNT daemon, no extra ports to discover.

### What if port 2049 is blocked?

No bypass. NFSv4 runs exclusively on port 2049 over TCP. There is no UDP option (RFC 7530 §3.1). If port 2049 is filtered, NFSv4 is unreachable. `--nfs-port PORT` supports non-standard ports.

### Getting the initial file handle

On v2/v3, you needed MOUNT to convert a path to a handle. On v4, the server gives you the root for free:

- **PUTROOTFH** (operation 24) -- Sets the "current filehandle" to the server's pseudo-root. No authentication check, no export path, no ACL. Every v4 server must support this.
- **GETFH** (operation 10) -- Returns the current filehandle as opaque bytes. Combined with PUTROOTFH, this is the v4 equivalent of MOUNT.

So the v4 "MOUNT" is just: `COMPOUND([PUTROOTFH, GETFH])` -- two operations, one RPC call, zero extra services.

### Mapping the namespace

On v3, mapping all exports required MOUNT EXPORT (list paths) then MOUNT MNT for each one. On v4, the pseudo-filesystem exposes everything:

```
COMPOUND([PUTROOTFH, READDIR])
--> lists top-level directories under the pseudo-root

COMPOUND([PUTROOTFH, LOOKUP("srv"), LOOKUP("nfs"), READDIR])
--> lists contents of /srv/nfs

COMPOUND([PUTROOTFH, LOOKUP("srv"), LOOKUP("nfs"), GETATTR(fsid)])
--> fsid change = export boundary crossing
```

**SECINFO** per directory reveals which auth flavors are required:
```
COMPOUND([PUTROOTFH, SECINFO("srv")])
--> [AUTH_SYS(1)]  -- spoofable, no Kerberos

COMPOUND([PUTROOTFH, LOOKUP("srv"), SECINFO("restricted")])
--> [RPCSEC_GSS(6)]  -- Kerberos required, AUTH_SYS rejected
```

### Can you brute-force v4 file handles?

Not effectively. The v3 STALE/BADHANDLE oracle does not apply to v4 in the same way. NFSv4 defines both `NFS4ERR_STALE` (70) and `NFS4ERR_BADHANDLE` (10001), but servers do not return them as consistently as v3 -- the clean format/content distinction that makes v3 brute-forcing efficient is less reliable. Additionally, v4 handles can be **volatile** (RFC 7530 §4.2.3) -- the server may change them at any time, especially for pseudo-filesystem entries.

Handle forging and brute-forcing are v2/v3 attacks. On v4, use SECINFO + PUTROOTFH + LOOKUP for namespace discovery instead.

### Anonymous reads without OPEN

NFSv4 normally requires OPEN before READ (stateful protocol). But RFC 7530 §9.1.4.3 defines an **anonymous stateid** (seqid=0, other=all-zeros) that allows reads without opening the file first. nfswolf uses this for all v4 reads -- no SETCLIENTID, no OPEN, no lease management needed. Most servers accept this for world-readable files.

---

## Connection Flow

```
Client                                Server
  |                                     |
  |-- TCP connect ------------------->  |:2049
  |-- RPC COMPOUND {                    |
  |     minorversion = 0,              |
  |     ops = [PUTROOTFH, GETFH]       |
  |   } --------------------------------|
  |<-- CompoundRes {                    |
  |     status = NFS4_OK,              |
  |     results = [ok, Fh(root_fh)]    |
  |   } --------------------------------|
  |                                     |
  |-- COMPOUND [PUTFH(root_fh),    -->  |
  |             LOOKUP("srv"),          |
  |             LOOKUP("nfs"),          |
  |             LOOKUP("public"),       |
  |             GETFH,                  |
  |             READDIR]                |
  |<-- directory listing + handle -----  |
```

No portmapper. No MOUNT. One TCP connection. All operations batched.

---

## 1. Portmapper

**Not used.** NFSv4 always runs on port 2049 (RFC 7530 §3.1). There is no portmapper dependency. The scanner still probes portmapper to detect v2/v3 registrations, but v4 is discovered via a direct COMPOUND probe to port 2049.

nfswolf's scanner sends `COMPOUND([PUTROOTFH])` to port 2049 and checks for `NFS4_OK` (`probe_nfs4()` in `src/proto/nfs4/compound.rs`). This works even when portmapper is completely filtered.

---

## 2. MOUNT Protocol

**Not used.** NFSv4 integrates mount functionality into the protocol itself (RFC 7530 §1.4.3). PUTROOTFH replaces MNT for getting the initial handle. The pseudo-filesystem replaces EXPORT for listing available paths.

**What MOUNT gave v2/v3 that v4 provides differently:**

| MOUNT feature | NFSv4 equivalent |
|---------------|-----------------|
| MNT (path -> handle) | PUTROOTFH + LOOKUP chain |
| EXPORT (list paths) | READDIR on pseudo-root |
| Auth flavor list | SECINFO per path |
| DUMP (connected clients) | No equivalent -- v4 server tracks state internally |
| UMNT (stealth cleanup) | No equivalent -- v4 has no mount table to clean |

---

## 3. NFS -- Program 100003, Version 4

Port 2049 (mandatory). TCP required (RFC 7530 §3.1). Defined in RFC 7530.

NFSv4 has only two RPC procedures: NULL (proc 0) and COMPOUND (proc 1). All file operations are expressed as **operations** batched inside COMPOUND. RFC 7530 defines 39 operations (op numbers 3-39 + 10044).

nfswolf implements 9 of the 39 operations -- the subset needed for recon and read-only file access. The remaining 30 are stateful operations (OPEN/CLOSE/LOCK), delegation management, or write paths that nfswolf handles via v3 instead.

### Implemented operations

| Op | Name | nfswolf | Via | Correct | Purpose |
|----|------|---------|-----|---------|---------|
| 9 | `GETATTR` | **Yes** | Own XDR | Correct | Get file attributes (type, size, fsid, owner). Supports bitmap-based attribute requests per RFC 7530 §18.7. |
| 10 | `GETFH` | **Yes** | Own XDR | Correct | Return current filehandle as opaque bytes. Used after PUTROOTFH or LOOKUP to capture the handle. |
| 15 | `LOOKUP` | **Yes** | Own XDR | Correct | Resolve one path component. Sets current FH to the result. Chain multiple LOOKUPs in one COMPOUND for full path traversal. |
| 22 | `PUTFH` | **Yes** | Own XDR | Correct | Set current FH to a known handle (from prior GETFH). Equivalent to v3's "use this handle for the next operation." |
| 23 | `PUTPUBFH` | **Yes** | Own XDR | Correct | Set current FH to the server's public (WebNFS) handle (RFC 7530 §16.21). Similar to PUTROOTFH but the public handle is server-defined and may differ from the pseudo-root. |
| 24 | `PUTROOTFH` | **Yes** | Own XDR | Correct | Set current FH to server's pseudo-root. The v4 replacement for MOUNT -- no export path needed, no ACL check. |
| 25 | `READ` | **Yes** | Own XDR | Correct | Read file data using the anonymous stateid (seqid=0, other=all-zeros per RFC 7530 §9.1.4.3). No OPEN required for world-readable files. |
| 26 | `READDIR` | **Yes** | Own XDR | Correct | List directory entries with inline attributes. Cookie-based pagination with 8-byte verifier. |
| 33 | `SECINFO` | **Yes** | Own XDR | Correct | Query supported auth flavors for a named child path. Returns array of flavor codes (1=AUTH_SYS, 6=RPCSEC_GSS). Decodes RPCSEC_GSS sub-fields (OID, QOP, service) when present. |

### Not implemented (with rationale)

| Op | Name | Why not | Attack relevance |
|----|------|---------|-----------------|
| 3 | `ACCESS` | v4 ACCESS requires OPEN state on some servers | Would enable quiet permission probing like v3. Low priority -- GETATTR reveals mode/uid/gid already. |
| 4 | `CLOSE` | Stateful -- requires SETCLIENTID + OPEN first | Needed for write attacks. nfswolf uses v3 for writes. |
| 5 | `COMMIT` | No async writes on v4 (no OPEN/WRITE) | Same as above. |
| 6 | `CREATE` | Stateful -- returns stateid, needs CLOSE | File creation via v3 instead. |
| 7 | `DELEGPURGE` | Delegation management | Not relevant for offensive use. |
| 8 | `DELEGRETURN` | Delegation management | Not relevant for offensive use. |
| 11 | `LINK` | Not needed for recon | Could be useful for persistence. Low priority. |
| 12-14 | `LOCK/LOCKT/LOCKU` | Stateful locking | DoS potential (lock files to deny access). Out of scope since NLM removal. |
| 16 | `LOOKUPP` | Look up parent directory | Useful but LOOKUP("..") serves same purpose on most servers. |
| 17 | `NVERIFY` | Conditional check (cache validation) | Not useful for offensive ops. |
| 18 | `OPEN` | Full state machine: SETCLIENTID -> OPEN_CONFIRM -> stateid tracking | Required for writes, creates, exclusive access. nfswolf uses v3 for all write ops. |
| 19 | `OPENATTR` | Named attribute access | Rarely used. Potential for hidden data exfil. Low priority. |
| 20-21 | `OPEN_CONFIRM/DOWNGRADE` | Part of OPEN state machine | Same as OPEN. |
| 27 | `READLINK` | Read symlink target | Would be useful. Low priority -- v3 shell has it. |
| 28-29 | `REMOVE/RENAME` | Destructive ops | Available via v3 with `--allow-write`. |
| 30 | `RENEW` | Lease renewal (stateful) | Only needed with SETCLIENTID sessions. |
| 31-32 | `SAVEFH/RESTOREFH` | FH stack operations | Used with LINK and RENAME for dual-FH ops. |
| 34 | `SETATTR` | Attribute modification | Available via v3 SETATTR. |
| 35-36 | `SETCLIENTID/CONFIRM` | Session establishment | Required for OPEN/LOCK/delegations. nfswolf is stateless on v4. |
| 37 | `VERIFY` | Conditional check | Not useful for offensive ops. |
| 38 | `WRITE` | Requires OPEN stateid | Available via v3 WRITE with `--allow-write`. |
| 39 | `RELEASE_LOCKOWNER` | Lock cleanup | Part of lock state machine. |
| 10044 | `ILLEGAL` | Error sentinel | Server returns this for unrecognized op numbers. |

**Implementation**: All 9 operations are nfswolf's own XDR code -- `#[derive(XdrCodec)]` Pack/Unpack implementations in `crates/nfs-v4/src/wire.rs` (re-exported as `types` via `src/proto/nfs4/mod.rs`). The `Nfs4Status` enum carries 25 named variants (Ok + 24 error codes including `BadHandle`, `WrongSec`, `Moved`, and `BadXdr`) plus an `Unknown(u32)` catch-all, and implements `Display` with RFC 7530 error names (e.g., `NFS4ERR_STALE`). nfswolf uses the `onc-rpc-client` crate's `RpcClient` for the RPC transport layer but implements all NFSv4 XDR encoding/decoding in its own crate.

### NFSv4 client variants

nfswolf has two NFSv4 clients for different use cases:

**`Nfs4Client`** (pool-backed, `src/proto/nfs4/compound.rs`): Used by the analyzer for SECINFO probes and pseudo-FS mapping. Shares the connection pool and circuit breaker with v3 calls.

| Method | Operations | Purpose |
|--------|-----------|---------|
| `compound(ops)` | Any | Raw COMPOUND dispatch |
| `lookup_path(components, attrs)` | PUTROOTFH + LOOKUP chain + GETATTR | Navigate to path, get attributes |
| `secinfo(parent, name)` | PUTROOTFH + LOOKUP chain + SECINFO | Query auth flavors for a path |
| `map_pseudo_fs()` | PUTROOTFH + GETFH + GETATTR(fsid) | Detect Linux pseudo-root UUID |

**`Nfs4DirectClient`** (direct TCP, `src/proto/nfs4/compound.rs`): Used by the interactive v4 shell (`--nfs-version 4`) and the scanner's v4 probe. Connects directly to port 2049 without the connection pool.

| Method | Operations | Purpose |
|--------|-----------|---------|
| `connect(addr)` | (TCP connect) | Connect with AUTH_NONE |
| `connect_with_auth(addr, uid, gid, hostname)` | (TCP connect) | Connect with AUTH_SYS |
| `reconnect_with_auth(uid, gid, hostname)` | (TCP reconnect) | Change credentials mid-session |
| `get_root_fh()` | PUTROOTFH + GETFH | Get pseudo-root handle |
| `lookup_fh(components)` | PUTROOTFH + LOOKUP chain + GETFH | Navigate to path, get handle |
| `list_dir(dir_fh)` | PUTFH + READDIR | List directory entries |
| `read_chunk(file_fh, offset, count)` | PUTFH + READ (anon stateid) | Read file data without OPEN |

### NFSv4 shell commands

The interactive v4 shell (`nfswolf shell --nfs-version 4`) supports:

| Command | v4 Operations Used |
|---------|-------------------|
| `ls` | PUTFH + READDIR |
| `ls <path>` | PUTROOTFH + LOOKUP chain + READDIR |
| `cd <dir>` | PUTROOTFH + LOOKUP chain + GETFH |
| `pwd` | (local state) |
| `cat <file>` | PUTROOTFH + LOOKUP chain + READ (anon stateid) |
| `get <file>` | Same as cat, writes to local file |
| `uid <n>` | Reconnects with new AUTH_SYS credential |
| `gid <n>` | Reconnects with new AUTH_SYS credential |
| `hostname <name>` | Reconnects with new AUTH_SYS machine name |
| `whoami` | Shows current uid/gid/hostname |
| `handle` | (local state) -- prints current FH as hex |
| `lcd <dir>` | (local filesystem) -- change local working directory |
| `lls [dir]` | (local filesystem) -- list local directory |
| `lpwd` | (local filesystem) -- print local working directory |
| `lmkdir <dir>` | (local filesystem) -- create local directory |
| `history` | (local state) -- navigate command history via readline |

**Limitations vs the v3 shell**: No `stat`, `put`, `mkdir`, `rm`, `escape-root`, `secrets-scan`, `suid-scan`, `world-writable`, `mount-handle`, recursive `get -r`/`put -r`, `tree`, `find`, `readlink`, `last`/`lastb`/`lastlog`. These require either write operations (OPEN/WRITE/CREATE) or v3-specific procedures (READDIRPLUS, FSSTAT). Local commands (`lcd`, `lls`, `lpwd`, `lmkdir`, `handle`, `history`) are fully supported. The read-only NFS commands (`stat`, `tree`, `find`, `readlink`, analysis commands) could technically work with existing COMPOUND+GETATTR+READDIR but are not yet implemented. Use the v3 shell for the full feature set.

### When port 2049 is blocked

No bypass. Port 2049 over TCP is the only transport (RFC 7530 §3.1). No UDP fallback exists for NFSv4.

---

## NFSv4 Security Properties

### What changed from v3

| Property | v3 | v4 | Impact |
|----------|----|----|--------|
| Auth negotiation | MOUNT response (one-time) | SECINFO per-path (dynamic) | Attacker can probe auth requirements per directory without triggering denials |
| Kerberos | Optional (most servers don't enforce) | Mandatory to implement (RFC 7530 §3.2.1) | More v4 deployments enforce Kerberos, but AUTH_SYS still accepted on many |
| Transport | TCP or UDP | TCP only | No IP spoofing via UDP source address forgery |
| IP-based ACLs | MOUNT-time check, often not re-checked | Per-RPC checks more common (server tracks state) | Harder to bypass with stolen handles on well-configured v4 servers |
| File handles | Variable up to 64B, persistent | Variable, persistent or volatile | Volatile handles make brute-forcing unreliable -- handle may change between probes |
| Handle oracle | STALE vs BADHANDLE (distinct errors) | STALE + BADHANDLE both defined, but less reliably distinguished by servers | Handle brute-forcing oracle is unreliable on v4. v3 is better for this attack |
| State | Stateless (every call independent) | Stateful (SETCLIENTID, OPEN, leases) | Write/create attacks require state management nfswolf doesn't implement on v4 |

### Kerberos on v4

RFC 7530 §3.2.1 says RPCSEC_GSS with Kerberos V5 is mandatory to implement. In practice:

- **Linux knfsd**: Supports Kerberos but defaults to `sec=sys`. Most exports accept AUTH_SYS unless explicitly configured with `sec=krb5`.
- **Windows NFS**: Typically Kerberos-integrated via Active Directory. More likely to enforce krb5 than Linux.
- **Appliance NFS (NetApp, EMC)**: Varies. Enterprise deployments often enforce Kerberos on v4 while leaving v3 on AUTH_SYS.

nfswolf's SECINFO probe detects which flavors a specific path requires. If AUTH_SYS (flavor 1) appears in the SECINFO response, credential spoofing works. If only RPCSEC_GSS (flavor 6) appears, downgrade to v3 or v2 (where Kerberos enforcement may be weaker or absent).

### The pseudo-root is not an export

The pseudo-root handle from PUTROOTFH points to a virtual namespace constructed by the server, not to a real filesystem. You can READDIR on it to list exported paths, but the files you see are synthetic directory entries bridging gaps between exports.

nfswolf detects the Linux pseudo-root by checking the fsid against the well-known UUID `39c6b5c1-3f24-4f4e-977c-7fe6546b8a25` (defined in `src/proto/nfs4/mod.rs`). When the root fsid matches this UUID, the current directory is the pseudo-root, not a real export.

Export boundaries are detected by fsid changes during LOOKUP traversal. When the fsid returned by GETATTR differs from the parent's fsid, you have crossed into a real exported filesystem.
