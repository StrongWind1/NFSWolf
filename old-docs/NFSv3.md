# NFSv3 Protocol Reference

Technical companion guide for NFSv3 (RFC 1813, June 1995). Covers the three RPC services required for a complete NFSv3 session, what nfswolf implements for each, and how to operate when individual services are unreachable.

---

## v3 vs v2: What Actually Matters for Attacking

The trust model is identical -- AUTH_SYS is still unsecured, file handles are still bearer tokens, credentials are still forgeable. The same fundamental attacks work on both versions. The differences are operational:

**v3 is better for the attacker in every way except one:**

- **Handle oracle** -- v3 distinguishes STALE (right format, wrong inode) from BADHANDLE (wrong format). v2 returns STALE for both. This means handle brute-forcing on v3 tells you immediately when your handle structure is correct, reducing the search to an inode/gen sweep. On v2, brute-forcing is blind.
- **READDIRPLUS** -- One call returns every filename, file handle, and full attributes for an entire directory. On v2, listing a directory requires READDIR (names only) then a LOOKUP + GETATTR per entry. Mapping a 100-file directory: v3 = 1 RPC, v2 = 201 RPCs.
- **ACCESS** -- Silent permission probing. Check READ/WRITE/EXECUTE permissions for any uid/gid without actually attempting the operation. The UID sprayer uses this to test thousands of credentials quietly. On v2, you blind-try READ/WRITE and catch the error.
- **64-bit file sizes** -- v2 caps at 2 GB. v3 has no practical limit. Exfiltrating a 10 GB database dump is impossible on v2.
- **Async writes** -- WRITE with `stable=UNSTABLE` lets the server buffer writes in memory. Bulk write attacks are 5-10x faster than v2's mandatory synchronous flush. Call COMMIT once at the end.
- **Auth flavor discovery** -- MOUNT v3 returns which auth methods the export supports. You learn immediately if Kerberos is required (don't waste time) or if AUTH_SYS is accepted (game on). v2 has no such signal.

**The one v2 advantage:**

- **No auth negotiation** (RFC 2623 §2.7) -- Some servers that enforce Kerberos on v3 exports skip enforcement on v2 because v2 has no mechanism for it. If a server supports both versions, try v2 first -- root_squash and auth requirements may be weaker or absent.

**Bottom line**: If the server supports v3, use v3. The only reason to downgrade to v2 is when v3 enforces Kerberos but v2 doesn't -- pass `--nfs-version 2` explicitly to try the downgrade (the credential ladder does not auto-downgrade from v3 to v2).

---

## Attack Path

### The happy path (all services reachable)

The same three-service chain as NFSv2, but with upgraded MOUNT (v3) and NFS (v3) protocols:

1. **Portmapper** (port 111) -- Same as v2. Ask: "what port is mountd on?" Get back a port number. Identical PMAPPROC_GETPORT call, same bypass options.

2. **MOUNT v3** (random port) -- Ask: "give me a handle for `/export`." Get back a **variable-length handle** (up to 64 bytes, vs v2's fixed 32) plus a **list of auth flavors** the export supports. The auth flavor list is new in v3 -- it reveals whether the export requires Kerberos (RPCSEC_GSS, flavor 6) or accepts spoofable AUTH_SYS (flavor 1). This is finding F-1.1 in nfswolf.

3. **NFS v3** (port 2049) -- Same concept as v2 but with 22 procedures (vs 18), variable-length handles, 64-bit file sizes, async writes, and two critical new features: the **ACCESS** procedure for permission probing and the **STALE/BADHANDLE oracle** for handle brute-forcing.

### What if portmapper is blocked?

Identical to NFSv2. Portmapper is the same program (100000 v2) for both NFS versions:

- **`--mount-port PORT`** -- Specify mountd port directly.
- **Automatic fallback** -- nfswolf probes ports 2049 then 20048 when portmapper is unreachable.
- **`--handle HEX`** -- Skip portmapper and mountd entirely.

### What if mountd is blocked?

Same bypasses as v2, but v3 handles are variable-length (up to 64 bytes) so the `--handle` hex string will be longer:

- **`--handle HEX`** -- Supply a handle from a prior session, escape, brute-force, or network capture.
- **`escape` output** -- nfswolf prints the escaped root handle in hex.
- **`brute-handle`** -- The STALE/BADHANDLE oracle (v3 only) makes brute-forcing more efficient than v2. STALE (error 70) confirms the handle format is correct; BADHANDLE (error 10001) means the format is wrong entirely. This lets you narrow the search to inode/generation values without wasting time on wrong formats.

### What if you only have port 2049?

Same minimum case: a valid file handle is the sole input. But v3 gives you better tools once you have one:

- **READDIRPLUS** -- Returns file handles + attributes for every entry in a directory, in a single call. On v2 you need READDIR (names only) then LOOKUP each name individually. READDIRPLUS collapses N+1 calls into 1.
- **ACCESS** -- Check permissions before attempting an operation. On v2 you blind-try READ/WRITE and catch the error. ACCESS lets you probe quietly. (But remember: ACCESS is advisory -- always confirm with the actual operation. RFC 1813 §3.3.4.)
- **FSINFO** -- Get max read/write sizes and filesystem capabilities. Not available on v2.

### Can you blind brute-force file handles?

Yes, and v3 is **better for brute-forcing than v2** because of the STALE/BADHANDLE oracle:

**The oracle** (RFC 1813 §2.6):
- `NFS3ERR_STALE` (70) = handle format recognized, but the specific inode/generation is invalid. **Confirms the handle layout is correct.**
- `NFS3ERR_BADHANDLE` (10001) = handle format itself is unrecognized. **Wrong format entirely -- adjust the header/structure and retry.**

On v2, both cases return `NFSERR_STALE` -- you can't tell format errors from content errors, so brute-forcing is blind. On v3, the oracle tells you when the format is right, reducing the search to sweeping inode/generation values.

**Linux ext4 v3 handle structure** (typical, up to 44 bytes):
```
[4B header] [4B export_inode] [4B export_gen] [16B UUID] [4B inode] [4B gen]
 fixed       known from seed   known           known      GUESS      GUESS

fileid_type=0x02 variant adds [4B parent_inode] [4B parent_gen] = 44 bytes
```

Same search space as v2 (root inode 2 + gen 0 = instant), but the oracle means you can discard wrong-format candidates immediately.

**Rate limiting**: Same as v2 -- none. NFS servers do not rate-limit GETATTR calls. 10,000+ probes/sec on a LAN. No lockout, no detection.

### Is port 2049 TCP only?

No. RFC 1813 §2.3: *"The NFS protocol is normally supported over the TCP and UDP protocols."* Both registered in portmapper by default on Linux. However, modern best practice is TCP:

- **TCP**: Handles large reads/writes (64 KB+ chunks), survives packet loss, supports record marking for message framing.
- **UDP**: Limited to ~8 KB per datagram (MTU constrained), no retransmission, but lower latency for small ops on reliable LANs.

nfswolf uses TCP by default. `nfswolf scan --scan-udp` additionally probes NFS and mountd over UDP for environments where TCP/111 is filtered. The `call_rpc_udp()` function in `src/proto/udp.rs` handles single-shot UDP RPC calls without TCP record marking.

---

## Connection Flow

```
Client                                Server
  |                                     |
  |-- PMAPPROC_GETPORT(100005,3) -----> |:111   portmapper
  |<-- port 59231 --------------------- |       "mountd v3 is on 59231"
  |                                     |
  |-- MNTPROC3_MNT("/export") -------> |:59231 mountd v3
  |<-- fhandle3[var] + auth_flavors --- |       "here is your handle + auth"
  |                                     |
  |-- NFSPROC3_READDIRPLUS(fh) -------> |:2049  nfsd v3
  |<-- entries[name+fh+attrs] --------- |
  |-- NFSPROC3_READ(child_fh, 0, 64k)-> |
  |<-- data + attrs ------------------- |
```

Note the MOUNT version changes: PMAPPROC_GETPORT queries program 100005 version **3** (not version 1 as in NFSv2). MOUNT v3 returns variable-length handles and auth flavor lists.

---

## 1. Portmapper -- Program 100000, Version 2

Port 111 (fixed). Defined in RFC 1057 Appendix A. Identical to the portmapper used for NFSv2. Same program, same version, same procedures. The only difference is the arguments: when resolving mountd for NFSv3, the client queries `GETPORT(100005, 3)` instead of `GETPORT(100005, 1)`.

| # | Procedure | nfswolf | Via | Correct | Purpose |
|---|-----------|---------|-----|---------|---------|
| 0 | `NULL` | No | -- | -- | No-op. Not needed; nfswolf never health-checks portmapper. |
| 1 | `SET` | No | -- | -- | Register an RPC service. Server-side only. |
| 2 | `UNSET` | No | -- | -- | Unregister an RPC service. Server-side only. |
| 3 | `GETPORT` | **Yes** | onc-rpcbind | Correct | Resolves mountd v3 port. Queries `(100005, 3, TCP)`. |
| 4 | `DUMP` | **Yes** | onc-rpcbind | Correct | Lists all registered RPC services. Reveals NFS versions (filters program 100003), NIS presence (programs 100004/100007), NetApp (program 400010), and amplification surface (F-3.2). |
| 5 | `CALLIT` | No | -- | -- | Indirect RPC call. Potential amplification vector but not implemented -- nfswolf estimates amplification from DUMP response size. |

### When port 111 is blocked

Same three bypasses as NFSv2:

- **`--mount-port PORT`** -- Specify mountd port directly.
- **Automatic fallback** -- Probes ports 2049 (Windows), 20048 (RHEL).
- **`--handle HEX`** -- Skip portmapper and mountd entirely.

Additionally, the scanner detects NFSv4 via a direct COMPOUND probe to port 2049 (`probe_nfs4`), independent of portmapper. If portmapper is filtered but port 2049 is open, the scanner reports "v4+" to indicate NFSv4 was confirmed outside the portmapper.

---

## 2. MOUNT -- Program 100005, Version 3

Dynamic port (assigned by portmapper). Defined in RFC 1813 Appendix I. Same 6 procedures as MOUNT v1 (NFSv2), but with two critical changes:

1. **Variable-length file handles** -- Up to 64 bytes (RFC 1813 Appendix I, FHSIZE3 = 64), vs fixed 32 bytes in v1. Allows servers to encode more complex metadata (filesystem UUIDs, generation numbers, parent references).

2. **Auth flavor list** -- MNT response includes a vector of supported authentication flavors. This reveals whether the export requires RPCSEC_GSS (Kerberos, flavor 6) or accepts AUTH_SYS (flavor 1). AUTH_SYS-only exports are vulnerable to credential spoofing (F-1.1).

| # | Procedure | nfswolf | Via | Correct | Purpose |
|---|-----------|---------|-----|---------|---------|
| 0 | `NULL` | **Yes** | nfs-mount | Correct | No-op. Used internally for mountd port probing. |
| 1 | `MNT` | **Yes** | nfs-mount | Correct | Path in, variable-length handle + auth flavors out. Auto-retries with privileged source port on MNT3ERR_ACCES (error 13). Auth flavors feed finding F-1.1. |
| 2 | `DUMP` | **Yes** | nfs-mount | Correct | Lists mounted clients (hostname + directory). Reveals active NFS consumers. |
| 3 | `UMNT` | **Yes** | nfs-mount | Correct | Stealth cleanup -- removes our entry from the mount table (F-2.5). |
| 4 | `UMNTALL` | **Yes** | nfs-mount | Correct | Removes all mount entries for our client hostname. |
| 5 | `EXPORT` | **Yes** | nfs-mount | Correct | Lists exports with ACL groups. Empty or wildcard groups = world-accessible (F-7.1). |

### When mountd is blocked

Same bypasses as NFSv2:

- **`--handle HEX`** -- Supply a handle directly. v3 handles are longer (typically 28-44 bytes on Linux, up to 64), so the hex string is correspondingly longer than v2's 64-char string.
- **Handle sources**: prior shell session (`handle` command), `escape` output, `brute-handle` with the STALE/BADHANDLE oracle, network captures.
- **`--nfs-port PORT`** -- Combine with `--handle` to specify a non-standard NFS port.

The SOCKS5 privileged-port limitation applies: proxied MOUNT requests use ephemeral source ports, which exports with the `secure` option reject. Workaround: obtain a handle via direct connection first, then use `--handle` for proxied sessions.

Note: unlike v2, MOUNT v3 tells you what auth the server expects. If you can reach mountd but get denied, check whether the export requires RPCSEC_GSS -- AUTH_SYS spoofing won't help there. nfswolf reports this as finding F-1.1 in the analyzer.

---

## 3. NFS -- Program 100003, Version 3

Port 2049 (conventional). Defined in RFC 1813 §3.3. The file service. Variable-length handles up to 64 bytes (RFC 1813 §2.5: `struct nfs_fh3 { opaque data<NFS3_FHSIZE>; }`). Same AUTH_SYS trust model as v2 -- credentials are not cryptographically verified (RFC 2623 §2.1). File handles remain bearer tokens (RFC 2623 §2.6).

| # | Procedure | nfswolf | Via | Correct | Purpose |
|---|-----------|---------|-----|---------|---------|
| 0 | `NULL` | **Yes** | nfs-v3 | Correct | No-op. Connectivity test. |
| 1 | `GETATTR` | **Yes** | nfs-v3 | Correct | Returns fattr3: type, mode, nlink, uid, gid, size (64-bit), used, rdev, fsid, fileid, atime, mtime, ctime. |
| 2 | `SETATTR` | **Yes** | nfs-v3 | Correct | Set attributes with optional guard (ctime check for atomic modify). |
| 3 | `LOOKUP` | **Yes** | nfs-v3 | Correct | Resolve one filename in a directory. Returns child file handle + attrs. Core path traversal. |
| 4 | `ACCESS` | **Yes** | nfs-v3 | Correct | **New in v3.** Advisory permission check. Returns bitmask of allowed operations (READ/LOOKUP/MODIFY/EXTEND/DELETE/EXECUTE). Used by UID sprayer to test credentials without triggering writes. **Advisory only** -- RFC 1813 §3.3.4: results may not reflect actual access. |
| 5 | `READLINK` | **Yes** | nfs-v3 | Correct | Read symbolic link target. |
| 6 | `READ` | **Yes** | nfs-v3 | Correct | Read file data. 64-bit offset (vs v2's 32-bit). Returns data + post-op attrs + EOF flag. |
| 7 | `WRITE` | **Yes** | nfs-v3 | Correct | **Enhanced in v3.** Supports `stable_how`: UNSTABLE (async), DATA_SYNC, FILE_SYNC. Returns bytes written + committed stability level + write verifier. v2 was FILE_SYNC-only. |
| 8 | `CREATE` | **Yes** | nfs-v3 | Correct | **Enhanced in v3.** Supports create modes: UNCHECKED (overwrite OK), GUARDED (fail if exists), EXCLUSIVE (atomic create with verifier). |
| 9 | `MKDIR` | **Yes** | nfs-v3 | Correct | Create directory. Returns handle + attrs + wcc_data. |
| 10 | `SYMLINK` | **Yes** | nfs-v3 | Correct | Create symbolic link. Returns handle + attrs (v2 returned only status). |
| 11 | `MKNOD` | **Yes** | nfs-v3 | Correct | **New in v3.** Create special files: sockets, FIFOs, block/char devices. Not in v2. |
| 12 | `REMOVE` | **Yes** | nfs-v3 | Correct | Delete a file. Returns wcc_data for cache consistency. |
| 13 | `RMDIR` | **Yes** | nfs-v3 | Correct | Remove directory. Returns wcc_data. |
| 14 | `RENAME` | **Yes** | nfs-v3 | Correct | Rename/move a file. Returns wcc_data for both source and destination directories. |
| 15 | `LINK` | **Yes** | nfs-v3 | Correct | Create hard link. Returns post-op attrs + wcc_data. |
| 16 | `READDIR` | **Yes** | nfs-v3 | Correct | List directory entries (fileid + name + cookie). Cookie-based pagination with 8-byte cookieverf for cache validation. |
| 17 | `READDIRPLUS` | **Yes** | nfs-v3 | Correct | **New in v3.** READDIR + file handles + full attrs for every entry. Eliminates N separate LOOKUP/GETATTR calls. Single call maps an entire directory. |
| 18 | `FSSTAT` | **Yes** | nfs-v3 | Correct | Filesystem space stats: total/free/available bytes and files. 64-bit counters (v2 was 32-bit blocks). |
| 19 | `FSINFO` | **Yes** | nfs-v3 | Correct | **New in v3.** Filesystem capabilities: max read/write/readdir sizes, time granularity, symlink/hardlink support, homogeneous flag. |
| 20 | `PATHCONF` | **Yes** | nfs-v3 | Correct | **New in v3.** POSIX pathconf values: max name length, no_trunc, chown_restricted, case_insensitive, case_preserving. |
| 21 | `COMMIT` | **Yes** | nfs-v3 | Correct | **New in v3.** Force unstable writes to stable storage. Returns write verifier -- if it differs from the WRITE response verifier, the server rebooted and data may be lost. Used with WRITE stable=UNSTABLE for async write pipelines. |

**Implementation**: 22 of 22 procedures implemented. All via the in-tree nfs-v3 library, which owns the XDR types and raw client. Unlike the NFSv2 client (hand-rolled domain API), the v3 client delegates all wire encoding to the library. `PooledTransport` (`src/proto/transport.rs`) handles connection pooling, circuit breaking, stealth delays, and credential injection transparently via the `RpcTransport` seam -- individual client methods contain no policy.

**Circuit breaker discrimination**: Permission errors (`NFS3ERR_ACCES`, `NFS3ERR_PERM`) do NOT trip the circuit breaker -- they are expected during UID spraying. Only transient errors (`NFS3ERR_IO`, `NFS3ERR_JUKEBOX`, `NFS3ERR_SERVERFAULT`) trip the breaker and poison the connection.

### When port 2049 is blocked

No bypass. Port 2049 is the file service. `--nfs-port PORT` supports servers on non-standard ports. The scanner probes 111 and 2049 by default; `--ports` adds additional ports.

---

## What v3 Adds Over v2 (Security-Relevant)

| Feature | v2 | v3 | Attack impact |
|---------|----|----|---------------|
| File handle size | Fixed 32 bytes | Variable, up to 64 bytes | Larger search space for blind brute-force, but STALE/BADHANDLE oracle compensates |
| File sizes | 32-bit (2 GB max) | 64-bit (unlimited) | No exfiltration size limit on v3 |
| STALE/BADHANDLE oracle | STALE only | STALE + BADHANDLE | v3 tells you when the handle format is correct vs wrong -- narrows brute-force to inode/gen sweep |
| ACCESS procedure | None | Advisory bitmask | Silent permission probing without triggering writes. Used by UID sprayer |
| READDIRPLUS | None | Returns handles + attrs | Map an entire directory tree in one call per directory instead of N+1 |
| MKNOD | None | Create sockets, FIFOs, devices | Create device files for privilege escalation (if writable) |
| Async writes | Synchronous only (FILE_SYNC) | UNSTABLE + COMMIT | Faster write attacks -- fire UNSTABLE writes then COMMIT once |
| FSINFO | None | Max read/write sizes, capabilities | Reveals server limits for tuning exfiltration chunk size |
| PATHCONF | None | Name length, case sensitivity | OS/FS fingerprinting (case_insensitive = Windows/macOS) |
| Auth negotiation | None | MOUNT v3 returns auth flavors | Reveals whether export requires Kerberos (F-1.1) before you waste time trying AUTH_SYS |
| Create modes | Overwrite only | UNCHECKED/GUARDED/EXCLUSIVE | EXCLUSIVE create with verifier for atomic operations |
| wcc_data | None | Weak cache consistency on mutating ops | Reveals pre/post attributes on writes -- confirms modifications succeeded |

### Auth model: unchanged

Despite the new features, the core security model is identical to v2. AUTH_SYS credentials are not signed or verified (RFC 2623 §2.1). File handles are bearer tokens (RFC 2623 §2.6). Any client on the network can claim any uid/gid. The `secure` export option (source port < 1024) is the only defense, and it is trivially bypassed on any system with root access.

NFSv3 adds the ability to *detect* whether Kerberos is required (via MOUNT auth flavors), but it does not add any mechanism to *enforce* stronger auth at the protocol level. AUTH_SYS remains the path of least resistance for attackers.
