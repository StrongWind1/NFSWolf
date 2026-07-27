# NFSv2 Protocol Reference

Technical companion guide for NFSv2 (RFC 1094, March 1989). Covers the three RPC services required for a complete NFSv2 session, what nfswolf implements for each, and how to operate when individual services are unreachable.

---

## Attack Path

### The happy path (all services reachable)

Three services cooperate. You need all three to go from "I have an IP" to "I'm reading files":

1. **Portmapper** (port 111) -- Ask: "what port is mountd on?" Get back a port number. That's all portmapper does for us. It maps RPC program numbers to ports. mountd runs on a random high port on Linux (e.g., 36801) so without portmapper you don't know where to connect.

2. **MOUNT** (random port) -- Ask: "give me a handle for `/export`." Get back a 32-byte opaque blob -- the **file handle**. This is the key to everything. MOUNT is the only place where human-readable path names appear. After this call, paths are gone -- everything is handles.

3. **NFS** (port 2049) -- Send the file handle with every operation. `LOOKUP(handle, "etc")` returns a new handle. `READ(handle, 0, 8192)` returns bytes. The file handle is the input to every single NFS call. No handle, no access.

### What if portmapper is blocked?

Portmapper only tells you the mountd port. Bypass:

- **`--mount-port PORT`** -- If you know the port from a prior scan, another host, or common defaults (2049 for Windows NFS, 20048 for RHEL/Fedora). nfswolf also auto-probes these fallback ports when portmapper is unreachable.
- **Skip mountd entirely** -- If you already have a file handle (see below), you don't need portmapper at all.

### What if mountd is blocked?

MOUNT converts a path string to a file handle. If mountd is down, you need to get a handle some other way:

- **`--handle HEX`** -- Supply a handle from a prior session, a network capture, or a brute-force run. nfswolf connects directly to nfsd on port 2049 and uses this handle as the root. No portmapper, no mountd.
- **`escape` output** -- A prior escape run prints the root handle. Save it. Use it later with `--handle`.
- **`brute-handle`** -- Generate candidate handles and probe nfsd directly. Needs a seed handle from somewhere, but once you have one export's handle you can forge handles for other inodes.

### What if you only have port 2049?

This is the minimum case: no portmapper, no mountd, just the NFS daemon. You need exactly one thing to operate: **a valid 32-byte file handle**.

The file handle is the sole input to NFSv2. Every procedure (GETATTR, LOOKUP, READ, WRITE, READDIR, etc.) takes a handle as its first argument. With a valid handle you can:

- `GETATTR(handle)` -- confirm it's valid, get file type/uid/gid/size
- `LOOKUP(handle, "etc")` -- traverse into child directory, get child handle
- `READDIR(handle)` -- list all entries in a directory
- `READ(handle, offset, count)` -- exfiltrate file contents
- Chain `LOOKUP` calls to walk the entire filesystem tree

### Can you blind brute-force file handles?

Yes, with caveats. A handle is 32 bytes (256 bits), but the entire space is NOT random:

**Linux ext4 handle structure** (typical):
```
[4B header] [4B export_inode] [4B export_gen] [16B UUID] [4B inode] [4B gen]
 fixed       known from seed   known           known      GUESS      GUESS
```

The filesystem UUID and export context are constant across all handles on the same export -- once you have one handle (from MOUNT or any other source), you know 24 of the 32 bytes. The unknowns are:

- **Inode number** (4 bytes, 32 bits) -- but root directories are always low inodes. ext4 root = inode 2, XFS root = inode 128 or 64. Most interesting files are in the first few thousand inodes.
- **Generation number** (4 bytes, 32 bits) -- assigned at file creation. Root directories typically have generation 0 (set at mkfs time). Other files get random 32-bit generations.

**Practical search space:**

| Target | Inode bits | Gen bits | Total | At 10k probes/sec |
|--------|-----------|---------|-------|-------------------|
| Root dir (inode 2, gen 0) | 1 | 0 | **1 probe** | Instant |
| Root dir (unknown gen) | 1 | 32 | 2^32 | ~5 days |
| Known inode, gen 0 | 0 | 0 | **1 probe** | Instant |
| Inode scan (first 1000) | 10 | 0 | 1,000 | 0.1 sec |
| Full inode + gen sweep | 32 | 32 | 2^64 | 58 million years |

The escape strategy works because root inodes are predictable (2 for ext4, 128 for XFS, 256+ for BTRFS) and generation 0 is the common case. Blind brute-force of the full 8-byte inode+generation space is infeasible, but targeted probes against known filesystem layouts succeed instantly.

**Rate limiting**: NFS servers do not rate-limit GETATTR calls. A single TCP connection can sustain 10,000+ GETATTR probes per second over a LAN. The server treats each as an independent stateless request. There is no lockout, no backoff, no detection mechanism in the protocol.

### Is port 2049 TCP only?

No. RFC 1094 §3.4: *"NFS is supported normally on UDP."* The original protocol was designed for UDP and port 2049 was a UDP port number. Most modern deployments use TCP (better for large reads/writes, survives packet loss), but many servers still accept both:

- **Linux nfsd**: TCP and UDP on port 2049 (both registered in portmapper by default).
- **Windows NFS**: TCP only on port 2049.
- **Legacy/embedded**: Some older HP-UX and NetApp configs are UDP-only.

nfswolf supports both: TCP is the default transport; `nfswolf scan --scan-udp` additionally probes over UDP for environments where TCP is filtered. The `call_rpc_udp()` function in `src/proto/udp.rs` handles single-shot UDP RPC calls without TCP record marking.

---

## Connection Flow

An NFSv2 session requires three cooperating RPC programs, each on its own TCP or UDP port:

```
Client                              Server
  |                                   |
  |-- PMAPPROC_GETPORT(100005,1) ---> |:111   portmapper
  |<-- port 36801 ------------------- |       "mountd is on 36801"
  |                                   |
  |-- MNTPROC_MNT("/export") ------> |:36801 mountd
  |<-- fhandle[32] + auth_flavors --- |       "here is your root handle"
  |                                   |
  |-- NFSPROC_LOOKUP(fh, "etc") ----> |:2049  nfsd
  |<-- new_fh + attrs --------------- |
  |-- NFSPROC_READ(new_fh, 0, 8192)-> |
  |<-- data ------------------------- |
```

The portmapper locates mountd; mountd converts a path string to a file handle; nfsd performs all subsequent file operations using that handle. Only nfsd is strictly required -- the other two are discovery mechanisms with well-documented bypasses.

---

## 1. Portmapper -- Program 100000, Version 2

Port 111 (fixed). Defined in RFC 1057 Appendix A. Maps `(program, version, protocol)` tuples to the port the service is listening on. Every ONC RPC service registers itself here on startup.

| # | Procedure | nfswolf | Via | Correct | Purpose |
|---|-----------|---------|-----|---------|---------|
| 0 | `NULL` | No | -- | -- | No-op. Not needed; nfswolf never health-checks portmapper. |
| 1 | `SET` | No | -- | -- | Register an RPC service. Server-side only. |
| 2 | `UNSET` | No | -- | -- | Unregister an RPC service. Server-side only. |
| 3 | `GETPORT` | **Yes** | nfswolf-rpc | Correct | Resolves mountd and NFS daemon ports by program number. Core discovery call. |
| 4 | `DUMP` | **Yes** | nfswolf-rpc | Correct | Lists every registered RPC service (program, version, protocol, port). Reveals NFS versions, NIS presence, NetApp services, and amplification surface. |
| 5 | `CALLIT` | No | -- | -- | Indirect RPC call routed through portmapper. Potential amplification vector, but nfswolf measures amplification via DUMP response size instead (F-3.2). |

### When port 111 is blocked

Portmapper is a convenience, not a hard dependency. nfswolf has three bypass paths:

- **`--mount-port PORT`** -- Specify the mountd port directly. Skips the GETPORT call entirely. Use when you already know the mountd port from a prior scan or from another host on the same network.
- **Automatic fallback** -- When portmapper is unreachable and no `--mount-port` is given, `NfsMountClient` probes well-known mountd ports before failing. It tries port 2049 first (Windows NFS multiplexes mountd and nfsd on the same port) then 20048 (the fixed mountd port used by RHEL/Fedora nfs-utils configurations). A MNTPROC_EXPORT call validates that the candidate port actually speaks the MOUNT protocol.
- **`--handle HEX`** -- Skip both portmapper and mountd entirely by supplying a file handle obtained from a prior session, an escape, or a brute-force run. nfswolf connects directly to nfsd on port 2049 (or `--nfs-port PORT`) and uses the supplied handle as the root.

DUMP results feed the scanner's version detection, NIS discovery, and amplification checks. When portmapper is filtered, these checks are silently skipped -- the scanner still reports the host based on direct TCP probes to port 2049 and NFSv4 COMPOUND probes.

---

## 2. MOUNT -- Program 100005, Version 1

Dynamic port (assigned by portmapper, typically high-numbered on Linux). Defined in RFC 1094 Appendix A. Converts an export path string into a 32-byte file handle. The MOUNT protocol is the only place where human-readable path names appear on the wire; after MNT succeeds, all operations reference files by opaque handle only.

| # | Procedure | nfswolf | Via | Correct | Purpose |
|---|-----------|---------|-----|---------|---------|
| 0 | `NULL` | **Yes** | nfswolf-nfs2 | Correct | No-op. Available for connectivity testing. |
| 1 | `MNT` | **Yes** | nfswolf-nfs2 | Correct | The critical call: path in, file handle out. Also returns supported auth flavors (AUTH_SYS, RPCSEC_GSS, etc.). Handles MNT3ERR_ACCES auto-retry with privileged source ports. |
| 2 | `DUMP` | **Yes** | nfswolf-nfs2 | Correct | Lists clients that currently have exports mounted (hostname + directory). Reveals who else is using the server. |
| 3 | `UMNT` | **Yes** | nfswolf-nfs2 | Correct | Removes our mount entry from the server's table. Stealth cleanup -- prevents `showmount -a` from revealing our activity (F-2.5). |
| 4 | `UMNTALL` | **Yes** | nfswolf-nfs2 | Correct | Removes ALL mount entries for our client hostname. |
| 5 | `EXPORT` | **Yes** | nfswolf-nfs2 | Correct | Lists every export with its allowed-host ACL groups. Core recon call for the scanner and analyzer. |

### When mountd is blocked

Mountd's sole purpose is converting a path to a file handle. If you already have a handle, mountd is unnecessary:

- **`--handle HEX`** -- Provide a raw file handle on the command line. nfswolf skips MOUNT entirely and connects directly to nfsd. Handles can be obtained from:
  - A prior `nfswolf shell` session (the `handle` command prints the current file handle)
  - The `escape` command output (prints the escaped root handle)
  - The `brute-handle` command (probes candidate handles via GETATTR)
  - Network captures (handles travel on the wire in cleartext unless TLS is in use)
- **`--nfs-port PORT`** -- When combined with `--handle`, specifies the NFS port to connect to directly. Defaults to 2049.
- **`escape` and `brute-handle`** -- These commands need mountd for their initial seed handle, but the handles they produce can then be used with `--handle` in subsequent sessions even if mountd goes down between runs.

Note that the MOUNT protocol enforces the `secure` export option (source port < 1024) separately from nfsd. When operating through a SOCKS5 proxy, privileged port binding is impossible -- the proxy controls the outbound port. Exports with the `secure` option will reject proxied MOUNT requests with MNT3ERR_ACCES (error 13). The workaround is to obtain a handle through a direct connection first, then use `--handle` for proxied sessions.

---

## 3. NFS -- Program 100003, Version 2

Port 2049 (conventional, not fixed by the protocol). Defined in RFC 1094 §2.2. The actual file service. All operations use 32-byte opaque file handles (RFC 1094 §2.3.3: `typedef opaque fhandle[FHSIZE]`). The server trusts the AUTH_SYS credential in each RPC call without cryptographic verification (RFC 2623 §2.1). File handles are bearer tokens -- anyone holding a valid handle can access the file regardless of credentials (RFC 2623 §2.6).

| # | Procedure | nfswolf | Via | Correct | Purpose |
|---|-----------|---------|-----|---------|---------|
| 0 | `NULL` | **Yes** | nfswolf-nfs2 | Correct | No-op. Connectivity test. |
| 1 | `GETATTR` | **Yes** | nfswolf-nfs2 | Correct | Returns file type, mode, uid, gid, size, timestamps. XDR `attrstat` union decoded correctly (status-only on error). |
| 2 | `SETATTR` | **Yes** | nfswolf-nfs2 | Correct | Changes mode, uid, gid, size, timestamps. Uses `SATTR_UNCHANGED` sentinel (0xFFFFFFFF) per RFC 1094 §2.3.6. |
| 3 | `ROOT` | **Yes** | nfswolf-nfs2 | Correct | **Obsolete probe.** RFC 1094 §2.2.3: *"This procedure is no longer used."* nfswolf sends it deliberately as a MOUNT-bypass check: if a server responds with a handle, any client can obtain the root handle without going through mountd's export ACLs. Linux knfsd returns an empty/error response (tested on kernel 4.4 and 4.15). |
| 4 | `LOOKUP` | **Yes** | nfswolf-nfs2 | Correct | Resolves one filename in a directory to a new file handle. Path traversal is done by chaining repeated LOOKUPs (one component at a time). |
| 5 | `READLINK` | **Yes** | nfswolf-nfs2 | Correct | Reads the target path of a symbolic link. |
| 6 | `READ` | **Yes** | nfswolf-nfs2 | Correct | Reads bytes from a file. `totalcount` field set to 0 per RFC. `read_file()` helper reads entire files in 64 KB chunks. |
| 7 | `WRITECACHE` | No | -- | -- | **Reserved.** RFC 1094 §2.2.8: not implemented by any known server. |
| 8 | `WRITE` | **Yes** | nfswolf-nfs2 | Correct | Writes bytes to a file. Always synchronous in v2 -- server must flush to stable storage before returning (RFC 1094 §2.2). `beginoffset` and `totalcount` set to 0 per RFC. |
| 9 | `CREATE` | **Yes** | nfswolf-nfs2 | Correct | Creates a new file. Returns file handle + attrs. |
| 10 | `REMOVE` | **Yes** | nfswolf-nfs2 | Correct | Deletes a file. Non-idempotent -- retry after timeout may return NOENT. |
| 11 | `RENAME` | **Yes** | nfswolf-nfs2 | Correct | Renames or moves a file. Atomic on the server. |
| 12 | `LINK` | **Yes** | nfswolf-nfs2 | Correct | Creates a hard link. |
| 13 | `SYMLINK` | **Yes** | nfswolf-nfs2 | Correct | Creates a symbolic link. |
| 14 | `MKDIR` | **Yes** | nfswolf-nfs2 | Correct | Creates a directory. Returns file handle + attrs. |
| 15 | `RMDIR` | **Yes** | nfswolf-nfs2 | Correct | Removes a directory. Non-idempotent. |
| 16 | `READDIR` | **Yes** | nfswolf-nfs2 | Correct | Lists directory entries (fileid + name + cookie). Cookie-based pagination with XDR boolean-preceded linked list. Handles EOF flag. |
| 17 | `STATFS` | **Yes** | nfswolf-nfs2 | Correct | Returns filesystem stats: optimal transfer size, block size, total/free/available blocks. |

**Implementation**: All 18 procedures are implemented in `crates/nfswolf-nfs2/src/{wire.rs,client.rs}`, including ROOT (as a MOUNT-bypass probe) and WRITECACHE (as a reserved no-op). The binary links `nfswolf-nfs2` and `--nfs-version 2` enters a v2 shell via MOUNT v1 MNT. The v2 shell supports `--handle HEX` for MOUNT bypass (connect directly to nfsd with a known handle, skipping portmapper and mountd) and `-c "command"` for non-interactive scripting mode. `brute-handle` and `escape` automatically fall back to NFSv2 when the target server does not support v3 or when v3 enforces Kerberos. Live-tested against Ubuntu 14 (kernel 4.4) and Ubuntu 18 (kernel 4.15).

### When port 2049 is blocked

There is no bypass. Port 2049 (or whatever port nfsd listens on) is the actual file service. If it is unreachable, no NFS operations are possible.

nfswolf supports `--nfs-port PORT` for servers running nfsd on a non-standard port. The scanner probes both port 111 and 2049 by default and can be pointed at additional ports with `--ports`.

---

## NFSv2 Security Properties

These properties make NFSv2 the preferred downgrade target for attackers when a server supports both v2 and v3/v4:

- **No auth negotiation** (RFC 2623 §2.7) -- NFSv2 has no mechanism for negotiating stronger authentication. There is no equivalent of NFSv3's MOUNT auth flavor list or NFSv4's SECINFO. The server accepts whatever AUTH_SYS credentials the client sends.
- **No ACCESS procedure** -- NFSv2 has no way to check permissions before attempting an operation. The client simply tries READ/WRITE/LOOKUP and handles the error. This makes permission probing noisier on v2.
- **Fixed 32-byte handles** -- Simpler to brute-force than v3's variable-length handles (up to 64 bytes). The fixed size means fewer bits to guess, though the inode/generation encoding is still server-specific.
- **32-bit file sizes** -- Maximum 2 GB file size. Not a security issue but a limitation for exfiltrating large files.
- **Synchronous writes only** -- Every WRITE must be flushed to stable storage before the server replies. No `stable_how::UNSTABLE` option. Slower than v3 but guarantees data persistence.
- **No STALE/BADHANDLE distinction** -- NFSv2 only has `NFSERR_STALE` (error 70). There is no `BADHANDLE` error code, so the handle oracle that works on v3 (right format vs wrong format) is not available. Handle brute-forcing on v2 is blind -- STALE means "invalid" without distinguishing format errors from inode/generation misses.
