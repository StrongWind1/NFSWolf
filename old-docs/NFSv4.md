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
- **LOOKUPP** -- Look up the parent directory from any file handle. This enables export escape (walk above the export root) and cross-export lateral movement (discover sibling exports via upward traversal). On v3, parent traversal depends on server interpretation of LOOKUP("..").
- **Full stateful operations** -- nfswolf implements the complete SETCLIENTID lifecycle, OPEN/CLOSE with stateid tracking, LOCK/LOCKU, and crash recovery. Write attacks, file creation, and lock-based DoS all work natively over v4 without falling back to v3.

**What hurts the attacker:**

- **No STALE/BADHANDLE oracle** -- NFSv4 uses different error semantics. The clean STALE-vs-BADHANDLE distinction from v3 that makes handle brute-forcing efficient is less reliable on v4 servers. Handle forging is a v2/v3 attack.
- **Kerberos is mandatory in the spec** -- RFC 7530 section 3.2.1 says RPCSEC_GSS with Kerberos V5 is mandatory to implement. In practice, most servers still accept AUTH_SYS (the spec says MAY for other flavors), but properly hardened v4 deployments are more likely to enforce Kerberos than v3 deployments.
- **TCP required** -- RFC 7530 section 3.1 mandates TCP. No UDP support. You can't IP-spoof with TCP like you can with UDP on v2/v3.

**The one thing that matters most:** If the server accepts AUTH_SYS on NFSv4, you have the same credential-spoofing attack surface as v2/v3 but with easier recon (SECINFO, pseudo-FS, single port) and full write/create/lock capability. If it enforces Kerberos, v4 is the hardest version to attack -- try downgrading to v3 or v2 instead.

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
  |-- COMPOUND[ SETCLIENTID,       --> |
  |             SETCLIENTID_CONFIRM ]  |
  |<-- clientid + lease -------------- |
  |                                    |
  |-- COMPOUND[ PUTFH(dir),        --> |
  |             OPEN("target"),        |
  |             READ(stateid) ]        |
  |<-- file data --------------------- |
  |                                    |
  |-- COMPOUND[ PUTFH(dir),        --> |
  |             OPEN_WRITE("out"),     |
  |             WRITE(stateid, data),  |
  |             CLOSE(stateid) ]       |
  |<-- write confirmed --------------- |
```

One port. One RPC procedure (COMPOUND). Multiple operations batched per call. No portmapper, no MOUNT daemon, no extra ports to discover. Full read/write/create/lock capability.

### What if port 2049 is blocked?

No bypass. NFSv4 runs exclusively on port 2049 over TCP. There is no UDP option (RFC 7530 section 3.1). If port 2049 is filtered, NFSv4 is unreachable. `--nfs-port PORT` supports non-standard ports.

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

**LOOKUPP** for cross-export discovery:
```
COMPOUND([PUTFH(export_fh), LOOKUPP, GETFH])
--> parent directory handle above the export root

COMPOUND([PUTFH(parent_fh), READDIR])
--> sibling exports visible from the parent directory
```

This is the v4 equivalent of export escape and powers the `exports` shell command (F-2.12).

### Export escape on v4-only servers

When the MOUNT protocol is firewalled, the v4 escape pipeline provides a pure-NFSv4 path. `find_escape_v4` acquires seed handles via PUTROOTFH + LOOKUP and runs the full escape algorithm against each. `Nfs4EscapeProbe` implements the `EscapeProbe` trait, supporting all 18 filesystem types. The `escape --all` flag acquires seed handles from MOUNT v3, MOUNT v1, and NFSv4 LOOKUP, running the full escape against each source.

### Can you brute-force v4 file handles?

Not effectively. The v3 STALE/BADHANDLE oracle does not apply to v4 in the same way. NFSv4 defines both `NFS4ERR_STALE` (70) and `NFS4ERR_BADHANDLE` (10001), but servers do not return them as consistently as v3 -- the clean format/content distinction that makes v3 brute-forcing efficient is less reliable. Additionally, v4 handles can be **volatile** (RFC 7530 section 4.2.3) -- the server may change them at any time, especially for pseudo-filesystem entries.

Handle forging and brute-forcing are v2/v3 attacks. On v4, use SECINFO + PUTROOTFH + LOOKUP + LOOKUPP for namespace discovery and escape instead.

### Stateful operations: reads, writes, locks

nfswolf implements the full NFSv4 state machine:

- **SETCLIENTID + SETCLIENTID_CONFIRM** -- Establishes a client identity and lease with the server. Managed by `Nfs4Session` with automatic lease renewal.
- **OPEN** -- Opens files for read or write, returning a stateid that authorizes subsequent I/O. `open_read()` and `open_write()` in the client API.
- **READ/WRITE with stateids** -- File I/O using the stateid from OPEN. `read_via_open()` and `write_via_open()` handle the full open-read/write-close cycle. For world-readable files, the anonymous stateid (seqid=0, other=all-zeros per RFC 7530 section 9.1.4.3) still works without OPEN.
- **CLOSE** -- Releases the open state. Tracked per open-owner via `OpenState`.
- **LOCK/LOCKT/LOCKU** -- Byte-range locking with lock-owner tracking via `LockState`.
- **Crash recovery** -- `OpenState` and `LockState` support reclaim operations after server restart.

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
  |-- COMPOUND [SETCLIENTID,       -->  |
  |             SETCLIENTID_CONFIRM]    |
  |<-- clientid + confirm ----------    |
  |                                     |
  |-- COMPOUND [PUTFH(root_fh),    -->  |
  |             LOOKUP("srv"),          |
  |             LOOKUP("nfs"),          |
  |             LOOKUP("public"),       |
  |             GETFH,                  |
  |             READDIR]                |
  |<-- directory listing + handle -----  |
```

No portmapper. No MOUNT. One TCP connection. All operations batched. Session establishment (SETCLIENTID) is automatic when stateful operations are needed.

---

## 1. Portmapper

**Not used.** NFSv4 always runs on port 2049 (RFC 7530 section 3.1). There is no portmapper dependency. The scanner still probes portmapper to detect v2/v3 registrations, but v4 is discovered via a direct COMPOUND probe to port 2049.

nfswolf's scanner sends `COMPOUND([PUTROOTFH])` to port 2049 and checks for `NFS4_OK` (`probe_nfs4()` in `src/proto/nfs4/compound.rs`). This works even when portmapper is completely filtered.

---

## 2. MOUNT Protocol

**Not used.** NFSv4 integrates mount functionality into the protocol itself (RFC 7530 section 1.4.3). PUTROOTFH replaces MNT for getting the initial handle. The pseudo-filesystem replaces EXPORT for listing available paths.

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

Port 2049 (mandatory). TCP required (RFC 7530 section 3.1). Defined in RFC 7530.

NFSv4 has only two RPC procedures: NULL (proc 0) and COMPOUND (proc 1). All file operations are expressed as **operations** batched inside COMPOUND. RFC 7530 defines 38 operations (37 in ops 3-39, plus ILLEGAL op 10044).

The `nfs-v4` crate implements all 37 NFSv4.0 operations (ops 3-39) plus ILLEGAL (op 10044) as fully typed `ArgOp` variants with response decoders, plus 4 NFSv4.1 operations (EXCHANGE_ID op 42, GETDEVICEINFO op 47, GETDEVICELIST op 48, SECINFO_NO_NAME op 52). NFSv4.2 security labels are supported via `FATTR4_SEC_LABEL` and `SecLabel4` (RFC 7862). The `Nfs4Client` provides 47 public methods covering path resolution, directory operations, stateful file I/O, locking, session management, and security negotiation. The crate has 244 tests.

### All 37 operations

Every operation listed below is fully typed with argument encoding and response decoding in `crates/nfs-v4/src/wire.rs`.

| Op | Name | nfswolf use | Purpose |
|----|------|-------------|---------|
| 3 | `ACCESS` | Shell, analyzer | Check access permissions against current credentials (RFC 7530 section 18.1) |
| 4 | `CLOSE` | Shell (file I/O) | Release open state, return stateid. Tracked by `OpenState` |
| 5 | `COMMIT` | Shell (write ops) | Flush async writes to stable storage |
| 6 | `CREATE` | Shell (`mkdir`, `link`, etc.) | Create non-regular files (directories, symlinks, devices) |
| 7 | `DELEGPURGE` | Wire-representable | Purge delegations awaiting recovery |
| 8 | `DELEGRETURN` | Wire-representable | Return a delegation to the server |
| 9 | `GETATTR` | Shell, analyzer, escape | Get file attributes via bitmap requests (type, size, fsid, owner, mode) |
| 10 | `GETFH` | Shell, analyzer, escape | Return current filehandle as opaque bytes |
| 11 | `LINK` | Shell (`link` command) | Create hard link |
| 12 | `LOCK` | Client API | Byte-range lock with lock-owner tracking via `LockState` |
| 13 | `LOCKT` | Client API | Test for conflicting lock |
| 14 | `LOCKU` | Client API | Release byte-range lock |
| 15 | `LOOKUP` | Shell, analyzer, escape | Resolve one path component, sets current FH |
| 16 | `LOOKUPP` | Shell (`exports`), escape | Look up parent directory -- enables export escape and cross-export lateral (F-2.12) |
| 17 | `NVERIFY` | Wire-representable | Conditional: proceed only if attributes differ |
| 18 | `OPEN` | Shell (read/write) | Open file with stateid. `open_read()` and `open_write()` in client API |
| 19 | `OPENATTR` | Wire-representable | Access named attribute directory |
| 20 | `OPEN_CONFIRM` | Session management | Confirm open (used by `Nfs4Session`) |
| 21 | `OPEN_DOWNGRADE` | Wire-representable | Reduce open mode without closing |
| 22 | `PUTFH` | Shell, analyzer, escape | Set current FH to a known handle |
| 23 | `PUTPUBFH` | Analyzer | Set current FH to server's public (WebNFS) handle |
| 24 | `PUTROOTFH` | Shell, analyzer, escape | Set current FH to pseudo-root. The v4 replacement for MOUNT |
| 25 | `READ` | Shell (file reads) | Read file data using stateid (OPEN or anonymous) |
| 26 | `READDIR` | Shell, analyzer | List directory entries with inline attributes |
| 27 | `READLINK` | Shell (`readlink`) | Read symlink target |
| 28 | `REMOVE` | Shell (`rm`) | Remove file or directory |
| 29 | `RENAME` | Shell (`mv`) | Rename file or directory |
| 30 | `RENEW` | Session management | Renew client lease. Called automatically by `Nfs4Session` |
| 31 | `SAVEFH` | Rename/link ops | Save current FH to saved-FH slot |
| 32 | `RESTOREFH` | Rename/link ops | Restore saved FH to current-FH slot |
| 33 | `SECINFO` | Analyzer, shell | Query auth flavors per path. Decodes RPCSEC_GSS sub-fields (OID, QOP, service) |
| 34 | `SETATTR` | Shell (`chmod`, `chown`) | Modify file attributes |
| 35 | `SETCLIENTID` | Session management | Establish client identity with server |
| 36 | `SETCLIENTID_CONFIRM` | Session management | Confirm client identity |
| 37 | `VERIFY` | Wire-representable | Conditional: proceed only if attributes match |
| 38 | `WRITE` | Shell (file writes) | Write file data using stateid from OPEN |
| 39 | `RELEASE_LOCKOWNER` | Wire-representable | Release lock owner state |
| 10044 | `ILLEGAL` | Error sentinel | Server returns this for unrecognized op numbers |

**Status codes**: `Nfs4Status` carries 66 named variants (Ok + 65 error codes) plus an `Unknown(u32)` catch-all. Classification predicates `is_permission_denied()`, `is_stale()`, and `is_not_found()` are available. `Nfs4Error<E>` (in `crates/nfs-v4/src/client.rs`) has three variants: `Rpc(E)`, `Status(Nfs4Status)`, and `MissingResult`.

### Stateful infrastructure

The `nfs-v4` crate implements the full NFSv4.0 state machine:

| Component | File | Purpose |
|-----------|------|---------|
| `Nfs4Session` | `crates/nfs-v4/src/session.rs` | SETCLIENTID lifecycle, lease renewal, clientid storage |
| `OpenState` | `crates/nfs-v4/src/state.rs` | Stateid tracking per open-owner, seqid sequencing, crash recovery reclaim |
| `LockState` | `crates/nfs-v4/src/state.rs` | Lock-owner management, byte-range lock tracking |

The session is established automatically when `V4Ops` connects. Lease renewal happens in the background. Open-owner sequencing ensures the seqid increments correctly across OPEN/CLOSE/LOCK cycles, which is the trickiest part of NFSv4 state management to get right.

### Client API (47 public methods)

The `Nfs4Client<T>` in `crates/nfs-v4/src/client.rs` exposes 47 methods organized by category:

**Path resolution**: `lookup`, `getattr`, `readlink` -- navigate the namespace and inspect files.

**Directory operations**: `readdir_plus`, `mkdir`, `remove`, `rename`, `link`, `symlink` -- full directory manipulation.

**Stateful file I/O**: `open_read`, `open_write`, `close_file`, `read_via_open`, `write_via_open`, `read_file`, `write_file` -- complete open-read/write-close cycles with automatic stateid management.

**Security**: `secinfo` -- per-path auth flavor probing with GSS mechanism decoding.

**Domain types**: `Nfs4FileInfo`, `Nfs4DirEntry`, `Nfs4FileType` -- high-level types matching the v3 domain API style.

### NFSv4 client variants

nfswolf has two NFSv4 clients for different use cases:

**`Nfs4Client`** (pool-backed, `src/proto/nfs4/compound.rs`): The primary v4 client. Used by the analyzer for SECINFO probes and pseudo-FS mapping, by the interactive v4 shell (`--nfs-version 4`), and by the escape engine for v4-only servers. Shares the connection pool and circuit breaker with v3 calls via `PooledTransport`. Carries `Nfs4Session` for stateful operations.

**`Nfs4DirectClient`** (direct TCP, `src/proto/nfs4/compound.rs`): Used by the scanner's v4 probe (`probe_nfs4()`). Connects directly to port 2049 without the connection pool.

| Method | Operations | Purpose |
|--------|-----------|---------|
| `connect(addr)` | (TCP connect) | Connect with AUTH_NONE |
| `connect_with_auth(addr, uid, gid, hostname)` | (TCP connect) | Connect with AUTH_SYS |
| `reconnect_with_auth(uid, gid, hostname)` | (TCP reconnect) | Change credentials mid-session |
| `get_root_fh()` | PUTROOTFH + GETFH | Get pseudo-root handle |
| `lookup_fh(components)` | PUTROOTFH + LOOKUP chain + GETFH | Navigate to path, get handle |
| `list_dir(dir_fh)` | PUTFH + READDIR | List directory entries |
| `read_chunk(file_fh, offset, count)` | PUTFH + READ (anon stateid) | Read file data without OPEN |

### Shell integration: all 52 commands

`V4Ops` in `src/shell/v4.rs` implements `ShellOps`, giving the v4 shell the complete unified command set -- the same 52 commands available in the v2 and v3 shells. The v4 shell is entered via `nfswolf shell --nfs-version 4` or by auto-detection (see below).

All commands work over NFSv4 COMPOUND operations:

| Category | Commands |
|----------|----------|
| Navigation | `cd`, `ls`, `ll`, `dir`, `pwd`, `tree` |
| File read | `cat`, `type`, `get`, `download`, `get -r` (recursive) |
| File write | `put`, `put -r` (recursive), `mkdir` -- requires `--allow-write` |
| File ops | `rm`, `mv`, `link`, `readlink`, `stat`, `chmod`, `chown` |
| Identity | `uid`, `gid`, `hostname`, `whoami`, `id` |
| Security analysis | `secrets-scan`, `suid-scan`, `world-writable`, `find` |
| Escape | `escape-root`, `mount-handle`, `exports` (LOOKUPP-based, F-2.12) |
| Handle | `handle`, `root` |
| Local | `lcd`, `lls`, `lpwd`, `lmkdir` |
| Session | `help`, `history`, `last`, `lastb`, `lastlog` |

Credential escalation uses `try_with_escalation()` shared across v2, v3, and v4. When a read or write is denied, the credential ladder is walked automatically. Credential caching is shared through `CredCache` in `shell/ops.rs`.

### Auto-version detection

When `--nfs-version` is omitted, `resolve_version` probes in order: v3 (portmapper GETPORT + NULL verification), v2 (portmapper GETPORT + NULL verification), v4 (direct COMPOUND to port 2049). The first version that responds successfully is selected. This means v4-only servers (no portmapper, no MOUNT) are detected and the full shell works automatically.

### When port 2049 is blocked

No bypass. Port 2049 over TCP is the only transport (RFC 7530 section 3.1). No UDP fallback exists for NFSv4.

---

## NFSv4 Security Properties

### What changed from v3

| Property | v3 | v4 | Impact |
|----------|----|----|--------|
| Auth negotiation | MOUNT response (one-time) | SECINFO per-path (dynamic) | Attacker can probe auth requirements per directory without triggering denials |
| Kerberos | Optional (most servers don't enforce) | Mandatory to implement (RFC 7530 section 3.2.1) | More v4 deployments enforce Kerberos, but AUTH_SYS still accepted on many |
| Transport | TCP or UDP | TCP only | No IP spoofing via UDP source address forgery |
| IP-based ACLs | MOUNT-time check, often not re-checked | Per-RPC checks more common (server tracks state) | Harder to bypass with stolen handles on well-configured v4 servers |
| File handles | Variable up to 64B, persistent | Variable, persistent or volatile | Volatile handles make brute-forcing unreliable -- handle may change between probes |
| Handle oracle | STALE vs BADHANDLE (distinct errors) | STALE + BADHANDLE both defined, but less reliably distinguished by servers | Handle brute-forcing oracle is unreliable on v4. v3 is better for this attack |
| State | Stateless (every call independent) | Stateful (SETCLIENTID, OPEN, leases) | nfswolf implements the full state machine: reads, writes, locks, and crash recovery all work on v4 |
| Parent traversal | LOOKUP("..") -- server-dependent | LOOKUPP (op 16) -- protocol-guaranteed | Export escape and cross-export discovery work reliably on v4 |

### Kerberos on v4

RFC 7530 section 3.2.1 says RPCSEC_GSS with Kerberos V5 is mandatory to implement. In practice:

- **Linux knfsd**: Supports Kerberos but defaults to `sec=sys`. Most exports accept AUTH_SYS unless explicitly configured with `sec=krb5`.
- **Windows NFS**: Typically Kerberos-integrated via Active Directory. More likely to enforce krb5 than Linux.
- **Appliance NFS (NetApp, EMC)**: Varies. Enterprise deployments often enforce Kerberos on v4 while leaving v3 on AUTH_SYS.

nfswolf's SECINFO probe detects which flavors a specific path requires. If AUTH_SYS (flavor 1) appears in the SECINFO response, credential spoofing works. If only RPCSEC_GSS (flavor 6) appears, downgrade to v3 or v2 (where Kerberos enforcement may be weaker or absent).

### The pseudo-root is not an export

The pseudo-root handle from PUTROOTFH points to a virtual namespace constructed by the server, not to a real filesystem. You can READDIR on it to list exported paths, but the files you see are synthetic directory entries bridging gaps between exports.

nfswolf detects the Linux pseudo-root by checking the fsid against the well-known UUID `39c6b5c1-3f24-4f4e-977c-7fe6546b8a25` (defined in `src/proto/nfs4/mod.rs`). When the root fsid matches this UUID, the current directory is the pseudo-root, not a real export.

Export boundaries are detected by fsid changes during LOOKUP traversal. When the fsid returned by GETATTR differs from the parent's fsid, you have crossed into a real exported filesystem.
