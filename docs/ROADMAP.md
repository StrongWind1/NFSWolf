# Roadmap -- future work, research, and new capabilities

Everything aspirational for nfswolf and its protocol crates. Organized by readiness: what can be built now, what needs research, and what is blocked. Security value drives priority: data access and code execution first, recon and DoS last.

Source references: X/Open CAE C702 "XNFS, Version 3W" at `ref/xopen-c702.pdf` (352 pages), D030 "(PC)NFS" at `ref/archive.opengroup.org/archive/CDROM/d030.pdf` (164 pages), RFCs in `ref/rfc/`, IANA registries at `ref/all_rfcs/`.

---

## Contents

- [Ready to build](#ready-to-build) -- wire format documented, implementation path clear
- [New protocol crates](#new-protocol-crates) -- standalone RPC program clients
- [Analyzer and scanner enhancements](#analyzer-and-scanner-enhancements) -- improvements to existing modules
- [OS fingerprinting](#os-fingerprinting) -- additional detection signals
- [NFSv4 recon operations](#nfsv4-recon-operations) -- remaining v4 probes
- [Cross-protocol attack chains](#cross-protocol-attack-chains) -- multi-protocol sequences
- [Crate publication](#crate-publication) -- publish to crates.io
- [Protocol reference](#protocol-reference) -- wire formats, XDR definitions, security analysis
- [Out of scope](#out-of-scope) -- explicitly deferred

---

## Ready to build

### RQUOTA -- UID enumeration via quota oracle

**Program 100011, v1/v2. 3 procedures each. Low effort.**

`GETQUOTA` takes a path + UID and returns disk usage if the UID exists on the server. This is a UID existence oracle without NFS export access -- faster than `uid-spray` because it probes identity existence without attempting file operations. v2 adds GID quota enumeration.

`rq_bsize` in the response leaks the filesystem block size (ext4=4096, XFS=512, ZFS=1024), narrowing the escape strategy before even running NFS. Active UIDs feed `credential_ladder_with()`.

**Wire format:** full XDR for both versions documented below in the [protocol reference](#rquota-wire-format).

### NFS_ACL -- permission bypass beyond mode bits

**Program 100227, v2/v3. 3-5 procedures. Medium effort.**

`GETACL` returns POSIX ACL entries revealing UIDs/GIDs with access beyond what mode bits show. ACL entries reference UIDs/GIDs that may own zero files (invisible to READDIRPLUS harvesting). Default ACL inheritance creates systemic false sense of security.

No public spec exists. Wire format reverse-engineered from Linux kernel source (`fs/nfsd/nfs2acl.c`, `fs/nfsd/nfs3acl.c`) and Solaris `nfsacl_prot.x`. Fully documented below.

### PCNFSD -- password oracle and code execution

**Program 150001, v1. 4 procedures. Medium effort.**

`PCNFSD_AUTH` (proc 1): password oracle. Takes username + password "obfuscated" via XOR 0x5b. Returns uid/gid on success, or a spec-sanctioned fail-open mode (`AUTH_RES_FAKE`) that hands back usable credentials even on failed auth. No rate limiting, no lockout.

`PCNFSD_PR_START` (proc 3): unauthenticated code execution. Accepts a bare username with zero cryptographic link to auth, changes effective user identity, spawns subprocess. On a server running pcnfsd, this is unauthenticated command execution.

Rare on modern systems but legacy SunOS/Solaris PC-NFS gateways persist in enterprise environments. Detection is already implemented (portmapper DUMP for program 150001 with security note). Full exploitation is the remaining work.

### Portmapper CALLIT -- amplification and relay primitive

**3 missing procedures: SET, UNSET, CALLIT. Low-medium effort.**

`CALLIT` (proc 5) forwards an RPC call to a local program over UDP and returns the result. Attack surface: UDP amplification (small request -> larger response with spoofed source IP), relay to programs on non-standard ports, and probing programs not directly reachable by the attacker. This is the primitive behind finding F-3.2, which the tool reports but cannot demonstrate.

---

## New protocol crates

Build as modules inside `nfswolf` first. Promote to standalone crates only when an external consumer needs them.

### nfs-nis -- credential store dump (programs 100004 + 100007)

**15 total procedures (12 ypserv + 3 ypbind). High effort.**

`YPPROC_ALL` on `passwd.byname` dumps the entire credential store (every uid/gid/home/shell). `group.byname` gives group membership. `netgroup` reveals NFS export ACL membership. Domain name discovery via ypbind `YPBINDPROC_DOMAIN`.

Transforms `uid-spray` from a blind sweep to a targeted dictionary attack. Maps from `passwd.byname`:

| Map | Content | Attack use |
|-----|---------|-----------|
| `passwd.byname` | uid, gid, home, shell for every user | Credential ladder input |
| `group.byname` | group membership | Auxiliary GID injection targets |
| `netgroup` | host/user/domain triples | Export ACL membership |
| `hosts.byname` | hostname -> IP | Export ACL impersonation |
| `mail.aliases` | alias -> expansion | Lateral movement |

Wire format: Sun `yp.x`. Full XDR documented in the protocol reference below.

### onc-rpcsec-gss -- GSS-API security layer

**High effort. Blocked on Kerberos infrastructure for full context establishment.**

The recon-only portion (OID parsing, SECINFO interpretation, `SecInfoEntry` with mechanism/QOP/service) is already implemented in `nfs-v4`. What remains is the client-side context establishment: `RPCSEC_GSS_INIT` handshake, per-message MIC/wrap, and the v2/v3 extensions (channel bindings, structured privileges).

Deferred until a consumer exists. The recon value is already captured.

---

## Analyzer and scanner enhancements

### Completed

- **ZFS escape handles** -- `construct_zfs_root_handle` using `zfid_short_t` layout with `gen=0` bypass. Lab-tested.
- **AUTH_SHORT token capture and replay** -- shell captures opaque tokens from server reply verifiers and replays them via `--short-token`. PCAP-based offline capture remains out of scope.
- **AUTH_DH cryptographic sessions** -- full RFC 2695 implementation behind the `auth-dh` feature: DH key exchange, DES encryption, timestamp verification. `--auth-dh-netname`/`--auth-dh-pubkey` CLI flags.
- **Unified escape engine** -- `find_escape_root()` covers 18/19 Linux filesystem types. Shared by the `escape` subcommand, `escape-root` shell command, and the analyzer's F-2.1 check.
- **F-2.11/F-2.12 analyzer checks** -- LOOKUPP export escape and cross-export lateral access detection. Live-tested against 5 lab VMs.
- **Multi-version FUSE mount** -- `NfsFuse<O: ShellOps>` supports NFSv2, v3, v4 with auto-detection.
- **Nfs2EscapeProbe** -- escape engine works on v2-only servers.
- **NFS_ACL client (F-5.14)** -- program 100227 GETACL v3. Detects named USER/GROUP POSIX ACL entries beyond mode bits. Wire format verified against Linux kernel and Solaris.
- **Analyzer NFSv4 LOOKUP fallback** -- when MOUNT fails, v4 LOOKUP acquires handles for escape/handle/NFS_ACL checks. Fixes zero-coverage on image-backed fstest exports and v4-only servers.

### Remaining

#### Analyzer v4 OPEN write testing

The `Nfs4Client` has `open_write()`/`write_via_open()` but the analyzer does not use them for honest write testing (squash probes). The v4 fallback path handles read-only checks (escape, handle analysis, NFS_ACL, SECINFO). Stateful v4 write testing via `Nfs4Session` would give accurate write-access detection on v4-only servers. Medium effort.

---

## OS fingerprinting

| Signal | Detects | Effort | Status |
|--------|---------|--------|--------|
| HP-UX one-request-per-TCP | HP-UX | Low | `OsGuess::HpUx` variant reserved; active TCP detection pending |
| CALLIT response behavior | Various | Medium | Requires CALLIT implementation |

---

## NFSv4 recon operations

### OPEN for honest write testing (op 18, v4.0)

**Done in the crate and shell.** `Nfs4Client` has `open_read()`, `open_write()`, `close_file()`, `read_via_open()`, `write_via_open()`, `read_file()`, `write_file()` with full `Nfs4Session` (SETCLIENTID lifecycle, seqid sequencing, lease tracking). The V4Ops shell backend uses these for all file I/O. Remaining gap: analyzer integration for honest write testing (not yet wired into the `analyze` subcommand -- see analyzer enhancements above).

---

## Cross-protocol attack chains

Multi-protocol sequences combining sideband RPC programs with NFS for compound exploitation. These describe orchestration patterns -- they work once the individual protocol modules are built.

| Chain | Sequence | Result |
|-------|----------|--------|
| 1. NIS -> NFS credential theft | ypbind DOMAIN -> ypserv ALL(passwd.byname) -> credential_ladder_with(harvested_uids) | Targeted UID spray from real credential store |
| 2. RQUOTA -> targeted uid-spray | GETQUOTA sweep -> active UID set -> uid-spray with only confirmed UIDs | Orders of magnitude fewer probes |
| 3. NFS_ACL -> hidden permission discovery | GETACL -> ACL entries with UIDs not in mode bits -> credential_ladder_with(acl_uids) | Access paths invisible to mode-bit analysis |
| 4. WebNFS -> MOUNT bypass -> full filesystem | Public handle + MCL "../../../etc/shadow" | Single-RPC file read without MOUNT |
| 5. PCNFSD -> authenticated NFS access | PCNFSD_AUTH brute-force -> verified uid/gid -> AUTH_SYS with confirmed identity | Credential verification before NFS ops |
| 6. Metadata leak -> targeted file discovery | post_op_attr from NFS3ERR_ACCES -> file owner/size/mode -> targeted credential selection | Reduces blind spray to targeted attempt |

---

## Crate publication

**Done.** All 8 protocol crates are published on [crates.io](https://crates.io) and usable independently of the `nfswolf` binary: `onc-xdr-derive`, `onc-xdr`, `onc-rpc-client`, `onc-rpcbind`, `nfs-mount`, `nfs-v2`, `nfs-v3`, `nfs-v4`. The binary is distributed via GitHub releases and `cargo install nfswolf`.

Future sideband protocol crates (RQUOTA, NFS_ACL, NIS) will be built as modules inside `nfswolf` first and promoted to standalone crates when an external consumer needs them.

---

## HVS Consulting gap analysis

Comparison against HVS Consulting's nfs-security-tooling (nfs_analyze + fuse_nfs, December 2024).

No remaining gaps. ZFS escape handles, multi-version FUSE mount, and AUTH_DH sessions all implemented and lab-tested. nfswolf exceeds the HVS tooling in escape coverage (18 vs 3 filesystem types), protocol version support (v2/v3/v4 vs v3 only), and automation (credential ladder, auto-version detection).

---

## Protocol reference

Wire formats, XDR definitions, and security analysis for protocols not yet implemented. Each section contains enough detail to implement a client without consulting external documents.

### RQUOTA wire format

Program 100011. UDP only.

**v1 procedures:**

| Proc | Name | Args | Result |
|------|------|------|--------|
| 0 | NULL | void | void |
| 1 | GETQUOTA | pathp (string) + uid (int) | getquota_rslt |
| 2 | GETACTIVEQUOTA | pathp (string) + uid (int) | getquota_rslt |

**v2 extends v1 with:**

| Proc | Name | Args | Result |
|------|------|------|--------|
| 1 | GETQUOTA | ext_getquota_args (pathp + id + type) | getquota_rslt |
| 2 | GETACTIVEQUOTA | ext_getquota_args | getquota_rslt |

Where `type = 0` means user quota and `type = 1` means group quota.

```
struct rquota {
    unsigned int rq_bsize;      /* block size (filesystem fingerprint) */
    bool         rq_active;
    unsigned int rq_bhardlimit;
    unsigned int rq_bsoftlimit;
    unsigned int rq_curblocks;  /* current disk usage in blocks */
    unsigned int rq_fhardlimit;
    unsigned int rq_fsoftlimit;
    unsigned int rq_curfiles;   /* current file count */
    unsigned int rq_btimeleft;
    unsigned int rq_ftimeleft;
};
```

**UID existence oracle:** if `GETQUOTA` returns `Q_OK` with `rq_curblocks > 0` or `rq_curfiles > 0`, the UID exists and has disk activity. `Q_NOQUOTA` means the UID has no quota record (may or may not exist). `Q_EPERM` means permission denied (UID exists but caller lacks access).

### NFS_ACL wire format

Program 100227. No public spec. Reverse-engineered from Linux `fs/nfsd/nfs2acl.c` and `fs/nfsd/nfs3acl.c`.

```
struct aclent {
    int a_type;   /* USER_OBJ, USER, GROUP_OBJ, GROUP, CLASS_OBJ, OTHER_OBJ */
    int a_id;     /* uid or gid when a_type is USER or GROUP */
    int a_perm;   /* rwx bitmask */
};
```

`GETACL` returns an array of `aclent` entries. `a_type = USER` (0x1) with `a_id = <uid>` reveals per-user ACL grants invisible to mode bits. `a_type = GROUP` (0x4) reveals per-group grants. The `CLASS_OBJ` (mask) entry determines effective permissions via `a_perm & mask_perm`.

### PCNFSD wire format

Program 150001. D030 "Protocols for X/Open PC Interworking: (PC)NFS" pp 88-108.

```
struct auth_args {
    string id<32>;       /* username, XOR 0x5b each byte, AND 0x7f */
    string pw<64>;       /* password, same obfuscation */
    string comment<255>; /* optional */
};

enum auth_stat {
    AUTH_RES_OK   = 0,   /* success: uid/gid are real */
    AUTH_RES_FAKE = 1,   /* fail-open: uid/gid are synthesized but usable */
    AUTH_RES_FAIL = 2    /* auth failed */
};
```

The "obfuscation" is published in the spec and trivially reversible: `original_byte = (obfuscated_byte ^ 0x5b) & 0x7f`. Credentials are restricted to 7-bit ASCII, narrowing brute-force keyspace.

### NIS wire format

Programs 100004 (ypserv, 12 procedures) and 100007 (ypbind, 3 procedures).

`YPPROC_ALL` (ypserv proc 8): streaming response. Returns all key/value pairs from a named map. The response is a linked list of `ypresp_key_val` entries terminated by `more = false`.

```
struct ypreq_nokey { string domain<>; string map<>; };
struct ypresp_key_val {
    int    status;
    string key<>;
    string val<>;
};
```

Well-known map names:
- `passwd.byname`: `username:password_hash:uid:gid:gecos:home:shell`
- `group.byname`: `groupname:password:gid:member1,member2,...`
- `netgroup`: `netgroup_name (host,user,domain) ...`
- `hosts.byname`: `hostname IP`
- `mail.aliases`: `alias: expansion`

---

## Detection and monitoring gaps

NFS attacks are invisible to standard defensive tooling. This is a research section -- not actionable for nfswolf, but informs the stealth design.

- **NFS runs in kernel space**: knfsd VFS calls bypass auditd file-access rules. No `open()`/`read()` syscall = no audit record.
- **No standard NFS-aware IDS signatures**: Snort/Suricata/Zeek ship zero NFS-specific rules. AUTH_SYS credential forging, handle brute-force, and export escape are all protocol-legal.
- **nfsd tracepoints exist but no monitoring product uses them**: `include/trace/events/nfsd.h` tracepoints require custom BPF programs to extract UID from thread credentials.
- **Write operations are equally invisible**: uploading SUID binaries, creating device nodes, modifying crontabs via NFS generates no log entry on the server.

---

## Out of scope

| Item | Reason |
|------|--------|
| Kerberos ticket acquisition | Use `kinit` externally |
| TLS certificate management | Use system PKI |
| Packet capture / sniffing | Use tcpdump/wireshark |
| Exploit payload generation | Use msfvenom externally |
| Post-exploitation (persistence, lateral movement) | Different tool category |
| NFSv4.1/4.2 full session management (OPEN/CLOSE/LOCK/delegations) | Major scope -- build incrementally via recon ops |
