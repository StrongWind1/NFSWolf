# Roadmap -- future work, research, and new capabilities

Everything aspirational for nfswolf and its protocol crates. Organized by readiness: what can be built now, what needs research, and what is blocked. Security value drives priority: data access and code execution first, recon and DoS last.

Source references: X/Open CAE C702 "XNFS, Version 3W" at `ref/xopen-c702.pdf` (352 pages), D030 "(PC)NFS" at `ref/archive.opengroup.org/archive/CDROM/d030.pdf` (164 pages), RFCs in `ref/rfc/`, IANA registries at `ref/all_rfcs/`.

---

## Contents

- [Ready to build](#ready-to-build) -- wire format documented, implementation path clear
- [New protocol crates](#new-protocol-crates) -- standalone RPC program clients
- [Analyzer and scanner enhancements](#analyzer-and-scanner-enhancements) -- improvements to existing modules
- [OS fingerprinting](#os-fingerprinting) -- additional detection signals
- [NFSv4 recon operations](#nfsv4-recon-operations) -- v4.0/v4.1/v4.2 probes not yet wired into the binary
- [Cross-protocol attack chains](#cross-protocol-attack-chains) -- multi-protocol sequences
- [Crate publication](#crate-publication) -- pre-publish checklist and phases
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

### WebNFS multi-component LOOKUP (MCL) path traversal

**Done.** `try_webnfs_escape()` in `escape.rs` sends `../../../etc/passwd` as a multi-component LOOKUP against the public handle for v2 (all-zero 32B), v3 (zero-length), and v4 (PUTPUBFH). Both single-slash (server splits) and component-by-component (client splits) paths are tried. The analyzer also probes MCL via `check_webnfs_public_handle()` with `etc/shadow`. Native path encoding (`0x80` prefix) is not implemented.

### Portmapper CALLIT -- amplification and relay primitive

**3 missing procedures: SET, UNSET, CALLIT. Low-medium effort.**

`CALLIT` (proc 5) forwards an RPC call to a local program over UDP and returns the result. Attack surface: UDP amplification (small request -> larger response with spoofed source IP), relay to programs on non-standard ports, and probing programs not directly reachable by the attacker. This is the primitive behind finding F-3.2, which the tool reports but cannot demonstrate.

### Write verifier reboot oracle

**Done.** `commit_verifier()` domain API exposes the raw 8-byte verifier. `check_write_verifier()` analyzer probe calls COMMIT twice and flags verifier changes. Shell `verifier` command prints the hex verifier.

### `.nfs*` silly-rename detection

**Done.** `check_silly_renames()` pattern-matches `.nfs<hex>` filenames in READDIRPLUS results. Finding F-5.9.

---

## New protocol crates

Build as modules inside `nfswolf` first. Promote to standalone crates only when an external consumer needs them.

### nfs-nlm -- lock manipulation (program 100021)

**24 procedures, v3 + v4 (64-bit widening). High effort.**

Key procedures:
- `NLM_TEST` (proc 1): leak lock holders (PID, byte range, owner handle)
- `NLM_LOCK` / `NLM_UNLOCK`: targeted lock manipulation
- `NLM_FREE_ALL` (proc 23): release ALL locks for an arbitrary hostname with a single UDP datagram -- unauthenticated bulk lock release
- `NLM_SHARE` (proc 20): persistent DoS via share reservations
- Async `_MSG` variants (procs 4-9): fire-and-forget with callback

Combined with NFS WRITE, the `NLM_TEST -> NLM_UNLOCK -> WRITE` chain gives write access to files protected by advisory locks.

Wire format: C702 ch. 10, 14. Full XDR for all 24 procedures documented in the protocol reference below.

### nfs-nsm -- reboot spoofing and callback coercion (program 100024)

**7 procedures, v1. Medium effort.**

Key procedures:
- `SM_MON` (proc 2): register attacker-controlled callbacks. The `my_id` structure specifies RPC program/version/procedure for the callback -- fully attacker-controlled.
- `SM_NOTIFY` (proc 6): spoof reboot notifications to trigger lock release across the cluster
- `SM_SIMU_CRASH` (proc 5): cascade lock recovery

Outbound-connection coercion primitive (like NFSv4 SETCLIENTID but for v2/v3). Combined with NLM, provides two independent lock-release paths.

Wire format: C702 ch. 11.

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

Improvements that use existing infrastructure, no new protocol crates needed.

### ZFS escape handles

ZFS file handles use a different structure than ext4/XFS/BTRFS. Requires lab testing with a ZFS NFS server to capture and analyze handle formats. The ext4/XFS/BTRFS escape paths are fully implemented; ZFS is the remaining gap.

### FSINFO time_delta + properties extraction

Done. `check_fsinfo_properties()` extracts `time_delta` (Solaris fingerprint: {0, 1000}) and `properties` bitmask. Findings F-5.10, F-5.11.

### FSSTAT free-space analysis

Done. `check_fsstat_capacity()` reports inode exhaustion when `avail_files < 1000`. Finding F-5.12.

### NFSv4 extended attributes (xattrs)

Done. `check_nfs4_xattrs()` issues OPENATTR + READDIR. Classifies security-relevant xattr names. Finding F-5.13.

### DRC replay attacks

After detecting a server reboot (via write verifier oracle), replay captured destructive XIDs (REMOVE, RENAME, CREATE UNCHECKED). The duplicate request cache is RAM-only -- a reboot wipes it. Requires the write verifier oracle (ready to build) and `--allow-write`. Medium effort.

### NFSv4 SETCLIENTID callback coercion

`SETCLIENTID` (op 35) takes a `cb_client4` with an attacker-controlled callback address. The server connects outbound to the registered address for delegation recalls. Connection-coercion primitive for relay attacks and firewall traversal. Requires v4.0 stateful ops. Medium effort.

### AUTH_SHORT token capture and replay

AUTH_SHORT opaque tokens captured from wire traffic can be replayed to impersonate the original client. Requires network sniffing or PCAP parsing. Post-v1.0.

### Per-path SECINFO probing

Done. `check_nfs4_secinfo_per_path()` walks subdirectories and compares per-path auth flavors to the root's. Finding F-3.6.

### NFS4ERR_WRONGSEC iterative enumeration

Partially done. Implemented in a worktree but not yet merged into main. Wire types ready.

### Scanner CSV auth column

Done. `Auth` column in CSV, `build_auth_flavors()` deduplicates across v2/v3/v4 exports.

---

## OS fingerprinting

Additional signals beyond what's already implemented (handle prefix, handle length, null-filename LOOKUP, PATHCONF case_insensitive).

| Signal | Detects | Effort | Status |
|--------|---------|--------|--------|
| Windows version pattern: v3+v4.1 only (no v2, no v4.0) | Windows NFS | Trivial | Done. `check_os_fingerprint()` + `detect_windows_handle_version()` promoted to production |
| FreeBSD subnet format in EXPORT ACL | FreeBSD | Trivial | Done. `check_export_acls()` pattern match, finding F-7.7 |
| HP-UX one-request-per-TCP | HP-UX | Low | `OsGuess::HpUx` variant reserved; active TCP detection pending |
| NetApp program 400010 in portmapper | NetApp ONTAP | Done | In IANA table |
| Null-string LOOKUP response | Linux knfsd vs spec-conformant | Done | `check_null_filename_fingerprint()` |
| Write verifier timestamp format | Solaris | Medium | Done. `check_fsinfo_properties()` detects Solaris via time_delta={0,1000}; `check_write_verifier()` probes verifier stability |
| CALLIT response behavior | Various | Medium | Requires CALLIT implementation |

---

## NFSv4 recon operations

Operations that have typed `ArgOp` variants and `CompoundBuilder` methods. Most are now wired into the scanner and/or analyzer.

### EXCHANGE_ID (op 42, v4.1)

Done. `probe_exchange_id()` sends EXCHANGE_ID via minorversion=1 COMPOUND, extracts `nii_name`, `nii_date`, pNFS flags. Populates `impl_fingerprint` in both scan and analyze output.

### SECINFO_NO_NAME (op 52, v4.1)

Partially done. Wire types ready. Implemented in a worktree (SECINFO fallback) but not merged. SECINFO on the export root is done; SECINFO_NO_NAME as a fallback for v4.1-only servers is pending.

### GETDEVICEINFO / GETDEVICELIST (ops 47-48, v4.1)

Done. `probe_pnfs_topology()` sends EXCHANGE_ID + GETDEVICELIST to discover pNFS MDS capability and enumerate data-server device IDs. Finding F-3.5.

### OPEN for honest write testing (op 18, v4.0)

Not done. Wire building blocks exist (`ArgOp::Open`, `encode_open_read()`, `CompoundBuilder::setclientid()`) but no analyzer integration. Requires SETCLIENTID for state management before OPEN can be issued. Medium-high effort.

### FATTR4_SEC_LABEL (attr 80, v4.2)

Done. `check_nfs4_sec_label()` reads SELinux labels via GETATTR with `AttrRequest::sec_label()`. Finding F-4.5.

---

## Cross-protocol attack chains

Multi-protocol sequences combining sideband RPC programs with NFS for compound exploitation. These describe orchestration patterns -- they work once the individual protocol modules are built.

| Chain | Sequence | Result |
|-------|----------|--------|
| 1. NIS -> NFS credential theft | ypbind DOMAIN -> ypserv ALL(passwd.byname) -> credential_ladder_with(harvested_uids) | Targeted UID spray from real credential store |
| 2. NSM -> NLM -> NFS write access | SM_NOTIFY(spoofed reboot) -> NLM locks released -> NFS WRITE to previously locked file | Write to advisory-locked files |
| 3. RQUOTA -> targeted uid-spray | GETQUOTA sweep -> active UID set -> uid-spray with only confirmed UIDs | Orders of magnitude fewer probes |
| 4. NFS_ACL -> hidden permission discovery | GETACL -> ACL entries with UIDs not in mode bits -> credential_ladder_with(acl_uids) | Access paths invisible to mode-bit analysis |
| 5. WebNFS -> MOUNT bypass -> full filesystem | Public handle + MCL "../../../etc/shadow" | Single-RPC file read without MOUNT |
| 6. PCNFSD -> authenticated NFS access | PCNFSD_AUTH brute-force -> verified uid/gid -> AUTH_SYS with confirmed identity | Credential verification before NFS ops |
| 7. Write verifier -> DRC replay window | COMMIT(count=0) poll -> verifier change = reboot -> replay captured destructive XIDs | Post-reboot destructive replay |
| 8. Metadata leak -> targeted file discovery | post_op_attr from NFS3ERR_ACCES -> file owner/size/mode -> targeted credential selection | Reduces blind spray to targeted attempt |

---

## Crate publication

Pre-publish checklist for the eight protocol crates. The binary (`nfswolf`) is distributed via GitHub releases and `cargo install --git`; the crates are internal-only until published.

### Pre-publish checklist

| Item | Status |
|------|--------|
| Crate renaming (`nfswolf-*` -> `onc-*`/`nfs-*`) | Done |
| `#[non_exhaustive]` on all public enums | 48 annotations present. 16 `pub enum` types in crates still lack it (mostly XDR wire types with derive macros). Audit before publish. |
| `keywords` and `categories` in every crate Cargo.toml | Done (all 8 crates) |
| Golden vector tests (real server bytes -> expected structs) | Partial (onc-xdr, onc-rpc-client, nfs-v2, nfs-v3, nfs-v4 have them; MOUNT/rpcbind gaps remain) |
| `cargo-hack --feature-powerset --no-dev-deps check` in CI | Done (ci.yml feature-powerset job) |
| Dedicated MSRV CI job | Done (ci.yml MSRV check) |
| `docs.rs` metadata (`all-features`, `docsrs` cfg) | Done (all 8 crates) |
| Re-export convention (key types at crate root) | Done (verified) |
| Switch from lockstep to independent versioning | Done (foundation crates 0.2.0, nfs-v4 stays 0.1.0) |
| README per crate with `0.x` stability caveat | Done |
| Re-check crates.io name availability | Done. All 8 names available. `onc-rpc` (taken, v0.3.3) is distinct from `onc-rpc-client` |
| Evaluate existing `onc-rpc` crate as dependency | Done. `onc-rpc` is serialization-only (no async client). Complementary, not competing. No dependency needed |

### Publication phases

| Phase | What | Status |
|-------|------|--------|
| Phase 0 | Binary fixes (v2 parity, proxy, errors) | Complete |
| Phase 1 | Foundation (portmapper, absorb udp.rs, derive tests) | Complete except CALLIT |
| Phase 2 | Extract (nfs-mount, onc-rpcbind, Nfs2Client) | Complete |
| Phase 3 | Prepare (keywords, golden vectors, cargo-hack, MSRV CI) | Done except golden vector gaps in MOUNT/rpcbind and 16 `pub enum` types missing `#[non_exhaustive]` |
| Phase 4 | Publish 8 crates to crates.io | Ready (all names available, all metadata present) |
| Phase 5 | Wire v4.1/v4.2 recon ops into scanner/analyzer | Done (EXCHANGE_ID, GETDEVICELIST, SECINFO_NO_NAME, FATTR4_SEC_LABEL, per-path SECINFO, xattrs) |
| Tier 3 | Sideband protocol crates (NLM, NSM, RQUOTA, NFS_ACL, NIS, RPCSEC_GSS) | Blocked on consumers |

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

### NLM wire format

Program 100021. C702 ch. 10, 14. 24 procedures in v3; v4 widens offset/length to 64-bit.

Key types:
```
struct nlm_lock {
    string       caller_name<>;  /* spoofable identity */
    netobj       fh;             /* NFS file handle (bearer token) */
    netobj       oh;             /* lock owner handle */
    unsigned int svid;           /* PID of lock holder */
    unsigned int l_offset;       /* byte offset (v3: 32-bit, v4: 64-bit) */
    unsigned int l_len;          /* byte count */
};

enum nlm_stats { LCK_GRANTED, LCK_DENIED, LCK_DENIED_NOLOCKS,
                 LCK_BLOCKED, LCK_DENIED_GRACE_PERIOD };
```

`FREE_ALL` (proc 23): takes only `caller_name` (string). Releases ALL locks held by that hostname. A single UDP datagram with a spoofed hostname releases every lock the victim holds.

### NSM wire format

Program 100024. C702 ch. 11. 7 procedures.

```
struct mon {
    mon_id   mon_id;
    opaque   priv[16];  /* attacker-controlled private data */
};
struct mon_id {
    string  mon_name<>;     /* hostname to monitor */
    my_id   my_id;          /* callback specification */
};
struct my_id {
    string       my_name<>;    /* callback target hostname */
    unsigned int my_prog;      /* callback RPC program */
    unsigned int my_vers;      /* callback RPC version */
    unsigned int my_proc;      /* callback RPC procedure */
};
```

`SM_MON` (proc 2): registers `my_id` as a callback target. The server will call `my_prog/my_vers/my_proc` at `my_name` when the monitored host reboots. All four fields are attacker-controlled -- outbound-connection coercion primitive.

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

## HVS Consulting gap analysis

Comparison against HVS Consulting's nfs-security-tooling (nfs_analyze + fuse_nfs, December 2024). Items not yet addressed by nfswolf:

| Gap | Description | Effort |
|-----|-------------|--------|
| ZFS escape handles | ZFS handle format not implemented in `FileHandleAnalyzer` | Medium (needs lab) -- **open** |
| Windows v4.1 handle parsing | 28-byte v4.1 handles with different internal structure | **Done.** `detect_windows_handle_version()` promoted, `check_windows_signing()` handles 28-byte v4.1 |
| HP-UX connection model detection | One-request-per-TCP behavior | **Stub.** `OsGuess::HpUx` variant added; active detection pending |
| NFSv4 escape via COMPOUND | Construct escape handle via v4 COMPOUND instead of v3 | **Done.** `try_nfs4_escape()` via PUTROOTFH + LOOKUPP chain |
| FreeBSD subnet format warning | Pattern-match EXPORT ACL for subnet-without-mask | **Done.** Finding F-7.7 in `check_export_acls()` |
| FUSE dev/suid mount options | Warn if FUSE mount lacks `-o nodev,nosuid` | **Done.** `tracing::warn!` at mount time |

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
