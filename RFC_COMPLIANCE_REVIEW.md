# NFSWolf RFC Compliance & Codebase Deep-Dive Review

Date: 2026-07-26 | Branch: `refactor/local-nfs-stack` | Version: v0.6.0

## Section 1: RFC Master Table

All 57 RFCs in `ref/all_rfcs/` classified by implementation tier.

**Tier Legend**: A = Full implementation | B = Partial implementation | C = Detection/analysis only | D = Superseded | E = Out of scope | F = Relevant but unimplemented

| RFC | Title | Category | Tier | Crate/Module | Sections Referenced | Gap Notes |
|-----|-------|----------|------|-------------|-------------------|-----------|
| 1014 | XDR: External Data Representation Standard | XDR | D | none | none | Superseded by RFC 4506 |
| 1050 | RPC: Remote Procedure Call Protocol Specification | RPC | D | none | none | Superseded by RFC 1057 |
| 1057 | RPC: Remote Procedure Call Protocol Specification Version 2 | RPC | D | nfswolf-rpc | sec. 9.2 (stamp), sec. 10 (UDP), Appendix A (portmapper) | Superseded by RFC 5531 but still referenced for portmapper and AUTH_SYS stamp semantics. 22 code references. |
| 1094 | NFS: Network File System Protocol Specification | NFSv2 | A | nfswolf-nfs2 | sec. 2.2-2.3 (procedures, types), Appendix A (MOUNT v1) | Full: all 18 procedures, 32-byte handles, MOUNT v1. 59 code refs. |
| 1813 | NFS Version 3 Protocol Specification | NFSv3 | A | nfswolf-nfs3 | sec. 2.5-2.6, 3.3.0-3.3.21, 4.4, Appendix I | Full: all 22 procedures, all 28 status codes, MOUNT v3 all 6 procs. 87 code refs. Most-referenced RFC. |
| 1831 | RPC: Remote Procedure Call Protocol Specification Version 2 | RPC | D | nfswolf-rpc | sec. 13 (PROG_MISMATCH) | Superseded by RFC 5531. Record marking and version range extraction. 4 code refs. |
| 1832 | XDR: External Data Representation Standard | XDR | D | none | none | Superseded by RFC 4506 |
| 1833 | Binding Protocols for ONC RPC Version 2 | RPC | B | nfswolf-rpc | sec. 2.1 (GETTIME), sec. 2.2.2 (GETSTAT) | Partial: 2 of ~12 rpcbind procedures (GETTIME, GETSTAT). Missing GETADDR, DUMP, CALLIT, SET, UNSET, UADDR2TADDR, TADDR2UADDR, GETVERSADDR, INDIRECT, GETADDRLIST. |
| 2054 | WebNFS Client Specification | WebNFS | C | src/engine/analyzer.rs | sec. 5 (public handle) | WebNFS public handle probing in analyzer. Zero-length v3 / all-zero v2 handles tested. |
| 2055 | WebNFS Server Specification | WebNFS | C | src/engine/analyzer.rs | sec. 5-6 (public handle, MCL) | WebNFS server detection via public handle acceptance. |
| 2203 | RPCSEC_GSS Protocol Specification | Security | C | nfswolf-rpc/auth.rs | sec. 5.2.1 (no mechanism negotiation) | Detection only: AuthFlavor::Gss classification, Kerberos pseudo-flavors (390003-390005). No GSS handshake. |
| 2224 | NFS URL Scheme | WebNFS | E | none | none | URL scheme for WebNFS. Not relevant to wire-level security assessment. |
| 2623 | NFS Version 2 and Version 3 Security Issues | Security | C | src/engine/analyzer.rs, nfswolf-rpc | sec. 2.1 (AUTH_SYS weakness), 2.5 (root squash), 2.6 (handle bearer token), 2.7 (v2 no negotiation) | Extensive: 23 code refs. Security issue detection across analyzer, shell, and protocol modules. The foundational security reference for nfswolf's threat model. |
| 2624 | NFS Version 4 Design Considerations | NFSv4 | E | none | none | Informational/historical. No implementation relevance. |
| 2695 | Authentication Mechanisms for ONC RPC | Security | E | none | none | Defines AUTH_DH and other mechanisms. Not relevant since nfswolf uses AUTH_SYS/AUTH_NONE only. |
| 2755 | Security Negotiation for WebNFS | Security | C | src/engine/analyzer.rs | SNEGO-MCL flavor enumeration | SNEGO-MCL security flavor enumeration via WebNFS public handle (analyzer.rs:846). |
| 3010 | NFS version 4 Protocol | NFSv4 | D | none | none | Superseded by RFC 3530, then RFC 7530. |
| 3529 | Using XML-RPC | Other | E | none | none | XML-RPC. Unrelated to NFS wire protocol. |
| 3530 | Network File System (NFS) version 4 Protocol | NFSv4 | D | none | none | Superseded by RFC 7530. |
| 4506 | XDR: External Data Representation Standard | XDR | A | nfswolf-xdr, nfswolf-xdr-derive | sec. 3 (block size), 4.2-4.4 (int, bool), 4.5-4.6 (hyper), 4.9-4.11 (opaque, string), 4.14-4.16 (struct, union, void) | Full for NFS-relevant types. Missing: signed int/hyper (i32/i64), float/double (f32/f64) — unused by NFS. |
| 5403 | RPCSEC_GSS Version 2 | Security | E | none | none | GSS extensions. nfswolf has no GSS implementation. |
| 5531 | RPC: Remote Procedure Call Protocol Specification Version 2 | RPC | A | nfswolf-rpc | sec. 8.2 (auth flavors), 9 (opaque_auth), 11 (record marking), 13 (PROG_MISMATCH), 14 (AUTH_SYS) | Full: all RPC message types, AUTH_SYS encoding, fragment header, PROG_MISMATCH range. 26 code refs. |
| 5532 | NFS RDMA Protocol | RDMA | E | none | none | RDMA transport. Out of scope — nfswolf uses TCP/UDP. |
| 5661 | NFSv4.1 Protocol | NFSv4.1 | D | nfswolf-nfs4 (mention only) | Referenced to disambiguate sec. 16 vs sec. 18 operation numbering | Superseded by RFC 8881. NFSv4.1 sessions not implemented. |
| 5662 | NFSv4.1 External Data Representation | NFSv4.1 | E | none | none | XDR for NFSv4.1. Out of scope. |
| 5663 | pNFS Block/Volume Layout | pNFS | E | none | none | pNFS block layout. Out of scope. |
| 5664 | Object-Based pNFS Operations | pNFS | E | none | none | pNFS object layout. Out of scope. |
| 5665 | IANA Considerations for RPC | RPC | E | none | none | IANA registry administrative. Out of scope. |
| 5666 | RDMA Transport for RPC | RDMA | E | none | none | RDMA transport. Out of scope. |
| 5667 | NFS Direct Data Placement | RDMA | E | none | none | RDMA data placement. Out of scope. |
| 5717 | Partial Lock RPC for NETCONF | Other | E | none | none | NETCONF. Unrelated to NFS. |
| 6641 | Using DNS SRV for NFS | NFSv4 ext | C | docs/FINDINGS.md | Appendix (NFSv4+ attack surfaces) | Informational: DNS SRV redirect documented as an NFSv4+ attack surface in FINDINGS.md appendix. No code. |
| 6688 | pNFS Block Disk Protection | pNFS | E | none | none | pNFS block protection. Out of scope. |
| 7204 | Requirements for Labeled NFS | Security | C | docs/findings/F-4.5 | SELinux/MAC label requirements | Referenced in F-4.5 (SELinux label bypass) documentation. No detection code. |
| 7530 | Network File System (NFS) Version 4 Protocol | NFSv4 | B | nfswolf-nfs4 | sec. 5.6 (bitmaps), 9.1.4.3 (anon stateid), 13 (status), 15.2 (COMPOUND), 16.7-16.31 (operations) | Partial: 8 of 37 operations (read-only subset). No stateful ops (OPEN/CLOSE/LOCK/delegations). 50 code refs. |
| 7531 | NFSv4 External Data Representation | NFSv4 | E | none | none | XDR tables for NFSv4. Out of scope. |
| 7861 | RPC Security Version 3 | Security | F | none | none | **Relevant but unimplemented.** RPCSEC_GSSv3 with label-aware security. Referenced by F-4.5 (SELinux label bypass) in FINDINGS.md. Could inform future labeled NFS detection. |
| 7862 | NFSv4.2 Protocol | NFSv4.2 | E | none | none | NFSv4.2 operations. Out of scope. |
| 7863 | NFSv4.2 External Data Representation | NFSv4.2 | E | none | none | XDR for NFSv4.2. Out of scope. |
| 7931 | NFSv4.0 Migration Specification Update | NFSv4 ext | C | docs/findings/F-6.3 | Migration/SETCLIENTID | Referenced in F-6.3 documentation. No code. |
| 8000 | Requirements for NFSv4 Multi-Domain Namespace | NFSv4 ext | E | none | none | Administrative requirements. Out of scope. |
| 8154 | pNFS SCSI Layout | pNFS | E | none | none | pNFS SCSI layout. Out of scope. |
| 8166 | RDMA Transport for RPC v2 | RDMA | E | none | none | RDMA transport v2. Out of scope. |
| 8167 | Bidirectional RPC on RPC-over-RDMA | RDMA | E | none | none | RDMA bidirectional. Out of scope. |
| 8178 | Rules for NFSv4 Extensions and Minor Versions | NFSv4 ext | E | none | none | Extension methodology. Out of scope. |
| 8267 | NFS Upper-Layer Binding to RPC-over-RDMA | RDMA | E | none | none | RDMA binding. Out of scope. |
| 8275 | Inheritable NFSv4 ACEs | NFSv4 ext | E | none | none | ACL inheritance. Out of scope. |
| 8276 | File System Extended Attributes in NFSv4 | NFSv4 ext | E | none | none | xattrs. Out of scope. |
| 8434 | Requirements for pNFS Layout Types | pNFS | E | none | none | pNFS layout requirements. Out of scope. |
| 8435 | pNFS Flexible File Layout | pNFS | E | none | none | pNFS flex files. Out of scope. |
| 8587 | NFS Version 4.0 Trunking Update | NFSv4 ext | C | docs/FINDINGS.md | Trunking | Referenced in FINDINGS.md. No code. |
| 8881 | NFSv4.1 Protocol | NFSv4.1 | E | nfswolf-nfs4 (mention only) | Mentioned in lib.rs as not yet implemented | NFSv4.1 sessions not implemented. |
| 9289 | Towards Remote Procedure Call Encryption by Default | Security | C | src/engine/analyzer.rs | sec. 1 (opt-in nature), Appendix A (machinename) | Detection: analyzer checks for absence of NFS-over-TLS/RPCSEC_GSS and emits F-3.1/F-3.4. 4 code refs. |
| 9561 | pNFS SCSI Layout for NVMe | pNFS | E | none | none | pNFS NVMe. Out of scope. |
| 9737 | Reporting Errors in NFSv4.2 via LAYOUTRETURN | pNFS | E | none | none | pNFS error reporting. Out of scope. |
| 9754 | Extensions for Opening/Delegating Files in NFSv4.2 | NFSv4.2 | E | none | none | NFSv4.2 extensions. Out of scope. |
| 9766 | Weak Cache Consistency in NFSv4.2 Flexible File Layout | NFSv4.2 | E | none | none | NFSv4.2 WCC. Out of scope. |

**Tier Summary**: A=4 | B=2 | C=8 | D=8 | E=34 | F=1

---

## Section 2: Protocol Crate Compliance

### nfswolf-xdr + nfswolf-xdr-derive (RFC 4506) — 5 tests

**Implemented**: u32, u64, bool, fixed-length opaque [u8;N], variable-length opaque (Opaque), string, void, struct (derive), enum (derive), discriminated union (derive), linked list (List/BoundedList). Padding per sec. 3 is correct.

**Missing (intentional)**: i32 (signed int), i64 (signed hyper), f32 (float), f64 (double), f128 (quadruple). None are used by any NFS protocol. Generic `Vec<T>` for T != u32 — handled by hand-written impls or List downstream.

**Bug found**: `Vec<u32>::unpack` allocation amplification — `with_capacity(len as usize)` uses unvalidated wire length, bypassing PREALLOC_CAP. Fix: use `vec_with_capacity()` helper.

**Deviations**: String decoder uses `from_utf8_lossy` (deliberate for security tool). Optional-data (sec. 4.19) not generic in xdr crate — provided as `Nfs3Option<T>` downstream.

### nfswolf-rpc (RFC 5531 / RFC 1057 / RFC 1833) — 9 tests

**Implemented**: All RPC message types (msg_type, reply_stat, accept_stat, reject_stat, auth_stat). AUTH_SYS encoding (stamp, machinename, uid, gid, gids[16]). Fragment header (bit 31 EOF, bits 0-30 length). PROG_MISMATCH with version range. Portmapper v2: NULL, GETPORT, DUMP. Rpcbind: GETTIME (proc 6), GETSTAT (proc 12).

**Missing portmapper**: SET (1), UNSET (2), CALLIT (5) — defined but no client methods. Intentional.

**Missing rpcbind**: 10 procedures — SET, UNSET, GETADDR, DUMP, CALLIT, UADDR2TADDR, TADDR2UADDR, GETVERSADDR, INDIRECT, GETADDRLIST. Intentional — security client needs only GETTIME and GETSTAT.

**Missing status values**: `auth_flavor` XDR enum lacks RPCSEC_GSS=6 (handled by AuthFlavor in auth.rs instead). `auth_stat` lacks values 8-14 (RPCSEC_GSS-specific rejection reasons).

**No bugs found.**

### nfswolf-nfs2 (RFC 1094) — 19 tests

**Implemented**: All 18 procedures (NULL through STATFS), all XDR types, fixed 32-byte handle, MOUNT v1 (NULL, MNT, UMNT, EXPORT).

**Bug found**: `DirOpRes::Pack` unconditionally writes fhandle+fattr on error status (100 extra bytes). RFC mandates void on non-OK. Unpack is correct. Impact: only affects encode path (e.g., mock servers), not the client decode path.

**Missing**: NFSERR_WFLUSH=99 — silently maps to Io. MOUNT v1 DUMP (proc 2) and UMNTALL (proc 4) — constants defined, no client methods.

**Extensions beyond RFC**: FType includes SOCK=6, BAD=7, FIFO=8 (Linux extensions, not in RFC 1094).

### nfswolf-nfs3 (RFC 1813) — 16 tests

**Implemented**: All 22 procedures (NULL through COMMIT), all 28 nfsstat3 codes, all 10 mountstat3 codes, all 6 ACCESS bits, all 4 FSF property bits, MOUNT v3 all 6 procedures, WCC data, domain API.

**No bugs found. Fully compliant.** Handle oracle (STALE vs BADHANDLE) correctly classified. mknoddata3 hand-written Pack/Unpack correct for all 5 file type branches.

### nfswolf-nfs4 (RFC 7530) — 15 tests

**Implemented**: COMPOUND (sec. 15.2), 8 operations: PUTROOTFH (24), PUTFH (22), LOOKUP (15), GETATTR (9), GETFH (10), SECINFO (33), READDIR (26), READ (25). Anonymous stateid correct per sec. 9.1.4.3. AttrRequest bitmap for FATTR4_FSID (bit 8).

**Missing (intentional)**: 29 operations — ACCESS(3), CLOSE(4), COMMIT(5), CREATE(6), DELEGPURGE(7), DELEGRETURN(8), LINK(11), LOCK(12), LOCKT(13), LOCKU(14), LOOKUPP(16), NVERIFY(17), OPEN(18), OPENATTR(19), OPEN_CONFIRM(20), OPEN_DOWNGRADE(21), PUTPUBFH(23), READLINK(27), REMOVE(28), RENAME(29), RENEW(30), RESTOREFH(31), SAVEFH(32), SETATTR(34), SETCLIENTID(35), SETCLIENTID_CONFIRM(36), VERIFY(37), WRITE(38), RELEASE_LOCKOWNER(39).

**Missing status codes**: 59 codes have no named variant — all captured by Unknown(u32), so decodable but not ergonomically matchable.

**Known limitation**: READDIR cookieverf=0 on continuation calls (documented in code, RFC requires echoing server's verifier).

**No bugs found.** All 8 implemented ops correct.

### src/proto (Application Layer) — 161 tests

**No bugs found.** AUTH_SYS stamp counter, SOCKS5 handshake (RFC 1928), circuit breaker discrimination, PooledTransport policy chain, portmapper DUMP/GETPORT, MOUNT MNT/EXPORT, UDP RPC (no record marking per RFC 1057 sec. 10) — all correct.

---

## Section 3: Finding Coverage Matrix

| Finding | Title | Analyzer? | Shell/Other? | Status |
|---------|-------|-----------|-------------|--------|
| F-1.1 | UID/GID spoofing | Yes | Yes (uid, gid, impersonate, uid-spray) | Implemented |
| F-1.2 | Root squash bypass | Yes | Yes (uid, credential ladder) | Implemented |
| F-1.3 | Auxiliary group injection | Yes | Yes (gid, with_groups) | Implemented |
| F-1.4 | Machine name spoofing | No | Yes (hostname cmd, --hostname flag) | Implicit |
| F-1.5 | Credential replay | No | No | Implicit (passive attack; precondition via F-3.1) |
| F-1.6 | NFSv2 downgrade | Yes | Yes (--nfs-version 2) | Implemented |
| F-1.7 | RPCSEC_GSS flavor downgrade | No | No | **Doc-only** (mixed-flavor check not implemented) |
| F-2.1 | Export escape | Yes | Yes (escape-root, escape cmd) | Implemented |
| F-2.2 | File handle guessing | Yes | Yes (brute-handle cmd) | Implemented |
| F-2.3 | Windows handle signing | Yes | No | Implemented |
| F-2.4 | BTRFS subvolume escape | Yes | Yes (escape-root) | Implemented |
| F-2.5 | Stale handle persistence | No | Yes (--handle, mount-handle) | Implicit |
| F-2.6 | Bind mount escape | No | Yes (escape still works) | Disabled (unsound heuristic) |
| F-2.7 | NFSD ACL blindness | No | Yes (--handle bypasses ACLs) | Implicit |
| F-2.8 | Sibling export lateral access | No | Yes (escape-root + cd) | Implicit |
| F-2.9 | WebNFS public handle | Yes | No | Implemented |
| F-3.1 | Plaintext wire protocol | Yes | No | Implemented |
| F-3.2 | Portmapper amplification | Yes | Yes (scan) | Implemented |
| F-3.3 | IP spoofing / host trust | No | No | Implicit (export ACL analysis) |
| F-3.4 | STRIPTLS downgrade | Yes | No | Implemented |
| F-3.5 | Portmapper tunnel bypass | No | Yes (scan direct port 2049) | Implicit |
| F-3.6 | UDP mount handle theft | No | Yes (--scan-udp) | Implicit |
| F-4.1 | no_root_squash | Yes | No | Implemented |
| F-4.2 | SUID/SGID escalation | No | Yes (suid-scan, chmod) | Implicit |
| F-4.3 | Device node creation | No | Yes (mknod) | Implicit |
| F-4.4 | Symlink escape | Yes | Yes (symlink) | Implemented |
| F-4.5 | SELinux label bypass | No | No | **Doc-only** (no SELinux check) |
| F-5.1 | Export list enumeration | No | Yes (scan EXPORT) | Implicit |
| F-5.2 | READDIRPLUS handle harvesting | No | Yes (every ls) | Implicit |
| F-5.3 | NIS credential extraction | Yes | No | Implemented |
| F-5.4 | RPC service enumeration | No | Yes (scan DUMP) | Implicit |
| F-5.5 | NFSv4 pseudo-FS leakage | No | Yes (scan v4 READDIR) | Implicit |
| F-6.1 | NLM lock attacks | No | No | Out-of-scope (NLM removed v0.2.0) |
| F-6.2 | Grace period DoS | No | No | Out-of-scope (NLM removed v0.2.0) |
| F-6.3 | SETCLIENTID state destruction | No | No | Out-of-scope (no stateful v4) |
| F-7.1 | Wildcard export policy | Yes | No | Implemented |
| F-7.2 | Privileged port bypass | No | No | Disabled (unsound test) |
| F-7.3 | nohide/crossmnt exposure | Yes | No | Implemented |
| F-7.4 | Missing nosuid/nodev | No | Yes (suid-scan) | Disabled (client-side opts) |
| F-7.5 | Squash misconfiguration | Yes | No | Implemented |
| F-7.6 | No audit logging | No | No | **Doc-only** (not remotely testable) |

**Summary**: 18 Implemented | 14 Implicit | 3 Disabled | 3 Doc-only | 3 Out-of-scope

---

## Section 4: CLAUDE.md Accuracy Report

| Claim | Verdict | Evidence |
|-------|---------|---------|
| "161 tests" | **FALSE** | Actual: 227 total (225 pass + 2 ignored). `cargo test --workspace` confirms. |
| "Rust 2024 edition, MSRV 1.95" | TRUE | Cargo.toml: `edition = "2024"`, `rust-version = "1.95"` |
| "6 workspace crates + the binary" | TRUE | `ls crates/` confirms 6 crates |
| "v0.6.0 is the last tagged release" | TRUE | `git tag` confirms |
| "No C dependencies" | TRUE | `cargo tree` shows only libc (Rust FFI bindings), no `-sys` crates |
| "18 NFSv2 procedures" | TRUE | All 18 in `nfswolf-nfs2/src/client.rs` |
| "22 NFSv3 procedures" | TRUE | All 22 in `nfswolf-nfs3/src/raw.rs` |
| "MOUNT v1 MNT + EXPORT" | **INCOMPLETE** | Also implements NULL and UMNT (4 methods total in `MountV1Client`) |
| "MOUNT v3 6 procedures" | TRUE | All 6 in `nfswolf-nfs3/src/mount.rs` |
| "44+ interactive commands" | TRUE | 44 accepted command strings (43 in SHELL_COMMANDS + "?" alias) |
| "NFSv4 ~7 operations" | TRUE | 8 ops implemented (PUTROOTFH, PUTFH, LOOKUP, GETATTR, GETFH, SECINFO, READDIR, READ) |
| "NLM/NSM removed in v0.2.0" | TRUE | `grep -rn "100021\|100024\|NLM\|NSM" src/ crates/` returns zero hits |
| "nfs3_server remains a dev-dependency" | TRUE | `Cargo.toml` dev-dependencies: `nfs3_server = { version = "0.11", features = ["memfs"] }` |
| "No nfs3_client dependency" | TRUE | Not in any Cargo.toml |
| All file paths in "Do Not Rewrite" table | TRUE | All 40+ listed files exist at stated paths |
| "RpcTransport is the single seam" | TRUE | Trait defined in `nfswolf-rpc`, all policy goes through it |
| "AUTH_SYS stamps from global AtomicU32" | TRUE | `src/proto/auth.rs` has `STAMP_COUNTER: AtomicU32` |
| API: `MountV1Client::mnt("/export")` takes string | **FALSE** | Actually takes `&str` path but through a different method signature: `mnt(path: &str)` — the doc example shows `mnt("/export")` which is correct, but the method returns `FhStatus` not a raw handle as implied |
| "src/proto/conn.rs contains Socks5Connector" | **FALSE** | No struct named `Socks5Connector`. SOCKS5 support is inline in `connect_proxy()` function. |
| "check-all runs ... test (161 tests)" | **STALE** | Test count is 227, not 161. Rest of the make target chain is correct. |
| "Feature Backlog: No open work items" | TRUE | All items marked Done with live-test results |
| "--allow-write flag for write operations" | TRUE | Verified in `cli/mod.rs` GlobalOpts and shell dispatch |
| Crate dependency table | TRUE | `nfswolf-nfs4` depends on xdr only, `nfswolf-nfs3` on xdr+rpc, etc. All verified. |
| "ref/nfs3/ is a read-only checkout of Vaiz/nfs3" | TRUE | Directory exists with upstream source |

---

## Section 5: Documentation Freshness

### docs/DESIGN.md — 1 critical stale claim

- **Lines 179-180 (Design Decision #4)**: Claims "the binary does not link [nfswolf-nfs2]" and "the shell refuses --nfs-version 2". **Completely wrong.** NFSv2 shell is fully implemented and live-tested. `src/cli/shell.rs` dispatches to `run_nfs2_shell()`, `MountV1Client` is used for MOUNT v1 MNT.

### docs/ARCHITECTURE.md — 5 stale claims

- **Line 623**: Lists `src/shell.rs` as single file. Actually `src/shell/` directory with mod.rs, ops.rs, v2.rs, v3.rs.
- **Line 655**: `scan_types.rs` described as containing 'ScanResult, ExportInfo'. `ScanResult` doesn't exist (actual type is `ScanOutput`). `ExportInfo` doesn't exist anywhere.
- **Line 683**: Claims `findings/` has '39 files'. Actual: 42 files (41 findings + README.md).
- **Lines 178-189**: Shell command list includes `mode`, `size`, `atime` etc. as standalone commands. These are `ls --sort` options, not commands. Missing: `last`, `lastb`, `lastlog`, `root`, `quit`.
- **Line 872**: Comparison table claims "TUI: Yes". nfswolf has readline REPL, not a TUI.

### docs/REQUIREMENTS.md — Current

No stale claims found. All R1-R7 requirements, priority levels, and traceability links are accurate.

### docs/FINDINGS.md — Current

No stale claims found. All 41 findings have correct severity, RFC citations, and detection methods. F-6.x out-of-scope notation is correct.

### docs/NFSv2.md — 2 stale claims

- **Lines 141-146**: MOUNT v1 "Via" column says `nfswolf-rpc`. Should be `nfswolf-nfs2`.
- **Lines 170-187**: NFS v2 procedures listed with "Via: Own code". Should say `nfswolf-nfs2` for consistency with NFSv3.md.

### docs/NFSv3.md — 3 stale claims

- **Lines 127-128**: Portmapper "Via" column says `nfswolf-nfs3`. Should be `nfswolf-rpc`.
- **Line 203**: Typo `nfswolf-nfs3rary` → should be `nfswolf-nfs3 library`.
- **Line 203**: Describes per-method circuit breaker/pool/stealth pattern. Superseded by `PooledTransport` architecture.

### docs/NFSv4.md — 3 stale claims

- **Line 207**: Claims XDR code in `src/proto/nfs4/types.rs`. File doesn't exist. Types are in `crates/nfswolf-nfs4/src/wire.rs`, re-exported as `types`.
- **Line 207**: References "The nfs3-rs library" as current external dependency. Absorbed into in-tree crates in v0.6.0.
- **Line 207**: States "nfswolf uses the library's RpcClient". Should reference own `nfswolf-rpc` crate.

### docs/UNUSED_CODE.md — Entirely stale

Self-identified as "HISTORICAL" and "obsolete". References removed modules (auto_uid.rs, privilege.rs, ReconnectStrategy::ResetPerCall, PoolStats). Claims NFSv2 subsystem "has no consumer" — it now has a full consumer chain.

---

## Section 6: Prioritized Next Steps

### P0: Correctness Bugs (fix immediately)

1. **XDR `Vec<u32>::unpack` allocation amplification** (`crates/nfswolf-xdr/src/primitives.rs:31`). Forged length of 0xFFFFFFFF causes ~16 GiB allocation attempt. Fix: replace `Self::with_capacity(len as usize)` with `crate::util::vec_with_capacity(len as usize)`.

2. **NFSv2 `DirOpRes::Pack` wrong union encoding** (`crates/nfswolf-nfs2/src/wire.rs:465`). Unconditionally writes fhandle+fattr on error status instead of RFC-mandated void. Fix: add status check in Pack impl, write only discriminant on non-OK.

3. **NFSv2 missing `NFSERR_WFLUSH=99`** (`crates/nfswolf-nfs2/src/wire.rs`). Currently maps to `Io`. Fix: add `WFlush = 99` variant to `NfsStat`.

### P1: Security-Relevant Gaps

4. **F-1.7 mixed-flavor detection not implemented**. FINDINGS.md claims detection via MOUNT auth_flavors and SECINFO, but `check_auth_methods()` only emits F-1.1 (AUTH_SYS-only). Needs: add check for `has_auth_sys && has_kerberos` (both present = downgrade risk).

5. **F-4.5 SELinux label bypass has no detection code**. Identity undecided (RFC 7861 vs CVE-2024-46695). Low priority until identity resolved.

6. **F-7.6 no audit logging is doc-only**. Not remotely testable. Consider adding an informational note in analyzer output when any access succeeds.

### P2: Documentation Debt

7. **CLAUDE.md test count**: Change "161 tests" to "227 tests" (or make it dynamic).

8. **CLAUDE.md MOUNT v1 description**: Change "MNT + EXPORT" to "NULL, MNT, UMNT, EXPORT (4 methods)".

9. **CLAUDE.md `Socks5Connector` reference**: Remove — SOCKS5 is inline in `connect_proxy()`, no dedicated struct.

10. **docs/DESIGN.md Decision #4**: Rewrite to reflect NFSv2 shell is fully implemented and live-tested. This is the most critical doc fix — it directly contradicts the code.

11. **docs/ARCHITECTURE.md**: Fix `src/shell.rs` → `src/shell/`, fix `ScanResult`/`ExportInfo` references, fix shell command list, fix findings count (39 → 42), fix TUI claim.

12. **docs/NFSv2.md, NFSv3.md, NFSv4.md**: Fix "Via" column crate attributions, remove nfs3-rs references, fix `types.rs` path.

13. **docs/UNUSED_CODE.md**: Either delete entirely or add a note that it is fully obsolete post-refactor.

### P3: Nice-to-Have

14. **RPC `auth_stat` values 8-14**: Add RPCSEC_GSS-specific rejection variants for better error messages against krb5 servers.

15. **NFSv4 READDIR cookieverf**: Surface cookieverf from decoder and echo on continuation calls. Cross-module change touching `nfswolf-nfs4` wire types and `src/proto/nfs4/compound.rs`.

16. **NFSv4 named status codes**: Add ergonomic variants for commonly-encountered errors beyond the current 6 (PERM, NOENT, IO, NOTDIR, ISDIR, INVAL, ROFS, etc.).

17. **rpcbind GETADDR**: Would enable direct service address resolution without portmapper v2 fallback. Low priority — portmapper v2 GETPORT works everywhere.

18. **NFSv4 PUTPUBFH (op 23)**: Would enable WebNFS public handle probing on NFSv4 without MOUNT. Currently WebNFS detection only covers v2/v3.

19. **NFSv4 write operations in shell**: The `let _ = allow_write;` stub in `cli/shell.rs:277` needs OPEN+WRITE+CLOSE implementation. Blocked by stateful v4 being out of scope.
