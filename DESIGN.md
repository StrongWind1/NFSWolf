# nfswolf -- Design Document

## Vision

A single, fast, native binary that replaces the fragmented landscape of NFS security tools (nfs_analyze, fuse_nfs, NfSpy, nfsshell, EvilNFSClient, NFSwalker, showmount, nmap scripts) with one unified toolkit purpose-built for offensive security research against NFS.

**Design principles:**
- Native speed (Rust) -- no Python interpreter, no JVM, no GC pauses
- Zero dependencies on target -- single static binary, cross-compiled for Linux/macOS/Windows
- No mount required -- pure userspace RPC/NFS implementation
- Stealth-aware -- minimal wire footprint, configurable delays, hide options
- Comprehensive -- covers all documented NFS security issues in one tool
- Spec-grounded -- every detection traces to an RFC section (see findings/ write-ups)

## Problem Statement

NFS security tooling is fragmented across 10+ tools in 5 languages, each covering a subset of the attack surface:

| Tool | Language | Strength | Gap |
|------|----------|----------|-----|
| nfs_analyze | Python | Best analysis coverage (escape, fingerprint, v4) | No scanning, no exploitation, no shell |
| fuse_nfs | Python | Auto-UID FUSE mount with escape handle | No analysis, no scanning, no shell |
| nfscli | C | Full shell + auto-UID + export escape + harvest | No analysis, no FUSE, UDP only, no v4 |
| niffler | Rust | Secret scanner with UID cycling + rule engine | Complementary tool -- covers post-access credential discovery |
| NfSpy | Python 2 | Stealth mount (hide mode), mknod, auto-UID | Dead (2014), no analysis, no v4 |
| nfsshell | C | Interactive shell, mknod, raw handles | No analysis, no escape construction, no v4 |
| EvilNFSClient | Go | Single binary, TUI, cross-platform | No analysis, no escape, no aux GIDs |
| NFSwalker | Python | v4 ACLs, GID permutation, SOCKS proxy | No FUSE, no scanning, no escape |
| RPCScan | Python | Network scan + portmapper + file read | Dead (2018), no analysis, no v4, no shell |
| nmap scripts | Lua | Ubiquitous | Shallow analysis |
| showmount | C | Standard on every box | Zero security analysis |

A security researcher assessing NFS infrastructure today needs to install, configure, and switch between all of these. nfswolf consolidates the attack-path tools (recon -> analysis -> escape -> shell -> exploitation). For deep credential discovery on accessible shares, niffler is the recommended companion -- nfswolf finds the attack path, niffler finds the secrets.

**Capabilities unique to nfswolf** (not present in any tool above):
- BTRFS cross-subvolume escape -- constructs handles targeting FS_TREE (subvol 5) and user subvolumes from any BTRFS export, giving access to all subvolumes on the device via a single export. The 20-byte FILEID_BTRFS_WITHOUT_PARENT format and compound UUID fsid variant were verified by live testing against Ubuntu 6.8 knfsd.
- XFS root inode fingerprinting -- detects XFS root at inodes 32 (1024-byte inodes), 64 (512-byte v4), or 128 (default) by probing all three candidates before falling back to an inode scan.
- subtree_check weakness documentation -- live testing confirmed that subtree_check is unreliable with bind-mounted exports due to a known Linux kernel limitation.
- `all_squash + anonuid=0` detection -- automatically flags when every client is mapped to root, which is a more severe misconfiguration than no_root_squash.
- Phase 2 scan directory verification -- the escape fast-path now rejects non-directory responses (e.g., ext4 inode 128 = journal file), eliminating false positives when trying XFS candidates on ext4 servers.

## Threat Model

nfswolf targets the following threat scenario:

**Attacker position**: Network access to an NFS server (same VLAN, VPN, compromised adjacent host, or internet-facing NFS). No privileged access to the NFS server itself.

**Target**: NFS servers using AUTH_SYS authentication (the default for virtually all deployments).

**Attack surface** (RFC-documented):

1. **Authentication is trust-based** -- AUTH_SYS credentials are client-asserted with no verifier (RFC 5531 §14). Any UID/GID can be claimed.

2. **File handles are bearer tokens** -- Possession grants access. No MAC, no expiry, no user binding (RFC 1094 §2.3.3).

3. **The wire is unprotected** -- No encryption or integrity by default (RFC 1813 §8). Credentials and data are plaintext.

4. **Access control is on the honor system** -- Port monitoring is "at best an inconvenience" (RFC 2623 §2.1). MOUNT is the only gate and is bypassed by handle theft (RFC 2623 §2.6).

5. **No practical revocation** -- The protocol contemplates handle revocation (RFC 1813 §2.5: "Servers can revoke the access provided by a file handle at any time") but provides no mandatory revocation mechanism. Most implementations never revoke handles, and UMNT removes only an advisory list entry (RFC 1094 Appendix A).

6. **The fixes are opt-in** -- RPCSEC_GSS and TLS are rarely deployed (RFC 9289 §1).

**Out of scope**: Attacks requiring privileged access to the NFS server, kernel exploits, physical access, or Kerberos ticket theft.

## Document Hierarchy

```
FINDINGS.md (60 findings with RFC-cited vulnerability analysis, F-1.1 through F-7.7)
    └── findings/ (detailed write-ups per finding)
        └── REQUIREMENTS.md (what the tool must detect, R1-R7)
            └── DESIGN.md (vision, goals, threat model)     <- you are here
                └── ARCHITECTURE.md (how it's built)
                    └── src/ (implementation)
```

Every feature in the tool traces upward through this chain to an RFC section. If a feature cannot be traced to a documented vulnerability with RFC backing, it should not be implemented.

## Operational Phases

nfswolf operates in five phases, matching a typical NFS security assessment:

### Phase 1: Reconnaissance (`nfswolf scan`)

Discover NFS infrastructure on the network. Map what's exposed.

- Port scanning (111, 2049, mountd ephemeral ports)
- RPC service enumeration via portmapper DUMP
- Export discovery via MOUNT protocol
- Version detection (v2/v3/v4.0/v4.1/v4.2)
- OS/filesystem fingerprinting from file handle structure
- NIS co-hosted service detection
- Auth flavor detection per export
- Portmapper amplification measurement

**Requirements**: [R1.1–R1.3](REQUIREMENTS.md#r1-reconnaissance-passive-discovery)

### Phase 2: Analysis (`nfswolf analyze`)

Deep security audit of a single NFS server. Non-destructive by default, with opt-in active checks.

- Export ACL analysis (wildcards, broad subnets)
- Squash configuration probing (root_squash, all_squash, anonuid)
- Export escape attempt (ext4/xfs/btrfs handle construction)
- File handle entropy and signing analysis
- NFSv2 downgrade risk detection
- NFSv4 pseudo-filesystem mapping
- Insecure port acceptance testing
- nohide/crossmnt sub-mount exposure

**Requirements**: [R2.1–R4.2](REQUIREMENTS.md#r2-authentication-testing)

### Phase 3: Exploitation (`escape`, `brute-handle`, `uid-spray`)

Three thin top-level subcommands for the offensive primitives that don't already live inside `shell` or `mount`. Read/write/upload/recursive-walk work is done from `shell` (`get`, `put`, `cat`, `find`) or `mount` (regular filesystem tools); both honour the same auto-UID escalation ladder as the standalone subcommands.

- `escape` -- construct ext4 / XFS / BTRFS escape handles to break out of an export. Single entry point for crossing the export boundary; prints a hex handle to feed into `shell --handle HEX` or `mount --handle HEX`.
- `brute-handle` -- brute-force file handles using the STALE / BADHANDLE oracle.
- `uid-spray` -- last-resort UID / GID brute force when the auto-UID ladder doesn't pin down a working credential. Should not normally be needed: `shell` and `mount` already escalate through owner / root / common service UIDs on every `NFS3ERR_ACCES`, and `escape` bypasses export-level ACLs entirely.

**Requirements**: [R5.1–R5.3](REQUIREMENTS.md#r5-exploitation-capabilities)

### Phase 4: Interactive Access (`nfswolf shell`, `nfswolf mount`)

Sustained access for data extraction and exploration.

- FTP-like interactive shell with identity switching
- FUSE mount with auto-UID impersonation
- Handle-based mount for escaped filesystems
- Stealth mode (immediate server-side unmount)

**Requirements**: Derived from R5 (exploitation) + operational needs

### Phase 5: Reporting (`nfswolf convert`)

Professional output for security assessments.

- Console (colored terminal), HTML (executive summary), JSON (automation), TXT (plain text), CSV, Markdown
- Finding deduplication and aggregation
- Remediation guidance per finding
- RFC reference per finding

**Requirements**: [R6.1–R6.2](REQUIREMENTS.md#r6-reporting)

## Key Design Decisions

### 1. Pure Userspace -- No Kernel Mount Required

nfswolf implements the entire RPC/NFS stack in userspace. This means:
- Works without root privileges (except for privileged port binding)
- No kernel NFS client dependency
- Full control over AUTH_SYS credentials on every call
- Works on systems where kernel NFS client is not installed
- The optional FUSE mount uses the userspace client under the hood

### 2. Own the Protocol Stack -- No libnfs, No Third-Party Wire Layer

The NFS wire protocol lives in-tree, split one crate per version over a shared foundation: `onc-xdr-derive` and `onc-xdr` (RFC 4506 codec), `onc-rpc-client` (ONC RPC v2, transport), `onc-rpcbind` (portmapper/rpcbind), `nfs-mount` (MOUNT v1/v3), then `nfs-v2`, `nfs-v3`, and `nfs-v4`. No edges between the version crates. Pure Rust, zero C dependencies, preserving the single static binary goal.

This started as a dependency on the pure-Rust [`nfs3-rs`](https://github.com/Vaiz/nfs3) workspace, which is public domain under the Unlicense. That was the right call while nfswolf only needed NFSv3: it supplied all 22 procedures, a complete XDR codec, and async I/O for free. The dependency stopped paying for itself once nfswolf had built NFSv2 and NFSv4 on top of it and needed four behaviours upstream did not expose -- mid-session credential swapping for UID spraying, `PROG_MISMATCH` version ranges as an enumeration oracle, ownership of the IO stream, and per-call deadlines. Three of those could not be wrapped, so nfswolf carried a `vendor/` patch tree and a hand-rolled RPC prober to work around them. In v0.6.0 the code was absorbed outright and both workarounds were deleted.

The deeper reason is that a security tool wants different defaults from a filesystem client. A permission denial is a result to record, not an error to retry. A malformed reply is a finding, not a fault. A rejection that leaks the server's supported version range is signal, not noise. Those judgements belong to whoever owns the code.

The layer boundary is strict: the protocol crates hold no policy -- no pooling, no retries, no circuit breaking, no stealth delays, no credential escalation. `src/proto/` supplies all of it through a single seam, `onc_rpc_client::RpcTransport`, plus AUTH_SYS stamp injection, SOCKS5 transport, UDP probes, and privileged port binding.

NFSv4 is fully implemented: all 37 operations are typed with response decoders, 66 named status codes, and the complete stateful infrastructure -- SETCLIENTID lifecycle, OPEN/CLOSE with stateid tracking, LOCK/LOCKU, and crash recovery (`Nfs4Session`, `OpenState`, `LockState`). The `Nfs4Client` exposes 47 public methods (244 crate tests). `V4Ops: ShellOps` integrates all 52 shell commands over NFSv4, and LOOKUPP enables export escape and cross-export lateral movement on v4-only servers. Only NFSv4.1 sessions remain unimplemented.

libnfs was never a candidate: it would require 52+ unsafe blocks for FFI (as niffler demonstrates), break cross-compilation, and hide the error codes the handle oracle depends on.

The published `nfs3_server` crate remains a dev-dependency -- it spins up an in-process mock NFS server for integration tests, and there is no reason to reimplement a server nfswolf does not otherwise need.

### 3. niffler as Companion Tool -- Not Replaced

nfswolf and [niffler](https://github.com/evilsocket/niffler) are complementary. nfswolf owns the attack path (recon -> analysis -> escape -> shell -> exploitation). niffler owns deep credential/secret discovery via its relay-chain rule engine, UID cycling, web dashboard, and FTS5 search. For a full NFS assessment: nfswolf finds the access, niffler finds the secrets.

### 4. NFSv2 as a Known Downgrade Risk

NFSv2 (RFC 1094) has zero security negotiation -- no auth flavor enforcement, no ACCESS procedure -- and some server implementations skip `root_squash` on the v2 code path (RFC 2623 §2.7). When `scan` or `analyze` detects v2 support alongside v3/v4 with RPCSEC_GSS, that combination is flagged as F-1.6 because v2 provides a downgrade path that bypasses the v3/v4 security policy entirely.

The NFSv2 wire protocol lives in `nfs-v2` (all 18 procedures, fixed 32-byte handles, 32-bit sizes) and the binary links it. `--nfs-version 2` enters a v2 shell backed by `V2Ops`, which obtains a 32-byte root handle via MOUNT v1 MNT (`MountV1Client` in `crates/nfs-mount/src/client.rs`) and wraps an `Nfs2Client<DirectTransport>` -- no connection pooling, no ACCESS procedure to drive a credential ladder, but identity changes are supported by reconnecting with new AUTH_SYS credentials (same pattern as the v4 shell's `reconnect_with_auth()`). `--handle HEX` also works, bypassing MOUNT entirely. All 52 shell commands are available through the unified `NfsShell<V2Ops>` architecture. `escape` and `brute-handle` fall back to NFSv2 automatically when MOUNT v3 fails, so v2-only servers are covered without an explicit `--nfs-version 2` flag. Live-tested against four VMs spanning kernels 2.6.32 through 4.15; Linux knfsd enforces `sec=krb5` on v2 NFS operations while MOUNT v1 leaks the handle without krb5 auth, confirming the downgrade gap documented in F-1.6.

### 5. Export Escape Lives in One Place -- `nfswolf escape`

Export escape is orthogonal to the operation being performed, but the user-facing surface should not duplicate the escape primitive across every module. Earlier revisions exposed `--escape` as an inline flag on every file-targeting attack, which led to ambiguity (escape + handle conflicts), surprised the operator (it implicitly did a MOUNT then constructed a handle in one step), and made it hard to inspect the chosen escape handle.

The current shape: `nfswolf escape` is the single entry point for crossing the export boundary. It prints the constructed root handle, which can then be fed back into `shell --handle HEX` or `mount --handle HEX`:

```bash
HANDLE=$(nfswolf escape target:/srv --json | jq -r .root_handle)
nfswolf shell target --handle "$HANDLE"
nfswolf --uid 0 mount target /mnt/escaped --handle "$HANDLE" --allow-write
```

The generic primitive is still `construct_handle_for_inode(inode, generation)`; `escape` calls `construct_escape_handle()` which is sugar for `construct_handle_for_inode(root_inode, 0)`.

### 6. Incremental AUTH_SYS Stamps

AUTH_SYS includes a `stamp` field (RFC 1057 §9.2). Some server implementations use it for duplicate request caching. nfswolf uses a global atomic counter (starting at 42, incremented per encode) injected into the `auth_unix` struct before each RPC call. Prevents false duplicate-request-cache hits during UID spraying.

### 7. Auto-UID/GID Escalation -- Evidence-Driven, Brute Force Never Automatic

AUTH_SYS lets a client assert any identity, so when an operation is refused the useful next move is to try a different one. `engine::credential::credential_ladder()` (and its evidence-aware variant `credential_ladder_with()`) returns candidates in priority order; the caller attempts each until one is accepted.

The order is not arbitrary. The file's own owner comes first, being the identity most likely to be permitted. Then the caller's UID paired with the file's group, which catches group-readable files. Then root, which a `no_root_squash` export honours. Then identities actually observed owning files on this export (from READDIRPLUS attrs, ranked by frequency via `observed_identities()`), followed by common service accounts (www-data, mysql, postgres).

The ladder is shortened by evidence already in hand. The GETATTR that produced the refusal carries the file's mode bits, and every READDIRPLUS carries per-entry ownership -- both come free with calls already made. When `mode & 0o007 == 0`, an identity that is neither the owner nor in the owning group has no POSIX path to the file, so the service-account rungs are provably wasted RPC and are skipped. Root keeps its rung regardless, because `no_root_squash` bypasses the permission check outright. This is deterministic, not heuristic: it follows from the mode the server itself reported.

Exhaustive UID/GID brute force is the `uid-spray` subcommand rather than an automatic fallback, because it is loud enough to be an explicit operator decision.

### 8. Advisory ACCESS Awareness

The NFSv3 ACCESS procedure is explicitly advisory (RFC 1813 §3.3.4). nfswolf never relies solely on ACCESS results -- it always confirms by attempting the actual operation (READ, WRITE, etc.).

### 9. Handle Oracle Exploitation

NFSv3 distinguishes NFS3ERR_BADHANDLE from NFS3ERR_STALE (RFC 1813 §2.6). nfswolf uses this oracle during handle brute-force: BADHANDLE means "wrong format, keep trying different structures"; STALE means "right format, wrong inode/generation, keep trying different values." `nfs_v3::Nfs3Error` preserves this distinction and exposes it as `is_handle_oracle_hit()` / `is_handle_oracle_miss()`.

### 10. Connection Pool with Health Eviction

Per-(host, export, uid, gid) connection pools with health-aware lifecycle. Idle connections older than 5 seconds get a GETATTR health check before reuse. Failed connections are "poisoned" (discarded on return). Backpressure via `Semaphore` prevents thundering herd at max connections.

### 11. Circuit Breaker per Host

Sliding-window (60s) circuit breaker per host prevents cascading failures during scans. Only **transient** errors (timeout, connection reset) count -- NFS3ERR_ACCES/PERM are expected during UID spraying and do not trip the breaker. Cooldown is exponential with jitter: `base * 2^(trips-1)`, capped at 5 minutes. Auto-recovery when success rate improves.

## Comparison with Existing Tools

See [ARCHITECTURE.md -- Comparison table](ARCHITECTURE.md#comparison-with-existing-tools) for the full feature matrix (10 tools, 57 feature rows).

## References

- [FINDINGS.md](FINDINGS.md) -- All 60 findings grouped by attack type (RFC-cited)
- [findings/](findings/README.md) -- Detailed write-ups per finding
- [REQUIREMENTS.md](REQUIREMENTS.md) -- Tool requirements with finding traceability
- [ARCHITECTURE.md](ARCHITECTURE.md) -- Implementation architecture and module layout
