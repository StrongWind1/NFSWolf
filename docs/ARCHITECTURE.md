# nfswolf -- Architecture Document

Implementation architecture, module layout, data flow, and build system.
For vision and goals, see [DESIGN.md](DESIGN.md). For security rationale, see [FINDINGS.md](FINDINGS.md) and [findings/](findings/).

## Document Traceability

```
FINDINGS.md (41 findings with RFC-cited analysis, F-1.1 through F-7.6)
    └── findings/ (detailed write-ups per finding)
        └── REQUIREMENTS.md (what the tool must detect, R1-R7)
            └── DESIGN.md (vision, goals, threat model)
                └── ARCHITECTURE.md (how it's built)        <- you are here
                    └── src/ (implementation)
```

## Module Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                         nfswolf CLI                                  │
│ ┌──────┐ ┌───────┐ ┌───────┐ ┌──────┐ ┌───────┐ ┌──────────┐ ┌──────┐│
│ │ scan │ │analyze│ │ shell │ │mount │ │escape │ │brute-h. /│ │conv. ││
│ │recon │ │ audit │ │ repl  │ │fuse  │ │exploit│ │uid-spray │ │report││
│ └──┬───┘ └───┬───┘ └───┬───┘ └──┬───┘ └───┬───┘ └────┬─────┘ └──┬───┘│
│    │         │         │        │         │          │          │    │
│ ┌──┴─────────┴─────────┴────────┴─────────┴──────────┴──────────┴──┐ │
│ │                    Core NFS Engine                                │ │
│ │  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌──────────┐ ┌──────────┐  │ │
│ │  │  RPC    │ │  NFS3   │ │  MOUNT  │ │  NFS4    │ │ Portmap  │  │ │
│ │  │  Layer  │ │  Proto  │ │  Proto  │ │  Proto   │ │ Client   │  │ │
│ │  └─────────┘ └─────────┘ └─────────┘ └──────────┘ └──────────┘  │ │
│ └──────────────────────────────────────────────────────────────────┘ │
│ ┌──────────────────────────────────────────────────────────────────┐ │
│ │                    Transport Layer                                │ │
│ │  ┌──────┐ ┌──────┐ ┌────────┐ ┌────────┐ ┌─────────────┐        │ │
│ │  │ TCP  │ │ UDP  │ │ SOCKS5 │ │ Priv   │ │ Rate Limit  │        │ │
│ │  │      │ │      │ │ Proxy  │ │ Ports  │ │ / Jitter    │        │ │
│ │  └──────┘ └──────┘ └────────┘ └────────┘ └─────────────┘        │ │
│ └──────────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────┘
```

## Modules

### 1. `nfswolf scan` -- Network Reconnaissance

Fast, async network scanner to discover NFS infrastructure.

```
nfswolf scan 192.168.0.0/24
nfswolf scan -f targets.txt --scan-udp
nfswolf scan 10.0.0.0/8 -c 500 --json results.json --csv results.csv
nfswolf scan 192.168.0.0/24 --auto-escape       # break out of every export found
```

**Architecture** (src/engine/scanner.rs, src/engine/scan_types.rs):
- tokio::spawn fan-out with Semaphore-based concurrency limit
- Per-host 9-stage probe sequence with panic isolation
- SIGINT handling: partial results collected via Arc<Mutex<Vec>>, exit code 130
- PROG_MISMATCH-aware probing (RFC 1831 §13) via raw record-marking framing
- Single TCP connection reuse for sequential v2/v3/v4 version probes
- UDP portmapper fallback (DUMP + GETPORT) when TCP/111 is firewalled

**Capabilities:**

| Capability | Description | Finding |
|------------|-------------|---------|
| Port scanning | Parallel TCP+UDP probe (111, 2049, mountd ports) | F-3.5 |
| Portmapper enumeration | PMAPPROC_DUMP over TCP; UDP fallback via `--scan-udp` | F-5.4 |
| Export discovery | MOUNT EXPORT (highest registered mountd version) + NFSv4 pseudo-root READDIR | F-5.1 |
| Version detection | NULL v2/v3 + COMPOUND v4 with PROG_MISMATCH range extraction | F-1.6 |
| Client enumeration | MOUNT DUMP (connected clients per export) | -- |
| NIS detection | Programs 100004/100007 in portmapper dump | F-5.3 |
| NFSv4 pseudo-FS | READDIR on pseudo-root with AUTH_SYS uid=0 | F-5.5 |
| UDP mountd detection | Identifies F-3.6 (UDP MOUNT spoof) attack surface | F-3.6 |
| Auto-escape (`--auto-escape`) | Attempts a subtree_check bypass on every discovered export and prints a ready-to-run `shell --handle` command for each filesystem root reached | F-2.1, F-2.4 |

**Output:** Dynamic table with blank-column hiding, per-host detail with export deduplication. `--json FILE` and `--csv FILE` for structured output.

**Auto-escape:** With `--auto-escape`, the scan runs a second pass after discovery that reuses the shared `cli::escape::find_escape_any` primitive (identical bypass logic to the standalone `escape` subcommand, including automatic NFSv2 fallback when MOUNT v3 fails) against the union of every host's v2/v3/v4 export paths, with bounded concurrency. It only runs on a complete scan (a `Ctrl+C` exits before the pass). The escape probe runs as uid=0 (to distinguish `root_squash` from a rejected handle), and honours `--proxy` and `--delay`/`--jitter`.

**Requirements**: [R1.1-R1.3](REQUIREMENTS.md#r1-reconnaissance-passive-discovery)

**Speed targets:**
- 10,000 hosts/minute for port scanning
- 1,000 hosts/minute for full NFS enumeration
- Configurable rate limiting and jitter for stealth
- Per-credential delay for UID spray (independent of global jitter)

### 2. `nfswolf analyze` -- Security Audit

Deep analysis of a single NFS server's security posture.

```
nfswolf analyze target.internal
nfswolf analyze --json target > results.json   # capture for offline rendering
nfswolf analyze target --test-read /etc/shadow --test-read-gids 42,15,0 --test-read-uids 0
```

Every analysis runs the full check matrix unconditionally. The only per-run knobs are `--test-read PATH` (defaults to `/etc/shadow`), `--test-read-uids`, `--test-read-gids`, and `--v4-depth`.

Output split: `analyze` prints an ANSI-coloured human-readable summary on stdout by default. With `--json` it emits a single JSON array on stdout instead -- redirect that into a file and feed it to `nfswolf convert` to render HTML/Markdown/CSV/TXT.

**Checks performed (all always-on):**

| Check | Description | Finding |
|-------|-------------|---------|
| Export ACLs | Wildcard/broad subnet detection | F-7.1 |
| Auth methods | AUTH_SYS vs krb5 per export (+ NFSv4 SECINFO per directory) | F-1.1 |
| Root squash | Test no_root_squash (creates and removes a temp dir) | F-4.1 |
| Squash probe | Detect anonuid/anongid, root_squash, all_squash | F-7.5 |
| Root squash bypass | Test non-root UID access (file owner impersonation) | F-1.2 |
| Subtree escape | Filesystem root access (ext4/xfs/btrfs handle construction) | F-2.1 |
| Escape confirmation | Compare READDIRPLUS child count to verify escape | F-2.1 |
| BTRFS subvolume escape | Construct handles for subvol IDs 256+ | F-2.4 |
| Bind mount escape | *(disabled -- equality check was unsound; F-2.6 is exercised by `escape`, not `analyze`)* | F-2.6 |
| File read test | Read each `--test-read` path under all UID/GID combinations (default: /etc/shadow + GIDs 0/42/15) | F-1.3 |
| Auxiliary group injection | Test shadow GIDs (42/15) and GID spray | F-1.3 |
| Symlink attack preconditions | Walk path components, detect writable parent dirs | F-4.4 |
| Windows signing (v3+v4.1) | Detect disabled HMAC (32-byte v3 + 28-byte v4.1 handles) | F-2.3 |
| Handle entropy | Analyze file handle randomness, estimate brute-force time | F-2.2 |
| Nested exports | Detect risky nested configurations | F-7.3 |
| `nohide`/`crossmnt` | Detect sub-mount traversal beneath exports | F-7.3 |
| Client enumeration | List connected clients + online check | -- |
| NFSv4 ACL extraction | Retrieve NFSv4/4.1 ACLs even on v3-primary servers | -- |
| NFSv4 pseudo-FS mapping | Recursive fsid-based export boundary detection | F-5.5 |
| NFSv4 browsing | Directory tree via NFSv4 even when v3 blocked | F-5.5 |
| Version matrix | Full version support map (v2, v3, v4.0, v4.1, v4.2) | F-1.6 |
| NFSv2 downgrade | Flag v2 alongside v3/v4; critical if v3=krb5 but v2=AUTH_SYS | F-1.6 |
| Server OS fingerprint | Handle format + version matrix + vendor protocols (NetApp 400010) | F-2.1 |
| Plaintext transport | Flag exports advertising no RPCSEC_GSS (Info); RFC 9289 TLS not actively probed | F-3.1 |
| Portmap amplification | Measure UDP/111 DUMP response factor; flag DDoS reflector | F-3.2 |
| TLS detection | AUTH_TLS probe + DANE/TLSA record check | F-3.4 |
| NIS detection | Portmapper check for programs 100004/100007 | F-5.3 |
| Writable check | Test write access per export | F-4.1 |

**Requirements**: [R2.1–R4.2](REQUIREMENTS.md#r2-authentication-testing)

**Output formats:** Terminal (colored), JSON (machine-readable)

### 3. `nfswolf mount` -- Virtual Filesystem Access

FUSE-based mount that automatically handles UID/GID spoofing for transparent file access.

```
nfswolf mount target:/export /mnt/nfs
nfswolf mount target /mnt/escaped --handle 01000700...
nfswolf mount target:/export /mnt/nfs --allow-write
```

**Features (all always-on -- this is a security toolkit, the goal is unobstructed access):**
- **Auto-UID mode**: Automatically impersonates file owner for each operation (F-1.1)
- **Manual UID/GID override**: Specify exact credentials per session (F-1.1)
- **Auxiliary GID injection**: Include arbitrary GIDs in AUTH_SYS (F-1.3, max 16 per RFC 1057 §9.2)
- **Handle-based mount**: Mount arbitrary file handles -- escaped filesystems, brute-forced handles (F-2.1, F-2.2, F-2.5)
- **Read-only default**: Explicit `--allow-write` required
- **Stealth mount**: Immediate unmount from server (`--hide`, like NfSpy `hide`) -- handle persists (F-2.5)
- **Server-side symlink resolution**: Always resolves symlinks against the export root, never the FUSE mount (F-4.4)
- **suid + dev passthrough**: Always honoured -- needed for SUID escalation testing (F-4.2, F-4.3)
- **`SessionACL::All`**: Mount is visible to every local user, not just whoever ran nfswolf
- **Permission elevation**: Owner mode bits are always copied into the other-mode slot so unprivileged local users can reach every file through FUSE
- **READDIRPLUS null-attr fixup**: Always falls back to LOOKUP when the server returns null attrs (NetApp / nested-export workaround)
- **Machine name spoofing**: Custom `--hostname` per mount session (F-1.4)

### 4. `nfswolf shell` -- Interactive NFS Shell

FTP-like interactive shell for exploration without FUSE dependency.

```
nfswolf shell target:/export
nfswolf shell target --uid 0 --gid 0
```

**Commands:**

```
Navigation:    ls, cd, pwd, tree, find
File ops:      get [-r] [--verify <sha256>], put [-r], cat, rm, mkdir, rmdir,
               mv, cp, readlink, symlink
Permissions:   chmod, chown, stat
Identity:      uid <n>, gid <n>, hostname <name>, whoami, impersonate <uid>:<gid>,
               handle
Devices:       mknod <name> c|b <major> <minor>
Analysis:      suid-scan, world-writable, secrets-scan
Forensics:     last, lastb, lastlog
Escape:        escape-root, mount-handle <hex>
Local:         lcd, lls, lpwd, lmkdir
Session:       help, history, exit, quit
```

**Unique features:**
- **Auto-complete**: Tab completion for remote paths
- **Identity switching**: Change UID/GID/hostname mid-session without reconnecting (F-1.1, F-1.4)
- **Hostname spoofing**: `hostname <name>` sets `AUTH_SYS.machinename` in-session to bypass hostname-restricted export ACLs
- **Pattern search**: `find` with regex support across the remote share
- **Secrets scanner**: Built-in patterns for SSH keys, env files, credentials
- **Recursive operations**: `get -r`, `put -r` mirror entire directory trees; `indicatif` spinner per directory
- **SHA-256 verification**: Every `get` prints the hash; `get --verify <hex>` asserts it -- evidence chain for reports
- **SOCKS5 proxy**: `--proxy socks5://host:port` tunnels all NFS connections through a pivot (inline CONNECT, no external crate)
- **Device node creation**: `mknod` for char/block devices (F-4.3)
- **Symlink creation**: Create symlinks pointing outside export boundaries (F-4.4)
- **Inline escape**: `escape-root` constructs filesystem root handle from current session (F-2.1)
- **NFSv2 mode**: `--nfs-version 2` drops into an NFSv2 shell via MOUNT v1 + `Nfs2Client`. Supports `--handle HEX` for MOUNT bypass. Includes the `root` probe (NFSPROC_ROOT bypass check, RFC 1094 sec. 2.2.3) which is not available in the v3 shell.
- **NFSv4 mode**: `--nfs-version 4` drops into an NFSv4 shell (ls/cd/cat/get/handle/lcd/lls/lpwd/lmkdir/history) without MOUNT -- read-only NFS operations plus local commands

### 5. Offensive subcommands -- `escape`, `brute-handle`, `uid-spray`

Three thin top-level subcommands that cover the offensive primitives not
already provided by `shell` or `mount`. Read/write/upload/recursive-walk
work is done through `shell` (`get`, `put`, `get -r`, `put -r`, `cat`,
`find`) or `mount` (regular filesystem tools); both honour the same
auto-UID escalation ladder and stealth/proxy flags as the standalone
subcommands.

| Subcommand | Description | Findings |
|------------|-------------|----------|
| `escape` | Construct ext4 / XFS / BTRFS escape handles to break out of an export | F-2.1, F-2.4, F-2.6 |
| `brute-handle` | Brute-force file handles using the STALE / BADHANDLE oracle | F-2.2, F-2.5 |
| `uid-spray` | Last-resort UID / GID + auxiliary-group brute force when the auto-UID ladder doesn't pin down a working credential | F-1.1, F-1.2, F-1.3 |

`escape` is the single entry point for crossing the export boundary. It tries NFSv3 first (MOUNT v3 + `Nfs3Client` probes), then falls back automatically to NFSv2 (MOUNT v1 + `Nfs2Client`) when MOUNT v3 fails. The `find_escape_any` function encapsulates this two-version fallback and is shared by `scan --auto-escape`. Once `escape` returns a hex handle, feed that handle into `shell --handle HEX` or `mount --handle HEX` to read, write, or recursively walk anything on the underlying filesystem.

```bash
# Step 1: construct the escape handle for the underlying filesystem (F-2.1)
nfswolf escape target:/srv
# Copy the printed hex handle

# Step 2: drop into a shell on the filesystem root and operate normally
nfswolf shell target --handle "$HANDLE"

# Or mount it locally and use regular tools
nfswolf --uid 0 mount target /mnt/escaped --handle "$HANDLE" --allow-write
```

`brute-handle` sweeps the inode/generation search space using `--inode-start`/`--inode-end` and `--gen-start`/`--gen-end` (defaults: inodes 0-500, gen 0). It derives its seed handle from `<HOST>:/export` via MOUNT or from an explicit `--seed-handle HEX`. Like `escape`, it tries NFSv3 first and falls back to NFSv2 automatically. For BTRFS, subvolume ID sweeping is attempted first (or as a fallback when the filesystem type is unknown).

`uid-spray` should not normally be needed: the auto-UID ladder built into `shell` and `mount` already tries owner, root, and common service UIDs on every `NFS3ERR_ACCES`, and `escape` bypasses export-level access checks entirely. It's included as a fallback when those don't pin down a working credential.

### 6. `nfswolf convert` -- Offline Report Rendering

Generate professional security assessment reports.

```
nfswolf convert --format html --input results.json -o report.html
```

**Output formats:**
- **Console**: Terminal output with severity coloring
- **HTML**: Styled report with executive summary, findings, remediation
- **JSON**: Machine-readable for automation pipelines
- **TXT**: Plain text report
- **Markdown**: For inclusion in pentest reports
- **CSV**: Spreadsheet-friendly finding list

**Finding content (per [R6.2](REQUIREMENTS.md#r62-finding-content)):**
- Finding ID (F-X.Y), title, severity, description
- Evidence (observed data, handle hex, file contents)
- RFC reference per finding
- Remediation guidance
- Affected export
- Deduplication across exports

**Requirements**: [R6.1–R6.2](REQUIREMENTS.md#r6-reporting)

## Core NFS Engine Design

### Protocol Layer: Eight Workspace Crates

nfswolf owns its entire NFS wire stack in-tree, layered as eight workspace crates with no edges between the version crates:

```
onc-xdr-derive             #[derive(XdrCodec)] proc macro
        |
onc-xdr                    RFC 4506 codec, length-hardened decoders
        |
onc-rpc-client             ONC RPC v2, AuthSys, RpcTransport seam
        |
+-------+-------+-------+
|       |       |       |
rpcbind mount   |       |     onc-rpcbind (portmapper/rpcbind), nfs-mount (MOUNT v1/v3)
        |       |       |
+-------+-------+       |
|       |       |       |
nfs-v2  nfs-v3  nfs-v4        one crate per NFS version, each standalone
```

Each version crate owns its own MOUNT protocol (v1 in nfs2, v3 in nfs3; v4 has no MOUNT) because the handle types genuinely differ (v1 fixed 32 bytes, v3 variable-length) and they are defined in different RFCs.

This began as a dependency on [`nfs3-rs`](https://github.com/Vaiz/nfs3) (Unlicense). In v0.6.0 the code was absorbed outright and the vendor patch tree deleted. `ref/nfs3/` remains for diffing against upstream. Each crate carries a NOTICE with the file-level provenance mapping.

**The layer boundary is strict.** The protocol crates hold no policy -- no pooling, no retries, no circuit breaking, no stealth delays, no credential escalation. All of that lives in `src/proto/` and reaches the protocol crates through one seam, `onc_rpc_client::RpcTransport`. Two implementations ship: `DirectTransport` (one socket, no policy -- makes each library standalone) and `PooledTransport` (the binary's single policy struct: connection reuse, circuit breaker, stealth pacing, deadlines).

**What the protocol crates provide:**

| Crate | Contents |
|-------|----------|
| `onc-xdr-derive` | `#[derive(XdrCodec)]` proc macro |
| `onc-xdr` | `Pack`/`Unpack` traits, `Opaque`, `List`, `BoundedList`, `Void`, length-hardened readers (`PREALLOC_CAP`) |
| `onc-rpc-client` | `RpcClient`, `RpcTransport` trait, `DirectTransport`, `AuthSys`, `AuthFlavor`, fragment headers, `AsyncRead`/`AsyncWrite` with tokio backend |
| `onc-rpcbind` | Portmapper v2 (RFC 1057), rpcbind v3/v4 (RFC 1833), `PortmapperClient`, `RpcbindClient` |
| `nfs-mount` | MOUNT v1/v3 (RFC 1094 Appendix A / RFC 1813 Appendix I), `MountV1Client`, `MountClient` |
| `nfs-v2` | All 18 NFSv2 procedures (RFC 1094), fixed 32-byte handles, `Nfs2Client`, `Nfs2Error` with classification predicates, `Display` for `NfsStat` |
| `nfs-v3` | All 22 NFSv3 procedures, domain API (`FileHandle`, `FileAttrs`, `Nfs3Fault`), `Nfs3Error` with handle-oracle predicates |
| `nfs-v4` | NFSv4.0 COMPOUND (RFC 7530) read-only subset, `Display` for `Nfs4Status` |

**What is deliberately absent:**
- A server implementation -- integration tests use the published `nfs3_server` crate as a mock
- The stateful half of NFSv4: OPEN, CLOSE, LOCK, delegations, v4.1 sessions (RFC 8881)
- RPCSEC_GSS / Kerberos (RFC 2203) -- detection only, via MOUNT auth flavors and NFSv4 SECINFO
- NLM and NSM -- removed in v0.2.0 with the lock-DoS module; F-6.x is out of scope

**What `src/proto/` adds on top:**
- `PooledTransport` (`src/proto/transport.rs`) -- the keystone: carries connection pool, circuit breaker, stealth config, credential and deadline in one struct
- AUTH_SYS stamp counter (global AtomicU32 from 42, incremented per encode) -- defeats duplicate-request caching during UID spraying (RFC 1057 §9.2)
- Connection pool with health-based eviction (see below)
- Circuit breaker per host (see below)
- Evidence-driven credential ladder (see below)
- SOCKS5 proxy transport via a custom `Connector` (inline CONNECT, no external crate)
- UDP transport for portmapper probes against TCP-filtered hosts
- Privileged port binding (< 1024) via socket2 + cap_net_bind_service
- Per-call 30s deadlines so a stalled server cannot drain the pool
- MOUNT auth flavor extraction and export ACL parsing
- File handle analysis, escape construction, fingerprinting

**Why not libnfs?** libnfs is a mature C library supporting NFSv3 and v4, but:
- Requires a C toolchain for cross-compilation -- breaks the single static binary goal
- No Rust bindings exist -- would need manual FFI (52+ unsafe blocks, as niffler demonstrates)
- High-level API hides error codes we need (the STALE vs BADHANDLE oracle)
- Event-loop model requires spawn_blocking wrappers for async compatibility
- No NFSv2 support either

niffler's v4 path (manual FFI to libnfs) has 52 unsafe blocks, manual struct layout assertions, RAII wrappers for C pointers, and `spawn_blocking` on every operation. We avoid all of this.

**Why not NetApp nfs-rs?** [`nfs-rs`](https://github.com/NetAppLabs/nfs-rs) is synchronous -- a non-starter for a tokio architecture. It covers NFSv3 + NFSv4.1 via the nfs4p1-rs submodule, whose `ArgOp`/`ResOp` enums and COMPOUND structs were a useful reference when writing `nfs-v4`, but it encodes with `serde-xdr` (an incompatible codec), so the types were adapted rather than depended on.

### RPC Layer

The `RpcTransport` trait is the single seam between protocol and policy:

```rust
pub trait RpcTransport: Send + Sync {
    type Error: std::error::Error + Send + Sync + 'static;
    fn call<C, R>(&self, prog: u32, vers: u32, proc: u32, args: &C)
        -> impl Future<Output = Result<R, Self::Error>> + Send
    where C: Pack + Send + Sync, R: Unpack;
    fn call_as<C, R>(&self, cred: opaque_auth<'static>, prog: u32, vers: u32, proc: u32, args: &C)
        -> impl Future<Output = Result<R, Self::Error>> + Send
    where C: Pack + Send + Sync, R: Unpack;
}
```

`DirectTransport` (library) owns one socket and applies no policy. `PooledTransport` (binary, `src/proto/transport.rs`) holds all five policy concerns -- connection pool, circuit breaker, stealth config, credential and per-call deadline -- and dispatches through a single `call()` that checks out a connection, sends the RPC, updates circuit breaker state, and returns the connection (or poisons it).

`NfsConnection` (`src/proto/conn.rs`) wraps a single `RpcClient` with health tracking, reconnect logic, the inline SOCKS5 connector, and GETATTR-on-root health checks (with NULL fallback).

**AUTH_SYS stamp handling**: Global atomic counter starting at 42, incremented per `encode()` call (`src/proto/auth.rs`). Injected into the `auth_unix` struct before each RPC call, preventing false duplicate-request-cache hits during UID spraying (RFC 1057 §9.2).

### Connection Pool with Health Eviction

Per-(host, export, uid, gid) connection pools with health-aware lifecycle management.

```rust
/// Pool key -- one pool per unique (host, export, uid, gid) tuple.
pub struct PoolKey {
    host: SocketAddr,
    export: String,
    uid: u32,
    gid: u32,
}

pub struct ConnectionPool {
    pools: DashMap<PoolKey, Arc<Mutex<VecDeque<NfsConnection>>>>,
    max_per_key: usize,        // max idle connections per key (default 4)
    max_total: usize,          // global connection limit (default 256)
    admission: Arc<Semaphore>, // one permit per outstanding checkout
    stale_threshold: Duration, // connections older than this get health-checked (default 5s)
}
```

**Lifecycle:**
1. **Checkout**: pop from idle queue -> if older than `stale_threshold`, send GETATTR on root handle as health check -> if healthy, return; if stale, discard and create new
2. **Return**: push back to idle queue (LIFO for cache warmth)
3. **Poison**: on RPC failure, mark connection as poisoned (discarded on next checkout)
4. **Backpressure**: admission is gated by `tokio::sync::Semaphore` with `max_total` permits -- prevents thundering herd

### Circuit Breaker per Host

Protects scan and analysis operations from cascading failures when hosts go down.

```rust
pub struct CircuitBreaker {
    hosts: DashMap<SocketAddr, HostHealth>,
    window: Duration,          // sliding window (default 60s)
    error_threshold: f64,      // trip at this error rate (default 0.80)
    min_samples: usize,        // minimum events before evaluating (default 10)
    base_cooldown: Duration,   // initial cooldown after trip (default 5s)
    max_cooldown: Duration,    // cap on exponential backoff (default 5min)
}

pub struct HostHealth {
    events: VecDeque<(Instant, bool)>,  // (timestamp, success)
    trip_count: u32,                     // number of times tripped
    tripped_until: Option<Instant>,      // cooldown expiry
}
```

**Behavior:**
- Only **transient** errors count (timeout, connection reset, ECONNREFUSED). Permission denials (NFS3ERR_ACCES, NFS3ERR_PERM) are expected during UID spraying and do NOT trip the breaker.
- Cooldown: `base * 2^(trip_count - 1)` with full jitter, capped at `max_cooldown`
- Recovery: success rate rises above `1.0 - (error_threshold / 2.0)` (i.e., above 60% at default 0.80 threshold) -> reset `trip_count`

### Evidence-Driven Credential Ladder

Every NFS operation that hits NFS3ERR_ACCES is retried through a credential sequence built from evidence already in hand (`src/engine/credential.rs`):

```
1. File owner (uid, gid)         -- from the GETATTR that preceded the refusal
2. Caller UID + file owner GID   -- catches group-readable files when root is squashed
3. Root (0, 0)                   -- works where the export allows no_root_squash
4. Observed identities           -- (uid, gid) pairs from READDIRPLUS, ranked by frequency
5. Service accounts              -- nobody, www-data, mysql, postgres (fixed list)
```

The ladder is shortened by the target's mode bits: when `mode & 0o007 == 0`, POSIX gives an identity that is neither the owner nor in the owning group no path to the file, so rungs 4-5 are provably wasted RPC and are skipped. Root keeps its rung regardless, because `no_root_squash` bypasses the check outright.

Steps 1-3 cost zero or one extra RPC. Step 4 reuses data already collected (every READDIRPLUS reply carries per-entry ownership). Step 5 costs one RPC each. Exhaustive UID/GID brute force is the `uid-spray` subcommand, never automatic.

File handles obtained during the directory walk are reused across all credential attempts -- NFS handles are bearer tokens (RFC 1094 §2.3.3), not bound to the credential that obtained them. If a handle returns NFS3ERR_STALE during a retry, re-LOOKUP from the parent directory.

### NFSv3 Protocol Client

The library crate (`nfs-v3`) exposes a domain API that takes and returns `FileHandle`, `FileAttrs` and friends rather than raw XDR. Failures are reported as `Nfs3Fault<E>`, which separates "no answer from the server" (`Rpc(E)`) from "the server answered and refused" (`Status(Nfs3Error)`).

In the binary, `Nfs3Client` is a type alias: `nfs_v3::Nfs3Client<PooledTransport>`. The domain methods (`attrs`, `resolve`, `read_at`, `write_at`, `list_dir`, `read_all`, `walk`, etc.) are inherent methods on the library's `Nfs3Client<T>`. The `PooledNfs3` extension trait adds pool-specific accessors (`host`, `uid`, `gid`, `machinename`, `with_credential`) that let the shell, FUSE, and offensive subcommands switch credentials mid-session.

### File Handle Analysis

The `FileHandleAnalyzer` is the core primitive enabling findings F-2.1 through F-2.6. It decodes the Linux `knfsd_fh` structure to fingerprint the server OS/filesystem and construct handles targeting arbitrary inodes.

```rust
/// Decode and analyze NFS file handles for OS/FS fingerprinting and escape
/// Implementation: src/engine/file_handle.rs
pub struct FileHandleAnalyzer;

impl FileHandleAnalyzer {
    /// Identify the server OS from handle structure (F-2.1)
    pub fn fingerprint_os(fh: &FileHandle) -> OsGuess;

    /// Identify the filesystem type from fileid_type (F-2.1)
    pub fn fingerprint_fs(fh: &FileHandle) -> FsType;

    /// Construct a handle targeting an arbitrary inode (F-2.1, F-2.2 -- generic primitive)
    pub fn construct_handle_for_inode(fh: &FileHandle, inode: u32, gen: u32) -> Option<EscapeResult>;

    /// Construct root directory handle (F-2.1 -- sugar for root inode per FS type)
    /// ext4: inode=2, xfs: inode=128/64, btrfs: inode=256
    pub fn construct_escape_handle(fh: &FileHandle) -> Option<EscapeResult>;

    /// Construct all XFS root candidates (inodes 32, 64, 128)
    pub fn construct_xfs_escape_candidates(fh: &FileHandle) -> Vec<EscapeResult>;

    /// Construct all known-root candidates across ext4/XFS/BTRFS
    pub fn construct_root_candidates(fh: &FileHandle) -> Vec<EscapeResult>;

    /// Construct BTRFS subvolume handles (F-2.4 -- subvol IDs 256+)
    pub fn construct_btrfs_subvol_handles(fh: &FileHandle, max_subvols: u32) -> Vec<EscapeResult>;

    /// Check Windows handle signing (F-2.3 -- HMAC present/absent)
    pub fn check_windows_signing(fh: &FileHandle) -> SigningStatus;

    /// Estimate handle entropy in bits (F-2.2 -- brute-force feasibility)
    pub fn estimate_entropy(fh: &FileHandle) -> EntropyAnalysis;
}

/// Handle oracle: NFS3ERR_BADHANDLE (10001) = wrong format, NFS3ERR_STALE (70) = right format,
/// wrong inode/gen. This distinction enables targeted brute-force (F-2.2, RFC 1813 §2.6).
```

**Handle structure decoded** (Linux `knfsd_fh`):

| Field | Size | Description |
|-------|------|-------------|
| `fh_version` | 1 byte | Always 1 for knfsd |
| `fh_auth_type` | 1 byte | 0 = no auth |
| `fh_fsid_type` | 1 byte | 0=dev(8B) 1=dev(4B) 2=dev+UUID(12B) 3-5=dev(8B) 6=UUID(16B) 7=compound-UUID(24B) |
| `fh_fileid_type` | 1 byte | 0=root 1=INO32_GEN(ext4) 2=INO32_GEN_PARENT 0x4d-0x4f=BTRFS 0x81=INO64_GEN(XFS) |
| `fh_fsid[]` | variable | Filesystem identifier (length determined by fh_fsid_type) |
| `fh_fileid[]` | variable | Inode + generation number (BTRFS: objectid + root_objectid + gen = 20 bytes) |

### File Handle Fingerprinting -- Live Test Findings

The following was established by live testing against loop-device filesystems of each type on Ubuntu 6.8 with Linux knfsd. These findings are encoded in `FileHandleAnalyzer` and drive the fast-path candidates in `construct_xfs_escape_candidates`.

**XFS root inode number by mkfs configuration:**

| `mkfs.xfs` flags | Inode size | Inodes/4KB block | Root inode |
|---|---|---|---|
| default (v5 CRC) | 512 B | 8 | **128** |
| `-i size=512` (v5) | 512 B | 8 | **128** |
| `-m crc=0` (v4 default) | 512 B | 8 | **128** |
| `-m crc=0 -i size=512` (v4) | 512 B | 8 | **64** |
| `-m crc=0 -i size=1024` (v4) | 1024 B | 4 | **32** |

The formula: root inode = reserved_blocks x inodes_per_block. XFS reserves 8 blocks in AG0 for the superblock and metadata B-trees. The three candidates (32, 64, 128) are all probed in the fast-path before falling through to the inode scan.

**Distinguishing ext4 vs XFS from handle bytes:**

1. `fileid_type == 0x81` (FILEID_INO64_GEN) -> **XFS only**. ext4 always uses 32-bit inodes (0x01).
2. Inode 2 in the handle -> **ext4/ext3/ext2** (root inode is always 2).
3. Inode 32, 64, or 128 in the handle -> **XFS** (root inode, layout-dependent).
4. `fileid_type 0x4d-0x4f` -> **BTRFS** (regardless of fsid_type).
5. `fsid_type=7, fileid_type=0, len=28` -> **compound UUID format** (ext4 OR XFS -- ambiguous; try all candidates).

**BTRFS escape handle format (20-byte fileid):**

For `FILEID_BTRFS_WITHOUT_PARENT (0x4d)` per `fs/btrfs/export.c`:
```
objectid      (u64 LE)  -- inode object ID in the subvolume; always 256 (BTRFS_FIRST_FREE_OBJECTID) for root dir
root_objectid (u64 LE)  -- subvolume/tree ID (5 = FS_TREE, 256+ = user subvolumes)
gen           (u32 LE)  -- generation number
```

For compound UUID MOUNT handles (fsid_type=7, fileid_type=0, 28 bytes), the 24-byte export context is the full fsid for BTRFS escape handles (not just the 16-byte UUID). Both variants are probed automatically.

**Export option effects on escape:**

| Option | Blocks escape? | Notes |
|---|---|---|
| `no_subtree_check` | No | Server only validates fsid; inode can be anywhere on FS |
| `subtree_check` | Yes (mostly) | Server validates parent chain; bind mounts make this unreliable |
| `root_squash` | No | Squashes uid/gid 0 responses; handle bearer token property unaffected |
| `all_squash,anonuid=0` | No | All clients run as uid=0; stronger than no_root_squash |
| `ro` | No (reads) | Escape works for reads; writes blocked at server |
| `fsid=0` | No | Numeric fsid (fsid_type=1, 4-byte); escape still constructs correctly |
| overlayfs as export | N/A | `exportfs` refuses overlayfs; `MNT3ERR_ACCES` returned to client |

**subtree_check + bind mounts:** Linux `man exportfs` warns that subtree checking is unreliable with bind mounts. During testing, `subtree_check` on a bind-mounted subdirectory did not prevent escape to sibling inodes. The NFS server could not correctly determine subtree boundaries across the bind mount. This is a known Linux kernel limitation.

## Finding Coverage Matrix

Every finding in [FINDINGS.md](FINDINGS.md) maps to one or more nfswolf modules:

"X" indicates the subcommand exercises (or directly enables exploitation
of) the finding. The offensive subcommands `escape`, `brute-handle`, and
`uid-spray` are grouped under the `escape` / `brute-handle` / `uid-spray`
columns. Read/write/upload/recursive-walk against an escape handle is
done from `shell` or `mount`.

| Finding | Title | Severity | scan | analyze | escape | brute-h. | uid-spray | mount | shell |
|---------|-------|----------|------|---------|--------|----------|-----------|-------|-------|
| F-1.1 | UID/GID Spoofing | Critical | | X | | | X | X | X |
| F-1.2 | Root Squash Bypass | High | | X | | | X | | X |
| F-1.3 | Auxiliary Group Injection | High | | X | | | X | X | X |
| F-1.4 | Machine Name Spoofing | Low | | | | | | X | X |
| F-1.5 | Credential Replay | High | | | | | | | |
| F-1.6 | NFSv2 Downgrade | High | X | X | | | | | |
| F-1.7 | RPCSEC_GSS Flavor Downgrade | High | | X | | | | | |
| F-2.1 | Export Escape | Critical | | X | X | | | X | X |
| F-2.2 | File Handle Guessing | High | | X | | X | | | |
| F-2.3 | Windows Handle Signing | Critical | | X | | | | | |
| F-2.4 | BTRFS Subvolume Escape | High | | X | X | | | X | X |
| F-2.5 | Stale Handle Persistence | Medium | | | | X | | X | |
| F-2.6 | Bind Mount Escape | High | | | X | | | X | X |
| F-2.7 | NFS Daemon ACL Blindness | Critical | | | X | | | X | X |
| F-2.8 | Sibling Export Lateral Access | Critical | | | X | | | X | X |
| F-2.9 | WebNFS Public File Handle | Critical | | X | | | | | |
| F-3.1 | Plaintext Wire Protocol | High | | X | | | | | |
| F-3.2 | Portmapper Amplification | Medium | X | X | | | | | |
| F-3.3 | IP Spoofing | High | | X | | | | | |
| F-3.4 | STRIPTLS Downgrade | High | | X | | | | | |
| F-3.5 | Portmapper Bypass | Medium | X | | | | | | |
| F-3.6 | UDP MOUNT Handle Theft | Critical | X | | | | | | |
| F-4.1 | no_root_squash | Critical | | X | | | | X | |
| F-4.2 | SUID/SGID Escalation | High | | | | | | X | X |
| F-4.3 | Device Node Creation | High | | | | | | X | X |
| F-4.4 | Symlink Escape | High | | X | | | | X | X |
| F-4.5 | SELinux Label Bypass | Medium | | | | | | | |
| F-5.1 | Export List Enumeration | Medium | X | X | | | | | |
| F-5.2 | READDIRPLUS Harvesting | High | | | | | | X | X |
| F-5.3 | NIS Credential Extraction | High | X | X | | | | | |
| F-5.4 | RPC Service Enumeration | Low | X | | | | | | |
| F-5.5 | NFSv4 Pseudo-FS Leakage | Low | X | X | | | | | |
| F-7.1 | Wildcard Exports | High | X | X | | | | | |
| F-7.2 | Privileged Port Bypass | Medium | | | | | | | |
| F-7.3 | nohide/crossmnt Exposure | Medium | | X | | | | X | X |
| F-7.4 | Missing nosuid/nodev | High | | | | | | | |
| F-7.5 | Squash Misconfiguration | Critical | | X | | | | | |
| F-7.6 | No Audit Logging | Medium | | | | | | | |

**Notes:**
- F-1.5 (Credential Replay) is a passive attack -- nfswolf detects the precondition (no encryption) via F-3.1
- F-6.x (NLM/NSM lock attacks, grace-period DoS, SETCLIENTID state destruction) is intentionally out of scope. The lock-DoS module was removed; F-6.2 / F-6.3 were never implemented.
- F-7.6 (No Audit Logging) is an operational gap -- documented for awareness, not remotely testable

## Technology Stack

| Component | Choice | Rationale |
|-----------|--------|-----------|
| Language | **Rust** | Zero-cost abstractions, no GC, memory safety, single binary |
| NFS protocol stack | **`crates/`** (8 crates, in-tree) | NFSv2/v3/v4 + RPC + XDR + portmapper + MOUNT + rpcbind, pure Rust, tokio async, no C deps |
| Async runtime | tokio | Industry standard, excellent for network I/O |
| CLI framework | clap | Derive macros, subcommands, shell completions |
| FUSE binding | fuser | Pure Rust FUSE implementation |
| Shell REPL | rustyline | Readline with tab completion and history |
| Serialization | serde + serde_json | JSON output |
| Networking | tokio::net | Async TCP/UDP + privileged port binding via TcpSocket |
| Proxy | Inline SOCKS5 CONNECT (`src/proto/conn.rs`) | No external crate; one-shot handshake |
| Connection pool | Custom (DashMap + VecDeque) | Per-(host, export, uid, gid) pooling with health eviction |
| Terminal output | colored + tabled + indicatif | ANSI colors, tables, progress bars |
| Integrity | sha2 | SHA-256 for `get --verify` evidence chain |
| Testing | proptest + assert_cmd + nfs3_server | Property-based + CLI + in-process NFS mock |

## Project Structure

```
nfswolf/
├── Cargo.toml                     # Workspace root (8 library crates + 1 binary)
├── crates/
│   ├── onc-xdr-derive/            # #[derive(XdrCodec)] proc macro
│   ├── onc-xdr/                   # RFC 4506 codec: Pack, Unpack, Opaque, List, hardened readers
│   ├── onc-rpc-client/            # ONC RPC v2, AuthSys, RpcTransport seam
│   ├── onc-rpcbind/               # Portmapper v2 (RFC 1057) / rpcbind v3/v4 (RFC 1833)
│   ├── nfs-mount/                 # MOUNT v1/v3 (RFC 1094 App A / RFC 1813 App I)
│   ├── nfs-v2/                    # RFC 1094: all 18 procedures, fixed 32-byte handles
│   ├── nfs-v3/                    # RFC 1813: 22 procedures + domain API
│   └── nfs-v4/                    # RFC 7530: COMPOUND encoder, stateless read-only subset
├── src/
│   ├── main.rs                    # CLI entry point with tracing + subcommand dispatch
│   ├── output.rs                  # status_info/warn/err, print_handle, print_handle_next_steps
│   ├── shell/                     # NfsShell: 44+ commands, tab completion, readline REPL
│   │   ├── mod.rs                 # Shell REPL loop, command dispatch, tab completion
│   │   ├── complete.rs            # Tab completion for remote/local paths
│   │   ├── ops.rs                 # ShellOps trait + version-neutral types
│   │   ├── v2.rs                  # V2Ops: ShellOps impl for NFSv2 with identity change via TCP reconnect
│   │   └── v3.rs                  # V3Ops: ShellOps impl for NFSv3 with credential escalation (read_file and read_chunk)
│   ├── fuse.rs                    # NfsFuse: full FUSE Filesystem trait, inode map, attr cache
│   ├── cli/
│   │   ├── mod.rs                 # Cli, Command enum, GlobalOpts, H_* help-section constants
│   │   ├── target.rs              # Unified host[:/export] positional parser
│   │   ├── probe.rs               # Shared connection/lookup helpers for offensive subcommands
│   │   ├── scan.rs                # nfswolf scan
│   │   ├── analyze.rs             # nfswolf analyze
│   │   ├── mount.rs               # nfswolf mount (FUSE) -- daemonises
│   │   ├── shell.rs               # nfswolf shell (NFSv2, NFSv3, and NFSv4 dispatch)
│   │   ├── escape.rs              # nfswolf escape
│   │   ├── brute_handle.rs        # nfswolf brute-handle
│   │   ├── uid_spray.rs           # nfswolf uid-spray (last-resort fallback)
│   │   └── convert.rs             # nfswolf convert
│   ├── proto/
│   │   ├── mod.rs
│   │   ├── auth.rs                # AUTH_SYS stamp counter + Credential type
│   │   ├── conn.rs                # NfsConnection: health tracking, reconnect, Socks5Connector
│   │   ├── pool.rs                # ConnectionPool: per-(host, export, uid, gid), LIFO + health
│   │   ├── circuit.rs             # CircuitBreaker: sliding window, exponential cooldown
│   │   ├── transport.rs           # PooledTransport: the single RpcTransport impl in the binary
│   │   ├── udp.rs                 # call_rpc_udp(): single-shot UDP RPC + NULL probe
│   │   ├── mount.rs               # NfsMountClient: EXPORT, MNT, UMNT, auth-flavor extraction
│   │   ├── portmap.rs             # PortmapClient: DUMP, GETPORT, NIS detection, amplification
│   │   ├── nfs2.rs                # Nfs2Client type alias (library client + PooledTransport)
│   │   ├── nfs3/mod.rs            # Nfs3Client type alias (library client + PooledTransport)
│   │   └── nfs4/{mod,compound}.rs # Nfs4DirectClient (pool-free, direct port 2049)
│   ├── engine/
│   │   ├── mod.rs
│   │   ├── scanner.rs             # Parallel host scanner (R1.1-R1.3); ScanOutput, ScanConfig
│   │   ├── scan_types.rs          # HostResult, TargetSpec, NfsPortInfo, MountPortInfo, PortReachability, V4ExportEntry, VersionRange
│   │   ├── analyzer.rs            # Security check engine (R2-R4)
│   │   ├── file_handle.rs         # Handle analysis + escape (F-2.1-F-2.6)
│   │   ├── uid_sprayer.rs         # UID/GID brute-force (F-1.1-F-1.3)
│   │   └── credential.rs          # credential_ladder() / credential_ladder_with() / observed_identities()
│   ├── report/
│   │   ├── mod.rs                 # Renderer dispatch + AnalysisResult + risk scoring
│   │   ├── console.rs             # ANSI-coloured terminal output
│   │   ├── html.rs                # Self-contained HTML report
│   │   ├── json.rs                # JSON serialisation
│   │   ├── txt.rs                 # Plain-text summary
│   │   ├── csv.rs                 # One row per finding
│   │   └── markdown.rs            # GitHub-flavoured Markdown
│   └── util/
│       ├── mod.rs
│       ├── stealth.rs             # StealthConfig: delay + jitter + async wait()
│       └── utmp.rs                # wtmp / btmp / lastlog binary record parsers
├── tests/integration/             # 6 test binaries
│   ├── scan_test.rs
│   ├── nfs3_protocol_test.rs
│   ├── analyzer_test.rs
│   ├── escape_test.rs
│   ├── credential_test.rs
│   └── xdr_fuzz_test.rs
├── docs/
│   ├── FINDINGS.md                # Finding catalog (41 findings, F-1.1 through F-7.6)
│   ├── REQUIREMENTS.md            # Tool requirements (R1 through R7)
│   ├── DESIGN.md                  # Vision, goals, threat model
│   ├── ARCHITECTURE.md            # This file
│   ├── NFSv2.md, NFSv3.md, NFSv4.md  # Protocol reference notes
│   └── findings/                  # Detailed finding write-ups (42 files: 41 findings + README)
└── ref/
    ├── nfs3/                      # Read-only Vaiz/nfs3 checkout (for upstream diffing)
    └── rfc/                       # NFS/RPC/XDR RFCs (1057, 1094, 1813, 1831, 2623, 5531, 7530, 9289)
```

## CLI Interface

### Global Options

```
nfswolf [OPTIONS] <COMMAND>

Options:
    --uid <UID>              AUTH_SYS UID for all operations [default: 1000]
    --gid <GID>              AUTH_SYS primary GID [default: 1000]
    --aux-gids <N,N,...>     Auxiliary GIDs in AUTH_SYS (max 16 per RFC 1057 §9.2)
    --hostname <NAME>        Spoof auth_unix.machinename [default: localhost]
    --privileged-port        Bind to source port < 1024 (cap_net_bind_service / root)
    --proxy <SOCKS5>         Route every TCP through a SOCKS5 (no-auth) proxy
    --nfs-port <PORT>        Override NFS port (skip portmapper)
    --mount-port <PORT>      Override mountd port (skip portmapper)
    --timeout <MS>           Connection timeout [default: 3000]
    --delay <MS>             Baseline inter-RPC delay [default: 0]
    --jitter <MS>            Random jitter added to each delay [default: 0]
    --no-color               Strip ANSI colors
    -v / -vv / -vvv          Verbosity (info / debug / trace)
    --quiet                  Suppress non-essential output

Commands:
  Recon:
    scan         Discover NFS servers on a network
    analyze      Deep security audit of an NFS server
    escape       Break out of an export to the filesystem root (subtree_check bypass)
  Connect:
    shell        Interactive NFS shell (NFSv3 default; --nfs-version 2 for v2, 4 for v4)
    mount        FUSE-mount an NFS export with UID spoofing
  Advanced:
    brute-handle Brute-force file handles via the STALE / BADHANDLE oracle
    uid-spray    Last-resort UID/GID brute force
  Utilities:
    convert      Render an `analyze --json` dump to HTML / JSON / CSV / MD / text / console
    completions  Generate shell completions (bash / zsh / fish / PowerShell)
```

The categories above are display groupings in `--help` (via `after_help`); every
command is still invoked flat, e.g. `nfswolf scan ...`, `nfswolf brute-handle ...`.

### Example Workflows

#### Red Team: Full Assessment

```bash
# 1. Discover NFS servers (F-5.4 portmapper enum, F-5.1 export enum)
nfswolf scan 10.0.0.0/8 --json targets.json

# 2. Deep analysis of each target (full check matrix is always on)
nfswolf analyze -f targets.txt --json findings.json

# 3. Construct an escape handle (F-2.1)
HANDLE=$(nfswolf escape 10.0.1.50:/srv/share --json | jq -r .root_handle)

# 4. Mount the escaped filesystem and extract loot (F-2.1 + F-1.1)
nfswolf mount 10.0.1.50 /mnt/target --handle "$HANDLE"
find /mnt/target/home -name "id_rsa" -exec cp {} ./loot/ \;
cp /mnt/target/etc/shadow ./loot/  # gid=42 spoof handled by mount's auto-UID ladder

# 5. Generate report (R6.1)
nfswolf convert --format html --input findings.json -o nfs-assessment.html
```

#### Blue Team: Configuration Audit

```bash
# Audit all NFS servers in the environment
nfswolf scan 192.168.0.0/16 --json inventory.json
nfswolf analyze -f inventory.json --json audit.json

# Parse JSON for custom alerting or generate HTML report
```

#### Penetration Testing: Quick Win Check

```bash
# One-liner to filter critical findings
nfswolf analyze target --quiet --json | jq '.findings[] | select(.severity == "critical")'
```

## Performance Targets

| Operation | Target | Notes |
|-----------|--------|-------|
| Port scan (2049) | 10,000 hosts/min | SYN scan with tokio |
| Full enumeration | 1,000 hosts/min | Portmap + mount + version |
| Export escape | < 1 second | Single handle construction |
| Handle brute-force (Linux root) | < 5 seconds | ~1,536 candidates |
| Directory listing (10K files) | < 2 seconds | READDIRPLUS batching |
| File download (100 MB) | Wire speed | 64KB read chunks |
| FUSE read latency | < 5ms overhead | Over raw NFS |

## Security Considerations for the Tool Itself

- Default read-only mode -- write operations require explicit flags
- No credentials stored on disk by default
- Clear documentation of what each operation does on the wire
- Support for operation logging (what was accessed, when, by which UID)

## Build and Distribution

```bash
# Development build
cargo build

# Release build (optimized, static linking)
cargo build --release --target x86_64-unknown-linux-musl

# Cross-compile for common targets
cargo build --release --target x86_64-unknown-linux-musl    # Linux amd64
cargo build --release --target aarch64-unknown-linux-musl   # Linux arm64
cargo build --release --target x86_64-apple-darwin          # macOS amd64
cargo build --release --target aarch64-apple-darwin         # macOS arm64
cargo build --release --target x86_64-pc-windows-gnu        # Windows amd64

# Install from git
cargo install --git https://github.com/StrongWind1/NFSWolf
```

## Comparison with Existing Tools

Ordered by similarity to nfswolf (most comprehensive first, most narrow last). Only NFS security/offensive tools included -- libraries and non-offensive clients excluded.

| Feature | nfswolf | nfs_analyze | nfscli | niffler | fuse_nfs | NfSpy | nfsshell | NFSwalker | EvilNFSClient | RPCScan |
|---------|---------|-------------|--------|---------|----------|-------|----------|-----------|---------------|---------|
| **General** | | | | | | | | | | |
| Language | Rust | Python | C | Rust | Python | Python 2 | C | Python | Go | Python |
| Single binary | Yes | No | Yes | Yes | No | No | Yes | No | Yes | No |
| Cross-platform | Yes | Linux | Linux | Yes | Linux | Linux | Linux | Yes | Yes | Linux |
| Maintained | New | Active | Active (2026) | Active (2026) | Active | Dead (2014) | Semi (2025) | Active | Active | Dead (2018) |
| **Protocol** | | | | | | | | | | |
| NFSv2 | Yes | No | Yes | No | No | No | No | No | No | No |
| NFSv3 | Yes | Yes | Yes | Yes | Yes | Yes | Yes | Yes | Yes | Yes |
| NFSv4 | Yes | Yes | No | Yes | No | No | No | Partial | No | No |
| NFSv4 SECINFO | Yes | Yes | No | No | No | No | No | No | No | No |
| NFSv4 ACL extraction | Yes | No | No | No | No | No | No | Yes | No | No |
| **Reconnaissance** | | | | | | | | | | |
| Network scan | Yes | Yes | No | Yes | No | No | No | No | No | Yes |
| Export enumeration (F-5.1) | Yes | Yes | Yes | Yes | No | No | Yes | No | Yes | Yes |
| Client enumeration | Yes | Yes | Yes | No | No | No | Yes | No | No | No |
| Portmapper DUMP (F-5.4) | Yes | Yes | No | Yes | No | No | No | No | No | Yes |
| Portmap amplification (F-3.2) | Yes | No | No | No | No | No | No | No | No | No |
| NIS detection (F-5.3) | Yes | No | No | No | No | No | No | No | No | No |
| TLS/STRIPTLS detection (F-3.4) | Yes | No | No | No | No | No | No | No | No | No |
| **Identity Attacks** | | | | | | | | | | |
| UID/GID spoofing (F-1.1) | Yes | Yes | Yes | Yes | Yes | Yes | Yes | Yes | Yes | Yes |
| Auto-UID mode | Yes | No | Yes | Yes | Yes | Yes | No | No | No | No |
| UID cycling on EPERM | Yes | No | Yes | Yes | Yes | No | No | No | No | No |
| Aux GID injection (F-1.3) | Yes | Yes | No | No | Partial | No | No | Yes | No | No |
| Shadow GID trick (42/15) | Yes | Yes | No | No | No | No | No | No | No | No |
| Machine name spoofing (F-1.4) | Yes | Partial | Partial | No | No | Yes | No | Yes | Partial | Yes |
| Incremental stamps (F-1.5) | Yes | Yes | No | No | No | No | No | No | No | No |
| Per-credential delay | Yes | Yes | No | No | No | No | No | Yes | No | No |
| **Access Control Bypass** | | | | | | | | | | |
| Export escape -- handle construction (F-2.1) | Yes | Yes | No | No | Via handle | No | Via handle | No | No | No |
| Export escape -- LOOKUP `..` traversal | Yes | No | Yes | Yes | No | No | No | No | No | No |
| READDIRPLUS `..` FH leak | Yes | No | Yes | No | No | No | No | No | No | No |
| Cross-export pivot | Yes | No | Yes | No | No | No | No | No | No | No |
| BTRFS subvol escape (F-2.4) | Yes | Yes | No | No | No | No | No | No | No | No |
| Bind mount escape (F-2.6) | Yes | No | No | No | No | No | No | No | No | No |
| Escape confirmation (F-2.1) | Yes | Yes | No | No | No | No | No | No | No | No |
| Handle brute-force (F-2.2) | Yes | No | No | No | No | Via handle | Partial | No | No | No |
| Windows signing detect (F-2.3) | Yes | Yes | No | No | No | No | No | No | No | No |
| Handle entropy analysis (F-2.2) | Yes | No | No | No | No | No | No | No | No | No |
| Raw handle injection | Yes | No | Yes | No | Yes | Yes | Yes | No | No | No |
| **Privilege Escalation** | | | | | | | | | | |
| no_root_squash check (F-4.1) | Yes | Yes | N/A | Yes | N/A | N/A | N/A | N/A | N/A | N/A |
| insecure port check (F-7.2) | No* | No | No | Yes | No | No | No | No | No | No |
| SUID binary plant (F-4.2) | Yes | No | Yes | No | Yes | Indirect | Yes | No | Yes | No |
| Device node creation (F-4.3) | Yes | No | Yes | No | Yes | Yes | Yes | No | No | No |
| Symlink creation (F-4.4) | Yes | No | Yes | No | Yes | Yes | No | No | No | No |
| Symlink attack precheck (F-4.4) | Yes | Yes | No | No | No | No | No | No | No | No |
| **Secret/Credential Discovery** | | | | | | | | | | |
| Shell-driven secret search (`find`, `grep`, `cat`) | Yes | No | Yes | No | No | Yes | Yes | No | Yes | No |
| Mount-driven secret search (regular tools) | Yes | No | Yes | No | Yes | No | No | No | No | No |
| Companion tool for rule-engine harvest (niffler) | Yes | No | No | Yes | No | No | No | No | No | No |
| **Interactive Access** | | | | | | | | | | |
| FUSE mount | Yes | No | Yes | No | Yes | No | No | No | No | No |
| FUSE suid/dev/allow_other | Yes | N/A | N/A | N/A | Yes | No | N/A | N/A | N/A | N/A |
| Interactive shell | Yes | No | Yes | No | No | Yes | Yes | No | Yes | No |
| Readline REPL | Yes | No | No | No | No | No | No | No | Yes | No |
| Stealth mount (F-2.5) | Yes | No | No | No | No | Yes | No | No | No | No |
| Privileged port binding | Yes | No | Yes | Yes | No | No | Yes | Yes | Yes | No |
| **Infrastructure** | | | | | | | | | | |
| OS fingerprinting | Yes | Yes | No | No | No | No | No | No | No | No |
| NetApp nested export fix | Yes | No | No | No | Yes | No | No | No | No | No |
| Keepalive (NULL probe) | Yes | No | No | No | Yes | No | No | No | No | No |
| SOCKS proxy | Yes | No | No | Yes | No | No | No | Yes | No | No |
| Source routing (IP spoof) | No | No | Yes | No | No | No | Yes | No | No | No |
| **Reporting** | | | | | | | | | | |
| Structured output | HTML/JSON/TXT/CSV/MD | JSON | No | SQLite+Web+CSV | No | No | No | No | No | No |
| Finding IDs + RFC citations | Yes | No | No | No | No | No | No | No | No | No |

### Key Differentiators

nfswolf is the only tool that combines all of the following in a single binary:
- **NFSv2 downgrade detection** -- flags the risk when v2 is available alongside v3/v4 with RPCSEC_GSS (F-1.6)
- Handle **construction** escape (F-2.1) + LOOKUP `..` escape + BTRFS subvol + bind mount -- four escape paths
- **Auto-UID/GID** escalation ladder shared by `shell`, `mount`, `escape`, and `uid-spray`
- NFSv4 SECINFO + pseudo-FS mapping + session cleanup
- Portmapper amplification measurement + NIS detection + TLS/STRIPTLS probing
- Incremental AUTH_SYS stamps (anti-cache) + shadow GID trick (42/15)
- Connection pool with health eviction + circuit breaker per host
- JSON output for CI/CD integration with Finding IDs traceable to RFCs

### Supporting Libraries

| Tool | Language | Stars | Relationship to nfswolf |
|------|----------|-------|-------------------------|
| [**nfs3-rs**](https://github.com/Vaiz/nfs3) | **Rust** | 20 | **Absorbed in v0.6.0** -- the NFSv3 + MOUNT + portmapper + XDR code is now spread across `crates/{onc-xdr,onc-xdr-derive,onc-rpc-client,nfs-v3,nfs-mount,onc-rpcbind}` (Unlicense; see each crate's NOTICE). Its `nfs3_server` crate remains a dev-dependency for integration testing. |
| [niffler](https://github.com/evilsocket/niffler) | Rust | -- | **Companion tool** -- deep credential/secret scanning with rule engine, UID cycling, web dashboard. nfswolf finds attack paths, niffler finds secrets. |
| [libnfs](https://github.com/sahlberg/libnfs) | C | 595 | Foundation for fuse_nfs/niffler v4 path; NOT used by nfswolf (C dep breaks static binary goal) |
| [anfs](https://github.com/skelsec/anfs) | Python | 29 | Async NFSv3 (OctoPwn); dynamic UID impersonation per directory; powers fuse_nfs |
| [ShenanigaNFS](https://github.com/JordanMilne/ShenanigaNFS) | Python | 8 | Malicious NFS **server** builder; TOCTOU symlink race, client fuzzing |
| [pynfs](https://github.com/hvs-consulting/pynfs) | Python | -- | NFSv4 test framework; powers nfs_analyze |
| [ms-nfs41-client](https://github.com/kofemann/ms-nfs41-client) | C | 143 | Windows NFSv4.1/pNFS driver; reference for F-2.3 handle signing |
| [nfs4-rs](https://github.com/NetAppLabs/nfs4p1-rs/) | Rust | -- | **Type reference** for NFSv4.1 COMPOUND operations -- ArgOp/ResOp enums, CompoundArgs/CompoundRes, SECINFO, session management. Uses serde-xdr (incompatible codec), so types are adapted, not imported. |
| [nfs-rs](https://github.com/NetAppLabs/nfs-rs) | Rust | 6 | Pure Rust NFSv3+v4.1; synchronous (no async), not used directly |

### Tool Summary by Attack Phase

| Phase | Best existing tool | Gap nfswolf fills |
|-------|--------------------|-------------------|
| **Reconnaissance** | nmap + RPCScan | Unified scan + portmap + NIS + version detect + amp measurement |
| **Analysis** | nfs_analyze | TLS detection, portmap amp, full finding catalog |
| **FUSE Mount** | fuse_nfs | Escape + auto-UID + SOCKS proxy + stealth in one tool |
| **Interactive Shell** | nfscli | Aux GIDs, handle construction escape, machine name spoof -- all in one binary |
| **Secret Harvesting** | niffler | Companion tool -- nfswolf provides escape + shell + mount to reach files; niffler's rule engine finds secrets in them |
| **Export Breakout** | Manual (nfscli + nfs_analyze) | Dedicated `escape` subcommand for ext4 / XFS / BTRFS; hand the resulting handle to `shell` or `mount` |
| **Privilege Escalation** | nfscli (manual) | Spoofed AUTH_SYS UID/GID/aux-GIDs and `mknod` are first-class in `shell` and `mount` |
| **Reporting** | niffler (SQLite+Web+FTS5), nfs_analyze (JSON) | HTML + JSON + TXT + CSV + MD with Finding IDs and RFC citations |
