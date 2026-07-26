# nfswolf -- Project Instructions

## What This Project Is

nfswolf is a Rust NFS security toolkit that consolidates 10+ fragmented NFS security tools into one fast native binary. It covers the full attack path: recon -> analysis -> escape -> shell -> exploitation. For authorized security research only.

## Current Status

v0.6.0 is the last tagged release. The full attack path (recon -> analyze -> escape -> shell -> exploit) is implemented in Rust across 6 workspace crates + the binary, with 451 tests. The `refactor/local-nfs-stack` branch (not yet merged to main) carries the six-crate workspace split, the NFSv3 domain API, the evidence-driven credential ladder, the unified `NfsShell<O: ShellOps>` architecture (v2 and v3 share all 44 shell commands), and several live-tested bug fixes. The v0.2.0 CLI overhaul removed the `attack` umbrella verb, promoted `escape` / `brute-handle` / `uid-spray` to top-level, renamed `export` to `convert`, and removed the NLM and NSM clients (lock-DoS was the only consumer; F-6.x is now out of scope). v0.3.x added the shell `wtmp` / `btmp` / `lastlog` log readers and rebased `escape-root` onto the filesystem root.

The repository is a Cargo workspace. The NFS protocol stack is owned in-tree and split one crate per version over a shared foundation -- see the crate table below. There is no `nfs3_client` dependency and no `vendor/` patch tree; `nfs3_server` remains a dev-dependency for the mock server used in integration tests.

The near-term feature backlog is in the *Feature Backlog -- Next Up* table below.

## Mandatory Reading Before Writing Any Code

Read these files first. Do not skip them. They contain the architectural decisions, threat model, requirement traceability, and API contracts you must follow.

### Project Documentation (read in this order)
1. `docs/DESIGN.md` -- Vision, threat model, 11 key design decisions. Every decision is numbered and referenced by tasks.
2. `docs/ARCHITECTURE.md` -- Module layout, data flow, struct signatures, CLI interface, comparison matrix. This is the source of truth for how modules connect.
3. `docs/REQUIREMENTS.md` -- What each module must detect/do (R1-R7). Every requirement traces to a finding.
4. `docs/FINDINGS.md` -- 41 findings (F-1.1 through F-7.6) organized by attack type. The authoritative catalog and the reference for why each attack works: every finding has severity, RFC reference, detection method, and the protocol-level rationale.
5. `docs/findings/*.md` -- Detailed write-ups for each finding. Read the specific finding file when implementing a check that references it.

### Reference Materials (consult as needed)

**Protocol crates** -- the wire layer, owned in-tree. USE THEM, do not reimplement what they provide.

| Crate | Contents | Depends on |
|-------|----------|-----------|
| `crates/nfswolf-xdr-derive/` | `#[derive(XdrCodec)]` proc macro | -- |
| `crates/nfswolf-xdr/` | XDR codec (RFC 4506): `Pack`, `Unpack`, `Opaque`, `List`, `Void`, length-hardened readers | derive |
| `crates/nfswolf-rpc/` | ONC RPC v2 (RFC 5531), portmapper v2, rpcbind v3/v4 (`RpcbindClient`: GETTIME + GETSTAT, RFC 1833), `AuthSys`, the `RpcTransport` seam, tokio backend | xdr |
| `crates/nfswolf-nfs2/` | NFSv2 (RFC 1094): 18 procedures, fixed 32-byte handles, MOUNT v1 (`MountV1Client`: NULL, MNT, UMNT, EXPORT, RFC 1094 Appendix A) | xdr, rpc |
| `crates/nfswolf-nfs3/` | NFSv3 (RFC 1813): 22 procedures, MOUNT v3, domain types, `Nfs3Error` | xdr, rpc |
| `crates/nfswolf-nfs4/` | NFSv4.0 (RFC 7530): COMPOUND, read-only subset | xdr |

There are no edges between the version crates. Each is a standalone library that deliberately covers more than the tool needs.

**The layer boundary is strict.** The protocol crates hold no policy: no pooling, no retries, no circuit breaking, no stealth delays, no credential escalation. All of that lives in `src/proto/`, and reaches the protocol crates through one seam -- `nfswolf_rpc::RpcTransport`. Do not push policy down into a protocol crate, and do not re-encode wire formats up in `src/`.

**Upstream origin** -- `ref/nfs3/` is a read-only checkout of [Vaiz/nfs3](https://github.com/Vaiz/nfs3), the Unlicense project the NFSv3/MOUNT/portmapper/XDR code was absorbed from in v0.6.0. It is kept for diffing against upstream fixes only; nothing builds against it. See `crates/nfswolf-xdr/NOTICE` for the file-level mapping. The published `nfs3_server` crate is still a dev-dependency, used only as a mock server in integration tests.

**RFCs** -- at `ref/rfc/`. Consult when implementing protocol details:
- `ref/rfc/rfc1057.txt` -- ONC RPC (program, version, procedure model, AUTH_SYS stamp field sec. 9.2)
- `ref/rfc/rfc1094.txt` -- NFSv2 (18 procedures, fixed 32-byte handles, all v2 XDR types)
- `ref/rfc/rfc1813.txt` -- NFSv3 (22 procedures, ACCESS advisory sec. 3.3.4, STALE vs BADHANDLE sec. 2.6)
- `ref/rfc/rfc1831.txt` -- RPC v2
- `ref/rfc/rfc2623.txt` -- NFS security (AUTH_SYS weakness sec. 2.1, handle bearer token sec. 2.6, v2 weakness sec. 2.7)
- `ref/rfc/rfc5531.txt` -- RPC v2 update (AUTH_SYS sec. 14)
- `ref/rfc/rfc7530.txt` -- NFSv4.0 (COMPOUND, SECINFO, pseudo-FS)
- `ref/rfc/rfc9289.txt` -- NFS over TLS (opt-in nature sec. 1)

## Protocol Stack API Quick Reference

Every protocol client is generic over `nfswolf_rpc::RpcTransport`. That trait is the one seam between protocol and policy: above it, wire types; below it, connection management.

### Choosing a transport

```rust
use nfswolf_rpc::{DirectTransport, RpcTransport};

// Library use: one socket, no policy.
let transport = DirectTransport::new(io);

// Inside nfswolf: pooling, circuit breaker, stealth pacing, per-call deadline.
let transport = PooledTransport::new(pool, pool_key, circuit, stealth, cred, reconnect);
```

Both satisfy `RpcTransport`, so every client below works with either.

### NFSv3 (`nfswolf-nfs3`)

```rust
use nfswolf_nfs3::{Nfs3Client, MountClient};
use nfswolf_nfs3::wire::*;

let mount = MountClient::new(transport);
let res = mount.mnt(dirpath(Opaque::borrowed(b"/export"))).await?;
// res.fhandle -> root handle;  res.auth_flavors -> what the export accepts

let nfs = Nfs3Client::new(transport);
let res = nfs.getattr(&GETATTR3args { object: root_fh.clone() }).await?;
let res = nfs.lookup(&LOOKUP3args { what: diropargs3 { dir: root_fh.clone(), name: Opaque::borrowed(b"etc") } }).await?;
let res = nfs.read(&READ3args { file: fh.clone(), offset: 0, count: 65536 }).await?;
```

Results are `Nfs3Result<Ok, Fail>` -- match on them. `Nfs3Result::Err((status, _))` carries an `nfsstat3`; convert with `Nfs3Error::from_nfsstat3(status)` to reach the classification predicates (`is_transient`, `is_permission_denied`, `is_handle_oracle_hit`, `is_handle_oracle_miss`).

### NFSv2 (`nfswolf-nfs2`) and NFSv4 (`nfswolf-nfs4`)

```rust
// v2 exposes a domain API directly -- no raw wire args at the call site.
let v2 = nfswolf_nfs2::Nfs2Client::new(transport);
let (fh, attrs) = v2.lookup(&root, "etc").await?;
let data = v2.read_file(&fh).await?;

// v4 batches operations into one COMPOUND round trip.
use nfswolf_nfs4::{ArgOp, AttrRequest};
let ops = vec![ArgOp::Putrootfh, ArgOp::Lookup("etc".into()), ArgOp::Getfh];
```

### Portmapper, rpcbind, and generic RPC (`nfswolf-rpc`)

```rust
use nfswolf_rpc::{PortmapperClient, RpcbindClient, portmap::IPPROTO_TCP};

// Portmapper v2 (RFC 1057 Appendix A)
let mut pm = PortmapperClient::new(io);
let mappings = pm.dump().await?;                        // every registered service
let port = pm.getport(100_003, 3, IPPROTO_TCP).await?;  // NFSv3 port

// rpcbind v3/v4 (RFC 1833)
let mut rb = RpcbindClient::new(io);
let secs = rb.gettime().await?;                         // server clock (epoch seconds)
let stats = rb.getstat().await?;                        // per-version call counts

// RpcTransport::call is generic -- any program, version, procedure.
let result: MyRes = transport.call(100_003, 2, 4, &args).await?;
```

### MOUNT v1 (`nfswolf-nfs2::mount`)

```rust
use nfswolf_nfs2::MountV1Client;

let mut mount = MountV1Client::new(transport);
let fhstatus = mount.mnt("/export").await?;             // 32-byte root handle
let exports = mount.export().await?;                    // export list (same wire as v3)
```

### AUTH_SYS (`nfswolf-rpc::auth`)

```rust
use nfswolf_rpc::AuthSys;

let cred = AuthSys::with_groups(0, 0, &[0, 42], "localhost");
let opaque = cred.to_opaque_auth(stamp);  // caller supplies the stamp
```

The stamp is deliberately a parameter, not generated inside the library: the counter is nfswolf policy (`src/proto/auth.rs`), so library encoding stays deterministic and testable.

NLM (program 100021) and NSM (program 100024) were removed in v0.2.0 together with the lock-DoS attack module. Do not add them back without also rewriting the F-6.x analyzer surface, which is currently documented as out of scope.

## Critical Design Rules (MUST follow)

1. **Keep the layer boundary**: the `crates/nfswolf-*` protocol crates own the wire format and nothing else. Policy -- pooling, retries, circuit breaking, stealth delays, credential escalation -- lives in `src/proto/` and reaches the protocol crates through one seam, `nfswolf_rpc::RpcTransport`. Do not push policy down into a protocol crate, and do not re-encode wire formats up in `src/`.

2. **AUTH_SYS stamps**: Every RPC call uses a fresh stamp from the global `AtomicU32` counter in `proto::auth.rs` (already implemented). Never reuse stamps -- prevents false duplicate-request-cache hits during UID spraying.

3. **Circuit breaker discrimination**: ONLY transient errors (timeout, connection reset) trip the breaker. Permission denials (`NFS3ERR_ACCES`, `NFS3ERR_PERM`) are EXPECTED during UID spraying and MUST NOT trip the breaker. Use `Nfs3Error::is_transient()`.

4. **Handle oracle**: `NFS3ERR_STALE` (70) = right format, wrong inode/generation. `NFS3ERR_BADHANDLE` (10001) = wrong format entirely. This distinction enables targeted brute-force. Use `Nfs3Error::is_handle_oracle_hit()` / `is_handle_oracle_miss()`.

5. **ACCESS is advisory**: NFSv3 ACCESS results are advisory only (RFC 1813 sec. 3.3.4). Always confirm by attempting the actual operation (READ, WRITE, etc.).

6. **File handles are bearer tokens**: Handles obtained by any credential work with any other credential (RFC 1094 sec. 2.3.3). Reuse handles across UID switches. Only re-LOOKUP on `NFS3ERR_STALE`.

7. **Auto-UID escalation order**: `engine::credential::credential_ladder()` / `credential_ladder_with()` is the evidence-driven ladder -- file owner first, then caller UID with the file's group, then root, then observed identities from READDIRPLUS (ranked by frequency), then common service accounts. When the mode bits prove no "other" access (`mode & 0o007 == 0`), the service-account rungs are skipped. Brute force is the `uid-spray` subcommand, never automatic. Credential escalation is implemented in V3Ops (via `with_credential()` on the pooled client); V2Ops does not escalate (DirectTransport has fixed credentials). The ladder does NOT auto-downgrade from v3 to v2 -- explicit `--nfs-version 2` is required.

8. **Read-only by default**: Write operations require explicit `--allow-write`. Attack modules that write must check this flag.

9. **No C dependencies**: Everything pure Rust. No libnfs, no system NFS client. Binary must be statically linkable via `x86_64-unknown-linux-musl`.

10. **Stealth delay**: Every RPC call path must honor `StealthConfig` when configured. Call `stealth.wait()` before each RPC call.

## Existing Code -- Do Not Rewrite

All of the following are fully implemented and passing `make check-all`. Build on top of them; do not touch unless fixing a bug.

| File | What it does |
|------|-------------|
| `crates/nfswolf-xdr-derive/src/lib.rs` | `#[derive(XdrCodec)]` proc macro generating XDR `Pack`/`Unpack` (RFC 4506) |
| `crates/nfswolf-xdr/src/` | XDR codec: `Pack`, `Unpack`, `Opaque`, `List`, `BoundedList`, `Void`, padding and length-hardened readers |
| `crates/nfswolf-rpc/src/rpc/` | ONC RPC v2 message types + generic `RpcClient` (credential swappable mid-session) |
| `crates/nfswolf-rpc/src/transport/` | The `RpcTransport` seam, `DirectTransport`, `AsyncRead`/`AsyncWrite`, `Connector`, tokio backend |
| `crates/nfswolf-rpc/src/{portmap,auth}` | Portmapper v2 types + client; rpcbind v3/v4 `RpcbindClient` (GETTIME, GETSTAT, RFC 1833); `AuthSys` / `AuthFlavor` (RFC 5531 sec. 14) |
| `crates/nfswolf-nfs2/src/` | All NFSv2 XDR types (18 procedures, fixed 32-byte handles) + `Nfs2Client` + `MountV1Client` (NULL, MNT, UMNT, EXPORT, RFC 1094 Appendix A) |
| `crates/nfswolf-nfs3/src/wire/` | All NFSv3 XDR types (RFC 1813) + MOUNT v3 types |
| `crates/nfswolf-nfs3/src/{raw,mount}.rs` | `Nfs3Client` (22 procedures) and `MountClient` (6 procedures) |
| `crates/nfswolf-nfs3/src/{api,error}` | `FileHandle`, `FileAttrs`, `FileType`, `DirEntryPlus`, `FsStat`, `FsInfo`, access bits; `Nfs3Error` with `is_transient()`, `is_permission_denied()`, handle oracle |
| `crates/nfswolf-nfs4/src/wire.rs` | NFSv4 COMPOUND XDR: GETATTR, READDIR, SECINFO, READ, GETFH (RFC 7530); `ResOpData` |
| `src/main.rs` | CLI entry point with tracing and subcommand dispatch |
| `src/output.rs` | `status_info/warn/err`, `print_handle`, `print_handle_next_steps` |
| `src/shell/mod.rs` | `NfsShell<O: ShellOps>`: unified shell generic over NFS version. 44+ interactive commands (incl. `link`, `root`, `escape-root`, `mount-handle`, `secrets-scan`, `suid-scan`, `world-writable`); tab completion, readline REPL; `get -r`/`put -r` recursive with `indicatif` spinners; `download_file()` returns `(bytes, sha256)`; `--verify <hash>` on `get` |
| `src/shell/ops.rs` | `ShellOps` trait + version-neutral types (`ShellHandle`, `ShellFileInfo`, `ShellEntry`, `ShellFileType`) |
| `src/shell/v3.rs` | `V3Ops`: ShellOps impl wrapping `Arc<Nfs3Client>` with credential escalation + cred cache |
| `src/shell/v2.rs` | `V2Ops`: ShellOps impl wrapping `Nfs2Client<DirectTransport>` (no escalation, no reconnect) |
| `src/fuse.rs` | `NfsFuse`: full FUSE `Filesystem` trait, inode map, attr cache; every `Nfs3Client` procedure wired through a callback; auto-UID escalation per inode |
| `src/cli/mod.rs` | `Cli` struct, `Command` enum (Scan / Analyze / Mount / Shell / Escape / BruteHandle / UidSpray / Convert / Completions), `GlobalOpts`, `H_*` help-section constants, `emit_replay()` |
| `src/cli/target.rs` | `Target` / `Source` / `parse()` -- unified `host[:/export]` positional parser shared by every subcommand that touches a single export |
| `src/cli/probe.rs` | Shared connection / lookup helpers used by the offensive subcommands (`escape`, `uid-spray`, `brute-handle`): `make_mount_client`, pool-backed `Nfs3Client` build, walk-with-escalation |
| `src/cli/scan.rs` | `ScanArgs::run()`: scanner dispatch, output formatting |
| `src/cli/analyze.rs` | `AnalyzeArgs::run()`: analyzer dispatch, finding output |
| `src/cli/mount.rs` | `MountArgs::run()`: FUSE mount driver; daemonises so the FUSE handler outlives the launcher |
| `src/cli/shell.rs` | `ShellArgs::run()`: dispatches NFSv2, NFSv3, or NFSv4 shell. V2 and v3 share `NfsShell<V2Ops>` / `NfsShell<V3Ops>`; `run_nfs4_shell()` + `dispatch_nfs4()` for `--nfs-version 4`. All versions support `--handle HEX` for MOUNT bypass. |
| `src/cli/escape.rs` | `EscapeArgs::run()`: ext4 / XFS / BTRFS escape handle construction; emits handle hex |
| `src/cli/brute_handle.rs` | `BruteHandleArgs::run()`: handle brute-force with STALE/BADHANDLE oracle |
| `src/cli/uid_spray.rs` | `UidSprayArgs::run()`: last-resort UID/GID brute force |
| `src/cli/convert.rs` | `ConvertArgs::run()`: offline rendering of `analyze --json` dumps to HTML / Markdown / CSV / TXT / console |
| `src/proto/auth.rs` | AUTH_SYS stamp injection, `AuthSys`, `Credential`, `to_opaque_auth()` |
| `src/proto/conn.rs` | `NfsConnection`, health tracking, reconnect; inline SOCKS5 support in `connect_proxy()` (no crate dependency) |
| `src/proto/pool.rs` | Connection pool per (host, export, uid, gid), LIFO + health eviction; `ConnectionPool::with_proxy()` |
| `src/proto/circuit.rs` | Circuit breaker: sliding window, exponential cooldown, jitter |
| `src/proto/portmap.rs` | `PortmapClient`: DUMP, GETPORT, NIS detection, amplification measurement (TCP + UDP) |
| `src/proto/mount.rs` | `NfsMountClient`: EXPORT, MNT, UMNT, auth-flavor extraction, `dump_clients` |

| `src/proto/udp.rs` | `call_rpc_udp()`: single-shot UDP RPC call (no record marking); `probe_udp_rpc()` NULL probe |
| `src/proto/nfs3/mod.rs` | `Nfs3Client` type alias binding the library client to `PooledTransport`, plus the `PooledNfs3` accessor trait |
| `src/proto/transport.rs` | `PooledTransport`: the single `RpcTransport` implementation carrying all of nfswolf's connection policy |
| `src/proto/nfs4/{mod.rs, compound.rs}` | `Nfs4DirectClient` (pool-free, direct port 2049, no MOUNT); `probe_nfs4()`; re-exports `nfswolf_nfs4::wire` as `types` |
| `src/engine/file_handle.rs` | `FileHandleAnalyzer`: OS/FS fingerprinting, escape construction (ext4/xfs/btrfs), inode 32/64/128 candidates, BTRFS compound UUID escape, Windows signing, entropy |
| `src/engine/credential.rs` | `credential_ladder()` / `credential_ladder_with()` / `observed_identities()` -- the credential escalation ladder; evidence-driven mode-bit pruning + READDIRPLUS-harvested identity ranking; shared by `shell`, `mount`, `escape`, `brute-handle`, `uid-spray` |
| `src/engine/scanner.rs` | `Scanner::scan_range()`: concurrent host/export/version enumeration; parallel TCP probes via `tokio::join!`; per-RPC `tokio::time::timeout` to survive half-open firewalls; per-host panic isolation |
| `src/engine/analyzer.rs` | `Analyzer::analyze()`: 20+ security checks across the 41 findings (minus F-6.x out-of-scope) |
| `src/engine/uid_sprayer.rs` | `UidSprayer`: UID/GID brute-force with ACCESS oracle |
| `src/report/mod.rs` | Report dispatcher + `AnalysisResult` + risk scoring |
| `src/report/{html,json,txt,csv,markdown,console}.rs` | Six render targets: self-contained HTML, JSON, plain TXT summary, one-row-per-finding CSV, GitHub-flavoured Markdown, ANSI-coloured terminal |
| `src/util/stealth.rs` | `StealthConfig`: delay + jitter + async `wait()` |

## Feature Backlog -- Next Up

No open work items. Completed items and live-test results:

| Feature | Status | Notes |
|---------|--------|-------|
| NFSv2 in the shell | **Done** | Unified `NfsShell<V2Ops>` with all 44 commands. `--nfs-version 2` + `--handle HEX` both work. Live-tested against 4 VMs (kernels 2.6.32-4.15). MOUNT v1 MNT in `src/proto/mount.rs`. Linux knfsd enforces `sec=krb5` on v2 ops; MOUNT v1 leaks handles without krb5 auth. |
| `--scan-udp` against firewalled target | **Verified** | With TCP/111 DROP'd, `--scan-udp` recovers portmapper via UDP/111, resolves mount port, confirms NFSv3. Export enumeration after UDP discovery has a gap (scanner doesn't wire EXPORT after the UDP path). |
| `--hostname` vs IP-based ACLs | **Confirmed** | MNT denied both with and without `--hostname` spoofing. knfsd uses TCP source IP, not `auth_unix.machinename`, for export ACL decisions (per F-1.4). |
| F-1.6 v2 downgrade vs `sec=krb5` | **Live-tested** | Linux knfsd 2.6.32+ enforces `sec=krb5` on v2 NFS operations. MOUNT v1 leaks the handle without krb5 auth. Mixed `sec=krb5:sys` exports are fully accessible via AUTH_SYS on both versions. |

## Code Style

- Rust 2024 edition, MSRV 1.95
- Use `thiserror` for error enums, `anyhow` for application errors
- Use `tracing` for logging (`tracing::info!`, `tracing::debug!`, `tracing::warn!`)
- Use `tokio` for async runtime (already configured)
- Use `colored` for terminal colors, `tabled` for tables, `indicatif` for progress bars
- Imperative commit messages, no emoji, no AI attribution
- Match the style of existing implemented files (auth.rs, file_handle.rs, etc.)
- Comments: explain WHY, not WHAT. Reference RFC sections for protocol details.
- Every protocol constant must reference its RFC section in a comment.

## Build Verification

After every change:
```bash
make check-all
```

This runs: fmt -> clippy (zero warnings) -> cargo deny -> check -> test (451 tests) -> doc -> ascii-check -> lf-check -> machete.

Makefile targets:
- `make dev` -- debug build, fast iteration (`target/debug/`)
- `make build` -- optimised native build, verify before shipping (`target/release/`)
- `make dist` / bare `make` -- cross-compiled shippable artifacts (`dist/`)

Note: `cargo deny check` requires network access to fetch the advisory DB from GitHub. It will fail in air-gapped environments; all other steps pass.

The only Cargo feature is `fuse` (default-on, gates `nfswolf mount`). The project must compile both with `--features fuse` and with `--no-default-features`. The musl-static build drops `fuse` because libfuse3 cannot be statically linked against musl.
