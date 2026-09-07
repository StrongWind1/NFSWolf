# Changelog

All notable changes to nfswolf are documented here. Versions follow [Semantic Versioning](https://semver.org/). Each release is cut locally with `make cut-release VERSION=X.Y.Z` and published via signed tag.

---

## v1.2.0 (2026-08-17)

**Scanner redesign, escape pipeline rewrite, and offline handle decoder.**

- Rewrite `escape` subcommand as a seven-phase pipeline: gather seeds from all protocol versions (MOUNT v3, MOUNT v1, NFSv4 LOOKUP, pseudo-FS walk, upward traversal), construct candidates, probe across versions with credential escalation, dedup/filter, rootfs detection, score/annotate, report
- Add `--fast` mode for single-export quick escape (~10-80 RPCs), shared by `scan --auto-escape` and `shell escape-root`
- Add `--json`, `--read-shadow`, and `--all-handles` flags to `escape`
- Add 5 new handle sources for comprehensive seed gathering in escape pipeline
- Sort escape results by quality, best candidates first
- Annotate escape handles with plain-English analysis and security assessment
- Redesign scanner around a 3-phase pipeline with parallel port probing via `tokio::join!`
- Add `--rpc-port`, `--skip-rpc`, `--skip-mountd`, and `--probe-port` scanner flags
- Add `nfswolf decode` subcommand: offline NFS file handle decoder with field-by-field breakdown, OS/FS fingerprinting, and security assessment (no network access)
- Add NFSv4 export discovery via pseudo-FS fsid walking when MOUNT is unavailable
- Thread `nfs_port` through all analyzer v4 checks
- Fix retry on privileged port binding TIME_WAIT exhaustion
- Cap pseudo-FS walk to 10 children per directory
- Fix `is_root_dir` to parent-is-self only; add v4 probe to `escape --all`; prefer more handles over false negatives
- Extract shared test helpers, deduplicate server setup across integration tests
- Extract shared sideband helpers, move `Nfs3EscapeProbe` to engine
- Unify shell command lists, extract `require_write` guard (eliminates 160 duplicated lines)
- Extract NFSv4 connect helpers, use shared `export_components` / `build_export_lookup_ops` in analyzer
- Extract identity-change guard, merge `cmd_uid`/`cmd_gid` into shared helper
- `fuse.rs` `require_write!` and `get_fh!` macros eliminate 25 repeated guard blocks
- Add 32 unit tests for sanitization, HTML/markdown escape, `format_rwx`, `ShellHandle`, sideband helpers
- Add unit tests for NFS_ACL decode, RQUOTA decode, and escape engine mock probe
- 8 bug fixes across shell, analyzer, CLI, and nfs-v4 crate

## v1.1.0 (2026-08-16)

**Sideband RPC programs, NFSv4 analyzer fallback, and escape engine upgrade.**

- Add NFS_ACL client (program 100227) and F-5.14 POSIX ACL analyzer check
- Add RQUOTA client (program 100011) and F-5.15 UID enumeration analyzer check
- Analyzer NFSv4 fallback when MOUNT fails -- escape checks work on v4-only and image-backed exports
- Upgrade analyzer `check_escape` to use `find_escape_root()` (18 filesystem types instead of 3)
- Add F-2.11 (LOOKUPP export escape) and F-2.12 (cross-export lateral movement) analyzer checks
- Add `exports` shell command: discovers sibling exports via LOOKUPP traversal
- Add `escape --all` mode: gathers seeds from MOUNT v3, MOUNT v1, and NFSv4 LOOKUP
- Add NFSv4 escape path via LOOKUPP (`find_escape_v4`)
- Add `Nfs2EscapeProbe` for v2-only server escape
- Unified escape engine with `EscapeProbe` trait covering 18/19 Linux filesystem types
- Add AUTH_DH (AUTH_DES) cryptographic session implementation (RFC 2695, `auth-dh` feature)
- Add `--auth-dh-netname` / `--auth-dh-pubkey` CLI flags
- Add AUTH_SHORT credential replay with `--short-token` CLI flag
- FUSE mount over NFSv2, v3, and v4 with auto-detection via `NfsFuse<O: ShellOps>`
- Add `ShellOps` FUSE methods: `access`, `setattr`, `statfs`, `commit`, `with_credential`
- Fix unique NFSv4 client names per `V4Ops` instance (NFS4ERR_BAD_SEQID)
- Fix `ShellError` attachment to anyhow chains for correct FUSE errno mapping
- Auto-detect NFS version with TCP NULL verification and v2 direct port
- Deduplicate credential escalation and constants across shell backends
- Fix `escape-root` to use cwd as seed handle

## v1.0.0 (2026-08-08)

**Complete IANA registries, crates.io publication, and NFSv4 recon.**

- Publish all 8 protocol crates and the `nfswolf` binary on [crates.io](https://crates.io/crates/nfswolf)
- Complete IANA RPC program numbers registry (1251 entries)
- Complete IANA RPC auth flavor + status registries (19/19 each)
- Add RPCSEC_GSS v3 auth status codes 15-18 (RFC 7861)
- Add AUTH_TOOWEAK oracle probe (F-1.8)
- Scanner v4 SECINFO probing + auth flavor display
- Comprehensive auth flavor enumeration with SECINFO GSS mechanism decoding
- AUTH_SHORT session credential finding (F-3.9)
- NFSv4 escape via LOOKUPP, pNFS topology, SEC_LABEL, per-path SECINFO, xattrs
- OS fingerprinting via EXCHANGE_ID (op 42, v4.1)
- Handle acquisition matrix: MOUNT v1/v3 cross-version with pad/trim variants
- SECINFO_NO_NAME fallback + WRONGSEC oracle
- Golden vector tests for MOUNT and portmapper wire types
- Fix AUTH_TLS STARTTLS verifier encoding (RFC 9289 S4.1)
- NFSv4.1/v4.2 feature-gated recon operations
- Wire all 37 NFSv4.0 operations with response decoders
- Rename crates from `nfswolf-*` to vendor-neutral names (`onc-xdr`, `onc-rpc-client`, etc.)
- Extract portmapper + rpcbind into `onc-rpcbind` crate
- Extract MOUNT into `nfs-mount` crate
- Add workspace metadata, semver prep, golden vector tests

## v0.8.0 (2026-07-28)

**Unified shell architecture and cross-version parity.**

- Unify `NfsShell` over `ShellOps` trait: v2, v3, and v4 share all 52 commands
- Enrich `ShellOps` types for full shell unification (Stage 1-4)
- Tab completion for all shell versions (v2, v3, v4)
- Add shell aliases: `ll`, `dir`, `type`, `del`, `rename`, `copy`, `id`, `su`, `download`, `upload`
- Remove 35 dead code items, enforce `#[expect]` over `#[allow]`
- Fix v2 shell `cd /` and absolute path resolution
- Cross-version shell consistency audit and fixes
- Fix blocking_lock with try_lock in pool checkin

## v0.7.0 (2026-07-27)

**In-tree protocol stack, domain API, credential ladder, NFSv2 shell.**

- Absorb the NFS protocol stack in-tree: split into 8 workspace crates (`onc-xdr-derive`, `onc-xdr`, `onc-rpc-client`, `onc-rpcbind`, `nfs-mount`, `nfs-v2`, `nfs-v3`, `nfs-v4`)
- Add `RpcTransport` seam and policy-free `DirectTransport` implementation
- Add `PooledTransport`: single `RpcTransport` carrying all connection policy
- NFSv3 domain API: `FileHandle`, `FileAttrs`, `FileType`, `DirEntryPlus`, `FsStat`, `FsInfo`
- `Nfs3Error` with `is_transient()`, `is_permission_denied()`, handle oracle predicates
- Evidence-driven credential ladder: `credential_ladder()` / `credential_ladder_with()` with mode-bit pruning and READDIRPLUS identity ranking
- Full NFSv2 shell via MOUNT v1 MNT with near-feature parity to v3
- Shell credential caching per file handle
- Add `escape` fallback to NFSv2 and BTRFS identity check fix
- `brute-handle` auto-fallback to NFSv2, reports all discovered handles
- F-1.7 mixed auth flavor downgrade detection
- Add MOUNT v1 and rpcbind modules
- 161 RFC-grounded tests across protocol crates
- Add proptest fuzz harness for XDR decoders (22 tests)
- Wire EXPORT enumeration after UDP portmapper discovery
- Probe WebNFS public file handle (F-2.9, MOUNT bypass)
- Patch three P0 correctness bugs found by RFC audit

## v0.6.0 (2026-07-02)

**CI/CD standardization and release tooling.**

- Standardize CI/CD workflows, scaffolding, and release tooling
- Set LICENSE copyright owner

## v0.5.0 (2026-06-29)

**Auto-escape and security hardening.**

- Add `scan --auto-escape` for automatic escape attempt during scanning
- Harden against full security review findings
- Make argument flags consistent across subcommands

## v0.4.0 (2026-06-28)

**Shell improvements and dependency updates.**

- Add `tree` command and escalation-aware `get` to shell
- Optional brute-handle seed from export handle
- Grouped CLI help sections
- Track stable Rust toolchain, set MSRV to 1.95

## v0.3.1 (2026-05-13)

Dependency update and vendor sync.

## v0.3.0 (2026-04-29)

**Shell log readers and scanner rewrite.**

- Add `last`, `lastb`, `lastlog` binary log reader commands to shell
- Rewrite scan module with PROG_MISMATCH probing, SIGINT handling, and UDP support

## v0.2.0 (2026-04-28)

**CLI restructure and performance.**

- Remove `attack` umbrella command; promote `escape`, `brute-handle`, `uid-spray` to top-level subcommands
- Parallelize port probes in scanner
- Handle multi-fragment RPC replies and isolate per-host scan panics
- Detach `mount` into a daemon so the FUSE handler outlives the launcher
- Fix five CLI bugs surfaced by live-server testing

## v0.1.0 (2026-04-17)

**Initial release.**

- Scanner with export enumeration and RPC service discovery
- Analyzer with security finding detection
- Export escape via file handle construction (ext4, XFS, BTRFS)
- Interactive NFSv3 shell with read/write operations
- FUSE mount with auto-UID escalation
- Handle brute-force with STALE/BADHANDLE oracle
- UID/GID spray with ACCESS oracle
- Six report formats: HTML, JSON, TXT, CSV, Markdown, console
- SOCKS proxy support
- Stealth mode with configurable delays
