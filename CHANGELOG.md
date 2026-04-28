# Changelog

All notable changes to nfswolf are documented in this file. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### CLI cleanup

- `--help` is now grouped into seven sections (Target / Identity / Permissions / Network / Stealth / Output / Behavior) on every subcommand, replacing the flat alphabetical list.
- Unified positional `<TARGET>` accepts `host`, `host:/export`, or bracketed IPv6 (`[2001:db8::1]:/srv`) on every subcommand that touches a single export. `--export` and `--handle` still work as flags; the parser rejects ambiguous combinations with a clear error.
- `--export` now consistently has `-e` as its short form on every subcommand (`scan`, `mount`, `shell`, `attack read|write|upload|harvest|uid-spray|symlink-swap|lock-dos`).
- `--nfs-port` and `--mount-port` are now global flags (apply to every subcommand). They were previously duplicated on `mount` and `shell`.
- Successful subcommand runs print a `# rerun: nfswolf …` line on stderr that can be pasted back into the shell. Suppressed by `--quiet` or `--json`.
- `scan`: dropped `--fast`, `--no-rpc-enum`, `--check-portmap-amplification`, `--check-v2-downgrade`, `--check-nis`, `--check-portmap-bypass`. Every scan now runs the full check matrix unconditionally. The only knobs are concurrency, ports, and timeout.
- `analyze`: dropped `-A/--check-all`, `--skip-version-check`, `--no-exploit`, `--check-v4`, `--check-no-root-squash`, `--check-insecure-port`, `--check-nohide`, `--check-v2-downgrade`, `--check-portmap-amplification`, `--check-nis`, `--probe-squash`. Every analysis now runs the full check matrix unconditionally; the only per-run knobs are `--test-read PATH`, `--test-read-uids`, `--test-read-gids`, and `--v4-depth`. `--test-read` defaults to `/etc/shadow` when no paths are supplied.
- `mount`: dropped `--auto-uid`, `--allow-root`, `--suid`, `--dev`, `--allow-other`, `--elevate-perms`. The credential ladder, owner-bit elevation, suid/dev passthrough, and shared-mount visibility are always on -- this is a security toolkit, the goal is unobstructed access. `-e` short for `--export` was added.
- `shell`: dropped `--auto-uid`. The credential ladder is always on (it never had a real off-state, since the shell falls through to escalated credentials whenever the server returns NFS3ERR_ACCES).
- `attack`: dropped `--escape` from every sub-module. To reach files outside the export boundary, run `attack escape` first to obtain a root handle, then pass the resulting hex string back via `--handle HEX`. The escape module is the single entry point for export-escape; it no longer gets duplicated as an inline flag.
- FUSE: fixed `--elevate-perms` shift offset (now correctly copies owner bits to other; previously copied group bits, leaving 0700 unchanged) -- behavior is now always-on.
- FUSE: fixed `--nfs-port` being silently ignored when `--export` was used (it was only honored with `--handle`).
- FUSE: fixed `--proxy` not being passed to the connection pool, so `--handle` mounts now tunnel through SOCKS5.
- FUSE: every `Nfs3Client` procedure is now wired through a `Filesystem` callback (lookup, getattr, setattr, access, readlink, mknod, mkdir, symlink, create, unlink, rmdir, rename, link, readdir, read, write, fsync, statfs); auto-UID escalation runs on every callback and caches the resolved credential per inode.
- FUSE: server-side symlink resolution and the null-attr READDIRPLUS fix-up are always on.
- Renamed `export` subcommand to `convert` and clarified the pipeline relationship: `analyze` produces the JSON, `convert` renders it. `analyze` lost its per-subcommand `--output FILE` and `--txt FILE` flags; instead, the global `--json` flag now causes `analyze` to emit a JSON array on stdout. Capture with shell redirection (`> results.json`) and feed to `nfswolf convert` to render HTML/Markdown/CSV/TXT/console. Re-running `analyze` to regenerate a different format would re-execute every check (including the squash/no-root-squash probes that touch the server); `convert` is the safe, offline path for re-rendering.

## [0.1.0] - 2026-04-17

First public release. Covers the full NFS attack path: recon → enumeration → analysis → exploitation → shell. For authorized security research only.

### Protocol support

- NFSv2, NFSv3, and NFSv4.0 over TCP with full XDR encoding
- AUTH_SYS credential injection with per-call stamp rotation to avoid duplicate-request-cache hits
- MOUNT, portmapper (DUMP / GETPORT), NLM4 lock procedures, and NSM stat/monitor
- NFSv4 COMPOUND operations: PUTROOTFH, GETFH, LOOKUP, GETATTR, READDIR, READ, SECINFO
- UDP transport for single-shot RPC probes (portmapper amplification measurement)
- SOCKS5 proxy support for all TCP connections
- Connection pool with per-(host, export, uid, gid) bucketing, LIFO reuse, and health eviction
- Circuit breaker with sliding-window failure tracking and exponential-backoff cooldown; permission denials do not trip the breaker during UID spraying

### Subcommands

- **scan** — concurrent host and export enumeration across configurable CIDR ranges; detects NFSv2/v3/v4, supported auth flavors, and open portmapper/NLM/NSM services
- **analyze** — automated security analysis against all 36 findings (F-1.1 through F-7.6); produces a risk-scored report
- **shell** — interactive NFS shell with 35 commands, tab completion, and readline history; supports `get`/`put` with recursive (`-r`) directory transfer and SHA-256 verification; `hostname` spoofing to bypass hostname-restricted exports
- **mount** — FUSE filesystem mount with spoofed AUTH_SYS credentials; exposes the remote export as a local directory
- **export** — renders a prior analysis result in any of six output formats
- **attack** — nine targeted attack modules:
  - `uid-spray` — brute-force UID/GID pairs using the ACCESS oracle
  - `escape` — construct file-handle escape payloads for ext4, XFS, and BTRFS
  - `read` — read arbitrary files by inode using forged handles
  - `write` — write files as any UID without `no_root_squash` mitigation
  - `harvest` — recursive secret pattern matching across an export tree
  - `brute-handle` — inode-range handle brute-force with STALE/BADHANDLE oracle discrimination
  - `lock-dos` — NLM4 lock-storm denial-of-service
  - `symlink-swap` — TOCTOU symlink substitution attack
  - `v4-grace` — NFSv4 grace-period state disruption

### Security analysis

- 36 findings across seven categories: credential spoofing (F-1.x), export escape (F-2.x), network (F-3.x), privilege escalation (F-4.x), enumeration (F-5.x), locking (F-6.x), and policy misconfiguration (F-7.x)
- Every finding references the authoritative RFC section and includes severity, detection method, and a detailed write-up
- Auto-UID resolution: nine-step strategy that tries NFSv2 (no root_squash negotiation), NFSv3 ACCESS oracle, and UID 0/65534/1000 before falling back to spray

### File handle engine

- OS and filesystem fingerprinting from handle structure (Linux ext4, XFS, BTRFS, Windows, FreeBSD)
- Escape handle construction targeting inode 2 (ext4 root), XFS inode 128, and BTRFS subvolume UUID layouts
- BTRFS compound-UUID escape with subvolume enumeration
- Windows handle signing detection (HMAC presence / absence)
- Shannon entropy analysis for handle classification

### Output and reporting

- Six report formats: ANSI-colored console, HTML (self-contained), JSON, CSV, Markdown, plain text
- Risk scoring: weighted sum across finding severities
- `--output` flag on `export` selects format; all formats accept the same `AnalysisResult` input

### Releases

- Pre-built binaries for Linux x86\_64 (musl static, glibc+FUSE), Linux arm64 (musl static, glibc+FUSE), Windows x86\_64 (MSVC, GNU), Windows arm64 (MSVC), macOS arm64, macOS x86\_64, and macOS universal
- `SHA256SUMS` file with cosign keyless signature (`SHA256SUMS.sig`) for every release
- SLSA build provenance attestations for every binary via `actions/attest-build-provenance`

[Unreleased]: https://github.com/StrongWind1/NFSWolf/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/StrongWind1/NFSWolf/releases/tag/v0.1.0
