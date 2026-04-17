# Changelog

All notable changes to nfswolf are documented in this file. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
