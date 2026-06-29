# Changelog

All notable changes to nfswolf are documented in this file. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.5.0] - 2026-06-29

### Added

- `scan --auto-escape`: after discovery, automatically attempt an export escape (subtree_check bypass) against every discovered export path and print a ready-to-run `shell --handle` command for each filesystem root reached. Runs only on a complete scan, with bounded concurrency and a per-host timeout; honours `--proxy` and `--delay`/`--jitter`. The escape logic is shared with the `escape` subcommand via a single `find_escape` primitive.
- `analyze --json [FILE]`: optional file argument writes the JSON report to a file (matching `scan --json <FILE>`); with no value it still emits to stdout.
- NFSv4 shell honours `--aux-gids` (the shadow-GID trick now works in `--nfs-version 4` mode, including across mid-session `uid`/`gid`/`hostname` reconnects).

### Changed

- **Breaking** -- `scan`: the "additional ports to probe" flag is renamed `--nfs-port` to `--probe-port`. `--nfs-port` now means the single-value port override consistently across every subcommand, and `scan` folds it into its probe set instead of ignoring it.
- **Breaking** -- `convert`: `--format` is long-only; the `-f` short flag is removed (`-f` is the targets-file flag in `scan`/`analyze`).
- `shell`: removed the local `--uid`/`--gid` that shadowed the global `-u`/`-g`; the session now uses the global identity flags consistently, so `shell -u 0` works like every other subcommand.
- analyzer: dropped the unsound bind-mount (F-2.6) check and the tautological insecure-port (F-7.2) check (both produced false positives on well-configured servers); added a plaintext-transport check (F-3.1, Info); F-1.2 is now emitted when a forged non-root UID is honoured; F-4.1 (`no_root_squash`) and F-7.5 (`all_squash`+`anonuid=0`) are disambiguated; the world-writable/symlink check includes root-owned directories; duplicate F-1.3 findings are deduplicated.
- Circuit breaker: trips only on genuine transient transport outages (never on `NFS3ERR_ACCES`/`PERM`, nor on `FragmentedReply`), records connection-establishment failures so a dead host opens the breaker, and escalates the cooldown once per outage rather than per failure. Every RPC also carries a per-call timeout so a stalled server cannot pin a pool connection.
- NFSv2/NFSv4: NFSv2 raw RPC now uses a fresh AUTH_SYS stamp per call and feeds the circuit breaker; NFSv4 clients honour `StealthConfig`; both bound directory paging and XDR allocations against hostile servers; privileged source ports are used for raw NFSv2 RPC and MOUNT v1.
- FUSE: `read` loops on short reads (no more zero-filled gaps); `readdir` pages a directory to completion with a per-inode cache; `forget` bounds inode-map growth; device major/minor are encoded correctly in `mknod`.
- CLI: `analyze` resolves hostnames and IPv6 targets; `--nfs-port` and `--hostname` are threaded through the offensive subcommands; the connection pool re-stamps the requested credential (aux-gids/hostname) on checkout.

### Fixed

- Addressed roughly one hundred correctness, robustness, and protocol findings from a two-cycle security review: short-read/short-write loops in the shell and NFSv2 read paths, unbounded directory listings and in-memory reads, escape-handle byte-layout and root-confirmation correctness (fsid_type=7 length, XFS-root candidates, identity check against the export's own inode), wildcard/netmask export-ACL detection, and numerous smaller fixes. See the commit history for the full list.

### Security

- `shell get -r` now rejects server-controlled directory-entry names that contain a path separator or `..` before writing locally, preventing a malicious NFS server from escaping the chosen download directory (a zip-slip-class arbitrary local file write -- remote code execution when run under `sudo`).
- Report renderers and the live `analyze` console neutralize untrusted server data: terminal control/escape sequences, Markdown/CSV/HTML injection, and Unicode bidirectional / zero-width "trojan source" characters (CVE-2021-42574 class).
- Bounded every directory-listing and XDR allocation driven by an attacker-supplied length or count (memory-exhaustion DoS), and added per-call/per-host timeouts so an unresponsive server cannot hang the client.
- UDP RPC binds to the target's address family and accepts replies only from the address it sent to (drops spoofed responses).

## [0.4.0] - 2026-06-28

### Added

- `shell`: `tree [depth]` command -- recursively map a directory (default depth 3), always traversing hidden dot-directories (`.ssh`, `.aws`, `.bash_history` are exactly what you want on a security tool).
- `shell`: the prompt now shows `uid=<n> gid=<n>` and tracks mid-session `uid` / `gid` / `impersonate` changes.
- `brute-handle` reports a non-destructive writability hint per hit from advisory ACCESS bits (probed as uid=0 and the object's owner). It never writes to the server -- a handle is not itself read-only/read-write; the export's ro/rw flag and the credential decide.
- `access::WRITE_BITS` / `access::grants_write()` helpers in `proto::nfs3::types`.

### Changed

- `--help` groups the nine subcommands into Recon / Connect / Advanced / Utilities sections; commands are still invoked flat (`nfswolf scan ...`).
- `shell`: `get` now honours the auto-UID escalation ladder like `cat`, so `get /etc/shadow` succeeds where it previously failed with `NFS3ERR_ACCES`; `tree` escalates credentials to descend into root-only hidden directories.
- `brute-handle`: `--seed-handle` is now optional -- a bare `host:/export` target derives the seed handle by mounting the export (MNTPROC_MNT), matching `escape`. `--seed-handle HEX` remains an explicit override and a new `-e/--export` flag mirrors `escape`.
- `brute-handle`: candidate generation now fingerprints the seed (`--fs-type auto`, the default) and tries the same known-root candidates as `escape` (ext4 inode 2 / compound-UUID, XFS 128/64/32, BTRFS subvolumes) before the generic inode sweep. A hit is accepted on `NFS3_OK` *or* `NFS3ERR_ACCES`/`NFS3ERR_PERM`, so brute-handle now finds the same roots `escape` does (a root_squash'd root is a valid handle, no longer discarded).
- Docs: reconciled the finding count (39 findings, F-1.1 through F-7.6), RFC citation format (`§`), write-up severities, and CLI/command references across FINDINGS / ARCHITECTURE / README / CLAUDE; CONTRIBUTING MSRV is now 1.95.

### Removed

- `docs/scanning-module-plan.md` (the completed scan-rewrite plan); the `conn.rs` raw-RPC comments no longer reference the removed NLM/NSM clients.

## [0.3.1] - 2026-05-13

### Changed

- Scanner rewrite: new probe infrastructure using raw RPC record-marking to detect PROG_MISMATCH version ranges (RFC 1831 §13). Probes NFS NULL v2, NULL v3, and COMPOUND v4 over a single TCP connection per host. Reports confirmed protocol versions alongside a portmapper-derived "Hint" column showing the server-advertised version range.
- Scanner: MOUNT EXPORT and DUMP now run against the highest registered mountd version rather than attempting all three separately (mountd v1/v2/v3 serve the same data).
- Scanner: NFSv4 pseudo-root READDIR uses AUTH_SYS uid=0 instead of AUTH_NONE (servers reject anonymous access).
- Scanner: blank table columns are hidden dynamically -- a /24 scan against hosts with no NFSv2 will never show the "v2x" column.
- Scanner: "Mounts" column renamed to "Clients" (reflects that MOUNT DUMP returns connected client entries, not export counts).
- Scanner: "NFS Versions" column renamed to "Hint" and hidden entirely when all hosts already have confirmed version probes (the hint is redundant).
- Scanner: `--transport-udp` removed from global flags; replaced by `--scan-udp` on the `scan` subcommand only. Mutually exclusive with `--proxy` (UDP cannot traverse SOCKS5).
- Scanner: `--json <FILE>` and `--csv <FILE>` write output to files instead of stdout. JSON wrapper includes an `"interrupted"` field.

### Added

- Scanner: SIGINT (Ctrl+C) handling with partial result collection. Workers push results into shared state as they complete; on interrupt the CLI prints all hosts discovered so far, appends an interruption footer, writes partial JSON/CSV if requested, and exits with code 130.
- New `src/engine/scan_types.rs` module with serializable data types (`HostResult`, `NfsPortInfo`, `MountPortInfo`, `V4ExportEntry`, `PortReachability`, `VersionRange`) consumed by all output formats.
- New `src/proto/rpc_probe.rs` module with PROG_MISMATCH-aware RPC probing: `ProbeResult<T>` enum, `probe_nfs_versions_tcp()` for single-connection multi-version detection, `probe_nfs_null_udp()` for UDP fallback.
- `src/proto/mount.rs`: `list_exports_v1()` for MOUNT v1 EXPORT (raw RPC call, program 100005 version 1 procedure 5).

### Removed

- Global `--transport-udp` flag (replaced by per-subcommand `--scan-udp`).
- Global `--json` flag (replaced by per-subcommand `--json <FILE>` on `scan` and bool `--json` on `analyze`).

### Dependencies

- `nfs3_client` vendor updated to upstream HEAD `82e07b1` (Vaiz/nfs3 PRs #159/#161/#162). The only API-breaking change affecting nfswolf is `PortmapperClient::getport` now requiring an explicit transport protocol argument (`IPPROTO_TCP`/`IPPROTO_UDP` per RFC 1057 Appendix A). All four call sites updated. Multi-fragment RPC reassembly and `set_credential` vendor patches unchanged.

## [0.3.0] - 2026-04-29

This release adds three login-history readers to the interactive shell -- `last`, `lastb`, and `lastlog` -- so an operator who has reached an NFS-exported filesystem root (typically via `escape-root`) can decode `/var/log/wtmp`, `/var/log/btmp`, and `/var/log/lastlog` directly over NFS without staging them locally first. Parsing follows the canonical glibc `struct utmpx` (384 bytes) and `struct lastlog` (292 bytes) layouts and was cross-checked against util-linux 2.42 `login-utils/last.c`.

### Added

- Shell: `last [N]` decodes `/var/log/wtmp` and prints paired login sessions with full timestamps and durations. The state machine mirrors util-linux 2.42 `login-utils/last.c::process_wtmp_file()` -- USER_PROCESS pairs with DEAD_PROCESS on `ut_line`, sysvinit pseudo-records (`~`/`reboot`, `~`/`shutdown`, `~`/`runlevel`) are reclassified, and unmatched sessions are closed as `Crash` (next boot) or `Down` (clean shutdown / runlevel 0/6) per the same rules. Always-on full-time format and numeric IPs.
- Shell: `lastb [N]` decodes `/var/log/btmp` and prints failed-login attempts. Same `struct utmpx` parser as `last`.
- Shell: `lastlog` decodes `/var/log/lastlog` (uid-indexed 292-byte slots), maps UIDs to usernames via `/etc/passwd` from the same export, and prints one row per user that has actually logged in. When the classic flat file is empty or absent the command also probes `/var/lib/lastlog/lastlog2.db` (util-linux 2.42 default) and prints a `get` hint -- the SQLite database is left to offline tooling because pure-Rust SQLite would violate the project's no-C-deps rule.
- New module `src/util/utmp.rs`: pure-Rust binary parser for `struct utmpx`, `struct lastlog`, and `/etc/passwd`. Bounds-checked, panic-free, with seven unit tests covering record sizes, BOOT_TIME / USER_PROCESS layouts, partial-trailing-record handling, UID-indexed lastlog slots, and IPv4 address rendering. Spec-cited to util-linux 2.42, glibc `<bits/utmp.h>`, and `<bits/lastlog.h>`. Safe on every architecture supported by the project: the on-disk record sizes are fixed by the Linux ABI regardless of native `time_t` width.
- New shell helper `read_all_escalated()`: returns the full contents of a file handle after running the standard auto-UID escalation ladder. Required by the binary log readers because wtmp/btmp are typically `gid=43` (`utmp`); the helper transparently switches credentials on `NFS3ERR_ACCES`.

### Changed

- Shell `escape-root` now also rebases the session's notion of `/` to the constructed filesystem root. Absolute path lookups (`cat /etc/shadow`, `last`, `cd /`) walk from the underlying filesystem root rather than the narrow export the session originally MOUNTed through. Without this fix the new log readers couldn't reach `/var/log/wtmp` after an escape because the path was still resolved against the original sub-export.
- Crate metadata: expanded `description`, added `filesystem` to `categories`, added `[package.metadata.docs.rs]` with `all-features = true` and `--cfg docsrs` so docs.rs rebuilds are deterministic, and switched the `include` list to absolute (`/`-prefixed) paths to match the convention used by most well-curated Rust crates.
- README: added crates.io and docs.rs badges, and pointed the security-disclosure paragraph at the GitHub private security advisory channel rather than a `SECURITY.md` file.

### Verified against the lab

- `10.252.0.30` (Ubuntu 24.04): 5 boot/shutdown sessions paired correctly; durations match wall-clock (a 4-day 17-hour 45-minute boot pairs with the matching `SHUTDOWN_TIME` record); 16 failed `lastb` entries showing both console (tty1) and `ssh:notty` attempts; `lastlog` correctly reports the file as empty.
- `10.252.0.32` (Ubuntu 24.04): wtmp contains only `LOGIN_PROCESS` getty spawns, which util-linux's own `last` ignores per `last.c` lines 886-893; the new command produces the same "no completed sessions" outcome rather than synthesizing fake rows.

### Deferred

- Live state -- `ps`, `ss` / `netstat`, `who` / `w` -- is not reachable over NFS. The Linux kernel NFS server refuses to traverse onto procfs / sysfs / tmpfs even when `crossmnt` is set, so `/proc/<pid>/*`, `/proc/net/tcp`, and `/var/run/utmp` cannot be exported regardless of client behavior. This is enforced kernel-side and not in scope for any future release.
- `lastlog2` SQLite parsing. Pure-Rust SQLite readers all carry C dependencies (`rusqlite`, `sqlx`) and the project enforces a hard no-C-deps rule for the static-musl build target. Operators reaching a host that has migrated to `lastlog2.db` should `get` the file and read it offline with `sqlite3`.

## [0.2.0] - 2026-04-28

The headline change is a substantial CLI overhaul: the `attack` umbrella verb is gone, primitives that duplicated `shell` / `mount` were removed, and three offensive primitives (`escape`, `brute-handle`, `uid-spray`) have been promoted to top-level subcommands. The `export` subcommand was renamed to `convert`. Every subcommand now runs the full check matrix unconditionally -- the per-check toggles are gone -- and `--help` is grouped into seven sections on every subcommand. The scanner is faster and more resilient against half-open firewalls, and the FUSE driver is now feature-complete.

This is a breaking release. Scripts that called `nfswolf attack ...` or `nfswolf export ...` need updating; see the migration notes inline.

### Added

- New top-level subcommands: `nfswolf escape`, `nfswolf brute-handle`, `nfswolf uid-spray`. Replaces `nfswolf attack escape | brute-handle | uid-spray`.
- New top-level subcommand `nfswolf convert` that renders a JSON dump produced by `nfswolf analyze --json` into HTML / Markdown / CSV / TXT / console. The pipeline is now `analyze --json > results.json` then `convert -i results.json -f html -o report.html`. `convert` is safe to re-run because it does not touch the server.
- Unified positional `<TARGET>` parser shared by every subcommand that touches a single export. Accepts `host`, `host:/export`, or bracketed IPv6 (`[2001:db8::1]:/srv`). `--export` and `--handle` still work as flags; the parser rejects ambiguous combinations with a clear error.
- `--nfs-port` and `--mount-port` are now global flags (previously duplicated on `mount` and `shell`).
- Successful subcommand runs print a `# rerun: nfswolf ...` line on stderr that can be pasted back into the shell to reproduce the run. Suppressed by `--quiet` or `--json`.
- `--help` for every subcommand is now grouped into seven sections: Target / Identity / Permissions / Network / Stealth / Output / Behavior.
- Shell: `get -r` and `put -r` recursive directory transfer with `indicatif` per-directory spinners; `get --verify <sha256>` validates the downloaded file against an expected hash.
- Shell: `hostname <name>` command sets `auth_unix.machinename` mid-session to bypass hostname-restricted export ACLs (F-1.4 / F-3.3 precondition probe).
- Shell: SHA-256 of every downloaded file is printed for evidence chains.
- Shell: `--proxy socks5://host:port` tunnels every NFS connection through a SOCKS5 pivot. Inline CONNECT, no external crate.
- Global `--transport-udp` flag for single-shot UDP RPC probes (portmapper amplification measurement, NSM probes). Wiring into the scanner's portmapper queries is tracked as the next step in `tasklist.md`.
- FUSE: every `Nfs3Client` procedure is now wired through a `Filesystem` callback (lookup, getattr, setattr, access, readlink, mknod, mkdir, symlink, create, unlink, rmdir, rename, link, readdir, read, write, fsync, statfs). Auto-UID escalation runs on every callback and caches the resolved credential per inode.
- NFSv4 shell: `nfswolf shell --nfs-version 4` drops into a minimal NFSv4 shell (ls / cd / pwd / cat / get) using `Nfs4DirectClient` -- works against NFSv4-only servers where MOUNT and the portmapper are filtered.
- Scanner: `nfs4_reachable: bool` field in `HostResult`, set by a direct NFSv4 COMPOUND PUTROOTFH probe to confirm v4 even when portmapper is filtered (F-3.3).

### Changed

- Scanner: per-host TCP probes for ports 111 and 2049 now run concurrently via `tokio::join!`. A half-open firewall on one port no longer serializes the other.
- Scanner: every portmap / mount RPC call inside `scan_host` (`detect_nfs_versions`, `list_exports`, `mount`, `dump_clients`, `detect_nis`) is wrapped in `tokio::time::timeout(probe_timeout, ...)`. A stateful firewall that completes the TCP handshake on 111 but drops RPC payload can no longer stall a worker for the underlying client default.
- Scanner: per-host workers are panic-isolated. A single misbehaving target can no longer sink a multi-thousand-host sweep.
- `nfswolf mount(1)` now detaches into a daemon so the FUSE handler outlives the shell.
- `analyze`: every analysis now runs the full check matrix unconditionally. The only per-run knobs are `--test-read PATH`, `--test-read-uids`, `--test-read-gids`, and `--v4-depth`. `--test-read` defaults to `/etc/shadow` when no paths are supplied.
- `analyze`: dropped per-check toggles (`-A/--check-all`, `--skip-version-check`, `--no-exploit`, `--check-v4`, `--check-no-root-squash`, `--check-insecure-port`, `--check-nohide`, `--check-v2-downgrade`, `--check-portmap-amplification`, `--check-nis`, `--probe-squash`).
- `analyze`: dropped `--output FILE` / `--txt FILE`. The global `--json` flag now makes `analyze` emit a JSON array on stdout -- capture with shell redirection and feed to `nfswolf convert`.
- `scan`: dropped per-check toggles (`--fast`, `--no-rpc-enum`, `--check-portmap-amplification`, `--check-v2-downgrade`, `--check-nis`, `--check-portmap-bypass`). Every scan now runs the full check matrix unconditionally. The only knobs are concurrency, ports, and timeout.
- `mount`: dropped `--auto-uid`, `--allow-root`, `--suid`, `--dev`, `--allow-other`, `--elevate-perms`. The credential ladder, owner-bit elevation, suid/dev passthrough, and shared-mount visibility are always on -- this is a security toolkit, the goal is unobstructed access. `-e` short for `--export` was added.
- `shell`: dropped `--auto-uid`. The credential ladder is always on; the shell falls through to escalated credentials on every `NFS3ERR_ACCES`.
- `--export` consistently has `-e` as its short form on every subcommand that accepts it.

### Removed

- The `attack` parent verb is gone.
- Removed `attack read`, `attack write`, `attack upload`, `attack harvest`, and `attack symlink-swap`. `shell` (`get`, `put`, `get -r`, `put -r`, `cat`, `find`) and `mount` (regular filesystem tools) cover the same primitives with the same credential ladder.
- Removed `attack lock-dos` entirely. Lock-storm DoS was the only NLM-dependent feature; with it gone, the NLM and NSM clients (`src/proto/nlm/`, `src/proto/nsm/`), the F-6.1 NLM lock-attack analyzer check, and the portmapper helpers `detect_nlm` / `detect_nsm` are removed. F-6.2 / F-6.3 (grace-period DoS, SETCLIENTID state destruction) were never implemented and are documented as out of scope.
- Removed `attack v4-grace` (placeholder-only; no working implementation).
- Removed `src/engine/fs_walker.rs` (recursive walker used only by `harvest`) and the `CredentialManager` struct from `src/engine/credential.rs` (used only by removed attack modules). The `escalation_list` helper survives -- it is shared by `shell`, `mount`, and the three offensive subcommands.
- Removed inline `--escape` flag from offensive subcommands. To cross the export boundary, run `nfswolf escape` first and feed the resulting handle into `shell --handle HEX` or `mount --handle HEX`. The escape module is now the single entry point for export breakout.

### Fixed

- FUSE: `--elevate-perms` shift offset (now correctly copies owner bits to other; previously copied group bits, leaving 0700 unchanged). Behavior is now always-on.
- FUSE: `--nfs-port` being silently ignored when `--export` was used (was only honored with `--handle`).
- FUSE: `--proxy` not being passed to the connection pool, so `--handle` mounts now tunnel through SOCKS5.
- FUSE: server-side symlink resolution and the null-attr READDIRPLUS fix-up are always on (NetApp / nested-export workaround).
- Multiple small CLI bugs surfaced by live-server testing.

### Migration

- `nfswolf attack escape ...`        -> `nfswolf escape ...`
- `nfswolf attack brute-handle ...`  -> `nfswolf brute-handle ...`
- `nfswolf attack uid-spray ...`     -> `nfswolf uid-spray ...`
- `nfswolf attack read ...`          -> `nfswolf shell ... -c "cat <path>"` (or `get`)
- `nfswolf attack write ...`         -> `nfswolf shell ... -c "put <path>"` (with `--allow-write`)
- `nfswolf attack upload ...`        -> `nfswolf shell ... -c "put -r <dir>"`
- `nfswolf attack harvest ...`       -> `nfswolf shell ... -c "find /"` then `cat`
- `nfswolf attack symlink-swap ...`  -> `nfswolf shell ... -c "symlink ..."`
- `nfswolf attack lock-dos ...`      -> no replacement; out of scope
- `nfswolf attack v4-grace ...`      -> no replacement; out of scope
- `nfswolf export -i results.json -f html` -> `nfswolf convert -i results.json -f html`
- `nfswolf analyze --output report.html`   -> `nfswolf analyze --json > results.json && nfswolf convert -i results.json -f html -o report.html`

## [0.1.0] - 2026-04-17

First public release. Covers the full NFS attack path: recon -> enumeration -> analysis -> exploitation -> shell. For authorized security research only.

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

- **scan** -- concurrent host and export enumeration across configurable CIDR ranges; detects NFSv2/v3/v4, supported auth flavors, and open portmapper/NLM/NSM services
- **analyze** -- automated security analysis against all 36 findings (F-1.1 through F-7.6); produces a risk-scored report
- **shell** -- interactive NFS shell with 35 commands, tab completion, and readline history; supports `get`/`put` with recursive (`-r`) directory transfer and SHA-256 verification; `hostname` spoofing to bypass hostname-restricted exports
- **mount** -- FUSE filesystem mount with spoofed AUTH_SYS credentials; exposes the remote export as a local directory
- **export** -- renders a prior analysis result in any of six output formats
- **attack** -- nine targeted attack modules:
  - `uid-spray` -- brute-force UID/GID pairs using the ACCESS oracle
  - `escape` -- construct file-handle escape payloads for ext4, XFS, and BTRFS
  - `read` -- read arbitrary files by inode using forged handles
  - `write` -- write files as any UID without `no_root_squash` mitigation
  - `harvest` -- recursive secret pattern matching across an export tree
  - `brute-handle` -- inode-range handle brute-force with STALE/BADHANDLE oracle discrimination
  - `lock-dos` -- NLM4 lock-storm denial-of-service
  - `symlink-swap` -- TOCTOU symlink substitution attack
  - `v4-grace` -- NFSv4 grace-period state disruption

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

[Unreleased]: https://github.com/StrongWind1/NFSWolf/compare/v0.5.0...HEAD
[0.5.0]: https://github.com/StrongWind1/NFSWolf/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/StrongWind1/NFSWolf/compare/v0.3.1...v0.4.0
[0.3.1]: https://github.com/StrongWind1/NFSWolf/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/StrongWind1/NFSWolf/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/StrongWind1/NFSWolf/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/StrongWind1/NFSWolf/releases/tag/v0.1.0
