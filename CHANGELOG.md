# Changelog

All notable changes to nfswolf are documented in this file. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Unified escape engine** -- `EscapeProbe` trait and `find_escape_root()` algorithm in `src/engine/escape.rs`, shared by both the `escape` subcommand and the `escape-root` shell command. Supports 18 of 19 Linux filesystem types (ext2/3/4, XFS, BTRFS, ZFS, f2fs, JFS, NILFS2, ReiserFS, VFAT, NTFS3, UDF, bcachefs, SquashFS, EROFS, ISO9660; only tmpfs resists). INO32_GEN candidate table with 9 labeled entries, plus filesystem-specific constructors for ZFS, EROFS, NILFS2, bcachefs, UDF, ISO9660.
- **`escape --all` mode** -- acquires seed handles from MOUNT v3, MOUNT v1, and NFSv4 LOOKUP, runs the full escape against each, and reports every working root handle instead of stopping at the first.
- **NFSv4 handle escape path** (`find_escape_v4`) -- pure-NFSv4 escape when MOUNT is firewalled. Connects via PooledTransport, navigates to the export with component-by-component LOOKUP, and constructs root handles from the v4-acquired seed.
- **`exports` shell command** -- discovers sibling exports via LOOKUPP traversal of the NFSv4 pseudo-root (F-2.12 cross-export lateral access).
- **NFSv4 crate completion** -- all 8 phases of the NFSv4 completion plan implemented: all 37 ops fully typed with response decoders, 66 named status codes, stateful infrastructure (SETCLIENTID lifecycle, OPEN/CLOSE/LOCK state, crash recovery), domain types (`Nfs4FileInfo`, `Nfs4DirEntry`, `Nfs4FileType`), and a shell-ready `Nfs4Client` with 47 public methods (244 crate tests).
- **NFSv4 shell integration** -- `V4Ops: ShellOps` in `src/shell/v4.rs` integrates all 52 shell commands over NFSv4 with credential escalation via `try_with_escalation()`. NFSv2, v3, and v4 now share the full unified shell.
- **Auto-version detection** -- probes v3 -> v2 -> v4 when `--nfs-version` is omitted, using portmapper GETPORT + TCP NULL verification for v2/v3 and direct COMPOUND for v4.
- **F-2.11: NFSv4 LOOKUPP export escape** -- critical severity. LOOKUPP from a subdirectory export reaches the filesystem root, bypassing export boundaries without MOUNT.
- **F-2.12: NFSv4 LOOKUPP cross-export lateral access** -- high severity. LOOKUPP traversal through the pseudo-root reaches sibling exports.
- **F-5.10: pNFS flex-file layout security downgrade** -- medium severity. pNFS data servers may bypass NFSv4 security enforcement.
- **Filesystem escape research matrix** -- `docs/research/FILESYSTEM_ESCAPE_MATRIX.md`, 335-line analysis of 23 Linux filesystem types with kernel source references, handle formats, root inodes, and generation check behavior.
- **Linux kernel NFS breakdown** -- `ref/linux-kernel/BREAKDOWN.md`, 3200-line function-level walkthrough of Linux 7.1.8 knfsd mapping every security-relevant kernel code path to nfswolf findings.
- **NFSv4 escape via LOOKUPP** -- pseudo-filesystem traversal to the real filesystem root, bypassing export boundaries without MOUNT.
- **Handle acquisition matrix** -- MOUNT v1/v3 cross-version handle probing with pad/trim variants and per-variant GETATTR validation against both NFSv3 and NFSv2.
- **SECINFO_NO_NAME fallback** (op 52, RFC 5661) -- probes auth requirements on the pseudo-root when per-name SECINFO fails; WRONGSEC oracle detects per-path Kerberos enforcement.
- **OS fingerprinting** -- EXCHANGE_ID (op 42, RFC 5661) vendor/version strings decoded in the analyzer for server identification.
- **pNFS topology** -- GETDEVICEINFO/GETDEVICELIST enumerate pNFS data-server layout devices.
- **Per-path SECINFO probing** and xattr detection via FATTR4_SEC_LABEL (RFC 7862).
- **Golden vector tests** for MOUNT and portmapper wire types (round-trip encoding validation).
- **Protocol crates on crates.io** -- all 8 protocol crates published as standalone libraries.

### Changed

- **Credential escalation deduplication** -- 9 copy-pasted 25-line escalation loops across v2/v3/v4 shell backends replaced by shared `CredCache` and `try_with_escalation()` in `shell/ops.rs`. Credential results are cached per-handle.
- **Version-agnostic shell dispatch** -- `ShellSetup`, `run_repl`, `connect_v2`/`connect_v3`/`connect_v4` replace 3 copy-pasted REPL setup blocks. `ShellArgs.nfs_version` changed from `u32` to `Option<u32>`.
- **`escape-root` uses cwd as seed** -- previously used `self.export_root` (pseudo-root on v4), now uses `self.cwd` so escape works from any directory.
- All 8 protocol crates bumped to v1.0.0.
- Standardized crate READMEs: centered headers, badges (CI, crates.io, edition, MSRV, license, docs.rs), nav links, API reference tables, ASCII dependency graph, protocol/codec coverage, safety sections.
- Removed `publish = false` from all crates; added `documentation` field (docs.rs).
- Fixed `readme` path: workspace-inherited readme resolved outside the package; now crate-local.
- Fixed provenance text for nfs-v2 and nfs-v4 READMEs (incorrectly said "Derived from Vaiz/nfs3"; NOTICE files say "Original NFSWolf work").
- Top-level README: added crates.io and docs.rs badges, `cargo install nfswolf` option, protocol crates table, WEPWolf in related tools.
- Scanner stores handles from MOUNT for cross-version testing; MOUNT v1 MNT runs per export.

### Fixed

- **Analyzer ext4 escape false negative** -- XFS-first candidate ordering caused ext4 exports to be misclassified; fixed candidate ordering.
- **IPv6 privileged-port binding** -- `onc-rpc-client` now binds to IPv6 addresses correctly when `--privileged-port` is used.
- **nfsstat3 Unknown(u32) catch-all** -- unknown NFS status codes no longer cause deserialization failures.
- **NFSv4 LOOKUPP pseudo-FS vs real-FS root** -- correctly distinguishes pseudo-root from filesystem root in LOOKUPP output.
- **clippy format_collect and needless_update** -- resolved CI-breaking clippy lints.
- **Non-ASCII em-dashes in source** -- replaced with ASCII `--` to pass the hygiene gate.

## [1.0.0] - 2026-08-03

### Added

- **Comprehensive auth flavor enumeration** -- the analyzer and scanner now discover and report all authentication types available on every export.
  - SECINFO GSS mechanism decoding: `rpcsec_gss_info` (OID, QOP, service level) is now parsed from NFSv4 SECINFO responses, distinguishing krb5/krb5i/krb5p directly from SECINFO instead of relying on MOUNT pseudo-flavors.
  - Scanner v4 SECINFO probing: NFSv4 pseudo-root entries now show auth flavors via per-entry SECINFO queries.
  - Scanner v3 MNT auth probing: every v3 export is probed via MNT to discover `auth_flavors` (RFC 1813 Appendix III), displayed in console and JSON output.
  - `AUTH_TOOWEAK` oracle (F-1.8): detects Kerberos enforcement at the NFS operation level when MOUNT accepts AUTH_SYS but GETATTR returns `AUTH_TOOWEAK` (RFC 5531 S8.3).
  - `AUTH_SHORT` session credential finding (F-3.9): warns when AUTH_SHORT (flavor 2) is advertised, since opaque session tokens are replayable from wire captures (RFC 1057 S9.2).
  - Unified `flavor_name()` function: single source of truth for flavor-to-name mapping across analyzer and scanner, covering all 19 IANA-assigned flavors.
  - `SecInfoEntry` struct in `nfs-v4` crate: carries GSS mechanism OID, QOP, and service level alongside the raw flavor number.
- **New analyzer checks** -- 6 new security findings using existing protocol crate infrastructure:
  - F-3.7: AUTH_DH advertised (cryptographically broken, RFC 5531 S14) -- detected in both MOUNT auth_flavors and NFSv4 SECINFO.
  - F-3.8: RPC-with-TLS supported (RFC 9289) -- AUTH_TLS NULL probe with STARTTLS verifier.
  - F-3.9: AUTH_SHORT session credentials advertised -- replayable without knowing original UID/GID.
  - F-4.6: Unrestricted chown via PATHCONF `chown_restricted=false` -- ownership hijacking risk.
  - F-5.7: Case-insensitive filesystem via PATHCONF `case_insensitive=true` -- Windows NFS / NTFS fingerprint.
  - F-5.8: Export root attributes leaked via AUTH_NONE GETATTR (RFC 2623 S2.3.2 automounter support).
  - F-1.8: NFS operations reject AUTH_SYS (Kerberos enforced at NFS layer via AUTH_TOOWEAK).
- **Complete IANA registries** -- all three RPC registries now have full coverage:
  - RPC program numbers: 1251 entries from the IANA CSV, replacing the previous 13-entry hand-curated table. Every assigned program in a portmapper DUMP is now decoded by name.
  - Auth flavor numbers: all 19 assigned values (AUTH_NONE through AUTH_TLS, plus legacy AUTH_KERB/AUTH_RSA/AUTH_NW/AUTH_SEC/AUTH_ESV/AUTH_NQNFS/AUTH_GSSAPI/AUTH_ILU_UGEN and pseudo-flavors AUTH_SPNEGO/krb5/krb5i/krb5p).
  - Auth status numbers: all 19 values (AUTH_OK through RPCSEC_GSS_UNKNOWN_MESSAGE, RFC 7861).
- **Scanner security notes** for sideband RPC programs -- NLM, NSM, RQUOTA, NFS_ACL, NIS (ypserv/ypbind), PCNFSD, rstatd, rusersd, yppasswdd, rexec, ypupdate, keyserv, ypxfrd, ttdbserverd, sadmind annotated with attack surface descriptions in console and JSON output.
- `AuthFlavor::Tls` variant and `RPCSEC_GSS = 6` in the `auth_flavor` wire enum (`onc-rpc-client`).
- `auth_flavors` field on `ExportEntry` and `V4ExportEntry` for scanner output.
- **Eight-crate workspace rename** -- all protocol crates renamed from `nfswolf-*` to vendor-neutral names: `nfswolf-xdr-derive` to `onc-xdr-derive`, `nfswolf-xdr` to `onc-xdr`, `nfswolf-rpc` to `onc-rpc-client`, `nfswolf-rpcbind` to `onc-rpcbind`, `nfswolf-mount` to `nfs-mount`, `nfswolf-nfs2` to `nfs-v2`, `nfswolf-nfs3` to `nfs-v3`, `nfswolf-nfs4` to `nfs-v4`. Portmapper and rpcbind extracted from `onc-rpc-client` into their own `onc-rpcbind` crate; MOUNT extracted into `nfs-mount`.

### Changed

- **NFSv2 on PooledTransport** -- all v2 code paths (shell, escape, brute-handle) now use the same `PooledTransport` infrastructure as v3, providing connection pooling, circuit breaker, stealth pacing, and SOCKS5 proxy support. Previously v2 used raw `DirectTransport` with no policy.
- **NFSv4 wire coverage** -- all 37 NFSv4.0 operations (ops 3-39) plus ILLEGAL (10044) are now representable as `ArgOp` variants. `CompoundBuilder` has typed methods for 13+ operations including SETCLIENTID, OPEN, EXCHANGE_ID, SECINFO_NO_NAME, GETDEVICEINFO, GETDEVICELIST. NFSv4.1 operations (EXCHANGE_ID op 42, SECINFO_NO_NAME op 52, GETDEVICEINFO op 47, GETDEVICELIST op 48) and NFSv4.2 security labels (FATTR4_SEC_LABEL, SecLabel4, RFC 7862) are supported.
- `parse_flavor()` in mount.rs now delegates to `AuthFlavor::from_u32()`, fixing a bug where krb5 pseudo-flavors (390003-390005) mapped to `Unknown` instead of `Gss`.
- `NfsMountClient::unmount()` is no longer gated behind `#[cfg(feature = "fuse")]` -- it is a basic MOUNT protocol operation used by the scanner for stealth cleanup.
- `auth_stat` enum extended from 8 to 19 variants (all IANA-assigned values).
- `AuthFlavor::from_u32()` classifies AUTH_SPNEGO (390000) as `Gss` and AUTH_TLS (7) as `Tls`.
- Removed stale dead-code suppression comment from main.rs.
- Updated CRATE-DESIGN.md: proxy bypass table, NFSv2 parity table, phase completion status, error taxonomy all reflect current state.
- Updated all markdown documentation: finding counts (47), test counts (543), shell command counts (52), crate README compilation fixes, NFSv4.md operation coverage.

### Fixed

- Three inline flavor-to-name match blocks (analyzer, scanner, mount) replaced by single `flavor_name()` function, eliminating naming inconsistencies ("RPCSEC_GSS(krb5)" vs "krb5" vs `Unknown`).

## [0.8.0] - 2026-07-28

### Added

- **Shell aliases** -- `download`/`upload` for `get`/`put`, `ll` for `ls -a` (full columns), `dir` for `ls`, `type` for `cat`, `del` for `rm`, `rename` for `mv`, `copy` for `cp`, `id` for `whoami`, `su` for `impersonate`. All aliases work across v2, v3, and v4 shells with tab completion.
- **NFSv4 local commands** -- `handle` (print current FH as hex), `lcd`, `lls`, `lpwd`, `lmkdir`, `history` now work in the v4 shell. Previously these were v2/v3-only.
- **NFSv2 identity change** -- `uid`, `gid`, `hostname`, and `impersonate` now work in the v2 shell by tearing down the TCP session and reconnecting with new AUTH_SYS credentials. Previously v2 identity was fixed at connect time.
- **NFSv2 default export** -- `nfswolf shell host --nfs-version 2` now defaults to mounting `/` when no export is specified, matching v3 behavior.
- **NFSv2 escape guards** -- the v2 escape path now checks `export_is_fs_root` (prevents false positives when the export already is the filesystem root) and includes the BTRFS subvolume sweep (previously v3-only).
- **Nfs2Error classification predicates** -- `is_permission_denied()`, `is_stale()`, `is_not_found()`, matching NFSv3's `Nfs3Fault` API.
- **Display impls** -- `NfsStat` (v2, RFC 1094 names) and `Nfs4Status` (v4, RFC 7530 names) now implement `Display`.
- `Nfs2Client::into_transport()` -- consuming accessor matching `Nfs3Client`.
- NFSv2 RPC call failures are now logged at `tracing::debug!` level, matching v3.
- `uid-spray --help` now documents the NFSv3 requirement (uses the ACCESS procedure).

### Fixed

- **Analyzer proxy bypass** -- per-export `Nfs3Client` instances now inherit `--proxy`, `--hostname`, and `--aux-gids` from the top-level configuration. Previously the per-export clients silently bypassed the SOCKS5 proxy and hardcoded `"nfswolf"` as the AUTH_SYS machinename.
- **Analyzer shared pool** -- a single connection pool is shared across all exports instead of creating a fresh pool per export.
- **Analyzer pagination** -- `check_nohide` and `check_symlink_preconditions` now iterate all READDIRPLUS pages instead of checking only the first page.
- **`cat` vs `get` credential gap** -- `read_chunk()` (used by `get`/`download`) now performs full credential escalation matching `read_file()` (used by `cat`). Previously `cat /etc/shadow` could succeed via auto-escalation while `get /etc/shadow` failed with `NFS3ERR_ACCES`.
- **NFSv4 `cat` binary corruption** -- replaced `String::from_utf8_lossy` with raw `stdout.write_all()`, matching v2/v3 behavior.
- **NFSv2 fattr data loss** -- `rdev`, `fsid`, and `used` (disk usage) are now mapped from the NFSv2 wire data instead of hardcoded to zero. `stat` on device nodes shows correct major/minor numbers.
- **Pool `blocking_lock` panic** -- `checkin()` now uses `try_lock()` instead of `blocking_lock()`, which panicked when called from within the tokio runtime (e.g. when an async task drops a `PooledConnection`). The shared-pool analyzer change exposed this latent issue.
- **Scan interrupted message** -- no longer double-counts NFS hosts as both "completed" and "with NFS".
- **Brute-handle inode truncation** -- warns when `--inode-start`/`--inode-end` exceeds u32 range instead of silently clamping.
- NFSv2 shell now warns when `--proxy`, `--delay`, or `--jitter` are ignored.
- NFSv4 tab completion no longer advertises write commands (`put`, `mkdir`, `rm`, etc.) that always fail.
- NFSv4 prompt now shows `gid` (matching v2 pattern).
- Replay hints (`# rerun: ...`) added to v3 and v4 shell connect paths (v2 already had one).

### Changed

- **Walker consolidation** -- four near-identical recursive walkers (`suid_scan_recursive`, `world_writable_recursive`, `secrets_recursive`, `find_recursive`) replaced by a single generic `walk_recursive()` with filter closures.
- **rwx dedup** -- extracted `format_rwx()` in `ops.rs`; both `mode_string()` and `format_mode()` call it instead of duplicating the bit-manipulation logic.
- `uid-spray` now shares a single connection pool between the sprayer and `lookup_path` instead of creating two independent pools.

### Removed

- Dead struct `RpcbindTime` (defined but never used; `gettime()` returns `u32` directly).
- Duplicate `Opaque::from_vec()` constructor (identical to `Opaque::owned()`).

## [0.7.0] - 2026-07-27

### Changed

- **Breaking (internal)** -- the NFS wire protocol is now owned in-tree, and the repository is a Cargo workspace of six library crates plus the binary. The `nfs3_client` and `nfs3_types` dependencies are gone, as is the `vendor/nfs3_client/` patch tree and the `[patch.crates-io]` block that pointed at it. `nfs3_server` remains a dev-dependency for the mock server used in integration tests. The absorbed code comes from [Vaiz/nfs3](https://github.com/Vaiz/nfs3), released into the public domain under the Unlicense; `NOTICE` records the file-level mapping.
- The stack is layered strictly, with no edges between the three version crates: `nfswolf-xdr-derive` (the `#[derive(XdrCodec)]` proc macro) and `nfswolf-xdr` (RFC 4506 codec) sit at the bottom, `nfswolf-rpc` (ONC RPC v2, portmapper, AUTH_SYS) above them, and `nfswolf-nfs2` (RFC 1094, 18 procedures), `nfswolf-nfs3` (RFC 1813, 22 procedures plus MOUNT v3) and `nfswolf-nfs4` (RFC 7530 COMPOUND) in parallel on top. Each version crate carries its own MOUNT protocol, because MOUNT v1 and v3 are defined in different RFCs and their handle types genuinely differ. All six are standalone libraries that cover more of their RFCs than the binary uses.
- The `RpcTransport` trait is the single seam between protocol and policy. Everything above it speaks in procedures and domain types; everything below it speaks in sockets, retries and timeouts. The libraries ship a policy-free `DirectTransport`; the binary supplies `PooledTransport`, which holds connection reuse, the circuit breaker, stealth pacing and deadlines in one place instead of a policy block repeated once per procedure.
- `nfswolf-nfs3` gained a domain API: methods take and return `FileHandle`, `FileAttrs` and friends rather than raw XDR, and report failures as `Nfs3Fault`, which separates "no answer from the server" from "the server answered and refused". Consumers no longer hand-build wire args or match `Nfs3Result`, which removed roughly 670 wire-type references and 190 result-match arms from `src/`.
- The four upstream workarounds this removes: the vendor patch that made `RpcClient`'s credential public for mid-session UID spraying, the `RawIoRef` borrow adapter that existed because `RpcClient` would not release its IO stream, the hand-rolled RPC prober that recovered `PROG_MISMATCH` version ranges upstream discarded, and the per-call timeout wrapper compensating for a receive path with no deadline. Credential swapping and version-range preservation are now simply how the code is written.
- The credential ladder is evidence-driven. It reads the mode bits the server already reported and the ownership carried by every `READDIRPLUS` reply, both of which arrive free with calls already made. When a target grants no "other" access, POSIX gives an identity that is neither the owner nor in the owning group no path to the file, so the service-account rungs are provably wasted RPC and are skipped; identities actually observed owning files on the export outrank guesses. Root keeps its rung regardless, because `no_root_squash` bypasses the check outright.
- The smol runtime backend that upstream offered was dropped during absorption; nfswolf is tokio-only.
- `make lint`, `check`, `test`, `test-matrix` and `doc` now pass `--workspace`, so the protocol crates are covered by the gate rather than silently skipped.

### Fixed

- `Opaque::unpack` sized its allocation directly from an attacker-chosen 4-byte length, so a single malformed reply could ask for up to 4 GiB before the read failed. This decoder handles every filename, symlink target, file handle and `READ` payload. It now allocates incrementally through the hardened reader (CWE-789). `RpcClient`'s reply buffer had the same shape, bounded only by the fragment header's 2 GiB mask, and is now capped at 8 MiB.
- The pooled MOUNT path dropped the AUTH_SYS credential and mounted as `AUTH_NONE`, which a `sec=sys` mountd refuses outright and which silently omitted `--hostname` from the server's logs. `NfsMountClient` now carries the credential through.
- A MOUNT authorization denial tripped the circuit breaker. Since the breaker is keyed on address, ten refusals on one unauthorised export would have written off every other export on that host. An authorization decision is not an outage and no longer counts as one.
- `RpcError::UnexpectedXid` was treated as a reusable connection error, but it means the reply stream is off by one; returning that connection to the pool wedged the slot permanently.
- `AuthSys::with_groups` dropped the primary GID, unlike `AuthSys::new`. Servers resolve group access from the supplied list, so callers passing an empty auxiliary set built credentials with no groups at all. Fixing it also removed two hand-rolled workarounds that had been compensating for it.
- `NfsConnection::health_check` had been weakened to an RPC `NULL` probe, which servers answer before any export check and which therefore stayed healthy across an `exportfs` reload. It is a `GETATTR` on the root handle again, with `NULL` only as a fallback.
- `uid-spray` was unusable at its defaults: the GID range defaulted to the full 0-65535 space, so a 61-UID sweep expanded to about 4 million probes and a bare invocation to 4.3 billion. GID now follows UID by default, with `--gid-start`/`--gid-end` to opt into the cross product and a `--max-attempts` ceiling.
- `--nfs-version 2` fell through to the v3 path and returned v3 results, which would read as evidence a server accepts v2. It is now refused explicitly; version detection in `scan` and `analyze` is unaffected.
- `AsyncRead::async_read_exact` looped forever when the peer closed the connection mid-message, because a `read` returning `Ok(0)` left the remaining-bytes slice unchanged. It now returns `UnexpectedEof`. `async_write_all` gained the matching `WriteZero` guard.
- `RpcClient::send_call` panicked rather than erroring on a message too large for a single RPC fragment: `u32::try_from` on the length would panic above 4 GiB, and `fragment_header::new` asserted above 2 GiB. Both now return `RpcError::WrongLength`.

### Removed

- Dead code that the workspace-wide `unused = "allow"` had been hiding: the unreferenced privilege helper, the pooled NFSv4 client (only the direct client was ever used), `ReconnectStrategy::ResetPerCall`, `PoolStats`, and the `AutoUidResolver`, whose nine steps turned out to be one never implemented, one already shipping as the `uid-spray` subcommand, one genuinely novel idea now folded into the credential ladder, and five duplicating the ladder outright.

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

- Multiple Ubuntu 24.04 targets: 5 boot/shutdown sessions paired correctly; durations match wall-clock (a 4-day 17-hour 45-minute boot pairs with the matching `SHUTDOWN_TIME` record); 16 failed `lastb` entries showing both console (tty1) and `ssh:notty` attempts; `lastlog` correctly reports the file as empty.
- Target with getty-only wtmp: wtmp contains only `LOGIN_PROCESS` getty spawns, which util-linux's own `last` ignores per `last.c` lines 886-893; the new command produces the same "no completed sessions" outcome rather than synthesizing fake rows.

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

[Unreleased]: https://github.com/StrongWind1/NFSWolf/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/StrongWind1/NFSWolf/compare/v0.8.0...v1.0.0
[0.8.0]: https://github.com/StrongWind1/NFSWolf/compare/v0.7.0...v0.8.0
[0.7.0]: https://github.com/StrongWind1/NFSWolf/compare/v0.5.0...v0.7.0
[0.5.0]: https://github.com/StrongWind1/NFSWolf/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/StrongWind1/NFSWolf/compare/v0.3.1...v0.4.0
[0.3.1]: https://github.com/StrongWind1/NFSWolf/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/StrongWind1/NFSWolf/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/StrongWind1/NFSWolf/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/StrongWind1/NFSWolf/releases/tag/v0.1.0
