# v1.0 Release Tasklist

What must change before stamping 1.0.0. Every gap below was verified against the current codebase (v0.8.0) — items that CRATE-DESIGN.md or FUTURE-RESEARCH.md listed as open but that already shipped in v0.7.0/v0.8.0 are excluded.

## Already done (verified, no action needed)

These items appear as open in CRATE-DESIGN.md but are already implemented. Listed here to prevent re-work.

| Item | Evidence |
|------|----------|
| NFSv2 on PooledTransport (pool, circuit breaker, stealth, proxy) | All v2 paths use `make_v2_client_with_hostname` → `make_pooled_transport` (`src/cli/probe.rs:93-136`) |
| NFSv2 SOCKS5 proxy bypass (escape, brute-handle, shell) | `escape.rs:235,581`, `brute_handle.rs:372`, `shell.rs:691` all pass `globals.proxy.as_deref()` |
| WebNFS analyzer proxy bypass (`_proxy` unused) | Fixed: `analyzer.rs:867` takes `proxy: Option<&str>`, passes to `connect_tcp` at line 878 |
| `NfsStat` → `Nfs2Stat` rename | `crates/nfs-v2/src/wire.rs:80` defines `pub enum Nfs2Stat` |
| `MountError::Denied` → `Status` | `crates/nfs-mount/src/error.rs:24` has `Status(mountstat3)`, with `#[non_exhaustive]` |
| `Nfs4Status` classification methods | `crates/nfs-v4/src/wire.rs:1687-1703`: `is_permission_denied`, `is_stale`, `is_not_found` |
| `fuse.rs` duplicate `is_permission_refusal` | Removed; fuse.rs uses `Nfs3Error::is_permission_denied` directly (line 471, 496) |
| `rpc_probe.rs` (266 lines of stale RPC parsing) | Deleted entirely |
| `udp.rs` absorbed into `onc-rpc-client` | `src/proto/udp.rs` is a 7-line re-export shim |
| `#[non_exhaustive]` on public enums | 48 annotations across all crates |
| `thiserror` removed from `nfs-v3` | Not in `crates/nfs-v3/Cargo.toml` |
| `onc-xdr-derive` tests | 156-line test file + 4 trybuild UI tests at `crates/onc-xdr-derive/tests/` |
| `nfs-mount` and `onc-rpcbind` extracted as standalone crates | Both exist as independent workspace members |
| `MountError` blanket `From<E>` | Only explicit `Rpc`/`Status` construction |
| WebNFS v2/v3 public handle probe | `analyzer.rs:867-943`: v3 zero-length + v2 all-zero 32B, emits F-2.9 |
| Failure-response attribute recovery | `analyzer.rs:998-1051`: `probe_file_access()` harvests `post_op_attr` from denials, emits F-5.6 |

---

## Tier 1 — Must-have: new analyzer checks

These use existing crate infrastructure that src/ never calls. Each adds a new security finding using procedures already implemented in the protocol crates.

### ~~T-1.1: AUTH_DH (flavor 3) security finding~~ ✅ DONE

Emits F-3.7 from both `check_auth_methods()` and `check_nfs4_secinfo()` when AUTH_DH (flavor 3) is present.

### ~~T-1.2: PATHCONF case-insensitive + chown_restricted detection~~ ✅ DONE

`check_pathconf()` calls raw PATHCONF per-export. Emits F-5.7 (case-insensitive) and F-4.6 (unrestricted chown).

### ~~T-1.3: AUTH_TLS STARTTLS probe (RFC 9289)~~ ✅ DONE

`check_auth_tls()` sends AUTH_TLS NULL probe (flavor 7). Emits F-3.8 when TLS is available. Added `AUTH_TLS = 7` and `RPCSEC_GSS = 6` to `auth_flavor` enum in `onc-rpc-client`.

### ~~T-1.4: AUTH_NONE metadata leak probe (FSINFO/GETATTR)~~ ✅ DONE

`check_auth_none_leak()` sends GETATTR with AUTH_NONE per-export. Emits F-5.8 when metadata is leaked to unauthenticated clients.

---

## Tier 2 — Must-have: scanner enrichment

### ~~T-2.1: Portmapper sideband program security labeling~~ ✅ DONE

Added `security_note()` in `onc-rpcbind/src/programs.rs` covering NLM, NSM, RQUOTA, NFS_ACL, NIS, PCNFSD. Scanner console output shows notes in yellow with ⚠ prefix. JSON output includes `security_note` field.

### ~~T-2.2: NetApp program 400010 in program table~~ ✅ DONE

Added `(400_010, "netapp_mgmt")` to sorted PROGRAMS array with test.

### ~~T-2.3: Scanner auth flavor enumeration per export~~ ✅ DONE

Added `auth_flavors: Vec<u32>` to `ExportEntry`. Scanner now MNTs each v3 export to discover auth flavors, then UMNTs. Console output shows `[AUTH_SYS,krb5p]` alongside the ACL. JSON output includes `auth_flavors` array per export.

---

## Tier 3 — Must-have: documentation cleanup

### ~~T-3.1: Update CRATE-DESIGN.md~~ ✅ DONE

Updated proxy bypass table (all 4 fixed), NFSv2 parity table (all on PooledTransport), phase completion status, error taxonomy (all resolved), `#[non_exhaustive]` (48 annotations), xdr-derive tests (present), removed stale rpc_probe.rs references.

### ~~T-3.2: Remove stale dead-code comment in main.rs~~ ✅ DONE

Removed the stale 5-line comment about crate-level dead-code suppression.

---

## Tier 4 — Release

### T-4.1: Version bump to 1.0.0

- **What to do:** Change `version = "0.8.0"` to `version = "1.0.0"` in `Cargo.toml` line 23 (`workspace.package.version`). Protocol crates stay at 0.1.0 (internal, not published).
- **Files:** `Cargo.toml`

### T-4.2: CHANGELOG entry for 1.0.0

- **What to do:** Write the `[1.0.0]` section documenting all changes since v0.8.0.
- **Files:** `CHANGELOG.md`

### ~~T-4.3: FINDINGS.md + finding write-ups~~ ✅ DONE

Added F-3.7, F-3.8, F-4.6, F-5.6, F-5.7, F-5.8 to `docs/FINDINGS.md`. Individual write-up files in `docs/findings/`.

### ~~T-4.4: REQUIREMENTS.md update~~ ✅ DONE

Added requirements for PATHCONF (F-5.7, F-4.6), AUTH_TLS (F-3.8), AUTH_DH (F-3.7), sideband program labeling, and NetApp 400010 with finding traceability.

### T-4.5: README update

- **What to do:** Update findings count, test count, version references for 1.0.
- **Files:** `README.md`

### T-4.6: CLAUDE.md version bump

- **What to do:** Update "v0.8.0 is the latest tagged release" and feature backlog.
- **Files:** `CLAUDE.md`

---

## Tier 5 — Nice-to-have (not blocking 1.0)

### T-5.1: Write verifier reboot oracle

The `writeverf3` field in WRITE/COMMIT responses changes on server reboot. A zero-count COMMIT returns the current verifier at no cost. The wire types exist (`crates/nfs-v3/src/wire/types.rs:984`, COMMIT3resok line 582) but the domain API (`commit_range` at `crates/nfs-v3/src/api/ops.rs:256`) discards the verifier via `flatten()`. No code in `src/` surfaces or uses it.

- **What to do:** Expose the verifier from `commit_range()` (or add a new `commit_verifier()` method). Add a `verifier` shell command or analyzer probe.
- **Effort:** Low
- **Files:** `crates/nfs-v3/src/api/ops.rs`, `src/shell/mod.rs` or `src/engine/analyzer.rs`

### T-5.2: `.nfs*` silly-rename detection

Linux NFS clients create `.nfs<inode><hex>` files when an open file is unlinked. These indicate active file usage. No code checks for this pattern in directory listings.

- **What to do:** Flag `.nfs*` entries in `cmd_ls` output or add a `silly-rename` shell command that scans for them.
- **Effort:** Trivial
- **Files:** `src/shell/mod.rs`

### T-5.3: OS fingerprinting — Windows version-pattern correlation

Windows NFS servers advertise v3+v4.1 only (no v2, no v4.0). The `detect_windows_handle_version` function exists at `src/engine/file_handle.rs:228` but is `#[cfg(test)]` only. The version-set correlation is not used as a fingerprinting signal.

- **What to do:** Add version-pattern heuristic to the analyzer's OS fingerprinting: if a server supports v3+v4.1 but not v4.0 and not v2, flag as likely Windows.
- **Effort:** Low
- **Files:** `src/engine/analyzer.rs` or `src/engine/file_handle.rs`

### T-5.4: FSINFO time_delta + properties extraction

The analyzer reads FSINFO for transfer sizes but does not extract or report `time_delta` (clock granularity, useful for timestamp fingerprinting) or the `properties` bitmask (`FSF3_LINK`, `FSF3_SYMLINK`, `FSF3_HOMOGENEOUS`, `FSF3_CANSETTIME`).

- **What to do:** Extract and report these fields in the analyzer output.
- **Effort:** Low
- **Files:** `src/engine/analyzer.rs`

### T-5.5: Portmapper CALLIT (SET/UNSET/CALLIT)

Only 3 of 6 portmapper procedures are implemented (NULL, GETPORT, DUMP). CALLIT is the amplification/relay primitive behind F-3.2. Currently reported but cannot be demonstrated.

- **What to do:** Implement SET, UNSET, CALLIT in `crates/onc-rpcbind/src/client.rs`.
- **Effort:** Medium
- **Files:** `crates/onc-rpcbind/src/client.rs`, `crates/onc-rpcbind/src/types.rs`

---

## Out of scope (post-v1.0)

| Item | Reason |
|------|--------|
| NLM/NSM/NIS/RQUOTA/NFS_ACL protocol clients | New crates, no consumer yet |
| NFSv4.1/4.2 sessions (OPEN/CLOSE/LOCK/delegations) | Major scope expansion |
| PCNFSD exploitation (auth brute-force, print spool) | New protocol module |
| DRC replay attacks | Requires write verifier oracle first |
| SETCLIENTID callback coercion | NFSv4 stateful ops |
| RPCSEC_GSS context establishment | New crate |
| crates.io publication | Pre-publish checklist not complete |
| ZFS escape handles | Needs lab testing with ZFS servers |
| AUTH_SHORT token replay | Requires network sniffing / PCAP |

---

## Implementation order

1. **Trivial wins (day 1):** T-2.2 (NetApp 400010), T-3.2 (main.rs comment), T-1.1 (AUTH_DH finding)
2. **Low-effort analyzer checks (days 2-3):** T-2.1 (sideband labeling), T-1.2 (PATHCONF), T-1.3 (AUTH_TLS), T-1.4 (AUTH_NONE)
3. **Docs (day 4):** T-3.1 (CRATE-DESIGN.md update)
4. **Nice-to-haves if time permits (day 5):** T-5.1 through T-5.4
5. **Release (day 6):** T-4.1 through T-4.6 (version bump, CHANGELOG, findings, README)

## Verification

After every change: `make check-all` (fmt → clippy → deny → check → test → doc → hygiene → machete).
