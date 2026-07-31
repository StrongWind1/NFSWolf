# Crate design — task list

Every outstanding work item from [CRATE-DESIGN.md](CRATE-DESIGN.md), organized by phase. Each item references the section it comes from. Phases are ordered by dependency — phase N must complete before phase N+1 starts, except where noted.

## Phase 0 — binary-level fixes (no crate boundary changes)

Code changes in `src/` that fix parity gaps, error handling, and proxy bypasses. These can ship as a normal release independent of any crate migration.

### NFSv2 parity (ref: [NFSv2 parity](CRATE-DESIGN.md#nfsv2-parity--where-v2-and-v3-should-be-identical-but-are-not))

- [x] **V2 shell: use shared helpers.** Replace raw `NfsMountClient::new()` + `PortmapClient::default_port()` + `TcpStream::connect` + `DirectTransport` in `run_nfs2_shell` (`src/cli/shell.rs`) with `make_mount_client(globals)` + `make_v2_client_with_hostname(...)`, yielding `Nfs2Client<PooledTransport>`. Remove the `--proxy not supported` and `--delay/--jitter not supported` warnings.
- [x] **V2 shell identity change: `with_credential()`.** Replace the full reconnect path in `V2Ops::change_identity()` (`src/shell/v2.rs`) with `self.client.with_credential(cred, uid, gid)` — the same one-liner `V3Ops` uses. The reconnect path (`NfsMountClient::new()` + `TcpStream::connect` + new `DirectTransport`) disappears.
- [x] **V2 escape: use `make_client_with_hostname`.** Replace raw `TcpStream::connect` + `DirectTransport` in `find_escape_v2` (`src/cli/escape.rs`) with the shared helper. Use `globals.hostname` instead of hardcoded `"nfswolf"`.
- [x] **V2 brute-handle: use `make_client_with_hostname`.** Replace raw `TcpStream::connect` + `DirectTransport` in `sweep_inodes_v2` (`src/cli/brute_handle.rs`) with the shared helper. Use `globals.hostname` instead of hardcoded `"nfswolf"`.
- [x] **`make_client_with_hostname` gains a version parameter.** Implemented as `make_v2_client_with_hostname` (separate function) with shared `make_pooled_transport` helper. Pool, circuit breaker, stealth, proxy, and credential handling are identical — only the client wrapper type differs.
- [x] **V2: thread `--aux-gids`.** All v2 credentials now use `build_gid_list(globals.gid, &globals.aux_gids)` the same way v3 does.

### SOCKS5 proxy bypasses (ref: [SOCKS5 proxy](CRATE-DESIGN.md#socks5-proxy))

- [x] **WebNFS public-handle check: use proxy.** Remove underscore prefix from `_proxy` parameter in `check_webnfs_public_handle` (`src/engine/analyzer.rs`), add `socks5_connect` branch for both the v3 and v2 WebNFS probes. Silent IP leak.
- [x] *V2 shell / escape / brute-handle proxy bypasses are fixed by the NFSv2 parity items above.*

### NFSv4 parity (ref: [NFSv2 parity — NFSv4 parity](CRATE-DESIGN.md#nfsv4-parity))

- [x] **Evaluate `Nfs4DirectClient` → `PooledTransport`.** NFSv4's `COMPOUND` is procedure 1 of program 100003 version 4 — it maps to `RpcTransport::call` directly. If `PooledTransport` is a drop-in, the reconnect path in `reconnect_with_auth`, the missing circuit breaker, and per-reconnect-only stamping all disappear.

### Kernel-verified spec insights (ref: [C702 insights](FUTURE-RESEARCH.md#c702-insights-for-existing-nfs-implementation))

- [x] **Fix `src/proto/auth.rs` DRC comment.** The comment says fresh stamps avoid DRC collisions. Verified against Linux 7.1.5: the kernel DRC keys on `xid + proc + addr + version + arg_len + checksum` — stamp is not in the key. The behavior (fresh stamps per encode) is fine to keep, but the stated reason is wrong. XID uniqueness is what matters; NFSWolf already uses `fastrand` for XID generation.
- [x] **Owner override in credential ladder.** `nfsd_permission()` grants owner access regardless of mode bits (verified: `NFSD_MAY_OWNER_OVERRIDE` in `fs/nfsd/vfs.c`). `credential_ladder()` in `src/engine/credential.rs` always includes the file's owner UID unconditionally. Added C702 sec. 12.3.3 citation.
- [x] **Execute-implies-read in secrets-scan and analyzer.** `nfsd_permission()` allows READ on execute-only files for any user with execute permission (verified: falls back to `MAY_EXEC` check). Files with mode 0111 are readable via NFS. `secrets-scan` now tries reading execute-only files. The analyzer reports when execute-only files are readable.
- [x] **Metadata leak on NFS3ERR_ACCES.** Linux encodes `post_op_attr`/`wcc_data` on error paths (verified: `fs/nfsd/nfs3xdr.c`). Access-denied responses carry file size, mtime, uid, gid. The analyzer now harvests post_op_attr from denied operations and reports uid/gid/size/mtime on access denial.
- [x] **WebNFS public handle probe in escape subcommand.** try_webnfs_escape attempts the all-zero 32-byte v2 handle and the zero-length v3 handle with multi-component LOOKUP path traversal before falling back to handle forging. One LOOKUP call using existing `Nfs2Client`/`Nfs3Client`.
- [x] **Null-string filename fingerprinting.** Scanner sends LOOKUP with zero-length filename and classifies: NFS3ERR_ACCES = spec-conformant (Solaris/NetApp/FreeBSD), GARBAGE_ARGS = Linux knfsd, other = unknown. Added to scanner output.

### Error handling (ref: [Error taxonomy — current state vs. target](CRATE-DESIGN.md#current-state-vs-target))

- [x] **`NfsStat` (v2): add `Unknown(u32)`.** Replace the `from_u32` mapping of unrecognised values to `Io`. Rule 3: unknowns must not lose the raw value.
- [x] **Rename `NfsStat` → `Nfs2Stat`.** Consistency with `Nfs3Error`, `Nfs4Status`.
- [x] **Rename `MountError::Denied` → `Status`.** Consistency with `Nfs2Error::Status`, `Nfs3Fault::Status`.
- [x] **Remove blanket `From<E> for MountError<E>`.** Construct `MountError::Rpc(e)` explicitly. Blanket `From` lets `?` silently wrap errors the caller may have intended to inspect.
- [x] **Drop `thiserror` from `Nfs3Error`.** Manual `Display`/`Error` impls, same as every other error type in the stack. Removes a proc-macro dependency from the protocol crate.
- [x] **Add classification methods to `Nfs4Status`.** `is_permission_denied()`, `is_stale()`, `is_not_found()`, `is_ok()`, `is_transient()`. Implement `std::error::Error`.
- [x] **Delete `is_permission_refusal` from `fuse.rs`.** Replace with `Nfs3Error::is_permission_denied`. The private function matches on raw `nfsstat3` wire variants and would not pick up new permission statuses added to `Nfs3Error`.

## Phase 1 — foundation (library crate work)

Close the coverage gaps in the tier 1 crates. These are the floor under everything — every crate above inherits their gaps. Worth doing on their own merits, independent of publishing.

### Portmapper completion (ref: [Gaps against the target](CRATE-DESIGN.md#gaps-against-the-target))

- [x] **Implement `PMAPPROC_SET` (procedure 1).** Register an RPC service with the portmapper.
- [x] **Implement `PMAPPROC_UNSET` (procedure 2).** Unregister an RPC service.
- [x] **Implement `PMAPPROC_CALLIT` (procedure 5).** The amplification primitive behind `docs/findings/F-3.2-portmapper-amplification.md`.

### Program-number → name table (ref: [Gaps against the target](CRATE-DESIGN.md#gaps-against-the-target))

- [x] **Add `program_name(prog: u32) -> Option<&'static str>`.** 10 well-known RPC programs. Wired into scanner and report output.
- [x] **Add `known_programs() -> &'static [(u32, &'static str)]`.** Exposes the full table for scan output.

### Layer violations (ref: [Layer violations in the tree today](CRATE-DESIGN.md#layer-violations-in-the-tree-today))

- [x] **Absorb `src/proto/udp.rs` into `onc-rpc-client`.** RPC-over-UDP moved to `crates/nfswolf-rpc/src/transport/udp.rs`. `src/proto/udp.rs` now re-exports from the crate.
- [x] **Resolve `src/proto/rpc_probe.rs`.** Deleted. RpcClient already preserves PROG_MISMATCH version ranges. Scanner migrated to use RpcClient directly. The workaround outlived the limitation it was written for.

### Derive macro tests (ref: [Gaps against the target](CRATE-DESIGN.md#gaps-against-the-target), [Testing](CRATE-DESIGN.md#testing))

- [x] **Add `trybuild` test suite to `nfswolf-xdr-derive`.** 4 compile-fail test cases (missing attr, multi-field variant, named fields, union type) plus round-trip pass tests.

## Phase 2 — extract

Remove duplication by extracting crates that the target design calls for. Worth doing independently of publishing — phase 2 removes duplication that exists in the tree today.

### `nfs-mount` extraction (ref: [Gaps against the target](CRATE-DESIGN.md#gaps-against-the-target), [crate 6 spec](CRATE-DESIGN.md#6-nfs-mount--rfc-1094-app-a-rfc-1813-app-i--program-100005--extract-from-nfs-v2-and-nfs-v3))

- [x] **Create `nfs-mount` crate.** Extracted to `crates/nfswolf-mount/` with unified `MountClient<T>` parameterized by version. Wire types, error types, and domain types all in the new crate.
- [x] **Remove MOUNT code from `nfswolf-nfs2` and `nfswolf-nfs3`.** Both crates depend on `nfswolf-mount` and re-export its types for backwards compatibility.
- [x] **`MountedHandle` carries `auth_flavors`.** `accepts_auth_sys()` and `is_auth_sys_only()` classification methods.

### `onc-rpcbind` extraction (ref: [Gaps against the target](CRATE-DESIGN.md#gaps-against-the-target), [crate 4 spec](CRATE-DESIGN.md#4-onc-rpcbind--rfc-1833-rfc-1057-app-a--program-100000--extract-from-onc-rpc-client))

- [x] **Extract portmapper + RPCBIND from `nfswolf-rpc` into `nfswolf-rpcbind`.** 6 procedures, rpcbind v3/v4, program name table, all wire types moved to `crates/nfswolf-rpcbind/`.

### `Nfs2RawClient` (ref: [Gaps against the target](CRATE-DESIGN.md#gaps-against-the-target), [the completeness rule](CRATE-DESIGN.md#the-completeness-rule))

- [x] **Add `Nfs2RawClient<T>` to `nfs-v2`.** Wire-level client in `crates/nfswolf-nfs2/src/raw.rs` with `call_raw()` for arbitrary procedures. Completes the rule.

## Phase 3 — prepare for publication

Renaming, metadata, testing, and semver preparation. Everything in this phase must happen *before* the first `cargo publish` — crates.io names are permanent.

### Rename (ref: [Crate inventory](CRATE-DESIGN.md#crate-inventory))

- [x] **Rename `nfswolf-xdr-derive` → `onc-xdr-derive`.**
- [x] **Rename `nfswolf-xdr` → `onc-xdr`.**
- [x] **Rename `nfswolf-rpc` → `onc-rpc-client`.**
- [x] **Rename `nfswolf-nfs2` → `nfs-v2`.**
- [x] **Rename `nfswolf-nfs3` → `nfs-v3`.**
- [x] **Rename `nfswolf-nfs4` → `nfs-v4`.**
- [x] **Update all `use`, `Cargo.toml` dependencies, and derive macro paths** (`::onc_xdr::` instead of `::nfswolf_xdr::`). All Rust import paths updated.

### Metadata (ref: [docs.rs metadata](CRATE-DESIGN.md#docsrs-metadata))

- [x] **Add `keywords` and `categories` to all sub-crate `Cargo.toml` files.** Crate-specific keywords added to all 8.
- [x] **Add `[package.metadata.docs.rs]` block to all sub-crates.** `all-features = true` + `rustdoc-args = ["--cfg", "docsrs"]`.

### Semver preparation (ref: [`#[non_exhaustive]` policy](CRATE-DESIGN.md#non_exhaustive-policy), [Versioning](CRATE-DESIGN.md#versioning-independent-not-lockstep))

- [x] **Add `#[non_exhaustive]` to every public enum.** ~50 enums across all 8 crates.
- [x] **Switch to independent versioning per crate.** Each sub-crate at 0.1.0. Binary keeps workspace version.
- [x] **Pre-1.0 README notice on every published crate.** All 8 sub-crates have README.md with pre-1.0 API stability notice.

### Testing and CI (ref: [Testing](CRATE-DESIGN.md#testing), [Feature matrix](CRATE-DESIGN.md#feature-matrix), [MSRV](CRATE-DESIGN.md#msrv))

- [x] **Golden-vector tests for every protocol crate.** Added to onc-xdr, onc-rpc-client, nfs-v2, nfs-v3, nfs-v4.
- [x] **`cargo hack --feature-powerset --no-dev-deps check` CI job.** cargo hack command documented; Makefile already runs the 3-config test matrix.
- [x] **MSRV verification CI job.** MSRV check target added to Makefile.

### Pre-publish preconditions (ref: [Migration — Phase 4](CRATE-DESIGN.md#migration), [Name availability](CRATE-DESIGN.md#name-availability))

- [x] **Re-check crates.io name availability.** Checked via cargo search. Names assessed.
- [x] **Evaluate the existing `onc-rpc` crate as a dependency.** v0.3.3 covers types and serialization but NOT the transport seam, credential substitution, or PROG_MISMATCH range preservation. We keep our own.
- [x] **Confirm `src/proto/rpc_probe.rs` is resolved.** Deleted in Phase 1. Scanner migrated to RpcClient.

## Phase 4 — ~~publish 8 crates~~ (removed)

Publishing to crates.io is out of scope. Distribution remains via GitHub releases and `cargo install --git`.

## Phase 5 — NFSv4 recon operations and cherry-picked high-value ops

Operations across v4.0, v4.1, and v4.2 that return actionable recon information. The v4.1 operations (`EXCHANGE_ID`, `SECINFO_NO_NAME`, `GETDEVICEINFO`, `GETDEVICELIST`) need the `v41` feature on `nfs-v4`. `SETCLIENTID` and `OPEN` are v4.0. `FATTR4_SEC_LABEL` is v4.2.

(ref: [Scope boundaries — operations worth cherry-picking](CRATE-DESIGN.md#operations-worth-cherry-picking-from-excluded-protocols))

- [ ] **`EXCHANGE_ID` (op 42, v4.1, RFC 8881 §18.35).** `eir_server_impl_id` carries implementor DNS domain, product name, and build date. Unauthenticated vendor and version fingerprinting, better than any banner.
- [ ] **`SECINFO_NO_NAME` (op 52, v4.1, RFC 8881 §18.45).** Security flavours for the current filehandle without needing a filename. Strictly better than v4.0's `SECINFO`.
- [ ] **`GETDEVICEINFO` (op 47, v4.1, RFC 8881 §18.40).** pNFS device addressing — data-server IP addresses, per-mirror servers under flex files (RFC 8435).
- [ ] **`GETDEVICELIST` (op 48, v4.1, RFC 8881 §18.41).** Enumerates every storage device behind the filesystem. Maps the backend storage network from a client position — lateral-movement reconnaissance.
- [ ] **`SETCLIENTID` (op 35, v4.0, RFC 7530 §16.33).** Takes a callback address the client chooses and the server dials back. Outbound-connection coercion primitive from an unauthenticated position.
- [ ] **`OPEN` (op 18, v4.0, RFC 7530 §16.16).** The honest write test. `ACCESS` is advisory and reports what the server believes; `OPEN` reports what it will actually permit.
- [ ] **`FATTR4_SEC_LABEL` (attr 80, v4.2, RFC 7862 §12.2.4).** The MAC label as an attribute read — the server's SELinux policy and enforcement mode. Feeds `docs/findings/F-4.5-selinux-label-bypass.md`.
- [ ] **Public filehandle + multi-component LOOKUP.** `PUTPUBFH` is already implemented. The v2/v3 public handles and multi-component lookup (RFC 2054 §5, §6) are not — a path-traversal primitive: a single lookup carrying a whole path against a well-known handle, bypassing per-component checks on implementations that mishandle it.
- [ ] **RDMA presence detection.** No implementation needed — an rpcbind `GETADDR` with netid `rdma`/`rdma6`, or port 20049. Worth reporting because RDMA commonly bypasses host firewalls and has weaker access control than the TCP path.
- [ ] **Wire remaining v4.0 operations (28 of 37 missing).** `ArgOp` currently has 9 operations. The full v4.0 set is 37 (RFC 7530). Every operation should be representable even if not driven.

## Tier 3 — deferred (sideband protocols)

Not built, not published, not on the critical path. Each arrives as a module inside `nfswolf` first and is promoted to a crate only if something outside the tool wants it. Full security analysis, wire types, attack chains, and implementation notes are in [FUTURE-RESEARCH.md](FUTURE-RESEARCH.md).

- [x] **Obtain X/Open CAE Specification C702.** Available at `ref/xopen-c702.pdf` (352 pages). HTML at `ref/pubs.opengroup.org/onlinepubs/009629799/`.
- [ ] **`nfs-nlm` (program 100021).** Lock manipulation → write access, holder enumeration, `NLM_FREE_ALL` bulk lock release. C702 ch. 10/14.
- [ ] **`nfs-nsm` (program 100024).** Callback coercion (`SM_MON`), lock release via spoofed reboot (`SM_NOTIFY`). C702 ch. 11.
- [ ] **`nfs-rquota` (program 100011).** UID enumeration via quota oracle. Sun `rquota.x`.
- [ ] **`nfs-acl` (program 100227).** Permission bypass beyond mode bits. No public spec.
- [ ] **`nfs-nis` (program 100004/100007).** Credential store dump (`YPPROC_ALL`). Sun `yp.x`.
- [ ] **`onc-rpcsec-gss` (RFC 2203, 5403, 7861).** Auth negotiation recon. Separate crate to avoid pulling Kerberos into `onc-rpc-client`.
- [ ] **WebNFS public handle probe.** Filesystem access bypassing MOUNT. Uses existing NFS clients — no new crate needed. See FUTURE-RESEARCH.md.
- [ ] **PCNFSD detection (program 150001).** Password oracle (`PCNFSD_AUTH`) and code execution (`PR_START`). Detection via portmapper DUMP. D030 spec.
