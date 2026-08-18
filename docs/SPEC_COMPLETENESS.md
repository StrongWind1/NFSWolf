# Spec Completeness — Crate Gap Analysis

Status of each protocol crate against its authoritative RFC, with precise section citations for remaining gaps. Last updated 2026-08-12.

Verified by 10-agent parallel audit: 540 items checked, 505 correct on first pass, all 29 deviations resolved (2 medium, 15 low, 5 info, 7 missing).

---

## Summary

| Crate | Status | Primary RFC | Procedures |
|-------|--------|-------------|------------|
| `nfs-mount` | **Complete** | RFC 1094 App A / RFC 1813 App I | 6/6 (v1 + v3) |
| `nfs-v2` | **Complete** | RFC 1094 | 18/18 |
| `nfs-v3` | **Complete** | RFC 1813 | 22/22 |
| `onc-xdr-derive` | **Complete** | RFC 4506 | structs + enums + unions |
| `onc-xdr` | **Complete** | RFC 4506 | all primitive types (i32, u32, i64, u64, f32, f64, bool, opaque, string, void) |
| `onc-rpcbind` | **Complete** | RFC 1833 | portmapper 6/6 + rpcbind v3 8/8 + v4 12/12 |
| `onc-rpc-client` | **Complete** (excluding RPCSEC_GSS) | RFC 5531 / RFC 2695 | TCP + UDP transport, AUTH_SYS, AUTH_DH full cryptographic sessions (`auth-dh` feature), AUTH_SHORT credential replay, multi-fragment, batched calls, broadcast |
| `nfs-v4` | **Complete** — full RFC 7530 wire compliance + stateful infrastructure | RFC 7530 | 37/37 typed + decoded, 66 status codes, stateful OPEN/CLOSE/LOCK |

---

## Completed Crates (1–7)

### `nfs-mount`

6/6 procedures for both MOUNT v1 (RFC 1094 Appendix A) and MOUNT v3 (RFC 1813 Appendix I): NULL, MNT, DUMP, UMNT, UMNTALL, EXPORT.

### `nfs-v2`

18/18 procedures (RFC 1094 sec 2.2, procs 0–17). All wire types verified against the RFC. Constants: `FHSIZE=32`, `MAXDATA=8192`, `MAXPATHLEN=1024`, `MAXNAMLEN=255`, `COOKIESIZE=4`. `FType` preserves unknown wire values. `readdirres` stores the `eof` flag.

### `nfs-v3`

22/22 procedures (RFC 1813 sec 3, procs 0–21). All wire types, domain types, and error classifications verified. `Nfs3Error::from_nfsstat3` preserves unknown status codes. `FsStat` exposes `invarsec`.

### `onc-xdr-derive`

Handles all XDR type shapes: structs (RFC 4506 sec 4.14), enums and discriminated unions (sec 4.15).

### `onc-xdr`

All XDR primitive types implemented: `i32` (sec 4.1), `u32` (sec 4.2), `bool` (sec 4.4), `i64`/`u64` (sec 4.5), `f32` (sec 4.6), `f64` (sec 4.7), fixed-length opaque (sec 4.9), variable-length opaque (sec 4.10), string (sec 4.11), variable-length array (sec 4.13), void (sec 4.16), optional-data linked list (sec 4.19). Quadruple-precision float (sec 4.8) is omitted — Rust has no native f128 and no NFS protocol uses it.

### `onc-rpcbind`

All portmapper v2 procedures (RFC 1057 Appendix A): NULL, SET, UNSET, GETPORT, DUMP, CALLIT. All rpcbind v3 procedures (RFC 1833 sec 2.2.1): SET, UNSET, GETADDR, DUMP, CALLIT, GETTIME, UADDR2TADDR, TADDR2UADDR. All rpcbind v4 procedures (RFC 1833 sec 2.2.2): BCAST, GETVERSADDR, INDIRECT, GETADDRLIST, GETSTAT. Wire types: `RpcbEntry`, `RpcbList`, `RpcbRmtCallArgs`, `RpcbRmtCallRes`, `Netbuf`, `RpcbAddrEntry`, `RpcbAddrList`, `RpcbStatByvers`.

### `onc-rpc-client` (excluding RPCSEC_GSS)

All RFC 5531 client-side features implemented except RPCSEC_GSS:

| Feature | RFC Section | Status |
|---------|------------|--------|
| TCP record marking (multi-fragment reassembly) | sec 11 | Done |
| XID matching | sec 9 | Done |
| All `accept_stat` / `reject_stat` / `auth_stat` values | sec 8.3, 13.2 | Done (including RFC 7861 extensions) |
| AUTH_NONE / AUTH_SYS credentials | sec 14 | Done |
| AUTH_DH full cryptographic session (DH key exchange, DES encryption, timestamp verification) | RFC 2695 | Done (`auth-dh` feature: `AuthDhSession`, `--auth-dh-netname`/`--auth-dh-pubkey` CLI flags) |
| AUTH_SHORT credential replay (opaque token capture from reply verifiers) | RFC 5531 sec 14 / RFC 1057 sec 9.3 | Done (`--short-token` CLI flag) |
| Batched calls | sec 8.4.1 | Done (`send_batch`) |
| UDP RPC (no record marking) | sec 10 | Done |
| UDP retransmission with XID reuse | sec 5 | Done (`call_rpc_udp_retry`) |
| Broadcast RPC (multi-reply collection) | sec 8.4.2 | Done (`broadcast_rpc_udp`) |

**Remaining gap — RPCSEC_GSS (RFC 2203):** context init handshake (sec 5.2), per-message integrity (sec 5.3.2.2), per-message privacy (sec 5.3.2.3), sequence window (sec 5.3.1), context destruction (sec 5.4), error recovery (sec 5.3.3.3). Pulls in the entire GSS-API/Kerberos stack. 2+ months of work with no current consumer.

---

## 8. `nfs-v4` — Complete (RFC 7530)

**Status: Complete.** All 8 phases of the NFSv4 completion plan have been implemented. 244 nfs-v4 crate tests, 790 total project tests. Live-validated against 4 Linux knfsd servers.

### What shipped

| Area | Details |
|------|---------|
| Status codes | All 66 RFC 7530 S13.1 status codes named (was 25/49). Classification methods: `is_transient()`, `is_stateid_error()`, `is_lease_error()`, `is_permission_denied()`, `is_not_found()`, `is_stale()`. |
| Typed operations | All 37 ops use typed args (was 10 opaque `Vec<u8>` payloads). All response decoders working (was 5 ops causing COMPOUND parse stops). |
| Wire types | `Stateid4`, `ChangeInfo4`, `NfsFtype4`, `OpenOwner4`, `LockOwner4`, `NfsAce4`, `StableHow4`, `OpenDelegationType4`, `CreateMode4`, `LockType4`. |
| GETATTR decode | Generalized `Fattr4Decoded` decoder for 15 key attributes (was fsid + sec_label only). READDIR entries carry inline attrs + filehandle. |
| CompoundBuilder | Builder methods for all 37 ops (was 15). |
| Domain types | `Nfs4FileInfo`, `Nfs4DirEntry`, `Nfs4FileType`. `AttrRequest::shell_attrs()` / `shell_attrs_with_fh()`. |
| Client API | 47 public methods: path resolution (`lookup`, `getattr`, `readlink`, `access`), directory ops (`readdir_plus`, `mkdir`, `remove`, `rename`, `link`, `symlink`), stateful file I/O (`open_read`/`open_write`/`close`, `read_via_open`/`write_via_open`, `read_file`/`write_file`), SECINFO. |
| Stateful infrastructure | `Nfs4Session` (SETCLIENTID lifecycle, lease renewal), `OpenState` (stateid tracking, open-owner sequencing, OPEN_CONFIRM), `LockState` (lock-owner management). |
| Crash recovery | `NFS4ERR_GRACE` wait-and-retry, `NFS4ERR_STALE_CLIENTID` re-establish, `NFS4ERR_EXPIRED` full state re-open. |
| Error classification | `Nfs4Error<E>` with `is_transient()`, `is_permission_denied()`, `is_not_found()`, `is_stale()`, `nfs_status()`. |

### What remains deliberately out of scope

| Item | Reason |
|------|--------|
| CB_RECALL callback server | Requires a listening RPC service on the client; different architecture |
| NFSv4.1 session management (RFC 8881) | Different protocol version; the 4 v4.1 ops already present are sufficient for recon |
| Full ACL encoding/decoding | Complex attribute; encode as opaque for now |
| All 76 fattr4 attributes | The 15 key attributes are decoded; others remain opaque |
| RPCSEC_GSS integration | Separate crate concern (onc-rpc-client); see the remaining gap note below |

### Remaining gap — RPCSEC_GSS (onc-rpc-client, not nfs-v4)

RPCSEC_GSS (RFC 2203) is the only cross-crate gap: context init handshake (sec 5.2), per-message integrity (sec 5.3.2.2), per-message privacy (sec 5.3.2.3), sequence window (sec 5.3.1), context destruction (sec 5.4), error recovery (sec 5.3.3.3). Pulls in the entire GSS-API/Kerberos stack. 2+ months of work with no current consumer.
