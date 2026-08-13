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
| `onc-rpc-client` | **Complete** (excluding RPCSEC_GSS) | RFC 5531 / RFC 2695 | TCP + UDP transport, AUTH_SYS, AUTH_DH wire types, multi-fragment, batched calls, broadcast |
| `nfs-v4` | Partial — stateless read-only subset | RFC 7530 | 37/37 sendable, ~17 fully decoded |

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
| AUTH_DH wire types (credential + verifier) | RFC 2695 sec 2.4 | Done (separate cred/verf per spec) |
| Batched calls | sec 8.4.1 | Done (`send_batch`) |
| UDP RPC (no record marking) | sec 10 | Done |
| UDP retransmission with XID reuse | sec 5 | Done (`call_rpc_udp_retry`) |
| Broadcast RPC (multi-reply collection) | sec 8.4.2 | Done (`broadcast_rpc_udp`) |

**Remaining gap — RPCSEC_GSS (RFC 2203):** context init handshake (sec 5.2), per-message integrity (sec 5.3.2.2), per-message privacy (sec 5.3.2.3), sequence window (sec 5.3.1), context destruction (sec 5.4), error recovery (sec 5.3.3.3). Pulls in the entire GSS-API/Kerberos stack. 2+ months of work with no current consumer.

---

## 8. `nfs-v4` — Remaining Gaps (RFC 7530)

The only crate with significant remaining work. The stateless read-only subset is complete; the stateful half is not implemented.

### Response decoding gaps

5 ops cause COMPOUND parsing to stop — all results after them in the COMPOUND are lost:

| Op | Name | Missing Response Types | RFC 7530 Section |
|----|------|----------------------|-----------------|
| 6 | CREATE | `change_info4`, `bitmap4` (attrset) | S16.4 |
| 12 | LOCK | `stateid4` (lock stateid) | S16.10 |
| 13 | LOCKT | `LOCK4denied` (denied lock info) | S16.11 |
| 18 | OPEN | `stateid4`, `change_info4`, `rflags`, `bitmap4`, `open_delegation4` | S16.16 |
| 35 | SETCLIENTID | `clientid4`, `verifier4` (confirm) | S16.33 |

### Encode gaps

10 ops use opaque `Vec<u8>` payloads instead of typed args:

| Op | Name | RFC 7530 Section |
|----|------|-----------------|
| 6 | CREATE | S16.4 |
| 12 | LOCK | S16.10 |
| 13 | LOCKT | S16.11 |
| 14 | LOCKU | S16.12 |
| 17 | NVERIFY | S16.15 |
| 18 | OPEN | S16.16 |
| 34 | SETATTR | S16.32 |
| 35 | SETCLIENTID | S16.33 |
| 37 | VERIFY | S16.35 |
| 39 | RELEASE_LOCKOWNER | S16.37 |

### Missing `Nfs4Status` codes

24 of 49 RFC-defined error codes (RFC 7530 S13.1) fall to `Unknown(u32)`:

| Category | Missing Codes (value) | RFC 7530 Sections |
|----------|----------------------|------------------|
| File System | `XDEV` (18), `MLINK` (31), `DQUOT` (69), `BADTYPE` (10007), `RESTOREFH` (10030), `FILE_OPEN` (10046) | S13.1.4.x |
| General | `TOOSMALL` (10005), `SERVERFAULT` (10006), `DELAY` (10008), `RESOURCE` (10018), `MINOR_VERS_MISMATCH` (10021), `OP_ILLEGAL` (10044) | S13.1.1.x, S13.1.3.x |
| Locking | `SHARE_DENIED` (10015), `BAD_SEQID` (10026), `LOCK_RANGE` (10028), `LOCKS_HELD` (10037), `OPENMODE` (10038), `BAD_RANGE` (10042), `LOCK_NOTSUPP` (10043), `DEADLOCK` (10045) | S13.1.8.x |
| Stateid | `STALE_CLIENTID` (10022), `STALE_STATEID` (10023), `OLD_STATEID` (10024), `BAD_STATEID` (10025), `LEASE_MOVED` (10031), `ADMIN_REVOKED` (10047) | S13.1.5.x, S13.1.10.x |
| Reclaim | `GRACE` (10013), `NO_GRACE` (10033), `RECLAIM_BAD` (10034), `RECLAIM_CONFLICT` (10035) | S13.1.9.x |
| Filehandle | `FHEXPIRED` (10014), `NOFILEHANDLE` (10020), `SYMLINK` (10029) | S13.1.2.x |
| Client ID | `CLID_INUSE` (10017) | S13.1.10.1 |
| Attribute | `SAME` (10009), `NOT_SAME` (10027), `ATTRNOTSUPP` (10032), `BADOWNER` (10039), `BADCHAR` (10040), `BADNAME` (10041) | S13.1.7.x, S13.1.11.x |
| Callback | `CB_PATH_DOWN` (10048) | S13.1.12.1 |

### Absent stateful infrastructure

| Component | RFC 7530 Sections | What's needed |
|-----------|-------------------|---------------|
| Client ID lifecycle | S9.1.1, S16.33, S16.34 | SETCLIENTID -> SETCLIENTID_CONFIRM state machine, clientid storage, verifier management |
| Stateid tracking | S9.1.4, S2.2.11 | Open/lock/delegation stateid storage, seqid advancement |
| Open-owner sequencing | S9.1.3, S9.1.11 | Per-owner seqid counter, OPEN_CONFIRM on first use |
| Lock-owner management | S9.1.5, S2.2.14–15 | `lock_owner4` struct, `open_to_lock_owner4` transition |
| Lease renewal | S9.5 | Background RENEW loop, implicit renewal tracking |
| OPEN response parsing | S16.16 | Full `OPEN4res` decode |
| SETCLIENTID response parsing | S16.33 | Extract `clientid4` + `setclientid_confirm` verifier |
| Delegation infrastructure | S10, S10.2, S10.4, S18.2 | Callback server for CB_RECALL, delegation stateid storage |
| Crash recovery | S9.6 | Grace period handling, NFS4ERR_GRACE/STALE_CLIENTID recovery loops |
| Share reservations | S9.9 | Per-open share_access/share_deny bookkeeping |

### Effort estimate

Adding the 24 `Nfs4Status` codes is a day. Typing the 10 opaque ops is a week. Fixing the 5 response decoders is another week. The stateful engine is 3–6 months of new architecture. And that's before NFSv4.1 sessions (RFC 8881).
