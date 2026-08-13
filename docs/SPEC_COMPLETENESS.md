# Spec Completeness — Crate Gap Analysis

Effort ranking to bring each protocol crate to 100% spec completeness, with precise RFC section citations for every gap. Last updated 2026-08-12.

---

## Ranking Summary

| Rank | Crate | Status | Primary RFC |
|------|-------|--------|-------------|
| 1 | `nfs-mount` | **Complete** | RFC 1094 App A / RFC 1813 App I |
| 2 | `nfs-v2` | **Complete** | RFC 1094 |
| 3 | `nfs-v3` | **Complete** | RFC 1813 |
| 4 | `onc-xdr-derive` | **Complete** | RFC 4506 |
| 5 | `onc-xdr` | **Complete** | RFC 4506 |
| 6 | `onc-rpcbind` | **Complete** | RFC 1833 |
| 7 | `onc-rpc-client` | **Complete** (excluding RPCSEC_GSS) | RFC 5531 / RFC 2203 |
| 8 | `nfs-v4` | Partial — stateless read-only subset | RFC 7530 |

---

## 1. `nfs-mount` — Zero effort

Already complete. 6/6 procedures for both MOUNT v1 (RFC 1094 Appendix A) and MOUNT v3 (RFC 1813 Appendix I): NULL, MNT, DUMP, UMNT, UMNTALL, EXPORT.

## 2. `nfs-v2` — Zero effort

Already complete. 18/18 procedures (RFC 1094 sec 2.2, procs 0–17).

## 3. `nfs-v3` — Zero effort

Already complete. 22/22 procedures (RFC 1813 sec 3, procs 0–21).

## 4. `onc-xdr-derive` — Zero effort

Already complete. Handles all XDR type shapes: structs (RFC 4506 sec 4.14), enums and discriminated unions (sec 4.15).

---

## 5. `onc-xdr` — Complete

All 4 missing `Pack`/`Unpack` impls added (i32, i64, f32, f64):

| Type | RFC 4506 Section | Wire Encoding | NFS Usage |
|------|-----------------|---------------|-----------|
| `i32` | sec 4.1 | 4 bytes, big-endian, two's complement | NFSv4 `int32_t` typedef (RFC 7530) — defined but unused in wire structs |
| `i64` | sec 4.5 | 8 bytes, big-endian, two's complement | NFSv4 `nfstime4.seconds` (RFC 7530 sec 2.2.8) — the only real consumer |
| `f32` | sec 4.6 | 4 bytes, big-endian, IEEE 754 single | Not used by any NFS version |
| `f64` | sec 4.7 | 8 bytes, big-endian, IEEE 754 double | Not used by any NFS version |

Only `i64` has a real NFS consumer. The other three are pure spec-completeness.

---

## 6. `onc-rpcbind` — Complete

### Portmapper v2 (RFC 1833 sec 3.1–3.2)

Wire types exist for all 6 procedures. 3 client methods missing:

| Proc | Name | Gap | Section |
|------|------|-----|---------|
| 0 | `PMAPPROC_NULL` | Done | sec 3.1, 3.2 |
| 1 | `PMAPPROC_SET` | Client method only | sec 3.1, 3.2 |
| 2 | `PMAPPROC_UNSET` | Client method only | sec 3.1, 3.2 |
| 3 | `PMAPPROC_GETPORT` | Done | sec 3.1, 3.2 |
| 4 | `PMAPPROC_DUMP` | Done | sec 3.1, 3.2 |
| 5 | `PMAPPROC_CALLIT` | Client method only | sec 3.1, 3.2 |

### rpcbind v3 (RFC 1833 sec 2.1, 2.2.1)

| Proc | Name | Gap | Section |
|------|------|-----|---------|
| 1 | `RPCBPROC_SET` | Client method (args type exists) | sec 2.2.1 |
| 2 | `RPCBPROC_UNSET` | Client method (args type exists) | sec 2.2.1 |
| 3 | `RPCBPROC_GETADDR` | Done | sec 2.2.1 |
| 4 | `RPCBPROC_DUMP` | Wire types (`rpcblist_ptr`) + client method | sec 2.2.1 |
| 5 | `RPCBPROC_CALLIT` | Wire types (`rpcb_rmtcallargs`, `rpcb_rmtcallres`) + client method | sec 2.2.1 |
| 6 | `RPCBPROC_GETTIME` | Done | sec 2.2.1 |
| 7 | `RPCBPROC_UADDR2TADDR` | Wire types (`netbuf`) + client method | sec 2.2.1 |
| 8 | `RPCBPROC_TADDR2UADDR` | Wire types (`netbuf`) + client method | sec 2.2.1 |

### rpcbind v4 (RFC 1833 sec 2.1, 2.2.2)

Inherits all v3 gaps, plus:

| Proc | Name | Gap | Section |
|------|------|-----|---------|
| 5 | `RPCBPROC_BCAST` | Same types as CALLIT + client method | sec 2.2.2 |
| 9 | `RPCBPROC_GETVERSADDR` | Client method only (reuses `Rpcb` + `XdrString`) | sec 2.2.2 |
| 10 | `RPCBPROC_INDIRECT` | Same types as CALLIT + client method | sec 2.2.2 |
| 11 | `RPCBPROC_GETADDRLIST` | Wire types (`rpcb_entry`, `rpcb_entry_list_ptr`) + client method | sec 2.2.2 |
| 12 | `RPCBPROC_GETSTAT` | Done | sec 2.2.2 |

### Missing XDR types

These RFC 1833 sec 2.1 types have no representation in the crate:

- `rpcblist_ptr` / `rp__list` — needed by DUMP (v3/v4 proc 4)
- `rpcb_rmtcallargs` — needed by CALLIT (v3 proc 5), BCAST (v4 proc 5), INDIRECT (v4 proc 10)
- `rpcb_rmtcallres` — needed by CALLIT, BCAST, INDIRECT
- `netbuf` — needed by UADDR2TADDR (proc 7) and TADDR2UADDR (proc 8)
- `rpcb_entry` / `rpcb_entry_list_ptr` — needed by GETADDRLIST (v4 proc 11)

Total: 5 new XDR types, 3 portmapper client methods, 10 rpcbind client methods. All mechanical RPC wiring with no tricky state.

---

## 7. `onc-rpc-client` — Complete (excluding RPCSEC_GSS)

### Low-effort gaps (days each)

| Gap | RFC Section | Notes |
|-----|------------|-------|
| Multi-fragment reply reassembly | RFC 5531 sec 11 | Loop in `recv_reply` to concatenate fragments until EOF bit set. Currently returns `FragmentedReply` error. |
| Multi-fragment send | RFC 5531 sec 11 | `send_call` always emits a single fragment with EOF=true. Needs splitting for messages exceeding 2^31 - 1 bytes. |
| AUTH_SHORT verifier caching | RFC 5531 Appendix A | Read reply verifier, cache opaque handle, substitute on subsequent calls. |
| Reply verifier validation | RFC 5531 sec 8.2 | Inspect `accepted_reply.verf` — trivial for AUTH_SYS (always AUTH_NONE), required for GSS. |
| Batched calls | RFC 5531 sec 8.4.1 | Fire-and-forget API that sends calls without awaiting replies. |
| UDP retransmission | RFC 5531 sec 5 | Retry loop around `call_rpc_udp` with backoff. Currently delegated to caller. |

### Medium-effort gaps

| Gap | RFC Section | Notes |
|-----|------------|-------|
| Broadcast RPC | RFC 5531 sec 8.4.2 | Multi-reply UDP listener on broadcast address. |
| AUTH_DH | RFC 5531 sec 8.2 | DH key exchange + timestamp encryption. Spec says deprecated (sec 14) — questionable value. |

### RPCSEC_GSS — the cliff (RFC 5531 sec 8.2 / RFC 2203)

This is the dominant cost. Everything above is days; GSS alone is 2+ months.

| Component | RFC 2203 Section | What's needed |
|-----------|-----------------|---------------|
| Context init handshake | sec 5.2.2–5.2.3 | `RPCSEC_GSS_INIT` + `CONTINUE_INIT` multi-leg exchange with `GSS_Init_sec_context()` |
| Window capture | sec 5.2.3.1 | Store `seq_window` from successful context creation |
| Init verifier validation | sec 5.2.3.1 | `GSS_GetMIC()` checksum of `seq_window` in reply verifier |
| Per-message integrity | sec 5.3.2.2 | `GSS_GetMIC()` over header + `rpc_gss_integ_data` wrapping of args |
| Per-message privacy | sec 5.3.2.3 | `GSS_Wrap()` with `conf_req_flag=TRUE` encrypting `rpc_gss_data_t` |
| Sequence window tracking | sec 5.3.1, 5.3.3.1 | Per-context `seq_num` counter, increment even on retries with same XID |
| No-data-integrity mode | sec 5.3.2.1 | `rpc_gss_svc_none` — header integrity only, data in the clear |
| Context destruction | sec 5.4 | `RPCSEC_GSS_DESTROY` control message with valid seq_num + header checksum |
| Error recovery | sec 5.3.3.3 | `CREDPROBLEM`/`CTXPROBLEM` → destroy old context, re-establish, retry |
| Sequence exhaustion | sec 5.3.3.3, sec 5 | When `seq_num` reaches `MAXSEQ` (0x80000000), refresh context |

Pulls in the entire GSS-API/Kerberos stack as a dependency.

---

## 8. `nfs-v4` — Very high (3–6 months)

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

All are representable via `Nfs4Status::Unknown(u32)` — no wire values are lost. They lack named variants for pattern matching.

### Absent stateful infrastructure — the real cost

| Component | RFC 7530 Sections | What's needed |
|-----------|-------------------|---------------|
| Client ID lifecycle | S9.1.1, S16.33, S16.34 | SETCLIENTID → SETCLIENTID_CONFIRM state machine, clientid storage, verifier management |
| Stateid tracking | S9.1.4, S2.2.11 | Open/lock/delegation stateid storage, seqid advancement. Currently all reads use anonymous stateid (all-zeros, S9.1.4.3). |
| Open-owner sequencing | S9.1.3, S9.1.11 | Per-owner seqid counter (`encode_open_read` hardcodes seqid=1), OPEN_CONFIRM on first use of each open-owner |
| Lock-owner management | S9.1.5, S2.2.14–15 | `lock_owner4` struct, `open_to_lock_owner4` transition to create lock-owners under an open |
| Lease renewal | S9.5 | Background RENEW loop, implicit renewal tracking (any op with valid clientid/stateid renews all leases) |
| OPEN response parsing | S16.16 | Full `OPEN4res` decode: stateid, change_info4, rflags, attrset, open_delegation4 |
| SETCLIENTID response parsing | S16.33 | Extract `clientid4` + `setclientid_confirm` verifier from response |
| Delegation infrastructure | S10, S10.2, S10.4, S18.2 | Callback server for CB_RECALL, delegation stateid storage, CLAIM_PREVIOUS reclaim during grace period |
| Crash recovery | S9.6 | Grace period handling, NFS4ERR_GRACE/STALE_CLIENTID recovery loops |
| Share reservations | S9.9 | Per-open share_access/share_deny bookkeeping, OPEN_DOWNGRADE state tracking |

Adding the 24 `Nfs4Status` codes is a day. Typing the 10 opaque ops is a week. Fixing the 5 response decoders is another week. The stateful engine is 3–6 months of new architecture. And that's before NFSv4.1 sessions (RFC 8881).

---

## Conclusion

4 of 8 crates are already spec-complete. `onc-xdr` is a trivial PR. `onc-rpcbind` is a solid week of mechanical wiring. After that there's a cliff — `onc-rpc-client` is dominated by RPCSEC_GSS which pulls in the entire Kerberos stack, and `nfs-v4` stateful ops require building a state engine from scratch. Neither has a consumer that justifies the investment today. The roadmap items (RQUOTA, NFS_ACL, PCNFSD) deliver far more security value per hour than chasing full spec coverage on the bottom two.
