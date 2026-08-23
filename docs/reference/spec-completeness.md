# Spec completeness

Coverage of each in-tree protocol crate against its authoritative RFC. All crates are published on [crates.io](https://crates.io/crates/nfswolf).

## Coverage summary

| Crate | RFC | Spec Coverage | Procedures/Ops | Tests | Notes |
|-------|-----|--------------|----------------|-------|-------|
| `onc-xdr` | RFC 4506 | **Complete** | All XDR types | 57 | `Pack`, `Unpack`, `Opaque`, `List`, `BoundedList`, `Void`, padding, length-hardened readers |
| `onc-xdr-derive` | RFC 4506 | **Complete** | `#[derive(XdrCodec)]` | 7 | Generates `Pack`/`Unpack` for structs and enums |
| `onc-rpc-client` | RFC 5531 | **Complete** | RPC v2 message types, AUTH_SYS, AUTH_DH | 85 | `RpcTransport` seam, `DirectTransport`, `AuthSys`, `AuthDhSession` (feature-gated), all 19 auth flavors, all 19 auth status codes |
| `onc-rpcbind` | RFC 1057 / RFC 1833 | **Complete** | Portmapper v2 (DUMP, GETPORT, SET, UNSET, NULL) + rpcbind v3/v4 (GETTIME, GETSTAT) | 18 | Full IANA RPC program numbers registry (1251 entries) |
| `nfs-mount` | RFC 1094 App A / RFC 1813 App I | **Complete** | v1: NULL, MNT, UMNT, DUMP, EXPORT; v3: NULL, MNT, UMNT, UMNTALL, DUMP, EXPORT | 14 | Shared by `nfs-v2` and `nfs-v3` |
| `nfs-v2` | RFC 1094 | **Complete** | All 18 procedures | 44 | Fixed 32-byte handles, domain API |
| `nfs-v3` | RFC 1813 | **Complete** | All 22 procedures | 50 | Domain types (`FileHandle`, `FileAttrs`, `FileType`, `DirEntryPlus`), `Nfs3Error` with classification predicates |
| `nfs-v4` | RFC 7530 | **Complete** | All 37 ops typed with response decoders | 244 | 66 named `Nfs4Status` codes, stateful infrastructure (SETCLIENTID, OPEN/CLOSE/LOCK), session lifecycle, 47 public client methods |

**Total: 519 tests across 8 crates.**

## Per-crate detail

### onc-xdr (RFC 4506)

All XDR data types from RFC 4506 are implemented:

- [x] Integer, Unsigned Integer, Hyper, Unsigned Hyper, Float, Double
- [x] Boolean, Enumeration
- [x] Fixed-length Opaque, Variable-length Opaque
- [x] String
- [x] Fixed-length Array, Variable-length Array
- [x] Structure, Discriminated Union
- [x] Void, Optional Data
- [x] Length-hardened readers (prevent over-allocation attacks)

### onc-rpc-client (RFC 5531)

- [x] RPC v2 message format (call + reply)
- [x] AUTH_NONE, AUTH_SYS (sec. 14), AUTH_SHORT
- [x] AUTH_DH / AUTH_DES (RFC 2695, behind `auth-dh` feature)
- [x] All 19 IANA-registered auth flavors
- [x] All 19 IANA-registered auth status codes
- [x] RPCSEC_GSS v3 status codes 15-18 (RFC 7861)
- [x] `RpcTransport` trait (the policy seam)
- [x] `DirectTransport` (zero-policy, one socket)
- [x] `Connector` for async TCP/IPv4/IPv6

### onc-rpcbind (RFC 1057 / RFC 1833)

- [x] Portmapper v2: NULL, SET, UNSET, GETPORT, DUMP
- [x] rpcbind v3: GETTIME
- [x] rpcbind v4: GETSTAT
- [x] Full IANA RPC program number registry (1251 entries)
- [ ] rpcbind v3: GETADDR, DUMP (not needed by nfswolf)
- [ ] CALLIT / INDIRECT (removed as out of scope)

### nfs-mount (RFC 1094 Appendix A / RFC 1813 Appendix I)

- [x] MOUNT v1: NULL, MNT, UMNT, DUMP, EXPORT
- [x] MOUNT v3: NULL, MNT, UMNT, UMNTALL, DUMP, EXPORT
- [x] Auth flavor extraction from MNT response
- [x] Export list with group parsing

### nfs-v2 (RFC 1094)

All 18 NFSv2 procedures implemented:

- [x] NULL, GETATTR, SETATTR, ROOT, LOOKUP, READLINK
- [x] READ, WRITECACHE, WRITE, CREATE, REMOVE, RENAME
- [x] LINK, SYMLINK, MKDIR, RMDIR, READDIR, STATFS

### nfs-v3 (RFC 1813)

All 22 NFSv3 procedures implemented:

- [x] NULL, GETATTR, SETATTR, LOOKUP, ACCESS, READLINK
- [x] READ, WRITE, CREATE, MKDIR, SYMLINK, MKNOD
- [x] REMOVE, RMDIR, RENAME, LINK, READDIR, READDIRPLUS
- [x] FSSTAT, FSINFO, PATHCONF, COMMIT

### nfs-v4 (RFC 7530)

All 37 NFSv4.0 operations implemented:

- [x] ACCESS, CLOSE, COMMIT, CREATE, DELEGPURGE, DELEGRETURN
- [x] GETATTR, GETFH, LINK, LOCK, LOCKT, LOCKU
- [x] LOOKUP, LOOKUPP, NVERIFY, OPEN, OPENATTR, OPEN_CONFIRM
- [x] OPEN_DOWNGRADE, PUTFH, PUTPUBFH, PUTROOTFH, READ, READDIR
- [x] READLINK, REMOVE, RENAME, RENEW, RESTOREFH, SAVEFH
- [x] SECINFO, SETATTR, SETCLIENTID, SETCLIENTID_CONFIRM, VERIFY, WRITE
- [x] RELEASE_LOCKOWNER, ILLEGAL

Stateful infrastructure:

- [x] SETCLIENTID lifecycle and lease renewal (`Nfs4Session`)
- [x] OPEN/CLOSE stateid tracking (`OpenState`)
- [x] LOCK/LOCKU/LOCKT state management (`LockState`)
- [x] Open-owner and lock-owner sequencing
- [x] Crash recovery primitives

!!! note "NFSv4.1 and v4.2"
    EXCHANGE_ID (op 42, v4.1) is wired for vendor/OS fingerprinting. Other v4.1/v4.2 operations are feature-gated for recon use only. Full v4.1 session support (SEQUENCE, CREATE_SESSION, DESTROY_SESSION) is not implemented.

## What is not covered

| Protocol | Status | Reason |
|----------|--------|--------|
| NLM (program 100021) | Removed in v0.2.0 | Lock-DoS attack module removed; F-6.x findings documented as out of scope |
| NSM (program 100024) | Removed in v0.2.0 | Paired with NLM removal |
| NFSv4.1 sessions | Not planned | SEQUENCE/CREATE_SESSION/DESTROY_SESSION; nfswolf targets v4.0 |
| RPCSEC_GSS wire format | Not implemented | Kerberos ticket encoding; nfswolf uses AUTH_SYS for offensive operations |
| rpcbind CALLIT | Not implemented | Indirect RPC calls; not needed for security testing |
