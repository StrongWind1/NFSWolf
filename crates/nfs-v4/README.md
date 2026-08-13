<h1 align="center">nfs-v4</h1>

<p align="center">
  <strong>NFS version 4 (RFC 7530 / 8881 / 7862): complete v4.0 implementation with all 37 ops, stateful client, domain types, and v4.1/v4.2 recon extensions.</strong>
</p>

<p align="center">
  <a href="https://github.com/StrongWind1/NFSWolf/actions/workflows/ci.yml"><img src="https://github.com/StrongWind1/NFSWolf/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://crates.io/crates/nfs-v4"><img src="https://img.shields.io/crates/v/nfs-v4.svg" alt="crates.io"></a>
  <a href="../../rust-toolchain.toml"><img src="https://img.shields.io/badge/edition-2024-informational" alt="Edition 2024"></a>
  <a href="../../Cargo.toml"><img src="https://img.shields.io/badge/msrv-1.95-informational" alt="MSRV 1.95"></a>
  <a href="../../LICENSE"><img src="https://img.shields.io/badge/License-Apache_2.0-blue.svg" alt="License: Apache 2.0"></a>
  <a href="https://docs.rs/nfs-v4"><img src="https://img.shields.io/docsrs/nfs-v4" alt="docs.rs"></a>
</p>

<p align="center">
  <a href="#usage">Usage</a> &bull;
  <a href="#api-reference">API reference</a> &bull;
  <a href="#protocol-coverage">Protocol coverage</a> &bull;
  <a href="#safety-and-hardening">Safety</a>
</p>

---

Part of the [NFSWolf](https://github.com/StrongWind1/NFSWolf) protocol stack.

NFSv4 is a different shape from v2 and v3. Rather than one RPC per operation, the client batches operations into a single `COMPOUND` call that the server executes in order against a "current file handle" the operations mutate as they go, so `PUTROOTFH; LOOKUP "etc"; GETFH` is one round trip. MOUNT is gone -- the server exports a single pseudo-filesystem tree reached from `PUTROOTFH`. This crate provides a complete NFSv4.0 implementation: all 37 operation codes are typed and serializable, the `Nfs4Client` exposes 45 public methods covering stateless reads, stateful OPEN/CLOSE/LOCK workflows, session management, crash recovery, and delegation return. Domain types (`Nfs4FileInfo`, `Nfs4DirEntry`, `Nfs4FileType`) provide ergonomic access to file attributes and directory listings. Generic over `onc_rpc_client::RpcTransport`, so it carries no connection policy of its own. 244 tests.

## Usage

```rust
use nfs_v4::{Nfs4Client, CompoundBuilder, ArgOp, AttrRequest, ResOpData};
use onc_rpc_client::DirectTransport;

let stream = tokio::net::TcpStream::connect("server:2049").await?;
let nfs = Nfs4Client::new(DirectTransport::new(stream));

// Walk to /etc and get its file handle in one round trip.
let fh = nfs.lookup_fh(&["etc"]).await?;

// List directory entries with full attributes.
let entries = nfs.readdir_plus(&fh).await?;
for e in &entries {
    println!("{} {:o} uid={}", e.name, e.info.mode, e.info.uid);
}

// Read a file chunk using the anonymous stateid.
let (data, eof) = nfs.read_chunk(&file_fh, 0, 65536).await?;

// Stateful workflow: establish session, open/read/close.
let session = nfs.establish("my-client", "0.0.0.0").await?;
let (open, info) = nfs.open_read(&session, &dir_fh, "passwd").await?;
let (data, eof) = nfs.read_via_open(&open, 0, 65536).await?;
nfs.close_file(&session, &open).await?;
```

## API reference

### Client and session types

| Type | Description |
|------|-------------|
| `Nfs4Client<T>` | Full NFSv4.0 client: 45 public methods covering stateless reads, stateful OPEN/CLOSE/LOCK, session management, crash recovery, and delegation return |
| `Nfs4Error<E>` | Error type with `is_transient()`, `is_permission_denied()`, `is_stale()`, `is_grace()`, `is_stale_clientid()`, `is_expired()` classification predicates |
| `Nfs4Session` | Client session state: clientid, confirm verifier, open owner, seqid tracking, lease time, renewal detection |
| `OpenState` | State from a successful OPEN: stateid + file handle |
| `LockState` | State from a successful LOCK: lock stateid + lock owner + range |

### COMPOUND builder and wire types

| Type | Description |
|------|-------------|
| `CompoundBuilder` | Chainable builder with a method for every NFSv4.0 operation: `putrootfh()`, `putpubfh()`, `putfh()`, `lookup()`, `lookupp()`, `getfh()`, `getattr()`, `readdir()`, `readlink()`, `read()`, `write()`, `create()`, `remove()`, `rename()`, `link()`, `open()`, `open_confirm()`, `open_downgrade()`, `close()`, `lock()`, `lockt()`, `locku()`, `release_lockowner()`, `delegpurge()`, `delegreturn()`, `setattr()`, `commit()`, `access()`, `nverify()`, `verify()`, `savefh()`, `restorefh()`, `openattr()`, `secinfo()`, `setclientid()`, `setclientid_confirm()`, `renew()`, `illegal()`, plus v4.1/v4.2 extensions |
| `CompoundArgs` / `CompoundRes` | Wire-level COMPOUND request and response |
| `ArgOp` | Enum of all 37 NFSv4.0 operations (ops 3-39) plus ILLEGAL (10044) |
| `ResOp` / `ResOpData` | Result operation with typed payloads for every operation |
| `Nfs4Status` | Status codes with `Display` impl |

### Domain types

| Type | Description |
|------|-------------|
| `Nfs4FileInfo` | Domain-level file attributes (type, mode, size, uid, gid, times, nlink) |
| `Nfs4DirEntry` | Directory entry with name and `Nfs4FileInfo` |
| `Nfs4FileType` | File type enum (Regular, Directory, Symlink, BlockDev, CharDev, Fifo, Socket) |
| `ChangeInfo4` | Change info (before/after change IDs, atomicity flag) |

### Attribute, state, and security types

| Type | Description |
|------|-------------|
| `AttrRequest` | Bitmask for requesting specific file attributes |
| `Fattr4` / `Fattr4Decoded` | Wire-level and decoded file attributes |
| `Stateid4` | State ID for OPEN/LOCK/READ/WRITE operations |
| `OpenOwner4` / `LockOwner4` | Owner identifiers for open and lock state |
| `DirEntry4` | Wire-level directory entry (name, cookie, optional attributes) |
| `NfsImplId4` | Server implementation ID (NFSv4.1+) |
| `SecInfoEntry` | SECINFO response entry (flavor, OID, QOP, service, context) |
| `SecLabel4` | Security label (LFS + PI + label bytes, [RFC 7862] S12.2.4) |
| `FATTR4_SEC_LABEL` | Attribute number 80 for requesting security labels |
| `LockType4` / `StableHow4` / `CreateMode4` | Protocol enums for lock, write stability, and create modes |
| `OpenDelegation4` / `OpenDelegationType4` | Delegation types for crash recovery |

### Constants

| Constant | Description |
|------|-------------|
| `PROGRAM` | NFS program number (100003) |
| `VERSION` | NFSv4 version (4) |
| `NFS4_PROC_COMPOUND` | COMPOUND procedure number (1) |

## Protocol coverage

**All 37 NFSv4.0 operations** (ops 3-39, [RFC 7530] sec. 16) are fully typed in `ArgOp` and `CompoundBuilder`, with typed response decoders in `ResOpData`. The complete list: ACCESS, CLOSE, COMMIT, CREATE, DELEGPURGE, DELEGRETURN, GETATTR, GETFH, LINK, LOCK, LOCKT, LOCKU, LOOKUP, LOOKUPP, NVERIFY, OPEN, OPENATTR, OPEN_CONFIRM, OPEN_DOWNGRADE, PUTFH, PUTPUBFH, PUTROOTFH, READ, READDIR, READLINK, REMOVE, RENAME, RENEW, RESTOREFH, SAVEFH, SECINFO, SETATTR, SETCLIENTID, SETCLIENTID_CONFIRM, VERIFY, WRITE, RELEASE_LOCKOWNER, plus ILLEGAL (10044).

**Stateful infrastructure:** `Nfs4Session` tracks clientid, confirm verifier, open owner, and seqid state. `OpenState` and `LockState` track per-file open and lock stateids. The client provides `establish()` / `re_establish()` for session setup and crash recovery, `renew()` for lease maintenance, `open_read()` / `open_write()` / `open_rw()` for stateful file access, `lock()` / `unlock()` / `test_lock()` for byte-range locking, `close_file()` for releasing open state, `delegreturn()` for returning delegations, and `reclaim_open()` for grace-period recovery.

**High-level convenience methods:** `lookup_fh()`, `lookup()`, `getattr()`, `readdir_plus()`, `read_file()`, `write_file()`, `mkdir()`, `remove()`, `rename()`, `link()`, `symlink()`, `readlink()`, `access()`, `secinfo()`, `commit()`, `setattr()`.

**NFSv4.1/4.2 extensions:** SECINFO_NO_NAME (op 52, [RFC 5661]), EXCHANGE_ID (op 42, [RFC 5661]), GETDEVICEINFO (op 47, [RFC 5661] S18.40), and GETDEVICELIST (op 48, [RFC 5661] S18.41) are supported for probing server capabilities and pNFS device enumeration. `AttrRequest` supports `FATTR4_SEC_LABEL` (attribute 80, [RFC 7862] S12.2.4) for requesting security labels, with the `SecLabel4` type for decoding the response.

**Not implemented:** the v4.1 session machinery of [RFC 8881] (CREATE_SESSION, SEQUENCE, BIND_CONN_TO_SESSION).

## Safety and hardening

- `list_dir()` and `readdir_plus()` cap accumulated entries at 1 million and detect non-advancing cookies to prevent infinite loops against hostile servers.
- `read_chunk()` uses the anonymous stateid ([RFC 7530] sec. 9.1.4.3), avoiding the OPEN/CLOSE state machine for read-only access.
- `Nfs4Error` provides classification predicates for automated decision-making: `is_transient()` for circuit breaker integration, `is_permission_denied()` for expected denials during credential probing, `is_stale()` and `is_stale_clientid()` for handle and session recovery, `is_grace()` for grace-period awareness, `is_expired()` for lease expiration detection.
- `Nfs4Session::needs_renewal()` checks whether the lease is approaching expiry, enabling proactive `RENEW` calls.
- `re_establish()` handles crash recovery by performing a fresh SETCLIENTID/SETCLIENTID_CONFIRM cycle with the same client name, allowing the server to merge state.

## Crate position

```
onc-xdr-derive
  +-- onc-xdr
       +-- onc-rpc-client
            +-- onc-rpcbind
            +-- nfs-mount
            |    +-- nfs-v2
            |    +-- nfs-v3
            +-- nfs-v4       <-- this crate
```

## Provenance

Original NFSWolf work (Apache-2.0). Implements NFSv4.0 directly from the RFC with no upstream-derived code. Builds on `onc-xdr`, which carries code from [Vaiz/nfs3](https://github.com/Vaiz/nfs3); see its NOTICE file.

## License

[Apache License 2.0](../../LICENSE)

[RFC 7530]: https://www.rfc-editor.org/rfc/rfc7530
[RFC 5661]: https://www.rfc-editor.org/rfc/rfc5661
[RFC 7862]: https://www.rfc-editor.org/rfc/rfc7862
[RFC 8881]: https://www.rfc-editor.org/rfc/rfc8881
