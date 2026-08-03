# nfs-v3

NFS version 3 ([RFC 1813]): all 22 procedures, domain types with hex-encoded file handles, and classified error codes with handle-oracle and permission-denial predicates.

This is a complete NFSv3 client split into two layers. The `wire` module provides the raw XDR types transcribed verbatim from the RFC. The `api` module provides ergonomic domain types -- file handles with hex encoding, structured attributes, access-bit constants, and directory-listing pages. `Nfs3Client` sits between them: one method per procedure, wire types in and out, no policy. Generic over `onc_rpc_client::RpcTransport`, so it carries no connection policy of its own.

## Quick start

```rust
use nfs_v3::{Nfs3Client, MountClient, FileHandle, Nfs3Error};
use nfs_mount::MountVersion;
use onc_rpc_client::DirectTransport;
use onc_xdr::Opaque;

let stream = tokio::net::TcpStream::connect("server:mount_port").await?;
let mount = MountClient::new(DirectTransport::new(stream), MountVersion::V3);
let mounted = mount.mnt(nfs_mount::wire::dirpath(Opaque::borrowed(b"/export"))).await?;

let stream = tokio::net::TcpStream::connect("server:nfs_port").await?;
let nfs = Nfs3Client::new(DirectTransport::new(stream));
let root = nfs_v3::wire::nfs_fh3(Opaque::owned(mounted.bytes));
let res = nfs.getattr(&nfs_v3::wire::GETATTR3args { object: root }).await?;
```

## API overview

| Type | Description |
|------|-------------|
| `Nfs3Client<T>` | Client with one method per NFSv3 procedure (22 total) |
| `MountClient<T>` | Re-export of `nfs_mount::MountClient` for backward compatibility |
| `FileHandle` | Opaque file handle with hex encode/decode and equality |
| `FileAttrs` | Domain-level file attributes (type, mode, size, uid, gid, times) |
| `FileType` | File type enum (regular, directory, symlink, block/char, fifo, socket) |
| `DirEntry` / `DirEntryPlus` | Directory listing entries (name + cookie, optionally with attrs/handle) |
| `DirPage` | A page of directory entries from READDIR/READDIRPLUS |
| `FsInfo` / `FsStat` | Filesystem info and space statistics |
| `Nfs3Error` | Classified status codes with oracle and permission predicates |
| `Nfs3Fault` | Structured fault type for domain-level operations |
| `access` module | Access-bit constants (`READ`, `LOOKUP`, `MODIFY`, `EXTEND`, `DELETE`, `EXECUTE`) |
| `wire::*` | Raw XDR types: `nfs_fh3`, `fattr3`, `nfsstat3`, all `*3args`/`*3res` |

## Protocol coverage

All 22 NFSv3 procedures (RFC 1813 sec. 3.3): `NULL`, `GETATTR`, `SETATTR`, `LOOKUP`, `ACCESS`, `READLINK`, `READ`, `WRITE`, `CREATE`, `MKDIR`, `SYMLINK`, `MKNOD`, `REMOVE`, `RMDIR`, `RENAME`, `LINK`, `READDIR`, `READDIRPLUS`, `FSSTAT`, `FSINFO`, `PATHCONF`, `COMMIT`.

The `MountClient` re-export provides MOUNT v3 (RFC 1813 appendix I) for obtaining the root file handle before NFS operations begin.

## Safety and hardening

Two protocol properties are load-bearing for security work:

**File handles are bearer tokens.** A handle obtained under one credential keeps working under any other (RFC 1813 sec. 2.6). The server does not re-check how you got it. Handles can be reused across identity switches, and a handle constructed rather than looked up is just as valid.

**`ACCESS` is advisory.** The server answers what it believes the caller may do and is not required to be right (RFC 1813 sec. 3.3.4). Confirm by attempting the actual operation.

`Nfs3Error` classifies every status code for automated decision-making:

| Predicate | Purpose |
|---|---|
| `is_transient()` | I/O, JUKEBOX, SERVERFAULT -- should trip a circuit breaker |
| `is_permission_denied()` | PERM, ACCES -- expected during identity probing, must not trip breaker |
| `is_handle_oracle_hit()` | STALE (70) -- right format, wrong inode/generation |
| `is_handle_oracle_miss()` | BADHANDLE (10001) -- wrong format entirely |

The STALE/BADHANDLE distinction (RFC 1813 sec. 2.6) enables targeted handle brute-force: STALE means the format is correct and only the inode or generation needs varying; BADHANDLE means the entire structure is wrong.

## Pre-1.0

This crate is pre-1.0. The API may change between minor versions.

## Provenance

Derived from [Vaiz/nfs3](https://github.com/Vaiz/nfs3) (Unlicense / public domain). See [NOTICE](NOTICE).

## License

Apache-2.0

[RFC 1813]: https://www.rfc-editor.org/rfc/rfc1813
