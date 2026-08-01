# nfs-v2

NFS version 2 ([RFC 1094]): all 18 procedures, fixed 32-byte file handles, and a domain-level client that operates directly on handles, names, and attributes.

NFSv2 is long obsolete and still enabled on plenty of servers, which is exactly why it matters. It is the weakest of the three versions by a wide margin: no security negotiation at all ([RFC 2623] sec. 2.7), no `ACCESS` procedure for advisory permission checks, and fixed 32-byte file handles with no length prefix. Some servers apply `root_squash` on their v3 path but not their v2 path, so where both are offered v2 is worth probing first. Generic over `onc_rpc_client::RpcTransport`, so it carries no connection policy of its own.

## Quick start

```rust
use nfs_v2::{Nfs2Client, MountV1Client};
use nfs_mount::MountVersion;
use onc_rpc_client::DirectTransport;

let stream = tokio::net::TcpStream::connect("server:mount_port").await?;
let mount = MountV1Client::new(DirectTransport::new(stream), MountVersion::V1);
let handle = mount.mnt(onc_xdr::Opaque::borrowed(b"/export")).await?;

let stream = tokio::net::TcpStream::connect("server:nfs_port").await?;
let nfs = Nfs2Client::new(DirectTransport::new(stream));
let (fh, attrs) = nfs.lookup(&handle.bytes.try_into().unwrap(), "etc").await?;
let data = nfs.read_file(&fh).await?;
```

## API overview

| Type | Description |
|------|-------------|
| `Nfs2Client<T>` | Domain-level client: 18 procedures + `lookup_path()`, `read_file()` |
| `Nfs2RawClient<T>` | Wire-level client: raw XDR types in and out, no status checking |
| `Nfs2Error<E>` | Error type with `is_permission_denied()`, `is_stale()`, `is_not_found()` |
| `Nfs2FileHandle` | Fixed 32-byte file handle (`[u8; 32]`) |
| `Nfs2FileAttr` | File attributes (type, mode, size, uid, gid, timestamps) |
| `Nfs2SetAttr` | Attribute values for SETATTR |
| `Nfs2Stat` | NFSv2 status codes |
| `MountV1Client<T>` | Re-export of `nfs_mount::MountClient` configured for MOUNT v1 |

## Protocol coverage

All 18 NFSv2 procedures (RFC 1094 sec. 2.2): `NULL`, `GETATTR`, `SETATTR`, `ROOT` (obsolete probe), `LOOKUP`, `READLINK`, `READ`, `WRITECACHE` (no-op), `WRITE`, `CREATE`, `REMOVE`, `RENAME`, `LINK`, `SYMLINK`, `MKDIR`, `RMDIR`, `READDIR`, `STATFS`. Both the domain client (`Nfs2Client`) and the raw client (`Nfs2RawClient`) expose all 18.

The domain client adds `lookup_path()` for multi-component path resolution and `read_file()` for reading an entire file with automatic chunking.

## Safety and hardening

- `Nfs2Error::is_permission_denied()` identifies expected denials during identity probing, preventing false alarms.
- `Nfs2Error::is_stale()` detects stale handles that need re-lookup.
- The `ROOT` procedure (proc 3) probes for non-compliant servers that leak handles without MOUNT -- a known bypass on certain embedded NFS implementations.

## Pre-1.0

This crate is pre-1.0. The API may change between minor versions.

## Provenance

Derived from [Vaiz/nfs3](https://github.com/Vaiz/nfs3) (Unlicense / public domain). See [NOTICE](NOTICE).

## License

Apache-2.0

[RFC 1094]: https://www.rfc-editor.org/rfc/rfc1094
[RFC 2623]: https://www.rfc-editor.org/rfc/rfc2623
