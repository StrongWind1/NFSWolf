# nfs-mount

MOUNT protocol client for versions 1 ([RFC 1094] appendix A) and 3 ([RFC 1813] appendix I) -- the sideband service that turns a directory path into the root file handle every NFS operation starts from.

MOUNT v1 (NFSv2-era) returns a bare 32-byte handle. MOUNT v3 (NFSv3-era) returns a variable-length handle plus the list of authentication flavors the export accepts, which is the only way to learn whether Kerberos is required before trying an NFS operation. `MountClient` wraps both versions behind one type with version-specific and version-neutral methods. This crate depends only on `onc-xdr` and `onc-rpc-client`; the NFS version crates depend on it, not the reverse.

## Quick start

```rust
use nfs_mount::{MountClient, MountVersion, MountedHandle};
use nfs_mount::wire::dirpath;
use onc_rpc_client::DirectTransport;
use onc_xdr::Opaque;

let stream = tokio::net::TcpStream::connect("server:mountport").await?;
let transport = DirectTransport::new(stream);
let mount = MountClient::v3(transport);

// Get the root handle and auth flavors for an export.
let handle: MountedHandle = mount.mnt(dirpath(Opaque::borrowed(b"/export"))).await?;
println!("handle: {} bytes, auth_sys: {}", handle.bytes.len(), handle.accepts_auth_sys());

// List all exports.
let exports = mount.export().await?;
```

## API overview

| Type | Description |
|------|-------------|
| `MountClient<T>` | Unified MOUNT client, generic over `RpcTransport` |
| `MountVersion` | Version selector: `V1` or `V3` |
| `MountedHandle` | File handle bytes + auth flavor list from a successful MNT |
| `MountError<E>` | Error type distinguishing RPC failures from protocol denials |
| `wire::dirpath` | XDR type for the export path argument |
| `wire::exports` | XDR type for the export list |
| `wire::mountres3` / `mountres3_ok` | Wire-level MNT v3 response types |
| `wire::FhStatus` | Wire-level MNT v1 response (status + 32-byte handle) |
| `wire::mountstat3` | MOUNT v3 status codes |

## Protocol coverage

**MOUNT v1** (RFC 1094 appendix A): `NULL`, `MNT`, `DUMP`, `UMNT`, `UMNTALL`, `EXPORT`. The client exposes `null()`, `v1_mnt()`, `export()`, `umnt()`.

**MOUNT v3** (RFC 1813 appendix I): `NULL`, `MNT`, `DUMP`, `UMNT`, `UMNTALL`, `EXPORT`. The client exposes `null()`, `v3_mnt()`, `export()`, `umnt()`, `dump()`, `umntall()`.

The version-neutral `mnt()` method returns a `MountedHandle` regardless of which version is configured. MOUNT v1 errors (raw UNIX errno values) are mapped to `mountstat3` for uniform error handling.

## Safety and hardening

- `MountedHandle::accepts_auth_sys()` and `is_auth_sys_only()` let callers check whether an export requires Kerberos before attempting NFS operations.
- `MountError::is_denial()` distinguishes a server refusing the mount (a finding about the export's configuration) from a transport failure (not a finding).

## Pre-1.0

This crate is pre-1.0. The API may change between minor versions.

## License

Apache-2.0

[RFC 1094]: https://www.rfc-editor.org/rfc/rfc1094
[RFC 1813]: https://www.rfc-editor.org/rfc/rfc1813
