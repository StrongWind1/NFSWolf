<h1 align="center">nfs-mount</h1>

<p align="center">
  <strong>MOUNT protocol (RFC 1094 Appendix A / RFC 1813 Appendix I): versions 1 and 3, wire types, and a unified MountClient.</strong>
</p>

<p align="center">
  <a href="https://github.com/StrongWind1/NFSWolf/actions/workflows/ci.yml"><img src="https://github.com/StrongWind1/NFSWolf/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://crates.io/crates/nfs-mount"><img src="https://img.shields.io/crates/v/nfs-mount.svg" alt="crates.io"></a>
  <a href="../../rust-toolchain.toml"><img src="https://img.shields.io/badge/edition-2024-informational" alt="Edition 2024"></a>
  <a href="../../Cargo.toml"><img src="https://img.shields.io/badge/msrv-1.95-informational" alt="MSRV 1.95"></a>
  <a href="../../LICENSE"><img src="https://img.shields.io/badge/License-Apache_2.0-blue.svg" alt="License: Apache 2.0"></a>
  <a href="https://docs.rs/nfs-mount"><img src="https://img.shields.io/docsrs/nfs-mount" alt="docs.rs"></a>
</p>

<p align="center">
  <a href="#usage">Usage</a> &bull;
  <a href="#api-reference">API reference</a> &bull;
  <a href="#protocol-coverage">Protocol coverage</a> &bull;
  <a href="#safety-and-hardening">Safety</a>
</p>

---

Part of the [NFSWolf](https://github.com/StrongWind1/NFSWolf) protocol stack.

MOUNT is the sideband service that turns a directory path into the root file handle every NFS operation starts from. MOUNT v1 (NFSv2-era) returns a bare 32-byte handle. MOUNT v3 (NFSv3-era) returns a variable-length handle plus the list of authentication flavors the export accepts, which is the only way to learn whether Kerberos is required before trying an NFS operation. `MountClient` wraps both versions behind one type with version-specific and version-neutral methods. This crate depends only on `onc-xdr` and `onc-rpc-client`; the NFS version crates depend on it, not the reverse.

## Usage

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

## API reference

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
| `wire::PROGRAM` | MOUNT program number (100005) |
| `wire::MOUNT_V1` / `MOUNT_V3` | Version constants |
| `wire::FHSIZE2` / `FHSIZE3` | Maximum file handle sizes (32 / 64 bytes) |

## Protocol coverage

**MOUNT v1** ([RFC 1094] appendix A): `NULL`, `MNT`, `DUMP`, `UMNT`, `UMNTALL`, `EXPORT`. The client exposes `null()`, `v1_mnt()`, `export()`, `umnt()`.

**MOUNT v3** ([RFC 1813] appendix I): `NULL`, `MNT`, `DUMP`, `UMNT`, `UMNTALL`, `EXPORT`. The client exposes `null()`, `v3_mnt()`, `export()`, `umnt()`, `dump()`, `umntall()`.

The version-neutral `mnt()` method returns a `MountedHandle` regardless of which version is configured. MOUNT v1 errors (raw UNIX errno values) are mapped to `mountstat3` for uniform error handling.

## Safety and hardening

- `MountedHandle::accepts_auth_sys()` and `is_auth_sys_only()` let callers check whether an export requires Kerberos before attempting NFS operations.
- `MountError::is_denial()` distinguishes a server refusing the mount (a finding about the export's configuration) from a transport failure (not a finding).

## Crate position

```
onc-xdr-derive
  +-- onc-xdr
       +-- onc-rpc-client
            +-- onc-rpcbind
            +-- nfs-mount    <-- this crate
            |    +-- nfs-v2
            |    +-- nfs-v3
            +-- nfs-v4
```

## License

[Apache License 2.0](../../LICENSE)

[RFC 1094]: https://www.rfc-editor.org/rfc/rfc1094
[RFC 1813]: https://www.rfc-editor.org/rfc/rfc1813
