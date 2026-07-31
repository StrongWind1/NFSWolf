# nfs-mount

MOUNT protocol ([RFC 1094] appendix A / [RFC 1813] appendix I): versions 1 and 3, wire types, and a unified `MountClient`.

The MOUNT protocol is how NFS clients obtain the root file handle for an export before issuing any NFS operations. MOUNT v1 (NFSv2-era) returns a bare 32-byte handle. MOUNT v3 (NFSv3-era) returns a variable-length handle plus the list of authentication flavors the export accepts, which is the only way to learn whether Kerberos is required before trying. `MountClient` wraps both versions behind one type with version-specific and version-neutral methods.

Generic over `onc_rpc_client::RpcTransport`, so it carries no connection policy of its own.

## Pre-1.0

This crate is pre-1.0. The API may change between minor versions.

[RFC 1094]: https://www.rfc-editor.org/rfc/rfc1094
[RFC 1813]: https://www.rfc-editor.org/rfc/rfc1813
