# nfs-v4

NFS version 4.0 ([RFC 7530]): COMPOUND encoding and the stateless read-only operation subset.

NFSv4 is a different shape from v2 and v3. Rather than one RPC per operation, the client batches operations into a single `COMPOUND` call that the server executes in order against a "current file handle" the operations mutate as they go, so `PUTROOTFH; LOOKUP "etc"; GETFH` is one round trip. MOUNT is gone: the server exports a single pseudo-filesystem tree reached from `PUTROOTFH`.

Even against a server that primarily serves NFSv3, the v4 endpoint is often live on the same port and answers questions v3 cannot. `SECINFO` reports the authentication flavors a directory actually accepts, per-directory rather than per-export. The pseudo-filesystem exposes export boundaries through fsid changes. And `READDIR` still works when the v3 endpoint is filtered.

## Scope

Implemented: the stateless read-only subset -- walking the pseudo-filesystem, reading attributes, listing directories, querying security flavors, reading file data.

Not implemented: the stateful half -- `OPEN`, `CLOSE`, `LOCK`, delegations, and the v4.1 session machinery of [RFC 8881]. Those require clientid and stateid tracking, `OPEN_CONFIRM`, and lease renewal, which is a substantially larger piece of work than the operations here.

## Pre-1.0

This crate is pre-1.0. The API may change between minor versions.

[RFC 7530]: https://www.rfc-editor.org/rfc/rfc7530
[RFC 8881]: https://www.rfc-editor.org/rfc/rfc8881
