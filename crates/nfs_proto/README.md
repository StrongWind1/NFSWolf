# nfs_proto

Pure-Rust NFS wire protocol: XDR encoding, ONC RPC framing, and the NFSv2, NFSv3, NFSv4, MOUNT, and portmapper protocols. No C dependencies, no `libnfs`, no system NFS client.

This is the wire layer NFSWolf is built on. It deliberately holds no policy -- no connection pooling, no retries, no circuit breaking, no credential escalation. Those decisions live in the binary, because a security tool needs to make them differently from a filesystem client: a permission denial is an expected result to be recorded rather than an error to be retried, and a malformed reply is a finding rather than a fault.

## Layout

| Module | Protocol | Spec |
|--------|----------|------|
| `xdr` | External Data Representation | [RFC 4506] |
| `rpc` | ONC RPC version 2 | [RFC 5531] |
| `portmap` | Portmapper / RPCBIND v2 | [RFC 1057] app. A |
| `mount` | MOUNT version 3 | [RFC 1813] app. I |
| `nfs2` | NFS version 2 | [RFC 1094] |
| `nfs3` | NFS version 3 | [RFC 1813] |
| `nfs4` | NFS version 4.0 (read-only subset) | [RFC 7530] |
| `transport` | Async I/O traits and TCP connectors | -- |

Wire types are transcribed with the RFC's own identifiers -- `fattr3`, `nfsstat3`, `NFS3ERR_STALE` -- so a reader can check a definition against the spec without a translation step. The RFC section is the documentation; per-field prose would only restate the field name.

## Deliberate deviations

Two behaviours differ from a conventional NFS client, both because a security tool needs information a filesystem client discards:

- A `PROG_MISMATCH` rejection preserves the server's supported `(low, high)` version range instead of collapsing into an opaque error. That range is a free version-enumeration oracle.
- `rpc::RpcClient` allows its AUTH_SYS credential to be replaced on an established connection, so one TCP session can issue calls under many identities without re-handshaking.

## Scope

NFSv4 covers the read-only subset needed for reconnaissance: walking the pseudo-filesystem, reading attributes, listing directories, querying per-directory security flavors, and reading file data. The stateful half -- `OPEN`, `CLOSE`, `LOCK`, delegations, and the v4.1 session machinery of [RFC 8881] -- is not implemented.

There is no server implementation here. NFSWolf's integration tests use the published `nfs3_server` crate.

## Provenance

Derived from [Vaiz/nfs3](https://github.com/Vaiz/nfs3) (Unlicense / public domain), plus the NFSv2 and NFSv4 layers written for NFSWolf. See [NOTICE](NOTICE) for the file-level mapping.

[RFC 4506]: https://www.rfc-editor.org/rfc/rfc4506
[RFC 5531]: https://www.rfc-editor.org/rfc/rfc5531
[RFC 1057]: https://www.rfc-editor.org/rfc/rfc1057
[RFC 1094]: https://www.rfc-editor.org/rfc/rfc1094
[RFC 1813]: https://www.rfc-editor.org/rfc/rfc1813
[RFC 7530]: https://www.rfc-editor.org/rfc/rfc7530
[RFC 8881]: https://www.rfc-editor.org/rfc/rfc8881
