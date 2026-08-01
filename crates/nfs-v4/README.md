# nfs-v4

NFS version 4.0 ([RFC 7530]): COMPOUND encoding, all 37 operation codes, a `CompoundBuilder` for chaining operations, and a client with convenience methods for filesystem traversal and file reads.

NFSv4 is a different shape from v2 and v3. Rather than one RPC per operation, the client batches operations into a single `COMPOUND` call that the server executes in order against a "current file handle" the operations mutate as they go, so `PUTROOTFH; LOOKUP "etc"; GETFH` is one round trip. MOUNT is gone -- the server exports a single pseudo-filesystem tree reached from `PUTROOTFH`. Generic over `onc_rpc_client::RpcTransport`, so it carries no connection policy of its own.

## Quick start

```rust
use nfs_v4::{Nfs4Client, CompoundBuilder, ArgOp, AttrRequest, ResOpData};
use onc_rpc_client::DirectTransport;

let stream = tokio::net::TcpStream::connect("server:2049").await?;
let nfs = Nfs4Client::new(DirectTransport::new(stream));

// Walk to /etc and get its file handle in one round trip.
let fh = nfs.lookup_fh(&["etc"]).await?;

// List directory entries.
let names = nfs.list_dir(&fh).await?;

// Read a file chunk using the anonymous stateid.
let (data, eof) = nfs.read_chunk(&file_fh, 0, 65536).await?;
```

## API overview

| Type | Description |
|------|-------------|
| `Nfs4Client<T>` | Client with `compound()`, `get_root_fh()`, `lookup_fh()`, `list_dir()`, `read_chunk()` |
| `Nfs4Error<E>` | Error type: `Rpc`, `Status`, `MissingResult` |
| `CompoundBuilder` | Chainable builder: `putrootfh()`, `lookup()`, `getfh()`, `getattr()`, `secinfo()`, etc. |
| `CompoundArgs` / `CompoundRes` | Wire-level COMPOUND request and response |
| `ArgOp` | Enum of all 37 NFSv4.0 operations (ops 3-39) plus ILLEGAL (10044) |
| `ResOp` / `ResOpData` | Result operation with typed payloads (Fh, Readdir, Read, Secinfo, Getattr, ...) |
| `AttrRequest` | Bitmask for requesting specific file attributes |
| `Nfs4Status` | Status codes with `Display` impl |
| `DirEntry4` | Directory entry (name, cookie, optional attributes) |
| `NfsImplId4` | Server implementation ID (NFSv4.1+) |

## Protocol coverage

**Implemented (stateless, read-only):** PUTROOTFH, PUTPUBFH, PUTFH, LOOKUP, LOOKUPP, GETFH, GETATTR, READDIR, READLINK, READ, SECINFO, SAVEFH, RESTOREFH, NVERIFY, VERIFY, ACCESS, SETCLIENTID, SETCLIENTID_CONFIRM, RENEW. All 37 v4.0 operation codes (ops 3-39, RFC 7530 sec. 16) are representable in `ArgOp` -- operations without typed fields carry opaque payloads so every valid op code can be serialised and round-tripped.

**NFSv4.1/4.2 extensions:** SECINFO_NO_NAME (op 52, RFC 5661) and EXCHANGE_ID (op 42, RFC 5661) are supported for probing server capabilities.

**Not implemented:** the stateful half -- `OPEN`, `CLOSE`, `LOCK`, delegations, and the v4.1 session machinery of [RFC 8881]. Those require clientid and stateid tracking, `OPEN_CONFIRM`, and lease renewal.

## Safety and hardening

- `list_dir()` caps accumulated entries at 1 million and detects non-advancing cookies to prevent infinite loops against hostile servers.
- `read_chunk()` uses the anonymous stateid (RFC 7530 sec. 9.1.4.3), avoiding the OPEN/CLOSE state machine for read-only access.
- `Nfs4Error::Status` preserves the NFSv4 status code for automated classification. Permission denials are expected during credential probing and must not trip circuit breakers.

## Pre-1.0

This crate is pre-1.0. The API may change between minor versions.

## Provenance

Derived from [Vaiz/nfs3](https://github.com/Vaiz/nfs3) (Unlicense / public domain). See [NOTICE](NOTICE).

## License

Apache-2.0

[RFC 7530]: https://www.rfc-editor.org/rfc/rfc7530
[RFC 5661]: https://www.rfc-editor.org/rfc/rfc5661
[RFC 8881]: https://www.rfc-editor.org/rfc/rfc8881
