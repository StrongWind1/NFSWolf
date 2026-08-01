# onc-rpcbind

Portmapper v2 ([RFC 1057] appendix A) and rpcbind v3/v4 ([RFC 1833]) clients for ONC RPC service discovery, plus a well-known program number table.

The portmapper (program 100000, port 111) maps a (program, version, protocol) triple onto the TCP or UDP port serving it. `DUMP` returns the entire mapping table to any caller, making it the fastest way to enumerate what RPC services a host runs and on which ports. rpcbind extends the portmapper with `GETTIME` (server clock, v3) and `GETSTAT` (per-version operational statistics, v4). This crate depends on `onc-rpc-client` for the generic RPC client and transport layer.

## Quick start

```rust
use onc_rpcbind::{PortmapperClient, RpcbindClient, IPPROTO_TCP, program_name};

// Portmapper v2: find the NFS port and dump all registrations.
let stream = tokio::net::TcpStream::connect("server:111").await?;
let mut pm = PortmapperClient::new(stream);
let port = pm.getport(100_003, 3, IPPROTO_TCP).await?;
let mappings = pm.dump().await?;
for m in &mappings {
    let name = program_name(m.prog).unwrap_or("unknown");
    println!("{name} v{} on port {}", m.vers, m.port);
}
```

## API overview

| Type / Function | Description |
|------|-------------|
| `PortmapperClient<IO>` | Portmapper v2 client: `null()`, `getport()`, `dump()` |
| `RpcbindClient<IO>` | rpcbind v3/v4 client: `getaddr()`, `gettime()`, `getstat()` |
| `PortmapError` | Error type for portmapper operations |
| `RpcbindStatEntry` | Per-version call statistics from `GETSTAT` |
| `program_name(u32)` | Look up a human-readable name for an RPC program number |
| `known_programs()` | The full table of well-known program numbers |
| `mapping` | XDR type for a portmapper registration entry |
| `IPPROTO_TCP` / `IPPROTO_UDP` | Protocol constants for `getport()` |
| `PMAP_PORT` | Well-known portmapper port (111) |

## Protocol coverage

**Portmapper v2** (RFC 1057 appendix A, 6 procedures): `NULL`, `SET`, `UNSET`, `GETPORT`, `DUMP`, `CALLIT`. The client implements `NULL`, `GETPORT`, and `DUMP` -- the query procedures a scanner needs.

**rpcbind v3** (RFC 1833): `GETADDR` (universal address lookup) and `GETTIME` (server clock in epoch seconds).

**rpcbind v4** (RFC 1833 sec. 2.2.2): `GETSTAT` returns per-version call counts, SET/UNSET totals, and address/rmtcall statistics for versions 2, 3, and 4.

The program number table covers portmapper, NFS, mountd, ypserv, ypbind, rquotad, nlockmgr, status (NSM), nfs_acl, pcnfsd, and other programs commonly found alongside NFS.

## Pre-1.0

This crate is pre-1.0. The API may change between minor versions.

## License

Apache-2.0

[RFC 1057]: https://www.rfc-editor.org/rfc/rfc1057
[RFC 1833]: https://www.rfc-editor.org/rfc/rfc1833
