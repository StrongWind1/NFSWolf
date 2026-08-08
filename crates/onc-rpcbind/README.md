<h1 align="center">onc-rpcbind</h1>

<p align="center">
  <strong>Portmapper v2 (RFC 1057) and rpcbind v3/v4 (RFC 1833) clients for ONC RPC service discovery.</strong>
</p>

<p align="center">
  <a href="https://github.com/StrongWind1/NFSWolf/actions/workflows/ci.yml"><img src="https://github.com/StrongWind1/NFSWolf/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://crates.io/crates/onc-rpcbind"><img src="https://img.shields.io/crates/v/onc-rpcbind.svg" alt="crates.io"></a>
  <a href="../../rust-toolchain.toml"><img src="https://img.shields.io/badge/edition-2024-informational" alt="Edition 2024"></a>
  <a href="../../Cargo.toml"><img src="https://img.shields.io/badge/msrv-1.95-informational" alt="MSRV 1.95"></a>
  <a href="../../LICENSE"><img src="https://img.shields.io/badge/License-Apache_2.0-blue.svg" alt="License: Apache 2.0"></a>
  <a href="https://docs.rs/onc-rpcbind"><img src="https://img.shields.io/docsrs/onc-rpcbind" alt="docs.rs"></a>
</p>

<p align="center">
  <a href="#usage">Usage</a> &bull;
  <a href="#api-reference">API reference</a> &bull;
  <a href="#protocol-coverage">Protocol coverage</a> &bull;
  <a href="#safety-and-hardening">Safety</a>
</p>

---

Part of the [NFSWolf](https://github.com/StrongWind1/NFSWolf) protocol stack.

The portmapper (program 100000, port 111) maps a (program, version, protocol) triple onto the TCP or UDP port serving it. `DUMP` returns the entire mapping table to any caller, making it the fastest way to enumerate what RPC services a host runs and on which ports. rpcbind extends the portmapper with `GETTIME` (server clock, v3) and `GETSTAT` (per-version operational statistics, v4). This crate also ships a well-known program number table covering 1251 IANA-registered RPC programs.

## Usage

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

## API reference

| Type / Function | Description |
|------|-------------|
| `PortmapperClient<IO>` | Portmapper v2 client: `null()`, `getport()`, `dump()` |
| `RpcbindClient<IO>` | rpcbind v3/v4 client: `getaddr()`, `gettime()`, `getstat()` |
| `PortmapError` | Error type for portmapper operations |
| `RpcbindStatEntry` | Per-version call statistics from `GETSTAT` |
| `program_name(u32)` | Look up a human-readable name for an RPC program number |
| `known_programs()` | The full table of 1251 well-known program numbers |
| `security_note(u32)` | Return a security-relevant note for a sideband RPC program number |
| `mapping` | XDR type for a portmapper registration entry |
| `pmaplist` | Type alias for `List<mapping>` |
| `call_args` / `call_result` | Wire types for the CALLIT proxy procedure |
| `IPPROTO_TCP` / `IPPROTO_UDP` | Protocol constants for `getport()` |
| `PMAP_PORT` | Well-known portmapper port (111) |
| `PROGRAM` / `VERSION` | Portmapper program number (100000) and version (2) |

## Protocol coverage

**Portmapper v2** ([RFC 1057] appendix A, 6 procedures): `NULL`, `SET`, `UNSET`, `GETPORT`, `DUMP`, `CALLIT`. The client implements `NULL`, `GETPORT`, and `DUMP` -- the query procedures a scanner needs.

**rpcbind v3** ([RFC 1833]): `GETADDR` (universal address lookup) and `GETTIME` (server clock in epoch seconds).

**rpcbind v4** ([RFC 1833] sec. 2.2.2): `GETSTAT` returns per-version call counts, SET/UNSET totals, and address/rmtcall statistics for versions 2, 3, and 4.

The program number table covers portmapper, NFS, mountd, ypserv, ypbind, rquotad, nlockmgr, status (NSM), nfs_acl, pcnfsd, netapp_mgmt (400010), and other programs commonly found alongside NFS.

## Safety and hardening

- `PortmapError::is_connection_reusable()` distinguishes errors that leave the transport in a usable state from those that corrupt the stream.
- `security_note()` returns brief security-relevant notes for programs that have one (e.g., rquotad's unprotected per-user quota exposure), enabling automated flagging of high-risk sideband services.

## Crate position

```
onc-xdr-derive
  +-- onc-xdr
       +-- onc-rpc-client
            +-- onc-rpcbind  <-- this crate
            +-- nfs-mount
            |    +-- nfs-v2
            |    +-- nfs-v3
            +-- nfs-v4
```

## License

[Apache License 2.0](../../LICENSE)

[RFC 1057]: https://www.rfc-editor.org/rfc/rfc1057
[RFC 1833]: https://www.rfc-editor.org/rfc/rfc1833
