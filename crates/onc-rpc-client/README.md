<h1 align="center">onc-rpc-client</h1>

<p align="center">
  <strong>ONC RPC v2 (RFC 5531) client and a runtime-agnostic async transport layer.</strong>
</p>

<p align="center">
  <a href="https://github.com/StrongWind1/NFSWolf/actions/workflows/ci.yml"><img src="https://github.com/StrongWind1/NFSWolf/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://crates.io/crates/onc-rpc-client"><img src="https://img.shields.io/crates/v/onc-rpc-client.svg" alt="crates.io"></a>
  <a href="../../rust-toolchain.toml"><img src="https://img.shields.io/badge/edition-2024-informational" alt="Edition 2024"></a>
  <a href="../../Cargo.toml"><img src="https://img.shields.io/badge/msrv-1.95-informational" alt="MSRV 1.95"></a>
  <a href="../../LICENSE"><img src="https://img.shields.io/badge/License-Apache_2.0-blue.svg" alt="License: Apache 2.0"></a>
  <a href="https://docs.rs/onc-rpc-client"><img src="https://img.shields.io/docsrs/onc-rpc-client" alt="docs.rs"></a>
</p>

<p align="center">
  <a href="#usage">Usage</a> &bull;
  <a href="#api-reference">API reference</a> &bull;
  <a href="#protocol-coverage">Protocol coverage</a> &bull;
  <a href="#safety-and-hardening">Safety</a>
</p>

---

Part of the [NFSWolf](https://github.com/StrongWind1/NFSWolf) protocol stack.

Every NFS version rides on ONC RPC. A call names a (program, version, procedure) triple and carries a credential; the reply either accepts the call and returns results, or rejects it with a reason. This crate provides that machinery once, so a per-version protocol crate only has to describe its own wire types and procedure numbers. The portmapper and rpcbind clients have been extracted to [`onc-rpcbind`](../onc-rpcbind) -- they are a specific RPC service, not part of the RPC machinery itself.

## Usage

```rust
use onc_rpc_client::{DirectTransport, RpcTransport, AuthSys};

// Connect and wrap in a policy-free transport.
let stream = tokio::net::TcpStream::connect("server:2049").await?;
let transport = DirectTransport::new(stream);

// Issue a raw RPC call (program 100003 = NFS, version 3, proc 0 = NULL).
let result: onc_xdr::Void = transport.call(100_003, 3, 0, &onc_xdr::Void).await?;

// Switch identity mid-session for UID spraying.
let cred = AuthSys::new(1000, 1000, "scanner");
let auth = cred.to_opaque_auth(1);
let result: MyRes = transport.call_as(auth, 100_003, 3, 1, &args).await?;
```

## API reference

### Core types

| Type / Trait | Description |
|------|-------------|
| `RpcTransport` | Trait for issuing RPC calls -- the seam between protocol and policy |
| `DirectTransport<IO>` | Policy-free `RpcTransport` over a single connection |
| `RpcClient<IO>` | Low-level ONC RPC v2 client with public credential field |
| `AuthSys` | AUTH_SYS credential: UID, GID, group list, hostname |
| `AuthFlavor` | Enum classifying flavor numbers (None, Sys, Short, Dh, Gss, Tls, Unknown) |
| `RpcError` | Error type covering I/O, XDR, auth failures, and version mismatch |

### Wire types

| Type | Description |
|------|-------------|
| `opaque_auth` | Wire-level credential encoding |
| `auth_flavor` | Wire enum: `AUTH_NULL`, `AUTH_UNIX`, `AUTH_SHORT`, `AUTH_DES`, `RPCSEC_GSS` (6), `AUTH_TLS` (7, RFC 9289) |
| `auth_unix` | AUTH_SYS credential body (stamp, machinename, uid, gid, gids) |
| `rpc_msg` | Complete RPC message (call or reply) |
| `call_body` / `accepted_reply` | Call and reply bodies |
| `msg_type` / `reply_stat` / `accept_stat` | Message classification enums |
| `RPC_VERSION_2` | Constant `2` |
| `MAX_AUX_GIDS` | Maximum auxiliary group count (16, per RFC 5531 sec. 14) |

### Transport layer

| Type / Function | Description |
|------|-------------|
| `AsyncRead` / `AsyncWrite` | Runtime-agnostic async I/O traits |
| `Connector` | Trait for establishing TCP connections |
| `TokioIo<T>` | Adapter bridging tokio streams to `AsyncRead`/`AsyncWrite` |
| `TokioConnector` | `Connector` impl using `tokio::net::TcpStream` |
| `call_rpc_udp()` | Single-shot UDP RPC call (no record marking) |
| `probe_udp_rpc()` | UDP NULL probe returning `true` if the program responds |

## Protocol coverage

Implements the ONC RPC v2 call/reply message format ([RFC 5531]). Supports `AUTH_NONE`, `AUTH_SYS`, `AUTH_DH` (RFC 2695, behind the `auth-dh` Cargo feature), and `AUTH_SHORT` credential replay. The `auth_flavor` wire enum also includes `RPCSEC_GSS` (6) for Kerberos detection and `AUTH_TLS` (7, [RFC 9289]) for STARTTLS probing -- useful for security reconnaissance even though this crate does not implement the GSS or TLS handshakes. The `RpcTransport` trait enables `call_as()` for identity switching on a live connection without re-handshaking. `PROG_MISMATCH` errors preserve the server's supported version range (`low`/`high`) rather than discarding it -- this is a version-enumeration oracle.

The transport layer provides async I/O traits (`AsyncRead`/`AsyncWrite`), a tokio backend, TCP connection helpers, and UDP single-shot RPC calls.

## Safety and hardening

- Reply size is capped at 8 MiB per fragment to prevent allocation exhaustion from forged fragment headers.
- `RpcError::is_connection_reusable()` distinguishes errors that leave the transport in a usable state from those that corrupt the stream.
- AUTH_SYS group lists are truncated to the RFC 5531 sec. 14 limit of 16 entries.
- `call_as()` unconditionally restores the previous credential after a call, even on failure, so a shared connection is never left carrying a borrowed identity.

## Crate position

```
onc-xdr-derive
  +-- onc-xdr
       +-- onc-rpc-client  <-- this crate
            +-- onc-rpcbind
            +-- nfs-mount
            |    +-- nfs-v2
            |    +-- nfs-v3
            +-- nfs-v4
```

## Provenance

Derived from [Vaiz/nfs3](https://github.com/Vaiz/nfs3) (Unlicense / public domain). See [NOTICE](NOTICE).

## License

[Apache License 2.0](../../LICENSE)

[RFC 5531]: https://www.rfc-editor.org/rfc/rfc5531
[RFC 9289]: https://www.rfc-editor.org/rfc/rfc9289
