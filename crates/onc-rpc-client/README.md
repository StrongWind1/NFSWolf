# onc-rpc-client

ONC RPC version 2 ([RFC 5531]) client with AUTH_SYS credentials and a runtime-agnostic async transport layer.

Every NFS version rides on ONC RPC. A call names a (program, version, procedure) triple and carries a credential; the reply either accepts the call and returns results, or rejects it with a reason. This crate provides that machinery once, so a per-version protocol crate only has to describe its own wire types and procedure numbers. The portmapper and rpcbind clients have been extracted to `onc-rpcbind` -- they are a specific RPC service, not part of the RPC machinery itself.

## Quick start

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

## API overview

| Type / Trait | Description |
|------|-------------|
| `RpcTransport` | Trait for issuing RPC calls -- the seam between protocol and policy |
| `DirectTransport<IO>` | Policy-free `RpcTransport` over a single connection |
| `RpcClient<IO>` | Low-level ONC RPC v2 client with public credential field |
| `AuthSys` | AUTH_SYS credential: UID, GID, group list, hostname |
| `AuthFlavor` | Enum classifying flavor numbers (None, Sys, Short, Dh, Gss, Unknown) |
| `auth_flavor` | Wire enum with `AUTH_NULL`, `AUTH_UNIX`, `AUTH_SHORT`, `AUTH_DES`, `RPCSEC_GSS` (6), `AUTH_TLS` (7, RFC 9289 STARTTLS probe) |
| `RpcError` | Error type covering I/O, XDR, auth failures, and version mismatch |
| `opaque_auth` | Wire-level credential encoding |

## Protocol coverage

Implements the ONC RPC v2 call/reply message format (RFC 5531). Supports `AUTH_NONE` and `AUTH_SYS` credentials. The `auth_flavor` wire enum also includes `RPCSEC_GSS` (6) for Kerberos detection and `AUTH_TLS` (7, RFC 9289) for STARTTLS probing -- useful for security reconnaissance even though this crate does not implement the GSS or TLS handshakes. The `RpcTransport` trait enables `call_as()` for identity switching on a live connection without re-handshaking. `PROG_MISMATCH` errors preserve the server's supported version range (`low`/`high`) rather than discarding it -- this is a version-enumeration oracle.

The transport layer provides async I/O traits (`AsyncRead`/`AsyncWrite`), a tokio backend, TCP connection helpers, and UDP single-shot RPC calls.

## Safety and hardening

- Reply size is capped at 8 MiB per fragment to prevent allocation exhaustion from forged fragment headers.
- `RpcError::is_connection_reusable()` distinguishes errors that leave the transport in a usable state from those that corrupt the stream.
- AUTH_SYS group lists are truncated to the RFC 5531 sec. 14 limit of 16 entries.
- `call_as()` unconditionally restores the previous credential after a call, even on failure, so a shared connection is never left carrying a borrowed identity.

## Pre-1.0

This crate is pre-1.0. The API may change between minor versions.

## Provenance

Derived from [Vaiz/nfs3](https://github.com/Vaiz/nfs3) (Unlicense / public domain). See [NOTICE](NOTICE).

## License

Apache-2.0

[RFC 5531]: https://www.rfc-editor.org/rfc/rfc5531
