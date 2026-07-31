# onc-rpc-client

ONC RPC version 2 ([RFC 5531]) client and a runtime-agnostic async transport layer.

Every NFS version rides on ONC RPC. A call names a (program, version, procedure) triple and carries a credential; the reply either accepts the call and returns results, or rejects it with a reason. This crate provides that machinery once, so a per-version protocol crate only has to describe its own wire types and procedure numbers.

```rust,ignore
let mut rpc = RpcClient::new(io);
// Any program, any version, any procedure.
let res: MyResult = rpc.call(100_003, 3, 1, &my_args).await?;
```

## What a security tool needs that a filesystem client does not

Two behaviours differ from a conventional RPC client, deliberately.

**AUTH_SYS is unauthenticated, and this crate leans into that.** The credential is a plain struct asserting a UID, GID, and group list (RFC 5531 sec. 14). Nothing signs it, and nothing verifies it. `RpcClient` therefore exposes its credential for replacement on an established connection, so a single TCP session can issue calls under many identities without re-handshaking.

**`PROG_MISMATCH` preserves the server's version range.** A server rejecting a call reports the lowest and highest versions it does support. That is a free version-enumeration oracle, so `RpcError::ProgMismatch` carries `{ low, high }` rather than collapsing into an opaque error.

## Layout

| Module | Contents |
|---|---|
| `rpc` | RPC v2 message types and the generic `RpcClient` |
| `auth` | AUTH_SYS / AUTH_UNIX credential encoding (RFC 5531 sec. 14) |
| `transport` | `RpcTransport` trait, `DirectTransport`, `Connector`, tokio backend |

The transport traits are minimal and runtime-agnostic on purpose: the clients need only "fill this buffer" and "drain this buffer", so a caller can supply a plain TCP stream, a proxied stream, or a test double without the client knowing the difference. Only a tokio backend ships here.

## Pre-1.0

This crate is pre-1.0. The API may change between minor versions.

## Provenance

Derived from [Vaiz/nfs3](https://github.com/Vaiz/nfs3) (Unlicense / public domain). See [NOTICE](NOTICE).

[RFC 5531]: https://www.rfc-editor.org/rfc/rfc5531
