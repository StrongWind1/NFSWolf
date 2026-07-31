# nfs-v3

NFS version 3 ([RFC 1813]): all 22 procedures, the MOUNT v3 protocol it depends on, and domain types over the raw wire format.

## Layers

Pick one by what you are doing.

| Module | What it is |
|---|---|
| `wire` | XDR types transcribed verbatim from the RFC, keeping its spelling (`fattr3`, `nfsstat3`, `NFS3ERR_STALE`) |
| `Nfs3Client` | One method per procedure, wire types in and out |
| `mount` | The MOUNT v3 client (RFC 1813 appendix I) |
| `api` | Domain types: file handles, attributes, access bits |
| `Nfs3Error` | Protocol status codes, classified |

Reading a file wants `api`. Sending a deliberately malformed request to see how a server reacts wants `wire` and the raw client, which encodes whatever you hand it.

The crate carries no connection policy: no pooling, no retries, no timeouts, no pacing. It is generic over `onc_rpc_client::RpcTransport`, so a caller supplies whichever of those it wants. `DirectTransport` gives you a working client over one socket with none of it.

## Two protocol properties worth knowing

**File handles are bearer tokens.** A handle obtained under one credential keeps working under any other (RFC 1813 sec. 2.6) -- the server does not re-check how you got it. So handles can be reused across identity switches instead of re-resolving paths, and a handle that was constructed rather than looked up is just as valid to the server.

**`ACCESS` is advisory.** The server answers what it believes the caller may do and is not required to be right (RFC 1813 sec. 3.3.4). It may permit an operation there and refuse it for real, or the reverse. Confirm by attempting the operation.

## Pre-1.0

This crate is pre-1.0. The API may change between minor versions.

## Provenance

Derived from [Vaiz/nfs3](https://github.com/Vaiz/nfs3) (Unlicense / public domain). See [NOTICE](NOTICE).

[RFC 1813]: https://www.rfc-editor.org/rfc/rfc1813
