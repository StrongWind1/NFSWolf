# onc-xdr

XDR ([RFC 4506]) codec: the `Pack` and `Unpack` traits, the opaque and list types every ONC RPC protocol needs, and decoders hardened against untrusted length fields.

This is the foundation the NFSWolf protocol crates are built on. It knows nothing about NFS, RPC, or sockets -- only how to turn Rust values into XDR bytes and back.

## Encoding rules

- Integers are big-endian and always occupy a multiple of 4 bytes. A `u8`, a `bool`, and a `u32` all take 4 bytes on the wire.
- Variable-length data is length-prefixed by a 4-byte count, then zero-padded to the next 4-byte boundary.
- Fixed-length opaque data carries no length prefix. NFSv2's 32-byte file handle is 32 raw bytes; NFSv3's is a prefixed byte string.
- Discriminated unions lead with a 4-byte discriminant.

Most wire types get their implementations from `#[derive(XdrCodec)]`, re-exported here from [`onc-xdr-derive`](../onc-xdr-derive). Types whose encoding breaks the mechanical field-by-field rule implement the traits by hand.

## Decoding untrusted input

Every length and count on the wire is chosen by the peer, and a security tool talks to servers that may be actively hostile. A four-byte header claiming 4 GiB costs the sender nothing but would cost the receiver the allocation (CWE-789 / CWE-770).

The `util` module provides the hardened alternatives the protocol crates use instead of trusting a declared length:

| Instead of | Use |
|---|---|
| `Vec::with_capacity(len)` then `read_exact` | `read_bytes(input, len)` |
| `Vec::with_capacity(count)` for an array | `vec_with_capacity(count)` |

Both reserve at most `PREALLOC_CAP` (1 MiB) regardless of what was declared, and grow only as real bytes arrive. Honest inputs decode identically; only the speculative reservation is bounded.

## Pre-1.0

This crate is pre-1.0. The API may change between minor versions.

## Provenance

Derived from [Vaiz/nfs3](https://github.com/Vaiz/nfs3) (Unlicense / public domain). See [NOTICE](NOTICE).

[RFC 4506]: https://www.rfc-editor.org/rfc/rfc4506
