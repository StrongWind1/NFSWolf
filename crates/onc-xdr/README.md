# onc-xdr

XDR ([RFC 4506]) codec for ONC RPC protocols: the `Pack` and `Unpack` traits, variable-length opaque data, linked lists, and decoders hardened against untrusted length fields.

This is the foundation crate of the protocol stack. It knows nothing about NFS, RPC, or sockets -- only how to turn Rust values into XDR bytes and back. Every protocol crate in the workspace (`onc-rpc-client`, `nfs-v2`, `nfs-v3`, `nfs-v4`, `nfs-mount`, `onc-rpcbind`) depends on it.

## Quick start

```rust
use onc_xdr::{Pack, Unpack, Opaque, XdrCodec};

// Encode an opaque byte string.
let data = Opaque::borrowed(b"hello");
let mut buf = Vec::new();
data.pack(&mut buf).unwrap();

// Decode it back.
let (decoded, bytes_read) = Opaque::unpack(&mut buf.as_slice()).unwrap();
assert_eq!(decoded.as_ref(), b"hello");

// Derive works on your own types.
#[derive(XdrCodec)]
struct MyArgs {
    file_id: u32,
    name: Opaque<'static>,
}
```

## API overview

| Type / Trait | Description |
|------|-------------|
| `Pack` | Trait for encoding a value into XDR bytes |
| `Unpack` | Trait for decoding a value from XDR bytes |
| `XdrCodec` | Re-exported derive macro from `onc-xdr-derive` |
| `Opaque<'a>` | Variable-length opaque byte string (RFC 4506 sec. 4.10) |
| `List<T>` | Boolean-tagged linked list (RFC 4506 sec. 4.11) |
| `BoundedList<T>` | A `List` that refuses elements once its packed size exceeds a cap |
| `Void` | Zero-byte type for procedures that take or return nothing |
| `Error` | Decode/encode error: I/O, invalid enum, bad length, oversized object |
| `read_bytes()` | Length-hardened read that caps pre-allocation at `PREALLOC_CAP` |
| `vec_with_capacity()` | Bounded `Vec::with_capacity` for wire-declared element counts |
| `pack_string()` / `unpack_string()` | XDR string helpers with padding |
| `PREALLOC_CAP` | Maximum speculative allocation (1 MiB) |

## Protocol coverage

Implements the full XDR encoding specified in RFC 4506: integers (`u32`, `u64`, `i32`, `i64`, `bool`), opaque data (variable and fixed-length), strings, optional-data (linked lists), discriminated unions, and structs. Primitive `Pack`/`Unpack` implementations cover `u8` through `u64`, `i32`, `i64`, `bool`, and `String`.

## Safety and hardening

Every length and count on the wire is chosen by the peer. A four-byte header claiming 4 GiB costs the sender nothing but would cost the receiver the allocation (CWE-789 / CWE-770). The hardened alternatives in the `util` module are used throughout the protocol stack:

| Instead of | Use |
|---|---|
| `Vec::with_capacity(len)` then `read_exact` | `read_bytes(input, len)` |
| `Vec::with_capacity(count)` for an array | `vec_with_capacity(count)` |

Both reserve at most `PREALLOC_CAP` (1 MiB) regardless of what was declared and grow only as real bytes arrive. Honest inputs decode identically -- only the speculative reservation is bounded.

## Pre-1.0

This crate is pre-1.0. The API may change between minor versions.

## Provenance

Derived from [Vaiz/nfs3](https://github.com/Vaiz/nfs3) (Unlicense / public domain). See [NOTICE](NOTICE).

## License

Apache-2.0

[RFC 4506]: https://www.rfc-editor.org/rfc/rfc4506
