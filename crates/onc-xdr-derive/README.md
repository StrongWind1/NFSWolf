# onc-xdr-derive

Derive macro that generates XDR ([RFC 4506]) `Pack` and `Unpack` implementations for Rust structs and enums.

XDR is the serialisation format every ONC RPC protocol is built on -- NFSv2, NFSv3, NFSv4, MOUNT, and the portmapper all encode their arguments and results with it. The ~200 wire types in [RFC 1813] alone would be error-prone to implement by hand, so `#[derive(XdrCodec)]` generates the codec mechanically. The `Pack` and `Unpack` traits themselves live in [`onc-xdr`](../onc-xdr); this crate exists only because Rust requires proc macros to ship in their own crate.

## Quick start

```rust
use onc_xdr::{Pack, Unpack, XdrCodec};

// Simple enum -- discriminant from `as u32`.
#[derive(XdrCodec, Clone, Copy)]
#[repr(u32)]
enum ftype3 {
    NF3REG = 1,
    NF3DIR = 2,
}

// Data-carrying enum (discriminated union) -- explicit #[xdr(N)].
#[derive(XdrCodec)]
enum post_op_attr {
    #[xdr(1)]
    Some(fattr3),
    #[xdr(0)]
    None,
}

// Struct -- fields pack in declaration order, no tag.
#[derive(XdrCodec)]
struct GETATTR3args {
    object: nfs_fh3,
}
```

## API overview

| Item | Description |
|------|-------------|
| `#[derive(XdrCodec)]` | Generates `Pack` and `Unpack` for structs and enums |
| `#[repr(u32)]` | Required on simple enums so discriminants come from variant values |
| `#[xdr(N)]` | Sets the discriminant on data-carrying enum variants |

## Encoding rules

- Struct fields pack in declaration order with no padding between them (RFC 4506 sec. 4.14).
- Simple enums (all unit variants) encode as a 4-byte big-endian discriminant using the variant's `as u32` value.
- Data-carrying enums (discriminated unions) encode as a 4-byte discriminant from `#[xdr(N)]`, followed by the arm's payload (RFC 4506 sec. 4.15).
- Each union arm carries at most one value -- multi-field and braced variants are rejected at compile time.

Types whose wire form breaks these rules -- NFSv2's fixed 32-byte file handles, the RPC reply body's nested unions -- implement the traits by hand in their protocol crate.

## Pre-1.0

This crate is pre-1.0. The API may change between minor versions.

## Provenance

Derived from [Vaiz/nfs3](https://github.com/Vaiz/nfs3) (Unlicense / public domain). See [`../onc-xdr/NOTICE`](../onc-xdr/NOTICE).

## License

Apache-2.0

[RFC 4506]: https://www.rfc-editor.org/rfc/rfc4506
[RFC 1813]: https://www.rfc-editor.org/rfc/rfc1813
