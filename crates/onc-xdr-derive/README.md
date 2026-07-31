# onc-xdr-derive

`#[derive(XdrCodec)]` -- generates XDR ([RFC 4506]) `Pack` and `Unpack` implementations for the NFSWolf protocol stack.

XDR is the serialisation format every ONC RPC protocol is built on. NFSv2, NFSv3, NFSv4, MOUNT, and the portmapper all encode their arguments and results with it, which adds up to a few hundred wire types across [RFC 1094], [RFC 1813], and [RFC 7530]. Hand-writing the codec for each one is exactly the kind of mechanical work that invites a transposed field, so this macro generates it.

The traits themselves live in [`onc-xdr`](../onc-xdr); this crate only exists because Rust requires proc macros to ship in their own crate.

## Encoding rules

- Fields pack in declaration order, no padding between them.
- Enums (XDR "enum" and discriminated "union") lead with a 4-byte big-endian discriminant, then the arm's payload if it has one.
- Structs carry no tag of their own.

Simple enums take their discriminant from the variant's `as u32` value. Data-carrying variants cannot, so each is tagged explicitly:

```rust,ignore
#[derive(XdrCodec)]
enum post_op_attr {
    #[xdr(1)]
    Some(fattr3),
    #[xdr(0)]
    None,
}
```

Types whose wire form breaks the mechanical rule -- NFSv2's fixed-width 32-byte file handles, the RPC reply body's nested unions -- implement the traits by hand in the protocol crate that defines them.

## Pre-1.0

This crate is pre-1.0. The API may change between minor versions.

## Provenance

Derived from [Vaiz/nfs3](https://github.com/Vaiz/nfs3) (Unlicense / public domain). See [`../onc-xdr/NOTICE`](../onc-xdr/NOTICE).

[RFC 4506]: https://www.rfc-editor.org/rfc/rfc4506
[RFC 1094]: https://www.rfc-editor.org/rfc/rfc1094
[RFC 1813]: https://www.rfc-editor.org/rfc/rfc1813
[RFC 7530]: https://www.rfc-editor.org/rfc/rfc7530
