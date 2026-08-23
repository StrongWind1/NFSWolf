# ONC XDR

**External Data Representation (XDR)** is the binary serialization format used by every protocol in the NFS stack. Defined in [RFC 4506](https://www.rfc-editor.org/rfc/rfc4506) (originally RFC 1014, 1987), XDR encodes structured data into a platform-independent byte stream so that machines with different architectures (different endianness, word sizes, alignment requirements) can exchange RPC messages without ambiguity. Think of it as protobuf from 1987, but without a schema compiler: the encoding rules are fixed by convention, and both sides must agree on the structure in advance.

Every byte that nfswolf sends or receives (AUTH_SYS credentials, file handles, directory listings, COMPOUND operations) is XDR-encoded. Understanding XDR is not strictly necessary to use the tool, but it is essential for reading packet captures, understanding why certain fields are manipulable, and debugging wire-level issues.

!!! info "nfswolf implementation"
    The `onc-xdr` crate provides the `Pack` and `Unpack` traits for XDR encoding and decoding. The `onc-xdr-derive` crate provides `#[derive(XdrCodec)]` to generate implementations automatically from Rust struct definitions. Length-hardened readers in `onc_xdr::util` defend against malicious length fields in untrusted input.

## Encoding rules

Three rules govern all of XDR:

1. **Big-endian byte order.** All multi-byte integers are stored most-significant byte first (network byte order). A `u32` value of `1` encodes as `00 00 00 01`.

2. **4-byte alignment.** Every encoded value occupies a multiple of 4 bytes. A 1-byte boolean, a 2-byte integer, and a 4-byte integer all take exactly 4 bytes on the wire. Variable-length data is padded with zero bytes to reach the next 4-byte boundary.

3. **Implicit typing.** XDR has no self-describing wire format -- there are no type tags or field names in the encoded data. Both sides must know the exact structure being encoded. If the sender writes a `string` and the receiver expects an `int`, the receiver silently interprets the length prefix as an integer value. This is by design (bandwidth was expensive in 1987) and it means that any corruption or desync in the byte stream cascades silently.

## Data types

RFC 4506 defines the following base types. Every NFS wire type is composed from these.

### Integer types

| Type | XDR size | Rust equivalent | Encoding |
|------|----------|-----------------|----------|
| `int` | 4 bytes | `i32` | Big-endian two's complement |
| `unsigned int` | 4 bytes | `u32` | Big-endian unsigned |
| `hyper` | 8 bytes | `i64` | Big-endian two's complement |
| `unsigned hyper` | 8 bytes | `u64` | Big-endian unsigned |
| `bool` | 4 bytes | `bool` | `0x00000000` = false, `0x00000001` = true |
| `enum` | 4 bytes | Rust enum | Discriminant as `int` |

All integer types smaller than 32 bits are widened to 4 bytes. XDR has no native `u8` or `u16` -- a boolean takes the same 4 bytes as a 32-bit integer.

### Floating point

| Type | XDR size | Encoding |
|------|----------|----------|
| `float` | 4 bytes | IEEE 754 single precision |
| `double` | 8 bytes | IEEE 754 double precision |

NFS rarely uses floating-point types. They exist in XDR for completeness.

### Opaque data

Opaque data is raw bytes with no internal structure. XDR defines two forms:

=== "Fixed-length opaque"
    ```text
    opaque identifier[32];
    ```
    Encoded as exactly `n` bytes, padded to a 4-byte boundary. No length prefix. NFSv2's 32-byte file handle (`fhandle2`) uses this form -- 32 bytes of handle data, no padding needed since 32 is already a multiple of 4.

=== "Variable-length opaque"
    ```text
    opaque data<1024>;
    ```
    Encoded as a 4-byte unsigned length, followed by that many bytes, padded to a 4-byte boundary. The angle brackets declare the maximum length; the actual length is in the prefix. NFSv3's variable-length file handle (`nfs_fh3`) uses this form.

### Strings

```text
string path<1024>;
```

Strings are identical to variable-length opaque data on the wire: a 4-byte length prefix followed by the string bytes, padded to 4-byte alignment. The only difference is semantic -- strings are expected to contain ASCII text. XDR does not define a character encoding; NFS conventionally uses ASCII for path components and hostnames.

### Arrays

=== "Fixed-length array"
    ```text
    int values[4];
    ```
    Encoded as `n` consecutive elements with no length prefix. Each element is encoded according to its own type rules.

=== "Variable-length array"
    ```text
    int values<8>;
    ```
    Encoded as a 4-byte count followed by that many elements. The angle brackets declare the maximum count. AUTH_SYS's auxiliary group list (`gids<16>`) is a variable-length array of up to 16 `unsigned int` values.

### Structs

```text
struct file_info {
    unsigned int  fileid;
    unsigned int  size;
    string        name<255>;
};
```

Structs encode their fields consecutively in declaration order, with no delimiters or field tags. The receiver must know the field order and types. Adding, removing, or reordering fields breaks compatibility silently.

### Discriminated unions

```text
union result switch (unsigned int status) {
    case 0:
        file_info info;
    default:
        void;
};
```

A discriminated union encodes a 4-byte discriminant (the `switch` value) followed by the arm that matches. This is the XDR equivalent of a tagged enum. Nearly every NFS reply uses one: `status = 0` (NFS_OK) carries the result data; any other status carries error-specific data or `void`.

### Void

`void` encodes as zero bytes. It is used in union arms where no data is needed (e.g., the error arm of a result that carries only a status code) and as the body of AUTH_NONE verifiers.

## Annotated hex dump

The following hex dump shows a complete XDR-encoded `authsys_parms` structure (RFC 5531 Appendix A) as it appears on the wire inside an ONC RPC call. This is the credential that nfswolf forges on every AUTH_SYS request.

```text
 Offset  Hex                               Field
 ------  --------------------------------  --------------------------
 0x00    00 00 00 2A                       stamp = 42
 0x04    00 00 00 09                       machinename length = 9
 0x08    6C 6F 63 61 6C 68 6F 73 74 00     "localhost" + 1 pad byte
         00 00
 0x14    00 00 00 00                       uid = 0 (root)
 0x18    00 00 00 00                       gid = 0 (root)
 0x1C    00 00 00 01                       gids count = 1
 0x20    00 00 00 00                       gids[0] = 0
```

Total: 36 bytes (9 words). Every field is 4-byte aligned. The string `"localhost"` is 9 bytes, so 3 bytes of zero padding are appended to reach the next 4-byte boundary (only 1 pad byte after the 9th character, then 2 more zero bytes fill the next word -- the pad is `10 00 00` occupying offsets `0x11`-`0x13`).

!!! note "Reading this in Wireshark"
    Wireshark decodes XDR natively for NFS traffic. Filter with `rpc.auth.flavor == 1` to isolate AUTH_SYS calls, then expand the "Credentials" section to see each field decoded.

## How NFS uses XDR

Every NFS message -- call arguments, reply results, file attributes, directory entries -- is an XDR-encoded struct or union. Some examples:

| NFS concept | XDR type | Notable encoding detail |
|-------------|----------|------------------------|
| File handle (v2) | `opaque fhandle[32]` | Fixed 32 bytes, no length prefix |
| File handle (v3) | `opaque data<64>` | Variable-length, 4-byte length prefix, up to 64 bytes |
| File handle (v4) | `opaque data<128>` | Variable-length, up to 128 bytes |
| File attributes | `struct fattr3` | 20 fields encoded consecutively, 84 bytes total |
| Directory entry | `struct entry3` | Recursive: each entry contains an optional pointer to the next |
| COMPOUND (v4) | `struct COMPOUND4args` | Array of `nfs_argop4` unions -- variable count, each union discriminated by opcode |
| AUTH_SYS cred | `struct authsys_parms` | The credential nfswolf forges -- see hex dump above |

The discriminated union pattern is pervasive. Every NFS procedure reply is a union discriminated on `nfsstat3` (or `nfsstat4`): the success arm carries the result data, and the error arm carries post-op attributes or `void`. This means the first 4 bytes after the RPC reply header always tell you whether the call succeeded.

## Security considerations

XDR itself is a serialization format with no security properties -- no authentication, no integrity, no confidentiality. But its encoding rules create specific opportunities for manipulation:

!!! danger "Length field manipulation"
    Variable-length opaque data and strings are prefixed by a 4-byte unsigned length. A crafted length can cause a naive decoder to allocate an arbitrary amount of memory (up to 2^32 bytes) or read past the end of the message buffer. RFC 4506 Section 4.10 specifies a maximum length for each declaration (the value in angle brackets), but enforcement is the decoder's responsibility.

    nfswolf's `onc-xdr` crate defends against this with a hardened reader (`onc_xdr::util`) that caps pre-allocation at `PREALLOC_CAP` and validates lengths against declared maximums before allocating. Servers that nfswolf talks to may not be so careful.

!!! warning "No type tags means no validation"
    Because XDR is implicitly typed, there is no way to detect a type mismatch at the wire level. If a server expects a `LOOKUP3args` struct and receives raw bytes that happen to be the right length, it will decode them as a directory handle and filename regardless of what they actually represent. This property is what makes file handle brute-forcing work: the server decodes whatever bytes it receives as a handle and checks them against the inode table, returning `STALE` or `BADHANDLE` as an oracle.

!!! note "Padding bytes are ignored"
    The zero-padding bytes that bring values to 4-byte alignment are required to be zero on encode, but RFC 4506 does not mandate that decoders reject non-zero padding. In practice, padding bytes are ignored. This is not exploitable in NFS but it does mean that two different byte sequences can decode to the same logical value.

## XDR in nfswolf's crate stack

The `onc-xdr` crate sits at the bottom of the dependency graph. Every protocol crate depends on it:

```text
onc-xdr-derive   (proc macro: #[derive(XdrCodec)])
    |
    v
onc-xdr           (Pack, Unpack, Opaque, List, BoundedList, Void)
    |
    +---> onc-rpc-client  (RPC framing)
    +---> onc-rpcbind     (portmapper)
    +---> nfs-mount       (MOUNT v1/v3)
    +---> nfs-v2          (NFSv2)
    +---> nfs-v3          (NFSv3)
    +---> nfs-v4          (NFSv4.0)
```

The `Pack` trait serializes a Rust value into an XDR byte stream. The `Unpack` trait deserializes. The `#[derive(XdrCodec)]` macro generates both implementations by encoding struct fields in declaration order and union variants by their discriminant -- exactly matching the XDR spec's mechanical rules.

```rust
use onc_xdr::XdrCodec;

#[derive(XdrCodec)]
struct LookupArgs {
    dir: FileHandle,      // encoded first
    name: String,         // encoded second, as XDR string (length + bytes + pad)
}
```

The traits are implemented by hand for types whose wire encoding does not follow the mechanical field-by-field rule: `Opaque` (which needs special fixed-vs-variable handling), `List` (which uses XDR array encoding), and `Void` (zero bytes).
