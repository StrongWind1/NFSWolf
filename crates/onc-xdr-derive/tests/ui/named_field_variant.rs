/// Enum variant with named (struct-like) fields -- XDR union arms are positional.
use onc_xdr_derive::XdrCodec;

#[derive(XdrCodec)]
enum Bad {
    #[xdr(0)]
    Variant { value: u32 },
}

fn main() {}
