/// Enum variant with multiple fields -- XDR union arms carry at most one value.
use nfswolf_xdr_derive::XdrCodec;

#[derive(XdrCodec)]
enum Bad {
    #[xdr(0)]
    Variant(u32, u32),
}

fn main() {}
