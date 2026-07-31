/// Data-carrying enum variant without the required `#[xdr(N)]` discriminant.
use nfswolf_xdr_derive::XdrCodec;

#[derive(XdrCodec)]
enum Bad {
    Variant(u32),
}

fn main() {}
