/// Data-carrying enum variant without the required `#[xdr(N)]` discriminant.
use onc_xdr_derive::XdrCodec;

#[derive(XdrCodec)]
enum Bad {
    Variant(u32),
}

fn main() {}
