/// A present but unparseable `#[xdr(...)]` must be reported as malformed,
/// not as missing.
use onc_xdr_derive::XdrCodec;

#[derive(XdrCodec)]
enum Bad {
    #[xdr("one")]
    Variant(u32),
}

fn main() {}
