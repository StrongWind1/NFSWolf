/// An open enum has exactly one catch-all arm.
use onc_xdr_derive::XdrCodec;

#[derive(XdrCodec)]
enum Bad {
    #[xdr(0)]
    Known,
    #[xdr(other)]
    First(u32),
    #[xdr(other)]
    Second(u32),
}

fn main() {}
