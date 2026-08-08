/// XdrCodec on a Rust `union` is not valid -- XDR has no encoding for it.
use onc_xdr_derive::XdrCodec;

#[derive(XdrCodec)]
union Bad {
    a: u32,
    b: i32,
}

fn main() {}
