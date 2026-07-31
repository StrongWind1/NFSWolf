//! Compile-fail and round-trip tests for `#[derive(XdrCodec)]`.
//!
//! The `ui/` directory contains `.rs` files that must fail to compile, each
//! paired with a `.stderr` snapshot of the expected diagnostics. trybuild
//! compares actual compiler output against these snapshots.

// The proc-macro's own lib dependencies (proc_macro2, quote, syn) plus the
// derive crate itself are visible to this test binary but only used
// indirectly through onc_xdr's re-export of the derive macro.
#![expect(unused_crate_dependencies, reason = "proc-macro lib deps visible to test binary but not used directly")]

#[test]
fn xdr_compile_fail() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/ui/*.rs");
}

/// Verify the macro generates correct Pack/Unpack for a simple struct.
#[test]
fn round_trip_named_struct() {
    use onc_xdr::{Pack, Unpack};

    #[derive(onc_xdr::XdrCodec, Debug, PartialEq)]
    struct Point {
        x: u32,
        y: u32,
    }

    let original = Point { x: 42, y: 99 };

    let mut buf = Vec::new();
    let written = original.pack(&mut buf).expect("pack failed");
    assert_eq!(written, 8);
    assert_eq!(original.packed_size(), 8);

    let (decoded, read) = Point::unpack(&mut buf.as_slice()).expect("unpack failed");
    assert_eq!(read, 8);
    assert_eq!(decoded, original);
}

/// Verify the macro generates correct Pack/Unpack for a tuple struct.
#[test]
fn round_trip_tuple_struct() {
    use onc_xdr::{Pack, Unpack};

    #[derive(onc_xdr::XdrCodec, Debug, PartialEq)]
    struct Wrapper(u32);

    let original = Wrapper(0xDEAD_BEEF);

    let mut buf = Vec::new();
    let written = original.pack(&mut buf).expect("pack failed");
    assert_eq!(written, 4);

    let (decoded, read) = Wrapper::unpack(&mut buf.as_slice()).expect("unpack failed");
    assert_eq!(read, 4);
    assert_eq!(decoded, original);
}

/// Verify the macro generates correct Pack/Unpack for a unit struct.
#[test]
fn round_trip_unit_struct() {
    use onc_xdr::{Pack, Unpack};

    #[derive(onc_xdr::XdrCodec, Debug, PartialEq)]
    struct Marker;

    let original = Marker;

    let mut buf = Vec::new();
    let written = original.pack(&mut buf).expect("pack failed");
    assert_eq!(written, 0);

    let (decoded, read) = Marker::unpack(&mut buf.as_slice()).expect("unpack failed");
    assert_eq!(read, 0);
    assert_eq!(decoded, original);
}

/// Verify Pack/Unpack for a simple enum (all unit variants, uses `as u32`).
#[test]
fn round_trip_simple_enum() {
    use onc_xdr::{Pack, Unpack};

    #[derive(onc_xdr::XdrCodec, Debug, PartialEq, Clone, Copy)]
    #[repr(u32)]
    enum Color {
        Red = 0,
        Green = 1,
        Blue = 2,
    }

    for (variant, tag) in [(Color::Red, 0u32), (Color::Green, 1), (Color::Blue, 2)] {
        let mut buf = Vec::new();
        let written = variant.pack(&mut buf).expect("pack failed");
        assert_eq!(written, 4);
        assert_eq!(buf, tag.to_be_bytes());

        let (decoded, read) = Color::unpack(&mut buf.as_slice()).expect("unpack failed");
        assert_eq!(read, 4);
        assert_eq!(decoded, variant);
    }
}

/// Verify Pack/Unpack for a data-carrying enum (discriminated union).
#[test]
fn round_trip_complex_enum() {
    use onc_xdr::{Pack, Unpack};

    #[derive(onc_xdr::XdrCodec, Debug, PartialEq)]
    enum OptionalValue {
        #[xdr(0)]
        None,
        #[xdr(1)]
        Some(u32),
    }

    // Unit variant
    let none = OptionalValue::None;
    let mut buf = Vec::new();
    let written = none.pack(&mut buf).expect("pack failed");
    assert_eq!(written, 4);
    assert_eq!(none.packed_size(), 4);

    let (decoded, read) = OptionalValue::unpack(&mut buf.as_slice()).expect("unpack failed");
    assert_eq!(read, 4);
    assert_eq!(decoded, OptionalValue::None);

    // Data variant
    let some = OptionalValue::Some(0x1234_5678);
    let mut buf = Vec::new();
    let written = some.pack(&mut buf).expect("pack failed");
    assert_eq!(written, 8);
    assert_eq!(some.packed_size(), 8);

    let (decoded, read) = OptionalValue::unpack(&mut buf.as_slice()).expect("unpack failed");
    assert_eq!(read, 8);
    assert_eq!(decoded, OptionalValue::Some(0x1234_5678));
}

/// Invalid discriminant on unpack returns `InvalidEnumValue`.
#[test]
fn invalid_discriminant_unpack() {
    use onc_xdr::Unpack;

    #[derive(onc_xdr::XdrCodec, Debug, PartialEq, Clone, Copy)]
    #[repr(u32)]
    enum TwoVariants {
        A = 0,
        B = 1,
    }

    // Tag 99 is not a valid variant.
    let buf = 99u32.to_be_bytes();
    let result = TwoVariants::unpack(&mut buf.as_slice());
    assert!(result.is_err());
}
