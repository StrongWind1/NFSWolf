//! Derive macro for XDR (External Data Representation) encoding.
//!
//! XDR is the serialisation format every ONC RPC protocol is built on --
//! NFSv2, NFSv3, NFSv4, MOUNT, and the portmapper all encode their arguments
//! and results with it.  The format is defined by [RFC 4506]; the essential
//! rules this macro implements are:
//!
//! * Every field is packed in declaration order with no padding between them.
//! * Enums (XDR "enum" and discriminated "union") are tagged by a 4-byte
//!   big-endian discriminant, followed by the arm's payload if it has one.
//! * Structs carry no tag of their own -- they are just their fields, in order.
//!
//! Writing `Pack` and `Unpack` by hand for the ~200 types in [RFC 1813] alone
//! would be error-prone busywork, so `#[derive(XdrCodec)]` generates them.
//! Types whose wire form does not follow the mechanical rules above (NFSv2's
//! fixed-width 32-byte file handles, the RPC reply body's nested unions) still
//! implement the traits by hand in the protocol crate that defines them.
//!
//! # Discriminant values
//!
//! Simple enums (all unit variants) use the variant's own `as u32` value, so
//! the discriminant is declared the normal Rust way:
//!
//! ```ignore
//! #[derive(XdrCodec, Clone, Copy)]
//! #[repr(u32)]
//! enum ftype3 {
//!     NF3REG = 1,
//!     NF3DIR = 2,
//! }
//! ```
//!
//! Enums carrying data cannot use `as u32`, so each variant is tagged with an
//! explicit `#[xdr(N)]` attribute giving its discriminant:
//!
//! ```ignore
//! #[derive(XdrCodec)]
//! enum post_op_attr {
//!     #[xdr(1)]
//!     Some(fattr3),
//!     #[xdr(0)]
//!     None,
//! }
//! ```
//!
//! [RFC 4506]: https://www.rfc-editor.org/rfc/rfc4506
//! [RFC 1813]: https://www.rfc-editor.org/rfc/rfc1813

#![expect(
    clippy::panic,
    reason = "a derive macro's \"runtime\" is the compiler's expansion pass, so a \
panic here surfaces as a build failure on the offending type, never as a fault in \
a running binary. Reporting via syn::Error would point at a tighter source span \
and is worth doing, but these panics cannot reach production code"
)]

use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;
use quote::quote;
use syn::{Attribute, Data, DataEnum, DeriveInput, Expr, Fields, FieldsNamed, FieldsUnnamed, Ident, Index, Lit, Meta, Variant, parse_macro_input};

/// Reads the discriminant out of a `#[xdr(N)]` attribute.
///
/// Only data-carrying enum variants need this; simple enums get their
/// discriminant from `as u32` instead.
fn parse_xdr_value(attrs: &[Attribute]) -> Option<u32> {
    for attr in attrs {
        if attr.path().is_ident("xdr")
            && let Meta::List(meta_list) = &attr.meta
            && let Ok(Expr::Lit(syn::ExprLit { lit: Lit::Int(lit_int), .. })) = meta_list.parse_args::<Expr>()
            && let Ok(value) = lit_int.base10_parse::<u32>()
        {
            return Some(value);
        }
    }
    None
}

/// Emits per-field pack/unpack fragments for a braced struct.
struct NamedFieldsGenerator<'a> {
    fields: &'a FieldsNamed,
}

impl<'a> NamedFieldsGenerator<'a> {
    const fn new(fields: &'a FieldsNamed) -> Self {
        Self { fields }
    }

    fn pack_fields(&self) -> impl Iterator<Item = TokenStream2> + '_ {
        self.fields.named.iter().map(|f| {
            let name = &f.ident;
            quote! {
                total_write += self.#name.pack(out)?;
            }
        })
    }

    fn packed_size_fields(&self) -> impl Iterator<Item = TokenStream2> + '_ {
        self.fields.named.iter().map(|f| {
            let name = &f.ident;
            quote! {
                total_size += ::nfswolf_xdr::Pack::packed_size(&self.#name);
            }
        })
    }

    fn unpack_fields(&self) -> impl Iterator<Item = TokenStream2> + '_ {
        self.fields.named.iter().map(|f| {
            let name = &f.ident;
            quote! {
                let (#name, read_bytes) = ::nfswolf_xdr::Unpack::unpack(input)?;
                total_read += read_bytes;
            }
        })
    }

    fn struct_construction_fields(&self) -> impl Iterator<Item = TokenStream2> + '_ {
        self.fields.named.iter().map(|f| {
            let name = &f.ident;
            quote! { #name, }
        })
    }
}

/// Emits per-field pack/unpack fragments for a tuple struct.
struct UnnamedFieldsGenerator<'a> {
    fields: &'a FieldsUnnamed,
}

impl<'a> UnnamedFieldsGenerator<'a> {
    const fn new(fields: &'a FieldsUnnamed) -> Self {
        Self { fields }
    }

    fn pack_fields(&self) -> impl Iterator<Item = TokenStream2> + '_ {
        self.fields.unnamed.iter().enumerate().map(|(i, _)| {
            let index = Index::from(i);
            quote! {
                total_write += self.#index.pack(out)?;
            }
        })
    }

    fn packed_size_fields(&self) -> impl Iterator<Item = TokenStream2> + '_ {
        self.fields.unnamed.iter().enumerate().map(|(i, _)| {
            let index = Index::from(i);
            quote! {
                total_size += ::nfswolf_xdr::Pack::packed_size(&self.#index);
            }
        })
    }

    fn unpack_fields(&self) -> impl Iterator<Item = TokenStream2> + '_ {
        self.fields.unnamed.iter().enumerate().map(|(i, _)| {
            let var_name = Ident::new(&format!("field_{i}"), proc_macro2::Span::call_site());
            quote! {
                let (#var_name, read_bytes) = ::nfswolf_xdr::Unpack::unpack(input)?;
                total_read += read_bytes;
            }
        })
    }

    fn struct_construction_fields(&self) -> impl Iterator<Item = TokenStream2> + '_ {
        (0..self.fields.unnamed.len()).map(|i| {
            let var_name = Ident::new(&format!("field_{i}"), proc_macro2::Span::call_site());
            quote! { #var_name }
        })
    }
}

/// Generates `Pack`/`Unpack` for a struct.
///
/// XDR structs are untagged: the encoding is exactly the fields back to back,
/// so there is no discriminant to write (RFC 4506 sec. 4.14).
fn generate_struct_impl(name: &Ident, generics: &syn::Generics, fields: &Fields) -> TokenStream2 {
    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();

    match fields {
        Fields::Named(named_fields) => {
            let generator = NamedFieldsGenerator::new(named_fields);
            let pack_fields = generator.pack_fields();
            let packed_size_fields = generator.packed_size_fields();
            let unpack_fields = generator.unpack_fields();
            let struct_fields = generator.struct_construction_fields();

            quote! {
                impl #impl_generics ::nfswolf_xdr::Pack for #name #ty_generics
                #where_clause {
                    fn packed_size(&self) -> usize {
                        let mut total_size = 0;
                        #(#packed_size_fields)*
                        total_size
                    }

                    fn pack(&self, out: &mut impl std::io::Write) -> ::nfswolf_xdr::Result<usize> {
                        use ::nfswolf_xdr::Pack;
                        let mut total_write = 0;
                        #(#pack_fields)*
                        Ok(total_write)
                    }
                }
                impl #impl_generics ::nfswolf_xdr::Unpack for #name #ty_generics
                #where_clause {
                    fn unpack(input: &mut impl std::io::Read) -> ::nfswolf_xdr::Result<(Self, usize)> {
                        use ::nfswolf_xdr::Unpack;
                        let mut total_read = 0;
                        #(#unpack_fields)*
                        Ok((Self { #(#struct_fields)* }, total_read))
                    }
                }
            }
        },
        Fields::Unnamed(unnamed_fields) => {
            let generator = UnnamedFieldsGenerator::new(unnamed_fields);
            let pack_fields = generator.pack_fields();
            let packed_size_fields = generator.packed_size_fields();
            let unpack_fields = generator.unpack_fields();
            let struct_fields = generator.struct_construction_fields();

            quote! {
                impl #impl_generics ::nfswolf_xdr::Pack for #name #ty_generics
                #where_clause {
                    fn packed_size(&self) -> usize {
                        let mut total_size = 0;
                        #(#packed_size_fields)*
                        total_size
                    }

                    fn pack(&self, out: &mut impl std::io::Write) -> ::nfswolf_xdr::Result<usize> {
                        use ::nfswolf_xdr::Pack;
                        let mut total_write = 0;
                        #(#pack_fields)*
                        Ok(total_write)
                    }
                }
                impl #impl_generics ::nfswolf_xdr::Unpack for #name #ty_generics
                #where_clause {
                    fn unpack(input: &mut impl std::io::Read) -> ::nfswolf_xdr::Result<(Self, usize)> {
                        use ::nfswolf_xdr::Unpack;
                        let mut total_read = 0;
                        #(#unpack_fields)*
                        Ok((Self(#(#struct_fields),*), total_read))
                    }
                }
            }
        },
        Fields::Unit => {
            quote! {
                impl #impl_generics ::nfswolf_xdr::Pack for #name #ty_generics
                #where_clause {
                    fn packed_size(&self) -> usize {
                        0
                    }

                    fn pack(&self, _out: &mut impl std::io::Write) -> ::nfswolf_xdr::Result<usize> {
                        Ok(0)
                    }
                }
                impl #impl_generics ::nfswolf_xdr::Unpack for #name #ty_generics
                #where_clause {
                    fn unpack(_input: &mut impl std::io::Read) -> ::nfswolf_xdr::Result<(Self, usize)> {
                        Ok((Self, 0))
                    }
                }
            }
        },
    }
}

/// Rejects enum shapes XDR has no encoding for.
///
/// An XDR discriminated union arm carries at most one value (RFC 4506
/// sec. 4.15), so multi-field and braced variants cannot be represented.
fn validate_complex_enum_variant(variant: &Variant) -> Result<(), String> {
    match &variant.fields {
        Fields::Unit => Ok(()),
        Fields::Unnamed(fields) if fields.unnamed.len() == 1 => Ok(()),
        _ => Err(format!("Complex enum variant '{}' must be either unit or have exactly one unnamed field", variant.ident)),
    }
}

/// Emits the pack arm for one variant of a data-carrying enum.
fn generate_complex_enum_pack_variant(variant: &Variant) -> TokenStream2 {
    let ident = &variant.ident;
    let xdr_value = parse_xdr_value(&variant.attrs).unwrap_or_else(|| {
        panic!("Complex enum variant '{ident}' must have #[xdr(value)] attribute");
    });

    match &variant.fields {
        Fields::Unit => {
            quote! {
                Self::#ident => #xdr_value.pack(out),
            }
        },
        Fields::Unnamed(fields) if fields.unnamed.len() == 1 => {
            quote! {
                Self::#ident(val) => {
                    let mut len = #xdr_value.pack(out)?;
                    len += val.pack(out)?;
                    Ok(len)
                },
            }
        },
        _ => panic!("Invalid complex enum variant: {ident}"),
    }
}

/// Emits the `packed_size` arm for one variant of a data-carrying enum.
///
/// The constant 4 is the discriminant, which XDR always encodes as a 4-byte
/// big-endian integer regardless of how few values the union has.
fn generate_complex_enum_packed_size_variant(variant: &Variant) -> TokenStream2 {
    let ident = &variant.ident;

    match &variant.fields {
        Fields::Unit => {
            quote! {
                Self::#ident => 4,
            }
        },
        Fields::Unnamed(fields) if fields.unnamed.len() == 1 => {
            quote! {
                Self::#ident(val) => 4 + val.packed_size(),
            }
        },
        _ => panic!("Invalid complex enum variant: {ident}"),
    }
}

/// Emits the unpack arm for one variant of a data-carrying enum.
fn generate_complex_enum_unpack_variant(variant: &Variant) -> TokenStream2 {
    let ident = &variant.ident;
    let xdr_value = parse_xdr_value(&variant.attrs).unwrap_or_else(|| {
        panic!("Complex enum variant '{ident}' must have #[xdr(value)] attribute");
    });

    match &variant.fields {
        Fields::Unit => {
            quote! {
                #xdr_value => Ok(Self::#ident),
            }
        },
        Fields::Unnamed(fields) if fields.unnamed.len() == 1 => {
            quote! {
                #xdr_value => {
                    let (val, val_bytes) = ::nfswolf_xdr::Unpack::unpack(input)?;
                    bytes_read += val_bytes;
                    Ok(Self::#ident(val))
                },
            }
        },
        _ => panic!("Invalid complex enum variant: {ident}"),
    }
}

/// Generates `Pack`/`Unpack` for an enum whose variants are all unit.
///
/// These map onto a plain XDR enum: just the 4-byte discriminant, taken from
/// the variant's `as u32` value.
fn generate_simple_enum_impl(name: &Ident, generics: &syn::Generics, data: &DataEnum) -> TokenStream2 {
    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();

    let pack_variants = data.variants.iter().map(|v| {
        let ident = &v.ident;
        quote! {
            Self::#ident => (*self as u32).pack(out),
        }
    });

    let unpack_variants = data.variants.iter().map(|v| {
        let ident = &v.ident;
        quote! {
            x if x == Self::#ident as u32 => Ok(Self::#ident),
        }
    });

    quote! {
        impl #impl_generics ::nfswolf_xdr::Pack for #name #ty_generics
        #where_clause {
            fn packed_size(&self) -> usize {
                4
            }

            fn pack(&self, out: &mut impl std::io::Write) -> ::nfswolf_xdr::Result<usize> {
                use ::nfswolf_xdr::Pack;
                match self {
                    #(#pack_variants)*
                }
            }
        }
        impl #impl_generics ::nfswolf_xdr::Unpack for #name #ty_generics
        #where_clause {
            fn unpack(input: &mut impl std::io::Read) -> ::nfswolf_xdr::Result<(Self, usize)> {
                let (tag, bytes_read) = u32::unpack(input)?;
                let result = match tag {
                    #(#unpack_variants)*
                    _ => Err(::nfswolf_xdr::Error::InvalidEnumValue(tag)),
                };
                result.map(|value| (value, bytes_read))
            }
        }
    }
}

/// Generates `Pack`/`Unpack` for an enum with data-carrying variants.
///
/// These map onto an XDR discriminated union: the 4-byte discriminant from
/// `#[xdr(N)]`, followed by the arm's payload.
fn generate_complex_enum_impl(name: &Ident, generics: &syn::Generics, data: &DataEnum) -> TokenStream2 {
    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();

    // Fail at expansion time rather than emitting code that cannot compile.
    for variant in &data.variants {
        if let Err(err) = validate_complex_enum_variant(variant) {
            panic!("{}", err);
        }
    }

    let pack_variants = data.variants.iter().map(generate_complex_enum_pack_variant);
    let packed_size_variants = data.variants.iter().map(generate_complex_enum_packed_size_variant);
    let unpack_variants = data.variants.iter().map(generate_complex_enum_unpack_variant);

    quote! {
        impl #impl_generics ::nfswolf_xdr::Pack for #name #ty_generics
        #where_clause {
            fn packed_size(&self) -> usize {
                match self {
                    #(#packed_size_variants)*
                }
            }

            fn pack(&self, out: &mut impl std::io::Write) -> ::nfswolf_xdr::Result<usize> {
                use ::nfswolf_xdr::Pack;
                match self {
                    #(#pack_variants)*
                }
            }
        }
        impl #impl_generics ::nfswolf_xdr::Unpack for #name #ty_generics
        #where_clause {
            fn unpack(input: &mut impl std::io::Read) -> ::nfswolf_xdr::Result<(Self, usize)> {
                use ::nfswolf_xdr::Unpack;
                let (tag, mut bytes_read) = u32::unpack(input)?;
                let result = match tag {
                    #(#unpack_variants)*
                    _ => Err(::nfswolf_xdr::Error::InvalidEnumValue(tag)),
                };
                result.map(|value| (value, bytes_read))
            }
        }
    }
}

/// Dispatches to the simple or discriminated-union enum generator.
fn generate_enum_impl(name: &Ident, generics: &syn::Generics, data: &DataEnum) -> TokenStream2 {
    let has_data_variants = data.variants.iter().any(|v| !matches!(v.fields, Fields::Unit));

    if has_data_variants { generate_complex_enum_impl(name, generics, data) } else { generate_simple_enum_impl(name, generics, data) }
}

/// Derives XDR `Pack` and `Unpack` for a struct or enum.
///
/// See the crate documentation for the encoding rules and for when to reach
/// for a hand-written implementation instead.
///
/// # Panics
///
/// Panics at macro-expansion time when the type cannot be expressed in XDR:
/// on unions, on a data-carrying enum variant with more than one field or with
/// named fields, or on a data-carrying variant missing its `#[xdr(N)]` tag.
#[proc_macro_derive(XdrCodec, attributes(xdr))]
pub fn derive_xdr_codec(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let name = &input.ident;
    let generics = &input.generics;

    let result = match &input.data {
        Data::Struct(data_struct) => generate_struct_impl(name, generics, &data_struct.fields),
        Data::Enum(data_enum) => generate_enum_impl(name, generics, data_enum),
        Data::Union(_) => panic!("XdrCodec can only be derived for structs and enums"),
    };

    result.into()
}

// Dev-dependencies (nfswolf_xdr, trybuild) are visible to the lib test target
// but only used from the integration test binary in tests/derive.rs.
#[cfg(test)]
mod _dev_dep_anchors {
    use nfswolf_xdr as _;
    use trybuild as _;
}
