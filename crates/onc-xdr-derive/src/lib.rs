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
//! A unit variant of such an enum may give its discriminant the normal Rust
//! way (`NAME = N`, which needs `#[repr(u32)]`) instead of `#[xdr(N)]`.
//!
//! # Open enums
//!
//! A value received from a peer is not limited to the variants a spec lists:
//! servers return status codes, flavors and types that a later RFC added or
//! that are vendor-specific. A closed enum turns every such value into a
//! decode error for the whole message. Marking one `u32` tuple variant
//! `#[xdr(other)]` makes the enum open -- an unlisted discriminant decodes
//! into that variant carrying the raw value, and packs back unchanged:
//!
//! ```ignore
//! #[derive(XdrCodec, Clone, Copy)]
//! #[repr(u32)]
//! enum auth_stat {
//!     AUTH_OK = 0,
//!     AUTH_BADCRED = 1,
//!     #[xdr(other)]
//!     Unknown(u32),
//! }
//! ```
//!
//! # Hygiene
//!
//! Local bindings in the expanded code use mixed-site hygiene, so a struct
//! field may be named `input`, `out` or anything else without colliding with
//! them.
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
use proc_macro2::{Span, TokenStream as TokenStream2};
use quote::quote;
use syn::{Data, DataEnum, DeriveInput, Expr, Fields, FieldsNamed, FieldsUnnamed, Ident, Index, Lit, Meta, Variant, parse_macro_input};

/// Identifiers for the bindings the expanded code declares.
///
/// They carry [`Span::mixed_site`], so they live in the macro's own hygiene
/// context: a user's field named `input` or `total_read` gets a binding of
/// its own instead of shadowing the decoder's.
struct Locals {
    input: Ident,
    out: Ident,
    total_read: Ident,
    total_write: Ident,
    total_size: Ident,
    read_bytes: Ident,
    bytes_read: Ident,
    tag: Ident,
    val: Ident,
    val_bytes: Ident,
    result: Ident,
    len: Ident,
}

impl Locals {
    fn new() -> Self {
        let local = |name: &str| Ident::new(name, Span::mixed_site());
        Self {
            input: local("input"),
            out: local("out"),
            total_read: local("total_read"),
            total_write: local("total_write"),
            total_size: local("total_size"),
            read_bytes: local("read_bytes"),
            bytes_read: local("bytes_read"),
            tag: local("tag"),
            val: local("val"),
            val_bytes: local("val_bytes"),
            result: local("result"),
            len: local("len"),
        }
    }

    /// Binding for the `i`th field of a tuple struct while it is decoded.
    fn field(i: usize) -> Ident {
        Ident::new(&format!("field_{i}"), Span::mixed_site())
    }
}

/// What a variant's `#[xdr(...)]` attribute says.
enum XdrAttr {
    /// `#[xdr(N)]` -- the variant's discriminant.
    Value(u32),
    /// `#[xdr(other)]` -- the catch-all arm of an open enum.
    Other,
}

/// Reads a variant's `#[xdr(...)]` attribute, if it has one.
///
/// # Panics
///
/// When the attribute is present but is neither an integer literal that fits
/// in a `u32` nor `other`. Treating that as absent would report a missing
/// attribute on a variant that has one.
fn parse_xdr_attr(variant: &Variant) -> Option<XdrAttr> {
    let attr = variant.attrs.iter().find(|a| a.path().is_ident("xdr"))?;
    let malformed = || -> ! { panic!("Malformed #[xdr(...)] attribute on variant '{}': expected an integer literal that fits in u32, or `other`", variant.ident) };
    let Meta::List(meta_list) = &attr.meta else { malformed() };
    match meta_list.parse_args::<Expr>() {
        Ok(Expr::Lit(syn::ExprLit { lit: Lit::Int(lit_int), .. })) => lit_int.base10_parse::<u32>().map_or_else(|_| malformed(), |v| Some(XdrAttr::Value(v))),
        Ok(Expr::Path(path)) if path.path.is_ident("other") => Some(XdrAttr::Other),
        _ => malformed(),
    }
}

/// The wire discriminant of a non-catch-all variant of a data-carrying enum.
///
/// Taken from `#[xdr(N)]`, or failing that from an explicit `= N`.
///
/// # Panics
///
/// When the variant has neither, or both and they disagree.
fn variant_tag(variant: &Variant) -> u32 {
    let ident = &variant.ident;
    let explicit = variant.discriminant.as_ref().map(|(_, expr)| match expr {
        Expr::Lit(syn::ExprLit { lit: Lit::Int(lit_int), .. }) => lit_int.base10_parse::<u32>().unwrap_or_else(|_| panic!("Discriminant of variant '{ident}' must fit in u32")),
        _ => panic!("Discriminant of variant '{ident}' must be an integer literal"),
    });
    match (parse_xdr_attr(variant), explicit) {
        (Some(XdrAttr::Value(v)), None) | (None, Some(v)) => v,
        (Some(XdrAttr::Value(v)), Some(d)) if v == d => v,
        (Some(XdrAttr::Value(_)), Some(_)) => panic!("Variant '{ident}' has an #[xdr(N)] attribute and a discriminant that disagree"),
        (Some(XdrAttr::Other), _) => unreachable!("catch-all variants are handled before their tag is asked for"),
        (None, None) => panic!("Complex enum variant '{ident}' must have #[xdr(value)] attribute"),
    }
}

/// Whether a variant is the `#[xdr(other)]` catch-all.
fn is_catch_all(variant: &Variant) -> bool {
    matches!(parse_xdr_attr(variant), Some(XdrAttr::Other))
}

/// Emits per-field pack/unpack fragments for a braced struct.
struct NamedFieldsGenerator<'a> {
    fields: &'a FieldsNamed,
    locals: &'a Locals,
}

impl<'a> NamedFieldsGenerator<'a> {
    const fn new(fields: &'a FieldsNamed, locals: &'a Locals) -> Self {
        Self { fields, locals }
    }

    fn pack_fields(&self) -> impl Iterator<Item = TokenStream2> + '_ {
        let Locals { out, total_write, .. } = self.locals;
        self.fields.named.iter().map(move |f| {
            let name = &f.ident;
            quote! {
                #total_write += self.#name.pack(#out)?;
            }
        })
    }

    fn packed_size_fields(&self) -> impl Iterator<Item = TokenStream2> + '_ {
        let total_size = &self.locals.total_size;
        self.fields.named.iter().map(move |f| {
            let name = &f.ident;
            quote! {
                #total_size += ::onc_xdr::Pack::packed_size(&self.#name);
            }
        })
    }

    fn unpack_fields(&self) -> impl Iterator<Item = TokenStream2> + '_ {
        let Locals { input, total_read, read_bytes, .. } = self.locals;
        self.fields.named.iter().map(move |f| {
            let name = &f.ident;
            quote! {
                let (#name, #read_bytes) = ::onc_xdr::Unpack::unpack(#input)?;
                #total_read += #read_bytes;
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
    locals: &'a Locals,
}

impl<'a> UnnamedFieldsGenerator<'a> {
    const fn new(fields: &'a FieldsUnnamed, locals: &'a Locals) -> Self {
        Self { fields, locals }
    }

    fn pack_fields(&self) -> impl Iterator<Item = TokenStream2> + '_ {
        let Locals { out, total_write, .. } = self.locals;
        self.fields.unnamed.iter().enumerate().map(move |(i, _)| {
            let index = Index::from(i);
            quote! {
                #total_write += self.#index.pack(#out)?;
            }
        })
    }

    fn packed_size_fields(&self) -> impl Iterator<Item = TokenStream2> + '_ {
        let total_size = &self.locals.total_size;
        self.fields.unnamed.iter().enumerate().map(move |(i, _)| {
            let index = Index::from(i);
            quote! {
                #total_size += ::onc_xdr::Pack::packed_size(&self.#index);
            }
        })
    }

    fn unpack_fields(&self) -> impl Iterator<Item = TokenStream2> + '_ {
        let Locals { input, total_read, read_bytes, .. } = self.locals;
        self.fields.unnamed.iter().enumerate().map(move |(i, _)| {
            let var_name = Locals::field(i);
            quote! {
                let (#var_name, #read_bytes) = ::onc_xdr::Unpack::unpack(#input)?;
                #total_read += #read_bytes;
            }
        })
    }

    fn struct_construction_fields(&self) -> impl Iterator<Item = TokenStream2> + '_ {
        (0..self.fields.unnamed.len()).map(|i| {
            let var_name = Locals::field(i);
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
    let locals = Locals::new();
    let Locals { input, out, total_read, total_write, total_size, .. } = &locals;

    match fields {
        Fields::Named(named_fields) => {
            let generator = NamedFieldsGenerator::new(named_fields, &locals);
            let pack_fields = generator.pack_fields();
            let packed_size_fields = generator.packed_size_fields();
            let unpack_fields = generator.unpack_fields();
            let struct_fields = generator.struct_construction_fields();

            quote! {
                impl #impl_generics ::onc_xdr::Pack for #name #ty_generics
                #where_clause {
                    fn packed_size(&self) -> usize {
                        let mut #total_size = 0;
                        #(#packed_size_fields)*
                        #total_size
                    }

                    fn pack(&self, #out: &mut impl std::io::Write) -> ::onc_xdr::Result<usize> {
                        use ::onc_xdr::Pack;
                        let mut #total_write = 0;
                        #(#pack_fields)*
                        Ok(#total_write)
                    }
                }
                impl #impl_generics ::onc_xdr::Unpack for #name #ty_generics
                #where_clause {
                    fn unpack(#input: &mut impl std::io::Read) -> ::onc_xdr::Result<(Self, usize)> {
                        use ::onc_xdr::Unpack;
                        let mut #total_read = 0;
                        #(#unpack_fields)*
                        Ok((Self { #(#struct_fields)* }, #total_read))
                    }
                }
            }
        },
        Fields::Unnamed(unnamed_fields) => {
            let generator = UnnamedFieldsGenerator::new(unnamed_fields, &locals);
            let pack_fields = generator.pack_fields();
            let packed_size_fields = generator.packed_size_fields();
            let unpack_fields = generator.unpack_fields();
            let struct_fields = generator.struct_construction_fields();

            quote! {
                impl #impl_generics ::onc_xdr::Pack for #name #ty_generics
                #where_clause {
                    fn packed_size(&self) -> usize {
                        let mut #total_size = 0;
                        #(#packed_size_fields)*
                        #total_size
                    }

                    fn pack(&self, #out: &mut impl std::io::Write) -> ::onc_xdr::Result<usize> {
                        use ::onc_xdr::Pack;
                        let mut #total_write = 0;
                        #(#pack_fields)*
                        Ok(#total_write)
                    }
                }
                impl #impl_generics ::onc_xdr::Unpack for #name #ty_generics
                #where_clause {
                    fn unpack(#input: &mut impl std::io::Read) -> ::onc_xdr::Result<(Self, usize)> {
                        use ::onc_xdr::Unpack;
                        let mut #total_read = 0;
                        #(#unpack_fields)*
                        Ok((Self(#(#struct_fields),*), #total_read))
                    }
                }
            }
        },
        Fields::Unit => {
            quote! {
                impl #impl_generics ::onc_xdr::Pack for #name #ty_generics
                #where_clause {
                    fn packed_size(&self) -> usize {
                        0
                    }

                    fn pack(&self, _out: &mut impl std::io::Write) -> ::onc_xdr::Result<usize> {
                        Ok(0)
                    }
                }
                impl #impl_generics ::onc_xdr::Unpack for #name #ty_generics
                #where_clause {
                    fn unpack(_input: &mut impl std::io::Read) -> ::onc_xdr::Result<(Self, usize)> {
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
fn generate_complex_enum_pack_variant(variant: &Variant, locals: &Locals) -> TokenStream2 {
    let ident = &variant.ident;
    let Locals { out, val, len, .. } = locals;
    if is_catch_all(variant) {
        // The catch-all carries the raw discriminant it was decoded from.
        return quote! {
            Self::#ident(#val) => #val.pack(#out),
        };
    }
    let xdr_value = variant_tag(variant);

    match &variant.fields {
        Fields::Unit => {
            quote! {
                Self::#ident => #xdr_value.pack(#out),
            }
        },
        Fields::Unnamed(fields) if fields.unnamed.len() == 1 => {
            quote! {
                Self::#ident(#val) => {
                    let mut #len = #xdr_value.pack(#out)?;
                    #len += #val.pack(#out)?;
                    Ok(#len)
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
fn generate_complex_enum_packed_size_variant(variant: &Variant, locals: &Locals) -> TokenStream2 {
    let ident = &variant.ident;
    let val = &locals.val;
    if is_catch_all(variant) {
        return quote! {
            Self::#ident(_) => 4,
        };
    }

    match &variant.fields {
        Fields::Unit => {
            quote! {
                Self::#ident => 4,
            }
        },
        Fields::Unnamed(fields) if fields.unnamed.len() == 1 => {
            quote! {
                Self::#ident(#val) => 4 + #val.packed_size(),
            }
        },
        _ => panic!("Invalid complex enum variant: {ident}"),
    }
}

/// Emits the unpack arm for one non-catch-all variant of a data-carrying enum.
fn generate_complex_enum_unpack_variant(variant: &Variant, locals: &Locals) -> TokenStream2 {
    let ident = &variant.ident;
    let Locals { input, bytes_read, val, val_bytes, .. } = locals;
    let xdr_value = variant_tag(variant);

    match &variant.fields {
        Fields::Unit => {
            quote! {
                #xdr_value => Ok(Self::#ident),
            }
        },
        Fields::Unnamed(fields) if fields.unnamed.len() == 1 => {
            quote! {
                #xdr_value => {
                    let (#val, #val_bytes) = ::onc_xdr::Unpack::unpack(#input)?;
                    #bytes_read += #val_bytes;
                    Ok(Self::#ident(#val))
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
    let locals = Locals::new();
    let Locals { input, out, tag, bytes_read, result, .. } = &locals;

    let pack_variants = data.variants.iter().map(|v| {
        let ident = &v.ident;
        quote! {
            Self::#ident => (*self as u32).pack(#out),
        }
    });

    let unpack_variants = data.variants.iter().map(|v| {
        let ident = &v.ident;
        quote! {
            x if x == Self::#ident as u32 => Ok(Self::#ident),
        }
    });

    quote! {
        impl #impl_generics ::onc_xdr::Pack for #name #ty_generics
        #where_clause {
            fn packed_size(&self) -> usize {
                4
            }

            fn pack(&self, #out: &mut impl std::io::Write) -> ::onc_xdr::Result<usize> {
                use ::onc_xdr::Pack;
                match self {
                    #(#pack_variants)*
                }
            }
        }
        impl #impl_generics ::onc_xdr::Unpack for #name #ty_generics
        #where_clause {
            fn unpack(#input: &mut impl std::io::Read) -> ::onc_xdr::Result<(Self, usize)> {
                use ::onc_xdr::Unpack;
                let (#tag, #bytes_read) = u32::unpack(#input)?;
                let #result = match #tag {
                    #(#unpack_variants)*
                    _ => Err(::onc_xdr::Error::InvalidEnumValue(#tag)),
                };
                #result.map(|value| (value, #bytes_read))
            }
        }
    }
}

/// Generates `Pack`/`Unpack` for an enum with data-carrying variants.
///
/// These map onto an XDR discriminated union: the 4-byte discriminant from
/// `#[xdr(N)]` (or `= N`), followed by the arm's payload. An `#[xdr(other)]`
/// variant receives any discriminant no other arm claims.
fn generate_complex_enum_impl(name: &Ident, generics: &syn::Generics, data: &DataEnum) -> TokenStream2 {
    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();
    let locals = Locals::new();
    let Locals { input, out, tag, bytes_read, result, .. } = &locals;

    // Fail at expansion time rather than emitting code that cannot compile.
    for variant in &data.variants {
        if let Err(err) = validate_complex_enum_variant(variant) {
            panic!("{}", err);
        }
    }
    let mut catch_alls = data.variants.iter().filter(|v| is_catch_all(v));
    let catch_all = catch_alls.next();
    if let Some(extra) = catch_alls.next() {
        panic!("Only one variant may be #[xdr(other)]; '{}' is a second", extra.ident);
    }
    if let Some(v) = catch_all
        && !matches!(&v.fields, Fields::Unnamed(fields) if fields.unnamed.len() == 1)
    {
        panic!("The #[xdr(other)] variant '{}' must have exactly one unnamed u32 field", v.ident);
    }

    let pack_variants = data.variants.iter().map(|v| generate_complex_enum_pack_variant(v, &locals));
    let packed_size_variants = data.variants.iter().map(|v| generate_complex_enum_packed_size_variant(v, &locals));
    let unpack_variants = data.variants.iter().filter(|v| !is_catch_all(v)).map(|v| generate_complex_enum_unpack_variant(v, &locals));
    let fallback = catch_all.map_or_else(
        || quote! { _ => Err(::onc_xdr::Error::InvalidEnumValue(#tag)), },
        |v| {
            let ident = &v.ident;
            quote! { _ => Ok(Self::#ident(#tag)), }
        },
    );

    quote! {
        impl #impl_generics ::onc_xdr::Pack for #name #ty_generics
        #where_clause {
            fn packed_size(&self) -> usize {
                match self {
                    #(#packed_size_variants)*
                }
            }

            fn pack(&self, #out: &mut impl std::io::Write) -> ::onc_xdr::Result<usize> {
                use ::onc_xdr::Pack;
                match self {
                    #(#pack_variants)*
                }
            }
        }
        impl #impl_generics ::onc_xdr::Unpack for #name #ty_generics
        #where_clause {
            fn unpack(#input: &mut impl std::io::Read) -> ::onc_xdr::Result<(Self, usize)> {
                use ::onc_xdr::Unpack;
                let (#tag, mut #bytes_read) = u32::unpack(#input)?;
                let #result = match #tag {
                    #(#unpack_variants)*
                    #fallback
                };
                #result.map(|value| (value, #bytes_read))
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
/// named fields, on a data-carrying enum variant missing its discriminant, on
/// a malformed `#[xdr(...)]` attribute, or on more than one `#[xdr(other)]`.
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

// Dev-dependencies (onc_xdr, trybuild) are visible to the lib test target
// but only used from the integration test binary in tests/derive.rs.
#[cfg(test)]
mod _dev_dep_anchors {
    use onc_xdr as _;
    use trybuild as _;
}

#[cfg(doctest)]
#[doc = include_str!("../README.md")]
struct ReadmeDoctests;
