//! Integration tests for the nfswolf binary and its protocol crates.
//!
//! One test binary rather than one per file: it links once instead of six
//! times, and the shared `helpers` module is checked for dead code across all
//! of its callers instead of being exempted file by file.

#![allow(
    unused_crate_dependencies,
    unused_qualifications,
    missing_docs,
    missing_debug_implementations,
    unused_import_braces,
    unused_lifetimes,
    single_use_lifetimes,
    trivial_casts,
    trivial_numeric_casts,
    elided_lifetimes_in_paths,
    explicit_outlives_requirements,
    variant_size_differences,
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    clippy::cargo,
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_precision_loss,
    clippy::cast_sign_loss,
    clippy::missing_asserts_for_indexing,
    let_underscore_drop,
    reason = "integration test  --  all lints suppressed per project policy; nfswolf's own dependencies are visible here but used only through the binary"
)]

mod helpers;

mod analyzer_test;
mod credential_test;
mod escape_test;
mod nfs3_protocol_test;
mod scan_test;
mod xdr_fuzz_test;
