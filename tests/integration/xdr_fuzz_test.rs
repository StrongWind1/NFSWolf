//! Proptest fuzz harness for XDR decoders across all protocol crates.
//!
//! Feeds random/adversarial byte sequences into Unpack implementations to
//! catch panics, infinite loops, or excessive allocations from malformed
//! wire data. Every decoder must return Ok or Err -- never crash.
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
    let_underscore_drop,
    reason = "integration test  --  all lints suppressed per project policy"
)]

use std::io::Cursor;

use proptest::prelude::*;

use onc_xdr::{Opaque, Pack, Unpack};

// --- Configuration ---

fn fuzz_config() -> ProptestConfig {
    ProptestConfig { cases: 256, ..ProptestConfig::default() }
}

fn fuzz_bytes() -> impl Strategy<Value = Vec<u8>> {
    proptest::collection::vec(any::<u8>(), 0..1024)
}

// --- XDR primitives (nfswolf-xdr) ---

proptest! {
    #![proptest_config(fuzz_config())]

    #[test]
    fn fuzz_u32_unpack(data in fuzz_bytes()) {
        let _ = u32::unpack(&mut Cursor::new(&data));
    }

    #[test]
    fn fuzz_u64_unpack(data in fuzz_bytes()) {
        let _ = u64::unpack(&mut Cursor::new(&data));
    }

    #[test]
    fn fuzz_bool_unpack(data in fuzz_bytes()) {
        let _ = bool::unpack(&mut Cursor::new(&data));
    }

    #[test]
    fn fuzz_opaque_unpack(data in fuzz_bytes()) {
        let _ = Opaque::unpack(&mut Cursor::new(&data));
    }

    #[test]
    fn fuzz_vec_u32_unpack(data in fuzz_bytes()) {
        let _ = Vec::<u32>::unpack(&mut Cursor::new(&data));
    }
}

// --- NFSv3 types (nfswolf-nfs3) ---

proptest! {
    #![proptest_config(fuzz_config())]

    #[test]
    fn fuzz_nfsstat3_unpack(data in fuzz_bytes()) {
        let _ = nfs_v3::wire::nfsstat3::unpack(&mut Cursor::new(&data));
    }

    #[test]
    fn fuzz_ftype3_unpack(data in fuzz_bytes()) {
        let _ = nfs_v3::wire::ftype3::unpack(&mut Cursor::new(&data));
    }

    #[test]
    fn fuzz_fattr3_unpack(data in fuzz_bytes()) {
        let _ = nfs_v3::wire::fattr3::unpack(&mut Cursor::new(&data));
    }

    #[test]
    fn fuzz_nfs_fh3_unpack(data in fuzz_bytes()) {
        let _ = nfs_v3::wire::nfs_fh3::unpack(&mut Cursor::new(&data));
    }

    #[test]
    fn fuzz_mountres3_unpack(data in fuzz_bytes()) {
        let _ = nfs_v3::wire::mount::mountres3::unpack(&mut Cursor::new(&data));
    }
}

// --- NFSv4 types (nfswolf-nfs4) ---

proptest! {
    #![proptest_config(fuzz_config())]

    #[test]
    #[ignore]
    fn fuzz_compound_res_unpack(data in fuzz_bytes()) {
        let _ = nfs_v4::CompoundRes::unpack(&mut Cursor::new(&data));
    }

    #[test]
    fn fuzz_nfs4_status_from_u32(v: u32) {
        // Total function: must never panic for any input.
        let _ = nfs_v4::Nfs4Status::from_u32(v);
    }
}

// --- RPC types (nfswolf-rpc) ---

proptest! {
    #![proptest_config(fuzz_config())]

    #[test]
    #[ignore]
    fn fuzz_rpc_msg_unpack(data in fuzz_bytes()) {
        let _ = onc_rpc_client::rpc::rpc_msg::unpack(&mut Cursor::new(&data));
    }

    #[test]
    fn fuzz_accepted_reply_unpack(data in fuzz_bytes()) {
        let _ = onc_rpc_client::rpc::accepted_reply::unpack(&mut Cursor::new(&data));
    }
}

// --- NFSv2 types (nfswolf-nfs2) ---

proptest! {
    #![proptest_config(fuzz_config())]

    #[test]
    fn fuzz_nfs2_nfsstat_unpack(data in fuzz_bytes()) {
        let _ = nfs_v2::Nfs2Stat::unpack(&mut Cursor::new(&data));
    }

    #[test]
    fn fuzz_nfs2_diropres_unpack(data in fuzz_bytes()) {
        let _ = nfs_v2::wire::DirOpRes::unpack(&mut Cursor::new(&data));
    }

    #[test]
    fn fuzz_nfs2_attrstatres_unpack(data in fuzz_bytes()) {
        let _ = nfs_v2::wire::AttrStatRes::unpack(&mut Cursor::new(&data));
    }
}

// --- Round-trip tests: pack then unpack, assert equality ---

proptest! {
    #![proptest_config(fuzz_config())]

    #[test]
    fn roundtrip_u32(val: u32) {
        let mut buf = Vec::new();
        let written = val.pack(&mut buf).unwrap();
        let (decoded, read) = u32::unpack(&mut Cursor::new(&buf)).unwrap();
        prop_assert_eq!(decoded, val);
        prop_assert_eq!(read, written);
    }

    #[test]
    fn roundtrip_u64(val: u64) {
        let mut buf = Vec::new();
        let written = val.pack(&mut buf).unwrap();
        let (decoded, read) = u64::unpack(&mut Cursor::new(&buf)).unwrap();
        prop_assert_eq!(decoded, val);
        prop_assert_eq!(read, written);
    }

    #[test]
    fn roundtrip_bool(val: bool) {
        let mut buf = Vec::new();
        let written = val.pack(&mut buf).unwrap();
        let (decoded, read) = bool::unpack(&mut Cursor::new(&buf)).unwrap();
        prop_assert_eq!(decoded, val);
        prop_assert_eq!(read, written);
    }

    #[test]
    fn roundtrip_opaque(data in proptest::collection::vec(any::<u8>(), 0..256)) {
        let opaque = Opaque::owned(data.clone());
        let mut buf = Vec::new();
        let written = opaque.pack(&mut buf).unwrap();
        let (decoded, read) = Opaque::unpack(&mut Cursor::new(&buf)).unwrap();
        prop_assert_eq!(decoded.as_ref(), data.as_slice());
        prop_assert_eq!(read, written);
    }

    #[test]
    fn roundtrip_vec_u32(data in proptest::collection::vec(any::<u32>(), 0..64)) {
        let mut buf = Vec::new();
        let written = data.pack(&mut buf).unwrap();
        let (decoded, read) = Vec::<u32>::unpack(&mut Cursor::new(&buf)).unwrap();
        prop_assert_eq!(decoded, data);
        prop_assert_eq!(read, written);
    }
}
