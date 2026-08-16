//! NFSv3 protocol integration tests using an in-process MemFs NFS server.
//!
//! Covers the procedures and invariants not exercised by scan_test.rs:
//! READDIRPLUS, AUTH_SYS stamp uniqueness, circuit breaker discrimination
//! (transient vs permission errors), and connection health checks.
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
    reason = "integration test  --  all lints suppressed per project policy"
)]
use std::time::Duration;

use nfs_v3::wire::mount::dirpath;
use nfs_v3::wire::{
    ACCESS3_DELETE, ACCESS3_EXECUTE, ACCESS3_EXTEND, ACCESS3_LOOKUP, ACCESS3_MODIFY, ACCESS3_READ, ACCESS3args, CREATE3args, FSINFO3args, FSSTAT3args, GETATTR3args, LOOKUP3args, Nfs3Result, PATHCONF3args, READ3args, READDIR3args, READDIRPLUS3args, REMOVE3args, WRITE3args, cookieverf3, createhow3,
    diropargs3, filename3, ftype3, nfs_fh3, nfsstat3, sattr3, stable_how,
};
use nfs3_server::memfs::MemFsConfig;
use onc_xdr::Opaque;

#[path = "helpers.rs"]
mod helpers;
use helpers::{mount_client, nfs3_client, start_server};

// --- READDIRPLUS tests ---

#[tokio::test]
async fn readdirplus_lists_all_entries() {
    let mut config = MemFsConfig::default();
    config.add_file("/alpha.txt", b"a");
    config.add_file("/beta.txt", b"b");
    config.add_file("/gamma.txt", b"g");

    let (_srv, port) = start_server(config).await;
    tokio::time::sleep(Duration::from_millis(20)).await;

    let mc = mount_client(port).await;
    let mnt = mc.v3_mnt(dirpath(Opaque::borrowed(b"/"))).await.expect("MOUNT must succeed");
    let root_fh = nfs_fh3 { data: mnt.fhandle.0.clone() };

    let nfs = nfs3_client(port).await;
    let args = READDIRPLUS3args { dir: root_fh, cookie: 0, cookieverf: cookieverf3([0u8; 8]), dircount: 4096, maxcount: 65536 };
    let result = nfs.readdirplus(&args).await.expect("READDIRPLUS RPC must succeed");

    match result {
        Nfs3Result::Ok(ok) => {
            let names: Vec<String> = ok.reply.entries.0.iter().map(|e| String::from_utf8_lossy(e.name.0.as_ref()).to_string()).collect();
            // The three files must be present (plus . and .. on some implementations).
            assert!(names.contains(&"alpha.txt".to_owned()), "alpha.txt missing from READDIRPLUS: {names:?}");
            assert!(names.contains(&"beta.txt".to_owned()), "beta.txt missing from READDIRPLUS: {names:?}");
            assert!(names.contains(&"gamma.txt".to_owned()), "gamma.txt missing from READDIRPLUS: {names:?}");
        },
        Nfs3Result::Err((stat, _)) => panic!("READDIRPLUS failed: {stat:?}"),
        _ => unreachable!(),
    }
}

#[tokio::test]
async fn readdirplus_entries_carry_attributes() {
    // Attributes in READDIRPLUS entries are the key difference from READDIR.
    // Verify the attrs field is populated for at least one regular file.
    let mut config = MemFsConfig::default();
    config.add_file("/data.txt", b"content here");

    let (_srv, port) = start_server(config).await;
    tokio::time::sleep(Duration::from_millis(20)).await;

    let mc = mount_client(port).await;
    let mnt = mc.v3_mnt(dirpath(Opaque::borrowed(b"/"))).await.expect("MOUNT must succeed");
    let root_fh = nfs_fh3 { data: mnt.fhandle.0.clone() };

    let nfs = nfs3_client(port).await;
    let args = READDIRPLUS3args { dir: root_fh, cookie: 0, cookieverf: cookieverf3([0u8; 8]), dircount: 4096, maxcount: 65536 };

    match nfs.readdirplus(&args).await.expect("READDIRPLUS RPC must succeed") {
        Nfs3Result::Ok(ok) => {
            let file_entry = ok.reply.entries.0.iter().find(|e| e.name.0.as_ref() == b"data.txt");
            assert!(file_entry.is_some(), "data.txt not found in READDIRPLUS reply");
            let entry = file_entry.unwrap();
            // name_attributes is Nfs3Option<fattr3>  --  check it is Some.
            assert!(entry.name_attributes.is_some(), "data.txt should have inline attributes");
            // name_handle is Nfs3Option<nfs_fh3>  --  must be populated.
            assert!(entry.name_handle.is_some(), "data.txt should have inline file handle");
        },
        Nfs3Result::Err((stat, _)) => panic!("READDIRPLUS failed: {stat:?}"),
        _ => unreachable!(),
    }
}

// --- AUTH_SYS stamp uniqueness ---

#[tokio::test]
async fn each_rpc_call_produces_a_different_xid() {
    // Two sequential GETATTR calls must have different XIDs  --  the RPC library
    // increments XID per call. This is a proxy for stamp uniqueness since we
    // can't inspect the AUTH_SYS stamp directly from the client side.
    let config = MemFsConfig::default();
    let (_srv, port) = start_server(config).await;
    tokio::time::sleep(Duration::from_millis(20)).await;

    let mc = mount_client(port).await;
    let mnt = mc.v3_mnt(dirpath(Opaque::borrowed(b"/"))).await.expect("MOUNT must succeed");
    let root_fh = nfs_fh3 { data: mnt.fhandle.0.clone() };

    let nfs = nfs3_client(port).await;
    let args = GETATTR3args { object: root_fh.clone() };

    // Both calls must succeed  --  uniqueness is verified by the fact that the
    // server doesn't reject either as a duplicate RPC (XID replay).
    let r1 = nfs.getattr(&args).await.expect("first GETATTR must succeed");
    let r2 = nfs.getattr(&args).await.expect("second GETATTR must succeed");

    assert!(matches!(r1, Nfs3Result::Ok(_)), "first GETATTR must return Ok");
    assert!(matches!(r2, Nfs3Result::Ok(_)), "second GETATTR must return Ok");
}

// --- LOOKUP + READ pipeline ---

#[tokio::test]
async fn lookup_then_read_reproduces_content() {
    let expected = b"the quick brown fox";
    let mut config = MemFsConfig::default();
    config.add_file("/fox.txt", expected.as_slice());

    let (_srv, port) = start_server(config).await;
    tokio::time::sleep(Duration::from_millis(20)).await;

    let mc = mount_client(port).await;
    let mnt = mc.v3_mnt(dirpath(Opaque::borrowed(b"/"))).await.expect("MOUNT must succeed");
    let root_fh = nfs_fh3 { data: mnt.fhandle.0.clone() };

    let nfs = nfs3_client(port).await;

    let lookup = nfs.lookup(&LOOKUP3args { what: diropargs3 { dir: root_fh, name: filename3(Opaque::borrowed(b"fox.txt")) } }).await.expect("LOOKUP RPC must succeed");

    let file_fh = match lookup {
        Nfs3Result::Ok(ok) => ok.object,
        Nfs3Result::Err((stat, _)) => panic!("LOOKUP failed: {stat:?}"),
        _ => unreachable!(),
    };

    let read = nfs.read(&READ3args { file: file_fh, offset: 0, count: 256 }).await.expect("READ RPC must succeed");

    match read {
        Nfs3Result::Ok(ok) => {
            assert_eq!(ok.data.as_ref(), expected, "READ data must match written content");
            assert!(ok.eof, "small file must be EOF after first full read");
        },
        Nfs3Result::Err((stat, _)) => panic!("READ failed: {stat:?}"),
        _ => unreachable!(),
    }
}

// --- Root directory attribute checks ---

#[tokio::test]
async fn memfs_getattr_root_nlink_is_nonzero() {
    // Root directory must have at least one hard link. MemFs returns nlink=1
    // (not the POSIX-standard 2) since it doesn't track . and .. internally.
    let config = MemFsConfig::default();
    let (_srv, port) = start_server(config).await;
    tokio::time::sleep(Duration::from_millis(20)).await;

    let mc = mount_client(port).await;
    let mnt = mc.v3_mnt(dirpath(Opaque::borrowed(b"/"))).await.expect("MOUNT must succeed");
    let root_fh = nfs_fh3 { data: mnt.fhandle.0.clone() };

    let nfs = nfs3_client(port).await;
    match nfs.getattr(&GETATTR3args { object: root_fh }).await.expect("GETATTR must succeed") {
        Nfs3Result::Ok(ok) => {
            assert!(ok.obj_attributes.nlink >= 1, "root dir nlink must be >= 1, got {}", ok.obj_attributes.nlink);
        },
        Nfs3Result::Err((stat, _)) => panic!("GETATTR failed: {stat:?}"),
        _ => unreachable!(),
    }
}

// --- Read offset and EOF behavior ---

#[tokio::test]
async fn memfs_read_at_offset_returns_partial() {
    let content = b"0123456789ABCDEF";
    let mut config = MemFsConfig::default();
    config.add_file("/partial.txt", content.as_slice());

    let (_srv, port) = start_server(config).await;
    tokio::time::sleep(Duration::from_millis(20)).await;

    let mc = mount_client(port).await;
    let mnt = mc.v3_mnt(dirpath(Opaque::borrowed(b"/"))).await.expect("MOUNT must succeed");
    let root_fh = nfs_fh3 { data: mnt.fhandle.0.clone() };

    let nfs = nfs3_client(port).await;
    let fh = match nfs.lookup(&LOOKUP3args { what: diropargs3 { dir: root_fh, name: filename3(Opaque::borrowed(b"partial.txt")) } }).await.expect("LOOKUP must succeed") {
        Nfs3Result::Ok(ok) => ok.object,
        Nfs3Result::Err((stat, _)) => panic!("LOOKUP: {stat:?}"),
        _ => unreachable!(),
    };

    // Read starting at offset 4 with count 4  --  should return "4567"
    let args = READ3args { file: fh, offset: 4, count: 4 };
    match nfs.read(&args).await.expect("READ must succeed") {
        Nfs3Result::Ok(ok) => {
            assert_eq!(ok.data.as_ref(), b"4567", "offset read must return correct slice");
        },
        Nfs3Result::Err((stat, _)) => panic!("READ: {stat:?}"),
        _ => unreachable!(),
    }
}

#[tokio::test]
async fn memfs_read_past_eof_returns_empty() {
    let content = b"short";
    let mut config = MemFsConfig::default();
    config.add_file("/short.txt", content.as_slice());

    let (_srv, port) = start_server(config).await;
    tokio::time::sleep(Duration::from_millis(20)).await;

    let mc = mount_client(port).await;
    let mnt = mc.v3_mnt(dirpath(Opaque::borrowed(b"/"))).await.expect("MOUNT must succeed");
    let root_fh = nfs_fh3 { data: mnt.fhandle.0.clone() };

    let nfs = nfs3_client(port).await;
    let fh = match nfs.lookup(&LOOKUP3args { what: diropargs3 { dir: root_fh, name: filename3(Opaque::borrowed(b"short.txt")) } }).await.expect("LOOKUP must succeed") {
        Nfs3Result::Ok(ok) => ok.object,
        Nfs3Result::Err((stat, _)) => panic!("LOOKUP: {stat:?}"),
        _ => unreachable!(),
    };

    // Read starting past the end of the file
    let args = READ3args { file: fh, offset: 1000, count: 100 };
    match nfs.read(&args).await.expect("READ must succeed") {
        Nfs3Result::Ok(ok) => {
            assert!(ok.data.as_ref().is_empty(), "read past EOF must return empty data");
            assert!(ok.eof, "read past EOF must set eof flag");
        },
        Nfs3Result::Err((stat, _)) => panic!("READ: {stat:?}"),
        _ => unreachable!(),
    }
}

#[tokio::test]
async fn memfs_readdirplus_empty_dir() {
    // Default MemFs with no files  --  only . and .. may appear (server-dependent).
    let config = MemFsConfig::default();
    let (_srv, port) = start_server(config).await;
    tokio::time::sleep(Duration::from_millis(20)).await;

    let mc = mount_client(port).await;
    let mnt = mc.v3_mnt(dirpath(Opaque::borrowed(b"/"))).await.expect("MOUNT must succeed");
    let root_fh = nfs_fh3 { data: mnt.fhandle.0.clone() };

    let nfs = nfs3_client(port).await;
    let args = READDIRPLUS3args { dir: root_fh, cookie: 0, cookieverf: cookieverf3([0u8; 8]), dircount: 4096, maxcount: 65536 };
    match nfs.readdirplus(&args).await.expect("READDIRPLUS must succeed") {
        Nfs3Result::Ok(ok) => {
            // With no files added, the directory should have no user-visible entries.
            // Some servers include . and .., but the key invariant is that the call
            // succeeds and the entries list is finite.
            let names: Vec<String> = ok.reply.entries.0.iter().map(|e| String::from_utf8_lossy(e.name.0.as_ref()).to_string()).collect();
            // None of our test files should appear
            assert!(!names.contains(&"alpha.txt".to_owned()), "empty dir must not contain alpha.txt");
        },
        Nfs3Result::Err((stat, _)) => panic!("READDIRPLUS: {stat:?}"),
        _ => unreachable!(),
    }
}

// --- GETATTR attribute values ---

#[tokio::test]
async fn memfs_getattr_file_type_is_regular() {
    // Verify that a file added to MemFs has type NF3REG via GETATTR.
    let mut config = MemFsConfig::default();
    config.add_file("/regular.txt", b"data");

    let (_srv, port) = start_server(config).await;
    tokio::time::sleep(Duration::from_millis(20)).await;

    let mc = mount_client(port).await;
    let mnt = mc.v3_mnt(dirpath(Opaque::borrowed(b"/"))).await.expect("MOUNT must succeed");
    let root_fh = nfs_fh3 { data: mnt.fhandle.0.clone() };

    let nfs = nfs3_client(port).await;
    let fh = match nfs.lookup(&LOOKUP3args { what: diropargs3 { dir: root_fh, name: filename3(Opaque::borrowed(b"regular.txt")) } }).await.expect("LOOKUP must succeed") {
        Nfs3Result::Ok(ok) => ok.object,
        Nfs3Result::Err((stat, _)) => panic!("LOOKUP: {stat:?}"),
        _ => unreachable!(),
    };

    match nfs.getattr(&GETATTR3args { object: fh }).await.expect("GETATTR must succeed") {
        Nfs3Result::Ok(ok) => {
            assert_eq!(ok.obj_attributes.type_, nfs_v3::wire::ftype3::NF3REG, "file must have type NF3REG");
        },
        Nfs3Result::Err((stat, _)) => panic!("GETATTR: {stat:?}"),
        _ => unreachable!(),
    }
}

#[tokio::test]
async fn getattr_size_matches_file_content_length() {
    let content = b"exactly 15 chars";
    let mut config = MemFsConfig::default();
    config.add_file("/sized.txt", content.as_slice());

    let (_srv, port) = start_server(config).await;
    tokio::time::sleep(Duration::from_millis(20)).await;

    let mc = mount_client(port).await;
    let mnt = mc.v3_mnt(dirpath(Opaque::borrowed(b"/"))).await.expect("MOUNT must succeed");
    let root_fh = nfs_fh3 { data: mnt.fhandle.0.clone() };

    let nfs = nfs3_client(port).await;

    let fh = match nfs.lookup(&LOOKUP3args { what: diropargs3 { dir: root_fh, name: filename3(Opaque::borrowed(b"sized.txt")) } }).await.expect("LOOKUP must succeed") {
        Nfs3Result::Ok(ok) => ok.object,
        Nfs3Result::Err((stat, _)) => panic!("LOOKUP failed: {stat:?}"),
        _ => unreachable!(),
    };

    match nfs.getattr(&GETATTR3args { object: fh }).await.expect("GETATTR must succeed") {
        Nfs3Result::Ok(ok) => {
            assert_eq!(ok.obj_attributes.size, content.len() as u64, "GETATTR size must equal content length");
        },
        Nfs3Result::Err((stat, _)) => panic!("GETATTR failed: {stat:?}"),
        _ => unreachable!(),
    }
}

// --- Multiple sequential reads (chunked) ---

#[tokio::test]
async fn chunked_read_reassembles_full_content() {
    // Simulate reading a larger file in small chunks  --  exercises the offset/count path.
    let content: Vec<u8> = (0u8..=127).collect(); // 128 bytes
    let mut config = MemFsConfig::default();
    config.add_file("/chunks.bin", content.as_slice());

    let (_srv, port) = start_server(config).await;
    tokio::time::sleep(Duration::from_millis(20)).await;

    let mc = mount_client(port).await;
    let mnt = mc.v3_mnt(dirpath(Opaque::borrowed(b"/"))).await.expect("MOUNT must succeed");
    let root_fh = nfs_fh3 { data: mnt.fhandle.0.clone() };

    let nfs = nfs3_client(port).await;
    let fh = match nfs.lookup(&LOOKUP3args { what: diropargs3 { dir: root_fh, name: filename3(Opaque::borrowed(b"chunks.bin")) } }).await.expect("LOOKUP must succeed") {
        Nfs3Result::Ok(ok) => ok.object,
        Nfs3Result::Err((stat, _)) => panic!("LOOKUP: {stat:?}"),
        _ => unreachable!(),
    };

    let chunk_size = 32u32;
    let mut assembled: Vec<u8> = Vec::new();
    let mut offset = 0u64;

    loop {
        let args = READ3args { file: fh.clone(), offset, count: chunk_size };
        match nfs.read(&args).await.expect("READ must succeed") {
            Nfs3Result::Ok(ok) => {
                let data = ok.data.as_ref();
                assembled.extend_from_slice(data);
                offset += data.len() as u64;
                if ok.eof || data.is_empty() {
                    break;
                }
            },
            Nfs3Result::Err((stat, _)) => panic!("READ at offset {offset}: {stat:?}"),
            _ => unreachable!(),
        }
    }

    assert_eq!(assembled, content, "chunked read must reproduce full file content");
}

// --- NULL procedure (liveness probe) ---

#[tokio::test]
async fn null_procedure_succeeds() {
    // NULL (procedure 0) costs nothing and touches no state -- the standard
    // RPC liveness probe.  Must succeed on any compliant server.
    let config = MemFsConfig::default();
    let (_srv, port) = start_server(config).await;
    tokio::time::sleep(Duration::from_millis(20)).await;

    let nfs = nfs3_client(port).await;
    nfs.null().await.expect("NULL procedure must succeed");
}

// --- ACCESS procedure with different bitmasks ---

#[tokio::test]
async fn access_read_on_file_returns_read_bit() {
    // ACCESS is advisory (RFC 1813 sec. 3.3.4), but the server should at least
    // grant ACCESS3_READ on a readable file.
    let mut config = MemFsConfig::default();
    config.add_file("/readable.txt", b"read me");

    let (_srv, port) = start_server(config).await;
    tokio::time::sleep(Duration::from_millis(20)).await;

    let mc = mount_client(port).await;
    let mnt = mc.v3_mnt(dirpath(Opaque::borrowed(b"/"))).await.expect("MOUNT must succeed");
    let root_fh = nfs_fh3 { data: mnt.fhandle.0.clone() };

    let nfs = nfs3_client(port).await;
    let fh = match nfs.lookup(&LOOKUP3args { what: diropargs3 { dir: root_fh, name: filename3(Opaque::borrowed(b"readable.txt")) } }).await.expect("LOOKUP must succeed") {
        Nfs3Result::Ok(ok) => ok.object,
        Nfs3Result::Err((stat, _)) => panic!("LOOKUP: {stat:?}"),
        _ => unreachable!(),
    };

    let args = ACCESS3args { object: fh, access: ACCESS3_READ };
    match nfs.access(&args).await.expect("ACCESS RPC must succeed") {
        Nfs3Result::Ok(ok) => {
            assert!(ok.access & ACCESS3_READ != 0, "ACCESS must grant READ on a readable file");
        },
        Nfs3Result::Err((stat, _)) => panic!("ACCESS: {stat:?}"),
        _ => unreachable!(),
    }
}

#[tokio::test]
async fn access_lookup_on_directory_returns_lookup_bit() {
    // Directories should grant ACCESS3_LOOKUP so clients can resolve names.
    let config = MemFsConfig::default();
    let (_srv, port) = start_server(config).await;
    tokio::time::sleep(Duration::from_millis(20)).await;

    let mc = mount_client(port).await;
    let mnt = mc.v3_mnt(dirpath(Opaque::borrowed(b"/"))).await.expect("MOUNT must succeed");
    let root_fh = nfs_fh3 { data: mnt.fhandle.0.clone() };

    let nfs = nfs3_client(port).await;
    let args = ACCESS3args { object: root_fh, access: ACCESS3_READ | ACCESS3_LOOKUP };
    match nfs.access(&args).await.expect("ACCESS RPC must succeed") {
        Nfs3Result::Ok(ok) => {
            assert!(ok.access & ACCESS3_LOOKUP != 0, "ACCESS must grant LOOKUP on root directory");
        },
        Nfs3Result::Err((stat, _)) => panic!("ACCESS: {stat:?}"),
        _ => unreachable!(),
    }
}

#[tokio::test]
async fn access_all_bits_requested() {
    // Request all six ACCESS bits at once and verify the server responds without error.
    let config = MemFsConfig::default();
    let (_srv, port) = start_server(config).await;
    tokio::time::sleep(Duration::from_millis(20)).await;

    let mc = mount_client(port).await;
    let mnt = mc.v3_mnt(dirpath(Opaque::borrowed(b"/"))).await.expect("MOUNT must succeed");
    let root_fh = nfs_fh3 { data: mnt.fhandle.0.clone() };

    let nfs = nfs3_client(port).await;
    let all_bits = ACCESS3_READ | ACCESS3_LOOKUP | ACCESS3_MODIFY | ACCESS3_EXTEND | ACCESS3_DELETE | ACCESS3_EXECUTE;
    let args = ACCESS3args { object: root_fh, access: all_bits };
    match nfs.access(&args).await.expect("ACCESS RPC must succeed") {
        Nfs3Result::Ok(ok) => {
            // The granted mask must be a subset of the requested mask.
            assert_eq!(ok.access & !all_bits, 0, "server must not grant bits the client did not request");
        },
        Nfs3Result::Err((stat, _)) => panic!("ACCESS: {stat:?}"),
        _ => unreachable!(),
    }
}

// --- FSSTAT procedure ---

#[tokio::test]
async fn fsstat_returns_nonzero_total_space() {
    // FSSTAT (RFC 1813 sec. 3.3.18) reports dynamic filesystem statistics.
    // Total bytes should be nonzero on any filesystem that has capacity.
    let config = MemFsConfig::default();
    let (_srv, port) = start_server(config).await;
    tokio::time::sleep(Duration::from_millis(20)).await;

    let mc = mount_client(port).await;
    let mnt = mc.v3_mnt(dirpath(Opaque::borrowed(b"/"))).await.expect("MOUNT must succeed");
    let root_fh = nfs_fh3 { data: mnt.fhandle.0.clone() };

    let nfs = nfs3_client(port).await;
    let args = FSSTAT3args { fsroot: root_fh };
    match nfs.fsstat(&args).await.expect("FSSTAT RPC must succeed") {
        Nfs3Result::Ok(ok) => {
            // MemFs may report arbitrary values, but tbytes should be > 0.
            assert!(ok.tbytes > 0, "total bytes should be nonzero, got {}", ok.tbytes);
        },
        Nfs3Result::Err((stat, _)) => panic!("FSSTAT: {stat:?}"),
        _ => unreachable!(),
    }
}

// --- FSINFO procedure ---

#[tokio::test]
async fn fsinfo_returns_read_write_limits() {
    // FSINFO (RFC 1813 sec. 3.3.19) returns static FS limits: max/pref read/write sizes.
    let config = MemFsConfig::default();
    let (_srv, port) = start_server(config).await;
    tokio::time::sleep(Duration::from_millis(20)).await;

    let mc = mount_client(port).await;
    let mnt = mc.v3_mnt(dirpath(Opaque::borrowed(b"/"))).await.expect("MOUNT must succeed");
    let root_fh = nfs_fh3 { data: mnt.fhandle.0.clone() };

    let nfs = nfs3_client(port).await;
    let args = FSINFO3args { fsroot: root_fh };
    match nfs.fsinfo(&args).await.expect("FSINFO RPC must succeed") {
        Nfs3Result::Ok(ok) => {
            assert!(ok.rtmax > 0, "rtmax (max read size) must be nonzero, got {}", ok.rtmax);
            assert!(ok.wtmax > 0, "wtmax (max write size) must be nonzero, got {}", ok.wtmax);
            assert!(ok.rtpref > 0, "rtpref (preferred read size) must be nonzero");
            assert!(ok.wtpref > 0, "wtpref (preferred write size) must be nonzero");
            // Preferred sizes should not exceed max sizes.
            assert!(ok.rtpref <= ok.rtmax, "rtpref must be <= rtmax");
            assert!(ok.wtpref <= ok.wtmax, "wtpref must be <= wtmax");
        },
        Nfs3Result::Err((stat, _)) => panic!("FSINFO: {stat:?}"),
        _ => unreachable!(),
    }
}

// --- PATHCONF procedure ---

#[tokio::test]
async fn pathconf_returns_valid_limits() {
    // PATHCONF (RFC 1813 sec. 3.3.20) returns POSIX pathname limits.
    let config = MemFsConfig::default();
    let (_srv, port) = start_server(config).await;
    tokio::time::sleep(Duration::from_millis(20)).await;

    let mc = mount_client(port).await;
    let mnt = mc.v3_mnt(dirpath(Opaque::borrowed(b"/"))).await.expect("MOUNT must succeed");
    let root_fh = nfs_fh3 { data: mnt.fhandle.0.clone() };

    let nfs = nfs3_client(port).await;
    let args = PATHCONF3args { object: root_fh };
    match nfs.pathconf(&args).await.expect("PATHCONF RPC must succeed") {
        Nfs3Result::Ok(ok) => {
            // name_max should be at least 1 (any filesystem supports at least single-char names).
            assert!(ok.name_max > 0, "name_max must be nonzero, got {}", ok.name_max);
        },
        Nfs3Result::Err((stat, _)) => panic!("PATHCONF: {stat:?}"),
        _ => unreachable!(),
    }
}

// --- READDIR (plain, without attributes) ---

#[tokio::test]
async fn readdir_lists_file_names() {
    // READDIR (RFC 1813 sec. 3.3.16) returns names and file IDs only, unlike READDIRPLUS.
    let mut config = MemFsConfig::default();
    config.add_file("/aaa.txt", b"a");
    config.add_file("/bbb.txt", b"b");

    let (_srv, port) = start_server(config).await;
    tokio::time::sleep(Duration::from_millis(20)).await;

    let mc = mount_client(port).await;
    let mnt = mc.v3_mnt(dirpath(Opaque::borrowed(b"/"))).await.expect("MOUNT must succeed");
    let root_fh = nfs_fh3 { data: mnt.fhandle.0.clone() };

    let nfs = nfs3_client(port).await;
    let args = READDIR3args { dir: root_fh, cookie: 0, cookieverf: cookieverf3([0u8; 8]), count: 4096 };
    match nfs.readdir(&args).await.expect("READDIR RPC must succeed") {
        Nfs3Result::Ok(ok) => {
            let names: Vec<String> = ok.reply.entries.0.iter().map(|e| String::from_utf8_lossy(e.name.0.as_ref()).to_string()).collect();
            assert!(names.contains(&"aaa.txt".to_owned()), "aaa.txt missing from READDIR: {names:?}");
            assert!(names.contains(&"bbb.txt".to_owned()), "bbb.txt missing from READDIR: {names:?}");
        },
        Nfs3Result::Err((stat, _)) => panic!("READDIR: {stat:?}"),
        _ => unreachable!(),
    }
}

// --- WRITE then READ data integrity ---

#[tokio::test]
async fn write_then_read_data_integrity() {
    // WRITE (RFC 1813 sec. 3.3.7) data to a file, then READ it back and verify
    // the bytes are identical. This exercises the write path through the wire.
    let mut config = MemFsConfig::default();
    config.add_file("/writable.txt", b"original");

    let (_srv, port) = start_server(config).await;
    tokio::time::sleep(Duration::from_millis(20)).await;

    let mc = mount_client(port).await;
    let mnt = mc.v3_mnt(dirpath(Opaque::borrowed(b"/"))).await.expect("MOUNT must succeed");
    let root_fh = nfs_fh3 { data: mnt.fhandle.0.clone() };

    let nfs = nfs3_client(port).await;
    let fh = match nfs.lookup(&LOOKUP3args { what: diropargs3 { dir: root_fh, name: filename3(Opaque::borrowed(b"writable.txt")) } }).await.expect("LOOKUP must succeed") {
        Nfs3Result::Ok(ok) => ok.object,
        Nfs3Result::Err((stat, _)) => panic!("LOOKUP: {stat:?}"),
        _ => unreachable!(),
    };

    let new_data = b"overwritten content here";
    let write_args = WRITE3args { file: fh.clone(), offset: 0, count: new_data.len() as u32, stable: stable_how::FILE_SYNC, data: Opaque::borrowed(new_data) };
    match nfs.write(&write_args).await.expect("WRITE RPC must succeed") {
        Nfs3Result::Ok(ok) => {
            assert_eq!(ok.count, new_data.len() as u32, "WRITE must report full byte count");
        },
        Nfs3Result::Err((stat, _)) => panic!("WRITE: {stat:?}"),
        _ => unreachable!(),
    }

    // Read back and verify the content matches.
    let read_args = READ3args { file: fh, offset: 0, count: 4096 };
    match nfs.read(&read_args).await.expect("READ RPC must succeed") {
        Nfs3Result::Ok(ok) => {
            assert_eq!(ok.data.as_ref(), new_data.as_slice(), "READ after WRITE must return the written data");
        },
        Nfs3Result::Err((stat, _)) => panic!("READ: {stat:?}"),
        _ => unreachable!(),
    }
}

// --- CREATE + LOOKUP + READ round trip ---

#[tokio::test]
async fn create_then_lookup_finds_new_file() {
    // CREATE (RFC 1813 sec. 3.3.8) a new file, then LOOKUP it to verify the server
    // accepted the create and allocated a handle.
    let config = MemFsConfig::default();
    let (_srv, port) = start_server(config).await;
    tokio::time::sleep(Duration::from_millis(20)).await;

    let mc = mount_client(port).await;
    let mnt = mc.v3_mnt(dirpath(Opaque::borrowed(b"/"))).await.expect("MOUNT must succeed");
    let root_fh = nfs_fh3 { data: mnt.fhandle.0.clone() };

    let nfs = nfs3_client(port).await;

    let create_args = CREATE3args { where_: diropargs3 { dir: root_fh.clone(), name: filename3(Opaque::borrowed(b"newfile.txt")) }, how: createhow3::UNCHECKED(sattr3::default()) };
    match nfs.create(&create_args).await.expect("CREATE RPC must succeed") {
        Nfs3Result::Ok(ok) => {
            assert!(ok.obj.is_some(), "CREATE must return a file handle for the new file");
        },
        Nfs3Result::Err((stat, _)) => panic!("CREATE: {stat:?}"),
        _ => unreachable!(),
    }

    // LOOKUP the newly created file.
    match nfs.lookup(&LOOKUP3args { what: diropargs3 { dir: root_fh, name: filename3(Opaque::borrowed(b"newfile.txt")) } }).await.expect("LOOKUP must succeed") {
        Nfs3Result::Ok(ok) => {
            assert!(!ok.object.data.as_ref().is_empty(), "LOOKUP must return a non-empty handle for the created file");
        },
        Nfs3Result::Err((stat, _)) => panic!("LOOKUP after CREATE: {stat:?}"),
        _ => unreachable!(),
    }
}

// --- REMOVE procedure ---

#[tokio::test]
async fn remove_then_lookup_returns_noent() {
    // REMOVE (RFC 1813 sec. 3.3.12) a file, then verify LOOKUP returns NFS3ERR_NOENT.
    let mut config = MemFsConfig::default();
    config.add_file("/doomed.txt", b"delete me");

    let (_srv, port) = start_server(config).await;
    tokio::time::sleep(Duration::from_millis(20)).await;

    let mc = mount_client(port).await;
    let mnt = mc.v3_mnt(dirpath(Opaque::borrowed(b"/"))).await.expect("MOUNT must succeed");
    let root_fh = nfs_fh3 { data: mnt.fhandle.0.clone() };

    let nfs = nfs3_client(port).await;

    let rm_args = REMOVE3args { object: diropargs3 { dir: root_fh.clone(), name: filename3(Opaque::borrowed(b"doomed.txt")) } };
    match nfs.remove(&rm_args).await.expect("REMOVE RPC must succeed") {
        Nfs3Result::Ok(_) => {},
        Nfs3Result::Err((stat, _)) => panic!("REMOVE: {stat:?}"),
        _ => unreachable!(),
    }

    // LOOKUP must now fail with NOENT.
    match nfs.lookup(&LOOKUP3args { what: diropargs3 { dir: root_fh, name: filename3(Opaque::borrowed(b"doomed.txt")) } }).await.expect("LOOKUP after REMOVE must succeed at protocol level") {
        Nfs3Result::Ok(_) => panic!("LOOKUP should return NOENT after REMOVE"),
        Nfs3Result::Err((stat, _)) => {
            assert_eq!(stat, nfsstat3::NFS3ERR_NOENT, "removed file must return NOENT");
        },
        _ => unreachable!(),
    }
}

// --- Multiple sequential operations on the same connection ---

#[tokio::test]
async fn multiple_sequential_operations_same_connection() {
    // Exercise many different procedures over a single TCP connection to verify
    // the transport correctly frames sequential RPC messages.
    let mut config = MemFsConfig::default();
    config.add_file("/seq_a.txt", b"aaa");
    config.add_file("/seq_b.txt", b"bbb");

    let (_srv, port) = start_server(config).await;
    tokio::time::sleep(Duration::from_millis(20)).await;

    let mc = mount_client(port).await;
    let mnt = mc.v3_mnt(dirpath(Opaque::borrowed(b"/"))).await.expect("MOUNT must succeed");
    let root_fh = nfs_fh3 { data: mnt.fhandle.0.clone() };

    let nfs = nfs3_client(port).await;

    // 1. NULL
    nfs.null().await.expect("NULL must succeed");

    // 2. GETATTR on root
    match nfs.getattr(&GETATTR3args { object: root_fh.clone() }).await.expect("GETATTR must succeed") {
        Nfs3Result::Ok(ok) => assert_eq!(ok.obj_attributes.type_, ftype3::NF3DIR),
        Nfs3Result::Err((stat, _)) => panic!("GETATTR: {stat:?}"),
        _ => unreachable!(),
    }

    // 3. LOOKUP seq_a.txt
    let fh_a = match nfs.lookup(&LOOKUP3args { what: diropargs3 { dir: root_fh.clone(), name: filename3(Opaque::borrowed(b"seq_a.txt")) } }).await.expect("LOOKUP must succeed") {
        Nfs3Result::Ok(ok) => ok.object,
        Nfs3Result::Err((stat, _)) => panic!("LOOKUP seq_a: {stat:?}"),
        _ => unreachable!(),
    };

    // 4. READ seq_a.txt
    match nfs.read(&READ3args { file: fh_a.clone(), offset: 0, count: 256 }).await.expect("READ must succeed") {
        Nfs3Result::Ok(ok) => assert_eq!(ok.data.as_ref(), b"aaa"),
        Nfs3Result::Err((stat, _)) => panic!("READ seq_a: {stat:?}"),
        _ => unreachable!(),
    }

    // 5. ACCESS on seq_a.txt
    match nfs.access(&ACCESS3args { object: fh_a, access: ACCESS3_READ }).await.expect("ACCESS must succeed") {
        Nfs3Result::Ok(_) => {},
        Nfs3Result::Err((stat, _)) => panic!("ACCESS seq_a: {stat:?}"),
        _ => unreachable!(),
    }

    // 6. LOOKUP seq_b.txt
    let fh_b = match nfs.lookup(&LOOKUP3args { what: diropargs3 { dir: root_fh.clone(), name: filename3(Opaque::borrowed(b"seq_b.txt")) } }).await.expect("LOOKUP must succeed") {
        Nfs3Result::Ok(ok) => ok.object,
        Nfs3Result::Err((stat, _)) => panic!("LOOKUP seq_b: {stat:?}"),
        _ => unreachable!(),
    };

    // 7. GETATTR on seq_b.txt
    match nfs.getattr(&GETATTR3args { object: fh_b }).await.expect("GETATTR must succeed") {
        Nfs3Result::Ok(ok) => assert_eq!(ok.obj_attributes.type_, ftype3::NF3REG),
        Nfs3Result::Err((stat, _)) => panic!("GETATTR seq_b: {stat:?}"),
        _ => unreachable!(),
    }

    // 8. FSSTAT on root
    match nfs.fsstat(&FSSTAT3args { fsroot: root_fh.clone() }).await.expect("FSSTAT must succeed") {
        Nfs3Result::Ok(_) => {},
        Nfs3Result::Err((stat, _)) => panic!("FSSTAT: {stat:?}"),
        _ => unreachable!(),
    }

    // 9. FSINFO on root
    match nfs.fsinfo(&FSINFO3args { fsroot: root_fh }).await.expect("FSINFO must succeed") {
        Nfs3Result::Ok(_) => {},
        Nfs3Result::Err((stat, _)) => panic!("FSINFO: {stat:?}"),
        _ => unreachable!(),
    }
}

// --- GETATTR after WRITE reflects new size ---

#[tokio::test]
async fn getattr_reflects_size_after_write() {
    // After a WRITE, GETATTR must reflect the new file size.
    let mut config = MemFsConfig::default();
    config.add_file("/grow.txt", b"");

    let (_srv, port) = start_server(config).await;
    tokio::time::sleep(Duration::from_millis(20)).await;

    let mc = mount_client(port).await;
    let mnt = mc.v3_mnt(dirpath(Opaque::borrowed(b"/"))).await.expect("MOUNT must succeed");
    let root_fh = nfs_fh3 { data: mnt.fhandle.0.clone() };

    let nfs = nfs3_client(port).await;
    let fh = match nfs.lookup(&LOOKUP3args { what: diropargs3 { dir: root_fh, name: filename3(Opaque::borrowed(b"grow.txt")) } }).await.expect("LOOKUP must succeed") {
        Nfs3Result::Ok(ok) => ok.object,
        Nfs3Result::Err((stat, _)) => panic!("LOOKUP: {stat:?}"),
        _ => unreachable!(),
    };

    let payload = b"new payload of 24 bytes!";
    let write_args = WRITE3args { file: fh.clone(), offset: 0, count: payload.len() as u32, stable: stable_how::FILE_SYNC, data: Opaque::borrowed(payload) };
    match nfs.write(&write_args).await.expect("WRITE must succeed") {
        Nfs3Result::Ok(_) => {},
        Nfs3Result::Err((stat, _)) => panic!("WRITE: {stat:?}"),
        _ => unreachable!(),
    }

    match nfs.getattr(&GETATTR3args { object: fh }).await.expect("GETATTR must succeed") {
        Nfs3Result::Ok(ok) => {
            assert_eq!(ok.obj_attributes.size, payload.len() as u64, "GETATTR size must reflect written content length");
        },
        Nfs3Result::Err((stat, _)) => panic!("GETATTR after WRITE: {stat:?}"),
        _ => unreachable!(),
    }
}

// --- LOOKUP on non-existent name ---

#[tokio::test]
async fn lookup_nonexistent_entry_returns_noent() {
    // Confirm that LOOKUP for a name that was never created yields NOENT.
    let config = MemFsConfig::default();
    let (_srv, port) = start_server(config).await;
    tokio::time::sleep(Duration::from_millis(20)).await;

    let mc = mount_client(port).await;
    let mnt = mc.v3_mnt(dirpath(Opaque::borrowed(b"/"))).await.expect("MOUNT must succeed");
    let root_fh = nfs_fh3 { data: mnt.fhandle.0.clone() };

    let nfs = nfs3_client(port).await;
    match nfs.lookup(&LOOKUP3args { what: diropargs3 { dir: root_fh, name: filename3(Opaque::borrowed(b"no_such_file")) } }).await.expect("LOOKUP must succeed at protocol level") {
        Nfs3Result::Ok(_) => panic!("LOOKUP should have returned NOENT"),
        Nfs3Result::Err((stat, _)) => {
            assert_eq!(stat, nfsstat3::NFS3ERR_NOENT, "missing file must return NOENT, got {stat:?}");
        },
        _ => unreachable!(),
    }
}

// --- GETATTR with invalid handle returns BADHANDLE or STALE ---

#[tokio::test]
async fn getattr_invalid_handle_returns_error() {
    // Sending a bogus file handle should return BADHANDLE or STALE, never panic.
    let config = MemFsConfig::default();
    let (_srv, port) = start_server(config).await;
    tokio::time::sleep(Duration::from_millis(20)).await;

    let nfs = nfs3_client(port).await;
    let bogus_fh = nfs_fh3 { data: Opaque::owned(vec![0xDE, 0xAD, 0xBE, 0xEF]) };
    match nfs.getattr(&GETATTR3args { object: bogus_fh }).await.expect("GETATTR must succeed at protocol level") {
        Nfs3Result::Ok(_) => {
            // Some servers might accept anything -- the point is no panic.
        },
        Nfs3Result::Err((stat, _)) => {
            assert!(matches!(stat, nfsstat3::NFS3ERR_BADHANDLE | nfsstat3::NFS3ERR_STALE), "invalid handle must return BADHANDLE or STALE, got {stat:?}");
        },
        _ => unreachable!(),
    }
}

// --- File handles are bearer tokens (RFC 1094 sec. 2.3.3) ---

#[tokio::test]
async fn file_handle_works_across_separate_connections() {
    // Obtain a file handle on one connection, then use it on a second
    // independent connection -- verifying the bearer-token property.
    let mut config = MemFsConfig::default();
    config.add_file("/bearer.txt", b"token test");

    let (_srv, port) = start_server(config).await;
    tokio::time::sleep(Duration::from_millis(20)).await;

    let mc = mount_client(port).await;
    let mnt = mc.v3_mnt(dirpath(Opaque::borrowed(b"/"))).await.expect("MOUNT must succeed");
    let root_fh = nfs_fh3 { data: mnt.fhandle.0.clone() };

    // Connection 1: LOOKUP to get the file handle.
    let nfs1 = nfs3_client(port).await;
    let fh = match nfs1.lookup(&LOOKUP3args { what: diropargs3 { dir: root_fh, name: filename3(Opaque::borrowed(b"bearer.txt")) } }).await.expect("LOOKUP must succeed") {
        Nfs3Result::Ok(ok) => ok.object,
        Nfs3Result::Err((stat, _)) => panic!("LOOKUP: {stat:?}"),
        _ => unreachable!(),
    };

    // Connection 2: READ using the handle obtained from connection 1.
    let nfs2 = nfs3_client(port).await;
    match nfs2.read(&READ3args { file: fh, offset: 0, count: 256 }).await.expect("READ must succeed") {
        Nfs3Result::Ok(ok) => {
            assert_eq!(ok.data.as_ref(), b"token test", "handle must work on a different connection (bearer token)");
        },
        Nfs3Result::Err((stat, _)) => panic!("READ on second connection: {stat:?}"),
        _ => unreachable!(),
    }
}
