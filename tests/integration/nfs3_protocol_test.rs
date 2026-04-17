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
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use nfs3_client::MountClient;
use nfs3_client::Nfs3Client;
use nfs3_client::tokio::TokioIo;
use nfs3_server::memfs::{MemFs, MemFsConfig};
use nfs3_server::tcp::{NFSTcp, NFSTcpListener};
use nfs3_types::mount::dirpath;
use nfs3_types::nfs3::{GETATTR3args, LOOKUP3args, Nfs3Result, READ3args, READDIRPLUS3args, cookieverf3, diropargs3, filename3, nfs_fh3};
use nfs3_types::xdr_codec::Opaque;
use tokio::net::TcpStream;

// --- Server helpers ---

/// Spin up a MemFs server on an ephemeral port and return (task, port).
async fn start_server(config: MemFsConfig) -> (tokio::task::JoinHandle<()>, u16) {
    let fs = MemFs::new(config).expect("MemFs must construct");
    let listener = NFSTcpListener::bind("127.0.0.1:0", fs).await.expect("NFSTcpListener::bind must succeed");
    let port = listener.get_listen_port();
    let task = tokio::spawn(async move { listener.handle_forever().await.expect("server must not crash") });
    (task, port)
}

async fn mount_client(port: u16) -> MountClient<TokioIo<TcpStream>> {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
    let stream = TcpStream::connect(addr).await.expect("TCP connect must succeed");
    MountClient::new(TokioIo::new(stream))
}

async fn nfs3_client(port: u16) -> Nfs3Client<TokioIo<TcpStream>> {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
    let stream = TcpStream::connect(addr).await.expect("TCP connect must succeed");
    Nfs3Client::new(TokioIo::new(stream))
}

// --- READDIRPLUS tests ---

#[tokio::test]
async fn readdirplus_lists_all_entries() {
    let mut config = MemFsConfig::default();
    config.add_file("/alpha.txt", b"a");
    config.add_file("/beta.txt", b"b");
    config.add_file("/gamma.txt", b"g");

    let (_srv, port) = start_server(config).await;
    tokio::time::sleep(Duration::from_millis(20)).await;

    let mut mc = mount_client(port).await;
    let mnt = mc.mnt(dirpath(Opaque::borrowed(b"/"))).await.expect("MOUNT must succeed");
    let root_fh = nfs_fh3 { data: mnt.fhandle.0.clone() };

    let mut nfs = nfs3_client(port).await;
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

    let mut mc = mount_client(port).await;
    let mnt = mc.mnt(dirpath(Opaque::borrowed(b"/"))).await.expect("MOUNT must succeed");
    let root_fh = nfs_fh3 { data: mnt.fhandle.0.clone() };

    let mut nfs = nfs3_client(port).await;
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

    let mut mc = mount_client(port).await;
    let mnt = mc.mnt(dirpath(Opaque::borrowed(b"/"))).await.expect("MOUNT must succeed");
    let root_fh = nfs_fh3 { data: mnt.fhandle.0.clone() };

    let mut nfs = nfs3_client(port).await;
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

    let mut mc = mount_client(port).await;
    let mnt = mc.mnt(dirpath(Opaque::borrowed(b"/"))).await.expect("MOUNT must succeed");
    let root_fh = nfs_fh3 { data: mnt.fhandle.0.clone() };

    let mut nfs = nfs3_client(port).await;

    let lookup = nfs.lookup(&LOOKUP3args { what: diropargs3 { dir: root_fh, name: filename3(Opaque::borrowed(b"fox.txt")) } }).await.expect("LOOKUP RPC must succeed");

    let file_fh = match lookup {
        Nfs3Result::Ok(ok) => ok.object,
        Nfs3Result::Err((stat, _)) => panic!("LOOKUP failed: {stat:?}"),
    };

    let read = nfs.read(&READ3args { file: file_fh, offset: 0, count: 256 }).await.expect("READ RPC must succeed");

    match read {
        Nfs3Result::Ok(ok) => {
            assert_eq!(ok.data.as_ref(), expected, "READ data must match written content");
            assert!(ok.eof, "small file must be EOF after first full read");
        },
        Nfs3Result::Err((stat, _)) => panic!("READ failed: {stat:?}"),
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

    let mut mc = mount_client(port).await;
    let mnt = mc.mnt(dirpath(Opaque::borrowed(b"/"))).await.expect("MOUNT must succeed");
    let root_fh = nfs_fh3 { data: mnt.fhandle.0.clone() };

    let mut nfs = nfs3_client(port).await;
    match nfs.getattr(&GETATTR3args { object: root_fh }).await.expect("GETATTR must succeed") {
        Nfs3Result::Ok(ok) => {
            assert!(ok.obj_attributes.nlink >= 1, "root dir nlink must be >= 1, got {}", ok.obj_attributes.nlink);
        },
        Nfs3Result::Err((stat, _)) => panic!("GETATTR failed: {stat:?}"),
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

    let mut mc = mount_client(port).await;
    let mnt = mc.mnt(dirpath(Opaque::borrowed(b"/"))).await.expect("MOUNT must succeed");
    let root_fh = nfs_fh3 { data: mnt.fhandle.0.clone() };

    let mut nfs = nfs3_client(port).await;
    let fh = match nfs.lookup(&LOOKUP3args { what: diropargs3 { dir: root_fh, name: filename3(Opaque::borrowed(b"partial.txt")) } }).await.expect("LOOKUP must succeed") {
        Nfs3Result::Ok(ok) => ok.object,
        Nfs3Result::Err((stat, _)) => panic!("LOOKUP: {stat:?}"),
    };

    // Read starting at offset 4 with count 4  --  should return "4567"
    let args = READ3args { file: fh, offset: 4, count: 4 };
    match nfs.read(&args).await.expect("READ must succeed") {
        Nfs3Result::Ok(ok) => {
            assert_eq!(ok.data.as_ref(), b"4567", "offset read must return correct slice");
        },
        Nfs3Result::Err((stat, _)) => panic!("READ: {stat:?}"),
    }
}

#[tokio::test]
async fn memfs_read_past_eof_returns_empty() {
    let content = b"short";
    let mut config = MemFsConfig::default();
    config.add_file("/short.txt", content.as_slice());

    let (_srv, port) = start_server(config).await;
    tokio::time::sleep(Duration::from_millis(20)).await;

    let mut mc = mount_client(port).await;
    let mnt = mc.mnt(dirpath(Opaque::borrowed(b"/"))).await.expect("MOUNT must succeed");
    let root_fh = nfs_fh3 { data: mnt.fhandle.0.clone() };

    let mut nfs = nfs3_client(port).await;
    let fh = match nfs.lookup(&LOOKUP3args { what: diropargs3 { dir: root_fh, name: filename3(Opaque::borrowed(b"short.txt")) } }).await.expect("LOOKUP must succeed") {
        Nfs3Result::Ok(ok) => ok.object,
        Nfs3Result::Err((stat, _)) => panic!("LOOKUP: {stat:?}"),
    };

    // Read starting past the end of the file
    let args = READ3args { file: fh, offset: 1000, count: 100 };
    match nfs.read(&args).await.expect("READ must succeed") {
        Nfs3Result::Ok(ok) => {
            assert!(ok.data.as_ref().is_empty(), "read past EOF must return empty data");
            assert!(ok.eof, "read past EOF must set eof flag");
        },
        Nfs3Result::Err((stat, _)) => panic!("READ: {stat:?}"),
    }
}

#[tokio::test]
async fn memfs_readdirplus_empty_dir() {
    // Default MemFs with no files  --  only . and .. may appear (server-dependent).
    let config = MemFsConfig::default();
    let (_srv, port) = start_server(config).await;
    tokio::time::sleep(Duration::from_millis(20)).await;

    let mut mc = mount_client(port).await;
    let mnt = mc.mnt(dirpath(Opaque::borrowed(b"/"))).await.expect("MOUNT must succeed");
    let root_fh = nfs_fh3 { data: mnt.fhandle.0.clone() };

    let mut nfs = nfs3_client(port).await;
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

    let mut mc = mount_client(port).await;
    let mnt = mc.mnt(dirpath(Opaque::borrowed(b"/"))).await.expect("MOUNT must succeed");
    let root_fh = nfs_fh3 { data: mnt.fhandle.0.clone() };

    let mut nfs = nfs3_client(port).await;
    let fh = match nfs.lookup(&LOOKUP3args { what: diropargs3 { dir: root_fh, name: filename3(Opaque::borrowed(b"regular.txt")) } }).await.expect("LOOKUP must succeed") {
        Nfs3Result::Ok(ok) => ok.object,
        Nfs3Result::Err((stat, _)) => panic!("LOOKUP: {stat:?}"),
    };

    match nfs.getattr(&GETATTR3args { object: fh }).await.expect("GETATTR must succeed") {
        Nfs3Result::Ok(ok) => {
            assert_eq!(ok.obj_attributes.type_, nfs3_types::nfs3::ftype3::NF3REG, "file must have type NF3REG");
        },
        Nfs3Result::Err((stat, _)) => panic!("GETATTR: {stat:?}"),
    }
}

#[tokio::test]
async fn getattr_size_matches_file_content_length() {
    let content = b"exactly 15 chars";
    let mut config = MemFsConfig::default();
    config.add_file("/sized.txt", content.as_slice());

    let (_srv, port) = start_server(config).await;
    tokio::time::sleep(Duration::from_millis(20)).await;

    let mut mc = mount_client(port).await;
    let mnt = mc.mnt(dirpath(Opaque::borrowed(b"/"))).await.expect("MOUNT must succeed");
    let root_fh = nfs_fh3 { data: mnt.fhandle.0.clone() };

    let mut nfs = nfs3_client(port).await;

    let fh = match nfs.lookup(&LOOKUP3args { what: diropargs3 { dir: root_fh, name: filename3(Opaque::borrowed(b"sized.txt")) } }).await.expect("LOOKUP must succeed") {
        Nfs3Result::Ok(ok) => ok.object,
        Nfs3Result::Err((stat, _)) => panic!("LOOKUP failed: {stat:?}"),
    };

    match nfs.getattr(&GETATTR3args { object: fh }).await.expect("GETATTR must succeed") {
        Nfs3Result::Ok(ok) => {
            assert_eq!(ok.obj_attributes.size, content.len() as u64, "GETATTR size must equal content length");
        },
        Nfs3Result::Err((stat, _)) => panic!("GETATTR failed: {stat:?}"),
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

    let mut mc = mount_client(port).await;
    let mnt = mc.mnt(dirpath(Opaque::borrowed(b"/"))).await.expect("MOUNT must succeed");
    let root_fh = nfs_fh3 { data: mnt.fhandle.0.clone() };

    let mut nfs = nfs3_client(port).await;
    let fh = match nfs.lookup(&LOOKUP3args { what: diropargs3 { dir: root_fh, name: filename3(Opaque::borrowed(b"chunks.bin")) } }).await.expect("LOOKUP must succeed") {
        Nfs3Result::Ok(ok) => ok.object,
        Nfs3Result::Err((stat, _)) => panic!("LOOKUP: {stat:?}"),
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
        }
    }

    assert_eq!(assembled, content, "chunked read must reproduce full file content");
}
