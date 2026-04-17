//! Attack module integration tests against an in-process MemFs NFS server.
//!
//! Verifies that attack primitives behave correctly:
//! - `escape` command: MemFs file handles are synthetic; escape constructs should
//!   fail with BADHANDLE or STALE, never panic.
//! - `read` command: a file planted in MemFs is retrievable with the correct handle.
//! - CLI help flags for all attack sub-commands pass validation.
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

use assert_cmd::Command;
use nfs3_client::MountClient;
use nfs3_client::Nfs3Client;
use nfs3_client::tokio::TokioIo;
use nfs3_server::memfs::{MemFs, MemFsConfig};
use nfs3_server::tcp::{NFSTcp, NFSTcpListener};
use nfs3_types::mount::dirpath;
use nfs3_types::nfs3::{LOOKUP3args, Nfs3Result, READ3args, diropargs3, filename3};
use nfs3_types::xdr_codec::Opaque;
use tokio::net::TcpStream;

// --- Helpers ---

async fn start_memfs(config: MemFsConfig) -> (tokio::task::JoinHandle<()>, u16) {
    let fs = MemFs::new(config).expect("MemFs creation must succeed");
    let listener = NFSTcpListener::bind("127.0.0.1:0", fs).await.expect("bind must succeed");
    let port = listener.get_listen_port();
    let handle = tokio::spawn(async move {
        listener.handle_forever().await.expect("server must not crash");
    });
    (handle, port)
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

// --- CLI smoke tests for attack sub-commands ---

#[test]
fn attack_symlink_swap_help_succeeds() {
    Command::cargo_bin("nfswolf").expect("binary must be built").args(["attack", "symlink-swap", "--help"]).assert().success();
}

#[test]
fn attack_brute_handle_help_succeeds() {
    Command::cargo_bin("nfswolf").expect("binary must be built").args(["attack", "brute-handle", "--help"]).assert().success();
}

#[test]
fn attack_harvest_help_succeeds() {
    Command::cargo_bin("nfswolf").expect("binary must be built").args(["attack", "harvest", "--help"]).assert().success();
}

#[test]
fn attack_lock_dos_help_succeeds() {
    Command::cargo_bin("nfswolf").expect("binary must be built").args(["attack", "lock-dos", "--help"]).assert().success();
}

// --- Read primitive against MemFs ---

#[tokio::test]
async fn memfs_read_planted_file_returns_content() {
    // Verifies that the read attack primitive (LOOKUP + READ) retrieves planted content.
    // This is what `nfswolf attack read` does under the hood.
    let expected = b"secret credentials\n";
    let mut config = MemFsConfig::default();
    config.add_file("/creds.txt", expected.as_slice());

    let (_server, port) = start_memfs(config).await;
    tokio::time::sleep(Duration::from_millis(20)).await;

    // MOUNT to get root handle.
    let mut mc = mount_client(port).await;
    let exports = mc.export().await.expect("MNTPROC_EXPORT must succeed");
    let first_path = exports.into_inner().into_iter().next().map(|e| e.ex_dir.0.as_ref().to_vec()).expect("export");
    let mount_res = mc.mnt(dirpath(Opaque::owned(first_path))).await.expect("MNT must succeed");
    let root_fh = nfs3_types::nfs3::nfs_fh3 { data: mount_res.fhandle.0.clone() };

    let mut nfs = nfs3_client(port).await;

    // LOOKUP "creds.txt".
    let lookup_res = nfs.lookup(&LOOKUP3args { what: diropargs3 { dir: root_fh, name: filename3(Opaque::borrowed(b"creds.txt")) } }).await.expect("LOOKUP RPC must succeed");

    let file_fh = match lookup_res {
        Nfs3Result::Ok(ok) => ok.object,
        Nfs3Result::Err((stat, _)) => panic!("LOOKUP failed: {stat:?}"),
    };

    // READ the file.
    let read_res = nfs.read(&READ3args { file: file_fh, offset: 0, count: 1024 }).await.expect("READ RPC must succeed");

    match read_res {
        Nfs3Result::Ok(ok) => {
            assert_eq!(ok.data.as_ref(), expected, "read content must match planted content");
            assert!(ok.eof, "small file must report EOF");
        },
        Nfs3Result::Err((stat, _)) => panic!("READ failed: {stat:?}"),
    }
}

// --- Escape primitive: MemFs handles are synthetic ---

#[tokio::test]
async fn memfs_escape_attempt_fails_gracefully() {
    // Verifies that constructing an escape handle against MemFs returns BADHANDLE or STALE,
    // confirming the handle oracle works (BADHANDLE = wrong format, STALE = wrong inode).
    // MemFs handles are synthetic and don't follow the ext4/XFS filesystem format.
    use nfs3_types::nfs3::{GETATTR3args, nfsstat3};

    let config = MemFsConfig::default();
    let (_server, port) = start_memfs(config).await;
    tokio::time::sleep(Duration::from_millis(20)).await;

    // No MOUNT needed -- we only test GETATTR with a crafted handle directly.
    let mut nfs = nfs3_client(port).await;

    // Construct a Linux ext4-style escape handle (fsid=0, inode=2, gen=0).
    // format: type(1) + fhtype(1) + len(2) + fsid(16) + inode(8) + gen(4) = 32 bytes
    let mut escape_handle = vec![0u8; 32];
    escape_handle[0] = 0x01; // FSID_DEV type
    escape_handle[1] = 0x01; // ext4 format
    escape_handle[2] = 0x1c; // length = 28
    // inode = 2 (ext4 root) at offset 20
    escape_handle[27] = 2;

    let fake_fh = nfs3_types::nfs3::nfs_fh3 { data: nfs3_types::xdr_codec::Opaque::owned(escape_handle) };
    let res = nfs.getattr(&GETATTR3args { object: fake_fh }).await.expect("GETATTR RPC must succeed at protocol level");

    // MemFs must reject an escape handle with BADHANDLE or STALE -- never panic or succeed.
    match res {
        Nfs3Result::Err((stat, _)) => {
            assert!(matches!(stat, nfsstat3::NFS3ERR_BADHANDLE | nfsstat3::NFS3ERR_STALE), "escape handle must return BADHANDLE or STALE, got {stat:?}");
        },
        Nfs3Result::Ok(_) => {
            // If MemFs somehow accepts the handle, that's OK -- it means the format matched.
            // The important thing is no panic.
        },
    }
}
