//! Scanner-level integration tests.
//!
//! Two layers of coverage:
//!
//! 1. **CLI smoke tests**  --  verify the binary's help output and that required
//!    arguments are enforced. These run without any NFS server.
//!
//! 2. **In-process NFS server tests**  --  spin up a `MemFs`-backed `NFSTcpListener`
//!    on an ephemeral port and verify that a real `MountClient` + `Nfs3Client`
//!    can MOUNT, GETATTR, and LOOKUP files through it. This exercises the same
//!    code path as nfswolf's scanner engine.
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
use nfs3_client::PortmapperClient;
use nfs3_client::tokio::TokioIo;
use nfs3_server::memfs::{MemFs, MemFsConfig};
use nfs3_server::tcp::{NFSTcp, NFSTcpListener};
use nfs3_types::mount::dirpath;
use nfs3_types::nfs3::{GETATTR3args, LOOKUP3args, Nfs3Result, diropargs3, filename3};
use nfs3_types::xdr_codec::Opaque;
use predicates::prelude::PredicateBooleanExt;
use predicates::str::contains;
use tokio::net::TcpStream;

// --- CLI smoke tests (no server required) ---

#[test]
fn help_flag_succeeds() {
    Command::cargo_bin("nfswolf").expect("binary must be built").arg("--help").assert().success().stdout(contains("NFS").or(contains("nfs")));
}

#[test]
fn scan_help_succeeds() {
    Command::cargo_bin("nfswolf").expect("binary must be built").args(["scan", "--help"]).assert().success();
}

#[test]
fn analyze_help_succeeds() {
    Command::cargo_bin("nfswolf").expect("binary must be built").args(["analyze", "--help"]).assert().success();
}

#[test]
fn attack_help_succeeds() {
    Command::cargo_bin("nfswolf").expect("binary must be built").args(["attack", "--help"]).assert().success();
}

#[test]
fn export_help_succeeds() {
    Command::cargo_bin("nfswolf").expect("binary must be built").args(["export", "--help"]).assert().success();
}

#[test]
fn shell_help_succeeds() {
    Command::cargo_bin("nfswolf").expect("binary must be built").args(["shell", "--help"]).assert().success();
}

#[test]
fn scan_missing_targets_fails() {
    // `scan` requires at least one target. Missing it should exit non-zero.
    Command::cargo_bin("nfswolf").expect("binary must be built").arg("scan").assert().failure();
}

#[test]
fn analyze_missing_target_fails() {
    // `analyze` requires a target argument.
    Command::cargo_bin("nfswolf").expect("binary must be built").arg("analyze").assert().failure();
}

#[test]
fn completions_help_succeeds() {
    Command::cargo_bin("nfswolf").expect("binary must be built").args(["completions", "--help"]).assert().success();
}

#[cfg(feature = "fuse")]
#[test]
fn mount_help_succeeds() {
    Command::cargo_bin("nfswolf").expect("binary must be built").args(["mount", "--help"]).assert().success();
}

#[test]
fn attack_escape_help_succeeds() {
    Command::cargo_bin("nfswolf").expect("binary must be built").args(["attack", "escape", "--help"]).assert().success();
}

#[test]
fn attack_read_help_succeeds() {
    Command::cargo_bin("nfswolf").expect("binary must be built").args(["attack", "read", "--help"]).assert().success();
}

#[test]
fn attack_write_help_succeeds() {
    Command::cargo_bin("nfswolf").expect("binary must be built").args(["attack", "write", "--help"]).assert().success();
}

#[test]
fn attack_uid_spray_help_succeeds() {
    Command::cargo_bin("nfswolf").expect("binary must be built").args(["attack", "uid-spray", "--help"]).assert().success();
}

// --- Scanner coverage: MemFs-based export enumeration ---
//
// These tests verify what Scanner::scan_range() would find by exercising the
// same protocol operations (EXPORT, MNT) directly against a live MemFs server.

#[tokio::test]
async fn memfs_export_list_shows_root() {
    let config = MemFsConfig::default();
    let (_server, port) = start_memfs_server(config).await;
    tokio::time::sleep(Duration::from_millis(20)).await;

    let mut mc = mount_client(port).await;
    // MNTPROC_EXPORT: the scanner calls this to discover exports.
    let exports = mc.export().await.expect("MNTPROC_EXPORT must succeed");
    let export_list = exports.into_inner();
    assert!(!export_list.is_empty(), "MemFs must advertise at least one export");

    // Verify we can MNT the first export and get a root handle.
    let path = export_list[0].ex_dir.0.as_ref().to_vec();
    let root_fh = mc.mnt(dirpath(Opaque::owned(path))).await.expect("MNT must succeed");
    assert!(!root_fh.fhandle.0.as_ref().is_empty(), "root handle must be non-empty");
}

#[tokio::test]
async fn memfs_portmapper_responds_to_getport() {
    // The nfs3_server handles portmapper GETPORT on the same TCP port as NFS.
    // The scanner uses PMAPPROC_GETPORT to verify NFS versions are registered.
    // PMAPPROC_DUMP is not implemented in MemFs, but GETPORT is.
    let config = MemFsConfig::default();
    let (_server, port) = start_memfs_server(config).await;
    tokio::time::sleep(Duration::from_millis(20)).await;

    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
    let stream = tokio::net::TcpStream::connect(addr).await.expect("connect must succeed");
    let io = TokioIo::new(stream);
    let mut pm = PortmapperClient::new(io);

    // PMAPPROC_GETPORT: query where NFS v3 is listening.
    // MemFs serves NFS on the same port it was bound to.
    let nfs_port = pm.getport(100_003, 3).await.expect("PMAPPROC_GETPORT for NFS v3 must succeed");
    assert_eq!(nfs_port, port, "portmapper must report NFS port matching server bind port");
}

// --- In-process MemFs NFS server tests ---

/// Start a MemFs-backed NFS server on an ephemeral port.
/// Returns (server_task, port).
///
/// The `NFSTcpListener` serves MOUNT and NFS3 on the same port. We bind MOUNT
/// and NFS3 clients to the same port as the nfs3_server does not separate them.
async fn start_memfs_server(config: MemFsConfig) -> (tokio::task::JoinHandle<()>, u16) {
    let fs = MemFs::new(config).expect("MemFs creation must succeed");

    // Bind on 127.0.0.1:0 to get an OS-assigned ephemeral port.
    let listener = NFSTcpListener::bind("127.0.0.1:0", fs).await.expect("NFSTcpListener::bind must succeed");
    let port = listener.get_listen_port();

    let handle = tokio::spawn(async move {
        listener.handle_forever().await.expect("server must not crash");
    });

    (handle, port)
}

/// Connect a `MountClient` to the given port on loopback.
async fn mount_client(port: u16) -> MountClient<TokioIo<TcpStream>> {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
    let stream = TcpStream::connect(addr).await.expect("TCP connect must succeed");
    MountClient::new(TokioIo::new(stream))
}

/// Connect an `Nfs3Client` to the given port on loopback.
async fn nfs3_client(port: u16) -> Nfs3Client<TokioIo<TcpStream>> {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
    let stream = TcpStream::connect(addr).await.expect("TCP connect must succeed");
    Nfs3Client::new(TokioIo::new(stream))
}

#[tokio::test]
async fn memfs_mount_returns_root_handle() {
    let mut config = MemFsConfig::default();
    config.add_file("/hello.txt", b"hello world\n".as_slice());

    let (_server, port) = start_memfs_server(config).await;
    // Give the server a moment to start accepting.
    tokio::time::sleep(Duration::from_millis(20)).await;

    let mut mc = mount_client(port).await;
    let mount_ok = mc.mnt(dirpath(Opaque::borrowed(b"/"))).await.expect("MOUNT must succeed");

    // The root file handle must be non-empty.
    assert!(!mount_ok.fhandle.0.as_ref().is_empty(), "root handle must be non-empty");
    // The server should advertise at least one auth flavour (AUTH_SYS = 1).
    assert!(!mount_ok.auth_flavors.is_empty(), "server must advertise at least one auth flavour");
}

#[tokio::test]
async fn memfs_getattr_on_root() {
    let config = MemFsConfig::default();
    let (_server, port) = start_memfs_server(config).await;
    tokio::time::sleep(Duration::from_millis(20)).await;

    // MOUNT to get the root handle.
    let mut mc = mount_client(port).await;
    let mount_ok = mc.mnt(dirpath(Opaque::borrowed(b"/"))).await.expect("MOUNT must succeed");
    let root_fh = nfs3_types::nfs3::nfs_fh3 { data: mount_ok.fhandle.0.clone() };

    // GETATTR on the root handle.
    let mut nfs = nfs3_client(port).await;
    let result = nfs.getattr(&GETATTR3args { object: root_fh.clone() }).await.expect("GETATTR RPC must succeed");

    match result {
        Nfs3Result::Ok(ok) => {
            // Root must be a directory.
            assert_eq!(ok.obj_attributes.type_, nfs3_types::nfs3::ftype3::NF3DIR, "root must be a directory");
        },
        Nfs3Result::Err((stat, _)) => {
            panic!("GETATTR failed: {stat:?}");
        },
    }
}

#[tokio::test]
async fn memfs_lookup_file_in_root() {
    let mut config = MemFsConfig::default();
    config.add_file("/secret.txt", b"top secret\n".as_slice());
    config.add_file("/other.txt", b"other\n".as_slice());

    let (_server, port) = start_memfs_server(config).await;
    tokio::time::sleep(Duration::from_millis(20)).await;

    let mut mc = mount_client(port).await;
    let mount_ok = mc.mnt(dirpath(Opaque::borrowed(b"/"))).await.expect("MOUNT must succeed");
    let root_fh = nfs3_types::nfs3::nfs_fh3 { data: mount_ok.fhandle.0.clone() };

    let mut nfs = nfs3_client(port).await;

    // LOOKUP for "secret.txt" in root.
    let lookup_result = nfs.lookup(&LOOKUP3args { what: diropargs3 { dir: root_fh, name: filename3(Opaque::borrowed(b"secret.txt")) } }).await.expect("LOOKUP RPC must succeed");

    match lookup_result {
        Nfs3Result::Ok(ok) => {
            // We got a file handle  --  it must be non-empty.
            assert!(!ok.object.data.as_ref().is_empty(), "file handle must be non-empty");
        },
        Nfs3Result::Err((stat, _)) => {
            panic!("LOOKUP failed: {stat:?}");
        },
    }
}

#[tokio::test]
async fn memfs_lookup_missing_file_returns_noent() {
    use nfs3_types::nfs3::nfsstat3;

    let config = MemFsConfig::default();
    let (_server, port) = start_memfs_server(config).await;
    tokio::time::sleep(Duration::from_millis(20)).await;

    let mut mc = mount_client(port).await;
    let mount_ok = mc.mnt(dirpath(Opaque::borrowed(b"/"))).await.expect("MOUNT must succeed");
    let root_fh = nfs3_types::nfs3::nfs_fh3 { data: mount_ok.fhandle.0.clone() };

    let mut nfs = nfs3_client(port).await;
    let result = nfs.lookup(&LOOKUP3args { what: diropargs3 { dir: root_fh, name: filename3(Opaque::borrowed(b"does_not_exist.txt")) } }).await.expect("LOOKUP RPC must succeed (protocol level)");

    match result {
        Nfs3Result::Ok(_) => panic!("LOOKUP should have returned NOENT"),
        Nfs3Result::Err((stat, _)) => {
            // The server must return NFS3ERR_NOENT for a missing file.
            assert_eq!(stat, nfsstat3::NFS3ERR_NOENT, "missing file must return NOENT");
        },
    }
}

#[tokio::test]
async fn memfs_read_file_content() {
    use nfs3_types::nfs3::{LOOKUP3args, READ3args, diropargs3};

    let expected = b"integration test content";
    let mut config = MemFsConfig::default();
    config.add_file("/data.bin", expected.as_slice());

    let (_server, port) = start_memfs_server(config).await;
    tokio::time::sleep(Duration::from_millis(20)).await;

    let mut mc = mount_client(port).await;
    let mount_ok = mc.mnt(dirpath(Opaque::borrowed(b"/"))).await.expect("MOUNT must succeed");
    let root_fh = nfs3_types::nfs3::nfs_fh3 { data: mount_ok.fhandle.0.clone() };

    let mut nfs = nfs3_client(port).await;

    // LOOKUP to get the file handle.
    let lookup_ok = match nfs.lookup(&LOOKUP3args { what: diropargs3 { dir: root_fh, name: filename3(Opaque::borrowed(b"data.bin")) } }).await.expect("LOOKUP must succeed") {
        Nfs3Result::Ok(ok) => ok,
        Nfs3Result::Err((stat, _)) => panic!("LOOKUP failed: {stat:?}"),
    };

    // READ the file content.
    let read_result = nfs.read(&READ3args { file: lookup_ok.object, offset: 0, count: 1024 }).await.expect("READ RPC must succeed");

    match read_result {
        Nfs3Result::Ok(ok) => {
            assert_eq!(ok.data.as_ref(), expected, "read content must match written content");
            assert!(ok.eof, "small file must be EOF on first read");
        },
        Nfs3Result::Err((stat, _)) => panic!("READ failed: {stat:?}"),
    }
}
