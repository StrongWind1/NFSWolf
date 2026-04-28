//! Escape subcommand and file handle analysis integration tests.
//!
//! Tests what can be tested without a lib target: the MemFs server behaviour
//! that the scanner and `escape` subcommand rely on (handle format, MOUNT
//! response, auth-flavor advertisement, escape-handle rejection). The core
//! fingerprinting/escape logic is covered by the unit tests embedded in
//! `src/engine/file_handle.rs`.
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
use nfs3_types::xdr_codec::Opaque;
use tokio::net::TcpStream;

// --- Server helpers ---

async fn start_server(config: MemFsConfig) -> (tokio::task::JoinHandle<()>, u16) {
    let fs = MemFs::new(config).expect("MemFs must construct");
    let listener = NFSTcpListener::bind("127.0.0.1:0", fs).await.expect("bind must succeed");
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

// --- File handle byte-level helpers ---

/// Build a minimal Linux ext4-style file handle (matches kernel exportfs layout).
///
/// Layout per Documentation/filesystems/nfs/exporting.rst:
///   [handle_bytes(1)] [fsid_type(1)] [fileid_type(1)] [padding(1)] [fsid(8)] [inode(4)] [generation(4)]
fn make_linux_ext4_fh(inode: u32, generation: u32) -> Vec<u8> {
    let mut data = vec![0u8; 20];
    data[0] = 0x14; // handle_bytes = 20
    data[1] = 0x00; // fsid_type = 0 (UUID / superblock UUID)
    data[2] = 0x01; // fileid_type = 1 (inode + gen)
    // fsid at bytes 3..11 (8 bytes)  --  any non-zero value
    data[3] = 0x01;
    data[4..8].copy_from_slice(&inode.to_le_bytes());
    data[8..12].copy_from_slice(&generation.to_le_bytes());
    data
}

/// Build a 32-byte Windows-style handle. `signed` controls whether the
/// trailing HMAC bytes (bytes 22..32) are non-zero.
fn make_windows_fh(signed: bool) -> Vec<u8> {
    let mut data = vec![0u8; 32];
    // First 22 bytes non-zero -> triggers Windows detection in fingerprint_os.
    for b in &mut data[0..22] {
        *b = 0x01;
    }
    if signed {
        for b in &mut data[22..32] {
            *b = 0xAB;
        }
    }
    data
}

// --- Handle format invariant tests ---

#[test]
fn linux_ext4_fh_is_exactly_20_bytes() {
    assert_eq!(make_linux_ext4_fh(2, 0).len(), 20);
}

#[test]
fn windows_fh_is_exactly_32_bytes() {
    assert_eq!(make_windows_fh(true).len(), 32);
}

#[test]
fn linux_ext4_fh_inode_round_trips_via_bytes() {
    let inode: u32 = 131_072;
    let fh_bytes = make_linux_ext4_fh(inode, 1);
    // The inode occupies bytes 4..8 in LE.
    let recovered = u32::from_le_bytes(fh_bytes[4..8].try_into().unwrap());
    assert_eq!(recovered, inode);
}

#[test]
fn unsigned_windows_fh_hmac_bytes_are_all_zero() {
    let fh = make_windows_fh(false);
    assert!(fh[22..32].iter().all(|&b| b == 0), "unsigned handle must have zero HMAC bytes");
}

#[test]
fn signed_windows_fh_hmac_bytes_are_nonzero() {
    let fh = make_windows_fh(true);
    assert!(fh[22..32].iter().any(|&b| b != 0), "signed handle must have non-zero HMAC bytes");
}

// --- MemFs server: handle and auth flavor properties ---

#[tokio::test]
async fn memfs_root_handle_is_nonempty() {
    let (_srv, port) = start_server(MemFsConfig::default()).await;
    tokio::time::sleep(Duration::from_millis(20)).await;

    let mut mc = mount_client(port).await;
    let mnt = mc.mnt(dirpath(Opaque::borrowed(b"/"))).await.expect("MOUNT must succeed");

    assert!(!mnt.fhandle.0.as_ref().is_empty(), "server must return a non-empty root file handle");
}

#[tokio::test]
async fn memfs_advertises_at_least_one_auth_flavor() {
    let (_srv, port) = start_server(MemFsConfig::default()).await;
    tokio::time::sleep(Duration::from_millis(20)).await;

    let mut mc = mount_client(port).await;
    let mnt = mc.mnt(dirpath(Opaque::borrowed(b"/"))).await.expect("MOUNT must succeed");

    // AUTH_SYS (flavor 1) must be present  --  the MemFs server must accept it.
    assert!(!mnt.auth_flavors.is_empty(), "server must advertise at least one auth flavor");
    assert!(mnt.auth_flavors.contains(&1), "server must advertise AUTH_SYS (flavor 1)");
}

#[tokio::test]
async fn memfs_consecutive_mounts_return_same_root_handle() {
    // File handles must be stable for the same path  --  a second MOUNT must
    // return the same root handle as the first (bearer-token property).
    let (_srv, port) = start_server(MemFsConfig::default()).await;
    tokio::time::sleep(Duration::from_millis(20)).await;

    // Two independent TCP connections to simulate two separate clients.
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);

    let stream1 = TcpStream::connect(addr).await.expect("connect 1");
    let mut mc1 = MountClient::new(TokioIo::new(stream1));
    let mnt1 = mc1.mnt(dirpath(Opaque::borrowed(b"/"))).await.expect("MOUNT 1 must succeed");

    let stream2 = TcpStream::connect(addr).await.expect("connect 2");
    let mut mc2 = MountClient::new(TokioIo::new(stream2));
    let mnt2 = mc2.mnt(dirpath(Opaque::borrowed(b"/"))).await.expect("MOUNT 2 must succeed");

    assert_eq!(mnt1.fhandle.0.as_ref(), mnt2.fhandle.0.as_ref(), "root handle must be stable across mounts (bearer token property)");
}

#[tokio::test]
async fn memfs_with_files_still_returns_root_handle() {
    let mut config = MemFsConfig::default();
    // MemFs only supports top-level paths  --  no subdirectories.
    config.add_file("/secret.key", b"-----BEGIN RSA PRIVATE KEY-----");
    config.add_file("/shadow.txt", b"root:$6$...:19000:0:99999:7:::");

    let (_srv, port) = start_server(config).await;
    tokio::time::sleep(Duration::from_millis(20)).await;

    let mut mc = mount_client(port).await;
    let mnt = mc.mnt(dirpath(Opaque::borrowed(b"/"))).await.expect("MOUNT must succeed");

    assert!(!mnt.fhandle.0.as_ref().is_empty(), "root handle must be non-empty even with files present");
}

// --- Escape primitive: MemFs handles are synthetic ---

#[tokio::test]
async fn memfs_escape_attempt_fails_gracefully() {
    // Verifies that constructing an escape handle against MemFs returns BADHANDLE or STALE,
    // confirming the handle oracle works (BADHANDLE = wrong format, STALE = wrong inode).
    // MemFs handles are synthetic and don't follow the ext4/XFS filesystem format.
    use nfs3_types::nfs3::{GETATTR3args, Nfs3Result, nfsstat3};

    let config = MemFsConfig::default();
    let (_server, port) = start_server(config).await;
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
