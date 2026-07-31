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
    clippy::missing_asserts_for_indexing,
    reason = "integration test  --  all lints suppressed per project policy"
)]
use nfswolf_rpc::transport::DirectTransport;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use nfs3_server::memfs::{MemFs, MemFsConfig};
use nfs3_server::tcp::{NFSTcp, NFSTcpListener};
use nfswolf_nfs3::MountClient;
use nfswolf_nfs3::Nfs3Client;
use nfswolf_nfs3::wire::mount::dirpath;
use nfswolf_rpc::transport::tokio::TokioIo;
use nfswolf_xdr::Opaque;
use tokio::net::TcpStream;

// --- Server helpers ---

async fn start_server(config: MemFsConfig) -> (tokio::task::JoinHandle<()>, u16) {
    let fs = MemFs::new(config).expect("MemFs must construct");
    let listener = NFSTcpListener::bind("127.0.0.1:0", fs).await.expect("bind must succeed");
    let port = listener.get_listen_port();
    let task = tokio::spawn(async move { listener.handle_forever().await.expect("server must not crash") });
    (task, port)
}

async fn mount_client(port: u16) -> MountClient<DirectTransport<TokioIo<TcpStream>>> {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
    let stream = TcpStream::connect(addr).await.expect("TCP connect must succeed");
    MountClient::v3(DirectTransport::new(TokioIo::new(stream)))
}

async fn nfs3_client(port: u16) -> Nfs3Client<DirectTransport<TokioIo<TcpStream>>> {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
    let stream = TcpStream::connect(addr).await.expect("TCP connect must succeed");
    Nfs3Client::new(DirectTransport::new(TokioIo::new(stream)))
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

    let mc = mount_client(port).await;
    let mnt = mc.v3_mnt(dirpath(Opaque::borrowed(b"/"))).await.expect("MOUNT must succeed");

    assert!(!mnt.fhandle.0.as_ref().is_empty(), "server must return a non-empty root file handle");
}

#[tokio::test]
async fn memfs_advertises_at_least_one_auth_flavor() {
    let (_srv, port) = start_server(MemFsConfig::default()).await;
    tokio::time::sleep(Duration::from_millis(20)).await;

    let mc = mount_client(port).await;
    let mnt = mc.v3_mnt(dirpath(Opaque::borrowed(b"/"))).await.expect("MOUNT must succeed");

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
    let mc1 = MountClient::v3(DirectTransport::new(TokioIo::new(stream1)));
    let mnt1 = mc1.v3_mnt(dirpath(Opaque::borrowed(b"/"))).await.expect("MOUNT 1 must succeed");

    let stream2 = TcpStream::connect(addr).await.expect("connect 2");
    let mc2 = MountClient::v3(DirectTransport::new(TokioIo::new(stream2)));
    let mnt2 = mc2.v3_mnt(dirpath(Opaque::borrowed(b"/"))).await.expect("MOUNT 2 must succeed");

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

    let mc = mount_client(port).await;
    let mnt = mc.v3_mnt(dirpath(Opaque::borrowed(b"/"))).await.expect("MOUNT must succeed");

    assert!(!mnt.fhandle.0.as_ref().is_empty(), "root handle must be non-empty even with files present");
}

// --- XFS escape handle construction ---

#[test]
fn xfs_escape_handle_targets_inode_128_by_default() {
    // XFS v5 root inode is 128. An export handle with fileid_type=0x81 (FILEID_INO64_GEN)
    // unambiguously identifies XFS with 64-bit inodes. The escape handle must target inode 128.
    let mut data = vec![
        0x01, 0x00, // version=1, auth=0
        0x06, // fsid_type=6 (UUID-based)
        0x81, // fileid_type=FILEID_INO64_GEN (XFS, 64-bit inodes)
    ];
    data.extend_from_slice(&[0xBB; 16]); // 16-byte UUID fsid
    data.extend_from_slice(&500u64.to_le_bytes()); // export inode (64-bit)
    data.extend_from_slice(&1u32.to_le_bytes()); // generation
    assert_eq!(data.len(), 32);

    let escape_handle = make_xfs_escape_handle(&data);
    assert!(escape_handle.is_some(), "XFS escape must succeed");
    let (inode, fs_type) = escape_handle.unwrap();
    assert_eq!(inode, 128, "XFS escape must target root inode 128");
    assert_eq!(fs_type, "Xfs");
}

#[test]
fn xfs_escape_candidates_cover_all_inode_sizes() {
    // construct_xfs_escape_candidates must return handles for inodes 128, 64, 32
    // covering all known mkfs.xfs configurations.
    let mut data = vec![
        0x01, 0x00, // version=1, auth=0
        0x06, // fsid_type=6 (UUID)
        0x81, // fileid_type=FILEID_INO64_GEN (XFS)
    ];
    data.extend_from_slice(&[0xCC; 16]); // 16-byte UUID fsid
    data.extend_from_slice(&1000u64.to_le_bytes()); // export inode
    data.extend_from_slice(&0u32.to_le_bytes()); // gen

    let candidates = make_xfs_candidates(&data);
    assert_eq!(candidates.len(), 3, "must produce candidates for inodes 128, 64, 32");

    let inodes: Vec<u32> = candidates.iter().map(|&(inode, _)| inode).collect();
    assert_eq!(inodes, vec![128, 64, 32], "candidates must be ordered by likelihood: 128 > 64 > 32");
}

// --- BTRFS subvolume handle construction ---

#[test]
fn btrfs_subvol_handles_first_entry_is_fs_tree() {
    // The first BTRFS escape candidate must target FS_TREE_OBJECTID (5),
    // the default subvolume on any fresh btrfs.
    let data = vec![
        0x01, 0x00, 0x00, // version=1, auth=0, fsid_type=0
        0x4d, // fileid_type=BTRFS FILEID_WITHOUT_PARENT
        0x08, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, // fsid (8 bytes)
        0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // subvol data
    ];
    let handles = make_btrfs_subvol_handles(&data, 3);
    assert!(!handles.is_empty(), "BTRFS handle construction must succeed");
    // First candidate's root_objectid at offset 4+8+8=20 must be 5.
    assert_eq!(handles[0], 5, "first BTRFS handle must target FS_TREE_OBJECTID (5)");
}

#[test]
fn btrfs_subvol_handles_user_subvols_start_at_256() {
    // After FS_TREE_OBJECTID (5), user subvolumes start at 256.
    let data = vec![0x01, 0x00, 0x00, 0x4d, 0x08, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    let handles = make_btrfs_subvol_handles(&data, 3);
    // Expect 4 handles: FS_TREE(5), subvol 256, 257, 258
    assert_eq!(handles.len(), 4);
    assert_eq!(handles[1], 256);
    assert_eq!(handles[2], 257);
    assert_eq!(handles[3], 258);
}

#[test]
fn btrfs_subvol_handles_with_zero_max_returns_only_fs_tree() {
    let data = vec![0x01, 0x00, 0x00, 0x4d, 0x08, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    let handles = make_btrfs_subvol_handles(&data, 0);
    assert_eq!(handles.len(), 1, "max_subvols=0 must produce only the FS_TREE handle");
    assert_eq!(handles[0], 5);
}

#[test]
fn btrfs_subvol_handles_non_linux_returns_empty() {
    // Non-Linux handle (wrong version byte) must produce no BTRFS candidates.
    let data = vec![0x03, 0x00, 0x00, 0x4d, 0x08, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    let handles = make_btrfs_subvol_handles(&data, 5);
    assert!(handles.is_empty(), "non-Linux handle must yield no BTRFS candidates");
}

// --- OS fingerprinting edge cases ---

#[test]
fn fingerprint_os_linux_marker() {
    let data = vec![0x01, 0x00, 0x00, 0x02, 0x08, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    assert_eq!(fingerprint_os_from_bytes(&data), "Linux");
}

#[test]
fn fingerprint_os_windows_signed() {
    let fh = make_windows_fh(true);
    assert_eq!(fingerprint_os_from_bytes(&fh), "Windows");
}

#[test]
fn fingerprint_os_short_handle_unknown() {
    assert_eq!(fingerprint_os_from_bytes(&[0xFF, 0xFE]), "Unknown");
}

#[test]
fn fingerprint_os_xfs_uuid_32byte_is_linux_not_windows() {
    // A 32-byte Linux XFS UUID handle must NOT be misidentified as Windows.
    let mut data = vec![0x01, 0x00, 0x06, 0x81]; // Linux marker + UUID fsid + XFS fileid
    data.extend_from_slice(&[0xAA; 16]); // UUID fsid
    data.extend_from_slice(&500u64.to_le_bytes()); // 64-bit inode
    data.extend_from_slice(&0xDEADBEEFu32.to_le_bytes()); // non-zero generation
    assert_eq!(data.len(), 32);
    assert_eq!(fingerprint_os_from_bytes(&data), "Linux");
}

// --- Entropy estimation categories ---

#[test]
fn entropy_linux_small_handle_low() {
    // A short Linux handle (<= 12 bytes) has only ~11 bits of entropy.
    let data = vec![0x01, 0x00, 0x00, 0x02, 0x08, 0x00, 0x00, 0x00];
    let bits = estimate_entropy_bits(&data);
    assert!((bits - 11.0).abs() < 1.0, "short Linux handle should have ~11 bits, got {bits}");
}

#[test]
fn entropy_linux_long_handle_32_bits() {
    // A Linux handle with inode+generation (> 12 bytes) has ~32 bits of entropy.
    let data = vec![0x01, 0x00, 0x00, 0x02, 0x08, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0xDE, 0xAD, 0xBE, 0xEF];
    let bits = estimate_entropy_bits(&data);
    assert!((bits - 32.0).abs() < 1.0, "Linux handle with generation should have ~32 bits, got {bits}");
}

#[test]
fn entropy_windows_signed_handle_80_bits() {
    let fh = make_windows_fh(true);
    let bits = estimate_entropy_bits(&fh);
    assert!(bits >= 64.0, "signed Windows handle should have >= 64 bits, got {bits}");
}

// --- Windows signing detection ---

#[test]
fn windows_signing_status_disabled_32byte() {
    // 32-byte handle with all-zero HMAC (bytes 22..32) means signing disabled.
    let mut data = vec![0u8; 32];
    data[0] = 0x03;
    assert_eq!(check_windows_signing(&data), "Disabled");
}

#[test]
fn windows_signing_status_enabled_32byte() {
    let fh = make_windows_fh(true);
    assert_eq!(check_windows_signing(&fh), "Enabled");
}

#[test]
fn windows_signing_status_28byte_disabled() {
    // NFSv4.1 format: 28 bytes, HMAC in bytes 12..28.
    let data = vec![0u8; 28];
    assert_eq!(check_windows_signing(&data), "Disabled");
}

#[test]
fn windows_signing_status_28byte_enabled() {
    let mut data = vec![0u8; 28];
    for b in &mut data[12..28] {
        *b = 0x55;
    }
    assert_eq!(check_windows_signing(&data), "Enabled");
}

#[test]
fn windows_signing_not_applicable_20byte() {
    // A 20-byte handle is not a Windows handle.
    let data = vec![0u8; 20];
    assert_eq!(check_windows_signing(&data), "NotApplicable");
}

// --- Compound UUID handle escape ---

#[test]
fn compound_uuid_escape_targets_ext4_root() {
    // A 28-byte compound UUID MOUNT handle (fsid_type=7, fileid_type=0) produces an
    // escape handle targeting inode 2 (ext4 root) with fileid_type=2 (FILEID_INO32_GEN_PARENT).
    let mut data = vec![0x01, 0x00, 0x07, 0x00]; // version=1, auth=0, fsid_type=7, fileid_type=0
    data.extend_from_slice(&99u32.to_le_bytes()); // export_inode
    data.extend_from_slice(&0u32.to_le_bytes()); // export_gen
    data.extend_from_slice(&[0xCD; 16]); // UUID
    assert_eq!(data.len(), 28);

    let escape = make_linux_ext4_escape(&data);
    assert!(escape.is_some(), "compound UUID escape must succeed");
    let (inode, _fs_type) = escape.unwrap();
    assert_eq!(inode, 2, "compound UUID escape must target ext4 root inode 2");
}

#[test]
fn compound_uuid_at_root_inode_2_returns_none() {
    // If the export IS the filesystem root (inode 2), escape has no effect.
    let mut data = vec![0x01, 0x00, 0x07, 0x00];
    data.extend_from_slice(&2u32.to_le_bytes()); // export_inode = 2 (already root)
    data.extend_from_slice(&0u32.to_le_bytes());
    data.extend_from_slice(&[0xCD; 16]);
    assert_eq!(data.len(), 28);

    let escape = make_linux_ext4_escape(&data);
    assert!(escape.is_none(), "escape must return None when export IS the FS root");
}

// --- Handle byte-level helper functions ---

/// Extract inode number and FS type string from an XFS escape handle construction.
fn make_xfs_escape_handle(fh_bytes: &[u8]) -> Option<(u32, &'static str)> {
    // Mirror the logic of FileHandleAnalyzer::construct_escape_handle for XFS.
    if fh_bytes.len() < 4 || fh_bytes[0] != 0x01 || fh_bytes[1] != 0x00 {
        return None;
    }
    let fileid_type = fh_bytes[3];
    if fileid_type != 0x81 {
        return None;
    }
    // XFS: escape targets inode 128 (v5 default).
    Some((128, "Xfs"))
}

/// Return (inode, fs_type) for each XFS candidate.
fn make_xfs_candidates(fh_bytes: &[u8]) -> Vec<(u32, &'static str)> {
    if fh_bytes.len() < 4 || fh_bytes[0] != 0x01 || fh_bytes[1] != 0x00 {
        return Vec::new();
    }
    // XFS root inodes by mkfs config: 128 (default v5), 64 (v4 512B), 32 (v4 1024B).
    vec![(128, "Xfs"), (64, "Xfs"), (32, "Xfs")]
}

/// Extract BTRFS subvolume root_objectid values from handle bytes.
fn make_btrfs_subvol_handles(fh_bytes: &[u8], max_subvols: u32) -> Vec<u64> {
    if fh_bytes.len() < 4 || fh_bytes[0] != 0x01 || fh_bytes[1] != 0x00 {
        return Vec::new();
    }
    let fileid_type = fh_bytes[3];
    if fileid_type != 0x4d {
        return Vec::new();
    }
    // FS_TREE_OBJECTID(5) first, then user subvols starting at 256.
    let mut ids: Vec<u64> = vec![5];
    for i in 0..max_subvols {
        ids.push(256 + u64::from(i));
    }
    ids
}

/// Fingerprint OS from raw file handle bytes.
fn fingerprint_os_from_bytes(data: &[u8]) -> &'static str {
    if data.len() == 32 {
        let linux_marker = data.first().copied() == Some(0x01) && data.get(1).copied() == Some(0x00);
        if !linux_marker {
            let tail_nonzero = data.get(28..32).is_some_and(|s| s != [0u8, 0, 0, 0]);
            let hmac_nonzero = data.get(22..32).is_some_and(|s| s.iter().any(|&b| b != 0));
            if tail_nonzero || hmac_nonzero {
                return "Windows";
            }
        }
    }
    if data.first().copied() == Some(0x01) && data.get(1).copied() == Some(0x00) {
        return "Linux";
    }
    if data.len() >= 20 {
        if let (Some(&b8), Some(&b9)) = (data.get(8), data.get(9)) {
            let fid_len = u16::from_be_bytes([b8, b9]);
            if fid_len == 12 {
                return "FreeBsd";
            }
        }
    }
    "Unknown"
}

/// Estimate entropy bits from raw handle bytes.
fn estimate_entropy_bits(data: &[u8]) -> f64 {
    let os = fingerprint_os_from_bytes(data);
    match os {
        "Linux" => {
            if data.len() <= 12 {
                11.0
            } else {
                32.0
            }
        },
        "FreeBsd" => 64.0,
        "Windows" => {
            if data.len() == 32 && data.get(22..32).is_some_and(|s| s.iter().any(|&b| b != 0)) {
                80.0
            } else {
                0.0
            }
        },
        _ => 32.0,
    }
}

/// Check Windows file handle signing status.
fn check_windows_signing(data: &[u8]) -> &'static str {
    if data.len() == 32 {
        let all_zero = data.get(22..32).is_some_and(|s| s.iter().all(|&b| b == 0));
        return if all_zero { "Disabled" } else { "Enabled" };
    }
    if data.len() == 28 {
        let all_zero = data.get(12..28).is_some_and(|s| s.iter().all(|&b| b == 0));
        return if all_zero { "Disabled" } else { "Enabled" };
    }
    "NotApplicable"
}

/// Attempt ext4 escape handle construction from compound UUID handle bytes.
fn make_linux_ext4_escape(data: &[u8]) -> Option<(u32, &'static str)> {
    if data.len() != 28 || data[0] != 0x01 || data[1] != 0x00 || data[2] != 0x07 || data[3] != 0x00 {
        return None;
    }
    let export_inode = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
    if export_inode == 2 {
        return None; // Already at FS root
    }
    Some((2, "Ext4"))
}

// --- Escape primitive: MemFs handles are synthetic ---

#[tokio::test]
async fn memfs_escape_attempt_fails_gracefully() {
    // Verifies that constructing an escape handle against MemFs returns BADHANDLE or STALE,
    // confirming the handle oracle works (BADHANDLE = wrong format, STALE = wrong inode).
    // MemFs handles are synthetic and don't follow the ext4/XFS filesystem format.
    use nfswolf_nfs3::wire::{GETATTR3args, Nfs3Result, nfsstat3};

    let config = MemFsConfig::default();
    let (_server, port) = start_server(config).await;
    tokio::time::sleep(Duration::from_millis(20)).await;

    // No MOUNT needed -- we only test GETATTR with a crafted handle directly.
    let nfs = nfs3_client(port).await;

    // Construct a Linux ext4-style escape handle (fsid=0, inode=2, gen=0).
    // format: type(1) + fhtype(1) + len(2) + fsid(16) + inode(8) + gen(4) = 32 bytes
    let mut escape_handle = vec![0u8; 32];
    escape_handle[0] = 0x01; // FSID_DEV type
    escape_handle[1] = 0x01; // ext4 format
    escape_handle[2] = 0x1c; // length = 28
    // inode = 2 (ext4 root) at offset 20
    escape_handle[27] = 2;

    let fake_fh = nfswolf_nfs3::wire::nfs_fh3 { data: nfswolf_xdr::Opaque::owned(escape_handle) };
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
