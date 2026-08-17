//! `nfswolf decode` -- offline NFS file handle decoder.
//!
//! Takes a hex-encoded handle and prints every field decoded to human-readable
//! format. No network access, no server needed. Works with handles from any
//! NFS version (v2/v3/v4) or any source (MOUNT, escape, GETFH, pcap).

use clap::Args;
use colored::Colorize as _;

use crate::engine::file_handle::FileHandleAnalyzer;
use crate::proto::nfs3::types::FileHandle;

#[derive(Debug, Args)]
pub(crate) struct DecodeArgs {
    /// Hex-encoded file handle (e.g., 010007020300240000000000...)
    pub handle: String,
}

pub(crate) fn run(args: &DecodeArgs) -> anyhow::Result<()> {
    let hex = args.handle.trim();
    anyhow::ensure!(hex.len() >= 8, "handle must be at least 4 bytes (8 hex chars)");
    anyhow::ensure!(hex.len().is_multiple_of(2), "hex string must have even length");

    let bytes: Vec<u8> = (0..hex.len())
        .step_by(2)
        .map(|i| {
            let pair = hex.get(i..i + 2).unwrap_or("00");
            u8::from_str_radix(pair, 16)
        })
        .collect::<Result<_, _>>()
        .map_err(|e| anyhow::anyhow!("invalid hex: {e}"))?;

    println!();
    println!("  {} {} bytes", "Handle:".bold(), bytes.len());
    println!("  {}", hex.cyan());
    println!();

    // Header (bytes 0-3)
    let version = bytes.first().copied().unwrap_or(0);
    let auth_type = bytes.get(1).copied().unwrap_or(0);
    let fsid_type = bytes.get(2).copied().unwrap_or(0);
    let fileid_type = bytes.get(3).copied().unwrap_or(0);

    println!("  {}", "Header".bold().underline());
    println!("    byte 0  version      = {} {}", version, if version == 1 { "(Linux knfsd)".dimmed() } else { "(unknown)".dimmed() });
    println!("    byte 1  auth_type    = {} {}", auth_type, "(deprecated, always 0)".dimmed());
    println!("    byte 2  fsid_type    = {} {}", fsid_type, format!("({})", fsid_type_name(fsid_type)).dimmed());
    println!("    byte 3  fileid_type  = 0x{:02x} {}", fileid_type, format!("({})", fileid_type_name(fileid_type)).dimmed());
    println!();

    // fsid section
    let fsid_size = fsid_data_size(fsid_type);
    let fsid_end = 4 + fsid_size;
    if let Some(fsid_data) = bytes.get(4..fsid_end) {
        println!("  {}", "Filesystem ID (fsid)".bold().underline());
        decode_fsid(fsid_type, fsid_data);
        println!();
    }

    // fileid section
    if bytes.len() > fsid_end && fileid_type != 0 {
        let fileid_data = bytes.get(fsid_end..).unwrap_or(&[]);
        println!("  {}", "File ID (fileid)".bold().underline());
        decode_fileid(fileid_type, fileid_data);
        println!();
    } else if fileid_type == 0 {
        println!("  {}", "File ID (fileid)".bold().underline());
        println!("    (FILEID_ROOT -- this is the export/mount root, no inode data)");
        println!();
    }

    // OS and FS fingerprint
    let fh = FileHandle::from_bytes(&bytes);
    let os = FileHandleAnalyzer::fingerprint_os(&fh);
    let fs = FileHandleAnalyzer::fingerprint_fs(&fh);
    println!("  {}", "Fingerprint".bold().underline());
    println!("    OS:         {os:?}");
    println!("    Filesystem: {fs:?}");

    // Security assessment
    println!();
    println!("  {}", "Assessment".bold().underline());
    print_assessment(fsid_type, fileid_type, &bytes);

    println!();
    Ok(())
}

fn fsid_type_name(t: u8) -> &'static str {
    match t {
        0 => "FSID_DEV: device major/minor + inode",
        1 => "FSID_NUM: user-specified fsid number (pseudo-FS)",
        2 => "FSID_MAJOR_MINOR: explicit major+minor+inode (deprecated)",
        3 => "FSID_ENCODE_DEV: encoded device + inode",
        4 => "FSID_UUID4_INUM: 4-byte UUID prefix + inode",
        5 => "FSID_UUID8: 8-byte UUID prefix",
        6 => "FSID_UUID16: full 16-byte filesystem UUID",
        7 => "FSID_UUID16_INUM: export inode + generation + 16-byte UUID",
        _ => "unknown",
    }
}

fn fileid_type_name(t: u8) -> &'static str {
    match t {
        0x00 => "FILEID_ROOT: mount/export root",
        0x01 => "INO32_GEN: 32-bit inode + generation",
        0x02 => "INO32_GEN_PARENT: 32-bit inode + gen + parent inode + parent gen",
        0x4d => "BTRFS_WITHOUT_PARENT: objectid + root_objectid + generation",
        0x4e => "BTRFS_WITH_PARENT: objectid + root + gen + parent",
        0x4f => "BTRFS_WITH_PARENT_ROOT: objectid + root + gen + parent + parent_root",
        0x51 => "UDF_WITHOUT_PARENT: block + partref + generation",
        0x52 => "UDF_WITH_PARENT: block + partref + gen + parent",
        0x61 => "NILFS_WITHOUT_PARENT: checkpoint + inode + generation",
        0x62 => "NILFS_WITH_PARENT: checkpoint + inode + gen + parent",
        0x71 => "FAT_WITHOUT_PARENT: generation + i_pos",
        0x81 => "INO64_GEN: 64-bit inode + generation (XFS, EROFS)",
        0x82 => "INO64_GEN_PARENT: 64-bit inode + gen + parent",
        0xb1 => "BCACHEFS_WITHOUT_PARENT: inode + subvol + generation",
        0xb2 => "BCACHEFS_WITH_PARENT: inode + subvol + gen + parent",
        0xff => "FILEID_INVALID",
        _ => "unknown/filesystem-specific",
    }
}

fn fsid_data_size(fsid_type: u8) -> usize {
    match fsid_type {
        0 | 3..=5 => 8,
        1 => 4,
        2 => 12,
        6 => 16,
        7 => 24,
        _ => 0,
    }
}

fn read_le_u32(data: &[u8], offset: usize) -> Option<u32> {
    let s = data.get(offset..offset + 4)?;
    Some(u32::from_le_bytes(s.try_into().ok()?))
}

fn read_le_u64(data: &[u8], offset: usize) -> Option<u64> {
    let s = data.get(offset..offset + 8)?;
    Some(u64::from_le_bytes(s.try_into().ok()?))
}

fn hex_str(data: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(data.len() * 2);
    for b in data {
        let _ = write!(s, "{b:02x}");
    }
    s
}

fn decode_fsid(fsid_type: u8, data: &[u8]) {
    match fsid_type {
        0 => {
            let dev_major = data.get(0..2).and_then(|b| b.try_into().ok()).map_or(0, u16::from_le_bytes);
            let dev_minor = data.get(2..4).and_then(|b| b.try_into().ok()).map_or(0, u16::from_le_bytes);
            let ino = read_le_u32(data, 4).unwrap_or(0);
            println!("    dev_major    = {dev_major}");
            println!("    dev_minor    = {dev_minor}");
            println!("    export_ino   = {ino}");
        },
        1 => {
            let num = read_le_u32(data, 0).unwrap_or(0);
            println!("    fsid_num     = {num} {}", if num == 0 { "(pseudo-root)".dimmed() } else { "".dimmed() });
        },
        3 => {
            let dev = read_le_u32(data, 0).unwrap_or(0);
            let ino = read_le_u32(data, 4).unwrap_or(0);
            println!("    encoded_dev  = 0x{dev:08x}");
            println!("    export_ino   = {ino}");
        },
        4 => {
            let ino = read_le_u32(data, 0).unwrap_or(0);
            let uuid_bytes = data.get(4..8).unwrap_or(&[]);
            println!("    export_ino   = {ino}");
            println!("    uuid_prefix  = {}", hex_str(uuid_bytes));
        },
        5 => {
            println!("    uuid_prefix  = {}", hex_str(data));
        },
        6 => {
            println!("    uuid         = {}", hex_str(data));
        },
        7 => {
            let export_ino = read_le_u32(data, 0).unwrap_or(0);
            let export_gen = read_le_u32(data, 4).unwrap_or(0);
            let uuid_bytes = data.get(8..24).unwrap_or(&[]);
            println!("    export_ino   = {export_ino}");
            println!("    export_gen   = {export_gen}");
            println!("    uuid         = {}", hex_str(uuid_bytes));
        },
        _ => {
            println!("    raw          = {}", hex_str(data));
        },
    }
}

fn decode_fileid(fileid_type: u8, data: &[u8]) {
    match fileid_type {
        0x01 => {
            let ino = read_le_u32(data, 0).unwrap_or(0);
            let generation = read_le_u32(data, 4).unwrap_or(0);
            println!("    inode        = {ino}");
            println!("    generation   = {generation}");
        },
        0x02 => {
            let ino = read_le_u32(data, 0).unwrap_or(0);
            let generation = read_le_u32(data, 4).unwrap_or(0);
            let pino = read_le_u32(data, 8).unwrap_or(0);
            let pgen = read_le_u32(data, 12).unwrap_or(0);
            println!("    inode        = {ino}");
            println!("    generation   = {generation}");
            println!("    parent_inode = {pino}");
            println!("    parent_gen   = {pgen}");
        },
        0x4d..=0x4f => {
            let objectid = read_le_u64(data, 0).unwrap_or(0);
            let root_objectid = read_le_u64(data, 8).unwrap_or(0);
            let generation = read_le_u32(data, 16).unwrap_or(0);
            println!("    objectid       = {objectid} {}", btrfs_object_label(objectid).dimmed());
            println!("    root_objectid  = {root_objectid} {}", btrfs_object_label(root_objectid).dimmed());
            println!("    generation     = {generation}");
            if fileid_type >= 0x4e && data.len() >= 28 {
                let parent = read_le_u64(data, 20).unwrap_or(0);
                let pgen = read_le_u32(data, 28).unwrap_or(0);
                println!("    parent_objectid = {parent}");
                println!("    parent_gen      = {pgen}");
            }
        },
        0x51 | 0x52 => {
            let block = read_le_u32(data, 0).unwrap_or(0);
            let partref = data.get(4..6).and_then(|b| b.try_into().ok()).map_or(0, u16::from_le_bytes);
            let generation = read_le_u32(data, 8).unwrap_or(0);
            println!("    block        = {block}");
            println!("    partref      = {partref}");
            println!("    generation   = {generation}");
        },
        0x61 | 0x62 => {
            let cno = read_le_u64(data, 0).unwrap_or(0);
            let ino = read_le_u64(data, 8).unwrap_or(0);
            let generation = read_le_u32(data, 16).unwrap_or(0);
            println!("    checkpoint   = {cno}");
            println!("    inode        = {ino}");
            println!("    generation   = {generation}");
        },
        0x81 | 0x82 => {
            let ino = read_le_u64(data, 0).unwrap_or(0);
            let generation = read_le_u32(data, 8).unwrap_or(0);
            println!("    inode        = {ino} (64-bit)");
            println!("    generation   = {generation}");
            if fileid_type == 0x82 && data.len() >= 24 {
                let pino = read_le_u64(data, 12).unwrap_or(0);
                let pgen = read_le_u32(data, 20).unwrap_or(0);
                println!("    parent_inode = {pino}");
                println!("    parent_gen   = {pgen}");
            }
        },
        0xb1 | 0xb2 => {
            let ino = read_le_u64(data, 0).unwrap_or(0);
            let subvol = read_le_u32(data, 8).unwrap_or(0);
            let generation = read_le_u32(data, 12).unwrap_or(0);
            println!("    inode        = {ino}");
            println!("    subvolume    = {subvol}");
            println!("    generation   = {generation}");
        },
        _ => {
            println!("    raw          = {}", hex_str(data));
        },
    }
}

fn btrfs_object_label(id: u64) -> String {
    match id {
        5 => "(fs-tree root)".to_owned(),
        256 => "(default subvolume)".to_owned(),
        id if id >= 256 => format!("(subvolume {id})"),
        _ => String::new(),
    }
}

fn print_assessment(fsid_type: u8, fileid_type: u8, bytes: &[u8]) {
    match (fsid_type, fileid_type) {
        (7, 1 | 2) => println!("    {} This handle has full export context and real inode data.", "[BEST]".bold().green()),
        (7, 0) => println!("    {} Export root with full context. Can be used to construct escape handles.", "[GOOD]".bold().green()),
        (6, 0x4d) => println!("    {} BTRFS handle reaches the BTRFS volume root, not the host root.", "[BTRFS]".bold().yellow()),
        (6, 1 | 2) => println!("    {} UUID-only with real inode. May resolve to pseudo-root on NFSv4.", "[CAUTION]".bold().yellow()),
        (6, 0) => println!("    {} UUID-only export root. Usable as escape seed on NFSv3.", "[GOOD]".bold().green()),
        (1, _) => println!("    {} Pseudo-FS synthetic handle. Not a real filesystem, cannot escape.", "[PSEUDO]".bold().red()),
        (4, 0) => println!("    {} Short-format export root (MOUNT v1). Usable as escape seed.", "[GOOD]".bold().green()),
        (4, 1) => println!("    {} Short-format with real inode. Usable on NFSv2/v3.", "[GOOD]".bold().green()),
        _ => println!("    {} Unknown handle type.", "[?]".bold()),
    }

    // Cross-protocol note
    if fsid_type != 1 && bytes.len() >= 8 {
        println!("    Handles are cross-protocol: this handle works on NFSv2, v3, and v4");
        println!("    (on servers that support the respective version).");
    }
}
