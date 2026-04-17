//! FUSE-based NFS mount with automatic UID spoofing.
//!
//! Mounts an NFS export as a local FUSE filesystem so the operator can use
//! ordinary tools (ls, find, cp, etc.) without a kernel NFS client.
//! The `fuse` feature must be enabled; without it, the command prints an
//! informational message and exits cleanly.

use clap::Parser;

/// FUSE-mount an NFS export with transparent UID spoofing
#[derive(Parser)]
pub struct MountArgs {
    /// NFS server (IP or hostname)
    pub host: String,

    /// Local mount point
    pub mountpoint: String,

    /// Export path to mount (mutually exclusive with --handle)
    #[arg(long, group = "source")]
    pub export: Option<String>,

    /// Raw file handle in hex (for escaped mounts)
    #[arg(long, group = "source")]
    pub handle: Option<String>,

    /// Automatically fake UID/GID to match file ownership
    #[arg(long)]
    pub auto_uid: bool,

    /// Allow faking UID 0 (requires no_root_squash on server)
    #[arg(long)]
    pub allow_root: bool,

    /// Allow write operations (default: read-only)
    #[arg(long)]
    pub allow_write: bool,

    /// Immediately unmount from server (stealth mode)
    #[arg(long)]
    pub hide: bool,

    /// Follow symlinks on server rather than client
    #[arg(long)]
    pub remote_symlinks: bool,

    /// Override NFS port (skip portmapper)
    #[arg(long)]
    pub nfs_port: Option<u16>,

    /// Override mount port (skip portmapper)
    #[arg(long)]
    pub mount_port: Option<u16>,

    /// Allow SUID binaries on the mounted filesystem.
    /// Required for privilege escalation testing (e.g., testing no_root_squash + SUID).
    /// Default: disabled (nosuid).
    #[arg(long)]
    pub suid: bool,

    /// Allow device files on the mounted filesystem.
    /// Default: disabled (nodev).
    #[arg(long)]
    pub dev: bool,

    /// Allow all local users to access the mount (FUSE allow_other option).
    #[arg(long)]
    pub allow_other: bool,

    /// Elevate client-side permissions: copy owner bits to other bits
    /// so that unprivileged local users can access all files through FUSE.
    /// This is a client-side workaround  --  it does NOT change server permissions.
    /// fuse_nfs implements this with `(mode >> 3) & 0o007` bit shifting.
    #[arg(long)]
    pub elevate_perms: bool,

    /// Work around NetApp servers that return null attributes in READDIRPLUS.
    /// Falls back to individual LOOKUP calls for entries with missing attrs.
    #[arg(long)]
    pub fix_nested_exports: bool,

    /// Keepalive interval in seconds (sends NFS NULL probe).
    /// Prevents server from garbage-collecting client state.
    #[arg(long, default_value = "60")]
    pub keepalive_secs: u64,
}

/// Run the `mount` subcommand.
///
/// The `#[cfg(feature = "fuse")]` variant does the real work; the stub
/// variant prints a message and exits cleanly so the binary doesn't break
/// when built without the `fuse` feature.
#[cfg(feature = "fuse")]
pub async fn run(args: MountArgs, globals: &crate::cli::GlobalOpts) -> anyhow::Result<()> {
    use std::net::{IpAddr, SocketAddr};
    use std::sync::Arc;

    use fuser::MountOption;

    use crate::proto::auth::{AuthSys, Credential};
    use crate::proto::circuit::CircuitBreaker;
    use crate::proto::conn::ReconnectStrategy;
    use crate::proto::mount::NfsMountClient;
    use crate::proto::nfs3::client::Nfs3Client;
    use crate::proto::nfs3::types::FileHandle;
    use crate::proto::pool::{ConnectionPool, PoolKey};
    use crate::util::stealth::StealthConfig;

    tracing::info!(host = %args.host, mountpoint = %args.mountpoint, "mounting NFS export via FUSE");

    let host: IpAddr = args.host.parse().map_err(|_| anyhow::anyhow!("invalid host: '{}'", args.host))?;
    let export = args.export.as_deref().unwrap_or("/");
    let addr = SocketAddr::new(host, 111);

    // Obtain the root file handle  --  either via MOUNT or from a raw hex handle.
    let root_fh = if let Some(hex) = &args.handle {
        FileHandle::from_hex(hex)?
    } else {
        let mc = args.mount_port.map_or_else(NfsMountClient::new, NfsMountClient::with_port);
        eprintln!("[*] Mounting {host}:{export}");
        let mr = mc.mount(addr, export).await?;

        // Stealth: unmount from server immediately after obtaining the handle.
        if args.hide {
            let _ = mc.unmount(addr, export).await;
            eprintln!("[*] Stealth: unmounted from server");
        }

        mr.handle
    };

    // Build pool-backed NFS3 client.
    let pool = Arc::new(ConnectionPool::default_config());
    let circuit = Arc::new(CircuitBreaker::default_config());
    let cred = Credential::Sys(AuthSys::new(globals.uid, globals.gid, &globals.hostname));
    let pool_key = PoolKey { host: addr, export: export.to_owned(), uid: globals.uid, gid: globals.gid };
    let stealth = StealthConfig::new(globals.delay, globals.jitter);
    let nfs3 = Arc::new(Nfs3Client::new(Arc::clone(&pool), pool_key, Arc::clone(&circuit), stealth, cred, ReconnectStrategy::Persistent));

    // Assemble FUSE mount options.
    // In fuser v0.15+, `allow_other` is no longer a MountOption variant -- it
    // moved to `Config::acl = SessionACL::All`.  All other per-export flags
    // remain as `MountOption` entries inside `Config::mount_options`.
    let mut mount_options = vec![MountOption::FSName(format!("nfswolf:{}", args.host)), MountOption::DefaultPermissions];
    if args.allow_write {
        mount_options.push(MountOption::RW);
    } else {
        mount_options.push(MountOption::RO);
    }
    if args.suid {
        mount_options.push(MountOption::Suid);
    } else {
        mount_options.push(MountOption::NoSuid);
    }
    if args.dev {
        mount_options.push(MountOption::Dev);
    } else {
        mount_options.push(MountOption::NoDev);
    }
    // Config is #[non_exhaustive] so we can't use a struct literal; mutate after default().
    let mut config = fuser::Config::default();
    config.mount_options = mount_options;
    config.acl = if args.allow_other { fuser::SessionACL::All } else { fuser::SessionACL::Owner };

    let fs = crate::fuse::NfsFuse::new(nfs3, root_fh, args.allow_write, args.elevate_perms);
    eprintln!("[*] Mounting at {} (Ctrl-C to unmount)", args.mountpoint);

    let mountpoint = args.mountpoint.clone();
    tokio::task::spawn_blocking(move || fuser::mount2(fs, &mountpoint, &config)).await??;

    Ok(())
}

/// Stub for builds without the `fuse` feature.
#[cfg(not(feature = "fuse"))]
pub async fn run(_args: MountArgs, _globals: &crate::cli::GlobalOpts) -> anyhow::Result<()> {
    eprintln!("FUSE support not compiled in. Rebuild with: cargo build --features fuse");
    Ok(())
}
