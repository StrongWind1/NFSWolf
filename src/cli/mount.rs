//! FUSE-based NFS mount with automatic UID spoofing.
//!
//! Mounts an NFS export as a local FUSE filesystem so the operator can use
//! ordinary tools (ls, find, cp, etc.) without a kernel NFS client.
//! The `fuse` feature must be enabled; without it, the command prints an
//! informational message and exits cleanly.

use clap::Parser;

use crate::cli::{H_BEHAVIOR, H_PERMISSIONS, H_STEALTH, H_TARGET};

/// FUSE-mount an NFS export with transparent UID spoofing.
///
/// The mount surface is version-neutral: it works over NFSv2, NFSv3, or
/// NFSv4, auto-detecting the best available version when `--nfs-version`
/// is omitted. The auto-UID credential ladder, owner-bit elevation,
/// server-side symlink resolution, suid/dev passthrough, and shared-mount
/// visibility are always on -- this is a security toolkit, the goal is
/// unobstructed access.
///
/// Cleanup: nfswolf detaches itself once the kernel mount is in place
/// (just like mount(8)) and the FUSE handler runs in a daemon process,
/// so the mount survives the operator's shell exiting.  Always unmount
/// manually:
///   `fusermount3 -u MOUNTPOINT`   # Linux
///   `umount MOUNTPOINT`           # macOS
/// After a SIGKILL or hard panic of the daemon, the kernel may keep the
/// mount in a "Transport endpoint is not connected" state; the same
/// command clears it.
///
/// Examples:
///   nfswolf mount 10.0.0.5:/srv /mnt/x
///   nfswolf mount 10.0.0.5 /mnt/x -e /srv
///   nfswolf mount 10.0.0.5 /mnt/x --handle 01000200...
///   nfswolf mount 10.0.0.5:/srv /mnt/x --nfs-version 4
#[derive(Parser)]
pub(crate) struct MountArgs {
    /// Target host with optional :/export suffix (e.g. 10.0.0.5:/srv)
    #[arg(help_heading = H_TARGET, value_name = "TARGET")]
    pub target: String,

    /// Local mount point (must already exist and be a directory)
    #[arg(help_heading = H_TARGET)]
    pub mountpoint: String,

    /// Export path to mount (mutually exclusive with --handle)
    #[arg(short = 'e', long, group = "source", help_heading = H_TARGET)]
    pub export: Option<String>,

    /// Raw file handle in hex (for escaped mounts)
    #[arg(long, group = "source", help_heading = H_TARGET)]
    pub handle: Option<String>,

    /// NFS protocol version (2, 3, or 4). Auto-detected from the server if omitted.
    #[arg(long, value_name = "VER", value_parser = clap::value_parser!(u32).range(2..=4), help_heading = H_BEHAVIOR)]
    pub nfs_version: Option<u32>,

    /// Allow write operations (default: read-only)
    #[arg(long, help_heading = H_PERMISSIONS)]
    pub allow_write: bool,

    /// Immediately unmount from server after capturing the handle (stealth).
    /// Has no effect with --handle, since no MOUNT was performed.
    #[arg(long, help_heading = H_STEALTH)]
    pub hide: bool,
}

/// Synchronous pre-flight checks that must run BEFORE the binary detaches.
#[cfg(feature = "fuse")]
pub(crate) fn preflight(args: &MountArgs) -> anyhow::Result<()> {
    if args.hide && args.handle.is_some() {
        anyhow::bail!("--hide has no effect with --handle: there is no server-side mount to unmount");
    }
    match std::fs::metadata(&args.mountpoint) {
        Ok(md) if md.is_dir() => Ok(()),
        Ok(_) => anyhow::bail!("mountpoint {} is not a directory", args.mountpoint),
        Err(e) => anyhow::bail!("mountpoint {} unusable: {e}", args.mountpoint),
    }
}

#[cfg(feature = "fuse")]
pub(crate) async fn run(args: MountArgs, globals: &crate::cli::GlobalOpts) -> anyhow::Result<()> {
    use std::net::IpAddr;

    tracing::info!(target = %args.target, mountpoint = %args.mountpoint, "mounting NFS export via FUSE");

    let target = crate::cli::target::parse(&args.target, args.export.as_deref(), args.handle.as_deref(), true)?;
    let host: IpAddr = target.host;

    let version = resolve_mount_version(&args, host, globals).await?;
    match version {
        2 => connect_v2_mount(&args, &target, host, globals).await,
        3 => connect_v3_mount(&args, &target, host, globals).await,
        4 => connect_v4_mount(&args, &target, host, globals).await,
        _ => unreachable!("value_parser restricts to 2..=4"),
    }
}

// =============================================================================
// Version detection -- reuses the shell's probing logic
// =============================================================================

#[cfg(feature = "fuse")]
async fn resolve_mount_version(args: &MountArgs, host: std::net::IpAddr, globals: &crate::cli::GlobalOpts) -> anyhow::Result<u32> {
    use std::net::SocketAddr;
    use std::time::Duration;

    if let Some(v) = args.nfs_version {
        return Ok(v);
    }

    eprintln!("{}", crate::output::status_info("No --nfs-version specified, probing server..."));
    let probe_timeout = Duration::from_secs(2);
    let pmap_addr = SocketAddr::new(host, 111);
    let portmap = match &globals.proxy {
        Some(p) => crate::proto::portmap::PortmapClient::default_port().with_proxy(p.clone()),
        None => crate::proto::portmap::PortmapClient::default_port(),
    };

    if let Ok(Ok(port)) = tokio::time::timeout(probe_timeout, portmap.query_port(pmap_addr, 100_003, 3)).await
        && port > 0
        && crate::cli::shell::verify_nfs_version_tcp(host, port, 3, probe_timeout, globals.proxy.as_deref()).await
    {
        eprintln!("{}", crate::output::status_ok(&format!("Detected NFSv3 on port {port}")));
        return Ok(3);
    }

    if let Ok(Ok(port)) = tokio::time::timeout(probe_timeout, portmap.query_port(pmap_addr, 100_003, 2)).await
        && port > 0
        && crate::cli::shell::verify_nfs_version_tcp(host, port, 2, probe_timeout, globals.proxy.as_deref()).await
    {
        eprintln!("{}", crate::output::status_ok(&format!("Detected NFSv2 on port {port}")));
        return Ok(2);
    }

    let nfs_port = globals.nfs_port.unwrap_or(2049);
    let v4_addr = SocketAddr::new(host, nfs_port);
    if let Ok(Ok(_)) = tokio::time::timeout(probe_timeout, async {
        let mut client = crate::proto::nfs4::compound::Nfs4DirectClient::connect_proxy(v4_addr, globals.proxy.as_deref()).await?;
        client.get_root_fh().await
    })
    .await
    {
        eprintln!("{}", crate::output::status_ok(&format!("Detected NFSv4 on port {nfs_port}")));
        return Ok(4);
    }

    anyhow::bail!("Could not detect NFS version on {host}. Specify --nfs-version explicitly (2, 3, or 4).")
}

// =============================================================================
// Per-version connect + mount
// =============================================================================

#[cfg(feature = "fuse")]
async fn connect_v3_mount(args: &MountArgs, target: &crate::cli::target::Target, host: std::net::IpAddr, globals: &crate::cli::GlobalOpts) -> anyhow::Result<()> {
    use std::net::SocketAddr;
    use std::sync::Arc;

    use crate::cli::probe::make_mount_client;
    use crate::proto::auth::{AuthSys, Credential};
    use crate::proto::circuit::CircuitBreaker;
    use crate::proto::conn::ReconnectStrategy;
    use crate::proto::nfs3::Nfs3Client;
    use crate::proto::nfs3::types::FileHandle;
    use crate::proto::pool::{ConnectionPool, PoolKey};
    use crate::proto::transport::PooledTransport;
    use crate::shell::ops::ShellHandle;
    use crate::shell::v3::V3Ops;
    use crate::util::stealth::StealthConfig;

    let (export, handle_hex) = parse_source(target);
    let addr = SocketAddr::new(host, 111);

    let direct_nfs_port = match (handle_hex.is_some(), globals.nfs_port) {
        (_, Some(p)) => Some(p),
        (true, None) => Some(2049),
        (false, None) => None,
    };

    let root_fh = if let Some(hex) = &handle_hex {
        FileHandle::from_hex(hex)?
    } else {
        let mc = make_mount_client(globals);
        eprintln!("{}", crate::output::status_info(&format!("Mounting {host}:{export} (NFSv3)")));
        let mr = mc.mount(addr, &export).await?;
        stealth_unmount(&mc, addr, &export, args.hide).await;
        mr.handle
    };

    let pool = Arc::new(match &globals.proxy {
        Some(p) => ConnectionPool::with_proxy(p.clone()),
        None => ConnectionPool::default_config(),
    });
    let circuit = Arc::new(CircuitBreaker::default_config());
    let gids = crate::cli::probe::build_gid_list(globals.gid, &globals.aux_gids);
    let cred = Credential::Sys(AuthSys::with_groups(globals.uid, globals.gid, &gids, &globals.hostname));
    let pool_key = PoolKey { host: addr, export: export.clone(), uid: globals.uid, gid: globals.gid };
    let stealth = StealthConfig::new(globals.delay, globals.jitter);
    let nfs3 = Arc::new(if let Some(nfs_port) = direct_nfs_port {
        Nfs3Client::new(PooledTransport::new_direct(Arc::clone(&pool), pool_key, Arc::clone(&circuit), stealth, cred, ReconnectStrategy::Persistent, nfs_port))
    } else {
        Nfs3Client::new(PooledTransport::new(Arc::clone(&pool), pool_key, Arc::clone(&circuit), stealth, cred, ReconnectStrategy::Persistent))
    });

    let ops = V3Ops::new(nfs3);
    let root = ShellHandle(root_fh.as_bytes().to_vec());
    do_mount(ops, root, args, host, &export, handle_hex.is_some()).await
}

#[cfg(feature = "fuse")]
async fn connect_v2_mount(args: &MountArgs, target: &crate::cli::target::Target, host: std::net::IpAddr, globals: &crate::cli::GlobalOpts) -> anyhow::Result<()> {
    use std::net::SocketAddr;
    use std::sync::Arc;

    use crate::cli::probe::{make_mount_client, make_v2_client_with_hostname, parse_addr_with_port};
    use crate::proto::nfs3::types::FileHandle;
    use crate::shell::ops::ShellHandle;
    use crate::shell::v2::V2Ops;
    use crate::util::stealth::StealthConfig;

    let (export, handle_hex) = parse_source(target);

    let root_fh = if let Some(hex) = &handle_hex {
        let generic = FileHandle::from_hex(hex).map_err(|e| anyhow::anyhow!("invalid --handle: {e}"))?;
        nfs_v2::wire::Nfs2FileHandle::from_bytes(generic.as_bytes())
    } else {
        let mc = make_mount_client(globals);
        let addr = SocketAddr::new(host, 111);
        eprintln!("{}", crate::output::status_info(&format!("Mounting {host}:{export} (MOUNT v1 / NFSv2)")));
        let mr = mc.mount_v1(addr, &export).await?;
        stealth_unmount(&mc, addr, &export, args.hide).await;
        nfs_v2::wire::Nfs2FileHandle::from_bytes(mr.handle.as_bytes())
    };

    let nfs_port = Some(globals.nfs_port.unwrap_or(2049));
    let addr = parse_addr_with_port(&host.to_string(), nfs_port)?;
    let stealth = StealthConfig::new(globals.delay, globals.jitter);
    let (_pool, _circuit, client) = make_v2_client_with_hostname(addr, &export, globals.uid, globals.gid, &globals.aux_gids, stealth, globals.proxy.as_deref(), nfs_port, &globals.hostname);
    let client = Arc::new(client);

    let ops = V2Ops::new(client);
    let root = ShellHandle(root_fh.0.to_vec());
    do_mount(ops, root, args, host, &export, handle_hex.is_some()).await
}

#[cfg(feature = "fuse")]
async fn connect_v4_mount(args: &MountArgs, target: &crate::cli::target::Target, host: std::net::IpAddr, globals: &crate::cli::GlobalOpts) -> anyhow::Result<()> {
    use std::net::SocketAddr;
    use std::sync::Arc;

    use crate::proto::auth::{AuthSys, Credential};
    use crate::proto::circuit::CircuitBreaker;
    use crate::proto::conn::ReconnectStrategy;
    use crate::proto::nfs4::Nfs4Client as PooledNfs4Client;
    use crate::proto::pool::{ConnectionPool, PoolKey};
    use crate::proto::transport::PooledTransport;
    use crate::shell::ops::ShellHandle;
    use crate::shell::v4::V4Ops;
    use crate::util::stealth::StealthConfig;

    let (export, handle_hex) = parse_source(target);
    let nfs_port = globals.nfs_port.unwrap_or(2049);
    let addr = SocketAddr::new(host, nfs_port);

    eprintln!("{}", crate::output::status_info(&format!("Connecting to {host}:{nfs_port} via NFSv4 (no MOUNT)")));

    let pool = Arc::new(match &globals.proxy {
        Some(p) => ConnectionPool::with_proxy(p.clone()),
        None => ConnectionPool::default_config(),
    });
    let circuit = Arc::new(CircuitBreaker::default_config());
    let stealth = StealthConfig::new(globals.delay, globals.jitter);
    let gids = crate::cli::probe::build_gid_list(globals.gid, &globals.aux_gids);
    let cred = Credential::Sys(AuthSys::with_groups(globals.uid, globals.gid, &gids, &globals.hostname));
    let pool_key = PoolKey { host: addr, export: format!("__nfs4__{nfs_port}"), uid: globals.uid, gid: globals.gid };
    let transport = PooledTransport::new_direct(Arc::clone(&pool), pool_key, Arc::clone(&circuit), stealth, cred, ReconnectStrategy::Persistent, nfs_port);
    let client = Arc::new(PooledNfs4Client::new(transport));

    let root_fh = if let Some(hex) = &handle_hex {
        eprintln!("{}", crate::output::status_info(&format!("Using raw handle (NFSv4): {hex}")));
        ShellHandle::from_hex(hex).map_err(|e| anyhow::anyhow!("invalid --handle: {e}"))?
    } else {
        // Navigate from the pseudo-root into the export path via LOOKUP.
        // PUTROOTFH gives the NFSv4 pseudo-root (/); we need the export
        // directory itself, not the top-level pseudo-FS.
        let components: Vec<&str> = export.trim_matches('/').split('/').filter(|s| !s.is_empty()).collect();
        let fh_bytes = if components.is_empty() {
            client.get_root_fh().await.map_err(|e| anyhow::anyhow!("PUTROOTFH failed: {e}"))?
        } else {
            eprintln!("{}", crate::output::status_info(&format!("Navigating to export {export}")));
            client.lookup_fh(&components).await.map_err(|e| anyhow::anyhow!("LOOKUP into {export} failed: {e}"))?
        };
        ShellHandle(fh_bytes)
    };

    let ops = V4Ops::new(client);
    do_mount(ops, root_fh, args, host, &export, handle_hex.is_some()).await
}

// =============================================================================
// Shared helpers
// =============================================================================

#[cfg(feature = "fuse")]
fn parse_source(target: &crate::cli::target::Target) -> (String, Option<String>) {
    match &target.source {
        crate::cli::target::Source::Export(p) => (p.clone(), None),
        crate::cli::target::Source::Handle(h) => (String::from("/"), Some(h.clone())),
        crate::cli::target::Source::None => (String::from("/"), None),
    }
}

#[cfg(feature = "fuse")]
async fn stealth_unmount(mc: &crate::proto::mount::NfsMountClient, addr: std::net::SocketAddr, export: &str, hide: bool) {
    if hide {
        match mc.unmount(addr, export).await {
            Ok(()) => eprintln!("{}", crate::output::status_info("Stealth: unmounted from server")),
            Err(e) => tracing::warn!(error = %e, "stealth UMNT failed; server may still show this client in its mount table"),
        }
    }
}

#[cfg(feature = "fuse")]
async fn do_mount<O: crate::shell::ops::ShellOps>(ops: O, root_fh: crate::shell::ops::ShellHandle, args: &MountArgs, host: std::net::IpAddr, export: &str, is_handle: bool) -> anyhow::Result<()> {
    use std::path::Path;

    use fuser::MountOption;

    let fs_name = if is_handle { format!("nfswolf:{host}:handle") } else { format!("nfswolf:{host}:{export}") };
    let mut mount_options = vec![MountOption::FSName(fs_name), MountOption::DefaultPermissions, MountOption::Suid, MountOption::Dev];
    if args.allow_write {
        mount_options.push(MountOption::RW);
    } else {
        mount_options.push(MountOption::RO);
    }
    tracing::warn!("FUSE mount uses suid+dev passthrough for security testing (F-4.2, F-4.3) -- do not use on production systems");

    let mut config = fuser::Config::default();
    config.mount_options = mount_options;
    config.acl = fuser::SessionACL::All;

    let rt_handle = tokio::runtime::Handle::current();
    let fs = crate::fuse::NfsFuse::new(crate::fuse::NfsFuseConfig { ops, root_fh, allow_write: args.allow_write, rt: rt_handle });

    let mountpoint = Path::new(&args.mountpoint).to_path_buf();
    tokio::task::spawn_blocking(move || fuser::mount(fs, &mountpoint, &config)).await??;
    Ok(())
}
