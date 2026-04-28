//! FUSE-based NFS mount with automatic UID spoofing.
//!
//! Mounts an NFS export as a local FUSE filesystem so the operator can use
//! ordinary tools (ls, find, cp, etc.) without a kernel NFS client.
//! The `fuse` feature must be enabled; without it, the command prints an
//! informational message and exits cleanly.

use clap::Parser;

use crate::cli::{H_PERMISSIONS, H_STEALTH, H_TARGET};

/// FUSE-mount an NFS export with transparent UID spoofing.
///
/// The mount surface implements the full set of NFSv3 procedures (every
/// `Nfs3Client` method is wired through a corresponding FUSE callback).
/// The auto-UID credential ladder, owner-bit elevation, server-side symlink
/// resolution, suid/dev passthrough, and shared-mount visibility are always
/// on -- this is a security toolkit, the goal is unobstructed access.
///
/// Protocol scope: NFSv3 only. NFSv4-only servers are not supported by the
/// FUSE mount; use `nfswolf shell --nfs-version 4` for interactive NFSv4
/// browsing instead.
///
/// Cleanup: the mount is unmounted automatically when the process exits
/// cleanly. After a SIGKILL or hard panic the kernel may keep the mount
/// in a "Transport endpoint is not connected" state; clean it up with
/// `fusermount -u <mountpoint>` (Linux) or `umount <mountpoint>` (macOS).
///
/// Examples:
///   nfswolf mount 10.0.0.5:/srv /mnt/x
///   nfswolf mount 10.0.0.5 /mnt/x -e /srv
///   nfswolf mount 10.0.0.5 /mnt/x --handle 01000200...
#[derive(Parser)]
pub struct MountArgs {
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

    /// Allow write operations (default: read-only)
    #[arg(long, help_heading = H_PERMISSIONS)]
    pub allow_write: bool,

    /// Immediately unmount from server after capturing the handle (stealth).
    /// Has no effect with --handle, since no MOUNT was performed.
    #[arg(long, help_heading = H_STEALTH)]
    pub hide: bool,
}

/// Run the `mount` subcommand.
///
/// The `#[cfg(feature = "fuse")]` variant does the real work; the stub
/// variant prints a message and exits cleanly so the binary doesn't break
/// when built without the `fuse` feature.
#[cfg(feature = "fuse")]
pub async fn run(args: MountArgs, globals: &crate::cli::GlobalOpts) -> anyhow::Result<()> {
    use std::net::{IpAddr, SocketAddr};
    use std::path::Path;
    use std::sync::Arc;

    use fuser::MountOption;

    use crate::cli::probe::make_mount_client;
    use crate::proto::auth::{AuthSys, Credential};
    use crate::proto::circuit::CircuitBreaker;
    use crate::proto::conn::ReconnectStrategy;
    use crate::proto::nfs3::client::Nfs3Client;
    use crate::proto::nfs3::types::FileHandle;
    use crate::proto::pool::{ConnectionPool, PoolKey};
    use crate::util::stealth::StealthConfig;

    tracing::info!(target = %args.target, mountpoint = %args.mountpoint, "mounting NFS export via FUSE");

    // Reject incoherent flag combinations early so the operator gets a
    // clear error before we do any network work.
    if args.hide && args.handle.is_some() {
        anyhow::bail!("--hide has no effect with --handle: there is no server-side mount to unmount");
    }

    // Pre-flight the mountpoint so fuser doesn't return an opaque errno.
    match std::fs::metadata(&args.mountpoint) {
        Ok(md) if md.is_dir() => {},
        Ok(_) => anyhow::bail!("mountpoint {} is not a directory", args.mountpoint),
        Err(e) => anyhow::bail!("mountpoint {} unusable: {e}", args.mountpoint),
    }

    // Parse the unified `<TARGET>` -- accepts host, host:/export, or
    // bare host with --export / --handle. Mount requires a source.
    let target = crate::cli::target::parse(&args.target, args.export.as_deref(), args.handle.as_deref(), true)?;
    let host: IpAddr = target.host;
    let (export, handle_hex) = match target.source {
        crate::cli::target::Source::Export(p) => (p, None),
        crate::cli::target::Source::Handle(h) => (String::from("/"), Some(h)),
        crate::cli::target::Source::None => unreachable!("target::parse(.., true) rejected this"),
    };
    let export = export.as_str();
    let addr = SocketAddr::new(host, 111);

    // Decide whether the connection pool should bypass portmapper/MOUNT for
    // future checkouts. We do this in two cases:
    //   1. `--handle` is given (no MOUNT to begin with, so every reconnect
    //      must go directly to the NFS port -- otherwise the pool would
    //      re-mount on every checkout, defeating the whole point of
    //      `--handle`).
    //   2. `--nfs-port` is explicitly set (the operator wants every NFS
    //      call to land on a specific port regardless of what portmapper
    //      reports). The default fallback is 2049 only when `--handle`
    //      forces a direct path; otherwise we honour exactly what was
    //      provided.
    let direct_nfs_port = match (handle_hex.is_some(), globals.nfs_port) {
        (_, Some(p)) => Some(p),
        (true, None) => Some(2049),
        (false, None) => None,
    };

    // Obtain the root file handle  --  either via MOUNT or from a raw hex handle.
    let root_fh = if let Some(hex) = &handle_hex {
        FileHandle::from_hex(hex)?
    } else {
        let mc = make_mount_client(globals);
        eprintln!("{}", crate::output::status_info(&format!("Mounting {host}:{export}")));
        let mr = mc.mount(addr, export).await?;

        // Stealth: unmount from server immediately after obtaining the handle.
        // The local FUSE mount continues to use the captured handle (file
        // handles are bearer tokens per RFC 1094 S2.3.3), so dropping the
        // server-side MOUNT entry doesn't break us.
        if args.hide {
            match mc.unmount(addr, export).await {
                Ok(()) => eprintln!("{}", crate::output::status_info("Stealth: unmounted from server")),
                Err(e) => tracing::warn!(error = %e, "stealth UMNT failed; server may still show this client in its mount table"),
            }
        }

        mr.handle
    };

    // Build pool-backed NFS3 client. When `--handle` is supplied, route the
    // pool through `checkout_direct` so future RPC calls bypass MOUNT.
    // `--proxy` is honoured: every TCP connection the pool opens (initial
    // mount, raw-RPC handle, reconnects) tunnels through the SOCKS5 proxy.
    let pool = Arc::new(match &globals.proxy {
        Some(p) => ConnectionPool::with_proxy(p.clone()),
        None => ConnectionPool::default_config(),
    });
    let circuit = Arc::new(CircuitBreaker::default_config());
    // Build the AUTH_SYS credential once; the FUSE adapter takes its own
    // copy via `default_cred` so we clone rather than rebuild from scratch.
    // `--aux-gids` from the global flag is folded in here so FUSE callbacks
    // inherit the same group set (e.g. shadow GID 42 to read /etc/shadow).
    let gids = crate::cli::probe::build_gid_list(globals.gid, &globals.aux_gids);
    let cred = Credential::Sys(AuthSys::with_groups(globals.uid, globals.gid, &gids, &globals.hostname));
    let pool_key = PoolKey { host: addr, export: export.to_owned(), uid: globals.uid, gid: globals.gid };
    let stealth = StealthConfig::new(globals.delay, globals.jitter);
    let nfs3 = Arc::new(if let Some(nfs_port) = direct_nfs_port {
        Nfs3Client::new_direct(Arc::clone(&pool), pool_key, Arc::clone(&circuit), stealth, cred.clone(), ReconnectStrategy::Persistent, nfs_port)
    } else {
        Nfs3Client::new(Arc::clone(&pool), pool_key, Arc::clone(&circuit), stealth, cred.clone(), ReconnectStrategy::Persistent)
    });

    // Assemble FUSE mount options. This is a security toolkit, so the
    // mount is configured for maximum local-side access:
    //   - suid + dev are honoured (needed for SUID escalation testing)
    //   - allow_other (`SessionACL::All`) makes the mount visible to every
    //     local user, not just whoever ran nfswolf
    //   - DefaultPermissions delegates kernel-level perm checks to the
    //     POSIX semantics layer above us
    // The FSName uses the resolved IP (and export path when available)
    // rather than the raw `<TARGET>` -- otherwise the colon-form leaks
    // colons into `mount | grep nfswolf` listings.
    let fs_name = if handle_hex.is_some() { format!("nfswolf:{host}:handle") } else { format!("nfswolf:{host}:{export}") };
    // In fuser v0.15+, `allow_other` is no longer a MountOption variant -- it
    // moved to `Config::acl = SessionACL::All`. All other per-export flags
    // remain as `MountOption` entries inside `Config::mount_options`.
    let mut mount_options = vec![MountOption::FSName(fs_name), MountOption::DefaultPermissions, MountOption::Suid, MountOption::Dev];
    if args.allow_write {
        mount_options.push(MountOption::RW);
    } else {
        mount_options.push(MountOption::RO);
    }
    // Config is #[non_exhaustive] so we can't use a struct literal; mutate after default().
    let mut config = fuser::Config::default();
    config.mount_options = mount_options;
    config.acl = fuser::SessionACL::All;

    // Capture the runtime handle before handing the FUSE filesystem to a
    // blocking thread. The fuser session spawns its own worker threads which
    // are not Tokio tasks; passing this handle in lets those threads dispatch
    // async NFS calls onto the runtime that owns the connection pool.
    let rt_handle = tokio::runtime::Handle::current();
    let fs = crate::fuse::NfsFuse::new(crate::fuse::NfsFuseConfig { nfs3, root_fh, allow_write: args.allow_write, default_cred: cred, rt: rt_handle });
    eprintln!("{}", crate::output::status_info(&format!("Mounting at {} (Ctrl-C to unmount)", args.mountpoint)));

    let mountpoint = Path::new(&args.mountpoint).to_path_buf();
    tokio::task::spawn_blocking(move || fuser::mount2(fs, &mountpoint, &config)).await??;

    crate::cli::emit_replay(globals);
    Ok(())
}

/// Stub for builds without the `fuse` feature.
#[cfg(not(feature = "fuse"))]
pub async fn run(_args: MountArgs, _globals: &crate::cli::GlobalOpts) -> anyhow::Result<()> {
    eprintln!("FUSE support not compiled in. Rebuild with: cargo build --features fuse");
    Ok(())
}
