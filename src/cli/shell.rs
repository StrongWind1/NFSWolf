//! Interactive NFS exploration shell.
//!
//! Connects to an NFS server, mounts an export, and enters a readline REPL
//! so the operator can browse the filesystem without a kernel NFS client.
//! A single `--command` flag lets it run headlessly (useful in scripts).

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use clap::Parser;
use rustyline::Editor;
use rustyline::error::ReadlineError;
use rustyline::history::DefaultHistory;

use crate::cli::probe::{build_gid_list, make_mount_client};
use crate::cli::target::Source as TargetSource;
use crate::cli::{GlobalOpts, H_BEHAVIOR, H_IDENTITY, H_PERMISSIONS, H_TARGET};
use crate::proto::auth::{AuthSys, Credential};
use crate::proto::circuit::CircuitBreaker;
use crate::proto::conn::ReconnectStrategy;
use crate::proto::nfs3::Nfs3Client;
use crate::proto::nfs3::types::FileHandle;
use crate::proto::pool::{ConnectionPool, PoolKey};
use crate::proto::transport::PooledTransport;
use crate::shell::NfsShell;
use crate::shell::complete::ShellCompleter;
use crate::shell::ops::ShellHandle;
use crate::shell::v3::V3Ops;
use crate::util::stealth::StealthConfig;

/// Interactive NFS exploration shell.
///
/// Opens a readline REPL over NFS so you can browse exports without a kernel
/// NFS client.  Use -c for non-interactive (scripting) mode.
///
/// Target formats (same shape across every subcommand):
///   host              mount root /, no export needed  (rare)
///   host:/export      mount the named export
///   host --export /p  same, but supplied as a flag
///   host --handle HEX bypass MOUNT, use a raw root file handle
///
/// Examples:
///   nfswolf shell 192.168.1.10:/srv
///   nfswolf shell 192.168.1.10 -c "ls /etc"
///   nfswolf shell 192.168.1.10 --handle 01000200abcdef... --allow-write
///   nfswolf shell 192.168.1.10:/srv --uid 0
#[derive(Parser)]
pub(crate) struct ShellArgs {
    /// Target host with optional :/export suffix (e.g. 10.0.0.5:/srv)
    #[arg(help_heading = H_TARGET)]
    pub target: String,

    /// Export path (alternative to host:/export in the positional target)
    #[arg(short = 'e', long, value_name = "PATH", help_heading = H_TARGET)]
    pub export: Option<String>,

    /// Enable write operations (CREATE, WRITE, MKDIR, REMOVE, etc.)
    #[arg(long, help_heading = H_PERMISSIONS)]
    pub allow_write: bool,

    /// Run a single shell command then exit (non-interactive / scripting mode)
    #[arg(short = 'c', long, value_name = "CMD", help_heading = H_BEHAVIOR)]
    pub command: Option<String>,

    /// Use a raw file handle (hex) as the shell root  --  skips MOUNT entirely.
    /// Obtain handles from `nfswolf escape` or `nfswolf brute-handle`.
    #[arg(long, value_name = "HEX", help_heading = H_TARGET)]
    pub handle: Option<String>,

    /// NFS protocol version (2, 3, or 4). Auto-detected from the server if omitted.
    #[arg(long, value_name = "VER", value_parser = clap::value_parser!(u32).range(2..=4), help_heading = H_BEHAVIOR)]
    pub nfs_version: Option<u32>,

    /// AUTH_SHORT session token (hex). Replays a server-issued opaque token
    /// as the RPC credential instead of AUTH_SYS. Obtain from a packet
    /// capture or from the analyzer's F-3.9 active probe against non-Linux
    /// NFS servers (Solaris, NetApp ONTAP).
    #[arg(long, value_name = "HEX", help_heading = H_IDENTITY)]
    pub short_token: Option<String>,
}

// =============================================================================
// Shared setup
// =============================================================================

/// Parsed configuration shared across all NFS version connect paths.
///
/// Built once by `from_args`, then consumed by the version-specific
/// `connect_v3` / `connect_v2` / `connect_v4` functions. Avoids repeating
/// pool/circuit/credential construction three times.
struct ShellSetup {
    host: std::net::IpAddr,
    target: crate::cli::target::Target,
    pool: Arc<ConnectionPool>,
    circuit: Arc<CircuitBreaker>,
    stealth: StealthConfig,
    cred: Credential,
    uid: u32,
    gid: u32,
    hostname: String,
    allow_write: bool,
    command: Option<String>,
    nfs_port: Option<u16>,
}

impl ShellSetup {
    /// Parse `ShellArgs` + `GlobalOpts` into the version-neutral setup struct.
    fn from_args(args: &ShellArgs, globals: &GlobalOpts) -> anyhow::Result<Self> {
        let target = crate::cli::target::parse(&args.target, args.export.as_deref(), args.handle.as_deref(), false)?;
        let host = target.host;
        let uid = globals.uid;
        let gid = globals.gid;
        let hostname = globals.hostname.clone();

        let pool = Arc::new(match &globals.proxy {
            Some(p) => ConnectionPool::with_proxy(p.clone()),
            None => ConnectionPool::default_config(),
        });
        let circuit = Arc::new(CircuitBreaker::default_config());
        let stealth = StealthConfig::new(globals.delay, globals.jitter);
        let gids = build_gid_list(gid, &globals.aux_gids);
        let cred = if let Some(ref hex) = args.short_token {
            let token = ShellHandle::from_hex(hex).map_err(|e| anyhow::anyhow!("invalid --short-token hex: {e}"))?;
            eprintln!("{}", crate::output::status_info(&format!("Using AUTH_SHORT token ({} bytes)", token.0.len())));
            Credential::Short(token.0)
        } else {
            Credential::Sys(AuthSys::with_groups(uid, gid, &gids, &hostname))
        };

        Ok(Self { host, target, pool, circuit, stealth, cred, uid, gid, hostname, allow_write: args.allow_write, command: args.command.clone(), nfs_port: globals.nfs_port })
    }
}

// =============================================================================
// Generic REPL loop
// =============================================================================

/// Run the interactive REPL (or a single `--command`) for any NFS version.
///
/// `version_tag` is appended to the prompt: `""` for v3, `" [v2]"` for v2,
/// `" [v4]"` for v4. When `command` is `Some`, dispatches once and returns
/// without entering the readline loop.
async fn run_repl<O: crate::shell::ops::ShellOps>(shell: &mut NfsShell<O>, host: std::net::IpAddr, command: Option<&str>, version_tag: &str, globals: &GlobalOpts) -> anyhow::Result<()> {
    if let Some(cmd) = command {
        // Non-interactive: run one command and return.
        shell.dispatch(cmd).await;
        crate::cli::emit_replay(globals);
        return Ok(());
    }

    // Interactive REPL with Tab completion.
    let completer = shell.make_completer();
    let mut rl = Editor::<ShellCompleter, DefaultHistory>::new()?;
    rl.set_helper(Some(completer));

    loop {
        // Read uid/gid from the shell so the prompt tracks mid-session
        // `uid` / `gid` / `impersonate` changes (the credential lives on the
        // client, not the captured `uid` local).
        let prompt = format!("nfswolf@{host}:{} uid={} gid={}{version_tag}> ", shell.cwd_path(), shell.current_uid(), shell.current_gid());
        match rl.readline(&prompt) {
            Ok(line) => {
                // History add failure is non-fatal (in-memory only).
                drop(rl.add_history_entry(&line));
                let trimmed = line.trim();
                if trimmed == "exit" || trimmed == "quit" {
                    break;
                }
                shell.dispatch(&line).await;
                // Keep completer's shared cache pointer in sync after commands
                // that might change the cwd (mount-handle, escape-root update
                // self.cwd but don't call refresh_tab_cache). Cheaply sync the
                // cwd file handle pointer so live lookups in the completer use
                // the right parent.
            },
            Err(ReadlineError::Interrupted | ReadlineError::Eof) => break,
            Err(e) => {
                eprintln!("readline error: {e}");
                break;
            },
        }
    }
    crate::cli::emit_replay(globals);
    Ok(())
}

// =============================================================================
// Auto-version detection
// =============================================================================

/// Determine the NFS version to use.
///
/// If the user set `--nfs-version`, return that immediately (no network I/O).
/// Otherwise, probe the server: try v3 (portmapper GETPORT 100003/3), then
/// v2 (GETPORT 100003/2), then v4 (direct COMPOUND to port 2049). v3 first
/// because it is the most common; v2 before v4 because v2 servers tend to
/// have weaker security (more interesting for a security tool); v4 last as
/// the fallback when portmapper (111/tcp) is firewalled.
///
/// GETPORT alone is not sufficient: some portmappers register all NFS
/// versions against a single daemon that only speaks a subset (e.g. v2-only
/// knfsd registered as v2 *and* v3). After GETPORT returns a port, we send
/// an RPC NULL to that port with the claimed version. A PROG_MISMATCH reply
/// means the daemon does not actually speak that version.
async fn resolve_version(args: &ShellArgs, globals: &GlobalOpts) -> anyhow::Result<u32> {
    if let Some(v) = args.nfs_version {
        return Ok(v);
    }

    // Parse the target just to extract the host IP.
    let target = crate::cli::target::parse(&args.target, args.export.as_deref(), args.handle.as_deref(), false)?;
    let host = target.host;

    eprintln!("{}", crate::output::status_info("No --nfs-version specified, probing server..."));

    let probe_timeout = Duration::from_secs(2);
    let pmap_addr = SocketAddr::new(host, 111);
    let portmap = match &globals.proxy {
        Some(p) => crate::proto::portmap::PortmapClient::default_port().with_proxy(p.clone()),
        None => crate::proto::portmap::PortmapClient::default_port(),
    };

    // Try NFSv3 via portmapper GETPORT, then verify with a TCP NULL call.
    if let Ok(Ok(port)) = tokio::time::timeout(probe_timeout, portmap.query_port(pmap_addr, 100_003, 3)).await
        && port > 0
        && verify_nfs_version_tcp(host, port, 3, probe_timeout, globals.proxy.as_deref()).await
    {
        eprintln!("{}", crate::output::status_ok(&format!("Detected NFSv3 on port {port}")));
        return Ok(3);
    }

    // Try NFSv2 via portmapper GETPORT, then verify with a TCP NULL call.
    if let Ok(Ok(port)) = tokio::time::timeout(probe_timeout, portmap.query_port(pmap_addr, 100_003, 2)).await
        && port > 0
        && verify_nfs_version_tcp(host, port, 2, probe_timeout, globals.proxy.as_deref()).await
    {
        eprintln!("{}", crate::output::status_ok(&format!("Detected NFSv2 on port {port}")));
        return Ok(2);
    }

    // Try NFSv4 via direct COMPOUND to port 2049 (no portmapper needed).
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

/// Send an RPC NULL (procedure 0) to the NFS program at `host:port` with the
/// given `version`. Returns `true` if the server accepts (no PROG_MISMATCH),
/// `false` if the reply indicates a version mismatch or the connection fails.
pub(crate) async fn verify_nfs_version_tcp(host: std::net::IpAddr, port: u16, version: u32, timeout_dur: Duration, proxy: Option<&str>) -> bool {
    use onc_rpc_client::RpcClient;
    use onc_rpc_client::transport::tokio::TokioIo;
    use onc_xdr::Void;
    use tokio::net::TcpStream;

    let addr = SocketAddr::new(host, port);
    let connect_result = if let Some(p) = proxy {
        let Ok(proxy_addr) = crate::proto::conn::parse_proxy_addr(p) else {
            return false;
        };
        tokio::time::timeout(timeout_dur, crate::proto::conn::socks5_connect(proxy_addr, addr)).await
    } else {
        tokio::time::timeout(timeout_dur, TcpStream::connect(addr)).await
    };

    let Ok(Ok(stream)) = connect_result else {
        return false;
    };

    let mut client = RpcClient::new(TokioIo::new(stream));
    // NULL call: program 100003, proc 0, no args/reply body.
    matches!(client.call::<Void, Void>(100_003, version, 0, &Void).await, Ok(Void))
}

// =============================================================================
// Entry point
// =============================================================================

/// Entry point for the `shell` subcommand.
pub(crate) async fn run(args: ShellArgs, globals: &GlobalOpts) -> anyhow::Result<()> {
    tracing::info!(target = %args.target, "starting NFS shell");
    let version = resolve_version(&args, globals).await?;
    let setup = ShellSetup::from_args(&args, globals)?;
    match version {
        2 => connect_v2(&setup, globals).await,
        3 => connect_v3(&setup, globals).await,
        4 => connect_v4(&setup, globals).await,
        _ => unreachable!("value_parser restricts to 2..=4, and resolve_version returns 2/3/4"),
    }
}

// `parse_target` / `resolve_host` removed -- target parsing now lives in
// `crate::cli::target`, shared by all subcommands.

// =============================================================================
// NFSv3 connect
// =============================================================================

/// Connect via NFSv3: MOUNT v3 (with v1 fallback) or `--handle` bypass.
async fn connect_v3(setup: &ShellSetup, globals: &GlobalOpts) -> anyhow::Result<()> {
    let host = setup.host;
    let uid = setup.uid;
    let gid = setup.gid;

    let (export, handle_hex_arg): (String, Option<String>) = match &setup.target.source {
        TargetSource::Export(p) => (p.clone(), None),
        TargetSource::Handle(h) => (String::from("/"), Some(h.clone())),
        TargetSource::None => (String::from("/"), None),
    };

    let addr = SocketAddr::new(host, 111);

    // When --handle is given, skip MOUNT entirely and connect straight to the
    // NFS data port. The raw handle is the shell root (file handles are bearer
    // tokens per RFC 1094 S2.3.3 / RFC 2623 S2.6), so no MOUNT/EXPORT RPC is
    // needed. Issuing MNTPROC_EXPORT here would block on SYN timeouts when
    // portmapper/mountd (TCP/111) is firewalled -- the exact case --handle
    // exists to bypass.
    let (root_fh, pool_key, direct_nfs_port) = if let Some(ref hex) = handle_hex_arg {
        let fh = FileHandle::from_hex(hex).map_err(|e| anyhow::anyhow!("invalid --handle: {e}"))?;
        eprintln!("{}", crate::output::status_info(&format!("Using raw handle: {hex}")));

        let nfs_port = setup.nfs_port.unwrap_or(2049);
        eprintln!("{}", crate::output::status_info(&format!("Session via {host}:{nfs_port} (MOUNT bypassed)")));
        let key = PoolKey { host: SocketAddr::new(host, nfs_port), export: format!("__handle__{nfs_port}"), uid, gid };
        (fh, key, Some(nfs_port))
    } else {
        let mount_client = make_mount_client(globals);
        eprintln!("{}", crate::output::status_info(&format!("Mounting {host}:{export}")));
        let (mount_result, via_v1) = match mount_client.mount(addr, &export).await {
            Ok(r) => (r, false),
            Err(v3_err) => {
                tracing::info!("MOUNT v3 failed ({v3_err}); trying MOUNT v1");
                let r = mount_client.mount_v1(addr, &export).await.map_err(|v1_err| anyhow::anyhow!("MOUNT v3: {v3_err}; MOUNT v1: {v1_err}"))?;
                (r, true)
            },
        };
        let key = PoolKey { host: addr, export: export.clone(), uid, gid };
        // When MOUNT v1 returned the handle, force direct port 2049 so the
        // pooled transport doesn't try a lazy MOUNT v3 (which would fail again).
        let direct_port = if via_v1 && setup.nfs_port.is_none() { Some(2049) } else { setup.nfs_port };
        (mount_result.handle, key, direct_port)
    };

    let nfs3 = if let Some(nfs_port) = direct_nfs_port {
        Arc::new(Nfs3Client::new(PooledTransport::new_direct(Arc::clone(&setup.pool), pool_key, Arc::clone(&setup.circuit), setup.stealth.clone(), setup.cred.clone(), ReconnectStrategy::Persistent, nfs_port)))
    } else {
        Arc::new(Nfs3Client::new(PooledTransport::new(Arc::clone(&setup.pool), pool_key, Arc::clone(&setup.circuit), setup.stealth.clone(), setup.cred.clone(), ReconnectStrategy::Persistent)))
    };

    let ops = V3Ops::new(Arc::clone(&nfs3));
    let root_handle = ShellHandle(root_fh.as_bytes().to_vec());
    let mut shell = NfsShell::new(ops, root_handle, setup.allow_write, setup.hostname.clone());
    shell.refresh_tab_cache().await;
    eprintln!("{}", crate::output::status_ok(&format!("Connected to {host} as uid={uid} gid={gid}{}   --   type 'help' for commands", if setup.allow_write { "  [write enabled]" } else { "" })));
    eprintln!("# rerun: nfswolf shell {host}:{export} --nfs-version 3 --uid {uid} --gid {gid}");

    run_repl(&mut shell, host, setup.command.as_deref(), "", globals).await
}

// =============================================================================
// NFSv4 connect
// =============================================================================

/// Connect via NFSv4: direct port 2049 (no MOUNT), PUTROOTFH for root handle.
///
/// The pooled transport gives the v4 shell circuit breaking, connection reuse,
/// stealth pacing, and zero-round-trip credential swaps -- same as v2 and v3.
async fn connect_v4(setup: &ShellSetup, globals: &GlobalOpts) -> anyhow::Result<()> {
    use crate::proto::nfs4::Nfs4Client as PooledNfs4Client;
    use crate::shell::v4::V4Ops;

    let host = setup.host;
    let nfs_port = setup.nfs_port.unwrap_or(2049);
    let addr = SocketAddr::new(host, nfs_port);
    let uid = setup.uid;
    let gid = setup.gid;

    eprintln!("{}", crate::output::status_info(&format!("Connecting to {host}:{nfs_port} via NFSv4 (no MOUNT)")));

    // Build the pooled transport -- same pattern as the v3 and v2 shells.
    // NFSv4 needs no MOUNT, so we use `new_direct` to bypass portmapper.
    // Synthetic export key: NFSv4 has no MOUNT exports, but the pool keys on
    // (host, export, uid, gid). The port is embedded so distinct --nfs-port
    // values don't collide.
    let pool_key = PoolKey { host: addr, export: format!("__nfs4__{nfs_port}"), uid, gid };
    let transport = PooledTransport::new_direct(Arc::clone(&setup.pool), pool_key, Arc::clone(&setup.circuit), setup.stealth.clone(), setup.cred.clone(), ReconnectStrategy::Persistent, nfs_port);
    let client = Arc::new(PooledNfs4Client::new(transport));

    // Get root FH or use --handle for direct bypass.
    let root_fh = if let TargetSource::Handle(hex) = &setup.target.source {
        eprintln!("{}", crate::output::status_info(&format!("Using raw handle (NFSv4): {hex}")));
        ShellHandle::from_hex(hex).map_err(|e| anyhow::anyhow!("invalid --handle: {e}"))?
    } else {
        let fh_bytes = client.get_root_fh().await.map_err(|e| anyhow::anyhow!("PUTROOTFH failed: {e}"))?;
        ShellHandle(fh_bytes)
    };

    let v4ops = V4Ops::new(client);
    let mut shell = NfsShell::new(v4ops, root_fh, setup.allow_write, setup.hostname.clone());
    shell.refresh_tab_cache().await;
    eprintln!("{}", crate::output::status_ok(&format!("Connected to {host} as uid={uid} gid={gid} (NFSv4 shell  --  type 'help' for commands)")));
    eprintln!("# rerun: nfswolf shell {host} --nfs-version 4 --uid {uid} --gid {gid}");

    run_repl(&mut shell, host, setup.command.as_deref(), " [v4]", globals).await
}

// =============================================================================
// NFSv2 connect
// =============================================================================

/// Connect via NFSv2: MOUNT v1 for the 32-byte handle, then Nfs2Client.
///
/// The v2 data client uses `PooledTransport`, so `--proxy`, `--delay`/`--jitter`,
/// and mid-session credential swaps all work the same as the v3 path.
async fn connect_v2(setup: &ShellSetup, globals: &GlobalOpts) -> anyhow::Result<()> {
    use crate::cli::probe::{make_v2_client_with_hostname, parse_addr_with_port};
    use crate::cli::target::Source;
    use crate::shell::v2::V2Ops;

    let host = setup.host;
    let uid = setup.uid;
    let gid = setup.gid;

    let (root_fh, export) = match &setup.target.source {
        Source::Export(p) => {
            let mount_client = make_mount_client(globals);
            let addr = SocketAddr::new(host, 111);
            eprintln!("{}", crate::output::status_info(&format!("Mounting {host}:{p} (MOUNT v1)")));
            let mount_result = mount_client.mount_v1(addr, p).await?;
            let fh = nfs_v2::wire::Nfs2FileHandle::from_bytes(mount_result.handle.as_bytes());
            (fh, p.clone())
        },
        Source::Handle(hex) => {
            let generic = FileHandle::from_hex(hex).map_err(|e| anyhow::anyhow!("invalid --handle: {e}"))?;
            let fh = nfs_v2::wire::Nfs2FileHandle::from_bytes(generic.as_bytes());
            eprintln!("{}", crate::output::status_info(&format!("Using raw handle (NFSv2): {hex}")));
            (fh, String::from("/"))
        },
        Source::None => {
            let mount_client = make_mount_client(globals);
            let addr = SocketAddr::new(host, 111);
            let export = "/".to_owned();
            eprintln!("{}", crate::output::status_info(&format!("Mounting {host}:/ (MOUNT v1)")));
            let mount_result = mount_client.mount_v1(addr, &export).await?;
            let fh = nfs_v2::wire::Nfs2FileHandle::from_bytes(mount_result.handle.as_bytes());
            (fh, export)
        },
    };

    // NFSv2 servers often support only MOUNT v1/v2, so the pooled transport
    // must never attempt a lazy MOUNT v3 discovery. Force direct NFS port to
    // bypass the MOUNT-based port resolution path entirely.
    let nfs_port = Some(setup.nfs_port.unwrap_or(2049));
    let addr = parse_addr_with_port(&host.to_string(), nfs_port)?;
    let (_pool, _circuit, client) = make_v2_client_with_hostname(addr, &export, uid, gid, &globals.aux_gids, setup.stealth.clone(), globals.proxy.as_deref(), nfs_port, &setup.hostname);
    let client = Arc::new(client);

    let v2ops = V2Ops::new(client);
    let root = ShellHandle(root_fh.0.to_vec());
    let mut shell = NfsShell::new(v2ops, root, setup.allow_write, setup.hostname.clone());
    shell.refresh_tab_cache().await;
    eprintln!("{}", crate::output::status_ok(&format!("Connected to {host} as uid={uid} gid={gid} (NFSv2 shell  --  type 'help' for commands)")));
    eprintln!("# rerun: nfswolf shell {host}:{export} --nfs-version 2 --uid {uid} --gid {gid}");

    run_repl(&mut shell, host, setup.command.as_deref(), " [v2]", globals).await
}
