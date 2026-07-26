//! Interactive NFS exploration shell.
//!
//! Connects to an NFS server, mounts an export, and enters a readline REPL
//! so the operator can browse the filesystem without a kernel NFS client.
//! A single `--command` flag lets it run headlessly (useful in scripts).

use std::net::SocketAddr;
use std::sync::Arc;

use clap::Parser;
use rustyline::Editor;
use rustyline::error::ReadlineError;
use rustyline::history::DefaultHistory;

use crate::cli::probe::{build_gid_list, make_mount_client};
use crate::cli::target::Source as TargetSource;
use crate::cli::{GlobalOpts, H_BEHAVIOR, H_PERMISSIONS, H_TARGET};
use crate::proto::auth::{AuthSys, Credential};
use crate::proto::circuit::CircuitBreaker;
use crate::proto::conn::ReconnectStrategy;
use crate::proto::nfs3::Nfs3Client;
use crate::proto::nfs3::types::FileHandle;
use crate::proto::pool::{ConnectionPool, PoolKey};
use crate::proto::transport::PooledTransport;
use crate::shell::{NfsCompleter, NfsShell};
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

    /// NFS protocol version (2, 3, or 4).
    #[arg(long, default_value = "3", value_name = "VER", help_heading = H_BEHAVIOR)]
    pub nfs_version: u32,
}

/// Entry point for the `shell` subcommand.
pub(crate) async fn run(args: ShellArgs, globals: &GlobalOpts) -> anyhow::Result<()> {
    tracing::info!(target = %args.target, "starting NFS shell");

    // NFSv4 mode: bypass MOUNT, connect directly to port 2049.
    if args.nfs_version == 4 {
        return run_nfs4_shell(args, globals).await;
    }

    // NFSv2 mode: MOUNT v1 for the 32-byte handle, then Nfs2Client.
    if args.nfs_version == 2 {
        return run_nfs2_shell(args, globals).await;
    }

    if args.nfs_version != 3 {
        anyhow::bail!("--nfs-version {} is not supported (use 2, 3, or 4)", args.nfs_version);
    }

    // Parse `<TARGET>` + --export + --handle into the unified form. The
    // shell tolerates a bare host (no source) by defaulting to "/", since
    // `shell host` was historically a valid invocation.
    let target = crate::cli::target::parse(&args.target, args.export.as_deref(), args.handle.as_deref(), false)?;
    let host = target.host;
    let (export, handle_hex_arg): (String, Option<String>) = match &target.source {
        TargetSource::Export(p) => (p.clone(), None),
        TargetSource::Handle(h) => (String::from("/"), Some(h.clone())),
        TargetSource::None => (String::from("/"), None),
    };
    let uid = globals.uid;
    let gid = globals.gid;

    let addr = SocketAddr::new(host, 111);
    let pool = Arc::new(match &globals.proxy {
        Some(p) => ConnectionPool::with_proxy(p.clone()),
        None => ConnectionPool::default_config(),
    });
    let circuit = Arc::new(CircuitBreaker::default_config());
    let gids = build_gid_list(gid, &globals.aux_gids);
    let cred = Credential::Sys(AuthSys::with_groups(uid, gid, &gids, &globals.hostname));

    // When --handle is given, skip MOUNT entirely and connect straight to the
    // NFS data port. The raw handle is the shell root (file handles are bearer
    // tokens per RFC 1094 S2.3.3 / RFC 2623 S2.6), so no MOUNT/EXPORT RPC is
    // needed. Issuing MNTPROC_EXPORT here would block on SYN timeouts when
    // portmapper/mountd (TCP/111) is firewalled -- the exact case --handle
    // exists to bypass.
    let (root_fh, pool_key, direct_nfs_port) = if let Some(ref hex) = handle_hex_arg {
        let fh = FileHandle::from_hex(hex).map_err(|e| anyhow::anyhow!("invalid --handle: {e}"))?;
        eprintln!("{}", crate::output::status_info(&format!("Using raw handle: {hex}")));

        let nfs_port = globals.nfs_port.unwrap_or(2049);
        eprintln!("{}", crate::output::status_info(&format!("Session via {host}:{nfs_port} (MOUNT bypassed)")));
        let key = PoolKey { host: SocketAddr::new(host, nfs_port), export: format!("__handle__{nfs_port}"), uid, gid };
        (fh, key, Some(nfs_port))
    } else {
        let mount_client = make_mount_client(globals);
        eprintln!("{}", crate::output::status_info(&format!("Mounting {host}:{export}")));
        let mount_result = mount_client.mount(addr, &export).await?;
        let key = PoolKey { host: addr, export: export.clone(), uid, gid };
        // Honour --nfs-port on the MOUNT path too: when set, route the data
        // client directly to the chosen port (new_direct) instead of resolving
        // it via portmapper, which hangs when TCP/111 is firewalled. `None`
        // keeps the portmapper default (mirrors src/cli/mount.rs).
        (mount_result.handle, key, globals.nfs_port)
    };

    let stealth = StealthConfig::new(globals.delay, globals.jitter);
    let nfs3 = if let Some(nfs_port) = direct_nfs_port {
        Arc::new(Nfs3Client::new(PooledTransport::new_direct(Arc::clone(&pool), pool_key, Arc::clone(&circuit), stealth, cred, ReconnectStrategy::Persistent, nfs_port)))
    } else {
        Arc::new(Nfs3Client::new(PooledTransport::new(Arc::clone(&pool), pool_key, Arc::clone(&circuit), stealth, cred, ReconnectStrategy::Persistent)))
    };

    let mut shell = NfsShell::new(Arc::clone(&nfs3), root_fh, args.allow_write, globals.hostname.clone());
    eprintln!("{}", crate::output::status_ok(&format!("Connected to {host} as uid={uid} gid={gid}{}   --   type 'help' for commands", if args.allow_write { "  [write enabled]" } else { "" })));

    if let Some(cmd) = args.command {
        // Non-interactive: run one command and return.
        shell.dispatch(&cmd).await;
        crate::cli::emit_replay(globals);
        return Ok(());
    }

    // Interactive REPL with Tab completion.
    let completer = shell.make_completer();
    let mut rl = Editor::<NfsCompleter, DefaultHistory>::new()?;
    rl.set_helper(Some(completer));

    loop {
        // Read uid/gid from the shell so the prompt tracks mid-session
        // `uid` / `gid` / `impersonate` changes (the credential lives on the
        // client, not the captured `uid` local).
        let prompt = format!("nfswolf@{host}:{} uid={} gid={}> ", shell.cwd_path(), shell.current_uid(), shell.current_gid());
        match rl.readline(&prompt) {
            Ok(line) => {
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

// `parse_target` / `resolve_host` removed -- target parsing now lives in
// `crate::cli::target`, shared by all subcommands.

// =============================================================================
// NFSv4 shell  --  minimal REPL for NFSv4-only servers
// =============================================================================

/// Hard cap on a single NFSv4 shell `cat` / `get` read.
///
/// The NFS server is untrusted (CLAUDE.md threat model): a hostile server can
/// return full 64 KiB chunks with `eof = false` forever, so the read loop must
/// bound its total instead of buffering until OOM or looping indefinitely.
/// Mirrors the v3 shell's `READ_ALL_MAX_BYTES` (src/shell.rs).
const NFS4_READ_MAX_BYTES: u64 = 256 * 1024 * 1024; // 256 MiB

/// Run an interactive NFSv4 shell.
///
/// Used when `--nfs-version 4` is set.  Connects directly to port 2049 without
/// the MOUNT protocol (which is not required for NFSv4).  Supports a subset of
/// the full NFSv3 shell commands sufficient to explore NFSv4-only servers.
async fn run_nfs4_shell(args: ShellArgs, globals: &GlobalOpts) -> anyhow::Result<()> {
    use crate::proto::nfs4::compound::Nfs4DirectClient;
    use rustyline::DefaultEditor;

    let target = crate::cli::target::parse(&args.target, args.export.as_deref(), args.handle.as_deref(), false)?;
    let host = target.host;
    drop(target.source); // NFSv4 path doesn't use MOUNT or raw handle
    let nfs_port = globals.nfs_port.unwrap_or(2049);
    let addr = SocketAddr::new(host, nfs_port);
    let mut uid = globals.uid;
    let mut gid = globals.gid;
    let mut hostname = globals.hostname.clone();

    // Send the primary GID plus any --aux-gids (RFC 5531 S14, up to 16) so the
    // shadow-GID trick (e.g. GID 42 to read /etc/shadow) works in v4 mode just as
    // it does in the v3 shell. The client retains the aux GIDs, so a later
    // `uid`/`gid`/`hostname` change (dispatch_nfs4) re-applies them on reconnect.
    eprintln!("{}", crate::output::status_info(&format!("Connecting to {host}:{nfs_port} via NFSv4 (no MOUNT)")));
    let stealth = StealthConfig::new(globals.delay, globals.jitter);
    let mut client = Nfs4DirectClient::connect_with_groups_proxy(addr, uid, gid, &globals.aux_gids, &hostname, globals.proxy.as_deref()).await.map_err(|e| anyhow::anyhow!("NFSv4 connect to {addr} failed: {e}"))?.with_stealth(stealth);

    // Fetch the root FH from PUTROOTFH + GETFH.
    let root_fh = client.get_root_fh().await.map_err(|e| anyhow::anyhow!("PUTROOTFH failed: {e}"))?;
    eprintln!("{}", crate::output::status_ok(&format!("Connected to {host} as uid={uid} gid={gid} hostname={hostname}  (NFSv4 shell  --  type 'help' for commands)")));

    let mut cwd_fh = root_fh;
    let mut cwd_path = "/".to_owned();

    // Non-interactive mode: run one command and return.
    if let Some(ref cmd) = args.command {
        dispatch_nfs4(&mut client, cmd, &mut cwd_fh, &mut cwd_path, args.allow_write, &mut uid, &mut gid, &mut hostname).await;
        crate::cli::emit_replay(globals);
        return Ok(());
    }

    // Interactive REPL (no Tab completion for NFSv4 shell).
    let mut rl = DefaultEditor::new()?;
    loop {
        let prompt = format!("nfswolf@{host}:{cwd_path} uid={uid} hostname={hostname} [v4]> ");
        match rl.readline(&prompt) {
            Ok(line) => {
                drop(rl.add_history_entry(&line));
                let trimmed = line.trim();
                if trimmed == "exit" || trimmed == "quit" {
                    break;
                }
                dispatch_nfs4(&mut client, trimmed, &mut cwd_fh, &mut cwd_path, args.allow_write, &mut uid, &mut gid, &mut hostname).await;
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

/// Dispatch a single command in the NFSv4 shell REPL.
async fn dispatch_nfs4(client: &mut crate::proto::nfs4::compound::Nfs4DirectClient, line: &str, cwd_fh: &mut Vec<u8>, cwd_path: &mut String, allow_write: bool, uid: &mut u32, gid: &mut u32, hostname: &mut String) {
    // NFSv4 write operations (CREATE, WRITE, REMOVE, RENAME, etc.) require
    // OPEN+WRITE+CLOSE with stateid tracking (RFC 7530 S16.2.5), which is out
    // of scope until stateful v4 support is added.  Suppress the unused warning
    // until then.
    let _ = allow_write;
    let mut parts = line.split_whitespace();
    let Some(cmd) = parts.next() else { return };
    let args: Vec<&str> = parts.collect();

    match cmd {
        "help" | "?" => {
            println!("NFSv4 shell commands:");
            println!("  ls              list current directory");
            println!("  ls <path>       list a subdirectory");
            println!("  cd <dir>        change directory (cd / for root)");
            println!("  pwd             print current directory");
            println!("  cat <file>      print file contents");
            println!("  get <file>      download file to current local directory");
            println!("  uid <n>         set AUTH_SYS UID (reconnects)");
            println!("  gid <n>         set AUTH_SYS GID (reconnects)");
            println!("  hostname <name> spoof AUTH_SYS machine name (reconnects)");
            println!("  whoami          show current uid/gid/hostname");
            println!("  exit / quit     exit the shell");
        },
        "whoami" => println!("uid={uid}  gid={gid}  hostname={hostname}"),
        "uid" => match args.first().and_then(|s| s.parse::<u32>().ok()) {
            Some(new_uid) => {
                *uid = new_uid;
                match client.reconnect_with_auth(*uid, *gid, hostname).await {
                    Ok(()) => println!("uid={uid} gid={gid} hostname={hostname}"),
                    Err(e) => eprintln!("uid: reconnect failed: {e}"),
                }
            },
            None => eprintln!("uid: usage: uid <number>"),
        },
        "gid" => match args.first().and_then(|s| s.parse::<u32>().ok()) {
            Some(new_gid) => {
                *gid = new_gid;
                match client.reconnect_with_auth(*uid, *gid, hostname).await {
                    Ok(()) => println!("uid={uid} gid={gid} hostname={hostname}"),
                    Err(e) => eprintln!("gid: reconnect failed: {e}"),
                }
            },
            None => eprintln!("gid: usage: gid <number>"),
        },
        "hostname" => {
            if let Some(new_host) = args.first() {
                (*new_host).clone_into(hostname);
                match client.reconnect_with_auth(*uid, *gid, hostname).await {
                    Ok(()) => println!("hostname={hostname}"),
                    Err(e) => eprintln!("hostname: reconnect failed: {e}"),
                }
            } else {
                println!("{hostname}");
            }
        },
        "pwd" => println!("{cwd_path}"),
        "ls" => {
            let target_fh = if let Some(subdir) = args.first() {
                // Resolve subdir relative to cwd.
                let components = cwd_path_plus(cwd_path, subdir);
                let refs: Vec<&str> = components.iter().map(String::as_str).collect();
                match client.lookup_fh(&refs).await {
                    Ok(fh) => fh,
                    Err(e) => {
                        eprintln!("ls: {e}");
                        return;
                    },
                }
            } else {
                cwd_fh.clone()
            };
            match client.list_dir(&target_fh).await {
                Ok(names) => {
                    let mut sorted = names;
                    sorted.sort();
                    for name in &sorted {
                        println!("{name}");
                    }
                },
                Err(e) => eprintln!("ls: {e}"),
            }
        },
        "cd" => {
            let target = args.first().copied().unwrap_or("/");
            let new_path = if target == "/" {
                // Return to root.
                match client.get_root_fh().await {
                    Ok(fh) => {
                        *cwd_fh = fh;
                        "/".to_owned()
                    },
                    Err(e) => {
                        eprintln!("cd /: {e}");
                        return;
                    },
                }
            } else {
                let components = cwd_path_plus(cwd_path, target);
                let refs: Vec<&str> = components.iter().map(String::as_str).collect();
                match client.lookup_fh(&refs).await {
                    Ok(fh) => {
                        *cwd_fh = fh;
                        format!("/{}", components.join("/"))
                    },
                    Err(e) => {
                        eprintln!("cd: {e}");
                        return;
                    },
                }
            };
            *cwd_path = new_path;
        },
        "cat" => {
            let Some(filename) = args.first() else {
                eprintln!("usage: cat <file>");
                return;
            };
            let file_components = cwd_path_plus(cwd_path, filename);
            let refs: Vec<&str> = file_components.iter().map(String::as_str).collect();
            let file_fh = match client.lookup_fh(&refs).await {
                Ok(fh) => fh,
                Err(e) => {
                    eprintln!("cat: {e}");
                    return;
                },
            };
            let mut offset: u64 = 0;
            loop {
                match client.read_chunk(&file_fh, offset, 65536).await {
                    Ok((data, eof)) => {
                        // Safety: print as lossy UTF-8 to avoid crashing on binary files.
                        print!("{}", String::from_utf8_lossy(&data));
                        offset += data.len() as u64;
                        if eof || data.is_empty() {
                            break;
                        }
                        // Untrusted server: stop once the cap is hit so a server
                        // that never sets eof can't loop forever.
                        if offset > NFS4_READ_MAX_BYTES {
                            eprintln!("cat: aborted at {offset} bytes: exceeds {NFS4_READ_MAX_BYTES}-byte cap (untrusted server returning endless non-EOF data)");
                            break;
                        }
                    },
                    Err(e) => {
                        eprintln!("cat: {e}");
                        break;
                    },
                }
            }
        },
        "get" => {
            let Some(filename) = args.first() else {
                eprintln!("usage: get <file>");
                return;
            };
            let file_components = cwd_path_plus(cwd_path, filename);
            let refs: Vec<&str> = file_components.iter().map(String::as_str).collect();
            let file_fh = match client.lookup_fh(&refs).await {
                Ok(fh) => fh,
                Err(e) => {
                    eprintln!("get: {e}");
                    return;
                },
            };
            // Derive local filename from the last component.
            let local_name = file_components.last().map_or(*filename, String::as_str);
            let mut buf = Vec::new();
            let mut offset: u64 = 0;
            loop {
                match client.read_chunk(&file_fh, offset, 65536).await {
                    Ok((data, eof)) => {
                        offset += data.len() as u64;
                        buf.extend_from_slice(&data);
                        if eof || data.is_empty() {
                            break;
                        }
                        // Untrusted server: abort (don't write a partial file)
                        // once the cap is hit so endless non-EOF chunks can't
                        // grow `buf` without bound.
                        if offset > NFS4_READ_MAX_BYTES {
                            eprintln!("get: aborted at {offset} bytes: exceeds {NFS4_READ_MAX_BYTES}-byte cap (untrusted server returning endless non-EOF data)");
                            return;
                        }
                    },
                    Err(e) => {
                        eprintln!("get: read error: {e}");
                        return;
                    },
                }
            }
            match std::fs::write(local_name, &buf) {
                Ok(()) => println!("{}", crate::output::status_ok(&format!("saved {} bytes -> {local_name}", buf.len()))),
                Err(e) => eprintln!("get: write {local_name}: {e}"),
            }
        },
        "exit" | "quit" => {}, // handled by the REPL loop
        // Write commands exist in the v2/v3 shell but require stateful v4
        // operations (OPEN+WRITE+CLOSE with stateid tracking, RFC 7530
        // S16.2.5).  Tell the user explicitly rather than falling through to
        // "unknown command".
        "put" | "mkdir" | "rm" | "rmdir" | "mv" | "chmod" | "chown" | "symlink" | "link" | "mknod" => {
            eprintln!("{cmd}: not supported in NFSv4 mode (requires stateful OPEN/CLOSE with stateid tracking)");
        },
        _ => eprintln!("unknown command '{cmd}'  --  type 'help' for commands"),
    }
}

/// Build the full path component list for `target` relative to `cwd_path`.
///
/// Handles absolute paths (starting with `/`), parent navigation (`..`),
/// and current-dir navigation (`.`).
fn cwd_path_plus(cwd_path: &str, target: &str) -> Vec<String> {
    let base: Vec<&str> = if target.starts_with('/') {
        // Absolute path: ignore cwd.
        vec![]
    } else {
        cwd_path.trim_start_matches('/').split('/').filter(|s| !s.is_empty()).collect()
    };

    let mut components: Vec<String> = base.iter().map(|s| (*s).to_owned()).collect();
    for part in target.trim_start_matches('/').split('/') {
        match part {
            "" | "." => {},
            ".." => {
                drop(components.pop());
            },
            other => components.push(other.to_owned()),
        }
    }
    components
}

// =============================================================================
// NFSv2 shell  --  MOUNT v1 + Nfs2Client
// =============================================================================

#[expect(clippy::cognitive_complexity, reason = "shell dispatch loop")]
async fn run_nfs2_shell(args: ShellArgs, globals: &GlobalOpts) -> anyhow::Result<()> {
    use colored::Colorize as _;
    use nfswolf_nfs2::{
        Nfs2Client,
        wire::{Nfs2FileHandle, Nfs2SetAttr},
    };
    use nfswolf_rpc::{rpc::opaque_auth, transport::direct::DirectTransport, transport::tokio::TokioIo};
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt as _;

    use crate::cli::target::{Source, parse as parse_target};
    use crate::proto::auth::next_stamp;
    use crate::proto::mount::NfsMountClient;
    use crate::proto::portmap::PortmapClient;

    let target = parse_target(&args.target, args.export.as_deref(), args.handle.as_deref(), false)?;
    let host = target.host;
    let export = match &target.source {
        Source::Export(p) => p.clone(),
        _ => anyhow::bail!("--nfs-version 2 requires an export path (not a raw handle)"),
    };
    let addr = SocketAddr::new(host, 111);

    let uid = globals.uid;
    let gid = globals.gid;
    let hostname = globals.hostname.clone();

    let mount_client = NfsMountClient::new().with_credential(Credential::Sys(AuthSys::new(uid, gid, &hostname)));
    let mount_result = mount_client.mount_v1(addr, &export).await?;
    let root_fh: Nfs2FileHandle = {
        let b = mount_result.handle.as_bytes();
        let mut arr = [0u8; 32];
        let len = b.len().min(32);
        #[expect(clippy::indexing_slicing, reason = "len = min(b.len(), 32) <= 32 = arr.len()")]
        {
            arr[..len].copy_from_slice(&b[..len]);
        }
        Nfs2FileHandle(arr)
    };

    let nfs_port = if let Some(p) = globals.nfs_port {
        p
    } else {
        let portmap = PortmapClient::default_port();
        portmap.query_port(addr, 100_003, 2).await.unwrap_or(2049)
    };

    let nfs_addr = SocketAddr::new(host, nfs_port);
    let stream = tokio::net::TcpStream::connect(nfs_addr).await?;
    let io = TokioIo::new(stream);
    let cred = AuthSys::with_groups(uid, gid, &[gid], &hostname);
    let opaque = cred.to_opaque_auth(next_stamp());
    let transport = DirectTransport::with_auth(io, opaque, opaque_auth::default());
    let client = Nfs2Client::new(transport);

    println!("{}", format!("[+] Connected to {host} as uid={uid} gid={gid} (NFSv2 shell  --  type 'help' for commands)").green());
    println!("# rerun: nfswolf shell {host}:{export} --nfs-version 2 --uid {uid} --gid {gid}");

    let mut cwd_fh = root_fh;
    let mut cwd_path = String::from("/");

    let mut rl = rustyline::DefaultEditor::new()?;
    loop {
        let prompt = format!("nfsv2:{cwd_path}> ");
        let input = match rl.readline(&prompt) {
            Ok(l) => l,
            Err(ReadlineError::Eof | ReadlineError::Interrupted) => break,
            Err(e) => {
                eprintln!("readline: {e}");
                break;
            },
        };
        let line = input.trim();
        if line.is_empty() {
            continue;
        }
        drop(rl.add_history_entry(line));

        let (cmd, arg) = line.split_once(' ').map_or((line, ""), |(c, a)| (c, a.trim()));

        match cmd {
            "ls" => {
                let dir = if arg.is_empty() {
                    cwd_fh
                } else {
                    match client.lookup_path(&cwd_fh, arg).await {
                        Ok((fh, _)) => fh,
                        Err(e) => {
                            eprintln!("{}", format!("ls: {arg}: {e}").red());
                            continue;
                        },
                    }
                };
                match v2_readdir_all(&client, &dir).await {
                    Ok(entries) => {
                        println!("{:<12} {:>8} {:>8} {:>10}  name", "mode", "uid", "gid", "size");
                        println!("{}", "-".repeat(60));
                        for e in &entries {
                            match client.lookup(&dir, &e.name).await {
                                Ok((_, a)) => println!("{:<12} {:>8} {:>8} {:>10}  {}", v2_mode_str(&a), a.uid, a.gid, a.size, e.name),
                                Err(_) => println!("{:<12} {:>8} {:>8} {:>10}  {}", "??????????", "?", "?", "?", e.name),
                            }
                        }
                    },
                    Err(e) => eprintln!("{}", format!("ls: {e}").red()),
                }
            },
            "cd" => {
                if arg.is_empty() {
                    cwd_fh = root_fh;
                    "/".clone_into(&mut cwd_path);
                    continue;
                }
                match client.lookup_path(&cwd_fh, arg).await {
                    Ok((fh, _)) => {
                        cwd_fh = fh;
                        if arg.starts_with('/') {
                            cwd_path = format!("/{}", arg.trim_start_matches('/'));
                        } else {
                            cwd_path = format!("{}/{}", cwd_path.trim_end_matches('/'), arg);
                        }
                    },
                    Err(e) => eprintln!("{}", format!("cd: {arg}: {e}").red()),
                }
            },
            "pwd" => println!("{cwd_path}"),
            "cat" => {
                if arg.is_empty() {
                    eprintln!("{}", "usage: cat <file>".yellow());
                    continue;
                }
                match client.lookup_path(&cwd_fh, arg).await {
                    Ok((fh, _)) => match client.read_file(&fh).await {
                        Ok(data) => {
                            drop(std::io::Write::write_all(&mut std::io::stdout(), &data));
                        },
                        Err(e) => eprintln!("{}", format!("cat: {arg}: {e}").red()),
                    },
                    Err(e) => eprintln!("{}", format!("cat: {arg}: {e}").red()),
                }
            },
            "stat" => {
                if arg.is_empty() {
                    eprintln!("{}", "usage: stat <path>".yellow());
                    continue;
                }
                match client.lookup_path(&cwd_fh, arg).await {
                    Ok((fh, a)) => {
                        println!("  File: {arg}");
                        println!("  Handle: {}", v2_handle_hex(&fh));
                        println!("  Mode: {:#o}  Type: {}", a.mode, v2_type_str(a.ftype));
                        println!("  Uid: {}  Gid: {}  Nlink: {}", a.uid, a.gid, a.nlink);
                        println!("  Size: {}  Blocks: {}", a.size, a.blocks);
                    },
                    Err(e) => eprintln!("{}", format!("stat: {arg}: {e}").red()),
                }
            },
            "get" => {
                let (remote, local) = arg.split_once(' ').unwrap_or((arg, ""));
                if remote.is_empty() {
                    eprintln!("{}", "usage: get <remote> [local]".yellow());
                    continue;
                }
                let dest = if local.is_empty() { remote.rsplit('/').next().unwrap_or(remote) } else { local };
                match client.lookup_path(&cwd_fh, remote).await {
                    Ok((fh, _)) => match client.read_file(&fh).await {
                        Ok(data) => match std::fs::write(dest, &data) {
                            Ok(()) => println!("{}", format!("get: {} bytes -> {dest}", data.len()).green()),
                            Err(e) => eprintln!("{}", format!("get: write {dest}: {e}").red()),
                        },
                        Err(e) => eprintln!("{}", format!("get: read {remote}: {e}").red()),
                    },
                    Err(e) => eprintln!("{}", format!("get: {remote}: {e}").red()),
                }
            },
            "root" => {
                // RFC 1094 sec. 2.2.3: NFSPROC_ROOT is obsolete. If a server
                // responds with a handle, that bypasses MOUNT entirely -- a
                // significant finding since it means any client can obtain the
                // root handle without going through mountd's export ACLs.
                match client.root().await {
                    Ok(Some(fh)) => {
                        println!("{}", "[!] Server returned a root handle via NFSPROC_ROOT -- MOUNT bypass!".red().bold());
                        println!("    handle: {}", v2_handle_hex(&fh));
                        println!("    This is obsolete per RFC 1094 sec. 2.2.3. A server that");
                        println!("    responds to it gives any client the root handle without");
                        println!("    going through MOUNT's export ACL checks.");
                        cwd_fh = fh;
                    },
                    Ok(None) => println!("{}", "NFSPROC_ROOT: server did not return a handle (expected -- procedure is obsolete since RFC 1094)".yellow()),
                    Err(e) => eprintln!("{}", format!("NFSPROC_ROOT: {e}").yellow()),
                }
            },
            "put" => {
                if !args.allow_write {
                    eprintln!("{}", "write disabled -- rerun with --allow-write".red());
                    continue;
                }
                let (local, remote) = v2_split2(arg);
                if local.is_empty() || remote.is_empty() {
                    eprintln!("{}", "usage: put <local> <remote>".yellow());
                    continue;
                }
                let data = match std::fs::read(local) {
                    Ok(d) => d,
                    Err(e) => {
                        eprintln!("{}", format!("put: cannot read {local}: {e}").red());
                        continue;
                    },
                };
                let (parent, name) = v2_resolve_parent(&client, &cwd_fh, &root_fh, remote).await;
                let parent = match parent {
                    Ok(p) => p,
                    Err(e) => {
                        eprintln!("{}", format!("put: {e}").red());
                        continue;
                    },
                };
                #[cfg(unix)]
                let mode = std::fs::metadata(local).map_or(0o644, |m| m.permissions().mode() & 0o7777);
                #[cfg(not(unix))]
                let mode = 0o644;
                let sattr = v2_sattr_mode(mode);
                match client.create(&parent, &name, &sattr).await {
                    Ok((fh, _)) => match v2_upload_data(&client, &fh, &data).await {
                        Ok(n) => println!("{}", format!("put: {n} bytes -> {remote}").green()),
                        Err(e) => eprintln!("{}", format!("put: write error: {e}").red()),
                    },
                    Err(e) => eprintln!("{}", format!("put: create {remote}: {e}").red()),
                }
            },
            "rm" => {
                if !args.allow_write {
                    eprintln!("{}", "write disabled -- rerun with --allow-write".red());
                    continue;
                }
                if arg.is_empty() {
                    eprintln!("{}", "usage: rm <file>".yellow());
                    continue;
                }
                let (parent, name) = v2_resolve_parent(&client, &cwd_fh, &root_fh, arg).await;
                match parent {
                    Ok(p) => match client.remove(&p, &name).await {
                        Ok(()) => println!("{}", format!("removed {arg}").green()),
                        Err(e) => eprintln!("{}", format!("rm: {arg}: {e}").red()),
                    },
                    Err(e) => eprintln!("{}", format!("rm: {e}").red()),
                }
            },
            "mkdir" => {
                if !args.allow_write {
                    eprintln!("{}", "write disabled -- rerun with --allow-write".red());
                    continue;
                }
                if arg.is_empty() {
                    eprintln!("{}", "usage: mkdir <dir>".yellow());
                    continue;
                }
                let (parent, name) = v2_resolve_parent(&client, &cwd_fh, &root_fh, arg).await;
                match parent {
                    Ok(p) => {
                        let sattr = v2_sattr_mode(0o755);
                        match client.mkdir(&p, &name, &sattr).await {
                            Ok(_) => println!("{}", format!("created {arg}").green()),
                            Err(e) => eprintln!("{}", format!("mkdir: {arg}: {e}").red()),
                        }
                    },
                    Err(e) => eprintln!("{}", format!("mkdir: {e}").red()),
                }
            },
            "rmdir" => {
                if !args.allow_write {
                    eprintln!("{}", "write disabled -- rerun with --allow-write".red());
                    continue;
                }
                if arg.is_empty() {
                    eprintln!("{}", "usage: rmdir <dir>".yellow());
                    continue;
                }
                let (parent, name) = v2_resolve_parent(&client, &cwd_fh, &root_fh, arg).await;
                match parent {
                    Ok(p) => match client.rmdir(&p, &name).await {
                        Ok(()) => println!("{}", format!("removed {arg}").green()),
                        Err(e) => eprintln!("{}", format!("rmdir: {arg}: {e}").red()),
                    },
                    Err(e) => eprintln!("{}", format!("rmdir: {e}").red()),
                }
            },
            "mv" => {
                if !args.allow_write {
                    eprintln!("{}", "write disabled -- rerun with --allow-write".red());
                    continue;
                }
                let (src, dst) = v2_split2(arg);
                if src.is_empty() || dst.is_empty() {
                    eprintln!("{}", "usage: mv <src> <dst>".yellow());
                    continue;
                }
                let (sp, sn) = v2_resolve_parent(&client, &cwd_fh, &root_fh, src).await;
                let (dp, dn) = v2_resolve_parent(&client, &cwd_fh, &root_fh, dst).await;
                match (sp, dp) {
                    (Ok(sp), Ok(dp)) => match client.rename(&sp, &sn, &dp, &dn).await {
                        Ok(()) => println!("{}", format!("renamed {src} -> {dst}").green()),
                        Err(e) => eprintln!("{}", format!("mv: {e}").red()),
                    },
                    (Err(e), _) | (_, Err(e)) => eprintln!("{}", format!("mv: {e}").red()),
                }
            },
            "chmod" => {
                if !args.allow_write {
                    eprintln!("{}", "write disabled -- rerun with --allow-write".red());
                    continue;
                }
                let (mode_s, path) = v2_split2(arg);
                if mode_s.is_empty() || path.is_empty() {
                    eprintln!("{}", "usage: chmod <mode> <path>".yellow());
                    continue;
                }
                let Ok(mode) = u32::from_str_radix(mode_s, 8) else {
                    eprintln!("{}", format!("chmod: invalid mode: {mode_s}").red());
                    continue;
                };
                match client.lookup_path(&cwd_fh, path).await {
                    Ok((fh, _)) => {
                        let sattr = v2_sattr_mode(mode);
                        match client.setattr(&fh, &sattr).await {
                            Ok(_) => println!("{}", format!("chmod {mode_s} {path}").green()),
                            Err(e) => eprintln!("{}", format!("chmod: {e}").red()),
                        }
                    },
                    Err(e) => eprintln!("{}", format!("chmod: {path}: {e}").red()),
                }
            },
            "chown" => {
                if !args.allow_write {
                    eprintln!("{}", "write disabled -- rerun with --allow-write".red());
                    continue;
                }
                let (owner_s, path) = v2_split2(arg);
                if owner_s.is_empty() || path.is_empty() {
                    eprintln!("{}", "usage: chown <uid[:gid]> <path>".yellow());
                    continue;
                }
                let (u, g) = if let Some((us, gs)) = owner_s.split_once(':') { (us.parse::<u32>().ok(), gs.parse::<u32>().ok()) } else { (owner_s.parse::<u32>().ok(), None) };
                match client.lookup_path(&cwd_fh, path).await {
                    Ok((fh, _)) => {
                        use nfswolf_nfs2::wire::{SATTR_UNCHANGED, Timeval};
                        let ut = Timeval { seconds: SATTR_UNCHANGED, useconds: SATTR_UNCHANGED };
                        let sattr = Nfs2SetAttr { mode: SATTR_UNCHANGED, uid: u.unwrap_or(SATTR_UNCHANGED), gid: g.unwrap_or(SATTR_UNCHANGED), size: SATTR_UNCHANGED, atime: ut, mtime: ut };
                        match client.setattr(&fh, &sattr).await {
                            Ok(_) => println!("{}", format!("chown {owner_s} {path}").green()),
                            Err(e) => eprintln!("{}", format!("chown: {e}").red()),
                        }
                    },
                    Err(e) => eprintln!("{}", format!("chown: {path}: {e}").red()),
                }
            },
            "readlink" => {
                if arg.is_empty() {
                    eprintln!("{}", "usage: readlink <path>".yellow());
                    continue;
                }
                match client.lookup_path(&cwd_fh, arg).await {
                    Ok((fh, _)) => match client.readlink(&fh).await {
                        Ok(target) => println!("{target}"),
                        Err(e) => eprintln!("{}", format!("readlink: {e}").red()),
                    },
                    Err(e) => eprintln!("{}", format!("readlink: {arg}: {e}").red()),
                }
            },
            "symlink" => {
                if !args.allow_write {
                    eprintln!("{}", "write disabled -- rerun with --allow-write".red());
                    continue;
                }
                let (name, target) = v2_split2(arg);
                if name.is_empty() || target.is_empty() {
                    eprintln!("{}", "usage: symlink <name> <target>".yellow());
                    continue;
                }
                let (parent, link_name) = v2_resolve_parent(&client, &cwd_fh, &root_fh, name).await;
                match parent {
                    Ok(p) => {
                        let sattr = v2_sattr_mode(0o777);
                        match client.symlink(&p, &link_name, target, &sattr).await {
                            Ok(()) => println!("{}", format!("created symlink {name} -> {target}").green()),
                            Err(e) => eprintln!("{}", format!("symlink: {e}").red()),
                        }
                    },
                    Err(e) => eprintln!("{}", format!("symlink: {e}").red()),
                }
            },
            "lcd" => {
                if arg.is_empty() {
                    eprintln!("{}", "usage: lcd <dir>".yellow());
                    continue;
                }
                if let Err(e) = std::env::set_current_dir(arg) {
                    eprintln!("{}", format!("lcd: {e}").red());
                }
            },
            "lls" => {
                let dir = if arg.is_empty() { "." } else { arg };
                match std::fs::read_dir(dir) {
                    Ok(rd) => {
                        for e in rd.flatten() {
                            println!("{}", e.file_name().to_string_lossy());
                        }
                    },
                    Err(e) => eprintln!("{}", format!("lls: {e}").red()),
                }
            },
            "lpwd" => match std::env::current_dir() {
                Ok(p) => println!("{}", p.display()),
                Err(e) => eprintln!("{}", format!("lpwd: {e}").red()),
            },
            "lmkdir" => {
                if arg.is_empty() {
                    eprintln!("{}", "usage: lmkdir <dir>".yellow());
                    continue;
                }
                if let Err(e) = std::fs::create_dir_all(arg) {
                    eprintln!("{}", format!("lmkdir: {e}").red());
                }
            },
            "whoami" => println!("uid={uid}  gid={gid}  hostname={hostname}  (NFSv2)"),
            "handle" => println!("{}", v2_handle_hex(&cwd_fh)),
            "help" | "?" => {
                println!("NFSv2 shell commands:");
                println!();
                println!("Navigation:");
                println!("  ls [path]           List directory");
                println!("  cd [path]           Change directory (no arg = root)");
                println!("  pwd                 Print working directory");
                println!();
                println!("File operations:");
                println!("  cat <file>          Print file contents");
                println!("  get <remote> [local]  Download file");
                println!("  put <local> <remote>  Upload file (--allow-write)");
                println!("  rm <file>           Remove file (--allow-write)");
                println!("  mkdir <dir>         Create directory (--allow-write)");
                println!("  rmdir <dir>         Remove directory (--allow-write)");
                println!("  mv <src> <dst>      Rename/move (--allow-write)");
                println!("  readlink <path>     Read symlink target");
                println!("  symlink <name> <t>  Create symlink (--allow-write)");
                println!();
                println!("Permissions:");
                println!("  chmod <mode> <path> Change mode (--allow-write)");
                println!("  chown <uid[:gid]> <path>  Change owner (--allow-write)");
                println!("  stat <path>         File attributes");
                println!();
                println!("Identity:");
                println!("  whoami              Current AUTH_SYS identity");
                println!("  handle              Print current directory handle");
                println!();
                println!("Probes:");
                println!("  root                NFSPROC_ROOT bypass check (RFC 1094)");
                println!();
                println!("Local:");
                println!("  lcd / lls / lpwd / lmkdir");
                println!();
                println!("Session:");
                println!("  help                This message");
                println!("  quit / exit         Exit shell");
            },
            "quit" | "exit" => break,
            _ => eprintln!("{}", format!("unknown command: {cmd}  (type 'help')").red()),
        }
    }
    Ok(())
}

/// Read all directory entries via paginated NFSv2 READDIR.
async fn v2_readdir_all<T: nfswolf_rpc::RpcTransport>(client: &nfswolf_nfs2::Nfs2Client<T>, dir: &nfswolf_nfs2::wire::Nfs2FileHandle) -> Result<Vec<nfswolf_nfs2::wire::ReaddirEntry>, nfswolf_nfs2::Nfs2Error<T::Error>> {
    let mut all = Vec::new();
    let mut cookie = 0u32;
    loop {
        let entries = client.readdir(dir, cookie, 4096).await?;
        if entries.is_empty() {
            break;
        }
        cookie = entries.last().map_or(0, |e| e.cookie);
        let was_empty = entries.is_empty();
        all.extend(entries);
        if was_empty || all.len() > 100_000 {
            break;
        }
    }
    Ok(all)
}

fn v2_mode_str(a: &nfswolf_nfs2::wire::Nfs2FileAttr) -> String {
    use nfswolf_nfs2::wire::FType;
    let t = match a.ftype {
        FType::Regular => '-',
        FType::Directory => 'd',
        FType::Block => 'b',
        FType::Character => 'c',
        FType::Symlink => 'l',
        FType::Socket => 's',
        FType::Fifo => 'p',
        FType::NonFile | FType::Bad => '?',
    };
    let m = a.mode;
    let mut s = String::with_capacity(10);
    s.push(t);
    for shift in (0..9).rev() {
        let ch = *b"xwr".get(shift % 3).unwrap_or(&b'?');
        s.push(if m & (1 << shift) != 0 { ch as char } else { '-' });
    }
    s
}

fn v2_type_str(ftype: nfswolf_nfs2::wire::FType) -> &'static str {
    use nfswolf_nfs2::wire::FType;
    match ftype {
        FType::NonFile => "NON",
        FType::Regular => "REG",
        FType::Directory => "DIR",
        FType::Block => "BLK",
        FType::Character => "CHR",
        FType::Symlink => "LNK",
        FType::Socket => "SOCK",
        FType::Bad => "BAD",
        FType::Fifo => "FIFO",
    }
}

/// Split `arg` into two space-separated tokens.
fn v2_split2(s: &str) -> (&str, &str) {
    s.split_once(' ').map_or((s, ""), |(a, b)| (a.trim(), b.trim()))
}

/// Resolve the parent directory and filename from a path.
async fn v2_resolve_parent<T: nfswolf_rpc::RpcTransport>(client: &nfswolf_nfs2::Nfs2Client<T>, cwd: &nfswolf_nfs2::wire::Nfs2FileHandle, root: &nfswolf_nfs2::wire::Nfs2FileHandle, path: &str) -> (anyhow::Result<nfswolf_nfs2::wire::Nfs2FileHandle>, String) {
    let path = path.trim_end_matches('/');
    let (parent_path, name) = if let Some(slash) = path.rfind('/') { (&path[..slash], &path[slash + 1..]) } else { ("", path) };
    let start = if path.starts_with('/') { *root } else { *cwd };
    if parent_path.is_empty() || parent_path == "/" {
        return (Ok(start), name.to_owned());
    }
    let parent_rel = parent_path.trim_start_matches('/');
    match client.lookup_path(&start, parent_rel).await {
        Ok((fh, _)) => (Ok(fh), name.to_owned()),
        Err(e) => (Err(anyhow::anyhow!("{e}")), name.to_owned()),
    }
}

/// Write data to a v2 file handle in 8KB chunks (NFSv2 MAXDATA).
async fn v2_upload_data<T: nfswolf_rpc::RpcTransport>(client: &nfswolf_nfs2::Nfs2Client<T>, fh: &nfswolf_nfs2::wire::Nfs2FileHandle, data: &[u8]) -> anyhow::Result<u64> {
    const CHUNK: usize = 8192;
    let mut offset = 0u32;
    for chunk in data.chunks(CHUNK) {
        let _ = client.write(fh, offset, chunk.to_vec()).await.map_err(|e| anyhow::anyhow!("{e}"))?;
        offset = offset.saturating_add(u32::try_from(chunk.len()).unwrap_or(u32::MAX));
    }
    Ok(u64::from(offset))
}

fn v2_sattr_mode(mode: u32) -> nfswolf_nfs2::wire::Nfs2SetAttr {
    use nfswolf_nfs2::wire::{SATTR_UNCHANGED, Timeval};
    let ut = Timeval { seconds: SATTR_UNCHANGED, useconds: SATTR_UNCHANGED };
    nfswolf_nfs2::wire::Nfs2SetAttr { mode, uid: SATTR_UNCHANGED, gid: SATTR_UNCHANGED, size: SATTR_UNCHANGED, atime: ut, mtime: ut }
}

fn v2_handle_hex(fh: &nfswolf_nfs2::wire::Nfs2FileHandle) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(64);
    for b in &fh.0 {
        let _ = write!(s, "{b:02x}");
    }
    s
}
